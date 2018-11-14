#include "qemu/osdep.h"
#include "hw/block/block.h"
#include "hw/pci/msix.h"
#include "hw/pci/msi.h"
#include "qapi/visitor.h"
#include "qapi/error.h"

#include "nvme.h"

static void nvme_post_cqe(NvmeCQueue *cq, NvmeRequest *req)
{
    FemuCtrl *n = cq->ctrl;
    NvmeSQueue *sq = req->sq;
    NvmeCqe *cqe = &req->cqe;
    uint8_t phase = cq->phase;
    hwaddr addr;

    if (cq->phys_contig) {
        addr = cq->dma_addr + cq->tail * n->cqe_size;
    } else {
        addr = nvme_discontig(cq->prp_list, cq->tail, n->page_size, n->cqe_size);
    }

    cqe->status = cpu_to_le16((req->status << 1) | phase);
    cqe->sq_id = cpu_to_le16(sq->sqid);
    cqe->sq_head = cpu_to_le16(sq->head);
    nvme_addr_write(n, addr, (void *)cqe, sizeof(*cqe));
    nvme_inc_cq_tail(cq);

    QTAILQ_INSERT_TAIL(&sq->req_list, req, entry);
}

void nvme_post_cqes_io(void *opaque)
{
    NvmeCQueue *cq = opaque;
    NvmeRequest *req, *next;
    int64_t cur_time, ntt = 0;
    int processed = 0;

    QTAILQ_FOREACH_SAFE(req, &cq->req_list, entry, next) {
        if (nvme_cq_full(cq)) {
            break;
        }

        /*
         * Coperd: decide whether to return I/O based on its expire_time
         * Set a 5us grace time period as overhead of QEMU-to-guest is not
         * included in delay emulation (TODO: optimize this)
         */
        cur_time = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
        if (cq->cqid != 0 && cur_time < req->expire_time) {
            ntt = req->expire_time;
            break;
        }

        QTAILQ_REMOVE(&cq->req_list, req, entry);
        nvme_post_cqe(cq, req);
        processed++;
    }

    if (ntt == 0) {
        ntt = qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + CQ_POLLING_PERIOD_NS;
    }

    timer_mod(cq->timer, ntt);

    /* Coperd: only interrupt guest when we "do" complete some I/Os */
    if (processed > 0) {
        nvme_isr_notify_io(cq);
    }
}

static void nvme_enqueue_req_completion_io(NvmeCQueue *cq, NvmeRequest *req)
{
    NvmeRequest *iter, *next;
    bool inserted = false;

    assert(cq->cqid == req->sq->cqid);
    QTAILQ_REMOVE(&req->sq->out_req_list, req, entry);
    //QTAILQ_INSERT_TAIL(&cq->req_list, req, entry);

    if (QTAILQ_EMPTY(&cq->req_list)) {
        QTAILQ_INSERT_HEAD(&cq->req_list, req, entry);
        timer_mod(cq->timer, req->expire_time);
        return;
    }

    QTAILQ_FOREACH_SAFE(iter, &cq->req_list, entry, next) {
        if (req->expire_time < iter->expire_time) {
            QTAILQ_INSERT_BEFORE(iter, req, entry);
            inserted = true;
            break;
        }
    }
    if (inserted == false) {
        QTAILQ_INSERT_TAIL(&cq->req_list, req, entry);
    }
}

static uint16_t nvme_rw(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)cmd;
    uint16_t ctrl = le16_to_cpu(rw->control);
    uint32_t nlb  = le16_to_cpu(rw->nlb) + 1;
    uint64_t slba = le64_to_cpu(rw->slba);
    uint64_t prp1 = le64_to_cpu(rw->prp1);
    uint64_t prp2 = le64_to_cpu(rw->prp2);
    //uint64_t gtsc = le64_to_cpu(rw->rsvd2);
    const uint8_t lba_index = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    const uint16_t ms = le16_to_cpu(ns->id_ns.lbaf[lba_index].ms);
    const uint8_t data_shift = ns->id_ns.lbaf[lba_index].ds;
    uint64_t data_size = (uint64_t)nlb << data_shift;
    uint64_t data_offset = slba << data_shift;
    uint64_t meta_size = nlb * ms;
    uint64_t elba = slba + nlb;
    uint16_t err;
    int64_t overhead = 0;
    struct ssdstate *ssd = &(n->ssd);

    req->data_offset = data_offset;
    req->is_write = (rw->opcode == NVME_CMD_WRITE) ? 1 : 0;

    err = nvme_rw_check_req(n, ns, cmd, req, slba, elba, nlb, ctrl, data_size,
            meta_size);
    if (err)
        return err;

    if (nvme_map_prp(&req->qsg, &req->iov, prp1, prp2, data_size, n)) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
                offsetof(NvmeRwCmd, prp1), 0, ns->id);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    assert((nlb << data_shift) == req->qsg.size);

    req->slba = slba;
    req->meta_size = 0;
    req->status = NVME_SUCCESS;
    req->nlb = nlb;
    req->ns = ns;
    //overhead = cyc2ns(rdtscp() + tsc_offset - gtsc);
    req->expire_time = qemu_clock_get_ns(QEMU_CLOCK_REALTIME); // + 200000 - overhead;

    if (req->is_write) {
        //printf("SSD_WRITE: nlb = %lld, slba=%lld, data_size=%lld, data_offset=%lld\n", nlb, slba, data_size, data_offset);
        overhead = qemu_clock_get_ns(QEMU_CLOCK_REALTIME) - req->expire_time;
        if (n->femu_mode == FEMU_BLACKBOX_MODE)
            req->expire_time += SSD_WRITE(ssd, data_size >> 9, data_offset >> 9) - overhead;
    } else {
        //printf("SSD_READ: nlb = %lld, slba=%lld, data_size=%lld, data_offset=%lld\n", nlb, slba, data_size, data_offset);
        overhead = qemu_clock_get_ns(QEMU_CLOCK_REALTIME) - req->expire_time;
        if (n->femu_mode == FEMU_BLACKBOX_MODE)
            req->expire_time += SSD_READ(ssd, data_size >> 9 , data_offset >> 9) - overhead;
    }

    //return NVME_SUCCESS;
    return femu_rw_mem_backend(n, ns, cmd, req);
}

static uint16_t nvme_io_cmd(FemuCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeNamespace *ns;
    uint32_t nsid = le32_to_cpu(cmd->nsid);

    if (nsid == 0 || nsid > n->num_namespaces) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ns = &n->namespaces[nsid - 1];

    switch (cmd->opcode) {
    case NVME_CMD_READ:
    case NVME_CMD_WRITE:
        return nvme_rw(n, ns, cmd, req);

    case NVME_CMD_FLUSH:
        if (!n->id_ctrl.vwc || !n->features.volatile_wc) {
            return NVME_SUCCESS;
        }
        return nvme_flush(n, ns, cmd, req);

    case NVME_CMD_DSM:
        if (NVME_ONCS_DSM & n->oncs) {
            return nvme_dsm(n, ns, cmd, req);
        }
        return NVME_INVALID_OPCODE | NVME_DNR;

    case NVME_CMD_COMPARE:
        if (NVME_ONCS_COMPARE & n->oncs) {
            return nvme_compare(n, ns, cmd, req);
        }
        return NVME_INVALID_OPCODE | NVME_DNR;

    case NVME_CMD_WRITE_ZEROS:
        if (NVME_ONCS_WRITE_ZEROS & n->oncs) {
            return nvme_write_zeros(n, ns, cmd, req);
        }
        return NVME_INVALID_OPCODE | NVME_DNR;

    case NVME_CMD_WRITE_UNCOR:
        if (NVME_ONCS_WRITE_UNCORR & n->oncs) {
            return nvme_write_uncor(n, ns, cmd, req);
        }
        return NVME_INVALID_OPCODE | NVME_DNR;

    /* Coperd: FEMU OC command handling */
    case FEMU_OC_CMD_HYBRID_WRITE:
    case FEMU_OC_CMD_PHYS_READ:
    case FEMU_OC_CMD_PHYS_WRITE:
        return femu_oc_rw(n, ns, cmd, req);
    case FEMU_OC_CMD_ERASE_ASYNC:
        if (femu_oc_dev(n))
            return femu_oc_erase_async(n, ns, cmd, req);
        return NVME_INVALID_OPCODE | NVME_DNR;

    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

/* Coperd: eventidx buffer is not needed */
#if 0
static void nvme_update_sq_eventidx(const NvmeSQueue *sq)
{
    if (sq->eventidx_addr) {
        nvme_addr_write(sq->ctrl, sq->eventidx_addr, (void *)&sq->tail,
            sizeof(sq->tail));
    }
}
#endif

void nvme_process_sq_io(void *opaque)
{
    NvmeSQueue *sq = opaque;
    FemuCtrl *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];

    uint16_t status;
    hwaddr addr;
    NvmeCmd cmd;
    NvmeRequest *req;
    int processed = 0;

    nvme_update_sq_tail(sq);
    while (!(nvme_sq_empty(sq) || QTAILQ_EMPTY(&sq->req_list)) &&
            processed++ < sq->arb_burst) {
        if (sq->phys_contig) {
            addr = sq->dma_addr + sq->head * n->sqe_size;
        } else {
            addr = nvme_discontig(sq->prp_list, sq->head, n->page_size,
                    n->sqe_size);
        }
        nvme_addr_read(n, addr, (void *)&cmd, sizeof(cmd));
        nvme_inc_sq_head(sq);

        if (cmd.opcode == NVME_OP_ABORTED) {
            continue;
        }
        req = QTAILQ_FIRST(&sq->req_list);
        QTAILQ_REMOVE(&sq->req_list, req, entry);
        QTAILQ_INSERT_TAIL(&sq->out_req_list, req, entry);
        memset(&req->cqe, 0, sizeof(req->cqe));
        req->cqe.cid = cmd.cid;
        req->aiocb = NULL;

        status = nvme_io_cmd(n, &cmd, req);
        if (status != NVME_NO_COMPLETE) {
            req->status = status;
            nvme_enqueue_req_completion_io(cq, req);
        }
    }

    /*
     * Coperd: no need to keep the tail up-to-date with guest, we will handle
     * newly submitted I/Os during next sq->timer triggering
     */
#if 0
    nvme_update_sq_eventidx(sq);
    nvme_update_sq_tail(sq);
#endif

    sq->completed += processed;

    timer_mod(sq->timer, qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + SQ_POLLING_PERIOD_NS);
}

static void nvme_clear_ctrl(FemuCtrl *n, bool shutdown)
{
    int i;

    if (shutdown) {
        printf("FEMU shutting down NVMe Controller ...\n");
    } else {
        printf("FEMU disabling NVMe Controller ...\n");
    }

    if (shutdown) {
        nvme_clear_guest_notifier(n);
    }

    for (i = 0; i <= n->num_io_queues; i++) {
        if (n->sq[i] != NULL) {
            nvme_free_sq(n->sq[i], n);
        }
    }
    for (i = 0; i <= n->num_io_queues; i++) {
        if (n->cq[i] != NULL) {
            nvme_free_cq(n->cq[i], n);
        }
    }

    n->bar.cc = 0;
    n->dataplane_started = false;
    n->features.temp_thresh = 0x14d;
    n->temp_warn_issued = 0;
}

static int nvme_start_ctrl(FemuCtrl *n)
{
    uint32_t page_bits = NVME_CC_MPS(n->bar.cc) + 12;
    uint32_t page_size = 1 << page_bits;

    if (n->cq[0] || n->sq[0] || !n->bar.asq || !n->bar.acq ||
            n->bar.asq & (page_size - 1) || n->bar.acq & (page_size - 1) ||
            NVME_CC_MPS(n->bar.cc) < NVME_CAP_MPSMIN(n->bar.cap) ||
            NVME_CC_MPS(n->bar.cc) > NVME_CAP_MPSMAX(n->bar.cap) ||
            NVME_CC_IOCQES(n->bar.cc) < NVME_CTRL_CQES_MIN(n->id_ctrl.cqes) ||
            NVME_CC_IOCQES(n->bar.cc) > NVME_CTRL_CQES_MAX(n->id_ctrl.cqes) ||
            NVME_CC_IOSQES(n->bar.cc) < NVME_CTRL_SQES_MIN(n->id_ctrl.sqes) ||
            NVME_CC_IOSQES(n->bar.cc) > NVME_CTRL_SQES_MAX(n->id_ctrl.sqes) ||
            !NVME_AQA_ASQS(n->bar.aqa) || NVME_AQA_ASQS(n->bar.aqa) > 4095 ||
            !NVME_AQA_ACQS(n->bar.aqa) || NVME_AQA_ACQS(n->bar.aqa) > 4095) {
        return -1;
    }

    n->page_bits = page_bits;
    n->page_size = 1 << n->page_bits;
    n->max_prp_ents = n->page_size / sizeof(uint64_t);
    n->cqe_size = 1 << NVME_CC_IOCQES(n->bar.cc);
    n->sqe_size = 1 << NVME_CC_IOSQES(n->bar.cc);

    nvme_init_cq(&n->admin_cq, n, n->bar.acq, 0, 0,
            NVME_AQA_ACQS(n->bar.aqa) + 1, 1, 1);
    nvme_init_sq(&n->admin_sq, n, n->bar.asq, 0, 0,
            NVME_AQA_ASQS(n->bar.aqa) + 1, NVME_Q_PRIO_HIGH, 1);

    return 0;
}

static void nvme_write_bar(FemuCtrl *n, hwaddr offset, uint64_t data,
    unsigned size)
{
    switch (offset) {
    case 0xc:
        n->bar.intms |= data & 0xffffffff;
        n->bar.intmc = n->bar.intms;
        break;
    case 0x10:
        n->bar.intms &= ~(data & 0xffffffff);
        n->bar.intmc = n->bar.intms;
        break;
    case 0x14:
        if (NVME_CC_EN(data) && !NVME_CC_EN(n->bar.cc)) {
            n->bar.cc = data;
            if (nvme_start_ctrl(n)) {
                n->bar.csts = NVME_CSTS_FAILED;
            } else {
                n->bar.csts = NVME_CSTS_READY;
            }
        } else if (!NVME_CC_EN(data) && NVME_CC_EN(n->bar.cc)) {
            nvme_clear_ctrl(n, false);
            n->bar.csts &= ~NVME_CSTS_READY;
        }
        if (NVME_CC_SHN(data) && !(NVME_CC_SHN(n->bar.cc))) {
            nvme_clear_ctrl(n, true);
            n->bar.cc = data;
            n->bar.csts |= NVME_CSTS_SHST_COMPLETE;
        } else if (!NVME_CC_SHN(data) && NVME_CC_SHN(n->bar.cc)) {
            n->bar.csts &= ~NVME_CSTS_SHST_COMPLETE;
            n->bar.cc = data;
        }
        break;
    case 0x24:
        n->bar.aqa = data & 0xffffffff;
        break;
    case 0x28:
        n->bar.asq = data;
        break;
    case 0x2c:
        n->bar.asq |= data << 32;
        break;
    case 0x30:
        n->bar.acq = data;
        break;
    case 0x34:
        n->bar.acq |= data << 32;
        break;
    default:
        break;
    }
}

static uint64_t nvme_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    FemuCtrl *n = (FemuCtrl *)opaque;
    uint8_t *ptr = (uint8_t *)&n->bar;
    uint64_t val = 0;

    if (addr < sizeof(n->bar)) {
        memcpy(&val, ptr + addr, size);
    }

    return val;
}

static void nvme_process_db_admin(FemuCtrl *n, hwaddr addr, int val)
{
    uint32_t qid;
    uint16_t new_val = val & 0xffff;
    NvmeSQueue *sq;

    if (((addr - 0x1000) >> (2 + n->db_stride)) & 1) {
        NvmeCQueue *cq;

        qid = (addr - (0x1000 + (1 << (2 + n->db_stride)))) >>
            (3 + n->db_stride);
        if (nvme_check_cqid(n, qid)) {
            return;
        }

        cq = n->cq[qid];
        if (new_val >= cq->size) {
            return;
        }

        cq->head = new_val;

        if (cq->tail != cq->head) {
            nvme_isr_notify_admin(cq);
        }
    } else {
        qid = (addr - 0x1000) >> (3 + n->db_stride);
        if (nvme_check_sqid(n, qid)) {
            return;
        }
        sq = n->sq[qid];
        if (new_val >= sq->size) {
            return;
        }

        sq->tail = new_val;
        nvme_process_sq_admin(sq);
    }
}

static void nvme_process_db_io(FemuCtrl *n, hwaddr addr, int val)
{
    uint32_t qid;
    uint16_t new_val = val & 0xffff;
    NvmeSQueue *sq;

    if (n->dataplane_started) {
        printf("FEMU: ignoring guest MMIO DB ring since poller is up\n");
        return;
    }

    if (addr & ((1 << (2 + n->db_stride)) - 1)) {
        return;
    }

    if (((addr - 0x1000) >> (2 + n->db_stride)) & 1) {
        NvmeCQueue *cq;

        qid = (addr - (0x1000 + (1 << (2 + n->db_stride)))) >>
            (3 + n->db_stride);
        if (nvme_check_cqid(n, qid)) {
            return;
        }

        cq = n->cq[qid];
        if (new_val >= cq->size) {
            return;
        }

        if (!cq->db_addr) {
            cq->head = new_val;
        }

        if (cq->tail != cq->head) {
            nvme_isr_notify_io(cq);
        }
    } else {
        qid = (addr - 0x1000) >> (3 + n->db_stride);
        if (nvme_check_sqid(n, qid)) {
            return;
        }
        sq = n->sq[qid];
        if (new_val >= sq->size) {
            return;
        }

        if (!sq->db_addr) {
            sq->tail = new_val;
        }
    }
}

static void nvme_mmio_write(void *opaque, hwaddr addr, uint64_t data,
        unsigned size)
{
    FemuCtrl *n = (FemuCtrl *)opaque;
    if (addr < sizeof(n->bar)) {
        nvme_write_bar(n, addr, data, size);
    } else if (addr >= 0x1000 && addr < 0x1008) {
        nvme_process_db_admin(n, addr, data);
    } else {
        nvme_process_db_io(n, addr, data);
    }
}

static const MemoryRegionOps nvme_cmb_ops = {
    .read = nvme_cmb_read,
    .write = nvme_cmb_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 2,
        .max_access_size = 8,
    },
};

static const MemoryRegionOps nvme_mmio_ops = {
    .read = nvme_mmio_read,
    .write = nvme_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 2,
        .max_access_size = 8,
    },
};

static int nvme_check_constraints(FemuCtrl *n)
{
    /* Coperd: FEMU doesn't rely on backend image file: !(n->conf.blk) */
    if (!(n->serial) ||
        (n->num_namespaces == 0 || n->num_namespaces > NVME_MAX_NUM_NAMESPACES) ||
        (n->num_io_queues < 1 || n->num_io_queues > NVME_MAX_QS) ||
        (n->db_stride > NVME_MAX_STRIDE) ||
        (n->max_q_ents < 1) ||
        (n->max_sqes > NVME_MAX_QUEUE_ES || n->max_cqes > NVME_MAX_QUEUE_ES ||
            n->max_sqes < NVME_MIN_SQUEUE_ES || n->max_cqes < NVME_MIN_CQUEUE_ES) ||
        (n->vwc > 1 || n->intc > 1 || n->cqr > 1 || n->extended > 1) ||
        (n->nlbaf > 16) ||
        (n->lba_index >= n->nlbaf) ||
        (n->meta && !n->mc) ||
        (n->extended && !(NVME_ID_NS_MC_EXTENDED(n->mc))) ||
        (!n->extended && n->meta && !(NVME_ID_NS_MC_SEPARATE(n->mc))) ||
        (n->dps && n->meta < 8) ||
        (n->dps && ((n->dps & DPS_FIRST_EIGHT) &&
            !NVME_ID_NS_DPC_FIRST_EIGHT(n->dpc))) ||
        (n->dps && !(n->dps & DPS_FIRST_EIGHT) &&
            !NVME_ID_NS_DPC_LAST_EIGHT(n->dpc)) ||
        (n->dps & DPS_TYPE_MASK && !((n->dpc & NVME_ID_NS_DPC_TYPE_MASK) &
            (1 << ((n->dps & DPS_TYPE_MASK) - 1)))) ||
        (n->mpsmax > 0xf || n->mpsmax > n->mpsmin) ||
        (n->oacs & ~(NVME_OACS_FORMAT)) ||
        (n->oncs & ~(NVME_ONCS_COMPARE | NVME_ONCS_WRITE_UNCORR |
            NVME_ONCS_DSM | NVME_ONCS_WRITE_ZEROS))) {
        return -1;
    }

    return 0;
}

uint64_t ns_blks(NvmeNamespace *ns, uint8_t lba_idx)
{
    FemuCtrl *n = ns->ctrl;
    NvmeIdNs *id_ns = &ns->id_ns;
    uint64_t ns_size = n->ns_size;

    uint32_t lba_ds = (1 << id_ns->lbaf[lba_idx].ds);
    uint32_t lba_sz = lba_ds + n->meta;

    printf("Coperd,ns_size=%ld,lba_ds=%d,lba_sz=%d\n", ns_size, lba_ds, lba_sz);
    return ns_size / lba_sz;
	if (n->femu_mode == FEMU_WHITEBOX_MODE && femu_oc_dev(n)) {
		/* p_ent: LBA + md + L2P entry */
		uint64_t p_ent = lba_sz + sizeof(*(ns->tbl));
		uint64_t p_ents = ns_size / p_ent;

		return p_ents;
	} else {
        return ns_size / lba_sz;
    }
}

static uint64_t ns_bdrv_blks(NvmeNamespace *ns, uint64_t blks, uint8_t lba_idx)
{
    NvmeIdNs *id_ns = &ns->id_ns;

    return blks << (id_ns->lbaf[lba_idx].ds - BDRV_SECTOR_BITS);
}

void nvme_partition_ns(NvmeNamespace *ns, uint8_t lba_idx)
{
    FemuCtrl *n = ns->ctrl;
    NvmeIdNs *id_ns = &ns->id_ns;
    uint64_t blks;
    uint64_t bdrv_blks;

    blks = ns->ns_blks;
    bdrv_blks = ns_bdrv_blks(ns, ns->ns_blks, lba_idx);

    if (n->femu_mode == FEMU_WHITEBOX_MODE && femu_oc_dev(n)) {
        ns->tbl_dsk_start_offset =
            (ns->start_block + bdrv_blks) << BDRV_SECTOR_BITS;
        ns->tbl_entries = blks;
        if (ns->tbl) {
            g_free(ns->tbl);
        }
        ns->tbl = qemu_memalign(4096, femu_oc_tbl_size(ns));
        femu_oc_tbl_initialize(ns);
    } else {
        ns->tbl = NULL;
        ns->tbl_entries = 0;
    }

    id_ns->nuse = id_ns->ncap = id_ns->nsze = cpu_to_le64(blks);
    ns->meta_start_offset =
        ((ns->start_block + bdrv_blks) << BDRV_SECTOR_BITS) + femu_oc_tbl_size(ns);

    if (ns->util)
        g_free(ns->util);
    ns->util = bitmap_new(blks);
    if (ns->uncorrectable)
        g_free(ns->uncorrectable);
    ns->uncorrectable = bitmap_new(blks);
}

static void nvme_init_namespaces(FemuCtrl *n)
{
    int i, j, k;
    int ji = n->meta ? 2 : 1;

    for (i = 0; i < n->num_namespaces; i++) {
        uint64_t blks;
        int lba_index;
        NvmeNamespace *ns = &n->namespaces[i];
        NvmeIdNs *id_ns = &ns->id_ns;

        id_ns->nsfeat = 0x0;
        id_ns->nlbaf = n->nlbaf - 1;
        id_ns->flbas = n->lba_index | (n->extended << 4);
        id_ns->mc = n->mc;
        id_ns->dpc = n->dpc;
        id_ns->dps = n->dps;

        if (n->femu_mode == FEMU_WHITEBOX_MODE) {
            if (femu_oc_dev(n))
                id_ns->vs[0] = 0x1;
        }

        for (j = 0; j < ji; j++) {
            for (k = 0; k < n->nlbaf / ji; k++) {
                id_ns->lbaf[k + (n->nlbaf / ji) * j].ds = BDRV_SECTOR_BITS + k;
                if (j) {
                    id_ns->lbaf[k + (n->nlbaf / ji)].ms = cpu_to_le16(n->meta);
                }
            }
        }

        lba_index = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
        blks = n->ns_size / ((1 << id_ns->lbaf[lba_index].ds));
        id_ns->nuse = id_ns->ncap = id_ns->nsze = cpu_to_le64(blks);

        ns->id = i + 1;
        ns->ctrl = n;
        //ns->start_block = i * n->ns_size >> BDRV_SECTOR_BITS;
        ns->ns_blks = ns_blks(ns, lba_index);
        ns->start_block = i * ((n->ns_size >> BDRV_SECTOR_BITS)
                + (n->meta * ns_bdrv_blks(ns, ns->ns_blks, lba_index)));
        ns->util = bitmap_new(blks);
        ns->uncorrectable = bitmap_new(blks);
        nvme_partition_ns(ns, lba_index);
    }
}

static void nvme_init_ctrl(FemuCtrl *n)
{
    int i;
    NvmeIdCtrl *id = &n->id_ctrl;
    uint8_t *pci_conf = n->parent_obj.config;

    id->vid = cpu_to_le16(pci_get_word(pci_conf + PCI_VENDOR_ID));
    id->ssvid = cpu_to_le16(pci_get_word(pci_conf + PCI_SUBSYSTEM_VENDOR_ID));
    strpadcpy((char *)id->mn, sizeof(id->mn), "FEMU NVMe Ctrl", ' ');
    strpadcpy((char *)id->fr, sizeof(id->fr), "1.0", ' ');
    strpadcpy((char *)id->sn, sizeof(id->sn), n->serial, ' ');
    id->rab = 6;
    id->ieee[0] = 0x00;
    id->ieee[1] = 0x02;
    id->ieee[2] = 0xb3;
    id->cmic = 0;
    id->mdts = n->mdts;
    id->oacs = cpu_to_le16(n->oacs | NVME_OACS_DBBUF);
    id->acl = n->acl;
    id->aerl = n->aerl;
    id->frmw = 7 << 1 | 1;
    id->lpa = 0 << 0;
    id->elpe = n->elpe;
    id->npss = 0;
    id->sqes = (n->max_sqes << 4) | 0x6;
    id->cqes = (n->max_cqes << 4) | 0x4;
    id->nn = cpu_to_le32(n->num_namespaces);
    id->oncs = cpu_to_le16(n->oncs);
    id->fuses = cpu_to_le16(0);
    id->fna = 0;
    id->vwc = n->vwc;
    id->awun = cpu_to_le16(0);
    id->awupf = cpu_to_le16(0);
    id->psd[0].mp = cpu_to_le16(0x9c4);
    id->psd[0].enlat = cpu_to_le32(0x10);
    id->psd[0].exlat = cpu_to_le32(0x4);

    n->features.arbitration     = 0x1f0f0706;
    n->features.power_mgmt      = 0;
    n->features.temp_thresh     = 0x14d;
    n->features.err_rec         = 0;
    n->features.volatile_wc     = n->vwc;
    n->features.num_io_queues      = (n->num_io_queues - 1) |
        ((n->num_io_queues - 1) << 16);
    n->features.int_coalescing  = n->intc_thresh | (n->intc_time << 8);
    n->features.write_atomicity = 0;
    n->features.async_config    = 0x0;
    n->features.sw_prog_marker  = 0;

    for (i = 0; i <= n->num_io_queues; i++) {
        n->features.int_vector_config[i] = i | (n->intc << 16);
    }

    n->bar.cap = 0;
    NVME_CAP_SET_MQES(n->bar.cap, n->max_q_ents);
    NVME_CAP_SET_CQR(n->bar.cap, n->cqr);
    NVME_CAP_SET_AMS(n->bar.cap, 1);
    NVME_CAP_SET_TO(n->bar.cap, 0xf);
    NVME_CAP_SET_DSTRD(n->bar.cap, n->db_stride);
    NVME_CAP_SET_NSSRS(n->bar.cap, 0);
    NVME_CAP_SET_CSS(n->bar.cap, 1);
    if (n->femu_mode == FEMU_WHITEBOX_MODE) {
        if (femu_oc_dev(n))
            NVME_CAP_SET_FEMU_OC(n->bar.cap, 1);
    }

    NVME_CAP_SET_MPSMIN(n->bar.cap, n->mpsmin);
    NVME_CAP_SET_MPSMAX(n->bar.cap, n->mpsmax);

    if (n->cmbsz)
        n->bar.vs = 0x00010200;
    else
        n->bar.vs = 0x00010100;
    n->bar.intmc = n->bar.intms = 0;
    n->temperature = NVME_TEMPERATURE;
}

static void nvme_init_pci(FemuCtrl *n)
{
    uint8_t *pci_conf = n->parent_obj.config;

    pci_conf[PCI_INTERRUPT_PIN] = 1;
    /* Coperd: QEMU-OCSSD(0x1d1d,0x1f1f), QEMU-NVMe(0x8086,0x5845) */
    pci_config_set_prog_interface(pci_conf, 0x2);
    pci_config_set_vendor_id(pci_conf, n->vid);
    pci_config_set_device_id(pci_conf, n->did);
    pci_config_set_class(pci_conf, PCI_CLASS_STORAGE_EXPRESS);
    pcie_endpoint_cap_init(&n->parent_obj, 0x80);

    memory_region_init_io(&n->iomem, OBJECT(n), &nvme_mmio_ops, n, "nvme",
            n->reg_size);
    pci_register_bar(&n->parent_obj, 0,
            PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64,
            &n->iomem);
    msix_init_exclusive_bar(&n->parent_obj, n->num_io_queues, 4, NULL);
    msi_init(&n->parent_obj, 0x50, 32, true, false, NULL);

    if (n->cmbsz) {

        n->bar.cmbloc = n->cmbloc;
        n->bar.cmbsz  = n->cmbsz;

        n->cmbuf = g_malloc0(NVME_CMBSZ_GETSIZE(n->bar.cmbsz));
        memory_region_init_io(&n->ctrl_mem, OBJECT(n), &nvme_cmb_ops, n, "nvme-cmb",
                NVME_CMBSZ_GETSIZE(n->bar.cmbsz));
        pci_register_bar(&n->parent_obj, NVME_CMBLOC_BIR(n->bar.cmbloc),
                PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64,
                &n->ctrl_mem);

    }
}

static int femu_init(PCIDevice *pci_dev)
{
    FemuCtrl *n = FEMU(pci_dev);
    int64_t bs_size;

    blkconf_serial(&n->conf, &n->serial);
    if (nvme_check_constraints(n)) {
        return -1;
    }

    bs_size = ((int64_t)n->memsz) * 1024 * 1024;

    femu_init_mem_backend(&n->mbe, bs_size);

    n->start_time = time(NULL);
    n->reg_size = pow2ceil(0x1004 + 2 * (n->num_io_queues + 1) * 4);
    n->ns_size = bs_size / (uint64_t)n->num_namespaces;

    /* Coperd: [1..num_io_queues] are used for IO queues */
    n->sq = g_malloc0(sizeof(*n->sq) * (n->num_io_queues + 1));
    n->cq = g_malloc0(sizeof(*n->cq) * (n->num_io_queues + 1));
    n->namespaces = g_malloc0(sizeof(*n->namespaces) * n->num_namespaces);
    n->elpes = g_malloc0((n->elpe + 1) * sizeof(*n->elpes));
    n->aer_reqs = g_malloc0((n->aerl + 1) * sizeof(*n->aer_reqs));
    n->features.int_vector_config = g_malloc0((n->num_io_queues + 1) *
            sizeof(*n->features.int_vector_config));

    nvme_init_pci(n);
    nvme_init_ctrl(n);
    nvme_init_namespaces(n);

    if (n->femu_mode == FEMU_WHITEBOX_MODE) {
        printf("FEMU: starting in OCSSD mode ..\n");
        if (femu_oc_dev(n)) {
            return femu_oc_init(n);
        }
    } else if (n->femu_mode == FEMU_BLACKBOX_MODE) {
        struct ssdstate *ssd = &(n->ssd);
        printf("FEMU: starting in blackbox SSD mode ..\n");
        SSD_INIT(ssd);
    }

    return 0;
}

static void femu_exit(PCIDevice *pci_dev)
{
    FemuCtrl *n = FEMU(pci_dev);

    nvme_clear_ctrl(n, true);

    femu_destroy_mem_backend(&n->mbe);

    g_free(n->namespaces);
    g_free(n->features.int_vector_config);
    g_free(n->aer_reqs);
    g_free(n->elpes);
    g_free(n->cq);
    g_free(n->sq);
    msix_uninit_exclusive_bar(pci_dev);
    memory_region_unref(&n->iomem);
    if (n->cmbsz) {
        memory_region_unref(&n->ctrl_mem);
    }

    if (n->femu_mode == FEMU_WHITEBOX_MODE) {
        if (femu_oc_dev(n)) {
            femu_oc_exit(n);
        }
    }
}

static Property femu_props[] = {
    DEFINE_BLOCK_PROPERTIES(FemuCtrl, conf),
    DEFINE_PROP_STRING("serial", FemuCtrl, serial),
    DEFINE_PROP_UINT32("memsz", FemuCtrl, memsz, 1024), /* Coperd: MB */
    DEFINE_PROP_UINT32("namespaces", FemuCtrl, num_namespaces, 1),
    DEFINE_PROP_UINT32("queues", FemuCtrl, num_io_queues, 1),
    DEFINE_PROP_UINT32("entries", FemuCtrl, max_q_ents, 0x7ff),
    DEFINE_PROP_UINT8("max_cqes", FemuCtrl, max_cqes, 0x4),
    DEFINE_PROP_UINT8("max_sqes", FemuCtrl, max_sqes, 0x6),
    DEFINE_PROP_UINT8("stride", FemuCtrl, db_stride, 0),
    DEFINE_PROP_UINT8("aerl", FemuCtrl, aerl, 3),
    DEFINE_PROP_UINT8("acl", FemuCtrl, acl, 3),
    DEFINE_PROP_UINT8("elpe", FemuCtrl, elpe, 3),
    DEFINE_PROP_UINT8("mdts", FemuCtrl, mdts, 10),
    DEFINE_PROP_UINT8("cqr", FemuCtrl, cqr, 1),
    DEFINE_PROP_UINT8("vwc", FemuCtrl, vwc, 0),
    DEFINE_PROP_UINT8("intc", FemuCtrl, intc, 0),
    DEFINE_PROP_UINT8("intc_thresh", FemuCtrl, intc_thresh, 0),
    DEFINE_PROP_UINT8("intc_time", FemuCtrl, intc_time, 0),
    DEFINE_PROP_UINT8("mpsmin", FemuCtrl, mpsmin, 0),
    DEFINE_PROP_UINT8("mpsmax", FemuCtrl, mpsmax, 0),
    DEFINE_PROP_UINT8("nlbaf", FemuCtrl, nlbaf, 5),
    DEFINE_PROP_UINT8("lba_index", FemuCtrl, lba_index, 3),
    DEFINE_PROP_UINT8("extended", FemuCtrl, extended, 0),
    DEFINE_PROP_UINT8("dpc", FemuCtrl, dpc, 0),
    DEFINE_PROP_UINT8("dps", FemuCtrl, dps, 0),
    DEFINE_PROP_UINT8("mc", FemuCtrl, mc, 0),
    DEFINE_PROP_UINT8("meta", FemuCtrl, meta, 0),
    DEFINE_PROP_UINT32("cmbsz", FemuCtrl, cmbsz, 0),
    DEFINE_PROP_UINT32("cmbloc", FemuCtrl, cmbloc, 0),
    DEFINE_PROP_UINT16("oacs", FemuCtrl, oacs, NVME_OACS_FORMAT),
    DEFINE_PROP_UINT16("oncs", FemuCtrl, oncs, NVME_ONCS_DSM),
    DEFINE_PROP_UINT16("vid", FemuCtrl, vid, 0x1d1d),
    DEFINE_PROP_UINT16("did", FemuCtrl, did, 0x1f1f),
    DEFINE_PROP_UINT8("femu_mode", FemuCtrl, femu_mode, FEMU_DEF_NOSSD_MODE),
    DEFINE_PROP_UINT8("lver", FemuCtrl, femu_oc_ctrl.id_ctrl.ver_id, 0),
    DEFINE_PROP_UINT32("ll2pmode", FemuCtrl, femu_oc_ctrl.id_ctrl.dom, 1),
    DEFINE_PROP_UINT16("lsec_size", FemuCtrl, femu_oc_ctrl.params.sec_size, 4096),
    DEFINE_PROP_UINT8("lsecs_per_pg", FemuCtrl, femu_oc_ctrl.params.sec_per_pg, 1),
    DEFINE_PROP_UINT16("lpgs_per_blk", FemuCtrl, femu_oc_ctrl.params.pgs_per_blk, 256),
    DEFINE_PROP_UINT8("lmax_sec_per_rq", FemuCtrl, femu_oc_ctrl.params.max_sec_per_rq, 64),
    DEFINE_PROP_UINT8("lmtype", FemuCtrl, femu_oc_ctrl.params.mtype, 0),
    DEFINE_PROP_UINT8("lfmtype", FemuCtrl, femu_oc_ctrl.params.fmtype, 0),
    DEFINE_PROP_UINT8("lnum_ch", FemuCtrl, femu_oc_ctrl.params.num_ch, 1),
    DEFINE_PROP_UINT8("lnum_lun", FemuCtrl, femu_oc_ctrl.params.num_lun, 1),
    DEFINE_PROP_UINT8("lnum_pln", FemuCtrl, femu_oc_ctrl.params.num_pln, 1),
    DEFINE_PROP_UINT8("lreadl2ptbl", FemuCtrl, femu_oc_ctrl.read_l2p_tbl, 1),
    DEFINE_PROP_STRING("lbbtable", FemuCtrl, femu_oc_ctrl.bbt_fname),
    DEFINE_PROP_STRING("lmetadata", FemuCtrl, femu_oc_ctrl.meta_fname),
    DEFINE_PROP_UINT16("lmetasize", FemuCtrl, femu_oc_ctrl.params.sos, 16),
    DEFINE_PROP_UINT8("lbbfrequency", FemuCtrl, femu_oc_ctrl.bbt_gen_freq, 0),
    DEFINE_PROP_UINT32("lb_err_write", FemuCtrl, femu_oc_ctrl.err_write, 0),
    DEFINE_PROP_UINT32("ln_err_write", FemuCtrl, femu_oc_ctrl.n_err_write, 0),
    DEFINE_PROP_UINT8("ldebug", FemuCtrl, femu_oc_ctrl.debug, 0),
    DEFINE_PROP_UINT8("lstrict", FemuCtrl, femu_oc_ctrl.strict, 0),
    DEFINE_PROP_END_OF_LIST(),
};

static const VMStateDescription femu_vmstate = {
    .name = "femu",
    .unmigratable = 1,
};

static void femu_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    PCIDeviceClass *pc = PCI_DEVICE_CLASS(oc);

    pc->init = femu_init;
    pc->exit = femu_exit;
    pc->class_id = PCI_CLASS_STORAGE_EXPRESS;
    // Coperd: change from PCI_VENDOR_ID_INTEL to 0x1d1d for OCSSD
    pc->vendor_id = 0x1d1d;
    pc->is_express = 1;

    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    dc->desc = "Non-Volatile Memory Express";
    dc->props = femu_props;
    dc->vmsd = &femu_vmstate;
}

static void femu_get_bootindex(Object *obj, Visitor *v, const char *name,
                                void *opaque, Error **errp)
{
    FemuCtrl *s = FEMU(obj);

    visit_type_int32(v, name, &s->conf.bootindex, errp);
}

static void femu_set_bootindex(Object *obj, Visitor *v, const char *name,
                                void *opaque, Error **errp)
{
    FemuCtrl *s = FEMU(obj);
    int32_t boot_index;
    Error *local_err = NULL;

    visit_type_int32(v, name, &boot_index, &local_err);
    if (local_err) {
        goto out;
    }
    /* check whether bootindex is present in fw_boot_order list  */
    check_boot_index(boot_index, &local_err);
    if (local_err) {
        goto out;
    }
    /* change bootindex to a new one */
    s->conf.bootindex = boot_index;

out:
    if (local_err) {
        error_propagate(errp, local_err);
    }
}

static void femu_instance_init(Object *obj)
{
    object_property_add(obj, "bootindex", "int32",
                        femu_get_bootindex,
                        femu_set_bootindex, NULL, NULL, NULL);
    object_property_set_int(obj, -1, "bootindex", NULL);
}

static const TypeInfo femu_info = {
    .name          = "femu",
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(FemuCtrl),
    .class_init    = femu_class_init,
    .instance_init = femu_instance_init,
};

static void femu_register_types(void)
{
    type_register_static(&femu_info);
}

type_init(femu_register_types)
