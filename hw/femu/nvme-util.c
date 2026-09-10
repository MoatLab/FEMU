#include "./nvme.h"

/*
 * Deallocation-state tracking (TRIM / Write Zeroes Deallocate / DULBE).
 *
 * ns->util is the per-LBA "has valid data" bitmap: a set bit means the logical
 * block has been written (allocated); a clear bit means it is deallocated or
 * never-written. Writes set it (nvme_mark_written); deallocate clears it AND
 * zeroes the backing store for those LBAs (nvme_deallocate_range), so that a
 * subsequent read returns deterministic zeros straight from the backend -- which
 * is what DLFEAT DRB=001b promises (NVM Command Set, 3.3.3.2.1). Only the trimmed
 * range is zeroed (never the whole device), keeping the cost bounded.
 *
 * On read, nvme_check_dulbe enforces the Deallocated-or-Unwritten Logical Block
 * error when the host has enabled it via the Error Recovery feature (DULBE bit):
 * a read overlapping any deallocated block is aborted with NVME_DULB. When DULBE
 * is not enabled the read simply returns the zeros already in the backend.
 */

/* Mark [slba, slba+nlb) as written (allocated). Called on every host write. */
void nvme_mark_written(NvmeNamespace *ns, uint64_t slba, uint32_t nlb)
{
    if (ns->util) {
        bitmap_set(ns->util, slba, nlb);
    }
}

/*
 * Deallocate [slba, slba+nlb): clear the util bits and zero the backing store so
 * later reads return deterministic zeros. Bounded to the requested range.
 *
 * The backing store is one flat allocation shared by every namespace, so the
 * memset has to be addressed within this namespace's slice of it the same way
 * nvme_rw() addresses reads and writes. backend_offset is 0 for the first
 * namespace; without it a deallocate on any later namespace zeroes another
 * namespace's data.
 */
void nvme_deallocate_range(FemuCtrl *n, NvmeNamespace *ns, uint64_t slba,
                           uint32_t nlb)
{
    if (ns->util) {
        bitmap_clear(ns->util, slba, nlb);
    }
    if (n->mbe && n->mbe->logical_space) {
        uint8_t lba_index = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
        uint8_t data_shift = ns->id_ns.lbaf[lba_index].lbads;
        uint64_t off = ns->backend_offset + (slba << data_shift);
        uint64_t len = (uint64_t)nlb << data_shift;
        memset((uint8_t *)n->mbe->logical_space + off, 0, len);
    }
}

/*
 * Read-side DULBE check. Returns NVME_DULB if the Deallocated-or-Unwritten
 * Logical Block error is enabled for this namespace and the read range overlaps
 * any deallocated/unwritten block; 0 otherwise. find_next_zero_bit over util
 * finds the first non-allocated block in [slba, elba).
 */
uint16_t nvme_check_dulbe(FemuCtrl *n, NvmeNamespace *ns, uint64_t slba,
                          uint64_t elba)
{
    if (!ns->util || !NVME_ERR_REC_DULBE(ns->err_rec)) {
        return 0;
    }
    if (find_next_zero_bit(ns->util, elba, slba) < elba) {
        return NVME_DULB | NVME_DNR;
    }
    return 0;
}

int nvme_check_sqid(FemuCtrl *n, uint16_t sqid)
{
    return sqid <= n->nr_io_queues && n->sq[sqid] != NULL ? 0 : -1;
}

int nvme_check_cqid(FemuCtrl *n, uint16_t cqid)
{
    return cqid <= n->nr_io_queues && n->cq[cqid] != NULL ? 0 : -1;
}

/*
 * Hold the pollers off the queues and the namespace bookkeeping.
 *
 * A poller checks dataplane_started at the top of every sweep and publishes
 * poller_in_sweep while it is inside one, so clearing the flag and then waiting
 * for every sweep to end leaves a window in which no poller is in flight. That
 * is what an admin command needs before it frees or replaces state the I/O path
 * indexes on each request -- the per-LBA bitmaps of a namespace being
 * formatted, or a queue being deleted.
 *
 * Callers run on the vCPU thread, where the admin queue is processed. Returns
 * whether the data plane was running, which nvme_resume_pollers() takes back.
 */
bool nvme_pause_pollers(FemuCtrl *n)
{
    bool was_started = n->dataplane_started;
    int p;
    bool busy;

    if (!was_started) {
        return false;
    }

    n->dataplane_started = false;
    smp_mb();   /* publish the flag before reading anyone's sweep state */

    do {
        busy = false;
        if (n->poller_on && n->poller_in_sweep) {
            for (p = 1; p <= (int)n->nr_pollers; p++) {
                if (n->poller_in_sweep[p]) {
                    busy = true;
                    break;
                }
            }
        }
        /*
         * The FTL thread holds requests too, and for longer than a poller
         * does, so waiting only for the pollers leaves it free to touch state
         * the caller is about to release.
         */
        if (n->ftl_thread_running && n->ftl_in_sweep) {
            busy = true;
        }
        if (busy) {
            usleep(100);
        }
    } while (busy);

    return was_started;
}

void nvme_resume_pollers(FemuCtrl *n, bool was_started)
{
    if (!was_started) {
        return;
    }

    smp_mb();   /* land every change before a poller can observe the flag */
    n->dataplane_started = true;
}

void nvme_inc_cq_tail(NvmeCQueue *cq)
{
    cq->tail++;
    if (cq->tail >= cq->size) {
        cq->tail = 0;
        cq->phase = !cq->phase;
    }
}

void nvme_inc_sq_head(NvmeSQueue *sq)
{
    sq->head = (sq->head + 1) % sq->size;
}

void nvme_update_sq_tail(NvmeSQueue *sq)
{
    if (sq->db_addr_hva) {
        sq->tail = *((uint32_t *)sq->db_addr_hva);
        return;
    }

    if (sq->db_addr) {
        nvme_addr_read(sq->ctrl, sq->db_addr, &sq->tail, sizeof(sq->tail));
    }
}

void nvme_update_cq_head(NvmeCQueue *cq)
{
    if (cq->db_addr_hva) {
        cq->head = *(uint32_t *)(cq->db_addr_hva);
        return;
    }

    if (cq->db_addr) {
        nvme_addr_read(cq->ctrl, cq->db_addr, &cq->head, sizeof(cq->head));
    }
}

void nvme_update_cq_eventidx(NvmeCQueue *cq)
{
    /*
     * Same dbbuf contract as the SQ side (see nvme_update_sq_eventidx): the
     * eventidx is a pure CQ-head-doorbell MMIO-suppression hint. Publishing
     * ei == cq->head makes the guest cross it on its next CQ-head update and
     * take a doorbell exit every completion batch. FEMU reads the CQ head from
     * the shadow doorbell every poll (nvme_update_cq_head) and never blocks on
     * a guest notification, so publish one slot behind the current head to keep
     * need_event() false for all advances. The same busy-poll INVARIANT as the
     * SQ side applies: correct only while the poller sweeps unconditionally.
     *
     * Refresh cq->head from the shadow doorbell first: unlike the SQ tail (read
     * every sweep in nvme_process_sq_io), the completion path does not otherwise
     * re-read the CQ head, so without this the published eventidx would trail a
     * stale head and suppress only a fraction of the CQ-head doorbell MMIOs.
     */
    if (cq->size == 0) {
        return;
    }
    nvme_update_cq_head(cq);
    uint32_t ei = (cq->head + cq->size - 1) % cq->size;
    if (cq->eventidx_addr_hva) {
        *((uint32_t *)(cq->eventidx_addr_hva)) = ei;
        return;
    }
    if (cq->eventidx_addr) {
        nvme_addr_write(cq->ctrl, cq->eventidx_addr, (void *)&ei, sizeof(ei));
    }
}

uint8_t nvme_cq_full(NvmeCQueue *cq)
{
    nvme_update_cq_head(cq);

    return (cq->tail + 1) % cq->size == cq->head;
}

uint8_t nvme_sq_empty(NvmeSQueue *sq)
{
    return sq->head == sq->tail;
}

uint64_t *nvme_setup_discontig(FemuCtrl *n, uint64_t prp_addr, uint16_t
                               queue_depth, uint16_t entry_size)
{
    uint16_t prps_per_page = n->page_size >> 3;
    uint64_t *prp = g_malloc0(sizeof(uint64_t) * prps_per_page);
    uint16_t total_prps = DIV_ROUND_UP(queue_depth * entry_size, n->page_size);
    uint64_t *prp_list = g_malloc0(total_prps * sizeof(*prp_list));
    int i;

    /*
     * Each page of the list is read from guest memory and its entries are the
     * queue's pages. This wrote instead of read, and wrote the address of the
     * local pointer rather than the buffer behind it, so it put a host heap
     * address into guest memory and left the buffer empty -- which then failed
     * every entry's validity check, so a discontiguous queue never came up at
     * all. It also skipped the load for the final page, so a queue whose list
     * fits in one page never read anything.
     *
     * A list longer than one page chains through the last entry of each full
     * page. Reaching that needs a queue of more than prps_per_page pages, which
     * the entries property cannot currently reach, and it is not exercised.
     */
    for (i = 0; i < total_prps; i++) {
        if (i % prps_per_page == 0) {
            if (!prp_addr || prp_addr & (n->page_size - 1)) {
                g_free(prp);
                g_free(prp_list);
                return NULL;
            }
            nvme_addr_read(n, prp_addr, (uint8_t *)prp, n->page_size);
            prp_addr = le64_to_cpu(prp[prps_per_page - 1]);
        }
        prp_list[i] = le64_to_cpu(prp[i % prps_per_page]);
        if (!prp_list[i] || prp_list[i] & (n->page_size - 1)) {
            g_free(prp);
            g_free(prp_list);
            return NULL;
        }
    }

    g_free(prp);
    return prp_list;
}

void nvme_set_error_page(FemuCtrl *n, uint16_t sqid, uint16_t cid, uint16_t
                         status, uint16_t location, uint64_t lba, uint32_t nsid)
{
    NvmeErrorLog *elp;

    elp = &n->elpes[n->elp_index];
    elp->error_count = n->error_count++;
    elp->sqid = sqid;
    elp->cid = cid;
    /* bits 15:1 carry the status; bit 0 is the phase tag */
    elp->status_field = cpu_to_le16(status << 1);
    elp->param_error_location = location;
    elp->lba = lba;
    elp->nsid = nsid;
    n->elp_index = (n->elp_index + 1) % (n->elpe + 1);
    ++n->num_errors;
}

uint16_t femu_nvme_rw_check_req(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                                NvmeRequest *req, uint64_t slba, uint64_t elba,
                                uint32_t nlb, uint16_t ctrl, uint64_t data_size,
                                uint64_t meta_size)
{

    uint64_t nsze = le64_to_cpu(ns->id_ns.nsze);

    /* slba + nlb wraps for an slba near the top; test it in a form that cannot */
    if (slba > nsze || nlb > nsze - slba) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_LBA_RANGE,
                            offsetof(NvmeRwCmd, nlb), elba, ns->id);
        return NVME_LBA_RANGE | NVME_DNR;
    }
    if (n->id_ctrl.mdts && data_size > n->page_size * (1 << n->id_ctrl.mdts)) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
                            offsetof(NvmeRwCmd, nlb), nlb, ns->id);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (meta_size) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
                            offsetof(NvmeRwCmd, control), ctrl, ns->id);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if ((ctrl & NVME_RW_PRINFO_PRACT) && !(ns->id_ns.dps & DPS_TYPE_MASK)) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
                            offsetof(NvmeRwCmd, control), ctrl, ns->id);
        /* Not contemplated in LightNVM for now */
        if (OCSSD(n)) {
            return 0;
        }
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (!req->is_write && find_next_bit(ns->uncorrectable, elba, slba) < elba) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_UNRECOVERED_READ,
                            offsetof(NvmeRwCmd, slba), elba, ns->id);
        return NVME_UNRECOVERED_READ;
    }
    if (!req->is_write) {
        uint16_t dulbe = nvme_check_dulbe(n, ns, slba, elba);
        if (dulbe) {
            return dulbe;
        }
    }

    return 0;
}

/*
 * Drop every request that belongs to sq from the dataplane's queues.
 *
 * Deleting a submission queue frees the request array that backs it, but
 * requests from it may still be sitting in the ring towards the FTL, the ring
 * back from it, or the poller's queue of completions waiting for their due
 * time. Freeing the array while any of those still point into it leaves the
 * next sweep reading memory that is gone.
 *
 * The caller must have paused the dataplane, so nothing is in flight and these
 * structures are stable while they are rewritten. The requests dropped here
 * are not completed: the host asked for the queue to go away, and the
 * specification lets their commands be lost with it.
 */
void nvme_drain_sq(FemuCtrl *n, NvmeSQueue *sq)
{
    NvmeRequest *req;
    void **kept;
    size_t count, i, nkept;
    int p;

    for (p = 1; p <= (int)n->nr_pollers; p++) {
        struct rte_ring *rings[2];
        int r;

        rings[0] = n->to_ftl ? n->to_ftl[p] : NULL;
        rings[1] = n->to_poller ? n->to_poller[p] : NULL;

        for (r = 0; r < 2; r++) {
            if (!rings[r]) {
                continue;
            }
            count = femu_ring_count(rings[r]);
            if (!count) {
                continue;
            }
            kept = g_new(void *, count);
            nkept = 0;
            for (i = 0; i < count; i++) {
                if (femu_ring_dequeue(rings[r], (void **)&req, 1) != 1) {
                    break;
                }
                if (req->sq != sq) {
                    kept[nkept++] = req;
                }
            }
            /* put the survivors back in the order they were taken */
            for (i = 0; i < nkept; i++) {
                femu_ring_enqueue(rings[r], &kept[i], 1);
            }
            g_free(kept);
        }

        if (!n->pq || !n->pq[p]) {
            continue;
        }
        count = pqueue_size(n->pq[p]);
        if (!count) {
            continue;
        }
        kept = g_new(void *, count);
        nkept = 0;
        while (nkept < count && (req = pqueue_pop(n->pq[p])) != NULL) {
            if (req->sq != sq) {
                kept[nkept++] = req;
            }
        }
        for (i = 0; i < nkept; i++) {
            pqueue_insert(n->pq[p], kept[i]);
        }
        g_free(kept);
    }
}

void nvme_free_sq(NvmeSQueue *sq, FemuCtrl *n)
{
    n->sq[sq->sqid] = NULL;
    g_free(sq->io_req);
    if (sq->prp_list) {
        g_free(sq->prp_list);
    }
    if (sq->sqid) {
        g_free(sq);
    }
}

uint16_t nvme_init_sq(NvmeSQueue *sq, FemuCtrl *n, uint64_t dma_addr, uint16_t
                      sqid, uint16_t cqid, uint16_t size, enum NvmeQueueFlags
                      prio, int contig)
{
    uint8_t stride = n->db_stride;
    int dbbuf_entry_sz = 1 << (2 + stride);
    AddressSpace *as = pci_get_address_space(&n->parent_obj);
    dma_addr_t sqsz = (dma_addr_t)size;
    NvmeCQueue *cq;

    sq->ctrl = n;
    sq->sqid = sqid;
    sq->size = size;
    sq->cqid = cqid;
    sq->head = sq->tail = 0;
    sq->phys_contig = contig;
    if (sq->phys_contig) {
        sq->dma_addr = dma_addr;
        sq->dma_addr_hva = (uint64_t)dma_memory_map(as, dma_addr, &sqsz, 0, MEMTXATTRS_UNSPECIFIED);
    } else {
        sq->prp_list = nvme_setup_discontig(n, dma_addr, size, n->sqe_size);
        if (!sq->prp_list) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
    }

    sq->io_req = g_malloc0(sq->size * sizeof(*sq->io_req));
    QTAILQ_INIT(&sq->req_list);
    QTAILQ_INIT(&sq->out_req_list);
    for (int i = 0; i < sq->size; i++) {
        sq->io_req[i].sq = sq;
        QTAILQ_INSERT_TAIL(&(sq->req_list), &sq->io_req[i], entry);
    }

    switch (prio) {
    case NVME_Q_PRIO_URGENT:
        sq->arb_burst = (1 << NVME_ARB_AB(n->features.arbitration));
        break;
    case NVME_Q_PRIO_HIGH:
        sq->arb_burst = NVME_ARB_HPW(n->features.arbitration) + 1;
        break;
    case NVME_Q_PRIO_NORMAL:
        sq->arb_burst = NVME_ARB_MPW(n->features.arbitration) + 1;
        break;
    case NVME_Q_PRIO_LOW:
    default:
        sq->arb_burst = NVME_ARB_LPW(n->features.arbitration) + 1;
        break;
    }

    if (sqid && n->dbs_addr && n->eis_addr) {
        sq->db_addr = n->dbs_addr + 2 * sqid * dbbuf_entry_sz;
        sq->db_addr_hva = n->dbs_addr_hva + 2 * sqid * dbbuf_entry_sz;
        sq->eventidx_addr = n->eis_addr + 2 * sqid * dbbuf_entry_sz;
        sq->eventidx_addr_hva = n->eis_addr_hva + 2 * sqid * dbbuf_entry_sz;
        femu_debug("SQ[%d],db=%" PRIu64 ",ei=%" PRIu64 "\n", sqid, sq->db_addr,
                sq->eventidx_addr);
    }

    assert(n->cq[cqid]);
    cq = n->cq[cqid];
    QTAILQ_INSERT_TAIL(&(cq->sq_list), sq, entry);
    n->sq[sqid] = sq;

    return NVME_SUCCESS;
}

uint16_t nvme_init_cq(NvmeCQueue *cq, FemuCtrl *n, uint64_t dma_addr, uint16_t
                      cqid, uint16_t vector, uint16_t size, uint16_t
                      irq_enabled, int contig)
{
    cq->ctrl = n;
    cq->cqid = cqid;
    cq->size = size;
    cq->phase = 1;
    cq->irq_enabled = irq_enabled;
    cq->vector = vector;
    cq->head = cq->tail = 0;
    cq->phys_contig = contig;

    uint8_t stride = n->db_stride;
    int dbbuf_entry_sz = 1 << (2 + stride);
    AddressSpace *as = pci_get_address_space(&n->parent_obj);
    dma_addr_t cqsz = (dma_addr_t)size;

    if (cq->phys_contig) {
        cq->dma_addr = dma_addr;
        cq->dma_addr_hva = (uint64_t)dma_memory_map(as, dma_addr, &cqsz, 1, MEMTXATTRS_UNSPECIFIED);
    } else {
        cq->prp_list = nvme_setup_discontig(n, dma_addr, size, n->cqe_size);
        if (!cq->prp_list) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
    }

    QTAILQ_INIT(&cq->req_list);
    QTAILQ_INIT(&cq->sq_list);
    if (cqid && n->dbs_addr && n->eis_addr) {
        cq->db_addr = n->dbs_addr + (2 * cqid + 1) * dbbuf_entry_sz;
        cq->db_addr_hva = n->dbs_addr_hva + (2 * cqid + 1) * dbbuf_entry_sz;
        cq->eventidx_addr = n->eis_addr + (2 * cqid + 1) * dbbuf_entry_sz;
        cq->eventidx_addr_hva = n->eis_addr_hva + (2 * cqid + 1) * dbbuf_entry_sz;
        femu_debug("CQ, db_addr=%" PRIu64 ", eventidx_addr=%" PRIu64 "\n",
                    cq->db_addr, cq->eventidx_addr);
    }
    msix_vector_use(&n->parent_obj, cq->vector);
    n->cq[cqid] = cq;

    return NVME_SUCCESS;
}

void nvme_free_cq(NvmeCQueue *cq, FemuCtrl *n)
{
    n->cq[cq->cqid] = NULL;
    msix_vector_unuse(&n->parent_obj, cq->vector);
    if (cq->prp_list) {
        g_free(cq->prp_list);
    }
    if (cq->cqid) {
        g_free(cq);
    }
}

void nvme_set_ctrl_name(FemuCtrl *n, const char *mn, const char *sn, int *dev_id)
{
    NvmeIdCtrl *id = &n->id_ctrl;
    char *subnqn;
    char serial[MN_MAX_LEN], dev_id_str[ID_MAX_LEN];

    memset(serial, 0, MN_MAX_LEN);
    memset(dev_id_str, 0, ID_MAX_LEN);
    strcat(serial, sn);

    sprintf(dev_id_str, "%d", *dev_id);
    strcat(serial, dev_id_str);
    (*dev_id)++;
    strpadcpy((char *)id->mn, sizeof(id->mn), mn, ' ');

    memset(n->devname, 0, MN_MAX_LEN);
    g_strlcpy(n->devname, serial, sizeof(serial));

    strpadcpy((char *)id->sn, sizeof(id->sn), serial, ' ');
    strpadcpy((char *)id->fr, sizeof(id->fr), "1.0", ' ');

    subnqn = g_strdup_printf("nqn.2021-05.org.femu:%s", serial);
    strpadcpy((char *)id->subnqn, sizeof(id->subnqn), subnqn, '\0');
}

