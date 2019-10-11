/*
 * QEMU NVM Express Controller
 *
 * Copyright (c) 2012, Intel Corporation
 *
 * Written by Keith Busch <keith.busch@intel.com>
 *
 * This code is licensed under the GNU GPL v2 or later.
 */

/**
 * Reference Specs: http://www.nvmexpress.org, 1.3d, 1.2, 1.1, 1.0e
 *
 *  http://www.nvmexpress.org/resources/
 */

/**
 * Usage: add options:
 *     -drive file=<file>,if=none,id=<drive_id>
 *     -device nvme,serial=<serial>,id=nvme0
 *     -device nvme-ns,drive=<drive_id>,bus=nvme0,nsid=1
 *
 * Advanced optional options:
 *
 *   num_queues=<uint32>      : Maximum number of IO Queues.
 *                              Default: 64
 *   cmb_size_mb=<uint32>     : Size of Controller Memory Buffer in MBs.
 *                              Default: 0 (disabled)
 *   mdts=<uint8>             : Maximum Data Transfer Size (power of two)
 *                              Default: 7
 *   ms=<int>                 : Number of metadata bytes provided per LBA.
 *                              Default:0
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/cutils.h"
#include "hw/pci/msix.h"
#include "sysemu/sysemu.h"
#include "sysemu/block-backend.h"
#include "qapi/error.h"

#include "trace.h"

#include "hw/block/nvme.h"

#define NVME_MAX_QS PCI_MSIX_FLAGS_QSIZE
#define NVME_TEMPERATURE 0x143
#define NVME_ELPE 3
#define NVME_AERL 3
#define NVME_OP_ABORTED 0xff

static void nvme_process_sq(void *opaque);

static inline uint8_t nvme_addr_is_cmb(NvmeCtrl *n, hwaddr addr)
{
    return n->cmbsz && addr >= n->ctrl_mem.addr &&
        addr < (n->ctrl_mem.addr + int128_get64(n->ctrl_mem.size));
}

void nvme_addr_read(NvmeCtrl *n, hwaddr addr, void *buf, int size)
{
    if (nvme_addr_is_cmb(n, addr)) {
        memcpy(buf, (void *)&n->cmbuf[addr - n->ctrl_mem.addr], size);

        return;
    }

    pci_dma_read(&n->parent_obj, addr, buf, size);
}

void nvme_addr_write(NvmeCtrl *n, hwaddr addr, void *buf, int size)
{
    if (nvme_addr_is_cmb(n, addr)) {
        memcpy((void *)&n->cmbuf[addr - n->ctrl_mem.addr], buf, size);

        return;
    }

    pci_dma_write(&n->parent_obj, addr, buf, size);
}

static int nvme_check_sqid(NvmeCtrl *n, uint16_t sqid)
{
    return sqid < n->params.num_queues && n->sq[sqid] != NULL ? 0 : -1;
}

static int nvme_check_cqid(NvmeCtrl *n, uint16_t cqid)
{
    return cqid < n->params.num_queues && n->cq[cqid] != NULL ? 0 : -1;
}

static void nvme_inc_cq_tail(NvmeCQueue *cq)
{
    cq->tail++;
    if (cq->tail >= cq->size) {
        cq->tail = 0;
        cq->phase = !cq->phase;
    }
}

static void nvme_inc_sq_head(NvmeSQueue *sq)
{
    sq->head = (sq->head + 1) % sq->size;
}

static uint8_t nvme_cq_full(NvmeCQueue *cq)
{
    return (cq->tail + 1) % cq->size == cq->head;
}

static uint8_t nvme_sq_empty(NvmeSQueue *sq)
{
    return sq->head == sq->tail;
}

static void nvme_irq_check(NvmeCtrl *n)
{
    if (msix_enabled(&(n->parent_obj))) {
        return;
    }
    if (~n->bar.intms & n->irq_status) {
        pci_irq_assert(&n->parent_obj);
    } else {
        pci_irq_deassert(&n->parent_obj);
    }
}

static void nvme_irq_assert(NvmeCtrl *n, NvmeCQueue *cq)
{
    if (cq->irq_enabled) {
        if (msix_enabled(&(n->parent_obj))) {
            trace_nvme_irq_msix(cq->vector);
            msix_notify(&(n->parent_obj), cq->vector);
        } else {
            trace_nvme_irq_pin();
            assert(cq->cqid < 64);
            n->irq_status |= 1 << cq->cqid;
            nvme_irq_check(n);
        }
    } else {
        trace_nvme_irq_masked();
    }
}

static void nvme_irq_deassert(NvmeCtrl *n, NvmeCQueue *cq)
{
    if (cq->irq_enabled) {
        if (msix_enabled(&(n->parent_obj))) {
            return;
        } else {
            assert(cq->cqid < 64);
            n->irq_status &= ~(1 << cq->cqid);
            nvme_irq_check(n);
        }
    }
}

static uint16_t nvme_map_prp(NvmeCtrl *n, QEMUSGList *qsg, uint64_t prp1,
    uint64_t prp2, uint32_t len, NvmeRequest *req)
{
    hwaddr trans_len = n->page_size - (prp1 % n->page_size);
    trans_len = MIN(len, trans_len);
    int num_prps = (len >> n->page_bits) + 1;
    uint16_t status = NVME_SUCCESS;
    bool prp_list_in_cmb = false;

    trace_nvme_map_prp(req->cmd.opcode, trans_len, len, prp1, prp2, num_prps);

    if (unlikely(!prp1)) {
        trace_nvme_err_invalid_prp();
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (nvme_addr_is_cmb(n, prp1)) {
        req->is_cmb = true;
    }

    pci_dma_sglist_init(qsg, &n->parent_obj, num_prps);
    qemu_sglist_add(qsg, prp1, trans_len);

    len -= trans_len;
    if (len) {
        if (unlikely(!prp2)) {
            trace_nvme_err_invalid_prp2_missing();
            status = NVME_INVALID_FIELD | NVME_DNR;
            goto unmap;
        }

        if (len > n->page_size) {
            uint64_t prp_list[n->max_prp_ents];
            uint32_t nents, prp_trans;
            int i = 0;

            if (nvme_addr_is_cmb(n, prp2)) {
                prp_list_in_cmb = true;
            }

            nents = (len + n->page_size - 1) >> n->page_bits;
            prp_trans = MIN(n->max_prp_ents, nents) * sizeof(uint64_t);
            nvme_addr_read(n, prp2, (void *) prp_list, prp_trans);
            while (len != 0) {
                bool addr_is_cmb;
                uint64_t prp_ent = le64_to_cpu(prp_list[i]);

                if (i == n->max_prp_ents - 1 && len > n->page_size) {
                    if (unlikely(!prp_ent || prp_ent & (n->page_size - 1))) {
                        trace_nvme_err_invalid_prplist_ent(prp_ent);
                        status = NVME_INVALID_FIELD | NVME_DNR;
                        goto unmap;
                    }

                    addr_is_cmb = nvme_addr_is_cmb(n, prp_ent);
                    if ((prp_list_in_cmb && !addr_is_cmb) ||
                        (!prp_list_in_cmb && addr_is_cmb)) {
                        status = NVME_INVALID_USE_OF_CMB | NVME_DNR;
                        goto unmap;
                    }

                    i = 0;
                    nents = (len + n->page_size - 1) >> n->page_bits;
                    prp_trans = MIN(n->max_prp_ents, nents) * sizeof(uint64_t);
                    nvme_addr_read(n, prp_ent, (void *) prp_list, prp_trans);
                    prp_ent = le64_to_cpu(prp_list[i]);
                }

                if (unlikely(!prp_ent || prp_ent & (n->page_size - 1))) {
                    trace_nvme_err_invalid_prplist_ent(prp_ent);
                    status = NVME_INVALID_FIELD | NVME_DNR;
                    goto unmap;
                }

                addr_is_cmb = nvme_addr_is_cmb(n, prp_ent);
                if ((req->is_cmb && !addr_is_cmb) ||
                    (!req->is_cmb && addr_is_cmb)) {
                    status = NVME_INVALID_USE_OF_CMB | NVME_DNR;
                    goto unmap;
                }

                trans_len = MIN(len, n->page_size);
                qemu_sglist_add(qsg, prp_ent, trans_len);

                len -= trans_len;
                i++;
            }
        } else {
            bool addr_is_cmb = nvme_addr_is_cmb(n, prp2);
            if ((req->is_cmb && !addr_is_cmb) ||
                (!req->is_cmb && addr_is_cmb)) {
                status = NVME_INVALID_USE_OF_CMB | NVME_DNR;
                goto unmap;
            }

            if (unlikely(prp2 & (n->page_size - 1))) {
                trace_nvme_err_invalid_prp2_align(prp2);
                status = NVME_INVALID_FIELD | NVME_DNR;
                goto unmap;
            }

            qemu_sglist_add(qsg, prp2, len);
        }
    }

    return NVME_SUCCESS;

unmap:
    qemu_sglist_destroy(qsg);

    return status;
}

static uint16_t nvme_map_sgl_data(NvmeCtrl *n, QEMUSGList *qsg,
    NvmeSglDescriptor *segment, uint64_t nsgld, uint32_t *len,
    NvmeRequest *req)
{
    dma_addr_t addr, trans_len;

    for (int i = 0; i < nsgld; i++) {
        if (NVME_SGL_TYPE(segment[i].type) != SGL_DESCR_TYPE_DATA_BLOCK) {
            fprintf(stderr, "argh\n");
            trace_nvme_err_invalid_sgl_descriptor(req->cqe.cid,
                NVME_SGL_TYPE(segment[i].type));
            return NVME_SGL_DESCRIPTOR_TYPE_INVALID | NVME_DNR;
        }

        if (*len == 0) {
            if (!NVME_CTRL_SGLS_EXCESS_LENGTH(n->id_ctrl.sgls)) {
                trace_nvme_err_invalid_sgl_excess_length(req->cqe.cid);
                return NVME_DATA_SGL_LENGTH_INVALID | NVME_DNR;
            }

            break;
        }

        addr = le64_to_cpu(segment[i].addr);
        trans_len = MIN(*len, le64_to_cpu(segment[i].len));

        if (nvme_addr_is_cmb(n, addr)) {
            /*
             * All data and metadata, if any, associated with a particular
             * command shall be located in either the CMB or host memory. Thus,
             * if an address if found to be in the CMB and we have already
             * mapped data that is in host memory, the use is invalid.
             */
            if (!req->is_cmb && qsg->size) {
                return NVME_INVALID_USE_OF_CMB | NVME_DNR;
            }

            req->is_cmb = true;
        } else {
            /*
             * Similarly, if the address does not reference the CMB, but we
             * have already established that the request has data or metadata
             * in the CMB, the use is invalid.
             */
            if (req->is_cmb) {
                return NVME_INVALID_USE_OF_CMB | NVME_DNR;
            }
        }

        qemu_sglist_add(qsg, addr, trans_len);

        *len -= trans_len;
    }

    return NVME_SUCCESS;
}

static uint16_t nvme_map_sgl(NvmeCtrl *n, QEMUSGList *qsg,
    NvmeSglDescriptor sgl, uint32_t len, NvmeRequest *req)
{
    const int MAX_NSGLD = 256;

    NvmeSglDescriptor segment[MAX_NSGLD];
    uint64_t nsgld;
    uint16_t status;
    bool sgl_in_cmb = false;
    hwaddr addr = le64_to_cpu(sgl.addr);

    trace_nvme_map_sgl(req->cqe.cid, NVME_SGL_TYPE(sgl.type), req->nlb, len);

    pci_dma_sglist_init(qsg, &n->parent_obj, 1);

    /*
     * If the entire transfer can be described with a single data block it can
     * be mapped directly.
     */
    if (NVME_SGL_TYPE(sgl.type) == SGL_DESCR_TYPE_DATA_BLOCK) {
        status = nvme_map_sgl_data(n, qsg, &sgl, 1, &len, req);
        if (status) {
            goto unmap;
        }

        goto out;
    }

    /*
     * If the segment is located in the CMB, the submission queue of the
     * request must also reside there.
     */
    if (nvme_addr_is_cmb(n, addr)) {
        if (!nvme_addr_is_cmb(n, req->sq->dma_addr)) {
            return NVME_INVALID_USE_OF_CMB | NVME_DNR;
        }

        sgl_in_cmb = true;
    }

    while (NVME_SGL_TYPE(sgl.type) == SGL_DESCR_TYPE_SEGMENT) {
        bool addr_is_cmb;

        nsgld = le64_to_cpu(sgl.len) / sizeof(NvmeSglDescriptor);

        /* read the segment in chunks of 256 descriptors (4k) */
        while (nsgld > MAX_NSGLD) {
            nvme_addr_read(n, addr, segment, sizeof(segment));

            status = nvme_map_sgl_data(n, qsg, segment, MAX_NSGLD, &len, req);
            if (status) {
                goto unmap;
            }

            nsgld -= MAX_NSGLD;
            addr += MAX_NSGLD * sizeof(NvmeSglDescriptor);
        }

        nvme_addr_read(n, addr, segment, nsgld * sizeof(NvmeSglDescriptor));

        sgl = segment[nsgld - 1];
        addr = le64_to_cpu(sgl.addr);

        /* an SGL is allowed to end with a Data Block in a regular Segment */
        if (NVME_SGL_TYPE(sgl.type) == SGL_DESCR_TYPE_DATA_BLOCK) {
            status = nvme_map_sgl_data(n, qsg, segment, nsgld, &len, req);
            if (status) {
                goto unmap;
            }

            goto out;
        }

        /* do not map last descriptor */
        status = nvme_map_sgl_data(n, qsg, segment, nsgld - 1, &len, req);
        if (status) {
            goto unmap;
        }

        /*
         * If the next segment is in the CMB, make sure that the sgl was
         * already located there.
         */
        addr_is_cmb = nvme_addr_is_cmb(n, addr);
        if ((sgl_in_cmb && !addr_is_cmb) || (!sgl_in_cmb && addr_is_cmb)) {
            status = NVME_INVALID_USE_OF_CMB | NVME_DNR;
            goto unmap;
        }
    }

    /*
     * If the segment did not end with a Data Block or a Segment descriptor, it
     * must be a Last Segment descriptor.
     */
    if (NVME_SGL_TYPE(sgl.type) != SGL_DESCR_TYPE_LAST_SEGMENT) {
        fprintf(stderr, "yuck\n");
        trace_nvme_err_invalid_sgl_descriptor(req->cqe.cid,
            NVME_SGL_TYPE(sgl.type));
        return NVME_SGL_DESCRIPTOR_TYPE_INVALID | NVME_DNR;
    }

    nsgld = le64_to_cpu(sgl.len) / sizeof(NvmeSglDescriptor);

    while (nsgld > MAX_NSGLD) {
        nvme_addr_read(n, addr, segment, sizeof(segment));

        status = nvme_map_sgl_data(n, qsg, segment, MAX_NSGLD, &len, req);
        if (status) {
            goto unmap;
        }

        nsgld -= MAX_NSGLD;
        addr += MAX_NSGLD * sizeof(NvmeSglDescriptor);
    }

    nvme_addr_read(n, addr, segment, nsgld * sizeof(NvmeSglDescriptor));

    status = nvme_map_sgl_data(n, qsg, segment, nsgld, &len, req);
    if (status) {
        goto unmap;
    }

out:
    /* if there is any residual left in len, the SGL was too short */
    if (len) {
        status = NVME_DATA_SGL_LENGTH_INVALID | NVME_DNR;
        goto unmap;
    }

    return NVME_SUCCESS;

unmap:
    qemu_sglist_destroy(qsg);

    return status;
}

static void dma_to_cmb(NvmeCtrl *n, QEMUSGList *qsg, QEMUIOVector *iov)
{
    for (int i = 0; i < qsg->nsg; i++) {
        void *addr = &n->cmbuf[qsg->sg[i].base - n->ctrl_mem.addr];
        qemu_iovec_add(iov, addr, qsg->sg[i].len);
    }
}

static uint16_t nvme_dma_write_prp(NvmeCtrl *n, uint8_t *ptr, uint32_t len,
    uint64_t prp1, uint64_t prp2, NvmeRequest *req)
{
    QEMUSGList qsg;
    uint16_t err = NVME_SUCCESS;

    err = nvme_map_prp(n, &qsg, prp1, prp2, len, req);
    if (err) {
        return err;
    }

    if (req->is_cmb) {
        QEMUIOVector iov;

        qemu_iovec_init(&iov, qsg.nsg);
        dma_to_cmb(n, &qsg, &iov);

        if (unlikely(qemu_iovec_to_buf(&iov, 0, ptr, len) != len)) {
            trace_nvme_err_invalid_dma();
            err = NVME_INVALID_FIELD | NVME_DNR;
        }

        qemu_iovec_destroy(&iov);

        return err;
    }

    if (unlikely(dma_buf_write(ptr, len, &qsg))) {
        trace_nvme_err_invalid_dma();
        err = NVME_INVALID_FIELD | NVME_DNR;
    }

    qemu_sglist_destroy(&qsg);

    return err;
}

static uint16_t nvme_dma_write_sgl(NvmeCtrl *n, uint8_t *ptr, uint32_t len,
    NvmeSglDescriptor sgl, NvmeRequest *req)
{
    QEMUSGList qsg;
    uint16_t err = NVME_SUCCESS;

    err = nvme_map_sgl(n, &qsg, sgl, len, req);
    if (err) {
        return err;
    }

    if (req->is_cmb) {
        QEMUIOVector iov;

        qemu_iovec_init(&iov, qsg.nsg);
        dma_to_cmb(n, &qsg, &iov);

        if (unlikely(qemu_iovec_to_buf(&iov, 0, ptr, len) != len)) {
            trace_nvme_err_invalid_dma();
            err = NVME_INVALID_FIELD | NVME_DNR;
        }

        qemu_iovec_destroy(&iov);

        return err;
    }

    if (unlikely(dma_buf_write(ptr, len, &qsg))) {
        trace_nvme_err_invalid_dma();
        err = NVME_INVALID_FIELD | NVME_DNR;
    }

    qemu_sglist_destroy(&qsg);

    return err;
}

uint16_t nvme_dma_write(NvmeCtrl *n, uint8_t *ptr, uint32_t len, NvmeCmd *cmd,
    NvmeRequest *req)
{
    if (NVME_CMD_FLAGS_PSDT(cmd->flags)) {
        return nvme_dma_write_sgl(n, ptr, len, cmd->dptr.sgl, req);
    }

    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp.prp2);

    return nvme_dma_write_prp(n, ptr, len, prp1, prp2, req);
}

static uint16_t nvme_dma_read_prp(NvmeCtrl *n, uint8_t *ptr, uint32_t len,
    uint64_t prp1, uint64_t prp2, NvmeRequest *req)
{
    uint16_t err = NVME_SUCCESS;

    err = nvme_map_prp(n, &req->qsg, prp1, prp2, len, req);
    if (err) {
        return err;
    }

    if (req->is_cmb) {
        QEMUIOVector iov;

        qemu_iovec_init(&iov, req->qsg.nsg);
        dma_to_cmb(n, &req->qsg, &iov);

        if (unlikely(qemu_iovec_from_buf(&iov, 0, ptr, len) != len)) {
            trace_nvme_err_invalid_dma();
            err = NVME_INVALID_FIELD | NVME_DNR;
        }

        qemu_iovec_destroy(&iov);

        goto out;
    }

    if (unlikely(dma_buf_read(ptr, len, &req->qsg))) {
        trace_nvme_err_invalid_dma();
        err = NVME_INVALID_FIELD | NVME_DNR;
    }

out:
    qemu_sglist_destroy(&req->qsg);

    return err;
}

uint16_t nvme_dma_read_sgl(NvmeCtrl *n, uint8_t *ptr, uint32_t len,
    NvmeSglDescriptor sgl, NvmeCmd *cmd, NvmeRequest *req)
{
    QEMUSGList qsg;
    uint16_t err = NVME_SUCCESS;

    err = nvme_map_sgl(n, &qsg, sgl, len, req);
    if (err) {
        return err;
    }

    if (req->is_cmb) {
        QEMUIOVector iov;

        qemu_iovec_init(&iov, qsg.nsg);
        dma_to_cmb(n, &qsg, &iov);

        if (unlikely(qemu_iovec_from_buf(&iov, 0, ptr, len) != len)) {
            trace_nvme_err_invalid_dma();
            err = NVME_INVALID_FIELD | NVME_DNR;
        }

        qemu_iovec_destroy(&iov);

        goto out;
    }

    if (unlikely(dma_buf_read(ptr, len, &qsg))) {
        trace_nvme_err_invalid_dma();
        err = NVME_INVALID_FIELD | NVME_DNR;
    }

out:
    qemu_sglist_destroy(&qsg);

    return err;
}

uint16_t nvme_dma_read(NvmeCtrl *n, uint8_t *ptr, uint32_t len,
    NvmeCmd *cmd, NvmeRequest *req)
{
    if (NVME_CMD_FLAGS_PSDT(cmd->flags)) {
        return nvme_dma_read_sgl(n, ptr, len, cmd->dptr.sgl, cmd, req);
    }

    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp.prp2);

    return nvme_dma_read_prp(n, ptr, len, prp1, prp2, req);
}

static void nvme_blk_req_destroy(NvmeBlockBackendRequest *blk_req)
{
    if (blk_req->iov.nalloc) {
        qemu_iovec_destroy(&blk_req->iov);
    }

    g_free(blk_req);
}

void nvme_blk_req_put(NvmeCtrl *n, NvmeBlockBackendRequest *blk_req)
{
    nvme_blk_req_destroy(blk_req);
}

NvmeBlockBackendRequest *nvme_blk_req_get(NvmeCtrl *n, NvmeRequest *req,
    QEMUSGList *qsg)
{
    NvmeBlockBackendRequest *blk_req = g_malloc0(sizeof(*blk_req));

    blk_req->req = req;

    if (qsg) {
        blk_req->qsg = qsg;
    }

    return blk_req;
}

static uint16_t nvme_blk_setup(NvmeCtrl *n, NvmeNamespace *ns, QEMUSGList *qsg,
    uint64_t blk_offset, uint32_t unit_len, NvmeRequest *req)
{
    NvmeBlockBackendRequest *blk_req = nvme_blk_req_get(n, req, qsg);
    if (!blk_req) {
        NVME_GUEST_ERR(nvme_err_internal_dev_error, "nvme_blk_req_get: %s",
            "could not allocate memory");
        return NVME_INTERNAL_DEV_ERROR;
    }

    blk_req->slba = req->slba;
    blk_req->nlb = req->nlb;
    blk_req->blk_offset = blk_offset + req->slba * unit_len;

    QTAILQ_INSERT_TAIL(&req->blk_req_tailq, blk_req, tailq_entry);

    return NVME_SUCCESS;
}

uint16_t nvme_blk_map(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req,
    NvmeBlockSetupFn blk_setup)
{
    NvmeNamespace *ns = req->ns;
    uint16_t err;

    uint32_t unit_len = nvme_ns_lbads_bytes(ns);
    uint32_t len = req->nlb * unit_len;
    uint32_t meta_unit_len = nvme_ns_ms(ns);
    uint32_t meta_len = req->nlb * meta_unit_len;

    NvmeSglDescriptor sgl;

    if (NVME_CMD_FLAGS_PSDT(cmd->flags)) {
        err = nvme_map_sgl(n, &req->qsg, cmd->dptr.sgl, len, req);
        if (err) {
            return err;
        }
    } else {
        uint64_t prp1 = le64_to_cpu(cmd->dptr.prp.prp1);
        uint64_t prp2 = le64_to_cpu(cmd->dptr.prp.prp2);

        err = nvme_map_prp(n, &req->qsg, prp1, prp2, len, req);
        if (err) {
            return err;
        }
    }

    err = blk_setup(n, ns, &req->qsg, ns->blk_offset, unit_len, req);
    if (err) {
        goto out;
    }

    if (ns->params.ms && cmd->mptr) {
        if (NVME_CMD_FLAGS_PSDT(cmd->flags) == PSDT_SGL_MPTR_SGL) {
            nvme_addr_read(n, le64_to_cpu(cmd->mptr), &sgl,
                sizeof(NvmeSglDescriptor));

            err = nvme_map_sgl(n, &req->qsg_md, sgl, meta_len, req);
            if (err) {
                 /*
                 * nvme_map_sgl does not know if it was mapping a data or meta
                 * data SGL, so fix the error code if needed.
                 */
                if (nvme_is_error(err, NVME_DATA_SGL_LENGTH_INVALID)) {
                    err = NVME_METADATA_SGL_LENGTH_INVALID | NVME_DNR;
                }

                return err;
            }
        } else {
            pci_dma_sglist_init(&req->qsg_md, &n->parent_obj, 1);
            qemu_sglist_add(&req->qsg_md, le64_to_cpu(cmd->mptr), meta_len);
        }

        err = blk_setup(n, ns, &req->qsg_md, ns->blk_offset_md, meta_unit_len,
            req);
        if (err) {
            goto out;
        }
    }

    return NVME_SUCCESS;

out:
    qemu_sglist_destroy(&req->qsg);
    if (req->qsg_md.nalloc) {
        qemu_sglist_destroy(&req->qsg_md);
    }

    return err;
}

static void nvme_post_cqes(void *opaque)
{
    NvmeCQueue *cq = opaque;
    NvmeCtrl *n = cq->ctrl;
    NvmeRequest *req, *next;

    QTAILQ_FOREACH_SAFE(req, &cq->req_list, entry, next) {
        NvmeSQueue *sq;
        NvmeCqe *cqe = &req->cqe;
        hwaddr addr;

        if (nvme_cq_full(cq)) {
            break;
        }

        QTAILQ_REMOVE(&cq->req_list, req, entry);
        sq = req->sq;
        req->cqe.status = cpu_to_le16((req->status << 1) | cq->phase);
        req->cqe.sq_id = cpu_to_le16(sq->sqid);
        req->cqe.sq_head = cpu_to_le16(sq->head);
        addr = cq->dma_addr + cq->tail * n->cqe_size;
        nvme_inc_cq_tail(cq);
        nvme_addr_write(n, addr, (void *) cqe, sizeof(*cqe));
        QTAILQ_INSERT_TAIL(&sq->req_list, req, entry);
    }
    if (cq->tail != cq->head) {
        nvme_irq_assert(n, cq);
    }
}

void nvme_enqueue_req_completion(NvmeCQueue *cq, NvmeRequest *req)
{
    assert(cq->cqid == req->sq->cqid);

    if (req->qsg.nalloc) {
        qemu_sglist_destroy(&req->qsg);
    }

    if (req->qsg_md.nalloc) {
        qemu_sglist_destroy(&req->qsg_md);
    }

    trace_nvme_enqueue_req_completion(req->cqe.cid, cq->cqid);
    QTAILQ_REMOVE(&req->sq->out_req_list, req, entry);
    QTAILQ_INSERT_TAIL(&cq->req_list, req, entry);
    timer_mod(cq->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 500);
}

void nvme_enqueue_event(NvmeCtrl *n, uint8_t event_type, uint8_t event_info,
    uint8_t log_page)
{
    NvmeAsyncEvent *event;

    trace_nvme_enqueue_event(event_type, event_info, log_page);

    /*
     * Do not enqueue the event if something of this type is already queued.
     * This bounds the size of the event queue and makes sure it does not grow
     * indefinitely when events are not processed by the host (i.e. does not
     * issue any AERs).
     */
    if (n->aer_mask_queued & (1 << event_type)) {
        return;
    }
    n->aer_mask_queued |= (1 << event_type);

    event = g_new(NvmeAsyncEvent, 1);
    event->result = (NvmeAerResult) {
        .event_type = event_type,
        .event_info = event_info,
        .log_page   = log_page,
    };

    QSIMPLEQ_INSERT_TAIL(&n->aer_queue, event, entry);

    timer_mod(n->aer_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 500);
}

static void nvme_process_aers(void *opaque)
{
    NvmeCtrl *n = opaque;
    NvmeRequest *req;
    NvmeAerResult *result;
    NvmeAsyncEvent *event, *next;

    trace_nvme_process_aers();

    QSIMPLEQ_FOREACH_SAFE(event, &n->aer_queue, entry, next) {
        /* can't post cqe if there is nothing to complete */
        if (!n->outstanding_aers) {
            trace_nvme_no_outstanding_aers();
            break;
        }

        /* ignore if masked (cqe posted, but event not cleared) */
        if (n->aer_mask & (1 << event->result.event_type)) {
            trace_nvme_aer_masked(event->result.event_type, n->aer_mask);
            continue;
        }

        QSIMPLEQ_REMOVE_HEAD(&n->aer_queue, entry);

        n->aer_mask |= 1 << event->result.event_type;
        n->aer_mask_queued &= ~(1 << event->result.event_type);
        n->outstanding_aers--;

        req = n->aer_reqs[n->outstanding_aers];
        result = (NvmeAerResult *) &req->cqe.cdw0;
        result->event_type = event->result.event_type;
        result->event_info = event->result.event_info;
        result->log_page = event->result.log_page;
        g_free(event);

        req->status = NVME_SUCCESS;

        trace_nvme_aer_post_cqe(result->event_type, result->event_info,
            result->log_page);

        nvme_enqueue_req_completion(&n->admin_cq, req);
    }
}

void nvme_noop_cb(void *opaque, int ret)
{
    NvmeBlockBackendRequest *blk_req = opaque;
    NvmeRequest *req = blk_req->req;
    NvmeSQueue *sq = req->sq;
    NvmeCtrl *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];

    QTAILQ_REMOVE(&req->blk_req_tailq, blk_req, tailq_entry);

    if (ret) {
        NVME_GUEST_ERR(nvme_err_internal_dev_error, "block request failed: %s",
            strerror(-ret));
        req->status = NVME_INTERNAL_DEV_ERROR;
    }

    if (QTAILQ_EMPTY(&req->blk_req_tailq)) {
        nvme_enqueue_req_completion(cq, req);
    }

    nvme_blk_req_put(n, blk_req);
}

void nvme_rw_cb(void *opaque, int ret)
{
    NvmeBlockBackendRequest *blk_req = opaque;
    NvmeRequest *req = blk_req->req;
    NvmeSQueue *sq = req->sq;
    NvmeCtrl *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];
    NvmeNamespace *ns = req->ns;

    QTAILQ_REMOVE(&req->blk_req_tailq, blk_req, tailq_entry);

    trace_nvme_rw_cb(req->cqe.cid, ns->params.nsid);

    if (!ret) {
        block_acct_done(blk_get_stats(ns->conf.blk), &blk_req->acct);
    } else {
        block_acct_failed(blk_get_stats(ns->conf.blk), &blk_req->acct);
        NVME_GUEST_ERR(nvme_err_internal_dev_error, "block request failed: %s",
            strerror(-ret));
        req->status = NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }

    if (QTAILQ_EMPTY(&req->blk_req_tailq)) {
        nvme_enqueue_req_completion(cq, req);
    }

    nvme_blk_req_put(n, blk_req);
}

static uint16_t nvme_flush(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeNamespace *ns = req->ns;
    NvmeBlockBackendRequest *blk_req = nvme_blk_req_get(n, req, NULL);
    if (!blk_req) {
        NVME_GUEST_ERR(nvme_err_internal_dev_error, "nvme_blk_req_get: %s",
            "could not allocate memory");
        return NVME_INTERNAL_DEV_ERROR;
    }

    block_acct_start(blk_get_stats(ns->conf.blk), &blk_req->acct, 0,
         BLOCK_ACCT_FLUSH);
    blk_req->aiocb = blk_aio_flush(ns->conf.blk, nvme_rw_cb, blk_req);

    QTAILQ_INSERT_TAIL(&req->blk_req_tailq, blk_req, tailq_entry);

    return NVME_NO_COMPLETE;
}

static uint16_t nvme_write_zeros(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)cmd;
    NvmeNamespace *ns = req->ns;
    NvmeBlockBackendRequest *blk_req;
    const uint8_t lbads = nvme_ns_lbads(req->ns);
    uint64_t slba = le64_to_cpu(rw->slba);
    uint32_t nlb  = le16_to_cpu(rw->nlb) + 1;
    uint64_t offset = slba << lbads;
    uint32_t count = nlb << lbads;

    if (unlikely(slba + nlb > req->ns->id_ns.nsze)) {
        trace_nvme_err_invalid_lba_range(slba, nlb, req->ns->id_ns.nsze);
        return NVME_LBA_RANGE | NVME_DNR;
    }

    blk_req = nvme_blk_req_get(n, req, NULL);
    if (!blk_req) {
        NVME_GUEST_ERR(nvme_err_internal_dev_error, "nvme_blk_req_get: %s",
            "could not allocate memory");
        return NVME_INTERNAL_DEV_ERROR;
    }

    block_acct_start(blk_get_stats(ns->conf.blk), &blk_req->acct, 0,
        BLOCK_ACCT_WRITE);

    blk_req->aiocb = blk_aio_pwrite_zeroes(ns->conf.blk, offset, count,
        BDRV_REQ_MAY_UNMAP, nvme_rw_cb, blk_req);

    QTAILQ_INSERT_TAIL(&req->blk_req_tailq, blk_req, tailq_entry);

    return NVME_NO_COMPLETE;
}

uint16_t nvme_rw_check_req(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeNamespace *ns = req->ns;
    NvmeRwCmd *rw = (NvmeRwCmd *) cmd;

    uint16_t ctrl = le16_to_cpu(rw->control);
    uint32_t data_size = req->nlb << nvme_ns_lbads(ns);

    if (n->params.mdts && data_size > n->page_size * (1 << n->params.mdts)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if ((ctrl & NVME_RW_PRINFO_PRACT) && !(ns->id_ns.dps & DPS_TYPE_MASK)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    return NVME_SUCCESS;
}

static void nvme_blk_submit_dma(NvmeCtrl *n, NvmeBlockBackendRequest *blk_req,
    BlockCompletionFunc *cb)
{
    NvmeRequest *req = blk_req->req;
    NvmeNamespace *ns = req->ns;

    if (req->is_write) {
        dma_acct_start(ns->conf.blk, &blk_req->acct, blk_req->qsg,
            BLOCK_ACCT_WRITE);

        blk_req->aiocb = dma_blk_write(ns->conf.blk, blk_req->qsg,
            blk_req->blk_offset, BDRV_SECTOR_SIZE, cb, blk_req);
    } else {
        dma_acct_start(ns->conf.blk, &blk_req->acct, blk_req->qsg,
            BLOCK_ACCT_READ);

        blk_req->aiocb = dma_blk_read(ns->conf.blk, blk_req->qsg,
            blk_req->blk_offset, BDRV_SECTOR_SIZE, cb, blk_req);
    }
}

static void nvme_blk_submit_cmb(NvmeCtrl *n, NvmeBlockBackendRequest *blk_req,
    BlockCompletionFunc *cb)
{
    NvmeRequest *req = blk_req->req;
    NvmeNamespace *ns = req->ns;

    qemu_iovec_init(&blk_req->iov, blk_req->qsg->nsg);
    dma_to_cmb(n, blk_req->qsg, &blk_req->iov);

    if (req->is_write) {
        block_acct_start(blk_get_stats(ns->conf.blk), &blk_req->acct,
            blk_req->iov.size, BLOCK_ACCT_WRITE);

        blk_req->aiocb = blk_aio_pwritev(ns->conf.blk, blk_req->blk_offset,
            &blk_req->iov, 0, cb, blk_req);
    } else {
        block_acct_start(blk_get_stats(ns->conf.blk), &blk_req->acct,
            blk_req->iov.size, BLOCK_ACCT_READ);

        blk_req->aiocb = blk_aio_preadv(ns->conf.blk, blk_req->blk_offset,
            &blk_req->iov, 0, cb, blk_req);
    }
}

uint16_t nvme_blk_submit_io(NvmeCtrl *n, NvmeRequest *req,
    BlockCompletionFunc *cb)
{
    NvmeBlockBackendRequest *blk_req;

    if (QTAILQ_EMPTY(&req->blk_req_tailq)) {
        return NVME_SUCCESS;
    }

    QTAILQ_FOREACH(blk_req, &req->blk_req_tailq, tailq_entry) {
        if (req->is_cmb) {
            nvme_blk_submit_cmb(n, blk_req, cb);
        } else {
            nvme_blk_submit_dma(n, blk_req, cb);
        }
    }

    return NVME_NO_COMPLETE;
}

static uint16_t nvme_rw(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)cmd;
    uint32_t nlb  = le32_to_cpu(rw->nlb) + 1;
    uint64_t slba = le64_to_cpu(rw->slba);

    req->is_write = nvme_rw_is_write(req);

    trace_nvme_rw(req->is_write ? "write" : "read", nlb,
        nlb << nvme_ns_lbads(req->ns), slba);

int err = nvme_blk_map(n, cmd, req, nvme_blk_setup);
    if (err) {
        return err;
    }

    return nvme_blk_submit_io(n, req, nvme_rw_cb);
}

uint16_t nvme_io_cmd(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeRwCmd *rw;
    int err;

    uint32_t nsid = le32_to_cpu(cmd->nsid);

    if (unlikely(nsid == 0 || nsid > n->num_namespaces)) {
        trace_nvme_err_invalid_ns(nsid, n->num_namespaces);
        return NVME_INVALID_NSID | NVME_DNR;
    }

    req->ns = n->namespaces[nsid - 1];

    switch (cmd->opcode) {
    case NVME_CMD_FLUSH:
        return nvme_flush(n, cmd, req);
    case NVME_CMD_WRITE_ZEROS:
        return nvme_write_zeros(n, cmd, req);
    case NVME_CMD_WRITE:
    case NVME_CMD_READ:
        rw = (NvmeRwCmd *)cmd;

        req->nlb  = le16_to_cpu(rw->nlb) + 1;
        req->slba = le64_to_cpu(rw->slba);

        err = nvme_rw_check_req(n, cmd, req);
        if (err) {
            return err;
        }

        return nvme_rw(n, cmd, req);
    default:
        trace_nvme_err_invalid_opc(cmd->opcode);
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

static void nvme_free_sq(NvmeSQueue *sq, NvmeCtrl *n)
{
    n->sq[sq->sqid] = NULL;
    timer_del(sq->timer);
    timer_free(sq->timer);
    g_free(sq->io_req);
    if (sq->sqid) {
        g_free(sq);
    }
    n->qs_created--;
}

static uint16_t nvme_del_sq(NvmeCtrl *n, NvmeCmd *cmd)
{
    NvmeDeleteQ *c = (NvmeDeleteQ *)cmd;
    NvmeRequest *req, *next;
    NvmeSQueue *sq;
    NvmeCQueue *cq;
    NvmeBlockBackendRequest *blk_req;
    uint16_t qid = le16_to_cpu(c->qid);

    if (unlikely(!qid || nvme_check_sqid(n, qid))) {
        trace_nvme_err_invalid_del_sq(qid);
        return NVME_INVALID_QID | NVME_DNR;
    }

    trace_nvme_del_sq(qid);

    sq = n->sq[qid];
    while (!QTAILQ_EMPTY(&sq->out_req_list)) {
        req = QTAILQ_FIRST(&sq->out_req_list);
        while (!QTAILQ_EMPTY(&req->blk_req_tailq)) {
            blk_req = QTAILQ_FIRST(&req->blk_req_tailq);
            assert(blk_req->aiocb);
            blk_aio_cancel(blk_req->aiocb);
        }
    }
    if (!nvme_check_cqid(n, sq->cqid)) {
        cq = n->cq[sq->cqid];
        QTAILQ_REMOVE(&cq->sq_list, sq, entry);

        nvme_post_cqes(cq);
        QTAILQ_FOREACH_SAFE(req, &cq->req_list, entry, next) {
            if (req->sq == sq) {
                QTAILQ_REMOVE(&cq->req_list, req, entry);
                QTAILQ_INSERT_TAIL(&sq->req_list, req, entry);
            }
        }
    }

    nvme_free_sq(sq, n);
    return NVME_SUCCESS;
}

static void nvme_init_sq(NvmeSQueue *sq, NvmeCtrl *n, uint64_t dma_addr,
    uint16_t sqid, uint16_t cqid, uint16_t size)
{
    int i;
    NvmeCQueue *cq;

    sq->ctrl = n;
    sq->dma_addr = dma_addr;
    sq->sqid = sqid;
    sq->size = size;
    sq->cqid = cqid;
    sq->head = sq->tail = 0;
    sq->io_req = g_new0(NvmeRequest, sq->size);

    QTAILQ_INIT(&sq->req_list);
    QTAILQ_INIT(&sq->out_req_list);
    for (i = 0; i < sq->size; i++) {
        sq->io_req[i].sq = sq;
        QTAILQ_INIT(&(sq->io_req[i].blk_req_tailq));
        QTAILQ_INSERT_TAIL(&(sq->req_list), &sq->io_req[i], entry);
    }
    sq->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, nvme_process_sq, sq);

    assert(n->cq[cqid]);
    cq = n->cq[cqid];
    QTAILQ_INSERT_TAIL(&(cq->sq_list), sq, entry);
    n->sq[sqid] = sq;
    n->qs_created++;
}

static uint16_t nvme_create_sq(NvmeCtrl *n, NvmeCmd *cmd)
{
    NvmeSQueue *sq;
    NvmeCreateSq *c = (NvmeCreateSq *)cmd;

    uint16_t cqid = le16_to_cpu(c->cqid);
    uint16_t sqid = le16_to_cpu(c->sqid);
    uint16_t qsize = le16_to_cpu(c->qsize);
    uint16_t qflags = le16_to_cpu(c->sq_flags);
    uint64_t prp1 = le64_to_cpu(c->prp1);

    trace_nvme_create_sq(prp1, sqid, cqid, qsize, qflags);

    if (unlikely(!cqid || nvme_check_cqid(n, cqid))) {
        trace_nvme_err_invalid_create_sq_cqid(cqid);
        return NVME_INVALID_CQID | NVME_DNR;
    }
    if (unlikely(!sqid || !nvme_check_sqid(n, sqid))) {
        trace_nvme_err_invalid_create_sq_sqid(sqid);
        return NVME_INVALID_QID | NVME_DNR;
    }
    if (unlikely(!qsize || qsize > NVME_CAP_MQES(n->bar.cap))) {
        trace_nvme_err_invalid_create_sq_size(qsize);
        return NVME_MAX_QSIZE_EXCEEDED | NVME_DNR;
    }
    if (unlikely(!prp1 || prp1 & (n->page_size - 1))) {
        trace_nvme_err_invalid_create_sq_addr(prp1);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (unlikely(!(NVME_SQ_FLAGS_PC(qflags)))) {
        trace_nvme_err_invalid_create_sq_qflags(NVME_SQ_FLAGS_PC(qflags));
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    sq = g_malloc0(sizeof(*sq));
    nvme_init_sq(sq, n, prp1, sqid, cqid, qsize + 1);
    return NVME_SUCCESS;
}

static void nvme_free_cq(NvmeCQueue *cq, NvmeCtrl *n)
{
    n->cq[cq->cqid] = NULL;
    timer_del(cq->timer);
    timer_free(cq->timer);
    msix_vector_unuse(&n->parent_obj, cq->vector);
    if (cq->cqid) {
        g_free(cq);
    }
    n->qs_created--;
}

static uint16_t nvme_del_cq(NvmeCtrl *n, NvmeCmd *cmd)
{
    NvmeDeleteQ *c = (NvmeDeleteQ *)cmd;
    NvmeCQueue *cq;
    uint16_t qid = le16_to_cpu(c->qid);

    if (unlikely(!qid || nvme_check_cqid(n, qid))) {
        trace_nvme_err_invalid_del_cq_cqid(qid);
        return NVME_INVALID_CQID | NVME_DNR;
    }

    cq = n->cq[qid];
    if (unlikely(!QTAILQ_EMPTY(&cq->sq_list))) {
        trace_nvme_err_invalid_del_cq_notempty(qid);
        return NVME_INVALID_QUEUE_DEL;
    }
    nvme_irq_deassert(n, cq);
    trace_nvme_del_cq(qid);
    nvme_free_cq(cq, n);
    return NVME_SUCCESS;
}

static void nvme_init_cq(NvmeCQueue *cq, NvmeCtrl *n, uint64_t dma_addr,
    uint16_t cqid, uint16_t vector, uint16_t size, uint16_t irq_enabled)
{
    cq->ctrl = n;
    cq->cqid = cqid;
    cq->size = size;
    cq->dma_addr = dma_addr;
    cq->phase = 1;
    cq->irq_enabled = irq_enabled;
    cq->vector = vector;
    cq->head = cq->tail = 0;
    QTAILQ_INIT(&cq->req_list);
    QTAILQ_INIT(&cq->sq_list);
    msix_vector_use(&n->parent_obj, cq->vector);
    n->cq[cqid] = cq;
    cq->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, nvme_post_cqes, cq);
    n->qs_created++;
}

static uint16_t nvme_create_cq(NvmeCtrl *n, NvmeCmd *cmd)
{
    NvmeCQueue *cq;
    NvmeCreateCq *c = (NvmeCreateCq *)cmd;
    uint16_t cqid = le16_to_cpu(c->cqid);
    uint16_t vector = le16_to_cpu(c->irq_vector);
    uint16_t qsize = le16_to_cpu(c->qsize);
    uint16_t qflags = le16_to_cpu(c->cq_flags);
    uint64_t prp1 = le64_to_cpu(c->prp1);

    trace_nvme_create_cq(prp1, cqid, vector, qsize, qflags,
                         NVME_CQ_FLAGS_IEN(qflags) != 0);

    if (unlikely(!cqid || !nvme_check_cqid(n, cqid))) {
        trace_nvme_err_invalid_create_cq_cqid(cqid);
        return NVME_INVALID_CQID | NVME_DNR;
    }
    if (unlikely(!qsize || qsize > NVME_CAP_MQES(n->bar.cap))) {
        trace_nvme_err_invalid_create_cq_size(qsize);
        return NVME_MAX_QSIZE_EXCEEDED | NVME_DNR;
    }
    if (unlikely(!prp1)) {
        trace_nvme_err_invalid_create_cq_addr(prp1);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (unlikely(vector > n->params.num_queues)) {
        trace_nvme_err_invalid_create_cq_vector(vector);
        return NVME_INVALID_IRQ_VECTOR | NVME_DNR;
    }
    if (unlikely(!(NVME_CQ_FLAGS_PC(qflags)))) {
        trace_nvme_err_invalid_create_cq_qflags(NVME_CQ_FLAGS_PC(qflags));
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    cq = g_malloc0(sizeof(*cq));
    nvme_init_cq(cq, n, prp1, cqid, vector, qsize + 1,
        NVME_CQ_FLAGS_IEN(qflags));
    return NVME_SUCCESS;
}

static uint16_t nvme_identify_ctrl(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    trace_nvme_identify_ctrl();

    return nvme_dma_read(n, (uint8_t *) &n->id_ctrl, sizeof(n->id_ctrl), cmd,
        req);
}

static uint16_t nvme_identify_ns(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeNamespace *ns;
    uint32_t nsid = le32_to_cpu(cmd->nsid);

    trace_nvme_identify_ns(nsid);

    if (unlikely(nsid == 0 || nsid > n->num_namespaces)) {
        trace_nvme_err_invalid_ns(nsid, n->num_namespaces);
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ns = n->namespaces[nsid - 1];

    return nvme_dma_read(n, (uint8_t *) &ns->id_ns, sizeof(ns->id_ns), cmd,
        req);
}

static uint16_t nvme_identify_ns_list(NvmeCtrl *n, NvmeCmd *cmd,
    NvmeRequest *req)
{
    static const int data_len = 4 * KiB;
    uint32_t min_nsid = le32_to_cpu(cmd->nsid);
    uint32_t *list;
    uint16_t ret;
    int i, j = 0;

    trace_nvme_identify_ns_list(min_nsid);

    list = g_malloc0(data_len);
    for (i = 0; i < n->num_namespaces; i++) {
        if (i < min_nsid) {
            continue;
        }
        list[j++] = cpu_to_le32(i + 1);
        if (j == data_len / sizeof(uint32_t)) {
            break;
        }
    }
    ret = nvme_dma_read(n, (uint8_t *) list, data_len, cmd, req);
    g_free(list);
    return ret;
}

static uint16_t nvme_identify_ns_descriptor_list(NvmeCtrl *n, NvmeCmd *cmd,
    NvmeRequest *req)
{
    static const int data_len = 4 * KiB;

    /*
     * The device model does not have anywhere to store a persistent UUID, so
     * conjure up something that is reproducible. We generate an UUID of the
     * form "00000000-0000-0000-0000-<nsid>", where nsid is similar to, say,
     * 000000000001.
     */
    struct ns_descr {
        uint8_t nidt;
        uint8_t nidl;
        uint8_t rsvd[14];
        uint32_t nid;
    };

    uint32_t nsid = le32_to_cpu(cmd->nsid);

    struct ns_descr *list;
    uint16_t ret;

    trace_nvme_identify_ns_descriptor_list(nsid);

    if (unlikely(nsid == 0 || nsid > n->num_namespaces)) {
        trace_nvme_err_invalid_ns(nsid, n->num_namespaces);
        return NVME_INVALID_NSID | NVME_DNR;
    }

    list = g_malloc0(data_len);
    list->nidt = 0x3;
    list->nidl = 0x10;
    list->nid = cpu_to_be32(nsid);

    ret = nvme_dma_read(n, (uint8_t *) list, data_len, cmd, req);
    g_free(list);
    return ret;
}

static uint16_t nvme_identify(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeIdentify *c = (NvmeIdentify *)cmd;

    switch (le32_to_cpu(c->cns)) {
    case 0x00:
        return nvme_identify_ns(n, cmd, req);
    case 0x01:
        return nvme_identify_ctrl(n, cmd, req);
    case 0x02:
        return nvme_identify_ns_list(n, cmd, req);
    case 0x03:
        return nvme_identify_ns_descriptor_list(n, cmd, req);
    default:
        trace_nvme_err_invalid_identify_cns(le32_to_cpu(c->cns));
        return NVME_INVALID_FIELD | NVME_DNR;
    }
}

static inline void nvme_set_timestamp(NvmeCtrl *n, uint64_t ts)
{
    trace_nvme_setfeat_timestamp(ts);

    n->host_timestamp = le64_to_cpu(ts);
    n->timestamp_set_qemu_clock_ms = qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL);
}

static inline uint64_t nvme_get_timestamp(const NvmeCtrl *n)
{
    uint64_t current_time = qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL);
    uint64_t elapsed_time = current_time - n->timestamp_set_qemu_clock_ms;

    union nvme_timestamp {
        struct {
            uint64_t timestamp:48;
            uint64_t sync:1;
            uint64_t origin:3;
            uint64_t rsvd1:12;
        };
        uint64_t all;
    };

    union nvme_timestamp ts;
    ts.all = 0;

    /*
     * If the sum of the Timestamp value set by the host and the elapsed
     * time exceeds 2^48, the value returned should be reduced modulo 2^48.
     */
    ts.timestamp = (n->host_timestamp + elapsed_time) & 0xffffffffffff;

    /* If the host timestamp is non-zero, set the timestamp origin */
    ts.origin = n->host_timestamp ? 0x01 : 0x00;

    trace_nvme_getfeat_timestamp(ts.all);

    return cpu_to_le64(ts.all);
}

static uint16_t nvme_get_feature_timestamp(NvmeCtrl *n, NvmeCmd *cmd,
    NvmeRequest *req)
{
    uint64_t timestamp = nvme_get_timestamp(n);

    return nvme_dma_read(n, (uint8_t *)&timestamp, sizeof(timestamp), cmd,
        req);
}

uint16_t nvme_get_feature(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeNamespace *ns = req->ns;

    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint32_t dw11 = le32_to_cpu(cmd->cdw11);
    uint32_t result;

    trace_nvme_getfeat(dw10);

    switch (dw10) {
    case NVME_ARBITRATION:
        result = cpu_to_le32(n->features.arbitration);
        break;
    case NVME_POWER_MANAGEMENT:
        result = cpu_to_le32(n->features.power_mgmt);
        break;
    case NVME_TEMPERATURE_THRESHOLD:
        result = cpu_to_le32(n->features.temp_thresh);
        break;
    case NVME_ERROR_RECOVERY:
        result = cpu_to_le32(n->features.err_rec);
        break;
    case NVME_VOLATILE_WRITE_CACHE:
        result = blk_enable_write_cache(ns->conf.blk);
        trace_nvme_getfeat_vwcache(result ? "enabled" : "disabled");
        break;
    case NVME_NUMBER_OF_QUEUES:
        result = cpu_to_le32((n->params.num_queues - 2) |
            ((n->params.num_queues - 2) << 16));
        trace_nvme_getfeat_numq(result);
        break;
    case NVME_TIMESTAMP:
        return nvme_get_feature_timestamp(n, cmd, req);
    case NVME_INTERRUPT_COALESCING:
        result = cpu_to_le32(n->features.int_coalescing);
        break;
    case NVME_INTERRUPT_VECTOR_CONF:
        if ((dw11 & 0xffff) > n->params.num_queues) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }

        result = cpu_to_le32(n->features.int_vector_config[dw11 & 0xffff]);
        break;
    case NVME_WRITE_ATOMICITY:
        result = cpu_to_le32(n->features.write_atomicity);
        break;
    case NVME_ASYNCHRONOUS_EVENT_CONF:
        result = cpu_to_le32(n->features.async_config);
        break;
    default:
        trace_nvme_err_invalid_getfeat(dw10);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    req->cqe.cdw0 = result;
    return NVME_SUCCESS;
}

static uint16_t nvme_set_feature_timestamp(NvmeCtrl *n, NvmeCmd *cmd,
    NvmeRequest *req)
{
    uint16_t ret;
    uint64_t timestamp;

    ret = nvme_dma_write(n, (uint8_t *)&timestamp, sizeof(timestamp), cmd,
        req);
    if (ret != NVME_SUCCESS) {
        return ret;
    }

    nvme_set_timestamp(n, timestamp);

    return NVME_SUCCESS;
}

uint16_t nvme_set_feature(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeNamespace *ns = req->ns;

    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint32_t dw11 = le32_to_cpu(cmd->cdw11);

    trace_nvme_setfeat(dw10, dw11);

    switch (dw10) {
    case NVME_TEMPERATURE_THRESHOLD:
        n->features.temp_thresh = dw11;
        if (n->features.temp_thresh <= n->temperature) {
            nvme_enqueue_event(n, NVME_AER_TYPE_SMART,
                NVME_AER_INFO_SMART_TEMP_THRESH, NVME_LOG_SMART_INFO);
        }
        break;
    case NVME_VOLATILE_WRITE_CACHE:
        blk_set_enable_write_cache(ns->conf.blk, dw11 & 1);
        break;
    case NVME_NUMBER_OF_QUEUES:
        if (n->qs_created > 2) {
            return NVME_CMD_SEQ_ERROR | NVME_DNR;
        }

        if ((dw11 & 0xffff) == 0xffff || ((dw11 >> 16) & 0xffff) == 0xffff) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }

        trace_nvme_setfeat_numq((dw11 & 0xFFFF) + 1,
                                ((dw11 >> 16) & 0xFFFF) + 1,
                                n->params.num_queues - 1,
                                n->params.num_queues - 1);
        req->cqe.cdw0 = cpu_to_le32((n->params.num_queues - 2) |
            ((n->params.num_queues - 2) << 16));
        break;
    case NVME_TIMESTAMP:
        return nvme_set_feature_timestamp(n, cmd, req);
    case NVME_ASYNCHRONOUS_EVENT_CONF:
        n->features.async_config = dw11;
        break;
    case NVME_ARBITRATION:
    case NVME_POWER_MANAGEMENT:
    case NVME_ERROR_RECOVERY:
    case NVME_INTERRUPT_COALESCING:
    case NVME_INTERRUPT_VECTOR_CONF:
    case NVME_WRITE_ATOMICITY:
        return NVME_FEAT_NOT_CHANGABLE | NVME_DNR;
    default:
        trace_nvme_err_invalid_setfeat(dw10);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    return NVME_SUCCESS;
}

void nvme_clear_events(NvmeCtrl *n, uint8_t event_type)
{
    n->aer_mask &= ~(1 << event_type);
    if (!QSIMPLEQ_EMPTY(&n->aer_queue)) {
        timer_mod(n->aer_timer,
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 500);
    }
}

static uint16_t nvme_error_log_info(NvmeCtrl *n, NvmeCmd *cmd, uint8_t rae,
    uint32_t buf_len, uint64_t off, NvmeRequest *req)
{
    uint32_t trans_len;

    if (off > sizeof(*n->elpes) * (NVME_ELPE + 1)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    trans_len = MIN(sizeof(*n->elpes) * (NVME_ELPE + 1) - off, buf_len);

    if (!rae) {
        nvme_clear_events(n, NVME_AER_TYPE_ERROR);
    }

    return nvme_dma_read(n, (uint8_t *) n->elpes + off, trans_len, cmd, req);
}

static uint16_t nvme_smart_info(NvmeCtrl *n, NvmeCmd *cmd, uint8_t rae,
    uint32_t buf_len, uint64_t off, NvmeRequest *req)
{
    uint32_t trans_len;
    time_t current_ms;
    NvmeSmartLog smart;

    if (cmd->nsid != 0 && cmd->nsid != 0xffffffff) {
        trace_nvme_err(req->cqe.cid, "smart log not supported for namespace",
            NVME_INVALID_FIELD | NVME_DNR);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (off > sizeof(smart)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    trans_len = MIN(sizeof(smart) - off, buf_len);

    memset(&smart, 0x0, sizeof(smart));
    smart.number_of_error_log_entries[0] = cpu_to_le64(0);
    smart.temperature[0] = n->temperature & 0xff;
    smart.temperature[1] = (n->temperature >> 8) & 0xff;

    if (n->features.temp_thresh <= n->temperature) {
        smart.critical_warning |= NVME_SMART_TEMPERATURE;
    }

    current_ms = qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL);
    smart.power_on_hours[0] = cpu_to_le64(
        (((current_ms - n->starttime_ms) / 1000) / 60) / 60);

    if (!rae) {
        nvme_clear_events(n, NVME_AER_TYPE_SMART);
    }

    return nvme_dma_read(n, (uint8_t *) &smart + off, trans_len, cmd, req);
}

static uint16_t nvme_fw_log_info(NvmeCtrl *n, NvmeCmd *cmd, uint32_t buf_len,
    uint64_t off, NvmeRequest *req)
{
    uint32_t trans_len;
    NvmeFwSlotInfoLog fw_log;

    if (off > sizeof(fw_log)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    memset(&fw_log, 0, sizeof(NvmeFwSlotInfoLog));

    trans_len = MIN(sizeof(fw_log) - off, buf_len);

    return nvme_dma_read(n, (uint8_t *) &fw_log + off, trans_len, cmd, req);
}

uint16_t nvme_get_log(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint32_t dw11 = le32_to_cpu(cmd->cdw11);
    uint32_t dw12 = le32_to_cpu(cmd->cdw12);
    uint32_t dw13 = le32_to_cpu(cmd->cdw13);
    uint16_t lid = dw10 & 0xff;
    uint8_t  rae = (dw10 >> 15) & 0x1;
    uint32_t numdl, numdu, len;
    uint64_t off, lpol, lpou;

    numdl = (dw10 >> 16);
    numdu = (dw11 & 0xffff);
    lpol = dw12;
    lpou = dw13;

    len = (((numdu << 16) | numdl) + 1) << 2;
    off = (lpou << 32ULL) | lpol;

    if (off & 0x3) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    trace_nvme_get_log(req->cqe.cid, lid);

    switch (lid) {
    case NVME_LOG_ERROR_INFO:
        return nvme_error_log_info(n, cmd, rae, len, off, req);
    case NVME_LOG_SMART_INFO:
        return nvme_smart_info(n, cmd, rae, len, off, req);
    case NVME_LOG_FW_SLOT_INFO:
        return nvme_fw_log_info(n, cmd, len, off, req);
    default:
        trace_nvme_err_invalid_log_page(req->cqe.cid, lid);
        return NVME_INVALID_LOG_ID | NVME_DNR;
    }
}

static uint16_t nvme_aer(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    trace_nvme_aer(req->cqe.cid);

    if (n->outstanding_aers > NVME_AERL) {
        trace_nvme_aer_aerl_exceeded();
        return NVME_AER_LIMIT_EXCEEDED;
    }

    n->aer_reqs[n->outstanding_aers] = req;
    timer_mod(n->aer_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 500);
    n->outstanding_aers++;

    return NVME_NO_COMPLETE;
}

static uint16_t nvme_abort(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeSQueue *sq;
    NvmeRequest *new;
    uint32_t index = 0;
    uint16_t sqid = cmd->cdw10 & 0xffff;
    uint16_t cid = (cmd->cdw10 >> 16) & 0xffff;

    req->cqe.cdw0 = 1;
    if (nvme_check_sqid(n, sqid)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    sq = n->sq[sqid];

    /* only consider queued (and not executing) commands for abort */
    while ((sq->head + index) % sq->size != sq->tail) {
        NvmeCmd abort_cmd;
        hwaddr addr;

        addr = sq->dma_addr + ((sq->head + index) % sq->size) * n->sqe_size;

        nvme_addr_read(n, addr, (void *) &abort_cmd, sizeof(abort_cmd));
        if (abort_cmd.cid == cid) {
            req->cqe.cdw0 = 0;
            new = QTAILQ_FIRST(&sq->req_list);
            QTAILQ_REMOVE(&sq->req_list, new, entry);
            QTAILQ_INSERT_TAIL(&sq->out_req_list, new, entry);

            memset(&new->cqe, 0, sizeof(new->cqe));
            new->cqe.cid = cid;
            new->status = NVME_CMD_ABORT_REQ;

            abort_cmd.opcode = NVME_OP_ABORTED;
            nvme_addr_write(n, addr, (void *) &abort_cmd, sizeof(abort_cmd));

            nvme_enqueue_req_completion(n->cq[sq->cqid], new);

            return NVME_SUCCESS;
        }

        ++index;
    }

    return NVME_SUCCESS;
}

uint16_t nvme_admin_cmd(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    switch (cmd->opcode) {
    case NVME_ADM_CMD_DELETE_SQ:
        return nvme_del_sq(n, cmd);
    case NVME_ADM_CMD_CREATE_SQ:
        return nvme_create_sq(n, cmd);
    case NVME_ADM_CMD_DELETE_CQ:
        return nvme_del_cq(n, cmd);
    case NVME_ADM_CMD_CREATE_CQ:
        return nvme_create_cq(n, cmd);
    case NVME_ADM_CMD_IDENTIFY:
        return nvme_identify(n, cmd, req);
    case NVME_ADM_CMD_SET_FEATURES:
        return nvme_set_feature(n, cmd, req);
    case NVME_ADM_CMD_GET_FEATURES:
        return nvme_get_feature(n, cmd, req);
    case NVME_ADM_CMD_GET_LOG_PAGE:
        return nvme_get_log(n, cmd, req);
    case NVME_ADM_CMD_ASYNC_EV_REQ:
        return nvme_aer(n, cmd, req);
    case NVME_ADM_CMD_ABORT:
        return nvme_abort(n, cmd, req);
    default:
        trace_nvme_err_invalid_admin_opc(cmd->opcode);
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

static void nvme_init_req(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    memset(&req->cqe, 0, sizeof(req->cqe));
    req->cqe.cid = le16_to_cpu(cmd->cid);

    memcpy(&req->cmd, cmd, sizeof(NvmeCmd));
    req->is_cmb = false;

    req->status = NVME_SUCCESS;
}

static void nvme_process_sq(void *opaque)
{
    NvmeSQueue *sq = opaque;
    NvmeCtrl *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];

    uint16_t status;
    hwaddr addr;
    NvmeCmd cmd;
    NvmeRequest *req;

    while (!(nvme_sq_empty(sq) || QTAILQ_EMPTY(&sq->req_list))) {
        addr = sq->dma_addr + sq->head * n->sqe_size;
        nvme_addr_read(n, addr, (void *)&cmd, sizeof(cmd));
        nvme_inc_sq_head(sq);

        if (cmd.opcode == NVME_OP_ABORTED) {
            continue;
        }

        req = QTAILQ_FIRST(&sq->req_list);
        QTAILQ_REMOVE(&sq->req_list, req, entry);
        QTAILQ_INSERT_TAIL(&sq->out_req_list, req, entry);

        nvme_init_req(n, &cmd, req);

        status = sq->sqid ? n->io_cmd(n, &cmd, req) :
            n->admin_cmd(n, &cmd, req);
        if (status != NVME_NO_COMPLETE) {
            req->status = status;
            nvme_enqueue_req_completion(cq, req);
        }
    }
}

static void nvme_clear_ctrl(NvmeCtrl *n)
{
    NvmeAsyncEvent *event;
    int i;

    for (int i = 0; i < n->num_namespaces; i++) {
        blk_drain(n->namespaces[i]->conf.blk);
    }

    for (i = 0; i < n->params.num_queues; i++) {
        if (n->sq[i] != NULL) {
            nvme_free_sq(n->sq[i], n);
        }
    }
    for (i = 0; i < n->params.num_queues; i++) {
        if (n->cq[i] != NULL) {
            nvme_free_cq(n->cq[i], n);
        }
    }

    if (n->aer_timer) {
        timer_del(n->aer_timer);
        timer_free(n->aer_timer);
        n->aer_timer = NULL;
    }
    while ((event = QSIMPLEQ_FIRST(&n->aer_queue)) != NULL) {
        QSIMPLEQ_REMOVE_HEAD(&n->aer_queue, entry);
        g_free(event);
    }

    for (int i = 0; i < n->num_namespaces; i++) {
        blk_flush(n->namespaces[i]->conf.blk);
    }

    n->bar.cc = 0;
    n->outstanding_aers = 0;
}

static int nvme_start_ctrl(NvmeCtrl *n)
{
    uint32_t page_bits = NVME_CC_MPS(n->bar.cc) + 12;
    uint32_t page_size = 1 << page_bits;

    if (unlikely(n->cq[0])) {
        trace_nvme_err_startfail_cq();
        return -1;
    }
    if (unlikely(n->sq[0])) {
        trace_nvme_err_startfail_sq();
        return -1;
    }
    if (unlikely(!n->bar.asq)) {
        trace_nvme_err_startfail_nbarasq();
        return -1;
    }
    if (unlikely(!n->bar.acq)) {
        trace_nvme_err_startfail_nbaracq();
        return -1;
    }
    if (unlikely(n->bar.asq & (page_size - 1))) {
        trace_nvme_err_startfail_asq_misaligned(n->bar.asq);
        return -1;
    }
    if (unlikely(n->bar.acq & (page_size - 1))) {
        trace_nvme_err_startfail_acq_misaligned(n->bar.acq);
        return -1;
    }
    if (unlikely(NVME_CC_MPS(n->bar.cc) <
                 NVME_CAP_MPSMIN(n->bar.cap))) {
        trace_nvme_err_startfail_page_too_small(
                    NVME_CC_MPS(n->bar.cc),
                    NVME_CAP_MPSMIN(n->bar.cap));
        return -1;
    }
    if (unlikely(NVME_CC_MPS(n->bar.cc) >
                 NVME_CAP_MPSMAX(n->bar.cap))) {
        trace_nvme_err_startfail_page_too_large(
                    NVME_CC_MPS(n->bar.cc),
                    NVME_CAP_MPSMAX(n->bar.cap));
        return -1;
    }
    if (unlikely(NVME_CC_IOCQES(n->bar.cc) <
                 NVME_CTRL_CQES_MIN(n->id_ctrl.cqes))) {
        trace_nvme_err_startfail_cqent_too_small(
                    NVME_CC_IOCQES(n->bar.cc),
                    NVME_CTRL_CQES_MIN(n->bar.cap));
        return -1;
    }
    if (unlikely(NVME_CC_IOCQES(n->bar.cc) >
                 NVME_CTRL_CQES_MAX(n->id_ctrl.cqes))) {
        trace_nvme_err_startfail_cqent_too_large(
                    NVME_CC_IOCQES(n->bar.cc),
                    NVME_CTRL_CQES_MAX(n->bar.cap));
        return -1;
    }
    if (unlikely(NVME_CC_IOSQES(n->bar.cc) <
                 NVME_CTRL_SQES_MIN(n->id_ctrl.sqes))) {
        trace_nvme_err_startfail_sqent_too_small(
                    NVME_CC_IOSQES(n->bar.cc),
                    NVME_CTRL_SQES_MIN(n->bar.cap));
        return -1;
    }
    if (unlikely(NVME_CC_IOSQES(n->bar.cc) >
                 NVME_CTRL_SQES_MAX(n->id_ctrl.sqes))) {
        trace_nvme_err_startfail_sqent_too_large(
                    NVME_CC_IOSQES(n->bar.cc),
                    NVME_CTRL_SQES_MAX(n->bar.cap));
        return -1;
    }
    if (unlikely(!NVME_AQA_ASQS(n->bar.aqa))) {
        trace_nvme_err_startfail_asqent_sz_zero();
        return -1;
    }
    if (unlikely(!NVME_AQA_ACQS(n->bar.aqa))) {
        trace_nvme_err_startfail_acqent_sz_zero();
        return -1;
    }

    n->page_bits = page_bits;
    n->page_size = page_size;
    n->max_prp_ents = n->page_size / sizeof(uint64_t);
    n->cqe_size = 1 << NVME_CC_IOCQES(n->bar.cc);
    n->sqe_size = 1 << NVME_CC_IOSQES(n->bar.cc);
    nvme_init_cq(&n->admin_cq, n, n->bar.acq, 0, 0,
        NVME_AQA_ACQS(n->bar.aqa) + 1, 1);
    nvme_init_sq(&n->admin_sq, n, n->bar.asq, 0, 0,
        NVME_AQA_ASQS(n->bar.aqa) + 1);

    nvme_set_timestamp(n, 0ULL);

    n->aer_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, nvme_process_aers, n);
    QSIMPLEQ_INIT(&n->aer_queue);

    return 0;
}

static void nvme_write_bar(NvmeCtrl *n, hwaddr offset, uint64_t data,
    unsigned size)
{
    if (unlikely(offset & (sizeof(uint32_t) - 1))) {
        NVME_GUEST_ERR(nvme_ub_mmiowr_misaligned32,
                       "MMIO write not 32-bit aligned,"
                       " offset=0x%"PRIx64"", offset);
        /* should be ignored, fall through for now */
    }

    if (unlikely(size < sizeof(uint32_t))) {
        NVME_GUEST_ERR(nvme_ub_mmiowr_toosmall,
                       "MMIO write smaller than 32-bits,"
                       " offset=0x%"PRIx64", size=%u",
                       offset, size);
        /* should be ignored, fall through for now */
    }

    switch (offset) {
    case 0xc:   /* INTMS */
        if (unlikely(msix_enabled(&(n->parent_obj)))) {
            NVME_GUEST_ERR(nvme_ub_mmiowr_intmask_with_msix,
                           "undefined access to interrupt mask set"
                           " when MSI-X is enabled");
            /* should be ignored, fall through for now */
        }
        n->bar.intms |= data & 0xffffffff;
        n->bar.intmc = n->bar.intms;
        trace_nvme_mmio_intm_set(data & 0xffffffff,
                                 n->bar.intmc);
        nvme_irq_check(n);
        break;
    case 0x10:  /* INTMC */
        if (unlikely(msix_enabled(&(n->parent_obj)))) {
            NVME_GUEST_ERR(nvme_ub_mmiowr_intmask_with_msix,
                           "undefined access to interrupt mask clr"
                           " when MSI-X is enabled");
            /* should be ignored, fall through for now */
        }
        n->bar.intms &= ~(data & 0xffffffff);
        n->bar.intmc = n->bar.intms;
        trace_nvme_mmio_intm_clr(data & 0xffffffff,
                                 n->bar.intmc);
        nvme_irq_check(n);
        break;
    case 0x14:  /* CC */
        trace_nvme_mmio_cfg(data & 0xffffffff);
        /* Windows first sends data, then sends enable bit */
        if (!NVME_CC_EN(data) && !NVME_CC_EN(n->bar.cc) &&
            !NVME_CC_SHN(data) && !NVME_CC_SHN(n->bar.cc))
        {
            n->bar.cc = data;
        }

        if (NVME_CC_EN(data) && !NVME_CC_EN(n->bar.cc)) {
            n->bar.cc = data;
            if (unlikely(nvme_start_ctrl(n))) {
                trace_nvme_err_startfail();
                n->bar.csts = NVME_CSTS_FAILED;
            } else {
                trace_nvme_mmio_start_success();
                n->bar.csts = NVME_CSTS_READY;
            }
        } else if (!NVME_CC_EN(data) && NVME_CC_EN(n->bar.cc)) {
            trace_nvme_mmio_stopped();
            nvme_clear_ctrl(n);
            n->bar.csts &= ~NVME_CSTS_READY;
        }
        if (NVME_CC_SHN(data) && !(NVME_CC_SHN(n->bar.cc))) {
            trace_nvme_mmio_shutdown_set();
            nvme_clear_ctrl(n);
            n->bar.cc = data;
            n->bar.csts |= NVME_CSTS_SHST_COMPLETE;
        } else if (!NVME_CC_SHN(data) && NVME_CC_SHN(n->bar.cc)) {
            trace_nvme_mmio_shutdown_cleared();
            n->bar.csts &= ~NVME_CSTS_SHST_COMPLETE;
            n->bar.cc = data;
        }
        break;
    case 0x1C:  /* CSTS */
        if (data & (1 << 4)) {
            NVME_GUEST_ERR(nvme_ub_mmiowr_ssreset_w1c_unsupported,
                           "attempted to W1C CSTS.NSSRO"
                           " but CAP.NSSRS is zero (not supported)");
        } else if (data != 0) {
            NVME_GUEST_ERR(nvme_ub_mmiowr_ro_csts,
                           "attempted to set a read only bit"
                           " of controller status");
        }
        break;
    case 0x20:  /* NSSR */
        if (data == 0x4E564D65) {
            trace_nvme_ub_mmiowr_ssreset_unsupported();
        } else {
            /* The spec says that writes of other values have no effect */
            return;
        }
        break;
    case 0x24:  /* AQA */
        n->bar.aqa = data & 0xffffffff;
        trace_nvme_mmio_aqattr(data & 0xffffffff);
        break;
    case 0x28:  /* ASQ */
        n->bar.asq = data;
        trace_nvme_mmio_asqaddr(data);
        break;
    case 0x2c:  /* ASQ hi */
        n->bar.asq |= data << 32;
        trace_nvme_mmio_asqaddr_hi(data, n->bar.asq);
        break;
    case 0x30:  /* ACQ */
        trace_nvme_mmio_acqaddr(data);
        n->bar.acq = data;
        break;
    case 0x34:  /* ACQ hi */
        n->bar.acq |= data << 32;
        trace_nvme_mmio_acqaddr_hi(data, n->bar.acq);
        break;
    case 0x38:  /* CMBLOC */
        NVME_GUEST_ERR(nvme_ub_mmiowr_cmbloc_reserved,
                       "invalid write to reserved CMBLOC"
                       " when CMBSZ is zero, ignored");
        return;
    case 0x3C:  /* CMBSZ */
        NVME_GUEST_ERR(nvme_ub_mmiowr_cmbsz_readonly,
                       "invalid write to read only CMBSZ, ignored");
        return;
    default:
        NVME_GUEST_ERR(nvme_ub_mmiowr_invalid,
                       "invalid MMIO write,"
                       " offset=0x%"PRIx64", data=%"PRIx64"",
                       offset, data);
        break;
    }
}

static uint64_t nvme_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    NvmeCtrl *n = (NvmeCtrl *)opaque;
    uint8_t *ptr = (uint8_t *)&n->bar;
    uint64_t val = 0;

    if (unlikely(addr & (sizeof(uint32_t) - 1))) {
        NVME_GUEST_ERR(nvme_ub_mmiord_misaligned32,
                       "MMIO read not 32-bit aligned,"
                       " offset=0x%"PRIx64"", addr);
        /* should RAZ, fall through for now */
    } else if (unlikely(size < sizeof(uint32_t))) {
        NVME_GUEST_ERR(nvme_ub_mmiord_toosmall,
                       "MMIO read smaller than 32-bits,"
                       " offset=0x%"PRIx64"", addr);
        /* should RAZ, fall through for now */
    }

    if (addr < sizeof(n->bar)) {
        memcpy(&val, ptr + addr, size);
    } else {
        NVME_GUEST_ERR(nvme_ub_mmiord_invalid_ofs,
                       "MMIO read beyond last register,"
                       " offset=0x%"PRIx64", returning 0", addr);
    }

    return val;
}

static void nvme_process_db(NvmeCtrl *n, hwaddr addr, int val)
{
    uint32_t qid;

    if (unlikely(addr & ((1 << 2) - 1))) {
        NVME_GUEST_ERR(nvme_ub_db_wr_misaligned,
                       "doorbell write not 32-bit aligned,"
                       " offset=0x%"PRIx64", ignoring", addr);
        return;
    }

    if (((addr - 0x1000) >> 2) & 1) {
        /* Completion queue doorbell write */

        uint16_t new_head = val & 0xffff;
        int start_sqs;
        NvmeCQueue *cq;

        qid = (addr - (0x1000 + (1 << 2))) >> 3;
        if (unlikely(nvme_check_cqid(n, qid))) {
            NVME_GUEST_ERR(nvme_ub_db_wr_invalid_cq,
                           "completion queue doorbell write"
                           " for nonexistent queue,"
                           " sqid=%"PRIu32", ignoring", qid);

            if (n->outstanding_aers) {
                nvme_enqueue_event(n, NVME_AER_TYPE_ERROR,
                    NVME_AER_INFO_ERR_INVALID_DB_REGISTER,
                    NVME_LOG_ERROR_INFO);
            }

            return;
        }

        cq = n->cq[qid];
        if (unlikely(new_head >= cq->size)) {
            NVME_GUEST_ERR(nvme_ub_db_wr_invalid_cqhead,
                           "completion queue doorbell write value"
                           " beyond queue size, sqid=%"PRIu32","
                           " new_head=%"PRIu16", ignoring",
                           qid, new_head);

            if (n->outstanding_aers) {
                nvme_enqueue_event(n, NVME_AER_TYPE_ERROR,
                    NVME_AER_INFO_ERR_INVALID_DB_VALUE, NVME_LOG_ERROR_INFO);
            }

            return;
        }

        start_sqs = nvme_cq_full(cq) ? 1 : 0;
        cq->head = new_head;
        if (start_sqs) {
            NvmeSQueue *sq;
            QTAILQ_FOREACH(sq, &cq->sq_list, entry) {
                timer_mod(sq->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 500);
            }
            timer_mod(cq->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 500);
        }

        if (cq->tail == cq->head) {
            nvme_irq_deassert(n, cq);
        }
    } else {
        /* Submission queue doorbell write */

        uint16_t new_tail = val & 0xffff;
        NvmeSQueue *sq;

        qid = (addr - 0x1000) >> 3;
        if (unlikely(nvme_check_sqid(n, qid))) {
            NVME_GUEST_ERR(nvme_ub_db_wr_invalid_sq,
                           "submission queue doorbell write"
                           " for nonexistent queue,"
                           " sqid=%"PRIu32", ignoring", qid);

            if (n->outstanding_aers) {
                nvme_enqueue_event(n, NVME_AER_TYPE_ERROR,
                    NVME_AER_INFO_ERR_INVALID_DB_REGISTER,
                    NVME_LOG_ERROR_INFO);
            }

            return;
        }

        sq = n->sq[qid];
        if (unlikely(new_tail >= sq->size)) {
            NVME_GUEST_ERR(nvme_ub_db_wr_invalid_sqtail,
                           "submission queue doorbell write value"
                           " beyond queue size, sqid=%"PRIu32","
                           " new_tail=%"PRIu16", ignoring",
                           qid, new_tail);

            if (n->outstanding_aers) {
                nvme_enqueue_event(n, NVME_AER_TYPE_ERROR,
                    NVME_AER_INFO_ERR_INVALID_DB_VALUE, NVME_LOG_ERROR_INFO);
            }

            return;
        }

        sq->tail = new_tail;
        timer_mod(sq->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 500);
    }
}

static void nvme_mmio_write(void *opaque, hwaddr addr, uint64_t data,
    unsigned size)
{
    NvmeCtrl *n = (NvmeCtrl *)opaque;
    if (addr < sizeof(n->bar)) {
        nvme_write_bar(n, addr, data, size);
    } else if (addr >= 0x1000) {
        nvme_process_db(n, addr, data);
    }
}

static const MemoryRegionOps nvme_mmio_ops = {
    .read = nvme_mmio_read,
    .write = nvme_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 2,
        .max_access_size = 8,
    },
};

static void nvme_cmb_write(void *opaque, hwaddr addr, uint64_t data,
    unsigned size)
{
    NvmeCtrl *n = (NvmeCtrl *)opaque;
    stn_le_p(&n->cmbuf[addr], size, data);
}

static uint64_t nvme_cmb_read(void *opaque, hwaddr addr, unsigned size)
{
    NvmeCtrl *n = (NvmeCtrl *)opaque;
    return ldn_le_p(&n->cmbuf[addr], size);
}

static const MemoryRegionOps nvme_cmb_ops = {
    .read = nvme_cmb_read,
    .write = nvme_cmb_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 1,
        .max_access_size = 8,
    },
};

int nvme_check_constraints(NvmeCtrl *n, Error **errp)
{
    NvmeParams *params = &n->params;

    if (!n->parent_obj.qdev.id) {
        error_setg(errp, "nvme: invalid 'id' parameter");
        return 1;
    }

    if (!params->serial) {
        error_setg(errp, "nvme: serial not configured");
        return 1;
    }

    if ((params->num_queues < 1 || params->num_queues > NVME_MAX_QS)) {
        error_setg(errp, "nvme: invalid queue configuration");
        return 1;
    }

    return 0;
}

void nvme_init_state(NvmeCtrl *n)
{
    n->num_namespaces = 0;
    n->reg_size = pow2ceil(0x1004 + 2 * (n->params.num_queues + 1) * 4);
    n->starttime_ms = qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL);
    n->sq = g_new0(NvmeSQueue *, n->params.num_queues);
    n->cq = g_new0(NvmeCQueue *, n->params.num_queues);
    n->elpes = g_new0(NvmeErrorLog, NVME_ELPE + 1);
    n->aer_reqs = g_new0(NvmeRequest *, NVME_AERL + 1);
    n->features.int_vector_config = g_malloc0_n(n->params.num_queues,
        sizeof(*n->features.int_vector_config));
}

static void nvme_init_cmb(NvmeCtrl *n, PCIDevice *pci_dev)
{
    NVME_CMBLOC_SET_BIR(n->bar.cmbloc, 2);
    NVME_CMBLOC_SET_OFST(n->bar.cmbloc, 0);

    NVME_CMBSZ_SET_SQS(n->bar.cmbsz, 1);
    NVME_CMBSZ_SET_CQS(n->bar.cmbsz, 1);
    NVME_CMBSZ_SET_LISTS(n->bar.cmbsz, 1);
    NVME_CMBSZ_SET_RDS(n->bar.cmbsz, 1);
    NVME_CMBSZ_SET_WDS(n->bar.cmbsz, 1);
    NVME_CMBSZ_SET_SZU(n->bar.cmbsz, 2);
    NVME_CMBSZ_SET_SZ(n->bar.cmbsz, n->params.cmb_size_mb);

    n->cmbloc = n->bar.cmbloc;
    n->cmbsz = n->bar.cmbsz;

    n->cmbuf = g_malloc0(NVME_CMBSZ_GETSIZE(n->bar.cmbsz));
    memory_region_init_io(&n->ctrl_mem, OBJECT(n), &nvme_cmb_ops, n,
                            "nvme-cmb", NVME_CMBSZ_GETSIZE(n->bar.cmbsz));
    pci_register_bar(pci_dev, NVME_CMBLOC_BIR(n->bar.cmbloc),
        PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64 |
        PCI_BASE_ADDRESS_MEM_PREFETCH, &n->ctrl_mem);
}

void nvme_init_pci(NvmeCtrl *n, PCIDevice *pci_dev)
{
    uint8_t *pci_conf = pci_dev->config;

    pci_conf[PCI_INTERRUPT_PIN] = 1;
    pci_config_set_prog_interface(pci_conf, 0x2);
    pci_config_set_vendor_id(pci_conf, PCI_VENDOR_ID_INTEL);
    pci_config_set_device_id(pci_conf, 0x5845);
    pci_config_set_class(pci_conf, PCI_CLASS_STORAGE_EXPRESS);
    pcie_endpoint_cap_init(pci_dev, 0x80);

    memory_region_init_io(&n->iomem, OBJECT(n), &nvme_mmio_ops, n, "nvme",
        n->reg_size);
    pci_register_bar(pci_dev, 0,
        PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64,
        &n->iomem);
    msix_init_exclusive_bar(pci_dev, n->params.num_queues, 4, NULL);

    if (n->params.cmb_size_mb) {
        nvme_init_cmb(n, pci_dev);
    }
}

void nvme_init_ctrl(NvmeCtrl *n)
{
    NvmeIdCtrl *id = &n->id_ctrl;
    NvmeParams *params = &n->params;
    uint8_t *pci_conf = n->parent_obj.config;

    id->vid = cpu_to_le16(pci_get_word(pci_conf + PCI_VENDOR_ID));
    id->ssvid = cpu_to_le16(pci_get_word(pci_conf + PCI_SUBSYSTEM_VENDOR_ID));
    strpadcpy((char *)id->mn, sizeof(id->mn), "QEMU NVMe Ctrl", ' ');
    strpadcpy((char *)id->fr, sizeof(id->fr), "1.0", ' ');
    strpadcpy((char *)id->sn, sizeof(id->sn), params->serial, ' ');
    id->rab = 6;
    id->ieee[0] = 0x00;
    id->ieee[1] = 0x02;
    id->ieee[2] = 0xb3;
    id->cmic = 0;
    id->mdts = params->mdts;
    id->ver = cpu_to_le32(0x00010300);
    id->oacs = cpu_to_le16(0);
    id->acl = 3;
    id->aerl = NVME_AERL;
    id->frmw = 7 << 1 | 1;
    id->lpa = 1 << 2;
    id->elpe = NVME_ELPE;
    id->npss = 0;
    id->sqes = (0x6 << 4) | 0x6;
    id->cqes = (0x4 << 4) | 0x4;
    id->nn = cpu_to_le32(n->num_namespaces);
    id->oncs = cpu_to_le16(NVME_ONCS_WRITE_ZEROS | NVME_ONCS_TIMESTAMP);
    id->fuses = cpu_to_le16(0);
    id->fna = 0;
    id->vwc = 1;
    id->awun = cpu_to_le16(0);
    id->awupf = cpu_to_le16(0);
    id->sgls = cpu_to_le32(0x1);

    strcpy((char *) id->subnqn, "nqn.2014-08.org.nvmexpress:uuid:");
    qemu_uuid_unparse(&qemu_uuid,
        (char *) id->subnqn + strlen((char *) id->subnqn));

    id->psd[0].mp = cpu_to_le16(0x9c4);
    id->psd[0].enlat = cpu_to_le32(0x10);
    id->psd[0].exlat = cpu_to_le32(0x4);

    n->temperature = NVME_TEMPERATURE;
    n->features.temp_thresh = 0x14d;

    /* disable coalescing (not supported) */
    for (int i = 0; i < n->params.num_queues; i++) {
        n->features.int_vector_config[i] = i | (1 << 16);
    }

    n->bar.cap = 0;
    NVME_CAP_SET_MQES(n->bar.cap, 0x7ff);
    NVME_CAP_SET_CQR(n->bar.cap, 1);
    NVME_CAP_SET_TO(n->bar.cap, 0xf);
    NVME_CAP_SET_CSS(n->bar.cap, 1);
    NVME_CAP_SET_MPSMAX(n->bar.cap, 4);

    n->bar.vs = 0x00010300;
    n->bar.intmc = n->bar.intms = 0;
}

int nvme_register_namespace(NvmeCtrl *n, NvmeNamespace *ns, Error **errp)
{
    if (ns->params.nsid == 0 || ns->params.nsid > NVME_MAX_NAMESPACES) {
        error_setg(errp, "invalid namespace id");
        return 1;
    }

    trace_nvme_register_namespace(ns->params.nsid);

    n->namespaces[ns->params.nsid - 1] = ns;
    n->num_namespaces++;
    n->id_ctrl.nn++;

    return 0;
}

static void nvme_realize(PCIDevice *pci_dev, Error **errp)
{
    NvmeCtrl *n = NVME(pci_dev);
    Error *local_err = NULL;

    n->admin_cmd = nvme_admin_cmd;
    n->io_cmd = nvme_io_cmd;

    if (nvme_check_constraints(n, &local_err)) {
        error_propagate_prepend(errp, local_err, "nvme_check_constraints: ");
        return;
    }

    qbus_create_inplace(&n->bus, sizeof(NvmeBus), TYPE_NVME_BUS,
        &pci_dev->qdev, n->parent_obj.qdev.id);

    nvme_init_state(n);
    nvme_init_pci(n, pci_dev);
    nvme_init_ctrl(n);
}

void nvme_free_ctrl(NvmeCtrl *n, PCIDevice *pci_dev)
{
    nvme_clear_ctrl(n);
    g_free(n->cq);
    g_free(n->sq);
    g_free(n->elpes);
    g_free(n->aer_reqs);
    g_free(n->features.int_vector_config);

    if (n->params.cmb_size_mb) {
        g_free(n->cmbuf);
    }

    msix_uninit_exclusive_bar(pci_dev);
}

static void nvme_exit(PCIDevice *pci_dev)
{
    NvmeCtrl *n = NVME(pci_dev);

    nvme_free_ctrl(n, pci_dev);
}

static Property nvme_props[] = {
    DEFINE_NVME_PROPERTIES(NvmeCtrl, params),
    DEFINE_PROP_END_OF_LIST(),
};

static const VMStateDescription nvme_vmstate = {
    .name = "nvme",
    .unmigratable = 1,
};

static void nvme_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    PCIDeviceClass *pc = PCI_DEVICE_CLASS(oc);

    pc->realize = nvme_realize;
    pc->exit = nvme_exit;
    pc->class_id = PCI_CLASS_STORAGE_EXPRESS;
    pc->vendor_id = PCI_VENDOR_ID_INTEL;
    pc->device_id = 0x5845;
    pc->revision = 2;

    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    dc->desc = "Non-Volatile Memory Express";
    dc->props = nvme_props;
    dc->vmsd = &nvme_vmstate;
}

static const TypeInfo nvme_info = {
    .name          = TYPE_NVME,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(NvmeCtrl),
    .class_init    = nvme_class_init,
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_PCIE_DEVICE },
        { }
    },
};

static const TypeInfo nvme_bus_info = {
    .name = TYPE_NVME_BUS,
    .parent = TYPE_BUS,
    .instance_size = sizeof(NvmeBus),
};

static void nvme_register_types(void)
{
    type_register_static(&nvme_info);
    type_register_static(&nvme_bus_info);
}

type_init(nvme_register_types)
