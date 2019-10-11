/*
 * QEMU OpenChannel 2.0 Controller
 *
 * Copyright (c) 2019 CNEX Labs, Inc.
 *
 * Written by Klaus Birkelund Abildgaard Jensen <klaus@birkelund.eu>
 *
 * Thank you to the following people for their contributions to the original
 * qemu-nvme (github.com/OpenChannelSSD/qemu-nvme) implementation.
 *
 *   Matias Bjørling <mb@lightnvm.io>
 *   Javier González <javier@javigon.com>
 *   Simon Andreas Frimann Lund <ocssd@safl.dk>
 *   Hans Holmberg <hans@owltronix.com>
 *   Jesper Devantier <contact@pseudonymous.me>
 *   Young Tack Jin <youngtack.jin@circuitblvd.com>
 *
 * This code is licensed under the GNU GPL v2 or later.
 */

/*
 * This device emulates an OpenChannel 2.0 compliant NVMe controller.
 *
 * Reference docs: http://lightnvm.io/docs/OCSSD-2_0-20180129.pdf
 *
 *
 * Usage
 * -----
 *
 * The device must have a backing image to store data, metadata and intenal
 * meta data. Create a zero-sized image file. The device will resize the image
 * to accomodate the chosen geometry.
 *
 *   qemu-img create -f raw ocssd.img 0
 *
 * To add the OCSSD NVMe device, extend the QEMU arguments with something like
 *
 *   -drive file=<file>,if=none,id=<drive_id>
 *   -device ocssd,serial=<serial>,id=nvme0
 *   -device ocssd-ns,drive=<drive_id>,bus=nvme0,nsid=1
 *
 * In addition to the standard nvme-ns device parameters (nsid, ms), the
 * following are also available for the ocssd-ns device.
 *
 *   num_grp=<uint16>   : Number of groups.
 *                        Default: 2
 *   num_pu=<uint16>    : Number of parallel units per group.
 *                        Default: 4
 *   num_chk=<uint32>   : Number of chunks per parallel unit.
 *                        Default: 60
 *   clba=<uint32>      : Number of logical blocks per chunk.
 *                        Default: 4096
 *   lbads=<uint8>      : Logical block data size. Specified in terms of a
 *                        power of two (2^n). A value smaller than 9 is not
 *                        supported.
 *                        Default: 12 (4096 bytes)
 *   pe_cycles=<uint32> : Program/erase cycles per chunk.
 *                        Default: 1000
 *
 * NOTE: The above defaults (and the `ms` nvme parameter) are only used at
 * image initialization time (when the image size is zero). If the image has
 * already been initialized, the values are fixed to what was specified when
 * the image was first initialized. If any of those parameters are specified
 * and differs from what is stored in the image, the device will error out and
 * refuse to be realized.
 *
 * The following remaining parameters may be changed at your discretion to
 * modify the behavior of the device.
 *
 *   mccap=<uint32>     : Media and Controller Capabilities (MCCAP). OR'ed
 *                        value of the following:
 *                          vector copy supported           0x1
 *                          multiple resets                 0x2
 *                          early resets (non-standard)     0x4
 *                        Default: 0x5
 *   ws_min=<uint32>    : Mininum write size for device in sectors.
 *                        Default: 4
 *   ws_opt=<uint32>    : Optimal write size for device in sectors.
 *                        Default: 8
 *   mw_cunits=<uint32> : Cache minimum write size units. If DULBE is enabled,
 *                        an error will be reported if reads are within this
 *                        window.
 *                        Default: 24
 *   wit=<uint8>        : Wear-level index delta threshold.
 *                        Default: 10
 *   chunkinfo=<file>   : Overwrite chunk states from file.
 *   resetfail=<file>   : Reset fail injection configuration file.
 *   writefail=<file>   : Write fail injection configuration file.
 *   early_reset        : Allow early resets (reset open chunks).
 *                        Default: enabled
 *
 * The emulated device maintains a Chunk Info Log Page on the backing image.
 * When the device is brought up any state will be restored. The restored chunk
 * states may be overwritten using the `chunkinfo` parameter. An example chunk
 * state file follows (note the use of the '*' wildcard to match multiple
 * groups, punits or chunks).
 *
 *   # "reset" all chunks
 *   group=* punit=* chunk=* state=FREE type=SEQUENTIAL pe_cycles=0
 *
 *   # first chunk on all luns has type random
 *   group=* punit=* chunk=0 type=RANDOM
 *
 *   # add an open chunk
 *   group=0 punit=0 chunk=1 state=OPEN type=SEQ wp=0x800
 *
 *   # add a closed chunk
 *   group=0 punit=0 chunk=2 state=CLOSED type=SEQ wp=0x1000
 *
 *   # add an offline chunk
 *   group=0 punit=0 chunk=3 state=OFFLINE type=SEQ
 *
 *
 * The `resetfail` and `writefail` QEMU parameters can be used to do
 * probabilistic error injection. The parameters points to text files and they
 * also support the '*' wildcard.
 *
 * Write error injection is done per sector.
 *
 *   # always fail writes for this sector
 *   group=0 punit=3 chunk=0 sectr=53 prob=100
 *
 *
 * Reset error injection is done per chunk, so exclude the `sectr` parameter.
 *
 *   # fail resets for this chunk with 90% probability
 *   group=0 punit=3 chunk=0 prob=90
 *
 *
 * You probably want to make sure the following options are enabled in the
 * kernel you are going to use.
 *
 *   CONFIG_BLK_DEV_INTEGRITY=y
 *   CONFIG_HOTPLUG_PCI_PCIE=y
 *   CONFIG_HOTPLUG_PCI_ACPI=y
 *
 *
 * It is assumed that when using vector write requests, then the LBAs for
 * different chunks are laid out contiguously and sorted with increasing
 * addresses.
 */

#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "sysemu/block-backend.h"
#include "sysemu/sysemu.h"
#include "qapi/error.h"

#include "trace.h"
#include "hw/block/ocssd.h"
#include "hw/block/ocssd-ns.h"

/* #define OCSSD_CTRL_DEBUG */

#ifdef OCSSD_CTRL_DEBUG
#define _dprintf(fmt, ...) \
    do { \
        fprintf(stderr, "ocssd: " fmt, ## __VA_ARGS__); \
    } while (0)

static inline void _dprint_lba(OcssdCtrl *o, OcssdNamespace *ons, uint64_t lba)
{
    OcssdAddrF *addrf = &ons->addrf;

    uint8_t group, punit;
    uint16_t chunk;
    uint32_t sectr;

    group = _group(addrf, lba);
    punit = _punit(addrf, lba);
    chunk = _chunk(addrf, lba);
    sectr = _sectr(addrf, lba);

    _dprintf("lba 0x%016"PRIx64" group %"PRIu8" punit %"PRIu8" chunk %"PRIu16
        " sectr %"PRIu32"\n", lba, group, punit, chunk, sectr);
}

static inline void _dprint_vector_rw(OcssdCtrl *o, NvmeRequest *req)
{
    OcssdNamespace *ons = _ons(o, req->ns->id);
    _dprintf("vector %s request: cid %d nlb %d\n",
        req->is_write ? "write" : "read", req->cqe.cid, req->nlb);
    _dprintf("lba list:\n");
    for (uint16_t i = 0; i < req->nlb; i++) {
        _dprint_lba(o, ons, _vlba(req, i));
    }
}
#else
#define _dprintf(fmt, ...)
static void _dprint_lba(OcssdCtrl *o, OcssdNamespace *ons, uint64_t lba) {}
static void _dprint_vector_rw(OcssdCtrl *o, NvmeRequest *req) {}
#endif


static inline bool _is_write(NvmeRequest *req)
{
    return req->cmd.opcode == OCSSD_CMD_VECT_WRITE || nvme_rw_is_write(req);
}

static inline bool _is_vector_request(NvmeRequest *req)
{
    switch (req->cmd.opcode) {
    case OCSSD_CMD_VECT_RESET:
    case OCSSD_CMD_VECT_WRITE:
    case OCSSD_CMD_VECT_READ:
    case OCSSD_CMD_VECT_COPY:
        return true;
    }

    return false;
}

static inline OcssdNamespace *_ons(OcssdCtrl *o, uint32_t nsid)
{
    NvmeCtrl *n = &o->nvme;

    if (!nvme_nsid_is_valid(n, nsid)) {
        return NULL;
    }

    return OCSSD_NS(n->namespaces[nsid - 1]);
}

static inline uint64_t _vlba(NvmeRequest *req, uint16_t n)
{
    return req->nlb > 1 ? ((uint64_t *) req->slba)[n] : req->slba;
}

static inline void _sglist_to_iov(NvmeCtrl *n, QEMUSGList *qsg,
    QEMUIOVector *iov)
{
    for (int i = 0; i < qsg->nsg; i++) {
        qemu_iovec_add(iov, (void *) qsg->sg[i].base, qsg->sg[i].len);
    }
}

/*
 * _sglist_copy_from copies `len` bytes from the `idx`'th scatter gather entry
 * at `offset` in the `to` QEMUSGList into the `to` QEMUSGList. `idx` and
 * `offset` are updated to mark the position in `to` at which the function
 * reached `len` bytes.
 */
static void _sglist_copy_from(QEMUSGList *to, QEMUSGList *from, int *idx,
    size_t *offset, size_t len)
{
    dma_addr_t curr_addr, curr_len;

    while (len) {
        curr_addr = from->sg[*idx].base + *offset;
        curr_len = from->sg[*idx].len - *offset;

        curr_len = MIN(curr_len, len);

        if (to) {
            qemu_sglist_add(to, curr_addr, curr_len);
        }

        *offset += curr_len;
        len -= curr_len;

        if (*offset == from->sg[*idx].len) {
            *offset = 0;
            (*idx)++;
        }
    }
}

static inline bool _wi_outside_threshold(OcssdNamespace *ons,
    OcssdChunkDescriptor *chk)
{
    return chk->wear_index < ons->wear_index_avg - ons->id.wit ||
        chk->wear_index > ons->wear_index_avg + ons->id.wit;
}

static void _get_lba_list(OcssdCtrl *o, hwaddr addr, uint64_t **lbal,
    NvmeRequest *req)
{
    NvmeCtrl *n = &o->nvme;
    uint32_t len = req->nlb * sizeof(uint64_t);

    if (req->nlb > 1) {
        *lbal = g_malloc_n(req->nlb, sizeof(uint64_t));
        nvme_addr_read(n, addr, *lbal, len);
    } else {
        *lbal = (uint64_t *) addr;
    }
}

static void ocssd_commit_chunk_acct(OcssdCtrl *o, OcssdNamespace *ons,
    NvmeRequest *req, OcssdChunkDescriptor *chk,
    OcssdChunkAcctDescriptor *chk_acct)
{
    NvmeCtrl *n = &o->nvme;
    NvmeNamespace *ns = NVME_NS(ons);
    NvmeBlockBackendRequest *blk_req = nvme_blk_req_get(n, req, NULL);

    blk_req->blk_offset = ons->acct.blk_offset;

    qemu_iovec_init(&blk_req->iov, 1);
    if (chk) {
        qemu_iovec_add(&blk_req->iov, chk_acct,
            sizeof(OcssdChunkAcctDescriptor));
        blk_req->blk_offset += ocssd_ns_chk_idx(ons, chk->slba) *
            sizeof(OcssdChunkAcctDescriptor);
    } else {
        qemu_iovec_add(&blk_req->iov, ons->acct.descr, ons->acct.size);
    }

    QTAILQ_INSERT_TAIL(&req->blk_req_tailq, blk_req, tailq_entry);

    block_acct_start(blk_get_stats(ns->conf.blk), &blk_req->acct,
        blk_req->iov.size, BLOCK_ACCT_WRITE);

    blk_req->aiocb = blk_aio_pwritev(ns->conf.blk, blk_req->blk_offset,
        &blk_req->iov, 0, nvme_noop_cb, blk_req);
}

static void ocssd_commit_chunk_info(OcssdCtrl *o, OcssdNamespace *ons,
    NvmeRequest *req, OcssdChunkDescriptor *chk)
{
    NvmeCtrl *n = &o->nvme;
    NvmeNamespace *ns = NVME_NS(ons);
    NvmeBlockBackendRequest *blk_req = nvme_blk_req_get(n, req, NULL);

    blk_req->blk_offset = ons->info.blk_offset;

    qemu_iovec_init(&blk_req->iov, 1);
    if (chk) {
        qemu_iovec_add(&blk_req->iov, chk, sizeof(OcssdChunkDescriptor));
        blk_req->blk_offset += ocssd_ns_chk_idx(ons, chk->slba) *
            sizeof(OcssdChunkDescriptor);
    } else {
        qemu_iovec_add(&blk_req->iov, ons->info.descr, ons->info.size);
    }

    QTAILQ_INSERT_TAIL(&req->blk_req_tailq, blk_req, tailq_entry);

    block_acct_start(blk_get_stats(ns->conf.blk), &blk_req->acct,
        blk_req->iov.size, BLOCK_ACCT_WRITE);

    blk_req->aiocb = blk_aio_pwritev(ns->conf.blk, blk_req->blk_offset,
        &blk_req->iov, 0, nvme_noop_cb, blk_req);
}

static uint16_t ocssd_do_get_chunk_info(OcssdCtrl *o, NvmeCmd *cmd,
    uint32_t buf_len, uint64_t off, NvmeRequest *req)
{
    uint8_t *log_page;
    uint32_t log_len, trans_len;

    OcssdNamespace *ons = _ons(o, le32_to_cpu(cmd->nsid));
    if (!ons) {
        trace_ocssd_err(req->cqe.cid, "chunk info requires nsid",
            NVME_INVALID_FIELD | NVME_DNR);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    log_len = ons->chks_total * sizeof(OcssdChunkDescriptor);

    if (off > log_len) {
        trace_ocssd_err(req->cqe.cid, "invalid log page offset",
            NVME_INVALID_FIELD | NVME_DNR);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    trans_len = MIN(log_len - off, buf_len);
    log_page = (uint8_t *) ons->info.descr + off;

    return nvme_dma_read(&o->nvme, log_page, trans_len, cmd, req);
}

static uint16_t ocssd_do_get_chunk_notification(OcssdCtrl *o, NvmeCmd *cmd,
    uint32_t buf_len, uint64_t off, uint8_t rae, NvmeRequest *req)
{
    NvmeCtrl *n = &o->nvme;

    uint8_t *log_page;
    uint32_t log_len, trans_len;

    log_len = OCSSD_MAX_CHUNK_NOTIFICATIONS * sizeof(OcssdChunkNotification);

    if (off > log_len) {
        trace_ocssd_err(req->cqe.cid, "invalid log page offset",
            NVME_INVALID_FIELD | NVME_DNR);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    trans_len = MIN(log_len - off, buf_len);
    log_page = (uint8_t *) &o->notifications[off];

    if (!rae) {
        nvme_clear_events(n, NVME_AER_TYPE_VENDOR_SPECIFIC);
    }

    return nvme_dma_read(&o->nvme, log_page, trans_len, cmd, req);
}

static void ocssd_add_chunk_notification(OcssdCtrl *o, OcssdNamespace *ons,
    uint64_t lba, uint16_t state, uint8_t mask, uint16_t nlb)
{
    NvmeNamespace *ns = NVME_NS(ons);
    OcssdChunkNotification *notice;

    notice = &o->notifications[o->notifications_index];
    notice->nc = cpu_to_le64(++(o->notifications_count));
    notice->lba = cpu_to_le64(lba);
    notice->nsid = cpu_to_le32(ns->params.nsid);
    notice->state = cpu_to_le16(state);
    notice->mask = mask;
    notice->nlb = cpu_to_le16(nlb);

    o->notifications_index = (o->notifications_index + 1) %
        OCSSD_MAX_CHUNK_NOTIFICATIONS;
}

static uint16_t ocssd_rw_check_chunk_read(OcssdCtrl *o, NvmeCmd *cmd,
    NvmeRequest *req, uint64_t lba)
{
    NvmeNamespace *ns = req->ns;
    OcssdNamespace *ons = OCSSD_NS(ns);
    OcssdAddrF *addrf = &ons->addrf;
    OcssdIdWrt *wrt = &ons->id.wrt;

    OcssdChunkDescriptor *chk;
    uint64_t sectr, mw_cunits, wp;
    uint8_t state;

    chk = ocssd_ns_get_chunk(ons, lba);
    if (!chk) {
        trace_ocssd_err_invalid_chunk(req->cqe.cid,
            lba & ~ons->addrf.sec_mask);
        return NVME_DULB;
    }

    sectr = ocssd_addrf_sectr(addrf, lba);
    mw_cunits = wrt->mw_cunits;
    wp = chk->wp;
    state = chk->state;

    if (chk->type == OCSSD_CHUNK_TYPE_RANDOM) {
        /*
         * For OCSSD_CHUNK_TYPE_RANDOM it is sufficient to ensure that the
         * chunk is OPEN and that we are reading a valid address.
         */
        if (state != OCSSD_CHUNK_OPEN || sectr >= chk->cnlb) {
            trace_ocssd_err_invalid_chunk_state(req->cqe.cid,
                lba & ~(ons->addrf.sec_mask), chk->state);
            return NVME_DULB;
        }

        return NVME_SUCCESS;
    }

    if (state == OCSSD_CHUNK_CLOSED && sectr < wp) {
        return NVME_SUCCESS;
    }

    if (state == OCSSD_CHUNK_OPEN) {
        if (wp < mw_cunits) {
            return NVME_DULB;
        }

        if (sectr < (wp - mw_cunits)) {
            return NVME_SUCCESS;
        }
    }

    return NVME_DULB;
}

static uint16_t ocssd_rw_check_chunk_write(OcssdCtrl *o, NvmeCmd *cmd,
    uint64_t lba, uint32_t ws, NvmeRequest *req)
{
    OcssdChunkDescriptor *chk;
    NvmeNamespace *ns = req->ns;
    OcssdNamespace *ons = OCSSD_NS(ns);
    OcssdIdWrt *wrt = &ons->id.wrt;

    chk = ocssd_ns_get_chunk(ons, lba);
    if (!chk) {
        trace_ocssd_err_invalid_chunk(req->cqe.cid,
            lba & ~ons->addrf.sec_mask);
        return NVME_WRITE_FAULT | NVME_DNR;
    }

    uint32_t start_sectr = lba & ons->addrf.sec_mask;
    uint32_t end_sectr = start_sectr + ws;

    /* check if we are at all allowed to write to the chunk */
    if (chk->state == OCSSD_CHUNK_OFFLINE ||
        chk->state == OCSSD_CHUNK_CLOSED) {
        trace_ocssd_err_invalid_chunk_state(req->cqe.cid,
            lba & ~(ons->addrf.sec_mask), chk->state);
        return NVME_WRITE_FAULT | NVME_DNR;
    }

    if (end_sectr > chk->cnlb) {
        trace_ocssd_err_out_of_bounds(req->cqe.cid, end_sectr, chk->cnlb);
        return NVME_WRITE_FAULT | NVME_DNR;
    }


    if (chk->type == OCSSD_CHUNK_TYPE_RANDOM) {
        return NVME_SUCCESS;
    }

    if (ws < wrt->ws_min || (ws % wrt->ws_min) != 0) {
        trace_ocssd_err_write_constraints(req->cqe.cid, ws, wrt->ws_min);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    /* check that the write begins at the current wp */
    if (start_sectr != chk->wp) {
        trace_ocssd_err_out_of_order(req->cqe.cid, start_sectr, chk->wp);
        return OCSSD_OUT_OF_ORDER_WRITE | NVME_DNR;
    }

    return NVME_SUCCESS;
}

static uint16_t ocssd_rw_check_vector_read_req(OcssdCtrl *o, NvmeCmd *cmd,
    NvmeRequest *req, uint64_t *dulbe)
{
    uint16_t status;

    assert(dulbe);

    for (int i = 0; i < req->nlb; i++) {
        status = ocssd_rw_check_chunk_read(o, cmd, req, _vlba(req, i));

        if (status) {
            if (nvme_is_error(status, NVME_DULB)) {
                *dulbe |= (1 << i);
                continue;
            }

            return status;
        }
    }

    return NVME_SUCCESS;
}

static uint16_t ocssd_rw_check_vector_write_req(OcssdCtrl *o, NvmeCmd *cmd,
    NvmeRequest *req)
{
    NvmeNamespace *ns = req->ns;
    OcssdNamespace *ons = OCSSD_NS(ns);
    OcssdAddrF *addrf = &ons->addrf;

    uint64_t prev_lba = _vlba(req, 0);
    uint64_t prev_chk_idx = ocssd_ns_chk_idx(ons, prev_lba);
    uint32_t sectr = ocssd_addrf_sectr(addrf, prev_lba);
    uint16_t ws = 1, status;

    for (uint16_t i = 1; i < req->nlb; i++) {
        uint64_t lba = _vlba(req, i);
        uint64_t chk_idx = ocssd_ns_chk_idx(ons, lba);

        /*
         * It is assumed that LBAs for different chunks are laid out
         * contiguously and sorted with increasing addresses.
         */
        if (prev_chk_idx != chk_idx) {
            status = ocssd_rw_check_chunk_write(o, cmd, prev_lba, ws, req);
            if (status) {
                req->cqe.res64 = cpu_to_le64((1 << req->nlb) - 1);
                return status;
            }

            prev_lba = lba;
            prev_chk_idx = chk_idx;
            sectr = ocssd_addrf_sectr(addrf, prev_lba);
            ws = 1;

            continue;
        }

        if (++sectr != ocssd_addrf_sectr(addrf, lba)) {
            return OCSSD_OUT_OF_ORDER_WRITE | NVME_DNR;
        }

        ws++;
    }

    return ocssd_rw_check_chunk_write(o, cmd, prev_lba, ws, req);
}

static uint16_t ocssd_rw_check_scalar_req(OcssdCtrl *o, NvmeCmd *cmd,
    NvmeRequest *req)
{
    NvmeCtrl *n = &o->nvme;
    uint16_t status;

    status = nvme_rw_check_req(n, cmd, req);
    if (status) {
        trace_ocssd_err(req->cqe.cid, "nvme_rw_check_req", status);
        return status;
    }

    if (req->is_write) {
        return ocssd_rw_check_chunk_write(o, cmd, req->slba, req->nlb, req);
    }

    for (uint16_t i = 0; i < req->nlb; i++) {
        status = ocssd_rw_check_chunk_read(o, cmd, req, req->slba + i);
        if (nvme_is_error(status, NVME_DULB)) {
            if (NVME_ERR_REC_DULBE(n->features.err_rec)) {
                return NVME_DULB | NVME_DNR;
            }

            break;
        }

        return status;
    }

    return NVME_SUCCESS;
}

static uint16_t ocssd_rw_check_vector_req(OcssdCtrl *o, NvmeCmd *cmd,
    NvmeRequest *req, uint64_t *dulbe)
{
    NvmeCtrl *n = &o->nvme;
    uint16_t status;

    status = nvme_rw_check_req(n, cmd, req);
    if (status) {
        trace_ocssd_err(req->cqe.cid, "nvme_rw_check_req", status);
        return status;
    }

    if (req->is_write) {
        return ocssd_rw_check_vector_write_req(o, cmd, req);
    }

    return ocssd_rw_check_vector_read_req(o, cmd, req, dulbe);
}

static uint16_t ocssd_blk_setup_scalar(NvmeCtrl *n, NvmeNamespace *ns,
    QEMUSGList *qsg, uint64_t blk_offset, uint32_t unit_len, NvmeRequest *req)
{
    OcssdNamespace *ons = OCSSD_NS(ns);

    NvmeBlockBackendRequest *blk_req = nvme_blk_req_get(n, req, qsg);
    if (!blk_req) {
        NVME_GUEST_ERR(nvme_err_internal_dev_error, "nvme_blk_req_get: %s",
            "could not allocate memory");
        return NVME_INTERNAL_DEV_ERROR;
    }

    blk_req->slba = req->slba;
    blk_req->nlb = req->nlb;
    blk_req->blk_offset = blk_offset + ocssd_ns_sectr_idx(ons, req->slba) *
        unit_len;

    QTAILQ_INSERT_TAIL(&req->blk_req_tailq, blk_req, tailq_entry);

    return NVME_SUCCESS;
}

static uint16_t ocssd_blk_setup_vector(NvmeCtrl *n, NvmeNamespace *ns,
    QEMUSGList *qsg, uint64_t blk_offset, uint32_t unit_len, NvmeRequest *req)
{
    OcssdNamespace *ons = OCSSD_NS(ns);

    size_t curr_byte = 0;
    uint64_t lba, chk_idx, prev_chk_idx;
    int curr_sge = 0;

    NvmeBlockBackendRequest *blk_req = nvme_blk_req_get(n, req, NULL);

    blk_req->qsg = g_new(QEMUSGList, 1);
    pci_dma_sglist_init(blk_req->qsg, &n->parent_obj, 1);

    /*
     * Similar to ocssd_rw_check_vector_write_req, it is assumed that LBAs for
     * different chunks are laid out contiguously and sorted with increasing
     * addresses. Thus, split request into multiple NvmeBlockBackendRequest for
     * each chunk involved unconditionally, even if the last sector of chunk N
     * has address K and the first address of chunk N+1 has address K+1 and
     * would be contiguous on the block backend. The invariant that a single
     * NvmeBlockBackendRequest corresponds to at most one chunk is used in
     * e.g. write error injection.
     */

    lba = _vlba(req, 0);
    prev_chk_idx = ocssd_ns_chk_idx(ons, lba);

    blk_req->blk_offset = blk_offset + ocssd_ns_sectr_idx(ons, lba) * unit_len;
    blk_req->slba = lba;
    blk_req->nlb = 1;

    QTAILQ_INSERT_TAIL(&req->blk_req_tailq, blk_req, tailq_entry);

    for (uint16_t i = 1; i < req->nlb; i++) {
        lba = _vlba(req, i);
        chk_idx = ocssd_ns_chk_idx(ons, lba);

        if (prev_chk_idx != chk_idx) {
            _sglist_copy_from(blk_req->qsg, qsg, &curr_sge, &curr_byte,
                blk_req->nlb * unit_len);

            blk_req = nvme_blk_req_get(n, req, NULL);
            if (!blk_req) {
                NVME_GUEST_ERR(nvme_err_internal_dev_error,
                    "nvme_blk_req_get: %s", "could not allocate memory");
                return NVME_INTERNAL_DEV_ERROR;
            }

            blk_req->qsg = g_new(QEMUSGList, 1);
            pci_dma_sglist_init(blk_req->qsg, &n->parent_obj, 1);

            blk_req->blk_offset = blk_offset + ocssd_ns_sectr_idx(ons, lba) *
                unit_len;
            blk_req->slba = lba;

            QTAILQ_INSERT_TAIL(&req->blk_req_tailq, blk_req, tailq_entry);

            prev_chk_idx = chk_idx;
        }

        blk_req->nlb++;
    }

    _sglist_copy_from(blk_req->qsg, qsg, &curr_sge, &curr_byte,
        blk_req->nlb * unit_len);

    return NVME_SUCCESS;
}

static uint16_t ocssd_do_chunk_reset(OcssdCtrl *o, OcssdNamespace *ons,
    uint64_t lba, hwaddr mptr, NvmeRequest *req)
{
    NvmeCtrl *n = &o->nvme;
    OcssdChunkDescriptor *chk;
    OcssdChunkAcctDescriptor *chk_acct;
    uint8_t p;

    chk = ocssd_ns_get_chunk(ons, lba);
    if (!chk) {
        trace_ocssd_err_invalid_chunk(req->cqe.cid,
            lba & ~ons->addrf.sec_mask);
        return OCSSD_INVALID_RESET | NVME_DNR;
    }

    if (chk->state & OCSSD_CHUNK_RESETABLE) {
        switch (chk->state) {
        case OCSSD_CHUNK_FREE:
            trace_ocssd_notice_double_reset(req->cqe.cid, lba);

            if (!(ons->id.mccap & OCSSD_IDENTITY_MCCAP_MULTIPLE_RESETS)) {
                return OCSSD_INVALID_RESET | NVME_DNR;
            }

            break;

        case OCSSD_CHUNK_OPEN:
            trace_ocssd_notice_early_reset(req->cqe.cid, lba, chk->wp);
            if (!(ons->id.mccap & OCSSD_IDENTITY_MCCAP_EARLY_RESET)) {
                return OCSSD_INVALID_RESET | NVME_DNR;
            }

            break;
        }

        if (ons->resetfail) {
            p = ons->resetfail[ocssd_ns_chk_idx(ons, lba)];

            if (p == 100 || (rand() % 100) < p) {
                chk->state = OCSSD_CHUNK_OFFLINE;
                chk->wp = UINT64_MAX;
                trace_ocssd_inject_reset_err(req->cqe.cid, p, lba);
                return OCSSD_INVALID_RESET | NVME_DNR;
            }
        }

        chk->state = OCSSD_CHUNK_FREE;

        if (chk->type == OCSSD_CHUNK_TYPE_SEQUENTIAL) {
            chk->wp = 0;

            chk_acct = ocssd_ns_get_chunk_acct(ons, lba);

            if (chk_acct->pe_cycles < ons->hdr.pe_cycles) {
                chk_acct->pe_cycles++;

                ons->wear_index_total++;
                ons->wear_index_avg = ons->wear_index_total / ons->chks_total;

                chk->wear_index = ocssd_ns_calc_wi(ons, chk_acct->pe_cycles);

                if (_wi_outside_threshold(ons, chk)) {
                    ocssd_add_chunk_notification(o, ons, chk->slba,
                        OCSSD_CHUNK_NOTIFICATION_STATE_WLI,
                        OCSSD_CHUNK_NOTIFICATION_MASK_CHUNK, 0);

                    nvme_enqueue_event(n, NVME_AER_TYPE_VENDOR_SPECIFIC, 0x0,
                        OCSSD_CHUNK_NOTIFICATION);
                }
            }

            if (chk->wear_index == 255) {
                chk->state = OCSSD_CHUNK_OFFLINE;
            }

            ocssd_commit_chunk_acct(o, ons, req, chk, chk_acct);
        }

        if (mptr) {
            nvme_addr_write(n, mptr, chk, sizeof(*chk));
        }

        ocssd_commit_chunk_info(o, ons, req, chk);

        return NVME_SUCCESS;
    }

    trace_ocssd_err_offline_chunk(req->cqe.cid, lba);

    return OCSSD_OFFLINE_CHUNK | NVME_DNR;
}

static uint16_t ocssd_do_advance_wp(OcssdCtrl *o, OcssdNamespace *ons,
    uint64_t lba, uint16_t nlb, NvmeRequest *req)
{
    OcssdChunkDescriptor *chk;

    trace_ocssd_advance_wp(req->cqe.cid, lba, nlb);
    _dprint_lba(o, ons, lba);

    chk = ocssd_ns_get_chunk(ons, lba);
    if (!chk) {
        NVME_GUEST_ERR(ocssd_err_invalid_chunk,
            "invalid chunk; cid %d slba 0x%lx", req->cqe.cid,
            lba & ~ons->addrf.sec_mask);
        return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }

    if (chk->state == OCSSD_CHUNK_FREE) {
        chk->state = OCSSD_CHUNK_OPEN;
    }

    if (chk->type == OCSSD_CHUNK_TYPE_RANDOM) {
        goto commit;
    }

    if (chk->state != OCSSD_CHUNK_OPEN) {
        NVME_GUEST_ERR(ocssd_err_invalid_chunk_state,
            "invalid chunk state; cid %d slba 0x%lx state 0x%x",
            req->cqe.cid, lba, chk->state);
        return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }

    chk->wp += nlb;
    if (chk->wp == chk->cnlb) {
        chk->state = OCSSD_CHUNK_CLOSED;
    }

commit:
    ocssd_commit_chunk_info(o, ons, req, chk);

    return NVME_SUCCESS;
}

static void ocssd_dsm_cb(void *opaque, int ret)
{
    NvmeBlockBackendRequest *blk_req = opaque;
    NvmeRequest *req = blk_req->req;
    NvmeSQueue *sq = req->sq;
    NvmeCtrl *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];
    NvmeNamespace *ns = req->ns;

    OcssdCtrl *o = OCSSD(n);
    OcssdNamespace *ons = OCSSD_NS(ns);

    uint16_t status;

    QTAILQ_REMOVE(&req->blk_req_tailq, blk_req, tailq_entry);

    if (!ret) {
        status = ocssd_do_chunk_reset(o, ons, blk_req->slba, 0x0, req);
        if (status) {
            trace_ocssd_err(req->cqe.cid, "ocssd_do_chunk_reset", status);
            req->status = status;
            goto out;
        }
    } else {
        NVME_GUEST_ERR(nvme_err_internal_dev_error, "block request failed: %s",
            strerror(-ret));
        req->status = NVME_INTERNAL_DEV_ERROR;
    }

out:
    if (QTAILQ_EMPTY(&req->blk_req_tailq)) {
        nvme_enqueue_req_completion(cq, req);
    }

    nvme_blk_req_put(n, blk_req);
}


static uint16_t ocssd_dsm(OcssdCtrl *o, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeCtrl *n = &o->nvme;
    NvmeNamespace *ns = req->ns;
    NvmeDsmCmd *dsm = (NvmeDsmCmd *) cmd;

    OcssdNamespace *ons = OCSSD_NS(ns);

    uint16_t status;

    if (dsm->attributes & NVME_DSMGMT_AD) {
        NvmeBlockBackendRequest *blk_req;
        OcssdChunkDescriptor *chk;

        uint16_t nr = (dsm->nr & 0xff) + 1;
        uint8_t lbads = nvme_ns_lbads(ns);

        NvmeDsmRange range[nr];

        status = nvme_dma_write(n, (uint8_t *) range, sizeof(range), cmd, req);
        if (status) {
            trace_ocssd_err(req->cqe.cid, "nvme_dma_write", status);
            return status;
        }

        for (int i = 0; i < nr; i++) {
            int64_t sidx = ocssd_ns_sectr_idx(ons, range[i].slba);

            chk = ocssd_ns_get_chunk(ons, range[i].slba);

            if (!chk) {
                trace_ocssd_err_invalid_chunk(req->cqe.cid,
                    range[i].slba & ~ons->addrf.sec_mask);
                return OCSSD_INVALID_RESET | NVME_DNR;
            }

            if (range[i].nlb != chk->cnlb) {
                trace_ocssd_err(req->cqe.cid, "invalid reset size",
                    NVME_LBA_RANGE);
                return NVME_LBA_RANGE | NVME_DNR;
            }

            blk_req = nvme_blk_req_get(n, req, NULL);
            if (!blk_req) {
                NVME_GUEST_ERR(nvme_err_internal_dev_error,
                    "nvme_blk_req_get: %s", "could not allocate memory");
                return NVME_INTERNAL_DEV_ERROR;
            }

            blk_req->slba = range[i].slba;

            blk_req->aiocb = blk_aio_pdiscard(ns->conf.blk,
                ns->blk_offset + (sidx << lbads), range[i].nlb << lbads,
                ocssd_dsm_cb, blk_req);

            QTAILQ_INSERT_TAIL(&req->blk_req_tailq, blk_req, tailq_entry);

            if (ns->params.ms) {
                blk_req = nvme_blk_req_get(n, req, NULL);
                if (!blk_req) {
                    NVME_GUEST_ERR(nvme_err_internal_dev_error,
                        "nvme_blk_req_get: %s", "could not allocate memory");
                    return NVME_INTERNAL_DEV_ERROR;
                }

                blk_req->slba = range[i].slba;

                blk_req->aiocb = blk_aio_pdiscard(ns->conf.blk,
                    ns->blk_offset_md + sidx * nvme_ns_ms(ns),
                    range[i].nlb * nvme_ns_ms(ns), nvme_noop_cb, blk_req);

                QTAILQ_INSERT_TAIL(&req->blk_req_tailq, blk_req, tailq_entry);
            }
        }

        return NVME_NO_COMPLETE;
    }

    return NVME_SUCCESS;
}

static void ocssd_reset_cb(void *opaque, int ret)
{
    NvmeBlockBackendRequest *blk_req = opaque;
    NvmeRequest *req = blk_req->req;
    NvmeSQueue *sq = req->sq;
    NvmeCtrl *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];
    NvmeNamespace *ns = req->ns;

    OcssdCtrl *o = OCSSD(n);
    OcssdNamespace *ons = OCSSD_NS(ns);

    hwaddr mptr;
    uint16_t status;

    QTAILQ_REMOVE(&req->blk_req_tailq, blk_req, tailq_entry);

    if (!ret) {
        /*
         * blk_req->nlb has been hijacked to store the index that this entry
         * held in the LBA list, so use that to calculate the MPTR offset.
         */
        mptr = req->mptr ? req->mptr +
            blk_req->nlb * sizeof(OcssdChunkDescriptor) : 0x0;
        status = ocssd_do_chunk_reset(o, ons, blk_req->slba, mptr, req);
        if (status) {
            trace_ocssd_err(req->cqe.cid, "ocssd_do_chunk_reset", status);
            req->status = status;
            goto out;
        }
    } else {
        NVME_GUEST_ERR(nvme_err_internal_dev_error, "block request failed: %s",
            strerror(-ret));
        req->status = NVME_INTERNAL_DEV_ERROR;
    }

out:
    if (QTAILQ_EMPTY(&req->blk_req_tailq)) {
        nvme_enqueue_req_completion(cq, req);
    }

    nvme_blk_req_put(n, blk_req);
}

static uint16_t ocssd_reset(OcssdCtrl *o, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeCtrl *n = &o->nvme;
    NvmeNamespace *ns = req->ns;
    OcssdRwCmd *rst = (OcssdRwCmd *) cmd;
    OcssdNamespace *ons = OCSSD_NS(ns);
    hwaddr lbal_addr = le64_to_cpu(rst->lbal);
    uint16_t nlb = le16_to_cpu(rst->nlb) + 1;
    uint8_t lbads = nvme_ns_lbads(req->ns);
    uint16_t status = NVME_NO_COMPLETE;
    uint64_t *lbal;

    trace_ocssd_reset(req->cqe.cid, nlb);

    req->nlb = nlb;
    req->mptr = le64_to_cpu(cmd->mptr);

    _get_lba_list(o, lbal_addr, &lbal, req);
    req->slba = (uint64_t) lbal;

    for (int i = 0; i < nlb; i++) {
        uint64_t slba = _vlba(req, i);
        uint64_t sidx = ocssd_ns_sectr_idx(ons, slba);

        OcssdChunkDescriptor *chk;

        NvmeBlockBackendRequest *blk_req = nvme_blk_req_get(n, req, NULL);
        if (!blk_req) {
            NVME_GUEST_ERR(nvme_err_internal_dev_error, "nvme_blk_req_get: %s",
                "could not allocate memory");
            status = NVME_INTERNAL_DEV_ERROR | NVME_DNR;
            goto out;
        }

        blk_req->slba = slba;

        /*
         * The resetting of multiple chunks is done asynchronously, so hijack
         * blk_req->nlb to store the LBAL index which is required for the
         * callback to know the index in MPTR at which to store the updated
         * chunk descriptor.
         */
        blk_req->nlb = i;

        chk = ocssd_ns_get_chunk(ons, blk_req->slba);
        if (!chk) {
            trace_ocssd_err_invalid_chunk(req->cqe.cid,
                blk_req->slba & ~ons->addrf.sec_mask);
            status = OCSSD_INVALID_RESET | NVME_DNR;
            goto out;
        }

        blk_req->aiocb = blk_aio_pdiscard(ns->conf.blk,
            req->ns->blk_offset + (sidx << lbads), chk->cnlb << lbads,
            ocssd_reset_cb, blk_req);

        QTAILQ_INSERT_TAIL(&req->blk_req_tailq, blk_req, tailq_entry);

        if (ns->params.ms) {
            blk_req = nvme_blk_req_get(n, req, NULL);
            if (!blk_req) {
                NVME_GUEST_ERR(nvme_err_internal_dev_error,
                    "nvme_blk_req_get: %s", "could not allocate memory");
                status = NVME_INTERNAL_DEV_ERROR | NVME_DNR;
                goto out;
            }

            blk_req->slba = slba;

            blk_req->aiocb = blk_aio_pdiscard(ns->conf.blk,
                req->ns->blk_offset_md + slba * nvme_ns_ms(ns),
                chk->cnlb * nvme_ns_ms(ns), nvme_noop_cb, blk_req);

            QTAILQ_INSERT_TAIL(&req->blk_req_tailq, blk_req, tailq_entry);
        }
    }

out:
    if (req->nlb > 1) {
        g_free((uint64_t *) req->slba);
    }

    return status;
}

static uint16_t ocssd_maybe_write_error_inject(OcssdCtrl *o,
    NvmeBlockBackendRequest *blk_req)
{
    NvmeRequest *req = blk_req->req;
    NvmeNamespace *ns = req->ns;
    OcssdNamespace *ons = OCSSD_NS(ns);
    OcssdChunkDescriptor *chk;
    uint8_t p;
    uint64_t cidx, slba = blk_req->slba;

    if (!ons->writefail || !req->is_write) {
        return NVME_SUCCESS;
    }

    for (uint16_t i = 0; i < blk_req->nlb; i++) {
        p = ons->writefail[ocssd_ns_sectr_idx(ons, slba + i)];

        if (p && (p == 100 || (rand() % 100) < p)) {
            trace_ocssd_inject_write_err(req->cqe.cid, p, slba + i);

            chk = ocssd_ns_get_chunk(ons, slba);
            if (!chk) {
                NVME_GUEST_ERR(ocssd_err_invalid_chunk,
                    "invalid chunk; cid %d addr 0x%lx", req->cqe.cid,
                    slba & ~ons->addrf.sec_mask);
                return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
            }

            cidx = ocssd_ns_chk_idx(ons, slba + i);
            chk->state = OCSSD_CHUNK_CLOSED;

            ocssd_commit_chunk_info(o, ons, req, chk);
            ons->resetfail[cidx] = 100;

            if (_is_vector_request(req)) {
                for (uint16_t j = 0; j < req->nlb; j++) {
                    if (cidx == ocssd_ns_chk_idx(ons, slba)) {
                        bitmap_set(&req->cqe.res64, j, 1);
                    }
                }
            }

            return OCSSD_CHUNK_EARLY_CLOSE | NVME_DNR;
        }
    }

    return NVME_SUCCESS;
}

static void ocssd_rwc_aio_complete(OcssdCtrl *o,
    NvmeBlockBackendRequest *blk_req, int ret)
{
    NvmeRequest *req = blk_req->req;
    NvmeNamespace *ns = req->ns;
    OcssdNamespace *ons = OCSSD_NS(ns);
    uint16_t status;

    if (!ret) {
        block_acct_done(blk_get_stats(ns->conf.blk), &blk_req->acct);

        if (req->is_write && blk_req->blk_offset >= ns->blk_offset &&
            blk_req->blk_offset < ns->blk_offset_md) {

            /*
             * We know that each NvmeBlockBackendRequest corresponds to a write
             * to at most one chunk (one contiguous write). This way, we can
             * allow a write to a single chunk to fail (while leaving the write
             * pointer intact), but allow writes to other chunks to proceed.
             */
            status = ocssd_maybe_write_error_inject(o, blk_req);
            if (!status) {
                status = ocssd_do_advance_wp(o, ons, blk_req->slba,
                    blk_req->nlb, req);
            }

            /*
             * An internal device error trumps all other errors, but there is
             * no way of triaging other errors, so only set an error if one has
             * not already been set.
             */
            if (status) {
                if (nvme_is_error(status, NVME_INTERNAL_DEV_ERROR)) {
                    NVME_GUEST_ERR(nvme_err_internal_dev_error, "%s",
                        "internal device error");
                    req->status = status;
                }

                if (!req->status) {
                    req->status = status;
                }
            }
        }
    } else {
        block_acct_failed(blk_get_stats(ns->conf.blk), &blk_req->acct);
        NVME_GUEST_ERR(nvme_err_internal_dev_error, "block request failed: %s",
            strerror(-ret));
        req->status = NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }
}

static void ocssd_copy_out_cb(void *opaque, int ret)
{
    NvmeBlockBackendRequest *blk_req = opaque;
    NvmeRequest *req = blk_req->req;
    NvmeSQueue *sq = req->sq;
    NvmeCtrl *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];

    OcssdCtrl *o = OCSSD(n);
    OcssdNamespace *ons = OCSSD_NS(req->ns);
    hwaddr addr;

    trace_ocssd_copy_out_cb(req->cqe.cid, req->ns->params.nsid);

    QTAILQ_REMOVE(&req->blk_req_tailq, blk_req, tailq_entry);

    ocssd_rwc_aio_complete(o, blk_req, ret);
    nvme_blk_req_put(n, blk_req);

    if (QTAILQ_EMPTY(&req->blk_req_tailq)) {
        /* free the bounce buffers */
        addr = req->cmd.cdw12;
        addr = (addr << 32) | req->cmd.cdw13;
        g_free((void *) addr);

        if (ons->hdr.md_size) {
            g_free((void *) req->cmd.mptr);
        }

        nvme_enqueue_req_completion(cq, req);
    }
}

static void ocssd_copy_in_cb(void *opaque, int ret)
{
    NvmeBlockBackendRequest *blk_req = opaque;
    NvmeRequest *req = blk_req->req;
    NvmeSQueue *sq = req->sq;
    NvmeCtrl *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];
    NvmeNamespace *ns = req->ns;

    OcssdCtrl *o = OCSSD(n);
    OcssdNamespace *ons = OCSSD_NS(ns);
    OcssdCopyCmd *cpy = (OcssdCopyCmd *) &req->cmd;

    hwaddr addr = le64_to_cpu(cpy->dlbal);
    uint64_t *dlbal;
    size_t unit_len = nvme_ns_lbads_bytes(ns);
    size_t unit_len_meta = nvme_ns_ms(ns);
    uint16_t status;

    QEMUSGList qsg;

    QTAILQ_REMOVE(&req->blk_req_tailq, blk_req, tailq_entry);

    trace_ocssd_copy_in_cb(req->cqe.cid, req->ns->params.nsid);

    if (!ret) {
        block_acct_done(blk_get_stats(ns->conf.blk), &blk_req->acct);
    } else {
        block_acct_failed(blk_get_stats(ns->conf.blk), &blk_req->acct);
        NVME_GUEST_ERR(nvme_err_internal_dev_error, "block request failed: %s",
            strerror(-ret));
        req->status = NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }

    nvme_blk_req_put(n, blk_req);

    if (QTAILQ_EMPTY(&req->blk_req_tailq)) {
        _get_lba_list(o, addr, &dlbal, req);
        req->slba = (uint64_t) dlbal;

        /* second phase of copy is a write */
        req->is_write = true;

        addr = req->cmd.cdw12;
        addr = (addr << 32) | req->cmd.cdw13;

        status = ocssd_rw_check_vector_req(o, &req->cmd, req, NULL);
        if (status) {
            trace_ocssd_err(req->cqe.cid, "ocssd_rw_check_vector_req",
                status);
            goto out;
        }

        pci_dma_sglist_init(&qsg, &n->parent_obj, 1);
        qemu_sglist_add(&qsg, addr, req->nlb * unit_len);

        status = ocssd_blk_setup_vector(n, ns, &qsg, ns->blk_offset, unit_len,
            req);
        if (status) {
            trace_ocssd_err(req->cqe.cid, "ocssd_blk_setup_vector", status);
            goto out_sglist_destroy;
        }

        if (ons->hdr.md_size) {
            qsg.nsg = 0;
            qsg.size = 0;

            qemu_sglist_add(&qsg, req->cmd.mptr, req->nlb * unit_len_meta);

            status = ocssd_blk_setup_vector(n, ns, &qsg, ns->blk_offset_md,
                unit_len_meta, req);
            if (status) {
                trace_ocssd_err(req->cqe.cid, "ocssd_blk_setup_vector", status);
                goto out_sglist_destroy;
            }
        }

        QTAILQ_FOREACH(blk_req, &req->blk_req_tailq, tailq_entry) {
            qemu_iovec_init(&blk_req->iov, blk_req->qsg->nsg);
            _sglist_to_iov(n, blk_req->qsg, &blk_req->iov);

            block_acct_start(blk_get_stats(ns->conf.blk), &blk_req->acct,
                blk_req->iov.size, BLOCK_ACCT_WRITE);

            blk_req->aiocb = blk_aio_pwritev(ns->conf.blk, blk_req->blk_offset,
                &blk_req->iov, 0, ocssd_copy_out_cb, blk_req);
        }

out_sglist_destroy:
        qemu_sglist_destroy(&qsg);

out:
        if (req->nlb > 1) {
            g_free(dlbal);
        }

        if (status != NVME_SUCCESS) {
            g_free((void *) addr);

            if (ons->hdr.md_size) {
                g_free((void *) req->cmd.mptr);
            }

            req->status = status;
            nvme_enqueue_req_completion(cq, req);
        }
    }
}

static uint16_t ocssd_copy(OcssdCtrl *o, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeCtrl *n = &o->nvme;
    NvmeNamespace *ns = req->ns;
    OcssdNamespace *ons = OCSSD_NS(ns);
    OcssdCopyCmd *cpy = (OcssdCopyCmd *) cmd;
    NvmeBlockBackendRequest *blk_req;

    hwaddr addr = 0x0;
    uint64_t *lbal;
    uint64_t dulbe = 0;
    size_t unit_len = nvme_ns_lbads_bytes(ns);
    size_t unit_len_meta = nvme_ns_ms(ns);
    uint16_t status;

    trace_ocssd_copy(req->cqe.cid, req->nlb);

    if (req->nlb > OCSSD_MAX_VECTOR_COMMAND_LBAS) {
        trace_ocssd_err(req->cqe.cid, "OCSSD_CMD_MAX_LBAS exceeded",
            NVME_INVALID_FIELD | NVME_DNR);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    _get_lba_list(o, le64_to_cpu(cpy->lbal), &lbal, req);
    req->slba = (uint64_t) lbal;

    status = ocssd_rw_check_vector_req(o, cmd, req, &dulbe);
    if (status) {
        trace_ocssd_err(req->cqe.cid, "ocssd_rw_check_vector_req",
            status);
        goto out;
    }

    if (NVME_ERR_REC_DULBE(n->features.err_rec)) {
        for (uint32_t i = 0; i < req->nlb; i++) {
            if (dulbe & (1 << i)) {
                status = NVME_DULB | NVME_DNR;
                goto out;
            }
        }
    }

    /*
     * For now, use bounce buffers to do the copy. Store the bounce buffer
     * addresses in the unused cdw12/cdw13 and mptr fields so it can be
     * referred to in the callback.
     */
    addr = (hwaddr) g_malloc_n(req->nlb, unit_len);
    req->cmd.cdw12 = addr >> 32;
    req->cmd.cdw13 = addr & 0xffffffff;

    QEMUSGList qsg;
    pci_dma_sglist_init(&qsg, &n->parent_obj, 1);
    qemu_sglist_add(&qsg, addr, req->nlb * unit_len);

    status = ocssd_blk_setup_vector(n, ns, &qsg, ns->blk_offset, unit_len,
        req);
    if (status) {
        trace_ocssd_err(req->cqe.cid, "ocssd_blk_setup_vector", status);
        goto out_sglist_destroy;
    }

    if (ons->hdr.md_size) {
        req->cmd.mptr = (hwaddr) g_malloc_n(req->nlb, unit_len_meta);

        qsg.nsg = 0;
        qsg.size = 0;

        qemu_sglist_add(&qsg, req->cmd.mptr, req->nlb * unit_len_meta);

        status = ocssd_blk_setup_vector(n, ns, &qsg, ns->blk_offset_md,
            unit_len_meta, req);
        if (status) {
            trace_ocssd_err(req->cqe.cid, "ocssd_blk_setup_vector", status);
            goto out_sglist_destroy;
        }
    }

    QTAILQ_FOREACH(blk_req, &req->blk_req_tailq, tailq_entry) {
        qemu_iovec_init(&blk_req->iov, blk_req->qsg->nsg);
        _sglist_to_iov(n, blk_req->qsg, &blk_req->iov);

        block_acct_start(blk_get_stats(ns->conf.blk), &blk_req->acct,
            blk_req->iov.size, BLOCK_ACCT_READ);

        blk_req->aiocb = blk_aio_preadv(ns->conf.blk, blk_req->blk_offset,
            &blk_req->iov, 0, ocssd_copy_in_cb, blk_req);
    }

out_sglist_destroy:
    qemu_sglist_destroy(&qsg);

out:
    if (req->nlb > 1) {
        g_free(lbal);
    }

    if (status) {
        g_free((void *) addr);

        if (ons->hdr.md_size) {
            g_free((void *) req->cmd.mptr);
        }

        return status;
    }

    return NVME_NO_COMPLETE;
}


static void ocssd_rw_cb(void *opaque, int ret)
{
    NvmeBlockBackendRequest *blk_req = opaque;
    NvmeRequest *req = blk_req->req;
    NvmeSQueue *sq = req->sq;
    NvmeCtrl *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];

    OcssdCtrl *o = OCSSD(n);

    trace_ocssd_rw_cb(req->cqe.cid, req->ns->params.nsid);

    QTAILQ_REMOVE(&req->blk_req_tailq, blk_req, tailq_entry);

    ocssd_rwc_aio_complete(o, blk_req, ret);

    if (QTAILQ_EMPTY(&req->blk_req_tailq)) {
        trace_nvme_enqueue_req_completion(req->cqe.cid, cq->cqid);
        nvme_enqueue_req_completion(cq, req);
    }

    if (_is_vector_request(req)) {
        g_free(blk_req->qsg);
    }

    nvme_blk_req_put(n, blk_req);
}

static uint16_t ocssd_rw(OcssdCtrl *o, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeCtrl *n = &o->nvme;
    OcssdRwCmd *orw = (OcssdRwCmd *) cmd;

    uint64_t dulbe = 0;
    uint64_t *lbal;
    uint64_t lbal_addr = le64_to_cpu(orw->lbal);
    uint16_t status = NVME_SUCCESS;

    if (req->nlb > OCSSD_MAX_VECTOR_COMMAND_LBAS) {
        trace_ocssd_err(req->cqe.cid, "OCSSD_CMD_MAX_LBAS exceeded",
            NVME_INVALID_FIELD | NVME_DNR);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    _get_lba_list(o, lbal_addr, &lbal, req);
    req->slba = (uint64_t) lbal;

    _dprint_vector_rw(o, req);

    status = ocssd_rw_check_vector_req(o, cmd, req, &dulbe);
    if (status) {
        trace_ocssd_err(req->cqe.cid, "ocssd_rw_check_vector_req", status);
        goto out;
    }

    if (!req->is_write && NVME_ERR_REC_DULBE(n->features.err_rec)) {
        for (uint32_t i = 0; i < req->nlb; i++) {
            if (dulbe & (1 << i)) {
                status = NVME_DULB | NVME_DNR;
                goto out;
            }
        }
    }

    status = nvme_blk_map(n, cmd, req, ocssd_blk_setup_vector);
    if (status) {
        trace_ocssd_err(req->cqe.cid, "nvme_blk_map", status);
        goto out;
    }

out:
    if (req->nlb > 1) {
        g_free((uint64_t *) req->slba);
    }

    if (status) {
        return status;
    }

    return nvme_blk_submit_io(n, req, ocssd_rw_cb);
}

static uint16_t ocssd_geometry(OcssdCtrl *o, NvmeCmd *cmd, NvmeRequest *req)
{
    OcssdNamespace *ons = _ons(o, le32_to_cpu(cmd->nsid));
    if (!ons) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    return nvme_dma_read(&o->nvme, (uint8_t *) &ons->id, sizeof(OcssdIdentity),
        cmd, req);
}

static uint16_t ocssd_get_log(OcssdCtrl *o, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeCtrl *n = &o->nvme;

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

    switch (lid) {
    case OCSSD_CHUNK_INFO:
        return ocssd_do_get_chunk_info(o, cmd, len, off, req);
    case OCSSD_CHUNK_NOTIFICATION:
        return ocssd_do_get_chunk_notification(o, cmd, len, off, rae, req);
    default:
        return nvme_get_log(n, cmd, req);
    }
}

static uint16_t ocssd_get_feature(OcssdCtrl *o, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeCtrl *n = &o->nvme;

    uint32_t dw10 = le32_to_cpu(cmd->cdw10);

    trace_ocssd_getfeat(dw10);

    switch (dw10) {
    case OCSSD_MEDIA_FEEDBACK:
        req->cqe.cdw0 = cpu_to_le32(o->features.media_feedback);
        break;
    default:
        return nvme_get_feature(n, cmd, req);
    }

    return NVME_SUCCESS;
}

static uint16_t ocssd_set_feature(OcssdCtrl *o, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeCtrl *n = &o->nvme;

    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint32_t dw11 = le32_to_cpu(cmd->cdw11);

    trace_ocssd_setfeat(dw10, dw11);

    switch (dw10) {
    case NVME_ERROR_RECOVERY:
        n->features.err_rec = dw11;
        break;
    case OCSSD_MEDIA_FEEDBACK:
        o->features.media_feedback = dw11;
        break;
    default:
        return nvme_set_feature(n, cmd, req);
    }

    return NVME_SUCCESS;
}

static uint16_t ocssd_admin_cmd(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    OcssdCtrl *o = OCSSD(n);

    switch (cmd->opcode) {
    case NVME_ADM_CMD_SET_FEATURES:
        return ocssd_set_feature(o, cmd, req);
    case NVME_ADM_CMD_GET_FEATURES:
        return ocssd_get_feature(o, cmd, req);
    case OCSSD_ADM_CMD_GEOMETRY:
        return ocssd_geometry(o, cmd, req);
    case NVME_ADM_CMD_GET_LOG_PAGE:
        return ocssd_get_log(o, cmd, req);
    default:
        return nvme_admin_cmd(n, cmd, req);
    }
}

static uint16_t ocssd_io_cmd(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    OcssdCtrl *o = OCSSD(n);
    NvmeRwCmd *rw;
    uint16_t status;

    uint32_t nsid = le32_to_cpu(cmd->nsid);

    if (!nvme_nsid_is_valid(n, nsid)) {
        trace_nvme_err_invalid_ns(nsid, n->num_namespaces);
        return NVME_INVALID_NSID | NVME_DNR;
    }

    trace_ocssd_io_cmd(req->cqe.cid, nsid, cmd->opcode);

    req->ns = n->namespaces[nsid - 1];

    switch (cmd->opcode) {
    case NVME_CMD_READ:
    case NVME_CMD_WRITE:
        rw = (NvmeRwCmd *) cmd;

        req->nlb  = le16_to_cpu(rw->nlb) + 1;
        req->is_write = nvme_rw_is_write(req);
        req->slba = le64_to_cpu(rw->slba);

        trace_nvme_rw(req->is_write ? "write" : "read", req->nlb,
            req->nlb << nvme_ns_lbads(req->ns), req->slba);

        status = ocssd_rw_check_scalar_req(o, cmd, req);
        if (status) {
            trace_ocssd_err(req->cqe.cid, "ocssd_rw_check_scalar_req", status);
            return status;
        }

        status = nvme_blk_map(n, cmd, req, ocssd_blk_setup_scalar);
        if (status) {
            trace_ocssd_err(req->cqe.cid, "nvme_blk_map", status);
            return status;
        }

        return nvme_blk_submit_io(n, req, ocssd_rw_cb);

    case NVME_CMD_DSM:
        return ocssd_dsm(o, cmd, req);

    case OCSSD_CMD_VECT_READ:
    case OCSSD_CMD_VECT_WRITE:
        rw = (NvmeRwCmd *) cmd;

        req->nlb = le16_to_cpu(rw->nlb) + 1;
        req->is_write = _is_write(req);

        trace_ocssd_rw(req->cqe.cid, nsid, req->cmd.opcode, req->nlb);

        return ocssd_rw(o, cmd, req);

    case OCSSD_CMD_VECT_COPY:
        rw = (NvmeRwCmd *) cmd;
        req->nlb = le16_to_cpu(rw->nlb) + 1;

        /* first phase of copy is a read */
        req->is_write = false;

        return ocssd_copy(o, cmd, req);

    case OCSSD_CMD_VECT_RESET:
        return ocssd_reset(o, cmd, req);

    default:
        return nvme_io_cmd(n, cmd, req);
    }
}

static void ocssd_free_namespace(OcssdCtrl *o, OcssdNamespace *ons)
{
    g_free(ons->info.descr);
    g_free(ons->acct.descr);
    g_free(ons->resetfail);
    g_free(ons->writefail);
}

static void ocssd_free_namespaces(OcssdCtrl *o)
{
    NvmeCtrl *n = &o->nvme;
    OcssdNamespace *ons;
    for (int i = 0; i < n->num_namespaces; i++) {
        ons = OCSSD_NS(n->namespaces[i]);
        ocssd_free_namespace(o, ons);
    }
}

static void ocssd_realize(PCIDevice *pci_dev, Error **errp)
{
    OcssdCtrl *o = OCSSD(pci_dev);
    NvmeCtrl *n = &o->nvme;
    NvmeIdCtrl *id_ctrl = &n->id_ctrl;
    Error *local_err = NULL;

    n->admin_cmd = ocssd_admin_cmd;
    n->io_cmd = ocssd_io_cmd;

    if (nvme_check_constraints(n, &local_err)) {
        error_propagate_prepend(errp, local_err, "nvme_check_constraints: ");
        return;
    }

    qbus_create_inplace(&n->bus, sizeof(NvmeBus), TYPE_NVME_BUS,
        &pci_dev->qdev, n->parent_obj.qdev.id);

    nvme_init_state(n);

    nvme_init_pci(n, pci_dev);
    pci_config_set_vendor_id(pci_dev->config, PCI_VENDOR_ID_CNEX);
    pci_config_set_device_id(pci_dev->config, 0x1f1f);
    nvme_init_ctrl(n);

    n->id_ctrl.oncs |= cpu_to_le16(NVME_ONCS_DSM);

    strpadcpy((char *)id_ctrl->mn, sizeof(id_ctrl->mn),
        "QEMU NVM Express LightNVM Controller", ' ');
}

static void ocssd_exit(PCIDevice *pci_dev)
{
    OcssdCtrl *o = OCSSD(pci_dev);

    ocssd_free_namespaces(o);
    nvme_free_ctrl(&o->nvme, pci_dev);
}

static Property ocssd_props[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static const VMStateDescription ocssd_vmstate = {
    .name = "ocssd",
    .unmigratable = 1,
};

static void ocssd_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    PCIDeviceClass *pc = PCI_DEVICE_CLASS(oc);

    pc->realize = ocssd_realize;
    pc->exit = ocssd_exit;
    pc->class_id = PCI_CLASS_STORAGE_EXPRESS;
    pc->vendor_id = PCI_VENDOR_ID_CNEX;
    pc->device_id = 0x1f1f;
    pc->revision = 2;

    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    dc->desc = "OpenChannel 2.0 NVMe";
    dc->props = ocssd_props;
    dc->vmsd = &ocssd_vmstate;
}

static const TypeInfo ocssd_info = {
    .name          = TYPE_OCSSD,
    .parent        = TYPE_NVME,
    .instance_size = sizeof(OcssdCtrl),
    .class_init    = ocssd_class_init,
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_PCIE_DEVICE },
        { }
    },
};

static void ocssd_register_types(void)
{
    type_register_static(&ocssd_info);
}

type_init(ocssd_register_types)
