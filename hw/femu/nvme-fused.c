/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Fused Compare and Write (fused_cw, NVM Command Set 1.2, 2.1.3.1)
 *
 * A Compare (FUSE 01b) and the Write after it (FUSE 10b) run as one
 * atomic unit: the Write programs only when the Compare matches, and no
 * other command on the range sees a state between the two.
 *
 *  fetch:  both SQEs --> checks --> both payloads staged
 *  run:    lock range --> DULBE, uncorrectable, memcmp
 *            match:    book the Write (bbssd) --> copy --> mark --> unlock
 *            no match: Compare 0285h, Write 09h, nothing booked
 *
 * A NoSSD pair runs at fetch on the poller. A bbssd pair rides to the FTL
 * thread on the Compare's request, which carries the Write's request,
 * and runs there, so the Write books from the end of the Compare read.
 * Every other command that changes bytes also changes the block state in
 * the same range lock (nvme_zero_range(), backend_rw_done()), so the pair
 * never sees a half-done one.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "nvme.h"

/*
 * ACWU and the staging cap: one pair stages at most twice this, and at
 * most FEMU_FUSED_MAX pairs are in flight on a controller.
 */
#define FEMU_FUSED_CAP      (1u << 20)
#define FEMU_FUSED_BLOCKS   65536u

/**
 * femu_fused_check - validate fused_cw at realize and size ACWU
 * @n: the controller
 * @errp: set on a refusal
 *
 * The refused options either keep a second copy of block data (metadata,
 * PI, the power-loss model, a CXL medium) or end commands by a path the
 * pair does not take (cancel, reservations, Opal, a femu-subsys).
 */
bool femu_fused_check(FemuCtrl *n, Error **errp)
{
    unsigned lbads = BDRV_SECTOR_BITS + MAX(n->nlbaf, 1) - 1;
    unsigned shift = 12 + n->mpsmin + n->mdts;
    uint64_t limit = FEMU_FUSED_CAP;
    uint64_t blocks;
    const char *why = NULL;

    n->fused_acwu = 0;
    if (!n->fused_cw) {
        return true;
    }
    if ((n->femu_mode != FEMU_BBSSD_MODE &&
         n->femu_mode != FEMU_NOSSD_MODE) || n->namespace_modes) {
        why = "a mode other than bbssd or NoSSD";
    } else if (n->subsys) {
        why = "a femu-subsys";
    } else if (n->meta || n->pi || n->extended) {
        why = "metadata";
    } else if (n->opal) {
        why = "x-opal";
    } else if (n->cancel) {
        why = "cancel";
    } else if (n->reservations) {
        why = "reservations";
    } else if (n->power_loss) {
        why = "power_loss";
    } else if (n->cxl_dev) {
        why = "cxl_ssd";
    } else if (n->streams) {
        why = "streams";
    } else if (n->pcie_bandwidth_mbps || n->pcie_prop_delay_ns) {
        why = "the host link model";
    } else if (!(n->oncs & NVME_ONCS_COMPARE)) {
        why = "oncs without Compare";
    }
    if (why) {
        error_setg(errp, "femu: fused_cw is not supported with %s", why);
        return false;
    }
    /* MDTS 0 is no limit; a shift past 63 is none either */
    if (n->mdts && shift < 63) {
        limit = MIN(limit, UINT64_C(1) << shift);
    }
    blocks = MIN(limit >> lbads, FEMU_FUSED_BLOCKS);
    if (!blocks) {
        error_setg(errp, "femu: fused_cw needs MDTS to hold one block of "
                   "the largest LBA format");
        return false;
    }
    n->fused_acwu = blocks - 1;
    return true;
}

/**
 * femu_fused_check_cmd - the checks one command of a pair takes at fetch
 * @n: the controller
 * @cmd: the command
 * @nsp: set to its namespace, or NULL
 *
 * These read state only: they log no error and change nothing, as the
 * pair may still stay in the queue. DULBE and uncorrectable blocks are
 * checked when the pair runs, in the range lock.
 */
uint16_t femu_fused_check_cmd(FemuCtrl *n, NvmeCmd *cmd, NvmeNamespace **nsp)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)cmd;
    uint64_t slba = le64_to_cpu(rw->slba);
    uint32_t nlb = le16_to_cpu(rw->nlb) + 1;
    NvmeNamespace *ns = nvme_ns(n, le32_to_cpu(cmd->nsid));
    uint64_t nsze;

    *nsp = ns;
    if (!ns) {
        /* an inactive NSID, as nvme_io_cmd() answers it */
        uint32_t nsid = le32_to_cpu(cmd->nsid);

        if (nvme_ns_mgmt_supported(n) && nsid && nsid <= n->namespace_limit) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        return NVME_INVALID_NSID | NVME_DNR;
    }
    if (!NS_BBSSD(ns) && !NS_NOSSD(ns)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (unlikely(n->ana)) {
        uint16_t status = nvme_ana_io_check(n, ns);

        if (status) {
            return status;
        }
    }
    if (unlikely(n->ns_wp)) {
        bool noop;
        uint16_t status = femu_wp_io(ns, cmd, &noop);

        if (status) {
            return status;
        }
    }
    if (unlikely(qatomic_read(&ns->san_busy))) {
        return NVME_SANITIZE_NS_IN_PROGRESS;
    }
    if (unlikely(nvme_sanitize_busy(n))) {
        return NVME_SANITIZE_IN_PROGRESS;
    }
    if (!nvme_ns_io_effects(n, ns, cmd->opcode)) {
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
    /* Compare FUA asks for a read of the media past the write buffer */
    if (cmd->opcode == NVME_CMD_COMPARE &&
        (le16_to_cpu(rw->control) & NVME_RW_FUA)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    nsze = le64_to_cpu(ns->id_ns.nsze);
    if (slba > nsze || nlb > nsze - slba) {
        return NVME_LBA_RANGE | NVME_DNR;
    }
    if (nvme_check_mdts(n, (uint64_t)nlb << ns->lbaf.lbads)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    return NVME_SUCCESS;
}

/**
 * femu_fused_stage - copy the payloads of a pair from the host
 * @n: the controller
 * @c: the Compare
 * @w: the Write; one that failed its checks already has its status
 *
 * Returns the Compare's status. A Write whose data cannot be read gets
 * its own status; its Compare still runs (Figure 26). An SGL must name
 * exactly the transfer, as for a Compare or Write alone.
 */
uint16_t femu_fused_stage(FemuCtrl *n, NvmeRequest *c, NvmeRequest *w)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)&c->cmd;
    NvmeNamespace *ns = c->ns;
    uint32_t nlb = le16_to_cpu(rw->nlb) + 1;
    uint32_t len = nlb << ns->lbaf.lbads;
    uint16_t status;

    c->slba = w->slba = le64_to_cpu(rw->slba);
    c->nlb = w->nlb = nlb;
    c->is_write = 0;
    w->is_write = 1;
    c->fused_cmp = g_try_malloc(len);
    if (!c->fused_cmp) {
        return NVME_INTERNAL_DEV_ERROR;
    }
    status = dma_write_cmd_exact(n, &c->cmd, c->fused_cmp, len);
    if (status) {
        g_clear_pointer(&c->fused_cmp, g_free);
        return status;
    }
    if (w->status != NVME_SUCCESS) {
        return NVME_SUCCESS;
    }
    w->fused_wr = g_try_malloc(len);
    if (!w->fused_wr) {
        w->status = NVME_INTERNAL_DEV_ERROR;
        return NVME_SUCCESS;
    }
    status = dma_write_cmd_exact(n, &w->cmd, w->fused_wr, len);
    if (status) {
        g_clear_pointer(&w->fused_wr, g_free);
        w->status = status;
    }
    return NVME_SUCCESS;
}

/**
 * femu_fused_log - the error log entry of a pair command that failed a check
 * @n: the controller
 * @req: the command, taken from its queue
 *
 * The checks at fetch log nothing, as the pair may stay queued. Once it is
 * taken, each command that failed one gets its entry, as it would alone.
 */
void femu_fused_log(FemuCtrl *n, NvmeRequest *req)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)&req->cmd;
    uint16_t sc = req->status & ~NVME_DNR;
    uint16_t off;

    switch (sc) {
    case NVME_LBA_RANGE:
        off = offsetof(NvmeRwCmd, nlb);
        break;
    case NVME_INVALID_FIELD:
    case NVME_INVALID_NSID:
    case NVME_INVALID_OPCODE:
        off = sc == NVME_INVALID_NSID ? offsetof(NvmeRwCmd, nsid) :
              offsetof(NvmeRwCmd, opcode);
        break;
    default:
        return;
    }
    nvme_set_error_page(n, req->sq->sqid, req->cqe.cid, sc, off,
                        le64_to_cpu(rw->slba), le32_to_cpu(rw->nsid),
                        req->cmd.opcode, req->ns ? req->ns->csi : 0);
}

/**
 * femu_fused_drop - end a staged pair that does not run
 * @n: the controller
 * @c: the Compare that carries the Write
 *
 * Frees both payloads, gives back the Write's credits and its staging
 * slot, and clears the link. Returns the Write, now a request of its own.
 */
NvmeRequest *femu_fused_drop(FemuCtrl *n, NvmeRequest *c)
{
    NvmeRequest *w = c->fused;

    nvme_eol_release(w);
    g_clear_pointer(&c->fused_cmp, g_free);
    g_clear_pointer(&w->fused_wr, g_free);
    c->fused = NULL;
    qatomic_dec(&n->fused_inflight);
    return w;
}

/**
 * femu_fused_run - run a staged pair
 * @n: the controller
 * @c: the Compare, which carries the Write in @c->fused
 * @ftl: on the FTL thread: charge the read and book the Write
 *
 * Returns the Compare's latency. The Write's times and status are set,
 * the link between the two is cleared, and each request then completes
 * on its own. The Write's end-of-life credits go back here. A Write that
 * failed its checks keeps its status only when the Compare succeeds.
 */
int64_t femu_fused_run(FemuCtrl *n, NvmeRequest *c, bool ftl)
{
    NvmeRequest *w = c->fused;
    NvmeNamespace *ns = c->ns;
    uint64_t slba = c->slba;
    uint64_t elba = slba + c->nlb;
    uint64_t len = (uint64_t)c->nlb << ns->lbaf.lbads;
    uint64_t off = ns->backend_offset + (slba << ns->lbaf.lbads);
    uint8_t *base = n->mbe->logical_space;
    int64_t lat_c = 0;
    int64_t lat_w = 0;
    uint64_t bad;
    uint16_t status = NVME_SUCCESS;

    /* the media read of the Compare: its faults are the Compare's */
    if (ftl) {
        lat_c = bb_ftl_process_req(n, ns, c);
        status = c->status;
    }
    if (status == NVME_SUCCESS) {
        backend_lock_range(n->mbe, off, len);
        status = nvme_check_dulbe(n, ns, slba, elba);
        if (!status && femu_lba_bad(ns, slba, elba, &bad)) {
            status = NVME_UNRECOVERED_READ | NVME_DNR;
        }
        if (!status && memcmp(base + off, c->fused_cmp, len)) {
            status = NVME_CMP_FAILURE | NVME_DNR;
        }
        /* qtest: x-copy-hold stops the pair here, inside its range lock */
        if (unlikely(qatomic_read(&n->test_copy_hold))) {
            femu_test_copy_hold(n);
        }
        if (!status && w->status == NVME_SUCCESS) {
            if (ftl) {
                /* the Write starts where the Compare read ends */
                w->stime = c->stime + lat_c;
                w->expire_time = w->stime;
                lat_w = bb_ftl_process_req(n, ns, w);
            }
            if (w->status == NVME_SUCCESS) {
                memcpy(base + off, w->fused_wr, len);
                nvme_mark_written(ns, slba, c->nlb);
                nvme_note_user_write(n);
            }
        }
        backend_unlock_range(n->mbe, off, len);
    }
    c->status = status;
    if (status != NVME_SUCCESS) {
        w->status = NVME_CMD_ABORT_FAILED_FUSE;
        w->expire_time = c->stime + lat_c;
    } else if (lat_w) {
        w->expire_time = w->stime + lat_w;
    } else {
        w->expire_time = MAX(w->expire_time, c->stime + lat_c);
    }
    w->reqlat = w->expire_time - w->t_submit;
    femu_fused_drop(n, c);
    return lat_c;
}
