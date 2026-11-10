/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Sanitize Namespace (Base 2.3, 5.2.23 and 8.1.26) with sanitize_ns=on:
 * a Crypto Erase of one namespace, one operation at a time (MNSOIP 1).
 *
 *   8Ch, SANACT 100b, dataplane paused:
 *     busy --> mark the namespace's queued commands --> retire its
 *     unfinished requests --> erase it (backend slice, metadata, bitmaps,
 *     FTL mappings, buffered pages) --> SOS 010b
 *   sanitize_ms later (or at once): SOS 001b, NDE --> AER (log 81h, NSID)
 *
 * The erase runs at the start, after every command of the namespace that
 * the host queued or the device holds has been stopped with Sanitize
 * Namespace In Progress (2Ch), so none can change the namespace after it.
 * Work that already finished keeps its status. The buffered pages are
 * dropped, not written back: they are being sanitized, and a write-back
 * could fail. So the operation cannot fail, and the failure states are not
 * reachable. While it runs, the namespace's commands fail with 2Ch, Flush
 * aside.
 */

#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "qemu/timer.h"
#include "qapi/error.h"
#include "nvme.h"
#include "bbssd/ftl.h"

/**
 * femu_sanns_check - validate sanitize_ns at realize
 * @n: the controller
 * @errp: set on a refusal
 *
 * Crypto Erase comes with sanitize_ops. The namespace history (NDE) is
 * kept in memory, so a persist_file would restore data with a wrong
 * history. One controller and fixed namespaces keep the operation state
 * in one place.
 */
bool femu_sanns_check(FemuCtrl *n, Error **errp)
{
    const char *why = NULL;

    if (!n->sanitize_ns) {
        return true;
    }
    if (!n->sanitize_ops) {
        error_setg(errp, "femu: sanitize_ns needs sanitize_ops");
        return false;
    }
    if ((n->femu_mode != FEMU_BBSSD_MODE &&
         n->femu_mode != FEMU_NOSSD_MODE) || n->namespace_modes) {
        why = "a mode other than bbssd or NoSSD";
    } else if (n->subsys) {
        why = "a femu-subsys";
    } else if (n->ns_mgmt) {
        why = "namespace management";
    } else if (n->cxl_dev) {
        why = "cxl_ssd";
    } else if (n->persist_file) {
        why = "persist_file";
    }
    if (why) {
        error_setg(errp, "femu: sanitize_ns is not supported with %s", why);
        return false;
    }
    return true;
}

/* a namespace sanitize is in progress */
bool femu_sanns_busy(FemuCtrl *n)
{
    return qatomic_read(&n->san_ns_target) != 0;
}

/* the Crypto Erase stand-in: everything of @ns reads as never written */
static void femu_sanns_erase(FemuCtrl *n, NvmeNamespace *ns)
{
    if (n->mbe && n->mbe->logical_space) {
        backend_lock_range(n->mbe, ns->backend_offset, ns->extent_size);
        memset((uint8_t *)n->mbe->logical_space + ns->backend_offset, 0,
               ns->extent_size);
        backend_unlock_range(n->mbe, ns->backend_offset, ns->extent_size);
    }
    bitmap_zero(ns->util, ns->ns_blks);
    bitmap_zero(ns->uncorrectable, ns->ns_blks);
    if (ns->mdata) {
        memset(ns->mdata, 0, ns->mdata_len);
    }
    /* mappings, translation pages and buffered pages go */
    if (NS_BBSSD(ns)) {
        bbssd_deallocate_all(ns);
    }
    /* its open stream identifiers end (8.1.26.5) */
    nvme_streams_release(ns, false);
}

/* SSTAT of @ns: its SOS, NDE, and the subsystem's GDE */
static uint16_t femu_sanns_sstat(FemuCtrl *n, NvmeNamespace *ns)
{
    uint16_t gde = qatomic_read(&nvme_sanitize_state(n)->sstat) &
                   NVME_SSTAT_GDE;

    return ns->san_sstat | gde |
           (qatomic_read(&ns->nde) ? NVME_SSTAT_NDE : 0);
}

/*
 * The operation on the target namespace ends; it cannot fail. The status,
 * NDE and the completion record are set with the dataplane paused, so a
 * write after the namespace reopens clears an NDE that is already set.
 */
void femu_sanns_finish(FemuCtrl *n)
{
    uint32_t nsid = n->san_ns_target;
    NvmeNamespace *ns = nvme_ns(n, nsid);
    uint8_t ev[12] = { 0 };
    bool resume;

    if (!ns) {
        qatomic_set(&n->san_ns_target, 0);
        return;
    }
    resume = nvme_pause_pollers(n);
    ns->san_sstat = 0x1;
    qatomic_set(&ns->nde, true);
    /* Sanitize Completion (Figure 248) for the namespace */
    stw_le_p(ev, 0xffff);
    stw_le_p(ev + 2, femu_sanns_sstat(n, ns));
    stl_le_p(ev + 8, nsid);
    qatomic_set(&ns->san_busy, false);
    qatomic_set(&n->san_ns_target, 0);
    n->sanns_genctr++;          /* from in progress to erased */
    nvme_resume_pollers(n, resume);
    femu_pel_log(n, NVME_PEL_SANITIZE_COMPLETION, 2, ev, sizeof(ev));
    /* Sanitize Operation Completed, the NSID in Dword 1 */
    nvme_enqueue_ns_event(n, NVME_AER_TYPE_IO_SPECIFIC,
                          NVME_AER_INFO_SANITIZED, NVME_LOG_SANITIZE, nsid);
}

/*
 * Sanitize Namespace (Figure 391). Every check runs before anything
 * changes, so a refused command leaves the status, the data and the log
 * as they were.
 */
uint16_t femu_sanns_cmd(FemuCtrl *n, NvmeCmd *cmd)
{
    uint32_t nsid = le32_to_cpu(cmd->nsid);
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint8_t sanact = dw10 & 0x7;
    bool emvs = dw10 & (1 << 10);
    NvmeNamespace *ns;
    uint8_t ev[16] = { 0 };
    bool resume;

    if (!n->sanitize_ns) {
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
    if (!nsid || nsid == NVME_NSID_BROADCAST) {
        return NVME_INVALID_NSID | NVME_DNR;
    }
    ns = nvme_ns(n, nsid);
    if (!ns) {
        return NVME_INVALID_NSID | NVME_DNR;
    }
    if (nvme_sanitize_busy(n)) {
        return NVME_SANITIZE_IN_PROGRESS;
    }
    if (qatomic_read(&ns->san_busy)) {
        return NVME_SANITIZE_NS_IN_PROGRESS;
    }
    if (femu_wp(ns)) {
        return NVME_NS_WRITE_PROTECTED | NVME_DNR;
    }
    switch (sanact) {
    case 0x1:   /* Exit Failure Mode: the operation never fails */
        return NVME_SUCCESS;
    case 0x4:   /* Crypto Erase */
        break;
    default:    /* 101b needs NVERS, which is 0; the rest are reserved */
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    /* no Media Verification state (NVERS 0) */
    if (emvs) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (femu_fw_pending(n)) {
        return NVME_FW_REQ_CLR | NVME_DNR;
    }
    if (femu_sanns_busy(n)) {
        return NVME_SANITIZE_NS_LIMIT | NVME_DNR;
    }

    /*
     * With the dataplane paused: refuse new commands, stop the queued and
     * unfinished ones (8.1.26.5), then erase.
     */
    resume = nvme_pause_pollers(n);
    qatomic_set(&ns->san_busy, true);
    nvme_mark_ns_queued(n, nsid);
    nvme_retire_ns_requests_status(n, ns, NVME_SANITIZE_NS_IN_PROGRESS);
    femu_sanns_erase(n, ns);
    ns->san_sstat = 0x2;
    ns->san_cdw10 = dw10;
    n->sanns_genctr++;          /* it joins the in-progress list */
    n->san_ns_start_ms = qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL);
    qatomic_set(&n->san_ns_target, nsid);
    nvme_resume_pollers(n, resume);

    /* Sanitize Start (Figure 247) for the namespace */
    stl_le_p(ev, le32_to_cpu(n->id_ctrl.sanicap));
    stl_le_p(ev + 4, dw10);
    stl_le_p(ev + 12, nsid);
    femu_pel_log(n, NVME_PEL_SANITIZE_START, 2, ev, sizeof(ev));
    /* a new operation clears the completion event of the last one */
    nvme_clear_ns_events(n, NVME_AER_TYPE_IO_SPECIFIC, NVME_LOG_SANITIZE,
                         nsid, true);
    if (!n->sanitize_ms) {
        femu_sanns_finish(n);
        return NVME_SUCCESS;
    }
    timer_mod(n->san_timer, n->san_ns_start_ms + n->sanitize_ms);
    return NVME_SUCCESS;
}

/* the Sanitize Status log (Figure 302) for namespace @ns, 512 bytes */
void femu_sanns_log(FemuCtrl *n, NvmeNamespace *ns, uint8_t *log)
{
    memset(log, 0, 512);
    if (qatomic_read(&ns->san_busy) && n->sanitize_ms) {
        int64_t done = qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) -
                       n->san_ns_start_ms;

        stw_le_p(log, MIN(MAX(done, 0) * 65536 / n->sanitize_ms, 0xfffe));
    } else {
        stw_le_p(log, 0xffff);
    }
    stw_le_p(log + 2, femu_sanns_sstat(n, ns));
    stl_le_p(log + 4, ns->san_cdw10);
    /* only the Crypto Erase estimate applies to a namespace */
    for (int i = 0; i < 6; i++) {
        stl_le_p(log + 8 + 4 * i, i == 2 && n->sanitize_ms ?
                 DIV_ROUND_UP(n->sanitize_ms, 1000) : 0xffffffff);
    }
    stl_le_p(log + 32, 0xffffffff);     /* no post-verification time */
    stl_le_p(log + 40, 0xffffffff);     /* MNSOIP: subsystem log only */
    stl_le_p(log + 44, ns->id);         /* STNSID */
}

/*
 * A subsystem sanitize with @cdw10 completed with SOS @sos (pollers
 * paused): it covered every namespace, so each takes it as its last
 * operation and reads as erased.
 */
void femu_sanns_subsys_done(FemuCtrl *n, uint32_t cdw10, uint16_t sos)
{
    bool changed = false;

    for (int i = 0; i < n->namespace_limit; i++) {
        NvmeNamespace *ns = &n->namespaces[i];

        if (ns->allocated) {
            changed |= !qatomic_read(&ns->nde);
            qatomic_set(&ns->nde, true);
            ns->san_sstat = sos;
            ns->san_cdw10 = cdw10;
        }
    }
    /* GENCTR moves only when a namespace joins the erased list */
    if (changed) {
        n->sanns_genctr++;
    }
}
