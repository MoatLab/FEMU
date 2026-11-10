/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Namespace Write Protection (Base 2.3, 8.1.17; feature 84h) with
 * ns_wp=on: the No Write Protect and Write Protect states. The other two
 * states need the Write Protection Control field of an RPMB, which FEMU
 * does not have, so Set Features refuses them as not changeable.
 *
 *   Set 84h, WPS 1:  wp := 1 --> drain the fetched requests --> destage
 *                    the write buffer --> release Streams --> done
 *   I/O to a protected namespace (Figure 671):
 *     Read, Compare, Verify, Reservations, DSM without AD --> as before
 *     Flush --> success, no effect;  vendor opcodes --> as before
 *     anything else --> Namespace Is Write Protected (20h)
 *
 * A command that passed the check before Set Features sets wp is drained
 * before the command completes, so its data is in the buffer when the
 * buffer is destaged. A destaged page is durable as the power cut model
 * has it. The state is the namespace's: resets and power cuts keep it.
 */

#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "qapi/error.h"
#include "nvme.h"
#include "bbssd/ftl.h"

#define FEMU_WP_DRAIN_MS    1000

/**
 * femu_wp_check - validate ns_wp at realize
 * @n: the controller
 * @errp: set on a refusal
 *
 * Only NVM namespaces of bbssd or NoSSD: a zoned namespace must take its
 * open zones to Full first (ZNS 1.4), and KV and CSD write through
 * commands of their own. The CXL path writes the same bytes past the NVMe
 * dispatch. The state must survive a power cycle, which a QEMU restart
 * with persist_file would be.
 */
bool femu_wp_check(FemuCtrl *n, Error **errp)
{
    const char *why = NULL;

    if (!n->ns_wp) {
        return true;
    }
    if ((n->femu_mode != FEMU_BBSSD_MODE &&
         n->femu_mode != FEMU_NOSSD_MODE) || n->namespace_modes) {
        why = "a mode other than bbssd or NoSSD";
    } else if (n->ns_mgmt || nvme_ns_shared(n)) {
        why = "namespace management or shared namespaces";
    } else if (n->subsys && n->subsys->endgrp.fdp.enabled) {
        /* FDP namespaces share one FTL and one write buffer */
        why = "FDP";
    } else if (n->cxl_dev) {
        why = "cxl_ssd";
    } else if (n->persist_file) {
        why = "persist_file";
    }
    if (why) {
        error_setg(errp, "femu: ns_wp is not supported with %s", why);
        return false;
    }
    return true;
}

bool femu_wp(NvmeNamespace *ns)
{
    return ns && ns->ctrl && ns->ctrl->ns_wp && qatomic_read(&ns->wp);
}

/*
 * The status of I/O command @cmd to namespace @ns (Figure 671): success
 * to run it as usual, success with *@noop for a Flush that has nothing to
 * do, or Namespace Is Write Protected. The NSID of a Copy is its
 * destination; a protected source is fine.
 */
uint16_t femu_wp_io(NvmeNamespace *ns, NvmeCmd *cmd, bool *noop)
{
    *noop = false;
    if (!femu_wp(ns)) {
        return NVME_SUCCESS;
    }
    switch (cmd->opcode) {
    case NVME_CMD_READ:
    case NVME_CMD_COMPARE:
    case NVME_CMD_VERIFY:
    case NVME_CMD_RESV_REGISTER:
    case NVME_CMD_RESV_REPORT:
    case NVME_CMD_RESV_ACQUIRE:
    case NVME_CMD_RESV_RELEASE:
        return NVME_SUCCESS;
    case NVME_CMD_FLUSH:
        /* the buffer was destaged when the protection came */
        *noop = true;
        return NVME_SUCCESS;
    case NVME_CMD_DSM:
        if (!(le32_to_cpu(cmd->cdw11) & NVME_DSMGMT_AD)) {
            return NVME_SUCCESS;
        }
        return NVME_NS_WRITE_PROTECTED | NVME_DNR;
    default:
        if (cmd->opcode >= 0x80) {
            return NVME_SUCCESS;
        }
        return NVME_NS_WRITE_PROTECTED | NVME_DNR;
    }
}

/* the rings of fetched requests are empty (pollers paused) */
static bool femu_wp_rings_empty(FemuCtrl *n)
{
    for (int i = 1; n->to_ftl && i <= n->nr_pollers; i++) {
        if (n->to_ftl[i] && femu_ring_count(n->to_ftl[i])) {
            return false;
        }
    }
    return true;
}

/* destage the write buffer of @ns (pollers and FTL paused) */
static uint16_t femu_wp_destage(FemuCtrl *n, NvmeNamespace *ns)
{
    struct ssd *ssd = ns->ssd;
    uint64_t now = femu_dev_now(n);
    uint64_t lat;

    if (!NS_BBSSD(ns) || !ssd || ssd->sp.buffer_size <= 0) {
        return NVME_SUCCESS;
    }
    lat = ssd_buffer_destage(ssd, 0, now);
    /* a later Flush waits for these programs, as after a cache disable */
    ssd->buffer_bg_fence = MAX(ssd->buffer_bg_fence, now + lat);
    return ssd->write_buffer_cnt ? NVME_CAP_EXCEEDED | NVME_DNR :
                                   NVME_SUCCESS;
}

/*
 * Set Features 84h: WPS @wps for namespace @nsid, or every namespace for
 * FFFFFFFFh. Moving to Write Protect drains what the pollers fetched,
 * destages the write buffers and releases the Streams resources. On a
 * failure every namespace keeps the state it had.
 */
uint16_t femu_wp_set(FemuCtrl *n, uint32_t nsid, uint32_t dw11)
{
    uint8_t wps = dw11 & 0x7;
    g_autofree bool *old = g_new0(bool, n->namespace_limit);
    int64_t end;
    uint16_t status = NVME_SUCCESS;
    bool resume;
    uint32_t i;

    if (wps == 2 || wps == 3) {
        /* WPUPCC and PWPC are 0: there is no RPMB (5.2.26.1.35) */
        return NVME_FEAT_NOT_CHANGEABLE | NVME_DNR;
    }
    if (wps > 3) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    for (i = 0; i < n->namespace_limit; i++) {
        NvmeNamespace *ns = &n->namespaces[i];

        old[i] = ns->wp;
        if (ns->allocated && (nsid == NVME_NSID_BROADCAST || ns->id == nsid)) {
            qatomic_set(&ns->wp, wps == 1);
        }
    }
    if (wps == 0) {
        return NVME_SUCCESS;
    }

    /* a command the check passed has changed the backend: let it finish */
    end = g_get_monotonic_time() + FEMU_WP_DRAIN_MS * 1000;
    for (;;) {
        resume = nvme_pause_pollers(n);
        if (femu_wp_rings_empty(n)) {
            break;
        }
        nvme_resume_pollers(n, resume);
        if (g_get_monotonic_time() >= end || !resume) {
            status = NVME_CMD_INTERRUPTED;
            goto undo;
        }
        g_usleep(1000);
    }
    for (i = 0; i < n->namespace_limit && !status; i++) {
        NvmeNamespace *ns = &n->namespaces[i];

        if (ns->allocated && ns->wp && !old[i]) {
            status = femu_wp_destage(n, ns);
        }
    }
    if (!status) {
        for (i = 0; i < n->namespace_limit; i++) {
            NvmeNamespace *ns = &n->namespaces[i];

            if (ns->allocated && ns->wp && !old[i]) {
                nvme_streams_release(ns, true);
            }
        }
    }
    nvme_resume_pollers(n, resume);
    if (!status) {
        return NVME_SUCCESS;
    }
undo:
    for (i = 0; i < n->namespace_limit; i++) {
        qatomic_set(&n->namespaces[i].wp, old[i]);
    }
    return status;
}

/* Get Features 84h: the state of namespace @nsid (one namespace) */
uint32_t femu_wp_get(FemuCtrl *n, uint32_t nsid)
{
    NvmeNamespace *ns = nvme_ns(n, nsid);

    return ns && ns->wp ? 1 : 0;
}

/*
 * Format NVM and Sanitize: Namespace Is Write Protected when a namespace
 * in scope is protected, checked before anything changes. @nsid
 * FFFFFFFFh means every namespace.
 */
uint16_t femu_wp_scope(FemuCtrl *n, uint32_t nsid)
{
    if (!n->ns_wp) {
        return NVME_SUCCESS;
    }
    for (uint32_t i = 0; i < n->namespace_limit; i++) {
        NvmeNamespace *ns = &n->namespaces[i];

        if (ns->allocated && ns->wp &&
            (nsid == NVME_NSID_BROADCAST || ns->id == nsid)) {
            return NVME_NS_WRITE_PROTECTED | NVME_DNR;
        }
    }
    return NVME_SUCCESS;
}
