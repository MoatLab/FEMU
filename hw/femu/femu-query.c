/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * query-femu: report a controller's FTL state over QMP.
 *
 * The FTL thread owns the FTL state and holds no lock over it, so the
 * command does not read it from the main thread. It posts a request to the
 * controller, and the FTL thread copies the state into buffers the command
 * sized beforehand, between two requests. The command waits in a coroutine,
 * so the main loop keeps running, and builds the reply from the copy.
 */
#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "qemu/coroutine.h"
#include "qemu/timer.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-femu.h"
#include "qom/object.h"
#include "nvme.h"
#include "bbssd/ftl.h"
#include "femu-query.h"

/* How long the FTL thread may take to pick a request up. */
#define FEMU_QUERY_TIMEOUT_NS   (5 * NANOSECONDS_PER_SECOND)

/* Realize refuses a femu_mode past FEMU_KVSSD_MODE. */
static FemuMode femu_query_mode(uint8_t mode)
{
    switch (mode) {
    case FEMU_OCSSD_MODE:
        return FEMU_MODE_OCSSD;
    case FEMU_BBSSD_MODE:
        return FEMU_MODE_BBSSD;
    case FEMU_NOSSD_MODE:
        return FEMU_MODE_NOSSD;
    case FEMU_ZNSSD_MODE:
        return FEMU_MODE_ZNSSD;
    case FEMU_CSD_MODE:
        return FEMU_MODE_CSD;
    case FEMU_KVSSD_MODE:
        return FEMU_MODE_KVSSD;
    default:
        g_assert_not_reached();
    }
}

static bool femu_query_supported(NvmeNamespace *ns)
{
    return NS_BBSSD(ns) && ns->ssd && !ns->ssd->fdp_enabled &&
           !ns->ssd_borrowed;
}

void femu_query_service(FemuCtrl *n, FemuQueryReq *req)
{
    bool shared = nvme_ns_shared(n);

    if (shared) {
        qemu_mutex_lock(&n->subsys->ns_lock);
    }
    for (uint32_t i = 0; i < req->nr_ns; i++) {
        FemuQueryNs *q = &req->ns[i];
        NvmeNamespace *ns = nvme_ns(n, q->nsid);

        /* The namespace may have been replaced since the request was made. */
        if (!ns || ns->creation_generation != q->generation ||
            !femu_query_supported(ns)) {
            q->status = -ENOENT;
            continue;
        }
        ssd_query_collect(ns->ssd, q);
    }
    if (shared) {
        qemu_mutex_unlock(&n->subsys->ns_lock);
    }
    qatomic_store_release(&req->done, true);
}

void femu_query_cancel(FemuQueryReq *req)
{
    req->status = -ENODEV;
    qatomic_store_release(&req->done, true);
}

static FemuCtrl *femu_query_find(const char *path, Error **errp)
{
    bool ambiguous = false;
    Object *obj;

    if (path) {
        obj = object_resolve_path_type(path, TYPE_NVME, NULL);
        if (!obj) {
            error_setg(errp, "'%s' is not a femu device", path);
            return NULL;
        }
    } else {
        obj = object_resolve_path_type("", TYPE_NVME, &ambiguous);
        if (ambiguous) {
            error_setg(errp, "more than one femu device; give a path");
            return NULL;
        }
        if (!obj) {
            error_setg(errp, "no femu device");
            return NULL;
        }
    }
    if (!DEVICE(obj)->realized) {
        error_setg(errp, "femu device is not realized");
        return NULL;
    }

    return FEMU(obj);
}

/* Check one namespace and size its buffers. */
static bool femu_query_prepare(FemuCtrl *n, NvmeNamespace *ns, bool lines,
                               uint32_t offset, uint32_t limit,
                               FemuQueryNs *q, Error **errp)
{
    if (!femu_query_supported(ns)) {
        const char *what = FemuMode_str(femu_query_mode(ns->femu_mode));

        if (NS_BBSSD(ns) && ns->ssd && ns->ssd->fdp_enabled) {
            what = "flexible data placement";
        } else if (NS_BBSSD(ns) && ns->ssd_borrowed) {
            what = "CXL-backed";
        }
        error_setg(errp, "namespace %u: query-femu does not support %s "
                   "namespaces yet", ns->id, what);
        return false;
    }

    q->nsid = ns->id;
    q->generation = ns->creation_generation;
    if (!lines) {
        return true;
    }
    if (offset >= (uint32_t)ns->ssd->lm.tt_lines) {
        error_setg(errp, "namespace %u: offset %u is past its last line (%d "
                   "lines)", ns->id, offset, ns->ssd->lm.tt_lines);
        return false;
    }
    q->offset = offset;
    q->max_lines = limit;
    q->lines = g_new0(FemuQueryLine, limit);
    q->state_cap = ns->ssd->lm.tt_lines;
    q->state = g_malloc0(q->state_cap);

    return true;
}

static void femu_query_free(FemuQueryReq *req)
{
    for (uint32_t i = 0; i < req->nr_ns; i++) {
        g_free(req->ns[i].lines);
        g_free(req->ns[i].state);
    }
    g_free(req->ns);
    g_free(req);
}

/*
 * Post @req to the FTL thread and wait until it has been served. The thread
 * picks requests up only while the data plane runs; one that is not picked
 * up in time is taken back. Once the thread has taken it, the copy is short
 * and bounded, so the wait continues until it finishes.
 */
static void coroutine_fn femu_query_run(FemuCtrl *n, FemuQueryReq *req,
                                        Error **errp)
{
    int64_t deadline;
    int64_t pause_ns = 20 * SCALE_US;
    int64_t test_delay_ns = n->test_query_delay_ms * SCALE_MS;

    if (qatomic_cmpxchg(&n->query_req, NULL, req) != NULL) {
        error_setg(errp, "another query-femu is running on this device");
        return;
    }

    deadline = qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + FEMU_QUERY_TIMEOUT_NS;
    while (!qatomic_load_acquire(&req->done)) {
        if (qemu_clock_get_ns(QEMU_CLOCK_REALTIME) > deadline &&
            qatomic_cmpxchg(&n->query_req, req, NULL) == req) {
            error_setg(errp, "the FTL thread did not take the query; the "
                       "controller may be paused or disabled");
            return;
        }
        qemu_co_sleep_ns(QEMU_CLOCK_REALTIME, pause_ns);
        pause_ns = MIN(pause_ns * 2, SCALE_MS);
    }
    if (req->status == -ENODEV) {
        error_setg(errp, "the femu device was removed during the query");
    }
    /* qtest: widen the window between the copy and the reply */
    if (test_delay_ns) {
        qemu_co_sleep_ns(QEMU_CLOCK_REALTIME, test_delay_ns);
    }
}

static FemuNamespaceInfo *femu_query_ns_info(FemuQueryNs *q, FemuMode mode,
                                             bool lines)
{
    FemuNamespaceInfo *info = g_new0(FemuNamespaceInfo, 1);
    FemuGeometry *geo = g_new0(FemuGeometry, 1);
    FemuWriteCounters *ctr = g_new0(FemuWriteCounters, 1);
    FemuLineCounts *cnt = g_new0(FemuLineCounts, 1);

    info->nsid = q->nsid;
    info->mode = mode;

    geo->channels = q->nchs;
    geo->luns_per_channel = q->luns_per_ch;
    geo->planes_per_lun = q->pls_per_lun;
    geo->blocks_per_plane = q->blks_per_pl;
    geo->pages_per_block = q->pgs_per_blk;
    geo->page_size = q->page_size;
    geo->pages_per_line = q->pgs_per_line;
    info->geometry = geo;

    ctr->host_write_pages = q->host_pages;
    ctr->nand_write_pages = q->nand_pages;
    ctr->gc_write_pages = q->gc_pages;
    ctr->block_erases = q->erases;
    if (q->host_pages) {
        ctr->has_waf = true;
        ctr->waf = ((double)q->nand_pages + (double)q->gc_pages) /
                   (double)q->host_pages;
    }
    info->counters = ctr;

    cnt->free = q->free_lines;
    cnt->victim = q->victim_lines;
    cnt->full = q->full_lines;
    cnt->total = q->tt_lines;
    info->line_counts = cnt;

    if (lines) {
        FemuLineInfoList **tail = &info->lines;

        info->has_lines = true;
        for (uint32_t i = 0; i < q->nr_lines; i++) {
            FemuLineInfo *li = g_new0(FemuLineInfo, 1);

            li->id = q->lines[i].id;
            li->state = q->lines[i].state;
            li->vpc = q->lines[i].vpc;
            li->ipc = q->lines[i].ipc;
            li->erase_min = q->lines[i].erase_min;
            li->erase_max = q->lines[i].erase_max;
            QAPI_LIST_APPEND(tail, li);
        }
        info->has_offset = true;
        info->offset = q->offset;
        if (q->offset + q->nr_lines < q->tt_lines) {
            info->has_next_offset = true;
            info->next_offset = q->offset + q->nr_lines;
        }
    }

    return info;
}

FemuInfo *coroutine_fn qmp_query_femu(const char *path, bool has_nsid,
                                      uint32_t nsid, bool has_kind,
                                      FemuQueryKind kind, bool has_offset,
                                      uint32_t offset, bool has_limit,
                                      uint32_t limit, Error **errp)
{
    bool lines = has_kind && kind == FEMU_QUERY_KIND_LINES;
    FemuQueryReq *req = NULL;
    FemuInfo *info = NULL;
    FemuMode *modes = NULL;
    FemuMode ctrl_mode;
    Error *local_err = NULL;
    g_autofree char *qom_path = NULL;
    FemuCtrl *n;
    uint32_t i;

    n = femu_query_find(path, errp);
    if (!n) {
        return NULL;
    }
    if (!lines && (has_offset || has_limit)) {
        error_setg(errp, "offset and limit apply only to kind 'lines'");
        return NULL;
    }
    if (!has_limit) {
        limit = FEMU_QUERY_DEFAULT_LINES;
    }
    if (limit < 1 || limit > FEMU_QUERY_MAX_LINES) {
        error_setg(errp, "limit must be 1 to %d", FEMU_QUERY_MAX_LINES);
        return NULL;
    }
    if (!has_offset) {
        offset = 0;
    }

    /*
     * Namespace support is checked first: a controller in a mode with no
     * FTL thread is never "enabled" in the sense below.
     */
    req = g_new0(FemuQueryReq, 1);
    req->ns = g_new0(FemuQueryNs, n->namespace_limit);
    modes = g_new0(FemuMode, n->namespace_limit);
    if (has_nsid) {
        NvmeNamespace *ns = nvme_ns(n, nsid);

        if (!ns) {
            error_setg(errp, "namespace %u is not attached", nsid);
            goto out;
        }
        if (!femu_query_prepare(n, ns, lines, offset, limit, &req->ns[0],
                                errp)) {
            goto out;
        }
        modes[0] = femu_query_mode(ns->femu_mode);
        req->nr_ns = 1;
    } else {
        for (i = 1; i <= n->namespace_limit; i++) {
            NvmeNamespace *ns = nvme_ns(n, i);

            if (!ns) {
                continue;
            }
            if (lines && req->nr_ns) {
                error_setg(errp, "kind 'lines' needs an nsid when the "
                           "controller has more than one namespace");
                goto out;
            }
            if (!femu_query_prepare(n, ns, lines, offset, limit,
                                    &req->ns[req->nr_ns], errp)) {
                goto out;
            }
            modes[req->nr_ns++] = femu_query_mode(ns->femu_mode);
        }
        if (!req->nr_ns) {
            error_setg(errp, "the controller has no attached namespace");
            goto out;
        }
    }

    if (!n->ftl_thread_running || !n->dataplane_started) {
        error_setg(errp, "the femu controller is not enabled");
        goto out;
    }

    /*
     * The device may be unplugged during the wait. Take what the reply needs
     * from it now, and hold a reference until the wait is over.
     */
    qom_path = object_get_canonical_path(OBJECT(n));
    ctrl_mode = femu_query_mode(n->femu_mode);
    object_ref(OBJECT(n));
    femu_query_run(n, req, &local_err);
    object_unref(OBJECT(n));
    n = NULL;   /* may be freed now */
    if (local_err) {
        error_propagate(errp, local_err);
        goto out;
    }

    info = g_new0(FemuInfo, 1);
    info->path = g_steal_pointer(&qom_path);
    info->mode = ctrl_mode;
    for (i = 0; i < req->nr_ns; i++) {
        if (req->ns[i].status) {
            error_setg(errp, "namespace %u changed during the query",
                       req->ns[i].nsid);
            qapi_free_FemuInfo(info);
            info = NULL;
            goto out;
        }
    }
    {
        FemuNamespaceInfoList **tail = &info->namespaces;

        for (i = 0; i < req->nr_ns; i++) {
            QAPI_LIST_APPEND(tail, femu_query_ns_info(&req->ns[i], modes[i],
                                                      lines));
        }
    }

out:
    g_free(modes);
    femu_query_free(req);
    return info;
}
