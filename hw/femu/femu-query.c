/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * query-femu: report a controller's FTL state over QMP.
 *
 * The FTL thread owns the bbssd state and holds no lock over it, so the
 * command does not read it from the main thread. It posts a request to the
 * controller, and the FTL thread copies the state into buffers the command
 * sized beforehand, between two requests. The command waits in a coroutine,
 * so the main loop keeps running, and builds the reply from the copy.
 *
 * Zone state belongs to no single thread: the pollers change it under the
 * namespace's zone lock. The command copies it on the main loop under that
 * lock instead.
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
#include "kvssd/kvssd.h"
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

/* A namespace the FTL thread copies. */
static bool femu_query_supported(NvmeNamespace *ns)
{
    return NS_BBSSD(ns) && ns->ssd && !ns->ssd_borrowed;
}

/* A namespace the main loop copies under its zone lock. */
static bool femu_query_zoned(NvmeNamespace *ns)
{
    return NS_ZNSSD(ns) && ns->zns && ns->zone_array;
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

/*
 * One selected namespace: which copy holds it, its mode, and its media
 * timing. A csd, kvssd or ocssd namespace has the media timing only.
 */
typedef struct FemuQuerySel {
    FemuMode mode;
    bool zoned;
    bool media_only;
    uint32_t nsid;
    uint32_t idx;               /* into req->ns, or into the zoned copies */
    int onfi_mode;              /* -1 without the ONFI profile */
    int onfi_col;               /* address cycles of the profile */
    int onfi_row;
    NandMediaPhases media;
    bool has_lsm;               /* a kvssd namespace with kv_index=lsm */
    FemuKvLsmSnap lsm;
    bool has_pack;              /* a kvssd namespace with kv_pack=on */
    FemuKvPackSnap pack;
} FemuQuerySel;

/*
 * The media layer of a namespace, or NULL. Realize builds it. Later only
 * admin commands change it (delay emulation, OCSSD timing). They run
 * under the BQL, as this command does, so the copy here needs no request
 * to the FTL thread.
 */
static const NandMedia *femu_query_media(FemuCtrl *n, NvmeNamespace *ns,
                                         FemuQuerySel *sel)
{
    sel->onfi_mode = -1;
    sel->onfi_col = 0;
    sel->onfi_row = 0;
    if ((NS_BBSSD(ns) || NS_CSD(ns) || NS_KVSSD(ns)) && ns->ssd &&
        !ns->ssd_borrowed) {
        sel->onfi_mode = ns->ssd->sp.onfi_mode;
        if (sel->onfi_mode >= 0) {
            sel->onfi_col = ns->ssd->sp.onfi_col_cycles;
            sel->onfi_row = ns->ssd->sp.onfi_row_cycles;
        }
        return &ns->ssd->media;
    }
    if (femu_query_zoned(ns)) {
        return zns_query_media(ns);
    }
    if (NS_OCSSD(ns)) {
        return oc_query_media(n);
    }
    return NULL;
}

/* Check one namespace and size the buffers of its copy. */
static bool femu_query_prepare(FemuCtrl *n, NvmeNamespace *ns,
                               FemuQueryKind kind, uint32_t offset,
                               uint32_t limit, FemuQueryReq *req,
                               FemuQueryZoned *zoned, uint32_t *nr_zoned,
                               FemuQuerySel *sel, Error **errp)
{
    const NandMedia *media = femu_query_media(n, ns, sel);

    sel->mode = femu_query_mode(ns->femu_mode);
    sel->nsid = ns->id;
    if (media) {
        nand_media_phases(media, &sel->media);
    }

    if (media && (NS_CSD(ns) || NS_KVSSD(ns) || NS_OCSSD(ns))) {
        if (kind != FEMU_QUERY_KIND_SUMMARY) {
            error_setg(errp, "namespace %u: kind '%s' does not apply to %s "
                       "namespaces", ns->id, FemuQueryKind_str(kind),
                       FemuMode_str(sel->mode));
            return false;
        }
        sel->media_only = true;
        if (NS_KVSSD(ns) && ns->ext_ops.state) {
            sel->has_lsm = kvssd_ftl_lsm_snap(ns->ext_ops.state, &sel->lsm);
            sel->has_pack = kvssd_ftl_pack_snap(ns->ext_ops.state,
                                                &sel->pack);
        }
        return true;
    }

    if (femu_query_zoned(ns)) {
        FemuQueryZoned *q = &zoned[*nr_zoned];

        if (kind == FEMU_QUERY_KIND_LINES ||
            kind == FEMU_QUERY_KIND_RECLAIM_UNITS) {
            error_setg(errp, "namespace %u: kind '%s' applies only to "
                       "bbssd namespaces", ns->id, FemuQueryKind_str(kind));
            return false;
        }
        q->nsid = ns->id;
        q->generation = ns->creation_generation;
        if (kind == FEMU_QUERY_KIND_ZONES) {
            if (offset >= ns->num_zones) {
                error_setg(errp, "namespace %u: offset %u is past its last "
                           "zone (%u zones)", ns->id, offset, ns->num_zones);
                return false;
            }
            q->offset = offset;
            q->max_zones = limit;
            q->zones = g_new0(FemuQueryZone, limit);
        }
        sel->zoned = true;
        sel->idx = (*nr_zoned)++;
        return true;
    }

    if (!femu_query_supported(ns)) {
        const char *what = FemuMode_str(sel->mode);

        if (NS_BBSSD(ns) && ns->ssd_borrowed) {
            what = "CXL-backed";
        }
        error_setg(errp, "namespace %u: query-femu does not support %s "
                   "namespaces yet", ns->id, what);
        return false;
    }
    if (kind == FEMU_QUERY_KIND_ZONES) {
        error_setg(errp, "namespace %u: kind 'zones' applies only to "
                   "znssd namespaces", ns->id);
        return false;
    }

    if (kind == FEMU_QUERY_KIND_LINES && ns->ssd->fdp_enabled) {
        error_setg(errp, "namespace %u: kind 'lines' does not apply with "
                   "flexible data placement; use 'reclaim-units'", ns->id);
        return false;
    }
    if (kind == FEMU_QUERY_KIND_RECLAIM_UNITS && !ns->ssd->fdp_enabled) {
        error_setg(errp, "namespace %u: kind 'reclaim-units' applies only "
                   "with flexible data placement", ns->id);
        return false;
    }

    {
        FemuQueryNs *q = &req->ns[req->nr_ns];

        q->nsid = ns->id;
        q->generation = ns->creation_generation;
        if (ns->ssd->fdp_enabled) {
            struct ssd *ssd = ns->ssd;
            uint32_t total = ssd->rg ? ssd->nrg * ssd->rg[0].tt_nru : 0;

            q->nr_ruhs = ssd->nruhs;
            q->ruhs = g_new0(FemuQueryRuh, MAX(q->nr_ruhs, 1));
            q->nrg = ssd->nrg;
            q->rgs = g_new0(FemuQueryRg, MAX(q->nrg, 1));
            /* fixed at realize: FDP refuses namespace management */
            q->nr_phs = ns->fdp.nphs;
            q->phs = g_memdup2(ns->fdp.phs, ns->fdp.nphs * sizeof(uint16_t));
            q->ftl_nsid = ssd_owner_nsid(ssd);
            q->ru_state_cap = total;
            q->ru_state = g_malloc0(MAX(total, 1));
            if (kind == FEMU_QUERY_KIND_RECLAIM_UNITS) {
                if (offset >= total) {
                    error_setg(errp, "namespace %u: offset %u is past its "
                               "last reclaim unit (%u units)", ns->id, offset,
                               total);
                    goto fail;
                }
                q->offset = offset;
                q->max_rus = limit;
                q->rus = g_new0(FemuQueryRu, limit);
            }
        } else if (kind == FEMU_QUERY_KIND_LINES) {
            if (offset >= (uint32_t)ns->ssd->lm.tt_lines) {
                error_setg(errp, "namespace %u: offset %u is past its last "
                           "line (%d lines)", ns->id, offset,
                           ns->ssd->lm.tt_lines);
                return false;
            }
            q->offset = offset;
            q->max_lines = limit;
            q->lines = g_new0(FemuQueryLine, limit);
            q->state_cap = ns->ssd->lm.tt_lines;
            q->state = g_malloc0(q->state_cap);
        }
    }
    sel->zoned = false;
    sel->idx = req->nr_ns++;
    return true;

fail:
    /* req->nr_ns does not count this entry yet; free its buffers here */
    g_clear_pointer(&req->ns[req->nr_ns].ruhs, g_free);
    g_clear_pointer(&req->ns[req->nr_ns].rgs, g_free);
    g_clear_pointer(&req->ns[req->nr_ns].ru_state, g_free);
    g_clear_pointer(&req->ns[req->nr_ns].phs, g_free);
    return false;
}

static void femu_query_free(FemuQueryReq *req)
{
    for (uint32_t i = 0; i < req->nr_ns; i++) {
        g_free(req->ns[i].lines);
        g_free(req->ns[i].state);
        g_free(req->ns[i].ruhs);
        g_free(req->ns[i].rgs);
        g_free(req->ns[i].rus);
        g_free(req->ns[i].ru_state);
        g_free(req->ns[i].phs);
    }
    g_free(req->ns);
    g_free(req);
}

static void femu_query_zoned_free(FemuQueryZoned *zoned, uint32_t cap)
{
    for (uint32_t i = 0; i < cap; i++) {
        g_free(zoned[i].zones);
    }
    g_free(zoned);
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

/*
 * Copy each zoned namespace under its zone lock. A poller can hold the lock
 * for a whole Report Zones transfer, so the main loop only tries it, and
 * sleeps between tries. The device or a namespace may go away during a
 * sleep; look both up again after each one.
 */
static void coroutine_fn femu_query_zoned_run(FemuCtrl *n,
                                              FemuQueryZoned *zoned,
                                              uint32_t nr_zoned, Error **errp)
{
    int64_t deadline = qemu_clock_get_ns(QEMU_CLOCK_REALTIME) +
                       FEMU_QUERY_TIMEOUT_NS;

    for (uint32_t i = 0; i < nr_zoned; i++) {
        FemuQueryZoned *q = &zoned[i];
        int64_t pause_ns = 20 * SCALE_US;
        bool slept = false;

        for (;;) {
            NvmeNamespace *ns;

            if (slept && qemu_clock_get_ns(QEMU_CLOCK_REALTIME) > deadline) {
                error_setg(errp, "namespace %u: the zone lock stayed busy",
                           q->nsid);
                return;
            }
            if (!DEVICE(n)->realized) {
                error_setg(errp, "the femu device was removed during the "
                           "query");
                return;
            }
            ns = nvme_ns(n, q->nsid);
            if (!ns || ns->creation_generation != q->generation ||
                !femu_query_zoned(ns)) {
                error_setg(errp, "namespace %u changed during the query",
                           q->nsid);
                return;
            }
            if (zns_query_collect(ns, q)) {
                break;
            }
            qemu_co_sleep_ns(QEMU_CLOCK_REALTIME, pause_ns);
            pause_ns = MIN(pause_ns * 2, SCALE_MS);
            slept = true;
        }
    }
}

static FemuFdpInfo *femu_query_fdp_info(FemuQueryNs *q)
{
    FemuFdpInfo *fdp = g_new0(FemuFdpInfo, 1);
    FemuReclaimUnitCounts *cnt = g_new0(FemuReclaimUnitCounts, 1);
    FemuRuHandleInfoList **htail = &fdp->handles;
    FemuReclaimGroupInfoList **gtail = &fdp->groups;
    uint16List **ptail = &fdp->placement_handles;

    fdp->reclaim_groups = q->nrg;
    for (uint32_t g = 0; g < q->nrg; g++) {
        FemuReclaimGroupInfo *gi = g_new0(FemuReclaimGroupInfo, 1);

        gi->id = g;
        gi->first_channel = q->rgs[g].ch0;
        gi->channels = q->rgs[g].nch;
        gi->first_lun = q->rgs[g].lun0;
        gi->luns = q->rgs[g].nlun;
        gi->free_units = q->rgs[g].free_units;
        QAPI_LIST_APPEND(gtail, gi);
    }
    fdp->units_per_group = q->rus_per_rg;
    fdp->pages_per_unit = q->pgs_per_ru;
    for (uint32_t h = 0; h < q->nr_ruhs; h++) {
        FemuRuHandleInfo *hi = g_new0(FemuRuHandleInfo, 1);

        hi->id = q->ruhs[h].id;
        hi->type = q->ruhs[h].type;
        hi->host_bytes = q->ruhs[h].host_bytes;
        hi->media_bytes = q->ruhs[h].media_bytes;
        QAPI_LIST_APPEND(htail, hi);
    }

    for (uint16_t i = 0; i < q->nr_phs; i++) {
        QAPI_LIST_APPEND(ptail, q->phs[i]);
    }
    fdp->ftl_nsid = q->ftl_nsid;

    cnt->free = q->ru_counts[FEMU_RECLAIM_UNIT_STATE_FREE];
    cnt->open = q->ru_counts[FEMU_RECLAIM_UNIT_STATE_OPEN];
    cnt->full = q->ru_counts[FEMU_RECLAIM_UNIT_STATE_FULL];
    cnt->victim = q->ru_counts[FEMU_RECLAIM_UNIT_STATE_VICTIM];
    cnt->retired = q->ru_counts[FEMU_RECLAIM_UNIT_STATE_RETIRED];
    cnt->has_reserve = q->eol_mode;
    cnt->reserve = q->ru_counts[FEMU_RECLAIM_UNIT_STATE_RESERVE];
    cnt->total = q->nrg * q->rus_per_rg;
    fdp->unit_counts = cnt;

    if (q->rus) {
        FemuReclaimUnitInfoList **tail = &fdp->reclaim_units;

        fdp->has_reclaim_units = true;
        for (uint32_t i = 0; i < q->nr_rus; i++) {
            FemuReclaimUnitInfo *ri = g_new0(FemuReclaimUnitInfo, 1);

            ri->group = q->rus[i].group;
            ri->unit = q->rus[i].unit;
            ri->has_handle = q->rus[i].has_handle;
            ri->handle = q->rus[i].handle;
            ri->state = q->rus[i].state;
            ri->vpc = q->rus[i].vpc;
            ri->ipc = q->rus[i].ipc;
            ri->erase_min = q->rus[i].erase_min;
            ri->erase_max = q->rus[i].erase_max;
            QAPI_LIST_APPEND(tail, ri);
        }
    }

    return fdp;
}

static FemuMediaTiming *femu_query_media_info(const FemuQuerySel *sel)
{
    FemuMediaTiming *mt = g_new0(FemuMediaTiming, 1);
    const NandMediaPhases *ph = &sel->media;

    mt->staged_bus = ph->staged;
    mt->onfi_profile = sel->onfi_mode >= 0;
    mt->has_onfi_mode = mt->onfi_profile;
    mt->onfi_mode = mt->onfi_profile ? sel->onfi_mode : 0;
    mt->column_cycles = sel->onfi_col;
    mt->row_cycles = sel->onfi_row;
    mt->page_transfer_ns = ph->page_xfer_ns;
    mt->read_command_ns = ph->rd_cmd_ns;
    mt->program_command_ns = ph->wr_cmd_ns;
    mt->erase_command_ns = ph->er_cmd_ns;
    mt->copyback_read_command_ns = ph->cb_rd_cmd_ns;
    mt->copyback_program_command_ns = ph->cb_wr_cmd_ns;
    mt->status_ns = ph->status_ns;
    mt->data_out_lead_ns = ph->dout_pre_ns;
    mt->data_out_tail_ns = ph->dout_post_ns;
    mt->plane_select_ns = ph->dout_mp_pre_ns;
    mt->data_in_edges_ns = ph->din_burst_ns;
    mt->program_confirm_ns = ph->wr_post_ns;
    mt->plane_read_busy_ns = ph->tplrbsy_ns;
    mt->plane_program_busy_ns = ph->tplpbsy_ns;
    mt->plane_erase_busy_ns = ph->tplebsy_ns;
    mt->data_in_gap_ns = ph->din_gap_ns;
    mt->data_out_edges_ns = ph->dout_edge_ns;
    mt->sca = ph->sca;
    mt->cache_read = ph->cache_read;
    mt->read_cache_busy_ns = ph->trcbsy_ns;
    mt->cache_step_ns = ph->rc_step_ns;
    mt->cache_select_ns = ph->rc_sel_ns;
    mt->onfi_order = ph->onfi_order;
    mt->page_register_hold = ph->page_reg_hold;
    mt->status_per_plane = ph->mp_status_per_plane;
    return mt;
}

static FemuKvLsmInfo *femu_query_lsm_info(const FemuKvLsmSnap *l)
{
    FemuKvLsmInfo *info = g_new0(FemuKvLsmInfo, 1);
    FemuKvLsmLevelList **tail = &info->levels;

    info->memtable_keys = l->memtable_keys;
    info->memtable_capacity = l->memtable_cap;
    info->size_ratio = l->ratio;
    info->pinned_levels = l->pinned;
    info->records_per_page = l->per_page;
    info->device_dram_bytes = l->dram_bytes;
    info->meta_flash_bytes = l->meta_flash_bytes;
    for (int i = 1; i <= l->depth; i++) {
        FemuKvLsmLevel *lv = g_new0(FemuKvLsmLevel, 1);

        lv->level = i;
        lv->records = l->records[i - 1];
        lv->capacity = l->capacity[i - 1];
        lv->pages = l->pages[i - 1];
        lv->pinned = (uint32_t)i <= l->pinned;
        QAPI_LIST_APPEND(tail, lv);
    }
    info->flushes = l->flushes;
    info->compactions = l->compactions;
    info->dropped_records = l->dropped;
    info->reinserted_keys = l->reinserted;
    info->probe_read_pages = l->io[KV_LSM_IO_PROBE];
    info->scan_read_pages = l->io[KV_LSM_IO_SCAN];
    info->compaction_read_pages = l->io[KV_LSM_IO_COMPACT_READ];
    info->compaction_program_pages = l->io[KV_LSM_IO_COMPACT_PROGRAM];
    info->gc_read_pages = l->io[KV_LSM_IO_GC_READ];
    info->gc_meta_pages = l->gc_meta_pages;
    info->gc_stale_value_pages = l->gc_stale_pages;
    info->valid_value_pages = l->valid_value_pages;
    info->versions = l->versions;
    return info;
}

static FemuKvPackInfo *femu_query_pack_info(const FemuKvPackSnap *p)
{
    FemuKvPackInfo *info = g_new0(FemuKvPackInfo, 1);

    info->record_header_bytes = p->header_bytes;
    info->open_bytes = p->open_bytes;
    info->open_values = p->open_values;
    info->packed_pages = p->pages;
    info->packed_values = p->values;
    info->flash_pages = p->flash_pages;
    info->flash_live_bytes = p->flash_live_bytes;
    info->pad_bytes = p->pad_bytes;
    info->early_programs = p->early;
    info->dropped_pages = p->dropped;
    info->buffer_reads = p->buf_reads;
    info->gc_moved_values = p->gc_moved;
    info->gc_stale_values = p->gc_stale;
    info->host_bytes = p->host_bytes;
    return info;
}

static FemuNamespaceInfo *femu_query_media_ns_info(const FemuQuerySel *sel)
{
    FemuNamespaceInfo *ns_info = g_new0(FemuNamespaceInfo, 1);
    FemuMediaTiming *mt = femu_query_media_info(sel);

    ns_info->nsid = sel->nsid;
    ns_info->mode = sel->mode;
    switch (sel->mode) {
    case FEMU_MODE_CSD:
        ns_info->u.csd.media = mt;
        break;
    case FEMU_MODE_KVSSD:
        ns_info->u.kvssd.media = mt;
        if (sel->has_lsm) {
            ns_info->u.kvssd.lsm = femu_query_lsm_info(&sel->lsm);
        }
        if (sel->has_pack) {
            ns_info->u.kvssd.pack = femu_query_pack_info(&sel->pack);
        }
        break;
    case FEMU_MODE_OCSSD:
        ns_info->u.ocssd.media = mt;
        break;
    default:
        g_assert_not_reached();
    }
    return ns_info;
}

static FemuNamespaceInfo *femu_query_ns_info(FemuQueryNs *q, bool lines)
{
    FemuNamespaceInfo *ns_info = g_new0(FemuNamespaceInfo, 1);
    FemuBbssdInfo *info = &ns_info->u.bbssd;
    FemuGeometry *geo = g_new0(FemuGeometry, 1);
    FemuWriteCounters *ctr = g_new0(FemuWriteCounters, 1);
    FemuLineCounts *cnt = g_new0(FemuLineCounts, 1);

    ns_info->nsid = q->nsid;
    ns_info->mode = FEMU_MODE_BBSSD;

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
    if (q->pad_pages) {
        ctr->has_pad_write_pages = true;
        ctr->pad_write_pages = q->pad_pages;
    }
    if (q->tp_on) {
        ctr->has_map_write_pages = true;
        ctr->map_write_pages = q->map_pages;
        ctr->has_map_read_pages = true;
        ctr->map_read_pages = q->map_reads;
    }
    if (q->host_pages) {
        ctr->has_waf = true;
        ctr->waf = ((double)q->nand_pages + (double)q->gc_pages +
                    (double)q->map_pages + (double)q->pad_pages) /
                   (double)q->host_pages;
    }
    info->counters = ctr;

    if (q->eol_mode) {
        FemuEolInfo *eol = g_new0(FemuEolInfo, 1);

        eol->read_only = q->media_ro;
        eol->credit_pages = q->eol_cap;
        eol->held_pages = q->eol_pages;
        eol->held_requests = q->eol_reqs;
        info->end_of_life = eol;
    }
    if (q->fdp) {
        g_free(cnt);
        info->fdp = femu_query_fdp_info(q);
        if (q->rus) {
            uint32_t total = q->nrg * q->rus_per_rg;

            info->has_offset = true;
            info->offset = q->offset;
            if (q->offset + q->nr_rus < total) {
                info->has_next_offset = true;
                info->next_offset = q->offset + q->nr_rus;
            }
        }
        return ns_info;
    }
    cnt->free = q->free_lines;
    cnt->victim = q->victim_lines;
    cnt->full = q->full_lines;
    cnt->retired = q->retired_lines;
    cnt->spare = q->spare_lines;
    cnt->has_reserve = q->eol_mode;
    cnt->reserve = q->reserve_lines;
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

    return ns_info;
}

static FemuNamespaceInfo *femu_query_zoned_info(FemuQueryZoned *q)
{
    FemuNamespaceInfo *ns_info = g_new0(FemuNamespaceInfo, 1);
    FemuZonedInfo *info = &ns_info->u.znssd;
    FemuZoneCounts *cnt = g_new0(FemuZoneCounts, 1);

    ns_info->nsid = q->nsid;
    ns_info->mode = FEMU_MODE_ZNSSD;
    info->lba_size = q->lba_size;
    info->zone_size = q->zone_size;
    info->zone_capacity = q->zone_cap;
    info->max_open = q->max_open;
    info->max_active = q->max_active;

    cnt->empty = q->counts[FEMU_ZONE_STATE_EMPTY];
    cnt->implicitly_open = q->counts[FEMU_ZONE_STATE_IMPLICITLY_OPEN];
    cnt->explicitly_open = q->counts[FEMU_ZONE_STATE_EXPLICITLY_OPEN];
    cnt->closed = q->counts[FEMU_ZONE_STATE_CLOSED];
    cnt->read_only = q->counts[FEMU_ZONE_STATE_READ_ONLY];
    cnt->full = q->counts[FEMU_ZONE_STATE_FULL];
    cnt->offline = q->counts[FEMU_ZONE_STATE_OFFLINE];
    cnt->total = q->num_zones;
    info->zone_counts = cnt;

    if (q->zones) {
        FemuZoneInfoList **tail = &info->zones;

        info->has_zones = true;
        for (uint32_t i = 0; i < q->nr_zones; i++) {
            FemuZoneInfo *zi = g_new0(FemuZoneInfo, 1);

            zi->index = q->zones[i].index;
            zi->type = q->zones[i].type;
            zi->state = q->zones[i].state;
            zi->start_lba = q->zones[i].slba;
            zi->capacity = q->zones[i].cap;
            zi->has_write_pointer = q->zones[i].wp_valid;
            zi->write_pointer = q->zones[i].wp;
            zi->zrwa = q->zones[i].zrwa;
            QAPI_LIST_APPEND(tail, zi);
        }
        info->has_offset = true;
        info->offset = q->offset;
        if (q->offset + q->nr_zones < q->num_zones) {
            info->has_next_offset = true;
            info->next_offset = q->offset + q->nr_zones;
        }
    }

    return ns_info;
}

FemuInfo *coroutine_fn qmp_query_femu(const char *path, bool has_nsid,
                                      uint32_t nsid, bool has_kind,
                                      FemuQueryKind kind, bool has_offset,
                                      uint32_t offset, bool has_limit,
                                      uint32_t limit, Error **errp)
{
    bool window;
    FemuQueryReq *req = NULL;
    FemuQueryZoned *zoned = NULL;
    FemuQuerySel *sel = NULL;
    FemuInfo *info = NULL;
    FemuMode ctrl_mode;
    Error *local_err = NULL;
    g_autofree char *qom_path = NULL;
    uint32_t nr_sel = 0;
    uint32_t nr_zoned = 0;
    uint32_t cap;
    FemuCtrl *n;
    uint32_t i;

    n = femu_query_find(path, errp);
    if (!n) {
        return NULL;
    }
    if (!has_kind) {
        kind = FEMU_QUERY_KIND_SUMMARY;
    }
    window = kind != FEMU_QUERY_KIND_SUMMARY;
    if (!window && (has_offset || has_limit)) {
        error_setg(errp, "offset and limit apply only to kind 'lines', "
                   "'zones' or 'reclaim-units'");
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
    cap = n->namespace_limit;
    req = g_new0(FemuQueryReq, 1);
    req->ns = g_new0(FemuQueryNs, cap);
    zoned = g_new0(FemuQueryZoned, cap);
    sel = g_new0(FemuQuerySel, cap);
    if (has_nsid) {
        NvmeNamespace *ns = nvme_ns(n, nsid);

        if (!ns) {
            error_setg(errp, "namespace %u is not attached", nsid);
            goto out;
        }
        if (!femu_query_prepare(n, ns, kind, offset, limit, req, zoned,
                                &nr_zoned, &sel[0], errp)) {
            goto out;
        }
        nr_sel = 1;
    } else {
        for (i = 1; i <= n->namespace_limit; i++) {
            NvmeNamespace *ns = nvme_ns(n, i);

            if (!ns) {
                continue;
            }
            if (window && nr_sel) {
                error_setg(errp, "kind '%s' needs an nsid when the "
                           "controller has more than one namespace",
                           FemuQueryKind_str(kind));
                goto out;
            }
            if (!femu_query_prepare(n, ns, kind, offset, limit, req,
                                    zoned, &nr_zoned, &sel[nr_sel], errp)) {
                goto out;
            }
            nr_sel++;
        }
        if (!nr_sel) {
            error_setg(errp, "the controller has no attached namespace");
            goto out;
        }
    }

    /* only the FTL thread's copy needs the controller enabled */
    if (req->nr_ns && (!n->ftl_thread_running || !n->dataplane_started)) {
        error_setg(errp, "the femu controller is not enabled");
        goto out;
    }

    /*
     * The device may be unplugged during the waits. Take what the reply
     * needs from it now, and hold a reference until the waits are over.
     */
    qom_path = object_get_canonical_path(OBJECT(n));
    ctrl_mode = femu_query_mode(n->femu_mode);
    object_ref(OBJECT(n));
    femu_query_zoned_run(n, zoned, nr_zoned, &local_err);
    if (!local_err && req->nr_ns) {
        femu_query_run(n, req, &local_err);
    } else if (!local_err && n->test_query_delay_ms) {
        /* qtest: widen the window between the copy and the reply */
        qemu_co_sleep_ns(QEMU_CLOCK_REALTIME,
                         n->test_query_delay_ms * SCALE_MS);
    }
    object_unref(OBJECT(n));
    n = NULL;   /* may be freed now */
    if (local_err) {
        error_propagate(errp, local_err);
        goto out;
    }

    for (i = 0; i < req->nr_ns; i++) {
        if (req->ns[i].status) {
            error_setg(errp, "namespace %u changed during the query",
                       req->ns[i].nsid);
            goto out;
        }
    }
    info = g_new0(FemuInfo, 1);
    info->path = g_steal_pointer(&qom_path);
    info->mode = ctrl_mode;
    {
        FemuNamespaceInfoList **tail = &info->namespaces;

        for (i = 0; i < nr_sel; i++) {
            FemuNamespaceInfo *ns_info;

            if (sel[i].media_only) {
                ns_info = femu_query_media_ns_info(&sel[i]);
            } else if (sel[i].zoned) {
                ns_info = femu_query_zoned_info(&zoned[sel[i].idx]);
                ns_info->u.znssd.media = femu_query_media_info(&sel[i]);
            } else {
                ns_info = femu_query_ns_info(&req->ns[sel[i].idx],
                                             kind == FEMU_QUERY_KIND_LINES);
                ns_info->u.bbssd.media = femu_query_media_info(&sel[i]);
            }
            QAPI_LIST_APPEND(tail, ns_info);
        }
    }

out:
    g_free(sel);
    femu_query_zoned_free(zoned, cap);
    femu_query_free(req);
    return info;
}

FemuIoStages *qmp_query_femu_stages(const char *path, bool has_reset,
                                    bool reset, Error **errp)
{
    FemuCtrl *n = femu_query_find(path, errp);
    FemuIoStages *info;
    FemuIoStageInfoList **tail;
    bool clear = has_reset && reset && n && n->stage_sets;
    bool resume = false;

    if (!n) {
        return NULL;
    }
    if (!n->io_stages) {
        error_setg(errp, "the femu device does not time I/O stages; set "
                   "io_stages=on");
        return NULL;
    }

    /* a reset reads and clears with the pollers stopped, so it loses none */
    if (clear) {
        resume = nvme_pause_pollers(n);
    }
    info = g_new0(FemuIoStages, 1);
    info->path = object_get_canonical_path(OBJECT(n));
    tail = &info->stages;
    for (int st = 0; st < FEMU_STAGE_NR; st++) {
        FemuIoStageInfo *si = g_new0(FemuIoStageInfo, 1);
        uint64List **btail = &si->buckets;
        uint64_t buckets[FEMU_STAGE_BUCKETS] = { 0 };

        si->stage = st;
        /* the pollers write their own sets; each word reads whole */
        for (int p = 1; n->stage_sets && p <= n->nr_pollers; p++) {
            const FemuStageHist *h = &n->stage_sets[p].st[st];

            si->count += qatomic_read(&h->count);
            si->sum_ns += qatomic_read(&h->sum_ns);
            si->max_ns = MAX(si->max_ns, qatomic_read(&h->max_ns));
            for (int b = 0; b < FEMU_STAGE_BUCKETS; b++) {
                buckets[b] += qatomic_read(&h->buckets[b]);
            }
        }
        for (int b = 0; b < FEMU_STAGE_BUCKETS; b++) {
            QAPI_LIST_APPEND(btail, buckets[b]);
        }
        QAPI_LIST_APPEND(tail, si);
    }
    for (int p = 1; n->stage_sets && p <= n->nr_pollers; p++) {
        info->returned_after_due +=
            qatomic_read(&n->stage_sets[p].returned_after_due);
    }

    if (clear) {
        memset(n->stage_sets, 0, sizeof(FemuStageSet) * (n->nr_pollers + 1));
        nvme_resume_pollers(n, resume);
    }
    return info;
}
