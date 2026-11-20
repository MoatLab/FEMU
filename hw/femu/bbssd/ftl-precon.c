/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Preconditioning at realize (precon_fill_pct). Each planned page write
 * goes through bb_ftl_process_req(), the call the FTL thread makes for a
 * guest write, so the map, the lines, the write pointers and the wear
 * end as after the same guest writes. Only host time is not spent: the
 * timelines go back to idle, and the traffic counters to zero, because
 * a drive does not count factory writes as host writes. The knobs whose
 * decisions read the clock or a data age are refused, so the reset of
 * the timelines changes no decision.
 *
 * This runs on the realize thread before the FTL thread and the pollers
 * exist, so nothing else touches the FTL.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "ftl.h"
#include "ftl-internal.h"
#include "ftl-precon-math.h"
#include "../femu-query.h"

/* writes between two drops of the booked media time */
#define PRECON_IDLE_EVERY 1024

/*
 * The knob, if any, outside the scope where the state after the plan is
 * the state after the same writes from the host: a decision that reads
 * the clock or data ages, state a host write sets up outside the FTL, or
 * an FTL this version does not cover.
 */
static const char *precon_refused(FemuCtrl *n)
{
    const BbCtrlParams *p = &n->bb_params;
    const char *map = p->mapping_scheme;

    if (n->femu_mode != FEMU_BBSSD_MODE) {
        return "a mode other than bbssd";
    }
    if (n->num_namespaces != 1 || n->namespace_modes || n->ns_mgmt) {
        return "more than one namespace, namespace_modes or ns_mgmt";
    }
    if (nvme_ns_shared(n) || n->shared_ftl) {
        return "shared namespaces or shared_ftl";
    }
    if (n->subsys && n->subsys->endgrp.fdp.enabled) {
        return "FDP";
    }
    if (n->cxl_dev) {
        return "cxl_ssd";
    }
    if (map && *map && strcmp(map, "page")) {
        return "a mapping other than page";
    }
    if (p->gc_policy && !strcmp(p->gc_policy, "cost-benefit")) {
        return "gc_policy=cost-benefit";
    }
    if (p->gc_idle_ms) {
        return "gc_idle_ms";
    }
    if (p->tier_mode && *p->tier_mode && strcmp(p->tier_mode, "off")) {
        return "tier_mode";
    }
    if (p->pd_open_close_sec) {
        return "pd_open_close_sec";
    }
    if (p->retention_limit_sec) {
        return "retention_limit_sec";
    }
    if (p->rber_ppb) {
        return "rber_ppb";
    }
    if (p->gc_copyback) {
        return "gc_copyback";
    }
    if (p->buffer_low_pcent) {
        return "buffer_low_pcent";
    }
    /* admission refuses writes past the end of life, outside the FTL */
    if (n->eol_admit) {
        return "eol_read_only or rain_read_only with an end of life";
    }
    if (n->power_loss || n->durable_at_done) {
        return "power_loss or durable_at_done";
    }
    if (n->streams) {
        return "streams";
    }
    if (n->err_write_fail_ppm) {
        return "err_write_fail_ppm";
    }
    if (n->persist_file && !n->persist_ftl) {
        return "persist_file without persist_ftl";
    }
    return NULL;
}

/* the properties alone, before any namespace is built */
bool femu_precon_check(FemuCtrl *n, Error **errp)
{
    const char *why;

    if (!n->precon_fill_pct) {
        if (n->precon_overwrite_pct || n->precon_pattern) {
            error_setg(errp, "precon_overwrite_pct and precon_pattern need "
                       "precon_fill_pct");
            return false;
        }
        return true;
    }
    if (n->precon_fill_pct > 100) {
        error_setg(errp, "precon_fill_pct must be 0 to 100");
        return false;
    }
    if (n->precon_overwrite_pct > PRECON_OVERWRITE_MAX_PCT) {
        error_setg(errp, "precon_overwrite_pct must be 0 to %u",
                   PRECON_OVERWRITE_MAX_PCT);
        return false;
    }
    if (n->precon_pattern && strcmp(n->precon_pattern, "rand") &&
        strcmp(n->precon_pattern, "seq")) {
        error_setg(errp, "precon_pattern must be rand or seq");
        return false;
    }
    why = precon_refused(n);
    if (why) {
        error_setg(errp, "precon_fill_pct is not supported with %s", why);
        return false;
    }
    return true;
}

/* one request through the FTL thread's call; false when it failed */
static bool precon_submit(FemuCtrl *n, NvmeNamespace *ns, NvmeRequest *req,
                          uint8_t opcode, uint64_t slba, uint32_t nlb)
{
    memset(req, 0, sizeof(*req));
    req->ns = ns;
    req->cmd.opcode = opcode;
    req->slba = slba;
    req->nlb = nlb;
    req->status = NVME_SUCCESS;
    req->stime = femu_dev_now(n);
    req->t_submit = req->stime;
    bb_ftl_process_req(n, ns, req);
    return req->status == NVME_SUCCESS;
}

/*
 * Every busy-until value back to that of a new device. Only booked time
 * goes: a multi-plane batch not yet charged would be work still owed, and
 * every request flushes its batches, so one here is a bug.
 */
static bool ssd_precon_idle(struct ssd *ssd, Error **errp)
{
    struct ssdparams *spp = &ssd->sp;

    for (int c = 0; c < spp->nchs; c++) {
        for (int l = 0; l < ssd->ch[c].nluns; l++) {
            if (ssd->ch[c].lun[l].mp_prog.n || ssd->ch[c].lun[l].mp_rd.n) {
                error_setg(errp, "precon_fill_pct: a multi-plane batch is "
                           "still open after a request");
                return false;
            }
        }
    }

    for (int c = 0; c < spp->nchs; c++) {
        struct ssd_channel *ch = &ssd->ch[c];

        ch->next_ch_avail_time = 0;
        ch->gc_endtime = 0;
        ch->busy = false;
        for (int l = 0; l < ch->nluns; l++) {
            struct nand_lun *lun = &ch->lun[l];

            lun->next_lun_avail_time = 0;
            lun->gc_endtime = 0;
            lun->busy = false;
            for (int p = 0; p < lun->npls; p++) {
                lun->pl[p].next_pl_avail_time = 0;
            }
        }
    }
    ssd->forced_gc_end = 0;
    ssd->buffer_bg_fence = 0;
    ssd->gc_idle_busy = 0;
    ssd->gc_idle_fence = 0;
    ssd->last_prog_done = 0;
    if (ssd->tp_done) {
        memset(ssd->tp_done, 0, ssd->n_tps * sizeof(*ssd->tp_done));
    }
    nand_media_idle(&ssd->media);
    return true;
}

/* traffic counters to zero: the study counts from here */
static void ssd_precon_zero(struct ssd *ssd)
{
    ssd->host_write_pages = 0;
    ssd->nand_write_pages = 0;
    ssd->gc_write_pages = 0;
    ssd->map_write_pages = 0;
    ssd->map_read_pages = 0;
    ssd->pd_pad_pages = 0;
    ssd->parity_pages = 0;
    ssd->gc_copyback_pages = 0;
    ssd->gc_untimed_reads = 0;
    memset(ssd->media_ops, 0, sizeof(ssd->media_ops));
    memset(ssd->media_plane_ops, 0, sizeof(ssd->media_plane_ops));
    ssd->sp.read_cnt = 0;
    ssd->sp.write_cnt = 0;
    ssd->sp.read_hit_cnt = 0;
    ssd->sp.write_hit_cnt = 0;
    ssd->partial_page_writes = 0;
    ssd->unaligned_writes = 0;
    ssd->gc_stalled_writes = 0;
    ssd->gc_stall_passes = 0;
    ssd->forced_gc_timed = 0;
    ssd->buffer_full_destages = 0;
    ssd->buffer_bg_pages = 0;
    ssd->iu_rmw_pages = 0;
    ssd->pace_copies = 0;
    ssd->pace_lines = 0;
    ssd->pace_takeovers = 0;
    ssd->tp_moves = 0;
    if (ssd->ns_ctr) {
        memset(ssd->ns_ctr, 0, ssd->nr_ns_slices * sizeof(*ssd->ns_ctr));
    }
}

/* the plan on one namespace that owns a bbssd FTL */
static bool ssd_precon_ns(FemuCtrl *n, NvmeNamespace *ns, Error **errp)
{
    struct ssd *ssd = ns->ssd;
    uint64_t page = (uint64_t)ssd->sp.secsz * ssd->sp.secs_per_pg;
    uint8_t lbads = ns->lbaf.lbads;
    uint64_t lbas;
    uint64_t lpn;
    uint64_t total;
    uint64_t tenth;
    int64_t t0 = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
    g_autofree NvmeRequest *req = g_new0(NvmeRequest, 1);
    PreconPlan plan;
    struct ssd_precon *pc = &ssd->precon;

    /* one Write per flash page, on page boundaries of the FTL */
    if ((1ULL << lbads) > page || page % (1ULL << lbads) ||
        ssd_ns_byte_base(ssd, ns) % page) {
        error_setg(errp, "precon_fill_pct: the LBAs of namespace %u do not "
                   "tile its flash pages", ns->id);
        return false;
    }
    lbas = page >> lbads;
    /* the reference host writes must be legal NVMe Writes of one page */
    if (ns->lbaf.ms || lbas > 0x10000 || nvme_check_mdts(n, page)) {
        error_setg(errp, "precon_fill_pct: a one-page Write on namespace %u "
                   "has metadata or exceeds mdts", ns->id);
        return false;
    }
    precon_plan_init(&plan, ns->size / page, n->precon_fill_pct,
                     n->precon_overwrite_pct,
                     n->precon_pattern && !strcmp(n->precon_pattern, "seq"),
                     n->precon_seed);
    if (!plan.fill) {
        error_setg(errp, "precon_fill_pct: %u%% of namespace %u is less "
                   "than one flash page", n->precon_fill_pct, ns->id);
        return false;
    }
    total = precon_plan_total(&plan);
    tenth = MAX(total / 10, 1);
    /* qtest control: the background collection pass does not run */
    ssd->precon_break = n->test_precon_break != 0;
    while (precon_plan_next(&plan, &lpn)) {
        if (!precon_submit(n, ns, req, NVME_CMD_WRITE, lpn * lbas, lbas)) {
            error_setg(errp, "precon_fill_pct: namespace %u: the write of "
                       "page %" PRIu64 " failed with status 0x%x", ns->id,
                       lpn, req->status);
            return false;
        }
        /*
         * Timing never steers a decision in this scope, so the booked
         * work can go at any point. Dropping it often keeps the media
         * windows of the staged bus from piling up over the whole run.
         */
        if (plan.done % PRECON_IDLE_EVERY == 0) {
            if (!ssd_precon_idle(ssd, errp)) {
                return false;
            }
        }
        if (plan.done % tenth == 0) {
            femu_log("%s,precondition nsid %u: %" PRIu64 "/%" PRIu64
                     " pages\n", n->devname, ns->id, plan.done, total);
        }
    }
    /* what the buffer holds goes to the media, as after a host Flush */
    if (ssd->write_buffer_cnt &&
        !precon_submit(n, ns, req, NVME_CMD_FLUSH, 0, 0)) {
        error_setg(errp, "precon_fill_pct: namespace %u: the final Flush "
                   "failed with status 0x%x", ns->id, req->status);
        return false;
    }
    ssd->precon_break = false;
    if (n->test_precon_break) {
        /* the control reads back how many passes it took out */
        n->test_precon_break = 1 + MIN(ssd->precon_skipped, UINT32_MAX - 1);
    }
    for (uint64_t l = 0; l < plan.fill * lbas; l += 1ULL << 30) {
        nvme_mark_written(ns, l, MIN(plan.fill * lbas - l, 1ULL << 30));
    }
    /* a host Write clears Global Data Erased; so does the plan */
    nvme_note_user_write(n);

    pc->done = true;
    pc->fill = plan.fill;
    pc->overwrite = plan.overwrite;
    pc->host = ssd->host_write_pages;
    pc->nand = ssd->nand_write_pages;
    pc->gc = ssd->gc_write_pages;
    pc->map = ssd->map_write_pages;
    pc->pad = ssd->pd_pad_pages;
    pc->parity = ssd->parity_pages;
    pc->erases = ssd->total_erases;
    pc->waf_x1000 = ssd_waf_x1000(ssd);
    pc->ms = qemu_clock_get_ms(QEMU_CLOCK_REALTIME) - t0;

    if (!ssd_precon_idle(ssd, errp)) {
        return false;
    }
    ssd_precon_zero(ssd);
    femu_log("%s,precondition nsid %u: %" PRIu64 " pages, waf %u.%03u, "
             "%" PRIu64 " erases, %" PRIu64 " ms\n", n->devname, ns->id,
             total, pc->waf_x1000 / 1000, pc->waf_x1000 % 1000, pc->erases,
             pc->ms);
    return true;
}

/*
 * Run the plan on each namespace with a bbssd FTL of its own, in nsid
 * order. A saved FTL that realize loaded (persist_ftl) wins.
 */
bool femu_precon_run(FemuCtrl *n, Error **errp)
{
    bool any = false;

    if (!n->precon_fill_pct) {
        return true;
    }
    if (n->persist_ftl_loaded) {
        femu_log("%s,precondition skipped: persist_ftl loaded a saved FTL\n",
                 n->devname);
        return true;
    }
    /* its bytes and LBA states would no longer match the FTL */
    if (n->persist_file_loaded) {
        error_setg(errp, "precon_fill_pct: persist_file '%s' holds data but "
                   "no FTL state", n->persist_path);
        return false;
    }
    for (uint32_t i = 0; i < n->num_namespaces; i++) {
        NvmeNamespace *ns = &n->namespaces[i];

        if (!ns->ssd || ns->ssd_shared || ns->ssd_borrowed ||
            !NS_BBSSD(ns)) {
            continue;
        }
        if (!ssd_precon_ns(n, ns, errp)) {
            return false;
        }
        any = true;
    }
    if (!any) {
        error_setg(errp, "precon_fill_pct: no namespace has a bbssd FTL");
        return false;
    }
    return true;
}

void ssd_query_precon(struct ssd *ssd, FemuQueryNs *q)
{
    const struct ssd_precon *pc = &ssd->precon;

    q->precon_on = pc->done;
    if (!pc->done) {
        return;
    }
    q->precon_fill = pc->fill;
    q->precon_overwrite = pc->overwrite;
    q->precon_nand = pc->nand;
    q->precon_gc = pc->gc;
    q->precon_map = pc->map;
    q->precon_pad = pc->pad;
    q->precon_parity = pc->parity;
    q->precon_erases = pc->erases;
    q->precon_host = pc->host;
    q->precon_ms = pc->ms;
}

/* FNV-1a over the 8 bytes of @v */
static uint64_t sd_mix(uint64_t h, uint64_t v)
{
    for (int i = 0; i < 8; i++) {
        h = (h ^ ((v >> (8 * i)) & 0xff)) * 0x100000001b3ULL;
    }
    return h;
}

static uint64_t sd_wp(uint64_t h, const struct write_pointer *wp)
{
    h = sd_mix(h, wp->curline ? (uint64_t)wp->curline->id : UINT64_MAX);
    h = sd_mix(h, wp->ch);
    h = sd_mix(h, wp->lun);
    h = sd_mix(h, wp->pl);
    h = sd_mix(h, wp->blk);
    return sd_mix(h, wp->pg);
}

/*
 * qtest only: six hashes of the FTL state, in hex: map, page, block,
 * line, pointer and other state. Times and traffic counters are left
 * out, so a device that preconditioned and one that took the same
 * writes from the host hash the same. Page mapping only: the scope of
 * precon_fill_pct has no translation or log-block state.
 */
char *ssd_state_digest(struct ssd *ssd)
{
    struct ssdparams *spp = &ssd->sp;
    struct line_mgmt *lm = &ssd->lm;
    const uint64_t basis = 0xcbf29ce484222325ULL;
    uint64_t h[6] = { basis, basis, basis, basis, basis, basis };
    struct line *line;
    struct buffer_entry *be;
    struct ppa ppa;

    for (uint64_t lpn = 0; lpn < (uint64_t)spp->tt_pgs; lpn++) {
        h[0] = sd_mix(h[0], ssd->maptbl[lpn].ppa);
    }
    ppa.ppa = 0;
    for (int c = 0; c < spp->nchs; c++) {
        for (int l = 0; l < spp->luns_per_ch; l++) {
            for (int p = 0; p < spp->pls_per_lun; p++) {
                for (int b = 0; b < spp->blks_per_pl; b++) {
                    struct nand_block *blk = &ssd->ch[c].lun[l].pl[p].blk[b];

                    ppa.g.ch = c;
                    ppa.g.lun = l;
                    ppa.g.pl = p;
                    ppa.g.blk = b;
                    for (int pg = 0; pg < spp->pgs_per_blk; pg++) {
                        ppa.g.pg = pg;
                        h[1] = sd_mix(h[1], blk->pg[pg].status);
                        h[1] = sd_mix(h[1], get_rmap_ent(ssd, &ppa));
                    }
                    h[2] = sd_mix(h[2], blk->erase_cnt);
                    h[2] = sd_mix(h[2], (uint32_t)blk->vpc);
                    h[2] = sd_mix(h[2], (uint32_t)blk->ipc);
                    h[2] = sd_mix(h[2], (uint32_t)blk->wp);
                    h[2] = sd_mix(h[2], blk->pe_limit);
                    h[2] = sd_mix(h[2], blk->overworn | (blk->failed << 1));
                    h[2] = sd_mix(h[2], blk->read_cnt);
                    h[2] = sd_mix(h[2], blk->uid);
                }
                h[2] = sd_mix(h[2],
                              (uint32_t)ssd->ch[c].lun[l].pl[p].spares_used);
            }
        }
    }
    for (int i = 0; i < lm->tt_lines; i++) {
        line = &lm->lines[i];
        h[3] = sd_mix(h[3], (uint32_t)line->vpc);
        h[3] = sd_mix(h[3], (uint32_t)line->ipc);
        h[3] = sd_mix(h[3], line->close_seq);
        h[3] = sd_mix(h[3], line->kind);
        h[3] = sd_mix(h[3], line->retired | (line->spare << 1) |
                      (line->reserve << 2) | (line->reclaiming << 3));
        h[3] = sd_mix(h[3], line->pos);
    }
    h[3] = sd_mix(h[3], UINT64_MAX);
    QTAILQ_FOREACH(line, &lm->free_line_list, entry) {
        h[3] = sd_mix(h[3], line->id);
    }
    h[3] = sd_mix(h[3], UINT64_MAX);
    QTAILQ_FOREACH(line, &lm->full_line_list, entry) {
        h[3] = sd_mix(h[3], line->id);
    }
    h[3] = sd_mix(h[3], UINT64_MAX);
    for (size_t i = 1; i < lm->victim_line_pq->size; i++) {
        h[3] = sd_mix(h[3], ((struct line *)lm->victim_line_pq->d[i])->id);
    }
    h[4] = sd_wp(h[4], &ssd->wp);
    h[4] = sd_wp(h[4], &ssd->hot_wp);
    h[4] = sd_wp(h[4], &ssd->gc_wp);
    h[4] = sd_wp(h[4], &ssd->log_wp);
    h[4] = sd_wp(h[4], &ssd->tp_wp);
    h[5] = sd_mix(h[5], ssd->total_erases);
    h[5] = sd_mix(h[5], lm->next_close_seq);
    h[5] = sd_mix(h[5], (uint32_t)lm->free_line_cnt);
    h[5] = sd_mix(h[5], (uint32_t)lm->full_line_cnt);
    h[5] = sd_mix(h[5], (uint32_t)lm->retired_line_cnt);
    h[5] = sd_mix(h[5], ssd->gc_rng);
    h[5] = sd_mix(h[5], ssd->wl_credit);
    h[5] = sd_mix(h[5], ssd->wl_on);
    h[5] = sd_mix(h[5], ssd->victim_digest);
    h[5] = sd_mix(h[5], ssd->grown_bad_blocks);
    h[5] = sd_mix(h[5], ssd->media_ro);
    h[5] = sd_mix(h[5], qatomic_read(&ssd->eol_word));
    h[5] = sd_mix(h[5], ssd->read_reclaim_line ?
                  (uint64_t)ssd->read_reclaim_line->id : UINT64_MAX);
    h[5] = sd_mix(h[5], ssd->reclaim_why);
    h[5] = sd_mix(h[5], ssd->pace_line ?
                  (uint64_t)ssd->pace_line->id : UINT64_MAX);
    h[5] = sd_mix(h[5], (uint32_t)ssd->pace_cursor);
    h[5] = sd_mix(h[5], ssd->pace_v0);
    h[5] = sd_mix(h[5], ssd->pace_acc);
    h[5] = sd_mix(h[5], ssd->pace_failed);
    h[5] = sd_mix(h[5], (uint32_t)ssd->write_buffer_cnt);
    QTAILQ_FOREACH(be, &ssd->write_buffer, b_entry) {
        h[5] = sd_mix(h[5], be->lpn);
    }
    return g_strdup_printf("%016" PRIx64 " %016" PRIx64 " %016" PRIx64
                           " %016" PRIx64 " %016" PRIx64 " %016" PRIx64,
                           h[0], h[1], h[2], h[3], h[4], h[5]);
}
