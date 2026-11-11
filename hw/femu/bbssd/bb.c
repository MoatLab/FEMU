#include "../nvme.h"
#include "qemu/error-report.h"
#include "./ftl.h"

static void bb_init_ctrl_str(FemuCtrl *n, NvmeNamespace *ns)
{
    static int fsid_vbb = 0;
    const char *vbbssd_mn = "FEMU BlackBox-SSD Controller";
    const char *vbbssd_sn = "vSSD";

    nvme_set_ctrl_name(n, ns, vbbssd_mn, vbbssd_sn, &fsid_vbb);
}

/*
 * The logical bytes the FTL of @ns maps. Under FDP every namespace of the
 * controller places into the one FTL, each in its own slice of the backend,
 * so the FTL maps up to the end of the last slice; otherwise only @ns.
 */
uint64_t bb_ftl_bytes(FemuCtrl *n, NvmeNamespace *ns)
{
    uint64_t end = ns->size;

    if (!n->shared_ftl && (!n->subsys || !n->subsys->endgrp.fdp.enabled)) {
        return end;
    }
    for (int i = 0; i < n->num_namespaces; i++) {
        NvmeNamespace *o = &n->namespaces[i];

        end = MAX(end, o->backend_offset + o->size);
    }
    return end;
}

/*
 * Reclaim groups of the FTL are sets of dies: in the order ch x luns_per_ch +
 * lun, group g takes the g-th of nrg equal runs. The write pointer of a
 * unit steps over a rectangle of channels and LUNs, so a run must be whole
 * channels, or LUNs of one channel.
 */
static int bb_check_fdp_groups(FemuCtrl *n, Error **errp)
{
    const BbCtrlParams *p = &n->bb_params;
    uint32_t nrg = n->subsys->endgrp.fdp.nrg;
    uint32_t dies = (uint32_t)p->nchs * p->luns_per_ch;

    if (nrg == 1 || (p->nchs % nrg) == 0 ||
        ((nrg % p->nchs) == 0 && (p->luns_per_ch % (nrg / p->nchs)) == 0)) {
        return 0;
    }
    error_setg(errp, "FEMU bbssd: fdp.nrg (%u) must divide nchs (%d), or be "
               "a multiple of nchs that divides the %u dies of nchs x "
               "luns_per_ch: a reclaim group is a set of whole channels, or "
               "of LUNs of one channel", nrg, p->nchs, dies);
    return -1;
}

/*
 * A reclaim unit holds at least one logical block, or RUAMW, which counts
 * blocks, stays 0. With more than one group the FTL also keeps groups apart
 * only if no page holds blocks of two writes: the FTL maps whole pages, and
 * a write of part of a page would move the rest of it into the group of
 * the write.
 */
static int bb_check_fdp_block(FemuCtrl *n, NvmeNamespace *ns,
                              const char *mode, Error **errp)
{
    const BbCtrlParams *p = &n->bb_params;
    uint32_t nrg = n->subsys->endgrp.fdp.nrg;
    uint64_t page = (uint64_t)p->secs_per_pg * p->secsz;
    /* a pSLC unit holds fewer pages per block: the smallest unit counts */
    int blk_pgs = bb_fdp_slc_blk_pgs(n) ? bb_fdp_slc_blk_pgs(n) :
                  p->pgs_per_blk;
    uint64_t unit = (uint64_t)p->nchs * p->luns_per_ch * p->pls_per_lun *
                    blk_pgs * page / nrg;
    uint64_t block = 1ULL << ns->lbaf.lbads;

    if (block > unit) {
        error_setg(errp, "FEMU %s: a reclaim unit (%" PRIu64 " bytes) must "
                   "hold a logical block; namespace %u has %" PRIu64 "-byte "
                   "blocks: lower lba_index or fdp.nrg", mode, unit, ns->id,
                   block);
        return -1;
    }
    if (nrg == 1 || !(block % page)) {
        return 0;
    }
    error_setg(errp, "FEMU %s: fdp.nrg above 1 needs a logical block of whole "
               "NAND pages (%" PRIu64 " bytes); namespace %u has %" PRIu64
               "-byte blocks: set lba_index", mode, page, ns->id, block);
    return -1;
}

/*
 * A line is only reclaimable by relocating its valid pages somewhere else, so
 * part of the NAND has to stay unexposed. Expose all of it and a host that
 * fills the namespace leaves garbage collection nothing to free: the write
 * path then runs out of lines and aborts mid-run. Refuse the geometry instead,
 * and say what would fit.
 */
int bb_check_capacity(FemuCtrl *n, NvmeNamespace *ns, Error **errp)
{
    BbCtrlParams *p = &n->bb_params;
    uint64_t page_bytes = (uint64_t)p->secs_per_pg * p->secsz;
    /* a line is one block on every plane of every LUN, as the FTL builds it */
    uint64_t pgs_per_line = (uint64_t)p->nchs * p->luns_per_ch *
                            p->pls_per_lun * p->pgs_per_blk;
    /* the pages of a line that hold data: rain_parity keeps one per row */
    uint64_t data_pgs = bb_line_data_pgs(p);
    /*
     * Spare lines only replace worn-out blocks, and reserve lines wait for
     * the end of life; neither holds data before that.
     */
    uint64_t reserve_eol = bb_eol_reserve_lines(n);
    uint64_t tt_lines = (uint64_t)p->blks_per_pl -
                        (n->blk_pe_limit ? n->spare_lines : 0);
    uint64_t reserve_lines, usable_pgs, exposed_pgs;
    uint64_t tier_lines;
    int tp_lines;

    /*
     * The free lines GC insists on, plus one for every write pointer this
     * configuration can hold open at once. Counting only the data pointer
     * leaves a device that hot/cold separation or a log-block scheme can run
     * out of lines on, which used to be fatal and is now a refused write.
     */
    reserve_lines = bb_gc_forced_lines(n);
    reserve_lines += 1;                      /* the data write pointer */
    if (n->streams) {
        reserve_lines += n->streams_max + 1;
        if (pgs_per_line > UINT16_MAX) {
            error_setg(errp, "Streams SGS exceeds the 16-bit field");
            return -1;
        }
        if (femu_mapping_name_uses_log_class(p->mapping_scheme)) {
            error_setg(errp, "Streams requires page or dftl mapping");
            return -1;
        }
    }
    if (p->hot_cold_sep) {
        reserve_lines += 1;                  /* the hot write pointer */
    }
    if (p->gc_frontier) {
        reserve_lines += 1;                  /* the collection write pointer */
    }
    if (femu_mapping_name_uses_log_class(p->mapping_scheme)) {
        reserve_lines += 1;                  /* the log write pointer */
    }
    /* the admission counts pages in 31 bits of one word */
    if (reserve_eol >= (1ULL << 31) / data_pgs) {
        error_setg(errp, "FEMU bbssd: eol_read_only needs %" PRIu64 " reserve "
                   "lines of %" PRIu64 " pages; lower mdts", reserve_eol,
                   data_pgs);
        return -1;
    }
    reserve_lines += reserve_eol;
    /* dftl without FDP: translation page lines and their pointer */
    tp_lines = bb_tp_reserve_lines(n, ns);
    reserve_lines += tp_lines;
    /* the static pSLC pool: its lines never hold dense data */
    tier_lines = bb_tier_pool_lines(n);
    reserve_lines += tier_lines;

    if (reserve_eol && tt_lines <= reserve_lines) {
        error_setg(errp, "FEMU bbssd: the geometry has only %" PRIu64 " lines, "
                   "fewer than the %" PRIu64 " garbage collection and the "
                   "eol_read_only reserve (%" PRIu64 ", from mdts) need; lower "
                   "mdts or raise blks_per_pl", tt_lines, reserve_lines,
                   reserve_eol);
        return -1;
    }
    if (tt_lines <= reserve_lines) {
        error_setg(errp, "FEMU bbssd: the geometry has only %" PRIu64 " lines, "
                   "fewer than the %" PRIu64 " garbage collection needs free%s",
                   tt_lines, reserve_lines, tier_lines ? " with the "
                   "tier_static_mb pSLC pool" : "");
        return -1;
    }

    /*
     * Under placement the reclaim units are what the write path draws from, and
     * one is held open per handle with another for the unit being collected
     * into. Fewer than that and the very first setup asks for a unit that is
     * not there, which the handle initialisation dereferences without looking.
     */
    if (n->subsys && n->subsys->endgrp.fdp.enabled) {
        NvmeEnduranceGroup *endgrp = &n->subsys->endgrp;
        uint32_t nrg = endgrp->fdp.nrg;
        /* each group has a unit per block id, on its own dies */
        uint64_t pool = endgrp->fdp.nru ? MIN(tt_lines, endgrp->fdp.nru) :
                                          tt_lines;
        uint64_t needed = 2 * (uint64_t)endgrp->fdp.nruh + 1;
        uint64_t unit_pgs;
        uint64_t reserve;
        const char *eol;

        if (bb_check_fdp_groups(n, errp) ||
            bb_check_fdp_block(n, ns, "bbssd", errp)) {
            return -1;
        }
        unit_pgs = pgs_per_line / nrg;

        /*
         * The FTL's reclaim unit is one superblock of the dies of a group,
         * and the host sizes its placement by the unit it is told about.
         */
        if (n->subsys->params.fdp.runs &&
            n->subsys->params.fdp.runs != unit_pgs * page_bytes) {
            error_setg(errp, "FEMU bbssd: fdp.runs must be %" PRIu64 ", the "
                       "size of one superblock of the dies of a reclaim "
                       "group of this geometry, or unset",
                       unit_pgs * page_bytes);
            return -1;
        }
        if (pool < needed) {
            error_setg(errp, "FEMU bbssd: placement needs %" PRIu64 " reclaim "
                       "units in each group for %u handles and this geometry "
                       "gives %" PRIu64 "; raise blks_per_pl or fdp.nru, or "
                       "lower fdp.nruh", needed, endgrp->fdp.nruh, pool);
            return -1;
        }

        /*
         * Placement draws from the units alone, so they are what bounds the
         * namespace: in each group, one held open per handle, one more per
         * persistently isolated handle to collect into (the initially
         * isolated handle collects into its open one), and the free units
         * forced collection keeps. The data pointer line counted above is
         * not used under placement. A host may send all of its data to one
         * group (Base 2.3, 8.1.11), and a write within the namespace
         * capacity must not fail, so one group must hold every namespace.
         */
        reserve = bb_fdp_reserve_units(n, pool);
        /*
         * eol_read_only holds erased units in every group for the writes in
         * flight at the end of life, and counts their pages in 31 bits.
         */
        if (bb_fdp_eol_units(n) >= (1ULL << 31) / unit_pgs) {
            error_setg(errp, "FEMU bbssd: eol_read_only needs %" PRIu64
                       " reserve units of %" PRIu64 " pages; lower mdts",
                       bb_fdp_eol_units(n), unit_pgs);
            return -1;
        }
        reserve += bb_fdp_eol_reserve(n);
        /* the static pSLC units of each group hold no dense data */
        reserve += bb_fdp_slc_units(n);
        eol = bb_fdp_eol_reserve(n) ? " and the eol_read_only reserve (lower "
              "mdts)" : bb_fdp_slc_units(n) ? " and the pSLC units" : "";
        usable_pgs = pool > reserve ? (pool - reserve) * unit_pgs : 0;
        /* every namespace of the controller places into this one FTL */
        exposed_pgs = DIV_ROUND_UP(bb_ftl_bytes(n, ns), page_bytes);
        if (exposed_pgs > usable_pgs && nrg > 1) {
            error_setg(errp, "FEMU bbssd: a reclaim group must hold every "
                       "namespace, since a host may place all of its data "
                       "in one: the namespaces expose %" PRIu64 " KiB, and "
                       "each of the %u groups keeps %" PRIu64 " of its %"
                       PRIu64 " units for handles, collection%s, leaving %"
                       PRIu64 " KiB; lower devsz_mb or fdp.nrg, or raise "
                       "blks_per_pl or op_pcent", bb_ftl_bytes(n, ns) >> 10,
                       nrg, reserve, pool, eol, (usable_pgs * page_bytes) >> 10);
            return -1;
        }
        if (exposed_pgs > usable_pgs && n->num_namespaces > 1) {
            error_setg(errp, "FEMU bbssd: the %u namespaces expose %" PRIu64
                       " KiB, but placement keeps %" PRIu64 " of the %" PRIu64
                       " reclaim units for %u handles, collection%s, leaving "
                       "%" PRIu64 " KiB; lower devsz_mb or fdp.nruh, raise "
                       "blks_per_pl, or raise op_pcent", n->num_namespaces,
                       bb_ftl_bytes(n, ns) >> 10, reserve, pool,
                       endgrp->fdp.nruh, eol, (usable_pgs * page_bytes) >> 10);
            return -1;
        }
        if (exposed_pgs > usable_pgs) {
            error_setg(errp, "FEMU bbssd: namespace %u exposes %" PRIu64
                       " KiB, but placement keeps %" PRIu64 " of the %" PRIu64
                       " reclaim units for %u handles, collection%s, leaving "
                       "%" PRIu64 " KiB; lower devsz_mb or fdp.nruh, raise "
                       "blks_per_pl, or raise op_pcent", ns->id,
                       ns->size >> 10, reserve, pool, endgrp->fdp.nruh, eol,
                       (usable_pgs * page_bytes) >> 10);
            return -1;
        }
        return 0;
    }

    usable_pgs = (tt_lines - reserve_lines) * data_pgs;
    exposed_pgs = DIV_ROUND_UP(bb_ftl_bytes(n, ns), page_bytes);

    if (exposed_pgs > usable_pgs && n->shared_ftl) {
        error_setg(errp, "FEMU bbssd: the %u namespaces share one FTL and "
                   "expose %" PRIu64 " KiB, but this geometry keeps %" PRIu64
                   " KiB after garbage collection's room; lower devsz_mb or "
                   "the namespace sizes, or set op_pcent", n->num_namespaces,
                   bb_ftl_bytes(n, ns) >> 10,
                   (usable_pgs * page_bytes) >> 10);
        return -1;
    }
    if (exposed_pgs > usable_pgs) {
        error_setg(errp, "FEMU bbssd: namespace %u exposes %" PRIu64 " MiB of "
                   "the %" PRIu64 " MiB this geometry has, leaving garbage "
                   "collection no room; expose at most %" PRIu64 " MiB per "
                   "namespace (lower devsz_mb, or set op_pcent)%s%s",
                   ns->id, ns->size >> 20,
                   (tt_lines * pgs_per_line * page_bytes) >> 20,
                   (usable_pgs * page_bytes) >> 20,
                   tp_lines ? "; mapping=dftl keeps lines for its translation "
                   "pages" : "",
                   tier_lines ? "; the tier_static_mb pSLC pool keeps lines "
                   "out of the dense capacity" : "");
        return -1;
    }

    return 0;
}

/*
 * gc_idle_ms collects in idle time on the FTL thread. The first version
 * serves one bbssd controller whose one page-mapped namespace is its own:
 * a step then runs alone inside ftl_in_sweep, and all media work goes
 * through the request path. Each refusal below breaks one of these.
 */
/*
 * The raw bit error model books each retry as a later read on the flat
 * bus model, on host reads only. Refuse it where that booking or its
 * inputs would be wrong, and check its limits, all only when it is on.
 */
int bb_check_rber(FemuCtrl *n, const char *mode, Error **errp)
{
    const BbCtrlParams *p = &n->bb_params;
    const char *map = p->mapping_scheme;
    const char *page = p->onfi_param_page;
    uint64_t pgsz = (uint64_t)p->secs_per_pg * p->secsz;
    const char *why = NULL;

    if (!p->rber_ppb) {
        return 0;
    }
    if (strcmp(mode, "bbssd")) {
        why = mode;
    } else if (p->cmd_addr_lat || p->pg_xfer_lat || p->ch_xfer_lat ||
               p->status_lat) {
        why = "bus phase timing (cmd_addr_lat, pg_xfer_lat, ch_xfer_lat, "
              "status_lat)";
    } else if (p->onfi_mode != -1 || (page && *page) || p->onfi_sca) {
        why = "ONFI timing";
    } else if (p->pe_suspend) {
        why = "pe_suspend";
    } else if (p->read_prio) {
        why = "read_prio";
    } else if (p->mp_read || p->onfi_cache_read) {
        why = "mp_read or onfi_cache_read";
    } else if (p->gc_copyback) {
        why = "gc_copyback";
    } else if (p->ecc_step_ns) {
        why = "ecc_step_ns";
    } else if (n->cxl_ssd) {
        why = "cxl_ssd";
    } else if (p->tier_mode && strcmp(p->tier_mode, "off")) {
        why = "the pSLC tier";
    } else if (map && *map && strcmp(map, "page") && strcmp(map, "dftl")) {
        why = "a mapping other than page or dftl";
    }
    if (why) {
        error_setg(errp, "FEMU %s: rber_ppb is not supported with %s",
                   mode, why);
        return -1;
    }
    if (p->rber_ppb > 1000000000u) {
        why = "rber_ppb must be at most 1000000000";
    } else if (p->ecc_cw_bytes < 256 || pgsz % p->ecc_cw_bytes ||
               pgsz / p->ecc_cw_bytes > 16) {
        why = "ecc_cw_bytes must be 256 or more, divide the page, and give "
              "16 codewords or fewer";
    } else if (p->ecc_hard_bits < 1 || p->ecc_hard_bits > FTL_RBER_BITS_MAX) {
        why = "ecc_hard_bits must be 1 to 1024";
    } else if (p->ecc_soft_bits && (p->ecc_soft_bits < p->ecc_hard_bits ||
                                    p->ecc_soft_bits > FTL_RBER_BITS_MAX)) {
        why = "ecc_soft_bits must be 0, or ecc_hard_bits to 1024";
    } else if (p->rr_steps > FTL_RBER_STEPS_MAX) {
        why = "rr_steps must be 0 to 16";
    } else if (p->rr_gain < 2 || p->rr_gain > 16) {
        why = "rr_gain must be 2 to 16";
    } else if (p->rr_floor_pct > 100) {
        why = "rr_floor_pct must be 0 to 100";
    } else if (p->rr_soft_senses > 8) {
        why = "rr_soft_senses must be 0 to 8";
    } else if (p->rr_soft_ns > 10000000) {
        why = "rr_soft_ns must be at most 10000000";
    }
    if (why) {
        error_setg(errp, "FEMU %s: %s", mode, why);
        return -1;
    }
    return 0;
}

int bb_check_gc_idle(FemuCtrl *n, const char *mode, Error **errp)
{
    const BbCtrlParams *p = &n->bb_params;
    const char *map = p->mapping_scheme;
    const char *why = NULL;

    if (p->gc_idle_pcent && !p->gc_idle_ms) {
        warn_report("femu: gc_idle_pcent has no effect unless gc_idle_ms "
                    "is set");
    }
    if (p->maint_idle && !p->gc_idle_ms) {
        error_setg(errp, "FEMU %s: maint_idle needs gc_idle_ms", mode);
        return -1;
    }
    if (!p->gc_idle_ms) {
        return 0;
    }
    if (p->gc_idle_pcent > 99) {
        why = "gc_idle_pcent above 99";
    } else if (strcmp(mode, "bbssd")) {
        why = mode;
    } else if (nvme_ns_shared(n)) {
        why = "shared namespaces";
    } else if (n->ns_mgmt) {
        why = "ns_mgmt";
    } else if (n->num_namespaces != 1) {
        why = "more than one namespace";
    } else if (n->subsys && n->subsys->endgrp.fdp.enabled) {
        why = "FDP";
    } else if (n->cxl_ssd) {
        why = "cxl_ssd";
    } else if (p->gc_pace) {
        why = "gc_pace";
    } else if (n->streams) {
        why = "Streams";
    } else if (n->power_loss) {
        why = "power_loss";
    } else if (p->tier_mode && strcmp(p->tier_mode, "off")) {
        why = "the pSLC tier";
    } else if (map && *map && strcmp(map, "page")) {
        why = "a mapping other than page";
    }
    if (why) {
        error_setg(errp, "FEMU %s: gc_idle_ms is not supported with %s",
                   mode, why);
        return -1;
    }
    return 0;
}

/*
 * bb_gc_idle - the idle collection pass of the FTL thread
 *
 * Runs one step when one is due. The step runs inside ftl_in_sweep, as a
 * request does, so a caller that pauses the controller waits for it.
 */
/* the idle FTL thread writes buffered pages back (buffer_low_pcent) */
void bb_buffer_idle(FemuCtrl *n)
{
    n->ftl_in_sweep = true;
    smp_mb();   /* publish the flag before re-reading the pause state */
    for (uint32_t i = 0; n->dataplane_started && i < n->namespace_limit; i++) {
        NvmeNamespace *ns = &n->namespaces[i];

        /* an FTL that namespaces share takes one step, through its owner */
        if (ns->allocated && ns->ssd && !ns->ssd_shared &&
            (NS_BBSSD(ns) || NS_CSD(ns))) {
            if (ssd_durable_on(ns->ssd)) {
                ssd_durable_retire(ns->ssd, ssd_now(ns->ssd));
            }
            if (n->buffer_bg) {
                ssd_buffer_bg_step(ns->ssd, ssd_now(ns->ssd));
            }
        }
    }
    n->ftl_in_sweep = false;
}

void bb_gc_idle(FemuCtrl *n)
{
    struct ssd *ssd = n->ssd;
    uint64_t now;

    if (!ssd || ssd->gc_idle_hold) {
        return;
    }
    now = ssd_now(ssd);
    if (!ssd_gc_idle_due(ssd, now)) {
        return;
    }
    n->ftl_in_sweep = true;
    smp_mb();   /* publish the flag before re-reading the pause state */
    /*
     * A qtest hook may have changed the hold or the fence while this
     * thread was between the first check and the flag, so check again.
     */
    now = ssd_now(ssd);
    if (n->dataplane_started && !ssd->gc_idle_hold &&
        ssd_gc_idle_due(ssd, now)) {
        qatomic_set(&ssd->gc_idle_running, true);
        if (unlikely(ssd->gc_idle_latch_ms)) {
            g_usleep(ssd->gc_idle_latch_ms * 1000);
        }
        ssd_gc_idle_step(ssd, now);
        qatomic_set(&ssd->gc_idle_running, false);
    }
    n->ftl_in_sweep = false;
}

/*
 * gc_frontier gives the pages collection copies a write pointer of their
 * own. Refuse it where that pointer would be ignored or would break an
 * accounting that counts one frontier: FDP (reclaim units collect per
 * handle; checked here, before capacity, so its own message wins), a
 * controller that borrows the FTL of
 * a CXL medium, paced collection (its budget counts the data pointer only),
 * Streams (released tags seal their GC line on each change, and at no free
 * line Streams refuses a victim), and retention refresh without the aged
 * close of open lines (an open line has no close time to age from).
 */
int bb_check_gc_frontier(FemuCtrl *n, const char *mode, Error **errp)
{
    const BbCtrlParams *p = &n->bb_params;
    const char *why = NULL;

    if (!p->gc_frontier) {
        return 0;
    }
    if (n->subsys && n->subsys->endgrp.fdp.enabled) {
        why = "FDP: each reclaim unit handle already collects into units of "
              "its own";
    } else if (n->cxl_ssd) {
        why = "cxl_ssd: the controller uses the FTL of the CXL medium";
    } else if (p->gc_pace) {
        why = "gc_pace: its budget counts one write frontier";
    } else if (n->streams) {
        why = "Streams: released streams already collect into a line of "
              "their own";
    } else if (p->retention_limit_sec && !p->pd_open_close_sec) {
        why = "retention_limit_sec without pd_open_close_sec: an open "
              "collection line would never age";
    }
    if (why) {
        error_setg(errp, "FEMU %s: gc_frontier is not supported with %s",
                   mode, why);
        return -1;
    }
    return 0;
}

/*
 * FDP keeps its own write and reclaim path. Refuse the knobs it does not
 * take rather than accept them silently. The write buffer keeps the handle
 * of each page, dftl adds timing only, and gc_policy names a unit strategy,
 * so those pass with the media and refresh knobs. Every mode that runs this
 * FTL under FDP needs the refusal and the reclaim unit size, not only
 * bbssd. A no-op without FDP.
 */
int bb_init_fdp(FemuCtrl *n, NvmeNamespace *ns, const char *mode,
                Error **errp)
{
    const BbCtrlParams *p = &n->bb_params;

    if (!n->subsys || !n->subsys->endgrp.fdp.enabled) {
        return 0;
    }

    /*
     * Under FDP the placement handle of a write names the unit it goes to.
     * Both knobs below program host data through write pointers of their
     * own, so they would put it in units no handle references.
     */
    if (p->hot_cold_sep) {
        error_setg(errp, "FEMU %s: hot_cold_sep is not supported under FDP: "
                   "the placement handle of a write chooses its reclaim "
                   "unit, and the overwrite pointer writes past it; give "
                   "hot data a handle of its own", mode);
        return -1;
    }
    /* dftl adds only translation-page timing, which places no data */
    if (femu_mapping_name_uses_log_class(p->mapping_scheme)) {
        error_setg(errp, "FEMU %s: mapping=%s is not supported under FDP: "
                   "the log-block mappings write and merge through lines "
                   "that are not FDP-aware; use page or dftl", mode,
                   p->mapping_scheme);
        return -1;
    }

    /* gc_policy picks the unit strategy that gc_strategy also picks */
    if (p->gc_policy && *p->gc_policy && strcmp(p->gc_policy, "greedy") &&
        p->gc_strategy != GC_GLOBAL_GREEDY) {
        error_setg(errp, "FEMU %s: set gc_policy or gc_strategy under FDP, "
                   "not both", mode);
        return -1;
    }

    if (bb_check_fdp_block(n, ns, mode, errp)) {
        return -1;
    }

    /* a unit is one block of each plane of each die of its group */
    n->subsys->endgrp.fdp.runs = (uint64_t)p->nchs * p->luns_per_ch *
                                 p->pls_per_lun * p->pgs_per_blk *
                                 p->secs_per_pg * p->secsz /
                                 n->subsys->endgrp.fdp.nrg;
    nvme_ns_refresh_fdp(ns);
    return 0;
}

/* bb <=> black-box */
static void bb_init(FemuCtrl *n, NvmeNamespace *ns, Error **errp)
{
    struct ssd *ssd;

    if (bb_check_gc_frontier(n, "bbssd", errp) ||
        bb_check_gc_idle(n, "bbssd", errp) ||
        bb_check_rber(n, "bbssd", errp)) {
        return;
    }

    /* A linked CXL medium already built the FTL from its own geometry. */
    if (n->cxl_ssd) {
        ns->ssd = n->cxl_ssd;
        ns->ssd_borrowed = true;
        n->ssd = ns->ssd;
        bb_init_ctrl_str(n, ns);
        return;
    }

    /*
     * Under FDP the reclaim units belong to the endurance group, so the first
     * namespace's FTL serves every later one; realize already checked it
     * holds them all.
     */
    if (n->ssd && n->subsys && n->subsys->endgrp.fdp.enabled) {
        if (bb_init_fdp(n, ns, "bbssd", errp)) {
            return;
        }
        ns->ssd = n->ssd;
        ns->ssd_shared = true;
        return;
    }
    /* shared_ftl: realize checked that the FTL holds every slice */
    if (n->ssd && n->shared_ftl) {
        ns->ssd = n->ssd;
        ns->ssd_shared = true;
        return;
    }

    if (bb_check_geometry(n, errp)) {
        return;
    }

    if (bb_check_capacity(n, ns, errp)) {
        return;
    }

    if (bb_init_fdp(n, ns, "bbssd", errp)) {
        return;
    }

    ssd = ns->ssd = g_malloc0(sizeof(struct ssd));

    if (!n->ns_mgmt) {
        bb_init_ctrl_str(n, ns);
    }

    /*
     * Each bbssd namespace carries its own FTL, so the controller can mix it
     * with namespaces of other modes. The first one also answers the
     * controller-wide queries that predate per-namespace state.
     */
    if (!n->ssd) {
        n->ssd = ssd;
    }

    ssd->dataplane_started_ptr = &n->dataplane_started;
    ssd->ssdname = (char *)n->devname;
    femu_debug("Starting FEMU in Blackbox-SSD mode ...\n");
    ssd_init(n, ns);
    if (n->die_stats && !ssd->media.die_stat) {
        error_setg(errp, "die_stats does not count plane_reads, pe_suspend, "
                   "read priority, cache reads or bus timing yet");
        return;
    }
    if (n->bb_params.gc_idle_ms) {
        ssd->gc_idle_ns = (uint64_t)n->bb_params.gc_idle_ms * 1000000;
        ssd->maint_idle = n->bb_params.maint_idle;
        n->gc_idle = true;
    }
}

/*
 * Apply a timing or GC toggle to every namespace carrying an FTL. Flip arrives
 * as an admin command and names no namespace, so it is device-wide; n->ssd is
 * only whichever namespace brought its mode up first, and using it would leave
 * every other FTL-backed namespace on the previous setting.
 */
static void bb_flip_apply(FemuCtrl *n, int64_t cdw10)
{
    bool resume;
    int i;

    /*
     * These are the timings the FTL thread reads on every request, and the
     * media layer is rebuilt from them below. Stop the dataplane first: this
     * runs on the thread that took the admin command, so nothing else keeps
     * the fields still.
     */
    resume = nvme_pause_pollers(n);

    /* The medium's worker shares these timings; it applies them locked. */
    if (n->cxl_media) {
        femu_cxl_nvme_ops->flip(n, cdw10);
        nvme_resume_pollers(n, resume);
        return;
    }

    for (i = 0; i < n->namespace_limit; i++) {
        struct ssd *ssd = n->namespaces[i].ssd;

        if (!n->namespaces[i].allocated || !ssd) {
            continue;
        }

        switch (cdw10) {
        case FEMU_ENABLE_GC_DELAY:
            ssd->sp.enable_gc_delay = true;
            break;
        case FEMU_DISABLE_GC_DELAY:
            ssd->sp.enable_gc_delay = false;
            break;
        case FEMU_ENABLE_DELAY_EMU:
            ssd->sp.pg_rd_lat = NAND_READ_LATENCY;
            ssd->sp.pg_wr_lat = NAND_PROG_LATENCY;
            ssd->sp.blk_er_lat = NAND_ERASE_LATENCY;
            ssd->sp.ch_xfer_lat = 0;
            /* refresh the media-layer timing snapshot from the updated params */
            bb_nand_media_refresh_timing(ssd);
            break;
        case FEMU_DISABLE_DELAY_EMU:
            ssd->sp.pg_rd_lat = 0;
            ssd->sp.pg_wr_lat = 0;
            ssd->sp.blk_er_lat = 0;
            ssd->sp.ch_xfer_lat = 0;
            /* refresh the media-layer timing snapshot from the updated params */
            bb_nand_media_refresh_timing(ssd);
            break;
        default:
            break;
        }
    }

    nvme_resume_pollers(n, resume);
}

static uint16_t bb_flip(FemuCtrl *n, NvmeCmd *cmd)
{
    int64_t cdw10 = le64_to_cpu(cmd->cdw10);

    /*
     * The thermal throttle needs timed media: untimed collection books no
     * energy, and zero delays leave nothing to stretch.
     */
    if (n->throttle && (cdw10 == FEMU_DISABLE_GC_DELAY ||
                        cdw10 == FEMU_DISABLE_DELAY_EMU)) {
        femu_log("%s,FEMU delay toggle ignored: throttle=on\n", n->devname);
        return NVME_SUCCESS;
    }
    /* a persist_ftl file holds the FTL of the properties, not of a toggle */
    if (n->persist_ftl && (cdw10 == FEMU_ENABLE_GC_DELAY ||
                           cdw10 == FEMU_DISABLE_GC_DELAY ||
                           cdw10 == FEMU_ENABLE_DELAY_EMU ||
                           cdw10 == FEMU_DISABLE_DELAY_EMU)) {
        femu_log("%s,FEMU toggle refused: persist_ftl=on\n", n->devname);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    /* untimed collection would skip the parity programs it makes due */
    if ((n->bb_params.die_parity || n->bb_params.rain_parity) &&
        cdw10 == FEMU_DISABLE_GC_DELAY) {
        femu_log("%s,FEMU GC delay toggle ignored: parity is on\n",
                 n->devname);
        return NVME_SUCCESS;
    }

    switch (cdw10) {
    case FEMU_ENABLE_GC_DELAY:
        bb_flip_apply(n, cdw10);
        femu_log("%s,FEMU GC Delay Emulation [Enabled]!\n", n->devname);
        break;
    case FEMU_DISABLE_GC_DELAY:
        bb_flip_apply(n, cdw10);
        femu_log("%s,FEMU GC Delay Emulation [Disabled]!\n", n->devname);
        break;
    case FEMU_ENABLE_DELAY_EMU:
        bb_flip_apply(n, cdw10);
        femu_log("%s,FEMU Delay Emulation [Enabled]!\n", n->devname);
        break;
    case FEMU_DISABLE_DELAY_EMU:
        bb_flip_apply(n, cdw10);
        femu_log("%s,FEMU Delay Emulation [Disabled]!\n", n->devname);
        break;
    case FEMU_RESET_ACCT: {
        /* counters are sharded per poller (see FemuPollerCtr); sum then reset */
        int64_t tt = 0, late = 0;
        if (n->poller_ctr) {
            for (uint32_t p = 1; p <= n->nr_pollers; p++) {
                tt += n->poller_ctr[p].nr_tt_ios;
                late += n->poller_ctr[p].nr_tt_late_ios;
                n->poller_ctr[p].nr_tt_ios = 0;
                n->poller_ctr[p].nr_tt_late_ios = 0;
            }
        }
        femu_log("%s,Reset tt_late_ios/tt_ios,%ld/%ld\n", n->devname, late, tt);
        break;
    }
    case FEMU_ENABLE_LOG:
        n->print_log = true;
        femu_log("%s,Log print [Enabled]!\n", n->devname);
        break;
    case FEMU_DISABLE_LOG:
        n->print_log = false;
        femu_log("%s,Log print [Disabled]!\n", n->devname);
        break;
    default:
        printf("FEMU:%s,Not implemented flip cmd (%lu)\n", n->devname, cdw10);
    }
    return NVME_SUCCESS;
}

/*
 * Release what the namespace's FTL still holds. Reached for the mode the
 * controller itself runs; a namespace running bbssd underneath a controller of
 * another mode is not dispatched an exit at all, which is a gap in the generic
 * teardown rather than one here.
 */
/*
 * Release the FTL this mode built. Each mode allocates its own ns->ssd and
 * frees the ones its namespaces own, so a controller mixing modes tears each
 * down exactly once. n->ssd aliases the first namespace's, so clear it before
 * the memory goes.
 */
static void bb_ns_exit(FemuCtrl *n, NvmeNamespace *ns)
{
    if (!ns->ssd) {
        return;
    }
    if (ns->ssd_shared) {
        ns->ssd = NULL;
        ns->ssd_shared = false;
        return;
    }
    if (n->ssd == ns->ssd) {
        n->ssd = NULL;
    }
    if (ns->ssd_borrowed) {
        ns->ssd = NULL;
        return;
    }
    /* the namespaces that share this FTL lose it with its owner */
    for (int i = 0; i < n->namespace_limit; i++) {
        NvmeNamespace *o = &n->namespaces[i];

        if (o != ns && o->ssd == ns->ssd) {
            o->ssd = NULL;
            o->ssd_shared = false;
        }
    }
    ssd_free(ns->ssd);
    g_free(ns->ssd);
    ns->ssd = NULL;
}

static void bb_exit(FemuCtrl *n)
{
    int i;

    for (i = 0; i < n->namespace_limit; i++) {
        NvmeNamespace *ns = &n->namespaces[i];

        if (NS_BBSSD(ns)) {
            bb_ns_exit(n, ns);
        }
    }
}

static uint16_t bb_nvme_rw(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                           NvmeRequest *req)
{
    return nvme_rw(n, ns, cmd, req);
}

static uint16_t bb_io_cmd(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                          NvmeRequest *req)
{
    switch (cmd->opcode) {
    case NVME_CMD_READ:
    case NVME_CMD_WRITE:
        return bb_nvme_rw(n, ns, cmd, req);
    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

static uint16_t bb_admin_cmd(FemuCtrl *n, NvmeCmd *cmd)
{
    switch (cmd->opcode) {
    case NVME_ADM_CMD_FEMU_FLIP:
        return bb_flip(n, cmd);
    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

int nvme_register_bbssd(FemuCtrl *n)
{
    n->ext_ops = (FemuExtCtrlOps) {
        .state            = NULL,
        .init_ctrl_name   = bb_init_ctrl_str,
        .ns_exit          = bb_ns_exit,
        .init             = bb_init,
        .exit             = bb_exit,
        .rw_check_req     = NULL,
        .admin_cmd        = bb_admin_cmd,
        .io_cmd           = bb_io_cmd,
        .get_log          = NULL,
    };

    return 0;
}

