#include "../nvme.h"
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

    if (!n->subsys || !n->subsys->endgrp.fdp.enabled) {
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
    uint64_t unit = (uint64_t)p->nchs * p->luns_per_ch * p->pls_per_lun *
                    p->pgs_per_blk * page / nrg;
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
    /*
     * Spare lines only replace worn-out blocks, and reserve lines wait for
     * the end of life; neither holds data before that.
     */
    uint64_t reserve_eol = bb_eol_reserve_lines(n);
    uint64_t tt_lines = (uint64_t)p->blks_per_pl -
                        (n->blk_pe_limit ? n->spare_lines : 0);
    uint64_t reserve_lines, usable_pgs, exposed_pgs;
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
    if (femu_mapping_name_uses_log_class(p->mapping_scheme)) {
        reserve_lines += 1;                  /* the log write pointer */
    }
    /* the admission counts pages in 31 bits of one word */
    if (reserve_eol >= (1ULL << 31) / pgs_per_line) {
        error_setg(errp, "FEMU bbssd: eol_read_only needs %" PRIu64 " reserve "
                   "lines of %" PRIu64 " pages; lower mdts", reserve_eol,
                   pgs_per_line);
        return -1;
    }
    reserve_lines += reserve_eol;
    /* dftl without FDP: translation page lines and their pointer */
    tp_lines = bb_tp_reserve_lines(n, ns);
    reserve_lines += tp_lines;

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
                   "fewer than the %" PRIu64 " garbage collection needs free",
                   tt_lines, reserve_lines);
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
        reserve = endgrp->fdp.nruh;
        reserve += endgrp->fdp.nruh -
                   (n->subsys->params.fdp.isolation_mode ? 1 : 0);
        reserve += bb_fdp_forced_units(n, pool);
        usable_pgs = pool > reserve ? (pool - reserve) * unit_pgs : 0;
        /* every namespace of the controller places into this one FTL */
        exposed_pgs = DIV_ROUND_UP(bb_ftl_bytes(n, ns), page_bytes);
        if (exposed_pgs > usable_pgs && nrg > 1) {
            error_setg(errp, "FEMU bbssd: a reclaim group must hold every "
                       "namespace, since a host may place all of its data "
                       "in one: the namespaces expose %" PRIu64 " KiB, and "
                       "each of the %u groups keeps %" PRIu64 " of its %"
                       PRIu64 " units for handles and collection, leaving %"
                       PRIu64 " KiB; lower devsz_mb or fdp.nrg, or raise "
                       "blks_per_pl or op_pcent", bb_ftl_bytes(n, ns) >> 10,
                       nrg, reserve, pool, (usable_pgs * page_bytes) >> 10);
            return -1;
        }
        if (exposed_pgs > usable_pgs && n->num_namespaces > 1) {
            error_setg(errp, "FEMU bbssd: the %u namespaces expose %" PRIu64
                       " KiB, but placement keeps %" PRIu64 " of the %" PRIu64
                       " reclaim units for %u handles and collection, leaving "
                       "%" PRIu64 " KiB; lower devsz_mb or fdp.nruh, raise "
                       "blks_per_pl, or raise op_pcent", n->num_namespaces,
                       bb_ftl_bytes(n, ns) >> 10, reserve, pool,
                       endgrp->fdp.nruh, (usable_pgs * page_bytes) >> 10);
            return -1;
        }
        if (exposed_pgs > usable_pgs) {
            error_setg(errp, "FEMU bbssd: namespace %u exposes %" PRIu64
                       " KiB, but placement keeps %" PRIu64 " of the %" PRIu64
                       " reclaim units for %u handles and collection, leaving "
                       "%" PRIu64 " KiB; lower devsz_mb or fdp.nruh, raise "
                       "blks_per_pl, or raise op_pcent", ns->id,
                       ns->size >> 10, reserve, pool, endgrp->fdp.nruh,
                       (usable_pgs * page_bytes) >> 10);
            return -1;
        }
        return 0;
    }

    usable_pgs = (tt_lines - reserve_lines) * pgs_per_line;
    exposed_pgs = DIV_ROUND_UP(ns->size, page_bytes);

    if (exposed_pgs > usable_pgs) {
        error_setg(errp, "FEMU bbssd: namespace %u exposes %" PRIu64 " MiB of "
                   "the %" PRIu64 " MiB this geometry has, leaving garbage "
                   "collection no room; expose at most %" PRIu64 " MiB per "
                   "namespace (lower devsz_mb, or set op_pcent)%s",
                   ns->id, ns->size >> 20,
                   (tt_lines * pgs_per_line * page_bytes) >> 20,
                   (usable_pgs * page_bytes) >> 20,
                   tp_lines ? "; mapping=dftl keeps lines for its translation "
                   "pages" : "");
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

static void bb_flip(FemuCtrl *n, NvmeCmd *cmd)
{
    int64_t cdw10 = le64_to_cpu(cmd->cdw10);

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
        bb_flip(n, cmd);
        return NVME_SUCCESS;
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

