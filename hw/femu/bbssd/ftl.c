#include "ftl.h"
#include "ftl-internal.h"

//#define FEMU_DEBUG_FTL






void ssd_init(FemuCtrl *n, NvmeNamespace *ns)
{
    struct ssd *ssd = ns->ssd;
    struct ssdparams *spp = &ssd->sp;

    ftl_assert(ssd);
    ssd->n = n;

    /* read the data-remanence experiment env vars once (debug only, off by default) */
    exp_load_cfg();

    ssd_init_params(spp, n);

    /* initialize ssd internal layout architecture */
    ssd->ch = g_malloc0(sizeof(struct ssd_channel) * spp->nchs);
    for (int i = 0; i < spp->nchs; i++) {
        ssd_init_ch(&ssd->ch[i], spp);
    }

    /*
     * Validate the optional NAND cell type before the media layer or the datapath
     * indexes the per-type tables with it. Only SLC..QLC have populated tables and
     * page-type pairing; anything else (including PLC) falls back to flat timing.
     */
    if (n->nand_cell_type &&
        (n->nand_cell_type < SLC || n->nand_cell_type > QLC)) {
        ftl_err("nand_cell_type %u out of range (1 SLC..4 QLC); using flat timing\n",
                n->nand_cell_type);
        n->nand_cell_type = 0;
    }
    /*
     * The pgtype_lat program model needs a bits-per-cell count to pick a
     * multiplier row and to fold the page number into a page type; default it to
     * TLC when the model is on but cell_pages was left unset, so the page type
     * and the multiplier row stay consistent.
     */
    if (spp->pgtype_lat && spp->cell_pages < 1) {
        spp->cell_pages = 3; /* TLC */
    }

    /* factory bad-block count, reported via SMART available_spare; clamp to the
     * total block count so a misconfigured value cannot exceed 100% depletion */
    ssd->debug_ftl = n->debug_ftl;

    /*
     * Turn a parts-per-million rate into a 1-in-N period, clamped so a non-zero
     * rate always injects something. Zero leaves injection off.
     */
    ssd->err_read_unc_period = 0;
    ssd->err_read_counter = 0;
    ssd->err_read_injected = 0;
    if (n->err_read_unc_ppm) {
        ssd->err_read_unc_period = 1000000u / n->err_read_unc_ppm;
        if (ssd->err_read_unc_period < 1) {
            ssd->err_read_unc_period = 1;
        }
    }
    ssd->err_write_fail_period = 0;
    ssd->err_write_counter = 0;
    ssd->err_write_injected = 0;
    if (n->err_write_fail_ppm) {
        ssd->err_write_fail_period = 1000000u / n->err_write_fail_ppm;
        if (ssd->err_write_fail_period < 1) {
            ssd->err_write_fail_period = 1;
        }
    }
    ssd->host_write_pages = 0;
    ssd->gc_write_pages = 0;

    ssd->bad_blocks = n->nand_bad_blocks;
    if (spp->tt_blks > 0 && ssd->bad_blocks > (uint32_t)spp->tt_blks) {
        ssd->bad_blocks = (uint32_t)spp->tt_blks;
    }

    /* configure the NAND media-layer timing (reads spp, points at ssd->ch) */
    bb_nand_media_init(ssd);

    /* initialize maptbl */
    ssd_init_maptbl(ssd);

    /* initialize rmap */
    ssd_init_rmap(ssd);

    /* initialize all the lines */
    ssd_init_lines(ssd);

    /* resolve the base-path GC victim policy (greedy by default) */
    ssd->policy = femu_ftl_policy_lookup(n->bb_params.gc_policy);

    /*
     * L2P mapping scheme: "page" (default, full DRAM L2P, bit-identical) vs "dftl"
     * (demand-cached L2P via the CMT). The CMT turns on when dftl is named or
     * mapping_cache_mb is set; a named dftl with no explicit size gets 4 MB.
     */
    ssd->mapping = femu_mapping_scheme_lookup(n->bb_params.mapping_scheme);
    /* schemes that keep private state allocate it here; page/dftl keep it NULL */
    ssd->map_priv = NULL;
    if (ssd->mapping->init) {
        ssd->mapping->init(ssd);
    }
    uint32_t map_cache_mb = n->mapping_cache_mb;
    if (femu_mapping_scheme_uses_cmt(ssd->mapping) && map_cache_mb == 0) {
        map_cache_mb = 4; /* default dftl cache when no explicit size given */
    }
    /* the CMT is a dftl-only cost model: never charge it under the page scheme,
     * even if mapping_cache_mb was set */
    cmt_init(ssd, femu_mapping_scheme_uses_cmt(ssd->mapping) ? map_cache_mb : 0);

    /*
     * Optional DRAM read cache (opt-in via read_cache_mb; 0 = off, bit-identical
     * default). cache_evict selects the eviction policy.
     */
    uint32_t rc_evict = 0; /* 0 = CLOCK (default) */
    if (n->bb_params.cache_evict) {
        if (!strcmp(n->bb_params.cache_evict, "random")) {
            rc_evict = 1;
        } else if (!strcmp(n->bb_params.cache_evict, "lru")) {
            rc_evict = 2;
        } else if (!strcmp(n->bb_params.cache_evict, "arc")) {
            rc_evict = 3; /* scan-resistant 2Q-style */
        }
    }
    rcache_init(ssd, n->read_cache_mb, rc_evict);

    /* FDP vs non-FDP init path */
    ssd->fdp_enabled = (n->subsys != NULL &&
                        n->subsys->params.fdp.enabled);
    ssd->fdp_debug = (getenv("FEMU_FDP_DEBUG") != NULL);

    if (ssd->fdp_enabled) {
        ssd_init_fdp_params(spp, n);

        ftl_log("FDP: initializing reclaim groups\n");
        femu_fdp_ssd_init_reclaim_group(n, ssd);
        ftl_log("FDP: initializing RU handles\n");
        femu_fdp_ssd_init_ru_handles(n, ssd);
        ftl_log("FDP: init complete (nrg=%lu, nruhs=%lu)\n",
                ssd->nrg, ssd->nruhs);
    } else {
        /* non-FDP: use single write pointer */
        ssd_init_write_pointer(ssd);
    }
}

/*
 * Write-amplification factor scaled by 1000, so it needs no floating point on
 * the read path: (host + relocated) / host. Reads 1000 (a factor of 1.0) before
 * the host has written anything.
 */
uint32_t ssd_waf_x1000(struct ssd *ssd)
{
    uint64_t host = ssd->host_write_pages;
    uint64_t total = host + ssd->gc_write_pages;

    if (host == 0) {
        return 1000;
    }

    return (uint32_t)((total * 1000ull) / host);
}

/* struct ssd is opaque outside the FTL, so the raw counters need accessors */
uint64_t ssd_host_write_pages(struct ssd *ssd)
{
    return ssd->host_write_pages;
}

uint64_t ssd_gc_write_pages(struct ssd *ssd)
{
    return ssd->gc_write_pages;
}

/*
 * SMART available_spare: 100% on a healthy device, reduced by the factory
 * bad-block fraction (bad_blocks / tt_blks) as bad blocks consume the
 * over-provisioned reserve. A reported value only -- placement is unaffected.
 */
uint8_t ssd_available_spare(struct ssd *ssd)
{
    struct ssdparams *spp = &ssd->sp;
    uint64_t bad_pct;

    if (ssd->bad_blocks == 0 || spp->tt_blks <= 0) {
        return 100;
    }
    bad_pct = ((uint64_t)ssd->bad_blocks * 100ull) / (uint64_t)spp->tt_blks;
    return bad_pct >= 100 ? 0 : (uint8_t)(100 - bad_pct);
}



/*
 * ssd_advance_status now lives in the NAND media-layer bridge
 * (hw/femu/bbssd/ftl-media.c), which runs the same flat per-LUN read/program/
 * erase timing through the uniform nand_media API.
 */




/*
 * Run one request against this namespace's bbssd FTL and return the latency to
 * charge it. The controller's FTL thread calls this once it has picked out the
 * namespace, so one controller can serve namespaces of different modes.
 */
uint64_t bb_ftl_process_req(FemuCtrl *n, NvmeNamespace *ns, NvmeRequest *req)
{
    struct ssd *ssd = ns->ssd;
    uint64_t lat = 0;

    if (!ssd) {
        return 0;
    }

    /*
     * A request that already failed validation in the I/O layer is only routed
     * through the FTL ring so the poller completes it with its carried error
     * status. It must not run any opcode handler: req->slba and req->nlb may be
     * stale (the I/O layer returns before setting them) and ssd_read/ssd_write
     * would then touch unrelated mapping state and overwrite the error. Leave
     * latency at zero and let the poller post the carried status.
     */
    if (req->status != NVME_SUCCESS) {
        return 0;
    }

    switch (req->cmd.opcode) {
    case NVME_CMD_WRITE:
        if (ssd->fdp_enabled) {
            lat = nvme_do_write_fdp(n, req, req->slba, req->nlb);
        } else {
            lat = ssd_write(ssd, req);
        }
        /* optional write fault on every Nth write, on the same principle */
        if (ssd->err_write_fail_period &&
            (++ssd->err_write_counter % ssd->err_write_fail_period) == 0) {
            req->status = NVME_WRITE_FAULT;
            ssd->err_write_injected++;
        }
        break;
    case NVME_CMD_READ:
        lat = ssd_read(ssd, req);
        /*
         * Optional media error on every Nth read. The counter makes a run
         * reproducible, unlike a random draw.
         */
        if (ssd->err_read_unc_period &&
            (++ssd->err_read_counter % ssd->err_read_unc_period) == 0) {
            req->status = NVME_UNRECOVERED_READ | NVME_DNR;
            ssd->err_read_injected++;
        }
        break;
    case NVME_CMD_DSM:
        if (ssd->fdp_enabled) {
            ssd_trim_fdp_style(n, req, req->slba, req->nlb);
            lat = 0;
        } else if (req->dsm_ranges && req->dsm_nr_ranges > 0) {
            lat = ssd_trim(ssd, req);
        }
        break;
    default:
        ;
    }

    /* background GC */
    if (ssd->fdp_enabled) {
        int16_t rgidx;
        /*
         * Trigger a single GC pass on a reclaim group over threshold; the GC
         * policy itself lives in do_gc_fdp_style(), not here.
         */
        if (!((rgidx = should_gc_fdp_style(ssd)) < 0)) {
            if (ssd->nrg == 1) {
                do_gc_fdp_style(ssd, 0, 0, false);
            } else {
                do_gc_fdp_style(ssd, rgidx, 0, false);
            }
        }
    } else if (should_gc(ssd)) {
        do_gc(ssd, false);
    }

    return lat;
}
