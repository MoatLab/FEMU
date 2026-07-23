#include "ftl.h"
#include "ftl-internal.h"

//#define FEMU_DEBUG_FTL

static void *ftl_thread(void *arg);





void ssd_init(FemuCtrl *n)
{
    struct ssd *ssd = n->ssd;
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

    qemu_thread_create(&ssd->ftl_thread, "FEMU-FTL-Thread", ftl_thread, n,
                       QEMU_THREAD_JOINABLE);
}



/*
 * ssd_advance_status now lives in the NAND media-layer bridge
 * (hw/femu/bbssd/ftl-media.c), which runs the same flat per-LUN read/program/
 * erase timing through the uniform nand_media API.
 */




static void *ftl_thread(void *arg)
{
    FemuCtrl *n = (FemuCtrl *)arg;
    struct ssd *ssd = n->ssd;
    NvmeRequest *req = NULL;
    uint64_t lat = 0;
    int rc;
    int i;

    while (!*(ssd->dataplane_started_ptr)) {
        usleep(100000);
    }

    /* FIXME: not safe, to handle ->to_ftl and ->to_poller gracefully */
    ssd->to_ftl = n->to_ftl;
    ssd->to_poller = n->to_poller;

    while (1) {
        for (i = 1; i <= n->nr_pollers; i++) {
            if (!ssd->to_ftl[i] || !femu_ring_count(ssd->to_ftl[i]))
                continue;

            rc = femu_ring_dequeue(ssd->to_ftl[i], (void *)&req, 1);
            if (rc != 1) {
                printf("FEMU: FTL to_ftl dequeue failed\n");
            }

            ftl_assert(req);
            lat = 0;
            /*
             * A request that already failed validation in the I/O layer is only
             * routed through the FTL ring so the poller completes it with its
             * carried error status. It must not run any opcode handler: req->slba
             * and req->nlb may be stale (the I/O layer returns before setting
             * them) and ssd_read/ssd_write would then touch unrelated mapping
             * state and overwrite the error. Leave latency at zero and let the
             * poller post the carried status.
             */
            if (req->status == NVME_SUCCESS) {
                switch (req->cmd.opcode) {
                case NVME_CMD_WRITE:
                    if (ssd->fdp_enabled) {
                        lat = nvme_do_write_fdp(n, req, req->slba, req->nlb);
                    } else {
                        lat = ssd_write(ssd, req);
                    }
                    break;
                case NVME_CMD_READ:
                    lat = ssd_read(ssd, req);
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
            }

            req->reqlat = lat;
            req->expire_time += lat;

            rc = femu_ring_enqueue(ssd->to_poller[i], (void *)&req, 1);
            if (rc != 1) {
                ftl_err("FTL to_poller enqueue failed\n");
            }

            /* background GC */
            if (ssd->fdp_enabled) {
                int16_t rgidx;
                /*
                 * Trigger a single GC pass on a reclaim group over threshold;
                 * the GC policy itself lives in do_gc_fdp_style(), not here.
                 */
                if (!((rgidx = should_gc_fdp_style(ssd)) < 0))
                {
                    //do_gc_fdp_style(ssd, rgidx, 0, false);
                    if (ssd->nrg == 1)
                        do_gc_fdp_style(ssd, 0, 0, false);
                    else
                    {
                        do_gc_fdp_style(ssd, rgidx, 0, false);
                    }
                }
            } else if (should_gc(ssd)) {
                do_gc(ssd, false);
            }
        }
    }

    return NULL;
}
