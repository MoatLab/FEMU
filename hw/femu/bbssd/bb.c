#include "../nvme.h"
#include "./ftl.h"

static void bb_init_ctrl_str(FemuCtrl *n)
{
    static int fsid_vbb = 0;
    const char *vbbssd_mn = "FEMU BlackBox-SSD Controller";
    const char *vbbssd_sn = "vSSD";

    nvme_set_ctrl_name(n, vbbssd_mn, vbbssd_sn, &fsid_vbb);
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
    uint64_t tt_lines = (uint64_t)p->blks_per_pl;
    uint64_t reserve_lines, usable_pgs, exposed_pgs;

    /*
     * The free lines GC insists on, plus one for every write pointer this
     * configuration can hold open at once. Counting only the data pointer
     * leaves a device that hot/cold separation or a log-block scheme can run
     * out of lines on, which used to be fatal and is now a refused write.
     */
    reserve_lines = (uint64_t)((1 - p->gc_thres_pcent_high / 100.0) * tt_lines);
    reserve_lines += 1;                      /* the data write pointer */
    if (p->hot_cold_sep) {
        reserve_lines += 1;                  /* the hot write pointer */
    }
    if (femu_mapping_name_uses_log_class(p->mapping_scheme)) {
        reserve_lines += 1;                  /* the log write pointer */
    }

    if (tt_lines <= reserve_lines) {
        error_setg(errp, "FEMU bbssd: the geometry has only %" PRIu64 " lines, "
                   "fewer than the %" PRIu64 " garbage collection needs free",
                   tt_lines, reserve_lines);
        return -1;
    }

    usable_pgs = (tt_lines - reserve_lines) * pgs_per_line;
    exposed_pgs = ns->size / page_bytes;

    if (exposed_pgs > usable_pgs) {
        error_setg(errp, "FEMU bbssd: namespace %u exposes %" PRIu64 " MiB of "
                   "the %" PRIu64 " MiB this geometry has, leaving garbage "
                   "collection no room; expose at most %" PRIu64 " MiB per "
                   "namespace (lower devsz_mb, or set op_pcent)",
                   ns->id, ns->size >> 20,
                   (tt_lines * pgs_per_line * page_bytes) >> 20,
                   (usable_pgs * page_bytes) >> 20);
        return -1;
    }

    return 0;
}

/* bb <=> black-box */
static void bb_init(FemuCtrl *n, NvmeNamespace *ns, Error **errp)
{
    struct ssd *ssd;

    if (bb_check_geometry(n, errp)) {
        return;
    }

    if (bb_check_capacity(n, ns, errp)) {
        return;
    }

    /*
     * FDP keeps its own write and reclaim path, which none of these knobs
     * reach; refuse them rather than accept them silently.
     */
    if (n->subsys && n->subsys->endgrp.fdp.enabled) {
        const BbCtrlParams *p = &n->bb_params;
        const char *knob = NULL;

        if (p->buffer_size) {
            knob = "buffer_size";
        } else if (p->hot_cold_sep) {
            knob = "hot_cold_sep";
        } else if (p->read_reclaim_limit) {
            knob = "read_reclaim_limit";
        } else if (p->retention_limit_sec) {
            knob = "retention_limit_sec";
        } else if (p->ecc_retention_sec) {
            knob = "ecc_retention_sec";
        } else if (p->trim_lat_ns) {
            knob = "trim_lat_ns";
        } else if (p->mapping_scheme && strcmp(p->mapping_scheme, "page")) {
            knob = "mapping";
        } else if (p->gc_policy && strcmp(p->gc_policy, "greedy")) {
            knob = "gc_policy";
        }
        if (knob) {
            error_setg(errp, "FEMU bbssd: %s has no effect under FDP", knob);
            return;
        }
    }

    ssd = ns->ssd = g_malloc0(sizeof(struct ssd));

    bb_init_ctrl_str(n);

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
static void bb_flush_stats(FemuCtrl *n);

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

    for (i = 0; i < n->num_namespaces; i++) {
        struct ssd *ssd = n->namespaces[i].ssd;

        if (!ssd) {
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
    case FEMU_RESET_QLC: {
        /*
         * Zero the physical-read meters so what follows is attributable to the
         * workload alone. Stored data, the mapping table and the page layout are
         * untouched. qlc_first_read_ns goes too, so elapsed time restarts at the
         * next counted read rather than at one from the fill.
         */
        uint64_t before = 0;
        for (int i = 0; i < n->num_namespaces; i++) {
            struct ssd *ssd = n->namespaces[i].ssd;
            if (!ssd) {
                continue;
            }
            for (int c = 0; c < 4; c++) {
                before += __atomic_load_n(&ssd->qlc_read_pages[c], __ATOMIC_RELAXED);
                __atomic_store_n(&ssd->qlc_read_pages[c], 0, __ATOMIC_RELAXED);
                __atomic_store_n(&ssd->qlc_read_bytes[c], 0, __ATOMIC_RELAXED);
                __atomic_store_n(&ssd->qlc_read_active_ns[c], 0, __ATOMIC_RELAXED);
            }
            __atomic_store_n(&ssd->qlc_first_read_ns, 0, __ATOMIC_RELAXED);
        }
        /* Logged, not discarded: the pre-workload total is itself a measurement
         * of what boot and fill cost, and it is the only record of it. */
        femu_log("%s,QLC counters reset, discarded %" PRIu64 " pages\n",
                 n->devname, before);
        break;
    }
    case FEMU_SNAP_QLC:
        bb_flush_stats(n);
        femu_log("%s,QLC counters snapshotted\n", n->devname);
        break;
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

/* Snapshot physical QLC activity without freeing state; process-exit notifiers
 * use this path because PCI device teardown is not guaranteed at VM shutdown. */
static void bb_flush_stats(FemuCtrl *n)
{
    uint64_t pages[4] = {0};
    uint64_t bytes[4] = {0};
    uint64_t active_ns[4] = {0};
    uint64_t first_ns = 0;
    uint64_t wall_ns = 0;
    int n_luns = 0;
    const char *stats_path = getenv("FEMU_QLC_STATS_PATH");
    FILE *stats = NULL;
    uint64_t t;
    int i;

    for (i = 0; i < n->num_namespaces; i++) {
        struct ssd *ssd = n->namespaces[i].ssd;

        if (ssd) {
            int page_class;

            for (page_class = 0; page_class < 4; page_class++) {
                pages[page_class] += __atomic_load_n(
                    &ssd->qlc_read_pages[page_class], __ATOMIC_RELAXED);
                bytes[page_class] += __atomic_load_n(
                    &ssd->qlc_read_bytes[page_class], __ATOMIC_RELAXED);
                active_ns[page_class] += __atomic_load_n(
                    &ssd->qlc_read_active_ns[page_class], __ATOMIC_RELAXED);
            }

            if (!n_luns) {
                n_luns = ssd->sp.nchs * ssd->sp.luns_per_ch * ssd->sp.pls_per_lun;
            }

            t = __atomic_load_n(&ssd->qlc_first_read_ns, __ATOMIC_RELAXED);
            if (t && (!first_ns || t < first_ns)) {
                first_ns = t;
            }
        }
    }

    /*
     * Elapsed time since the first counted read. Sum(t_active) is per-LUN service
     * time added up, so it runs ahead of this by roughly the LUN parallelism; the
     * controller is a single resource and has to be charged against elapsed time.
     */
    if (first_ns) {
        uint64_t now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);

        wall_ns = now > first_ns ? now - first_ns : 0;
    }

    if (stats_path && stats_path[0]) {
        stats = fopen(stats_path, "w");
        if (!stats) {
            femu_log("QLC stats: cannot open %s: %s\n",
                     stats_path, strerror(errno));
        }
    }

    /*
     * Energy columns are Sum(count x cited coefficient), the same arithmetic the
     * offline accounting does; the coefficients used are written into the file so
     * the columns stay auditable. Coefficients are milli-pJ/bit, byte counts are
     * exact, so uJ = bytes * 8 * mpj / 1e9. Sweeps (channel, controller, idle,
     * scenario codes) stay offline in experiments/energy_account.py.
     */
    if (stats) {
        double e_nand_uj[4], e_xfer_uj[4], e_array_uj[4], e_periph_uj[4];
        double nand_total = 0, xfer_total = 0;
        double array_total = 0, periph_total = 0;

        for (i = 0; i < 4; i++) {
            double bits = (double)bytes[i] * 8.0;
            /*
             * Peripheral is the remainder rather than its own coefficient, so
             * the two halves always add back to the total the offline
             * accounting uses. An array share above the total would make it
             * negative, which is a misconfiguration, not a measurement.
             */
            uint32_t array_mpj = n->e_array_mpj[i] <= n->e_read_mpj[i]
                               ? n->e_array_mpj[i] : n->e_read_mpj[i];

            e_nand_uj[i] = bits * n->e_read_mpj[i] / 1e9;
            e_array_uj[i] = bits * array_mpj / 1e9;
            e_periph_uj[i] = e_nand_uj[i] - e_array_uj[i];
            e_xfer_uj[i] = bits * n->e_xfer_mpj / 1e9;
            nand_total += e_nand_uj[i];
            array_total += e_array_uj[i];
            periph_total += e_periph_uj[i];
            xfer_total += e_xfer_uj[i];

            if (n->e_array_mpj[i] > n->e_read_mpj[i]) {
                femu_log("QLC energy: class %d array coefficient %u exceeds the "
                         "read total %u; clamped\n",
                         i, n->e_array_mpj[i], n->e_read_mpj[i]);
            }
        }

        fprintf(stats, "# coeff_mpj_per_bit: c0=%u c1=%u c2=%u c3=%u xfer=%u\n",
                n->e_read_mpj[0], n->e_read_mpj[1], n->e_read_mpj[2],
                n->e_read_mpj[3], n->e_xfer_mpj);
        fprintf(stats, "# array_mpj_per_bit: c0=%u c1=%u c2=%u c3=%u  "
                "(peripheral is the remainder of each read coefficient)\n",
                n->e_array_mpj[0], n->e_array_mpj[1], n->e_array_mpj[2],
                n->e_array_mpj[3]);
        fprintf(stats, "# nand_cell_type=%u  e_nand_uj_total=%.3f  "
                "e_periph_uj_total=%.3f  e_array_uj_total=%.3f  "
                "e_xfer_uj_total=%.3f\n",
                n->nand_cell_type, nand_total, periph_total, array_total,
                xfer_total);
        fprintf(stats, "# t_wall_us=%.3f  t_active_sum_us=%.3f  luns=%d\n",
                wall_ns / 1000.0,
                (active_ns[0] + active_ns[1] + active_ns[2] + active_ns[3])
                / 1000.0, n_luns);
        fprintf(stats, "# t_wall is elapsed since the first counted read (the "
                "observation window). t_active_sum is per-LUN service time "
                "added up, so device busy time is about t_active_sum/luns; the "
                "controller belongs on that, not on either raw number.\n");
        fprintf(stats, "page_class,n_read,bytes_read,t_active_us,"
                "e_nand_uj,e_periph_uj,e_array_uj,e_xfer_uj\n");
        for (i = 0; i < 4; i++) {
            fprintf(stats, "%d,%" PRIu64 ",%" PRIu64 ",%.3f,%.3f,%.3f,%.3f,%.3f\n",
                    i, pages[i], bytes[i], active_ns[i] / 1000.0,
                    e_nand_uj[i], e_periph_uj[i], e_array_uj[i], e_xfer_uj[i]);
        }
        fclose(stats);
    } else {
        for (i = 0; i < 4; i++) {
            femu_log("QLC_READ_STATS,class=%d,reads=%" PRIu64
                     ",bytes=%" PRIu64 ",active_ns=%" PRIu64
                     ",e_nand_uj=%.3f\n",
                     i, pages[i], bytes[i], active_ns[i],
                     (double)bytes[i] * 8.0 * n->e_read_mpj[i] / 1e9);
        }
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
static void bb_exit(FemuCtrl *n)
{
    int i;

    bb_flush_stats(n);
    for (i = 0; i < n->num_namespaces; i++) {
        NvmeNamespace *ns = &n->namespaces[i];

        if (!NS_BBSSD(ns) || !ns->ssd) {
            continue;
        }
        if (n->ssd == ns->ssd) {
            n->ssd = NULL;
        }
        ssd_free(ns->ssd);
        g_free(ns->ssd);
        ns->ssd = NULL;
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
        .init             = bb_init,
        .exit             = bb_exit,
        .stats_flush      = bb_flush_stats,
        .rw_check_req     = NULL,
        .admin_cmd        = bb_admin_cmd,
        .io_cmd           = bb_io_cmd,
        .get_log          = NULL,
    };

    return 0;
}
