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
static int bb_check_capacity(FemuCtrl *n, NvmeNamespace *ns, Error **errp)
{
    BbCtrlParams *p = &n->bb_params;
    uint64_t page_bytes = (uint64_t)p->secs_per_pg * p->secsz;
    /* a line is one block on every plane of every LUN, as the FTL builds it */
    uint64_t pgs_per_line = (uint64_t)p->nchs * p->luns_per_ch *
                            p->pls_per_lun * p->pgs_per_blk;
    uint64_t tt_lines = (uint64_t)p->blks_per_pl;
    uint64_t reserve_lines, usable_pgs, exposed_pgs;

    /* the free lines GC insists on, plus one for the open write pointer */
    reserve_lines = (uint64_t)((1 - p->gc_thres_pcent_high / 100.0) * tt_lines);
    reserve_lines += 1;

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
static void bb_flip_apply(FemuCtrl *n, int64_t cdw10)
{
    int i;

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
static void bb_exit(FemuCtrl *n)
{
    int i;

    for (i = 0; i < n->num_namespaces; i++) {
        struct ssd *ssd = n->namespaces[i].ssd;

        if (ssd) {
            ssd_free_write_buffer(ssd);
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
        .init             = bb_init,
        .exit             = bb_exit,
        .rw_check_req     = NULL,
        .admin_cmd        = bb_admin_cmd,
        .io_cmd           = bb_io_cmd,
        .get_log          = NULL,
    };

    return 0;
}

