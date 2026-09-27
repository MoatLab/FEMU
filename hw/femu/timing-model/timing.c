#include "../nvme.h"

/*
 * The per-chip arrays this model locks and stamps are fixed-size members of the
 * controller, indexed by the flat LUN id -- channel * num_lun + lun -- so it is
 * the product that has to fit. Bounding each axis on its own lets a geometry
 * that looks legal stamp past the end of the array and into the rest of the
 * controller. The counts also divide the namespace size when the geometry is
 * built, so a zero is a division fault at realize rather than a wrong answer.
 */
bool oc_timing_geometry_ok(FemuCtrl *n, Error **errp)
{
    unsigned ch = n->oc_params.num_ch;
    unsigned lun = n->oc_params.num_lun;

    if (!ch || !lun || !n->oc_params.num_pln || !n->oc_params.secs_per_pg ||
        !n->oc_params.pgs_per_blk || !n->oc_params.sec_size) {
        error_setg(errp, "FEMU ocssd: lnum_ch, lnum_lun, lnum_pln, "
                   "lsecs_per_pg, lpgs_per_blk and lsec_size must all be "
                   "greater than zero");
        return false;
    }

    if (ch > FEMU_MAX_NUM_CHNLS || ch * lun > FEMU_MAX_NUM_CHIPS) {
        error_setg(errp, "FEMU ocssd: lnum_ch must not exceed %d and "
                   "lnum_ch * lnum_lun must not exceed %d, got %u and %u",
                   FEMU_MAX_NUM_CHNLS, FEMU_MAX_NUM_CHIPS, ch, lun);
        return false;
    }

    return true;
}

void set_latency(FemuCtrl *n)
{
    if (n->flash_type == TLC) {
        n->upg_rd_lat_ns = TLC_UPPER_PAGE_READ_LATENCY_NS;
        n->cpg_rd_lat_ns = TLC_CENTER_PAGE_READ_LATENCY_NS;
        n->lpg_rd_lat_ns = TLC_LOWER_PAGE_READ_LATENCY_NS;
        n->upg_wr_lat_ns = TLC_UPPER_PAGE_WRITE_LATENCY_NS;
        n->cpg_wr_lat_ns = TLC_CENTER_PAGE_WRITE_LATENCY_NS;
        n->lpg_wr_lat_ns = TLC_LOWER_PAGE_WRITE_LATENCY_NS;
        n->blk_er_lat_ns = TLC_BLOCK_ERASE_LATENCY_NS;
        n->chnl_pg_xfer_lat_ns = TLC_CHNL_PAGE_TRANSFER_LATENCY_NS;
    } else if (n->flash_type == QLC) {
        n->upg_rd_lat_ns  = QLC_UPPER_PAGE_READ_LATENCY_NS;
        n->cupg_rd_lat_ns = QLC_CENTER_UPPER_PAGE_READ_LATENCY_NS;
        n->clpg_rd_lat_ns = QLC_CENTER_LOWER_PAGE_READ_LATENCY_NS;
        n->lpg_rd_lat_ns  = QLC_LOWER_PAGE_READ_LATENCY_NS;
        n->upg_wr_lat_ns  = QLC_UPPER_PAGE_WRITE_LATENCY_NS;
        n->cupg_wr_lat_ns = QLC_CENTER_UPPER_PAGE_WRITE_LATENCY_NS;
        n->clpg_wr_lat_ns = QLC_CENTER_LOWER_PAGE_WRITE_LATENCY_NS;
        n->lpg_wr_lat_ns  = QLC_LOWER_PAGE_WRITE_LATENCY_NS;
        n->blk_er_lat_ns  = QLC_BLOCK_ERASE_LATENCY_NS;
        n->chnl_pg_xfer_lat_ns = QLC_CHNL_PAGE_TRANSFER_LATENCY_NS;
    } else if (n->flash_type == MLC) {
        n->upg_rd_lat_ns = MLC_UPPER_PAGE_READ_LATENCY_NS;
        n->lpg_rd_lat_ns = MLC_LOWER_PAGE_READ_LATENCY_NS;
        n->upg_wr_lat_ns = MLC_UPPER_PAGE_WRITE_LATENCY_NS;
        n->lpg_wr_lat_ns = MLC_LOWER_PAGE_WRITE_LATENCY_NS;
        n->blk_er_lat_ns = MLC_BLOCK_ERASE_LATENCY_NS;
        n->chnl_pg_xfer_lat_ns = MLC_CHNL_PAGE_TRANSFER_LATENCY_NS;
    }
}

typedef struct OcChannelReservation {
    uint64_t start;
    uint64_t end;
} OcChannelReservation;

/* Fit transfers around future reads, as in the NAND media channel model. */
static int64_t reserve_channel(FemuCtrl *n, int ch, uint64_t now,
                               uint64_t earliest, uint64_t transfer_ns,
                               bool future)
{
    GArray *reservations;
    OcChannelReservation reservation;
    uint64_t start;
    unsigned i;

    if (!transfer_ns) {
        return earliest;
    }

    pthread_spin_lock(&n->chnl_locks[ch]);
    reservations = n->chnl_reservations[ch];
    if (!reservations) {
        reservations = g_array_new(false, false, sizeof(reservation));
        n->chnl_reservations[ch] = reservations;
    }

    /* Prune at submission time, never at a read's future array completion. */
    for (i = 0; i < reservations->len; i++) {
        if (g_array_index(reservations, OcChannelReservation, i).end > now) {
            break;
        }
    }
    g_array_remove_range(reservations, 0, i);
    start = MAX(earliest, n->chnl_next_avail_time[ch]);
    for (i = 0; i < reservations->len; i++) {
        OcChannelReservation *r = &g_array_index(reservations,
                                                OcChannelReservation, i);

        if (r->end <= start) {
            continue;
        }
        if (r->start >= start + transfer_ns) {
            break;
        }
        start = r->end;
    }
    reservation.start = start;
    reservation.end = start + transfer_ns;
    if (future) {
        /* Growing the list preserves gaps even with many reads outstanding. */
        g_array_insert_val(reservations, i, reservation);
    } else {
        n->chnl_next_avail_time[ch] = reservation.end;
    }
    pthread_spin_unlock(&n->chnl_locks[ch]);

    return reservation.end;
}

int64_t advance_channel_timestamp(FemuCtrl *n, int ch, uint64_t now,
                                  uint64_t transfer_ns)
{
    return reserve_channel(n, ch, now, now, transfer_ns, false);
}

int64_t advance_read_channel_timestamp(FemuCtrl *n, int ch, uint64_t now,
                                       uint64_t earliest, uint64_t transfer_ns)
{
    return reserve_channel(n, ch, now, earliest, transfer_ns, true);
}

int64_t advance_chip_timestamp(FemuCtrl *n, int lunid, uint64_t now, int opcode,
                               uint8_t page_type)
{
    int64_t lat;
    int64_t io_done_ts;

    switch (opcode) {
    case NVME_CMD_OC_READ:
    case NVME_CMD_READ:
        lat = get_page_read_latency(n->flash_type, page_type);
        break;
    case NVME_CMD_OC_WRITE:
    case NVME_CMD_WRITE:
        lat = get_page_write_latency(n->flash_type, page_type);
        break;
    case NVME_CMD_OC_ERASE:
        lat = get_blk_erase_latency(n->flash_type);
        break;
    default:
        assert(0);
    }

    pthread_spin_lock(&n->chip_locks[lunid]);
    if (now < n->chip_next_avail_time[lunid]) {
        n->chip_next_avail_time[lunid] += lat;
    } else {
        n->chip_next_avail_time[lunid] = now + lat;
    }
    io_done_ts = n->chip_next_avail_time[lunid];
    pthread_spin_unlock(&n->chip_locks[lunid]);

    return io_done_ts;
}

