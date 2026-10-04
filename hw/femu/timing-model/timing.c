#include "../nvme.h"
#include "../ocssd/oc12.h"
#include "../ocssd/oc20.h"

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
    int ft = n->flash_type;

    init_nand_flash(n);
    for (int p = 0; p < MAX_FLASH_TYPE; p++) {
        n->oc_pg_rd_lat[p] = nand_flash_timing.pg_rd_lat[ft][p];
        n->oc_pg_wr_lat[p] = nand_flash_timing.pg_wr_lat[ft][p];
    }
    n->oc_blk_er_lat = nand_flash_timing.blk_er_lat[ft];
    n->oc_chnl_pg_xfer_lat = n->bb_params.ch_xfer_lat ?
                             n->bb_params.ch_xfer_lat :
                             nand_flash_timing.chnl_pg_xfer_lat[ft];
}

/*
 * Vendor admin command 0xEE: set this controller's NAND times at run time.
 * A cell holds flash_type bits, so its lowest page type is the lower page and
 * page type flash_type - 1 the upper one; the centre pages of TLC and QLC keep
 * their times. SLC has a single page type, which takes the lower page times.
 */
void oc_set_latency(FemuCtrl *n, uint32_t rd_upper, uint32_t rd_lower,
                    uint32_t wr_upper, uint32_t wr_lower, uint32_t erase,
                    uint32_t xfer)
{
    int upper = n->flash_type - 1;
    /* the pollers read these per command; keep a command from mixing them */
    bool resume = nvme_pause_pollers(n);

    n->oc_pg_rd_lat[upper] = rd_upper;
    n->oc_pg_wr_lat[upper] = wr_upper;
    n->oc_pg_rd_lat[0] = rd_lower;
    n->oc_pg_wr_lat[0] = wr_lower;
    n->oc_blk_er_lat = erase;
    n->oc_chnl_pg_xfer_lat = xfer;
    if (n->lver == OCSSD12) {
        oc12_refresh_timing(n);
    } else if (n->lver == OCSSD20) {
        oc20_refresh_timing(n);
    }
    nvme_resume_pollers(n, resume);
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
        lat = n->oc_pg_rd_lat[page_type];
        break;
    case NVME_CMD_OC_WRITE:
    case NVME_CMD_WRITE:
        lat = n->oc_pg_wr_lat[page_type];
        break;
    case NVME_CMD_OC_ERASE:
        lat = n->oc_blk_er_lat;
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

