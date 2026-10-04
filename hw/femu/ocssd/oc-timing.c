#include "../nvme.h"
#include "./oc12.h"
#include "./oc20.h"
#include "./oc-timing.h"

/*
 * Both versions keep a LUN timeline array indexed by the flat LUN id --
 * channel * num_lun + lun -- and a per-channel array, all fixed-size, so the
 * product has to fit. Bounding each axis on its own lets a geometry that looks
 * legal write past the end of the array. The counts also divide the namespace
 * size when the geometry is built, so a zero is a division fault at realize.
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
