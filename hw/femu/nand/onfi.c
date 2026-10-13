/*
 * ONFI 6.0 bus timing profile: timing mode table and the derivation of the
 * NAND media bus phases. See onfi.h and hw/femu/docs/design/nand-timing.md.
 *
 * All sums run in ps and each phase is rounded up to whole ns once. Values
 * are the conventional (Conv.) protocol on an x8 DDR bus: one tDSC cycle
 * moves two bytes.
 */

#include "qemu/osdep.h"
#include "onfi.h"

/* tDSC(avg) per NV-LPDDR4 timing mode, ps (Table 4-36; tRC in Table 4-38) */
static const int32_t onfi_tdsc[ONFI_NUM_MODES] = {
    30000, 25000, 15000, 12000, 10000, 7500, 6000, 5000,   /* modes 0-7 */
    3750, 3000, 2500, 1875, 1667, 1500, 1364, 1250,        /* modes 8-15 */
    1111, 1000, 909, 833, 714, 625, 555, 500,              /* modes 16-23 */
    476, 455, 417,                                         /* modes 24-26 */
};

/* constant Conv. timing, ps (Table 4-34, Table 4-36, Table 4-38) */
enum {
    ONFI_TWC_PS    = 25000,    /* command or address cycle */
    ONFI_TWB_PS    = 100000,   /* last cycle to busy (max) */
    ONFI_TWHR_PS   = 80000,    /* command to status data out */
    ONFI_TADL_PS   = 412000,   /* address to first data in */
    ONFI_TRHW_PS   = 100000,   /* data out to next command */
    ONFI_TRPRE2_PS = 25000,    /* read preamble */
    ONFI_TRPSTH_PS = 15000,    /* read postamble hold */
    ONFI_TWPRE2_PS = 25000,    /* write preamble */
    ONFI_TWPST2_PS = 6500,     /* write postamble */
    ONFI_TWPSTH2_PS = 25000,   /* write postamble hold */
    ONFI_TPLBSY_PS = 500000,   /* multi-plane short busy, typical (Table 4-30) */
};

int onfi_tdsc_ps(int mode)
{
    if (mode < 0 || mode >= ONFI_NUM_MODES) {
        return -1;
    }
    return onfi_tdsc[mode];
}

static int64_t ps_to_ns(uint64_t ps)
{
    return (int64_t)((ps + 999) / 1000);
}

int onfi_derive(const OnfiInput *in, OnfiTiming *out)
{
    uint64_t c = ONFI_TWC_PS;
    uint64_t addr = in->col_cycles + in->row_cycles;
    uint64_t tccs = in->tccs_ns * 1000;
    uint64_t tdsc;
    uint64_t sel;
    int td = onfi_tdsc_ps(in->mode);

    if (td < 0 || in->mts < 0 || in->mts > ONFI_MAX_MTS) {
        return -1;
    }
    memset(out, 0, sizeof(*out));

    /*
     * An explicit rate sets the page payload only; the status byte, driven
     * for a whole tDSC cycle, keeps the mode's tDSC.
     */
    tdsc = td;
    if (in->mts) {
        out->page_xfer_ns = (int64_t)((in->page_bytes * 1000 + in->mts - 1) /
                                      in->mts);
    } else {
        out->page_xfer_ns = (int64_t)((in->page_bytes * td + 1999) / 2000);
    }

    /* 00h, address, 30h, then tWB before the device goes busy */
    out->rd_cmd_ns = ps_to_ns((2 + addr) * c + ONFI_TWB_PS);
    /* 80h, address, then tADL before the first data byte */
    out->wr_cmd_ns = ps_to_ns((1 + addr) * c + ONFI_TADL_PS);
    out->din_burst_ns = ps_to_ns(ONFI_TWPRE2_PS + ONFI_TWPST2_PS +
                                 ONFI_TWPSTH2_PS);
    /* 10h, then tWB */
    out->wr_post_ns = ps_to_ns(c + ONFI_TWB_PS);
    /* 60h, row address, D0h, then tWB */
    out->er_cmd_ns = ps_to_ns((2 + in->row_cycles) * c + ONFI_TWB_PS);
    /* copyback: 00h, address, 35h and 85h, address, 10h, each then tWB */
    out->cb_rd_cmd_ns = ps_to_ns((2 + addr) * c + ONFI_TWB_PS);
    out->cb_wr_cmd_ns = ps_to_ns((2 + addr) * c + ONFI_TWB_PS);

    /*
     * Status: 70h, or 78h with a row address when several LUNs share the
     * channel (Section 3.1.3), then tWHR, the preamble, one byte, the
     * postamble hold and tRHW before the next command.
     */
    sel = in->multi_lun ? 1 + in->row_cycles : 1;
    out->status_ns = ps_to_ns(sel * c + ONFI_TWHR_PS + ONFI_TRPRE2_PS + tdsc +
                              ONFI_TRPSTH_PS + ONFI_TRHW_PS);

    /*
     * Data out: 00h back to the data with one LUN; Change Read Column
     * Enhanced (06h, address, E0h) and tCCS with several LUNs, and for each
     * plane of a multi-plane read (Section 9.6). Then the preamble.
     */
    out->dout_pre_ns = in->multi_lun ?
                       ps_to_ns((2 + addr) * c + tccs + ONFI_TRPRE2_PS) :
                       ps_to_ns(c + ONFI_TRPRE2_PS);
    out->dout_mp_pre_ns = ps_to_ns((2 + addr) * c + tccs + ONFI_TRPRE2_PS);
    out->dout_post_ns = ps_to_ns(ONFI_TRPSTH_PS + ONFI_TRHW_PS);
    out->plbusy_ns = ps_to_ns(ONFI_TPLBSY_PS);
    return 0;
}
