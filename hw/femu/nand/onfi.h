#ifndef __FEMU_NAND_ONFI_H
#define __FEMU_NAND_ONFI_H

/*
 * ONFI 6.0 bus timing profile.
 *
 * ONFI 6.0 defines one data interface, NV-LPDDR4, with timing modes 0 to 26
 * (Table 4-36) and the constant command and address times of Table 4-34. It
 * gives no array times (tR, tPROG, tBERS): those stay with the FEMU array
 * knobs. This file turns a timing mode and a page size into the bus phase
 * lengths of the NAND media layer. It needs no QEMU header beyond osdep.h,
 * so the unit tests build it standalone.
 */

#include <stdint.h>
#include <stdbool.h>

#define ONFI_NUM_MODES   27
#define ONFI_MAX_MTS     100000   /* onfi_mts limit, MT/s */

typedef struct OnfiInput {
    int      mode;         /* NV-LPDDR4 timing mode, 0 to 26 */
    int      mts;          /* 0, or the payload rate in MT/s */
    uint64_t page_bytes;   /* data plus spare bytes moved per page */
    uint32_t col_cycles;   /* column address cycles */
    uint32_t row_cycles;   /* row address cycles */
    bool     multi_lun;    /* several LUNs share the channel */
    uint64_t tccs_ns;      /* tCCS from a datasheet; 0 charges nothing */
} OnfiInput;

/* bus phase lengths in ns, each rounded up once */
typedef struct OnfiTiming {
    int64_t page_xfer_ns;
    int64_t rd_cmd_ns;
    int64_t wr_cmd_ns;
    int64_t din_burst_ns;
    int64_t wr_post_ns;
    int64_t er_cmd_ns;
    int64_t cb_rd_cmd_ns;
    int64_t cb_wr_cmd_ns;
    int64_t status_ns;
    int64_t dout_pre_ns;
    int64_t dout_post_ns;
    int64_t dout_mp_pre_ns;
    int64_t plbusy_ns;     /* Table 4-30 typical tPLRBSY/tPLPBSY/tPLEBSY */
} OnfiTiming;

/* tDSC of @mode in ps (Table 4-36), or -1 for a mode outside 0 to 26 */
int onfi_tdsc_ps(int mode);

/* fill @out from @in; returns 0, or -1 for a bad mode or rate */
int onfi_derive(const OnfiInput *in, OnfiTiming *out);

#endif /* __FEMU_NAND_ONFI_H */
