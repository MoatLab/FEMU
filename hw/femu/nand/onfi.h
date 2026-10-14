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
#include <stddef.h>

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

/*
 * Parameter page (Section 6.7.1, Table 6-4). One copy is 256 bytes; a
 * device stores at least three. Multi-byte fields are little endian.
 */
#define ONFI_PARAM_PAGE_BYTES  256

/* bytes 4-5: revision */
#define ONFI_REV_6_0           (1u << 15)
/* bytes 6-7: features supported */
#define ONFI_FEAT_X16          (1u << 0)
#define ONFI_FEAT_MULTI_LUN    (1u << 1)
#define ONFI_FEAT_MP_PROG_ERASE (1u << 3)
#define ONFI_FEAT_ODD_EVEN_CB  (1u << 4)
#define ONFI_FEAT_MP_READ      (1u << 6)
#define ONFI_FEAT_PR_CLEAR     (1u << 8)
#define ONFI_FEAT_NV_LPDDR4    (1u << 9)
/* bytes 8-9: optional commands supported */
#define ONFI_OPT_READ_CACHE    (1u << 1)
#define ONFI_OPT_STATUS_ENH    (1u << 3)
#define ONFI_OPT_COPYBACK      (1u << 4)
#define ONFI_OPT_COLUMN_ENH    (1u << 6)
/* byte 114: multi-plane operation attributes */
#define ONFI_MP_OVERLAPPED     (1u << 0)

/* the fields of a good parameter page copy that FEMU reads */
typedef struct OnfiParamPage {
    uint16_t revision;        /* bytes 4-5 */
    uint16_t features;        /* bytes 6-7 */
    uint16_t opt_cmds;        /* bytes 8-9 */
    uint32_t data_bytes;      /* bytes 80-83, per page */
    uint16_t spare_bytes;     /* bytes 84-85, per page */
    uint32_t pages_per_block; /* bytes 92-95 */
    uint32_t blocks_per_lun;  /* bytes 96-99 */
    uint8_t  luns;            /* byte 100, LUNs per target */
    uint8_t  col_cycles;      /* byte 101 bits 4-7 */
    uint8_t  row_cycles;      /* byte 101 bits 0-3 */
    uint8_t  bits_per_entry;  /* byte 102; 0xff = not given */
    uint8_t  plane_bits;      /* byte 113 bits 0-3 */
    uint8_t  mp_attr;         /* byte 114 */
    uint32_t modes;           /* bytes 118-121, bits 0 to 23 */
    int      copy;            /* the copy that was good: 0, 1, 2, ... */
} OnfiParamPage;

/* CRC-16 of Section 6.7.1.42: polynomial 8005h, initial value 4F4Eh */
uint16_t onfi_crc16(const uint8_t *buf, size_t len);

/*
 * Find the first good copy in @buf (@len bytes) and fill @out. Returns 0,
 * or -1 with *@why naming the reason.
 */
int onfi_param_parse(const uint8_t *buf, size_t len, OnfiParamPage *out,
                     const char **why);

/* the highest NV-LPDDR4 mode the page lists, or -1 for none */
int onfi_param_max_mode(const OnfiParamPage *p);

/* true when the page lists NV-LPDDR4 mode @mode */
bool onfi_param_has_mode(const OnfiParamPage *p, int mode);

/* the FEMU settings a parameter page must agree with */
typedef struct OnfiGeometry {
    uint64_t data_bytes;       /* secsz * secs_per_pg */
    uint64_t spare_bytes;      /* onfi_spare_bytes, 0 = take the page's */
    uint32_t pages_per_block;
    uint32_t blocks_per_lun;   /* blocks per plane * planes per LUN */
    uint32_t luns_per_ch;
    uint32_t planes_per_lun;
    uint32_t bits_per_entry;   /* 1 to 4, or 0 to skip the check */
    int      mode;             /* the user mode, or -1 */
    bool     mp_program;
    bool     mp_read;
    bool     copyback;
} OnfiGeometry;

/*
 * Check @p against @g. Returns 0, or -1 with a message in @msg (@len
 * bytes) that names the field and both values.
 */
int onfi_param_check(const OnfiParamPage *p, const OnfiGeometry *g,
                     char *msg, size_t len);

#endif /* __FEMU_NAND_ONFI_H */
