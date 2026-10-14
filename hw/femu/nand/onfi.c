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
    ONFI_TRCBSY_PS = 3000000,  /* read cache busy, typical (Table 4-30) */
};

/* SCA protocol timing, ps (Table 5-9; Section 5.7) */
enum {
    SCA_TCACI_PS    = 4000,    /* CA_CLK input cycle */
    SCA_PACKET_PS   = 3 * SCA_TCACI_PS, /* 4-bit header + 8-bit body, DDR x2 */
    SCA_HEADER_PS   = SCA_TCACI_PS,     /* a CA output header: 4 bits */
    SCA_TCDL_PS     = 400000,  /* 12h to the end of the write preamble */
    SCA_TCACO_PS    = 10000,   /* CA_CLK output cycle */
    SCA_TW2R_PS     = 20000,   /* output header to the first output clock */
    SCA_TR2W_PS     = (30000 + SCA_TCACO_PS / 2) + 30000 + 20000,
                               /* tCACOPST + tCEH2 + tCELCLK */
    SCA_TSCR_PS     = 50000,   /* SCE to RE_n low */
    SCA_TRPRE2_PS   = 30000,   /* read preamble with SCA */
    SCA_TDQSRE_PS   = 25000,   /* RE_n to DQS, maximum (Table 5-9) */
    SCA_TSCD_PS     = 50000,   /* SCE to DQS low */
    SCA_TWPRE2_PS   = 25000,   /* write preamble */
    SCA_THOLD_PS    = 50000,   /* tRPSTH_CA, tWPSTH_CA: hold after SCT */
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

/*
 * SCA (Section 5): commands, addresses and status move to the CA bus, so
 * these fields are CA lengths. A data burst owns the DQ bus from its SCE
 * packet to the hold after its SCT packet (Sections 5.9.4, 5.9.5):
 *
 *   read   SCE, tSCR, tRPRE2, page, tRPST_CA - P, SCT, tRPSTH_CA
 *   write  SCE, tSCD, tWPRE2, page, SCT, tWPSTH_CA
 *
 * tRPST_CA is tDQSRE (its maximum) plus half a tRC. tCDL runs from the
 * 12h packet to the end of the write preamble (Table 5-9 note 1).
 */
static void onfi_derive_sca(const OnfiInput *in, uint64_t tdsc,
                            OnfiTiming *out)
{
    uint64_t p = SCA_PACKET_PS;
    uint64_t addr = in->col_cycles + in->row_cycles;
    uint64_t sel = in->multi_lun ? 1 + in->row_cycles : 1;
    uint64_t wlead = p + SCA_TSCD_PS + SCA_TWPRE2_PS;
    uint64_t tail = p + SCA_THOLD_PS;
    uint64_t rpst = SCA_TDQSRE_PS + (tdsc + 1) / 2;

    out->rd_cmd_ns = ps_to_ns((2 + addr) * p + ONFI_TWB_PS);
    /* 80h, address, 12h; the data waits tCDL */
    out->wr_cmd_ns = ps_to_ns((2 + addr) * p);
    out->din_gap_ns = ps_to_ns(SCA_TCDL_PS - wlead);
    out->din_burst_ns = ps_to_ns(wlead + tail);
    /* 10h, then tWB */
    out->wr_post_ns = ps_to_ns(p + ONFI_TWB_PS);
    out->er_cmd_ns = ps_to_ns((2 + in->row_cycles) * p + ONFI_TWB_PS);
    out->cb_rd_cmd_ns = ps_to_ns((2 + addr) * p + ONFI_TWB_PS);
    /* 85h, address, 12h, 10h */
    out->cb_wr_cmd_ns = ps_to_ns((3 + addr) * p + ONFI_TWB_PS);
    /*
     * 70h or 78h with a row address, tWHR, the CA output header, tW2R_CA,
     * one byte on CA[1] at two bits per tCACO, then CA_CE# high and
     * tR2W_CA before the next header (Section 5.7.2).
     */
    out->status_ns = ps_to_ns(sel * p + ONFI_TWHR_PS + SCA_HEADER_PS +
                              SCA_TW2R_PS + 4 * SCA_TCACO_PS + SCA_TR2W_PS);
    /* Change Read Column Enhanced, with one LUN too (Section 5.9.6) */
    out->dout_pre_ns = ps_to_ns((2 + addr) * p);
    out->dout_mp_pre_ns = out->dout_pre_ns;
    out->ccs_ns = (int64_t)in->tccs_ns;
    out->dout_post_ns = 0;
    out->dout_edge_ns = ps_to_ns(p + SCA_TSCR_PS + SCA_TRPRE2_PS + rpst +
                                 SCA_THOLD_PS);
    out->sca_packet_ns = ps_to_ns(p);
    out->sca_tail_ns = ps_to_ns(tail);
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
    out->rc_step_ns = ps_to_ns(c + ONFI_TWB_PS);
    if (in->sca) {
        onfi_derive_sca(in, tdsc, out);
        out->rc_step_ns = ps_to_ns(SCA_PACKET_PS + ONFI_TWB_PS);
    }
    /* 78h selects the LUN before 31h or 3Fh with several LUNs (6.15) */
    out->rc_sel_ns = in->multi_lun ? out->status_ns : 0;
    out->trcbsy_ns = ps_to_ns(ONFI_TRCBSY_PS);
    return 0;
}

/* MSB first, no reflection, no final XOR (Section 6.7.1.42) */
uint16_t onfi_crc16(const uint8_t *buf, size_t len)
{
    uint16_t crc = 0x4f4e;

    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)buf[i] << 8;
        for (int b = 0; b < 8; b++) {
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x8005) :
                                   (uint16_t)(crc << 1);
        }
    }
    return crc;
}

static uint32_t le16(const uint8_t *p)
{
    return p[0] | (uint32_t)p[1] << 8;
}

static uint32_t le32(const uint8_t *p)
{
    return le16(p) | le16(p + 2) << 16;
}

/* a copy is present when two or more signature bytes match (6.7.1.1) */
static bool onfi_param_present(const uint8_t *p)
{
    static const uint8_t sig[4] = { 0x4f, 0x4e, 0x46, 0x49 };
    int match = 0;

    for (int i = 0; i < 4; i++) {
        match += p[i] == sig[i];
    }
    return match >= 2;
}

int onfi_param_parse(const uint8_t *buf, size_t len, OnfiParamPage *out,
                     const char **why)
{
    bool present = false;
    size_t off;

    *why = "the file is shorter than one 256-byte copy";
    /* copy 0, then the redundant copies of Sections 6.7.1.43 to 6.7.1.45 */
    for (off = 0; off + ONFI_PARAM_PAGE_BYTES <= len;
         off += ONFI_PARAM_PAGE_BYTES) {
        const uint8_t *p = buf + off;

        if (!onfi_param_present(p)) {
            if (!present) {
                *why = "no copy has the ONFI signature";
            }
            continue;
        }
        present = true;
        *why = "no copy with the ONFI signature has a good CRC";
        if (onfi_crc16(p, 254) != le16(p + 254)) {
            continue;
        }
        memset(out, 0, sizeof(*out));
        out->revision = le16(p + 4);
        out->features = le16(p + 6);
        out->opt_cmds = le16(p + 8);
        out->data_bytes = le32(p + 80);
        out->spare_bytes = le16(p + 84);
        out->pages_per_block = le32(p + 92);
        out->blocks_per_lun = le32(p + 96);
        out->luns = p[100];
        out->col_cycles = p[101] >> 4;
        out->row_cycles = p[101] & 0xf;
        out->bits_per_entry = p[102];
        out->plane_bits = p[113] & 0xf;
        out->mp_attr = p[114];
        out->modes = le32(p + 118) & 0xffffff;
        out->copy = (int)(off / ONFI_PARAM_PAGE_BYTES);
        *why = NULL;
        return 0;
    }
    return -1;
}

/* bit 0 covers modes 0 to 3; bit k covers mode k + 3 (6.7.1.30) */
int onfi_param_max_mode(const OnfiParamPage *p)
{
    for (int k = 23; k >= 0; k--) {
        if (p->modes & (1u << k)) {
            return k ? k + 3 : 3;
        }
    }
    return -1;
}

bool onfi_param_has_mode(const OnfiParamPage *p, int mode)
{
    if (mode < 0 || mode >= ONFI_NUM_MODES) {
        return false;
    }
    return p->modes & (1u << (mode <= 3 ? 0 : mode - 3));
}

/* address bits for @n values: ceil(log2(n)), 0 for one value */
static uint32_t addr_bits(uint64_t n)
{
    uint32_t b = 0;

    while (b < 64 && (1ULL << b) < n) {
        b++;
    }
    return b;
}

#define ONFI_REFUSE(...) do {                   \
        snprintf(msg, len, __VA_ARGS__);        \
        return -1;                              \
    } while (0)

int onfi_param_check(const OnfiParamPage *p, const OnfiGeometry *g,
                     char *msg, size_t len)
{
    uint64_t spare = g->spare_bytes ? g->spare_bytes : p->spare_bytes;
    uint32_t row_bits;

    if (!(p->revision & ONFI_REV_6_0)) {
        ONFI_REFUSE("revision (bytes 4-5) 0x%04x does not list ONFI 6.0 "
                    "(bit 15)", p->revision);
    }
    if (!(p->features & ONFI_FEAT_NV_LPDDR4)) {
        ONFI_REFUSE("features (bytes 6-7) 0x%04x do not list NV-LPDDR4 "
                    "(bit 9)", p->features);
    }
    if (p->features & ONFI_FEAT_X16) {
        ONFI_REFUSE("features (bytes 6-7) 0x%04x list a 16-bit bus (bit 0); "
                    "NV-LPDDR4 is x8", p->features);
    }
    /* Sections 6.7.1.14 and 6.7.1.16 */
    if (p->data_bytes < 512 || (p->data_bytes & (p->data_bytes - 1))) {
        ONFI_REFUSE("data bytes per page (bytes 80-83) %u is not a power of "
                    "two of 512 or more", p->data_bytes);
    }
    if (!p->pages_per_block || p->pages_per_block % 32) {
        ONFI_REFUSE("pages per block (bytes 92-95) %u is not a multiple of 32",
                    p->pages_per_block);
    }
    if (p->data_bytes != g->data_bytes) {
        ONFI_REFUSE("data bytes per page (bytes 80-83) %u, FEMU %llu",
                    p->data_bytes, (unsigned long long)g->data_bytes);
    }
    if (g->spare_bytes && g->spare_bytes != p->spare_bytes) {
        ONFI_REFUSE("spare bytes per page (bytes 84-85) %u, onfi_spare_bytes "
                    "%llu", p->spare_bytes,
                    (unsigned long long)g->spare_bytes);
    }
    if (p->pages_per_block != g->pages_per_block) {
        ONFI_REFUSE("pages per block (bytes 92-95) %u, FEMU %u",
                    p->pages_per_block, g->pages_per_block);
    }
    if (p->blocks_per_lun != g->blocks_per_lun) {
        ONFI_REFUSE("blocks per LUN (bytes 96-99) %u, FEMU %u",
                    p->blocks_per_lun, g->blocks_per_lun);
    }
    if (!p->luns || g->luns_per_ch % p->luns) {
        ONFI_REFUSE("LUNs per target (byte 100) %u does not divide FEMU's %u "
                    "LUNs per channel", p->luns, g->luns_per_ch);
    }
    /*
     * With several LUNs on one target, a program on one LUN must leave the
     * page register of the others alone (Section 3.1.3), which the held
     * page register model needs.
     */
    if (p->luns > 1 && (~p->features & (ONFI_FEAT_MULTI_LUN |
                                        ONFI_FEAT_PR_CLEAR))) {
        ONFI_REFUSE("features (bytes 6-7) 0x%04x: %u LUNs per target need "
                    "multiple LUN operations (bit 1) and the program page "
                    "register clear enhancement (bit 8)", p->features,
                    p->luns);
    }
    if (g->luns_per_ch > 1 && !(p->opt_cmds & ONFI_OPT_STATUS_ENH)) {
        ONFI_REFUSE("optional commands (bytes 8-9) 0x%04x: several LUNs per "
                    "channel need Read Status Enhanced (bit 3)", p->opt_cmds);
    }
    if ((g->luns_per_ch > 1 || g->planes_per_lun > 1) &&
        !(p->opt_cmds & ONFI_OPT_COLUMN_ENH)) {
        ONFI_REFUSE("optional commands (bytes 8-9) 0x%04x: several LUNs or "
                    "planes need Change Read Column Enhanced (bit 6)",
                    p->opt_cmds);
    }
    if (p->col_cycles < 1 || p->col_cycles > 8 || p->row_cycles < 1 ||
        p->row_cycles > 8) {
        ONFI_REFUSE("address cycles (byte 101): column %u and row %u must "
                    "each be 1 to 8", p->col_cycles, p->row_cycles);
    }
    if (addr_bits(g->data_bytes + spare) > 8u * p->col_cycles) {
        ONFI_REFUSE("address cycles (byte 101): %u column cycles cannot "
                    "address %llu bytes", p->col_cycles,
                    (unsigned long long)(g->data_bytes + spare));
    }
    /* page, block and LUN fields are each rounded up alone (Section 3.1) */
    row_bits = addr_bits(p->pages_per_block) + addr_bits(p->blocks_per_lun) +
               addr_bits(p->luns);
    if (row_bits > 8u * p->row_cycles) {
        ONFI_REFUSE("address cycles (byte 101): %u row cycles cannot hold "
                    "%u row address bits", p->row_cycles, row_bits);
    }
    /* 0xff means not given; 0 is not a valid count (6.7.1.20) */
    if (!p->bits_per_entry) {
        ONFI_REFUSE("bits per memory entry (byte 102) is 0");
    }
    if (g->bits_per_entry && p->bits_per_entry != 0xff &&
        p->bits_per_entry != g->bits_per_entry) {
        ONFI_REFUSE("bits per memory entry (byte 102) %u, FEMU %u",
                    p->bits_per_entry, g->bits_per_entry);
    }
    if (p->plane_bits > 4 || (1u << p->plane_bits) != g->planes_per_lun) {
        ONFI_REFUSE("plane address bits (byte 113) %u, FEMU %u planes per "
                    "LUN", p->plane_bits, g->planes_per_lun);
    }
    if (g->planes_per_lun > 1) {
        /* garbage collection erases a block on every plane at once */
        if (!(p->features & ONFI_FEAT_MP_PROG_ERASE)) {
            ONFI_REFUSE("features (bytes 6-7) 0x%04x: several planes need "
                        "multi-plane program and erase (bit 3)", p->features);
        }
        if (p->mp_attr & ONFI_MP_OVERLAPPED) {
            ONFI_REFUSE("multi-plane attributes (byte 114) 0x%02x: FEMU "
                        "models concurrent multi-plane operations, not "
                        "overlapped ones (bit 0)", p->mp_attr);
        }
    }
    if (g->mp_read && !(p->features & ONFI_FEAT_MP_READ)) {
        ONFI_REFUSE("features (bytes 6-7) 0x%04x: mp_read needs multi-plane "
                    "read (bit 6)", p->features);
    }
    if (g->mp_program && !(p->features & ONFI_FEAT_MP_PROG_ERASE)) {
        ONFI_REFUSE("features (bytes 6-7) 0x%04x: mp_program needs "
                    "multi-plane program (bit 3)", p->features);
    }
    /* SCA needs 06h-E0h before each data out; SCE carries 4 LUN bits */
    if (g->sca && !(p->opt_cmds & ONFI_OPT_COLUMN_ENH)) {
        ONFI_REFUSE("optional commands (bytes 8-9) 0x%04x: onfi_sca needs "
                    "Change Read Column Enhanced (bit 6)", p->opt_cmds);
    }
    if (g->sca && p->luns > 16) {
        ONFI_REFUSE("LUNs per target (byte 100) %u: an SCA packet addresses "
                    "16 LUNs", p->luns);
    }
    if (g->cache_read && !(p->opt_cmds & ONFI_OPT_READ_CACHE)) {
        ONFI_REFUSE("optional commands (bytes 8-9) 0x%04x: onfi_cache_read "
                    "needs the Read Cache commands (bit 1)", p->opt_cmds);
    }
    if (g->copyback && !(p->opt_cmds & ONFI_OPT_COPYBACK)) {
        ONFI_REFUSE("optional commands (bytes 8-9) 0x%04x: gc_copyback needs "
                    "Copyback (bit 4)", p->opt_cmds);
    }
    if (onfi_param_max_mode(p) < 0) {
        ONFI_REFUSE("NV-LPDDR4 timing modes (bytes 118-121) list no mode");
    }
    /* the supported modes form one range (6.7.1.30) */
    {
        uint32_t lo = p->modes & -p->modes;
        uint32_t span = (p->modes | (lo - 1)) + 1;

        if (span & (span - 1)) {
            ONFI_REFUSE("NV-LPDDR4 timing modes (bytes 118-121) 0x%06x are "
                        "not one range", p->modes);
        }
    }
    if (g->mode >= 0 && !onfi_param_has_mode(p, g->mode)) {
        ONFI_REFUSE("NV-LPDDR4 timing modes (bytes 118-121) 0x%06x do not "
                    "list onfi_mode %d", p->modes, g->mode);
    }
    if ((g->data_bytes + spare) % 2) {
        ONFI_REFUSE("the page on the bus, %llu data and spare bytes, is odd",
                    (unsigned long long)(g->data_bytes + spare));
    }
    return 0;
}
