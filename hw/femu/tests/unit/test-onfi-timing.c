/*
 * Unit tests for the ONFI 6.0 bus timing profile (hw/femu/nand/onfi.c) and
 * the per-op bus phases it feeds into the NAND media layer.
 *
 * The expected values come from the ONFI 6.0 tables by hand: tDSC per mode
 * (Table 4-36), the constant command times (Table 4-34) and the burst edges
 * (Tables 4-36 and 4-38). A legacy hash pins the media layer with every
 * profile field at 0 to the value master's nand-media.c gives.
 *
 * Output is TAP, as for test-nand-media.c.
 */
#include "qemu/osdep.h"
#include "hw/femu/nand/nand-media.h"
#include "hw/femu/nand/onfi.h"

#define T_CHS  2
#define T_LUNS 8

static uint64_t ch_avail[T_CHS];
static uint64_t lun_avail[T_CHS * T_LUNS];
static uint64_t pl_avail[T_CHS * T_LUNS * 2];

static uint64_t *t_ch(void *o, uint32_t ch)
{
    (void)o;
    return &ch_avail[ch % T_CHS];
}

static uint64_t *t_lun(void *o, const NandLoc *l)
{
    (void)o;
    return &lun_avail[(l->ch * T_LUNS + l->lun) % (T_CHS * T_LUNS)];
}

static uint64_t *t_pl(void *o, const NandLoc *l)
{
    (void)o;
    return &pl_avail[((l->ch * T_LUNS + l->lun) * 2 + l->pl) %
                     (T_CHS * T_LUNS * 2)];
}

static const NandTimelineOps timeline = {
    .ch_avail = t_ch, .lun_avail = t_lun, .plane_avail = t_pl,
};

static int failures;
static int ntests;

static void reset_timelines(void)
{
    memset(ch_avail, 0, sizeof(ch_avail));
    memset(lun_avail, 0, sizeof(lun_avail));
    memset(pl_avail, 0, sizeof(pl_avail));
}

static void check(const char *what, uint64_t got, uint64_t want)
{
    ntests++;
    if (got == want) {
        printf("ok %d - %s (%llu)\n", ntests, what, (unsigned long long)got);
    } else {
        printf("not ok %d - %s: got %llu want %llu\n", ntests, what,
               (unsigned long long)got, (unsigned long long)want);
        failures++;
    }
}

static OnfiTiming derive(int mode, int mts, uint64_t bytes, bool multi_lun,
                         uint64_t tccs, int *rc)
{
    OnfiInput in = {
        .mode = mode, .mts = mts, .page_bytes = bytes, .col_cycles = 2,
        .row_cycles = 3, .multi_lun = multi_lun, .tccs_ns = tccs,
    };
    OnfiTiming t;

    memset(&t, 0, sizeof(t));
    *rc = onfi_derive(&in, &t);
    return t;
}

static void test_mode_table(void)
{
    printf("# timing mode table (Table 4-36)\n");
    check("mode 0 tDSC 30 ns", onfi_tdsc_ps(0), 30000);
    check("mode 4 tDSC 10 ns", onfi_tdsc_ps(4), 10000);
    check("mode 12 tDSC 1.667 ns", onfi_tdsc_ps(12), 1667);
    check("mode 26 tDSC 0.417 ns", onfi_tdsc_ps(26), 417);
    check("mode -1 refused", onfi_tdsc_ps(-1) == -1, 1);
    check("mode 27 refused", onfi_tdsc_ps(27) == -1, 1);
}

static void test_page_xfer(void)
{
    static const struct {
        int mode;
        uint64_t bytes;
        int64_t ns;
    } cases[] = {
        { 0, 4096, 61440 }, { 4, 16384, 81920 }, { 12, 4096, 3415 },
        { 14, 18432, 12571 }, { 22, 16384, 4547 }, { 26, 4096, 855 },
        { 26, 16384, 3417 }, { 26, 18432, 3844 },
    };
    char what[96];
    OnfiTiming t;
    int rc;

    printf("# page transfer: ceil(bytes * tDSC / 2), x8 DDR\n");
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        t = derive(cases[i].mode, 0, cases[i].bytes, false, 0, &rc);
        snprintf(what, sizeof(what), "mode %d, %llu bytes", cases[i].mode,
                 (unsigned long long)cases[i].bytes);
        check(what, t.page_xfer_ns, cases[i].ns);
    }
    t = derive(26, 0, 4753, false, 0, &rc);
    check("mode 26, 4753 bytes: rounded once, not per half ps",
          t.page_xfer_ns, 992);
    t = derive(26, 4800, 4096, false, 0, &rc);
    check("4800 MT/s override, 4096 bytes: ceil(4096000 / 4800)",
          t.page_xfer_ns, 854);
    derive(26, ONFI_MAX_MTS + 1, 4096, false, 0, &rc);
    check("rate above the limit refused", rc, (uint64_t)-1);
    derive(27, 0, 4096, false, 0, &rc);
    check("mode 27 refused by derive", rc, (uint64_t)-1);
}

static void test_command_fields(void)
{
    OnfiTiming t;
    int rc;

    printf("# command, status and burst phases, 2 column + 3 row cycles\n");
    t = derive(26, 0, 16384, false, 0, &rc);
    check("derive ok", rc, 0);
    check("read: 7 cycles + tWB", t.rd_cmd_ns, 7 * 25 + 100);
    check("program: 6 cycles + tADL", t.wr_cmd_ns, 6 * 25 + 412);
    check("data in edges: 25 + 6.5 + 25, rounded up", t.din_burst_ns, 57);
    check("program confirm: 10h + tWB", t.wr_post_ns, 125);
    check("erase: 5 cycles + tWB", t.er_cmd_ns, 5 * 25 + 100);
    check("copyback read: 7 cycles + tWB", t.cb_rd_cmd_ns, 275);
    check("copyback program, no data: 7 cycles + tWB", t.cb_wr_cmd_ns, 275);
    /* 70h, tWHR, tRPRE2, one tDSC, tRPSTH, tRHW: 245.417 ns */
    check("status, one LUN", t.status_ns, 246);
    check("data out lead, one LUN: 00h + tRPRE2", t.dout_pre_ns, 50);
    check("data out tail: tRPSTH + tRHW", t.dout_post_ns, 115);
    check("multi-plane column select: 7 cycles + tRPRE2", t.dout_mp_pre_ns,
          200);
    check("short busy, Table 4-30 typical", t.plbusy_ns, 500);

    t = derive(26, 0, 16384, true, 0, &rc);
    /* 78h + 3 row cycles: 320.417 ns */
    check("status, several LUNs (78h)", t.status_ns, 321);
    check("data out lead, several LUNs: 06h..E0h + tRPRE2", t.dout_pre_ns,
          200);
    t = derive(26, 0, 16384, true, 300, &rc);
    check("tCCS adds to the several-LUN lead", t.dout_pre_ns, 500);
    check("tCCS adds to the multi-plane select", t.dout_mp_pre_ns, 500);
    t = derive(0, 0, 16384, false, 0, &rc);
    check("status at mode 0: one 30 ns byte", t.status_ns, 275);
    t = derive(0, 4800, 16384, false, 0, &rc);
    check("a rate override keeps the mode's status byte", t.status_ns, 275);
}

/*
 * Parameter page (Section 6.7.1). A good page for a device of 4096 data
 * and 256 spare bytes per page, 32 pages per block, 24 blocks per LUN,
 * one LUN per target, one plane and every NV-LPDDR4 mode.
 */
static void put16(uint8_t *p, uint32_t v)
{
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
}

static void put32(uint8_t *p, uint32_t v)
{
    put16(p, v & 0xffff);
    put16(p + 2, v >> 16);
}

static void seal_page(uint8_t *p)
{
    put16(p + 254, onfi_crc16(p, 254));
}

static void make_page(uint8_t *p)
{
    memset(p, 0, ONFI_PARAM_PAGE_BYTES);
    memcpy(p, "ONFI", 4);
    put16(p + 4, ONFI_REV_6_0);
    put16(p + 6, ONFI_FEAT_NV_LPDDR4 | ONFI_FEAT_MULTI_LUN |
          ONFI_FEAT_PR_CLEAR | ONFI_FEAT_MP_PROG_ERASE | ONFI_FEAT_MP_READ);
    put16(p + 8, ONFI_OPT_READ_CACHE | ONFI_OPT_STATUS_ENH |
          ONFI_OPT_COPYBACK | ONFI_OPT_COLUMN_ENH);
    put32(p + 80, 4096);
    put16(p + 84, 256);
    put32(p + 92, 32);
    put32(p + 96, 24);
    p[100] = 1;
    p[101] = 0x23;          /* 2 column, 3 row cycles */
    p[102] = 0xff;
    p[113] = 0;
    put32(p + 118, 0xffffff);
    seal_page(p);
}

static OnfiGeometry page_geometry(void)
{
    OnfiGeometry g = {
        .data_bytes = 4096, .pages_per_block = 32, .blocks_per_lun = 24,
        .luns_per_ch = 1, .planes_per_lun = 1, .mode = -1,
    };

    return g;
}

/* 0 when @p parses and passes the check against @g; else -1 */
static int page_ok(const uint8_t *p, size_t len, const OnfiGeometry *g,
                   const char *want)
{
    OnfiParamPage pg;
    const char *why;
    char msg[256];
    int rc;

    if (onfi_param_parse(p, len, &pg, &why)) {
        rc = -1;
        snprintf(msg, sizeof(msg), "%s", why);
    } else {
        rc = onfi_param_check(&pg, g, msg, sizeof(msg));
    }
    if (rc && want && !strstr(msg, want)) {
        printf("# refused for another reason: %s\n", msg);
        return -2;
    }
    return rc;
}

static void test_param_page(void)
{
    uint8_t buf[3 * ONFI_PARAM_PAGE_BYTES];
    uint8_t *p = buf;
    OnfiGeometry g = page_geometry();
    OnfiParamPage pg;
    const char *why;
    int rc;

    printf("# parameter page: CRC-16, copies, modes, geometry\n");
    /*
     * Hand value: polynomial division of the message with its first 16
     * bits XORed by 4F4Eh, which is what the initial value does.
     */
    check("CRC of \"123456789\"", onfi_crc16((const uint8_t *)"123456789", 9),
          0x2771);
    check("CRC of nothing is the initial value", onfi_crc16(buf, 0), 0x4f4e);

    make_page(p);
    rc = onfi_param_parse(p, ONFI_PARAM_PAGE_BYTES, &pg, &why);
    check("good page parses", rc, 0);
    check("copy 0 used", pg.copy, 0);
    check("data bytes", pg.data_bytes, 4096);
    check("spare bytes", pg.spare_bytes, 256);
    check("column cycles", pg.col_cycles, 2);
    check("row cycles", pg.row_cycles, 3);
    check("every mode: highest is 26", onfi_param_max_mode(&pg), 26);
    check("good page passes the check", page_ok(p, ONFI_PARAM_PAGE_BYTES,
                                                &g, NULL), 0);

    pg.modes = 1;
    check("bit 0 only: modes 0 to 3, highest 3", onfi_param_max_mode(&pg), 3);
    check("bit 0 lists mode 2", onfi_param_has_mode(&pg, 2), 1);
    check("bit 0 does not list mode 4", onfi_param_has_mode(&pg, 4), 0);
    pg.modes = 1u << 1;
    check("bit 1 is mode 4", onfi_param_max_mode(&pg), 4);
    pg.modes = 1u << 23;
    check("bit 23 is mode 26", onfi_param_max_mode(&pg), 26);
    check("bit 23 lists mode 26", onfi_param_has_mode(&pg, 26), 1);
    check("bit 23 does not list mode 25", onfi_param_has_mode(&pg, 25), 0);
    pg.modes = 0;
    check("no bit: no mode", (uint64_t)(int64_t)onfi_param_max_mode(&pg),
          (uint64_t)-1);

    /* copy 0 with a bad CRC, copy 1 good, copy 2 without a signature */
    make_page(buf);
    make_page(buf + ONFI_PARAM_PAGE_BYTES);
    memset(buf + 2 * ONFI_PARAM_PAGE_BYTES, 0, ONFI_PARAM_PAGE_BYTES);
    buf[50] ^= 1;
    rc = onfi_param_parse(buf, sizeof(buf), &pg, &why);
    check("bad copy 0, good copy 1: parses", rc, 0);
    check("bad copy 0, good copy 1: copy 1 used", pg.copy, 1);
    check("bad CRC in every copy: refused",
          page_ok(buf, ONFI_PARAM_PAGE_BYTES, &g, "good CRC"), (uint64_t)-1);
    make_page(buf);
    buf[0] = buf[1] = buf[2] = 0;
    seal_page(buf);
    check("one signature byte: no copy present",
          page_ok(buf, ONFI_PARAM_PAGE_BYTES, &g, "signature"), (uint64_t)-1);
    make_page(buf);
    buf[0] = buf[1] = 0;
    seal_page(buf);
    check("two signature bytes: present", page_ok(buf, ONFI_PARAM_PAGE_BYTES,
                                                  &g, NULL), 0);
    check("short file refused", page_ok(buf, 255, &g, "shorter"),
          (uint64_t)-1);

    printf("# parameter page refusals\n");
    {
        static const struct {
            const char *what;
            int off;
            int width;
            uint32_t val;
            const char *msg;
        } bad[] = {
            { "revision without 6.0", 4, 2, 1u << 14, "bytes 4-5" },
            { "no NV-LPDDR4", 6, 2, ONFI_FEAT_MULTI_LUN, "bit 9" },
            { "x16 bus", 6, 2, ONFI_FEAT_NV_LPDDR4 | ONFI_FEAT_X16,
              "16-bit" },
            { "data bytes differ", 80, 4, 8192, "bytes 80-83" },
            { "data bytes not a power of two", 80, 4, 3072, "power of two" },
            { "data bytes under 512", 80, 4, 256, "power of two" },
            { "pages per block differ", 92, 4, 64, "bytes 92-95" },
            { "pages per block not a multiple of 32", 92, 4, 16,
              "multiple of 32" },
            { "blocks per LUN differ", 96, 4, 48, "bytes 96-99" },
            { "no LUN count", 100, 1, 0, "byte 100" },
            { "one column cycle for 4352 bytes", 101, 1, 0x13,
              "column cycles cannot" },
            { "one row cycle for 10 row bits", 101, 1, 0x21,
              "row cycles cannot" },
            { "plane bits for two planes", 113, 1, 1, "byte 113" },
            { "no mode", 118, 4, 0, "list no mode" },
            { "a hole in the modes: 0-3 and 5", 118, 4, 0x5, "one range" },
            { "bits per memory entry 0", 102, 1, 0, "byte 102" },
            { "odd spare bytes", 84, 2, 255, "odd" },
        };

        for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            make_page(p);
            if (bad[i].width == 1) {
                p[bad[i].off] = bad[i].val;
            } else if (bad[i].width == 2) {
                put16(p + bad[i].off, bad[i].val);
            } else {
                put32(p + bad[i].off, bad[i].val);
            }
            seal_page(p);
            check(bad[i].what, page_ok(p, ONFI_PARAM_PAGE_BYTES, &g,
                                       bad[i].msg), (uint64_t)-1);
        }
    }
    make_page(p);
    p[100] = 2;
    put16(p + 6, ONFI_FEAT_NV_LPDDR4 | ONFI_FEAT_MULTI_LUN);
    seal_page(p);
    g.luns_per_ch = 2;
    check("two LUNs per target without the clear enhancement",
          page_ok(p, ONFI_PARAM_PAGE_BYTES, &g, "bit 8"), (uint64_t)-1);
    g = page_geometry();
    g.luns_per_ch = 3;
    make_page(p);
    p[100] = 2;
    seal_page(p);
    check("3 LUNs per channel, 2 per target", page_ok(p, ONFI_PARAM_PAGE_BYTES,
                                                      &g, "byte 100"),
          (uint64_t)-1);
    g = page_geometry();
    g.luns_per_ch = 2;
    make_page(p);
    put16(p + 8, ONFI_OPT_COLUMN_ENH);
    seal_page(p);
    check("two LUNs need Read Status Enhanced",
          page_ok(p, ONFI_PARAM_PAGE_BYTES, &g, "bit 3"), (uint64_t)-1);
    g = page_geometry();
    g.spare_bytes = 128;
    make_page(p);
    check("onfi_spare_bytes that differs", page_ok(p, ONFI_PARAM_PAGE_BYTES,
                                                   &g, "onfi_spare_bytes"),
          (uint64_t)-1);
    g = page_geometry();
    g.mode = 12;
    make_page(p);
    put32(p + 118, 1u << 1);
    seal_page(p);
    check("onfi_mode the page does not list",
          page_ok(p, ONFI_PARAM_PAGE_BYTES, &g, "onfi_mode 12"), (uint64_t)-1);
    g = page_geometry();
    g.copyback = true;
    make_page(p);
    put16(p + 8, ONFI_OPT_READ_CACHE);
    seal_page(p);
    check("gc_copyback without Copyback", page_ok(p, ONFI_PARAM_PAGE_BYTES,
                                                  &g, "Copyback"),
          (uint64_t)-1);
    g = page_geometry();
    g.planes_per_lun = 2;
    g.blocks_per_lun = 24;
    make_page(p);
    p[113] = 1;
    p[114] = ONFI_MP_OVERLAPPED;
    seal_page(p);
    check("two planes, overlapped only", page_ok(p, ONFI_PARAM_PAGE_BYTES,
                                                 &g, "overlapped"),
          (uint64_t)-1);
    make_page(p);
    p[113] = 1;
    put16(p + 6, ONFI_FEAT_NV_LPDDR4);
    seal_page(p);
    check("two planes without multi-plane erase",
          page_ok(p, ONFI_PARAM_PAGE_BYTES, &g, "bit 3"), (uint64_t)-1);
    make_page(p);
    p[113] = 1;
    seal_page(p);
    check("two planes, concurrent: accepted",
          page_ok(p, ONFI_PARAM_PAGE_BYTES, &g, NULL), 0);

    printf("# address cycles set the command lengths\n");
    {
        OnfiInput in = {
            .mode = 26, .page_bytes = 4096, .col_cycles = 3, .row_cycles = 4,
        };
        OnfiTiming t;

        onfi_derive(&in, &t);
        check("3 column + 4 row: read 9 cycles + tWB", t.rd_cmd_ns,
              9 * 25 + 100);
        check("3 column + 4 row: erase 6 cycles + tWB", t.er_cmd_ns,
              6 * 25 + 100);
    }
}

/* bbssd's staged config with the profile's fields for @t */
static void onfi_config(NandMediaConfig *cfg, const OnfiTiming *t,
                        uint32_t planes)
{
    memset(cfg, 0, sizeof(*cfg));
    reset_timelines();
    cfg->nchs = T_CHS;
    cfg->luns_per_ch = T_LUNS;
    cfg->planes_per_lun = planes;
    cfg->timing.rd_ns = 40000;
    cfg->timing.wr_ns = 200000;
    cfg->timing.er_ns = 2000000;
    cfg->timing.page_xfer_ns = t->page_xfer_ns;
    cfg->timing.status_ns = t->status_ns;
    cfg->timing.rd_cmd_ns = t->rd_cmd_ns;
    cfg->timing.wr_cmd_ns = t->wr_cmd_ns;
    cfg->timing.er_cmd_ns = t->er_cmd_ns;
    cfg->timing.cb_rd_cmd_ns = t->cb_rd_cmd_ns;
    cfg->timing.cb_wr_cmd_ns = t->cb_wr_cmd_ns;
    cfg->timing.din_burst_ns = t->din_burst_ns;
    cfg->timing.wr_post_ns = t->wr_post_ns;
    cfg->timing.dout_pre_ns = t->dout_pre_ns;
    cfg->timing.dout_post_ns = t->dout_post_ns;
    cfg->timing.dout_mp_pre_ns = t->dout_mp_pre_ns;
    cfg->timing.tplpbsy_ns = t->plbusy_ns;
    cfg->timing.tplrbsy_ns = t->plbusy_ns;
    cfg->timing.tplebsy_ns = t->plbusy_ns;
    cfg->policy.array_contend = NAND_CONTEND_LUN_ONLY;
    cfg->policy.channel_mode = NAND_CH_STAGED;
    cfg->policy.use_flat_timing = true;
    cfg->timeline = &timeline;
}

static void test_media_phases(void)
{
    NandMediaConfig cfg;
    NandMedia m;
    NandLoc a = { .ch = 0, .lun = 0 };
    NandLoc b = { .ch = 0, .lun = 1 };
    OnfiTiming t;
    int rc;

    printf("# media op latency on an idle LUN, mode 26, 16 KiB, one LUN "
           "per channel\n");
    t = derive(26, 0, 16384, false, 0, &rc);

    onfi_config(&cfg, &t, 1);
    nand_media_init(&m, &cfg);
    /* 275 + 40000 + (50 + 3417 + 115) + 246 */
    check("read", nand_media_op(&m, &a, NAND_MEDIA_READ, 0).latency_ns,
          275 + 40000 + 50 + 3417 + 115 + 246);
    nand_media_destroy(&m);

    onfi_config(&cfg, &t, 1);
    nand_media_init(&m, &cfg);
    /* 562 + (57 + 3417 + 125) + 200000 */
    check("program", nand_media_op(&m, &a, NAND_MEDIA_PROGRAM, 0).latency_ns,
          562 + 57 + 3417 + 125 + 200000);
    nand_media_destroy(&m);

    onfi_config(&cfg, &t, 1);
    nand_media_init(&m, &cfg);
    check("erase", nand_media_op(&m, &a, NAND_MEDIA_ERASE, 0).latency_ns,
          225 + 2000000 + 246);
    nand_media_destroy(&m);

    onfi_config(&cfg, &t, 1);
    nand_media_init(&m, &cfg);
    /* 275, tR, then status + the no-data program command, then tPROG */
    check("copyback", nand_media_copyback(&m, &a, &b, 0).latency_ns,
          275 + 40000 + 246 + 275 + 200000);
    nand_media_destroy(&m);

    printf("# multi-plane, two planes\n");
    onfi_config(&cfg, &t, 2);
    nand_media_init(&m, &cfg);
    {
        NandLoc p[2] = { { .ch = 0, .lun = 0, .pl = 0 },
                         { .ch = 0, .lun = 0, .pl = 1 } };

        /* per plane 562 + 3599, one 500 gap, one tPROG, then status */
        check("program", nand_media_multiplane(&m, p, 2, NAND_MEDIA_PROGRAM,
                                               0).latency_ns,
              2 * (562 + 57 + 3417 + 125) + 500 + 200000 + 246);
    }
    nand_media_destroy(&m);

    onfi_config(&cfg, &t, 2);
    nand_media_init(&m, &cfg);
    {
        NandLoc p[2] = { { .ch = 0, .lun = 0, .pl = 0 },
                         { .ch = 0, .lun = 0, .pl = 1 } };

        /* two commands, one gap, tR, status, per plane select + page + tail */
        check("read", nand_media_multiplane(&m, p, 2, NAND_MEDIA_READ,
                                            0).latency_ns,
              2 * 275 + 500 + 40000 + 246 + 2 * (200 + 3417 + 115));
    }
    nand_media_destroy(&m);
}

/* the config bb_nand_media_init() builds with the profile on */
static void order_config(NandMediaConfig *cfg, const OnfiTiming *t,
                         uint32_t planes, bool per_plane)
{
    onfi_config(cfg, t, planes);
    cfg->policy.bus_res_unbounded = true;
    cfg->policy.onfi_order = true;
    cfg->policy.page_reg_hold = true;
    cfg->policy.mp_status_per_plane = per_plane;
}

/* order_config() plus one ECC tier of @ecc ns per 750 erases */
static void gap_config(NandMediaConfig *cfg, const OnfiTiming *t,
                       uint64_t ecc)
{
    order_config(cfg, t, 1, false);
    cfg->timing.ecc_step_ns = ecc;
    cfg->timing.ecc_pe_per_tier = 750;
    cfg->timing.ecc_max_tiers = 4;
    cfg->policy.ecc_on_read = true;
}

/*
 * Mode 26, 16 KiB, one-LUN fields: read command 275, tR 40000, status 246,
 * data out 50 + 3417 + 115 = 3582; program command 562, data in
 * 57 + 3417 + 125 = 3599, tPROG 200000; tPL*BSY 500.
 */
static void test_onfi_order(void)
{
    NandMediaConfig cfg;
    NandMedia m;
    NandLoc l0 = { .ch = 0, .lun = 0 };
    NandLoc l1 = { .ch = 0, .lun = 1 };
    NandLoc l1e = { .ch = 0, .lun = 1, .pe_cycles = 750 };
    NandLoc p[2] = { { .ch = 0, .lun = 0, .pl = 0 },
                     { .ch = 0, .lun = 0, .pl = 1 } };
    OnfiTiming t, tm;
    int rc;

    printf("# ONFI order and page register hold\n");
    t = derive(26, 0, 16384, false, 0, &rc);
    tm = derive(26, 0, 16384, true, 0, &rc);

    order_config(&cfg, &t, 1, false);
    nand_media_init(&m, &cfg);
    check("read: command, tR, status, then data out",
          nand_media_op(&m, &l0, NAND_MEDIA_READ, 0).latency_ns,
          275 + 40000 + 246 + 3582);
    nand_media_destroy(&m);

    order_config(&cfg, &t, 1, false);
    nand_media_init(&m, &cfg);
    check("program ends at its status",
          nand_media_op(&m, &l0, NAND_MEDIA_PROGRAM, 0).latency_ns,
          562 + 3599 + 200000 + 246);
    nand_media_destroy(&m);

    /* the second read sends its command only when the first has its data */
    order_config(&cfg, &t, 1, false);
    nand_media_init(&m, &cfg);
    nand_media_op(&m, &l0, NAND_MEDIA_READ, 0);
    check("second read on the LUN: command after the first data out",
          nand_media_op(&m, &l0, NAND_MEDIA_READ, 0).latency_ns,
          44103 + 275 + 40000 + 246 + 3582);
    nand_media_destroy(&m);

    /*
     * A program queued on a busy LUN books its input in the future, so a
     * read on an idle LUN takes the bus at once (after the first input).
     */
    order_config(&cfg, &t, 1, false);
    nand_media_init(&m, &cfg);
    nand_media_op(&m, &l0, NAND_MEDIA_PROGRAM, 0);
    nand_media_op(&m, &l0, NAND_MEDIA_PROGRAM, 1000);
    check("idle LUN read is not held behind a future program input",
          nand_media_op(&m, &l1, NAND_MEDIA_READ, 2000).latency_ns,
          (4161 - 2000) + 275 + 40000 + 246 + 3582);
    nand_media_destroy(&m);

    /* a read on the LUN waits for the program's status, not its array */
    order_config(&cfg, &t, 1, false);
    nand_media_init(&m, &cfg);
    nand_media_op(&m, &l0, NAND_MEDIA_PROGRAM, 0);
    check("read after a program waits for the program's status",
          nand_media_op(&m, &l0, NAND_MEDIA_READ, 1).latency_ns,
          204407 - 1 + 44103);
    nand_media_destroy(&m);

    /*
     * A two-plane program input is one window: the read on LUN 1 booked
     * its status at [40275, 40521) and its data out at [40521, 44103). One
     * plane (4161 ns) fits before them at 36000, the 8822 ns group does
     * not, so it starts at 44103.
     */
    order_config(&cfg, &t, 2, false);
    nand_media_init(&m, &cfg);
    nand_media_op(&m, &l1, NAND_MEDIA_READ, 0);
    check("multi-plane program input stays in one window",
          nand_media_multiplane(&m, p, 2, NAND_MEDIA_PROGRAM,
                                36000).latency_ns,
          44103 + 8822 + 200000 + 246 - 36000);
    nand_media_destroy(&m);

    /*
     * The second plane command of a read is a future window at
     * [775, 1050), so the idle LUN's read command fits at [275, 550).
     */
    order_config(&cfg, &t, 2, false);
    nand_media_init(&m, &cfg);
    check("multi-plane read",
          nand_media_multiplane(&m, p, 2, NAND_MEDIA_READ, 0).latency_ns,
          275 + 500 + 275 + 40000 + 246 + 2 * (200 + 3417 + 115));
    check("idle LUN command fits in the gap between plane commands",
          nand_media_op(&m, &l1, NAND_MEDIA_READ, 100).latency_ns,
          48760 + 3582 - 100);
    nand_media_destroy(&m);

    order_config(&cfg, &tm, 2, true);
    nand_media_init(&m, &cfg);
    check("several LUNs: one 78h status per plane of a program",
          nand_media_multiplane(&m, p, 2, NAND_MEDIA_PROGRAM, 0).latency_ns,
          2 * (562 + 3599) + 500 + 200000 + 2 * 321);
    nand_media_destroy(&m);

    /* copyback holds the die to its final status; no ECC on the die */
    order_config(&cfg, &t, 1, false);
    nand_media_init(&m, &cfg);
    check("copyback ends at its status",
          nand_media_copyback(&m, &l0, &l0, 0).latency_ns,
          275 + 40000 + 246 + 275 + 200000 + 246);
    check("read after a copyback waits for its status",
          nand_media_op(&m, &l0, NAND_MEDIA_READ, 1).latency_ns,
          241042 - 1 + 44103);
    nand_media_destroy(&m);

    order_config(&cfg, &t, 1, false);
    nand_media_init(&m, &cfg);
    check("erase", nand_media_op(&m, &l0, NAND_MEDIA_ERASE, 0).latency_ns,
          225 + 2000000 + 246);
    nand_media_destroy(&m);

    /*
     * Gap probes. A read on LUN 1 with one ECC tier of @E ns books its
     * status 240 ns after LUN 0's op leaves its array. LUN 0's own status
     * (246 ns) cannot fit in that gap and moves past LUN 1's windows, but an
     * erase command (225 ns) can. A LUN 0 erase must still wait for the
     * end of LUN 0's op; a LUN released early takes the gap.
     */
    /*
     * Op times are not monotonic: a copy's write starts at its read's end.
     * A program whose command waits for its LUN must not prune the windows
     * that an earlier-timed op still has to avoid. Several-LUN fields: data
     * out 200 + 3417 + 115 = 3732.
     */
    order_config(&cfg, &tm, 1, false);
    nand_media_init(&m, &cfg);
    {
        NandLoc l2 = { .ch = 0, .lun = 2 };
        uint64_t r0, r2;

        nand_media_op(&m, &l1, NAND_MEDIA_PROGRAM, 1000);
        r0 = nand_media_op(&m, &l0, NAND_MEDIA_READ, 2000).done_ns;
        nand_media_op(&m, &l1, NAND_MEDIA_PROGRAM, r0);
        r2 = nand_media_op(&m, &l2, NAND_MEDIA_READ, 3000).done_ns;
        check("a later read's data out does not overlap an earlier one",
              r2 >= r0 + 3732 || r2 <= r0 - 3732, 1);
    }
    nand_media_destroy(&m);

    /*
     * A two-plane read's column select and page stay together. LUN 1's
     * read (one ECC tier of 1596) books its status at 41871, 300 ns after
     * LUN 0's status ends: room for a 200 ns select, none for its page.
     */
    order_config(&cfg, &t, 2, false);
    cfg.timing.ecc_step_ns = 1596;
    cfg.timing.ecc_pe_per_tier = 750;
    cfg.timing.ecc_max_tiers = 4;
    cfg.policy.ecc_on_read = true;
    nand_media_init(&m, &cfg);
    nand_media_op(&m, &l1e, NAND_MEDIA_READ, 0);
    check("multi-plane select and page form one window",
          nand_media_multiplane(&m, p, 2, NAND_MEDIA_READ, 0).latency_ns,
          45699 + 2 * 3732);
    nand_media_destroy(&m);

    /* copyback reads on the die: no controller ECC, which a read pays */
    gap_config(&cfg, &t, 5000);
    nand_media_init(&m, &cfg);
    check("copyback of a worn page pays no ECC",
          nand_media_copyback(&m, &l1e, &l1e, 0).latency_ns,
          275 + 40000 + 246 + 275 + 200000 + 246);
    nand_media_destroy(&m);
    gap_config(&cfg, &t, 5000);
    nand_media_init(&m, &cfg);
    check("a read of the same page pays one ECC tier",
          nand_media_op(&m, &l1e, NAND_MEDIA_READ, 0).latency_ns,
          275 + 45000 + 246 + 3582);
    nand_media_destroy(&m);

    printf("# gap probes: the LUN is held, not only the bus\n");
    gap_config(&cfg, &t, 515);
    nand_media_init(&m, &cfg);
    nand_media_op(&m, &l1e, NAND_MEDIA_READ, 0);
    nand_media_op(&m, &l0, NAND_MEDIA_READ, 0);
    /* LUN 0 data out ends at 48446 */
    check("erase after a read waits for the read's data out",
          nand_media_op(&m, &l0, NAND_MEDIA_ERASE, 1000).latency_ns,
          48446 + 225 + 2000000 + 246 - 1000);
    nand_media_destroy(&m);

    gap_config(&cfg, &t, 164401);
    nand_media_init(&m, &cfg);
    nand_media_op(&m, &l1e, NAND_MEDIA_READ, 0);
    nand_media_op(&m, &l0, NAND_MEDIA_PROGRAM, 0);
    /* LUN 0 program status ends at 208750 */
    check("erase after a program waits for the program's status",
          nand_media_op(&m, &l0, NAND_MEDIA_ERASE, 1000).latency_ns,
          208750 + 225 + 2000000 + 246 - 1000);
    nand_media_destroy(&m);

    gap_config(&cfg, &t, 201036);
    nand_media_init(&m, &cfg);
    nand_media_op(&m, &l1e, NAND_MEDIA_READ, 0);
    nand_media_copyback(&m, &l0, &l0, 0);
    /* LUN 0 copyback status ends at 245385 */
    check("erase after a copyback waits for the copyback's status",
          nand_media_op(&m, &l0, NAND_MEDIA_ERASE, 1000).latency_ns,
          245385 + 225 + 2000000 + 246 - 1000);
    nand_media_destroy(&m);
}

/*
 * Bus history. Every bus phase of non-zero length goes to the bus_phase
 * observer, also the ones whose window was dropped later and the ones that
 * advance ch_avail, so the check sees every phase that ever ran.
 */
static uint64_t rng_state;
static uint32_t rng(void);

typedef struct PhaseLog {
    NandBusRes *r;
    size_t n;
    size_t cap;
} PhaseLog;

static PhaseLog phase_log[T_CHS];

static void log_phase(void *o, uint32_t ch, uint64_t start, uint64_t end)
{
    PhaseLog *l = &phase_log[ch % T_CHS];

    (void)o;
    if (l->n == l->cap) {
        l->cap = l->cap ? 2 * l->cap : 1024;
        l->r = realloc(l->r, l->cap * sizeof(*l->r));
        if (!l->r) {
            abort();
        }
    }
    l->r[l->n].start = start;
    l->r[l->n++].end = end;
}

static const NandTimelineOps logged_timeline = {
    .ch_avail = t_ch, .lun_avail = t_lun, .plane_avail = t_pl,
    .bus_phase = log_phase,
};

static int cmp_start(const void *a, const void *b)
{
    const NandBusRes *x = a;
    const NandBusRes *y = b;

    return x->start < y->start ? -1 : x->start > y->start;
}

/* the number of overlapping phase pairs (by sweep), and clear the log */
static uint64_t phase_overlaps(void)
{
    uint64_t bad = 0;

    for (int ch = 0; ch < T_CHS; ch++) {
        PhaseLog *l = &phase_log[ch];
        uint64_t end = 0;

        if (l->n > 1) {
            qsort(l->r, l->n, sizeof(*l->r), cmp_start);
        }
        for (size_t i = 0; i < l->n; i++) {
            if (i && l->r[i].start < end) {
                bad++;
            }
            end = l->r[i].end > end ? l->r[i].end : end;
        }
        free(l->r);
        memset(l, 0, sizeof(*l));
    }
    return bad;
}

/* the windows of channel 0 that end at or before @t */
static uint32_t history(const NandMedia *m, uint64_t t)
{
    const NandBusResList *l = &m->bus_res[0];
    const NandBusRes *r = l->grown ? l->grown : l->r;
    uint32_t k = 0;

    while (k < (uint32_t)l->n && r[k].end <= t) {
        k++;
    }
    return k;
}

/* a second timeline, so two media can run side by side */
static uint64_t ch_b[T_CHS];
static uint64_t lun_b[T_CHS * T_LUNS];

static uint64_t *t_ch_b(void *o, uint32_t ch)
{
    (void)o;
    return &ch_b[ch % T_CHS];
}

static uint64_t *t_lun_b(void *o, const NandLoc *l)
{
    (void)o;
    return &lun_b[(l->ch * T_LUNS + l->lun) % (T_CHS * T_LUNS)];
}

static const NandTimelineOps timeline_b = {
    .ch_avail = t_ch_b, .lun_avail = t_lun_b,
};

/*
 * Mode 26, 16 KiB, one-LUN fields (as in test_onfi_order()): a read is
 * 275 + 40000 + 246 + 3582 = 44103 on an idle LUN.
 */
static void test_bus_history(void)
{
    NandMediaConfig cfg;
    NandMedia m;
    NandLoc l0 = { .ch = 0, .lun = 0 };
    NandLoc l1 = { .ch = 0, .lun = 1 };
    OnfiTiming t;
    int rc;

    printf("# bus history: older ops and earlier gaps\n");
    t = derive(26, 0, 16384, false, 0, &rc);

    /*
     * LUN 0 programs from 0 to 204407. A read on LUN 0 at 100000 waits for
     * it and books its command at 204407; ch_avail stays at 4161. A read on
     * LUN 1 at 50000 is older than 100000 and finds the bus idle there.
     */
    order_config(&cfg, &t, 1, false);
    nand_media_init(&m, &cfg);
    nand_media_op(&m, &l0, NAND_MEDIA_PROGRAM, 0);
    nand_media_op(&m, &l0, NAND_MEDIA_READ, 100000);
    check("an older op uses an earlier bus gap",
          nand_media_op(&m, &l1, NAND_MEDIA_READ, 50000).done_ns,
          50000 + 44103);
    nand_media_destroy(&m);

    /*
     * A bounded list keeps the latest start time as its prune mark: it has
     * no room to keep history next to future windows. Five paced reads on
     * LUN 0, ten more at the same time, then an idle LUN 1 read at that time.
     */
    order_config(&cfg, &t, 1, false);
    cfg.policy.bus_res_unbounded = false;
    nand_media_init(&m, &cfg);
    {
        uint64_t now = 0;

        for (int i = 0; i < 5; i++) {
            now = nand_media_op(&m, &l0, NAND_MEDIA_READ, now).done_ns - 100;
        }
        for (int i = 0; i < 10; i++) {
            nand_media_op(&m, &l0, NAND_MEDIA_READ, now);
        }
        check("a bounded list keeps the latest start as its prune mark",
              nand_media_op(&m, &l1, NAND_MEDIA_READ, now).done_ns, 268721);
    }
    nand_media_destroy(&m);

    /*
     * One busy LUN, each read 100 ns before the one before ends: ch_avail
     * stays at the first command, and history piles up behind the latest
     * start. The cap keeps it bounded (Codex code review round 2).
     */
    order_config(&cfg, &t, 1, false);
    nand_media_init(&m, &cfg);
    {
        uint64_t now = 0;
        int most = 0;

        for (int i = 0; i < 100000; i++) {
            now = nand_media_op(&m, &l0, NAND_MEDIA_READ, now).done_ns - 100;
            most = m.bus_res[0].n > most ? m.bus_res[0].n : most;
        }
        check("history stays at most the cap plus one op under a busy LUN",
              most <= NAND_BUS_HISTORY_MAX + 8, 1);
        check("the list does not grow past twice the cap",
              m.bus_res[0].cap <= 2 * NAND_BUS_HISTORY_MAX, 1);
    }
    nand_media_destroy(&m);

    /*
     * The cap itself: with k windows at or before the latest start, k at
     * most the cap leaves the prune mark alone, and k above it raises the
     * mark to the end of window k - cap/2 - 1, which keeps cap/2 of them.
     * Several caps make k meet the cap exactly and pass it by one.
     */
    {
        bool at_cap = false, past_cap = false, rule_ok = true;

        for (uint32_t c = 6; c <= 14; c += 2) {
            uint64_t now = 0;

            order_config(&cfg, &t, 1, false);
            nand_media_init(&m, &cfg);
            m.bus_res[0].hist_cap = c;
            for (int i = 0; i < 40; i++) {
                const NandBusResList *l = &m.bus_res[0];
                uint64_t high = l->high > now ? l->high : now;
                uint32_t k = history(&m, high);
                uint64_t want = l->low;

                if (k > c && l->grown[k - c / 2 - 1].end > want) {
                    want = l->grown[k - c / 2 - 1].end;
                }
                at_cap |= k == c;
                past_cap |= k == c + 1;
                now = nand_media_op(&m, &l0, NAND_MEDIA_READ, now).done_ns -
                      100;
                rule_ok &= m.bus_res[0].low == want;
            }
            nand_media_destroy(&m);
        }
        check("the prune mark follows the cap rule", rule_ok, 1);
        check("a run meets the cap exactly", at_cap, 1);
        check("a run passes the cap by one window", past_cap, 1);
    }

    /*
     * The same op stream on a list with a small cap (a) and on one whose
     * cap never applies (b). Starts that never fall behind the prune mark
     * give the same times on both. Then an op at exactly the mark, and one
     * between the mark and the latest start, still match. An op before the
     * mark starts at the mark on (a), the fallback.
     */
    {
        NandMediaConfig cb;
        NandMedia b;
        uint64_t now = 0, low;
        bool same = true;

        order_config(&cfg, &t, 1, false);
        nand_media_init(&m, &cfg);
        m.bus_res[0].hist_cap = 8;
        cb = cfg;
        cb.timeline = &timeline_b;
        memset(ch_b, 0, sizeof(ch_b));
        memset(lun_b, 0, sizeof(lun_b));
        nand_media_init(&b, &cb);
        b.bus_res[0].hist_cap = UINT32_MAX;
        for (int i = 0; i < 30; i++) {
            uint64_t da = nand_media_op(&m, &l0, NAND_MEDIA_READ, now).done_ns;
            uint64_t db = nand_media_op(&b, &l0, NAND_MEDIA_READ, now).done_ns;

            same &= da == db;
            now = da - 100;
        }
        low = m.bus_res[0].low;
        check("a cap was crossed", low > 0, 1);
        check("starts at or after the mark: same times as with no cap", same,
              1);
        check("an op at the mark: same time as with no cap",
              nand_media_op(&m, &l1, NAND_MEDIA_READ, low).done_ns,
              nand_media_op(&b, &l1, NAND_MEDIA_READ, low).done_ns);
        {
            NandLoc l2 = { .ch = 0, .lun = 2 };
            uint64_t mid = low + (m.bus_res[0].high - low) / 2;

            check("an op between the mark and the latest start: same time",
                  nand_media_op(&m, &l2, NAND_MEDIA_PROGRAM, mid).done_ns,
                  nand_media_op(&b, &l2, NAND_MEDIA_PROGRAM, mid).done_ns);
        }
        {
            NandLoc l3 = { .ch = 0, .lun = 3 };
            uint64_t da = nand_media_op(&m, &l3, NAND_MEDIA_READ,
                                        low - 1000).done_ns;

            check("an op before the mark starts at the mark", da >= low + 44103,
                  1);
        }
        nand_media_destroy(&b);
        nand_media_destroy(&m);
    }

    /*
     * Zero-length phases do not move ch_avail, so ch_avail can stay below
     * the prune mark. Hand-set phases with the hold off: tR and tPROG 100,
     * program command 5, page 10, no status or read command. Ten reads on
     * LUN 0, each 1 ns before the one before ends, then a program on idle
     * LUN 1 at 100: its command and data must start no earlier than the
     * prune mark, past the dropped transfer [100, 110). A bounded list and
     * a grown list with a cap of 2 give their own prune marks.
     */
    for (int grown = 0; grown < 2; grown++) {
        uint64_t now = 0, done;

        memset(&cfg, 0, sizeof(cfg));
        reset_timelines();
        cfg.nchs = T_CHS;
        cfg.luns_per_ch = T_LUNS;
        cfg.planes_per_lun = 1;
        cfg.timing.rd_ns = 100;
        cfg.timing.wr_ns = 100;
        cfg.timing.wr_cmd_ns = 5;
        cfg.timing.page_xfer_ns = 10;
        cfg.policy.array_contend = NAND_CONTEND_LUN_ONLY;
        cfg.policy.channel_mode = NAND_CH_STAGED;
        cfg.policy.use_flat_timing = true;
        cfg.policy.onfi_order = true;
        cfg.policy.bus_res_unbounded = grown;
        cfg.timeline = &logged_timeline;
        nand_media_init(&m, &cfg);
        if (grown) {
            m.bus_res[0].hist_cap = 2;
        }
        for (int i = 0; i < 10; i++) {
            now = nand_media_op(&m, &l0, NAND_MEDIA_READ, now).done_ns - 1;
        }
        done = nand_media_op(&m, &l1, NAND_MEDIA_PROGRAM, 100).done_ns;
        check(grown ? "zero-length phases, grown list: program after low"
                    : "zero-length phases, bounded list: program after low",
              done, grown ? 770 : 1097);
        check("zero-length phases: no two bus phases overlap",
              phase_overlaps(), 0);
        nand_media_destroy(&m);
    }

    /*
     * Random op streams with start times that run back by up to 300 us, on
     * every timing mode: no two bus phases that ever ran overlap. A small
     * cap makes older ops fall behind the prune mark often; the bounded
     * list takes its own rule. Variant 3 turns the page register hold off,
     * so a program sends its command and data at once.
     */
    {
        uint64_t bad = 0, phases = 0;

        for (int mode = 0; mode < ONFI_NUM_MODES; mode++) {
            for (int v = 0; v < 4; v++) {
                OnfiTiming tv = derive(mode, 0, 16384, v != 1, 0, &rc);
                uint64_t now = 0;

                order_config(&cfg, &tv, 2, v != 1);
                cfg.timeline = &logged_timeline;
                cfg.policy.bus_res_unbounded = v != 2;
                cfg.policy.page_reg_hold = v != 3;
                nand_media_init(&m, &cfg);
                if (v == 0 || v == 3) {
                    m.bus_res[0].hist_cap = 8;
                    m.bus_res[1].hist_cap = 8;
                }
                rng_state = 1000 + mode * 3 + v;
                for (int i = 0; i < 1500; i++) {
                    NandLoc l = { .ch = rng() % T_CHS, .lun = rng() % T_LUNS,
                                  .pl = rng() % 2 };
                    NandLoc g[2] = { l, l };
                    uint64_t back = rng() % 300000;
                    uint64_t st = now > back ? now - back : 0;
                    uint32_t k = rng() % 8;

                    g[0].pl = 0;
                    g[1].pl = 1;
                    now += rng() % 20000;
                    if (k < 3) {
                        nand_media_op(&m, &l, NAND_MEDIA_READ, st);
                    } else if (k < 5) {
                        nand_media_op(&m, &l, NAND_MEDIA_PROGRAM, st);
                    } else if (k == 5) {
                        nand_media_op(&m, &l, NAND_MEDIA_ERASE, st);
                    } else if (k == 6) {
                        nand_media_multiplane(&m, g, 2,
                                              (NandMediaOp)(rng() % 3), st);
                    } else {
                        nand_media_copyback(&m, &l, &l, st);
                    }
                }
                for (int ch = 0; ch < T_CHS; ch++) {
                    phases += phase_log[ch].n;
                }
                bad += phase_overlaps();
                nand_media_destroy(&m);
            }
        }
        printf("# %llu bus phases checked\n", (unsigned long long)phases);
        check("no two bus phases overlap, every mode, older ops", bad, 0);
    }
}

/*
 * SCA protocol (Section 5). The CA bus has its own log; a CA phase of one
 * packet is an SCE or SCT, and every data burst must hold exactly its own
 * two: SCE at its start, SCT one tail before its end.
 */
static PhaseLog ca_log[T_CHS];

static void log_ca(void *o, uint32_t ch, uint64_t start, uint64_t end)
{
    PhaseLog *l = &ca_log[ch % T_CHS];

    (void)o;
    if (l->n == l->cap) {
        l->cap = l->cap ? 2 * l->cap : 1024;
        l->r = realloc(l->r, l->cap * sizeof(*l->r));
        if (!l->r) {
            abort();
        }
    }
    l->r[l->n].start = start;
    l->r[l->n++].end = end;
}

static const NandTimelineOps sca_timeline = {
    .ch_avail = t_ch, .lun_avail = t_lun, .plane_avail = t_pl,
    .bus_phase = log_phase, .ca_phase = log_ca,
};

/* is there a CA phase of exactly [s, s + len) in the sorted log @l */
static bool ca_has(const PhaseLog *l, uint64_t s, uint64_t len)
{
    size_t lo = 0, hi = l->n;

    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;

        if (l->r[mid].start < s) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo < l->n && l->r[lo].start == s && l->r[lo].end == s + len;
}

/*
 * Overlaps on both buses, plus bursts without their own SCE and SCT and
 * packets outside a burst; clears both logs.
 */
static uint64_t sca_violations(uint64_t pkt, uint64_t tail)
{
    uint64_t bad = 0;

    for (int ch = 0; ch < T_CHS; ch++) {
        PhaseLog *d = &phase_log[ch];
        PhaseLog *c = &ca_log[ch];
        uint64_t packets = 0, end = 0;

        if (c->n > 1) {
            qsort(c->r, c->n, sizeof(*c->r), cmp_start);
        }
        for (size_t i = 0; i < c->n; i++) {
            if (i && c->r[i].start < end) {
                bad++;
            }
            end = c->r[i].end > end ? c->r[i].end : end;
            packets += c->r[i].end - c->r[i].start == pkt;
        }
        for (size_t i = 0; i < d->n; i++) {
            bad += !ca_has(c, d->r[i].start, pkt);
            bad += !ca_has(c, d->r[i].end - tail, pkt);
        }
        bad += packets != 2 * d->n;
        free(c->r);
        memset(c, 0, sizeof(*c));
    }
    return bad + phase_overlaps();
}

static void sca_config(NandMediaConfig *cfg, const OnfiTiming *t,
                       uint32_t planes, bool multi_lun)
{
    order_config(cfg, t, planes, multi_lun);
    cfg->timing.din_gap_ns = t->din_gap_ns;
    cfg->timing.dout_edge_ns = t->dout_edge_ns;
    cfg->timing.ccs_ns = t->ccs_ns;
    cfg->timing.sca_packet_ns = t->sca_packet_ns;
    cfg->timing.sca_tail_ns = t->sca_tail_ns;
    cfg->policy.ca_separate = true;
}

static OnfiTiming derive_sca(int mode, uint64_t bytes, bool multi_lun,
                             uint64_t tccs)
{
    OnfiInput in = {
        .mode = mode, .page_bytes = bytes, .col_cycles = 2, .row_cycles = 3,
        .multi_lun = multi_lun, .tccs_ns = tccs, .sca = true,
    };
    OnfiTiming t;

    memset(&t, 0, sizeof(t));
    onfi_derive(&in, &t);
    return t;
}

/*
 * Mode 26, 16 KiB, one LUN: read command 184, status 241, select 84, read
 * burst 168 + 3417; program command 84, tCDL gap 313, write burst
 * 149 + 3417, 10h 112. Packets are 12 ns.
 */
static void test_sca(void)
{
    NandMediaConfig cfg;
    NandMedia m;
    NandLoc l0 = { .ch = 0, .lun = 0 };
    NandLoc l1 = { .ch = 0, .lun = 1 };
    OnfiTiming t;
    uint64_t rd, d0;

    printf("# SCA derived lengths, mode 26, 2 column + 3 row cycles\n");
    t = derive_sca(26, 16384, false, 0);
    check("read command: 7 packets + tWB", t.rd_cmd_ns, 7 * 12 + 100);
    check("program command: 80h, 5 address, 12h", t.wr_cmd_ns, 7 * 12);
    check("tCDL gap: 400 - (12 + 50 + 25)", t.din_gap_ns, 313);
    check("write burst edges: 87 + 62", t.din_burst_ns, 149);
    check("10h + tWB", t.wr_post_ns, 112);
    check("erase command: 5 packets + tWB", t.er_cmd_ns, 160);
    check("copyback read command", t.cb_rd_cmd_ns, 184);
    check("copyback program command: 8 packets + tWB", t.cb_wr_cmd_ns, 196);
    /* 12 + 80 + 4 + 20 + 40 + 85 */
    check("status, one LUN (70h)", t.status_ns, 241);
    check("column select: 06h, 5 address, E0h", t.dout_pre_ns, 84);
    check("no tail after a burst", t.dout_post_ns, 0);
    /* 12 + 50 + 30 + (25 + 0.209) + 50 */
    check("read burst edges, mode 26", t.dout_edge_ns, 168);
    check("packet", t.sca_packet_ns, 12);
    check("SCT and hold", t.sca_tail_ns, 62);
    check("page unchanged", t.page_xfer_ns, 3417);
    t = derive_sca(26, 16384, true, 300);
    check("status, several LUNs (78h + 3 row)", t.status_ns, 277);
    check("tCCSR is its own wait", t.ccs_ns, 300);
    check("tCCSR is not in the select", t.dout_pre_ns, 84);
    t = derive_sca(0, 16384, false, 0);
    /* tRPST_CA = 25 + 15 at mode 0 */
    check("read burst edges, mode 0", t.dout_edge_ns, 12 + 50 + 30 + 40 + 50);

    printf("# SCA ops on an idle LUN\n");
    t = derive_sca(26, 16384, false, 0);
    sca_config(&cfg, &t, 1, false);
    nand_media_init(&m, &cfg);
    rd = nand_media_op(&m, &l0, NAND_MEDIA_READ, 0).latency_ns;
    check("read", rd, 184 + 40000 + 241 + 84 + 168 + 3417);
    nand_media_destroy(&m);
    sca_config(&cfg, &t, 1, false);
    nand_media_init(&m, &cfg);
    check("program", nand_media_op(&m, &l0, NAND_MEDIA_PROGRAM, 0).latency_ns,
          84 + 313 + 149 + 3417 + 112 + 200000 + 241);
    nand_media_destroy(&m);
    sca_config(&cfg, &t, 1, false);
    nand_media_init(&m, &cfg);
    check("erase", nand_media_op(&m, &l0, NAND_MEDIA_ERASE, 0).latency_ns,
          160 + 2000000 + 241);
    nand_media_destroy(&m);
    sca_config(&cfg, &t, 1, false);
    nand_media_init(&m, &cfg);
    check("copyback", nand_media_copyback(&m, &l0, &l1, 0).latency_ns,
          184 + 40000 + 241 + 196 + 200000 + 241);
    nand_media_destroy(&m);
    sca_config(&cfg, &t, 2, false);
    nand_media_init(&m, &cfg);
    {
        NandLoc p[2] = { { .ch = 0, .lun = 0, .pl = 0 },
                         { .ch = 0, .lun = 0, .pl = 1 } };

        /* per plane: command, tCDL, burst, 11h or 10h; one tDBSY gap */
        check("multi-plane program, tDBSY = tPLPBSY",
              nand_media_multiplane(&m, p, 2, NAND_MEDIA_PROGRAM,
                                    0).latency_ns,
              2 * (84 + 313 + 149 + 3417 + 112) + 500 + 200000 + 241);
    }
    nand_media_destroy(&m);
    sca_config(&cfg, &t, 2, false);
    nand_media_init(&m, &cfg);
    {
        NandLoc p[2] = { { .ch = 0, .lun = 0, .pl = 0 },
                         { .ch = 0, .lun = 0, .pl = 1 } };

        check("multi-plane read",
              nand_media_multiplane(&m, p, 2, NAND_MEDIA_READ, 0).latency_ns,
              2 * 184 + 500 + 40000 + 241 + 2 * (84 + 168 + 3417));
    }
    nand_media_destroy(&m);

    printf("# SCA: commands leave the data bus\n");
    t = derive_sca(26, 16384, true, 0);
    sca_config(&cfg, &t, 1, true);
    cfg.timeline = &sca_timeline;
    nand_media_init(&m, &cfg);
    d0 = nand_media_op(&m, &l0, NAND_MEDIA_READ, 0).done_ns;
    {
        /* a read of LUN 1 that starts 50 ns into LUN 0's burst */
        uint64_t burst = d0 - (168 + 3417);
        NandOpCompletion c1 = nand_media_op(&m, &l1, NAND_MEDIA_READ,
                                            burst + 50);

        check("LUN 0 burst starts after its select",
              burst, 184 + 40000 + 277 + 84);
        check("LUN 1 command during LUN 0's burst: an idle read",
              c1.latency_ns, 184 + 40000 + 277 + 84 + 168 + 3417);
    }
    check("LUN 0 left in place, SCE and SCT inside their bursts",
          sca_violations(12, 62), 0);
    nand_media_destroy(&m);

    /*
     * A delayed SCT moves the whole burst. LUN 1's erase command holds CA
     * on [44000, 44160). LUN 0's burst would start at 40545 with its SCT
     * at 40545 + 3585 - 62 = 44068, inside that command; the burst moves
     * so its SCT starts at 44160, and the read ends at 44160 + 62.
     */
    sca_config(&cfg, &t, 1, true);
    nand_media_init(&m, &cfg);
    nand_media_op(&m, &l1, NAND_MEDIA_ERASE, 44000);
    check("a busy CA bus moves the SCT and its burst",
          nand_media_op(&m, &l0, NAND_MEDIA_READ, 0).done_ns, 44160 + 62);
    nand_media_destroy(&m);

    printf("# SCA: an older op uses an earlier gap on both buses\n");
    sca_config(&cfg, &t, 1, true);
    nand_media_init(&m, &cfg);
    nand_media_op(&m, &l0, NAND_MEDIA_READ, 100000);
    check("older read on an idle LUN",
          nand_media_op(&m, &l1, NAND_MEDIA_READ, 50000).latency_ns,
          184 + 40000 + 277 + 84 + 168 + 3417);
    nand_media_destroy(&m);

    /*
     * A random stream with older ops, every mode, with and without a small
     * history cap: no overlap on either bus, and every SCE and SCT inside
     * its own burst.
     */
    {
        uint64_t bad = 0, bursts = 0;

        for (int mode = 0; mode < ONFI_NUM_MODES; mode++) {
            for (int v = 0; v < 2; v++) {
                OnfiTiming tv = derive_sca(mode, 16384, true, 40 * v);
                uint64_t now = 0;

                sca_config(&cfg, &tv, 2, true);
                cfg.timeline = &sca_timeline;
                nand_media_init(&m, &cfg);
                if (v == 0) {
                    for (int ch = 0; ch < T_CHS; ch++) {
                        m.bus_res[ch].hist_cap = 8;
                        m.ca_res[ch].hist_cap = 8;
                    }
                }
                rng_state = 5000 + mode * 3 + v;
                for (int i = 0; i < 1500; i++) {
                    NandLoc l = { .ch = rng() % T_CHS, .lun = rng() % T_LUNS,
                                  .pl = rng() % 2 };
                    NandLoc g[2] = { l, l };
                    uint64_t back = rng() % 300000;
                    uint64_t st = now > back ? now - back : 0;
                    uint32_t k = rng() % 8;

                    g[0].pl = 0;
                    g[1].pl = 1;
                    now += rng() % 20000;
                    if (k < 3) {
                        nand_media_op(&m, &l, NAND_MEDIA_READ, st);
                    } else if (k < 5) {
                        nand_media_op(&m, &l, NAND_MEDIA_PROGRAM, st);
                    } else if (k == 5) {
                        nand_media_op(&m, &l, NAND_MEDIA_ERASE, st);
                    } else if (k == 6) {
                        nand_media_multiplane(&m, g, 2,
                                              (NandMediaOp)(rng() % 3), st);
                    } else {
                        nand_media_copyback(&m, &l, &l, st);
                    }
                }
                for (int ch = 0; ch < T_CHS; ch++) {
                    bursts += phase_log[ch].n;
                }
                bad += sca_violations(tv.sca_packet_ns, tv.sca_tail_ns);
                nand_media_destroy(&m);
            }
        }
        printf("# %llu SCA bursts checked\n", (unsigned long long)bursts);
        check("SCA: no overlap on either bus, packets in their bursts",
              bad, 0);
    }
}

/*
 * A fixed mixed sequence with every profile field at 0. After each op the
 * hash takes the completion, every channel, LUN and plane time and the
 * suspend state; at the end it takes every booked bus window. The runs cover
 * the staged and plain paths, flat and table timing, partial transfers,
 * suspend, and bounded and unbounded window lists. LEGACY_HASH is what
 * master's nand-media.c gives for the same runs, so the profile fields
 * change nothing when unset.
 */
#define LEGACY_HASH 0x19a76fe047b587bdULL

static uint64_t fnv(uint64_t h, uint64_t v)
{
    for (int i = 0; i < 8; i++) {
        h ^= (v >> (8 * i)) & 0xff;
        h *= 0x100000001b3ULL;
    }
    return h;
}

static uint32_t rng(void)
{
    rng_state = rng_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return (uint32_t)(rng_state >> 33);
}

static uint64_t hash_state(const NandMedia *m, uint64_t h)
{
    size_t npos = (size_t)T_CHS * T_LUNS * 2;

    for (int i = 0; i < T_CHS; i++) {
        h = fnv(h, ch_avail[i]);
    }
    for (int i = 0; i < T_CHS * T_LUNS; i++) {
        h = fnv(h, lun_avail[i]);
    }
    for (int i = 0; i < T_CHS * T_LUNS * 2; i++) {
        h = fnv(h, pl_avail[i]);
    }
    if (m->susp) {
        for (size_t i = 0; i < npos; i++) {
            h = fnv(h, m->susp[i].pe_end);
            h = fnv(h, m->susp[i].rd_end);
        }
    }
    return h;
}

static uint64_t legacy_run(bool staged, bool suspend, bool unbounded,
                           NandArrayContend contend, bool table,
                           bool partial, uint64_t h)
{
    NandMediaConfig cfg;
    NandMedia m;
    uint64_t now = 0;

    memset(&cfg, 0, sizeof(cfg));
    reset_timelines();
    cfg.nchs = T_CHS;
    cfg.luns_per_ch = T_LUNS;
    cfg.planes_per_lun = 2;
    cfg.timing.rd_ns = 40000;
    cfg.timing.wr_ns = 200000;
    cfg.timing.er_ns = 2000000;
    if (staged) {
        cfg.timing.cmd_addr_ns = 1000;
        cfg.timing.page_xfer_ns = 10000;
        cfg.timing.status_ns = 500;
        cfg.policy.channel_mode = NAND_CH_STAGED;
    }
    cfg.timing.tplpbsy_ns = 700;
    cfg.timing.tplrbsy_ns = 300;
    cfg.timing.tplebsy_ns = 900;
    cfg.timing.tsusp_ns = 2000;
    cfg.policy.pe_suspend = suspend;
    cfg.policy.bus_res_unbounded = unbounded;
    cfg.policy.array_contend = contend;
    cfg.policy.use_flat_timing = !table;
    if (table) {
        for (int p = 0; p < NAND_MEDIA_MAX_PGTYPE; p++) {
            cfg.timing.rd_table_ns[3][p] = 30000 + 10000 * p;
            cfg.timing.wr_table_ns[3][p] = 150000 + 100000 * p;
        }
        cfg.timing.er_table_ns[3] = 3000000;
    }
    cfg.timing.ecc_step_ns = 5000;
    cfg.timing.ecc_pe_per_tier = 750;
    cfg.timing.ecc_max_tiers = 4;
    cfg.policy.ecc_on_read = true;
    if (partial) {
        cfg.secs_per_page = 8;
    }
    cfg.timeline = &timeline;
    nand_media_init(&m, &cfg);

    rng_state = 42;
    for (int i = 0; i < 3000; i++) {
        NandLoc l = { .ch = rng() % T_CHS, .lun = rng() % T_LUNS,
                      .pl = rng() % 2, .pg = rng() % 64,
                      .flash_type = 3, .page_type = rng() % 3,
                      .pe_cycles = rng() % 3000,
                      .xfer_secs = partial ? rng() % 9 : 0 };
        NandLoc g[2] = { l, l };
        uint32_t k = rng() % 10;
        NandOpCompletion c;

        g[0].pl = 0;
        g[1].pl = 1;
        now += rng() % 3000;
        if (k < 5) {
            c = nand_media_op(&m, &l, NAND_MEDIA_READ, now);
        } else if (k < 7) {
            c = nand_media_op(&m, &l, NAND_MEDIA_PROGRAM, now);
        } else if (k == 7) {
            c = nand_media_op(&m, &l, NAND_MEDIA_ERASE, now);
        } else if (k == 8) {
            c = nand_media_multiplane(&m, g, 2, (NandMediaOp)(rng() % 3),
                                      now);
        } else {
            NandLoc d = l;

            d.pg = (l.pg + 1) % 64;
            c = nand_media_copyback(&m, &l, &d, now);
        }
        h = fnv(h, c.done_ns);
        h = fnv(h, c.latency_ns);
        h = hash_state(&m, h);
    }
    if (m.bus_res) {
        for (int ch = 0; ch < T_CHS; ch++) {
            const NandBusResList *l = &m.bus_res[ch];
            const NandBusRes *r = l->grown ? l->grown : l->r;

            h = fnv(h, (uint64_t)l->n);
            for (int i = 0; i < l->n; i++) {
                h = fnv(h, r[i].start);
                h = fnv(h, r[i].end);
            }
        }
    }
    nand_media_destroy(&m);
    return h;
}

static void test_legacy_hash(void)
{
    uint64_t h = 0xcbf29ce484222325ULL;

    printf("# every profile field 0: same op math as master\n");
    h = legacy_run(true, false, false, NAND_CONTEND_LUN_ONLY, false, false, h);
    h = legacy_run(true, true, false, NAND_CONTEND_LUN_ONLY, false, false, h);
    h = legacy_run(true, false, true, NAND_CONTEND_LUN_ONLY, false, false, h);
    h = legacy_run(false, false, false, NAND_CONTEND_LUN_ONLY, false, false,
                   h);
    h = legacy_run(false, true, false, NAND_CONTEND_LUN_AND_PLANE, false,
                   false, h);
    h = legacy_run(true, false, false, NAND_CONTEND_PLANE_ONLY, false, false,
                   h);
    h = legacy_run(true, true, false, NAND_CONTEND_LUN_ONLY, true, false, h);
    h = legacy_run(true, false, false, NAND_CONTEND_LUN_ONLY, false, true, h);
    h = legacy_run(false, true, false, NAND_CONTEND_PLANE_ONLY, true, true, h);
    printf("# legacy hash 0x%016llx\n", (unsigned long long)h);
    check("legacy hash matches master", h, LEGACY_HASH);
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);

    test_mode_table();
    test_page_xfer();
    test_command_fields();
    test_param_page();
    test_media_phases();
    test_onfi_order();
    test_bus_history();
    test_sca();
    test_legacy_hash();
    printf("1..%d\n", ntests);
    return failures ? 1 : 0;
}
