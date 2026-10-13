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

    /*
     * One busy LUN, each read issued 100 ns before the one before ends: at
     * most two ops are in flight, so at most a few windows stay booked.
     */
    order_config(&cfg, &t, 1, false);
    nand_media_init(&m, &cfg);
    {
        uint64_t now = 0;
        int most = 0;

        for (int i = 0; i < 2000; i++) {
            now = nand_media_op(&m, &l0, NAND_MEDIA_READ, now).done_ns - 100;
            most = m.bus_res[0].n > most ? m.bus_res[0].n : most;
        }
        check("windows stay few under a busy LUN", most <= 8, 1);
    }
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

static uint64_t rng_state;

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
    test_media_phases();
    test_onfi_order();
    test_legacy_hash();
    printf("1..%d\n", ntests);
    return failures ? 1 : 0;
}
