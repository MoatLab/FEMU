/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Unit test for the command lines of events_file (femu-fsched.c): the
 * grammar and its refusals, the view checks, the matcher, and the fault
 * record ring (femu-frec.c) with a producer thread against a reader. Each
 * refusal has an accepted twin that differs in one value, so a check that
 * refuses everything fails here too. The seeds come from a search for
 * first draws of 0 and 999999, the two ends of the odds comparison.
 */
#include "qemu/osdep.h"
#include <inttypes.h>
#include <stdarg.h>
#include <pthread.h>
#include <sched.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#include "hw/femu/femu-fsched.c"
#define FEMU_FR_TEST_HOOKS
#include "hw/femu/femu-frec.c"

/* TAP output, as meson runs this test with the TAP protocol */
static int ntests;
static int failures;

#define CHECK(cond) do {                                                \
    ntests++;                                                           \
    if (cond) {                                                         \
        printf("ok %d - line %d\n", ntests, __LINE__);                  \
    } else {                                                            \
        printf("not ok %d - line %d: %s\n", ntests, __LINE__, #cond);   \
        failures++;                                                     \
    }                                                                   \
} while (0)

/* first draws: 0 for SEED_ZERO, 999999 for SEED_TOP */
#define SEED_ZERO   1147169
#define SEED_TOP    221237

static const uint64_t nsze2[2] = { 1024, 512 };

/* bbssd with every option the actions need */
static FemuFsDev dev_full(void)
{
    FemuFsDev d = {
        .bbssd = true, .power_loss = true, .vwc = true, .sdc = true,
        .nr_ns = 2, .nsze = nsze2,
    };

    return d;
}

static bool parse(const FemuFsDev *d, const char *s, FemuFsLine *l,
                  char *err)
{
    err[0] = '\0';
    return femu_fs_parse(d, s, 7, l, err, FEMU_FS_ERR_LEN);
}

/* @s is refused on @d, with @msg in the reason */
static void refused(const FemuFsDev *d, const char *s, const char *msg)
{
    FemuFsLine l;
    char err[FEMU_FS_ERR_LEN];
    bool ok = parse(d, s, &l, err);

    if (ok || !strstr(err, msg)) {
        printf("# refused '%s': ok %d reason '%s'\n", s, ok, err);
    }
    CHECK(!ok && strstr(err, msg));
}

static void accepted(const FemuFsDev *d, const char *s)
{
    FemuFsLine l;
    char err[FEMU_FS_ERR_LEN];
    bool ok = parse(d, s, &l, err);

    if (!ok) {
        printf("# accepted '%s': reason '%s'\n", s, err);
    }
    CHECK(ok && l.line == 7);
}

static void test_grammar(void)
{
    FemuFsDev d = dev_full();
    FemuFsLine l;
    char err[FEMU_FS_ERR_LEN];

    /* each pair: an accepted line, then its twin past one limit */
    accepted(&d, "@write#1 write-fail");
    refused(&d, "@write#0 write-fail", "#N takes N from 1");
    accepted(&d, "@write#18446744073709551615 write-fail");
    refused(&d, "@write#18446744073709551616 write-fail", "#N takes N");
    refused(&d, "@write#99999999999999999999999 write-fail", "#N takes N");
    refused(&d, "@write#3x write-fail", "#N takes N");
    accepted(&d, "@write%1000000~0 write-fail");
    refused(&d, "@write%1000001~0 write-fail", "%PPM~SEED takes");
    accepted(&d, "@write%0~9223372036854775807 write-fail");
    refused(&d, "@write%0~9223372036854775808 write-fail", "%PPM~SEED");
    refused(&d, "@write%5 write-fail", "%PPM~SEED");
    refused(&d, "@write write-fail", "ends in #N or %PPM~SEED");
    accepted(&d, "@any#1 delay ms=600000");
    refused(&d, "@any#1 delay ms=600001", "ms= takes 1 to 600000");
    refused(&d, "@any#1 delay ms=0", "ms= takes 1");
    refused(&d, "@any#1 delay", "needs ms=");
    accepted(&d, "@any#1 power-loss keep=1000000 seed=5 grain=lba at=pre");
    refused(&d, "@any#1 power-loss keep=1000001", "keep= takes 0 to");
    refused(&d, "@any#1 power-loss at=post", "at= takes pre");
    refused(&d, "@any#1 power-loss grain=block", "grain= takes page");

    /* duplicates and unknown names */
    refused(&d, "@write,ns=1,ns=1#1 write-fail", "ns= given twice");
    refused(&d, "@write,lba=0-1,lba=0-1#1 write-fail", "lba= given twice");
    refused(&d, "@write#1 wb-fail mode=unc mode=old", "mode= given twice");
    refused(&d, "@write,zone=1#1 write-fail", "unknown match key");
    refused(&d, "@write#1 write-fail mode=unc", "takes no option 'mode'");
    refused(&d, "@write#1 wb-fail frob", "takes no option 'frob'");
    refused(&d, "@write#1 frob", "unknown action 'frob'");
    refused(&d, "@trim#1 hang", "unknown op '@trim'");
    refused(&d, "@dsm#1 hang", "are not matchable");
    refused(&d, "@copy#1 hang", "are not matchable");
    refused(&d, "@write#1", "a command line is");
    refused(&d, "@any#1 ana=1:2 extra", "takes no option 'extra'");

    /* the trigger an action takes */
    accepted(&d, "@wzero#1 write-fail");
    accepted(&d, "@fua#1 write-fail");
    refused(&d, "@read#1 write-fail", "write-fail takes @write, @fua or");
    refused(&d, "@any#1 write-fail", "write-fail takes");
    accepted(&d, "@write#1 wb-fail mode=old report=once aer=on");
    refused(&d, "@fua#1 wb-fail", "wb-fail takes @write only");
    accepted(&d, "@fua#1 fua-lie");
    refused(&d, "@write#1 fua-lie", "fua-lie takes @fua only");
    accepted(&d, "@read#1 read-unc");
    refused(&d, "@write#1 read-unc", "read-unc takes @read only");
    accepted(&d, "@flush#1 flush-lie");
    refused(&d, "@any#1 flush-lie", "flush-lie takes @flush only");
    accepted(&d, "@write#1 sdc kind=misdirect lba=1023");
    refused(&d, "@write#1 sdc kind=misdirect lba=1024", "lba= of sdc");
    refused(&d, "@write#1 sdc", "needs kind=");
    refused(&d, "@read#1 sdc kind=flip", "sdc takes @write only");

    /* the match keys against the namespaces */
    accepted(&d, "@write,ns=2,lba=0-511#1 hang");
    refused(&d, "@write,ns=2,lba=0-512#1 hang", "is past the namespace");
    accepted(&d, "@write,lba=0-1023#1 hang");
    refused(&d, "@write,lba=0-1024#1 hang", "is past the namespace");
    refused(&d, "@write,lba=5-4#1 hang", "first <= last");
    refused(&d, "@write,ns=3#1 hang", "ns= names no namespace");
    refused(&d, "@write,ns=0#1 hang", "ns= names no namespace");
    accepted(&d, "@flush,ns=1#1 hang");
    refused(&d, "@flush,lba=0-1#1 hang", "@flush has no LBA range");

    /* the parse keeps the values */
    CHECK(parse(&d, "@write,ns=1,lba=8-15%250000~42 delay ms=9", &l, err));
    CHECK(l.op == FEMU_FS_OP_WRITE && l.has_ns && l.nsid == 1 &&
          l.lba_lo == 8 && l.lba_hi == 15 && l.ppm_trigger &&
          l.ppm == 250000 && l.seed == 42 && l.rng == 42 &&
          l.act == FEMU_FS_ACT_DELAY && l.grp == FEMU_FS_GRP_TIMING &&
          l.delay_ms == 9);
    CHECK(parse(&d, "@any#4 slow=0:1:500", &l, err));
    CHECK(l.act == FEMU_FS_ACT_SLOW && !strcmp(l.action, "slow=0:1:500") &&
          l.grp == FEMU_FS_GRP_NONE && l.nth == 4);
}

/* parse @s on @d, which must succeed, into @l */
static void parse_ok(const FemuFsDev *d, const char *s, FemuFsLine *l)
{
    char err[FEMU_FS_ERR_LEN];
    bool ok = parse(d, s, l, err);

    if (!ok) {
        printf("# '%s': %s\n", s, err);
    }
    CHECK(ok && l->line == 7);
}

/* every option keeps its value, and an absent one its default */
static void test_options(void)
{
    FemuFsDev dev = dev_full();
    const FemuFsDev *d = &dev;
    FemuFsLine l;

    parse_ok(d, "@any#1 power-loss", &l);
    CHECK(!l.has_keep && l.keep == 0 && l.grain == FEMU_FS_GRAIN_PAGE &&
          l.keep_seed == 0 && l.grp == FEMU_FS_GRP_TERMINAL);
    parse_ok(d, "@any#1 power-loss at=pre keep=250000 grain=lba seed=77",
             &l);
    CHECK(l.has_keep && l.keep == 250000 && l.grain == FEMU_FS_GRAIN_LBA &&
          l.keep_seed == 77);
    parse_ok(d, "@any#1 power-loss keep=0", &l);
    CHECK(l.has_keep && l.keep == 0);
    parse_ok(d, "@write#1 wb-fail", &l);
    CHECK(l.wb_mode == FEMU_FS_WB_UNC &&
          l.wb_report == FEMU_FS_REPORT_STICKY && !l.wb_aer &&
          l.act == FEMU_FS_ACT_WB_FAIL && l.grp == FEMU_FS_GRP_DATA);
    parse_ok(d, "@write#1 wb-fail mode=old report=once aer=on", &l);
    CHECK(l.wb_mode == FEMU_FS_WB_OLD &&
          l.wb_report == FEMU_FS_REPORT_ONCE && l.wb_aer);
    parse_ok(d, "@write#1 wb-fail mode=unc report=sticky aer=off", &l);
    CHECK(l.wb_mode == FEMU_FS_WB_UNC &&
          l.wb_report == FEMU_FS_REPORT_STICKY && !l.wb_aer);
    parse_ok(d, "@write#1 sdc kind=flip", &l);
    CHECK(l.sdc_kind == FEMU_FS_SDC_FLIP && !l.has_sdc_lba &&
          l.sdc_lba == 0 && l.grp == FEMU_FS_GRP_SDC);
    parse_ok(d, "@write#1 sdc kind=lost lba=5", &l);
    CHECK(l.sdc_kind == FEMU_FS_SDC_LOST && l.has_sdc_lba && l.sdc_lba == 5);
    parse_ok(d, "@write#1 sdc kind=misdirect lba=0", &l);
    CHECK(l.sdc_kind == FEMU_FS_SDC_MISDIRECT && l.has_sdc_lba &&
          l.sdc_lba == 0);
    parse_ok(d, "@any#1 delay ms=600000", &l);
    CHECK(l.delay_ms == 600000);
    parse_ok(d, "@any#1 cfs at=pre", &l);
    CHECK(l.act == FEMU_FS_ACT_CFS && l.grp == FEMU_FS_GRP_TERMINAL);
    parse_ok(d, "@write#18446744073709551615 hang", &l);
    CHECK(!l.ppm_trigger && l.nth == UINT64_MAX && !l.has_ns &&
          !l.has_lba && l.op == FEMU_FS_OP_WRITE);
    parse_ok(d, "@fua,ns=2,lba=0-511%0~9223372036854775807 fua-lie", &l);
    CHECK(l.ppm_trigger && l.ppm == 0 && l.seed == INT64_MAX &&
          l.op == FEMU_FS_OP_FUA && l.has_ns && l.nsid == 2 &&
          l.has_lba && l.lba_lo == 0 && l.lba_hi == 511);
}

static void test_device(void)
{
    FemuFsDev d = dev_full();
    FemuFsDev x;

    x = d;
    x.bbssd = false;
    refused(&x, "@any#1 hang", "not supported with a mode other than bbssd");
    x = d;
    x.ns_mgmt = true;
    refused(&x, "@any#1 hang", "not supported with ns_mgmt");
    x = d;
    x.namespace_modes = true;
    refused(&x, "@any#1 hang", "with namespace_modes");
    x = d;
    x.subsys = true;
    refused(&x, "@any#1 hang", "with subsys");
    x = d;
    x.shared_ftl = true;
    refused(&x, "@any#1 hang", "with shared_ftl");
    x = d;
    x.cxl_ssd = true;
    refused(&x, "@any#1 hang", "with cxl_ssd");

    /* power_loss off: the faults with no model there */
    x = d;
    x.power_loss = false;
    x.sdc = false;
    refused(&x, "@any#1 power-loss", "power-loss needs power_loss=on");
    refused(&x, "@any#1 cfs", "cfs needs power_loss=on");
    refused(&x, "@write#1 wb-fail", "wb-fail needs power_loss=on");
    refused(&x, "@fua#1 fua-lie", "fua-lie needs power_loss=on");
    refused(&x, "@flush#1 flush-lie", "flush-lie needs power_loss=on");
    refused(&x, "@write#1 sdc kind=flip", "sdc needs sdc=on");
    accepted(&x, "@any#1 hang");
    accepted(&x, "@any#1 delay ms=5");
    accepted(&x, "@read#1 read-unc");
    accepted(&x, "@write#1 write-fail");

    x = d;
    x.vwc = false;
    refused(&x, "@write#1 wb-fail", "wb-fail needs vwc=1");
    refused(&x, "@flush#1 flush-lie", "flush-lie needs vwc=1");
    accepted(&x, "@fua#1 fua-lie");

    x = d;
    x.durable_at_done = true;
    refused(&x, "@any#1 power-loss", "power-loss is not supported with "
            "durable_at_done");
    refused(&x, "@write#1 wb-fail", "wb-fail is not supported with durable");
    refused(&x, "@fua#1 fua-lie", "fua-lie is not supported with durable");
    refused(&x, "@flush#1 flush-lie", "flush-lie is not supported");
    accepted(&x, "@any#1 cfs");

    x = d;
    x.buffer_low = true;
    refused(&x, "@write#1 wb-fail", "not supported with buffer_low_pcent");
    x = d;
    x.fdp = true;
    refused(&x, "@write#1 wb-fail", "not supported with FDP");

    x = d;
    x.awupf_lbas = 2;
    refused(&x, "@any#1 power-loss keep=5 grain=lba", "grain=lba needs");
    accepted(&x, "@any#1 power-loss keep=5 grain=page");
    x.awupf_lbas = 1;
    accepted(&x, "@any#1 power-loss keep=5 grain=lba");
}

static FemuFsView view(uint8_t opc, uint64_t slba, uint32_t nlb, bool fua)
{
    FemuFsView v = { .opc = opc, .nsid = 1, .slba = slba, .nlb = nlb,
                     .fua = fua };

    return v;
}

static void test_view(void)
{
    FemuFsView v;

    v = view(FEMU_FS_OPC_WRITE, 1023, 1, false);
    CHECK(femu_fs_view_ok(&v, 1024, 9, 0, 0));
    v = view(FEMU_FS_OPC_WRITE, 1023, 2, false);
    CHECK(!femu_fs_view_ok(&v, 1024, 9, 0, 0));
    v = view(FEMU_FS_OPC_READ, 1024, 1, false);
    CHECK(!femu_fs_view_ok(&v, 1024, 9, 0, 0));
    /* slba + nlb wraps past 2^64: still out of range */
    v = view(FEMU_FS_OPC_READ, UINT64_MAX - 1, 2, false);
    CHECK(!femu_fs_view_ok(&v, UINT64_MAX, 9, 0, 0));
    v = view(FEMU_FS_OPC_READ, UINT64_MAX - 1, 1, false);
    CHECK(femu_fs_view_ok(&v, UINT64_MAX, 9, 0, 0));
    v = view(FEMU_FS_OPC_READ, 0, 0, false);
    CHECK(!femu_fs_view_ok(&v, 1024, 9, 0, 0));
    /* MDTS of 4 KiB with 512-byte blocks: 8 blocks fit, 9 do not */
    v = view(FEMU_FS_OPC_READ, 0, 8, false);
    CHECK(femu_fs_view_ok(&v, 1024, 9, 0, 12));
    v = view(FEMU_FS_OPC_READ, 0, 9, false);
    CHECK(!femu_fs_view_ok(&v, 1024, 9, 0, 12));
    v = view(FEMU_FS_OPC_WZERO, 0, 9, false);
    CHECK(femu_fs_view_ok(&v, 1024, 9, 0, 12));
    v = view(FEMU_FS_OPC_FLUSH, 0, 0, false);
    CHECK(femu_fs_view_ok(&v, 0, 0, 0, 12));
    /*
     * 8 bytes of extended metadata count: 512-byte blocks and an MDTS of
     * 8 KiB take 15 blocks (7800 bytes), not 16 (8320). Write Zeroes
     * moves nothing, so its 16 still pass.
     */
    v = view(FEMU_FS_OPC_READ, 0, 15, false);
    CHECK(femu_fs_view_ok(&v, 1024, 9, 8, 13));
    v = view(FEMU_FS_OPC_READ, 0, 16, false);
    CHECK(femu_fs_view_ok(&v, 1024, 9, 0, 13));
    CHECK(!femu_fs_view_ok(&v, 1024, 9, 8, 13));
    v = view(FEMU_FS_OPC_WZERO, 0, 16, false);
    CHECK(femu_fs_view_ok(&v, 1024, 9, 8, 13));
    /* which metadata counts: extended only, and not a PRACT tuple */
    CHECK(femu_fs_xfer_ms(8, true, 0, 8, false) == 8);
    CHECK(femu_fs_xfer_ms(8, false, 0, 8, false) == 0);
    CHECK(femu_fs_xfer_ms(0, true, 0, 8, false) == 0);
    CHECK(femu_fs_xfer_ms(8, true, 1, 8, true) == 0);
    CHECK(femu_fs_xfer_ms(8, true, 1, 8, false) == 8);
    CHECK(femu_fs_xfer_ms(16, true, 1, 8, true) == 16);
    CHECK(femu_fs_xfer_ms(8, true, 0, 8, true) == 8);
    /* Dataset Management: not in the set */
    v = view(0x09, 0, 1, false);
    CHECK(!femu_fs_view_ok(&v, 1024, 9, 0, 0));
}

/* lines from text, as realize compiles them */
static int lines(FemuFsLine *l, const char *const *text, int nr)
{
    FemuFsDev d = dev_full();
    char err[FEMU_FS_ERR_LEN];

    for (int i = 0; i < nr; i++) {
        if (!femu_fs_parse(&d, text[i], i + 1, &l[i], err, sizeof(err))) {
            printf("# line '%s': %s\n", text[i], err);
            CHECK(0);
        }
    }
    return nr;
}

static void run(FemuFsLine *l, int nr, FemuFsView v, uint8_t *out)
{
    FemuFsView eff;

    femu_fs_match(l, nr, &v, out, NULL, &eff);
}

static void test_nth(void)
{
    static const char *const t[] = { "@write#3 write-fail" };
    FemuFsLine l[1];
    uint8_t out[1];
    int sel = 0;

    lines(l, t, 1);
    for (int i = 1; i <= 5; i++) {
        /* a read between the writes counts for no write line */
        run(l, 1, view(FEMU_FS_OPC_READ, 0, 8, false), out);
        CHECK(out[0] == FEMU_FS_OUT_NONE);
        run(l, 1, view(FEMU_FS_OPC_WRITE, 0, 8, false), out);
        if (out[0] == FEMU_FS_OUT_APPLIED) {
            CHECK(i == 3);
            sel++;
        }
        CHECK(femu_fs_done(l, 1) == (i >= 3));
    }
    CHECK(sel == 1);
    CHECK(l[0].matched == 5 && l[0].selected == 1 && l[0].applied == 1);
}

/*
 * The match count wraps, the one selection stays done: #2 does not come
 * round again after 2^64 matches, and #UINT64_MAX selects once.
 */
static void test_wrap(void)
{
    static const char *const t[] = {
        "@write#2 hang", "@write#18446744073709551615 write-fail",
    };
    FemuFsLine l[2];
    uint8_t out[2];
    int sel[2] = { 0, 0 };

    lines(l, t, 2);
    l[1].matched = UINT64_MAX - 3;
    for (int i = 0; i < 8; i++) {
        run(l, 2, view(FEMU_FS_OPC_WRITE, 0, 1, false), out);
        for (int k = 0; k < 2; k++) {
            sel[k] += out[k] != FEMU_FS_OUT_NONE;
        }
        if (i == 2) {
            /* #UINT64_MAX had its match; #2 jumps near the wrap */
            CHECK(l[1].matched == UINT64_MAX && sel[1] == 1);
            l[0].matched = UINT64_MAX - 1;
        }
    }
    /* both wrapped; #2 met its count 2 a second time */
    CHECK(l[0].matched == 3 && l[1].matched == 4);
    CHECK(sel[0] == 1 && sel[1] == 1);
    CHECK(l[0].selected == 1 && l[1].selected == 1);
    CHECK(femu_fs_done(l, 2));
}

static void test_ppm(void)
{
    uint64_t r;
    FemuFsLine l[1];
    uint8_t out[1];
    static const struct {
        const char *text;
        bool sel;
    } ends[] = {
        { "@write%0~1147169 hang", false },        /* draw 0, PPM 0 */
        { "@write%1~1147169 hang", true },         /* draw 0, PPM 1 */
        { "@write%999999~221237 hang", false },    /* draw 999999 */
        { "@write%1000000~221237 hang", true },
    };

    r = SEED_ZERO;
    CHECK(femu_fs_draw(&r) == 0);
    r = SEED_TOP;
    CHECK(femu_fs_draw(&r) == 999999);
    for (size_t i = 0; i < ARRAY_SIZE(ends); i++) {
        lines(l, &ends[i].text, 1);
        run(l, 1, view(FEMU_FS_OPC_WRITE, 0, 8, false), out);
        CHECK((out[0] == FEMU_FS_OUT_APPLIED) == ends[i].sel);
        CHECK(l[0].matched == 1 && l[0].selected == ends[i].sel);
    }

    /* a seed gives a literal mask; another seed gives another */
    for (uint64_t s = 1; s <= 2; s++) {
        char text[64];
        const char *p = text;
        uint64_t mask = 0;

        snprintf(text, sizeof(text), "@write%%500000~%" PRIu64 " hang", s);
        lines(l, &p, 1);
        for (int i = 0; i < 64; i++) {
            run(l, 1, view(FEMU_FS_OPC_WRITE, 0, 8, false), out);
            if (out[0] == FEMU_FS_OUT_APPLIED) {
                mask |= UINT64_C(1) << i;
            }
        }
        CHECK(mask == (s == 1 ? UINT64_C(0xdc7631c660aa7582) :
                                UINT64_C(0xfabb7a286a7d1755)));
        CHECK(!femu_fs_done(l, 1));
    }
}

static void test_overlap(void)
{
    static const char *const t[] = {
        "@any,lba=8-15%1000000~1 hang",
        "@any,ns=2%1000000~1 delay ms=1",
    };
    static const struct {
        uint64_t slba;
        uint32_t nlb;
        bool hit;
    } w[] = {
        { 0, 8, false }, { 16, 8, false }, { 4, 8, true }, { 15, 1, true },
        { 8, 1, true }, { 0, 24, true }, { 7, 1, false },
    };
    FemuFsLine l[2];
    uint8_t out[2];

    lines(l, t, 2);
    for (size_t i = 0; i < ARRAY_SIZE(w); i++) {
        run(l, 2, view(FEMU_FS_OPC_WRITE, w[i].slba, w[i].nlb, false), out);
        CHECK((out[0] == FEMU_FS_OUT_APPLIED) == w[i].hit);
        CHECK(out[1] == FEMU_FS_OUT_NONE);
    }
    /* a Flush has no blocks, so lba= never matches it, even with @any */
    run(l, 2, view(FEMU_FS_OPC_FLUSH, 0, 0, false), out);
    CHECK(out[0] == FEMU_FS_OUT_NONE);
    CHECK(l[0].matched == 4);
    /* a command on namespace 2 matches ns=2, and lba= of any namespace */
    {
        FemuFsView v2 = view(FEMU_FS_OPC_READ, 0, 1, false);

        v2.nsid = 2;
        run(l, 2, v2, out);
        CHECK(out[0] == FEMU_FS_OUT_NONE && out[1] == FEMU_FS_OUT_APPLIED);
        v2.slba = 9;
        run(l, 2, v2, out);
        CHECK(out[0] == FEMU_FS_OUT_APPLIED && out[1] == FEMU_FS_OUT_NO_EFFECT);
        v2.opc = FEMU_FS_OPC_FLUSH;
        v2.slba = 0;
        v2.nlb = 0;
        run(l, 2, v2, out);
        CHECK(out[0] == FEMU_FS_OUT_NONE && out[1] == FEMU_FS_OUT_APPLIED);
    }
    CHECK(l[0].matched == 5 && l[1].matched == 3);
}

/* the outcomes of one command on @t */
static void outcomes(const char *const *t, int nr, FemuFsView v,
                     const uint8_t *want, FemuFsView *eff)
{
    FemuFsLine l[8];
    uint8_t out[8];
    FemuFsView e;

    lines(l, t, nr);
    femu_fs_match(l, nr, &v, out, NULL, &e);
    for (int i = 0; i < nr; i++) {
        if (out[i] != want[i]) {
            printf("# '%s': outcome %d, want %d\n", t[i], out[i], want[i]);
        }
        CHECK(out[i] == want[i]);
        CHECK(l[i].selected == l[i].applied + l[i].superseded +
              l[i].no_effect);
    }
    if (eff) {
        *eff = e;
    }
}

enum { N = FEMU_FS_OUT_NONE, A = FEMU_FS_OUT_APPLIED,
       S = FEMU_FS_OUT_SUPERSEDED, X = FEMU_FS_OUT_NO_EFFECT };

static void test_groups(void)
{
    FemuFsView wr = view(FEMU_FS_OPC_WRITE, 0, 8, false);
    FemuFsView fua = view(FEMU_FS_OPC_WRITE, 0, 8, true);
    FemuFsView eff;
    FemuFsLine l[1];
    uint8_t out[1];

    /* the examples of the conflict rules, and each in reverse order */
    outcomes((const char *const[]) { "@write#1 write-fail",
                                     "@write#1 wb-fail" },
             2, wr, (const uint8_t[]) { A, S }, NULL);
    outcomes((const char *const[]) { "@write#1 wb-fail",
                                     "@write#1 write-fail" },
             2, wr, (const uint8_t[]) { A, S }, NULL);
    outcomes((const char *const[]) { "@write#1 wb-fail mode=unc",
                                     "@write#1 wb-fail mode=old" },
             2, wr, (const uint8_t[]) { A, S }, NULL);
    outcomes((const char *const[]) { "@fua#1 fua-lie", "@write#1 wb-fail" },
             2, fua, (const uint8_t[]) { A, S }, NULL);
    outcomes((const char *const[]) { "@write#1 wb-fail" },
             1, fua, (const uint8_t[]) { X }, NULL);
    outcomes((const char *const[]) { "@write#1 sdc kind=flip",
                                     "@write#1 sdc kind=lost" },
             2, wr, (const uint8_t[]) { A, S }, NULL);

    /* a cut at pre leaves no other effect; groups apart still select */
    outcomes((const char *const[]) { "@write#1 power-loss", "@write#1 hang",
                                     "@write#1 write-fail",
                                     "@write#1 delay ms=1",
                                     "@any#1 slow=0:0:200" },
             5, wr, (const uint8_t[]) { A, S, X, X, X }, NULL);
    outcomes((const char *const[]) { "@write#1 hang", "@write#1 power-loss" },
             2, wr, (const uint8_t[]) { A, S }, NULL);
    /* hang lets the data winner apply; a delay then has no effect */
    outcomes((const char *const[]) { "@write#1 hang", "@write#1 write-fail",
                                     "@write#1 delay ms=1" },
             3, wr, (const uint8_t[]) { A, A, X }, NULL);
    /* lines with no group each apply */
    outcomes((const char *const[]) { "@any#1 slow=0:0:200",
                                     "@any#1 slow=0:1:200" },
             2, wr, (const uint8_t[]) { A, A }, NULL);
    /* a line that matches but is not selected takes no group */
    outcomes((const char *const[]) { "@write#2 write-fail",
                                     "@write#1 wb-fail" },
             2, wr, (const uint8_t[]) { N, A }, NULL);

    /*
     * Eligibility uses the original command. After an applied fua-lie,
     * a later @fua line still matches, though the command it leaves has
     * no FUA, and against that command the line would not match.
     */
    outcomes((const char *const[]) { "@fua#1 fua-lie", "@fua#1 delay ms=1",
                                     "@write#1 wb-fail" },
             3, fua, (const uint8_t[]) { A, A, S }, &eff);
    CHECK(!eff.fua);
    lines(l, (const char *const[]) { "@fua#1 delay ms=1" }, 1);
    run(l, 1, eff, out);
    CHECK(out[0] == N);
    /* control: a plain Write matches neither @fua line */
    outcomes((const char *const[]) { "@fua#1 fua-lie", "@fua#1 delay ms=1",
                                     "@write#1 wb-fail" },
             3, wr, (const uint8_t[]) { N, N, A }, &eff);
    CHECK(!eff.fua);
}

/* why a winner has no effect: the original FUA, a cut at pre, a hang */
static void test_why(void)
{
    static const char *const t[] = {
        "@write#1 wb-fail", "@write#1 write-fail", "@write#1 delay ms=1",
        "@write#1 hang",
    };
    static const char *const cut[] = {
        "@write#1 power-loss", "@write#1 write-fail", "@write#1 hang",
    };
    FemuFsLine l[4];
    uint8_t out[4];
    uint8_t why[4];
    FemuFsView v = view(FEMU_FS_OPC_WRITE, 0, 8, true);
    FemuFsView eff;

    /* FUA Write: wb-fail wins its group with no effect, as it needs a page */
    lines(l, t, 4);
    memset(why, 0xff, sizeof(why));
    femu_fs_match(l, 4, &v, out, why, &eff);
    CHECK(out[0] == X && why[0] == FEMU_FS_WHY_FUA);
    CHECK(out[1] == S && why[1] == FEMU_FS_WHY_NONE);
    CHECK(out[2] == X && why[2] == FEMU_FS_WHY_HANG);
    CHECK(out[3] == A && why[3] == FEMU_FS_WHY_NONE);

    v.fua = false;
    lines(l, cut, 3);
    femu_fs_match(l, 3, &v, out, why, &eff);
    CHECK(out[0] == A && why[0] == FEMU_FS_WHY_NONE);
    CHECK(out[1] == X && why[1] == FEMU_FS_WHY_PRE);
    CHECK(out[2] == S && why[2] == FEMU_FS_WHY_NONE);

    CHECK(!strcmp(femu_fs_act_name(FEMU_FS_ACT_WB_FAIL), "wb-fail"));
    CHECK(!strcmp(femu_fs_act_name(FEMU_FS_ACT_ANA), "ana"));
    CHECK(!strcmp(femu_fs_act_name(FEMU_FS_ACT_SLOW), "slow"));
    CHECK(!strcmp(femu_fs_act_name(FEMU_FS_ACT_DELAY), "delay"));
    CHECK(!strcmp(femu_fr_name_why(FEMU_FS_WHY_FUA), "fua"));
    CHECK(!strcmp(femu_fr_name_why(FEMU_FS_WHY_PRE), "pre"));
    CHECK(!strcmp(femu_fr_name_why(FEMU_FS_WHY_HANG), "hang"));
}

/*
 * What came of a lie, in the order of the checks: a failed command, then
 * working plp, then no buffer, then (fua-lie only) a transaction, then
 * no page left volatile. Each case changes one fact of a lie that applies.
 */
static void test_lie_why(void)
{
    const FemuFsLie fua = {
        .act = FEMU_FS_ACT_FUA_LIE, .buffer = true, .pages = 2,
    };
    const FemuFsLie flush = {
        .act = FEMU_FS_ACT_FLUSH_LIE, .buffer = true, .pages = 3,
    };
    FemuFsLie s;

    CHECK(femu_fs_lie_why(&fua) == FEMU_FS_WHY_NONE);
    CHECK(femu_fs_lie_why(&flush) == FEMU_FS_WHY_NONE);

    s = fua;
    s.failed = true;
    s.plp = true;
    CHECK(femu_fs_lie_why(&s) == FEMU_FS_WHY_CMD_FAILED);
    s = flush;
    s.failed = true;
    CHECK(femu_fs_lie_why(&s) == FEMU_FS_WHY_CMD_FAILED);

    s = fua;
    s.plp = true;
    s.buffer = false;
    CHECK(femu_fs_lie_why(&s) == FEMU_FS_WHY_PLP);
    s = flush;
    s.plp = true;
    CHECK(femu_fs_lie_why(&s) == FEMU_FS_WHY_PLP);

    s = fua;
    s.buffer = false;
    s.atomic = true;
    CHECK(femu_fs_lie_why(&s) == FEMU_FS_WHY_NO_BUFFER);
    s = flush;
    s.buffer = false;
    CHECK(femu_fs_lie_why(&s) == FEMU_FS_WHY_NO_BUFFER);

    s = fua;
    s.atomic = true;
    CHECK(femu_fs_lie_why(&s) == FEMU_FS_WHY_ATOMIC);
    s = fua;
    s.pages = 0;
    CHECK(femu_fs_lie_why(&s) == FEMU_FS_WHY_DURABLE);

    /* an empty buffer leaves nothing volatile; atomic is a FUA fact */
    s = flush;
    s.pages = 0;
    CHECK(femu_fs_lie_why(&s) == FEMU_FS_WHY_DURABLE);
    s = flush;
    s.atomic = true;
    CHECK(femu_fs_lie_why(&s) == FEMU_FS_WHY_NONE);

    CHECK(!strcmp(femu_fr_name_why(FEMU_FS_WHY_PLP), "plp"));
    CHECK(!strcmp(femu_fr_name_why(FEMU_FS_WHY_ATOMIC), "atomic"));
    CHECK(!strcmp(femu_fr_name_why(FEMU_FS_WHY_NO_BUFFER), "no-buffer"));
    CHECK(!strcmp(femu_fr_name_why(FEMU_FS_WHY_CMD_FAILED), "cmd-failed"));
    CHECK(!strcmp(femu_fr_name_why(FEMU_FS_WHY_DURABLE), "durable"));
    CHECK(!strcmp(femu_fr_name_phase(FEMU_FR_PHASE_APPLY), "apply"));
    CHECK(!strcmp(femu_fr_name_outcome(FEMU_FR_OUT_DONE), "done"));
}

/* a record whose fields all follow from @k, so a reader can check it */
static FemuFrRec rec_of(uint64_t k)
{
    return (FemuFrRec) {
        .step = k * 3, .match = k + 7, .slba = k << 20, .nlb = k + 1,
        .nsid = 1, .line = k & 0xffff, .sqid = 1, .cid = k & 0xffff,
        .origin = FEMU_FR_ORIGIN_SCHED_CMD, .phase = FEMU_FR_PHASE_SELECT,
        .act = FEMU_FS_ACT_HANG, .outcome = FEMU_FR_OUT_SELECTED,
        .opc = FEMU_FS_OPC_WRITE,
    };
}

/* @r matches rec_of(@k) in every field, with id @id */
static bool rec_is(const FemuFrRec *r, uint64_t k, uint64_t id)
{
    FemuFrRec w = rec_of(k);

    w.id = id;
    return !memcmp(r, &w, sizeof(w));
}

/* with no consumer the ring keeps the newest records and counts the rest */
static void test_ring_window(void)
{
    FemuFrSlot slot[4] = { 0 };
    FemuFrRec out[8];
    FemuFrRing r;
    uint32_t n;

    femu_fr_init(&r, slot, 4, true);
    CHECK(femu_fr_read(&r, out, 8) == 0);
    for (uint64_t k = 1; k <= 3; k++) {
        FemuFrRec x = rec_of(k);

        CHECK(femu_fr_put(&r, &x) == k && x.id == k);
    }
    n = femu_fr_read(&r, out, 8);
    CHECK(n == 3 && rec_is(&out[0], 1, 1) && rec_is(&out[2], 3, 3));
    CHECK(r.overwritten == 0);
    for (uint64_t k = 4; k <= 10; k++) {
        FemuFrRec x = rec_of(k);

        femu_fr_put(&r, &x);
    }
    /* the last 4 of 10, oldest first; 6 pushed out, none dropped */
    n = femu_fr_read(&r, out, 8);
    CHECK(n == 4);
    for (uint32_t i = 0; i < n; i++) {
        CHECK(rec_is(&out[i], 7 + i, 7 + i));
    }
    CHECK(r.overwritten == 6 && r.dropped == 0 && r.next_id == 10);
    /* a short read keeps the newest */
    n = femu_fr_read(&r, out, 2);
    CHECK(n == 2 && out[0].id == 9 && out[1].id == 10);
    /* a slot caught mid-write is left out, never returned torn */
    slot[(9 - 1) % 4].seq |= 1;
    n = femu_fr_read(&r, out, 8);
    CHECK(n == 3 && out[0].id == 7 && out[1].id == 8 && out[2].id == 10);
}

/* with a consumer a full ring drops the new record and notes its id */
static void test_ring_drop(void)
{
    FemuFrSlot slot[4] = { 0 };
    FemuFrIdRange d[FEMU_FR_DROP_RANGES];
    FemuFrRec out[8];
    FemuFrRec x;
    FemuFrRing r;
    uint32_t n;

    femu_fr_init(&r, slot, 4, false);
    CHECK(!femu_fr_pop(&r, &x));
    for (uint64_t k = 1; k <= 10; k++) {
        x = rec_of(k);
        /* ids keep counting for the dropped records */
        CHECK(femu_fr_put(&r, &x) == k);
    }
    CHECK(r.dropped == 6 && r.overwritten == 0 && r.next_id == 10);
    n = femu_fr_read(&r, out, 8);
    CHECK(n == 4 && rec_is(&out[0], 1, 1) && rec_is(&out[3], 4, 4));
    CHECK(femu_fr_dropped_ids(&r, d) == 1 && d[0].lo == 5 && d[0].hi == 10);

    /* the consumer frees two: ids 11 and 12 fit, 13 does not */
    CHECK(femu_fr_pop(&r, &x) && rec_is(&x, 1, 1));
    CHECK(femu_fr_pop(&r, &x) && rec_is(&x, 2, 2));
    for (uint64_t k = 11; k <= 13; k++) {
        x = rec_of(k);
        femu_fr_put(&r, &x);
    }
    n = femu_fr_read(&r, out, 8);
    CHECK(n == 4 && out[0].id == 3 && out[1].id == 4 &&
          rec_is(&out[2], 11, 11) && rec_is(&out[3], 12, 12));
    CHECK(femu_fr_dropped_ids(&r, d) == 2 && d[1].lo == 13 && d[1].hi == 13);
    CHECK(r.dropped == 7);
    /* the consumer takes them in id order, then finds the ring empty */
    for (uint64_t id = 3; id <= 12; id++) {
        if (id == 5) {
            id = 11;
        }
        CHECK(femu_fr_pop(&r, &x) && x.id == id);
    }
    CHECK(!femu_fr_pop(&r, &x));
    CHECK(femu_fr_read(&r, out, 8) == 0);
}

/* only the first FEMU_FR_DROP_RANGES ranges are kept; the count goes on */
static void test_ring_drop_ranges(void)
{
    FemuFrSlot slot[1] = { 0 };
    FemuFrIdRange d[FEMU_FR_DROP_RANGES];
    FemuFrRec x;
    FemuFrRing r;
    uint32_t n;

    femu_fr_init(&r, slot, 1, false);
    x = rec_of(0);
    femu_fr_put(&r, &x);
    /* each round: one dropped, then one stored after a pop */
    for (int i = 0; i < 20; i++) {
        x = rec_of(0);
        femu_fr_put(&r, &x);
        CHECK(femu_fr_pop(&r, &x));
        x = rec_of(0);
        femu_fr_put(&r, &x);
    }
    n = femu_fr_dropped_ids(&r, d);
    CHECK(n == FEMU_FR_DROP_RANGES && r.dropped == 20);
    for (uint32_t i = 0; i < n; i++) {
        CHECK(d[i].lo == 2 + 2 * i && d[i].hi == d[i].lo);
    }
}

static void test_ring_json(void)
{
    FemuFrRec x = rec_of(5);
    char buf[FEMU_FR_JSON_MAX];
    int n;

    x.id = 9;
    n = femu_fr_json(&x, buf, sizeof(buf));
    CHECK(n == (int)strlen(buf));
    CHECK(!strcmp(buf, "{\"id\":9,\"origin\":\"sched-cmd\",\"line\":5,"
                  "\"match\":12,\"action\":\"hang\",\"phase\":\"select\","
                  "\"step\":15,\"nsid\":1,\"sqid\":1,\"cid\":5,\"opc\":1,"
                  "\"fua\":false,\"slba\":5242880,\"nlb\":6,"
                  "\"outcome\":\"selected\"}\n"));
    x.outcome = FEMU_FR_OUT_NO_EFFECT;
    x.why = FEMU_FS_WHY_FUA;
    x.fua = 1;
    x.cause = 3;
    x.status = 0x280;
    femu_fr_json(&x, buf, sizeof(buf));
    CHECK(strstr(buf, "{\"id\":9,\"cause\":3,\"origin\"") == buf);
    CHECK(strstr(buf, "\"fua\":true,"));
    CHECK(strstr(buf, "\"outcome\":\"no-effect\",\"reason\":\"fua\","
                  "\"status\":640}\n"));
    x.outcome = FEMU_FR_OUT_SUPERSEDED;
    femu_fr_json(&x, buf, sizeof(buf));
    CHECK(strstr(buf, "\"outcome\":\"superseded\",\"status\""));

    /* an apply record of a lie: its pages, under the name of its action */
    x = rec_of(5);
    x.id = 10;
    x.cause = 9;
    x.phase = FEMU_FR_PHASE_APPLY;
    x.act = FEMU_FS_ACT_FLUSH_LIE;
    x.opc = FEMU_FS_OPC_FLUSH;
    x.outcome = FEMU_FR_OUT_DONE;
    x.pages = 4;
    femu_fr_json(&x, buf, sizeof(buf));
    CHECK(strstr(buf, "\"action\":\"flush-lie\",\"phase\":\"apply\","));
    CHECK(strstr(buf, "\"outcome\":\"done\",\"buffered_at_flush_lie\":4}"
                  "\n"));
    x.act = FEMU_FS_ACT_FUA_LIE;
    femu_fr_json(&x, buf, sizeof(buf));
    CHECK(strstr(buf, "\"outcome\":\"done\",\"lie_pages\":4}\n"));
    CHECK(!strstr(buf, "buffered_at_flush_lie"));
    /* no pages without the effect, and none on a select record */
    x.outcome = FEMU_FR_OUT_NO_EFFECT;
    x.why = FEMU_FS_WHY_PLP;
    femu_fr_json(&x, buf, sizeof(buf));
    CHECK(strstr(buf, "\"outcome\":\"no-effect\",\"reason\":\"plp\"}\n"));
    x.why = FEMU_FS_WHY_CMD_FAILED;
    femu_fr_json(&x, buf, sizeof(buf));
    CHECK(strstr(buf, "\"reason\":\"cmd-failed\"}\n"));
    x.phase = FEMU_FR_PHASE_SELECT;
    x.outcome = FEMU_FR_OUT_DONE;
    femu_fr_json(&x, buf, sizeof(buf));
    CHECK(!strstr(buf, "lie_pages") && strstr(buf, "\"phase\":\"select\""));
}

/*
 * A reuse between the words of a copy and its second look at the
 * sequence word: the copy holds record 1, the slot now holds record 2.
 * The read must leave record 1 out, though its first look passed.
 */
static FemuFrRing *mid_ring;

static void mid_put(void)
{
    FemuFrRec x = rec_of(2);

    fr_test_mid_copy = NULL;
    femu_fr_put(mid_ring, &x);
}

static void test_ring_mid_copy(void)
{
    FemuFrSlot slot[1] = { 0 };
    FemuFrRec out[2];
    FemuFrRec x = rec_of(1);
    FemuFrRing r;

    femu_fr_init(&r, slot, 1, true);
    femu_fr_put(&r, &x);
    mid_ring = &r;
    fr_test_mid_copy = mid_put;
    CHECK(femu_fr_read(&r, out, 2) == 0);
    CHECK(!fr_test_mid_copy);
    /* control: with no reuse in the copy, the next read keeps record 2 */
    CHECK(femu_fr_read(&r, out, 2) == 1 && rec_is(&out[0], 2, 2));
}

/*
 * A consumer frees slots while the reader copies them: the pending count
 * follows, and a read sees only what the consumer has not taken.
 */
static void test_ring_pending(void)
{
    FemuFrSlot slot[4] = { 0 };
    FemuFrRec out[4];
    FemuFrRec x;
    FemuFrRing r;

    femu_fr_init(&r, slot, 4, false);
    CHECK(femu_fr_pending(&r) == 0);
    for (uint64_t k = 1; k <= 3; k++) {
        x = rec_of(k);
        femu_fr_put(&r, &x);
    }
    CHECK(femu_fr_pending(&r) == 3);
    CHECK(femu_fr_pop(&r, &x) && rec_is(&x, 1, 1));
    CHECK(femu_fr_pending(&r) == 2);
    CHECK(femu_fr_read(&r, out, 4) == 2 && out[0].id == 2);
    /* a peek keeps the slot until the release */
    CHECK(femu_fr_peek(&r, &x) && rec_is(&x, 2, 2));
    CHECK(femu_fr_pending(&r) == 2 && femu_fr_peek(&r, &x) && x.id == 2);
    femu_fr_release(&r);
    CHECK(femu_fr_pending(&r) == 1 && femu_fr_peek(&r, &x) && x.id == 3);
}

/*
 * The consumer frees records between the tail load and the head load of
 * a read and of femu_fr_pending(): it takes the 3 records, the producer
 * adds 2, and it takes those too. With the head loaded first, the tail
 * passes it and head - tail wraps: the read returns nothing and the
 * count is huge. Tail first gives a read of ids 2 to 5, whose slots still
 * hold them, and a count that is old but at most the ring size.
 */
static FemuFrRing *ends_ring;

static void ends_consume(const FemuFrRing *r)
{
    FemuFrRec x;

    CHECK(r == ends_ring);
    fr_test_mid_ends = NULL;
    while (femu_fr_pop(ends_ring, &x)) {
        /* free them */
    }
    for (uint64_t k = 4; k <= 5; k++) {
        x = rec_of(k);
        femu_fr_put(ends_ring, &x);
    }
    while (femu_fr_pop(ends_ring, &x)) {
        /* free them */
    }
}

static void test_ring_ends(void)
{
    FemuFrSlot slot[4] = { 0 };
    FemuFrRec out[8];
    FemuFrRec x;
    FemuFrRing r;
    uint32_t n;

    femu_fr_init(&r, slot, 4, false);
    ends_ring = &r;
    for (uint64_t k = 1; k <= 3; k++) {
        x = rec_of(k);
        femu_fr_put(&r, &x);
    }
    fr_test_mid_ends = ends_consume;
    n = femu_fr_read(&r, out, 8);
    CHECK(fr_test_mid_ends == NULL);
    CHECK(n == 4 && out[0].id == 2 && out[3].id == 5);

    /* the control: nothing moves between the loads */
    CHECK(femu_fr_read(&r, out, 8) == 0);
    CHECK(femu_fr_pending(&r) == 0);

    x = rec_of(6);
    femu_fr_put(&r, &x);
    CHECK(femu_fr_pending(&r) == 1);
    /* tail 5 seen, then 3 more taken and 2 added: a stale count, no wrap */
    fr_test_mid_ends = ends_consume;
    CHECK(femu_fr_pending(&r) == 3);
    CHECK(fr_test_mid_ends == NULL);
}

/*
 * A producer thread fills a small window while the main thread reads it.
 * Each read must be in id order, with no torn record. The producer starts
 * only once the reader is in its loop, and the reader reads once more
 * after the producer ends, so the test never depends on the scheduler.
 * On x86 a load is never moved before an earlier load, and a store never
 * before an earlier store, so this test cannot catch a missing fence
 * there; the forced copy of test_ring_mid_copy() covers the sequence
 * checks.
 */
#define STRESS_PUTS     2000000

static int stress_go;

static void *stress_put(void *arg)
{
    FemuFrRing *r = arg;

    while (!__atomic_load_n(&stress_go, __ATOMIC_ACQUIRE)) {
        sched_yield();
    }
    for (uint64_t k = 1; k <= STRESS_PUTS; k++) {
        FemuFrRec x = rec_of(k);

        femu_fr_put(r, &x);
    }
    return NULL;
}

static void test_ring_threads(void)
{
    static FemuFrSlot slot[16];
    FemuFrRec out[16];
    FemuFrRing r;
    pthread_t th;
    uint64_t reads = 0;
    uint64_t seen = 0;
    bool ok = true;

    bool more;

    femu_fr_init(&r, slot, 16, true);
    __atomic_store_n(&stress_go, 0, __ATOMIC_RELEASE);
    if (pthread_create(&th, NULL, stress_put, &r)) {
        CHECK(0);
        return;
    }
    __atomic_store_n(&stress_go, 1, __ATOMIC_RELEASE);
    do {
        uint32_t n;
        uint64_t last = 0;

        /* the last pass reads after the producer is done */
        more = __atomic_load_n(&r.head, __ATOMIC_ACQUIRE) < STRESS_PUTS;
        n = femu_fr_read(&r, out, 16);

        for (uint32_t i = 0; i < n; i++) {
            /* the producer gives record k the id k */
            ok = ok && out[i].id > last && rec_is(&out[i], out[i].id,
                                                  out[i].id);
            last = out[i].id;
        }
        reads++;
        seen += n;
    } while (more);
    CHECK(pthread_join(th, NULL) == 0);
    printf("# %" PRIu64 " reads, %" PRIu64 " records\n", reads, seen);
    /* the final read holds the last 16, after the producer ended */
    CHECK(ok && seen >= 16 && out[15].id == STRESS_PUTS);
    CHECK(r.overwritten == STRESS_PUTS - 16);
}

/*
 * wb-fail fault slots: 256 at most, freed by the last reference. The
 * slot the 257th selection asks for is refused, and a freed slot comes
 * back zeroed.
 */
static void test_wb_slots(void)
{
    static FemuWbTab t;
    bool ok = true;
    int s;

    memset(&t, 0, sizeof(t));
    for (int i = 0; i < FEMU_WB_SLOTS; i++) {
        ok = ok && femu_wb_slot_get(&t) == i;
    }
    CHECK(ok);
    CHECK(femu_wb_slot_get(&t) == -1);
    /* a mark adds a reference: one put keeps the slot */
    t.slot[7].refs++;
    t.slot[7].marked = 3;
    femu_wb_slot_put(&t, 7);
    CHECK(femu_wb_slot_get(&t) == -1);
    femu_wb_slot_put(&t, 7);
    s = femu_wb_slot_get(&t);
    CHECK(s == 7 && t.slot[7].refs == 1 && t.slot[7].marked == 0);
    /* a put of a free or bad slot does nothing */
    femu_wb_slot_put(&t, -1);
    femu_wb_slot_put(&t, FEMU_WB_SLOTS);
    t.slot[9].refs = 0;
    femu_wb_slot_put(&t, 9);
    CHECK(t.slot[9].refs == 0);
}

static FemuWbFail wb_fail_of(int slot, uint8_t report, uint32_t nsid,
                             uint64_t slba)
{
    FemuWbFail f = {
        .slot = slot, .report = report, .nsid = nsid, .page_slba = slba,
        .lbas = 8, .fail_id = slba + 100,
    };

    return f;
}

static int wb_state(const FemuWbTab *t, uint64_t slba)
{
    for (uint32_t i = 0; i < t->nr; i++) {
        if (t->fail[i].page_slba == slba) {
            return t->fail[i].state;
        }
    }
    return 0;
}

/*
 * The life of a failure: pending, reserved by the completion that
 * reports it, consumed when that CQE posts, pending again when it never
 * does. sticky never leaves pending and sets DNR.
 */
static void test_wb_collect(void)
{
    static FemuWbTab t;
    FemuWbFail fail[8];
    bool held;
    int a;
    int b;

    memset(&t, 0, sizeof(t));
    t.fail = fail;
    t.cap = 8;
    a = femu_wb_slot_get(&t);
    b = femu_wb_slot_get(&t);
    t.slot[a].report = FEMU_FS_REPORT_ONCE;
    t.slot[b].report = FEMU_FS_REPORT_STICKY;
    /* each mark holds a reference; the failures take them over */
    t.slot[a].refs += 2;
    t.slot[b].refs += 1;
    femu_wb_slot_put(&t, a);
    femu_wb_slot_put(&t, b);

    CHECK(!femu_wb_pending(&t, 0));
    CHECK(femu_wb_collect(&t, 0, 1, false, &held) == 0 && !held);
    femu_wb_fail_add(&t, &(FemuWbFail){ .slot = a, .report = 1, .nsid = 1,
                                        .page_slba = 8, .tok = 77 });
    CHECK(t.nr == 1 && t.fail[0].state == FEMU_WB_PENDING &&
          t.fail[0].tok == 0);
    t.nr = 0;
    {
        FemuWbFail x = wb_fail_of(a, FEMU_FS_REPORT_ONCE, 1, 8);

        femu_wb_fail_add(&t, &x);
    }

    /* scope: another namespace sees nothing, 0 sees all */
    CHECK(femu_wb_pending(&t, 1) && !femu_wb_pending(&t, 2) &&
          femu_wb_pending(&t, 0));
    CHECK(femu_wb_collect(&t, 2, 5, false, &held) == 0 && !held);

    /* I/O: Write Fault, no DNR for once; the failure is reserved */
    CHECK(femu_wb_collect(&t, 1, 5, false, &held) == FEMU_WB_SC_WF);
    CHECK(held && wb_state(&t, 8) == FEMU_WB_RESERVED);
    /* reserved: no other completion reports it */
    CHECK(!femu_wb_pending(&t, 0));
    CHECK(femu_wb_collect(&t, 0, 6, false, &held) == 0 && !held);
    /* the CQE never posts: pending again, for the next drain */
    CHECK(femu_wb_publish(&t, 6) == 0);
    CHECK(femu_wb_unreserve(&t, 5) == 1);
    CHECK(wb_state(&t, 8) == FEMU_WB_PENDING);
    CHECK(femu_wb_unreserve(&t, 5) == 0);
    /* Admin: Internal Error */
    CHECK(femu_wb_collect(&t, 0, 7, true, &held) == FEMU_WB_SC_INTERNAL);
    CHECK(held && femu_wb_publish(&t, 7) == 1 && t.nr == 0);
    CHECK(!femu_wb_pending(&t, 0));
    /* the last reference went with it */
    CHECK(t.slot[a].refs == 1);

    /* sticky: DNR, never reserved, never consumed */
    {
        FemuWbFail x = wb_fail_of(b, FEMU_FS_REPORT_STICKY, 2, 16);

        femu_wb_fail_add(&t, &x);
    }
    for (uint64_t tok = 10; tok < 13; tok++) {
        CHECK(femu_wb_collect(&t, 2, tok, false, &held) ==
              (FEMU_WB_SC_WF | FEMU_WB_SC_DNR) && !held);
        CHECK(femu_wb_publish(&t, tok) == 0 && t.nr == 1);
        CHECK(t.fail[0].tok == tok);
    }
    CHECK(femu_wb_collect(&t, 0, 13, true, &held) ==
          (FEMU_WB_SC_INTERNAL | FEMU_WB_SC_DNR));

    /* a once next to a sticky: DNR, and the once one is held */
    {
        FemuWbFail x = wb_fail_of(a, FEMU_FS_REPORT_ONCE, 2, 24);

        t.slot[a].refs++;
        femu_wb_fail_add(&t, &x);
    }
    CHECK(femu_wb_collect(&t, 2, 20, false, &held) ==
          (FEMU_WB_SC_WF | FEMU_WB_SC_DNR) && held);
    CHECK(femu_wb_publish(&t, 20) == 1 && t.nr == 1 &&
          t.fail[0].page_slba == 16);

    /* reset: every failure goes, slots that marks hold stay */
    femu_wb_clear(&t, false);
    CHECK(t.nr == 0 && t.slot[a].refs == 1 && t.slot[b].refs == 0);
    /* cut: the slots go too */
    femu_wb_clear(&t, true);
    CHECK(t.slot[a].refs == 0);
}

/* lost blocks: a byte or a state that differs from the media copy */
static void test_wb_lost(void)
{
    uint8_t now[4 * 16];
    uint8_t undo[4 * 16];
    uint8_t st_now[4] = { 1, 1, 0, 3 };
    uint8_t st_undo[4] = { 1, 1, 0, 1 };

    memset(now, 0xa5, sizeof(now));
    memset(undo, 0xa5, sizeof(undo));
    now[16 + 15] ^= 1;
    CHECK(!femu_wb_lba_lost(now, undo, st_now, st_undo, 0, 16));
    CHECK(femu_wb_lba_lost(now, undo, st_now, st_undo, 1, 16));
    CHECK(!femu_wb_lba_lost(now, undo, st_now, st_undo, 2, 16));
    /* same bytes, but the buffered write made it uncorrectable */
    CHECK(femu_wb_lba_lost(now, undo, st_now, st_undo, 3, 16));
}

/* why an apply marked nothing, first match wins */
static void test_wb_apply_why(void)
{
    CHECK(femu_wb_apply_why(false, false, true, false, false, 0) ==
          FEMU_FS_WHY_SLOTS_FULL);
    CHECK(femu_wb_apply_why(true, false, true, false, false, 2) ==
          FEMU_FS_WHY_NONE);
    /* a mark is a mark, whatever the status says */
    CHECK(femu_wb_apply_why(true, true, true, false, false, 1) ==
          FEMU_FS_WHY_NONE);
    CHECK(femu_wb_apply_why(true, true, true, false, false, 0) ==
          FEMU_FS_WHY_CMD_FAILED);
    CHECK(femu_wb_apply_why(true, false, false, false, false, 0) ==
          FEMU_FS_WHY_NO_BUFFER);
    CHECK(femu_wb_apply_why(true, false, true, true, false, 0) ==
          FEMU_FS_WHY_ATOMIC);
    CHECK(femu_wb_apply_why(true, false, true, false, true, 0) ==
          FEMU_FS_WHY_MARKED);
    CHECK(femu_wb_apply_why(true, false, true, false, false, 0) ==
          FEMU_FS_WHY_DURABLE);
}

/* the JSON of each wb-fail phase */
static void test_wb_json(void)
{
    FemuFrRec x = rec_of(5);
    char buf[FEMU_FR_JSON_MAX];

    CHECK(sizeof(FemuFrRec) == 80 && sizeof(FemuFrSlot) == 88);
    x.act = FEMU_FS_ACT_WB_FAIL;
    x.phase = FEMU_FR_PHASE_APPLY;
    x.outcome = FEMU_FR_OUT_MARKED;
    x.pages = 3;
    x.fslot = 2;
    femu_fr_json(&x, buf, sizeof(buf));
    CHECK(strstr(buf, "\"outcome\":\"marked\",\"slot\":2,\"pages\":3}\n"));
    x.phase = FEMU_FR_PHASE_FAIL;
    x.outcome = FEMU_FR_OUT_UNC;
    x.found = FEMU_FR_FOUND_BG;
    x.lba_mask = 0xf0;
    x.lost = 4;
    x.status = 0x280;
    femu_fr_json(&x, buf, sizeof(buf));
    CHECK(strstr(buf, "\"phase\":\"fail\","));
    CHECK(strstr(buf, "\"outcome\":\"unc\",\"slot\":2,\"lba_mask\":240,"
                  "\"lost\":4,\"found\":\"background\",\"status\":640}\n"));
    x.outcome = FEMU_FR_OUT_OLD;
    x.found = FEMU_FR_FOUND_CMD;
    femu_fr_json(&x, buf, sizeof(buf));
    CHECK(strstr(buf, "\"outcome\":\"old\",") &&
          strstr(buf, "\"found\":\"command\""));
    x.phase = FEMU_FR_PHASE_REPORT;
    x.outcome = FEMU_FR_OUT_REPORTED;
    x.found = FEMU_FR_FOUND_PENDING;
    x.status = 0x4280;
    femu_fr_json(&x, buf, sizeof(buf));
    CHECK(strstr(buf, "\"phase\":\"report\","));
    CHECK(strstr(buf, "\"outcome\":\"reported\",\"slot\":2,"
                  "\"found\":\"pending\",\"status\":17024}\n"));
    x.found = FEMU_FR_FOUND_SELF;
    femu_fr_json(&x, buf, sizeof(buf));
    CHECK(strstr(buf, "\"found\":\"self\""));
    x.phase = FEMU_FR_PHASE_SUPERSEDE;
    x.outcome = FEMU_FR_OUT_SUPERSEDED;
    x.status = 0;
    femu_fr_json(&x, buf, sizeof(buf));
    CHECK(strstr(buf, "\"phase\":\"supersede\",") &&
          strstr(buf, "\"outcome\":\"superseded\",\"slot\":2}\n"));
    x.outcome = FEMU_FR_OUT_NO_EFFECT;
    x.phase = FEMU_FR_PHASE_APPLY;
    x.why = FEMU_FS_WHY_SLOTS_FULL;
    x.fslot = 0;
    femu_fr_json(&x, buf, sizeof(buf));
    CHECK(strstr(buf, "\"reason\":\"slots-full\"}\n") &&
          !strstr(buf, "slot\":"));
    x.why = FEMU_FS_WHY_MARKED;
    femu_fr_json(&x, buf, sizeof(buf));
    CHECK(strstr(buf, "\"reason\":\"marked\"}\n"));
}

int main(void)
{
    test_grammar();
    test_options();
    test_device();
    test_view();
    test_nth();
    test_wrap();
    test_ppm();
    test_overlap();
    test_groups();
    test_why();
    test_lie_why();
    test_ring_window();
    test_ring_drop();
    test_ring_drop_ranges();
    test_ring_json();
    test_ring_mid_copy();
    test_ring_pending();
    test_ring_ends();
    test_ring_threads();
    test_wb_slots();
    test_wb_collect();
    test_wb_lost();
    test_wb_apply_why();
    test_wb_json();
    printf("1..%d\n", ntests);
    return failures ? 1 : 0;
}
