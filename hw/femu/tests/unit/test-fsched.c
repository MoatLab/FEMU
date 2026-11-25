/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Unit test for the command lines of events_file (femu-fsched.c): the
 * grammar and its refusals, the view checks, and the matcher. Each
 * refusal has an accepted twin that differs in one value, so a check that
 * refuses everything fails here too. The seeds come from a search for
 * first draws of 0 and 999999, the two ends of the odds comparison.
 */
#include "qemu/osdep.h"
#include <inttypes.h>
#include <stdarg.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#include "hw/femu/femu-fsched.c"

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
    printf("1..%d\n", ntests);
    return failures ? 1 : 0;
}
