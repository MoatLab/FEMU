/*
 * Unit tests for the uniform NAND media timing layer.
 *
 * These cover the arithmetic only -- gating, ECC tiers and multi-plane
 * batching -- which is the part that is otherwise measurable solely by booting
 * a guest and timing it. Two bugs in 2026 were mis-diagnosed because a slow
 * end-to-end measurement was the only evidence available: an ECC adder that
 * could never run, and a multi-plane gate that read state its caller leaves
 * unset. Both are asserted below.
 *
 * Output is TAP, so the same binary runs under meson (make check-unit) and
 * from hw/femu/tests/Makefile, which builds it in milliseconds against a stub
 * osdep.h before the QEMU build exists.
 */
#include "qemu/osdep.h"
#include "hw/femu/nand/nand-media.h"

/* sizes for this test's fake timelines; the media layer has no opinion */
#define NAND_TEST_CHS  8
#define NAND_TEST_LUNS 64

static uint64_t ch_avail[NAND_TEST_CHS];
static uint64_t lun_avail[NAND_TEST_LUNS];
static uint64_t pl_avail[NAND_TEST_LUNS];

static uint64_t *t_ch(void *o, uint32_t ch) { (void)o; return &ch_avail[ch % NAND_TEST_CHS]; }
static uint64_t *t_lun(void *o, const NandLoc *l) { (void)o; return &lun_avail[(l->ch * 8 + l->lun) % NAND_TEST_LUNS]; }
static uint64_t *t_pl(void *o, const NandLoc *l) { (void)o; return &pl_avail[(l->ch * 8 + l->lun) % NAND_TEST_LUNS]; }
static const NandTimelineOps timeline = {
    .ch_avail = t_ch, .lun_avail = t_lun, .plane_avail = t_pl,
};

/* what bbssd actually registers: no plane_avail, because its gate is LUN-only */
static const NandTimelineOps lun_only_timeline = {
    .ch_avail = t_ch, .lun_avail = t_lun,
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

static void check_lt(const char *what, uint64_t got, uint64_t bound)
{
    ntests++;
    if (got < bound) {
        printf("ok %d - %s (%llu < %llu)\n", ntests, what,
               (unsigned long long)got, (unsigned long long)bound);
    } else {
        printf("not ok %d - %s: %llu not < %llu\n", ntests, what,
               (unsigned long long)got, (unsigned long long)bound);
        failures++;
    }
}

/* the configuration bb_nand_media_init() builds, so the tests match bbssd */
static void bb_config(NandMediaConfig *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    reset_timelines();
    cfg->nchs = 8;
    cfg->luns_per_ch = 8;
    cfg->planes_per_lun = 1;
    cfg->timing.rd_ns = 10000;
    cfg->timing.wr_ns = 40000;
    cfg->timing.er_ns = 2000000;
    cfg->timing.ecc_pe_per_tier = 750;
    cfg->timing.ecc_max_tiers = 4;
    cfg->policy.use_flat_timing = true;
    cfg->policy.ecc_on_read = true;
    cfg->policy.array_gate = NAND_GATE_LUN_ONLY;
    cfg->policy.channel_mode = NAND_CH_OFF;
    cfg->timeline = &timeline;
    cfg->timeline_opaque = NULL;
}

/*
 * Each call starts from an idle array. Without this the LUN gate carries the
 * previous op's completion forward and every latency after the first is the
 * sum of those before it.
 */
static uint64_t read_lat(const NandMediaConfig *cfg, uint32_t pe, uint32_t age)
{
    NandMedia m;
    NandLoc loc;

    reset_timelines();
    nand_media_init(&m, cfg);
    memset(&loc, 0, sizeof(loc));
    loc.pe_cycles = pe;
    loc.age_sec = age;
    {
        uint64_t lat = nand_media_op(&m, &loc, NAND_MEDIA_READ,
                                     1000000000ULL).latency_ns;
        nand_media_destroy(&m);
        return lat;
    }
}

static void test_ecc(void)
{
    NandMediaConfig cfg;

    printf("# ECC read adder\n");
    bb_config(&cfg);
    check("fresh, unworn read is just the array latency", read_lat(&cfg, 0, 0), 10000);

    /* ecc_step_ns unset: the adder must contribute nothing */
    bb_config(&cfg);
    cfg.timing.ecc_retention_per_tier_sec = 10;
    check("ecc_step_ns=0 disables the adder", read_lat(&cfg, 3000, 100), 10000);

    /*
     * policy.ecc_on_read false must also disable it. This is the bug that made
     * ecc_step_ns inert: nothing ever set the flag.
     */
    bb_config(&cfg);
    cfg.policy.ecc_on_read = false;
    cfg.timing.ecc_step_ns = 200000;
    cfg.timing.ecc_retention_per_tier_sec = 10;
    check("ecc_on_read=false disables the adder", read_lat(&cfg, 3000, 100), 10000);

    bb_config(&cfg);
    cfg.timing.ecc_step_ns = 200000;
    check("wear: 1500 P/E = 2 tiers", read_lat(&cfg, 1500, 0), 10000 + 2 * 200000);
    check("wear is capped at ecc_max_tiers", read_lat(&cfg, 100000, 0), 10000 + 4 * 200000);

    bb_config(&cfg);
    cfg.timing.ecc_step_ns = 200000;
    cfg.timing.ecc_retention_per_tier_sec = 10;
    check("age below one tier adds nothing", read_lat(&cfg, 0, 9), 10000);
    check("age: 30s at 10s per tier = 3 tiers", read_lat(&cfg, 0, 30), 10000 + 3 * 200000);
    check("age is capped at ecc_max_tiers", read_lat(&cfg, 0, 6000), 10000 + 4 * 200000);
    check("wear and age tiers add", read_lat(&cfg, 750, 20), 10000 + 3 * 200000);
    check("their sum shares one cap", read_lat(&cfg, 2250, 30), 10000 + 4 * 200000);
}

/* one op on an idle array and bus, latency only */
static uint64_t staged_lat(const NandMediaConfig *cfg, NandMediaOp op)
{
    NandMedia m;
    NandLoc loc;

    reset_timelines();
    nand_media_init(&m, cfg);
    memset(&loc, 0, sizeof(loc));
    {
        uint64_t lat = nand_media_op(&m, &loc, op, 1000000000ULL).latency_ns;
        nand_media_destroy(&m);
        return lat;
    }
}

static void test_staged_channel(void)
{
    NandMediaConfig cfg;
    NandMedia m;
    NandLoc a, b;
    uint64_t first, second;

    printf("# staged channel bus\n");
    bb_config(&cfg);
    cfg.policy.channel_mode = NAND_CH_STAGED;
    cfg.timing.cmd_addr_ns = 300;
    cfg.timing.page_xfer_ns = 20000;
    cfg.timing.status_ns = 100;
    check("read = command + array + transfer + status",
          staged_lat(&cfg, NAND_MEDIA_READ), 300 + 10000 + 20000 + 100);
    check("program = command + transfer + array",
          staged_lat(&cfg, NAND_MEDIA_PROGRAM), 300 + 20000 + 40000);
    check("erase = command + array + status",
          staged_lat(&cfg, NAND_MEDIA_ERASE), 300 + 2000000 + 100);

    /* two reads on one channel but different LUNs share the bus, not the array */
    reset_timelines();
    nand_media_init(&m, &cfg);
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    b.lun = 1;
    first = nand_media_op(&m, &a, NAND_MEDIA_READ, 1000000000ULL).latency_ns;
    second = nand_media_op(&m, &b, NAND_MEDIA_READ, 1000000000ULL).latency_ns;
    /*
     * The second read's command goes out while the first is still in its
     * array time (the bus is idle then); only its data-out queues behind the
     * first's transfer and status, which end at 30400: 300 cmd, 10000 array,
     * wait until 30400, 20000 transfer, 100 status.
     */
    check("the second read queues only its transfer behind the first",
          second, 300 + 10000 + (30400 - 10300) + 20000 + 100);

    /* with the phases unset the plain gate is used and the bus never queues */
    bb_config(&cfg);
    reset_timelines();
    nand_media_destroy(&m);
    nand_media_init(&m, &cfg);
    first = nand_media_op(&m, &a, NAND_MEDIA_READ, 1000000000ULL).latency_ns;
    second = nand_media_op(&m, &b, NAND_MEDIA_READ, 1000000000ULL).latency_ns;
    check("channel off: another LUN's read costs the same", second, first);
    nand_media_destroy(&m);
}

/* the configuration zns_nand_media_init() builds once a bus phase is set */
static void zns_config(NandMediaConfig *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    reset_timelines();
    cfg->nchs = 8;
    cfg->luns_per_ch = 4;
    cfg->planes_per_lun = 2;
    cfg->timing.rd_table_ns[0][0] = 65000;
    cfg->timing.wr_table_ns[0][0] = 450000;
    cfg->timing.er_table_ns[0] = 2000000;
    cfg->policy.use_flat_timing = false;
    cfg->policy.array_gate = NAND_GATE_PLANE_ONLY;
    cfg->policy.channel_mode = NAND_CH_STAGED;
    cfg->timing.page_xfer_ns = 25000;
    cfg->timeline = &timeline;
    cfg->timeline_opaque = NULL;
}

static void test_plane_gate_with_channel(void)
{
    NandMediaConfig cfg;
    NandMedia m;
    NandLoc a, b;
    uint64_t first, second;

    printf("# plane gate with the channel bus (ZNS)\n");
    zns_config(&cfg);
    check("read = array + transfer",
          staged_lat(&cfg, NAND_MEDIA_READ), 65000 + 25000);
    check("program = transfer + array",
          staged_lat(&cfg, NAND_MEDIA_PROGRAM), 25000 + 450000);
    check("erase is array only when no command phase is set",
          staged_lat(&cfg, NAND_MEDIA_ERASE), 2000000);

    /* two reads on different planes of one channel share the bus, not the array */
    reset_timelines();
    nand_media_init(&m, &cfg);
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    b.lun = 1;
    first = nand_media_op(&m, &a, NAND_MEDIA_READ, 1000000000ULL).latency_ns;
    second = nand_media_op(&m, &b, NAND_MEDIA_READ, 1000000000ULL).latency_ns;
    check_lt("the first read pays no bus wait", first, 65000 + 25000 + 1);
    check("the second read waits only for the first transfer",
          second, first + 25000);

    /* a program on the same channel uses the bus while the read's array is busy */
    reset_timelines();
    nand_media_destroy(&m);
    nand_media_init(&m, &cfg);
    b.lun = 1;
    first = nand_media_op(&m, &a, NAND_MEDIA_READ, 1000000000ULL).latency_ns;
    second = nand_media_op(&m, &b, NAND_MEDIA_PROGRAM, 1000000000ULL).latency_ns;
    check("a program backfills the bus during the read's tR",
          second, 25000 + 450000);

    /* eight reads on one plane pipeline their transfers behind the array */
    reset_timelines();
    nand_media_destroy(&m);
    nand_media_init(&m, &cfg);
    {
        uint64_t last = 0;
        int i;
        for (i = 0; i < 8; i++) {
            last = nand_media_op(&m, &a, NAND_MEDIA_READ, 1000000000ULL).latency_ns;
        }
        check("eight same-plane reads = 8 x tR + one transfer",
              last, 8 * 65000 + 25000);
        /* more reads than the window list holds: past windows are pruned */
        for (; i < 3 * NAND_BUS_RES_MAX; i++) {
            last = nand_media_op(&m, &a, NAND_MEDIA_READ,
                                 1000000000ULL + i * 65000ULL).latency_ns;
        }
        check("a long stream of reads keeps pipelining", last,
              (uint64_t)65000 + 25000);
    }

    /* the same two reads on different channels do not interact */
    reset_timelines();
    nand_media_destroy(&m);
    nand_media_init(&m, &cfg);
    b.lun = 0;
    b.ch = 1;
    first = nand_media_op(&m, &a, NAND_MEDIA_READ, 1000000000ULL).latency_ns;
    second = nand_media_op(&m, &b, NAND_MEDIA_READ, 1000000000ULL).latency_ns;
    check("another channel's read costs the same", second, first);

    /* all phases zero: CH_OFF, and the plane gate alone decides */
    zns_config(&cfg);
    cfg.timing.page_xfer_ns = 0;
    cfg.policy.channel_mode = NAND_CH_OFF;
    reset_timelines();
    nand_media_destroy(&m);
    nand_media_init(&m, &cfg);
    b.ch = 0;
    b.lun = 1;
    first = nand_media_op(&m, &a, NAND_MEDIA_READ, 1000000000ULL).latency_ns;
    second = nand_media_op(&m, &b, NAND_MEDIA_READ, 1000000000ULL).latency_ns;
    check("channel off: reads on one channel cost the same", second, first);
    check("channel off: a read is the array time alone", first, 65000);
    nand_media_destroy(&m);
}

static void test_multiplane_erase(void)
{
    NandMediaConfig cfg;
    NandMedia m;
    NandLoc locs[4];
    uint64_t one, batched, serial;
    int i;

    printf("# multi-plane erase\n");

    /*
     * One plane must be identical to the single-op path. A commit claimed this
     * and only a guest run could check it until now.
     */
    bb_config(&cfg);
    nand_media_init(&m, &cfg);
    memset(locs, 0, sizeof(locs));
    one = nand_media_op(&m, &locs[0], NAND_MEDIA_ERASE, 0).latency_ns;
    bb_config(&cfg);
    nand_media_destroy(&m);
    nand_media_init(&m, &cfg);
    memset(locs, 0, sizeof(locs));
    batched = nand_media_multiplane(&m, locs, 1, NAND_MEDIA_ERASE, 0).latency_ns;
    check("one plane matches the single-op path", batched, one);

    /*
     * Two planes of a LUN erase as one array operation, so the batch must beat
     * two serial erases. It must also not read plane state: the bbssd gate is
     * LUN-only and leaves plane_avail unset, which used to be dereferenced.
     */
    bb_config(&cfg);
    cfg.planes_per_lun = 2;
    nand_media_destroy(&m);
    nand_media_init(&m, &cfg);
    memset(locs, 0, sizeof(locs));
    locs[1].pl = 1;
    batched = nand_media_multiplane(&m, locs, 2, NAND_MEDIA_ERASE, 0).latency_ns;

    bb_config(&cfg);
    cfg.planes_per_lun = 2;
    nand_media_destroy(&m);
    nand_media_init(&m, &cfg);
    memset(locs, 0, sizeof(locs));
    locs[1].pl = 1;
    serial = 0;
    for (i = 0; i < 2; i++) {
        serial = nand_media_op(&m, &locs[i], NAND_MEDIA_ERASE, 0).done_ns;
    }
    check_lt("two planes batch cheaper than two serial erases", batched, serial);
    check("the batch is one erase, not two", batched, cfg.timing.er_ns);
    nand_media_destroy(&m);
}

static void test_copyback(void)
{
    NandMediaConfig cfg;
    NandMedia m;
    NandLoc src, dst;
    NandOpCompletion c;

    printf("# on-chip copyback\n");

    /*
     * A LUN-only caller (bbssd) leaves plane_avail unset. Reading it would be a
     * NULL call, which is what kept the multi-plane path unusable; copyback had
     * the same defect. Reaching the check below at all is the regression guard.
     */
    bb_config(&cfg);
    cfg.timeline = &lun_only_timeline;
    nand_media_init(&m, &cfg);
    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));
    dst.lun = 1;
    c = nand_media_copyback(&m, &src, &dst, 1000000000ULL);
    check("LUN-only gate does not touch plane state",
          c.done_ns, 1000000000ULL + 10000 + 40000);

    /*
     * An op cannot start before it was requested. With idle resources whose
     * timestamps sit in the past, the old code started at the resource time and
     * returned a completion earlier than stime.
     */
    bb_config(&cfg);
    nand_media_destroy(&m);
    nand_media_init(&m, &cfg);
    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));
    dst.lun = 1;
    c = nand_media_copyback(&m, &src, &dst, 5000000000ULL);
    check("idle array still starts at stime, not in the past",
          c.done_ns, 5000000000ULL + 10000 + 40000);

    /* a busy destination LUN pushes the program out */
    bb_config(&cfg);
    nand_media_destroy(&m);
    nand_media_init(&m, &cfg);
    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));
    dst.lun = 1;
    lun_avail[1] = 5000000000ULL + 500000;
    c = nand_media_copyback(&m, &src, &dst, 5000000000ULL);
    check("a busy destination LUN delays the program",
          c.done_ns, 5000000000ULL + 500000 + 40000);
    nand_media_destroy(&m);
}

int main(void)
{
    /*
     * Under meson the output goes through a pipe, so stdout is fully buffered
     * and an abort -- an armed assertion, a sanitizer report -- would discard
     * every TAP line written so far, leaving an empty log for the failure that
     * matters most. Line buffering costs nothing here and keeps the record.
     */
    setvbuf(stdout, NULL, _IOLBF, 0);

    test_ecc();
    test_staged_channel();
    test_plane_gate_with_channel();
    test_multiplane_erase();
    test_copyback();
    printf("1..%d\n", ntests);
    return failures ? 1 : 0;
}
