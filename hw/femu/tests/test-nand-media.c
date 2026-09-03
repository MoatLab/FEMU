/*
 * Unit tests for the uniform NAND media timing layer.
 *
 * These cover the arithmetic only -- gating, ECC tiers and multi-plane
 * batching -- which is the part that is otherwise measurable solely by booting
 * a guest and timing it. Two bugs in 2026 were mis-diagnosed because a slow
 * end-to-end measurement was the only evidence available: an ECC adder that
 * could never run, and a multi-plane gate that read state its caller leaves
 * unset. Both are asserted below.
 */
#include <stdio.h>
#include <string.h>
#include "nand-media.h"

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

static int failures;

static void reset_timelines(void)
{
    memset(ch_avail, 0, sizeof(ch_avail));
    memset(lun_avail, 0, sizeof(lun_avail));
    memset(pl_avail, 0, sizeof(pl_avail));
}

static void check(const char *what, uint64_t got, uint64_t want)
{
    if (got == want) {
        printf("  ok    %-52s %lu\n", what, (unsigned long)got);
    } else {
        printf("  FAIL  %-52s got %lu want %lu\n", what,
               (unsigned long)got, (unsigned long)want);
        failures++;
    }
}

static void check_lt(const char *what, uint64_t got, uint64_t bound)
{
    if (got < bound) {
        printf("  ok    %-52s %lu < %lu\n", what, (unsigned long)got,
               (unsigned long)bound);
    } else {
        printf("  FAIL  %-52s %lu not < %lu\n", what, (unsigned long)got,
               (unsigned long)bound);
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
    return nand_media_op(&m, &loc, NAND_MEDIA_READ, 1000000000ULL).latency_ns;
}

static void test_ecc(void)
{
    NandMediaConfig cfg;

    puts("ECC read adder");
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

static void test_multiplane_erase(void)
{
    NandMediaConfig cfg;
    NandMedia m;
    NandLoc locs[4];
    uint64_t one, batched, serial;
    int i;

    puts("multi-plane erase");

    /*
     * One plane must be identical to the single-op path. A commit claimed this
     * and only a guest run could check it until now.
     */
    bb_config(&cfg);
    nand_media_init(&m, &cfg);
    memset(locs, 0, sizeof(locs));
    one = nand_media_op(&m, &locs[0], NAND_MEDIA_ERASE, 0).latency_ns;
    bb_config(&cfg);
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
    nand_media_init(&m, &cfg);
    memset(locs, 0, sizeof(locs));
    locs[1].pl = 1;
    batched = nand_media_multiplane(&m, locs, 2, NAND_MEDIA_ERASE, 0).latency_ns;

    bb_config(&cfg);
    cfg.planes_per_lun = 2;
    nand_media_init(&m, &cfg);
    memset(locs, 0, sizeof(locs));
    locs[1].pl = 1;
    serial = 0;
    for (i = 0; i < 2; i++) {
        serial = nand_media_op(&m, &locs[i], NAND_MEDIA_ERASE, 0).done_ns;
    }
    check_lt("two planes batch cheaper than two serial erases", batched, serial);
    check("the batch is one erase, not two", batched, cfg.timing.er_ns);
}

int main(void)
{
    test_ecc();
    test_multiplane_erase();
    if (failures) {
        printf("\n%d FAILURE(S)\n", failures);
        return 1;
    }
    puts("\nall checks passed");
    return 0;
}
