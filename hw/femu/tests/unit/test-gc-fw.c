/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Firmware time of a collection move (fw_gc_page_ns): the slot math of
 * bbssd/ftl-gc-fw-math.h on the real media layer, in exact ns.
 *
 * Each move books as ssd_gc_charge_move() and ssd_gc_charge_copyback() do:
 *
 *   read on LUN s at now -> slot on the GC firmware line -> program on
 *   LUN d at the slot end; a copyback takes its slot first
 *
 * Output is TAP, as test-nand-media.c, and it builds the same way.
 */
#include "qemu/osdep.h"
#include "hw/femu/nand/nand-media.h"
#include "hw/femu/bbssd/ftl-gc-fw-math.h"

#define NLUNS 8
#define T0    1000000000ULL
#define TR    10000ULL
#define TPROG 40000ULL
#define F     25000ULL

static uint64_t ch_avail[1];
static uint64_t lun_avail[NLUNS];

static uint64_t *t_ch(void *o, uint32_t ch)
{
    (void)o;
    (void)ch;
    return &ch_avail[0];
}

static uint64_t *t_lun(void *o, const NandLoc *l)
{
    (void)o;
    return &lun_avail[l->lun % NLUNS];
}

/* what bbssd registers: no plane_avail, its rule is LUN-only */
static const NandTimelineOps timeline = {
    .ch_avail = t_ch, .lun_avail = t_lun,
};

static int failures;
static int ntests;

static NandMedia media;
static bool media_up;
static uint64_t fw_free;
static uint64_t fw_cost;

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

/* an idle device of one channel and 8 LUNs, as bb_nand_media_init() */
static void setup(uint64_t cost)
{
    NandMediaConfig cfg;

    if (media_up) {
        nand_media_destroy(&media);
    }
    memset(&cfg, 0, sizeof(cfg));
    memset(ch_avail, 0, sizeof(ch_avail));
    memset(lun_avail, 0, sizeof(lun_avail));
    cfg.nchs = 1;
    cfg.luns_per_ch = NLUNS;
    cfg.planes_per_lun = 1;
    cfg.timing.rd_ns = TR;
    cfg.timing.wr_ns = TPROG;
    cfg.timing.er_ns = 2000000;
    cfg.timing.ecc_pe_per_tier = 750;
    cfg.timing.ecc_max_tiers = 4;
    cfg.policy.use_flat_timing = true;
    cfg.policy.ecc_on_read = true;
    cfg.policy.array_contend = NAND_CONTEND_LUN_ONLY;
    cfg.policy.channel_mode = NAND_CH_OFF;
    cfg.timeline = &timeline;
    cfg.timeline_opaque = NULL;
    nand_media_init(&media, &cfg);
    media_up = true;
    fw_free = 0;
    fw_cost = cost;
}

static NandLoc on_lun(uint32_t lun)
{
    NandLoc l;

    memset(&l, 0, sizeof(l));
    l.lun = lun;
    return l;
}

/*
 * One off-chip move at @now, as the FTL books it with gc_erase_order (the
 * default): the read from now; with a cost, the program at the end of the
 * slot, else when the read ends. Returns the end of the program; *@pstart
 * is its start.
 */
static uint64_t gc_move(uint32_t src, uint32_t dst, uint64_t now,
                        uint64_t *pstart)
{
    NandLoc s = on_lun(src);
    NandLoc d = on_lun(dst);
    uint64_t ready = nand_media_op(&media, &s, NAND_MEDIA_READ, now).done_ns;
    uint64_t stime = ready > now ? ready : now;
    NandOpCompletion c;

    if (fw_cost) {
        stime = gc_fw_slot_end(ready, now, fw_free, fw_cost);
        fw_free = stime;
    }
    c = nand_media_op(&media, &d, NAND_MEDIA_PROGRAM, stime);
    if (pstart) {
        *pstart = c.done_ns - TPROG;
    }
    return c.done_ns;
}

/* one copyback at @now on @lun, as ssd_gc_charge_copyback() books it */
static uint64_t gc_copyback(uint32_t lun, uint64_t now)
{
    NandLoc s = on_lun(lun);
    NandLoc d = on_lun(lun);
    uint64_t stime = now;

    if (fw_cost) {
        stime = gc_fw_slot_end(0, now, fw_free, fw_cost);
        fw_free = stime;
    }
    return nand_media_copyback(&media, &s, &d, stime).done_ns;
}

/* U1: the slot sits between the read and the program: + F, no more */
static void test_one_move(void)
{
    printf("# one move, one LUN\n");
    setup(0);
    check("U1 no cost: program right after the read", gc_move(0, 0, T0, NULL),
          T0 + TR + TPROG);
    setup(F);
    check("U1 cost: program after the read and the slot",
          gc_move(0, 0, T0, NULL), T0 + TR + F + TPROG);
}

/* U2: two moves on one LUN: each adds tR + F + tPROG to the die */
static void test_two_moves_one_lun(void)
{
    printf("# two moves, one LUN\n");
    setup(F);
    gc_move(0, 0, T0, NULL);
    check("U2 second move ends after two full moves", gc_move(0, 0, T0, NULL),
          T0 + 2 * (TR + F + TPROG));
}

/* U3: one firmware line for the whole FTL, not one per LUN */
static void test_shared_line(void)
{
    printf("# one firmware line, four LUNs\n");
    setup(F);
    check("U3 move A", gc_move(0, 1, T0, NULL), T0 + TR + F + TPROG);
    /* a line per LUN would end B at T0 + TR + F + TPROG as well */
    check("U3 move B waits for the slot of A", gc_move(2, 3, T0, NULL),
          T0 + TR + 2 * F + TPROG);
}

/* U4: a busy destination hides the slot: no blanket addition */
static void test_busy_destination(void)
{
    printf("# busy destination\n");
    setup(0);
    lun_avail[1] = T0 + 200000;
    check("U4 no cost", gc_move(0, 1, T0, NULL), T0 + 200000 + TPROG);
    setup(F);
    lun_avail[1] = T0 + 200000;
    check("U4 cost: the same end", gc_move(0, 1, T0, NULL),
          T0 + 200000 + TPROG);
}

/* U5: a busy source moves the slot, so the program follows its read */
static void test_busy_source(void)
{
    uint64_t start;

    printf("# busy source\n");
    setup(F);
    lun_avail[0] = T0 + 100000;
    gc_move(0, 1, T0, &start);
    check("U5 program starts at source busy + tR + F", start,
          T0 + 100000 + TR + F);
}

/* U6: a copyback takes its slot before the die op */
static void test_copyback(void)
{
    printf("# copyback\n");
    setup(0);
    check("U6 no cost", gc_copyback(0, T0), T0 + TR + TPROG);
    setup(F);
    check("U6 cost: the slot comes first", gc_copyback(0, T0),
          T0 + F + TR + TPROG);
    /* its slot ran while the first copyback held the die */
    check("U6 second copyback", gc_copyback(0, T0),
          T0 + F + 2 * (TR + TPROG));
}

/*
 * U8: the line serves moves in booking order. A move with a slow read holds
 * up a move booked after it whose read ended long before: the model limit
 * that the design note states. B waits 1015 us more than a core that took
 * ready work first would make it wait.
 */
static void test_booking_order(void)
{
    printf("# booking order\n");
    setup(F);
    lun_avail[0] = T0 + 990000;
    check("U8 slow move A", gc_move(0, 1, T0, NULL), T0 + 1000000 + F + TPROG);
    check("U8 fast move B waits behind the slot of A", gc_move(2, 3, T0, NULL),
          T0 + 1000000 + 2 * F + TPROG);
}

/* U9: no cost, two LUNs: the program still follows its read */
static void test_no_cost_cross_lun(void)
{
    printf("# no cost, two LUNs\n");
    setup(0);
    check("U9 idle source", gc_move(0, 1, T0, NULL), T0 + TR + TPROG);
    setup(0);
    lun_avail[0] = T0 + 100000;
    check("U9 busy source", gc_move(0, 1, T0, NULL),
          T0 + 100000 + TR + TPROG);
}

/* U7: the slot starts at the latest of ready, now and the free line */
static void test_slot_math(void)
{
    printf("# slot math\n");
    check("U7 ready latest", gc_fw_slot_end(50, 30, 40, 10), 60);
    check("U7 now latest", gc_fw_slot_end(50, 90, 40, 10), 100);
    check("U7 line latest", gc_fw_slot_end(50, 30, 80, 10), 90);
    check("U7 no cost keeps the start", gc_fw_slot_end(50, 30, 80, 0), 80);
    check("U7 64-bit times", gc_fw_slot_end(1ULL << 40, 0, 0, 1ULL << 31),
          (1ULL << 40) + (1ULL << 31));
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    /* line buffered, so an abort keeps every TAP line written so far */
    setvbuf(stdout, NULL, _IOLBF, 0);

    test_one_move();
    test_two_moves_one_lun();
    test_shared_line();
    test_busy_destination();
    test_busy_source();
    test_copyback();
    test_slot_math();
    test_booking_order();
    test_no_cost_cross_lun();
    if (media_up) {
        nand_media_destroy(&media);
    }
    printf("1..%d\n", ntests);
    return failures ? 1 : 0;
}
