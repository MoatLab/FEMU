/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Unit test for the KV-SSD LSM-tree index (kvssd/kv-lsm.c). A plain array
 * of the newest state of each key is the reference. The page counts of
 * the small cases are worked out by hand in the comments.
 */
#include "qemu/osdep.h"

/*
 * The core is included here so that its allocations can fail on cue: the
 * Nth one after fail_nth is set returns NULL.
 */
static int fail_nth;

static void *test_malloc(size_t n)
{
    if (fail_nth && --fail_nth == 0) {
        return NULL;
    }
    return malloc(n);
}

static void *test_calloc(size_t n, size_t sz)
{
    if (fail_nth && --fail_nth == 0) {
        return NULL;
    }
    return calloc(n, sz);
}

#define malloc test_malloc
#define calloc test_calloc
#include "hw/femu/kvssd/kv-lsm.c"
#undef malloc
#undef calloc

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

#define NKEYS 20000

/* key i: its 4 big-endian bytes, then i % 13 pad bytes, so lengths vary */
static uint8_t make_key(uint32_t i, uint8_t *k)
{
    uint8_t kl = 4 + i % 13;

    k[0] = i >> 24;
    k[1] = i >> 16;
    k[2] = i >> 8;
    k[3] = i;
    memset(k + 4, 'x', kl - 4);
    return kl;
}

static int key_cmp(const uint8_t *a, uint8_t al, const uint8_t *b, uint8_t bl)
{
    int c = memcmp(a, b, al < bl ? al : bl);

    return c ? c : (al > bl) - (al < bl);
}

static uint32_t rng = 12345;

static uint32_t next_rand(void)
{
    rng = rng * 1103515245u + 12345u;
    return rng >> 8;
}

/* reference: the slot of each key, or KV_LSM_NO_SLOT */
static uint32_t ref[NKEYS];

static int sort_idx[NKEYS];
static int live_idx[NKEYS];

static int idx_cmp(const void *pa, const void *pb)
{
    uint8_t a[16], b[16];
    uint8_t al = make_key(*(const int *)pa, a);
    uint8_t bl = make_key(*(const int *)pb, b);

    return key_cmp(a, al, b, bl);
}

static bool get_ok(KvLsm *l, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        uint8_t k[16];
        uint8_t kl = make_key(i, k);
        uint32_t slot = 0;
        bool live = kv_lsm_get(l, k, kl, &slot, false);

        if (live != (ref[i] != KV_LSM_NO_SLOT) ||
            (live && slot != ref[i])) {
            printf("# key %u: live %d slot %u, want %u\n", i, live, slot,
                   ref[i]);
            return false;
        }
    }
    return true;
}

/* no tombstone in the deepest level: nothing below it could be shadowed */
static bool deepest_clean(const KvLsm *l)
{
    int d = kv_lsm_depth(l);

    if (!d) {
        return true;
    }
    for (uint32_t i = 0; i < l->lvl[d - 1].nr; i++) {
        if (l->lvl[d - 1].rec[i].dead) {
            return false;
        }
    }
    return true;
}

/* each level is sorted with one record per key, and its pages cover it */
static bool runs_ok(const KvLsm *l)
{
    for (int i = 0; i < KV_LSM_MAX_LEVELS; i++) {
        const KvLsmRun *r = &l->lvl[i];

        if (r->nr && (!r->npg || r->pg[0].first != 0)) {
            return false;
        }
        for (uint32_t p = 1; p < r->npg; p++) {
            if (r->pg[p].first <= r->pg[p - 1].first ||
                r->pg[p].first >= r->nr) {
                return false;
            }
        }
        for (uint32_t k = 1; k < r->nr; k++) {
            if (key_cmp(r->rec[k - 1].key, r->rec[k - 1].kl,
                        r->rec[k].key, r->rec[k].kl) >= 0) {
                return false;
            }
        }
    }
    return true;
}

typedef struct ScanState {
    int count;
    int limit;
    uint8_t key[NKEYS][16];
    uint8_t kl[NKEYS];
    uint32_t slot[NKEYS];
} ScanState;

static ScanState scan;

static bool scan_fn(void *opaque, const uint8_t *key, uint8_t kl,
                    uint32_t slot)
{
    ScanState *s = opaque;

    if (s->count >= NKEYS) {
        return false;
    }
    memcpy(s->key[s->count], key, kl);
    s->kl[s->count] = kl;
    s->slot[s->count] = slot;
    s->count++;
    return !s->limit || s->count < s->limit;
}

/* the live keys from the first at or after @start, then the wrap */
static bool scan_matches(KvLsm *l, const uint8_t *start, uint8_t start_len)
{
    int live = 0;
    int first = 0;
    int pos = 0;

    for (int i = 0; i < NKEYS; i++) {
        if (ref[sort_idx[i]] != KV_LSM_NO_SLOT) {
            live_idx[live++] = sort_idx[i];
        }
    }
    if (start_len) {
        while (first < live) {
            uint8_t k[16];
            uint8_t kl = make_key(live_idx[first], k);

            if (key_cmp(k, kl, start, start_len) >= 0) {
                break;
            }
            first++;
        }
    }
    scan.count = 0;
    scan.limit = 0;
    if (kv_lsm_scan(l, start, start_len, scan_fn, &scan) ||
        scan.count != live) {
        printf("# scan returned %d keys, want %d\n", scan.count, live);
        return false;
    }
    for (int n = 0; n < live; n++) {
        int i = live_idx[(first + n) % live];
        uint8_t k[16];
        uint8_t kl = make_key(i, k);

        if (scan.kl[pos] != kl || memcmp(scan.key[pos], k, kl) ||
            scan.slot[pos] != ref[i]) {
            printf("# scan entry %d is not key %d\n", pos, i);
            return false;
        }
        pos++;
    }
    return true;
}

static void reset_sort(void)
{
    for (int i = 0; i < NKEYS; i++) {
        sort_idx[i] = i;
    }
    qsort(sort_idx, NKEYS, sizeof(int), idx_cmp);
}

#define NOPS 80000
#define NPAGES (1u << 22)

/*
 * The flash and slot owner the tree reports to. Each put has its own slot
 * (its op number), so a slot leaves the tree once, and never while it is
 * the newest record of its key. Each page is freed once, after it was
 * programmed.
 */
static uint32_t key_of[NOPS];
static uint8_t in_tree[NOPS];
static uint8_t *page_live;
static uint64_t next_page;
static uint64_t pages_live;
static uint64_t drops;
static uint64_t bad_drops;
static uint64_t bad_frees;
static int fail_alloc;

static bool own_alloc(void *opaque, int level, uint64_t *id)
{
    (void)opaque;
    (void)level;
    if (fail_alloc && --fail_alloc == 0) {
        return false;
    }
    if (next_page >= NPAGES) {
        return false;
    }
    page_live[next_page] = 1;
    pages_live++;
    *id = next_page++;
    return true;
}

static void own_free(void *opaque, uint64_t id)
{
    (void)opaque;
    if (id >= NPAGES || !page_live[id]) {
        bad_frees++;
        return;
    }
    page_live[id] = 0;
    pages_live--;
}

static void own_drop(void *opaque, uint32_t slot)
{
    (void)opaque;
    drops++;
    if (slot >= NOPS || !in_tree[slot] || ref[key_of[slot]] == slot) {
        bad_drops++;
        return;
    }
    in_tree[slot] = 0;
}

static const KvLsmOps own_ops = {
    .alloc = own_alloc,
    .free_page = own_free,
    .drop = own_drop,
};

static void own_reset(void)
{
    if (!page_live) {
        page_live = calloc(NPAGES, 1);
    }
    memset(page_live, 0, NPAGES);
    memset(in_tree, 0, sizeof(in_tree));
    next_page = 0;
    pages_live = 0;
    drops = 0;
    bad_drops = 0;
    bad_frees = 0;
    fail_alloc = 0;
}

/* the pages the levels name are the live ones; the live slots are in a run */
static bool owners_ok(const KvLsm *l)
{
    uint64_t pages = 0;
    uint64_t recs = 0;
    uint64_t slots = 0;

    for (int i = 1; i <= KV_LSM_MAX_LEVELS; i++) {
        const KvLsmRun *r = &l->lvl[i - 1];

        for (uint32_t p = 0; p < r->npg; p++) {
            if (kv_lsm_level_pinned(l, i)) {
                if (r->pg[p].id != KV_LSM_NO_PAGE) {
                    return false;
                }
                continue;
            }
            if (r->pg[p].id >= NPAGES || !page_live[r->pg[p].id]) {
                return false;
            }
            pages++;
        }
        for (uint32_t k = 0; k < r->nr; k++) {
            recs += !r->rec[k].dead;
        }
    }
    for (uint32_t k = 0; k < l->mem.nr; k++) {
        recs += !l->mem.rec[k].dead;
    }
    for (uint32_t s = 0; s < NOPS; s++) {
        slots += in_tree[s];
    }
    return pages == pages_live && recs == slots && !bad_drops && !bad_frees;
}

/* random puts, overwrites and deletes against the reference */
static void test_random(void)
{
    KvLsm l;
    bool ok = true;
    bool clean = true;
    bool sorted = true;
    bool owned = true;
    uint8_t k[17];
    uint8_t kl;

    own_reset();
    CHECK(kv_lsm_init(&l, 64, 4, 1, 8, &own_ops, NULL) == 0);
    for (int i = 0; i < NKEYS; i++) {
        ref[i] = KV_LSM_NO_SLOT;
    }
    for (int op = 0; op < NOPS; op++) {
        uint32_t i = next_rand() % NKEYS;
        uint32_t slot = (next_rand() % 3 == 0) ? KV_LSM_NO_SLOT : (uint32_t)op;
        uint32_t old = ref[i];

        kl = make_key(i, k);
        if (slot != KV_LSM_NO_SLOT) {
            key_of[slot] = i;
            in_tree[slot] = 1;
        }
        /* the reference changes first: the old record is no longer newest */
        ref[i] = slot;
        if (kv_lsm_put(&l, k, kl, slot)) {
            ref[i] = old;
            ok = false;
            break;
        }
        if (op % 4000 == 0) {
            ok = ok && get_ok(&l, NKEYS);
            clean = clean && deepest_clean(&l);
            sorted = sorted && runs_ok(&l);
            owned = owned && owners_ok(&l);
        }
    }
    CHECK(ok && get_ok(&l, NKEYS));
    CHECK(clean && deepest_clean(&l));
    CHECK(sorted && runs_ok(&l));
    CHECK(owned && owners_ok(&l) && drops > 0 && pages_live > 0);
    CHECK(kv_lsm_depth(&l) >= 3);
    CHECK(l.flushes > 0 && l.compactions > 0 && l.dropped > 0);

    reset_sort();
    CHECK(scan_matches(&l, NULL, 0));
    kl = make_key(sort_idx[NKEYS / 2], k);
    CHECK(scan_matches(&l, k, kl));
    /* a start key that is no key: between two keys */
    kl = make_key(sort_idx[NKEYS / 3], k);
    if (kl == 16) {
        kl = make_key(sort_idx[NKEYS / 3 + 1], k);
    }
    k[kl] = 0;
    CHECK(scan_matches(&l, k, kl + 1));

    /* the scan stops when its callback says so */
    scan.count = 0;
    scan.limit = 10;
    CHECK(kv_lsm_scan(&l, NULL, 0, scan_fn, &scan) == 0 && scan.count == 10);

    /*
     * A full compaction leaves one level with the newest live record of
     * each key: no tombstone, no old record, each dropped slot reported.
     */
    {
        int runs = 0;
        uint64_t live = 0;

        CHECK(kv_lsm_compact_all(&l) == 0);
        for (int i = 0; i < KV_LSM_MAX_LEVELS; i++) {
            runs += l.lvl[i].nr != 0;
        }
        for (int i = 0; i < NKEYS; i++) {
            live += ref[i] != KV_LSM_NO_SLOT;
        }
        CHECK(runs == 1 && l.mem.nr == 0 && kv_lsm_records(&l) == live);
        CHECK(get_ok(&l, NKEYS) && deepest_clean(&l) && runs_ok(&l) &&
              owners_ok(&l));
    }

    kv_lsm_clear(&l);
    for (int i = 0; i < NKEYS; i++) {
        ref[i] = KV_LSM_NO_SLOT;
    }
    CHECK(kv_lsm_depth(&l) == 0 && get_ok(&l, NKEYS) && l.flushes == 0);
    kv_lsm_destroy(&l);
}

static uint64_t ios[KV_LSM_IO_NR];
static uint64_t last_id;

static int last_level;

static void count_io(void *opaque, uint64_t id, KvLsmIo io, int level)
{
    (void)opaque;
    ios[io]++;
    last_id = id;
    last_level = level;
}

static const KvLsmOps count_ops = {
    .io = count_io,
    .alloc = own_alloc,
    .free_page = own_free,
};

static void put_u(KvLsm *l, uint32_t i, uint32_t slot)
{
    uint8_t k[4] = { i >> 24, i >> 16, i >> 8, i };

    kv_lsm_put(l, k, 4, slot);
}

static uint64_t probes(KvLsm *l, uint32_t i)
{
    uint8_t k[4] = { i >> 24, i >> 16, i >> 8, i };
    uint64_t before = ios[KV_LSM_IO_PROBE];

    kv_lsm_get(l, k, 4, NULL, true);
    return ios[KV_LSM_IO_PROBE] - before;
}

/*
 * memtable 4, ratio 2, 2 records a page, no pinned level:
 *  put 1..4, put 5   flush [1..4] to an empty L1: 2 programs
 *  put 6..8, put 9   flush [5..8]; it overlaps L1 page [3,4]: 1 read,
 *                    [3..8] is 3 programs; L1 = 8 = cap(1)
 *  put 10..12, 13    flush [9..12]; it overlaps page [7,8]: 1 read,
 *                    3 programs; L1 = 12 > 8, so L1 (6 pages) merges into
 *                    the empty L2: 6 reads, 6 programs
 *  reads 8, programs 14, flushes 3, compactions 1
 */
static void test_counts(void)
{
    KvLsm l;
    uint8_t k[4];
    uint32_t slot = 0;

    memset(ios, 0, sizeof(ios));
    own_reset();
    CHECK(kv_lsm_init(&l, 4, 2, 0, 2, &count_ops, NULL) == 0);
    for (uint32_t i = 1; i <= 5; i++) {
        put_u(&l, i, i);
    }
    CHECK(ios[KV_LSM_IO_COMPACT_READ] == 0 &&
          ios[KV_LSM_IO_COMPACT_PROGRAM] == 2);
    for (uint32_t i = 6; i <= 9; i++) {
        put_u(&l, i, i);
    }
    CHECK(ios[KV_LSM_IO_COMPACT_READ] == 1 &&
          ios[KV_LSM_IO_COMPACT_PROGRAM] == 5);
    /* the page [1,2] lay outside the merge: it keeps its records and id */
    CHECK(l.lvl[0].npg == 4 && l.lvl[0].pg[0].id == 0 &&
          l.lvl[0].pg[0].first == 0 && l.lvl[0].pg[1].first == 2);
    for (uint32_t i = 10; i <= 13; i++) {
        put_u(&l, i, i);
    }
    CHECK(ios[KV_LSM_IO_COMPACT_READ] == 8);
    CHECK(ios[KV_LSM_IO_COMPACT_PROGRAM] == 14);
    CHECK(l.flushes == 3 && l.compactions == 1);
    CHECK(l.lvl[0].nr == 0 && l.lvl[1].nr == 12 && l.lvl[1].npg == 6);
    CHECK(l.pages[KV_LSM_IO_COMPACT_READ] == 8);
    /* 14 programmed, 8 replaced: the 6 pages of L2 stay */
    CHECK(pages_live == 6 && !bad_frees);

    /* key 13 is in the memtable, key 3 in L2, key 99 past every level */
    CHECK(probes(&l, 13) == 0);
    CHECK(probes(&l, 3) == 1);
    CHECK(probes(&l, 99) == 0);

    /*
     * The scan of L2 enters each of its 6 pages once. From key 7 (page 3)
     * the first pass enters pages 3 to 5 and the wrap pages 0 to 2. From
     * key 8, the wrap ends in page 3, which the first pass read.
     */
    memset(ios, 0, sizeof(ios));
    scan.count = 0;
    scan.limit = 0;
    kv_lsm_scan(&l, NULL, 0, scan_fn, &scan);
    CHECK(scan.count == 13 && ios[KV_LSM_IO_SCAN] == 6);
    for (uint32_t s = 7; s <= 8; s++) {
        k[0] = k[1] = k[2] = 0;
        k[3] = s;
        memset(ios, 0, sizeof(ios));
        scan.count = 0;
        kv_lsm_scan(&l, k, 4, scan_fn, &scan);
        CHECK(scan.count == 13 && ios[KV_LSM_IO_SCAN] == 6);
        CHECK(scan.kl[0] == 4 && scan.key[0][3] == s);
    }

    /*
     * A seek reads the page the level list names. A start between keys 6
     * and 7 names page [5,6], which holds no key at or after it, so the
     * seek reads page [7,8] too: two reads for one key. A scan that stops
     * at key 8 does not read the page after it.
     */
    {
        uint8_t mid[5] = { 0, 0, 0, 6, 0 };

        memset(ios, 0, sizeof(ios));
        scan.count = 0;
        scan.limit = 1;
        kv_lsm_scan(&l, mid, 5, scan_fn, &scan);
        CHECK(scan.count == 1 && scan.key[0][3] == 7 &&
              ios[KV_LSM_IO_SCAN] == 2);
        k[3] = 7;
        memset(ios, 0, sizeof(ios));
        scan.count = 0;
        scan.limit = 2;
        kv_lsm_scan(&l, k, 4, scan_fn, &scan);
        CHECK(scan.count == 2 && ios[KV_LSM_IO_SCAN] == 1);
        scan.limit = 0;
    }

    /*
     * Value GC: keys 3 and 4 share a page of L2, so their check is one
     * read, and both go back to the memtable. Key 13 is in the memtable,
     * so its pointer changes in DRAM.
     */
    memset(ios, 0, sizeof(ios));
    CHECK(kv_lsm_gc_begin(&l) == 0);
    k[3] = 3;
    CHECK(kv_lsm_gc_check(&l, k, 4, &slot) && slot == 3);
    k[3] = 4;
    CHECK(kv_lsm_gc_check(&l, k, 4, &slot) && slot == 4);
    k[3] = 13;
    CHECK(!kv_lsm_gc_check(&l, k, 4, &slot) && slot == 13);
    kv_lsm_gc_check_done(&l);
    CHECK(ios[KV_LSM_IO_GC_READ] == 1 && last_id == l.lvl[1].pg[1].id &&
          last_level == 2);
    kv_lsm_gc_check_done(&l);
    CHECK(ios[KV_LSM_IO_GC_READ] == 1);
    k[3] = 3;
    CHECK(kv_lsm_reinsert(&l, k, 4, 33) == 0);
    k[3] = 4;
    CHECK(kv_lsm_reinsert(&l, k, 4, 44) == 0);
    CHECK(l.reinserted == 2 && l.mem.nr == 3);
    k[3] = 3;
    CHECK(kv_lsm_get(&l, k, 4, &slot, true) && slot == 33);
    CHECK(!kv_lsm_gc_check(&l, k, 4, &slot) && slot == 33);

    /* an absent key: the check reads the page its range names, no slot */
    CHECK(kv_lsm_gc_begin(&l) == 0);
    {
        uint8_t mid[5] = { 0, 0, 0, 6, 0 };

        memset(ios, 0, sizeof(ios));
        CHECK(!kv_lsm_gc_check(&l, mid, 5, &slot) &&
              slot == KV_LSM_NO_SLOT);
        kv_lsm_gc_check_done(&l);
        CHECK(ios[KV_LSM_IO_GC_READ] == 1);
    }

    /* meta page GC moves page 0 of L2; the level list follows it */
    {
        uint64_t old = l.lvl[1].pg[0].id;

        CHECK(kv_lsm_relocate(&l, old, 777) && l.lvl[1].pg[0].id == 777);
        CHECK(!kv_lsm_relocate(&l, old, 778));
    }
    kv_lsm_destroy(&l);
}

/*
 * memtable 16, ratio 2: flushes happen at the 17th, 33rd and 49th put.
 * After 33 puts level 1 holds 32 = cap(1); the 49th makes it 48, so it
 * merges into level 2.
 */
static void test_depth(void)
{
    KvLsm l;

    own_reset();
    CHECK(kv_lsm_init(&l, 16, 2, 1, 4, &count_ops, NULL) == 0);
    for (uint32_t i = 0; i < 33; i++) {
        put_u(&l, i, i);
    }
    CHECK(kv_lsm_depth(&l) == 1 && l.lvl[0].nr == 32);
    for (uint32_t i = 33; i < 49; i++) {
        put_u(&l, i, i);
    }
    CHECK(kv_lsm_depth(&l) == 2 && l.lvl[0].nr == 0 && l.lvl[1].nr == 48);
    CHECK(kv_lsm_level_cap(&l, 1) == 32 && kv_lsm_level_cap(&l, 2) == 64);
    CHECK(kv_lsm_level_cap(&l, KV_LSM_MAX_LEVELS) == UINT64_MAX);

    /* level 1 is pinned: a key in level 2 costs one read, in level 1 none */
    for (uint32_t i = 49; i < 65; i++) {
        put_u(&l, i, i);
    }
    CHECK(l.lvl[0].nr == 16 && l.lvl[1].nr == 48);
    CHECK(probes(&l, 10) == 1);
    CHECK(probes(&l, 60) == 0);
    kv_lsm_destroy(&l);

    /* no pinned level: a key below an overlapping level 1 costs two */
    own_reset();
    CHECK(kv_lsm_init(&l, 16, 2, 0, 4, &count_ops, NULL) == 0);
    for (uint32_t i = 0; i < 49; i++) {
        put_u(&l, i * 2, i);
    }
    for (uint32_t i = 0; i < 16; i++) {
        put_u(&l, i * 6 + 1, i);
    }
    put_u(&l, 1000, 0);
    CHECK(l.lvl[0].nr == 16 && l.lvl[1].nr == 48);
    CHECK(probes(&l, 10) == 2);         /* within level 1, found in 2 */
    CHECK(probes(&l, 7) == 1);          /* found in level 1 */
    kv_lsm_destroy(&l);
}

/*
 * A tombstone hides an older record in a lower level; a new key that
 * reuses the slot of the deleted one does not bring it back.
 */
static void test_shadow(void)
{
    KvLsm l;
    uint32_t slot = 0;
    uint8_t a[4] = { 0, 0, 0, 1 };
    uint8_t b[4] = { 0, 0, 0, 2 };

    CHECK(kv_lsm_init(&l, 16, 2, 0, 4, NULL, NULL) == 0);
    kv_lsm_put(&l, a, 4, 5);
    for (uint32_t i = 100; i < 149; i++) {
        put_u(&l, i, i);
    }
    CHECK(kv_lsm_depth(&l) >= 2 && l.mem.nr < 16);
    kv_lsm_put(&l, a, 4, KV_LSM_NO_SLOT);
    kv_lsm_put(&l, b, 4, 5);
    CHECK(!kv_lsm_get(&l, a, 4, &slot, false));
    CHECK(kv_lsm_get(&l, b, 4, &slot, false) && slot == 5);
    /* push the tombstone down; it drops once it reaches the bottom */
    for (uint32_t i = 200; i < 400; i++) {
        put_u(&l, i, i);
    }
    CHECK(!kv_lsm_get(&l, a, 4, &slot, false));
    CHECK(kv_lsm_get(&l, b, 4, &slot, false) && slot == 5);
    CHECK(deepest_clean(&l) && l.dropped >= 2);
    kv_lsm_destroy(&l);

    CHECK(kv_lsm_init(&l, 0, 2, 0, 4, NULL, NULL) == -1);
    CHECK(kv_lsm_init(&l, 16, 1, 0, 4, NULL, NULL) == -1);
    CHECK(kv_lsm_init(&l, 16, 2, KV_LSM_MAX_LEVELS + 1, 4, NULL, NULL) == -1);
}

/*
 * A short allocation in the first merge of a flush fails the put and
 * leaves the tree as it was. One in a later merge of the cascade leaves a
 * level over its capacity; the next flush merges it, even when the level
 * above is within its own. memtable 4, ratio 2: cap(1) 8, cap(2) 16. The
 * 25th put is the sixth flush: L1 reaches 12 and merges into L2, which
 * reaches 24 and merges into L3 with the 11th allocation (4 per merge).
 */
static void test_alloc_fail(void)
{
    KvLsm l;
    uint32_t slot = 0;
    uint8_t k[4];

    CHECK(kv_lsm_init(&l, 4, 2, 0, 2, NULL, NULL) == 0);
    for (uint32_t i = 1; i <= 4; i++) {
        put_u(&l, i, i);
    }
    fail_nth = 1;
    k[0] = k[1] = k[2] = 0;
    k[3] = 5;
    CHECK(kv_lsm_put(&l, k, 4, 5) == -1);
    fail_nth = 0;
    CHECK(l.mem.nr == 4 && l.lvl[0].nr == 0 && l.flushes == 0);
    CHECK(!kv_lsm_get(&l, k, 4, &slot, false));
    k[3] = 2;
    CHECK(kv_lsm_get(&l, k, 4, &slot, false) && slot == 2);
    for (uint32_t i = 5; i <= 24; i++) {
        put_u(&l, i, i);
    }
    CHECK(l.lvl[0].nr == 8 && l.lvl[1].nr == 12);
    fail_nth = 11;
    put_u(&l, 25, 25);
    fail_nth = 0;
    CHECK(l.lvl[0].nr == 0 && l.lvl[1].nr == 24 && l.lvl[2].nr == 0);
    for (uint32_t i = 26; i <= 29; i++) {
        put_u(&l, i, i);
    }
    CHECK(l.lvl[0].nr == 4 && l.lvl[1].nr == 0 && l.lvl[2].nr == 24);
    {
        bool all = true;

        for (uint32_t i = 1; i <= 29; i++) {
            k[3] = i;
            all = all && kv_lsm_get(&l, k, 4, &slot, false) && slot == i;
        }
        CHECK(all);
    }

    /* the marks of a value GC are taken up front, or not at all */
    fail_nth = 1;
    CHECK(kv_lsm_gc_begin(&l) == -1);
    fail_nth = 0;
    CHECK(!l.lvl[0].dirty && !l.lvl[2].dirty);
    kv_lsm_destroy(&l);
}

/*
 * No free flash page: the merge releases the pages it took and changes
 * nothing, so the put fails and every key reads as before. memtable 4,
 * ratio 2, 2 records a page: the fifth put flushes 4 records into 2 pages.
 */
static void test_no_page(void)
{
    KvLsm l;
    uint32_t slot = 0;
    uint8_t k[4] = { 0, 0, 0, 0 };

    own_reset();
    CHECK(kv_lsm_init(&l, 4, 2, 0, 2, &own_ops, NULL) == 0);
    for (uint32_t i = 1; i <= 4; i++) {
        key_of[i] = i;
        in_tree[i] = 1;
        ref[i] = i;
        put_u(&l, i, i);
    }
    fail_alloc = 2;
    k[3] = 5;
    CHECK(kv_lsm_put(&l, k, 4, 5) == -1);
    CHECK(l.mem.nr == 4 && l.lvl[0].nr == 0 && l.flushes == 0);
    CHECK(pages_live == 0 && next_page == 1 && !bad_frees);
    fail_alloc = 0;
    k[3] = 2;
    CHECK(kv_lsm_get(&l, k, 4, &slot, false) && slot == 2);

    /* a put over a memtable record drops the old one at once */
    ref[2] = 6;
    key_of[6] = 2;
    in_tree[6] = 1;
    CHECK(kv_lsm_put(&l, k, 4, 6) == 0 && drops == 1 && !in_tree[2]);
    k[3] = 5;
    key_of[5] = 5;
    in_tree[5] = 1;
    ref[5] = 5;
    CHECK(kv_lsm_put(&l, k, 4, 5) == 0 && pages_live == 2);
    CHECK(owners_ok(&l));
    kv_lsm_destroy(&l);
}

static bool no_room;

static bool own_room(void *opaque, uint64_t pages)
{
    (void)opaque;
    (void)pages;
    return !no_room;
}

static const KvLsmOps room_ops = {
    .room = own_room,
    .alloc = own_alloc,
    .free_page = own_free,
    .drop = own_drop,
};

/*
 * With no room for a flush, a put fails before it takes a page, and a
 * tombstone goes into the memtable over its capacity. Once there is room,
 * the next put flushes all of it into the empty level 1, which drops the
 * two tombstones. memtable 4, 2 records a page.
 */
static void test_tombstone_over(void)
{
    KvLsm l;
    uint32_t slot = 0;
    uint8_t k[4] = { 0, 0, 0, 0 };

    own_reset();
    CHECK(kv_lsm_init(&l, 4, 2, 0, 2, &room_ops, NULL) == 0);
    for (uint32_t i = 1; i <= 4; i++) {
        key_of[i] = i;
        in_tree[i] = 1;
        ref[i] = i;
        put_u(&l, i, i);
    }
    no_room = true;
    k[3] = 9;
    CHECK(kv_lsm_put(&l, k, 4, 9) == -1 && next_page == 0);
    CHECK(kv_lsm_put_tombstone(&l, k, 4) == 0 && l.mem.nr == 5);
    k[3] = 2;
    ref[2] = KV_LSM_NO_SLOT;
    CHECK(kv_lsm_put_tombstone(&l, k, 4) == 0 && l.mem.nr == 5);
    CHECK(drops == 1 && !kv_lsm_get(&l, k, 4, &slot, false));
    no_room = false;
    k[3] = 10;
    key_of[10] = 10;
    in_tree[10] = 1;
    ref[10] = 10;
    CHECK(kv_lsm_put(&l, k, 4, 10) == 0 && l.mem.nr == 1 &&
          l.lvl[0].nr == 3 && l.flushes == 1);
    CHECK(owners_ok(&l));
    kv_lsm_destroy(&l);
}

int main(void)
{
    test_random();
    test_counts();
    test_depth();
    test_shadow();
    test_alloc_fail();
    test_no_page();
    test_tombstone_over();
    printf("1..%d\n", ntests);
    return failures ? 1 : 0;
}
