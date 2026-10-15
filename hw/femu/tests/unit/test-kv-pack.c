/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Unit test for the KV-SSD packed page header (kvssd/kv-pack.c). The page
 * is 4096 bytes and each record takes a 32 byte header, so 31 records of
 * 100 byte values (132 bytes each) fill 4092 bytes of it.
 */
#include "qemu/osdep.h"

/*
 * The header code is included here so that its allocations can fail on
 * cue: the Nth one after fail_nth is set returns NULL.
 */
static int fail_nth;

static void *test_calloc(size_t n, size_t sz)
{
    if (fail_nth && --fail_nth == 0) {
        return NULL;
    }
    return calloc(n, sz);
}

static void *test_realloc(void *p, size_t n)
{
    if (fail_nth && --fail_nth == 0) {
        return NULL;
    }
    return realloc(p, n);
}

#define calloc test_calloc
#define realloc test_realloc
#include "hw/femu/kvssd/kv-pack.c"
#undef calloc
#undef realloc

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

#define PGSZ    4096u

/* the moves kv_pack_compact() reports */
static uint64_t moved_owner[64];
static uint32_t moved_off[64];
static int nmoved;

static void record_move(void *opaque, uint64_t owner, uint32_t off)
{
    (void)opaque;
    if (nmoved < 64) {
        moved_owner[nmoved] = owner;
        moved_off[nmoved] = off;
    }
    nmoved++;
}

/* a record fits only while the page has its bytes and its header */
static void test_fit(void)
{
    KvPackPage *pg = kv_pack_new();
    uint32_t off;

    CHECK(pg && pg->id == KV_PACK_NO_PAGE && !pg->nr && !pg->fill);
    CHECK(kv_pack_rec(100) == 132);
    CHECK(kv_pack_fits(pg, PGSZ - KV_PACK_HDR, PGSZ));
    CHECK(!kv_pack_fits(pg, PGSZ - KV_PACK_HDR + 1, PGSZ));
    CHECK(!kv_pack_full(pg, PGSZ));

    /* two records of 2016 bytes fill the page exactly */
    CHECK(kv_pack_append(pg, 1, 2016, &off) == 0 && off == 0);
    CHECK(!kv_pack_full(pg, PGSZ));
    CHECK(kv_pack_append(pg, 2, 2016, &off) == 0 && off == 2048);
    CHECK(pg->fill == PGSZ && pg->live == 2 && pg->live_bytes == PGSZ);
    CHECK(!kv_pack_fits(pg, 1, PGSZ));
    CHECK(kv_pack_full(pg, PGSZ));
    /* a dead record is room a compaction can give back: not full */
    CHECK(kv_pack_drop(pg, 0) == 2048);
    CHECK(!kv_pack_full(pg, PGSZ));
    kv_pack_free(pg);
}

/* 31 records fill a page; each is found by its offset; drops count once */
static void test_records(void)
{
    KvPackPage *pg = kv_pack_new();
    uint32_t off;
    bool all = true;

    for (uint32_t i = 0; i < 31; i++) {
        all &= kv_pack_append(pg, 100 + i, 100, &off) == 0 && off == i * 132;
    }
    CHECK(all);
    CHECK(pg->fill == 31 * 132 && pg->live == 31);
    CHECK(!kv_pack_fits(pg, 100, PGSZ));
    CHECK(kv_pack_full(pg, PGSZ));
    for (uint32_t i = 0; i < 31; i++) {
        all &= kv_pack_find(pg, i * 132) == (int)i;
    }
    CHECK(all);
    CHECK(kv_pack_find(pg, 7) == -1);
    CHECK(kv_pack_find(pg, 31 * 132) == -1);

    CHECK(kv_pack_drop(pg, 5) == 132);
    CHECK(kv_pack_drop(pg, 5) == 0);
    CHECK(pg->live == 30 && pg->live_bytes == 30 * 132);
    /* the record stays in the header as dead until a compaction */
    CHECK(pg->nr == 31 && kv_pack_find(pg, 5 * 132) == 5);
    kv_pack_free(pg);
}

/*
 * A compaction closes the gaps of dead records: the live ones after a gap
 * move down, each move is reported, and the fill shrinks to the live bytes.
 */
static void test_compact(void)
{
    KvPackPage *pg = kv_pack_new();
    uint32_t off;

    for (uint32_t i = 0; i < 6; i++) {
        kv_pack_append(pg, i, 100, &off);
    }
    kv_pack_drop(pg, 1);
    kv_pack_drop(pg, 4);
    nmoved = 0;
    kv_pack_compact(pg, record_move, NULL);
    CHECK(pg->nr == 4 && pg->live == 4 && pg->fill == 4 * 132);
    CHECK(pg->live_bytes == pg->fill);
    /* record 0 stays; 2, 3 and 5 move down */
    CHECK(nmoved == 3);
    CHECK(moved_owner[0] == 2 && moved_off[0] == 132);
    CHECK(moved_owner[1] == 3 && moved_off[1] == 264);
    CHECK(moved_owner[2] == 5 && moved_off[2] == 396);
    CHECK(kv_pack_find(pg, 396) == 3 && pg->item[3].owner == 5);
    /* the room is back for a new record at the new fill */
    CHECK(kv_pack_append(pg, 9, 100, &off) == 0 && off == 528);

    /* all dead: the page is empty again */
    for (uint32_t i = 0; i < pg->nr; i++) {
        kv_pack_drop(pg, (int)i);
    }
    kv_pack_compact(pg, NULL, NULL);
    CHECK(pg->nr == 0 && pg->fill == 0 && pg->live == 0 &&
          pg->live_bytes == 0);
    kv_pack_free(pg);
}

/* a failed allocation leaves the header as it was */
static void test_alloc_fail(void)
{
    KvPackPage *pg;
    uint32_t off = 77;
    bool all = true;

    fail_nth = 1;
    CHECK(kv_pack_new() == NULL);

    pg = kv_pack_new();
    fail_nth = 1;
    CHECK(kv_pack_append(pg, 1, 10, &off) == -1);
    CHECK(pg->nr == 0 && pg->fill == 0 && pg->live == 0 && off == 77);

    /* growth past the first 16 items fails; the 16 stay */
    for (uint32_t i = 0; i < 16; i++) {
        all &= kv_pack_append(pg, i, 10, &off) == 0;
    }
    CHECK(all && pg->cap == 16);
    fail_nth = 1;
    CHECK(kv_pack_append(pg, 16, 10, &off) == -1);
    CHECK(pg->nr == 16 && pg->fill == 16 * 42 && pg->live == 16);
    kv_pack_free(pg);

    /* a reserve takes the allocation first; appends then need none */
    pg = kv_pack_new();
    CHECK(kv_pack_reserve(pg, 40) == 0 && pg->cap == 40);
    fail_nth = 1;
    all = true;
    for (uint32_t i = 0; i < 40; i++) {
        all &= kv_pack_append(pg, i, 10, &off) == 0;
    }
    CHECK(all && pg->nr == 40);
    /* the unused fault hits the next allocation: the reserve fails */
    CHECK(kv_pack_reserve(pg, 80) == -1 && pg->cap == 40 && pg->nr == 40);
    fail_nth = 0;
    kv_pack_free(pg);
}

int main(void)
{
    test_fit();
    test_records();
    test_compact();
    test_alloc_fail();
    printf("1..%d\n", ntests);
    return failures ? 1 : 0;
}
