/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * FEMU KV-SSD LSM-tree index (kv_index=lsm).
 *
 * A leveled LSM tree of key -> slot records, after the design of PinK (Im
 * et al., USENIX ATC '20): a sorted memtable in DRAM, levels that grow by a
 * size ratio, a DRAM level list with the first key of each meta page, and
 * top levels pinned whole in DRAM. The tree reports each flash page it
 * would read or program through a callback; the caller charges the time.
 * It needs nothing from QEMU, so a unit test builds it alone.
 */
#ifndef FEMU_KV_LSM_H
#define FEMU_KV_LSM_H

#define KV_LSM_KEY_MAX      16
/* the deepest level takes every record that overflows the one above */
#define KV_LSM_MAX_LEVELS   24
/* flash bytes of a record: 16 key, 8 pointer, 8 length and flags */
#define KV_LSM_REC_BYTES    32
/* DRAM bytes of a level list entry: first key and page address */
#define KV_LSM_LIST_BYTES   (KV_LSM_KEY_MAX + 8)
/* the slot of a tombstone */
#define KV_LSM_NO_SLOT      UINT32_MAX

typedef enum KvLsmIo {
    KV_LSM_IO_PROBE,            /* lookup read, one per unpinned level */
    KV_LSM_IO_SCAN,             /* List read of a page its walk enters */
    KV_LSM_IO_COMPACT_READ,     /* merge input from an unpinned level */
    KV_LSM_IO_COMPACT_PROGRAM,  /* merge output to an unpinned level */
    KV_LSM_IO_GC_READ,          /* validity check of a value GC moves */
    KV_LSM_IO_NR,
} KvLsmIo;

/* the id of a page that only DRAM holds: a page of a pinned level */
#define KV_LSM_NO_PAGE      UINT64_MAX

/*
 * What the tree asks of the flash under it. Meta pages are real pages:
 * @alloc takes one and names it, @io later reports its program, and
 * @free_page says the tree holds nothing in it any more. @drop says a record left the tree, so the value it named
 * is garbage. Each may be NULL.
 */
typedef struct KvLsmOps {
    /* @level is 1 based; the reads of one level in a scan depend on each other */
    void (*io)(void *opaque, uint64_t page_id, KvLsmIo io, int level);
    /* false when fewer than @pages pages are free; asked before alloc */
    bool (*room)(void *opaque, uint64_t pages);
    /*
     * Take a page for a merge output and name it; false when none is
     * free, and the merge then changes nothing. The program itself comes
     * later, as KV_LSM_IO_COMPACT_PROGRAM through @io.
     */
    bool (*alloc)(void *opaque, int level, uint64_t *page_id);
    void (*free_page)(void *opaque, uint64_t page_id);
    void (*drop)(void *opaque, uint32_t slot);
} KvLsmOps;

/* return false to stop the scan */
typedef bool (*KvLsmScanFn)(void *opaque, const uint8_t *key, uint8_t kl,
                            uint32_t slot);

typedef struct KvLsmRec {
    uint8_t  key[KV_LSM_KEY_MAX];
    uint8_t  kl;
    uint8_t  dead;              /* tombstone */
    uint32_t slot;
} KvLsmRec;

/* a level list entry; its records run to the first one of the next page */
typedef struct KvLsmPage {
    uint32_t first;
    uint64_t id;                /* flash page, or KV_LSM_NO_PAGE when pinned */
} KvLsmPage;

typedef struct KvLsmRun {
    KvLsmRec  *rec;
    uint32_t   nr;
    uint32_t   cap;
    KvLsmPage *pg;
    uint32_t   npg;
    uint32_t   pgcap;
    uint8_t   *dirty;           /* pages a value move touched, or NULL */
} KvLsmRun;

typedef struct KvLsm {
    uint32_t mem_cap;           /* memtable records */
    uint32_t ratio;
    uint32_t pinned;            /* levels 1..pinned live in DRAM */
    uint32_t per_page;          /* records of a meta page */
    KvLsmRun mem;
    KvLsmRun lvl[KV_LSM_MAX_LEVELS];    /* lvl[0] is level 1 */
    KvLsmOps ops;
    void *opaque;

    uint64_t flushes;           /* memtable merges into level 1 */
    uint64_t compactions;       /* level merges into the level below */
    uint64_t dropped;           /* shadowed records and tombstones dropped */
    uint64_t reinserted;        /* keys value GC put back in the memtable */
    uint64_t pages[KV_LSM_IO_NR];
} KvLsm;

/* return 0, or -1 when an argument is out of range or memory is short */
int kv_lsm_init(KvLsm *l, uint32_t mem_cap, uint32_t ratio, uint32_t pinned,
                uint32_t per_page, const KvLsmOps *ops, void *opaque);
void kv_lsm_destroy(KvLsm *l);
/*
 * Drop every record and page and zero the counters. No callback runs: the
 * caller resets the flash and the slots itself.
 */
void kv_lsm_clear(KvLsm *l);

/* capacity in records of level @level (1 based); the deepest has no limit */
uint64_t kv_lsm_level_cap(const KvLsm *l, int level);
/* the deepest level that holds a record, or 0 */
int kv_lsm_depth(const KvLsm *l);
bool kv_lsm_level_pinned(const KvLsm *l, int level);
/* DRAM the tree holds: memtable, pinned levels and level lists */
uint64_t kv_lsm_dram_bytes(const KvLsm *l);
/* records in the memtable and every level, tombstones and old ones too */
uint64_t kv_lsm_records(const KvLsm *l);

/*
 * Look @key up. Return true with *@slot set for a live key, false for an
 * absent or deleted one. With @charge, each meta page read of an unpinned
 * level goes to the callback as KV_LSM_IO_PROBE, in lookup order.
 */
bool kv_lsm_get(KvLsm *l, const uint8_t *key, uint8_t kl, uint32_t *slot,
                bool charge);

/*
 * Put a live record (@slot) or a tombstone (KV_LSM_NO_SLOT) in the
 * memtable, flushing first when it is full. A record of the same key in the
 * memtable leaves the tree. Return 0, or -1 when memory or a free page is
 * short; the tree is then as it was.
 */
int kv_lsm_put(KvLsm *l, const uint8_t *key, uint8_t kl, uint32_t slot);

/*
 * Put a tombstone as kv_lsm_put does. When the flush fails, the memtable
 * takes it over its capacity, as device DRAM holds a Delete it cannot
 * merge yet; the next put flushes again. Return -1 only when memory is
 * short.
 */
int kv_lsm_put_tombstone(KvLsm *l, const uint8_t *key, uint8_t kl);

/*
 * Merge every run down into the deepest level, where tombstones and the
 * records they shadow drop. A device does this to take back the space of
 * Deletes that sit in the upper levels. Return 0, or -1 when a merge
 * failed; the merges before it stay done.
 */
int kv_lsm_compact_all(KvLsm *l);

/*
 * Call @fn for each live key in byte order from the first key at or after
 * @start, then from the smallest key up to @start: every live key once.
 * Pages of unpinned levels go to the callback as KV_LSM_IO_SCAN. Return 0,
 * or -1 when memory is short.
 */
int kv_lsm_scan(KvLsm *l, const uint8_t *start, uint8_t start_len,
                KvLsmScanFn fn, void *opaque);

/*
 * Value GC checks a value as PinK does: it looks the key up and compares
 * the newest record with the value it found on flash. kv_lsm_gc_begin()
 * sets up the marks; return 0, or -1 when memory is short.
 * kv_lsm_gc_check() marks each unpinned page the lookup reads and sets
 * *@slot to the newest slot, KV_LSM_NO_SLOT for a deleted or absent key.
 * It returns true when the newest record is in an unpinned level: a moved
 * value must then go back to the memtable (kv_lsm_reinsert), since the
 * flash page keeps the old pointer.
 */
int kv_lsm_gc_begin(KvLsm *l);
bool kv_lsm_gc_check(KvLsm *l, const uint8_t *key, uint8_t kl,
                     uint32_t *slot);
/* read each marked page once, as KV_LSM_IO_GC_READ */
void kv_lsm_gc_check_done(KvLsm *l);
/* put a key that value GC moved back in the memtable; as kv_lsm_put */
int kv_lsm_reinsert(KvLsm *l, const uint8_t *key, uint8_t kl, uint32_t slot);
/*
 * A copy of meta page @old_id is now at @new_id (meta page GC). Return
 * false when no level list names @old_id.
 */
bool kv_lsm_relocate(KvLsm *l, uint64_t old_id, uint64_t new_id);

#endif
