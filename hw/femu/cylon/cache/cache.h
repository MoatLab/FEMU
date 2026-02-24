#ifndef __CYLON_CACHE_H
#define __CYLON_CACHE_H

#include "qemu/osdep.h"
#include "qemu/queue.h"
#include <glib.h>

struct ssd;

/* Cache way: 1 = single entry per set; FULL = use full capacity per set */
typedef enum CacheWay {
    CACHE_WAY_1 = 0,
    CACHE_WAY_2,
    CACHE_WAY_4,
    CACHE_WAY_8,
    CACHE_WAY_16,
    CACHE_WAY_FULL
} CacheWay;

typedef uint64_t lpn_t;

#define CACHE_PAGE_SIZE  4096

typedef struct CacheEntry {
    lpn_t lpn;
    bool dirty;
    void *policy_data;
    uint32_t slot_id;   /* index into cache_backend (prealloc) for this page */
    QTAILQ_ENTRY(CacheEntry) entry;
} CacheEntry;

typedef struct CacheSet {
    CacheEntry *entry;       /* single entry when way == CACHE_WAY_1 */
    QTAILQ_HEAD(, CacheEntry) queue;
    int count;
    void *policy_private;    /* per-set policy data (e.g. S3FIFO: ghost/small lists; CLOCK: hand) */
} CacheSet;

typedef struct CacheStats {
    uint64_t insert_count;
    uint64_t evict_count;
} CacheStats;

struct CachePolicy;

typedef struct Cache {
    struct ssd *ssd;
    int policy_id;
    const struct CachePolicy *policy;
    int size;                /* max entries */
    CacheWay way;
    GTree *tree;             /* lpn -> CacheEntry */
    void *policy_private;    /* per-policy data (e.g. S3FIFO: ghost_tree) */
    CacheSet *sets;
    int nr_sets;
    int entry_count;
    CacheStats stats;
    void *backend;           /* for direct MR / EPT (optional) */
    /* Preallocated cache_backend (DER) and NAND backend for memcpy */
    void    *cache_buf;      /* cache_backend.buf_space */
    int64_t cache_buf_size;
    void    *nand_buf;       /* mbe->logical_space */
    int64_t nand_size;
    uint32_t next_slot;      /* slot allocator */
    uint32_t nr_slots;
} Cache;

/* Flush one page from cache to NAND (implemented in FTL) */
void cache_flush_page(struct ssd *ssd, lpn_t lpn);

Cache *cache_create(struct ssd *ssd, int policy_id, int size, CacheWay way);
void cache_destroy(Cache *c);

CacheEntry *cache_lookup(Cache *c, lpn_t lpn);
int cylon_cache_insert(Cache *c, CacheEntry *entry, int prefetch);

/* Set backends for NAND <-> cache_backend memcpy (call after create) */
void cache_set_backend(Cache *c, void *cache_buf, int64_t cache_buf_size,
                       void *nand_buf, int64_t nand_size);

#endif
