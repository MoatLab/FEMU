/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FEMU_CXL_CACHE_H
#define FEMU_CXL_CACHE_H

#include <glib.h>
#include <stdbool.h>
#include <stdint.h>

typedef enum FemuCxlPolicy {
    FEMU_CXL_FIFO,
    FEMU_CXL_LIFO,
    FEMU_CXL_CLOCK,
    FEMU_CXL_S3FIFO,
} FemuCxlPolicy;

typedef enum FemuCxlQueue {
    FEMU_CXL_SMALL,
    FEMU_CXL_MAIN,
    FEMU_CXL_PINNED,
} FemuCxlQueue;

typedef struct FemuCxlEntry {
    uint64_t lpn;
    bool dirty;
    unsigned freq;
    /* Hits served by MMIO while the direct-mapping budget was full. */
    unsigned der_hits;
    /* The page lost its direct mapping to a hotter one while cached. */
    bool der_displaced;
    /* The entry's own node in the queue @queue, for O(1) removal. */
    GList *link;
    FemuCxlQueue queue;
} FemuCxlEntry;

/* Pinned entries leave small and main, so eviction never sees them. */
typedef struct FemuCxlSet {
    GQueue small;
    GQueue main;
    GQueue ghost;
    GQueue pinned;
} FemuCxlSet;

typedef struct FemuCxlCache {
    FemuCxlSet *sets;
    GHashTable *entries;
    GHashTable *ghosts;
    uint32_t nsets;
    uint32_t ways;
    FemuCxlPolicy policy;
    uint64_t hits;
    uint64_t misses;
    uint64_t inserts;
    uint64_t evictions;
    uint64_t pinned;
    /* Bumped by every rebuild, so a long operation can notice one. */
    uint64_t generation;
} FemuCxlCache;

typedef bool (*FemuCxlEvict)(void *opaque, FemuCxlEntry *entry);
/* Whether eviction must pass over @lpn and take the next candidate. */
typedef bool (*FemuCxlKeep)(void *opaque, uint64_t lpn);

bool femu_cxl_policy(const char *name, FemuCxlPolicy *policy);
void femu_cxl_cache_init(FemuCxlCache *c, uint32_t pages, uint32_t ways,
                         FemuCxlPolicy policy);
FemuCxlEntry *femu_cxl_cache_find(FemuCxlCache *c, uint64_t lpn);
FemuCxlEntry *femu_cxl_cache_insert(FemuCxlCache *c, uint64_t lpn,
                                   FemuCxlEvict evict, void *opaque);
FemuCxlEntry *femu_cxl_cache_insert_keep(FemuCxlCache *c, uint64_t lpn,
                                         FemuCxlEvict evict, FemuCxlKeep keep,
                                         void *opaque);
bool femu_cxl_cache_clear(FemuCxlCache *c, FemuCxlEvict evict, void *opaque);
void femu_cxl_cache_destroy(FemuCxlCache *c);

FemuCxlSet *femu_cxl_cache_set(FemuCxlCache *c, uint64_t lpn);
bool femu_cxl_cache_all_pinned(FemuCxlCache *c, uint64_t lpn);
uint32_t femu_cxl_cache_pin_room(FemuCxlCache *c, uint64_t lpn);
void femu_cxl_cache_pin(FemuCxlCache *c, FemuCxlEntry *e);
void femu_cxl_cache_unpin(FemuCxlCache *c, FemuCxlEntry *e);
void femu_cxl_cache_unpin_all(FemuCxlCache *c);
bool femu_cxl_cache_remove(FemuCxlCache *c, FemuCxlEntry *e,
                           FemuCxlEvict evict, void *opaque);
bool femu_cxl_cache_clean_pinned(FemuCxlCache *c, FemuCxlEvict wb,
                                 void *opaque);
bool femu_cxl_cache_pins_fit(FemuCxlCache *c, uint32_t pages, uint32_t ways);
void femu_cxl_cache_rebuild(FemuCxlCache *c, uint32_t pages, uint32_t ways);

#endif
