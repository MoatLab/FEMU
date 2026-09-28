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

typedef struct FemuCxlEntry {
    uint64_t lpn;
    bool dirty;
    unsigned freq;
} FemuCxlEntry;

typedef struct FemuCxlSet {
    GQueue small;
    GQueue main;
    GQueue ghost;
} FemuCxlSet;

typedef struct FemuCxlCache {
    FemuCxlSet *sets;
    GHashTable *entries;
    uint32_t nsets;
    uint32_t ways;
    FemuCxlPolicy policy;
    uint64_t hits;
    uint64_t misses;
    uint64_t inserts;
    uint64_t evictions;
} FemuCxlCache;

typedef bool (*FemuCxlEvict)(void *opaque, FemuCxlEntry *entry);

bool femu_cxl_policy(const char *name, FemuCxlPolicy *policy);
void femu_cxl_cache_init(FemuCxlCache *c, uint32_t pages, uint32_t ways,
                         FemuCxlPolicy policy);
FemuCxlEntry *femu_cxl_cache_find(FemuCxlCache *c, uint64_t lpn);
FemuCxlEntry *femu_cxl_cache_insert(FemuCxlCache *c, uint64_t lpn,
                                   FemuCxlEvict evict, void *opaque);
bool femu_cxl_cache_clear(FemuCxlCache *c, FemuCxlEvict evict, void *opaque);
void femu_cxl_cache_destroy(FemuCxlCache *c);

#endif
