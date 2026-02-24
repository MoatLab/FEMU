#ifndef __CYLON_CACHE_IMPL_H
#define __CYLON_CACHE_IMPL_H

#include "cache.h"
#include "policy/cache_policy.h"

static inline CacheWay cache_get_way(const Cache *c)
{
    return c->way;
}

static inline int cache_get_size(const Cache *c)
{
    return c->size;
}

static inline struct ssd *cache_get_ssd(const Cache *c)
{
    return c->ssd;
}

static inline GTree *cache_get_tree(const Cache *c)
{
    return c->tree;
}

static inline CacheSet *cache_get_set(Cache *c, lpn_t lpn)
{
    uint32_t set_idx = (lpn * 2654435761U) % (uint32_t)c->nr_sets;
    return &c->sets[set_idx];
}

static inline void cache_entry_free(CacheEntry *e)
{
    if (e && e->policy_data) {
        g_free(e->policy_data);
    }
    g_free(e);
}

static inline void cache_inc_entry_count(Cache *c)
{
    c->entry_count++;
}

static inline void cache_dec_entry_count(Cache *c)
{
    c->entry_count--;
}

static inline void cache_inc_set_count(CacheSet *set)
{
    set->count++;
}

static inline void cache_dec_set_count(CacheSet *set)
{
    set->count--;
}

#endif
