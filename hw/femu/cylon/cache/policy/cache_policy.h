#ifndef __CYLON_CACHE_POLICY_H
#define __CYLON_CACHE_POLICY_H

#include "../cache.h"

/* Policy IDs matching FemuCtrl rep / POLICY_* in femu.h */
enum {
    CACHE_POLICY_NONE = 0,
    CACHE_POLICY_LIFO,
    CACHE_POLICY_FIFO,
    CACHE_POLICY_CLOCK,
    CACHE_POLICY_S3FIFO,
    CACHE_POLICY_MAX
};

typedef struct CachePolicy {
    const char *name;
    
    /* Evict: only list/metadata update; return victim or NULL. No flush, tree remove, EPT, or free. */
    CacheEntry *(*evict_victim)(Cache *cache, CacheSet *set);
    /* Insert: only list/tree/metadata. No memcpy, no EPT. Caller does memcpy + epte_set_direct before this. */
    int (*insert_entry)(Cache *cache, CacheEntry *entry);
    void (*init)(Cache *cache);
    void (*cleanup)(Cache *cache);
    void *opaque;
} CachePolicy;

void cache_policy_register(int policy_id, const CachePolicy *policy);
const CachePolicy *cache_policy_get(int policy_id);
void cache_policy_register_all(void);

void cache_policy_fifo_register(void);
void cache_policy_lifo_register(void);
void cache_policy_clock_register(void);
void cache_policy_s3fifo_register(void);

#endif
