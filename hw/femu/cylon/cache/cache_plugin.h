#ifndef __CYLON_CACHE_PLUGIN_H
#define __CYLON_CACHE_PLUGIN_H

#include "qemu/osdep.h"

typedef uint64_t lpn_t;

struct cache_entry;
struct cache_plugin;

typedef struct cache_ops {
    struct cache_entry *(*lookup)(void *cache_data, lpn_t lpn);
    void (*set_dirty)(struct cache_entry *e, bool dirty);
    bool (*is_dirty)(struct cache_entry *e);
    void (*insert)(void *cache_data, struct cache_entry *e, int prefetch);
    struct cache_entry *(*entry_init)(void *cache_data, lpn_t lpn);
    uint32_t (*get_slot_id)(struct cache_entry *e);
} cache_ops_t;

typedef struct cache_plugin {
    void *cache_data;
    cache_ops_t ops;
} cache_plugin_t;

struct FemuCtrl;
struct cache_plugin *cylon_cache_plugin_create(struct FemuCtrl *n);
void cylon_cache_plugin_destroy(struct cache_plugin *p);

#endif
