#include "../cache.h"
#include "../cache_impl.h"
#include "cache_policy.h"
#include "../../../nvme.h"
#include "../../../ftl/ftl.h"
#include <glib.h>

/* LIFO: evict = list/metadata only; high-level does flush, EPT, tree remove, free */
static CacheEntry *lifo_evict_victim(Cache *cache, CacheSet *set)
{
    CacheEntry *victim = NULL;
    CacheWay way = cache_get_way(cache);

    if (way == CACHE_WAY_1) {
        victim = set->entry;
        if (victim) {
            set->entry = NULL;
        }
    } else {
        if (QTAILQ_EMPTY(&set->queue)) {
            return NULL;
        }
        victim = QTAILQ_LAST(&set->queue);
        QTAILQ_REMOVE(&set->queue, victim, entry);
    }

    if (!victim) {
        return NULL;
    }
    /* List/metadata only; high-level does epte_set_trap, flush, tree remove, counts, free */
    return victim;
}

static int lifo_insert_entry(Cache *cache, CacheEntry *entry)
{
    CacheSet *set = cache_get_set(cache, entry->lpn);
    CacheWay way = cache_get_way(cache);
    int ent_max = (way == CACHE_WAY_FULL) ? cache_get_size(cache) : (1 << way);
    CacheEntry target = { .lpn = entry->lpn };

    if (g_tree_lookup(cache_get_tree(cache), &target)) {
        return 0;
    }
    if (set->count >= ent_max) {
        return -1;
    }

    if (way == CACHE_WAY_1) {
        set->entry = entry;
    } else {
        QTAILQ_INSERT_TAIL(&set->queue, entry, entry);
    }

    g_tree_insert(cache_get_tree(cache), entry, entry);
    cache_inc_entry_count(cache);
    cache_inc_set_count(set);
    cache->stats.insert_count++;
    return 1;
}

static void lifo_init(Cache *cache)
{
    /* LIFO doesn't need initialization */
}

static void lifo_cleanup(Cache *cache)
{
    /* LIFO doesn't need cleanup */
}

/* LIFO policy definition */
static const CachePolicy lifo_policy = {
    .name = "LIFO",
    .evict_victim = lifo_evict_victim,
    .insert_entry = lifo_insert_entry,
    .init = lifo_init,
    .cleanup = lifo_cleanup,
    .opaque = NULL,
};

void cache_policy_lifo_register(void)
{
    cache_policy_register(CACHE_POLICY_LIFO, &lifo_policy);
}
