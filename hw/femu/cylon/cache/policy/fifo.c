#include "../cache.h"
#include "../cache_impl.h"
#include "cache_policy.h"
#include "../../../nvme.h"
#include "../../../ftl/ftl.h"

/* FIFO: evict = list/metadata only; high-level does flush, EPT, tree remove, free */
static CacheEntry *fifo_evict_victim(Cache *cache, CacheSet *set)
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
        victim = QTAILQ_FIRST(&set->queue);
        QTAILQ_REMOVE(&set->queue, victim, entry);
    }

    if (!victim) {
        return NULL;
    }
    /* List/metadata only; high-level does epte_set_trap, flush, tree remove, counts, free */
    return victim;
}

static int fifo_insert_entry(Cache *cache, CacheEntry *entry)
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

static void fifo_init(Cache *cache)
{
    /* FIFO doesn't need initialization */
}

static void fifo_cleanup(Cache *cache)
{
    /* FIFO doesn't need cleanup */
}

/* FIFO policy definition */
static const CachePolicy fifo_policy = {
    .name = "FIFO",
    .evict_victim = fifo_evict_victim,
    .insert_entry = fifo_insert_entry,
    .init = fifo_init,
    .cleanup = fifo_cleanup,
    .opaque = NULL,
};

void cache_policy_fifo_register(void)
{
    cache_policy_register(CACHE_POLICY_FIFO, &fifo_policy);
}
