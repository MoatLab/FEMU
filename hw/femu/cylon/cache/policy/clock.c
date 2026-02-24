#include "../cache.h"
#include "../cache_impl.h"
#include "cache_policy.h"
#include "../../../nvme.h"
#include "../../../ftl/ftl.h"
#include <glib.h>

/* Per-set CLOCK private data */
typedef struct ClockSetPrivate {
    CacheEntry *hand;
} ClockSetPrivate;

static inline ClockSetPrivate *clock_set_private(CacheSet *set)
{
    return (ClockSetPrivate *)set->policy_private;
}

static inline CacheEntry *clock_hand(CacheSet *set)
{
    ClockSetPrivate *sp = clock_set_private(set);
    return sp ? sp->hand : NULL;
}

static inline void clock_set_hand(CacheSet *set, CacheEntry *e)
{
    ClockSetPrivate *sp = clock_set_private(set);
    if (sp) sp->hand = e;
}

/* Per-entry CLOCK policy data */
typedef struct {
    uint8_t ref;  /* Reference bit for CLOCK algorithm */
} ClockPolicyData;

/* Helper functions to access CLOCK policy data */
static inline ClockPolicyData *clock_get_data(void *policy_data)
{
    return (ClockPolicyData *)policy_data;
}

static inline uint8_t clock_get_ref(void *policy_data)
{
    ClockPolicyData *data = clock_get_data(policy_data);
    return data ? data->ref : 0;
}

static inline void clock_set_ref(void *policy_data, uint8_t ref)
{
    ClockPolicyData *data = clock_get_data(policy_data);
    if (data) {
        data->ref = ref;
    }
}

/* CLOCK policy implementation */
static inline CacheEntry *clock_next(CacheSet *set, CacheEntry *cur)
{
    if (!cur) {
        return QTAILQ_FIRST(&set->queue);
    }
    CacheEntry *next = QTAILQ_NEXT(cur, entry);
    return next ? next : QTAILQ_FIRST(&set->queue);
}

/* List/metadata only; high-level does epte_set_trap, flush, tree remove, counts, free */
static CacheEntry *clock_evict_victim(Cache *cache, CacheSet *set)
{
    if (QTAILQ_EMPTY(&set->queue)) {
        return NULL;
    }

    if (!clock_hand(set)) {
        clock_set_hand(set, QTAILQ_FIRST(&set->queue));
    }

    CacheEntry *ent = clock_hand(set);

    while (1) {
        if (!ent) {
            ent = QTAILQ_FIRST(&set->queue);
            if (!ent) {
                return NULL;
            }
        }

        if (clock_get_ref(ent->policy_data) == 0) {
            CacheEntry *next = clock_next(set, ent);

            QTAILQ_REMOVE(&set->queue, ent, entry);

            if (QTAILQ_EMPTY(&set->queue)) {
                clock_set_hand(set, NULL);
            } else {
                clock_set_hand(set, (next == ent) ? QTAILQ_FIRST(&set->queue) : next);
            }
            return ent;
        } else {
            clock_set_ref(ent->policy_data, 0);
            ent = clock_next(set, ent);
            clock_set_hand(set, ent);
        }
    }
}

static int clock_insert_entry(Cache *cache, CacheEntry *entry)
{
    CacheSet *set = cache_get_set(cache, entry->lpn);
    CacheWay way = cache_get_way(cache);
    int ent_max = (way == CACHE_WAY_FULL) ? cache_get_size(cache) : (1 << way);
    CacheEntry target = { .lpn = entry->lpn };

    /* Check if already in cache: touch (set ref) only */
    if (g_tree_lookup(cache_get_tree(cache), &target)) {
        if (entry->policy_data) {
            clock_set_ref(entry->policy_data, 1);
        }
        return 0;
    }

    if (set->count >= ent_max) {
        return -1;  /* High-level evicts then retries */
    }

    /* Initialize policy data */
    if (!entry->policy_data) {
        entry->policy_data = g_malloc0(sizeof(ClockPolicyData));
        if (!entry->policy_data) {
            return -1;
        }
    }
    clock_set_ref(entry->policy_data, 1);

    /* Place at tail */
    QTAILQ_INSERT_TAIL(&set->queue, entry, entry);

    if (!clock_hand(set)) {
        clock_set_hand(set, entry);
    }

    g_tree_insert(cache_get_tree(cache), entry, entry);
    cache_inc_entry_count(cache);
    cache_inc_set_count(set);
    cache->stats.insert_count++;

    return 1;
}

static void clock_init(Cache *cache)
{
    int i;
    for (i = 0; i < cache->nr_sets; i++) {
        ClockSetPrivate *sp = g_malloc0(sizeof(ClockSetPrivate));
        cache->sets[i].policy_private = sp;
    }
}

static void clock_cleanup(Cache *cache)
{
    int i;
    for (i = 0; i < cache->nr_sets; i++) {
        g_free(cache->sets[i].policy_private);
        cache->sets[i].policy_private = NULL;
    }
}

/* CLOCK policy definition */
static const CachePolicy clock_policy = {
    .name = "CLOCK",
    .evict_victim = clock_evict_victim,
    .insert_entry = clock_insert_entry,
    .init = clock_init,
    .cleanup = clock_cleanup,
    .opaque = NULL,
};

void cache_policy_clock_register(void)
{
    cache_policy_register(CACHE_POLICY_CLOCK, &clock_policy);
}
