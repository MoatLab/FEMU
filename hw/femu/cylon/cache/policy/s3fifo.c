#include "../cache.h"
#include "../cache_impl.h"
#include "cache_policy.h"
#include "../../../nvme.h"
#include "../../../ftl/ftl.h"
#include <glib.h>

/* Per-cache S3FIFO private data */
typedef struct S3FifoCachePrivate {
    GTree *ghost_tree;
} S3FifoCachePrivate;

/* Per-set S3FIFO private data (ghost + small/main queues and counts) */
typedef struct S3FifoSetPrivate {
    QTAILQ_HEAD(, CacheEntry) ghost;
    QTAILQ_HEAD(, CacheEntry) small;
    int cnt_ghost;
    int cnt_main;
    int cnt_small;
} S3FifoSetPrivate;

static inline S3FifoCachePrivate *s3fifo_cache_private(const Cache *c)
{
    return (S3FifoCachePrivate *)c->policy_private;
}

static inline GTree *s3fifo_ghost_tree(const Cache *c)
{
    S3FifoCachePrivate *pv = s3fifo_cache_private(c);
    return pv ? pv->ghost_tree : NULL;
}

static inline S3FifoSetPrivate *s3fifo_set_private(CacheSet *set)
{
    return (S3FifoSetPrivate *)set->policy_private;
}

/* S3FIFO policy private data (per CacheEntry) */
typedef struct {
    uint8_t freq;  /* Frequency counter */
    uint8_t tier;  /* Tier: 0 = S (small), 1 = M (main) */
} S3FifoPolicyData;

/* Helper functions to access S3FIFO policy data */
static inline S3FifoPolicyData *s3fifo_get_data(void *policy_data)
{
    return (S3FifoPolicyData *)policy_data;
}

static inline uint8_t s3fifo_get_freq(void *policy_data)
{
    S3FifoPolicyData *data = s3fifo_get_data(policy_data);
    return data ? data->freq : 0;
}

static inline void s3fifo_set_freq(void *policy_data, uint8_t freq)
{
    S3FifoPolicyData *data = s3fifo_get_data(policy_data);
    if (data) {
        data->freq = freq;
    }
}

static inline uint8_t s3fifo_get_tier(void *policy_data)
{
    S3FifoPolicyData *data = s3fifo_get_data(policy_data);
    return data ? data->tier : 0;
}

static inline void s3fifo_set_tier(void *policy_data, uint8_t tier)
{
    S3FifoPolicyData *data = s3fifo_get_data(policy_data);
    if (data) {
        data->tier = tier;
    }
}

/* S3FIFO helper functions */
static inline int s3_cap_s(int ent_max)
{
    int s = ent_max / 10;
    return s ? s : 1;
}

static inline int s3_cap_m(int ent_max)
{
    return ent_max - s3_cap_s(ent_max);
}

static inline int s3_cap_g(int ent_max)
{
    return s3_cap_m(ent_max);
}

static inline void freq_inc(CacheEntry *e)
{
    if (!e->policy_data) {
        return;
    }
    uint8_t freq = s3fifo_get_freq(e->policy_data);
    if (freq < 3) {
        s3fifo_set_freq(e->policy_data, freq + 1);
    }
}

static inline void freq_dec(CacheEntry *e)
{
    if (!e->policy_data) {
        return;
    }
    uint8_t freq = s3fifo_get_freq(e->policy_data);
    if (freq > 0) {
        s3fifo_set_freq(e->policy_data, freq - 1);
    }
}

static int s3fifo_lpn_cmp(const void *a, const void *b)
{
    const CacheEntry *ea = a, *eb = b;
    if (ea->lpn < eb->lpn) return -1;
    if (ea->lpn > eb->lpn) return 1;
    return 0;
}

static void evict_ghost(Cache *cache, CacheSet *set, int cap_g)
{
    S3FifoSetPrivate *sp = s3fifo_set_private(set);
    GTree *gt = s3fifo_ghost_tree(cache);
    CacheEntry *e;

    if (!sp || !gt) return;
    e = QTAILQ_LAST(&sp->ghost);
    if (e) {
        QTAILQ_REMOVE(&sp->ghost, e, entry);
        sp->cnt_ghost--;
        g_tree_remove(gt, e);
        cache_entry_free(e);
    }
}

static void insert_ghost(Cache *cache, CacheSet *set, CacheEntry *entry, int cap_g)
{
    S3FifoSetPrivate *sp = s3fifo_set_private(set);
    GTree *gt = s3fifo_ghost_tree(cache);

    if (!sp || !gt) return;
    QTAILQ_INSERT_HEAD(&sp->ghost, entry, entry);
    sp->cnt_ghost++;
    g_tree_insert(gt, entry, entry);

    while (sp->cnt_ghost > cap_g) {
        evict_ghost(cache, set, cap_g);
    }
}

/* List/metadata only; returns victim. High-level does epte_set_trap, flush, tree remove, counts, free. */
static CacheEntry *evict_main(Cache *cache, CacheSet *set, int ent_max)
{
    S3FifoSetPrivate *sp = s3fifo_set_private(set);
    CacheEntry *victim = NULL;

    if (!sp) return NULL;
    while (1) {
        victim = QTAILQ_LAST(&set->queue);
        if (!victim) {
            return NULL;
        }
        QTAILQ_REMOVE(&set->queue, victim, entry);

        if (s3fifo_get_freq(victim->policy_data) > 0) {
            freq_dec(victim);
            QTAILQ_INSERT_HEAD(&set->queue, victim, entry);
            victim = NULL;
        } else {
            sp->cnt_main--;
            return victim;
        }
    }
}

/* List/metadata only; returns victim. When adding to ghost, use a new lpn-only entry; caller returns original. */
static CacheEntry *evict_small(Cache *cache, CacheSet *set, int ent_max)
{
    S3FifoSetPrivate *sp = s3fifo_set_private(set);
    int cap_g = s3_cap_g(ent_max);
    CacheEntry *victim = NULL;

    if (!sp) return NULL;
    while (1) {
        victim = QTAILQ_LAST(&sp->small);
        if (!victim) {
            return NULL;
        }
        QTAILQ_REMOVE(&sp->small, victim, entry);
        sp->cnt_small--;

        if (s3fifo_get_freq(victim->policy_data) > 1) {
            QTAILQ_INSERT_HEAD(&set->queue, victim, entry);
            sp->cnt_main++;
            victim = NULL;
            if (sp->cnt_main > s3_cap_m(ent_max)) {
                return evict_main(cache, set, ent_max);
            }
        } else {
            CacheEntry *ghost_entry = g_malloc0(sizeof(CacheEntry));
            ghost_entry->lpn = victim->lpn;
            insert_ghost(cache, set, ghost_entry, cap_g);
            return victim;
        }
    }
}

static CacheEntry *s3fifo_evict_victim(Cache *cache, CacheSet *set)
{
    S3FifoSetPrivate *sp = s3fifo_set_private(set);
    CacheWay way = cache_get_way(cache);
    int ent_max = (way == CACHE_WAY_FULL) ? cache_get_size(cache) : (1 << way);

    if (way == CACHE_WAY_1) {
        CacheEntry *victim = set->entry;
        if (!victim) {
            return NULL;
        }
        set->entry = NULL;
        return victim;
    }
    if (!sp) return NULL;
    if (sp->cnt_small > s3_cap_s(ent_max)) {
        return evict_small(cache, set, ent_max);
    }
    return evict_main(cache, set, ent_max);
}

static int s3fifo_insert_entry(Cache *cache, CacheEntry *entry)
{
    CacheSet *set = cache_get_set(cache, entry->lpn);
    CacheWay way = cache_get_way(cache);
    int ent_max = (way == CACHE_WAY_FULL) ? cache_get_size(cache) : (1 << way);
    CacheEntry target = { .lpn = entry->lpn };

    /* Check if already in cache: touch (freq_inc) only */
    if (g_tree_lookup(cache_get_tree(cache), &target)) {
        if (entry->policy_data) {
            freq_inc(entry);
        }
        return 0;
    }

    if (set->count >= ent_max) {
        return -1;  /* High-level evicts then retries */
    }

    /* Insert entry */
    if (way == CACHE_WAY_1) {
        set->entry = entry;
    } else {
        S3FifoSetPrivate *sp = s3fifo_set_private(set);
        GTree *gt = s3fifo_ghost_tree(cache);
        CacheEntry *ghost_entry = (sp && gt) ? g_tree_lookup(gt, &target) : NULL;
        if (ghost_entry) {
            g_tree_remove(gt, ghost_entry);
            QTAILQ_REMOVE(&sp->ghost, ghost_entry, entry);
            sp->cnt_ghost--;
            cache_entry_free(ghost_entry);
            QTAILQ_INSERT_HEAD(&set->queue, entry, entry);
            sp->cnt_main++;
        } else if (sp) {
            QTAILQ_INSERT_HEAD(&sp->small, entry, entry);
            sp->cnt_small++;
        }
    }

    /* Initialize policy data */
    if (!entry->policy_data) {
        entry->policy_data = g_malloc0(sizeof(S3FifoPolicyData));
        if (!entry->policy_data) {
            return -1;
        }
    }
    s3fifo_set_freq(entry->policy_data, 0);
    g_tree_insert(cache_get_tree(cache), entry, entry);

    cache_inc_entry_count(cache);
    cache_inc_set_count(set);
    cache->stats.insert_count++;

    return 1;
}

static void s3fifo_init(Cache *cache)
{
    S3FifoCachePrivate *cp;
    S3FifoSetPrivate *sp;
    int i;

    cp = g_malloc0(sizeof(S3FifoCachePrivate));
    cp->ghost_tree = g_tree_new(s3fifo_lpn_cmp);
    cache->policy_private = cp;

    for (i = 0; i < cache->nr_sets; i++) {
        sp = g_malloc0(sizeof(S3FifoSetPrivate));
        QTAILQ_INIT(&sp->ghost);
        QTAILQ_INIT(&sp->small);
        cache->sets[i].policy_private = sp;
    }
}

static void s3fifo_cleanup(Cache *cache)
{
    S3FifoCachePrivate *cp = s3fifo_cache_private(cache);
    int i;

    if (!cp) return;
    for (i = 0; i < cache->nr_sets; i++) {
        S3FifoSetPrivate *sp = s3fifo_set_private(&cache->sets[i]);
        CacheEntry *e, *next;
        if (!sp) continue;
        QTAILQ_FOREACH_SAFE(e, &sp->ghost, entry, next) {
            QTAILQ_REMOVE(&sp->ghost, e, entry);
            g_tree_remove(cp->ghost_tree, e);
            cache_entry_free(e);
        }
        g_free(sp);
        cache->sets[i].policy_private = NULL;
    }
    g_tree_destroy(cp->ghost_tree);
    g_free(cp);
    cache->policy_private = NULL;
}

/* S3FIFO policy definition */
static const CachePolicy s3fifo_policy = {
    .name = "S3FIFO",
    .evict_victim = s3fifo_evict_victim,
    .insert_entry = s3fifo_insert_entry,
    .init = s3fifo_init,
    .cleanup = s3fifo_cleanup,
    .opaque = NULL,
};

void cache_policy_s3fifo_register(void)
{
    cache_policy_register(CACHE_POLICY_S3FIFO, &s3fifo_policy);
}
