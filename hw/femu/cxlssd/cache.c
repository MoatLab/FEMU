/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "cache.h"

bool femu_cxl_policy(const char *name, FemuCxlPolicy *policy)
{
    static const char * const names[] = { "fifo", "lifo", "clock", "s3-fifo" };
    unsigned i;

    for (i = 0; i < G_N_ELEMENTS(names); i++) {
        if (!g_strcmp0(name, names[i])) {
            *policy = i;
            return true;
        }
    }
    return false;
}

void femu_cxl_cache_init(FemuCxlCache *c, uint32_t pages, uint32_t ways,
                         FemuCxlPolicy policy)
{
    uint32_t i;

    *c = (FemuCxlCache) {
        .ways = ways,
        .nsets = pages ? pages / ways : 0,
        .policy = policy,
        .entries = g_hash_table_new(g_int64_hash, g_int64_equal),
    };
    c->sets = g_new0(FemuCxlSet, c->nsets);
    for (i = 0; i < c->nsets; i++) {
        g_queue_init(&c->sets[i].small);
        g_queue_init(&c->sets[i].main);
        g_queue_init(&c->sets[i].ghost);
    }
}

FemuCxlEntry *femu_cxl_cache_find(FemuCxlCache *c, uint64_t lpn)
{
    FemuCxlEntry *e = g_hash_table_lookup(c->entries, &lpn);

    if (e) {
        e->freq = MIN(e->freq + 1, 3);
        c->hits++;
    } else {
        c->misses++;
    }
    return e;
}

static bool ghost_remove(FemuCxlSet *set, uint64_t lpn)
{
    GList *it;

    for (it = set->ghost.head; it; it = it->next) {
        uint64_t *key = it->data;

        if (*key == lpn) {
            g_free(key);
            g_queue_delete_link(&set->ghost, it);
            return true;
        }
    }
    return false;
}

static bool cache_evict(FemuCxlCache *c, FemuCxlSet *set,
                         FemuCxlEvict evict, void *opaque)
{
    GQueue *queue = &set->small;
    FemuCxlEntry *e;
    bool ghost = false;

    for (;;) {
        if (c->policy == FEMU_CXL_S3FIFO && c->ways > 1) {
            queue = (set->small.length >= MAX(1, c->ways / 10) ||
                     g_queue_is_empty(&set->main)) ? &set->small : &set->main;
        }
        e = c->policy == FEMU_CXL_LIFO ? g_queue_peek_tail(queue) :
                                       g_queue_peek_head(queue);
        g_assert(e);
        if (c->policy == FEMU_CXL_CLOCK && e->freq) {
            e->freq = 0;
            g_queue_push_tail(queue, g_queue_pop_head(queue));
        } else if (c->policy == FEMU_CXL_S3FIFO && c->ways > 1 &&
                   queue == &set->small && e->freq > 1) {
            e->freq = 0;
            g_queue_push_tail(&set->main, g_queue_pop_head(queue));
        } else if (c->policy == FEMU_CXL_S3FIFO &&
                   queue == &set->main && e->freq) {
            e->freq--;
            g_queue_push_tail(queue, g_queue_pop_head(queue));
        } else {
            ghost = c->policy == FEMU_CXL_S3FIFO && queue == &set->small;
            break;
        }
    }
    /* Keep the entry resident if the media cannot accept its write. */
    if (evict && !evict(opaque, e)) {
        return false;
    }
    if (ghost) {
        uint64_t *key = g_new(uint64_t, 1);

        *key = e->lpn;
        g_queue_push_tail(&set->ghost, key);
        while (set->ghost.length > c->ways) {
            g_free(g_queue_pop_head(&set->ghost));
        }
    }
    g_queue_remove(queue, e);
    g_hash_table_remove(c->entries, &e->lpn);
    g_free(e);
    c->evictions++;
    return true;
}

FemuCxlEntry *femu_cxl_cache_insert(FemuCxlCache *c, uint64_t lpn,
                                   FemuCxlEvict evict, void *opaque)
{
    FemuCxlSet *set;
    FemuCxlEntry *e;
    bool main;

    if (!c->nsets) {
        return NULL;
    }
    e = g_hash_table_lookup(c->entries, &lpn);
    if (e) {
        return e;
    }
    set = &c->sets[lpn % c->nsets];
    main = ghost_remove(set, lpn) && c->ways > 1;
    if (set->small.length + set->main.length == c->ways &&
        !cache_evict(c, set, evict, opaque)) {
        return NULL;
    }
    e = g_new0(FemuCxlEntry, 1);
    e->lpn = lpn;
    e->freq = c->policy == FEMU_CXL_CLOCK;
    g_queue_push_tail(main ? &set->main : &set->small, e);
    g_hash_table_insert(c->entries, &e->lpn, e);
    c->inserts++;
    return e;
}

bool femu_cxl_cache_clear(FemuCxlCache *c, FemuCxlEvict evict, void *opaque)
{
    uint32_t i;

    for (i = 0; i < c->nsets; i++) {
        FemuCxlSet *set = &c->sets[i];

        while (set->small.length + set->main.length) {
            if (!cache_evict(c, set, evict, opaque)) {
                return false;
            }
        }
        g_queue_clear_full(&set->ghost, g_free);
    }
    return true;
}

void femu_cxl_cache_destroy(FemuCxlCache *c)
{
    femu_cxl_cache_clear(c, NULL, NULL);
    g_hash_table_destroy(c->entries);
    g_free(c->sets);
}
