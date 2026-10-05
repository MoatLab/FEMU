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
        .ghosts = g_hash_table_new(g_int64_hash, g_int64_equal),
    };
    c->sets = g_new0(FemuCxlSet, c->nsets);
    for (i = 0; i < c->nsets; i++) {
        g_queue_init(&c->sets[i].small);
        g_queue_init(&c->sets[i].main);
        g_queue_init(&c->sets[i].ghost);
        g_queue_init(&c->sets[i].pinned);
    }
}

FemuCxlSet *femu_cxl_cache_set(FemuCxlCache *c, uint64_t lpn)
{
    return c->nsets ? &c->sets[lpn % c->nsets] : NULL;
}

static GQueue *entry_queue(FemuCxlSet *set, FemuCxlQueue queue)
{
    switch (queue) {
    case FEMU_CXL_SMALL:
        return &set->small;
    case FEMU_CXL_MAIN:
        return &set->main;
    default:
        return &set->pinned;
    }
}

/* Moving the node itself keeps e->link valid across rotations. */
static void entry_move(FemuCxlSet *set, FemuCxlEntry *e, FemuCxlQueue to)
{
    g_queue_unlink(entry_queue(set, e->queue), e->link);
    g_queue_push_tail_link(entry_queue(set, to), e->link);
    e->queue = to;
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

static bool ghost_remove(FemuCxlCache *c, FemuCxlSet *set, uint64_t lpn)
{
    GList *link = g_hash_table_lookup(c->ghosts, &lpn);

    if (!link) {
        return false;
    }
    g_hash_table_remove(c->ghosts, &lpn);
    g_free(link->data);
    g_queue_delete_link(&set->ghost, link);
    return true;
}

static bool cache_evict(FemuCxlCache *c, FemuCxlSet *set,
                         FemuCxlEvict evict, FemuCxlKeep keep, void *opaque)
{
    GQueue *queue = &set->small;
    /* Pins take ways away; size the small queue from what is left. */
    uint32_t ways = c->ways - set->pinned.length;
    FemuCxlEntry *e;
    bool ghost = false;
    unsigned kept = 0;
    GQueue *forced = NULL;
    /* Each entry is rotated, demoted or promoted only a few times. */
    uint64_t budget = 8 * ((uint64_t)c->ways + 1);

    /*
     * @keep makes the policy pass over an entry: it goes to the far end of
     * its queue, as if just inserted, and the policy goes on with its own
     * rules. Each entry is passed over at most once in a row; when S3-FIFO
     * finds every entry of its queue kept, it tries the other queue, until
     * a promotion empties that one and the choice is made again.
     */
    for (;;) {
        if (!budget--) {
            return false;
        }
        if (forced && g_queue_is_empty(forced)) {
            forced = NULL;
        }
        if (forced) {
            queue = forced;
        } else if (c->policy == FEMU_CXL_S3FIFO && c->ways > 1) {
            queue = (set->small.length >= MAX(1, ways / 10) ||
                     g_queue_is_empty(&set->main)) ? &set->small : &set->main;
        }
        e = c->policy == FEMU_CXL_LIFO ? g_queue_peek_tail(queue) :
                                       g_queue_peek_head(queue);
        g_assert(e);
        if (c->policy == FEMU_CXL_CLOCK && e->freq) {
            e->freq = 0;
            g_queue_push_tail_link(queue, g_queue_pop_head_link(queue));
        } else if (c->policy == FEMU_CXL_S3FIFO && c->ways > 1 &&
                   queue == &set->small && e->freq > 1) {
            e->freq = 0;
            entry_move(set, e, FEMU_CXL_MAIN);
        } else if (c->policy == FEMU_CXL_S3FIFO &&
                   queue == &set->main && e->freq) {
            e->freq--;
            g_queue_push_tail_link(queue, g_queue_pop_head_link(queue));
        } else if (keep && keep(opaque, e->lpn)) {
            if (++kept > queue->length) {
                GQueue *other = queue == &set->small ? &set->main :
                                                       &set->small;

                if (forced || g_queue_is_empty(other)) {
                    return false;
                }
                forced = other;
                kept = 0;
                continue;
            }
            if (c->policy == FEMU_CXL_LIFO) {
                g_queue_push_head_link(queue, g_queue_pop_tail_link(queue));
            } else {
                g_queue_push_tail_link(queue, g_queue_pop_head_link(queue));
            }
            continue;
        } else {
            break;
        }
        kept = 0;
    }
    ghost = c->policy == FEMU_CXL_S3FIFO && queue == &set->small;
    /* Keep the entry resident if the media cannot accept its write. */
    if (evict && !evict(opaque, e)) {
        return false;
    }
    if (ghost) {
        uint64_t *key = g_new(uint64_t, 1);

        *key = e->lpn;
        g_queue_push_tail(&set->ghost, key);
        g_hash_table_insert(c->ghosts, key, set->ghost.tail);
        while (set->ghost.length > c->ways) {
            uint64_t *old = g_queue_pop_head(&set->ghost);

            g_hash_table_remove(c->ghosts, old);
            g_free(old);
        }
    }
    g_queue_delete_link(queue, e->link);
    g_hash_table_remove(c->entries, &e->lpn);
    g_free(e);
    c->evictions++;
    return true;
}

FemuCxlEntry *femu_cxl_cache_insert(FemuCxlCache *c, uint64_t lpn,
                                   FemuCxlEvict evict, void *opaque)
{
    return femu_cxl_cache_insert_keep(c, lpn, evict, NULL, opaque);
}

FemuCxlEntry *femu_cxl_cache_insert_keep(FemuCxlCache *c, uint64_t lpn,
                                         FemuCxlEvict evict, FemuCxlKeep keep,
                                         void *opaque)
{
    FemuCxlSet *set;
    FemuCxlEntry *e;
    bool main;
    uint32_t tries;

    if (!c->nsets) {
        return NULL;
    }
    set = &c->sets[lpn % c->nsets];
    e = g_hash_table_lookup(c->entries, &lpn);
    if (e) {
        return e;
    }
    if (set->pinned.length == c->ways) {
        return NULL;
    }
    /* A ghost hit goes to main; take it before evictions add ghosts. */
    main = ghost_remove(c, set, lpn) && c->ways > 1;
    /*
     * An eviction callback can drop the BQL (a write-back), and another
     * access may then insert this page or take the freed way: look again
     * after each eviction.
     */
    for (tries = 0;; tries++) {
        e = g_hash_table_lookup(c->entries, &lpn);
        if (e) {
            return e;
        }
        /* A set whose every way is pinned has nothing to evict. */
        if (set->pinned.length == c->ways || tries > c->ways) {
            return NULL;
        }
        if (set->small.length + set->main.length + set->pinned.length <
            c->ways) {
            break;
        }
        if (!cache_evict(c, set, evict, keep, opaque)) {
            return NULL;
        }
    }
    e = g_new0(FemuCxlEntry, 1);
    e->lpn = lpn;
    e->freq = c->policy == FEMU_CXL_CLOCK;
    e->queue = main ? FEMU_CXL_MAIN : FEMU_CXL_SMALL;
    g_queue_push_tail(entry_queue(set, e->queue), e);
    e->link = entry_queue(set, e->queue)->tail;
    g_hash_table_insert(c->entries, &e->lpn, e);
    c->inserts++;
    return e;
}

/* Pinned entries stay; only small and main are evicted. */
bool femu_cxl_cache_clear(FemuCxlCache *c, FemuCxlEvict evict, void *opaque)
{
    uint32_t i;

    for (i = 0; i < c->nsets; i++) {
        FemuCxlSet *set = &c->sets[i];

        while (set->small.length + set->main.length) {
            if (!cache_evict(c, set, evict, NULL, opaque)) {
                return false;
            }
        }
        while (set->ghost.head) {
            uint64_t *key = set->ghost.head->data;

            ghost_remove(c, set, *key);
        }
    }
    return true;
}

void femu_cxl_cache_destroy(FemuCxlCache *c)
{
    uint32_t i;

    femu_cxl_cache_clear(c, NULL, NULL);
    for (i = 0; i < c->nsets; i++) {
        FemuCxlEntry *e;

        while ((e = g_queue_pop_head(&c->sets[i].pinned))) {
            g_hash_table_remove(c->entries, &e->lpn);
            g_free(e);
        }
    }
    c->pinned = 0;
    g_hash_table_destroy(c->entries);
    g_hash_table_destroy(c->ghosts);
    g_free(c->sets);
}

bool femu_cxl_cache_all_pinned(FemuCxlCache *c, uint64_t lpn)
{
    FemuCxlSet *set = femu_cxl_cache_set(c, lpn);

    return set && set->pinned.length == c->ways;
}

uint32_t femu_cxl_cache_pin_room(FemuCxlCache *c, uint64_t lpn)
{
    FemuCxlSet *set = femu_cxl_cache_set(c, lpn);

    return set ? c->ways - set->pinned.length : 0;
}

void femu_cxl_cache_pin(FemuCxlCache *c, FemuCxlEntry *e)
{
    if (e->queue != FEMU_CXL_PINNED) {
        entry_move(femu_cxl_cache_set(c, e->lpn), e, FEMU_CXL_PINNED);
        c->pinned++;
    }
}

/* Requeue as a fresh insert would; under LIFO that makes it the next victim. */
void femu_cxl_cache_unpin(FemuCxlCache *c, FemuCxlEntry *e)
{
    if (e->queue == FEMU_CXL_PINNED) {
        entry_move(femu_cxl_cache_set(c, e->lpn), e,
                   c->policy == FEMU_CXL_S3FIFO && c->ways > 1 ?
                   FEMU_CXL_MAIN : FEMU_CXL_SMALL);
        c->pinned--;
    }
}

void femu_cxl_cache_unpin_all(FemuCxlCache *c)
{
    uint32_t i;

    for (i = 0; c->pinned && i < c->nsets; i++) {
        while (c->sets[i].pinned.head) {
            femu_cxl_cache_unpin(c, c->sets[i].pinned.head->data);
        }
    }
}

/* Drop one entry, pinned or not, without leaving a ghost behind. */
bool femu_cxl_cache_remove(FemuCxlCache *c, FemuCxlEntry *e,
                           FemuCxlEvict evict, void *opaque)
{
    FemuCxlSet *set = femu_cxl_cache_set(c, e->lpn);

    if (evict && !evict(opaque, e)) {
        return false;
    }
    if (e->queue == FEMU_CXL_PINNED) {
        c->pinned--;
    }
    g_queue_delete_link(entry_queue(set, e->queue), e->link);
    ghost_remove(c, set, e->lpn);
    g_hash_table_remove(c->entries, &e->lpn);
    g_free(e);
    return true;
}

/*
 * Write back dirty pinned entries; they stay resident and pinned. Callers
 * revoke direct mappings first, so the dirty bit is current here.
 */
bool femu_cxl_cache_clean_pinned(FemuCxlCache *c, FemuCxlEvict wb,
                                 void *opaque)
{
    uint32_t i;

    for (i = 0; c->pinned && i < c->nsets; i++) {
        GList *l;

        for (l = c->sets[i].pinned.head; l; l = l->next) {
            FemuCxlEntry *e = l->data;

            if (!e->dirty) {
                continue;
            }
            if (wb && !wb(opaque, e)) {
                return false;
            }
            e->dirty = false;
        }
    }
    return true;
}

/* Whether every pinned entry still fits the geometry @pages / @ways. */
bool femu_cxl_cache_pins_fit(FemuCxlCache *c, uint32_t pages, uint32_t ways)
{
    g_autoptr(GHashTable) counts = NULL;
    uint32_t nsets = pages / ways;
    uint32_t i;

    if (!c->pinned) {
        return true;
    }
    if (!nsets || c->pinned > pages) {
        return false;
    }
    counts = g_hash_table_new(g_direct_hash, g_direct_equal);
    for (i = 0; i < c->nsets; i++) {
        GList *l;

        for (l = c->sets[i].pinned.head; l; l = l->next) {
            gpointer key = GUINT_TO_POINTER(((FemuCxlEntry *)l->data)->lpn %
                                            nsets);
            uint32_t n = GPOINTER_TO_UINT(g_hash_table_lookup(counts, key));

            if (n == ways) {
                return false;
            }
            g_hash_table_insert(counts, key, GUINT_TO_POINTER(n + 1));
        }
    }
    return true;
}

/*
 * Rebuild with a new geometry, keeping pinned pages pinned. The caller has
 * evicted everything else and written the pinned pages back, and checked
 * femu_cxl_cache_pins_fit(); event totals carry over.
 */
void femu_cxl_cache_rebuild(FemuCxlCache *c, uint32_t pages, uint32_t ways)
{
    g_autoptr(GArray) pins = g_array_new(false, false, sizeof(uint64_t));
    FemuCxlCache previous;
    uint32_t i;

    for (i = 0; i < c->nsets; i++) {
        GList *l;

        for (l = c->sets[i].pinned.head; l; l = l->next) {
            g_array_append_val(pins, ((FemuCxlEntry *)l->data)->lpn);
        }
    }
    previous = *c;
    femu_cxl_cache_destroy(c);
    femu_cxl_cache_init(c, pages, ways, previous.policy);
    for (i = 0; i < pins->len; i++) {
        FemuCxlEntry *e = femu_cxl_cache_insert(c,
                              g_array_index(pins, uint64_t, i), NULL, NULL);

        g_assert(e);
        femu_cxl_cache_pin(c, e);
    }
    c->hits = previous.hits;
    c->misses = previous.misses;
    c->inserts = previous.inserts;
    c->evictions = previous.evictions;
    c->generation = previous.generation + 1;
}
