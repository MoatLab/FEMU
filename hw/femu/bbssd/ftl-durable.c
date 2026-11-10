/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * durable_at_done (with power_loss): a written page is durable when its
 * program ends, not when it is booked. Each booked program of a host page
 * keeps a generation: the page's bytes and LBA states before it, and the
 * program's end time. A cut restores what did not end.
 *
 *   per LPN, oldest first:  durable base | g1 (d1) | g2 (d2) | g3 (d3)
 *   g2 ends (now >= d2):    drop g1 and g2; g3 stays
 *   cut at c:               from g3 back, restore while d > c, then stop
 *
 * Programs on different LUNs end out of order, so a generation that ends
 * takes every older one of its LPN with it: their data is older than data
 * that is now durable. The mapping is not rolled back; only the payload
 * and its LBA states are (the reduced model of the T10.5 design).
 */

#include "qemu/osdep.h"
#include "ftl.h"
#include "ftl-internal.h"

typedef struct ssd_gen {
    uint64_t lpn;
    NvmeNamespace *ns;
    uint8_t *undo;
    uint8_t *lba_state;
    int64_t done;
    QTAILQ_ENTRY(ssd_gen) link;     /* all generations, in program order */
} ssd_gen;

bool ssd_durable_on(struct ssd *ssd)
{
    return ssd->n && ssd->n->durable_at_done;
}

void ssd_durable_init(struct ssd *ssd)
{
    QTAILQ_INIT(&ssd->gens);
    ssd->nr_gens = 0;
    /* as many pages as the buffer holds; at the bound writes fail */
    ssd->gen_cap = MAX(ssd->sp.buffer_size, 1);
}

static void ssd_gen_free(struct ssd *ssd, ssd_gen *g)
{
    QTAILQ_REMOVE(&ssd->gens, g, link);
    g_free(g->undo);
    g_free(g->lba_state);
    g_free(g);
    ssd->nr_gens--;
}

void ssd_durable_drop_all(struct ssd *ssd)
{
    ssd_gen *g;

    while ((g = QTAILQ_FIRST(&ssd->gens))) {
        ssd_gen_free(ssd, g);
    }
}

/*
 * Drop the generations whose program ended by @now, each with every older
 * generation of its LPN. The list is in program order: the first pass
 * finds, for each LPN, the position of its newest ended generation; the
 * second drops every generation of that LPN up to that position.
 */
void ssd_durable_retire(struct ssd *ssd, int64_t now)
{
    GHashTable *last;
    uint64_t pos = 0;
    ssd_gen *g;
    ssd_gen *next;

    /* the idle pass calls this often: nothing to do costs nothing */
    if (QTAILQ_EMPTY(&ssd->gens)) {
        return;
    }
    last = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, g_free);

    QTAILQ_FOREACH(g, &ssd->gens, link) {
        pos++;
        if (g->done <= now) {
            uint64_t *p = g_new(uint64_t, 1);

            *p = pos;
            g_hash_table_replace(last, &g->lpn, p);
        }
    }
    pos = 0;
    QTAILQ_FOREACH_SAFE(g, &ssd->gens, link, next) {
        uint64_t *p = g_hash_table_lookup(last, &g->lpn);

        pos++;
        if (p && pos <= *p) {
            /* the key points into a generation; drop the entry first */
            if (pos == *p) {
                g_hash_table_remove(last, &g->lpn);
            }
            ssd_gen_free(ssd, g);
        }
    }
    g_hash_table_destroy(last);
}

/*
 * Room for one more generation. Ended ones go only when the bound is
 * reached, so the common write pays one comparison.
 */
bool ssd_durable_room(struct ssd *ssd)
{
    if (ssd->nr_gens < ssd->gen_cap) {
        return true;
    }
    ssd_durable_retire(ssd, ssd_now(ssd));
    return ssd->nr_gens < ssd->gen_cap;
}

/* keep the before-image of a booked program; takes @undo and @state */
void ssd_durable_push(struct ssd *ssd, NvmeNamespace *ns, uint64_t lpn,
                      uint8_t *undo, uint8_t *state, int64_t done)
{
    ssd_gen *g = g_new0(ssd_gen, 1);

    g->lpn = lpn;
    g->ns = ns;
    g->undo = undo;
    g->lba_state = state;
    g->done = done;
    QTAILQ_INSERT_TAIL(&ssd->gens, g, link);
    ssd->nr_gens++;
}

/* the latest end of a pending program; 0 when none is pending */
int64_t ssd_durable_deadline(struct ssd *ssd)
{
    int64_t end = 0;
    ssd_gen *g;

    QTAILQ_FOREACH(g, &ssd->gens, link) {
        end = MAX(end, g->done);
    }
    return end;
}

/* put the bytes and LBA states of @undo/@state back into page @lpn */
void ssd_page_restore(struct ssd *ssd, NvmeNamespace *ns, uint64_t lpn,
                      const uint8_t *undo, const uint8_t *state)
{
    uint32_t page_size = ssd_page_size(ssd);
    uint8_t shift = ns->lbaf.lbads;
    uint64_t offset = lpn * page_size - ns->backend_offset;
    uint64_t slba = offset >> shift;
    uint8_t *base = (uint8_t *)ssd->n->mbe->logical_space + ns->backend_offset;

    backend_lock_range(ssd->n->mbe, ns->backend_offset + offset, page_size);
    memcpy(base + offset, undo, page_size);
    for (uint32_t i = 0; i < page_size >> shift; i++) {
        if (state[i] & 1) {
            set_bit(slba + i, ns->util);
        } else {
            clear_bit(slba + i, ns->util);
        }
        if (state[i] & 2) {
            set_bit(slba + i, ns->uncorrectable);
        } else {
            clear_bit(slba + i, ns->uncorrectable);
        }
    }
    backend_unlock_range(ssd->n->mbe, ns->backend_offset + offset, page_size);
    rcache_invalidate(ssd, lpn);
}

/*
 * A cut at @c, after the buffered pages are restored: from the newest
 * generation back, each one whose program did not end by @c gives back
 * the page as it was before it. The first one that ended stops the walk
 * of its LPN. Then every generation goes. Returns true when a page changed.
 */
bool ssd_durable_cut(struct ssd *ssd, int64_t c)
{
    bool lost = false;
    ssd_gen *g;
    GHashTable *stop = g_hash_table_new(g_int64_hash, g_int64_equal);

    QTAILQ_FOREACH_REVERSE(g, &ssd->gens, link) {
        if (g_hash_table_contains(stop, &g->lpn)) {
            continue;
        }
        if (g->done <= c) {
            g_hash_table_add(stop, &g->lpn);
            continue;
        }
        ssd_page_restore(ssd, g->ns, g->lpn, g->undo, g->lba_state);
        lost = true;
    }
    g_hash_table_destroy(stop);
    ssd_durable_drop_all(ssd);
    return lost;
}

/* qtest: LPNs with generations, generations, and those already ended */
void ssd_durable_counts(struct ssd *ssd, uint64_t *lpns, uint64_t *gens,
                        uint64_t *ended)
{
    GHashTable *seen = g_hash_table_new(g_int64_hash, g_int64_equal);
    int64_t now = ssd_now(ssd);
    ssd_gen *g;

    *gens = 0;
    *ended = 0;
    QTAILQ_FOREACH(g, &ssd->gens, link) {
        g_hash_table_add(seen, &g->lpn);
        (*gens)++;
        *ended += g->done <= now;
    }
    *lpns = g_hash_table_size(seen);
    g_hash_table_destroy(seen);
}
