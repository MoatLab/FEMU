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
 *
 * At most gen_cap protected programs overlap in device time: each takes
 * the slot that is free first and starts no earlier than that, so a full
 * journal stalls the write as a full buffer does on a real drive.
 *
 *   slots f1 <= f2 <= ... :  program p starts at max(stime, f1),
 *                            ends at d, and f1 becomes d
 *
 * Before-images are taken when the write is handled, so the list can be
 * longer than gen_cap; at gen_max the FTL thread waits for a program to
 * end, which bounds the memory.
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
    /* as many programs in flight as the buffer holds pages */
    ssd->gen_cap = MAX(ssd->sp.buffer_size, 1);
    ssd->gen_max = MAX(8 * ssd->gen_cap, 1024);
    ssd->gen_first = INT64_MAX;
    if (ssd_durable_on(ssd)) {
        ssd->gen_slot = g_new0(int64_t, ssd->gen_cap);
    }
}

void ssd_durable_free(struct ssd *ssd)
{
    ssd_durable_drop_all(ssd);
    g_clear_pointer(&ssd->gen_slot, g_free);
}

/*
 * The start of a protected program the caller would book at @stime: no
 * earlier than the first free slot. Sets @book and returns the wait.
 */
uint64_t ssd_durable_start(struct ssd *ssd, uint64_t stime, uint64_t *book)
{
    uint64_t base = stime ? stime : ssd_now(ssd);
    int64_t f = ssd->gen_slot[0];

    *book = stime;
    if (f <= (int64_t)base) {
        return 0;
    }
    *book = f;
    return f - base;
}

/* the program in the first slot was placed and ends at @done */
void ssd_durable_slot_used(struct ssd *ssd, int64_t done)
{
    int64_t *h = ssd->gen_slot;
    uint32_t n = ssd->gen_cap;
    uint32_t i = 0;

    h[0] = done;
    for (;;) {
        uint32_t l = 2 * i + 1;
        uint32_t m = i;
        int64_t t;

        if (l < n && h[l] < h[m]) {
            m = l;
        }
        if (l + 1 < n && h[l + 1] < h[m]) {
            m = l + 1;
        }
        if (m == i) {
            break;
        }
        t = h[i];
        h[i] = h[m];
        h[m] = t;
        i = m;
    }
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
    ssd->gen_first = INT64_MAX;
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
    if (QTAILQ_EMPTY(&ssd->gens) || now < ssd->gen_first) {
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
    ssd->gen_first = INT64_MAX;
    QTAILQ_FOREACH(g, &ssd->gens, link) {
        ssd->gen_first = MIN(ssd->gen_first, g->done);
    }
}

/*
 * Room for one more generation. At gen_max the FTL thread waits for the
 * first pending program to end: every one has an end, so the wait ends.
 * A pause (a cut, a reset, an admin drain) waits for this request, so
 * then the request goes on past gen_max, by at most its own pages, and
 * the pause takes its time at once. False only when the FTL thread stops.
 */
bool ssd_durable_room(struct ssd *ssd)
{
    if (ssd->nr_gens < ssd->gen_max) {
        return true;
    }
    for (;;) {
        int64_t now = ssd_now(ssd);

        ssd_durable_retire(ssd, now);
        if (ssd->nr_gens < ssd->gen_max) {
            return true;
        }
        if (qatomic_read(&ssd->n->ftl_stopping)) {
            return false;
        }
        if (!qatomic_read(&ssd->n->dataplane_started)) {
            return true;
        }
        ssd->durable_waits++;
        g_usleep(MIN(MAX((ssd->gen_first - now) / 1000, 1), 1000));
    }
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
    ssd->gen_first = MIN(ssd->gen_first, done);
}

/*
 * LBAs [@slba, @slba + @nlb) of @ns changed with no program, durable at
 * once (@how, FEMU_DURABLE_*). Each pending before-image of their pages
 * takes the change, so a cut that rolls a page back keeps it. The live
 * bytes and bits changed already.
 */
void bbssd_durable_patch(NvmeNamespace *ns, uint64_t slba, uint32_t nlb,
                         int how)
{
    struct ssd *ssd = ns->ssd;
    uint32_t page_size;
    uint8_t shift = ns->lbaf.lbads;
    ssd_gen *g;

    if (!ssd || !ssd_durable_on(ssd)) {
        return;
    }
    page_size = ssd_page_size(ssd);
    QTAILQ_FOREACH(g, &ssd->gens, link) {
        uint64_t first = (g->lpn * page_size - ns->backend_offset) >> shift;
        uint64_t count = page_size >> shift;
        uint64_t lo = MAX(first, slba);
        uint64_t hi = MIN(first + count, slba + nlb);

        if (g->ns != ns || lo >= hi) {
            continue;
        }
        for (uint64_t lba = lo; lba < hi; lba++) {
            uint64_t i = lba - first;

            switch (how) {
            case FEMU_DURABLE_DEALLOC:
                memset(g->undo + (i << shift), 0, 1u << shift);
                g->lba_state[i] &= ~1;
                break;
            case FEMU_DURABLE_ZEROES_DEAC:
                memset(g->undo + (i << shift), 0, 1u << shift);
                g->lba_state[i] = 0;
                break;
            case FEMU_DURABLE_UNCOR:
                g->lba_state[i] |= 3;
                break;
            }
        }
    }
}

/* every generation of @ns goes: its data was replaced (Format, Sanitize) */
void ssd_durable_drop_ns(struct ssd *ssd, NvmeNamespace *ns)
{
    ssd_gen *g;
    ssd_gen *next;

    QTAILQ_FOREACH_SAFE(g, &ssd->gens, link, next) {
        if (g->ns == ns) {
            ssd_gen_free(ssd, g);
        }
    }
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
