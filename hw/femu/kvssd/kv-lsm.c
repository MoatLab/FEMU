/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * FEMU KV-SSD LSM-tree index (kv_index=lsm). See kv-lsm.h.
 *
 * Each run (the memtable or one level) is a sorted array of records with
 * one record per key. A level also has its level list: the index of the
 * first record and the flash page id of each meta page. A key lives in the
 * newest run that holds it, so a lookup stops at the first hit, and a
 * tombstone there means the key is gone.
 */
#include "qemu/osdep.h"

#include "kv-lsm.h"

static uint32_t kv_lsm_min(uint32_t a, uint32_t b)
{
    return a < b ? a : b;
}

/* byte order over the shorter key, then the shorter key first */
static int kv_lsm_cmp(const uint8_t *a, uint8_t al, const uint8_t *b,
                      uint8_t bl)
{
    int c = memcmp(a, b, kv_lsm_min(al, bl));

    if (c) {
        return c;
    }
    return (al > bl) - (al < bl);
}

static int kv_lsm_rcmp(const KvLsmRec *a, const KvLsmRec *b)
{
    return kv_lsm_cmp(a->key, a->kl, b->key, b->kl);
}

/* the first record in [lo, hi) at or after @key */
static uint32_t kv_lsm_lower(const KvLsmRec *rec, uint32_t lo, uint32_t hi,
                             const uint8_t *key, uint8_t kl)
{
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;

        if (kv_lsm_cmp(rec[mid].key, rec[mid].kl, key, kl) < 0) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo;
}

static void kv_lsm_emit(KvLsm *l, uint64_t id, KvLsmIo io, int level)
{
    l->pages[io]++;
    if (l->ops.io) {
        l->ops.io(l->opaque, id, io, level);
    }
}

static void kv_lsm_run_free(KvLsmRun *r)
{
    free(r->rec);
    free(r->pg);
    free(r->dirty);
    memset(r, 0, sizeof(*r));
}

static uint32_t kv_lsm_page_end(const KvLsmRun *r, uint32_t p)
{
    return p + 1 < r->npg ? r->pg[p + 1].first : r->nr;
}

/*
 * The page whose key range holds @key: the last page whose first key is
 * at or before it, or page 0 for a key before them all. This is the level
 * list search, done in DRAM.
 */
static uint32_t kv_lsm_page_of(const KvLsmRun *r, const uint8_t *key,
                               uint8_t kl)
{
    uint32_t lo = 0;
    uint32_t hi = r->npg;

    while (hi - lo > 1) {
        uint32_t mid = lo + (hi - lo) / 2;
        const KvLsmRec *f = &r->rec[r->pg[mid].first];

        if (kv_lsm_cmp(f->key, f->kl, key, kl) <= 0) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    return lo;
}

/* the page that holds record @pos */
static uint32_t kv_lsm_page_at(const KvLsmRun *r, uint32_t pos)
{
    uint32_t lo = 0;
    uint32_t hi = r->npg;

    while (hi - lo > 1) {
        uint32_t mid = lo + (hi - lo) / 2;

        if (r->pg[mid].first <= pos) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    return lo;
}

/* a key outside the first and last key of a level needs no page of it */
static bool kv_lsm_in_range(const KvLsmRun *r, const uint8_t *key,
                            uint8_t kl)
{
    return r->nr &&
           kv_lsm_cmp(key, kl, r->rec[0].key, r->rec[0].kl) >= 0 &&
           kv_lsm_cmp(key, kl, r->rec[r->nr - 1].key,
                      r->rec[r->nr - 1].kl) <= 0;
}

bool kv_lsm_level_pinned(const KvLsm *l, int level)
{
    return level >= 1 && (uint32_t)level <= l->pinned;
}

uint64_t kv_lsm_level_cap(const KvLsm *l, int level)
{
    uint64_t cap = l->mem_cap;

    if (level >= KV_LSM_MAX_LEVELS) {
        return UINT64_MAX;
    }
    for (int i = 0; i < level; i++) {
        if (cap > UINT64_MAX / l->ratio) {
            return UINT64_MAX;
        }
        cap *= l->ratio;
    }
    return cap;
}

int kv_lsm_depth(const KvLsm *l)
{
    for (int i = KV_LSM_MAX_LEVELS; i >= 1; i--) {
        if (l->lvl[i - 1].nr) {
            return i;
        }
    }
    return 0;
}

uint64_t kv_lsm_dram_bytes(const KvLsm *l)
{
    uint64_t b = (uint64_t)l->mem.nr * KV_LSM_REC_BYTES;

    for (int i = 1; i <= KV_LSM_MAX_LEVELS; i++) {
        const KvLsmRun *r = &l->lvl[i - 1];

        if (kv_lsm_level_pinned(l, i)) {
            b += (uint64_t)r->nr * KV_LSM_REC_BYTES;
        } else {
            b += (uint64_t)r->npg * KV_LSM_LIST_BYTES;
        }
    }
    return b;
}

uint64_t kv_lsm_records(const KvLsm *l)
{
    uint64_t n = l->mem.nr;

    for (int i = 0; i < KV_LSM_MAX_LEVELS; i++) {
        n += l->lvl[i].nr;
    }
    return n;
}

int kv_lsm_init(KvLsm *l, uint32_t mem_cap, uint32_t ratio, uint32_t pinned,
                uint32_t per_page, const KvLsmOps *ops, void *opaque)
{
    memset(l, 0, sizeof(*l));
    if (!mem_cap || ratio < 2 || pinned > KV_LSM_MAX_LEVELS || !per_page) {
        return -1;
    }
    l->mem.rec = malloc((size_t)mem_cap * sizeof(KvLsmRec));
    if (!l->mem.rec) {
        return -1;
    }
    l->mem.cap = mem_cap;
    l->mem_cap = mem_cap;
    l->ratio = ratio;
    l->pinned = pinned;
    l->per_page = per_page;
    if (ops) {
        l->ops = *ops;
    }
    l->opaque = opaque;
    return 0;
}

void kv_lsm_destroy(KvLsm *l)
{
    kv_lsm_run_free(&l->mem);
    for (int i = 0; i < KV_LSM_MAX_LEVELS; i++) {
        kv_lsm_run_free(&l->lvl[i]);
    }
}

void kv_lsm_clear(KvLsm *l)
{
    l->mem.nr = 0;
    for (int i = 0; i < KV_LSM_MAX_LEVELS; i++) {
        kv_lsm_run_free(&l->lvl[i]);
    }
    l->flushes = 0;
    l->compactions = 0;
    l->dropped = 0;
    l->reinserted = 0;
    memset(l->pages, 0, sizeof(l->pages));
}

/* no level below @level holds a record, so a tombstone there shadows nothing */
static bool kv_lsm_deepest(const KvLsm *l, int level)
{
    for (int i = level + 1; i <= KV_LSM_MAX_LEVELS; i++) {
        if (l->lvl[i - 1].nr) {
            return false;
        }
    }
    return true;
}

static void kv_lsm_free_page(KvLsm *l, uint64_t id)
{
    if (id != KV_LSM_NO_PAGE && l->ops.free_page) {
        l->ops.free_page(l->opaque, id);
    }
}

/*
 * Merge run @up (the memtable when @up_level is 0) into level @level.
 * Only the pages of the lower level that the key range of @up overlaps are
 * read and rewritten; the others keep their records and pages. On equal
 * keys the upper record wins. The new arrays and pages are taken before
 * anything changes, so a short allocation leaves both runs as they were.
 * Once the merge commits, the pages it replaced and the records it dropped
 * go back to the caller.
 */
static int kv_lsm_merge(KvLsm *l, KvLsmRun *up, int up_level, int level)
{
    KvLsmRun *lo = &l->lvl[level - 1];
    bool up_flash = up_level > 0 && !kv_lsm_level_pinned(l, up_level);
    bool lo_flash = !kv_lsm_level_pinned(l, level);
    bool drop = kv_lsm_deepest(l, level);
    uint32_t a = 0, b = 0, ra = 0, rb = 0;
    uint32_t i, j, m = 0, midp, new_nr, new_npg, k;
    uint32_t ngone = 0;
    uint64_t total;
    uint64_t dropped = 0;
    KvLsmRec *mid, *rec;
    KvLsmPage *pg;
    uint32_t *gone;

    if (!up->nr) {
        return 0;
    }
    if (lo->nr) {
        a = kv_lsm_page_of(lo, up->rec[0].key, up->rec[0].kl);
        b = kv_lsm_page_of(lo, up->rec[up->nr - 1].key,
                           up->rec[up->nr - 1].kl);
        ra = lo->pg[a].first;
        rb = kv_lsm_page_end(lo, b);
    }

    /* a run indexes its records and pages with 32 bits */
    total = (uint64_t)up->nr + lo->nr;
    if (total > UINT32_MAX) {
        return -1;
    }
    mid = malloc(((size_t)up->nr + (rb - ra)) * sizeof(KvLsmRec));
    gone = malloc(((size_t)(rb - ra) + 1) * sizeof(uint32_t));
    if (!mid || !gone) {
        free(mid);
        free(gone);
        return -1;
    }
    i = 0;
    j = ra;
    while (i < up->nr || j < rb) {
        const KvLsmRec *r;
        int c;

        if (i == up->nr) {
            c = 1;
        } else if (j == rb) {
            c = -1;
        } else {
            c = kv_lsm_rcmp(&up->rec[i], &lo->rec[j]);
        }
        if (c <= 0) {
            r = &up->rec[i++];
            if (c == 0) {
                /* the older record is shadowed */
                if (!lo->rec[j].dead) {
                    gone[ngone++] = lo->rec[j].slot;
                }
                j++;
                dropped++;
            }
        } else {
            r = &lo->rec[j++];
        }
        if (drop && r->dead) {
            dropped++;
            continue;
        }
        mid[m++] = *r;
    }

    midp = (uint32_t)(((uint64_t)m + l->per_page - 1) / l->per_page);
    new_nr = ra + m + (lo->nr - rb);
    new_npg = lo->nr ? a + midp + (lo->npg - b - 1) : midp;
    rec = malloc(((size_t)new_nr ? new_nr : 1) * sizeof(KvLsmRec));
    pg = malloc(((size_t)new_npg ? new_npg : 1) * sizeof(KvLsmPage));
    if (!rec || !pg) {
        goto fail;
    }
    if (lo_flash && l->ops.room && !l->ops.room(l->opaque, midp)) {
        goto fail;
    }
    for (k = 0; k < midp; k++) {
        pg[a + k].first = ra + k * l->per_page;
        pg[a + k].id = KV_LSM_NO_PAGE;
        if (lo_flash && l->ops.alloc &&
            !l->ops.alloc(l->opaque, level, &pg[a + k].id)) {
            while (k--) {
                kv_lsm_free_page(l, pg[a + k].id);
            }
            goto fail;
        }
    }
    if (ra) {
        memcpy(rec, lo->rec, (size_t)ra * sizeof(KvLsmRec));
    }
    if (m) {
        memcpy(rec + ra, mid, (size_t)m * sizeof(KvLsmRec));
    }
    if (lo->nr > rb) {
        memcpy(rec + ra + m, lo->rec + rb,
               (size_t)(lo->nr - rb) * sizeof(KvLsmRec));
    }
    free(mid);

    /* the merge reads its inputs before it programs the output */
    if (up_flash) {
        for (k = 0; k < up->npg; k++) {
            kv_lsm_emit(l, up->pg[k].id, KV_LSM_IO_COMPACT_READ, up_level);
        }
    }
    if (lo_flash && lo->nr) {
        for (k = a; k <= b; k++) {
            kv_lsm_emit(l, lo->pg[k].id, KV_LSM_IO_COMPACT_READ, level);
        }
    }
    if (lo_flash) {
        for (k = 0; k < midp; k++) {
            kv_lsm_emit(l, pg[a + k].id, KV_LSM_IO_COMPACT_PROGRAM, level);
        }
    }
    if (up_flash) {
        for (k = 0; k < up->npg; k++) {
            kv_lsm_free_page(l, up->pg[k].id);
        }
    }
    if (lo->nr) {
        if (lo_flash) {
            for (k = a; k <= b; k++) {
                kv_lsm_free_page(l, lo->pg[k].id);
            }
        }
        memcpy(pg, lo->pg, (size_t)a * sizeof(KvLsmPage));
        for (k = b + 1; k < lo->npg; k++) {
            pg[a + midp + (k - b - 1)].first = lo->pg[k].first - rb + ra + m;
            pg[a + midp + (k - b - 1)].id = lo->pg[k].id;
        }
    }

    kv_lsm_run_free(lo);
    lo->rec = rec;
    lo->nr = new_nr;
    lo->cap = new_nr;
    lo->pg = pg;
    lo->npg = new_npg;
    lo->pgcap = new_npg;
    if (up_level) {
        kv_lsm_run_free(up);
    } else {
        up->nr = 0;
    }
    l->dropped += dropped;
    for (k = 0; k < ngone; k++) {
        if (l->ops.drop) {
            l->ops.drop(l->opaque, gone[k]);
        }
    }
    free(gone);
    return 0;

fail:
    free(rec);
    free(pg);
    free(mid);
    free(gone);
    return -1;
}

/*
 * Merge the memtable into level 1, then each level that is over its
 * capacity into the one below. Only the first merge must succeed: every
 * flush checks every level, so a level that a short allocation left over
 * its capacity merges at a later one.
 */
static int kv_lsm_flush(KvLsm *l)
{
    if (kv_lsm_merge(l, &l->mem, 0, 1)) {
        return -1;
    }
    l->flushes++;
    for (int i = 1; i < KV_LSM_MAX_LEVELS; i++) {
        if (l->lvl[i - 1].nr > kv_lsm_level_cap(l, i) &&
            !kv_lsm_merge(l, &l->lvl[i - 1], i, i + 1)) {
            l->compactions++;
        }
    }
    return 0;
}

/* a record and the run it came from, 0 the memtable: lower is newer */
typedef struct KvLsmAged {
    KvLsmRec rec;
    int run;
} KvLsmAged;

static int kv_lsm_aged_cmp(const void *pa, const void *pb)
{
    const KvLsmAged *a = pa;
    const KvLsmAged *b = pb;
    int c = kv_lsm_rcmp(&a->rec, &b->rec);

    return c ? c : a->run - b->run;
}

/*
 * One merge of every run into the deepest level, in one pass: the output
 * holds only the newest live record of each key, so it needs no more
 * pages than the live keys take, and the inputs free after it.
 */
int kv_lsm_compact_all(KvLsm *l)
{
    int depth = kv_lsm_depth(l);
    int to = depth ? depth : 1;
    bool to_flash = !kv_lsm_level_pinned(l, to);
    uint64_t total = kv_lsm_records(l);
    KvLsmAged *all;
    KvLsmRec *rec;
    KvLsmPage *pg;
    uint32_t *gone;
    uint32_t n = 0, m = 0, ngone = 0, npg, k;

    if (!total) {
        return 0;
    }
    if (total > UINT32_MAX) {
        return -1;
    }
    all = malloc((size_t)total * sizeof(*all));
    rec = malloc((size_t)total * sizeof(*rec));
    gone = malloc((size_t)total * sizeof(*gone));
    pg = malloc(((size_t)total / l->per_page + 1) * sizeof(*pg));
    if (!all || !rec || !gone || !pg) {
        goto fail;
    }
    for (int i = 0; i <= KV_LSM_MAX_LEVELS; i++) {
        const KvLsmRun *r = i ? &l->lvl[i - 1] : &l->mem;

        for (uint32_t j = 0; j < r->nr; j++) {
            all[n].rec = r->rec[j];
            all[n].run = i;
            n++;
        }
    }
    qsort(all, n, sizeof(*all), kv_lsm_aged_cmp);
    for (uint32_t i = 0; i < n; i++) {
        if (i && !kv_lsm_rcmp(&all[i].rec, &all[i - 1].rec)) {
            if (!all[i].rec.dead) {
                gone[ngone++] = all[i].rec.slot;
            }
            continue;
        }
        if (!all[i].rec.dead) {
            rec[m++] = all[i].rec;
        }
    }
    npg = (uint32_t)(((uint64_t)m + l->per_page - 1) / l->per_page);
    if (to_flash && npg && l->ops.room && !l->ops.room(l->opaque, npg)) {
        goto fail;
    }
    for (k = 0; k < npg; k++) {
        pg[k].first = k * l->per_page;
        pg[k].id = KV_LSM_NO_PAGE;
        if (to_flash && l->ops.alloc &&
            !l->ops.alloc(l->opaque, to, &pg[k].id)) {
            while (k--) {
                kv_lsm_free_page(l, pg[k].id);
            }
            goto fail;
        }
    }

    /* read every unpinned input page, program the output, free the inputs */
    for (int i = 1; i <= KV_LSM_MAX_LEVELS; i++) {
        KvLsmRun *r = &l->lvl[i - 1];

        if (kv_lsm_level_pinned(l, i)) {
            continue;
        }
        for (uint32_t p = 0; p < r->npg; p++) {
            kv_lsm_emit(l, r->pg[p].id, KV_LSM_IO_COMPACT_READ, i);
        }
    }
    for (k = 0; to_flash && k < npg; k++) {
        kv_lsm_emit(l, pg[k].id, KV_LSM_IO_COMPACT_PROGRAM, to);
    }
    for (int i = 1; i <= KV_LSM_MAX_LEVELS; i++) {
        KvLsmRun *r = &l->lvl[i - 1];

        if (!kv_lsm_level_pinned(l, i)) {
            for (uint32_t p = 0; p < r->npg; p++) {
                kv_lsm_free_page(l, r->pg[p].id);
            }
        }
        kv_lsm_run_free(r);
    }
    l->mem.nr = 0;
    l->lvl[to - 1].rec = rec;
    l->lvl[to - 1].nr = m;
    l->lvl[to - 1].cap = m;
    l->lvl[to - 1].pg = pg;
    l->lvl[to - 1].npg = npg;
    l->lvl[to - 1].pgcap = npg;
    l->dropped += n - m;
    l->compactions++;
    for (k = 0; k < ngone; k++) {
        if (l->ops.drop) {
            l->ops.drop(l->opaque, gone[k]);
        }
    }
    free(gone);
    free(all);
    return 0;

fail:
    free(all);
    free(rec);
    free(gone);
    free(pg);
    return -1;
}

static bool kv_lsm_eq(const KvLsmRec *r, const uint8_t *key, uint8_t kl)
{
    return r->kl == kl && !memcmp(r->key, key, kl);
}

/*
 * The newest record of @key, or NULL. *@level is 0 for the memtable, and
 * *@page the page in a level.
 */
static const KvLsmRec *kv_lsm_find(KvLsm *l, const uint8_t *key, uint8_t kl,
                                   bool charge, int *level, uint32_t *page)
{
    uint32_t pos = kv_lsm_lower(l->mem.rec, 0, l->mem.nr, key, kl);

    if (pos < l->mem.nr && kv_lsm_eq(&l->mem.rec[pos], key, kl)) {
        *level = 0;
        return &l->mem.rec[pos];
    }
    for (int i = 1; i <= KV_LSM_MAX_LEVELS; i++) {
        KvLsmRun *r = &l->lvl[i - 1];
        uint32_t p, end;

        if (!kv_lsm_in_range(r, key, kl)) {
            continue;
        }
        p = kv_lsm_page_of(r, key, kl);
        if (charge && !kv_lsm_level_pinned(l, i)) {
            kv_lsm_emit(l, r->pg[p].id, KV_LSM_IO_PROBE, i);
        }
        end = kv_lsm_page_end(r, p);
        pos = kv_lsm_lower(r->rec, r->pg[p].first, end, key, kl);
        if (pos < end && kv_lsm_eq(&r->rec[pos], key, kl)) {
            *level = i;
            *page = p;
            return &r->rec[pos];
        }
    }
    return NULL;
}

bool kv_lsm_get(KvLsm *l, const uint8_t *key, uint8_t kl, uint32_t *slot,
                bool charge)
{
    int level;
    uint32_t page;
    const KvLsmRec *r = kv_lsm_find(l, key, kl, charge, &level, &page);

    if (!r || r->dead) {
        return false;
    }
    if (slot) {
        *slot = r->slot;
    }
    return true;
}

static int kv_lsm_put_mem(KvLsm *l, const uint8_t *key, uint8_t kl,
                          uint32_t slot, bool over)
{
    KvLsmRun *m = &l->mem;
    uint32_t pos;

    if (!kl || kl > KV_LSM_KEY_MAX) {
        return -1;
    }
    pos = kv_lsm_lower(m->rec, 0, m->nr, key, kl);
    if (pos == m->nr || !kv_lsm_eq(&m->rec[pos], key, kl)) {
        if (m->nr >= l->mem_cap && kv_lsm_flush(l) && !over) {
            return -1;
        }
        /* only a tombstone that no flush could make room for grows it */
        if (m->nr == m->cap) {
            KvLsmRec *r = realloc(m->rec, (size_t)m->cap * 2 *
                                  sizeof(KvLsmRec));

            if (!r) {
                return -1;
            }
            m->rec = r;
            m->cap *= 2;
        }
        pos = kv_lsm_lower(m->rec, 0, m->nr, key, kl);
        memmove(&m->rec[pos + 1], &m->rec[pos],
                (size_t)(m->nr - pos) * sizeof(KvLsmRec));
        m->nr++;
        memset(&m->rec[pos], 0, sizeof(KvLsmRec));
        memcpy(m->rec[pos].key, key, kl);
        m->rec[pos].kl = kl;
        m->rec[pos].dead = 1;
    }
    /* the record it replaces leaves the tree */
    if (!m->rec[pos].dead && m->rec[pos].slot != slot && l->ops.drop) {
        l->ops.drop(l->opaque, m->rec[pos].slot);
    }
    m->rec[pos].dead = slot == KV_LSM_NO_SLOT;
    m->rec[pos].slot = slot;
    return 0;
}

int kv_lsm_put(KvLsm *l, const uint8_t *key, uint8_t kl, uint32_t slot)
{
    return kv_lsm_put_mem(l, key, kl, slot, false);
}

int kv_lsm_put_tombstone(KvLsm *l, const uint8_t *key, uint8_t kl)
{
    return kv_lsm_put_mem(l, key, kl, KV_LSM_NO_SLOT, true);
}

/* a position in one run during a scan */
typedef struct KvLsmCursor {
    const KvLsmRun *run;
    int level;                  /* 0 for the memtable */
    bool flash;                 /* an unpinned level: its pages cost a read */
    uint32_t pos;
    uint32_t end;
    uint32_t start;             /* first position of the first pass */
    uint32_t page;              /* the page of pos, UINT32_MAX before one */
    uint32_t skip;              /* a page the first pass read already */
} KvLsmCursor;

static void kv_lsm_enter(KvLsm *l, KvLsmCursor *c, uint32_t p)
{
    c->page = p;
    if (c->flash && p != c->skip) {
        kv_lsm_emit(l, c->run->pg[p].id, KV_LSM_IO_SCAN, c->level);
    }
}

/* charge the page a cursor moved into, once */
static void kv_lsm_settle(KvLsm *l, KvLsmCursor *c)
{
    uint32_t p;

    if (!c->level || c->pos >= c->end) {
        return;
    }
    if (c->page == UINT32_MAX) {
        p = kv_lsm_page_at(c->run, c->pos);
    } else {
        p = c->page;
        while (c->pos >= kv_lsm_page_end(c->run, p)) {
            p++;
        }
    }
    if (p != c->page) {
        kv_lsm_enter(l, c, p);
    }
}

/*
 * Place a cursor at the first record at or after @start. The level list
 * names the page that can hold it; when every record there is smaller, the
 * record is the first of the next page, so the seek reads both.
 */
static void kv_lsm_seek(KvLsm *l, KvLsmCursor *c, const uint8_t *start,
                        uint8_t start_len)
{
    const KvLsmRun *r = c->run;
    uint32_t p;

    c->page = UINT32_MAX;
    if (!start_len) {
        c->start = 0;
        c->pos = 0;
        kv_lsm_settle(l, c);
        return;
    }
    c->start = kv_lsm_lower(r->rec, 0, r->nr, start, start_len);
    c->pos = c->start;
    if (!c->level) {
        return;
    }
    p = kv_lsm_page_of(r, start, start_len);
    kv_lsm_enter(l, c, p);
    kv_lsm_settle(l, c);
}

/*
 * Return false when @fn stopped the scan. A key goes to @fn before the
 * cursors move past it, so a key that does not fit reads no page beyond it.
 */
static bool kv_lsm_pass(KvLsm *l, KvLsmCursor *c, int n, KvLsmScanFn fn,
                        void *opaque)
{
    for (;;) {
        const KvLsmRec *best = NULL;

        /* runs go newest first, so on equal keys the first one wins */
        for (int k = 0; k < n; k++) {
            const KvLsmRec *x;

            if (c[k].pos >= c[k].end) {
                continue;
            }
            x = &c[k].run->rec[c[k].pos];
            if (!best || kv_lsm_rcmp(x, best) < 0) {
                best = x;
            }
        }
        if (!best) {
            return true;
        }
        if (!best->dead && !fn(opaque, best->key, best->kl, best->slot)) {
            return false;
        }
        {
            KvLsmRec r = *best;

            for (int k = 0; k < n; k++) {
                if (c[k].pos < c[k].end &&
                    !kv_lsm_rcmp(&c[k].run->rec[c[k].pos], &r)) {
                    c[k].pos++;
                    kv_lsm_settle(l, &c[k]);
                }
            }
        }
    }
}

int kv_lsm_scan(KvLsm *l, const uint8_t *start, uint8_t start_len,
                KvLsmScanFn fn, void *opaque)
{
    KvLsmCursor c[KV_LSM_MAX_LEVELS + 1];
    int n = 0;

    for (int i = 0; i <= KV_LSM_MAX_LEVELS; i++) {
        const KvLsmRun *r = i ? &l->lvl[i - 1] : &l->mem;

        if (!r->nr) {
            continue;
        }
        c[n].run = r;
        c[n].level = i;
        c[n].flash = i && !kv_lsm_level_pinned(l, i);
        c[n].end = r->nr;
        c[n].skip = UINT32_MAX;
        kv_lsm_seek(l, &c[n], start, start_len);
        n++;
    }
    if (!kv_lsm_pass(l, c, n, fn, opaque) || !start_len) {
        return 0;
    }

    /*
     * The wrap: from the smallest key up to the start key. The last page it
     * enters can be one the seek read; that page is still in the buffer.
     */
    for (int k = 0; k < n; k++) {
        c[k].skip = c[k].level ? kv_lsm_page_of(c[k].run, start, start_len) :
                    UINT32_MAX;
        c[k].end = c[k].start;
        c[k].pos = 0;
        c[k].page = UINT32_MAX;
        kv_lsm_settle(l, &c[k]);
    }
    kv_lsm_pass(l, c, n, fn, opaque);
    return 0;
}

int kv_lsm_gc_begin(KvLsm *l)
{
    for (int i = 1; i <= KV_LSM_MAX_LEVELS; i++) {
        KvLsmRun *r = &l->lvl[i - 1];

        if (!r->npg || kv_lsm_level_pinned(l, i)) {
            continue;
        }
        free(r->dirty);
        r->dirty = calloc(r->npg, 1);
        if (!r->dirty) {
            for (int j = 0; j < KV_LSM_MAX_LEVELS; j++) {
                free(l->lvl[j].dirty);
                l->lvl[j].dirty = NULL;
            }
            return -1;
        }
    }
    return 0;
}

/* mark the page of each unpinned level the lookup of @key reads */
static void kv_lsm_gc_mark(KvLsm *l, const uint8_t *key, uint8_t kl,
                           int upto)
{
    for (int i = 1; i <= upto; i++) {
        KvLsmRun *r = &l->lvl[i - 1];

        if (r->dirty && kv_lsm_in_range(r, key, kl)) {
            r->dirty[kv_lsm_page_of(r, key, kl)] = 1;
        }
    }
}

bool kv_lsm_gc_check(KvLsm *l, const uint8_t *key, uint8_t kl,
                     uint32_t *slot)
{
    int level = 0;
    uint32_t page = 0;
    const KvLsmRec *r = kv_lsm_find(l, key, kl, false, &level, &page);

    *slot = r && !r->dead ? r->slot : KV_LSM_NO_SLOT;
    kv_lsm_gc_mark(l, key, kl, r ? level : KV_LSM_MAX_LEVELS);
    return r && level && !kv_lsm_level_pinned(l, level);
}

void kv_lsm_gc_check_done(KvLsm *l)
{
    for (int i = 1; i <= KV_LSM_MAX_LEVELS; i++) {
        KvLsmRun *r = &l->lvl[i - 1];

        if (!r->dirty) {
            continue;
        }
        for (uint32_t p = 0; p < r->npg; p++) {
            if (r->dirty[p]) {
                kv_lsm_emit(l, r->pg[p].id, KV_LSM_IO_GC_READ, i);
            }
        }
        free(r->dirty);
        r->dirty = NULL;
    }
}

int kv_lsm_reinsert(KvLsm *l, const uint8_t *key, uint8_t kl, uint32_t slot)
{
    if (kv_lsm_put(l, key, kl, slot)) {
        return -1;
    }
    l->reinserted++;
    return 0;
}

bool kv_lsm_relocate(KvLsm *l, uint64_t old_id, uint64_t new_id)
{
    for (int i = 1; i <= KV_LSM_MAX_LEVELS; i++) {
        KvLsmRun *r = &l->lvl[i - 1];

        for (uint32_t p = 0; p < r->npg; p++) {
            if (r->pg[p].id == old_id) {
                r->pg[p].id = new_id;
                return true;
            }
        }
    }
    return false;
}
