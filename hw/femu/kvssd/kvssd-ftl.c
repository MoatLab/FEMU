#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/error-report.h"

#include "kvssd.h"
#include "kv-pack.h"
#include "../nvme.h"
#include "../bbssd/ftl.h"
#include "../bbssd/ftl-internal.h"

/*
 * KV-SSD firmware: the device-side key->location index, the NAND-backed value
 * space, and value-page timing routed through FEMU's NAND media model.
 *
 * Value timing is faithful: each value page is placed on a real (channel, LUN,
 * plane) via the bbssd page allocator (get_new_page) and charged with
 * ssd_advance_status(NAND_READ/WRITE) -- so KV throughput reflects flash channel
 * parallelism, not a flat constant. The byte arena (kvssd->values) holds the data
 * the host DMAs to/from; the parallel NAND ssd holds the timing/placement state.
 */

#define KV_DEFAULT_KEY_MAX    16
#define KV_DEFAULT_VALUE_MAX  (2u << 20)    /* 2 MiB max value (KVVML) */
#define KV_INDEX_LOAD_NUM     2             /* size index ~2x expected keys */

static uint32_t kv_fnv1a(const uint8_t *key, uint8_t kl)
{
    uint32_t h = 2166136261u;
    for (uint8_t i = 0; i < kl; i++) {
        h ^= key[i];
        h *= 16777619u;
    }
    return h;
}

static bool kv_entry_empty(const FemuKvssdMappingEntry *e)
{
    return e->key_len == 0;
}

static void kv_entry_clear(FemuKvssdMappingEntry *e)
{
    memset(e, 0, sizeof(*e));
}

static void kv_entry_drop_ppas(FemuKvssdMappingEntry *e)
{
    g_free(e->ppas);
    e->ppas = NULL;
    e->nr_ppas = 0;
}

static bool kv_key_eq(const FemuKvssdMappingEntry *e, const uint8_t *key,
                      uint8_t kl)
{
    return e->key_len == kl && memcmp(e->key, key, kl) == 0;
}

/* --- page owners --- */

/*
 * ssd->rmap names the owner of each programmed page: a table slot for a
 * value page, KV_OWNER_META for a meta page of the LSM tree. A page is
 * released only by its owner, so an owner that holds an address after the
 * page was erased and programmed again cannot release the new data.
 */
#define KV_OWNER_NONE   INVALID_LPN
#define KV_OWNER_META   (INVALID_LPN - 1)
/* a page of packed values; its header names the owner of each value */
#define KV_OWNER_PACK   (INVALID_LPN - 2)
/* the page of a packed value that is still in the open page, in DRAM */
#define KV_PPA_OPEN     (UNMAPPED_PPA - 1)

/* live bytes of the line that holds @ppa */
static void kv_line_live(FemuKvssdState *s, struct ppa *ppa, int64_t bytes)
{
    s->line_live[ppa->g.blk] += bytes;
}

static bool kv_page_owned(FemuKvssdState *s, struct ppa *ppa, uint64_t owner)
{
    return ppa->ppa != UNMAPPED_PPA && ppa->ppa != KV_PPA_OPEN &&
           valid_ppa(s->ssd, ppa) &&
           get_pg(s->ssd, ppa)->status == PG_VALID &&
           get_rmap_ent(s->ssd, ppa) == owner;
}

/* a whole page or a meta page is programmed for @owner */
static void kv_page_valid(FemuKvssdState *s, struct ppa *ppa, uint64_t owner)
{
    mark_page_valid(s->ssd, ppa);
    set_rmap_ent(s->ssd, owner, ppa);
    kv_line_live(s, ppa, s->pgsz);
}

static void kv_release_page(FemuKvssdState *s, struct ppa *ppa, uint64_t owner)
{
    if (kv_page_owned(s, ppa, owner)) {
        set_rmap_ent(s->ssd, KV_OWNER_NONE, ppa);
        mark_page_invalid(s->ssd, ppa);
        kv_line_live(s, ppa, -(int64_t)s->pgsz);
    }
}

/* --- packed pages --- */

/*
 * kv_pack: a value whose record fits a page shares the page with other
 * values (kv-pack.c holds the page header). A value never crosses a page,
 * so a Retrieve reads one page. A programmed page stays valid until its
 * last record dies; ssd->rmap names it KV_OWNER_PACK, and its header names
 * the owner of each record.
 */
/* a value packs when its record fits a page; a larger one takes pages */
static bool kv_packs(FemuKvssdState *s, uint64_t len)
{
    return s->pack && len && len + KV_PACK_HDR <= (uint64_t)s->pgsz;
}

/* the header of the page @id names, or NULL */
static KvPackPage *kv_pack_page(FemuKvssdState *s, uint64_t id)
{
    if (id == KV_PPA_OPEN) {
        return s->open;
    }
    if (id == UNMAPPED_PPA || !s->packed) {
        return NULL;
    }
    return g_hash_table_lookup(s->packed, &id);
}

/*
 * Item @i of @pg dies. A programmed page with no live value left is
 * invalid now; return true when @pg is freed with it.
 */
static bool kv_pack_kill(FemuKvssdState *s, KvPackPage *pg, int i)
{
    struct ppa ppa = { .ppa = pg->id };
    uint32_t bytes = kv_pack_drop(pg, i);

    if (!bytes || pg->id == KV_PACK_NO_PAGE) {
        return false;           /* the open page: dropped if it stays empty */
    }
    kv_line_live(s, &ppa, -(int64_t)bytes);
    if (pg->live) {
        return false;
    }
    set_rmap_ent(s->ssd, KV_OWNER_NONE, &ppa);
    mark_page_invalid(s->ssd, &ppa);
    g_hash_table_remove(s->packed, &pg->id);
    kv_pack_free(pg);
    return true;
}

/* the item of packed value @e, when @owner holds it, or -1 */
static int kv_pack_owned(FemuKvssdState *s, const FemuKvssdMappingEntry *e,
                         uint64_t owner, KvPackPage **out)
{
    KvPackPage *pg;
    int i;

    if (!e->packed || e->nr_ppas != 1) {
        return -1;
    }
    pg = kv_pack_page(s, e->ppas[0].ppa);
    i = pg ? kv_pack_find(pg, e->pack_off) : -1;
    if (i < 0 || !pg->item[i].live || pg->item[i].owner != owner) {
        return -1;
    }
    *out = pg;
    return i;
}

static void kv_release_ppas(FemuKvssdState *s, struct ppa *ppas, uint32_t n,
                            uint64_t owner)
{
    for (uint32_t i = 0; i < n; i++) {
        kv_release_page(s, &ppas[i], owner);
    }
}

/* the flash of value @e changes owner, as a table entry moves */
static void kv_move_owner(FemuKvssdState *s, const FemuKvssdMappingEntry *e,
                          uint64_t from, uint64_t to)
{
    KvPackPage *pg;
    int i;

    if (e->packed) {
        i = kv_pack_owned(s, e, from, &pg);
        if (i >= 0) {
            pg->item[i].owner = to;
        }
        return;
    }
    for (uint32_t k = 0; k < e->nr_ppas; k++) {
        if (kv_page_owned(s, &e->ppas[k], from)) {
            set_rmap_ent(s->ssd, to, &e->ppas[k]);
        }
    }
}

/* the flash of value @e is garbage, when @owner holds it */
static void kv_release_value(FemuKvssdState *s, const FemuKvssdMappingEntry *e,
                             uint64_t owner)
{
    KvPackPage *pg;
    int i;

    if (e->packed) {
        i = kv_pack_owned(s, e, owner, &pg);
        if (i >= 0) {
            kv_pack_kill(s, pg, i);
        }
        return;
    }
    kv_release_ppas(s, e->ppas, e->nr_ppas, owner);
}

static void kv_discard_value_ppas(FemuKvssdState *s, FemuKvssdMappingEntry *e,
                                  uint32_t slot)
{
    kv_release_value(s, e, slot);
    kv_entry_drop_ppas(e);
    e->packed = false;
}

/*
 * Default index: open-addressing with LINEAR PROBING. A single consistent scheme
 * (no mixed home-slot/chain links): find/insert both probe forward from the home
 * slot to the first empty slot; delete uses backshift to keep probe sequences
 * intact. key_len>0 is the sole occupancy predicate, so a zero-length value at
 * offset 0 is fully representable.
 */
static int kv_hash_find(FemuKvssdState *s, const uint8_t *key, uint8_t kl,
                        int *prev_slot)
{
    uint32_t home = kv_fnv1a(key, kl) % s->hash_slots;

    if (prev_slot) {
        *prev_slot = -1;               /* unused under linear probing */
    }
    for (uint32_t i = 0; i < s->hash_slots; i++) {
        uint32_t slot = (home + i) % s->hash_slots;
        FemuKvssdMappingEntry *e = &s->table[slot];
        if (e->key_len == 0) {
            return -1;                 /* empty slot ends the probe sequence */
        }
        if (kv_key_eq(e, key, kl)) {
            return (int)slot;
        }
    }
    return -1;
}

/* the value fields of @v into @e, and its flash to @slot */
static void kv_entry_set_value(FemuKvssdState *s, FemuKvssdMappingEntry *e,
                               const FemuKvssdMappingEntry *v, uint32_t slot)
{
    e->value_off = v->value_off;
    e->length = v->length;
    e->ppas = v->ppas;
    e->nr_ppas = v->nr_ppas;
    e->packed = v->packed;
    e->pack_off = v->pack_off;
    kv_move_owner(s, e, KV_OWNER_NONE, slot);
}

static uint16_t kv_hash_upsert(FemuKvssdState *s, const uint8_t *key, uint8_t kl,
                               const FemuKvssdMappingEntry *v)
{
    uint32_t home = kv_fnv1a(key, kl) % s->hash_slots;

    for (uint32_t i = 0; i < s->hash_slots; i++) {
        uint32_t slot = (home + i) % s->hash_slots;
        FemuKvssdMappingEntry *e = &s->table[slot];
        if (e->key_len != 0 && kv_key_eq(e, key, kl)) {
            kv_entry_set_value(s, e, v, slot);  /* update in place */
            return NVME_SUCCESS;
        }
        if (e->key_len == 0) {         /* first free slot in the probe run */
            if (s->kv_max_keys && s->nr_entries >= s->kv_max_keys) {
                return NVME_CAP_EXCEEDED | NVME_DNR;
            }
            memcpy(e->key, key, kl);
            e->key_len = kl;
            kv_entry_set_value(s, e, v, slot);
            s->nr_entries++;
            return NVME_SUCCESS;
        }
    }
    return NVME_CAP_EXCEEDED | NVME_DNR;  /* table full */
}

static int kv_hash_remove(FemuKvssdState *s, const uint8_t *key, uint8_t kl)
{
    int slot = kv_hash_find(s, key, kl, NULL);
    uint32_t hole, next;

    if (slot < 0) {
        return 0;
    }
    /* backshift deletion: pull up following entries whose home position is at or
     * before the hole, so no probe sequence is broken by the cleared slot. */
    hole = (uint32_t)slot;
    kv_entry_clear(&s->table[hole]);
    next = (hole + 1) % s->hash_slots;
    while (s->table[next].key_len != 0) {
        uint32_t h = kv_fnv1a(s->table[next].key, s->table[next].key_len) %
                     s->hash_slots;
        /* if `next`'s home is not within (hole, next], it must shift into hole */
        bool movable = (hole < next) ? (h <= hole || h > next)
                                     : (h <= hole && h > next);
        if (movable) {
            s->table[hole] = s->table[next];
            kv_entry_clear(&s->table[next]);
            /* value GC finds a page's entry by its slot */
            kv_move_owner(s, &s->table[hole], next, hole);
            hole = next;
        }
        next = (next + 1) % s->hash_slots;
    }
    s->nr_entries--;
    return 1;
}

static const FemuKvIndexOps kv_index_hash = {
    .name   = "hash",
    .find   = kv_hash_find,
    .upsert = kv_hash_upsert,
    .remove = kv_hash_remove,
    .probe  = NULL,                    /* DRAM-resident hash: 0 flash reads */
};

/* --- write pointers --- */

static struct ppa kv_wp_ppa(struct write_pointer *wpp)
{
    struct ppa ppa = { .ppa = 0 };

    ppa.g.ch = wpp->ch;
    ppa.g.lun = wpp->lun;
    ppa.g.pl = wpp->pl;
    ppa.g.pg = wpp->pg;
    ppa.g.blk = wpp->blk;
    return ppa;
}

/* pages left on the open line of @wpp */
static uint64_t kv_wp_remaining(FemuKvssdState *s, struct write_pointer *wpp)
{
    struct ssdparams *spp = &s->ssd->sp;
    uint64_t stride = (uint64_t)spp->nchs * spp->luns_per_ch;
    uint64_t idx;

    if (!wpp || !wpp->curline) {
        return 0;
    }
    /*
     * The pointer walks channel, then lun, then plane, then page, so the plane
     * is part of the position. Leaving it out reported up to half a line more
     * room than the media has once a lun holds more than one plane.
     */
    if (spp->plane_first) {
        idx = (uint64_t)wpp->pg * stride * spp->pls_per_lun +
              ((uint64_t)wpp->lun * spp->nchs + wpp->ch) * spp->pls_per_lun +
              wpp->pl;
    } else {
        idx = (uint64_t)wpp->pg * stride * spp->pls_per_lun +
              (uint64_t)wpp->pl * stride +
              (uint64_t)wpp->lun * spp->nchs + wpp->ch;
    }
    return idx < (uint64_t)spp->pgs_per_line ?
           (uint64_t)spp->pgs_per_line - idx : 0;
}

/*
 * Erase every line that holds no valid page, from @stime, and return the
 * time it takes. The erase runs whatever enable_gc_delay says.
 */
static uint64_t kv_reclaim_empty_lines(FemuKvssdState *s, int64_t stime)
{
    struct ssd *ssd = s->ssd;
    struct ssdparams *spp = &ssd->sp;
    struct line_mgmt *lm = &ssd->lm;
    uint64_t lat = 0;

    for (;;) {
        struct line *line = pqueue_peek(lm->victim_line_pq);
        struct ppa ppa = { .ppa = 0 };

        if (!line || line->vpc != 0) {
            break;
        }
        line = pqueue_pop(lm->victim_line_pq);
        ppa.g.blk = line->id;

        for (int ch = 0; ch < spp->nchs; ch++) {
            for (int lun = 0; lun < spp->luns_per_ch; lun++) {
                lat = MAX(lat, ssd_erase_lun_block(ssd, ch, lun, ppa.g.blk,
                                                   true, stime));
            }
        }
        mark_line_free(ssd, &ppa);
    }
    return lat;
}

/* give @wpp a free line when it has none; false when no line is free */
static bool kv_wp_line(FemuKvssdState *s, struct write_pointer *wpp)
{
    struct ssd *ssd = s->ssd;

    if (wpp->curline) {
        return true;
    }
    if (QTAILQ_EMPTY(&ssd->lm.free_line_list)) {
        return false;
    }
    ssd_wp_reset(wpp, get_next_free_line(ssd));
    return true;
}

/* move @wpp past the page just programmed; a full line goes to its list */
static void kv_wp_step(FemuKvssdState *s, struct write_pointer *wpp)
{
    struct ssd *ssd = s->ssd;
    struct ssdparams *spp = &ssd->sp;
    struct line_mgmt *lm = &ssd->lm;

    if (!ssd_wp_step(spp, wpp)) {
        return;
    }
    wpp->curline->close_time = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    if (wpp->curline->vpc == spp->pgs_per_line) {
        QTAILQ_INSERT_TAIL(&lm->full_line_list, wpp->curline, entry);
        lm->full_line_cnt++;
    } else {
        pqueue_insert(lm->victim_line_pq, wpp->curline);
    }
    wpp->curline = NULL;
}

/* pages a value can still take: free lines and the open value line */
static uint64_t kv_room(FemuKvssdState *s)
{
    uint64_t room = (uint64_t)s->ssd->lm.free_line_cnt *
                    s->ssd->sp.pgs_per_line +
                    kv_wp_remaining(s, &s->ssd->wp);
    /* the open page owes a page: a Flush must find it */
    uint64_t owed = s->open && s->open->live;

    return room > owed ? room - owed : 0;
}

/*
 * Pages a Store must leave free. GC needs a line to move a victim's pages
 * into. The LSM tree also needs a line for its open meta page, and room
 * for its largest merge: one that rewrites every record, with a part page
 * for each level. A merge frees its input pages only after it has
 * programmed its output. A Store that would take that room fails instead,
 * so any merge, also one that a Delete or GC starts, finds its pages.
 */
static uint64_t kv_reserve(FemuKvssdState *s)
{
    struct ssdparams *spp = &s->ssd->sp;
    uint64_t recs;

    if (!s->lsm) {
        return spp->pgs_per_line;
    }
    recs = kv_lsm_records(s->lsm) + 1;
    return 2ULL * spp->pgs_per_line + KV_LSM_MAX_LEVELS +
           DIV_ROUND_UP(recs, s->lsm->per_page);
}

/* --- the LSM index --- */

/*
 * kv_index=lsm. The LSM tree (kv-lsm.c) maps a key to a slot of s->table.
 * Each Store takes a new slot, a version of the key, so each slot has one
 * record in the tree, and a version keeps its pages until the tree drops
 * its record. Meta pages are real pages on meta_wp, in lines that hold no
 * value, as PinK keeps meta segments apart from data segments.
 */

/* a merge read or program, issued once the command's own work is charged */
struct FemuKvLsmIo {
    uint64_t id;
    bool program;
};

static uint64_t kv_tree_nand(FemuKvssdState *s, uint64_t id, int cmd,
                             int type, int64_t stime)
{
    struct nand_cmd c = { .type = type, .cmd = cmd, .stime = stime };
    struct ppa ppa = { .ppa = id };

    return ssd_advance_status(s->ssd, &ppa, &c);
}

/*
 * The tree reports each page it reads or programs. A lookup reads one
 * level after another, and a List reads the pages of one level one after
 * another, so each read starts when the one before it ends. A GC check
 * reads level by level: a key's lookup reads a level only once it missed
 * the one above. Merge I/O is queued: issued now, it would make this
 * command's own later reads wait behind it.
 */
static void kv_tree_issue(FemuKvssdState *s);
static void kv_tree_issue_one(FemuKvssdState *s, uint64_t id, bool program);

static void kv_tree_io(void *opaque, uint64_t id, KvLsmIo io, int level)
{
    FemuKvssdState *s = opaque;
    struct FemuKvLsmIo *p;

    switch (io) {
    case KV_LSM_IO_PROBE:
        s->lsm_probe += kv_tree_nand(s, id, NAND_READ, USER_IO,
                                     s->lsm_stime + s->lsm_probe);
        return;
    case KV_LSM_IO_SCAN:
        if (level >= 0 && level <= KV_LSM_MAX_LEVELS) {
            s->lsm_level[level] += kv_tree_nand(s, id, NAND_READ, USER_IO,
                                                s->lsm_stime +
                                                s->lsm_level[level]);
        }
        return;
    case KV_LSM_IO_GC_READ:
        if (level != s->lsm_gc_level) {
            s->lsm_gc_level = level;
            s->lsm_gc_base = s->lsm_gc;
        }
        s->lsm_gc = MAX(s->lsm_gc, s->lsm_gc_base +
                        kv_tree_nand(s, id, NAND_READ, GC_IO,
                                     s->lsm_stime + s->lsm_gc_base));
        return;
    default:
        break;
    }
    if (io == KV_LSM_IO_COMPACT_PROGRAM) {
        /* a program, but not one the host asked for */
        s->meta_wr_pages++;
        s->ssd->nand_write_pages++;
    }
    if (s->lsm_npend == s->lsm_pend_cap) {
        uint32_t cap = s->lsm_pend_cap ? 2 * s->lsm_pend_cap : 256;

        p = g_try_renew(struct FemuKvLsmIo, s->lsm_pend, cap);
        if (!p) {
            /*
             * With no room to queue it, issue what is queued now, in
             * order, and start a new queue with this I/O. Only the
             * deferral behind the command's own work is lost.
             */
            kv_tree_issue(s);
        }
        if (p) {
            s->lsm_pend = p;
            s->lsm_pend_cap = cap;
        }
    }
    if (s->lsm_npend == s->lsm_pend_cap) {
        kv_tree_issue_one(s, id, io == KV_LSM_IO_COMPACT_PROGRAM);
        return;
    }
    s->lsm_pend[s->lsm_npend].id = id;
    s->lsm_pend[s->lsm_npend].program = io == KV_LSM_IO_COMPACT_PROGRAM;
    s->lsm_npend++;
}

/* free lines a merge leaves, for the pages value GC moves */
#define KV_META_FLOOR   1

/* meta pages a merge may take: the open meta line and the free lines */
static uint64_t kv_tree_pages(FemuKvssdState *s)
{
    uint64_t lines = s->ssd->lm.free_line_cnt;

    lines = lines > KV_META_FLOOR ? lines - KV_META_FLOOR : 0;
    return lines * s->ssd->sp.pgs_per_line +
           kv_wp_remaining(s, s->meta_wp);
}

static bool kv_tree_room(void *opaque, uint64_t pages)
{
    FemuKvssdState *s = opaque;

    if (kv_tree_pages(s) < pages) {
        s->lsm_nospace = true;
        return false;
    }
    return true;
}

/*
 * A merge takes a meta page. It takes a free line but never erases one or
 * runs GC: either would change pages the merge still reads. The program is
 * counted when the merge issues it.
 */
static bool kv_tree_alloc(void *opaque, int level, uint64_t *id)
{
    FemuKvssdState *s = opaque;
    struct ppa ppa;

    (void)level;
    if (!s->meta_wp->curline &&
        s->ssd->lm.free_line_cnt <= KV_META_FLOOR) {
        s->lsm_nospace = true;
        return false;
    }
    if (!kv_wp_line(s, s->meta_wp)) {
        s->lsm_nospace = true;
        return false;
    }
    ppa = kv_wp_ppa(s->meta_wp);
    kv_page_valid(s, &ppa, KV_OWNER_META);
    kv_wp_step(s, s->meta_wp);
    *id = ppa.ppa;
    return true;
}

static void kv_tree_free_page(void *opaque, uint64_t id)
{
    FemuKvssdState *s = opaque;
    struct ppa ppa = { .ppa = id };

    kv_release_page(s, &ppa, KV_OWNER_META);
}

/*
 * The record that named @slot left the tree, so no lookup can reach the
 * version: its pages are garbage now, and the slot is free.
 */
static void kv_tree_drop(void *opaque, uint32_t slot)
{
    FemuKvssdState *s = opaque;
    FemuKvssdMappingEntry *e = &s->table[slot];

    kv_discard_value_ppas(s, e, slot);
    kv_entry_clear(e);
    s->free_slots[s->nr_free++] = slot;
}

static const KvLsmOps kv_tree_ops = {
    .io        = kv_tree_io,
    .room      = kv_tree_room,
    .alloc     = kv_tree_alloc,
    .free_page = kv_tree_free_page,
    .drop      = kv_tree_drop,
};

/*
 * The merge schedule of one command, in absolute ns. It starts at the
 * command's arrival, or at lsm_ready when that is later: records that
 * value GC put back point to moved values, which exist only once their
 * programs end, also when a later command flushes them.
 */
static void kv_tree_begin(FemuKvssdState *s, int64_t stime)
{
    s->lsm_stime = stime;
    s->lsm_mstart = MAX(stime, s->lsm_ready);
    s->lsm_mend = s->lsm_mstart;
    s->lsm_mkind = -1;
}

/*
 * A merge programs its output only after it has read its input, and the
 * next merge of a cascade reads what the one before wrote: each run of
 * reads or of programs starts when the run before it ends. The time is
 * not the command's; later commands on the same LUNs wait behind it.
 */
static void kv_tree_issue_one(FemuKvssdState *s, uint64_t id, bool program)
{
    uint64_t lat;

    if (s->lsm_mkind >= 0 && program != s->lsm_mkind) {
        s->lsm_mstart = s->lsm_mend;
    }
    if (s->lsm_ready > s->lsm_mstart) {
        s->lsm_mstart = s->lsm_ready;
        s->lsm_mend = MAX(s->lsm_mend, s->lsm_ready);
    }
    lat = kv_tree_nand(s, id, program ? NAND_WRITE : NAND_READ, GC_IO,
                       s->lsm_mstart);
    s->lsm_mend = MAX(s->lsm_mend, s->lsm_mstart + (int64_t)lat);
    s->lsm_mkind = program;
}

static void kv_tree_issue(FemuKvssdState *s)
{
    for (uint32_t i = 0; i < s->lsm_npend; i++) {
        kv_tree_issue_one(s, s->lsm_pend[i].id, s->lsm_pend[i].program);
    }
    s->lsm_npend = 0;
}

/*
 * A free slot. The table grows when none is left, so a held entry
 * pointer is stale after this; callers keep slot numbers.
 */
static bool kv_slot_pop(FemuKvssdState *s, uint32_t *slot)
{
    if (!s->nr_free) {
        uint32_t old = s->hash_slots;
        uint64_t want = (uint64_t)old * 2;
        FemuKvssdMappingEntry *t;
        uint32_t *f;

        /* find() returns a slot as an int */
        if (want > INT32_MAX) {
            want = INT32_MAX;
        }
        if (want <= old) {
            return false;
        }
        t = g_try_renew(FemuKvssdMappingEntry, s->table, want);
        if (!t) {
            return false;
        }
        s->table = t;
        memset(&t[old], 0, (want - old) * sizeof(*t));
        f = g_try_renew(uint32_t, s->free_slots, want);
        if (!f) {
            return false;
        }
        s->free_slots = f;
        s->hash_slots = (uint32_t)want;
        for (uint64_t i = want; i > old; i--) {
            s->free_slots[s->nr_free++] = (uint32_t)(i - 1);
        }
    }
    *slot = s->free_slots[--s->nr_free];
    return true;
}

static int kv_tree_find(FemuKvssdState *s, const uint8_t *key, uint8_t kl,
                        int *prev_slot)
{
    uint32_t slot;

    if (prev_slot) {
        *prev_slot = -1;
    }
    return kv_lsm_get(s->lsm, key, kl, &slot, false) ? (int)slot : -1;
}

/* the status of a put the tree refused */
static uint16_t kv_tree_put_status(FemuKvssdState *s)
{
    return s->lsm_nospace ? NVME_CAP_EXCEEDED | NVME_DNR :
           NVME_INTERNAL_DEV_ERROR | NVME_DNR;
}

/*
 * A Store writes a new version: a new slot with its record in the
 * memtable, as an LSM tree writes out of place. The old version keeps its
 * pages until the tree drops its record; it goes stale now. The new slot
 * goes back on failure, and the caller releases the new pages.
 */
static uint16_t kv_tree_upsert(FemuKvssdState *s, const uint8_t *key,
                               uint8_t kl, const FemuKvssdMappingEntry *v)
{
    FemuKvssdMappingEntry *e;
    uint32_t old = KV_LSM_NO_SLOT;
    uint32_t slot;

    if (!kv_lsm_get(s->lsm, key, kl, &old, false)) {
        old = KV_LSM_NO_SLOT;
        if (s->kv_max_keys && s->nr_entries >= s->kv_max_keys) {
            return NVME_CAP_EXCEEDED | NVME_DNR;
        }
    }
    if (!kv_slot_pop(s, &slot)) {
        return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }
    e = &s->table[slot];
    memcpy(e->key, key, kl);
    e->key_len = kl;
    e->stale = false;
    kv_entry_set_value(s, e, v, slot);

    s->lsm_nospace = false;
    if (kv_lsm_put(s->lsm, key, kl, slot)) {
        kv_move_owner(s, &s->table[slot], slot, KV_OWNER_NONE);
        kv_entry_clear(&s->table[slot]);
        s->free_slots[s->nr_free++] = slot;
        return kv_tree_put_status(s);
    }
    if (old == KV_LSM_NO_SLOT) {
        s->nr_entries++;
    } else if (s->table[old].key_len) {
        /* still in the tree: the put did not replace it in the memtable */
        s->table[old].stale = true;
    }
    return NVME_SUCCESS;
}

/*
 * The tombstone goes in; the old version goes stale and keeps its pages
 * until a merge drops its record, or at once when the tombstone replaces
 * it in the memtable.
 */
static int kv_tree_remove(FemuKvssdState *s, const uint8_t *key, uint8_t kl)
{
    uint32_t slot;

    s->lsm_nospace = false;
    if (!kv_lsm_get(s->lsm, key, kl, &slot, false)) {
        /*
         * A blind Delete cannot know the key is absent, so its tombstone
         * goes in all the same. With EDNEK the lookup found it absent.
         */
        if (!s->ednek && kv_lsm_put_tombstone(s->lsm, key, kl)) {
            return -1;
        }
        return 0;
    }
    /* with no page for a flush, the memtable holds the tombstone over */
    if (kv_lsm_put_tombstone(s->lsm, key, kl)) {
        return -1;
    }
    if (s->table[slot].key_len) {
        s->table[slot].stale = true;
    }
    s->nr_entries--;
    return 1;
}

static uint64_t kv_tree_probe(FemuKvssdState *s, const uint8_t *key,
                              uint8_t kl, int64_t stime)
{
    s->lsm_stime = stime;
    s->lsm_probe = 0;
    kv_lsm_get(s->lsm, key, kl, NULL, true);
    return s->lsm_probe;
}

static const FemuKvIndexOps kv_index_lsm = {
    .name   = "lsm",
    .find   = kv_tree_find,
    .upsert = kv_tree_upsert,
    .remove = kv_tree_remove,
    .probe  = kv_tree_probe,
};

/*
 * Every table entry free again, as after realize. The tree is cleared with
 * no callback, so its meta pages are released here, and the caller has
 * released the value pages.
 */
static void kv_tree_reset(FemuKvssdState *s)
{
    if (!s->lsm) {
        return;
    }
    for (int i = 1; i <= KV_LSM_MAX_LEVELS; i++) {
        KvLsmRun *r = &s->lsm->lvl[i - 1];

        for (uint32_t p = 0; p < r->npg && s->ssd; p++) {
            kv_tree_free_page(s, r->pg[p].id);
        }
    }
    kv_lsm_clear(s->lsm);
    for (uint32_t i = 0; i < s->hash_slots; i++) {
        s->free_slots[i] = s->hash_slots - 1 - i;
    }
    s->nr_free = s->hash_slots;
    s->lsm_npend = 0;
    s->lsm_ready = 0;
}

/* release the lock, issuing the merge I/O the command queued first */
static void kv_unlock(FemuKvssdState *s)
{
    if (s->lsm_npend) {
        kv_tree_issue(s);
    }
    qemu_mutex_unlock(&s->lock);
}

/* --- value-space placement + NAND timing --- */

static uint32_t kv_value_pages(FemuKvssdState *s, uint64_t bytes)
{
    return bytes ? DIV_ROUND_UP(bytes, (uint64_t)s->pgsz) : 0;
}

/*
 * Program the pages of a value from @stime, at or after the request start;
 * the latency in *@lat counts from the request start. The pages have no
 * owner until the index takes the value.
 */
static uint16_t kv_program_ppas(FemuKvssdState *s, NvmeRequest *req,
                                uint64_t bytes, struct ppa **out,
                                uint32_t *out_nr, uint64_t *lat, int64_t stime)
{
    struct ssd *ssd = s->ssd;
    uint32_t pages = kv_value_pages(s, bytes);
    struct ppa *ppas = NULL;
    uint64_t wait = stime > req->stime ? stime - req->stime : 0;
    struct nand_cmd c = {
        .type = USER_IO,
        .cmd = NAND_WRITE,
        .stime = stime,
    };

    *out = NULL;
    *out_nr = 0;
    if (!pages) {
        return NVME_SUCCESS;
    }
    *lat = MAX(*lat, kv_reclaim_empty_lines(s, req->stime));
    if (kv_room(s) < pages) {
        return NVME_CAP_EXCEEDED | NVME_DNR;
    }

    ppas = g_try_new0(struct ppa, pages);
    if (!ppas) {
        return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }

    for (uint32_t i = 0; i < pages; i++) {
        struct ppa ppa;
        uint64_t sub;

        if (!kv_wp_line(s, &ssd->wp)) {
            kv_release_ppas(s, ppas, i, KV_OWNER_NONE);
            g_free(ppas);
            return NVME_CAP_EXCEEDED | NVME_DNR;
        }

        ppa = kv_wp_ppa(&ssd->wp);
        kv_page_valid(s, &ppa, KV_OWNER_NONE);
        sub = wait + ssd_advance_status(ssd, &ppa, &c);
        *lat = sub > *lat ? sub : *lat;
        ppas[i] = ppa;
        /*
         * Counted on the ssd as well as in this mode's own state, because the
         * health log reads the counters every FTL-backed mode keeps there.
         * nand_write_pages counts a page the host asked for, gc_write_pages
         * a page the device relocated, as the black-box mode splits them.
         */
        s->nand_wr_pages++;
        /* with kv_pack the host side counts bytes (kv_count_host) */
        if (!s->pack) {
            ssd->host_write_pages++;
        }
        ssd->nand_write_pages++;
        kv_wp_step(s, &ssd->wp);
    }

    *out = ppas;
    *out_nr = pages;
    return NVME_SUCCESS;
}

/*
 * The open page may stay in controller DRAM unless the host enabled a
 * volatile write cache and then disabled it: then every command's data
 * must be persistent at completion (Base 2.3, 5.2.26.1.4). With vwc=0
 * the controller has no volatile cache, so its buffer counts as
 * non-volatile, as the bbssd write buffer does (ssd_buffer_enabled()).
 */
static bool kv_pack_hold(FemuKvssdState *s)
{
    FemuCtrl *n = s->ssd->n;

    return !(n && n->vwc && !n->features.volatile_wc);
}

/* the host side of the WAF: value bytes in pages, with kv_pack */
static void kv_count_host(FemuKvssdState *s, uint64_t bytes)
{
    uint64_t before = s->host_bytes / s->pgsz;

    if (!s->pack) {
        return;
    }
    s->host_bytes += bytes;
    s->ssd->host_write_pages += s->host_bytes / s->pgsz - before;
}

static void kv_pack_moved(void *opaque, uint64_t owner, uint32_t off)
{
    FemuKvssdState *s = opaque;

    if (owner < s->hash_slots) {
        s->table[owner].pack_off = off;
    }
}

/*
 * Close the gaps that dead values left in the open page, as a write
 * buffer drops the data an overwrite replaced. It is DRAM, so it costs no
 * time; each live value keeps its slot and moves to a new offset.
 */
static void kv_pack_compact_open(FemuKvssdState *s)
{
    kv_pack_compact(s->open, kv_pack_moved, s);
}

/*
 * Program the open page from @stime; *@lat takes the time it takes. The
 * page is padded when it is not full. An open page with no live value
 * goes with no program: its values died in DRAM. @early: durability, not
 * a full page, asked for the program. @v is the value of a Store that the
 * index has not taken yet; it learns its page here.
 */
static uint16_t kv_pack_program(FemuKvssdState *s, int64_t stime,
                                uint64_t *lat, bool early,
                                FemuKvssdMappingEntry *v)
{
    struct ssd *ssd = s->ssd;
    KvPackPage *pg = s->open;
    struct nand_cmd c = { .type = USER_IO, .cmd = NAND_WRITE,
                          .stime = stime };
    struct ppa ppa;
    uint64_t t;

    if (!pg) {
        return NVME_SUCCESS;
    }
    if (!pg->live) {
        kv_pack_free(pg);
        s->open = NULL;
        s->pack_dropped++;
        return NVME_SUCCESS;
    }
    if (!kv_wp_line(s, &ssd->wp)) {
        return NVME_CAP_EXCEEDED | NVME_DNR;
    }
    /* dead records do not go to flash; a pending Store's record stays put */
    if (!v) {
        kv_pack_compact_open(s);
    }
    ppa = kv_wp_ppa(&ssd->wp);
    mark_page_valid(ssd, &ppa);
    set_rmap_ent(ssd, KV_OWNER_PACK, &ppa);
    t = ssd_advance_status(ssd, &ppa, &c);
    *lat = MAX(*lat, t);
    /* a Flush waits for this program, also once the page has left DRAM */
    s->pack_persist = MAX(s->pack_persist, stime + (int64_t)t);
    pg->id = ppa.ppa;
    kv_line_live(s, &ppa, pg->live_bytes);
    for (uint32_t i = 0; i < pg->nr; i++) {
        KvPackItem *it = &pg->item[i];

        if (!it->live) {
            continue;
        }
        if (it->owner < s->hash_slots) {
            s->table[it->owner].ppas[0] = ppa;
        } else if (v && v->packed && v->pack_off == it->off) {
            v->ppas[0] = ppa;
        }
    }
    g_hash_table_insert(s->packed, &pg->id, pg);
    s->open = NULL;
    s->nand_wr_pages++;
    ssd->nand_write_pages++;
    s->pack_pages++;
    s->pack_pad_bytes += s->pgsz - pg->fill;
    s->pack_early += early && kv_pack_fits(pg, 1, s->pgsz);
    kv_wp_step(s, &ssd->wp);
    return NVME_SUCCESS;
}

/*
 * Place a value of @len bytes for a Store into @v: whole pages for a
 * value whose record does not fit a page, else the open page. The open
 * page is programmed first when the value does not fit, and with the
 * value in it when it may not stay in DRAM; a program that fails leaves
 * the index as it was. The flash has no owner until the index takes the
 * value.
 */
static uint16_t kv_place_value(FemuKvssdState *s, NvmeRequest *req,
                               uint64_t len, FemuKvssdMappingEntry *v,
                               uint64_t *lat)
{
    bool hold = kv_pack_hold(s);
    uint32_t rec = kv_pack_rec(len);
    uint64_t t = 0;
    uint16_t status;
    uint32_t off;

    v->packed = false;
    v->pack_off = 0;
    if (!kv_packs(s, len)) {
        return kv_program_ppas(s, req, len, &v->ppas, &v->nr_ppas, lat,
                               req->stime);
    }
    v->ppas = NULL;
    v->nr_ppas = 0;
    *lat = MAX(*lat, kv_reclaim_empty_lines(s, req->stime));
    if (s->open && !kv_pack_fits(s->open, len, s->pgsz) &&
        s->open->live_bytes + rec <= (uint32_t)s->pgsz) {
        kv_pack_compact_open(s);
    }
    if (s->open && (!kv_pack_fits(s->open, len, s->pgsz) || !hold)) {
        status = kv_pack_program(s, req->stime, &t, !hold, NULL);
        if (status) {
            return status;
        }
    }
    if (!s->open) {
        s->open = kv_pack_new();
        if (!s->open) {
            return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
        }
    }
    v->ppas = g_try_new(struct ppa, 1);
    if (!v->ppas || kv_pack_append(s->open, KV_OWNER_NONE, len, &off)) {
        g_free(v->ppas);
        v->ppas = NULL;
        return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }
    v->ppas[0].ppa = KV_PPA_OPEN;
    v->nr_ppas = 1;
    v->packed = true;
    v->pack_off = off;
    /*
     * A page that may not stay in DRAM goes to flash with the value, before
     * the index takes it, so a failed program changes nothing.
     */
    if (!hold) {
        status = kv_pack_program(s, req->stime, &t, true, v);
        if (status) {
            kv_release_value(s, v, KV_OWNER_NONE);
            g_free(v->ppas);
            v->ppas = NULL;
            v->nr_ppas = 0;
            v->packed = false;
            return status;
        }
    }
    *lat = MAX(*lat, t);
    return NVME_SUCCESS;
}

/*
 * A Store's packed value is in the index, and the value it replaced is
 * released. A page now full of live records goes to flash, and the Store
 * waits for it; one still in DRAM costs the DRAM time, as a bbssd write
 * the buffer takes. The page may stay in DRAM here, so a program that
 * finds no page leaves it for the next Store.
 */
static void kv_pack_settle(FemuKvssdState *s, NvmeRequest *req,
                           const FemuKvssdMappingEntry *v, uint64_t *lat)
{
    uint64_t t = 0;

    if (!v->packed) {
        return;
    }
    s->pack_values++;
    if (v->ppas[0].ppa != KV_PPA_OPEN) {
        return;
    }
    if (s->open && kv_pack_full(s->open, s->pgsz) &&
        !kv_pack_program(s, req->stime, &t, false, NULL)) {
        *lat = MAX(*lat, t);
        return;
    }
    *lat = MAX(*lat, ssd_buffer_hit_lat(s->ssd));
}

/* as kv_program_ppas: reads from @stime, latency from the request start */
static uint16_t kv_read_ppas(FemuKvssdState *s, NvmeRequest *req,
                             const FemuKvssdMappingEntry *e, uint64_t bytes,
                             uint64_t *lat, int64_t stime)
{
    uint32_t pages = kv_value_pages(s, bytes);
    uint64_t wait = stime > req->stime ? stime - req->stime : 0;
    struct nand_cmd c = {
        .type = USER_IO,
        .cmd = NAND_READ,
        .stime = stime,
    };

    /* a packed value is in one page; still in DRAM it costs no read */
    if (e->packed && pages && e->nr_ppas == 1 &&
        e->ppas[0].ppa == KV_PPA_OPEN) {
        *lat = MAX(*lat, wait + ssd_buffer_hit_lat(s->ssd));
        s->pack_buf_reads++;
        return NVME_SUCCESS;
    }
    if (e->packed) {
        pages = MIN(pages, 1);
    }
    if (pages > e->nr_ppas) {
        return NVME_KV_UNRECOVERED_ERROR | NVME_DNR;
    }
    for (uint32_t i = 0; i < pages; i++) {
        struct ppa ppa = e->ppas[i];
        uint64_t sub;

        if (!valid_ppa(s->ssd, &ppa) || get_pg(s->ssd, &ppa)->status != PG_VALID) {
            return NVME_KV_UNRECOVERED_ERROR | NVME_DNR;
        }
        sub = wait + ssd_advance_status(s->ssd, &ppa, &c);
        *lat = sub > *lat ? sub : *lat;
        s->nand_rd_pages++;
    }
    return NVME_SUCCESS;
}

/* --- value GC: one victim line at a time --- */

#define KV_GC_VALID     1           /* the newest record names the version */
#define KV_GC_FLASH     2           /* that record is in an unpinned level */

/* return a line that GC could not empty to the list its counts call for */
static void kv_gc_requeue(FemuKvssdState *s, struct line *line)
{
    struct line_mgmt *lm = &s->ssd->lm;

    line->reclaiming = false;
    if (line->vpc == s->ssd->sp.pgs_per_line) {
        QTAILQ_INSERT_TAIL(&lm->full_line_list, line, entry);
        lm->full_line_cnt++;
    } else {
        pqueue_insert(lm->victim_line_pq, line);
    }
}

/* the owner of the first valid page of @line, or KV_OWNER_NONE */
static uint64_t kv_line_owner(FemuKvssdState *s, struct line *line)
{
    struct ssdparams *spp = &s->ssd->sp;
    struct ppa ppa = { .ppa = 0 };

    ppa.g.blk = line->id;
    for (int ch = 0; ch < spp->nchs; ch++) {
        for (int lun = 0; lun < spp->luns_per_ch; lun++) {
            for (int pl = 0; pl < spp->pls_per_lun; pl++) {
                for (int pg = 0; pg < spp->pgs_per_blk; pg++) {
                    ppa.g.ch = ch;
                    ppa.g.lun = lun;
                    ppa.g.pl = pl;
                    ppa.g.pg = pg;
                    if (get_pg(s->ssd, &ppa)->status == PG_VALID) {
                        return get_rmap_ent(s->ssd, &ppa);
                    }
                }
            }
        }
    }
    return KV_OWNER_NONE;
}

/*
 * The full value lines when a GC run starts, oldest first. With the LSM
 * tree a full line can still hold stale values that no merge has dropped,
 * so GC looks at them when no line has an invalid page. Lines that fill
 * during the run hold what it moved, so they are not in the list.
 */
typedef struct KvGcFull {
    uint32_t *id;
    uint32_t nr;
    uint32_t next;
    /*
     * kv_pack: the closed lines when the run starts. Each is tried once;
     * the lines the run fills hold what it moved.
     */
    uint8_t *cand;
    uint32_t ncand;
} KvGcFull;

static void kv_gc_full_init(FemuKvssdState *s, KvGcFull *f)
{
    struct line_mgmt *lm = &s->ssd->lm;
    struct line *line;

    f->id = NULL;
    f->nr = 0;
    f->next = 0;
    f->cand = NULL;
    f->ncand = 0;
    if (!s->lsm || !lm->full_line_cnt) {
        return;
    }
    f->id = g_new(uint32_t, lm->full_line_cnt);
    QTAILQ_FOREACH(line, &lm->full_line_list, entry) {
        if (f->nr < (uint32_t)lm->full_line_cnt &&
            kv_line_owner(s, line) != KV_OWNER_META) {
            f->id[f->nr++] = line->id;
        }
    }
}

/* a line is on the full list: closed, all valid, in no queue */
static bool kv_line_full(FemuKvssdState *s, struct line *line)
{
    return !line->pos && !line->reclaiming &&
           line->vpc == s->ssd->sp.pgs_per_line &&
           line != s->ssd->wp.curline &&
           (!s->meta_wp || line != s->meta_wp->curline);
}

/*
 * kv_pack: the closed line with the fewest live bytes. A full line of
 * packed pages can hold dead values, so the full lines count too; a line
 * with no dead byte does not.
 */
static struct line *kv_gc_least_live(FemuKvssdState *s, KvGcFull *f)
{
    struct line_mgmt *lm = &s->ssd->lm;
    uint64_t cap = (uint64_t)s->ssd->sp.pgs_per_line * s->pgsz;
    struct line *best = NULL;

    for (int i = 0; i < lm->tt_lines; i++) {
        struct line *line = &lm->lines[i];

        if (!f->cand[i] || (!line->pos && !kv_line_full(s, line)) ||
            s->line_live[i] >= cap) {
            continue;
        }
        if (!best || s->line_live[i] < s->line_live[best->id]) {
            best = line;
        }
    }
    if (best) {
        f->cand[best->id] = 0;
    }
    return best;
}

static void kv_gc_cand_init(FemuKvssdState *s, KvGcFull *f)
{
    struct line_mgmt *lm = &s->ssd->lm;

    if (!s->pack) {
        return;
    }
    f->cand = g_new0(uint8_t, lm->tt_lines);
    for (int i = 0; i < lm->tt_lines; i++) {
        if (lm->lines[i].pos || kv_line_full(s, &lm->lines[i])) {
            f->cand[i] = 1;
            f->ncand++;
        }
    }
}

/*
 * The victim: the line with the fewest valid pages (with kv_pack, the
 * line of @f with the fewest live bytes), or else, when a Store has no
 * room (@want), the next full value line of @f. *@full says which.
 */
static struct line *kv_gc_victim(FemuKvssdState *s, KvGcFull *f, bool want,
                                 bool *full)
{
    struct line_mgmt *lm = &s->ssd->lm;
    struct line *line;

    *full = false;
    if (s->pack) {
        line = kv_gc_least_live(s, f);
        if (line && line->pos) {
            pqueue_remove(lm->victim_line_pq, line);
            return line;
        }
        if (line) {
            QTAILQ_REMOVE(&lm->full_line_list, line, entry);
            lm->full_line_cnt--;
            return line;
        }
    } else {
        line = pqueue_peek(lm->victim_line_pq);
        if (line) {
            pqueue_pop(lm->victim_line_pq);
            return line;
        }
    }
    while (want && f->next < f->nr) {
        line = &lm->lines[f->id[f->next++]];
        if (kv_line_full(s, line)) {
            QTAILQ_REMOVE(&lm->full_line_list, line, entry);
            lm->full_line_cnt--;
            *full = true;
            return line;
        }
    }
    return NULL;
}

/* forget the page @ppa of a version: GC found it stale and released it */
static void kv_entry_forget_ppa(FemuKvssdMappingEntry *e, struct ppa *ppa)
{
    for (uint32_t i = 0; i < e->nr_ppas; i++) {
        if (e->ppas[i].ppa == ppa->ppa) {
            e->ppas[i].ppa = UNMAPPED_PPA;
        }
    }
}

/*
 * PinK section 4.5: a moved value whose record is on flash goes back into
 * the memtable. It takes a new slot that holds the value and its pages; the
 * old slot keeps no page and goes when the tree drops its record. A put
 * that fails leaves the old slot as it was, so only the cost is skipped.
 */
static void kv_gc_reinsert(FemuKvssdState *s, uint32_t slot)
{
    FemuKvssdMappingEntry *e;
    uint32_t to;

    if (!s->table[slot].key_len || s->table[slot].stale ||
        !kv_slot_pop(s, &to)) {
        return;
    }
    s->table[to] = s->table[slot];
    e = &s->table[slot];
    e->ppas = NULL;
    e->nr_ppas = 0;
    e->packed = false;
    e->stale = true;
    kv_move_owner(s, &s->table[to], slot, to);
    if (kv_lsm_reinsert(s->lsm, s->table[to].key, s->table[to].key_len,
                        to)) {
        e = &s->table[slot];
        e->ppas = s->table[to].ppas;
        e->nr_ppas = s->table[to].nr_ppas;
        e->packed = s->table[to].packed;
        e->pack_off = s->table[to].pack_off;
        e->stale = false;
        kv_move_owner(s, e, to, slot);
        kv_entry_clear(&s->table[to]);
        s->free_slots[s->nr_free++] = to;
    }
}

typedef struct KvGcPage {
    struct ppa ppa;
    uint64_t owner;
} KvGcPage;

/* a packed value GC moves: its source and its place in the GC page */
typedef struct KvGcMove {
    uint64_t owner;
    uint64_t src;               /* the ppa of the source page */
    uint32_t src_off;
    uint32_t len;
} KvGcMove;

/* the page GC packs moved values into, programmed before the erase */
typedef struct KvGcPack {
    KvGcMove *mv;
    uint32_t nr;
    uint32_t cap;
    uint32_t fill;
    int64_t ready;              /* the reads of its sources end */
} KvGcPack;

static void kv_gc_pack_add(KvGcPack *gp, uint64_t owner, uint64_t src,
                           const KvPackItem *it, int64_t ready)
{
    if (gp->nr == gp->cap) {
        gp->cap = gp->cap ? 2 * gp->cap : 16;
        gp->mv = g_renew(KvGcMove, gp->mv, gp->cap);
    }
    gp->mv[gp->nr++] = (KvGcMove) {
        .owner = owner, .src = src, .src_off = it->off, .len = it->len,
    };
    gp->fill += kv_pack_rec(it->len);
    gp->ready = MAX(gp->ready, ready);
}

/*
 * Program the GC page once its sources are read: each moved value takes
 * its new place, and its source dies. False when no page is free; the
 * sources then stay as they are.
 */
static bool kv_gc_pack_program(FemuKvssdState *s, KvGcPack *gp,
                               int64_t *tdone)
{
    struct ssd *ssd = s->ssd;
    struct nand_cmd wr = { .type = GC_IO, .cmd = NAND_WRITE,
                           .stime = gp->ready };
    KvPackPage *pg;
    struct ppa np;

    if (!gp->nr) {
        return true;
    }
    pg = kv_pack_new();
    if (!pg || kv_pack_reserve(pg, gp->nr) || !kv_wp_line(s, &ssd->wp)) {
        kv_pack_free(pg);
        return false;
    }
    np = kv_wp_ppa(&ssd->wp);
    pg->id = np.ppa;
    mark_page_valid(ssd, &np);
    set_rmap_ent(ssd, KV_OWNER_PACK, &np);
    *tdone = MAX(*tdone, gp->ready +
                 (int64_t)ssd_advance_status(ssd, &np, &wr));
    for (uint32_t i = 0; i < gp->nr; i++) {
        KvGcMove *m = &gp->mv[i];
        FemuKvssdMappingEntry *e = &s->table[m->owner];
        KvPackPage *src = kv_pack_page(s, m->src);
        int k = src ? kv_pack_find(src, m->src_off) : -1;
        uint32_t off;

        if (k < 0 || !e->packed || e->ppas[0].ppa != m->src ||
            e->pack_off != m->src_off) {
            continue;
        }
        /* the reserve above leaves no allocation to fail here */
        kv_pack_append(pg, m->owner, m->len, &off);
        e->ppas[0] = np;
        e->pack_off = off;
        kv_pack_kill(s, src, k);
    }
    kv_line_live(s, &np, pg->live_bytes);
    g_hash_table_insert(s->packed, &pg->id, pg);
    s->gc_wr_pages++;
    s->gc_moved_values += pg->live;
    s->pack_pad_bytes += s->pgsz - pg->fill;
    ssd->gc_write_pages++;
    kv_wp_step(s, &ssd->wp);
    gp->nr = 0;
    gp->fill = 0;
    gp->ready = 0;
    if (!pg->live) {
        /* a mismatch moved nothing: the page holds no value */
        set_rmap_ent(ssd, KV_OWNER_NONE, &np);
        mark_page_invalid(ssd, &np);
        g_hash_table_remove(s->packed, &np.ppa);
        kv_pack_free(pg);
    }
    return true;
}
/* the GC check of the LSM tree: newest record and where it is */
static void kv_gc_seen(FemuKvssdState *s, GHashTable *seen, uint64_t owner)
{
    uint32_t slot = (uint32_t)owner;
    FemuKvssdMappingEntry *e;
    uint32_t newest;
    int how = 0;

    if (owner >= s->hash_slots ||
        g_hash_table_contains(seen, GUINT_TO_POINTER(slot))) {
        return;
    }
    e = &s->table[slot];
    if (kv_lsm_gc_check(s->lsm, e->key, e->key_len, &newest)) {
        how |= KV_GC_FLASH;
    }
    if (newest == slot) {
        how |= KV_GC_VALID;
    }
    g_hash_table_insert(seen, GUINT_TO_POINTER(slot), GINT_TO_POINTER(how + 4));
}

static int kv_gc_how(GHashTable *seen, uint64_t owner)
{
    return GPOINTER_TO_INT(g_hash_table_lookup(
               seen, GUINT_TO_POINTER((uint32_t)owner))) - 4;
}

/*
 * Reinsert before the erase, as PinK does. Merges of the keys that go back
 * program meta pages that point to the moved values, so they wait for the
 * moves (@tdone). A key whose value did not move goes back too, at the
 * cost of a record.
 */
static void kv_gc_reinsert_all(FemuKvssdState *s, GHashTable *seen,
                               int64_t tdone)
{
    GHashTableIter it;
    gpointer k, v;

    s->lsm_ready = MAX(s->lsm_ready, tdone);
    g_hash_table_iter_init(&it, seen);
    while (g_hash_table_iter_next(&it, &k, &v)) {
        int how = GPOINTER_TO_INT(v) - 4;

        if ((how & KV_GC_VALID) && (how & KV_GC_FLASH)) {
            kv_gc_reinsert(s, GPOINTER_TO_UINT(k));
        }
    }
    kv_tree_issue(s);
}

/*
 * Move the live values of the packed page @ppa, read from @tmove: each
 * goes into the GC page, or is released when the LSM tree says it is
 * stale or no slot holds it. False when the GC page found no free page.
 */
static bool kv_gc_packed(FemuKvssdState *s, struct ppa *ppa, int64_t tmove,
                         GHashTable *seen, KvGcPack *gp, int64_t *tdone)
{
    struct nand_cmd rd = { .type = GC_IO, .cmd = NAND_READ, .stime = tmove };
    KvPackPage *src = kv_pack_page(s, ppa->ppa);
    g_autofree KvPackItem *items = NULL;
    int64_t ready;
    uint32_t nr;

    if (!src) {
        return true;
    }
    ready = tmove + (int64_t)ssd_advance_status(s->ssd, ppa, &rd);
    nr = src->nr;
    items = g_memdup2(src->item, nr * sizeof(*items));
    for (uint32_t i = 0; i < nr; i++) {
        KvPackItem *it = &items[i];

        if (!it->live) {
            continue;
        }
        if (it->owner >= s->hash_slots ||
            (s->lsm && !(kv_gc_how(seen, it->owner) & KV_GC_VALID))) {
            /* the page may go with the last item; look it up each time */
            KvPackPage *pg = kv_pack_page(s, ppa->ppa);
            int k = pg ? kv_pack_find(pg, it->off) : -1;

            if (it->owner < s->hash_slots) {
                FemuKvssdMappingEntry *e = &s->table[it->owner];

                if (e->packed && e->nr_ppas == 1 &&
                    e->ppas[0].ppa == ppa->ppa && e->pack_off == it->off) {
                    e->ppas[0].ppa = UNMAPPED_PPA;
                }
            }
            if (it->owner < s->hash_slots) {
                s->gc_stale_values++;
            }
            if (k >= 0 && kv_pack_kill(s, pg, k) &&
                it->owner < s->hash_slots) {
                s->gc_stale_pages++;
            }
            continue;
        }
        if (gp->fill + kv_pack_rec(it->len) > (uint32_t)s->pgsz &&
            !kv_gc_pack_program(s, gp, tdone)) {
            return false;
        }
        kv_gc_pack_add(gp, it->owner, ppa->ppa, it, ready);
    }
    *tdone = MAX(*tdone, ready);
    return true;
}

/*
 * Collect one victim line from @t0 (absolute ns). Value pages: the hash
 * index moves each valid page; the LSM tree first checks each version, as
 * PinK does, moves the ones the newest record names and releases the
 * others. Packed values move one by one into a GC page, which is
 * programmed before the erase. Meta pages move and the level list follows
 * them. The victim is erased once nothing on it is valid. *@tend is when
 * the erase ends.
 */
static bool kv_gc_line(FemuKvssdState *s, int64_t t0, KvGcFull *f,
                       bool want, bool *full, int64_t *tend)
{
    struct ssd *ssd = s->ssd;
    struct ssdparams *spp = &ssd->sp;
    struct line *victim = kv_gc_victim(s, f, want, full);
    g_autoptr(GHashTable) seen = NULL;
    g_autofree KvGcPage *pg = NULL;
    KvGcPack gp = { 0 };
    struct ppa ppa = { .ppa = 0 };
    struct nand_cmd rd = { .type = GC_IO, .cmd = NAND_READ };
    struct nand_cmd wr = { .type = GC_IO, .cmd = NAND_WRITE };
    int64_t tmove = t0;
    int64_t tdone = t0;
    uint32_t npg = 0;
    bool meta = false;

    if (!victim) {
        return false;
    }
    victim->reclaiming = true;
    pg = g_new(KvGcPage, spp->pgs_per_line);
    ppa.g.blk = victim->id;
    for (int ch = 0; ch < spp->nchs; ch++) {
        for (int lun = 0; lun < spp->luns_per_ch; lun++) {
            for (int pl = 0; pl < spp->pls_per_lun; pl++) {
                for (int p = 0; p < spp->pgs_per_blk; p++) {
                    ppa.g.ch = ch;
                    ppa.g.lun = lun;
                    ppa.g.pl = pl;
                    ppa.g.pg = p;
                    if (get_pg(ssd, &ppa)->status != PG_VALID) {
                        continue;
                    }
                    pg[npg].ppa = ppa;
                    pg[npg].owner = get_rmap_ent(ssd, &ppa);
                    meta |= pg[npg].owner == KV_OWNER_META;
                    npg++;
                }
            }
        }
    }

    /* the validity check reads meta pages; the moves wait for it */
    seen = g_hash_table_new(NULL, NULL);
    if (!meta && s->lsm && npg) {
        if (kv_lsm_gc_begin(s->lsm)) {
            kv_gc_requeue(s, victim);
            return false;
        }
        for (uint32_t i = 0; i < npg; i++) {
            KvPackPage *pk = pg[i].owner == KV_OWNER_PACK ?
                             kv_pack_page(s, pg[i].ppa.ppa) : NULL;

            for (uint32_t k = 0; pk && k < pk->nr; k++) {
                if (pk->item[k].live) {
                    kv_gc_seen(s, seen, pk->item[k].owner);
                }
            }
            kv_gc_seen(s, seen, pg[i].owner);
        }
        s->lsm_stime = t0;
        s->lsm_gc = 0;
        s->lsm_gc_base = 0;
        s->lsm_gc_level = -1;
        kv_lsm_gc_check_done(s->lsm);
        tmove = t0 + (int64_t)s->lsm_gc;
        tdone = tmove;
    }

    for (uint32_t i = 0; i < npg; i++) {
        uint64_t owner = pg[i].owner;
        struct ppa np;
        uint64_t r;
        uint64_t w;

        if (owner == KV_OWNER_PACK) {
            if (!kv_gc_packed(s, &pg[i].ppa, tmove, seen, &gp, &tdone)) {
                goto abort;
            }
            continue;
        }
        if (!meta && s->lsm && owner < s->hash_slots &&
            !(kv_gc_how(seen, owner) & KV_GC_VALID)) {
            kv_entry_forget_ppa(&s->table[owner], &pg[i].ppa);
            kv_release_page(s, &pg[i].ppa, owner);
            s->gc_stale_pages++;
            continue;
        }
        if (meta && !kv_lsm_relocate(s->lsm, pg[i].ppa.ppa, pg[i].ppa.ppa)) {
            /* no level list names it: a merge already replaced it */
            kv_release_page(s, &pg[i].ppa, KV_OWNER_META);
            continue;
        }
        if (!meta && owner >= s->hash_slots) {
            /* no owner: a value page whose Store failed; nothing reads it */
            kv_release_page(s, &pg[i].ppa, owner);
            continue;
        }
        if (!kv_wp_line(s, meta ? s->meta_wp : &ssd->wp)) {
            goto abort;
        }
        np = kv_wp_ppa(meta ? s->meta_wp : &ssd->wp);
        rd.stime = tmove;
        r = ssd_advance_status(ssd, &pg[i].ppa, &rd);
        wr.stime = tmove + (int64_t)r;
        kv_page_valid(s, &np, owner);
        w = ssd_advance_status(ssd, &np, &wr);
        tdone = MAX(tdone, tmove + (int64_t)(r + w));
        if (meta) {
            kv_lsm_relocate(s->lsm, pg[i].ppa.ppa, np.ppa);
            s->gc_meta_pages++;
        } else {
            FemuKvssdMappingEntry *e = &s->table[owner];

            for (uint32_t k = 0; k < e->nr_ppas; k++) {
                if (e->ppas[k].ppa == pg[i].ppa.ppa) {
                    e->ppas[k] = np;
                }
            }
            s->gc_wr_pages++;
        }
        kv_release_page(s, &pg[i].ppa, owner);
        ssd->gc_write_pages++;
        kv_wp_step(s, meta ? s->meta_wp : &ssd->wp);
    }
    /* the moved values are on flash before their victim is erased */
    if (!kv_gc_pack_program(s, &gp, &tdone)) {
        goto abort;
    }
    g_free(gp.mv);
    if (!meta && s->lsm) {
        kv_gc_reinsert_all(s, seen, tdone);
    }
    /* a page that is still valid holds data: never erase it */
    if (victim->vpc) {
        kv_gc_requeue(s, victim);
        *tend = tdone;
        return false;
    }

    *tend = tdone;
    ppa.ppa = 0;
    ppa.g.blk = victim->id;
    for (int ch = 0; ch < spp->nchs; ch++) {
        for (int lun = 0; lun < spp->luns_per_ch; lun++) {
            *tend = MAX(*tend, tdone + (int64_t)ssd_erase_lun_block(
                            ssd, ch, lun, victim->id, true, tdone));
        }
    }
    victim->reclaiming = false;
    mark_line_free(ssd, &ppa);
    s->gc_lines++;
    return true;

abort:
    /*
     * The values still in the GC page keep their sources; the moves that
     * were programmed stay, and their keys go back to the memtable too.
     */
    g_free(gp.mv);
    if (!meta && s->lsm) {
        kv_gc_reinsert_all(s, seen, tdone);
    }
    kv_gc_requeue(s, victim);
    *tend = tdone;
    return false;
}

static void kv_check(FemuKvssdState *s);

/*
 * GC in the command, from its start: while the free lines are at or below
 * the threshold, or a value of @need pages has no room, collect one victim
 * after another. A queued victim that gives no usable page ends the run,
 * unless a Store needs room: then up to as many such victims as the queue
 * held at the start. A full line is looked at once per run. *@lat takes
 * the time from the request start.
 */
static void kv_gc_run(FemuKvssdState *s, NvmeRequest *req, uint64_t need,
                      uint64_t *lat)
{
    struct ssd *ssd = s->ssd;
    int64_t t = req->stime;
    int passes = 2 * ssd->lm.tt_lines;
    bool ran = false;
    uint32_t tries;
    KvGcFull f;

    *lat = MAX(*lat, kv_reclaim_empty_lines(s, req->stime));
    if (!should_gc(ssd) && kv_room(s) >= need) {
        return;
    }
    kv_gc_full_init(s, &f);
    kv_gc_cand_init(s, &f);
    tries = s->pack ? f.ncand : pqueue_size(ssd->lm.victim_line_pq);
    while (passes-- > 0 && (should_gc(ssd) || kv_room(s) < need)) {
        uint64_t before = kv_room(s) + kv_wp_remaining(s, s->meta_wp);
        bool want = kv_room(s) < need;
        int64_t end = t;
        bool full;

        /* a full line holds no dead value unless values pack, or with the
         * LSM tree; without kv_pack it moves only for room */
        if (!kv_gc_line(s, t, &f, want, &full, &end)) {
            t = MAX(t, end);
            break;
        }
        ran = true;
        t = end;
        t += kv_reclaim_empty_lines(s, t);
        /*
         * A victim can give nothing when its moves and the merges of its
         * keys take what its erase frees. Without a Store to make room
         * for, that ends the run; with one, GC tries the victims that were
         * queued when it started, and the full lines, before it gives up.
         */
        if (!full && kv_room(s) + kv_wp_remaining(s, s->meta_wp) <= before &&
            (!want || tries-- == 0)) {
            break;
        }
    }
    g_free(f.id);
    g_free(f.cand);
    if (t > req->stime) {
        *lat = MAX(*lat, (uint64_t)(t - req->stime));
    }
    if (ran) {
        kv_check(s);
    }
}

/*
 * Fixed per-command cost of the hash index's work, so metadata-only
 * commands (exist, delete, a miss) are never free: one page read on the LUN
 * that holds the key's part of the index. It is charged as a mapping read,
 * since it reads no data block, and places nothing.
 *
 * The index is spread over every LUN by the key's hash, so lookups of
 * different keys proceed in parallel the way value pages do.
 */
static struct ppa kv_index_ppa(FemuKvssdState *s, const uint8_t *key,
                               uint8_t kl)
{
    struct ssdparams *spp = &s->ssd->sp;
    uint32_t luns = (uint32_t)spp->nchs * spp->luns_per_ch;
    uint32_t i = kv_fnv1a(key, kl) % luns;
    struct ppa ppa = { .ppa = 0 };

    ppa.g.ch = i % spp->nchs;
    ppa.g.lun = i / spp->nchs;
    return ppa;
}

static uint64_t kv_charge_base(FemuKvssdState *s, NvmeRequest *req,
                               const uint8_t *key, uint8_t kl)
{
    struct nand_cmd c = { .type = MAP_IO, .cmd = NAND_READ,
                          .stime = req->stime };
    struct ppa ppa = kv_index_ppa(s, key, kl);

    return ssd_advance_status(s->ssd, &ppa, &c);
}

/*
 * Index-probe cost: a flash-resident index (the LSM tree) reads its meta
 * pages one after another from the request start; a DRAM-resident index
 * (hash) pays nothing extra.
 */
static uint64_t kv_charge_index(FemuKvssdState *s, NvmeRequest *req,
                                const uint8_t *key, uint8_t kl)
{
    return (s->index->probe && key) ?
           s->index->probe(s, key, kl, req->stime) : 0;
}

/*
 * The cost of a command's index work. The hash pays its base read; the
 * LSM tree pays only its lookup, which is all the flash it reads.
 *
 * Every cost is measured from the request's own start time on the LUN
 * timelines, so each already contains any wait the LUN was under, including
 * a wait for an earlier stage of the same command. Adding them would count
 * that wait twice; the command completes when its last stage does.
 */
static uint64_t kv_charge_stages(FemuKvssdState *s, NvmeRequest *req,
                                 const uint8_t *key, uint8_t kl)
{
    uint64_t index = kv_charge_index(s, req, key, kl);

    if (s->lsm) {
        return index;
    }
    return MAX(kv_charge_base(s, req, key, kl), index);
}

/*
 * kv_timing=model: add the command to the window and return the model time
 * in place of @lat, the NAND model time. The NAND model still ran, so wear,
 * space and the media timelines stay as in media mode. Called under s->lock.
 */
static uint64_t kv_model_lat(FemuKvssdState *s, FemuKvOp op, uint64_t vlen,
                             uint64_t lat)
{
    bool floored;

    if (!s->timing_model) {
        return lat;
    }
    kv_window_add(&s->window, op, (uint32_t)vlen);
    lat = kv_model_latency_ns(&s->model, &s->window, &floored);
    /* once per namespace: s->lock covers the count, a shared flag it would not */
    if (floored && !s->model_floored++) {
        warn_report("FEMU kvssd: the KV timing model gave less than %g kIOPS "
                    "or no finite value; check kv_model_coeffs",
                    KV_MODEL_MIN_KIOPS);
    }
    return lat;
}

static void kv_apply_lat(NvmeRequest *req, uint64_t lat)
{
    req->reqlat += lat;
    req->expire_time += lat;
}

/* --- the host byte arena --- */

static int kv_entry_value_off_cmp(const void *a, const void *b)
{
    const FemuKvssdMappingEntry *ea = *(FemuKvssdMappingEntry **)a;
    const FemuKvssdMappingEntry *eb = *(FemuKvssdMappingEntry **)b;

    return (ea->value_off > eb->value_off) - (ea->value_off < eb->value_off);
}

/*
 * Pack the live values to the front of the byte arena. The arena is the
 * emulator's store of the host bytes, not the device: this moves memory
 * only and costs no NAND time. Value GC is what the device does.
 */
static bool kv_arena_pack(FemuKvssdState *s)
{
    g_autofree FemuKvssdMappingEntry **live = NULL;
    uint64_t frontier = 0;
    uint32_t nr = 0;

    live = g_try_new(FemuKvssdMappingEntry *, MAX(s->nr_entries, 1));
    if (!live) {
        return false;
    }
    for (uint32_t i = 0; i < s->hash_slots; i++) {
        FemuKvssdMappingEntry *e = &s->table[i];

        if (e->key_len && !e->stale && nr < MAX(s->nr_entries, 1)) {
            live[nr++] = e;
        }
    }
    qsort(live, nr, sizeof(*live), kv_entry_value_off_cmp);
    for (uint32_t i = 0; i < nr; i++) {
        FemuKvssdMappingEntry *e = live[i];

        if (e->length && e->value_off != frontier) {
            memmove(s->values + frontier, s->values + e->value_off,
                    e->length);
        }
        e->value_off = frontier;
        frontier += e->length;
    }
    s->value_next = frontier;
    s->value_reclaimable = 0;
    return true;
}

/*
 * Allocate host bytes (log-append). If the append frontier cannot fit and
 * there are dead bytes, pack first. Returns false only if even packed live
 * data plus the new value would exceed capacity.
 */
static bool kv_value_alloc(FemuKvssdState *s, uint64_t len, uint64_t *off)
{
    if (s->value_next <= s->value_capacity &&
        len <= s->value_capacity - s->value_next) {
        *off = s->value_next;
        s->value_next += len;
        return true;
    }
    if (s->value_reclaimable > 0 && kv_arena_pack(s) &&
        s->value_next <= s->value_capacity &&
        len <= s->value_capacity - s->value_next) {
        *off = s->value_next;
        s->value_next += len;
        return true;
    }
    return false;
}

static bool kv_logical_capacity_ok(FemuKvssdState *s,
                                   const FemuKvssdMappingEntry *old,
                                   uint8_t kl, uint64_t new_len)
{
    uint64_t old_len = old ? old->length : 0;
    uint64_t old_key = old ? old->key_len : 0;
    uint64_t used = s->value_used + s->key_used;

    if (used < old_len + old_key) {
        return false;
    }
    used -= old_len + old_key;
    if (new_len > UINT64_MAX - used || kl > UINT64_MAX - used - new_len) {
        return false;
    }
    return used + new_len + kl <= s->value_capacity;
}

/* NUSE: an old version stops using capacity at its overwrite or Delete */
static void kv_account_drop(FemuKvssdState *s, const FemuKvssdMappingEntry *old)
{
    s->value_reclaimable += old->length;
    if (s->value_used >= old->length) {
        s->value_used -= old->length;
    }
    if (s->key_used >= old->key_len) {
        s->key_used -= old->key_len;
    }
}

uint64_t kvssd_ftl_max_value(FemuKvssdState *s)
{
    return s->kv_value_max;
}

bool kvssd_ftl_exists(FemuKvssdState *s, const uint8_t *key, uint8_t kl)
{
    bool found;
    qemu_mutex_lock(&s->lock);
    found = s->index->find(s, key, kl, NULL) >= 0;
    qemu_mutex_unlock(&s->lock);
    return found;
}

/* the owner check runs every this many commands under FEMU_KV_CHECK */
#define KV_CHECK_EVERY  64

static void kv_tick(FemuKvssdState *s)
{
    if (s->check && ++s->check_tick % KV_CHECK_EVERY == 0) {
        kv_check(s);
    }
}

uint16_t kvssd_ftl_exist(FemuCtrl *n, FemuKvssdState *s, NvmeRequest *req,
                         const uint8_t *key, uint8_t kl)
{
    uint64_t lat;
    bool found;

    (void)n;
    qemu_mutex_lock(&s->lock);
    found = s->index->find(s, key, kl, NULL) >= 0;
    lat = kv_charge_stages(s, req, key, kl);
    kv_tick(s);
    qemu_mutex_unlock(&s->lock);
    kv_apply_lat(req, lat);
    return found ? NVME_SUCCESS : (NVME_KV_KEY_NOT_EXIST | NVME_DNR);
}

uint16_t kvssd_ftl_store(FemuCtrl *n, FemuKvssdState *s, NvmeRequest *req,
                         const uint8_t *key, uint8_t kl, uint32_t vsize,
                         bool sike, bool sinke)
{
    uint64_t off;
    uint64_t lat = 0;
    uint64_t probe = 0;
    uint16_t status;
    int existing;
    FemuKvssdMappingEntry old = {};
    FemuKvssdMappingEntry v = {};
    uint32_t pages = kv_value_pages(s, vsize);
    (void)n;

    qemu_mutex_lock(&s->lock);
    kv_tree_begin(s, req->stime);   /* for merge I/O the index queues */
    kv_tick(s);

    existing = s->index->find(s, key, kl, NULL);
    if (sike && existing < 0) {
        lat = kv_charge_stages(s, req, key, kl);
        kv_unlock(s);
        kv_apply_lat(req, lat);
        return NVME_KV_KEY_NOT_EXIST | NVME_DNR;
    }
    if (sinke && existing >= 0) {
        lat = kv_charge_stages(s, req, key, kl);
        kv_unlock(s);
        kv_apply_lat(req, lat);
        return NVME_KV_KEY_EXISTS | NVME_DNR;
    }
    if (existing < 0 && ((s->kv_max_keys && s->nr_entries >= s->kv_max_keys) ||
                         (!s->lsm && s->nr_entries >= s->hash_slots))) {
        lat = kv_charge_stages(s, req, key, kl);
        kv_unlock(s);
        kv_apply_lat(req, lat);
        return NVME_CAP_EXCEEDED | NVME_DNR;
    }
    if (existing >= 0) {
        old = s->table[existing];
    }
    if (!kv_logical_capacity_ok(s, existing >= 0 ? &old : NULL, kl, vsize)) {
        lat = kv_charge_stages(s, req, key, kl);
        kv_unlock(s);
        kv_apply_lat(req, lat);
        return NVME_CAP_EXCEEDED | NVME_DNR;
    }
    /*
     * The LSM tree looks a key up only for a conditional Store; a plain one
     * goes blind into the memtable. The lookup runs before the insert, and
     * beside the value programs.
     */
    if (s->lsm && (sike || sinke)) {
        probe = kv_charge_index(s, req, key, kl);
        lat = probe;
    }

    /* value GC makes room first; the Store leaves the reserve free */
    kv_gc_run(s, req, pages + kv_reserve(s), &lat);
    /*
     * Deletes and old records that sit in the upper levels hold meta pages
     * and the reserve for their merges. Merge them down, so they drop, and
     * collect the pages that frees.
     */
    if (s->lsm && kv_room(s) < pages + kv_reserve(s) &&
        kv_lsm_records(s->lsm) > s->nr_entries) {
        kv_lsm_compact_all(s->lsm);
        kv_tree_issue(s);
        kv_gc_run(s, req, pages + kv_reserve(s), &lat);
    }
    /* an LSM Store merges, so a zero-length one needs the reserve too */
    if ((pages || s->lsm) && kv_room(s) < pages + kv_reserve(s)) {
        kv_unlock(s);
        kv_apply_lat(req, lat);
        return NVME_CAP_EXCEEDED | NVME_DNR;
    }

    if (!kv_value_alloc(s, vsize, &off)) {
        kv_unlock(s);
        kv_apply_lat(req, lat);
        return NVME_CAP_EXCEEDED | NVME_DNR;
    }

    if (vsize) {
        /* DMA held under the lock: the arena slot [off,off+vsize) is reserved on
         * the append frontier and a concurrent pack could relocate it, so
         * the copy must be atomic with the allocation. */
        status = dma_write_cmd(n, &req->cmd, s->values + off, vsize);
        if (status) {
            s->value_next = off;            /* roll back the append */
            kv_unlock(s);
            kv_apply_lat(req, lat);         /* any GC still ran */
            return status;
        }
    }

    status = kv_place_value(s, req, vsize, &v, &lat);
    if (status) {
        s->value_next = off;
        kv_unlock(s);
        kv_apply_lat(req, lat);
        return status;
    }

    existing = s->index->find(s, key, kl, NULL);
    if (existing >= 0) {
        old = s->table[existing];
    }
    v.value_off = off;
    v.length = vsize;
    status = s->index->upsert(s, key, kl, &v);
    if (status) {
        kv_release_value(s, &v, KV_OWNER_NONE);
        g_free(v.ppas);
        s->value_next = off;
        kv_unlock(s);
        kv_apply_lat(req, lat);
        return status;
    }
    if (existing >= 0) {
        /* the LSM tree releases the old pages when it drops their record */
        if (!s->lsm) {
            kv_discard_value_ppas(s, &old, (uint32_t)existing);
        }
        kv_account_drop(s, &old);
    }
    s->value_used += vsize;
    s->key_used += kl;
    /* after the old value died, so an overwrite in DRAM is not programmed */
    kv_pack_settle(s, req, &v, &lat);
    kv_count_host(s, vsize);

    /* command/index base cost + value-page program timing through the NAND model */
    if (!s->lsm) {
        lat = MAX(lat, kv_charge_stages(s, req, key, kl));
    }
    lat = MAX(lat, probe);
    lat = kv_model_lat(s, existing >= 0 ? KV_OP_UPDATE : KV_OP_INSERT, vsize,
                       lat);

    kv_unlock(s);
    kv_apply_lat(req, lat);
    return NVME_SUCCESS;
}

uint16_t kvssd_ftl_retrieve(FemuCtrl *n, FemuKvssdState *s, NvmeRequest *req,
                            const uint8_t *key, uint8_t kl, uint32_t hbs,
                            uint32_t *full_len)
{
    int slot;
    uint64_t off, vlen, xfer, lat = 0;
    uint16_t status;
    (void)n;

    qemu_mutex_lock(&s->lock);
    kv_tick(s);
    slot = s->index->find(s, key, kl, NULL);
    if (slot < 0) {
        lat = kv_charge_stages(s, req, key, kl);
        qemu_mutex_unlock(&s->lock);
        kv_apply_lat(req, lat);
        *full_len = 0;
        return NVME_KV_KEY_NOT_EXIST | NVME_DNR;
    }
    off = s->table[slot].value_off;
    vlen = s->table[slot].length;
    xfer = MIN(vlen, hbs);              /* spec: return min(HBS, value) bytes */
    *full_len = (uint32_t)vlen;         /* but report the FULL size in CQE Dword0 */

    /* MDTS bounds what moves: the smaller of the buffer and the value */
    status = nvme_check_mdts(n, xfer);
    if (status) {
        qemu_mutex_unlock(&s->lock);
        return status;
    }

    if (s->lsm) {
        /* the value pointer is in the meta page: the value read waits for it */
        uint64_t probe = kv_charge_index(s, req, key, kl);

        lat = probe;
        status = kv_read_ppas(s, req, &s->table[slot], xfer, &lat,
                              req->stime + probe);
    } else {
        /* base + read of the value pages actually touched (the transferred span) */
        lat = kv_charge_base(s, req, key, kl);
        status = kv_read_ppas(s, req, &s->table[slot], xfer, &lat,
                              req->stime);
    }
    if (status) {
        qemu_mutex_unlock(&s->lock);
        /* the LSM reads ran; the hash keeps its error path */
        if (s->lsm) {
            kv_apply_lat(req, lat);
        }
        return status;
    }
    lat = MAX(lat, s->lsm ? 0 : kv_charge_index(s, req, key, kl));
    if (xfer) {
        status = dma_read_cmd_buf(n, &req->cmd, s->values + off,
                                  (uint32_t)xfer, hbs);
        if (status) {
            qemu_mutex_unlock(&s->lock);
            if (s->lsm) {
                kv_apply_lat(req, lat);
            }
            return status;
        }
    }

    lat = kv_model_lat(s, KV_OP_READ, xfer, lat);

    qemu_mutex_unlock(&s->lock);
    kv_apply_lat(req, lat);
    return NVME_SUCCESS;
}

uint16_t kvssd_ftl_delete(FemuCtrl *n, FemuKvssdState *s, NvmeRequest *req,
                          const uint8_t *key, uint8_t kl, bool *deleted)
{
    int slot;
    int removed;
    uint64_t lat = 0;
    uint64_t probe = 0;
    FemuKvssdMappingEntry old = {};
    (void)n;

    qemu_mutex_lock(&s->lock);
    kv_tree_begin(s, req->stime);   /* for merge I/O the index queues */
    kv_tick(s);
    /*
     * The LSM tree looks the key up only when EDNEK makes the status depend
     * on it; otherwise the tombstone goes in blind. Its merges may need
     * pages, so GC runs first; a Delete may use the reserve.
     */
    if (s->lsm) {
        if (s->ednek) {
            probe = kv_charge_index(s, req, key, kl);
        }
        kv_gc_run(s, req, 0, &lat);
    }
    slot = s->index->find(s, key, kl, NULL);
    if (slot >= 0) {
        old = s->table[slot];
    }
    removed = s->index->remove(s, key, kl);
    if (removed > 0) {
        if (!s->lsm) {
            kv_discard_value_ppas(s, &old, (uint32_t)slot);
        }
        kv_account_drop(s, &old);
    }
    if (s->lsm) {
        lat = MAX(lat, probe);
    } else {
        lat = kv_charge_stages(s, req, key, kl);
    }
    kv_unlock(s);

    kv_apply_lat(req, lat);
    *deleted = removed > 0;
    return removed < 0 ? NVME_INTERNAL_DEV_ERROR | NVME_DNR : NVME_SUCCESS;
}

/*
 * Make the values in the open page persistent: Flush with a volatile
 * write cache enabled (Base 2.3, 7.2). With @req NULL (shutdown, or the
 * host cleared WCE) no command waits; the program loads the LUN only.
 */
static uint16_t kv_flush(FemuKvssdState *s, NvmeRequest *req)
{
    int64_t now = req ? req->stime : qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    uint64_t lat = 0;
    uint16_t status;

    qemu_mutex_lock(&s->lock);
    status = kv_pack_program(s, now, &lat, true, NULL);
    /* values that left DRAM earlier may still be in their program */
    if (s->pack_persist > now) {
        lat = MAX(lat, (uint64_t)(s->pack_persist - now));
    }
    qemu_mutex_unlock(&s->lock);
    if (req) {
        kv_apply_lat(req, lat);
    }
    return status ? NVME_INTERNAL_DEV_ERROR | NVME_DNR : NVME_SUCCESS;
}

uint16_t kvssd_ftl_flush(FemuKvssdState *s, NvmeRequest *req)
{
    return kv_flush(s, req);
}

/* the List return structure as it grows */
typedef struct KvListBuf {
    uint8_t *buf;
    uint32_t cap;
    uint32_t pos;
    uint32_t hbs;
    uint32_t nrk;
} KvListBuf;

/*
 * Add one key; false when it does not fit. Figure 16: a key data structure
 * is padded to end on a 4 byte boundary, so the next entry begins at the
 * padded offset rather than immediately after the key. Advancing by the
 * unpadded length would misalign every following entry and desynchronize a
 * host walking the list. Only whole keys that fit in the host buffer are
 * returned.
 */
static bool kv_list_add(KvListBuf *lb, const uint8_t *key, uint8_t kl)
{
    uint32_t need = 2 + kl;
    uint32_t padded = (lb->pos + need + 3) & ~3u;

    if (padded > lb->hbs) {
        return false;
    }
    if (padded > lb->cap) {
        uint32_t grown = MAX(padded, (uint32_t)MIN(lb->hbs, 2ULL * lb->cap));

        lb->buf = g_realloc(lb->buf, grown);
        memset(lb->buf + lb->cap, 0, grown - lb->cap);
        lb->cap = grown;
    }
    stw_le_p(lb->buf + lb->pos, kl);
    memcpy(lb->buf + lb->pos + 2, key, kl);
    lb->pos = padded;                  /* buf is zeroed, so the pad is zero */
    lb->nrk++;
    return true;
}

static bool kv_list_add_scan(void *opaque, const uint8_t *key, uint8_t kl,
                             uint32_t slot)
{
    (void)slot;
    return kv_list_add(opaque, key, kl);
}

static uint16_t kv_build_list_locked(FemuKvssdState *s, const uint8_t *start_key,
                                     uint8_t start_len, uint32_t hbs,
                                     uint8_t **out, uint32_t *out_len,
                                     uint32_t *out_nrk)
{
    KvListBuf lb = { .pos = 4, .hbs = hbs };   /* room for the NRK header */
    uint32_t start_slot = 0;
    int slot;

    if (hbs < 4) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    /*
     * Without MDTS the host buffer can be 4 GiB; grow ours with the keys
     * found rather than allocate what the host asked for.
     */
    lb.cap = MIN(hbs, 4096);
    lb.buf = g_malloc0(lb.cap);

    if (s->lsm) {
        /*
         * The LSM tree returns the keys in byte order from the first key at
         * or after the start key, then wraps: every key once, as the table
         * walk below does, in an order no merge changes.
         */
        if (kv_lsm_scan(s->lsm, start_key, start_len, kv_list_add_scan,
                        &lb)) {
            g_free(lb.buf);
            return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
        }
        goto done;
    }

    if (start_len) {
        slot = s->index->find(s, start_key, start_len, NULL);
        if (slot >= 0) {
            start_slot = (uint32_t)slot;
        }
    }

    /*
     * Enumerate keys present in the index. The spec only requires a stable order
     * in the absence of mutations and that the start key (if it exists) is first;
     * if it does not exist, the first returned key is vendor specific. We use a
     * circular table order, starting at the matching slot or at slot 0.
     */
    for (uint32_t scanned = 0; scanned < s->hash_slots; scanned++) {
        uint32_t i = (start_slot + scanned) % s->hash_slots;
        FemuKvssdMappingEntry *e = &s->table[i];

        if (kv_entry_empty(e)) {
            continue;
        }
        if (!kv_list_add(&lb, e->key, e->key_len)) {
            break;
        }
    }
done:
    stl_le_p(lb.buf, lb.nrk);          /* Number of Returned Keys header */
    *out = lb.buf;
    *out_len = lb.pos;                 /* already 4 byte aligned by the pad */
    *out_nrk = lb.nrk;
    return NVME_SUCCESS;
}

uint16_t kvssd_ftl_list(FemuCtrl *n, FemuKvssdState *s, NvmeRequest *req,
                        const uint8_t *start_key, uint8_t start_len,
                        uint32_t hbs)
{
    uint8_t *buf = NULL;
    uint32_t len = 0;
    uint32_t nrk = 0;
    uint16_t status;
    uint64_t lat;

    /*
     * The host buffer size is taken straight from the command and used to
     * size the list this builds, so without a bound a host could ask for four
     * gigabytes at a time. The maximum data transfer the controller
     * advertises is the limit that already applies to the transfer itself.
     */
    status = nvme_check_mdts(n, hbs);
    if (status) {
        return status;
    }

    qemu_mutex_lock(&s->lock);
    kv_tick(s);
    if (s->lsm) {
        /* the scan reads each level in sequence, the levels side by side */
        s->lsm_stime = req->stime;
        memset(s->lsm_level, 0, sizeof(s->lsm_level));
    }
    status = kv_build_list_locked(s, start_key, start_len, hbs, &buf, &len, &nrk);
    if (status) {
        qemu_mutex_unlock(&s->lock);
        return status;
    }
    if (s->lsm) {
        /* the scan reads are all the flash a List of the tree reads */
        lat = 0;
        for (int i = 0; i <= KV_LSM_MAX_LEVELS; i++) {
            lat = MAX(lat, s->lsm_level[i]);
        }
    } else {
        lat = kv_charge_stages(s, req, start_key, start_len);
    }
    qemu_mutex_unlock(&s->lock);

    status = dma_read_cmd_buf(n, &req->cmd, buf, len, hbs);
    g_free(buf);
    if (status) {
        /* the LSM scan reads ran; the hash keeps its error path */
        if (s->lsm) {
            kv_apply_lat(req, lat);
        }
        return status;
    }
    kv_apply_lat(req, lat);
    return NVME_SUCCESS;
}

/* --- lifecycle --- */

/*
 * Drop the open page and every packed page header. The entries released
 * their values first, so no header should be left; one that is left
 * gives its page back too.
 */
static void kv_pack_reset(FemuKvssdState *s)
{
    GHashTableIter it;
    gpointer k, v;

    kv_pack_free(s->open);
    s->open = NULL;
    if (!s->packed) {
        return;
    }
    g_hash_table_iter_init(&it, s->packed);
    while (g_hash_table_iter_next(&it, &k, &v)) {
        KvPackPage *pg = v;

        struct ppa ppa = { .ppa = pg->id };

        if (s->ssd && kv_page_owned(s, &ppa, KV_OWNER_PACK)) {
            set_rmap_ent(s->ssd, KV_OWNER_NONE, &ppa);
            mark_page_invalid(s->ssd, &ppa);
            kv_line_live(s, &ppa, -(int64_t)pg->live_bytes);
        }
        g_hash_table_iter_remove(&it);
        kv_pack_free(pg);
    }
}

/*
 * Drop every pair. The pages they held are released, so the flash shows
 * no orphan; the blocks keep their wear.
 */
static void kvssd_reset_table(FemuKvssdState *s)
{
    for (uint32_t i = 0; i < s->hash_slots; i++) {
        if (s->ssd) {
            kv_discard_value_ppas(s, &s->table[i], i);
        }
        kv_entry_drop_ppas(&s->table[i]);
        kv_entry_clear(&s->table[i]);
    }
    s->nr_entries = 0;
    s->value_next = 0;
    s->value_used = 0;
    s->key_used = 0;
    s->value_reclaimable = 0;
    kv_tree_reset(s);
    kv_pack_reset(s);
}



static void kvssd_free_ssd(FemuKvssdState *s)
{
    struct ssd *ssd = s->ssd;

    if (!ssd) {
        return;
    }

    /*
     * The same teardown the other FTL-backed modes use. This mode used to
     * carry its own copy, which had drifted: it never released the media
     * layer, and it freed the mapping scheme's private state with a flat
     * g_free() that missed the allocations hanging off it.
     */
    /*
     * The namespace and the controller point at this FTL too, and the other
     * FTL-backed modes clear both when they release theirs. Leaving them set
     * left every reader that tests ns->ssd -- the SMART and endurance counters
     * among them -- looking at freed memory.
     */
    if (s->ns) {
        if (s->ns->ctrl && s->ns->ctrl->ssd == ssd) {
            s->ns->ctrl->ssd = NULL;
        }
        if (s->ns->ssd == ssd) {
            s->ns->ssd = NULL;
        }
    }
    ssd_free(ssd);
    g_free(ssd);
    s->ssd = NULL;
}

static bool kvssd_init_timing_ssd(FemuKvssdState *s, FemuCtrl *n,
                                  NvmeNamespace *ns)
{
    struct ssd *ssd = g_try_new0(struct ssd, 1);

    if (!ssd) {
        return false;
    }
    ssd->ssdname = (char *)n->devname;
    ssd->dataplane_started_ptr = &n->dataplane_started;

    /*
     * The FTL is set up through the namespace, as it is for the other
     * FTL-backed modes, so hand it the device this mode owns.
     */
    ns->ssd = ssd;
    if (!n->ssd) {
        n->ssd = ssd;
    }
    ssd_init(n, ns);
    s->ssd = ssd;
    s->pgsz = ssd->sp.secsz * ssd->sp.secs_per_pg;
    if (s->pgsz <= 0) {
        s->pgsz = 4096;
    }
    return true;
}

static void kv_tree_free(FemuKvssdState *s)
{
    if (s->lsm) {
        kv_lsm_destroy(s->lsm);
    }
    g_free(s->lsm);
    g_free(s->free_slots);
    g_free(s->lsm_pend);
    g_free(s->meta_wp);
    s->lsm = NULL;
    s->free_slots = NULL;
    s->lsm_pend = NULL;
    s->meta_wp = NULL;
}

FemuKvssdState *kvssd_ftl_alloc(FemuCtrl *n, NvmeNamespace *ns, Error **errp)
{
    FemuKvssdState *s;
    uint64_t cap;
    uint32_t slots;

    /*
     * KV reclaims by taking the emptiest line off the shared victim queue.
     * Another policy reorders that queue (fifo by close order, which KV never
     * records), so the line it takes is no longer the emptiest.
     */
    if (n->bb_params.gc_policy && strcmp(n->bb_params.gc_policy, "greedy")) {
        error_setg(errp, "FEMU kvssd: gc_policy=%s is not supported; KV mode "
                   "always reclaims the emptiest line", n->bb_params.gc_policy);
        return NULL;
    }

    s = g_try_new0(FemuKvssdState, 1);
    if (!s) {
        error_setg(errp, "KVSSD state allocation failed");
        return NULL;
    }

    /* value-space capacity = this namespace's byte size (NSZE in KV terms). This
     * is refined below once the NAND geometry is known: the host-visible arena is
     * bounded by the physical NAND minus a GC reserve, so a KV namespace can never
     * claim more live bytes than the emulated flash can hold (see the OP clamp). */
    cap = ns->size ? ns->size : (uint64_t)n->memsz * 1024 * 1024;
    if (cap == 0) {
        cap = 256ull * 1024 * 1024;
    }
    s->value_capacity = cap;
    s->kv_key_max = KV_DEFAULT_KEY_MAX;
    s->kv_value_max = KV_DEFAULT_VALUE_MAX;
    s->kv_max_keys = 0;                /* set below, once the index is sized */
    s->ednek = false;                 /* spec default: delete-missing succeeds */

    /*
     * NAND timing engine: a full bbssd ssd built from bb_params (channels, LUNs,
     * planes, NAND latencies) -- value pages are placed + charged through it.
     * Built before the arena so the value capacity can be clamped to the physical
     * NAND size.
     */
    s->ns = ns;
    if (!kvssd_init_timing_ssd(s, n, ns)) {
        error_setg(errp, "KVSSD NAND timing allocation failed");
        g_free(s);
        return NULL;
    }

    /*
     * Clamp the host-visible value arena to the physical NAND, minus a GC reserve.
     * A real KV-SSD over-provisions: the usable (live) capacity is smaller than the
     * raw flash so log-structured value placement + compaction always have free
     * lines to relocate into. Without this, value_capacity (from ns->size) could
     * exceed what the emulated channels/LUNs/planes hold, and the byte arena and
     * the NAND page pool would disagree on "full". Usable = tt_pgs * pgsz * (1-OP),
     * OP taken from the same GC threshold bbssd uses. Never grow beyond ns->size.
     */
    {
        struct ssdparams *spp = &s->ssd->sp;
        uint64_t nand_bytes = (uint64_t)spp->tt_pgs * (uint64_t)s->pgsz;
        /*
         * bbssd: gc_thres_lines = (1 - gc_thres_pcent) * tt_lines and GC triggers
         * at free_line_cnt <= gc_thres_lines, so gc_thres_pcent is the usable
         * fraction and (1 - gc_thres_pcent) is the free-line (OP) reserve. The
         * live value arena gets the usable fraction.
         */
        double usable_frac = spp->gc_thres_pcent;

        if (usable_frac <= 0.0 || usable_frac > 1.0) {
            usable_frac = 0.75;                   /* sane default if unset */
        }
        if (nand_bytes) {
            uint64_t usable = (uint64_t)((double)nand_bytes * usable_frac);
            if (usable < s->value_capacity) {
                s->value_capacity = usable;
            }
        }
        if (s->value_capacity == 0) {
            s->value_capacity = s->pgsz;          /* never zero */
        }
    }
    cap = s->value_capacity;

    /* size the index to ~2x the keys that fit if all values were 4 KiB */
    slots = (uint32_t)MIN((uint64_t)(1u << 22),
                          (cap / 4096 + 1) * KV_INDEX_LOAD_NUM);
    if (slots < 1024) {
        slots = 1024;
    }
    s->hash_slots = slots;
    /*
     * The index is what actually caps the key count, and the format reported a
     * maximum of zero -- which the field defines as no maximum -- so a host was
     * told it could store keys the device then refused for want of capacity.
     * Report the limit that is enforced.
     */
    s->kv_max_keys = s->hash_slots - 1;
    s->index = &kv_index_hash;
    s->pack = n->kv_pack;
    s->packed = g_hash_table_new(g_int64_hash, g_int64_equal);
    s->line_live = g_try_new0(uint64_t, s->ssd->lm.tt_lines);

    s->table = g_try_new0(FemuKvssdMappingEntry, s->hash_slots);
    s->values = g_try_malloc0(s->value_capacity);
    if (s->table && s->values && n->kv_index && !strcmp(n->kv_index, "lsm")) {
        /* a meta page record: 16 key bytes, 8 pointer, 8 length and flags */
        if (s->pgsz < KV_LSM_REC_BYTES) {
            error_setg(errp, "FEMU kvssd: kv_index=lsm needs a page of at "
                       "least %d bytes; the page is %d", KV_LSM_REC_BYTES,
                       s->pgsz);
            goto fail;
        }
        s->lsm = g_try_new0(KvLsm, 1);
        s->free_slots = g_try_new(uint32_t, s->hash_slots);
        s->meta_wp = g_try_new0(struct write_pointer, 1);
        if (!s->lsm || !s->free_slots || !s->meta_wp ||
            kv_lsm_init(s->lsm, n->kv_lsm_memtable_keys,
                        n->kv_lsm_size_ratio, n->kv_lsm_pinned_levels,
                        s->pgsz / KV_LSM_REC_BYTES, &kv_tree_ops, s)) {
            error_setg(errp, "KVSSD LSM index allocation failed");
            goto fail;
        }
        s->index = &kv_index_lsm;
        kv_tree_reset(s);
    }
    if (!s->table || !s->values || !s->line_live) {
        error_setg(errp, "KVSSD DRAM allocation failed");
        goto fail;
    }
    for (uint32_t i = 0; i < s->hash_slots; i++) {
        kv_entry_clear(&s->table[i]);
    }

    qemu_mutex_init(&s->lock);
    /* the owner check of every page, for tests; it is slow */
    s->check = getenv("FEMU_KV_CHECK") != NULL;

    femu_log("%s,KVSSD mode: NVMe-KV 1.3, value_cap=%" PRIu64 " MB (NAND %" PRIu64
             " MB, OP %.0f%%), index=%s slots=%u, NAND pgsz=%d\n", n->devname,
             s->value_capacity / (1024 * 1024),
             ((uint64_t)s->ssd->sp.tt_pgs * (uint64_t)s->pgsz) / (1024 * 1024),
             (1.0 - s->ssd->sp.gc_thres_pcent) * 100.0, s->index->name,
             s->hash_slots, s->pgsz);

    if (getenv("FEMU_KV_SELFTEST")) {
        kvssd_ftl_selftest(s);
    }
    return s;

fail:
    kv_tree_free(s);
    g_hash_table_destroy(s->packed);
    g_free(s->line_live);
    g_free(s->values);
    g_free(s->table);
    kvssd_free_ssd(s);
    g_free(s);
    return NULL;
}

static uint16_t kv_selftest_store_one(FemuKvssdState *s, NvmeRequest *req,
                                      const void *key, uint8_t kl,
                                      const void *data, uint32_t len)
{
    uint64_t off;
    uint64_t lat = 0;
    int existing = s->index->find(s, key, kl, NULL);
    FemuKvssdMappingEntry old = {};
    FemuKvssdMappingEntry v = {};
    uint16_t status;

    if (existing >= 0) {
        old = s->table[existing];
    }
    if (existing < 0 && ((s->kv_max_keys && s->nr_entries >= s->kv_max_keys) ||
                         s->nr_entries >= s->hash_slots)) {
        return NVME_CAP_EXCEEDED | NVME_DNR;
    }
    if (!kv_logical_capacity_ok(s, existing >= 0 ? &old : NULL, kl, len)) {
        return NVME_CAP_EXCEEDED | NVME_DNR;
    }
    kv_gc_run(s, req, kv_value_pages(s, len) + kv_reserve(s), &lat);
    if (!kv_value_alloc(s, len, &off)) {
        return NVME_CAP_EXCEEDED | NVME_DNR;
    }
    if (len) {
        memcpy(s->values + off, data, len);
    }
    status = kv_place_value(s, req, len, &v, &lat);
    if (status) {
        s->value_next = off;
        return status;
    }

    existing = s->index->find(s, key, kl, NULL);
    if (existing >= 0) {
        old = s->table[existing];
    }
    v.value_off = off;
    v.length = len;
    status = s->index->upsert(s, key, kl, &v);
    if (status) {
        kv_release_value(s, &v, KV_OWNER_NONE);
        g_free(v.ppas);
        s->value_next = off;
        return status;
    }
    if (existing >= 0) {
        if (!s->lsm) {
            kv_discard_value_ppas(s, &old, (uint32_t)existing);
        }
        kv_account_drop(s, &old);
    }
    s->value_used += len;
    s->key_used += kl;
    kv_pack_settle(s, req, &v, &lat);
    kv_count_host(s, len);
    kv_apply_lat(req, lat);
    return NVME_SUCCESS;
}

/* as a command: merge I/O the store queues is issued before it returns */
static uint16_t kv_selftest_store_locked(FemuKvssdState *s, NvmeRequest *req,
                                         const void *key, uint8_t kl,
                                         const void *data, uint32_t len)
{
    uint16_t status;

    kv_tree_begin(s, req->stime);
    status = kv_selftest_store_one(s, req, key, kl, data, len);
    kv_tree_issue(s);
    return status;
}

static bool kv_selftest_delete_locked(FemuKvssdState *s, const void *key,
                                      uint8_t kl)
{
    int slot = s->index->find(s, key, kl, NULL);
    FemuKvssdMappingEntry old;

    if (slot < 0) {
        return false;
    }
    old = s->table[slot];
    kv_tree_begin(s, s->lsm_stime);
    if (s->index->remove(s, key, kl) <= 0) {
        kv_tree_issue(s);
        return false;
    }
    kv_tree_issue(s);
    if (!s->lsm) {
        kv_discard_value_ppas(s, &old, (uint32_t)slot);
    }
    kv_account_drop(s, &old);
    return true;
}

/*
 * In-device self-test of the KV-FTL logic that the stock guest kernel cannot reach
 * (it won't attach a CSI=01h namespace, so no IO passthru). Logs KVSELFTEST
 * PASS/FAIL lines. Enabled with FEMU_KV_SELFTEST=1.
 */
void kvssd_ftl_selftest(FemuKvssdState *s)
{
    FemuCtrl *n = s->ssd ? s->ssd->n : NULL;
    NvmeRequest req = {};
    uint64_t saved_cap;
    int fails = 0;
    int npass = 0;
#define KVT(cond, name) do { \
        if (cond) { npass++; } \
        else { fails++; femu_err("KVSELFTEST FAIL %s\n", (name)); } \
    } while (0)

    req.stime = req.expire_time = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    qemu_mutex_lock(&s->lock);

    /* 1. many keys with forced collisions: store 64 keys, all must be findable */
    for (int i = 0; i < 64; i++) {
        char k[8]; int kl = snprintf(k, sizeof(k), "k%d", i);
        char v[16]; int vl = snprintf(v, sizeof(v), "val%d", i) + 1;
        KVT(kv_selftest_store_locked(s, &req, k, kl, v, vl) == NVME_SUCCESS,
            "store-many-keys");
    }
    {
        bool all = true;
        for (int i = 0; i < 64; i++) {
            char k[8]; int kl = snprintf(k, sizeof(k), "k%d", i);
            int slot = s->index->find(s, (const uint8_t *)k, kl, NULL);
            if (slot < 0) { all = false; break; }
            char v[16]; int vl = snprintf(v, sizeof(v), "val%d", i) + 1;
            if (memcmp(s->values + s->table[slot].value_off, v, vl) != 0) {
                all = false; break;
            }
        }
        KVT(all, "collision-find-and-data (K-1)");
    }

    /* 2. zero-length value: key exists, length 0 (K-3) */
    KVT(kv_selftest_store_locked(s, &req, "zero", 4, "", 0) == NVME_SUCCESS,
        "store-zero-length");
    {
        int slot = s->index->find(s, (const uint8_t *)"zero", 4, NULL);
        KVT(slot >= 0 && s->table[slot].length == 0 &&
            s->key_used >= 4, "zero-length-value (K-3)");
    }

    /* 3. overwrite accounting: overwrite k0, used/key bytes must not double-count */
    {
        uint64_t used_before = s->value_used;
        uint64_t key_before = s->key_used;
        uint64_t k0len = 0;
        int slot = s->index->find(s, (const uint8_t *)"k0", 2, NULL);
        if (slot >= 0) k0len = s->table[slot].length;
        KVT(kv_selftest_store_locked(s, &req, "k0", 2,
                                     "OVERWRITTEN-VALUE", 18) == NVME_SUCCESS,
            "overwrite-store");
        KVT(s->value_used == used_before - k0len + 18 &&
            s->key_used == key_before, "overwrite-accounting (K-4)");
    }

    /* 4. delete then find must miss; remaining keys still findable (K-1 backshift) */
    {
        bool removed = kv_selftest_delete_locked(s, "k5", 2);
        int slot = s->index->find(s, (const uint8_t *)"k5", 2, NULL);
        int other = s->index->find(s, (const uint8_t *)"k6", 2, NULL);
        KVT(removed && slot < 0 && other >= 0, "delete-backshift (K-1)");
    }

    /* 5. capacity checks include keys+values and reject over-limit stores */
    saved_cap = s->value_capacity;
    s->value_capacity = s->value_used + s->key_used + 1;
    KVT(kv_selftest_store_locked(s, &req, "cap", 3, "0123456789", 10) ==
        (NVME_CAP_EXCEEDED | NVME_DNR), "capacity-exceeded-key-value");
    s->value_capacity = saved_cap;
    KVT(kvssd_ftl_max_value(s) == KV_DEFAULT_VALUE_MAX, "value-size-limit");

    /* 6. compaction: force reclaimable, compact, and verify remapped data + GC writes */
    {
        char *big = g_malloc0(s->pgsz * 2);
        uint64_t old_next;

        memset(big, 0x5a, s->pgsz * 2);
        for (int i = 10; i < 40; i++) {
            char k[8]; int kl = snprintf(k, sizeof(k), "k%d", i);
            KVT(kv_selftest_store_locked(s, &req, k, kl, "XX", 3) ==
                NVME_SUCCESS, "overwrite-for-compaction");
        }
        for (int i = 0; i < 4; i++) {
            big[0] = (char)i;
            KVT(kv_selftest_store_locked(s, &req, "hot", 3, big,
                                         s->pgsz * 2) == NVME_SUCCESS,
                "overwrite-hot-compaction");
        }
        saved_cap = s->value_capacity;
        s->value_capacity = s->value_used + s->key_used + 64;
        old_next = s->value_next;
        KVT(kv_selftest_store_locked(s, &req, "cmp", 3, "COMPACT", 8) ==
            NVME_SUCCESS, "store-triggers-compaction");
        {
            int slot = s->index->find(s, (const uint8_t *)"k20", 3, NULL);
            bool ok = slot >= 0 &&
                      memcmp(s->values + s->table[slot].value_off, "XX", 3) == 0 &&
                      s->value_reclaimable == 0 &&
                      s->value_next < old_next;
            KVT(ok, "arena-pack-remap (K-2)");
        }
        s->value_capacity = saved_cap;
        g_free(big);
    }

    /* 7. List structure: start key first, missing start still returns stable keys */
    {
        uint8_t *buf = NULL;
        uint32_t len = 0, nrk = 0;
        uint16_t status = kv_build_list_locked(s, (const uint8_t *)"k20", 3,
                                               64, &buf, &len, &nrk);
        bool ok = status == NVME_SUCCESS && nrk > 0 && len <= 64 &&
                  (len % 4) == 0 && lduw_le_p(buf + 4) == 3 &&
                  memcmp(buf + 6, "k20", 3) == 0;
        g_free(buf);
        KVT(ok, "list-start-key-bytes");

        buf = NULL;
        len = nrk = 0;
        status = kv_build_list_locked(s, (const uint8_t *)"missing", 7,
                                      64, &buf, &len, &nrk);
        ok = status == NVME_SUCCESS && nrk > 0 && len <= 64 && (len % 4) == 0;
        g_free(buf);
        KVT(ok, "list-missing-start-vendor-order");

        buf = NULL;
        len = nrk = 0;
        status = kv_build_list_locked(s, (const uint8_t *)"k20", 3,
                                      8, &buf, &len, &nrk);
        ok = status == NVME_SUCCESS && len <= 8 && (len % 4) == 0;
        g_free(buf);
        KVT(ok, "list-hbs-pad-limit");
    }

    /* 8. Reads charge existing PPAs and do not consume write-pointer pages */
    {
        int slot = s->index->find(s, (const uint8_t *)"k20", 3, NULL);
        uint64_t wr_before = s->nand_wr_pages;
        uint64_t lat = 0;
        bool ok = slot >= 0;

        for (int i = 0; ok && i < 128; i++) {
            ok = kv_read_ppas(s, &req, &s->table[slot],
                              MIN((uint64_t)s->table[slot].length,
                                  (uint64_t)s->pgsz), &lat,
                              req.stime) == NVME_SUCCESS;
        }
        KVT(ok && s->nand_wr_pages == wr_before, "retrieve-no-page-allocation");
    }

    /*
     * 9. Long overwrite run crosses at least one NAND line without
     * allocator abort. Values of a page each program a page; a small value
     * would only stay in the open page.
     */
    {
        uint64_t loops = MIN((uint64_t)s->ssd->sp.pgs_per_line + 32, 20000ull);
        g_autofree char *v = g_malloc0(s->pgsz);
        bool ok = true;

        for (uint64_t i = 0; i < loops; i++) {
            snprintf(v, s->pgsz, "L%05" PRIu64, i);
            if (kv_selftest_store_locked(s, &req, "loop", 4, v, s->pgsz) !=
                NVME_SUCCESS) {
                ok = false;
                break;
            }
        }
        KVT(ok && s->ssd->wp.curline != NULL, "long-overwrite-line-reclaim");
    }

    /*
     * 8. List return buffer: walk it back exactly as a host does (Figure 15 NRK
     * header, then Figure 16 entries) using keys whose lengths are not multiples
     * of 4, so any missing pad desynchronizes the walk on the second entry.
     */
    {
        static const char *lk[] = { "a", "bcd", "ef", "ghijk" };
        uint8_t *lbuf = NULL;
        uint32_t llen = 0, lnrk = 0;
        bool ok;

        kvssd_reset_table(s);
        for (int i = 0; i < 4; i++) {
            KVT(kv_selftest_store_locked(s, &req, lk[i],
                                         (uint8_t)strlen(lk[i]), "v", 1)
                == NVME_SUCCESS, "list-seed-store");
        }
        ok = (kv_build_list_locked(s, NULL, 0, 4096, &lbuf, &llen, &lnrk) ==
              NVME_SUCCESS);
        if (ok) {
            uint32_t pos = 4;
            uint32_t seen = 0;

            ok = (ldl_le_p(lbuf) == 4) && (llen % 4 == 0);
            while (ok && seen < lnrk) {
                uint32_t kl;

                if (pos + 2 > llen) {
                    ok = false;
                    break;
                }
                kl = lduw_le_p(lbuf + pos);
                /* every entry must start 4 byte aligned and carry a sane length */
                ok = (pos % 4 == 0) && kl >= 1 && kl <= FEMU_KVSSD_KEY_MAX &&
                     (pos + 2 + kl) <= llen;
                pos = (pos + 2 + kl + 3) & ~3u;
                seen++;
            }
            ok = ok && seen == 4 && pos == llen;
        }
        g_free(lbuf);
        KVT(ok, "list-entry-4byte-padding");
    }

    qemu_mutex_unlock(&s->lock);

    /* reset state so the self-test does not pollute a real run */
    kvssd_reset_table(s);
    s->nand_rd_pages = 0;
    s->nand_wr_pages = 0;
    s->gc_wr_pages = 0;
    s->gc_lines = 0;
    s->meta_wr_pages = 0;
    s->gc_meta_pages = 0;
    s->gc_stale_pages = 0;
    s->host_bytes = 0;
    s->pack_pages = 0;
    s->pack_values = 0;
    s->pack_pad_bytes = 0;
    s->pack_early = 0;
    s->pack_dropped = 0;
    s->pack_buf_reads = 0;
    s->gc_moved_values = 0;
    s->gc_stale_values = 0;
    s->pack_persist = 0;
    if (n) {
        if (n->ssd == s->ssd) {
            n->ssd = NULL;
        }
        kvssd_free_ssd(s);
        if (!kvssd_init_timing_ssd(s, n, s->ns)) {
            fails++;
            femu_err("KVSELFTEST FAIL reset-timing-ssd\n");
        }
        if (s->meta_wp) {
            memset(s->meta_wp, 0, sizeof(*s->meta_wp));
        }
        if (s->ssd) {
            memset(s->line_live, 0,
                   s->ssd->lm.tt_lines * sizeof(*s->line_live));
        }
    }

    femu_err("KVSELFTEST DONE pass=%d fails=%d\n", npass, fails);
#undef KVT
}

/* a broken owner invariant: say which, and stop, so a test cannot miss it */
static void kv_check_fail(const char *what, uint64_t a, uint64_t b)
{
    error_report("FEMU kvssd: owner check failed: %s (%" PRIu64 ", %" PRIu64
                 ")", what, a, b);
    abort();
}

/*
 * The header of packed page @pg (at @ppa, or the open page with NULL):
 * its counts add up, and each live value is the one its slot names.
 */
static bool kv_check_pack(FemuKvssdState *s, KvPackPage *pg, struct ppa *ppa)
{
    uint64_t bytes = 0;
    uint32_t live = 0;
    uint32_t fill = 0;

    for (uint32_t i = 0; i < pg->nr; i++) {
        KvPackItem *it = &pg->item[i];
        FemuKvssdMappingEntry *e;

        if (it->off != fill) {
            kv_check_fail("packed item offset", it->off, fill);
        }
        fill += kv_pack_rec(it->len);
        if (!it->live) {
            continue;
        }
        live++;
        bytes += kv_pack_rec(it->len);
        e = it->owner < s->hash_slots ? &s->table[it->owner] : NULL;
        if (!e || !e->packed || e->nr_ppas != 1 || e->pack_off != it->off ||
            e->length != it->len ||
            e->ppas[0].ppa != (ppa ? ppa->ppa : KV_PPA_OPEN)) {
            kv_check_fail("packed item owner", it->owner, it->off);
        }
    }
    if (fill != pg->fill || fill > (uint32_t)s->pgsz) {
        kv_check_fail("packed page fill", fill, pg->fill);
    }
    return live == pg->live && bytes == pg->live_bytes && (!ppa || live);
}

/* each line is in one place: free, full, victim queue, open or collected */
static void kv_check_lines(FemuKvssdState *s)
{
    struct line_mgmt *lm = &s->ssd->lm;
    g_autofree uint8_t *seen = g_new0(uint8_t, lm->tt_lines);
    struct line *line;
    int n = 0;

    QTAILQ_FOREACH(line, &lm->free_line_list, entry) {
        if (seen[line->id]++ || line->vpc || line->pos) {
            kv_check_fail("free line", line->id, line->vpc);
        }
        n++;
    }
    QTAILQ_FOREACH(line, &lm->full_line_list, entry) {
        if (seen[line->id]++ || !kv_line_full(s, line)) {
            kv_check_fail("full line", line->id, line->vpc);
        }
        n++;
    }
    for (int i = 0; i < lm->tt_lines; i++) {
        line = &lm->lines[i];
        if (line->pos) {
            if (seen[i]++) {
                kv_check_fail("victim line on two lists", i, line->pos);
            }
            n++;
        }
        if (line->reclaiming) {
            kv_check_fail("line left reclaiming", i, line->vpc);
        }
    }
    for (int i = 0; i < lm->tt_lines; i++) {
        n += !seen[i] && (lm->lines[i].retired || lm->lines[i].spare);
    }
    if (s->ssd->wp.curline && seen[s->ssd->wp.curline->id]++) {
        kv_check_fail("open value line on a list", s->ssd->wp.curline->id, 0);
    }
    n += !!s->ssd->wp.curline;
    if (s->meta_wp && s->meta_wp->curline &&
        seen[s->meta_wp->curline->id]++) {
        kv_check_fail("open meta line on a list", s->meta_wp->curline->id, 0);
    }
    n += s->meta_wp && s->meta_wp->curline;
    if (n != lm->tt_lines) {
        kv_check_fail("lines placed", n, lm->tt_lines);
    }
}

/*
 * Each slot that holds a key has exactly one record, and a free slot none;
 * each meta page a level names is a valid page the tree owns, named once.
 */
static void kv_check_tree(FemuKvssdState *s, uint64_t used)
{
    g_autofree uint8_t *refs = g_new0(uint8_t, s->hash_slots);
    g_autoptr(GHashTable) pages = g_hash_table_new(g_int64_hash,
                                                   g_int64_equal);
    uint64_t recs = 0;

    for (int i = 0; i <= KV_LSM_MAX_LEVELS; i++) {
        KvLsmRun *r = i ? &s->lsm->lvl[i - 1] : &s->lsm->mem;

        for (uint32_t k = 0; k < r->nr; k++) {
            uint32_t slot = r->rec[k].slot;

            if (r->rec[k].dead) {
                continue;
            }
            if (slot >= s->hash_slots || refs[slot]++ ||
                !s->table[slot].key_len) {
                kv_check_fail("record slot", slot, i);
            }
            recs++;
        }
        if (!i || kv_lsm_level_pinned(s->lsm, i)) {
            continue;
        }
        for (uint32_t p = 0; p < r->npg; p++) {
            struct ppa ppa = { .ppa = r->pg[p].id };

            if (!kv_page_owned(s, &ppa, KV_OWNER_META) ||
                g_hash_table_contains(pages, &r->pg[p].id)) {
                kv_check_fail("meta page", r->pg[p].id, i);
            }
            g_hash_table_add(pages, &r->pg[p].id);
        }
    }
    if (recs != used || used + s->nr_free != s->hash_slots) {
        kv_check_fail("records, slots", recs, used);
    }
}

/*
 * FEMU_KV_CHECK: every valid page has the owner rmap names, every owner
 * holds its pages, each line counts its valid pages, and with the LSM tree
 * each slot that holds a key has one record. Called under s->lock.
 */
static void kv_check(FemuKvssdState *s)
{
    struct ssd *ssd = s->ssd;
    struct ssdparams *spp = &ssd->sp;
    uint64_t live = 0;
    uint64_t used = 0;

    if (!s->check) {
        return;
    }
    uint64_t npack = 0;

    for (int blk = 0; blk < spp->blks_per_pl; blk++) {
        struct line *line = &ssd->lm.lines[blk];
        uint64_t vpc = 0;
        uint64_t bytes = 0;
        struct ppa ppa = { .ppa = 0 };

        ppa.g.blk = blk;
        for (int ch = 0; ch < spp->nchs; ch++) {
            for (int lun = 0; lun < spp->luns_per_ch; lun++) {
                for (int pl = 0; pl < spp->pls_per_lun; pl++) {
                    for (int pg = 0; pg < spp->pgs_per_blk; pg++) {
                        uint64_t owner;
                        bool held = false;

                        ppa.g.ch = ch;
                        ppa.g.lun = lun;
                        ppa.g.pl = pl;
                        ppa.g.pg = pg;
                        if (get_pg(ssd, &ppa)->status != PG_VALID) {
                            continue;
                        }
                        vpc++;
                        owner = get_rmap_ent(ssd, &ppa);
                        if (owner == KV_OWNER_PACK) {
                            KvPackPage *pk = kv_pack_page(s, ppa.ppa);

                            held = pk && kv_check_pack(s, pk, &ppa);
                            bytes += held ? pk->live_bytes : 0;
                            npack++;
                        } else if (owner == KV_OWNER_META) {
                            held = s->lsm && kv_lsm_relocate(s->lsm, ppa.ppa,
                                                             ppa.ppa);
                        } else if (owner < s->hash_slots) {
                            FemuKvssdMappingEntry *e = &s->table[owner];

                            for (uint32_t i = 0; i < e->nr_ppas; i++) {
                                held |= e->ppas[i].ppa == ppa.ppa;
                            }
                        }
                        if (!held) {
                            kv_check_fail("valid page with no holder",
                                          ppa.ppa, owner);
                        }
                        if (owner != KV_OWNER_PACK) {
                            bytes += s->pgsz;
                        }
                    }
                }
            }
        }
        if (vpc != (uint64_t)line->vpc) {
            kv_check_fail("line valid count", vpc, line->vpc);
        }
        if (bytes != s->line_live[blk]) {
            kv_check_fail("line live bytes", bytes, s->line_live[blk]);
        }
    }
    if (npack != g_hash_table_size(s->packed)) {
        kv_check_fail("packed page headers", npack,
                      g_hash_table_size(s->packed));
    }
    if (s->open && (s->open->id != KV_PACK_NO_PAGE ||
                    !kv_check_pack(s, s->open, NULL))) {
        kv_check_fail("open page", s->open->nr, s->open->live);
    }
    for (uint32_t i = 0; i < s->hash_slots; i++) {
        FemuKvssdMappingEntry *e = &s->table[i];
        KvPackPage *pk;

        if (e->packed && (e->nr_ppas != 1 || !s->pack ||
                          (e->ppas[0].ppa != UNMAPPED_PPA &&
                           kv_pack_owned(s, e, i, &pk) < 0))) {
            kv_check_fail("packed value not owned", i, e->ppas[0].ppa);
        }
        for (uint32_t k = 0; !e->packed && k < e->nr_ppas; k++) {
            if (e->ppas[k].ppa != UNMAPPED_PPA &&
                !kv_page_owned(s, &e->ppas[k], i)) {
                kv_check_fail("entry page not owned", i, e->ppas[k].ppa);
            }
        }
        if (!e->key_len) {
            continue;
        }
        used++;
        if (!e->stale) {
            /* a live value holds every page of its length */
            if (e->nr_ppas != kv_value_pages(s, e->length) ||
                e->packed != kv_packs(s, e->length)) {
                kv_check_fail("live value pages", i, e->nr_ppas);
            }
            for (uint32_t k = 0; k < e->nr_ppas; k++) {
                if (e->ppas[k].ppa == UNMAPPED_PPA) {
                    kv_check_fail("live value lost a page", i, k);
                }
            }
            live++;
        }
        if (s->lsm) {
            uint32_t slot;
            bool newest = kv_lsm_get(s->lsm, e->key, e->key_len, &slot,
                                     false) && slot == i;

            if (newest == e->stale) {
                kv_check_fail("stale flag disagrees with the tree", i,
                              e->stale);
            }
        }
    }
    if (live != s->nr_entries) {
        kv_check_fail("live keys", live, s->nr_entries);
    }
    kv_check_lines(s);
    if (s->lsm) {
        kv_check_tree(s, used);
    }
}

bool kvssd_ftl_lsm_snap(FemuKvssdState *s, FemuKvLsmSnap *snap)
{
    KvLsm *l;

    memset(snap, 0, sizeof(*snap));
    qemu_mutex_lock(&s->lock);
    l = s->lsm;
    if (!l) {
        qemu_mutex_unlock(&s->lock);
        return false;
    }
    snap->memtable_keys = l->mem.nr;
    snap->memtable_cap = l->mem_cap;
    snap->ratio = l->ratio;
    snap->pinned = l->pinned;
    snap->per_page = l->per_page;
    snap->dram_bytes = kv_lsm_dram_bytes(l);
    snap->depth = kv_lsm_depth(l);
    for (int i = 1; i <= snap->depth; i++) {
        snap->records[i - 1] = l->lvl[i - 1].nr;
        snap->capacity[i - 1] = kv_lsm_level_cap(l, i);
        snap->pages[i - 1] = l->lvl[i - 1].npg;
        if (!kv_lsm_level_pinned(l, i)) {
            snap->meta_flash_bytes += (uint64_t)l->lvl[i - 1].npg * s->pgsz;
        }
    }
    snap->flushes = l->flushes;
    snap->compactions = l->compactions;
    snap->dropped = l->dropped;
    snap->reinserted = l->reinserted;
    memcpy(snap->io, l->pages, sizeof(snap->io));
    snap->versions = s->hash_slots - s->nr_free;
    snap->gc_meta_pages = s->gc_meta_pages;
    snap->gc_stale_pages = s->gc_stale_pages;
    /* every valid page is a value page or a meta page a level names */
    for (int i = 0; i < s->ssd->lm.tt_lines; i++) {
        snap->valid_value_pages += s->ssd->lm.lines[i].vpc;
    }
    for (int i = 1; i <= KV_LSM_MAX_LEVELS; i++) {
        if (!kv_lsm_level_pinned(l, i)) {
            snap->valid_value_pages -= l->lvl[i - 1].npg;
        }
    }
    qemu_mutex_unlock(&s->lock);
    return true;
}

bool kvssd_ftl_pack_snap(FemuKvssdState *s, FemuKvPackSnap *snap)
{
    GHashTableIter it;
    gpointer k, v;

    memset(snap, 0, sizeof(*snap));
    qemu_mutex_lock(&s->lock);
    if (!s->pack) {
        qemu_mutex_unlock(&s->lock);
        return false;
    }
    snap->header_bytes = KV_PACK_HDR;
    if (s->open) {
        snap->open_bytes = s->open->fill;
        snap->open_values = s->open->live;
    }
    snap->pages = s->pack_pages;
    snap->values = s->pack_values;
    g_hash_table_iter_init(&it, s->packed);
    while (g_hash_table_iter_next(&it, &k, &v)) {
        snap->flash_pages++;
        snap->flash_live_bytes += ((KvPackPage *)v)->live_bytes;
    }
    snap->pad_bytes = s->pack_pad_bytes;
    snap->early = s->pack_early;
    snap->dropped = s->pack_dropped;
    snap->buf_reads = s->pack_buf_reads;
    snap->gc_moved = s->gc_moved_values;
    snap->gc_stale = s->gc_stale_values;
    snap->host_bytes = s->host_bytes;
    qemu_mutex_unlock(&s->lock);
    return true;
}

void kvssd_ftl_free(FemuKvssdState *s)
{
    if (!s) {
        return;
    }
    qemu_mutex_destroy(&s->lock);
    kvssd_reset_table(s);
    kv_tree_free(s);
    g_hash_table_destroy(s->packed);
    g_free(s->line_live);
    g_free(s->values);
    g_free(s->table);
    kvssd_free_ssd(s);
    g_free(s);
}
