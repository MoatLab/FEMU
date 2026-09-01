#include "qemu/osdep.h"
#include "qapi/error.h"

#include "kvssd.h"
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

static uint16_t kv_hash_upsert(FemuKvssdState *s, const uint8_t *key, uint8_t kl,
                               uint64_t off, uint64_t len, struct ppa *ppas,
                               uint32_t nr_ppas)
{
    uint32_t home = kv_fnv1a(key, kl) % s->hash_slots;

    for (uint32_t i = 0; i < s->hash_slots; i++) {
        uint32_t slot = (home + i) % s->hash_slots;
        FemuKvssdMappingEntry *e = &s->table[slot];
        if (e->key_len != 0 && kv_key_eq(e, key, kl)) {
            e->value_off = off;        /* update in place */
            e->length = len;
            e->ppas = ppas;
            e->nr_ppas = nr_ppas;
            return NVME_SUCCESS;
        }
        if (e->key_len == 0) {         /* first free slot in the probe run */
            if (s->kv_max_keys && s->nr_entries >= s->kv_max_keys) {
                return NVME_CAP_EXCEEDED | NVME_DNR;
            }
            memcpy(e->key, key, kl);
            e->key_len = kl;
            e->value_off = off;
            e->length = len;
            e->ppas = ppas;
            e->nr_ppas = nr_ppas;
            s->nr_entries++;
            return NVME_SUCCESS;
        }
    }
    return NVME_CAP_EXCEEDED | NVME_DNR;  /* table full */
}

static bool kv_hash_remove(FemuKvssdState *s, const uint8_t *key, uint8_t kl)
{
    int slot = kv_hash_find(s, key, kl, NULL);
    uint32_t hole, next;

    if (slot < 0) {
        return false;
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
            hole = next;
        }
        next = (next + 1) % s->hash_slots;
    }
    s->nr_entries--;
    return true;
}

static const FemuKvIndexOps kv_index_hash = {
    .name   = "hash",
    .find   = kv_hash_find,
    .upsert = kv_hash_upsert,
    .remove = kv_hash_remove,
    .probe_reads = NULL,               /* DRAM-resident hash: 0 flash reads */
};

/* --- value-space placement + NAND timing --- */

static uint32_t kv_value_pages(FemuKvssdState *s, uint64_t bytes)
{
    return bytes ? DIV_ROUND_UP(bytes, (uint64_t)s->pgsz) : 0;
}

static uint64_t kv_reclaim_empty_lines(FemuKvssdState *s, NvmeRequest *req)
{
    struct ssd *ssd = s->ssd;
    struct ssdparams *spp = &ssd->sp;
    struct line_mgmt *lm = &ssd->lm;
    uint64_t lat = 0;
    struct nand_cmd c = {
        .type = GC_IO,
        .cmd = NAND_ERASE,
        .stime = req ? req->stime : 0,
    };

    for (;;) {
        struct line *line = pqueue_peek(lm->victim_line_pq);
        struct ppa ppa = { .ppa = 0 };

        if (!line || line->vpc != 0) {
            break;
        }
        line = pqueue_pop(lm->victim_line_pq);
        line->pos = 0;
        lm->victim_line_cnt--;
        ppa.g.blk = line->id;

        for (int ch = 0; ch < spp->nchs; ch++) {
            for (int lun = 0; lun < spp->luns_per_ch; lun++) {
                struct nand_lun *lunp;
                struct ppa ppas[1 << PL_BITS];
                uint64_t sub;

                ppa.g.ch = ch;
                ppa.g.lun = lun;
                ppa.g.pl = 0;
                lunp = get_lun(ssd, &ppa);
                for (int pl = 0; pl < spp->pls_per_lun; pl++) {
                    ppa.g.pl = pl;
                    ppa.g.pg = 0;
                    mark_block_free(ssd, &ppa);
                    ppas[pl] = ppa;
                }
                /* same block on every plane: one erase, not one per plane */
                sub = ssd_advance_status_multiplane(ssd, ppas, spp->pls_per_lun,
                                                    &c);
                lat = sub > lat ? sub : lat;
                lunp->gc_endtime = lunp->next_lun_avail_time;
            }
        }
        mark_line_free(ssd, &ppa);
    }
    return lat;
}

static void kv_reset_write_pointer(struct write_pointer *wpp, struct line *line)
{
    wpp->curline = line;
    wpp->ch = 0;
    wpp->lun = 0;
    wpp->pg = 0;
    wpp->blk = line->id;
    wpp->pl = 0;
}

static bool kv_ensure_write_pointer(FemuKvssdState *s, NvmeRequest *req,
                                    uint64_t *lat)
{
    struct ssd *ssd = s->ssd;
    struct line *line;

    if (ssd->wp.curline) {
        return true;
    }
    if (lat) {
        *lat += kv_reclaim_empty_lines(s, req);
    } else {
        kv_reclaim_empty_lines(s, req);
    }
    line = get_next_free_line(ssd);
    if (!line) {
        return false;
    }
    kv_reset_write_pointer(&ssd->wp, line);
    return true;
}

static uint64_t kv_write_pointer_remaining(FemuKvssdState *s)
{
    struct ssd *ssd = s->ssd;
    struct ssdparams *spp = &ssd->sp;
    struct write_pointer *wpp = &ssd->wp;
    uint64_t stride = (uint64_t)spp->nchs * spp->luns_per_ch;
    uint64_t idx;

    if (!wpp->curline) {
        return 0;
    }
    idx = (uint64_t)wpp->pg * stride +
          (uint64_t)wpp->lun * spp->nchs + wpp->ch;
    return idx < (uint64_t)spp->pgs_per_line ?
           (uint64_t)spp->pgs_per_line - idx : 0;
}

static uint64_t kv_physical_pages_available(FemuKvssdState *s, NvmeRequest *req,
                                            uint64_t *lat)
{
    struct ssd *ssd = s->ssd;
    uint64_t avail;

    if (lat) {
        *lat += kv_reclaim_empty_lines(s, req);
    } else {
        kv_reclaim_empty_lines(s, req);
    }
    avail = kv_write_pointer_remaining(s);
    avail += (uint64_t)ssd->lm.free_line_cnt * ssd->sp.pgs_per_line;
    return avail;
}

static bool kv_advance_write_pointer(FemuKvssdState *s, NvmeRequest *req,
                                     uint64_t *lat, bool need_next)
{
    struct ssd *ssd = s->ssd;
    struct ssdparams *spp = &ssd->sp;
    struct write_pointer *wpp = &ssd->wp;
    struct line_mgmt *lm = &ssd->lm;

    check_addr(wpp->ch, spp->nchs);
    wpp->ch++;
    if (wpp->ch != spp->nchs) {
        return true;
    }
    wpp->ch = 0;

    check_addr(wpp->lun, spp->luns_per_ch);
    wpp->lun++;
    if (wpp->lun != spp->luns_per_ch) {
        return true;
    }
    wpp->lun = 0;

    check_addr(wpp->pg, spp->pgs_per_blk);
    wpp->pg++;
    if (wpp->pg != spp->pgs_per_blk) {
        return true;
    }

    wpp->pg = 0;
    wpp->curline->close_time = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    if (wpp->curline->vpc == spp->pgs_per_line) {
        ftl_assert(wpp->curline->ipc == 0);
        QTAILQ_INSERT_TAIL(&lm->full_line_list, wpp->curline, entry);
        lm->full_line_cnt++;
    } else {
        ftl_assert(wpp->curline->ipc > 0);
        pqueue_insert(lm->victim_line_pq, wpp->curline);
        lm->victim_line_cnt++;
    }

    wpp->curline = NULL;
    if (lat) {
        *lat += kv_reclaim_empty_lines(s, req);
    } else {
        kv_reclaim_empty_lines(s, req);
    }
    if (!need_next && ssd->lm.free_line_cnt == 0) {
        return true;
    }
    return kv_ensure_write_pointer(s, req, lat);
}

static void kv_invalidate_ppa_array(FemuKvssdState *s, struct ppa *ppas,
                                    uint32_t nr_ppas)
{
    for (uint32_t i = 0; i < nr_ppas; i++) {
        struct ppa ppa = ppas[i];

        if (valid_ppa(s->ssd, &ppa) && get_pg(s->ssd, &ppa)->status == PG_VALID) {
            mark_page_invalid(s->ssd, &ppa);
        }
    }
}

static void kv_discard_value_ppas(FemuKvssdState *s, FemuKvssdMappingEntry *e)
{
    kv_invalidate_ppa_array(s, e->ppas, e->nr_ppas);
    kv_entry_drop_ppas(e);
}

static uint16_t kv_program_ppas(FemuKvssdState *s, NvmeRequest *req,
                                uint64_t bytes, int io_type, struct ppa **out,
                                uint32_t *out_nr, uint64_t *lat)
{
    struct ssd *ssd = s->ssd;
    uint32_t pages = kv_value_pages(s, bytes);
    struct ppa *ppas = NULL;
    struct nand_cmd c = {
        .type = io_type,
        .cmd = NAND_WRITE,
        .stime = req->stime,
    };

    *out = NULL;
    *out_nr = 0;
    if (!pages) {
        return NVME_SUCCESS;
    }
    if (kv_physical_pages_available(s, req, lat) < pages) {
        return NVME_CAP_EXCEEDED | NVME_DNR;
    }

    ppas = g_try_new0(struct ppa, pages);
    if (!ppas) {
        return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }

    for (uint32_t i = 0; i < pages; i++) {
        struct ppa ppa;
        uint64_t sub;

        if (!kv_ensure_write_pointer(s, req, lat)) {
            kv_invalidate_ppa_array(s, ppas, i);
            g_free(ppas);
            return NVME_CAP_EXCEEDED | NVME_DNR;
        }

        ppa = get_new_page(ssd);
        mark_page_valid(ssd, &ppa);
        sub = ssd_advance_status(ssd, &ppa, &c);
        *lat = sub > *lat ? sub : *lat;
        ppas[i] = ppa;
        if (io_type == GC_IO) {
            s->gc_wr_pages++;
        } else {
            s->nand_wr_pages++;
        }

        if (!kv_advance_write_pointer(s, req, lat, i + 1 < pages)) {
            kv_invalidate_ppa_array(s, ppas, i + 1);
            g_free(ppas);
            return NVME_CAP_EXCEEDED | NVME_DNR;
        }
    }

    *out = ppas;
    *out_nr = pages;
    return NVME_SUCCESS;
}

static uint16_t kv_read_ppas(FemuKvssdState *s, NvmeRequest *req,
                             const FemuKvssdMappingEntry *e, uint64_t bytes,
                             uint64_t *lat)
{
    uint32_t pages = kv_value_pages(s, bytes);
    struct nand_cmd c = {
        .type = USER_IO,
        .cmd = NAND_READ,
        .stime = req->stime,
    };

    if (pages > e->nr_ppas) {
        return NVME_KV_UNRECOVERED_ERROR | NVME_DNR;
    }
    for (uint32_t i = 0; i < pages; i++) {
        struct ppa ppa = e->ppas[i];
        uint64_t sub;

        if (!valid_ppa(s->ssd, &ppa) || get_pg(s->ssd, &ppa)->status != PG_VALID) {
            return NVME_KV_UNRECOVERED_ERROR | NVME_DNR;
        }
        sub = ssd_advance_status(s->ssd, &ppa, &c);
        *lat = sub > *lat ? sub : *lat;
        s->nand_rd_pages++;
    }
    return NVME_SUCCESS;
}

/* fixed-cost per-command controller/index base latency so metadata-only ops
 * (exist/delete/miss) are never free. One NAND-page-read worth on the current
 * geometry, charged via the media model on a synthetic ppa (no write pointer
 * advance, no page marked valid -- a base cost, not real placement). */
static uint64_t kv_charge_base(FemuKvssdState *s, NvmeRequest *req)
{
    struct ssd *ssd = s->ssd;
    struct nand_cmd c = { .type = USER_IO, .cmd = NAND_READ, .stime = req->stime };
    struct ppa ppa = { .ppa = 0 };
    return ssd_advance_status(ssd, &ppa, &c);
}

/* index-probe latency: a flash-resident index (probe_reads>0) pays N page reads
 * on the index structure; a DRAM-resident index (hash) pays nothing extra. Models
 * reads via ssd_advance_status on a synthetic ppa -- no data write pointer advance
 * and no page marked valid (those would consume value-space placement). */
static uint64_t kv_charge_index(FemuKvssdState *s, NvmeRequest *req,
                                const uint8_t *key, uint8_t kl)
{
    int reads = (s->index->probe_reads && key) ?
                s->index->probe_reads(s, key, kl) : 0;
    struct ssd *ssd = s->ssd;
    struct nand_cmd c = { .type = USER_IO, .cmd = NAND_READ, .stime = req->stime };
    uint64_t maxlat = 0;

    for (int i = 0; i < reads; i++) {
        struct ppa ppa = { .ppa = 0 };
        uint64_t sub = ssd_advance_status(ssd, &ppa, &c);
        maxlat = sub > maxlat ? sub : maxlat;
    }
    return maxlat;
}

static void kv_apply_lat(NvmeRequest *req, uint64_t lat)
{
    req->reqlat += lat;
    req->expire_time += lat;
}

static int kv_entry_value_off_cmp(const void *a, const void *b)
{
    const FemuKvssdMappingEntry *ea = *(FemuKvssdMappingEntry **)a;
    const FemuKvssdMappingEntry *eb = *(FemuKvssdMappingEntry **)b;

    return (ea->value_off > eb->value_off) - (ea->value_off < eb->value_off);
}

/*
 * Real value-log compaction: walk live index entries, copy their value bytes down
 * to a fresh frontier in old-offset order, and update each entry's value_off.
 * Charges the relocated live pages as GC writes through the NAND model. Called
 * with the lock held when the append frontier cannot fit a new value but dead
 * space exists.
 */
static bool kv_compact(FemuKvssdState *s, NvmeRequest *req)
{
    uint64_t frontier = 0;
    uint64_t live_bytes = 0;
    uint64_t lat = 0;
    uint64_t live_pages = 0;
    uint32_t live_nr = 0;
    FemuKvssdMappingEntry **live;

    live = g_try_new(FemuKvssdMappingEntry *, s->nr_entries);
    if (!live && s->nr_entries) {
        return false;
    }
    for (uint32_t i = 0; i < s->hash_slots; i++) {
        FemuKvssdMappingEntry *e = &s->table[i];
        if (e->key_len == 0) {
            continue;
        }
        live[live_nr++] = e;
        live_bytes += e->length;
        live_pages += kv_value_pages(s, e->length);
    }
    if (kv_physical_pages_available(s, req, &lat) < live_pages) {
        g_free(live);
        return false;
    }
    qsort(live, live_nr, sizeof(*live), kv_entry_value_off_cmp);

    for (uint32_t i = 0; i < live_nr; i++) {
        FemuKvssdMappingEntry *e = live[i];
        FemuKvssdMappingEntry old;
        struct ppa *new_ppas = NULL;
        uint32_t new_nr_ppas = 0;
        uint16_t status;

        old = *e;
        status = kv_program_ppas(s, req, e->length, GC_IO, &new_ppas,
                                 &new_nr_ppas, &lat);
        if (status) {
            g_free(live);
            return false;
        }
        if (e->length && e->value_off != frontier) {
            memmove(s->values + frontier, s->values + e->value_off, e->length);
        }
        e->value_off = frontier;
        e->ppas = new_ppas;
        e->nr_ppas = new_nr_ppas;
        kv_discard_value_ppas(s, &old);
        frontier += e->length;
    }
    g_free(live);
    kv_apply_lat(req, lat);

    s->value_next = frontier;
    s->value_reclaimable = 0;
    ftl_assert(live_bytes == frontier);
    return true;
}

/*
 * Allocate value space (log-append). If the append frontier cannot fit and there
 * is reclaimable dead space, compact first. Returns false only if even compacted
 * live data plus the new value would exceed capacity (true Capacity Exceeded).
 */
static bool kv_value_alloc(FemuKvssdState *s, NvmeRequest *req, uint64_t len,
                           uint64_t *off)
{
    if (s->value_next <= s->value_capacity &&
        len <= s->value_capacity - s->value_next) {
        *off = s->value_next;
        s->value_next += len;
        return true;
    }
    if (s->value_reclaimable > 0) {
        if (!kv_compact(s, req)) {
            return false;
        }
        if (s->value_next <= s->value_capacity &&
            len <= s->value_capacity - s->value_next) {
            *off = s->value_next;
            s->value_next += len;
            return true;
        }
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

uint16_t kvssd_ftl_exist(FemuCtrl *n, FemuKvssdState *s, NvmeRequest *req,
                         const uint8_t *key, uint8_t kl)
{
    uint64_t lat;
    bool found;

    (void)n;
    qemu_mutex_lock(&s->lock);
    found = s->index->find(s, key, kl, NULL) >= 0;
    lat = kv_charge_base(s, req) + kv_charge_index(s, req, key, kl);
    qemu_mutex_unlock(&s->lock);
    kv_apply_lat(req, lat);
    return found ? NVME_SUCCESS : (NVME_KV_KEY_NOT_EXIST | NVME_DNR);
}

uint16_t kvssd_ftl_store(FemuCtrl *n, FemuKvssdState *s, NvmeRequest *req,
                         const uint8_t *key, uint8_t kl, uint32_t vsize,
                         uint64_t prp1, uint64_t prp2, bool sike, bool sinke)
{
    uint64_t off;
    uint64_t lat = 0;
    uint16_t status;
    int existing;
    FemuKvssdMappingEntry old = {};
    struct ppa *new_ppas = NULL;
    uint32_t new_nr_ppas = 0;
    (void)n;

    qemu_mutex_lock(&s->lock);

    existing = s->index->find(s, key, kl, NULL);
    if (sike && existing < 0) {
        lat = kv_charge_base(s, req) + kv_charge_index(s, req, key, kl);
        qemu_mutex_unlock(&s->lock);
        kv_apply_lat(req, lat);
        return NVME_KV_KEY_NOT_EXIST | NVME_DNR;
    }
    if (sinke && existing >= 0) {
        lat = kv_charge_base(s, req) + kv_charge_index(s, req, key, kl);
        qemu_mutex_unlock(&s->lock);
        kv_apply_lat(req, lat);
        return NVME_KV_KEY_EXISTS | NVME_DNR;
    }
    if (existing < 0 && ((s->kv_max_keys && s->nr_entries >= s->kv_max_keys) ||
                         s->nr_entries >= s->hash_slots)) {
        lat = kv_charge_base(s, req) + kv_charge_index(s, req, key, kl);
        qemu_mutex_unlock(&s->lock);
        kv_apply_lat(req, lat);
        return NVME_CAP_EXCEEDED | NVME_DNR;
    }
    if (existing >= 0) {
        old = s->table[existing];
    }
    if (!kv_logical_capacity_ok(s, existing >= 0 ? &old : NULL, kl, vsize)) {
        lat = kv_charge_base(s, req) + kv_charge_index(s, req, key, kl);
        qemu_mutex_unlock(&s->lock);
        kv_apply_lat(req, lat);
        return NVME_CAP_EXCEEDED | NVME_DNR;
    }

    if (!kv_value_alloc(s, req, vsize, &off)) {
        qemu_mutex_unlock(&s->lock);
        return NVME_CAP_EXCEEDED | NVME_DNR;
    }

    if (vsize) {
        /* DMA held under the lock: the arena slot [off,off+vsize) is reserved on
         * the append frontier and a concurrent compaction could relocate it, so
         * the copy must be atomic with the allocation. */
        status = dma_write_prp(n, s->values + off, vsize, prp1, prp2);
        if (status) {
            s->value_next = off;            /* roll back the append */
            qemu_mutex_unlock(&s->lock);
            return status;
        }
    }

    status = kv_program_ppas(s, req, vsize, USER_IO, &new_ppas, &new_nr_ppas,
                             &lat);
    if (status) {
        s->value_next = off;
        qemu_mutex_unlock(&s->lock);
        return status;
    }

    existing = s->index->find(s, key, kl, NULL);
    if (existing >= 0) {
        old = s->table[existing];
    }
    status = s->index->upsert(s, key, kl, off, vsize, new_ppas, new_nr_ppas);
    if (status) {
        kv_invalidate_ppa_array(s, new_ppas, new_nr_ppas);
        g_free(new_ppas);
        s->value_next = off;
        qemu_mutex_unlock(&s->lock);
        return status;
    }
    if (existing >= 0) {
        kv_discard_value_ppas(s, &old);
        s->value_reclaimable += old.length;
        if (s->value_used >= old.length) {
            s->value_used -= old.length;
        }
        if (s->key_used >= old.key_len) {
            s->key_used -= old.key_len;
        }
    }
    s->value_used += vsize;
    s->key_used += kl;

    /* command/index base cost + value-page program timing through the NAND model */
    lat += kv_charge_base(s, req);
    lat += kv_charge_index(s, req, key, kl);

    qemu_mutex_unlock(&s->lock);
    kv_apply_lat(req, lat);
    return NVME_SUCCESS;
}

uint16_t kvssd_ftl_retrieve(FemuCtrl *n, FemuKvssdState *s, NvmeRequest *req,
                            const uint8_t *key, uint8_t kl, uint32_t hbs,
                            uint64_t prp1, uint64_t prp2, uint32_t *full_len)
{
    int slot;
    uint64_t off, vlen, xfer, lat = 0;
    uint16_t status;
    (void)n;

    qemu_mutex_lock(&s->lock);
    slot = s->index->find(s, key, kl, NULL);
    if (slot < 0) {
        lat = kv_charge_base(s, req) + kv_charge_index(s, req, key, kl);
        qemu_mutex_unlock(&s->lock);
        kv_apply_lat(req, lat);
        *full_len = 0;
        return NVME_KV_KEY_NOT_EXIST | NVME_DNR;
    }
    off = s->table[slot].value_off;
    vlen = s->table[slot].length;
    xfer = MIN(vlen, hbs);              /* spec: return min(HBS, value) bytes */
    *full_len = (uint32_t)vlen;         /* but report the FULL size in CQE Dword0 */

    /* base + read of the value pages actually touched (the transferred span) */
    lat += kv_charge_base(s, req);
    status = kv_read_ppas(s, req, &s->table[slot], xfer, &lat);
    if (status) {
        qemu_mutex_unlock(&s->lock);
        return status;
    }
    lat += kv_charge_index(s, req, key, kl);
    if (xfer) {
        status = dma_read_prp(n, s->values + off, (uint32_t)xfer, prp1, prp2);
        if (status) {
            qemu_mutex_unlock(&s->lock);
            return status;
        }
    }

    qemu_mutex_unlock(&s->lock);
    kv_apply_lat(req, lat);
    return NVME_SUCCESS;
}

bool kvssd_ftl_delete(FemuCtrl *n, FemuKvssdState *s, NvmeRequest *req,
                      const uint8_t *key, uint8_t kl)
{
    int slot;
    bool removed;
    uint64_t lat;
    FemuKvssdMappingEntry old = {};
    (void)n;

    qemu_mutex_lock(&s->lock);
    slot = s->index->find(s, key, kl, NULL);
    if (slot >= 0) {
        old = s->table[slot];
    }
    removed = s->index->remove(s, key, kl);
    if (removed) {
        kv_discard_value_ppas(s, &old);
        s->value_reclaimable += old.length;
        if (s->value_used >= old.length) {
            s->value_used -= old.length;
        }
        if (s->key_used >= old.key_len) {
            s->key_used -= old.key_len;
        }
    }
    lat = kv_charge_base(s, req) + kv_charge_index(s, req, key, kl); /* metadata */
    qemu_mutex_unlock(&s->lock);

    kv_apply_lat(req, lat);
    return removed;
}

static uint16_t kv_build_list_locked(FemuKvssdState *s, const uint8_t *start_key,
                                     uint8_t start_len, uint32_t hbs,
                                     uint8_t **out, uint32_t *out_len,
                                     uint32_t *out_nrk)
{
    uint8_t *buf;
    uint32_t cap = hbs;
    uint32_t pos = 4;                  /* leave room for the NRK header */
    uint32_t nrk = 0;
    uint32_t start_slot = 0;
    int slot;

    if (cap < 4) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    buf = g_try_malloc0(cap);
    if (!buf) {
        return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
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
        uint32_t need;
        uint32_t padded;

        if (kv_entry_empty(e)) {
            continue;
        }
        need = 2 + e->key_len;
        /*
         * Figure 16: a key data structure is padded to end on a 4 byte boundary,
         * so the next entry begins at the padded offset rather than immediately
         * after the key. Advancing by the unpadded length would misalign every
         * following entry and desynchronize a host walking the list. Only whole
         * keys that fit in the host buffer are returned.
         */
        padded = (pos + need + 3) & ~3u;
        if (padded > cap) {
            break;
        }
        stw_le_p(buf + pos, e->key_len);
        memcpy(buf + pos + 2, e->key, e->key_len);
        pos = padded;                  /* buf is zeroed, so the pad is zero */
        nrk++;
    }
    stl_le_p(buf, nrk);                /* Number of Returned Keys header */
    *out = buf;
    *out_len = pos;                    /* already 4 byte aligned by the pad */
    *out_nrk = nrk;
    return NVME_SUCCESS;
}

uint16_t kvssd_ftl_list(FemuCtrl *n, FemuKvssdState *s, NvmeRequest *req,
                        const uint8_t *start_key, uint8_t start_len, uint32_t hbs,
                        uint64_t prp1, uint64_t prp2)
{
    uint8_t *buf = NULL;
    uint32_t len = 0;
    uint32_t nrk = 0;
    uint16_t status;
    uint64_t lat;
    (void)n;

    qemu_mutex_lock(&s->lock);
    status = kv_build_list_locked(s, start_key, start_len, hbs, &buf, &len, &nrk);
    if (status) {
        qemu_mutex_unlock(&s->lock);
        return status;
    }
    lat = kv_charge_base(s, req) + kv_charge_index(s, req, NULL, 0);
    qemu_mutex_unlock(&s->lock);

    status = dma_read_prp(n, buf, len, prp1, prp2);
    g_free(buf);
    if (status) {
        return status;
    }
    kv_apply_lat(req, lat);
    return NVME_SUCCESS;
}

/* --- lifecycle --- */

static void kvssd_reset_table(FemuKvssdState *s)
{
    for (uint32_t i = 0; i < s->hash_slots; i++) {
        kv_entry_drop_ppas(&s->table[i]);
        kv_entry_clear(&s->table[i]);
    }
    s->nr_entries = 0;
    s->value_next = 0;
    s->value_used = 0;
    s->key_used = 0;
    s->value_reclaimable = 0;
}

static void kvssd_free_ru_mgmt(struct ru_mgmt *rm)
{
    if (!rm) {
        return;
    }
    if (rm->victim_ru_pq) {
        pqueue_free(rm->victim_ru_pq);
    }
    if (rm->victim_ru_cb) {
        pqueue_free(rm->victim_ru_cb);
    }
    g_free(rm);
}

static void kvssd_free_fdp_state(struct ssd *ssd)
{
    if (ssd->ruhs) {
        for (uint64_t i = 0; i < ssd->nruhs; i++) {
            g_free(ssd->ruhs[i].rus);
            kvssd_free_ru_mgmt(ssd->ruhs[i].ru_mgmt);
        }
        g_free(ssd->ruhs);
    }
    if (ssd->rg) {
        for (uint64_t i = 0; i < ssd->nrg; i++) {
            FemuReclaimGroup *rg = &ssd->rg[i];

            if (rg->rus) {
                for (int j = 0; j < rg->tt_nru; j++) {
                    g_free(rg->rus[j].ssd_wptr);
                    g_free(rg->rus[j].lines);
                }
            }
            kvssd_free_ru_mgmt(rg->ru_mgmt);
        }
        if (ssd->rus) {
            for (uint64_t i = 0; i < ssd->nrg; i++) {
                g_free(ssd->rus[i]);
            }
            g_free(ssd->rus);
        }
        g_free(ssd->rg);
    }
}

static void kvssd_free_ssd(FemuKvssdState *s)
{
    struct ssd *ssd = s->ssd;
    struct ssdparams *spp;

    if (!ssd) {
        return;
    }
    spp = &ssd->sp;
    kvssd_free_fdp_state(ssd);
    g_free(ssd->cmt.slots);
    g_free(ssd->cmt.hash);
    g_free(ssd->rcache.slots);
    g_free(ssd->rcache.hash);
    g_free(ssd->map_priv);
    if (ssd->lm.victim_line_pq) {
        pqueue_free(ssd->lm.victim_line_pq);
    }
    g_free(ssd->lm.lines);
    g_free(ssd->maptbl);
    g_free(ssd->rmap);
    if (ssd->ch) {
        for (int ch = 0; ch < spp->nchs; ch++) {
            for (int lun = 0; lun < ssd->ch[ch].nluns; lun++) {
                struct nand_lun *lunp = &ssd->ch[ch].lun[lun];

                for (int pl = 0; pl < lunp->npls; pl++) {
                    struct nand_plane *plane = &lunp->pl[pl];

                    for (int blk = 0; blk < plane->nblks; blk++) {
                        struct nand_block *block = &plane->blk[blk];

                        for (int pg = 0; pg < block->npgs; pg++) {
                            g_free(block->pg[pg].sec);
                        }
                        g_free(block->pg);
                    }
                    g_free(plane->blk);
                }
                g_free(lunp->pl);
            }
            g_free(ssd->ch[ch].lun);
        }
        g_free(ssd->ch);
    }
    g_free(ssd);
    s->ssd = NULL;
}

static bool kvssd_init_timing_ssd(FemuKvssdState *s, FemuCtrl *n)
{
    NvmeNamespace *ns = &n->namespaces[0];
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

FemuKvssdState *kvssd_ftl_alloc(FemuCtrl *n, NvmeNamespace *ns, Error **errp)
{
    FemuKvssdState *s = g_try_new0(FemuKvssdState, 1);
    uint64_t cap;
    uint32_t slots;

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
    s->kv_max_keys = 0;                /* unlimited (bounded by capacity) */
    s->ednek = false;                 /* spec default: delete-missing succeeds */

    /*
     * NAND timing engine: a full bbssd ssd built from bb_params (channels, LUNs,
     * planes, NAND latencies) -- value pages are placed + charged through it.
     * Built before the arena so the value capacity can be clamped to the physical
     * NAND size.
     */
    if (!kvssd_init_timing_ssd(s, n)) {
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
    s->index = &kv_index_hash;

    s->table = g_try_new0(FemuKvssdMappingEntry, s->hash_slots);
    s->values = g_try_malloc0(s->value_capacity);
    if (!s->table || !s->values) {
        error_setg(errp, "KVSSD DRAM allocation failed");
        g_free(s->values);
        g_free(s->table);
        kvssd_free_ssd(s);
        g_free(s);
        return NULL;
    }
    for (uint32_t i = 0; i < s->hash_slots; i++) {
        kv_entry_clear(&s->table[i]);
    }

    qemu_mutex_init(&s->lock);

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
}

static uint16_t kv_selftest_store_locked(FemuKvssdState *s, NvmeRequest *req,
                                         const void *key, uint8_t kl,
                                         const void *data, uint32_t len)
{
    uint64_t off;
    uint64_t lat = 0;
    int existing = s->index->find(s, key, kl, NULL);
    FemuKvssdMappingEntry old = {};
    struct ppa *new_ppas = NULL;
    uint32_t new_nr_ppas = 0;
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
    if (!kv_value_alloc(s, req, len, &off)) {
        return NVME_CAP_EXCEEDED | NVME_DNR;
    }
    if (len) {
        memcpy(s->values + off, data, len);
    }
    status = kv_program_ppas(s, req, len, USER_IO, &new_ppas, &new_nr_ppas,
                             &lat);
    if (status) {
        s->value_next = off;
        return status;
    }

    existing = s->index->find(s, key, kl, NULL);
    if (existing >= 0) {
        old = s->table[existing];
    }
    status = s->index->upsert(s, key, kl, off, len, new_ppas, new_nr_ppas);
    if (status) {
        kv_invalidate_ppa_array(s, new_ppas, new_nr_ppas);
        g_free(new_ppas);
        s->value_next = off;
        return status;
    }
    if (existing >= 0) {
        kv_discard_value_ppas(s, &old);
        s->value_reclaimable += old.length;
        if (s->value_used >= old.length) {
            s->value_used -= old.length;
        }
        if (s->key_used >= old.key_len) {
            s->key_used -= old.key_len;
        }
    }
    s->value_used += len;
    s->key_used += kl;
    kv_apply_lat(req, lat);
    return NVME_SUCCESS;
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
    if (!s->index->remove(s, key, kl)) {
        return false;
    }
    kv_discard_value_ppas(s, &old);
    s->value_reclaimable += old.length;
    if (s->value_used >= old.length) {
        s->value_used -= old.length;
    }
    if (s->key_used >= old.key_len) {
        s->key_used -= old.key_len;
    }
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
        uint64_t gc_before;
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
        gc_before = s->gc_wr_pages;
        old_next = s->value_next;
        KVT(kv_selftest_store_locked(s, &req, "cmp", 3, "COMPACT", 8) ==
            NVME_SUCCESS, "store-triggers-compaction");
        {
            int slot = s->index->find(s, (const uint8_t *)"k20", 3, NULL);
            bool ok = slot >= 0 &&
                      memcmp(s->values + s->table[slot].value_off, "XX", 3) == 0 &&
                      s->value_reclaimable == 0 &&
                      s->value_next < old_next &&
                      s->gc_wr_pages > gc_before;
            KVT(ok, "compaction-remap-real-gc (K-2)");
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
                                  (uint64_t)s->pgsz), &lat) == NVME_SUCCESS;
        }
        KVT(ok && s->nand_wr_pages == wr_before, "retrieve-no-page-allocation");
    }

    /* 9. Long overwrite run crosses at least one NAND line without allocator abort */
    {
        uint64_t loops = MIN((uint64_t)s->ssd->sp.pgs_per_line + 32, 20000ull);
        bool ok = true;

        for (uint64_t i = 0; i < loops; i++) {
            char v[16];
            int vl = snprintf(v, sizeof(v), "L%05" PRIu64, i) + 1;
            if (kv_selftest_store_locked(s, &req, "loop", 4, v, vl) !=
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
    if (n) {
        kvssd_free_ssd(s);
        if (!kvssd_init_timing_ssd(s, n)) {
            fails++;
            femu_err("KVSELFTEST FAIL reset-timing-ssd\n");
        }
    }

    femu_err("KVSELFTEST DONE pass=%d fails=%d\n", npass, fails);
#undef KVT
}

void kvssd_ftl_free(FemuKvssdState *s)
{
    if (!s) {
        return;
    }
    qemu_mutex_destroy(&s->lock);
    kvssd_reset_table(s);
    g_free(s->values);
    g_free(s->table);
    kvssd_free_ssd(s);
    g_free(s);
}
