/*
 * DFTL / cached mapping table (CMT) cost model. A bounded cache of translation
 * pages over the flat maptbl; a CMT miss charges a translation-page NAND read
 * (and a write-back if a dirty TP is evicted). Timing-only: the flat maptbl in
 * ftl-map.c stays the source of truth. cmt_touch is the datapath entry point.
 */
#include "qemu/osdep.h"
#include "ftl.h"
#include "ftl-internal.h"

/* Open-address hash over the CMT slot array: find the slot holding tp_id, or -1. */
static int32_t cmt_lookup(struct ssd *ssd, uint64_t tp_id)
{
    uint32_t h = (tp_id * 2654435761u) % ssd->cmt.hash_sz;
    for (uint32_t probe = 0; probe < ssd->cmt.hash_sz; probe++) {
        int32_t slot = ssd->cmt.hash[h];
        if (slot < 0) {
            return -1; /* empty bucket -> not present */
        }
        if (ssd->cmt.slots[slot].valid &&
            ssd->cmt.slots[slot].tp_id == tp_id) {
            return slot;
        }
        h = (h + 1) % ssd->cmt.hash_sz;
    }
    return -1;
}

/* Rebuild the open-address hash from the current slot contents (after eviction). */
static void cmt_rehash(struct ssd *ssd)
{
    for (uint32_t i = 0; i < ssd->cmt.hash_sz; i++) {
        ssd->cmt.hash[i] = -1;
    }
    for (uint32_t s = 0; s < ssd->cmt.capacity; s++) {
        if (!ssd->cmt.slots[s].valid) {
            continue;
        }
        uint32_t h = (ssd->cmt.slots[s].tp_id * 2654435761u) % ssd->cmt.hash_sz;
        while (ssd->cmt.hash[h] >= 0) {
            h = (h + 1) % ssd->cmt.hash_sz;
        }
        ssd->cmt.hash[h] = s;
    }
}

/* Pick a victim slot by CLOCK (second chance) and return its index. */
static uint32_t cmt_clock_evict(struct ssd *ssd)
{
    for (;;) {
        uint32_t s = ssd->cmt.hand;
        ssd->cmt.hand = (ssd->cmt.hand + 1) % ssd->cmt.capacity;
        if (!ssd->cmt.slots[s].valid) {
            return s;
        }
        if (!ssd->cmt.slots[s].ref) {
            return s;
        }
        ssd->cmt.slots[s].ref = false;
    }
}

/*
 * Charge the cached-mapping-table cost for one USER request's translation-page
 * access. Hit: O(1), set the reference bit, no added latency. Miss: charge a
 * translation-page read on the TP's home LUN (and a program if a dirty TP is
 * evicted), then install the TP. Timing-only: maptbl is unaffected. Returns the
 * added latency in ns.
 */
uint64_t cmt_touch(struct ssd *ssd, uint64_t lpn, uint64_t stime, bool is_write)
{
    struct ssdparams *spp = &ssd->sp;
    uint64_t tp_id = lpn / ssd->cmt.lpn_per_tp;
    int32_t slot = cmt_lookup(ssd, tp_id);
    uint64_t lat = 0;

    if (slot >= 0) {
        ssd->cmt.slots[slot].ref = true;
        if (is_write) {
            ssd->cmt.slots[slot].dirty = true;
        }
        ssd->cmt.hits++;
        return 0;
    }

    /* miss: model the translation-page access on a home LUN */
    ssd->cmt.misses++;
    uint32_t home = tp_id % spp->tt_luns;
    struct ppa tppa = {.ppa = 0};
    tppa.g.ch = home / spp->luns_per_ch;
    tppa.g.lun = home % spp->luns_per_ch;

    uint32_t victim = cmt_clock_evict(ssd);
    if (ssd->cmt.slots[victim].valid && ssd->cmt.slots[victim].dirty) {
        /* writeback of the evicted dirty translation page */
        struct nand_cmd twr = {.type = USER_IO, .cmd = NAND_WRITE, .stime = stime};
        lat += ssd_advance_status(ssd, &tppa, &twr);
    }
    if (ssd->cmt.slots[victim].valid) {
        ssd->cmt.used--;
    }

    struct nand_cmd trd = {.type = USER_IO, .cmd = NAND_READ, .stime = stime};
    lat += ssd_advance_status(ssd, &tppa, &trd);

    ssd->cmt.slots[victim].tp_id = tp_id;
    ssd->cmt.slots[victim].valid = true;
    ssd->cmt.slots[victim].ref = true;
    ssd->cmt.slots[victim].dirty = is_write;
    ssd->cmt.used++;
    cmt_rehash(ssd);
    return lat;
}

/*
 * Allocate the CMT from cache_mb (0 = disabled), one slot per translation page.
 * The sizing is held in 64 bits and bounded so capacity and hash_sz stay within
 * uint32_t. lpn_per_tp is the number of PPAs a translation page holds.
 */
void cmt_init(struct ssd *ssd, uint32_t cache_mb)
{
    struct ssdparams *spp = &ssd->sp;

    ssd->cmt.capacity = 0;
    if (!cache_mb) {
        return;
    }
    uint32_t pgsz = (uint32_t)spp->secsz * spp->secs_per_pg;
    if (pgsz == 0) {
        pgsz = 4096;
    }
    ssd->cmt.lpn_per_tp = pgsz / sizeof(uint64_t); /* PPAs per translation page */
    if (ssd->cmt.lpn_per_tp < 1) {
        ssd->cmt.lpn_per_tp = 1;
    }
    uint64_t cap = ((uint64_t)cache_mb * 1024 * 1024) / pgsz;
    /* bound so capacity and hash_sz (= capacity * 2 + 1) never overflow uint32_t */
    if (cap > (UINT32_MAX - 1) / 2) {
        cap = (UINT32_MAX - 1) / 2;
    }
    if (cap < 1) {
        cap = 1;
    }
    ssd->cmt.capacity = (uint32_t)cap;
    ssd->cmt.hash_sz = ssd->cmt.capacity * 2 + 1;
    ssd->cmt.slots = g_malloc0(sizeof(*ssd->cmt.slots) * ssd->cmt.capacity);
    ssd->cmt.hash = g_malloc(sizeof(*ssd->cmt.hash) * ssd->cmt.hash_sz);
    for (uint32_t i = 0; i < ssd->cmt.hash_sz; i++) {
        ssd->cmt.hash[i] = -1;
    }
    ssd->cmt.used = ssd->cmt.hand = 0;
    ssd->cmt.hits = ssd->cmt.misses = 0;
}
