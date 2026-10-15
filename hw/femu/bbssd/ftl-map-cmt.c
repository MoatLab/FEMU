/*
 * DFTL cached mapping table (CMT): a bounded cache of whole translation pages
 * over the flat maptbl, which stays the source of truth for lookups.
 *
 * Without FDP the translation pages live on flash (ftl-map-tp.c) and
 * cmt_access() reads and writes them there. Under FDP cmt_touch() keeps the
 * timing-only model: a miss reads, and a dirty eviction programs, a
 * placeholder page on the TP's home LUN, and GC and TRIM cost nothing.
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

    /* miss: model the translation-page access */
    ssd->cmt.misses++;
    uint32_t victim = cmt_clock_evict(ssd);

    /*
     * If a dirty translation page is evicted, write it back on ITS OWN home LUN
     * (not the incoming TP's), then serialize the new TP read after it so the two
     * accesses are charged once, in order, rather than both from stime.
     */
    uint64_t wb_lat = 0;
    if (ssd->cmt.slots[victim].valid) {
        if (ssd->cmt.slots[victim].dirty) {
            uint32_t vhome = ssd->cmt.slots[victim].tp_id % spp->tt_luns;
            struct ppa vppa = {.ppa = 0};
            vppa.g.ch = vhome / spp->luns_per_ch;
            vppa.g.lun = vhome % spp->luns_per_ch;
            struct nand_cmd twr = {.type = MAP_IO, .cmd = NAND_WRITE,
                                   .stime = stime};
            wb_lat = ssd_advance_status(ssd, &vppa, &twr);
        }
        ssd->cmt.used--;
    }

    uint32_t home = tp_id % spp->tt_luns;
    struct ppa tppa = {.ppa = 0};
    tppa.g.ch = home / spp->luns_per_ch;
    tppa.g.lun = home % spp->luns_per_ch;
    struct nand_cmd trd = {.type = MAP_IO, .cmd = NAND_READ,
                           .stime = stime + wb_lat};
    lat = wb_lat + ssd_advance_status(ssd, &tppa, &trd);

    ssd->cmt.slots[victim].tp_id = tp_id;
    ssd->cmt.slots[victim].valid = true;
    ssd->cmt.slots[victim].ref = true;
    ssd->cmt.slots[victim].dirty = is_write;
    ssd->cmt.used++;
    cmt_rehash(ssd);
    return lat;
}

int32_t cmt_slot_of(struct ssd *ssd, uint64_t tp)
{
    return ssd->cmt.capacity ? cmt_lookup(ssd, tp) : -1;
}

/* empty the CMT and write nothing back: its mappings are being discarded */
void cmt_drop_all(struct ssd *ssd)
{
    if (!ssd->cmt.capacity) {
        return;
    }
    memset(ssd->cmt.slots, 0, sizeof(*ssd->cmt.slots) * ssd->cmt.capacity);
    for (uint32_t i = 0; i < ssd->cmt.hash_sz; i++) {
        ssd->cmt.hash[i] = -1;
    }
    ssd->cmt.used = ssd->cmt.hand = 0;
}

/**
 * cmt_access - the translation of @lpn for a host access, with TPs on flash
 * @ssd: the device
 * @lpn: the logical page
 * @stime: when the access starts
 * @is_write: the access changes the mapping
 *
 * A hit is ready when the slot's own fill ends. A miss evicts a slot by
 * CLOCK; a dirty victim is programmed at the TP pointer once its fill has
 * ended, in parallel with the read of the new TP, since the program holds
 * its own copy. A TP with no flash copy needs no read. A pending TP merges
 * its changes into the new slot and the slot is dirty.
 *
 * When the dirty victim has no page to go to (the free lines are down to
 * the forced reserve), nothing is evicted: the TP is read for this access
 * alone, and a write's change goes pending (tp_note()). So a host command
 * never fails for TP space. Returns the time the translation is ready.
 */
uint64_t cmt_access(struct ssd *ssd, uint64_t lpn, uint64_t stime,
                    bool is_write)
{
    uint64_t tp = lpn / ssd->cmt.lpn_per_tp;
    int32_t slot = cmt_lookup(ssd, tp);
    struct cmt_slot *v;
    uint32_t victim;
    uint64_t ready;

    if (slot >= 0) {
        ssd->cmt.slots[slot].ref = true;
        if (is_write) {
            ssd->cmt.slots[slot].dirty = true;
        }
        ssd->cmt.hits++;
        return MAX(stime, ssd->cmt.slots[slot].ready);
    }

    ssd->cmt.misses++;
    victim = cmt_clock_evict(ssd);
    v = &ssd->cmt.slots[victim];
    if (v->valid && v->dirty &&
        !tp_program(ssd, v->tp_id, false, MAX(stime, v->ready), true, NULL)) {
        return tp_read(ssd, tp, stime, true);
    }
    if (v->valid) {
        ssd->cmt.used--;
    }

    ready = tp_read(ssd, tp, stime, true);
    v->tp_id = tp;
    v->valid = true;
    v->ref = true;
    v->dirty = is_write || tp_pending(ssd, tp);
    v->ready = ready;
    tp_pending_drop(ssd, tp);
    ssd->cmt.used++;
    cmt_rehash(ssd);
    return ready;
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
    /* the CMT models translation-page reads on a home LUN; without LUNs there is
     * nothing to model (and tp_id % tt_luns would divide by zero) */
    if (spp->tt_luns == 0) {
        return;
    }
    uint64_t pgsz = (uint64_t)spp->secsz * spp->secs_per_pg;
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
    /* a test may ask for fewer slots than one MiB holds */
    if (ssd->n && ssd->n->test_cmt_slots) {
        cap = ssd->n->test_cmt_slots;
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

/* release what cmt_init() took */
void cmt_destroy(struct ssd *ssd)
{
    g_free(ssd->cmt.slots);
    g_free(ssd->cmt.hash);
    ssd->cmt.slots = NULL;
    ssd->cmt.hash = NULL;
    ssd->cmt.capacity = 0;
}
