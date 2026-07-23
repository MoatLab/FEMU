/*
 * bbssd device DRAM read cache (opt-in; capacity 0 = disabled). A bounded set of
 * recently-read LPNs with a fixed slot array and an open-address hash index --
 * the same structure as a cached mapping table. Timing-only: it does not hold
 * data (NAND remains the source of truth), it only models the latency benefit of
 * a controller read cache. Runs on the single FTL thread. The eviction policy is
 * selectable: CLOCK (default), random, true LRU, or a scan-resistant 2Q variant.
 */
#include "qemu/osdep.h"
#include "ftl.h"
#include "ftl-internal.h"

/* Open-address hash over the rcache slot array: find the slot holding lpn, or -1. */
static int32_t rcache_lookup(struct ssd *ssd, uint64_t lpn)
{
    uint32_t h = (lpn * 2654435761u) % ssd->rcache.hash_sz;
    for (uint32_t probe = 0; probe < ssd->rcache.hash_sz; probe++) {
        int32_t slot = ssd->rcache.hash[h];
        if (slot < 0) {
            return -1; /* empty bucket -> not present */
        }
        if (ssd->rcache.slots[slot].valid &&
            ssd->rcache.slots[slot].lpn == lpn) {
            return slot;
        }
        h = (h + 1) % ssd->rcache.hash_sz;
    }
    return -1;
}

/* Rebuild the open-address hash from current slot contents (after an eviction). */
static void rcache_rehash(struct ssd *ssd)
{
    for (uint32_t i = 0; i < ssd->rcache.hash_sz; i++) {
        ssd->rcache.hash[i] = -1;
    }
    for (uint32_t s = 0; s < ssd->rcache.capacity; s++) {
        if (!ssd->rcache.slots[s].valid) {
            continue;
        }
        uint32_t h = (ssd->rcache.slots[s].lpn * 2654435761u) % ssd->rcache.hash_sz;
        while (ssd->rcache.hash[h] >= 0) {
            h = (h + 1) % ssd->rcache.hash_sz;
        }
        ssd->rcache.hash[h] = s;
    }
}

/* Pick a victim slot by CLOCK (second chance) and return its index. */
static uint32_t rcache_clock_evict(struct ssd *ssd)
{
    for (;;) {
        uint32_t s = ssd->rcache.hand;
        ssd->rcache.hand = (ssd->rcache.hand + 1) % ssd->rcache.capacity;
        if (!ssd->rcache.slots[s].valid) {
            return s;
        }
        if (!ssd->rcache.slots[s].ref) {
            return s;
        }
        ssd->rcache.slots[s].ref = false;
    }
}

/*
 * Random eviction: pick a victim by a deterministic LCG over an internal counter
 * so a run is reproducible. A baseline for comparing against CLOCK's recency
 * approximation.
 */
static uint32_t rcache_random_evict(struct ssd *ssd)
{
    ssd->rcache.rand_state = ssd->rcache.rand_state * 6364136223846793005ull
                             + 1442695040888963407ull;
    return (uint32_t)((ssd->rcache.rand_state >> 33) % ssd->rcache.capacity);
}

/*
 * True LRU: evict the slot with the smallest last_used tick (least recently
 * accessed). O(capacity) scan -- exact recency, the reference point CLOCK
 * approximates cheaply.
 */
static uint32_t rcache_lru_evict(struct ssd *ssd)
{
    uint32_t victim = 0;
    uint64_t oldest = (uint64_t)-1;

    for (uint32_t s = 0; s < ssd->rcache.capacity; s++) {
        if (!ssd->rcache.slots[s].valid) {
            return s;
        }
        if (ssd->rcache.slots[s].last_used < oldest) {
            oldest = ssd->rcache.slots[s].last_used;
            victim = s;
        }
    }
    return victim;
}

/*
 * Scan-resistant 2Q-style eviction. The `ref` bit acts as a "protected" flag: a
 * page is inserted unprotected (ref=false, seen once) and only promoted to
 * protected (ref=true) on a second access (a real hit). Eviction prefers the LRU
 * among unprotected slots -- so scan traffic (touched once, never re-referenced)
 * is reclaimed before re-referenced pages, defeating the looping-scan pathology
 * that sinks LRU/CLOCK. Falls back to LRU among protected slots if every slot is
 * protected.
 */
static uint32_t rcache_2q_evict(struct ssd *ssd)
{
    uint32_t victim = 0;
    uint64_t oldest_unprot = (uint64_t)-1, oldest_any = (uint64_t)-1;
    int unprot_victim = -1;

    for (uint32_t s = 0; s < ssd->rcache.capacity; s++) {
        if (!ssd->rcache.slots[s].valid) {
            return s;
        }
        if (ssd->rcache.slots[s].last_used < oldest_any) {
            oldest_any = ssd->rcache.slots[s].last_used;
            victim = s;
        }
        if (!ssd->rcache.slots[s].ref &&
            ssd->rcache.slots[s].last_used < oldest_unprot) {
            oldest_unprot = ssd->rcache.slots[s].last_used;
            unprot_victim = (int)s;
        }
    }
    return (unprot_victim >= 0) ? (uint32_t)unprot_victim : victim;
}

/* Eviction-policy dispatch: 0 = CLOCK (default), 1 = random, 2 = LRU, 3 = 2Q. */
static uint32_t rcache_evict(struct ssd *ssd)
{
    if (ssd->rcache.evict_policy == 1) {
        return rcache_random_evict(ssd);
    }
    if (ssd->rcache.evict_policy == 2) {
        return rcache_lru_evict(ssd);
    }
    if (ssd->rcache.evict_policy == 3) {
        return rcache_2q_evict(ssd);
    }
    return rcache_clock_evict(ssd);
}

/*
 * Consult the read cache for a USER read of `lpn`. On a hit, set the reference
 * bit and return the DRAM hit latency (the caller substitutes it for the NAND
 * read). On a miss, insert the LPN (evicting via the selected policy if full) and
 * return 0 so the caller pays the NAND read. No-op (returns 0) when disabled.
 */
uint64_t rcache_touch(struct ssd *ssd, uint64_t lpn)
{
    if (!ssd->rcache.capacity) {
        return 0;
    }

    int32_t slot = rcache_lookup(ssd, lpn);
    if (slot >= 0) {
        ssd->rcache.slots[slot].ref = true;
        ssd->rcache.slots[slot].last_used = ++ssd->rcache.tick;
        ssd->rcache.hits++;
        return ssd->rcache.hit_lat;
    }

    ssd->rcache.misses++;
    uint32_t victim;
    if (ssd->rcache.used < ssd->rcache.capacity) {
        victim = ssd->rcache.used++;
        ssd->rcache.slots[victim].valid = true;
        ssd->rcache.slots[victim].lpn = lpn;
        /*
         * 2Q (policy 3): new pages enter unprotected (probation), promoted on a
         * second hit. Other policies keep ref=true on insert (unchanged behavior).
         */
        ssd->rcache.slots[victim].ref = (ssd->rcache.evict_policy != 3);
        ssd->rcache.slots[victim].last_used = ++ssd->rcache.tick;
        uint32_t h = (lpn * 2654435761u) % ssd->rcache.hash_sz;
        while (ssd->rcache.hash[h] >= 0) {
            h = (h + 1) % ssd->rcache.hash_sz;
        }
        ssd->rcache.hash[h] = victim;
    } else {
        victim = rcache_evict(ssd);
        ssd->rcache.slots[victim].lpn = lpn;
        ssd->rcache.slots[victim].ref = (ssd->rcache.evict_policy != 3);
        ssd->rcache.slots[victim].last_used = ++ssd->rcache.tick;
        rcache_rehash(ssd); /* slot's key changed -> rebuild index */
    }
    return 0;
}

/*
 * Drop any cached entry for lpn so a subsequent read does not return a stale
 * DRAM-hit after the page is overwritten or trimmed. No-op when disabled or when
 * the lpn is not cached.
 */
void rcache_invalidate(struct ssd *ssd, uint64_t lpn)
{
    if (!ssd->rcache.capacity) {
        return;
    }

    /* find the hash bucket holding this lpn */
    uint32_t hs = ssd->rcache.hash_sz;
    uint32_t i = (lpn * 2654435761u) % hs;
    uint32_t probe;
    for (probe = 0; probe < hs; probe++) {
        int32_t s = ssd->rcache.hash[i];
        if (s < 0) {
            return; /* not present */
        }
        if (ssd->rcache.slots[s].valid && ssd->rcache.slots[s].lpn == lpn) {
            /*
             * Mark the slot dead but leave `used`: the slot index stays within
             * the allocated prefix and is reclaimed by normal eviction; a dead
             * slot is simply never a lookup hit (valid=false).
             */
            ssd->rcache.slots[s].valid = false;
            ssd->rcache.slots[s].ref = false;
            break;
        }
        i = (i + 1) % hs;
    }
    if (probe == hs) {
        return;
    }

    /*
     * Backward-shift deletion: removing one open-addressed bucket means clearing
     * it and re-inserting the following contiguous run so no lookup chain breaks.
     * O(cluster length), not O(capacity) -- this runs on the write hot path.
     */
    ssd->rcache.hash[i] = -1;
    uint32_t j = (i + 1) % hs;
    while (ssd->rcache.hash[j] >= 0) {
        int32_t moved = ssd->rcache.hash[j];
        ssd->rcache.hash[j] = -1;
        uint32_t k = (ssd->rcache.slots[moved].lpn * 2654435761u) % hs;
        while (ssd->rcache.hash[k] >= 0) {
            k = (k + 1) % hs;
        }
        ssd->rcache.hash[k] = moved;
        j = (j + 1) % hs;
    }
}

/*
 * Allocate the read cache from read_cache_mb (0 = disabled). One slot per 4 KiB
 * page. hit_lat defaults to ~1/16 of a page read (a DRAM-ish hit) when pg_rd_lat
 * is known.
 */
void rcache_init(struct ssd *ssd, uint32_t read_cache_mb, uint32_t evict_policy)
{
    ssd->rcache.capacity = 0;
    if (read_cache_mb == 0) {
        return;
    }
    ssd->rcache.capacity = ((uint64_t)read_cache_mb * 1024 * 1024) / 4096;
    if (ssd->rcache.capacity < 1) {
        ssd->rcache.capacity = 1;
    }
    ssd->rcache.used = 0;
    ssd->rcache.hand = 0;
    ssd->rcache.evict_policy = evict_policy; /* 0 = CLOCK, 1 = random, 2 = LRU, 3 = 2Q */
    ssd->rcache.rand_state = 0x9e3779b97f4a7c15ull; /* fixed seed -> reproducible */
    ssd->rcache.tick = 0; /* LRU recency counter */
    ssd->rcache.hits = 0;
    ssd->rcache.misses = 0;
    ssd->rcache.hit_lat = ssd->sp.pg_rd_lat ? ssd->sp.pg_rd_lat / 16 : 1000;
    ssd->rcache.hash_sz = ssd->rcache.capacity * 2 + 1;
    ssd->rcache.slots = g_malloc0(sizeof(*ssd->rcache.slots) * ssd->rcache.capacity);
    ssd->rcache.hash = g_malloc(sizeof(*ssd->rcache.hash) * ssd->rcache.hash_sz);
    for (uint32_t i = 0; i < ssd->rcache.hash_sz; i++) {
        ssd->rcache.hash[i] = -1;
    }
}
