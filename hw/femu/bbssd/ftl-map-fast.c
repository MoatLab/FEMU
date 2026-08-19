/*
 * FAST (Fully-Associative Sector Translation, Lee et al. TECS'07) log-block mapping,
 * mapping=fast, on the FEMU_MAP_CLASS_LOG allocator hook. Like the faithful BAST hybrid
 * (ftl-map-fast mirrors ftl-map-hybrid), but with FAST's fully-associative log organization:
 *
 *  - A single SEQUENTIAL-WRITE (SW) log block: a sequential run of overwrites to one data
 *    block lands here; if it fills the block in order it can switch-merge (cheap).
 *  - A SHARED, fully-associative RANDOM-WRITE (RW) log pool: overwrites from ANY data block
 *    land in a common pool of RW log capacity. Because logs are not pinned 1:1 to a data
 *    block (as in BAST), a single data block churning does not force an immediate merge --
 *    full merges are DELAYED until the RW pool fills, at which point a random merge must
 *    reconcile EVERY distinct data block (LBN) that has pages in the pool. That is FAST's
 *    trade: fewer but larger (multi-victim) merges vs BAST's frequent 1:1 merges.
 *
 * Faithfulness: writes physically land in LOG-class blocks (get_new_page_class), and merges
 * PHYSICALLY relocate valid pages into fresh DATA-class blocks (read old, program new,
 * invalidate old, validate new, update L2P/rmap, advance the data write pointer,
 * gc_write_pages++) -- so write amplification is genuine, like the faithful BAST. translate
 * uses the flat L2P (always holds the real log-or-data ppa). State lives behind ssd->map_priv.
 *
 * Simplifications (documented, like BAST): the SW log detects only a strict in-order run; the
 * RW pool is a fixed page budget; the random-merge victim is "all LBNs currently in the RW
 * pool" drained in one bounded pass; no FAST second-chance/partial-merge heuristics. reclaim
 * is budget=1 (one merge pass per drain) to bound per-request latency.
 */
#include "qemu/osdep.h"
#include "ftl.h"
#include "ftl-internal.h"

#define FAST_RW_LOG_BLOCKS 16   /* shared RW log pool size, in blocks */
#define FAST_MAX_DIRTY_LBNS 4096
#define FAST_MERGE_LBNS_PER_PASS 2  /* victim data blocks merged per reclaim drain (bound) */

struct femu_map_fast {
    int pgs_per_blk;
    /* shared RW log pool: a page budget + the set of data blocks (LBNs) with pages in it */
    int rw_capacity_pages;   /* total RW log pages before a random merge is forced */
    int rw_used_pages;       /* RW log pages currently in use */
    uint8_t *lbn_dirty;      /* lbn_dirty[lbn] = has pages in the RW pool */
    int64_t *dirty_list;     /* compact list of dirty LBNs (for the merge sweep) */
    int dirty_cnt;
    int64_t nr_lbns;
    /* SW (sequential-write) log: tracks one in-order run */
    int64_t sw_lbn;          /* data block the SW log currently serves; -1 = none */
    int sw_used;             /* pages written into the SW log in order */
    /* stats (exposed via SMART vendor area, same accessors as hybrid) */
    uint64_t switch_merges;
    uint64_t full_merges;
    uint64_t merge_read_pages;
    uint64_t merge_write_pages;
};

static inline struct femu_map_fast *fa(struct ssd *ssd)
{
    return (struct femu_map_fast *)ssd->map_priv;
}

static void femu_map_fast_init(struct ssd *ssd)
{
    struct ssdparams *spp = &ssd->sp;
    struct femu_map_fast *f = g_malloc0(sizeof(*f));

    f->pgs_per_blk = spp->pgs_per_blk;
    f->rw_capacity_pages = FAST_RW_LOG_BLOCKS * spp->pgs_per_blk;
    f->rw_used_pages = 0;
    f->nr_lbns = spp->tt_pgs / spp->pgs_per_blk + 1;
    f->lbn_dirty = g_malloc0(sizeof(uint8_t) * f->nr_lbns);
    f->dirty_list = g_malloc0(sizeof(int64_t) * FAST_MAX_DIRTY_LBNS);
    f->dirty_cnt = 0;
    f->sw_lbn = -1;
    f->sw_used = 0;
    ssd->map_priv = f;
}

/* translate: flat L2P holds the real ppa (log or data) -- always correct. */
static struct ppa femu_map_fast_translate(struct ssd *ssd, uint64_t lpn)
{
    return get_maptbl_ent(ssd, lpn);
}

/*
 * prepare_write: all overwrites go to the LOG class. Signal may_need_reclaim when the
 * shared RW pool is (about to be) full -- the datapath then drains one random merge.
 */
static struct map_write_plan femu_map_fast_prepare_write(struct ssd *ssd,
                                                         uint64_t lpn, int io_type)
{
    struct femu_map_fast *f = fa(ssd);
    struct map_write_plan plan = { .target_class = FEMU_MAP_CLASS_LOG,
                                   .may_need_reclaim = false };
    (void)lpn; (void)io_type;

    if (f->rw_used_pages >= f->rw_capacity_pages ||
        f->dirty_cnt >= FAST_MAX_DIRTY_LBNS - 1) {
        plan.may_need_reclaim = true;
    }
    return plan;
}

/*
 * commit_write: flat L2P update (data-correct), then account the overwrite into the FAST
 * log model. A strict in-order run to a single data block uses the SW log; anything else
 * goes to the shared RW pool, marking that LBN dirty.
 */
static void femu_map_fast_commit_write(struct ssd *ssd, uint64_t lpn,
                                       struct ppa *new_ppa)
{
    struct femu_map_fast *f = fa(ssd);
    int64_t lbn = lpn / f->pgs_per_blk;
    int off = lpn % f->pgs_per_blk;
    struct ppa old = get_maptbl_ent(ssd, lpn);

    if (mapped_ppa(&old)) {
        mark_page_invalid(ssd, &old);
        set_rmap_ent(ssd, INVALID_LPN, &old);
    }
    set_maptbl_ent(ssd, lpn, new_ppa);
    set_rmap_ent(ssd, lpn, new_ppa);

    /* SW log: continue an in-order run to the same data block */
    if (lbn == f->sw_lbn && off == f->sw_used) {
        f->sw_used++;
        return;
    }
    if (f->sw_lbn < 0 && off == 0) {
        f->sw_lbn = lbn;
        f->sw_used = 1;
        return;
    }

    /* otherwise -> shared RW pool */
    if (lbn >= 0 && lbn < f->nr_lbns && !f->lbn_dirty[lbn] &&
        f->dirty_cnt < FAST_MAX_DIRTY_LBNS) {
        f->lbn_dirty[lbn] = 1;
        f->dirty_list[f->dirty_cnt++] = lbn;
    }
    f->rw_used_pages++;
}

static bool femu_map_fast_needs_reclaim(struct ssd *ssd)
{
    struct femu_map_fast *f = fa(ssd);

    return (f->rw_used_pages >= f->rw_capacity_pages) ||
           (f->sw_lbn >= 0 && f->sw_used >= f->pgs_per_blk) ||
           (f->dirty_cnt >= FAST_MAX_DIRTY_LBNS - 1);
}

static uint64_t fast_charge(struct ssd *ssd, struct ppa *ppa, int cmd)
{
    struct nand_cmd c = { .type = GC_IO, .cmd = cmd, .stime = 0 };
    return ssd_advance_status(ssd, ppa, &c);
}

/*
 * Physically relocate one data block's valid pages into fresh DATA-class pages.
 * *relocated (if non-NULL) receives the number of valid pages actually moved, so
 * the caller can decrement the RW-pool page counter by the real count rather than
 * a fixed block's worth (sparse LBNs hold fewer than pgs_per_blk pages).
 */
static uint64_t fast_merge_one_lbn(struct ssd *ssd, int64_t lbn, int *relocated)
{
    struct femu_map_fast *f = fa(ssd);
    uint64_t base_lpn = (uint64_t)lbn * f->pgs_per_blk;
    uint64_t lat = 0;
    int moved = 0;

    for (int off = 0; off < f->pgs_per_blk; off++) {
        uint64_t lpn = base_lpn + off;
        struct ppa old = get_maptbl_ent(ssd, lpn);
        if (!mapped_ppa(&old) || !valid_ppa(ssd, &old)) {
            continue;
        }
        lat += fast_charge(ssd, &old, NAND_READ);
        mark_page_invalid(ssd, &old);
        set_rmap_ent(ssd, INVALID_LPN, &old);

        struct ppa new = get_new_page_class(ssd, FEMU_MAP_CLASS_DATA);
        set_maptbl_ent(ssd, lpn, &new);
        set_rmap_ent(ssd, lpn, &new);
        mark_page_valid(ssd, &new);
        lat += fast_charge(ssd, &new, NAND_WRITE);
        ssd_advance_write_pointer_class(ssd, FEMU_MAP_CLASS_DATA);
        ssd->gc_write_pages++;
        f->merge_read_pages++;
        f->merge_write_pages++;
        moved++;
    }
    if (relocated) {
        *relocated = moved;
    }
    return lat;
}

/*
 * reclaim (one bounded pass per drain): a FAST random merge reconciles EVERY data block
 * that currently has pages in the shared RW pool (the multi-victim cost), physically
 * relocating their valid pages into data blocks; then the RW pool is empty. The SW log, if
 * it filled in order, switch-merges (cheap). This is FAST's "fewer but larger merges".
 */
static uint64_t femu_map_fast_reclaim(struct ssd *ssd, int budget)
{
    struct femu_map_fast *f = fa(ssd);
    uint64_t lat = 0;
    (void)budget; /* one full random-merge pass; inherently bounded by dirty_cnt */

    /* SW switch merge: a fully in-order SW log promotes in place (no copy) */
    if (f->sw_lbn >= 0 && f->sw_used >= f->pgs_per_blk) {
        struct ppa anchor = get_maptbl_ent(ssd, (uint64_t)f->sw_lbn * f->pgs_per_blk);
        if (mapped_ppa(&anchor)) {
            lat += fast_charge(ssd, &anchor, NAND_ERASE);
        }
        f->switch_merges++;
        f->sw_lbn = -1;
        f->sw_used = 0;
    }

    /*
     * RW random merge, bounded: relocate up to FAST_MERGE_LBNS_PER_PASS dirty data blocks
     * per drain (pop from the tail of the dirty list), leaving the rest dirty for the next
     * drain. FAST's random merge is multi-victim, but relocating ALL dirty LBNs in one call
     * can be thousands of page copies -> a latency spike that starves the guest; bounding the
     * per-pass victim count keeps each reclaim's cost in check (a faithfulness/latency
     * tradeoff -- the merge is still real and multi-victim, just throttled). Each freed LBN
     * returns ~one block of RW capacity.
     */
    int merged = 0;
    while (f->dirty_cnt > 0 && merged < FAST_MERGE_LBNS_PER_PASS) {
        int relocated = 0;
        int64_t lbn = f->dirty_list[--f->dirty_cnt];
        lat += fast_merge_one_lbn(ssd, lbn, &relocated);
        if (lbn >= 0 && lbn < f->nr_lbns) {
            f->lbn_dirty[lbn] = 0;
        }
        /* decrement by the pages actually relocated; a sparse LBN holds fewer
         * than a full block, and subtracting a fixed pgs_per_blk would underflow
         * the unsigned counter and wedge reclaim/pool-capacity tracking. */
        if (f->rw_used_pages >= (uint64_t)relocated) {
            f->rw_used_pages -= relocated;
        } else {
            f->rw_used_pages = 0;
        }
        merged++;
    }
    if (merged > 0) {
        f->full_merges++;          /* one (bounded) random-merge pass */
    }
    /* if the pool is drained of dirty LBNs, the counter must be zero -- guards
     * against a stale count leaving needs_reclaim permanently true. */
    if (f->dirty_cnt == 0) {
        f->rw_used_pages = 0;
    }

    if (ssd->debug_ftl) {
        ftl_log("FAST merges: switch=%lu random=%lu merge_wr_pages=%lu gc_wr=%lu\n",
                (unsigned long)f->switch_merges, (unsigned long)f->full_merges,
                (unsigned long)f->merge_write_pages,
                (unsigned long)ssd->gc_write_pages);
    }
    return lat;
}

static void femu_map_fast_gc_relocate_commit(struct ssd *ssd, uint64_t lpn,
                                             struct ppa *old_ppa, struct ppa *new_ppa)
{
    (void)old_ppa;
    set_maptbl_ent(ssd, lpn, new_ppa);
    set_rmap_ent(ssd, lpn, new_ppa);
}

static void femu_map_fast_trim(struct ssd *ssd, uint64_t lpn)
{
    struct ppa old = get_maptbl_ent(ssd, lpn);

    if (mapped_ppa(&old)) {
        mark_page_invalid(ssd, &old);
        set_rmap_ent(ssd, INVALID_LPN, &old);
        old.ppa = UNMAPPED_PPA;
        set_maptbl_ent(ssd, lpn, &old);
    }
}

const struct femu_mapping_ops femu_mapping_fast_ops = {
    .name               = "fast",
    .uses_cmt           = false,
    .init               = femu_map_fast_init,
    .translate          = femu_map_fast_translate,
    .prepare_write      = femu_map_fast_prepare_write,
    .commit_write       = femu_map_fast_commit_write,
    .needs_reclaim      = femu_map_fast_needs_reclaim,
    .reclaim            = femu_map_fast_reclaim,
    .gc_relocate_commit = femu_map_fast_gc_relocate_commit,
    .trim               = femu_map_fast_trim,
};
