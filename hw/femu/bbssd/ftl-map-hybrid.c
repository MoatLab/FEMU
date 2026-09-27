/*
 * Hybrid log-block mapping with BAST's one-log-per-logical-block association.
 * Each page reaching NAND consumes a fresh log slot, even when its logical
 * offset was already written. NAND cannot overwrite a programmed page; neither
 * overwrite invalidation nor trim restores a slot. Only merging resets it.
 * See Lee et al., "A Log Buffer-Based Flash Translation Layer Using
 * Fully-Associative Sector Translation", sections 2.2 and 2.4, for BAST's
 * append and merge rules; section 3 describes FAST's shared-log alternative.
 *
 * FEMU routes initial writes as well as overwrites through sixteen logical
 * logs. It merges the fullest log when a log fills or the pool is occupied,
 * breaking ties by slot order. A complete in-order log can switch without
 * copying; a full merge copies each currently mapped page of the logical
 * block once, including surviving data from earlier merges.
 *
 * This is a merge-cost model, not physical BAST block placement: LOG and DATA
 * have separate line write pointers, but logical logs share physical lines.
 * Full merges really relocate pages and charge gc_write_pages; switch merges
 * charge an erase without physically exchanging blocks. Physical line GC is
 * separate and can add copies. Reads use the flat L2P.
 */
#include "qemu/osdep.h"
#include "ftl.h"
#include "ftl-internal.h"

/* one log block per data block (BAST 1:1); a small fixed pool of active log blocks. */
#define HYBRID_DEFAULT_LOG_BLOCKS 16

struct hybrid_log {
    int64_t lbn;          /* data block this log serves; -1 = free */
    int used;             /* programs, including invalidated pages */
    int seq;              /* pages still in sequential order (offset i at slot i) */
};

struct femu_map_hybrid {
    int pgs_per_blk;      /* pages per (data/log) block = BAST merge unit */
    int nr_logs;          /* size of the log-block pool */
    struct hybrid_log *logs;
    /* per-data-block -> index into logs[], or -1 if no open log block */
    int *lbn_to_log;
    int64_t nr_lbns;
    /* counters (exposed via ftl_log / debug) */
    uint64_t switch_merges;
    uint64_t full_merges;
    uint64_t merge_read_pages;
    uint64_t merge_write_pages;
};

static inline struct femu_map_hybrid *hy(struct ssd *ssd)
{
    return (struct femu_map_hybrid *)ssd->map_priv;
}

static void femu_map_hybrid_init(struct ssd *ssd)
{
    struct ssdparams *spp = &ssd->sp;
    struct femu_map_hybrid *h = g_malloc0(sizeof(*h));

    h->pgs_per_blk = spp->pgs_per_blk;
    h->nr_logs = HYBRID_DEFAULT_LOG_BLOCKS;
    h->logs = g_malloc0(sizeof(struct hybrid_log) * h->nr_logs);
    for (int i = 0; i < h->nr_logs; i++) {
        h->logs[i].lbn = -1;
    }
    h->nr_lbns = spp->tt_pgs / spp->pgs_per_blk + 1;
    h->lbn_to_log = g_malloc0(sizeof(int) * h->nr_lbns);
    for (int64_t i = 0; i < h->nr_lbns; i++) {
        h->lbn_to_log[i] = -1;
    }
    ssd->map_priv = h;
}

/*
 * translate: data correctness comes from the flat L2P (maptbl), exactly like the page
 * scheme -- the log/data distinction in this overlay is for merge accounting, not for
 * where the latest data physically lives. So a read is the standard maptbl lookup.
 */
static struct ppa femu_map_hybrid_translate(struct ssd *ssd, uint64_t lpn)
{
    return get_maptbl_ent(ssd, lpn);
}

/* find an existing log for lbn, or claim a free one; -1 if the pool is full. */
static int hybrid_get_log(struct femu_map_hybrid *h, int64_t lbn)
{
    /* defensive: lbn derives from lpn; out-of-range would index lbn_to_log[] OOB.
     * The datapath rejects out-of-range LPNs, but guard the mapping too. */
    if (lbn < 0 || lbn >= h->nr_lbns) {
        return -1;
    }
    if (h->lbn_to_log[lbn] >= 0) {
        return h->lbn_to_log[lbn];
    }
    for (int i = 0; i < h->nr_logs; i++) {
        if (h->logs[i].lbn < 0) {
            h->logs[i].lbn = lbn;
            h->logs[i].used = 0;
            h->logs[i].seq = 0;
            h->lbn_to_log[lbn] = i;
            return i;
        }
    }
    return -1; /* pool full -> caller must reclaim first */
}

/*
 * prepare_write: route an overwrite into this LBN's log block. If the LBN has no open log
 * and the pool is full, signal may_need_reclaim so the datapath drains a merge first.
 */
static struct map_write_plan femu_map_hybrid_prepare_write(struct ssd *ssd,
                                                           uint64_t lpn, int io_type)
{
    struct femu_map_hybrid *h = hy(ssd);
    int64_t lbn = lpn / h->pgs_per_blk;
    struct map_write_plan plan = { .target_class = FEMU_MAP_CLASS_LOG,
                                   .may_need_reclaim = false };
    (void)io_type;

    if (h->lbn_to_log[lbn] < 0) {
        /* would need a fresh log block; if none free, ask for reclaim */
        bool have_free = false;
        for (int i = 0; i < h->nr_logs; i++) {
            if (h->logs[i].lbn < 0) { have_free = true; break; }
        }
        if (!have_free) {
            plan.may_need_reclaim = true;
        }
    }
    return plan;
}

/*
 * commit_write: update the flat L2P exactly as the page scheme (keeps data correct), and
 * record the overwrite into the LBN's log model to drive merge classification. An offset
 * written out of sequence breaks the switch-merge eligibility for this log block.
 */
static void femu_map_hybrid_commit_write(struct ssd *ssd, uint64_t lpn,
                                         struct ppa *new_ppa)
{
    struct femu_map_hybrid *h = hy(ssd);
    int64_t lbn = lpn / h->pgs_per_blk;
    int off = lpn % h->pgs_per_blk;
    struct ppa old = get_maptbl_ent(ssd, lpn);

    if (mapped_ppa(&old)) {
        mark_page_invalid(ssd, &old);
        set_rmap_ent(ssd, INVALID_LPN, &old);
    }
    set_maptbl_ent(ssd, lpn, new_ppa);
    set_rmap_ent(ssd, lpn, new_ppa);

    int li = hybrid_get_log(h, lbn);
    if (li >= 0) {
        struct hybrid_log *lg = &h->logs[li];
        /* sequential iff this write lands at the next in-order slot */
        if (lg->used == off) {
            lg->seq++;
        }
        lg->used++;
    }
}

static bool femu_map_hybrid_needs_reclaim(struct ssd *ssd)
{
    struct femu_map_hybrid *h = hy(ssd);

    for (int i = 0; i < h->nr_logs; i++) {
        if (h->logs[i].lbn >= 0 && h->logs[i].used >= h->pgs_per_blk) {
            return true; /* a full log block needs merging */
        }
    }
    /* also reclaim when the pool is exhausted (every slot in use) */
    for (int i = 0; i < h->nr_logs; i++) {
        if (h->logs[i].lbn < 0) {
            return false;
        }
    }
    return true;
}

/* charge one NAND op of `cmd` on `ppa` to the timeline (GC-class, like real merge I/O). */
static uint64_t hybrid_charge(struct ssd *ssd, struct ppa *ppa, int cmd)
{
    struct nand_cmd c = { .type = GC_IO, .cmd = cmd, .stime = 0 };
    return ssd_advance_status(ssd, ppa, &c);
}

/*
 * reclaim: merge one log block (BAST). Switch merge if the log filled sequentially
 * (in-order overwrite of the whole block) -> ~free, just an erase of the old data block.
 * Otherwise a full merge -> read every valid page of the merge unit and rewrite it,
 * charging reads+writes (the WAF cost) plus the erases. Picks the fullest log block.
 */
static uint64_t femu_map_hybrid_reclaim(struct ssd *ssd, int budget)
{
    struct femu_map_hybrid *h = hy(ssd);
    uint64_t lat = 0;

    for (int n = 0; n < budget; n++) {
        /* victim = fullest in-use log block */
        int vi = -1, vmax = -1;
        for (int i = 0; i < h->nr_logs; i++) {
            if (h->logs[i].lbn >= 0 && h->logs[i].used > vmax) {
                vmax = h->logs[i].used;
                vi = i;
            }
        }
        if (vi < 0) {
            break;
        }
        struct hybrid_log *lg = &h->logs[vi];
        int64_t lbn = lg->lbn;
        uint64_t base_lpn = (uint64_t)lbn * h->pgs_per_blk;

        bool switch_ok = (lg->seq >= h->pgs_per_blk);
        if (switch_ok) {
            /* switch merge: log block becomes the data block; old data block erased.
             * cost ~ one block erase, no page copies. */
            struct ppa anchor = get_maptbl_ent(ssd, base_lpn);
            if (mapped_ppa(&anchor)) {
                lat += hybrid_charge(ssd, &anchor, NAND_ERASE);
            }
            h->switch_merges++;
        } else {
            /* full merge (faithful): physically relocate every valid logical page of
             * the merge unit from wherever it lives (a log block, via the flat L2P)
             * into freshly-allocated DATA-class pages, then erase/free the vacated log
             * line. This is real relocation -- read old page, program a new DATA page,
             * invalidate old, validate new, update L2P/rmap -- so the NAND traffic and
             * gc_write_pages reflect genuine merge write-amplification (not an overlay). */
            for (int off = 0; off < h->pgs_per_blk; off++) {
                uint64_t lpn = base_lpn + off;
                struct ppa old = get_maptbl_ent(ssd, lpn);
                if (!mapped_ppa(&old) || !valid_ppa(ssd, &old)) {
                    continue;
                }
                /*
                 * Allocate before invalidating the old copy: with nowhere to
                 * put the merged page, invalidating first would drop the only
                 * copy of the data on the floor.
                 */
                struct ppa new = get_new_page_class(ssd, FEMU_MAP_CLASS_DATA);
                if (!mapped_ppa(&new)) {
                    break;
                }
                lat += hybrid_charge(ssd, &old, NAND_READ);   /* read valid page */
                mark_page_invalid(ssd, &old);
                set_rmap_ent(ssd, INVALID_LPN, &old);

                set_maptbl_ent(ssd, lpn, &new);
                set_rmap_ent(ssd, lpn, &new);
                mark_page_valid(ssd, &new);
                lat += hybrid_charge(ssd, &new, NAND_WRITE);  /* program merged page */
                ssd_advance_write_pointer_class(ssd, FEMU_MAP_CLASS_DATA);
                ssd->gc_write_pages++;       /* WAF: a merge-relocated page */
                h->merge_read_pages++;
                h->merge_write_pages++;
            }
            h->full_merges++;
        }

        /* free the log block */
        h->lbn_to_log[lbn] = -1;
        lg->lbn = -1;
        lg->used = 0;
        lg->seq = 0;
    }

    if (ssd->debug_ftl && (h->switch_merges + h->full_merges) % 64 == 0) {
        ftl_log("HYBRID merges: switch=%lu full=%lu merge_wr_pages=%lu gc_wr=%lu\n",
                (unsigned long)h->switch_merges, (unsigned long)h->full_merges,
                (unsigned long)h->merge_write_pages,
                (unsigned long)ssd->gc_write_pages);
    }

    return lat;
}

/* gc_relocate_commit: identical to the page scheme (line GC relocates a valid page; the
 * overlay's log model is unaffected -- merges are driven by host overwrites, not GC). */
static void femu_map_hybrid_gc_relocate_commit(struct ssd *ssd, uint64_t lpn,
                                               struct ppa *old_ppa,
                                               struct ppa *new_ppa)
{
    (void)old_ppa;
    set_maptbl_ent(ssd, lpn, new_ppa);
    set_rmap_ent(ssd, lpn, new_ppa);
}

/* Trim changes logical validity, not the number of programmed log slots. */
static void femu_map_hybrid_trim(struct ssd *ssd, uint64_t lpn)
{
    struct ppa old = get_maptbl_ent(ssd, lpn);

    if (mapped_ppa(&old)) {
        mark_page_invalid(ssd, &old);
        set_rmap_ent(ssd, INVALID_LPN, &old);
        old.ppa = UNMAPPED_PPA;
        set_maptbl_ent(ssd, lpn, &old);
    }
}

static void femu_map_hybrid_exit(struct ssd *ssd)
{
    struct femu_map_hybrid *h = ssd->map_priv;

    if (!h) {
        return;
    }
    g_free(h->logs);
    g_free(h->lbn_to_log);
    g_free(h);
    ssd->map_priv = NULL;
}

const struct femu_mapping_ops femu_mapping_hybrid_ops = {
    .exit           = femu_map_hybrid_exit,
    .uses_log_class = true,
    .name               = "hybrid",
    .uses_cmt           = false,
    .init               = femu_map_hybrid_init,
    .translate          = femu_map_hybrid_translate,
    .prepare_write      = femu_map_hybrid_prepare_write,
    .commit_write       = femu_map_hybrid_commit_write,
    .needs_reclaim      = femu_map_hybrid_needs_reclaim,
    .reclaim            = femu_map_hybrid_reclaim,
    .gc_relocate_commit = femu_map_hybrid_gc_relocate_commit,
    .trim               = femu_map_hybrid_trim,
};
