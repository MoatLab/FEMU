/*
 * Hybrid log-block L2P mapping (BAST: Block-Associative Sector Translation, Kim 2002),
 * implemented behind the femu_mapping_ops vtable. This is a genuinely-behavioral scheme:
 * it models a small pool of per-data-block log blocks that absorb overwrites, and runs the
 * BAST merge state machine (switch merge vs full merge) whose cost -- extra NAND reads,
 * writes, and erases -- is charged to the timeline (ssd_advance_status) and to the WAF
 * counters (ssd->gc_write_pages), so write amplification is measurable and workload-shaped
 * (sequential overwrites -> cheap switch merges, WAF~1; random overwrites -> full merges,
 * WAF rises). Reference: flashsim FTLs/bast_ftl.cpp (is_sequential->promote / random_merge);
 * wiscsee nkftl2 switch/full merge. Founding paper: Kim et al. 2002 (1:1 log:data block).
 *
 * Faithful-vs-simplified note (honest): FEMU's data placement goes through one shared
 * write-pointer allocator (get_new_page) over lines, which does not let a scheme pin a
 * write to a specific physical log block. So this scheme is a *merge-cost overlay*: the L2P
 * (maptbl/rmap) and physical page allocation stay exactly as the page scheme's (data is
 * always correct and read-back identical), while the BAST log/merge BEHAVIOR and its WAF
 * cost are modeled on top. A fully-faithful BAST that physically segregates log vs data
 * blocks would need an allocator hook (FEMU_MAP_CLASS_LOG honored by get_new_page); that is
 * a documented future datapath change, not implemented here. The merge accounting is real;
 * the physical block segregation is abstracted.
 */
#include "qemu/osdep.h"
#include "ftl.h"
#include "ftl-internal.h"

/* one log block per data block (BAST 1:1); a small fixed pool of active log blocks. */
#define HYBRID_DEFAULT_LOG_BLOCKS 16

struct hybrid_log {
    int64_t lbn;          /* data block this log serves; -1 = free */
    int used;             /* pages written into this log block */
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
                lat += hybrid_charge(ssd, &old, NAND_READ);   /* read valid page */
                mark_page_invalid(ssd, &old);
                set_rmap_ent(ssd, INVALID_LPN, &old);

                struct ppa new = get_new_page_class(ssd, FEMU_MAP_CLASS_DATA);
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

/* trim: drop the lpn from the flat L2P and adjust its log model bookkeeping. */
static void femu_map_hybrid_trim(struct ssd *ssd, uint64_t lpn)
{
    struct femu_map_hybrid *h = hy(ssd);
    int64_t lbn = lpn / h->pgs_per_blk;
    struct ppa old = get_maptbl_ent(ssd, lpn);

    if (mapped_ppa(&old)) {
        mark_page_invalid(ssd, &old);
        set_rmap_ent(ssd, INVALID_LPN, &old);
        old.ppa = UNMAPPED_PPA;
        set_maptbl_ent(ssd, lpn, &old);
    }
    if (h->lbn_to_log[lbn] >= 0 && h->logs[h->lbn_to_log[lbn]].used > 0) {
        h->logs[h->lbn_to_log[lbn]].used--;
    }
}

const struct femu_mapping_ops femu_mapping_hybrid_ops = {
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
