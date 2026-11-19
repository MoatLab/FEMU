/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FEMU_FTL_OPS_H
#define FEMU_FTL_OPS_H

/*
 * The policy interface of the bbssd FTL: L2P mapping schemes (the mapping
 * property) and GC victim policies (the gc_policy property). The same FTL
 * runs under bbssd, CSD, FDP, KV and femu-cxl-ssd. KV refuses every
 * gc_policy but greedy and keeps its own mapping and victim choice;
 * femu-cxl-ssd has neither property, so it runs page mapping and greedy.
 *
 *   write  prepare_write -> allocate -> commit_write -> program
 *          -> needs_reclaim / reclaim
 *   read   translate
 *   GC     select_victim_line -> for each valid page: gc_relocate_commit
 *   trim   trim, or the flat invalidation when trim is NULL
 *
 * FDP host writes and trims update the maps directly, with no
 * prepare_write, commit_write or trim; FDP relocation calls
 * gc_relocate_commit.
 *
 * Callers. One FTL can have more than one caller thread; they take turns:
 *
 *   caller                          when
 *   ------------------------------  --------------------------------------
 *   FEMU-FTL-Thread of a            I/O, GC, reclaim, flush and destage;
 *   controller                      on shared storage, under the
 *                                   subsystem ns_lock
 *   femu-cxl-ftl worker, and the    I/O of a femu-cxl-ssd medium and of
 *   FTL thread of a linked          its linked controller, under the
 *   controller                      lock of the medium
 *   BQL context, with the callers   realize (ssd_init, preconditioning,
 *   above stopped or paused         restore of a saved FTL), unrealize,
 *                                   Format, namespace create and delete,
 *                                   probes such as the Streams one
 *
 * nvme_pause_pollers() pauses the NVMe controllers only. It does not pause
 * the femu-cxl-ftl worker, so a BQL caller on a CXL medium also needs the
 * lock of the medium.
 *
 * Rules for every hook:
 *
 * - No hook takes a lock, sleeps, or touches guest memory.
 * - Times are uint64_t nanoseconds of the device clock (femu_dev_now()).
 *   The caller joins the latency of reclaim() to the request with MAX.
 *   Line ages use ssd_age_now(). FDP cost-benefit keeps microseconds.
 * - A mapping operation keeps maptbl and rmap inverse to each other. The
 *   hook and its caller share this: gc_relocate_commit maps the new page,
 *   and the caller then invalidates the old one.
 * - A mapping scheme changes page and line counts only through the
 *   ftl-internal.h helpers, and keeps its own state in ssd->map_priv.
 * - A policy reads ssd->lm.victim_line_pq and line fields. It removes the
 *   line it returns from the queue. When it returns NULL, the queue keeps
 *   the same lines; the heap order of equal keys may change.
 * - A policy draws random numbers only from ftl_gc_rand(), so gc_seed fixes
 *   the victim order of the policies that sample.
 *
 * The lookups check each table with femu_mapping_ops_check() and
 * femu_ftl_policy_ops_check(), and abort on a broken table.
 *
 * Version rule: an optional hook, whose NULL keeps the old behaviour, keeps
 * the version. A new required hook, a changed signature or rule, or a
 * removed hook adds one.
 */

#include <stdbool.h>
#include <stdint.h>

#define FEMU_FTL_OPS_VERSION 1

/* fdp_strategy of a policy that leaves the FDP strategy to gc_strategy */
#define FEMU_FDP_FROM_GC_STRATEGY (-1)

struct line;
struct ppa;
struct ssd;

/*
 * Allocation class chosen for a new write. Page and dftl use DATA, or DATA and
 * HOT when hot/cold separation is on; a log-block scheme puts its overwrites in
 * LOG so they land in blocks of their own rather than mixed in with data.
 */
enum { FEMU_MAP_CLASS_DATA = 0, FEMU_MAP_CLASS_LOG = 1,
       FEMU_MAP_CLASS_HOT = 2, FEMU_MAP_CLASS_GC = 3 };

/**
 * struct map_write_plan - placement of one page write
 * @target_class: FEMU_MAP_CLASS_* of the write pointer for the new page
 * @may_need_reclaim: set by hybrid and fast; no caller reads it today
 */
struct map_write_plan {
    int target_class;
    bool may_need_reclaim;
};

/**
 * struct femu_mapping_ops - an L2P mapping scheme
 * @name: value of the mapping property
 * @uses_cmt: charge the demand-cached mapping table cost (ftl-map-cmt.c)
 * @uses_log_class: writes go through the LOG write pointer; the reserve grows
 *                  by one line and Streams are refused
 * @reclaim_per_page: run @reclaim after each page instead of once per
 *                    request; needs @needs_reclaim and @reclaim
 * @init: allocate ssd->map_priv; false when memory runs out, and
 *        ssd_init() then fails the device. Optional.
 * @exit: free ssd->map_priv; optional
 * @translate: the physical page of @lpn, or an unmapped ppa. Required.
 * @prepare_write: choose the class for a new page of @lpn. Required.
 * @commit_write: map @lpn to @new_ppa and invalidate the old page. Runs
 *                before the program of the new page. Required.
 * @needs_reclaim: whether the scheme's own structures need a merge; set
 *                 with @reclaim or not at all
 * @reclaim: merge; charges its own NAND operations and returns their
 *           latency in ns. hybrid does at most @budget merges; fast does
 *           one full pass and ignores @budget.
 * @gc_relocate_commit: map @lpn to the page GC moved it to. Required.
 * @trim: unmap @lpn on deallocate; NULL keeps the flat invalidation
 */
struct femu_mapping_ops {
    const char *name;
    bool uses_cmt;
    bool uses_log_class;
    bool reclaim_per_page;

    bool (*init)(struct ssd *ssd);
    void (*exit)(struct ssd *ssd);

    struct ppa (*translate)(struct ssd *ssd, uint64_t lpn);

    struct map_write_plan (*prepare_write)(struct ssd *ssd, uint64_t lpn,
                                           int io_type);
    void (*commit_write)(struct ssd *ssd, uint64_t lpn, struct ppa *new_ppa);

    bool (*needs_reclaim)(struct ssd *ssd);
    uint64_t (*reclaim)(struct ssd *ssd, int budget);

    void (*gc_relocate_commit)(struct ssd *ssd, uint64_t lpn,
                               struct ppa *old_ppa, struct ppa *new_ppa);

    void (*trim)(struct ssd *ssd, uint64_t lpn);
};

/**
 * struct femu_ftl_policy_ops - a GC victim policy
 * @name: value of the gc_policy property
 * @select_victim_line: take the next victim out of the victim queue, or
 *                      return NULL. With @force false it returns NULL when
 *                      its candidate has fewer invalid pages than
 *                      ssd_line_data_pgs() / 8. Required.
 * @by_close_order: the victim queue is ordered by close_seq instead of the
 *                  valid page count
 * @fdp_strategy: the reclaim unit strategy (GC_GLOBAL_*, above 0) that this
 *                name selects under FDP, or FEMU_FDP_FROM_GC_STRATEGY.
 *                0 is refused, so a table cannot omit it.
 */
struct femu_ftl_policy_ops {
    const char *name;
    struct line *(*select_victim_line)(struct ssd *ssd, bool force);
    bool by_close_order;
    int fdp_strategy;
};

/**
 * femu_mapping_ops_check - check a mapping scheme against the rules
 * @ops: the scheme
 * @why: set to the broken rule when the check fails; may be NULL
 *
 * Returns: true when @ops has a name, the four required hooks, both or none
 * of @needs_reclaim and @reclaim, and both when @reclaim_per_page is set.
 */
bool femu_mapping_ops_check(const struct femu_mapping_ops *ops,
                            const char **why);

/**
 * femu_ftl_policy_ops_check - check a GC victim policy against the rules
 * @ops: the policy
 * @why: set to the broken rule when the check fails; may be NULL
 *
 * Returns: true when @ops has a name, @select_victim_line, and an
 * @fdp_strategy that is above 0 or FEMU_FDP_FROM_GC_STRATEGY.
 */
bool femu_ftl_policy_ops_check(const struct femu_ftl_policy_ops *ops,
                               const char **why);

#endif
