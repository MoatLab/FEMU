/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Checks of the mapping scheme and GC victim policy tables (ftl-ops.h). This
 * file needs no QEMU or FTL code, so the unit test links it as it is.
 */
#include "qemu/osdep.h"
#include "ftl-ops.h"

bool femu_mapping_ops_check(const struct femu_mapping_ops *ops,
                            const char **why)
{
    const char *bad = NULL;

    if (!ops) {
        bad = "no table";
    } else if (!ops->name || !ops->name[0]) {
        bad = "no name";
    } else if (!ops->translate || !ops->prepare_write ||
               !ops->commit_write || !ops->gc_relocate_commit) {
        /* the data path and GC call these four with no check */
        bad = "a required hook is NULL";
    } else if (!ops->needs_reclaim != !ops->reclaim) {
        bad = "needs_reclaim and reclaim must come together";
    } else if (ops->reclaim_per_page && !ops->reclaim) {
        /* the per-page path calls both with no check */
        bad = "reclaim_per_page without reclaim";
    }
    if (bad && why) {
        *why = bad;
    }
    return !bad;
}

bool femu_ftl_policy_ops_check(const struct femu_ftl_policy_ops *ops,
                               const char **why)
{
    const char *bad = NULL;

    if (!ops) {
        bad = "no table";
    } else if (!ops->name || !ops->name[0]) {
        bad = "no name";
    } else if (!ops->select_victim_line) {
        bad = "no select_victim_line";
    } else if (ops->fdp_strategy <= 0 &&
               ops->fdp_strategy != FEMU_FDP_FROM_GC_STRATEGY) {
        /* 0 is what an omitted field reads as */
        bad = "no fdp_strategy";
    }
    if (bad && why) {
        *why = bad;
    }
    return !bad;
}
