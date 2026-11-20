/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Checks and walks over the mode handler tables (femu-ext-ops.h). This file
 * needs no QEMU code, so the unit test links it as it is.
 */
#include "qemu/osdep.h"
#include "femu-ext-ops.h"

bool femu_ext_ops_check(const FemuExtCtrlOps *ops, const char **why)
{
    const char *bad = NULL;

    if (!ops) {
        bad = "no table";
    } else if (!ops->name || !ops->name[0]) {
        bad = "no name";
    } else if (!ops->io_cmd) {
        /* the SLM and CP path calls io_cmd with no check */
        bad = "no io_cmd";
    } else if (ops->admin_cmd && ops->admin_cmd_cqe) {
        /* admin_cmd_cqe runs first, so admin_cmd would never run */
        bad = "both admin_cmd and admin_cmd_cqe";
    } else if (ops->state) {
        bad = "state set in the exported table";
    }
    if (bad && why) {
        *why = bad;
    }
    return !bad;
}

bool femu_ext_ops_check_set(const FemuExtCtrlOps *const *set, size_t nr,
                            const char **why)
{
    const char *bad = NULL;

    for (size_t i = 0; i < nr && !bad; i++) {
        for (size_t j = i + 1; j < nr && !bad; j++) {
            const FemuExtCtrlOps *a = set[i];
            const FemuExtCtrlOps *b = set[j];

            if (!strcmp(a->name, b->name)) {
                bad = "two tables share a name";
            } else if (a->start_ctrl && a->start_ctrl == b->start_ctrl) {
                bad = "two tables share start_ctrl";
            } else if (a->exit && a->exit == b->exit) {
                bad = "two tables share exit";
            }
        }
    }
    if (bad && why) {
        *why = bad;
    }
    return !bad;
}

size_t femu_ext_ops_distinct(const FemuExtCtrlOps *const *list, size_t nr,
                             const FemuExtCtrlOps **out, size_t max)
{
    size_t nout = 0;

    for (size_t i = 0; i < nr; i++) {
        const FemuExtCtrlOps *t = list[i];
        size_t j;

        if (!t || !t->name) {
            continue;
        }
        for (j = 0; j < nout; j++) {
            if (!strcmp(out[j]->name, t->name)) {
                break;
            }
        }
        if (j == nout && nout < max) {
            out[nout++] = t;
        }
    }
    return nout;
}
