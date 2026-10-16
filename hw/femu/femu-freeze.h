/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HW_FEMU_FREEZE_H
#define HW_FEMU_FREEZE_H

#include "qapi/error.h"

/*
 * Stop the guest, vCPUs and clocks, while the host does work that a real
 * device does in parallel with the host, such as a CSD program run.
 *
 * A worker thread calls femu_freeze_begin() before the work and
 * femu_freeze_end() after it, with no lock held and never under the BQL.
 * The main loop does the stop and the restart, so overlapped users share one
 * stop. Under KVM the guest kvmclock and TSC skip the span of the stop, and
 * so does the device clock of femu_freeze_now().
 */

typedef struct FemuFreezeStats {
    uint64_t freezes;   /* stops done */
    uint64_t thaws;     /* restarts that hid the span of the stop */
    uint64_t skipped;   /* requests served with no stop */
    uint64_t lost;      /* restarts that could not hide the span */
    uint64_t expired;   /* stops ended by the time limit */
    uint64_t users;     /* begin calls not yet ended */
} FemuFreezeStats;

/* Check the accelerator and set up the service; main loop, BQL held. */
bool femu_freeze_init(Error **errp);

/*
 * Wait until the main loop has answered: the guest is stopped, or it could
 * not be stopped. Return false, at once, when *cancel becomes true.
 */
bool femu_freeze_begin(const bool *cancel, uint32_t max_ms);
void femu_freeze_end(void);

/* Wake every femu_freeze_begin() so it rechecks its cancel flag. */
void femu_freeze_kick(void);

/* The device clock, in ns: it does not move while the guest is stopped. */
int64_t femu_freeze_now(void);

void femu_freeze_stats(FemuFreezeStats *stats);

/* The KVM clock steps, in femu-freeze-kvm.c; no-ops without KVM. */
#define FEMU_FREEZE_KVM_FATAL   (-2)
bool femu_freeze_kvm_check(Error **errp);
int femu_freeze_kvm_save(void);
int femu_freeze_kvm_restore(uint64_t *span);

#endif
