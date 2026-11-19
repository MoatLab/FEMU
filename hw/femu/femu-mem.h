/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HW_FEMU_MEM_H
#define HW_FEMU_MEM_H

#include "qemu/atomic.h"
#include "qemu/error-report.h"

/*
 * Host memory accounting of a FEMU device.
 *
 * Each owner of large allocations (controller, subsystem, namespace, FTL)
 * holds one FemuMemAcct. Each allocation site charges the bytes it asked
 * for, and each free site releases the same number. A reader takes the
 * counters with qatomic_read() and walks no table, so it needs no lock of
 * the owner. The counters exclude allocator overhead and GLib internal
 * storage.
 *
 * Each counter is atomic on its own. A set of reads is not a snapshot: the
 * totals are exact only while the device is idle.
 */

typedef enum FemuMemCat {
    FEMU_MEM_BACKEND,   /* the data backend */
    FEMU_MEM_MAPPING,   /* L2P, reverse map, translation tables */
    FEMU_MEM_MEDIA,     /* NAND state, lines, zones, chunks */
    FEMU_MEM_VALUES,    /* key-value value arena */
    FEMU_MEM_INDEX,     /* key-value index and LSM state */
    FEMU_MEM_OTHER,     /* bitmaps, metadata, caches, the rest */
    FEMU_MEM__MAX,
} FemuMemCat;

typedef struct FemuMemAcct {
    uint64_t bytes[FEMU_MEM__MAX];
} FemuMemAcct;

static inline void femu_mem_charge(FemuMemAcct *a, FemuMemCat cat,
                                   uint64_t n)
{
    if (a && n) {
        qatomic_add(&a->bytes[cat], n);
    }
}

static inline void femu_mem_release(FemuMemAcct *a, FemuMemCat cat,
                                    uint64_t n)
{
    if (!a || !n) {
        return;
    }
#ifdef FEMU_FTL_ASSERT
    if (qatomic_read(&a->bytes[cat]) < n) {
        error_report("femu: release of %" PRIu64 " bytes from category %d "
                     "that holds %" PRIu64, n, cat,
                     qatomic_read(&a->bytes[cat]));
        abort();
    }
#endif
    qatomic_sub(&a->bytes[cat], n);
}

/* a number for an owner that has no name of its own, unique per process */
uint32_t femu_mem_next_id(void);

/* a buffer of @old bytes now holds @new bytes */
static inline void femu_mem_resize(FemuMemAcct *a, FemuMemCat cat,
                                   uint64_t old, uint64_t new)
{
    if (new >= old) {
        femu_mem_charge(a, cat, new - old);
    } else {
        femu_mem_release(a, cat, old - new);
    }
}

static inline uint64_t femu_mem_get(const FemuMemAcct *a, FemuMemCat cat)
{
    return qatomic_read(&a->bytes[cat]);
}

/*
 * The owner @what goes away: each charge must have its release. A sanitizer
 * build aborts on a counter that is not zero, so a free site that forgets
 * its release fails CI.
 */
static inline void femu_mem_check_empty(const FemuMemAcct *a,
                                        const char *what)
{
#ifdef FEMU_FTL_ASSERT
    for (int c = 0; c < FEMU_MEM__MAX; c++) {
        uint64_t left = qatomic_read(&a->bytes[c]);

        if (left) {
            error_report("femu: %s freed with %" PRIu64 " bytes charged "
                         "to category %d", what, left, c);
            abort();
        }
    }
#endif
}

#endif /* HW_FEMU_MEM_H */
