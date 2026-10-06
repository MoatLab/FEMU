/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FEMU_CXL_DER_H
#define FEMU_CXL_DER_H

#include "cache.h"
typedef struct FemuCylon FemuCylon;
typedef struct FemuCxlSsd FemuCxlSsd;

typedef struct FemuCxlDer {
    FemuCxlSsd *dev;
    GHashTable *maps;
    /*
     * Cylon version 2: pages whose leaf got the emulation marker, because
     * the caching API kept them uncached. Their leaves go back to zero when
     * they become admissible again; see femu_cxl_der_unmark().
     */
    GHashTable *marked;
    uint64_t ratio;
    uint64_t ratio_end;
    /* A restore failed and was reported; cleared once it maps again. */
    bool ratio_warned;
    bool available;
    bool warned;
    bool cylon;
    /* der=memslot: mappings are memory regions, changed under the BQL. */
    bool memslot;
    FemuCylon *fast;
    FemuCxlCache *cache;
    /* Windows that route here, valid for one invalidation generation. */
    GPtrArray *windows;
    uint64_t windows_generation;
    bool windows_valid;
    /* One-page cache aliases, oldest first, for budget replacement. */
    GQueue installed;
    uint32_t replace_rate;
    unsigned replace_backoff;
    unsigned replace_clean;
    int64_t replace_last;
    uint64_t replacements;
    uint64_t remaps;
    uint64_t revocations;
    uint64_t quiet_revocations;
    uint64_t fallbacks;
    uint64_t probes;
    uint64_t mapped;
    /* Cylon: the host kernel hands unemulatable accesses to FEMU. */
    bool emul_exit;
    /* Pages filled and mapped for such accesses, and the ones that failed. */
    uint64_t emul_fills;
    uint64_t emul_failures;
    /* Of @emul_fills, those for code executed from an unmapped page. */
    uint64_t emul_fetch_fills;
    /* Version 2 (per VM, see cylon_v2): cold pages exit with their type. */
    uint64_t fault_reads;
    uint64_t fault_writes;
    uint64_t fault_fetches;
    uint64_t fault_walks;
    /* Pages handed back to KVM's emulator because they cannot be mapped. */
    uint64_t fault_emulated;
    /* Protections released early: the instruction's bound was full. */
    uint64_t fault_unprotected;
    /* Fills refused because the instruction's own pages fill the set. */
    uint64_t fault_conflicts;
    /*
     * Pages mapped without a cache way for an instruction KVM cannot run,
     * or (version 2) for any page that cannot keep a way.
     */
    uint64_t fault_overflows;
    /* Of @fault_overflows, uncached pages mapped for a walk or a delivery. */
    uint64_t fault_forced;
    /* Version 2 exits made by an event delivery. */
    uint64_t fault_deliveries;
    /* Emulation markers refused by the version 2 rule (a defect if not 0). */
    uint64_t fault_marker_refused;
    /* Fault exits that were served again under the BQL. */
    uint64_t fault_bql;
    /*
     * Cylon version 2: most pages a full revocation may take (the victim
     * included), its TLB flushes, the pages revoked ahead of their
     * eviction, and those mapped again before it.
     */
    uint32_t revoke_batch;
    uint64_t revoke_flushes;
    uint64_t revoked_ahead;
    uint64_t ahead_remaps;
} FemuCxlDer;

/* Upper bound of cylon-revoke-batch. */
#define FEMU_CXL_REVOKE_BATCH_MAX 256

/*
 * Cylon's direct ratios leave every period-th page on MMIO; zero means no
 * ratio and one means every page.
 */
static inline uint64_t femu_cxl_ratio_period(uint64_t ratio)
{
    switch (ratio) {
    case 0:
        return 0;
    case 50:
        return 2;
    case 75:
        return 4;
    case 90:
        return 10;
    case 95:
        return 20;
    case 97:
        return 33;
    case 98:
        return 50;
    case 99:
        return 100;
    case 995:
        return 200;
    case 999:
        return 1000;
    default:
        return 1;
    }
}

static inline bool femu_cxl_ratio_selected(uint64_t ratio, uint64_t lpn)
{
    uint64_t period = femu_cxl_ratio_period(ratio);

    return period == 1 || (period && lpn % period != 0);
}

void femu_cxl_der_init(FemuCxlDer *der, FemuCxlSsd *dev, const char *mode,
                       FemuCxlCache *cache);
bool femu_cxl_der_map(FemuCxlDer *der, uint64_t hpa, uint64_t dpa,
                      FemuCxlEntry *e);
void femu_cxl_der_remove(FemuCxlDer *der, uint64_t lpn);
unsigned femu_cxl_der_batch(FemuCxlDer *der, uint64_t lpn);
void femu_cxl_der_remove_batch(FemuCxlDer *der, uint64_t lpn,
                               const uint64_t *ahead, unsigned n);
bool femu_cxl_der_sample(FemuCxlDer *der, uint64_t lpn);
void femu_cxl_der_precheck(FemuCxlDer *der, uint64_t lpn);
void femu_cxl_der_precheck_run(void);
void femu_cxl_der_precheck_drop(void);
void femu_cxl_der_clear(FemuCxlDer *der);
void femu_cxl_der_unmark(FemuCxlDer *der);
void femu_cxl_der_disable(FemuCxlDer *der);
void femu_cxl_der_fallback(FemuCxlDer *der, const char *reason);
void femu_cxl_der_destroy(FemuCxlDer *der);

#endif
