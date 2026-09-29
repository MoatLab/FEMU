/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FEMU_CXL_DER_H
#define FEMU_CXL_DER_H

#include "cache.h"
typedef struct FemuCylon FemuCylon;
typedef struct FemuCxlSsd FemuCxlSsd;

typedef struct FemuCxlDer {
    FemuCxlSsd *dev;
    GHashTable *maps;
    uint64_t ratio;
    uint64_t ratio_end;
    /* A restore failed and was reported; cleared once it maps again. */
    bool ratio_warned;
    bool available;
    bool warned;
    bool cylon;
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
    uint64_t fallbacks;
    uint64_t probes;
    uint64_t mapped;
} FemuCxlDer;

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
bool femu_cxl_der_sample(FemuCxlDer *der, uint64_t lpn);
void femu_cxl_der_clear(FemuCxlDer *der);
void femu_cxl_der_disable(FemuCxlDer *der);
void femu_cxl_der_fallback(FemuCxlDer *der, const char *reason);
void femu_cxl_der_destroy(FemuCxlDer *der);

#endif
