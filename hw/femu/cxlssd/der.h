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
    bool available;
    bool warned;
    bool cylon;
    FemuCylon *fast;
    FemuCxlCache *cache;
    uint64_t remaps;
    uint64_t revocations;
    uint64_t fallbacks;
    uint64_t probes;
    uint64_t mapped;
} FemuCxlDer;

bool femu_cxl_ratio_selected(uint64_t ratio, uint64_t lpn);
void femu_cxl_der_init(FemuCxlDer *der, FemuCxlSsd *dev, const char *mode,
                       FemuCxlCache *cache);
bool femu_cxl_der_map(FemuCxlDer *der, uint64_t hpa, uint64_t dpa);
void femu_cxl_der_remove(FemuCxlDer *der, uint64_t lpn);
void femu_cxl_der_clear(FemuCxlDer *der);
void femu_cxl_der_fallback(FemuCxlDer *der, const char *reason);
void femu_cxl_der_destroy(FemuCxlDer *der);

#endif
