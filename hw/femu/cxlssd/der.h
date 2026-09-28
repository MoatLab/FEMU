/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FEMU_CXL_DER_H
#define FEMU_CXL_DER_H

#include "hw/cxl/cxl_device.h"

typedef struct FemuCxlDer {
    CXLType3Dev *dev;
    GHashTable *maps;
    bool available;
    uint64_t probes;
    uint64_t mapped;
} FemuCxlDer;

void femu_cxl_der_init(FemuCxlDer *der, CXLType3Dev *dev, bool enabled);
bool femu_cxl_der_map(FemuCxlDer *der, uint64_t hpa, uint64_t dpa);
void femu_cxl_der_remove(FemuCxlDer *der, uint64_t lpn);
void femu_cxl_der_clear(FemuCxlDer *der);
void femu_cxl_der_destroy(FemuCxlDer *der);

#endif
