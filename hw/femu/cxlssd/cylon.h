/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FEMU_CXL_CYLON_H
#define FEMU_CXL_CYLON_H

#include "hw/cxl/cxl_host.h"

typedef struct FemuCylon FemuCylon;
typedef struct FemuCxlDer FemuCxlDer;

FemuCylon *femu_cylon_prepare(FemuCxlDer *der, const char **reason);
bool femu_cylon_map(FemuCxlDer *der, CXLFixedWindow *fw,
                    uint64_t hpa, uint64_t dpa);
void femu_cylon_remove(FemuCxlDer *der, uint64_t lpn);
void femu_cylon_destroy(FemuCxlDer *der);
#endif
