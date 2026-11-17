/*
 * QEMU PowerPC nest MMU model
 *
 * Copyright (c) 2025, IBM Corporation.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This code is licensed under the GPL version 2 or later. See the
 * COPYING file in the top-level directory.
 */

#ifndef PPC_PNV_NMMU_H
#define PPC_PNV_NMMU_H

#define TYPE_PNV_NMMU "pnv-nmmu"
#define PNV_NMMU(obj) OBJECT_CHECK(PnvNMMU, (obj), TYPE_PNV_NMMU)

typedef struct PnvNMMU {
    DeviceState parent;

    struct PnvChip *chip;

    MemoryRegion xscom_regs;
    uint32_t nmmu_id;
    uint64_t ptcr;
} PnvNMMU;

#endif /*PPC_PNV_NMMU_H */
