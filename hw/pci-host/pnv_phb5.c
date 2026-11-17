/*
 * QEMU PowerPC PowerNV (POWER10) PHB5 model
 *
 * Copyright (c) 2018-2026, IBM Corporation.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/pci-host/pnv_phb4.h"

static const TypeInfo pnv_phb5_type_info = {
    .name          = TYPE_PNV_PHB5,
    .parent        = TYPE_PNV_PHB4,
    .instance_size = sizeof(PnvPHB4),
};

static void pnv_phb5_register_types(void)
{
    type_register_static(&pnv_phb5_type_info);
}

type_init(pnv_phb5_register_types);
