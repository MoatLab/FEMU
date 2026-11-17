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

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "hw/core/qdev-properties.h"

#include "hw/ppc/pnv.h"
#include "hw/ppc/pnv_xscom.h"
#include "hw/ppc/pnv_nmmu.h"
#include "hw/ppc/fdt.h"

#include <libfdt.h>

#define NMMU_XLAT_CTL_PTCR 0xb

static uint64_t pnv_nmmu_xscom_read(void *opaque, hwaddr addr, unsigned size)
{
    PnvNMMU *nmmu = PNV_NMMU(opaque);
    int reg = addr >> 3;
    uint64_t val;

    if (reg == NMMU_XLAT_CTL_PTCR) {
        val = nmmu->ptcr;
    } else {
        val = 0xffffffffffffffffull;
        qemu_log_mask(LOG_UNIMP, "nMMU: xscom read at 0x%" PRIx32 "\n", reg);
    }
    return val;
}

static void pnv_nmmu_xscom_write(void *opaque, hwaddr addr,
                                 uint64_t val, unsigned size)
{
    PnvNMMU *nmmu = PNV_NMMU(opaque);
    int reg = addr >> 3;

    if (reg == NMMU_XLAT_CTL_PTCR) {
        nmmu->ptcr = val;
    } else {
        qemu_log_mask(LOG_UNIMP, "nMMU: xscom write at 0x%" PRIx32 "\n", reg);
    }
}

static const MemoryRegionOps pnv_nmmu_xscom_ops = {
    .read = pnv_nmmu_xscom_read,
    .write = pnv_nmmu_xscom_write,
    .valid.min_access_size = 8,
    .valid.max_access_size = 8,
    .impl.min_access_size = 8,
    .impl.max_access_size = 8,
    .endianness = DEVICE_BIG_ENDIAN,
};

static void pnv_nmmu_realize(DeviceState *dev, Error **errp)
{
    PnvNMMU *nmmu = PNV_NMMU(dev);

    assert(nmmu->chip);

    /* NMMU xscom region */
    pnv_xscom_region_init(&nmmu->xscom_regs, OBJECT(nmmu),
                          &pnv_nmmu_xscom_ops, nmmu,
                          "xscom-nmmu",
                          PNV10_XSCOM_NMMU_SIZE);
}

static int pnv_nmmu_dt_xscom(PnvXScomInterface *dev, void *fdt,
                             int offset)
{
    PnvNMMU *nmmu = PNV_NMMU(dev);
    char *name;
    int nmmu_offset;
    const char compat[] = "ibm,power9-nest-mmu";
    uint32_t nmmu_pcba = PNV10_XSCOM_NEST0_MMU_BASE + nmmu->nmmu_id * 0x1000000;
    uint32_t reg[2] = {
        cpu_to_be32(nmmu_pcba),
        cpu_to_be32(PNV10_XSCOM_NMMU_SIZE)
    };

    name = g_strdup_printf("nmmu@%x", nmmu_pcba);
    nmmu_offset = fdt_add_subnode(fdt, offset, name);
    _FDT(nmmu_offset);
    g_free(name);

    _FDT(fdt_setprop(fdt, nmmu_offset, "reg", reg, sizeof(reg)));
    _FDT(fdt_setprop(fdt, nmmu_offset, "compatible", compat, sizeof(compat)));
    return 0;
}

static const Property pnv_nmmu_properties[] = {
    DEFINE_PROP_UINT32("nmmu_id", PnvNMMU, nmmu_id, 0),
    DEFINE_PROP_LINK("chip", PnvNMMU, chip, TYPE_PNV_CHIP, PnvChip *),
};

static void pnv_nmmu_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PnvXScomInterfaceClass *xscomc = PNV_XSCOM_INTERFACE_CLASS(klass);

    xscomc->dt_xscom = pnv_nmmu_dt_xscom;

    dc->desc = "PowerNV nest MMU";
    dc->realize = pnv_nmmu_realize;
    device_class_set_props(dc, pnv_nmmu_properties);
}

static const TypeInfo pnv_nmmu_info = {
    .name          = TYPE_PNV_NMMU,
    .parent        = TYPE_DEVICE,
    .instance_size = sizeof(PnvNMMU),
    .class_init    = pnv_nmmu_class_init,
    .interfaces    = (InterfaceInfo[]) {
        { TYPE_PNV_XSCOM_INTERFACE },
        { }
    }
};

static void pnv_nmmu_register_types(void)
{
    type_register_static(&pnv_nmmu_info);
}

type_init(pnv_nmmu_register_types);
