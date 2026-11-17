/*
 * Specific Purpose Memory (SPM) device
 *
 * Copyright (c) 2026 Advanced Micro Devices, Inc.
 *
 * Authors:
 *  FangSheng Huang <FangSheng.Huang@amd.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/module.h"
#include "qapi/error.h"
#include "hw/core/qdev-properties.h"
#include "hw/core/qdev.h"
#include "hw/mem/sp-mem.h"
#include "hw/mem/memory-device.h"
#include "system/hostmem.h"

#define SP_MEM_MEMDEV_PROP    "memdev"
#define SP_MEM_NODE_PROP      "node"
#define SP_MEM_ADDR_PROP      "addr"

static const Property sp_mem_properties[] = {
    DEFINE_PROP_LINK(SP_MEM_MEMDEV_PROP, SpMemDevice, hostmem,
                     TYPE_MEMORY_BACKEND, HostMemoryBackend *),
    DEFINE_PROP_UINT32(SP_MEM_NODE_PROP, SpMemDevice, node, 0),
    DEFINE_PROP_UINT64(SP_MEM_ADDR_PROP, SpMemDevice, addr, 0),
};

static uint64_t sp_mem_get_addr(const MemoryDeviceState *md)
{
    return object_property_get_uint(OBJECT(md), SP_MEM_ADDR_PROP,
                                    &error_abort);
}

static void sp_mem_set_addr(MemoryDeviceState *md, uint64_t addr,
                            Error **errp)
{
    object_property_set_uint(OBJECT(md), SP_MEM_ADDR_PROP, addr, errp);
}

static MemoryRegion *sp_mem_get_memory_region(MemoryDeviceState *md,
                                              Error **errp)
{
    SpMemDevice *spm = SP_MEM(md);

    if (!spm->hostmem) {
        error_setg(errp, "'%s' property must be set", SP_MEM_MEMDEV_PROP);
        return NULL;
    }
    return host_memory_backend_get_memory(spm->hostmem);
}

static void sp_mem_fill_device_info(const MemoryDeviceState *md,
                                    MemoryDeviceInfo *info)
{
    SpMemDeviceInfo *di = g_new0(SpMemDeviceInfo, 1);
    SpMemDevice *spm = SP_MEM(md);
    DeviceState *dev = DEVICE(md);

    di->id = dev->id ? g_strdup(dev->id) : NULL;
    di->addr = spm->addr;
    di->size = memory_region_size(
                   host_memory_backend_get_memory(spm->hostmem));
    di->node = spm->node;
    di->memdev = object_get_canonical_path(OBJECT(spm->hostmem));

    info->u.sp_mem.data = di;
    info->type = MEMORY_DEVICE_INFO_KIND_SP_MEM;
}

static void sp_mem_realize(DeviceState *dev, Error **errp)
{
    SpMemDevice *spm = SP_MEM(dev);

    if (!spm->hostmem) {
        error_setg(errp, "'%s' property is required", SP_MEM_MEMDEV_PROP);
        return;
    }
    if (host_memory_backend_is_mapped(spm->hostmem)) {
        error_setg(errp, "memory backend '%s' is already in use",
                   object_get_canonical_path_component(OBJECT(spm->hostmem)));
        return;
    }
    host_memory_backend_set_mapped(spm->hostmem, true);
}

static void sp_mem_unrealize(DeviceState *dev)
{
    SpMemDevice *spm = SP_MEM(dev);

    host_memory_backend_set_mapped(spm->hostmem, false);
}

static void sp_mem_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    MemoryDeviceClass *mdc = MEMORY_DEVICE_CLASS(oc);

    dc->desc = "SPM (Specific Purpose Memory) device";
    dc->hotpluggable = false;
    dc->realize = sp_mem_realize;
    dc->unrealize = sp_mem_unrealize;
    device_class_set_props(dc, sp_mem_properties);

    mdc->get_addr            = sp_mem_get_addr;
    mdc->set_addr            = sp_mem_set_addr;
    mdc->get_memory_region   = sp_mem_get_memory_region;
    mdc->get_plugged_size    = memory_device_get_region_size;
    mdc->fill_device_info    = sp_mem_fill_device_info;
}

static const TypeInfo sp_mem_types[] = {
    {
        .name          = TYPE_SP_MEM,
        .parent        = TYPE_DEVICE,
        .class_init    = sp_mem_class_init,
        .instance_size = sizeof(SpMemDevice),
        .interfaces    = (InterfaceInfo[]) {
            { TYPE_MEMORY_DEVICE },
            { }
        },
    },
};

DEFINE_TYPES(sp_mem_types)
