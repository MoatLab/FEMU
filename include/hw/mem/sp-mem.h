/*
 * Specific Purpose Memory (SPM) device
 *
 * TYPE_MEMORY_DEVICE subclass for boot-time-only memory exposed to the
 * guest as an E820 SOFT_RESERVED range with a SRAT memory-affinity entry.
 *
 * Copyright (c) 2026 Advanced Micro Devices, Inc.
 *
 * Authors:
 *  FangSheng Huang <FangSheng.Huang@amd.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef QEMU_SP_MEM_H
#define QEMU_SP_MEM_H

#include "hw/core/qdev.h"
#include "qom/object.h"

#define TYPE_SP_MEM "sp-mem"

OBJECT_DECLARE_SIMPLE_TYPE(SpMemDevice, SP_MEM)

struct SpMemDevice {
    DeviceState parent_obj;

    HostMemoryBackend *hostmem;
    uint32_t node;
    uint64_t addr;
};

#endif /* QEMU_SP_MEM_H */
