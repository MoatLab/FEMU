/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * ARM Generic Interrupt Controller using HVF platform support stub
 *
 * Copyright (c) 2026 Mohamed Mediouni
 *
 */
#include "qemu/osdep.h"
#include "hw/intc/arm_gicv3_common.h"
#include "migration/vmstate.h"
#include "qemu/typedefs.h"

static bool needed_never(void *opaque)
{
    return false;
}

const VMStateDescription vmstate_gicv3_hvf = {
    .name = "arm_gicv3/hvf_gic_state",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = needed_never,
    .version_id = 1,
    .minimum_version_id = 1,
};
