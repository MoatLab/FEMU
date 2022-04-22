/*
 * QEMU Hypervisor.framework (HVF) support
 *
 * Copyright Google Inc., 2017
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

/* header to be included in non-HVF-specific code */

#ifndef HVF_H
#define HVF_H

#include "qemu/accel.h"
#include "qom/object.h"

#ifdef NEED_CPU_H

#ifdef CONFIG_HVF
uint32_t hvf_get_supported_cpuid(uint32_t func, uint32_t idx,
                                 int reg);
extern bool hvf_allowed;
#define hvf_enabled() (hvf_allowed)
#else /* !CONFIG_HVF */
#define hvf_enabled() 0
#define hvf_get_supported_cpuid(func, idx, reg) 0
#endif /* !CONFIG_HVF */

#endif /* NEED_CPU_H */

#define TYPE_HVF_ACCEL ACCEL_CLASS_NAME("hvf")

typedef struct HVFState HVFState;
DECLARE_INSTANCE_CHECKER(HVFState, HVF_STATE,
                         TYPE_HVF_ACCEL)

#endif
