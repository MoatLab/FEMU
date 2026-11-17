/*
 * QEMU target info initialization
 *
 * Copyright (c) Qualcomm
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This file is included by each file defining a TargetInfo structure and is
 * responsible for registering it.
 */

#ifndef QEMU_TARGET_INFO_INIT_H
#define QEMU_TARGET_INFO_INIT_H

#define DEFINE_TARGET_INFO_TYPE(info)                                       \
static void do_qemu_init_target_info(void)                                  \
{                                                                           \
    type_register_static(&info);                                            \
}                                                                           \
module_init(do_qemu_init_target_info, MODULE_INIT_TARGET_INFO)

#ifdef COMPILING_PER_TARGET
#ifdef CONFIG_USER_ONLY

/*
 * User mode does not support multiple targets in the same binary, so just
 * define target_info().
 */
#define target_info_init(ti_var)        \
const TargetInfo *target_info(void)     \
{                                       \
    return &ti_var;                     \
}

#else /* CONFIG_USER_ONLY */

#include "qemu/target-info-qom.h"
#include "qom/object.h"

#define target_info_init(ti_var)                                            \
static const TypeInfo target_info_qom_target_type_info = {                  \
    .name =  TYPE_TARGET_INFO"-"TARGET_NAME,                                \
    .parent = TYPE_TARGET_INFO,                                             \
    .instance_size = sizeof(TargetInfoQom),                                 \
    .class_size = sizeof(TargetInfoQomClass),                               \
    .class_data = &ti_var,                                                  \
};                                                                          \
DEFINE_TARGET_INFO_TYPE(target_info_qom_target_type_info)

#endif /* CONFIG_USER_ONLY */
#endif /* COMPILING_PER_TARGET */

#endif /* QEMU_TARGET_INFO_INIT_H */
