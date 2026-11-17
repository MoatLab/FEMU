/*
 * QEMU ARM CPU -- interface for the Arm v8M IDAU
 *
 * Copyright (c) 2018 Linaro Ltd
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "target/arm/tcg/idau.h"

static const TypeInfo idau_types[] = {
    {
        .name       = TYPE_IDAU_INTERFACE,
        .parent     = TYPE_INTERFACE,
        .class_size = sizeof(IDAUInterfaceClass),
    }
};

DEFINE_TYPES(idau_types)
