/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (c) QEMU contributors
 */
#ifndef QEMU_CP437_H
#define QEMU_CP437_H

#include <stdint.h>

int unicode_to_cp437(uint32_t codepoint);

#endif /* QEMU_CP437_H */
