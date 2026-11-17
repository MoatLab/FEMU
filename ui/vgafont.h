/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef VGAFONT_H
#define VGAFONT_H

#include <stdint.h>

/* supports only vga 8x16 */
#define FONT_WIDTH 8
#define FONT_HEIGHT 16

extern const uint8_t vgafont16[256 * FONT_HEIGHT];

#endif
