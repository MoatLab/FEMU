// Common svga mode definitions
//
// Copyright (C) 2012  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2011  Julian Pidancet <julian.pidancet@citrix.com>
//  Copyright (C) 2002 Jeroen Janssen
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "stdvga.h" // SEG_GRAPH
#include "vgabios.h" // VAR16

#include "svgamodes.h"

struct generic_svga_mode svga_modes[] VAR16 = {
    /* standard modes */
    { 0x100, { MM_PACKED, 640,  400,  8,  8, 16, SEG_GRAPH } },
    { 0x101, { MM_PACKED, 640,  480,  8,  8, 16, SEG_GRAPH } },
    { 0x102, { MM_PLANAR, 800,  600,  4,  8, 16, SEG_GRAPH } },
    { 0x103, { MM_PACKED, 800,  600,  8,  8, 16, SEG_GRAPH } },
    { 0x104, { MM_PLANAR, 1024, 768,  4,  8, 16, SEG_GRAPH } },
    { 0x105, { MM_PACKED, 1024, 768,  8,  8, 16, SEG_GRAPH } },
    { 0x106, { MM_PLANAR, 1280, 1024, 4,  8, 16, SEG_GRAPH } },
    { 0x107, { MM_PACKED, 1280, 1024, 8,  8, 16, SEG_GRAPH } },
    { 0x10D, { MM_DIRECT, 320,  200,  15, 8, 16, SEG_GRAPH } },
    { 0x10E, { MM_DIRECT, 320,  200,  16, 8, 16, SEG_GRAPH } },
    { 0x10F, { MM_DIRECT, 320,  200,  24, 8, 16, SEG_GRAPH } },
    { 0x110, { MM_DIRECT, 640,  480,  15, 8, 16, SEG_GRAPH } },
    { 0x111, { MM_DIRECT, 640,  480,  16, 8, 16, SEG_GRAPH } },
    { 0x112, { MM_DIRECT, 640,  480,  24, 8, 16, SEG_GRAPH } },
    { 0x113, { MM_DIRECT, 800,  600,  15, 8, 16, SEG_GRAPH } },
    { 0x114, { MM_DIRECT, 800,  600,  16, 8, 16, SEG_GRAPH } },
    { 0x115, { MM_DIRECT, 800,  600,  24, 8, 16, SEG_GRAPH } },
    { 0x116, { MM_DIRECT, 1024, 768,  15, 8, 16, SEG_GRAPH } },
    { 0x117, { MM_DIRECT, 1024, 768,  16, 8, 16, SEG_GRAPH } },
    { 0x118, { MM_DIRECT, 1024, 768,  24, 8, 16, SEG_GRAPH } },
    { 0x119, { MM_DIRECT, 1280, 1024, 15, 8, 16, SEG_GRAPH } },
    { 0x11A, { MM_DIRECT, 1280, 1024, 16, 8, 16, SEG_GRAPH } },
    { 0x11B, { MM_DIRECT, 1280, 1024, 24, 8, 16, SEG_GRAPH } },
    { 0x11C, { MM_PACKED, 1600, 1200, 8,  8, 16, SEG_GRAPH } },
    { 0x11D, { MM_DIRECT, 1600, 1200, 15, 8, 16, SEG_GRAPH } },
    { 0x11E, { MM_DIRECT, 1600, 1200, 16, 8, 16, SEG_GRAPH } },
    { 0x11F, { MM_DIRECT, 1600, 1200, 24, 8, 16, SEG_GRAPH } },
    /* other modes */
    { 0x140, { MM_DIRECT, 320,  200,  32, 8, 16, SEG_GRAPH } },
    { 0x141, { MM_DIRECT, 640,  400,  32, 8, 16, SEG_GRAPH } },
    { 0x142, { MM_DIRECT, 640,  480,  32, 8, 16, SEG_GRAPH } },
    { 0x143, { MM_DIRECT, 800,  600,  32, 8, 16, SEG_GRAPH } },
    { 0x144, { MM_DIRECT, 1024, 768,  32, 8, 16, SEG_GRAPH } },
    { 0x145, { MM_DIRECT, 1280, 1024, 32, 8, 16, SEG_GRAPH } },
    { 0x146, { MM_PACKED, 320,  200,  8,  8, 16, SEG_GRAPH } },
    { 0x147, { MM_DIRECT, 1600, 1200, 32, 8, 16, SEG_GRAPH } },
    { 0x148, { MM_PACKED, 1152, 864,  8,  8, 16, SEG_GRAPH } },
    { 0x149, { MM_DIRECT, 1152, 864,  15, 8, 16, SEG_GRAPH } },
    { 0x14a, { MM_DIRECT, 1152, 864,  16, 8, 16, SEG_GRAPH } },
    { 0x14b, { MM_DIRECT, 1152, 864,  24, 8, 16, SEG_GRAPH } },
    { 0x14c, { MM_DIRECT, 1152, 864,  32, 8, 16, SEG_GRAPH } },
    { 0x175, { MM_DIRECT, 1280, 768,  16, 8, 16, SEG_GRAPH } },
    { 0x176, { MM_DIRECT, 1280, 768,  24, 8, 16, SEG_GRAPH } },
    { 0x177, { MM_DIRECT, 1280, 768,  32, 8, 16, SEG_GRAPH } },
    { 0x178, { MM_DIRECT, 1280, 800,  16, 8, 16, SEG_GRAPH } },
    { 0x179, { MM_DIRECT, 1280, 800,  24, 8, 16, SEG_GRAPH } },
    { 0x17a, { MM_DIRECT, 1280, 800,  32, 8, 16, SEG_GRAPH } },
    { 0x17b, { MM_DIRECT, 1280, 960,  16, 8, 16, SEG_GRAPH } },
    { 0x17c, { MM_DIRECT, 1280, 960,  24, 8, 16, SEG_GRAPH } },
    { 0x17d, { MM_DIRECT, 1280, 960,  32, 8, 16, SEG_GRAPH } },
    { 0x17e, { MM_DIRECT, 1440, 900,  16, 8, 16, SEG_GRAPH } },
    { 0x17f, { MM_DIRECT, 1440, 900,  24, 8, 16, SEG_GRAPH } },
    { 0x180, { MM_DIRECT, 1440, 900,  32, 8, 16, SEG_GRAPH } },
    { 0x181, { MM_DIRECT, 1400, 1050, 16, 8, 16, SEG_GRAPH } },
    { 0x182, { MM_DIRECT, 1400, 1050, 24, 8, 16, SEG_GRAPH } },
    { 0x183, { MM_DIRECT, 1400, 1050, 32, 8, 16, SEG_GRAPH } },
    { 0x184, { MM_DIRECT, 1680, 1050, 16, 8, 16, SEG_GRAPH } },
    { 0x185, { MM_DIRECT, 1680, 1050, 24, 8, 16, SEG_GRAPH } },
    { 0x186, { MM_DIRECT, 1680, 1050, 32, 8, 16, SEG_GRAPH } },
    { 0x187, { MM_DIRECT, 1920, 1200, 16, 8, 16, SEG_GRAPH } },
    { 0x188, { MM_DIRECT, 1920, 1200, 24, 8, 16, SEG_GRAPH } },
    { 0x189, { MM_DIRECT, 1920, 1200, 32, 8, 16, SEG_GRAPH } },
    { 0x18a, { MM_DIRECT, 2560, 1600, 16, 8, 16, SEG_GRAPH } },
    { 0x18b, { MM_DIRECT, 2560, 1600, 24, 8, 16, SEG_GRAPH } },
    { 0x18c, { MM_DIRECT, 2560, 1600, 32, 8, 16, SEG_GRAPH } },
    { 0x18d, { MM_DIRECT, 1280, 720,  16, 8, 16, SEG_GRAPH } },
    { 0x18e, { MM_DIRECT, 1280, 720,  24, 8, 16, SEG_GRAPH } },
    { 0x18f, { MM_DIRECT, 1280, 720,  32, 8, 16, SEG_GRAPH } },
    { 0x190, { MM_DIRECT, 1920, 1080, 16, 8, 16, SEG_GRAPH } },
    { 0x191, { MM_DIRECT, 1920, 1080, 24, 8, 16, SEG_GRAPH } },
    { 0x192, { MM_DIRECT, 1920, 1080, 32, 8, 16, SEG_GRAPH } },

    /* custom resolutions for 16:9 displays */
    { 0x193, { MM_DIRECT, 1600,  900, 16, 8, 16, SEG_GRAPH } },
    { 0x194, { MM_DIRECT, 1600,  900, 24, 8, 16, SEG_GRAPH } },
    { 0x195, { MM_DIRECT, 1600,  900, 32, 8, 16, SEG_GRAPH } },
    { 0x196, { MM_DIRECT, 2560, 1440, 16, 8, 16, SEG_GRAPH } },
    { 0x197, { MM_DIRECT, 2560, 1440, 24, 8, 16, SEG_GRAPH } },
    { 0x198, { MM_DIRECT, 2560, 1440, 32, 8, 16, SEG_GRAPH } },
};
unsigned int svga_mcount VAR16 = ARRAY_SIZE(svga_modes);
