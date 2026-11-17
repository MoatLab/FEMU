/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * i.MX6UL LCDIF controller
 *
 * Copyright (c) 2026 Yucai Liu <1486344514@qq.com>
 */

#ifndef IMX6UL_LCDIF_H
#define IMX6UL_LCDIF_H

#include "hw/core/sysbus.h"
#include "qom/object.h"
#include "qemu/timer.h"
#include "ui/console.h"

#define TYPE_IMX6UL_LCDIF "imx6ul-lcdif"
#define IMX6UL_LCDIF_REGS_NUM ((0x230 >> 4) + 1)
OBJECT_DECLARE_SIMPLE_TYPE(IMX6ULLCDIFState, IMX6UL_LCDIF)

struct IMX6ULLCDIFState {
    SysBusDevice parent_obj;

    MemoryRegion iomem;
    MemoryRegionSection fbsection;
    qemu_irq irq;
    QemuConsole *con;
    QEMUTimer *frame_timer;
    uint32_t fb_base;
    uint32_t src_width;
    uint32_t rows;
    uint8_t src_bpp;
    bool invalidate;
    uint32_t regs[IMX6UL_LCDIF_REGS_NUM];
};

#endif /* IMX6UL_LCDIF_H */
