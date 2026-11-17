/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * i.MX6UL LCDIF controller
 *
 * Copyright (c) 2026 Yucai Liu <1486344514@qq.com>
 */

#include "qemu/osdep.h"
#include "hw/display/imx6ul_lcdif.h"
#include "hw/core/irq.h"
#include "hw/core/registerfields.h"
#include "hw/display/framebuffer.h"
#include "migration/vmstate.h"
#include "system/address-spaces.h"
#include "qemu/module.h"
#include "qemu/units.h"
#include "ui/pixel_ops.h"

#define LCDIF_MMIO_SIZE             (16 * KiB)
#define LCDIF_RESET_CTRL1           0x000f0000

REG32(CTRL, 0x00)
    FIELD(CTRL, RUN, 0, 1)
    FIELD(CTRL, WORD_LENGTH, 8, 2)
REG32(CTRL1, 0x10)
    FIELD(CTRL1, CUR_FRAME_DONE_IRQ, 9, 1)
    FIELD(CTRL1, CUR_FRAME_DONE_IRQ_EN, 13, 1)
    FIELD(CTRL1, BYTE_PACKING_FORMAT, 16, 4)
REG32(V4_TRANSFER_COUNT, 0x30)
    FIELD(V4_TRANSFER_COUNT, H_COUNT, 0, 16)
    FIELD(V4_TRANSFER_COUNT, V_COUNT, 16, 16)
REG32(V4_CUR_BUF, 0x40)
REG32(V4_NEXT_BUF, 0x50)
REG32(AS_NEXT_BUF, 0x230)

#define REG_SET                     0x4
#define REG_CLR                     0x8
#define REG_TOG                     0xc

#define CTRL_WORD_LENGTH_16         0
#define CTRL_WORD_LENGTH_24         3

#define FRAME_PERIOD_NS             (16 * 1000 * 1000ULL)

enum IMX6ULLCDIFReg {
    IMX6UL_LCDIF_REG_CTRL = A_CTRL >> 4,
    IMX6UL_LCDIF_REG_CTRL1 = A_CTRL1 >> 4,
    IMX6UL_LCDIF_REG_V4_TRANSFER_COUNT = A_V4_TRANSFER_COUNT >> 4,
    IMX6UL_LCDIF_REG_V4_CUR_BUF = A_V4_CUR_BUF >> 4,
    IMX6UL_LCDIF_REG_V4_NEXT_BUF = A_V4_NEXT_BUF >> 4,
    IMX6UL_LCDIF_REG_AS_NEXT_BUF = A_AS_NEXT_BUF >> 4,
};

static inline bool imx6ul_lcdif_reg_exists(hwaddr reg)
{
    return (reg >> 4) < IMX6UL_LCDIF_REGS_NUM;
}

static inline bool imx6ul_lcdif_reg_has_setclr(hwaddr reg)
{
    switch (reg) {
    case A_CTRL:
    case A_CTRL1:
        return true;
    default:
        return false;
    }
}

static inline bool imx6ul_lcdif_is_running(IMX6ULLCDIFState *s)
{
    uint32_t ctrl = s->regs[IMX6UL_LCDIF_REG_CTRL];

    return FIELD_EX32(ctrl, CTRL, RUN);
}

static inline bool imx6ul_lcdif_frame_done_pending(IMX6ULLCDIFState *s)
{
    uint32_t ctrl1 = s->regs[IMX6UL_LCDIF_REG_CTRL1];

    return FIELD_EX32(ctrl1, CTRL1, CUR_FRAME_DONE_IRQ);
}

static void imx6ul_lcdif_schedule_frame(IMX6ULLCDIFState *s)
{
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);

    timer_mod(s->frame_timer, now + FRAME_PERIOD_NS);
}

static void imx6ul_lcdif_maybe_schedule_frame(IMX6ULLCDIFState *s)
{
    if (imx6ul_lcdif_is_running(s) && !imx6ul_lcdif_frame_done_pending(s)) {
        imx6ul_lcdif_schedule_frame(s);
    } else {
        timer_del(s->frame_timer);
    }
}

static void imx6ul_lcdif_update_irq(IMX6ULLCDIFState *s)
{
    uint32_t ctrl1 = s->regs[IMX6UL_LCDIF_REG_CTRL1];
    bool level = FIELD_EX32(ctrl1, CTRL1, CUR_FRAME_DONE_IRQ_EN) &&
                 FIELD_EX32(ctrl1, CTRL1, CUR_FRAME_DONE_IRQ);

    qemu_set_irq(s->irq, level);
}

static void imx6ul_lcdif_frame_done(IMX6ULLCDIFState *s)
{
    uint32_t ctrl1 = s->regs[IMX6UL_LCDIF_REG_CTRL1];

    ctrl1 = FIELD_DP32(ctrl1, CTRL1, CUR_FRAME_DONE_IRQ, 1);
    s->regs[IMX6UL_LCDIF_REG_CTRL1] = ctrl1;
    imx6ul_lcdif_update_irq(s);
}

static void imx6ul_lcdif_draw_line_rgb565(void *opaque, uint8_t *dst,
                                          const uint8_t *src, int width,
                                          int dststep)
{
    uint32_t *dst32 = (uint32_t *)dst;
    int i;

    for (i = 0; i < width; i++) {
        uint16_t pixel = lduw_le_p(src);
        uint8_t r = ((pixel >> 11) & 0x1f) << 3;
        uint8_t g = ((pixel >> 5) & 0x3f) << 2;
        uint8_t b = (pixel & 0x1f) << 3;

        *dst32++ = rgb_to_pixel32(r, g, b);
        src += 2;
    }
}

static void imx6ul_lcdif_draw_line_xrgb8888(void *opaque, uint8_t *dst,
                                            const uint8_t *src, int width,
                                            int dststep)
{
    uint32_t *dst32 = (uint32_t *)dst;
    int i;

    for (i = 0; i < width; i++) {
        uint32_t pixel = ldl_le_p(src);
        uint8_t r = (pixel >> 16) & 0xff;
        uint8_t g = (pixel >> 8) & 0xff;
        uint8_t b = pixel & 0xff;

        *dst32++ = rgb_to_pixel32(r, g, b);
        src += 4;
    }
}

static bool imx6ul_lcdif_update_display(void *opaque)
{
    IMX6ULLCDIFState *s = opaque;
    DisplaySurface *surface = qemu_console_surface(s->con);
    uint32_t transfer_count = s->regs[IMX6UL_LCDIF_REG_V4_TRANSFER_COUNT];
    uint32_t width = FIELD_EX32(transfer_count, V4_TRANSFER_COUNT, H_COUNT);
    uint32_t height = FIELD_EX32(transfer_count, V4_TRANSFER_COUNT, V_COUNT);
    uint32_t ctrl = s->regs[IMX6UL_LCDIF_REG_CTRL];
    uint32_t frame_base = s->regs[IMX6UL_LCDIF_REG_V4_CUR_BUF];
    drawfn fn;
    int first = 0;
    int last = 0;
    int src_width;

    if (!imx6ul_lcdif_is_running(s) || width == 0 || height == 0) {
        return true;
    }

    switch (FIELD_EX32(ctrl, CTRL, WORD_LENGTH)) {
    case CTRL_WORD_LENGTH_16:
        s->src_bpp = 2;
        fn = imx6ul_lcdif_draw_line_rgb565;
        break;
    case CTRL_WORD_LENGTH_24:
        s->src_bpp = 4;
        fn = imx6ul_lcdif_draw_line_xrgb8888;
        break;
    default:
        return true;
    }

    if (surface_width(surface) != width || surface_height(surface) != height) {
        qemu_console_resize(s->con, width, height);
        surface = qemu_console_surface(s->con);
        s->invalidate = true;
    }

    src_width = width * s->src_bpp;
    if (s->invalidate || s->fb_base != frame_base ||
        s->src_width != src_width || s->rows != height) {
        framebuffer_update_memory_section(&s->fbsection, get_system_memory(),
                                          frame_base, height, src_width);
        s->fb_base = frame_base;
        s->src_width = src_width;
        s->rows = height;
    }

    framebuffer_update_display(surface, &s->fbsection, width, height,
                               src_width, surface_stride(surface), 0,
                               s->invalidate, fn, s, &first, &last);
    if (first >= 0) {
        qemu_console_update(s->con, 0, first, width, last - first + 1);
    }

    s->invalidate = false;
    return true;
}

static void imx6ul_lcdif_invalidate_display(void *opaque)
{
    IMX6ULLCDIFState *s = opaque;

    s->invalidate = true;
}

static const GraphicHwOps imx6ul_lcdif_graphic_ops = {
    .invalidate = imx6ul_lcdif_invalidate_display,
    .gfx_update = imx6ul_lcdif_update_display,
};

static void imx6ul_lcdif_frame_timer_cb(void *opaque)
{
    IMX6ULLCDIFState *s = opaque;

    if (!imx6ul_lcdif_is_running(s) || imx6ul_lcdif_frame_done_pending(s)) {
        return;
    }

    imx6ul_lcdif_frame_done(s);
}

static uint64_t imx6ul_lcdif_read(void *opaque, hwaddr offset, unsigned size)
{
    IMX6ULLCDIFState *s = opaque;
    hwaddr reg = offset & ~0xf;
    uint32_t idx;

    assert(size == 4);
    assert(!(offset & 0x3));
    assert(offset < LCDIF_MMIO_SIZE);

    idx = reg >> 4;
    if (idx >= ARRAY_SIZE(s->regs)) {
        return 0;
    }

    return s->regs[idx];
}

static void imx6ul_lcdif_write(void *opaque, hwaddr offset,
                               uint64_t value, unsigned size)
{
    IMX6ULLCDIFState *s = opaque;
    hwaddr reg = offset & ~0xf;
    uint32_t idx;
    uint32_t oldv;

    assert(size == 4);
    assert(!(offset & 0x3));
    assert(offset < LCDIF_MMIO_SIZE);

    if (!imx6ul_lcdif_reg_exists(reg)) {
        return;
    }

    idx = reg >> 4;
    oldv = s->regs[idx];

    switch (offset & 0xf) {
    case 0:
        s->regs[idx] = (uint32_t)value;
        break;
    case REG_SET:
        if (!imx6ul_lcdif_reg_has_setclr(reg)) {
            return;
        }
        s->regs[idx] = oldv | (uint32_t)value;
        break;
    case REG_CLR:
        if (!imx6ul_lcdif_reg_has_setclr(reg)) {
            return;
        }
        s->regs[idx] = oldv & ~(uint32_t)value;
        break;
    case REG_TOG:
        if (!imx6ul_lcdif_reg_has_setclr(reg)) {
            return;
        }
        s->regs[idx] = oldv ^ (uint32_t)value;
        break;
    default:
        g_assert_not_reached();
    }

    switch (reg) {
    case A_CTRL:
        if (!FIELD_EX32(oldv, CTRL, RUN) &&
            FIELD_EX32(s->regs[idx], CTRL, RUN)) {
            s->invalidate = true;
            qemu_console_hw_invalidate(s->con);
            imx6ul_lcdif_maybe_schedule_frame(s);
            break;
        }
        if (FIELD_EX32(oldv, CTRL, RUN) &&
            !FIELD_EX32(s->regs[idx], CTRL, RUN)) {
            timer_del(s->frame_timer);
        }
        break;
    case A_CTRL1:
        if (FIELD_EX32(oldv, CTRL1, CUR_FRAME_DONE_IRQ) &&
            !FIELD_EX32(s->regs[idx], CTRL1, CUR_FRAME_DONE_IRQ)) {
            imx6ul_lcdif_maybe_schedule_frame(s);
        }
        break;
    case A_V4_TRANSFER_COUNT:
        s->invalidate = true;
        qemu_console_hw_invalidate(s->con);
        break;
    case A_V4_CUR_BUF:
        s->invalidate = true;
        qemu_console_hw_invalidate(s->con);
        break;
    case A_V4_NEXT_BUF:
        s->regs[IMX6UL_LCDIF_REG_V4_CUR_BUF] = s->regs[idx];
        imx6ul_lcdif_frame_done(s);
        s->invalidate = true;
        qemu_console_hw_invalidate(s->con);
        imx6ul_lcdif_maybe_schedule_frame(s);
        return;
    case A_AS_NEXT_BUF:
        imx6ul_lcdif_frame_done(s);
        imx6ul_lcdif_maybe_schedule_frame(s);
        return;
    default:
        break;
    }

    imx6ul_lcdif_update_irq(s);
}

static const MemoryRegionOps imx6ul_lcdif_ops = {
    .read = imx6ul_lcdif_read,
    .write = imx6ul_lcdif_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
        .unaligned = false,
    },
};

static void imx6ul_lcdif_reset(DeviceState *dev)
{
    IMX6ULLCDIFState *s = IMX6UL_LCDIF(dev);

    memset(s->regs, 0, sizeof(s->regs));
    s->regs[IMX6UL_LCDIF_REG_CTRL1] = LCDIF_RESET_CTRL1;
    s->fb_base = 0;
    s->src_width = 0;
    s->rows = 0;
    s->src_bpp = 0;
    s->invalidate = true;
    timer_del(s->frame_timer);
    imx6ul_lcdif_update_irq(s);
}

static int imx6ul_lcdif_post_load(void *opaque, int version_id)
{
    IMX6ULLCDIFState *s = opaque;

    s->fb_base = 0;
    s->src_width = 0;
    s->rows = 0;
    s->src_bpp = 0;
    s->invalidate = true;

    imx6ul_lcdif_update_irq(s);
    if (imx6ul_lcdif_is_running(s) &&
        !imx6ul_lcdif_frame_done_pending(s) &&
        !timer_pending(s->frame_timer)) {
        imx6ul_lcdif_schedule_frame(s);
    }

    return 0;
}

static const VMStateDescription vmstate_imx6ul_lcdif = {
    .name = TYPE_IMX6UL_LCDIF,
    .version_id = 1,
    .minimum_version_id = 1,
    .post_load = imx6ul_lcdif_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32_ARRAY(regs, IMX6ULLCDIFState, IMX6UL_LCDIF_REGS_NUM),
        VMSTATE_TIMER_PTR(frame_timer, IMX6ULLCDIFState),
        VMSTATE_END_OF_LIST()
    },
};

static void imx6ul_lcdif_realize(DeviceState *dev, Error **errp)
{
    IMX6ULLCDIFState *s = IMX6UL_LCDIF(dev);

    s->frame_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                  imx6ul_lcdif_frame_timer_cb, s);
    s->invalidate = true;
    memory_region_init_io(&s->iomem, OBJECT(dev), &imx6ul_lcdif_ops, s,
                          TYPE_IMX6UL_LCDIF, LCDIF_MMIO_SIZE);
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->iomem);
    sysbus_init_irq(SYS_BUS_DEVICE(dev), &s->irq);
    s->con = qemu_graphic_console_create(dev, 0, &imx6ul_lcdif_graphic_ops, s);
}

static void imx6ul_lcdif_unrealize(DeviceState *dev)
{
    IMX6ULLCDIFState *s = IMX6UL_LCDIF(dev);

    timer_del(s->frame_timer);
    timer_free(s->frame_timer);
    s->frame_timer = NULL;

    if (s->con) {
        qemu_graphic_console_close(s->con);
        s->con = NULL;
    }
}

static void imx6ul_lcdif_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = imx6ul_lcdif_realize;
    dc->unrealize = imx6ul_lcdif_unrealize;
    dc->vmsd = &vmstate_imx6ul_lcdif;
    device_class_set_legacy_reset(dc, imx6ul_lcdif_reset);
    dc->desc = "i.MX6UL LCDIF";
}

static const TypeInfo imx6ul_lcdif_info = {
    .name = TYPE_IMX6UL_LCDIF,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(IMX6ULLCDIFState),
    .class_init = imx6ul_lcdif_class_init,
};

static void imx6ul_lcdif_register_types(void)
{
    type_register_static(&imx6ul_lcdif_info);
}

type_init(imx6ul_lcdif_register_types)
