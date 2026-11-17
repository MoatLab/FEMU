/*
 * QEMU graphical console surface helper
 *
 * Copyright (c) 2004 Fabrice Bellard
 *
 * SPDX-License-Identifier: MIT
 */
#include "qemu/osdep.h"
#include "ui/console.h"
#include "ui/vgafont.h"
#include "trace.h"

void qemu_displaysurface_set_share_handle(DisplaySurface *surface,
                                          qemu_pixman_shareable handle,
                                          uint32_t offset)
{
    assert(surface->share_handle == SHAREABLE_NONE);

    surface->share_handle = handle;
    surface->share_handle_offset = offset;

}

DisplaySurface *qemu_create_displaysurface(int width, int height)
{
    trace_displaysurface_create(width, height);

    return qemu_create_displaysurface_from(
        width, height,
        PIXMAN_x8r8g8b8,
        width * 4, NULL
    );
}

DisplaySurface *qemu_create_displaysurface_from(int width, int height,
                                                pixman_format_code_t format,
                                                int linesize, uint8_t *data)
{
    DisplaySurface *surface = g_new0(DisplaySurface, 1);

    trace_displaysurface_create_from(surface, width, height, format);
    surface->share_handle = SHAREABLE_NONE;

    if (data) {
        surface->image = pixman_image_create_bits(format,
                                                  width, height,
                                                  (void *)data, linesize);
    } else {
        qemu_pixman_image_new_shareable(&surface->image,
                                        &surface->share_handle,
                                        "displaysurface",
                                        format,
                                        width,
                                        height,
                                        linesize,
                                        &error_abort);
        surface->flags = QEMU_ALLOCATED_FLAG;
    }

    assert(surface->image != NULL);
    return surface;
}

DisplaySurface *qemu_create_displaysurface_pixman(pixman_image_t *image)
{
    DisplaySurface *surface = g_new0(DisplaySurface, 1);

    trace_displaysurface_create_pixman(surface);
    surface->share_handle = SHAREABLE_NONE;
    surface->image = pixman_image_ref(image);

    return surface;
}

DisplaySurface *qemu_create_placeholder_surface(int w, int h,
                                                const char *msg)
{
    DisplaySurface *surface = qemu_create_displaysurface(w, h);
#ifdef CONFIG_PIXMAN
    pixman_color_t bg = QEMU_PIXMAN_COLOR_BLACK;
    pixman_color_t fg = QEMU_PIXMAN_COLOR_GRAY;
    pixman_image_t *glyph;
    int len, x, y, i;

    len = strlen(msg);
    x = (w / FONT_WIDTH  - len) / 2;
    y = (h / FONT_HEIGHT - 1)   / 2;
    for (i = 0; i < len; i++) {
        glyph = qemu_pixman_glyph_from_vgafont(FONT_HEIGHT, vgafont16, msg[i]);
        qemu_pixman_glyph_render(glyph, surface->image, &fg, &bg,
                                 x + i, y, FONT_WIDTH, FONT_HEIGHT);
        qemu_pixman_image_unref(glyph);
    }
#endif
    surface->flags |= QEMU_PLACEHOLDER_FLAG;
    return surface;
}

void qemu_free_displaysurface(DisplaySurface *surface)
{
    if (surface == NULL) {
        return;
    }
    trace_displaysurface_free(surface);
    qemu_pixman_image_unref(surface->image);
    g_free(surface);
}
