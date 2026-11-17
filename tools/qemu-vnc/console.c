/*
 * Minimal QemuConsole helpers for the standalone qemu-vnc binary.
 *
 * Copyright (C) 2026 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"

#include "ui/console.h"
#include "ui/console-priv.h"
#include "ui/vt100.h"
#include "qapi-types-char.h"
#include "qemu-vnc.h"
#include "trace.h"

/*
 * Our own QemuTextConsole definition — the one in console-vc.c uses
 * a Chardev* backend which is not available in the standalone binary.
 * Here we drive the VT100 emulator directly over a raw file descriptor.
 */
typedef struct QemuTextConsole {
    QemuConsole parent;
    QemuVT100 vt;
    int chardev_fd;
    guint io_watch_id;
    char *name;
} QemuTextConsole;

typedef QemuConsoleClass QemuTextConsoleClass;

OBJECT_DEFINE_TYPE(QemuTextConsole, qemu_text_console,
                   QEMU_TEXT_CONSOLE, QEMU_CONSOLE)

static void qemu_text_console_class_init(ObjectClass *oc, const void *data)
{
}

static void text_console_invalidate(void *opaque)
{
    QemuTextConsole *s = QEMU_TEXT_CONSOLE(opaque);

    vt100_set_image(&s->vt, QEMU_CONSOLE(s)->surface->image);
    vt100_refresh(&s->vt);
}

static const GraphicHwOps text_console_ops = {
    .invalidate  = text_console_invalidate,
};

static void qemu_text_console_init(Object *obj)
{
    QemuTextConsole *c = QEMU_TEXT_CONSOLE(obj);

    QEMU_CONSOLE(c)->hw_ops = &text_console_ops;
    QEMU_CONSOLE(c)->hw = c;
}

static void qemu_text_console_finalize(Object *obj)
{
    QemuTextConsole *tc = QEMU_TEXT_CONSOLE(obj);

    vt100_fini(&tc->vt);
    if (tc->io_watch_id) {
        g_source_remove(tc->io_watch_id);
    }
    if (tc->chardev_fd >= 0) {
        close(tc->chardev_fd);
    }
    g_free(tc->name);
}


static void text_console_out_flush(QemuVT100 *vt)
{
    QemuTextConsole *tc = container_of(vt, QemuTextConsole, vt);
    const uint8_t *data;
    uint32_t len;

    while (!fifo8_is_empty(&vt->out_fifo)) {
        ssize_t ret;

        data = fifo8_pop_bufptr(&vt->out_fifo,
                                fifo8_num_used(&vt->out_fifo), &len);
        ret = write(tc->chardev_fd, data, len);
        if (ret < 0) {
            trace_qemu_vnc_console_io_error(tc->name);
            break;
        }
    }
}

static void text_console_image_update(QemuVT100 *vt, int x, int y, int w, int h)
{
    QemuTextConsole *tc = container_of(vt, QemuTextConsole, vt);
    QemuConsole *con = QEMU_CONSOLE(tc);

    qemu_console_update(con, x, y, w, h);
}

static gboolean text_console_io_cb(GIOChannel *source,
    GIOCondition cond, gpointer data)
{
    QemuTextConsole *tc = data;
    uint8_t buf[4096];
    ssize_t n;

    if (cond & (G_IO_HUP | G_IO_ERR)) {
        tc->io_watch_id = 0;
        return G_SOURCE_REMOVE;
    }

    n = read(tc->chardev_fd, buf, sizeof(buf));
    if (n <= 0) {
        trace_qemu_vnc_console_io_error(tc->name);
        tc->io_watch_id = 0;
        return G_SOURCE_REMOVE;
    }

    vt100_input(&tc->vt, buf, n);
    return G_SOURCE_CONTINUE;
}

QemuTextConsole *qemu_vnc_text_console_new(const char *name,
                                           int fd, bool echo,
                                           ChardevVCEncoding encoding)
{
    int w = TEXT_COLS * TEXT_FONT_WIDTH;
    int h = TEXT_ROWS * TEXT_FONT_HEIGHT;
    QemuTextConsole *tc;
    QemuConsole *con;
    pixman_image_t *image;
    GIOChannel *chan;

    tc = QEMU_TEXT_CONSOLE(object_new(TYPE_QEMU_TEXT_CONSOLE));
    con = QEMU_CONSOLE(tc);

    tc->name = g_strdup(name);
    tc->chardev_fd = fd;

    image = pixman_image_create_bits(PIXMAN_x8r8g8b8, w, h, NULL, 0);
    con->surface = qemu_create_displaysurface_pixman(image);
    con->scanout.kind = SCANOUT_SURFACE;
    qemu_pixman_image_unref(image);

    vt100_init(&tc->vt, con->surface->image, encoding,
               text_console_image_update, text_console_out_flush);
    tc->vt.echo = echo;
    vt100_refresh(&tc->vt);

    chan = g_io_channel_unix_new(fd);
    g_io_channel_set_encoding(chan, NULL, NULL);
    tc->io_watch_id = g_io_add_watch(chan,
                                      G_IO_IN | G_IO_HUP | G_IO_ERR,
                                      text_console_io_cb, tc);
    g_io_channel_unref(chan);

    return tc;
}

void qemu_text_console_handle_keysym(QemuTextConsole *s, int keysym)
{
    vt100_keysym(&s->vt, keysym);
}

void qemu_text_console_update_size(QemuTextConsole *c)
{
    qemu_console_text_resize(QEMU_CONSOLE(c), c->vt.width, c->vt.height);
}
