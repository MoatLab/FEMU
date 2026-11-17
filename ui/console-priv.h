/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * QEMU UI Console
 */
#ifndef CONSOLE_PRIV_H
#define CONSOLE_PRIV_H

#include "ui/console.h"
#include "qemu/coroutine.h"
#include "qemu/timer.h"

struct QemuConsole {
    Object parent;

    int index;
    DisplayState *ds;
    DisplaySurface *surface;
    DisplayScanout scanout;
    DisplayGLCtx *gl;
    int gl_block;
    QEMUTimer *gl_unblock_timer;
    int window_id;
    QemuUIInfo ui_info;
    QEMUTimer *ui_timer;
    const GraphicHwOps *hw_ops;
    void *hw;
    CoQueue dump_queue;

    QTAILQ_ENTRY(QemuConsole) next;
};

void qemu_text_console_update_size(QemuTextConsole *c);
void qemu_text_console_handle_keysym(QemuTextConsole *s, int keysym);

#endif
