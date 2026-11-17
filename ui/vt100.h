/*
 * SPDX-License-Identifier: MIT
 * QEMU vt100
 */
#ifndef VT100_H
#define VT100_H

#include "chardev/char.h"
#include "ui/console.h"
#include "qemu/fifo8.h"
#include "qemu/queue.h"

typedef struct TextAttributes {
    uint8_t fgcol:4;
    uint8_t bgcol:4;
    uint8_t bold:1;
    uint8_t uline:1;
    uint8_t blink:1;
    uint8_t invers:1;
    uint8_t unvisible:1;
} TextAttributes;

#define TEXT_ATTRIBUTES_DEFAULT ((TextAttributes) { \
    .fgcol = QEMU_COLOR_WHITE,                      \
    .bgcol = QEMU_COLOR_BLACK                       \
})

typedef struct TextCell {
    uint8_t ch;
    TextAttributes t_attrib;
} TextCell;

#define MAX_ESC_PARAMS 3

enum TTYState {
    TTY_STATE_NORM,
    TTY_STATE_ESC,
    TTY_STATE_CSI,
    TTY_STATE_G0,
    TTY_STATE_G1,
    TTY_STATE_OSC,
};

typedef struct QemuVT100 QemuVT100;

struct QemuVT100 {
    pixman_image_t *image;
    void (*image_update)(QemuVT100 *vt, int x, int y, int width, int height);

    ChardevVCEncoding encoding;
    int width;
    int height;
    int total_height;
    int backscroll_height;
    int x, y;
    int y_displayed;
    int y_base;
    TextCell *cells;
    int text_x[2], text_y[2], cursor_invalidate;
    int echo;

    int update_x0;
    int update_y0;
    int update_x1;
    int update_y1;

    enum TTYState state;
    int esc_params[MAX_ESC_PARAMS];
    int nb_esc_params;
    uint32_t utf8_state;     /* UTF-8 DFA decoder state */
    uint32_t utf8_codepoint; /* accumulated UTF-8 code point */
    TextAttributes t_attrib; /* currently active text attributes */
    TextAttributes t_attrib_saved;
    int x_saved, y_saved;
    /* fifo for key pressed */
    Fifo8 out_fifo;
    void (*out_flush)(QemuVT100 *vt);

    QTAILQ_ENTRY(QemuVT100) list;
};

void vt100_init(QemuVT100 *vt,
                pixman_image_t *image,
                ChardevVCEncoding encoding,
                void (*image_update)(QemuVT100 *vt, int x, int y, int width, int height),
                void (*out_flush)(QemuVT100 *vt));
void vt100_fini(QemuVT100 *vt);

void vt100_update_cursor(void);
size_t vt100_input(QemuVT100 *vt, const uint8_t *buf, size_t len);
void vt100_keysym(QemuVT100 *vt, int keysym);
void vt100_set_image(QemuVT100 *vt, pixman_image_t *image);
void vt100_refresh(QemuVT100 *vt);

#endif
