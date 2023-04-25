/* STI console code
 *
 * Copyright (C) 2019 Sven Schnelle <svens@stackframe.org>
 *
 * This file may be distributed under the terms of the GNU LGPLv3 license.
 */

#include "autoconf.h"
#include "types.h"
#include "std/optionrom.h"
#include "vgahw.h"
#include "parisc/sticore.h"
#include "parisc/hppa_hardware.h"
#include "output.h"
#include "pdc.h"
#include "hppa.h"

static int sti_enabled;

static struct sti_init_flags sti_init_flags = {
        .wait = 1,
        .reset = 1,
        .text = 1,
        .nontext = 1,
        .cmap_blk = 1,
        .no_chg_bet = 1,
        .no_chg_bei = 1,
        .init_cmap_tx = 1,
        .clear = 1,
};

static struct sti_glob_cfg_ext sti_glob_ext_cfg = {
};

static struct sti_glob_cfg sti_glob_cfg = {
        .region_ptrs = { 0, ARTIST_FB_ADDR, 0xf8100000, 0xf8380000, 0, 0, 0, 0 },
        .ext_ptr = (u32)&sti_glob_ext_cfg,
};

static struct sti_init_inptr_ext sti_init_inptr_ext = {
        .config_mon_type = 1,
};

static struct sti_init_inptr sti_init_inptr = {
        .text_planes = 3,
        .ext_ptr = (u32)&sti_init_inptr_ext,
};

static struct sti_init_outptr sti_init_outptr = {
};

static struct sti_font_flags sti_font_flags = {
        .wait = 1,
};

static struct sti_font_inptr sti_font_inptr = {
        .fg_color = 1,
        .bg_color = 0,
};

static struct sti_font_outptr sti_font_outptr = {
};

static struct sti_blkmv_flags sti_blkmv_flags = {
        .wait = 1,
};

static struct sti_blkmv_inptr sti_blkmv_inptr = {
};

static struct sti_blkmv_outptr sti_blkmv_outptr = {
};

static void sti_putchar(struct sti_rom *rom, int row, int column, const char c)
{
    int (*sti_unpmv)(struct sti_font_flags *,
                     struct sti_font_inptr *,
                     struct sti_font_outptr *,
                     struct sti_glob_cfg *);

    struct sti_rom_font *font = (void *)rom + rom->font_start;
    sti_unpmv = (void *)rom + rom->font_unpmv;

    sti_font_inptr.dest_x = column * font->width;
    sti_font_inptr.dest_y = row * font->height;
    sti_font_inptr.index = c;
    sti_font_inptr.font_start_addr = (u32) font;

    sti_unpmv(&sti_font_flags, &sti_font_inptr,
        &sti_font_outptr, &sti_glob_cfg);
}

static void sti_block_move(struct sti_rom *rom, int src_x, int src_y,
                                          int dest_x, int dest_y,
                                          int width, int height,
                                          int clear)
{
    int (*sti_block_move)(struct sti_blkmv_flags *,
                          struct sti_blkmv_inptr *,
                          struct sti_blkmv_outptr *,
                          struct sti_glob_cfg *);
    sti_block_move = (void *)rom + rom->block_move;

    sti_blkmv_inptr.src_x = src_x;
    sti_blkmv_inptr.src_y = src_y;
    sti_blkmv_inptr.dest_x = dest_x;
    sti_blkmv_inptr.dest_y = dest_y;
    sti_blkmv_inptr.width = width;
    sti_blkmv_inptr.height = height;
    sti_blkmv_flags.clear = clear;

    sti_block_move(&sti_blkmv_flags, &sti_blkmv_inptr,
                   &sti_blkmv_outptr, &sti_glob_cfg);
}

void sti_console_init(struct sti_rom *rom)
{
    int (*sti_init)(struct sti_init_flags *,
                    struct sti_init_inptr *,
                    struct sti_init_outptr *,
                    struct sti_glob_cfg *);

    sti_init = (void *)rom + rom->init_graph;

    sti_init(&sti_init_flags, &sti_init_inptr,
             &sti_init_outptr, &sti_glob_cfg);

    sti_enabled = 1;
}

void sti_putc(const char c)
{
    struct sti_rom *rom = (struct sti_rom *)PAGE0->proc_sti;
    struct sti_rom_font *font = (void *)rom + rom->font_start;
    static int row, col;

    if (!sti_enabled)
        return;

    if (c == '\r') {
        col = 0;
        return;
    }

    if (c == 0x08) {
        if (col > 0)
            col--;
        return;
    }

    if (c == '\n') {
        col = 0;
        row++;

        if (row >= sti_glob_cfg.onscreen_y / font->height) {
            sti_block_move(rom,
                    0, font->height,
                    0, 0,
                    sti_glob_cfg.total_x, sti_glob_cfg.onscreen_y - font->height, 0);

            /* clear new line at bottom */
            sti_block_move(rom,
                    0, 0, /* source */
                    0, sti_glob_cfg.onscreen_y - font->height, /* dest */
                    sti_glob_cfg.onscreen_x, font->height,
                    1);

            row = (sti_glob_cfg.onscreen_y / font->height)-1;
        }
        return;
    }

    /* wrap to next line or scroll screen if EOL reached */
    if (col >= ((sti_glob_cfg.onscreen_x / font->width) - 1))
	sti_putc('\n');

    sti_putchar(rom, row, col++, c);
}
