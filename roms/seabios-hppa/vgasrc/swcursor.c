// Virtual software based cursor support
//
// Copyright (C) 2014-2016  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_BDA
#include "bregs.h" // struct bregs
#include "vgabios.h" // get_cursor_pos
#include "vgafb.h" // handle_gfx_op
#include "vgautil.h" // swcursor_check_event

// Draw/undraw a cursor on the framebuffer by xor'ing the cursor cell
static void
gfx_set_swcursor(struct vgamode_s *vmode_g, int enable, struct cursorpos cp)
{
    u16 cursor_type = get_cursor_shape();
    u8 start = cursor_type >> 8, end = cursor_type & 0xff;
    struct gfx_op op;
    init_gfx_op(&op, vmode_g);
    op.x = cp.x * 8;
    int cheight = GET_BDA(char_height);
    op.y = cp.y * cheight + start;

    int i;
    for (i = start; i < cheight && i <= end; i++, op.y++) {
        op.op = GO_READ8;
        handle_gfx_op(&op);
        int j;
        for (j = 0; j < 8; j++)
            op.pixels[j] ^= 0x07;
        op.op = GO_WRITE8;
        handle_gfx_op(&op);
    }
}

// Draw/undraw a cursor on the screen
static void
set_swcursor(int enable)
{
    u8 flags = GET_BDA_EXT(flags);
    if (!!(flags & BF_SWCURSOR) == enable)
        // Already in requested mode.
        return;
    struct vgamode_s *vmode_g = get_current_mode();
    if (!vmode_g)
        return;
    struct cursorpos cp = get_cursor_pos(GET_BDA(video_page));
    if (cp.x >= GET_BDA(video_cols) || cp.y > GET_BDA(video_rows)
        || GET_BDA(cursor_type) >= 0x2000)
        // Cursor not visible
        return;

    SET_BDA_EXT(flags, (flags & ~BF_SWCURSOR) | (enable ? BF_SWCURSOR : 0));

    if (GET_GLOBAL(vmode_g->memmodel) != MM_TEXT) {
        gfx_set_swcursor(vmode_g, enable, cp);
        return;
    }

    // In text mode, swap foreground and background attributes for cursor
    void *dest_far = text_address(cp) + 1;
    u8 attr = GET_FARVAR(GET_GLOBAL(vmode_g->sstart), *(u8*)dest_far);
    attr = (attr >> 4) | (attr << 4);
    SET_FARVAR(GET_GLOBAL(vmode_g->sstart), *(u8*)dest_far, attr);
}

// Disable virtual cursor if a vgabios call accesses the framebuffer
void
swcursor_pre_handle10(struct bregs *regs)
{
    if (!vga_emulate_text())
        return;
    switch (regs->ah) {
    case 0x4f:
        if (!CONFIG_VGA_VBE || regs->al != 0x02)
            break;
        // NO BREAK
    case 0x00 ... 0x02:
    case 0x05 ... 0x0e:
    case 0x13:
        set_swcursor(0);
        break;
    default:
        break;
    }
}

// Called by periodic (18.2hz) timer
void
swcursor_check_event(void)
{
    if (!vga_emulate_text())
        return;
    set_swcursor(GET_BDA(timer_counter) % 18 < 9);
}
