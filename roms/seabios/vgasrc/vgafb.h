#ifndef __VGAFB_H
#define __VGAFB_H

// Graphics pixel operations.
struct gfx_op {
    struct vgamode_s *vmode_g;
    u32 linelength;
    u32 displaystart;

    u8 op;
    u16 x, y;

    u8 pixels[8];
    u16 xlen, ylen;
    u16 srcy;
};

#define GO_READ8   1
#define GO_WRITE8  2
#define GO_MEMSET  3
#define GO_MEMMOVE 4

struct cursorpos {
    u8 x, y, page, pad;
};

struct carattr {
    u8 car, attr, use_attr, pad;
};

// vgafb.c
void memcpy_high(void *dest, void *src, u32 len);
void init_gfx_op(struct gfx_op *op, struct vgamode_s *vmode_g);
void handle_gfx_op(struct gfx_op *op);
void *text_address(struct cursorpos cp);
void vgafb_scroll(struct cursorpos win, struct cursorpos winsize
                  , int lines, struct carattr ca);
void vgafb_write_char(struct cursorpos cp, struct carattr ca);
struct carattr vgafb_read_char(struct cursorpos cp);
void vgafb_write_pixel(u8 color, u16 x, u16 y);
u8 vgafb_read_pixel(u16 x, u16 y);

#endif // vgafb.h
