#ifndef __VGABIOS_H
#define __VGABIOS_H

#include "config.h" // CONFIG_VGA_EMULATE_TEXT
#include "farptr.h" // GET_FARVAR
#include "types.h" // u8

// Save/Restore flags
#define SR_HARDWARE   0x0001
#define SR_BDA        0x0002
#define SR_DAC        0x0004
#define SR_REGISTERS  0x0008
#define SR_SAVE       0x0100
#define SR_RESTORE    0x0200

// Mode flags
#define MF_LEGACY     0x0001
#define MF_GRAYSUM    0x0002
#define MF_NOPALETTE  0x0008
#define MF_CUSTOMCRTC 0x0800
#define MF_LINEARFB   0x4000
#define MF_NOCLEARMEM 0x8000
#define MF_VBEFLAGS   0xfe00

// Memory model types
#define MM_TEXT            0x00
#define MM_CGA             0x01
#define MM_HERCULES        0x02
#define MM_PLANAR          0x03
#define MM_PACKED          0x04
#define MM_NON_CHAIN_4_256 0x05
#define MM_DIRECT          0x06
#define MM_YUV             0x07

struct vgamode_s {
    u8 memmodel;
    u16 width;
    u16 height;
    u8 depth;
    u8 cwidth;
    u8 cheight;
    u16 sstart;
};

// Custom internal storage in BDA (don't change here without also
// updating vgaentry.S)
#define VGA_CUSTOM_BDA 0xb9

struct vga_bda_s {
    u8 flags;
    u16 vbe_mode;
    u16 vgamode_offset;
} PACKED;

#define BF_PM_MASK      0x0f
#define BF_EMULATE_TEXT 0x10
#define BF_SWCURSOR     0x20
#define BF_EXTRA_STACK  0x40

#define GET_BDA_EXT(var) \
    GET_FARVAR(SEG_BDA, ((struct vga_bda_s *)VGA_CUSTOM_BDA)->var)
#define SET_BDA_EXT(var, val) \
    SET_FARVAR(SEG_BDA, ((struct vga_bda_s *)VGA_CUSTOM_BDA)->var, (val))
#define MASK_BDA_EXT(var, off, on)                                      \
    SET_BDA_EXT(var, (GET_BDA_EXT(var) & ~(off)) | (on))

static inline int vga_emulate_text(void) {
    return CONFIG_VGA_EMULATE_TEXT && GET_BDA_EXT(flags) & BF_EMULATE_TEXT;
}

// Write to global variables (during "post" phase only)
#define SET_VGA(var, val) SET_FARVAR(get_global_seg(), (var), (val))

// Debug settings
#define DEBUG_VGA_POST 1
#define DEBUG_VGA_10 9

// vgabios.c
int vga_bpp(struct vgamode_s *vmode_g);
u16 calc_page_size(u8 memmodel, u16 width, u16 height);
u16 get_cursor_shape(void);
struct cursorpos get_cursor_pos(u8 page);
int bda_save_restore(int cmd, u16 seg, void *data);
struct vgamode_s *get_current_mode(void);
int vga_set_mode(int mode, int flags);
extern struct video_func_static static_functionality;

#endif // vgabios.h
