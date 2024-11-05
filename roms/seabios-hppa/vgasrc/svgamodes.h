#ifndef __SVGAMODES_H
#define __SVGAMODES_H

struct generic_svga_mode {
    u16 mode;
    struct vgamode_s info;
};

extern struct generic_svga_mode svga_modes[] VAR16;
extern unsigned int svga_mcount VAR16;

#endif /* __SVGAMODES_H */
