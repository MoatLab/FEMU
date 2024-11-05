// Misc function and variable declarations.
#ifndef __VGAUTIL_H
#define __VGAUTIL_H

#include "types.h" // u8

// cbvga.c
struct vgamode_s *cbvga_find_mode(int mode);
void cbvga_list_modes(u16 seg, u16 *dest, u16 *last);
int cbvga_get_window(struct vgamode_s *vmode_g, int window);
int cbvga_set_window(struct vgamode_s *vmode_g, int window, int val);
int cbvga_get_linelength(struct vgamode_s *vmode_g);
int cbvga_set_linelength(struct vgamode_s *vmode_g, int val);
int cbvga_get_displaystart(struct vgamode_s *vmode_g);
int cbvga_set_displaystart(struct vgamode_s *vmode_g, int val);
int cbvga_get_dacformat(struct vgamode_s *vmode_g);
int cbvga_set_dacformat(struct vgamode_s *vmode_g, int val);
int cbvga_save_restore(int cmd, u16 seg, void *data);
int cbvga_set_mode(struct vgamode_s *vmode_g, int flags);
int cbvga_get_linesize(struct vgamode_s *vmode_g);
void cbvga_setup_modes(u64 addr, u8 bpp, u32 xlines, u32 ylines, u32 linelength);
int cbvga_setup(void);

// bochsdisplay.c
int bochs_display_setup(void);

// ramfb.c
int ramfb_setup(void);

// clext.c
struct vgamode_s *clext_find_mode(int mode);
void clext_list_modes(u16 seg, u16 *dest, u16 *last);
int clext_get_window(struct vgamode_s *vmode_g, int window);
int clext_set_window(struct vgamode_s *vmode_g, int window, int val);
int clext_get_linelength(struct vgamode_s *vmode_g);
int clext_set_linelength(struct vgamode_s *vmode_g, int val);
int clext_get_displaystart(struct vgamode_s *vmode_g);
int clext_set_displaystart(struct vgamode_s *vmode_g, int val);
int clext_save_restore(int cmd, u16 seg, void *data);
int clext_set_mode(struct vgamode_s *vmode_g, int flags);
struct bregs;
void clext_1012(struct bregs *regs);
int clext_setup(void);

// atiext.c
struct vgamode_s *ati_find_mode(int mode);
void ati_list_modes(u16 seg, u16 *dest, u16 *last);
int ati_set_mode(struct vgamode_s *vmode_g, int flags);
int ati_setup(void);

// stdvgaio.c
u8 stdvga_pelmask_read(void);
void stdvga_pelmask_write(u8 val);
u8 stdvga_misc_read(void);
void stdvga_misc_write(u8 value);
void stdvga_misc_mask(u8 off, u8 on);
u8 stdvga_sequ_read(u8 index);
void stdvga_sequ_write(u8 index, u8 value);
void stdvga_sequ_mask(u8 index, u8 off, u8 on);
u8 stdvga_grdc_read(u8 index);
void stdvga_grdc_write(u8 index, u8 value);
void stdvga_grdc_mask(u8 index, u8 off, u8 on);
u8 stdvga_crtc_read(u16 crtc_addr, u8 index);
void stdvga_crtc_write(u16 crtc_addr, u8 index, u8 value);
void stdvga_crtc_mask(u16 crtc_addr, u8 index, u8 off, u8 on);
u8 stdvga_attr_read(u8 index);
void stdvga_attr_write(u8 index, u8 value);
void stdvga_attr_mask(u8 index, u8 off, u8 on);
u8 stdvga_attrindex_read(void);
void stdvga_attrindex_write(u8 value);
void stdvga_dac_read(u16 seg, u8 *data_far, u8 start, int count);
void stdvga_dac_write(u16 seg, u8 *data_far, u8 start, int count);

// stdvgamodes.c
struct vgamode_s *stdvga_find_mode(int mode);
void stdvga_list_modes(u16 seg, u16 *dest, u16 *last);
void stdvga_build_video_param(void);
void stdvga_override_crtc(int mode, u8 *crtc);
int stdvga_set_mode(struct vgamode_s *vmode_g, int flags);
int stdvga_get_linesize(struct vgamode_s *vmode_g);
void stdvga_set_packed_palette(void);

// swcursor.c
void swcursor_pre_handle10(struct bregs *regs);
void swcursor_check_event(void);

// vbe.c
extern u32 VBE_total_memory;
extern u32 VBE_capabilities;
extern u32 VBE_framebuffer;
extern u16 VBE_win_granularity;
extern u8 VBE_edid[256];
void handle_104f(struct bregs *regs);

// vgafonts.c
extern u8 vgafont8[];
extern u8 vgafont14[];
extern u8 vgafont16[];
extern u8 vgafont14alt[];
extern u8 vgafont16alt[];

// vgainit.c
extern int VgaBDF;
extern int HaveRunInit;
u32 allocate_pmm(u32 size, int highmem, int aligned);

// vgaversion.c
extern const char VERSION[], BUILDINFO[];

#endif // vgautil.h
