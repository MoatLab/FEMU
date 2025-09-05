#ifndef __STDVGA_H
#define __STDVGA_H

#include "types.h" // u8
#include "std/vbe.h" // struct vbe_palette_entry

// VGA registers
#define VGAREG_ACTL_ADDRESS            0x3c0
#define VGAREG_ACTL_WRITE_DATA         0x3c0
#define VGAREG_ACTL_READ_DATA          0x3c1

#define VGAREG_INPUT_STATUS            0x3c2
#define VGAREG_WRITE_MISC_OUTPUT       0x3c2
#define VGAREG_VIDEO_ENABLE            0x3c3
#define VGAREG_SEQU_ADDRESS            0x3c4
#define VGAREG_SEQU_DATA               0x3c5

#define VGAREG_PEL_MASK                0x3c6
#define VGAREG_DAC_STATE               0x3c7
#define VGAREG_DAC_READ_ADDRESS        0x3c7
#define VGAREG_DAC_WRITE_ADDRESS       0x3c8
#define VGAREG_DAC_DATA                0x3c9

#define VGAREG_READ_FEATURE_CTL        0x3ca
#define VGAREG_READ_MISC_OUTPUT        0x3cc

#define VGAREG_GRDC_ADDRESS            0x3ce
#define VGAREG_GRDC_DATA               0x3cf

#define VGAREG_MDA_CRTC_ADDRESS        0x3b4
#define VGAREG_MDA_CRTC_DATA           0x3b5
#define VGAREG_VGA_CRTC_ADDRESS        0x3d4
#define VGAREG_VGA_CRTC_DATA           0x3d5

#define VGAREG_MDA_WRITE_FEATURE_CTL   0x3ba
#define VGAREG_VGA_WRITE_FEATURE_CTL   0x3da
#define VGAREG_ACTL_RESET              0x3da

#define VGAREG_MDA_MODECTL             0x3b8
#define VGAREG_CGA_MODECTL             0x3d8
#define VGAREG_CGA_PALETTE             0x3d9

/* Video memory */
#define SEG_GRAPH 0xA000
#define SEG_CTEXT 0xB800
#define SEG_MTEXT 0xB000

// stdvga.c
void stdvga_set_cga_background_color(u8 color);
void stdvga_set_cga_palette(u8 palid);
void stdvga_set_overscan_border_color(u8 color);
u8 stdvga_get_overscan_border_color(void);
void stdvga_set_all_palette_reg(u16 seg, u8 *data_far);
void stdvga_get_all_palette_reg(u16 seg, u8 *data_far);
void stdvga_set_palette_blinking(u8 enable_blink);
void stdvga_set_palette_pagesize(u8 pal_pagesize);
void stdvga_set_palette_page(u8 pal_page);
void stdvga_get_palette_page(u8 *pal_pagesize, u8 *pal_page);
void stdvga_dac_read_many(u16 seg, u8 *data_far, u8 start, int count);
void stdvga_dac_write_many(u16 seg, u8 *data_far, u8 start, int count);
void stdvga_perform_gray_scale_summing(u16 start, u16 count);
void stdvga_planar4_plane(int plane);
void stdvga_set_font_location(u8 spec);
void stdvga_load_font(u16 seg, void *src_far, u16 count
                      , u16 start, u8 destflags, u8 fontsize);
u16 stdvga_get_crtc(void);
struct vgamode_s;
int stdvga_vram_ratio(struct vgamode_s *vmode_g);
void stdvga_set_cursor_shape(u16 cursor_type);
void stdvga_set_cursor_pos(int address);
void stdvga_set_character_height(u8 lines);
u16 stdvga_get_vertical_size(void);
void stdvga_set_vertical_size(int lines);
int stdvga_get_window(struct vgamode_s *curmode_g, int window);
int stdvga_set_window(struct vgamode_s *curmode_g, int window, int val);
int stdvga_minimum_linelength(struct vgamode_s *vmode_g);
int stdvga_get_linelength(struct vgamode_s *curmode_g);
int stdvga_set_linelength(struct vgamode_s *curmode_g, int val);
int stdvga_get_displaystart(struct vgamode_s *curmode_g);
int stdvga_set_displaystart(struct vgamode_s *curmode_g, int val);
int stdvga_get_dacformat(struct vgamode_s *curmode_g);
int stdvga_set_dacformat(struct vgamode_s *curmode_g, int val);
int stdvga_save_restore(int cmd, u16 seg, void *data);
void stdvga_enable_video_addressing(u8 disable);
int stdvga_setup(void);

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
struct vbe_palette_entry stdvga_dac_read(u8 color);
void stdvga_dac_write(u8 color, struct vbe_palette_entry rgb);

#endif // stdvga.h
