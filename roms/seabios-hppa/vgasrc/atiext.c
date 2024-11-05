//  QEMU ATI VGABIOS Extension.
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_GLOBAL
#include "bregs.h" // struct bregs
#include "hw/pci.h" // pci_config_readl
#include "hw/pci_regs.h" // PCI_BASE_ADDRESS_0
#include "output.h" // dprintf
#include "stdvga.h" // VGAREG_SEQU_ADDRESS
#include "string.h" // memset16_far
#include "vgabios.h" // SET_VGA
#include "vgautil.h" // VBE_total_memory
#include "vgafb.h" // memset_high

#include "svgamodes.h"

#define MM_INDEX                                0x0000
#define MM_DATA                                 0x0004
#define CRTC_GEN_CNTL                           0x0050
#define CRTC_EXT_CNTL                           0x0054
#define GPIO_VGA_DDC                            0x0060
#define GPIO_DVI_DDC                            0x0064
#define GPIO_MONID                              0x0068
#define CRTC_H_TOTAL_DISP                       0x0200
#define CRTC_V_TOTAL_DISP                       0x0208
#define CRTC_OFFSET                             0x0224
#define CRTC_PITCH                              0x022c

/* CRTC control values (CRTC_GEN_CNTL) */
#define CRTC2_EXT_DISP_EN                       0x01000000
#define CRTC2_EN                                0x02000000

#define CRTC_PIX_WIDTH_MASK                     0x00000700
#define CRTC_PIX_WIDTH_4BPP                     0x00000100
#define CRTC_PIX_WIDTH_8BPP                     0x00000200
#define CRTC_PIX_WIDTH_15BPP                    0x00000300
#define CRTC_PIX_WIDTH_16BPP                    0x00000400
#define CRTC_PIX_WIDTH_24BPP                    0x00000500
#define CRTC_PIX_WIDTH_32BPP                    0x00000600

/* CRTC_EXT_CNTL */
#define CRT_CRTC_DISPLAY_DIS                    0x00000400
#define CRT_CRTC_ON                             0x00008000

static u32 ati_io_addr VAR16 = 0;
static u32 ati_i2c_reg VAR16;
static u32 ati_i2c_bit_scl_out VAR16;
static u32 ati_i2c_bit_sda_out VAR16;
static u32 ati_i2c_bit_sda_in VAR16;
static u32 ati_i2c_bit_enable VAR16 = -1;


int
is_ati_mode(struct vgamode_s *vmode_g)
{
    unsigned int mcount = GET_GLOBAL(svga_mcount);

    return (vmode_g >= &svga_modes[0].info &&
            vmode_g <= &svga_modes[mcount-1].info);
}

struct vgamode_s *
ati_find_mode(int mode)
{
    u32 io_addr = GET_GLOBAL(ati_io_addr);
    struct generic_svga_mode *table_g = svga_modes;
    unsigned int mcount = GET_GLOBAL(svga_mcount);

    if (io_addr) {
        while (table_g < &svga_modes[mcount]) {
            if (GET_GLOBAL(table_g->mode) == mode)
                return &table_g->info;
            table_g++;
        }
    }

    return stdvga_find_mode(mode);
}

void
ati_list_modes(u16 seg, u16 *dest, u16 *last)
{
    u32 io_addr = GET_GLOBAL(ati_io_addr);
    unsigned int mcount = GET_GLOBAL(svga_mcount);

    dprintf(1, "%s: ati ext %s\n", __func__, io_addr ? "yes" : "no");
    if (io_addr) {
        int i;
        for (i=0; i<mcount && dest<last; i++) {
            u16 mode = GET_GLOBAL(svga_modes[i].mode);
            if (mode == 0xffff)
                continue;
            SET_FARVAR(seg, *dest, mode);
            dest++;
        }
    }

    stdvga_list_modes(seg, dest, last);
}

/****************************************************************
 * Mode setting
 ****************************************************************/

static inline void ati_write(u32 reg, u32 val)
{
    u32 io_addr = GET_GLOBAL(ati_io_addr);

    if (reg < 0x100) {
        outl(val, io_addr + reg);
    } else {
        outl(reg, io_addr + MM_INDEX);
        outl(val, io_addr + MM_DATA);
    }
}

static inline u32 ati_read(u32 reg)
{
    u32 io_addr = GET_GLOBAL(ati_io_addr);
    u32 val;

    if (reg < 0x100) {
        val = inl(io_addr + reg);
    } else {
        outl(reg, io_addr + MM_INDEX);
        val = inl(io_addr + MM_DATA);
    }
    return val;
}

static void ati_clear(u32 offset, u32 size)
{
    u8 data[64];
    void *datap = MAKE_FLATPTR(GET_SEG(SS), data);
    void *fb = (void*)(GET_GLOBAL(VBE_framebuffer) + offset);
    u32 i, pos;

    for (i = 0; i < sizeof(data); i++)
        data[i] = 0;
    for (pos = 0; pos < size; pos += sizeof(data)) {
        memcpy_high(fb, datap, sizeof(data));
        fb += sizeof(data);
    }
}

static int
ati_ext_mode(struct generic_svga_mode *table, int flags)
{
    u32 width  = GET_GLOBAL(table->info.width);
    u32 height = GET_GLOBAL(table->info.height);
    u32 depth  = GET_GLOBAL(table->info.depth);
    u32 stride = width;
    u32 offset = 0;
    u32 pxmask = 0;
    u32 bytes  = 0;

    dprintf(1, "%s: 0x%x, %dx%d-%d\n", __func__,
            GET_GLOBAL(table->mode),
            width, height, depth);

    switch (depth) {
    case  8: pxmask = CRTC_PIX_WIDTH_8BPP;  bytes = 1; break;
    case 15: pxmask = CRTC_PIX_WIDTH_15BPP; bytes = 2; break;
    case 16: pxmask = CRTC_PIX_WIDTH_16BPP; bytes = 2; break;
    case 24: pxmask = CRTC_PIX_WIDTH_24BPP; bytes = 3; break;
    case 32: pxmask = CRTC_PIX_WIDTH_32BPP; bytes = 4; break;
    }

    /* disable display */
    ati_write(CRTC_EXT_CNTL, CRT_CRTC_DISPLAY_DIS);

    /* modeset */
    ati_write(CRTC_GEN_CNTL, CRTC2_EXT_DISP_EN | CRTC2_EN | pxmask);
    ati_write(CRTC_H_TOTAL_DISP, ((width / 8) - 1) << 16);
    ati_write(CRTC_V_TOTAL_DISP, (height - 1) << 16);
    ati_write(CRTC_OFFSET, offset);
    ati_write(CRTC_PITCH, stride / 8);

    /* clear screen */
    if (!(flags & MF_NOCLEARMEM)) {
        u32 size = width * height * bytes;
        ati_clear(offset, size);
    }

    /* enable display */
    ati_write(CRTC_EXT_CNTL, 0);

    return 0;
}

int
ati_set_mode(struct vgamode_s *vmode_g, int flags)
{
    struct generic_svga_mode *table_g =
        container_of(vmode_g, struct generic_svga_mode, info);

    if (is_ati_mode(vmode_g)) {
        return ati_ext_mode(table_g, flags);
    }

    ati_write(CRTC_GEN_CNTL, 0);
    return stdvga_set_mode(vmode_g, flags);
}

/****************************************************************
 * edid
 ****************************************************************/

static void
ati_i2c_set_scl_sda(int scl, int sda)
{
    u32 enable = GET_GLOBAL(ati_i2c_bit_enable);
    u32 data = 0;

    if (enable != -1)
        data |= (1 << enable);
    if (!scl)
        data |= (1 << GET_GLOBAL(ati_i2c_bit_scl_out));
    if (!sda)
        data |= (1 << GET_GLOBAL(ati_i2c_bit_sda_out));
    ati_write(GET_GLOBAL(ati_i2c_reg), data);
}

static int
ati_i2c_get_sda(void)
{
    u32 data = ati_read(GET_GLOBAL(ati_i2c_reg));

    return data & (1 << GET_GLOBAL(ati_i2c_bit_sda_in)) ? 1 : 0;
}

static void ati_i2c_start(void)
{
    ati_i2c_set_scl_sda(1, 1);
    ati_i2c_set_scl_sda(1, 0);
    ati_i2c_set_scl_sda(0, 0);
}

static void ati_i2c_ack(void)
{
    ati_i2c_set_scl_sda(0, 0);
    ati_i2c_set_scl_sda(1, 0);
    ati_i2c_set_scl_sda(0, 0);
}

static void ati_i2c_stop(void)
{
    ati_i2c_set_scl_sda(0, 0);
    ati_i2c_set_scl_sda(1, 0);
    ati_i2c_set_scl_sda(1, 1);
}

static void ati_i2c_send_byte(u8 byte)
{
    int i, bit;

    for (i = 0; i < 8; i++) {
        bit = (1 << (7-i)) & byte ? 1 : 0;
        ati_i2c_set_scl_sda(0, bit);
        ati_i2c_set_scl_sda(1, bit);
        ati_i2c_set_scl_sda(0, bit);
    }
}

static u8 ati_i2c_recv_byte(void)
{
    u8 byte = 0;
    int i, bit;

    for (i = 0; i < 8; i++) {
        ati_i2c_set_scl_sda(0, 1);
        ati_i2c_set_scl_sda(1, 1);
        bit = ati_i2c_get_sda();
        ati_i2c_set_scl_sda(0, 1);
        if (bit)
            byte |= (1 << (7-i));
    }

    return byte;
}

static void ati_i2c_edid(void)
{
    u8 byte;
    int i;

    ati_i2c_start();
    ati_i2c_send_byte(0x50 << 1 | 1);
    ati_i2c_ack();
    for (i = 0; i < 128; i++) {
        byte = ati_i2c_recv_byte();
        ati_i2c_ack();
        SET_VGA(VBE_edid[i], byte);
    }
    ati_i2c_stop();
}

static void ati_i2c_edid_radeon(void)
{
    int valid;

    SET_VGA(ati_i2c_bit_scl_out, 17);
    SET_VGA(ati_i2c_bit_sda_out, 16);
    SET_VGA(ati_i2c_bit_sda_in, 8);

    dprintf(1, "ati: reading edid blob (radeon vga) ... \n");
    SET_VGA(ati_i2c_reg, GPIO_VGA_DDC);
    ati_i2c_edid();
    valid = (GET_GLOBAL(VBE_edid[0]) == 0x00 &&
             GET_GLOBAL(VBE_edid[1]) == 0xff);
    dprintf(1, "ati: ... %s\n", valid ? "good" : "invalid");
    if (valid)
        return;

    dprintf(1, "ati: reading edid blob (radeon dvi) ... \n");
    SET_VGA(ati_i2c_reg, GPIO_DVI_DDC);
    ati_i2c_edid();
    valid = (GET_GLOBAL(VBE_edid[0]) == 0x00 &&
             GET_GLOBAL(VBE_edid[1]) == 0xff);
    dprintf(1, "ati: ... %s\n", valid ? "good" : "invalid");
}

static void ati_i2c_edid_rage128(void)
{
    int valid;

    SET_VGA(ati_i2c_bit_enable, 25);
    SET_VGA(ati_i2c_bit_scl_out, 18);
    SET_VGA(ati_i2c_bit_sda_out, 17);
    SET_VGA(ati_i2c_bit_sda_in, 9);
    SET_VGA(ati_i2c_reg, GPIO_MONID);

    dprintf(1, "ati: reading edid blob (rage128) ... \n");
    ati_i2c_edid();
    valid = (GET_GLOBAL(VBE_edid[0]) == 0x00 &&
             GET_GLOBAL(VBE_edid[1]) == 0xff);
    dprintf(1, "ati: ... %s\n", valid ? "good" : "invalid");
}

/****************************************************************
 * init
 ****************************************************************/

int
ati_setup(void)
{
    int ret = stdvga_setup();
    if (ret)
        return ret;

    dprintf(1, "%s:%d\n", __func__, __LINE__);

    if (GET_GLOBAL(HaveRunInit))
        return 0;

    int bdf = GET_GLOBAL(VgaBDF);
    if (!CONFIG_VGA_PCI || bdf == 0)
        return 0;

    u32 bar = pci_config_readl(bdf, PCI_BASE_ADDRESS_0);
    u32 lfb_addr = bar & PCI_BASE_ADDRESS_MEM_MASK;
    pci_config_writel(bdf, PCI_BASE_ADDRESS_0, ~0);
    u32 barmask = pci_config_readl(bdf, PCI_BASE_ADDRESS_0);
    u32 totalmem = ~(barmask & PCI_BASE_ADDRESS_MEM_MASK) + 1;
    pci_config_writel(bdf, PCI_BASE_ADDRESS_0, bar);

    bar = pci_config_readl(bdf, PCI_BASE_ADDRESS_1);
    u32 io_addr = bar & PCI_BASE_ADDRESS_IO_MASK;

    bar = pci_config_readl(bdf, PCI_BASE_ADDRESS_2);
    u32 mmio_addr = bar & PCI_BASE_ADDRESS_MEM_MASK;

    dprintf(1, "ati: bdf %02x:%02x.%x, lfb 0x%x, %d MB, io 0x%x, mmio 0x%x\n",
            pci_bdf_to_bus(bdf), pci_bdf_to_dev(bdf), pci_bdf_to_fn(bdf),
            lfb_addr, totalmem / (1024 * 1024), io_addr, mmio_addr);

    SET_VGA(VBE_framebuffer, lfb_addr);
    SET_VGA(VBE_total_memory, totalmem);
    SET_VGA(ati_io_addr, io_addr);

    // Validate modes
    struct generic_svga_mode *m = svga_modes;
    unsigned int mcount = GET_GLOBAL(svga_mcount);
    for (; m < &svga_modes[mcount]; m++) {
        u8 memmodel = GET_GLOBAL(m->info.memmodel);
        u16 width = GET_GLOBAL(m->info.width);
        u16 height = GET_GLOBAL(m->info.height);
        u32 mem = (height * DIV_ROUND_UP(width * vga_bpp(&m->info), 8)
                   * stdvga_vram_ratio(&m->info));

        if (width % 8 != 0 ||
            width > 0x7ff * 8 ||
            height > 0xfff ||
            mem > totalmem ||
            memmodel != MM_DIRECT) {
            dprintf(3, "ati: removing mode 0x%x\n", GET_GLOBAL(m->mode));
            SET_VGA(m->mode, 0xffff);
        }
    }

    u16 device = pci_config_readw(bdf, PCI_DEVICE_ID);
    switch (device) {
    case 0x5046:
        ati_i2c_edid_rage128();
        break;
    case 0x5159:
        ati_i2c_edid_radeon();
        break;
    }

    return 0;
}
