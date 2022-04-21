// Bochs VGA interface to extended "VBE" modes
//
// Copyright (C) 2012  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2011  Julian Pidancet <julian.pidancet@citrix.com>
//  Copyright (C) 2002 Jeroen Janssen
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_GLOBAL
#include "bochsvga.h" // bochsvga_set_mode
#include "config.h" // CONFIG_*
#include "hw/pci.h" // pci_config_readl
#include "hw/pci_regs.h" // PCI_BASE_ADDRESS_0
#include "output.h" // dprintf
#include "std/vbe.h" // VBE_CAPABILITY_8BIT_DAC
#include "stdvga.h" // stdvga_get_linelength
#include "vgabios.h" // SET_VGA
#include "vgautil.h" // VBE_total_memory
#include "x86.h" // outw


/****************************************************************
 * Mode tables
 ****************************************************************/

#include "svgamodes.h"

static int dispi_found VAR16 = 0;

static int is_bochsvga_mode(struct vgamode_s *vmode_g)
{
    unsigned int mcount = GET_GLOBAL(svga_mcount);

    return (vmode_g >= &svga_modes[0].info
            && vmode_g <= &svga_modes[mcount-1].info);
}

struct vgamode_s *bochsvga_find_mode(int mode)
{
    struct generic_svga_mode *m = svga_modes;
    unsigned int mcount = GET_GLOBAL(svga_mcount);

    if (GET_GLOBAL(dispi_found))
        for (; m < &svga_modes[mcount]; m++)
            if (GET_GLOBAL(m->mode) == mode)
                return &m->info;
    return stdvga_find_mode(mode);
}

void
bochsvga_list_modes(u16 seg, u16 *dest, u16 *last)
{
    struct generic_svga_mode *m = svga_modes;
    unsigned int mcount = GET_GLOBAL(svga_mcount);

    if (GET_GLOBAL(dispi_found)) {
        for (; m < &svga_modes[mcount] && dest<last; m++) {
            u16 mode = GET_GLOBAL(m->mode);
            if (mode == 0xffff)
                continue;
            SET_FARVAR(seg, *dest, mode);
            dest++;
        }
    }
    stdvga_list_modes(seg, dest, last);
}


/****************************************************************
 * Helper functions
 ****************************************************************/

static inline u16 dispi_read(u16 reg)
{
    outw(reg, VBE_DISPI_IOPORT_INDEX);
    return inw(VBE_DISPI_IOPORT_DATA);
}
static inline void dispi_write(u16 reg, u16 val)
{
    outw(reg, VBE_DISPI_IOPORT_INDEX);
    outw(val, VBE_DISPI_IOPORT_DATA);
}

static u8
bochsvga_dispi_enabled(void)
{
    if (!GET_GLOBAL(dispi_found))
        return 0;
    u16 en = dispi_read(VBE_DISPI_INDEX_ENABLE);
    if (!(en & VBE_DISPI_ENABLED))
        return 0;
    return 1;
}

int
bochsvga_get_window(struct vgamode_s *vmode_g, int window)
{
    if (!bochsvga_dispi_enabled())
        return stdvga_get_window(vmode_g, window);
    if (window != 0)
        return -1;
    return dispi_read(VBE_DISPI_INDEX_BANK);
}

int
bochsvga_set_window(struct vgamode_s *vmode_g, int window, int val)
{
    if (!bochsvga_dispi_enabled())
        return stdvga_set_window(vmode_g, window, val);
    if (window != 0)
        return -1;
    dispi_write(VBE_DISPI_INDEX_BANK, val);
    if (dispi_read(VBE_DISPI_INDEX_BANK) != val)
        return -1;
    return 0;
}

int
bochsvga_get_linelength(struct vgamode_s *vmode_g)
{
    if (!bochsvga_dispi_enabled())
        return stdvga_get_linelength(vmode_g);
    return dispi_read(VBE_DISPI_INDEX_VIRT_WIDTH) * vga_bpp(vmode_g) / 8;
}

int
bochsvga_set_linelength(struct vgamode_s *vmode_g, int val)
{
    stdvga_set_linelength(vmode_g, val);
    if (bochsvga_dispi_enabled()) {
        int pixels = (val * 8) / vga_bpp(vmode_g);
        dispi_write(VBE_DISPI_INDEX_VIRT_WIDTH, pixels);
    }
    return 0;
}

int
bochsvga_get_displaystart(struct vgamode_s *vmode_g)
{
    if (!bochsvga_dispi_enabled())
        return stdvga_get_displaystart(vmode_g);
    int bpp = vga_bpp(vmode_g);
    int linelength = dispi_read(VBE_DISPI_INDEX_VIRT_WIDTH) * bpp / 8;
    int x = dispi_read(VBE_DISPI_INDEX_X_OFFSET);
    int y = dispi_read(VBE_DISPI_INDEX_Y_OFFSET);
    return x * bpp / 8 + linelength * y;
}

int
bochsvga_set_displaystart(struct vgamode_s *vmode_g, int val)
{
    stdvga_set_displaystart(vmode_g, val);
    if (bochsvga_dispi_enabled()) {
        int bpp = vga_bpp(vmode_g);
        int linelength = dispi_read(VBE_DISPI_INDEX_VIRT_WIDTH) * bpp / 8;
        if (!linelength)
            return 0;
        dispi_write(VBE_DISPI_INDEX_X_OFFSET, (val % linelength) * 8 / bpp);
        dispi_write(VBE_DISPI_INDEX_Y_OFFSET, val / linelength);
    }
    return 0;
}

int
bochsvga_get_dacformat(struct vgamode_s *vmode_g)
{
    if (!bochsvga_dispi_enabled())
        return stdvga_get_dacformat(vmode_g);
    u16 en = dispi_read(VBE_DISPI_INDEX_ENABLE);
    return (en & VBE_DISPI_8BIT_DAC) ? 8 : 6;
}

int
bochsvga_set_dacformat(struct vgamode_s *vmode_g, int val)
{
    if (!bochsvga_dispi_enabled())
        return stdvga_set_dacformat(vmode_g, val);
    u16 en = dispi_read(VBE_DISPI_INDEX_ENABLE);
    if (val == 6)
        en &= ~VBE_DISPI_8BIT_DAC;
    else if (val == 8)
        en |= VBE_DISPI_8BIT_DAC;
    else
        return -1;
    dispi_write(VBE_DISPI_INDEX_ENABLE, en);
    return 0;
}

static int
bochsvga_save_state(u16 seg, u16 *info)
{
    u16 en = dispi_read(VBE_DISPI_INDEX_ENABLE);
    SET_FARVAR(seg, *info, en);
    info++;
    if (!(en & VBE_DISPI_ENABLED))
        return 0;
    int i;
    for (i = VBE_DISPI_INDEX_XRES; i <= VBE_DISPI_INDEX_Y_OFFSET; i++)
        if (i != VBE_DISPI_INDEX_ENABLE) {
            u16 v = dispi_read(i);
            SET_FARVAR(seg, *info, v);
            info++;
        }
    return 0;
}

static int
bochsvga_restore_state(u16 seg, u16 *info)
{
    u16 en = GET_FARVAR(seg, *info);
    info++;
    if (!(en & VBE_DISPI_ENABLED)) {
        dispi_write(VBE_DISPI_INDEX_ENABLE, en);
        return 0;
    }
    int i;
    for (i = VBE_DISPI_INDEX_XRES; i <= VBE_DISPI_INDEX_Y_OFFSET; i++)
        if (i == VBE_DISPI_INDEX_ENABLE) {
            dispi_write(i, en);
        } else {
            dispi_write(i, GET_FARVAR(seg, *info));
            info++;
        }
    return 0;
}

int
bochsvga_save_restore(int cmd, u16 seg, void *data)
{
    int ret = stdvga_save_restore(cmd, seg, data);
    if (ret < 0 || !(cmd & SR_REGISTERS) || !GET_GLOBAL(dispi_found))
        return ret;

    u16 *info = (data + ret);
    if (cmd & SR_SAVE)
        bochsvga_save_state(seg, info);
    if (cmd & SR_RESTORE)
        bochsvga_restore_state(seg, info);
    return ret + (VBE_DISPI_INDEX_Y_OFFSET-VBE_DISPI_INDEX_XRES+1)*sizeof(u16);
}


/****************************************************************
 * Mode setting
 ****************************************************************/

int
bochsvga_set_mode(struct vgamode_s *vmode_g, int flags)
{
    if (GET_GLOBAL(dispi_found))
        dispi_write(VBE_DISPI_INDEX_ENABLE, VBE_DISPI_DISABLED);
    if (! is_bochsvga_mode(vmode_g))
        return stdvga_set_mode(vmode_g, flags);
    if (!GET_GLOBAL(dispi_found))
        return -1;

    u8 memmodel = GET_GLOBAL(vmode_g->memmodel);
    if (memmodel == MM_PLANAR)
        stdvga_set_mode(stdvga_find_mode(0x6a), 0);
    if (memmodel == MM_PACKED && !(flags & MF_NOPALETTE))
        stdvga_set_packed_palette();

    dispi_write(VBE_DISPI_INDEX_BPP, GET_GLOBAL(vmode_g->depth));
    u16 width = GET_GLOBAL(vmode_g->width);
    u16 height = GET_GLOBAL(vmode_g->height);
    dispi_write(VBE_DISPI_INDEX_XRES, width);
    dispi_write(VBE_DISPI_INDEX_YRES, height);
    dispi_write(VBE_DISPI_INDEX_BANK, 0);
    u16 bf = ((flags & MF_NOCLEARMEM ? VBE_DISPI_NOCLEARMEM : 0)
              | (flags & MF_LINEARFB ? VBE_DISPI_LFB_ENABLED : 0));
    dispi_write(VBE_DISPI_INDEX_ENABLE, VBE_DISPI_ENABLED | bf);

    /* VGA compat setup */
    u16 crtc_addr = VGAREG_VGA_CRTC_ADDRESS;
    stdvga_crtc_write(crtc_addr, 0x11, 0x00);
    stdvga_crtc_write(crtc_addr, 0x01, width / 8 - 1);
    stdvga_set_linelength(vmode_g, width);
    stdvga_crtc_write(crtc_addr, 0x12, height - 1);
    u8 v = 0;
    if ((height - 1) & 0x0100)
        v |= 0x02;
    if ((height - 1) & 0x0200)
        v |= 0x40;
    stdvga_crtc_mask(crtc_addr, 0x07, 0x42, v);

    stdvga_crtc_write(crtc_addr, 0x09, 0x00);
    stdvga_crtc_mask(crtc_addr, 0x17, 0x00, 0x03);
    stdvga_attr_mask(0x10, 0x00, 0x01);
    stdvga_grdc_write(0x06, 0x05);
    stdvga_sequ_write(0x02, 0x0f);
    if (memmodel != MM_PLANAR) {
        stdvga_crtc_mask(crtc_addr, 0x14, 0x00, 0x40);
        stdvga_attr_mask(0x10, 0x00, 0x40);
        stdvga_sequ_mask(0x04, 0x00, 0x08);
        stdvga_grdc_mask(0x05, 0x20, 0x40);
    }
    stdvga_attrindex_write(0x20);

    return 0;
}


/****************************************************************
 * Init
 ****************************************************************/

int
bochsvga_setup(void)
{
    int ret = stdvga_setup();
    if (ret)
        return ret;

    /* Sanity checks */
    dispi_write(VBE_DISPI_INDEX_ID, VBE_DISPI_ID0);
    if (dispi_read(VBE_DISPI_INDEX_ID) != VBE_DISPI_ID0) {
        dprintf(1, "No VBE DISPI interface detected, falling back to stdvga\n");
        return 0;
    }

    dispi_write(VBE_DISPI_INDEX_ID, VBE_DISPI_ID5);
    SET_VGA(dispi_found, 1);

    if (GET_GLOBAL(HaveRunInit))
        return 0;

    u32 lfb_addr = VBE_DISPI_LFB_PHYSICAL_ADDRESS;
    u32 io_addr = 0;
    int bdf = GET_GLOBAL(VgaBDF);
    if (CONFIG_VGA_PCI && bdf >= 0) {
        u16 vendor = pci_config_readw(bdf, PCI_VENDOR_ID);
        int barid, bar;
        switch (vendor) {
        case 0x15ad: /* qemu vmware vga */
            barid = 1;
            break;
        case 0x1234: /* stdvga */
            bar = pci_config_readl(bdf, PCI_BASE_ADDRESS_2);
            io_addr = bar & PCI_BASE_ADDRESS_IO_MASK;
            barid = 0;
            break;
        default: /* qxl, virtio */
            barid = 0;
            break;
        }
        bar = pci_config_readl(bdf, PCI_BASE_ADDRESS_0 + barid * 4);
        lfb_addr = bar & PCI_BASE_ADDRESS_MEM_MASK;
        dprintf(1, "VBE DISPI: bdf %02x:%02x.%x, bar %d\n", pci_bdf_to_bus(bdf)
                , pci_bdf_to_dev(bdf), pci_bdf_to_fn(bdf), barid);
    }

    SET_VGA(VBE_framebuffer, lfb_addr);
    u32 totalmem = dispi_read(VBE_DISPI_INDEX_VIDEO_MEMORY_64K) * 64 * 1024;
    SET_VGA(VBE_total_memory, totalmem);
    SET_VGA(VBE_win_granularity, 64);
    SET_VGA(VBE_capabilities, VBE_CAPABILITY_8BIT_DAC);

    dprintf(1, "VBE DISPI: lfb_addr=%x, size %d MB\n",
            lfb_addr, totalmem >> 20);

    // Validate modes
    u16 en = dispi_read(VBE_DISPI_INDEX_ENABLE);
    dispi_write(VBE_DISPI_INDEX_ENABLE, en | VBE_DISPI_GETCAPS);
    u16 max_xres = dispi_read(VBE_DISPI_INDEX_XRES);
    u16 max_bpp = dispi_read(VBE_DISPI_INDEX_BPP);
    dispi_write(VBE_DISPI_INDEX_ENABLE, en);
    struct generic_svga_mode *m = svga_modes;
    unsigned int mcount = GET_GLOBAL(svga_mcount);
    for (; m < &svga_modes[mcount]; m++) {
        u16 width = GET_GLOBAL(m->info.width);
        u16 height = GET_GLOBAL(m->info.height);
        u8 depth = GET_GLOBAL(m->info.depth);
        u32 mem = (height * DIV_ROUND_UP(width * vga_bpp(&m->info), 8)
                   * stdvga_vram_ratio(&m->info));

        if (width > max_xres || depth > max_bpp || mem > totalmem) {
            dprintf(1, "Removing mode %x\n", GET_GLOBAL(m->mode));
            SET_VGA(m->mode, 0xffff);
        }
    }

    if (io_addr) {
        int i;
        u8 *edid = (void*)(io_addr);
        for (i = 0; i < sizeof(VBE_edid); i++)
            SET_VGA(VBE_edid[i], readb(edid + i));
    }

    return 0;
}
