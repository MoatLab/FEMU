// Simple framebuffer vgabios for use with qemu bochs-display device
//
// Copyright (C) 2019 Gerd Hoffmann <kraxel@redhat.com>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_BDA
#include "output.h" // dprintf
#include "string.h" // memset16_far
#include "bochsvga.h" // VBE_BOCHS_*
#include "hw/pci.h" // pci_config_readl
#include "hw/pci_regs.h" // PCI_BASE_ADDRESS_0
#include "vgabios.h" // SET_VGA
#include "vgautil.h" // VBE_total_memory

#define FRAMEBUFFER_WIDTH      1024
#define FRAMEBUFFER_HEIGHT     768
#define FRAMEBUFFER_BPP        4

int
bochs_display_setup(void)
{
    dprintf(1, "bochs-display: setup called\n");

    if (GET_GLOBAL(HaveRunInit))
        return 0;

    int bdf = GET_GLOBAL(VgaBDF);
    if (bdf == 0)
        return 0;

    u32 bar = pci_config_readl(bdf, PCI_BASE_ADDRESS_0);
    u32 lfb_addr = bar & PCI_BASE_ADDRESS_MEM_MASK;
    bar = pci_config_readl(bdf, PCI_BASE_ADDRESS_2);
    u32 io_addr = bar & PCI_BASE_ADDRESS_IO_MASK;
    dprintf(1, "bochs-display: bdf %02x:%02x.%x, bar 0 at 0x%x, bar 1 at 0x%x\n"
            , pci_bdf_to_bus(bdf) , pci_bdf_to_dev(bdf), pci_bdf_to_fn(bdf),
            lfb_addr, io_addr);

    u16 *dispi = (void*)(io_addr + 0x500);
    u8 *vga = (void*)(io_addr + 0x400);
    u16 id = readw(dispi + VBE_DISPI_INDEX_ID);
    dprintf(1, "bochs-display: id is 0x%x, %s\n", id
            , id == VBE_DISPI_ID5 ? "good" : "FAIL");
    if (id != VBE_DISPI_ID5)
        return -1;

    int i;
    u8 *edid = (void*)(io_addr);
    for (i = 0; i < sizeof(VBE_edid); i++)
        SET_VGA(VBE_edid[i], readb(edid + i));

    int fb_width  = FRAMEBUFFER_WIDTH;
    int fb_height = FRAMEBUFFER_HEIGHT;
    if (GET_GLOBAL(VBE_edid[0]) == 0x00 &&
        GET_GLOBAL(VBE_edid[1]) == 0xff) {
        fb_width = GET_GLOBAL(VBE_edid[54 + 2]);
        fb_width |= (GET_GLOBAL(VBE_edid[54 + 4]) & 0xf0) << 4;
        fb_height = GET_GLOBAL(VBE_edid[54 + 5]);
        fb_height |= (GET_GLOBAL(VBE_edid[54 + 7]) & 0xf0) << 4;
    }
    int fb_stride = FRAMEBUFFER_BPP * fb_width;

    dprintf(1, "bochs-display: using %dx%d, %d bpp (%d stride)\n"
            , fb_width, fb_height
            , FRAMEBUFFER_BPP * 8, fb_stride);

    cbvga_setup_modes(lfb_addr, FRAMEBUFFER_BPP * 8,
                      fb_width, fb_height, fb_stride);

    writew(dispi + VBE_DISPI_INDEX_XRES,   fb_width);
    writew(dispi + VBE_DISPI_INDEX_YRES,   fb_height);
    writew(dispi + VBE_DISPI_INDEX_BPP,    FRAMEBUFFER_BPP * 8);
    writew(dispi + VBE_DISPI_INDEX_ENABLE, VBE_DISPI_ENABLED);

    writeb(vga, 0x20); /* unblank (for qemu -device VGA) */

    return 0;
}
