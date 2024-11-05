// PCI config space access functions.
//
// Copyright (C) 2008  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2002  MandrakeSoft S.A.
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "output.h" // dprintf
#include "pci.h" // pci_config_writel
#include "pci_regs.h" // PCI_VENDOR_ID
#include "byteorder.h" // cpu_to_le16
#include "util.h" // udelay
#include "x86.h" // outl

#if CONFIG_X86
#define PORT_PCI_CMD           0x0cf8
#define PORT_PCI_DATA          0x0cfc
#elif CONFIG_PARISC
#include "parisc/hppa_hardware.h"
#endif

static u32 mmconfig;

static void *mmconfig_addr(u16 bdf, u32 addr)
{
    return (void*)(mmconfig + ((u32)bdf << 12) + addr);
}

static u32 ioconfig_cmd(u16 bdf, u32 addr)
{
    return 0x80000000 | (bdf << 8) | (addr & 0xfc);
}

/*
 * Memory mapped I/O
 *
 * readX()/writeX() do byteswapping and take an ioremapped address
 * __raw_readX()/__raw_writeX() don't byteswap and take an ioremapped address.
 * gsc_*() don't byteswap and operate on physical addresses;
 *   eg dev->hpa or 0xfee00000.
 */

/* each elroy has 0x2000 offset */
#define ELROY_MAX_BUSSES        4
unsigned long elroy_offset(u16 bdf)
{
    static const int elroy_hpa_offsets[ELROY_MAX_BUSSES] = { 0x30000, 0x32000, 0x38000, 0x3c000 };
    int bus = pci_bdf_to_bus(bdf);
    if (bus >= ELROY_MAX_BUSSES)
        return -1UL;
    return elroy_hpa_offsets[bus] - elroy_hpa_offsets[0];
}

void *elroy_port(unsigned long port, unsigned long offs)
{
    return (void *)(port + offs);
}

void pci_config_writel(u16 bdf, u32 addr, u32 val)
{
    if (has_astro) {
        unsigned long offs = elroy_offset(bdf);
        if (offs == -1UL)
            return;
        writel(elroy_port(PORT_PCI_CMD, offs), ioconfig_cmd((u8)bdf, addr));
        writel(elroy_port(PORT_PCI_DATA, offs), val);
    } else
    if (!MODESEGMENT && mmconfig) {
        writel(mmconfig_addr(bdf, addr), val);
    } else {
        *(u32*)PORT_PCI_CMD = ioconfig_cmd(bdf, addr);
        *(u32*)PORT_PCI_DATA = cpu_to_le32(val);
    }
}

void pci_config_writew(u16 bdf, u32 addr, u16 val)
{
    if (has_astro) {
        unsigned long offs = elroy_offset(bdf);
        if (offs == -1UL)
            return;
        writel(elroy_port(PORT_PCI_CMD, offs), ioconfig_cmd((u8)bdf, addr));
        writew(elroy_port(PORT_PCI_DATA + (addr & 2), offs), val);
    } else
    if (!MODESEGMENT && mmconfig) {
        writew(mmconfig_addr(bdf, addr), val);
    } else {
        *(u32*)PORT_PCI_CMD = ioconfig_cmd(bdf, addr);
        *(u16*)(PORT_PCI_DATA + (addr & 2)) = cpu_to_le16(val);
    }
}

void pci_config_writeb(u16 bdf, u32 addr, u8 val)
{
    if (has_astro) {
        unsigned long offs = elroy_offset(bdf);
        if (offs == -1UL)
            return;
        writel(elroy_port(PORT_PCI_CMD, offs), ioconfig_cmd((u8)bdf, addr));
        writeb(elroy_port(PORT_PCI_DATA + (addr & 3), offs), val);
    } else
    if (!MODESEGMENT && mmconfig) {
        writeb(mmconfig_addr(bdf, addr), val);
    } else {
        *(u32*)PORT_PCI_CMD = ioconfig_cmd(bdf, addr);
        *(u8*)(PORT_PCI_DATA + (addr & 3)) = val;
    }
}

u32 pci_config_readl(u16 bdf, u32 addr)
{
    if (has_astro) {
        unsigned long offs = elroy_offset(bdf);
        if (offs == -1UL)
            return -1;
        writel(elroy_port(PORT_PCI_CMD, offs), ioconfig_cmd((u8)bdf, addr));
        return readl(elroy_port(PORT_PCI_DATA, offs));
    } else
    if (!MODESEGMENT && mmconfig) {
        return readl(mmconfig_addr(bdf, addr));
    } else {
        *(u32*)PORT_PCI_CMD = ioconfig_cmd(bdf, addr);
        return (le32_to_cpu(*(u32*)PORT_PCI_DATA));
    }
}

u16 pci_config_readw(u16 bdf, u32 addr)
{
    if (has_astro) {
        unsigned long offs = elroy_offset(bdf);
        if (offs == -1UL)
            return -1;
        writel(elroy_port(PORT_PCI_CMD, offs), ioconfig_cmd((u8)bdf, addr));
        return readw(elroy_port(PORT_PCI_DATA + (addr & 2), offs));
    } else
    if (!MODESEGMENT && mmconfig) {
        return readw(mmconfig_addr(bdf, addr));
    } else {
        *(u32*)PORT_PCI_CMD = ioconfig_cmd(bdf, addr);
        return (le16_to_cpu(*(u16*)(PORT_PCI_DATA + (addr & 2))));
    }
}

u8 pci_config_readb(u16 bdf, u32 addr)
{
    if (has_astro) {
        unsigned long offs = elroy_offset(bdf);
        if (offs == -1UL)
            return -1;
        writel(elroy_port(PORT_PCI_CMD, offs), ioconfig_cmd((u8)bdf, addr));
        return readb(elroy_port(PORT_PCI_DATA + (addr & 3), offs));
    } else
    if (!MODESEGMENT && mmconfig) {
        return readb(mmconfig_addr(bdf, addr));
    } else {
        *(u32*)PORT_PCI_CMD = ioconfig_cmd(bdf, addr);
        return (*(u8*)(PORT_PCI_DATA + (addr & 3)));
    }
}

void
pci_config_maskw(u16 bdf, u32 addr, u16 off, u16 on)
{
    u16 val = pci_config_readw(bdf, addr);
    val = (val & ~off) | on;
    pci_config_writew(bdf, addr, val);
}

void
pci_enable_mmconfig(u64 addr, const char *name)
{
    if (addr >= 0x100000000ll)
        return;
    dprintf(1, "PCIe: using %s mmconfig at 0x%llx\n", name, addr);
    mmconfig = addr;
}

u8 pci_find_capability(u16 bdf, u8 cap_id, u8 cap)
{
    int i;
    u16 status = pci_config_readw(bdf, PCI_STATUS);

    if (!(status & PCI_STATUS_CAP_LIST))
        return 0;

    if (cap == 0) {
        /* find first */
        cap = pci_config_readb(bdf, PCI_CAPABILITY_LIST);
    } else {
        /* find next */
        cap = pci_config_readb(bdf, cap + PCI_CAP_LIST_NEXT);
    }
    for (i = 0; cap && i <= 0xff; i++) {
        if (pci_config_readb(bdf, cap + PCI_CAP_LIST_ID) == cap_id)
            return cap;
        cap = pci_config_readb(bdf, cap + PCI_CAP_LIST_NEXT);
    }

    return 0;
}

// Helper function for foreachbdf() macro - return next device
int
pci_next(int bdf, int bus)
{
    if (pci_bdf_to_fn(bdf) == 0
        && (pci_config_readb(bdf, PCI_HEADER_TYPE) & 0x80) == 0)
        // Last found device wasn't a multi-function device - skip to
        // the next device.
        bdf += 8;
    else
        bdf += 1;

    for (;;) {
        if (pci_bdf_to_bus(bdf) != bus)
            return -1;

        u16 v = pci_config_readw(bdf, PCI_VENDOR_ID);
        if (v != 0x0000 && v != 0xffff)
            // Device is present.
            return bdf;

        if (pci_bdf_to_fn(bdf) == 0)
            bdf += 8;
        else
            bdf += 1;
    }
}

// Check if PCI is available at all
int
pci_probe_host(void)
{
    outl(0x80000000, PORT_PCI_CMD);
    if (inl(PORT_PCI_CMD) != 0x80000000) {
        dprintf(1, "Detected non-PCI system\n");
        return -1;
    }
    return 0;
}

void
pci_reboot(void)
{
    u8 v = inb(PORT_PCI_REBOOT) & ~6;
    outb(v|2, PORT_PCI_REBOOT); /* Request hard reset */
    udelay(50);
    outb(v|6, PORT_PCI_REBOOT); /* Actually do the reset */
    udelay(50);
}
