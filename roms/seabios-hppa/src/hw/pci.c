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

void pci_config_writel(u16 bdf, u32 addr, u32 val)
{
    if (!MODESEGMENT && mmconfig) {
        writel(mmconfig_addr(bdf, addr), val);
    } else {
        outl(ioconfig_cmd(bdf, addr), PORT_PCI_CMD);
        outl(cpu_to_le32(val), PORT_PCI_DATA);
    }
}

void pci_config_writew(u16 bdf, u32 addr, u16 val)
{
    if (!MODESEGMENT && mmconfig) {
        writew(mmconfig_addr(bdf, addr), val);
    } else {
        outl(ioconfig_cmd(bdf, addr), PORT_PCI_CMD);
        outw(cpu_to_le16(val), PORT_PCI_DATA + (addr & 2));
    }
}

void pci_config_writeb(u16 bdf, u32 addr, u8 val)
{
    if (!MODESEGMENT && mmconfig) {
        writeb(mmconfig_addr(bdf, addr), val);
    } else {
        outl(ioconfig_cmd(bdf, addr), PORT_PCI_CMD);
        outb(val, PORT_PCI_DATA + (addr & 3));
    }
}

u32 pci_config_readl(u16 bdf, u32 addr)
{
    if (!MODESEGMENT && mmconfig) {
        return readl(mmconfig_addr(bdf, addr));
    } else {
        outl(ioconfig_cmd(bdf, addr), PORT_PCI_CMD);
        return le32_to_cpu(inl(PORT_PCI_DATA));
    }
}

u16 pci_config_readw(u16 bdf, u32 addr)
{
    if (!MODESEGMENT && mmconfig) {
        return readw(mmconfig_addr(bdf, addr));
    } else {
        outl(ioconfig_cmd(bdf, addr), PORT_PCI_CMD);
        return le16_to_cpu(inw(PORT_PCI_DATA + (addr & 2)));
    }
}

u8 pci_config_readb(u16 bdf, u32 addr)
{
    if (!MODESEGMENT && mmconfig) {
        return readb(mmconfig_addr(bdf, addr));
    } else {
        outl(ioconfig_cmd(bdf, addr), PORT_PCI_CMD);
        return inb(PORT_PCI_DATA + (addr & 3));
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
