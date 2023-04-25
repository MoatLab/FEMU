// Main VGA bios initialization
//
// Copyright (C) 2009-2013  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2001-2008 the LGPL VGABios developers Team
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // SET_BDA
#include "bregs.h" // struct bregs
#include "hw/pci.h" // pci_config_readw
#include "hw/pci_regs.h" // PCI_VENDOR_ID
#include "hw/serialio.h" // serial_debug_preinit
#include "output.h" // dprintf
#include "std/optionrom.h" // struct pci_data
#include "std/pmm.h" // struct pmmheader
#include "string.h" // checksum_far
#include "vgabios.h" // SET_VGA
#include "vgahw.h" // vgahw_setup
#include "vgautil.h" // swcursor_check_event

#if CONFIG_X86
// Type of emulator platform - for dprintf with certain compile options.
int PlatformRunningOn VAR16;
#endif

/****************************************************************
 * PCI Data
 ****************************************************************/

struct pci_data rom_pci_data VAR16 VISIBLE16 = {
    .signature = PCI_ROM_SIGNATURE,
    .vendor = CONFIG_VGA_VID,
    .device = CONFIG_VGA_DID,
    .dlen = 0x18,
    .class_hi = 0x300,
    .irevision = 1,
    .type = PCIROM_CODETYPE_X86,
    .indicator = 0x80,
};


/****************************************************************
 * PMM call and extra stack setup
 ****************************************************************/

u32
allocate_pmm(u32 size, int highmem, int aligned)
{
    u32 pmmscan;
    for (pmmscan=0; pmmscan < BUILD_BIOS_SIZE; pmmscan+=16) {
        struct pmmheader *pmm = (void*)pmmscan;
        if (GET_FARVAR(SEG_BIOS, pmm->signature) != PMM_SIGNATURE)
            continue;
        if (checksum_far(SEG_BIOS, pmm, GET_FARVAR(SEG_BIOS, pmm->length)))
            continue;
        struct segoff_s entry = GET_FARVAR(SEG_BIOS, pmm->entry);
        dprintf(1, "Attempting to allocate %u bytes %s via pmm call to %04x:%04x\n"
                , size, highmem ? "highmem" : "lowmem"
                , entry.seg, entry.offset);
        u16 res1, res2;
        u16 flags = 8 |
            ( highmem ? 2 : 1 )|
            ( aligned ? 4 : 0 );
        size >>= 4;
        asm volatile(
            "pushl %0\n"
            "pushw %2\n"                // flags
            "pushl $0xffffffff\n"       // Anonymous handle
            "pushl %1\n"                // size
            "pushw $0x00\n"             // PMM allocation request
            "lcallw *12(%%esp)\n"
            "addl $16, %%esp\n"
            "cli\n"
            "cld\n"
            : "+r" (entry.segoff), "+r" (size), "+r" (flags),
              "=a" (res1), "=d" (res2) : : "cc", "memory");
        u32 res = res1 | (res2 << 16);
        if (!res || res == PMM_FUNCTION_NOT_SUPPORTED)
            return 0;
        return res;
    }
    return 0;
}

u16 ExtraStackSeg VAR16 VISIBLE16;

static void
allocate_extra_stack(void)
{
    if (!CONFIG_VGA_ALLOCATE_EXTRA_STACK)
        return;
    u32 res = allocate_pmm(CONFIG_VGA_EXTRA_STACK_SIZE, 0, 0);
    if (!res)
        return;
    dprintf(1, "VGA stack allocated at %x\n", res);
    SET_VGA(ExtraStackSeg, res >> 4);
    extern void entry_10_extrastack(void);
    SET_IVT(0x10, SEGOFF(get_global_seg(), (u32)entry_10_extrastack));
    return;
}


/****************************************************************
 * Timer hook
 ****************************************************************/

struct segoff_s Timer_Hook_Resume VAR16 VISIBLE16;

void VISIBLE16
handle_timer_hook(void)
{
    swcursor_check_event();
}

static void
hook_timer_irq(void)
{
    if (!CONFIG_VGA_EMULATE_TEXT)
        return;
    extern void entry_timer_hook(void);
    extern void entry_timer_hook_extrastack(void);
    struct segoff_s oldirq = GET_IVT(0x08);
    struct segoff_s newirq = SEGOFF(get_global_seg(), (u32)entry_timer_hook);
    if (CONFIG_VGA_ALLOCATE_EXTRA_STACK && GET_GLOBAL(ExtraStackSeg))
        newirq = SEGOFF(get_global_seg(), (u32)entry_timer_hook_extrastack);
    dprintf(1, "Hooking hardware timer irq (old=%x new=%x)\n"
            , oldirq.segoff, newirq.segoff);
    SET_VGA(Timer_Hook_Resume, oldirq);
    SET_IVT(0x08, newirq);
}


/****************************************************************
 * VGA post
 ****************************************************************/

static void
init_bios_area(void)
{
    // init detected hardware BIOS Area
    // set 80x25 color (not clear from RBIL but usual)
    set_equipment_flags(0x30, 0x20);

    // Set the basic modeset options
    SET_BDA(modeset_ctl, 0x51);

    SET_BDA(dcc_index, CONFIG_VGA_STDVGA_PORTS ? 0x08 : 0xff);

    // FIXME
    SET_BDA(video_msr, 0x00); // Unavailable on vanilla vga, but...
    SET_BDA(video_pal, 0x00); // Unavailable on vanilla vga, but...
}

int VgaBDF VAR16 = -1;
int HaveRunInit VAR16;

void VISIBLE16
vga_post(struct bregs *regs)
{
    serial_debug_preinit();
    dprintf(1, "Start SeaVGABIOS (version %s)\n", VERSION);
    dprintf(1, "VGABUILD: %s\n", BUILDINFO);
    debug_enter(regs, DEBUG_VGA_POST);

    if (CONFIG_VGA_PCI && !GET_GLOBAL(HaveRunInit)) {
        u16 bdf = regs->ax;
        if ((pci_config_readw(bdf, PCI_VENDOR_ID)
             == GET_GLOBAL(rom_pci_data.vendor))
            && (pci_config_readw(bdf, PCI_DEVICE_ID)
                == GET_GLOBAL(rom_pci_data.device)))
            SET_VGA(VgaBDF, bdf);
    }

    int ret = vgahw_setup();
    if (ret) {
        dprintf(1, "Failed to initialize VGA hardware.  Exiting.\n");
        return;
    }

    if (GET_GLOBAL(HaveRunInit))
        return;

    init_bios_area();

    if (CONFIG_VGA_STDVGA_PORTS)
        stdvga_build_video_param();

    extern void entry_10(void);
    SET_IVT(0x10, SEGOFF(get_global_seg(), (u32)entry_10));

    allocate_extra_stack();

    hook_timer_irq();

    SET_VGA(HaveRunInit, 1);

    // Fixup checksum
    extern u8 _rom_header_size, _rom_header_checksum;
    SET_VGA(_rom_header_checksum, 0);
    u8 sum = -checksum_far(get_global_seg(), 0,
                           GET_GLOBAL(_rom_header_size) * 512);
    SET_VGA(_rom_header_checksum, sum);
}
