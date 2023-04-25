// Glue code for parisc architecture
//
// Copyright (C) 2017-2022  Helge Deller <deller@gmx.de>
// Copyright (C) 2019 Sven Schnelle <svens@stackframe.org>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_BDA
#include "bregs.h" // struct bregs
#include "hw/pic.h" // enable_hwirq
#include "output.h" // debug_enter
#include "stacks.h" // call16_int
#include "string.h" // memset
#include "util.h" // serial_setup
#include "malloc.h" // malloc
#include "hw/serialio.h" // qemu_debug_port
#include "hw/pcidevice.h" // foreachpci
#include "hw/pci.h" // pci_config_readl
#include "hw/pci_ids.h" // PCI IDs
#include "hw/pci_regs.h" // PCI_BASE_ADDRESS_0
#include "hw/ata.h"
#include "hw/blockcmd.h" // scsi_is_ready()
#include "hw/rtc.h"
#include "fw/paravirt.h" // PlatformRunningOn
#include "vgahw.h"
#include "parisc/hppa_hardware.h" // DINO_UART_BASE
#include "parisc/pdc.h"
#include "parisc/b160l.h"
#include "parisc/sticore.h"
#include "parisc/lasips2.h"

#include "vgabios.h"

#define SEABIOS_HPPA_VERSION 6

/*
 * Various variables which are needed by x86 code.
 * Defined here to be able to link seabios.
 */
int HaveRunPost;
u8 ExtraStack[BUILD_EXTRA_STACK_SIZE+1] __aligned(8);
u8 *StackPos;
u8 __VISIBLE parisc_stack[32*1024] __aligned(64);

volatile int num_online_cpus;
int __VISIBLE toc_lock = 1;
union {
	struct pdc_toc_pim_11 pim11;
	struct pdc_toc_pim_20 pim20;
} pim_toc_data[HPPA_MAX_CPUS] __VISIBLE __aligned(8);

#define is_64bit()	0	/* we only support 32-bit PDC for now. */

u8 BiosChecksum;

char zonefseg_start, zonefseg_end;  // SYMBOLS
char varlow_start, varlow_end, final_varlow_start;
char final_readonly_start;
char code32flat_start, code32flat_end;
char zonelow_base;

struct bios_data_area_s __VISIBLE bios_data_area;
struct vga_bda_s	__VISIBLE vga_bios_data_area;
struct floppy_dbt_s diskette_param_table;
struct bregs regs;
unsigned long parisc_vga_mem;
unsigned long parisc_vga_mmio;
struct segoff_s ivt_table[256];

void mtrr_setup(void) { }
void mouse_init(void) { }
void pnp_init(void) { }
u16  get_pnp_offset(void) { return 0; }
void mathcp_setup(void) { }
void smp_setup(void) { }
void bios32_init(void) { }
void yield_toirq(void) { }
void farcall16(struct bregs *callregs) { }
void farcall16big(struct bregs *callregs) { }
void mutex_lock(struct mutex_s *mutex) { }
void mutex_unlock(struct mutex_s *mutex) { }
void start_preempt(void) { }
void finish_preempt(void) { }
int wait_preempt(void) { return 0; }

void cpuid(u32 index, u32 *eax, u32 *ebx, u32 *ecx, u32 *edx)
{
    *eax = *ebx = *ecx = *edx = 0;
}

void wrmsr_smp(u32 index, u64 val) { }

/********************************************************
 * PA-RISC specific constants and functions.
 ********************************************************/

/* Pointer to zero-page of PA-RISC */
#define PAGE0 ((volatile struct zeropage *) 0UL)

/* variables provided by qemu */
extern unsigned long boot_args[];
#define ram_size		(boot_args[0])
#define linux_kernel_entry	(boot_args[1])
#define cmdline			(boot_args[2])
#define initrd_start		(boot_args[3])
#define initrd_end		(boot_args[4])
#define smp_cpus		(boot_args[5])
#define pdc_debug               (boot_args[6])
#define fw_cfg_port		(boot_args[7])

/* flags for pdc_debug */
#define DEBUG_PDC       0x0001
#define DEBUG_IODC      0x0002

int pdc_console;
/* flags for pdc_console */
#define CONSOLE_DEFAULT   0x0000
#define CONSOLE_SERIAL    0x0001
#define CONSOLE_GRAPHICS  0x0002

int sti_font;

/* Want PDC boot menu? Enable via qemu "-boot menu=on" option. */
unsigned int show_boot_menu;
unsigned int interact_ipl;

unsigned long PORT_QEMU_CFG_CTL;
unsigned int tlb_entries = 256;
unsigned int btlb_entries = 8;

#define PARISC_SERIAL_CONSOLE   PORT_SERIAL1

extern char pdc_entry;
extern char pdc_entry_table[12];
extern char iodc_entry[512];
extern char iodc_entry_table[14*4];

/* args as handed over for firmware calls */
#define ARG0 arg[7-0]
#define ARG1 arg[7-1]
#define ARG2 arg[7-2]
#define ARG3 arg[7-3]
#define ARG4 arg[7-4]
#define ARG5 arg[7-5]
#define ARG6 arg[7-6]
#define ARG7 arg[7-7]

/* size of I/O block used in HP firmware */
#define FW_BLOCKSIZE    2048

#define MIN_RAM_SIZE	(16*1024*1024) // 16 MB

#define MEM_PDC_ENTRY	0x4800	/* as in a B160L */

#define CPU_HPA_IDX(i)  (CPU_HPA + (i)*0x1000) /* CPU_HPA of CPU#i */

static int index_of_CPU_HPA(unsigned long hpa) {
    int i;
    for (i = 0; i < smp_cpus; i++) {
        if (hpa == CPU_HPA_IDX(i))
            return i;
    }
    return -1;
}

static unsigned long GoldenMemory = MIN_RAM_SIZE;

static unsigned int chassis_code = 0;

/*
 * Emulate the power switch button flag in head section of firmware.
 * Bit 31 (the lowest bit) is the status of the power switch.
 * This bit is "1" if the button is NOT pressed.
 */
int powersw_nop;
int *powersw_ptr;

void __VISIBLE __noreturn hlt(void)
{
    if (pdc_debug)
        printf("HALT initiated from %p\n",  __builtin_return_address(0));
    printf("SeaBIOS wants SYSTEM HALT.\n\n");
    /* call qemu artificial "halt" asm instruction */
    asm volatile("\t.word 0xfffdead0": : :"memory");
    while (1);
}

static void check_powersw_button(void)
{
    /* halt immediately if power button was pressed. */
    if ((*powersw_ptr & 1) == 0) {
        printf("SeaBIOS machine power switch was pressed.\n");
        hlt();
    }
}

void __VISIBLE __noreturn reset(void)
{
    if (pdc_debug)
        printf("RESET initiated from %p\n",  __builtin_return_address(0));
    printf("SeaBIOS wants SYSTEM RESET.\n"
            "***************************\n");
    check_powersw_button();
    PAGE0->imm_soft_boot = 1;
    /* call qemu artificial "reset" asm instruction */
    asm volatile("\t.word 0xfffdead1": : :"memory");
    while (1);
}

#undef BUG_ON
#define BUG_ON(cond) \
    if (unlikely(cond)) \
{ printf("ERROR in %s:%d\n", __FUNCTION__, __LINE__); hlt(); }

void flush_data_cache(char *start, size_t length)
{
    char *end = start + length;

    do
    {
        asm volatile("fdc 0(%0)" : : "r" (start));
        asm volatile("fic 0(%%sr0,%0)" : : "r" (start));
        start += 16;
    } while (start < end);
    asm volatile("fdc 0(%0)" : : "r" (end));

    asm ("sync");
}

void memdump(void *mem, unsigned long len)
{
    printf("memdump @ 0x%x : ", (unsigned int) mem);
    while (len--) {
        printf("0x%x ", (unsigned int) *(unsigned char *)mem);
        mem++;
    }
    printf("\n");
}

/********************************************************
 * Boot drives
 ********************************************************/

static struct drive_s *boot_drive; // really currently booted drive
static struct drive_s *parisc_boot_harddisc; // first hard disc
static struct drive_s *parisc_boot_cdrom;    // first DVD or CD-ROM

static struct pdc_module_path mod_path_emulated_drives = {
    .path = { .flags = 0x0, .bc = { 0xff, 0xff, 0xff, 0x8, 0x0, 0x0 }, .mod = 0x0  },
    .layers = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 } // first two layer entries get replaced
};

/********************************************************
 * FIRMWARE IO Dependent Code (IODC) HANDLER
 ********************************************************/

typedef struct {
    unsigned long hpa;
    struct pdc_iodc *iodc;
    struct pdc_system_map_mod_info *mod_info;
    struct pdc_module_path *mod_path;
    int num_addr;
    int add_addr[5];
} hppa_device_t;

static hppa_device_t parisc_devices[HPPA_MAX_CPUS+16] = { PARISC_DEVICE_LIST };

#define PARISC_KEEP_LIST \
    GSC_HPA,\
    DINO_HPA,\
    DINO_UART_HPA,\
    /* DINO_SCSI_HPA, */ \
    LASI_HPA, \
    LASI_UART_HPA, \
    LASI_LAN_HPA, \
    LASI_LPT_HPA, \
    CPU_HPA,\
    MEMORY_HPA,\
    LASI_GFX_HPA,\
    LASI_PS2KBD_HPA, \
    LASI_PS2MOU_HPA, \
    0

static const char *hpa_name(unsigned long hpa)
{
    struct pci_device *pci;
    int i;

    #define DO(x) if (hpa == x) return #x;
    DO(GSC_HPA)
    DO(DINO_HPA)
    DO(DINO_UART_HPA)
    DO(DINO_SCSI_HPA)
    DO(CPU_HPA)
    DO(MEMORY_HPA)
    DO(IDE_HPA)
    DO(LASI_HPA)
    DO(LASI_UART_HPA)
    DO(LASI_SCSI_HPA)
    DO(LASI_LAN_HPA)
    DO(LASI_LPT_HPA)
    DO(LASI_AUDIO_HPA)
    DO(LASI_PS2KBD_HPA)
    DO(LASI_PS2MOU_HPA)
    DO(LASI_GFX_HPA)
    #undef DO

    /* could be one of the SMP CPUs */
    for (i = 1; i < smp_cpus; i++) {
        static char CPU_TXT[] = "CPU_HPA_x";
        if (hpa == CPU_HPA_IDX(i)) {
            CPU_TXT[8] = '0'+i;
            return CPU_TXT;
        }
    }

    /* could be a PCI device */
    foreachpci(pci) {
        unsigned long mem, mmio;
        mem = pci_config_readl(pci->bdf, PCI_BASE_ADDRESS_0);
        mem &= PCI_BASE_ADDRESS_MEM_MASK;
        if (hpa == mem)
            return "HPA_PCI_CARD_MEM";
        mmio = pci_config_readl(pci->bdf, PCI_BASE_ADDRESS_2);
        mmio &= PCI_BASE_ADDRESS_MEM_MASK;
        if (hpa == mem)
            return "HPA_PCI_CARD_MMIO";
    }

    return "UNKNOWN HPA";
}

int HPA_is_serial_device(unsigned long hpa)
{
    return (hpa == DINO_UART_HPA) || (hpa == LASI_UART_HPA);
}

int HPA_is_storage_device(unsigned long hpa)
{
    return (hpa == DINO_SCSI_HPA) || (hpa == IDE_HPA) || (hpa == LASI_SCSI_HPA);
}

int HPA_is_keyboard_device(unsigned long hpa)
{
    return (hpa == LASI_PS2KBD_HPA);
}

#define GFX_NUM_PAGES 0x2000
int HPA_is_graphics_device(unsigned long hpa)
{
    return (hpa == LASI_GFX_HPA) || (hpa == 0xf4000000) ||
           (hpa == 0xf8000000)   || (hpa == 0xfa000000);
}

static const char *hpa_device_name(unsigned long hpa, int output)
{
    return HPA_is_graphics_device(hpa) ? "GRAPHICS(1)" :
            HPA_is_keyboard_device(hpa) ? "PS2" :
            ((hpa + 0x800) == PORT_SERIAL1) ?
                "SERIAL_1.9600.8.none" : "SERIAL_2.9600.8.none";
}

static unsigned long keep_list[] = { PARISC_KEEP_LIST };

static void remove_from_keep_list(unsigned long hpa)
{
    int i = 0;

    while (keep_list[i] && keep_list[i] != hpa)
        i++;
    while (keep_list[i]) {
            ++i;
            keep_list[i-1] = keep_list[i];
    }
}

static int keep_this_hpa(unsigned long hpa)
{
    int i = 0;

    while (keep_list[i]) {
        if (keep_list[i] == hpa)
            return 1;
        i++;
    }
    return 0;
}

/* Rebuild hardware list and drop all devices which are not listed in
 * PARISC_KEEP_LIST. Generate num_cpus CPUs. */
static void remove_parisc_devices(unsigned int num_cpus)
{
    static struct pdc_system_map_mod_info modinfo[HPPA_MAX_CPUS] = { {1,}, };
    static struct pdc_module_path modpath[HPPA_MAX_CPUS] = { {{1,}} };
    hppa_device_t *cpu_dev = NULL;
    unsigned long hpa;
    int i, p, t;

    /* already initialized? */
    static int uninitialized = 1;
    if (!uninitialized)
        return;
    uninitialized = 0;

    /* check if qemu emulates LASI chip (LASI_IAR exists) */
    if (*(unsigned long *)(LASI_HPA+16) == 0) {
        remove_from_keep_list(LASI_UART_HPA);
        remove_from_keep_list(LASI_LAN_HPA);
        remove_from_keep_list(LASI_LPT_HPA);
    } else {
        /* check if qemu emulates LASI i82596 LAN card */
        if (*(unsigned long *)(LASI_LAN_HPA+12) != 0xBEEFBABE)
            remove_from_keep_list(LASI_LAN_HPA);
    }

    p = t = 0;
    while ((hpa = parisc_devices[p].hpa) != 0) {
        if (keep_this_hpa(hpa)) {
            parisc_devices[t] = parisc_devices[p];
            if (hpa == CPU_HPA)
                cpu_dev = &parisc_devices[t];
            t++;
        }
        p++;
    }

    /* Fix monarch CPU */
    BUG_ON(!cpu_dev);
    cpu_dev->mod_info->mod_addr = CPU_HPA;
    cpu_dev->mod_path->path.mod = (CPU_HPA - DINO_HPA) / 0x1000;

    /* Generate other CPU devices */
    for (i = 1; i < num_cpus; i++) {
        unsigned long hpa = CPU_HPA_IDX(i);

        parisc_devices[t] = *cpu_dev;
        parisc_devices[t].hpa = hpa;

        modinfo[i] = *cpu_dev->mod_info;
        modinfo[i].mod_addr = hpa;
        parisc_devices[t].mod_info = &modinfo[i];

        modpath[i] = *cpu_dev->mod_path;
        modpath[i].path.mod = (hpa - DINO_HPA) / 0x1000;
        parisc_devices[t].mod_path = &modpath[i];

        t++;
    }

    BUG_ON(t > ARRAY_SIZE(parisc_devices));

    while (t < ARRAY_SIZE(parisc_devices)) {
        memset(&parisc_devices[t], 0, sizeof(parisc_devices[0]));
        t++;
    }
}

static int find_hpa_index(unsigned long hpa)
{
    int i;
    if (!hpa)
        return -1;
    for (i = 0; i < (ARRAY_SIZE(parisc_devices)-1); i++) {
        if (hpa == parisc_devices[i].hpa)
            return i;
        if (!parisc_devices[i].hpa)
            return -1;
    }
    return -1;
}

static int compare_module_path(struct pdc_module_path *path,
                               struct pdc_module_path *search,
                               int check_layers)
{
    int i;

    if (path->path.mod != search->path.mod)
        return -1;

    for(i = 0; i < ARRAY_SIZE(path->path.bc); i++) {
        if (path->path.bc[i] != search->path.bc[i])
            return -1;
    }

    if (check_layers) {
        for(i = 0; i < ARRAY_SIZE(path->layers); i++) {
            if (path->layers[i] != search->layers[i])
                return -1;
        }
    }
    return 0;
}

static hppa_device_t *find_hppa_device_by_path(struct pdc_module_path *search,
                                        unsigned long *index, int check_layers)
{
    hppa_device_t *dev;
    int i;

    for (i = 0; i < (ARRAY_SIZE(parisc_devices)-1); i++) {
        dev = parisc_devices + i;
        if (!dev->hpa)
            continue;

        if (!compare_module_path(dev->mod_path, search, check_layers)) {
            *index = i;
            return dev;
        }
    }
    return NULL;
}

#define SERIAL_TIMEOUT 20
static unsigned long parisc_serial_in(char *c, unsigned long maxchars)
{
    portaddr_t addr = PAGE0->mem_kbd.hpa + 0x800; /* PARISC_SERIAL_CONSOLE */
    unsigned long end = timer_calc(SERIAL_TIMEOUT);
    unsigned long count = 0;
    while (count < maxchars) {
        u8 lsr = inb(addr+SEROFF_LSR);
        if (lsr & 0x01) {
            // Success - can read data
            *c++ = inb(addr+SEROFF_DATA);
            count++;
        }
        if (timer_check(end))
            break;
    }
    return count;
}

static void parisc_serial_out(char c)
{
    portaddr_t addr = PAGE0->mem_cons.hpa + 0x800; /* PARISC_SERIAL_CONSOLE */
    for (;;) {
        if (c == '\n')
            parisc_serial_out('\r');
        u8 lsr = inb(addr+SEROFF_LSR);
        if ((lsr & 0x60) == 0x60) {
            // Success - can write data
            outb(c, addr+SEROFF_DATA);
            break;
        }
    }
}

static void parisc_putchar_internal(char c)
{
    if (HPA_is_graphics_device(PAGE0->mem_cons.hpa))
        sti_putc(c);
    else
        parisc_serial_out(c);
}

/* print char to default PDC output device */
void parisc_putchar(char c)
{
    if (c == '\n')
        parisc_putchar_internal('\r');
    parisc_putchar_internal(c);
}

/* read char from default PDC input device (serial port / ps2-kbd) */
static char parisc_getchar(void)
{
    int count;
    char c;

    if (HPA_is_serial_device(PAGE0->mem_kbd.hpa))
        count = parisc_serial_in(&c, sizeof(c));
    else
        count = lasips2_kbd_in(&c, sizeof(c));
    if (count == 0)
        c = 0;
    return c;
}

void iodc_log_call(unsigned int *arg, const char *func)
{
    if (pdc_debug & DEBUG_IODC) {
        printf("\nIODC %s called: hpa=0x%x (%s) option=0x%x arg2=0x%x arg3=0x%x ", func, ARG0, hpa_name(ARG0), ARG1, ARG2, ARG3);
        printf("result=0x%x arg5=0x%x arg6=0x%x arg7=0x%x\n", ARG4, ARG5, ARG6, ARG7);
    }
}

#define FUNC_MANY_ARGS , \
    int a0, int a1, int a2, int a3,  int a4,  int a5,  int a6, \
    int a7, int a8, int a9, int a10, int a11, int a12


int __VISIBLE parisc_iodc_ENTRY_IO(unsigned int *arg FUNC_MANY_ARGS)
{
    unsigned long hpa = ARG0;
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG4;
    int ret, len;
    char *c;
    struct disk_op_s disk_op;

    if (1 &&
            (((HPA_is_serial_device(hpa) || HPA_is_graphics_device(hpa)) && option == ENTRY_IO_COUT) ||
             ((HPA_is_serial_device(hpa) || HPA_is_graphics_device(hpa)) && option == ENTRY_IO_CIN) ||
             (HPA_is_storage_device(hpa) && option == ENTRY_IO_BOOTIN))) {
        /* avoid debug messages */
    } else {
        iodc_log_call(arg, __FUNCTION__);
    }

    /* console I/O */
    switch (option) {
        case ENTRY_IO_COUT: /* console output */
            c = (char*)ARG6;
            result[0] = len = ARG7;
            if (HPA_is_serial_device(hpa) || HPA_is_graphics_device(hpa)) {
                while (len--)
                    printf("%c", *c++);
            }
            return PDC_OK;
        case ENTRY_IO_CIN: /* console input, with 5 seconds timeout */
            c = (char*)ARG6;
            /* FIXME: Add loop to wait for up to 5 seconds for input */
            if (HPA_is_serial_device(hpa))
                result[0] = parisc_serial_in(c, ARG7);
            else if (HPA_is_keyboard_device(hpa))
                result[0] = lasips2_kbd_in(c, ARG7);
            return PDC_OK;
    }

    /* boot medium I/O */
    if (HPA_is_storage_device(hpa))
        switch (option) {
            case ENTRY_IO_BOOTIN: /* boot medium IN */
            case ENTRY_IO_BBLOCK_IN: /* boot block medium IN */
                disk_op.drive_fl = boot_drive;
                disk_op.buf_fl = (void*)ARG6;
                disk_op.command = CMD_READ;
                if (option == ENTRY_IO_BBLOCK_IN) { /* in 2k blocks */
                    disk_op.count = (ARG7 * ((u64)FW_BLOCKSIZE / disk_op.drive_fl->blksize));
                    disk_op.lba = (ARG5 * ((u64)FW_BLOCKSIZE / disk_op.drive_fl->blksize));
                } else {
                    disk_op.count = (ARG7 / disk_op.drive_fl->blksize);
                    disk_op.lba = (ARG5 / disk_op.drive_fl->blksize);
                }
                // ARG8 = maxsize !!!
                ret = process_op(&disk_op);
                // dprintf(0, "\nBOOT IO res %d count = %d\n", ret, ARG7);
                result[0] = ARG7;
                if (ret)
                    return PDC_ERROR;
                return PDC_OK;
        }

    if (option == ENTRY_IO_CLOSE)
        return PDC_OK;

    //	BUG_ON(1);
    iodc_log_call(arg, __FUNCTION__);

    return PDC_BAD_OPTION;
}


int __VISIBLE parisc_iodc_ENTRY_INIT(unsigned int *arg FUNC_MANY_ARGS)
{
    unsigned long hpa = ARG0;
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG4;
    int hpa_index;

    iodc_log_call(arg, __FUNCTION__);

    hpa_index = find_hpa_index(hpa);
    if (hpa_index < 0 && hpa != IDE_HPA)
        return PDC_INVALID_ARG;

    switch (option) {
        case ENTRY_INIT_SRCH_FRST: /* 2: Search first */
            memcpy((void *)ARG3, &mod_path_emulated_drives.layers,
                sizeof(mod_path_emulated_drives.layers)); /* fill ID_addr */
            result[0] = 0;
            result[1] = HPA_is_serial_device(hpa) ? CL_DUPLEX:
                HPA_is_storage_device(hpa) ? CL_RANDOM : 0;
            result[2] = result[3] = 0; /* No network card, so no MAC. */
            return PDC_OK;
	case ENTRY_INIT_SRCH_NEXT: /* 3: Search next */
            return PDC_NE_BOOTDEV; /* No further boot devices */
        case ENTRY_INIT_MOD_DEV: /* 4: Init & test mod & dev */
        case ENTRY_INIT_DEV:     /* 5: Init & test dev */
            result[0] = 0; /* module IO_STATUS */
            result[1] = HPA_is_serial_device(hpa) ? CL_DUPLEX:
                HPA_is_storage_device(hpa) ? CL_RANDOM : 0;
            result[2] = result[3] = 0; /* TODO?: MAC of network card. */
            return PDC_OK;
        case ENTRY_INIT_MOD:    /* 6: INIT */
            result[0] = 0; /* module IO_STATUS */
            return PDC_OK;
    }
    return PDC_BAD_OPTION;
}

int __VISIBLE parisc_iodc_ENTRY_SPA(unsigned int *arg FUNC_MANY_ARGS)
{
    iodc_log_call(arg, __FUNCTION__);
    return PDC_BAD_OPTION;
}

int __VISIBLE parisc_iodc_ENTRY_CONFIG(unsigned int *arg FUNC_MANY_ARGS)
{
    iodc_log_call(arg, __FUNCTION__);
    return PDC_BAD_OPTION;
}

int __VISIBLE parisc_iodc_ENTRY_TEST(unsigned int *arg FUNC_MANY_ARGS)
{
    unsigned long hpa = ARG0;
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG4;
    int hpa_index;

    iodc_log_call(arg, __FUNCTION__);

    hpa_index = find_hpa_index(hpa);
    if (hpa_index < 0 && hpa != IDE_HPA)
        return PDC_INVALID_ARG;

    /* The options ARG1=0 and ARG1=1 are required. Others are optional. */
    if (option == 0) { // Return info
        unsigned long *list_addr = (unsigned long *)ARG5;
        list_addr[0] = 0; // no test lists available.
        result[0] = 0; // data buffer size, no bytes required.
        result[1] = 0; // message buffer size, no bytes required.
        return PDC_OK;
    }

    if (option == 1) { // Execute step
        result[0] = 0; // fixed address of remote por
        return PDC_OK;
    }

    return PDC_BAD_OPTION;
}

int __VISIBLE parisc_iodc_ENTRY_TLB(unsigned int *arg FUNC_MANY_ARGS)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG4;

    iodc_log_call(arg, __FUNCTION__);

    if (option == 0) {
        result[0] = 0; /* no TLB */
        result[1] = 0;
        return PDC_OK;
    }
    return PDC_BAD_OPTION;
}

/********************************************************
 * FIRMWARE PDC HANDLER
 ********************************************************/

#define STABLE_STORAGE_SIZE	512
static unsigned char stable_storage[STABLE_STORAGE_SIZE];

#define NVOLATILE_STORAGE_SIZE	512
static unsigned char nvolatile_storage[NVOLATILE_STORAGE_SIZE];

static void init_stable_storage(void)
{
    /* see ENGINEERING NOTE on page 4-92 in PDC2.0 doc */
    memset(&stable_storage, 0, STABLE_STORAGE_SIZE);
    // no intial paths
    stable_storage[0x07] = 0xff;
    stable_storage[0x67] = 0xff;
    stable_storage[0x87] = 0xff;
    stable_storage[0xa7] = 0xff;
    // 0x0e/0x0f => fastsize = all, needed for HPUX
    stable_storage[0x5f] = 0x0f;
}

static unsigned long lasi_rtc_read(void)
{
    return *(u32 *)LASI_RTC_HPA;
}

static void lasi_rtc_write(u32 val)
{
    *(u32 *)LASI_RTC_HPA = val;
}

/* values in PDC_CHASSIS */
const char * const systat[] = {
    "Off", "Fault", "Test", "Initialize",
    "Shutdown", "Warning", "Run", "All On"
};

static const char *pdc_name(unsigned long num)
{
#define DO(x) if (num == x) return #x;
        DO(PDC_POW_FAIL)
        DO(PDC_CHASSIS)
        DO(PDC_PIM)
        DO(PDC_MODEL)
        DO(PDC_CACHE)
        DO(PDC_HPA)
        DO(PDC_COPROC)
        DO(PDC_IODC)
        DO(PDC_TOD)
        DO(PDC_STABLE)
        DO(PDC_NVOLATILE)
        DO(PDC_ADD_VALID)
        DO(PDC_INSTR)
        DO(PDC_PROC)
        DO(PDC_BLOCK_TLB)
        DO(PDC_TLB)
        DO(PDC_MEM)
        DO(PDC_PSW)
        DO(PDC_SYSTEM_MAP)
        DO(PDC_SOFT_POWER)
        DO(PDC_CRASH_PREP)
        DO(PDC_MEM_MAP)
        DO(PDC_EEPROM)
        DO(PDC_NVM)
        DO(PDC_SEED_ERROR)
        DO(PDC_IO)
        DO(PDC_BROADCAST_RESET)
        DO(PDC_LAN_STATION_ID)
        DO(PDC_CHECK_RANGES)
        DO(PDC_NV_SECTIONS)
        DO(PDC_PERFORMANCE)
        DO(PDC_SYSTEM_INFO)
        DO(PDC_RDR)
        DO(PDC_INTRIGUE)
        DO(PDC_STI)
        DO(PDC_PCI_INDEX)
        DO(PDC_RELOCATE)
        DO(PDC_INITIATOR)
        DO(PDC_LINK)
#undef DO
        return "UNKNOWN!";
}

static int pdc_chassis(unsigned int *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;
    short *display_model = (short *)ARG3;

    switch (option) {
        case PDC_CHASSIS_DISP:
            ARG3 = ARG2;
            result = (unsigned long *)&ARG4; // do not write to ARG2, use &ARG4 instead
            // fall through
        case PDC_CHASSIS_DISPWARN:
            ARG4 = (ARG3 >> 17) & 7;
            chassis_code = ARG3 & 0xffff;
            if (0) printf("\nPDC_CHASSIS: %s (%d), %sCHASSIS  %0x\n",
                    systat[ARG4], ARG4, (ARG3>>16)&1 ? "blank display, ":"", chassis_code);
            // fall through
        case PDC_CHASSIS_WARN:
            // return warnings regarding fans, batteries and temperature: None!
            result[0] = 0;
            return PDC_OK;
        case PDC_RETURN_CHASSIS_INFO: /* return chassis LED/LCD info */
            // XXX: Later we could emulate an LCD display here.
            result[0] = result[1] = 4; // actcnt & maxcnt
            memset((char *)ARG3, 0, ARG4);
            display_model[0] = 1; // 1=DISPLAY_MODEL_NONE
            display_model[1] = 0; // 0=LCD WIDTH is 0
            return PDC_OK;
    }
    return PDC_BAD_PROC;
}

static int pdc_pim(unsigned int *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;
    unsigned long hpa;
    int i;
    unsigned int count, default_size;

    if (is_64bit())
	default_size = sizeof(struct pdc_toc_pim_20);
    else
	default_size = sizeof(struct pdc_toc_pim_11);

    switch (option) {
        case PDC_PIM_HPMC:
            break;
        case PDC_PIM_RETURN_SIZE:
            *result = default_size;
            // B160 returns only "2". Why?
            return PDC_OK;
        case PDC_PIM_LPMC:
        case PDC_PIM_SOFT_BOOT:
            break;
        case PDC_PIM_TOC:
            hpa = mfctl(CPU_HPA_CR_REG); /* get CPU HPA from cr7 */
            i = index_of_CPU_HPA(hpa);
            if (i < 0 || i >= HPPA_MAX_CPUS) {
                *result = PDC_INVALID_ARG;
                return PDC_OK;
            }
            if (( is_64bit() && pim_toc_data[i].pim20.cpu_state.val == 0) ||
                (!is_64bit() && pim_toc_data[i].pim11.cpu_state.val == 0)) {
                /* PIM contents invalid */
                *result = PDC_NE_MOD;
                return PDC_OK;
            }
            count = (default_size < ARG4) ? default_size : ARG4;
            memcpy((void *)ARG3, &pim_toc_data[i], count);
            *result = count;
            /* clear PIM contents */
            if (is_64bit())
                pim_toc_data[i].pim20.cpu_state.val = 0;
            else
                pim_toc_data[i].pim11.cpu_state.val = 0;
            return PDC_OK;
    }
    return PDC_BAD_OPTION;
}

static struct pdc_model model = { PARISC_PDC_MODEL };

static int pdc_model(unsigned int *arg)
{
    static const char model_str[] = PARISC_MODEL;
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;

    switch (option) {
        case PDC_MODEL_INFO:
            memcpy(result, &model, sizeof(model));
            return PDC_OK;
        case PDC_MODEL_VERSIONS:
            switch (ARG3) {
                case 0: /* return CPU0 version */
                    result[0] = 35; // TODO! ???
                    return PDC_OK;
                case 1: /* return PDC version */
                    result[0] = PARISC_PDC_VERSION;
                    return PDC_OK;
            }
            return -4; // invalid c_index
        case PDC_MODEL_SYSMODEL:
            result[0] = sizeof(model_str) - 1;
            strtcpy((char *)ARG4, model_str, sizeof(model_str));
            return PDC_OK;
        case PDC_MODEL_ENSPEC:
        case PDC_MODEL_DISPEC:
            if (ARG3 != model.pot_key)
                return -20;
            return PDC_OK;
        case PDC_MODEL_CPU_ID:
            result[0] = PARISC_PDC_CPUID;
            return PDC_OK;
        case PDC_MODEL_CAPABILITIES:
            result[0] = PARISC_PDC_CAPABILITIES;
            result[0] |= PDC_MODEL_OS32; /* we do support 32-bit */
            result[0] &= ~PDC_MODEL_OS64; /* but not 64-bit (yet) */
            return PDC_OK;
        case PDC_MODEL_GET_INSTALL_KERNEL:
            // No need to provide a special install kernel during installation of HP-UX
            return PDC_BAD_OPTION;
    }
    dprintf(0, "\n\nSeaBIOS: Unimplemented PDC_MODEL function %d %x %x %x %x\n", ARG1, ARG2, ARG3, ARG4, ARG5);
    return PDC_BAD_OPTION;
}

static int pdc_cache(unsigned int *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;
    static unsigned long cache_info[] = { PARISC_PDC_CACHE_INFO };
    static struct pdc_cache_info *machine_cache_info
        = (struct pdc_cache_info *) &cache_info;

    switch (option) {
        case PDC_CACHE_INFO:
            BUG_ON(sizeof(cache_info) != sizeof(*machine_cache_info));
            machine_cache_info->it_size = tlb_entries;
            machine_cache_info->dt_size = tlb_entries;
            machine_cache_info->it_loop = 1;
            machine_cache_info->dt_loop = 1;

#if 0
            dprintf(0, "\n\nCACHE  IC: %ld %ld %ld DC: %ld %ld %ld\n",
                    machine_cache_info->ic_count, machine_cache_info->ic_loop, machine_cache_info->ic_stride,
                    machine_cache_info->dc_count, machine_cache_info->dc_loop, machine_cache_info->dc_stride);
#endif
#if 1
            /* Increase cc_block from 1 to 11. This increases icache_stride
             * and dcache_stride to 32768 bytes. Revisit for HP-UX. */
            machine_cache_info->dc_conf.cc_block = 11;
            machine_cache_info->ic_conf.cc_block = 11;

            machine_cache_info->ic_size = 0; /* no instruction cache */
            machine_cache_info->ic_count = 0;
            machine_cache_info->ic_loop = 0;
            machine_cache_info->dc_size = 0; /* no data cache */
            machine_cache_info->dc_count = 0;
            machine_cache_info->dc_loop = 0;
#endif

            memcpy(result, cache_info, sizeof(cache_info));
            return PDC_OK;
    }
    dprintf(0, "\n\nSeaBIOS: Unimplemented PDC_CACHE function %d %x %x %x %x\n", ARG1, ARG2, ARG3, ARG4, ARG5);
    return PDC_BAD_OPTION;
}

static int pdc_hpa(unsigned int *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;
    unsigned long hpa;
    int i;

    switch (option) {
        case PDC_HPA_PROCESSOR:
            hpa = mfctl(CPU_HPA_CR_REG); /* get CPU HPA from cr7 */
            i = index_of_CPU_HPA(hpa);
            BUG_ON(i < 0); /* ARGH, someone modified cr7! */
            result[0] = hpa;    /* CPU_HPA */
            result[1] = i;      /* for SMP: 0,1,2,3,4...(num of this cpu) */
            return PDC_OK;
        case PDC_HPA_MODULES:
            return PDC_BAD_OPTION; // all modules on same board as the processor.
    }
    return PDC_BAD_OPTION;
}

static int pdc_coproc(unsigned int *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;
    unsigned long mask;
    switch (option) {
        case PDC_COPROC_CFG:
            memset(result, 0, 32 * sizeof(unsigned long));
            /* Set one bit per cpu in ccr_functional and ccr_present.
               Ignore that specification only mentions 8 bits for cr10
               and set all FPUs functional */
            mask = -1UL;
            mtctl(mask, 10); /* initialize cr10 */
            result[0] = mask;
            result[1] = mask;
            result[17] = 1; // Revision
            result[18] = 19; // Model
            return PDC_OK;
    }
    return PDC_BAD_OPTION;
}

static int pdc_iodc(unsigned int *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;
    unsigned long hpa;
    struct pdc_iodc *iodc_p;
    int hpa_index;
    unsigned char *c;

    // dprintf(0, "\n\nSeaBIOS: Info PDC_IODC function %ld ARG3=%x ARG4=%x ARG5=%x ARG6=%x\n", option, ARG3, ARG4, ARG5, ARG6);
    switch (option) {
        case PDC_IODC_READ:
            hpa = ARG3;
            if (hpa == IDE_HPA) { // do NOT check for DINO_SCSI_HPA, breaks Linux which scans IO areas for unlisted io modules
                iodc_p = &iodc_data_hpa_fff8c000; // workaround for PCI ATA
            } else {
                hpa_index = find_hpa_index(hpa);
                if (hpa_index < 0)
                    return -4; // not found
                iodc_p = parisc_devices[hpa_index].iodc;
            }

            if (ARG4 == PDC_IODC_INDEX_DATA) {
                // if (hpa == MEMORY_HPA)
                //	ARG6 = 2; // Memory modules return 2 bytes of IODC memory (result2 ret[0] = 0x6701f41 HI !!)
                memcpy((void*) ARG5, iodc_p, ARG6);
                c = (unsigned char *) ARG5;
                // printf("SeaBIOS: PDC_IODC get: hpa = 0x%lx, HV: 0x%x 0x%x IODC_SPA=0x%x  type 0x%x, \n", hpa, c[0], c[1], c[2], c[3]);
                // c[0] = iodc_p->hversion_model; // FIXME. BROKEN HERE !!!
                // c[1] = iodc_p->hversion_rev || (iodc_p->hversion << 4);
                *result = ARG6;
                return PDC_OK;
            }

            // ARG4 is IODC function to copy.
            if (ARG4 < PDC_IODC_RI_INIT || ARG4 > PDC_IODC_RI_TLB)
                return PDC_IODC_INVALID_INDEX;

            *result = 512; /* max size of function iodc_entry */
            if (ARG6 < *result)
                return PDC_IODC_COUNT;
            memcpy((void*) ARG5, &iodc_entry, *result);
            c = (unsigned char *) &iodc_entry_table;
            /* calculate offset into jump table. */
            c += (ARG4 - PDC_IODC_RI_INIT) * 2 * sizeof(unsigned int);
            memcpy((void*) ARG5, c, 2 * sizeof(unsigned int));
            // dprintf(0, "\n\nSeaBIOS: Info PDC_IODC function OK\n");
            flush_data_cache((char*)ARG5, *result);
            return PDC_OK;
            break;
        case PDC_IODC_NINIT:	/* non-destructive init */
        case PDC_IODC_DINIT:	/* destructive init */
            break;
        case PDC_IODC_MEMERR:
            result[0] = 0; /* IO_STATUS */
            result[1] = 0;
            result[2] = 0;
            result[3] = 0;
            return PDC_OK;
    }
    dprintf(0, "\n\nSeaBIOS: Unimplemented PDC_IODC function %ld ARG3=%x ARG4=%x ARG5=%x ARG6=%x\n", option, ARG3, ARG4, ARG5, ARG6);
    return PDC_BAD_OPTION;
}

static int pdc_tod(unsigned int *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;

    switch (option) {
        case PDC_TOD_READ:
            result[0] = lasi_rtc_read();
            result[1] = result[2] = result[3] = 0;
            return PDC_OK;
        case PDC_TOD_WRITE:
            lasi_rtc_write(ARG2);
            return PDC_OK;
        case 2: /* PDC_TOD_CALIBRATE_TIMERS */
            /* double-precision floating-point with frequency of Interval Timer in megahertz: */
            *(double*)&result[0] = (double)CPU_CLOCK_MHZ;
            /* unsigned 64-bit integers representing  clock accuracy in parts per billion: */
            result[2] = 1000000000; /* TOD_acc */
            result[3] = 0x5a6c; /* CR_acc (interval timer) */
            return PDC_OK;
    }
    dprintf(0, "\n\nSeaBIOS: Unimplemented PDC_TOD function %ld ARG2=%x ARG3=%x ARG4=%x\n", option, ARG2, ARG3, ARG4);
    return PDC_BAD_OPTION;
}

static int pdc_stable(unsigned int *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;

    // dprintf(0, "\n\nSeaBIOS: PDC_STABLE function %ld ARG2=%x ARG3=%x ARG4=%x\n", option, ARG2, ARG3, ARG4);
    switch (option) {
        case PDC_STABLE_READ:
            if ((ARG2 + ARG4) > STABLE_STORAGE_SIZE)
                return PDC_INVALID_ARG;
            memcpy((unsigned char *) ARG3, &stable_storage[ARG2], ARG4);
            return PDC_OK;
        case PDC_STABLE_WRITE:
            if ((ARG2 + ARG4) > STABLE_STORAGE_SIZE)
                return PDC_INVALID_ARG;
            memcpy(&stable_storage[ARG2], (unsigned char *) ARG3, ARG4);
            return PDC_OK;
        case PDC_STABLE_RETURN_SIZE:
            result[0] = STABLE_STORAGE_SIZE;
            return PDC_OK;
        case PDC_STABLE_VERIFY_CONTENTS:
            return PDC_OK;
        case PDC_STABLE_INITIALIZE:
            init_stable_storage();
            return PDC_OK;
    }
    return PDC_BAD_OPTION;
}

static int pdc_nvolatile(unsigned int *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;

    switch (option) {
        case PDC_NVOLATILE_READ:
            if ((ARG2 + ARG4) > NVOLATILE_STORAGE_SIZE)
                return PDC_INVALID_ARG;
            memcpy((unsigned char *) ARG3, &nvolatile_storage[ARG2], ARG4);
            return PDC_OK;
        case PDC_NVOLATILE_WRITE:
            if ((ARG2 + ARG4) > NVOLATILE_STORAGE_SIZE)
                return PDC_INVALID_ARG;
            memcpy(&nvolatile_storage[ARG2], (unsigned char *) ARG3, ARG4);
            return PDC_OK;
        case PDC_NVOLATILE_RETURN_SIZE:
            result[0] = NVOLATILE_STORAGE_SIZE;
            return PDC_OK;
        case PDC_NVOLATILE_VERIFY_CONTENTS:
            return PDC_OK;
        case PDC_NVOLATILE_INITIALIZE:
            memset(nvolatile_storage, 0, sizeof(nvolatile_storage));
            return PDC_OK;
    }
    return PDC_BAD_OPTION;
}

static int pdc_add_valid(unsigned int *arg)
{
    unsigned long option = ARG1;

    // dprintf(0, "\n\nSeaBIOS: PDC_ADD_VALID function %ld ARG2=%x called.\n", option, ARG2);
    if (option != 0)
        return PDC_BAD_OPTION;
    if (0 && ARG2 == 0) // should PAGE0 be valid?  HP-UX asks for it, but maybe due a bug in our code...
        return 1;
    // if (ARG2 < PAGE_SIZE) return PDC_ERROR;
    if (ARG2 < ram_size)
        return PDC_OK;
    if (ARG2 >= (unsigned long)_sti_rom_start &&
        ARG2 <= (unsigned long)_sti_rom_end)
        return PDC_OK;
    if (ARG2 < FIRMWARE_END)
        return 1;
    if (ARG2 <= 0xffffffff)
        return PDC_OK;
    dprintf(0, "\n\nSeaBIOS: FAILED!!!! PDC_ADD_VALID function %ld ARG2=%x called.\n", option, ARG2);
    return PDC_REQ_ERR_0; /* Operation completed with a requestor bus error. */
}

static int pdc_proc(unsigned int *arg)
{
    extern void enter_smp_idle_loop(void);
    unsigned long option = ARG1;

    switch (option) {
        case 1:
            if (ARG2 != 0)
                return PDC_BAD_PROC;
            if (pdc_debug & DEBUG_PDC)
                printf("\nSeaBIOS: CPU%d enters rendenzvous loop.\n",
                        index_of_CPU_HPA(mfctl(CPU_HPA_CR_REG)));
            /* wait until all outstanding timer irqs arrived. */
            msleep(500);
            /* let the current CPU sleep until rendenzvous. */
            enter_smp_idle_loop();
            return PDC_OK;
    }
    return PDC_BAD_OPTION;
}

static int pdc_block_tlb(unsigned int *arg)
{
    unsigned long option = ARG1;
    struct pdc_btlb_info *info = (struct pdc_btlb_info *) ARG2;

    switch (option) {
        case PDC_BTLB_INFO:
            memset(info, 0, sizeof(*info));
            if (btlb_entries) {
                /* TODO: fill in BTLB info */
            }
            return PDC_OK;
        case PDC_BTLB_INSERT:
        case PDC_BTLB_PURGE:
        case PDC_BTLB_PURGE_ALL:
            /* TODO: implement above functions */
            return PDC_BAD_OPTION;

    }
    return PDC_BAD_OPTION;
}

static int pdc_tlb(unsigned int *arg)
{
#if 0
    /* still buggy, let's avoid it to keep things simple. */
    switch (option) {
        case PDC_TLB_INFO:
            result[0] = PAGE_SIZE;
            result[0] = PAGE_SIZE << 2;
            return PDC_OK;
        case PDC_TLB_SETUP:
            result[0] = ARG5 & 1;
            result[1] = 0;
            return PDC_OK;
    }
#endif
    return PDC_BAD_PROC;
}

static int pdc_mem(unsigned int *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;

    // only implemented on 64bit PDC!
    if (sizeof(unsigned long) == sizeof(unsigned int))
        return PDC_BAD_PROC;

    switch (option) {
        case PDC_MEM_MEMINFO:
            result[0] = 0;	// no PDT entries
            result[1] = 0;	// page entries
            result[2] = 0;	// PDT status
            result[3] = (unsigned long)-1ULL; // dbe_loc
            result[4] = GoldenMemory; // good_mem
            return PDC_OK;
        case PDC_MEM_READ_PDT:
            result[0] = 0;	// no PDT entries
            return PDC_OK;
        case PDC_MEM_GOODMEM:
            GoldenMemory = ARG3;
            return PDC_OK;
    }
    dprintf(0, "\n\nSeaBIOS: Check PDC_MEM option %ld ARG3=%x ARG4=%x ARG5=%x\n", option, ARG3, ARG4, ARG5);
    return PDC_BAD_PROC;
}

static int pdc_psw(unsigned int *arg)
{
    static unsigned long psw_defaults = PDC_PSW_ENDIAN_BIT;
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;

    if (option > PDC_PSW_SET_DEFAULTS)
        return PDC_BAD_OPTION;
    /* FIXME: For 64bit support enable PDC_PSW_WIDE_BIT too! */
    if (option == PDC_PSW_MASK)
        *result = PDC_PSW_ENDIAN_BIT;
    if (option == PDC_PSW_GET_DEFAULTS)
        *result = psw_defaults;
    if (option == PDC_PSW_SET_DEFAULTS) {
        psw_defaults = ARG2;
    }
    return PDC_OK;
}

static int pdc_system_map(unsigned int *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;
    struct pdc_module_path *mod_path;
    unsigned long hpa;
    int hpa_index;

    // dprintf(0, "\n\nSeaBIOS: Info: PDC_SYSTEM_MAP function %ld ARG3=%x ARG4=%x ARG5=%x\n", option, ARG3, ARG4, ARG5);
    switch (option) {
        case PDC_FIND_MODULE:
            hpa_index = ARG4;
            if (hpa_index >= ARRAY_SIZE(parisc_devices))
                return PDC_NE_MOD; // Module not found
            hpa = parisc_devices[hpa_index].hpa;
            if (!hpa)
                return PDC_NE_MOD; // Module not found

            mod_path = (struct pdc_module_path *)ARG3;
            if (mod_path)
                *mod_path = *parisc_devices[hpa_index].mod_path;

            // *pdc_mod_info = *parisc_devices[hpa_index].mod_info; -> can be dropped.
            memset(result, 0, 32*sizeof(long));
            result[0] = hpa; // .mod_addr for PDC_IODC
            result[1] = HPA_is_graphics_device(hpa) ? GFX_NUM_PAGES : 1;
            result[2] = parisc_devices[hpa_index].num_addr; // additional addresses
            return PDC_OK;

        case PDC_FIND_ADDRESS:
            hpa_index = ARG3;
            if (hpa_index >= ARRAY_SIZE(parisc_devices))
                return PDC_NE_MOD; // Module not found
            hpa = parisc_devices[hpa_index].hpa;
            if (!hpa)
                return PDC_NE_MOD; // Module not found

            memset(result, 0, 32*sizeof(long));
            ARG4 -= 1;
            if (ARG4 >= parisc_devices[hpa_index].num_addr)
                return PDC_INVALID_ARG;
            result[0] = parisc_devices[hpa_index].add_addr[ARG4];
            result[1] = HPA_is_graphics_device(hpa) ? GFX_NUM_PAGES : 1;
            return PDC_OK;

        case PDC_TRANSLATE_PATH:
            mod_path = (struct pdc_module_path *)ARG3;
            hppa_device_t *dev = find_hppa_device_by_path(mod_path, result+3, 1);
            if (!dev)
                return PDC_NE_MOD;

            result[0] = dev->hpa;
            result[1] = 1;
            result[2] = 0;
            return PDC_OK;
    }
    return PDC_BAD_OPTION;
}

static int pdc_soft_power(unsigned int *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;

    switch (option) {
        case PDC_SOFT_POWER_INFO:
            result[0] = (unsigned long) powersw_ptr;
            return PDC_OK;
        case PDC_SOFT_POWER_ENABLE:
            /* put soft power button under hardware (ARG3=0) or
             * software (ARG3=1) control. */
            *powersw_ptr = (ARG3 & 1) << 8 | (*powersw_ptr & 1);
            check_powersw_button();
            return PDC_OK;
    }
    // dprintf(0, "\n\nSeaBIOS: PDC_SOFT_POWER called with ARG2=%x ARG3=%x ARG4=%x\n", ARG2, ARG3, ARG4);
    return PDC_BAD_OPTION;
}

static int pdc_mem_map(unsigned int *arg)
{
    unsigned long option = ARG1;
    struct pdc_memory_map *memmap = (struct pdc_memory_map *) ARG2;
    struct device_path *dp = (struct device_path *) ARG3;
    hppa_device_t *dev;
    unsigned long index;

    switch (option) {
        case PDC_MEM_MAP_HPA:
            // dprintf(0, "\nSeaBIOS: PDC_MEM_MAP_HPA  bus = %d,  mod = %d\n", dp->bc[4], dp->mod);
            dev = find_hppa_device_by_path((struct pdc_module_path *) dp, &index, 0);
            if (!dev)
                return PDC_NE_MOD;
            memcpy(memmap, dev->mod_info, sizeof(*memmap));
            return PDC_OK;
    }
    return PDC_BAD_OPTION;
}

static int pdc_io(unsigned int *arg)
{
    unsigned long option = ARG1;

    switch (option) {
        case PDC_IO_READ_AND_CLEAR_ERRORS:
            dprintf(0, "\n\nSeaBIOS: PDC_IO called with ARG2=%x ARG3=%x ARG4=%x\n", ARG2, ARG3, ARG4);
            // return PDC_BAD_OPTION;
        case PDC_IO_RESET:
        case PDC_IO_RESET_DEVICES:
            return PDC_OK;
    }
    return PDC_BAD_OPTION;
}

static int pdc_lan_station_id(unsigned int *arg)
{
    unsigned long option = ARG1;

    switch (option) {
        case PDC_LAN_STATION_ID_READ:
            if (ARG3 != LASI_LAN_HPA)
                return PDC_INVALID_ARG;
            if (!keep_this_hpa(LASI_LAN_HPA))
                return PDC_INVALID_ARG;
            /* Let qemu store the MAC of NIC to address @ARG2 */
            *(unsigned long *)(LASI_LAN_HPA+12) = ARG2;
            return PDC_OK;
    }
    return PDC_BAD_OPTION;
}

static int pdc_pci_index(unsigned int *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;

    // dprintf(0, "\n\nSeaBIOS: PDC_PCI_INDEX(%lu) called with ARG2=%x ARG3=%x ARG4=%x\n", option, ARG2, ARG3, ARG4);
    switch (option) {
        case PDC_PCI_INTERFACE_INFO:
            memset(result, 0, 32 * sizeof(unsigned long));
            result[0] = 2;  /* XXX physical hardware returns those ?!? */
            result[16] = 0x60;
            result[17] = 0x90;
            return PDC_OK;
        case PDC_PCI_GET_INT_TBL_SIZE:
        case PDC_PCI_GET_INT_TBL:
            memset(result, 0, 32 * sizeof(unsigned long));
            result[0] = 2; /* Hardware fills in, even though we return PDC_BAD_OPTION below. */
            result[16] = 0x60;
            result[17] = 0x90;
            return PDC_BAD_OPTION;
        case PDC_PCI_PCI_PATH_TO_PCI_HPA:
            result[0] = PCI_HPA;
            return PDC_OK;
        case PDC_PCI_PCI_HPA_TO_PCI_PATH:
            BUG_ON(1);
    }
    return PDC_BAD_OPTION;
}

static int pdc_initiator(unsigned int *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;

    switch (option) {
        case PDC_GET_INITIATOR:
            // ARG3 points to the hwpath of device for which initiator is asked for.
            result[0] = 7;  // initiator_id/host_id: 7 to 15.
            result[1] = 10; // scsi_rate: 1, 2, 5 or 10 for 5, 10, 20 or 40 MT/s
            result[2] = 7;  // firmware suggested value for initiator_id
            result[3] = 10; // firmware suggested value for scsi_rate
            result[4] = 0;  // width: 0:"Narrow, 1:"Wide"
            result[5] = 0; // mode: 0:SMODE_SE, 1:SMODE_HVD, 2:SMODE_LVD
            return PDC_OK;
        case PDC_SET_INITIATOR:
        case PDC_DELETE_INITIATOR:
        case PDC_RETURN_TABLE_SIZE:
        case PDC_RETURN_TABLE:
            break;
    }
    dprintf(0, "\n\nSeaBIOS: Unimplemented PDC_INITIATOR function %ld ARG3=%x ARG4=%x ARG5=%x\n", option, ARG3, ARG4, ARG5);
    return PDC_BAD_OPTION;
}


int __VISIBLE parisc_pdc_entry(unsigned int *arg FUNC_MANY_ARGS)
{
    unsigned long proc = ARG0;
    unsigned long option = ARG1;

    if (pdc_debug & DEBUG_PDC) {
        printf("\nSeaBIOS: Start PDC proc %s(%d) option %d result=0x%x ARG3=0x%x %s ",
                pdc_name(ARG0), ARG0, ARG1, ARG2, ARG3, (proc == PDC_IODC)?hpa_name(ARG3):"");
        printf("ARG4=0x%x ARG5=0x%x ARG6=0x%x ARG7=0x%x\n", ARG4, ARG5, ARG6, ARG7);
    }

    switch (proc) {
        case PDC_POW_FAIL:
            break;

        case PDC_CHASSIS: /* chassis functions */
            return pdc_chassis(arg);

        case PDC_PIM:
            return pdc_pim(arg);

        case PDC_MODEL: /* model information */
            return pdc_model(arg);

        case PDC_CACHE:
            return pdc_cache(arg);

        case PDC_HPA:
            return pdc_hpa(arg);

        case PDC_COPROC:
            return pdc_coproc(arg);

        case PDC_IODC: /* Call IODC functions */
            return pdc_iodc(arg);

        case PDC_TOD:	/* Time of day */
            return pdc_tod(arg);

        case PDC_STABLE:
            return pdc_stable(arg);

        case PDC_NVOLATILE:
            return pdc_nvolatile(arg);

        case PDC_ADD_VALID:
            return pdc_add_valid(arg);

        case PDC_INSTR:
            return PDC_BAD_PROC;

        case PDC_PROC:
            return pdc_proc(arg);

        case PDC_CONFIG:	/* Obsolete */
            return PDC_BAD_PROC;

        case PDC_BLOCK_TLB:
            return pdc_block_tlb(arg);

        case PDC_TLB:		/* hardware TLB not used on Linux, but on HP-UX (if available) */
            return pdc_tlb(arg);

        case PDC_MEM:
            return pdc_mem(arg);

        case PDC_PSW:	/* Get/Set default System Mask  */
            return pdc_psw(arg);

        case PDC_SYSTEM_MAP:
            return pdc_system_map(arg);

        case PDC_SOFT_POWER: // don't have a soft-power switch
            return pdc_soft_power(arg);

        case PDC_CRASH_PREP:
            /* This should actually quiesce all I/O and prepare the System for crash dumping.
               Ignoring it for now, otherwise the BUG_ON below would quit qemu before we have
               a chance to see the kernel panic */
            return PDC_OK;

        case 26: // PDC_SCSI_PARMS is the architected firmware interface to replace the Hversion PDC_INITIATOR procedure.
            return PDC_BAD_PROC;

        case 64: // Called by HP-UX 11 bootcd during boot. Probably checks PDC_PAT_CELL (even if we are not PAT firmware)
        case 65: // Called by HP-UX 11 bootcd during boot. Probably checks PDC_PAT_CHASSIS_LOG (even if we are not PAT firmware)
            dprintf(0, "\n\nSeaBIOS: UNKNOWN PDC proc %lu OPTION %lu called with ARG2=%x ARG3=%x ARG4=%x\n", proc, option, ARG2, ARG3, ARG4);
            return PDC_BAD_PROC;

	case PDC_MEM_MAP:
            return pdc_mem_map(arg);

        case 134:
            if (ARG1 == 1 || ARG1 == 513) /* HP-UX 11.11 ask for it. */
                return PDC_BAD_PROC;
            break;

        case PDC_IO:
            return pdc_io(arg);

        case PDC_BROADCAST_RESET:
            dprintf(0, "\n\nSeaBIOS: PDC_BROADCAST_RESET (reset system) called with ARG3=%x ARG4=%x\n", ARG3, ARG4);
            reset();
            return PDC_OK;

        case PDC_LAN_STATION_ID:
            return pdc_lan_station_id(arg);

        case PDC_SYSTEM_INFO:
            if (ARG1 == PDC_SYSINFO_RETURN_INFO_SIZE)
                return PDC_BAD_PROC;
            break;

        case PDC_PCI_INDEX:
            return pdc_pci_index(arg);

        case PDC_RELOCATE:
            /* We don't want to relocate any firmware. */
            return PDC_BAD_PROC;

        case PDC_INITIATOR:
            return pdc_initiator(arg);
    }

    printf("\n** WARNING **: SeaBIOS: Unimplemented PDC proc %s(%d) option %d result=%x ARG3=%x ",
            pdc_name(ARG0), ARG0, ARG1, ARG2, ARG3);
    printf("ARG4=%x ARG5=%x ARG6=%x ARG7=%x\n", ARG4, ARG5, ARG6, ARG7);

    BUG_ON(pdc_debug);
    return PDC_BAD_PROC;
}

/********************************************************
 * TOC HANDLER
 ********************************************************/

unsigned long __VISIBLE toc_handler(struct pdc_toc_pim_11 *pim)
{
        unsigned long hpa, os_toc_handler;
        int cpu, y;
        unsigned long *p;
        struct pdc_toc_pim_11 *pim11;
        struct pdc_toc_pim_20 *pim20;
        struct pim_cpu_state_cf state = { .iqv=1, .iqf=1, .ipv=1, .grv=1, .crv=1, .srv=1, .trv=1, .td=1 };

        hpa = mfctl(CPU_HPA_CR_REG); /* get CPU HPA from cr7 */
        cpu = index_of_CPU_HPA(hpa);

        pim11 = &pim_toc_data[cpu].pim11;
        pim20 = &pim_toc_data[cpu].pim20;
        if (is_64bit())
                pim20->cpu_state = state;
        else
                pim11->cpu_state = state;

        /* check that we use the same PIM entries as assembly code */
        BUG_ON(pim11 != pim);

        printf("\n");
        printf("##### CPU %d HPA %lx: SeaBIOS TOC register dump #####\n", cpu, hpa);
        for (y = 0; y < 32; y += 8) {
                if (is_64bit())
                        p = (unsigned long *)&pim20->gr[y];
                else
                        p = (unsigned long *)&pim11->gr[y];
                printf("GR%02d: %lx %lx %lx %lx",  y, p[0], p[1], p[2], p[3]);
                printf(       " %lx %lx %lx %lx\n",   p[4], p[5], p[6], p[7]);
        }
        printf("\n");
        for (y = 0; y < 32; y += 8) {
                if (is_64bit())
                        p = (unsigned long *)&pim20->cr[y];
                else
                        p = (unsigned long *)&pim11->cr[y];
                printf("CR%02d: %lx %lx %lx %lx", y, p[0], p[1], p[2], p[3]);
                printf(       " %lx %lx %lx %lx\n",  p[4], p[5], p[6], p[7]);
        }
        printf("\n");
        if (is_64bit())
                p = (unsigned long *)&pim20->sr[0];
        else
                p = (unsigned long *)&pim11->sr[0];
        printf("SR0: %lx %lx %lx %lx %lx %lx %lx %lx\n", p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
        if (is_64bit()) {
                printf("IAQ: %lx.%lx %lx.%lx\n",
                        (unsigned long)pim20->cr[17], (unsigned long)pim20->cr[18],
                        (unsigned long)pim20->iasq_back, (unsigned long)pim20->iaoq_back);
                printf("RP(r2): %lx\n", (unsigned long)pim20->gr[2]);
        } else {
                printf("IAQ: %x.%x %x.%x\n", pim11->cr[17], pim11->cr[18],
                        pim11->iasq_back, pim11->iaoq_back);
                printf("RP(r2): %x\n", pim11->gr[2]);
        }

        os_toc_handler = PAGE0->vec_toc;
        if (is_64bit())
                os_toc_handler |= ((unsigned long long) PAGE0->vec_toc_hi << 32);

        /* release lock - let other CPUs join now. */
        toc_lock = 1;

        num_online_cpus--;

        if (os_toc_handler) {
                /* will call OS handler, after all CPUs are here */
                while (num_online_cpus)
                        ; /* wait */
                return os_toc_handler; /* let asm code call os handler */
        }

        /* No OS handler installed. Wait for all CPUs, then last CPU will reset. */
        if (num_online_cpus)
                while (1) /* this CPU will wait endless. */;

        printf("SeaBIOS: Resetting machine after TOC.\n");
        reset();
}

/********************************************************
 * BOOT MENU
 ********************************************************/

extern void find_initial_parisc_boot_drives(
        struct drive_s **harddisc,
        struct drive_s **cdrom);
extern struct drive_s *select_parisc_boot_drive(char bootdrive);
extern int parisc_get_scsi_target(struct drive_s **boot_drive, int target);

static void print_menu(void)
{
    printf("\n------- Main Menu -------------------------------------------------------------\n\n"
            "        Command                         Description\n"
            "        -------                         -----------\n"
            "        BOot [PRI|ALT|<path>]           Boot from specified path\n"
#if 0
            "        PAth [PRI|ALT|CON|KEY] [<path>] Display or modify a path\n"
            "        SEArch [DIsplay|IPL] [<path>]   Search for boot devices\n\n"
            "        COnfiguration [<command>]       Access Configuration menu/commands\n"
            "        INformation [<command>]         Access Information menu/commands\n"
            "        SERvice [<command>]             Access Service menu/commands\n\n"
            "        DIsplay                         Redisplay the current menu\n"
#endif
            "        HElp [<menu>|<command>]         Display help for menu or command\n"
            "        RESET                           Restart the system\n"
            "-------\n");
}

/* Copyright (C) 1999 Jason L. Eckhardt (jle@cygnus.com) - taken from palo */
static char *enter_text(char *txt, int maxchars)
{
    char c;
    int pos;
    for (pos = 0; txt[pos]; pos++);	/* calculate no. of chars */
    if (pos > maxchars)	/* if input too long, shorten it */
    {
        pos = maxchars;
        txt[pos] = '\0';
    }
    printf(txt);		/* print initial text */
    do
    {
        c = parisc_getchar();
        if (c == 13)
        {			/* CR -> finish! */
            if (pos <= maxchars)
                txt[pos] = 0;
            else
                txt[maxchars] = '\0';
            return txt;
        };
        if (c == '\b' || c == 127 )
        {			/* BS -> delete prev. char */
            if (pos)
            {
                pos--;
                c='\b';
                parisc_putchar(c);
                parisc_putchar(' ');
                parisc_putchar(c);
            }
        } else if (c == 21)
        {			/* CTRL-U */
            while (pos)
            {
                pos--;
                c='\b';
                parisc_putchar(c);
                parisc_putchar(' ');
                parisc_putchar(c);
            }
            txt[0] = 0;
        } else if ((pos < maxchars) && c >= ' ')
        {
            txt[pos] = c;
            pos++;
            parisc_putchar(c);
        }
    }
    while (c != 13);
    return txt;
}

static void menu_loop(void)
{
    int scsi_boot_target;
    char input[24];
    char *c, reply;

    // snprintf(input, sizeof(input), "BOOT FWSCSI.%d.0", boot_drive->target);
again:
    print_menu();

again2:
    input[0] = '\0';
    printf("Main Menu: Enter command > ");
    /* ask user for boot menu command */
    enter_text(input, sizeof(input)-1);
    parisc_putchar('\n');

    /* convert to uppercase */
    c = input;
    while (*c) {
        if ((*c >= 'a') && (*c <= 'z'))
            *c += 'A'-'a';
        c++;
    }

    if (input[0] == 'R' && input[1] == 'E')     // RESET?
        reset();
    if (input[0] == 'H' && input[1] == 'E')     // HELP?
        goto again;
    if (input[0] != 'B' || input[1] != 'O') {   // BOOT?
        printf("Unknown command, please try again.\n\n");
        goto again2;
    }
    // from here on we handle "BOOT PRI/ALT/FWSCSI.x"
    c = input;
    while (*c && (*c != ' '))   c++;    // search space
    // preset with default boot target (this is same as "BOOT PRI"
    scsi_boot_target = boot_drive->target;
    if (c[0] == 'A' && c[1] == 'L' && c[2] == 'T')
        scsi_boot_target = parisc_boot_cdrom->target;
    while (*c) {
        if (*c >= '0' && *c <= '9') {
            scsi_boot_target = *c - '0';
            break;
        }
        c++;
    }

    if (!parisc_get_scsi_target(&boot_drive, scsi_boot_target)) {
        printf("No FWSCSI.%d.0 device available for boot. Please try again.\n\n",
            scsi_boot_target);
        goto again2;
    }

    printf("Interact with IPL (Y, N, or Cancel)?> ");
    input[0] = '\0';
    enter_text(input, 1);
    parisc_putchar('\n');
    reply = input[0];
    if (reply == 'C' || reply == 'c')
        goto again2;
    // allow Z as Y. It's the key used on german keyboards.
    if (reply == 'Y' || reply == 'y' || reply == 'Z' || reply == 'z')
        interact_ipl = 1;
}

static int parisc_boot_menu(unsigned long *iplstart, unsigned long *iplend,
        char bootdrive)
{
    int ret;
    unsigned int *target = (void *)(PAGE0->mem_free + 32*1024);
    struct disk_op_s disk_op = {
        .buf_fl = target,
        .command = CMD_SEEK,
        .count = 0,
        .lba = 0,
    };

    boot_drive = select_parisc_boot_drive(bootdrive);

    /* enter main menu if booted with "boot menu=on" */
    if (show_boot_menu)
        menu_loop();
    else
        interact_ipl = 0;

    disk_op.drive_fl = boot_drive;
    if (boot_drive == NULL) {
        printf("SeaBIOS: No boot device.\n");
        return 0;
    }

    printf("\nBooting from FWSCSI.%d.0 ...\n", boot_drive->target);

    /* seek to beginning of disc/CD */
    disk_op.drive_fl = boot_drive;
    ret = process_op(&disk_op);
    // printf("DISK_SEEK returned %d\n", ret);
    if (ret)
        return 0;

    // printf("Boot disc type is 0x%x\n", boot_drive->type);
    disk_op.drive_fl = boot_drive;
    if (boot_drive->type == DTYPE_ATA_ATAPI ||
            boot_drive->type == DTYPE_ATA) {
        disk_op.command = CMD_ISREADY;
        ret = process_op(&disk_op);
    } else {
        ret = scsi_is_ready(&disk_op);
    }
    // printf("DISK_READY returned %d\n", ret);

    /* read boot sector of disc/CD */
    disk_op.drive_fl = boot_drive;
    disk_op.buf_fl = target;
    disk_op.command = CMD_READ;
    disk_op.count = (FW_BLOCKSIZE / disk_op.drive_fl->blksize);
    disk_op.lba = 0;
    // printf("blocksize is %d, count is %d\n", disk_op.drive_fl->blksize, disk_op.count);
    ret = process_op(&disk_op);
    // printf("DISK_READ(count=%d) = %d\n", disk_op.count, ret);
    if (ret)
        return 0;

    unsigned int ipl_addr = be32_to_cpu(target[0xf0/sizeof(int)]); /* offset 0xf0 in bootblock */
    unsigned int ipl_size = be32_to_cpu(target[0xf4/sizeof(int)]);
    unsigned int ipl_entry= be32_to_cpu(target[0xf8/sizeof(int)]);

    /* check LIF header of bootblock */
    if ((target[0]>>16) != 0x8000) {
        printf("Not a PA-RISC boot image. LIF magic is 0x%x, should be 0x8000.\n", target[0]>>16);
        return 0;
    }
    // printf("ipl start at 0x%x, size %d, entry 0x%x\n", ipl_addr, ipl_size, ipl_entry);
    // TODO: check ipl values for out of range. Rules are:
    // IPL_ADDR - 2 Kbyte aligned, nonzero.
    // IPL_SIZE - Multiple of 2 Kbytes, nonzero, less than or equal to 256 Kbytes.
    // IPL_ENTRY-  Word aligned, less than IPL_SIZE

    /* seek to beginning of IPL */
    disk_op.drive_fl = boot_drive;
    disk_op.command = CMD_SEEK;
    disk_op.count = 0; // (ipl_size / disk_op.drive_fl->blksize);
    disk_op.lba = (ipl_addr / disk_op.drive_fl->blksize);
    ret = process_op(&disk_op);
    // printf("DISK_SEEK to IPL returned %d\n", ret);

    /* read IPL */
    disk_op.drive_fl = boot_drive;
    disk_op.buf_fl = target;
    disk_op.command = CMD_READ;
    disk_op.count = (ipl_size / disk_op.drive_fl->blksize);
    disk_op.lba = (ipl_addr / disk_op.drive_fl->blksize);
    ret = process_op(&disk_op);
    // printf("DISK_READ IPL returned %d\n", ret);

    // printf("First word at %p is 0x%x\n", target, target[0]);

    /* execute IPL */
    // TODO: flush D- and I-cache, not needed in emulation ?
    *iplstart = *iplend = (unsigned long) target;
    *iplstart += ipl_entry;
    *iplend += ALIGN(ipl_size, sizeof(unsigned long));
    return 1;
}


/********************************************************
 * FIRMWARE MAIN ENTRY POINT
 ********************************************************/

static const struct pz_device mem_cons_sti_boot = {
    .hpa = LASI_GFX_HPA,
    .iodc_io = (unsigned long)&iodc_entry,
    .cl_class = CL_DISPL,
};

static const struct pz_device mem_kbd_sti_boot = {
    .hpa = LASI_PS2KBD_HPA,
    .iodc_io = (unsigned long)&iodc_entry,
    .cl_class = CL_KEYBD,
};

static struct pz_device mem_cons_boot = {
    .hpa = PARISC_SERIAL_CONSOLE - 0x800,
    .iodc_io = (unsigned long)&iodc_entry,
    .cl_class = CL_DUPLEX,
};

static struct pz_device mem_kbd_boot = {
    .hpa = PARISC_SERIAL_CONSOLE - 0x800,
    .iodc_io = (unsigned long)&iodc_entry,
    .cl_class = CL_KEYBD,
};

static const struct pz_device mem_boot_boot = {
    .dp.flags = PF_AUTOBOOT,
    .hpa = IDE_HPA, // DINO_SCSI_HPA,  // IDE_HPA
    .iodc_io = (unsigned long) &iodc_entry,
    .cl_class = CL_RANDOM,
};

static void find_pci_slot_for_dev(unsigned int pciid, char *pci_slot)
{
    struct pci_device *pci;

    foreachpci(pci)
        if (pci->vendor == pciid) {
            *pci_slot = (pci->bdf >> 3) & 0x0f;
            return;
        }
}

/* Prepare boot paths in PAGE0 and stable memory */
static void prepare_boot_path(volatile struct pz_device *dest,
        const struct pz_device *source,
        unsigned int stable_offset)
{
    int hpa_index;
    unsigned long hpa;
    struct pdc_module_path *mod_path;

    hpa = source->hpa;
    hpa_index = find_hpa_index(hpa);

    if (HPA_is_storage_device(hpa))
        mod_path = &mod_path_emulated_drives;
    else if (hpa == LASI_UART_HPA) // HPA_is_serial_device(hpa))
        mod_path = &mod_path_hpa_ffd05000;
    else if (hpa == DINO_UART_HPA) // HPA_is_serial_device(hpa))
        mod_path = &mod_path_hpa_fff83000;
    else {
        BUG_ON(hpa_index < 0);
        mod_path = parisc_devices[hpa_index].mod_path;
    }

    /* copy device path to entry in PAGE0 */
    memcpy((void*)dest, source, sizeof(*source));
    memcpy((void*)&dest->dp, mod_path, sizeof(struct device_path));

    /* copy device path to stable storage */
    memcpy(&stable_storage[stable_offset], mod_path, sizeof(*mod_path));

    BUG_ON(sizeof(*mod_path) != 0x20);
    BUG_ON(sizeof(struct device_path) != 0x20);
}

static int artist_present(void)
{
    return !!(*(u32 *)0xf8380004 == 0x6dc20006);
}

unsigned long _atoul(char *str)
{
    unsigned long val = 0;
    while (*str) {
        val *= 10;
        val += *str - '0';
        str++;
    }
    return val;
}

unsigned long romfile_loadstring_to_int(const char *name, unsigned long defval)
{
    char *str = romfile_loadfile(name, NULL);
    if (str)
        return _atoul(str);
    return defval;
}

void __VISIBLE start_parisc_firmware(void)
{
    unsigned int i, cpu_hz;
    unsigned long iplstart, iplend;
    char *str;

    char bootdrive = (char)cmdline; // c = hdd, d = CD/DVD
    show_boot_menu = (linux_kernel_entry == 1);

    if (smp_cpus > HPPA_MAX_CPUS)
        smp_cpus = HPPA_MAX_CPUS;
    num_online_cpus = smp_cpus;

    if (ram_size >= FIRMWARE_START)
        ram_size = FIRMWARE_START;

    /* Initialize malloc stack */
    malloc_preinit();

    /* Initialize qemu fw_cfg interface */
    PORT_QEMU_CFG_CTL = fw_cfg_port;
    qemu_cfg_init();

    /* Initialize boot structures. Needs working fw_cfg for bootprio option. */
    boot_init();

    i = romfile_loadint("/etc/firmware-min-version", 0);
    if (i && i > SEABIOS_HPPA_VERSION) {
        printf("\nSeaBIOS firmware is version %d, but version %d is required. "
            "Please update.\n", (int)SEABIOS_HPPA_VERSION, i);
        hlt();
    }
    /* Qemu versions which request a SEABIOS_HPPA_VERSION < 6 have the bug that
     * they use the DINO UART instead of the LASI UART as serial port #0.
     * Fix it up here and switch the serial console code to use PORT_SERIAL2
     * for such Qemu versions, so that we can still use this higher SeaBIOS
     * version with older Qemus. */
    if (i < 6) {
        mem_cons_boot.hpa = PORT_SERIAL2 - 0x800;
        mem_kbd_boot.hpa = PORT_SERIAL2 - 0x800;
    }

    tlb_entries = romfile_loadint("/etc/cpu/tlb_entries", 256);
    dprintf(0, "fw_cfg: TLB entries %d\n", tlb_entries);

    btlb_entries = romfile_loadint("/etc/cpu/btlb_entries", 8);
    dprintf(0, "fw_cfg: BTLB entries %d\n", btlb_entries);

    powersw_ptr = (int *) (unsigned long)
        romfile_loadint("/etc/power-button-addr", (unsigned long)&powersw_nop);

    /* use -fw_cfg opt/pdc_debug,string=255 to enable all firmware debug infos */
    pdc_debug = romfile_loadstring_to_int("opt/pdc_debug", 0);

    pdc_console = CONSOLE_DEFAULT;
    str = romfile_loadfile("opt/console", NULL);
    if (str) {
	if (strcmp(str, "serial") == 0)
		pdc_console = CONSOLE_SERIAL;
	if (strcmp(str, "graphics") == 0)
		pdc_console = CONSOLE_GRAPHICS;
    }

    /* 0,1 = default 8x16 font, 2 = 16x32 font */
    sti_font = romfile_loadstring_to_int("opt/font", 0);

    model.sw_id = romfile_loadstring_to_int("opt/hostid", model.sw_id);
    dprintf(0, "fw_cfg: machine hostid %lu\n", model.sw_id);

    /* Initialize PAGE0 */
    memset((void*)PAGE0, 0, sizeof(*PAGE0));

    /* copy pdc_entry entry into low memory. */
    memcpy((void*)MEM_PDC_ENTRY, &pdc_entry_table, 3*4);
    flush_data_cache((char*)MEM_PDC_ENTRY, 3*4);

    PAGE0->memc_cont = ram_size;
    PAGE0->memc_phsize = ram_size;
    PAGE0->memc_adsize = ram_size;
    PAGE0->mem_pdc_hi = (MEM_PDC_ENTRY + 0ULL) >> 32;
    PAGE0->mem_free = 0x6000; // min PAGE_SIZE
    PAGE0->mem_hpa = CPU_HPA; // HPA of boot-CPU
    PAGE0->mem_pdc = MEM_PDC_ENTRY;
    PAGE0->mem_10msec = CPU_CLOCK_MHZ*(1000000ULL/100);

    BUG_ON(PAGE0->mem_free <= MEM_PDC_ENTRY);
    BUG_ON(smp_cpus < 1 || smp_cpus > HPPA_MAX_CPUS);
    BUG_ON(sizeof(pim_toc_data[0]) != PIM_STORAGE_SIZE);

    /* Put QEMU/SeaBIOS marker in PAGE0.
     * The Linux kernel will search for it. */
    memcpy((char*)&PAGE0->pad0, "SeaBIOS", 8);
    PAGE0->pad0[2] = ((unsigned long long)PORT_QEMU_CFG_CTL) >> 32; /* store as 64bit value */
    PAGE0->pad0[3] = PORT_QEMU_CFG_CTL;
    *powersw_ptr = 0x01; /* button not pressed, hw controlled. */

    PAGE0->imm_hpa = MEMORY_HPA;
    PAGE0->imm_spa_size = ram_size;
    PAGE0->imm_max_mem = ram_size;

    /* initialize graphics (if available) */
    if (artist_present()) {
        sti_rom_init();
        sti_console_init(&sti_proc_rom);
        PAGE0->proc_sti = (u32)&sti_proc_rom;
        ps2port_setup();
    } else {
        remove_from_keep_list(LASI_GFX_HPA);
        remove_from_keep_list(LASI_PS2KBD_HPA);
        remove_from_keep_list(LASI_PS2MOU_HPA);
    }

    // Initialize boot paths (graphics & keyboard)
    if (pdc_console == CONSOLE_DEFAULT) {
	if (artist_present())
            pdc_console = CONSOLE_GRAPHICS;
	else
            pdc_console = CONSOLE_SERIAL;
    }
    if (pdc_console == CONSOLE_GRAPHICS) {
        prepare_boot_path(&(PAGE0->mem_cons), &mem_cons_sti_boot, 0x60);
        prepare_boot_path(&(PAGE0->mem_kbd),  &mem_kbd_sti_boot, 0xa0);
    } else {
        prepare_boot_path(&(PAGE0->mem_cons), &mem_cons_boot, 0x60);
        prepare_boot_path(&(PAGE0->mem_kbd),  &mem_kbd_boot, 0xa0);
    }

    /* Initialize device list */
    remove_parisc_devices(smp_cpus);

    /* Show list of HPA devices which are still returned by firmware. */
    if (0) { for (i=0; parisc_devices[i].hpa; i++)
        printf("Kept #%d at 0x%lx\n", i, parisc_devices[i].hpa);
    }

    // Initialize stable storage
    init_stable_storage();

    chassis_code = 0;

    // set Qemu serial debug port
    DebugOutputPort = PARISC_SERIAL_CONSOLE;
    // PlatformRunningOn = PF_QEMU;  // emulate runningOnQEMU()

    cpu_hz = 100 * PAGE0->mem_10msec; /* Hz of this PARISC */
    dprintf(1, "\nPARISC SeaBIOS Firmware, %ld x PA7300LC (PCX-L2) at %d.%06d MHz, %lu MB RAM.\n",
            smp_cpus, cpu_hz / 1000000, cpu_hz % 1000000,
            ram_size/1024/1024);

    if (ram_size < MIN_RAM_SIZE) {
        printf("\nSeaBIOS: Machine configured with too little "
                "memory (%ld MB), minimum is %d MB.\n\n",
                ram_size/1024/1024, MIN_RAM_SIZE/1024/1024);
        hlt();
    }

    // handle_post();
    serial_debug_preinit();
    debug_banner();
    // maininit();
    qemu_preinit();
    RamSize = ram_size;
    // coreboot_preinit();

    pci_setup();

    serial_setup();
    block_setup();

    printf("\n");
    printf("SeaBIOS PA-RISC Firmware Version %d\n"
            "\n"
            "Duplex Console IO Dependent Code (IODC) revision 1\n"
            "\n", SEABIOS_HPPA_VERSION);
    printf("------------------------------------------------------------------------------\n"
            "  (c) Copyright 2017-2022 Helge Deller <deller@gmx.de> and SeaBIOS developers.\n"
            "------------------------------------------------------------------------------\n\n");
    printf( "  Processor   Speed            State           Coprocessor State  Cache Size\n"
            "  ---------  --------   ---------------------  -----------------  ----------\n");
    for (i = 0; i < smp_cpus; i++)
        printf("     %s%d      " __stringify(CPU_CLOCK_MHZ)
                " MHz    %s                 Functional            0 KB\n",
                i < 10 ? " ":"", i, i?"Idle  ":"Active");
    printf("\n\n");
    printf("  Available memory:     %llu MB\n"
            "  Good memory required: %d MB\n\n",
            (unsigned long long)ram_size/1024/1024, MIN_RAM_SIZE/1024/1024);

    // search boot devices
    find_initial_parisc_boot_drives(&parisc_boot_harddisc, &parisc_boot_cdrom);

    printf("  Primary boot path:    FWSCSI.%d.%d\n"
           "  Alternate boot path:  FWSCSI.%d.%d\n"
           "  Console path:         %s\n"
           "  Keyboard path:        %s\n\n",
            parisc_boot_harddisc->target, parisc_boot_harddisc->lun,
            parisc_boot_cdrom->target, parisc_boot_cdrom->lun,
            hpa_device_name(PAGE0->mem_cons.hpa, 1),
            hpa_device_name(PAGE0->mem_kbd.hpa, 0));

    if (bootdrive == 'c')
        boot_drive = parisc_boot_harddisc;
    else
        boot_drive = parisc_boot_cdrom;

    // Find PCI bus id of LSI SCSI card
    find_pci_slot_for_dev(PCI_VENDOR_ID_LSI_LOGIC,
            &mod_path_emulated_drives.path.bc[5]);

    // Store initial emulated drives path master data
    if (parisc_boot_harddisc) {
        mod_path_emulated_drives.layers[0] = parisc_boot_harddisc->target;
        mod_path_emulated_drives.layers[1] = parisc_boot_harddisc->lun;
    }

    prepare_boot_path(&(PAGE0->mem_boot), &mem_boot_boot, 0x0);

    // copy primary boot path to alt boot path
    memcpy(&stable_storage[0x80], &stable_storage[0], 0x20);
    if (parisc_boot_cdrom) {
        stable_storage[0x80 + 11] = parisc_boot_cdrom->target;
        stable_storage[0x80 + 12] = parisc_boot_cdrom->lun;
    }
    // currently booted path == CD in PAGE0->mem_boot
    if (boot_drive) {
        PAGE0->mem_boot.dp.layers[0] = boot_drive->target;
        PAGE0->mem_boot.dp.layers[1] = boot_drive->lun;
    }

    /* directly start Linux kernel if it was given on qemu command line. */
    if (linux_kernel_entry > 1) {
        void (*start_kernel)(unsigned long mem_free, unsigned long cline,
                unsigned long rdstart, unsigned long rdend);

        printf("Autobooting Linux kernel which was loaded by qemu...\n\n");
        start_kernel = (void *) linux_kernel_entry;
        start_kernel(PAGE0->mem_free, cmdline, initrd_start, initrd_end);
        hlt(); /* this ends the emulator */
    }

    /* check for bootable drives, and load and start IPL bootloader if possible */
    if (parisc_boot_menu(&iplstart, &iplend, bootdrive)) {
        void (*start_ipl)(long interactive, long iplend);

        PAGE0->mem_boot.dp.layers[0] = boot_drive->target;
        PAGE0->mem_boot.dp.layers[1] = boot_drive->lun;

        printf("\nBooting...\n"
                "Boot IO Dependent Code (IODC) revision 153\n\n"
                "%s Booted.\n", PAGE0->imm_soft_boot ? "SOFT":"HARD");
        start_ipl = (void *) iplstart;
        start_ipl(interact_ipl, iplend);
    }

    hlt(); /* this ends the emulator */
}
