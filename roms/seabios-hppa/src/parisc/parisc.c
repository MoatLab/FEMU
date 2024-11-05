// Glue code for parisc architecture
//
// Copyright (C) 2017-2024 Helge Deller <deller@gmx.de>
// Copyright (C) 2019 Sven Schnelle <svens@stackframe.org>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.
//
// Example command line:
// ./qemu-system-hppa -drive file=../qemu-images/hdd.img -kernel vmlinux -append "root=/dev/sda5 cryptomgr.notests"  -smp cpus=2  -snapshot -machine C3700  -vnc :1  -fw_cfg opt/console,string=serial -serial mon:stdio  -device secondary-vga

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
#include "hw/usb.h"
#include "hw/usb-ohci.h"
#include "hw/blockcmd.h" // scsi_is_ready()
#include "hw/rtc.h"
#include "fw/paravirt.h" // PlatformRunningOn
#include "vgahw.h"
#include "parisc/hppa_hardware.h" // DINO_UART_BASE
#include "parisc/pdc.h"
#include "parisc/pdcpat.h"
#include "parisc/sticore.h"
#include "parisc/lasips2.h"

#include "vgabios.h"

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

#if defined(__LP64__)
# define cpu_bit_width      64
# define is_64bit_PDC()     1      /* 64-bit PDC */
#else
char cpu_bit_width;
# define is_64bit_PDC()     0      /* 32-bit PDC */
#endif

#define is_64bit_CPU()     (cpu_bit_width == 64)  /* 64-bit CPU? */

/* running 64-bit PDC, but called from 32-bit app */
#define is_compat_mode()  (is_64bit_PDC() && ((psw_defaults & PDC_PSW_WIDE_BIT) == 0))

#define COMPAT_VAL(val)   ((long)(int)(val))    // (is_compat_mode() ? (long)(int)(val) : (val))

/* Do not write back result buffer in compat mode */
#define NO_COMPAT_RETURN_VALUE(res)     { res = 0; }

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

/* boot_args[] variables provided by qemu */
#define boot_args		((unsigned long *)(uintptr_t)&PAGE0->pad608)
#define ram_size		boot_args[0]
#define linux_kernel_entry	boot_args[1]
#define cmdline			boot_args[2]
#define initrd_start		boot_args[3]
#define initrd_end		boot_args[4]
#define smp_cpus		boot_args[5]
#define pdc_debug		boot_args[6]
#define fw_cfg_port		F_EXTEND(boot_args[7])

/* flags for pdc_debug */
#define DEBUG_PDC       0x01
#define DEBUG_IODC      0x02
#define DEBUG_BOOT_IO   0x04
#define DEBUG_CHASSIS   0x08

int pdc_console;
/* flags for pdc_console */
#define CONSOLE_DEFAULT   0x0000
#define CONSOLE_SERIAL    0x0001
#define CONSOLE_GRAPHICS  0x0002

int sti_font;

char qemu_version[16] = "unknown version";
char qemu_machine[16] = "B160L";
char has_astro;
#define PCI_HPA         DINO_HPA        /* initial temp. PCI bus */
unsigned long pci_hpa = PCI_HPA;    /* HPA of Dino or Elroy0 */
unsigned long hppa_port_pci_cmd  = (PCI_HPA + DINO_PCI_ADDR);
unsigned long hppa_port_pci_data = (PCI_HPA + DINO_CONFIG_DATA);

/* Want PDC boot menu? Enable via qemu "-boot menu=on" option. */
unsigned int show_boot_menu;
unsigned int interact_ipl;

unsigned int __VISIBLE firmware_width_locked; /* no 64-bit calls allowed */
unsigned int __VISIBLE psw_defaults;

unsigned long PORT_QEMU_CFG_CTL;
unsigned int tlb_entries = 256;

#define PARISC_SERIAL_CONSOLE   PORT_SERIAL1

extern char pdc_entry;
extern char pdc_entry_table;
extern char pdc_entry_table_end;
extern char iodc_entry[512];
extern char iodc_entry_table;
extern char iodc_entry_table_one_entry;

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

#define CPU_HPA_IDX(i)  (F_EXTEND(CPU_HPA) + (i)*0x1000) /* CPU_HPA of CPU#i */

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

/* allow 64-bit OS installation on 64-bit firmware */
#define OS64_32_DEFAULT (is_64bit_PDC() ? PDC_MODEL_OS64 | PDC_MODEL_OS32 : PDC_MODEL_OS32)
int enable_OS64 = OS64_32_DEFAULT;

/*
 * Real time clock emulation
 * Either LASI or Astro will provide access to an emulated RTC clock.
 */
int *rtc_ptr = (int *) (unsigned long) LASI_RTC_HPA;

void __VISIBLE __noreturn hlt(void)
{
    if (pdc_debug)
        printf("HALT initiated from %p\n",  __builtin_return_address(0));
    printf("SeaBIOS wants SYSTEM HALT.\n\n");
    /* call qemu artificial "halt" asm instruction */
    asm volatile("\t.word 0xfffdead0": : :"memory");
    while (1);
}

static int powerswitch_supported(void)
{
    return powersw_ptr != NULL;
}

static void check_powersw_button(void)
{
    /* halt immediately if power button was pressed. */
    if (powerswitch_supported() && (*powersw_ptr & 1) == 0) {
        printf("SeaBIOS: Machine powered off via power switch button.\n");
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

void __VISIBLE __noreturn firmware_fault_handler(unsigned long fault)
{
    printf("\n***************************\n"
        "SeaBIOS: Detected trap #%lu, at 0x%lx:0x%lx, IIR=0x%lx, IOR addr=0x%lx:0x%lx\n", fault,
        mfctl(17), mfctl(18), mfctl(19), mfctl(20), mfctl(21));
    while (1) { asm("or %r10,%r10,%r10"); };
}

#undef BUG_ON
#define BUG_ON(cond) \
    if (unlikely(cond)) { \
        printf("*ERROR* in SeaBIOS-hppa-v%d:\n%s:%d\n", SEABIOS_HPPA_VERSION, \
        __FUNCTION__, __LINE__); hlt(); \
    }

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
    printf("memdump @ 0x%lx : ", (unsigned long) mem);
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

#define	MAX_DEVICES	HPPA_MAX_CPUS+16

typedef struct {
    unsigned long hpa;
    struct pdc_iodc *iodc;
    struct pdc_system_map_mod_info *mod_info;
    struct pdc_module_path *mod_path;
    int num_addr;
    int add_addr[5];
    unsigned long hpa_parent;
    struct pci_device *pci;
    unsigned long pci_addr;
    int index;
} hppa_device_t;

static hppa_device_t *find_hpa_device(unsigned long hpa);

#define CONCAT2(a, b) a ## b
#define CONCAT(a, b) CONCAT2(a, b)

struct machine_info {
        char			pdc_modelstr[16];
        struct pdc_model 	pdc_model;
        int			pdc_version;
        int			pdc_cpuid;
        int			pdc_caps;
        unsigned long		pdc_entry;
        unsigned long		pdc_cache_info[30];
        hppa_device_t		device_list[MAX_DEVICES];
};


/* create machine definitions */
#define MACHINE	B160L
#include "parisc/b160l.h"
#include "parisc/machine-create.h"

#define MACHINE	C3700
#include "parisc/c3700.h"
#include "parisc/machine-create.h"

#define MACHINE	715
#include "parisc/715_64.h"
#include "parisc/machine-create.h"

struct machine_info *current_machine = &machine_B160L;

static hppa_device_t *parisc_devices = machine_B160L.device_list;

#define PARISC_KEEP_LIST \
    DINO_UART_HPA,\
    /* DINO_SCSI_HPA, */ \
    LASI_UART_HPA, \
    LASI_LAN_HPA, \
    LASI_LPT_HPA, \
    LASI_GFX_HPA,\
    LASI_PS2KBD_HPA, \
    LASI_PS2MOU_HPA, \
    MEMORY_HPA, \
    0

static const char *hpa_name(unsigned long hpa)
{
    int i;

    #define DO(x) if (hpa == F_EXTEND(x)) return #x;
    DO(GSC_HPA)
    DO(DINO_HPA)
    DO(DINO_UART_HPA)
    DO(DINO_SCSI_HPA)
    DO(CPU_HPA)
    DO(MEMORY_HPA)
    DO(SCSI_HPA)
    DO(LASI_HPA)
    DO(LASI_UART_HPA)
    DO(LASI_SCSI_HPA)
    DO(LASI_LAN_HPA)
    DO(LASI_LPT_HPA)
    DO(LASI_AUDIO_HPA)
    DO(LASI_PS2KBD_HPA)
    DO(LASI_PS2MOU_HPA)
    DO(LASI_GFX_HPA)
    DO(ASTRO_HPA)
    DO(ASTRO_MEMORY_HPA)
    DO(ELROY0_HPA)
    DO(ELROY2_HPA)
    DO(ELROY8_HPA)
    DO(ELROYc_HPA)
    #undef DO

    /* could be one of the SMP CPUs */
    for (i = 1; i < smp_cpus; i++) {
        static char CPU_TXT[] = "CPU_HPA_0";
        if (hpa == CPU_HPA_IDX(i)) {
            CPU_TXT[8] = i < 10 ? '0' + i : 'A' - 10 + i;
            return CPU_TXT;
        }
    }

    /* search PCI devices */
    hppa_device_t *dev = find_hpa_device(hpa);
    if (dev) {
        static char pci_dev_name[12];
        snprintf(pci_dev_name, sizeof(pci_dev_name), "PCI_%pP", dev->pci);
        return pci_dev_name;
    }

    return "UNKNOWN HPA";
}

/* used to generate HPA for PCI device */
unsigned long pci_get_first_mmio_or_io(struct pci_device *pci)
{
    unsigned long io = 0;
    int i;
    for (i = PCI_BASE_ADDRESS_0; i <= PCI_BASE_ADDRESS_5; i++) {
        unsigned long mem;
        mem = pci_config_readl(pci->bdf, i);
        if ((mem & ~PCI_BASE_ADDRESS_SPACE_IO) == 0)
            continue;
        if (mem & PCI_BASE_ADDRESS_SPACE_IO) {
            if (!io)
                io = mem & ~PCI_BASE_ADDRESS_SPACE_IO;
            continue;
        }
        // found mem
        return mem & ~PCI_BASE_ADDRESS_SPACE_IO;
    }
    // use io instead
    return IOS_DIST_BASE_ADDR + io;
}

int HPA_is_astro_ioport(unsigned long hpa)
{
    if (!has_astro)
        return 0;
    return ((hpa - IOS_DIST_BASE_ADDR) < IOS_DIST_BASE_SIZE);
}

int HPA_is_astro_mmio(unsigned long hpa)
{
    if (!has_astro)
        return 0;
    return ((hpa - LMMIO_DIST_BASE_ADDR) < LMMIO_DIST_BASE_SIZE);
}

struct pci_device *find_pci_from_HPA(unsigned long hpa)
{
    struct pci_device *pci = NULL;
    int ioport;

    if (HPA_is_astro_ioport(hpa)) {
        ioport = 1;
        hpa -= IOS_DIST_BASE_ADDR;
    } else if (HPA_is_astro_mmio(hpa))
        ioport = 0;
    else
        return NULL;

    foreachpci(pci) {
        int i;
        for (i = 0; i < 6; i++) {
            unsigned long addr = PCI_BASE_ADDRESS_0 + 4*i;
            unsigned long mem;
            mem = pci_config_readl(pci->bdf, addr);
            if ((mem & PCI_BASE_ADDRESS_SPACE_IO) &&
                ((mem & PCI_BASE_ADDRESS_IO_MASK) == hpa) &&
                (ioport == 1))
                    return pci;     /* found ioport */
            if (((mem & PCI_BASE_ADDRESS_SPACE_IO) == 0) &&
                ((mem & PCI_BASE_ADDRESS_MEM_MASK) == hpa) &&
                (ioport == 0))
                    return pci;     /* found memaddr */
        }
    }
    dprintf(1, "No PCI device found for HPA %lx\n", hpa);
    return NULL;
}

int DEV_is_storage_device(hppa_device_t *dev)
{
    BUG_ON(!dev);
    if (dev->pci)
        return (dev->pci->class == PCI_CLASS_STORAGE_SCSI);
    return ((dev->iodc->type & 0xf) == 0x04); /* HPHW_A_DMA */
}

int DEV_is_serial_device(hppa_device_t *dev)
{
    BUG_ON(!dev);
    if (dev->pci)
        return (dev->pci->class == PCI_CLASS_COMMUNICATION_SERIAL);
    return ((dev->iodc->type & 0xf) == 0x0a); /* HPHW_FIO */
}

int HPA_is_serial_device(unsigned long hpa)
{
    hppa_device_t *dev;

    dev = find_hpa_device(hpa);
    if (!dev)
        return 0;
    return DEV_is_serial_device(dev);
}

int DEV_is_network_device(hppa_device_t *dev)
{
    BUG_ON(!dev);
    if (dev->pci)
        return (dev->pci->class == PCI_CLASS_NETWORK_ETHERNET);
    return ((dev->iodc->type & 0xf) == 0x0a); /* HPHW_FIO */
}

static int HPA_is_LASI_keyboard(unsigned long hpa)
{
    return !has_astro && (hpa == LASI_PS2KBD_HPA);
}

#if 0
static int HPA_is_keyboard_device(unsigned long hpa)
{
    struct pci_device *pci;
    int ret;

    if (HPA_is_LASI_keyboard(hpa))
        return 1;
    pci = find_pci_from_HPA(hpa);
    if (!pci)
        return 0;
    ret = pci->class == PCI_CLASS_COMMUNICATION_SERIAL ||
            pci->class == PCI_CLASS_INPUT_KEYBOARD;
    dprintf(1, "PCI: is_keyboard? %pP -> %s\n", pci, ret?"Yes":"no");
    return ret;
}
#endif

static int artist_present(void)
{
    return !!(*(u32 *)F_EXTEND(0xf8380004) == 0x6dc20006);
}

int HPA_is_LASI_graphics(unsigned long hpa)
{
    /* return true if hpa is LASI graphics (artist graphics card) */
    return (hpa == LASI_GFX_HPA) && artist_present();
}
#define GFX_NUM_PAGES 0x2000
int HPA_is_graphics_device(unsigned long hpa)
{
    hppa_device_t *dev;

    dev = find_hpa_device(hpa);
    if (!dev)
        return 0;
    if (dev->pci)
        return (dev->pci->class >> 8) == PCI_BASE_CLASS_DISPLAY;
    return (dev->iodc->sversion_model == 0x3b); /* XXX */
}

static const char *hpa_device_name(unsigned long hpa, int output)
{
    return HPA_is_LASI_graphics(hpa) ? "GRAPHICS(1)" :
            HPA_is_graphics_device(hpa) ? "VGA" :
            HPA_is_LASI_keyboard(hpa) ? "PS2" :
            ((hpa + 0x800) == PORT_SERIAL1) ?
                "SERIAL_1.9600.8.none" : "SERIAL_2.9600.8.none";
}

static void print_mod_path(struct pdc_module_path *p)
{
    dprintf(1, "PATH %d/%d/%d/%d/%d/%d/%d:%d.%d.%d ", p->path.bc[0], p->path.bc[1],
            p->path.bc[2],p->path.bc[3],p->path.bc[4],p->path.bc[5],
            p->path.mod, p->layers[0], p->layers[1], p->layers[2]);
}

void make_module_path_from_pcidev(struct pci_device *pci,
            struct pdc_module_path *p)
{
    memset(p, 0, sizeof(*p));
    memset(&p->path.bc, 0xff, sizeof(p->path.bc));

    switch (pci->class) {
    case PCI_CLASS_COMMUNICATION_SERIAL:
    case PCI_CLASS_NETWORK_ETHERNET:
    case PCI_CLASS_STORAGE_SCSI:
    case PCI_CLASS_SERIAL_USB:
    default:
#if 0
static struct pdc_module_path mod_path_hpa_fed3c000 = { // SCSI
        .path = { .flags = 0x0, .bc = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xa }, .mod = 0x6  },
        .layers = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
#endif
        p->path.bc[3] = has_astro ? ASTRO_BUS_MODULE : 0x08; /* astro or dino */
        p->path.bc[4] = 0; // elroy index (0,1,4,6) == PCI Bus number (0,1,2,3)
        p->path.bc[5] = pci->bdf >> 3;  /* slot */
        p->path.mod = pci->bdf & 0x07; /* function */
        break;
    }
}

void make_iodc_from_pcidev(struct pci_device *pci,
            struct pdc_iodc *p)
{
    memset(p, 0, sizeof(*p));
    p->hversion_model = 0x0058;
    p->hversion = 0x0020;
    p->sversion_model = 0;
    p->sversion_opt = 0;
    p->rev = 0x0099;
    p->length = 1;

    switch (pci->class) {
    case PCI_CLASS_STORAGE_SCSI:
        p->features = 0x0001;
        p->type = 0x0084;
        break;
    case PCI_CLASS_COMMUNICATION_SERIAL:
    case PCI_CLASS_NETWORK_ETHERNET:
    case PCI_CLASS_SERIAL_USB:
    default:
        p->type = 0x008a;
        break;
    }
};

void make_modinfo_from_pcidev(struct pci_device *pci,
            struct pdc_system_map_mod_info *p, unsigned long pfa)
{
    memset(p, 0, sizeof(*p));
    p->mod_addr = pfa;
    p->mod_pgs = 0;
    p->add_addrs = HPA_is_graphics_device(pfa) ? GFX_NUM_PAGES : 0;
};

#define MAX_PCI_DEVICES         10
static int curr_pci_devices;    /* current number of PCI devices in list */
static hppa_device_t                    hppa_pci_devices[MAX_PCI_DEVICES];
static struct pdc_iodc                  hppa_pci_iodc[MAX_PCI_DEVICES];
static struct pdc_system_map_mod_info   hppa_pci_mod_info[MAX_PCI_DEVICES];
static struct pdc_module_path           hppa_pci_mod_path[MAX_PCI_DEVICES];


/* create table of PFA (PCI Function address), similiar to HPA */
static void hppa_pci_build_devices_list(void)
{
    struct pci_device *pci;

    memset(&hppa_pci_devices, 0, sizeof(hppa_pci_devices));

    curr_pci_devices = 0;

    dprintf(1, "\n PCI DEVICE LIST PFA TABLE\n");
    foreachpci(pci) {
        unsigned long pfa, offs;
        hppa_device_t *pdev = &hppa_pci_devices[curr_pci_devices];

        offs = elroy_offset(pci->bdf);
        BUG_ON(offs == -1UL);
#if 0
        pfa = F_EXTEND(elroy_port(0, offs));
        pfa += pci->bdf << 8;
        pfa |= SCSI_HPA;
#else
        pfa = F_EXTEND(pci_get_first_mmio_or_io(pci));
        BUG_ON(!pfa);
#endif
#if 0
[    2.721607] BOOT DISK HPA f4008000
[    2.765613] page0 00 ff ff ff 0a 00 0c 00 00 01 00 00 9a 47 10 bf
[    2.845608] page0 48 86 a9 54 cb 07 fe 03 c0 a8 14 33 c0 a8 14 42
[    2.925607] page0 f4 00 80 00 00 00 00 00 00 01 90 00 00 00 10 02
[    3.005607] path
[    3.029608] page0 00 ff ff ff 0a 00 0c 00
[    3.085607] layers
[    3.109608] page0 00 01 00 00 9a 47 10 bf 48 86 a9 54 cb 07 fe 03
[    3.189607] page0 c0 a8 14 33 c0 a8 14 42
[    3.241607] BOOT CONS HPA fee003f8
[    3.289607] BOOT KBD HPA  fee003f8
#endif

        pdev->hpa       = pfa;
        pdev->iodc      = &hppa_pci_iodc[curr_pci_devices];
        pdev->mod_info  = &hppa_pci_mod_info[curr_pci_devices];
        pdev->mod_path  = &hppa_pci_mod_path[curr_pci_devices];
        pdev->num_addr  = 0;
        pdev->pci = pci;
        pdev->hpa_parent = F_EXTEND(pci_hpa);
        pdev->index     = curr_pci_devices;
        dprintf(1, "PCI device #%d %pP bdf 0x%x at pfa 0x%lx\n", curr_pci_devices, pci, pci->bdf, pfa);

        make_iodc_from_pcidev(pci, pdev->iodc);
        make_modinfo_from_pcidev(pci, pdev->mod_info, pfa);
        make_module_path_from_pcidev(pci, pdev->mod_path);

        curr_pci_devices++;
        BUG_ON(curr_pci_devices >= MAX_PCI_DEVICES);
    }
}

static hppa_device_t *find_hpa_device(unsigned long hpa)
{
    int i;

    hpa = COMPAT_VAL(hpa);

    /* search classical HPPA devices */
    if (hpa) {
        for (i = 0; i < (MAX_DEVICES-1); i++) {
            if (hpa == parisc_devices[i].hpa)
                return &parisc_devices[i];
            if (!parisc_devices[i].hpa)
                break;
        }
    }

    /* search PCI devices */
    for (i = 0; i < curr_pci_devices; i++) {
        if (hpa == hppa_pci_devices[i].hpa)
            return &hppa_pci_devices[i];
    }
    return NULL;
}

static unsigned long keep_list[20] = { PARISC_KEEP_LIST };

static void remove_from_keep_list(unsigned long hpa)
{
    int i = 0;

    while (keep_list[i] && keep_list[i] != hpa)
        i++;
    while (keep_list[i]) {
            keep_list[i] = keep_list[i+1];
            ++i;
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

/* walk all machine devices and add generic ones to the keep_list[] */
static int keep_add_generic_devices(void)
{
    hppa_device_t *dev = current_machine->device_list;
    int i = 0;

    /* search end of list */
    while (keep_list[i]) i++;

    while (dev->hpa) {
	switch (dev->iodc->type) {
	case 0x0041:	/* Memory. Save HPA in PAGE0 entry. */
                        /* MEMORY_HPA or ASTRO_MEMORY_HPA */
                PAGE0->imm_hpa = dev->hpa;
                /* fallthrough */
	case 0x0007:	/* GSC+ Port bridge */
	case 0x004d:	/* Dino PCI bridge */
	case 0x004b:	/* Core Bus adapter (LASI) */
	case 0x0040:	/* CPU */
	case 0x000d:	/* Elroy PCI bridge */
	case 0x000c:	/* Runway port */
		keep_list[i++] = dev->hpa;
	}
	dev++;
    }
    BUG_ON(i >= ARRAY_SIZE(keep_list));

    return 0;
}

/* Rebuild hardware list and drop all devices which are not listed in
 * PARISC_KEEP_LIST. Generate num_cpus CPUs. */
static void remove_parisc_devices(unsigned int num_cpus)
{
    static struct pdc_system_map_mod_info modinfo[HPPA_MAX_CPUS] = { {1,}, };
    static struct pdc_module_path modpath[HPPA_MAX_CPUS] = { {{1,}} };
    hppa_device_t *cpu_dev = NULL;
    unsigned long hpa, cpu_offset;
    int i, p, t;

    /* already initialized? */
    static int uninitialized = 1;
    if (!uninitialized)
        return;
    uninitialized = 0;

    /* check if qemu emulates LASI chip (LASI_IAR exists) */
    if (has_astro || *(unsigned long *)(LASI_HPA+16) == 0) {
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
    cpu_dev->mod_info->mod_addr = F_EXTEND(CPU_HPA);
    if (has_astro)
        cpu_offset = CPU_HPA - 32*0x1000;
    else
        cpu_offset = pci_hpa;
    cpu_dev->mod_path->path.mod = (CPU_HPA - cpu_offset) / 0x1000;

    /* Generate other CPU devices */
    for (i = 1; i < num_cpus; i++) {
        unsigned long hpa = CPU_HPA_IDX(i);

        parisc_devices[t] = *cpu_dev;
        parisc_devices[t].hpa = hpa;

        modinfo[i] = *cpu_dev->mod_info;
        modinfo[i].mod_addr = hpa;
        parisc_devices[t].mod_info = &modinfo[i];

        modpath[i] = *cpu_dev->mod_path;
        modpath[i].path.mod = (hpa - cpu_offset) / 0x1000;
        parisc_devices[t].mod_path = &modpath[i];

        t++;
    }

    BUG_ON(t > MAX_DEVICES);

    while (t < MAX_DEVICES) {
        memset(&parisc_devices[t], 0, sizeof(*parisc_devices));
        t++;
    }
}

static int compare_module_path(struct pdc_module_path *path,
                               struct pdc_module_path *search,
                               int check_layers)
{
    int i;

    if (path->path.mod != search->path.mod)
        return 0;

    for(i = 0; i < ARRAY_SIZE(path->path.bc); i++) {
        if (path->path.bc[i] != search->path.bc[i])
            return 0;
    }

    if (check_layers) {
        for(i = 0; i < ARRAY_SIZE(path->layers); i++) {
            if (path->layers[i] != search->layers[i])
                return 0;
        }
    }
    return 1;
}

/* add index number to all devices */
static hppa_device_t *add_index_all_devices(void)
{
    hppa_device_t *dev;
    int i, index = 0;

    for (i = 0; i < (MAX_DEVICES-1); i++) {
        dev = parisc_devices + i;
        if (!dev->hpa)
            continue;

        /* FIX PDC up for 64-bit PDC !!!
         * hpa and mod_addr in device tables need upper 32 bits set
         */
        dev->hpa = F_EXTEND(dev->hpa);
        dev->mod_info->mod_addr = F_EXTEND(dev->mod_info->mod_addr);

        dev->index = index;
        if (0)
            dprintf(1, "device HPA %lx %s is index # %d\n", dev->hpa, hpa_name(dev->hpa), index);
        dev->hpa_parent = 0;
        dev->num_addr = dev->mod_info->add_addrs;
        index++;
    }

    /* search PCI devices */
    for (i = 0; i < curr_pci_devices; i++) {
        dev = hppa_pci_devices + i;
        if (dev->hpa) {
            dev->index = index;
            if (0)
                dprintf(1, "device HPA %lx %s is index # %d\n", dev->hpa, hpa_name(dev->hpa), index);
            index++;
        }
    }

    return NULL;
}

static hppa_device_t *find_hppa_device_by_hpa(unsigned long hpa)
{
    hppa_device_t *dev;
    int i, nr = 0;

    for (i = 0; i < (MAX_DEVICES-1); i++) {
        dev = parisc_devices + i;
        if (dev && dev->hpa == hpa) {
            // found it.
            return dev;
        }
        nr++;
    }

    /* search PCI devices */
    for (i = 0; i < curr_pci_devices; i++) {
        dev = hppa_pci_devices + i;
        if (dev && dev->hpa == hpa) {
            // found it.
            return dev;
        }
        nr++;
    }

    return NULL;
}

static hppa_device_t *find_hppa_device_by_path(struct pdc_module_path *search,
                            unsigned long *index, int check_layers)
{
    hppa_device_t *dev;
    int i, nr = 0;

    for (i = 0; i < (MAX_DEVICES-1); i++) {
        dev = parisc_devices + i;

        if (compare_module_path(dev->mod_path, search, check_layers)) {
            if (index)
                *index = nr;
            return dev;
        }
        nr++;
    }

    /* search PCI devices */
    for (i = 0; i < curr_pci_devices; i++) {
        dev = hppa_pci_devices + i;
        if (compare_module_path(dev->mod_path, search, check_layers)) {
            if (index)
                *index = nr;
            return dev;
        }
        nr++;
    }

    return NULL;
}

static hppa_device_t *find_hppa_device_by_index(unsigned long hpa_parent, unsigned int index, int search_pci)
{
    hppa_device_t *dev;
    int i;

    for (i = 0; i < (MAX_DEVICES-1); i++) {
        dev = parisc_devices + i;
        if (!dev->hpa)
            continue;
        if (dev->hpa_parent != hpa_parent)
            continue;
        if (dev->index == index)
            return dev;
    }

    /* search PCI devices */
    if (search_pci) {
        for (i = 0; i < curr_pci_devices; i++) {
            dev = hppa_pci_devices + i;
            if (dev->index == index)
                return dev;
        }
    }

    return NULL;
}

#define SERIAL_TIMEOUT 20
static unsigned long parisc_serial_in(char *c, unsigned long maxchars)
{
    portaddr_t addr = PAGE0->mem_kbd.hpa;
    unsigned long end = timer_calc(SERIAL_TIMEOUT);
    unsigned long count = 0;

    if (has_astro) {
        hppa_device_t *dev = find_hpa_device(addr);
        BUG_ON(!dev);
        addr = dev->pci_addr;
    } else
        addr += 0x800;
    while (count < maxchars) {
        u8 lsr = inb(F_EXTEND(addr+SEROFF_LSR));
        if (lsr & 0x01) {
            // Success - can read data
            *c++ = inb(F_EXTEND(addr+SEROFF_DATA));
            count++;
        }
        if (timer_check(end))
            break;
    }
    return count;
}

static void parisc_serial_out(char c)
{
    portaddr_t addr = PAGE0->mem_cons.hpa;

    /* might not be initialized if problems happen during early bootup */
    if (!addr) {
        /* use debugoutput instead */
        builtin_console_out(c);
        return;
    }
    if (0) {
        dprintf(1,"parisc_serial_out  search hpa %x   ", PAGE0->mem_cons.hpa);
        print_mod_path(&PAGE0->mem_cons.dp);
        dprintf(1,"  \n");
    }
    hppa_device_t *dev;
    dev = find_hppa_device_by_path(&PAGE0->mem_cons.dp, NULL, 0);
    if (0) {
        dprintf(1,"parisc_serial_out  hpa %x\n", PAGE0->mem_cons.hpa);
        print_mod_path(dev->mod_path);
    }
    if (!dev) hlt();
    BUG_ON(!dev);
    if (dev->pci_addr)
        addr = dev->pci_addr;
    else
        addr += 0x800;  /* add offset for serial port on GSC */
//  dprintf(1,"  addr %x\n", addr);

    if (c == '\n')
        parisc_serial_out('\r');

    for (;;) {
        u8 lsr = inb(F_EXTEND(addr+SEROFF_LSR));
        if ((lsr & 0x60) == 0x60) {
            // Success - can write data
            outb(c, F_EXTEND(addr+SEROFF_DATA));
            break;
        }
    }
}

static void parisc_putchar_internal(char c)
{
    if (HPA_is_LASI_graphics(PAGE0->mem_cons.hpa))
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

    if (HPA_is_LASI_keyboard(PAGE0->mem_kbd.hpa))
        count = lasips2_kbd_in(&c, sizeof(c));
    else if (HPA_is_serial_device(PAGE0->mem_kbd.hpa))
        count = parisc_serial_in(&c, sizeof(c));
    else
        BUG_ON(1);
    if (count == 0)
        c = 0;
    return c;
}

void iodc_log_call(unsigned int *arg, const char *func)
{
    if (pdc_debug & DEBUG_IODC) {
        printf("\nIODC %s called: hpa=0x%x (%s) option=0x%x arg2=0x%x arg3=0x%x ",
                func, ARG0, hpa_name(ARG0), ARG1, ARG2, ARG3);
        printf("result=0x%x arg5=0x%x arg6=0x%x arg7=0x%x\n", ARG4, ARG5, ARG6, ARG7);
    }
}

#define FUNC_MANY_ARGS , \
    int a0, int a1, int a2, int a3,  int a4,  int a5,  int a6, \
    int a7, int a8, int a9, int a10, int a11, int a12


int __VISIBLE parisc_iodc_ENTRY_IO(unsigned int *arg FUNC_MANY_ARGS)
{
    unsigned long hpa = COMPAT_VAL(ARG0);
    unsigned long option = ARG1;
    unsigned int *result = (unsigned int *)ARG4;
    hppa_device_t *dev;
    int ret, len;
    char *c;
    struct disk_op_s disk_op;

    dev = find_hpa_device(hpa);
    if (!dev) {

        BUG_ON(1);
        return PDC_INVALID_ARG;
    }

    if (1 &&
            (((DEV_is_serial_device(dev) || HPA_is_graphics_device(hpa)) && option == ENTRY_IO_COUT) ||
             ((DEV_is_serial_device(dev) || HPA_is_graphics_device(hpa)) && option == ENTRY_IO_CIN) ||
             ((DEV_is_storage_device(dev) && option == ENTRY_IO_BOOTIN && !(pdc_debug & DEBUG_BOOT_IO)))) ) {
        /* avoid debug messages */
    } else {
        iodc_log_call(arg, __FUNCTION__);
    }

    /* console I/O */
    switch (option) {
        case ENTRY_IO_COUT: /* console output */
            c = (char*)ARG6;
            result[0] = len = ARG7;
            if (DEV_is_serial_device(dev) || HPA_is_LASI_graphics(hpa)) {
                while (len--)
                    printf("%c", *c++);
            }
            return PDC_OK;
        case ENTRY_IO_CIN: /* console input, with 5 seconds timeout */
            c = (char*)ARG6;
            /* FIXME: Add loop to wait for up to 5 seconds for input */
            if (HPA_is_LASI_keyboard(hpa))
                result[0] = lasips2_kbd_in(c, ARG7);
            else if (DEV_is_serial_device(dev))
                result[0] = parisc_serial_in(c, ARG7);
            return PDC_OK;
    }

    /* boot medium I/O */
    if (DEV_is_storage_device(dev))
        switch (option) {
            case ENTRY_IO_BOOTIN: /* boot medium IN */
            case ENTRY_IO_BBLOCK_IN: /* boot block medium IN */
                disk_op.drive_fl = boot_drive;
                disk_op.buf_fl = (void*)ARG6;
                disk_op.command = CMD_READ;

                // Make sure we know how many bytes we can read at once!
                // NOTE: LSI SCSI can not read more than 8191 blocks, esp only 64k
                if (disk_op.drive_fl->max_bytes_transfer == 0) {
                    dprintf(0, "WARNING: Maximum transfer size not set for boot disc.\n");
                    disk_op.drive_fl->max_bytes_transfer = 64*1024;   /* 64kb */
                }

                if (option == ENTRY_IO_BBLOCK_IN) { /* in 2k blocks */
                    unsigned long maxcount;
                    // one block at least
                    // if (!ARG7) return PDC_INVALID_ARG;
                    /* reqsize must not be bigger than maxsize */
                    // if (ARG7 > ARG8) return PDC_INVALID_ARG;
                    disk_op.count = (ARG7 * ((u64)FW_BLOCKSIZE / disk_op.drive_fl->blksize));
                    // limit transfer size (#blocks) based on scsi controller capability
                    maxcount = disk_op.drive_fl->max_bytes_transfer / disk_op.drive_fl->blksize;
                    if (disk_op.count > maxcount)
                        disk_op.count = maxcount;
                    disk_op.lba = (ARG5 * ((u64)FW_BLOCKSIZE / disk_op.drive_fl->blksize));
                } else {
                    // read one block at least.
                    if (ARG7 && (ARG7 < disk_op.drive_fl->blksize))
                        ARG7 = disk_op.drive_fl->blksize;
                    // limit transfer size based on scsi controller capability
                    if (ARG7 > disk_op.drive_fl->max_bytes_transfer)
                        ARG7 = disk_op.drive_fl->max_bytes_transfer;
                    /* reqsize must be multiple of 2K */
                    if (ARG7 & (FW_BLOCKSIZE-1))
                        return PDC_INVALID_ARG;
                    /* reqsize must not be bigger than maxsize */
                    // if (ARG7 > ARG8) return PDC_INVALID_ARG;
                    /* medium start must be 2K aligned */
                    if (ARG5 & (FW_BLOCKSIZE-1))
                        return PDC_INVALID_ARG;
                    disk_op.count = (ARG7 / disk_op.drive_fl->blksize);
                    disk_op.lba = (ARG5 / disk_op.drive_fl->blksize);
                }

                // dprintf(0, "LBA %d  COUNT  %d\n", (u32) disk_op.lba, (u32)disk_op.count);
                ret = process_op(&disk_op);
                if (option == ENTRY_IO_BOOTIN)
                    result[0] = disk_op.count * disk_op.drive_fl->blksize; /* return bytes */
                else
                    result[0] = (disk_op.count * (u64)disk_op.drive_fl->blksize) / FW_BLOCKSIZE; /* return blocks */
                // printf("\nBOOT IO result %d, requested %d, read %ld\n", ret, ARG7, result[0]);
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
    unsigned long hpa = COMPAT_VAL(ARG0);
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG4;
    hppa_device_t *dev;

    iodc_log_call(arg, __FUNCTION__);

    dev = find_hpa_device(hpa);
    // dprintf(1, "HPA1 %lx  DEV %p  pci %p\n", hpa, dev, dev->pci);

    if (!dev || !(DEV_is_storage_device(dev) || DEV_is_serial_device(dev) || DEV_is_network_device(dev)))
        return PDC_INVALID_ARG;
    // dprintf(1, "HPA2 %lx  DEV %p\n", hpa, dev);

    switch (option) {
        case ENTRY_INIT_SRCH_FRST: /* 2: Search first */
            if (DEV_is_network_device(dev))
                return PDC_NE_BOOTDEV; /* No further boot devices */
            memcpy((void *)ARG3, &mod_path_emulated_drives.layers,
                sizeof(mod_path_emulated_drives.layers)); /* fill ID_addr */
            result[0] = 0;
            result[1] = DEV_is_serial_device(dev) ? CL_DUPLEX : CL_RANDOM;
            result[2] = result[3] = 0; /* No network card, so no MAC. */
            return PDC_OK;
	case ENTRY_INIT_SRCH_NEXT: /* 3: Search next */
            return PDC_NE_BOOTDEV; /* No further boot devices */
        case ENTRY_INIT_MOD_DEV: /* 4: Init & test mod & dev */
        case ENTRY_INIT_DEV:     /* 5: Init & test dev */
            result[0] = 0; /* module IO_STATUS */
            result[1] = DEV_is_serial_device(dev) ? CL_DUPLEX: CL_RANDOM;
            if (DEV_is_network_device(dev))
                result[2] = result[3] = 0x11221133; /* TODO?: MAC of network card. */
            else
                result[2] = result[3] = 0;
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
    // BUG_ON(1);
    return PDC_BAD_OPTION;
}

int __VISIBLE parisc_iodc_ENTRY_TEST(unsigned int *arg FUNC_MANY_ARGS)
{
    unsigned long hpa = COMPAT_VAL(ARG0);
    unsigned long option = ARG1;
    unsigned int *result = (unsigned int *)ARG4;
    hppa_device_t *dev;

    iodc_log_call(arg, __FUNCTION__);

    dev = find_hpa_device(hpa);
    if (!dev || !(DEV_is_storage_device(dev) || DEV_is_serial_device(dev)))
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
    unsigned int *result = (unsigned int *)ARG4;

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
        DO(PDC_PAT_CELL)
        DO(PDC_PAT_CHASSIS_LOG)
        DO(PDC_PAT_CPU)
        DO(PDC_PAT_PD)
        DO(PDC_LINK)
#undef DO
        return "UNKNOWN!";
}

static int pdc_chassis(unsigned long *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;
    short *display_model = (short *)ARG3;

    switch (option) {
        case PDC_CHASSIS_DISP:
            ARG3 = ARG2;
            /* WARNING: Avoid copyig the 64-bit result array to ARG2 */
            NO_COMPAT_RETURN_VALUE(ARG2);
            result = (unsigned long *)&ARG4; // do not write to ARG2, use &ARG4 instead
            // fall through
        case PDC_CHASSIS_DISPWARN:
            ARG4 = (ARG3 >> 17) & 7;
            chassis_code = ARG3 & 0xffff;
            if (pdc_debug & DEBUG_CHASSIS)
                printf("\nPDC_CHASSIS: %s (%ld), %sCHASSIS  0x%x\n",
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

static int pdc_pim(unsigned long *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;
    unsigned long hpa;
    int i;
    unsigned int count, default_size;

    if (is_64bit_CPU())
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
            if (i < 0 || i >= smp_cpus) {
                *result = PDC_INVALID_ARG;
                return PDC_OK;
            }
            if (( is_64bit_CPU() && pim_toc_data[i].pim20.cpu_state.val == 0) ||
                (!is_64bit_CPU() && pim_toc_data[i].pim11.cpu_state.val == 0)) {
                /* PIM contents invalid */
                *result = PDC_NE_MOD;
                return PDC_OK;
            }
            count = (default_size < ARG4) ? default_size : ARG4;
            memcpy((void *)ARG3, &pim_toc_data[i], count);
            *result = count;
            /* clear PIM contents */
            if (is_64bit_CPU())
                pim_toc_data[i].pim20.cpu_state.val = 0;
            else
                pim_toc_data[i].pim11.cpu_state.val = 0;
            return PDC_OK;
    }
    return PDC_BAD_OPTION;
}

static int pdc_model(unsigned long *arg)
{
    const char *model_str = current_machine->pdc_modelstr;
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;

    switch (option) {
        case PDC_MODEL_INFO:
            /*
             * In case we run on a 32-bit only emulation, avoid a kernel crash
             * with old qemu versions which will try to run 64-bit instructions
             * kernel sr_disable_hash() function
             */
            memset(result, 0, 32 * sizeof(unsigned long));
            memcpy(result, (is_64bit_CPU()) ?
                    &current_machine->pdc_model : &machine_B160L.pdc_model,
			sizeof(current_machine->pdc_model));
            return PDC_OK;
        case PDC_MODEL_VERSIONS:
            switch (ARG3) {
                case 0: /* return CPU0 version */
                    result[0] = current_machine->pdc_version;
                    return PDC_OK;
                case 1: /* return PDC version */
                    result[0] = (is_64bit_CPU()) ? 0x20 : 0x011;
                    return PDC_OK;
                case 2: /* return PDC PAT(?) version */
                    if (!is_64bit_CPU())
                        break;
                    result[0] = 0x20;
                    return PDC_OK;
            }
            return -4; // invalid c_index
        case PDC_MODEL_SYSMODEL:
            result[0] = strlen(model_str);
            strtcpy((char *)ARG4, model_str, result[0] + 1);
            return PDC_OK;
        case PDC_MODEL_ENSPEC:
        case PDC_MODEL_DISPEC:
            if (ARG3 != current_machine->pdc_model.pot_key)
                return -20;
            NO_COMPAT_RETURN_VALUE(ARG2);
            return PDC_OK;
        case PDC_MODEL_CPU_ID:
            /* if CPU does not support 64bits, use the B160L CPUID */
            if (is_64bit_CPU())
                result[0] = current_machine->pdc_cpuid;
            else
                result[0] = machine_B160L.pdc_cpuid;
            return PDC_OK;
        case PDC_MODEL_CAPABILITIES:
            /* unlock pdc call if running wide. */
            firmware_width_locked = !(psw_defaults & PDC_PSW_WIDE_BIT);
            result[0] = current_machine->pdc_caps;
            if (!is_64bit_PDC() || (enable_OS64 & PDC_MODEL_OS32))
                result[0] |= PDC_MODEL_OS32; /* we support 32-bit PDC */
            else
                result[0] &= ~PDC_MODEL_OS32;
            if (is_64bit_PDC() && (enable_OS64 & PDC_MODEL_OS64)) /* and maybe 64-bit */
                result[0] |= PDC_MODEL_OS64; /* this means 64-bit PDC calls are supported */
            else
                result[0] &= ~PDC_MODEL_OS64;
            result[0] &= ~0x4; /* remove NP flag, our IO-PDIR is coherent and needs no flush */
            result[0] &= ~0x8; /* remove SV flag, we need no virtual index in SBA */
            result[0] &= ~0x30; /* remove NVA bits, we have no issues with non-equiv. aliasing */
            return PDC_OK;
        case PDC_MODEL_GET_INSTALL_KERNEL:
            // No need to provide a special install kernel during installation of HP-UX
            return PDC_BAD_OPTION;
        case PDC_MODEL_GET_PLATFORM_INFO:
            if (1)      /* not supported on B160L or C3700 */
                return PDC_BAD_OPTION;
            model_str = has_astro ? "A6057A" : "9000/778";
            strtcpy((char *)ARG2, model_str, 16);
            strtcpy((char *)ARG3, model_str, 16);
            /* use: current_machine->pdc_model.sw_id ? */
            strtcpy((char *)ARG4, "001122334455", 16);
            NO_COMPAT_RETURN_VALUE(ARG2);
            return PDC_OK;
    }
    dprintf(0, "\n\nSeaBIOS: Unimplemented PDC_MODEL function %ld %lx %lx %lx %lx\n", ARG1, ARG2, ARG3, ARG4, ARG5);
    return PDC_BAD_OPTION;
}

static int pdc_cache(unsigned long *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;
    struct pdc_cache_info *machine_cache_info
        = (struct pdc_cache_info *) current_machine->pdc_cache_info;

    switch (option) {
        case PDC_CACHE_INFO:
            machine_cache_info->it_size = tlb_entries;
            machine_cache_info->dt_size = tlb_entries;
            machine_cache_info->it_conf = (struct pdc_tlb_cf) { .tc_sh = 3, .tc_page = 1, .tc_cst = 1, .tc_sr = 0, };
            machine_cache_info->dt_conf = (struct pdc_tlb_cf) { .tc_sh = 3, .tc_page = 1, .tc_cst = 1, .tc_sr = 0, };
            machine_cache_info->it_loop = 1;
            machine_cache_info->dt_loop = 1;

#if 0
            dprintf(0, "\n\nCACHE  IC: %ld %ld %ld DC: %ld %ld %ld\n",
                    machine_cache_info->ic_count, machine_cache_info->ic_loop, machine_cache_info->ic_stride,
                    machine_cache_info->dc_count, machine_cache_info->dc_loop, machine_cache_info->dc_stride);
#endif
#if 1
            /* ODE has problems if we report no cache */
            machine_cache_info->ic_size = 1024; /* no instruction cache */
            machine_cache_info->dc_size = 1024; /* no data cache */
#elif 1
            machine_cache_info->dc_conf = (struct pdc_cache_cf) { .cc_line = 7, .cc_sh = 1, .cc_cst = 1 };
            machine_cache_info->ic_conf = (struct pdc_cache_cf) { .cc_line = 7, .cc_sh = 1, .cc_cst = 1 };

            machine_cache_info->ic_size = 0; /* no instruction cache */
            machine_cache_info->ic_count = 0;
            machine_cache_info->ic_loop = -1;
            machine_cache_info->ic_base = 0;
            machine_cache_info->ic_stride = 0;
            machine_cache_info->dc_size = 0; /* no data cache */
            machine_cache_info->dc_count = 0;
            machine_cache_info->dc_loop = -1;
            machine_cache_info->dc_base = 0;
            machine_cache_info->dc_stride = 0;
#endif

            memcpy(result, machine_cache_info, sizeof(*machine_cache_info));
            return PDC_OK;
        case PDC_CACHE_RET_SPID:	/* returns space-ID bits when sr-hasing is enabled */
            memset(result, 0, 32 * sizeof(unsigned long));
            result[0] = 0;
            return PDC_OK;
    }
    dprintf(0, "\n\nSeaBIOS: Unimplemented PDC_CACHE function %ld %lx %lx %lx %lx\n", ARG1, ARG2, ARG3, ARG4, ARG5);
    return PDC_BAD_OPTION;
}

static int pdc_hpa(unsigned long *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;
    unsigned long hpa;
    int i;

    switch (option) {
        case PDC_HPA_PROCESSOR:
            hpa = mfctl(CPU_HPA_CR_REG); /* get CPU HPA from cr7 */
            i = index_of_CPU_HPA(hpa);
            BUG_ON(i < 0 || i >= smp_cpus); /* ARGH, someone modified cr7! */
            result[0] = hpa;    /* CPU_HPA */
            result[1] = i;      /* for SMP: 0,1,2,3,4...(num of this cpu) */
            return PDC_OK;
        case PDC_HPA_MODULES:
            return PDC_BAD_OPTION; // all modules on same board as the processor.
    }
    return PDC_BAD_OPTION;
}

static int pdc_coproc(unsigned long *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;
    unsigned long mask;
    switch (option) {
        case PDC_COPROC_CFG:
            memset(result, 0, 32 * sizeof(unsigned long));
            mask = 3UL << 6;    /* bit for FPU available/functional */
            mtctl(mask, 10);    /* initialize cr10 */
            result[0] = mask;   /* ccr_enable */
            result[1] = mask;   /* ccr_present */
            result[17] = 1;     /* FPU revision */
            result[18] = current_machine->pdc_cpuid >> 5; /* FPU model */
            return PDC_OK;
    }
    return PDC_BAD_OPTION;
}

static int pdc_iodc(unsigned long *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;
    unsigned long hpa, entry_len;
    hppa_device_t *dev;
    struct pdc_iodc *iodc_p;
    unsigned char *c;

    // dprintf(1, "\n\nSeaBIOS: Info PDC_IODC function %ld ARG3=%lx ARG4=%lx ARG5=%lx ARG6=%lx\n", option, ARG3, ARG4, ARG5, ARG6);
    switch (option) {
        case PDC_IODC_READ:
            hpa = COMPAT_VAL(ARG3);
            // dev = find_hpa_device(hpa);
            // searches for 0xf1041000
            dev = find_hppa_device_by_hpa(hpa);
            // printf("pdc_iodc found dev %p\n", dev);
            if (!dev)
                return -4; // not found

            iodc_p = dev->iodc;

            if (ARG4 == PDC_IODC_INDEX_DATA) {
                if (ARG6 > sizeof(*iodc_p))
                    ARG6 = sizeof(*iodc_p);
                memcpy((void*) ARG5, iodc_p, ARG6);
                c = (unsigned char *) ARG5;
                // printf("SeaBIOS: PDC_IODC get: hpa = 0x%lx, HV: 0x%x 0x%x IODC_SPA=0x%x  type 0x%x, \n", hpa, c[0], c[1], c[2], c[3]);
                result[0] = ARG6;
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
            entry_len = &iodc_entry_table_one_entry - &iodc_entry_table;
            c += (ARG4 - PDC_IODC_RI_INIT) * entry_len;
            memcpy((void*) ARG5, c, entry_len);
            // printf("\n\nSeaBIOS: Info PDC_IODC function OK\n");
            flush_data_cache((char*)ARG5, *result);
            return PDC_OK;
            break;
        case PDC_IODC_NINIT:	/* non-destructive init - for memory */
        case PDC_IODC_DINIT:	/* destructive init */
            result[0] = 0; /* IO_STATUS */
            result[1] = 0; /* max_spa */
            result[2] = ram_size; /* max memory */
            result[3] = 0;
            return PDC_OK;
        case PDC_IODC_MEMERR:
            result[0] = 0; /* IO_STATUS */
            result[1] = 0;
            result[2] = 0;
            result[3] = 0;
            return PDC_OK;
    }
    dprintf(0, "\n\nSeaBIOS: Unimplemented PDC_IODC function %ld ARG3=%lx ARG4=%lx ARG5=%lx ARG6=%lx\n", option, ARG3, ARG4, ARG5, ARG6);
    return PDC_BAD_OPTION;
}

static int pdc_tod(unsigned long *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;

    switch (option) {
        case PDC_TOD_READ:
            result[0] = *rtc_ptr;
            result[1] = result[2] = result[3] = 0;
            return PDC_OK;
        case PDC_TOD_WRITE:
            *rtc_ptr = ARG2;
            NO_COMPAT_RETURN_VALUE(ARG2);
            return PDC_OK;
        case 2: /* PDC_TOD_CALIBRATE_TIMERS */
            /* double-precision floating-point with frequency of Interval Timer in megahertz: */
            *(double*)&result[0] = (double)CPU_CLOCK_MHZ;
            /* unsigned 64-bit integers representing  clock accuracy in parts per billion: */
            result[2] = 1000000000; /* TOD_acc */
            result[3] = 0x5a6c; /* CR_acc (interval timer) */
            return PDC_OK;
    }
    dprintf(0, "\n\nSeaBIOS: Unimplemented PDC_TOD function %ld ARG2=%lx ARG3=%lx ARG4=%lx\n", option, ARG2, ARG3, ARG4);
    return PDC_BAD_OPTION;
}

static int pdc_stable(unsigned long *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;

    // dprintf(0, "\n\nSeaBIOS: PDC_STABLE function %ld ARG2=%lx ARG3=%lx ARG4=%lx\n", option, ARG2, ARG3, ARG4);
    switch (option) {
        case PDC_STABLE_READ:
            if ((ARG2 + ARG4) > STABLE_STORAGE_SIZE)
                return PDC_INVALID_ARG;
            memcpy((unsigned char *) ARG3, &stable_storage[ARG2], ARG4);
            NO_COMPAT_RETURN_VALUE(ARG2);
            return PDC_OK;
        case PDC_STABLE_WRITE:
            if ((ARG2 + ARG4) > STABLE_STORAGE_SIZE)
                return PDC_INVALID_ARG;
            memcpy(&stable_storage[ARG2], (unsigned char *) ARG3, ARG4);
            NO_COMPAT_RETURN_VALUE(ARG2);
            return PDC_OK;
        case PDC_STABLE_RETURN_SIZE:
            result[0] = STABLE_STORAGE_SIZE;
            return PDC_OK;
        case PDC_STABLE_VERIFY_CONTENTS:
            NO_COMPAT_RETURN_VALUE(ARG2);
            return PDC_OK;
        case PDC_STABLE_INITIALIZE:
            init_stable_storage();
            NO_COMPAT_RETURN_VALUE(ARG2);
            return PDC_OK;
    }
    return PDC_BAD_OPTION;
}

static int pdc_nvolatile(unsigned long *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;

    switch (option) {
        case PDC_NVOLATILE_READ:
            if ((ARG2 + ARG4) > NVOLATILE_STORAGE_SIZE)
                return PDC_INVALID_ARG;
            memcpy((unsigned char *) ARG3, &nvolatile_storage[ARG2], ARG4);
            NO_COMPAT_RETURN_VALUE(ARG2);
            return PDC_OK;
        case PDC_NVOLATILE_WRITE:
            if ((ARG2 + ARG4) > NVOLATILE_STORAGE_SIZE)
                return PDC_INVALID_ARG;
            memcpy(&nvolatile_storage[ARG2], (unsigned char *) ARG3, ARG4);
            NO_COMPAT_RETURN_VALUE(ARG2);
            return PDC_OK;
        case PDC_NVOLATILE_RETURN_SIZE:
            result[0] = NVOLATILE_STORAGE_SIZE;
            return PDC_OK;
        case PDC_NVOLATILE_VERIFY_CONTENTS:
            NO_COMPAT_RETURN_VALUE(ARG2);
            return PDC_OK;
        case PDC_NVOLATILE_INITIALIZE:
            memset(nvolatile_storage, 0, sizeof(nvolatile_storage));
            NO_COMPAT_RETURN_VALUE(ARG2);
            return PDC_OK;
    }
    return PDC_BAD_OPTION;
}

static int pdc_add_valid(unsigned long *arg)
{
    unsigned long option = ARG1;
    unsigned long arg2 = is_compat_mode() ? COMPAT_VAL(ARG2) : ARG2;

    NO_COMPAT_RETURN_VALUE(ARG2);
    // dprintf(0, "\n\nSeaBIOS: PDC_ADD_VALID function %ld arg2=%x called.\n", option, arg2);
    if (option != 0)
        return PDC_BAD_OPTION;
    if (0 && arg2 == 0) // should PAGE0 be valid?  HP-UX asks for it, but maybe due a bug in our code...
        return 1;
    // if (arg2 < PAGE_SIZE) return PDC_ERROR;
    if (arg2 < ram_size)
        return PDC_OK;
    if (arg2 >= (unsigned long)_sti_rom_start &&
        arg2 <= (unsigned long)_sti_rom_end)
        return PDC_OK;
    if (arg2 < FIRMWARE_END)
        return 1;
    if (arg2 <= 0xffffffff)
        return PDC_OK;
    if (find_hpa_device(arg2))
        return PDC_OK;
    dprintf(0, "\n\nSeaBIOS: FAILED!!!! PDC_ADD_VALID function %ld arg2=%lx called.\n", option, arg2);
    return PDC_REQ_ERR_0; /* Operation completed with a requestor bus error. */
}

static int pdc_proc(unsigned long *arg)
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

static int pdc_block_tlb(unsigned long *arg)
{
    int ret;

    /* Block TLB is only supported on 32-bit CPUs */
    if (is_64bit_CPU())
        return PDC_BAD_PROC;

    asm(
	"ldw (7-0)*%2(%1),%%r26 ! ldw (7-1)*%2(%1),%%r25 ! ldw (7-2)*%2(%1),%%r24 ! ldw (7-3)*%2(%1),%%r23\n"
	"ldw (7-4)*%2(%1),%%r22 ! ldw (7-5)*%2(%1),%%r21 ! ldw (7-6)*%2(%1),%%r20 ! ldw (7-7)*%2(%1),%%r19\n"
	"ldi %3,%%ret0\n"
	"diag 0x100\n"
	"copy %%ret0,%0\n"
	: "=r" (ret)
	: "r" (arg), "i" (sizeof(long)), "i" (PDC_BAD_OPTION)
	: "r28", "r26", "r25", "r24", "r23", "r22", "r21", "r20", "r19" );

    return ret;
}

static int pdc_tlb(unsigned long *arg)
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

static int pdc_mem(unsigned long *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;

    // only implemented on 64bit PDC variants
    if (!is_64bit_PDC())
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
            GoldenMemory = (unsigned int)ARG3;
            NO_COMPAT_RETURN_VALUE(ARG2);
            return PDC_OK;
        case PDC_MEM_GET_MEMORY_SYSTEM_TABLES_SIZE:
        case PDC_MEM_GET_MEMORY_SYSTEM_TABLES:
            /* not yet implemented for 64-bit */
            return PDC_BAD_PROC;
    }
    dprintf(0, "\n\nSeaBIOS: Check PDC_MEM option %ld ARG3=%lx ARG4=%lx ARG5=%lx\n", option, ARG3, ARG4, ARG5);
    return PDC_BAD_PROC;
}

static int pdc_psw(unsigned long *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;
    unsigned long mask;

    if (is_64bit_CPU() /* && !firmware_width_locked*/)
        mask = PDC_PSW_WIDE_BIT | PDC_PSW_ENDIAN_BIT;
    else
        mask = PDC_PSW_ENDIAN_BIT;

    if (option > PDC_PSW_SET_DEFAULTS)
        return PDC_BAD_OPTION;
    if (option == PDC_PSW_MASK)
        *result = mask;
    if (option == PDC_PSW_GET_DEFAULTS)
        *result = psw_defaults & mask;
    if (option == PDC_PSW_SET_DEFAULTS) {
        psw_defaults = ARG2 & mask;
        /* we do not yet support little endian mode */
        BUG_ON((psw_defaults & PDC_PSW_ENDIAN_BIT) == 1);
        /* tell qemu the default mask */
        mtctl(psw_defaults, CR_PSW_DEFAULT);
        /* let model know that we support 64-bit */
        current_machine->pdc_model.width = (psw_defaults & PDC_PSW_WIDE_BIT) ? 1 : 0;
        NO_COMPAT_RETURN_VALUE(ARG2);
    }
    return PDC_OK;
}

static int pdc_system_map(unsigned long *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;
    struct pdc_module_path *mod_path;
    hppa_device_t *dev;
    unsigned long hpa_index;

    // dprintf(0, "\n\nSeaBIOS: Info: PDC_SYSTEM_MAP function %ld ARG3=%x ARG4=%x ARG5=%x\n", option, ARG3, ARG4, ARG5);
    switch (option) {
        case PDC_FIND_MODULE:
            hpa_index = ARG4;
            dev = find_hppa_device_by_index(0, hpa_index, 0); /* root devices */
            if (!dev)
                return PDC_NE_MOD; // Module not found

            if (0) {
                dprintf(1, "PDC_FIND_MODULE dev=%p hpa=%lx ", dev, dev ? dev->hpa:0UL);
                print_mod_path(dev->mod_path);
                if (dev->pci)
                    dprintf(1, "PCI %pP ", dev->pci);
                dprintf(1, "\n");
            }

            memset(result, 0, 32*sizeof(long));

            mod_path = (struct pdc_module_path *)ARG3;
            if (mod_path)
                *mod_path = *dev->mod_path;

            // *pdc_mod_info = *parisc_devices[hpa_index].mod_info; -> can be dropped.
            result[0] = dev->mod_info->mod_addr; //  for PDC_IODC
            result[1] = dev->mod_info->mod_pgs;
            result[2] = dev->num_addr;           //  dev->mod_info->add_addr;
            if (0)
                dprintf(1, "PDC_FIND_MODULE %lx %ld %ld \n", result[0], result[1],result[2]);

            return PDC_OK;

        case PDC_FIND_ADDRESS:
            hpa_index = ARG3;
            dev = find_hppa_device_by_index(0, hpa_index, 0); /* root devices */
            if (!dev)
                return PDC_NE_MOD; // Module not found
            ARG4 -= 1;
            if (ARG4 >= dev->num_addr)
                return PDC_INVALID_ARG;
            memset(result, 0, 32*sizeof(long));
            result[0] = dev->add_addr[ARG4];
            result[1] = HPA_is_graphics_device(dev->hpa) ? GFX_NUM_PAGES : 1;
            return PDC_OK;

        case PDC_TRANSLATE_PATH:
            mod_path = (struct pdc_module_path *)ARG3;
            hppa_device_t *dev = find_hppa_device_by_path(mod_path, &hpa_index, 1); // XXX
            if (0) {
                dprintf(1, "PDC_TRANSLATE_PATH dev=%p hpa=%lx ", dev, dev ? dev->hpa:0UL);
                print_mod_path(mod_path);
                if (dev && dev->pci)
                    dprintf(1, "PCI %pP ", dev->pci);
                dprintf(1, "\n");
            }
            if (!dev)
                return PDC_NE_MOD;

            result[0] = dev->mod_info->mod_addr; //  for PDC_IODC
            result[1] = dev->mod_info->mod_pgs;
            result[2] = dev->num_addr;           //  dev->mod_info->add_addr;
            result[3] = hpa_index;
            return PDC_OK;
    }
    return PDC_BAD_OPTION;
}

static int pdc_soft_power(unsigned long *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;

    if (!powerswitch_supported())
        return PDC_BAD_PROC;

    switch (option) {
        case PDC_SOFT_POWER_INFO:
            result[0] = (unsigned long) powersw_ptr;
            return PDC_OK;
        case PDC_SOFT_POWER_ENABLE:
            /* put soft power button under hardware (ARG3=0) or
             * software (ARG3=1) control. */
            *powersw_ptr = (ARG3 & 1) << 8 | (*powersw_ptr & 1);
            check_powersw_button();
            NO_COMPAT_RETURN_VALUE(ARG2);
            return PDC_OK;
    }
    // dprintf(0, "\n\nSeaBIOS: PDC_SOFT_POWER called with ARG2=%x ARG3=%x ARG4=%x\n", ARG2, ARG3, ARG4);
    return PDC_BAD_OPTION;
}

static int pdc_mem_map(unsigned long *arg)
{
    unsigned long option = ARG1;
    struct pdc_memory_map *memmap = (struct pdc_memory_map *) ARG2;
    struct pdc_module_path *dp = (struct pdc_module_path *) ARG3;
    hppa_device_t *dev;

    switch (option) {
        case PDC_MEM_MAP_HPA:
            dprintf(0, "\nSeaBIOS: PDC_MEM_MAP_HPA  bus = %d,  mod = %d\n", dp->path.bc[4], dp->path.mod);
            dev = find_hppa_device_by_path(dp, NULL, 0);
            if (!dev)
                return PDC_NE_MOD;
            memcpy(memmap, dev->mod_info, sizeof(*memmap));
            return PDC_OK;
    }
    return PDC_BAD_OPTION;
}

static int pdc_io(unsigned long *arg)
{
    unsigned long option = ARG1;

    switch (option) {
        case PDC_IO_READ_AND_CLEAR_ERRORS:
            dprintf(0, "\n\nSeaBIOS: PDC_IO called with ARG2=%lx ARG3=%lx ARG4=%lx\n", ARG2, ARG3, ARG4);
            // return PDC_BAD_OPTION;
        case PDC_IO_RESET:
        case PDC_IO_RESET_DEVICES:
            NO_COMPAT_RETURN_VALUE(ARG2);
            return PDC_OK;
    }
    return PDC_BAD_OPTION;
}

static int pdc_lan_station_id(unsigned long *arg)
{
    unsigned long option = ARG1;

    switch (option) {
        case PDC_LAN_STATION_ID_READ:
            if (has_astro)
                return PDC_INVALID_ARG;
            if (ARG3 != LASI_LAN_HPA)
                return PDC_INVALID_ARG;
            if (!keep_this_hpa(LASI_LAN_HPA))
                return PDC_INVALID_ARG;
            /* Let qemu store the MAC of NIC to address @ARG2 */
            *(unsigned long *)(LASI_LAN_HPA+12) = ARG2;
            NO_COMPAT_RETURN_VALUE(ARG2);
            return PDC_OK;
    }
    return PDC_BAD_OPTION;
}


#if 0
    Interrupt Routing Table (cell 0)
    8b10000f30000002 fffffffffed30800 -   8b 10 00 0f 30 00 00 02 fffffffffed30800
    8b10000f34000003 fffffffffed30800 -   8b 10 00 0f 34 00 00 03 fffffffffed30800
    8b10000d3b000000 fffffffffed30800 -   8b 10 00 0d 3b 00 00 00 fffffffffed30800
    8b10000f3c000001 fffffffffed30800 -   8b 10 00 0f 3c 00 00 01 fffffffffed30800
    8b10000f3c000001 fffffffffed30800 -   8b 10 00 0f 3c 00 00 01 fffffffffed30800
#endif
#define MAX_IRT_TABLE_ENTRIES   24
#define IOSAPIC_HPA             0xfffffffffed30800ULL
#define ELROY_IRQS              8 /* IOSAPIC IRQs */
static int irt_table_entries;
static u32 irt_table[MAX_IRT_TABLE_ENTRIES * 16/sizeof(u32)];

static void iosapic_table_setup(void)
{
    struct pci_device *pci;
    u32 *p;
    u8 slot = 0, iosapic_intin = 0, irq_devno, bus_id;

    irt_table_entries = 0;
    memset(irt_table, 0, sizeof(irt_table));
    p = irt_table;

    foreachpci(pci) {
        // if (!pci->irq) continue;
        BUG_ON(irt_table_entries >= MAX_IRT_TABLE_ENTRIES);
        irt_table_entries++;
        dprintf(5, "IRT ENTRY #%d: bdf %02x\n", irt_table_entries, pci->bdf);
        /* write the 16 bytes */
        /* 1: entry_type, entry_length, interrupt_type, polarity_trigger */
        *p++ = 0x8b10000f;      // oder 0x8b10000d
        /* 2: src_bus_irq_devno, src_bus_id, src_seg_id, dest_iosapic_intin */
        /* irq_devno = (slot << 2) | (intr_pin-1); */
        irq_devno = (slot++ << 2) | (pci->irq - 1);
        bus_id = 0;
        *p++ = (irq_devno << 24) | (bus_id << 16) | (0 << 8) | (iosapic_intin << 0);
        *p++ = IOSAPIC_HPA >> 32;
        *p++ = (u32) IOSAPIC_HPA;
        iosapic_intin++;
        iosapic_intin &= (ELROY_IRQS - 1 );
    }
}

static int pdc_pci_index(unsigned long *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;
    /* machines with Dino don't provide this info */

    // dprintf(0, "\n\nSeaBIOS: PDC_PCI_INDEX(%lu) called with ARG2=%x ARG3=%x ARG4=%x\n", option, ARG2, ARG3, ARG4);
    switch (option) {
        case PDC_PCI_INTERFACE_INFO:
            memset(result, 0, 32 * sizeof(unsigned long));
            // BUG_ON(1);
            result[0] = 2;  /* XXX physical hardware returns those ?!? */
            return PDC_OK;
        case PDC_PCI_GET_INT_TBL_SIZE:
            if (!has_astro)
                return PDC_BAD_OPTION;
            result[0] = irt_table_entries;
            return PDC_OK;
        case PDC_PCI_GET_INT_TBL:
            if (!has_astro)
                return PDC_BAD_OPTION;
            result[0] = irt_table_entries;
            /* ARG4 is ptr to irt table */
            memcpy((void *)ARG4, irt_table, irt_table_entries * 16);
            return PDC_OK;
        case PDC_PCI_PCI_PATH_TO_PCI_HPA:
            // BUG_ON(1);
            result[0] = pci_hpa;
            return PDC_OK;
        case PDC_PCI_PCI_HPA_TO_PCI_PATH:
            BUG_ON(1);
            break;
    }
    return PDC_BAD_OPTION;
}

static int pdc_initiator(unsigned long *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;

    switch (option) {
        case PDC_GET_INITIATOR:
            /* SCSI controller is on normal PCI bus on machines with Astro */
            if (has_astro) return PDC_BAD_OPTION;
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
    dprintf(0, "\n\nSeaBIOS: Unimplemented PDC_INITIATOR function %ld ARG3=%lx ARG4=%lx ARG5=%lx\n", option, ARG3, ARG4, ARG5);
    return PDC_BAD_OPTION;
}

static int pdc_pat_cell(unsigned long *arg)
{
    unsigned long option = ARG1;
    struct pdc_pat_cell_num *cell_info = (void *)ARG2;

    switch (option) {
        case PDC_PAT_CELL_GET_NUMBER:
            // cell_info->cell_num = cell_info->cell_loc = 0;
            memset(cell_info, 0, 32*sizeof(long long));
            return PDC_OK;
        case PDC_PAT_CELL_GET_INFO:
            return PDC_BAD_OPTION; /* optional on single-cell machines */
        default:
            break;
    }
    dprintf(0, "\n\nSeaBIOS: Unimplemented PDC_PAT_CELL function %ld ARG3=%lx ARG4=%lx ARG5=%lx\n", option, ARG3, ARG4, ARG5);
    return PDC_BAD_OPTION;
}

static int pdc_pat_cpu(unsigned long *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;
    unsigned long hpa;

    switch (option) {
        case PDC_PAT_CPU_GET_NUMBER:
            hpa = COMPAT_VAL(ARG3);
            result[0] = index_of_CPU_HPA(hpa);
            result[1] = hpa;    /* location */
            result[2] = 0;      /* num siblings */
            return PDC_OK;
        case PDC_PAT_CPU_GET_HPA:
            if ((unsigned long)ARG3 >= smp_cpus)
                return PDC_INVALID_ARG;
            hpa = CPU_HPA_IDX(ARG3);
            result[0] = hpa;
            result[1] = hpa;    /* location */
            result[2] = 0;      /* num siblings */
            return PDC_OK;
        default:
            break;
    }
    dprintf(0, "\n\nSeaBIOS: Unimplemented PDC_PAT_CPU OPTION %lu called with ARG2=%lx ARG3=%lx ARG4=%lx\n", option, ARG2, ARG3, ARG4);
    return PDC_BAD_OPTION;
}

static int pdc_pat_pd(unsigned long *arg)
{
    unsigned long option = ARG1;
    unsigned long *result = (unsigned long *)ARG2;
    struct pdc_pat_pd_addr_map_entry *mem_table = (void *)ARG3;
    unsigned long count = ARG4;
    unsigned long offset = ARG5;

    switch (option) {
        case PDC_PAT_PD_GET_ADDR_MAP:
            if (count < sizeof(*mem_table) || offset != 0)
                return PDC_INVALID_ARG;
            memset(mem_table, 0, sizeof(*mem_table));
            mem_table->entry_type = PAT_MEMORY_DESCRIPTOR;
            mem_table->memory_type = PAT_MEMTYPE_MEMORY;
            mem_table->memory_usage = PAT_MEMUSE_GENERAL; /* ?? */
            mem_table->paddr = 0;  /* note: 64bit! */
            mem_table->pages = ram_size / 4096; /* Length in 4K pages */
            mem_table->cell_map = 0;
            result[0] = sizeof(*mem_table);
            return PDC_OK;

        case PDC_PAT_PD_GET_PDC_INTERF_REV:
            result[0] = 5;  // legacy_rev
            result[1] = 6;  // pat_rev
            result[2] = PDC_PAT_CAPABILITY_BIT_SIMULTANEOUS_PTLB;  // pat_cap
            return PDC_OK;
        default:
            break;
    }
    dprintf(0, "\n\nSeaBIOS: Unimplemented PDC_PAT_PD function %ld ARG3=%lx ARG4=%lx ARG5=%lx\n", option, ARG3, ARG4, ARG5);
    return PDC_BAD_OPTION;
}

static int pdc_pat_mem(unsigned long *arg)
{
    unsigned long option = ARG1;

    switch (option) {
        default:
            break;
    }
    dprintf(0, "\n\nSeaBIOS: Unimplemented PDC_PAT_MEM function %ld ARG3=%lx ARG4=%lx ARG5=%lx\n", option, ARG3, ARG4, ARG5);
    return PDC_BAD_OPTION;
}


int __VISIBLE parisc_pdc_entry(unsigned long *arg FUNC_MANY_ARGS)
{
    unsigned long proc = ARG0;
    unsigned long option = ARG1;

    if (pdc_debug & DEBUG_PDC) {
        printf("\nSeaBIOS: Start PDC%d proc %s(%ld) option %ld result=0x%lx ARG3=0x%lx %s ",
                (!is_64bit_PDC() || is_compat_mode()) ? 32 : 64, pdc_name(ARG0), ARG0, ARG1, ARG2, ARG3,
                (proc == PDC_IODC)?hpa_name(ARG3):"");
        printf("ARG4=0x%lx ARG5=0x%lx ARG6=0x%lx ARG7=0x%lx\n", ARG4, ARG5, ARG6, ARG7);
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

	case PDC_MEM_MAP:
            return pdc_mem_map(arg);

        case 134:
            if (ARG1 == 1 || ARG1 == 513) /* HP-UX 11.11 ask for it. */
                return PDC_BAD_PROC;
            break;

        case PDC_IO:
            return pdc_io(arg);

        case PDC_BROADCAST_RESET:
            dprintf(0, "\n\nSeaBIOS: PDC_BROADCAST_RESET (reset system) called with ARG3=%lx ARG4=%lx\n", ARG3, ARG4);
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

        /* PDC PAT functions */
        case PDC_PAT_CELL:
            if (firmware_width_locked)
                return PDC_BAD_PROC;
            return pdc_pat_cell(arg);

        case PDC_PAT_CHASSIS_LOG:
            if (firmware_width_locked)
                return PDC_BAD_PROC;
            dprintf(0, "\n\nSeaBIOS: PDC_PAT_CHASSIS_LOG OPTION %lu called with ARG2=%lx ARG3=%lx ARG4=%lx\n", option, ARG2, ARG3, ARG4);
            return PDC_BAD_PROC;

        case PDC_PAT_CPU:
            if (firmware_width_locked)
                return PDC_BAD_PROC;
            return pdc_pat_cpu(arg);

        case PDC_PAT_PD:
            if (firmware_width_locked)
                return PDC_BAD_PROC;
            return pdc_pat_pd(arg);

        case PDC_PAT_MEM:
            if (firmware_width_locked)
                return PDC_BAD_PROC;
            return pdc_pat_mem(arg);
    }

    printf("\n** WARNING **: SeaBIOS: Unimplemented PDC proc %s(%ld) option %ld result=%lx ARG3=%lx ",
            pdc_name(ARG0), ARG0, ARG1, ARG2, ARG3);
    printf("ARG4=%lx ARG5=%lx ARG6=%lx ARG7=%lx\n", ARG4, ARG5, ARG6, ARG7);

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
        if (is_64bit_CPU())
                pim20->cpu_state = state;
        else
                pim11->cpu_state = state;

        /* check that we use the same PIM entries as assembly code */
        BUG_ON(pim11 != pim);

        printf("\n");
        printf("##### CPU %d HPA %lx: SeaBIOS TOC register dump #####\n", cpu, hpa);
        for (y = 0; y < 32; y += 8) {
                if (is_64bit_CPU())
                        p = (unsigned long *)&pim20->gr[y];
                else
                        p = (unsigned long *)&pim11->gr[y];
                printf("GR%02d: %lx %lx %lx %lx",  y, p[0], p[1], p[2], p[3]);
                printf(       " %lx %lx %lx %lx\n",   p[4], p[5], p[6], p[7]);
        }
        printf("\n");
        for (y = 0; y < 32; y += 8) {
                if (is_64bit_CPU())
                        p = (unsigned long *)&pim20->cr[y];
                else
                        p = (unsigned long *)&pim11->cr[y];
                printf("CR%02d: %lx %lx %lx %lx", y, p[0], p[1], p[2], p[3]);
                printf(       " %lx %lx %lx %lx\n",  p[4], p[5], p[6], p[7]);
        }
        printf("\n");
        if (is_64bit_CPU())
                p = (unsigned long *)&pim20->sr[0];
        else
                p = (unsigned long *)&pim11->sr[0];
        printf("SR0: %lx %lx %lx %lx %lx %lx %lx %lx\n", p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
        if (is_64bit_CPU()) {
                printf("IAQ: %lx.%lx %lx.%lx   PSW: %lx\n",
                        (unsigned long)pim20->cr[17], (unsigned long)pim20->cr[18],
                        (unsigned long)pim20->iasq_back, (unsigned long)pim20->iaoq_back,
			(unsigned long)pim20->cr[22]);
                printf("RP(r2): %lx\n", (unsigned long)pim20->gr[2]);
        } else {
                printf("IAQ: %x.%x %x.%x   PSW: %x\n", pim11->cr[17], pim11->cr[18],
                        pim11->iasq_back, pim11->iaoq_back, pim11->cr[22]);
                printf("RP(r2): %x\n", pim11->gr[2]);
        }

        os_toc_handler = PAGE0->vec_toc;
        if (is_64bit_CPU())
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
            "        EXIT                            Exit QEMU emulation\n"
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

again:
    print_menu();

again2:
    input[0] = '\0';
    if (is_64bit_PDC() && HPA_is_LASI_graphics(PAGE0->mem_cons.hpa)) {
        printf("WARNING: USB Keyboard not yet functional in boot menu with 64-bit firmware!\n");
    }
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
    if (input[0] == 'L' && input[1] == 'S')     // HELP? (ls)
        goto again;
    if (input[0] == 'E' && input[1] == 'X')     // EXIT
        hlt();
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

static struct pz_device mem_cons_sti_boot = {
    .hpa = LASI_GFX_HPA,
    .cl_class = CL_DISPL,
};

static struct pz_device mem_kbd_sti_boot = {
    .hpa = LASI_PS2KBD_HPA,
    .cl_class = CL_KEYBD,
};

static struct pz_device mem_cons_boot = {
    .hpa = PARISC_SERIAL_CONSOLE - 0x800,
    .cl_class = CL_DUPLEX,
};

static struct pz_device mem_kbd_boot = {
    .hpa = PARISC_SERIAL_CONSOLE - 0x800,
    .cl_class = CL_KEYBD,
};

static struct pz_device mem_boot_boot = {
    .dp.path.flags = PF_AUTOBOOT,
    .hpa = DINO_SCSI_HPA,  // will be overwritten
    .cl_class = CL_RANDOM,
};

static void initialize_iodc_entry(void)
{
    unsigned long iodc_p = (unsigned long) &iodc_entry;

    /* need to initialize at runtime, required on 64-bit firmware */
    mem_cons_sti_boot.iodc_io = iodc_p;
    mem_kbd_sti_boot.iodc_io = iodc_p;
    mem_cons_boot.iodc_io = iodc_p;
    mem_kbd_boot.iodc_io = iodc_p;
    mem_boot_boot.iodc_io = iodc_p;
}

#if 0
static void find_pci_slot_for_dev(unsigned int vendor, char *pci_slot)
{
    struct pci_device *pci;

    foreachpci(pci)
        if (pci->vendor == vendor) {
            *pci_slot = (pci->bdf >> 3) & 0x0f;
            return;
        }
}
#endif

/* find serial PCI card (to be used as console) */
static void find_serial_pci_card(void)
{
    struct pci_device *pci;
    hppa_device_t *pdev;
    u32 pmem;

    if (!has_astro)     /* use built-in LASI serial port for console */
        return;

    pci = pci_find_class(PCI_CLASS_COMMUNICATION_SERIAL);
    if (!pci)
        return;

    dprintf(1, "PCI: Enabling %pP for primary SERIAL PORT\n", pci);
    pci_config_maskw(pci->bdf, PCI_COMMAND, 0,
                     PCI_COMMAND_IO | PCI_COMMAND_MEMORY);
    pmem = pci_enable_iobar(pci, PCI_BASE_ADDRESS_0);
    dprintf(1, "PCI: Enabling %pP for primary SERIAL PORT mem %x\n", pci, pmem);
    pmem += IOS_DIST_BASE_ADDR;

    /* set serial port for console output and keyboard input */
    pdev = &hppa_pci_devices[0];
    while (pdev->pci != pci)
        pdev++;
    pdev->pci_addr = pmem;
    mem_cons_boot.hpa = pdev->hpa;
    mem_kbd_boot.hpa = pdev->hpa;
    mem_kbd_sti_boot.hpa = pdev->hpa;
}

/* find SCSI PCI card (to be used as boot device) */
static void find_scsi_pci_card(void)
{
    struct pci_device *pci;
    hppa_device_t *pdev;
    u32 pmem;

    // if (!has_astro) return;
    pci = pci_find_class(PCI_CLASS_STORAGE_SCSI);
    if (!pci)
        return;
    dprintf(1, "PCI: Enabling %pP for primary SCSI PORT\n", pci);
    pmem = pci_enable_iobar(pci, PCI_BASE_ADDRESS_0);
    dprintf(1, "PCI: Enabling %pP for primary SCSI PORT mem %x\n", pci, pmem);
    pmem += IOS_DIST_BASE_ADDR;

    /* set SCSI HPA */
    pdev = &hppa_pci_devices[0];
    while (pdev->pci != pci)
        pdev++;
    pdev->pci_addr = pmem;
    mem_boot_boot.hpa = pdev->hpa;
    dprintf(1, "PCI: Enabling BOOT DEVICE HPA %x\n", mem_boot_boot.hpa);
}


/* Prepare boot paths in PAGE0 and stable memory */
static int prepare_boot_path(volatile struct pz_device *dest,
        const struct pz_device *source,
        unsigned int stable_offset)
{
    hppa_device_t *dev;
    unsigned long hpa;
    struct pdc_module_path *mod_path;

    hpa = source->hpa;
    dev = find_hpa_device(hpa);
    if (!dev)
        return 1;

    if (0 && DEV_is_storage_device(dev))
        mod_path = &mod_path_emulated_drives;
    else if (dev)
        mod_path = dev->mod_path;
    else {
        BUG_ON(1);
    }

    /* copy device path to entry in PAGE0 */
    memcpy((void*)dest, source, sizeof(*source));
    memcpy((void*)&dest->dp, mod_path, sizeof(struct pdc_module_path));

    /* copy device path to stable storage */
    memcpy(&stable_storage[stable_offset], mod_path, sizeof(*mod_path));

    BUG_ON(sizeof(*mod_path) != 0x20);
    BUG_ON(sizeof(struct pdc_module_path) != 0x20);
    return 0;
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

extern void start_kernel(unsigned long mem_free, unsigned long cline,
                         unsigned long rdstart,  unsigned long rdend,
                         unsigned long kernel_start_address);

void __VISIBLE start_parisc_firmware(void)
{
    unsigned int i, cpu_hz;
    unsigned long iplstart, iplend, sw_id;
    char *str;

    char bootdrive = (char)cmdline; // c = hdd, d = CD/DVD
    show_boot_menu = (linux_kernel_entry == 1);

    has_astro = (sizeof(long) != 4); /* 64-bit firmware does not support Dino */

    initialize_iodc_entry();

#ifndef __LP64__
    // detect if we emulate a 32- or 64-bit CPU.
    // set all bits in cr11, read back, and if the return
    // value is 63 this is a 64-bit capable CPU.
    // A 32-bit only CPU returns 31.
    mtctl(-1UL, 11);
    /* this is: mfctl,w sar,r1: */
    asm(".word 0x016048a0 + 1 ! copy %%r1,%0\n" : "=r" (i): : "r1");
    cpu_bit_width = (i == 63) ? 64 : 32;
#endif

    /* lock all 64-bit and PAT functions until unlocked from OS
     * via PDC_MODEL/PDC_MODEL_CAPABILITIES call */
    firmware_width_locked = 1;

    psw_defaults = PDC_PSW_ENDIAN_BIT;
    if (0 && is_64bit_PDC()) {
        /* enable 64-bit PSW by default */
        psw_defaults |= PDC_PSW_WIDE_BIT;
        current_machine->pdc_model.width = 1;
        firmware_width_locked = 0;
    }
    mtctl(psw_defaults, CR_PSW_DEFAULT);

    if (smp_cpus > HPPA_MAX_CPUS)
        smp_cpus = HPPA_MAX_CPUS;
    num_online_cpus = smp_cpus;

    if (ram_size >= FIRMWARE_START)
        ram_size = FIRMWARE_START;

    /* Initialize malloc stack */
    malloc_preinit();

    // PlatformRunningOn = PF_QEMU;  // emulate runningOnQEMU()

    /*
     * Initialize main variables at reboot, e.g. initialize the HPA of the main
     * console to "unknown" (0), which is required to get output via
     * parisc_putchar() at bootup.  Set initial PCI bus to Dino, which will be
     * corrected later when we get the machine model (C3000/B160L) via cfg(),
     * but cfg() tries to initialize the PCI bus.
     */
    PAGE0->mem_cons.hpa = 0;
    pci_hpa = PCI_HPA;    /* HPA of Dino or Elroy0 */
    hppa_port_pci_cmd  = (PCI_HPA + DINO_PCI_ADDR);
    hppa_port_pci_data = (PCI_HPA + DINO_CONFIG_DATA);

    /* Initialize qemu fw_cfg interface */
    PORT_QEMU_CFG_CTL = fw_cfg_port;
    qemu_cfg_init();

    /* Initialize boot structures. Needs working fw_cfg for bootprio option. */
    boot_init();

    DebugOutputPort = romfile_loadint("/etc/hppa/DebugOutputPort", CPU_HPA + 24);
    DebugOutputPort = F_EXTEND(DebugOutputPort);

    i = romfile_loadint("/etc/firmware-min-version", 0);
    if (i && i > SEABIOS_HPPA_VERSION) {
        printf("\nSeaBIOS firmware is version %d, but version %d is required. "
            "Please update.\n", (int)SEABIOS_HPPA_VERSION, i);
        hlt();
    }

    /* which machine shall we emulate? */
    str = romfile_loadfile("/etc/hppa/machine", NULL);
    if (!str) {
        str = "B160L";
        current_machine = &machine_B160L;
        pci_hpa = DINO_HPA;
        hppa_port_pci_cmd  = pci_hpa + DINO_PCI_ADDR;
        hppa_port_pci_data = pci_hpa + DINO_CONFIG_DATA;
    }
    if (strcmp(str, "C3700") == 0) {
        has_astro = 1;
        current_machine = &machine_C3700;
        pci_hpa = (unsigned long) ELROY0_BASE_HPA;
        hppa_port_pci_cmd  = pci_hpa + 0x040;
        hppa_port_pci_data = pci_hpa + 0x048;
        // but report back ASTRO_HPA
        // pci_hpa = (unsigned long) ASTRO_HPA;
        /* no serial port for now, will find later */
        mem_cons_boot.hpa = 0;
        mem_kbd_boot.hpa = 0;
    }
    if (strcmp(str, "715") == 0) {
        has_astro = 0; /* No Astro */
        current_machine = &machine_715;
        pci_hpa = 0; /* No PCI bus */
        hppa_port_pci_cmd  = 0;
        hppa_port_pci_data = 0;
        mem_cons_boot.hpa = 0xf0105000; /* serial port */
        mem_kbd_boot.hpa = 0xf0105000;
    }
    parisc_devices = current_machine->device_list;
    strtcpy(qemu_machine, str, sizeof(qemu_machine));

    tlb_entries = romfile_loadint("/etc/cpu/tlb_entries", 256);
    dprintf(0, "fw_cfg: TLB entries %d\n", tlb_entries);

    powersw_ptr = (int *) (unsigned long)
        romfile_loadint("/etc/hppa/power-button-addr", (unsigned long)&powersw_nop);

    /* allow user to disable power button: "-fw_cfg opt/power-button-enable,string=0" */
    i = romfile_loadstring_to_int("opt/power-button-enable", 1);
    if (i == 0) {
        powersw_ptr = NULL;
    }

    /* possibility to disable or limit to 64-bit OS installation: "-fw_cfg opt/OS64,string=3" */
    if (is_64bit_PDC()) {
        enable_OS64 = romfile_loadstring_to_int("opt/OS64", enable_OS64);
        if ((enable_OS64 & OS64_32_DEFAULT) == 0)
            enable_OS64 = OS64_32_DEFAULT;
    }

    /* real-time-clock addr */
    rtc_ptr = (int *) F_EXTEND(romfile_loadint("/etc/hppa/rtc-addr", (int) LASI_RTC_HPA));
    // dprintf(0, "RTC PTR 0x%p\n", rtc_ptr);

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

    sw_id = romfile_loadstring_to_int("opt/hostid",
                        current_machine->pdc_model.sw_id);
    if (sw_id != current_machine->pdc_model.sw_id) {
        current_machine->pdc_model.sw_id = sw_id;
        /* and store in 32-bit machine too */
        machine_B160L.pdc_model.sw_id = sw_id;
    }
    dprintf(0, "fw_cfg: machine hostid %lu\n", sw_id);

    str = romfile_loadfile("/etc/qemu-version", NULL);
    if (str)
        strtcpy(qemu_version, str, sizeof(qemu_version));

    /* Do not initialize PAGE0. We have the boot args stored there. */
    /* memset((void*)PAGE0, 0, sizeof(*PAGE0)); */

    /* copy pdc_entry entry into low memory. */
    i = &pdc_entry_table_end - &pdc_entry_table;
    memcpy((void*)MEM_PDC_ENTRY, &pdc_entry_table, i);
    flush_data_cache((char*)MEM_PDC_ENTRY, i);

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
    PAGE0->pad0[4] = 0x01;  /* reserved for emulated power switch button */
    if (powerswitch_supported())
        *powersw_ptr = 0x01; /* button not pressed, hw controlled. */

    /* PAGE0->imm_hpa - is set later (MEMORY_HPA) */
    PAGE0->imm_spa_size = ram_size;
    PAGE0->imm_max_mem = ram_size;

    /* initialize graphics (if available) */
    if (artist_present()) {
        sti_rom_init();
        sti_console_init(&sti_proc_rom);
        PAGE0->proc_sti = (uintptr_t)&sti_proc_rom;
        if (has_astro)
            kbd_init();
        else
            ps2port_setup();
    } else {
        remove_from_keep_list(LASI_GFX_HPA);
        remove_from_keep_list(LASI_PS2KBD_HPA);
        remove_from_keep_list(LASI_PS2MOU_HPA);
    }

    /* Initialize device list */
    keep_add_generic_devices();
    remove_parisc_devices(smp_cpus);

    add_index_all_devices();
    /* Show list of HPA devices which are still returned by firmware. */
    if (0) {
        hppa_device_t *dev;
        unsigned long hpa;
        for (i=0; parisc_devices[i].hpa; i++) {
            dev = &parisc_devices[i];
            hpa = dev->hpa;
            printf("Kept #%d at 0x%lx %s  parent_hpa 0x%lx index %d\n", i, hpa, hpa_name(hpa), dev->hpa_parent, dev->index );
        }
    }

    // Initialize stable storage
    init_stable_storage();

    chassis_code = 0;

    cpu_hz = 100 * PAGE0->mem_10msec; /* Hz of this PARISC */
    dprintf(1, "\nPARISC SeaBIOS Firmware, %ld x %d-bit PA-RISC CPU at %d.%06d MHz, %ld MB RAM.\n",
            smp_cpus, cpu_bit_width, cpu_hz / 1000000, cpu_hz % 1000000,
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
    if (has_astro) {
        iosapic_table_setup();
    }
    hppa_pci_build_devices_list();

    /* find serial PCI card when running on Astro */
    find_serial_pci_card();

    serial_setup();
    // usb_setup();
    // ohci_setup();
    block_setup();

    /* find SCSI PCI card when running on Astro or Dino */
    find_scsi_pci_card();

    // Initialize boot paths (graphics & keyboard)
    if (pdc_console != CONSOLE_SERIAL) {
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

    PAGE0->vec_rendz = 0; /* No rendezvous yet. Add MEM_RENDEZ_HI later */

    printf("\n");
    printf("SeaBIOS PA-RISC %d-bit Firmware Version " SEABIOS_HPPA_VERSION_STR
           " (QEMU %s)\n\n"
            "Duplex Console IO Dependent Code (IODC) revision " SEABIOS_HPPA_VERSION_STR "\n"
            "\n", is_64bit_PDC() ? 64 : 32, qemu_version);
    printf("------------------------------------------------------------------------------\n"
            "  (c) Copyright 2017-2024 Helge Deller <deller@gmx.de> and SeaBIOS developers.\n"
            "------------------------------------------------------------------------------\n\n");
    printf( "  Processor   Speed            State           Coprocessor State  Cache Size\n"
            "  ---------  --------   ---------------------  -----------------  ----------\n");
    for (i = 0; i < smp_cpus; i++)
        printf("     %s%d      " __stringify(CPU_CLOCK_MHZ)
                " MHz    %s                 Functional            0 KB\n",
                i < 10 ? " ":"", i, i?"Idle  ":"Active");
    printf("\n\n");
    printf("  Emulated machine:     HP %s (%d-bit %s), %d-bit PDC%s%s\n"
            "  Available memory:     %lu MB\n"
            "  Good memory required: %d MB\n\n",
            qemu_machine, cpu_bit_width, is_64bit_CPU() ? "PA2.0" : "PA1.1",
            is_64bit_PDC() ? 64 : 32,
            enable_OS64 & PDC_MODEL_OS32 ? ", OS32":"",
            enable_OS64 & PDC_MODEL_OS64 ? ", OS64":"",
            ram_size/1024/1024, MIN_RAM_SIZE/1024/1024);

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
    // find_pci_slot_for_dev(PCI_VENDOR_ID_LSI_LOGIC, &mod_path_emulated_drives.path.bc[5]);

    // Store initial emulated drives path master data
    if (parisc_boot_harddisc) {
        mod_path_emulated_drives.layers[0] = parisc_boot_harddisc->target;
        mod_path_emulated_drives.layers[1] = parisc_boot_harddisc->lun;
    }

    if (prepare_boot_path(&(PAGE0->mem_boot), &mem_boot_boot, 0x0))
        printf("Note: No supported SCSI controller or SCSI boot device found.\n");

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

    /* Qemu-specific: Drop *all* TLB entries for all CPUs before start. */
    /* Necessary if machine was rebooted. */
    asm("pdtlbe %%r0(%%sr1,%%r0)" : : : "memory");

    /* directly start Linux kernel if it was given on qemu command line. */
    if (linux_kernel_entry > 1) {
        unsigned long kernel_entry = linux_kernel_entry;

        printf("Autobooting Linux kernel which was loaded by qemu...\n\n");
	/* zero out kernel entry point in case we reset the machine: */
        linux_kernel_entry = 0;
        start_kernel(PAGE0->mem_free, cmdline, initrd_start, initrd_end,
                kernel_entry);
        hlt(); /* this ends the emulator */
    }

    /* check for bootable drives, and load and start IPL bootloader if possible */
    if (parisc_boot_menu(&iplstart, &iplend, bootdrive)) {
        PAGE0->mem_boot.dp.layers[0] = boot_drive->target;
        PAGE0->mem_boot.dp.layers[1] = boot_drive->lun;

        printf("\nBooting...\n"
                "Boot IO Dependent Code (IODC) revision 153\n\n"
                "%s Booted.\n", PAGE0->imm_soft_boot ? "SOFT":"HARD");
        /* actually: start_ipl(interact_ipl, iplend); */
        start_kernel(interact_ipl, iplend, 0, 0, iplstart);
    }

    hlt(); /* this ends the emulator */
}
