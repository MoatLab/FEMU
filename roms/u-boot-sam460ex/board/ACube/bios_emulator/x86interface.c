#define _STDDEF_H
#include <common.h>
#include "glue.h"
#include "scitech/include/x86emu/x86emu.h"
#include "x86interface.h"
#include "../common/misc_utils.h"

/*
 * This isn't nice, but there are a lot of incompatibilities in the U-Boot and scitech include
 * files that this is the only really workable solution.
 * Might be cleaned out later.
 */

#undef DEBUG
#undef SINGLESTEP
#undef FORCE_SINGLESTEP

#undef IO_LOGGING
#undef MEM_LOGGING

#ifdef IO_LOGGING
#define LOGIO(port, format, args...) if (dolog(port)) printf(format , ## args)
#else
#define LOGIO(port, format, args...)
#endif

#ifdef MEM_LOGGIN
#define LOGMEM(format, args...) printf(format , ## args)
#else
#define LOGMEM(format, args...)
#endif

#define log_printf(format, args...)  if (getenv("x86_log")) printf(format, ## args);

#ifdef DEBUG
#define PRINTF(format, args...) printf(format , ## args)
#else
#define PRINTF(format, argc...)
#endif

typedef unsigned char UBYTE;
typedef unsigned short UWORD;
typedef unsigned long ULONG;

typedef char BYTE;
typedef short WORT;
typedef long LONG;

#define EMULATOR_MEM_SIZE       (1024*1024)
#define EMULATOR_BIOS_OFFSET    0xC0000
#define EMULATOR_STRAP_OFFSET   0x30000
#define EMULATOR_STACK_OFFSET   0x20000
#define EMULATOR_LOGO_OFFSET    0x40000 // If you change this, change the strap code, too

extern int tstc(void);
extern int getc(void);
extern unsigned char video_get_attr(void);
extern void find_radeon_values(pci_dev_t dev, u8 * rom_addr);
extern void reloc_mode_table(void *reloc_addr);

extern int onbus;
extern u32 mmio_base_phys;
extern u32 io_base_phys;

#include "x86interface.h"

extern void bios_set_mode(int mode);
 
void sam440_remove_init_data(void)
{
      
}

void setup_tlb_for_cache(int enable)
{
	// not used anymore
}

//Forward declaration
void do_inout(void);

int abs(int x)
{
    if (x < 0)
       return -x;

    return x;
}

void cons_gets(char *buffer)
{
    int i = 0;
    char c = 0;

    buffer[0] = 0;
    if (getenv("x86_runthru")) return; //FIXME:
    while (c != 0x0D && c != 0x0A)
    {
    	while (!tstc());
    	c = getc();
    	if (c>=32 && c < 127)
    	{
    	    buffer[i] = c;
    	    i++;
    	    buffer[i] = 0;
    	    putc(c);
    	}
    	else
    	{
    	    if (c == 0x08)
    	    {
        		if (i>0) i--;
        		buffer[i] = 0;
    	    }
    	}
    }
    buffer[i] = '\n';
    buffer[i+1] = 0;
}

char *bios_date = "08/14/02";
UBYTE model = 0xFC;
UBYTE submodel = 0x00;

static int log_init = 0;
static int log_do = 0;
static int log_low = 0;

int dolog(int port)
{
    if (log_init && log_do)
    {
    	if (log_low && port > 0x400) return 0;
    	return 1;
    }

    if (!log_init)
    {
    	log_init = 1;
    	log_do = (getenv("x86_logio") != (char *)0);
    	log_low = (getenv("x86_loglow") != (char *)0);
    	if (log_do) 
    	{
    	    if (log_low && port > 0x400) return 0;
    	    return 1;
    	}
    }
    return 0;
}

static u32 dummy;

u32 screen_addr(u32 addr)
{
	return &dummy; 
}

// Converts an emulator address to a physical address.
// Handles all special cases (bios date, model etc), and might need work
u32 memaddr(u32 addr)
{
//    if (addr >= 0xF0000 && addr < 0xFFFFF) printf("WARNING: Segment F access (0x%x)\n", addr);
//    printf("MemAddr=%p\n", addr);
    if (addr >= 0xA0000 && addr < 0xC0000)
    	return screen_addr(addr); //CFG_ISA_IO_BASE_ADDRESS + addr;
    else if (addr >= 0xFFFF5 && addr < 0xFFFFE)
    {
       	return (u32)bios_date+addr-0xFFFF5;
    }
    else if (addr == 0xFFFFE)
	    return (u32)&model;
    else if (addr == 0xFFFFF)
	    return (u32)&submodel;
    else if (addr >= 0x80000000)
    {
    	//printf("Warning: High memory access at 0x%x\n", addr);
	    return addr;
    }
    else
    	return (u32)M.mem_base+addr;
}

u8 A1_rdb(u32 addr)
{
    u8 a = in8((UBYTE *)memaddr(addr));
    LOGMEM("rdb: %x -> %x\n", addr, a);
    return a;
}

u16 A1_rdw(u32 addr)
{
    u16 a = in16r((UWORD *)memaddr(addr));
    LOGMEM("rdw: %x -> %x\n", addr, a);
    return a;
}

u32 A1_rdl(u32 addr)
{
    u32 a = in32r((ULONG *)memaddr(addr));
    LOGMEM("rdl: %x -> %x\n", addr, a);
    return a;
}

void A1_wrb(u32 addr, u8 val)
{
    LOGMEM("wrb: %x <- %x\n", addr, val);
    out8((UBYTE *)memaddr(addr), val);
}

void A1_wrw(u32 addr, u16 val)
{
    LOGMEM("wrw: %x <- %x\n", addr, val);
    out16r((UWORD *)memaddr(addr), val);
}

void A1_wrl(u32 addr, u32 val)
{
    LOGMEM("wrl: %x <- %x\n", addr, val);
    out32r((ULONG *)memaddr(addr), val);
}

static X86EMU_memFuncs _A1_mem;

#define in_byte(from) in8( (UBYTE *)port_to_mem(from))
#define in_word(from) in16r((UWORD *)port_to_mem(from))
#define in_long(from) in32r((ULONG *)port_to_mem(from))
#define out_byte(to, val) out8((UBYTE *)port_to_mem(to), val)
#define out_word(to, val) out16r((UWORD *)port_to_mem(to), val)
#define out_long(to, val) out32r((ULONG *)port_to_mem(to), val)

u32 port_to_mem(int port)
{
#ifdef CONFIG_SAM460EX 
    /* here we assume that a Radeon is on bus 0 (PCI)         */
    /* and a RadeonHD is on bus 1 or higher (PCI or PCI-E)    */
 
    if (onbus >= 1) 
    {	
        if (port >= io_base_phys) port -= io_base_phys;

        return mmio_base_phys + port;
    }    
    else     
    {
        if (port >= 0xcfc && port <= 0xcff) 
            return 0xDEC00004;
        else if (port >= 0xcf8 && port <= 0xcfb) 
            return 0xDEC00000;
            
        return CFG_ISA_IO_BASE_ADDRESS + port; 
    }  
#else
    if (port >= 0xcfc && port <= 0xcff) 
	    return 0xEEC00004;
    else if (port >= 0xcf8 && port <= 0xcfb) 
	    return 0xEEC00000;
	    
	return CFG_ISA_IO_BASE_ADDRESS + port;
#endif
}

u8 A1_inb(int port)
{
    u8 a;
    //if (port == 0x3BA) return 0;
    a = in_byte(port);
    LOGIO(port, "inb: %Xh -> %d (%Xh)\n", port, a, a);
    return a;
}

u16 A1_inw(int port)
{
    u16 a = in_word(port);
    LOGIO(port, "inw: %Xh -> %d (%Xh)\n", port, a, a);
    return a;
}

u32 A1_inl(int port)
{
    u32 a = in_long(port);
    LOGIO(port, "inl: %Xh -> %d (%Xh)\n", port, a, a);
    return a;
}

void A1_outb(int port, u8 val)
{
    LOGIO(port, "outb: %Xh <- %d (%Xh)\n", port, val, val);
/*    if (port == 0xCF8) port = 0xCFB;
    else if (port == 0xCF9) port = 0xCFA;
    else if (port == 0xCFA) port = 0xCF9;
    else if (port == 0xCFB) port = 0xCF8;*/
    
    out_byte(port, val);
}

void A1_outw(int port, u16 val)
{
    LOGIO(port, "outw: %Xh <- %d (%Xh)\n", port, val, val);
    out_word(port, val);
}

int blocked_port = 0;

void A1_outl(int port, u32 val)
{
    LOGIO(port, "outl: %Xh <- %d (%Xh)\n", port, val, val);

    // Workaround
    if (port != blocked_port)
    out_long(port, val);
    else
	LOGIO(port, "blocked\n");
}

static X86EMU_pioFuncs _A1_pio;

static int reloced_ops = 0;

void reloc_ops(void *reloc_addr)
{
    extern void (*x86emu_optab[256])(u8);
    extern void (*x86emu_optab2[256])(u8);
    extern void tables_relocate(unsigned int offset);
    int i;
    unsigned long delta;
    if (reloced_ops == 1) return;
    reloced_ops = 1;

    PRINTF("reloc_addr = %p\n", reloc_addr);
    delta = TEXT_BASE - (unsigned long)reloc_addr;
    PRINTF("delta = %p\n", delta);
    PRINTF("x86emu_optab %p\n",x86emu_optab);
    PRINTF("x86emu_optab %p\n",x86emu_optab-delta);

    for (i=0; i<256; i++)
    {
    	x86emu_optab[i] -= delta;
    	x86emu_optab2[i] -= delta;
    }

    _A1_mem.rdb = A1_rdb;
    _A1_mem.rdw = A1_rdw;
    _A1_mem.rdl = A1_rdl;
    _A1_mem.wrb = A1_wrb;
    _A1_mem.wrw = A1_wrw;
    _A1_mem.wrl = A1_wrl;

    _A1_pio.inb = (u8 (X86APIP)(X86EMU_pioAddr))A1_inb;
    _A1_pio.inw = (u16 (X86APIP)(X86EMU_pioAddr))A1_inw;
    _A1_pio.inl = (u32 (X86APIP)(X86EMU_pioAddr))A1_inl;
    _A1_pio.outb = (void (X86APIP)(X86EMU_pioAddr, u8))A1_outb;
    _A1_pio.outw = (void (X86APIP)(X86EMU_pioAddr, u16))A1_outw;
    _A1_pio.outl = (void (X86APIP)(X86EMU_pioAddr, u32))A1_outl;

    tables_relocate(delta);
}


#define ANY_KEY(text)			\
    printf(text);				\
    while (!tstc());


unsigned char more_strap[] = {
        0xb4, 0x0, 0xb0, 0x2, 0xcd, 0x10,
};
#define MORE_STRAP_BYTES 6 // Additional bytes of strap code


unsigned char *done_msg="VGA Initialized\0";

int execute_bios(pci_dev_t gr_dev, void *reloc_addr)
{
    extern void bios_init(void);
    extern void remove_init_data(void);
    extern int video_rows(void);
    extern int video_cols(void);
    extern int video_size(int, int);
    u8 *strap;
    //unsigned char *logo;
    //u8 cfg;
    int i;
    //char c;
    //char *s;
#ifdef EASTEREGG
    int easteregg_active = 0;
#endif
    char *pal_reset;
    //u8 *fb;
    //unsigned char *msg;
    //unsigned char current_attr;

    PRINTF("Trying to remove init data\n");
    sam440_remove_init_data();
    PRINTF("Removed init data from cache, now in RAM\n");

    reloc_ops(reloc_addr);
    reloc_mode_table(reloc_addr);
    
    PRINTF("Attempting to run emulator on %02x:%02x:%02x\n",
	   PCI_BUS(gr_dev), PCI_DEV(gr_dev), PCI_FUNC(gr_dev));

    // Enable compatibility hole for emulator access to frame buffer
    //PRINTF("Enabling compatibility hole\n");
    //enable_compatibility_hole();

#ifdef DEBUG
/*
    s = getenv("x86_ask_start");
    if (s)
    {
		printf("Press 'q' to skip initialization, 'd' for dry init\n'i' for i/o session");
		while (!tstc());
		c = getc();
		if (c == 'q') return 0;
		if (c == 'd')
		{
		    bios_set_mode(0x03);
		    return 0;
		}
		if (c == 'i') do_inout();
    }
*/
#endif

    // Allocate memory
    // FIXME: We shouldn't use this much memory really.
    memset(&M, 0, sizeof(X86EMU_sysEnv));
    M.mem_base = (unsigned long)malloc(EMULATOR_MEM_SIZE);
    M.mem_size = (unsigned long)EMULATOR_MEM_SIZE;

    if (!M.mem_base)
    {
		PRINTF("Unable to allocate one megabyte for emulator\n");
		return 0;
    }

    if (attempt_map_rom(gr_dev, (void *)(M.mem_base + EMULATOR_BIOS_OFFSET)) == 0)
    {
		PRINTF("Error mapping rom. Emulation terminated\n");
		return 0;
    }


#ifdef EASTEREGG
/*    if (tstc())
    {
	if (getc() == 'c')
	{
	    easteregg_active = 1;
	}
    }
*/
    if (getenv("easteregg"))
    {
		easteregg_active = 1;
    }

    if (easteregg_active)
    {
		// Yay!
		setenv("x86_mode", "1");
		setenv("vga_fg_color", "11");
		setenv("vga_bg_color", "1");
		easteregg_active = 1;
    }
#endif

    strap = (u8*)M.mem_base + EMULATOR_STRAP_OFFSET;
/*
    {
		char *m = getenv("x86_mode");
		if (m)
		{
	    	more_strap[3] = atoi(m);
	    	if (more_strap[3] == 1) video_size(40, 25);
	    	else                    video_size(80, 25);
		}
    }
*/
    /*
     * Poke the strap routine. This might need a bit of extending
     * if there is a mode switch involved, i.e. we want to int10
     * afterwards to set a different graphics mode, or alternatively
     * there might be a different start address requirement if the
     * ROM doesn't have an x86 image in its first image.
     */

    PRINTF("Poking strap...\n");

    // FAR CALL c000:0003
    *strap++ = 0x9A; *strap++ = 0x03; *strap++ = 0x00;
    *strap++ = 0x00; *strap++ = 0xC0;

#if 1
    // insert additional strap code
    for (i=0; i < MORE_STRAP_BYTES; i++)
    {
    	*strap++ = more_strap[i];
    }
#endif
    // HALT
    *strap++ = 0xF4;

    PRINTF("Done poking strap\n");
    
#if 0
    PRINTF("Setting up logo data\n");
    logo = (unsigned char *)M.mem_base + EMULATOR_LOGO_OFFSET;
    for (i=0; i<16; i++)
    {
		*logo++ = 0xFF;
    }
#endif
    /*
     * Setup the init parameters.
     * Per PCI specs, AH must contain the bus and AL
     * must contain the devfn, encoded as (dev<<3)|fn
     */

    PRINTF("Settingup init parameters\n");
    // Execution starts here
    M.x86.R_CS = SEG(EMULATOR_STRAP_OFFSET);
    M.x86.R_IP = OFF(EMULATOR_STRAP_OFFSET);

    // Stack at top of ram
    M.x86.R_SS = SEG(EMULATOR_STACK_OFFSET);
    M.x86.R_SP = OFF(EMULATOR_STACK_OFFSET);

    // Input parameters
    M.x86.R_AH = PCI_BUS(gr_dev);
    M.x86.R_AL = (PCI_DEV(gr_dev)<<3) | PCI_FUNC(gr_dev);

    PRINTF("Setting up I/O and memory access functions\n");
    // Set the I/O and memory access functions
    X86EMU_setupMemFuncs(&_A1_mem);
    PRINTF("PIO\n");
    X86EMU_setupPioFuncs(&_A1_pio);

#if 0 
    // Enable timer 2
    cfg = in_byte(0x61); // Get Misc control
    cfg |= 0x01;         // Enable timer 2
    out_byte(0x61, cfg); // output again

    // Set up the timers
    out_byte(0x43, 0x54);
    out_byte(0x41, 0x18);

    out_byte(0x43, 0x36);
    out_byte(0x40, 0x00);
    out_byte(0x40, 0x00);

    out_byte(0x43, 0xb6);
    out_byte(0x42, 0x31);
    out_byte(0x42, 0x13);
#endif
    
    // If the initializing card is an ATI card, block access to port 0x34
    unsigned short vendor;
    pci_read_config_word(gr_dev, PCI_VENDOR_ID, &vendor);
    if (vendor == 0x1002)
    {
    	PRINTF("Initializing a Radeon, blocking port access\n");
    	int bar;
    	
    	for (bar = PCI_BASE_ADDRESS_0; bar <= PCI_BASE_ADDRESS_5; bar += 4)
    	{
    		unsigned int val;
    		pci_read_config_dword(gr_dev, bar, &val);
    		if (val & PCI_BASE_ADDRESS_SPACE_IO)
    		{
    			blocked_port = val & PCI_BASE_ADDRESS_IO_MASK;
    			blocked_port += 0x34;
    			break;
    		}
    	}
    }
    else    
    	blocked_port = 0;
	PRINTF("Blocked port %x\n",blocked_port);
	    
    // Init the "BIOS".
    PRINTF("BIOS init\n");
    bios_init();
    // Video Card Reset
    PRINTF("Video card reset\n");
    //    out_byte(0x3D8, 0);
    //    out_byte(0x3B8, 1);
    //    (void)in_byte(0x3BA);
    //    (void)in_byte(0x3DA);
    //    out_byte(0x3C0, 0);
    //    out_byte(0x61, 0xFC);
    PRINTF("Done resetting\n");
#if defined(DEBUG) && defined(SINGLESTEP)
#ifndef FORCE_SINGLESTEP
    s = _getenv("x86_singlestep");
    if (s && strcmp(s, "on")==0)
    {
#endif
		PRINTF("Enabling single stepping for debug\n");
		X86EMU_trace_on();
#ifndef FORCE_SINGLESTEP
    }
#endif
#endif

#ifdef DEBUG
//	icache_disable();
//    dcache_disable();
#endif
    // Ready set go...
    PRINTF("Running emulator\n");
    setup_tlb_for_cache(1);
    X86EMU_exec();
    setup_tlb_for_cache(0);
    //	find_radeon_values(gr_dev, (u8 *)(M.mem_base + EMULATOR_BIOS_OFFSET));
    PRINTF("Done running emulator\n");

/* FIXME: Remove me */
    pal_reset = getenv("x86_palette_reset");
    if (pal_reset && strcmp(pal_reset, "on") == 0)
    {
	PRINTF("Palette reset\n");
	//(void)in_byte(0x3da);
	//out_byte(0x3c0, 0);

	out_byte(0x3C8, 0);
	out_byte(0x3C9, 0);
	out_byte(0x3C9, 0);
	out_byte(0x3C9, 0);
	for (i=0; i<254; i++)
	{
	    out_byte(0x3C9, 63);
	    out_byte(0x3C9, 63);
	    out_byte(0x3C9, 63);
	}

	out_byte(0x3c0, 0x20);
    }
/* FIXME: remove me */
#ifdef EASTEREGG
    if (easteregg_active)
    {
	extern void video_easteregg(void);
	video_easteregg();
    }
#endif
/*
    current_attr = video_get_attr();
    fb = (u8 *)VIDEO_BASE;
    for (i=0; i<video_rows()*video_cols()*2; i+=2)
    {
	*(fb+i) = ' ';
	*(fb+i+1) = current_attr;
    }

    fb = (u8 *)VIDEO_BASE + (video_rows())-1*(video_cols()*2);
    for (i=0; i<video_cols(); i++)
    {
	*(fb + 2*i)     = 32;
	*(fb + 2*i + 1) = 0x17;
    }

    msg = done_msg;
    while (*msg)
    {
	*fb = *msg;
	fb  += 2;
	msg ++;
    }
*/
#ifdef DEBUG
    //if (getenv("x86_do_inout")) do_inout();
#endif
	
    return 1;
}

// Clean up the x86 mess
void shutdown_bios(void)
{
//    disable_compatibility_hole();
    // Free the memory associated
//    free(M.mem_base);
//    setup_tlb_for_cache(0);
}

int to_int(char *buffer)
{
    int base = 0;
    int res  = 0;

    if (*buffer == '$') 
    {
	base = 16;
	buffer++;
    }
    else base = 10;

    for (;;)
    {
	switch(*buffer)
	{
	case '0' ... '9':
	    res *= base;
	    res += *buffer - '0';
	    break;
	case 'A':
	case 'a':
	    res *= base;
	    res += 10;
	    break;
	case 'B':
	case 'b':
	    res *= base;
	    res += 11;
	    break;	    
	case 'C':
	case 'c':
	    res *= base;
	    res += 12;
	    break;	    
	case 'D':
	case 'd':
	    res *= base;
	    res += 13;
	    break;	    
	case 'E':
	case 'e':
	    res *= base;
	    res += 14;
	    break;
	case 'F':
	case 'f':
	    res *= base;
	    res += 15;
	    break;	
	default:
	    return res;
	}
	buffer++;
    }
    return res;
}
/*
void one_arg(char *buffer, int *a)
{
    while (*buffer && *buffer != '\n')
    {
	if (*buffer == ' ') buffer++;
	else break;
    }

    *a = to_int(buffer);
}

void two_args(char *buffer, int *a, int *b)
{
    while (*buffer && *buffer != '\n')
    {
	if (*buffer == ' ') buffer++;
	else break;
    }

    *a = to_int(buffer);

    while (*buffer && *buffer != '\n')
    {
	if (*buffer != ' ') buffer++;
	else break;
    }

    while (*buffer && *buffer != '\n')
    {
	if (*buffer == ' ') buffer++;
	else break;
    }

    *b = to_int(buffer);
}
*/
/*
void do_inout(void)
{
    char buffer[256];
    char *arg1;
    //char *arg2;
    int a,b;

    printf("In/Out Session\nUse 'i[bwl]' for in, 'o[bwl]' for out and 'q' to quit\n");

    do
    {
	cons_gets(buffer);
	printf("\n");

	arg1 = buffer;
	while (*arg1 != ' ' ) arg1++;
	while (*arg1 == ' ') arg1++;

	if (buffer[0] == 'i')
	{
	    one_arg(buffer+2, &a);
	    switch (buffer[1])
	    {
	    case 'b':
		printf("in_byte(%xh) = %xh\n", a, A1_inb(a));
		break;
	    case 'w':
		printf("in_word(%xh) = %xh\n", a, A1_inw(a));
		break;
	    case 'l':
		printf("in_dword(%xh) = %xh\n", a, A1_inl(a));
		break;
	    default:
		printf("Invalid length '%c'\n", buffer[1]);
		break;
	    }
	}
	else if (buffer[0] == 'o')
	{
	    two_args(buffer+2, &a, &b);
	    switch (buffer[1])
	    {
	    case 'b':
		printf("out_byte(%d, %d)\n", a, b);
		A1_outb(a,b);
		break;
	    case 'w':
		printf("out_word(%d, %d)\n", a, b);
		A1_outw(a, b);
		break;
	    case 'l':
		printf("out_long(%d, %d)\n", a, b);
		A1_outl(a, b);
		break;
	    default:
		printf("Invalid length '%c'\n", buffer[1]);
		break;
	    }
	} else if (buffer[0] == 'q') return;
    } while (1);
}

#include <command.h>

void do_vmode(cmd_tbl_t *cmdtp, int flag, int argc, char *argv[])
{
	if (argc != 2)
	{
		printf("Usage: %s\n", cmdtp->usage);
		return;
	}

	int mode = simple_strtoul(argv[1], NULL, 16);
	bios_set_mode(mode);
}
U_BOOT_CMD( vmode,      
		2,      0,      do_vmode,  
		"vmode - set vga mode\n", 
		"set vga mode\n");

typedef unsigned long uint32;
// TLB definitions
typedef struct tlb440
{
	// Word 0
	uint32 	EPN:22;		// Effective page number
	uint32	V:1;		// Entry valid
	uint32	TS:1;		// Translation space
	uint32	SIZE:4;		// Size, see below
	uint32	TPAR:4;		// Tag parity
	
	// Word 1
	uint32	RPN:22;		// Real (physical) page number
	uint32	PAR1:2;		// Parity
	uint32	RES1:4;		// Unused		
	uint32	ERPN:4;		// Extended real page number, for 36 bit memory addressing
	
	// Word 2
	uint32	PAR2:2;		// Parity
	uint32	RES2:14;	// Unused
	uint32	U03:4;		// Bits U0 - U3
	uint32	WIMG:4;		// Memory attributes
	uint32	E:1;		// Endian flag
	uint32	RES3:1;		// Unused
	uint32	XWRXWR:6;	// Protection bits
} tlb440_t;

void do_tlb(void)
{
	int i;
	uint32 tlba[3];
	tlb440_t *tlb = (tlb440_t *)tlba;
	
	printf("\nDump of all active TLB's\n");
	
	for (i = 0; i < 64; i++)
	{
		__asm volatile("tlbre	%0, %3, 0			\n\
						tlbre	%1, %3, 1			\n\
						tlbre	%2, %3, 2"
					: "=r" (tlba[0]), "=r" (tlba[1]), "=r" (tlba[2])
					: "r" (i));
		if (tlb->V)
		{
			printf("TLB %2d: EPN = %p TS = %d, SIZE = %d\n", i, tlb->EPN, tlb->TS, tlb->SIZE);
			printf("        RPN = %p, WIMG = 0x%x XWRXWR = 0x%x\n", tlb->RPN, tlb->WIMG, tlb->XWRXWR);
			printf("        (Maps %p to %p)\n", tlb->EPN << 10, tlb->RPN << 10);
		}
	}
} 

U_BOOT_CMD( tlb,      1,      0,      do_tlb,  "tlb - dump all tlbs\n", "dump all tlbs\n");
*/
