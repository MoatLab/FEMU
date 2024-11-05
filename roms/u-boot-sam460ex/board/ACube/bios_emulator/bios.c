/*
 * Mostly done after the Scitech Bios emulation
 * Written by Hans-Jörg Frieden
 * Hyperion Entertainment
 */
#include <common.h>
#include "scitech/include/x86emu/x86emu.h"
#include "glue.h"
#include "scitech/include/x86emu/regs.h"
#include "x86interface.h"

#undef DEBUG

#ifdef DEBUG
#define PRINTF(fmt, args...) printf(fmt, ## args)
#else
#define PRINTF(fmt, args...)
#endif

#define BIOS_SEG 0xFFF0
#define PCIBIOS_SUCCESSFUL 0
#define PCIBIOS_DEVICE_NOT_FOUND 0x86

typedef unsigned char UBYTE;
typedef unsigned short UWORD;
typedef unsigned long ULONG;

typedef char BYTE;
typedef short WORT;
typedef long LONG;

//#define port_to_mem(from) (CFG_ISA_IO_BASE_ADDRESS|(from))
/*
#define in_byte(from) in8( (UBYTE *)port_to_mem(from))
#define in_word(from) in16r((UWORD *)port_to_mem(from))
#define in_long(from) in32r(ULONG *)port_to_mem(from))
#define out_byte(to, val) out8((UBYTE *)port_to_mem(to), val)
#define out_word(to, val) out16r((UWORD *)port_to_mem(to), val)
#define out_long(to, val) out32r((ULONG *)port_to_mem(to), val)
*/

#define out_byte(to, val) out8((UBYTE *)port_to_mem(to), val)

static void X86API undefined_intr(int intno)
{
    PRINTF("X86API undefined_intr\n");
    
    extern u16 A1_rdw(u32 addr);
    if (A1_rdw(intno * 4 + 2) == BIOS_SEG)
    {
    	PRINTF("Undefined interrupt 0x%x called AX = 0x%x, BX = 0x%x, CX = 0x%x, DX = 0x%x\n",
    	   intno, M.x86.R_AX, M.x86.R_BX, M.x86.R_CX, M.x86.R_DX);
    	X86EMU_halt_sys();
    }
    else
    {
    	PRINTF("Calling interrupt %xh, AL=%xh, AH=%xh\n", intno, M.x86.R_AL, M.x86.R_AH);
    	X86EMU_prepareForInt(intno);
    }
}

static void X86API int42(int intno);
static void X86API int15(int intno);

static void X86API int10(int intno)
{
    PRINTF("X86API int10\n");

    if (A1_rdw(intno*4+2) == BIOS_SEG)
    	int42(intno);
    else
    {
    	PRINTF("int10: branching to %04X:%04X, AL=%xh, AH=%xh\n", A1_rdw(intno*4+2), A1_rdw(intno*4),
	       M.x86.R_AL, M.x86.R_AH);
    	X86EMU_prepareForInt(intno);
    }
}

static void X86API int1A(int intno)
{
    PRINTF("X86API int1A\n");

    int device;
    
    switch(M.x86.R_AX)
    {
    case 0xB101: // PCI Bios Present?
       	M.x86.R_AL  = 0x00;
    	M.x86.R_EDX = 0x20494350;
    	M.x86.R_BX  = 0x0210;
    	M.x86.R_CL  = 3;
    	CLEAR_FLAG(F_CF);
    	break;
    case 0xB102: // Find device
    	device = mypci_find_device(M.x86.R_DX, M.x86.R_CX, M.x86.R_SI);
    	if (device != -1)
    	{
    	    M.x86.R_AH = PCIBIOS_SUCCESSFUL;
    	    M.x86.R_BH = mypci_bus(device);
    	    M.x86.R_BL = mypci_devfn(device);
    	}
    	else
    	{
    	    M.x86.R_AH = PCIBIOS_DEVICE_NOT_FOUND;
    	}
    	CONDITIONAL_SET_FLAG((M.x86.R_AH != PCIBIOS_SUCCESSFUL), F_CF);
    	break;
    case 0xB103: // Find PCI class code
    	M.x86.R_AH = PCIBIOS_DEVICE_NOT_FOUND;
    	printf("Find by class not yet implmented");
    	CONDITIONAL_SET_FLAG((M.x86.R_AH != PCIBIOS_SUCCESSFUL), F_CF);
    	break;
    case 0xB108: // read config byte
    	M.x86.R_CL = mypci_read_cfg_byte(M.x86.R_BH, M.x86.R_BL, M.x86.R_DI);
    	M.x86.R_AH = PCIBIOS_SUCCESSFUL;
    	CONDITIONAL_SET_FLAG((M.x86.R_AH != PCIBIOS_SUCCESSFUL), F_CF);
    	PRINTF("read_config_byte %x,%x,%x -> %x\n", M.x86.R_BH, M.x86.R_BL, M.x86.R_DI, M.x86.R_CL);
    	break;
    case 0xB109: // read config word
    	M.x86.R_CX = mypci_read_cfg_word(M.x86.R_BH, M.x86.R_BL, M.x86.R_DI);
    	M.x86.R_AH = PCIBIOS_SUCCESSFUL;
    	CONDITIONAL_SET_FLAG((M.x86.R_AH != PCIBIOS_SUCCESSFUL), F_CF);
    	PRINTF("read_config_word %x,%x,%x -> %x\n", M.x86.R_BH, M.x86.R_BL, M.x86.R_DI, M.x86.R_CX);
    	break;
    case 0xB10A: // read config dword
    	M.x86.R_ECX = mypci_read_cfg_long(M.x86.R_BH, M.x86.R_BL, M.x86.R_DI);
    	M.x86.R_AH = PCIBIOS_SUCCESSFUL;
    	CONDITIONAL_SET_FLAG((M.x86.R_AH != PCIBIOS_SUCCESSFUL), F_CF);
    	PRINTF("read_config_long %x,%x,%x -> %x\n", M.x86.R_BH, M.x86.R_BL, M.x86.R_DI, M.x86.R_ECX);
    	break;
    case 0xB10B: // write config byte
    	mypci_write_cfg_byte(M.x86.R_BH, M.x86.R_BL, M.x86.R_DI, M.x86.R_CL);
    	M.x86.R_AH = PCIBIOS_SUCCESSFUL;
    	CONDITIONAL_SET_FLAG((M.x86.R_AH != PCIBIOS_SUCCESSFUL), F_CF);
    	PRINTF("write_config_byte %x,%x,%x <- %x\n", M.x86.R_BH, M.x86.R_BL, M.x86.R_DI, M.x86.R_CL);
    	break;
    case 0xB10C: // write config word
    	mypci_write_cfg_word(M.x86.R_BH, M.x86.R_BL, M.x86.R_DI, M.x86.R_CX);
    	M.x86.R_AH = PCIBIOS_SUCCESSFUL;
    	CONDITIONAL_SET_FLAG((M.x86.R_AH != PCIBIOS_SUCCESSFUL), F_CF);
    	PRINTF("write_config_word %x,%x,%x <- %x\n", M.x86.R_BH, M.x86.R_BL, M.x86.R_DI, M.x86.R_CX);
    	break;
    case 0xB10D: // write config dword
    	mypci_write_cfg_long(M.x86.R_BH, M.x86.R_BL, M.x86.R_DI, M.x86.R_ECX);
    	M.x86.R_AH = PCIBIOS_SUCCESSFUL;
    	CONDITIONAL_SET_FLAG((M.x86.R_AH != PCIBIOS_SUCCESSFUL), F_CF);
    	PRINTF("write_config_long %x,%x,%x <- %x\n", M.x86.R_BH, M.x86.R_BL, M.x86.R_DI, M.x86.R_ECX);
    	break;
    default:
    	PRINTF("BIOS int %xh: Unknown function AX=%04xh\n", intno, M.x86.R_AX);
    }
}

void bios_init(void)
{
    int i;
    X86EMU_intrFuncs bios_intr_tab[256];

    PRINTF("Interrupt table\n");
    for (i=0; i<256; i++)
    {
	    out32r((volatile ULONG *)(M.mem_base+i*4), BIOS_SEG<<16);
	    bios_intr_tab[i] = undefined_intr;
    }

    bios_intr_tab[0x10] = int10;
    bios_intr_tab[0x1A] = int1A;
    bios_intr_tab[0x42] = int42;
    bios_intr_tab[0x15] = int15;

    bios_intr_tab[0x6D] = int42;

    X86EMU_setupIntrFuncs(bios_intr_tab);
    // why here? Because it is needed.
    //PRINTF("video_init\n");
    //video_init();
}

unsigned char setup_40x25[] =
{
    0x38, 0x28, 0x2d, 0x0a, 0x1f, 6, 0x19,
    0x1c, 2, 7, 6, 7, 0, 0, 0, 0
};

unsigned char setup_80x25[] =
{
    0x71, 0x50, 0x5a, 0x0a, 0x1f, 6, 0x19,
    0x1c, 2, 7, 6, 7, 0, 0, 0, 0
};

unsigned char setup_graphics[] =
{
    0x38, 0x28, 0x20, 0x0a, 0x7f, 6, 0x64,
    0x70, 2, 1, 6, 7, 0, 0, 0, 0
};

unsigned char setup_bw[] =
{
    0x61, 0x50, 0x52, 0x0f, 0x19, 6, 0x19,
    0x19, 2, 0x0d, 0x0b, 0x0c, 0, 0, 0, 0
};

unsigned char * setup_modes[] =
{
    setup_40x25,     // mode 0: 40x25 bw text
    setup_40x25,     // mode 1: 40x25 col text
    setup_80x25,     // mode 2: 80x25 bw text
    setup_80x25,     // mode 3: 80x25 col text
    setup_graphics,  // mode 4: 320x200 col graphics
    setup_graphics,  // mode 5: 320x200 bw graphics
    setup_graphics,  // mode 6: 640x200 bw graphics
    setup_bw         // mode 7: 80x25 mono text
};

unsigned int setup_cols[] =
{
    40, 40, 80, 80, 40, 40, 80, 80
};

unsigned char setup_modesets[] =
{
     0x2C, 0x28, 0x2D, 0x29, 0x2A, 0x2E, 0x1E, 0x29
};

unsigned int setup_bufsize[] =
{
    2048, 2048, 4096, 2096, 16384, 16384, 16384, 4096
};

int reloc_mode_done = 0;

void reloc_mode_table(void *reloc_addr)
{
    unsigned long delta;
    int i;
    
    if (reloc_mode_done) 
	return;

    reloc_mode_done = 1;

    PRINTF("reloc_addr = %p\n", reloc_addr);
    delta = TEXT_BASE - (unsigned long)reloc_addr;
    PRINTF("delta = %p\n", delta);

    for (i = 0; i < sizeof(setup_modes)/sizeof(unsigned char *); i++)
	    setup_modes[i] = (unsigned char *) ((unsigned long)setup_modes[i] - delta);
}

void bios_set_mode(int mode)
{
    int i;
    unsigned char mode_set = setup_modesets[mode]; // Control register value
    unsigned char *setup_regs = setup_modes[mode]; // Register 3D4 Array

    flush_cache(0, 32768);

    PRINTF("bios_set_mode: mode = %d, setup_regs = %p\n", mode, setup_regs);
    
    // Switch video off
    out_byte(0x3D8, mode_set & 0x37);

    // Set up parameters at 3D4h
    for (i=0; i<16; i++)
    {
    	out_byte(0x3D4, (unsigned char)i);
	    out_byte(0x3D5,  *setup_regs);
    	setup_regs++;
    }

    // Enable video
    out_byte(0x3D8, mode_set);

    // Set overscan
    if (mode == 6) out_byte(0x3D9, 0x3F);
    else           out_byte(0x3D9, 0x30);

    PRINTF("bios_set_mode: done\n");
}
/*
static void bios_print_string(void)
{
    extern void video_bios_print_string(char *string, int x, int y, int attr, int count);
    //char *s = (char *)(M.x86.R_ES<<4) + M.x86.R_BP;
    int attr;
    if (M.x86.R_AL & 0x02) attr = - 1;
    else                   attr = M.x86.R_BL;
    //video_bios_print_string(s, M.x86.R_DH, M.x86.R_DL, attr, M.x86.R_CX);
}
*/
static void X86API int42(int intno)
{
    PRINTF("int42: AH = 0x%x, AL = 0x%x, AX = 0x%x, BX = 0x%x\n",
		    M.x86.R_AH, M.x86.R_AL, M.x86.R_AX, M.x86.R_BX);

    switch (M.x86.R_AH)
    {
    case 0x00:
	bios_set_mode(M.x86.R_AL);
	break;
    case 0x13:
	//bios_print_string();
	break;
    default:
	PRINTF("Warning: VIDEO BIOS interrupt %xh unimplemented function %xh, AL = %xh\n",
	       intno, M.x86.R_AH, M.x86.R_AL);
	break;
    }
}

static void X86API int15(int intno)
{
    PRINTF("Called interrupt 15h: AX = %xh, BX = %xh, CX = %xh, DX = %xh\n",
	   M.x86.R_AX, M.x86.R_BX, M.x86.R_CX, M.x86.R_DX);
//#if 0
    if (M.x86.R_AX == 0x04e08)
    {
		switch (M.x86.R_BL)
		{
/*	
		    case 0x06:			// Power Management Mode request
			M.x86.R_BL = 0;		// Assume APM
			M.x86.R_AL = 0;
			break;
		
		    case 0x05:			// Get TV standard
				M.x86.R_BX = 0xff;	// Select No TV
				M.x86.R_AL = 0;
				break;
*/		
		    case 0x01:					 // Get Request Display
			    if ((M.x86.R_BH & 0x08) == 0x08)
			    {					
					M.x86.R_BL = 0x08;	// DVI
					M.x86.R_BH = 0;
					M.x86.R_AL = 0;		// supported
					PRINTF("DVI Monitor Found\n");
				}
			
			    if (((M.x86.R_BH & 0x08) == 0x08) || ((M.x86.R_BH & 0x02) == 0x02))
			    {					
					M.x86.R_BL = 0x02;	// CRT
					M.x86.R_BH = 0;
					M.x86.R_AL = 0;		// supported
					PRINTF("CRT Monitor Found\n");
				}

			    if (((M.x86.R_BH & 0x08) == 0x08) || ((M.x86.R_BH & 0x04) == 0x04))
			    {					
					M.x86.R_BL = 0x04;	// CRT 2
					M.x86.R_BH = 0;
					M.x86.R_AX = 0;		// supported
					PRINTF("CRT2 Monitor Found\n");
				}
							
				break;
			
		    default:
				PRINTF("Subfunction %d not implemented\n", M.x86.R_BL);
				M.x86.R_AL = 2;		// Not supported
				break;
		}
		PRINTF("Result: AX = %xh, BX = %xh\n", M.x86.R_AX, M.x86.R_BX);
    }
//#endif
//    // For now, just declare this interrupt as not implemented
//    M.x86.R_AX = 2;    
}
