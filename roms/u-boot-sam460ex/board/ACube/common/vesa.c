#include <common.h>
#include "x86emu/x86emu.h"
#include "../bios_emulator/glue.h"
#include "vesa_code.h"
#include "memio.h"
#include "misc_utils.h"
#include "vesa.h"

#define EMULATOR_STRAP_OFFSET   0x30000
#define EMULATOR_STACK_OFFSET   0x20000
#define EMULATOR_VESA_OFFSET    0x40000
#define EMULATOR_BIOS_OFFSET    0xC0000

extern pci_dev_t video_dev;

typedef short WORD;
typedef unsigned char BYTE;
typedef unsigned long DWORD;

struct MODEINFO {
   // Mandatory information for all VBE revision
   WORD  modeattributes;     // Mode attributes
   BYTE  winaattributes;     // Window A attributes
   BYTE  winbattributes;     // Window B attributes
   WORD  wingranularity;     // Window granularity
   WORD  winsize;    	     // Window size
   WORD  winasegment;        // Window A start segment
   WORD  winbsegment;        // Window B start segment
   DWORD winfuncptr;         // pointer to window function
   WORD  bytesperscanline;   // Bytes per scan line

   // Mandatory information for VBE 1.2 and above
   WORD  xresolution;         // Horizontal resolution in pixel or chars
   WORD  yresolution;         // Vertical resolution in pixel or chars
   BYTE  xcharsize;           // Character cell width in pixel
   BYTE  ycharsize;           // Character cell height in pixel
   BYTE  numberofplanes;      // Number of memory planes
   BYTE  bitsperpixel;        // Bits per pixel
   BYTE  numberofbanks;       // Number of banks
   BYTE  memorymodel;         // Memory model type
   BYTE  banksize;            // Bank size in KB
   BYTE  numberofimagepages;  // Number of images
   BYTE  reserved1;           // Reserved for page function

   // Direct Color fields (required for direct/6 and YUV/7 memory models)
   BYTE  redmasksize;         // Size of direct color red mask in bits
   BYTE  redfieldposition;    // Bit position of lsb of red bask
   BYTE  greenmasksize;       // Size of direct color green mask in bits
   BYTE  greenfieldposition;  // Bit position of lsb of green bask
   BYTE  bluemasksize;        // Size of direct color blue mask in bits
   BYTE  bluefieldposition;   // Bit position of lsb of blue bask
   BYTE  rsvdmasksize;        // Size of direct color reserved mask in bits
   BYTE  rsvdfieldposition;   // Bit position of lsb of reserved bask
   BYTE  directcolormodeinfo; // Direct color mode attributes

   // Mandatory information for VBE 2.0 and above
   DWORD physbaseptr;         // Physical address for flat frame buffer
   DWORD offscreenmemoffset;  // Pointer to start of off screen memory
   WORD  offscreenmemsize;    // Amount of off screen memory in 1Kb units
   char  reserved2[206];      // Remainder of ModeInfoBlock
} __attribute__((packed));

/* WARNING: Must be kept in line with the OS 4 bootloader. */

#define SWAPWORD(x) mi->x = (WORD)read_word_little(&(mi->x))
#define SWAPLONG(x) mi->x = (DWORD)read_long_little(&(mi->x))

unsigned short makemask(int bits, int shift)
{
	unsigned short mask = 0;
	while (bits)
	{
		bits--;
		mask = mask << 1;
		mask = mask | 1;
	}

	if (shift) mask = mask << shift;
	return mask;
}

#define PRFBI(x) printf("%s = %ld (%lx)\n", #x, (unsigned long)fbi->x, (unsigned long)fbi->x)

void fill_fbi(struct MODEINFO *mi, struct FrameBufferInfo *fbi)
{
	int i;
    unsigned char *a;

	fbi->BaseAddress   = (void *)mi->physbaseptr;
	fbi->XSize         = mi->xresolution;
	fbi->YSize         = mi->yresolution;
	fbi->BitsPerPixel  = mi->bitsperpixel;
	fbi->Modulo        = mi->bytesperscanline;

	fbi->RedMask       = makemask(mi->redmasksize, 8-mi->redmasksize);
	fbi->RedShift      = mi->redfieldposition;

	fbi->GreenMask     = makemask(mi->greenmasksize, 8-mi->greenmasksize);
	fbi->GreenShift    = mi->greenfieldposition;

	fbi->BlueMask      = makemask(mi->bluemasksize, 8-mi->bluemasksize);
	fbi->BlueShift     = mi->bluefieldposition;


#if 0
	PRFBI(BaseAddress);
	PRFBI(XSize);
	PRFBI(YSize);
	PRFBI(BitsPerPixel);
	PRFBI(Modulo);
	PRFBI(RedMask);
	PRFBI(RedShift);
	PRFBI(GreenMask);
	PRFBI(GreenShift);
	PRFBI(BlueMask);
	PRFBI(BlueShift);
#endif

#if 0
	a = (unsigned char *)mi->physbaseptr;
    if (!a) return;

    i = mi->bytesperscanline * mi->yresolution;
    while (i)
    {
    	*a = 0;
        i--;
        a++;
    }
#endif
}

void swap_modeinfo(struct MODEINFO *mi)
{
	SWAPWORD(modeattributes);
	SWAPWORD(wingranularity);
	SWAPWORD(winsize);
	SWAPWORD(winasegment);
	SWAPWORD(winbsegment);
	SWAPLONG(winfuncptr);
	SWAPWORD(bytesperscanline);
	SWAPWORD(xresolution);
	SWAPWORD(yresolution);
	SWAPLONG(physbaseptr);
	SWAPLONG(offscreenmemoffset);
	SWAPWORD(offscreenmemsize);
}

#define PRF(x) printf("%s = %ld (%lx)\n", #x, (unsigned long)mi->x, (unsigned long)mi->x)

void print_modeinfo(struct MODEINFO *mi)
{
#if 0
	PRF(modeattributes);
	PRF(winaattributes);
	PRF(winbattributes);
	PRF(wingranularity);
	PRF(winsize);
	PRF(winasegment);
	PRF(winbsegment);
	PRF(winfuncptr);
	PRF(bytesperscanline);
	PRF(xresolution);
	PRF(yresolution);
	PRF(xcharsize);
	PRF(ycharsize);
	PRF(numberofplanes);
	PRF(bitsperpixel);
	PRF(numberofbanks);
	PRF(memorymodel);
	PRF(banksize);
	PRF(numberofimagepages);
	PRF(redmasksize);
	PRF(redfieldposition);
	PRF(greenmasksize);
	PRF(greenfieldposition);
	PRF(bluemasksize);
	PRF(bluefieldposition);
	PRF(directcolormodeinfo);
	PRF(physbaseptr);
	PRF(offscreenmemoffset);
	PRF(offscreenmemsize);
#endif
}

void *set_vesa_mode(int mode)
{
    u8 *strap;
    int i;
    struct MODEINFO *mi = (struct MODEINFO *)(M.mem_base + EMULATOR_VESA_OFFSET);

    char *s;

    code[4] = (unsigned char)mode;
    code[20] = (unsigned char)mode;

	// Execution starts here
    M.x86.R_CS = SEG(EMULATOR_STRAP_OFFSET);
    M.x86.R_IP = OFF(EMULATOR_STRAP_OFFSET);

	// Stack at top of ram
    M.x86.R_SS = SEG(EMULATOR_STACK_OFFSET);
    M.x86.R_SP = OFF(EMULATOR_STACK_OFFSET);

	strap = (u8*)M.mem_base + EMULATOR_STRAP_OFFSET;
    for (i=0; i<code_COUNT; i++)
    {
    	*strap++ = code[i];
    }

	disable_interrupts();
    X86EMU_exec();
    enable_interrupts();

	swap_modeinfo(mi);

	fbi = (struct FrameBufferInfo *)(malloc(sizeof(struct FrameBufferInfo)));
    if (fbi) fill_fbi(mi,fbi);

    return fbi;
}
