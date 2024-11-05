/*
 * (C) Copyright 2001-2004
 * Stefan Roese, esd gmbh germany, stefan.roese@esd-electronics.com
 *
 * (C) Copyright 2005
 * Stefan Roese, DENX Software Engineering, sr@denx.de.
 *
 * (C) Copyright 2006-2007
 * Matthias Fuchs, esd GmbH, matthias.fuchs@esd-electronics.com
 *
 * (C) Copyright 2009-2010
 * Max Tretene, ACube Systems Srl. mtretene@acube-systems.com.
 *
 * See file CREDITS for list of people who contributed to this
 * project.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

#include <common.h>
#include <asm/processor.h>
#include <command.h>
#include <malloc.h>
#include <pci.h>
#include <video_fb.h>
#include <sm501.h>

#ifdef CONFIG_VIDEO_SM502

DECLARE_GLOBAL_DATA_PTR;

#define SWAP32(x)	 ((((x) & 0x000000ff) << 24) | (((x) & 0x0000ff00) << 8)|\
			  (((x) & 0x00ff0000) >>  8) | (((x) & 0xff000000) >> 24) )

#ifdef CONFIG_VIDEO_SM501_8BPP
#define BPP	8
#endif

#define read8(ptrReg)                \
    *(volatile unsigned char *)(sm501.isaBase + ptrReg)

#define write8(ptrReg,value) \
    *(volatile unsigned char *)(sm501.isaBase + ptrReg) = value

#define read16(ptrReg) \
    (*(volatile unsigned short *)(sm501.isaBase + ptrReg))

#define write16(ptrReg,value) \
    (*(volatile unsigned short *)(sm501.isaBase + ptrReg) = value)

#define read32(ptrReg) \
    (*(volatile unsigned int *)(sm501.isaBase + ptrReg))

#define write32(ptrReg, value) \
    (*(volatile unsigned int *)(sm501.isaBase + ptrReg) = value)

GraphicDevice sm501;

#define DISPLAY_WIDTH   640
#define DISPLAY_HEIGHT  480

static const SMI_REGS init_regs_640x480[] = {
    {0x00004, SWAP32(0x00000000)},
    /* clocks for pm0... */
    {0x00040, SWAP32(0x0002184f)},
    {0x00044, SWAP32(0x091a0a01)}, /* 24 MHz pixclk */
    {0x00054, SWAP32(0x00000000)},
    /* clocks for pm1... */
    {0x00048, SWAP32(0x0002184f)},
    {0x0004C, SWAP32(0x091a0a01)},
    {0x00054, SWAP32(0x00000001)},
    /* panel control regs... */
    {0x80004, SWAP32(0xc428bb17)},
    {0x8000C, SWAP32(0x00000000)},
    {0x80010, SWAP32(0x02800280)},
    {0x80014, SWAP32(0x02800000)},
    {0x80018, SWAP32(0x01e00000)},
    {0x8001C, SWAP32(0x00000000)},
    {0x80020, SWAP32(0x01e00280)},
    {0x80024, SWAP32(0x02fa027f)},
    {0x80028, SWAP32(0x004a0280)},
    {0x8002C, SWAP32(0x020c01df)},
    {0x80030, SWAP32(0x000201e7)},
    {0x80200, SWAP32(0x00010000)},
    {0x00008, SWAP32(0x20000000)}, /* gpio29 is pwm0, LED_PWM */
    {0x0000C, SWAP32(0x3f000000)}, /* gpio56 - gpio61 as flat panel data pins */
    {0x10020, SWAP32(0x25725728)}, /* 20 kHz pwm0, 50 % duty cycle, disabled */
    {0x80000, SWAP32(0x0f013104)}, /* panel display control: 8 bit indexed mode */
    {0x800F0, SWAP32(0x00000000)}, /* hardware sprite off */
    {0x80040, SWAP32(0x00000000)}, /* video layer off */
    /* Drawing Engine...                                                    */
    /* Contrary to what said in the datasheet the Drawing Engine registers  */
    /* are NOT initialized to ZERO at power-up, this lead to strange visual */
    /* bugs under Linux and AmigaOS4.1 for example                          */
    {0x100000, 0},
    {0x100004, 0},
    {0x100008, 0},
    {0x10000c, 0},
    {0x100010, 0},
    {0x100014, 0},
    {0x100018, 0},
    {0x10001c, 0},
    {0x100020, 0},
    {0x100024, 0},
    {0x100028, 0},
    {0x10002c, 0},
    {0x100030, 0},        
    {0x100034, 0},
    {0x100038, 0},
    {0x10003c, 0},
    {0x100040, 0},
    {0x100044, 0},
    {0x100048, 0},
    {0x10004c, 0},
    {0x100050, 0},
    {0, 0}
};

/*
 * Returns SM501 register base address. First thing called in the driver.
 */
unsigned int board_video_init (void)
{
	pci_dev_t devbusfn;
	u32 addr;

	/*
	 * Is SM501 connected (ppc221/ppc231)?
	 */
	devbusfn = pci_find_device(PCI_VENDOR_SM, PCI_DEVICE_SM501, 0);
	if (devbusfn != -1) {
		pci_read_config_dword(devbusfn, PCI_BASE_ADDRESS_1, (u32 *)&addr);
		return (addr & 0xfffffffe);
	}

	return 0;
}

/*
 * Returns SM501 framebuffer address
 */
unsigned int board_video_get_fb (void)
{
	pci_dev_t devbusfn;
	u32 addr;

	/*
	 * Is SM501 connected (ppc221/ppc231)?
	 */
	devbusfn = pci_find_device(PCI_VENDOR_SM, PCI_DEVICE_SM501, 0);
	if (devbusfn != -1) {
		pci_read_config_dword(devbusfn, PCI_BASE_ADDRESS_0, (u32 *)&addr);
		addr &= 0xfffffffe;
#ifdef CONFIG_VIDEO_SM501_FBMEM_OFFSET
		addr += CONFIG_VIDEO_SM501_FBMEM_OFFSET;
#endif
		return addr;
	}

	return 0;
}

/*
 * Called after initializing the SM501 and before clearing the screen.
 */
void board_validate_screen (unsigned int base)
{
}

/*
 * Return a pointer to the initialization sequence.
 */
const SMI_REGS *board_get_regs (void)
{
	return init_regs_640x480;
}

int board_get_width (void)
{
	return 640;
}

int board_get_height (void)
{
	return 480;
}

/*-----------------------------------------------------------------------------
 * SmiSetRegs --
 *-----------------------------------------------------------------------------
 */
static void SmiSetRegs (void)
{
	/*
	 * The content of the chipset register depends on the board (clocks,
	 * ...)
	 */
	const SMI_REGS *preg = board_get_regs ();
	while (preg->Index) {
		write32 (preg->Index, preg->Value);
		/*
		 * Insert a delay between
		 */
		udelay (1000);
		preg ++;
	}
}

/*-----------------------------------------------------------------------------
 * video_hw_init --
 *-----------------------------------------------------------------------------
 */
void *video_hw_init (void)
{
	unsigned int *vm, i;

	memset (&sm501, 0, sizeof (GraphicDevice));

	/*
	 * Initialization of the access to the graphic chipset Retreive base
	 * address of the chipset (see board/RPXClassic/eccx.c)
	 */
	if ((sm501.isaBase = board_video_init ()) == 0) {
		return (NULL);
	}

	if ((sm501.frameAdrs = board_video_get_fb ()) == 0) {
		return (NULL);
	}

	sm501.winSizeX = board_get_width ();
	sm501.winSizeY = board_get_height ();

#if defined(CONFIG_VIDEO_SM501_8BPP)
	sm501.gdfIndex = GDF__8BIT_INDEX;
	sm501.gdfBytesPP = 1;

#elif defined(CONFIG_VIDEO_SM501_16BPP)
	sm501.gdfIndex = GDF_16BIT_565RGB;
	sm501.gdfBytesPP = 2;

#elif defined(CONFIG_VIDEO_SM501_32BPP)
	sm501.gdfIndex = GDF_32BIT_X888RGB;
	sm501.gdfBytesPP = 4;
#else
#error Unsupported SM501 BPP
#endif

	sm501.memSize = sm501.winSizeX * sm501.winSizeY * sm501.gdfBytesPP;

	/* Load Smi registers */
	SmiSetRegs ();

	/* (see board/RPXClassic/RPXClassic.c) */
	board_validate_screen (sm501.isaBase);

	/* Clear video memory */
	i = sm501.memSize/4;
	vm = (unsigned int *)sm501.frameAdrs;
	while(i--)
		*vm++ = 0;

	return (&sm501);
}

/*-----------------------------------------------------------------------------
 * video_set_lut --
 *-----------------------------------------------------------------------------
 */
void video_set_lut (
	unsigned int index,           /* color number */
	unsigned char r,              /* red */
	unsigned char g,              /* green */
	unsigned char b               /* blue */
	)
{
	unsigned long value = 0;
	//unsigned char tt = index;
	
	value = (r << 16) | (g << 8) | b;
	
	// using a gray palette
	//value = (tt << 16) | (tt << 8) | tt;
		
	write32 ((index*4) + 0x80400, SWAP32(value));	
}

#endif /* CONFIG_VIDEO_SM502 */
