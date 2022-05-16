/*
 * (C) Copyright 2003
 *
 * Thomas Frieden (ThomasF@hyperion-entertainment.com)
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
 *
 */
#include <common.h>
#include <asm/processor.h>
#include <asm/string.h>
#include <devices.h>
#include <pci.h>
#include "memio.h"
#include "catweasel.h"
#include "cw4.h"
#include "../menu/menu.h"

#define CATW_PCI_VENDOR		0xe159
#define CATW_PCI_PRODUCT	0x0001

#define CATW4_SUBSYS_VENDOR	0x5213
#define CATW4_SUBSYS_ID1	0x0002
#define CATW4_SUBSYS_ID2	0x0003

#define CATW_KEY_DATA		0xd0
#define CATW_KEY_STATUS		0xd4

#define CATW_KS_READY		0x80

#define CATW_NAME			"amikbd"

#define CATW4_FILEID		FileID('C','A','T','4')

#undef CATW_DEBUG
#ifdef	CATW_DEBUG
#define	dprintf(fmt,args...)	printf (fmt ,##args)
#else
#define dprintf(fmt,args...)
#endif

int catw_getc(void);
int catw_testc(void);

static int catw_pci = -1;
static unsigned long catw_iobase = 0;

static int catw_poll_delay = 20000;

static char catw_shift_state = 0;

static unsigned char catw_normal_xlate[0x70] =
{          /*  0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F */
/* 00 - 0F */ '`','1','2','3','4','5','6','7','8','9','0','ß','\'','\\',0, '0',
/* 10 - 1F */ 'q','w','e','r','t','z','u','i','o','p','ü','+', 0 ,'1','2','3',
/* 20 - 2F */ 'a','s','d','f','g','h','j','k','l','ö','ä','#', 0 ,'4','5','6',
/* 30 - 3F */ '<','y','x','c','v','b','n','m',',','.','-', 0 , 0 ,'7','8','9',
/* 40 - 4F */ ' ', 8 , 9 , 13, 13, 27,127, 0 , 0 , 0 ,'-', 0 , 0 , 0 , 0 , 0 ,
/* 50 - 5F */  0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 ,'[',']','/','*','+', 0 ,
/* 60 - 6F */  0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
};

static unsigned char catw_shifted_xlate[0x70] =
{          /*  0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F */
/* 00 - 0F */ '~','!','"','§','$','%','&','/','(',')','=','?','`','|', 0, '0',
/* 10 - 1F */ 'Q','W','E','R','T','Z','U','I','O','P','Ü','*', 0 ,'1','2','3',
/* 20 - 2F */ 'A','S','D','F','G','H','J','K','L','Ö','Ä','^', 0 ,'4','5','6',
/* 30 - 3F */ '>','Y','X','C','V','B','N','M',';',':','_', 0 , 0 ,'7','8','9',
/* 40 - 4F */ ' ', 8 , 9 , 13, 13, 27,127, 0 , 0 , 0 ,'-', 0 , 0 , 0 , 0 , 0 ,
/* 50 - 5F */  0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 ,'{','}','/','*','+', 0 ,
/* 60 - 6F */  0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
};

//"

#define CATW_BUFFER_SIZE 20
static unsigned char catw_buffer[CATW_BUFFER_SIZE];
static int catw_inptr = 0, catw_outptr = 0;

void catw_handle(int c)
{
	int kup = (c&0x80);
	int key = (c&0x7f);
	
	switch (key)
	{
		case 0x60:
		case 0x61:
		case 0x62:
			if (kup)
				catw_shift_state = 0;
			else
				catw_shift_state = 1;
			break;
		case 0x78:
			/* Reset */
			dprintf("Reset!\n");
			break;
	}
}

int catw_xlate(int c)
{
	c &= 0x7f;
	
	switch(c)
	{
	case 0x4C:
		return KEY_PREV_ITEM;
	case 0x4D:
		return KEY_NEXT_ITEM;
	case 0x4E:
		return KEY_NEXT_OPTION;
	case 0x4F:
		return KEY_PREV_OPTION;
	default:
		if (catw_shift_state)
			return catw_shifted_xlate[c];
		else
			return catw_normal_xlate[c];
	}
}

static int catw_fpga_ready(void)
{
	if ((in_byte(catw_iobase + 0x07) & 8) == 8) return 1;
	else return 0;
}

static int catw_config_done(void)
{
	if ((in_byte(catw_iobase + 0x07) & 4) == 4) return 1;
	else return 0;
}

static void catw_reset_fpga(void)
{
	dprintf("Resetting fpga...\n");
	out_byte(catw_iobase + 0x02, 227);
	out_byte(catw_iobase + 0x03, 0);
	udelay(1000);
	out_byte(catw_iobase + 0x03, 65);
	dprintf("Done\n");
}

static void *catw_get_config(uint32 *size)
{
	*size = 59215;
	return &cw4[0];
}

static int catw_program_fpga_config(void)
{
	uint32 length;
	uint8 b;
	int i;
	int try;
	uint8 *config = (uint8*)catw_get_config(&length);
	
	if (!config)
	{
		dprintf("Couldn't find core config\n");
		return 0;
	}
	
	#ifdef CATW_DEBUG
	dprintf("Found a config string of %d bytes\n", length);
	dprintf("starting with...\n");
	{
		int i;
		for (i=0; i<40; i++)
		{
			dprintf("%02x ", *(config+i));
		}
		dprintf("\n");
		dprintf("...\n");
		
		for (i=0; i<40; i++)
		{
			dprintf("%02x ", *(config+length-40+i));
		}
		dprintf("\n");
	}
	#endif
	
	for (i=0; i<length-1; i++)
	{
		b = *(config+i);
		try = 0;
		
		if ((b & 0x01) == 0x01)
			out_byte(catw_iobase + 0x03, 0x43);
		else
			out_byte(catw_iobase + 0x03, 0x41);
		
		while (catw_fpga_ready() == 0) 
		{
			udelay(2000);
			try++;
			dprintf("waiting for FPGA (try = %d)\n", try);
			if (try == 10)
			{
				dprintf("PANIC: FPGA failed on catw_fpga_ready()\n");
				dprintf("at byte offset %d\n", i);
				dprintf("byte written was %02x\n", b);
				return 0;
			}
		}
		
		out_byte(catw_iobase + 0xc0, b);
	}
	
	return 1;
}
	

int catw_kb_init(void)
{
	int i;
	device_t catw_kbddev;
	int error;
	char *s;
	uint16 subsys_vendor, subsys_device;

	/* Some init */
	catw_shift_state = 0;

	/* Find the device */
	catw_pci = pci_find_device(CATW_PCI_VENDOR, CATW_PCI_PRODUCT, 0);
	if (catw_pci == -1)
	{
		dprintf("No Catweasel controller (0x%0x4, 0x%04x) attached\n", CATW_PCI_VENDOR, CATW_PCI_PRODUCT);
		return -1;
	}
	
	/* Get IO base */
	for (i = 0; i < 6; i++)
	{
		pci_read_config_dword(catw_pci, PCI_BASE_ADDRESS_0+4*i, (u32 *)&catw_iobase);
		if (catw_iobase & 1)
		{
			/* Found the IO base */
			break;
		}
	}
	
	/* Check the iobase */
	if (catw_iobase & 1)
	{
		catw_iobase &= ~1;
		dprintf("I/O base: %p\n", (u32 *)catw_iobase);
	}
	else
	{
		printf("Error: Unable to find I/O address range\n");
		return -1;
	}
	
	pci_read_config_word(catw_pci, PCI_SUBSYSTEM_VENDOR_ID, &subsys_vendor);
	pci_read_config_word(catw_pci, PCI_SUBSYSTEM_ID, &subsys_device);
	
	if (subsys_vendor == CATW4_SUBSYS_VENDOR && 
	   ((subsys_device == CATW4_SUBSYS_ID1) || (subsys_device == CATW4_SUBSYS_ID1)))
	{
		dprintf("Catweasel Mark IV detected\n");
		/* Send Mark IV initialisation sequence */
		out_byte(catw_iobase + 0x00, 0xF1);
		out_byte(catw_iobase + 0x01, 0x00);
		out_byte(catw_iobase + 0x02, 0xE3);
		out_byte(catw_iobase + 0x03, 0x41);
		out_byte(catw_iobase + 0x04, 0x00);
		out_byte(catw_iobase + 0x05, 0x00);
		out_byte(catw_iobase + 0x29, 0x00);
		out_byte(catw_iobase + 0x2B, 0x00);
		
		#ifdef CATW_DEBUG
		if (catw_config_done())
			dprintf("FPGA already configured\n");
		else
			dprintf("FPGA Empty\n");
		#endif
		
		catw_reset_fpga();
		if (catw_config_done())
		{
			printf("**PANIC** FPGA reset failed\n");
			return -1;
		}
		#ifdef CATW_DEBUG
		else
		{
			dprintf("FPGA reset OK\n");
		}
		#endif
		
		if (0 == catw_program_fpga_config())
		{
			printf("**ERROR** FPGA Programming failed\n");
			return -1;
		}
		
		if (catw_config_done())
		{
			printf("Catweasel Mark IV configured\n\n");
		}
		else
		{
			printf("**ERROR** Catweasel Mark IV configuration failed\n");
			return -1;
		}
		udelay(1000);
	}
	/* Catweasel mark III cannot work on Sam
	 * it's a +5V only PCI card...
	else
	{
		dprintf("Catweasel Mark III detected\n");
		// Send initialisation sequence for Mark III
		out_byte(catw_iobase + 0x00, 0xf1);
		out_byte(catw_iobase + 0x01, 0x00);
		out_byte(catw_iobase + 0x02, 0x00);
		out_byte(catw_iobase + 0x04, 0x00);
		out_byte(catw_iobase + 0x05, 0x00);
		out_byte(catw_iobase + 0x29, 0x00);
		out_byte(catw_iobase + 0x2b, 0x00);
	}
	*/
	
	out_byte(catw_iobase + CATW_KEY_DATA, 0);
	
	/* Register us as a possible keyboard device */
	memset(&catw_kbddev, 0, sizeof(catw_kbddev));
	strcpy(catw_kbddev.name, CATW_NAME);
	catw_kbddev.flags =  DEV_FLAGS_INPUT | DEV_FLAGS_SYSTEM;
  	catw_kbddev.putc = NULL;
	catw_kbddev.puts = NULL;
	catw_kbddev.getc = catw_getc;
	catw_kbddev.tstc = catw_testc;
	
	s = getenv("catw_poll_delay");
	if (s) 
	{
		catw_poll_delay = simple_strtol(s, NULL, 0) * 1000;
	}

	error = device_register(&catw_kbddev);
	if (0 == error )
	{
		/* Check if we are stdin */
		if (0 == strcmp(getenv("stdin"), CATW_NAME))
		{
			if (overwrite_console())
				return 1;
				
			error = console_assign(stdin,CATW_NAME);
			if (0 == error)
			{
				dprintf("Catweasel keyboard initialized 1\n");
				return 1;
			}
			else
			{
				dprintf("Catweasel keyboard initialized 2\n");
				return error;
			}
		}

		dprintf("Catweasel keyboard initialized 3\n");
		return 1;
	}
	
	return error;
}

static void catw_push(unsigned char c)
{
	if (catw_inptr == CATW_BUFFER_SIZE-1)
	{
		if (catw_outptr == 0) return;
		catw_inptr = 0;
	}
	else if (catw_inptr + 1 == catw_outptr)
	{
		return;
	}
	
	catw_buffer[++catw_inptr] = c;
}

static int catw_pop(void)
{
	if (catw_inptr == catw_outptr) return -1;
	if (catw_outptr >= CATW_BUFFER_SIZE-1)
		catw_outptr = 0;
	else
		++catw_outptr;
		
	return (int)catw_buffer[catw_outptr];
}

static void catw_poll(void)
{
	int x;
	
	x = in_byte(catw_iobase + CATW_KEY_STATUS);

	if (x & CATW_KS_READY)
	{
		x = in_byte(catw_iobase + CATW_KEY_DATA);
		dprintf("got char: %x\n", x);
		catw_handle(x);
		
		if (!(x&0x80))
		{
			x = catw_xlate(x);
			if (x)
			{
				dprintf("xlate: %x\n", x);
				catw_push((unsigned char)x);
			}
		}
		udelay(1000);
		out_byte(catw_iobase + CATW_KEY_DATA, 0);
	}
}
	
int catw_getc(void)
{
	int c;
	
	do
	{
		udelay(catw_poll_delay);
		catw_poll();
		c = catw_pop();
	} while (c == -1);

	return c;
}	
	
unsigned long long get_ticks(void);
unsigned long ticks2usec(unsigned long ticks);

int catw_testc(void)
{
	catw_poll();
	if (catw_inptr == catw_outptr) return 0;
	else return 1;
}
