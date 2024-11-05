#include <common.h>
#if defined (CONFIG_SAM440EP)
#include <configs/Sam440ep.h>
#elif defined (CONFIG_SAM440EP_FLEX)
#include <configs/Sam440ep_flex.h>
#elif defined (CONFIG_SAM460EX)
#include <configs/Sam460ex.h>
#endif

#include <part.h>
#include <ide.h>
#include <ata.h>
#include <pci.h> //We need the PCI primitives.
#include <malloc.h>

#include "sys_dep.h" //Il marchio di fabbrica.
#include "sam_ide.h"
#include "misc_utils.h"

#ifdef CONFIG_SAM460EX
DECLARE_GLOBAL_DATA_PTR;

#define BOARD_CANYONLANDS_PCIE	1
#define BOARD_CANYONLANDS_SATA	2

block_dev_desc_t sata_dev_desc[CONFIG_SYS_SATA_MAX_DEVICE];
extern ulong sata_read(int device, ulong blknr, lbaint_t blkcnt, void *buffer);
#endif

/*
How to add new IDE boards to this module.
This note explains how to add new controller cards to those supported by 
a1ide.c/UBoot.

To add support for a new IDE controller you need to:
- add a new entry in the controllers[] array.
- write a couple of functions to read from the controllers, one for ATA and 
one for ATAPI.
These are very simple and usually don't need special care, they simply 
forward the call to the generic reading routines.
- write a small function to fetch a unit from those present on the controller;
much like the point above.
- write a function to initialize the controller card.
- add some bits and pieces here and there (all explained below).

Let's start with the big chunk: the controllers[] array. 
It's an array of struct controller_context.
There must be one for every supported controller/chip.
But first, a word from our spon.... no: a word about UBoot!
In "controllers" and elsewhere, it's quite often to find function pointers.
Due to the fact that UBoot gets relocated early during the initialization 
phases, NO function pointer can be used in a static structure
or a static variable of a module!!! So if you plan to use function pointers 
like in controllers, you MUST initialize them at RUN TIME, _NOT COMPILE TIME_!!!

The controller_context sturcture:
BOOL	cc_present: 		
	set this to TRUE during the initialization routine if
	the card was found and it's working.
UBYTE	cc_maxunit: 		
	total number of units that can exists on this controller
UBYTE	cc_maxbus: 			
	total number of different bus that are handled by this 
	controller. Usually 2.
char *cc_maxbus_var: 
	pointer to a string with the environment variable used
	to limit the buses being used/scanned.
BOOL *cc_bus_ok:
	an array of BOOLs, allocated at runtime, length is 
	cc_maxbus: tells which bus have real units.
base_io_address *cc_base_io: 
	array of io_address, allocated at runtime, length is 
	cc_maxbus: base IO addresses for each bus.
block_dev_desc_t * cc_units: 
	array of device descriptors, allocated at runtime, length is cc_maxunit.
char *cc_description: 
	a string defining the controller itself.
unsigned long (* cc_block_read)(): 
	function pointer to the ATA block read routine, see the warning above.
unsigned long (* cc_atapi_read)(): 
	function pointer to the ATAPI block read routine, see the warning above.

Some of these fields will be filled in by the generic part, so you don't have 
to care for them.
What must be supplied by you are:
STATIC (compile-time): cc_maxunit, cc_maxbus, cc_maxbus_var, cc_description.
DYNAMIC (run-time): cc_present, cc_base_io, cc_block_read, cc_atapi_read
DYNAMIC (run-time), simply allocated and cleared: cc_bus_ok, cc_units.

The last two entries refer to the two reading routines, one for ATA and the
second for ATAPI.
They use common code but, because of compatibility reasons, they cannot have
the controller_context structure in their prototipes. But they call upon it, 
so all you need to do is forward the call to local_ide_read and local_atapi_read,
using the appropriate cc_base_io. 
Have a look at p_sii_block_read and p_sii_atapi_read for an example.
The same kind of reasoning is applied to the "get_dev" function: you must write
one function like via_get_dev that returns a (block_dev_desc_t *) of your 
controller. This function is the hook used by cmd_boota to use units on your 
controller. You decide the name.

The initialization function: this is the main part of adding a new controller. 
This function must:
- check if the controller is really present in your system. If not present, 
	quit immediately. Otherwise:
- allocate and clear cc_units, cc_base_io and cc_bus_ok.
- really initialize the controller HW. You should know what to do here.
- fill in with sensible values cc_base_io.
- if you want to let the user swap the primary and secondary bus, call ide_swap().
- fill in cc_block_read and cc_atapi_read, linking them with the callbacks for
	your controller.
- set cc_present to TRUE.

Ok, that's it.
One more step is required: add a call to the above initialization function 
from init_controllers.

Done!
*/

#undef	IDE_DEBUG
#ifdef	IDE_DEBUG
#define	PRINTF(fmt,args...)		printf (fmt ,##args)
#define	PRINTF2(fmt,args...)    
#else
#define PRINTF(fmt,args...)
#define PRINTF2(fmt,args...)
#endif

#undef	ATAPI_DEBUG
#ifdef	ATAPI_DEBUG
#define	AT_PRINTF(fmt,args...)	printf (fmt ,##args)
#else
#define AT_PRINTF(fmt,args...)
#endif

#define EIEIO	__asm__ volatile ("eieio")

static inline base_io_address IDE_BUS_ADV(const struct controller_context * const cc, const unsigned dev)
{
	return cc->cc_base_io[dev/cc->cc_units_per_bus];
}

//#define ATA_DEVICE_ADV(cc, dev) ((dev & 1)<<4)
static int ATA_DEVICE_ADV(const struct controller_context * const cc, const unsigned dev)
{
    if (strcmp(cc->cc_description,"Sii0680") == 0) return((dev & 1)<<4);
    else return 0;
}

#define ATA_CURR_BASE_ADV(cc, dev)	(CONFIG_SYS_ATA_BASE_ADDR+IDE_BUS_ADV(cc,dev))

#define IDE_TIME_OUT			2000 /* 2 sec timeout */
#define ATAPI_TIME_OUT			7000 /* 7 sec timeout (5 sec seems to work...) */
#define IDE_SPIN_UP_TIME_OUT	5000 /* 5 sec spin-up timeout */

#ifdef CONFIG_SHOW_BOOT_PROGRESS
#include <status_led.h>
#define SHOW_BOOT_PROGRESS(arg)	show_boot_progress(arg)
#else
#define SHOW_BOOT_PROGRESS(arg)
#endif

struct controller_context controllers[]=
{
	{ FALSE, MAX_S_SII_UNITS,		MAX_S_SII_BUS,		0, NULL, NULL, NULL, NULL, NULL, NULL, NULL},
	{ FALSE, MAX_S_4_SII_UNITS,		MAX_S_4_SII_BUS,	0, NULL, NULL, NULL, NULL, NULL, NULL, NULL},
#ifdef CONFIG_SAM460EX
	{ FALSE, MAX_SATA2_460_UNITS,	MAX_SATA2_460_BUS,	0, NULL, NULL, NULL, NULL, NULL, NULL, NULL},
#endif
	{ FALSE, MAX_P_SII_UNITS,		MAX_P_SII_BUS,		0, NULL, NULL, NULL, NULL, NULL, NULL, NULL},
};

enum
{
	S_SII_POS = 0,
	S4_SII_POS,
#ifdef CONFIG_SAM460EX	
	SATA2_460_POS,
#endif
	P_SII_POS		
};

//Forward declarations.
static unsigned long s_sii_block_read(int dev, unsigned long start, lbaint_t blkcnt, unsigned long *buffer);
static ulong s_sii_atapi_read (int device, lbaint_t blknr, ulong blkcnt, ulong *buffer);

static unsigned long s_4_sii_block_read(int dev, unsigned long start, lbaint_t blkcnt, unsigned long *buffer);
static ulong s_4_sii_atapi_read (int device, lbaint_t blknr, ulong blkcnt, ulong *buffer);

static unsigned long p_sii_block_read(int dev, unsigned long start, lbaint_t blkcnt, unsigned long *buffer);
static ulong p_sii_atapi_read (int device, lbaint_t blknr, ulong blkcnt, ulong *buffer);

static ulong local_ide_read (int device, lbaint_t blknr, ulong blkcnt, ulong *buffer, const struct controller_context * const cc);
static void local_input_swap_data(int dev, ulong *sect_buf, int words, const struct controller_context * const cc);
static void local_input_data(int dev, ulong *sect_buf, int words, const struct controller_context * const cc);
static void local_ide_ident (block_dev_desc_t *dev_desc, struct controller_context * const ctx);
static uchar local_ide_wait (int dev, ulong t, const struct controller_context * const cc);
static void local_ident_cpy (unsigned char *dst, unsigned char *src, unsigned int len);

//This should between an ifdef ATAPI /endif pair
static void local_atapi_inquiry(block_dev_desc_t * dev_desc, struct controller_context * const ctx);
static uchar local_atapi_wait_mask (int dev, ulong t,uchar mask, uchar res, const struct controller_context * const cc);
static unsigned char local_atapi_issue(int device,unsigned char* ccb,int ccblen, unsigned char * buffer,int buflen, const struct controller_context * const cc);

static _Bool local_ide_set_pio(const int device, const unsigned char mode, const struct controller_context * const cc);

static void local_ide_outb(int dev, int port, unsigned char val, const struct controller_context * const cc)
{
	PRINTF2 ("a1_ide_outb (dev= %d, port= 0x%x, val= 0x%02x) : @ 0x%08lx\n",
		dev, port, val, (ATA_CURR_BASE_ADV(cc, dev)+port));
	/* Ensure I/O operations complete */
	EIEIO;
	*((uchar *)(ATA_CURR_BASE_ADV(cc, dev)+port)) = val;
}

static unsigned char local_ide_inb(int dev, int port, const struct controller_context * const cc)
{
	uchar val;
	/* Ensure I/O operations complete */
	EIEIO;
	val = *((uchar *)(ATA_CURR_BASE_ADV(cc, dev)+port));
	
	PRINTF2 ("a1_ide_inb (dev= %d, port= 0x%x) : @ 0x%08lx -> 0x%02x\n",
		dev, port, (ATA_CURR_BASE_ADV(cc, dev)+port), val);
	
	return (val);
}

//--------------

static void s_sii_early_init(struct controller_context * const ctx)
{
	unsigned int bdf;
	unsigned int addr;
	uint32_t class_rev;
	
	PRINTF ("s_sii_init: START\n");

	//Creates the devices description array.
	
	ctx->cc_units = calloc(sizeof(block_dev_desc_t),  ctx->cc_maxunit);
	ctx->cc_base_io = calloc(sizeof(base_io_address), ctx->cc_maxbus);
	ctx->cc_bus_ok = calloc(sizeof(BOOL), ctx->cc_maxbus);
	ctx->cc_maxbus_var = "ssii_maxbus";
	ctx->cc_description = "Sii3112";
		
	/* get IDE Controller Device ID */

	if ((bdf = pci_find_device(PCI_VENDOR_ID_CMD, PCI_DEVICE_ID_SII_3112, 0)) == -1)
	{
		if ((bdf = pci_find_device(PCI_VENDOR_ID_CMD, PCI_DEVICE_ID_SII_3512, 0)) == -1)
	    {
	        return;
	    }
	}

	pci_write_config_dword(bdf, PCI_COMMAND, PCI_COMMAND_IO | PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);
	
	// Reset chip registers to safe values
	pci_read_config_dword(bdf, PCI_CLASS_REVISION, &class_rev);
	class_rev &= 0xFF;
	pci_write_config_byte(bdf, PCI_CACHE_LINE_SIZE, (class_rev) ? 1 : 255); 

	pci_read_config_dword (bdf, PCI_BASE_ADDRESS_0, &addr);
	ctx->cc_base_io[0] = (void *)(addr & PCI_BASE_ADDRESS_IO_MASK);
	pci_read_config_dword (bdf, PCI_BASE_ADDRESS_2, &addr);
	ctx->cc_base_io[1] = (void *)(addr & PCI_BASE_ADDRESS_IO_MASK);

	ctx->cc_present = TRUE;
	ctx->cc_block_read = s_sii_block_read;
	ctx->cc_atapi_read = s_sii_atapi_read;
	
	PRINTF("Done s_sii initialization, base IO addresses at %08lx, %08lx\n",
		ctx->cc_base_io[0], ctx->cc_base_io[1]);
}

static void s_4_sii_early_init(struct controller_context * const ctx)
{
	unsigned int bdf;
	unsigned int addr;
	uint32_t class_rev;
	
	PRINTF ("s_4_sii_init: START\n");

	//Creates the devices description array.
	
	ctx->cc_units = calloc(sizeof(block_dev_desc_t),  ctx->cc_maxunit);
	ctx->cc_base_io = calloc(sizeof(base_io_address), ctx->cc_maxbus);
	ctx->cc_bus_ok = calloc(sizeof(BOOL), ctx->cc_maxbus);
	ctx->cc_maxbus_var = "s4sii_maxbus";
	ctx->cc_description = "Sii3114";
		
	/* get IDE Controller Device ID */

	if ((bdf = pci_find_device(PCI_VENDOR_ID_CMD, PCI_DEVICE_ID_SII_3114, 0)) == -1)
	{
		return;
	}

	pci_write_config_dword(bdf, PCI_COMMAND, PCI_COMMAND_IO | PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);
	
	// Reset chip registers to safe values
	pci_read_config_dword(bdf, PCI_CLASS_REVISION, &class_rev);
	class_rev &= 0xFF;
	pci_write_config_byte(bdf, PCI_CACHE_LINE_SIZE, (class_rev) ? 1 : 255); 
	//I really don't know what the above code is all about.....
	
	
	pci_read_config_dword (bdf, PCI_BASE_ADDRESS_0, &addr);
	ctx->cc_base_io[0] = (void *)(addr & PCI_BASE_ADDRESS_IO_MASK);
	pci_read_config_dword (bdf, PCI_BASE_ADDRESS_2, &addr);
	ctx->cc_base_io[1] = (void *)(addr & PCI_BASE_ADDRESS_IO_MASK);
	
/*
	Here we got a problem: since the "autoconfiguration" (ahemm...) of PCI is done via
	BAR registers, it's very likely that other cards I/O space overlap with the
	3114 "hole" after which the 2 upper buses are placed.
	This really happens if a 680 is used at the same time.
	So for the time being the two upper buses are disabled.
	
	ctx->cc_base_io[2] = ctx->cc_base_io[0] + SILLY_SIL_4_PORTS_OFFSET;
	ctx->cc_base_io[3] = ctx->cc_base_io[1] + SILLY_SIL_4_PORTS_OFFSET;
*/
//	ctx->cc_maxunit = ctx->cc_maxbus = 2; //See the comment above.

	ctx->cc_base_io[2] = ctx->cc_base_io[0] + SILLY_SIL_4_PORTS_OFFSET;
	ctx->cc_base_io[3] = ctx->cc_base_io[1] + SILLY_SIL_4_PORTS_OFFSET;
		ctx->cc_maxunit = ctx->cc_maxbus = 4;
	
	ctx->cc_present = TRUE;
	ctx->cc_block_read = s_4_sii_block_read;
	ctx->cc_atapi_read = s_4_sii_atapi_read;
	
	PRINTF("Done s_4_sii initialization, base IO addresses at %08lx, %08lx, %08lx, %08lx\n",
		ctx->cc_base_io[0], ctx->cc_base_io[1], ctx->cc_base_io[2], ctx->cc_base_io[3]);
}

#ifdef CONFIG_SAM460EX
static void sata2_460_early_init(struct controller_context * const ctx)
{
	PRINTF ("sata2_460_init: START\n");

	//Creates the devices description array.
	
	ctx->cc_units = NULL;						// later... 
	ctx->cc_base_io = NULL;						// not used
	ctx->cc_bus_ok = calloc(sizeof(BOOL), ctx->cc_maxbus);
	ctx->cc_maxbus_var = "sata2_maxbus";
	ctx->cc_description = "SATA2-460";
		
	/* get IDE Controller Device ID */
	
	if (gd->board_type != BOARD_CANYONLANDS_SATA) return;

	ctx->cc_present = TRUE;
	ctx->cc_block_read = sata_read;
	ctx->cc_atapi_read = sata_read;
	
	PRINTF("Done sata2_460 initialization\n");
}
#endif

static void p_sii_early_init(struct controller_context * const ctx)
{
	unsigned int cmd, bdf;
	unsigned int addr;
	unsigned char tmpbyte = 0;

	PRINTF ("p_sii_init: START\n");

	//Creates the devices description array.
	
	ctx->cc_units = calloc(sizeof(block_dev_desc_t),  ctx->cc_maxunit);
	ctx->cc_base_io = calloc(sizeof(base_io_address), ctx->cc_maxbus);
	ctx->cc_bus_ok = calloc(sizeof(BOOL), ctx->cc_maxbus);
	ctx->cc_maxbus_var = "psii_maxbus";
	ctx->cc_description = "Sii0680";
	
	/* get IDE Controller Device ID */

	if ((bdf = pci_find_device(PCI_VENDOR_ID_CMD, PCI_DEVICE_ID_SII_680, 0)) == -1)
	{
		return;
	}

	pci_read_config_dword (bdf, PCI_BASE_ADDRESS_0, &addr);
	ctx->cc_base_io[0] = (void *)(addr & PCI_BASE_ADDRESS_IO_MASK);
	pci_read_config_dword (bdf, PCI_BASE_ADDRESS_2, &addr);
	ctx->cc_base_io[1] = (void *)(addr & PCI_BASE_ADDRESS_IO_MASK);

	PRINTF("p_sii base addresses at %08lx and %08lx\n", ctx->cc_base_io[0], ctx->cc_base_io[1]);
	
	/* Enable bus mastering in case this has not been done, yet. */

	pci_read_config_dword (bdf, PCI_COMMAND, &cmd);
	cmd |= PCI_COMMAND_MASTER;
	pci_write_config_dword (bdf, PCI_COMMAND, cmd);

  	/* initialize registers */

	pci_write_config_byte (bdf, 0x80, 0x00);
	pci_write_config_byte (bdf, 0x84, 0x00);
	pci_read_config_byte (bdf, 0x8A, &tmpbyte);
	pci_write_config_byte (bdf, 0x8A, tmpbyte | 0x01);

	pci_write_config_word (bdf, 0xA2, 0x328A);
	pci_write_config_dword (bdf, 0xA4, 0x328A328A);
	pci_write_config_dword (bdf, 0xA8, 0x43924392);
	pci_write_config_dword (bdf, 0xAC, 0x40094009);
	pci_write_config_word (bdf, 0xB2, 0x328A);
	pci_write_config_dword (bdf, 0xB4, 0x328A328A);
	pci_write_config_dword (bdf, 0xB8, 0x43924392);
	pci_write_config_dword (bdf, 0xBC, 0x40094009);
	
	ctx->cc_present = TRUE;
	ctx->cc_block_read = p_sii_block_read;
	ctx->cc_atapi_read = p_sii_atapi_read;
	
	PRINTF("Done p_sii initialization\n");
}

static void init_controllers(void) //Will fill in controllers[] with the appropriate values.
{
	unsigned cnt;
	s_sii_early_init(&controllers[S_SII_POS]);
	s_4_sii_early_init(&controllers[S4_SII_POS]);
#ifdef CONFIG_SAM460EX
	sata2_460_early_init(&controllers[SATA2_460_POS]);
#endif
	p_sii_early_init(&controllers[P_SII_POS]);	

	PRINTF("Looping in early init for a total of %lu controllers to compute units per bus\n", 
		((sizeof controllers)/(sizeof (struct controller_context))));

	for(cnt=0; cnt < ((sizeof controllers)/(sizeof (struct controller_context))); cnt++)
	{
		controllers[cnt].cc_units_per_bus = controllers[cnt].cc_maxunit/controllers[cnt].cc_maxbus;
		PRINTF("Units per bus for bus %u: %u\n", cnt, controllers[cnt].cc_units_per_bus);
	}

	PRINTF("Done init controllers\n");
}

static void internal_ide_unit_scan(struct controller_context * ctx) //Taken from cmd_ide.c/ide_init, but sort of preprocessed.
{
	unsigned char c;
	int i, bus;
	
	unsigned int max_bus_scan;
	unsigned int ata_reset_time;
	char *s;
		
	/*
	 * Wait for IDE to get ready.
	 * According to spec, this can take up to 31 seconds!
	 */
	PRINTF("Checking for %s\n",ctx->cc_maxbus_var);
	s = getenv(ctx->cc_maxbus_var);
	if (s) 
	    max_bus_scan = simple_strtol(s, NULL, 10);
	else 
	    max_bus_scan = ctx->cc_maxbus;

	PRINTF("Now looping for a total of %u bus\n", max_bus_scan);

	for (bus=0; bus<max_bus_scan; ++bus) 
	{
		int dev = bus * (ctx->cc_maxunit / max_bus_scan);
        printf ("SATA Device %d: ",dev);
        
		ctx->cc_bus_ok[bus] = 0;

		/* Select device
		 */
		udelay (100000);		/* 100 ms */
		local_ide_outb (dev, ATA_DEV_HD, ATA_LBA | ATA_DEVICE_ADV(ctx,dev), ctx);
		udelay (100000);		/* 100 ms */
		
		ata_reset_time = ATA_RESET_TIME;
		s = getenv("ide_reset_timeout");
		if (s) ata_reset_time = simple_strtol(s, NULL, 10);
		
		i = 0;
		do {
			udelay (10000);		/* 10 ms */

			c = local_ide_inb (dev, ATA_STATUS, ctx);
			i++;
			
			if (i > (ata_reset_time * 100)) 
			{
				puts ("* Timeout *\n");
				
				/* If this is the second bus, the first one was OK */
				if (bus != 0) 
				{
				    ctx->cc_bus_ok[bus] = FALSE;
				    goto skip_bus;
				}
				return;
			}
			if ((i >= 100) && ((i%100)==0)) 
			{
				putc ('.');
				PRINTF ("%x",c);
			}
		} while (c & ATA_STAT_BUSY);

		if (c & (ATA_STAT_BUSY | ATA_STAT_FAULT)) 
		{
			puts ("not available ");
			PRINTF ("Status = 0x%02X ", c);
#ifndef CONFIG_ATAPI /* ATAPI Devices do not set DRDY */
		} else  if ((c & ATA_STAT_READY) == 0) {
			puts ("not available ");
			PRINTF ("Status = 0x%02X ", c);
#endif
		} else {
			puts ("OK ");
			ctx->cc_bus_ok[bus] = TRUE;
		}
	}

skip_bus:
	putc ('\n');

	for (i=0; i<ctx->cc_maxunit; i++) 
	{
		ctx->cc_units[i].type=DEV_TYPE_UNKNOWN;
		ctx->cc_units[i].if_type=IF_TYPE_IDE;
		ctx->cc_units[i].dev=i;
		ctx->cc_units[i].part_type=PART_TYPE_UNKNOWN;
		ctx->cc_units[i].blksz=0;
		ctx->cc_units[i].lba=0;
		ctx->cc_units[i].block_read=ctx->cc_block_read;
		
		if (!ctx->cc_bus_ok[IDE_BUS(i)])
			continue;

		local_ide_ident(&ctx->cc_units[i], ctx);

		dev_print(&ctx->cc_units[i]);

		if ((ctx->cc_units[i].lba > 0) && (ctx->cc_units[i].blksz > 0)) 
		{
			/* initialize partition type */
			init_part (&ctx->cc_units[i]);			
		}
	}
}

#ifdef CONFIG_SAM460EX
void sata_460_initialize(struct controller_context *curr)
{
	PRINTF("CALLING init_sata\n");

	int rc, i;

	for (i = 0; i < CONFIG_SYS_SATA_MAX_DEVICE; i++) 
	{
		memset(&sata_dev_desc[i], 0, sizeof(struct block_dev_desc));
		sata_dev_desc[i].if_type = IF_TYPE_SATA;
		sata_dev_desc[i].dev = i;
		sata_dev_desc[i].part_type = PART_TYPE_UNKNOWN;
		sata_dev_desc[i].type = DEV_TYPE_HARDDISK;
		sata_dev_desc[i].lba = 0;
		sata_dev_desc[i].blksz = 512;
		sata_dev_desc[i].block_read = sata_read;
		//sata_dev_desc[i].block_write = sata_write;

		rc = init_sata(i);
		rc = scan_sata(i);
		if ((sata_dev_desc[i].lba > 0) && (sata_dev_desc[i].blksz > 0))
			init_part(&sata_dev_desc[i]);
	}
	
	curr->cc_units = &sata_dev_desc;
	
	if (rc == 0)
	{				
		for (i = 0; i < CONFIG_SYS_SATA_MAX_DEVICE; ++i) 
		{
			if (sata_dev_desc[i].type == DEV_TYPE_UNKNOWN)
				continue;
			printf ("SATA device %d:\n", i);
			dev_print(&curr->cc_units[i]);
		}
	}
}
#endif

void ide_controllers_init(void)
{
	unsigned cnt;
	
	//Activates all the controllers	
	init_controllers(); 

	//Ok, now tries to scan the various HDD buses.
	for(cnt=0; cnt < sizeof(controllers)/sizeof(struct controller_context); cnt++)
	{
		struct controller_context *curr = &controllers[cnt];

		if(curr->cc_present)
		{
			unsigned unit_index;
			PRINTF("doing unit scan for controller n. %u\n", cnt);

#ifdef CONFIG_SAM460EX			
			if (strcmp(curr->cc_description,"SATA2-460") == 0)
			{
				sata_460_initialize(curr);
			}			
			else
#endif			
			{				
			    internal_ide_unit_scan(curr);

				//For each unit tries to enable PIO4
			
				for(unit_index = 0; unit_index < curr->cc_maxunit; unit_index++) 
				{
					block_dev_desc_t * dev = &curr->cc_units[unit_index];
					if(dev->blksz)
					{
						local_ide_set_pio(unit_index, 4, curr);
					}
				}
			}
		}
	}
}

static block_dev_desc_t * generic_get_dev(const unsigned unit, const struct controller_context * const cc)
{
	if(unit < cc->cc_maxunit)
	{
		if(cc->cc_units[unit].block_read)
		{
			return &cc->cc_units[unit];
		}
	}
	return NULL;
}

block_dev_desc_t *s_sii_get_dev(const unsigned unit)
{
	return generic_get_dev(unit, &controllers[S_SII_POS]);
}

static unsigned long s_sii_block_read(int dev, unsigned long start, lbaint_t blkcnt, unsigned long *buffer)
{
	return local_ide_read(dev, start, blkcnt, buffer, &controllers[S_SII_POS]);
}

block_dev_desc_t *s_4_sii_get_dev(const unsigned unit)
{
	return generic_get_dev(unit, &controllers[S4_SII_POS]);
}

static unsigned long s_4_sii_block_read(int dev, unsigned long start, lbaint_t blkcnt, unsigned long *buffer)
{
	return local_ide_read(dev, start, blkcnt, buffer, &controllers[S4_SII_POS]);
}

#ifdef CONFIG_SAM460EX
block_dev_desc_t * sata2_460_get_dev(const unsigned unit)
{
	return generic_get_dev(unit, &controllers[SATA2_460_POS]);
}
#endif

block_dev_desc_t *p_sii_get_dev(const unsigned unit)
{
	return generic_get_dev(unit, &controllers[P_SII_POS]);
}

static unsigned long p_sii_block_read(int dev, unsigned long start, lbaint_t blkcnt, unsigned long *buffer)
{
	return local_ide_read(dev, start, blkcnt, buffer, &controllers[P_SII_POS]);
}

static ulong local_ide_read (int device, lbaint_t blknr, ulong blkcnt, ulong *buffer, const struct controller_context * const cc)
{
	ulong n = 0;
	unsigned char c;
	unsigned char pwrsave=0; /* power save */
#ifdef CONFIG_LBA48
	unsigned char lba48 = 0;

	if (blknr & (uint64_t)0x0000fffff0000000) {
		/* more than 28 bits used, use 48bit mode */
		lba48 = 1;
	}
#endif
	PRINTF ("ide_read dev %d start %p, blocks %lX buffer at %p\n",
		device, blknr, blkcnt, (ulong)buffer);

	/* Select device
	 */
	local_ide_outb (device, ATA_DEV_HD, ATA_LBA | ATA_DEVICE_ADV(cc,device), cc);
	c = local_ide_wait (device, IDE_TIME_OUT, cc);

	if (c & ATA_STAT_BUSY) {
		printf ("IDE read: device %d not ready\n", device);
		goto IDE_READ_E;
	}

	/* first check if the drive is in Powersaving mode, if yes,
	 * increase the timeout value */
	local_ide_outb (device, ATA_COMMAND,  ATA_CMD_CHK_PWR, cc);
	udelay (50);

	c = local_ide_wait (device, IDE_TIME_OUT, cc);	/* can't take over 500 ms */

	if (c & ATA_STAT_BUSY) {
		printf ("IDE read: device %d not ready\n", device);
		goto IDE_READ_E;
	}
	if ((c & ATA_STAT_ERR) == ATA_STAT_ERR) {
		printf ("No Powersaving mode %X\n", c);
	} else {
		c = local_ide_inb(device,ATA_SECT_CNT, cc);
		PRINTF("Powersaving %02X\n",c);
		if(c==0)
			pwrsave=1;
	}

	while (blkcnt-- > 0) 
	{
		c = local_ide_wait (device, IDE_TIME_OUT, cc);

		if (c & ATA_STAT_BUSY) 
		{
			printf ("IDE read: device %d not ready\n", device);
			break;
		}
#ifdef CONFIG_LBA48
		if (lba48) 
		{
			/* write high bits */
			local_ide_outb (device, ATA_SECT_CNT, 0, cc);
			local_ide_outb (device, ATA_LBA_LOW,  (blknr >> 24) & 0xFF, cc);
			local_ide_outb (device, ATA_LBA_MID,  (blknr >> 32) & 0xFF, cc);
			local_ide_outb (device, ATA_LBA_HIGH, (blknr >> 40) & 0xFF, cc);
		}
#endif
		local_ide_outb (device, ATA_SECT_CNT, 1, cc);
		local_ide_outb (device, ATA_LBA_LOW,  (blknr >>  0) & 0xFF, cc);
		local_ide_outb (device, ATA_LBA_MID,  (blknr >>  8) & 0xFF, cc);
		local_ide_outb (device, ATA_LBA_HIGH, (blknr >> 16) & 0xFF, cc);

#ifdef CONFIG_LBA48
		if (lba48) 
		{
			local_ide_outb (device, ATA_DEV_HD, ATA_LBA | ATA_DEVICE_ADV(cc,device) , cc);
			local_ide_outb (device, ATA_COMMAND, ATA_CMD_READ_EXT, cc);

		} else
#endif
		{
			local_ide_outb (device, ATA_DEV_HD,   ATA_LBA		|
						    ATA_DEVICE_ADV(cc, device)	|
						    ((blknr >> 24) & 0xF) , cc);
			local_ide_outb (device, ATA_COMMAND,  ATA_CMD_READ, cc);
		}

		udelay (50);

		if(pwrsave) 
		{
			c = local_ide_wait (device, IDE_SPIN_UP_TIME_OUT, cc);	/* may take up to 4 sec */
			pwrsave=0;
		} else {
			c = local_ide_wait (device, IDE_TIME_OUT, cc);	/* can't take over 500 ms */
		}

		if ((c&(ATA_STAT_DRQ|ATA_STAT_BUSY|ATA_STAT_ERR)) != ATA_STAT_DRQ) {
#if defined(CONFIG_SYS_64BIT_LBA) && defined(CONFIG_SYS_64BIT_VSPRINTF)
			printf ("Error (no IRQ) dev %d blk %qd: status 0x%02x\n",
				device, blknr, c);
#else
			printf ("Error (no IRQ) dev %d blk %ld: status 0x%02x\n",
				device, (ulong)blknr, c);
#endif
			break;
		}

		local_input_data (device, buffer, ATA_SECTORWORDS, cc);
		(void) local_ide_inb (device, ATA_STATUS, cc);	/* clear IRQ */

		++n;
		++blknr;
		buffer += ATA_SECTORWORDS;
	}
	
IDE_READ_E:
	return (n);
}

static void local_input_swap_data(int dev, ulong *sect_buf, int words, const struct controller_context * const cc)
{
	volatile ushort	*pbuf = (ushort *)(ATA_CURR_BASE_ADV(cc, dev)+ATA_DATA_REG);
	ushort	*dbuf = (ushort *)sect_buf;

	PRINTF("in input swap data base for read is %lx\n", (unsigned long) pbuf);

	while (words--) {
		EIEIO;
		*dbuf++ = ld_le16(pbuf);
		EIEIO;		
		*dbuf++ = ld_le16(pbuf);
	}
}

static void local_input_data(int dev, ulong *sect_buf, int words, const struct controller_context * const cc)
{
	ushort	*dbuf;
	volatile ushort	*pbuf;

	pbuf = (ushort *)(ATA_CURR_BASE_ADV(cc, dev)+ATA_DATA_REG);
	dbuf = (ushort *)sect_buf;

	PRINTF("in input data base for read is %lx\n", (unsigned long) pbuf);

	while (words--) {
		EIEIO;
		*dbuf++ = *pbuf;
		EIEIO;
		*dbuf++ = *pbuf;
	}
}

static void local_ide_ident(block_dev_desc_t *dev_desc, struct controller_context * const ctx)
{
	ulong iobuf[ATA_SECTORWORDS] = { 0 };
	hd_driveid_t *iop = (hd_driveid_t *)iobuf;

	int ii;
	int device;
	int max_bus_scan;
	int retries = 0;
	int do_retry = 0;
	char *s;
	unsigned char c;
			
	device=dev_desc->dev;
	PRINTF("ENTERED local_ide_ident %p %d %p\n",dev_desc,device,ctx);

 	s = getenv(ctx->cc_maxbus_var);
	if (s) {
		max_bus_scan = simple_strtol(s, NULL, 10);
	} else {
		max_bus_scan = CONFIG_SYS_IDE_MAXBUS;
	}

	if (device >= max_bus_scan*2) {
		dev_desc->type=DEV_TYPE_UNKNOWN;
		return;
	}

	// issue a device reset, since it could happen the device is in an unkwown state
	//local_ide_outb (device, ATA_COMMAND, 0x08, ctx);
	/* wait 750 ms */
	//for (ii=0; ii<750; ++ii) 
	//{
	//	udelay (1000);
	//}
	
	/* Select device
	 */
	 
	local_ide_outb (device, ATA_DEV_HD, ATA_LBA | ATA_DEVICE_ADV(ctx,device), ctx);
	udelay (100000);		/* 100 ms */
	
	// issue a device reset, since it could happen the device is in an unkwown state
	local_ide_outb (device, ATA_COMMAND, 0x08, ctx);
	udelay (100000);		/* 100 ms */
		
	dev_desc->if_type=IF_TYPE_IDE;
    
	do_retry = 0;
	retries = 0;

	/* Warning: This will be tricky to read */
	while (retries <= 2) 
	{
		/* check signature */
		u8 tmp = local_ide_inb(device,ATA_SECT_NUM, ctx);
		
		if (/*(tmp == 0x00) ||*/
			((tmp == 0x01) &&
			 (local_ide_inb(device,ATA_CYL_LOW, ctx)  == 0x14) &&
			 (local_ide_inb(device,ATA_CYL_HIGH, ctx) == 0xEB)))
		{
			/* ATAPI Signature found */
			PRINTF("ATAPI\n");
			dev_desc->if_type=IF_TYPE_ATAPI;
			/* Start Ident Command
			 */
			local_ide_outb (device, ATA_COMMAND, ATAPI_CMD_IDENT, ctx);
			/*
			 * Wait for completion - ATAPI devices need more time
			 * to become ready
			 */
			c = local_ide_wait (device, ATAPI_TIME_OUT, ctx);
		} 
		else
		{
			/* Start Ident Command
			 */
			PRINTF("ATA\n");
			local_ide_outb (device, ATA_COMMAND, ATA_CMD_IDENT, ctx);
	
			/* Wait for completion
			 */
			c = local_ide_wait (device, IDE_TIME_OUT, ctx);
		}

		if (((c & ATA_STAT_DRQ) == 0) ||
		    ((c & (ATA_STAT_FAULT|ATA_STAT_ERR)) != 0) ) 
		{
			if (retries <=1) //== 0) 
			{
				do_retry = 1;
			} 
			else 
			{
				return;
			}
		}

		s = getenv("ide_doreset");
		if (s && strcmp(s, "on") == 0 && 1 == do_retry) 
		{
			/* Need to soft reset the device in case it's an ATAPI...  */
			PRINTF("Retrying...\n");
			local_ide_outb (device, ATA_DEV_HD, ATA_LBA | ATA_DEVICE_ADV(ctx,device), ctx);
			udelay(100000);
			local_ide_outb (device, ATA_COMMAND, 0x08, ctx);
			udelay (100000);	/* 100 ms */
			retries++;
		} 
		else 
		{
			retries = 100;
		}
	}	/* see above - ugly to read */

	local_input_swap_data (device, iobuf, ATA_SECTORWORDS, ctx);

	local_ident_cpy (dev_desc->revision, iop->fw_rev, sizeof(dev_desc->revision));
	local_ident_cpy (dev_desc->vendor, iop->model, sizeof(dev_desc->vendor));
	local_ident_cpy (dev_desc->product, iop->serial_no, sizeof(dev_desc->product));
	
	if ((iop->config & 0x0080)==0x0080)
		dev_desc->removable = 1;
	else
		dev_desc->removable = 0;

#ifdef CONFIG_ATAPI
	if (dev_desc->if_type==IF_TYPE_ATAPI) 
	{
		local_atapi_inquiry(dev_desc, ctx);
		return;
	}
#endif /* CONFIG_ATAPI */

	/* swap shorts */
	dev_desc->lba = (iop->lba_capacity << 16) | (iop->lba_capacity >> 16);

#ifdef CONFIG_LBA48
	if (iop->command_set_2 & 0x0400) { /* LBA 48 support */
		dev_desc->lba48 = 1;
		dev_desc->lba = (unsigned long long)iop->lba48_capacity[0] |
						  ((unsigned long long)iop->lba48_capacity[1] << 16) |
						  ((unsigned long long)iop->lba48_capacity[2] << 32) |
						  ((unsigned long long)iop->lba48_capacity[3] << 48);
	} else {
		dev_desc->lba48 = 0;
	}
#endif /* CONFIG_LBA48 */
	/* assuming HD */
	dev_desc->type=DEV_TYPE_HARDDISK;
	dev_desc->blksz=ATA_BLOCKSIZE;
	dev_desc->lun=0; /* just to fill something in... */
}

static uchar local_ide_wait (int dev, ulong t, const struct controller_context * const cc)
{
	ulong delay = 10 * t;		/* poll every 100 us */
	uchar c;

	while ((c = local_ide_inb(dev, ATA_STATUS, cc)) & ATA_STAT_BUSY) 
	{
		udelay (100);
		if (delay-- == 0) 
		{
			break;
		}
	}
	return (c);
}

static void local_ident_cpy (unsigned char *dst, unsigned char *src, unsigned int len)
{
	unsigned char *end, *last;

	last = dst;
	end  = src + len - 1;

	/* reserve space for '\0' */
	if (len < 2)
		goto OUT;

	/* skip leading white space */
	while ((*src) && (src<end) && (*src==' '))
		++src;

	/* copy string, omitting trailing white space */
	while ((*src) && (src<end)) 
	{
		*dst++ = *src;
		if (*src++ != ' ')
			last = dst;
	}
OUT:
	*last = '\0';
}

#ifdef CONFIG_ATAPI
/****************************************************************************
 * ATAPI Support
 */

/* since ATAPI may use commands with not 4 bytes alligned length
 * we have our own transfer functions, 2 bytes aligned */
static void local_output_data_shorts(int dev, ushort *sect_buf, int shorts, const struct controller_context * const cc)
{
	ushort	*dbuf;
	volatile ushort	*pbuf;

	pbuf = (ushort *)(ATA_CURR_BASE_ADV(cc, dev)+ATA_DATA_REG);
	dbuf = (ushort *)sect_buf;

	AT_PRINTF("in output data shorts base for read is %lx\n", (unsigned long) pbuf);

	while (shorts--) 
	{
		EIEIO;
		*pbuf = *dbuf++;
	}
}

static void local_input_data_shorts(int dev, ushort *sect_buf, int shorts, const struct controller_context * const cc)
{
	ushort	*dbuf;
	volatile ushort	*pbuf;

	pbuf = (ushort *)(ATA_CURR_BASE_ADV(cc, dev)+ATA_DATA_REG);
	dbuf = (ushort *)sect_buf;

	AT_PRINTF("in input data shorts base for read is %lx\n", (unsigned long) pbuf);

	while (shorts--) 
	{
		EIEIO;
		*dbuf++ = *pbuf;
	}
}

/*
 * Wait until (Status & mask) == res, or timeout (in ms)
 * Return last status
 * This is used since some ATAPI CD ROMs clears their Busy Bit first
 * and then they set their DRQ Bit
 */
static uchar local_atapi_wait_mask (int dev, ulong t,uchar mask, uchar res, const struct controller_context * const cc)
{
	ulong delay = 10 * t;		/* poll every 100 us */
	uchar c;

	c = local_ide_inb(dev,ATA_DEV_CTL, cc); /* prevents to read the status before valid */
	while (((c = local_ide_inb(dev, ATA_STATUS, cc)) & mask) != res) 
	{
		/* break if error occurs (doesn't make sense to wait more) */
		if((c & ATA_STAT_ERR)==ATA_STAT_ERR)
			break;
		udelay (100);
		if (delay-- == 0) 
		{
			break;
		}
	}
	return (c);
}

/*
 * issue an atapi command
 */
static unsigned char local_atapi_issue(int device,unsigned char* ccb,int ccblen, unsigned char * buffer,int buflen, const struct controller_context * const cc)
{
	unsigned char c,err,mask,res;
	int n;

	/* Select device
	 */
	mask = ATA_STAT_BUSY|ATA_STAT_DRQ;
	res = 0;
/*
#ifdef	CONFIG_AMIGAONEG3SE
# warning THF: Removed LBA mode ???
#endif
*/
	local_ide_outb (device, ATA_DEV_HD, ATA_LBA | ATA_DEVICE_ADV(cc,device), cc);
	c = local_atapi_wait_mask(device,ATAPI_TIME_OUT,mask,res, cc);
	if ((c & mask) != res) 
	{
		printf ("ATAPI_ISSUE: device %d not ready status %X\n", device,c);
		err=0xFF;
		goto AI_OUT;
	}
	/* write taskfile */
	local_ide_outb (device, ATA_ERROR_REG, 0, cc); /* no DMA, no overlaped */
	local_ide_outb (device, ATA_SECT_CNT, 0, cc);
	local_ide_outb (device, ATA_SECT_NUM, 0, cc);
	local_ide_outb (device, ATA_CYL_LOW,  (unsigned char)(buflen & 0xFF), cc);
	local_ide_outb (device, ATA_CYL_HIGH, (unsigned char)((buflen>>8) & 0xFF), cc);

/*
#ifdef	CONFIG_AMIGAONEG3SE
# warning THF: Removed LBA mode ???
#endif
*/
	local_ide_outb (device, ATA_DEV_HD,   ATA_LBA | ATA_DEVICE_ADV(cc,device), cc);

	local_ide_outb (device, ATA_COMMAND,  ATAPI_CMD_PACKET, cc);
	udelay (50);

	mask = ATA_STAT_DRQ|ATA_STAT_BUSY|ATA_STAT_ERR;
	res = ATA_STAT_DRQ;
	c = local_atapi_wait_mask(device,ATAPI_TIME_OUT,mask,res, cc);

	if ((c & mask) != res) { /* DRQ must be 1, BSY 0 */
		printf ("ATAPI_ISSUE: Error (no IRQ) before sending ccb dev %d status 0x%02x\n",device,c);
		err=0xFF;
		goto AI_OUT;
	}

	local_output_data_shorts (device, (unsigned short *)ccb,ccblen/2, cc); /* write command block */
 	/* ATAPI Command written wait for completition */
	/* Was 5000 in the original firmware, for QEMU we could get rid of it */
	udelay (50); /* device must set bsy */

	mask = ATA_STAT_DRQ|ATA_STAT_BUSY|ATA_STAT_ERR;
	/* if no data wait for DRQ = 0 BSY = 0
	 * if data wait for DRQ = 1 BSY = 0 */
	res=0;
	if(buflen)
		res = ATA_STAT_DRQ;
	c = local_atapi_wait_mask(device,ATAPI_TIME_OUT,mask,res, cc);
	if ((c & mask) != res ) 
	{
		if (c & ATA_STAT_ERR) 
		{
			err=(local_ide_inb(device,ATA_ERROR_REG, cc))>>4;
			AT_PRINTF("atapi_issue 1 returned sense key %X status %02X\n",err,c);
		} 
		else 
		{
			printf ("ATAPI_ISSUE: (no DRQ) after sending ccb (%x) status 0x%02x\n", ccb[0],c);
			err=0xFF;
		}
		goto AI_OUT;
	}
	n=local_ide_inb(device, ATA_CYL_HIGH, cc);
	n<<=8;
	n+=local_ide_inb(device, ATA_CYL_LOW, cc);
	if(n>buflen) 
	{
		printf("ERROR, transfer bytes %d requested only %d\n",n,buflen);
		err=0xff;
		goto AI_OUT;
	}
	if((n==0)&&(buflen<0)) 
	{
		printf("ERROR, transfer bytes %d requested %d\n",n,buflen);
		err=0xff;
		goto AI_OUT;
	}
	if(n!=buflen) 
	{
		AT_PRINTF("WARNING, transfer bytes %d not equal with requested %d\n",n,buflen);
	}
	if(n!=0) { /* data transfer */
		AT_PRINTF("ATAPI_ISSUE: %d Bytes to transfer\n",n);
		 /* we transfer shorts */
		n>>=1;
		/* ok now decide if it is an in or output */
		if ((local_ide_inb(device, ATA_SECT_CNT, cc)&0x02)==0) 
		{
			AT_PRINTF("Write to device\n");
			local_output_data_shorts(device,(unsigned short *)buffer,n, cc);
		} 
		else 
		{
			AT_PRINTF("Read from device @ %p shorts %d\n",buffer,n);
			local_input_data_shorts(device,(unsigned short *)buffer,n, cc);
		}
	}
	/* Was 5000 in the original firmware, for QEMU we could get rid of it */
	udelay(50); /* seems that some CD ROMs need this... */
	mask = ATA_STAT_BUSY|ATA_STAT_ERR;
	res=0;
	c = local_atapi_wait_mask(device,ATAPI_TIME_OUT,mask,res, cc);
	if ((c & ATA_STAT_ERR) == ATA_STAT_ERR) 
	{
		err=(local_ide_inb(device,ATA_ERROR_REG, cc) >> 4);
		AT_PRINTF("atapi_issue 2 returned sense key %X status %X\n",err,c);
	} 
	else 
	{
		err = 0;
	}
AI_OUT:
	return (err);
}

/*
 * sending the command to atapi_issue. If an status other than good
 * returns, an request_sense will be issued
 */

#define ATAPI_DRIVE_NOT_READY 	100
#define ATAPI_UNIT_ATTN		10

unsigned char local_atapi_issue_autoreq (int device,
				   unsigned char* ccb,
				   int ccblen,
				   unsigned char *buffer,
				   int buflen,
				   const struct controller_context * const cc)
{
	unsigned char sense_data[18],sense_ccb[12];
	unsigned char res,key,asc,ascq;
	int notready,unitattn;

	char *s;
	unsigned int timeout, retrycnt;

	s = getenv("ide_cd_timeout");
	timeout = s ? (simple_strtol(s, NULL, 10)*1000000)/5 : 0;

	retrycnt = 0;

	unitattn=ATAPI_UNIT_ATTN;
	notready=ATAPI_DRIVE_NOT_READY;

retry:
	res= local_atapi_issue(device,ccb,ccblen,buffer,buflen, cc);
	if (res==0)
		return (0); /* Ok */

	if (res==0xFF)
		return (0xFF); /* error */

	AT_PRINTF("(auto_req)atapi_issue returned sense key %X\n",res);

	memset(sense_ccb,0,sizeof(sense_ccb));
	memset(sense_data,0,sizeof(sense_data));
	sense_ccb[0]=ATAPI_CMD_REQ_SENSE;
	sense_ccb[4]=18; /* allocation Length */

	res=local_atapi_issue(device,sense_ccb,12,sense_data,18, cc);
	key=(sense_data[2]&0xF);
	asc=(sense_data[12]);
	ascq=(sense_data[13]);

	AT_PRINTF("ATAPI_CMD_REQ_SENSE returned %x\n",res);
	AT_PRINTF(" Sense page: %02X key %02X ASC %02X ASCQ %02X\n",
		sense_data[0],
		key,
		asc,
		ascq);

	if((key==0))
		return 0; /* ok device ready */

	if((key==5) && (asc==0x24) && (ascq==00)) 
	{
		// this patch is required by some slim DVD/CD 
		AT_PRINTF("CDB in UFI command contains illegal value\n");
		return 0; /* ok device ready */
	}
			
	if((key==6)|| (asc==0x29) || (asc==0x28)) { /* Unit Attention */
		if(unitattn-->0) 
		{
			udelay(200*1000);
			goto retry;
		}
		printf("Unit Attention, tried %d\n",ATAPI_UNIT_ATTN);
		goto error;
	}
	
	if((asc==0x4) && (ascq==0x1)) { /* not ready, but will be ready soon */
		if (notready-->0) 
		{
			udelay(200*1000);
			goto retry;
		}
		printf("Drive not ready, tried %d times\n",ATAPI_DRIVE_NOT_READY);
		goto error;
	}
	
	if(asc==0x3a) 
	{
		AT_PRINTF("Media not present\n");
		goto error;
	}

	if ((sense_data[2]&0xF)==0x0B) 
	{
		AT_PRINTF("ABORTED COMMAND...retry\n");
		if (retrycnt++ < 4)
			goto retry;
		return (0xFF);
	}

	if ((sense_data[2]&0xf) == 0x02 &&
	    sense_data[12] == 0x04	&&
	    sense_data[13] == 0x01	) 
	{
		AT_PRINTF("Waiting for unit to become active\n");
		udelay(timeout);
		if (retrycnt++ < 4)
			goto retry;
		return 0xFF;
	}

	printf ("ERROR: Unknown Sense key %02X ASC %02X ASCQ %02X\n",key,asc,ascq);
error:
	AT_PRINTF ("ERROR Sense key %02X ASC %02X ASCQ %02X\n",key,asc,ascq);
	return (0xFF);
}


static void local_atapi_inquiry(block_dev_desc_t * dev_desc, struct controller_context * const ctx)
{
	unsigned char ccb[12]; /* Command descriptor block */
	unsigned char iobuf[64]; /* temp buf */
	unsigned char c;
	int device;
	
	device=dev_desc->dev;
	dev_desc->type=DEV_TYPE_UNKNOWN; /* not yet valid */
	dev_desc->block_read=ctx->cc_atapi_read;

	memset(ccb,0,sizeof(ccb));
	memset(iobuf,0,sizeof(iobuf));

	ccb[0]=ATAPI_CMD_INQUIRY;
	ccb[4]=40; /* allocation Legnth */
	c=local_atapi_issue_autoreq(device,ccb,12,(unsigned char *)iobuf,40, ctx);

	AT_PRINTF("ATAPI_CMD_INQUIRY returned %x\n",c);
	if (c!=0)
		return;

	/* copy device ident strings */
	local_ident_cpy(dev_desc->vendor,&iobuf[8],8);
	local_ident_cpy(dev_desc->product,&iobuf[16],16);
	local_ident_cpy(dev_desc->revision,&iobuf[32],5);

	dev_desc->lun=0;
	dev_desc->lba=0;
	dev_desc->blksz=0;
	dev_desc->type=iobuf[0] & 0x1f;

	if ((iobuf[1]&0x80)==0x80)
		dev_desc->removable = 1;
	else
		dev_desc->removable = 0;

	memset(ccb,0,sizeof(ccb));
	memset(iobuf,0,sizeof(iobuf));
	ccb[0]=ATAPI_CMD_START_STOP;
	ccb[4]=0x03; /* start */

	c=local_atapi_issue_autoreq(device,ccb,12,(unsigned char *)iobuf,0, ctx);

	AT_PRINTF("ATAPI_CMD_START_STOP returned %x\n",c);
	if (c!=0)
		return;

	memset(ccb,0,sizeof(ccb));
	memset(iobuf,0,sizeof(iobuf));
	c=local_atapi_issue_autoreq(device,ccb,12,(unsigned char *)iobuf,0, ctx);

	AT_PRINTF("ATAPI_CMD_UNIT_TEST_READY returned %x\n",c);
	if (c!=0)
		return;

	memset(ccb,0,sizeof(ccb));
	memset(iobuf,0,sizeof(iobuf));
	ccb[0]=ATAPI_CMD_READ_CAP;
	c=local_atapi_issue_autoreq(device,ccb,12,(unsigned char *)iobuf,8, ctx);
	AT_PRINTF("ATAPI_CMD_READ_CAP returned %x\n",c);
	if (c!=0)
		return;

	AT_PRINTF("Read Cap: LBA %02X%02X%02X%02X blksize %02X%02X%02X%02X\n",
		iobuf[0],iobuf[1],iobuf[2],iobuf[3],
		iobuf[4],iobuf[5],iobuf[6],iobuf[7]);

	dev_desc->lba  =((unsigned long)iobuf[0]<<24) +
			((unsigned long)iobuf[1]<<16) +
			((unsigned long)iobuf[2]<< 8) +
			((unsigned long)iobuf[3]);
	dev_desc->blksz=((unsigned long)iobuf[4]<<24) +
			((unsigned long)iobuf[5]<<16) +
			((unsigned long)iobuf[6]<< 8) +
			((unsigned long)iobuf[7]);
#ifdef CONFIG_LBA48
	dev_desc->lba48 = 0; /* ATAPI devices cannot use 48bit addressing (ATA/ATAPI v7) */
#endif
	return;
}

/*
 * atapi_read:
 * we transfer only one block per command, since the multiple DRQ per
 * command is not yet implemented
 */
#define ATAPI_READ_MAX_BYTES	2048	/* we read max 2kbytes */
#define ATAPI_READ_BLOCK_SIZE	2048	/* assuming CD part */
#define ATAPI_READ_MAX_BLOCK ATAPI_READ_MAX_BYTES/ATAPI_READ_BLOCK_SIZE	/* max blocks */

static ulong local_atapi_read (int device, lbaint_t blknr, ulong blkcnt, ulong *buffer,
				const struct controller_context * const cc)
{
	ulong n = 0;
	unsigned char ccb[12]; /* Command descriptor block */
	ulong cnt;

	AT_PRINTF("atapi_read dev %d start %lX, blocks %lX buffer at %lX\n",
		device, blknr, blkcnt, (ulong)buffer);

	do {
		if (blkcnt>ATAPI_READ_MAX_BLOCK) 
		{
			cnt=ATAPI_READ_MAX_BLOCK;
		} 
		else 
		{
			cnt=blkcnt;
		}
		ccb[0]=ATAPI_CMD_READ_12;
		ccb[1]=0; /* reserved */
		ccb[2]=(unsigned char) (blknr>>24) & 0xFF; /* MSB Block */
		ccb[3]=(unsigned char) (blknr>>16) & 0xFF; /*  */
		ccb[4]=(unsigned char) (blknr>> 8) & 0xFF;
		ccb[5]=(unsigned char)  blknr      & 0xFF; /* LSB Block */
		ccb[6]=(unsigned char) (cnt  >>24) & 0xFF; /* MSB Block count */
		ccb[7]=(unsigned char) (cnt  >>16) & 0xFF;
		ccb[8]=(unsigned char) (cnt  >> 8) & 0xFF;
		ccb[9]=(unsigned char)  cnt	   & 0xFF; /* LSB Block */
		ccb[10]=0; /* reserved */
		ccb[11]=0; /* reserved */

		if (local_atapi_issue_autoreq(device,ccb,12,
					(unsigned char *)buffer,
					cnt*ATAPI_READ_BLOCK_SIZE, cc) == 0xFF) 
		{
			return (n);
		}
		n+=cnt;
		blkcnt-=cnt;
		blknr+=cnt;
		buffer+=cnt*(ATAPI_READ_BLOCK_SIZE/4); /* ulong blocksize in ulong */
	} 
	while (blkcnt > 0);
	
	return (n);
}

static ulong s_sii_atapi_read (int device, lbaint_t blknr, ulong blkcnt, ulong *buffer)
{
	return local_atapi_read(device, blknr, blkcnt, buffer, &controllers[S_SII_POS]);//Note that uboot is broken if lbaint_t is 64 bit!
}

static ulong s_4_sii_atapi_read (int device, lbaint_t blknr, ulong blkcnt, ulong *buffer)
{
	return local_atapi_read(device, blknr, blkcnt, buffer, &controllers[S4_SII_POS]);//Note that uboot is broken if lbaint_t is 64 bit!
}

static ulong p_sii_atapi_read (int device, lbaint_t blknr, ulong blkcnt, ulong *buffer)
{
	return local_atapi_read(device, blknr, blkcnt, buffer, &controllers[P_SII_POS]);//Note that uboot is broken if lbaint_t is 64 bit!
}

/* ------------------------------------------------------------------------- */

#endif /* CONFIG_ATAPI */

static _Bool local_ide_set_pio(const int device, const unsigned char mode, const struct controller_context * const cc)
{
	_Bool ret = 0;
	unsigned char pwrsave=0, c; // power save
	
	PRINTF ("Trying to set PIO mode %u for device %d \n", mode, device);

	//Select device
	
	local_ide_outb (device, ATA_DEV_HD, ATA_LBA | ATA_DEVICE_ADV(cc,device), cc);
	c = local_ide_wait (device, IDE_TIME_OUT, cc);

	if (c & ATA_STAT_BUSY)
	{
		goto IDE_EXIT;
	}

	// first check if the drive is in Powersaving mode, if yes, increase the timeout value
	local_ide_outb (device, ATA_COMMAND,  ATA_CMD_CHK_PWR, cc);
	udelay (50);

	c = local_ide_wait (device, IDE_TIME_OUT, cc);	// can't take over 500 ms

	if (c & ATA_STAT_BUSY)
	{
		goto IDE_EXIT;
	}
		
	if ((c & ATA_STAT_ERR) == ATA_STAT_ERR)
	{
	}
	else	{
		c = local_ide_inb(device,ATA_SECT_CNT, cc);
		PRINTF("Powersaving %02X\n",c);
		if(c==0)
			pwrsave=1;
	}

	//Ok, the real game starts here.

	c = local_ide_wait (device, IDE_TIME_OUT, cc);
		
	if (c & ATA_STAT_BUSY)
	{
		goto IDE_EXIT;
	}
		
	local_ide_outb (device, ATA_DEV_HD, ATA_LBA | ATA_DEVICE_ADV(cc,device), cc);
	local_ide_outb (device, ATA_SECT_NUM, 0x00, cc);
	local_ide_outb (device, ATA_CYL_LOW,  0x00, cc);
	local_ide_outb (device, ATA_CYL_HIGH, 0x00, cc);
	
	local_ide_outb (device, ATA_ERROR_REG, 0x03, cc); //Set tramsfer mode; this is the "feature" register when writing.
	local_ide_outb (device, ATA_SECT_CNT, 8|mode, cc); //Sets selected PIO mode
	
	//This one must be the last one, and it actually starts the command.
	local_ide_outb (device, ATA_COMMAND,  ATA_CMD_SETF, cc);

	udelay (50);

	if(pwrsave)
	{
		c = local_ide_wait (device, IDE_SPIN_UP_TIME_OUT, cc);	// may take up to 4 sec
		pwrsave=0;
	}
	 else	{
		c = local_ide_wait (device, IDE_TIME_OUT, cc);	 //can't take over 500 ms
	}

	if(!(c & ATA_STAT_ERR))
	{
		PRINTF("Done!\n");
		ret = 1; //Done!
	}
	else PRINTF("Status is 0x%02x\n", c);
	(void) local_ide_inb (device, ATA_STATUS, cc);	// clear IRQ
	
IDE_EXIT:
	return ret;
}

int local_do_ide (cmd_tbl_t *cmdtp, int flag, int argc, char *argv[]);
//int local_do_diskboot (cmd_tbl_t *cmdtp, int flag, int argc, char *argv[]);

U_BOOT_CMD(
	sata,  5,  1,  local_do_ide,
	"SATA sub-system",
	"sata reset [x] - init SATA controller 'x'\n"
	"sata info [x] - show available SATA devices on controller 'x'\n"
	"sata device [x] [dev] - select device 'dev' on controller 'x'\n"
	"sata part [x] [dev] - print partition table of device 'dev' on controller 'x'\n"

);

/*
U_BOOT_CMD(
	diskboot,	4,	1,	local_do_diskboot,
	"boot from IDE device",
	"loadAddr dev:part [x] - boot from IDE device 'dev' on controller 'x'\n"
);
*/
//This one should be inlined, but it's not because of code size concerns.
static BOOL valid_controller_num(WORD pos, WORD * old)
{ 
	int last;
	
//#ifdef CONFIG_SAM460EX	
	last = SATA2_460_POS;
//#else
	last = S4_SII_POS;
//#endif
    
    last = P_SII_POS;
    
	//if(pos >= 0 && pos <= ((sizeof(controllers) / sizeof(struct controller_context))))
	if ((pos >= 0) && (pos <= last))	
	{
		if(controllers[pos].cc_present)
		{
			*old = pos;
			return TRUE;
		}
	}
	
	//if(*old >= 0 && *old <= ((sizeof(controllers) / sizeof(struct controller_context))))
	//if ((*old >= 0) && (*old <= last))	
	//	return TRUE;
	
	return FALSE;
}

//WARNING: prerequisite is that valid_controller_num was successfull!!
static BOOL valid_unit_num(const WORD c_controller, WORD devoffset, WORD * old_dev)
{
	struct controller_context * curr_cont = &controllers[c_controller];

	if(devoffset >= 0 && devoffset <= curr_cont->cc_maxunit)
	{
		if(curr_cont->cc_units[devoffset].type != DEV_TYPE_UNKNOWN && curr_cont->cc_units[devoffset].blksz)
		{
			if(old_dev) *old_dev = devoffset;
			return TRUE;
		}
	}

	if(old_dev)
	{
		devoffset = *old_dev;

		if(devoffset >= 0 && devoffset <= curr_cont->cc_maxunit)
		{
			if(curr_cont->cc_units[devoffset].type != DEV_TYPE_UNKNOWN && curr_cont->cc_units[devoffset].blksz)
				return TRUE;
		}
	}
	
	return FALSE;
}

struct match_opt {
	char *	mo_string;
	WORD	mo_value;
	UWORD	mo_minlen;
};

enum do_ide_vals {
	UNDEFINED = -1,
	VAL_RESET=0,
	VAL_INFO,
	VAL_DEVICE,
	VAL_PART,
};

struct match_opt do_ide_opts[] ={
	{ "reset",	VAL_RESET,	3},
	{ "info",	VAL_INFO,	3},
	{ "device",	VAL_DEVICE,	3},
	{ "part",	VAL_PART,	4},
	{ "",		UNDEFINED,	1}
};

static WORD find_opt(char * const str, const struct match_opt * const mo, const UWORD len)
{
	UWORD cnt;
	for(cnt=0; cnt < len; cnt++)
	{
		if(!strncmp(str, mo[cnt].mo_string, mo[cnt].mo_minlen))
			return mo[cnt].mo_value;
	}
	return UNDEFINED;
}

static void print_no_controller(void)
{
	puts("Selected controller doesn't exist\n");
}

static void print_controller(const unsigned index)
{
	UWORD i;
	struct controller_context * cc = &controllers[index];

	printf("Units on controller %s\n", cc->cc_description);

	for (i=0; i< controllers[index].cc_maxunit; ++i)
	{
		if (controllers[index].cc_units[i].type==DEV_TYPE_UNKNOWN)
			continue; // list only known devices
		printf ("SATA device %d: ", i);
		dev_print(&controllers[index].cc_units[i]);
	}
	puts("\n");
}

static WORD curr_controller = UNDEFINED;
//The variable above holds the currently selected controller. 
//It's used by both local_do_ide and local_do_diskboot.

int local_do_ide (cmd_tbl_t *cmdtp, int flag, int argc, char *argv[])
{
    WORD scanres, val1=0, val2=0;
    static WORD curr_device=UNDEFINED;
    
    if(argc == 0 || argc == 1)
	{
		printf ("Usage:\n%s\n", cmdtp->usage);
		return 1;
	}
		
	scanres = find_opt(argv[1], do_ide_opts, sizeof(do_ide_opts)/sizeof(struct match_opt));
	if(argc>2)
  	{
		val1 = atoi(argv[2]);
		if(argc>=3)
			val2 = atoi(argv[3]);
	}
		
	switch(scanres)
  	{
	case -1:
		printf ("Usage:\n%s\n", cmdtp->usage);
		return 1;
	
	case VAL_RESET:
		if(valid_controller_num(val1, &curr_controller))
		{
#ifdef CONFIG_SAM460EX		
			if (curr_controller == 2) 
				sata_460_initialize(&controllers[curr_controller]);
			else
#endif			
				internal_ide_unit_scan(&controllers[curr_controller]);
		}
		else 
		{
			print_no_controller();
		}
		break;
		
	case VAL_INFO:
		if(valid_controller_num(val1, &curr_controller))
		{
			print_controller(curr_controller);
		}
		else print_no_controller();
		break;
		
	case VAL_DEVICE:
		if(valid_controller_num(val1, &curr_controller) && valid_unit_num(curr_controller, val2, &curr_device))
		{
			printf("Device %d on %s selected.\n", curr_device, controllers[curr_controller].cc_description);
		}
		break;
		
	case VAL_PART:
		if(valid_controller_num(val1, &curr_controller) && valid_unit_num(curr_controller, val2, &curr_device))
		{
			block_dev_desc_t * currdev = &controllers[curr_controller].cc_units[curr_device];
			if(currdev->part_type!=PART_TYPE_UNKNOWN)
			{
				print_part(currdev);
			}
		}
		break;
	default:
		printf("Unknown option.\n");
	}
	
	return 1;
}
/*
int local_do_diskboot (cmd_tbl_t *cmdtp, int flag, int argc, char *argv[])
{
	char *boot_device = NULL;
	char *ep;
	int dev, part = 0;
	ulong cnt;
	ulong addr;
	disk_partition_t info;
	image_header_t *hdr;
	int rcode = 0;
	block_dev_desc_t * target_unit;

	switch (argc) {
	case 1:
		addr = CONFIG_SYS_LOAD_ADDR;
		boot_device = getenv ("bootdevice");
		break;
	case 2:
		addr = simple_strtoul(argv[1], NULL, 16);
		boot_device = getenv ("bootdevice");
		break;
	case 3:
		addr = simple_strtoul(argv[1], NULL, 16);
		boot_device = argv[2];
		break;
	case 4:
		{
		WORD tentative_controller = atoi(argv[3]);
		if(valid_controller_num(tentative_controller, &curr_controller))
		{
			addr = simple_strtoul(argv[1], NULL, 16);
			boot_device = argv[2];
			break;
		}
		//If the controller entry is not valid, code will fall through to the default entry.
		}
	default:
		printf ("Usage:\n%s\n", cmdtp->usage);
		SHOW_BOOT_PROGRESS (-1);
		return 1;
	}

	if(curr_controller == UNDEFINED)
	{
		printf ("\n* No valid controller specified *\n", cmdtp->usage);
		SHOW_BOOT_PROGRESS (-1);
		return 1;		
	}
	
	if (!boot_device) {
		puts ("\n* No boot device *\n");
		SHOW_BOOT_PROGRESS (-1);
		return 1;
	}

	dev = simple_strtoul(boot_device, &ep, 16);

	if (!valid_unit_num(curr_controller, dev, NULL))
	{
		printf ("\n* Device %d not available\n", dev);
		SHOW_BOOT_PROGRESS (-1);
		return 1;
	}

	//Now tries to find the partition to boot from, by moving the cursor upto where
	//the end of the boot_device number was.
	if (*ep) {
		if (*ep != ':') {
			puts ("\n* Invalid boot device, use `dev[:part]' *\n");
			SHOW_BOOT_PROGRESS (-1);
			return 1;
		}
		part = simple_strtoul(++ep, NULL, 16);
	}
	
	target_unit = &controllers[curr_controller].cc_units[dev];
	
	if (get_partition_info (target_unit, part, &info)) {
		SHOW_BOOT_PROGRESS (-1);
		return 1;
	}
	
	if ((strncmp(info.type, BOOT_PART_TYPE, sizeof(info.type)) != 0) &&
	    (strncmp(info.type, BOOT_PART_COMP, sizeof(info.type)) != 0)) {
		printf ("\n* Invalid partition type \"%.32s\""
			" (expect \"" BOOT_PART_TYPE "\")\n",
			info.type);
		SHOW_BOOT_PROGRESS (-1);
		return 1;
	}

	printf ("\nLoading from IDE device %d, partition %d: "
		"Name: %.32s  Type: %.32s\n",
		dev, part, info.name, info.type);

	PRINTF ("First Block: %ld,  # of blocks: %ld, Block Size: %ld\n",
		info.start, info.size, info.blksz);

	if (target_unit->block_read (dev, info.start, 1, (ulong *)addr) != 1)
	{
		printf ("* Read error on %d:%d\n", dev, part);
		SHOW_BOOT_PROGRESS (-1);
		return 1;
	}

	hdr = (image_header_t *)addr;

	if (ntohl(hdr->ih_magic) == IH_MAGIC) {

		//print_image_hdr (hdr);

		cnt = (ntohl(hdr->ih_size) + sizeof(image_header_t));
		cnt += info.blksz - 1;
		cnt /= info.blksz;
		cnt -= 1;
	} else {
		printf("\n* Bad Magic Number *\n");
		SHOW_BOOT_PROGRESS (-1);
		return 1;
	}

	if (target_unit->block_read (dev, info.start+1, cnt,
		      (ulong *)(addr+info.blksz)) != cnt) {
		printf ("* Read error on %d:%d\n", dev, part);
		SHOW_BOOT_PROGRESS (-1);
		return 1;
	}

	// Loading ok, update default load address

	load_addr = addr;

	// Check if we should attempt an auto-start
	if (((ep = getenv("autostart")) != NULL) && (strcmp(ep,"yes") == 0)) {
		char *local_args[2];
		extern int do_bootm (cmd_tbl_t *, int, int, char *[]);

		local_args[0] = argv[0];
		local_args[1] = NULL;

		printf ("Automatic boot of image at addr 0x%08lX ...\n", addr);

		do_bootm (cmdtp, 0, 1, local_args);
		rcode = 1;
	}
	return rcode;;
}
*/
