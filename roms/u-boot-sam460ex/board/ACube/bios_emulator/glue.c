#include <common.h>
#include <pci.h>

DECLARE_GLOBAL_DATA_PTR;

#undef DEBUG

#ifdef DEBUG
#define PRINTF(format, args...) printf(format , ## args)
#else
#define PRINTF(format, argc...)
#endif

#ifdef CONFIG_SAM460EX
extern struct pci_controller *ppc460_hose;
#endif

static pci_dev_t to_pci(int bus, int devfn)
{
    return PCI_BDF(bus, (devfn>>3), devfn&3);
}

int mypci_find_device(int vendor, int product, int index)
{
    return pci_find_device(vendor, product, index);
}

int mypci_bus(int device)
{
    return PCI_BUS(device);
}

int mypci_devfn(int device)
{
    return (PCI_DEV(device)<<3) | PCI_FUNC(device);
}


#define mypci_read_func(type, size)				\
type mypci_read_cfg_##size(int bus, int devfn, int offset)	\
{								\
    type c;							\
    pci_read_config_##size(to_pci(bus, devfn), offset, &c);	\
    return c;							\
}

#define mypci_write_func(type, size)				\
void mypci_write_cfg_##size(int bus, int devfn, int offset, int value)	\
{								\
    pci_write_config_##size(to_pci(bus, devfn), offset, value);	\
}

mypci_read_func(u8,byte);
mypci_read_func(u16,word);

mypci_write_func(u8,byte);
mypci_write_func(u16,word);

u32 mypci_read_cfg_long(int bus, int devfn, int offset)
{
    u32 c;
    pci_read_config_dword(to_pci(bus, devfn), offset, &c);
    return c;
}

void mypci_write_cfg_long(int bus, int devfn, int offset, int value)
{
    pci_write_config_dword(to_pci(bus, devfn), offset, value);
}

unsigned long get_bar_size(pci_dev_t dev, int offset)
{
    u32 bar_back, bar_value;

    /*  Save old BAR value */
    pci_read_config_dword(dev, offset, &bar_back);

    /*  Write all 1's. */
    pci_write_config_dword(dev, offset, ~0);

    /*  Now read back the relevant bits */
    pci_read_config_dword(dev, offset, &bar_value);

    /*  Restore original value */
    pci_write_config_dword(dev, offset, bar_back);

    if (bar_value == 0) return 0xFFFFFFFF; /*  This BAR is disabled */
    
    PRINTF("get_bar_size %08x\n",bar_value);

    if ((bar_value & PCI_BASE_ADDRESS_SPACE) == PCI_BASE_ADDRESS_SPACE_MEMORY)
    {
	/*  This is a memory space BAR. Mask it out so we get the size of it */
	return ~(bar_value & PCI_BASE_ADDRESS_MEM_MASK) + 1;
    }

    /*  Not suitable */
    return 0xFFFFFFFF;
}

#ifdef DEBUG
unsigned long get_real_size(pci_dev_t dev, int offset)
{
    u32 bar_back, bar_value;

    /*  Save old BAR value */
    pci_read_config_dword(dev, offset, &bar_back);

    /*  Write all 1's. */
    pci_write_config_dword(dev, offset, ~0);

    /*  Now read back the relevant bits */
    pci_read_config_dword(dev, offset, &bar_value);

    /*  Restore original value */
    pci_write_config_dword(dev, offset, bar_back);

    if (bar_value == 0) return 0;

    if ((bar_value & PCI_BASE_ADDRESS_SPACE) == PCI_BASE_ADDRESS_SPACE_MEMORY)
    {
		/*  This is a memory space BAR. Mask it out so we get the size of it */
		return ~(bar_value & PCI_BASE_ADDRESS_MEM_MASK) + 1;
    }
    
    if ((bar_value & PCI_BASE_ADDRESS_SPACE) == PCI_BASE_ADDRESS_SPACE_IO)
    {
    	return ~(bar_value & PCI_BASE_ADDRESS_IO_MASK) + 1;
    }

    return 0;
}
#endif

void enable_compatibility_hole(void)
{
    u8 cfg;
    pci_dev_t art = PCI_BDF(0,0,0);

    pci_read_config_byte(art, 0x54, &cfg);
    /* cfg |= 0x08; */
    cfg |= 0x20;
    pci_write_config_byte(art, 0x54, cfg);
}

void disable_compatibility_hole(void)
{
    u8 cfg;
    pci_dev_t art = PCI_BDF(0,0,0);

    pci_read_config_byte(art, 0x54, &cfg);
    /* cfg &= ~0x08; */
    cfg &= ~0x20;
    pci_write_config_byte(art, 0x54, cfg);
}

void map_rom(pci_dev_t dev, u32 address)
{
    pci_write_config_dword(dev, PCI_ROM_ADDRESS, address|PCI_ROM_ADDRESS_ENABLE);
}

void unmap_rom(pci_dev_t dev)
{
    pci_write_config_dword(dev, PCI_ROM_ADDRESS, 0);
}

void bat_map(u8 batnum, u32 address, u32 length)
{
	return;
    u32 temp = address;
    address &= 0xFFFE0000;
    temp    &= 0x0001FFFF;
    length = (length - 1 ) >> 17;
    length <<= 2;

    switch (batnum)
    {
    case 0:
	__asm volatile ("mtdbatu 0, %0" : : "r" (address | length | 3));
	__asm volatile ("mtdbatl 0, %0" : : "r" (address | 0x22));
	break;
    case 1:
	__asm volatile ("mtdbatu 1, %0" : : "r" (address | length | 3));
	__asm volatile ("mtdbatl 1, %0" : : "r" (address | 0x22));
	break;
    case 2:
	__asm volatile ("mtdbatu 2, %0" : : "r" (address | length | 3));
	__asm volatile ("mtdbatl 2, %0" : : "r" (address | 0x22));
	break;
    case 3:
	__asm volatile ("mtdbatu 3, %0" : : "r" (address | length | 3));
	__asm volatile ("mtdbatl 3, %0" : : "r" (address | 0x22));
	break;
    }
}

void clear_bat2(void)
{
	return;
    u32 temp = 0;
    __asm volatile(
	"mtdbatu 2, %0\n"
	"mtdbatl 2, %0\n"
	"mtibatu 2, %0\n"
	"mtibatl 2, %0\n"
	: : "r" (temp));
}

void find_radeon_values(pci_dev_t dev, u8 * rom_addr)
{
	u16 bios_header;
	u16 pll_info_block;
	struct radeon_data
	{
		unsigned short ReferenceFrequency;
		unsigned short ReferenceDivider;
		unsigned long PLLMin;
		unsigned long PLLMax;
	} __attribute__((packed));
	u16 vendor;
	
	struct radeon_data *rdat;
	
	DECLARE_GLOBAL_DATA_PTR;
	
	/* If it's an ATI card, get the values needed by the driver */
	pci_read_config_word(dev, PCI_VENDOR_ID, &vendor);
	if (vendor != 0x1002)
		return;
		
	gd->bd->bi_sramstart = malloc(sizeof(struct radeon_data));
	rdat = (struct radeon_data *) gd->bd->bi_sramstart;
	
	bios_header = rom_addr[0x48] | (rom_addr[0x49]<<8);
	bios_header += 0x30;
	pll_info_block = rom_addr[bios_header] | (rom_addr[bios_header+1]<<8);
	pll_info_block += 0x0e;
	
	rdat->ReferenceFrequency = rom_addr[pll_info_block] | (rom_addr[pll_info_block+1]<<8);
	pll_info_block += 2;
	
	rdat->ReferenceDivider = rom_addr[pll_info_block] | (rom_addr[pll_info_block+1]<<8);
	pll_info_block += 2;
	
	rdat->PLLMin =  rom_addr[pll_info_block]
				 | (rom_addr[pll_info_block+1]<<8)
				 | (rom_addr[pll_info_block+2]<<16)
				 | (rom_addr[pll_info_block+3]<<14);
	pll_info_block += 4;

	rdat->PLLMax =  rom_addr[pll_info_block]
				 | (rom_addr[pll_info_block+1]<<8)
				 | (rom_addr[pll_info_block+2]<<16)
				 | (rom_addr[pll_info_block+3]<<14);
}
				 
				 
int find_image(u32 rom_address, u32 rom_size, void **image, u32 *image_size);

#if defined(CONFIG_SAM440EP)  
#include "radeon_bios.h"

void load_compressed_bios(void *copy_address)
{
    memcpy(copy_address, radeon_bios, 65536);
}
#endif

int attempt_map_rom(pci_dev_t dev, void *copy_address)
{
    u32 rom_size      = 0;
    u32 rom_address   = 0;
    u32 bar_size      = 0;
    u32 bar_backup    = 0;
    int i;
    void *image       = 0;
    u32 image_size    = 0;
    u32 prefetch_idx  = 0;
    u32 lower         = 0xFFFFFFFF;
    u32 upper         = 0x00000000;
    u32 mlower        = 0xFFFFFFFF;
    u32 mupper        = 0x00000000;
    int foundimg      = 0;
    int foundmini     = 0;
    u16 vendor        = 0;
    //u32 iobase        = 0;

//#ifdef CONFIG_SAM460EX
//	struct pci_region *isaio = ppc460_hose->regions+0;
//#else    
//	struct pci_region *isaio = gd->ppc440_hose->regions+0;
//#endif
		
    /*  Get the size of the VGA expansion rom */

#if defined(CONFIG_SAM440EP) 
    if(PCI_BUS(dev) == 0 && PCI_DEV(dev) == 0xc)
    {
        foundmini = 1;
        rom_size  = 64*1024;
        PRINTF("FOUNDMINI\n");	    	
    }
    else
#endif   
    {
        pci_write_config_dword(dev, PCI_ROM_ADDRESS, 0xFFFFFFFF);
        pci_read_config_dword(dev, PCI_ROM_ADDRESS, &rom_size);
        if ((rom_size & 0x01) == 0)
        {
            PRINTF("No ROM\n");
            return 0;
        }
        else
        {
            rom_size &= 0xFFFFF800;
            rom_size = (~rom_size)+1;
        }
    }

    PRINTF("ROM Size is %dK\n", rom_size/1024);
    
    /*
     * Try to find a place for the ROM. We always attempt to use
     * one of the card's bases for this, as this will be in any
     * bridge's resource range as well as being free of conflicts
     * with other cards. In a graphics card it is very unlikely
     * that there won't be any base address that is large enough to
     * hold the rom.
     *
     * FIXME: To work around this, theoretically the largest base
     * could be used if none is found in the loop below.
     */

    //for (i = PCI_BASE_ADDRESS_0; i <= PCI_BASE_ADDRESS_5; i += 4)
    i = PCI_BASE_ADDRESS_0;
    {
        bar_size = get_bar_size(dev, i);
        PRINTF("PCI_BASE_ADDRESS_%d is %dK large\n", (i - PCI_BASE_ADDRESS_0)/4, bar_size/1024);
        
        if ((bar_size & PCI_BASE_ADDRESS_MEM_TYPE_MASK) == PCI_BASE_ADDRESS_MEM_TYPE_64) {
            PRINTF("MEM64 found\n");
            rom_address = 0xa0000000;
            //return 0;
        } else {
            if (bar_size != 0xFFFFFFFF && bar_size >= rom_size)
            {
                PRINTF("Found a match for rom size\n");
                pci_read_config_dword(dev, i, &rom_address);
                rom_address &= 0xFFFFFFF0;
            }
        }
    }

    PRINTF("Rom is being mapped to %p\n", rom_address);

    if (rom_address == 0 || rom_address == 0xFFFFFFF0)
    {
        PRINTF("No suitable rom address found\n");
        return 0;
    }

    /*  Disable the BAR */
    pci_read_config_dword(dev, i, &bar_backup);
    pci_write_config_dword(dev, i, 0);

    /*  Map ROM */
    pci_write_config_dword(dev, PCI_ROM_ADDRESS, rom_address | PCI_ROM_ADDRESS_ENABLE);

    /*  Copy the rom to a place in the emulator space */
    PRINTF("Trying to find an X86 BIOS image in ROM\n");

#if defined(CONFIG_SAM440EP)  
    if (foundmini == 1)
    {
    	load_compressed_bios(copy_address);
    }
    else
#endif    
    {
        foundimg = find_image(rom_address, rom_size, &image, &image_size);

        PRINTF("find_image return %d\n", foundimg);
        if (foundimg == 0)
        {
            PRINTF("No x86 BIOS image found\n");
            return 0;
        }

        PRINTF("Copying %ld bytes from 0x%lx to 0x%lx\n", (long)image_size, (long)image, (long)copy_address);

        memcpy(copy_address, rom_address, rom_size);
//        {
//            unsigned char *from = (unsigned char *)image; /* rom_address; */
//            unsigned char *to = (unsigned char *)copy_address;
//            PRINTF("----- ROM STARTS HERE -----------\n");
//            for (j=0; j<image_size /*rom_size*/; j++)
//            {
//                //PRINTF("%c", *from);
//                *to++ = *from++;
//            }
//            PRINTF("----- ROM ENDS HERE --------------\n");
//        }
    }

    PRINTF("Copy is done\n");

    /* If it's an ATI card, get the values needed by the driver */
    pci_read_config_word(dev, PCI_VENDOR_ID, &vendor);
    if ( (vendor == 0x1002) || (foundmini == 1) )
        find_radeon_values(dev, copy_address);
		
    clear_bat2();

    /*  Unmap the ROM and restore the BAR */
    pci_write_config_dword(dev, PCI_ROM_ADDRESS, 0);
    pci_write_config_dword(dev, i, bar_backup);

	//iobase = isaio->bus_lower;
	//PRINTF("GLUE.C IOBASE = %x\n",iobase);

#ifdef DEBUG
	PRINTF("\n\nCard Summary\n------------\n");
	{
		int x=0;
		for (i = PCI_BASE_ADDRESS_0; i <= PCI_BASE_ADDRESS_5; i += 4)
		{
    		u32 bar_size = get_real_size(dev, i);
    		u32 bar;
        		
            if (bar_size != 0xFFFFFFFF && bar_size != 0x00000000)
            {
				pci_read_config_dword(dev, i, &bar);
			
				PRINTF("PCI_BASE_ADDRESS_%d: %p-%p",
					x, bar&0xFFFFFFF0, (bar&0xFFFFFFF0)+bar_size);
				if ((bar&PCI_BASE_ADDRESS_SPACE))
				{
					PRINTF(" (io)\n");
				}
  				else
  				{
 					PRINTF("(memory");
   					if (bar & PCI_BASE_ADDRESS_MEM_PREFETCH)
   						PRINTF(",prefetch)\n");
   					else
   						PRINTF(")\n");
   				}
   			}
   			++x;
		}
	}
#endif

    return 1;
}

int find_image(u32 rom_address, u32 rom_size, void **image, u32 *image_size)
{
#ifdef DEBUG
    int i = 0;
#endif    
    unsigned char *rom = (unsigned char *)rom_address;

	PRINTF("find_image:\n");
	PRINTF("rom_address = %p\n", rom_address);

    /* if (*rom != 0x55 || *(rom+1) != 0xAA) return 0; // No bios rom this is, yes. */
#if 1
	{
		int j;
		unsigned int length;
		unsigned int data_offs = *(rom+0x18) + 256* *(rom+0x19);
		
		PRINTF("Rom data offset at %p\n", data_offs);
		PRINTF("Rom header: ");
		for (j=0; j<0x16; j++)
		{
			PRINTF("%02x ", *(rom+j));
		}
		PRINTF("\n");
		PRINTF("Image header: ");
		for (j=0; j<0x16; j++)
		{
			PRINTF("%02x ", *(rom+j+data_offs));
		}
		PRINTF("\n");
		length = *(rom+data_offs+0x10) + 256* *(rom+data_offs+0x11);
		PRINTF("length: raw=%d, yields %d\n", length, length*512);
	}
#endif	
    for (;;)
    {
		unsigned int pci_data_offset = *(rom+0x18) + 256 * *(rom+0x19);
		unsigned int pci_image_length = (*(rom+pci_data_offset+0x10) + 256 * *(rom+pci_data_offset+0x11)) * 512;
		unsigned char pci_image_type = *(rom+pci_data_offset+0x14);
		if (*rom != 0x55 || *(rom+1) != 0xAA)
		{
		    PRINTF("Invalid header this is\n");
	    	return 0;
		}
		PRINTF("Image %i: Type %d (%s)\n", i++, pci_image_type,
	    	   pci_image_type==0 ? "x86" :
		       	pci_image_type==1 ? "OpenFirmware" :
		       "Unknown");
		PRINTF("Image size: %d\n", pci_image_length);
		if (pci_image_type == 0)
		{
		    *image = rom;
		    *image_size = pci_image_length;
	    	return 1;
		}

		if (*(rom+pci_data_offset+0x15) & 0x80)
		{
		    PRINTF("LAST image encountered, no image found\n");
	    	return 0;
		}

		rom += pci_image_length;
    }
}

void show_bat_mapping(void)
{

}

void remove_init_data(void)
{
	//invalidate_l1_data_cache();
	dcache_disable();
	icache_enable();
	//l1dcache_enable();
/*
    char *s;

    //  Invalidate and disable data cache
    invalidate_l1_data_cache();
    l2cache_invalidate();
    dcache_disable();

    s = getenv("x86_cache");

    if (!s)
    {
	icache_enable();
	l1dcache_enable();
    }
    else if (s)
    {
        if (strcmp(s, "dcache")==0)
        {
	    l1dcache_enable();
        }
        else if (strcmp(s, "icache") == 0)
        {
            icache_enable();
        }
        else if (strcmp(s, "on")== 0 || strcmp(s, "both") == 0)
        {
            l1dcache_enable();
            icache_enable();
        }
    }

    l2cache_disable();
    //   show_bat_mapping();
*/
}
