/*
 * (C) Copyright 2009-2011
 * Max Tretene, ACube Systems Srl. mtretene@acube-systems.com.
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
#include <pci.h>
#include <sm501.h>
#include <video_fb.h>
#include "../common/vesa.h"

DECLARE_GLOBAL_DATA_PTR;

#undef DEBUG

#ifdef  DEBUG
#define PRINTF(fmt,args...)     printf (fmt ,##args)
#else
#define PRINTF(fmt,args...)
#endif

extern int execute_bios(pci_dev_t gr_dev, void *);

u32 fb_base_phys = 0;
u32 mmio_base_phys = 0;
u32 io_base_phys = 0;

int onbus = -1;

struct FrameBufferInfo *fbi = NULL;

pci_dev_t pci_find_radeon(struct pci_controller *ppc460_hose)
{
	struct pci_controller * hose;
	u16 vendor;
	u8 header_type;
	pci_dev_t bdf;
	int bus, found_multi = 0;

	static struct pci_device_id id;

	id.vendor = PCI_VENDOR_ID_ATI;
	
	for (hose = ppc460_hose; hose; hose = hose->next)
	{
		for (bus = 0; bus <= hose->last_busno; bus++)
		{
			PRINTF("pci_find_radeon %d\n",bus);
			
			for (bdf = PCI_BDF(bus,0,0);
			     bdf < PCI_BDF(bus+1,0,0);
			     bdf += PCI_BDF(0,0,1))
			{
				if (!PCI_FUNC(bdf)) {
					pci_read_config_byte(bdf,
							     PCI_HEADER_TYPE,
							     &header_type);

					found_multi = header_type & 0x80;
				} else {
					if (!found_multi)
						continue;
				}

				pci_read_config_word(bdf,
						     PCI_VENDOR_ID,
						     &vendor);

				if (vendor == id.vendor) 
				{
				    onbus = bus;
				    return bdf;
				}
			}
		}
	}

	return (-1);
}

int init_radeon(struct pci_controller *hose)
{
    int jj;
	unsigned char agp_control;
	unsigned short cmd, devcmd;
	pci_dev_t dev = ~0;
	pci_dev_t bridge = ~0;
	    
 	puts("VGA:   ");
 	    
	dev = pci_find_radeon(hose);
 	
	if (dev != -1)
	{
		PRINTF("RADEON found on %02x:%02x:%02x\n",
			PCI_BUS(dev), PCI_DEV(dev), PCI_FUNC(dev));
			
		// ----------------------------------------------------------	
			
		PRINTF("Shutting down graphics card at %x.%x.%x\n",
			PCI_BUS(dev), PCI_DEV(dev), PCI_FUNC(dev));
			
		// Graphics card...
		pci_read_config_word(dev, PCI_COMMAND, &cmd);
		
		devcmd = cmd;
		cmd &= ~(PCI_COMMAND_IO|PCI_COMMAND_MEMORY);
		
		pci_write_config_word(dev, PCI_COMMAND, cmd);
		PRINTF("    CMD register now %X\n", cmd);
		
		// ----------------------------------------------------------	

		//bridge = pci_find_bridge_for_bus(hose, PCI_BUS(dev));

		bridge = PCI_BDF(0,0,0);
		PRINTF("Behind bridge (%d) at %02x:%02x:%02x\n", bridge,
			PCI_BUS(bridge), PCI_DEV(bridge), PCI_FUNC(bridge));			

	    pci_read_config_byte(bridge, 0x3E, &agp_control);
   		agp_control |= 0x18;
	    pci_write_config_byte(bridge, 0x3E, agp_control);

		// ----------------------------------------------------------	
		
		PRINTF("Re-enabling %x.%x.%x\n",
			PCI_BUS(dev), PCI_DEV(dev), PCI_FUNC(dev));

		pci_write_config_word(dev,
			PCI_COMMAND, devcmd | PCI_COMMAND_IO | PCI_COMMAND_MEMORY);
		
		// ----------------------------------------------------------
		
#ifdef DEBUG2
    	PRINTF("\nCard Summary\n------------\n");
    	{
        	int bar, found_mem64;
        	unsigned int bar_response;
		    unsigned int io, mem;
		   	pci_addr_t bar_value;
        	pci_size_t bar_size;
	    	
        	for (bar = PCI_BASE_ADDRESS_0; bar < PCI_BASE_ADDRESS_5; bar += 4) {
        		pci_write_config_dword (dev, bar, 0xffffffff);
        		pci_read_config_dword (dev, bar, &bar_response);
        
        		if (!bar_response)
        			continue;
        
        		found_mem64 = 0;
        		io = 0;
        		mem = 0;
        
        		/* Check the BAR type and set our address mask */
        		if (bar_response & PCI_BASE_ADDRESS_SPACE) {
        			bar_size = ~(bar_response & PCI_BASE_ADDRESS_IO_MASK) + 1;
        			/* round up region base address to a multiple of size */
        			io = 1; //((io - 1) | (bar_size - 1)) + 1;
        			//bar_value = io;
        			/* compute new region base address */
        			//io = io + bar_size;
        		} else {
        			if ((bar_response & PCI_BASE_ADDRESS_MEM_TYPE_MASK) ==
        				PCI_BASE_ADDRESS_MEM_TYPE_64) {
        				u32 bar_response_upper;
        				u64 bar64;
        				pci_write_config_dword(dev, bar+4, 0xffffffff);
        				pci_read_config_dword(dev, bar+4, &bar_response_upper);
        
        				bar64 = ((u64)bar_response_upper << 32) | bar_response;
        
        				bar_size = ~(bar64 & PCI_BASE_ADDRESS_MEM_MASK) + 1;
        				found_mem64 = 1;
        			} else {
        				bar_size = (u32)(~(bar_response & PCI_BASE_ADDRESS_MEM_MASK) + 1);
        			}
        
        			/* round up region base address to multiple of size */
        			mem = 1; //((mem - 1) | (bar_size - 1)) + 1;
        			//bar_value = mem;
        			/* compute new region base address */
        			//mem = mem + bar_size;
        		} 
        		
        		u32 low, high;       		
        		low = bar_size & 0xffffffff;       		
        		if (found_mem64) high = (bar_size >> 32) & 0xffffffff;
        		else high = 0;
        		       
        		PRINTF("bar_size = %08x%08x, io = %x, mem = %x mem64 = %x\n", high, low, io, mem, found_mem64);
        		
        		if (found_mem64) bar += 4;  	
    	    }
    	}
#endif	
		
		pci_read_config_dword(dev, PCI_BASE_ADDRESS_2, &mmio_base_phys);
		mmio_base_phys &= ~0x0F;
		PRINTF("mmio_base_phys = %08x\n",mmio_base_phys);

        /* here we assume that a Radeon is on bus 0 (PCI)            */
        /* and a RadeonHD is on bus 1 or higher (PCI or PCI-E)       */
        
        if (onbus == 0)
          pci_read_config_dword(dev, PCI_BASE_ADDRESS_1, &io_base_phys);       
        else
          pci_read_config_dword(dev, PCI_BASE_ADDRESS_4, &io_base_phys);
        
		io_base_phys &= ~0x0F;
		PRINTF("io_base = %08x\n",io_base_phys);

        pci_read_config_dword(dev, PCI_BASE_ADDRESS_0, &fb_base_phys);
        fb_base_phys &= ~0x0F;
        PRINTF("fb_base = %08x\n",fb_base_phys);
    		     		
		PRINTF("executing bios onbus=%d\n",onbus);

		if (execute_bios(dev, TEXT_BASE))		
		{
			puts("1\n");
			
            u32 *tmp = fb_base_phys;
			
			jj = (640 * 480) / 4;
    		while (jj--)
    		  *tmp++ = 0;
    		     			
    		puts("VESA:  ");
    		
    		// 257 = 640 x 480 - 8 bit 
    		// 259 = 800 x 600 - 8 bit
    		fbi = set_vesa_mode(257);
    				
    		if (fbi)
    		{
    			puts("OK\n");
    			
    			// fixme: there is a problem with some radeon cards
    			// the fbi structure isn't filled with the required
    			// information, here we fill it in such case

				PRINTF("%08x %d %d %d %d\n",fbi->BaseAddress,
					fbi->XSize,
					fbi->YSize,
					fbi->BitsPerPixel,
					fbi->Modulo);
						    								
				if (fbi->BaseAddress != fb_base_phys)
				{
					fbi->BaseAddress = fb_base_phys;
					fbi->XSize = 640;
					fbi->YSize = 480;
					fbi->BitsPerPixel = 8;
					fbi->Modulo = 640;	

					PRINTF("%08x %d %d %d %d\n",fbi->BaseAddress,
						fbi->XSize,
						fbi->YSize,
						fbi->BitsPerPixel,
						fbi->Modulo);
				}
												
    			drv_video_init();
    		}
    		else
    			puts("ERROR\n");		
    				
			return 1;
		}	
		else puts("ERROR EXECUTING BIOS\n");	
	}
	else puts("NO CARDS\n");

    return 0;
}
