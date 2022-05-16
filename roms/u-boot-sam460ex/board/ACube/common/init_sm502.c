/*
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
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

#ifdef CONFIG_VIDEO_SM502

DECLARE_GLOBAL_DATA_PTR;

#undef DEBUG

#ifdef  DEBUG
#define PRINTF(fmt,args...)     printf (fmt ,##args)
#else
#define PRINTF(fmt,args...)
#endif

unsigned char SM502INIT = 0;
u32 *fb_base_phys_sm502;
pci_dev_t dev_sm502 = ~0;

void init_sm502()
{
    int jj = 0;
	    
	dev_sm502 = pci_find_device(PCI_VENDOR_SM, PCI_DEVICE_SM501, 0);	
 	    
	if (dev_sm502 != -1)
	{
		printf("SM502: found\n");
		PRINTF("calling video_hw_init\n");
		SM502INIT = 1;
		video_hw_init();

		PRINTF("read config\n");
		pci_read_config_dword(dev_sm502, PCI_BASE_ADDRESS_0, &fb_base_phys_sm502);
		*fb_base_phys_sm502 = *fb_base_phys_sm502 & 0xfffff000;
		PRINTF("fb_base = %8x\n",fb_base_phys_sm502);
		
		for (jj=0;jj<256;jj++)
			video_set_lut(jj,jj,jj,jj);
					
		jj = (800 * 600) / 4;
		u32 *tmp = fb_base_phys_sm502;
		while (jj--)
			*tmp++ = 0;		
	}
	else printf("SM502: not found\n");
}
#endif
