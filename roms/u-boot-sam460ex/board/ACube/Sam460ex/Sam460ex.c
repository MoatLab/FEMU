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
#include <ppc440.h>
#include <libfdt.h>
#include <fdt_support.h>
#include <i2c.h>
#include <asm/processor.h>
#include <asm/io.h>
#include <asm/mmu.h>
#include <asm/4xx_pcie.h>
#include <asm/gpio.h>
#include <asm/errno.h>
#include <sm501.h>
#include "../common/vesa.h"

#undef DEBUG

#ifdef  DEBUG
#define PRINTF(fmt,args...)     printf (fmt ,##args)
#else
#define PRINTF(fmt,args...)
#endif

#define SAMLOGO
#ifdef SAMLOGO
#include "../common/logo_acube.h"
#else
#define LOGO_WIDTH 176
#define LOGO_HEIGHT 48
unsigned char logo_acube[LOGO_WIDTH * LOGO_HEIGHT] = { 0 };
#endif

#ifndef CONFIG_SYS_NO_FLASH
extern flash_info_t flash_info[CONFIG_SYS_MAX_FLASH_BANKS]; /* info for FLASH chips */
#endif

DECLARE_GLOBAL_DATA_PTR;

#define BOARD_CANYONLANDS_PCIE	1
#define BOARD_CANYONLANDS_SATA	2

extern int onbus;
extern int console_col; /* cursor col */
extern int console_row; /* cursor row */

extern u32 *fb_base_phys_sm502;
extern unsigned char SM502INIT;
extern pci_dev_t dev_sm502;
extern struct FrameBufferInfo *fbi;

unsigned char SM502 = 0;
struct pci_controller *ppc460_hose = NULL;

/*
 * Override the default functions in cpu/ppc4xx/44x_spd_ddr2.c with
 * board specific values.
 */
 
u32 ddr_wrdtr(u32 default_val) {
	return (SDRAM_WRDTR_LLWP_1_CYC | SDRAM_WRDTR_WTR_180_DEG_ADV | 0x823);
}

u32 ddr_clktr(u32 default_val) {
	return (SDRAM_CLKTR_CLKP_90_DEG_ADV);
}

static int pvr_460ex(void)
{
	u32 pvr = get_pvr();

	if ((pvr == PVR_460EX_RA) || (pvr == PVR_460EX_SE_RA) ||
	    (pvr == PVR_460EX_RB))
		return 1;

	return 0;
}

int board_early_init_f(void)
{
	u32 sdr0_cust0;
	
	/*
	 * Setup the interrupt controller polarities, triggers, etc.
	 */
	 
	// Sam460ex IRQ MAP:
    // IRQ0  = ETH_INT
    // IRQ1  = FPGA_INT
    // IRQ2  = PCI_INT (PCIA, PCIB, PCIC, PCIB)
    // IRQ3  = FPGA_INT2
    // IRQ11 = RTC_INT
    // IRQ12 = SM502_INT
    
	mtdcr(UIC0SR, 0xffffffff);	/* clear all */
	mtdcr(UIC0ER, 0x00000000);	/* disable all */
	mtdcr(UIC0CR, 0x00000005);	/* ATI & UIC1 crit are critical */
	mtdcr(UIC0PR, 0xffffffff);	/* per ref-board manual */
	mtdcr(UIC0TR, 0x00000000);	/* per ref-board manual */
	mtdcr(UIC0VR, 0x00000000);	/* int31 highest, base=0x000 */
	mtdcr(UIC0SR, 0xffffffff);	/* clear all */

	mtdcr(UIC1SR, 0xffffffff);	/* clear all */
	mtdcr(UIC1ER, 0x00000000);	/* disable all */
	mtdcr(UIC1CR, 0x00000000);	/* all non-critical */
	mtdcr(UIC1PR, 0xefffffff);	/* IRQ2 neg */
	mtdcr(UIC1TR, 0x00000000);	/* per ref-board manual */
	mtdcr(UIC1VR, 0x00000000);	/* int31 highest, base=0x000 */
	mtdcr(UIC1SR, 0xffffffff);	/* clear all */

	mtdcr(UIC2SR, 0xffffffff);	/* clear all */
	mtdcr(UIC2ER, 0x00000000);	/* disable all */
	mtdcr(UIC2CR, 0x00000000);	/* all non-critical */
	mtdcr(UIC2PR, 0xffffffff);	/* per ref-board manual */
	mtdcr(UIC2TR, 0x00000000);	/* per ref-board manual */
	mtdcr(UIC2VR, 0x00000000);	/* int31 highest, base=0x000 */
	mtdcr(UIC2SR, 0xffffffff);	/* clear all */

	mtdcr(UIC3SR, 0xffffffff);	/* clear all */
	mtdcr(UIC3ER, 0x00000000);	/* disable all */
	mtdcr(UIC3CR, 0x00000000);	/* all non-critical */
	mtdcr(UIC3PR, 0xffefffff);	/* IRQ12 neg */
	mtdcr(UIC3TR, 0x00000000);	/* per ref-board manual */
	mtdcr(UIC3VR, 0x00000000);	/* int31 highest, base=0x000 */
	mtdcr(UIC3SR, 0xffffffff);	/* clear all */
	
	/* SDR Setting - enable NDFC */
	mfsdr(SDR0_CUST0, sdr0_cust0);
	sdr0_cust0 = SDR0_CUST0_MUX_NDFC_SEL	|
		SDR0_CUST0_NDFC_ENABLE		|
		SDR0_CUST0_NDFC_BW_8_BIT	|
		SDR0_CUST0_NDFC_ARE_MASK	|
		SDR0_CUST0_NDFC_BAC_ENCODE(3)	|
		(0x80000000 >> (28 + CONFIG_SYS_NAND_CS));
	mtsdr(SDR0_CUST0, sdr0_cust0);

	/*
	 * Configure PFC (Pin Function Control) registers
	 * Enable GPIO 49-63
	 * UART0: 8 pins
	 */
	mtsdr(SDR0_PFC0, 0x00007fff);
	mtsdr(SDR0_PFC1, 0x00000000);

	/* Enable PCI host functionality in SDR0_PCI0 */
	mtsdr(SDR0_PCI0, 0xa0000000);
	
	mtsdr(SDR0_SRST1, 0);	/* Pull AHB out of reset default=1 */

	/* Setup PLB4-AHB bridge based on the system address map */
	mtdcr(AHB_TOP, 0x8000004B);
	mtdcr(AHB_BOT, 0x8000004B);
		
	return 0;
}

static void canyonlands_sata_init(int board_type)
{
	u32 reg;

	if (board_type == BOARD_CANYONLANDS_SATA) {
		/* Put SATA in reset */
		SDR_WRITE(SDR0_SRST1, 0x00020001);

		/* Set the phy for SATA, not PCI-E port 0 */
		reg = SDR_READ(PESDR0_PHY_CTL_RST);
		SDR_WRITE(PESDR0_PHY_CTL_RST, (reg & 0xeffffffc) | 0x00000001);
		reg = SDR_READ(PESDR0_L0CLK);
		SDR_WRITE(PESDR0_L0CLK, (reg & 0xfffffff8) | 0x00000007);
		SDR_WRITE(PESDR0_L0CDRCTL, 0x00003111);
		SDR_WRITE(PESDR0_L0DRV, 0x00000104);

		/* Bring SATA out of reset */
		SDR_WRITE(SDR0_SRST1, 0x00000000);
	}
}

int checkboard(void)
{
	char s[64] = { 0 };
		 
	gd->board_type = BOARD_CANYONLANDS_PCIE;
	getenv_r("serdes",s,64);

	if (strcmp(s,"sata2") == 0)
		gd->board_type = BOARD_CANYONLANDS_SATA;
	
	puts("Board: Sam460ex, PCIe 4x + ");

	switch (gd->board_type) {
	case BOARD_CANYONLANDS_PCIE:
		puts("PCIe 1x\n");
		break;

	case BOARD_CANYONLANDS_SATA:
		puts("SATA-2\n");
		break;
	}

	canyonlands_sata_init(gd->board_type);

	return (0);
}

/*************************************************************************
 *  pci_pre_init
 *
 *  This routine is called just prior to registering the hose and gives
 *  the board the opportunity to check things. Returning a value of zero
 *  indicates that things are bad & PCI initialization should be aborted.
 *
 *	Different boards may wish to customize the pci controller structure
 *	(add regions, override default access routines, etc) or perform
 *	certain pre-initialization actions.
 *
 ************************************************************************/
#if defined(CONFIG_PCI)
int pci_pre_init(struct pci_controller * hose )
{
	ppc460_hose = hose;

	return 1;
}
#endif	/* defined(CONFIG_PCI) */

#if defined(CONFIG_PCI) && defined(CONFIG_SYS_PCI_MASTER_INIT)
void pci_master_init(struct pci_controller *hose)
{
	/*--------------------------------------------------------------------------+
	  | PowerPC440 PCI Master configuration.
	  | Map PLB/processor addresses to PCI memory space.
	  |   PLB address 0xA0000000-0xCFFFFFFF ==> PCI address 0x80000000-0xCFFFFFFF
	  |   Use byte reversed out routines to handle endianess.
	  | Make this region non-prefetchable.
	  +--------------------------------------------------------------------------*/
	out32r(PCIL0_POM0SA, 0 ); /* disable */
	out32r(PCIL0_POM1SA, 0 ); /* disable */
	out32r(PCIL0_POM2SA, 0 ); /* disable */

	out32r(PCIL0_POM0LAL, CONFIG_SYS_PCI_MEMBASE);		/* PMM0 Local Address */
	out32r(PCIL0_POM0LAH, 0x0000000c);					/* PMM0 Local Address */
	out32r(PCIL0_POM0PCIAL, CONFIG_SYS_PCI_MEMBASE);	/* PMM0 PCI Low Address */
	out32r(PCIL0_POM0PCIAH, 0x00000000);				/* PMM0 PCI High Address */
	out32r(PCIL0_POM0SA, ~(0x10000000 - 1) | 1);		/* 256MB + enable region */

	out32r(PCIL0_POM1LAL, CONFIG_SYS_PCI_MEMBASE2);		/* PMM0 Local Address */
	out32r(PCIL0_POM1LAH, 0x0000000c);					/* PMM0 Local Address */
	out32r(PCIL0_POM1PCIAL, CONFIG_SYS_PCI_MEMBASE2);	/* PMM0 PCI Low Address */
	out32r(PCIL0_POM1PCIAH, 0x00000000);				/* PMM0 PCI High Address */
	out32r(PCIL0_POM1SA, ~(0x10000000 - 1) | 1);		/* 256MB + enable region */
	
	out_le16((void *)PCIL0_CMD, in16r(PCIL0_CMD) | PCI_COMMAND_MASTER);		
}
#endif /* defined(CONFIG_PCI) && defined(CONFIG_SYS_PCI_MASTER_INIT) */

#if defined(CONFIG_PCI)
int board_pcie_first(void)
{
	/*
	 * Canyonlands with SATA enabled has only one PCIe slot
	 * (2nd one).
	 */
	if (gd->board_type == BOARD_CANYONLANDS_SATA)
		return 1;

	return 0;
}
#endif /* CONFIG_PCI */

int board_early_init_r (void)
{
	/*
	 * Clear potential errors resulting from auto-calibration.
	 * If not done, then we could get an interrupt later on when
	 * exceptions are enabled.
	 */
	 
	set_mcsr(get_mcsr());

	return 0;
}

int misc_init_r(void)
{
	u32 sdr0_srst1 = 0;
	u32 eth_cfg;
	u8 val;

	/*
	 * Set EMAC mode/configuration (GMII, SGMII, RGMII...).
	 * This is board specific, so let's do it here.
	 */
	mfsdr(SDR0_ETH_CFG, eth_cfg);
	/* disable SGMII mode */
	eth_cfg &= ~(SDR0_ETH_CFG_SGMII2_ENABLE |
		     SDR0_ETH_CFG_SGMII1_ENABLE |
		     SDR0_ETH_CFG_SGMII0_ENABLE);
	/* Set the for 2 RGMII mode */
	/* GMC0 EMAC4_0, GMC0 EMAC4_1, RGMII Bridge 0 */
	eth_cfg &= ~SDR0_ETH_CFG_GMC0_BRIDGE_SEL;
	if (pvr_460ex())
		eth_cfg |= SDR0_ETH_CFG_GMC1_BRIDGE_SEL;
	else
		eth_cfg &= ~SDR0_ETH_CFG_GMC1_BRIDGE_SEL;
	mtsdr(SDR0_ETH_CFG, eth_cfg);

	/*
	 * The AHB Bridge core is held in reset after power-on or reset
	 * so enable it now
	 */
	mfsdr(SDR0_SRST1, sdr0_srst1);
	sdr0_srst1 &= ~SDR0_SRST1_AHB;
	mtsdr(SDR0_SRST1, sdr0_srst1);

	/*
	 * RTC/M41T62:
	 * Disable square wave output: Batterie will be drained
	 * quickly, when this output is not disabled
	 */
	val = i2c_reg_read(CONFIG_SYS_I2C_RTC_ADDR, 0xa);
	val &= ~0x40;
	i2c_reg_write(CONFIG_SYS_I2C_RTC_ADDR, 0xa, val);

	return 0;
}

#if defined(CONFIG_OF_LIBFDT) && defined(CONFIG_OF_BOARD_SETUP)
void ft_board_setup(void *blob, bd_t *bd)
{
	u32 val[4];
	int rc;

	ft_cpu_setup(blob, bd);

	/* Fixup NOR mapping */
	val[0] = 0;				/* chip select number */
	val[1] = 0;				/* always 0 */
	val[2] = CONFIG_SYS_FLASH_BASE_PHYS_L;		/* we fixed up this address */
	val[3] = gd->bd->bi_flashsize;
	rc = fdt_find_and_setprop(blob, "/plb/opb/ebc", "ranges",
				  val, sizeof(val), 1);
	if (rc) {
		printf("Unable to update property NOR mapping, err=%s\n",
		       fdt_strerror(rc));
	}

	if (gd->board_type == BOARD_CANYONLANDS_SATA) {
		/*
		 * When SATA is selected we need to disable the first PCIe
		 * node in the device tree, so that Linux doesn't initialize
		 * it.
		 */
		rc = fdt_find_and_setprop(blob, "/plb/pciex@d00000000", "status",
					  "disabled", sizeof("disabled"), 1);
		if (rc) {
			printf("Unable to update property status in PCIe node, err=%s\n",
			       fdt_strerror(rc));
		}
	}

	if (gd->board_type == BOARD_CANYONLANDS_PCIE) {
		/*
		 * When PCIe is selected we need to disable the SATA
		 * node in the device tree, so that Linux doesn't initialize
		 * it.
		 */
		rc = fdt_find_and_setprop(blob, "/plb/sata@bffd1000", "status",
					  "disabled", sizeof("disabled"), 1);
		if (rc) {
			printf("Unable to update property status in PCIe node, err=%s\n",
			       fdt_strerror(rc));
		}
	}
}
#endif /* defined(CONFIG_OF_LIBFDT) && defined(CONFIG_OF_BOARD_SETUP) */

void pciauto_setup_device_mem(struct pci_controller *hose,
			  pci_dev_t dev, int bars_num,
			  struct pci_region *mem,
			  struct pci_region *prefetch,
			  struct pci_region *io,
			  pci_size_t bar_size_lower,
			  pci_size_t bar_size_upper)
{
	unsigned int bar_response, bar_back;
	pci_addr_t bar_value;
	pci_size_t bar_size;
	struct pci_region *bar_res;
	int bar, bar_nr = 0;
	int found_mem64 = 0;

	for (bar = PCI_BASE_ADDRESS_0; bar < PCI_BASE_ADDRESS_0 + (bars_num*4); bar += 4) {
		/* Tickle the BAR and get the response */
		pci_hose_read_config_dword(hose, dev, bar, &bar_back);
		pci_hose_write_config_dword(hose, dev, bar, 0xffffffff);
		pci_hose_read_config_dword(hose, dev, bar, &bar_response);
		pci_hose_write_config_dword(hose, dev, bar, bar_back);

		/* If BAR is not implemented go to the next BAR */
		if (!bar_response)
			continue;

		found_mem64 = 0;

		/* Check the BAR type and set our address mask */
		if ( ! (bar_response & PCI_BASE_ADDRESS_SPACE)) {
			if ( (bar_response & PCI_BASE_ADDRESS_MEM_TYPE_MASK) ==
			     PCI_BASE_ADDRESS_MEM_TYPE_64) {
				u32 bar_response_upper;
				u64 bar64;
				pci_hose_write_config_dword(hose, dev, bar+4, 0xffffffff);
				pci_hose_read_config_dword(hose, dev, bar+4, &bar_response_upper);

				bar64 = ((u64)bar_response_upper << 32) | bar_response;

				bar_size = ~(bar64 & PCI_BASE_ADDRESS_MEM_MASK) + 1;
				found_mem64 = 1;
			} else {
				bar_size = (u32)(~(bar_response & PCI_BASE_ADDRESS_MEM_MASK) + 1);
			}
			if (prefetch && (bar_response & PCI_BASE_ADDRESS_MEM_PREFETCH))
				bar_res = prefetch;
			else
				bar_res = mem;

			PRINTF("PCI Autoconfig: BAR %d, Mem, size=0x%llx, ", bar_nr, (u64)bar_size);
			
            if ((bar_size >= bar_size_lower) && (bar_size <= bar_size_upper)) {
        		if (pciauto_region_allocate(bar_res, bar_size, &bar_value) == 0) {
        			/* Write it out and update our limit */
        			pci_hose_write_config_dword(hose, dev, bar, (u32)bar_value);
        			PRINTF(" BAR written value=0x%8x, ", (u32)bar_value);
        
        			if (found_mem64) {
        				bar += 4;
#ifdef CONFIG_SYS_PCI_64BIT
        				pci_hose_write_config_dword(hose, dev, bar, (u32)(bar_value>>32));
#else
        				/*
        				 * If we are a 64-bit decoder then increment to the
        				 * upper 32 bits of the bar and force it to locate
        				 * in the lower 4GB of memory.
        				 */
        				pci_hose_write_config_dword(hose, dev, bar, 0x00000000);
#endif
        			}
        		}
    		}
		}

		PRINTF("\n");

		bar_nr++;
	}
}

void fix_pci_bars(void)
{
    struct pci_controller *hose = ppc460_hose; 
	unsigned int found_multi=0,problem=0,sec_func=0;
	unsigned short vendor, device, class;
	unsigned char header_type;
	pci_dev_t dev;
	u32 bar0;

    PRINTF("fix_pci_bars ++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    
	for (dev =  PCI_BDF(0,0,0);
	     dev <  PCI_BDF(0,PCI_MAX_PCI_DEVICES-1,PCI_MAX_PCI_FUNCTIONS-1);
	     dev += PCI_BDF(0,0,1)) {

		if (pci_skip_dev(hose, dev))
			continue;

		if (PCI_FUNC(dev) && !found_multi)
			continue;

		pci_hose_read_config_byte(hose, dev, PCI_HEADER_TYPE, &header_type);

		pci_hose_read_config_word(hose, dev, PCI_VENDOR_ID, &vendor);

		if (vendor != 0xffff && vendor != 0x0000) {		
		
			if (!PCI_FUNC(dev))
				found_multi = header_type & 0x80;
								
			pci_hose_read_config_word(hose, dev, PCI_CLASS_DEVICE, &class);				

			PRINTF("PCI Scan: Found Bus %d, Device %d, Function %d - %x\n",
				PCI_BUS(dev), PCI_DEV(dev), PCI_FUNC(dev), class );
				
			if (((PCI_BUS(dev)==0) && (PCI_DEV(dev)==4) && (PCI_FUNC(dev)==0)) && 
			    ((class==0x300)	|| (class==0x380))) problem +=1;

			if (((PCI_BUS(dev)==0) && (PCI_DEV(dev)==4) && (PCI_FUNC(dev)==1)) && 
			    ((class==0x300)	|| (class==0x380))) sec_func =1;
			    			    
			if ((PCI_BUS(dev)==0) && (PCI_DEV(dev)==6) && (PCI_FUNC(dev)==0)) {
			    pci_read_config_dword(dev, PCI_BASE_ADDRESS_0, &bar0);
		        bar0 = bar0 & 0xfffff000;
		        PRINTF("BAR0 = %8x\n",bar0);
		        
		        if ((bar0 == 0) || (bar0 >= 0x9c000000)) problem +=1;
		    }    
		}
	}
	
	PRINTF("problem = %d\n",problem);
	
	if (problem >= 2) {	
	
	    pciauto_config_init(hose);
	                   
        /* setup MEM SPACE for PCI gfx card (big BARs) */
        dev =  PCI_BDF(0,4,0);   	
        pciauto_setup_device_mem(hose, dev, 6, hose->pci_mem, hose->pci_prefetch, hose->pci_io, 0x00100000, 0xFFFFFFFF);    	
       
        if (sec_func) {        
            dev =  PCI_BDF(0,4,1);   	
            pciauto_setup_device_mem(hose, dev, 6, hose->pci_mem, hose->pci_prefetch, hose->pci_io, 0x00100000, 0xFFFFFFFF);    	
        }
       
        /* setup MEM SPACE for the onboard gfx card */
        dev =  PCI_BDF(0,6,0);   	
        pciauto_setup_device(hose, dev, 6, hose->pci_mem, hose->pci_prefetch, hose->pci_io); 

        /* setup MEM SPACE for PCI gfx card (small BARs) */
        dev =  PCI_BDF(0,4,0);   	
        pciauto_setup_device_mem(hose, dev, 6, hose->pci_mem, hose->pci_prefetch, hose->pci_io, 0x0, 0x000FFFFF);    	
       
        if (sec_func) {         
            dev =  PCI_BDF(0,4,1);   	
            pciauto_setup_device_mem(hose, dev, 6, hose->pci_mem, hose->pci_prefetch, hose->pci_io, 0x0, 0x000FFFFF);  
        }        
    }
}

extern struct pci_controller pcie_hose[CONFIG_SYS_PCIE_NR_PORTS];
	
void assign_pci_irq (void)
{
	u8 ii, class, pin;
	int BusNum, Device, Function;
	unsigned char HeaderType;
	unsigned short VendorID;
	pci_dev_t dev;

	// On Board fixed PCI devices -------------------------
	
	// Silicon Motion SM502
	if ((dev = pci_find_device(PCI_VENDOR_SM, PCI_DEVICE_SM501, 0)) >= 0)
	{
		// video IRQ connected to UIC3-20 -----------------
		pci_write_config_byte(dev, PCI_INTERRUPT_LINE, 116);
		pci_write_config_byte(dev, PCI_LATENCY_TIMER, 0x20);
	}
				
	// Optional PCI devices on PCI Slots 33/66 Mhz --------
		
	for (BusNum = 0; BusNum <= ppc460_hose->last_busno; BusNum++) 
	{
		for (Device = 0; Device < PCI_MAX_PCI_DEVICES; Device++) 
		{
			HeaderType = 0;
		
			for (Function = 0; Function < PCI_MAX_PCI_FUNCTIONS; Function++) 
			{
				if (Function && !(HeaderType & 0x80))
					break;

				dev = PCI_BDF(BusNum, Device, Function);
				
				if (dev != -1)
				{
					pci_read_config_word(dev, PCI_VENDOR_ID, &VendorID);
					if ((VendorID == 0xFFFF) || (VendorID == 0x0000))
						continue;
	
					if (!Function) 
						pci_read_config_byte(dev, PCI_HEADER_TYPE, &HeaderType);
						
					if ((BusNum == 0) && (Device == 0x06)) continue;
				
					pci_read_config_byte(dev, PCI_CLASS_CODE, &class);
					
					//if (class != PCI_BASE_CLASS_BRIDGE)
					{						
						pci_read_config_byte(dev, PCI_INTERRUPT_PIN, &pin);
						
						if (pin > 0)
						{					    
						    // all pci IRQ on external slot are connected to UIC1-0												    
							pci_write_config_byte(dev, PCI_INTERRUPT_LINE, 32); 
						}

						pci_write_config_byte(dev, PCI_LATENCY_TIMER, 0x20);					
					}
				}
			}		
		}
	}
	
	// PCI-Express bus ----------------------------------------------
	
	struct pci_controller *hose;
	
	for (ii = 0; ii < CONFIG_SYS_PCIE_NR_PORTS; ii++)
	{
    	hose = &pcie_hose[ii];
    	
    	if (hose)
    	{
    	    if (hose->last_busno > hose->first_busno)
    	    {
    	        // there is card in the PCIE slot
    	        // assume no bridge presents
    	        
    	        dev = PCI_BDF(hose->last_busno,0,0);
    	        
                if (dev != -1)
    			{
    				pci_read_config_byte(dev, PCI_INTERRUPT_PIN, &pin);
    				
    				if (pin > 0)
    				{					    
    				    // PCIE 1x slot is connected to UIC3-0												    
    				    // PCIE 4x slot is connected to UIC3-6												    
    					pci_write_config_byte(dev, PCI_INTERRUPT_LINE, 0x60 + ii*0x6);
    				}			
    			}
    		}
    	}
    }					    
}

/*
void show_tlb(void)
{
	int i;
	unsigned long tlb_word0_value;
	unsigned long tlb_word1_value;
	unsigned long tlb_word2_value;

	for (i=0; i<PPC4XX_TLB_SIZE; i++) 
	{
		tlb_word0_value = mftlb1(i);
		tlb_word1_value = mftlb2(i);
		tlb_word2_value = mftlb3(i);
		
		printf("TLB %i, %08x %08x %08x\n",i,tlb_word0_value,tlb_word1_value,tlb_word2_value);

		if ((tlb_word0_value & TLB_WORD0_V_MASK) == TLB_WORD0_V_DISABLE)
			break;
	}
}
*/
/*
void show_pcie_info(void)
{
	volatile void *mbase = NULL;

	mbase = (u32 *)CONFIG_SYS_PCIE0_XCFGBASE;
	
	printf("0:PEGPL_OMR1BA=%08x.%08x MSK=%08x.%08x\n",
	      mfdcr(DCRN_PEGPL_OMR1BAH(PCIE0)),
	      mfdcr(DCRN_PEGPL_OMR1BAL(PCIE0)),
	      mfdcr(DCRN_PEGPL_OMR1MSKH(PCIE0)),
	      mfdcr(DCRN_PEGPL_OMR1MSKL(PCIE0)));

	printf("0:PECFG_POM0LA=%08x.%08x\n", in_le32(mbase + PECFG_POM0LAH),
	      in_le32(mbase + PECFG_POM0LAL));		            	      

	printf("0:PECFG_POM2LA=%08x.%08x\n", in_le32(mbase + PECFG_POM2LAH),
	      in_le32(mbase + PECFG_POM2LAL));		            	      
	      
	mbase = (u32 *)CONFIG_SYS_PCIE1_XCFGBASE;

	// pci-express bar0
	printf("1:PEGPL_OMR1BA=%08x.%08x MSK=%08x.%08x\n",
	      mfdcr(DCRN_PEGPL_OMR1BAH(PCIE1)),
	      mfdcr(DCRN_PEGPL_OMR1BAL(PCIE1)),
	      mfdcr(DCRN_PEGPL_OMR1MSKH(PCIE1)),
	      mfdcr(DCRN_PEGPL_OMR1MSKL(PCIE1)));	
	      
	printf("1:PECFG_POM0LA=%08x.%08x\n", in_le32(mbase + PECFG_POM0LAH),
	      in_le32(mbase + PECFG_POM0LAL));		            	      

	printf("1:PECFG_POM2LA=%08x.%08x\n", in_le32(mbase + PECFG_POM2LAH),
	      in_le32(mbase + PECFG_POM2LAL));		            	      

}
*/

int last_stage_init (void)
{
	uchar buf; 
	int jj, ret = 0;
	u16 fpga_val = 0;
	
	u32 val = mfspr(SPRN_MMUCR);
	val = 0x00010000;
	mtspr(SPRN_MMUCR,val);
	
	do_fpga();
	
	// Red Led OFF ----------------------------------------
	fpga_val = in_be16((void *)CONFIG_SYS_FPGA_BASE + 0x2E);
	fpga_val &= ~0x0002;
	out_be16((void *)CONFIG_SYS_FPGA_BASE + 0x2E, fpga_val);	
	
	// fix possible menuboot_cmd misconfiguration ---------	
	char *s = getenv("menuboot_cmd");
	if ((!s) ||
	    ((s) && (strlen(s) < 3)) ||
	    ((s) && (strcmp(s,"noboot") == 0))) 
	{   
	    setenv("menuboot_cmd","boota");
	    saveenv();
	}
			
    fix_pci_bars();			
	assign_pci_irq();	

	// cache on -------------------------------------------	
	change_tlb(0, 256*1024*1024, 0);
		
	// SM502 Graphic card on PCI --------------------------
#ifdef CONFIG_VIDEO_SM502
	init_sm502();
#endif

	// x86 Graphic card on PCI ----------------------------	
	ret = init_radeon(ppc460_hose);
	
	// active gfx card ------------------------------------
	SM502 = 0;                      // default VGA card

#ifdef CONFIG_VIDEO_SM502	
	s = getenv("video_activate");
	if ((strcmp(s, "sm502") == 0) && (SM502INIT)) SM502 = 1;
	else if ((SM502INIT) && (ret == 0)) SM502 = 1;	
#endif
	
	if (SM502 && SM502INIT)
	{	
#ifdef CONFIG_VIDEO_SM502
		fbi = (struct FrameBufferInfo *)(malloc(sizeof(struct FrameBufferInfo)));
	    if (fbi)
	    {
	       	fbi->BaseAddress   = fb_base_phys_sm502;
			fbi->XSize         = board_get_width();
			fbi->YSize         = board_get_height();
			fbi->BitsPerPixel  = 8;
			fbi->Modulo		   = board_get_width();
	
			onbus = 0;
			drv_video_init();	
		}
#endif	
	}
	else if (ret > 0)
	{	   	
	    if (SM502INIT)
	    {
	        // shutdown onboard gfx card
	        unsigned short cmd;
	        
    		pci_read_config_word(dev_sm502, PCI_COMMAND, &cmd);
    		cmd &= ~(PCI_COMMAND_IO|PCI_COMMAND_MEMORY);		
    		pci_write_config_word(dev_sm502, PCI_COMMAND, cmd);
	    }
	}
	
	// custom silent mode ---------------------------------	
    int hush = 0;
	s = getenv("hush"); 
	if (s) hush = atoi(s);
	if (hush) {
	    s = getenv("stdout");
	    if ((s) && (strncmp(s,"vga",3) == 0))
	        gd->flags |= GD_FLG_SILENT;
	 }
	 		
#ifdef SAMLOGO
    // Welcome Screen -------------------------------------
	if (fbi)	
	{			
		unsigned int xx, yy, xoff = 0, yoff = 0;
		
		if (gd->flags & GD_FLG_SILENT) {
		    xoff = (fbi->XSize-LOGO_WIDTH) / 2;	
		    yoff = (fbi->YSize-LOGO_HEIGHT) / 9;
		}
        else puts("\n\n\n\n");
				
		for (xx = 0; xx < LOGO_WIDTH; xx++)
		{
			for (yy = 0; yy < LOGO_HEIGHT; yy++)
    		{
    			buf = logo_acube[xx + (LOGO_HEIGHT-yy-1)*LOGO_WIDTH];
    			*((char *)(fbi->BaseAddress + (xx+xoff) + (yy+yoff)*fbi->XSize*(fbi->BitsPerPixel/8))) = buf;
    		}
		}
	}	
#endif

	puts("Config: PCIe 4x + ");

	if (gd->board_type == BOARD_CANYONLANDS_PCIE)
		puts("PCIe 1x\n");
    else
		puts("SATA-2\n");

	// cache off ------------------------------------------	
	change_tlb(0, 256*1024*1024, TLB_WORD2_I_ENABLE);

    // Yellow LED OFF -------------------------------------	
	fpga_val = in_be16((void *)CONFIG_SYS_FPGA_BASE + 0x2E); 
	fpga_val &= ~0x0004; 
	out_be16((void *)CONFIG_SYS_FPGA_BASE + 0x2E, fpga_val);
	
	// Catweasel keyboard ---------------------------------		
	//ret = catw_kb_init();
	
	// cleanup last 8 bytes of the RTC registers bank -----
	
	char arr[8] = { 0 };
	i2c_write(0x68, 0x08, 1, &arr, 8);
	
	// USB Init -------------------------------------------

	uint32_t cmd;
	
	SDR_WRITE(SDR0_SRST1, 0x00000008);

   	//gpio_config(19, GPIO_OUT, GPIO_ALT1, GPIO_OUT_1);
	gpio_config(16, GPIO_OUT, GPIO_ALT1, GPIO_OUT_1);
	wait_ms(200);

	fpga_val = in_be16((void *)CONFIG_SYS_FPGA_BASE + 0x30);
	fpga_val |= 0x0004; //0x0014;
	out_be16((void *)CONFIG_SYS_FPGA_BASE + 0x30, fpga_val);	
	wait_ms(200);
	
	SDR_WRITE(SDR0_SRST1, 0);

	cmd = in_le32(CONFIG_SYS_AHB_BASE | 0xd0410);
	cmd |= 1 << 1;
	out_le32(CONFIG_SYS_AHB_BASE | 0xd0410, cmd);
    wait_ms(10);
    
	cmd = in_le32(CONFIG_SYS_AHB_BASE | 0xd0454);
	cmd |= 1 << 12;
	out_le32(CONFIG_SYS_AHB_BASE | 0xd0454, cmd);
    wait_ms(10);
        
	cmd = in_le32(CONFIG_SYS_AHB_BASE | 0xd0410);
	cmd |= 1 << 1;
	out_le32(CONFIG_SYS_AHB_BASE | 0xd0410, cmd);
    wait_ms(10);    
			            	
    out_le32((void *)CONFIG_SYS_AHB_BASE + 0xd0048,0xff000001);

    s = getenv("usb_delay");
    if (s) {
        ret = atoi(s) * 10;
        if (ret <= 0) ret = 0;
        if (ret > 2000) ret = 2000;
        for (jj=0;jj<ret;jj++) udelay(10000); 
    } 
    
    if (gd->flags & GD_FLG_SILENT) {
        gd->flags &= ~GD_FLG_SILENT;
        console_row = 29;
        console_col = 28;
        puts("Init USB... ");
        gd->flags |= GD_FLG_SILENT;
    }
            		
	ret = usb_init();

#ifdef CONFIG_USB_STORAGE
	// try to recognize storage devices immediately	-------
	if (ret >= 0)
	{	
	    usb_event_poll();
		s = getenv("scan_usb_storage");
		if (s) usb_stor_scan(1);
	}
#endif

	// Init SATA controller -------------------------------		
	if (gd->flags & GD_FLG_SILENT) {
        gd->flags &= ~GD_FLG_SILENT;
        puts("Done - Init SATA... ");
        gd->flags |= GD_FLG_SILENT;
    }
    
	ide_controllers_init();

    // Ambra LED OFF --------------------------------------  	
    fpga_val = in_be16((void *)CONFIG_SYS_FPGA_BASE + 0x2E);
	fpga_val &= ~0x0008; 
	out_be16((void *)CONFIG_SYS_FPGA_BASE + 0x2E, fpga_val);

	if (gd->flags & GD_FLG_SILENT) {
        gd->flags &= ~GD_FLG_SILENT;
        puts("Done\n");
        gd->flags |= GD_FLG_SILENT;
    } 
    
    //show_pcie_info();
    
    //show_tlb();
           
   	return 0;
}

void do_fpga(void)
{
    u8  tmp,dd,mm,yy,rv;
    u16 fpga_val;
    
	fpga_val = in_be16((void *)CONFIG_SYS_FPGA_BASE + 0x2a);
	tmp = fpga_val & 0xff;
	mm = (tmp/16)*10 + (tmp%16);
	tmp = (fpga_val >> 8) & 0xff;   
	dd = (tmp/16)*10 + (tmp%16); 
	
	fpga_val = in_be16((void *)CONFIG_SYS_FPGA_BASE + 0x2c);
	tmp = fpga_val & 0xff;
	rv = (tmp/16)*10 + (tmp%16);
	tmp = (fpga_val >> 8) & 0xff;;
	yy = (tmp/16)*10 + (tmp%16);
	
	printf("FPGA:  Revision %02d (20%2d-%02d-%02d)\n",rv,yy,mm,dd);
}

void do_shutdown(void)
{
    u16 fpga_val;
    
	fpga_val = 0x000f; 
	out_be16((void *)CONFIG_SYS_FPGA_BASE + 0x2E, fpga_val);
	wait_ms(300);
	fpga_val = 0x0000; 
	out_be16((void *)CONFIG_SYS_FPGA_BASE + 0x2E, fpga_val);
	wait_ms(300); 
	fpga_val = 0x000f; 
	out_be16((void *)CONFIG_SYS_FPGA_BASE + 0x2E, fpga_val);
	wait_ms(300);

	fpga_val = 0x0010; 
	out_be16((void *)CONFIG_SYS_FPGA_BASE + 0x2E, fpga_val);
	
	while(1); // never return
} 

void board_reset(void)
{
    u16 fpga_val;
    fpga_val = in_be16((void *)CONFIG_SYS_FPGA_BASE + 0x2E);
	fpga_val |= 0x0010; 
	out_be16((void *)CONFIG_SYS_FPGA_BASE + 0x2E, fpga_val);
	wait_ms(25);
    fpga_val &= ~0x0010;
	out_be16((void *)CONFIG_SYS_FPGA_BASE + 0x2E, fpga_val);	
}

U_BOOT_CMD( fpga,      1,      0,      do_fpga,  
    "show FPGA firmware revision", 
    "show FPGA firmware revision");

U_BOOT_CMD( shutdown,      1,      0,      do_shutdown,  
    "switch machine off", 
    "switch machine off");
