/*
 * (C) Copyright 2008
 * Stefan Roese, DENX Software Engineering, sr@denx.de.
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

/************************************************************************
 * canyonlands.h - configuration for Canyonlands (460EX)
 ***********************************************************************/
#ifndef __CONFIG_H
#define __CONFIG_H

/*-----------------------------------------------------------------------
 * High Level Configuration Options
 *----------------------------------------------------------------------*/
#define CONFIG_CANYONLANDS
#define CONFIG_SAM4XX		1	/* board is Sam4xx family	*/
#define CONFIG_SAM460EX

#define CONFIG_460EX		1	/* Specific PPC460EX		*/
#define CONFIG_HOSTNAME		Sam460ex

#define CONFIG_440			1
#define CONFIG_4xx			1	/* ... PPC4xx family */

#define CONFIG_SYS_CLK_FREQ	50000000	/* external freq to pll	*/

#define CONFIG_BOARD_RESET    1

#define CONFIG_SYS_SDRAM_BASE	0x00000000	/* _must_ be 0		*/
#define CONFIG_SYS_MONITOR_BASE	TEXT_BASE	/* Start of U-Boot	*/
#define CONFIG_SYS_MONITOR_LEN	(0xFFFFFFFF - CONFIG_SYS_MONITOR_BASE + 1)
#define CONFIG_SYS_MALLOC_LEN	(32 << 20)	/* Reserved for malloc	*/

#define CONFIG_BOARD_EARLY_INIT_F	1	/* Call board_early_init_f */
#define CONFIG_BOARD_EARLY_INIT_R	1	/* Call board_early_init_r */
#define CONFIG_MISC_INIT_R			1	/* Call misc_init_r */
#define CONFIG_BOARD_TYPES			1	/* support board types */
#define CONFIG_LAST_STAGE_INIT		1
#define CONFIG_VERY_BIG_RAM			1
#define CONFIG_MAX_MEM_MAPPED		256*1024*1024

/*-----------------------------------------------------------------------
 * Base addresses -- Note these are effective addresses where the
 * actual resources get mapped (not physical addresses)
 *----------------------------------------------------------------------*/
#define CONFIG_SYS_PCI_64BIT    1
 
#define CONFIG_SYS_PCI_MEMBASE	0x80000000	/* mapped PCI memory region1 */
#define CONFIG_SYS_PCI_BASE		0xd0000000	/* internal PCI regs	*/
#define CONFIG_SYS_PCI_TARGBASE	CONFIG_SYS_PCI_MEMBASE
#define CONFIG_SYS_PCI_MEMSIZE	0x20000000
#define CONFIG_SYS_PCI_MEMBASE2	CONFIG_SYS_PCI_MEMBASE + 0x10000000

#define CONFIG_SYS_PCIE_MEMBASE	0xA0000000	/* mapped PCIe memory	*/
#define CONFIG_SYS_PCIE_MEMSIZE	0x10000000	/* smallest incr for PCIe port */
#define CONFIG_SYS_PCIE_BASE	0xE4000000	/* PCIe UTL regs */

#define CONFIG_SYS_PCIE0_CFGBASE	0xE0000000
#define CONFIG_SYS_PCIE1_CFGBASE	0xE1000000
#define CONFIG_SYS_PCIE0_XCFGBASE	0xE3000000
#define CONFIG_SYS_PCIE1_XCFGBASE	0xE3001000

#define CONFIG_SYS_PCIE_IOBASE      0x0
#define CONFIG_SYS_PCIE_IOSIZE      0x10000

#define	CONFIG_SYS_PCIE0_UTLBASE	0xc08010000ULL	/* 36bit physical addr	*/

/* base address of inbound PCIe window */
#define CONFIG_SYS_PCIE_INBOUND_BASE	0x000000000ULL	/* 36bit physical addr	*/

/* EBC stuff */
#define CONFIG_SYS_FPGA_BASE		0xFF000000
#define CONFIG_SYS_FLASH_BASE		0xFFF00000	/* later mapped to this addr */
#define CONFIG_SYS_FLASH_SIZE		(1 << 20)
#define CONFIG_SYS_FLASH_BASE_PHYS_H 	0x4
#define CONFIG_SYS_FLASH_BASE_PHYS_L 	CONFIG_SYS_FLASH_BASE

#define CONFIG_SYS_BOOT_BASE_ADDR	0xF0000000	/* EBC Boot Space: 0xFF000000 */

#define CONFIG_SYS_OCM_BASE			0xE5000000	/* OCM: 64k		*/
#define CONFIG_SYS_SRAM_BASE		0xE8000000	/* SRAM: 256k		*/
#define CONFIG_SYS_LOCAL_CONF_REGS	0xEF000000

#define CONFIG_SYS_PERIPHERAL_BASE	0xEF600000	/* internal peripherals */

#define CONFIG_SYS_AHB_BASE			0xE2000000	/* internal AHB peripherals	*/

/*-----------------------------------------------------------------------
 * Initial RAM & stack pointer (placed in OCM)
 *----------------------------------------------------------------------*/
#define CONFIG_SYS_INIT_RAM_ADDR	CONFIG_SYS_OCM_BASE	/* OCM			*/
#define CONFIG_SYS_INIT_RAM_END		(4 << 10)
#define CONFIG_SYS_GBL_DATA_SIZE	256		/* num bytes initial data */
#define CONFIG_SYS_GBL_DATA_OFFSET	(CONFIG_SYS_INIT_RAM_END - CONFIG_SYS_GBL_DATA_SIZE)
#define CONFIG_SYS_INIT_SP_OFFSET	CONFIG_SYS_GBL_DATA_OFFSET

/*-----------------------------------------------------------------------
 * Serial Port
 *----------------------------------------------------------------------*/
#define CONFIG_SYS_EXT_SERIAL_CLOCK	11059200 /* use external 11.059MHz clk	*/
#undef CONFIG_UART1_CONSOLE	/* define this if you want console on UART1 */
#define CONFIG_BAUDRATE		115200
#define CONFIG_SERIAL_MULTI
#define CONFIG_SYS_BAUDRATE_TABLE  \
    {300, 600, 1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400}
#undef CONFIG_UART1_CONSOLE	/* define this if you want console on UART1 */

/*-----------------------------------------------------------------------
 * Environment
 *----------------------------------------------------------------------*/
/*
 * Define here the location of the environment variables (FLASH).
 */
#define CONFIG_ENV_IS_IN_EEPROM	1	/* use EEPROM for environment vars	*/

/*
 * IPL (Initial Program Loader, integrated inside CPU)
 * Will load first 4k from NAND (SPL) into cache and execute it from there.
 *
 * SPL (Secondary Program Loader)
 * Will load special U-Boot version (NUB) from NAND and execute it. This SPL
 * has to fit into 4kByte. It sets up the CPU and configures the SDRAM
 * controller and the NAND controller so that the special U-Boot image can be
 * loaded from NAND to SDRAM.
 *
 * NUB (NAND U-Boot)
 * This NAND U-Boot (NUB) is a special U-Boot version which can be started
 * from RAM. Therefore it mustn't (re-)configure the SDRAM controller.
 *
 * On 440EPx the SPL is copied to SDRAM before the NAND controller is
 * set up. While still running from cache, I experienced problems accessing
 * the NAND controller.	sr - 2006-08-25
 *
 * This is the first official implementation of booting from 2k page sized
 * NAND devices (e.g. Micron 29F2G08AA 256Mbit * 8)
 */

/*
 * Define the partitioning of the NAND chip (only RAM U-Boot is needed here)
 */
#define CONFIG_SYS_NAND_U_BOOT_OFFS	(128 << 10)	/* Offset to RAM U-Boot image */
#define CONFIG_SYS_NAND_U_BOOT_SIZE	(1 << 20)	/* Size of RAM U-Boot image   */

/*
 * Now the NAND chip has to be defined (no autodetection used!)
 */
#define CONFIG_SYS_NAND_PAGE_SIZE	(2 << 10)	/* NAND chip page size	      */
#define CONFIG_SYS_NAND_BLOCK_SIZE	(128 << 10)	/* NAND chip block size	      */
#define CONFIG_SYS_NAND_PAGE_COUNT	(CONFIG_SYS_NAND_BLOCK_SIZE / CONFIG_SYS_NAND_PAGE_SIZE)
						/* NAND chip page count	      */
#define CONFIG_SYS_NAND_BAD_BLOCK_POS	0		/* Location of bad block marker*/
#define CONFIG_SYS_NAND_5_ADDR_CYCLE			/* Fifth addr used (<=128MB)  */

#define CONFIG_SYS_NAND_ECCSIZE	256
#define CONFIG_SYS_NAND_ECCBYTES	3
#define CONFIG_SYS_NAND_ECCSTEPS	(CONFIG_SYS_NAND_PAGE_SIZE / CONFIG_SYS_NAND_ECCSIZE)
#define CONFIG_SYS_NAND_OOBSIZE	64
#define CONFIG_SYS_NAND_ECCTOTAL	(CONFIG_SYS_NAND_ECCBYTES * CONFIG_SYS_NAND_ECCSTEPS)
#define CONFIG_SYS_NAND_ECCPOS		{40, 41, 42, 43, 44, 45, 46, 47, \
				 48, 49, 50, 51, 52, 53, 54, 55, \
				 56, 57, 58, 59, 60, 61, 62, 63}

#ifdef CONFIG_ENV_IS_IN_NAND
/*
 * For NAND booting the environment is embedded in the U-Boot image. Please take
 * look at the file board/amcc/canyonlands/u-boot-nand.lds for details.
 */
#define CONFIG_ENV_SIZE				CONFIG_SYS_NAND_BLOCK_SIZE
#define CONFIG_ENV_OFFSET			(CONFIG_SYS_NAND_U_BOOT_OFFS + CONFIG_ENV_SIZE)
#define CONFIG_ENV_OFFSET_REDUND	(CONFIG_ENV_OFFSET + CONFIG_ENV_SIZE)
#endif

/*-----------------------------------------------------------------------
 * FLASH related
 *----------------------------------------------------------------------*/
#define CONFIG_SYS_NO_FLASH 1

#define CONFIG_SYS_MAX_FLASH_BANKS	1	/* max number of memory banks		*/
#define CONFIG_SYS_MAX_FLASH_SECT	11	/* max number of sectors on one chip	*/

#define CONFIG_SYS_FLASH_ERASE_TOUT	150000	/* Timeout for Flash Erase (in ms)	*/
#define CONFIG_SYS_FLASH_WRITE_TOUT	800	/* Timeout for Flash Write (in ms)	*/

#define CONFIG_SYS_FLASH_EMPTY_INFO		/* print 'E' for empty sector on flinfo */

#define CONFIG_SYS_FLASH_WORD_SIZE unsigned char
#define CONFIG_SYS_FLASH_ADDR0 0x555
#define CONFIG_SYS_FLASH_ADDR1 0x2aa
/*-----------------------------------------------------------------------
 * NAND-FLASH related
 *----------------------------------------------------------------------*/
#define CONFIG_SYS_MAX_NAND_DEVICE	1
#define CONFIG_SYS_NAND_CS			3	/* NAND chip connected to CSx */
#define CONFIG_SYS_NAND_BASE		(CONFIG_SYS_NAND_ADDR + CONFIG_SYS_NAND_CS)

/*------------------------------------------------------------------------------
 * DDR SDRAM
 *----------------------------------------------------------------------------*/
#if !defined(CONFIG_NAND_U_BOOT)
/*
 * NAND booting U-Boot version uses a fixed initialization, since the whole
 * I2C SPD DIMM autodetection/calibration doesn't fit into the 4k of boot
 * code.
 */
#define CONFIG_SPD_EEPROM		1			/* Use SPD EEPROM for setup	*/
#define SPD_EEPROM_ADDRESS		{0x50} 		/* SPD i2c spd addresses*/
#undef CONFIG_DDR_ECC
#define CONFIG_DDR_RQDC_FIXED	0x80000038 	/* fixed value for RQDC	*/
#endif

/*-----------------------------------------------------------------------
 * I2C
 *----------------------------------------------------------------------*/
#define CONFIG_HARD_I2C			/* I2C with hardware support	*/
#define CONFIG_PPC4XX_I2C		/* use PPC4xx driver		*/
#define CONFIG_SYS_I2C_SLAVE	0x7F
#define CONFIG_SYS_I2C_SPEED	400000	/* I2C speed			*/

#define CONFIG_SYS_I2C_MULTI_EEPROMS
#define CONFIG_SYS_I2C_EEPROM_ADDR		(0xa8>>1)
#define CONFIG_SYS_I2C_EEPROM_ADDR_LEN		1
#define CONFIG_SYS_EEPROM_PAGE_WRITE_BITS	3
#define CONFIG_SYS_EEPROM_PAGE_WRITE_DELAY_MS	10

/* I2C bootstrap EEPROM */
#define CONFIG_4xx_CONFIG_I2C_EEPROM_ADDR	0x52
#define CONFIG_4xx_CONFIG_I2C_EEPROM_OFFSET	0
#define CONFIG_4xx_CONFIG_BLOCKSIZE		16

/* RTC configuration */
#define CONFIG_RTC_M41T62	1
#define CONFIG_SYS_I2C_RTC_ADDR	0x68

#ifdef CONFIG_ENV_IS_IN_EEPROM
#define CONFIG_ENV_SIZE					0x400	/* Size of Environment vars */
#define CONFIG_ENV_OFFSET				0x0
#define CONFIG_ENV_OVERWRITE
#endif /* CFG_ENV_IS_IN_EEPROM */

/*-----------------------------------------------------------------------
 * Ethernet
 *----------------------------------------------------------------------*/
#define CONFIG_PPC4xx_EMAC
#define CONFIG_MII			/* MII PHY management		*/
#define CONFIG_NET_MULTI
#undef CONFIG_NETCONSOLE		/* include NetConsole support	*/
#define CONFIG_SYS_RX_ETH_BUFFER	4	/* number of eth rx buffers	*/
 
#define CONFIG_IBM_EMAC4_V4	1
#define CONFIG_PHY_ADDR		0	/* PHY address, See schematics	*/
#define CONFIG_PHY1_ADDR	1
#define CONFIG_HAS_ETH0
#define CONFIG_HAS_ETH1

#define CONFIG_PHY_RESET	1	/* reset phy upon startup	*/
#define CONFIG_PHY_GIGE		1	/* Include GbE speed/duplex detection */
#define CONFIG_PHY_DYNAMIC_ANEG	1

/*-----------------------------------------------------------------------
 * USB-OHCI
 *----------------------------------------------------------------------*/
/* Only Canyonlands (460EX) has USB */
#ifdef CONFIG_460EX
#define CONFIG_USB_OHCI_NEW
#define CONFIG_USB_STORAGE
#define CONFIG_USB_KEYBOARD
#define CONFIG_SYS_USB_EVENT_POLL
#undef CONFIG_SYS_OHCI_BE_CONTROLLER		/* 460EX has little endian descriptors	*/
#define CONFIG_SYS_OHCI_SWAP_REG_ACCESS	    /* 460EX has little endian register	*/
#undef CONFIG_SYS_OHCI_USE_NPS		        /* force NoPowerSwitching mode		*/
#define CONFIG_SYS_USB_OHCI_REGS_BASE	(CONFIG_SYS_AHB_BASE | 0xd0000)
#define CONFIG_SYS_USB_OHCI_SLOT_NAME	"ppc440"
#define CONFIG_SYS_USB_OHCI_MAX_ROOT_PORTS 1
#endif

/*
 * Default environment variables
 */
#define	CONFIG_EXTRA_ENV_SETTINGS		    \
	"stdout=vga\0"	    			        \
	"stdin=usbkbd\0"   					    \
	"hush=0\0"                              \
	"ide_doreset=on\0"					    \
	"ide_reset_timeout=15\0"			    \
	"ide_cd_timeout=20\0"				    \
	"pcie_mode=RP:RP\0"					    \
	"pciconfighost=1\0"                     \
	"ipaddr=192.168.2.50\0"				    \
	"serverip=192.168.2.222\0"			    \
	"ethaddr=00:50:C2:80:D5:00\0"           \
	"video_activate=pci\0"			    \
	"menuboot_delay=2\0"                    \
	"boota_timeout=2\0"                     \
	"bootcmd=menu; run menuboot_cmd\0"	    \
	"menucmd=menu\0"					    \
	"menuboot_cmd=boota\0"				    \
	"boot_method=boota\0"				    \
	"boot1=ssiicdrom\0"					    \
	"boot2=ssii\0"				            \
	"boot3=usb\0"                           \
	"os4_commandline=debuglevel=0\0"        \
	"bootargs=root=/dev/sda3 console=tty0\0"\
	"serdes=sata2\0"                        \
	"usb_enable_4x0=1\0"                    \
	"usb_retry=1\0"                         \
	"usb_ohci_power_down_before_reset=1\0"  \
	"scan_usb_storage=1\0"						

/*
 * Commands
 */

#define CONFIG_CMD_BDI 		/* bdinfo			*/
#ifndef CONFIG_SYS_NO_FLASH
#define CONFIG_CMD_FLASH	/* flinfo, erase, protect	*/
#endif
#define CONFIG_CMD_MEMORY 	/* md mm nm mw cp cmp crc base loop mtest */
#define CONFIG_CMD_NET		/* bootp, tftpboot, rarpboot	*/
#define CONFIG_CMD_RUN		/* run command in env variable	*/
#define CONFIG_CMD_SAVEENV	/* saveenv			*/

#if defined(CONFIG_440)
#undef CONFIG_CMD_CACHE
#endif

#define CONFIG_CMD_EEPROM
#define CONFIG_CMD_ELF
#define CONFIG_CMD_I2C
#define CONFIG_CMD_MII
#define CONFIG_CMD_NET

#if defined(CONFIG_SYS_RAMBOOT)
/*
 * Disable NOR FLASH commands on RAM-booting version. One main reason for this
 * RAM-booting version is boards with NAND and without NOR. This image can
 * be used for initial NAND programming.
 */
#define CONFIG_SYS_NO_FLASH
#undef CONFIG_CMD_FLASH
#undef CONFIG_CMD_IMLS
#endif

#define CONFIG_CMD_DATE
/* #define CONFIG_CMD_NAND */
#define CONFIG_CMD_PCI
#ifdef CONFIG_460EX
#define CONFIG_CMD_EXT2
#define CONFIG_CMD_USB
#endif

/* Partitions */
#define CONFIG_DOS_PARTITION
#define CONFIG_ISO_PARTITION
#define CONFIG_AMIGA_PARTITION

/*-----------------------------------------------------------------------
 * PCI stuff
 *----------------------------------------------------------------------*/
/* General PCI */
#define CONFIG_PCI						/* include pci support	*/
#define CONFIG_PCI_PNP					/* do pci plug-and-play	*/
#define CONFIG_PCI_SCAN_SHOW			/* show pci devices on startup	*/
#define CONFIG_PCI_CONFIG_HOST_BRIDGE
#define CFG_ISA_IO_BASE_ADDRESS	(CONFIG_SYS_PCI_BASE | 0x08000000) /* PCIX0_IOBASE */

/* Board-specific PCI */
#define CONFIG_SYS_PCI_TARGET_INIT		/* let board init pci target    */
#define	CONFIG_SYS_PCI_MASTER_INIT

#define CONFIG_SYS_PCI_SUBSYS_VENDORID 0x1014	/* IBM				*/
#define CONFIG_SYS_PCI_SUBSYS_DEVICEID 0xcafe	/* Whatever			*/

#define CONFIG_SYS_SCSI_SCAN_BUS_REVERSE  		/* Don't touch */

/*
 * SATA driver setup
 */
#define CONFIG_SATA_DWC
#define CONFIG_LIBATA
#define SATA_BASE_ADDR		0xe20d1000	/* PPC460EX SATA Base Address */
#define SATA_DMA_REG_ADDR	0xe20d0800	/* PPC460EX SATA Base Address */
#define CONFIG_SYS_SATA_MAX_DEVICE	1	/* SATA MAX DEVICE */
/* Convert sectorsize to wordsize */
#define ATA_SECTOR_WORDS (ATA_SECT_SIZE/2)

/*-----------------------------------------------------------------------
 * Video stuff
 *----------------------------------------------------------------------*/
#define CONFIG_VIDEO_SM502
#define CONFIG_VIDEO_SM501_8BPP

#define CONFIG_SYS_CONSOLE_OVERWRITE_ROUTINE	1
#define CONFIG_SYS_CONSOLE_IS_IN_ENV			1

/*-----------------------------------------------------------------------
 * IDE ATAPI Configuration
 *----------------------------------------------------------------------*/
#define CONFIG_LBA48				1
#define CONFIG_ATAPI				1
#define CONFIG_SYS_IDE_MAXBUS		2
#define CONFIG_SYS_IDE_MAXDEVICE	4

#define CONFIG_SYS_ATA_BASE_ADDR	CFG_ISA_IO_BASE_ADDRESS
#define CONFIG_SYS_ATA_IDE0_OFFSET	0x1F0
#define CONFIG_SYS_ATA_IDE1_OFFSET	0x170
#define CONFIG_SYS_ATA_REG_OFFSET	0
#define CONFIG_SYS_ATA_DATA_OFFSET	0
#define CONFIG_SYS_ATA_ALT_OFFSET	0x0200

/*
#define CONFIG_CMD_SCSI
#define SCSI_VEND_ID 0x197b
#define SCSI_DEV_ID  0x2363
#define CONFIG_SCSI_AHCI
#define CONFIG_SYS_SCSI_MAX_SCSI_ID	4
#define CONFIG_SYS_SCSI_MAX_LUN	1
#define CONFIG_SYS_SCSI_MAX_DEVICE	(CONFIG_SYS_SCSI_MAX_SCSI_ID * CONFIG_SYS_SCSI_MAX_LUN)
#define CONFIG_SYS_SCSI_MAXDEVICE	CONFIG_SYS_SCSI_MAX_DEVICE
*/ 
/*-----------------------------------------------------------------------
 * External Bus Controller (EBC) Setup
 *----------------------------------------------------------------------*/

/* Memory Bank 0 (NOR-FLASH) initialization	*/				
#define CONFIG_SYS_EBC_PB0AP		0x06057240
#define CONFIG_SYS_EBC_PB0CR		0xfff18000 //(CONFIG_SYS_BOOT_BASE_ADDR | 0x18000)

/* Memory Bank 2 (FPGA) initialization  */
#define CONFIG_SYS_EBC_PB2AP		0x7f8ffe80
#define CONFIG_SYS_EBC_PB2CR		(CONFIG_SYS_FPGA_BASE | 0x3a000) /* BAS=FPGA,BS=2MB,BU=R/W,BW=16bit*/

/* Memory Bank 3 (NAND-FLASH) initialization						*/
/* #define CONFIG_SYS_EBC_PB3AP		0x018003c0 */
/* #define CONFIG_SYS_EBC_PB3CR		(CONFIG_SYS_NAND_ADDR | 0x1E000) *//* BAS=NAND,BS=1MB,BU=R/W,BW=32bit*/

#define CONFIG_SYS_EBC_CFG		0xB8400000		/*  EBC0_CFG */

/*-----------------------------------------------------------------------
 * Miscellaneous configurable options
 *----------------------------------------------------------------------*/
#define CONFIG_SYS_LONGHELP			/* undef to save memory		*/
#define CONFIG_SYS_PROMPT		"] "	/* Monitor Command Prompt	*/
#if defined(CONFIG_CMD_KGDB)
#define CONFIG_SYS_CBSIZE		1024	/* Console I/O Buffer Size	*/
#else
#define CONFIG_SYS_CBSIZE		100	/* Console I/O Buffer Size	*/
#endif
#define CONFIG_SYS_PBSIZE		(CONFIG_SYS_CBSIZE+sizeof(CONFIG_SYS_PROMPT)+16)
#define CONFIG_SYS_MAXARGS		16	/* max number of command args	*/
#define CONFIG_SYS_BARGSIZE		CONFIG_SYS_CBSIZE /* Boot Argument Buffer Size	*/

#define CONFIG_SYS_MEMTEST_START	0x0400000 /* memtest works on		*/
#define CONFIG_SYS_MEMTEST_END		0x0C00000 /* 4 ... 12 MB in DRAM	*/

#define CONFIG_SYS_LOAD_ADDR		0x100000  /* default load address	*/
#define CONFIG_SYS_EXTBDINFO			/* To use extended board_into (bd_t) */

#define CONFIG_SYS_HZ			1000	/* decrementer freq: 1 ms ticks	*/

#undef CONFIG_CMDLINE_EDITING		    /* add command line history	*/
#undef CONFIG_AUTO_COMPLETE		        /* add autocompletion support	*/
#undef CONFIG_LOOPW			            /* enable loopw command         */
#undef CONFIG_MX_CYCLIC		            /* enable mdc/mwc commands      */
#define CONFIG_ZERO_BOOTDELAY_CHECK	    /* check for keypress on bootdelay==0 */
#define CONFIG_VERSION_VARIABLE 	    /* include version env variable */
#define CONFIG_SYS_CONSOLE_INFO_QUIET	/* don't print console @ startup*/
#define CONFIG_SILENT_CONSOLE

#undef CONFIG_SYS_HUSH_PARSER			/* Use the HUSH parser		*/
#ifdef	CONFIG_SYS_HUSH_PARSER
#define	CONFIG_SYS_PROMPT_HUSH_PS2	"> "
#endif

#define CONFIG_LOADS_ECHO		        1    /* echo on for serial download	*/
#define CONFIG_SYS_LOADS_BAUD_CHANGE    1    /* allow baudrate change	*/

/*
 * For booting Linux, the board info and command line data
 * have to be in the first 16 MB of memory, since this is
 * the maximum mapped by the 40x Linux kernel during initialization.
 */
#define CONFIG_SYS_BOOTMAPSZ		(16 << 20) /* Initial Memory map for Linux */
#define CONFIG_SYS_BOOTM_LEN		(16 << 20) /* Increase max gunzip size */

/*
 * Internal Definitions
 */
#if defined(CONFIG_CMD_KGDB)
#define CONFIG_KGDB_BAUDRATE	230400	/* speed to run kgdb serial port*/
#define CONFIG_KGDB_SER_INDEX	2	/* which serial port to use	*/
#endif

/*
 * Pass open firmware flat tree
 */
#define CONFIG_OF_LIBFDT
#define CONFIG_OF_BOARD_SETUP

/*
 * Only very few boards have default console not on ttyS0 (like Taishan)
 */
#if !defined(CONFIG_USE_TTY)
#define CONFIG_USE_TTY	ttyS0
#endif

/*
 * Only very few boards have default netdev not set to eth0 (like Arches)
 */
#if !defined(CONFIG_USE_NETDEV)
#define CONFIG_USE_NETDEV	eth0
#endif

#define xstr(s)	str(s)
#define str(s)	#s

/*
 * PPC4xx GPIO Configuration
 */

/* 460EX: Use USB configuration */
#define CONFIG_SYS_4xx_GPIO_TABLE { /*	  Out		  GPIO	Alternate1	Alternate2	Alternate3 */ \
{											\
/* GPIO Core 0 */									\
{GPIO0_BASE, GPIO_BI , GPIO_ALT1, GPIO_OUT_0}, /* GPIO0	GMC1TxD(0)	USB2HostD(0)	*/	\
{GPIO0_BASE, GPIO_BI , GPIO_ALT1, GPIO_OUT_0}, /* GPIO1	GMC1TxD(1)	USB2HostD(1)	*/	\
{GPIO0_BASE, GPIO_BI , GPIO_ALT1, GPIO_OUT_0}, /* GPIO2	GMC1TxD(2)	USB2HostD(2)	*/	\
{GPIO0_BASE, GPIO_BI , GPIO_ALT1, GPIO_OUT_0}, /* GPIO3	GMC1TxD(3)	USB2HostD(3)	*/	\
{GPIO0_BASE, GPIO_BI , GPIO_ALT1, GPIO_OUT_0}, /* GPIO4	GMC1TxD(4)	USB2HostD(4)	*/	\
{GPIO0_BASE, GPIO_BI , GPIO_ALT1, GPIO_OUT_0}, /* GPIO5	GMC1TxD(5)	USB2HostD(5)	*/	\
{GPIO0_BASE, GPIO_BI , GPIO_ALT1, GPIO_OUT_0}, /* GPIO6	GMC1TxD(6)	USB2HostD(6)	*/	\
{GPIO0_BASE, GPIO_BI , GPIO_ALT1, GPIO_OUT_0}, /* GPIO7	GMC1TxD(7)	USB2HostD(7)	*/	\
{GPIO0_BASE, GPIO_BI , GPIO_ALT1, GPIO_OUT_0}, /* GPIO8	GMC1RxD(0)	USB2OTGD(0)	*/	\
{GPIO0_BASE, GPIO_BI , GPIO_ALT1, GPIO_OUT_0}, /* GPIO9	GMC1RxD(1)	USB2OTGD(1)	*/	\
{GPIO0_BASE, GPIO_BI , GPIO_ALT1, GPIO_OUT_0}, /* GPIO10 GMC1RxD(2)	USB2OTGD(2)	*/	\
{GPIO0_BASE, GPIO_BI , GPIO_ALT1, GPIO_OUT_0}, /* GPIO11 GMC1RxD(3)	USB2OTGD(3)	*/	\
{GPIO0_BASE, GPIO_BI , GPIO_ALT1, GPIO_OUT_0}, /* GPIO12 GMC1RxD(4)	USB2OTGD(4)	*/	\
{GPIO0_BASE, GPIO_BI , GPIO_ALT1, GPIO_OUT_0}, /* GPIO13 GMC1RxD(5)	USB2OTGD(5)	*/	\
{GPIO0_BASE, GPIO_BI , GPIO_ALT1, GPIO_OUT_0}, /* GPIO14 GMC1RxD(6)	USB2OTGD(6)	*/	\
{GPIO0_BASE, GPIO_BI , GPIO_ALT1, GPIO_OUT_0}, /* GPIO15 GMC1RxD(7)	USB2OTGD(7)	*/	\
{GPIO0_BASE, GPIO_OUT, GPIO_SEL , GPIO_OUT_0}, /* GPIO16 GMC1TxER	USB2HostStop	*/	\
{GPIO0_BASE, GPIO_IN , GPIO_ALT1, GPIO_OUT_0}, /* GPIO17 GMC1CD		USB2HostNext	*/	\
{GPIO0_BASE, GPIO_IN , GPIO_ALT1, GPIO_OUT_0}, /* GPIO18 GMC1RxER	USB2HostDir	*/	\
{GPIO0_BASE, GPIO_OUT, GPIO_SEL , GPIO_OUT_0}, /* GPIO19 GMC1TxEN	USB2OTGStop	*/	\
{GPIO0_BASE, GPIO_IN , GPIO_ALT1, GPIO_OUT_0}, /* GPIO20 GMC1CRS	USB2OTGNext	*/	\
{GPIO0_BASE, GPIO_IN , GPIO_ALT1, GPIO_OUT_0}, /* GPIO21 GMC1RxDV	USB2OTGDir	*/	\
{GPIO0_BASE, GPIO_IN , GPIO_ALT1, GPIO_OUT_0}, /* GPIO22 NFRDY				*/	\
{GPIO0_BASE, GPIO_IN , GPIO_ALT1, GPIO_OUT_0}, /* GPIO23 NFREN				*/	\
{GPIO0_BASE, GPIO_IN , GPIO_ALT1, GPIO_OUT_0}, /* GPIO24 NFWEN				*/	\
{GPIO0_BASE, GPIO_IN , GPIO_ALT1, GPIO_OUT_0}, /* GPIO25 NFCLE				*/	\
{GPIO0_BASE, GPIO_IN , GPIO_ALT1, GPIO_OUT_0}, /* GPIO26 NFALE				*/	\
{GPIO0_BASE, GPIO_IN , GPIO_ALT1, GPIO_OUT_0}, /* GPIO27 IRQ(0)				*/	\
{GPIO0_BASE, GPIO_IN , GPIO_ALT1, GPIO_OUT_0}, /* GPIO28 IRQ(1)				*/	\
{GPIO0_BASE, GPIO_IN , GPIO_ALT1, GPIO_OUT_0}, /* GPIO29 IRQ(2)				*/	\
{GPIO0_BASE, GPIO_OUT, GPIO_SEL , GPIO_OUT_0}, /* GPIO30 USER TP5 */ \
{GPIO0_BASE, GPIO_OUT, GPIO_SEL , GPIO_OUT_1}, /* GPIO31 USER TP6 */ \
},											\
{											\
/* GPIO Core 1 */									\
{GPIO1_BASE, GPIO_OUT, GPIO_SEL , GPIO_OUT_1}, /* GPIO32 USER TP8 */ \
{GPIO1_BASE, GPIO_OUT, GPIO_SEL , GPIO_OUT_1}, /* GPIO33 USER TP10 */ \
{GPIO1_BASE, GPIO_OUT, GPIO_ALT3, GPIO_OUT_1}, /* GPIO34 UART0_DCD_N	UART1_DSR_CTS_N	UART2_SOUT*/ \
{GPIO1_BASE, GPIO_IN , GPIO_ALT3, GPIO_OUT_0}, /* GPIO35 UART0_8PIN_DSR_N UART1_RTS_DTR_N UART2_SIN*/ \
{GPIO1_BASE, GPIO_IN , GPIO_ALT3, GPIO_OUT_0}, /* GPIO36 UART0_8PIN_CTS_N DMAAck3	UART3_SIN*/ \
{GPIO1_BASE, GPIO_BI , GPIO_ALT2, GPIO_OUT_0}, /* GPIO37 UART0_RTS_N	EOT3/TC3	UART3_SOUT*/ \
{GPIO1_BASE, GPIO_OUT, GPIO_ALT2, GPIO_OUT_1}, /* GPIO38 UART0_DTR_N	UART1_SOUT	*/	\
{GPIO1_BASE, GPIO_IN , GPIO_ALT2, GPIO_OUT_0}, /* GPIO39 UART0_RI_N	UART1_SIN	*/	\
{GPIO1_BASE, GPIO_IN , GPIO_ALT1, GPIO_OUT_0}, /* GPIO40 IRQ(3)				*/	\
{GPIO0_BASE, GPIO_OUT, GPIO_SEL , GPIO_OUT_1}, /* GPIO41 CS(1)				*/	\
{GPIO1_BASE, GPIO_OUT, GPIO_ALT1, GPIO_OUT_0}, /* GPIO42 CS(2)				*/	\
{GPIO1_BASE, GPIO_OUT, GPIO_ALT1, GPIO_OUT_0}, /* GPIO43 CS(3)		DMAReq1		IRQ(10)*/ \
{GPIO1_BASE, GPIO_IN , GPIO_ALT3, GPIO_OUT_0}, /* GPIO44 CS(4)		DMAAck1		IRQ(11)*/ \
{GPIO1_BASE, GPIO_IN , GPIO_ALT3, GPIO_OUT_0}, /* GPIO45 CS(5)		EOT/TC1		IRQ(12)*/ \
{GPIO1_BASE, GPIO_OUT, GPIO_ALT1, GPIO_OUT_0}, /* GPIO46 PerAddr(5)	DMAReq0		IRQ(13)*/ \
{GPIO1_BASE, GPIO_OUT, GPIO_ALT1, GPIO_OUT_0}, /* GPIO47 PerAddr(6)	DMAAck0		IRQ(14)*/ \
{GPIO1_BASE, GPIO_OUT, GPIO_ALT1, GPIO_OUT_0}, /* GPIO48 PerAddr(7)	EOT/TC0		IRQ(15)*/ \
{GPIO1_BASE, GPIO_IN , GPIO_SEL , GPIO_OUT_0}, /* GPIO49  Unselect via TraceSelect Bit	*/	\
{GPIO1_BASE, GPIO_IN , GPIO_SEL , GPIO_OUT_0}, /* GPIO50  Unselect via TraceSelect Bit	*/	\
{GPIO1_BASE, GPIO_IN , GPIO_SEL , GPIO_OUT_0}, /* GPIO51  Unselect via TraceSelect Bit	*/	\
{GPIO1_BASE, GPIO_OUT, GPIO_SEL , GPIO_OUT_1}, /* GPIO52  HD LED                       	*/	\
{GPIO1_BASE, GPIO_IN , GPIO_SEL , GPIO_OUT_0}, /* GPIO53  Unselect via TraceSelect Bit	*/	\
{GPIO1_BASE, GPIO_IN , GPIO_SEL , GPIO_OUT_0}, /* GPIO54  Unselect via TraceSelect Bit	*/	\
{GPIO1_BASE, GPIO_IN , GPIO_SEL , GPIO_OUT_0}, /* GPIO55  Unselect via TraceSelect Bit	*/	\
{GPIO1_BASE, GPIO_IN , GPIO_SEL , GPIO_OUT_0}, /* GPIO56  Unselect via TraceSelect Bit	*/	\
{GPIO1_BASE, GPIO_IN , GPIO_SEL , GPIO_OUT_0}, /* GPIO57  Unselect via TraceSelect Bit	*/	\
{GPIO1_BASE, GPIO_IN , GPIO_SEL , GPIO_OUT_0}, /* GPIO58  Unselect via TraceSelect Bit	*/	\
{GPIO1_BASE, GPIO_IN , GPIO_SEL , GPIO_OUT_0}, /* GPIO59  Unselect via TraceSelect Bit	*/	\
{GPIO1_BASE, GPIO_IN , GPIO_SEL , GPIO_OUT_0}, /* GPIO60  Unselect via TraceSelect Bit	*/	\
{GPIO1_BASE, GPIO_IN , GPIO_SEL , GPIO_OUT_0}, /* GPIO61  Unselect via TraceSelect Bit	*/	\
{GPIO1_BASE, GPIO_IN , GPIO_SEL , GPIO_OUT_0}, /* GPIO62  Unselect via TraceSelect Bit	*/	\
{GPIO1_BASE, GPIO_IN , GPIO_SEL , GPIO_OUT_0}, /* GPIO63  Unselect via TraceSelect Bit	*/	\
}											\
}

#endif	/* __CONFIG_H */
