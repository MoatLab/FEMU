/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (C) 2014 Soeren Moch <smoch@web.de>
 *
 * Configuration settings for the TBS2910 MatrixARM board.
 */

#ifndef __TBS2910_CONFIG_H
#define __TBS2910_CONFIG_H

#include "mx6_common.h"

/* General configuration */

#define CONFIG_MACH_TYPE		3980

#define CONFIG_SYS_HZ			1000

/* Physical Memory Map */
#define CONFIG_SYS_SDRAM_BASE		MMDC0_ARB_BASE_ADDR

#define CONFIG_SYS_INIT_RAM_ADDR	IRAM_BASE_ADDR
#define CONFIG_SYS_INIT_RAM_SIZE	IRAM_SIZE
#define CONFIG_SYS_INIT_SP_OFFSET \
	(CONFIG_SYS_INIT_RAM_SIZE - GENERATED_GBL_DATA_SIZE)
#define CONFIG_SYS_INIT_SP_ADDR \
	(CONFIG_SYS_INIT_RAM_ADDR + CONFIG_SYS_INIT_SP_OFFSET)

#define CONFIG_SYS_MALLOC_LEN		(128 * 1024 * 1024)

#define CONFIG_SYS_BOOTMAPSZ		0x10000000

/* Serial console */
#define CONFIG_MXC_UART_BASE		UART1_BASE /* select UART1/UART2 */

/* Framebuffer */
#define CONFIG_IMX_HDMI
#define CONFIG_IMX_VIDEO_SKIP

/* PCI */
#ifdef CONFIG_CMD_PCI
#define CONFIG_PCI_SCAN_SHOW
#define CONFIG_PCIE_IMX
#define CONFIG_PCIE_IMX_PERST_GPIO	IMX_GPIO_NR(7, 12)
#endif

/* SATA */
#ifdef CONFIG_CMD_SATA
#define CONFIG_SYS_SATA_MAX_DEVICE	1
#define CONFIG_DWC_AHSATA_PORT_ID	0
#define CONFIG_DWC_AHSATA_BASE_ADDR	SATA_ARB_BASE_ADDR
#define CONFIG_LBA48
#define CONFIG_SYS_64BIT_LBA
#endif

/* USB */
#ifdef CONFIG_CMD_USB
#define CONFIG_EHCI_HCD_INIT_AFTER_RESET
#define CONFIG_MXC_USB_PORTSC		(PORT_PTS_UTMI | PORT_PTS_PTW)
#ifdef CONFIG_CMD_USB_MASS_STORAGE
#define CONFIG_USBD_HS
#endif /* CONFIG_CMD_USB_MASS_STORAGE */
#endif /* CONFIG_CMD_USB      */

#define CONFIG_BOARD_SIZE_LIMIT		392192 /* (CONFIG_ENV_OFFSET - 1024) */

#define CONFIG_EXTRA_ENV_SETTINGS \
	BOOTENV \
	"bootargs_mmc1=console=ttymxc0,115200 di0_primary console=tty1\0" \
	"bootargs_mmc2=video=mxcfb0:dev=hdmi,1920x1080M@60 " \
			"video=mxcfb1:off video=mxcfb2:off fbmem=28M\0" \
	"bootargs_mmc3=root=/dev/mmcblk0p1 rootwait consoleblank=0 quiet\0" \
	"bootargs_mmc=setenv bootargs ${bootargs_mmc1} ${bootargs_mmc2} " \
			"${bootargs_mmc3}\0" \
	"bootargs_upd=setenv bootargs console=ttymxc0,115200 " \
			"rdinit=/sbin/init enable_wait_mode=off\0" \
	"bootcmd_mmc=run bootargs_mmc; mmc dev 2; " \
			"mmc read 0x10800000 0x800 0x4000; bootm 0x10800000\0" \
	"bootcmd_up1=load mmc 1 0x10800000 uImage\0" \
	"bootcmd_up2=load mmc 1 0x10d00000 uramdisk.img; " \
			"run bootargs_upd; " \
			"bootm 0x10800000 0x10d00000\0" \
	"console=ttymxc0\0" \
	"fan=gpio set 92\0" \
	"fdt_addr_r=0x18000000\0" \
	"fdtfile=" CONFIG_DEFAULT_FDT_FILE "\0" \
	"kernel_addr_r=0x12000000\0" \
	"pxefile_addr_r=0x10100000\0" \
	"ramdisk_addr_r=0x18080000\0" \
	"scriptaddr=0x10000000\0" \
	"set_con_serial=setenv stdout serial; " \
			"setenv stderr serial\0" \
	"set_con_hdmi=setenv stdout serial,vidconsole; " \
			"setenv stderr serial,vidconsole\0" \
	"stderr=serial,vidconsole\0" \
	"stdin=serial,usbkbd\0" \
	"stdout=serial,vidconsole\0"

/* Enable distro boot */
#define BOOT_TARGET_DEVICES(func) \
	func(MMC, mmc, 0) \
	func(MMC, mmc, 1) \
	func(MMC, mmc, 2) \
	func(SATA, sata, 0) \
	func(USB, usb, 0)

#include <config_distro_bootcmd.h>

#endif			       /* __TBS2910_CONFIG_H * */
