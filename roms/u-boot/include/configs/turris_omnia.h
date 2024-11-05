/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (C) 2017 Marek Behun <marek.behun@nic.cz>
 * Copyright (C) 2016 Tomas Hlavacek <tomas.hlavacek@nic.cz>
 */

#ifndef _CONFIG_TURRIS_OMNIA_H
#define _CONFIG_TURRIS_OMNIA_H

/*
 * High Level Configuration Options (easy to change)
 */

/*
 * TEXT_BASE needs to be below 16MiB, since this area is scrubbed
 * for DDR ECC byte filling in the SPL before loading the main
 * U-Boot into it.
 */
#define CONFIG_SYS_TCLK		250000000	/* 250MHz */

/* USB/EHCI configuration */
#define CONFIG_EHCI_IS_TDI

/* Environment in SPI NOR flash */

#define PHY_ANEG_TIMEOUT	8000	/* PHY needs a longer aneg time */

/* Keep device tree and initrd in lower memory so the kernel can access them */
#define RELOCATION_LIMITS_ENV_SETTINGS	\
	"fdt_high=0x10000000\0"		\
	"initrd_high=0x10000000\0"

/* Defines for SPL */
#define CONFIG_SPL_SIZE			(140 << 10)
#define CONFIG_SPL_MAX_SIZE		(CONFIG_SPL_SIZE - 0x0030)

#define CONFIG_SPL_BSS_START_ADDR	(0x40000000 + CONFIG_SPL_SIZE)
#define CONFIG_SPL_BSS_MAX_SIZE		(16 << 10)

#ifdef CONFIG_SPL_BUILD
#define CONFIG_SYS_MALLOC_SIMPLE
#endif

#define CONFIG_SPL_STACK		(0x40000000 + ((192 - 16) << 10))
#define CONFIG_SPL_BOOTROM_SAVE		(CONFIG_SPL_STACK + 4)
#define CONFIG_SPL_DRIVERS_MISC_SUPPORT

#ifdef CONFIG_MVEBU_SPL_BOOT_DEVICE_SPI
/* SPL related SPI defines */
# define CONFIG_SYS_U_BOOT_OFFS		CONFIG_SYS_SPI_U_BOOT_OFFS
#endif

#ifdef CONFIG_MVEBU_SPL_BOOT_DEVICE_MMC
/* SPL related MMC defines */
# define CONFIG_SYS_MMC_U_BOOT_OFFS		(160 << 10)
# define CONFIG_SYS_U_BOOT_OFFS			CONFIG_SYS_MMC_U_BOOT_OFFS
# ifdef CONFIG_SPL_BUILD
#  define CONFIG_FIXED_SDHCI_ALIGNED_BUFFER	0x00180000	/* in SDRAM */
# endif
#endif

/*
 * mv-common.h should be defined after CMD configs since it used them
 * to enable certain macros
 */
#include "mv-common.h"

/* Include the common distro boot environment */
#ifndef CONFIG_SPL_BUILD

#ifdef CONFIG_MMC
#define BOOT_TARGET_DEVICES_MMC(func) func(MMC, mmc, 0)
#else
#define BOOT_TARGET_DEVICES_MMC(func)
#endif

#ifdef CONFIG_USB_STORAGE
#define BOOT_TARGET_DEVICES_USB(func) func(USB, usb, 0)
#else
#define BOOT_TARGET_DEVICES_USB(func)
#endif

#ifdef CONFIG_SCSI
#define BOOT_TARGET_DEVICES_SCSI(func) func(SCSI, scsi, 0)
#else
#define BOOT_TARGET_DEVICES_SCSI(func)
#endif

#define BOOT_TARGET_DEVICES(func) \
	BOOT_TARGET_DEVICES_MMC(func) \
	BOOT_TARGET_DEVICES_SCSI(func) \
	BOOT_TARGET_DEVICES_USB(func) \
	func(PXE, pxe, na) \
	func(DHCP, dhcp, na)

#define KERNEL_ADDR_R	__stringify(0x1000000)
#define FDT_ADDR_R	__stringify(0x2000000)
#define RAMDISK_ADDR_R	__stringify(0x2200000)
#define SCRIPT_ADDR_R	__stringify(0x1800000)
#define PXEFILE_ADDR_R	__stringify(0x1900000)

#define LOAD_ADDRESS_ENV_SETTINGS \
	"kernel_addr_r=" KERNEL_ADDR_R "\0" \
	"fdt_addr_r=" FDT_ADDR_R "\0" \
	"ramdisk_addr_r=" RAMDISK_ADDR_R "\0" \
	"scriptaddr=" SCRIPT_ADDR_R "\0" \
	"pxefile_addr_r=" PXEFILE_ADDR_R "\0"

#include <config_distro_bootcmd.h>

/*
 * The factory reset bootcommand on Omnia first sets all the front LEDs to green
 * and then tries to load the rescue image from SPI flash memory and boot it
 */
#define TURRIS_OMNIA_BOOTCMD_RESCUE \
	"i2c dev 2; " \
	"i2c mw 0x2a.1 0x3 0x1c 1; " \
	"i2c mw 0x2a.1 0x4 0x1c 1; " \
	"mw.l 0x01000000 0x00ff000c; " \
	"i2c write 0x01000000 0x2a.1 0x5 4 -s; " \
	"setenv bootargs \"earlyprintk console=ttyS0,115200" \
		" omniarescue=$omnia_reset rescue_mode=$omnia_reset\"; " \
	"sf probe; " \
	"sf read 0x1000000 0x100000 0x700000; " \
	"lzmadec 0x1000000 0x1700000; " \
	"if gpio input gpio@71_4; then " \
		"bootm 0x1700000#sfp; " \
	"else " \
		"bootm 0x1700000; " \
	"fi; " \
	"bootz 0x1000000"

#define CONFIG_EXTRA_ENV_SETTINGS \
	RELOCATION_LIMITS_ENV_SETTINGS \
	LOAD_ADDRESS_ENV_SETTINGS \
	"fdtfile=" CONFIG_DEFAULT_DEVICE_TREE ".dtb\0" \
	"console=ttyS0,115200\0" \
	"ethact=ethernet@34000\0" \
	"bootcmd_rescue=" TURRIS_OMNIA_BOOTCMD_RESCUE "\0" \
	BOOTENV

#endif /* CONFIG_SPL_BUILD */

#endif /* _CONFIG_TURRIS_OMNIA_H */
