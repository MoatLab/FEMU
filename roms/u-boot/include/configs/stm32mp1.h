/* SPDX-License-Identifier: GPL-2.0+ OR BSD-3-Clause */
/*
 * Copyright (C) 2018, STMicroelectronics - All Rights Reserved
 *
 * Configuration settings for the STM32MP15x CPU
 */

#ifndef __CONFIG_H
#define __CONFIG_H
#include <linux/sizes.h>
#include <asm/arch/stm32.h>

#ifndef CONFIG_TFABOOT
/* PSCI support */
#define CONFIG_ARMV7_SECURE_BASE		STM32_SYSRAM_BASE
#define CONFIG_ARMV7_SECURE_MAX_SIZE		STM32_SYSRAM_SIZE
#endif

/*
 * Configuration of the external SRAM memory used by U-Boot
 */
#define CONFIG_SYS_SDRAM_BASE			STM32_DDR_BASE
#define CONFIG_SYS_INIT_SP_ADDR			CONFIG_SYS_TEXT_BASE

/*
 * Console I/O buffer size
 */
#define CONFIG_SYS_CBSIZE			SZ_1K

/*
 * default load address used for command tftp,  bootm , loadb, ...
 */
#define CONFIG_LOADADDR			0xc2000000
#define CONFIG_SYS_LOAD_ADDR		CONFIG_LOADADDR

/* ATAGs */
#define CONFIG_CMDLINE_TAG
#define CONFIG_SETUP_MEMORY_TAGS
#define CONFIG_INITRD_TAG

/*
 * For booting Linux, use the first 256 MB of memory, since this is
 * the maximum mapped by the Linux kernel during initialization.
 */
#define CONFIG_SYS_BOOTMAPSZ		SZ_256M

/* Extend size of kernel image for uncompression */
#define CONFIG_SYS_BOOTM_LEN		SZ_32M

/* SPL support */
#ifdef CONFIG_SPL
/* SPL use DDR */
#define CONFIG_SYS_SPL_MALLOC_START	0xC0300000
#define CONFIG_SYS_SPL_MALLOC_SIZE	0x01D00000

/* Restrict SPL to fit within SYSRAM */
#define STM32_SYSRAM_END		(STM32_SYSRAM_BASE + STM32_SYSRAM_SIZE)
#define CONFIG_SPL_MAX_FOOTPRINT	(STM32_SYSRAM_END - CONFIG_SPL_TEXT_BASE)
#define CONFIG_SPL_STACK		(STM32_SYSRAM_BASE + \
					 STM32_SYSRAM_SIZE)
#endif /* #ifdef CONFIG_SPL */
/*MMC SD*/
#define CONFIG_SYS_MMC_MAX_DEVICE	3

/* NAND support */
#define CONFIG_SYS_NAND_ONFI_DETECTION
#define CONFIG_SYS_MAX_NAND_DEVICE	1

/* Ethernet need */
#ifdef CONFIG_DWC_ETH_QOS
#define CONFIG_SERVERIP                 192.168.1.1
#define CONFIG_BOOTP_SERVERIP
#define CONFIG_SYS_AUTOLOAD		"no"
#endif

/*****************************************************************************/
#ifdef CONFIG_DISTRO_DEFAULTS
/*****************************************************************************/

#if !defined(CONFIG_SPL_BUILD)

#ifdef CONFIG_CMD_MMC
#define BOOT_TARGET_MMC0(func)	func(MMC, mmc, 0)
#define BOOT_TARGET_MMC1(func)	func(MMC, mmc, 1)
#define BOOT_TARGET_MMC2(func)	func(MMC, mmc, 2)
#else
#define BOOT_TARGET_MMC0(func)
#define BOOT_TARGET_MMC1(func)
#define BOOT_TARGET_MMC2(func)
#endif

#ifdef CONFIG_NET
#define BOOT_TARGET_PXE(func)	func(PXE, pxe, na)
#else
#define BOOT_TARGET_PXE(func)
#endif

#ifdef CONFIG_CMD_UBIFS
#define BOOT_TARGET_UBIFS(func)	func(UBIFS, ubifs, 0)
#else
#define BOOT_TARGET_UBIFS(func)
#endif

#ifdef CONFIG_USB
#define BOOT_TARGET_USB(func)	func(USB, usb, 0)
#else
#define BOOT_TARGET_USB(func)
#endif

#define BOOT_TARGET_DEVICES(func)	\
	BOOT_TARGET_MMC1(func)		\
	BOOT_TARGET_UBIFS(func)		\
	BOOT_TARGET_MMC0(func)		\
	BOOT_TARGET_MMC2(func)		\
	BOOT_TARGET_USB(func)		\
	BOOT_TARGET_PXE(func)

/*
 * bootcmd for stm32mp1:
 * for serial/usb: execute the stm32prog command
 * for mmc boot (eMMC, SD card), boot only on the same device
 * for nand or spi-nand boot, boot with on ubifs partition on UBI partition
 * for nor boot, use SD card = mmc0
 */
#define STM32MP_BOOTCMD "bootcmd_stm32mp=" \
	"echo \"Boot over ${boot_device}${boot_instance}!\";" \
	"if test ${boot_device} = serial || test ${boot_device} = usb;" \
	"then stm32prog ${boot_device} ${boot_instance}; " \
	"else " \
		"run env_check;" \
		"if test ${boot_device} = mmc;" \
		"then env set boot_targets \"mmc${boot_instance}\"; fi;" \
		"if test ${boot_device} = nand ||" \
		  " test ${boot_device} = spi-nand ;" \
		"then env set boot_targets ubifs0; fi;" \
		"if test ${boot_device} = nor;" \
		"then env set boot_targets mmc0; fi;" \
		"run distro_bootcmd;" \
	"fi;\0"

#ifdef CONFIG_FASTBOOT_CMD_OEM_FORMAT
/* eMMC default partitions for fastboot command: oem format */
#define PARTS_DEFAULT \
	"partitions=" \
	"name=ssbl,size=2M;" \
	"name=bootfs,size=64MB,bootable;" \
	"name=vendorfs,size=16M;" \
	"name=rootfs,size=746M;" \
	"name=userfs,size=-\0"
#else
#define PARTS_DEFAULT
#endif

#include <config_distro_bootcmd.h>

/*
 * memory layout for 32M uncompressed/compressed kernel,
 * 1M fdt, 1M script, 1M pxe and 1M for splashimage
 * and the ramdisk at the end.
 */
#define CONFIG_EXTRA_ENV_SETTINGS \
	"kernel_addr_r=0xc2000000\0" \
	"fdt_addr_r=0xc4000000\0" \
	"scriptaddr=0xc4100000\0" \
	"pxefile_addr_r=0xc4200000\0" \
	"splashimage=0xc4300000\0"  \
	"ramdisk_addr_r=0xc4400000\0" \
	"altbootcmd=run bootcmd\0" \
	"env_check=if env info -p -d -q; then env save; fi\0" \
	STM32MP_BOOTCMD \
	PARTS_DEFAULT \
	BOOTENV \
	"boot_net_usb_start=true\0"

#endif /* ifndef CONFIG_SPL_BUILD */
#endif /* ifdef CONFIG_DISTRO_DEFAULTS*/

#endif /* __CONFIG_H */
