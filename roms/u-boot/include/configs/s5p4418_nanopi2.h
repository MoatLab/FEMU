/* SPDX-License-Identifier: GPL-2.0+
 *
 * Copyright (C) Guangzhou FriendlyARM Computer Tech. Co., Ltd.
 * (http://www.friendlyarm.com)
 *
 * (C) Copyright 2016 Nexell
 * Hyejung Kwon <cjscld15@nexell.co.kr>
 *
 * Copyright (C) 2019  Stefan Bosch <stefan_b@posteo.net>
 */

#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <linux/sizes.h>
#include <asm/arch/nexell.h>

/*-----------------------------------------------------------------------
 *  System memory Configuration
 */
#define CONFIG_SYS_INIT_SP_ADDR		CONFIG_SYS_TEXT_BASE
#define CONFIG_SYS_MONITOR_BASE		CONFIG_SYS_TEXT_BASE
#define CONFIG_SYS_MEM_SIZE		0x40000000
#define CONFIG_SYS_SDRAM_BASE		0x71000000

/*
 * "(CONFIG_SYS_MEM_SIZE - CONFIG_SYS_RESERVE_MEM_SIZE)" has been used in
 * u-boot nanopi2-v2016.01.
 * This is not working anymore because boot_fdt_add_mem_rsv_regions() in
 * common/image-fdt.c has been extended:
 * Also reserved-memory sections are marked as unusable.
 *
 * In friendlyArm Ubuntu 16.04 source arch/arm/boot/dts/s5p4418.dtsi:
 *        reserved-memory {
 *            #address-cells = <1>;
 *            #size-cells = <1>;
 *            ranges;
 *
 *            secure_memory@b0000000 {
 *                reg = <0xB0000000 0x1000000>;
 *                nop-map;
 *            };
 *        };
 *
 * arch_lmb_reserve() of arch/arm/lib/bootm.c:
 *     "Allocate space for command line and board info - ... below the current
 *      stack pointer."
 *      --> Memory allocated would overlap with "secure_memory@b0000000"
 *      --> lmb_add_region(rgn, base==0xb0000000, size==0x1000000) fails,
 *      boot output:
 *        ...
 *        Kernel image @ 0x71080000 [ 0x000000 - 0x60e628 ]
 *        ## Flattened Device Tree blob at 7a000000
 *           Booting using the fdt blob at 0x7a000000
 *        ERROR: reserving fdt memory region failed (addr=b0000000 size=1000000)
 *           Using Device Tree in place at 7a000000, end 7a00fbf0
 *
 *        Starting kernel ...
 *        ...
 */
#define CONFIG_SYS_SDRAM_SIZE		(0xb0000000 - CONFIG_SYS_SDRAM_BASE)

#define CONFIG_SYS_MALLOC_LEN		(32 * 1024 * 1024)

#define BMP_LOAD_ADDR			0x78000000

/* kernel load address */
#define CONFIG_SYS_LOAD_ADDR		0x71080000
#define INITRD_START			0x79000000
#define KERNEL_DTB_ADDR			0x7A000000

/*-----------------------------------------------------------------------
 *  High Level System Configuration
 */
/* Not used: not need IRQ/FIQ stuff */
#undef  CONFIG_USE_IRQ
/* decrementer freq: 1ms ticks */
#define CONFIG_SYS_HZ			1000

/*-----------------------------------------------------------------------
 *  System initialize options (board_init_f)
 */
/* board_init_f->init_sequence, call arch_cpu_init */
#define CONFIG_ARCH_CPU_INIT

/*-----------------------------------------------------------------------
 * Miscellaneous configurable options
 */
#ifdef CONFIG_SYS_PROMPT
#undef CONFIG_SYS_PROMPT
/* Monitor Command Prompt */
#define CONFIG_SYS_PROMPT		"nanopi2# "
#endif

/* Console I/O Buffer Size */
#define CONFIG_SYS_CBSIZE		1024
/* Print Buffer Size */
#define CONFIG_SYS_PBSIZE		(CONFIG_SYS_CBSIZE +             \
					 sizeof(CONFIG_SYS_PROMPT) + 16)
/* max number of command args */
#define CONFIG_SYS_MAXARGS		16
/* Boot Argument Buffer Size */
#define CONFIG_SYS_BARGSIZE		CONFIG_SYS_CBSIZE

/*-----------------------------------------------------------------------
 * Etc Command definition
 */
#undef CONFIG_BOOTM_NETBSD
#undef CONFIG_BOOTM_RTEMS

/*-----------------------------------------------------------------------
 * serial console configuration
 */
#define CONFIG_PL011_CLOCK		50000000
#define CONFIG_PL01x_PORTS		{(void *)PHY_BASEADDR_UART0, \
					 (void *)PHY_BASEADDR_UART1, \
					 (void *)PHY_BASEADDR_UART2, \
					 (void *)PHY_BASEADDR_UART3}
#define CONFIG_SYS_BAUDRATE_TABLE	{ 9600, 19200, 38400, 57600, 115200 }

/*-----------------------------------------------------------------------
 * PLL
 */
#define CONFIG_SYS_PLLFIN		24000000UL

/*-----------------------------------------------------------------------
 * Timer
 */
#define CONFIG_TIMER_SYS_TICK_CH	0

/*-----------------------------------------------------------------------
 * BACKLIGHT
 */
#ifndef CONFIG_S5P4418_ONEWIRE
#ifdef CONFIG_PWM_NX
/* fallback to pwm */
#define BACKLIGHT_CH		0
#define BACKLIGHT_DIV		0
#define BACKLIGHT_INV		0
#define BACKLIGHT_DUTY		50
#define BACKLIGHT_HZ		1000
#endif
#endif

/*-----------------------------------------------------------------------
 * VIDEO
 */

#define CONFIG_VIDEO_LOGO

#ifdef CONFIG_VIDEO_LOGO
#ifdef CONFIG_SPLASH_SCREEN
#define SPLASH_FILE			logo.bmp
#endif

#endif

/*-----------------------------------------------------------------------
 * ENV
 */
#define BLOADER_MMC						\
	"ext4load mmc ${rootdev}:${bootpart} "

#ifdef CONFIG_OF_BOARD_SETUP
#define EXTRA_ENV_DTB_RESERVE					\
	"dtb_reserve="						\
	"if test -n \"$dtb_addr\"; then fdt addr $dtb_addr; fi\0"
#else
#define EXTRA_ENV_DTB_RESERVE					\
	"dtb_reserve="						\
	"if test -n \"$fb_addr\"; then "			\
	  "fdt addr $dtb_addr;"					\
	  "fdt resize;"						\
	  "fdt mk /reserved-memory display_reserved;"		\
	  "fdt set /reserved-memory/display_reserved "		\
	    "reg <$fb_addr 0x800000>;"				\
	"fi;\0"
#endif

#ifdef CONFIG_SPLASH_SCREEN
#define EXTRA_ENV_BOOT_LOGO					\
	"splashimage=" __stringify(BMP_LOAD_ADDR)"\0"		\
	"splashfile=" __stringify(SPLASH_FILE)"\0"		\
	"splashpos=m,m\0"					\
	"fb_addr=\0"						\
	EXTRA_ENV_DTB_RESERVE
#else
	#define EXTRA_ENV_BOOT_LOGO  EXTRA_ENV_DTB_RESERVE
#endif

#define CONFIG_EXTRA_ENV_SETTINGS				\
	"fdt_high=0xffffffff\0"					\
	"initrd_high=0xffffffff\0"				\
	"rootdev=" __stringify(CONFIG_ROOT_DEV) "\0"		\
	"rootpart=" __stringify(CONFIG_ROOT_PART) "\0"		\
	"bootpart=" __stringify(CONFIG_BOOT_PART) "\0"		\
	"kernel=zImage\0"					\
	"loadaddr=" __stringify(CONFIG_SYS_LOAD_ADDR) "\0"	\
	"dtb_name=s5p4418-nanopi2-rev01.dtb\0"			\
	"dtb_addr=" __stringify(KERNEL_DTB_ADDR) "\0"		\
	"initrd_name=ramdisk.img\0"				\
	"initrd_addr=" __stringify(INITRD_START) "\0"		\
	"initrd_size=0x600000\0"				\
	"load_dtb="						\
		BLOADER_MMC "${dtb_addr} ${dtb_name}; "		\
		"run dtb_reserve\0"				\
	"load_kernel="						\
		BLOADER_MMC "${loadaddr} ${kernel}\0"		\
	"load_initrd="						\
		BLOADER_MMC "${initrd_addr} ${initrd_name}; "	\
		"setenv initrd_size 0x${filesize}\0"		\
	"mmcboot="						\
		"run load_kernel; run load_initrd; run load_dtb; "	\
		"bootz ${loadaddr} ${initrd_addr}:${initrd_size} "	\
		  "${dtb_addr}\0"				\
	"bootcmd=run mmcboot\0"					\
	EXTRA_ENV_BOOT_LOGO

#endif /* __CONFIG_H__ */
