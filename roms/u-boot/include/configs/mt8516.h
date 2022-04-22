/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Configuration for Pumpkin board
 *
 * Copyright (C) 2019 BayLibre, SAS
 * Author: Fabien Parent <fparent@baylibre.com
 */

#ifndef __MT8516_H
#define __MT8516_H

#include <linux/sizes.h>

#define CONFIG_SYS_LOAD_ADDR		CONFIG_SYS_TEXT_BASE
#define CONFIG_SYS_MALLOC_LEN		SZ_4M

#define CONFIG_CPU_ARMV8
#define COUNTER_FREQUENCY		13000000

#define CONFIG_SYS_NS16550_SERIAL
#define CONFIG_SYS_NS16550_REG_SIZE	-4
#define CONFIG_SYS_NS16550_MEM32
#define CONFIG_SYS_NS16550_COM1		0x11005000
#define CONFIG_SYS_NS16550_CLK		26000000

#define CONFIG_SYS_INIT_SP_ADDR		(CONFIG_SYS_TEXT_BASE + SZ_2M - \
						 GENERATED_GBL_DATA_SIZE)

#define CONFIG_SYS_BOOTM_LEN		SZ_64M

/* Environment settings */
#include <config_distro_bootcmd.h>

#define BOOT_TARGET_DEVICES(func) \
	func(MMC, mmc, 0)

#define CONFIG_EXTRA_ENV_SETTINGS \
	"scriptaddr=0x40000000\0" \
	BOOTENV

#endif
