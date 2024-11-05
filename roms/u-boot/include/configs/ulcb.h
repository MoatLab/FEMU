/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * include/configs/ulcb.h
 *     This file is ULCB board configuration.
 *
 * Copyright (C) 2017 Renesas Electronics Corporation
 */

#ifndef __ULCB_H
#define __ULCB_H

#include "rcar-gen3-common.h"

/* Ethernet RAVB */
#define CONFIG_BITBANGMII_MULTI

/* Generic Timer Definitions (use in assembler source) */
#define COUNTER_FREQUENCY	0xFE502A	/* 16.66MHz from CPclk */

/* Environment in eMMC, at the end of 2nd "boot sector" */

#define CONFIG_CFI_FLASH_USE_WEAK_ACCESSORS
#define CONFIG_FLASH_SHOW_PROGRESS	45
#define CONFIG_SYS_FLASH_QUIET_TEST
#define CONFIG_SYS_FLASH_BANKS_LIST	{ 0x08000000 }
#define CONFIG_SYS_FLASH_CFI
#define CONFIG_SYS_FLASH_CFI_WIDTH	FLASH_CFI_16BIT
#define CONFIG_SYS_MAX_FLASH_BANKS_DETECT	1
#define CONFIG_SYS_MAX_FLASH_SECT	256
#define CONFIG_SYS_WRITE_SWAPPED_DATA

#endif /* __ULCB_H */
