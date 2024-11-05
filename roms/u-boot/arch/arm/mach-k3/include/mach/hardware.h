/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (C) 2018 Texas Instruments Incorporated - http://www.ti.com/
 *	Lokesh Vutla <lokeshvutla@ti.com>
 */
#ifndef _ASM_ARCH_HARDWARE_H_
#define _ASM_ARCH_HARDWARE_H_

#ifdef CONFIG_SOC_K3_AM6
#include "am6_hardware.h"
#endif

#ifdef CONFIG_SOC_K3_J721E
#include "j721e_hardware.h"
#endif

#ifdef CONFIG_SOC_K3_AM642
#include "am64_hardware.h"
#endif

/* Assuming these addresses and definitions stay common across K3 devices */
#define CTRLMMR_WKUP_JTAG_ID	0x43000014
#define JTAG_ID_VARIANT_SHIFT	28
#define JTAG_ID_VARIANT_MASK	(0xf << 28)
#define JTAG_ID_PARTNO_SHIFT	12
#define JTAG_ID_PARTNO_MASK	(0xffff << 12)

#define K3_ROM_BOOT_HEADER_MAGIC	"EXTBOOT"

struct rom_extended_boot_data {
	char header[8];
	u32 num_components;
};

#endif /* _ASM_ARCH_HARDWARE_H_ */
