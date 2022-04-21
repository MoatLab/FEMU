// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2017-2019 IBM Corp. */

#ifndef __PHYS_MAP_H
#define __PHYS_MAP_H

#include <compiler.h>
#include <stdint.h>
#include <processor.h>
#include <ccan/endian/endian.h>
#include <chip.h>

enum phys_map_type {
	NULL_MAP,
	SYSTEM_MEM,
	GPU_MEM_4T_DOWN,
	GPU_MEM_4T_UP,
	OCAPI_MEM,
	PHB4_64BIT_MMIO,
	PHB4_32BIT_MMIO,
	PHB4_XIVE_ESB,
	PHB4_REG_SPC,
	PHB5_64BIT_MMIO,
	PHB5_32BIT_MMIO,
	PHB5_XIVE_ESB,
	PHB5_REG_SPC,
	NPU_OCAPI_MMIO,
	XIVE_VC,
	XIVE_PC,
	VAS_USER_WIN,
	VAS_HYP_WIN,
	OCAB_XIVE_ESB,
	LPC_BUS,
	FSP_MMIO,
	NPU_REGS,
	NPU_USR,
	NPU_PHY,
	NPU_NTL,
	NPU_GENID,
	PSIHB_REG,
	XIVE_IC,
	XIVE_TM,
	PSIHB_ESB,
	NX_RNG,
	CENTAUR_SCOM,
	MC_OCMB_CFG,
	MC_OCMB_MMIO,
	XSCOM,
	RESV,
	XIVE_NVC,
	XIVE_NVPG,
	XIVE_ESB,
	XIVE_END,
};

extern void phys_map_get(uint64_t gcid, enum phys_map_type type,
			 int index, uint64_t *addr, uint64_t *size);

extern void __phys_map_get(uint64_t topology_idx, uint64_t gcid,
			   enum phys_map_type type, int index, uint64_t *addr, uint64_t *size);

extern void phys_map_init(unsigned long pvr);

#endif /* __PHYS_MAP_H */

//TODO self test overlaps and alignemnt and size.
