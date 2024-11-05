/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright 2017 NXP
 * Copyright 2020 Linaro
 *
 */

#ifndef __COMPULAB_DDR_H__
#define __COMPULAB_DDR_H__

extern struct dram_timing_info ucm_dram_timing_ff020008;
extern struct dram_timing_info ucm_dram_timing_ff000110;
extern struct dram_timing_info ucm_dram_timing_01061010;

void spl_dram_init_compulab(void);

#define TCM_DATA_CFG 0x7e0000

struct lpddr4_tcm_desc {
	unsigned int size;
	unsigned int sign;
	unsigned int index;
	unsigned int count;
};

#endif
