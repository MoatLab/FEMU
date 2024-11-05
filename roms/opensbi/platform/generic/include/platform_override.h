/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *   Anup Patel <anup.patel@wdc.com>
 */

#ifndef __PLATFORM_OVERRIDE_H__
#define __PLATFORM_OVERRIDE_H__

#include <sbi/sbi_ecall.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_types.h>
#include <sbi/sbi_trap.h>

struct platform_override {
	const struct fdt_match *match_table;
	u64 (*features)(const struct fdt_match *match);
	u64 (*tlbr_flush_limit)(const struct fdt_match *match);
	u32 (*tlb_num_entries)(const struct fdt_match *match);
	bool (*cold_boot_allowed)(u32 hartid, const struct fdt_match *match);
	int (*early_init)(bool cold_boot, const struct fdt_match *match);
	int (*final_init)(bool cold_boot, const struct fdt_match *match);
	void (*early_exit)(const struct fdt_match *match);
	void (*final_exit)(const struct fdt_match *match);
	int (*fdt_fixup)(void *fdt, const struct fdt_match *match);
	int (*extensions_init)(const struct fdt_match *match,
			       struct sbi_hart_features *hfeatures);
	int (*pmu_init)(const struct fdt_match *match);
	void (*fw_init)(void *fdt, const struct fdt_match *match);
	int (*vendor_ext_provider)(long funcid,
				   struct sbi_trap_regs *regs,
				   struct sbi_ecall_return *out,
				   const struct fdt_match *match);
};

#endif
