// SPDX-License-Identifier: BSD-2-Clause
/*
 * fdt_pmu.c - Flat Device Tree PMU helper routines
 *
 * Copyright (c) 2021 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *   Atish Patra <atish.patra@wdc.com>
 */

#ifndef __FDT_PMU_H__
#define __FDT_PMU_H__

#include <sbi/sbi_types.h>

struct fdt_pmu_hw_event_select_map {
	uint32_t eidx;
	uint64_t select;
};

struct fdt_pmu_hw_event_counter_map {
	uint32_t eidx_start;
	uint32_t eidx_end;
	uint32_t ctr_map;
};

struct fdt_pmu_raw_event_counter_map {
	uint64_t select;
	uint64_t select_mask;
	uint32_t ctr_map;
};

#ifdef CONFIG_FDT_PMU

/**
 * Fix up the PMU node in the device tree
 *
 * This routine:
 * 1. Disables opensbi specific properties from the DT
 *
 * It is recommended that platform support call this function in
 * their final_init() platform operation.
 *
 * @param fdt device tree blob
 */
int fdt_pmu_fixup(void *fdt);

/**
 * Setup PMU data from device tree
 *
 * @param fdt device tree blob
 *
 * @return 0 on success and negative error code on failure
 */
int fdt_pmu_setup(void *fdt);

/**
 * Get the mhpmevent select value read from DT for a given event
 * @param event_idx Event ID of the given event
 *
 * @return The select value read from DT or 0 if given index was not found
 */
uint64_t fdt_pmu_get_select_value(uint32_t event_idx);

/** The event index to selector value table instance */
extern struct fdt_pmu_hw_event_select_map fdt_pmu_evt_select[];
/** The number of valid entries in fdt_pmu_evt_select[] */
extern uint32_t hw_event_count;

#else

static inline void fdt_pmu_fixup(void *fdt) { }
static inline int fdt_pmu_setup(void *fdt) { return 0; }
static inline uint64_t fdt_pmu_get_select_value(uint32_t event_idx) { return 0; }

#endif

#endif
