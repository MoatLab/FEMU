// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __SLW_H
#define __SLW_H

#include <stdint.h>
#include <stdbool.h>

#include <ccan/short_types/short_types.h>

/* Define device-tree fields */
#define MAX_NAME_LEN	16
struct cpu_idle_states {
	char name[MAX_NAME_LEN];
	u32 latency_ns;
	u32 residency_ns;
	/*
	 * Register value/mask used to select different idle states.
	 * PMICR in POWER8 and PSSCR in POWER9
	 */
	u64 pm_ctrl_reg_val;
	u64 pm_ctrl_reg_mask;
	u32 flags;
};

/* Track failure in Wakup engine */
enum wakeup_engine_states {
	WAKEUP_ENGINE_NOT_PRESENT,
	WAKEUP_ENGINE_PRESENT,
	WAKEUP_ENGINE_FAILED
};
extern enum wakeup_engine_states wakeup_engine_state;
extern bool has_deep_states;

/* Patch SPR in SLW image */
extern int64_t opal_slw_set_reg(uint64_t cpu_pir, uint64_t sprn, uint64_t val);

extern void slw_init(void);

/* P8 specific */
struct cpu_thread;
struct proc_chip;
extern int64_t opal_slw_set_reg_p8(struct cpu_thread *c, struct proc_chip *chip,
			    uint64_t sprn, uint64_t val);
extern void slw_p8_init(void);
extern void find_cpu_idle_state_properties_p8(struct cpu_idle_states **states, int *nr_states, bool *can_sleep);

#endif /* __SKIBOOT_H */
