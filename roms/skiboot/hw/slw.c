// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Everything to do with deep power saving (stop) states
 * SLeep/Winkle, Handle ChipTOD chip & configure core timebases
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <skiboot.h>
#include <xscom.h>
#include <xscom-p8-regs.h>
#include <xscom-p9-regs.h>
#include <xscom-p10-regs.h>
#include <io.h>
#include <cpu.h>
#include <chip.h>
#include <mem_region.h>
#include <chiptod.h>
#include <interrupts.h>
#include <timebase.h>
#include <errorlog.h>
#include <libfdt/libfdt.h>
#include <opal-api.h>
#include <nvram.h>
#include <sbe-p8.h>
#include <xive.h>

#include <p10_stop_api.H>
#include <p8_pore_table_gen_api.H>
#include <sbe_xip_image.h>

enum wakeup_engine_states wakeup_engine_state = WAKEUP_ENGINE_NOT_PRESENT;
bool has_deep_states = false;

DEFINE_LOG_ENTRY(OPAL_RC_SLW_INIT, OPAL_PLATFORM_ERR_EVT, OPAL_SLW,
		 OPAL_PLATFORM_FIRMWARE, OPAL_PREDICTIVE_ERR_GENERAL,
		 OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_SLW_SET, OPAL_PLATFORM_ERR_EVT, OPAL_SLW,
		 OPAL_PLATFORM_FIRMWARE, OPAL_INFO,
		 OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_SLW_GET, OPAL_PLATFORM_ERR_EVT, OPAL_SLW,
		 OPAL_PLATFORM_FIRMWARE, OPAL_INFO,
		 OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_SLW_REG, OPAL_PLATFORM_ERR_EVT, OPAL_SLW,
		 OPAL_PLATFORM_FIRMWARE, OPAL_INFO,
		 OPAL_NA);

static bool slw_general_init(struct proc_chip *chip, struct cpu_thread *c)
{
	uint32_t core = pir_to_core_id(c->pir);
	uint64_t tmp;
	int rc;

	/* PowerManagement GP0 clear PM_DISABLE */
	rc = xscom_read(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_GP0), &tmp);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_INIT),
				"SLW: Failed to read PM_GP0\n");
		return false;
	}
	tmp = tmp & ~0x8000000000000000ULL;
	rc = xscom_write(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_GP0), tmp);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_INIT),
				"SLW: Failed to write PM_GP0\n");
		return false;
	}
	prlog(PR_TRACE, "SLW: PMGP0 set to 0x%016llx\n", tmp);

	/* Read back for debug */
	rc = xscom_read(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_GP0), &tmp);
	if (rc)
		log_simple_error(&e_info(OPAL_RC_SLW_INIT),
				 "SLW: Failed to re-read PM_GP0. Continuing...\n");

	prlog(PR_TRACE, "SLW: PMGP0 read   0x%016llx\n", tmp);

	return true;
}

static bool slw_set_overrides(struct proc_chip *chip, struct cpu_thread *c)
{
	uint32_t core = pir_to_core_id(c->pir);
	int rc;

	rc = xscom_write(chip->id,
			 XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_SPECIAL_WAKEUP_PHYP),
			 0);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_SET),
			"SLW: Failed to write PM_SPECIAL_WAKEUP_PHYP\n");
		return false;
	}

	return true;
}

static bool slw_set_overrides_p10(struct proc_chip *chip, struct cpu_thread *c)
{
	uint64_t tmp;
	int rc;
	uint32_t core = pir_to_core_id(c->pir);

	/* Special wakeup bits that could hold power mgt */
	rc = xscom_read(chip->id,
			XSCOM_ADDR_P10_QME_CORE(core, P10_QME_SPWU_HYP),
			&tmp);
        if (rc) {
          log_simple_error(&e_info(OPAL_RC_SLW_SET),
                           "SLW: Failed to read P10_QME_SPWU_HYP\n");
          return false;
        }
        if (tmp & P10_SPWU_REQ)
		prlog(PR_WARNING,
		        "SLW: core %d P10_QME_SPWU_HYP requested 0x%016llx\n",
		      core, tmp);

	return true;
}


static bool slw_set_overrides_p9(struct proc_chip *chip, struct cpu_thread *c)
{
	uint64_t tmp;
	int rc;
	uint32_t core = pir_to_core_id(c->pir);

	/* Special wakeup bits that could hold power mgt */
	rc = xscom_read(chip->id,
			XSCOM_ADDR_P9_EC_SLAVE(core, EC_PPM_SPECIAL_WKUP_HYP),
			&tmp);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_SET),
				 "SLW: Failed to read EC_PPM_SPECIAL_WKUP_HYP\n");
		return false;
	}
	if (tmp)
		prlog(PR_WARNING,
			"SLW: core %d EC_PPM_SPECIAL_WKUP_HYP read  0x%016llx\n",
		     core, tmp);
	rc = xscom_read(chip->id,
			XSCOM_ADDR_P9_EC_SLAVE(core, EC_PPM_SPECIAL_WKUP_OTR),
			&tmp);
	if (tmp)
		prlog(PR_WARNING,
			"SLW: core %d EC_PPM_SPECIAL_WKUP_OTR read  0x%016llx\n",
		      core, tmp);
	return true;
}

static bool slw_set_idle_mode(struct proc_chip *chip, struct cpu_thread *c)
{
	uint32_t core = pir_to_core_id(c->pir);
	uint64_t tmp;
	int rc;

	/*
	 * PM GP1 allows fast/deep mode to be selected independently for sleep
	 * and winkle. Init PM GP1 so that sleep happens in fast mode and
	 * winkle happens in deep mode.
	 * Make use of the OR XSCOM for this since the OCC might be manipulating
	 * the PM_GP1 register as well. Before doing this ensure that the bits
	 * managing idle states are cleared so as to override any bits set at
	 * init time.
	 */

	tmp = ~EX_PM_GP1_SLEEP_WINKLE_MASK;
	rc = xscom_write(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_CLEAR_GP1),
			 tmp);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_SET),
						"SLW: Failed to write PM_GP1\n");
		return false;
	}

	rc = xscom_write(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_SET_GP1),
			 EX_PM_SETUP_GP1_FAST_SLEEP_DEEP_WINKLE);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_SET),
						"SLW: Failed to write PM_GP1\n");
		return false;
	}

	/* Read back for debug */
	xscom_read(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_GP1), &tmp);
	prlog(PR_TRACE, "SLW: PMGP1 read   0x%016llx\n", tmp);
	return true;
}

static bool slw_get_idle_state_history(struct proc_chip *chip, struct cpu_thread *c)
{
	uint32_t core = pir_to_core_id(c->pir);
	uint64_t tmp;
	int rc;

	/* Cleanup history */
	rc = xscom_read(chip->id,
		   XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_IDLE_STATE_HISTORY_PHYP),
		   &tmp);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_GET),
			"SLW: Failed to read PM_IDLE_STATE_HISTORY\n");
		return false;
	}

	prlog(PR_TRACE, "SLW: core %x:%x history: 0x%016llx (old1)\n",
	    chip->id, core, tmp);

	rc = xscom_read(chip->id,
		   XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_IDLE_STATE_HISTORY_PHYP),
		   &tmp);

	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_GET),
			"SLW: Failed to read PM_IDLE_STATE_HISTORY\n");
		return false;
	}

	prlog(PR_TRACE, "SLW: core %x:%x history: 0x%016llx (old2)\n",
	    chip->id, core, tmp);

	return true;
}

static bool idle_prepare_core(struct proc_chip *chip, struct cpu_thread *c)
{
	prlog(PR_TRACE, "FASTSLEEP: Prepare core %x:%x\n",
	    chip->id, pir_to_core_id(c->pir));

	if(!slw_general_init(chip, c))
		return false;
	if(!slw_set_overrides(chip, c))
		return false;
	if(!slw_set_idle_mode(chip, c))
		return false;
	if(!slw_get_idle_state_history(chip, c))
		return false;

	return true;

}

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

static struct cpu_idle_states nap_only_cpu_idle_states[] = {
	{ /* nap */
		.name = "nap",
		.latency_ns = 4000,
		.residency_ns = 100000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_NAP_ENABLED \
		       | 0*OPAL_PM_SLEEP_ENABLED \
		       | 0*OPAL_PM_WINKLE_ENABLED \
		       | 0*OPAL_USE_PMICR,
		.pm_ctrl_reg_val = 0,
		.pm_ctrl_reg_mask = 0 },
};

static struct cpu_idle_states power8_cpu_idle_states[] = {
	{ /* nap */
		.name = "nap",
		.latency_ns = 4000,
		.residency_ns = 100000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_NAP_ENABLED \
		       | 0*OPAL_USE_PMICR,
		.pm_ctrl_reg_val = 0,
		.pm_ctrl_reg_mask = 0 },
	{ /* fast sleep (with workaround) */
		.name = "fastsleep_",
		.latency_ns = 40000,
		.residency_ns = 300000000,
		.flags = 1*OPAL_PM_DEC_STOP \
		       | 1*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_SLEEP_ENABLED_ER1 \
		       | 0*OPAL_USE_PMICR, /* Not enabled until deep
						states are available */
		.pm_ctrl_reg_val = OPAL_PM_FASTSLEEP_PMICR,
		.pm_ctrl_reg_mask = OPAL_PM_SLEEP_PMICR_MASK },
	{ /* Winkle */
		.name = "winkle",
		.latency_ns = 10000000,
		.residency_ns = 1000000000, /* Educated guess (not measured).
					     * Winkle is not currently used by 
					     * linux cpuidle subsystem so we
					     * don't have real world user.
					     * However, this should be roughly
					     * accurate for when linux does
					     * use it. */
		.flags = 1*OPAL_PM_DEC_STOP \
		       | 1*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 1*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 1*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_WINKLE_ENABLED \
		       | 0*OPAL_USE_PMICR, /* Currently choosing deep vs
						fast via EX_PM_GP1 reg */
		.pm_ctrl_reg_val = 0,
		.pm_ctrl_reg_mask = 0 },
};

/*
 * cpu_idle_states for key idle states of POWER9 that we want to
 * exploit.
 * Note latency_ns and residency_ns are estimated values for now.
 */
static struct cpu_idle_states power9_cpu_idle_states[] = {
	{
		.name = "stop0_lite", /* Enter stop0 with no state loss */
		.latency_ns = 1000,
		.residency_ns = 10000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 0*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(0) \
				 | OPAL_PM_PSSCR_MTL(3) \
				 | OPAL_PM_PSSCR_TR(3),
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },
	{
		.name = "stop0",
		.latency_ns = 2000,
		.residency_ns = 20000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(0) \
				 | OPAL_PM_PSSCR_MTL(3) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },

	/* stop1_lite has been removed since it adds no additional benefit over stop0_lite */

	{
		.name = "stop1",
		.latency_ns = 5000,
		.residency_ns = 50000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(1) \
				 | OPAL_PM_PSSCR_MTL(3) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },
	/*
	 * stop2_lite has been removed since currently it adds minimal benefit over stop2.
	 * However, the benefit is eclipsed by the time required to ungate the clocks
	 */

	{
		.name = "stop2",
		.latency_ns = 10000,
		.residency_ns = 100000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(2) \
				 | OPAL_PM_PSSCR_MTL(3) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },
	{
		.name = "stop4",
		.latency_ns = 100000,
		.residency_ns = 10000000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 1*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 1*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_DEEP,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(4) \
				 | OPAL_PM_PSSCR_MTL(7) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },
	{
		.name = "stop5",
		.latency_ns = 200000,
		.residency_ns = 20000000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 1*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 1*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_DEEP,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(5) \
				 | OPAL_PM_PSSCR_MTL(7) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },

	{
		.name = "stop8",
		.latency_ns = 2000000,
		.residency_ns = 20000000,
		.flags = 1*OPAL_PM_DEC_STOP \
		       | 1*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 1*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 1*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_DEEP,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(8) \
				 | OPAL_PM_PSSCR_MTL(11) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },

	{
		.name = "stop11",
		.latency_ns = 10000000,
		.residency_ns = 100000000,
		.flags = 1*OPAL_PM_DEC_STOP \
		       | 1*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 1*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 1*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_DEEP,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(11) \
				 | OPAL_PM_PSSCR_MTL(11) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },

};

/*
 * Prior to Mambo.7.8.21, mambo did set the MSR correctly for lite stop
 * states, so disable them for now.
 */
static struct cpu_idle_states power9_mambo_cpu_idle_states[] = {
	{
		.name = "stop0",
		.latency_ns = 2000,
		.residency_ns = 20000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(0) \
				 | OPAL_PM_PSSCR_MTL(3) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },
	{
		.name = "stop1",
		.latency_ns = 5000,
		.residency_ns = 50000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(1) \
				 | OPAL_PM_PSSCR_MTL(3) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },
	{
		.name = "stop2",
		.latency_ns = 10000,
		.residency_ns = 100000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(2) \
				 | OPAL_PM_PSSCR_MTL(3) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },
	{
		.name = "stop4",
		.latency_ns = 100000,
		.residency_ns = 1000000,
		.flags = 1*OPAL_PM_DEC_STOP \
		       | 1*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 1*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 1*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_DEEP,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(4) \
				 | OPAL_PM_PSSCR_MTL(7) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },

	{
		.name = "stop8",
		.latency_ns = 2000000,
		.residency_ns = 20000000,
		.flags = 1*OPAL_PM_DEC_STOP \
		       | 1*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 1*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 1*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_DEEP,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(8) \
				 | OPAL_PM_PSSCR_MTL(11) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },

	{
		.name = "stop11",
		.latency_ns = 10000000,
		.residency_ns = 100000000,
		.flags = 1*OPAL_PM_DEC_STOP \
		       | 1*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 1*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 1*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_DEEP,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(11) \
				 | OPAL_PM_PSSCR_MTL(11) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },

};

/*
 * cpu_idle_states for fused core configuration
 * These will be a subset of power9 idle states.
 */
static struct cpu_idle_states power9_fusedcore_cpu_idle_states[] = {
	{
		.name = "stop0_lite", /* Enter stop0 with no state loss */
		.latency_ns = 1000,
		.residency_ns = 10000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 0*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(0) \
				 | OPAL_PM_PSSCR_MTL(3) \
				 | OPAL_PM_PSSCR_TR(3),
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },
	{
		.name = "stop0",
		.latency_ns = 2000,
		.residency_ns = 20000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(0) \
				 | OPAL_PM_PSSCR_MTL(3) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },

	/* stop1_lite has been removed since it adds no additional benefit over stop0_lite */

	{
		.name = "stop1",
		.latency_ns = 5000,
		.residency_ns = 50000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(1) \
				 | OPAL_PM_PSSCR_MTL(3) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },
	/*
	 * stop2_lite has been removed since currently it adds minimal benefit over stop2.
	 * However, the benefit is eclipsed by the time required to ungate the clocks
	 */

	{
		.name = "stop2",
		.latency_ns = 10000,
		.residency_ns = 100000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(2) \
				 | OPAL_PM_PSSCR_MTL(3) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },
};

/*
 * Note latency_ns and residency_ns are estimated values for now.
 */
static struct cpu_idle_states power10_cpu_idle_states[] = {
	{
		.name = "stop0_lite", /* Enter stop0 with no state loss */
		.latency_ns = 1000,
		.residency_ns = 10000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 0*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(0) \
				 | OPAL_PM_PSSCR_MTL(0) \
				 | OPAL_PM_PSSCR_TR(3),
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },
	{
		.name = "stop0",
		.latency_ns = 10000,
		.residency_ns = 100000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(0) \
				 | OPAL_PM_PSSCR_MTL(0) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },
	{
		.name = "stop2",
		.latency_ns = 20000,
		.residency_ns = 200000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(2) \
				 | OPAL_PM_PSSCR_MTL(2) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },
	{
		.name = "stop3",
		.latency_ns = 45000,
		.residency_ns = 450000,
		.flags = 0*OPAL_PM_DEC_STOP \
		       | 0*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 0*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 0*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_FAST,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(3) \
				 | OPAL_PM_PSSCR_MTL(3) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },
#if 0
	{
		.name = "stop11",
		.latency_ns = 10000000,
		.residency_ns = 100000000,
		.flags = 1*OPAL_PM_DEC_STOP \
		       | 1*OPAL_PM_TIMEBASE_STOP  \
		       | 1*OPAL_PM_LOSE_USER_CONTEXT \
		       | 1*OPAL_PM_LOSE_HYP_CONTEXT \
		       | 1*OPAL_PM_LOSE_FULL_CONTEXT \
		       | 1*OPAL_PM_STOP_INST_DEEP,
		.pm_ctrl_reg_val = OPAL_PM_PSSCR_RL(11) \
				 | OPAL_PM_PSSCR_MTL(11) \
				 | OPAL_PM_PSSCR_TR(3) \
				 | OPAL_PM_PSSCR_ESL \
				 | OPAL_PM_PSSCR_EC,
		.pm_ctrl_reg_mask = OPAL_PM_PSSCR_MASK },
#endif
};

static void slw_late_init_p9(struct proc_chip *chip)
{
	struct cpu_thread *c;
	int rc;

	prlog(PR_INFO, "SLW: Configuring self-restore for HRMOR\n");
	for_each_available_cpu(c) {
		if (c->chip_id != chip->id)
			continue;
		/*
		 * Clear HRMOR. Need to update only for thread
		 * 0 of each core. Doing it anyway for all threads
		 */
		rc =  p9_stop_save_cpureg((void *)chip->homer_base,
						P9_STOP_SPR_HRMOR, 0,
						c->pir);
		if (rc) {
			log_simple_error(&e_info(OPAL_RC_SLW_REG),
			"SLW: Failed to set HRMOR for CPU %x,RC=0x%x\n",
			c->pir, rc);
			prlog(PR_ERR, "Disabling deep stop states\n");
		}
	}
}

static void slw_late_init_p10(struct proc_chip *chip)
{
	struct cpu_thread *c;
	int rc;

	prlog(PR_INFO, "SLW: Configuring self-restore for HRMOR\n");
	for_each_available_cpu(c) {
		if (c->chip_id != chip->id)
			continue;
		/*
		 * Clear HRMOR. Need to update only for thread
		 * 0 of each core. Doing it anyway for all threads
		 */
		rc =  proc_stop_save_cpureg((void *)chip->homer_base,
						PROC_STOP_SPR_HRMOR, 0,
						c->pir);
		if (rc) {
			log_simple_error(&e_info(OPAL_RC_SLW_REG),
			"SLW: Failed to set HRMOR for CPU %x,RC=0x%x\n",
			c->pir, rc);
			prlog(PR_ERR, "Disabling deep stop states\n");
		}
	}
}

/* Add device tree properties to describe idle states */
void add_cpu_idle_state_properties(void)
{
	struct dt_node *power_mgt;
	struct cpu_idle_states *states;
	struct proc_chip *chip;
	int nr_states;

	bool can_sleep = true;
	bool has_stop_inst = false;
	u8 i;

	fdt64_t *pm_ctrl_reg_val_buf;
	fdt64_t *pm_ctrl_reg_mask_buf;
	u32 supported_states_mask;
	u32 opal_disabled_states_mask = ~0xFC000000; /* all but stop11 */
	const char* nvram_disable_str;
	u32 nvram_disabled_states_mask = 0x00;
	u32 stop_levels;

	/* Variables to track buffer length */
	u8 name_buf_len;
	u8 num_supported_idle_states;

	/* Buffers to hold idle state properties */
	char *name_buf, *alloced_name_buf;
	fdt32_t *latency_ns_buf;
	fdt32_t *residency_ns_buf;
	fdt32_t *flags_buf;

	prlog(PR_DEBUG, "CPU idle state device tree init\n");

	/* Create /ibm,opal/power-mgt if it doesn't exist already */
	power_mgt = dt_new_check(opal_node, "power-mgt");
	if (!power_mgt) {
		/**
		 * @fwts-label CreateDTPowerMgtNodeFail
		 * @fwts-advice OPAL failed to add the power-mgt device tree
		 * node. This could mean that firmware ran out of memory,
		 * or there's a bug somewhere.
		 */
		prlog(PR_ERR, "creating dt node /ibm,opal/power-mgt failed\n");
		return;
	}

	/*
	 * Chose the right state table for the chip
	 *
	 * XXX We use the first chip version, we should probably look
	 * for the smaller of all chips instead..
	 */
	chip = next_chip(NULL);
	assert(chip);
	if (proc_gen >= proc_gen_p9) {
		if (chip->type == PROC_CHIP_P9_NIMBUS ||
		    chip->type == PROC_CHIP_P9_CUMULUS ||
		    chip->type == PROC_CHIP_P9P) {
			if (proc_chip_quirks & QUIRK_MAMBO_CALLOUTS) {
				states = power9_mambo_cpu_idle_states;
				nr_states = ARRAY_SIZE(power9_mambo_cpu_idle_states);
			} else if (this_cpu()->is_fused_core) {
			  states = power9_fusedcore_cpu_idle_states;
			  nr_states = ARRAY_SIZE(power9_fusedcore_cpu_idle_states);
			} else {
				states = power9_cpu_idle_states;
				nr_states = ARRAY_SIZE(power9_cpu_idle_states);
			}
		} else if (chip->type == PROC_CHIP_P10) {
			states = power10_cpu_idle_states;
			nr_states = ARRAY_SIZE(power10_cpu_idle_states);
		} else {
			prlog(PR_ERR, "determining chip type\n");
			return;
		}

		has_stop_inst = true;
		stop_levels = dt_prop_get_u32_def(power_mgt,
			"ibm,enabled-stop-levels", 0);
		if (!stop_levels) {
			prerror("SLW: No stop levels available. Power saving is disabled!\n");
			has_deep_states = false;
		} else {
		/* Iterate to see if we have deep states enabled */
			for (i = 0; i < nr_states; i++) {
				u32 level = 31 - (states[i].pm_ctrl_reg_val &
					 OPAL_PM_PSSCR_RL_MASK);

				if ((stop_levels & (1ul << level)) &&
					(states[i].flags & OPAL_PM_STOP_INST_DEEP))
					has_deep_states = true;
				}
			}
			if ((wakeup_engine_state == WAKEUP_ENGINE_PRESENT) && has_deep_states) {
				if (chip->type == PROC_CHIP_P9_NIMBUS ||
				    chip->type == PROC_CHIP_P9_CUMULUS) {
					slw_late_init_p9(chip);
					xive_late_init();
					nx_p9_rng_late_init();
				} else if (chip->type == PROC_CHIP_P10) {
					slw_late_init_p10(chip);
					xive2_late_init();
				}
			}
			if (wakeup_engine_state != WAKEUP_ENGINE_PRESENT)
				has_deep_states = false;
	} else if (chip->type == PROC_CHIP_P8_MURANO ||
	    chip->type == PROC_CHIP_P8_VENICE ||
	    chip->type == PROC_CHIP_P8_NAPLES) {
		const struct dt_property *p;

		p = dt_find_property(dt_root, "ibm,enabled-idle-states");
		if (p)
			prlog(PR_NOTICE,
			      "SLW: HB-provided idle states property found\n");
		states = power8_cpu_idle_states;
		nr_states = ARRAY_SIZE(power8_cpu_idle_states);

		/* Check if hostboot say we can sleep */
		if (!p || !dt_prop_find_string(p, "fast-sleep")) {
			prlog(PR_WARNING, "SLW: Sleep not enabled by HB"
			      " on this platform\n");
			can_sleep = false;
		}

		/* Clip to NAP only on Murano and Venice DD1.x */
		if ((chip->type == PROC_CHIP_P8_MURANO ||
		     chip->type == PROC_CHIP_P8_VENICE) &&
		    chip->ec_level < 0x20) {
			prlog(PR_NOTICE, "SLW: Sleep not enabled on P8 DD1.x\n");
			can_sleep = false;
		}

	} else {
		states = nap_only_cpu_idle_states;
		nr_states = ARRAY_SIZE(nap_only_cpu_idle_states);
	}


	/*
	 * Currently we can't append strings and cells to dt properties.
	 * So create buffers to which you can append values, then create
	 * dt properties with this buffer content.
	 */

	/* Allocate memory to idle state property buffers. */
	alloced_name_buf= malloc(nr_states * sizeof(char) * MAX_NAME_LEN);
	name_buf = alloced_name_buf;
	latency_ns_buf	= malloc(nr_states * sizeof(u32));
	residency_ns_buf= malloc(nr_states * sizeof(u32));
	flags_buf	= malloc(nr_states * sizeof(u32));
	pm_ctrl_reg_val_buf	= malloc(nr_states * sizeof(u64));
	pm_ctrl_reg_mask_buf	= malloc(nr_states * sizeof(u64));

	name_buf_len = 0;
	num_supported_idle_states = 0;

	/*
	 * Create a mask with the flags of all supported idle states
	 * set. Use this to only add supported idle states to the
	 * device-tree
	 */
	if (has_stop_inst) {
		/* Power 9/10 / POWER ISA 3.0 and above */
		supported_states_mask = OPAL_PM_STOP_INST_FAST;
		if (wakeup_engine_state == WAKEUP_ENGINE_PRESENT)
			supported_states_mask |= OPAL_PM_STOP_INST_DEEP;
	} else {
		/* Power 7 and Power 8 */
		supported_states_mask = OPAL_PM_NAP_ENABLED;
		if (can_sleep)
			supported_states_mask |= OPAL_PM_SLEEP_ENABLED |
						OPAL_PM_SLEEP_ENABLED_ER1;
		if (wakeup_engine_state == WAKEUP_ENGINE_PRESENT)
			supported_states_mask |= OPAL_PM_WINKLE_ENABLED;
	}
	nvram_disable_str = nvram_query_dangerous("opal-stop-state-disable-mask");
	if (nvram_disable_str)
		nvram_disabled_states_mask = strtol(nvram_disable_str, NULL, 0);
	prlog(PR_DEBUG, "NVRAM stop disable mask: %x\n", nvram_disabled_states_mask);
	for (i = 0; i < nr_states; i++) {
		/* For each state, check if it is one of the supported states. */
		if (!(states[i].flags & supported_states_mask))
			continue;

		/* We can only use the stop levels that HB has made available */
		if (has_stop_inst) {
			u32 level = 31 - (states[i].pm_ctrl_reg_val &
					 OPAL_PM_PSSCR_RL_MASK);

			if (!(stop_levels & (1ul << level)))
				continue;

			if ((opal_disabled_states_mask |
			     nvram_disabled_states_mask) &
			    (1ul << level)) {
				if (nvram_disable_str &&
				    !(nvram_disabled_states_mask & (1ul << level))) {
					prlog(PR_NOTICE, "SLW: Enabling: %s "
					      "(disabled in OPAL, forced by "
					      "NVRAM)\n",states[i].name);
				} else {
					prlog(PR_NOTICE, "SLW: Disabling: %s in OPAL\n",
					      states[i].name);
					continue;
				}
			}
		}

		prlog(PR_INFO, "SLW: Enabling: %s\n", states[i].name);

		/*
		 * If a state is supported add each of its property
		 * to its corresponding property buffer.
		 */
		strncpy(name_buf, states[i].name, MAX_NAME_LEN);
		name_buf = name_buf + strlen(states[i].name) + 1;

		*latency_ns_buf = cpu_to_fdt32(states[i].latency_ns);
		latency_ns_buf++;

		*residency_ns_buf = cpu_to_fdt32(states[i].residency_ns);
		residency_ns_buf++;

		*flags_buf = cpu_to_fdt32(states[i].flags);
		flags_buf++;

		*pm_ctrl_reg_val_buf = cpu_to_fdt64(states[i].pm_ctrl_reg_val);
		pm_ctrl_reg_val_buf++;

		*pm_ctrl_reg_mask_buf = cpu_to_fdt64(states[i].pm_ctrl_reg_mask);
		pm_ctrl_reg_mask_buf++;

		/* Increment buffer length trackers */
		name_buf_len += strlen(states[i].name) + 1;
		num_supported_idle_states++;

	}

	/* Point buffer pointers back to beginning of the buffer */
	name_buf -= name_buf_len;
	latency_ns_buf -= num_supported_idle_states;
	residency_ns_buf -= num_supported_idle_states;
	flags_buf -= num_supported_idle_states;
	pm_ctrl_reg_val_buf -= num_supported_idle_states;
	pm_ctrl_reg_mask_buf -= num_supported_idle_states;
	/* Create dt properties with the buffer content */
	dt_add_property(power_mgt, "ibm,cpu-idle-state-names", name_buf,
			name_buf_len* sizeof(char));
	dt_add_property(power_mgt, "ibm,cpu-idle-state-latencies-ns",
			latency_ns_buf, num_supported_idle_states * sizeof(u32));
	dt_add_property(power_mgt, "ibm,cpu-idle-state-residency-ns",
			residency_ns_buf, num_supported_idle_states * sizeof(u32));
	dt_add_property(power_mgt, "ibm,cpu-idle-state-flags", flags_buf,
			num_supported_idle_states * sizeof(u32));

	if (has_stop_inst) {
		dt_add_property(power_mgt, "ibm,cpu-idle-state-psscr",
				pm_ctrl_reg_val_buf,
				num_supported_idle_states * sizeof(u64));
		dt_add_property(power_mgt, "ibm,cpu-idle-state-psscr-mask",
				pm_ctrl_reg_mask_buf,
				num_supported_idle_states * sizeof(u64));
	} else {
		dt_add_property(power_mgt, "ibm,cpu-idle-state-pmicr",
				pm_ctrl_reg_val_buf,
				num_supported_idle_states * sizeof(u64));
		dt_add_property(power_mgt, "ibm,cpu-idle-state-pmicr-mask",
				pm_ctrl_reg_mask_buf,
				num_supported_idle_states * sizeof(u64));
	}
	assert(alloced_name_buf == name_buf);
	free(alloced_name_buf);
	free(latency_ns_buf);
	free(residency_ns_buf);
	free(flags_buf);
	free(pm_ctrl_reg_val_buf);
	free(pm_ctrl_reg_mask_buf);
}

static void slw_patch_regs(struct proc_chip *chip)
{
	struct cpu_thread *c;
	void *image = (void *)chip->slw_base;
	int rc;

	for_each_available_cpu(c) {
		if (c->chip_id != chip->id)
			continue;
	
		/* Clear HRMOR */
		rc =  p8_pore_gen_cpureg_fixed(image, P8_SLW_MODEBUILD_SRAM,
					       P8_SPR_HRMOR, 0,
					       cpu_get_core_index(c),
					       cpu_get_thread_index(c));
		if (rc) {
			log_simple_error(&e_info(OPAL_RC_SLW_REG),
				"SLW: Failed to set HRMOR for CPU %x\n",
				c->pir);
		}

		/* XXX Add HIDs etc... */
	}
}

static void slw_init_chip_p9(struct proc_chip *chip)
{
	struct cpu_thread *c;

	prlog(PR_DEBUG, "SLW: Init chip 0x%x\n", chip->id);

	/* At power ON setup inits for power-mgt */
	for_each_available_core_in_chip(c, chip->id)
		slw_set_overrides_p9(chip, c);


}

static void slw_init_chip_p10(struct proc_chip *chip)
{
	struct cpu_thread *c;

	prlog(PR_DEBUG, "SLW: Init chip 0x%x\n", chip->id);

	/* At power ON setup inits for power-mgt */
	for_each_available_core_in_chip(c, chip->id)
		slw_set_overrides_p10(chip, c);


}


static bool  slw_image_check_p9(struct proc_chip *chip)
{

	if (!chip->homer_base) {
		log_simple_error(&e_info(OPAL_RC_SLW_REG),
				 "SLW: HOMER base not set %x\n",
				 chip->id);
		return false;
	} else
		return true;


}

static bool  slw_image_check_p8(struct proc_chip *chip)
{
	int64_t rc;

	prlog(PR_DEBUG, "SLW: slw_check chip 0x%x\n", chip->id);
	if (!chip->slw_base) {
		prerror("SLW: No image found !\n");
		return false;
	}

	/* Check actual image size */
	rc = sbe_xip_get_scalar((void *)chip->slw_base, "image_size",
				&chip->slw_image_size);
	if (rc != 0) {
		log_simple_error(&e_info(OPAL_RC_SLW_INIT),
			"SLW: Error %lld reading SLW image size\n", rc);
		/* XXX Panic ? */
		chip->slw_base = 0;
		chip->slw_bar_size = 0;
		chip->slw_image_size = 0;
		return false;
	}
	prlog(PR_DEBUG, "SLW: Image size from image: 0x%llx\n",
	      chip->slw_image_size);

	if (chip->slw_image_size > chip->slw_bar_size) {
		log_simple_error(&e_info(OPAL_RC_SLW_INIT),
			"SLW: Built-in image size larger than BAR size !\n");
		/* XXX Panic ? */
		return false;
	}
	return true;

}

static void slw_late_init_p8(struct proc_chip *chip)
{

	prlog(PR_DEBUG, "SLW: late Init chip 0x%x\n", chip->id);

	/* Patch SLW image */
        slw_patch_regs(chip);

}
static void slw_init_chip_p8(struct proc_chip *chip)
{
	struct cpu_thread *c;

	prlog(PR_DEBUG, "SLW: Init chip 0x%x\n", chip->id);
	/* At power ON setup inits for fast-sleep */
	for_each_available_core_in_chip(c, chip->id) {
		idle_prepare_core(chip, c);
	}
}

/* Workarounds while entering fast-sleep */

static void fast_sleep_enter(void)
{
	uint32_t core = pir_to_core_id(this_cpu()->pir);
	uint32_t chip_id = this_cpu()->chip_id;
	struct cpu_thread *primary_thread;
	uint64_t tmp;
	int rc;

	primary_thread = this_cpu()->primary;

	rc = xscom_read(chip_id, XSCOM_ADDR_P8_EX(core, L2_FIR_ACTION1),
			&tmp);
	if (rc) {
		prlog(PR_WARNING, "fast_sleep_enter XSCOM failed(1):"
		      " rc=%d chip_id=%d core=%d\n",
		      rc, chip_id, core);
		return;
	}

	primary_thread->save_l2_fir_action1 = tmp;
	primary_thread->in_fast_sleep = true;

	tmp = tmp & ~0x0200000000000000ULL;
	rc = xscom_write(chip_id, XSCOM_ADDR_P8_EX(core, L2_FIR_ACTION1),
			 tmp);
	if (rc) {
		prlog(PR_WARNING, "fast_sleep_enter XSCOM failed(2):"
		      " rc=%d chip_id=%d core=%d\n",
		      rc, chip_id, core);
		return;
	}
	rc = xscom_read(chip_id, XSCOM_ADDR_P8_EX(core, L2_FIR_ACTION1),
			&tmp);
	if (rc) {
		prlog(PR_WARNING, "fast_sleep_enter XSCOM failed(3):"
		      " rc=%d chip_id=%d core=%d\n",
		      rc, chip_id, core);
		return;
	}

}

/* Workarounds while exiting fast-sleep */

void fast_sleep_exit(void)
{
	uint32_t core = pir_to_core_id(this_cpu()->pir);
	uint32_t chip_id = this_cpu()->chip_id;
	struct cpu_thread *primary_thread;
	int rc;

	primary_thread = this_cpu()->primary;
	primary_thread->in_fast_sleep = false;

	rc = xscom_write(chip_id, XSCOM_ADDR_P8_EX(core, L2_FIR_ACTION1),
			primary_thread->save_l2_fir_action1);
	if (rc) {
		prlog(PR_WARNING, "fast_sleep_exit XSCOM failed:"
		      " rc=%d chip_id=%d core=%d\n",
		      rc, chip_id, core);
		return;
	}
}

/*
 * Setup and cleanup method for fast-sleep workarounds
 * state = 1 fast-sleep
 * enter = 1 Enter state
 * exit  = 0 Exit state
 */

static int64_t opal_config_cpu_idle_state(uint64_t state, uint64_t enter)
{
	/* Only fast-sleep for now */
	if (state != 1)
		return OPAL_PARAMETER;	

	switch(enter) {
	case 1:
		fast_sleep_enter();
		break;
	case 0:
		fast_sleep_exit();
		break;
	default:
		return OPAL_PARAMETER;
	}

	return OPAL_SUCCESS;
}

opal_call(OPAL_CONFIG_CPU_IDLE_STATE, opal_config_cpu_idle_state, 2);

int64_t opal_slw_set_reg(uint64_t cpu_pir, uint64_t sprn, uint64_t val)
{

	struct cpu_thread *c = find_cpu_by_pir(cpu_pir);
	struct proc_chip *chip;
	int rc;

	if (!c) {
		prerror("SLW: Unknown thread with pir %x\n", (u32) cpu_pir);
		return OPAL_PARAMETER;
	}

	chip = get_chip(c->chip_id);
	if (!chip) {
		prerror("SLW: Unknown chip for thread with pir %x\n",
			(u32) cpu_pir);
		return OPAL_PARAMETER;
	}

	if (proc_gen >= proc_gen_p9) {
		if (!has_deep_states) {
			prlog(PR_INFO, "SLW: Deep states not enabled\n");
			return OPAL_SUCCESS;
		}

		if (wakeup_engine_state != WAKEUP_ENGINE_PRESENT) {
			log_simple_error(&e_info(OPAL_RC_SLW_REG),
					 "SLW: wakeup_engine in bad state=%d chip=%x\n",
					 wakeup_engine_state,chip->id);
			return OPAL_INTERNAL_ERROR;
		}
		if (proc_gen == proc_gen_p9) {
			rc = p9_stop_save_cpureg((void *)chip->homer_base,
					 sprn, val, cpu_pir);
		} else {
			rc = proc_stop_save_cpureg((void *)chip->homer_base,
					 sprn, val, cpu_pir);
		}

	} else if (proc_gen == proc_gen_p8) {
		int spr_is_supported = 0;
		void *image;
		int i;

		/* Check of the SPR is supported by libpore */
		for (i = 0; i < SLW_SPR_REGS_SIZE ; i++)  {
			if (sprn == SLW_SPR_REGS[i].value)  {
				spr_is_supported = 1;
				break;
			}
		}
		if (!spr_is_supported) {
			log_simple_error(&e_info(OPAL_RC_SLW_REG),
			"SLW: Trying to set unsupported spr for CPU %x\n",
				c->pir);
			return OPAL_UNSUPPORTED;
		}
		image = (void *)chip->slw_base;
		rc = p8_pore_gen_cpureg_fixed(image, P8_SLW_MODEBUILD_SRAM,
					      sprn, val,
					      cpu_get_core_index(c),
					      cpu_get_thread_index(c));
	} else {
		log_simple_error(&e_info(OPAL_RC_SLW_REG),
		"SLW: proc_gen not supported\n");
		return OPAL_UNSUPPORTED;

	}

	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SLW_REG),
			"SLW: Failed to set spr %llx for CPU %x, RC=0x%x\n",
			sprn, c->pir, rc);
		return OPAL_INTERNAL_ERROR;
	}
	prlog(PR_DEBUG, "SLW: restore spr:0x%llx on c:0x%x with 0x%llx\n",
	      sprn, c->pir, val);
	return OPAL_SUCCESS;

}

opal_call(OPAL_SLW_SET_REG, opal_slw_set_reg, 3);

void slw_init(void)
{
	struct proc_chip *chip;

	wakeup_engine_state = WAKEUP_ENGINE_NOT_PRESENT;
	if (chip_quirk(QUIRK_AWAN))
		return;
	if (chip_quirk(QUIRK_MAMBO_CALLOUTS)) {
		add_cpu_idle_state_properties();
		return;
	}

	if (proc_gen == proc_gen_p8) {
		for_each_chip(chip) {
			slw_init_chip_p8(chip);
			if(slw_image_check_p8(chip))
				wakeup_engine_state = WAKEUP_ENGINE_PRESENT;
			if (wakeup_engine_state == WAKEUP_ENGINE_PRESENT)
				slw_late_init_p8(chip);
		}
		p8_sbe_init_timer();
	} else if (proc_gen == proc_gen_p9) {
		for_each_chip(chip) {
			slw_init_chip_p9(chip);
			if(slw_image_check_p9(chip))
				wakeup_engine_state = WAKEUP_ENGINE_PRESENT;
			if (wakeup_engine_state == WAKEUP_ENGINE_PRESENT)
				slw_late_init_p9(chip);
		}
	} else if (proc_gen == proc_gen_p10) {
		for_each_chip(chip) {
			slw_init_chip_p10(chip);
			if(slw_image_check_p9(chip))
				wakeup_engine_state = WAKEUP_ENGINE_PRESENT;
			if (wakeup_engine_state == WAKEUP_ENGINE_PRESENT) {
				slw_late_init_p10(chip);
			}
		}
	}
	add_cpu_idle_state_properties();
}
