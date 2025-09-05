// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#include <skiboot.h>
#include <slw.h>
#include <xscom.h>
#include <xscom-p8-regs.h>
#include <cpu.h>
#include <chip.h>
#include <interrupts.h>
#include <timebase.h>
#include <errorlog.h>
#include <libfdt/libfdt.h>
#include <opal-api.h>
#include <sbe-p8.h>

#include <p8_pore_table_gen_api.H>
#include <sbe_xip_image.h>

/*
 * It would be nice to be able to define non-static log entry types and share
 * these with slw.c
 */
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

void find_cpu_idle_state_properties_p8(struct cpu_idle_states **states,
				       int *nr_states, bool *can_sleep)
{
	struct proc_chip *chip;

	chip = next_chip(NULL);
	assert(chip);

	*can_sleep = true;

	if (chip->type == PROC_CHIP_P8_MURANO ||
	    chip->type == PROC_CHIP_P8_VENICE ||
	    chip->type == PROC_CHIP_P8_NAPLES) {
		const struct dt_property *p;

		p = dt_find_property(dt_root, "ibm,enabled-idle-states");
		if (p)
			prlog(PR_NOTICE,
			      "SLW: HB-provided idle states property found\n");
		*states = power8_cpu_idle_states;
		*nr_states = ARRAY_SIZE(power8_cpu_idle_states);

		/* Check if hostboot say we can sleep */
		if (!p || !dt_prop_find_string(p, "fast-sleep")) {
			prlog(PR_WARNING, "SLW: Sleep not enabled by HB"
			      " on this platform\n");
			*can_sleep = false;
		}

		/* Clip to NAP only on Murano and Venice DD1.x */
		if ((chip->type == PROC_CHIP_P8_MURANO ||
		     chip->type == PROC_CHIP_P8_VENICE) &&
		    chip->ec_level < 0x20) {
			prlog(PR_NOTICE, "SLW: Sleep not enabled on P8 DD1.x\n");
			*can_sleep = false;
		}

	} else {
		*states = nap_only_cpu_idle_states;
		*nr_states = ARRAY_SIZE(nap_only_cpu_idle_states);
	}
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

int64_t opal_slw_set_reg_p8(struct cpu_thread *c, struct proc_chip *chip,
			    uint64_t sprn, uint64_t val)
{
	int spr_is_supported = 0;
	void *image;
	int i;
	int rc;

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
	return rc;
}

void slw_p8_init(void)
{
	struct proc_chip *chip;

	for_each_chip(chip) {
		slw_init_chip_p8(chip);
		if (slw_image_check_p8(chip))
			wakeup_engine_state = WAKEUP_ENGINE_PRESENT;
		if (wakeup_engine_state == WAKEUP_ENGINE_PRESENT)
			slw_late_init_p8(chip);
	}
	p8_sbe_init_timer();
}
