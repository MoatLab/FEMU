// SPDX-License-Identifier: Apache-2.0
/*
 * Directly control CPU cores/threads. SRESET, special wakeup, etc
 *
 * Copyright 2017-2019 IBM Corp.
 */

#include <direct-controls.h>
#include <skiboot.h>
#include <opal.h>
#include <cpu.h>
#include <xscom.h>
#include <xscom-p8-regs.h>
#include <xscom-p9-regs.h>
#include <xscom-p10-regs.h>
#include <timebase.h>
#include <chip.h>


/**************** mambo direct controls ****************/

extern unsigned long callthru_tcl(const char *str, int len);

static void mambo_sreset_cpu(struct cpu_thread *cpu)
{
	uint32_t chip_id = pir_to_chip_id(cpu->pir);
	uint32_t core_id = pir_to_core_id(cpu->pir);
	uint32_t thread_id = pir_to_thread_id(cpu->pir);
	char tcl_cmd[50];

	snprintf(tcl_cmd, sizeof(tcl_cmd),
			"mysim cpu %i:%i:%i start_thread 0x100",
			chip_id, core_id, thread_id);
	callthru_tcl(tcl_cmd, strlen(tcl_cmd));
}

static void mambo_stop_cpu(struct cpu_thread *cpu)
{
	uint32_t chip_id = pir_to_chip_id(cpu->pir);
	uint32_t core_id = pir_to_core_id(cpu->pir);
	uint32_t thread_id = pir_to_thread_id(cpu->pir);
	char tcl_cmd[50];

	snprintf(tcl_cmd, sizeof(tcl_cmd),
			"mysim cpu %i:%i:%i stop_thread",
			chip_id, core_id, thread_id);
	callthru_tcl(tcl_cmd, strlen(tcl_cmd));
}

/**************** POWER8 direct controls ****************/

static int p8_core_set_special_wakeup(struct cpu_thread *cpu)
{
	uint64_t val, poll_target, stamp;
	uint32_t core_id;
	int rc;

	/*
	 * Note: HWP checks for checkstops, but I assume we don't need to
	 * as we wouldn't be running if one was present
	 */

	/* Grab core ID once */
	core_id = pir_to_core_id(cpu->pir);

	prlog(PR_DEBUG, "RESET Waking up core 0x%x\n", core_id);

	/*
	 * The original HWp reads the XSCOM first but ignores the result
	 * and error, let's do the same until I know for sure that is
	 * not necessary
	 */
	xscom_read(cpu->chip_id,
		   XSCOM_ADDR_P8_EX_SLAVE(core_id, EX_PM_SPECIAL_WAKEUP_PHYP),
		   &val);

	/* Then we write special wakeup */
	rc = xscom_write(cpu->chip_id,
			 XSCOM_ADDR_P8_EX_SLAVE(core_id,
						EX_PM_SPECIAL_WAKEUP_PHYP),
			 PPC_BIT(0));
	if (rc) {
		prerror("RESET: XSCOM error %d asserting special"
			" wakeup on 0x%x\n", rc, cpu->pir);
		return rc;
	}

	/*
	 * HWP uses the history for Perf register here, dunno why it uses
	 * that one instead of the pHyp one, maybe to avoid clobbering it...
	 *
	 * In any case, it does that to check for run/nap vs.sleep/winkle/other
	 * to decide whether to poll on checkstop or not. Since we don't deal
	 * with checkstop conditions here, we ignore that part.
	 */

	/*
	 * Now poll for completion of special wakeup. The HWP is nasty here,
	 * it will poll at 5ms intervals for up to 200ms. This is not quite
	 * acceptable for us at runtime, at least not until we have the
	 * ability to "context switch" HBRT. In practice, because we don't
	 * winkle, it will never take that long, so we increase the polling
	 * frequency to 1us per poll. However we do have to keep the same
	 * timeout.
	 *
	 * We don't use time_wait_ms() either for now as we don't want to
	 * poll the FSP here.
	 */
	stamp = mftb();
	poll_target = stamp + msecs_to_tb(200);
	val = 0;
	while (!(val & EX_PM_GP0_SPECIAL_WAKEUP_DONE)) {
		/* Wait 1 us */
		time_wait_us(1);

		/* Read PM state */
		rc = xscom_read(cpu->chip_id,
				XSCOM_ADDR_P8_EX_SLAVE(core_id, EX_PM_GP0),
				&val);
		if (rc) {
			prerror("RESET: XSCOM error %d reading PM state on"
				" 0x%x\n", rc, cpu->pir);
			return rc;
		}
		/* Check timeout */
		if (mftb() > poll_target)
			break;
	}

	/* Success ? */
	if (val & EX_PM_GP0_SPECIAL_WAKEUP_DONE) {
		uint64_t now = mftb();
		prlog(PR_TRACE, "RESET: Special wakeup complete after %ld us\n",
		      tb_to_usecs(now - stamp));
		return 0;
	}

	/*
	 * We timed out ...
	 *
	 * HWP has a complex workaround for HW255321 which affects
	 * Murano DD1 and Venice DD1. Ignore that for now
	 *
	 * Instead we just dump some XSCOMs for error logging
	 */
	prerror("RESET: Timeout on special wakeup of 0x%0x\n", cpu->pir);
	prerror("RESET:      PM0 = 0x%016llx\n", val);
	val = -1;
	xscom_read(cpu->chip_id,
		   XSCOM_ADDR_P8_EX_SLAVE(core_id, EX_PM_SPECIAL_WAKEUP_PHYP),
		   &val);
	prerror("RESET: SPC_WKUP = 0x%016llx\n", val);
	val = -1;
	xscom_read(cpu->chip_id,
		   XSCOM_ADDR_P8_EX_SLAVE(core_id,
					  EX_PM_IDLE_STATE_HISTORY_PHYP),
		   &val);
	prerror("RESET:  HISTORY = 0x%016llx\n", val);

	return OPAL_HARDWARE;
}

static int p8_core_clear_special_wakeup(struct cpu_thread *cpu)
{
	uint64_t val;
	uint32_t core_id;
	int rc;

	/*
	 * Note: HWP checks for checkstops, but I assume we don't need to
	 * as we wouldn't be running if one was present
	 */

	/* Grab core ID once */
	core_id = pir_to_core_id(cpu->pir);

	prlog(PR_DEBUG, "RESET: Releasing core 0x%x wakeup\n", core_id);

	/*
	 * The original HWp reads the XSCOM first but ignores the result
	 * and error, let's do the same until I know for sure that is
	 * not necessary
	 */
	xscom_read(cpu->chip_id,
		   XSCOM_ADDR_P8_EX_SLAVE(core_id, EX_PM_SPECIAL_WAKEUP_PHYP),
		   &val);

	/* Then we write special wakeup */
	rc = xscom_write(cpu->chip_id,
			 XSCOM_ADDR_P8_EX_SLAVE(core_id,
						EX_PM_SPECIAL_WAKEUP_PHYP), 0);
	if (rc) {
		prerror("RESET: XSCOM error %d deasserting"
			" special wakeup on 0x%x\n", rc, cpu->pir);
		return rc;
	}

	/*
	 * The original HWp reads the XSCOM again with the comment
	 * "This puts an inherent delay in the propagation of the reset
	 * transition"
	 */
	xscom_read(cpu->chip_id,
		   XSCOM_ADDR_P8_EX_SLAVE(core_id, EX_PM_SPECIAL_WAKEUP_PHYP),
		   &val);

	return 0;
}

static int p8_stop_thread(struct cpu_thread *cpu)
{
	uint32_t core_id = pir_to_core_id(cpu->pir);
	uint32_t chip_id = pir_to_chip_id(cpu->pir);
	uint32_t thread_id = pir_to_thread_id(cpu->pir);
	uint32_t xscom_addr;

	xscom_addr = XSCOM_ADDR_P8_EX(core_id,
				      P8_EX_TCTL_DIRECT_CONTROLS(thread_id));

	if (xscom_write(chip_id, xscom_addr, P8_DIRECT_CTL_STOP)) {
		prlog(PR_ERR, "Could not stop thread %u:%u:%u:"
				" Unable to write EX_TCTL_DIRECT_CONTROLS.\n",
				chip_id, core_id, thread_id);
		return OPAL_HARDWARE;
	}

	return OPAL_SUCCESS;
}

static int p8_sreset_thread(struct cpu_thread *cpu)
{
	uint32_t core_id = pir_to_core_id(cpu->pir);
	uint32_t chip_id = pir_to_chip_id(cpu->pir);
	uint32_t thread_id = pir_to_thread_id(cpu->pir);
	uint32_t xscom_addr;

	xscom_addr = XSCOM_ADDR_P8_EX(core_id,
				      P8_EX_TCTL_DIRECT_CONTROLS(thread_id));

	if (xscom_write(chip_id, xscom_addr, P8_DIRECT_CTL_PRENAP)) {
		prlog(PR_ERR, "Could not prenap thread %u:%u:%u:"
				" Unable to write EX_TCTL_DIRECT_CONTROLS.\n",
				chip_id, core_id, thread_id);
		return OPAL_HARDWARE;
	}
	if (xscom_write(chip_id, xscom_addr, P8_DIRECT_CTL_SRESET)) {
		prlog(PR_ERR, "Could not sreset thread %u:%u:%u:"
				" Unable to write EX_TCTL_DIRECT_CONTROLS.\n",
				chip_id, core_id, thread_id);
		return OPAL_HARDWARE;
	}

	return OPAL_SUCCESS;
}


/**************** POWER9 direct controls ****************/

/* Long running instructions may take time to complete. Timeout 100ms */
#define P9_QUIESCE_POLL_INTERVAL	100
#define P9_QUIESCE_TIMEOUT		100000

/* Waking may take up to 5ms for deepest sleep states. Set timeout to 100ms */
#define P9_SPWKUP_POLL_INTERVAL		100
#define P9_SPWKUP_TIMEOUT		100000

/*
 * This implements direct control facilities of processor cores and threads
 * using scom registers.
 */

static int p9_core_is_gated(struct cpu_thread *cpu)
{
	uint32_t chip_id = pir_to_chip_id(cpu->pir);
	uint32_t core_id = pir_to_core_id(cpu->pir);
	uint32_t sshhyp_addr;
	uint64_t val;

	sshhyp_addr = XSCOM_ADDR_P9_EC_SLAVE(core_id, P9_EC_PPM_SSHHYP);

	if (xscom_read(chip_id, sshhyp_addr, &val)) {
		prlog(PR_ERR, "Could not query core gated on %u:%u:"
				" Unable to read PPM_SSHHYP.\n",
				chip_id, core_id);
		return OPAL_HARDWARE;
	}

	return !!(val & P9_CORE_GATED);
}

static int p9_core_set_special_wakeup(struct cpu_thread *cpu)
{
	uint32_t chip_id = pir_to_chip_id(cpu->pir);
	uint32_t core_id = pir_to_core_id(cpu->pir);
	uint32_t swake_addr;
	uint32_t sshhyp_addr;
	uint64_t val;
	int i;

	swake_addr = XSCOM_ADDR_P9_EC_SLAVE(core_id, EC_PPM_SPECIAL_WKUP_HYP);
	sshhyp_addr = XSCOM_ADDR_P9_EC_SLAVE(core_id, P9_EC_PPM_SSHHYP);

	if (xscom_write(chip_id, swake_addr, P9_SPWKUP_SET)) {
		prlog(PR_ERR, "Could not set special wakeup on %u:%u:"
				" Unable to write PPM_SPECIAL_WKUP_HYP.\n",
				chip_id, core_id);
		goto out_fail;
	}

	for (i = 0; i < P9_SPWKUP_TIMEOUT / P9_SPWKUP_POLL_INTERVAL; i++) {
		if (xscom_read(chip_id, sshhyp_addr, &val)) {
			prlog(PR_ERR, "Could not set special wakeup on %u:%u:"
					" Unable to read PPM_SSHHYP.\n",
					chip_id, core_id);
			goto out_fail;
		}
		if (val & P9_SPECIAL_WKUP_DONE) {
			/*
			 * CORE_GATED will be unset on a successful special
			 * wakeup of the core which indicates that the core is
			 * out of stop state. If CORE_GATED is still set then
			 * raise error.
			 */
			if (p9_core_is_gated(cpu)) {
				/* Deassert spwu for this strange error */
				xscom_write(chip_id, swake_addr, 0);
				prlog(PR_ERR, "Failed special wakeup on %u:%u"
						" as CORE_GATED is set\n",
						chip_id, core_id);
				goto out_fail;
			} else {
				return 0;
			}
		}
		time_wait_us(P9_SPWKUP_POLL_INTERVAL);
	}

	prlog(PR_ERR, "Could not set special wakeup on %u:%u:"
			" timeout waiting for SPECIAL_WKUP_DONE.\n",
			chip_id, core_id);

out_fail:
	/*
	 * As per the special wakeup protocol we should not de-assert
	 * the special wakeup on the core until WAKEUP_DONE is set.
	 * So even on error do not de-assert.
	 */
	return OPAL_HARDWARE;
}

static int p9_core_clear_special_wakeup(struct cpu_thread *cpu)
{
	uint32_t chip_id = pir_to_chip_id(cpu->pir);
	uint32_t core_id = pir_to_core_id(cpu->pir);
	uint32_t swake_addr;

	swake_addr = XSCOM_ADDR_P9_EC_SLAVE(core_id, EC_PPM_SPECIAL_WKUP_HYP);

	/*
	 * De-assert special wakeup after a small delay.
	 * The delay may help avoid problems setting and clearing special
	 * wakeup back-to-back. This should be confirmed.
	 */
	time_wait_us(1);
	if (xscom_write(chip_id, swake_addr, 0)) {
		prlog(PR_ERR, "Could not clear special wakeup on %u:%u:"
				" Unable to write PPM_SPECIAL_WKUP_HYP.\n",
				chip_id, core_id);
		return OPAL_HARDWARE;
	}

	/*
	 * Don't wait for de-assert to complete as other components
	 * could have requested for special wkeup. Wait for 10ms to
	 * avoid back-to-back asserts
	 */
	time_wait_us(10000);
	return 0;
}

static int p9_thread_quiesced(struct cpu_thread *cpu)
{
	uint32_t chip_id = pir_to_chip_id(cpu->pir);
	uint32_t core_id = pir_to_core_id(cpu->pir);
	uint32_t thread_id = pir_to_thread_id(cpu->pir);
	uint32_t ras_addr;
	uint64_t ras_status;

	ras_addr = XSCOM_ADDR_P9_EC(core_id, P9_RAS_STATUS);
	if (xscom_read(chip_id, ras_addr, &ras_status)) {
		prlog(PR_ERR, "Could not check thread state on %u:%u:"
				" Unable to read RAS_STATUS.\n",
				chip_id, core_id);
		return OPAL_HARDWARE;
	}

	/*
	 * This returns true when the thread is quiesced and all
	 * instructions completed. For sreset this may not be necessary,
	 * but we may want to use instruction ramming or stepping
	 * direct controls where it is important.
	 */
	if ((ras_status & P9_THREAD_QUIESCED(thread_id))
			== P9_THREAD_QUIESCED(thread_id))
		return 1;

	return 0;
}

static int p9_cont_thread(struct cpu_thread *cpu)
{
	uint32_t chip_id = pir_to_chip_id(cpu->pir);
	uint32_t core_id = pir_to_core_id(cpu->pir);
	uint32_t thread_id = pir_to_thread_id(cpu->pir);
	uint32_t cts_addr;
	uint32_t ti_addr;
	uint32_t dctl_addr;
	uint64_t core_thread_state;
	uint64_t thread_info;
	bool active, stop;
	int rc;

	rc = p9_thread_quiesced(cpu);
	if (rc < 0)
		return rc;
	if (!rc) {
		prlog(PR_ERR, "Could not cont thread %u:%u:%u:"
				" Thread is not quiesced.\n",
				chip_id, core_id, thread_id);
		return OPAL_BUSY;
	}

	cts_addr = XSCOM_ADDR_P9_EC(core_id, P9_CORE_THREAD_STATE);
	ti_addr = XSCOM_ADDR_P9_EC(core_id, P9_THREAD_INFO);
	dctl_addr = XSCOM_ADDR_P9_EC(core_id, P9_EC_DIRECT_CONTROLS);

	if (xscom_read(chip_id, cts_addr, &core_thread_state)) {
		prlog(PR_ERR, "Could not resume thread %u:%u:%u:"
				" Unable to read CORE_THREAD_STATE.\n",
				chip_id, core_id, thread_id);
		return OPAL_HARDWARE;
	}
	if (core_thread_state & PPC_BIT(56 + thread_id))
		stop = true;
	else
		stop = false;

	if (xscom_read(chip_id, ti_addr, &thread_info)) {
		prlog(PR_ERR, "Could not resume thread %u:%u:%u:"
				" Unable to read THREAD_INFO.\n",
				chip_id, core_id, thread_id);
		return OPAL_HARDWARE;
	}
	if (thread_info & PPC_BIT(thread_id))
		active = true;
	else
		active = false;

	if (!active || stop) {
		if (xscom_write(chip_id, dctl_addr, P9_THREAD_CLEAR_MAINT(thread_id))) {
			prlog(PR_ERR, "Could not resume thread %u:%u:%u:"
				      " Unable to write EC_DIRECT_CONTROLS.\n",
				      chip_id, core_id, thread_id);
		}
	} else {
		if (xscom_write(chip_id, dctl_addr, P9_THREAD_CONT(thread_id))) {
			prlog(PR_ERR, "Could not resume thread %u:%u:%u:"
				      " Unable to write EC_DIRECT_CONTROLS.\n",
				      chip_id, core_id, thread_id);
		}
	}

	return 0;
}

static int p9_stop_thread(struct cpu_thread *cpu)
{
	uint32_t chip_id = pir_to_chip_id(cpu->pir);
	uint32_t core_id = pir_to_core_id(cpu->pir);
	uint32_t thread_id = pir_to_thread_id(cpu->pir);
	uint32_t dctl_addr;
	int rc;
	int i;

	dctl_addr = XSCOM_ADDR_P9_EC(core_id, P9_EC_DIRECT_CONTROLS);

	rc = p9_thread_quiesced(cpu);
	if (rc < 0)
		return rc;
	if (rc) {
		prlog(PR_ERR, "Could not stop thread %u:%u:%u:"
				" Thread is quiesced already.\n",
				chip_id, core_id, thread_id);
		return OPAL_BUSY;
	}

	if (xscom_write(chip_id, dctl_addr, P9_THREAD_STOP(thread_id))) {
		prlog(PR_ERR, "Could not stop thread %u:%u:%u:"
				" Unable to write EC_DIRECT_CONTROLS.\n",
				chip_id, core_id, thread_id);
		return OPAL_HARDWARE;
	}

	for (i = 0; i < P9_QUIESCE_TIMEOUT / P9_QUIESCE_POLL_INTERVAL; i++) {
		int rc = p9_thread_quiesced(cpu);
		if (rc < 0)
			break;
		if (rc)
			return 0;

		time_wait_us(P9_QUIESCE_POLL_INTERVAL);
	}

	prlog(PR_ERR, "Could not stop thread %u:%u:%u:"
			" Unable to quiesce thread.\n",
			chip_id, core_id, thread_id);

	return OPAL_HARDWARE;
}

static int p9_sreset_thread(struct cpu_thread *cpu)
{
	uint32_t chip_id = pir_to_chip_id(cpu->pir);
	uint32_t core_id = pir_to_core_id(cpu->pir);
	uint32_t thread_id = pir_to_thread_id(cpu->pir);
	uint32_t dctl_addr;

	dctl_addr = XSCOM_ADDR_P9_EC(core_id, P9_EC_DIRECT_CONTROLS);

	if (xscom_write(chip_id, dctl_addr, P9_THREAD_SRESET(thread_id))) {
		prlog(PR_ERR, "Could not sreset thread %u:%u:%u:"
				" Unable to write EC_DIRECT_CONTROLS.\n",
				chip_id, core_id, thread_id);
		return OPAL_HARDWARE;
	}

	return 0;
}

/**************** POWER10 direct controls ****************/

/* Long running instructions may take time to complete. Timeout 100ms */
#define P10_QUIESCE_POLL_INTERVAL	100
#define P10_QUIESCE_TIMEOUT		100000

/* Waking may take up to 5ms for deepest sleep states. Set timeout to 100ms */
#define P10_SPWU_POLL_INTERVAL		100
#define P10_SPWU_TIMEOUT		100000

/*
 * This implements direct control facilities of processor cores and threads
 * using scom registers.
 */
static int p10_core_is_gated(struct cpu_thread *cpu)
{
	uint32_t chip_id = pir_to_chip_id(cpu->pir);
	uint32_t core_id = pir_to_core_id(cpu->pir);
	uint32_t ssh_addr;
	uint64_t val;

	ssh_addr = XSCOM_ADDR_P10_QME_CORE(core_id, P10_QME_SSH_HYP);

	if (xscom_read(chip_id, ssh_addr, &val)) {
		prlog(PR_ERR, "Could not query core gated on %u:%u:"
				" Unable to read QME_SSH_HYP.\n",
				chip_id, core_id);
		return OPAL_HARDWARE;
	}

	return !!(val & P10_SSH_CORE_GATED);
}


static int p10_core_set_special_wakeup(struct cpu_thread *cpu)
{
	uint32_t chip_id = pir_to_chip_id(cpu->pir);
	uint32_t core_id = pir_to_core_id(cpu->pir);
	uint32_t spwu_addr, ssh_addr;
	uint64_t val;
	int i;

	/* P10 could use SPWU_HYP done bit instead of SSH? */
	spwu_addr = XSCOM_ADDR_P10_QME_CORE(core_id, P10_QME_SPWU_HYP);
	ssh_addr = XSCOM_ADDR_P10_QME_CORE(core_id, P10_QME_SSH_HYP);

	if (xscom_write(chip_id, spwu_addr, P10_SPWU_REQ)) {
		prlog(PR_ERR, "Could not set special wakeup on %u:%u:"
				" Unable to write QME_SPWU_HYP.\n",
				chip_id, core_id);
		return OPAL_HARDWARE;
	}

	for (i = 0; i < P10_SPWU_TIMEOUT / P10_SPWU_POLL_INTERVAL; i++) {
		if (xscom_read(chip_id, ssh_addr, &val)) {
			prlog(PR_ERR, "Could not set special wakeup on %u:%u:"
					" Unable to read QME_SSH_HYP.\n",
					chip_id, core_id);
			return OPAL_HARDWARE;
		}
		if (val & P10_SSH_SPWU_DONE) {
			/*
			 * CORE_GATED will be unset on a successful special
			 * wakeup of the core which indicates that the core is
			 * out of stop state. If CORE_GATED is still set then
			 * check SPWU register and raise error only if SPWU_DONE
			 * is not set, else print a warning and consider SPWU
			 * operation as successful.
			 * This is in conjunction with a micocode bug, which
			 * calls out the fact that SPW can succeed in the case
			 * the core is gated but SPWU_HYP bit is set.
			 */
			if (p10_core_is_gated(cpu)) {
				if(xscom_read(chip_id, spwu_addr, &val)) {
					prlog(PR_ERR, "Core %u:%u:"
					      " unable to read QME_SPWU_HYP\n",
					      chip_id, core_id);
					return OPAL_HARDWARE;
				}
				if (val & P10_SPWU_DONE) {
					/*
					 * If SPWU DONE bit is set then
					 * SPWU operation is complete
					 */
					prlog(PR_DEBUG, "Special wakeup on "
					      "%u:%u: core remains gated while"
					      " SPWU_HYP DONE set\n",
					      chip_id, core_id);
					return 0;
				}
				/* Deassert spwu for this strange error */
				xscom_write(chip_id, spwu_addr, 0);
				prlog(PR_ERR,
				      "Failed special wakeup on %u:%u"
				      " core remains gated.\n",
				      chip_id, core_id);
				return OPAL_HARDWARE;
			} else {
				return 0;
			}
		}
		time_wait_us(P10_SPWU_POLL_INTERVAL);
	}

	prlog(PR_ERR, "Could not set special wakeup on %u:%u:"
			" operation timeout.\n",
			chip_id, core_id);
	/*
	 * As per the special wakeup protocol we should not de-assert
	 * the special wakeup on the core until WAKEUP_DONE is set.
	 * So even on error do not de-assert.
	 */

	return OPAL_HARDWARE;
}

static int p10_core_clear_special_wakeup(struct cpu_thread *cpu)
{
	uint32_t chip_id = pir_to_chip_id(cpu->pir);
	uint32_t core_id = pir_to_core_id(cpu->pir);
	uint32_t spwu_addr;

	spwu_addr = XSCOM_ADDR_P10_QME_CORE(core_id, P10_QME_SPWU_HYP);

	/* Add a small delay here if spwu problems time_wait_us(1); */
	if (xscom_write(chip_id, spwu_addr, 0)) {
		prlog(PR_ERR, "Could not clear special wakeup on %u:%u:"
				" Unable to write QME_SPWU_HYP.\n",
				chip_id, core_id);
		return OPAL_HARDWARE;
	}

	return 0;
}

static int p10_thread_quiesced(struct cpu_thread *cpu)
{
	uint32_t chip_id = pir_to_chip_id(cpu->pir);
	uint32_t core_id = pir_to_core_id(cpu->pir);
	uint32_t thread_id = pir_to_thread_id(cpu->pir);
	uint32_t ras_addr;
	uint64_t ras_status;

	ras_addr = XSCOM_ADDR_P10_EC(core_id, P10_EC_RAS_STATUS);
	if (xscom_read(chip_id, ras_addr, &ras_status)) {
		prlog(PR_ERR, "Could not check thread state on %u:%u:"
				" Unable to read EC_RAS_STATUS.\n",
				chip_id, core_id);
		return OPAL_HARDWARE;
	}

	/*
	 * p10_thread_stop for the purpose of sreset wants QUIESCED
	 * and MAINT bits set. Step, RAM, etc. need more, but we don't
	 * use those in skiboot.
	 *
	 * P10 could try wait for more here in case of errors.
	 */
	if (!(ras_status & P10_THREAD_QUIESCED(thread_id)))
		return 0;

	if (!(ras_status & P10_THREAD_MAINT(thread_id)))
		return 0;

	return 1;
}

static int p10_cont_thread(struct cpu_thread *cpu)
{
	uint32_t chip_id = pir_to_chip_id(cpu->pir);
	uint32_t core_id = pir_to_core_id(cpu->pir);
	uint32_t thread_id = pir_to_thread_id(cpu->pir);
	uint32_t cts_addr;
	uint32_t ti_addr;
	uint32_t dctl_addr;
	uint64_t core_thread_state;
	uint64_t thread_info;
	bool active, stop;
	int rc;
	int i;

	rc = p10_thread_quiesced(cpu);
	if (rc < 0)
		return rc;
	if (!rc) {
		prlog(PR_ERR, "Could not cont thread %u:%u:%u:"
				" Thread is not quiesced.\n",
				chip_id, core_id, thread_id);
		return OPAL_BUSY;
	}

	cts_addr = XSCOM_ADDR_P10_EC(core_id, P10_EC_CORE_THREAD_STATE);
	ti_addr = XSCOM_ADDR_P10_EC(core_id, P10_EC_THREAD_INFO);
	dctl_addr = XSCOM_ADDR_P10_EC(core_id, P10_EC_DIRECT_CONTROLS);

	if (xscom_read(chip_id, cts_addr, &core_thread_state)) {
		prlog(PR_ERR, "Could not resume thread %u:%u:%u:"
				" Unable to read EC_CORE_THREAD_STATE.\n",
				chip_id, core_id, thread_id);
		return OPAL_HARDWARE;
	}
	if (core_thread_state & P10_THREAD_STOPPED(thread_id))
		stop = true;
	else
		stop = false;

	if (xscom_read(chip_id, ti_addr, &thread_info)) {
		prlog(PR_ERR, "Could not resume thread %u:%u:%u:"
				" Unable to read EC_THREAD_INFO.\n",
				chip_id, core_id, thread_id);
		return OPAL_HARDWARE;
	}
	if (thread_info & P10_THREAD_ACTIVE(thread_id))
		active = true;
	else
		active = false;

	if (!active || stop) {
		if (xscom_write(chip_id, dctl_addr, P10_THREAD_CLEAR_MAINT(thread_id))) {
			prlog(PR_ERR, "Could not resume thread %u:%u:%u:"
				      " Unable to write EC_DIRECT_CONTROLS.\n",
				      chip_id, core_id, thread_id);
		}
	} else {
		if (xscom_write(chip_id, dctl_addr, P10_THREAD_START(thread_id))) {
			prlog(PR_ERR, "Could not resume thread %u:%u:%u:"
				      " Unable to write EC_DIRECT_CONTROLS.\n",
				      chip_id, core_id, thread_id);
		}
	}

	for (i = 0; i < P10_QUIESCE_TIMEOUT / P10_QUIESCE_POLL_INTERVAL; i++) {
		int rc = p10_thread_quiesced(cpu);
		if (rc < 0)
			break;
		if (!rc)
			return 0;

		time_wait_us(P10_QUIESCE_POLL_INTERVAL);
	}

	prlog(PR_ERR, "Could not start thread %u:%u:%u:"
			" Unable to start thread.\n",
			chip_id, core_id, thread_id);

	return OPAL_HARDWARE;
}

static int p10_stop_thread(struct cpu_thread *cpu)
{
	uint32_t chip_id = pir_to_chip_id(cpu->pir);
	uint32_t core_id = pir_to_core_id(cpu->pir);
	uint32_t thread_id = pir_to_thread_id(cpu->pir);
	uint32_t dctl_addr;
	int rc;
	int i;

	dctl_addr = XSCOM_ADDR_P10_EC(core_id, P10_EC_DIRECT_CONTROLS);

	rc = p10_thread_quiesced(cpu);
	if (rc < 0)
		return rc;
	if (rc) {
		prlog(PR_ERR, "Could not stop thread %u:%u:%u:"
				" Thread is quiesced already.\n",
				chip_id, core_id, thread_id);
		return OPAL_BUSY;
	}

	if (xscom_write(chip_id, dctl_addr, P10_THREAD_STOP(thread_id))) {
		prlog(PR_ERR, "Could not stop thread %u:%u:%u:"
				" Unable to write EC_DIRECT_CONTROLS.\n",
				chip_id, core_id, thread_id);
		return OPAL_HARDWARE;
	}

	for (i = 0; i < P10_QUIESCE_TIMEOUT / P10_QUIESCE_POLL_INTERVAL; i++) {
		int rc = p10_thread_quiesced(cpu);
		if (rc < 0)
			break;
		if (rc)
			return 0;

		time_wait_us(P10_QUIESCE_POLL_INTERVAL);
	}

	prlog(PR_ERR, "Could not stop thread %u:%u:%u:"
			" Unable to quiesce thread.\n",
			chip_id, core_id, thread_id);

	return OPAL_HARDWARE;
}

static int p10_sreset_thread(struct cpu_thread *cpu)
{
	uint32_t chip_id = pir_to_chip_id(cpu->pir);
	uint32_t core_id = pir_to_core_id(cpu->pir);
	uint32_t thread_id = pir_to_thread_id(cpu->pir);
	uint32_t dctl_addr;

	dctl_addr = XSCOM_ADDR_P10_EC(core_id, P10_EC_DIRECT_CONTROLS);

	if (xscom_write(chip_id, dctl_addr, P10_THREAD_SRESET(thread_id))) {
		prlog(PR_ERR, "Could not sreset thread %u:%u:%u:"
				" Unable to write EC_DIRECT_CONTROLS.\n",
				chip_id, core_id, thread_id);
		return OPAL_HARDWARE;
	}

	return 0;
}

/**************** generic direct controls ****************/

int dctl_set_special_wakeup(struct cpu_thread *t)
{
	struct cpu_thread *c = t->ec_primary;
	int rc = OPAL_SUCCESS;

	if (proc_gen == proc_gen_unknown)
		return OPAL_UNSUPPORTED;

	lock(&c->dctl_lock);
	if (c->special_wakeup_count == 0) {
		if (proc_gen == proc_gen_p10)
			rc = p10_core_set_special_wakeup(c);
		else if (proc_gen == proc_gen_p9)
			rc = p9_core_set_special_wakeup(c);
		else /* (proc_gen == proc_gen_p8) */
			rc = p8_core_set_special_wakeup(c);
	}
	if (!rc)
		c->special_wakeup_count++;
	unlock(&c->dctl_lock);

	return rc;
}

int dctl_clear_special_wakeup(struct cpu_thread *t)
{
	struct cpu_thread *c = t->ec_primary;
	int rc = OPAL_SUCCESS;

	if (proc_gen == proc_gen_unknown)
		return OPAL_UNSUPPORTED;

	lock(&c->dctl_lock);
	if (!c->special_wakeup_count)
		goto out;
	if (c->special_wakeup_count == 1) {
		if (proc_gen == proc_gen_p10)
			rc = p10_core_clear_special_wakeup(c);
		else if (proc_gen == proc_gen_p9)
			rc = p9_core_clear_special_wakeup(c);
		else /* (proc_gen == proc_gen_p8) */
			rc = p8_core_clear_special_wakeup(c);
	}
	if (!rc)
		c->special_wakeup_count--;
out:
	unlock(&c->dctl_lock);

	return rc;
}

int dctl_core_is_gated(struct cpu_thread *t)
{
	struct cpu_thread *c = t->primary;

	if (proc_gen == proc_gen_p10)
		return p10_core_is_gated(c);
	else if (proc_gen == proc_gen_p9)
		return p9_core_is_gated(c);
	else
		return OPAL_UNSUPPORTED;
}

static int dctl_stop(struct cpu_thread *t)
{
	struct cpu_thread *c = t->ec_primary;
	int rc;

	lock(&c->dctl_lock);
	if (t->dctl_stopped) {
		unlock(&c->dctl_lock);
		return OPAL_BUSY;
	}
	if (proc_gen == proc_gen_p10)
		rc = p10_stop_thread(t);
	else if (proc_gen == proc_gen_p9)
		rc = p9_stop_thread(t);
	else /* (proc_gen == proc_gen_p8) */
		rc = p8_stop_thread(t);
	if (!rc)
		t->dctl_stopped = true;
	unlock(&c->dctl_lock);

	return rc;
}

static int dctl_cont(struct cpu_thread *t)
{
	struct cpu_thread *c = t->primary;
	int rc;

	if (proc_gen != proc_gen_p10 && proc_gen != proc_gen_p9)
		return OPAL_UNSUPPORTED;

	lock(&c->dctl_lock);
	if (!t->dctl_stopped) {
		unlock(&c->dctl_lock);
		return OPAL_BUSY;
	}
	if (proc_gen == proc_gen_p10)
		rc = p10_cont_thread(t);
	else /* (proc_gen == proc_gen_p9) */
		rc = p9_cont_thread(t);
	if (!rc)
		t->dctl_stopped = false;
	unlock(&c->dctl_lock);

	return rc;
}

/*
 * NOTE:
 * The POWER8 sreset does not provide SRR registers, so it can be used
 * for fast reboot, but not OPAL_SIGNAL_SYSTEM_RESET or anywhere that is
 * expected to return. For now, callers beware.
 */
static int dctl_sreset(struct cpu_thread *t)
{
	struct cpu_thread *c = t->ec_primary;
	int rc;

	lock(&c->dctl_lock);
	if (!t->dctl_stopped) {
		unlock(&c->dctl_lock);
		return OPAL_BUSY;
	}
	if (proc_gen == proc_gen_p10)
		rc = p10_sreset_thread(t);
	else if (proc_gen == proc_gen_p9)
		rc = p9_sreset_thread(t);
	else /* (proc_gen == proc_gen_p8) */
		rc = p8_sreset_thread(t);
	if (!rc)
		t->dctl_stopped = false;
	unlock(&c->dctl_lock);

	return rc;
}


/**************** fast reboot API ****************/

int sreset_all_prepare(void)
{
	struct cpu_thread *cpu;

	if (proc_gen == proc_gen_unknown)
		return OPAL_UNSUPPORTED;

	prlog(PR_DEBUG, "RESET: Resetting from cpu: 0x%x (core 0x%x)\n",
	      this_cpu()->pir, pir_to_core_id(this_cpu()->pir));

	if (chip_quirk(QUIRK_MAMBO_CALLOUTS)) {
		for_each_ungarded_cpu(cpu) {
			if (cpu == this_cpu())
				continue;
			mambo_stop_cpu(cpu);
		}
		return OPAL_SUCCESS;
	}

	/* Assert special wakup on all cores. Only on operational cores. */
	for_each_ungarded_primary(cpu) {
		if (dctl_set_special_wakeup(cpu) != OPAL_SUCCESS)
			return OPAL_HARDWARE;
	}

	prlog(PR_DEBUG, "RESET: Stopping the world...\n");

	/* Put everybody in stop except myself */
	for_each_ungarded_cpu(cpu) {
		if (cpu == this_cpu())
			continue;
		if (dctl_stop(cpu) != OPAL_SUCCESS)
			return OPAL_HARDWARE;

	}

	return OPAL_SUCCESS;
}

void sreset_all_finish(void)
{
	struct cpu_thread *cpu;

	if (chip_quirk(QUIRK_MAMBO_CALLOUTS))
		return;

	for_each_ungarded_primary(cpu)
		dctl_clear_special_wakeup(cpu);
}

int sreset_all_others(void)
{
	struct cpu_thread *cpu;

	prlog(PR_DEBUG, "RESET: Resetting all threads but self...\n");

	/*
	 * mambo should actually implement stop as well, and implement
	 * the dctl_ helpers properly. Currently it's racy just sresetting.
	 */
	if (chip_quirk(QUIRK_MAMBO_CALLOUTS)) {
		for_each_ungarded_cpu(cpu) {
			if (cpu == this_cpu())
				continue;
			mambo_sreset_cpu(cpu);
		}
		return OPAL_SUCCESS;
	}

	for_each_ungarded_cpu(cpu) {
		if (cpu == this_cpu())
			continue;
		if (dctl_sreset(cpu) != OPAL_SUCCESS)
			return OPAL_HARDWARE;
	}

	return OPAL_SUCCESS;
}


/**************** OPAL_SIGNAL_SYSTEM_RESET API ****************/

/*
 * This provides a way for the host to raise system reset exceptions
 * on other threads using direct control scoms on POWER9.
 *
 * We assert special wakeup on the core first.
 * Then stop target thread and wait for it to quiesce.
 * Then sreset the target thread, which resumes execution on that thread.
 * Then de-assert special wakeup on the core.
 */
static int64_t do_sreset_cpu(struct cpu_thread *cpu)
{
	int rc;

	if (this_cpu() == cpu) {
		prlog(PR_ERR, "SRESET: Unable to reset self\n");
		return OPAL_PARAMETER;
	}

	rc = dctl_set_special_wakeup(cpu);
	if (rc)
		return rc;

	rc = dctl_stop(cpu);
	if (rc)
		goto out_spwk;

	rc = dctl_sreset(cpu);
	if (rc)
		goto out_cont;

	dctl_clear_special_wakeup(cpu);

	return 0;

out_cont:
	dctl_cont(cpu);
out_spwk:
	dctl_clear_special_wakeup(cpu);

	return rc;
}

static struct lock sreset_lock = LOCK_UNLOCKED;

int64_t opal_signal_system_reset(int cpu_nr)
{
	struct cpu_thread *cpu;
	int64_t ret;

	if (proc_gen != proc_gen_p9 && proc_gen != proc_gen_p10)
		return OPAL_UNSUPPORTED;

	/*
	 * Broadcasts unsupported. Not clear what threads should be
	 * signaled, so it's better for the OS to perform one-at-a-time
	 * for now.
	 */
	if (cpu_nr < 0)
		return OPAL_CONSTRAINED;

	/* Reset a single CPU */
	cpu = find_cpu_by_server(cpu_nr);
	if (!cpu) {
		prlog(PR_ERR, "SRESET: could not find cpu by server %d\n", cpu_nr);
		return OPAL_PARAMETER;
	}

	lock(&sreset_lock);
	ret = do_sreset_cpu(cpu);
	unlock(&sreset_lock);

	return ret;
}

void direct_controls_init(void)
{
	if (chip_quirk(QUIRK_MAMBO_CALLOUTS))
		return;

	if (proc_gen != proc_gen_p9 && proc_gen != proc_gen_p10)
		return;

	opal_register(OPAL_SIGNAL_SYSTEM_RESET, opal_signal_system_reset, 1);
}
