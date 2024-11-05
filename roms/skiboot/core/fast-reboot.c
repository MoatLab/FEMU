// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Full IPL is slow, let's cheat!
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <skiboot.h>
#include <cpu.h>
#include <console.h>
#include <fsp.h>
#include <psi.h>
#include <opal.h>
#include <mem_region.h>
#include <xscom.h>
#include <interrupts.h>
#include <cec.h>
#include <timebase.h>
#include <pci.h>
#include <xive.h>
#include <chip.h>
#include <chiptod.h>
#include <ipmi.h>
#include <direct-controls.h>
#include <nvram.h>

/* Flag tested by the OPAL entry code */
static volatile bool fast_boot_release;
static volatile bool spr_set_release;
static volatile bool nmi_mce_release;

static void wait_on(volatile bool *cond)
{
	sync();
	if (!*cond) {
		smt_lowest();
		while (!*cond)
			barrier();
		smt_medium();
	}
	sync();
}

static bool cpu_state_wait_all_others(enum cpu_thread_state state,
					unsigned long timeout_tb)
{
	struct cpu_thread *cpu;
	unsigned long end = mftb() + timeout_tb;

	sync();
	for_each_ungarded_cpu(cpu) {
		if (cpu == this_cpu())
			continue;

		if (cpu->state != state) {
			smt_lowest();
			while (cpu->state != state) {
				barrier();

				if (timeout_tb && (tb_compare(mftb(), end) == TB_AAFTERB)) {
					smt_medium();
					return false;
				}
			}
			smt_medium();
		}
	}
	sync();

	return true;
}

static const char *fast_reboot_disabled = NULL;

void disable_fast_reboot(const char *reason)
{
	if (fast_reboot_disabled)
		return;

	prlog(PR_NOTICE, "RESET: Fast reboot disabled: %s\n", reason);
	fast_reboot_disabled = reason;
}

void add_fast_reboot_dt_entries(void)
{
	dt_check_del_prop(opal_node, "fast-reboot");

	if (fast_reboot_disabled) {
		dt_add_property_string(opal_node, "fast-reboot", fast_reboot_disabled);
	} else {
		dt_add_property_string(opal_node, "fast-reboot", "okay");
	}
}

/*
 * This is called by the reboot CPU after all other CPUs have been
 * quiesced and stopped, to perform various sanity checks on firmware
 * data (and potentially hardware), to determine whether the fast
 * reboot should go ahead.
 */
static bool fast_reboot_sanity_check(void)
{
	if (!mem_check_all()) {
		disable_fast_reboot("Inconsistent firmware data");
		return false;
	}

	if (!verify_romem()) {
		disable_fast_reboot("Inconsistent firmware romem checksum");
		return false;
	}

	return true;
}

void fast_reboot(void)
{
	static int fast_reboot_count = 0;

	if (chip_quirk(QUIRK_NO_DIRECT_CTL)) {
		prlog(PR_DEBUG,
		      "RESET: Fast reboot disabled by quirk\n");
		return;
	}

	/*
	 * Ensure all other CPUs have left OPAL calls.
	 */
	if (!opal_quiesce(QUIESCE_HOLD, -1)) {
		disable_fast_reboot("OPAL quiesce timeout");
		return;
	}

	if (fast_reboot_disabled &&
	    nvram_query_eq_dangerous("force-fast-reset", "1")) {
		/* Do fast reboot even if it's been disabled */
		prlog(PR_NOTICE, "RESET: Ignoring fast reboot disabled: %s\n",
				fast_reboot_disabled);
	} else if (fast_reboot_disabled) {
		prlog(PR_NOTICE, "RESET: Fast reboot disabled: %s\n",
		      fast_reboot_disabled);
		opal_quiesce(QUIESCE_RESUME, -1);
		return;
	}

	prlog(PR_NOTICE, "RESET: Initiating fast reboot %d...\n", ++fast_reboot_count);
	fast_boot_release = false;
	spr_set_release = false;
	nmi_mce_release = false;
	sync();

	/* Put everybody in stop except myself */
	if (sreset_all_prepare()) {
		prlog(PR_NOTICE, "RESET: Fast reboot failed to prepare "
				"secondaries for system reset\n");
		opal_quiesce(QUIESCE_RESUME, -1);
		return;
	}

	if (!fast_reboot_sanity_check()) {
		opal_quiesce(QUIESCE_RESUME, -1);
		return;
	}

	cpu_set_sreset_enable(false);
	cpu_set_ipi_enable(false);

	/*
	 * The fast reboot sreset vector has FIXUP_ENDIAN, so secondaries can
	 * cope with a wrong HILE setting.
	 */
	copy_sreset_vector_fast_reboot();

	/*
	 * There is no point clearing special wakeup or un-quiesce due to
	 * failure after this point, because we will be going to full IPL.
	 * Less cleanup work means less opportunity to fail.
	 */

	/* Send everyone else to 0x100 */
	if (sreset_all_others() != OPAL_SUCCESS) {
		prlog(PR_NOTICE, "RESET: Fast reboot failed to system reset "
				"secondaries\n");
		return;
	}

	/* Ensure all the sresets get through */
	if (!cpu_state_wait_all_others(cpu_state_fast_reboot_entry, msecs_to_tb(1000))) {
		prlog(PR_NOTICE, "RESET: Fast reboot timed out waiting for "
				"secondaries to call in\n");
		return;
	}

	prlog(PR_DEBUG, "RESET: Releasing special wakeups...\n");
	sreset_all_finish();

	/* This resets our quiesce state ready to enter the new kernel. */
	opal_quiesce(QUIESCE_RESUME_FAST_REBOOT, -1);

	console_complete_flush();

	mtmsrd(0, 1); /* Clear MSR[RI] for 0x100 reset */
	asm volatile("ba	0x100\n\t" : : : "memory");
	for (;;)
		;
}

void __noreturn enter_nap(void);

static void check_split_core(void)
{
	struct cpu_thread *cpu;
	u64 mask, hid0;

        hid0 = mfspr(SPR_HID0);
	mask = SPR_HID0_POWER8_4LPARMODE | SPR_HID0_POWER8_2LPARMODE;

	if ((hid0 & mask) == 0)
		return;

	prlog(PR_INFO, "RESET: CPU 0x%04x is split !\n", this_cpu()->pir);

	/* If it's a secondary thread, just send it to nap */
	if (this_cpu()->pir & 7) {
		/* Prepare to be woken up */
		icp_prep_for_pm();
		/* Setup LPCR to wakeup on external interrupts only */
		mtspr(SPR_LPCR, ((mfspr(SPR_LPCR) & ~SPR_LPCR_P8_PECE) |
				 SPR_LPCR_P8_PECE2));
		isync();
		/* Go to nap (doesn't return) */
		enter_nap();
	}

	prlog(PR_INFO, "RESET: Primary, unsplitting... \n");

	/* Trigger unsplit operation and update SLW image */
	hid0 &= ~SPR_HID0_POWER8_DYNLPARDIS;
	set_hid0(hid0);
	opal_slw_set_reg(this_cpu()->pir, SPR_HID0, hid0);

	/* Wait for unsplit */
	while (mfspr(SPR_HID0) & mask)
		cpu_relax();

	/* Now the guys are sleeping, wake'em up. They will come back
	 * via reset and continue the fast reboot process normally.
	 * No need to wait.
	 */
	prlog(PR_INFO, "RESET: Waking unsplit secondaries... \n");

	for_each_cpu(cpu) {
		if (!cpu_is_sibling(cpu, this_cpu()) || (cpu == this_cpu()))
			continue;
		icp_kick_cpu(cpu);
	}
}

static void cleanup_cpu_state(void)
{
	struct cpu_thread *cpu = this_cpu();

	if (proc_gen == proc_gen_p9)
		xive_cpu_reset();
	else if (proc_gen == proc_gen_p10)
		xive2_cpu_reset();

	/* Per core cleanup */
	if (cpu_is_thread0(cpu) || cpu_is_core_chiplet_primary(cpu)) {
		/* Shared SPRs whacked back to normal */

		/* XXX Update the SLW copies ! Also dbl check HIDs etc... */
		init_shared_sprs();

		if (proc_gen == proc_gen_p8) {
			/* If somebody was in fast_sleep, we may have a
			 * workaround to undo
			 */
			if (cpu->in_fast_sleep) {
				prlog(PR_DEBUG, "RESET: CPU 0x%04x in fast sleep"
				      " undoing workarounds...\n", cpu->pir);
				fast_sleep_exit();
			}

			/* The TLB surely contains garbage.
			 * P9 clears TLBs in cpu_fast_reboot_complete
			 */
			cleanup_local_tlb();
		}

		/* And we might have lost TB sync */
		chiptod_wakeup_resync();
	}

	/* Per-thread additional cleanup */
	init_replicated_sprs();

	// XXX Cleanup SLW, check HIDs ...
}

/* Entry from asm after a fast reset */
void __noreturn fast_reboot_entry(void);

void __noreturn fast_reboot_entry(void)
{
	struct cpu_thread *cpu = this_cpu();

	if (proc_gen == proc_gen_p8) {
		/* We reset our ICP first ! Otherwise we might get stray
		 * interrupts when unsplitting
		 */
		reset_cpu_icp();

		/* If we are split, we need to unsplit. Since that can send us
		 * to NAP, which will come back via reset, we do it now
		 */
		check_split_core();
	}

	/* Until SPRs (notably HID[HILE]) are set and new exception vectors
	 * installed, nobody should take machine checks. Try to do minimal
	 * work between these points.
	 */
	disable_machine_check();
	mtmsrd(0, 1); /* Clear RI */

	sync();
	cpu->state = cpu_state_fast_reboot_entry;
	sync();
	if (cpu == boot_cpu) {
		cpu_state_wait_all_others(cpu_state_fast_reboot_entry, 0);
		spr_set_release = true;
	} else {
		wait_on(&spr_set_release);
	}


	/* Reset SPRs */
	if (cpu_is_thread0(cpu))
		init_shared_sprs();
	init_replicated_sprs();

	if (cpu == boot_cpu) {
		/* Restore skiboot vectors */
		copy_exception_vectors();
		copy_sreset_vector();
		patch_traps(true);
	}

	/* Must wait for others to because shared SPRs like HID0 are only set
	 * by thread0, so can't enable machine checks until those have been
	 * set.
	 */
	sync();
	cpu->state = cpu_state_present;
	sync();
	if (cpu == boot_cpu) {
		cpu_state_wait_all_others(cpu_state_present, 0);
		nmi_mce_release = true;
	} else {
		wait_on(&nmi_mce_release);
	}

	/* At this point skiboot exception vectors are in place and all
	 * cores/threads have SPRs set for running skiboot.
	 */
	enable_machine_check();
	mtmsrd(MSR_RI, 1);

	cleanup_cpu_state();

	prlog(PR_DEBUG, "RESET: CPU 0x%04x reset in\n", cpu->pir);

	/* The original boot CPU (not the fast reboot initiator) takes
	 * command. Secondaries wait for the signal then go to their secondary
	 * entry point.
	 */
	if (cpu != boot_cpu) {
		wait_on(&fast_boot_release);

		__secondary_cpu_entry();
	}

	if (proc_gen == proc_gen_p9)
		xive_reset();
	else if (proc_gen == proc_gen_p10)
		xive2_reset();

	/* Let the CPU layer do some last minute global cleanups */
	cpu_fast_reboot_complete();

	/* We can now do NAP mode */
	cpu_set_sreset_enable(true);
	cpu_set_ipi_enable(true);

	prlog(PR_INFO, "RESET: Releasing secondaries...\n");

	/* Release everybody */
	sync();
	fast_boot_release = true;
	sync();
	cpu->state = cpu_state_active;
	sync();

	/* Wait for them to respond */
	cpu_state_wait_all_others(cpu_state_active, 0);

	sync();

	prlog(PR_INFO, "RESET: All done, cleaning up...\n");

	/* Clear release flag for next time */
	fast_boot_release = false;

	if (!chip_quirk(QUIRK_MAMBO_CALLOUTS)) {
		/*
		 * mem_region_clear_unused avoids these preload regions
		 * so it can run along side image preloading. Clear these
		 * regions now to catch anything not overwritten by
		 * preload.
		 *
		 * Mambo may have embedded payload here, so don't clear
		 * it at all.
		 */
		memset(KERNEL_LOAD_BASE, 0, KERNEL_LOAD_SIZE);
		memset(INITRAMFS_LOAD_BASE, 0, INITRAMFS_LOAD_SIZE);
	}

	/* Start preloading kernel and ramdisk */
	start_preload_kernel();

	/* Start clearing memory */
	start_mem_region_clear_unused();

	if (platform.fast_reboot_init)
		platform.fast_reboot_init();

	if (proc_gen == proc_gen_p8) {
		/* XXX */
		/* Reset/EOI the PSI interrupt */
		psi_irq_reset();
	}

	/* update pci nvram settings */
	pci_nvram_init();

	/* Remove all PCI devices */
	if (pci_reset()) {
		prlog(PR_NOTICE, "RESET: Fast reboot failed to reset PCI\n");

		/*
		 * Can't return to caller here because we're past no-return.
		 * Attempt an IPL here which is what the caller would do.
		 */
		if (platform.cec_reboot)
			platform.cec_reboot();
		for (;;)
			;
	}

	ipmi_set_fw_progress_sensor(IPMI_FW_PCI_INIT);

	wait_mem_region_clear_unused();

	/* Load and boot payload */
	load_and_boot_kernel(true);
}
