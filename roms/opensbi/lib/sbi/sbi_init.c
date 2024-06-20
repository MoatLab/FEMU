/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *   Anup Patel <anup.patel@wdc.com>
 */

#include <sbi/riscv_asm.h>
#include <sbi/riscv_atomic.h>
#include <sbi/riscv_barrier.h>
#include <sbi/riscv_locks.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_cppc.h>
#include <sbi/sbi_domain.h>
#include <sbi/sbi_ecall.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_hartmask.h>
#include <sbi/sbi_heap.h>
#include <sbi/sbi_hsm.h>
#include <sbi/sbi_ipi.h>
#include <sbi/sbi_irqchip.h>
#include <sbi/sbi_platform.h>
#include <sbi/sbi_pmu.h>
#include <sbi/sbi_system.h>
#include <sbi/sbi_string.h>
#include <sbi/sbi_timer.h>
#include <sbi/sbi_tlb.h>
#include <sbi/sbi_version.h>

#define BANNER                                              \
	"   ____                    _____ ____ _____\n"     \
	"  / __ \\                  / ____|  _ \\_   _|\n"  \
	" | |  | |_ __   ___ _ __ | (___ | |_) || |\n"      \
	" | |  | | '_ \\ / _ \\ '_ \\ \\___ \\|  _ < | |\n" \
	" | |__| | |_) |  __/ | | |____) | |_) || |_\n"     \
	"  \\____/| .__/ \\___|_| |_|_____/|____/_____|\n"  \
	"        | |\n"                                     \
	"        |_|\n\n"

static void sbi_boot_print_banner(struct sbi_scratch *scratch)
{
	if (scratch->options & SBI_SCRATCH_NO_BOOT_PRINTS)
		return;

#ifdef OPENSBI_VERSION_GIT
	sbi_printf("\nOpenSBI %s\n", OPENSBI_VERSION_GIT);
#else
	sbi_printf("\nOpenSBI v%d.%d\n", OPENSBI_VERSION_MAJOR,
		   OPENSBI_VERSION_MINOR);
#endif

#ifdef OPENSBI_BUILD_TIME_STAMP
	sbi_printf("Build time: %s\n", OPENSBI_BUILD_TIME_STAMP);
#endif

#ifdef OPENSBI_BUILD_COMPILER_VERSION
	sbi_printf("Build compiler: %s\n", OPENSBI_BUILD_COMPILER_VERSION);
#endif

	sbi_printf(BANNER);
}

static void sbi_boot_print_general(struct sbi_scratch *scratch)
{
	char str[128];
	const struct sbi_pmu_device *pdev;
	const struct sbi_hsm_device *hdev;
	const struct sbi_ipi_device *idev;
	const struct sbi_timer_device *tdev;
	const struct sbi_console_device *cdev;
	const struct sbi_system_reset_device *srdev;
	const struct sbi_system_suspend_device *susp_dev;
	const struct sbi_cppc_device *cppc_dev;
	const struct sbi_platform *plat = sbi_platform_ptr(scratch);

	if (scratch->options & SBI_SCRATCH_NO_BOOT_PRINTS)
		return;

	/* Platform details */
	sbi_printf("Platform Name             : %s\n",
		   sbi_platform_name(plat));
	sbi_platform_get_features_str(plat, str, sizeof(str));
	sbi_printf("Platform Features         : %s\n", str);
	sbi_printf("Platform HART Count       : %u\n",
		   sbi_platform_hart_count(plat));
	idev = sbi_ipi_get_device();
	sbi_printf("Platform IPI Device       : %s\n",
		   (idev) ? idev->name : "---");
	tdev = sbi_timer_get_device();
	sbi_printf("Platform Timer Device     : %s @ %luHz\n",
		   (tdev) ? tdev->name : "---",
		   (tdev) ? tdev->timer_freq : 0);
	cdev = sbi_console_get_device();
	sbi_printf("Platform Console Device   : %s\n",
		   (cdev) ? cdev->name : "---");
	hdev = sbi_hsm_get_device();
	sbi_printf("Platform HSM Device       : %s\n",
		   (hdev) ? hdev->name : "---");
	pdev = sbi_pmu_get_device();
	sbi_printf("Platform PMU Device       : %s\n",
		   (pdev) ? pdev->name : "---");
	srdev = sbi_system_reset_get_device(SBI_SRST_RESET_TYPE_COLD_REBOOT, 0);
	sbi_printf("Platform Reboot Device    : %s\n",
		   (srdev) ? srdev->name : "---");
	srdev = sbi_system_reset_get_device(SBI_SRST_RESET_TYPE_SHUTDOWN, 0);
	sbi_printf("Platform Shutdown Device  : %s\n",
		   (srdev) ? srdev->name : "---");
	susp_dev = sbi_system_suspend_get_device();
	sbi_printf("Platform Suspend Device   : %s\n",
		   (susp_dev) ? susp_dev->name : "---");
	cppc_dev = sbi_cppc_get_device();
	sbi_printf("Platform CPPC Device      : %s\n",
		   (cppc_dev) ? cppc_dev->name : "---");

	/* Firmware details */
	sbi_printf("Firmware Base             : 0x%lx\n", scratch->fw_start);
	sbi_printf("Firmware Size             : %d KB\n",
		   (u32)(scratch->fw_size / 1024));
	sbi_printf("Firmware RW Offset        : 0x%lx\n", scratch->fw_rw_offset);
	sbi_printf("Firmware RW Size          : %d KB\n",
		   (u32)((scratch->fw_size - scratch->fw_rw_offset) / 1024));
	sbi_printf("Firmware Heap Offset      : 0x%lx\n", scratch->fw_heap_offset);
	sbi_printf("Firmware Heap Size        : "
		   "%d KB (total), %d KB (reserved), %d KB (used), %d KB (free)\n",
		   (u32)(scratch->fw_heap_size / 1024),
		   (u32)(sbi_heap_reserved_space() / 1024),
		   (u32)(sbi_heap_used_space() / 1024),
		   (u32)(sbi_heap_free_space() / 1024));
	sbi_printf("Firmware Scratch Size     : "
		   "%d B (total), %d B (used), %d B (free)\n",
		   SBI_SCRATCH_SIZE,
		   (u32)sbi_scratch_used_space(),
		   (u32)(SBI_SCRATCH_SIZE - sbi_scratch_used_space()));

	/* SBI details */
	sbi_printf("Runtime SBI Version       : %d.%d\n",
		   sbi_ecall_version_major(), sbi_ecall_version_minor());
	sbi_printf("\n");
}

static void sbi_boot_print_domains(struct sbi_scratch *scratch)
{
	if (scratch->options & SBI_SCRATCH_NO_BOOT_PRINTS)
		return;

	/* Domain details */
	sbi_domain_dump_all("      ");
}

static void sbi_boot_print_hart(struct sbi_scratch *scratch, u32 hartid)
{
	int xlen;
	char str[128];
	const struct sbi_domain *dom = sbi_domain_thishart_ptr();

	if (scratch->options & SBI_SCRATCH_NO_BOOT_PRINTS)
		return;

	/* Determine MISA XLEN and MISA string */
	xlen = misa_xlen();
	if (xlen < 1) {
		sbi_printf("Error %d getting MISA XLEN\n", xlen);
		sbi_hart_hang();
	}

	/* Boot HART details */
	sbi_printf("Boot HART ID              : %u\n", hartid);
	sbi_printf("Boot HART Domain          : %s\n", dom->name);
	sbi_hart_get_priv_version_str(scratch, str, sizeof(str));
	sbi_printf("Boot HART Priv Version    : %s\n", str);
	misa_string(xlen, str, sizeof(str));
	sbi_printf("Boot HART Base ISA        : %s\n", str);
	sbi_hart_get_extensions_str(scratch, str, sizeof(str));
	sbi_printf("Boot HART ISA Extensions  : %s\n", str);
	sbi_printf("Boot HART PMP Count       : %d\n",
		   sbi_hart_pmp_count(scratch));
	sbi_printf("Boot HART PMP Granularity : %u bits\n",
		   sbi_hart_pmp_log2gran(scratch));
	sbi_printf("Boot HART PMP Address Bits: %d\n",
		   sbi_hart_pmp_addrbits(scratch));
	sbi_printf("Boot HART MHPM Info       : %lu (0x%08x)\n",
		   sbi_popcount(sbi_hart_mhpm_mask(scratch)),
		   sbi_hart_mhpm_mask(scratch));
	sbi_hart_delegation_dump(scratch, "Boot HART ", "         ");
}

static spinlock_t coldboot_lock = SPIN_LOCK_INITIALIZER;
static struct sbi_hartmask coldboot_wait_hmask = { 0 };

static unsigned long coldboot_done;

static void wait_for_coldboot(struct sbi_scratch *scratch, u32 hartid)
{
	unsigned long saved_mie, cmip;

	if (__smp_load_acquire(&coldboot_done))
		return;

	/* Save MIE CSR */
	saved_mie = csr_read(CSR_MIE);

	/* Set MSIE and MEIE bits to receive IPI */
	csr_set(CSR_MIE, MIP_MSIP | MIP_MEIP);

	/* Acquire coldboot lock */
	spin_lock(&coldboot_lock);

	/* Mark current HART as waiting */
	sbi_hartmask_set_hartid(hartid, &coldboot_wait_hmask);

	/* Release coldboot lock */
	spin_unlock(&coldboot_lock);

	/* Wait for coldboot to finish using WFI */
	while (!__smp_load_acquire(&coldboot_done)) {
		do {
			wfi();
			cmip = csr_read(CSR_MIP);
		 } while (!(cmip & (MIP_MSIP | MIP_MEIP)));
	}

	/* Acquire coldboot lock */
	spin_lock(&coldboot_lock);

	/* Unmark current HART as waiting */
	sbi_hartmask_clear_hartid(hartid, &coldboot_wait_hmask);

	/* Release coldboot lock */
	spin_unlock(&coldboot_lock);

	/* Restore MIE CSR */
	csr_write(CSR_MIE, saved_mie);

	/*
	 * The wait for coldboot is common for both warm startup and
	 * warm resume path so clearing IPI here would result in losing
	 * an IPI in warm resume path.
	 *
	 * Also, the sbi_platform_ipi_init() called from sbi_ipi_init()
	 * will automatically clear IPI for current HART.
	 */
}

static void wake_coldboot_harts(struct sbi_scratch *scratch, u32 hartid)
{
	u32 i, hartindex = sbi_hartid_to_hartindex(hartid);

	/* Mark coldboot done */
	__smp_store_release(&coldboot_done, 1);

	/* Acquire coldboot lock */
	spin_lock(&coldboot_lock);

	/* Send an IPI to all HARTs waiting for coldboot */
	sbi_hartmask_for_each_hartindex(i, &coldboot_wait_hmask) {
		if (i == hartindex)
			continue;
		sbi_ipi_raw_send(i);
	}

	/* Release coldboot lock */
	spin_unlock(&coldboot_lock);
}

static unsigned long entry_count_offset;
static unsigned long init_count_offset;

static void __noreturn init_coldboot(struct sbi_scratch *scratch, u32 hartid)
{
	int rc;
	unsigned long *count;
	const struct sbi_platform *plat = sbi_platform_ptr(scratch);

	/* Note: This has to be first thing in coldboot init sequence */
	rc = sbi_scratch_init(scratch);
	if (rc)
		sbi_hart_hang();

	/* Note: This has to be second thing in coldboot init sequence */
	rc = sbi_heap_init(scratch);
	if (rc)
		sbi_hart_hang();

	/* Note: This has to be the third thing in coldboot init sequence */
	rc = sbi_domain_init(scratch, hartid);
	if (rc)
		sbi_hart_hang();

	entry_count_offset = sbi_scratch_alloc_offset(__SIZEOF_POINTER__);
	if (!entry_count_offset)
		sbi_hart_hang();

	init_count_offset = sbi_scratch_alloc_offset(__SIZEOF_POINTER__);
	if (!init_count_offset)
		sbi_hart_hang();

	count = sbi_scratch_offset_ptr(scratch, entry_count_offset);
	(*count)++;

	rc = sbi_hsm_init(scratch, hartid, true);
	if (rc)
		sbi_hart_hang();

	rc = sbi_platform_early_init(plat, true);
	if (rc)
		sbi_hart_hang();

	rc = sbi_hart_init(scratch, true);
	if (rc)
		sbi_hart_hang();

	rc = sbi_console_init(scratch);
	if (rc)
		sbi_hart_hang();

	rc = sbi_pmu_init(scratch, true);
	if (rc) {
		sbi_printf("%s: pmu init failed (error %d)\n",
			   __func__, rc);
		sbi_hart_hang();
	}

	sbi_boot_print_banner(scratch);

	rc = sbi_irqchip_init(scratch, true);
	if (rc) {
		sbi_printf("%s: irqchip init failed (error %d)\n",
			   __func__, rc);
		sbi_hart_hang();
	}

	rc = sbi_ipi_init(scratch, true);
	if (rc) {
		sbi_printf("%s: ipi init failed (error %d)\n", __func__, rc);
		sbi_hart_hang();
	}

	rc = sbi_tlb_init(scratch, true);
	if (rc) {
		sbi_printf("%s: tlb init failed (error %d)\n", __func__, rc);
		sbi_hart_hang();
	}

	rc = sbi_timer_init(scratch, true);
	if (rc) {
		sbi_printf("%s: timer init failed (error %d)\n", __func__, rc);
		sbi_hart_hang();
	}

	/*
	 * Note: Finalize domains after HSM initialization so that we
	 * can startup non-root domains.
	 * Note: Finalize domains before HART PMP configuration so
	 * that we use correct domain for configuring PMP.
	 */
	rc = sbi_domain_finalize(scratch, hartid);
	if (rc) {
		sbi_printf("%s: domain finalize failed (error %d)\n",
			   __func__, rc);
		sbi_hart_hang();
	}

	/*
	 * Note: Platform final initialization should be after finalizing
	 * domains so that it sees correct domain assignment and PMP
	 * configuration for FDT fixups.
	 */
	rc = sbi_platform_final_init(plat, true);
	if (rc) {
		sbi_printf("%s: platform final init failed (error %d)\n",
			   __func__, rc);
		sbi_hart_hang();
	}

	/*
	 * Note: Ecall initialization should be after platform final
	 * initialization so that all available platform devices are
	 * already registered.
	 */
	rc = sbi_ecall_init();
	if (rc) {
		sbi_printf("%s: ecall init failed (error %d)\n", __func__, rc);
		sbi_hart_hang();
	}

	sbi_boot_print_general(scratch);

	sbi_boot_print_domains(scratch);

	sbi_boot_print_hart(scratch, hartid);

	/*
	 * Configure PMP at last because if SMEPMP is detected,
	 * M-mode access to the S/U space will be rescinded.
	 */
	rc = sbi_hart_pmp_configure(scratch);
	if (rc) {
		sbi_printf("%s: PMP configure failed (error %d)\n",
			   __func__, rc);
		sbi_hart_hang();
	}

	wake_coldboot_harts(scratch, hartid);

	count = sbi_scratch_offset_ptr(scratch, init_count_offset);
	(*count)++;

	sbi_hsm_hart_start_finish(scratch, hartid);
}

static void __noreturn init_warm_startup(struct sbi_scratch *scratch,
					 u32 hartid)
{
	int rc;
	unsigned long *count;
	const struct sbi_platform *plat = sbi_platform_ptr(scratch);

	if (!entry_count_offset || !init_count_offset)
		sbi_hart_hang();

	count = sbi_scratch_offset_ptr(scratch, entry_count_offset);
	(*count)++;

	rc = sbi_hsm_init(scratch, hartid, false);
	if (rc)
		sbi_hart_hang();

	rc = sbi_platform_early_init(plat, false);
	if (rc)
		sbi_hart_hang();

	rc = sbi_hart_init(scratch, false);
	if (rc)
		sbi_hart_hang();

	rc = sbi_pmu_init(scratch, false);
	if (rc)
		sbi_hart_hang();

	rc = sbi_irqchip_init(scratch, false);
	if (rc)
		sbi_hart_hang();

	rc = sbi_ipi_init(scratch, false);
	if (rc)
		sbi_hart_hang();

	rc = sbi_tlb_init(scratch, false);
	if (rc)
		sbi_hart_hang();

	rc = sbi_timer_init(scratch, false);
	if (rc)
		sbi_hart_hang();

	rc = sbi_platform_final_init(plat, false);
	if (rc)
		sbi_hart_hang();

	/*
	 * Configure PMP at last because if SMEPMP is detected,
	 * M-mode access to the S/U space will be rescinded.
	 */
	rc = sbi_hart_pmp_configure(scratch);
	if (rc)
		sbi_hart_hang();

	count = sbi_scratch_offset_ptr(scratch, init_count_offset);
	(*count)++;

	sbi_hsm_hart_start_finish(scratch, hartid);
}

static void __noreturn init_warm_resume(struct sbi_scratch *scratch,
					u32 hartid)
{
	int rc;

	sbi_hsm_hart_resume_start(scratch);

	rc = sbi_hart_reinit(scratch);
	if (rc)
		sbi_hart_hang();

	rc = sbi_hart_pmp_configure(scratch);
	if (rc)
		sbi_hart_hang();

	sbi_hsm_hart_resume_finish(scratch, hartid);
}

static void __noreturn init_warmboot(struct sbi_scratch *scratch, u32 hartid)
{
	int hstate;

	wait_for_coldboot(scratch, hartid);

	hstate = sbi_hsm_hart_get_state(sbi_domain_thishart_ptr(), hartid);
	if (hstate < 0)
		sbi_hart_hang();

	if (hstate == SBI_HSM_STATE_SUSPENDED) {
		init_warm_resume(scratch, hartid);
	} else {
		sbi_ipi_raw_clear(sbi_hartid_to_hartindex(hartid));
		init_warm_startup(scratch, hartid);
	}
}

static atomic_t coldboot_lottery = ATOMIC_INITIALIZER(0);

/**
 * Initialize OpenSBI library for current HART and jump to next
 * booting stage.
 *
 * The function expects following:
 * 1. The 'mscratch' CSR is pointing to sbi_scratch of current HART
 * 2. Stack pointer (SP) is setup for current HART
 * 3. Interrupts are disabled in MSTATUS CSR
 * 4. All interrupts are disabled in MIE CSR
 *
 * @param scratch pointer to sbi_scratch of current HART
 */
void __noreturn sbi_init(struct sbi_scratch *scratch)
{
	u32 i, h;
	bool hartid_valid		= false;
	bool next_mode_supported	= false;
	bool coldboot			= false;
	u32 hartid			= current_hartid();
	const struct sbi_platform *plat = sbi_platform_ptr(scratch);

	for (i = 0; i < plat->hart_count; i++) {
		h = (plat->hart_index2id) ? plat->hart_index2id[i] : i;
		if (h == hartid)
			hartid_valid = true;
	}
	if (!hartid_valid)
		sbi_hart_hang();

	switch (scratch->next_mode) {
	case PRV_M:
		next_mode_supported = true;
		break;
	case PRV_S:
		if (misa_extension('S'))
			next_mode_supported = true;
		break;
	case PRV_U:
		if (misa_extension('U'))
			next_mode_supported = true;
		break;
	default:
		sbi_hart_hang();
	}

	/*
	 * Only the HART supporting privilege mode specified in the
	 * scratch->next_mode should be allowed to become the coldboot
	 * HART because the coldboot HART will be directly jumping to
	 * the next booting stage.
	 *
	 * We use a lottery mechanism to select coldboot HART among
	 * HARTs which satisfy above condition.
	 */

	if (sbi_platform_cold_boot_allowed(plat, hartid)) {
		if (next_mode_supported &&
		    atomic_xchg(&coldboot_lottery, 1) == 0)
			coldboot = true;
	}

	/*
	 * Do platform specific nascent (very early) initialization so
	 * that platform can initialize platform specific per-HART CSRs
	 * or per-HART devices.
	 */
	if (sbi_platform_nascent_init(plat))
		sbi_hart_hang();

	if (coldboot)
		init_coldboot(scratch, hartid);
	else
		init_warmboot(scratch, hartid);
}

unsigned long sbi_entry_count(u32 hartid)
{
	struct sbi_scratch *scratch;
	unsigned long *entry_count;

	if (!entry_count_offset)
		return 0;

	scratch = sbi_hartid_to_scratch(hartid);
	if (!scratch)
		return 0;

	entry_count = sbi_scratch_offset_ptr(scratch, entry_count_offset);

	return *entry_count;
}

unsigned long sbi_init_count(u32 hartid)
{
	struct sbi_scratch *scratch;
	unsigned long *init_count;

	if (!init_count_offset)
		return 0;

	scratch = sbi_hartid_to_scratch(hartid);
	if (!scratch)
		return 0;

	init_count = sbi_scratch_offset_ptr(scratch, init_count_offset);

	return *init_count;
}

/**
 * Exit OpenSBI library for current HART and stop HART
 *
 * The function expects following:
 * 1. The 'mscratch' CSR is pointing to sbi_scratch of current HART
 * 2. Stack pointer (SP) is setup for current HART
 *
 * @param scratch pointer to sbi_scratch of current HART
 */
void __noreturn sbi_exit(struct sbi_scratch *scratch)
{
	u32 hartid			= current_hartid();
	const struct sbi_platform *plat = sbi_platform_ptr(scratch);

	if (!sbi_hartid_valid(hartid))
		sbi_hart_hang();

	sbi_platform_early_exit(plat);

	sbi_pmu_exit(scratch);

	sbi_timer_exit(scratch);

	sbi_ipi_exit(scratch);

	sbi_irqchip_exit(scratch);

	sbi_platform_final_exit(plat);

	sbi_hsm_exit(scratch);
}
