/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *   Anup Patel <anup.patel@wdc.com>
 */

#include <libfdt.h>
#include <platform_override.h>
#include <sbi/riscv_asm.h>
#include <sbi/sbi_bitops.h>
#include <sbi/sbi_hartmask.h>
#include <sbi/sbi_heap.h>
#include <sbi/sbi_platform.h>
#include <sbi/sbi_string.h>
#include <sbi/sbi_system.h>
#include <sbi/sbi_tlb.h>
#include <sbi_utils/fdt/fdt_domain.h>
#include <sbi_utils/fdt/fdt_fixup.h>
#include <sbi_utils/fdt/fdt_helper.h>
#include <sbi_utils/fdt/fdt_pmu.h>
#include <sbi_utils/irqchip/fdt_irqchip.h>
#include <sbi_utils/irqchip/imsic.h>
#include <sbi_utils/serial/fdt_serial.h>
#include <sbi_utils/timer/fdt_timer.h>
#include <sbi_utils/ipi/fdt_ipi.h>
#include <sbi_utils/reset/fdt_reset.h>
#include <sbi_utils/serial/semihosting.h>

/* List of platform override modules generated at compile time */
extern const struct platform_override *platform_override_modules[];
extern unsigned long platform_override_modules_size;

static const struct platform_override *generic_plat = NULL;
static const struct fdt_match *generic_plat_match = NULL;

static void fw_platform_lookup_special(void *fdt, int root_offset)
{
	const struct platform_override *plat;
	const struct fdt_match *match;
	int pos;

	for (pos = 0; pos < platform_override_modules_size; pos++) {
		plat = platform_override_modules[pos];
		if (!plat->match_table)
			continue;

		match = fdt_match_node(fdt, root_offset, plat->match_table);
		if (!match)
			continue;

		generic_plat = plat;
		generic_plat_match = match;
		break;
	}
}

static u32 fw_platform_calculate_heap_size(u32 hart_count)
{
	u32 heap_size;

	heap_size = SBI_PLATFORM_DEFAULT_HEAP_SIZE(hart_count);

	/* For TLB fifo */
	heap_size += SBI_TLB_INFO_SIZE * (hart_count) * (hart_count);

	return BIT_ALIGN(heap_size, HEAP_BASE_ALIGN);
}

extern struct sbi_platform platform;
static bool platform_has_mlevel_imsic = false;
static u32 generic_hart_index2id[SBI_HARTMASK_MAX_BITS] = { 0 };

static DECLARE_BITMAP(generic_coldboot_harts, SBI_HARTMASK_MAX_BITS);

/*
 * The fw_platform_coldboot_harts_init() function is called by fw_platform_init() 
 * function to initialize the cold boot harts allowed by the generic platform
 * according to the DT property "cold-boot-harts" in "/chosen/opensbi-config" 
 * DT node. If there is no "cold-boot-harts" in DT, all harts will be allowed.
 */
static void fw_platform_coldboot_harts_init(void *fdt)
{
	int chosen_offset, config_offset, cpu_offset, len, err;
	u32 val32;
	const u32 *val;

	bitmap_zero(generic_coldboot_harts, SBI_HARTMASK_MAX_BITS);

	chosen_offset = fdt_path_offset(fdt, "/chosen");
	if (chosen_offset < 0)
		goto default_config;

	config_offset = fdt_node_offset_by_compatible(fdt, chosen_offset, "opensbi,config");
	if (config_offset < 0)
		goto default_config;

	val = fdt_getprop(fdt, config_offset, "cold-boot-harts", &len);
	len = len / sizeof(u32);
	if (val && len) {
		for (int i = 0; i < len; i++) {
			cpu_offset = fdt_node_offset_by_phandle(fdt,
							fdt32_to_cpu(val[i]));
			if (cpu_offset < 0)
				goto default_config;

			err = fdt_parse_hart_id(fdt, cpu_offset, &val32);
			if (err)
				goto default_config;

			if (!fdt_node_is_enabled(fdt, cpu_offset))
				continue;

			for (int i = 0; i < platform.hart_count; i++) {
				if (val32 == generic_hart_index2id[i])
					bitmap_set(generic_coldboot_harts, i, 1);
			}

		}
	}

	return;

default_config:
	bitmap_fill(generic_coldboot_harts, SBI_HARTMASK_MAX_BITS);
	return;
}

/*
 * The fw_platform_init() function is called very early on the boot HART
 * OpenSBI reference firmwares so that platform specific code get chance
 * to update "platform" instance before it is used.
 *
 * The arguments passed to fw_platform_init() function are boot time state
 * of A0 to A4 register. The "arg0" will be boot HART id and "arg1" will
 * be address of FDT passed by previous booting stage.
 *
 * The return value of fw_platform_init() function is the FDT location. If
 * FDT is unchanged (or FDT is modified in-place) then fw_platform_init()
 * can always return the original FDT location (i.e. 'arg1') unmodified.
 */
unsigned long fw_platform_init(unsigned long arg0, unsigned long arg1,
				unsigned long arg2, unsigned long arg3,
				unsigned long arg4)
{
	const char *model;
	void *fdt = (void *)arg1;
	u32 hartid, hart_count = 0;
	int rc, root_offset, cpus_offset, cpu_offset, len;

	root_offset = fdt_path_offset(fdt, "/");
	if (root_offset < 0)
		goto fail;

	fw_platform_lookup_special(fdt, root_offset);

	if (generic_plat && generic_plat->fw_init)
		generic_plat->fw_init(fdt, generic_plat_match);

	model = fdt_getprop(fdt, root_offset, "model", &len);
	if (model)
		sbi_strncpy(platform.name, model, sizeof(platform.name) - 1);

	if (generic_plat && generic_plat->features)
		platform.features = generic_plat->features(generic_plat_match);

	cpus_offset = fdt_path_offset(fdt, "/cpus");
	if (cpus_offset < 0)
		goto fail;

	fdt_for_each_subnode(cpu_offset, fdt, cpus_offset) {
		rc = fdt_parse_hart_id(fdt, cpu_offset, &hartid);
		if (rc)
			continue;

		if (SBI_HARTMASK_MAX_BITS <= hartid)
			continue;

		if (!fdt_node_is_enabled(fdt, cpu_offset))
			continue;

		generic_hart_index2id[hart_count++] = hartid;
	}

	platform.hart_count = hart_count;
	platform.heap_size = fw_platform_calculate_heap_size(hart_count);
	platform_has_mlevel_imsic = fdt_check_imsic_mlevel(fdt);

	fw_platform_coldboot_harts_init(fdt);

	/* Return original FDT pointer */
	return arg1;

fail:
	while (1)
		wfi();
}

static bool generic_cold_boot_allowed(u32 hartid)
{
	if (generic_plat && generic_plat->cold_boot_allowed)
		return generic_plat->cold_boot_allowed(
						hartid, generic_plat_match);

	for (int i = 0; i < platform.hart_count; i++) {
		if (hartid == generic_hart_index2id[i])
			return bitmap_test(generic_coldboot_harts, i);
	}

	return false;
}

static int generic_nascent_init(void)
{
	if (platform_has_mlevel_imsic)
		imsic_local_irqchip_init();
	return 0;
}

static int generic_early_init(bool cold_boot)
{
	if (cold_boot)
		fdt_reset_init();

	if (!generic_plat || !generic_plat->early_init)
		return 0;

	return generic_plat->early_init(cold_boot, generic_plat_match);
}

static int generic_final_init(bool cold_boot)
{
	void *fdt;
	int rc;

	if (generic_plat && generic_plat->final_init) {
		rc = generic_plat->final_init(cold_boot, generic_plat_match);
		if (rc)
			return rc;
	}

	if (!cold_boot)
		return 0;

	fdt = fdt_get_address();

	fdt_cpu_fixup(fdt);
	fdt_fixups(fdt);
	fdt_domain_fixup(fdt);

	if (generic_plat && generic_plat->fdt_fixup) {
		rc = generic_plat->fdt_fixup(fdt, generic_plat_match);
		if (rc)
			return rc;
	}

	return 0;
}

static bool generic_vendor_ext_check(void)
{
	return (generic_plat && generic_plat->vendor_ext_provider) ?
		true : false;
}

static int generic_vendor_ext_provider(long funcid,
				       struct sbi_trap_regs *regs,
				       struct sbi_ecall_return *out)
{
	return generic_plat->vendor_ext_provider(funcid, regs, out,
						 generic_plat_match);
}

static void generic_early_exit(void)
{
	if (generic_plat && generic_plat->early_exit)
		generic_plat->early_exit(generic_plat_match);
}

static void generic_final_exit(void)
{
	if (generic_plat && generic_plat->final_exit)
		generic_plat->final_exit(generic_plat_match);
}

static int generic_extensions_init(struct sbi_hart_features *hfeatures)
{
	int rc;

	/* Parse the ISA string from FDT and enable the listed extensions */
	rc = fdt_parse_isa_extensions(fdt_get_address(), current_hartid(),
				      hfeatures->extensions);

	if (rc)
		return rc;

	if (generic_plat && generic_plat->extensions_init)
		return generic_plat->extensions_init(generic_plat_match,
						     hfeatures);

	return 0;
}

static int generic_domains_init(void)
{
	void *fdt = fdt_get_address();
	int offset, ret;

	ret = fdt_domains_populate(fdt);
	if (ret < 0)
		return ret;

	offset = fdt_path_offset(fdt, "/chosen");

	if (offset >= 0) {
		offset = fdt_node_offset_by_compatible(fdt, offset,
						       "opensbi,config");
		if (offset >= 0 &&
		    fdt_get_property(fdt, offset, "system-suspend-test", NULL))
			sbi_system_suspend_test_enable();
	}

	return 0;
}

static u64 generic_tlbr_flush_limit(void)
{
	if (generic_plat && generic_plat->tlbr_flush_limit)
		return generic_plat->tlbr_flush_limit(generic_plat_match);
	return SBI_PLATFORM_TLB_RANGE_FLUSH_LIMIT_DEFAULT;
}

static u32 generic_tlb_num_entries(void)
{
	if (generic_plat && generic_plat->tlb_num_entries)
		return generic_plat->tlb_num_entries(generic_plat_match);
	return sbi_scratch_last_hartindex() + 1;
}

static int generic_pmu_init(void)
{
	int rc;

	if (generic_plat && generic_plat->pmu_init) {
		rc = generic_plat->pmu_init(generic_plat_match);
		if (rc)
			return rc;
	}

	rc = fdt_pmu_setup(fdt_get_address());
	if (rc && rc != SBI_ENOENT)
		return rc;

	return 0;
}

static uint64_t generic_pmu_xlate_to_mhpmevent(uint32_t event_idx,
					       uint64_t data)
{
	uint64_t evt_val = 0;

	/* data is valid only for raw events and is equal to event selector */
	if (event_idx == SBI_PMU_EVENT_RAW_IDX)
		evt_val = data;
	else {
		/**
		 * Generic platform follows the SBI specification recommendation
		 * i.e. zero extended event_idx is used as mhpmevent value for
		 * hardware general/cache events if platform does't define one.
		 */
		evt_val = fdt_pmu_get_select_value(event_idx);
		if (!evt_val)
			evt_val = (uint64_t)event_idx;
	}

	return evt_val;
}

static int generic_console_init(void)
{
	if (semihosting_enabled())
		return semihosting_init();
	else
		return fdt_serial_init();
}

const struct sbi_platform_operations platform_ops = {
	.cold_boot_allowed	= generic_cold_boot_allowed,
	.nascent_init		= generic_nascent_init,
	.early_init		= generic_early_init,
	.final_init		= generic_final_init,
	.early_exit		= generic_early_exit,
	.final_exit		= generic_final_exit,
	.extensions_init	= generic_extensions_init,
	.domains_init		= generic_domains_init,
	.console_init		= generic_console_init,
	.irqchip_init		= fdt_irqchip_init,
	.irqchip_exit		= fdt_irqchip_exit,
	.ipi_init		= fdt_ipi_init,
	.ipi_exit		= fdt_ipi_exit,
	.pmu_init		= generic_pmu_init,
	.pmu_xlate_to_mhpmevent = generic_pmu_xlate_to_mhpmevent,
	.get_tlbr_flush_limit	= generic_tlbr_flush_limit,
	.get_tlb_num_entries	= generic_tlb_num_entries,
	.timer_init		= fdt_timer_init,
	.timer_exit		= fdt_timer_exit,
	.vendor_ext_check	= generic_vendor_ext_check,
	.vendor_ext_provider	= generic_vendor_ext_provider,
};

struct sbi_platform platform = {
	.opensbi_version	= OPENSBI_VERSION,
	.platform_version	=
		SBI_PLATFORM_VERSION(CONFIG_PLATFORM_GENERIC_MAJOR_VER,
				     CONFIG_PLATFORM_GENERIC_MINOR_VER),
	.name			= CONFIG_PLATFORM_GENERIC_NAME,
	.features		= SBI_PLATFORM_DEFAULT_FEATURES,
	.hart_count		= SBI_HARTMASK_MAX_BITS,
	.hart_index2id		= generic_hart_index2id,
	.hart_stack_size	= SBI_PLATFORM_DEFAULT_HART_STACK_SIZE,
	.heap_size		= SBI_PLATFORM_DEFAULT_HEAP_SIZE(0),
	.platform_ops_addr	= (unsigned long)&platform_ops
};
