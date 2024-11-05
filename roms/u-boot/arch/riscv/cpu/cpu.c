// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2018, Bin Meng <bmeng.cn@gmail.com>
 */

#include <common.h>
#include <cpu.h>
#include <dm.h>
#include <init.h>
#include <log.h>
#include <asm/encoding.h>
#include <dm/uclass-internal.h>
#include <linux/bitops.h>

/*
 * The variables here must be stored in the data section since they are used
 * before the bss section is available.
 */
#ifdef CONFIG_OF_PRIOR_STAGE
phys_addr_t prior_stage_fdt_address __section(".data");
#endif
#ifndef CONFIG_XIP
u32 hart_lottery __section(".data") = 0;

/*
 * The main hart running U-Boot has acquired available_harts_lock until it has
 * finished initialization of global data.
 */
u32 available_harts_lock = 1;
#endif

static inline bool supports_extension(char ext)
{
#ifdef CONFIG_CPU
	struct udevice *dev;
	char desc[32];

	uclass_find_first_device(UCLASS_CPU, &dev);
	if (!dev) {
		debug("unable to find the RISC-V cpu device\n");
		return false;
	}
	if (!cpu_get_desc(dev, desc, sizeof(desc))) {
		/* skip the first 4 characters (rv32|rv64) */
		if (strchr(desc + 4, ext))
			return true;
	}

	return false;
#else  /* !CONFIG_CPU */
#if CONFIG_IS_ENABLED(RISCV_MMODE)
	return csr_read(CSR_MISA) & (1 << (ext - 'a'));
#else  /* !CONFIG_IS_ENABLED(RISCV_MMODE) */
#warning "There is no way to determine the available extensions in S-mode."
#warning "Please convert your board to use the RISC-V CPU driver."
	return false;
#endif /* CONFIG_IS_ENABLED(RISCV_MMODE) */
#endif /* CONFIG_CPU */
}

static int riscv_cpu_probe(void)
{
#ifdef CONFIG_CPU
	int ret;

	/* probe cpus so that RISC-V timer can be bound */
	ret = cpu_probe_all();
	if (ret)
		return log_msg_ret("RISC-V cpus probe failed\n", ret);
#endif

	return 0;
}

/*
 * This is called on secondary harts just after the IPI is init'd. Currently
 * there's nothing to do, since we just need to clear any existing IPIs, and
 * that is handled by the sending of an ipi itself.
 */
#if CONFIG_IS_ENABLED(SMP)
static void dummy_pending_ipi_clear(ulong hart, ulong arg0, ulong arg1)
{
}
#endif

int arch_cpu_init_dm(void)
{
	int ret;

	ret = riscv_cpu_probe();
	if (ret)
		return ret;

	/* Enable FPU */
	if (supports_extension('d') || supports_extension('f')) {
		csr_set(MODE_PREFIX(status), MSTATUS_FS);
		csr_write(CSR_FCSR, 0);
	}

	if (CONFIG_IS_ENABLED(RISCV_MMODE)) {
		/*
		 * Enable perf counters for cycle, time,
		 * and instret counters only
		 */
#ifdef CONFIG_RISCV_PRIV_1_9
		csr_write(CSR_MSCOUNTEREN, GENMASK(2, 0));
		csr_write(CSR_MUCOUNTEREN, GENMASK(2, 0));
#else
		csr_write(CSR_MCOUNTEREN, GENMASK(2, 0));
#endif

		/* Disable paging */
		if (supports_extension('s'))
#ifdef CONFIG_RISCV_PRIV_1_9
			csr_read_clear(CSR_MSTATUS, SR_VM);
#else
			csr_write(CSR_SATP, 0);
#endif
	}

#if CONFIG_IS_ENABLED(SMP)
	ret = riscv_init_ipi();
	if (ret)
		return ret;

	/*
	 * Clear all pending IPIs on secondary harts. We don't do anything on
	 * the boot hart, since we never send an IPI to ourselves, and no
	 * interrupts are enabled
	 */
	ret = smp_call_function((ulong)dummy_pending_ipi_clear, 0, 0, 0);
	if (ret)
		return ret;
#endif

	return 0;
}

int arch_early_init_r(void)
{
	return riscv_cpu_probe();
}

/**
 * harts_early_init() - A callback function called by start.S to configure
 * feature settings of each hart.
 *
 * In a multi-core system, memory access shall be careful here, it shall
 * take care of race conditions.
 */
__weak void harts_early_init(void)
{
}
