// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Deal with exceptions when in OPAL.
 *
 * Copyright 2013-2014 IBM Corp.
 */

#include <skiboot.h>
#include <stack.h>
#include <opal.h>
#include <processor.h>
#include <cpu.h>
#include <ras.h>

#define REG		"%016llx"
#define REG32		"%08x"
#define REGS_PER_LINE	4

static void dump_regs(struct stack_frame *stack)
{
	unsigned int i;

	prerror("CFAR : "REG" MSR  : "REG"\n", stack->cfar, stack->msr);
	prerror("SRR0 : "REG" SRR1 : "REG"\n", stack->srr0, stack->srr1);
	prerror("HSRR0: "REG" HSRR1: "REG"\n", stack->hsrr0, stack->hsrr1);
	prerror("DSISR: "REG32"         DAR  : "REG"\n", stack->dsisr, stack->dar);
	prerror("LR   : "REG" CTR  : "REG"\n", stack->lr, stack->ctr);
	prerror("CR   : "REG32"         XER  : "REG32"\n", stack->cr, stack->xer);
	for (i = 0;  i < 16;  i++)
		prerror("GPR%02d: "REG" GPR%02d: "REG"\n",
		       i, stack->gpr[i], i + 16, stack->gpr[i + 16]);
}

#define EXCEPTION_MAX_STR 320

static void handle_mce(struct stack_frame *stack, uint64_t nip, uint64_t msr, bool *fatal)
{
	uint64_t mce_flags, mce_addr;
	const char *mce_err;
	const char *mce_fix = NULL;
	char buf[EXCEPTION_MAX_STR];
	size_t l;

	decode_mce(stack->srr0, stack->srr1, stack->dsisr, stack->dar,
			&mce_flags, &mce_err, &mce_addr);

	/* Try to recover. */
	if (mce_flags & MCE_ERAT_ERROR) {
		/* Real-mode still uses ERAT, flush transient bitflips */
		flush_erat();
		mce_fix = "ERAT flush";

	} else {
		*fatal = true;
	}

	prerror("***********************************************\n");
	l = 0;
	l += snprintf(buf + l, EXCEPTION_MAX_STR - l,
		"%s MCE at "REG"   ", *fatal ? "Fatal" : "Non-fatal", nip);
	l += snprintf_symbol(buf + l, EXCEPTION_MAX_STR - l, nip);
	l += snprintf(buf + l, EXCEPTION_MAX_STR - l, "  MSR "REG, msr);
	prerror("%s\n", buf);

	l = 0;
	l += snprintf(buf + l, EXCEPTION_MAX_STR - l,
		"Cause: %s", mce_err);
	prerror("%s\n", buf);
	if (mce_flags & MCE_INVOLVED_EA) {
		l = 0;
		l += snprintf(buf + l, EXCEPTION_MAX_STR - l,
			"Effective address: 0x%016llx", mce_addr);
		prerror("%s\n", buf);
	}

	if (!*fatal) {
		l = 0;
		l += snprintf(buf + l, EXCEPTION_MAX_STR - l,
			"Attempting recovery: %s", mce_fix);
		prerror("%s\n", buf);
	}
}

void exception_entry(struct stack_frame *stack)
{
	bool fatal = false;
	bool hv;
	uint64_t nip;
	uint64_t msr;
	char buf[EXCEPTION_MAX_STR];
	size_t l;

	switch (stack->type) {
	case 0x500:
	case 0x980:
	case 0xe00:
	case 0xe20:
	case 0xe40:
	case 0xe60:
	case 0xe80:
	case 0xea0:
	case 0xf80:
		hv = true;
		break;
	default:
		hv = false;
		break;
	}

	if (hv) {
		nip = stack->hsrr0;
		msr = stack->hsrr1;
	} else {
		nip = stack->srr0;
		msr = stack->srr1;
	}
	stack->msr = msr;
	stack->pc = nip;

	if (!(msr & MSR_RI))
		fatal = true;

	l = 0;
	switch (stack->type) {
	case 0x100:
		prerror("***********************************************\n");
		if (fatal) {
			l += snprintf(buf + l, EXCEPTION_MAX_STR - l,
				"Fatal System Reset at "REG"   ", nip);
		} else {
			l += snprintf(buf + l, EXCEPTION_MAX_STR - l,
				"System Reset at "REG"   ", nip);
		}
		break;

	case 0x200:
		handle_mce(stack, nip, msr, &fatal);
		goto no_symbol;

	case 0x700: {
		struct trap_table_entry *tte;

		fatal = true;
		prerror("***********************************************\n");
		for (tte = __trap_table_start; tte < __trap_table_end; tte++) {
			if (tte->address == nip) {
				prerror("< %s >\n", tte->message);
				prerror("    .\n");
				prerror("     .\n");
				prerror("      .\n");
				prerror("        OO__)\n");
				prerror("       <\"__/\n");
				prerror("        ^ ^\n");
				break;
			}
		}
		l += snprintf(buf + l, EXCEPTION_MAX_STR - l,
			"Fatal TRAP at "REG"   ", nip);
		l += snprintf_symbol(buf + l, EXCEPTION_MAX_STR - l, nip);
		l += snprintf(buf + l, EXCEPTION_MAX_STR - l, "  MSR "REG, msr);
		prerror("%s\n", buf);
		dump_regs(stack);
		backtrace_r1((uint64_t)stack);
		if (platform.terminate)
			platform.terminate(buf);
		for (;;) ;
		break; }

	default:
		fatal = true;
		prerror("***********************************************\n");
		l += snprintf(buf + l, EXCEPTION_MAX_STR - l,
			"Fatal Exception 0x%llx at "REG"  ", stack->type, nip);
		break;
	}
	l += snprintf_symbol(buf + l, EXCEPTION_MAX_STR - l, nip);
	l += snprintf(buf + l, EXCEPTION_MAX_STR - l, "  MSR "REG, msr);
	prerror("%s\n", buf);
no_symbol:
	dump_regs(stack);
	backtrace_r1((uint64_t)stack);
	if (fatal) {
		if (platform.terminate)
			platform.terminate(buf);
		for (;;) ;
	}

	if (hv) {
		/* Set up for SRR return */
		stack->srr0 = nip;
		stack->srr1 = msr;
	}
}

void exception_entry_pm_sreset(void)
{
	char buf[EXCEPTION_MAX_STR];
	size_t l;

	prerror("***********************************************\n");
	l = 0;
	l += snprintf(buf + l, EXCEPTION_MAX_STR - l,
		"System Reset in sleep");
	prerror("%s\n", buf);
	backtrace();
}

void __noreturn exception_entry_pm_mce(void)
{
	char buf[EXCEPTION_MAX_STR];
	size_t l;

	prerror("***********************************************\n");
	l = 0;
	l += snprintf(buf + l, EXCEPTION_MAX_STR - l,
		"Fatal MCE in sleep");
	prerror("%s\n", buf);
	prerror("SRR0 : "REG" SRR1 : "REG"\n",
			(uint64_t)mfspr(SPR_SRR0), (uint64_t)mfspr(SPR_SRR1));
	prerror("DSISR: "REG32"         DAR  : "REG"\n",
			(uint32_t)mfspr(SPR_DSISR), (uint64_t)mfspr(SPR_DAR));
	abort();
}

static int64_t opal_register_exc_handler(uint64_t opal_exception __unused,
					 uint64_t handler_address __unused,
					 uint64_t glue_cache_line __unused)
{
	/* This interface is deprecated */
	return OPAL_UNSUPPORTED;
}
opal_call(OPAL_REGISTER_OPAL_EXCEPTION_HANDLER, opal_register_exc_handler, 3);

