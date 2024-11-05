// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __STACKFRAME_H
#define __STACKFRAME_H

#include <mem-map.h>

#define STACK_ENTRY_OPAL_API	0	/* OPAL call */
#define STACK_ENTRY_HMI		0x0e60	/* Hypervisor maintenance */
#define STACK_ENTRY_RESET	0x0100	/* System reset */
#define STACK_ENTRY_SOFTPATCH	0x1500	/* Soft patch (denorm emulation) */

#if HAVE_BIG_ENDIAN
#define STACK_TOC_OFFSET	40
#else
#define STACK_TOC_OFFSET	24
#endif

/* Safety/ABI gap at top of stack */
#define STACK_TOP_GAP		0x100

/* Remaining stack space (gap included) */
#define NORMAL_STACK_SIZE	(STACK_SIZE/2)

/* Emergency (re-entry) stack size */
#define EMERGENCY_STACK_SIZE	(STACK_SIZE/2)

/* Offset to get to normal CPU stacks */
#define CPU_STACKS_OFFSET	(CPU_STACKS_BASE + \
				 NORMAL_STACK_SIZE - STACK_TOP_GAP)

/* Offset to get to emergency CPU stacks */
#define EMERGENCY_CPU_STACKS_OFFSET	(CPU_STACKS_BASE + NORMAL_STACK_SIZE + \
				 EMERGENCY_STACK_SIZE - STACK_TOP_GAP)

/* Gap below the stack. If our stack checker sees the stack below that
 * gap, it will flag a stack overflow
 */
#define STACK_SAFETY_GAP	512

/* Warning threshold, if stack goes below that on mcount, print a
 * warning.
 */
#define STACK_WARNING_GAP	2048

#define STACK_CHECK_GUARD_BASE	0xdeadf00dbaad300
#define STACK_INT_MAGIC		0xb1ab1af00ba1234ULL

#ifndef __ASSEMBLY__

#include <stdint.h>
#include <opal-api.h>

/* This is the struct used to save GPRs etc.. on OPAL entry
 * and from some exceptions. It is not always entirely populated
 * depending on the entry type
 */
struct stack_frame {
	/* Standard 112-byte stack frame header (the minimum size required,
	 * using an 8-doubleword param save area). The callee (in C) may use
	 * lrsave; we declare these here so we don't get our own save area
	 * overwritten */
	uint64_t	backchain;
	uint64_t	crsave;
	uint64_t	lrsave;
	uint64_t	compiler_dw;
	uint64_t	linker_dw;
	uint64_t	tocsave;
	uint64_t	paramsave[8];

	/* Space for stack-local vars used by asm. At present we only use
	 * one doubleword. */
	uint64_t	locals[1];

	/* Interrupt entry magic value */
	uint64_t	magic;

	/* Entry type */
	uint64_t	type;

	/* GPR save area
	 *
	 * We don't necessarily save everything in here
	 */
	uint64_t	gpr[32];

	/* Other SPR saved
	 *
	 * Only for some exceptions.
	 */
	uint32_t	cr;
	uint32_t	xer;
	uint32_t	dsisr;
	uint64_t	ctr;
	uint64_t	lr;
	uint64_t	pc;
	uint64_t	msr;
	uint64_t	cfar;
	uint64_t	srr0;
	uint64_t	srr1;
	uint64_t	hsrr0;
	uint64_t	hsrr1;
	uint64_t	dar;
} __attribute__((aligned(16)));

/* Backtrace entry */
struct bt_entry {
	unsigned long	sp;
	unsigned long	pc;
	unsigned long	exception_type;
	unsigned long	exception_pc;
};

/* Backtrace metadata */
struct bt_metadata {
	unsigned int	ents;
	unsigned long	token;
	unsigned long	r1_caller;
	unsigned long	pir;
};

/* Boot stack top */
extern void *boot_stack_top;

/* Create a backtrace */
void backtrace_create(struct bt_entry *entries, unsigned int max_ents,
		      struct bt_metadata *metadata);

/* Convert a backtrace to ASCII */
extern void backtrace_print(struct bt_entry *entries,
			    struct bt_metadata *metadata, char *out_buf,
			    unsigned int *len, bool symbols);

/* For use by debug code, create and print backtrace, uses a static buffer */
extern void backtrace(void);

/* For use by exception debug code, supply an r1 */
extern void backtrace_r1(uint64_t r1);

#ifdef STACK_CHECK_ENABLED
extern void check_stacks(void);
#else
static inline void check_stacks(void) { }
#endif

#endif /* __ASSEMBLY__ */
#endif /* __STACKFRAME_H */

