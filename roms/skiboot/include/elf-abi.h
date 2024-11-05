// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2017 IBM Corp. */

#ifndef __ELF_ABI_H
#define __ELF_ABI_H

#ifndef __ASSEMBLY__

#if defined (_CALL_ELF) && _CALL_ELF == 2
#define ELF_ABI_v2
#else
#define ELF_ABI_v1
#endif

/* From linux/arch/powerpc/include/asm/code-patching.h */
#define OP_RT_RA_MASK   0xffff0000UL
#define LIS_R2          0x3c020000UL
#define ADDIS_R2_R12    0x3c4c0000UL
#define ADDI_R2_R2      0x38420000UL

static inline uint64_t function_entry_address(void *func)
{
#ifdef ELF_ABI_v2
	u32 *insn = func;
	/*
	 * A PPC64 ABIv2 function may have a local and a global entry
	 * point. We use the local entry point for branch tables called
	 * from asm, only a single TOC is used, so identify and step over
	 * the global entry point sequence.
	 *
	 * The global entry point sequence is always of the form:
	 *
	 * addis r2,r12,XXXX
	 * addi  r2,r2,XXXX
	 *
	 * A linker optimisation may convert the addis to lis:
	 *
	 * lis   r2,XXXX
	 * addi  r2,r2,XXXX
	 */
	if ((((*insn & OP_RT_RA_MASK) == ADDIS_R2_R12) ||
	     ((*insn & OP_RT_RA_MASK) == LIS_R2)) &&
	    ((*(insn+1) & OP_RT_RA_MASK) == ADDI_R2_R2))
		return (uint64_t)(insn + 2);
	else
		return (uint64_t)func;
#else
	return *(uint64_t *)func;
#endif
}

#endif /* __ASSEMBLY__ */

#endif /* __COMPILER_H */
