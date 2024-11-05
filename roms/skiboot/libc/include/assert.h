/******************************************************************************
 * Copyright (c) 2004, 2008, 2012 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#ifndef _ASSERT_H
#define _ASSERT_H

struct trap_table_entry {
	unsigned long address;
	const char *message;
};

extern struct trap_table_entry __trap_table_start[];
extern struct trap_table_entry __trap_table_end[];

#define stringify(expr)		stringify_1(expr)
/* Double-indirection required to stringify expansions */
#define stringify_1(expr)	#expr

void __attribute__((noreturn)) assert_fail(const char *msg,
						const char *file,
						unsigned int line,
						const char *function);

/*
 * The 'nop' gets patched to 'trap' after skiboot takes over the exception
 * vectors, then patched to 'nop' before booting the OS (see patch_traps).
 * This makes assert fall through to assert_fail when we can't use the 0x700
 * interrupt.
 */
#define assert(cond)							\
do {									\
	/* evaluate cond exactly once */				\
	const unsigned long __cond = (unsigned long)(cond);		\
	asm volatile(							\
		"	cmpdi	%0,0"				"\n\t"	\
		"	bne	2f"				"\n\t"	\
		"1:	nop		# assert"		"\n\t"	\
		"2:"						"\n\t"	\
		".section .rodata"				"\n\t"	\
		"3:	.string	\"assert failed at " __FILE__ ":" stringify(__LINE__) "\""	"\n\t" \
		".previous"					"\n\t"	\
		".section .trap_table,\"aw\""			"\n\t"	\
		".llong	1b"					"\n\t"	\
		".llong	3b"					"\n\t"	\
		".previous"					"\n\t"	\
			: : "r"(__cond) : "cr0");			\
	if (!__cond)							\
		assert_fail(stringify(cond), __FILE__, __LINE__, __FUNCTION__); \
} while (0)

#endif
