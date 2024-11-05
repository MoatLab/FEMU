// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2017 IBM Corp. */

#ifndef __CMPXCHG_H
#define __CMPXCHG_H

#ifndef __TEST__
/*
 * Bare cmpxchg, no barriers.
 */
static inline uint32_t __cmpxchg32(uint32_t *mem, uint32_t old, uint32_t new)
{
	uint32_t prev;

	asm volatile(
		"# __cmpxchg32		\n"
		"1:	lwarx	%0,0,%2	\n"
		"	cmpw	%0,%3	\n"
		"	bne-	2f	\n"
		"	stwcx.	%4,0,%2	\n"
		"	bne-	1b	\n"
		"2:			\n"

		: "=&r"(prev), "+m"(*mem)
		: "r"(mem), "r"(old), "r"(new)
		: "cr0");

	return prev;
}

static inline uint64_t __cmpxchg64(uint64_t *mem, uint64_t old, uint64_t new)
{
	uint64_t prev;

	asm volatile(
		"# __cmpxchg64		\n"
		"1:	ldarx	%0,0,%2	\n"
		"	cmpd	%0,%3	\n"
		"	bne-	2f	\n"
		"	stdcx.	%4,0,%2	\n"
		"	bne-	1b	\n"
		"2:			\n"

		: "=&r"(prev), "+m"(*mem)
		: "r"(mem), "r"(old), "r"(new)
		: "cr0");

	return prev;
}

static inline uint32_t cmpxchg32(uint32_t *mem, uint32_t old, uint32_t new)
{
	uint32_t prev;

	sync();
	prev = __cmpxchg32(mem, old,new);
	sync();

	return prev;
}
#endif /* __TEST_ */

#endif /* __CMPXCHG_H */


