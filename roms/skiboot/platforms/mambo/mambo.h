// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2016 IBM Corp. */

#ifndef __MAMBO_H__
#define __MAMBO_H__

static inline unsigned long callthru0(int command)
{
	register uint64_t c asm("r3") = command;
	asm volatile (".long 0x000eaeb0":"=r" (c):"r"(c));
	return c;
}

static inline unsigned long callthru2(int command, unsigned long arg1,
				      unsigned long arg2)
{
	register unsigned long c asm("r3") = command;
	register unsigned long a1 asm("r4") = arg1;
	register unsigned long a2 asm("r5") = arg2;
	asm volatile (".long 0x000eaeb0":"=r" (c):"r"(c), "r"(a1), "r"(a2));
	return c;
}

static inline unsigned long callthru3(int command, unsigned long arg1,
				      unsigned long arg2, unsigned long arg3)
{
	register unsigned long c asm("r3") = command;
	register unsigned long a1 asm("r4") = arg1;
	register unsigned long a2 asm("r5") = arg2;
	register unsigned long a3 asm("r6") = arg3;
	asm volatile (".long 0x000eaeb0":"=r" (c):"r"(c), "r"(a1), "r"(a2),
		      "r"(a3));
	return c;
}

/* Mambo callthru commands */
#define SIM_WRITE_CONSOLE_CODE	0
#define SIM_EXIT_CODE		31
#define SIM_READ_CONSOLE_CODE	60
#define SIM_GET_TIME_CODE	70
#define SIM_CALL_TCL		86
#define SIM_BOGUS_DISK_READ	116
#define SIM_BOGUS_DISK_WRITE	117
#define SIM_BOGUS_DISK_INFO	118

#endif /* __MAMBO_H__ */
