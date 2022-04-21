// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2017 IBM Corp. */

#ifndef __SKIBOOT_VALGRIND_H
#define __SKIBOOT_VALGRIND_H

#ifdef USE_VALGRIND
#include <valgrind/valgrind.h>
#include <valgrind/memcheck.h>
#else

#define RUNNING_ON_VALGRIND    0

#define VALGRIND_MAKE_MEM_UNDEFINED(p, len)	\
	do { 					\
		(void)(p);			\
		(void)(len);			\
	} while (0)

#endif

#endif /* __SKIBOOT_VALGRIND_H */
