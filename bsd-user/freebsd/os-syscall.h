/*
 * Copyright (c) 2023 Warner Losh <imp@bsdimp.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * OS-Specific portion of syscall_defs.h
 */

#include "syscall_nr.h"

/*
 * FreeBSD uses a 64bits time_t except on i386 so we have to add a special case
 * here.
 */
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
typedef int32_t target_time_t;
#else
typedef int64_t target_time_t;
#endif

typedef abi_long target_suseconds_t;
