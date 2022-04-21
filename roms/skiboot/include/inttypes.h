// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* This file exists because a bunch of files are built as part of
 * unit tests as well as skiboot and inttypes.h is part of libc rather
 * than gcc, so to get the magic to work when we don't have libc sitting
 * around, we get to rewrite inttypes.h.
 *
 * Copyright 2015 IBM Corp.
 */

#ifndef __SKIBOOT_INTTYPES_H
#define __SKIBOOT_INTTYPES_H

#include <stdint.h>

#ifndef __WORDSIZE
/* If we don't have __WORDSIZE it means we're *certainly* building skiboot
 * which will *ALWAYS* have a word size of 32bits.
 * (unless someone goes and ports skiboot to something that isn't powerpc)
 */
#define __WORDSIZE 32
#endif

#if __WORDSIZE == 64
#define PRIu64 "lu"
#define PRIx64 "lx"
#else
#define PRIu64 "llu"
#define PRIx64 "llx"
#endif

#endif
