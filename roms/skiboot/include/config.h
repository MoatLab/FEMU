// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __CONFIG_H
#define __CONFIG_H

/* Alignment to which skiboot lays out memory. */
#define PAGE_SIZE	0x10000

#define HAVE_TYPEOF			1
#define HAVE_BUILTIN_TYPES_COMPATIBLE_P	1

/* Keep -Wundef happy by defining whatever isn't on commandline to 0 */
#if defined(HAVE_LITTLE_ENDIAN) && HAVE_LITTLE_ENDIAN
#define HAVE_BIG_ENDIAN 0
#endif
#if defined(HAVE_BIG_ENDIAN) && HAVE_BIG_ENDIAN
#define HAVE_LITTLE_ENDIAN 0
#endif

/* We don't have a byteswap.h, and thus no bswap_64 */
#define HAVE_BYTESWAP_H 0
#define HAVE_BSWAP_64 0

/*
 * Build options.
 */

/* Enable lock debugging */
#define DEBUG_LOCKS		1

/* Enable printing of backtraces when locks not released */
#ifdef DEBUG
#define DEBUG_LOCKS_BACKTRACE  1
#else
//#define DEBUG_LOCKS_BACKTRACE	1
#endif

/* Enable lock dependency checker */
#define DEADLOCK_CHECKER	1

/* Enable OPAL entry point tracing */
//#define OPAL_TRACE_ENTRY	1

/* Enable tracing of event state change */
//#define OPAL_TRACE_EVT_CHG	1

/* Enable various levels of OPAL_console debug */
//#define OPAL_DEBUG_CONSOLE_IO	1
//#define OPAL_DEBUG_CONSOLE_POLL	1

/* Enable this to force all writes to the in-memory console to
 * be mirrored on the mambo console
 */
//#define MAMBO_DEBUG_CONSOLE		1

/* Enable this to hookup SkiBoot log to the DVS console */
#define DVS_CONSOLE		1

/* Enable this to force the dummy console to the kernel.
 * (ie, an OPAL console that injects into skiboot own console)
 * Where possible, leave this undefined and enable it dynamically using
 * the chosen->sapphire,enable-dummy-console in the device tree.
 *
 * Note: This only gets enabled if there is no FSP console. If there
 * is one it always takes over for now. This also cause the LPC UART
 * node to be marked "reserved" so Linux doesn't instanciate a 8250
 * driver for it.
 */
//#define FORCE_DUMMY_CONSOLE 1

/* Enable this to disable setting of the output pending event when
 * sending things on the console. The FSP is very slow to consume
 * and older kernels wait after each character during early boot so
 * things get very slow. Eventually, we may want to create an OPAL
 * API for the kernel to activate or deactivate that functionality
 */
#define DISABLE_CON_PENDING_EVT	1

#endif /* __CONFIG_H */

