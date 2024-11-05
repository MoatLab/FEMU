// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __OP_PANEL_H
#define __OP_PANEL_H

#include <stdint.h>

/* Operator Panel Dimensions */
#define OP_PANEL_NUM_LINES	2
#define OP_PANEL_LINE_LEN	16

/* Severity */
enum op_severity {
	OP_LOG		= 0x4342,	/* 'CB' - Progress info */
	OP_WARN		= 0x4542,	/* 'EB' - Information condition */
	OP_ERROR	= 0x4442,	/* 'DB' - Non fatal error */
	OP_FATAL	= 0x4242,	/* 'BB' - Fatal error */
};

/* Module */
enum op_module {
	OP_MOD_CORE	= 0x3030,	/* '00' - Anything really */
	OP_MOD_INIT	= 0x3031,	/* '01' - init */
	OP_MOD_LOCK	= 0x3032,	/* '02' - spinlocks */
	OP_MOD_FSP	= 0x3033,	/* '03' - FSP */
	OP_MOD_FSPCON	= 0x3034,	/* '04' - FSPCON */
	OP_MOD_CHIPTOD	= 0x3035,	/* '05' - ChipTOP */
	OP_MOD_CPU	= 0x3036,	/* '06' - CPU bringup */
	OP_MOD_MEM	= 0x3037,	/* '07' - Memory */
};

/* Common codes:
 *
 * 'BA010001' : Failed to load a kernel
 * 'BA010002' : Failed to create a device-tree
 * 'BA020000' : Locking already owned lock
 * 'BA020001' : Unlocking unlocked lock
 * 'BA020002' : Unlocking not-owned lock
 * 'BA006666' : Abort
 * 'BA050000' : Failed ChipTOD init/sync
 * 'BA050001' : Failed to find a CPU on the master chip
 * 'BA050002' : Master chip sync failed
 * 'EA05xxx2' : Slave sync failed (xxx = PIR)
 * 'BA070000' : Cannot find MS VPD or invalid
 * 'BA070001' : MS VPD wrong size
 * 'BA070002' : MS VPD doesn't have an MSAC
 * 'BA070003' : MS VPD doesn't have a total config
 */

extern void op_display(enum op_severity, enum op_module, uint16_t code);
extern void op_display_lpc(enum op_severity s, enum op_module m, uint16_t c);

extern void op_panel_disable_src_echo(void);
extern void op_panel_clear_src(void);
extern void fsp_oppanel_init(void);

#endif /* __OP_PANEL_H */
