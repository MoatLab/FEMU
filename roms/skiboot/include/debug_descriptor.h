// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __DEBUG_DESCRIPTOR_H
#define __DEBUG_DESCRIPTOR_H

#define OPAL_BOOT_COMPLETE 0x1
/* Debug descriptor. This structure is pointed to by the word at offset
 * 0x80 in the sapphire binary
 */
struct debug_descriptor {
	u8	eye_catcher[8];	/* "OPALdbug" */
#define DEBUG_DESC_VERSION	1
	__be32	version;
	u8	console_log_levels;	/* high 4 bits in memory,
					 * low 4 bits driver (e.g. uart). */
	u8	state_flags; /* various state flags - OPAL_BOOT_COMPLETE etc */
	__be16	reserved2;
	__be32	reserved[2];

	/* Memory console */
	__be64	memcons_phys;
	__be32	memcons_tce;
	__be32	memcons_obuf_tce;
	__be32	memcons_ibuf_tce;

	/* Traces */
	__be64	trace_mask;
	__be32	num_traces;
#define DEBUG_DESC_MAX_TRACES	256
	__be64	trace_phys[DEBUG_DESC_MAX_TRACES];
	__be32	trace_size[DEBUG_DESC_MAX_TRACES];
	__be32	trace_tce[DEBUG_DESC_MAX_TRACES];
	__be16	trace_pir[DEBUG_DESC_MAX_TRACES];
};
extern struct debug_descriptor debug_descriptor;

static inline bool opal_booting(void)
{
	return !(debug_descriptor.state_flags & OPAL_BOOT_COMPLETE);
}

#endif
