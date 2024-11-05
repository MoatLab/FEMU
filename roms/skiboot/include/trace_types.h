// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * API for kernel to read trace buffer.
 *
 * Copyright 2013-2019 IBM Corp.
 */

#ifndef __TRACE_TYPES_H
#define __TRACE_TYPES_H

#include <types.h>

#define TRACE_REPEAT	1
#define TRACE_OVERFLOW	2
#define TRACE_OPAL	3	/* OPAL call */
#define TRACE_FSP_MSG	4	/* FSP message sent/received */
#define TRACE_FSP_EVENT	5	/* FSP driver event */
#define TRACE_UART	6	/* UART driver traces */
#define TRACE_I2C	7	/* I2C driver traces */

/* One per cpu, plus one for NMIs */
struct tracebuf {
	/* Size used to get buffer offset */
	__be64 buf_size;
	/* This where the buffer starts. */
	__be64 start;
	/* This is where writer has written to. */
	__be64 end;
	/* This is where the writer wrote to previously. */
	__be64 last;
	/* Maximum possible size of a record. */
	__be32 max_size;

	char buf[/* TBUF_SZ + max_size */];
};

/* Common header for all trace entries. */
struct trace_hdr {
	__be64 timestamp;
	u8 type;
	u8 len_div_8;
	__be16 cpu;
	u8 unused[4];
};

/* Note: all other entries must be at least as large as this! */
struct trace_repeat {
	__be64 timestamp; /* Last repeat happened at this timestamp */
	u8 type; /* == TRACE_REPEAT */
	u8 len_div_8;
	__be16 cpu;
	__be16 prev_len;
	__be16 num; /* Starts at 1, ie. 1 repeat, or two traces. */
	/* Note that the count can be one short, if read races a repeat. */
};

/* Overflow is special */
struct trace_overflow {
	__be64 unused64; /* Timestamp is unused */
	u8 type; /* == TRACE_OVERFLOW */
	u8 len_div_8;
	u8 unused[6]; /* ie. hdr.cpu is indeterminate */
	__be64 bytes_missed;
};

/* All other trace types have a full header */
struct trace_opal {
	struct trace_hdr hdr;
	__be64 token, lr, sp, r3_to_11[9];
};

#define TRACE_FSP_MSG_IN	0
#define TRACE_FSP_MSG_OUT	1

struct trace_fsp_msg {
	struct trace_hdr hdr;
	__be32 word0;
	__be32 word1;
	u8 dlen;
	u8 dir; /* TRACE_FSP_MSG_IN or TRACE_FSP_MSG_OUT */
	u8 data[56]; /* See dlen, but max is 56 bytes. */
};

#define TRACE_FSP_EVT_LINK_DOWN		0
#define TRACE_FSP_EVT_DISR_CHG		1 /* 0:disr */
#define TRACE_FSP_EVT_SOFT_RR		2 /* 0:disr */
#define TRACE_FSP_EVT_RR_COMPL		3
#define TRACE_FSP_EVT_HDES_CHG		4 /* 0:hdes */
#define TRACE_FSP_EVT_POLL_IRQ		5 /* 0:irq? 1:hdir 2:ctl 3:psi_irq */

struct trace_fsp_event {
	struct trace_hdr hdr;
	__be16 event;
	__be16 fsp_state;
	__be32 data[4]; /* event type specific */
};

#define TRACE_UART_CTX_IRQ		0
#define TRACE_UART_CTX_POLL		1
#define TRACE_UART_CTX_READ		2

struct trace_uart {
	struct trace_hdr hdr;
	u8 ctx;
	u8 cnt;
	u8 irq_state;
	u8 unused;
	__be16 in_count;
};

struct trace_i2c {
	struct trace_hdr hdr;
	u16 bus;
	u16 type;
	u16 i2c_addr;
	u16 smbus_reg;
	u16 size;
	s16 rc;
};

union trace {
	struct trace_hdr hdr;
	/* Trace types go here... */
	struct trace_repeat repeat;
	struct trace_overflow overflow;
	struct trace_opal opal;
	struct trace_fsp_msg fsp_msg;
	struct trace_fsp_event fsp_evt;
	struct trace_uart uart;
	struct trace_i2c i2c;
};

#endif /* __TRACE_TYPES_H */
