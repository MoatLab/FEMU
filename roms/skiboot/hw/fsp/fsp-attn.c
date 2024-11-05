// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * FSP ATTentioN support
 *
 * FSP can grab a bunch of things on host firmware dying,
 * let's set that up.
 *
 * Copyright 2013-2019 IBM Corp.
*/
#include <fsp.h>
#include <skiboot.h>
#include <fsp-elog.h>
#include <fsp-attn.h>
#include <hdata/spira.h>
#include <stack.h>
#include <processor.h>
#include <opal-dump.h>

#define TI_CMD_VALID	0x1	/* Command valid */
#define TI_CMD		0xA1	/* Terminate Immediate command */
#define TI_DATA_LEN	0x0400	/* Data length */
/* Controls dump actions
 *	- Non-destructive hardware dump (bit 0)
 *	- memory dump (bit 1)
 *	- Destructive hardware dump (bit 2)
 */
#define TI_DMP_CTL	0x6
/* Dump type
 * 0 - Abbreviated hardware dump
 * 1 - Complete hardware dump
 * 2 - No hardware dump
 */
#define TI_DUMP_TYPE	0x1
#define TI_FORMAT	0x02	/* SRC format */
#define TI_SRC_FLAGS	0x0	/* SRC flags */
#define TI_ASCII_WORDS	0x0	/* Number of ASCII words */

/* HEX words: Number of hex words of data added, up to 8 total
 * this value is one more.
 */
#define TI_HEX_WORDS	0x02
/* SRC length : 8 byte header, 8 hex words of data and
 * 32 byte ASCII SRC
 */
#define TI_SRC_LEN	0x48

static struct ti_attn *ti_attn;

/* Initialises SP attention area with default values */
static void init_sp_attn_area(void)
{
	/* Already done */
	if (ti_attn)
		return;

	/* We are just enabling attention area 1 */
	ti_attn = (struct ti_attn *)&cpu_ctl_sp_attn_area1;

	/* Attention component checks Attn area 2  first, if its NULL
	 * it will check for Attn area 1.
	 */
	memset(&cpu_ctl_sp_attn_area1, 0, sizeof(struct sp_attn_area));
	memset(&cpu_ctl_sp_attn_area2, 0, sizeof(struct sp_attn_area));

	ti_attn->cmd_valid = TI_CMD_VALID;
	ti_attn->attn_cmd = TI_CMD;
	ti_attn->data_len = CPU_TO_BE16(TI_DATA_LEN);
	/* Dump control byte not used as of now */
	ti_attn->dump_ctrl =TI_DMP_CTL;
	ti_attn->dump_type = CPU_TO_BE16(TI_DUMP_TYPE);

	/* SRC format */
	ti_attn->src_fmt = TI_FORMAT;
	/* SRC flags */
	ti_attn->src_flags = TI_SRC_FLAGS;
	/* #ASCII words */
	ti_attn->ascii_cnt = TI_ASCII_WORDS;
	/* #HEX words */
	ti_attn->hex_cnt = TI_HEX_WORDS;
	ti_attn->src_len = CPU_TO_BE16(TI_SRC_LEN);
	snprintf(ti_attn->src, SRC_LEN, "%X", generate_src_from_comp(OPAL_RC_ATTN));
}

/* Updates src in sp attention area
 */
static void update_sp_attn_area(const char *msg)
{
#define STACK_BUF_ENTRIES	20
	struct bt_entry bt_buf[STACK_BUF_ENTRIES];
	struct bt_metadata metadata;
	unsigned int len;

	if (!fsp_present())
		return;

	/* This can be called early */
	if (!ti_attn)
		init_sp_attn_area();

	ti_attn->src_word[0] =
		cpu_to_be32((uint32_t)((uint64_t)__builtin_return_address(0) & 0xffffffff));

	snprintf(ti_attn->msg.version, VERSION_LEN, "%s", version);
	backtrace_create(bt_buf, STACK_BUF_ENTRIES, &metadata);
	metadata.token = OPAL_LAST + 1;
	len = BT_FRAME_LEN;
	backtrace_print(bt_buf, &metadata, ti_attn->msg.bt_buf, &len, false);
	snprintf(ti_attn->msg.file_info, FILE_INFO_LEN, "%s", msg);

	ti_attn->msg_len = cpu_to_be32(VERSION_LEN + BT_FRAME_LEN +
                                   strlen(ti_attn->msg.file_info));
}

void __attribute__((noreturn)) ibm_fsp_terminate(const char *msg)
{
	/* Update SP attention area */
	update_sp_attn_area(msg);

	/* Update op panel op_display */
	op_display(OP_FATAL, OP_MOD_CORE, 0x6666);

	/* Save crashing CPU details */
	opal_mpipl_save_crashing_pir();

	/* XXX FIXME: We should fsp_poll for a while to ensure any pending
	 * console writes have made it out, but until we have decent PSI
	 * link handling we must not do it forever. Polling can prevent the
	 * FSP from bringing the PSI link up and it can get stuck in a
	 * reboot loop.
	 */

	trigger_attn();
	for (;;) ;
}

/* Intialises SP attention area */
void fsp_attn_init(void)
{
	if (!fsp_present())
		return;

	init_sp_attn_area();
}
