// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Small LCD screen on the front of FSP machines
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <skiboot.h>
#include <fsp.h>
#include <lock.h>
#include <opal.h>
#include <device.h>
#include <processor.h>
#include <opal-msg.h>
#include <errorlog.h>

DEFINE_LOG_ENTRY(OPAL_RC_PANEL_WRITE, OPAL_PLATFORM_ERR_EVT, OPAL_OP_PANEL,
		 OPAL_MISC_SUBSYSTEM, OPAL_PREDICTIVE_ERR_GENERAL, OPAL_NA);

/* For OPAL OP_PANEL API we can only have one in flight due to TCEs */
static struct fsp_msg *op_req;
static uint64_t op_async_token;
static struct lock op_lock = LOCK_UNLOCKED;

static void fsp_op_display_fatal(uint32_t w0, uint32_t w1)
{
	static struct fsp_msg op_msg_resp;
	static struct fsp_msg op_msg = {
		.resp = &op_msg_resp,
	};

	fsp_fillmsg(&op_msg, FSP_CMD_DISP_SRC_DIRECT, 3, 1, w0, w1);

	/*
	 * A special way to send a message: it doesn't run pollers.
	 * This means we can call it while in a poller, which we may
	 * well be in when we're terminating (and thus displaying a *fatal*
	 * message on the op-panel).
	 */
	fsp_fatal_msg(&op_msg);
}

void fsp_op_display(enum op_severity sev, enum op_module mod, uint16_t code)
{
	struct fsp_msg *op_msg;
	uint32_t w0;
	uint32_t w1;

	if (!fsp_present())
		return;

	w0 = sev << 16 | mod;

	w1 =  tohex((code >> 12) & 0xf) << 24;
	w1 |= tohex((code >>  8) & 0xf) << 16;
	w1 |= tohex((code >>  4) & 0xf) <<  8;
	w1 |= tohex((code      ) & 0xf);

	if (sev == OP_FATAL) {
		fsp_op_display_fatal(w0, w1);
	} else {
		op_msg = fsp_allocmsg(true);
		if (!op_msg) {
			prerror("Failed to allocate FSP message for PANEL\n");
			return;
		}

		fsp_fillmsg(op_msg, FSP_CMD_DISP_SRC_DIRECT, 3, 1, w0, w1);

		if(fsp_queue_msg(op_msg, fsp_freemsg))
			prerror("Failed to queue FSP message for OP PANEL\n");
	}
}

void op_panel_disable_src_echo(void)
{
	struct fsp_msg op_msg_resp;
	struct fsp_msg op_msg = {
		.resp = &op_msg_resp,
	};

	if (!fsp_present())
		return;

	fsp_fillmsg(&op_msg, FSP_CMD_DIS_SRC_ECHO, 0);
	fsp_sync_msg(&op_msg, false);
}

void op_panel_clear_src(void)
{
	struct fsp_msg op_msg_resp;
	struct fsp_msg op_msg = {
		.resp = &op_msg_resp,
	};

	if (!fsp_present())
		return;

	fsp_fillmsg(&op_msg, FSP_CMD_CLEAR_SRC, 0);
	fsp_sync_msg(&op_msg, false);
}

/* opal_write_oppanel - Write to the physical op panel.
 *
 * Pass in an array of oppanel_line_t structs defining the ASCII characters
 * to display on each line of the oppanel. If there are two lines on the
 * physical panel, and you only want to write to the first line, you only
 * need to pass in one line. If you only want to write to the second line,
 * you need to pass in both lines, and set the line_len of the first line
 * to zero.
 *
 * This command is asynchronous. If OPAL_SUCCESS is returned, then the
 * operation was initiated successfully. Subsequent calls will return
 * OPAL_BUSY until the current operation is complete.
 */
struct op_src {
	uint8_t version;
#define OP_SRC_VERSION	2
	uint8_t	flags;
	uint8_t reserved;
	uint8_t	hex_word_cnt;
	__be16	reserved2;
	__be16	total_size;
	__be32	word2; /* SRC format in low byte */
	__be32	word3;
	__be32	word4;
	__be32	word5;
	__be32	word6;
	__be32	word7;
	__be32	word8;
	__be32	word9;
	uint8_t	ascii[OP_PANEL_NUM_LINES * OP_PANEL_LINE_LEN]; /* Word 11 */
} __packed __align(4);

/* Page align for the sake of TCE mapping */
static struct op_src op_src __align(0x1000);

static void __op_panel_write_complete(struct fsp_msg *msg)
{
	fsp_tce_unmap(PSI_DMA_OP_PANEL_MISC, 0x1000);

	lock(&op_lock);
	op_req = NULL;
	unlock(&op_lock);

	fsp_freemsg(msg);
}

static void op_panel_write_complete(struct fsp_msg *msg)
{
	uint8_t rc = (msg->resp->word1 >> 8) & 0xff;

	if (rc)
		prerror("OPPANEL: Error 0x%02x in display command\n", rc);

	__op_panel_write_complete(msg);

	opal_queue_msg(OPAL_MSG_ASYNC_COMP, NULL, NULL,
			cpu_to_be64(1),
			cpu_to_be64(op_async_token));
}

static int64_t __opal_write_oppanel(oppanel_line_t *lines, uint64_t num_lines,
				    uint64_t async_token)
{
	int64_t rc = OPAL_ASYNC_COMPLETION;
	int len;
	int i;

	if (num_lines < 1 || num_lines > OP_PANEL_NUM_LINES)
		return OPAL_PARAMETER;

	/* Only one in flight */
	lock(&op_lock);
	if (op_req) {
		rc = OPAL_BUSY_EVENT;
		unlock(&op_lock);
		goto bail;
	}

	op_req = fsp_allocmsg(true);
	if (!op_req) {
		rc = OPAL_NO_MEM;
		unlock(&op_lock);
		goto bail;
	}
	unlock(&op_lock);

	op_async_token = async_token;

	memset(&op_src, 0, sizeof(op_src));

	op_src.version = OP_SRC_VERSION;
	op_src.flags = 0;
	op_src.reserved = 0;
	op_src.hex_word_cnt = 1; /* header word only */
	op_src.reserved2 = 0;
	op_src.total_size = cpu_to_be16(sizeof(op_src));
	op_src.word2 = 0; /* should be unneeded */

	for (i = 0; i < num_lines; i++) {
		uint8_t *current_line = op_src.ascii + (i * OP_PANEL_LINE_LEN);

		len = be64_to_cpu(lines[i].line_len);
		if (len < OP_PANEL_LINE_LEN)
			memset(current_line + len, ' ', OP_PANEL_LINE_LEN-len);
		else
			len = OP_PANEL_LINE_LEN;
		memcpy(current_line, (void *) be64_to_cpu(lines[i].line), len);
	}

	for (i = 0; i < sizeof(op_src.ascii); i++) {
		/*
		 * So, there's this interesting thing if you send
		 * HTML/Javascript through the Operator Panel.
		 * You get to inject it into the ASM web ui!
		 * So we filter out anything suspect here,
		 * at least for the time being.
		 *
		 * Allowed characters:
		 *  . / 0-9 : a-z A-Z SPACE
		 */
		if (! ((op_src.ascii[i] >= '.' && op_src.ascii[i] <= ':') ||
		       (op_src.ascii[i] >= 'a' && op_src.ascii[i] <= 'z') ||
		       (op_src.ascii[i] >= 'A' && op_src.ascii[i] <= 'Z') ||
		       op_src.ascii[i] == ' ')) {
			op_src.ascii[i] = '.';
		}
	}

	fsp_tce_map(PSI_DMA_OP_PANEL_MISC, &op_src, 0x1000);

	fsp_fillmsg(op_req, FSP_CMD_DISP_SRC_INDIR, 3, 0,
		    PSI_DMA_OP_PANEL_MISC, sizeof(struct op_src));
	rc = fsp_queue_msg(op_req, op_panel_write_complete);
	if (rc) {
		__op_panel_write_complete(op_req);
		rc = OPAL_INTERNAL_ERROR;
	}
 bail:
	log_simple_error(&e_info(OPAL_RC_PANEL_WRITE),
			"FSP: Error updating Op Panel: %lld\n", rc);
	return rc;
}

static int64_t opal_write_oppanel_async(uint64_t async_token,
					oppanel_line_t *lines,
					uint64_t num_lines)
{
	return __opal_write_oppanel(lines, num_lines, async_token);
}

void fsp_oppanel_init(void)
{
	struct dt_node *oppanel;

	if (!fsp_present())
		return;

	opal_register(OPAL_WRITE_OPPANEL_ASYNC, opal_write_oppanel_async, 3);

	oppanel = dt_new(opal_node, "oppanel");
	dt_add_property_cells(oppanel, "#length", OP_PANEL_LINE_LEN);
	dt_add_property_cells(oppanel, "#lines", OP_PANEL_NUM_LINES);
	dt_add_property_string(oppanel, "compatible", "ibm,opal-oppanel");
}
