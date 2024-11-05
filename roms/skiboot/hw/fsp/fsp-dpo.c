// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * FSP DPO (Delayed Power Off) event support
 *
 * Copyright 2013-2017 IBM Corp.
 */

#define pr_fmt(fmt) "FSP-DPO: " fmt

#include <skiboot.h>
#include <fsp.h>
#include <stdio.h>
#include <timebase.h>
#include <opal.h>
#include <opal-msg.h>

#define DPO_CMD_SGN_BYTE0	0xf4 /* Byte[0] signature */
#define DPO_CMD_SGN_BYTE1	0x20 /* Byte[1] signature */
#define DPO_TIMEOUT		2700 /* 45 minutes in seconds */

bool fsp_dpo_pending;
static unsigned long fsp_dpo_init_tb;

/*
 * OPAL DPO interface
 *
 * Returns zero if DPO is not active, positive value indicating number
 * of seconds remaining for a forced system shutdown. This will enable
 * the host to schedule for shutdown voluntarily before timeout occurs.
 */
static int64_t fsp_opal_get_dpo_status(__be64 *dpo_timeout)
{
	if (!fsp_dpo_pending) {
		*dpo_timeout = 0;
		return OPAL_WRONG_STATE;
	}

	*dpo_timeout = cpu_to_be64(DPO_TIMEOUT - tb_to_secs(mftb() - fsp_dpo_init_tb));
	return OPAL_SUCCESS;
}

/* Process FSP DPO init message */
static void fsp_process_dpo(struct fsp_msg *msg)
{
	struct fsp_msg *resp;
	u32 cmd = FSP_RSP_INIT_DPO;
	int rc;

	/* DPO message does not have the correct signatures */
	if ((msg->data.bytes[0] != DPO_CMD_SGN_BYTE0)
			|| (msg->data.bytes[1] != DPO_CMD_SGN_BYTE1)) {
		prerror("Message signatures did not match\n");
		cmd |= FSP_STATUS_INVALID_CMD;
		resp = fsp_mkmsg(cmd, 0);
		if (resp == NULL) {
			prerror("%s : Message allocation failed\n", __func__);
			return;
		}
		if (fsp_queue_msg(resp, fsp_freemsg)) {
			fsp_freemsg(resp);
			prerror("%s : Failed to queue response "
				"message\n", __func__);
		}
		return;
	}

	/* OPAL is already in "DPO pending" state */
	if (fsp_dpo_pending) {
		prlog(PR_INFO, "OPAL already in DPO pending state\n");
		cmd |= FSP_STATUS_INVALID_DPOSTATE;
		resp = fsp_mkmsg(cmd, 0);
		if (resp == NULL) {
			prerror("%s : Message allocation failed\n", __func__);
			return;
		}
		if (fsp_queue_msg(resp, fsp_freemsg)) {
			fsp_freemsg(resp);
			prerror("%s : Failed to queue response "
				"message\n", __func__);
		}
		return;
	}


	/* Inform the host about DPO */
	rc = opal_queue_msg(OPAL_MSG_DPO, NULL, NULL);
	if (rc) {
		prerror("OPAL message queuing failed\n");
		cmd |= FSP_STATUS_GENERIC_ERROR;
		resp = fsp_mkmsg(cmd, 0);
		if (resp == NULL) {
			prerror("%s : Message allocation failed\n", __func__);
			return;
		}
		if (fsp_queue_msg(resp, fsp_freemsg)) {
			fsp_freemsg(resp);
			prerror("%s : Failed to queue response "
				"message\n", __func__);
		}
		return;
	} else
		prlog(PR_INFO, "Notified host about DPO event\n");

	/* Acknowledge the FSP on DPO */
	resp = fsp_mkmsg(cmd, 0);
	if (resp == NULL) {
		prerror("%s : Message allocation failed\n", __func__);
		return;
	}
	if (fsp_queue_msg(resp, fsp_freemsg)) {
		fsp_freemsg(resp);
		prerror("%s : Failed to queue response message\n", __func__);
		return;
	}

	/* Record DPO init time and set DPO pending flag */
	fsp_dpo_init_tb = mftb();
	fsp_dpo_pending = true;

	/*
	 * OPAL is now in DPO pending state. After first detecting DPO
	 * condition from OPAL, the host will have 45 minutes to prepare
	 * the system for shutdown. The host must take all necessary actions
	 * required in that regard and at the end shutdown itself. The host
	 * shutdown sequence eventually will make the call OPAL_CEC_POWER_DOWN
	 * which in turn ask the FSP to shutdown the CEC. If the FSP does not
	 * receive the cec power down command from OPAL within 45 minutes,
	 * it will assume that the host and the OPAL has processed the DPO
	 * sequence successfully and hence force power off the system.
	 */
}

/* Handle DPO sub-command from FSP */
static bool fsp_dpo_message(u32 cmd_sub_mod, struct fsp_msg *msg)
{
	if (cmd_sub_mod == FSP_CMD_INIT_DPO) {
		prlog(PR_INFO, "Delayed Power Off (DPO) notification received\n");
		fsp_process_dpo(msg);
		return true;
	}

	return false;
}

static struct fsp_client fsp_dpo_client = {
	.message = fsp_dpo_message,
};

void fsp_dpo_init(void)
{
	fsp_register_client(&fsp_dpo_client, FSP_MCLASS_SERVICE);
	opal_register(OPAL_GET_DPO_STATUS, fsp_opal_get_dpo_status, 1);
	prlog(PR_INFO, "FSP DPO support initialized\n");
}
