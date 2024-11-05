// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * We don't want to go on the cart!
 *
 * Copyright 2013-2018 IBM Corp.
 */

#include <skiboot.h>
#include <fsp.h>
#include <lock.h>
#include <processor.h>
#include <timebase.h>
#include <fsp-sysparam.h>
#include <errorlog.h>
#include <opal-api.h>

static bool fsp_surv_state = false;
static bool fsp_surv_ack_pending = false;
static u64 surv_timer;
static u64 surv_ack_timer;
static u32 surv_state_param;
static struct lock surv_lock = LOCK_UNLOCKED;

#define FSP_SURV_ACK_TIMEOUT	120	/* surv ack timeout in seconds */

DEFINE_LOG_ENTRY(OPAL_RC_SURVE_INIT, OPAL_MISC_ERR_EVT, OPAL_SURVEILLANCE,
		OPAL_SURVEILLANCE_ERR, OPAL_PREDICTIVE_ERR_GENERAL,
		OPAL_MISCELLANEOUS_INFO_ONLY);

DEFINE_LOG_ENTRY(OPAL_RC_SURVE_STATUS, OPAL_MISC_ERR_EVT, OPAL_SURVEILLANCE,
		OPAL_SURVEILLANCE_ERR, OPAL_PREDICTIVE_ERR_GENERAL,
		OPAL_MISCELLANEOUS_INFO_ONLY);

DEFINE_LOG_ENTRY(OPAL_RC_SURVE_ACK, OPAL_MISC_ERR_EVT, OPAL_SURVEILLANCE,
		OPAL_SURVEILLANCE_ERR, OPAL_PREDICTIVE_ERR_GENERAL,
		OPAL_MISCELLANEOUS_INFO_ONLY);

static void fsp_surv_ack(struct fsp_msg *msg)
{
	uint8_t val;

	if (!msg->resp)
		return;

	val = (msg->resp->word1 >> 8) & 0xff;
	if (val == 0) {
		/* reset the pending flag */
		prlog(PR_TRACE,
		      "SURV: Received heartbeat acknowledge from FSP\n");
		lock(&surv_lock);
		fsp_surv_ack_pending = false;
		unlock(&surv_lock);
	} else {
		/**
		 * @fwts-label FSPHeartbeatAckError
		 * @fwts-advice Error in acknowledging heartbeat to FSP.
		 * This could mean the FSP has gone away or it may mean
		 * the FSP may kill us for missing too many heartbeats.
		 */
		prlog(PR_ERR,
		      "SURV: Heartbeat Acknowledgment error from FSP\n");
	}

	fsp_freemsg(msg);
}

static void fsp_surv_check_timeout(void)
{
	u64 now = mftb();

	/*
	 * We just checked fsp_surv_ack_pending to be true in fsp_surv_hbeat
	 * and we haven't dropped the surv_lock between then and now. So, we
	 * just go ahead and check timeouts.
	 */
	if (tb_compare(now, surv_ack_timer) == TB_AAFTERB) {
		uint32_t plid = log_simple_error(&e_info(OPAL_RC_SURVE_ACK),
			"SURV: Surv ACK timed out; initiating R/R\n");

		/* Reset the pending trigger too */
		fsp_surv_ack_pending = false;
		fsp_trigger_reset(plid);
	}

	return;
}

/* Send surveillance heartbeat based on a timebase trigger */
static void fsp_surv_hbeat(void)
{
	u64 now = mftb();
	struct fsp_msg *msg;

	/* Check if an ack is pending... if so, don't send the ping just yet */
	if (fsp_surv_ack_pending) {
		fsp_surv_check_timeout();
		return;
	}

	/* add timebase callbacks */
	/*
	 * XXX This packet needs to be pushed to FSP in an interval
	 * less than 120s that's advertised to FSP.
	 *
	 * Verify if the command building format and call is fine.
	 */
	if (surv_timer == 0 ||
	    (tb_compare(now, surv_timer) == TB_AAFTERB) ||
	    (tb_compare(now, surv_timer) == TB_AEQUALB)) {
		prlog(PR_TRACE,
		      "SURV: Sending the heartbeat command to FSP\n");
		msg = fsp_mkmsg(FSP_CMD_SURV_HBEAT, 1, 120);
		if (!msg) {
			prerror("SURV: Failed to allocate heartbeat msg\n");
			return;
		}
		if (fsp_queue_msg(msg, fsp_surv_ack)) {
			fsp_freemsg(msg);
			prerror("SURV: Failed to queue heartbeat msg\n");
		} else {
			fsp_surv_ack_pending = true;
			surv_timer = now + secs_to_tb(60);
			surv_ack_timer = now + secs_to_tb(FSP_SURV_ACK_TIMEOUT);
		}
	}
}

static void fsp_surv_poll(void *data __unused)
{
	if (!fsp_surv_state)
		return;
	lock(&surv_lock);
	fsp_surv_hbeat();
	unlock(&surv_lock);
}

static void fsp_surv_got_param(uint32_t param_id __unused, int err_len,
			       void *data __unused)
{
	if (err_len != 4) {
		uint32_t plid = log_simple_error(&e_info(OPAL_RC_SURVE_STATUS),
		"SURV: Error (%d) retrieving surv status; initiating R/R\n",
			err_len);
		fsp_trigger_reset(plid);
		return;
	}

	surv_state_param = be32_to_cpu((__be32)surv_state_param);
	if (!(surv_state_param & 0x01)) {
		prlog(PR_NOTICE, "SURV: Status from FSP: disabled\n");
		return;
	}
	prlog(PR_NOTICE, "SURV: Status from FSP: enabled\n");

	lock(&surv_lock);
	fsp_surv_state = true;

	/* Also send one heartbeat now. The next one will not happen
	 * until we hit the OS.
	 */
	fsp_surv_hbeat();
	unlock(&surv_lock);
}

void fsp_surv_query(void)
{
	int rc;

	printf("SURV: Querying FSP's surveillance status\n");

	/* Reset surveillance settings */
	lock(&surv_lock);
	fsp_surv_state = false;
	surv_timer = 0;
	surv_ack_timer = 0;
	unlock(&surv_lock);

	/* Query FPS for surveillance state */
	rc = fsp_get_sys_param(SYS_PARAM_SURV, &surv_state_param, 4,
			       fsp_surv_got_param, NULL);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_SURVE_INIT),
			"SURV: Error %d queueing param request\n", rc);
	}
}

static bool fsp_surv_msg_rr(u32 cmd_sub_mod, struct fsp_msg *msg)
{
	assert(msg == NULL);

	switch (cmd_sub_mod) {
	case FSP_RESET_START:
		printf("SURV: Disabling surveillance\n");
		lock(&surv_lock);
		fsp_surv_state = false;
		fsp_surv_ack_pending = false;
		unlock(&surv_lock);
		return true;
	case FSP_RELOAD_COMPLETE:
		fsp_surv_query();
		return true;
	}
	return false;
}

static struct fsp_client fsp_surv_client_rr = {
	.message = fsp_surv_msg_rr,
};

/* This is called at boot time */
void fsp_init_surveillance(void)
{
	/* Always register the poller, so we don't have to add/remove
	 * it on reset-reload or change of surveillance state. Also the
	 * poller list has no locking so we don't want to play with it
	 * at runtime.
	 */
	opal_add_poller(fsp_surv_poll, NULL);

	/* Register for the reset/reload event */
	fsp_register_client(&fsp_surv_client_rr, FSP_MCLASS_RR_EVENT);

	/* Send query to FSP */
	fsp_surv_query();
}

