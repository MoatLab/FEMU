// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 *
 * P9 OPAL - SBE communication driver
 *
 * SBE firmware at https://github.com/open-power/sbe
 *
 * P9 chip has Self Boot Engine (SBE). OPAL uses SBE for various purpose like
 * timer, scom, MPIPL, etc,. Every chip has SBE. OPAL can communicate to SBE
 * on all chips. Based on message type it selects appropriate SBE (ex: schedule
 * timer on any chip).
 *
 * OPAL communicates to SBE via a set of data and control registers provided by
 * the PSU block in P9 chip.
 *  - Four 8 byte registers for Host to send command packets to SBE.
 *  - Four 8 byte registers for SBE to send response packets to Host.
 *  - Two doorbell registers (1 on each side) to alert either party
 *    when data is placed in above mentioned data registers. Once Host/SBE reads
 *    incoming data, it should clear doorbell register. Interrupt is disabled
 *    as soon as doorbell register is cleared.
 *
 * OPAL - SBE message format:
 *  - OPAL communicates to SBE via set of well defined commands.
 *  - Reg0 contains message header (command class, subclass, flags etc).
 *  - Reg1-3 contains actual data. If data is big then it uses indirect method
 *    (data is passed via memory and memory address/size is passed in Reg1-3).
 *  - Every message has defined timeout. SBE must respond within specified
 *    time. Otherwise OPAL discards message and sends error message to caller.
 *
 * Constraints:
 *  - Only one command is accepted in the command buffer until the response for
 *    the command is enqueued in the response buffer by SBE.
 *
 * Copyright 2017-2019 IBM Corp.
 */

#define pr_fmt(fmt) "SBE: " fmt

#include <chip.h>
#include <errorlog.h>
#include <lock.h>
#include <opal.h>
#include <opal-dump.h>
#include <sbe-p9.h>
#include <skiboot.h>
#include <timebase.h>
#include <timer.h>
#include <trace.h>
#include <xscom.h>

enum p9_sbe_mbox_state {
	sbe_mbox_idle = 0,	/* Ready to send message */
	sbe_mbox_send,		/* Message sent, waiting for ack/response */
	sbe_mbox_rr,		/* SBE in R/R */
};

struct p9_sbe {
	/* Chip ID to send message */
	u32			chip_id;

	/* List to hold SBE queue messages */
	struct list_head	msg_list;

	struct lock		lock;

	enum p9_sbe_mbox_state	state;

	/* SBE MBOX message sequence number */
	u16			cur_seq;
};

/* Default SBE chip ID */
static int sbe_default_chip_id = -1;

/* Is SBE timer running? */
static bool sbe_has_timer = false;
static bool sbe_timer_in_progress = false;
static bool has_new_target = false;

/* Inflight and next timer in TB */
static uint64_t sbe_last_gen_stamp;
static uint64_t sbe_timer_target;

/* Timer lock */
static struct lock sbe_timer_lock;

/*
 * Minimum timeout value for P9 is 500 microseconds. After that
 * SBE timer can handle granularity of 1 microsecond.
 */
#define SBE_TIMER_DEFAULT_US	500
static uint64_t sbe_timer_def_tb;

/*
 * Rate limit continuous timer update.
 * We can update inflight timer if new timer request is lesser than inflight
 * one. Limit such updates so that SBE gets time to handle FIFO side requests.
 */
#define SBE_TIMER_UPDATE_MAX	2
static uint32_t timer_update_cnt = 0;

/* Timer control message */
static struct p9_sbe_msg *timer_ctrl_msg;

#define SBE_STATUS_PRI_SHIFT	0x30
#define SBE_STATUS_SEC_SHIFT	0x20

/* Forward declaration */
static void p9_sbe_timeout_poll_one(struct p9_sbe *sbe);
static void p9_sbe_timer_schedule(void);

/* bit 0-15 : Primary status code */
static inline u16 p9_sbe_get_primary_rc(struct p9_sbe_msg *resp)
{
	return (resp->reg[0] >> SBE_STATUS_PRI_SHIFT);
}

static inline void p9_sbe_set_primary_rc(struct p9_sbe_msg *resp, u64 rc)
{
	resp->reg[0] |= (rc << SBE_STATUS_PRI_SHIFT);
}

static u64 p9_sbe_rreg(u32 chip_id, u64 reg)
{
	u64 data = 0;
	int rc;

	rc = xscom_read(chip_id, reg, &data);
	if (rc != OPAL_SUCCESS) {
		prlog(PR_DEBUG, "XSCOM error %d reading reg 0x%llx\n", rc, reg);
		return 0xffffffff;
	}

	return data;
}

static void p9_sbe_reg_dump(u32 chip_id)
{
#define SBE_DUMP_REG_ONE(chip_id, x) \
	prlog(PR_DEBUG, "  %20s: %016llx\n", #x, p9_sbe_rreg(chip_id, x))

	prlog(PR_DEBUG, "MBOX register dump for chip : %x\n", chip_id);
	SBE_DUMP_REG_ONE(chip_id, PSU_SBE_DOORBELL_REG_RW);
	SBE_DUMP_REG_ONE(chip_id, PSU_HOST_SBE_MBOX_REG0);
	SBE_DUMP_REG_ONE(chip_id, PSU_HOST_SBE_MBOX_REG1);
	SBE_DUMP_REG_ONE(chip_id, PSU_HOST_SBE_MBOX_REG2);
	SBE_DUMP_REG_ONE(chip_id, PSU_HOST_SBE_MBOX_REG3);
	SBE_DUMP_REG_ONE(chip_id, PSU_HOST_DOORBELL_REG_RW);
	SBE_DUMP_REG_ONE(chip_id, PSU_HOST_SBE_MBOX_REG4);
	SBE_DUMP_REG_ONE(chip_id, PSU_HOST_SBE_MBOX_REG5);
	SBE_DUMP_REG_ONE(chip_id, PSU_HOST_SBE_MBOX_REG6);
	SBE_DUMP_REG_ONE(chip_id, PSU_HOST_SBE_MBOX_REG7);
}

void p9_sbe_freemsg(struct p9_sbe_msg *msg)
{
	if (msg && msg->resp)
		free(msg->resp);
	free(msg);
}

static void p9_sbe_fillmsg(struct p9_sbe_msg *msg, u16 cmd,
			   u16 ctrl_flag, u64 reg1, u64 reg2, u64 reg3)
{
	bool response = !!(ctrl_flag & SBE_CMD_CTRL_RESP_REQ);
	u16 flag;

	/*
	 * Always set ack required flag. SBE will interrupt OPAL once it read
	 * message from mailbox register. If OPAL is expecting response, then
	 * it will update message timeout, otherwise it will send next message.
	 */
	flag = ctrl_flag | SBE_CMD_CTRL_ACK_REQ;

	/* Seqence ID is filled by p9_sbe_queue_msg() */
	msg->reg[0] = ((u64)flag << 32) | cmd;
	msg->reg[1] = reg1;
	msg->reg[2] = reg2;
	msg->reg[3] = reg3;
	msg->state = sbe_msg_unused;
	msg->response = response;
}

static struct p9_sbe_msg *p9_sbe_allocmsg(bool alloc_resp)
{
	struct p9_sbe_msg *msg;

	msg = zalloc(sizeof(struct p9_sbe_msg));
	if (!msg) {
		prlog(PR_ERR, "Failed to allocate SBE message\n");
		return NULL;
	}
	if (alloc_resp) {
		msg->resp = zalloc(sizeof(struct p9_sbe_msg));
		if (!msg->resp) {
			prlog(PR_ERR, "Failed to allocate SBE resp message\n");
			free(msg);
			return NULL;
		}
	}

	return msg;
}

/*
 * Handles "command with direct data" format only.
 *
 * Note: All mbox messages of our interest uses direct data format. If we need
 *       indirect data format then we may have to enhance this function.
 */
struct p9_sbe_msg *p9_sbe_mkmsg(u16 cmd, u16 ctrl_flag,
				u64 reg1, u64 reg2, u64 reg3)
{
	struct p9_sbe_msg *msg;

	msg = p9_sbe_allocmsg(!!(ctrl_flag & SBE_CMD_CTRL_RESP_REQ));
	if (!msg)
		return NULL;

	p9_sbe_fillmsg(msg, cmd, ctrl_flag, reg1, reg2, reg3);
	return msg;
}

static inline bool p9_sbe_mbox_busy(struct p9_sbe *sbe)
{
	return (sbe->state != sbe_mbox_idle);
}

static inline bool p9_sbe_msg_busy(struct p9_sbe_msg *msg)
{
	switch (msg->state) {
	case sbe_msg_queued:
	/* fall through */
	case sbe_msg_sent:
	case sbe_msg_wresp:
		return true;
	default:	/* + sbe_msg_unused, sbe_msg_done,
			     sbe_msg_timeout, sbe_msg_error */
		break;
	}
	return false;
}

static inline struct p9_sbe *p9_sbe_get_sbe(u32 chip_id)
{
	struct proc_chip *chip;

	/* Default to SBE on master chip */
	if (chip_id == -1) {
		if (sbe_default_chip_id == -1)
			return NULL;

		chip = get_chip(sbe_default_chip_id);
	} else {
		chip = get_chip(chip_id);
	}
	if (chip == NULL || chip->sbe == NULL)
		return NULL;

	return chip->sbe;
}

static int p9_sbe_msg_send(struct p9_sbe *sbe, struct p9_sbe_msg *msg)
{
	int rc, i;
	u64 addr, *data;

	addr = PSU_HOST_SBE_MBOX_REG0;
	data = &msg->reg[0];

	for (i = 0; i < NR_HOST_SBE_MBOX_REG; i++) {
		rc = xscom_write(sbe->chip_id, addr, *data);
		if (rc)
			return rc;

		addr++;
		data++;
	}

	rc = xscom_write(sbe->chip_id, PSU_SBE_DOORBELL_REG_OR,
			 HOST_SBE_MSG_WAITING);
	if (rc != OPAL_SUCCESS)
		return rc;

	prlog(PR_TRACE, "Message queued [chip id = 0x%x]:\n", sbe->chip_id);
	for (i = 0; i < 4; i++)
		prlog(PR_TRACE, "    Reg%d : %016llx\n", i, msg->reg[i]);

	msg->timeout = mftb() + msecs_to_tb(SBE_CMD_TIMEOUT_MAX);
	sbe->state = sbe_mbox_send;
	msg->state = sbe_msg_sent;
	return rc;
}

static int p9_sbe_msg_receive(u32 chip_id, struct p9_sbe_msg *resp)
{
	int i;
	int rc = OPAL_SUCCESS;
	u64 addr, *data;

	addr = PSU_HOST_SBE_MBOX_REG4;
	data = &resp->reg[0];

	for (i = 0; i < NR_HOST_SBE_MBOX_REG; i++) {
		rc = xscom_read(chip_id, addr, data);
		if (rc)
			return rc;

		addr++;
		data++;
	}
	return rc;
}

/* WARNING: This will drop sbe->lock */
static void p9_sbe_msg_complete(struct p9_sbe *sbe, struct p9_sbe_msg *msg,
				enum p9_sbe_msg_state msg_state)
{
	void (*comp)(struct p9_sbe_msg *msg);

	prlog(PR_TRACE, "Completing msg [chip id = %x], reg0 : 0x%llx\n",
	      sbe->chip_id, msg->reg[0]);

	comp = msg->complete;
	list_del(&msg->link);
	sync();
	msg->state = msg_state;

	if (comp) {
		unlock(&sbe->lock);
		comp(msg);
		lock(&sbe->lock);
	}
}

/* WARNING: This will drop sbe->lock */
static void p9_sbe_send_complete(struct p9_sbe *sbe)
{
	struct p9_sbe_msg *msg;

	if (list_empty(&sbe->msg_list))
		return;

	msg = list_top(&sbe->msg_list, struct p9_sbe_msg, link);
	/* Need response */
	if (msg->response) {
		msg->state = sbe_msg_wresp;
	} else {
		sbe->state = sbe_mbox_idle;
		p9_sbe_msg_complete(sbe, msg, sbe_msg_done);
	}
}

/* WARNING: This will drop sbe->lock */
static void p9_sbe_process_queue(struct p9_sbe *sbe)
{
	int rc, retry_cnt = 0;
	struct p9_sbe_msg *msg = NULL;

	if (p9_sbe_mbox_busy(sbe))
		return;

	while (!list_empty(&sbe->msg_list)) {
		msg = list_top(&sbe->msg_list, struct p9_sbe_msg, link);
		/* Send message */
		rc = p9_sbe_msg_send(sbe, msg);
		if (rc == OPAL_SUCCESS)
			return;

		prlog(PR_ERR, "Failed to send message to SBE [chip id = %x]\n",
		      sbe->chip_id);
		if (msg->resp) {
			p9_sbe_set_primary_rc(msg->resp,
					      SBE_STATUS_PRI_GENERIC_ERR);
		}
		p9_sbe_msg_complete(sbe, msg, sbe_msg_error);

		/*
		 * Repeatedly failed to send message to SBE. Lets stop
		 * sending message.
		 */
		if (retry_cnt++ >= 3) {
			prlog(PR_ERR, "Temporarily stopped sending "
			      "message to SBE\n");
			return;
		}
	}
}

/*
 * WARNING:
 *         Only one command is accepted in the command buffer until response
 *         to the command is enqueued in the response buffer by SBE.
 *
 *         Head of msg_list contains in-flight message. Hence we should always
 *         add new message to tail of the list.
 */
int p9_sbe_queue_msg(u32 chip_id, struct p9_sbe_msg *msg,
		     void (*comp)(struct p9_sbe_msg *msg))
{
	struct p9_sbe *sbe;

	if (!msg)
		return OPAL_PARAMETER;

	sbe = p9_sbe_get_sbe(chip_id);
	if (!sbe)
		return OPAL_HARDWARE;

	lock(&sbe->lock);
	/* Set completion and update sequence number */
	msg->complete = comp;
	msg->state = sbe_msg_queued;
	msg->reg[0] = msg->reg[0] | ((u64)sbe->cur_seq << 16);
	sbe->cur_seq++;

	/* Reset sequence number */
	if (sbe->cur_seq == 0xffff)
		sbe->cur_seq = 1;

	/* Add message to queue */
	list_add_tail(&sbe->msg_list, &msg->link);
	p9_sbe_process_queue(sbe);
	unlock(&sbe->lock);

	return OPAL_SUCCESS;
}

int p9_sbe_sync_msg(u32 chip_id, struct p9_sbe_msg *msg, bool autofree)
{
	int rc;
	struct p9_sbe *sbe;

	rc = p9_sbe_queue_msg(chip_id, msg, NULL);
	if (rc)
		goto free_msg;

	sbe = p9_sbe_get_sbe(chip_id);
	if (!sbe) {
		rc = OPAL_HARDWARE;
		goto free_msg;
	}

	while (p9_sbe_msg_busy(msg)) {
		cpu_relax();
		p9_sbe_timeout_poll_one(sbe);
	}

	if (msg->state == sbe_msg_done)
		rc = SBE_STATUS_PRI_SUCCESS;
	else
		rc = SBE_STATUS_PRI_GENERIC_ERR;

	if (msg->response && msg->resp)
		rc = p9_sbe_get_primary_rc(msg->resp);

free_msg:
	if (autofree)
		p9_sbe_freemsg(msg);

	return rc;
}

/* Remove SBE message from queue. It will not remove inflight message */
int p9_sbe_cancelmsg(u32 chip_id, struct p9_sbe_msg *msg)
{
	struct p9_sbe *sbe;

	sbe = p9_sbe_get_sbe(chip_id);
	if (!sbe)
		return OPAL_PARAMETER;

	lock(&sbe->lock);
	if (msg->state != sbe_msg_queued) {
		unlock(&sbe->lock);
		return OPAL_BUSY;
	}

	list_del(&msg->link);
	msg->state = sbe_msg_done;
	unlock(&sbe->lock);
	return OPAL_SUCCESS;
}

static void p9_sbe_handle_response(u32 chip_id, struct p9_sbe_msg *msg)
{
	u16 send_seq, resp_seq;
	int rc;

	if (msg == NULL || msg->resp == NULL)
		return;

	memset(msg->resp, 0, sizeof(struct p9_sbe_msg));

	rc = p9_sbe_msg_receive(chip_id, msg->resp);
	if (rc != OPAL_SUCCESS) {
		prlog(PR_ERR, "Failed to read response message "
		      "[chip id = %x]\n", chip_id);
		p9_sbe_set_primary_rc(msg->resp, SBE_STATUS_PRI_GENERIC_ERR);
		return;
	}

	/* Validate sequence number */
	send_seq = (msg->reg[0] >> 16) & 0xffff;
	resp_seq = (msg->resp->reg[0] >> 16) & 0xffff;
	if (send_seq != resp_seq) {
		/*
		 * XXX Handle SBE R/R.
		 *     Lets send sequence error to caller until SBE reset works.
		 */
		prlog(PR_ERR, "Invalid sequence id [chip id = %x]\n", chip_id);
		p9_sbe_set_primary_rc(msg->resp, SBE_STATUS_PRI_SEQ_ERR);
		return;
	}
}

static int p9_sbe_clear_interrupt(struct p9_sbe *sbe, u64 bits)
{
	int rc;
	u64 val;

	/* Clear doorbell register */
	val = SBE_HOST_RESPONSE_MASK & ~bits;
	rc = xscom_write(sbe->chip_id, PSU_HOST_DOORBELL_REG_AND, val);
	if (rc) {
		prlog(PR_ERR, "Failed to clear SBE to Host doorbell "
		      "interrupt [chip id = %x]\n", sbe->chip_id);
	}
	return rc;
}

/* WARNING: This will drop sbe->lock */
static void p9_sbe_timer_response(struct p9_sbe *sbe)
{
	if (sbe->chip_id != sbe_default_chip_id)
		return;

	sbe_timer_in_progress = false;
	/* Drop lock and call timers */
	unlock(&sbe->lock);

	lock(&sbe_timer_lock);
	/*
	 * Once we get timer expiry interrupt (even if its suprious interrupt)
	 * we can schedule next timer request.
	 */
	timer_update_cnt = 0;
	unlock(&sbe_timer_lock);

	check_timers(true);
	lock(&sbe->lock);
}

/* WARNING: This will drop sbe->lock */
static void __p9_sbe_interrupt(struct p9_sbe *sbe)
{
	bool has_response;
	int rc;
	u64 data = 0, val;
	struct p9_sbe_msg *msg = NULL;

again:
	/* Read doorbell register */
	rc = xscom_read(sbe->chip_id, PSU_HOST_DOORBELL_REG_RW, &data);
	if (rc) {
		prlog(PR_ERR, "Failed to read SBE to Host doorbell register "
		      "[chip id = %x]\n", sbe->chip_id);
		p9_sbe_reg_dump(sbe->chip_id);
		return;
	}

	/* Completed processing all the bits */
	if (!data)
		return;

	/* SBE came back from reset */
	if (data & SBE_HOST_RESET) {
		/* Clear all bits and restart sending message */
		rc = p9_sbe_clear_interrupt(sbe, data);
		if (rc)
			return;

		prlog(PR_NOTICE,
		      "Back from reset [chip id = %x]\n", sbe->chip_id);
		/* Reset SBE MBOX state */
		sbe->state = sbe_mbox_idle;

		/* Reset message state */
		if (!list_empty(&sbe->msg_list)) {
			msg = list_top(&sbe->msg_list, struct p9_sbe_msg, link);
			msg->state = sbe_msg_queued;
		}
		return;
	}

	/* Process ACK message before response */
	if (data & SBE_HOST_MSG_READ) {
		rc = p9_sbe_clear_interrupt(sbe, SBE_HOST_MSG_READ);
		if (rc)
			return;
		p9_sbe_send_complete(sbe);
		goto again;
	}

	/* Read SBE response before clearing doorbell register */
	if (data & SBE_HOST_RESPONSE_WAITING) {
		if (!list_empty(&sbe->msg_list)) {
			msg = list_top(&sbe->msg_list, struct p9_sbe_msg, link);
			p9_sbe_handle_response(sbe->chip_id, msg);
			has_response = true;
		} else {
			has_response = false;
			prlog(PR_DEBUG,
			      "Got response with no pending message\n");
		}

		rc = p9_sbe_clear_interrupt(sbe, SBE_HOST_RESPONSE_WAITING);
		if (rc)
			return;

		/* Reset SBE MBOX state */
		sbe->state = sbe_mbox_idle;
		if (has_response)
			p9_sbe_msg_complete(sbe, msg, sbe_msg_done);

		goto again;
	}

	/* SBE passthrough command, call prd handler */
	if (data & SBE_HOST_PASSTHROUGH) {
		rc = p9_sbe_clear_interrupt(sbe, SBE_HOST_PASSTHROUGH);
		if (rc)
			return;
		prd_sbe_passthrough(sbe->chip_id);
		goto again;
	}

	/* Timer expired */
	if (data & SBE_HOST_TIMER_EXPIRY) {
		rc = p9_sbe_clear_interrupt(sbe, SBE_HOST_TIMER_EXPIRY);
		if (rc)
			return;
		p9_sbe_timer_response(sbe);
		goto again;
	}

	/* Unhandled bits */
	val = data & ~(SBE_HOST_RESPONSE_MASK);
	if (val) {
		prlog(PR_ERR, "Unhandled interrupt bit [chip id = %x] : "
		      " %016llx\n", sbe->chip_id, val);
		rc = p9_sbe_clear_interrupt(sbe, data);
		if (rc)
			return;
		goto again;
	}
}

void p9_sbe_interrupt(uint32_t chip_id)
{
	struct proc_chip *chip;
	struct p9_sbe *sbe;

	chip = get_chip(chip_id);
	if (chip == NULL || chip->sbe == NULL)
		return;

	sbe = chip->sbe;
	lock(&sbe->lock);
	__p9_sbe_interrupt(sbe);
	p9_sbe_process_queue(sbe);
	unlock(&sbe->lock);
}

/*
 * Check if the timer is working. If at least 10ms elapsed since
 * last scheduled timer expiry.
 */
static void p9_sbe_timer_poll(struct p9_sbe *sbe)
{
	if (sbe->chip_id != sbe_default_chip_id)
		return;

	if (!sbe_has_timer || !sbe_timer_in_progress)
		return;

	if (tb_compare(mftb(), sbe_last_gen_stamp + msecs_to_tb(10))
	    != TB_AAFTERB)
		return;

	prlog(PR_ERR, "Timer stuck, falling back to OPAL pollers.\n");
	prlog(PR_ERR, "You will likely have slower I2C and may have "
	      "experienced increased jitter.\n");
	p9_sbe_reg_dump(sbe->chip_id);
	sbe_has_timer = false;
	sbe_timer_in_progress = false;
}

static void p9_sbe_timeout_poll_one(struct p9_sbe *sbe)
{
	struct p9_sbe_msg *msg;

	if (sbe->chip_id == sbe_default_chip_id) {
		if (list_empty_nocheck(&sbe->msg_list) &&
		    !sbe_timer_in_progress)
			return;
	} else {
		if (list_empty_nocheck(&sbe->msg_list))
			return;
	}

	lock(&sbe->lock);

	/*
	 * In some cases there will be a delay in calling OPAL interrupt
	 * handler routine (opal_handle_interrupt). In such cases its
	 * possible that SBE has responded, but OPAL didn't act on that.
	 * Hence check for SBE response.
	 */
	__p9_sbe_interrupt(sbe);
	p9_sbe_timer_poll(sbe);

	if (list_empty(&sbe->msg_list))
		goto out;

	/*
	 * For some reason OPAL didn't sent message to SBE.
	 * Lets try to send message again.
	 */
	if (!p9_sbe_mbox_busy(sbe)) {
		p9_sbe_process_queue(sbe);
		goto out;
	}

	msg = list_top(&sbe->msg_list, struct p9_sbe_msg, link);
	if (tb_compare(mftb(), msg->timeout) != TB_AAFTERB)
		goto out;

	/* Message timeout */
	prlog(PR_ERR, "Message timeout [chip id = %x], cmd = %llx, "
	      "subcmd = %llx\n", sbe->chip_id,
	      (msg->reg[0] >> 8) & 0xff, msg->reg[0] & 0xff);
	p9_sbe_reg_dump(sbe->chip_id);
	if (msg->resp) {
		p9_sbe_set_primary_rc(msg->resp,
				      SBE_STATUS_PRI_GENERIC_ERR);
	}

	/* XXX Handle SBE R/R. Reset SBE state until SBE R/R works. */
	sbe->state = sbe_mbox_idle;
	p9_sbe_msg_complete(sbe, msg, sbe_msg_timeout);
	p9_sbe_process_queue(sbe);

out:
	unlock(&sbe->lock);
}

static void p9_sbe_timeout_poll(void *user_data __unused)
{
	struct p9_sbe *sbe;
	struct proc_chip *chip;

	for_each_chip(chip) {
		if (chip->sbe == NULL)
			continue;
		sbe = chip->sbe;
		p9_sbe_timeout_poll_one(sbe);
	}
}

static void p9_sbe_timer_resp(struct p9_sbe_msg *msg)
{
	if (msg->state != sbe_msg_done) {
		prlog(PR_DEBUG, "Failed to schedule timer [chip id %x]\n",
		      sbe_default_chip_id);
	} else {
		/* Update last scheduled timer value */
		sbe_last_gen_stamp = mftb() +
			usecs_to_tb(timer_ctrl_msg->reg[1]);
		sbe_timer_in_progress = true;
	}

	if (!has_new_target)
		return;

	lock(&sbe_timer_lock);
	if (has_new_target) {
		if (!p9_sbe_msg_busy(timer_ctrl_msg)) {
			has_new_target = false;
			p9_sbe_timer_schedule();
		}
	}
	unlock(&sbe_timer_lock);
}

static void p9_sbe_timer_schedule(void)
{
	int rc;
	u32 tick_us = SBE_TIMER_DEFAULT_US;
	u64 tb_cnt, now = mftb();

	if (sbe_timer_in_progress) {
		if (sbe_timer_target >= sbe_last_gen_stamp)
			return;

		if (now >= sbe_last_gen_stamp)
			return;

		/* Remaining time of inflight timer <= sbe_timer_def_tb */
		if ((sbe_last_gen_stamp - now) <= sbe_timer_def_tb)
			return;
	}

	/* Stop sending timer update chipop until inflight timer expires */
	if (timer_update_cnt > SBE_TIMER_UPDATE_MAX)
		return;
	timer_update_cnt++;

	if (now < sbe_timer_target) {
		/* Calculate how many microseconds from now, rounded up */
		if ((sbe_timer_target - now) > sbe_timer_def_tb) {
			tb_cnt = sbe_timer_target - now + usecs_to_tb(1) - 1;
			tick_us = tb_to_usecs(tb_cnt);
		}
	}

	/* Clear sequence number. p9_sbe_queue_msg will add new sequene ID */
	timer_ctrl_msg->reg[0] &= ~(PPC_BITMASK(32, 47));
	/* Update timeout value */
	timer_ctrl_msg->reg[1] = tick_us;
	rc = p9_sbe_queue_msg(sbe_default_chip_id, timer_ctrl_msg,
			      p9_sbe_timer_resp);
	if (rc != OPAL_SUCCESS) {
		prlog(PR_ERR, "Failed to start timer [chip id = %x]\n",
		      sbe_default_chip_id);
		return;
	}
}

/*
 * This is called with the timer lock held, so there is no
 * issue with re-entrancy or concurrence
 */
void p9_sbe_update_timer_expiry(uint64_t new_target)
{
	if (!sbe_has_timer || new_target == sbe_timer_target)
		return;

	lock(&sbe_timer_lock);
	/* Timer message is in flight. Record new timer and schedule later */
	if (p9_sbe_msg_busy(timer_ctrl_msg) || has_new_target) {
		if (new_target < sbe_timer_target) {
			sbe_timer_target = new_target;
			has_new_target = true;
		}
	} else {
		sbe_timer_target = new_target;
		p9_sbe_timer_schedule();
	}
	unlock(&sbe_timer_lock);
}

/* Initialize SBE timer */
static void p9_sbe_timer_init(void)
{
	timer_ctrl_msg = p9_sbe_mkmsg(SBE_CMD_CONTROL_TIMER,
				      CONTROL_TIMER_START, 0, 0, 0);
	assert(timer_ctrl_msg);
	init_lock(&sbe_timer_lock);
	sbe_has_timer = true;
	sbe_timer_target = mftb();
	sbe_last_gen_stamp = ~0ull;
	sbe_timer_def_tb = usecs_to_tb(SBE_TIMER_DEFAULT_US);
	prlog(PR_INFO, "Timer facility on chip %x\n", sbe_default_chip_id);
}

bool p9_sbe_timer_ok(void)
{
	return sbe_has_timer;
}

static void p9_sbe_stash_chipop_resp(struct p9_sbe_msg *msg)
{
	int rc = p9_sbe_get_primary_rc(msg->resp);
	struct p9_sbe *sbe = (void *)msg->user_data;

	if (rc == SBE_STATUS_PRI_SUCCESS) {
		prlog(PR_DEBUG, "Sent stash MPIPL config [chip id =0x%x]\n",
		      sbe->chip_id);
	} else {
		prlog(PR_ERR, "Failed to send stash MPIPL config "
		      "[chip id = 0x%x, rc = %d]\n", sbe->chip_id, rc);
	}

	p9_sbe_freemsg(msg);
}

static void p9_sbe_send_relocated_base_single(struct p9_sbe *sbe, u64 reloc_base)
{
	u8 key = SBE_STASH_KEY_SKIBOOT_BASE;
	u16 cmd = SBE_CMD_STASH_MPIPL_CONFIG;
	u16 flag = SBE_CMD_CTRL_RESP_REQ;
	struct p9_sbe_msg *msg;

	msg = p9_sbe_mkmsg(cmd, flag, key, reloc_base, 0);
	if (!msg) {
		prlog(PR_ERR, "Message allocation failed\n");
		return;
	}

	msg->user_data = (void *)sbe;
	if (p9_sbe_queue_msg(sbe->chip_id, msg, p9_sbe_stash_chipop_resp)) {
		prlog(PR_ERR, "Failed to queue stash MPIPL config message\n");
	}
}

/* Send relocated skiboot base address to all SBE */
void p9_sbe_send_relocated_base(uint64_t reloc_base)
{
	struct proc_chip *chip;

	for_each_chip(chip) {
		if (chip->sbe == NULL)
			continue;

		p9_sbe_send_relocated_base_single(chip->sbe, reloc_base);
	}
}

void p9_sbe_init(void)
{
	struct dt_node *xn;
	struct proc_chip *chip;
	struct p9_sbe *sbe;

	if (proc_gen < proc_gen_p9)
		return;

	dt_for_each_compatible(dt_root, xn, "ibm,xscom") {
		sbe = zalloc(sizeof(struct p9_sbe));
		assert(sbe);
		sbe->chip_id = dt_get_chip_id(xn);
		sbe->cur_seq = 1;
		sbe->state = sbe_mbox_idle;
		list_head_init(&sbe->msg_list);
		init_lock(&sbe->lock);

		chip = get_chip(sbe->chip_id);
		assert(chip);
		chip->sbe = sbe;

		if (dt_has_node_property(xn, "primary", NULL)) {
			sbe_default_chip_id = sbe->chip_id;
			prlog(PR_DEBUG, "Master chip id : %x\n", sbe->chip_id);
		}
	}

	if (sbe_default_chip_id == -1) {
		prlog(PR_ERR, "Master chip ID not found.\n");
		return;
	}

	/* Initiate SBE timer */
	p9_sbe_timer_init();

	/* Initiate SBE timeout poller */
	opal_add_poller(p9_sbe_timeout_poll, NULL);
}

/* Terminate and initiate MPIPL */
void p9_sbe_terminate(void)
{
	uint32_t primary_chip = -1;
	int rc;
	u64 wait_tb;
	struct proc_chip *chip;

	/* Return if MPIPL is not supported */
	if (!is_mpipl_enabled())
		return;

	/* Save crashing CPU details */
	opal_mpipl_save_crashing_pir();

	/* Unregister flash. It will request BMC MBOX reset */
	if (!flash_unregister()) {
		prlog(PR_DEBUG, "Failed to reset BMC MBOX\n");
		return;
	}

	/*
	 * Send S0 interrupt to all SBE. Sequence:
	 *   - S0 interrupt on secondary chip SBE
	 *   - S0 interrupt on Primary chip SBE
	 */
	for_each_chip(chip) {
		if (dt_has_node_property(chip->devnode, "primary", NULL)) {
			primary_chip = chip->id;
			continue;
		}

		rc = xscom_write(chip->id,
				 SBE_CONTROL_REG_RW, SBE_CONTROL_REG_S0);
		/* Initiate normal reboot */
		if (rc) {
			prlog(PR_ERR, "Failed to write S0 interrupt [chip id = %x]\n",
			      chip->id);
			return;
		}
	}

	/* Initiate normal reboot */
	if (primary_chip == -1) {
		prlog(PR_ERR, "Primary chip ID not found.\n");
		return;
	}

	rc = xscom_write(primary_chip,
			 SBE_CONTROL_REG_RW, SBE_CONTROL_REG_S0);
	if (rc) {
		prlog(PR_ERR, "Failed to write S0 interrupt [chip id = %x]\n",
		      primary_chip);
		return;
	}

	/* XXX We expect SBE to act on interrupt, quiesce the system and start
	 *     MPIPL flow. Currently we do not have a way to detect SBE state.
	 *     Hence wait for max time SBE takes to respond and then trigger
	 *     normal reboot.
	 */
	prlog(PR_NOTICE, "Initiated MPIPL, waiting for SBE to respond...\n");
	wait_tb = mftb() + msecs_to_tb(SBE_CMD_TIMEOUT_MAX);
	while (mftb() < wait_tb) {
		cpu_relax();
	}

	prlog(PR_ERR, "SBE did not respond within timeout period (%d secs).\n",
	      SBE_CMD_TIMEOUT_MAX / 1000);
	prlog(PR_ERR, "Falling back to normal reboot\n");
}
