// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Block Transfer, typically what IPMI goes over
 *
 * Copyright 2013-2019 IBM Corp.
 */

#define pr_fmt(fmt) "BT: " fmt

#include <skiboot.h>
#include <lpc.h>
#include <lock.h>
#include <device.h>
#include <timebase.h>
#include <ipmi.h>
#include <bt.h>
#include <timer.h>
#include <ipmi.h>
#include <timebase.h>
#include <chip.h>
#include <interrupts.h>

/* BT registers */
#define BT_CTRL			0
#define BT_CTRL_B_BUSY		0x80
#define BT_CTRL_H_BUSY		0x40
#define BT_CTRL_OEM0		0x20
#define BT_CTRL_SMS_ATN		0x10
#define BT_CTRL_B2H_ATN		0x08
#define BT_CTRL_H2B_ATN		0x04
#define BT_CTRL_CLR_RD_PTR	0x02
#define BT_CTRL_CLR_WR_PTR	0x01
#define BT_HOST2BMC		1
#define BT_INTMASK		2
#define BT_INTMASK_B2H_IRQEN	0x01
#define BT_INTMASK_B2H_IRQ	0x02
#define BT_INTMASK_BMC_HWRST	0x80

/* Maximum size of the HW FIFO */
#define BT_FIFO_LEN		64

/* Default poll interval before interrupts are working */
#define BT_DEFAULT_POLL_MS	200

/*
 * Minimum size of an IPMI request/response including
 * mandatory headers.
 */
#define BT_MIN_REQ_LEN		3
#define BT_MIN_RESP_LEN		4

/* How long (in uS) to poll for new ipmi data. */
#define POLL_TIMEOUT		10000

/* Maximum number of outstanding messages to allow in the queue. */
#define BT_MAX_QUEUE_LEN	10

/* How long (in seconds) before a message is timed out. */
#define BT_MSG_TIMEOUT		3

/* Maximum number of times to attempt sending a message before giving up. */
#define BT_MAX_RETRIES		1

/* Macro to enable printing BT message queue for debug */
#define BT_QUEUE_DEBUG		0

/* BT message logging macros */
#define _BT_Q_LOG(level, msg, fmt, args...) \
	do { if (msg) \
			prlog(level, "seq 0x%02x netfn 0x%02x cmd 0x%02x: " fmt "\n", \
			(msg)->seq, ((msg)->ipmi_msg.netfn >> 2), (msg)->ipmi_msg.cmd, ##args); \
		else \
			prlog(level, "seq 0x?? netfn 0x?? cmd 0x??: " fmt "\n", ##args); \
	} while (0)

#define BT_Q_ERR(msg, fmt, args...) \
	_BT_Q_LOG(PR_ERR, msg, fmt, ##args)

#define BT_Q_DBG(msg, fmt, args...) \
	_BT_Q_LOG(PR_DEBUG, msg, fmt, ##args)

#define BT_Q_TRACE(msg, fmt, args...) \
	_BT_Q_LOG(PR_TRACE, msg, fmt, ##args)

struct bt_msg {
	struct list_node link;
	unsigned long tb;
	uint8_t seq;
	uint8_t send_count;
	bool disable_retry;
	struct ipmi_msg ipmi_msg;
};

struct bt_caps {
	uint8_t num_requests;
	uint16_t input_buf_len;
	uint16_t output_buf_len;
	uint8_t msg_timeout;
	uint8_t max_retries;
};

struct bt {
	uint32_t base_addr;
	struct lock lock;
	struct list_head msgq;
	struct list_head msgq_sync; /* separate list for synchronous messages */
	struct timer poller;
	bool irq_ok;
	int queue_len;
	struct bt_caps caps;
};

static struct bt bt;
static struct bt_msg *inflight_bt_msg; /* Holds in flight message */

static int ipmi_seq;

static inline uint8_t bt_inb(uint32_t reg)
{
	return lpc_inb(bt.base_addr + reg);
}

static inline void bt_outb(uint8_t data, uint32_t reg)
{
	lpc_outb(data, bt.base_addr + reg);
}

static inline void bt_set_h_busy(bool value)
{
	uint8_t rval;

	rval = bt_inb(BT_CTRL);
	if (value != !!(rval & BT_CTRL_H_BUSY))
		bt_outb(BT_CTRL_H_BUSY, BT_CTRL);
}

static inline void bt_assert_h_busy(void)
{
	uint8_t rval;
	rval = bt_inb(BT_CTRL);
	assert(rval & BT_CTRL_H_BUSY);
}

static void get_bt_caps_complete(struct ipmi_msg *msg)
{
	/* Ignore errors, we'll fallback to using the defaults, no big deal */
	if (msg->data[0] == 0) {
		prlog(PR_DEBUG, "Got illegal BMC BT capability\n");
		goto out;
	}

	if (msg->data[1] != BT_FIFO_LEN) {
		prlog(PR_DEBUG, "Got a input buffer len (%u) cap which differs from the default\n",
				msg->data[1]);
	}

	if (msg->data[2] != BT_FIFO_LEN) {
		prlog(PR_DEBUG, "Got a output buffer len (%u) cap which differs from the default\n",
				msg->data[2]);
	}

	/*
	 * IPMI Spec says that the value for buffer sizes are:
	 * "the largest value allowed in first byte"
	 * Therefore we want to add one to what we get
	 */
	bt.caps.num_requests = msg->data[0];
	bt.caps.input_buf_len = msg->data[1] + 1;
	bt.caps.output_buf_len = msg->data[2] + 1;
	bt.caps.msg_timeout = msg->data[3];
	bt.caps.max_retries = msg->data[4];
	prlog(PR_DEBUG, "BMC BT capabilities received:\n");
	prlog(PR_DEBUG, "buffer sizes: %d input %d output\n",
			bt.caps.input_buf_len, bt.caps.output_buf_len);
	prlog(PR_DEBUG, "number of requests: %d\n", bt.caps.num_requests);
	prlog(PR_DEBUG,  "msg timeout: %d max retries: %d\n",
			bt.caps.msg_timeout, bt.caps.max_retries);

out:
	ipmi_free_msg(msg);
}

static void get_bt_caps(void)
{

	struct ipmi_msg *bmc_caps;
	/*
	 * Didn't sent a message, now is a good time to ask the BMC for its
	 * capabilities.
	 */
	bmc_caps = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE, IPMI_GET_BT_CAPS,
			get_bt_caps_complete, NULL, NULL, 0, sizeof(struct bt_caps));
	if (!bmc_caps)
		prerror("Couldn't create BMC BT capabilities msg\n");

	if (bmc_caps && ipmi_queue_msg(bmc_caps))
		prerror("Couldn't enqueue request for BMC BT capabilities\n");

	/* Ignore errors, we'll fallback to using the defaults, no big deal */
}

static inline bool bt_idle(void)
{
	uint8_t bt_ctrl = bt_inb(BT_CTRL);

	return !(bt_ctrl & BT_CTRL_B_BUSY) && !(bt_ctrl & BT_CTRL_H2B_ATN);
}

/* Must be called with bt.lock held */
static void bt_msg_del(struct bt_msg *bt_msg)
{
	list_del(&bt_msg->link);
	bt.queue_len--;

	/* once inflight_bt_msg out of list, it should be emptyed */
	if (bt_msg == inflight_bt_msg)
		inflight_bt_msg = NULL;

	unlock(&bt.lock);
	ipmi_cmd_done(bt_msg->ipmi_msg.cmd,
		      IPMI_NETFN_RETURN_CODE(bt_msg->ipmi_msg.netfn),
		      IPMI_TIMEOUT_ERR, &bt_msg->ipmi_msg);
	lock(&bt.lock);
}

static void bt_init_interface(void)
{
	/* Clear interrupt condition & enable irq */
	bt_outb(BT_INTMASK_B2H_IRQ | BT_INTMASK_B2H_IRQEN, BT_INTMASK);

	/* Take care of a stable H_BUSY if any */
	bt_set_h_busy(false);
}

static void bt_reset_interface(void)
{
	bt_outb(BT_INTMASK_BMC_HWRST, BT_INTMASK);
	bt_init_interface();
}

/*
 * Try and send a message from the message queue. Caller must hold
 * bt.bt_lock and bt.lock and ensue the message queue is not
 * empty.
 */
static void bt_send_msg(struct bt_msg *bt_msg)
{
	int i;
	struct ipmi_msg *ipmi_msg;

	ipmi_msg = &bt_msg->ipmi_msg;

	/* Send the message */
	bt_outb(BT_CTRL_CLR_WR_PTR, BT_CTRL);

	/* Byte 1 - Length */
	bt_outb(ipmi_msg->req_size + BT_MIN_REQ_LEN, BT_HOST2BMC);

	/* Byte 2 - NetFn/LUN */
	bt_outb(ipmi_msg->netfn, BT_HOST2BMC);

	/* Byte 3 - Seq */
	bt_outb(bt_msg->seq, BT_HOST2BMC);

	/* Byte 4 - Cmd */
	bt_outb(ipmi_msg->cmd, BT_HOST2BMC);

	/* Byte 5:N - Data */
	for (i = 0; i < ipmi_msg->req_size; i++)
		bt_outb(ipmi_msg->data[i], BT_HOST2BMC);

	BT_Q_TRACE(bt_msg, "Message sent to host");
	bt_msg->send_count++;

	bt_outb(BT_CTRL_H2B_ATN, BT_CTRL);

	return;
}

static void bt_clear_fifo(void)
{
	int i;

	for (i = 0; i < bt.caps.input_buf_len; i++)
		bt_outb(0xff, BT_HOST2BMC);
}

static void bt_flush_msg(void)
{
	bt_assert_h_busy();
	bt_outb(BT_CTRL_B2H_ATN | BT_CTRL_CLR_RD_PTR | BT_CTRL_CLR_WR_PTR, BT_CTRL);
	bt_clear_fifo();
	/* Can't hurt to clear the write pointer again, just to be sure */
	bt_outb(BT_CTRL_CLR_WR_PTR, BT_CTRL);
	bt_set_h_busy(false);
}

static void bt_get_resp(void)
{
	int i;
	struct ipmi_msg *ipmi_msg;
	uint8_t resp_len, netfn, seq, cmd;
	uint8_t cc = IPMI_CC_NO_ERROR;

	/* Indicate to the BMC that we are busy */
	bt_set_h_busy(true);

	/* Clear B2H_ATN and read pointer */
	bt_outb(BT_CTRL_B2H_ATN, BT_CTRL);
	bt_outb(BT_CTRL_CLR_RD_PTR, BT_CTRL);

	/* Read the response */
	/* Byte 1 - Length (includes header size) */
	resp_len = bt_inb(BT_HOST2BMC) - BT_MIN_RESP_LEN;

	/* Byte 2 - NetFn/LUN */
	netfn = bt_inb(BT_HOST2BMC);

	/* Byte 3 - Seq */
	seq = bt_inb(BT_HOST2BMC);

	/* Byte 4 - Cmd */
	cmd = bt_inb(BT_HOST2BMC);

	/* Byte 5 - Completion Code */
	cc = bt_inb(BT_HOST2BMC);

	/* Find the corresponding message */
	if (inflight_bt_msg == NULL || inflight_bt_msg->seq != seq) {
		/* A response to a message we no longer care about. */
		prlog(PR_INFO, "Nobody cared about a response to an BT/IPMI message"
		       "(seq 0x%02x netfn 0x%02x cmd 0x%02x)\n", seq, (netfn >> 2), cmd);
		bt_flush_msg();
		return;
	}

	ipmi_msg = &inflight_bt_msg->ipmi_msg;

	/*
	 * Make sure we have enough room to store the response. As all values
	 * are unsigned we will also trigger this error if
	 * bt_inb(BT_HOST2BMC) < BT_MIN_RESP_LEN (which should never occur).
	 */
	if (resp_len > ipmi_msg->resp_size) {
		BT_Q_ERR(inflight_bt_msg, "Invalid resp_len %d", resp_len);
		resp_len = ipmi_msg->resp_size;
		cc = IPMI_ERR_MSG_TRUNCATED;
	}
	ipmi_msg->resp_size = resp_len;

	/* Byte 6:N - Data */
	for (i = 0; i < resp_len; i++)
		ipmi_msg->data[i] = bt_inb(BT_HOST2BMC);
	bt_set_h_busy(false);

	BT_Q_TRACE(inflight_bt_msg, "IPMI MSG done");

	list_del(&inflight_bt_msg->link);
	/* Ready to send next message */
	inflight_bt_msg = NULL;
	bt.queue_len--;
	unlock(&bt.lock);

	/* Call IPMI layer to finish processing the message. */
	ipmi_cmd_done(cmd, netfn, cc, ipmi_msg);
	lock(&bt.lock);

	return;
}

static void bt_expire_old_msg(uint64_t tb)
{
	struct bt_msg *bt_msg = inflight_bt_msg;

	if (bt_msg && bt_msg->tb > 0 && !chip_quirk(QUIRK_SIMICS) &&
	    (tb_compare(tb, bt_msg->tb +
			secs_to_tb(bt.caps.msg_timeout)) == TB_AAFTERB)) {
		if (bt_msg->send_count <= bt.caps.max_retries &&
		    !bt_msg->disable_retry) {
			/* A message timeout is usually due to the BMC
			 * clearing the H2B_ATN flag without actually
			 * doing anything. The data will still be in the
			 * FIFO so just reset the flag.*/
			BT_Q_ERR(bt_msg, "Retry sending message");

			/* This means we have started message timeout, but not
			 * yet sent message to BMC as driver was not free to
			 * send message. Lets resend message.
			 */
			if (bt_msg->send_count == 0)
				bt_send_msg(bt_msg);
			else
				bt_outb(BT_CTRL_H2B_ATN, BT_CTRL);

			bt_msg->send_count++;
			bt_msg->tb = tb;
		} else {
			BT_Q_ERR(bt_msg, "Timeout sending message");
			bt_msg_del(bt_msg);

			/*
			 * Timing out a message is inherently racy as the BMC
			 * may start writing just as we decide to kill the
			 * message. Hopefully resetting the interface is
			 * sufficient to guard against such things.
			 */
			bt_reset_interface();
		}
	}
}

#if BT_QUEUE_DEBUG
static void print_debug_queue_info(void)
{
	struct bt_msg *msg;
	static bool printed;

	if (!list_empty(&bt.msgq_sync) || !list_empty(&bt.msgq)) {
		printed = false;
		prlog(PR_DEBUG, "-------- BT Sync Msg Queue -------\n");
		list_for_each(&bt.msgq_sync, msg, link) {
			BT_Q_DBG(msg, "[ sent %d ]", msg->send_count);
		}
		prlog(PR_DEBUG, "---------- BT Msg Queue ----------\n");
		list_for_each(&bt.msgq, msg, link) {
			BT_Q_DBG(msg, "[ sent %d ]", msg->send_count);
		}
		prlog(PR_DEBUG, "----------------------------------\n");
	} else if (!printed) {
		printed = true;
		prlog(PR_DEBUG, "------- BT Msg Queue Empty -------\n");
	}
}
#endif

static void bt_send_and_unlock(void)
{
	/* Busy? */
	if (inflight_bt_msg)
		goto out_unlock;

	if (!lpc_ok())
		goto out_unlock;

	/* Synchronous messages gets priority over normal message */
	if (!list_empty(&bt.msgq_sync))
		inflight_bt_msg = list_top(&bt.msgq_sync, struct bt_msg, link);
	else if (!list_empty(&bt.msgq))
		inflight_bt_msg = list_top(&bt.msgq, struct bt_msg, link);
	else
		goto out_unlock;

	assert(inflight_bt_msg);
	/*
	 * Start the message timeout once it gets to the top
	 * of the queue. This will ensure we timeout messages
	 * in the case of a broken bt interface as occurs when
	 * the BMC is not responding to any IPMI messages.
	 */
	if (inflight_bt_msg->tb == 0)
		inflight_bt_msg->tb = mftb();

	/*
	 * Only send it if we haven't already.
	 * Timeouts and retries happen in bt_expire_old_msg()
	 * called from bt_poll()
	 */
	if (bt_idle() && inflight_bt_msg->send_count == 0)
		bt_send_msg(inflight_bt_msg);

out_unlock:
	unlock(&bt.lock);
}

static void bt_poll(struct timer *t __unused, void *data __unused,
		    uint64_t now)
{
	uint8_t bt_ctrl;

	/* Don't do anything if the LPC bus is offline */
	if (!lpc_ok())
		return;

	/*
	 * If we can't get the lock assume someone else will notice
	 * the new message and process it.
	 */
	lock(&bt.lock);

#if BT_QUEUE_DEBUG
	print_debug_queue_info();
#endif

	bt_ctrl = bt_inb(BT_CTRL);

	/* Is there a response waiting for us? */
	if (bt_ctrl & BT_CTRL_B2H_ATN)
		bt_get_resp();

	bt_expire_old_msg(now);

	/* Check for sms_atn */
	if (bt_inb(BT_CTRL) & BT_CTRL_SMS_ATN) {
		bt_outb(BT_CTRL_SMS_ATN, BT_CTRL);
		unlock(&bt.lock);
		ipmi_sms_attention();
		lock(&bt.lock);
	}

	/*
	 * Send messages if we can. If the BMC was really quick we
	 * could loop back to the start and check for a response
	 * instead of unlocking, but testing shows the BMC isn't that
	 * fast so we will wait for the IRQ or a call to the pollers instead.
	 */
	bt_send_and_unlock();

	schedule_timer(&bt.poller,
		       bt.irq_ok ? TIMER_POLL : msecs_to_tb(BT_DEFAULT_POLL_MS));
}

static void bt_ipmi_poll(void)
{
	bt_poll(NULL, NULL, mftb());
}

static void bt_add_msg(struct bt_msg *bt_msg)
{
	bt_msg->tb = 0;
	bt_msg->seq = ipmi_seq++;
	bt_msg->send_count = 0;
	bt.queue_len++;
	if (bt.queue_len > BT_MAX_QUEUE_LEN) {
		/* Maximum queue length exceeded, remove oldest messages. */
		BT_Q_ERR(bt_msg, "Maximum queue length exceeded");
		/* First try to remove message from normal queue */
		if (!list_empty(&bt.msgq))
			bt_msg = list_tail(&bt.msgq, struct bt_msg, link);
		else if (!list_empty(&bt.msgq_sync))
			bt_msg = list_tail(&bt.msgq_sync, struct bt_msg, link);
		assert(bt_msg);
		BT_Q_ERR(bt_msg, "Removed from queue");
		bt_msg_del(bt_msg);
	}
}

/* Add message to synchronous message list */
static int bt_add_ipmi_msg_head(struct ipmi_msg *ipmi_msg)
{
	struct bt_msg *bt_msg = container_of(ipmi_msg, struct bt_msg, ipmi_msg);

	lock(&bt.lock);
	bt_add_msg(bt_msg);
	list_add_tail(&bt.msgq_sync, &bt_msg->link);
	bt_send_and_unlock();

	return 0;
}

static int bt_add_ipmi_msg(struct ipmi_msg *ipmi_msg)
{
	struct bt_msg *bt_msg = container_of(ipmi_msg, struct bt_msg, ipmi_msg);

	lock(&bt.lock);
	bt_add_msg(bt_msg);
	list_add_tail(&bt.msgq, &bt_msg->link);
	bt_send_and_unlock();

	return 0;
}

static void bt_irq(uint32_t chip_id __unused, uint32_t irq_mask __unused)
{
	uint8_t ireg;

	ireg = bt_inb(BT_INTMASK);

	bt.irq_ok = true;
	if (ireg & BT_INTMASK_B2H_IRQ) {
		bt_outb(BT_INTMASK_B2H_IRQ | BT_INTMASK_B2H_IRQEN, BT_INTMASK);
		bt_poll(NULL, NULL, mftb());
	}
}

/*
 * Allocate an ipmi message and bt container and return the ipmi
 * message struct. Allocates enough space for the request and response
 * data.
 */
static struct ipmi_msg *bt_alloc_ipmi_msg(size_t request_size, size_t response_size)
{
	struct bt_msg *bt_msg;

	bt_msg = zalloc(sizeof(struct bt_msg) + MAX(request_size, response_size));
	if (!bt_msg)
		return NULL;

	bt_msg->ipmi_msg.req_size = request_size;
	bt_msg->ipmi_msg.resp_size = response_size;
	bt_msg->ipmi_msg.data = (uint8_t *) (bt_msg + 1);

	return &bt_msg->ipmi_msg;
}

/*
 * Free a previously allocated ipmi message.
 */
static void bt_free_ipmi_msg(struct ipmi_msg *ipmi_msg)
{
	struct bt_msg *bt_msg = container_of(ipmi_msg, struct bt_msg, ipmi_msg);

	free(bt_msg);
}

/*
 * Do not resend IPMI messages to BMC.
 */
static void bt_disable_ipmi_msg_retry(struct ipmi_msg *ipmi_msg)
{
	struct bt_msg *bt_msg = container_of(ipmi_msg, struct bt_msg, ipmi_msg);

	bt_msg->disable_retry = true;
}

/*
 * Remove a message from the queue. The memory allocated for the ipmi message
 * will need to be freed by the caller with bt_free_ipmi_msg() as it will no
 * longer be in the queue of messages.
 */
static int bt_del_ipmi_msg(struct ipmi_msg *ipmi_msg)
{
	struct bt_msg *bt_msg = container_of(ipmi_msg, struct bt_msg, ipmi_msg);

	lock(&bt.lock);
	list_del(&bt_msg->link);
	bt.queue_len--;
	bt_send_and_unlock();
	return 0;
}

static struct ipmi_backend bt_backend = {
	.alloc_msg = bt_alloc_ipmi_msg,
	.free_msg = bt_free_ipmi_msg,
	.queue_msg = bt_add_ipmi_msg,
	.queue_msg_head = bt_add_ipmi_msg_head,
	.dequeue_msg = bt_del_ipmi_msg,
	.disable_retry = bt_disable_ipmi_msg_retry,
	.poll = bt_ipmi_poll,
};

static struct lpc_client bt_lpc_client = {
	.interrupt = bt_irq,
};

void bt_init(void)
{
	struct dt_node *n;
	const struct dt_property *prop;
	uint32_t irq;

	/* Set sane capability defaults */
	bt.caps.num_requests = 1;
	bt.caps.input_buf_len = BT_FIFO_LEN;
	bt.caps.output_buf_len = BT_FIFO_LEN;
	bt.caps.msg_timeout = BT_MSG_TIMEOUT;
	bt.caps.max_retries = BT_MAX_RETRIES;

	/* We support only one */
	n = dt_find_compatible_node(dt_root, NULL, "ipmi-bt");
	if (!n) {
		prerror("No BT device\n");
		return;
	}

	/* Get IO base */
	prop = dt_find_property(n, "reg");
	if (!prop) {
		prerror("Can't find reg property\n");
		return;
	}
	if (dt_property_get_cell(prop, 0) != OPAL_LPC_IO) {
		prerror("Only supports IO addresses\n");
		return;
	}
	bt.base_addr = dt_property_get_cell(prop, 1);
	init_timer(&bt.poller, bt_poll, NULL);

	bt_init_interface();
	init_lock(&bt.lock);

	/*
	 * The iBT interface comes up in the busy state until the daemon has
	 * initialised it.
	 */
	list_head_init(&bt.msgq);
	list_head_init(&bt.msgq_sync);
	inflight_bt_msg = NULL;
	bt.queue_len = 0;

	prlog(PR_INFO, "Interface initialized, IO 0x%04x\n", bt.base_addr);

	ipmi_register_backend(&bt_backend);

	/*
	 * We initially schedule the poller as a relatively fast timer, at
	 * least until we have at least one interrupt occurring at which
	 * point we turn it into a background poller
	 */
	schedule_timer(&bt.poller, msecs_to_tb(BT_DEFAULT_POLL_MS));

	irq = dt_prop_get_u32(n, "interrupts");
	bt_lpc_client.interrupts = LPC_IRQ(irq);
	lpc_register_client(dt_get_chip_id(n), &bt_lpc_client,
			    IRQ_ATTR_TARGET_OPAL);

	/* Enqueue an IPMI message to ask the BMC about its BT capabilities */
	get_bt_caps();

	prlog(PR_DEBUG, "Using LPC IRQ %d\n", irq);
}
