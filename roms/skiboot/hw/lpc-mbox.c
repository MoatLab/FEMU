// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * LPC MBOX
 *
 * Copyright 2017-2018 IBM Corp.
 */

#define pr_fmt(fmt) "LPC-MBOX: " fmt

#include <skiboot.h>
#include <lpc.h>
#include <console.h>
#include <opal.h>
#include <device.h>
#include <interrupts.h>
#include <processor.h>
#include <errorlog.h>
#include <trace.h>
#include <timebase.h>
#include <timer.h>
#include <cpu.h>
#include <chip.h>
#include <io.h>

#include <lpc-mbox.h>

#define MBOX_FLAG_REG 0x0f
#define MBOX_STATUS_0 0x10
#define MBOX_STATUS_1 0x11
#define   MBOX_STATUS_1_ATTN (1 << 7)
#define   MBOX_STATUS_1_RESP (1 << 5)
#define MBOX_BMC_CTRL 0x12
#define   MBOX_CTRL_INT_STATUS (1 << 7)
#define   MBOX_CTRL_INT_MASK (1 << 1)
#define   MBOX_CTRL_INT_PING (1 << 0)
#define   MBOX_CTRL_INT_SEND (MBOX_CTRL_INT_PING | MBOX_CTRL_INT_MASK)
#define MBOX_HOST_CTRL 0x13
#define MBOX_BMC_INT_EN_0 0x14
#define MBOX_BMC_INT_EN_1 0x15
#define MBOX_HOST_INT_EN_0 0x16
#define MBOX_HOST_INT_EN_1 0x17

#define MBOX_MAX_QUEUE_LEN 5

struct mbox {
	uint32_t base;
	int queue_len;
	bool irq_ok;
	uint8_t seq;
	struct timer poller;
	void (*callback)(struct bmc_mbox_msg *msg, void *priv);
	void *drv_data;
	void (*attn)(uint8_t bits, void *priv);
	void *attn_data;
	struct lock lock;
	uint8_t sequence;
	unsigned long timeout;
};

static struct mbox mbox;

/*
 * MBOX accesses
 */

static void bmc_mbox_outb(uint8_t val, uint8_t reg)
{
	lpc_outb(val, mbox.base + reg);
}

static uint8_t bmc_mbox_inb(uint8_t reg)
{
	return lpc_inb(mbox.base + reg);
}

static void bmc_mbox_recv_message(struct bmc_mbox_msg *msg)
{
	uint8_t *msg_data = (uint8_t *)msg;
	int i;

	for (i = 0; i < BMC_MBOX_READ_REGS; i++)
		msg_data[i] = bmc_mbox_inb(i);
}

/* This needs work, don't write the data bytes that aren't needed */
static void bmc_mbox_send_message(struct bmc_mbox_msg *msg)
{
	uint8_t *msg_data = (uint8_t *)msg;
	int i;

	if (!lpc_ok())
		/* We're going to have to handle this better */
		prlog(PR_ERR, "LPC isn't ok\n");

	for (i = 0; i < BMC_MBOX_WRITE_REGS; i++)
		bmc_mbox_outb(msg_data[i], i);

	/*
	 * Don't touch the response byte - it's setup to generate an interrupt
	 * to the host (us) when written to, or the host status reg - we don't
	 * currently use it, or the BMC status reg - we're not allowed to.
	 */

	/* Ping */
	prlog(PR_TRACE, "Sending BMC interrupt\n");
	bmc_mbox_outb(MBOX_CTRL_INT_SEND, MBOX_HOST_CTRL);
}

int bmc_mbox_enqueue(struct bmc_mbox_msg *msg, unsigned int timeout_sec)
{
	if (!mbox.base) {
		prlog(PR_CRIT, "Using MBOX without init!\n");
		return OPAL_WRONG_STATE;
	}

	lock(&mbox.lock);
	if (mbox.timeout) {
		prlog(PR_DEBUG, "MBOX message already in flight\n");
		if (mftb() > mbox.timeout) {
			prlog(PR_ERR, "In flight message dropped on the floor\n");
		} else {
			unlock(&mbox.lock);
			return OPAL_BUSY;
		}
	}

	mbox.timeout = mftb() + secs_to_tb(timeout_sec);
	msg->seq = ++mbox.sequence;

	bmc_mbox_send_message(msg);
	unlock(&mbox.lock);

	schedule_timer(&mbox.poller, mbox.irq_ok ?
			TIMER_POLL : msecs_to_tb(MBOX_DEFAULT_POLL_MS));

	return 0;
}

static void mbox_poll(struct timer *t __unused, void *data __unused,
		uint64_t now __unused)
{
	struct bmc_mbox_msg msg;

	if (!lpc_ok())
		return;

	/*
	 * This status bit being high means that someone touched the
	 * response byte (byte 13).
	 * There is probably a response for the previously sent commant
	 */
	lock(&mbox.lock);
	if (bmc_mbox_inb(MBOX_STATUS_1) & MBOX_STATUS_1_RESP) {
		/* W1C on that reg */
		bmc_mbox_outb(MBOX_STATUS_1_RESP, MBOX_STATUS_1);

		prlog(PR_INSANE, "Got a regular interrupt\n");

		bmc_mbox_recv_message(&msg);
		if (mbox.sequence != msg.seq) {
			prlog(PR_ERR, "Got a response to a message we no longer care about\n");
			goto out_response;
		}

		mbox.timeout = 0;
		if (mbox.callback)
			mbox.callback(&msg, mbox.drv_data);
		else
			prlog(PR_ERR, "Detected NULL callback for mbox message\n");
	}

out_response:

	/*
	 * The BMC has touched byte 15 to get our attention as it has
	 * something to tell us.
	 */
	if (bmc_mbox_inb(MBOX_STATUS_1) & MBOX_STATUS_1_ATTN) {
		uint8_t action, all;

		/* W1C on that reg */
		bmc_mbox_outb(MBOX_STATUS_1_ATTN, MBOX_STATUS_1);

		all = action = bmc_mbox_inb(MBOX_FLAG_REG);
		prlog(PR_TRACE, "Got a status register interrupt with action 0x%02x\n",
				action);
		if (action & MBOX_ATTN_BMC_REBOOT) {
			/*
			 * It's unlikely that something needs to be done at the
			 * driver level. Let libflash deal with it.
			 * Print something just in case, it is quite a signficant
			 * event.
			 */
			prlog(PR_WARNING, "BMC reset detected\n");
			action &= ~MBOX_ATTN_BMC_REBOOT;
		}

		if (action & MBOX_ATTN_BMC_WINDOW_RESET)
			action &= ~MBOX_ATTN_BMC_WINDOW_RESET;

		if (action & MBOX_ATTN_BMC_FLASH_LOST)
			action &= ~MBOX_ATTN_BMC_FLASH_LOST;

		if (action & MBOX_ATTN_BMC_DAEMON_READY)
			action &= ~MBOX_ATTN_BMC_DAEMON_READY;

		if (action)
			prlog(PR_ERR, "Got a status bit set that don't know about: 0x%02x\n",
					action);

		mbox.attn(all, mbox.attn_data);
	}

	unlock(&mbox.lock);

	schedule_timer(&mbox.poller,
		       mbox.irq_ok ? TIMER_POLL : msecs_to_tb(MBOX_DEFAULT_POLL_MS));
}

static void mbox_irq(uint32_t chip_id __unused, uint32_t irq_mask __unused)
{
	mbox.irq_ok = true;
	mbox_poll(NULL, NULL, 0);
}

static struct lpc_client mbox_lpc_client = {
	.interrupt = mbox_irq,
};

static bool mbox_init_hw(void)
{
	/* Disable all status interrupts except attentions */
	bmc_mbox_outb(0x00, MBOX_HOST_INT_EN_0);
	bmc_mbox_outb(MBOX_STATUS_1_ATTN, MBOX_HOST_INT_EN_1);

	/* Cleanup host interrupt and status */
	bmc_mbox_outb(MBOX_CTRL_INT_STATUS, MBOX_HOST_CTRL);

	/* Disable host control interrupt for now (will be
	 * re-enabled when needed). Clear BMC interrupts
	 */
	bmc_mbox_outb(MBOX_CTRL_INT_MASK, MBOX_BMC_CTRL);

	return true;
}

int bmc_mbox_register_callback(void (*callback)(struct bmc_mbox_msg *msg, void *priv),
		void *drv_data)
{
	mbox.callback = callback;
	mbox.drv_data = drv_data;
	return 0;
}

int bmc_mbox_register_attn(void (*callback)(uint8_t bits, void *priv),
		void *drv_data)
{
	mbox.attn = callback;
	mbox.attn_data = drv_data;
	return 0;
}

uint8_t bmc_mbox_get_attn_reg(void)
{
	return bmc_mbox_inb(MBOX_FLAG_REG);
}

void mbox_init(void)
{
	const struct dt_property *prop;
	struct dt_node *np;
	uint32_t irq, chip_id;

	if (mbox.base) {
		prlog(PR_ERR, "Duplicate call to mbox_init()\n");
		return;
	}

	prlog(PR_DEBUG, "Attempting mbox init\n");
	np = dt_find_compatible_node(dt_root, NULL, "mbox");
	if (!np) {
		/* Only an ERROR on P9 and above, otherwise just
		 * a warning for someone doing development
		 */
		prlog((proc_gen <= proc_gen_p8) ? PR_DEBUG : PR_ERR,
		      "No device tree entry\n");
		return;
	}

	/* Read the interrupts property if any */
	irq = dt_prop_get_u32_def(np, "interrupts", 0);
	if (!irq) {
		prlog(PR_ERR, "No interrupts property\n");
		return;
	}

	if (!lpc_present()) {
		prlog(PR_ERR, "LPC not present\n");
		return;
	}

	/* Get IO base */
	prop = dt_find_property(np, "reg");
	if (!prop) {
		prlog(PR_ERR, "Can't find reg property\n");
		return;
	}
	if (dt_property_get_cell(prop, 0) != OPAL_LPC_IO) {
		prlog(PR_ERR, "Only supports IO addresses\n");
		return;
	}
	mbox.base = dt_property_get_cell(prop, 1);

	if (!mbox_init_hw()) {
		prlog(PR_DEBUG, "Couldn't init HW\n");
		return;
	}

	/* Disable the standard interrupt we don't care */
	bmc_mbox_outb(MBOX_CTRL_INT_MASK, MBOX_HOST_CTRL);

	/* Clear the status reg bits that we intend to use for interrupts */
	/* W1C */
	bmc_mbox_outb(MBOX_STATUS_1_RESP | MBOX_STATUS_1_ATTN, MBOX_STATUS_1);

	mbox.queue_len = 0;
	mbox.callback = NULL;
	mbox.drv_data = NULL;
	mbox.timeout = 0;
	mbox.sequence = 0;
	init_lock(&mbox.lock);

	init_timer(&mbox.poller, mbox_poll, NULL);

	chip_id = dt_get_chip_id(np);
	mbox_lpc_client.interrupts = LPC_IRQ(irq);
	lpc_register_client(chip_id, &mbox_lpc_client, IRQ_ATTR_TARGET_OPAL);

	/* Enable interrupts */
	bmc_mbox_outb(MBOX_STATUS_1_ATTN | MBOX_STATUS_1_RESP, MBOX_HOST_INT_EN_1);

	prlog(PR_DEBUG, "Enabled on chip %d, IO port 0x%x, IRQ %d\n",
	      chip_id, mbox.base, irq);
}


