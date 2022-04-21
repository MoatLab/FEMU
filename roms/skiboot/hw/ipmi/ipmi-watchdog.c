// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2013-2018 IBM Corp.
 * Copyright 2018 Google Corp.
 */

#include <stdlib.h>
#include <ipmi.h>
#include <lock.h>
#include <opal.h>
#include <device.h>
#include <timer.h>
#include <timebase.h>
#include <pool.h>
#include <skiboot.h>

#define TIMER_USE_DONT_LOG	0x80
#define TIMER_USE_DONT_STOP	0x40
#define TIMER_USE_POST		0x02

/* WDT expiration actions */
#define WDT_PRETIMEOUT_SMI	0x10
#define WDT_RESET_ACTION 	0x01
#define WDT_NO_ACTION		0x00

/* IPMI defined custom completion codes for the watchdog */
#define WDT_CC_OK		0x00
#define WDT_CC_NOT_INITIALIZED	0x80

/* Flags used for IPMI callbacks */
#define WDT_SET_DO_RESET	0x01
#define WDT_RESET_NO_REINIT	0x01

/* How long to set the overall watchdog timeout for. In units of
 * 100ms. If the timer is not reset within this time the watchdog
 * expiration action will occur. */
#define WDT_TIMEOUT		600

/* How often to reset the timer using schedule_timer(). Too short and
we risk accidentally resetting the system due to opal_run_pollers() not
being called in time, too short and we waste time resetting the wdt
more frequently than necessary. */
#define WDT_MARGIN		300

static struct timer wdt_timer;
static bool wdt_stopped;
static bool wdt_ticking;

/* Saved values from the last watchdog set action */
static uint8_t last_action;
static uint16_t last_count;
static uint8_t last_pretimeout;

static void reset_wdt(struct timer *t, void *data, uint64_t now);

static void set_wdt_complete(struct ipmi_msg *msg)
{
	const uintptr_t flags = (uintptr_t)msg->user_data;

	if (flags & WDT_SET_DO_RESET) {
		/* Make sure the reset action does not create a loop and
		 * perform a reset in the case where the BMC send an
		 * uninitialized error. */
		reset_wdt(NULL, (void *)WDT_RESET_NO_REINIT, 0);
	}

	ipmi_free_msg(msg);
}

static void set_wdt(uint8_t action, uint16_t count, uint8_t pretimeout,
		bool dont_stop, bool do_reset)
{
	struct ipmi_msg *ipmi_msg;
	uintptr_t completion_flags = 0;

	if (do_reset)
		completion_flags |= WDT_SET_DO_RESET;

	/* Save the values prior to issuing the set operation so that we can
	 * re-initialize the watchdog in error cases. */
	last_action = action;
	last_count = count;
	last_pretimeout = pretimeout;

	ipmi_msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE, IPMI_SET_WDT,
			      set_wdt_complete, NULL, NULL, 6, 0);
	if (!ipmi_msg) {
		prerror("Unable to allocate set wdt message\n");
		return;
	}
	ipmi_msg->error = set_wdt_complete;
	ipmi_msg->user_data = (void *)completion_flags;
	ipmi_msg->data[0] = TIMER_USE_POST |
		TIMER_USE_DONT_LOG |
		(dont_stop ? TIMER_USE_DONT_STOP : 0);
	ipmi_msg->data[1] = action;			/* Timer Actions */
	ipmi_msg->data[2] = pretimeout;			/* Pre-timeout Interval */
	ipmi_msg->data[3] = 0;				/* Timer Use Flags */
	ipmi_msg->data[4] = count & 0xff;		/* Initial countdown (lsb) */
	ipmi_msg->data[5] = (count >> 8) & 0xff;	/* Initial countdown (msb) */
	ipmi_queue_msg(ipmi_msg);
}

static void reset_wdt_complete(struct ipmi_msg *msg)
{
	const uintptr_t flags = (uintptr_t)msg->user_data;
	uint64_t reset_delay_ms = (WDT_TIMEOUT - WDT_MARGIN) * 100;

	if (msg->cc == WDT_CC_NOT_INITIALIZED &&
			!(flags & WDT_RESET_NO_REINIT)) {
		/* If our timer was not initialized on the BMC side, we should
		 * perform a single attempt to set it up again. */
		set_wdt(last_action, last_count, last_pretimeout, true, true);
	} else if (msg->cc != WDT_CC_OK) {
		/* Use a short (10s) timeout before performing the next reset
		 * if we encounter an unknown error. This makes sure that we
		 * are able to reset and re-initialize the timer since it might
		 * expire. */
		reset_delay_ms = 10 * 1000;
	}

	/* If we are inside of skiboot we need to periodically restart the
	 * timer. Reschedule a reset so it happens before the timeout. */
	if (wdt_ticking)
		schedule_timer(&wdt_timer, msecs_to_tb(reset_delay_ms));

	ipmi_free_msg(msg);
}

static struct ipmi_msg *wdt_reset_mkmsg(void)
{
	struct ipmi_msg *ipmi_msg;

	ipmi_msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE, IPMI_RESET_WDT,
			      reset_wdt_complete, NULL, NULL, 0, 0);
	if (!ipmi_msg) {
		prerror("Unable to allocate reset wdt message\n");
		return NULL;
	}
	ipmi_msg->error = reset_wdt_complete;

	return ipmi_msg;
}

static void sync_reset_wdt(void)
{
	struct ipmi_msg *ipmi_msg;

	if ((ipmi_msg = wdt_reset_mkmsg()))
		ipmi_queue_msg_sync(ipmi_msg);
}

static void reset_wdt(struct timer *t __unused, void *data,
		      uint64_t now __unused)
{
	struct ipmi_msg *ipmi_msg;

	if ((ipmi_msg = wdt_reset_mkmsg())) {
		ipmi_msg->user_data = data;
		ipmi_queue_msg_head(ipmi_msg);
	}
}

void ipmi_wdt_stop(void)
{
	if (!wdt_stopped) {
		/* Make sure the background reset timer is disabled before
		 * stopping the watchdog. If we issue a reset after disabling
		 * the timer, it will be re-enabled. */
		wdt_ticking = false;
		cancel_timer(&wdt_timer);

		/* Configure the watchdog to be disabled and do no action
		 * in case the underlying implementation is buggy and times
		 * out anyway. */
		wdt_stopped = true;
		set_wdt(WDT_NO_ACTION, 100, 0, false, false);
	}
}

void ipmi_wdt_final_reset(void)
{
	/* We can safely stop the timer prior to setting up our final
	 * watchdog timeout since we have enough margin before the
	 * timeout. */
	wdt_ticking = false;
	cancel_timer(&wdt_timer);

	/*
	 * We're going to wait a little while before requiring
	 * BOOTKERNEL to have IPMI watchdog support so that people
	 * can catch up in their development environments.
	 * If you still read this after 2018, send a patch!
	 */
#if 0
	/* Configure the watchdog and make sure it is still enabled */
	set_wdt(WDT_RESET_ACTION | WDT_PRETIMEOUT_SMI, WDT_TIMEOUT,
		WDT_MARGIN/10, true, true);
	sync_reset_wdt();
#else
	set_wdt(WDT_NO_ACTION, 100, 0, false, false);
#endif
	ipmi_set_boot_count();
}

void ipmi_wdt_init(void)
{
	init_timer(&wdt_timer, reset_wdt, NULL);
	set_wdt(WDT_RESET_ACTION, WDT_TIMEOUT, 0, true, false);

	/* Start the WDT. We do it synchronously to make sure it has
	 * started before skiboot continues booting. Otherwise we
	 * could crash before the wdt has actually been started. */
	wdt_ticking = true;
	sync_reset_wdt();

	return;
}
