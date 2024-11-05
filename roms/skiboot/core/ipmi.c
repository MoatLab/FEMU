// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * in-band IPMI, probably over bt (or via FSP mbox on FSP)
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <stdio.h>
#include <string.h>
#include <bt.h>
#include <ipmi.h>
#include <opal.h>
#include <device.h>
#include <skiboot.h>
#include <lock.h>
#include <cpu.h>
#include <timebase.h>
#include <debug_descriptor.h>

struct ipmi_backend *ipmi_backend = NULL;
static struct lock sync_lock = LOCK_UNLOCKED;
static struct ipmi_msg *sync_msg = NULL;

void ipmi_free_msg(struct ipmi_msg *msg)
{
	/* ipmi_free_msg frees messages allocated by the
	 * backend. Without a backend we couldn't have allocated
	 * messages to free (we don't support removing backends
	 * yet). */
	if (!ipmi_present()) {
		prerror("IPMI: Trying to free message without backend\n");
		return;
	}

	msg->backend->free_msg(msg);
}

void ipmi_init_msg(struct ipmi_msg *msg, int interface,
		   uint32_t code, void (*complete)(struct ipmi_msg *),
		   void *user_data, size_t req_size, size_t resp_size)
{
	/* We don't actually support multiple interfaces at the moment. */
	assert(interface == IPMI_DEFAULT_INTERFACE);

	msg->backend = ipmi_backend;
	msg->cmd = IPMI_CMD(code);
	msg->netfn = IPMI_NETFN(code) << 2;
	msg->req_size = req_size;
	msg->resp_size = resp_size;
	msg->complete = complete;
	msg->user_data = user_data;
}

struct ipmi_msg *ipmi_mkmsg_simple(uint32_t code, void *req_data, size_t req_size)
{
	return ipmi_mkmsg(IPMI_DEFAULT_INTERFACE, code, ipmi_free_msg, NULL,
			  req_data, req_size, 0);
}

struct ipmi_msg *ipmi_mkmsg(int interface, uint32_t code,
			    void (*complete)(struct ipmi_msg *),
			    void *user_data, void *req_data, size_t req_size,
			    size_t resp_size)
{
	struct ipmi_msg *msg;

	if (!ipmi_present())
		return NULL;

	msg = ipmi_backend->alloc_msg(req_size, resp_size);
	if (!msg)
		return NULL;

	ipmi_init_msg(msg, interface, code, complete, user_data, req_size,
		      resp_size);

	/* Commands are free to over ride this if they want to handle errors */
	msg->error = ipmi_free_msg;

	if (req_data)
		memcpy(msg->data, req_data, req_size);

	return msg;
}

int ipmi_queue_msg_head(struct ipmi_msg *msg)
{
	if (!ipmi_present())
		return OPAL_HARDWARE;

	if (!msg) {
		prerror("%s: Attempting to queue NULL message\n", __func__);
		return OPAL_PARAMETER;
	}

	return msg->backend->queue_msg_head(msg);
}

int ipmi_queue_msg(struct ipmi_msg *msg)
{
	/* Here we could choose which interface to use if we want to support
	   multiple interfaces. */
	if (!ipmi_present())
		return OPAL_HARDWARE;

	if (!msg) {
		prerror("%s: Attempting to queue NULL message\n", __func__);
		return OPAL_PARAMETER;
	}

	return msg->backend->queue_msg(msg);
}

int ipmi_dequeue_msg(struct ipmi_msg *msg)
{
	if (!ipmi_present())
		return OPAL_HARDWARE;

	if (!msg) {
		prerror("%s: Attempting to dequeue NULL message\n", __func__);
		return OPAL_PARAMETER;
	}

	return msg->backend->dequeue_msg(msg);
}

void ipmi_cmd_done(uint8_t cmd, uint8_t netfn, uint8_t cc, struct ipmi_msg *msg)
{
	msg->cc = cc;
	if (msg->cmd != cmd) {
		prerror("IPMI: Incorrect cmd 0x%02x in response\n", cmd);
		cc = IPMI_ERR_UNSPECIFIED;
	}

	if ((msg->netfn >> 2) + 1 != (netfn >> 2)) {
		prerror("IPMI: Incorrect netfn 0x%02x in response\n", netfn >> 2);
		cc = IPMI_ERR_UNSPECIFIED;
	}
	msg->netfn = netfn;

	if (cc != IPMI_CC_NO_ERROR) {
		prlog(PR_DEBUG, "IPMI: Got error response. cmd=0x%x, netfn=0x%x,"
		      " rc=0x%02x\n", msg->cmd, msg->netfn >> 2, msg->cc);

		assert(msg->error);
		msg->error(msg);
	} else if (msg->complete)
		msg->complete(msg);

	/* At this point the message has should have been freed by the
	   completion functions. */

	/* If this is a synchronous message flag that we are done */
	if (msg == sync_msg) {
		sync_msg = NULL;
		barrier();
	}
}

void ipmi_queue_msg_sync(struct ipmi_msg *msg)
{
	void (*poll)(void) = msg->backend->poll;

	if (!ipmi_present())
		return;

	if (!msg) {
		prerror("%s: Attempting to queue NULL message\n", __func__);
		return;
	}

	lock(&sync_lock);
	while (sync_msg);
	sync_msg = msg;
	if (msg->backend->disable_retry && !opal_booting())
		msg->backend->disable_retry(msg);
	ipmi_queue_msg_head(msg);
	unlock(&sync_lock);

	/*
	 * BT response handling relies on a timer. We can't just run all
	 * timers because we may have been called with a lock that a timer
	 * wants, and they're generally not written to cope with that.
	 * So, just run whatever the IPMI backend needs to make forward
	 * progress.
	 */
	while (sync_msg == msg) {
		if (poll)
			poll();
		time_wait_ms(10);
	}
}

static void ipmi_read_event_complete(struct ipmi_msg *msg)
{
	prlog(PR_DEBUG, "IPMI read event %02x complete: %d bytes. cc: %02x\n",
	      msg->cmd, msg->resp_size, msg->cc);

	/* Handle power control & PNOR handshake events */
	ipmi_parse_sel(msg);

	ipmi_free_msg(msg);
}

static void ipmi_get_message_flags_complete(struct ipmi_msg *msg)
{
	uint8_t flags = msg->data[0];

	ipmi_free_msg(msg);

	prlog(PR_DEBUG, "IPMI Get Message Flags: %02x\n", flags);

	/* Once we see an interrupt we assume the payload has
	 * booted. We disable the wdt and let the OS setup its own
	 * wdt.
	 *
	 * This is also where we consider the OS to be booted, so we set
	 * the boot count sensor */
	if (flags & IPMI_MESSAGE_FLAGS_WATCHDOG_PRE_TIMEOUT) {
		ipmi_wdt_stop();
		ipmi_set_boot_count();
	}

	/* Message available in the event buffer? Queue a Read Event command
	 * to retrieve it. The flag is cleared by performing a read */
	if (flags & IPMI_MESSAGE_FLAGS_EVENT_BUFFER) {
		msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE, IPMI_READ_EVENT,
				ipmi_read_event_complete, NULL, NULL, 0, 16);
		ipmi_queue_msg(msg);
	}
}

void ipmi_sms_attention(void)
{
	struct ipmi_msg *msg;

	if (!ipmi_present())
		return;

	/* todo: when we handle multiple IPMI interfaces, we'll need to
	 * ensure that this message is associated with the appropriate
	 * backend. */
	msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE, IPMI_GET_MESSAGE_FLAGS,
			ipmi_get_message_flags_complete, NULL, NULL, 0, 1);

	ipmi_queue_msg(msg);
}

void ipmi_register_backend(struct ipmi_backend *backend)
{
	/* We only support one backend at the moment */
	assert(backend->alloc_msg);
	assert(backend->free_msg);
	assert(backend->queue_msg);
	assert(backend->dequeue_msg);
	ipmi_backend = backend;
	ipmi_backend->opal_event_ipmi_recv = opal_dynamic_event_alloc();
}

bool ipmi_present(void)
{
	return ipmi_backend != NULL;
}
