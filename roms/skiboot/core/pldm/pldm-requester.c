// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// Copyright 2022 IBM Corp.

#define pr_fmt(fmt) "PLDM: " fmt

#include <cpu.h>
#include <stdio.h>
#include <string.h>
#include <timebase.h>
#include <ast.h>
#include <libpldm/utils.h>
#include "pldm.h"

#define TIMEOUT_MS 8000

struct pldm_request {
	struct list_node link;

	/* originating request params */
	struct pldm_header_info hdrinf;

	/* messages requested */
	struct pldm_tx_data *tx;

	/* timeout handling */
	struct timer timeout;
	uint64_t timeout_ms;
	uint64_t start_time;

	/* completion callback */
	void (*complete)(struct pldm_rx_data *rx, void *data);
	void *complete_data;
};

struct pldm_response {
	void **msg;
	size_t *msg_size;
	bool done;
	int rc;
};

/* pldm requests queue */
static struct lock pldm_requests_lock = LOCK_UNLOCKED;
static LIST_HEAD(list_pldm_requests);

static struct pldm_request *active_request;

static bool matches_request(const struct pldm_rx_data *rx,
			    const struct pldm_request *req)
{
	if (req->hdrinf.instance != rx->hdrinf.instance)
		return false;
	if (req->hdrinf.pldm_type != rx->hdrinf.pldm_type)
		return false;
	if (req->hdrinf.command != rx->hdrinf.command)
		return false;

	return true;
}

static void send_and_wait_complete(struct pldm_rx_data *rx, void *data)
{
	struct pldm_response *resp = (struct pldm_response *)data;
	int len;

	if (rx != NULL) {
		len = rx->msg_len;
		*resp->msg_size = len;
		*resp->msg = zalloc(len);
		memcpy(*resp->msg, rx->msg, len);

		resp->rc = OPAL_SUCCESS;
	} else {
		*resp->msg_size = 0;
		*resp->msg = NULL;
		resp->rc = OPAL_TIMEOUT;
	}

	resp->done = true;
}

static void handle_response(struct pldm_rx_data *rx)
{
	uint64_t now;

	if (active_request == NULL) {
		prlog(PR_ERR, "%s: No active request\n", __func__);
		return;
	}

	/* unactivate the timer */
	if (rx != NULL)
		cancel_timer(&active_request->timeout);

	if (active_request->complete)
		active_request->complete(rx, active_request->complete_data);

	now = mftb();
	prlog(PR_TRACE, "%s: Finished after %ldms, t:%d c:%d i:%d\n",
			__func__,
			tb_to_msecs(now - active_request->start_time),
			active_request->hdrinf.pldm_type,
			active_request->hdrinf.command,
			active_request->hdrinf.instance);

	free(active_request->tx);
	free(active_request);
	active_request = NULL;
}

/*
 * Timeout :(
 */
static void expiry(struct timer *t __unused, void *data, uint64_t now __unused)
{
	struct pldm_request *req = (struct pldm_request *)data;

	if (active_request == NULL) {
		prlog(PR_ERR, "request timedout! (active request NULL)\n");
		return;
	}

	prlog(PR_ERR, "PLDM: request timedout! (active request: t:0x%x c:0x%x i:%d)\n",
		      active_request->hdrinf.pldm_type,
		      active_request->hdrinf.command,
		      active_request->hdrinf.instance);

	prlog(PR_ERR, "PLDM: Original request t:0x%x c:0x%x i:%d -----\n",
			req->hdrinf.pldm_type,
			req->hdrinf.command, req->hdrinf.instance);

	/* no data received. Finish the procedure */
	handle_response(NULL);
}

/*
 * Handle PLDM message received from the PLDM terminus over MCTP
 */
int pldm_requester_handle_response(struct pldm_rx_data *rx)
{
	/* check the message received */
	if (active_request == NULL) {
		prlog(PR_ERR, "%s: No active request. "
			      "Response received t:%d c:%d i:%d\n",
			      __func__,
			      rx->hdrinf.pldm_type,
			      rx->hdrinf.command,
			      rx->hdrinf.instance);
		return OPAL_WRONG_STATE;
	}

	if (!matches_request(rx, active_request)) {
		prlog(PR_ERR, "%s: Unexpected response! t:%d c:%d i:%d want %d,%d,%d\n",
			      __func__,
			      rx->hdrinf.pldm_type,
			      rx->hdrinf.command,
			      rx->hdrinf.instance,
			      active_request->hdrinf.pldm_type,
			      active_request->hdrinf.command,
			      active_request->hdrinf.instance);
		return OPAL_WRONG_STATE;
	}

	/* The expected message seems correct */
	handle_response(rx);

	return OPAL_SUCCESS;
}

/*
 * Send the PLDM request
 */
static void requests_poller(void *data __unused)
{
	int rc = OPAL_SUCCESS;

	lock(&pldm_requests_lock);

	/* wait for the end of the processing of the current request */
	if (active_request) {
		unlock(&pldm_requests_lock);
		return;
	}

	/* no new request to handle */
	if (list_empty(&list_pldm_requests)) {
		unlock(&pldm_requests_lock);
		return;
	}

	/* remove the first entry in a list */
	active_request = list_pop(&list_pldm_requests,
				  struct pldm_request,
				  link);

	unlock(&pldm_requests_lock);

	/* Start timer to control a timeout from the PLDM terminus */
	init_timer(&active_request->timeout, expiry, active_request);
	schedule_timer(&active_request->timeout,
		       msecs_to_tb(active_request->timeout_ms));
	active_request->start_time = mftb();

	/* Send PLDM message over MCTP */
	prlog(PR_TRACE, "%s: Sending request to BMC t:%d c:%d i:%d -----\n",
			__func__,
			active_request->hdrinf.pldm_type,
			active_request->hdrinf.command,
			active_request->hdrinf.instance);

	rc = pldm_mctp_message_tx(active_request->tx);
	if (rc)
		prlog(PR_ERR, "%s: Error %d while sending request\n",
		      __func__, rc);
}

/*
 * Add PLDM request in the queue
 */
static int queue_request(struct pldm_tx_data *tx,
			 uint64_t timeout_ms,
			 void (*complete)(struct pldm_rx_data *rx, void *data),
			 void *complete_data)
{
	struct pldm_request *pending;
	struct pldm_msg *pldm_msg;
	size_t tx_size;

	tx_size = sizeof(struct pldm_tx_data) + tx->data_size;

	pending = zalloc(sizeof(struct pldm_request));
	if (!pending) {
		prlog(PR_ERR, "%s: failed to allocate request\n", __func__);
		return OPAL_NO_MEM;
	}

	pending->timeout_ms	= timeout_ms;
	pending->complete	= complete;
	pending->complete_data	= complete_data;
	pending->tx		= zalloc(tx_size);
	if (!pending->tx) {
		free(pending);
		prlog(PR_ERR, "%s: failed to allocate pldm packet (size: 0x%lx)\n",
			      __func__, tx_size);
		return OPAL_NO_MEM;
	}

	memcpy(pending->tx, tx, tx_size);

	pldm_msg = (struct pldm_msg *)tx->data;
	if (unpack_pldm_header(&pldm_msg->hdr, &pending->hdrinf)) {
		free(pending->tx);
		free(pending);
		prlog(PR_ERR, "%s: error parsing pldm header\n", __func__);
		return OPAL_PARAMETER;
	}

	/* add an entry at the end of a linked list */
	prlog(PR_TRACE, "%s: Add request t:%d c:%d i:%d -----\n",
			__func__,
			pending->hdrinf.pldm_type,
			pending->hdrinf.command,
			pending->hdrinf.instance);

	lock(&pldm_requests_lock);
	list_add_tail(&list_pldm_requests, &pending->link);
	unlock(&pldm_requests_lock);

	return OPAL_SUCCESS;
}

/*
 * Queue a PLDM request and don't wait.
 * When a response is received, call the associated callback.
 */
int pldm_requester_queue(struct pldm_tx_data *tx,
			 void (*complete)(struct pldm_rx_data *rx, void *data),
			 void *complete_data)
{
	int rc = OPAL_SUCCESS;

	/* Queue PLDM request */
	rc = queue_request(tx, TIMEOUT_MS, complete, complete_data);
	if (rc) {
		prlog(PR_ERR, "%s: error %d while queuing request\n",
			      __func__, rc);
		return rc;
	}

	return rc;
}

/*
 * Queue a PLDM request and spin until we get a response.
 */
int pldm_requester_queue_and_wait(struct pldm_tx_data *tx,
				  void **msg, size_t *msg_size)
{
	struct pldm_response *resp;
	int rc = OPAL_SUCCESS;

	resp = zalloc(sizeof(struct pldm_response));
	if (!resp) {
		prlog(PR_ERR, "%s: failed to allocate response\n", __func__);
		return OPAL_NO_MEM;
	}

	resp->msg = msg;
	resp->msg_size = msg_size;

	rc = pldm_requester_queue(tx, send_and_wait_complete, resp);
	if (rc)
		goto out;

	/* wait for a response from the BMC */
	for (;;) {
		if (resp->done)
			break;

		time_wait_ms(5);
	}
	rc = resp->rc;

out:
	free(resp);
	return rc;
}

int pldm_requester_init(void)
{
	/* requests poller */
	opal_add_poller(requests_poller, NULL);

	return OPAL_SUCCESS;
}
