// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// Copyright 2022 IBM Corp.

#define pr_fmt(fmt) "PLDM: " fmt

#include <lock.h>
#include <stdlib.h>
#include <string.h>
#include <opal.h>
#include <timebase.h>
#include <timer.h>
#include <pldm/include/libpldm/platform.h>
#include "pldm.h"

#define DEFAULT_WATCHDOG_TIMEOUT_SEC (10 * 60) /* 10 min */

/* Whether the watchdog timer is armed and Skiboot should be sending
 * regular heartbeats.
 */
bool watchdog_armed;

/* The period (in seconds) of the PLDM watchdog, as dictated by BMC */
int watchdog_period_sec = DEFAULT_WATCHDOG_TIMEOUT_SEC;

static uint8_t sequence_number;
struct timer watchdog_timer;

static void watchdog_reset_timer_complete(struct pldm_rx_data *rx,
					  void *data __unused)
{
	struct pldm_platform_event_message_resp response;
	size_t payload_len;
	int rc;

	if (rx == NULL) {
		prlog(PR_ERR, "%s: Response not received\n", __func__);
		return;
	}

	/* Decode the message */
	payload_len = rx->msg_len - sizeof(struct pldm_msg_hdr);

	rc = decode_platform_event_message_resp(
			rx->msg,
			payload_len,
			&response.completion_code,
			&response.platform_event_status);
	if (rc != PLDM_SUCCESS || response.completion_code != PLDM_SUCCESS) {
		prlog(PR_ERR, "Decode PlatformEventMessage Error, rc: %d, cc: %d, pes: %d\n",
			       rc, response.completion_code,
			       response.platform_event_status);
	}
}

static int pldm_watchdog_reset_timer(void)
{
	uint8_t heartbeat_elapsed_data[2];
	struct pldm_tx_data *tx;
	size_t payload_len;
	size_t data_size;
	int rc;

	struct pldm_platform_event_message_req event_message_req = {
		.format_version = PLDM_PLATFORM_EVENT_MESSAGE_FORMAT_VERSION,
		.tid = HOST_TID,
		.event_class = PLDM_HEARTBEAT_TIMER_ELAPSED_EVENT,
	};

	prlog(PR_TRACE, "%s - send the heartbeat to the BMC, sequence: %d, period: %d\n",
		       __func__, sequence_number, watchdog_period_sec);

	/* Send the event request */
	heartbeat_elapsed_data[0] = PLDM_PLATFORM_EVENT_MESSAGE_FORMAT_VERSION;

	/* We need to make sure that we send the BMC the correct
	 * sequence number. To prevent possible race conditions for the
	 * sequence number, lock it while we're incrementing and
	 * sending it down.
	 */
	heartbeat_elapsed_data[1] = sequence_number++;

	payload_len = PLDM_PLATFORM_EVENT_MESSAGE_MIN_REQ_BYTES + sizeof(heartbeat_elapsed_data);

	data_size = sizeof(struct pldm_msg_hdr) +
		    sizeof(struct pldm_platform_event_message_req) +
		    sizeof(heartbeat_elapsed_data);
	tx = zalloc(sizeof(struct pldm_tx_data) + data_size);
	if (!tx)
		return OPAL_NO_MEM;
	tx->data_size = data_size - 1;

	/* Encode the platform event message request */
	rc = encode_platform_event_message_req(
			DEFAULT_INSTANCE_ID,
			event_message_req.format_version,
			event_message_req.tid,
			event_message_req.event_class,
			heartbeat_elapsed_data,
			sizeof(heartbeat_elapsed_data),
			(struct pldm_msg *)tx->data,
			payload_len);
	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "Encode PlatformEventMessage Error, rc: %d\n", rc);
		free(tx);
		return OPAL_PARAMETER;
	}

	/* Send and get the response message bytes */
	rc = pldm_requester_queue(tx, watchdog_reset_timer_complete, NULL);
	if (rc) {
		prlog(PR_ERR, "Communication Error, req: PlatformEventMessage, rc: %d\n", rc);
		free(tx);
		return rc;
	}

	free(tx);
	return OPAL_SUCCESS;
}

static void watchdog_poller(struct timer *t __unused,
			    void *data __unused,
			    uint64_t now __unused)
{
	/* Whether the watchdog timer is armed and Skiboot should be sending
	 * regular heartbeats.
	 */
	if (watchdog_armed)
		pldm_watchdog_reset_timer();

	schedule_timer(&watchdog_timer, secs_to_tb(watchdog_period_sec));
}

int pldm_watchdog_init(void)
{
	if (watchdog_armed)
		pldm_watchdog_reset_timer();

	init_timer(&watchdog_timer, watchdog_poller, NULL);
	schedule_timer(&watchdog_timer, secs_to_tb(watchdog_period_sec));

	return OPAL_SUCCESS;
}
