// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// Copyright 2022 IBM Corp.

#define pr_fmt(fmt) "PLDM: " fmt

#include <cpu.h>
#include <opal.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <libpldm/base.h>
#include "pldm.h"

static uint8_t bmc_tid = -1;

uint8_t pldm_base_get_bmc_tid(void)
{
	return bmc_tid;
}

/*
 * Create a PLDM request message for GetTID.
 */
int pldm_base_get_tid_req(void)
{
	size_t data_size = PLDM_MSG_SIZE(0); /* the command doesn't have a message payload */
	size_t response_len, payload_len;
	struct pldm_tx_data *tx = NULL;
	void *response_msg;
	int rc;

	struct pldm_get_tid_resp response;

	/* Encode the get tid request */
	tx = zalloc(sizeof(struct pldm_tx_data) + data_size);
	if (!tx)
		return OPAL_NO_MEM;
	tx->data_size = data_size;

	rc = encode_get_tid_req(DEFAULT_INSTANCE_ID,
				(struct pldm_msg *)tx->data);
	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "Encode GetTID Error, rc: %d\n", rc);
		free(tx);
		return OPAL_PARAMETER;
	}

	/* Send and get the response message bytes */
	rc = pldm_requester_queue_and_wait(tx, &response_msg, &response_len);
	if (rc) {
		prlog(PR_ERR, "Communication Error, req: GetTID, rc: %d\n", rc);
		free(tx);
		return rc;
	}

	/* Decode the message */
	payload_len = response_len - sizeof(struct pldm_msg_hdr);

	rc = decode_get_tid_resp(response_msg, payload_len,
				 &response.completion_code,
				 &response.tid);
	if ((rc != PLDM_SUCCESS) || (response.completion_code != PLDM_SUCCESS)) {
		prlog(PR_ERR, "Decode GetTID Error, rc: %d, cc: %d\n",
			      rc, response.completion_code);
		free(tx);
		free(response_msg);
		return OPAL_PARAMETER;
	}

	prlog(PR_INFO, "BMC's TID is %d\n", response.tid);
	bmc_tid = response.tid;
	free(tx);
	free(response_msg);

	return OPAL_SUCCESS;
}
