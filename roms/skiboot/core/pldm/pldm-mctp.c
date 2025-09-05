// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// Copyright 2022 IBM Corp.

#define pr_fmt(fmt) "PLDM: " fmt

#include <cpu.h>
#include <opal.h>
#include <stdio.h>
#include <string.h>
#include "pldm.h"

/*
 * PLDM over MCTP (DSP0241)
 *
 * First byte of the MCTP message is the message Type = PLDM
 *    PLDM = 0x01 (000_0001b)
 *
 * Next bytes of the MCTP message (MCTP message body) contain the
 * PLDM message (The base PLDM message fields are defined in DSP0240)
 */

int pldm_mctp_message_tx(struct pldm_tx_data *tx)
{
	tx->mctp_msg_type = MCTP_MSG_TYPE_PLDM;

	return ast_mctp_message_tx(tx->tag_owner, tx->msg_tag,
				   &tx->mctp_msg_type,
				   tx->data_size + sizeof(tx->mctp_msg_type));
}

int pldm_mctp_message_rx(uint8_t eid, bool tag_owner, uint8_t msg_tag,
			 const uint8_t *buf, int len)
{
	struct pldm_rx_data *rx;
	int rc = 0;

	rx = zalloc(sizeof(struct pldm_rx_data));
	if (!rx) {
		prlog(PR_ERR, "failed to allocate rx message\n");
		return OPAL_NO_MEM;
	}

	rx->msg = (struct pldm_msg *)buf;
	rx->source_eid = eid;
	rx->msg_len = len;
	rx->tag_owner = tag_owner;
	rx->msg_tag = msg_tag;

	/* Additional header information */
	if (unpack_pldm_header(&rx->msg->hdr, &rx->hdrinf)) {
		prlog(PR_ERR, "%s: unable to decode header\n", __func__);
		rc = OPAL_EMPTY;
		goto out;
	}

	switch (rx->hdrinf.msg_type) {
	case PLDM_RESPONSE:
		rc = pldm_requester_handle_response(rx);
	break;
	case PLDM_REQUEST:
		rc = pldm_responder_handle_request(rx);
	break;
	default:
		prlog(PR_ERR, "%s: message not supported (msg type: 0%x)\n",
			      __func__, rx->hdrinf.msg_type);
		rc = OPAL_PARAMETER;
	break;
	}

out:
	free(rx);
	return rc;
}

int pldm_mctp_init(void)
{
	int nbr_elt = 8, rc = OPAL_SUCCESS;

	int (*pldm_config[])(void) = {
		ast_mctp_init,		/* MCTP Binding */
		pldm_responder_init,	/* Register mandatory commands we'll respond to */
		pldm_requester_init,	/* Requester implementation */
		pldm_base_get_tid_req,	/* Get BMC tid */
		pldm_platform_init,	/* Get PDRs data */
		pldm_bios_init,		/* Get Bios data */
		pldm_fru_init,		/* Get Fru data */
		pldm_file_io_init,	/* Get FILE IO data */
	};

	const char *pldm_config_error[] = {
		"Failed to bind MCTP",
		"Failed to register mandatory commands",
		"Failed to configure requister",
		"Failed to retrieve BMC Tid",
		"Failed to retrieve Data Records",
		"Failed to retrieve Bios data",
		"Failed to retrieve Fru data",
		"Failed to retrieve File io data",
	};

	prlog(PR_NOTICE, "%s - Getting PLDM data\n", __func__);

	for (int i = 0; i < nbr_elt; i++) {
		rc = pldm_config[i]();
		if (rc) {
			prlog(PR_ERR, "%s\n", pldm_config_error[i]);
			goto out;
		}
	}

out:
	prlog(PR_NOTICE, "%s - done, rc: %d\n", __func__, rc);
	return rc;
}

void pldm_mctp_exit(void)
{
	pldm_platform_exit();

	ast_mctp_exit();
}
