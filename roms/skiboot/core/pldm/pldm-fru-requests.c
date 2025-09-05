// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// Copyright 2022 IBM Corp.

#define pr_fmt(fmt) "PLDM: " fmt

#include <cpu.h>
#include <opal.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <libpldm/fru.h>
#include "pldm.h"

static void *fru_record_table;
static size_t fru_record_length;

static void *local_fru_record_table;
static size_t local_fru_table_length;

static bool fru_ready;
static char *bmc_version;

static void fru_init_complete(bool success)
{
	/* Read not successful, error out and free the buffer */
	if (!success) {
		fru_ready = false;

		if (fru_record_table != NULL) {
			free(fru_record_table);
			fru_record_length = 0;
		}
		return;
	}

	/* Mark ready */
	fru_ready = true;
}

int pldm_fru_get_bmc_version(void *bv, int len)
{
	if (bv == NULL)
		return OPAL_PARAMETER;

	if (bmc_version == NULL)
		return OPAL_PARAMETER;

	if (strlen(bmc_version) > (len + 1))
		return OPAL_PARAMETER;

	memcpy(bv, bmc_version, strlen(bmc_version) + 1);

	return OPAL_SUCCESS;
}

static int get_fru_record_table_req(void **record_table_data,
				    size_t *record_table_length)
{
	size_t data_size = PLDM_MSG_SIZE(struct pldm_get_fru_record_table_req);
	uint8_t transfer_flag, completion_code;
	size_t response_len, payload_len;
	struct pldm_tx_data *tx = NULL;
	uint32_t next_transfer_handle;
	uint8_t *table_data;
	size_t table_length;
	void *response_msg;
	int rc = OPAL_SUCCESS;

	struct pldm_get_fru_record_table_req fru_record_table_req = {
		.data_transfer_handle = 0, /* (0 if operation op is FIRSTPART) */
		.transfer_operation_flag = PLDM_GET_FIRSTPART,
	};
	payload_len = sizeof(struct pldm_get_fru_record_table_req);

	/* Encode the file table request */
	tx = zalloc(sizeof(struct pldm_tx_data) + data_size);
	if (!tx)
		return OPAL_NO_MEM;
	tx->data_size = data_size;

	rc = encode_get_fru_record_table_req(
			DEFAULT_INSTANCE_ID,
			fru_record_table_req.data_transfer_handle,
			fru_record_table_req.transfer_operation_flag,
			(struct pldm_msg *)tx->data,
			payload_len);
	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "Encode GetFruRecordTableReq Error, rc: %d\n", rc);
		free(tx);
		return OPAL_PARAMETER;
	}

	/* Send and get the response message bytes */
	rc = pldm_requester_queue_and_wait(tx, &response_msg, &response_len);
	if (rc) {
		prlog(PR_ERR, "Communication Error, req: GetFruRecordTableReq, rc: %d\n", rc);
		free(tx);
		return rc;
	}

	/* Decode the message */
	payload_len = response_len - sizeof(struct pldm_msg_hdr);
	table_data = zalloc(payload_len);
	if (!table_data) {
		free(tx);
		return OPAL_NO_MEM;
	}

	rc = decode_get_fru_record_table_resp(
				response_msg,
				payload_len,
				&completion_code,
				&next_transfer_handle,
				&transfer_flag,
				table_data,
				&table_length);
	if (rc != PLDM_SUCCESS || completion_code != PLDM_SUCCESS) {
		prlog(PR_ERR, "Decode GetFruRecordTableReq Error, rc: %d, cc: %d\n",
			      rc, completion_code);
		rc = OPAL_PARAMETER;
		goto out;
	}

	/* we do not support multipart transfer */
	if ((next_transfer_handle != PLDM_GET_NEXTPART) ||
	    (transfer_flag != PLDM_START_AND_END)) {
		prlog(PR_ERR, "Transfert GetFruRecordTableReq not complete, "
			      "transfer_hndl: %d, transfer_flag: %d\n",
			      next_transfer_handle,
			      transfer_flag);
		rc = OPAL_PARAMETER;
		goto out;
	}

	*record_table_length = table_length;
	*record_table_data = zalloc(table_length);
	if (!record_table_data)
		rc = OPAL_NO_MEM;
	else
		memcpy(*record_table_data, table_data, table_length);

out:
	free(tx);
	free(table_data);
	free(response_msg);
	return rc;
}

int pldm_fru_dt_add_bmc_version(void)
{
	struct pldm_fru_record_data_format *data;
	struct pldm_fru_record_tlv *tlv;
	struct dt_node *dt_fw_version;
	uint8_t *record_table;
	int rc = OPAL_SUCCESS;
	size_t record_size;

	if (!fru_ready)
		return OPAL_HARDWARE;

	if (!fru_record_table)
		return OPAL_HARDWARE;

	dt_fw_version = dt_find_by_name(dt_root, "ibm,firmware-versions");
	if (!dt_fw_version)
		return OPAL_HARDWARE;

	/* retrieve the bmc information with
	 * "FRU Record Set Identifier": 1,
	 * "FRU Record Type": "General(1)"
	 * "FRU Field Type": Version
	 *
	 * we can not know size of the record table got by options
	 * in advance, but it must be less than the source table. So
	 * it's safe to use sizeof the source table.
	 */
	record_table = zalloc(fru_record_length);
	if (!record_table)
		return OPAL_NO_MEM;

	record_size = fru_record_length;
	get_fru_record_by_option(
			fru_record_table,
			fru_record_length,
			record_table,
			&record_size,
			1,
			PLDM_FRU_RECORD_TYPE_GENERAL,
			PLDM_FRU_FIELD_TYPE_VERSION);

	if (record_size == 0) {
		prlog(PR_ERR, "%s - no FRU type version found\n", __func__);
		rc = OPAL_PARAMETER;
		goto out;
	}

	/* get tlv value */
	data = (struct pldm_fru_record_data_format *)record_table;
	tlv = (struct pldm_fru_record_tlv *)data->tlvs;
	prlog(PR_DEBUG, "%s - value: %s\n", __func__, tlv->value);

	dt_add_property_string(dt_fw_version, "bmc-firmware-version",
			       tlv->value);

	/* store the bmc version */
	bmc_version = zalloc(tlv->length + 1);
	if (!bmc_version)
		rc = OPAL_NO_MEM;
	else
		memcpy(bmc_version, tlv->value, tlv->length);

out:
	free(record_table);
	return rc;
}

#define RECORD_SET_ID 100

void pldm_fru_set_local_table(uint32_t *table_length,
			      uint16_t *total_record_set_identifiers,
			      uint16_t *total_table_records)
{
	struct pldm_fru_record_data_format *record;
	struct pldm_fru_record_tlv *fru_tlv;
	size_t fru_table_size, record_size;
	char fru_product[] = "IBM, skiboot";

	if (local_fru_record_table) {
		*table_length = local_fru_table_length;
		*total_record_set_identifiers =  1;
		*total_table_records = 1;
		return;
	}

	/* allocate fru table */
	fru_table_size = sizeof(struct pldm_fru_record_data_format) +
			 sizeof(struct pldm_fru_record_tlv) +
			 strlen(fru_product);
	local_fru_record_table = zalloc(fru_table_size);
	if (!local_fru_record_table) {
		prlog(PR_ERR, "%s: failed to allocate fru record table\n",
			      __func__);
		return;
	}

	/* fill fru record data */
	record = (struct pldm_fru_record_data_format *)local_fru_record_table;
	record->record_set_id = htole16(RECORD_SET_ID);
	record->record_type = PLDM_FRU_RECORD_TYPE_GENERAL;
	record->num_fru_fields = 1;
	record->encoding_type = PLDM_FRU_ENCODING_ASCII;

	/* to start, set the size as the start of the TLV structs */
	record_size = offsetof(struct pldm_fru_record_data_format, tlvs);

	/* TLVs data */
	fru_tlv = (struct pldm_fru_record_tlv *)(local_fru_record_table + record_size);
	fru_tlv->type = PLDM_FRU_FIELD_TYPE_OTHER;
	fru_tlv->length = strlen(fru_product);
	memcpy(fru_tlv->value, fru_product, fru_tlv->length);

	/* increment record_size by total size of this TLV */
	record_size += (offsetof(struct pldm_fru_record_tlv, value) + fru_tlv->length);

	*table_length = record_size;
	*total_record_set_identifiers =  1;
	*total_table_records = 1;

	local_fru_table_length = *table_length;
}

int pldm_fru_get_local_table(void **fru_record_table_bytes,
			     uint32_t *fru_record_table_size)
{
	if (!local_fru_record_table)
		return OPAL_PARAMETER;

	*fru_record_table_bytes = local_fru_record_table;
	*fru_record_table_size = local_fru_table_length;

	return OPAL_SUCCESS;
}

int pldm_fru_init(void)
{
	int rc;

	/* get fru record table */
	rc = get_fru_record_table_req(&fru_record_table,
				      &fru_record_length);
	if (rc)
		goto err;

	fru_init_complete(true);
	prlog(PR_DEBUG, "%s - done\n", __func__);

	return OPAL_SUCCESS;

err:
	fru_init_complete(false);
	return rc;
}
