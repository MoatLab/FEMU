#include <assert.h>
#include <endian.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "base.h"
#include "fru.h"
#include "utils.h"

int encode_get_fru_record_table_metadata_req(uint8_t instance_id,
					     struct pldm_msg *msg,
					     size_t payload_length)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (payload_length != PLDM_GET_FRU_RECORD_TABLE_METADATA_REQ_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_header_info header = { 0 };
	header.instance = instance_id;
	header.msg_type = PLDM_REQUEST;
	header.pldm_type = PLDM_FRU;
	header.command = PLDM_GET_FRU_RECORD_TABLE_METADATA;

	return pack_pldm_header(&header, &(msg->hdr));
}

int decode_get_fru_record_table_metadata_resp(
	const struct pldm_msg *msg, size_t payload_length,
	uint8_t *completion_code, uint8_t *fru_data_major_version,
	uint8_t *fru_data_minor_version, uint32_t *fru_table_maximum_size,
	uint32_t *fru_table_length, uint16_t *total_record_set_identifiers,
	uint16_t *total_table_records, uint32_t *checksum)
{
	if (msg == NULL || completion_code == NULL ||
	    fru_data_major_version == NULL || fru_data_minor_version == NULL ||
	    fru_table_maximum_size == NULL || fru_table_length == NULL ||
	    total_record_set_identifiers == NULL ||
	    total_table_records == NULL || checksum == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*completion_code = msg->payload[0];
	if (PLDM_SUCCESS != *completion_code) {
		return PLDM_SUCCESS;
	}

	if (payload_length != PLDM_GET_FRU_RECORD_TABLE_METADATA_RESP_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_get_fru_record_table_metadata_resp *response =
		(struct pldm_get_fru_record_table_metadata_resp *)msg->payload;

	*fru_data_major_version = response->fru_data_major_version;
	*fru_data_minor_version = response->fru_data_minor_version;
	*fru_table_maximum_size = le32toh(response->fru_table_maximum_size);
	*fru_table_length = le32toh(response->fru_table_length);
	*total_record_set_identifiers =
		le16toh(response->total_record_set_identifiers);
	*total_table_records = le16toh(response->total_table_records);
	*checksum = le32toh(response->checksum);

	return PLDM_SUCCESS;
}

int encode_get_fru_record_table_metadata_resp(
	uint8_t instance_id, uint8_t completion_code,
	uint8_t fru_data_major_version, uint8_t fru_data_minor_version,
	uint32_t fru_table_maximum_size, uint32_t fru_table_length,
	uint16_t total_record_set_identifiers, uint16_t total_table_records,
	uint32_t checksum, struct pldm_msg *msg)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_header_info header = { 0 };
	header.msg_type = PLDM_RESPONSE;
	header.instance = instance_id;
	header.pldm_type = PLDM_FRU;
	header.command = PLDM_GET_FRU_RECORD_TABLE_METADATA;

	uint8_t rc = pack_pldm_header(&header, &(msg->hdr));
	if (PLDM_SUCCESS != rc) {
		return rc;
	}

	struct pldm_get_fru_record_table_metadata_resp *response =
		(struct pldm_get_fru_record_table_metadata_resp *)msg->payload;
	response->completion_code = completion_code;
	if (response->completion_code == PLDM_SUCCESS) {
		response->fru_data_major_version = fru_data_major_version;
		response->fru_data_minor_version = fru_data_minor_version;
		response->fru_table_maximum_size =
			htole32(fru_table_maximum_size);
		response->fru_table_length = htole32(fru_table_length);
		response->total_record_set_identifiers =
			htole16(total_record_set_identifiers);
		response->total_table_records = htole16(total_table_records);
		response->checksum = htole32(checksum);
	}

	return PLDM_SUCCESS;
}

int decode_get_fru_record_table_req(const struct pldm_msg *msg,
				    size_t payload_length,
				    uint32_t *data_transfer_handle,
				    uint8_t *transfer_operation_flag)
{
	if (msg == NULL || data_transfer_handle == NULL ||
	    transfer_operation_flag == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (payload_length != PLDM_GET_FRU_RECORD_TABLE_REQ_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_get_fru_record_table_req *req =
		(struct pldm_get_fru_record_table_req *)msg->payload;

	*data_transfer_handle = le32toh(req->data_transfer_handle);
	*transfer_operation_flag = req->transfer_operation_flag;

	return PLDM_SUCCESS;
}

int encode_get_fru_record_table_resp(uint8_t instance_id,
				     uint8_t completion_code,
				     uint32_t next_data_transfer_handle,
				     uint8_t transfer_flag,
				     struct pldm_msg *msg)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_header_info header = { 0 };
	header.msg_type = PLDM_RESPONSE;
	header.instance = instance_id;
	header.pldm_type = PLDM_FRU;
	header.command = PLDM_GET_FRU_RECORD_TABLE;

	uint8_t rc = pack_pldm_header(&header, &(msg->hdr));
	if (rc > PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_get_fru_record_table_resp *resp =
		(struct pldm_get_fru_record_table_resp *)msg->payload;

	resp->completion_code = completion_code;

	if (resp->completion_code == PLDM_SUCCESS) {
		resp->next_data_transfer_handle =
			htole32(next_data_transfer_handle);
		resp->transfer_flag = transfer_flag;
	}

	return PLDM_SUCCESS;
}

int encode_fru_record(uint8_t *fru_table, size_t total_size, size_t *curr_size,
		      uint16_t record_set_id, uint8_t record_type,
		      uint8_t num_frus, uint8_t encoding, uint8_t *tlvs,
		      size_t tlvs_size)
{
	size_t record_hdr_size = sizeof(struct pldm_fru_record_data_format) -
				 sizeof(struct pldm_fru_record_tlv);

	if (fru_table == NULL || curr_size == NULL || !tlvs_size) {
		return PLDM_ERROR_INVALID_DATA;
	}
	if ((*curr_size + record_hdr_size + tlvs_size) != total_size) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_fru_record_data_format *record =
		(struct pldm_fru_record_data_format *)(fru_table + *curr_size);
	record->record_set_id = htole16(record_set_id);
	record->record_type = record_type;
	record->num_fru_fields = num_frus;
	record->encoding_type = encoding;
	*curr_size += record_hdr_size;

	if (tlvs) {
		memcpy(fru_table + *curr_size, tlvs, tlvs_size);
		*curr_size += tlvs_size;
	}

	return PLDM_SUCCESS;
}

static bool is_table_end(const struct pldm_fru_record_data_format *p,
			 const void *table, size_t table_size)
{
	return p >=
	       (const struct pldm_fru_record_data_format *)((uint8_t *)table +
							    table_size);
}

void get_fru_record_by_option(const uint8_t *table, size_t table_size,
			      uint8_t *record_table, size_t *record_size,
			      uint16_t rsi, uint8_t rt, uint8_t ft)
{
	const struct pldm_fru_record_data_format *record_data_src =
		(const struct pldm_fru_record_data_format *)table;
	struct pldm_fru_record_data_format *record_data_dest;
	int count = 0;

	const struct pldm_fru_record_tlv *tlv;
	size_t len;
	uint8_t *pos = record_table;

	while (!is_table_end(record_data_src, table, table_size)) {
		if ((record_data_src->record_set_id != htole16(rsi) &&
		     rsi != 0) ||
		    (record_data_src->record_type != rt && rt != 0)) {
			tlv = record_data_src->tlvs;
			for (int i = 0; i < record_data_src->num_fru_fields;
			     i++) {
				len = sizeof(*tlv) - 1 + tlv->length;
				tlv = (const struct pldm_fru_record_tlv
					       *)((char *)tlv + len);
			}
			record_data_src =
				(const struct pldm_fru_record_data_format
					 *)(tlv);
			continue;
		}

		len = sizeof(struct pldm_fru_record_data_format) -
		      sizeof(struct pldm_fru_record_tlv);

		assert(pos - record_table + len < *record_size);
		memcpy(pos, record_data_src, len);

		record_data_dest = (struct pldm_fru_record_data_format *)pos;
		pos += len;

		tlv = record_data_src->tlvs;
		count = 0;
		for (int i = 0; i < record_data_src->num_fru_fields; i++) {
			len = sizeof(*tlv) - 1 + tlv->length;
			if (tlv->type == ft || ft == 0) {
				assert(pos - record_table + len < *record_size);
				memcpy(pos, tlv, len);
				pos += len;
				count++;
			}
			tlv = (const struct pldm_fru_record_tlv *)((char *)tlv +
								   len);
		}
		record_data_dest->num_fru_fields = count;
		record_data_src =
			(const struct pldm_fru_record_data_format *)(tlv);
	}

	*record_size = pos - record_table;
}

int encode_get_fru_record_by_option_req(
	uint8_t instance_id, uint32_t data_transfer_handle,
	uint16_t fru_table_handle, uint16_t record_set_identifier,
	uint8_t record_type, uint8_t field_type, uint8_t transfer_op_flag,
	struct pldm_msg *msg, size_t payload_length)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (payload_length !=
	    sizeof(struct pldm_get_fru_record_by_option_req)) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_header_info header = { 0 };
	header.instance = instance_id;
	header.msg_type = PLDM_REQUEST;
	header.pldm_type = PLDM_FRU;
	header.command = PLDM_GET_FRU_RECORD_BY_OPTION;
	uint8_t rc = pack_pldm_header(&header, &(msg->hdr));
	if (rc != PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_get_fru_record_by_option_req *req =
		(struct pldm_get_fru_record_by_option_req *)msg->payload;

	req->data_transfer_handle = htole32(data_transfer_handle);
	req->fru_table_handle = htole16(fru_table_handle);
	req->record_set_identifier = htole16(record_set_identifier);
	req->record_type = record_type;
	req->field_type = field_type;
	req->transfer_op_flag = transfer_op_flag;

	return PLDM_SUCCESS;
}

int decode_get_fru_record_by_option_req(
	const struct pldm_msg *msg, size_t payload_length,
	uint32_t *data_transfer_handle, uint16_t *fru_table_handle,
	uint16_t *record_set_identifier, uint8_t *record_type,
	uint8_t *field_type, uint8_t *transfer_op_flag)
{
	if (msg == NULL || data_transfer_handle == NULL ||
	    fru_table_handle == NULL || record_set_identifier == NULL ||
	    record_type == NULL || field_type == NULL ||
	    transfer_op_flag == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (payload_length !=
	    sizeof(struct pldm_get_fru_record_by_option_req)) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_get_fru_record_by_option_req *req =
		(struct pldm_get_fru_record_by_option_req *)msg->payload;

	*data_transfer_handle = le32toh(req->data_transfer_handle);
	*fru_table_handle = le16toh(req->fru_table_handle);
	*record_set_identifier = le16toh(req->record_set_identifier);
	*record_type = req->record_type;
	*field_type = req->field_type;
	*transfer_op_flag = req->transfer_op_flag;
	return PLDM_SUCCESS;
}

int encode_get_fru_record_by_option_resp(uint8_t instance_id,
					 uint8_t completion_code,
					 uint32_t next_data_transfer_handle,
					 uint8_t transfer_flag,
					 const void *fru_structure_data,
					 size_t data_size, struct pldm_msg *msg,
					 size_t payload_length)
{
	if (msg == NULL || fru_structure_data == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (payload_length !=
	    PLDM_GET_FRU_RECORD_BY_OPTION_MIN_RESP_BYTES + data_size) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_header_info header = { 0 };
	header.instance = instance_id;
	header.msg_type = PLDM_RESPONSE;
	header.pldm_type = PLDM_FRU;
	header.command = PLDM_GET_FRU_RECORD_BY_OPTION;
	uint8_t rc = pack_pldm_header(&header, &(msg->hdr));
	if (rc != PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_get_fru_record_by_option_resp *resp =
		(struct pldm_get_fru_record_by_option_resp *)msg->payload;

	resp->completion_code = completion_code;
	resp->next_data_transfer_handle = htole32(next_data_transfer_handle);
	resp->transfer_flag = transfer_flag;

	if (completion_code == PLDM_SUCCESS) {
		memcpy(resp->fru_structure_data, fru_structure_data, data_size);
	}

	return PLDM_SUCCESS;
}

int decode_get_fru_record_by_option_resp(
	const struct pldm_msg *msg, size_t payload_length,
	uint8_t *completion_code, uint32_t *next_transfer_handle,
	uint8_t *transfer_flag, struct variable_field *fru_structure_data)
{
	if (msg == NULL || completion_code == NULL ||
	    next_transfer_handle == NULL || transfer_flag == NULL ||
	    fru_structure_data == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*completion_code = msg->payload[0];
	if (PLDM_SUCCESS != *completion_code) {
		return PLDM_SUCCESS;
	}

	if (payload_length < PLDM_GET_FRU_RECORD_BY_OPTION_MIN_RESP_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_get_fru_record_by_option_resp *resp =
		(struct pldm_get_fru_record_by_option_resp *)msg->payload;

	*next_transfer_handle = le32toh(resp->next_data_transfer_handle);
	*transfer_flag = resp->transfer_flag;
	fru_structure_data->ptr = resp->fru_structure_data;
	fru_structure_data->length =
		payload_length - PLDM_GET_FRU_RECORD_BY_OPTION_MIN_RESP_BYTES;

	return PLDM_SUCCESS;
}

int encode_get_fru_record_table_req(uint8_t instance_id,
				    uint32_t data_transfer_handle,
				    uint8_t transfer_operation_flag,
				    struct pldm_msg *msg, size_t payload_length)

{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}
	if (payload_length != sizeof(struct pldm_get_fru_record_table_req)) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_header_info header = { 0 };
	header.msg_type = PLDM_REQUEST;
	header.instance = instance_id;
	header.pldm_type = PLDM_FRU;
	header.command = PLDM_GET_FRU_RECORD_TABLE;

	uint8_t rc = pack_pldm_header(&header, &(msg->hdr));
	if (rc != PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_get_fru_record_table_req *req =
		(struct pldm_get_fru_record_table_req *)msg->payload;
	req->data_transfer_handle = htole32(data_transfer_handle);
	req->transfer_operation_flag = transfer_operation_flag;

	return PLDM_SUCCESS;
}

int decode_get_fru_record_table_resp_safe(
	const struct pldm_msg *msg, size_t payload_length,
	uint8_t *completion_code, uint32_t *next_data_transfer_handle,
	uint8_t *transfer_flag, uint8_t *fru_record_table_data,
	size_t *fru_record_table_length, size_t max_fru_record_table_length)
{
	if (msg == NULL || completion_code == NULL ||
	    next_data_transfer_handle == NULL || transfer_flag == NULL ||
	    fru_record_table_data == NULL || fru_record_table_length == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*completion_code = msg->payload[0];
	if (PLDM_SUCCESS != *completion_code) {
		return PLDM_SUCCESS;
	}
	if (payload_length <= PLDM_GET_FRU_RECORD_TABLE_MIN_RESP_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_get_fru_record_table_resp *resp =
		(struct pldm_get_fru_record_table_resp *)msg->payload;

	*next_data_transfer_handle = le32toh(resp->next_data_transfer_handle);
	*transfer_flag = resp->transfer_flag;

	*fru_record_table_length =
		payload_length - PLDM_GET_FRU_RECORD_TABLE_MIN_RESP_BYTES;

	if (*fru_record_table_length > max_fru_record_table_length) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	memcpy(fru_record_table_data, resp->fru_record_table_data,
	       *fru_record_table_length);

	return PLDM_SUCCESS;
}

int decode_get_fru_record_table_resp(const struct pldm_msg *msg,
				     size_t payload_length,
				     uint8_t *completion_code,
				     uint32_t *next_data_transfer_handle,
				     uint8_t *transfer_flag,
				     uint8_t *fru_record_table_data,
				     size_t *fru_record_table_length)
{
	return decode_get_fru_record_table_resp_safe(
		msg, payload_length, completion_code, next_data_transfer_handle,
		transfer_flag, fru_record_table_data, fru_record_table_length,
		(size_t)-1);
}

int decode_set_fru_record_table_req(const struct pldm_msg *msg,
				    size_t payload_length,
				    uint32_t *data_transfer_handle,
				    uint8_t *transfer_flag,
				    struct variable_field *fru_table_data)

{
	if (msg == NULL || data_transfer_handle == NULL ||
	    transfer_flag == NULL || fru_table_data == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (payload_length <= PLDM_SET_FRU_RECORD_TABLE_MIN_REQ_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_set_fru_record_table_req *req =
		(struct pldm_set_fru_record_table_req *)msg->payload;

	*data_transfer_handle = le32toh(req->data_transfer_handle);
	*transfer_flag = req->transfer_flag;
	fru_table_data->length =
		payload_length - PLDM_SET_FRU_RECORD_TABLE_MIN_REQ_BYTES;
	fru_table_data->ptr = req->fru_record_table_data;

	return PLDM_SUCCESS;
}

int encode_set_fru_record_table_resp(uint8_t instance_id,
				     uint8_t completion_code,
				     uint32_t next_data_transfer_handle,
				     size_t payload_length,
				     struct pldm_msg *msg)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}
	if (payload_length != PLDM_SET_FRU_RECORD_TABLE_RESP_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_header_info header = { 0 };
	header.instance = instance_id;
	header.msg_type = PLDM_RESPONSE;
	header.pldm_type = PLDM_FRU;
	header.command = PLDM_SET_FRU_RECORD_TABLE;

	uint8_t rc = pack_pldm_header(&header, &(msg->hdr));
	if (PLDM_SUCCESS != rc) {
		return rc;
	}

	struct pldm_set_fru_record_table_resp *response =
		(struct pldm_set_fru_record_table_resp *)msg->payload;
	response->completion_code = completion_code;
	response->next_data_transfer_handle =
		htole32(next_data_transfer_handle);

	return PLDM_SUCCESS;
}
