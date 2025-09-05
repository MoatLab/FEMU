#include "bios.h"
#include "base.h"
#include "utils.h"
#include <endian.h>
#include <string.h>

int encode_get_date_time_req(uint8_t instance_id, struct pldm_msg *msg)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_header_info header = { 0 };
	header.msg_type = PLDM_REQUEST;
	header.instance = instance_id;
	header.pldm_type = PLDM_BIOS;
	header.command = PLDM_GET_DATE_TIME;
	return pack_pldm_header(&header, &(msg->hdr));
}

int encode_get_date_time_resp(uint8_t instance_id, uint8_t completion_code,
			      uint8_t seconds, uint8_t minutes, uint8_t hours,
			      uint8_t day, uint8_t month, uint16_t year,
			      struct pldm_msg *msg)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_header_info header = { 0 };
	header.msg_type = PLDM_RESPONSE;
	header.instance = instance_id;
	header.pldm_type = PLDM_BIOS;
	header.command = PLDM_GET_DATE_TIME;

	uint8_t rc = pack_pldm_header(&header, &(msg->hdr));
	if (rc != PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_get_date_time_resp *response =
		(struct pldm_get_date_time_resp *)msg->payload;
	response->completion_code = completion_code;
	if (response->completion_code == PLDM_SUCCESS) {
		response->completion_code = completion_code;
		response->seconds = seconds;
		response->minutes = minutes;
		response->hours = hours;
		response->day = day;
		response->month = month;
		response->year = htole16(year);
	}
	return PLDM_SUCCESS;
}

int decode_get_date_time_resp(const struct pldm_msg *msg, size_t payload_length,
			      uint8_t *completion_code, uint8_t *seconds,
			      uint8_t *minutes, uint8_t *hours, uint8_t *day,
			      uint8_t *month, uint16_t *year)
{
	if (msg == NULL || seconds == NULL || minutes == NULL ||
	    hours == NULL || day == NULL || month == NULL || year == NULL ||
	    completion_code == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*completion_code = msg->payload[0];
	if (PLDM_SUCCESS != *completion_code) {
		return PLDM_SUCCESS;
	}

	if (payload_length != PLDM_GET_DATE_TIME_RESP_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_get_date_time_resp *response =
		(struct pldm_get_date_time_resp *)msg->payload;

	*seconds = response->seconds;
	*minutes = response->minutes;
	*hours = response->hours;
	*day = response->day;
	*month = response->month;
	*year = le16toh(response->year);

	return PLDM_SUCCESS;
}

int encode_set_date_time_req(uint8_t instance_id, uint8_t seconds,
			     uint8_t minutes, uint8_t hours, uint8_t day,
			     uint8_t month, uint16_t year, struct pldm_msg *msg,
			     size_t payload_length)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}
	if (payload_length != sizeof(struct pldm_set_date_time_req)) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	if (!is_time_legal(seconds, minutes, hours, day, month, year)) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_header_info header = { 0 };
	header.instance = instance_id;
	header.msg_type = PLDM_REQUEST;
	header.pldm_type = PLDM_BIOS;
	header.command = PLDM_SET_DATE_TIME;

	uint8_t rc = pack_pldm_header(&header, &msg->hdr);
	if (rc != PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_set_date_time_req *request =
		(struct pldm_set_date_time_req *)msg->payload;
	request->seconds = dec2bcd8(seconds);
	request->minutes = dec2bcd8(minutes);
	request->hours = dec2bcd8(hours);
	request->day = dec2bcd8(day);
	request->month = dec2bcd8(month);
	request->year = htole16(dec2bcd16(year));

	return PLDM_SUCCESS;
}

int decode_set_date_time_req(const struct pldm_msg *msg, size_t payload_length,
			     uint8_t *seconds, uint8_t *minutes, uint8_t *hours,
			     uint8_t *day, uint8_t *month, uint16_t *year)
{
	if (msg == NULL || seconds == NULL || minutes == NULL ||
	    hours == NULL || day == NULL || month == NULL || year == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}
	if (payload_length != sizeof(struct pldm_set_date_time_req)) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	const struct pldm_set_date_time_req *request =
		(struct pldm_set_date_time_req *)msg->payload;

	*seconds = bcd2dec8(request->seconds);
	*minutes = bcd2dec8(request->minutes);
	*hours = bcd2dec8(request->hours);
	*day = bcd2dec8(request->day);
	*month = bcd2dec8(request->month);
	*year = bcd2dec16(le16toh(request->year));

	if (!is_time_legal(*seconds, *minutes, *hours, *day, *month, *year)) {
		return PLDM_ERROR_INVALID_DATA;
	}

	return PLDM_SUCCESS;
}

int encode_set_date_time_resp(uint8_t instance_id, uint8_t completion_code,
			      struct pldm_msg *msg, size_t payload_length)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}
	if (payload_length != sizeof(struct pldm_only_cc_resp)) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_header_info header = { 0 };
	header.instance = instance_id;
	header.msg_type = PLDM_RESPONSE;
	header.pldm_type = PLDM_BIOS;
	header.command = PLDM_SET_DATE_TIME;

	uint8_t rc = pack_pldm_header(&header, &msg->hdr);
	if (rc != PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_only_cc_resp *response =
		(struct pldm_only_cc_resp *)msg->payload;
	response->completion_code = completion_code;

	return PLDM_SUCCESS;
}

int decode_set_date_time_resp(const struct pldm_msg *msg, size_t payload_length,
			      uint8_t *completion_code)
{
	if (msg == NULL || completion_code == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*completion_code = msg->payload[0];
	if (PLDM_SUCCESS != *completion_code) {
		return PLDM_SUCCESS;
	}

	if (payload_length != sizeof(struct pldm_only_cc_resp)) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	return PLDM_SUCCESS;
}

int encode_get_bios_table_resp(uint8_t instance_id, uint8_t completion_code,
			       uint32_t next_transfer_handle,
			       uint8_t transfer_flag, uint8_t *table_data,
			       size_t payload_length, struct pldm_msg *msg)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_header_info header = { 0 };
	header.msg_type = PLDM_RESPONSE;
	header.instance = instance_id;
	header.pldm_type = PLDM_BIOS;
	header.command = PLDM_GET_BIOS_TABLE;

	uint8_t rc = pack_pldm_header(&header, &(msg->hdr));
	if (rc != PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_get_bios_table_resp *response =
		(struct pldm_get_bios_table_resp *)msg->payload;
	response->completion_code = completion_code;
	if (response->completion_code == PLDM_SUCCESS) {
		response->next_transfer_handle = htole32(next_transfer_handle);
		response->transfer_flag = transfer_flag;
		if (table_data != NULL &&
		    payload_length > (sizeof(struct pldm_msg_hdr) +
				      PLDM_GET_BIOS_TABLE_MIN_RESP_BYTES)) {
			memcpy(response->table_data, table_data,
			       payload_length -
				       (sizeof(struct pldm_msg_hdr) +
					PLDM_GET_BIOS_TABLE_MIN_RESP_BYTES));
		}
	}
	return PLDM_SUCCESS;
}

int encode_get_bios_table_req(uint8_t instance_id, uint32_t transfer_handle,
			      uint8_t transfer_op_flag, uint8_t table_type,
			      struct pldm_msg *msg)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_header_info header = { 0 };
	header.msg_type = PLDM_REQUEST;
	header.instance = instance_id;
	header.pldm_type = PLDM_BIOS;
	header.command = PLDM_GET_BIOS_TABLE;

	uint8_t rc = pack_pldm_header(&header, &(msg->hdr));
	if (rc != PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_get_bios_table_req *request =
		(struct pldm_get_bios_table_req *)msg->payload;

	request->transfer_handle = htole32(transfer_handle);
	request->transfer_op_flag = transfer_op_flag;
	request->table_type = table_type;
	return PLDM_SUCCESS;
}

int decode_get_bios_table_req(const struct pldm_msg *msg, size_t payload_length,
			      uint32_t *transfer_handle,
			      uint8_t *transfer_op_flag, uint8_t *table_type)
{
	if (msg == NULL || transfer_op_flag == NULL || table_type == NULL ||
	    transfer_handle == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (payload_length != PLDM_GET_BIOS_TABLE_REQ_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_get_bios_table_req *request =
		(struct pldm_get_bios_table_req *)msg->payload;
	*transfer_handle = le32toh(request->transfer_handle);
	*transfer_op_flag = request->transfer_op_flag;
	*table_type = request->table_type;

	return PLDM_SUCCESS;
}

int decode_get_bios_table_resp(const struct pldm_msg *msg,
			       size_t payload_length, uint8_t *completion_code,
			       uint32_t *next_transfer_handle,
			       uint8_t *transfer_flag,
			       size_t *bios_table_offset)

{
	if (msg == NULL || transfer_flag == NULL ||
	    next_transfer_handle == NULL || completion_code == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}
	if (payload_length <= PLDM_GET_BIOS_TABLE_MIN_RESP_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_get_bios_table_resp *response =
		(struct pldm_get_bios_table_resp *)msg->payload;

	*completion_code = response->completion_code;

	if (PLDM_SUCCESS != *completion_code) {
		return PLDM_SUCCESS;
	}

	*next_transfer_handle = le32toh(response->next_transfer_handle);
	*transfer_flag = response->transfer_flag;

	*bios_table_offset = sizeof(*completion_code) +
			     sizeof(*next_transfer_handle) +
			     sizeof(*transfer_flag);

	return PLDM_SUCCESS;
}

int encode_get_bios_attribute_current_value_by_handle_req(
	uint8_t instance_id, uint32_t transfer_handle, uint8_t transfer_op_flag,
	uint16_t attribute_handle, struct pldm_msg *msg)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_header_info header = { 0 };
	header.msg_type = PLDM_REQUEST;
	header.instance = instance_id;
	header.pldm_type = PLDM_BIOS;
	header.command = PLDM_GET_BIOS_ATTRIBUTE_CURRENT_VALUE_BY_HANDLE;

	uint8_t rc = pack_pldm_header(&header, &(msg->hdr));
	if (rc != PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_get_bios_attribute_current_value_by_handle_req *request =
		(struct pldm_get_bios_attribute_current_value_by_handle_req *)
			msg->payload;

	request->transfer_handle = htole32(transfer_handle);
	request->transfer_op_flag = transfer_op_flag;
	request->attribute_handle = htole16(attribute_handle);
	return PLDM_SUCCESS;
}

int decode_get_bios_attribute_current_value_by_handle_resp(
	const struct pldm_msg *msg, size_t payload_length,
	uint8_t *completion_code, uint32_t *next_transfer_handle,
	uint8_t *transfer_flag, struct variable_field *attribute_data)
{
	if (msg == NULL || transfer_flag == NULL ||
	    next_transfer_handle == NULL || completion_code == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_get_bios_attribute_current_value_by_handle_resp *response =
		(struct pldm_get_bios_attribute_current_value_by_handle_resp *)
			msg->payload;

	*completion_code = response->completion_code;

	if (PLDM_SUCCESS != *completion_code) {
		return PLDM_SUCCESS;
	}

	if (payload_length <=
	    PLDM_GET_BIOS_ATTR_CURR_VAL_BY_HANDLE_MIN_RESP_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	*next_transfer_handle = le32toh(response->next_transfer_handle);
	*transfer_flag = response->transfer_flag;

	attribute_data->ptr = response->attribute_data;
	attribute_data->length = payload_length - sizeof(*response) + 1;

	return PLDM_SUCCESS;
}

int decode_get_bios_attribute_current_value_by_handle_req(
	const struct pldm_msg *msg, size_t payload_length,
	uint32_t *transfer_handle, uint8_t *transfer_op_flag,
	uint16_t *attribute_handle)
{
	if (msg == NULL || transfer_handle == NULL ||
	    transfer_op_flag == NULL || attribute_handle == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (payload_length != PLDM_GET_BIOS_ATTR_CURR_VAL_BY_HANDLE_REQ_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_get_bios_attribute_current_value_by_handle_req *request =
		(struct pldm_get_bios_attribute_current_value_by_handle_req *)
			msg->payload;
	*transfer_handle = le32toh(request->transfer_handle);
	*transfer_op_flag = request->transfer_op_flag;
	*attribute_handle = le16toh(request->attribute_handle);

	return PLDM_SUCCESS;
}

int encode_get_bios_current_value_by_handle_resp(uint8_t instance_id,
						 uint8_t completion_code,
						 uint32_t next_transfer_handle,
						 uint8_t transfer_flag,
						 const uint8_t *attribute_data,
						 size_t attribute_length,
						 struct pldm_msg *msg)
{
	if (msg == NULL || attribute_data == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_header_info header = { 0 };
	header.msg_type = PLDM_RESPONSE;
	header.instance = instance_id;
	header.pldm_type = PLDM_BIOS;
	header.command = PLDM_GET_BIOS_ATTRIBUTE_CURRENT_VALUE_BY_HANDLE;

	uint8_t rc = pack_pldm_header(&header, &(msg->hdr));
	if (rc != PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_get_bios_attribute_current_value_by_handle_resp *response =
		(struct pldm_get_bios_attribute_current_value_by_handle_resp *)
			msg->payload;
	response->completion_code = completion_code;
	if (response->completion_code == PLDM_SUCCESS) {
		response->next_transfer_handle = htole32(next_transfer_handle);
		response->transfer_flag = transfer_flag;
		if (attribute_data != NULL) {
			memcpy(response->attribute_data, attribute_data,
			       attribute_length);
		}
	}
	return PLDM_SUCCESS;
}
int encode_set_bios_attribute_current_value_req(
	uint8_t instance_id, uint32_t transfer_handle, uint8_t transfer_flag,
	const uint8_t *attribute_data, size_t attribute_length,
	struct pldm_msg *msg, size_t payload_length)
{
	if (msg == NULL || attribute_data == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}
	if (PLDM_SET_BIOS_ATTR_CURR_VAL_MIN_REQ_BYTES + attribute_length !=
	    payload_length) {
		return PLDM_ERROR_INVALID_LENGTH;
	}
	struct pldm_header_info header = { 0 };
	header.instance = instance_id;
	header.msg_type = PLDM_REQUEST;
	header.pldm_type = PLDM_BIOS;
	header.command = PLDM_SET_BIOS_ATTRIBUTE_CURRENT_VALUE;

	uint8_t rc = pack_pldm_header(&header, &msg->hdr);
	if (rc != PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_set_bios_attribute_current_value_req *request =
		(struct pldm_set_bios_attribute_current_value_req *)msg->payload;
	request->transfer_handle = htole32(transfer_handle);
	request->transfer_flag = transfer_flag;
	memcpy(request->attribute_data, attribute_data, attribute_length);

	return PLDM_SUCCESS;
}

int decode_set_bios_attribute_current_value_resp(const struct pldm_msg *msg,
						 size_t payload_length,
						 uint8_t *completion_code,
						 uint32_t *next_transfer_handle)
{
	if (msg == NULL || completion_code == NULL ||
	    next_transfer_handle == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*completion_code = msg->payload[0];
	if (PLDM_SUCCESS != *completion_code) {
		return PLDM_SUCCESS;
	}

	if (payload_length != PLDM_SET_BIOS_ATTR_CURR_VAL_RESP_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_set_bios_attribute_current_value_resp *response =
		(struct pldm_set_bios_attribute_current_value_resp *)
			msg->payload;

	*next_transfer_handle = le32toh(response->next_transfer_handle);

	return PLDM_SUCCESS;
}

int decode_set_bios_attribute_current_value_req(
	const struct pldm_msg *msg, size_t payload_length,
	uint32_t *transfer_handle, uint8_t *transfer_flag,
	struct variable_field *attribute)
{
	if (msg == NULL || transfer_handle == NULL || transfer_flag == NULL ||
	    attribute == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}
	if (payload_length < PLDM_SET_BIOS_ATTR_CURR_VAL_MIN_REQ_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_set_bios_attribute_current_value_req *request =
		(struct pldm_set_bios_attribute_current_value_req *)msg->payload;
	*transfer_handle = le32toh(request->transfer_handle);
	*transfer_flag = request->transfer_flag;
	attribute->length =
		payload_length - PLDM_SET_BIOS_ATTR_CURR_VAL_MIN_REQ_BYTES;
	attribute->ptr = request->attribute_data;
	return PLDM_SUCCESS;
}

int encode_set_bios_attribute_current_value_resp(uint8_t instance_id,
						 uint8_t completion_code,
						 uint32_t next_transfer_handle,
						 struct pldm_msg *msg)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}
	struct pldm_header_info header = { 0 };
	header.instance = instance_id;
	header.msg_type = PLDM_RESPONSE;
	header.pldm_type = PLDM_BIOS;
	header.command = PLDM_SET_BIOS_ATTRIBUTE_CURRENT_VALUE;

	uint8_t rc = pack_pldm_header(&header, &msg->hdr);
	if (rc != PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_set_bios_attribute_current_value_resp *response =
		(struct pldm_set_bios_attribute_current_value_resp *)
			msg->payload;
	response->completion_code = completion_code;
	response->next_transfer_handle = htole32(next_transfer_handle);

	return PLDM_SUCCESS;
}

int encode_set_bios_table_req(uint8_t instance_id, uint32_t transfer_handle,
			      uint8_t transfer_flag, uint8_t table_type,
			      const uint8_t *table_data, size_t table_length,
			      struct pldm_msg *msg, size_t payload_length)
{
	if (msg == NULL || table_data == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (PLDM_SET_BIOS_TABLE_MIN_REQ_BYTES + table_length !=
	    payload_length) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_header_info header = { 0 };
	header.instance = instance_id;
	header.msg_type = PLDM_REQUEST;
	header.pldm_type = PLDM_BIOS;
	header.command = PLDM_SET_BIOS_TABLE;

	uint8_t rc = pack_pldm_header(&header, &(msg->hdr));
	if (rc != PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_set_bios_table_req *request =
		(struct pldm_set_bios_table_req *)msg->payload;
	request->transfer_handle = htole32(transfer_handle);
	request->transfer_flag = transfer_flag;
	request->table_type = table_type;
	memcpy(request->table_data, table_data, table_length);

	return PLDM_SUCCESS;
}

int decode_set_bios_table_resp(const struct pldm_msg *msg,
			       size_t payload_length, uint8_t *completion_code,
			       uint32_t *next_transfer_handle)
{
	if (msg == NULL || completion_code == NULL ||
	    next_transfer_handle == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*completion_code = msg->payload[0];
	if (PLDM_SUCCESS != *completion_code) {
		return PLDM_SUCCESS;
	}

	if (payload_length != PLDM_SET_BIOS_TABLE_RESP_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_set_bios_table_resp *response =
		(struct pldm_set_bios_table_resp *)msg->payload;

	*next_transfer_handle = le32toh(response->next_transfer_handle);

	return PLDM_SUCCESS;
}

int encode_set_bios_table_resp(uint8_t instance_id, uint8_t completion_code,
			       uint32_t next_transfer_handle,
			       struct pldm_msg *msg)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_header_info header = { 0 };
	header.instance = instance_id;
	header.msg_type = PLDM_RESPONSE;
	header.pldm_type = PLDM_BIOS;
	header.command = PLDM_SET_BIOS_TABLE;

	uint8_t rc = pack_pldm_header(&header, &(msg->hdr));
	if (rc != PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_set_bios_table_resp *response =
		(struct pldm_set_bios_table_resp *)msg->payload;
	response->completion_code = completion_code;
	response->next_transfer_handle = htole32(next_transfer_handle);

	return PLDM_SUCCESS;
}

int decode_set_bios_table_req(const struct pldm_msg *msg, size_t payload_length,
			      uint32_t *transfer_handle, uint8_t *transfer_flag,
			      uint8_t *table_type, struct variable_field *table)
{
	if (msg == NULL || transfer_handle == NULL || transfer_flag == NULL ||
	    table_type == NULL || table == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (payload_length < PLDM_SET_BIOS_TABLE_MIN_REQ_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_set_bios_table_req *request =
		(struct pldm_set_bios_table_req *)msg->payload;
	*transfer_handle = le32toh(request->transfer_handle);
	*transfer_flag = request->transfer_flag;
	*table_type = request->table_type;
	table->length = payload_length - PLDM_SET_BIOS_TABLE_MIN_REQ_BYTES;
	table->ptr = request->table_data;

	return PLDM_SUCCESS;
}
