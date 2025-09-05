#include "base.h"
#include "pldm_types.h"
#include <endian.h>
#include <stdint.h>
#include <string.h>

uint8_t pack_pldm_header(const struct pldm_header_info *hdr,
			 struct pldm_msg_hdr *msg)
{
	if (msg == NULL || hdr == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (hdr->msg_type != PLDM_RESPONSE && hdr->msg_type != PLDM_REQUEST &&
	    hdr->msg_type != PLDM_ASYNC_REQUEST_NOTIFY) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (hdr->instance > PLDM_INSTANCE_MAX) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (hdr->pldm_type > (PLDM_MAX_TYPES - 1)) {
		return PLDM_ERROR_INVALID_PLDM_TYPE;
	}

	uint8_t datagram = (hdr->msg_type == PLDM_ASYNC_REQUEST_NOTIFY) ? 1 : 0;

	if (hdr->msg_type == PLDM_RESPONSE) {
		msg->request = PLDM_RESPONSE;
	} else if (hdr->msg_type == PLDM_REQUEST ||
		   hdr->msg_type == PLDM_ASYNC_REQUEST_NOTIFY) {
		msg->request = PLDM_REQUEST;
	}
	msg->datagram = datagram;
	msg->reserved = 0;
	msg->instance_id = hdr->instance;
	msg->header_ver = PLDM_CURRENT_VERSION;
	msg->type = hdr->pldm_type;
	msg->command = hdr->command;

	return PLDM_SUCCESS;
}

uint8_t unpack_pldm_header(const struct pldm_msg_hdr *msg,
			   struct pldm_header_info *hdr)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (msg->request == PLDM_RESPONSE) {
		hdr->msg_type = PLDM_RESPONSE;
	} else {
		hdr->msg_type = msg->datagram ? PLDM_ASYNC_REQUEST_NOTIFY :
						PLDM_REQUEST;
	}

	hdr->instance = msg->instance_id;
	hdr->pldm_type = msg->type;
	hdr->command = msg->command;

	return PLDM_SUCCESS;
}

int encode_get_types_req(uint8_t instance_id, struct pldm_msg *msg)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_header_info header = { 0 };
	header.instance = instance_id;
	header.msg_type = PLDM_REQUEST;
	header.command = PLDM_GET_PLDM_TYPES;

	return pack_pldm_header(&header, &(msg->hdr));
}

int encode_get_commands_req(uint8_t instance_id, uint8_t type, ver32_t version,
			    struct pldm_msg *msg)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_header_info header = { 0 };
	header.instance = instance_id;
	header.msg_type = PLDM_REQUEST;
	header.command = PLDM_GET_PLDM_COMMANDS;

	uint8_t rc = pack_pldm_header(&header, &(msg->hdr));
	if (rc != PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_get_commands_req *request =
		(struct pldm_get_commands_req *)msg->payload;

	request->type = type;
	request->version = version;

	return PLDM_SUCCESS;
}

int encode_get_types_resp(uint8_t instance_id, uint8_t completion_code,
			  const bitfield8_t *types, struct pldm_msg *msg)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_header_info header = { 0 };
	header.instance = instance_id;
	header.msg_type = PLDM_RESPONSE;
	header.command = PLDM_GET_PLDM_TYPES;

	uint8_t rc = pack_pldm_header(&header, &(msg->hdr));
	if (rc != PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_get_types_resp *response =
		(struct pldm_get_types_resp *)msg->payload;
	response->completion_code = completion_code;
	if (response->completion_code == PLDM_SUCCESS) {
		if (types == NULL) {
			return PLDM_ERROR_INVALID_DATA;
		}
		memcpy(response->types, &(types->byte), PLDM_MAX_TYPES / 8);
	}

	return PLDM_SUCCESS;
}

int decode_get_commands_req(const struct pldm_msg *msg, size_t payload_length,
			    uint8_t *type, ver32_t *version)
{
	if (msg == NULL || type == NULL || version == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (payload_length != PLDM_GET_COMMANDS_REQ_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_get_commands_req *request =
		(struct pldm_get_commands_req *)msg->payload;
	*type = request->type;
	*version = request->version;
	return PLDM_SUCCESS;
}

int encode_get_commands_resp(uint8_t instance_id, uint8_t completion_code,
			     const bitfield8_t *commands, struct pldm_msg *msg)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_header_info header = { 0 };
	header.instance = instance_id;
	header.msg_type = PLDM_RESPONSE;
	header.command = PLDM_GET_PLDM_COMMANDS;
	uint8_t rc = pack_pldm_header(&header, &(msg->hdr));
	if (rc != PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_get_commands_resp *response =
		(struct pldm_get_commands_resp *)msg->payload;
	response->completion_code = completion_code;
	if (response->completion_code == PLDM_SUCCESS) {
		if (commands == NULL) {
			return PLDM_ERROR_INVALID_DATA;
		}
		memcpy(response->commands, &(commands->byte),
		       PLDM_MAX_CMDS_PER_TYPE / 8);
	}

	return PLDM_SUCCESS;
}

int decode_get_types_resp(const struct pldm_msg *msg, size_t payload_length,
			  uint8_t *completion_code, bitfield8_t *types)
{
	if (msg == NULL || types == NULL || completion_code == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*completion_code = msg->payload[0];
	if (PLDM_SUCCESS != *completion_code) {
		return PLDM_SUCCESS;
	}

	if (payload_length != PLDM_GET_TYPES_RESP_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_get_types_resp *response =
		(struct pldm_get_types_resp *)msg->payload;

	memcpy(&(types->byte), response->types, PLDM_MAX_TYPES / 8);

	return PLDM_SUCCESS;
}

int decode_get_commands_resp(const struct pldm_msg *msg, size_t payload_length,
			     uint8_t *completion_code, bitfield8_t *commands)
{
	if (msg == NULL || commands == NULL || completion_code == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*completion_code = msg->payload[0];
	if (PLDM_SUCCESS != *completion_code) {
		return PLDM_SUCCESS;
	}

	if (payload_length != PLDM_GET_COMMANDS_RESP_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_get_commands_resp *response =
		(struct pldm_get_commands_resp *)msg->payload;

	memcpy(&(commands->byte), response->commands,
	       PLDM_MAX_CMDS_PER_TYPE / 8);

	return PLDM_SUCCESS;
}

int encode_get_version_req(uint8_t instance_id, uint32_t transfer_handle,
			   uint8_t transfer_opflag, uint8_t type,
			   struct pldm_msg *msg)
{
	if (NULL == msg) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_header_info header = { 0 };
	header.msg_type = PLDM_REQUEST;
	header.instance = instance_id;
	header.pldm_type = PLDM_BASE;
	header.command = PLDM_GET_PLDM_VERSION;

	uint8_t rc = pack_pldm_header(&header, &(msg->hdr));
	if (rc != PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_get_version_req *request =
		(struct pldm_get_version_req *)msg->payload;
	transfer_handle = htole32(transfer_handle);
	request->transfer_handle = transfer_handle;
	request->transfer_opflag = transfer_opflag;
	request->type = type;

	return PLDM_SUCCESS;
}

int encode_get_version_resp(uint8_t instance_id, uint8_t completion_code,
			    uint32_t next_transfer_handle,
			    uint8_t transfer_flag, const ver32_t *version_data,
			    size_t version_size, struct pldm_msg *msg)
{
	if (NULL == msg) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_header_info header = { 0 };
	header.msg_type = PLDM_RESPONSE;
	header.instance = instance_id;
	header.pldm_type = PLDM_BASE;
	header.command = PLDM_GET_PLDM_VERSION;

	uint8_t rc = pack_pldm_header(&header, &(msg->hdr));
	if (rc != PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_get_version_resp *response =
		(struct pldm_get_version_resp *)msg->payload;
	response->completion_code = completion_code;
	if (response->completion_code == PLDM_SUCCESS) {
		response->next_transfer_handle = htole32(next_transfer_handle);
		response->transfer_flag = transfer_flag;
		memcpy(response->version_data, (uint8_t *)version_data,
		       version_size);
	}
	return PLDM_SUCCESS;
}

int decode_get_version_req(const struct pldm_msg *msg, size_t payload_length,
			   uint32_t *transfer_handle, uint8_t *transfer_opflag,
			   uint8_t *type)
{
	if (payload_length != PLDM_GET_VERSION_REQ_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_get_version_req *request =
		(struct pldm_get_version_req *)msg->payload;
	*transfer_handle = le32toh(request->transfer_handle);
	*transfer_opflag = request->transfer_opflag;
	*type = request->type;
	return PLDM_SUCCESS;
}

int decode_get_version_resp(const struct pldm_msg *msg, size_t payload_length,
			    uint8_t *completion_code,
			    uint32_t *next_transfer_handle,
			    uint8_t *transfer_flag, ver32_t *version)
{
	if (msg == NULL || next_transfer_handle == NULL ||
	    transfer_flag == NULL || completion_code == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*completion_code = msg->payload[0];
	if (PLDM_SUCCESS != *completion_code) {
		return PLDM_SUCCESS;
	}

	if (payload_length < PLDM_GET_VERSION_RESP_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_get_version_resp *response =
		(struct pldm_get_version_resp *)msg->payload;

	*next_transfer_handle = le32toh(response->next_transfer_handle);
	*transfer_flag = response->transfer_flag;
	memcpy(version, (uint8_t *)response->version_data, sizeof(ver32_t));

	return PLDM_SUCCESS;
}

int encode_get_tid_req(uint8_t instance_id, struct pldm_msg *msg)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_header_info header = { 0 };
	header.instance = instance_id;
	header.msg_type = PLDM_REQUEST;
	header.command = PLDM_GET_TID;

	return pack_pldm_header(&header, &(msg->hdr));
}
int encode_get_tid_resp(uint8_t instance_id, uint8_t completion_code,
			uint8_t tid, struct pldm_msg *msg)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_header_info header = { 0 };
	header.instance = instance_id;
	header.msg_type = PLDM_RESPONSE;
	header.command = PLDM_GET_TID;

	uint8_t rc = pack_pldm_header(&header, &(msg->hdr));
	if (rc != PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_get_tid_resp *response =
		(struct pldm_get_tid_resp *)msg->payload;
	response->completion_code = completion_code;
	response->tid = tid;

	return PLDM_SUCCESS;
}

int decode_get_tid_resp(const struct pldm_msg *msg, size_t payload_length,
			uint8_t *completion_code, uint8_t *tid)
{
	if (msg == NULL || tid == NULL || completion_code == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*completion_code = msg->payload[0];
	if (PLDM_SUCCESS != *completion_code) {
		return PLDM_SUCCESS;
	}

	if (payload_length != PLDM_GET_TID_RESP_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_get_tid_resp *response =
		(struct pldm_get_tid_resp *)msg->payload;

	*tid = response->tid;

	return PLDM_SUCCESS;
}

int encode_set_tid_req(uint8_t instance_id, uint8_t tid, struct pldm_msg *msg)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (tid == 0x0 || tid == 0xff) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_header_info header = { 0 };
	header.instance = instance_id;
	header.msg_type = PLDM_REQUEST;
	header.command = PLDM_SET_TID;

	uint8_t rc = pack_pldm_header(&header, &(msg->hdr));
	if (rc != PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_set_tid_req *request =
		(struct pldm_set_tid_req *)msg->payload;
	request->tid = tid;

	return PLDM_SUCCESS;
}

int decode_multipart_receive_req(const struct pldm_msg *msg,
				 size_t payload_length, uint8_t *pldm_type,
				 uint8_t *transfer_opflag,
				 uint32_t *transfer_ctx,
				 uint32_t *transfer_handle,
				 uint32_t *section_offset,
				 uint32_t *section_length)
{
	if (msg == NULL || pldm_type == NULL || transfer_opflag == NULL ||
	    transfer_ctx == NULL || transfer_handle == NULL ||
	    section_offset == NULL || section_length == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (payload_length != PLDM_MULTIPART_RECEIVE_REQ_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_multipart_receive_req *request =
		(struct pldm_multipart_receive_req *)msg->payload;

	if (request->pldm_type != PLDM_BASE) {
		return PLDM_ERROR_INVALID_PLDM_TYPE;
	}

	// Any enum value above PLDM_XFER_CURRENT_PART is invalid.
	if (request->transfer_opflag > PLDM_XFER_CURRENT_PART) {
		return PLDM_INVALID_TRANSFER_OPERATION_FLAG;
	}

	// A section offset of 0 is only valid on FIRST_PART or COMPLETE Xfers.
	uint32_t sec_offset = le32toh(request->section_offset);
	if (sec_offset == 0 &&
	    (request->transfer_opflag != PLDM_XFER_FIRST_PART &&
	     request->transfer_opflag != PLDM_XFER_COMPLETE)) {
		return PLDM_ERROR_INVALID_DATA;
	}

	uint32_t handle = le32toh(request->transfer_handle);
	if (handle == 0 && request->transfer_opflag != PLDM_XFER_COMPLETE) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*pldm_type = request->pldm_type;
	*transfer_opflag = request->transfer_opflag;
	*transfer_ctx = request->transfer_ctx;
	*transfer_handle = handle;
	*section_offset = sec_offset;
	*section_length = le32toh(request->section_length);

	return PLDM_SUCCESS;
}

int encode_cc_only_resp(uint8_t instance_id, uint8_t type, uint8_t command,
			uint8_t cc, struct pldm_msg *msg)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_header_info header = { 0 };
	header.instance = instance_id;
	header.msg_type = PLDM_RESPONSE;
	header.pldm_type = type;
	header.command = command;

	uint8_t rc = pack_pldm_header(&header, &msg->hdr);
	if (rc != PLDM_SUCCESS) {
		return rc;
	}

	msg->payload[0] = cc;

	return PLDM_SUCCESS;
}

int encode_pldm_header_only(uint8_t msg_type, uint8_t instance_id,
			    uint8_t pldm_type, uint8_t command,
			    struct pldm_msg *msg)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_header_info header = { 0 };
	header.msg_type = msg_type;
	header.instance = instance_id;
	header.pldm_type = pldm_type;
	header.command = command;
	return pack_pldm_header(&header, &(msg->hdr));
}
