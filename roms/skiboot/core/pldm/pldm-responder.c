// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// Copyright 2022 IBM Corp.

#define pr_fmt(fmt) "PLDM: " fmt

#include <bitmap.h>
#include <cpu.h>
#include <opal.h>
#include <opal-msg.h>
#include <stdio.h>
#include <string.h>
#include <debug_descriptor.h>
#include <libpldm/fru.h>
#include <libpldm/platform.h>
#include <libpldm/platform_oem_ibm.h>
#include <libpldm/state_set.h>
#include <libpldm/utils.h>
#include "pldm.h"

struct pldm_type {
	const char *name;
	int pldm_type_id;
	ver32_t version;

	struct list_head commands;
	struct list_node link;
};

struct pldm_cmd {
	const char *name;
	int pldm_cmd_id;

	int (*handler)(const struct pldm_rx_data *rx);

	struct list_node link; /* link in the msg type's command list */
};

/*
 * Send a response with just a completion code and no payload
 */
static int cc_resp(const struct pldm_rx_data *rx, uint8_t type,
			uint8_t command, uint8_t cc)
{
	size_t data_size = PLDM_MSG_SIZE(uint8_t);
	struct pldm_tx_data *tx;
	int rc;

	/* Encode the cc response */
	tx = zalloc(sizeof(struct pldm_tx_data) + data_size);
	if (!tx)
		return OPAL_NO_MEM;
	tx->data_size = data_size;
	tx->tag_owner = true;
	tx->msg_tag = rx->msg_tag;

	encode_cc_only_resp(rx->hdrinf.instance,
			    type,
			    command,
			    cc,
			    (struct pldm_msg *)tx->data);

	rc = pldm_mctp_message_tx(tx);
	if (rc) {
		prlog(PR_ERR, "Failed to send response message containing only cc, "
			      "rc = %d, cc = %d\n", rc, cc);
		free(tx);
		return OPAL_HARDWARE;
	}

	free(tx);
	return OPAL_SUCCESS;
}

/*
 * PLDM Type / Command wrangling.
 */
LIST_HEAD(pldm_type_list);

static const struct pldm_type *find_type(int type_id)
{
	struct pldm_type *iter;

	list_for_each(&pldm_type_list, iter, link) {
		if (iter->pldm_type_id == type_id)
			return iter;
	}

	return NULL;
}

static const struct pldm_cmd *find_cmd(const struct pldm_type *type, int cmd)
{
	struct pldm_cmd *iter;

	list_for_each(&type->commands, iter, link)
		if (iter->pldm_cmd_id == cmd)
			return iter;

	return NULL;
}

static void add_type(struct pldm_type *new_type)
{
	assert(new_type->pldm_type_id < 32); /* limited by GetPLDMTypes */
	assert(!find_type(new_type->pldm_type_id));

	list_head_init(&new_type->commands);
	list_add_tail(&pldm_type_list, &new_type->link);

	prlog(PR_DEBUG, "Registered type %s (%d)\n",
	      new_type->name, new_type->pldm_type_id);
}

static void add_cmd(struct pldm_type *type, struct pldm_cmd *new_cmd)
{
	assert(new_cmd->pldm_cmd_id < 256); /* limited by GetPLDMCommands */
	assert(new_cmd->handler);
	assert(!find_cmd(type, new_cmd->pldm_cmd_id));

	list_add_tail(&type->commands, &new_cmd->link);
	prlog(PR_DEBUG, "Registered command %s (%d) under %s\n",
		new_cmd->name, new_cmd->pldm_cmd_id, type->name);
}

/*
 * PLDM Base commands support
 */
static struct pldm_type pldm_base_type = {
	.name = "base",
	.pldm_type_id = PLDM_BASE,
	.version = { 0xF1, 0xF0, 0xF0, 0x00 },
};

/*
 * GetTID command (0x02)
 * The GetTID command is used to retrieve the present Terminus ID (TID)
 * setting for a PLDM Terminus.
 */
static int base_get_tid_handler(const struct pldm_rx_data *rx)
{
	size_t data_size = PLDM_MSG_SIZE(struct pldm_get_tid_resp);
	struct pldm_tx_data *tx;
	int rc;

	/* create a PLDM response message for GetTID */
	tx = zalloc(sizeof(struct pldm_tx_data) + data_size);
	if (!tx)
		return OPAL_NO_MEM;
	tx->data_size = data_size;
	tx->tag_owner = true;
	tx->msg_tag = rx->msg_tag;

	rc = encode_get_tid_resp(rx->hdrinf.instance,
				 PLDM_SUCCESS,
				 HOST_TID,
				 (struct pldm_msg *)tx->data);
	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "Encode GetTID Error, rc: %d\n", rc);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command, PLDM_ERROR);
		free(tx);
		return OPAL_PARAMETER;
	}

	rc = pldm_mctp_message_tx(tx);
	if (rc) {
		prlog(PR_ERR, "Failed to send GetTID response, rc = %d\n", rc);
		free(tx);
		return OPAL_HARDWARE;
	}

	free(tx);
	return OPAL_SUCCESS;
}

static struct pldm_cmd pldm_base_get_tid = {
	.name = "PLDM_GET_TID",
	.pldm_cmd_id = PLDM_GET_TID,
	.handler = base_get_tid_handler,
};

/*
 * GetPLDMTypes (0x04)
 * The GetPLDMTypes command can be used to discover the PLDM type
 * capabilities supported by a PLDM terminus and to get a list of the
 * PLDM types that are supported.
 */
static int base_get_types_handler(const struct pldm_rx_data *rx)
{
	size_t data_size = PLDM_MSG_SIZE(struct pldm_get_types_resp);
	bitmap_elem_t type_map[BITMAP_ELEMS(PLDM_MAX_TYPES)];
	struct pldm_tx_data *tx;
	struct pldm_type *iter;
	int rc;

	/* build the supported type list from the registered type
	 * handlers
	 */
	memset(type_map, 0, sizeof(type_map));
	list_for_each(&pldm_type_list, iter, link)
		bitmap_set_bit(type_map, iter->pldm_type_id);

	for (int i = 0; i < BITMAP_ELEMS(PLDM_MAX_TYPES); i++)
		type_map[i] = cpu_to_le64(type_map[i]);

	/* create a PLDM response message for GetPLDMTypes */
	tx = zalloc(sizeof(struct pldm_tx_data) + data_size);
	if (!tx)
		return OPAL_NO_MEM;
	tx->data_size = data_size;
	tx->tag_owner = true;
	tx->msg_tag = rx->msg_tag;

	rc = encode_get_types_resp(rx->hdrinf.instance,
				   PLDM_SUCCESS,
				   (bitfield8_t *)type_map,
				   (struct pldm_msg *)tx->data);
	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "Encode GetPLDMTypes Error, rc: %d\n", rc);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command, PLDM_ERROR);
		free(tx);
		return OPAL_PARAMETER;
	}

	rc = pldm_mctp_message_tx(tx);
	if (rc) {
		prlog(PR_ERR, "Failed to send GetPLDMTypes response, rc = %d\n", rc);
		free(tx);
		return OPAL_HARDWARE;
	}

	free(tx);
	return OPAL_SUCCESS;
}

static struct pldm_cmd pldm_base_get_types = {
	.name = "PLDM_GET_PLDM_TYPES",
	.pldm_cmd_id = PLDM_GET_PLDM_TYPES,
	.handler = base_get_types_handler,
};

/*
 * Extended error codes defined for the Base command set.
 */
#define INVALID_DATA_TRANSFER_HANDLE           0x80
#define INVALID_TRANSFER_OPERATION_FLAG        0x81
#define INVALID_PLDM_TYPE_IN_REQUEST_DATA      0x83
#define INVALID_PLDM_VERSION_IN_REQUEST_DATA   0x84

/*
 * GetPLDMCommands (0x05)
 * The GetPLDMCommands command can be used to discover the PLDM command
 * capabilities supported by aPLDM terminus for a specific PLDM Type and
 * version as a responder.
 */
static int base_get_commands_handler(const struct pldm_rx_data *rx)
{
	size_t data_size = PLDM_MSG_SIZE(struct pldm_get_commands_resp);
	bitmap_elem_t cmd_map[BITMAP_ELEMS(PLDM_MAX_CMDS_PER_TYPE)];
	const struct pldm_type *type;
	const struct pldm_cmd *iter;
	struct pldm_tx_data *tx;
	size_t payload_len;
	ver32_t version;
	uint8_t type_id;
	int rc;

	payload_len = rx->msg_len - sizeof(struct pldm_msg_hdr);
	rc = decode_get_commands_req(rx->msg, payload_len,
				     &type_id, &version);
	if (rc) {
		prlog(PR_ERR, "Failed to decode GetPLDMCommands request, rc = %d", rc);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command, PLDM_ERROR);
		return OPAL_INTERNAL_ERROR;
	}

	type = find_type(type_id);
	if (!type) {
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command,
			INVALID_PLDM_TYPE_IN_REQUEST_DATA);
		return OPAL_PARAMETER;
	}

	if (memcmp(&type->version, &version, sizeof(version))) {
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command,
			INVALID_PLDM_VERSION_IN_REQUEST_DATA);
		return OPAL_PARAMETER;
	}

	/* build the supported type list from the registered type
	 * handlers
	 */
	memset(cmd_map, 0, sizeof(cmd_map));
	list_for_each(&type->commands, iter, link)
		bitmap_set_bit(cmd_map, iter->pldm_cmd_id);

	/* fix the endian */
	for (int i = 0; i < BITMAP_ELEMS(PLDM_MAX_CMDS_PER_TYPE); i++)
		cmd_map[i] = cpu_to_le64(cmd_map[i]);

	/* create a PLDM response message for GetPLDMCommands */
	tx = zalloc(sizeof(struct pldm_tx_data) + data_size);
	if (!tx)
		return OPAL_NO_MEM;
	tx->data_size = data_size;
	tx->tag_owner = true;
	tx->msg_tag = rx->msg_tag;

	rc = encode_get_commands_resp(rx->hdrinf.instance,
				      PLDM_SUCCESS,
				      (bitfield8_t *)cmd_map,
				      (struct pldm_msg *)tx->data);
	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "Encode GetPLDMCommands Error, rc: %d\n", rc);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command, PLDM_ERROR);
		free(tx);
		return OPAL_PARAMETER;
	}

	/* send PLDM message over MCTP */
	rc = pldm_mctp_message_tx(tx);
	if (rc) {
		prlog(PR_ERR, "Failed to send GetPLDMCommands response, rc = %d\n", rc);
		return OPAL_HARDWARE;
		free(tx);
	}

	free(tx);
	return OPAL_SUCCESS;
}

static struct pldm_cmd pldm_base_get_commands = {
	.name = "PLDM_GET_PLDM_COMMANDS",
	.pldm_cmd_id = PLDM_GET_PLDM_COMMANDS,
	.handler = base_get_commands_handler,
};

/*
 * GetPLDMVersion (0x03)
 * The GetPLDMVersion command can be used to retrieve the PLDM base
 * specification versions that the PLDM terminus supports, as well as
 * the PLDM Type specification versions supported for each PLDM Type.
 */
static int base_get_version_handler(const struct pldm_rx_data *rx)
{
	uint32_t version_data[2];
	size_t data_size = PLDM_MSG_SIZE(struct pldm_get_version_resp) + sizeof(version_data);
	const struct pldm_type *type;
	struct pldm_tx_data *tx;
	uint8_t type_id, opflag;
	uint32_t xfer_handle;
	size_t payload_len;
	int rc;

	payload_len = rx->msg_len - sizeof(struct pldm_msg_hdr);
	rc = decode_get_version_req(rx->msg, payload_len,
				    &xfer_handle,
				    &opflag,
				    &type_id);
	if (rc) {
		prlog(PR_ERR, "Failed to decode GetPLDMVersion request, rc = %d", rc);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command, PLDM_ERROR);
		return OPAL_INTERNAL_ERROR;
	}

	/* reject multipart requests */
	if (opflag != PLDM_GET_FIRSTPART) {
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command,
			INVALID_TRANSFER_OPERATION_FLAG);
		return OPAL_PARAMETER;
	}

	type = find_type(type_id);
	if (!type) {
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command,
			INVALID_PLDM_TYPE_IN_REQUEST_DATA);
		return OPAL_PARAMETER;
	}

	/* pack a scratch buffer with our version(s) and CRC32 the lot */
	memcpy(&version_data[0], &type->version, 4);

	version_data[1] = cpu_to_le32(crc32(&type->version, 4));

	/* create a PLDM response for GetPLDMVersion */
	tx = zalloc(sizeof(struct pldm_tx_data) + data_size);
	if (!tx)
		return OPAL_NO_MEM;
	tx->data_size = data_size;
	tx->tag_owner = true;
	tx->msg_tag = rx->msg_tag;

	rc = encode_get_version_resp(rx->hdrinf.instance,
				     PLDM_SUCCESS,
				     0x0, /* no handle */
				     PLDM_START_AND_END,
				     (ver32_t *) version_data,
				     sizeof(version_data),
				     (struct pldm_msg *)tx->data);
	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "Encode GetPLDMVersion Error, rc: %d\n", rc);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command, PLDM_ERROR);
		free(tx);
		return OPAL_PARAMETER;
	}

	/* send PLDM message over MCTP */
	rc = pldm_mctp_message_tx(tx);
	if (rc) {
		prlog(PR_ERR, "Failed to send GetPLDMVersion response, rc = %d\n", rc);
		free(tx);
		return OPAL_HARDWARE;
	}

	free(tx);

	/* BMC has certainly rebooted, so reload the PDRs */
	return pldm_platform_reload_pdrs();
}

static struct pldm_cmd pldm_base_get_version = {
	.name = "PLDM_GET_PLDM_VERSION",
	.pldm_cmd_id = PLDM_GET_PLDM_VERSION,
	.handler = base_get_version_handler,
};

/*
 * PLDM Platform commands support
 */
static struct pldm_type pldm_platform_type = {
	.name = "platform",
	.pldm_type_id = PLDM_PLATFORM,
};

#define MIN_WATCHDOG_TIMEOUT_SEC 15

/*
 * SetEventReceiver (0x04)
 * The SetEventReceiver command is used to set the address of the Event
 * Receiver into a terminus that generates event messages. It is also
 * used to globally enable or disable whether event messages are
 * generated from the terminus.
 */
static int platform_set_event_receiver_handler(const struct pldm_rx_data *rx)
{
	uint8_t event_message_global_enable, transport_protocol_type;
	uint8_t event_receiver_address_info, cc = PLDM_SUCCESS;
	uint16_t heartbeat_timer;
	int rc = OPAL_SUCCESS;

	/* decode SetEventReceiver request data */
	rc = decode_set_event_receiver_req(
				rx->msg,
				PLDM_SET_EVENT_RECEIVER_REQ_BYTES,
				&event_message_global_enable,
				&transport_protocol_type,
				&event_receiver_address_info,
				&heartbeat_timer);
	if (rc) {
		prlog(PR_ERR, "Failed to decode SetEventReceiver request, rc = %d\n", rc);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command, PLDM_ERROR);
		return OPAL_INTERNAL_ERROR;
	}

	/* invoke the appropriate callback handler */
	prlog(PR_DEBUG, "%s - event_message_global_enable: %d, "
			"transport_protocol_type: %d "
			"event_receiver_address_info: %d "
			"heartbeat_timer: %d\n",
			__func__,
			event_message_global_enable,
			transport_protocol_type,
			event_receiver_address_info,
			heartbeat_timer);

	if (event_message_global_enable !=
		PLDM_EVENT_MESSAGE_GLOBAL_ENABLE_ASYNC_KEEP_ALIVE) {

		prlog(PR_ERR, "%s - invalid value for message global enable received: %d\n",
			      __func__, event_message_global_enable);
		cc = PLDM_PLATFORM_ENABLE_METHOD_NOT_SUPPORTED;
	}

	if (heartbeat_timer < MIN_WATCHDOG_TIMEOUT_SEC) {
		prlog(PR_ERR, "%s - BMC requested watchdog timeout that's too small: %d\n",
			      __func__, heartbeat_timer);
		cc = PLDM_PLATFORM_HEARTBEAT_FREQUENCY_TOO_HIGH;
	} else {
		/* set the internal watchdog period to what BMC indicated */
		watchdog_period_sec = heartbeat_timer;
	}

	/* send the response to BMC */
	cc_resp(rx, PLDM_PLATFORM, PLDM_SET_EVENT_RECEIVER, cc);

	/* no error happened above, so arm the watchdog and set the default timeout */
	if (cc == PLDM_SUCCESS)
		watchdog_armed = true;

	return rc;
}

static struct pldm_cmd pldm_platform_set_event_receiver = {
	.name = "PLDM_SET_EVENT_RECEIVER",
	.pldm_cmd_id = PLDM_SET_EVENT_RECEIVER,
	.handler = platform_set_event_receiver_handler,
};

/*
 * PlatformEventMessage (0x10)
 * PLDM Event Messages are sent as PLDM request messages to the Event
 * Receiver using the PlatformEventMessage command.
 */
static int platform_event_message(const struct pldm_rx_data *rx)
{
	size_t data_size = PLDM_MSG_SIZE(struct pldm_platform_event_message_resp);
	struct pldm_bios_attribute_update_event_req *request;
	uint8_t format_version, tid, event_class;
	uint8_t *bios_attribute_handles;
	uint8_t cc = PLDM_SUCCESS;
	size_t event_data_offset;
	struct pldm_tx_data *tx;
	int rc, i;

	/* decode PlatformEventMessage request data */
	rc = decode_platform_event_message_req(
				rx->msg,
				sizeof(struct pldm_platform_event_message_req),
				&format_version,
				&tid,
				&event_class,
				&event_data_offset);
	if (rc) {
		prlog(PR_ERR, "Failed to decode PlatformEventMessage request, rc = %d\n", rc);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command, PLDM_ERROR);
		return OPAL_INTERNAL_ERROR;
	}

	prlog(PR_DEBUG, "%s - format_version: %d, "
			"tid: %d "
			"event_class: %d "
			"event_data: 0x%lx\n",
			__func__,
			format_version, tid,
			event_class, event_data_offset);

	/* we don't support any other event than the PDR Repo Changed event */
	if ((event_class != PLDM_PDR_REPOSITORY_CHG_EVENT) &&
	    (event_class != PLDM_EVENT_TYPE_OEM_EVENT_BIOS_ATTRIBUTE_UPDATE)) {
		prlog(PR_ERR, "%s - Invalid event class %d in platform event handler\n",
			      __func__, event_class);
		cc = PLDM_ERROR;
	}

	/* Encode the platform event request */
	tx = zalloc(sizeof(struct pldm_tx_data) + data_size);
	if (!tx)
		return OPAL_NO_MEM;
	tx->data_size = data_size;
	tx->tag_owner = true;
	tx->msg_tag = rx->msg_tag;

	rc = encode_platform_event_message_resp(
					rx->hdrinf.instance,
					cc,
					PLDM_EVENT_NO_LOGGING,
					(struct pldm_msg *)tx->data);
	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "Encode PlatformEventMessage Error, rc: %d\n", rc);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command, PLDM_ERROR);
		free(tx);
		return OPAL_PARAMETER;
	}

	/* send PLDM message over MCTP */
	rc = pldm_mctp_message_tx(tx);
	if (rc) {
		prlog(PR_ERR, "Failed to send PlatformEventMessage response, rc = %d\n", rc);
		free(tx);
		return OPAL_HARDWARE;
	}

	/* invoke the appropriate callback handler */
	if (event_class == PLDM_PDR_REPOSITORY_CHG_EVENT) {
		free(tx);
		return pldm_platform_reload_pdrs();
	}

	/* When the attribute value changes for any BIOS attribute, then
	 * PlatformEventMessage command with OEM event type
	 * PLDM_EVENT_TYPE_OEM_EVENT_BIOS_ATTRIBUTE_UPDATE is send to
	 * host with the list of BIOS attribute handles.
	 */
	if (event_class == PLDM_EVENT_TYPE_OEM_EVENT_BIOS_ATTRIBUTE_UPDATE) {
		request = (struct pldm_bios_attribute_update_event_req *)rx->msg->payload;
		bios_attribute_handles = (uint8_t *)request->bios_attribute_handles;

		prlog(PR_DEBUG, "%s - OEM_EVENT_BIOS_ATTRIBUTE_UPDATE, handles: %d\n",
				__func__, request->num_handles);

		/* list of BIOS attribute handles */
		for (i = 0; i < request->num_handles; i++) {
			prlog(PR_DEBUG, "%s - OEM_EVENT_BIOS_ATTRIBUTE_UPDATE: handle(%d): %d\n",
					__func__, i, *bios_attribute_handles);
			bios_attribute_handles += sizeof(uint16_t);
		}
	}

	free(tx);
	return OPAL_SUCCESS;
}

static struct pldm_cmd pldm_platform_event_message = {
	.name = "PLDM_PLATFORM_EVENT_MESSAGE",
	.pldm_cmd_id = PLDM_PLATFORM_EVENT_MESSAGE,
	.handler = platform_event_message,
};

/*
 * GetStateSensorReadings (0x21)
 * The GetStateSensorReadings command can return readings for multiple
 * state sensors (a PLDM State Sensor that returns more than one set of
 * state information is called a composite state sensor).
 */
static int platform_get_state_sensor_readings(const struct pldm_rx_data *rx)
{
	bitfield8_t sensor_rearm;
	struct pldm_tx_data *tx;
	uint16_t sensor_id;
	uint8_t reserved;
	size_t data_size;
	int rc;

	get_sensor_state_field sensor_state = {
		.sensor_op_state = PLDM_SENSOR_UNKNOWN,
		.present_state = 0,
		.previous_state = 0,
		.event_state = 0
	};

	/* decode GetStateSensorReadings request data */
	rc = decode_get_state_sensor_readings_req(
				rx->msg,
				PLDM_GET_STATE_SENSOR_READINGS_REQ_BYTES,
				&sensor_id,
				&sensor_rearm,
				&reserved);
	if (rc) {
		prlog(PR_ERR, "Failed to decode GetStateSensorReadings request, rc = %d\n", rc);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command, PLDM_ERROR);
		return OPAL_INTERNAL_ERROR;
	}

	prlog(PR_DEBUG, "%s - sensor_id: %d, sensor_rearm: %x\n",
			__func__, sensor_id, sensor_rearm.byte);

	/* send state sensor reading response */
	data_size = sizeof(struct pldm_msg_hdr) +
		    sizeof(struct pldm_get_state_sensor_readings_resp) +
		    (sizeof(get_sensor_state_field) * 1);

	tx = zalloc(sizeof(struct pldm_tx_data) + data_size);
	if (!tx)
		return OPAL_NO_MEM;
	tx->data_size = data_size;
	tx->tag_owner = true;
	tx->msg_tag = rx->msg_tag;

	rc = encode_get_state_sensor_readings_resp(
					rx->hdrinf.instance,
					PLDM_SUCCESS,
					1, /* sensor count of 1 */
					&sensor_state,
					(struct pldm_msg *)tx->data);
	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "Encode GetStateSensorReadings response Error, rc: %d\n", rc);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command, PLDM_ERROR);
		free(tx);
		return OPAL_PARAMETER;
	}

	/* send PLDM message over MCTP */
	rc = pldm_mctp_message_tx(tx);
	if (rc) {
		prlog(PR_ERR, "Failed to send GetStateSensorReadings response, rc = %d\n", rc);
		free(tx);
		return OPAL_HARDWARE;
	}

	free(tx);
	return OPAL_SUCCESS;
}

static struct pldm_cmd pldm_platform_get_state_sensor_readings = {
	.name = "PLDM_GET_STATE_SENSOR_READINGS",
	.pldm_cmd_id = PLDM_GET_STATE_SENSOR_READINGS,
	.handler = platform_get_state_sensor_readings,
};

#define SOFT_OFF		0x00
#define SOFT_REBOOT		0x01
#define CHASSIS_PWR_DOWN	0x00
#define DEFAULT_CHIP_ID		0

/*
 * SetStateEffecterStates (0x39)
 * The SetStateEffecterStates command is used to set the state of one
 * or more effecters within a PLDM State Effecter.
 */
static int platform_set_state_effecter_states_handler(const struct pldm_rx_data *rx)
{
	set_effecter_state_field field[8];
	uint8_t comp_effecter_count;
	uint16_t effecter_id;
	int rc, i;

	/* decode SetStateEffecterStates request data */
	rc = decode_set_state_effecter_states_req(
				rx->msg,
				PLDM_SET_STATE_EFFECTER_STATES_REQ_BYTES,
				&effecter_id,
				&comp_effecter_count,
				field);
	if (rc) {
		prlog(PR_ERR, "Failed to decode SetStateEffecterStates request, rc = %d\n", rc);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command, PLDM_ERROR);
		return OPAL_INTERNAL_ERROR;
	}

	/* invoke the appropriate callback handler */
	prlog(PR_DEBUG, "%s - effecter_id: %d, comp_effecter_count: %d\n",
			__func__, effecter_id, comp_effecter_count);

	for (i = 0; i < comp_effecter_count; i++) {
		/* other set_request not supported */
		if (field[i].set_request != PLDM_REQUEST_SET) {
			prlog(PR_ERR, "Got invalid set request 0x%x in "
				      "SetStateEffecterStates request\n",
				      field[i].set_request);
			cc_resp(rx, rx->hdrinf.pldm_type,
				rx->hdrinf.command,
				PLDM_PLATFORM_INVALID_STATE_VALUE);
			return OPAL_PARAMETER;
		}

		switch (field[i].effecter_state) {
		case PLDM_SW_TERM_GRACEFUL_SHUTDOWN_REQUESTED:
		case PLDM_STATE_SET_SYS_POWER_STATE_OFF_SOFT_GRACEFUL:
			prlog(PR_NOTICE, "Soft shutdown requested\n");
			cc_resp(rx, PLDM_PLATFORM,
				PLDM_SET_STATE_EFFECTER_STATES,
				PLDM_SUCCESS);

			if (opal_booting() && platform.cec_power_down) {
				prlog(PR_NOTICE, "Host not up, shutting down now\n");
				platform.cec_power_down(CHASSIS_PWR_DOWN);
			} else {
				opal_queue_msg(OPAL_MSG_SHUTDOWN,
					       NULL, NULL,
					       cpu_to_be64(SOFT_OFF));
			}

			break;

		case PLDM_SW_TERM_GRACEFUL_RESTART_REQUESTED:
			prlog(PR_NOTICE, "Soft reboot requested\n");
			cc_resp(rx, PLDM_PLATFORM,
				PLDM_SET_STATE_EFFECTER_STATES,
				PLDM_SUCCESS);

			if (opal_booting() && platform.cec_reboot) {
				prlog(PR_NOTICE, "Host not up, rebooting now\n");
				platform.cec_reboot();
			} else {
				opal_queue_msg(OPAL_MSG_SHUTDOWN,
					       NULL, NULL,
					       cpu_to_be64(SOFT_REBOOT));
			}

			pldm_platform_initiate_shutdown();
			break;

		case PLDM_STATE_SET_BOOT_RESTART_CAUSE_WARM_RESET:
		case PLDM_STATE_SET_BOOT_RESTART_CAUSE_HARD_RESET:
			prlog(PR_NOTICE, "OCC reset requested\n");
			cc_resp(rx, PLDM_PLATFORM,
				PLDM_SET_STATE_EFFECTER_STATES,
				PLDM_SUCCESS);

			/* invoke the appropriate callback handler */
			prd_occ_reset(DEFAULT_CHIP_ID); /* FIXME, others chip ? */
			break;

		default:
			prlog(PR_ERR, "Got invalid effecter state 0x%x in "
				      "SetStateEffecterStates request\n",
				      field[i].effecter_state);
			cc_resp(rx, rx->hdrinf.pldm_type,
				rx->hdrinf.command,
				PLDM_PLATFORM_INVALID_STATE_VALUE);
			return OPAL_PARAMETER;
		}
	}

	return OPAL_SUCCESS;
}

static struct pldm_cmd pldm_platform_set_state_effecter_states = {
	.name = "PLDM_SET_STATE_EFFECTER_STATES",
	.pldm_cmd_id = PLDM_SET_STATE_EFFECTER_STATES,
	.handler = platform_set_state_effecter_states_handler,
};

/*
 * GetPDR (0x51)
 * The GetPDR command is used to retrieve individual PDRs from a PDR
 * Repository. The record is identified by the PDR recordHandle value
 * that is passed in the request.
 */
static int platform_get_pdr_handle(const struct pldm_rx_data *rx)
{
	uint32_t data_transfer_handle, pdr_data_size = 0;
	uint32_t record_handle, next_record_handle;
	uint16_t request_count, record_change_number;
	uint8_t transfer_op_flag, *pdr_data = NULL;
	size_t payload_len, data_size;
	struct pldm_tx_data *tx;
	int rc;

	payload_len = rx->msg_len - sizeof(struct pldm_msg_hdr);
	rc = decode_get_pdr_req(rx->msg,
				payload_len,
				&record_handle,
				&data_transfer_handle,
				&transfer_op_flag,
				&request_count,
				&record_change_number);
	if (rc) {
		prlog(PR_ERR, "Failed to decode GetPDR request, rc = %d\n", rc);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command, PLDM_ERROR);
		return OPAL_INTERNAL_ERROR;
	}

	if (data_transfer_handle != 0) {
		/* We don't support multipart transfers */
		prlog(PR_ERR, "Got invalid data transfer handle 0x%x in GetPDR request\n",
			      data_transfer_handle);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command,
			PLDM_PLATFORM_INVALID_DATA_TRANSFER_HANDLE);
		return OPAL_PARAMETER;
	}

	if (transfer_op_flag != PLDM_GET_FIRSTPART) {
		prlog(PR_ERR, "Got invalid transfer op flag 0x%x in GetPDR request\n",
			      transfer_op_flag);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command,
			PLDM_PLATFORM_INVALID_TRANSFER_OPERATION_FLAG);
		return OPAL_PARAMETER;
	}

	if (record_change_number != 0) {
		prlog(PR_ERR, "Got invalid record change number 0x%x in GetPDR request\n",
			      record_change_number);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command,
			PLDM_PLATFORM_INVALID_RECORD_CHANGE_NUMBER);
		return OPAL_PARAMETER;
	}

	/* find PDR record by record handle */
	prlog(PR_INFO, "BMC requesting PDR handle %d\n", record_handle);

	rc = pldm_platform_pdr_find_record(record_handle,
					   &pdr_data,
					   &pdr_data_size,
					   &next_record_handle);
	if (rc) {
		prlog(PR_ERR, "Got invalid record handle 0x%x in GetPDR request\n",
			      record_handle);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command,
			PLDM_PLATFORM_INVALID_RECORD_HANDLE);
		return OPAL_PARAMETER;
	}

	/* create a PLDM response message for GetPDR */
	data_size = sizeof(struct pldm_msg_hdr) +
		    sizeof(struct pldm_get_pdr_resp) +
		    pdr_data_size;

	tx = zalloc(sizeof(struct pldm_tx_data) + data_size);
	if (!tx)
		return OPAL_NO_MEM;
	tx->data_size = data_size - 1;
	tx->tag_owner = true;
	tx->msg_tag = rx->msg_tag;

	rc = encode_get_pdr_resp(rx->hdrinf.instance,
				 PLDM_SUCCESS,
				 next_record_handle,
				 0, /* No remaining data */
				 PLDM_START_AND_END,
				 pdr_data_size,
				 pdr_data,
				 0, /* CRC not used for START_AND_END */
				 (struct pldm_msg *)tx->data);
	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "Encode GetPDR Error, rc: %d\n", rc);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command, PLDM_ERROR);
		free(tx);
		return OPAL_PARAMETER;
	}

	/* send PLDM message over MCTP */
	rc = pldm_mctp_message_tx(tx);
	if (rc) {
		prlog(PR_ERR, "Failed to send GetPDR response, rc = %d\n", rc);
		free(tx);
		return OPAL_HARDWARE;
	}

	free(tx);
	return OPAL_SUCCESS;
}

static struct pldm_cmd pldm_platform_get_pdr = {
	.name = "PLDM_GET_PDR",
	.pldm_cmd_id = PLDM_GET_PDR,
	.handler = platform_get_pdr_handle,
};

/*
 * PLDM Fru commands support
 */
static struct pldm_type pldm_fru_type = {
	.name = "fru",
	.pldm_type_id = PLDM_FRU,
};

/* currently we support version 1.0 of fru table */
#define SUPPORTED_FRU_VERSION_MAJOR 1
#define SUPPORTED_FRU_VERSION_MINOR 0

/* Used by the metadata request handler for the value of
 * FRUTableMaximumSize
 * 0 means SetFRURecordTable command is not supported (see DSP 0257
 * v1.0.0 Table 9)
 */
#define FRU_TABLE_MAX_SIZE_UNSUPPORTED 0

/*
 * GetFRURecordTableMetadata (0X01)
 * The GetFRURecordTableMetadata command is used to get the FRU Record
 * Table metadata information that includes the FRU Record major
 * version, the FRU Record minor version, the size of the largest FRU
 * Record data, total length of the FRU Record Table, total number of
 * FRU Record Data structures, and the integrity checksum on the FRU
 * Record Table data.
 */
static int fru_get_record_table_metadata_handler(const struct pldm_rx_data *rx)
{
	size_t data_size = PLDM_MSG_SIZE(struct pldm_get_fru_record_table_metadata_resp);
	uint16_t total_record_set_identifiers, total_table_records;
	uint32_t fru_table_length;
	struct pldm_tx_data *tx;
	int rc;

	/*
	 * GetFRURecordTableMetadata requests
	 * don't have any payload, so no need to decode them
	 */

	/* add specific fru record */
	pldm_fru_set_local_table(&fru_table_length,
				 &total_record_set_identifiers,
				 &total_table_records);

	/* create a PLDM response message for GetFRURecordTableMetadata */
	tx = zalloc(sizeof(struct pldm_tx_data) + data_size);
	if (!tx)
		return OPAL_NO_MEM;
	tx->data_size = data_size;
	tx->tag_owner = true;
	tx->msg_tag = rx->msg_tag;

	rc = encode_get_fru_record_table_metadata_resp(
				rx->hdrinf.instance,
				PLDM_SUCCESS,
				SUPPORTED_FRU_VERSION_MAJOR,
				SUPPORTED_FRU_VERSION_MINOR,
				FRU_TABLE_MAX_SIZE_UNSUPPORTED,
				fru_table_length,
				total_record_set_identifiers,
				total_table_records,
				0, // checksum, not calculated
				(struct pldm_msg *)tx->data);
	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "Encode GetFRURecordTableMetadata Error, rc: %d\n", rc);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command, PLDM_ERROR);
		free(tx);
		return OPAL_PARAMETER;
	}

	/* send PLDM message over MCTP */
	rc = pldm_mctp_message_tx(tx);
	if (rc) {
		prlog(PR_ERR, "Failed to send GetFRURecordTableMetadata response, rc = %d\n", rc);
		free(tx);
		return OPAL_HARDWARE;
	}

	free(tx);
	return OPAL_SUCCESS;
}

static struct pldm_cmd pldm_fru_get_record_table_metadata = {
	.name = "PLDM_GET_FRU_RECORD_TABLE_METADATA",
	.pldm_cmd_id = PLDM_GET_FRU_RECORD_TABLE_METADATA,
	.handler = fru_get_record_table_metadata_handler,
};

/*
 * GetFRURecordTable (0X02)
 * The GetFRURecordTable command is used to get the FRU Record Table
 * data. This command is defined to allow the FRU Record Table data to
 * be transferred using a sequence of one or more command/response
 * messages.
 */
static int fru_get_record_table_handler(const struct pldm_rx_data *rx)
{
	struct pldm_get_fru_record_table_resp *resp;
	void *fru_record_table_bytes;
	uint32_t fru_record_table_size;
	struct pldm_tx_data *tx;
	struct pldm_msg *msg;
	size_t data_size;
	int rc;

	/* The getFruRecordTable requests do have request data, but it's
	 * only related to multi-part transfers which we don't support
	 * and which the BMC will not send us.
	 */

	/* get local fru record table */
	rc = pldm_fru_get_local_table(&fru_record_table_bytes, &fru_record_table_size);
	if (rc) {
		prlog(PR_ERR, "Failed to get Fru Record Table\n");
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command, PLDM_ERROR);
		return OPAL_PARAMETER;
	}

	/* create a PLDM response message for GetFRURecordTable */
	data_size = sizeof(struct pldm_msg_hdr) +
		    sizeof(struct pldm_get_fru_record_table_resp) +
		    fru_record_table_size;

	tx = zalloc(sizeof(struct pldm_tx_data) + data_size);
	if (!tx)
		return OPAL_NO_MEM;
	tx->data_size = data_size - 1;
	tx->tag_owner = true;
	tx->msg_tag = rx->msg_tag;

	rc = encode_get_fru_record_table_resp(
				rx->hdrinf.instance,
				PLDM_SUCCESS,
				0, // No next transfer handle
				PLDM_START_AND_END,
				(struct pldm_msg *)tx->data);
	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "Encode GetFruRecordTable Error, rc: %d\n", rc);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command, PLDM_ERROR);
		free(tx);
		return OPAL_PARAMETER;
	}

	msg = (struct pldm_msg *)tx->data;
	resp = (struct pldm_get_fru_record_table_resp *)(msg->payload);
	memcpy(resp->fru_record_table_data,
	       fru_record_table_bytes,
	       fru_record_table_size);

	/* send PLDM message over MCTP */
	rc = pldm_mctp_message_tx(tx);
	if (rc) {
		prlog(PR_ERR, "Failed to send GetFruRecordTable response, rc = %d\n", rc);
		free(tx);
		return OPAL_HARDWARE;
	}

	free(tx);
	return OPAL_SUCCESS;
}

static struct pldm_cmd pldm_fru_get_record_table = {
	.name = "PLDM_GET_FRU_RECORD_TABLE",
	.pldm_cmd_id = PLDM_GET_FRU_RECORD_TABLE,
	.handler = fru_get_record_table_handler,
};

int pldm_responder_handle_request(struct pldm_rx_data *rx)
{
	const struct pldm_type *type;
	const struct pldm_cmd *cmd;

	prlog(PR_INFO, "Receive PLDM request from BMC, type: 0x%x, command: 0x%x\n",
			rx->hdrinf.pldm_type, rx->hdrinf.command);

	type = find_type(rx->hdrinf.pldm_type);
	if (!type) {
		prlog(PR_ERR, "Type not supported, type: 0x%x\n",
			      rx->hdrinf.pldm_type);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command,
			PLDM_ERROR_INVALID_PLDM_TYPE);
		return OPAL_UNSUPPORTED;
	}

	cmd = find_cmd(type, rx->hdrinf.command);
	if (!cmd) {
		prlog(PR_ERR, "Command not supported, type: 0x%x, command: 0x%x\n",
			      rx->hdrinf.pldm_type, rx->hdrinf.command);
		cc_resp(rx, rx->hdrinf.pldm_type,
			rx->hdrinf.command,
			PLDM_ERROR_UNSUPPORTED_PLDM_CMD);
		return OPAL_UNSUPPORTED;
	}

	return cmd->handler(rx);
}

int pldm_responder_init(void)
{
	/* Register mandatory commands we'll respond to - DSP0240 */
	add_type(&pldm_base_type);
	add_cmd(&pldm_base_type, &pldm_base_get_tid);
	add_cmd(&pldm_base_type, &pldm_base_get_types);
	add_cmd(&pldm_base_type, &pldm_base_get_commands);
	add_cmd(&pldm_base_type, &pldm_base_get_version);

	/* Register platform commands we'll respond to - DSP0248 */
	add_type(&pldm_platform_type);
	add_cmd(&pldm_platform_type, &pldm_platform_set_event_receiver);
	add_cmd(&pldm_platform_type, &pldm_platform_event_message);
	add_cmd(&pldm_platform_type, &pldm_platform_get_state_sensor_readings);
	add_cmd(&pldm_platform_type, &pldm_platform_set_state_effecter_states);
	add_cmd(&pldm_platform_type, &pldm_platform_get_pdr);

	/* Register fru commands we'll respond to - DSP0257 */
	add_type(&pldm_fru_type);
	add_cmd(&pldm_fru_type, &pldm_fru_get_record_table_metadata);
	add_cmd(&pldm_fru_type, &pldm_fru_get_record_table);

	return OPAL_SUCCESS;
}
