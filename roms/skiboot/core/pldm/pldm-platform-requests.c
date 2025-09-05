// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// Copyright 2022 IBM Corp.

#define pr_fmt(fmt) "PLDM: " fmt

#include <cpu.h>
#include <opal.h>
#include <stdio.h>
#include <string.h>
#include <timebase.h>
#include <inttypes.h>
#include <libpldm/entity.h>
#include <libpldm/pdr.h>
#include <libpldm/state_set.h>
#include <libpldm/platform.h>
#include "pldm.h"

#define NO_MORE_PDR_HANDLES 0

static pldm_pdr *pdrs_repo;
static bool pdr_ready;

struct pldm_pdrs {
	struct pldm_tx_data *tx;
	uint32_t record_hndl;
	bool done;
	int rc;
};

struct pldm_pdrs *pdrs;
/* assign specific sensor/effecter IDs */
#define PLDM_SENSOR_SE_ID_RANGE_START 0x6666
static int sensor_effecter_id = PLDM_SENSOR_SE_ID_RANGE_START;

static void pdr_init_complete(bool success)
{
	/* Read not successful, error out and free the buffer */
	if (!success) {
		pdr_ready = false;

		if (pdrs_repo) {
			pldm_pdr_destroy(pdrs_repo);
			pdrs_repo = NULL;
		}
		return;
	}

	/* Mark ready */
	pdr_ready = true;
}

/*
 * Find PDR record by record handle.
 */
int pldm_platform_pdr_find_record(uint32_t record_handle,
				  uint8_t **pdr_data,
				  uint32_t *pdr_data_size,
				  uint32_t *next_record_handle)
{
	const pldm_pdr_record *pdr_record;

	if (!pdr_ready)
		return OPAL_HARDWARE;

	pdr_record = pldm_pdr_find_record(pdrs_repo,
					  record_handle,
					  pdr_data,
					  pdr_data_size,
					  next_record_handle);

	if (!pdr_record)
		return OPAL_PARAMETER;

	return OPAL_SUCCESS;
}

/*
 * Search the matching record and return the sensor id.
 * PDR type = PLDM_STATE_SENSOR_PDR
 */
static int find_sensor_id_by_state_set_Id(uint16_t entity_type,
					  uint16_t state_set_id,
					  uint16_t *sensor_id,
					  uint16_t terminus_handle)
{
	struct state_sensor_possible_states *possible_states;
	struct pldm_state_sensor_pdr *state_sensor_pdr;
	const pldm_pdr_record *record = NULL;
	uint8_t *outData = NULL;
	uint32_t size;

	do {
		/* Find (first) PDR record by PLDM_STATE_SENSOR_PDR type
		 * if record not NULL, then search will begin from this
		 * record's next record
		 */
		record = pldm_pdr_find_record_by_type(
				pdrs_repo, /* PDR repo handle */
				PLDM_STATE_SENSOR_PDR,
				record, /* PDR record handle */
				&outData, &size);

		if (record) {
			state_sensor_pdr = (struct pldm_state_sensor_pdr *) outData;

			*sensor_id = le16_to_cpu(state_sensor_pdr->sensor_id);

			possible_states = (struct state_sensor_possible_states *)
				state_sensor_pdr->possible_states;

			if ((le16_to_cpu(state_sensor_pdr->entity_type) == entity_type) &&
			    (le16_to_cpu(state_sensor_pdr->terminus_handle) == terminus_handle) &&
			    (le16_to_cpu(possible_states->state_set_id) == state_set_id))
				return OPAL_SUCCESS;
		}

	} while (record);

	return OPAL_PARAMETER;
}

/*
 * Search the matching record and return the effecter id.
 * PDR type = PLDM_STATE_EFFECTER_PDR
 */
static int find_effecter_id_by_state_set_Id(uint16_t entity_type,
					    uint16_t state_set_id,
					    uint16_t *effecter_id,
					    uint16_t terminus_handle)
{
	struct state_effecter_possible_states *possible_states;
	struct pldm_state_effecter_pdr *state_effecter_pdr;
	const pldm_pdr_record *record = NULL;
	uint8_t *outData = NULL;
	uint32_t size;

	do {
		/* Find (first) PDR record by PLDM_STATE_EFFECTER_PDR type
		 * if record not NULL, then search will begin from this
		 * record's next record
		 */
		record = pldm_pdr_find_record_by_type(
				pdrs_repo, /* PDR repo handle */
				PLDM_STATE_EFFECTER_PDR,
				record, /* PDR record handle */
				&outData, &size);

		if (record) {
			state_effecter_pdr = (struct pldm_state_effecter_pdr *) outData;

			*effecter_id = le16_to_cpu(state_effecter_pdr->effecter_id);

			possible_states = (struct state_effecter_possible_states *)
				state_effecter_pdr->possible_states;

			if ((le16_to_cpu(state_effecter_pdr->entity_type) == entity_type) &&
			    (le16_to_cpu(state_effecter_pdr->terminus_handle) == terminus_handle) &&
			    (le16_to_cpu(possible_states->state_set_id) == state_set_id))
				return OPAL_SUCCESS;
		}

	} while (record);

	return OPAL_PARAMETER;
}

struct set_effecter_state_response {
	uint8_t completion_code;
};

/*
 * Create and send a PLDM request message for SetStateEffecterStates.
 */
static int set_state_effecter_states_req(uint16_t effecter_id,
					 set_effecter_state_field *field,
					 bool no_timeout)
{
	size_t data_size = PLDM_MSG_SIZE(struct pldm_set_state_effecter_states_req);
	struct set_effecter_state_response response;
	size_t response_len, payload_len;
	struct pldm_tx_data *tx = NULL;
	void *response_msg;
	int rc;

	struct pldm_set_state_effecter_states_req states_req = {
		.effecter_id = effecter_id,
		.comp_effecter_count = 1
	};

	/* Encode the state effecter states request */
	tx = zalloc(sizeof(struct pldm_tx_data) + data_size);
	if (!tx)
		return OPAL_NO_MEM;
	tx->data_size = data_size;

	rc = encode_set_state_effecter_states_req(
			DEFAULT_INSTANCE_ID,
			states_req.effecter_id,
			states_req.comp_effecter_count,
			field,
			(struct pldm_msg *)tx->data);
	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "Encode SetStateEffecter Error, rc: %d\n",
			      rc);
		free(tx);
		return OPAL_PARAMETER;
	}

	/* Send and get the response message bytes.
	 * It may happen that for some commands, the responder does not
	 * have time to respond.
	 */
	if (no_timeout) {
		rc = pldm_mctp_message_tx(tx);
		if (rc)
			prlog(PR_ERR, "Failed to send SetStateEffecter request, rc = %d\n", rc);
		free(tx);
		return rc;
	}

	/* Send and get the response message bytes */
	rc = pldm_requester_queue_and_wait(tx, &response_msg, &response_len);
	if (rc) {
		prlog(PR_ERR, "Communication Error, req: SetStateEffecter, rc: %d\n", rc);
		free(tx);
		return rc;
	}

	/* Decode the message */
	payload_len = response_len - sizeof(struct pldm_msg_hdr);

	rc = decode_set_state_effecter_states_resp(
				response_msg,
				payload_len,
				&response.completion_code);
	if (rc != PLDM_SUCCESS || response.completion_code != PLDM_SUCCESS) {
		prlog(PR_ERR, "Decode SetStateEffecter Error, rc: %d, cc: %d\n",
			      rc, response.completion_code);
		free(tx);
		free(response_msg);
		return OPAL_PARAMETER;
	}

	free(tx);
	free(response_msg);
	return OPAL_SUCCESS;
}

/*
 * entity_type:  System chassis (main enclosure)
 * state_set:    System Power State (260)
 * states:       Off-Soft Graceful(9)
 */
int pldm_platform_power_off(void)
{
	set_effecter_state_field field;
	uint16_t effecter_id;
	int rc;

	if (!pdr_ready)
		return OPAL_HARDWARE;

	rc = find_effecter_id_by_state_set_Id(
				PLDM_ENTITY_SYSTEM_CHASSIS,
				PLDM_STATE_SET_SYSTEM_POWER_STATE,
				&effecter_id, BMC_TID);
	if (rc) {
		prlog(PR_ERR, "%s - effecter id not found\n", __func__);
		return rc;
	}

	field.set_request = PLDM_REQUEST_SET;
	field.effecter_state = PLDM_STATE_SET_SYS_POWER_STATE_OFF_SOFT_GRACEFUL;

	prlog(PR_INFO, "sending system chassis Off-Soft Graceful request (effecter_id: %d)\n",
			effecter_id);

	return set_state_effecter_states_req(effecter_id, &field, true);
}

/*
 * entity_type:  System Firmware
 * state_set:    Software Termination Status(129)
 * states:       Graceful Restart Requested(6)
 */
int pldm_platform_restart(void)
{
	set_effecter_state_field field;
	uint16_t effecter_id;
	int rc;

	if (!pdr_ready)
		return OPAL_HARDWARE;

	rc = find_effecter_id_by_state_set_Id(
				PLDM_ENTITY_SYS_FIRMWARE,
				PLDM_STATE_SET_SW_TERMINATION_STATUS,
				&effecter_id, BMC_TID);
	if (rc) {
		prlog(PR_ERR, "%s - effecter id not found\n", __func__);
		return rc;
	}

	field.set_request = PLDM_REQUEST_SET;
	field.effecter_state = PLDM_SW_TERM_GRACEFUL_RESTART_REQUESTED;

	prlog(PR_INFO, "sending system firmware Graceful Restart request (effecter_id: %d)\n",
			effecter_id);

	return set_state_effecter_states_req(effecter_id, &field, true);
}

static int send_sensor_state_changed_event(uint16_t state_set_id,
					   uint16_t sensor_id,
					   uint8_t sensor_offset,
					   uint8_t sensor_state,
					   bool no_timeout)
{
	size_t event_data_size = 0, actual_event_data_size;
	size_t response_len, payload_len, data_size;
	uint8_t *event_data = NULL;
	struct pldm_tx_data *tx;
	void *response_msg;
	int rc, i;

	struct pldm_platform_event_message_req event_message_req = {
		.format_version = PLDM_PLATFORM_EVENT_MESSAGE_FORMAT_VERSION,
		.tid = HOST_TID,
		.event_class = PLDM_SENSOR_EVENT,
	};

	struct pldm_platform_event_message_resp response;

	prlog(PR_DEBUG, "%s - state_set_id: %d, sensor_id: %d, sensor_state: %d\n",
			__func__, state_set_id, sensor_id, sensor_state);

	/*
	 * The first time around this loop, event_data is nullptr which
	 * instructs the encoder to not actually do the encoding, but
	 * rather fill out actual_change_records_size with the correct
	 * size, stop and return PLDM_SUCCESS. Then we allocate the
	 * proper amount of memory and call the encoder again, which
	 * will cause it to actually encode the message.
	 */
	for (i = 0; i < 2; i++) {
		rc = encode_sensor_event_data(
			(struct pldm_sensor_event_data *)event_data,
			event_data_size,
			sensor_id,
			PLDM_STATE_SENSOR_STATE,
			sensor_offset,
			sensor_state,
			sensor_state,
			&actual_event_data_size);
		if (rc) {
			prlog(PR_ERR, "encode PldmSensorChgEventData Error, rc: %d\n", rc);
			return OPAL_PARAMETER;
		}

		if (event_data == NULL) {
			event_data_size = actual_event_data_size;
			event_data = zalloc(event_data_size);
			if (!event_data) {
				prlog(PR_ERR, "failed to allocate event data (size: 0x%lx)\n", event_data_size);
				return OPAL_NO_MEM;
			}
		}
	}

	/* Send the event request */
	payload_len = PLDM_PLATFORM_EVENT_MESSAGE_MIN_REQ_BYTES + event_data_size;

	data_size = sizeof(struct pldm_msg_hdr) +
		    sizeof(struct pldm_platform_event_message_req) +
		    event_data_size;
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
			(const uint8_t *)event_data,
			event_data_size,
			(struct pldm_msg *)tx->data,
			payload_len);
	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "Encode PlatformEventMessage Error, rc: %d\n", rc);
		free(event_data);
		free(tx);
		return OPAL_PARAMETER;
	}
	free(event_data);

	/* Send and get the response message bytes.
	 * It may happen that for some commands, the responder does not
	 * have time to respond.
	 */
	if (no_timeout) {
		rc = pldm_mctp_message_tx(tx);
		if (rc)
			prlog(PR_ERR, "Failed to send PlatformEventMessage request, rc = %d\n", rc);
		free(tx);
		return rc;
	}

	/* Send and get the response message bytes */
	rc = pldm_requester_queue_and_wait(tx,
					   &response_msg, &response_len);
	if (rc) {
		prlog(PR_ERR, "Communication Error, req: PlatformEventMessage, rc: %d\n", rc);
		free(tx);
		return rc;
	}
	free(tx);

	/* Decode the message */
	payload_len = response_len - sizeof(struct pldm_msg_hdr);
	rc = decode_platform_event_message_resp(
				response_msg,
				payload_len,
				&response.completion_code,
				&response.platform_event_status);
	if (rc != PLDM_SUCCESS || response.completion_code != PLDM_SUCCESS) {
		prlog(PR_ERR, "Decode PlatformEventMessage Error, rc: %d, cc: %d, pes: %d\n",
			      rc, response.completion_code,
			      response.platform_event_status);
		free(response_msg);
		return OPAL_PARAMETER;
	}

	free(response_msg);

	return OPAL_SUCCESS;
}

#define BOOT_STATE_SENSOR_INDEX 0

int pldm_platform_send_progress_state_change(
		enum pldm_state_set_boot_progress_state_values state)
{
	struct state_sensor_possible_states *possible_states;
	struct pldm_state_sensor_pdr *sensor_pdr = NULL;
	const pldm_pdr_record *record = NULL;
	uint16_t terminus_handle;
	uint8_t *outData = NULL;
	uint16_t sensor_id = 0;
	uint32_t size;

	if (!pdr_ready)
		return OPAL_HARDWARE;

	prlog(PR_INFO, "Setting boot progress, state: %d\n", state);

	do {
		/* Find (first) PDR record by PLDM_STATE_SENSOR_PDR type
		 * if record not NULL, then search will begin from this
		 * record's next record
		 */
		record = pldm_pdr_find_record_by_type(
				pdrs_repo, /* PDR repo handle */
				PLDM_STATE_SENSOR_PDR,
				record, /* PDR record handle */
				&outData, &size);

		if (record) {
			sensor_pdr = (struct pldm_state_sensor_pdr *) outData;
			terminus_handle = le16_to_cpu(sensor_pdr->terminus_handle);

			if ((le16_to_cpu(sensor_pdr->entity_type) == PLDM_ENTITY_SYS_BOARD) &&
			    (terminus_handle == HOST_TID)) {
				possible_states = (struct state_sensor_possible_states *)
							sensor_pdr->possible_states;

				if (le16_to_cpu(possible_states->state_set_id) ==
						PLDM_STATE_SET_BOOT_PROGRESS){
					sensor_id = le16_to_cpu(sensor_pdr->sensor_id);
					break;
				}
			}
		}

	} while (record);

	if (sensor_id == 0)
		return OPAL_PARAMETER;

	return send_sensor_state_changed_event(
			PLDM_STATE_SET_BOOT_PROGRESS,
			sensor_id,
			BOOT_STATE_SENSOR_INDEX,
			state,
			false);
}

#define SW_TERM_GRACEFUL_SHUTDOWN_INDEX 0

/*
 * entity_type:  System Firmware
 * state_set:    Software Termination Status(129)
 * states:       Graceful Shutdown Requested(7)
 */
int pldm_platform_initiate_shutdown(void)
{
	uint16_t sensor_id;
	int rc;

	if (!pdr_ready)
		return OPAL_HARDWARE;

	rc = find_sensor_id_by_state_set_Id(
				PLDM_ENTITY_SYSTEM_CHASSIS,
				PLDM_STATE_SET_SW_TERMINATION_STATUS,
				&sensor_id, HOST_TID);
	if (rc) {
		prlog(PR_ERR, "%s - sensor id not found\n", __func__);
		return rc;
	}

	prlog(PR_INFO, "sending system firmware Graceful Shutdown request (sensor_id: %d)\n",
			sensor_id);

	return send_sensor_state_changed_event(
			PLDM_STATE_SET_SW_TERMINATION_STATUS,
			sensor_id,
			SW_TERM_GRACEFUL_SHUTDOWN_INDEX,
			PLDM_SW_TERM_GRACEFUL_SHUTDOWN,
			true);
}

static int add_state_sensor_pdr(pldm_pdr *repo,
				uint32_t *record_handle,
				uint16_t entity_type,
				uint16_t state_set_id,
				uint32_t states)
{
	struct state_sensor_possible_states *possible_states;
	struct pldm_state_sensor_pdr *pdr;
	uint8_t DEFAULT_CONTAINER_ID = 0;
	size_t state_size, pdr_size, actual_pdr_size = 0;
	uint8_t *state_storage;
	uint32_t swapped;
	int rc;

	/* fill in possible states structure */
	state_size = sizeof(struct state_sensor_possible_states)
		     + sizeof(states)
		     - sizeof(bitfield8_t);
	state_storage = zalloc(state_size);
	if (!state_storage) {
		prlog(PR_ERR, "failed to allocate storage data (size: 0x%lx)\n", state_size);
		return OPAL_NO_MEM;
	}

	possible_states = (struct state_sensor_possible_states *) state_storage;
	possible_states->state_set_id = state_set_id;
	possible_states->possible_states_size = sizeof(states);

	/* need to swap the byte order for little endian order */
	swapped = htole32(states);
	memcpy(possible_states->states, &swapped, sizeof(swapped));

	pdr_size = sizeof(struct pldm_state_sensor_pdr) + state_size;
	pdr = zalloc(pdr_size);
	if (!pdr) {
		prlog(PR_ERR, "failed to allocate sensor pdr (size: 0x%lx)\n", pdr_size);
		free(state_storage);
		return OPAL_NO_MEM;
	}

	/* header */
	pdr->hdr.record_handle = 0; /* ask libpldm to fill this out */
	pdr->hdr.version = 0; /* will be filled out by the encoder */
	pdr->hdr.type = 0; /* will be filled out by the encoder */
	pdr->hdr.record_change_num = 0;
	pdr->hdr.length = 0; /* will be filled out by the encoder */

	/* body */
	pdr->terminus_handle = HOST_TID;
	pdr->sensor_id = sensor_effecter_id++;
	pdr->entity_type = entity_type;
	pdr->entity_instance = 1;
	pdr->container_id = DEFAULT_CONTAINER_ID;
	pdr->sensor_init = PLDM_NO_INIT;
	pdr->sensor_auxiliary_names_pdr = false;
	pdr->composite_sensor_count = 1;

	rc = encode_state_sensor_pdr(pdr, pdr_size,
				     possible_states,
				     state_size,
				     &actual_pdr_size);

	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "%s - Failed to encode state sensor PDR, rc: %d\n",
			      __func__, rc);
		free(state_storage);
		free(pdr);
		return rc;
	}

	*record_handle = pldm_pdr_add(repo,
				      (const uint8_t *) pdr,
				      actual_pdr_size,
				      0, false, HOST_TID);

	free(state_storage);
	free(pdr);

	return OPAL_SUCCESS;
}

/*
 * Add boot progress record in the repository.
 */
static uint32_t add_sensor_sw_term_pdr(pldm_pdr *repo,
				       uint32_t *record_handle)
{
	int rc;

	rc = add_state_sensor_pdr(
			repo,
			record_handle,
			PLDM_ENTITY_SYSTEM_CHASSIS,
			PLDM_STATE_SET_SW_TERMINATION_STATUS,
			enum_bit(PLDM_SW_TERM_NORMAL) |
			enum_bit(PLDM_SW_TERM_GRACEFUL_SHUTDOWN_REQUESTED) |
			enum_bit(PLDM_SW_TERM_GRACEFUL_SHUTDOWN));
	if (rc) {
		prlog(PR_ERR, "%s - Failed to add states sensor PDR, rc: %d\n",
			      __func__, rc);
		return rc;
	}

	prlog(PR_DEBUG, "Add state sensor pdr (record handle: %d)\n",
			*record_handle);

	return OPAL_SUCCESS;
}

/*
 * Add boot progress record in the repository.
 */
static uint32_t add_boot_progress_pdr(pldm_pdr *repo,
				      uint32_t *record_handle)
{
	int rc;

	rc = add_state_sensor_pdr(
			repo,
			record_handle,
			PLDM_ENTITY_SYS_BOARD,
			PLDM_STATE_SET_BOOT_PROGRESS,
			enum_bit(PLDM_STATE_SET_BOOT_PROG_STATE_COMPLETED) |
			enum_bit(PLDM_STATE_SET_BOOT_PROG_STATE_PCI_RESORUCE_CONFIG) |
			enum_bit(PLDM_STATE_SET_BOOT_PROG_STATE_STARTING_OP_SYS));
	if (rc) {
		prlog(PR_ERR, "%s - Failed to add boot progress PDR, rc: %d\n",
			      __func__, rc);
		return rc;
	}

	prlog(PR_DEBUG, "Add boot progress pdr (record handle: %d)\n",
			*record_handle);

	return OPAL_SUCCESS;
}

static int add_state_effecter_pdr(pldm_pdr *repo,
				  uint32_t *record_handle,
				  uint16_t entity_type,
				  uint16_t state_set_id,
				  uint32_t states)
{
	struct state_effecter_possible_states *possible_states;
	struct pldm_state_effecter_pdr *pdr;
	uint8_t DEFAULT_CONTAINER_ID = 0;
	size_t state_size, pdr_size, actual_pdr_size = 0;
	uint8_t *state_storage;
	uint32_t swapped;
	int rc;

	/* fill in possible states structure */
	state_size = sizeof(struct state_effecter_possible_states)
		     + sizeof(states)
		     - sizeof(bitfield8_t);
	state_storage = zalloc(state_size);
	if (!state_storage) {
		prlog(PR_ERR, "failed to allocate storage data (size: 0x%lx)\n", state_size);
		return OPAL_NO_MEM;
	}

	possible_states = (struct state_effecter_possible_states *) state_storage;
	possible_states->state_set_id = state_set_id;
	possible_states->possible_states_size = sizeof(states);

	/* need to swap the byte order for little endian order */
	swapped = htole32(states);
	memcpy(possible_states->states, &swapped, sizeof(swapped));

	pdr_size = sizeof(struct pldm_state_effecter_pdr) + state_size;
	pdr = zalloc(pdr_size);
	if (!pdr) {
		prlog(PR_ERR, "failed to allocate sensor pdr (size: 0x%lx)\n", pdr_size);
		free(state_storage);
		return OPAL_NO_MEM;
	}

	/* header */
	pdr->hdr.record_handle = 0; /* ask libpldm to fill this out */
	pdr->hdr.version = 0; /* will be filled out by the encoder */
	pdr->hdr.type = 0; /* will be filled out by the encoder */
	pdr->hdr.record_change_num = 0;
	pdr->hdr.length = 0; /* will be filled out by the encoder */

	/* body */
	pdr->terminus_handle = HOST_TID;
	pdr->effecter_id = sensor_effecter_id++;
	pdr->entity_type = entity_type;
	pdr->entity_instance = 1;
	pdr->container_id = DEFAULT_CONTAINER_ID;
	pdr->effecter_semantic_id = 0; /* PLDM defines no semantic IDs yet */
	pdr->effecter_init = PLDM_NO_INIT;
	pdr->has_description_pdr = false;
	pdr->composite_effecter_count = 1;

	rc = encode_state_effecter_pdr(pdr, pdr_size, possible_states,
				       state_size, &actual_pdr_size);
	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "%s - Failed to encode state effecter PDR, rc: %d\n",
			      __func__, rc);
		free(state_storage);
		free(pdr);
		return rc;
	}

	*record_handle = pldm_pdr_add(repo,
				      (const uint8_t *) pdr,
				      actual_pdr_size,
				      0, false, HOST_TID);

	free(state_storage);
	free(pdr);

	return OPAL_SUCCESS;
}

/*
 * Add state software termination record in the repository.
 */
static uint32_t add_state_sw_term_pdr(pldm_pdr *repo,
				      uint32_t *record_handle)
{
	int rc;

	rc = add_state_effecter_pdr(
			repo,
			record_handle,
			PLDM_ENTITY_SYSTEM_CHASSIS,
			PLDM_STATE_SET_SW_TERMINATION_STATUS,
			enum_bit(PLDM_SW_TERM_GRACEFUL_SHUTDOWN_REQUESTED));
	if (rc) {
		prlog(PR_ERR, "%s - Failed to add boot progress PDR, rc: %d\n",
			      __func__, rc);
		return rc;
	}

	prlog(PR_DEBUG, "Add state software termination pdr (record handle: %d)\n",
			*record_handle);

	return OPAL_SUCCESS;
}

/*
 * Add terminus locator record in the repository.
 */
static int add_terminus_locator_pdr(pldm_pdr *repo,
				    uint32_t *record_handle)
{
	struct pldm_terminus_locator_type_mctp_eid *locator_value;
	struct pldm_terminus_locator_pdr pdr;
	uint8_t DEFAULT_CONTAINER_ID = 0;
	uint32_t size;

	pdr.hdr.record_handle = 0; /* record_handle will be generated for us */
	pdr.hdr.version = 1;
	pdr.hdr.type = PLDM_TERMINUS_LOCATOR_PDR;
	pdr.hdr.record_change_num = 0;
	pdr.hdr.length = htole16(sizeof(struct pldm_terminus_locator_pdr) -
				  sizeof(struct pldm_pdr_hdr));
	pdr.terminus_handle = htole16(HOST_TID);
	pdr.validity = PLDM_TL_PDR_VALID;
	pdr.tid = HOST_TID;
	pdr.container_id = DEFAULT_CONTAINER_ID;
	pdr.terminus_locator_type = PLDM_TERMINUS_LOCATOR_TYPE_MCTP_EID;
	pdr.terminus_locator_value_size = sizeof(struct pldm_terminus_locator_type_mctp_eid);
	locator_value = (struct pldm_terminus_locator_type_mctp_eid *)pdr.terminus_locator_value;
	locator_value->eid = HOST_EID;

	size = sizeof(struct pldm_terminus_locator_pdr) +
	       sizeof(struct pldm_terminus_locator_type_mctp_eid);

	*record_handle = pldm_pdr_add(repo,
				      (const uint8_t *)(&pdr), size,
				      0, false, HOST_TID);

	prlog(PR_DEBUG, "Add terminus locator pdr (record handle: %d)\n",
			 *record_handle);

	return OPAL_SUCCESS;
}

static int send_repository_changed_event(uint32_t num_changed_pdrs,
					 uint32_t *record_handle)
{
	size_t actual_change_records_size = 0;
	uint8_t number_of_change_entries[1];
	size_t max_change_records_size = 0;
	size_t response_len, payload_len;
	uint8_t event_data_operation[1];
	uint32_t *change_entries[1];
	uint8_t *event_data = NULL;
	struct pldm_tx_data *tx;
	void *response_msg;
	size_t data_size;
	int rc, i;

	struct pldm_platform_event_message_req event_message_req = {
		.format_version = PLDM_PLATFORM_EVENT_MESSAGE_FORMAT_VERSION,
		.tid = HOST_TID,
		.event_class = PLDM_PDR_REPOSITORY_CHG_EVENT,
	};

	struct pldm_platform_event_message_resp response = {0};

	prlog(PR_DEBUG, "%s - num_changed_pdrs: %d\n", __func__, num_changed_pdrs);

	if (num_changed_pdrs == 0)
		return OPAL_PARAMETER;

	/* encode the platform change event data */
	event_data_operation[0] = PLDM_RECORDS_ADDED;
	number_of_change_entries[0] = num_changed_pdrs;
	change_entries[0] = record_handle;

	/*
	 * The first time around this loop, event_data is nullptr which
	 * instructs the encoder to not actually do the encoding, but
	 * rather fill out actual_change_records_size with the correct
	 * size, stop and return PLDM_SUCCESS. Then we allocate the
	 * proper amount of memory and call the encoder again, which
	 * will cause it to actually encode the message.
	 */
	for (i = 0; i < 2; i++) {
		rc = encode_pldm_pdr_repository_chg_event_data(
					FORMAT_IS_PDR_HANDLES,
					1, /* only one change record (RECORDS_ADDED) */
					event_data_operation,
					number_of_change_entries,
					(const uint32_t * const*)change_entries,
					(struct pldm_pdr_repository_chg_event_data *)event_data,
					&actual_change_records_size,
					max_change_records_size);
		if (rc) {
			prlog(PR_ERR, "Encode PldmPdrRepositoryChgEventData Error, rc: %d\n", rc);
			return OPAL_PARAMETER;
		}

		if (event_data == NULL) {
			max_change_records_size = actual_change_records_size;
			event_data = zalloc(max_change_records_size);
			if (!event_data) {
				prlog(PR_ERR, "failed to allocate event data (size: 0x%lx)\n", max_change_records_size);
				return OPAL_NO_MEM;
			}
		}
	}

	/* Send the event request */
	payload_len = PLDM_PLATFORM_EVENT_MESSAGE_MIN_REQ_BYTES + max_change_records_size;

	data_size = sizeof(struct pldm_msg_hdr) +
		    sizeof(struct pldm_platform_event_message_req) +
		    max_change_records_size;
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
			(const uint8_t *)event_data,
			max_change_records_size,
			(struct pldm_msg *)tx->data,
			payload_len);
	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "Encode PlatformEventMessage Error, rc: %d\n", rc);
		free(event_data);
		free(tx);
		return OPAL_PARAMETER;
	}
	free(event_data);

	/* Send and get the response message bytes */
	rc = pldm_requester_queue_and_wait(tx, &response_msg, &response_len);
	if (rc) {
		prlog(PR_ERR, "Communication Error, req: PlatformEventMessage, rc: %d\n", rc);
		free(tx);
		return rc;
	}
	free(tx);

	/* Decode the message */
	payload_len = response_len - sizeof(struct pldm_msg_hdr);
	rc = decode_platform_event_message_resp(
				response_msg,
				payload_len,
				&response.completion_code,
				&response.platform_event_status);
	if (rc != PLDM_SUCCESS || response.completion_code != PLDM_SUCCESS) {
		prlog(PR_ERR, "Decode PlatformEventMessage Error, rc: %d, cc: %d, pes: %d\n",
			      rc, response.completion_code,
			      response.platform_event_status);
		free(response_msg);
		return OPAL_PARAMETER;
	}

	free(response_msg);

	return OPAL_SUCCESS;
}

static int add_hosted_pdrs(pldm_pdr *repo)
{
	static uint32_t records_handle[2];
	uint8_t hosted_pdrs = 0;
	uint32_t record_handle;
	int rc = OPAL_SUCCESS;

	rc = add_state_sw_term_pdr(repo, &record_handle);
	if (!rc) {
		records_handle[hosted_pdrs] = record_handle;
		hosted_pdrs++;
	}

	rc = add_sensor_sw_term_pdr(repo, &record_handle);
	if (!rc) {
		records_handle[hosted_pdrs] = record_handle;
		hosted_pdrs++;
	}

	rc = add_boot_progress_pdr(repo, &record_handle);
	if (!rc) {
		records_handle[hosted_pdrs] = record_handle;
		hosted_pdrs++;
	}

	rc = add_terminus_locator_pdr(repo, &record_handle);
	if (!rc) {
		records_handle[hosted_pdrs] = record_handle;
		hosted_pdrs++;
	}

	/* tell BMC that these PDRs have changed */
	rc = send_repository_changed_event(hosted_pdrs, records_handle);
	if (rc)
		prlog(PR_ERR, "%s - Failed to update hosted PDRs\n", __func__);

	return rc;
}

struct get_pdr_response {
	uint8_t completion_code;
	uint32_t next_record_hndl;
	uint32_t next_data_transfer_hndl;
	uint8_t transfer_flag;
	uint16_t resp_cnt;
	uint8_t *record_data;
	size_t record_data_length;
	uint8_t transfer_crc;
};

static int encode_and_queue_get_pdr_req(struct pldm_pdrs *pdrs);

static void get_pdr_req_complete(struct pldm_rx_data *rx,
				 void *data)
{
	struct pldm_pdrs *pdrs = (struct pldm_pdrs *)data;
	uint32_t record_hndl = pdrs->record_hndl;
	struct get_pdr_response response;
	struct pldm_pdr_hdr *pdr_hdr;
	size_t payload_len;
	int rc, i;

	prlog(PR_DEBUG, "%s - record_hndl: %d\n", __func__, record_hndl);

	if (rx == NULL) {
		pdrs->rc = OPAL_PARAMETER;
		pdrs->done = true;
	}

	/* Decode the message twice; the first time, the payload buffer
	 * will be null so that the decoder will simply tell us how big
	 * the buffer should be. Then we create a suitable payload
	 * buffer and call the decoder again, this time with the real
	 * buffer so that it can fill it with data from the message.
	 *
	 * transfer_crc is not used in case of PLDM_START_AND_END.
	 */
	payload_len = rx->msg_len - sizeof(struct pldm_msg_hdr);
	response.record_data_length = 0;
	response.record_data = NULL;

	for (i = 0; i < 2; i++) {
		rc = decode_get_pdr_resp(
				rx->msg, payload_len,
				&response.completion_code,
				&response.next_record_hndl,
				&response.next_data_transfer_hndl,
				&response.transfer_flag,
				&response.resp_cnt,
				response.record_data,
				response.record_data_length,
				&response.transfer_crc);

		if (rc != PLDM_SUCCESS || response.completion_code != PLDM_SUCCESS) {
			/* Message decoding failed */
			prlog(PR_ERR, "Decode GetPDRResp Error (rc: %d, cc: %d)\n",
				      rc, response.completion_code);

			/* BMC is not ready, try again. This behavior can be
			 * encountered when the BMC reboots and the host is
			 * still operational.
			 * The host receives a GET VERSION request indicating
			 * that we must rehcrage the pdrs.
			 */
			if (response.completion_code == PLDM_ERROR_NOT_READY) {
				time_wait_ms(500);
				encode_and_queue_get_pdr_req(pdrs);
				return;
			}

			pdrs->rc = OPAL_PARAMETER;
			pdrs->done = true;
			return;
		}

		if (response.record_data == NULL) {
			response.record_data_length = response.resp_cnt;
			response.record_data = zalloc(response.resp_cnt);
			if (!response.record_data) {
				prlog(PR_ERR, "failed to allocate record data (size: 0x%lx)\n", response.record_data_length);
				pdrs->rc = OPAL_NO_MEM;
				pdrs->done = true;
				return;
			}
		}
	}

	/* we do not support multipart transfer */
	if (response.transfer_flag != PLDM_START_AND_END)
		prlog(PR_ERR, "Transfert GetPDRResp not complete, transfer_flag: %d\n",
			      response.transfer_flag);
	pdr_hdr = (struct pldm_pdr_hdr *)response.record_data;
	record_hndl = pdr_hdr->record_handle;

	prlog(PR_DEBUG, "%s - record_hndl: %d, next_record_hndl: %d, resp_cnt: %d\n",
			__func__, record_hndl,
			response.next_record_hndl,
			response.resp_cnt);

	/* Add a PDR record to a PDR repository.
	 * Use HOST_TID as terminus handle
	 */
	pldm_pdr_add(pdrs_repo,
		     response.record_data,
		     response.resp_cnt,
		     record_hndl,
		     false,
		     HOST_TID);

	free(response.record_data);

	if (response.next_record_hndl != NO_MORE_PDR_HANDLES) {
		pdrs->record_hndl = response.next_record_hndl;
		encode_and_queue_get_pdr_req(pdrs);
	} else {
		/* We have to indicate the end of the initialization when we
		 * reload the pdrs in background
		 */
		pdr_init_complete(true);
		pdrs->done = true;
		pdrs->rc = OPAL_SUCCESS;
		prlog(PR_DEBUG, "%s - done\n", __func__);
	}
}

/*
 * Send/receive a PLDM GetPDR stateEffecter request message
 * Get platform descriptor records.
 *
 * pldmtool platform GetPDR -t stateEffecter
 * ...
 * {
 * "nextRecordHandle": 138,
 * "responseCount": 30,
 * "recordHandle": 137,
 * "PDRHeaderVersion": 1,
 * "PDRType": "State Effecter PDR",
 * "recordChangeNumber": 0,
 * "dataLength": 20,
 * "PLDMTerminusHandle": 1,
 * "effecterID": 43,
 * "entityType": "[Physical] System chassis (main enclosure)",
 * ...
 * "Off-Soft Graceful(9)"
 * }
 * ...
 */
static int encode_and_queue_get_pdr_req(struct pldm_pdrs *pdrs)
{
	uint32_t record_hndl = pdrs->record_hndl;
	int rc;

	struct pldm_get_pdr_req pdr_req = {
		.record_handle = record_hndl, /* record change number (0 for first request) */
		.data_transfer_handle = 0, /* (0 if transfer op is FIRSTPART) */
		.transfer_op_flag = PLDM_GET_FIRSTPART, /* transfer op flag */
		.request_count = SHRT_MAX, /* Don't limit the size of the PDR */
		.record_change_number = 0 /* record change number (0 for first request) */
	};

	prlog(PR_DEBUG, "%s - record_hndl: %d\n", __func__, record_hndl);

	/* Encode the get_PDR request */
	rc = encode_get_pdr_req(DEFAULT_INSTANCE_ID,
				pdr_req.record_handle,
				pdr_req.data_transfer_handle,
				pdr_req.transfer_op_flag,
				pdr_req.request_count,
				pdr_req.record_change_number,
				(struct pldm_msg *)pdrs->tx->data,
				PLDM_GET_PDR_REQ_BYTES);
	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "Encode GetPDRReq Error, rc: %d\n", rc);
		pdrs->done = true;
		pdrs->rc = OPAL_PARAMETER;
		return OPAL_PARAMETER;
	}

	/* Queue the first getpdr request */
	rc = pldm_requester_queue(pdrs->tx, get_pdr_req_complete, pdrs);
	if (rc) {
		prlog(PR_ERR, "Communication Error, req: GetPDRReq, rc: %d\n", rc);
		pdrs->done = true;
		pdrs->rc = OPAL_PARAMETER;
	}

	return rc;
}

static int pldm_platform_load_pdrs(void)
{
	/* destroy current repo and mark repo not ready */
	pdr_init_complete(false);

	/* make a new PDR repository */
	pdrs_repo = pldm_pdr_init();

	/* collect all PDrs into a PDR Repository */
	pdrs->record_hndl = 0;
	pdrs->done = false;
	return encode_and_queue_get_pdr_req(pdrs);
}

int pldm_platform_reload_pdrs(void)
{
	return pldm_platform_load_pdrs();
}

static int pdrs_init(void)
{
	int rc;

	rc = pldm_platform_load_pdrs();
	if (rc)
		return rc;

	/* wait for the end of pdrs received */
	for (;;) {
		if (pdrs->done)
			break;

		time_wait_ms(5);
	}
	return pdrs->rc;
}

int pldm_platform_init(void)
{
	size_t data_size = PLDM_MSG_SIZE(struct pldm_get_pdr_req);
	int rc;

	pdrs = zalloc(sizeof(struct pldm_pdrs));
	if (!pdrs) {
		prlog(PR_ERR, "failed to allocate pdrs\n");
		return OPAL_NO_MEM;
	}

	pdrs->tx = zalloc(sizeof(struct pldm_tx_data) + data_size);
	if (!pdrs->tx)
		return OPAL_NO_MEM;
	pdrs->tx->data_size = data_size;

	/* retrieve all PDRs */
	rc = pdrs_init();
	if (rc)
		goto err;

	/* add hosted pdrs */
	rc = add_hosted_pdrs(pdrs_repo);
	if (rc)
		goto err;

	pdr_init_complete(true);
	prlog(PR_DEBUG, "%s - done\n", __func__);

	return OPAL_SUCCESS;

err:
	prlog(PR_ERR, "%s - failed to initialize pdrs, rc: %d\n", __func__, rc);
	pdr_init_complete(false);
	free(pdrs->tx);
	free(pdrs);
	return rc;
}

void pldm_platform_exit(void)
{
	if (pdr_ready)
		pldm_pdr_destroy(pdrs_repo);

	if (pdrs) {
		free(pdrs->tx);
		free(pdrs);
	}
}
