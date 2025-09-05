#include "libpldm/platform.h"
#include "libpldm/platform_oem_ibm.h"
#include <string.h>

int encode_bios_attribute_update_event_req(uint8_t instance_id,
					   uint8_t format_version, uint8_t tid,
					   uint8_t num_handles,
					   const uint8_t *list_of_handles,
					   size_t payload_length,
					   struct pldm_msg *msg)
{
	if (format_version != 1) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (msg == NULL || list_of_handles == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (num_handles == 0) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (payload_length !=
	    (PLDM_PLATFORM_EVENT_MESSAGE_MIN_REQ_BYTES + sizeof(num_handles) +
	     (num_handles * sizeof(uint16_t)))) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_header_info header = {0};
	header.msg_type = PLDM_REQUEST;
	header.instance = instance_id;
	header.pldm_type = PLDM_PLATFORM;
	header.command = PLDM_PLATFORM_EVENT_MESSAGE;
	uint8_t rc = pack_pldm_header(&header, &(msg->hdr));
	if (rc != PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_bios_attribute_update_event_req *request =
	    (struct pldm_bios_attribute_update_event_req *)msg->payload;
	request->format_version = format_version;
	request->tid = tid;
	request->event_class = PLDM_EVENT_TYPE_OEM_EVENT_BIOS_ATTRIBUTE_UPDATE;
	request->num_handles = num_handles;
	memcpy(request->bios_attribute_handles, list_of_handles,
	       num_handles * sizeof(uint16_t));

	return PLDM_SUCCESS;
}
