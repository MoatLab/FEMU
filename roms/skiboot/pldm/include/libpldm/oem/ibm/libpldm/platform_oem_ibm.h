#ifndef PLATFORM_OEM_IBM_H
#define PLATFORM_OEM_IBM_H

#ifdef __cplusplus
extern "C" {
#endif

#include "base.h"
#include <stddef.h>
#include <stdint.h>

enum pldm_event_types_ibm_oem {
	PLDM_EVENT_TYPE_OEM_EVENT_BIOS_ATTRIBUTE_UPDATE = 0xF0,
};

/** @struct pldm_bios_attribute_update_event_req
 *
 * 	Structure representing PlatformEventMessage command request data for OEM
 *  event type BIOS attribute update.
 */
struct pldm_bios_attribute_update_event_req {
	uint8_t format_version;
	uint8_t tid;
	uint8_t event_class;
	uint8_t num_handles;
	uint8_t bios_attribute_handles[1];
} __attribute__((packed));

/** @brief Encode PlatformEventMessage request data for BIOS attribute update
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] format_version - Version of the event format
 *  @param[in] tid - Terminus ID for the terminus that originated the event
 *                   message
 *  @param[in] num_handles - Number of BIOS handles with an update
 *  @param[in] list_of_handles - Pointer to the list of BIOS attribute handles
 *  @param[in] payload_length - Length of request message payload
 *  @param[out] msg - Message will be written to this
 *
 *  @return pldm_completion_codes
 *
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_bios_attribute_update_event_req(uint8_t instance_id,
					   uint8_t format_version, uint8_t tid,
					   uint8_t num_handles,
					   const uint8_t *list_of_handles,
					   size_t payload_length,
					   struct pldm_msg *msg);

#ifdef __cplusplus
}
#endif

#endif /* PLATFORM_OEM_IBM_H */