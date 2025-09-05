#ifndef OEM_IBM_HOST_H
#define OEM_IBM_HOST_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "base.h"

/* Maximum size for request */
#define PLDM_GET_ALERT_STATUS_REQ_BYTES 1

/* Response lengths are inclusive of completion code */
#define PLDM_GET_ALERT_STATUS_RESP_BYTES 9

enum pldm_host_commands {
	PLDM_HOST_GET_ALERT_STATUS = 0xF0 // Custom oem cmd
};

/** @brief PLDM Command specific codes
 */
enum pldm_host_completion_codes { PLDM_HOST_UNSUPPORTED_FORMAT_VERSION = 0x81 };

/** @struct pldm_get_alert_states_resp
 *
 * Structure representing GetAlertStatus response packet
 */
struct pldm_get_alert_status_resp {
	uint8_t completion_code;
	uint32_t rack_entry;
	uint32_t pri_cec_node;
} __attribute__((packed));

/* Requester */

/* GetAlertStatus */

/** @brief Create a PLDM request message for GetAlertStatus
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] version_id - The command/response format. 0x00 for this format
 *  @param[out] msg - Message will be written to this
 *  @param[in] payload_length - Length of request message payload
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_get_alert_status_req(uint8_t instance_id, uint8_t version_id,
				struct pldm_msg *msg, size_t payload_length);

/** @brief Decode GetAlertStatus response data
 *
 *  Note:
 *  * If the return value is not PLDM_SUCCESS, it represents a
 * transport layer error.
 *  * If the completion_code value is not PLDM_SUCCESS, it represents a
 * protocol layer error and all the out-parameters are invalid.
 *
 *  @param[in] msg - Request message
 *  @param[in] payload_length - Length of request message payload
 *  @param[out] completion_code - PLDM completion code
 *  @param[out] rack_entry - Enclosure ID, Alert Status, Flags, Config ID
 *  @param[out] pri_cec_node - Enclosure ID, Alert Status, Flags, Config ID
 *  @return pldm_completion_codes
 */
int decode_get_alert_status_resp(const struct pldm_msg *msg,
				 size_t payload_length,
				 uint8_t *completion_code, uint32_t *rack_entry,
				 uint32_t *pri_cec_node);

/* Responder */

/* GetAlertStatus */

/** @brief Decode GetAlertStatus request data
 *
 *  @param[in] msg - Request message
 *  @param[in] payload_length - Length of request message payload
 *  @param[out] version_id - the command/response format. 0x00 for this format
 *  @return pldm_completion_codes
 */
int decode_get_alert_status_req(const struct pldm_msg *msg,
				size_t payload_length, uint8_t *version_id);

/** @brief Create a PLDM OEM response message for GetAlertStatus
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - PLDM completion code
 *  @param[in] rack_entry - Enclosure ID, Alert Status, Flags, Config ID
 *  @param[in] pri_cec_node - Enclosure ID, Alert Status, Flags, Config ID
 *  @param[out] msg - Message will be written to this
 *  @param[in] payload_length - Length of request message payload
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.body.payload'
 */
int encode_get_alert_status_resp(uint8_t instance_id, uint8_t completion_code,
				 uint32_t rack_entry, uint32_t pri_cec_node,
				 struct pldm_msg *msg, size_t payload_length);

#ifdef __cplusplus
}
#endif

#endif /* OEM_IBM_HOST_H */
