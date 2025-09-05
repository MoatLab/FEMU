#ifndef BIOS_H
#define BIOS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/* Response lengths are inclusive of completion code */
#define PLDM_GET_DATE_TIME_RESP_BYTES 8

#define PLDM_GET_BIOS_TABLE_REQ_BYTES			     6
#define PLDM_GET_BIOS_TABLE_MIN_RESP_BYTES		     6
#define PLDM_SET_BIOS_TABLE_MIN_REQ_BYTES		     6
#define PLDM_SET_BIOS_TABLE_RESP_BYTES			     5
#define PLDM_SET_BIOS_ATTR_CURR_VAL_MIN_REQ_BYTES	     5
#define PLDM_SET_BIOS_ATTR_CURR_VAL_RESP_BYTES		     5
#define PLDM_GET_BIOS_ATTR_CURR_VAL_BY_HANDLE_REQ_BYTES	     7
#define PLDM_GET_BIOS_ATTR_CURR_VAL_BY_HANDLE_MIN_RESP_BYTES 6

enum pldm_bios_completion_codes {
	PLDM_BIOS_TABLE_UNAVAILABLE = 0x83,
	PLDM_INVALID_BIOS_TABLE_DATA_INTEGRITY_CHECK = 0x84,
	PLDM_INVALID_BIOS_TABLE_TYPE = 0x85,
	PLDM_INVALID_BIOS_ATTR_HANDLE = 0x88,
};
enum pldm_bios_commands {
	PLDM_GET_BIOS_TABLE = 0x01,
	PLDM_SET_BIOS_TABLE = 0x02,
	PLDM_SET_BIOS_ATTRIBUTE_CURRENT_VALUE = 0x07,
	PLDM_GET_BIOS_ATTRIBUTE_CURRENT_VALUE_BY_HANDLE = 0x08,
	PLDM_GET_DATE_TIME = 0x0c,
	PLDM_SET_DATE_TIME = 0x0d,
};

enum pldm_bios_table_types {
	PLDM_BIOS_STRING_TABLE,
	PLDM_BIOS_ATTR_TABLE,
	PLDM_BIOS_ATTR_VAL_TABLE,
};

struct pldm_msg;
struct variable_field;

struct pldm_bios_string_table_entry {
	uint16_t string_handle;
	uint16_t string_length;
	char name[1];
} __attribute__((packed));

struct pldm_bios_attr_table_entry {
	uint16_t attr_handle;
	uint8_t attr_type;
	uint16_t string_handle;
	uint8_t metadata[1];
} __attribute__((packed));

struct pldm_bios_enum_attr {
	uint8_t num_possible_values;
	uint16_t indices[1];
} __attribute__((packed));

struct pldm_bios_attr_val_table_entry {
	uint16_t attr_handle;
	uint8_t attr_type;
	uint8_t value[1];
} __attribute__((packed));

enum pldm_bios_attribute_type {
	PLDM_BIOS_ENUMERATION = 0x0,
	PLDM_BIOS_STRING = 0x1,
	PLDM_BIOS_PASSWORD = 0x2,
	PLDM_BIOS_INTEGER = 0x3,
	PLDM_BIOS_ENUMERATION_READ_ONLY = 0x80,
	PLDM_BIOS_STRING_READ_ONLY = 0x81,
	PLDM_BIOS_PASSWORD_READ_ONLY = 0x82,
	PLDM_BIOS_INTEGER_READ_ONLY = 0x83,
};

/** @struct pldm_get_bios_table_req
 *
 *  structure representing GetBIOSTable request packet
 */
struct pldm_get_bios_table_req {
	uint32_t transfer_handle;
	uint8_t transfer_op_flag;
	uint8_t table_type;
} __attribute__((packed));

/** @struct pldm_get_bios_table_resp
 *
 *  structure representing GetBIOSTable response packet
 */
struct pldm_get_bios_table_resp {
	uint8_t completion_code;
	uint32_t next_transfer_handle;
	uint8_t transfer_flag;
	uint8_t table_data[1];
} __attribute__((packed));

/** @struct pldm_get_date_time_resp
 *
 *  Structure representing PLDM get date time response
 */
struct pldm_get_date_time_resp {
	uint8_t completion_code; //!< completion code
	uint8_t seconds;	 //!< Seconds in BCD format
	uint8_t minutes;	 //!< Minutes in BCD format
	uint8_t hours;		 //!< Hours in BCD format
	uint8_t day;		 //!< Day of the month in BCD format
	uint8_t month;		 //!< Month in BCD format
	uint16_t year;		 //!< Year in BCD format
} __attribute__((packed));

/** @struct pldm_set_date_time_req
 *
 *  structure representing SetDateTime request packet
 *
 */
struct pldm_set_date_time_req {
	uint8_t seconds; //!< Seconds in BCD format
	uint8_t minutes; //!< Minutes in BCD format
	uint8_t hours;	 //!< Hours in BCD format
	uint8_t day;	 //!< Day of the month in BCD format
	uint8_t month;	 //!< Month in BCD format
	uint16_t year;	 //!< Year in BCD format
} __attribute__((packed));

/** @struct pldm_only_cc_resp
 *
 *  Structure representing PLDM responses only have completion code
 */
struct pldm_only_cc_resp {
	uint8_t completion_code;
} __attribute__((packed));

/** @struct pldm_get_bios_attribute_current_value_by_handle_req
 *
 *  structure representing GetBIOSAttributeCurrentValueByHandle request packet
 */
struct pldm_get_bios_attribute_current_value_by_handle_req {
	uint32_t transfer_handle;
	uint8_t transfer_op_flag;
	uint16_t attribute_handle;
} __attribute__((packed));

/** @struct pldm_get_bios_attribute_current_value_by_handle_resp
 *
 *  structure representing GetBIOSAttributeCurrentValueByHandle response
 */
struct pldm_get_bios_attribute_current_value_by_handle_resp {
	uint8_t completion_code;
	uint32_t next_transfer_handle;
	uint8_t transfer_flag;
	uint8_t attribute_data[1];
} __attribute__((packed));

/** @struct pldm_set_bios_attribute_current_value_req
 *
 *  structure representing SetBiosAttributeCurrentValue request packet
 *
 */
struct pldm_set_bios_attribute_current_value_req {
	uint32_t transfer_handle;
	uint8_t transfer_flag;
	uint8_t attribute_data[1];
} __attribute__((packed));

/** @struct pldm_set_bios_attribute_current_value_resp
 *
 *  structure representing SetBiosCurrentValue response packet
 *
 */
struct pldm_set_bios_attribute_current_value_resp {
	uint8_t completion_code;
	uint32_t next_transfer_handle;
} __attribute__((packed));

/** @struct pldm_set_bios_table_req
 *
 *  structure representing SetBIOSTable request packet
 *
 */
struct pldm_set_bios_table_req {
	uint32_t transfer_handle;
	uint8_t transfer_flag;
	uint8_t table_type;
	uint8_t table_data[1];
} __attribute__((packed));

/** @struct pldm_set_bios_table_resp
 *
 *  structure representing SetBIOSTable response packet
 *
 */
struct pldm_set_bios_table_resp {
	uint8_t completion_code;
	uint32_t next_transfer_handle;
} __attribute__((packed));

/* Requester */

/* GetDateTime */

/** @brief Create a PLDM request message for GetDateTime
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.body.payload'
 */

int encode_get_date_time_req(uint8_t instance_id, struct pldm_msg *msg);

/** @brief Decode a GetDateTime response message
 *
 *  Note:
 *  * If the return value is not PLDM_SUCCESS, it represents a
 * transport layer error.
 *  * If the completion_code value is not PLDM_SUCCESS, it represents a
 * protocol layer error and all the out-parameters are invalid.
 *
 *  @param[in] msg - Response message
 *  @param[in] payload_length - Length of response message payload
 *  @param[out] completion_code - Pointer to response msg's PLDM completion code
 *  @param[out] seconds - Seconds in BCD format
 *  @param[out] minutes - minutes in BCD format
 *  @param[out] hours - hours in BCD format
 *  @param[out] day - day of month in BCD format
 *  @param[out] month - number of month in BCD format
 *  @param[out] year - year in BCD format
 *  @return pldm_completion_codes
 */
int decode_get_date_time_resp(const struct pldm_msg *msg, size_t payload_length,
			      uint8_t *completion_code, uint8_t *seconds,
			      uint8_t *minutes, uint8_t *hours, uint8_t *day,
			      uint8_t *month, uint16_t *year);

/* SetBiosAttributeCurrentValue */

/** @brief Create a PLDM request message for SetBiosAttributeCurrentValue
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] transfer_handle - Handle to identify a BIOS table transfer
 *  @param[in] transfer_flag - Flag to indicate what part of the transfer
 * this request represents
 *  @param[in] attribute_data - Contains current value of attribute
 *  @param[in] attribute_length - Length of attribute
 *  @param[out] msg - Message will be written to this
 *  @param[in] payload_length - Length of message payload
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of params
 *         'msg.payload'
 */
int encode_set_bios_attribute_current_value_req(
	uint8_t instance_id, uint32_t transfer_handle, uint8_t transfer_flag,
	const uint8_t *attribute_data, size_t attribute_length,
	struct pldm_msg *msg, size_t payload_length);

/** @brief Decode a SetBiosAttributeCurrentValue response message
 *
 *  Note:
 *  * If the return value is not PLDM_SUCCESS, it represents a
 * transport layer error.
 *  * If the completion_code value is not PLDM_SUCCESS, it represents a
 * protocol layer error and all the out-parameters are invalid.
 *
 *  @param[in] msg - Response message
 *  @param[in] payload_length - Length of response message payload
 *  @param[out] completion_code - Pointer to response msg's PLDM completion code
 *  @param[out] next_transfer_handle - Pointer to a handle that identify the
 *              next portion of the transfer
 *  @return pldm_completion_codes
 */
int decode_set_bios_attribute_current_value_resp(
	const struct pldm_msg *msg, size_t payload_length,
	uint8_t *completion_code, uint32_t *next_transfer_handle);

/* SetBIOSTable */

/** @brief Create a PLDM request message for SetBIOSTable
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] transfer_handle - Handle to identify a BIOS table transfer
 *  @param[in] transfer_flag - Flag to indicate what part of the transfer
 * 			   this request represents
 *  @param[in] table_type - Indicates what table is being transferred
 *             {BIOSStringTable=0x0, BIOSAttributeTable=0x1,
 *              BIOSAttributeValueTable=0x2}
 *  @param[in] table_data - Contains data specific to the table type
 *  @param[in] table_length - Length of table data
 *  @param[out] msg - Message will be written to this
 *  @param[in] payload_length - Length of message payload
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of params
 *         'msg.payload'
 */
int encode_set_bios_table_req(uint8_t instance_id, uint32_t transfer_handle,
			      uint8_t transfer_flag, uint8_t table_type,
			      const uint8_t *table_data, size_t table_length,
			      struct pldm_msg *msg, size_t payload_length);

/** @brief Decode a SetBIOSTable response message
 *
 *  Note:
 *  * If the return value is not PLDM_SUCCESS, it represents a
 * transport layer error.
 *  * If the completion_code value is not PLDM_SUCCESS, it represents a
 * protocol layer error and all the out-parameters are invalid.
 *
 *  @param[in] msg - Response message
 *  @param[in] payload_length - Length of response message payload
 *  @param[out] completion_code - Pointer to response msg's PLDM completion code
 *  @param[out] next_transfer_handle - Pointer to a handle that identify the
 *              next portion of the transfer
 *  @return pldm_completion_codes
 */
int decode_set_bios_table_resp(const struct pldm_msg *msg,
			       size_t payload_length, uint8_t *completion_code,
			       uint32_t *next_transfer_handle);

/* Responder */

/* GetDateTime */

/** @brief Create a PLDM response message for GetDateTime
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - PLDM completion code
 *  @param[in] seconds - seconds in BCD format
 *  @param[in] minutes - minutes in BCD format
 *  @param[in] hours - hours in BCD format
 *  @param[in] day - day of the month in BCD format
 *  @param[in] month - number of month in BCD format
 *  @param[in] year - year in BCD format
 *  @param[out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.body.payload'
 */

int encode_get_date_time_resp(uint8_t instance_id, uint8_t completion_code,
			      uint8_t seconds, uint8_t minutes, uint8_t hours,
			      uint8_t day, uint8_t month, uint16_t year,
			      struct pldm_msg *msg);

/* GetBIOSTable */

/** @brief Create a PLDM response message for GetBIOSTable
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - PLDM completion code
 *  @param[in] next_transfer_handle - handle to identify the next portion of the
 * transfer
 *  @param[in] transfer_flag - To indicate what part of the transfer this
 * response represents
 *  @param[in] table_data - BIOS Table type specific data
 *  @param[in] payload_length - Length of payload message
 *  @param[out] msg - Message will be written to this
 *  @return pldm_completion_codes
 */
int encode_get_bios_table_resp(uint8_t instance_id, uint8_t completion_code,
			       uint32_t next_transfer_handle,
			       uint8_t transfer_flag, uint8_t *table_data,
			       size_t payload_length, struct pldm_msg *msg);

/** @brief Encode  GetBIOSTable request packet
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] transfer_handle - Handle to identify a BIOS table transfer
 *  @param[in] transfer_op_flag - Flag to indicate the start of a multipart
 *                                 transfer
 *  @param[in] table_type - BIOS table type
 *  @param[out] msg - Message will be written to this
 *  @return pldm_completion_codes
 */
int encode_get_bios_table_req(uint8_t instance_id, uint32_t transfer_handle,
			      uint8_t transfer_op_flag, uint8_t table_type,
			      struct pldm_msg *msg);

/** @brief Decode GetBIOSTable request packet
 *
 *  @param[in] msg - Request message
 *  @param[in] payload_length - Length of request message payload
 *  @param[out] transfer_handle - Handle to identify a BIOS table transfer
 *  @param[out] transfer_op_flag - Flag to indicate the start of a multipart
 * transfer
 *  @param[out] table_type - BIOS table type
 *  @return pldm_completion_codes
 */
int decode_get_bios_table_req(const struct pldm_msg *msg, size_t payload_length,
			      uint32_t *transfer_handle,
			      uint8_t *transfer_op_flag, uint8_t *table_type);

/** @brief Decode GetBIOSTable response packet
 *
 *  @param[in] msg - Response message
 *  @param[in] payload_length - Length of response message payload
 *  @param[in] completion_code - PLDM completion code
 *  @param[in] next_transfer_handle - handle to identify the next portion of the
 *                                    transfer
 *  @param[in] transfer_flag - To indicate what part of the transfer this
 *                             response represents
 *  @param[out] bios_table_offset - Offset where bios table data should be read
 *                                  in pldm msg
 *  @return pldm_completion_codes
 */
int decode_get_bios_table_resp(const struct pldm_msg *msg,
			       size_t payload_length, uint8_t *completion_code,
			       uint32_t *next_transfer_handle,
			       uint8_t *transfer_flag,
			       size_t *bios_table_offset);

/* GetBIOSAttributeCurrentValueByHandle */

/** @brief Decode GetBIOSAttributeCurrentValueByHandle request packet
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] transfer_handle - Handle to identify a BIOS attribute transfer
 *  @param[in] transfer_op_flag - Flag to indicate the start of a multipart
 *                                 transfer
 *  @param[in] attribute_handle - Handle to identify the BIOS attribute
 *  @param[out] msg - Message will be written to this
 *  @return pldm_completion_codes
 */
int encode_get_bios_attribute_current_value_by_handle_req(
	uint8_t instance_id, uint32_t transfer_handle, uint8_t transfer_op_flag,
	uint16_t attribute_handle, struct pldm_msg *msg);

/** @brief Decode GetBIOSAttributeCurrentValueByHandle response packet
 *
 *  @param[in] msg - Response message
 *  @param[in] payload_length - Length of response message payload
 *  @param[out] completion_code - PLDM completion code
 *  @param[out] next_transfer_handle - handle to identify the next portion of
 * the transfer
 *  @param[out] transfer_flag - To indicate what part of the transfer this
 *                             response represents
 *  @param[out] attribute_data - contains current value of attribute
 *  @return pldm_completion_codes
 */
int decode_get_bios_attribute_current_value_by_handle_resp(
	const struct pldm_msg *msg, size_t payload_length,
	uint8_t *completion_code, uint32_t *next_transfer_handle,
	uint8_t *transfer_flag, struct variable_field *attribute_data);

/** @brief Decode GetBIOSAttributeCurrentValueByHandle request packet
 *
 *  @param[in] msg - Request message
 *  @param[in] payload_length - Length of request message payload
 *  @param[out] transfer_handle - Handle to identify a BIOS table transfer
 *  @param[out] transfer_op_flag - Flag to indicate the start of a multipart
 * transfer
 *  @param[out] attribute_handle - Handle to identify the BIOS attribute
 *  @return pldm_completion_codes
 */
int decode_get_bios_attribute_current_value_by_handle_req(
	const struct pldm_msg *msg, size_t payload_length,
	uint32_t *transfer_handle, uint8_t *transfer_op_flag,
	uint16_t *attribute_handle);

/** @brief Create a PLDM response message for
 * GetBIOSAttributeCurrentValueByHandle
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - PLDM completion code
 *  @param[in] next_transfer_handle - handle to identify the next portion of the
 * transfer
 *  @param[in] transfer_flag - To indicate what part of the transfer this
 * response represents
 *  @param[in] attribute_data - contains current value of attribute
 *  @param[in] attribute_length - Length of attribute
 *  @param[out] msg - Message will be written to this
 *  @return pldm_completion_codes
 */
int encode_get_bios_current_value_by_handle_resp(uint8_t instance_id,
						 uint8_t completion_code,
						 uint32_t next_transfer_handle,
						 uint8_t transfer_flag,
						 const uint8_t *attribute_data,
						 size_t attribute_length,
						 struct pldm_msg *msg);

/* SetBiosAttributeCurrentValue */

/** @brief Decode SetBIOSAttributeCurrentValue request packet
 *
 *  @param[in] msg - Request message
 *  @param[in] payload_length - Length of request message payload
 *  @param[out] transfer_handle - Handle to identify a BIOS table transfer
 *  @param[out] transfer_flag - Flag to indicate what part of the transfer
 *                              this request represents
 *  @param[out] attribute - Struct variable_field, contains a pointer to the
 *                          attribute field in the buffer of \p msg, \p msg must
 *                          be valid when \p attribute is used.
 *  @return pldm_completion_codes
 */
int decode_set_bios_attribute_current_value_req(
	const struct pldm_msg *msg, size_t payload_length,
	uint32_t *transfer_handle, uint8_t *transfer_flag,
	struct variable_field *attribute);

/** @brief Create a PLDM response message for SetBiosAttributeCurrentValue
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - PLDM completion code
 *  @param[in] next_transfer_handle - handle to identify the next portion of the
 *  @param[out] msg - Message will be written to this
 */
int encode_set_bios_attribute_current_value_resp(uint8_t instance_id,
						 uint8_t completion_code,
						 uint32_t next_transfer_handle,
						 struct pldm_msg *msg);

/** @brief Create a PLDM request message for SetDateTime
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] seconds - Seconds in decimal format. Value range 0~59
 *  @param[in] minutes - minutes in decimal format. Value range 0~59
 *  @param[in] hours - hours in decimal format. Value range 0~23
 *  @param[in] day - day of month in decimal format. Value range 1~31
 *  @param[in] month - number of month in decimal format. Value range 1~12
 *  @param[in] year - year in decimal format. Value range 1970~
 *  @param[out] msg - Message will be written to this
 *  @param[in] payload_length - Length of request message payload
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.body.payload'
 */
int encode_set_date_time_req(uint8_t instance_id, uint8_t seconds,
			     uint8_t minutes, uint8_t hours, uint8_t day,
			     uint8_t month, uint16_t year, struct pldm_msg *msg,
			     size_t payload_length);

/** @brief Decode a SetDateTime request message
 *
 *  @param[in] msg - Response message
 *  @param[in] payload_length - Length of request message payload
 *  @param[out] seconds - seconds in BCD format
 *  @param[out] minutes - minutes in BCD format
 *  @param[out] hours - hours in BCD format
 *  @param[out] day - day of the month in BCD format
 *  @param[out] month - number of month in BCD format
 *  @param[out] year - year in BCD format
 *  @return pldm_completion_codes
 */
int decode_set_date_time_req(const struct pldm_msg *msg, size_t payload_length,
			     uint8_t *seconds, uint8_t *minutes, uint8_t *hours,
			     uint8_t *day, uint8_t *month, uint16_t *year);

/** @brief Create a PLDM response message for SetDateTime
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - PLDM completion code
 *  @param[out] msg - Message will be written to this
 *  @param[in] payload_length - Length of response message payload
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.body.payload'
 */
int encode_set_date_time_resp(uint8_t instance_id, uint8_t completion_code,
			      struct pldm_msg *msg, size_t payload_length);

/** @brief Decode a SetDateTime response message
 *
 *  Note:
 *  * If the return value is not PLDM_SUCCESS, it represents a
 * transport layer error.
 *  * If the completion_code value is not PLDM_SUCCESS, it represents a
 * protocol layer error and all the out-parameters are invalid.
 *
 *  @param[in] msg - Response message
 *  @param[in] payload_length - Length of response message payload
 *  @param[out] completion_code - Pointer to response msg's PLDM completion code
 *  @return pldm_completion_codes
 */
int decode_set_date_time_resp(const struct pldm_msg *msg, size_t payload_length,
			      uint8_t *completion_code);

/* SetBIOSTable */

/** @brief Create a PLDM response message for SetBIOSTable
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - PLDM completion code
 *  @param[in] next_transfer_handle - handle to identify the next portion of the
 *             transfer
 *  @param[out] msg - Message will be written to this
 */
int encode_set_bios_table_resp(uint8_t instance_id, uint8_t completion_code,
			       uint32_t next_transfer_handle,
			       struct pldm_msg *msg);

/** @brief Decode SetBIOSTable request packet
 *
 *  @param[in] msg - Request message
 *  @param[in] payload_length - Length of request message payload
 *  @param[out] transfer_handle - Handle to identify a BIOS table transfer
 *  @param[out] transfer_flag - Flag to indicate what part of the transfer
 *                              this request represents
 *  @param[out] table_type - Indicates what table is being transferred
 *             {BIOSStringTable=0x0, BIOSAttributeTable=0x1,
 *              BIOSAttributeValueTable=0x2}
 *  @param[out] table - Struct variable_field, contains data specific to the
 * 				table type and the length of table data.
 *  @return pldm_completion_codes
 */
int decode_set_bios_table_req(const struct pldm_msg *msg, size_t payload_length,
			      uint32_t *transfer_handle, uint8_t *transfer_flag,
			      uint8_t *table_type,
			      struct variable_field *table);

#ifdef __cplusplus
}
#endif

#endif /* BIOS_H */
