#ifndef BASE_H
#define BASE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <asm/byteorder.h>
#include <stddef.h>
#include <stdint.h>

#include "pldm_types.h"

typedef uint8_t pldm_tid_t;

/** @brief PLDM Types
 */
enum pldm_supported_types {
	PLDM_BASE = 0x00,
	PLDM_PLATFORM = 0x02,
	PLDM_BIOS = 0x03,
	PLDM_FRU = 0x04,
	PLDM_FWUP = 0x05,
	PLDM_OEM = 0x3F,
};

/** @brief PLDM Commands
 */
enum pldm_supported_commands {
	PLDM_SET_TID = 0x1,
	PLDM_GET_TID = 0x2,
	PLDM_GET_PLDM_VERSION = 0x3,
	PLDM_GET_PLDM_TYPES = 0x4,
	PLDM_GET_PLDM_COMMANDS = 0x5,
	PLDM_MULTIPART_RECEIVE = 0x9,
};

/** @brief PLDM base codes
 */
enum pldm_completion_codes {
	PLDM_SUCCESS = 0x00,
	PLDM_ERROR = 0x01,
	PLDM_ERROR_INVALID_DATA = 0x02,
	PLDM_ERROR_INVALID_LENGTH = 0x03,
	PLDM_ERROR_NOT_READY = 0x04,
	PLDM_ERROR_UNSUPPORTED_PLDM_CMD = 0x05,
	PLDM_ERROR_INVALID_PLDM_TYPE = 0x20,
	PLDM_INVALID_TRANSFER_OPERATION_FLAG = 0x21
};

enum transfer_op_flag {
	PLDM_GET_NEXTPART = 0,
	PLDM_GET_FIRSTPART = 1,
	PLDM_ACKNOWLEDGEMENT_ONLY = 2,
};

enum transfer_multipart_op_flag {
	PLDM_XFER_FIRST_PART = 0,
	PLDM_XFER_NEXT_PART = 1,
	PLDM_XFER_ABORT = 2,
	PLDM_XFER_COMPLETE = 3,
	PLDM_XFER_CURRENT_PART = 4,
};

enum transfer_resp_flag {
	PLDM_START = 0x01,
	PLDM_MIDDLE = 0x02,
	PLDM_END = 0x04,
	PLDM_START_AND_END = 0x05,
};

/** @brief PLDM transport protocol type
 */
enum pldm_transport_protocol_type {
	PLDM_TRANSPORT_PROTOCOL_TYPE_MCTP = 0x00,
	PLDM_TRANSPORT_PROTOCOL_TYPE_OEM = 0xFF,
};

/** @enum MessageType
 *
 *  The different message types supported by the PLDM specification.
 */
typedef enum {
	PLDM_RESPONSE,		   //!< PLDM response
	PLDM_REQUEST,		   //!< PLDM request
	PLDM_RESERVED,		   //!< Reserved
	PLDM_ASYNC_REQUEST_NOTIFY, //!< Unacknowledged PLDM request messages
} MessageType;

#define PLDM_INSTANCE_MAX      31
#define PLDM_MAX_TYPES	       64
#define PLDM_MAX_CMDS_PER_TYPE 256
#define PLDM_MAX_TIDS	       256

/* Message payload lengths */
#define PLDM_GET_COMMANDS_REQ_BYTES 5
#define PLDM_GET_VERSION_REQ_BYTES  6

/* Response lengths are inclusive of completion code */
#define PLDM_GET_TYPES_RESP_BYTES    9
#define PLDM_GET_TID_RESP_BYTES	     2
#define PLDM_SET_TID_RESP_BYTES	     1
#define PLDM_GET_COMMANDS_RESP_BYTES 33
/* Response data has only one version and does not contain the checksum */
#define PLDM_GET_VERSION_RESP_BYTES	 10
#define PLDM_MULTIPART_RECEIVE_REQ_BYTES 18

#define PLDM_VERSION_0	     0
#define PLDM_CURRENT_VERSION PLDM_VERSION_0

#define PLDM_TIMESTAMP104_SIZE 13

/** @struct pldm_msg_hdr
 *
 * Structure representing PLDM message header fields
 */
struct pldm_msg_hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	uint8_t instance_id : 5; //!< Instance ID
	uint8_t reserved : 1;	 //!< Reserved
	uint8_t datagram : 1;	 //!< Datagram bit
	uint8_t request : 1;	 //!< Request bit
#elif defined(__BIG_ENDIAN_BITFIELD)
	uint8_t request : 1;	 //!< Request bit
	uint8_t datagram : 1;	 //!< Datagram bit
	uint8_t reserved : 1;	 //!< Reserved
	uint8_t instance_id : 5; //!< Instance ID
#endif

#if defined(__LITTLE_ENDIAN_BITFIELD)
	uint8_t type : 6;	//!< PLDM type
	uint8_t header_ver : 2; //!< Header version
#elif defined(__BIG_ENDIAN_BITFIELD)
	uint8_t header_ver : 2;	 //!< Header version
	uint8_t type : 6;	 //!< PLDM type
#endif
	uint8_t command; //!< PLDM command code
} __attribute__((packed));

// Macros for byte-swapping variables in-place
#define HTOLE32(X) ((X) = htole32(X))
#define HTOLE16(X) ((X) = htole16(X))
#define LE32TOH(X) ((X) = le32toh(X))
#define LE16TOH(X) ((X) = le16toh(X))

/** @struct pldm_msg
 *
 * Structure representing PLDM message
 */
struct pldm_msg {
	struct pldm_msg_hdr hdr; //!< PLDM message header
	uint8_t payload[1]; //!< &payload[0] is the beginning of the payload
} __attribute__((packed));

/** @struct pldm_header_info
 *
 *  The information needed to prepare PLDM header and this is passed to the
 *  pack_pldm_header and unpack_pldm_header API.
 */
struct pldm_header_info {
	MessageType msg_type;	 //!< PLDM message type
	uint8_t instance;	 //!< PLDM instance id
	uint8_t pldm_type;	 //!< PLDM type
	uint8_t command;	 //!< PLDM command code
	uint8_t completion_code; //!< PLDM completion code, applies for response
};

/** @struct pldm_get_types_resp
 *
 *  Structure representing PLDM get types response.
 */
struct pldm_get_types_resp {
	uint8_t completion_code; //!< completion code
	bitfield8_t types[8]; //!< each bit represents whether a given PLDM Type
			      //!< is supported
} __attribute__((packed));

/** @struct pldm_get_commands_req
 *
 *  Structure representing PLDM get commands request.
 */
struct pldm_get_commands_req {
	uint8_t type;	 //!< PLDM Type for which command support information is
			 //!< being requested
	ver32_t version; //!< version for the specified PLDM Type
} __attribute__((packed));

/** @struct pldm_get_commands_resp
 *
 *  Structure representing PLDM get commands response.
 */
struct pldm_get_commands_resp {
	uint8_t completion_code;  //!< completion code
	bitfield8_t commands[32]; //!< each bit represents whether a given PLDM
				  //!< command is supported
} __attribute__((packed));

/** @struct pldm_get_version_req
 *
 *  Structure representing PLDM get version request.
 */
struct pldm_get_version_req {
	uint32_t transfer_handle; //!< handle to identify PLDM version data transfer
	uint8_t transfer_opflag; //!< PLDM GetVersion operation flag
	uint8_t type; //!< PLDM Type for which version information is being requested
} __attribute__((packed));

/** @struct pldm_get_version_resp
 *
 *  Structure representing PLDM get version response.
 */

struct pldm_get_version_resp {
	uint8_t completion_code;       //!< completion code
	uint32_t next_transfer_handle; //!< next portion of PLDM version data
				       //!< transfer
	uint8_t transfer_flag;	       //!< PLDM GetVersion transfer flag
	uint8_t version_data[1];       //!< PLDM GetVersion version field
} __attribute__((packed));

/** @struct pldm_set_tid_req
 *
 *  Structure representing PLDM set tid request.
 */

struct pldm_set_tid_req {
	uint8_t tid; //!< PLDM SetTID TID field
} __attribute__((packed));

/** @struct pldm_get_tid_resp
 *
 *  Structure representing PLDM get tid response.
 */

struct pldm_get_tid_resp {
	uint8_t completion_code; //!< completion code
	uint8_t tid;		 //!< PLDM GetTID TID field
} __attribute__((packed));

/** @struct pldm_multipart_receive_req
 *
 * Structure representing PLDM multipart receive request.
 */
struct pldm_multipart_receive_req {
	uint8_t pldm_type;	  //!< PLDM Type for the MultipartReceive
				  //!< command.
	uint8_t transfer_opflag;  //!< PLDM MultipartReceive operation flag.
	uint32_t transfer_ctx;	  //!< Protocol-specifc context for this
				  //!< transfer.
	uint32_t transfer_handle; //!< handle to identify the part of data to be
				  //!< received.
	uint32_t section_offset;  //!< The start offset for the requested
				  //!< section.
	uint32_t section_length;  //!< The length (in bytes) of the section
				  //!< requested.
} __attribute__((packed));
/**
 * @brief Populate the PLDM message with the PLDM header.The caller of this API
 *        allocates buffer for the PLDM header when forming the PLDM message.
 *        The buffer is passed to this API to pack the PLDM header.
 *
 * @param[in] hdr - Pointer to the PLDM header information
 * @param[out] msg - Pointer to PLDM message header
 *
 * @return 0 on success, otherwise PLDM error codes.
 * @note   Caller is responsible for alloc and dealloc of msg
 *         and hdr params
 */
uint8_t pack_pldm_header(const struct pldm_header_info *hdr,
			 struct pldm_msg_hdr *msg);

/**
 * @brief Unpack the PLDM header from the PLDM message.
 *
 * @param[in] msg - Pointer to the PLDM message header
 * @param[out] hdr - Pointer to the PLDM header information
 *
 * @return 0 on success, otherwise PLDM error codes.
 * @note   Caller is responsible for alloc and dealloc of msg
 *         and hdr params
 */
uint8_t unpack_pldm_header(const struct pldm_msg_hdr *msg,
			   struct pldm_header_info *hdr);

/* Requester */

/* GetPLDMTypes */

/** @brief Create a PLDM request message for GetPLDMTypes
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in,out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_get_types_req(uint8_t instance_id, struct pldm_msg *msg);

/** @brief Decode a GetPLDMTypes response message
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
 *  @param[out] types - pointer to array bitfield8_t[8] containing supported
 *              types (MAX_TYPES/8) = 8), as per DSP0240
 *  @return pldm_completion_codes
 */
int decode_get_types_resp(const struct pldm_msg *msg, size_t payload_length,
			  uint8_t *completion_code, bitfield8_t *types);

/* GetPLDMCommands */

/** @brief Create a PLDM request message for GetPLDMCommands
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] type - PLDM Type
 *  @param[in] version - Version for PLDM Type
 *  @param[in,out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_get_commands_req(uint8_t instance_id, uint8_t type, ver32_t version,
			    struct pldm_msg *msg);

/** @brief Decode a GetPLDMCommands response message
 *
 *  Note:
 *  * If the return value is not PLDM_SUCCESS, it represents a
 * transport layer error.
 *  * If the completion_code value is not PLDM_SUCCESS, it represents a
 * protocol layer error and all the out-parameters are invalid.
 *
 *  @param[in] msg - Response message
 *  @param[in] payload_length - Length of reponse message payload
 *  @param[out] completion_code - Pointer to response msg's PLDM completion code
 *  @param[in] commands - pointer to array bitfield8_t[32] containing supported
 *             commands (PLDM_MAX_CMDS_PER_TYPE/8) = 32), as per DSP0240
 *  @return pldm_completion_codes
 */
int decode_get_commands_resp(const struct pldm_msg *msg, size_t payload_length,
			     uint8_t *completion_code, bitfield8_t *commands);

/* GetPLDMVersion */

/** @brief Create a PLDM request for GetPLDMVersion
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] transfer_handle - Handle to identify PLDM version data transfer.
 *         This handle is ignored by the responder when the
 *         transferop_flag is set to getFirstPart.
 *  @param[in] transfer_opflag - flag to indicate whether it is start of
 *         transfer
 *  @param[in] type -  PLDM Type for which version is requested
 *  @param[in,out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_get_version_req(uint8_t instance_id, uint32_t transfer_handle,
			   uint8_t transfer_opflag, uint8_t type,
			   struct pldm_msg *msg);

/** @brief Decode a GetPLDMVersion response message
 *
 *  Note:
 *  * If the return value is not PLDM_SUCCESS, it represents a
 * transport layer error.
 *  * If the completion_code value is not PLDM_SUCCESS, it represents a
 * protocol layer error and all the out-parameters are invalid.
 *
 *  @param[in] msg - Response message
 *  @param[in] payload_length - Length of reponse message payload
 *  @param[out] completion_code - Pointer to response msg's PLDM completion code
 *  @param[out] next_transfer_handle - the next handle for the next part of data
 *  @param[out] transfer_flag - flag to indicate the part of data
 *  @return pldm_completion_codes
 */
int decode_get_version_resp(const struct pldm_msg *msg, size_t payload_length,
			    uint8_t *completion_code,
			    uint32_t *next_transfer_handle,
			    uint8_t *transfer_flag, ver32_t *version);

/* GetTID */

/** @brief Decode a GetTID response message
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
 *  @param[out] tid - Pointer to the terminus id
 *  @return pldm_completion_codes
 */
int decode_get_tid_resp(const struct pldm_msg *msg, size_t payload_length,
			uint8_t *completion_code, uint8_t *tid);

/* Responder */

/* GetPLDMTypes */

/** @brief Create a PLDM response message for GetPLDMTypes
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - PLDM completion code
 *  @param[in] types - pointer to array bitfield8_t[8] containing supported
 *             types (MAX_TYPES/8) = 8), as per DSP0240
 *  @param[in,out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_get_types_resp(uint8_t instance_id, uint8_t completion_code,
			  const bitfield8_t *types, struct pldm_msg *msg);

/* GetPLDMCommands */

/** @brief Decode GetPLDMCommands' request data
 *
 *  @param[in] msg - Request message
 *  @param[in] payload_length - Length of request message payload
 *  @param[out] type - PLDM Type
 *  @param[out] version - Version for PLDM Type
 *  @return pldm_completion_codes
 */
int decode_get_commands_req(const struct pldm_msg *msg, size_t payload_length,
			    uint8_t *type, ver32_t *version);

/** @brief Create a PLDM response message for GetPLDMCommands
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - PLDM completion code
 *  @param[in] commands - pointer to array bitfield8_t[32] containing supported
 *             commands (PLDM_MAX_CMDS_PER_TYPE/8) = 32), as per DSP0240
 *  @param[in,out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_get_commands_resp(uint8_t instance_id, uint8_t completion_code,
			     const bitfield8_t *commands, struct pldm_msg *msg);

/* GetPLDMVersion */

/** @brief Create a PLDM response for GetPLDMVersion
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - PLDM completion code
 *  @param[in] next_transfer_handle - Handle to identify next portion of
 *              data transfer
 *  @param[in] transfer_flag - Represents the part of transfer
 *  @param[in] version_data - the version data
 *  @param[in] version_size - size of version data
 *  @param[in,out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_get_version_resp(uint8_t instance_id, uint8_t completion_code,
			    uint32_t next_transfer_handle,
			    uint8_t transfer_flag, const ver32_t *version_data,
			    size_t version_size, struct pldm_msg *msg);

/** @brief Decode a GetPLDMVersion request message
 *
 *  @param[in] msg - Request message
 *  @param[in] payload_length - length of request message payload
 *  @param[out] transfer_handle - the handle of data
 *  @param[out] transfer_opflag - Transfer Flag
 *  @param[out] type - PLDM type for which version is requested
 *  @return pldm_completion_codes
 */
int decode_get_version_req(const struct pldm_msg *msg, size_t payload_length,
			   uint32_t *transfer_handle, uint8_t *transfer_opflag,
			   uint8_t *type);

/* Requester */

/* GetTID */

/** @brief Create a PLDM request message for GetTID
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in,out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_get_tid_req(uint8_t instance_id, struct pldm_msg *msg);

/** @brief Create a PLDM response message for GetTID
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - PLDM completion code
 *  @param[in] tid - Terminus ID
 *  @param[in,out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_get_tid_resp(uint8_t instance_id, uint8_t completion_code,
			uint8_t tid, struct pldm_msg *msg);

/** @brief Create a PLDM request message for SetTID
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] tid - Terminus ID
 *  @param[in,out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_set_tid_req(uint8_t instance_id, uint8_t tid, struct pldm_msg *msg);

/* Responder */

/* MultipartRecieve */

/** @brief Decode a PLDM MultipartReceive request message
 *
 *  @param[in] msg - Request message
 *  @param[in] payload_length - length of request message payload
 *  @param[out] pldm_type - PLDM type for which version is requested
 *  @param[out] transfer_opflag - Transfer Flag
 *  @param[out] transfer_ctx - The context of the packet
 *  @param[out] transfer_handle - The handle of data
 *  @param[out] section_offset - The start of the requested section
 *  @param[out] section_length - The length of the requested section
 *  @return pldm_completion_codes
 */
int decode_multipart_receive_req(const struct pldm_msg *msg,
				 size_t payload_length, uint8_t *pldm_type,
				 uint8_t *transfer_opflag,
				 uint32_t *transfer_ctx,
				 uint32_t *transfer_handle,
				 uint32_t *section_offset,
				 uint32_t *section_length);

/** @brief Create a PLDM response message containing only cc
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] type - PLDM Type
 *  @param[in] command - PLDM Command
 *  @param[in] cc - PLDM Completion Code
 *  @param[out] msg - Message will be written to this
 *  @return pldm_completion_codes
 */
int encode_cc_only_resp(uint8_t instance_id, uint8_t type, uint8_t command,
			uint8_t cc, struct pldm_msg *msg);

/** @brief Create a PLDM message only with the header
 *
 *	@param[in] msg_type - PLDM message type
 *	@param[in] instance_id - Message's instance id
 *	@param[in] pldm_type - PLDM Type
 *	@param[in] command - PLDM Command
 *	@param[out] msg - Message will be written to this
 *
 *	@return pldm_completion_codes
 */
int encode_pldm_header_only(uint8_t msg_type, uint8_t instance_id,
			    uint8_t pldm_type, uint8_t command,
			    struct pldm_msg *msg);

#ifdef __cplusplus
}
#endif

#endif /* BASE_H */
