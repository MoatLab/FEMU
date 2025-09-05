#ifndef FILEIO_H
#define FILEIO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

struct pldm_msg;
/** @brief PLDM Commands in IBM OEM type
 */
enum pldm_fileio_commands {
	PLDM_GET_FILE_TABLE = 0x1,
	PLDM_READ_FILE = 0x4,
	PLDM_WRITE_FILE = 0x5,
	PLDM_READ_FILE_INTO_MEMORY = 0x6,
	PLDM_WRITE_FILE_FROM_MEMORY = 0x7,
	PLDM_READ_FILE_BY_TYPE_INTO_MEMORY = 0x8,
	PLDM_WRITE_FILE_BY_TYPE_FROM_MEMORY = 0x9,
	PLDM_NEW_FILE_AVAILABLE = 0xA,
	PLDM_READ_FILE_BY_TYPE = 0xB,
	PLDM_WRITE_FILE_BY_TYPE = 0xC,
	PLDM_FILE_ACK = 0xD,
	PLDM_NEW_FILE_AVAILABLE_WITH_META_DATA = 0xE,
	PLDM_FILE_ACK_WITH_META_DATA = 0xF,
};

/** @brief PLDM Command specific codes
 */
enum pldm_fileio_completion_codes {
	PLDM_FILE_TABLE_UNAVAILABLE = 0x83,
	PLDM_INVALID_FILE_TABLE_TYPE = 0x85,
	PLDM_INVALID_FILE_HANDLE = 0x86,
	PLDM_DATA_OUT_OF_RANGE = 0x87,
	PLDM_INVALID_FILE_TYPE = 0x89,
	PLDM_ERROR_FILE_DISCARDED = 0x8A,
};

/** @brief PLDM File I/O table types
 */
enum pldm_fileio_table_type {
	PLDM_FILE_ATTRIBUTE_TABLE = 0,
	PLDM_OEM_FILE_ATTRIBUTE_TABLE = 1,
};

/** @brief PLDM File I/O table types
 */
enum pldm_fileio_file_type {
	PLDM_FILE_TYPE_PEL = 0x0,
	PLDM_FILE_TYPE_LID_PERM = 0x1,
	PLDM_FILE_TYPE_LID_TEMP = 0x2,
	PLDM_FILE_TYPE_DUMP = 0x3,
	PLDM_FILE_TYPE_CERT_SIGNING_REQUEST = 0x4,
	PLDM_FILE_TYPE_SIGNED_CERT = 0x5,
	PLDM_FILE_TYPE_ROOT_CERT = 0x6,
	PLDM_FILE_TYPE_LID_MARKER = 0x7,
	PLDM_FILE_TYPE_RESOURCE_DUMP_PARMS = 0x8,
	PLDM_FILE_TYPE_RESOURCE_DUMP = 0x9,
	PLDM_FILE_TYPE_PROGRESS_SRC = 0xA,
	PLDM_FILE_TYPE_ADJUNCT_DUMP = 0xB,
	PLDM_FILE_TYPE_DEVICE_DUMP = 0xC,
	PLDM_FILE_TYPE_COD_LICENSE_KEY = 0xD,
	PLDM_FILE_TYPE_COD_LICENSED_RESOURCES = 0xE,
	PLDM_FILE_TYPE_BMC_DUMP = 0xF,
	PLDM_FILE_TYPE_SBE_DUMP = 0x10,
	PLDM_FILE_TYPE_HOSTBOOT_DUMP = 0x11,
	PLDM_FILE_TYPE_HARDWARE_DUMP = 0x12,
	PLDM_FILE_TYPE_LID_RUNNING = 0x13,
	PLDM_FILE_TYPE_PCIE_TOPOLOGY = 0x14,
	PLDM_FILE_TYPE_CABLE_INFO = 0x15,
	PLDM_FILE_TYPE_PSPD_VPD_PDD_KEYWORD = 0x16,
};

#define PLDM_RW_FILE_MEM_REQ_BYTES			  20
#define PLDM_RW_FILE_MEM_RESP_BYTES			  5
#define PLDM_GET_FILE_TABLE_REQ_BYTES			  6
#define PLDM_GET_FILE_TABLE_MIN_RESP_BYTES		  6
#define PLDM_READ_FILE_REQ_BYTES			  12
#define PLDM_READ_FILE_RESP_BYTES			  5
#define PLDM_WRITE_FILE_REQ_BYTES			  12
#define PLDM_WRITE_FILE_RESP_BYTES			  5
#define PLDM_RW_FILE_BY_TYPE_MEM_REQ_BYTES		  22
#define PLDM_RW_FILE_BY_TYPE_MEM_RESP_BYTES		  5
#define PLDM_NEW_FILE_REQ_BYTES				  14
#define PLDM_NEW_FILE_RESP_BYTES			  1
#define PLDM_RW_FILE_BY_TYPE_REQ_BYTES			  14
#define PLDM_RW_FILE_BY_TYPE_RESP_BYTES			  5
#define PLDM_FILE_ACK_REQ_BYTES				  7
#define PLDM_FILE_ACK_RESP_BYTES			  1
#define PLDM_FILE_ACK_WITH_META_DATA_REQ_BYTES		  23
#define PLDM_FILE_ACK_WITH_META_DATA_RESP_BYTES		  1
#define PLDM_NEW_FILE_AVAILABLE_WITH_META_DATA_REQ_BYTES  30
#define PLDM_NEW_FILE_AVAILABLE_WITH_META_DATA_RESP_BYTES 1

/** @struct pldm_read_write_file_memory_req
 *
 *  Structure representing ReadFileIntoMemory request and WriteFileFromMemory
 *  request
 */
struct pldm_read_write_file_memory_req {
	uint32_t file_handle; //!< A Handle to the file
	uint32_t offset;      //!< Offset to the file
	uint32_t length;      //!< Number of bytes to be read/write
	uint64_t address;     //!< Memory address of the file
} __attribute__((packed));

/** @struct pldm_read_write_file_memory_resp
 *
 *  Structure representing ReadFileIntoMemory response and WriteFileFromMemory
 *  response
 */
struct pldm_read_write_file_memory_resp {
	uint8_t completion_code; //!< completion code
	uint32_t length;	 //!< Number of bytes read/written
} __attribute__((packed));

/** @brief Decode ReadFileIntoMemory and WriteFileFromMemory commands request
 *         data
 *
 *  @param[in] msg - Pointer to PLDM request message
 *  @param[in] payload_length - Length of request payload
 *  @param[out] file_handle - A handle to the file
 *  @param[out] offset - Offset to the file at which the read should begin
 *  @param[out] length - Number of bytes to be read
 *  @param[out] address - Memory address where the file content has to be
 *                        written to
 *  @return pldm_completion_codes
 */
int decode_rw_file_memory_req(const struct pldm_msg *msg, size_t payload_length,
			      uint32_t *file_handle, uint32_t *offset,
			      uint32_t *length, uint64_t *address);

/** @brief Create a PLDM response for ReadFileIntoMemory and
 *         WriteFileFromMemory
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] command - PLDM command
 *  @param[in] completion_code - PLDM completion code
 *  @param[in] length - Number of bytes read. This could be less than what the
			 requester asked for.
 *  @param[in,out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param 'msg'
 */
int encode_rw_file_memory_resp(uint8_t instance_id, uint8_t command,
			       uint8_t completion_code, uint32_t length,
			       struct pldm_msg *msg);

/** @brief Encode ReadFileIntoMemory and WriteFileFromMemory
 *         commands request data
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] command - PLDM command
 *  @param[in] file_handle - A handle to the file
 *  @param[in] offset -  Offset to the file at which the read should begin
 *  @param[in] length -  Number of bytes to be read/written
 *  @param[in] address - Memory address where the file content has to be
 *                       written to
 *  @param[out] msg - Message will be written to this
 *  @return pldm_completion_codes
 */
int encode_rw_file_memory_req(uint8_t instance_id, uint8_t command,
			      uint32_t file_handle, uint32_t offset,
			      uint32_t length, uint64_t address,
			      struct pldm_msg *msg);

/** @brief Decode ReadFileIntoMemory and WriteFileFromMemory
 *         commands response data
 *
 *  @param[in] msg - pointer to PLDM response message
 *  @param[in] payload_length - Length of response payload
 *  @param[out] completion_code - PLDM completion code
 *  @param[out] length - Number of bytes to be read/written
 *  @return pldm_completion_codes
 */
int decode_rw_file_memory_resp(const struct pldm_msg *msg,
			       size_t payload_length, uint8_t *completion_code,
			       uint32_t *length);

/** @struct pldm_get_file_table_req
 *
 *  Structure representing GetFileTable request
 */
struct pldm_get_file_table_req {
	uint32_t transfer_handle; //!< Data transfer handle
	uint8_t operation_flag;	  //!< Transfer operation flag
	uint8_t table_type;	  //!< Table type
} __attribute__((packed));

/** @struct pldm_get_file_table_resp
 *
 *  Structure representing GetFileTable response fixed data
 */
struct pldm_get_file_table_resp {
	uint8_t completion_code;       //!< Completion code
	uint32_t next_transfer_handle; //!< Next data transfer handle
	uint8_t transfer_flag;	       //!< Transfer flag
	uint8_t table_data[1];	       //!< Table Data
} __attribute__((packed));

/** @struct pldm_file_attr_table_entry
 *
 * Structure representing File attribute table entry
 */
struct pldm_file_attr_table_entry {
	uint32_t file_handle;		//!< File Handle
	uint16_t file_name_length;	//!< File name length
	uint8_t file_attr_table_nst[1]; //!< File name size traits
} __attribute__((packed));

/** @brief Decode GetFileTable command request data
 *
 *  @param[in] msg - Pointer to PLDM request message
 *  @param[in] payload_length - Length of request payload
 *  @param[out] trasnfer_handle - the handle of data
 *  @param[out] transfer_opflag - Transfer operation flag
 *  @param[out] table_type - the type of file table
 *  @return pldm_completion_codes
 */
int decode_get_file_table_req(const struct pldm_msg *msg, size_t payload_length,
			      uint32_t *transfer_handle,
			      uint8_t *transfer_opflag, uint8_t *table_type);

/** @brief Create a PLDM response for GetFileTable command
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - PLDM completion code
 *  @param[in] next_transfer_handle - Handle to identify next portion of
 *              data transfer
 *  @param[in] transfer_flag - Represents the part of transfer
 *  @param[in] table_data - pointer to file table data
 *  @param[in] table_size - file table size
 *  @param[in,out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param 'msg'
 */
int encode_get_file_table_resp(uint8_t instance_id, uint8_t completion_code,
			       uint32_t next_transfer_handle,
			       uint8_t transfer_flag, const uint8_t *table_data,
			       size_t table_size, struct pldm_msg *msg);

/** @brief Encode GetFileTable command request data
 *
 * @param[in] instance_id - Message's instance id
 * @param[in] transfer_handle - the handle of data
 * @param[in] transfer_opflag - Transfer operation flag
 * @param[in] table_type - the type of file table
 * @param[out] msg - Message will be written to this
 * @return pldm_completion_codes
 */
int encode_get_file_table_req(uint8_t instance_id, uint32_t transfer_handle,
			      uint8_t transfer_opflag, uint8_t table_type,
			      struct pldm_msg *msg);

/** @brief Decode GetFileTable command response data
 * @param[in] msg - Response message
 * @param[in] payload_length - length of response message payload
 * @param[out] completion_code - PLDM completion code
 * @param[out] next_transfer_handle -  Handle to identify next portion of data
 * transfer
 * @param[out] transfer_flag - Represents the part of transfer
 * @param[out] file_table_data_start_offset - This data is a portion of the
 * overall File Table
 * @param[out] file_table_length - Length of the File table data
 * @return pldm_completion_codes
 */
int decode_get_file_table_resp(const struct pldm_msg *msg,
			       size_t payload_length, uint8_t *completion_code,
			       uint32_t *next_transfer_handle,
			       uint8_t *transfer_flag,
			       uint8_t *file_table_data_start_offset,
			       size_t *file_table_length);

/** @struct pldm_read_file_req
 *
 *  Structure representing ReadFile request
 */
struct pldm_read_file_req {
	uint32_t file_handle; //!< Handle to file
	uint32_t offset;      //!< Offset to file where read starts
	uint32_t length;      //!< Bytes to be read
} __attribute__((packed));

/** @struct pldm_read_file_resp
 *
 *  Structure representing ReadFile response data
 */
struct pldm_read_file_resp {
	uint8_t completion_code; //!< Completion code
	uint32_t length;	 //!< Number of bytes read
	uint8_t file_data[1];	 //!< Address of this is where file data starts
} __attribute__((packed));

/** @struct pldm_write_file_req
 *
 *  Structure representing WriteFile request
 */
struct pldm_write_file_req {
	uint32_t file_handle; //!< Handle to file
	uint32_t offset;      //!< Offset to file where write starts
	uint32_t length;      //!< Bytes to be written
	uint8_t file_data[1]; //!< Address of this is where file data starts
} __attribute__((packed));

/** @struct pldm_write_file_resp
 *
 *  Structure representing WriteFile response data
 */
struct pldm_write_file_resp {
	uint8_t completion_code; //!< Completion code
	uint32_t length;	 //!< Bytes written
} __attribute__((packed));

/** @brief Decode Read File commands request
 *
 *  @param[in] msg - PLDM request message payload
 *  @param[in] payload_length - Length of request payload
 *  @param[out] file_handle - A handle to the file
 *  @param[out] offset - Offset to the file at which the read should begin
 *  @param[out] length - Number of bytes read
 *  @return pldm_completion_codes
 */
int decode_read_file_req(const struct pldm_msg *msg, size_t payload_length,
			 uint32_t *file_handle, uint32_t *offset,
			 uint32_t *length);

/** @brief Encode Read File commands request
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] file_handle - A handle to the file
 *  @param[in] offset - Offset to the file at which the read should begin
 *  @param[in] length - Number of bytes read
 *  @param[in,out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param 'msg'
 */
int encode_read_file_req(uint8_t instance_id, uint32_t file_handle,
			 uint32_t offset, uint32_t length,
			 struct pldm_msg *msg);

/** @brief Decode Read File commands response
 *
 *  @param[in] msg - PLDM response message payload
 *  @param[in] payload_length - Length of request payload
 *  @param[out] completion_code - PLDM completion code
 *  @param[out] length - Number of bytes read. This could be less than what the
 *                       requester asked for.
 *  @param[out] file_data_offset - Offset where file data should be read in pldm
 * msg.
 *  @return pldm_completion_codes
 */
int decode_read_file_resp(const struct pldm_msg *msg, size_t payload_length,
			  uint8_t *completion_code, uint32_t *length,
			  size_t *file_data_offset);

/** @brief Create a PLDM response for Read File
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - PLDM completion code
 *  @param[in] length - Number of bytes read. This could be less than what the
 *                      requester asked for.
 *  @param[in,out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param 'msg'.
 *  Although read file command response includes file data, this function
 *  does not encode the file data to prevent additional copying of the data.
 *  The position of file data is calculated by caller from address and size
 *  of other input arguments.
 */
int encode_read_file_resp(uint8_t instance_id, uint8_t completion_code,
			  uint32_t length, struct pldm_msg *msg);

/** @brief Decode Write File commands request
 *
 *  @param[in] msg - PLDM request message payload
 *  @param[in] payload_length - Length of request payload
 *  @param[out] file_handle - A handle to the file
 *  @param[out] offset - Offset to the file at which the write should begin
 *  @param[out] length - Number of bytes to write
 *  @param[out] file_data_offset - Offset where file data write begins in pldm
 * msg.
 *  @return pldm_completion_codes
 */
int decode_write_file_req(const struct pldm_msg *msg, size_t payload_length,
			  uint32_t *file_handle, uint32_t *offset,
			  uint32_t *length, size_t *file_data_offset);

/** @brief Create a PLDM request for Write File
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] file_handle - A handle to the file
 *  @param[in] offset - Offset to the file at which the read should begin
 *  @param[in] length - Number of bytes written. This could be less than what
 *                      the requester asked for.
 *  @param[in,out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param 'msg'.
 *  Although write file command request includes file data, this function
 *  does not encode the file data to prevent additional copying of the data.
 *  The position of file data is calculated by caller from address and size
 *  of other input arguments.
 */
int encode_write_file_req(uint8_t instance_id, uint32_t file_handle,
			  uint32_t offset, uint32_t length,
			  struct pldm_msg *msg);

/** @brief Decode Write File commands response
 *
 *  @param[in] msg - PLDM request message payload
 *  @param[in] payload_length - Length of request payload
 *  @param[out] completion_code - PLDM completion code
 *  @param[out] length - Number of bytes written
 *  @return pldm_completion_codes
 */
int decode_write_file_resp(const struct pldm_msg *msg, size_t payload_length,
			   uint8_t *completion_code, uint32_t *length);

/** @brief Create a PLDM response for Write File
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - PLDM completion code
 *  @param[in] length - Number of bytes written. This could be less than what
 *                      the requester asked for.
 *  @param[in,out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param 'msg'
 */
int encode_write_file_resp(uint8_t instance_id, uint8_t completion_code,
			   uint32_t length, struct pldm_msg *msg);

/** @struct pldm_read_write_file_by_type_memory_req
 *
 *  Structure representing ReadFileByTypeIntoMemory and
 * WriteFileByTypeFromMemory request
 */
struct pldm_read_write_file_by_type_memory_req {
	uint16_t file_type;   //!< Type of file
	uint32_t file_handle; //!< Handle to file
	uint32_t offset;      //!< Offset to file where read starts
	uint32_t length;      //!< Bytes to be read
	uint64_t address;     //!< Memory address of the file
} __attribute__((packed));

/** @struct pldm_read_write_file_by_type_memory_resp
 *
 *  Structure representing ReadFileByTypeIntoMemory and
 * WriteFileByTypeFromMemory response
 */
struct pldm_read_write_file_by_type_memory_resp {
	uint8_t completion_code; //!< Completion code
	uint32_t length;	 //!< Number of bytes read
} __attribute__((packed));

/** @brief Decode ReadFileByTypeIntoMemory and WriteFileByTypeFromMemory
 * commands request data
 *
 *  @param[in] msg - Pointer to PLDM request message
 *  @param[in] payload_length - Length of request payload
 *  @param[in] file_type - Type of the file
 *  @param[out] file_handle - A handle to the file
 *  @param[out] offset - Offset to the file at which the read should begin
 *  @param[out] length - Number of bytes to be read
 *  @param[out] address - Memory address of the file content
 *  @return pldm_completion_codes
 */
int decode_rw_file_by_type_memory_req(const struct pldm_msg *msg,
				      size_t payload_length,
				      uint16_t *file_type,
				      uint32_t *file_handle, uint32_t *offset,
				      uint32_t *length, uint64_t *address);

/** @brief Create a PLDM response for ReadFileByTypeIntoMemory and
 * WriteFileByTypeFromMemory
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] command - PLDM command
 *  @param[in] completion_code - PLDM completion code
 *  @param[in] length - Number of bytes read. This could be less than what the
 *                      requester asked for.
 *  @param[in,out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param 'msg'
 */
int encode_rw_file_by_type_memory_resp(uint8_t instance_id, uint8_t command,
				       uint8_t completion_code, uint32_t length,
				       struct pldm_msg *msg);

/** @brief Encode ReadFileByTypeIntoMemory and WriteFileByTypeFromMemory
 *         commands request data
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] command - PLDM command
 *  @param[in] file_type - Type of the file
 *  @param[in] file_handle - A handle to the file
 *  @param[in] offset -  Offset to the file at which the read should begin
 *  @param[in] length -  Number of bytes to be read/written
 *  @param[in] address - Memory address where the file content has to be
 *                       written to
 *  @param[out] msg - Message will be written to this
 *  @return pldm_completion_codes
 */
int encode_rw_file_by_type_memory_req(uint8_t instance_id, uint8_t command,
				      uint16_t file_type, uint32_t file_handle,
				      uint32_t offset, uint32_t length,
				      uint64_t address, struct pldm_msg *msg);

/** @brief Decode ReadFileTypeIntoMemory and WriteFileTypeFromMemory
 *         commands response data
 *
 *  @param[in] msg - pointer to PLDM response message
 *  @param[in] payload_length - Length of response payload
 *  @param[out] completion_code - PLDM completion code
 *  @param[out] length - Number of bytes to be read/written
 *  @return pldm_completion_codes
 */
int decode_rw_file_by_type_memory_resp(const struct pldm_msg *msg,
				       size_t payload_length,
				       uint8_t *completion_code,
				       uint32_t *length);

/** @struct pldm_new_file_req
 *
 *  Structure representing NewFile request
 */
struct pldm_new_file_req {
	uint16_t file_type;   //!< Type of file
	uint32_t file_handle; //!< Handle to file
	uint64_t length;      //!< Number of bytes in new file
} __attribute__((packed));

/** @struct pldm_new_file_resp
 *
 *  Structure representing NewFile response data
 */
struct pldm_new_file_resp {
	uint8_t completion_code; //!< Completion code
} __attribute__((packed));

/** @brief Decode NewFileAvailable command request data
 *
 *  @param[in] msg - Pointer to PLDM request message
 *  @param[in] payload_length - Length of request payload
 *  @param[in] file_type - Type of the file
 *  @param[out] file_handle - A handle to the file
 *  @param[out] length - Number of bytes in new file
 *  @return pldm_completion_codes
 */
int decode_new_file_req(const struct pldm_msg *msg, size_t payload_length,
			uint16_t *file_type, uint32_t *file_handle,
			uint64_t *length);

/** @brief Create a PLDM response for NewFileAvailable
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - PLDM completion code
 *  @param[in,out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param 'msg'
 */
int encode_new_file_resp(uint8_t instance_id, uint8_t completion_code,
			 struct pldm_msg *msg);

/** @brief Encode NewFileAvailable command request data
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] file_type - Type of the file
 *  @param[in] file_handle - A handle to the file
 *  @param[in] length -  Number of bytes in new file
 *  @param[out] msg - Message will be written to this
 *  @return pldm_completion_codes
 */
int encode_new_file_req(uint8_t instance_id, uint16_t file_type,
			uint32_t file_handle, uint64_t length,
			struct pldm_msg *msg);

/** @brief Decode NewFileAvailable command response data
 *
 *  @param[in] msg - pointer to PLDM response message
 *  @param[in] payload_length - Length of response payload
 *  @param[out] completion_code - PLDM completion code
 *  @return pldm_completion_codes
 */
int decode_new_file_resp(const struct pldm_msg *msg, size_t payload_length,
			 uint8_t *completion_code);

/** @struct pldm_read_write_file_by_type_req
 *
 *  Structure representing ReadFileByType and
 *  WriteFileByType request
 */
struct pldm_read_write_file_by_type_req {
	uint16_t file_type;   //!< Type of file
	uint32_t file_handle; //!< Handle to file
	uint32_t offset;      //!< Offset to file where read/write starts
	uint32_t length;      //!< Bytes to be read
} __attribute__((packed));

/** @struct pldm_read_write_file_by_type_resp
 *
 *  Structure representing ReadFileByType and
 *  WriteFileByType response
 */
struct pldm_read_write_file_by_type_resp {
	uint8_t completion_code; //!< Completion code
	uint32_t length;	 //!< Number of bytes read
} __attribute__((packed));

/** @brief Decode ReadFileByType and WriteFileByType
 *  commands request data
 *
 *  @param[in] msg - Pointer to PLDM request message
 *  @param[in] payload_length - Length of request payload
 *  @param[out] file_type - Type of the file
 *  @param[out] file_handle - A handle to the file
 *  @param[out] offset - Offset to the file at which the read/write should begin
 *  @param[out] length - Number of bytes to be read/written
 *  @return pldm_completion_codes
 */
int decode_rw_file_by_type_req(const struct pldm_msg *msg,
			       size_t payload_length, uint16_t *file_type,
			       uint32_t *file_handle, uint32_t *offset,
			       uint32_t *length);

/** @brief Create a PLDM response for ReadFileByType and
 *  WriteFileByType
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] command - PLDM command
 *  @param[in] completion_code - PLDM completion code
 *  @param[in] length - Number of bytes read/written. This could be less than
 *                      what the requester asked for.
 *  @param[in,out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param 'msg'
 *  @note File content has to be copied directly by the caller.
 */
int encode_rw_file_by_type_resp(uint8_t instance_id, uint8_t command,
				uint8_t completion_code, uint32_t length,
				struct pldm_msg *msg);

/** @brief Encode ReadFileByType and WriteFileByType
 *         commands request data
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] command - PLDM command
 *  @param[in] file_type - Type of the file
 *  @param[in] file_handle - A handle to the file
 *  @param[in] offset -  Offset to the file at which the read should begin
 *  @param[in] length -  Number of bytes to be read/written
 *  @param[out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note File content has to be read directly by the caller.
 */
int encode_rw_file_by_type_req(uint8_t instance_id, uint8_t command,
			       uint16_t file_type, uint32_t file_handle,
			       uint32_t offset, uint32_t length,
			       struct pldm_msg *msg);

/** @brief Decode ReadFileByType and WriteFileByType
 *         commands response data
 *
 *  @param[in] msg - pointer to PLDM response message
 *  @param[in] payload_length - Length of response payload
 *  @param[out] completion_code - PLDM completion code
 *  @param[out] length - Number of bytes to be read/written
 *  @return pldm_completion_codes
 */
int decode_rw_file_by_type_resp(const struct pldm_msg *msg,
				size_t payload_length, uint8_t *completion_code,
				uint32_t *length);

/** @struct pldm_file_ack_req
 *
 *  Structure representing FileAck request
 */
struct pldm_file_ack_req {
	uint16_t file_type;   //!< Type of file
	uint32_t file_handle; //!< Handle to file
	uint8_t file_status;  //!< Status of file processing
} __attribute__((packed));

/** @struct pldm_file_ack_resp
 *
 *  Structure representing NewFile response data
 */
struct pldm_file_ack_resp {
	uint8_t completion_code; //!< Completion code
} __attribute__((packed));

/** @brief Decode FileAck command request data
 *
 *  @param[in] msg - Pointer to PLDM request message
 *  @param[in] payload_length - Length of request payload
 *  @param[out] file_type - Type of the file
 *  @param[out] file_handle - A handle to the file
 *  @param[out] file_status - Status of file processing
 *  @return pldm_completion_codes
 */
int decode_file_ack_req(const struct pldm_msg *msg, size_t payload_length,
			uint16_t *file_type, uint32_t *file_handle,
			uint8_t *file_status);

/** @brief Create a PLDM response for FileAck
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - PLDM completion code
 *  @param[in,out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param 'msg'
 */
int encode_file_ack_resp(uint8_t instance_id, uint8_t completion_code,
			 struct pldm_msg *msg);

/** @brief Encode FileAck command request data
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] file_type - Type of the file
 *  @param[in] file_handle - A handle to the file
 *  @param[in] file_status - Status of file processing
 *  @param[out] msg - Message will be written to this
 *  @return pldm_completion_codes
 */
int encode_file_ack_req(uint8_t instance_id, uint16_t file_type,
			uint32_t file_handle, uint8_t file_status,
			struct pldm_msg *msg);

/** @brief Decode FileAck command response data
 *
 *  @param[in] msg - pointer to PLDM response message
 *  @param[in] payload_length - Length of response payload
 *  @param[out] completion_code - PLDM completion code
 *  @return pldm_completion_codes
 */
int decode_file_ack_resp(const struct pldm_msg *msg, size_t payload_length,
			 uint8_t *completion_code);

/* FileAckWithMetadata */

/** @struct pldm_file_ack_with_meta_data_req
 *
 *  Structure representing FileAckWithMetadata request
 */
struct pldm_file_ack_with_meta_data_req {
	uint16_t file_type;	   //!< Type of file
	uint32_t file_handle;	   //!< Handle to file
	uint8_t file_status;	   //!< Status of file processing
	uint32_t file_meta_data_1; //!< Meta data specific to file type 1
	uint32_t file_meta_data_2; //!< Meta data specific to file type 2
	uint32_t file_meta_data_3; //!< Meta data specific to file type 3
	uint32_t file_meta_data_4; //!< meta data specific to file type 4
} __attribute__((packed));

/** @struct pldm_file_ack_with_meta_data_resp
 *
 *  Structure representing FileAckWithMetadata response
 */
struct pldm_file_ack_with_meta_data_resp {
	uint8_t completion_code; //!< Completion code
} __attribute__((packed));

/** @brief Encode FileAckWithMetadata request data
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] file_type - Type of the file
 *  @param[in] file_handle - A handle to the file
 *  @param[in] file_status - Status of file processing
 *  @param[in] file_meta_data_1 - meta data specific to file type 1
 *  @param[in] file_meta_data_2 - meta data specific to file type 2
 *  @param[in] file_meta_data_3 - meta data specific to file type 3
 *  @param[in] file_meta_data_4 - Meta data specific to file type 4
 *  @param[out] msg - Message will be written to this
 *  @return pldm_completion_codes
 */
int encode_file_ack_with_meta_data_req(
	uint8_t instance_id, uint16_t file_type, uint32_t file_handle,
	uint8_t file_status, uint32_t file_meta_data_1,
	uint32_t file_meta_data_2, uint32_t file_meta_data_3,
	uint32_t file_meta_data_4, struct pldm_msg *msg);

/** @brief Decode FileAckWithMetadata command response data
 *
 * @param[in] msg - pointer to PLDM response message
 * @param[in] payload_length - Length of response payload
 * @param[out] completion_code - PLDM completion code
 * @return pldm_completion_codes
 */
int decode_file_ack_with_meta_data_resp(const struct pldm_msg *msg,
					size_t payload_length,
					uint8_t *completion_code);

/** @brief Decode FileAckWithMetadata request data
 *
 * @param[in] msg - Pointer to PLDM request message
 * @param[in] payload_length - Length of request payload
 * @param[out] file_type - Type of the file
 * @param[out] file_handle - A handle to the file
 * @param[out] file_status - Status of file processing
 * @param[out] file_meta_data_1 - meta data specific to file type 1
 * @param[out] file_meta_data_2 - meta data specific to file type 2
 * @param[out] file_meta_data_3 - meta data specific to file type 3
 * @param[out] file_meta_data_4 - Meta data specific to file type 4
 * @return pldm_completion_codes
 */
int decode_file_ack_with_meta_data_req(
	const struct pldm_msg *msg, size_t payload_length, uint16_t *file_type,
	uint32_t *file_handle, uint8_t *file_status, uint32_t *file_meta_data_1,
	uint32_t *file_meta_data_2, uint32_t *file_meta_data_3,
	uint32_t *file_meta_data_4);

/** @brief Create a PLDM response message for FileAckWithMetadata
 *
 * @param[in] instance_id - Message's instance id
 * @param[in] completion_code - PLDM completion code
 * @param[in,out] msg - Message will be written to this
 * @return pldm_completion_codes
 */
int encode_file_ack_with_meta_data_resp(uint8_t instance_id,
					uint8_t completion_code,
					struct pldm_msg *msg);

/* NewFileAvailableWithMetaData */

/** @struct pldm_new_file_with_metadata_req
 *
 *  Structure representing NewFileAvailableWithMetaData request
 */

struct pldm_new_file_with_metadata_req {
	uint16_t file_type;	   //!< Type of file
	uint32_t file_handle;	   //!< Handle to file
	uint64_t length;	   //!< Number of bytes in new file
	uint32_t file_meta_data_1; //!< Meta data specific to file type 1
	uint32_t file_meta_data_2; //!< Meta data specific to file type 2
	uint32_t file_meta_data_3; //!< Meta data specific to file type 3
	uint32_t file_meta_data_4; //!< Meta data specific to file type 4
} __attribute__((packed));

/** @struct pldm_new_file_with_metadata_resp
 *
 *  Structure representing NewFileAvailableWithMetaData response data
 */
struct pldm_new_file_with_metadata_resp {
	uint8_t completion_code; //!< Completion code
} __attribute__((packed));

/** @brief Encode NewFileAvailableWithMetaData request data
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] file_type - Type of the file
 *  @param[in] file_handle - A handle to the file
 *  @param[in] length -  Number of bytes in new file
 *  @param[in] file_meta_data_1 - Meta data specific to file type 1
 *  @param[in] file_meta_data_2 - Meta data specific to file type 2
 *  @param[in] file_meta_data_3 - Meta data specific to file type 3
 *  @param[in] file_meta_data_4 - Meta data specific to file type 4
 *  @param[out] msg - Message will be written to this
 *  @return pldm_completion_codes
 */
int encode_new_file_with_metadata_req(uint8_t instance_id, uint16_t file_type,
				      uint32_t file_handle, uint64_t length,
				      uint32_t file_meta_data_1,
				      uint32_t file_meta_data_2,
				      uint32_t file_meta_data_3,
				      uint32_t file_meta_data_4,
				      struct pldm_msg *msg);

/** @brief Decode NewFileAvailableWithMetaData response data
 *
 *  @param[in] msg - pointer to PLDM response message
 *  @param[in] payload_length - Length of response payload
 *  @param[out] completion_code - PLDM completion code
 *  @return pldm_completion_codes
 */
int decode_new_file_with_metadata_resp(const struct pldm_msg *msg,
				       size_t payload_length,
				       uint8_t *completion_code);

/** @brief Decode NewFileAvailableWithMetaData request data
 *
 *  @param[in] msg - Pointer to PLDM request message
 *  @param[in] payload_length - Length of request payload
 *  @param[out] file_type - Type of the file
 *  @param[out] file_handle - A handle to the file
 *  @param[out] length - Number of bytes in new file
 *  @param[out] file_meta_data_1 - Meta data specific to file type 1
 *  @param[out] file_meta_data_2 - Meta data specific to file type 2
 *  @param[out] file_meta_data_3 - Meta data specific to file type 3
 *  @param[out] file_meta_data_4 - Meta data specific to file type 4
 *  @return pldm_completion_codes
 */
int decode_new_file_with_metadata_req(
	const struct pldm_msg *msg, size_t payload_length, uint16_t *file_type,
	uint32_t *file_handle, uint64_t *length, uint32_t *file_meta_data_1,
	uint32_t *file_meta_data_2, uint32_t *file_meta_data_3,
	uint32_t *file_meta_data_4);

/** @brief Create a PLDM response for NewFileAvailableWithMetaData
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - PLDM completion code
 *  @param[in,out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param 'msg'
 */
int encode_new_file_with_metadata_resp(uint8_t instance_id,
				       uint8_t completion_code,
				       struct pldm_msg *msg);

#ifdef __cplusplus
}
#endif

#endif /* FILEIO_H */
