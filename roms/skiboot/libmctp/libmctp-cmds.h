/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#ifndef _LIBMCTP_CMDS_H
#define _LIBMCTP_CMDS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "libmctp.h"

/*
 * Helper structs and functions for MCTP control messages.
 * See DSP0236 v1.3.0 sec. 11 for reference.
 */

struct mctp_ctrl_msg_hdr {
	uint8_t ic_msg_type;
	uint8_t rq_dgram_inst;
	uint8_t command_code;
	uint8_t completion_code;
};

#define MCTP_CTRL_HDR_MSG_TYPE	       0
#define MCTP_CTRL_HDR_FLAG_REQUEST     (1 << 7)
#define MCTP_CTRL_HDR_FLAG_DGRAM       (1 << 6)
#define MCTP_CTRL_HDR_INSTANCE_ID_MASK 0x1F

/*
 * MCTP Control Command IDs
 * See DSP0236 v1.3.0 Table 12.
 */
#define MCTP_CTRL_CMD_RESERVED			 0x00
#define MCTP_CTRL_CMD_SET_ENDPOINT_ID		 0x01
#define MCTP_CTRL_CMD_GET_ENDPOINT_ID		 0x02
#define MCTP_CTRL_CMD_GET_ENDPOINT_UUID		 0x03
#define MCTP_CTRL_CMD_GET_VERSION_SUPPORT	 0x04
#define MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT	 0x05
#define MCTP_CTRL_CMD_GET_VENDOR_MESSAGE_SUPPORT 0x06
#define MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID	 0x07
#define MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS	 0x08
#define MCTP_CTRL_CMD_ROUTING_INFO_UPDATE	 0x09
#define MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES	 0x0A
#define MCTP_CTRL_CMD_PREPARE_ENDPOINT_DISCOVERY 0x0B
#define MCTP_CTRL_CMD_ENDPOINT_DISCOVERY	 0x0C
#define MCTP_CTRL_CMD_DISCOVERY_NOTIFY		 0x0D
#define MCTP_CTRL_CMD_GET_NETWORK_ID		 0x0E
#define MCTP_CTRL_CMD_QUERY_HOP			 0x0F
#define MCTP_CTRL_CMD_RESOLVE_UUID		 0x10
#define MCTP_CTRL_CMD_QUERY_RATE_LIMIT		 0x11
#define MCTP_CTRL_CMD_REQUEST_TX_RATE_LIMIT	 0x12
#define MCTP_CTRL_CMD_UPDATE_RATE_LIMIT		 0x13
#define MCTP_CTRL_CMD_QUERY_SUPPORTED_INTERFACES 0x14
#define MCTP_CTRL_CMD_MAX			 0x15
/* 0xF0 - 0xFF are transport specific */
#define MCTP_CTRL_CMD_FIRST_TRANSPORT 0xF0
#define MCTP_CTRL_CMD_LAST_TRANSPORT  0xFF

/*
 * MCTP Control Completion Codes
 * See DSP0236 v1.3.0 Table 13.
 */
#define MCTP_CTRL_CC_SUCCESS		   0x00
#define MCTP_CTRL_CC_ERROR		   0x01
#define MCTP_CTRL_CC_ERROR_INVALID_DATA	   0x02
#define MCTP_CTRL_CC_ERROR_INVALID_LENGTH  0x03
#define MCTP_CTRL_CC_ERROR_NOT_READY	   0x04
#define MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD 0x05
/* 0x80 - 0xFF are command specific */

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_CMDS_H */
