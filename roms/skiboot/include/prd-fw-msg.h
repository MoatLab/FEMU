// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2017-2019 IBM Corp. */

#ifndef __PRD_FW_MSG_H
#define __PRD_FW_MSG_H

#include <types.h>

/* Messaging structure for the opaque channel between OPAL and HBRT. This
 * format is used for the firmware_request and firmware_notify interfaces
 */
enum {
	PRD_FW_MSG_TYPE_REQ_NOP = 0,
	PRD_FW_MSG_TYPE_RESP_NOP = 1,
	PRD_FW_MSG_TYPE_RESP_GENERIC = 2,
	PRD_FW_MSG_TYPE_REQ_HCODE_UPDATE = 3,
	PRD_FW_MSG_TYPE_HBRT_FSP = 4,
	PRD_FW_MSG_TYPE_ERROR_LOG = 5,
	PRD_FW_MSG_TYPE_FSP_HBRT = 6,
};

struct prd_fw_msg {
	__be64		type;
	union {
		struct {
			__be64	status;
		} generic_resp;
		struct {
			__be32	plid;
			__be32	size;
			char	data[];
		} __packed errorlog;
		struct {
			char	data;
		} mbox_msg;
	};
};

#define PRD_FW_MSG_BASE_SIZE	sizeof(__be64)

#endif /* __PRD_FW_MSG_H */
