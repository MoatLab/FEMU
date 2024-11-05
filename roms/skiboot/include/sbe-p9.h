// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2017-2019 IBM Corp. */

#ifndef __SBE_P9_H
#define __SBE_P9_H

#include <bitutils.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>

/* Worst case command timeout value (90 sec) */
#define SBE_CMD_TIMEOUT_MAX			(90 * 1000)

/* Primary response status code */
#define SBE_STATUS_PRI_SUCCESS			0x00
#define SBE_STATUS_PRI_INVALID_CMD		0x01
#define SBE_STATUS_PRI_INVALID_DATA		0x02
#define SBE_STATUS_PRI_SEQ_ERR			0x03
#define SBE_STATUS_PRI_INTERNAL_ERR		0x04
#define SBE_STATUS_PRI_UNSECURE_ACCESS		0x05
#define SBE_STATUS_PRI_GENERIC_ERR		0xFE

/* Secondary response status code */
#define SBE_STATUS_SEC_SUCCESS			0x00
#define SBE_STATUS_SEC_CMD_CLASS_UNSUPPORTED	0x01
#define SBE_STATUS_SEC_CMD_UNSUPPORTED		0x02
#define SBE_STATUS_SEC_INV_ADDR			0x03
#define SBE_STATUS_SEC_INV_TARGET_TYPE		0x04
#define SBE_STATUS_SEC_INV_CHIPLET_ID		0x05
#define SBE_STATUS_SEC_TARGET_NOT_PRESENT	0x06
#define SBE_STATUS_SEC_TARGET_NOT_FUNC		0x07
#define SBE_STATUS_SEC_CMD_NOT_ALLOW		0x08
#define SBE_STATUS_SEC_FUNC_NOT_SUPPORTED	0x09
#define SBE_STATUS_SEC_GENERIC_ERR		0x0A
#define SBE_STATUS_SEC_BLACKLIST_REG		0x0B
#define SBE_STATUS_SEC_OS_FAILURE		0x0C
#define SBE_STATUS_SEC_MBX_REG_FAILURE		0x0D
#define SBE_STATUS_SEC_INSUFFICIENT_DATA	0x0E
#define SBE_STATUS_SEC_EXCESS_DATA		0x0F
#define SBE_STATUS_SEC_HW_TIMEOUT		0x10
#define SBE_STATUS_SEC_PCBPIB_ERR		0x11
#define SBE_STATUS_SEC_FIFO_PARITY_ERR		0x12
#define SBE_STATUS_SEC_TIMER_EXPIRED		0x13
#define SBE_STATUS_SEC_BLACKLISTED_MEM		0x14
#define SBE_STATUS_SEC_UNSEC_REGION_NOT_FOUND	0x15
#define SBE_STATUS_SEC_UNSEC_REGION_EXCEEDED	0x16
#define SBE_STATUS_SEC_UNSEC_REGION_AMEND	0x17
#define SBE_STATUS_SEC_INPUT_BUF_OVERFLOW	0x18
#define SBE_STATUS_SEC_INVALID_PARAMS		0x19
#define SBE_STATUS_SEC_BLACKLISTED_CMD		0x20

/* Number of MBOX register on each side */
#define NR_HOST_SBE_MBOX_REG		0x04

/*
 * SBE MBOX register address
 *   Reg 0 - 3 : Host to send command packets to SBE
 *   Reg 4 - 7 : SBE to send response packets to Host
 */
#define PSU_HOST_SBE_MBOX_REG0		0x000D0050
#define PSU_HOST_SBE_MBOX_REG1		0x000D0051
#define PSU_HOST_SBE_MBOX_REG2		0x000D0052
#define PSU_HOST_SBE_MBOX_REG3		0x000D0053
#define PSU_HOST_SBE_MBOX_REG4		0x000D0054
#define PSU_HOST_SBE_MBOX_REG5		0x000D0055
#define PSU_HOST_SBE_MBOX_REG6		0x000D0056
#define PSU_HOST_SBE_MBOX_REG7		0x000D0057
#define PSU_SBE_DOORBELL_REG_RW		0x000D0060
#define PSU_SBE_DOORBELL_REG_AND	0x000D0061
#define PSU_SBE_DOORBELL_REG_OR		0x000D0062
#define PSU_HOST_DOORBELL_REG_RW	0x000D0063
#define PSU_HOST_DOORBELL_REG_AND	0x000D0064
#define PSU_HOST_DOORBELL_REG_OR	0x000D0065

/*
 * Doorbell register to trigger SBE interrupt. Set by OPAL to inform
 * the SBE about a waiting message in the Host/SBE mailbox registers
 */
#define HOST_SBE_MSG_WAITING		PPC_BIT(0)

/*
 * Doorbell register for host bridge interrupt. Set by the SBE to inform
 * host about a response message in the Host/SBE mailbox registers
 */
#define SBE_HOST_RESPONSE_WAITING	PPC_BIT(0)
#define SBE_HOST_MSG_READ		PPC_BIT(1)
#define SBE_HOST_STOP15_EXIT		PPC_BIT(2)
#define SBE_HOST_RESET			PPC_BIT(3)
#define SBE_HOST_PASSTHROUGH		PPC_BIT(4)
#define SBE_HOST_TIMER_EXPIRY		PPC_BIT(14)
#define SBE_HOST_RESPONSE_MASK		(PPC_BITMASK(0, 4) | SBE_HOST_TIMER_EXPIRY)

/* SBE Control Register */
#define SBE_CONTROL_REG_RW		0x00050008

/* SBE interrupt s0/s1 bits */
#define SBE_CONTROL_REG_S0		PPC_BIT(14)
#define SBE_CONTROL_REG_S1		PPC_BIT(15)

/* SBE Target Type */
#define SBE_TARGET_TYPE_PROC		0x00
#define SBE_TARGET_TYPE_EX		0x01
#define SBE_TARGET_TYPE_PERV		0x02
#define SBE_TARGET_TYPE_MCS		0x03
#define SBE_TARGET_TYPE_EQ		0x04
#define SBE_TARGET_TYPE_CORE		0x05

/* SBE MBOX command class */
#define SBE_MCLASS_FIRST		0xD1
#define SBE_MCLASS_CORE_STATE		0xD1
#define SBE_MCLASS_SCOM			0xD2
#define SBE_MCLASS_RING			0xD3
#define SBE_MCLASS_TIMER		0xD4
#define SBE_MCLASS_MPIPL		0xD5
#define SBE_MCLASS_SECURITY		0xD6
#define SBE_MCLASS_GENERIC		0xD7
#define SBE_MCLASS_LAST			0xD7

/*
 * Commands are provided in xxyy form where:
 *   - xx : command class
 *   - yy : command
 *
 * Both request and response message uses same seq ID,
 * command class and command.
 */
#define SBE_CMD_CTRL_DEADMAN_LOOP	0xD101
#define SBE_CMD_MULTI_SCOM		0xD201
#define SBE_CMD_PUT_RING_FORM_IMAGE	0xD301
#define SBE_CMD_CONTROL_TIMER		0xD401
#define SBE_CMD_GET_ARCHITECTED_REG	0xD501
#define SBE_CMD_CLR_ARCHITECTED_REG	0xD502
#define SBE_CMD_SET_UNSEC_MEM_WINDOW	0xD601
#define SBE_CMD_GET_SBE_FFDC		0xD701
#define SBE_CMD_GET_CAPABILITY		0xD702
#define SBE_CMD_READ_SBE_SEEPROM	0xD703
#define SBE_CMD_SET_FFDC_ADDR		0xD704
#define SBE_CMD_QUIESCE_SBE		0xD705
#define SBE_CMD_SET_FABRIC_ID_MAP	0xD706
#define SBE_CMD_STASH_MPIPL_CONFIG	0xD707

/* SBE MBOX control flags */

/* Generic flags */
#define SBE_CMD_CTRL_RESP_REQ		0x0100
#define SBE_CMD_CTRL_ACK_REQ		0x0200

/* Deadman loop */
#define CTRL_DEADMAN_LOOP_START		0x0001
#define CTRL_DEADMAN_LOOP_STOP		0x0002

/* Control timer */
#define CONTROL_TIMER_START		0x0001
#define CONTROL_TIMER_STOP		0x0002

/* Stash MPIPL config */
#define SBE_STASH_KEY_SKIBOOT_BASE	0x03

/* SBE message state */
enum p9_sbe_msg_state {
	sbe_msg_unused = 0,	/* Free */
	sbe_msg_queued,		/* Queued to SBE list */
	sbe_msg_sent,		/* Sent to SBE */
	sbe_msg_wresp,		/* Waiting for response */
	sbe_msg_done,		/* Complete */
	sbe_msg_timeout,	/* Message timeout */
	sbe_msg_error,		/* Failed to send message to SBE */
};

/* SBE message */
struct p9_sbe_msg {
	/*
	 * Reg[0] :
	 *   word0 :
	 *     direct cmd  : reserved << 16 | ctrl flag
	 *     indirect cmd: mem_addr_size_dword
	 *     response    : primary status << 16 | secondary status
	 *
	 *   word1 : seq id << 16 | cmd class << 8 | cmd
	 *
	 * WARNING:
	 *   - Don't populate reg[0].seq (byte 4,5). This will be populated by
	 *     p9_sbe_queue_msg().
	 */
	u64	reg[4];

	/* cmd timout : mftb() + msecs_to_tb(SBE_CMD_TIMEOUT_MAX) */
	u64	timeout;

	/* Completion function */
	void (*complete)(struct p9_sbe_msg *msg);
	void *user_data;

	/* Current msg state */
	enum p9_sbe_msg_state	state;

	/* Set if the message expects a response */
	bool			response;

	/* Response will be filled by driver when response received */
	struct p9_sbe_msg	*resp;

	/* Internal queuing */
	struct list_node	link;
};


/* Allocate and populate p9_sbe_msg structure */
extern struct p9_sbe_msg *p9_sbe_mkmsg(u16 cmd, u16 ctrl_flag, u64 reg1,
				       u64 reg2, u64 reg3) __warn_unused_result;

/* Free p9_sbe_msg structure */
extern void p9_sbe_freemsg(struct p9_sbe_msg *msg);

/* Add new message to sbe queue */
extern int p9_sbe_queue_msg(uint32_t chip_id, struct p9_sbe_msg *msg,
		void (*comp)(struct p9_sbe_msg *msg)) __warn_unused_result;

/* Synchronously send message to SBE */
extern int p9_sbe_sync_msg(u32 chip_id, struct p9_sbe_msg *msg, bool autofree);

/* Remove message from SBE queue, it will not remove inflight message */
extern int p9_sbe_cancelmsg(u32 chip_id, struct p9_sbe_msg *msg);

/* Initialize the SBE mailbox driver */
extern void p9_sbe_init(void);

/* SBE interrupt */
extern void p9_sbe_interrupt(uint32_t chip_id);

/* Is SBE timer available ? */
extern bool p9_sbe_timer_ok(void);

/* Update SBE timer expiry */
extern void p9_sbe_update_timer_expiry(uint64_t new_target);

/* Send skiboot relocated base address to SBE */
extern void p9_sbe_send_relocated_base(uint64_t reloc_base);

/* Terminate and trigger MPIPL */
extern void p9_sbe_terminate(void);

#endif	/* __SBE_P9_H */
