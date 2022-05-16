// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2017-2018 IBM Corp. */

#ifndef __LPC_MBOX_H
#define __LPC_MBOX_H

#include <hiomap.h>
#include <opal.h>
#include <ccan/endian/endian.h>

#define BMC_MBOX_ARGS_REGS 11
#define BMC_MBOX_READ_REGS 16
#define BMC_MBOX_WRITE_REGS 13

#define MBOX_C_RESET_STATE 		HIOMAP_C_RESET
#define MBOX_C_GET_MBOX_INFO 		HIOMAP_C_GET_INFO
#define MBOX_C_GET_FLASH_INFO		HIOMAP_C_GET_FLASH_INFO
#define MBOX_C_CREATE_READ_WINDOW	HIOMAP_C_CREATE_READ_WINDOW
#define MBOX_C_CLOSE_WINDOW		HIOMAP_C_CLOSE_WINDOW
#define MBOX_C_CREATE_WRITE_WINDOW	HIOMAP_C_CREATE_WRITE_WINDOW
#define MBOX_C_MARK_WRITE_DIRTY		HIOMAP_C_MARK_DIRTY
#define MBOX_C_WRITE_FLUSH		HIOMAP_C_FLUSH
#define MBOX_C_BMC_EVENT_ACK		HIOMAP_C_ACK
#define MBOX_C_MARK_WRITE_ERASED	HIOMAP_C_ERASE
#define MBOX_C_GET_FLASH_NAME		HIOMAP_C_DEVICE_NAME
#define MBOX_C_MARK_LOCKED		HIOMAP_C_LOCK
#define MBOX_COMMAND_COUNT 12

#define MBOX_R_SUCCESS 0x01
#define MBOX_R_PARAM_ERROR 0x02
#define MBOX_R_WRITE_ERROR 0x03
#define MBOX_R_SYSTEM_ERROR 0x04
#define MBOX_R_TIMEOUT 0x05
#define MBOX_R_BUSY 0x06
#define MBOX_R_WINDOW_ERROR 0x07
#define MBOX_R_SEQ_ERROR 0x08
#define MBOX_R_LOCKED 0x09

#define MBOX_ATTN_ACK_MASK		HIOMAP_E_ACK_MASK
#define MBOX_ATTN_BMC_REBOOT		HIOMAP_E_PROTOCOL_RESET
#define MBOX_ATTN_BMC_WINDOW_RESET	HIOMAP_E_WINDOW_RESET
#define MBOX_ATTN_BMC_FLASH_LOST	HIOMAP_E_FLASH_LOST
#define MBOX_ATTN_BMC_DAEMON_READY	HIOMAP_E_DAEMON_READY

/* Default poll interval before interrupts are working */
#define MBOX_DEFAULT_POLL_MS	200

struct bmc_mbox_msg {
	uint8_t command;
	uint8_t seq;
	uint8_t args[BMC_MBOX_ARGS_REGS];
	uint8_t response;
	uint8_t host;
	uint8_t bmc;
};

int bmc_mbox_enqueue(struct bmc_mbox_msg *msg, unsigned int timeout_sec);
int bmc_mbox_register_callback(void (*callback)(struct bmc_mbox_msg *msg, void *priv),
		void *drv_data);
int bmc_mbox_register_attn(void (*callback)(uint8_t bits, void *priv),
		void *drv_data);
uint8_t bmc_mbox_get_attn_reg(void);
#endif /* __LPC_MBOX_H */
