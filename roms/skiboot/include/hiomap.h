// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2018 IBM Corp. */

#ifndef __HIOMAP_H
#define __HIOMAP_H

#include <ccan/endian/endian.h>
#include <ccan/short_types/short_types.h>
#include <compiler.h>
#include <stdint.h>

#define HIOMAP_V1                       1
#define HIOMAP_V2                       2

#define HIOMAP_C_RESET                  1
#define HIOMAP_C_GET_INFO               2
#define HIOMAP_C_GET_FLASH_INFO	        3
#define HIOMAP_C_CREATE_READ_WINDOW     4
#define HIOMAP_C_CLOSE_WINDOW           5
#define HIOMAP_C_CREATE_WRITE_WINDOW    6
#define HIOMAP_C_MARK_DIRTY             7
#define HIOMAP_C_FLUSH                  8
#define HIOMAP_C_ACK                    9
#define HIOMAP_C_ERASE                  10
#define HIOMAP_C_DEVICE_NAME            11
#define HIOMAP_C_LOCK                   12

#define HIOMAP_E_ACK_MASK               0x3
#define HIOMAP_E_PROTOCOL_RESET	        (1 << 0)
#define HIOMAP_E_WINDOW_RESET           (1 << 1)
#define HIOMAP_E_FLASH_LOST             (1 << 6)
#define HIOMAP_E_DAEMON_READY           (1 << 7)

struct hiomap_v2_range {
    le16 offset;
    le16 size;
} __packed;

struct hiomap_v2_info {
    uint8_t block_size_shift;
    le16 timeout;
} __packed;

struct hiomap_v2_flash_info {
    le16 total_size;
    le16 erase_granule;
} __packed;

struct hiomap_v2_create_window {
    le16 lpc_addr;
    le16 size;
    le16 offset;
} __packed;

#endif /* __HIOMAP_H */
