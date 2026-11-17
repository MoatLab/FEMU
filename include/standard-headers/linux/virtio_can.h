/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2021-2023 OpenSynergy GmbH
 * Copyright Red Hat, Inc. 2025
 */
#ifndef _LINUX_VIRTIO_VIRTIO_CAN_H
#define _LINUX_VIRTIO_VIRTIO_CAN_H

#include "standard-headers/linux/types.h"
#include "standard-headers/linux/virtio_types.h"
#include "standard-headers/linux/virtio_ids.h"
#include "standard-headers/linux/virtio_config.h"

/* Feature bit numbers */
#define VIRTIO_CAN_F_CAN_CLASSIC        0
#define VIRTIO_CAN_F_CAN_FD             1
#define VIRTIO_CAN_F_RTR_FRAMES         2
#define VIRTIO_CAN_F_LATE_TX_ACK        3

/* CAN Result Types */
#define VIRTIO_CAN_RESULT_OK            0
#define VIRTIO_CAN_RESULT_NOT_OK        1

/* CAN flags to determine type of CAN Id */
#define VIRTIO_CAN_FLAGS_EXTENDED       0x8000
#define VIRTIO_CAN_FLAGS_FD             0x4000
#define VIRTIO_CAN_FLAGS_RTR            0x2000

#define VIRTIO_CAN_MAX_DLEN    64 /* this is like CANFD_MAX_DLEN */

struct virtio_can_config {
#define VIRTIO_CAN_S_CTRL_BUSOFF (1u << 0) /* Controller BusOff */
	/* CAN controller status */
	uint16_t status;
};

/* TX queue message types */
struct virtio_can_tx_out {
#define VIRTIO_CAN_TX                   0x0001
	uint16_t msg_type;
	uint16_t length; /* 0..8 CC, 0..64 CAN-FD, 0..2048 CAN-XL, 12 bits */
	uint8_t reserved_classic_dlc; /* If CAN classic length = 8 then DLC can be 8..15 */
	uint8_t padding;
	uint16_t reserved_xl_priority; /* May be needed for CAN XL priority */
	uint32_t flags;
	uint32_t can_id;
	uint8_t sdu[] __counted_by_le(length);
};

struct virtio_can_tx_in {
	uint8_t result;
};

/* RX queue message types */
struct virtio_can_rx {
#define VIRTIO_CAN_RX                   0x0101
	uint16_t msg_type;
	uint16_t length; /* 0..8 CC, 0..64 CAN-FD, 0..2048 CAN-XL, 12 bits */
	uint8_t reserved_classic_dlc; /* If CAN classic length = 8 then DLC can be 8..15 */
	uint8_t padding;
	uint16_t reserved_xl_priority; /* May be needed for CAN XL priority */
	uint32_t flags;
	uint32_t can_id;
	uint8_t sdu[] __counted_by_le(length);
};

/* Control queue message types */
struct virtio_can_control_out {
#define VIRTIO_CAN_SET_CTRL_MODE_START  0x0201
#define VIRTIO_CAN_SET_CTRL_MODE_STOP   0x0202
	uint16_t msg_type;
};

struct virtio_can_control_in {
	uint8_t result;
};

#endif /* #ifndef _LINUX_VIRTIO_VIRTIO_CAN_H */
