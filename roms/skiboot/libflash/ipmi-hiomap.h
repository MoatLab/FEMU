// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2018-2019 IBM Corp. */

#ifndef __LIBFLASH_IPMI_HIOMAP_H
#define __LIBFLASH_IPMI_HIOMAP_H

#include <lock.h>
#include <stdbool.h>
#include <stdint.h>

#include "blocklevel.h"

enum lpc_window_state { closed_window, read_window, write_window };

struct lpc_window {
	uint32_t lpc_addr; /* Offset into LPC space */
	uint32_t cur_pos;  /* Current position of the window in the flash */
	uint32_t size;     /* Size of the window into the flash */
};

struct ipmi_hiomap {
	/* Members protected by the blocklevel lock */
	uint8_t seq;
	uint8_t version;
	uint8_t block_size_shift;
	uint16_t timeout;
	struct blocklevel_device bl;
	uint32_t total_size;
	uint32_t erase_granule;
	struct lpc_window current;

	/*
	 * update, bmc_state and window_state can be accessed by both calls
	 * through read/write/erase functions and the IPMI SEL handler. All
	 * three variables are protected by lock to avoid conflict.
	 */
	struct lock lock;
	uint8_t bmc_state;
	enum lpc_window_state window_state;
};

int ipmi_hiomap_init(struct blocklevel_device **bl);
bool ipmi_hiomap_exit(struct blocklevel_device *bl);

#endif /* __LIBFLASH_IPMI_HIOMAP_H */
