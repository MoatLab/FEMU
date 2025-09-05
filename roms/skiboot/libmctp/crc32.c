/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 IBM Corp. */

#include "crc32.h"

#include <limits.h>

/* Very dumb CRC-32 implementation */
uint32_t crc32(const void *buf, size_t len)
{
	const uint8_t *buf8 = buf;
	uint32_t rem = 0xffffffff;

	for (; len; len--) {
		int i;

		rem = rem ^ *buf8;
		for (i = 0; i < CHAR_BIT; i++)
			rem = (rem >> 1) ^ ((rem & 1) * 0xEDB88320);

		buf8++;
	}

	return rem ^ 0xffffffff;
}
