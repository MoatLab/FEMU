// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * This is based on the hostboot ecc code
 *
 * Copyright 2013-2018 IBM Corp.
 */

#ifndef __ECC_H
#define __ECC_H

#include <stdint.h>
#include <ccan/endian/endian.h>

struct ecc64 {
	beint64_t data;
	uint8_t ecc;
} __attribute__((__packed__));

extern int memcpy_from_ecc(beint64_t *dst, struct ecc64 *src, uint64_t len);
extern int memcpy_from_ecc_unaligned(beint64_t *dst, struct ecc64 *src, uint64_t len,
		uint8_t alignment);

extern int memcpy_to_ecc(struct ecc64 *dst, const beint64_t *src, uint64_t len);
extern int memcpy_to_ecc_unaligned(struct ecc64 *dst, const beint64_t *src, uint64_t len,
		uint8_t alignment);

/*
 * Calculate the size of a buffer if ECC is added
 *
 * We add 1 byte of ecc for every 8 bytes of data.  So we need to round up to 8
 * bytes length and then add 1/8
 */
#ifndef ALIGN_UP
#define ALIGN_UP(_v, _a)	(((_v) + (_a) - 1) & ~((_a) - 1))
#endif

#define BYTES_PER_ECC 8

static inline uint64_t ecc_size(uint64_t len)
{
	return ALIGN_UP(len, BYTES_PER_ECC) >> 3;
}

static inline uint64_t ecc_buffer_size(uint64_t len)
{
	return ALIGN_UP(len, BYTES_PER_ECC) + ecc_size(len);
}

static inline int ecc_buffer_size_check(uint64_t len)
{
	return len % (BYTES_PER_ECC + 1);
}

static inline uint64_t ecc_buffer_size_minus_ecc(uint64_t len)
{
	return len * BYTES_PER_ECC / (BYTES_PER_ECC + 1);
}

static inline uint64_t ecc_buffer_align(uint64_t start, uint64_t pos)
{
	return pos - ((pos - start) % (BYTES_PER_ECC + 1));
}

#endif
