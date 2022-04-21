// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2016 IBM Corp. */

#ifndef __BITUTILS_H
#define __BITUTILS_H

/* PPC bit number conversion */
#ifdef __ASSEMBLY__
#define PPC_BIT(bit)		(0x8000000000000000 >> (bit))
#define PPC_BIT32(bit)		(0x80000000 >> (bit))
#define PPC_BIT16(bit)		(0x8000 >> (bit))
#define PPC_BIT8(bit)		(0x80 >> (bit))
#else
#define PPC_BIT(bit)		(0x8000000000000000UL >> (bit))
#define PPC_BIT32(bit)		(0x80000000UL >> (bit))
#define PPC_BIT16(bit)		(0x8000UL >> (bit))
#define PPC_BIT8(bit)		(0x80UL >> (bit))
#endif
#define PPC_BITMASK(bs,be)	((PPC_BIT(bs) - PPC_BIT(be)) | PPC_BIT(bs))
#define PPC_BITMASK32(bs,be)	((PPC_BIT32(bs) - PPC_BIT32(be))|PPC_BIT32(bs))
#define PPC_BITMASK16(bs,be)	((PPC_BIT16(bs) - PPC_BIT16(be))|PPC_BIT16(bs))
#define PPC_BITMASK8(bs,be)	((PPC_BIT8(bs) - PPC_BIT8(be))|PPC_BIT8(bs))
#define PPC_BITLSHIFT(be)	(63 - (be))
#define PPC_BITLSHIFT32(be)	(31 - (be))

/*
 * PPC bitmask field manipulation
 */

/* Find left shift from first set bit in mask */
#define MASK_TO_LSH(m)		(__builtin_ffsl(m) - 1)

/* Extract field from 'v' according to mask 'm' */
#define GETFIELD(m, v)		(((v) & (m)) >> MASK_TO_LSH(m))

/* Set field specified by mask 'm' of 'v' to value 'val'
 * NOTE: 'v' isn't modified, the combined result is returned
 */
#define SETFIELD(m, v, val)				\
	(((v) & ~(m)) |	((((typeof(v))(val)) << MASK_TO_LSH(m)) & (m)))

#endif /* __BITUTILS_H */
