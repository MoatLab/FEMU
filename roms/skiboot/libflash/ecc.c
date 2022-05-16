// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * This is based on the hostboot ecc code
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#include <ccan/endian/endian.h>

#include "libflash.h"
#include "ecc.h"

/* Bit field identifiers for syndrome calculations. */
enum eccbitfields
{
        GD = 0xff,      //< Good, ECC matches.
        UE = 0xfe,      //< Uncorrectable.
        E0 = 71,        //< Error in ECC bit 0
        E1 = 70,        //< Error in ECC bit 1
        E2 = 69,        //< Error in ECC bit 2
        E3 = 68,        //< Error in ECC bit 3
        E4 = 67,        //< Error in ECC bit 4
        E5 = 66,        //< Error in ECC bit 5
        E6 = 65,        //< Error in ECC bit 6
        E7 = 64         //< Error in ECC bit 7
        /* 0-63 Correctable bit in byte */
};

/*
 * Matrix used for ECC calculation.
 *
 *  Each row of this is the set of data word bits that are used for
 *  the calculation of the corresponding ECC bit.  The parity of the
 *  bitset is the value of the ECC bit.
 *
 *  ie. ECC[n] = eccMatrix[n] & data
 *
 *  Note: To make the math easier (and less shifts in resulting code),
 *        row0 = ECC7.  HW numbering is MSB, order here is LSB.
 *
 *  These values come from the HW design of the ECC algorithm.
 */
static uint64_t eccmatrix[] = {
        0x0000e8423c0f99ffull,
        0x00e8423c0f99ff00ull,
        0xe8423c0f99ff0000ull,
        0x423c0f99ff0000e8ull,
        0x3c0f99ff0000e842ull,
        0x0f99ff0000e8423cull,
        0x99ff0000e8423c0full,
        0xff0000e8423c0f99ull
};

/**
 * Syndrome calculation matrix.
 *
 *  Maps syndrome to flipped bit.
 *
 *  To perform ECC correction, this matrix is a look-up of the bit
 *  that is bad based on the binary difference of the good and bad
 *  ECC.  This difference is called the "syndrome".
 *
 *  When a particular bit is on in the data, it cause a column from
 *  eccMatrix being XOR'd into the ECC field.  This column is the
 *  "effect" of each bit.  If a bit is flipped in the data then its
 *  "effect" is missing from the ECC.  You can calculate ECC on unknown
 *  quality data and compare the ECC field between the calculated
 *  value and the stored value.  If the difference is zero, then the
 *  data is clean.  If the difference is non-zero, you look up the
 *  difference in the syndrome table to identify the "effect" that
 *  is missing, which is the bit that is flipped.
 *
 *  Notice that ECC bit flips are recorded by a single "effect"
 *  bit (ie. 0x1, 0x2, 0x4, 0x8 ...) and double bit flips are identified
 *  by the UE status in the table.
 *
 *  Bits are in MSB order.
 */
static enum eccbitfields syndromematrix[] = {
        GD, E7, E6, UE, E5, UE, UE, 47, E4, UE, UE, 37, UE, 35, 39, UE,
        E3, UE, UE, 48, UE, 30, 29, UE, UE, 57, 27, UE, 31, UE, UE, UE,
        E2, UE, UE, 17, UE, 18, 40, UE, UE, 58, 22, UE, 21, UE, UE, UE,
        UE, 16, 49, UE, 19, UE, UE, UE, 23, UE, UE, UE, UE, 20, UE, UE,
        E1, UE, UE, 51, UE, 46,  9, UE, UE, 34, 10, UE, 32, UE, UE, 36,
        UE, 62, 50, UE, 14, UE, UE, UE, 13, UE, UE, UE, UE, UE, UE, UE,
        UE, 61,  8, UE, 41, UE, UE, UE, 11, UE, UE, UE, UE, UE, UE, UE,
        15, UE, UE, UE, UE, UE, UE, UE, UE, UE, 12, UE, UE, UE, UE, UE,
        E0, UE, UE, 55, UE, 45, 43, UE, UE, 56, 38, UE,  1, UE, UE, UE,
        UE, 25, 26, UE,  2, UE, UE, UE, 24, UE, UE, UE, UE, UE, 28, UE,
        UE, 59, 54, UE, 42, UE, UE, 44,  6, UE, UE, UE, UE, UE, UE, UE,
         5, UE, UE, UE, UE, UE, UE, UE, UE, UE, UE, UE, UE, UE, UE, UE,
        UE, 63, 53, UE,  0, UE, UE, UE, 33, UE, UE, UE, UE, UE, UE, UE,
         3, UE, UE, 52, UE, UE, UE, UE, UE, UE, UE, UE, UE, UE, UE, UE,
         7, UE, UE, UE, UE, UE, UE, UE, UE, 60, UE, UE, UE, UE, UE, UE,
        UE, UE, UE, UE,  4, UE, UE, UE, UE, UE, UE, UE, UE, UE, UE, UE,
};

/**
 * Create the ECC field corresponding to a 8-byte data field
 *
 *  @data:	The 8 byte data to generate ECC for.
 *  @return:	The 1 byte ECC corresponding to the data.
 */
static uint8_t eccgenerate(uint64_t data)
{
	int i;
	uint8_t result = 0;

	for (i = 0; i < 8; i++)
		result |= __builtin_parityll(eccmatrix[i] & data) << i;

	return result;
}

/**
 * Verify the data and ECC match or indicate how they are wrong.
 *
 * @data:	The data to check ECC on.
 * @ecc:	The [supposed] ECC for the data.
 *
 * @return:	eccBitfield or 0-64.
 *
 * @retval GD - Indicates the data is good (matches ECC).
 * @retval UE - Indicates the data is uncorrectable.
 * @retval all others - Indication of which bit is incorrect.
 */
static enum eccbitfields eccverify(uint64_t data, uint8_t ecc)
{
	return syndromematrix[eccgenerate(data) ^ ecc];
}

/* IBM bit ordering */
static inline uint64_t eccflipbit(uint64_t data, uint8_t bit)
{
	if (bit > 63)
		return data;

	return data ^ (1ul << (63 - bit));
}

static int eccbyte(beint64_t *dst, struct ecc64 *src)
{
	uint8_t ecc, badbit;
	uint64_t data;

	data = be64_to_cpu(src->data);
	ecc = src->ecc;

	badbit = eccverify(data, ecc);
	if (badbit == UE) {
		FL_ERR("ECC: uncorrectable error: %016llx %02x\n", (unsigned long long int)data, ecc);
		return badbit;
	}
	if (badbit <= UE)
		FL_INF("ECC: correctable error: %i\n", badbit);
	if (badbit < 64)
		*dst = cpu_to_be64(eccflipbit(data, badbit));
	else
		*dst = cpu_to_be64(data);

	return 0;
}

static beint64_t *inc_beint64_by(const void *p, uint64_t i)
{
	return (beint64_t *)(((char *)p) + i);
}

static uint64_t *inc_uint64_by(const void *p, uint64_t i)
{
	return (uint64_t *)(((char *)p) + i);
}

static struct ecc64 *inc_ecc64_by(struct ecc64 *p, uint64_t i)
{
	return (struct ecc64 *)(((char *)p) + i);
}

static uint64_t whole_ecc_bytes(uint64_t i)
{
	return i & ~(BYTES_PER_ECC - 1);
}

static uint64_t whole_ecc_structs(uint64_t i)
{
	return whole_ecc_bytes(i) >> 3;
}

/**
 * Copy data from an input buffer with ECC to an output buffer without ECC.
 * Correct it along the way and check for errors.
 *
 * @dst:	destination buffer without ECC
 * @src:	source buffer with ECC
 * @len:	number of bytes of data to copy (without ecc).
 *                   Must be 8 byte aligned.
 *
 * @return:	Success or error
 *
 * @retval: 0 - success
 * @retfal: other - fail
 */
int memcpy_from_ecc(beint64_t *dst, struct ecc64 *src, uint64_t len)
{
	uint32_t i;

	if (len & 0x7) {
		/* TODO: we could probably handle this */
		FL_ERR("ECC data length must be 8 byte aligned length:%" PRIx64  "\n",
		       len);
		return -1;
	}

	/* Handle in chunks of 8 bytes, so adjust the length */
	len >>= 3;

	for (i = 0; i < len; i++) {
		int rc;
		rc = eccbyte(dst, src + i);
		if (rc)
			return rc;
		dst++;
	}
	return 0;
}

/**
 * Copy data from an input buffer with ECC to an output buffer without ECC.
 * Correct it along the way and check for errors.
 *
 * Unlike memcmp_from_ecc() which requires that the first byte into
 * dst be the first byte in src (which must also be aligned to a
 * struct ecc64 struct boundary) this function can cope with the first
 * byte in dst not being the first byte in src.
 *
 * Note: src MUST still be aligned to a struct ecc64 otherwise ECC
 * calculations are impossible.
 *
 * The alignment parameter species the number of bytes present at the
 * start of src that should be skipped and not written to dst. Once
 * again, these bytes must be in src otherwise the ECC cannot be
 * checked.
 *
 * len also doesn't have any value limitation for this function. Of
 * course src must contain an exact multiple of struct ecc64 otherwise
 * ECC calculation cannot be performed but this function won't copy
 * the entirety of the last src data word if len is not mutiple of 8
 *
 * @dst:		destination buffer without ECC
 * @src:		source buffer with ECC
 * @len:		number of bytes of data to copy (without ecc).
 * @alignment:	number of leading bytes in src which shouldn't be
 * 				copied to dst
 * @return:	Success or error
 *
 * @retval: 0 - success
 * @retfal: other - fail
 */
int memcpy_from_ecc_unaligned(beint64_t *dst, struct ecc64 *src,
		uint64_t len, uint8_t alignment)
{
	char data[BYTES_PER_ECC];
	uint8_t bytes_wanted;
	int rc;

	if (alignment > 8)
		return -1;

	bytes_wanted = BYTES_PER_ECC - alignment;

	/*
	 * Only actually do the first calculation if an alignment is
	 * required - otherwise jump straight to memcpy_from_ecc()
	 */
	if (alignment) {
		rc = eccbyte((beint64_t *)data, src);
		if (rc)
			return rc;

		memcpy(dst, &data[alignment], bytes_wanted);

		src = inc_ecc64_by(src, sizeof(struct ecc64));
		dst = inc_beint64_by(dst, bytes_wanted);
		len -= bytes_wanted;
	}

	if (len >= BYTES_PER_ECC) {
		rc = memcpy_from_ecc(dst, src, whole_ecc_bytes(len));
		if (rc)
			return rc;

		/*
		 * It helps to let the compiler to the pointer arithmetic
		 * here, (dst and src are different types)
		 */
		dst += whole_ecc_structs(len);
		src += whole_ecc_structs(len);
		len -= whole_ecc_bytes(len);
	}

	if (len) {
		rc = eccbyte((beint64_t *)data, src);
		if (rc)
			return rc;

		memcpy(dst, data, len);
	}

	return 0;
}

/**
 * Copy data from an input buffer without ECC to an output buffer with ECC.
 *
 * @dst:	destination buffer with ECC
 * @src:	source buffer without ECC
 * @len:	number of bytes of data to copy (without ecc, length of src).
 *       Note: dst must be big enough to hold ecc bytes as well.
 *                   Must be 8 byte aligned.
 *
 * @return:	success or failure
 *
 * @retval: 0 - success
 * @retfal: other - fail
 */
int memcpy_to_ecc(struct ecc64 *dst, const beint64_t *src, uint64_t len)
{
	struct ecc64 ecc_word;
	uint64_t i;

	if (len & 0x7) {
		/* TODO: we could probably handle this */
		FL_ERR("Data to add ECC bytes to must be 8 byte aligned length: %"
		       PRIx64 "\n", len);
		return -1;
	}

	/* Handle in chunks of 8 bytes, so adjust the length */
	len >>= 3;

	for (i = 0; i < len; i++) {
		ecc_word.ecc = eccgenerate(be64_to_cpu(*(src + i)));
		ecc_word.data = *(src + i);

		*(dst + i) = ecc_word;
	}

	return 0;
}

/**
 * Copy data from an input buffer without ECC to an output buffer with ECC.
 *
 * Unlike memcmp_to_ecc() which requires that the first byte in src be
 * the first byte of a struct ecc64 structure this function does not
 * have this requirement.
 *
 * Like memcpy_to_ecc_unaligned() the alignment parameter specfies the
 * number of bytes in the first src word that are missing and would be
 * required to form a struct ecc64 structure.
 *
 * It must be noted here that extra work IN THE CALLER must be done
 * if your data is unaligned. In order to peform ECC calculations
 * whatever portions of the ecc words are missing in src must be in
 * dst.
 *
 * For example, if there is an alignment value of 1 then this means
 * there is 1 byte (of the total of 8 bytes) missing in src which is
 * needed to calculate the first ECC byte. Therefore the first byte of
 * dst MUST CONTAIN IT!
 *
 * The same problem exists for the end of the buffer where src may not
 * end exactly aligned, if this is the case dst must contain the
 * required bytes to calculate the last ECC byte - they should be in
 * dst where they would normally be found if src did contain those
 * bytes.
 *
 * @dst:		destination buffer with ECC
 * @src:		source buffer without ECC
 * @len:		number of bytes of data to copy (without ecc, length of src).
 * @alignment:	The number of bytes 'missing' from the start of src to
 * 				be struct ecc64 aligned
 *
 *       Note: dst must be big enough to hold ecc bytes as well.
 *                   Must be 8 byte aligned.
 *
 * @return:	success or failure
 *
 * @retval: 0 - success
 * @retfal: other - fail
 */

int memcpy_to_ecc_unaligned(struct ecc64 *dst, const beint64_t *src,
		uint64_t len, uint8_t alignment)
{
	struct ecc64 ecc_word;
	uint8_t bytes_wanted;
	int rc;

	bytes_wanted = BYTES_PER_ECC - alignment;

	/*
	 * Only actually do the first calculation if an alignment is
	 * required - otherwise jump straight to memcpy_to_ecc()
	 */
	if (alignment) {
		ecc_word.data = dst->data;
		memcpy(inc_uint64_by(&ecc_word.data, alignment), src, bytes_wanted);

		ecc_word.ecc = eccgenerate(be64_to_cpu(ecc_word.data));
		memcpy(dst, inc_ecc64_by(&ecc_word, alignment),
				sizeof(struct ecc64) - alignment);

		dst = inc_ecc64_by(dst, sizeof(struct ecc64) - alignment);
		src = inc_beint64_by(src, bytes_wanted);
		len -= bytes_wanted;
	}

	if (len >= BYTES_PER_ECC) {
		rc = memcpy_to_ecc(dst, src, whole_ecc_bytes(len));
		if (rc)
			return rc;

		/*
		 * It helps to let the compiler to the pointer arithmetic
		 * here, (dst and src are different types)
		 */
		dst += whole_ecc_structs(len);
		src += whole_ecc_structs(len);
		len -= whole_ecc_bytes(len);
	}

	if (len) {
		bytes_wanted = BYTES_PER_ECC - len;

		ecc_word.data = *src;
		memcpy(inc_uint64_by(&ecc_word.data, len), inc_ecc64_by(dst, len),
				bytes_wanted);
		ecc_word.ecc = eccgenerate(be64_to_cpu(ecc_word.data));

		*dst = ecc_word;
	}

	return 0;
}
