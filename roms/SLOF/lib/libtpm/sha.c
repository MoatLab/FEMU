/*****************************************************************************
 * Copyright (c) 2015-2021 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

/*
 *  See: NIST standard for SHA-1 in FIPS PUB 180-4
 */

#include "byteorder.h"
#include "sha.h"
#include "string.h"

typedef struct _sha1_ctx {
	uint32_t h[5];
} sha1_ctx;

#define rol(VAL, N)				\
({						\
	uint32_t res;				\
	__asm__ (				\
		"rotlwi %0, %1, %2\n\t"		\
		: "=r" (res)			\
		: "r" (VAL), "i" (N)		\
	);					\
	res; 					\
})

static void sha1_block(uint32_t *w, sha1_ctx *ctx)
{
	uint32_t i;
	uint32_t a,b,c,d,e,f;
	uint32_t tmp;
	uint32_t idx;

	/*
	 * FIPS 180-4 4.2.1: SHA1 Constants
	 */
	static const uint32_t sha_ko[4] = {
		0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
	};

	/*
	 * FIPS 180-4 6.1.2: step 1
	 *
	 *  0 <= i <= 15:
	 *    W(t) = M(t)
	 * 16 <= i <= 79:
	 *    W(t) = ROTL(W(t-3) XOR W(t-8) XOR W(t-14) XOR W(t-16), 1)
	 */

	/* w(0)..w(15) are in big endian format */
	for (i = 0; i <= 15; i++)
		w[i] = be32_to_cpu(w[i]);

	for (i = 16; i <= 79; i++) {
		tmp = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
		w[i] = rol(tmp, 1);
	}

	/*
	 * step 2: a = H0, b = H1, c = H2, d = H3, e = H4.
	 */
	a = ctx->h[0];
	b = ctx->h[1];
	c = ctx->h[2];
	d = ctx->h[3];
	e = ctx->h[4];

	/*
	 * step 3: For i = 0 to 79:
	 *    T = ROTL(a, 5) + f(i; b,c,d) + e + W(t) + K(t);
	 */
	for (i = 0; i <= 79; i++) {
		/*
		 * FIPS 180-4: 4.1.1 : definition of f(i; b,c,d)
		 */
		if (i <= 19) {
			/*
			 *  0 <= i <= 19:
			 *      f(i; b,c,d) = (b AND c) OR ((NOT b) AND d)
			 */
			f = (b & c) | ((b ^ 0xffffffff) & d);
			idx = 0;
		} else if (i <= 39) {
			/*
			 *  20 <= i <= 39:
			 *       f(i; b,c,d) = b XOR c XOR d
			 */
			f = b ^ c ^ d;
			idx = 1;
		} else if (i <= 59) {
			/*
			 * 40 <= i <= 59:
			 *      f(i; b,c,d) = (b AND c) OR (b AND d) OR (c AND d)
			 */
			f = (b & c) | (b & d) | (c & d);
			idx = 2;
		} else {
			/*
			 * 60 <= i <= 79:
			 *      f(i; b,c,d) = b XOR c XOR d
			 */
			f = b ^ c ^ d;
			idx = 3;
		}

		/*
		 * step 3:
		 *    t = ROTL(a, 5) + f(t;b,c,d) + e + K(t) + W(t);
		 *    e = d;  d = c;  c = ROTL(b, 30);  b = a; a = t;
		 */
		tmp = rol(a, 5) +
		      f +
		      e +
		      sha_ko[idx] +
		      w[i];
		e = d;
		d = c;
		c = rol(b, 30);
		b = a;
		a = tmp;
	}

	/*
	 * step 4:
	 *    H0 = a + H0, H1 = b + H1, H2 = c + H2, H3 = d + H3, H4 = e + H4
	 */
	ctx->h[0] += a;
	ctx->h[1] += b;
	ctx->h[2] += c;
	ctx->h[3] += d;
	ctx->h[4] += e;
}

static void sha1_do(sha1_ctx *ctx, const uint8_t *data32, uint32_t length)
{
	uint32_t offset = 0;
	uint16_t num;
	uint64_t bits = 0;
	uint32_t w[80];
	uint64_t tmp;

	/* treat data in 64-byte chunks */
	for (offset = 0; length - offset >= 64; offset += 64) {
		memcpy(w, data32 + offset, 64);
		sha1_block((uint32_t *)w, ctx);
		bits += (64 * 8);
	}

	/* last block with less than 64 bytes */
	num = length - offset;
	bits += (num << 3);

	memcpy(w, data32 + offset, num);
	/*
	 * FIPS 180-4 5.1: Padding the Message
	 */
	((uint8_t *)w)[num] = 0x80;
	if (64 - (num + 1) > 0)
		memset( &((uint8_t *)w)[num + 1], 0, 64 - (num + 1));

	if (num >= 56) {
		/* cannot append number of bits here */
		sha1_block((uint32_t *)w, ctx);
		memset(w, 0, 60);
	}

	/* write number of bits to end of block */
	tmp = cpu_to_be64(bits);
	memcpy(&w[14], &tmp, 8);

	sha1_block(w, ctx);

	/* need to switch result's endianness */
	for (num = 0; num < 5; num++)
		ctx->h[num] = cpu_to_be32(ctx->h[num]);
}

void sha1(const uint8_t *data, uint32_t length, uint8_t *hash)
{
	sha1_ctx ctx = {
		.h = {
			/*
			 * FIPS 180-4: 6.1.1
			 *   -> 5.3.1: initial hash value
			 */
			0x67452301,
			0xefcdab89,
			0x98badcfe,
			0x10325476,
			0xc3d2e1f0,
		}
	};

	sha1_do(&ctx, data, length);
	memcpy(hash, &ctx.h[0], 20);
}

#ifdef MAIN

#include "sha_test.h"

int main(void)
{
	TESTVECTORS(data);
	uint8_t hash[20];
	char input[64];
	int err = 0;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(data); i++)
		err |= test_hash(sha1, hash, sizeof(hash),
				 data[i], strlen(data[i]),
				 SHA1);

	memset(input, 'a', sizeof(input));
	/* cover critical input size around 56 bytes */
	for (i = 50; i < sizeof(input); i++)
		err |= test_hash(sha1, hash, sizeof(hash),
				 input, i, SHA1);

	return err;
}
#endif
