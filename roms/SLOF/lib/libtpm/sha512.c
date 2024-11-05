/*****************************************************************************
 * Copyright (c) 2021 IBM Corporation
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
 *  See: NIST standard for SHA-512 and SHA-384 in FIPS PUB 180-4 & RFC 6234
 */

#include "byteorder.h"
#include "sha.h"
#include "string.h"

typedef struct _sha512_ctx {
	uint64_t h[8];
} sha512_ctx;

#define rotr(VAL, N)				\
({						\
	uint64_t res;				\
	__asm__ (				\
		"rotrdi %0, %1, %2\n\t"		\
		: "=r" (res)			\
		: "r" (VAL), "i" (N)		\
	);					\
	res; 					\
})

static inline uint64_t Ch(uint64_t x, uint64_t y, uint64_t z)
{
	return (x & y) ^ ((x ^ 0xffffffffffffffffULL) & z);
}

static inline uint64_t Maj(uint64_t x, uint64_t y, uint64_t z)
{
	return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint64_t sum0(uint64_t x)
{
	return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39);
}

static inline uint64_t sum1(uint64_t x)
{
	return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41);
}

static inline uint64_t sigma0(uint64_t x)
{
	return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7);
}

static inline uint64_t sigma1(uint64_t x)
{
	return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6);
}

static void sha512_block(uint64_t *w, sha512_ctx *ctx)
{
	uint32_t t;
	uint64_t a, b, c, d, e, f, g, h;
	uint64_t T1, T2;

	/*
	 * FIPS 180-4 4.2.2: SHA512 Constants
	 */
	static const uint64_t sha_ko[80] = {
		0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
		0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
		0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
		0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
		0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
		0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
		0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
		0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
		0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
		0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
		0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
		0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
		0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
		0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
		0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
		0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
		0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
		0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
		0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
		0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
	};

	/*
	 * FIPS 180-4 6.4.2: step 1
	 *
	 *  0 <= i <= 15:
	 *    W(t) = M(t)
	 * 16 <= i <= 79:
	 *    W(t) = sigma1(W(t-2)) + W(t-7) + sigma0(W(t-15)) + W(t-16)
	 */

	/* w(0)..w(15) are in big endian format */
	for (t = 0; t <= 15; t++)
		w[t] = be64_to_cpu(w[t]);

	for (t = 16; t <= 79; t++)
		w[t] = sigma1(w[t-2]) + w[t-7] + sigma0(w[t-15]) + w[t-16];

	/*
	 * step 2: a = H0, b = H1, c = H2, d = H3, e = H4, f = H5, g = H6, h = H7
	 */
	a = ctx->h[0];
	b = ctx->h[1];
	c = ctx->h[2];
	d = ctx->h[3];
	e = ctx->h[4];
	f = ctx->h[5];
	g = ctx->h[6];
	h = ctx->h[7];

	/*
	 * step 3: For i = 0 to 79:
	 *    T1 = h + sum1(e) + Ch(e,f,g) + K(t) + W(t);
	 *    T2 = sum0(a) + Maj(a,b,c)
	 *    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a + T1 + T2
	 */
	for (t = 0; t <= 79; t++) {
		T1 = h + sum1(e) + Ch(e, f, g) + sha_ko[t] + w[t];
		T2 = sum0(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
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
	ctx->h[5] += f;
	ctx->h[6] += g;
	ctx->h[7] += h;
}

static void sha512_do(sha512_ctx *ctx, const uint8_t *data32, uint32_t length)
{
	uint32_t offset;
	uint16_t num;
	uint64_t bits = 0;
	uint64_t w[80];
	uint64_t tmp;

	/* treat data in 128-byte/1024 bit chunks */
	for (offset = 0; length - offset >= 128; offset += 128) {
		memcpy(w, data32 + offset, 128);
		sha512_block(w, ctx);
		bits += (128 * 8);
	}

	/* last block with less than 128 bytes */
	num = length - offset;
	bits += (num << 3);

	memcpy(w, data32 + offset, num);
	/*
	 * FIPS 180-4 5.1: Padding the Message
	 */
	((uint8_t *)w)[num] = 0x80;
	if (128 - (num + 1) > 0)
		memset( &((uint8_t *)w)[num + 1], 0, 128 - (num + 1));

	if (num >= 112) {
		/* cannot append number of bits here;
		 * need space for 128 bits (16 bytes)
		 */
		sha512_block((uint64_t *)w, ctx);
		memset(w, 0, 128);
	}

	/* write number of bits to end of the block; we write 64 bits */
	tmp = cpu_to_be64(bits);
	memcpy(&w[15], &tmp, 8);

	sha512_block(w, ctx);

	/* need to switch result's endianness */
	for (num = 0; num < 8; num++)
		ctx->h[num] = cpu_to_be64(ctx->h[num]);
}

void sha384(const uint8_t *data, uint32_t length, uint8_t *hash)
{
	sha512_ctx ctx = {
		.h = {
			/*
			 * FIPS 180-4: 6.2.1
			 *   -> 5.3.4: initial hash value
			 */
			0xcbbb9d5dc1059ed8,
			0x629a292a367cd507,
			0x9159015a3070dd17,
			0x152fecd8f70e5939,
			0x67332667ffc00b31,
			0x8eb44a8768581511,
			0xdb0c2e0d64f98fa7,
			0x47b5481dbefa4fa4
		}
	};

	sha512_do(&ctx, data, length);
	memcpy(hash, ctx.h, 384/8);
}

void sha512(const uint8_t *data, uint32_t length, uint8_t *hash)
{
	sha512_ctx ctx = {
		.h = {
			/*
			 * FIPS 180-4: 6.2.1
			 *   -> 5.3.5: initial hash value
			 */
			0x6a09e667f3bcc908,
			0xbb67ae8584caa73b,
			0x3c6ef372fe94f82b,
			0xa54ff53a5f1d36f1,
			0x510e527fade682d1,
			0x9b05688c2b3e6c1f,
			0x1f83d9abfb41bd6b,
			0x5be0cd19137e2179
		}
	};

	sha512_do(&ctx, data, length);
	memcpy(hash, ctx.h, sizeof(ctx.h));
}


#ifdef MAIN

#include "sha_test.h"

int main(void)
{
	TESTVECTORS(data);
	uint8_t hash512[64];
	uint8_t hash384[48];
	char input[128];
	int err = 0;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(data); i++) {
		err |= test_hash(sha384, hash384, sizeof(hash384),
				 data[i], strlen(data[i]),
				 SHA384);
		err |= test_hash(sha512, hash512, sizeof(hash512),
				 data[i], strlen(data[i]),
				 SHA512);
	}

	memset(input, 'a', sizeof(input));
	/* cover critical input size around 112 bytes */
	for (i = 110; i < sizeof(input); i++) {
		err |= test_hash(sha384, hash384, sizeof(hash384),
				 input, i, SHA384);
		err |= test_hash(sha512, hash512, sizeof(hash512),
				 input, i, SHA512);
	}

	return err;
}
#endif
