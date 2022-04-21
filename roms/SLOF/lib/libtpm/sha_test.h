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

#ifndef SHA_TEST_H
#define SHA_TEST_H

#include <stdio.h>

#include "helpers.h"

/* to avoid compilation issues do not include openssl/sha.h */
unsigned char *SHA1(const unsigned char *, size_t, unsigned char *);
unsigned char *SHA256(const unsigned char *, size_t, unsigned char *);
unsigned char *SHA384(const unsigned char *, size_t, unsigned char *);
unsigned char *SHA512(const unsigned char *, size_t, unsigned char *);

typedef void (*hashfunc)(const uint8_t *data, uint32_t length, uint8_t *hash);
typedef unsigned char *(*osslhashfunc)(const unsigned char *, size_t,
				       unsigned char *);

#define TESTVECTORS(NAME) \
char *NAME[] = {	\
	"",		\
	"abc",		\
	"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", \
	"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" \
};

static inline int
test_hash(hashfunc hf, uint8_t *hash, size_t hashlen,
	   const char *data, uint32_t length,
	   osslhashfunc osslhf)
{
	unsigned char expected[hashlen];
	int ret = 0;

	osslhf((const unsigned char *)data, length, expected);

	hf((uint8_t *)data, length, hash);
	if (!memcmp(hash, expected, hashlen)) {
		printf("PASS: input length: %u\n", length);
	} else {
		printf("FAIL data: %s\n", data);
		ret = 1;
	}

	return ret;
}

#endif /* SHA_TEST_H */
