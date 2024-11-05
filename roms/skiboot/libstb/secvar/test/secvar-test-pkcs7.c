// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2021 IBM Corp. */

#define MBEDTLS_PKCS7_C
#include "secvar_common_test.c"
#include "../../crypto/pkcs7/pkcs7.c"

const char *secvar_test_name = "pkcs7";

int run_test()
{
	const unsigned char underrun_p7s[] = {0x30, 0x48};
	mbedtls_pkcs7 pkcs7;
	unsigned char *data;
	int rc;

	mbedtls_pkcs7_init(&pkcs7);
	/* The data must live in the heap, not the stack, for valgrind to
	   catch the overread. */
	data = malloc(sizeof(underrun_p7s));
	memcpy(data, underrun_p7s, sizeof(underrun_p7s));
	rc = mbedtls_pkcs7_parse_der(data, sizeof(underrun_p7s), &pkcs7);
	free(data);
	ASSERT(0 > rc);

	return 0;
}

int main(void)
{
	return run_test();
}
