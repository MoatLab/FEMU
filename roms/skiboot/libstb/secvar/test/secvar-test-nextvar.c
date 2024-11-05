// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2019 IBM Corp. */

#include "secvar_api_test.c"

const char *secvar_test_name = "nextvar";

int run_test(void)
{
	int64_t rc;

	struct secvar *tmpvar;

	char key[1024] = {0};
	uint64_t key_len = 16;

	// Load up the bank with some variables.
	// If these fail, we have bigger issues.
	ASSERT(list_length(&variable_bank) == 0);
	tmpvar = new_secvar("test1", 6, NULL, 0, 0);
	list_add_tail(&variable_bank, &tmpvar->link);
	ASSERT(list_length(&variable_bank) == 1);

	tmpvar = new_secvar("test2", 5, NULL, 0, 0);  // ascii w/o null
	list_add_tail(&variable_bank, &tmpvar->link);
	ASSERT(list_length(&variable_bank) == 2);

	tmpvar = new_secvar((const char*) L"test3", 5*2, NULL, 0, 0); // wide char "unicode"
	list_add_tail(&variable_bank, &tmpvar->link);
	ASSERT(list_length(&variable_bank) == 3);

	// Test sequential nexts
	// first item
	memset(key, 0, sizeof(key));
	key_len = 0;
	rc = secvar_get_next(key, &key_len, sizeof(key));
	ASSERT(rc == OPAL_SUCCESS);
	ASSERT(key_len == 6);
	ASSERT(!memcmp(key, "test1", key_len));

	// second item
	rc = secvar_get_next(key, &key_len, sizeof(key));
	ASSERT(rc == OPAL_SUCCESS);
	ASSERT(key_len == 5);
	ASSERT(!memcmp(key, "test2", key_len));

	// last item
	rc = secvar_get_next(key, &key_len, sizeof(key));
	ASSERT(rc == OPAL_SUCCESS);
	ASSERT(key_len == 5*2);
	ASSERT(!memcmp(key, L"test3", key_len));

	// end-of-list
	rc = secvar_get_next(key, &key_len, sizeof(key));
	ASSERT(rc == OPAL_EMPTY);


	memset(key, 0, sizeof(key));
	/*** Time for a break to test bad parameters ***/
	// null key
	rc = secvar_get_next(NULL, &key_len, 1024);
	ASSERT(rc == OPAL_PARAMETER);
	// Size too small
	key_len = 0;
	rc = secvar_get_next(key, &key_len, 1);
	ASSERT(rc == OPAL_PARTIAL);
	ASSERT(key_len == 6);
	// Supplied key length is larger than the buffer
	key_len = 6;
	rc = secvar_get_next(key, &key_len, 1);
	ASSERT(rc == OPAL_PARAMETER);

	// NULL key_len pointer
	rc = secvar_get_next(key, NULL, 1024);
	ASSERT(rc == OPAL_PARAMETER);

	// NULL key_len pointer
	key_len = ~0;
	rc = secvar_get_next(key, &key_len, 1024);
	ASSERT(rc == OPAL_PARAMETER);

	// zero key_len
	key_len = 0;
	rc = secvar_get_next(key, &key_len, 0);
	ASSERT(rc == OPAL_PARAMETER);

	// Non-existing previous variable
	key_len = 1024;
	memcpy(key, L"foobar", 7*2);
	rc = secvar_get_next(key, &key_len, 1024);
	ASSERT(rc == OPAL_PARAMETER);

	secvar_enabled = 0;
	rc = secvar_get_next(key, &key_len, 1024);
	ASSERT(rc == OPAL_UNSUPPORTED);
	secvar_enabled = 1;

	secvar_ready = 0;
	rc = secvar_get_next(key, &key_len, 1024);
	ASSERT(rc == OPAL_RESOURCE);
	secvar_ready = 1;

	clear_bank_list(&variable_bank);

	return 0;
}
