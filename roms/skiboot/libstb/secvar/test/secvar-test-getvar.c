// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2019 IBM Corp. */

#include "secvar_api_test.c"

const char *secvar_test_name = "getvar";

// Run tests on the less obvious features of secvar_get
// Includes:
//  - Partial reads
//  - Size queries (NULL buffer)
//int run_test_helper(uint64_t bank_enum)
int run_test(void)
{
	int64_t rc;

	uint64_t size;
	char *temp = zalloc(100);
	char key[1024] = {0};

	struct secvar *var;
	size_t data_size = sizeof("foobar");
	char *data = zalloc(data_size);
	uint64_t key_len = 4;
	memcpy(data, "foobar", data_size);
	memcpy(key, "test", 4);

	// List should be empty at start
	rc = secvar_get(key, key_len, temp, &size);
	ASSERT(rc == OPAL_EMPTY);
	ASSERT(list_length(&variable_bank) == 0);

	// Manually add variables, and check get_variable call
	var = new_secvar(key, key_len, data, data_size, 0);
	list_add_tail(&variable_bank, &var->link);

	ASSERT(list_length(&variable_bank) == 1);

	// TEST ONLY DATA
	// Test actual variable get
	size = data_size;
	rc = secvar_get(key, key_len, temp, &size);
	ASSERT(rc == OPAL_SUCCESS);
	ASSERT(0 == memcmp("foobar", var->data, size));

	// Test buffer too small
	size = data_size / 2;
	memset(temp, 0, 100);
	rc = secvar_get(key, key_len, temp, &size);
	ASSERT(rc == OPAL_PARTIAL);

	size = 0;
	rc = secvar_get(key, key_len, temp, &size);
	ASSERT(rc == OPAL_PARTIAL);
	ASSERT(size == data_size);

	// Test size query w/ no data
	size = 0;
	rc = secvar_get(key, key_len, NULL, &size);
	ASSERT(rc == OPAL_SUCCESS);
	ASSERT(size == data_size);

	/**** Error/Bad param cases ****/
	// NULL key
	rc = secvar_get(NULL, key_len, data, &data_size);
	ASSERT(rc == OPAL_PARAMETER);
	// zero key_len
	rc = secvar_get(key, 0, data, &data_size);
	ASSERT(rc == OPAL_PARAMETER);
	// NULL size, valid data
	rc = secvar_get(key, key_len, data, NULL);
	ASSERT(rc == OPAL_PARAMETER);

	secvar_enabled = 0;
	rc = secvar_get(key, key_len, data, &data_size);
	ASSERT(rc == OPAL_UNSUPPORTED);
	secvar_enabled = 1;

	secvar_ready = 0;
	rc = secvar_get(key, key_len, data, &data_size);
	ASSERT(rc == OPAL_RESOURCE);
	secvar_ready = 1;

	free(data);
	free(temp);

	return 0;
}

