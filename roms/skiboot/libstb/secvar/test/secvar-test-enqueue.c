// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2019 IBM Corp. */

#include "secvar_api_test.c"

const char *secvar_test_name = "enqueue";

// Stub storage function, enqueue only cares that this succeeds
static int temp_write_bank(struct list_head *bank, int section)
{
	(void) bank, (void) section;
	return OPAL_SUCCESS;
}

int run_test(void)
{
	int64_t rc;

	struct secvar *var;
	char key[1024] = {0};

	uint64_t data_size = 128;
	char *data = zalloc(data_size);

	secvar_storage.max_var_size = 1024;

	/*** Bad cases first this time ***/
	// No write bank hook set
	secvar_storage.write_bank = NULL;
	memcpy(key, "meow", 4); // ascii
	rc = secvar_enqueue(key, 4, data, data_size);
	ASSERT(rc == OPAL_HARDWARE);

	// Set a stub bank writer, so the rest runs ok
	secvar_storage.write_bank = temp_write_bank;

	// Parameter checks
	// null key
	rc = secvar_enqueue(NULL, 5, data, data_size);
	ASSERT(rc == OPAL_PARAMETER);
	ASSERT(list_empty(&update_bank));

	// key is empty
	memset(key, 0, sizeof(key));
	rc = secvar_enqueue(key, 5, data, data_size);
	ASSERT(rc == OPAL_PARAMETER);
	ASSERT(list_empty(&update_bank));

	// keylen is zero
	rc = secvar_enqueue(key, 0, data, data_size);
	ASSERT(rc == OPAL_PARAMETER);
	ASSERT(list_empty(&update_bank));

	// keylen is excessive
	rc = secvar_enqueue(key, 5000, data, data_size);
	ASSERT(rc == OPAL_PARAMETER);
	ASSERT(list_empty(&update_bank));

	// null data
	rc = secvar_enqueue(key, 5, NULL, data_size);
	ASSERT(rc == OPAL_PARAMETER);
	ASSERT(list_empty(&update_bank));

	// data_size is excessive
	rc = secvar_enqueue(key, 5, data, 50000);
	ASSERT(rc == OPAL_PARAMETER);
	ASSERT(list_empty(&update_bank));

	// data_size is zero
	rc = secvar_enqueue(key, 5, data, 0);
	ASSERT(rc == OPAL_PARAMETER);
	ASSERT(list_empty(&update_bank));

	// secvar is disabled
	secvar_enabled = 0;
	rc = secvar_enqueue(key, 5, data, data_size);
	ASSERT(rc == OPAL_UNSUPPORTED);
	secvar_enabled = 1;

	// secvar is not ready
	secvar_ready = 0;
	rc = secvar_enqueue(key, 5, data, data_size);
	ASSERT(rc == OPAL_RESOURCE);
	secvar_ready = 1;


	/*** Good cases ***/
	// TODO: add data?
	memcpy(key, "test", 4); // ascii
	rc = secvar_enqueue(key, 4, data, data_size);
	ASSERT(rc == OPAL_SUCCESS);
	ASSERT(list_length(&update_bank) == 1);

	memcpy(key, "f\0o\0o\0b\0a\0r\0", 6*2); // "unicode"
	rc = secvar_enqueue(key, 6*2, data, data_size);
	ASSERT(rc == OPAL_SUCCESS);
	ASSERT(list_length(&update_bank) == 2);

	memcpy(key, "meep", 4);
	rc = secvar_enqueue(key, 4, data, data_size);
	ASSERT(rc == OPAL_SUCCESS);
	ASSERT(list_length(&update_bank) == 3); // should not increase

	// Re-add the same variable
	memcpy(key, "meep", 4);
	rc = secvar_enqueue(key, 4, data, data_size);
	ASSERT(rc == OPAL_SUCCESS);
	ASSERT(list_length(&update_bank) == 3); // should not increase
	var = list_tail(&update_bank, struct secvar, link);
	ASSERT(!memcmp(var->key, key, 4))	// should be at end

	// Unstage the variable update
	rc = secvar_enqueue(key, 4, NULL, 0);
	ASSERT(rc == OPAL_SUCCESS);
	ASSERT(list_length(&update_bank) == 2);

	// Unstage a bogus variable update
	rc = secvar_enqueue("nada", 4, NULL, 0);
	ASSERT(rc == OPAL_EMPTY);
	ASSERT(list_length(&update_bank) == 2);


	// Empty the in-memory cache, and reload from "pnor"
	//   Removed to drop dependency on a storage backend
	//   Probably not actually necessary to test, that's the
	//   job of the storage backend tests
	/*
	clear_bank_list(&update_bank);
	ASSERT(list_empty(&update_bank));
	secvar_storage.load_bank(&update_bank, SECVAR_UPDATE_BANK);
	printf("list_length = %d\n", list_length(&update_bank));
	ASSERT(list_length(&update_bank) == 2);

	node = list_top(&update_bank, struct secvar_node, link);
	ASSERT(node);
	ASSERT(!memcmp(node->var->key, "test", 4));
	node = list_next(&update_bank, node, link);
	ASSERT(node);
	ASSERT(!memcmp(node->var->key, "f\0o\0o\0b\0a\0r\0", 6*2));
	*/

	/*** ONE more bad case... ***/

	free(data);

	return 0;

}
