// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2020 IBM Corp. */
#define TPM_SKIBOOT
#include "secvar_common_test.c"
#include "../storage/secboot_tpm.c"
#include "../storage/fakenv_ops.c"
#include "../secvar_util.c"

char *secboot_buffer;

#define ARBITRARY_SECBOOT_SIZE 128000

const char *secvar_test_name = "secboot_tpm";

int flash_secboot_read(void *dst, uint32_t src, uint32_t len)
{
	memcpy(dst, secboot_buffer + src, len);
	return 0;
}

int flash_secboot_write(uint32_t dst, void *src, uint32_t len)
{
	memcpy(secboot_buffer + dst, src, len);
	return 0;
}

int flash_secboot_info(uint32_t *total_size)
{
	*total_size = ARBITRARY_SECBOOT_SIZE;
	return 0;
}

/* Toggle this to test the physical presence resetting */
bool phys_presence = false;
bool secvar_check_physical_presence(void)
{
	return phys_presence;
}

struct platform platform;

int run_test(void)
{
	int rc;
	struct secvar *tmp;

	secboot_buffer = zalloc(ARBITRARY_SECBOOT_SIZE);

	// Initialize and format the storage
	rc = secboot_tpm_store_init();
	ASSERT(OPAL_SUCCESS == rc);

	// Load the just-formatted empty section
	rc = secboot_tpm_load_bank(&variable_bank, SECVAR_VARIABLE_BANK);
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(0 == list_length(&variable_bank));

	// Add some test variables
	tmp = new_secvar("test", 5, "testdata", 8, 0);
	list_add_tail(&variable_bank, &tmp->link);

	tmp = new_secvar("foo", 3, "moredata", 8, 0);
	list_add_tail(&variable_bank, &tmp->link);

	// Add a priority variable, ensure that works
	tmp = new_secvar("priority", 9, "meep", 4, SECVAR_FLAG_PROTECTED);
	list_add_tail(&variable_bank, &tmp->link);

	// Add another one
	tmp = new_secvar("priority2", 9, "meep", 4, SECVAR_FLAG_PROTECTED);
	list_add_tail(&variable_bank, &tmp->link);

	ASSERT(4 == list_length(&variable_bank));

	// Write the bank
	rc = secboot_tpm_write_bank(&variable_bank, SECVAR_VARIABLE_BANK);
	ASSERT(OPAL_SUCCESS == rc);
	// should write to bank 1 first
	ASSERT(*((uint64_t*) secboot_image->bank[1]) != 0llu);
	ASSERT(*((uint64_t*) secboot_image->bank[0]) == 0llu);

	// Clear the variable list
	clear_bank_list(&variable_bank);
	ASSERT(0 == list_length(&variable_bank));

	// Load the bank
	rc = secboot_tpm_load_bank(&variable_bank, SECVAR_VARIABLE_BANK);
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(4 == list_length(&variable_bank));

	// Change a variable
	tmp = list_tail(&variable_bank, struct secvar, link);
	memcpy(tmp->data, "somethin", 8);

	// Write the bank
	rc = secboot_tpm_write_bank(&variable_bank, SECVAR_VARIABLE_BANK);
	ASSERT(OPAL_SUCCESS == rc);
	// should have data in both now
	ASSERT(*((uint64_t*) secboot_image->bank[0]) != 0llu);
	ASSERT(*((uint64_t*) secboot_image->bank[1]) != 0llu);

	clear_bank_list(&variable_bank);

	// Tamper with pnor, hash check should catch this
	secboot_image->bank[0][0] = ~secboot_image->bank[0][0];

	rc = secboot_tpm_load_bank(&variable_bank, SECVAR_VARIABLE_BANK);
	ASSERT(rc != OPAL_SUCCESS); // TODO: permission?

	// Fix it back...
	secboot_image->bank[0][0] = ~secboot_image->bank[0][0];

	// Should be ok again
	rc = secboot_tpm_load_bank(&variable_bank, SECVAR_VARIABLE_BANK);
	ASSERT(rc == OPAL_SUCCESS);

	clear_bank_list(&variable_bank);
	free(secboot_buffer);

	return 0;
}

int main(void)
{
	int rc = 0;

	list_head_init(&variable_bank);

	rc = run_test();

	if (rc)
		printf(COLOR_RED "FAILED" COLOR_RESET "\n");
	else
		printf(COLOR_GREEN "OK" COLOR_RESET "\n");

	free(tpmnv_vars_image);
	free(tpmnv_control_image);
	free(secboot_image);

	return rc;
}
