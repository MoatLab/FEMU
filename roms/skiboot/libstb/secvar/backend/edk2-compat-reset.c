// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2020 IBM Corp. */
#include <opal.h>
#include <device.h>
#include "edk2-compat-process.h"
#include "edk2-compat-reset.h"
#include "../secvar.h"

int reset_keystore(struct list_head *bank)
{
	struct secvar *var;
	int rc = 0;

	var = find_secvar("PK", 3, bank);
	if (var)
		rc = update_variable_in_bank(var, NULL, 0, bank);
	if (rc)
		return rc;

	var = find_secvar("KEK", 4, bank);
	if (var)
		rc = update_variable_in_bank(var, NULL, 0, bank);
	if (rc)
		return rc;

	var = find_secvar("db", 3, bank);
	if (var)
		rc = update_variable_in_bank(var, NULL, 0, bank);
	if (rc)
		return rc;

	var = find_secvar("dbx", 4, bank);
	if (var)
		rc = update_variable_in_bank(var, NULL, 0, bank);
	if (rc)
		return rc;

	var = find_secvar("TS", 3, bank);
	if (var)
		rc = update_variable_in_bank(var, NULL, 0, bank);
	if (rc)
		return rc;

	var = find_secvar("HWKH", 5, bank);
	if (var)
		rc = update_variable_in_bank(var, NULL, 0, bank);

	return rc;
}


int add_hw_key_hash(struct list_head *bank)
{
	struct secvar *var;
	uint32_t hw_key_hash_size;
	const char *hw_key_hash;
	struct dt_node *secureboot;

	secureboot = dt_find_by_path(dt_root, "ibm,secureboot");
	if (!secureboot)
		return false;

	hw_key_hash_size = dt_prop_get_u32(secureboot, "hw-key-hash-size");

	hw_key_hash = dt_prop_get(secureboot, "hw-key-hash");

	if (!hw_key_hash)
		return OPAL_PERMISSION;

	var = new_secvar("HWKH", 5, hw_key_hash,
			hw_key_hash_size, SECVAR_FLAG_PROTECTED);
	list_add_tail(bank, &var->link);

	return OPAL_SUCCESS;
}

int delete_hw_key_hash(struct list_head *bank)
{
	struct secvar *var;

	var = find_secvar("HWKH", 5, bank);
	if (!var)
		return OPAL_SUCCESS;

	list_del(&var->link);
	dealloc_secvar(var);

	return OPAL_SUCCESS;
}

int verify_hw_key_hash(void)
{
	const char *hw_key_hash;
	struct dt_node *secureboot;
	struct secvar *var;

	secureboot = dt_find_by_path(dt_root, "ibm,secureboot");
	if (!secureboot)
		return OPAL_INTERNAL_ERROR;

	hw_key_hash = dt_prop_get(secureboot, "hw-key-hash");

	if (!hw_key_hash)
		return OPAL_INTERNAL_ERROR;

	/* This value is from the protected storage */
	var = find_secvar("HWKH", 5, &variable_bank);
	if (!var)
		return OPAL_PERMISSION;

	if (memcmp(hw_key_hash, var->data, var->data_size) != 0)
		return OPAL_PERMISSION;

	return OPAL_SUCCESS;
}

