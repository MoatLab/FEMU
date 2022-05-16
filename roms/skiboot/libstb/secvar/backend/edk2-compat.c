// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2020 IBM Corp. */
#ifndef pr_fmt
#define pr_fmt(fmt) "EDK2_COMPAT: " fmt
#endif

#include <opal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <skiboot.h>
#include <ccan/endian/endian.h>
#include <mbedtls/error.h>
#include "libstb/crypto/pkcs7/pkcs7.h"
#include "edk2.h"
#include "../secvar.h"
#include "edk2-compat-process.h"
#include "edk2-compat-reset.h"

struct list_head staging_bank;

/*
 * Initializes supported variables as empty if not loaded from
 * storage. Variables are initialized as volatile if not found.
 * Updates should clear this flag.
 * Returns OPAL Error if anything fails in initialization
 */
static int edk2_compat_pre_process(struct list_head *variable_bank,
				   struct list_head *update_bank __unused)
{
	struct secvar *pkvar;
	struct secvar *kekvar;
	struct secvar *dbvar;
	struct secvar *dbxvar;
	struct secvar *tsvar;

	pkvar = find_secvar("PK", 3, variable_bank);
	if (!pkvar) {
		pkvar = new_secvar("PK", 3, NULL, 0, SECVAR_FLAG_VOLATILE
				| SECVAR_FLAG_PROTECTED);
		if (!pkvar)
			return OPAL_NO_MEM;

		list_add_tail(variable_bank, &pkvar->link);
	}
	if (pkvar->data_size == 0)
		setup_mode = true;
	else
		setup_mode = false;

	kekvar = find_secvar("KEK", 4, variable_bank);
	if (!kekvar) {
		kekvar = new_secvar("KEK", 4, NULL, 0, SECVAR_FLAG_VOLATILE);
		if (!kekvar)
			return OPAL_NO_MEM;

		list_add_tail(variable_bank, &kekvar->link);
	}

	dbvar = find_secvar("db", 3, variable_bank);
	if (!dbvar) {
		dbvar = new_secvar("db", 3, NULL, 0, SECVAR_FLAG_VOLATILE);
		if (!dbvar)
			return OPAL_NO_MEM;

		list_add_tail(variable_bank, &dbvar->link);
	}

	dbxvar = find_secvar("dbx", 4, variable_bank);
	if (!dbxvar) {
		dbxvar = new_secvar("dbx", 4, NULL, 0, SECVAR_FLAG_VOLATILE);
		if (!dbxvar)
			return OPAL_NO_MEM;

		list_add_tail(variable_bank, &dbxvar->link);
	}

	/*
	 * Should only ever happen on first boot. Timestamp is
	 * initialized with all zeroes.
	 */
	tsvar = find_secvar("TS", 3, variable_bank);
	if (!tsvar) {
		tsvar = alloc_secvar(3, sizeof(struct efi_time) * 4);
		if (!tsvar)
			return OPAL_NO_MEM;

		memcpy(tsvar->key, "TS", 3);
		tsvar->key_len = 3;
		tsvar->data_size = sizeof(struct efi_time) * 4;
		memset(tsvar->data, 0, tsvar->data_size);
		list_add_tail(variable_bank, &tsvar->link);
	}

	return OPAL_SUCCESS;
};

static int edk2_compat_process(struct list_head *variable_bank,
			       struct list_head *update_bank)
{
	struct secvar *var = NULL;
	struct secvar *tsvar = NULL;
	struct efi_time timestamp;
	char *newesl = NULL;
	int neweslsize;
	int rc = 0;

	prlog(PR_INFO, "Setup mode = %d\n", setup_mode);

	/* Check HW-KEY-HASH */
	if (!setup_mode) {
		rc = verify_hw_key_hash();
		if (rc != OPAL_SUCCESS) {
			prlog(PR_ERR, "Hardware key hash verification mismatch. Keystore and update queue is reset.\n");
			rc = reset_keystore(variable_bank);
			if (rc)
				goto cleanup;
			setup_mode = true;
			goto cleanup;
		}
	}

	/* Return early if we have no updates to process */
	if (list_empty(update_bank)) {
		return OPAL_EMPTY;
	}

	/*
	 * Make a working copy of variable bank that is updated
	 * during process
	 */
	list_head_init(&staging_bank);
	copy_bank_list(&staging_bank, variable_bank);

	/*
	 * Loop through each command in the update bank.
	 * If any command fails, it just loops out of the update bank.
	 * It should also clear the update bank.
	 */

	/* Read the TS variable first time and then keep updating it in-memory */
	tsvar = find_secvar("TS", 3, &staging_bank);

	/*
	 * We cannot find timestamp variable, did someone tamper it ?, return
	 * OPAL_PERMISSION
	 */
	if (!tsvar)
		return OPAL_PERMISSION;

	list_for_each(update_bank, var, link) {

		/*
		 * Submitted data is auth_2 descriptor + new ESL data
		 * Extract the auth_2 2 descriptor
		 */
		prlog(PR_INFO, "Update for %s\n", var->key);

		rc = process_update(var, &newesl,
				    &neweslsize, &timestamp,
				    &staging_bank,
				    tsvar->data);
		if (rc) {
			prlog(PR_ERR, "Update processing failed with rc %04x\n", rc);
			break;
		}

		/*
		 * If reached here means, signature is verified so update the
		 * value in the variable bank
		 */
		rc = update_variable_in_bank(var,
					     newesl,
					     neweslsize,
					     &staging_bank);
		if (rc) {
			prlog(PR_ERR, "Updating the variable data failed %04x\n", rc);
			break;
		}

		free(newesl);
		newesl = NULL;
		/* Update the TS variable with the new timestamp */
		rc = update_timestamp(var->key,
				      &timestamp,
				      tsvar->data);
		if (rc) {
			prlog (PR_ERR, "Variable updated, but timestamp updated failed %04x\n", rc);
			break;
		}

		/*
		 * If the PK is updated, update the secure boot state of the
		 * system at the end of processing
		 */
		if (key_equals(var->key, "PK")) {
			/*
			 * PK is tied to a particular firmware image by mapping it with
			 * hw-key-hash of that firmware. When PK is updated, hw-key-hash
			 * is updated. And when PK is deleted, delete hw-key-hash as well
			 */
			if(neweslsize == 0) {
				setup_mode = true;
				delete_hw_key_hash(&staging_bank);
			} else  {
				setup_mode = false;
				add_hw_key_hash(&staging_bank);
			}
			prlog(PR_DEBUG, "setup mode is %d\n", setup_mode);
		}
	}

	if (rc == 0) {
		/* Update the variable bank with updated working copy */
		clear_bank_list(variable_bank);
		copy_bank_list(variable_bank, &staging_bank);
	}

	free(newesl);
	clear_bank_list(&staging_bank);

	/* Set the global variable setup_mode as per final contents in variable_bank */
	var = find_secvar("PK", 3, variable_bank);
	if (!var) {
		/* This should not happen */
		rc = OPAL_INTERNAL_ERROR;
		goto cleanup;
	}

	if (var->data_size == 0)
		setup_mode = true;
	else
		setup_mode = false;

cleanup:
	/*
	 * For any failure in processing update queue, we clear the update bank
	 * and return failure
	 */
	clear_bank_list(update_bank);

	return rc;
}

static int edk2_compat_post_process(struct list_head *variable_bank,
				    struct list_head *update_bank __unused)
{
	struct secvar *hwvar;
	if (!setup_mode) {
		secvar_set_secure_mode();
		prlog(PR_INFO, "Enforcing OS secure mode\n");
		/*
		 * HW KEY HASH is no more needed after this point. It is already
		 * visible to userspace via device-tree, so exposing via sysfs is
		 * just a duplication. Remove it from in-memory copy.
		 */
		hwvar = find_secvar("HWKH", 5, variable_bank);
		if (!hwvar) {
			prlog(PR_ERR, "cannot find hw-key-hash, should not happen\n");
			return OPAL_INTERNAL_ERROR;
		}
		list_del(&hwvar->link);
		dealloc_secvar(hwvar);
	}

	return OPAL_SUCCESS;
}

static int edk2_compat_validate(struct secvar *var)
{

	/*
	 * Checks if the update is for supported
	 * Non-volatile secure variables
	 */
	if (!key_equals(var->key, "PK")
			&& !key_equals(var->key, "KEK")
			&& !key_equals(var->key, "db")
			&& !key_equals(var->key, "dbx"))
		return OPAL_PARAMETER;

	/* Check that signature type is PKCS7 */
	if (!is_pkcs7_sig_format(var->data))
		return OPAL_PARAMETER;

	return OPAL_SUCCESS;
};

struct secvar_backend_driver edk2_compatible_v1 = {
	.pre_process = edk2_compat_pre_process,
	.process = edk2_compat_process,
	.post_process = edk2_compat_post_process,
	.validate = edk2_compat_validate,
	.compatible = "ibm,edk2-compat-v1",
};
