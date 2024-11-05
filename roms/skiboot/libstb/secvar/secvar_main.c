// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2019 IBM Corp. */

#ifndef pr_fmt
#define pr_fmt(fmt) "SECVAR: " fmt
#endif

#include <stdlib.h>
#include <skiboot.h>
#include <opal.h>
#include <libstb/secureboot.h>
#include "secvar.h"
#include "secvar_devtree.h"

struct list_head variable_bank;
struct list_head update_bank;

int secvar_enabled = 0;	// Set to 1 if secvar is supported
int secvar_ready = 0;	// Set to 1 when base secvar inits correctly

// To be filled in by platform.secvar_init
struct secvar_storage_driver secvar_storage = {0};
struct secvar_backend_driver secvar_backend = {0};


int secvar_main(struct secvar_storage_driver storage_driver,
               struct secvar_backend_driver backend_driver)
{
	int rc = OPAL_UNSUPPORTED;

	prlog(PR_INFO, "Secure variables are supported, initializing secvar\n");

	secvar_storage = storage_driver;
	secvar_backend = backend_driver;

	secvar_init_devnode(secvar_backend.compatible);

	secvar_enabled = 1;

	list_head_init(&variable_bank);
	list_head_init(&update_bank);

	/*
	 * Failures here should indicate some kind of hardware problem,
	 * therefore we don't even attempt to continue
	 */
	rc = secvar_storage.store_init();
	if (rc)
		secureboot_enforce();

	rc = secvar_storage.load_bank(&variable_bank, SECVAR_VARIABLE_BANK);
	if (rc)
		goto fail;

	rc = secvar_storage.load_bank(&update_bank, SECVAR_UPDATE_BANK);
	if (rc)
		goto fail;

	/*
	 * At this point, base secvar is functional.
	 * In the event of some error, boot up to Petitboot in secure mode
	 * with an empty keyring, for an admin to attempt to debug.
	 */
	secvar_ready = 1;
	secvar_set_status("okay");

	if (secvar_backend.pre_process) {
		rc = secvar_backend.pre_process(&variable_bank, &update_bank);
		if (rc) {
			prlog(PR_ERR, "Error in backend pre_process = %d\n", rc);
			/* Early failure state, lock the storage */
			secvar_storage.lockdown();
			goto soft_fail;
		}
	}

	// Process is required, error if it doesn't exist
	if (!secvar_backend.process)
		goto soft_fail;

	/* Process variable updates from the update bank. */
	rc = secvar_backend.process(&variable_bank, &update_bank);

	/* Create and set the update-status device tree property */
	secvar_set_update_status(rc);

	/*
	 * Only write to the storage if we actually processed updates
	 * OPAL_EMPTY implies no updates were processed
	 * Refer to full table in doc/device-tree/ibm,opal/secvar.rst
	 */
	if (rc == OPAL_SUCCESS) {
		rc = secvar_storage.write_bank(&variable_bank, SECVAR_VARIABLE_BANK);
		if (rc)
			goto soft_fail;
	}
	/*
	 * Write (and probably clear) the update bank if .process() actually detected
	 * and handled updates in the update bank. Unlike above, this includes error
	 * cases, where the backend should probably be clearing the bank.
	 */
	if (rc != OPAL_EMPTY) {
		rc = secvar_storage.write_bank(&update_bank,
					       SECVAR_UPDATE_BANK);
		if (rc)
			goto soft_fail;
	}
	/* Unconditionally lock the storage at this point */
	secvar_storage.lockdown();

	if (secvar_backend.post_process) {
		rc = secvar_backend.post_process(&variable_bank, &update_bank);
		if (rc) {
			prlog(PR_ERR, "Error in backend post_process = %d\n", rc);
			goto soft_fail;
		}
	}

	prlog(PR_INFO, "secvar initialized successfully\n");

	return OPAL_SUCCESS;

fail:
	/* Early failure, base secvar support failed to initialize */
	secvar_set_status("fail");
	secvar_storage.lockdown();
	secvar_set_secure_mode();

	prerror("secvar failed to initialize, rc = %04x\n", rc);
	return rc;

soft_fail:
	/*
	 * Soft-failure, enforce secure boot with an empty keyring in
	 * bootloader for debug/recovery
	 */
	clear_bank_list(&variable_bank);
	clear_bank_list(&update_bank);
	secvar_storage.lockdown();
	secvar_set_secure_mode();

	prerror("secvar failed to initialize, rc = %04x\n", rc);
	return rc;
}
