// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2019 IBM Corp. */

#ifndef _SECVAR_DRIVER_
#define _SECVAR_DRIVER_

#include <stdint.h>

struct secvar;

struct secvar_storage_driver {
	int (*load_bank)(struct list_head *bank, int section);
	int (*write_bank)(struct list_head *bank, int section);
	int (*store_init)(void);
	void (*lockdown)(void);
	uint64_t max_var_size;
};

struct secvar_backend_driver {
	/* Perform any pre-processing stuff (e.g. determine secure boot state) */
	int (*pre_process)(struct list_head *variable_bank,
			   struct list_head *update_bank);

	/* Process all updates */
	int (*process)(struct list_head *variable_bank,
		       struct list_head *update_bank);

	/* Perform any post-processing stuff (e.g. derive/update variables)*/
	int (*post_process)(struct list_head *variable_bank,
			    struct list_head *update_bank);

	/* Validate a single variable, return boolean */
	int (*validate)(struct secvar *var);

	/* String to use for compatible in secvar node */
	const char *compatible;
};

extern struct secvar_storage_driver secboot_tpm_driver;
extern struct secvar_backend_driver edk2_compatible_v1;

int secvar_main(struct secvar_storage_driver, struct secvar_backend_driver);

#endif
