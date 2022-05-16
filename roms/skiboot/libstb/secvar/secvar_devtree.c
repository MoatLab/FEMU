// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#include <device.h>
#include <string.h>
#include "secvar.h"
#include "secvar_devtree.h"

struct dt_node *secvar_node;

int secvar_set_secure_mode(void)
{
	struct dt_node *sb_root;
	struct dt_property *prop;

	if (!secvar_node)
		return -1;

	sb_root = dt_find_by_path(dt_root, "/ibm,secureboot/");

	prop = (struct dt_property *) dt_find_property(sb_root, "os-secureboot-enforcing");
	if (prop)
		return 0;

	prop = dt_add_property(sb_root, "os-secureboot-enforcing", NULL, 0);
	if (!prop)
		return -2;

	return 0;
}

void secvar_init_devnode(const char *compatible)
{
	struct dt_node *sb_root;

	sb_root = dt_find_by_path(dt_root, "/ibm,opal/");

	secvar_node = dt_new(sb_root, "secvar");

	dt_add_property_strings(secvar_node, "compatible", "ibm,secvar-backend", compatible);
	dt_add_property_string(secvar_node, "format", compatible);
	dt_add_property_u64(secvar_node, "max-var-size", secvar_storage.max_var_size);
	dt_add_property_u64(secvar_node, "max-var-key-len", SECVAR_MAX_KEY_LEN);
}

void secvar_set_status(const char *status)
{
	if (!secvar_node)
		return; // Fail boot?

	/* This function should only be called once */
	dt_add_property_string(secvar_node, "status", status);
}


void secvar_set_update_status(uint64_t val)
{
	if (!secvar_node)
		return;

	if (dt_find_property(secvar_node, "update-status"))
		return;

	dt_add_property_u64(secvar_node, "update-status", val);
}

bool secvar_check_physical_presence(void)
{
	struct dt_node *secureboot;

	secureboot = dt_find_by_path(dt_root, "ibm,secureboot");
	if (!secureboot)
		return false;

	if (dt_find_property(secureboot, "clear-os-keys")
			|| dt_find_property(secureboot, "clear-all-keys")
			|| dt_find_property(secureboot, "clear-mfg-keys"))
		return true;

	return false;
}
