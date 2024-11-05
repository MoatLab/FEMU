// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2017 IBM Corp. */

#include <skiboot.h>
#include <vpd.h>
#include <string.h>
#include <device.h>

static const struct machine_info machine_table[] = {
	{"8247-21L", "IBM Power System S812L"},
	{"8247-22L", "IBM Power System S822L"},
	{"8247-24L", "IBM Power System S824L"},
	{"8286-41A", "IBM Power System S814"},
	{"8286-22A", "IBM Power System S822"},
	{"8286-42A", "IBM Power System S824"},
};

const struct machine_info *machine_info_lookup(const char *mtm)
{
	int i;
	for(i = 0; i < ARRAY_SIZE(machine_table); i++)
		if (!strcmp(machine_table[i].mtm, mtm))
			return &machine_table[i];
	return NULL;
}
