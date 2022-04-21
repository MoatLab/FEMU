// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Default implementations
 *
 * Copyright 2015-2017 IBM Corp.
 */

#include <stdlib.h>
#include <libflash/blocklevel.h>
#include "arch_flash.h"

/*
 * This just assumes that an erase from zero to total size is
 * 'correct'.
 * An erase from zero to total size is the correct approach for
 * powerpc and x86. ARM has it own function which also includes a call
 * to the flash driver.
 */
int __attribute__((weak)) arch_flash_erase_chip(struct blocklevel_device *bl)
{
	int rc;
	uint64_t total_size;

	rc = blocklevel_get_info(bl, NULL, &total_size, NULL);
	if (rc)
		return rc;

	return blocklevel_erase(bl, 0, total_size);
}

int __attribute__((weak,const)) arch_flash_4b_mode(struct blocklevel_device *bl, int set_4b)
{
	(void)bl;
	(void)set_4b;
	return -1;
}

enum flash_access __attribute__((weak,const)) arch_flash_access(struct blocklevel_device *bl, enum flash_access access)
{
	(void)bl;
	(void)access;
	return ACCESS_INVAL;
}

int __attribute__((weak,const)) arch_flash_set_wrprotect(struct blocklevel_device *bl, int set)
{
	(void)bl;
	(void)set;
	return -1;
}
