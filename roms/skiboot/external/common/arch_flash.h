// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2015 IBM Corp.
 */

#ifndef __EXTERNAL_ARCH_FLASH_H
#define __EXTERNAL_ARCH_FLASH_H

#include <getopt.h>
#include <libflash/blocklevel.h>

enum flash_access {
	PNOR_DIRECT,
	PNOR_MTD,
	BMC_DIRECT,
	BMC_MTD,
	ACCESS_INVAL
};

int arch_flash_init(struct blocklevel_device **bl, const char *file,
		bool keep_alive);

void arch_flash_close(struct blocklevel_device *bl, const char *file);

/* Low level functions that an architecture may support */

/*
 * If called BEFORE init, then this dictates how the flash will be
 * accessed.
 * If called AFTER init, then this returns how the flash is being accessed.
 */
enum flash_access arch_flash_access(struct blocklevel_device *bl,
		enum flash_access access);

int arch_flash_erase_chip(struct blocklevel_device *bl);
int arch_flash_4b_mode(struct blocklevel_device *bl, int set_4b);
int arch_flash_set_wrprotect(struct blocklevel_device *bl, int set);

#endif /* __EXTERNAL_ARCH_FLASH_H */
