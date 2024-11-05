// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2016 IBM Corp. */

#include <config.h>

#include "../container.c"

#include <assert.h>

int main(void)
{
	ROM_container_raw *c = malloc(SECURE_BOOT_HEADERS_SIZE);
	assert(stb_is_container(NULL, 0) == false);
	assert(stb_is_container(NULL, SECURE_BOOT_HEADERS_SIZE) == false);
	c->magic_number = cpu_to_be32(ROM_MAGIC_NUMBER + 1);
	assert(stb_is_container(c, SECURE_BOOT_HEADERS_SIZE) == false);
	c->magic_number = cpu_to_be32(ROM_MAGIC_NUMBER);
	assert(stb_is_container(c, SECURE_BOOT_HEADERS_SIZE) == true);

	return 0;
}
