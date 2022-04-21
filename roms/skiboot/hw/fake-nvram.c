// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2017 IBM Corp. */

#include <skiboot.h>
#include <opal.h>
#include <mem_region.h>
#include <lock.h>

static struct mem_region *nvram_region;
static struct lock fake_nvram_lock = LOCK_UNLOCKED;

int fake_nvram_info(uint32_t *total_size)
{
	nvram_region = find_mem_region("ibm,fake-nvram");

	if (!nvram_region)
		return OPAL_HARDWARE;

	*total_size = nvram_region->len;

	return OPAL_SUCCESS;
}

int fake_nvram_start_read(void *dst, uint32_t src, uint32_t len)
{
	if (!nvram_region)
		return -ENODEV;

	lock(&fake_nvram_lock);
	memcpy(dst, (void *) (nvram_region->start + src), len);
	unlock(&fake_nvram_lock);

	nvram_read_complete(true);

	return 0;
}

int fake_nvram_write(uint32_t offset, void *src, uint32_t size)
{
	if (!nvram_region)
		return OPAL_HARDWARE;

	lock(&fake_nvram_lock);
	memcpy((void *) (nvram_region->start + offset), src, size);
	unlock(&fake_nvram_lock);

	return 0;
}

