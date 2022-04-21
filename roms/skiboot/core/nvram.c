// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * NVRAM support
 *
 * Copyright 2013-2018 IBM Corp.
 */

#include <skiboot.h>
#include <fsp.h>
#include <opal.h>
#include <lock.h>
#include <device.h>
#include <platform.h>
#include <nvram.h>
#include <timebase.h>

static void *nvram_image;
static uint32_t nvram_size;

static bool nvram_ready; /* has the nvram been loaded? */
static bool nvram_valid; /* is the nvram format ok? */

static int64_t opal_read_nvram(uint64_t buffer, uint64_t size, uint64_t offset)
{
	if (!nvram_ready)
		return OPAL_HARDWARE;

	if (!opal_addr_valid((void *)buffer))
		return OPAL_PARAMETER;

	if (offset >= nvram_size || (offset + size) > nvram_size)
		return OPAL_PARAMETER;

	memcpy((void *)buffer, nvram_image + offset, size);
	return OPAL_SUCCESS;
}
opal_call(OPAL_READ_NVRAM, opal_read_nvram, 3);

static int64_t opal_write_nvram(uint64_t buffer, uint64_t size, uint64_t offset)
{
	if (!nvram_ready)
		return OPAL_HARDWARE;

	if (!opal_addr_valid((void *)buffer))
		return OPAL_PARAMETER;

	if (offset >= nvram_size || (offset + size) > nvram_size)
		return OPAL_PARAMETER;
	memcpy(nvram_image + offset, (void *)buffer, size);
	if (platform.nvram_write)
		platform.nvram_write(offset, nvram_image + offset, size);

	/* The host OS has written to the NVRAM so we can't be sure that it's
	 * well formatted.
	 */
	nvram_valid = false;

	return OPAL_SUCCESS;
}
opal_call(OPAL_WRITE_NVRAM, opal_write_nvram, 3);

bool nvram_validate(void)
{
	if (!nvram_valid) {
		if (!nvram_check(nvram_image, nvram_size))
			nvram_valid = true;
	}

	return nvram_valid;
}

static void nvram_reformat(void)
{
	if (nvram_format(nvram_image, nvram_size)) {
		prerror("NVRAM: Failed to format NVRAM!\n");
		nvram_valid = false;
		return;
	}

	/* Write the whole thing back */
	if (platform.nvram_write)
		platform.nvram_write(0, nvram_image, nvram_size);

	nvram_validate();
}

void nvram_reinit(void)
{
	/* It's possible we failed to load nvram at boot. */
	if (!nvram_ready)
		nvram_init();
	else if (!nvram_validate())
		nvram_reformat();
}

void nvram_read_complete(bool success)
{
	struct dt_node *np;

	/* Read not successful, error out and free the buffer */
	if (!success) {
		free(nvram_image);
		nvram_size = 0;
		return;
	}

	if (!nvram_validate())
		nvram_reformat();

	/* Add nvram node */
	np = dt_new(opal_node, "nvram");
	dt_add_property_cells(np, "#bytes", nvram_size);
	dt_add_property_string(np, "compatible", "ibm,opal-nvram");

	/* Mark ready */
	nvram_ready = true;
}

bool nvram_wait_for_load(void)
{
	uint64_t started;

	/* Short cut */
	if (nvram_ready)
		return true;

	/* Tell the caller it will never happen */
	if (!platform.nvram_info)
		return false;

	/*
	 * One of two things has happened here.
	 * 1. nvram_wait_for_load() was called before nvram_init()
	 * 2. The read of NVRAM failed.
	 * Either way, this is quite a bad event.
	 */
	if (!nvram_image && !nvram_size) {
		prlog(PR_CRIT, "NVRAM: Possible wait before nvram_init()!\n");
		return false;
	}

	started = mftb();

	while (!nvram_ready) {
		opal_run_pollers();
		/* If the read fails, tell the caller */
		if (!nvram_image && !nvram_size)
			return false;
	}

	prlog(PR_DEBUG, "NVRAM: Waited %lums for nvram to load\n",
		tb_to_msecs(mftb() - started));

	return true;
}

bool nvram_has_loaded(void)
{
	return nvram_ready;
}

void nvram_init(void)
{
	int rc;

	if (!platform.nvram_info)
		return;
	rc = platform.nvram_info(&nvram_size);
	if (rc) {
		prerror("NVRAM: Error %d retrieving nvram info\n", rc);
		return;
	}
	prlog(PR_INFO, "NVRAM: Size is %d KB\n", nvram_size >> 10);
	if (nvram_size > 0x100000) {
		prlog(PR_WARNING, "NVRAM: Cropping to 1MB !\n");
		nvram_size = 0x100000;
	}

	/*
	 * We allocate the nvram image with 4k alignment to make the
	 * FSP backend job's easier
	 */
	nvram_image = memalign(0x1000, nvram_size);
	if (!nvram_image) {
		prerror("NVRAM: Failed to allocate nvram image\n");
		nvram_size = 0;
		return;
	}

	/* Read it in */
	rc = platform.nvram_start_read(nvram_image, 0, nvram_size);
	if (rc) {
		prerror("NVRAM: Failed to read NVRAM from FSP !\n");
		nvram_size = 0;
		free(nvram_image);
		return;
	}

	/*
	 * We'll get called back later (or recursively from
	 * nvram_start_read) in nvram_read_complete()
	 */
}
