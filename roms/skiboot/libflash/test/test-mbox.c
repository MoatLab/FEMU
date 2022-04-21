// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2017-2018 IBM Corp. */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

#include <libflash/libflash.h>
#include <libflash/libflash-priv.h>

#include "stubs.h"
#include "mbox-server.h"

#define zalloc(n) calloc(1, n)
#define __unused          __attribute__((unused))

#undef pr_fmt

void mbox_init(void)
{
}

#include "../libflash.c"
#include "../mbox-flash.c"
#include "../ecc.c"
#include "../blocklevel.c"

#undef pr_fmt
#define pr_fmt(fmt) "MBOX-PROXY: " fmt

/* client interface */

#include "../../include/lpc-mbox.h"

#define ERR(...) FL_DBG(__VA_ARGS__)

static int run_flash_test(struct blocklevel_device *bl)
{
	struct mbox_flash_data *mbox_flash;
	char hello[] = "Hello World";
	uint32_t erase_granule;
	uint64_t total_size;
	const char *name;
	uint16_t *test;
	char *tmp;
	int i, rc;

	mbox_flash = container_of(bl, struct mbox_flash_data, bl);

	/*
	 * Do something first so that if it has been reset it does that
	 * before we check versions
	 */
	rc = blocklevel_get_info(bl, &name, &total_size, &erase_granule);
	if (rc) {
		ERR("blocklevel_get_info() failed with err %d\n", rc);
		return 1;
	}
	if (total_size != mbox_server_total_size()) {
		ERR("Total flash size is incorrect: 0x%08lx vs 0x%08x\n",
				total_size, mbox_server_total_size());
		return 1;
	}
	if (erase_granule != mbox_server_erase_granule()) {
		ERR("Erase granule is incorrect 0x%08x vs 0x%08x\n",
				erase_granule, mbox_server_erase_granule());
		return 1;
	}


	/* Sanity check that mbox_flash has inited correctly */
	if (mbox_flash->version != mbox_server_version()) {
		ERR("MBOX Flash didn't agree with the server version\n");
		return 1;
	}
	if (mbox_flash->version == 1 && mbox_flash->shift != 12) {
		ERR("MBOX Flash version 1 isn't using a 4K shift\n");
		return 1;
	}

	mbox_server_memset(0xff);

	test = calloc(erase_granule * 20, 1);

	/* Make up a test pattern */
	for (i = 0; i < erase_granule * 10; i++)
		test[i] = i;

	/* Write 64k of stuff at 0 and at 128k */
	printf("Writing test patterns...\n");
	rc = blocklevel_write(bl, 0, test, erase_granule * 10);
	if (rc) {
		ERR("blocklevel_write(0, erase_granule * 10) failed with err %d\n", rc);
		return 1;
	}
	rc = blocklevel_write(bl, erase_granule * 20, test, erase_granule * 10);
	if (rc) {
		ERR("blocklevel_write(0x20000, 0x10000) failed with err %d\n", rc);
		return 1;
	}

	if (mbox_server_memcmp(0, test, erase_granule * 10)) {
		ERR("Test pattern mismatch !\n");
		return 1;
	}

	/* Write "Hello world" straddling the 64k boundary */
	printf("Writing test string...\n");
	rc = blocklevel_write(bl, (erase_granule * 10) - 8, hello, sizeof(hello));
	if (rc) {
		ERR("blocklevel_write(0xfffc, %s, %lu) failed with err %d\n",
				hello, sizeof(hello), rc);
		return 1;
	}

	/* Check result */
	if (mbox_server_memcmp((erase_granule * 10) - 8, hello, sizeof(hello))) {
		ERR("Test string mismatch!\n");
		return 1;
	}

	/* Erase granule is something but never 0x50, this shouldn't succeed */
	rc = blocklevel_erase(bl, 0, 0x50);
	if (!rc) {
		ERR("blocklevel_erase(0, 0x50) didn't fail!\n");
		return 1;
	}

	/* Check it didn't silently erase */
	if (mbox_server_memcmp(0, test, (erase_granule * 10) - 8)) {
		ERR("Test pattern mismatch !\n");
		return 1;
	}

	/*
	 * For v1 protocol this should NOT call MARK_WRITE_ERASED!
	 * The server MARK_WRITE_ERASED will call exit(1) if it gets a
	 * MARK_WRITE_ERASED and version == 1
	 */
	rc = blocklevel_erase(bl, 0, erase_granule);
	if (rc) {
		ERR("blocklevel_erase(0, erase_granule) failed with err %d\n", rc);
		return 1;
	}

	/*
	 * Version 1 doesn't specify that the buffer actually becomes 0xff
	 * It is up to the daemon to do what it wants really - there are
	 * implementations that do nothing but writes to the same region
	 * work fine
	 */

	/* This check is important for v2 */
	/* Check stuff got erased */
	tmp = malloc(erase_granule * 2);
	if (!tmp) {
		ERR("malloc failed\n");
		return 1;
	}
	if (mbox_server_version() > 1) {
		memset(tmp, 0xff, erase_granule);
		if (mbox_server_memcmp(0, tmp, erase_granule)) {
			ERR("Buffer not erased\n");
			rc = 1;
			goto out;
		}
	}

	/* Read beyond the end of flash */
	rc = blocklevel_read(bl, total_size, tmp, 0x1000);
	if (!rc) {
		ERR("blocklevel_read(total_size, 0x1000) (read beyond the end) succeeded\n");
		goto out;
	}

	/* Test some simple write/read cases, avoid first page */
	rc = blocklevel_write(bl, erase_granule * 2, test, erase_granule / 2);
	if (rc) {
		ERR("blocklevel_write(erase_granule, erase_granule / 2) failed with err %d\n", rc);
		goto out;
	}
	rc = blocklevel_write(bl, erase_granule * 2 + erase_granule / 2, test, erase_granule / 2);
	if (rc) {
		ERR("blocklevel_write(erase_granule * 2 + erase_granule / 2, erase_granule) failed with err %d\n", rc);
		goto out;
	}

	rc = mbox_server_memcmp(erase_granule * 2, test, erase_granule / 2);
	if (rc) {
		ERR("%s:%d mbox_server_memcmp miscompare\n", __FILE__, __LINE__);
		goto out;
	}
	rc = mbox_server_memcmp(erase_granule * 2 + erase_granule / 2, test, erase_granule / 2);
	if (rc) {
		ERR("%s:%d mbox_server_memcmp miscompare\n", __FILE__, __LINE__);
		goto out;
	}

	/* Great so the writes made it, can we read them back? Do it in
	 * four small reads */
	for (i = 0; i < 4; i++) {
		rc = blocklevel_read(bl, erase_granule * 2 + (i * erase_granule / 4), tmp + (i * erase_granule / 4), erase_granule / 4);
		if (rc) {
			ERR("blocklevel_read(0x%08x, erase_granule / 4) failed with err %d\n",
					2 * erase_granule + (i * erase_granule / 4), rc);
			goto out;
		}
	}
	rc = memcmp(test, tmp, erase_granule / 2);
	if (rc) {
		ERR("%s:%d read back miscompare\n", __FILE__, __LINE__);
		goto out;
	}
	rc = memcmp(test, tmp + erase_granule / 2, erase_granule / 2);
	if (rc) {
		ERR("%s:%d read back miscompare\n", __FILE__, __LINE__);
		goto out;
	}

	/*
	 * Make sure we didn't corrupt other stuff, also make sure one
	 * blocklevel call will understand how to read from two windows
	 */
	for (i = 3; i < 9; i = i + 2) {
		printf("i:%d erase: 0x%08x\n", i, erase_granule);
		rc = blocklevel_read(bl, i * erase_granule, tmp, 2 * erase_granule);
		if (rc) {
			ERR("blocklevel_read(0x%08x, 2 * erase_granule) failed with err: %d\n", i * erase_granule, rc);
			goto out;
		}
		rc = memcmp(((char *)test) + (i * erase_granule), tmp, 2 * erase_granule);
		if (rc) {
			ERR("%s:%d read back miscompare (pos: 0x%08x)\n", __FILE__, __LINE__, i * erase_granule);
			goto out;
		}
	}

	srand(1);
	/*
	 * Try to jump around the place doing a tonne of small reads.
	 * Worth doing the same with writes TODO
	 */
#ifdef __STRICT_TEST__
#define TEST_LOOPS 1000
#else
#define TEST_LOOPS 100
#endif
	for (i = 0; i < TEST_LOOPS; i++) {
		int r = rand();

		printf("Loop %d of %d\n", i, TEST_LOOPS);
		/* Avoid reading too far, just skip it */
		if ((r % erase_granule * 10) + (r % erase_granule * 2) > erase_granule * 10)
			continue;

		rc = blocklevel_read(bl, erase_granule * 20 + (r % erase_granule * 10), tmp, r % erase_granule * 2);
		if (rc) {
			ERR("blocklevel_read(0x%08x, 0x%08x) failed with err %d\n", 0x20000 + (r % 0x100000), r % 0x2000, rc);
			goto out;
		}
		rc = memcmp(((char *)test) + (r % erase_granule * 10), tmp, r % erase_granule * 2);
		if (rc) {
			ERR("%s:%d read back miscompare (pos: 0x%08x)\n", __FILE__, __LINE__, 0x20000 + (r % 0x10000));
			goto out;
		}
	}
out:
	free(tmp);
	return rc;
}

int main(void)
{
	struct blocklevel_device *bl;
	int rc;

	libflash_debug = true;

	mbox_server_init();

#ifdef __STRICT_TEST__
	printf("Found __STRICT_TEST__, this may take time time.\n");
#else
	printf("__STRICT_TEST__ not found, use make strict-check for a more\n");
	printf("thorough test, it will take significantly longer.\n");
#endif

	printf("Doing mbox-flash V1 tests\n");

	/* run test */
	mbox_flash_init(&bl);
	rc = run_flash_test(bl);
	if (rc)
		goto out;
	/*
	 * Trick mbox-flash into thinking there was a reboot so we can
	 * switch to v2
	 */

	printf("Doing mbox-flash V2 tests\n");

	mbox_server_reset(2, 12);

	/* Do all the tests again */
	rc = run_flash_test(bl);
	if (rc)
		goto out;

	mbox_server_reset(2, 17);

	/* Do all the tests again */
	rc = run_flash_test(bl);
	if (rc)
		goto out;


	printf("Doing mbox-flash V3 tests\n");

	mbox_server_reset(3, 20);

	/* Do all the tests again */
	rc = run_flash_test(bl);


out:
	mbox_flash_exit(bl);

	mbox_server_destroy();

	return rc;
}
