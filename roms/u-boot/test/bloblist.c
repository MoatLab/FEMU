// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2018, Google Inc. All rights reserved.
 */

#include <common.h>
#include <bloblist.h>
#include <log.h>
#include <mapmem.h>
#include <asm/global_data.h>
#include <test/suites.h>
#include <test/test.h>
#include <test/ut.h>

DECLARE_GLOBAL_DATA_PTR;

/* Declare a new compression test */
#define BLOBLIST_TEST(_name, _flags) \
		UNIT_TEST(_name, _flags, bloblist_test)

enum {
	TEST_TAG		= 1,
	TEST_TAG2		= 2,
	TEST_TAG_MISSING	= 3,

	TEST_SIZE		= 10,
	TEST_SIZE2		= 20,
	TEST_SIZE_LARGE		= 0x3e0,

	TEST_ADDR		= CONFIG_BLOBLIST_ADDR,
	TEST_BLOBLIST_SIZE	= 0x400,

	ERASE_BYTE		= '\xff',
};

static struct bloblist_hdr *clear_bloblist(void)
{
	struct bloblist_hdr *hdr;

	/*
	 * Clear out any existing bloblist so we have a clean slate. Zero the
	 * header so that existing records are removed, but set everything else
	 * to 0xff for testing purposes.
	 */
	hdr = map_sysmem(CONFIG_BLOBLIST_ADDR, TEST_BLOBLIST_SIZE);
	memset(hdr, ERASE_BYTE, TEST_BLOBLIST_SIZE);
	memset(hdr, '\0', sizeof(*hdr));

	return hdr;
}

static int check_zero(void *data, int size)
{
	u8 *ptr;
	int i;

	for (ptr = data, i = 0; i < size; i++, ptr++) {
		if (*ptr)
			return -EINVAL;
	}

	return 0;
}

static int bloblist_test_init(struct unit_test_state *uts)
{
	struct bloblist_hdr *hdr;

	hdr = clear_bloblist();
	ut_asserteq(-ENOENT, bloblist_check(TEST_ADDR, TEST_BLOBLIST_SIZE));
	ut_assertok(bloblist_new(TEST_ADDR, TEST_BLOBLIST_SIZE, 0));
	hdr->version++;
	ut_asserteq(-EPROTONOSUPPORT, bloblist_check(TEST_ADDR,
						     TEST_BLOBLIST_SIZE));

	ut_asserteq(-ENOSPC, bloblist_new(TEST_ADDR, 0x10, 0));
	ut_asserteq(-EFAULT, bloblist_new(1, TEST_BLOBLIST_SIZE, 0));
	ut_assertok(bloblist_new(TEST_ADDR, TEST_BLOBLIST_SIZE, 0));

	ut_asserteq(-EIO, bloblist_check(TEST_ADDR, TEST_BLOBLIST_SIZE));
	ut_assertok(bloblist_finish());
	ut_assertok(bloblist_check(TEST_ADDR, TEST_BLOBLIST_SIZE));
	hdr->flags++;
	ut_asserteq(-EIO, bloblist_check(TEST_ADDR, TEST_BLOBLIST_SIZE));

	return 1;
}
BLOBLIST_TEST(bloblist_test_init, 0);

static int bloblist_test_blob(struct unit_test_state *uts)
{
	struct bloblist_hdr *hdr;
	struct bloblist_rec *rec, *rec2;
	char *data;

	/* At the start there should be no records */
	hdr = clear_bloblist();
	ut_assertnull(bloblist_find(TEST_TAG, TEST_BLOBLIST_SIZE));
	ut_assertok(bloblist_new(TEST_ADDR, TEST_BLOBLIST_SIZE, 0));
	ut_asserteq(map_to_sysmem(hdr), TEST_ADDR);

	/* Add a record and check that we can find it */
	data = bloblist_add(TEST_TAG, TEST_SIZE, 0);
	rec = (void *)(hdr + 1);
	ut_asserteq_addr(rec + 1, data);
	data = bloblist_find(TEST_TAG, TEST_SIZE);
	ut_asserteq_addr(rec + 1, data);

	/* Check the data is zeroed */
	ut_assertok(check_zero(data, TEST_SIZE));

	/* Check the 'ensure' method */
	ut_asserteq_addr(data, bloblist_ensure(TEST_TAG, TEST_SIZE));
	ut_assertnull(bloblist_ensure(TEST_TAG, TEST_SIZE2));
	rec2 = (struct bloblist_rec *)(data + ALIGN(TEST_SIZE, BLOBLIST_ALIGN));
	ut_assertok(check_zero(data, TEST_SIZE));

	/* Check for a non-existent record */
	ut_asserteq_addr(data, bloblist_ensure(TEST_TAG, TEST_SIZE));
	ut_asserteq_addr(rec2 + 1, bloblist_ensure(TEST_TAG2, TEST_SIZE2));
	ut_assertnull(bloblist_find(TEST_TAG_MISSING, 0));

	return 0;
}
BLOBLIST_TEST(bloblist_test_blob, 0);

/* Check bloblist_ensure_size_ret() */
static int bloblist_test_blob_ensure(struct unit_test_state *uts)
{
	void *data, *data2;
	int size;

	/* At the start there should be no records */
	clear_bloblist();
	ut_assertok(bloblist_new(TEST_ADDR, TEST_BLOBLIST_SIZE, 0));

	/* Test with an empty bloblist */
	size = TEST_SIZE;
	ut_assertok(bloblist_ensure_size_ret(TEST_TAG, &size, &data));
	ut_asserteq(TEST_SIZE, size);
	ut_assertok(check_zero(data, TEST_SIZE));

	/* Check that we get the same thing again */
	ut_assertok(bloblist_ensure_size_ret(TEST_TAG, &size, &data2));
	ut_asserteq(TEST_SIZE, size);
	ut_asserteq_addr(data, data2);

	/* Check that the size remains the same */
	size = TEST_SIZE2;
	ut_assertok(bloblist_ensure_size_ret(TEST_TAG, &size, &data));
	ut_asserteq(TEST_SIZE, size);

	/* Check running out of space */
	size = TEST_SIZE_LARGE;
	ut_asserteq(-ENOSPC, bloblist_ensure_size_ret(TEST_TAG2, &size, &data));

	return 0;
}
BLOBLIST_TEST(bloblist_test_blob_ensure, 0);

static int bloblist_test_bad_blob(struct unit_test_state *uts)
{
	struct bloblist_hdr *hdr;
	void *data;

	hdr = clear_bloblist();
	ut_assertok(bloblist_new(TEST_ADDR, TEST_BLOBLIST_SIZE, 0));
	data = hdr + 1;
	data += sizeof(struct bloblist_rec);
	ut_asserteq_addr(data, bloblist_ensure(TEST_TAG, TEST_SIZE));
	ut_asserteq_addr(data, bloblist_ensure(TEST_TAG, TEST_SIZE));

	return 0;
}
BLOBLIST_TEST(bloblist_test_bad_blob, 0);

static int bloblist_test_checksum(struct unit_test_state *uts)
{
	struct bloblist_hdr *hdr;
	char *data, *data2;

	hdr = clear_bloblist();
	ut_assertok(bloblist_new(TEST_ADDR, TEST_BLOBLIST_SIZE, 0));
	ut_assertok(bloblist_finish());
	ut_assertok(bloblist_check(TEST_ADDR, TEST_BLOBLIST_SIZE));

	/*
	 * Now change things amd make sure that the checksum notices. We cannot
	 * change the size or alloced fields, since that will crash the code.
	 * It has to rely on these being correct.
	 */
	hdr->flags--;
	ut_asserteq(-EIO, bloblist_check(TEST_ADDR, TEST_BLOBLIST_SIZE));
	hdr->flags++;

	hdr->size--;
	ut_asserteq(-EFBIG, bloblist_check(TEST_ADDR, TEST_BLOBLIST_SIZE));
	hdr->size++;

	hdr->spare++;
	ut_asserteq(-EIO, bloblist_check(TEST_ADDR, TEST_BLOBLIST_SIZE));
	hdr->spare--;

	hdr->chksum++;
	ut_asserteq(-EIO, bloblist_check(TEST_ADDR, TEST_BLOBLIST_SIZE));
	hdr->chksum--;

	/* Make sure the checksum changes when we add blobs */
	data = bloblist_add(TEST_TAG, TEST_SIZE, 0);
	ut_asserteq(-EIO, bloblist_check(TEST_ADDR, TEST_BLOBLIST_SIZE));

	data2 = bloblist_add(TEST_TAG2, TEST_SIZE2, 0);
	ut_asserteq(-EIO, bloblist_check(TEST_ADDR, TEST_BLOBLIST_SIZE));
	ut_assertok(bloblist_finish());

	/* It should also change if we change the data */
	ut_assertok(bloblist_check(TEST_ADDR, TEST_BLOBLIST_SIZE));
	*data += 1;
	ut_asserteq(-EIO, bloblist_check(TEST_ADDR, TEST_BLOBLIST_SIZE));
	*data -= 1;

	ut_assertok(bloblist_check(TEST_ADDR, TEST_BLOBLIST_SIZE));
	*data2 += 1;
	ut_asserteq(-EIO, bloblist_check(TEST_ADDR, TEST_BLOBLIST_SIZE));
	*data2 -= 1;

	/*
	 * Changing data outside the range of valid data should not affect
	 * the checksum.
	 */
	ut_assertok(bloblist_check(TEST_ADDR, TEST_BLOBLIST_SIZE));
	data[TEST_SIZE]++;
	data2[TEST_SIZE2]++;
	ut_assertok(bloblist_check(TEST_ADDR, TEST_BLOBLIST_SIZE));

	return 0;
}
BLOBLIST_TEST(bloblist_test_checksum, 0);

/* Test the 'bloblist info' command */
static int bloblist_test_cmd_info(struct unit_test_state *uts)
{
	struct bloblist_hdr *hdr;
	char *data, *data2;

	hdr = clear_bloblist();
	ut_assertok(bloblist_new(TEST_ADDR, TEST_BLOBLIST_SIZE, 0));
	data = bloblist_ensure(TEST_TAG, TEST_SIZE);
	data2 = bloblist_ensure(TEST_TAG2, TEST_SIZE2);

	console_record_reset_enable();
	ut_silence_console(uts);
	console_record_reset();
	run_command("bloblist info", 0);
	ut_assert_nextline("base:     %lx", (ulong)map_to_sysmem(hdr));
	ut_assert_nextline("size:     400    1 KiB");
	ut_assert_nextline("alloced:  70     112 Bytes");
	ut_assert_nextline("free:     390    912 Bytes");
	ut_assert_console_end();
	ut_unsilence_console(uts);

	return 0;
}
BLOBLIST_TEST(bloblist_test_cmd_info, 0);

/* Test the 'bloblist list' command */
static int bloblist_test_cmd_list(struct unit_test_state *uts)
{
	struct bloblist_hdr *hdr;
	char *data, *data2;

	hdr = clear_bloblist();
	ut_assertok(bloblist_new(TEST_ADDR, TEST_BLOBLIST_SIZE, 0));
	data = bloblist_ensure(TEST_TAG, TEST_SIZE);
	data2 = bloblist_ensure(TEST_TAG2, TEST_SIZE2);

	console_record_reset_enable();
	ut_silence_console(uts);
	console_record_reset();
	run_command("bloblist list", 0);
	ut_assert_nextline("Address       Size  Tag Name");
	ut_assert_nextline("%08lx  %8x    1 EC host event",
			   (ulong)map_to_sysmem(data), TEST_SIZE);
	ut_assert_nextline("%08lx  %8x    2 SPL hand-off",
			   (ulong)map_to_sysmem(data2), TEST_SIZE2);
	ut_assert_console_end();
	ut_unsilence_console(uts);

	return 0;
}
BLOBLIST_TEST(bloblist_test_cmd_list, 0);

/* Test alignment of bloblist blobs */
static int bloblist_test_align(struct unit_test_state *uts)
{
	struct bloblist_hdr *hdr;
	ulong addr;
	char *data;
	int i;

	/* At the start there should be no records */
	hdr = clear_bloblist();
	ut_assertok(bloblist_new(TEST_ADDR, TEST_BLOBLIST_SIZE, 0));
	ut_assertnull(bloblist_find(TEST_TAG, TEST_BLOBLIST_SIZE));

	/* Check the default alignment */
	for (i = 0; i < 3; i++) {
		int size = i * 3;
		ulong addr;
		char *data;
		int j;

		data = bloblist_add(i, size, 0);
		ut_assertnonnull(data);
		addr = map_to_sysmem(data);
		ut_asserteq(0, addr & (BLOBLIST_ALIGN - 1));

		/* Only the bytes in the blob data should be zeroed */
		for (j = 0; j < size; j++)
			ut_asserteq(0, data[j]);
		for (; j < BLOBLIST_ALIGN; j++)
			ut_asserteq(ERASE_BYTE, data[j]);
	}

	/* Check larger alignment */
	for (i = 0; i < 3; i++) {
		int align = 32 << i;

		data = bloblist_add(3 + i, i * 4, align);
		ut_assertnonnull(data);
		addr = map_to_sysmem(data);
		ut_asserteq(0, addr & (align - 1));
	}

	/* Check alignment with an bloblist starting on a smaller alignment */
	hdr = map_sysmem(TEST_ADDR + BLOBLIST_ALIGN, TEST_BLOBLIST_SIZE);
	memset(hdr, ERASE_BYTE, TEST_BLOBLIST_SIZE);
	memset(hdr, '\0', sizeof(*hdr));
	ut_assertok(bloblist_new(TEST_ADDR + BLOBLIST_ALIGN, TEST_BLOBLIST_SIZE,
				 0));

	data = bloblist_add(1, 5, BLOBLIST_ALIGN * 2);
	ut_assertnonnull(data);
	addr = map_to_sysmem(data);
	ut_asserteq(0, addr & (BLOBLIST_ALIGN * 2 - 1));

	return 0;
}
BLOBLIST_TEST(bloblist_test_align, 0);

/* Test relocation of a bloblist */
static int bloblist_test_reloc(struct unit_test_state *uts)
{
	const uint large_size = TEST_BLOBLIST_SIZE;
	const uint small_size = 0x20;
	void *old_ptr, *new_ptr;
	void *blob1, *blob2;
	ulong new_addr;
	ulong new_size;

	ut_assertok(bloblist_new(TEST_ADDR, TEST_BLOBLIST_SIZE, 0));
	old_ptr = map_sysmem(TEST_ADDR, TEST_BLOBLIST_SIZE);

	/* Add one blob and then one that won't fit */
	blob1 = bloblist_add(TEST_TAG, small_size, 0);
	ut_assertnonnull(blob1);
	blob2 = bloblist_add(TEST_TAG2, large_size, 0);
	ut_assertnull(blob2);

	/* Relocate the bloblist somewhere else, a bit larger */
	new_addr = TEST_ADDR + TEST_BLOBLIST_SIZE;
	new_size = TEST_BLOBLIST_SIZE + 0x100;
	new_ptr = map_sysmem(new_addr, TEST_BLOBLIST_SIZE);
	bloblist_reloc(new_ptr, new_size, old_ptr, TEST_BLOBLIST_SIZE);
	gd->bloblist = new_ptr;

	/* Check the old blob is there and that we can now add the bigger one */
	ut_assertnonnull(bloblist_find(TEST_TAG, small_size));
	ut_assertnull(bloblist_find(TEST_TAG2, small_size));
	blob2 = bloblist_add(TEST_TAG2, large_size, 0);
	ut_assertnonnull(blob2);

	return 0;
}
BLOBLIST_TEST(bloblist_test_reloc, 0);

int do_ut_bloblist(struct cmd_tbl *cmdtp, int flag, int argc,
		   char *const argv[])
{
	struct unit_test *tests = UNIT_TEST_SUITE_START(bloblist_test);
	const int n_ents = UNIT_TEST_SUITE_COUNT(bloblist_test);

	return cmd_ut_category("bloblist", "bloblist_test_",
			       tests, n_ents, argc, argv);
}
