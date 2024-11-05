// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2018 IBM Corp. */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <libflash/blocklevel.h>

#include "../ecc.c"
#include "../blocklevel.c"

#define __unused		__attribute__((unused))

#define ERR(fmt...) fprintf(stderr, fmt)

bool libflash_debug;

static int bl_test_bad_read(struct blocklevel_device *bl __unused, uint64_t pos __unused,
		void *buf __unused, uint64_t len __unused)
{
	return FLASH_ERR_PARM_ERROR;
}

static int bl_test_read(struct blocklevel_device *bl, uint64_t pos, void *buf, uint64_t len)
{
	if (pos + len > 0x1000)
		return FLASH_ERR_PARM_ERROR;

	memcpy(buf, bl->priv + pos, len);

	return 0;
}

static int bl_test_bad_write(struct blocklevel_device *bl __unused, uint64_t pos __unused,
		const void *buf __unused, uint64_t len __unused)
{
	return FLASH_ERR_PARM_ERROR;
}

static int bl_test_write(struct blocklevel_device *bl, uint64_t pos, const void *buf, uint64_t len)
{
	if (pos + len > 0x1000)
		return FLASH_ERR_PARM_ERROR;

	memcpy(bl->priv + pos, buf, len);

	return 0;
}

static int bl_test_erase(struct blocklevel_device *bl, uint64_t pos, uint64_t len)
{
	if (pos + len > 0x1000)
		return FLASH_ERR_PARM_ERROR;

	memset(bl->priv + pos, 0xff, len);

	return 0;
}

static void dump_buf(uint8_t *buf, int start, int end, int miss)
{
	int i;

	printf("pos: value\n");
	for (i = start; i < end; i++)
		printf("%04x: %c%s\n", i, buf[i] == 0xff ? '-' : buf[i], i == miss ? " <- First missmatch" : "");
}

/*
 * Returns zero if the buffer is ok. Otherwise returns the position of
 * the mismatch. If the mismatch is at zero -1 is returned
 */
static int check_buf(uint8_t *buf, int zero_start, int zero_end)
{
	int i;

	for (i = 0; i < 0x1000; i++) {
		if (i >= zero_start && i < zero_end && buf[i] != 0xff)
			return i == 0 ? -1 : i;
		if ((i < zero_start || i >= zero_end) && buf[i] != (i % 26) + 'a')
			return i == 0 ? -1 : i;
	}

	return 0;
}

static void reset_buf(uint8_t *buf)
{
	int i;

	for (i = 0; i < 0x1000; i++) {
		/* This gives repeating a - z which will be nice to visualise */
		buf[i] = (i % 26) + 'a';
	}
}

static void print_ptr(void *ptr, int len)
{
	int i;
	char *p = ptr;

	printf("0x");
	for (i = 0; i < len; i++) {
		putchar(*p);
		if (i && i % 8 == 0) {
			putchar('\n');
			if (len - i)
				printf("0x");
		}
	}
	putchar('\n');
}

int main(void)
{
	struct blocklevel_device bl_mem = { 0 };
	struct blocklevel_device *bl = &bl_mem;
	uint64_t with_ecc[10], without_ecc[10];
	char *buf = NULL, *data = NULL;
	int i, rc, miss;

	if (blocklevel_ecc_protect(bl, 0, 0x1000)) {
		ERR("Failed to blocklevel_ecc_protect!\n");
		return 1;
	}

	/* 0x1000 -> 0x3000 should remain unprotected */

	if (blocklevel_ecc_protect(bl, 0x3000, 0x1000)) {
		ERR("Failed to blocklevel_ecc_protect(0x3000, 0x1000)\n");
		return 1;
	}
	if (blocklevel_ecc_protect(bl, 0x2f00, 0x1100)) {
		ERR("Failed to blocklevel_ecc_protect(0x2f00, 0x1100)\n");
		return 1;
	}

	/* Zero length protection */
	if (!blocklevel_ecc_protect(bl, 0x4000, 0)) {
		ERR("Shouldn't have succeeded blocklevel_ecc_protect(0x4000, 0)\n");
		return 1;
	}

	/* Minimum creatable size */
	if (blocklevel_ecc_protect(bl, 0x4000, BYTES_PER_ECC)) {
		ERR("Failed to blocklevel_ecc_protect(0x4000, BYTES_PER_ECC)\n");
		return 1;
	}

	/* Deal with overlapping protections */
	if (blocklevel_ecc_protect(bl, 0x100, 0x1000)) {
		ERR("Failed to protect overlaping region blocklevel_ecc_protect(0x100, 0x1000)\n");
		return 1;
	}

	/* Deal with overflow */
	if (!blocklevel_ecc_protect(bl, 1, 0xFFFFFFFF)) {
		ERR("Added an 'overflow' protection blocklevel_ecc_protect(1, 0xFFFFFFFF)\n");
		return 1;
	}

	/* Protect everything */
	if (blocklevel_ecc_protect(bl, 0, 0xFFFFFFFF)) {
		ERR("Couldn't protect everything blocklevel_ecc_protect(0, 0xFFFFFFFF)\n");
		return 1;
	}

	if (ecc_protected(bl, 0, 1, NULL) != 1) {
		ERR("Invaid result for ecc_protected(0, 1)\n");
		return 1;
	}

	if (ecc_protected(bl, 0, 0x1000, NULL) != 1) {
		ERR("Invalid result for ecc_protected(0, 0x1000)\n");
		return 1;
	}

	if (ecc_protected(bl, 0x100, 0x100, NULL) != 1) {
		ERR("Invalid result for ecc_protected(0x0100, 0x100)\n");
		return 1;
	}

	/* Clear the protections */
	bl->ecc_prot.n_prot = 0;
	/* Reprotect */
	if (blocklevel_ecc_protect(bl, 0x3000, 0x1000)) {
		ERR("Failed to blocklevel_ecc_protect(0x3000, 0x1000)\n");
		return 1;
	}
	/* Deal with overlapping protections */
	if (blocklevel_ecc_protect(bl, 0x100, 0x1000)) {
		ERR("Failed to protect overlaping region blocklevel_ecc_protect(0x100, 0x1000)\n");
		return 1;
	}

	if (ecc_protected(bl, 0x1000, 0, NULL) != 1) {
		ERR("Invalid result for ecc_protected(0x1000, 0)\n");
		return 1;
	}

	if (ecc_protected(bl, 0x1000, 0x1000, NULL) != -1) {
		ERR("Invalid result for ecc_protected(0x1000, 0x1000)\n");
		return 1;
	}

	if (ecc_protected(bl, 0x1000, 0x100, NULL) != 1) {
		ERR("Invalid result for ecc_protected(0x1000, 0x100)\n");
		return 1;
	}

	if (ecc_protected(bl, 0x2000, 0, NULL) != 0) {
		ERR("Invalid result for ecc_protected(0x2000, 0)\n");
		return 1;
	}

	if (ecc_protected(bl, 0x4000, 1, NULL) != 0) {
		ERR("Invalid result for ecc_protected(0x4000, 1)\n");
		return 1;
	}

	/* Check for asking for a region with mixed protection */
	if (ecc_protected(bl, 0x100, 0x2000, NULL) != -1) {
		ERR("Invalid result for ecc_protected(0x100, 0x2000)\n");
		return 1;
	}

	/* Test the auto extending of regions */
	if (blocklevel_ecc_protect(bl, 0x5000, 0x100)) {
		ERR("Failed to blocklevel_ecc_protect(0x5000, 0x100)\n");
		return 1;
	}

	if (blocklevel_ecc_protect(bl, 0x5100, 0x100)) {
		ERR("Failed to blocklevel_ecc_protect(0x5100, 0x100)\n");
		return 1;
	}

	if (blocklevel_ecc_protect(bl, 0x5200, 0x100)) {
		ERR("Failed to blocklevel_ecc_protect(0x5200, 0x100)\n");
		return 1;
	}

	if (ecc_protected(bl, 0x5120, 0x10, NULL) != 1) {
		ERR("Invalid result for ecc_protected(0x5120, 0x10)\n");
		return 1;
	}

	if (blocklevel_ecc_protect(bl, 0x4f00, 0x100)) {
		ERR("Failed to blocklevel_ecc_protected(0x4900, 0x100)\n");
		return 1;
	}

	if (blocklevel_ecc_protect(bl, 0x4900, 0x100)) {
		ERR("Failed to blocklevel_ecc_protected(0x4900, 0x100)\n");
		return 1;
	}

	if (ecc_protected(bl, 0x4920, 0x10, NULL) != 1) {
		ERR("Invalid result for ecc_protected(0x4920, 0x10)\n");
		return 1;
	}

	if (blocklevel_ecc_protect(bl, 0x5290, 0x10)) {
		ERR("Failed to blocklevel_ecc_protect(0x5290, 0x10)\n");
		return 1;
	}

	/* Test the auto extending of regions */
	if (blocklevel_ecc_protect(bl, 0x6000, 0x100)) {
		ERR("Failed to blocklevel_ecc_protect(0x6000, 0x100)\n");
		return 1;
	}

	if (blocklevel_ecc_protect(bl, 0x6200, 0x100)) {
		ERR("Failed to blocklevel_ecc_protect(0x6200, 0x100)\n");
		return 1;
	}

	/* Test ECC reading and writing being 100% transparent to the
	 * caller */
	buf = malloc(0x1000);
	data = malloc(0x100);
	if (!buf || !data) {
		ERR("Malloc failed\n");
		rc = 1;
		goto out;
	}
	memset(bl, 0, sizeof(*bl));
	bl_mem.read = &bl_test_read;
	bl_mem.write = &bl_test_write;
	bl_mem.erase = &bl_test_erase;
	bl_mem.erase_mask = 0xff;
	bl_mem.priv = buf;
	reset_buf(buf);


	/*
	 * Test 1: One full and exact erase block, this shouldn't call
	 * read or write, ensure this fails if it does.
	 */
	bl_mem.write = &bl_test_bad_write;
	bl_mem.read = &bl_test_bad_read;
	if (blocklevel_smart_erase(bl, 0x100, 0x100)) {
		ERR("Failed to blocklevel_smart_erase(0x100, 0x100)\n");
		goto out;
	}
	miss = check_buf(buf, 0x100, 0x200);
	if (miss) {
		ERR("Buffer mismatch after blocklevel_smart_erase(0x100, 0x100) at 0x%0x\n",
				miss == -1 ? 0 : miss);
		dump_buf(buf, 0xfc, 0x105, miss == -1 ? 0 : miss);
		dump_buf(buf, 0x1fc, 0x205, miss == -1 ? 0 : miss);
		goto out;
	}
	bl_mem.read = &bl_test_read;
	bl_mem.write = &bl_test_write;

	reset_buf(buf);
	/* Test 2: Only touch one erase block */
	if (blocklevel_smart_erase(bl, 0x20, 0x40)) {
		ERR("Failed to blocklevel_smart_erase(0x20, 0x40)\n");
		goto out;
	}
	miss = check_buf(buf, 0x20, 0x60);
	if (miss) {
		ERR("Buffer mismatch after blocklevel_smart_erase(0x20, 0x40) at 0x%x\n",
				miss == -1 ? 0 : miss);
		dump_buf(buf, 0x1c, 0x65, miss == -1 ? 0 : miss);
		goto out;
	}

	reset_buf(buf);
	/* Test 3: Start aligned but finish somewhere in it */
	if (blocklevel_smart_erase(bl, 0x100, 0x50)) {
		ERR("Failed to blocklevel_smart_erase(0x100, 0x50)\n");
		goto out;
	}
	miss = check_buf(buf, 0x100, 0x150);
	if (miss) {
		ERR("Buffer mismatch after blocklevel_smart_erase(0x100, 0x50) at 0x%0x\n",
				miss == -1 ? 0 : miss);
		dump_buf(buf, 0xfc, 0x105, miss == -1 ? 0 : miss);
		dump_buf(buf, 0x14c, 0x155, miss == -1 ? 0 : miss);
		goto out;
	}

	reset_buf(buf);
	/* Test 4: Start somewhere in it, finish aligned */
	if (blocklevel_smart_erase(bl, 0x50, 0xb0)) {
		ERR("Failed to blocklevel_smart_erase(0x50, 0xb0)\n");
		goto out;
	}
	miss = check_buf(buf, 0x50, 0x100);
	if (miss) {
		ERR("Buffer mismatch after blocklevel_smart_erase(0x50, 0xb0) at 0x%x\n",
				miss == -1 ? 0 : miss);
		dump_buf(buf, 0x4c, 0x55, miss == -1 ? 0 : miss);
		dump_buf(buf, 0x100, 0x105, miss == -1 ? 0 : miss);
		goto out;
	}

	reset_buf(buf);
	/* Test 5: Cover two erase blocks exactly */
	if (blocklevel_smart_erase(bl, 0x100, 0x200)) {
		ERR("Failed to blocklevel_smart_erase(0x100, 0x200)\n");
		goto out;
	}
	miss = check_buf(buf, 0x100, 0x300);
	if (miss) {
		ERR("Buffer mismatch after blocklevel_smart_erase(0x100, 0x200) at 0x%x\n",
				miss == -1 ? 0 : miss);
		dump_buf(buf, 0xfc, 0x105, miss == -1 ? 0 : miss);
		dump_buf(buf, 0x2fc, 0x305, miss == -1 ? 0 : miss);
		goto out;
	}

	reset_buf(buf);
	/* Test 6: Erase 1.5 blocks (start aligned) */
	if (blocklevel_smart_erase(bl, 0x100, 0x180)) {
		ERR("Failed to blocklevel_smart_erase(0x100, 0x180)\n");
		goto out;
	}
	miss = check_buf(buf, 0x100, 0x280);
	if (miss) {
		ERR("Buffer mismatch after blocklevel_smart_erase(0x100, 0x180) at 0x%x\n",
				miss == -1 ? 0 : miss);
		dump_buf(buf, 0xfc, 0x105, miss == -1 ? 0 : miss);
		dump_buf(buf, 0x27c, 0x285, miss == -1 ? 0 : miss);
		goto out;
	}

	reset_buf(buf);
	/* Test 7: Erase 1.5 blocks (end aligned) */
	if (blocklevel_smart_erase(bl, 0x80, 0x180)) {
		ERR("Failed to blocklevel_smart_erase(0x80, 0x180)\n");
		goto out;
	}
	miss = check_buf(buf, 0x80, 0x200);
	if (miss) {
		ERR("Buffer mismatch after blocklevel_smart_erase(0x80, 0x180) at 0x%x\n",
				miss == -1 ? 0 : miss);
		dump_buf(buf, 0x7c, 0x85, miss == -1 ? 0 : miss);
		dump_buf(buf, 0x1fc, 0x205, miss == -1 ? 0 : miss);
		goto out;
	}

	reset_buf(buf);
	/* Test 8: Erase a big section, not aligned */
	if (blocklevel_smart_erase(bl, 0x120, 0x544)) {
		ERR("Failed to blocklevel_smart_erase(0x120, 0x544)\n");
		goto out;
	}
	miss = check_buf(buf, 0x120, 0x664);
	if (miss) {
		ERR("Buffer mismatch after blocklevel_smart_erase(0x120, 0x544) at 0x%x\n",
				miss == -1 ? 0 : miss);
		dump_buf(buf, 0x11c, 0x125, miss == -1 ? 0 : miss);
		dump_buf(buf, 0x65f, 0x669, miss == -1 ? 0 : miss);
		goto out;
	}

	bl_mem.priv = buf;
	reset_buf(buf);

	for (i = 0; i < 0x100; i++)
		data[i] = i;

	/* This really shouldn't fail */
	rc = blocklevel_ecc_protect(bl, 0, 0x100);
	if (rc) {
		ERR("Couldn't blocklevel_ecc_protect(0, 0x100)\n");
		goto out;
	}

	rc = blocklevel_write(bl, 0, data, 0x100);
	if (rc) {
		ERR("Couldn't blocklevel_write(0, 0x100)\n");
		goto out;
	}

	rc = blocklevel_write(bl, 0x200, data, 0x100);
	if (rc) {
		ERR("Couldn't blocklevel_write(0x200, 0x100)\n");
		goto out;
	}

	/*
	 * 0x50 once adjusted for the presence of ECC becomes 0x5a which
	 * is ECC aligned.
	 */
	rc = blocklevel_read(bl, 0x50, with_ecc, 8);
	if (rc) {
		ERR("Couldn't blocklevel_read(0x50, 8) with ecc rc=%d\n", rc);
		goto out;
	}
	rc = blocklevel_read(bl, 0x250, without_ecc, 8);
	if (rc) {
		ERR("Couldn't blocklevel_read(0x250, 8) without ecc rc=%d\n", rc);
		goto out;
	}
	if (memcmp(with_ecc, without_ecc, 8) || memcmp(with_ecc, &data[0x50], 8)) {
		ERR("ECC read and non-ECC read don't match or are wrong line: %d\n", __LINE__);
		print_ptr(with_ecc, 8);
		print_ptr(without_ecc, 8);
		print_ptr(&data[50], 8);
		rc = 1;
		goto out;
	}

	/*
	 * 0x50 once adjusted for the presence of ECC becomes 0x5a which
	 * is ECC aligned.
	 * So 0x4f won't be aligned!
	 */
	rc = blocklevel_read(bl, 0x4f, with_ecc, 8);
	if (rc) {
		ERR("Couldn't blocklevel_read(0x4f, 8) with ecc %d\n", rc);
		goto out;
	}
	rc = blocklevel_read(bl, 0x24f, without_ecc, 8);
	if (rc) {
		ERR("Couldn't blocklevel_read(0x24f, 8) without ecc %d\n", rc);
		goto out;
	}
	if (memcmp(with_ecc, without_ecc, 8) || memcmp(with_ecc, &data[0x4f], 8)) {
		ERR("ECC read and non-ECC read don't match or are wrong line: %d\n", __LINE__);
		print_ptr(with_ecc, 8);
		print_ptr(without_ecc, 8);
		print_ptr(&data[0x4f], 8);
		rc = 1;
		goto out;
	}

	/*
	 * 0x50 once adjusted for the presence of ECC becomes 0x5a which
	 * is ECC aligned.
	 */
	rc = blocklevel_read(bl, 0x50, with_ecc, 16);
	if (rc) {
		ERR("Couldn't blocklevel_read(0x50, 16) with ecc %d\n", rc);
		goto out;
	}
	rc = blocklevel_read(bl, 0x250, without_ecc, 16);
	if (rc) {
		ERR("Couldn't blocklevel_read(0x250, 16) without ecc %d\n", rc);
		goto out;
	}
	if (memcmp(with_ecc, without_ecc, 16)|| memcmp(with_ecc, &data[0x50], 16)) {
		ERR("(long read )ECC read and non-ECC read don't match or are wrong line: %d\n", __LINE__);
		print_ptr(with_ecc, 16);
		print_ptr(without_ecc, 16);
		print_ptr(&data[0x50], 16);
		rc = 1;
		goto out;
	}

	/*
	 * 0x50 once adjusted for the presence of ECC becomes 0x5a which
	 * is ECC aligned. So 4f won't be.
	 */
	rc = blocklevel_read(bl, 0x4f, with_ecc, 24);
	if (rc) {
		ERR("Couldn't blocklevel_read(0x4f, 24) with ecc %d\n", rc);
		goto out;
	}
	rc = blocklevel_read(bl, 0x24f, without_ecc, 24);
	if (rc) {
		ERR("Couldn't blocklevel_read(0x24f, 24) without ecc %d\n", rc);
		goto out;
	}
	if (memcmp(with_ecc, without_ecc, 24)|| memcmp(with_ecc, &data[0x4f], 24)) {
		ERR("(long read )ECC read and non-ECC read don't match or are wrong: %d\n", __LINE__);
		print_ptr(with_ecc, 24);
		print_ptr(without_ecc, 24);
		print_ptr(&data[0x4f], 24);
		rc = 1;
		goto out;
	}

	/*
	 * Now lets try to write at non ECC aligned positions
	 * Go easy first, 0x50 becomes 0x5a which is ECC byte aligned but
	 * not aligned to the start of the partition
	 */

	rc = blocklevel_write(bl, 0x50, data, 0xb0);
	if (rc) {
		ERR("Couldn't blocklevel_write()\n");
		goto out;
	}
	/* Read 8 bytes before to make sure we didn't ruin that */
	rc = blocklevel_read(bl, 0x48, with_ecc, 24);
	if (rc) {
		ERR("Couldn't blocklevel_read() with ecc %d\n", rc);
		goto out;
	}
	if (memcmp(with_ecc, data + 0x48, 8) || memcmp(with_ecc + 1, data, 16)) {
		rc = 1;
		ERR("Couldn't read back what we thought we wrote line: %d\n", __LINE__);
		print_ptr(with_ecc, 24);
		print_ptr(&data[0x48], 8);
		print_ptr(data, 16);
		goto out;
	}

	/* Ok lets get tricky */
	rc = blocklevel_write(bl, 0x31, data, 0xcf);
	if (rc) {
		ERR("Couldn't blocklevel_write(0x31, 0xcf)\n");
		goto out;
	}
	/* Read 8 bytes before to make sure we didn't ruin that */
	rc = blocklevel_read(bl, 0x29, with_ecc, 24);
	if (rc) {
		ERR("Couldn't blocklevel_read(0x29, 24) with ecc rc=%d\n", rc);
		goto out;
	}
	if (memcmp(with_ecc, &data[0x29], 8) || memcmp(with_ecc + 1, data, 16)) {
		ERR("Couldn't read back what we thought we wrote line: %d\n", __LINE__);
		print_ptr(with_ecc, 24);
		print_ptr(&data[0x29], 8);
		print_ptr(data, 16);
		rc = 1;
		goto out;
	}

	/*
	 * Rewrite the pattern that we've messed up
	 */
	rc = blocklevel_write(bl, 0, data, 0x100);
	if (rc) {
		ERR("Couldn't blocklevel_write(0, 0x100) to reset\n");
		goto out;
	}

	/* Be unalignmed as possible from now on, starting somewhat easy */
	rc = blocklevel_read(bl, 0, with_ecc, 5);
	if (rc) {
		ERR("Couldn't blocklevel_write(0, 5)\n");
		goto out;
	}
	if (memcmp(with_ecc, data, 5)) {
		ERR("blocklevel_read 5, 0) didn't match line: %d\n", __LINE__);
		print_ptr(with_ecc, 5);
		print_ptr(data, 5);
		rc = 1;
		goto out;
	}

	/* 39 is neither divisible by 8 or by 9 */
	rc = blocklevel_read(bl, 39, with_ecc, 5);
	if (rc) {
		ERR("Couldn't blocklevel_write(39, 5)\n");
		goto out;
	}
	if (memcmp(with_ecc, &data[39], 5)) {
		ERR("blocklevel_read(5, 39() didn't match line: %d\n", __LINE__);
		print_ptr(with_ecc, 5);
		print_ptr(&data[39], 5);
		rc = 1;
		goto out;
	}

	rc = blocklevel_read(bl, 0xb, &with_ecc, 39);
	if (rc) {
		ERR("Couldn't blocklevel_read(0xb, 39)\n");
		goto out;
	}
	if (memcmp(with_ecc, &data[0xb], 39)) {
		ERR("Strange sized and positioned read failed, blocklevel_read(0xb, 39) line: %d\n", __LINE__);
		print_ptr(with_ecc, 39);
		print_ptr(&data[0xb], 39);
		rc = 1;
		goto out;
	}

	rc = blocklevel_write(bl, 39, data, 50);
	if (rc) {
		ERR("Couldn't blocklevel_write(39, 50)\n");
		goto out;
	}

	rc = blocklevel_read(bl, 32, with_ecc, 39);
	if (rc) {
		ERR("Couldn't blocklevel_read(32, 39)\n");
		goto out;
	}

	if (memcmp(with_ecc, &data[32], 7) || memcmp(((char *)with_ecc) + 7, data, 32)) {
		ERR("Read back of odd placed/odd sized write failed, blocklevel_read(32, 39) line: %d\n", __LINE__);
		print_ptr(with_ecc, 39);
		print_ptr(&data[32], 7);
		print_ptr(data, 32);
		rc = 1;
		goto out;
	}

out:
	free(buf);
	free(data);
return rc;
}
