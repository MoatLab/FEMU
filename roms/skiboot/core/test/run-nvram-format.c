// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2013-2019 IBM Corp.
 */

#include <stdlib.h>

#include "../nvram-format.c"

bool nvram_wait_for_load(void)
{
	return true;
}

bool nvram_validate(void)
{
	return true;
}

bool nvram_has_loaded(void)
{
	return true;
}

static char *nvram_reset(void *nvram_image, int size)
{
	struct chrp_nvram_hdr *h = nvram_image;

	/* entire partition used by one key */
	assert(nvram_format(nvram_image, size) == 0);
	memset((char *) h + sizeof(*h), 0, NVRAM_SIZE_FW_PRIV - sizeof(*h));
	assert(nvram_check(nvram_image, size) == 0);

	return (char *) h + sizeof(*h);
}

int main(void)
{
	char *nvram_image;
	size_t sz;
	struct chrp_nvram_hdr *h;
	char *data;
	const char *result;

	/* 1024 bytes is too small for our NVRAM */
	nvram_image = malloc(1024);
	assert(nvram_format(nvram_image, 1024)!=0);
	free(nvram_image);

	/* 4096 bytes is too small for our NVRAM */
	nvram_image = malloc(4096);
	assert(nvram_format(nvram_image, 4096)!=0);
	free(nvram_image);

	/* 64k is too small for our NVRAM */
	nvram_image = malloc(0x10000);
	assert(nvram_format(nvram_image, 0x10000)!=0);
	free(nvram_image);

	/* 68k is too small for our NVRAM */
	nvram_image = malloc(68*1024);
	assert(nvram_format(nvram_image, 68*1024)!=0);
	free(nvram_image);

	/* 68k+16 bytes (nvram header) should generate empty free space */
	sz = NVRAM_SIZE_COMMON + NVRAM_SIZE_FW_PRIV
		+ sizeof(struct chrp_nvram_hdr);
	nvram_image = malloc(sz);
	assert(nvram_format(nvram_image, sz)==0);
	assert(nvram_check(nvram_image, sz)==0);
	assert(nvram_image[sz-14]==0);
	assert(nvram_image[sz-13]==1);
	h = (struct chrp_nvram_hdr*)(&nvram_image[NVRAM_SIZE_COMMON + NVRAM_SIZE_FW_PRIV]);
	assert(memcmp(h->name, "wwwwwwwwwwww", 12)==0);
	free(nvram_image);

	/* 128k NVRAM check */
	nvram_image = malloc(128*1024);
	assert(nvram_format(nvram_image, 128*1024)==0);
	assert(nvram_check(nvram_image,128*1024)==0);

	/* Now, we corrupt it */
	nvram_image[0] = 0;
	assert(nvram_check(nvram_image,128*1024) != 0);

	/* Does our NUL checking work? */
	assert(nvram_format(nvram_image, 128 * 1024) == 0);
	h = (struct chrp_nvram_hdr *) nvram_image;
	memset((char *) h + sizeof(*h), 0xFF, be16_to_cpu(h->len) * 16 - sizeof(*h));
	assert(nvram_check(nvram_image, 128 * 1024) != 0);

	assert(nvram_format(nvram_image, 128*1024)==0);
	/* corrupt the length of the partition */
	nvram_image[2] = 0;
	nvram_image[3] = 0;
	assert(nvram_check(nvram_image,128*1024) != 0);

	assert(nvram_format(nvram_image, 128*1024)==0);
	/* corrupt the length of the partition */
	nvram_image[2] = 0;
	nvram_image[3] = 0;
	/* but reset checksum! */
	h = (struct chrp_nvram_hdr*)nvram_image;
	h->cksum = chrp_nv_cksum(h);
	assert(nvram_check(nvram_image,128*1024) != 0);

	assert(nvram_format(nvram_image, 128*1024)==0);
	/* make the length insanely beyond end of nvram  */
	nvram_image[2] = 42;
	nvram_image[3] = 32;
	/* but reset checksum! */
	h = (struct chrp_nvram_hdr*)nvram_image;
	h->cksum = chrp_nv_cksum(h);
	assert(nvram_check(nvram_image,128*1024) != 0);

	assert(nvram_format(nvram_image, 128*1024)==0);
	/* remove skiboot partition */
	nvram_image[12] = '\0';
	/* but reset checksum! */
	h = (struct chrp_nvram_hdr*)nvram_image;
	h->cksum = chrp_nv_cksum(h);
	assert(nvram_check(nvram_image,128*1024) != 0);

	assert(nvram_format(nvram_image, 128*1024)==0);
	/* remove common partition */
	nvram_image[NVRAM_SIZE_FW_PRIV+5] = '\0';
	/* but reset checksum! */
	h = (struct chrp_nvram_hdr*)(&nvram_image[NVRAM_SIZE_FW_PRIV]);
	h->cksum = chrp_nv_cksum(h);
	assert(nvram_check(nvram_image,128*1024) != 0);

	/* test nvram_query() */

	/* does an empty partition break us? */
	data = nvram_reset(nvram_image, 128*1024);
	assert(nvram_query_safe("test") == NULL);

	/* does a zero length key break us? */
	data = nvram_reset(nvram_image, 128*1024);
	data[0] = '=';
	assert(nvram_query_safe("test") == NULL);

	/* does a missing = break us? */
	data = nvram_reset(nvram_image, 128*1024);
	data[0] = 'a';
	assert(nvram_query_safe("test") == NULL);

	/* does an empty value break us? */
	data = nvram_reset(nvram_image, 128*1024);
	data[0] = 'a';
	data[1] = '=';
	result = nvram_query_safe("a");
	assert(result);
	assert(strlen(result) == 0);

	/* do we trip over malformed keys? */
	data = nvram_reset(nvram_image, 128*1024);
#define TEST_1 "a\0a=\0test=test\0"
	memcpy(data, TEST_1, sizeof(TEST_1));
	result = nvram_query_safe("test");
	assert(result);
	assert(strcmp(result, "test") == 0);

	free(nvram_image);

	return 0;
}
