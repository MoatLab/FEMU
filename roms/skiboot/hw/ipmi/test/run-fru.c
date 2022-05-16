// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#define __TEST__

#include "../ipmi-fru.c"

#include <string.h>

int error = 0;

const char version[] = "a-too-long-version-test-string-is-here";

void ipmi_free_msg(struct ipmi_msg __unused *msg)
{
}

void ipmi_init_msg(struct ipmi_msg __unused *msg, int __unused interface,
		   uint32_t __unused code,
		   void __unused (*complete)(struct ipmi_msg *),
		   void __unused *user_data, size_t __unused req_size,
		   size_t __unused resp_size)
{
}

struct ipmi_msg *ipmi_mkmsg(int __unused interface, uint32_t __unused code,
			    void __unused (*complete)(struct ipmi_msg *),
			    void __unused *user_data, void __unused *req_data, size_t __unused req_size,
			    size_t __unused resp_size)
{
	return NULL;
}

int ipmi_queue_msg(struct ipmi_msg __unused *msg)
{
	return 0;
}

void _prlog(int __unused log_level, const __unused char* fmt, ...)
{
	return;
}

int main(void)
{
	u8 *buf;
	int len;
	struct product_info info = {
		.manufacturer = (char *) "IBM",
		.product = (char *) "skiboot",
		.part_no = (char *) "hello",
		.version = (char *) "12345",
		.serial_no = (char *) "12345",
		.asset_tag = (char *) "abcd",
	};
	struct product_info invalid_info = {
		.manufacturer = (char *) "I",
		.product = (char *) "skiboot",
		.part_no = (char *) "hello",
		.version = (char *) "12345",
		.serial_no = (char *) "12345",
		.asset_tag = (char *) "abcd",
	};
	struct product_info invalid_info2 = {
		.manufacturer = (char *) "IBM",
		.product = (char *) "skiboot",
		.part_no = (char *) "this is a really long string that's more"
		"than 32 characters, because it turns out that's invalid.",
		.version = (char *) "12345",
		.serial_no = (char *) "12345",
		.asset_tag = (char *) "abcd",
	};

	buf = malloc(256);

	len = fru_fill_product_info(buf, &info, 40);
	assert(len == 40);
	assert(memcmp(buf, "\001\005\000\303IBM\307skiboot\305hello"
		      "\30512345\30512345\304abcd\301-",len) == 0);


	/* Make sure the checksum is right */
	assert(!fru_checksum(buf, len));

	/* This should fail (not enough space) */
	assert(fru_fill_product_info(buf, &info, 39) < 0);

	memset(buf, 0, 256);
	len = fru_fill_product_info(buf, &invalid_info, 40);
	assert(len == OPAL_PARAMETER);

	memset(buf, 0, 256);
	len = fru_fill_product_info(buf, &invalid_info2, 256);
	assert(len == OPAL_PARAMETER);

	memset(buf, 0, 256);
	assert(fru_add(buf, 256) > 0);
	assert(0 == memcmp(&buf[64], "\001\a\000\303IBM\307skiboot\300"
			   "\337a-too-long-version-test-string+\300\300\301"
			   "\0\0\0",54));


	memset(buf, 0, 256);
	assert(fru_add(buf, 1) == OPAL_PARAMETER);

	memset(buf, 0, 256);
	assert(fru_add(buf, 65) == OPAL_PARAMETER);

	free(buf);

	return 0;
}
