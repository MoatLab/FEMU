// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Fill out firmware related FRUs (Field Replaceable Units)
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <skiboot.h>
#include <stdlib.h>
#include <string.h>
#include <ipmi.h>
#include <lock.h>
#include <opal.h>
#include <device.h>

struct product_info {
	char *manufacturer;
	char *product;
	char *part_no;
	char *version;
	char *serial_no;
	char *asset_tag;
};

struct common_header {
	u8 version;
	u8 internal_offset;
	u8 chassis_offset;
	u8 board_offset;
	u8 product_offset;
	u8 multirecord_offset;
	u8 pad;
	u8 checksum;
} __packed;

/* The maximum amount of FRU data we can store. */
#define FRU_DATA_SIZE 256

/* We allocate two bytes at these locations in the data array to track
 * state. */
#define WRITE_INDEX 256
#define REMAINING 257

/* The ASCII string encoding used only has 5 bits to encode length
 * hence the maximum is 31 characters. */
#define MAX_STR_LEN 31

static u8 fru_dev_id = 0;

static int fru_insert_string(u8 *buf, char *str)
{
	int len = strlen(str);

	/* The ASCII type/length format only supports a string length
	 * between 2 and 31 characters. Zero characters is ok though
	 * as it indicates no data present. */
	if (len == 1 || len > MAX_STR_LEN)
		return OPAL_PARAMETER;

	buf[0] = 0xc0 | len;
	memcpy(&buf[1], str, len);

	return len + 1;
}

static u8 fru_checksum(u8 *buf, int len)
{
	int i;
	u8 checksum = 0;

	for(i = 0; i < len; i++) {
		checksum += buf[i];
	}
	checksum = ~checksum + 1;
	return checksum;
}

#define FRU_INSERT_STRING(x, y)						\
	({ rc = fru_insert_string(x, y);				\
	 { if (rc < 1) return OPAL_PARAMETER; } rc; })

static int fru_fill_product_info(u8 *buf, struct product_info *info, size_t size)
{
	size_t total_size = 11;
	int index = 0;
	int rc;

	total_size += strlen(info->manufacturer);
	total_size += strlen(info->product);
	total_size += strlen(info->part_no);
	total_size += strlen(info->version);
	total_size += strlen(info->serial_no);
	total_size += strlen(info->asset_tag);
	total_size += (8 - (total_size % 8)) % 8;
	if (total_size > size)
		return OPAL_PARAMETER;

	buf[index++] = 0x1;		/* Version */
	buf[index++] = total_size / 8;	/* Size */
	buf[index++] = 0;		/* Language code (English) */

	index += FRU_INSERT_STRING(&buf[index], info->manufacturer);
	index += FRU_INSERT_STRING(&buf[index], info->product);
	index += FRU_INSERT_STRING(&buf[index], info->part_no);
	index += FRU_INSERT_STRING(&buf[index], info->version);
	index += FRU_INSERT_STRING(&buf[index], info->serial_no);
	index += FRU_INSERT_STRING(&buf[index], info->asset_tag);

	buf[index++] = 0xc1;		/* End of data marker */
	memset(&buf[index], 0, total_size - index - 1);
	index += total_size - index - 1;
	buf[index] = fru_checksum(buf, index);
	assert(index == total_size - 1);

	return total_size;
}

static int fru_add(u8 *buf, int size)
{
	int len;
	struct common_header common_hdr;
	char *short_version;
	struct product_info info = {
		.manufacturer = (char *) "IBM",
		.product = (char *) "skiboot",
		.part_no = (char *) "",
		.serial_no = (char *) "",
		.asset_tag = (char *) "",
	};

	if (size < sizeof(common_hdr))
		return OPAL_PARAMETER;

	/* We currently only support adding the version number at the
	 * product information offset. We choose an offset of 64 bytes
	 * because that's what the standard recommends. */
	common_hdr.version = 1;
	common_hdr.internal_offset = 0;
	common_hdr.chassis_offset = 0;
	common_hdr.board_offset = 0;
	common_hdr.product_offset = 64/8;
	common_hdr.multirecord_offset = 0;
	common_hdr.pad = 0;
	common_hdr.checksum = fru_checksum((u8 *) &common_hdr, sizeof(common_hdr) - 1);
	memcpy(buf, &common_hdr, sizeof(common_hdr));

	short_version = strdup(version);
	info.version = short_version;
	if (!strncmp(version, "skiboot-", 8))
		info.version = &short_version[8];

	if (strlen(info.version) >= MAX_STR_LEN) {
		if (info.version[MAX_STR_LEN] != '\0')
			info.version[MAX_STR_LEN - 1] = '+';
		info.version[MAX_STR_LEN] = '\0';
	}

	len = fru_fill_product_info(&buf[64], &info, size - 64);
	free(short_version);
	if (len < 0)
		return OPAL_PARAMETER;

	return len + 64;
}

static void fru_write_complete(struct ipmi_msg *msg)
{
	u8 write_count = msg->data[0];
	u16 offset;

	msg->data[WRITE_INDEX] += write_count;
	msg->data[REMAINING] -= write_count;
	if (msg->data[REMAINING] == 0)
		goto out;

	offset = msg->data[WRITE_INDEX];
	ipmi_init_msg(msg, IPMI_DEFAULT_INTERFACE, IPMI_WRITE_FRU,
		      fru_write_complete, NULL,
		      MIN(msg->data[REMAINING] + 3, IPMI_MAX_REQ_SIZE), 2);

	memmove(&msg->data[3], &msg->data[offset + 3], msg->req_size - 3);

	msg->data[0] = fru_dev_id;     		/* FRU Device ID */
	msg->data[1] = offset & 0xff;		/* Offset LSB */
	msg->data[2] = (offset >> 8) & 0xff;	/* Offset MSB */

	ipmi_queue_msg(msg);

	return;

out:
	ipmi_free_msg(msg);
}

static int fru_write(void)
{
	struct ipmi_msg *msg;
	int len;

	/* We allocate FRU_DATA_SIZE + 5 bytes for the message:
	 * - 3 bytes for the the write FRU command header
	 * - FRU_DATA_SIZE bytes for FRU data
	 * - 2 bytes for offset & bytes remaining count
	 */
	msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE, IPMI_WRITE_FRU,
			 fru_write_complete, NULL, NULL, FRU_DATA_SIZE + 5, 2);
	if (!msg)
		return OPAL_RESOURCE;

	msg->data[0] = fru_dev_id;	/* FRU Device ID */
	msg->data[1] = 0x0;		/* Offset LSB (we always write a new common header) */
	msg->data[2] = 0x0;		/* Offset MSB */
	len = fru_add(&msg->data[3], FRU_DATA_SIZE);

	if (len < 0)
		return len;

	/* Three bytes for the actual FRU Data Command */
	msg->data[WRITE_INDEX] = 0;
	msg->data[REMAINING] = len;
	msg->req_size = MIN(len + 3, IPMI_MAX_REQ_SIZE);
	return ipmi_queue_msg(msg);
}

void ipmi_fru_init(u8 dev_id)
{
	fru_dev_id = dev_id;
	fru_write();

	return;
}
