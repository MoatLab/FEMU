// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2015-2016 IBM Corp */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <mtd/mtd-user.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#undef ioctl
#define ioctl(d, req, arg) test_ioctl(d, req, arg)

int test_ioctl(int fd, int req, void *arg)
{
	if (req == MEMERASE) {
		uint8_t *buf;
		struct erase_info_user *erase = arg;

		buf = malloc(erase->length);
		memset(buf, 'E', erase->length);

		lseek(fd, erase->start, SEEK_SET);
		write(fd, buf, erase->length);

		free(buf);
	}

	return 0;
}

#include "../pnor.c"

bool compare_data(int fd, const uint8_t *check)
{
	uint8_t buf[16];
	int offset = 0;
	int bytes_read;
	int i;

	lseek(fd, 0, SEEK_SET);

	do {
		bytes_read = read(fd, buf, sizeof(buf));
		i = 0;
		while (i < bytes_read)
			if (buf[i++] != check[offset++])
				return false;
	} while (bytes_read == sizeof(buf));

out:
	lseek(fd, 0, SEEK_SET);

	return true;
}

void print_buf(uint8_t *buf, size_t len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (i % 16 == 0)
			printf("\n%06x : ", i);

		printf("%c ", buf[i]);
	}
	printf("\n");
}

void print_file(int fd)
{
	uint8_t buf[16];
	int offset = 0;
	int bytes_read;
	int i;

	lseek(fd, 0, SEEK_SET);

	do {
		bytes_read = read(fd, buf, sizeof(buf));
		if (bytes_read == 0)
			break;
		printf ("%06x : ", offset);
		for (i = 0; i < bytes_read; ++i)
			printf("%c ", buf[i]);
		printf("\n");
		offset += bytes_read;
	} while (bytes_read == sizeof(buf));

	lseek(fd, 0, SEEK_SET);
}

const uint8_t empty[32] = {
	'E', 'E', 'E', 'E', 'E', 'E', 'E', 'E',
	'E', 'E', 'E', 'E', 'E', 'E', 'E', 'E',
	'E', 'E', 'E', 'E', 'E', 'E', 'E', 'E',
	'E', 'E', 'E', 'E', 'E', 'E', 'E', 'E'};

const uint8_t test_one[32] = {
	'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
	'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
	'A', 'A', 'A', 'A', 'A', 'A', 'A', 'E',
	'E', 'E', 'E', 'E', 'E', 'E', 'E', 'E'};

const uint8_t test_three[32] = {
	'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
	'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
	'A', 'A', 'A', 'A', 'A', 'A', 'A', 'E',
	'M', 'M', 'M', 'M', 'M', 'M', 'M', 'M'};

int main(int argc, char **argv)
{
	int fd, i, rc;
	struct pnor pnor;
	uint8_t data[24];
	char filename[24];

	strcpy(filename, "/tmp/pnor-XXXXXX");

	fd = mkstemp(filename);
	if (fd < 0) {
		perror("mkstemp");
		return EXIT_FAILURE;
	}
	/* So the file disappears when we exit */
	unlink(filename);

	/* E for empty */
	memset(data, 'E', sizeof(data));
	for (i = 0; i < 2; i++)
		write(fd, data, 16);

	/* Adjust this if making the file smaller */
	pnor.size = 32;

	/* This is fake. Make it smaller than the size */
	pnor.erasesize = 4;

	printf("Write: ");
	memset(data, 'A', sizeof(data));
	rc = mtd_write(&pnor, fd, data, 0, 23);
	if (rc == 23 && compare_data(fd, test_one))
		printf("PASS\n");
	else
		printf("FAIL: %d\n", rc);

	printf("Read: ");
	memset(data, '0', sizeof(data));
	rc = mtd_read(&pnor, fd, data, 7, 24);
	if (rc == 24 && !memcmp(data, &test_one[7], 24))
		printf("PASS\n");
	else
		printf("FAIL\n");

	printf("Write with offset: ");
	memset(data, 'M', sizeof(data));
	rc = mtd_write(&pnor, fd, data, 24, 8);
	if (rc == 8 && compare_data(fd, test_three))
		printf("PASS\n");
	else
		printf("FAIL\n");

	printf("Write size past the end: ");
	rc = mtd_write(&pnor, fd, data, 0, 64);
	if (rc == -1 && compare_data(fd, test_three))
		printf("PASS\n");
	else
		printf("FAIL: %d\n", rc);

	printf("Write size past the end with offset: ");
	rc = mtd_write(&pnor, fd, data, 24, 24);
	if (rc == -1 && compare_data(fd, test_three))
		printf("PASS\n");
	else
		printf("FAIL\n");

	printf("Write with offset past the end: ");
	rc = mtd_write(&pnor, fd, data, 64, 12);
	if (rc == -1 && compare_data(fd, test_three))
		printf("PASS\n");
	else
		printf("FAIL\n");

	printf("Zero sized write: ");
	rc = mtd_write(&pnor, fd, data, 0, 0);
	if (rc == 0 && compare_data(fd, test_three))
		printf("PASS\n");
	else
		printf("FAIL\n");

	printf("Zero sized write with offset: ");
	rc = mtd_write(&pnor, fd, data, 12, 0);
	if (rc == 0 && compare_data(fd, test_three))
		printf("PASS\n");
	else
		printf("FAIL\n");

	printf("Read size past the end: ");
	rc = mtd_read(&pnor, fd, data, 0, 64);
	if (rc != 0 && compare_data(fd, test_three))
		printf("PASS\n");
	else
		printf("FAIL\n");


	printf("Read size past the end with offset: ");
	rc = mtd_read(&pnor, fd, data, 24, 24);
	if (rc != 0 && compare_data(fd, test_three))
		printf("PASS\n");
	else
		printf("FAIL\n");

	printf("Read with offset past the end: ");
	rc = mtd_read(&pnor, fd, data, 64, 12);
	if (rc != 0 && compare_data(fd, test_three))
		printf("PASS\n");
	else
		printf("FAIL\n");

	printf("Zero sized read: ");
	rc = mtd_read(&pnor, fd, data, 0, 0);
	if (rc == 0 && compare_data(fd, test_three))
		printf("PASS\n");
	else
		printf("FAIL\n");

	printf("Zero sized read with offset: ");
	rc = mtd_read(&pnor, fd, data, 12, 0);
	if (rc == 0 && compare_data(fd, test_three))
		printf("PASS\n");
	else
		printf("FAIL\n");

	return 0;
}
