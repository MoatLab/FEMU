/******************************************************************************
 * Copyright (c) 2008, 2009 Adrian Reber
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     Adrian Reber - initial implementation
 *****************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <byteswap.h>
#include <getopt.h>
#include <time.h>
#include <errno.h>

#include <calculatecrc.h>
#include <crclib.h>

#define VERSION 1

#ifdef _BIG_ENDIAN
#define cpu_to_be64(x)  (x)
#define be64_to_cpu(x)  (x)
#define be16_to_cpu(x)  (x)
#define be32_to_cpu(x)  (x)
#else
#define cpu_to_be64(x)  bswap_64(x)
#define be64_to_cpu(x)  bswap_64(x)
#define be16_to_cpu(x)  bswap_16(x)
#define be32_to_cpu(x)  bswap_32(x)
#endif


/* no board dependencies wanted here, let's hardcode SLOF's
 * magic strings here */

#define FLASHFS_MAGIC "magic123"
#define FLASHFS_PLATFORM_MAGIC "JS2XBlade"
#define FLASHFS_PLATFORM_REVISION "1"

/* there seems to be no structure defined anywhere in the code
 * which resembles the actual sloffs/romfs file header;
 * so defining it here for now */

struct sloffs {
	uint64_t next;
	uint64_t len;
	uint64_t flags;
	uint64_t data;
	char *name;
};

/* sloffs metadata size:
 * 4 * 8: 4 * uint64_t + (filename length) */
#define SLOFFS_META (4 * 8)
#define ALIGN64(x) (((x) + 7) & ~7)

static struct sloffs *
next_file_mm(struct sloffs *sloffs)
{
	return (struct sloffs *)((unsigned char *)sloffs +
				 be64_to_cpu(sloffs->next));
}

static int
next_file(const int fd, struct sloffs *sloffs)
{
	int ret;
	uint64_t size;
	uint64_t offset;
	char *name;

	offset = 0;

	/* if sloffs is not all NULL we want the next file
	 * else we just take the first file */
	if (sloffs->name && sloffs->len && sloffs->data) {
		offset = be64_to_cpu(sloffs->next);
		/* we already read over the header; skip it in the seek */
		offset -= be64_to_cpu(sloffs->data);
		free(sloffs->name);
		sloffs->name = NULL;
		lseek(fd, offset, SEEK_CUR);
	} else {
		lseek(fd, offset, SEEK_SET);
	}

	ret = read(fd, sloffs, SLOFFS_META);
	if (ret == -1)
		return -1;
	/* read the size of the header */
	size = be64_to_cpu(sloffs->data);
	/* get the size of the filename */
	size -= SLOFFS_META;
	name = malloc(size);

	ret = read(fd, name, size);
	if (ret == -1) {
		free(name);
		return -1;
	}
	sloffs->name = name;
	return 0;
}

static struct sloffs *
find_file_mm(const void *data, const char *name)
{
	struct sloffs *sloffs = (struct sloffs *)data;

	for (;;) {
		if (!strcmp((char *)&sloffs->name, name))
			return sloffs;

		if (be64_to_cpu(sloffs->next) == 0)
			break;
		sloffs = next_file_mm(sloffs);
	}
	return NULL;
}

static struct sloffs *
find_file(const int fd, const char *name, struct sloffs *sloffs)
{
	memset(sloffs, 0, sizeof(struct sloffs));

	if (next_file(fd, sloffs))
		return NULL;

	for (;;) {
		if (!strcmp(sloffs->name, name))
			return sloffs;

		if (be64_to_cpu(sloffs->next) == 0)
			break;
		if (next_file(fd, sloffs))
			return NULL;
	}

	free(sloffs->name);
	return NULL;
}

static struct stH *
sloffs_header_mm(const void *data)
{
	struct sloffs *sloffs;
	struct stH *header;

	/* find the "header" file with all the information about
	 * the flash image */
	sloffs = find_file_mm(data, "header");
	if (!sloffs) {
		printf("sloffs file \"header\" not found. aborting...\n");
		return NULL;
	}

	header = (struct stH *)((unsigned char *)sloffs +
				be64_to_cpu(sloffs->data));
	return header;
}

static struct stH *
sloffs_header(const int fd)
{
	struct sloffs file;
	struct sloffs *sloffs;
	struct stH *header;
	ssize_t rc;

	header = (struct stH *)malloc(sizeof(struct stH));

	/* find the "header" file with all the information about
	 * the flash image */
	sloffs = find_file(fd, "header", &file);
	if (!sloffs) {
		printf("sloffs file \"header\" not found. aborting...\n");
		return NULL;
	}

	rc = read(fd, header, sizeof(struct stH));
	if (rc != sizeof(struct stH)) {
		printf("Reading header, rc %ld, errno %d\n", rc, errno);
		free(header);
		header = NULL;
	}
	free(sloffs->name);
	return header;
}

static uint64_t
header_length_mm(const void *data)
{
	struct sloffs *sloffs;

	/* find the "header" file with all the information about
	 * the flash image */
	sloffs = find_file_mm(data, "header");
	if (!sloffs) {
		printf("sloffs file \"header\" not found. aborting...\n");
		return 0;
	}
	return be64_to_cpu(sloffs->len);
}

static uint64_t
header_length(const int fd)
{
	struct sloffs file;
	struct sloffs *sloffs;

	/* find the "header" file with all the information about
	 * the flash image */
	sloffs = find_file(fd, "header", &file);
	if (!sloffs) {
		printf("sloffs file \"header\" not found. aborting...\n");
		return 0;
	}

	free(sloffs->name);
	return be64_to_cpu(sloffs->len);
}

static void
update_modification_time(struct stH *header)
{
	struct tm *tm;
	time_t caltime;
	char dastr[16] = { 0, };
	uint64_t date;

	/* update modification date
	 * copied from create_crc.c */
	caltime = time(NULL);
	tm = localtime(&caltime);
	strftime(dastr, 15, "0x%Y%m%d%H%M", tm);
	date = cpu_to_be64(strtoll(dastr, NULL, 16));

	/* this does not match the definition from
	 * struct stH, but we immitate the bug from
	 * flash image creation in create_crc.c.
	 * The date is in mdate and time in padding2. */
	memcpy(&(header->mdate), &date, 8);
}

static void
update_crc(void *data)
{
	uint64_t crc;
	struct stH *header = sloffs_header_mm(data);
	uint64_t len = be64_to_cpu(header->flashlen);

	/* calculate header CRC */
	header->ui64CRC = 0;
	crc = checkCRC(data, header_length_mm(data), 0);
	header->ui64CRC = cpu_to_be64(crc);
	/* calculate flash image CRC */
	crc = checkCRC(data, len, 0);
	*(uint64_t *)(data + len - 8) = cpu_to_be64(crc);
}

static uint64_t
check_image_crc(const int fd, uint64_t len)
{
	uint64_t crc;
	uint64_t i;
	uint64_t read_bytes;
	unsigned char buffer[4096];

	lseek(fd, 0, SEEK_SET);
	crc = 0;
	read_bytes = 0;
	while (read_bytes < len) {
		i = read(fd, buffer, 4096);
		read_bytes += i;
		if (read_bytes > len)
			i -= read_bytes - len;
		crc = calCRCword(buffer, i, crc);
	}
	return crc;
}
static void
sloffs_append(const int file, const char *name, const char *dest)
{
	void *append;
	unsigned char *write_data;
	void *write_start;
	int fd;
	int out;
	struct stat stat;
	struct stH *header;
	uint64_t new_len;
	struct sloffs *sloffs;
	struct sloffs new_file;
	uint64_t read_len;
	int i;
	ssize_t rc;

	fd = open(name, O_RDONLY);

	if (fd == -1) {
		perror(name);
		exit(1);
	}

	fstat(fd, &stat);
	append = mmap(NULL, stat.st_size, PROT_READ, MAP_SHARED, fd, 0);
	header = sloffs_header(file);

	if (!header)
		return;

	new_len = ALIGN64(stat.st_size) + be64_to_cpu(header->flashlen);
	/* add the length of the sloffs file meta information */
	new_len += SLOFFS_META;
	/* add the length of the filename */
	new_len += ALIGN64(strlen(name) + 1);

	out = open(dest, O_CREAT | O_RDWR | O_TRUNC, 00666);

	if (out == -1) {
		perror(dest);
		exit(1);
	}

	/* write byte at the end to be able to mmap it */
	lseek(out, new_len - 1, SEEK_SET);
	rc = write(out, "", 1);
	if (rc != 1) {
		printf("Extending file failed, rc %ld, errno %d\n", rc, errno);
		exit(1);
	}
	write_start = mmap(NULL, new_len, PROT_READ | PROT_WRITE,
			   MAP_SHARED, out, 0);

	memset(write_start, 0, new_len);
	memset(&new_file, 0, sizeof(struct sloffs));

	new_file.len = cpu_to_be64(stat.st_size);
	new_file.data = cpu_to_be64(SLOFFS_META + ALIGN64(strlen(name) + 1));

	if (write_start == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}

	lseek(file, 0, SEEK_SET);
	write_data = write_start;
	read_len = be64_to_cpu(header->flashlen);
	for (;;) {
		i = read(file, write_data, read_len);
		if (i < 0) {
			perror("read");
			exit(1);
		}
		if (i == 0)
			break;
		write_data += i;
		read_len -= i;
	}
	/* -8: overwrite old CRC */
	write_data = write_start + be64_to_cpu(header->flashlen) - 8;
	memcpy(write_data, &new_file, SLOFFS_META);
	write_data += SLOFFS_META;
	/* write the filename */
	memcpy(write_data, name, strlen(name));
	write_data += ALIGN64(strlen(name) + 1 );
	memcpy(write_data, append, stat.st_size);

	write_data = write_start;

	/* find last file */
	sloffs = (struct sloffs *)write_start;
	for (;;) {
		if (be64_to_cpu(sloffs->next) == 0)
			break;
		sloffs = next_file_mm(sloffs);
	}
	/* get the distance to the next file */
	sloffs->next = ALIGN64(be64_to_cpu(sloffs->len));
	/* and the offset were the data starts */
	sloffs->next += be64_to_cpu(sloffs->data);
	/* and we have to skip the end of file marker
	 * if one is there; if the last uint64_t is -1
	 * it is an end of file marker; this is a bit dangerous
	 * but there is no other way to detect the end of
	 * file marker */
	if ((uint64_t)be64_to_cpu(*(uint64_t *)((unsigned char *)sloffs +
						sloffs->next)) == (uint64_t)-1ULL)
		sloffs->next += 8;

	sloffs->next = cpu_to_be64(sloffs->next);

	free(header);
	/* update new length of flash image */
	header = sloffs_header_mm(write_start);
	header->flashlen = cpu_to_be64(new_len);

	update_modification_time(header);

	update_crc(write_start);

	munmap(append, stat.st_size);
	munmap(write_start, new_len);
	close(fd);
	close(out);
}

static void print_header_date(void *dptr)
{
	uint8_t *date = dptr;

	if (date[2] || date[3] || date[4] || date[5] || date[6] || date[7]) {
		printf("%02x%02x-%02x-%02x %02x:%02x", date[2], date[3],
		       date[4], date[5], date[6], date[7]);
	} else {
		printf("N/A");
	}

}

static void
sloffs_dump(const int fd)
{
	void *data;
	struct stH *header;
	struct sloffs file;
	int i;
	uint64_t crc;
	uint64_t header_len;
	ssize_t rc;

	header = sloffs_header(fd);

	if (!header)
		return;

	if (memcmp(FLASHFS_MAGIC, header->magic, strlen(FLASHFS_MAGIC))) {
		printf("sloffs magic not found. "
		       "probably not a valid SLOF flash image. aborting...\n");
		return;
	}
	printf("  Magic       : %s\n", header->magic);
	printf("  Platform    : %s\n", header->platform_name);
	printf("  Version     : %s\n", header->version);
	/* there is a bug in the date position;
	 * it should be at header->date, but it is at (header->date + 2) */
	printf("  Build Date  : ");
	print_header_date(header->date);
	printf("\n");
	printf("  Modify Date : ");
	print_header_date(header->mdate);
	printf("\n");
	printf("  Image Length: %ld", be64_to_cpu(header->flashlen));
	printf(" (0x%lx) bytes\n", be64_to_cpu(header->flashlen));
	printf("  Revision    : %s\n", header->platform_revision);
	crc = be64_to_cpu(header->ui64CRC);
	printf("  Header CRC  : 0x%016lx CRC check: ", crc);
	/* to test the CRC of the header we need to know the actual
	 * size of the file and not just the size of the data
	 * which could be easily obtained with sizeof(struct stH);
	 * the actual size can only be obtained from the filesystem
	 * meta information */
	header_len = header_length(fd);
	/* no copy the header to memory to crc test it */
	data = malloc(header_len);
	lseek(fd, 0, SEEK_SET);
	rc = read(fd, data, header_len);
	if (rc != (ssize_t) header_len) {
		printf("Reading header failed, rc %zd, errno %d\n", rc, errno);
		return;
	}
	crc = calCRCword((unsigned char *)data, header_length(fd), 0);
	free(data);
	if (!crc)
		printf("[OK]");
	else
		printf("[FAILED]");
	printf("\n");

	crc = be64_to_cpu(header->flashlen);
	/* move to the CRC */
	lseek(fd, crc - 8, SEEK_SET);
	/* read it */
	rc = read(fd, &crc, 8);
	if (rc != 8) {
		printf("Reading crc failed, rc %zd, errno %d\n", rc, errno);
		return;
	}
	crc = be64_to_cpu(crc);
	printf("  Image CRC   : 0x%016lx CRC check: ", crc);
	crc = check_image_crc(fd, be64_to_cpu(header->flashlen));
	if (!crc)
		printf("[OK]");
	else
		printf("[FAILED]");
	printf("\n");

	/* count number of files */
	i = 0;
	memset(&file, 0, sizeof(struct sloffs));
	if (next_file(fd, &file))
		return;
	for (;;) {
		i++;

		if (be64_to_cpu(file.next) == 0)
			break;
		if (next_file(fd, &file))
			return;
	}
	free(file.name);
	printf("  Files       : %d\n", i);
	free(header);
}

static void
sloffs_list(const int fd)
{
	const char *name_header = "File Name";
	unsigned int i;
	unsigned int max;
	unsigned int line;
	struct sloffs file;
	uint64_t offset = 0;

	memset(&file, 0, sizeof(struct sloffs));

	if (next_file(fd, &file))
		return;

	/* find largest name */
	max = strlen(name_header);
	for (;;) {
		if (max < strlen((char *)file.name))
			max = strlen((char *)file.name);

		if (be64_to_cpu(file.next) == 0)
			break;
		if (next_file(fd, &file))
			return;
	}

	free(file.name);


	/* have at least two spaces between name and size column */
	max += 2;

	/* header for listing */
	line = printf("   Offset      ");
	line += printf("%s", name_header);
	for (i = 0; i < max - strlen(name_header); i++)
		line += printf(" ");
	line += printf("Size                ");
	line += printf("Flags\n");
	printf("   ");
	for (i = 0; i <= line; i++)
		printf("=");
	printf("\n");

	memset(&file, 0, sizeof(struct sloffs));

	if (next_file(fd, &file))
		return;

	for (;;) {
		printf("   0x%08lx", offset);
		offset += be64_to_cpu(file.next);
		printf("  %s", file.name);
		for (i = 0; i < max - strlen(file.name); i++)
			printf(" ");

		printf("%07ld ", be64_to_cpu(file.len));
		printf("(0x%06lx)", be64_to_cpu(file.len));
		printf("  0x%08lx\n", be64_to_cpu(file.flags));

		if (be64_to_cpu(file.next) == 0)
			break;
		if (next_file(fd, &file))
			return;
	}
	free(file.name);
}

static void
sloffs_copy(const int file, const char *name)
{
	uint64_t len;
	int out;
	unsigned char *write_buf;
	int i;
	struct stH *header;
	ssize_t rc;

	header = sloffs_header(file);

	if (!header)
		return;

	len = be64_to_cpu(header->flashlen);
	free(header);

	out = open(name, O_CREAT | O_RDWR | O_TRUNC, 00666);

	if (out == -1) {
		perror(name);
		exit(1);
	}
	/* write byte at the end to be able to mmap it */
	lseek(out, len - 1, SEEK_SET);
	rc = write(out, "", 1);
	if (rc != 1) {
		printf("Extending file failed, rc %zd, errno %d\n", rc, errno);
		exit(1);
	}
	write_buf = mmap(NULL, len, PROT_WRITE, MAP_SHARED, out, 0);

	if (write_buf == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}

	lseek(file, 0, SEEK_SET);

	for (;;) {
		i = read(file, write_buf, len);
		if (i < 0) {
			perror("read");
			exit(1);
		}
		if (i == 0)
			break;
		write_buf += i;
		len -= i;
	}

	munmap(write_buf, len);
	close(out);
}

static void
usage(void)
{
	printf("sloffs lists or changes a SLOF flash image\n\n");
	printf("Usage:\n");
	printf("  sloffs [OPTION]... [FILE]\n\n");
	printf("Options:\n");
	printf("  -h, --help             show this help, then exit\n");
	printf("  -l, --list             list all files in the flash image\n");
	printf("  -v, --version          print the version, then exit\n");
	printf("  -d, --dump             dump the information from the header\n");
	printf("  -a, --append=FILENAME  append file at the end of\n");
	printf("                         the existing image\n");
	printf("  -o, --output=FILENAME  if appending a file this parameter\n");
	printf("                         is necessary to specify the name of\n");
	printf("                         the output file\n");
	printf("  -c, --copy=FILENAME    copy SLOF image to specified file\n");
	printf("                         this is especially useful if the\n");
	printf("                         source file is /dev/slof_flash\n");
	printf("\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	int fd;
	const struct option loption[] = {
		{ "help", 0, NULL, 'h' },
		{ "list", 0, NULL, 'l' },
		{ "version", 0, NULL, 'v' },
		{ "dump", 0, NULL, 'd' },
		{ "append", 1, NULL, 'a' },
		{ "output", 1, NULL, 'o' },
		{ "copy", 1, NULL, 'o' },
		{ 0, 0, 0, 0 }
	};
	const char *soption = "dhlva:o:c:";
	int c;
	char mode = 0;
	char *append = NULL;
	char *output = NULL;

	for (;;) {
		c = getopt_long(argc, argv, soption, loption, NULL);
		if (c == -1)
			break;
		switch (c) {
		case 'l':
			mode = 'l';
			break;
		case 'v':
			printf("sloffs (version %d)\n", VERSION);
			exit(0);
		case 'd':
			mode = 'd';
			break;
		case 'a':
			mode = 'a';
			append = strdup(optarg);
			break;
		case 'o':
			output = strdup(optarg);
			break;
		case 'c':
			mode = 'c';
			output = strdup(optarg);
			break;
		case 'h':
		default:
			usage();
		}
	}

	if (optind >= argc)
		usage();

	fd = open(argv[optind], O_RDONLY);

	if (fd == -1) {
		perror(argv[optind]);
		exit(1);
	}

	lseek(fd, 0, SEEK_SET);

	switch (mode) {
	case 'l':
		sloffs_list(fd);
		break;
	case 'd':
		sloffs_dump(fd);
		break;
	case 'a':
		if (!output) {
			printf("sloffs requires -o, --output=FILENAME"
			       " when in append mode\n\n");
			usage();
		}
		sloffs_append(fd, append, output);
		break;
	case 'c':
		sloffs_copy(fd, output);
		break;
	}

	free(append);
	free(output);
	close(fd);
	return 0;
}
