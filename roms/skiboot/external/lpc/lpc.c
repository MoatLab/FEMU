// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * LPC operations through debugfs interface
 *
 * Copyright 2014-2018 IBM Corp.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <byteswap.h>
#include <stdint.h>
#include <stdbool.h>
#include <getopt.h>
#include <limits.h>
#include <arpa/inet.h>
#include <assert.h>
#include <endian.h>
#include <byteswap.h>

#define SYSFS_PREFIX "/sys/kernel/debug/powerpc/lpc"

int main(int argc, char *argv[])
{
	char		path[256];
	char		*dot;
	char		*eq;
	int		fd, size = 4;
	bool		do_write = false;
	bool		big_endian = false;
	uint32_t	addr, val;
	ssize_t		rc;

	if (argc < 3) {
		printf("Usage: %s <space> <addr>[.lLwWbBd[,size]][=value]\n", argv[0]);
		return 0;
	}

	eq = strchr(argv[2], '=');
	if (eq) {
		do_write = true;
		val = strtoul(eq + 1, NULL, 0);
		*eq = 0;
	}
	dot = strchr(argv[2], '.');
	if (dot) {
		*(dot++) = 0;
		switch(*dot) {
		case 'L':
			big_endian  = true;
		case 'l':
			break;
		case 'W':
			big_endian  = true;
		case 'w':
			size = 2;
			break;
		case 'B':
			big_endian  = true;
		case 'b':
			size = 1;
			break;
		default:
			fprintf(stderr, "Invalid size specifier\n");
			exit(1);
		}
	}
	addr = strtoul(argv[2], NULL, 0);

	memset(path, 0, sizeof(path));
	snprintf(path, 255, SYSFS_PREFIX "/%s", argv[1]);
	fd = open(path, O_RDWR);
	if (fd < 0) {
		perror("Failed to open sysfs file");
		exit(1);
	}

	lseek(fd, addr, SEEK_SET);
	if (do_write)  {
		uint8_t v8;
		uint16_t v16;
		uint32_t v32;

		switch(size) {
		case 1:
			val &= 0xff;
			v8 = val;
			rc = write(fd, &v8, 1);
			if (rc != 1) {
				perror("Failed to write to LPC");
				exit(1);
			}
			printf("[%s] W 0x%08x.%c=0x%02x\n",
			       argv[1], addr, big_endian ? 'B' : 'b', val);
			break;
		case 2:
			val &= 0xffff;
#if __BYTE_ORDER == __LITTLE_ENDIAN
			v16 = big_endian ? bswap_16(val) : val;
#else
			v16 = big_endian ? val : bswap_16(val);
#endif
			rc = write(fd, &v16, 2);
			if (rc != 2) {
				perror("Failed to write to LPC");
				exit(1);
			}
			printf("[%s] W 0x%08x.%c=0x%04x\n",
			       argv[1], addr, big_endian ? 'W' : 'w', val);
			break;
		default:
#if __BYTE_ORDER == __LITTLE_ENDIAN
			v32 = big_endian ? bswap_32(val) : val;
#else
			v32 = big_endian ? val : bswap_32(val);
#endif
			rc = write(fd, &v32, 4);
			if (rc != 4) {
				perror("Failed to write to LPC");
				exit(1);
			}
			printf("[%s] W 0x%08x.%c=0x%08x\n",
			       argv[1], addr, big_endian ? 'L' : 'l', val);
			break;
		}
	} else {
		uint8_t v8;
		uint16_t v16;
		uint32_t v32;

		switch(size) {
		case 1:
			rc = read(fd, &v8, 1);
			if (rc != 1) {
				perror("Failed to read from LPC");
				exit(1);
			}
			printf("[%s] R 0x%08x.%c=0x%02x\n", argv[1], addr,
			       big_endian ? 'B' : 'b', v8);
			break;
		case 2:
			rc = read(fd, &v16, 2);
			if (rc != 2) {
				perror("Failed to read from LPC");
				exit(1);
			}
#if __BYTE_ORDER == __LITTLE_ENDIAN
			v16 = big_endian ? bswap_16(v16) : v16;
#else
			v16 = big_endian ? v16 : bswap_16(v16);
#endif
			printf("[%s] R 0x%08x.%c=0x%04x\n", argv[1], addr,
			       big_endian ? 'W' : 'w', v16);
			break;
		default:
			rc = read(fd, &v32, 4);
			if (rc != 4) {
				perror("Failed to read from LPC");
				exit(1);
			}
#if __BYTE_ORDER == __LITTLE_ENDIAN
			v32 = big_endian ? bswap_32(v32) : v32;
#else
			v32 = big_endian ? v32 : bswap_32(v32);
#endif
			printf("[%s] R 0x%08x.%c=0x%08x\n", argv[1], addr,
			       big_endian ? 'L' : 'l', v32);
			break;
		}
	}
	return 0;
}
