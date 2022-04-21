// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * getscom
 *
 * Copyright 2014-2017 IBM Corp.
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

#include "xscom.h"

static void print_usage(int code)
{
	printf("usage: putscom [-c|--chip chip-id] [-b|--list-bits] addr value\n");
	printf("       putscom -v|--version\n");
	printf("\n");
	printf("       NB: --list-bits shows which PPC bits are set\n");
	exit(code);
	exit(code);
}

extern const char version[];

int main(int argc, char *argv[])
{
	uint64_t val = -1ull, addr = -1ull;
	uint32_t def_chip, chip_id = 0xffffffff;
	bool got_addr = false, got_val = false;
	bool list_bits = false;
	int rc;

	while(1) {
		static struct option long_opts[] = {
			{"chip",	required_argument,	NULL,	'c'},
			{"help",	no_argument,		NULL,	'h'},
			{"version",	no_argument,		NULL,	'v'},
		};
		int c, oidx = 0;

		c = getopt_long(argc, argv, "-c:bhv", long_opts, &oidx);
		if (c == EOF)
			break;
		switch(c) {
		case 1:
			if (!got_addr) {
				addr = strtoull(optarg, NULL, 16);
				got_addr = true;
				break;
			}
			val = strtoull(optarg, NULL, 16);
			got_val = true;
			break;
		case 'c':
			chip_id = strtoul(optarg, NULL, 16);
			break;
		case 'b':
			list_bits = true;
			break;
		case 'v':
			printf("xscom utils version %s\n", version);
			exit(0);
		case 'h':
			print_usage(0);
			break;
		default:
			exit(1);
		}
	}
	
	if (!got_addr || !got_val) {
		fprintf(stderr, "Invalid or missing address/value\n");
		print_usage(1);
	}

	def_chip = xscom_init();
	if (def_chip == 0xffffffff) {
		fprintf(stderr, "No valid XSCOM chip found\n");
		exit(1);
	}
	if (chip_id == 0xffffffff)
		chip_id = def_chip;

	rc = xscom_write(chip_id, addr, val);
	if (rc) {
		fprintf(stderr,"Error %d writing XSCOM\n", rc);
		exit(1);
	}
	if (xscom_readable(addr)) {
		rc = xscom_read(chip_id, addr, &val);
		if (rc) {
			fprintf(stderr,"Error %d reading XSCOM\n", rc);
			exit(1);
		}
	}

	printf("%016" PRIx64, val);
	if (list_bits) {
		int i;

		printf(" - set: ");

		for (i = 0; i < 64; i++)
			if (val & PPC_BIT(i))
				printf("%d ", i);
	}

	putchar('\n');
	return 0;
}

