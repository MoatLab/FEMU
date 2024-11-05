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
	printf("usage: getscom [-c|--chip chip-id] [-b|--list-bits] addr\n");
	printf("       getscom -l|--list-chips\n");
	printf("       getscom -v|--version\n");
	printf("\n");
	printf("       NB: --list-bits shows which PPC bits are set\n");
	exit(code);
}

static void print_chip_info(uint32_t chip_id)
{
	uint64_t f000f, cfam_id;
	const char *name;
	char uname_buf[64];
	int rc;

	rc = xscom_read(chip_id, 0xf000f, &f000f);
	if (rc)
		return;

	cfam_id = f000f >> 44;

	switch(cfam_id & 0xff) {
	case 0xef:
		name = "P8E (Murano) processor";
		break;
	case 0xea:
		name = "P8 (Venice) processor";
		break;
	case 0xd3:
		name = "P8NVL (Naples) processor";
		break;
	case 0xd1:
		name = "P9 (Nimbus) processor";
		break;
	case 0xd4:
		name = "P9 (Cumulus) processor";
		break;
	case 0xd9:
		name = "P9P (Axone) processor";
		break;
	case 0xda:
		name = "P10 processor";
		break;
	case 0xe9:
		name = "Centaur memory buffer";
		break;
	default:
		snprintf(uname_buf, sizeof(uname_buf), "Unknown ID 0x%02lx",
			 cfam_id & 0xff);
		name = uname_buf;
	}

	printf("%08x | DD%lx.%lx | %s\n",
	       chip_id, (cfam_id >> 16) & 0xf, (cfam_id >> 8) & 0xf, name);
}

extern const char version[];

int main(int argc, char *argv[])
{
	uint64_t val, addr = -1ull;
	uint32_t def_chip, chip_id = 0xffffffff;
	bool list_chips = false;
	bool no_work = false;
	bool list_bits = false;
	int rc;

	while(1) {
		static struct option long_opts[] = {
			{"chip",	required_argument,	NULL,	'c'},
			{"list-chips",	no_argument,		NULL,	'l'},
			{"help",	no_argument,		NULL,	'h'},
			{"version",	no_argument,		NULL,	'v'},
			{"list-bits",	no_argument,		NULL,	'b'},
		};
		int c, oidx = 0;

		c = getopt_long(argc, argv, "-c:bhlv", long_opts, &oidx);
		if (c == EOF)
			break;
		switch(c) {
		case 1:
			addr = strtoull(optarg, NULL, 16);
			break;
		case 'c':
			chip_id = strtoul(optarg, NULL, 16);
			break;
		case 'h':
			print_usage(0);
			break;
		case 'l':
			list_chips = true;
			break;
		case 'b':
			list_bits = true;
			break;
		case 'v':
			printf("xscom utils version %s\n", version);
			exit(0);
		default:
			exit(1);
		}
	}
	
	if (addr == -1ull)
		no_work = true;
	if (no_work && !list_chips) {
		fprintf(stderr, "Invalid or missing address\n");
		print_usage(1);
	}

	def_chip = xscom_init();
	if (def_chip == 0xffffffff) {
		fprintf(stderr, "No valid XSCOM chip found\n");
		exit(1);
	}
	if (list_chips) {
		printf("Chip ID  | Rev   | Chip type\n");
		printf("---------|-------|--------\n");
		xscom_for_each_chip(print_chip_info);
	}
	if (no_work)
		return 0;
	if (chip_id == 0xffffffff)
		chip_id = def_chip;

	rc = xscom_read(chip_id, addr, &val);
	if (rc) {
		fprintf(stderr,"Error %d reading XSCOM\n", rc);
		exit(1);
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

