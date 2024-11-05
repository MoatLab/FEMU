// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Read SRAM
 *
 * Copyright 2014-2018 IBM Corp.
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

#include "xscom.h"
#include "sram.h"

static void print_usage(int code)
{
	printf("usage: getsram [opts] addr\n");
	printf("	-c|--chip <chip-id>\n");
	printf("	-l|--length <size to read>\n");
	printf("        -n|--occ-channel <chan>\n");
	printf("	-f|--file <filename>\n");
	printf("        -v|--version\n");
	exit(code);
}

extern const char version[];

int main(int argc, char *argv[])
{
	uint64_t val, addr = -1ull, length = 8;
	uint32_t def_chip, chip_id = 0xffffffff;
	int rc;
	int occ_channel = 0;
	char *filename = NULL;
	FILE *f = stdout;

	while(1) {
		static struct option long_opts[] = {
			{"chip",	required_argument,	NULL,	'c'},
			{"occ-channel",	required_argument,	NULL,	'n'},
			{"help",	no_argument,		NULL,	'h'},
			{"version",	no_argument,		NULL,	'v'},
			{"length",	required_argument,	NULL,	'l'},
			{"file",	required_argument,	NULL,	'f'},
		};
		int c, oidx = 0;

		c = getopt_long(argc, argv, "-c:n:hl:vf:", long_opts, &oidx);
		if (c == EOF)
			break;
		switch(c) {
		case 1:
			addr = strtoull(optarg, NULL, 16);
			break;
		case 'c':
			chip_id = strtoul(optarg, NULL, 16);
			break;
		case 'n':
			occ_channel = strtoul(optarg, NULL, 0);
			if (occ_channel < 0 || occ_channel > 3) {
				fprintf(stderr, "occ-channel out of range 0 <= c <= 3\n");
				exit(1);
			}
			break;
		case 'h':
			print_usage(0);
			break;
		case 'v':
			printf("xscom utils version %s\n", version);
			exit(0);
		case 'f':
			filename = optarg;
			break;
		case 'l':
			length = strtoul(optarg, NULL, 0);
			length = (length + 7) & ~0x7; /* round up to an eight byte interval */
			break;
		default:
			exit(1);
		}
	}

	if (addr == -1ull) {
		fprintf(stderr, "Invalid or missing address\n");
		print_usage(1);
	}

	def_chip = xscom_init();
	if (def_chip == 0xffffffff) {
		fprintf(stderr, "No valid XSCOM chip found\n");
		exit(1);
	}
	if (chip_id == 0xffffffff)
		chip_id = def_chip;

	if (filename) {
		f = fopen(filename, "wb");
		if (!f) {
			fprintf(stderr, "unable to open %s for writing\n", filename);
			exit(1);
		}
	}

	rc = 0;
	while (length) {
		rc = sram_read(chip_id, occ_channel, addr, &val);
		if (rc)
			break;

		if (f) {
			int i;

			/* make sure we write it out big endian */
			for (i = 1; i <= 8; i++)
				fputc((val >> (64 - i * 8)) & 0xff, f);
		} else {
			printf("OCC%d: %" PRIx64 "\n", occ_channel, val);
		}

		length -= 8;
		addr += 8;
	}

	if (rc) {
		fprintf(stderr,"Error %d reading XSCOM\n", rc);
		exit(1);
	}
	return 0;
}
