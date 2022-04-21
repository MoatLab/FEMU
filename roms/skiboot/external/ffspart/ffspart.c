// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Assemble a FFS Image (no, not that FFS, this FFS)
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>

#include <libflash/libflash.h>
#include <libflash/libffs.h>
#include <libflash/blocklevel.h>
#include <libflash/ecc.h>
#include <common/arch_flash.h>

/*
 * Flags:
 *  - E: ECC for this part
 */

/*
 * TODO FIXME
 * Max line theoretical max size:
 *  - name: 15 chars = 15
 *  - base: 0xffffffff = 10
 *  - size: 0xffffffff = 10
 *  - flag: E = 1
 *
 *  36 + 3 separators = 39
 *  Plus \n 40
 *  Lets do 50.
 */
#define MAX_LINE (PATH_MAX+255)
#define MAX_TOCS 10
#define SEPARATOR ','

/* Full version number (possibly includes gitid). */
extern const char version[];

static int read_u32(const char *input, uint32_t *val)
{
	char *endptr;
	*val = strtoul(input, &endptr, 0);
	return (*endptr == SEPARATOR) ? 0 : 1;
}

static const char *advance_line(const char *input)
{
	char *pos = strchr(input, SEPARATOR);
	if (!pos)
		return NULL;
	return pos + 1;
}

static struct ffs_hdr *parse_toc(const char *line, uint32_t block_size,
		uint32_t block_count)
{
	struct ffs_entry_user user;
	struct ffs_entry *ent;
	struct ffs_hdr *hdr;
	uint32_t tbase;
	int rc;

	if (read_u32(line, &tbase)) {
		fprintf(stderr, "Couldn't parse TOC base address\n");
		return NULL;
	}

	line = advance_line(line);
	if (!line) {
		fprintf(stderr, "Couldn't find TOC flags\n");
		return NULL;
	}

	rc = ffs_string_to_entry_user(line, strlen(line), &user);
	if (rc) {
		fprintf(stderr, "Couldn't parse TOC flags\n");
		return NULL;
	}

	rc = ffs_entry_new("part", tbase, 0, &ent);
	if (rc) {
		fprintf(stderr, "Couldn't make entry for TOC@0x%08x\n", tbase);
		return NULL;
	}

	rc = ffs_entry_user_set(ent, &user);
	if (rc) {
		fprintf(stderr, "Invalid TOC flag\n");
		ffs_entry_put(ent);
		return NULL;
	}

	rc = ffs_hdr_new(block_size, block_count, &ent, &hdr);
	if (rc) {
		hdr = NULL;
		fprintf(stderr, "Couldn't make header for TOC@0x%08x\n", tbase);
	}

	ffs_entry_put(ent);
	return hdr;
}

static int parse_entry(struct blocklevel_device *bl,
		struct ffs_hdr **tocs, const char *line, bool allow_empty)
{
	char name[FFS_PART_NAME_MAX + 2] = { 0 };
	struct ffs_entry_user user = { 0 };
	uint32_t pbase, psize, pactual, i;
	struct ffs_entry *new_entry;
	struct stat data_stat;
	const char *filename;
	bool added = false;
	uint8_t *data_ptr, ecc = 0;
	int data_fd, rc;
	char *pos;

	memcpy(name, line, FFS_PART_NAME_MAX + 1);
	pos = strchr(name, SEPARATOR);
	/* There is discussion to be had as to if we should bail here */
	if (!pos) {
		fprintf(stderr, "WARNING: Long partition name will get truncated to '%s'\n",
				name);
		name[FFS_PART_NAME_MAX] = '\0';
	} else {
		*pos = '\0';
	}

	line = advance_line(line);
	if (!line || read_u32(line, &pbase)) {
		fprintf(stderr, "Couldn't parse '%s' partition base address\n",
				name);
		return -1;
	}

	line = advance_line(line);
	if (!line || read_u32(line, &psize)) {
		fprintf(stderr, "Couldn't parse '%s' partition length\n",
				name);
		return -1;
	}

	line = advance_line(line);
	if (!line || !advance_line(line)) {
		fprintf(stderr, "Couldn't find '%s' partition flags\n",
				name);
		return -1;
	}

	rc = ffs_string_to_entry_user(line, advance_line(line) - 1 - line, &user);
	if (rc) {
		fprintf(stderr, "Couldn't parse '%s' partition flags\n",
				name);
		return -1;
	}
	line = advance_line(line);
	/* Already checked return value */

	rc = ffs_entry_new(name, pbase, psize, &new_entry);
	if (rc) {
		fprintf(stderr, "Invalid entry '%s' 0x%08x for 0x%08x\n",
				name, pbase, psize);
		return -1;
	}

	rc = ffs_entry_user_set(new_entry, &user);
	if (rc) {
		fprintf(stderr, "Couldn't set '%s' partition flags\n",
				name);
		ffs_entry_put(new_entry);
		return -1;
	}

	if (has_flag(new_entry, FFS_MISCFLAGS_BACKUP)) {
		rc = ffs_entry_set_act_size(new_entry, 0);
		if (rc) {
			fprintf(stderr, "Couldn't set '%s' partition actual size\n",
					name);
			ffs_entry_put(new_entry);
			return -1;
		}
	}

	if (!advance_line(line)) {
		fprintf(stderr, "Missing TOC field for '%s' partition\n",
				name);
		ffs_entry_put(new_entry);
		return -1;
	}

	while (*line != SEPARATOR) {
		int toc = *(line++);

		if (!isdigit(toc)) {
			fprintf(stderr, "Bad TOC value %d (%c) for '%s' partition\n",
					toc, toc, name);
			ffs_entry_put(new_entry);
			return -1;
		}
		toc -= '0';
		if (!tocs[toc]) {
			fprintf(stderr, "No TOC with ID %d for '%s' partition\n",
					toc, name);
			ffs_entry_put(new_entry);
			return -1;
		}
		rc = ffs_entry_add(tocs[toc], new_entry);
		if (rc) {
			fprintf(stderr, "Couldn't add '%s' partition to TOC %d: %d\n",
					name, toc, rc);
			ffs_entry_put(new_entry);
			return rc;
		}
		added = true;
	}
	if (!added) {
		/*
		 * They didn't specify a TOC in the TOC field, use
		 * TOC@0 as the default
		 */
		rc = ffs_entry_add(tocs[0], new_entry);
		if (rc) {
			fprintf(stderr, "Couldn't add '%s' partition to default TOC: %d\n",
					name, rc);
			ffs_entry_put(new_entry);
			return rc;
		}
	}
	ffs_entry_put(new_entry);

	if (*line != '\0' && *(line + 1) != '\0') {
		size_t data_len;

		filename = line + 1;

		/*
		 * Support flashing already ecc'd data as this is the case
		 * for POWER8 SBE image binary.
		 */
		if (has_ecc(new_entry) && !strstr(filename, ".ecc"))
			blocklevel_ecc_protect(bl, pbase, psize);

		data_fd = open(filename, O_RDONLY);
		if (data_fd == -1) {
			fprintf(stderr, "Couldn't open file '%s' for '%s' partition "
					"(%m)\n", filename, name);
			return -1;
		}

		if (fstat(data_fd, &data_stat) == -1) {
			fprintf(stderr, "Couldn't stat file '%s' for '%s' partition "
				"(%m)\n", filename, name);
			close(data_fd);
			return -1;
		}

		data_ptr = calloc(1, psize);
		if (!data_ptr) {
			return -1;
		}

		pactual = data_stat.st_size;

		/*
		 * There's two char device inputs we care about: /dev/zero and
		 * /dev/urandom. Both have a stat.st_size of zero so read in
		 * a full partition worth, accounting for ECC overhead.
		 */
		if (!pactual && S_ISCHR(data_stat.st_mode)) {
			pactual = psize;

			if (has_ecc(new_entry)) {
				pactual = ecc_buffer_size_minus_ecc(pactual);

				/* ECC input size needs to be a multiple of 8 */
				pactual = pactual & ~0x7;
			}
		}
		/*
		 * Sanity check that the file isn't too large for
		 * partition
		 */
		if (has_ecc(new_entry) && !strstr(filename, ".ecc"))
			psize = ecc_buffer_size_minus_ecc(psize);
		if (pactual > psize) {
			fprintf(stderr, "File '%s' for partition '%s' is too large,"
				" %u > %u\n",
				filename, name, pactual, psize);
			close(data_fd);
			return -1;
		}

		for (data_len = 0; data_len < pactual; data_len += rc) {
			rc = read(data_fd, &data_ptr[data_len], pactual - data_len);
			if (rc == -1) {
				fprintf(stderr, "error reading from '%s'", filename);
				exit(1);
			}
		}

		rc = blocklevel_write(bl, pbase, data_ptr, pactual);
		if (rc) {
			fprintf(stderr, "Couldn't write file '%s' for '%s' partition to PNOR "
					"(%m)\n", filename, name);
			exit(1);
		}

		free(data_ptr);
		close(data_fd);
	} else {
		if (!allow_empty) {
			fprintf(stderr, "Filename missing for partition %s!\n",
					name);
			return -1;
		}
		if (has_ecc(new_entry)) {
			i = pbase + 8;
			while (i < pbase + psize) {
				rc = blocklevel_write(bl, i, &ecc, sizeof(ecc));
				if (rc) {
					fprintf(stderr, "\nError setting ECC byte at 0x%08x\n",
							i);
					return rc;
				}
				i += 9;
			}
		}

	}

	return 0;
}

static void print_version(void)
{
	printf("Open-Power FFS format tool %s\n", version);
}

static void print_help(const char *pname)
{
	print_version();
	printf("Usage: %s [options] -e -s size -c num -i layout_file -p pnor_file ...\n\n", pname);
	printf(" Options:\n");
	printf("\t-e, --allow_empty\n");
	printf("\t\tCreate partition as blank if not specified (sets ECC if flag set)\n\n");
	printf("\t-s, --block_size=size\n");
	printf("\t\tSize (in hex with leading 0x) of the blocks on the flash in bytes\n\n");
	printf("\t-c, --block_count=num\n");
	printf("\t\tNumber of blocks on the flash\n\n");
	printf("\t-i, --input=file\n");
	printf("\t\tFile containing the required partition data\n\n");
	printf("\t-p, --pnor=file\n");
	printf("\t\tOutput file to write data\n\n");
}

int main(int argc, char *argv[])
{
	static char line[MAX_LINE];

	char *pnor = NULL, *input = NULL;
	bool toc_created = false, bad_input = false, allow_empty = false;
	uint32_t block_size = 0, block_count = 0;
	struct ffs_hdr *tocs[MAX_TOCS] = { 0 };
	struct blocklevel_device *bl = NULL;
	const char *pname = argv[0];
	int line_number, rc, i;
	FILE *in_file;

	while(1) {
		struct option long_opts[] = {
			{"allow_empty", no_argument,		NULL,	'e'},
			{"block_count",	required_argument,	NULL,	'c'},
			{"block_size",	required_argument,	NULL,	's'},
			{"debug",	no_argument,		NULL,	'g'},
			{"input",	required_argument,	NULL,	'i'},
			{"pnor",	required_argument,	NULL,	'p'},
			{NULL,	0,	0, 0}
		};
		int c, oidx = 0;

		c = getopt_long(argc, argv, "+:ec:gi:p:s:", long_opts, &oidx);
		if (c == EOF)
			break;
		switch(c) {
		case 'e':
			allow_empty = true;
			break;
		case 'c':
			block_count = strtoul(optarg, NULL, 0);
			break;
		case 'g':
			libflash_debug = true;
			break;
		case 'i':
			free(input);
			input = strdup(optarg);
			if (!input)
				fprintf(stderr, "Out of memory!\n");
			break;
		case 'p':
			free(pnor);
			pnor = strdup(optarg);
			if (!pnor)
				fprintf(stderr, "Out of memory!\n");
			break;
		case 's':
			block_size = strtoul(optarg, NULL, 0);
			break;
		case ':':
			fprintf(stderr, "Unrecognised option \"%s\" to '%c'\n",
					optarg, optopt);
			bad_input = true;
			break;
		case '?':
			fprintf(stderr, "Unrecognised option '%c'\n", optopt);
			bad_input = true;
			break;
		default:
			fprintf(stderr , "Encountered unknown error parsing options\n");
			bad_input = true;
		}
	}

	if (bad_input || !block_size || !block_count || !input || !pnor) {
		print_help(pname);
		return 1;
	}

	in_file = fopen(input, "r");
	if (!in_file) {
		fprintf(stderr, "Couldn't open your input file %s: %m\n", input);
		return 2;
	}

	/*
	 * TODO: This won't create the file.
	 * We should do this
	 */
	rc = arch_flash_init(&bl, pnor, true);
	if (rc) {
		fprintf(stderr, "Couldn't initialise architecture flash structures\n");
		fclose(in_file);
		return 3;
	}

	/*
	 * 'Erase' the file, make it all 0xFF
	 * TODO: Add sparse option and don't do this.
	 */
	rc = blocklevel_erase(bl, 0, block_size * block_count);
	if (rc) {
		fprintf(stderr, "Couldn't erase '%s' pnor file\n", pnor);
		fclose(in_file);
		return 4;
	}

	line_number = 0;
	while (fgets(line, MAX_LINE, in_file) != NULL) {
		line_number++;

		/* Inline comments in input file */
		if (line[0] == '#')
			continue;

		if (line[strlen(line) - 1] == '\n')
			line[strlen(line) - 1] = '\0';

		if (line[0] == '@') {
			int toc_num = line[1];
			rc = 5;

			if (!isdigit(toc_num)) {
				fprintf(stderr, "Invalid TOC ID %d (%c)\n",
						toc_num, toc_num);
				goto parse_out;
			}

			toc_num -= '0';

			if (line[2] != SEPARATOR) {
				fprintf(stderr, "TOC ID too long\n");
				goto parse_out;
			}

			if (tocs[toc_num]) {
				fprintf(stderr, "Duplicate TOC ID %d\n", toc_num);
				goto parse_out;
			}

			tocs[toc_num] = parse_toc(&line[3], block_size, block_count);
			if (!tocs[toc_num])
				goto parse_out;
			toc_created = true;
		} else {
			if (!toc_created) {
				fprintf(stderr, "WARNING: Attempting to parse a partition line without any TOCs created.\n");
				fprintf(stderr, "         Generating a default TOC at zero\n");
				rc = ffs_hdr_new(block_size, block_count, NULL, &tocs[0]);
				if (rc) {
					rc = 7;
					fprintf(stderr, "Couldn't generate a default TOC at zero\n");
					goto parse_out;
				}
				toc_created = true;
			}
			rc = parse_entry(bl, tocs, line, allow_empty);
			if (rc) {
				rc = 6;
				goto parse_out;
			}
		}
	}

	for(i = 0; i < MAX_TOCS; i++) {
		if (tocs[i]) {
			rc = ffs_hdr_finalise(bl, tocs[i]);
			if (rc) {
				rc = 7;
				fprintf(stderr, "Failed to write out TOC values\n");
				break;
			}
		}
	}

parse_out:
	if (rc == 5 || rc == 6)
		fprintf(stderr, "Failed to parse input file '%s' at line %d\n",
				input, line_number);
	arch_flash_close(bl, pnor);
	fclose(in_file);
	for(i = 0; i < MAX_TOCS; i++)
		ffs_hdr_free(tocs[i]);
	free(input);
	free(pnor);
	return rc;
}
