// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Display progress bars, while also writing whole or part
 * of flash.
 *
 * Copyright 2013-2019 IBM Corp.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#include <inttypes.h>

#include <libflash/libflash.h>
#include <libflash/libffs.h>
#include <libflash/blocklevel.h>
#include <libflash/ecc.h>
#include <common/arch_flash.h>
#include "progress.h"

#define __aligned(x)			__attribute__((aligned(x)))

struct flash_details {
	struct blocklevel_device *bl;
	int need_relock;
	const char *name;
	uint64_t toc;
	uint64_t total_size;
	uint32_t erase_granule;
	bool mark_ecc;
};

/* Full pflash version number (possibly includes gitid). */
extern const char version[];

const char *flashfilename = NULL;
static bool must_confirm = true;
static bool dummy_run;
static bool bmc_flash;

#define FILE_BUF_SIZE	0x10000
static uint8_t file_buf[FILE_BUF_SIZE] __aligned(0x1000);

static bool check_confirm(void)
{
	char yes[8], *p;

	if (!must_confirm)
		return true;

	printf("WARNING ! This will modify your %s flash chip content !\n",
	       bmc_flash ? "BMC" : "HOST");
	printf("Enter \"yes\" to confirm:");
	memset(yes, 0, sizeof(yes));
	if (!fgets(yes, 7, stdin))
		return false;
	p = strchr(yes, 10);
	if (p)
		*p = 0;
	p = strchr(yes, 13);
	if (p)
		*p = 0;
	if (strcmp(yes, "yes")) {
		printf("Operation cancelled !\n");
		return false;
	}
	must_confirm = false;
	return true;
}

static uint32_t print_ffs_info(struct ffs_handle *ffsh, uint32_t toc)
{
	struct ffs_entry *ent;
	uint32_t next_toc = toc;
	int rc;
	int i;

	printf("\n");
	printf("TOC@0x%08x Partitions:\n", toc);
	printf("-----------\n");

	for (i = 0;; i++) {
		uint32_t start, size, act, end;
		struct ffs_entry_user user;
		char *name = NULL, *flags;

		rc = ffs_part_info(ffsh, i, &name, &start, &size, &act, NULL);
		if (rc == FFS_ERR_PART_NOT_FOUND)
			break;

		ent = ffs_entry_get(ffsh, i);
		if (rc || !ent) {
			fprintf(stderr, "Error %d scanning partitions\n",
					!ent ? FFS_ERR_PART_NOT_FOUND : rc);
		    goto out;
		}

		user = ffs_entry_user_get(ent);
		ffs_entry_put(ent);
		flags = ffs_entry_user_to_string(&user);
		if (!flags)
			goto out;

		end = start + size;
		printf("ID=%02d %15s 0x%08x..0x%08x (actual=0x%08x) [%s]\n",
				i, name, start, end, act, flags);

		if (strcmp(name, "OTHER_SIDE") == 0)
			next_toc = start;

		free(flags);
out:
		free(name);
	}

	return next_toc;
}

static struct ffs_handle *open_ffs(struct flash_details *flash)
{
	struct ffs_handle *ffsh;
	int rc;

	rc = ffs_init(flash->toc, flash->total_size,
			flash->bl, &ffsh, flash->mark_ecc);
	if (rc) {
		fprintf(stderr, "Error %d opening ffs !\n", rc);
		if (flash->toc) {
			fprintf(stderr, "You specified 0x%" PRIx64 " as the libffs TOC\n"
				   	"Looks like it doesn't exist\n", flash->toc);
			return NULL;
		}
	}

	return ffsh;
}

static void print_flash_info(struct flash_details *flash)
{
	struct ffs_handle *ffsh;
	uint32_t next_toc;
	uint32_t toc;

	printf("Flash info:\n");
	printf("-----------\n");
	printf("Name          = %s\n", flash->name);
	printf("Total size    = %" PRIu64 "MB\t Flags E:ECC, P:PRESERVED, R:READONLY, "
			"B:BACKUP\n", flash->total_size >> 20);
	printf("Erase granule = %2d%-13sF:REPROVISION, V:VOLATILE, C:CLEARECC\n",
			flash->erase_granule >> 10, "KB");

	if (bmc_flash)
		return;

	toc = flash->toc;

	ffsh = open_ffs(flash);
	if (!ffsh)
		return;

	next_toc = print_ffs_info(ffsh, toc);
	ffs_close(ffsh);
	while(next_toc != toc) {
		struct ffs_handle *next_ffsh;

		flash->toc = next_toc;
		next_ffsh = open_ffs(flash);
		if (!next_ffsh)
			break;
		next_toc = print_ffs_info(next_ffsh, next_toc);
		ffs_close(next_ffsh);
	}
	flash->toc = toc;
}

static struct ffs_handle *open_partition(struct flash_details *flash,
		const char *name, uint32_t *index)
{
	struct ffs_handle *ffsh;
	int rc;

	ffsh = open_ffs(flash);
	if (!ffsh)
		return NULL;

	if (!name)
		/* Just open the FFS */
		return ffsh;

	/* Find partition */
	rc = ffs_lookup_part(ffsh, name, index);
	if (rc == FFS_ERR_PART_NOT_FOUND) {
		fprintf(stderr, "Partition '%s' not found !\n", name);
		goto out;
	}
	if (rc) {
		fprintf(stderr, "Error %d looking for partition '%s' !\n",
			rc, name);
		goto out;
	}
	return ffsh;
out:
	ffs_close(ffsh);
	return NULL;
}

static struct ffs_handle *lookup_partition_at_toc(struct flash_details *flash,
		const char *name, uint32_t *index)
{
	return open_partition(flash, name, index);
}

static struct ffs_handle *lookup_partition_at_side(struct flash_details *flash,
		int side, const char *name, uint32_t *index)
{
	uint32_t toc = 0;
	int rc;

	if (side == 1) {
		struct ffs_handle *ffsh;
		uint32_t side_index;

		ffsh = open_partition(flash, "OTHER_SIDE", &side_index);
		if (!ffsh)
			return NULL;

		/* Just need to know where it starts */
		rc = ffs_part_info(ffsh, side_index, NULL, &toc, NULL, NULL, NULL);
		ffs_close(ffsh);
		if (rc)
			return NULL;
	}

	flash->toc = toc;
	return lookup_partition_at_toc(flash, name, index);
}

static int erase_chip(struct flash_details *flash)
{
	bool confirm;
	int rc;
	uint64_t pos;

	printf("About to erase chip !\n");
	confirm = check_confirm();
	if (!confirm)
		return 1;

	printf("Erasing... (may take a while)\n");
	fflush(stdout);

	if (dummy_run) {
		printf("skipped (dummy)\n");
		return 1;
	}

	/*
	 * We could use arch_flash_erase_chip() here BUT everyone really
	 * likes the progress bars.
	 * Lets do an erase block at a time erase then...
	 */
	progress_init(flash->total_size);
	for (pos = 0; pos < flash->total_size; pos += flash->erase_granule) {
		rc = blocklevel_erase(flash->bl, pos, flash->erase_granule);
		if (rc)
			break;
		progress_tick(pos);
	}
	progress_end();
	if (rc) {
		fprintf(stderr, "Error %d erasing chip\n", rc);
		return rc;
	}

	printf("done !\n");
	return 0;
}

static int erase_range(struct flash_details *flash,
		uint32_t start, uint32_t size, bool will_program,
		struct ffs_handle *ffsh, int ffs_index)
{
	uint32_t done = 0, erase_mask = flash->erase_granule - 1;
	struct ffs_entry *toc;
	bool confirm;
	int rc;

	printf("About to erase 0x%08x..0x%08x !\n", start, start + size);
	confirm = check_confirm();
	if (!confirm)
		return 1;

	if (dummy_run) {
		printf("skipped (dummy)\n");
		return 1;
	}

	printf("Erasing...\n");
	/*
	 * blocklevel_smart_erase() can do the entire thing in one call
	 * BUT everyone really likes progress bars so break stuff up
	 */
	progress_init(size);
	if (start & erase_mask) {
		/*
		 * Align to next erase block, or just do the entire
		 * thing if we fit within one erase block
		 */
		uint32_t first_size = MIN(size, (flash->erase_granule - (start & erase_mask)));

		rc = blocklevel_smart_erase(flash->bl, start, first_size);
		if (rc) {
			fprintf(stderr, "Failed to blocklevel_smart_erase(): %d\n", rc);
			return 1;
		}
		size -= first_size;
		done = first_size;
		start += first_size;
	}
	progress_tick(done);
	while (size & ~(erase_mask)) {
		rc = blocklevel_smart_erase(flash->bl, start, flash->erase_granule);
		if (rc) {
			fprintf(stderr, "Failed to blocklevel_smart_erase(): %d\n", rc);
			return 1;
		}
		start += flash->erase_granule;
		size -= flash->erase_granule;
		done += flash->erase_granule;
		progress_tick(done);
	}
	if (size) {
		rc = blocklevel_smart_erase(flash->bl, start, size);
		if (rc) {
			fprintf(stderr, "Failed to blocklevel_smart_erase(): %d\n", rc);
			return 1;
		}
		done += size;
		progress_tick(done);
	}
	progress_end();

	if (!ffsh)
		return 0;

	/* If this is a flash partition, mark it empty if we aren't
	 * going to program over it as well
	 */
	toc = ffs_entry_get(ffsh, 0);
	if (toc) {
		struct ffs_entry_user user;
		bool rw_toc;

		user = ffs_entry_user_get(toc);
		rw_toc = !(user.miscflags & FFS_MISCFLAGS_READONLY);
		if (ffs_index >= 0 && !will_program && rw_toc) {
			printf("Updating actual size in partition header...\n");
			ffs_update_act_size(ffsh, ffs_index, 0);
		}
	}

	return 0;
}

static int set_ecc(struct flash_details *flash, uint32_t start, uint32_t size)
{
	uint32_t i = start + 8;
	uint8_t ecc = 0;
	bool confirm;
	int rc;

	printf("About to erase and set ECC bits in region 0x%08x to 0x%08x\n", start, start + size);
	confirm = check_confirm();
	if (!confirm)
		return 1;

	rc = erase_range(flash, start, size, true, NULL, 0);
	if (rc) {
		fprintf(stderr, "Couldn't erase region to mark with ECC\n");
		return rc;
	}

	printf("Programming ECC bits...\n");
	progress_init(size);
	while (i < start + size) {
		rc = blocklevel_write(flash->bl, i, &ecc, sizeof(ecc));
		if (rc) {
			fprintf(stderr, "\nError setting ECC byte at 0x%08x\n", i);
			return rc;
		}
		i += 9;
		progress_tick(i - start);
	}
	progress_end();
	return 0;
}

static int program_file(struct blocklevel_device *bl,
		const char *file, uint32_t start, uint32_t size,
		struct ffs_handle *ffsh, int ffs_index)
{
	uint32_t actual_size = 0;
	struct ffs_entry *toc;
	int fd, rc = 0;
	bool confirm;

	fd = open(file, O_RDONLY);
	if (fd == -1) {
		perror("Failed to open file");
		return 1;
	}
	printf("About to program \"%s\" at 0x%08x..0x%08x !\n",
	       file, start, start + size);
	confirm = check_confirm();
	if (!confirm) {
		rc = 1;
		goto out;
	}

	if (dummy_run) {
		printf("skipped (dummy)\n");
		rc = 1;
		goto out;
	}

	printf("Programming & Verifying...\n");
	progress_init(size);
	while(size) {
		ssize_t len;

		len = read(fd, file_buf, FILE_BUF_SIZE);
		if (len < 0) {
			perror("Error reading file");
			rc = 1;
			goto out;
		}
		if (len == 0)
			break;
		if (len > size)
			len = size;
		size -= len;
		actual_size += len;
		rc = blocklevel_write(bl, start, file_buf, len);
		if (rc) {
			if (rc == FLASH_ERR_VERIFY_FAILURE)
				fprintf(stderr, "Verification failed for"
					" chunk at 0x%08x\n", start);
			else
				fprintf(stderr, "Flash write error %d for"
					" chunk at 0x%08x\n", rc, start);
			goto out;
		}
		start += len;
		progress_tick(actual_size);
	}
	progress_end();

	if (!ffsh)
		goto out;

	/* If this is a flash partition, adjust its size */
	toc = ffs_entry_get(ffsh, 0);
	if (toc) {
		struct ffs_entry_user user;
		bool rw_toc;

		user = ffs_entry_user_get(toc);
		rw_toc = !(user.miscflags & FFS_MISCFLAGS_READONLY);
		if (ffs_index >= 0 && rw_toc) {
			printf("Updating actual size in partition header...\n");
			ffs_update_act_size(ffsh, ffs_index, actual_size);
		}
	}
out:
	close(fd);
	return rc;
}

static int do_read_file(struct blocklevel_device *bl, const char *file,
		uint32_t start, uint32_t size, uint32_t skip_size)
{
	int fd, rc = 0;
	uint32_t done = 0;

	fd = open(file, O_WRONLY | O_TRUNC | O_CREAT, 00666);
	if (fd == -1) {
		perror("Failed to open file");
		return 1;
	}
	start += skip_size;
	size -= skip_size;

	printf("Reading to \"%s\" from 0x%08x..0x%08x !\n",
	       file, start, start + size);

	progress_init(size);
	while(size) {
		ssize_t len;

		len = size > FILE_BUF_SIZE ? FILE_BUF_SIZE : size;
		rc = blocklevel_read(bl, start, file_buf, len);
		if (rc) {
			fprintf(stderr, "Flash read error %d for"
				" chunk at 0x%08x\n", rc, start);
			break;
		}
		rc = write(fd, file_buf, len);
		/*
		 * zero isn't strictly an error.
		 * Treat it as such so we can be sure we'lre always
		 * making forward progress.
		 */
		if (rc <= 0) {
			perror("Error writing file");
			break;
		}
		start += rc;
		size -= rc;
		done += rc;
		progress_tick(done);
	}
	progress_end();
	close(fd);
	return size ? rc : 0;
}

static int enable_4B_addresses(struct blocklevel_device *bl)
{
	int rc;

	printf("Switching to 4-bytes address mode\n");

	rc = arch_flash_4b_mode(bl, true);
	if (rc) {
		if (rc == -1) {
			fprintf(stderr, "Switching address mode not available on this architecture\n");
		} else {
			fprintf(stderr, "Error %d enabling 4b mode\n", rc);
		}
	}

	return rc;
}

static int disable_4B_addresses(struct blocklevel_device *bl)
{
	int rc;

	printf("Switching to 3-bytes address mode\n");

	rc = arch_flash_4b_mode(bl, false);
	if (rc) {
		if (rc == -1) {
			fprintf(stderr, "Switching address mode not available on this architecture\n");
		} else {
			fprintf(stderr, "Error %d enabling 4b mode\n", rc);
		}
	}

	return rc;
}

static void print_partition_detail(struct ffs_handle *ffsh, uint32_t part_id)
{
	uint32_t start, size, act, end;
	char *ent_name = NULL, *flags;
	struct ffs_entry *ent;
	int rc, l;

	rc = ffs_part_info(ffsh, part_id, &ent_name, &start, &size,
			&act, NULL);
	if (rc) {
		fprintf(stderr, "Partition with ID %d doesn't exist error: %d\n",
				part_id, rc);
		goto out;
	}

	ent = ffs_entry_get(ffsh, part_id);
	if (!ent) {
		rc = FFS_ERR_PART_NOT_FOUND;
		fprintf(stderr, "Couldn't open partition entry\n");
		goto out;
	}

	printf("Detailed partition information\n");
	end = start + size;
	printf("Name:\n");
	printf("%s (ID=%02d)\n\n", ent_name, part_id);
	printf("%-10s  %-10s  %-10s\n", "Start", "End", "Actual");
	printf("0x%08x  0x%08x  0x%08x\n\n", start, end, act);

	printf("Flags:\n");

	l = asprintf(&flags, "%s%s%s%s%s%s%s", has_ecc(ent) ? "ECC [E]\n" : "",
			has_flag(ent, FFS_MISCFLAGS_PRESERVED) ? "PRESERVED [P]\n" : "",
			has_flag(ent, FFS_MISCFLAGS_READONLY) ? "READONLY [R]\n" : "",
			has_flag(ent, FFS_MISCFLAGS_BACKUP) ? "BACKUP [B]\n" : "",
			has_flag(ent, FFS_MISCFLAGS_REPROVISION) ?
					"REPROVISION [F]\n" : "",
			has_flag(ent, FFS_MISCFLAGS_VOLATILE) ? "VOLATILE [V]\n" : "",
			has_flag(ent, FFS_MISCFLAGS_CLEARECC) ? "CLEARECC [C]\n" : "");
	ffs_entry_put(ent);
	if (l < 0) {
		fprintf(stderr, "Memory allocation failure printing flags!\n");
		goto out;
	}

	printf("%s", flags);
	free(flags);

out:
	free(ent_name);
}

static void print_version(void)
{
	printf("Open-Power Flash tool %s\n", version);
}

static void print_help(const char *pname)
{
	printf("Usage: %s [options] commands...\n\n", pname);
	printf(" Options:\n");
	printf("\t-a address, --address=address\n");
	printf("\t\tSpecify the start address for erasing, reading\n");
	printf("\t\tor flashing\n\n");
	printf("\t-s size, --size=size\n");
	printf("\t\tSpecify the size in bytes for erasing, reading\n");
	printf("\t\tor flashing\n\n");
	printf("\t-P part_name, --partition=part_name\n");
	printf("\t\tSpecify the partition whose content is to be erased\n");
	printf("\t\tprogrammed or read. This is an alternative to -a and -s\n");
	printf("\t\tif both -P and -s are specified, the smallest of the\n");
	printf("\t\ttwo will be used\n\n");
	printf("\t-f, --force\n");
	printf("\t\tDon't ask for confirmation before erasing or flashing\n\n");
	printf("\t-d, --dummy\n");
	printf("\t\tDon't write to flash\n\n");
	printf("\t--direct\n");
	printf("\t\tBypass all safety provided to you by the kernel driver\n");
	printf("\t\tand use the flash driver built into pflash.\n");
	printf("\t\tIf you have mtd devices and you use this command, the\n");
	printf("\t\tsystem may become unstable.\n");
	printf("\t\tIf you are reading this sentence then this flag is not\n");
	printf("\t\twhat you want! Using this feature without knowing\n");
	printf("\t\twhat it does can and likely will result in a bricked\n");
	printf("\t\tmachine\n\n");
	printf("\t-b, --bmc\n");
	printf("\t\tTarget BMC flash instead of host flash.\n");
	printf("\t\tNote: This carries a high chance of bricking your BMC if you\n");
	printf("\t\tdon't know what you're doing. Consider --mtd to be safe(r)\n\n");
	printf("\t-F filename, --flash-file filename\n");
	printf("\t\tTarget filename instead of actual flash.\n\n");
	printf("\t-S, --side\n");
	printf("\t\tSide of the flash on which to operate, 0 (default) or 1\n\n");
	printf("\t--skip=N\n");
	printf("\t\tSkip N number of bytes from the start when reading\n\n");
	printf("\t-T, --toc\n");
	printf("\t\tlibffs TOC on which to operate, defaults to 0.\n");
	printf("\t\tleading 0x is required for interpretation of a hex value\n\n");
	printf("\t-g\n");
	printf("\t\tEnable verbose libflash debugging\n\n");
	printf(" Commands:\n");
	printf("\t-4, --enable-4B\n");
	printf("\t\tSwitch the flash and controller to 4-bytes address\n");
	printf("\t\tmode (no confirmation needed).\n\n");
	printf("\t-3, --disable-4B\n");
	printf("\t\tSwitch the flash and controller to 3-bytes address\n");
	printf("\t\tmode (no confirmation needed).\n\n");
	printf("\t-r file, --read=file\n");
	printf("\t\tRead flash content from address into file, use -s\n");
	printf("\t\tto specify the size to read (or it will use the source\n");
	printf("\t\tfile size if used in conjunction with -p and -s is not\n");
	printf("\t\tspecified). When using -r together with -e or -p, the\n");
	printf("\t\tread will be performed first\n\n");
	printf("\t-E, --erase-all\n");
	printf("\t\tErase entire flash chip\n");
	printf("\t\t(Not supported on all chips/controllers)\n\n");
	printf("\t-e, --erase\n");
	printf("\t\tErase the specified region. If size or address are not\n");
	printf("\t\tspecified, but \'--program\' is used, then the file\n");
	printf("\t\tsize will be used (rounded to an erase block) and the\n");
	printf("\t\taddress defaults to 0.\n\n");
	printf("\t-p file, --program=file\n");
	printf("\t\tWill program the file to flash. If the address is not\n");
	printf("\t\tspecified, it will use 0. If the size is not specified\n");
	printf("\t\tit will use the file size. Otherwise it will limit to\n");
	printf("\t\tthe specified size (whatever is smaller). If used in\n");
	printf("\t\tconjunction with any erase command, the erase will\n");
	printf("\t\ttake place first.\n\n");
	printf("\t-t, --tune\n");
	printf("\t\tJust tune the flash controller & access size\n");
	printf("\t\tMust be used in conjuction with --direct\n");
	printf("\t\t(Implicit for all other operations)\n\n");
	printf("\t-c --clear\n");
	printf("\t\tUsed to ECC clear a partition of the flash\n");
	printf("\t\tMust be used in conjunction with -P. Will erase the\n");
	printf("\t\tpartition and then set all the ECC bits as they should be\n\n");
	printf("\t-9 --ecc\n");
	printf("\t\tEncode/Decode ECC where specified in the FFS header.\n");
	printf("\t\tThis 9 byte ECC method is used for some OpenPOWER\n");
	printf("\t\tpartitions.\n");
	printf("\t-i, --info\n");
	printf("\t\tDisplay some information about the flash.\n\n");
	printf("\t--detail\n");
	printf("\t\tDisplays detailed info about a particular partition.\n");
	printf("\t\tAccepts a numeric partition or can be used in conjuction\n");
	printf("\t\twith the -P flag.\n\n");
	printf("\t-h, --help\n");
	printf("\t\tThis message.\n\n");
}

int main(int argc, char *argv[])
{
	const char *pname = argv[0];
	struct flash_details flash = { 0 };
	static struct ffs_handle *ffsh = NULL;
	uint32_t ffs_index;
	uint32_t address = 0, read_size = 0, detail_id = UINT_MAX;
	uint32_t write_size = 0, write_size_minus_ecc = 0;
	bool erase = false, do_clear = false;
	bool program = false, erase_all = false, info = false, do_read = false;
	bool enable_4B = false, disable_4B = false;
	bool show_help = false, show_version = false;
	bool no_action = false, tune = false;
	char *write_file = NULL, *read_file = NULL, *part_name = NULL;
	bool ffs_toc_seen = false, direct = false, print_detail = false;
	int flash_side = 0, skip_size = 0;
	int rc = 0;

	while(1) {
		struct option long_opts[] = {
			{"address",	required_argument,	NULL,	'a'},
			{"size",	required_argument,	NULL,	's'},
			{"partition",	required_argument,	NULL,	'P'},
			{"bmc",		no_argument,		NULL,	'b'},
			{"direct",	no_argument,		NULL,	'D'},
			{"enable-4B",	no_argument,		NULL,	'4'},
			{"disable-4B",	no_argument,		NULL,	'3'},
			{"read",	required_argument,	NULL,	'r'},
			{"erase-all",	no_argument,		NULL,	'E'},
			{"erase",	no_argument,		NULL,	'e'},
			{"program",	required_argument,	NULL,	'p'},
			{"force",	no_argument,		NULL,	'f'},
			{"flash-file",	required_argument,	NULL,	'F'},
			{"info",	no_argument,		NULL,	'i'},
			{"detail",  optional_argument,  NULL,   'm'},
			{"tune",	no_argument,		NULL,	't'},
			{"dummy",	no_argument,		NULL,	'd'},
			{"help",	no_argument,		NULL,	'h'},
			{"version",	no_argument,		NULL,	'v'},
			{"debug",	no_argument,		NULL,	'g'},
			{"side",	required_argument,	NULL,	'S'},
			{"skip",	required_argument,	NULL,	'k'},
			{"toc",		required_argument,	NULL,	'T'},
			{"clear",   no_argument,        NULL,   'c'},
			{"ecc",         no_argument,            NULL,   '9'},
			{NULL,	    0,                  NULL,    0 }
		};
		int c, oidx = 0;

		c = getopt_long(argc, argv, "+:a:s:P:r:43Eep:fdihvbtgS:T:c9F:",
				long_opts, &oidx);
		if (c == -1)
			break;
		switch(c) {
			char *endptr;

		case 'a':
			address = strtoul(optarg, &endptr, 0);
			if (*endptr != '\0') {
				rc = 1;
				no_action = true;
			}
			break;
		case 's':
			read_size = write_size = strtoul(optarg, &endptr, 0);
			if (*endptr != '\0') {
				rc = 1;
				no_action = true;
			}
			break;
		case 'P':
			free(part_name);
			part_name = strdup(optarg);
			break;
		case '4':
			enable_4B = true;
			break;
		case '3':
			disable_4B = true;
			break;
		case 'r':
			if (!optarg)
				break;
			do_read = true;
			free(read_file);
			read_file = strdup(optarg);
			break;
		case 'E':
			erase_all = erase = true;
			break;
		case 'e':
			erase = true;
			break;
		case 'D':
			direct = true;
			break;
		case 'p':
			if (!optarg)
				break;
			program = true;
			free(write_file);
			write_file = strdup(optarg);
			break;
		case 'f':
			must_confirm = false;
			break;
		case 'F':
			flashfilename = optarg;
			break;
		case 'd':
			must_confirm = false;
			dummy_run = true;
			break;
		case 'i':
			info = true;
			break;
		case 'b':
			bmc_flash = true;
			break;
		case 't':
			tune = true;
			break;
		case 'v':
			show_version = true;
			break;
		case 'h':
			show_help = show_version = true;
			break;
		case 'g':
			libflash_debug = true;
			break;
		case 'S':
			flash_side = atoi(optarg);
			break;
		case 'k':
			skip_size = strtoul(optarg, &endptr, 0);
			if (*endptr != '\0') {
				rc = 1;
				no_action = true;
			}
			break;
		case 'T':
			if (!optarg)
				break;
			ffs_toc_seen = true;
			flash.toc = strtoul(optarg, &endptr, 0);
			if (*endptr != '\0') {
				rc = 1;
				no_action = true;
			}
			break;
		case 'c':
			do_clear = true;
			break;
		case 'm':
			print_detail = true;
			if (optarg) {
				detail_id = strtoul(optarg, &endptr, 0);
				if (*endptr != '\0') {
					rc = 1;
					no_action = true;
				}
			}
			break;
		case '9':
			flash.mark_ecc = true;
			break;
		case ':':
			fprintf(stderr, "Unrecognised option \"%s\" to '%c'\n", optarg, optopt);
			no_action = true;
			break;
		case '?':
			fprintf(stderr, "Unrecognised option '%c'\n", optopt);
			no_action = true;
			break;
		default:
			fprintf(stderr , "Encountered unknown error parsing options\n");
			no_action = true;
		}
	}

	if (optind < argc) {
		/*
		 * It appears not everything passed to pflash was an option, best to
		 * not continue
		 */
		while (optind < argc)
			fprintf(stderr, "Unrecognised option or argument \"%s\"\n", argv[optind++]);

		no_action = true;
	}

	/* Check if we need to access the flash at all (which will
	 * also tune them as a side effect
	 */
	no_action = no_action || (!erase && !program && !info && !do_read &&
		!enable_4B && !disable_4B && !tune && !do_clear && !print_detail);

	/* Nothing to do, if we didn't already, print usage */
	if (no_action && !show_version)
		show_help = show_version = true;

	if (show_version)
		print_version();
	if (show_help)
		print_help(pname);

	if (no_action)
		goto out;

	/* --enable-4B and --disable-4B are mutually exclusive */
	if (enable_4B && disable_4B) {
		fprintf(stderr, "--enable-4B and --disable-4B are mutually"
			" exclusive !\n");
		rc = 1;
		goto out;
	}

	/* 4B not supported on BMC flash */
	if (enable_4B && bmc_flash) {
		fprintf(stderr, "--enable-4B not supported on BMC flash !\n");
		rc = 1;
		goto out;;
	}

	/* partitions not supported on BMC flash */
	if (part_name && bmc_flash) {
		fprintf(stderr, "--partition not supported on BMC flash !\n");
		rc = 1;
		goto out;
	}

	if (print_detail && ((detail_id == UINT_MAX && !part_name)
			|| (detail_id != UINT_MAX && part_name))) {
		fprintf(stderr, "--detail requires either a partition id or\n");
		fprintf(stderr, "a partition name with -P\n");
	}

	/* part-name and erase-all make no sense together */
	if (part_name && erase_all) {
		fprintf(stderr, "--partition and --erase-all are mutually"
			" exclusive !\n");
		rc = 1;
		goto out;
	}

	/* Read command should always come with a file */
	if (do_read && !read_file) {
		fprintf(stderr, "Read with no file specified !\n");
		rc = 1;
		goto out;
	}

	/* Skip only supported on read */
	if (skip_size && !do_read) {
		fprintf(stderr, "--skip requires a --read command !\n");
		rc = 1;
		goto out;
	}

	/* Program command should always come with a file */
	if (program && !write_file) {
		fprintf(stderr, "Program with no file specified !\n");
		rc = 1;
		goto out;
	}

	/* If both partition and address specified, error out */
	if (address && part_name) {
		fprintf(stderr, "Specify partition or address, not both !\n");
		rc = 1;
		goto out;
	}

	if (do_clear && !part_name) {
		fprintf(stderr, "--clear only supported on a partition name\n");
		rc = 1;
		goto out;
	}

	/* Explicitly only support two sides */
	if (flash_side != 0 && flash_side != 1) {
		fprintf(stderr, "Unexpected value for --side '%d'\n", flash_side);
		rc = 1;
		goto out;
	}

	if (ffs_toc_seen && flash_side) {
		fprintf(stderr, "--toc and --side are exclusive");
		rc = 1;
		goto out;
	}

	if (flashfilename && bmc_flash) {
		fprintf(stderr, "Filename or bmc flash but not both\n");
		rc = 1;
		goto out;
	}

	if (flashfilename && direct) {
		fprintf(stderr, "Filename or direct access but not both\n");
		rc = 1;
		goto out;
	}

	if (tune && !direct) {
		fprintf(stderr, "It doesn't make sense to --tune without --direct\n");
		rc = 1;
		goto out;
	}

	if (direct) {
		/* If -t is passed, then print a nice message */
		if (tune)
			printf("Flash and controller tuned\n");

		if (arch_flash_access(NULL, bmc_flash ? BMC_DIRECT : PNOR_DIRECT) == ACCESS_INVAL) {
			fprintf(stderr, "Can't access %s flash directly on this architecture\n",
			        bmc_flash ? "BMC" : "PNOR");
			rc = 1;
			goto out;
		}
	} else if (!flashfilename) {
		if (arch_flash_access(NULL, bmc_flash ? BMC_MTD : PNOR_MTD) == ACCESS_INVAL) {
			fprintf(stderr, "Can't access %s flash through MTD on this system\n",
			        bmc_flash ? "BMC" : "PNOR");
			rc = 1;
			goto out;
		}
	}

	if (arch_flash_init(&flash.bl, flashfilename, true)) {
		fprintf(stderr, "Couldn't initialise architecture flash structures\n");
		rc = 1;
		goto out;
	}

	rc = blocklevel_get_info(flash.bl, &flash.name,
			    &flash.total_size, &flash.erase_granule);
	if (rc) {
		fprintf(stderr, "Error %d getting flash info\n", rc);
		rc = 1;
		goto close;
	}

	/* If file specified but not size, get size from file */
	if (write_file && !write_size) {
		struct stat stbuf;

		if (stat(write_file, &stbuf)) {
			perror("Failed to get file size");
			rc = 1;
			goto close;
		}
		write_size = stbuf.st_size;
	}

	/* Only take ECC into account under some conditions later */
	write_size_minus_ecc = write_size;

	/* If read specified and no read_size, use flash size */
	if (do_read && !read_size && !part_name)
		read_size = flash.total_size;

	/* We have a partition, adjust read/write size if needed */
	if (part_name || print_detail) {
		uint32_t pstart, pmaxsz, pactsize;
		bool ecc, confirm;

		if (ffs_toc_seen)
			ffsh = lookup_partition_at_toc(&flash,
					part_name, &ffs_index);
		else
			ffsh = lookup_partition_at_side(&flash, flash_side,
					part_name, &ffs_index);
		if (!ffsh)
			goto close;

		if (!part_name)
			ffs_index = detail_id;

		rc = ffs_part_info(ffsh, ffs_index, NULL,
				   &pstart, &pmaxsz, &pactsize, &ecc);
		if (rc) {
			fprintf(stderr,"Failed to get partition info\n");
			goto close;
		}

		if (!ecc && do_clear) {
			fprintf(stderr, "The partition on which to do --clear "
					"does not have ECC, are you sure?\n");
			confirm = check_confirm();
			if (!confirm) {
				rc = 1;
				goto close;
			}
			/* Still confirm later on */
			must_confirm = true;
		}

		/* Read size is obtained from partition "actual" size */
		if (!read_size)
			read_size = pactsize;
		/* If we're decoding ecc and partition is ECC'd, then adjust */
		if (ecc && flash.mark_ecc)
			read_size = ecc_buffer_size_minus_ecc(read_size);

		/* Write size is max size of partition */
		if (!write_size)
			write_size = pmaxsz;

		/* But write size can take into account ECC as well */
		if (ecc && flash.mark_ecc)
			write_size_minus_ecc = ecc_buffer_size_minus_ecc(write_size);
		else
			write_size_minus_ecc = write_size;

		/* Crop write size to partition size if --force was passed */
		if ((write_size_minus_ecc > pmaxsz) && !must_confirm) {
			printf("WARNING: Size (%d bytes) larger than partition"
			       " (%d bytes), cropping to fit\n",
			       write_size, pmaxsz);
			write_size = pmaxsz;
		} else if (write_size_minus_ecc > pmaxsz) {
			printf("ERROR: Size (%d bytes) larger than partition"
			       " (%d bytes). Use --force to force\n",
			       write_size, pmaxsz);
			goto close;
		}

		/* Set address */
		address = pstart;
	} else if (erase) {
		if ((address | write_size) & (flash.erase_granule - 1)) {
			if (must_confirm) {
				printf("ERROR: Erase at 0x%08x for 0x%08x isn't erase block aligned\n",
						address, write_size);
				printf("Use --force to force\n");
				goto close;
			} else {
				printf("WARNING: Erase at 0x%08x for 0x%08x isn't erase block aligned\n",
						address, write_size);
			}
		}
	}

	/* Process commands */

	/* Both enable and disable can't be set (we've checked) */
	if (enable_4B)
		rc = enable_4B_addresses(flash.bl);
	if (disable_4B)
		rc = disable_4B_addresses(flash.bl);
	if (rc)
		goto close;

	if (info) {
		/*
		 * Don't pass through modfied TOC value if the modification was done
		 * because of --size, but still respect if it came from --toc (we
		 * assume the user knows what they're doing in that case)
		 */
		print_flash_info(&flash);
	}

	if (print_detail)
		print_partition_detail(ffsh, ffs_index);

	/* Unlock flash (PNOR only) */
	if ((erase || program || do_clear) && !bmc_flash && !flashfilename) {
		flash.need_relock = arch_flash_set_wrprotect(flash.bl, false);
		if (flash.need_relock == -1) {
			fprintf(stderr, "Architecture doesn't support write protection on flash\n");
			flash.need_relock = 0;
			goto close;
		}
	}
	rc = 0;
	if (do_read)
		rc = do_read_file(flash.bl, read_file, address, read_size, skip_size);
	if (!rc && erase_all)
		rc = erase_chip(&flash);
	else if (!rc && erase)
		rc = erase_range(&flash, address, write_size,
				program, ffsh, ffs_index);
	if (!rc && program)
		rc = program_file(flash.bl, write_file, address, write_size_minus_ecc,
				ffsh, ffs_index);
	if (!rc && do_clear)
		rc = set_ecc(&flash, address, write_size);

close:
	if (flash.need_relock)
		arch_flash_set_wrprotect(flash.bl, 1);
	arch_flash_close(flash.bl, flashfilename);
	if (ffsh)
		ffs_close(ffsh);
out:
	free(part_name);
	free(read_file);
	free(write_file);

	return rc;
}
