// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Manipulate GARD records in the GARD partition
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>
#include <inttypes.h>
#include <ctype.h>

#include <ccan/array_size/array_size.h>

#include <mtd/mtd-abi.h>

#include <getopt.h>

#include <libflash/libflash.h>
#include <libflash/libffs.h>
#include <libflash/file.h>
#include <libflash/blocklevel.h>
#include <common/arch_flash.h>

#include "gard.h"

#define FDT_PATH "/proc/device-tree"
#define FDT_FSP_NODE FDT_PATH"/fsps"
#define FDT_ACTIVE_FLASH_PATH FDT_PATH"/chosen/ibm,system-flash"
#define SYSFS_MTD_PATH "/sys/class/mtd/"
#define FLASH_GARD_PART "GUARD"

#define VPNOR_GARD_DIR "/media/pnor-prsv"
#define VPNOR_GARD_FILE VPNOR_GARD_DIR"/GUARD"

/* Full gard version number (possibly includes gitid). */
extern const char version[];


#define __unused __attribute__((unused))

struct gard_ctx {
	uint32_t f_size;
	uint32_t f_pos;

	uint32_t gard_part_idx;
	uint32_t gard_data_pos;
	uint32_t gard_data_len;

	struct blocklevel_device *bl;
	struct ffs_handle *ffs;
};

static void show_flash_err(int rc)
{
	switch (rc) {
		case FFS_ERR_BAD_MAGIC:
			fprintf(stderr, "libffs bad magic\n");
			break;
		case FFS_ERR_BAD_VERSION:
			fprintf(stderr, "libffs bad version\n");
			break;
		case FFS_ERR_BAD_CKSUM:
			fprintf(stderr, "libffs bad check sum\n");
			break;
		case FFS_ERR_PART_NOT_FOUND:
			fprintf(stderr, "libffs flash partition not found\n");
			break;
			/* ------- */
		case FLASH_ERR_MALLOC_FAILED:
			fprintf(stderr, "libflash malloc failed\n");
			break;
		case FLASH_ERR_CHIP_UNKNOWN:
			fprintf(stderr, "libflash unknown flash chip\n");
			break;
		case FLASH_ERR_PARM_ERROR:
			fprintf(stderr, "libflash parameter error\n");
			break;
		case FLASH_ERR_ERASE_BOUNDARY:
			fprintf(stderr, "libflash erase boundary error\n");
			break;
		case FLASH_ERR_WREN_TIMEOUT:
			fprintf(stderr, "libflash WREN timeout\n");
			break;
		case FLASH_ERR_WIP_TIMEOUT:
			fprintf(stderr, "libflash WIP timeout\n");
			break;
		case FLASH_ERR_VERIFY_FAILURE:
			fprintf(stderr, "libflash verification failure\n");
			break;
		case FLASH_ERR_4B_NOT_SUPPORTED:
			fprintf(stderr, "libflash 4byte mode not supported\n");
			break;
		case FLASH_ERR_CTRL_CONFIG_MISMATCH:
			fprintf(stderr, "libflash control config mismatch\n");
			break;
		case FLASH_ERR_CHIP_ER_NOT_SUPPORTED:
			fprintf(stderr, "libflash chip not supported\n");
			break;
		case FLASH_ERR_CTRL_CMD_UNSUPPORTED:
			fprintf(stderr, "libflash unsupported control command\n");
			break;
		case FLASH_ERR_CTRL_TIMEOUT:
			fprintf(stderr, "libflash control timeout\n");
			break;
		case FLASH_ERR_ECC_INVALID:
			fprintf(stderr, "libflash ecc invalid\n");
			break;
		default:
			fprintf(stderr, "A libflash/libffs error has occurred %d\n", rc);
	}
}

const struct chip_unit_desc *chip_units;
int chip_unit_count;

static void set_chip_gen(const struct chip_unit_desc *c)
{
	chip_units = c;
	chip_unit_count = 0;

	while (strcmp("LAST_IN_RANGE", c->desc)) {
		chip_unit_count++;
		c++;
	}
}

#ifdef __powerpc64__
static void guess_chip_gen(void)
{
	/*
	 * Guesstimate what chip generation based on the PVR if we're running
	 * on ppc64.
	 */
	uint32_t pvr;

	/* grab the chip type from the PVR SPR */
	asm ("mfspr  %0,0x11f" : "=r" (pvr));

	switch (pvr >> 16) {
	case 0x004b: /* murano */
	case 0x004c: /* naples */
	case 0x004d: /* venice */
		set_chip_gen(p8_chip_units);
		return;

	case 0x004e: /* nimbus */
	case 0x004f: /* axone */
		set_chip_gen(p9_chip_units);
		return;

	case 0x0080: /* power10 */
		set_chip_gen(p10_chip_units);
		return;

	default:
		fprintf(stderr, "Unsupported processor (pvr %#x)! Set the processor generation manually with -8, -9 or -0\n", pvr);
		exit(1);
	}
}
#else
static void guess_chip_gen(void)
{
#ifdef ASSUME_P8
	set_chip_gen(p8_chip_units);
#else
	set_chip_gen(p9_chip_units);
#endif
}
#endif

static const char *target_type_to_str(int type)
{
	int i;

	for (i = 0; i < chip_unit_count; i++)
		if (chip_units[i].type == type)
			return chip_units[i].desc;

	return "UNKNOWN";
}

static int str_to_target_type(const char *path)
{
	int i, len;

	for (i = 0; i < chip_unit_count; i++) {
		len = strlen(chip_units[i].desc);

		if (!strncasecmp(chip_units[i].desc, path, len))
			return chip_units[i].type; /* match! */
	}

	return -1;
}

static const char *deconfig_reason_str(enum gard_reason reason)
{
	switch (reason) {
	case GARD_NO_REASON:
		return "None";
	case GARD_MANUAL:
		return "Manual";
	case GARD_UNRECOVERABLE:
		return "Unrecoverable";
	case GARD_FATAL:
		return "Fatal";
	case GARD_PREDICTIVE:
		return "Predictive";
	case GARD_POWER:
		return "Power"; // What does this even mean?
	case GARD_HYP:
		return "Hypervisor";
	case GARD_RECONFIG:
		return "Reconfig";
	default:
		return "Unknown";
	}
};

static const char *path_type_to_str(enum path_type t)
{
	switch (t) {
		case PATH_NA:
			return "not applicable";
		case PATH_AFFINITY:
			return "affinity";
		case PATH_PHYSICAL:
			return "physical";
		case PATH_DEVICE:
			return "device";
		case PATH_POWER:
			return "power";
	}
	return "Unknown";
}

/*
 * NB: buffer is assumped to be MAX_PATH_SIZE
 */
static char *format_path(struct entity_path *path, char *buffer)
{
	int elements = path->type_size & PATH_ELEMENTS_MASK;
	int i, offset = 0;

	for (i = 0; i < elements; i++) {
		const struct path_element *e = &path->path_elements[i];

		offset += sprintf(buffer + offset, "/%s%d",
			target_type_to_str(e->target_type),
			e->instance);
	}

	return buffer;
}

/*
 * parses a Path string into the entity_path structured provided.
 *
 * str    - In param, String to parse
 * parsed - Out param, resultant entity_path
 *
 * e.g.
 *
 * "/Sys0/Node0/Proc1" -> {
 *      type_size = 0x23,
 *
 *      path_element[0] = {0, 0}
 *      path_element[1] = {1, 0}
 *      path_element[2] = {2, 1}
 * }
 */
static int parse_path(const char *str, struct entity_path *parsed)
{
	int unit_count = 0;

	memset(parsed, 0, sizeof(*parsed));

	while (*str != '\0') {
		int unit_id = str_to_target_type(++str); /* ++ skips the '/' */
		long instance;
		char *end;
		size_t len;

		if (unit_count > MAX_PATH_ELEMENTS - 1) {
			fprintf(stderr, "Path has more than 10 components!\n");
			return -1;
		}

		/* find the type Id of this component */
		if (unit_id < 0) { /* unknown unit, bail out */
			fprintf(stderr, "Unknown unit at: '%s'\n", str);
			return -1;
		}

		parsed->path_elements[unit_count].target_type = unit_id;

		/* now parse the instance # */
		len = strlen(target_type_to_str(unit_id));
		instance = strtol(str + len, &end, 10);

		if (!isdigit(*(str + len))) {
			fprintf(stderr, "Missing instance number after '%s'\n",
					str);
			return -1;
		}

		if (*end != '\0' && *end != '/') {
			fprintf(stderr, "Unable to parse instance after '%s'\n",
					str);
			return -1;
		}

		if (instance > 255 || instance < 0) {
			fprintf(stderr,
				"Instance %ld is invalid. Must be 0 to 255\n",
				instance);
			return -1;
		}
		parsed->path_elements[unit_count].instance = instance;

		str = end;
		unit_count++;
	}

	/*
	 * We assume the path is a physical path because every gard record I've
	 * seen so far uses them. We might need to fix this later on, but lets
	 * cross the bridge when we have to.
	 */
	parsed->type_size = (unit_count & 0xf) |
			(PATH_PHYSICAL << PATH_TYPE_SHIFT);

	return 0;
}

static struct gard_record blank_record;

static bool is_valid_record(struct gard_record *g)
{
	return memcmp(&blank_record, g, sizeof(*g));
}

static int do_iterate(struct gard_ctx *ctx,
		int (*func)(struct gard_ctx *ctx, int pos,
			struct gard_record *gard, void *priv),
		void *priv)
{
	int rc = 0;
	unsigned int i;
	struct gard_record gard, null_gard;

	memset(&null_gard, UINT_MAX, sizeof(gard));
	for (i = 0; i * sizeof(gard) < ctx->gard_data_len && rc == 0; i++) {
		memset(&gard, 0, sizeof(gard));

		rc = blocklevel_read(ctx->bl, ctx->gard_data_pos + (i * sizeof(gard)),
					&gard, sizeof(gard));
		/* It isn't super clear what constitutes the end, this should do */
		if (rc || memcmp(&gard, &null_gard, sizeof(gard)) == 0)
			break;

		rc = func(ctx, i, &gard, priv);
	}

	return rc;
}

/*
 * read the next guard record into the supplied buffer (gard)
 *
 * returns the record id (nb: 1 based not zero)
 *
 */
static int __gard_next(struct gard_ctx *ctx, int pos, struct gard_record *gard, int *rc)
{
	uint32_t offset = pos * sizeof(*gard);

	if (offset > ctx->gard_data_len) /* too big */
		return -1;

	/* you lose error handling information, *gruble* */
	memset(gard, 0, sizeof(*gard));
	*rc = blocklevel_read(ctx->bl, ctx->gard_data_pos + offset,
				gard, sizeof(*gard));

	if (!is_valid_record(gard))
		return -1;

	if (*rc)
		return -1;

	return pos;
}

#define for_each_gard(ctx, pos, gard, rc) \
	for (pos = __gard_next(ctx, 0, gard, rc); \
		pos >= 0; pos = __gard_next(ctx, ++pos, gard, rc))

static int count_records(struct gard_ctx *ctx)
{
	struct gard_record record;
	int rc, pos, count = 0;

	for_each_gard(ctx, pos, &record, &rc)
		count++;

	return rc ? rc : count;
}

static int count_valid_records(struct gard_ctx *ctx)
{
	struct gard_record record;
	int rc, pos, count = 0;

	for_each_gard(ctx, pos, &record, &rc)
		count++;

	return rc ? rc : count;
}

static size_t find_longest_path(struct gard_ctx *ctx)
{
	char scratch[MAX_PATH_SIZE];
	struct gard_record gard;
	size_t len, longest = 0;
	int rc, pos;

	for_each_gard(ctx, pos, &gard, &rc) {
		len = strlen(format_path(&gard.target_id, scratch));
		if (len > longest)
			longest = len;
	}

	return longest;
}

static void draw_ruler(char c, int size)
{
	int i;

	for (i = 0; i < size; i++)
		putchar(c);
	putchar('\n');
}

static int do_list(struct gard_ctx *ctx, int argc __attribute__((unused)),
		   char **argv __attribute__((unused)))
{
	/* This header matches the line formatting above in do_list_i() */
	const char *header = " ID       | Error    | Type       | Path";
	size_t ruler_size;
	char scratch[MAX_PATH_SIZE];
	struct gard_record gard;
	int rc = 0, pos;

	/* No entries */
	if (count_valid_records(ctx) == 0) {
		printf("No GARD entries to display\n");
		return 0;
	}

	puts(header);

	ruler_size = strlen(header) + find_longest_path(ctx);
	draw_ruler('-', ruler_size);

	for_each_gard(ctx, pos, &gard, &rc) {
		printf(" %08x | %08x | %-10s | %s%s\n",
			be32toh(gard.record_id),
			be32toh(gard.errlog_eid),
			deconfig_reason_str(gard.error_type),
			format_path(&gard.target_id, scratch),
                        gard.record_id == 0xffffffff ? " *CLEARED*" : "");
	}

	draw_ruler('=', ruler_size);

	return rc;
}

static int do_show_i(struct gard_ctx *ctx, int pos, struct gard_record *gard, void *priv)
{
	uint32_t id;

	(void)ctx;
	(void)pos;

	if (!priv || !gard)
		return -1;

	id = *(uint32_t *)priv;

	if (be32toh(gard->record_id) == id) {
		unsigned int count, i;

		printf("Record ID:    0x%08x%s\n", id, id == 0xffffffff ? " *CLEARED*" : "");
		printf("========================\n");
		printf("Error ID:     0x%08x\n", be32toh(gard->errlog_eid));
		printf("Error Type:   %s (0x%02x)\n",
			deconfig_reason_str(gard->error_type),
			gard->error_type);
		printf("Path Type: %s\n", path_type_to_str(gard->target_id.type_size >> PATH_TYPE_SHIFT));
		count = gard->target_id.type_size & PATH_ELEMENTS_MASK;
		for (i = 0; i < count && i < MAX_PATH_ELEMENTS; i++)
			printf("%*c%s, Instance #%d\n", i + 1, '>', target_type_to_str(gard->target_id.path_elements[i].target_type),
			       gard->target_id.path_elements[i].instance);
	}

	return 0;
}

static int do_show(struct gard_ctx *ctx, int argc, char **argv)
{
	uint32_t id;
	int rc;

	if (argc != 2) {
		fprintf(stderr, "%s option requires a GARD record\n", argv[0]);
		return -1;
	}

	id = strtoul(argv[1], NULL, 16);

	rc = do_iterate(ctx, &do_show_i, &id);

	return rc;
}

static int do_clear_i(struct gard_ctx *ctx, int pos, struct gard_record *gard, void *priv)
{
	int largest, rc = 0;
	char *buf;
	struct gard_record null_gard;

	if (!gard || !ctx || !priv)
		return -1;

	/* Not this one */
	if (be32toh(gard->record_id) != *(uint32_t *)priv)
		return 0;

	memset(&null_gard, 0xFF, sizeof(null_gard));

	largest = count_records(ctx);

	printf("Clearing gard record 0x%08x...", be32toh(gard->record_id));

	if (largest < 0 || pos > largest) {
		/* Something went horribly wrong */
		fprintf(stderr, "largest index out of range %d\n", largest);
		return -1;
	}

	if (pos < largest) {
		/* We're not clearing the last record, shift all the records up */
		int buf_len = ((largest - pos) * sizeof(struct gard_record));
		int buf_pos = ctx->gard_data_pos + ((pos + 1) * sizeof(struct gard_record));
		buf = malloc(buf_len);
		if (!buf)
			return -ENOMEM;

		rc = blocklevel_read(ctx->bl, buf_pos, buf, buf_len);
		if (rc) {
			free(buf);
			fprintf(stderr, "Couldn't read from flash at 0x%08x for len 0x%08x\n", buf_pos, buf_len);
			return rc;
		}

		rc = blocklevel_smart_write(ctx->bl, buf_pos - sizeof(*gard), buf, buf_len);
		free(buf);
		if (rc) {
			fprintf(stderr, "Couldn't write to flash at 0x%08x for len 0x%08x\n",
					buf_pos - (int) sizeof(struct gard_record), buf_len);
			return rc;
		}
	}

	/* Now wipe the last record */
	rc = blocklevel_smart_write(ctx->bl, ctx->gard_data_pos + (largest * sizeof(null_gard)),
	                            &null_gard, sizeof(null_gard));
	printf("done\n");

	return rc;
}

static int reset_partition(struct gard_ctx *ctx)
{
	int no_ecc_len = (ctx->gard_data_len / 9) * 8;
	struct gard_record *gard;
	int rc = 0;

	gard = malloc(ctx->gard_data_len);
	if (!gard) {
		return FLASH_ERR_MALLOC_FAILED;
	}
	memset(gard, 0xFF, ctx->gard_data_len);

	rc = blocklevel_smart_erase(ctx->bl, ctx->gard_data_pos, ctx->gard_data_len);
	if (rc) {
		fprintf(stderr, "Couldn't erase the gard partition. Bailing out\n");
		goto out;
	}

	rc = blocklevel_write(ctx->bl, ctx->gard_data_pos, gard, no_ecc_len);
	if (rc)
		fprintf(stderr, "Couldn't reset the entire gard partition. Bailing out\n");

out:
	free(gard);
	return rc;
}

static int do_clear(struct gard_ctx *ctx, int argc, char **argv)
{
	int rc;
	uint32_t id;

	if (argc != 2) {
		fprintf(stderr, "%s option requires a GARD record or 'all'\n", argv[0]);
		return -1;
	}

	if (strncmp(argv[1], "all", strlen("all")) == 0) {
		printf("Clearing the entire gard partition...");
		fflush(stdout);
		rc = reset_partition(ctx);
		printf("done\n");
	} else {
		id = strtoul(argv[1], NULL, 16);
		rc = do_iterate(ctx, do_clear_i, &id);
	}

	return rc;
}

static int do_create(struct gard_ctx *ctx, int argc, char **argv)
{
	int rc, pos, max_id = 0, last_pos = 0;
	struct gard_record gard;
	struct entity_path path;

	if (argc < 2) {
		fprintf(stderr, "create requires path to gard\n");
		fprintf(stderr, "e.g.\n");
		fprintf(stderr, "     /Sys0/Node0/Proc0\n");
		fprintf(stderr, "     /Sys0/Node0/DIMM15\n");
		return -1;
	}

	if (parse_path(argv[1], &path)) {
		fprintf(stderr, "Unable to parse path\n");
		return -1;
	}

	/* check if we already have a gard record applied to this path */
	for_each_gard(ctx, pos, &gard, &rc) {
		if (!memcmp(&path, &gard.target_id, sizeof(path))) {
			fprintf(stderr,
				"Unit %s is already GARDed by record %#08x\n",
				argv[1], be32toh(gard.record_id));
			return -1;
		}

		/*
		 * Keep track of the largest record ID seen so far,
		 * we'll give the new record the max + 1 to ensure
		 * that it's unique
		 */
		if (be32toh(gard.record_id) > max_id)
			max_id = be32toh(gard.record_id);

		last_pos++;
	}

	/* do we have an empty record to write into? */
	if (!rc && !is_valid_record(&gard)) {
		int offset = last_pos * sizeof(gard);

		memset(&gard, 0xff, sizeof(gard));

		gard.record_id = be32toh(max_id + 1);
		gard.error_type = GARD_MANUAL;
		gard.target_id = path;
		gard.errlog_eid = 0x0;

		if (offset > ctx->gard_data_len - sizeof(gard)) {
			fprintf(stderr, "No space in GUARD for a new record\n");
			return -1;
		}

		rc = blocklevel_smart_write(ctx->bl,
			ctx->gard_data_pos + offset, &gard, sizeof(gard));
	}

	return rc;
}

static int check_gard_partition(struct gard_ctx *ctx)
{
	int rc;
	struct gard_record gard;
	char msg[2];

	if (ctx->gard_data_len == 0 || ctx->gard_data_len % sizeof(struct gard_record) != 0)
		/* Just warn for now */
		fprintf(stderr, "The %s partition doesn't appear to be an exact multiple of"
				"gard records in size: %zd vs %u (or partition is zero in length)\n",
				FLASH_GARD_PART, sizeof(struct gard_record), ctx->gard_data_len);

	/*
	 * Attempt to read the first record, nothing can really operate if the
	 * first record is dead. There (currently) isn't a way to validate more
	 * than ECC correctness.
	 */
	rc = blocklevel_read(ctx->bl, ctx->gard_data_pos, &gard, sizeof(gard));
	if (rc == FLASH_ERR_ECC_INVALID) {
		fprintf(stderr, "The data at the GUARD partition does not appear to be valid gard data\n");
		fprintf(stderr, "Clear the entire GUARD partition? [y/N]\n");
		if (fgets(msg, sizeof(msg), stdin) == NULL) {
			fprintf(stderr, "Couldn't read from standard input\n");
			return -1;
		}
		if (msg[0] == 'y') {
			rc = reset_partition(ctx);
			if (rc) {
				fprintf(stderr, "Couldn't reset the GUARD partition. Bailing out\n");
				return rc;
			}
		}
		/*
		 * else leave rc as is so that the main bails out, not going to be
		 * able to do sensible anyway
		 */
	}
	return rc;
}

__attribute__ ((unused))
static int do_nop(struct gard_ctx *ctx, int argc, char **argv)
{
	(void)ctx;
	(void)argc;
	fprintf(stderr, "Unimplemented action '%s'\n", argv[0]);
	return EXIT_SUCCESS;
}

struct {
	const char	*name;
	const char	*desc;
	int		(*fn)(struct gard_ctx *, int, char **);
} actions[] = {
	{ "list", "List current GARD records", do_list },
	{ "show", "Show details of a GARD record", do_show },
	{ "clear", "Clear GARD records", do_clear },
	{ "create", "Create a GARD record", do_create },
};

static void print_version(void)
{
	printf("Open-Power GARD tool %s\n", version);
}

static void usage(const char *progname)
{
	unsigned int i;

	print_version();
	fprintf(stderr, "Usage: %s [-a -e -f <file> -p] <command> [<args>]\n\n",
			progname);
	fprintf(stderr, "-8 --p8\n");
	fprintf(stderr, "-9 --p9\n");
	fprintf(stderr, "-0 --p10\n\tSet the processor generation\n\n");
	fprintf(stderr, "-e --ecc\n\tForce reading/writing with ECC bytes.\n\n");
	fprintf(stderr, "-f --file <file>\n\tDon't search for MTD device,"
	                " read from <file>.\n\n");
	fprintf(stderr, "-p --part\n\tUsed in conjunction with -f to specify"
	                " that just\n");
	fprintf(stderr, "\tthe GUARD partition is in <file> and libffs\n");
	fprintf(stderr, "\tshouldn't be used.\n\n");


	fprintf(stderr, "Where <command> is one of:\n\n");

	for (i = 0; i < ARRAY_SIZE(actions); i++) {
		fprintf(stderr,  "\t%-7s\t%s\n",
				actions[i].name, actions[i].desc);
	}
}

static bool is_fsp(void)
{
	return access(FDT_FSP_NODE, F_OK) == 0;
}

static struct option global_options[] = {
	{ "file", required_argument, 0, 'f' },
	{ "part", no_argument, 0, 'p' },
	{ "ecc", no_argument, 0, 'e' },
	{ "p8", no_argument, 0, '8' },
	{ "p9", no_argument, 0, '9' },
	{ "p10", no_argument, 0, '0' },
	{ 0 },
};
static const char *global_optstring = "+ef:p890";

int main(int argc, char **argv)
{
	const char *action, *progname;
	char *filename = NULL;
	struct gard_ctx _ctx, *ctx;
	uint64_t bl_size;
	int rc, i = 0;
	bool part = 0;
	bool ecc = 0;

	progname = argv[0];

	ctx = &_ctx;
	memset(ctx, 0, sizeof(*ctx));
	memset(&blank_record, 0xff, sizeof(blank_record));

	/* process global options */
	for (;;) {
		int c;

		c = getopt_long(argc, argv, global_optstring, global_options,
				NULL);
		if (c == -1)
			break;
		switch (c) {
		case 'e':
			ecc = true;
			break;
		case 'f':
			/* If they specify -f twice */
			free(filename);

			filename = strdup(optarg);
			if (!filename) {
				fprintf(stderr, "Out of memory\n");
				return EXIT_FAILURE;
			}
			break;
		case 'p':
			part = true;
			break;
		case '8':
			set_chip_gen(p8_chip_units);
			break;
		case '9':
			set_chip_gen(p9_chip_units);
			break;
		case '0':
			set_chip_gen(p10_chip_units);
			break;
		case '?':
			usage(progname);
			rc = EXIT_FAILURE;
			goto out_free;
		}
	}


	if (is_fsp() && !filename) {
		fprintf(stderr, "This is the OpenPower gard tool which does "
				"not support FSP systems\n");
		return EXIT_FAILURE;
	}


	/*
	 * It doesn't make sense to specify that we have the gard partition but
	 * read from flash
	 */
	if (part && !filename) {
		usage(progname);
		fprintf(stderr, "-p only makes sense when used with -f!\n");
		return EXIT_FAILURE;
	}

	/* do we have a command? */
	if (optind == argc) {
		usage(progname);
		rc = EXIT_FAILURE;
		goto out_free;
	}

	argc -= optind;
	argv += optind;
	action = argv[0];

#ifdef __arm__
	/*
	 * HACK: Look for a vPNOR GUARD file if we haven't been given anything
	 * explitly. If it exists then we can safely assume that:
	 * a) The host is a P9
	 * b) The file is ECC protected
	 * c) The file is a bare partition.
	 *
	 * This is a stupid hack, but there's not other sane place for it.
	 * arch_init_flash() always looks for a FFS formatted PNOR when
	 * filename is NULL
	 */
	if (!filename) {
		struct stat buf;

		if (!stat(VPNOR_GARD_FILE, &buf)) {
			filename = strdup(VPNOR_GARD_FILE);
			/* BUG: This ignores the command line settings */
			part = true;
			ecc = true;
		} else if (!stat(VPNOR_GARD_DIR, &buf)) {
			printf(VPNOR_GARD_FILE" is missing. Nothing to do\n");
			return 0;
		}
	}
#endif

	if (!chip_units)
		guess_chip_gen();

	/*
	 * Force libflash to do flash accesses via the MTD. Direct mode is
	 * generally unsafe since it fiddles with the flash controller state
	 * underneath the kernel. Anyone who needs direct mode can use pflash
	 * instead.
	 */
	arch_flash_access(ctx->bl, PNOR_MTD);

	if (arch_flash_init(&(ctx->bl), filename, true)) {
		/* Can fail for a few ways, most likely couldn't open MTD device */
		fprintf(stderr, "Can't open %s\n", filename ? filename : "MTD Device. Are you root?");
		rc = EXIT_FAILURE;
		goto out_free;
	}

	rc = blocklevel_get_info(ctx->bl, NULL, &bl_size, NULL);
	if (rc)
		goto out;

	if (bl_size > UINT_MAX) {
		fprintf(stderr, "MTD device bigger than %i: size: %" PRIu64 "\n",
			UINT_MAX, bl_size);
		rc = EXIT_FAILURE;
		goto out;
	}
	ctx->f_size = bl_size;

	if (!part) {
		rc = ffs_init(0, ctx->f_size, ctx->bl, &ctx->ffs, 1);
		if (rc)
			goto out;

		rc = ffs_lookup_part(ctx->ffs, FLASH_GARD_PART, &ctx->gard_part_idx);
		if (rc)
			goto out;

		rc = ffs_part_info(ctx->ffs, ctx->gard_part_idx, NULL, &(ctx->gard_data_pos),
				&(ctx->gard_data_len), NULL, NULL);
		if (rc)
			goto out;
	} else {
		if (ecc) {
			rc = blocklevel_ecc_protect(ctx->bl, 0, ctx->f_size);
			if (rc)
				goto out;
		}

		ctx->gard_data_pos = 0;
		ctx->gard_data_len = ctx->f_size;
	}

	rc = check_gard_partition(ctx);
	if (rc) {
		fprintf(stderr, "Does not appear to be sane gard data\n");
		goto out;
	}

	for (i = 0; i < ARRAY_SIZE(actions); i++) {
		if (!strcmp(actions[i].name, action)) {
			rc = actions[i].fn(ctx, argc, argv);
			break;
		}
	}

out:
	if (ctx->ffs)
		ffs_close(ctx->ffs);

	file_exit_close(ctx->bl);

	if (i == ARRAY_SIZE(actions)) {
		fprintf(stderr, "%s: '%s' isn't a valid command\n", progname, action);
		usage(progname);
		rc = EXIT_FAILURE;
		goto out_free;
	}

	if (rc > 0) {
		show_flash_err(rc);
		if (filename && rc == FFS_ERR_BAD_MAGIC)
			fprintf(stderr, "Maybe you didn't give a full flash image file?\nDid you mean '--part'?\n");
	}

out_free:
	free(filename);
	return rc;
}
