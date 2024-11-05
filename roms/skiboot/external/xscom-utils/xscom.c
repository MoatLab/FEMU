// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Do XSCOMs through linux debugfs interface
 *
 * Copyright 2014-2017 IBM Corp.
 */

#define _LARGEFILE64_SOURCE
#include <sys/mman.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <dirent.h>
#include <assert.h>
#include <ctype.h>

#include "xscom.h"

#define XSCOM_BASE_PATH "/sys/kernel/debug/powerpc/scom"

struct xscom_chip {
	struct xscom_chip	*next;
	uint32_t		chip_id;
	int			fd;
};
static struct xscom_chip *xscom_chips;

void xscom_for_each_chip(void (*cb)(uint32_t chip_id))
{
	struct xscom_chip *c;

	for (c = xscom_chips; c; c = c->next)
		cb(c->chip_id);
}

static uint32_t xscom_add_chip(const char *base_path, const char *dname)
{
	char nbuf[strlen(base_path) + strlen(dname) + 16];
	struct xscom_chip *chip;
	int fd;

	snprintf(nbuf, sizeof(nbuf), "%s/%s/access", base_path, dname);
	fd = open(nbuf, O_RDWR);
	if (fd < 0) {
		perror("Failed to open SCOM access file");
		exit(1);
	}

	chip = malloc(sizeof(*chip));
	assert(chip);
	memset(chip, 0, sizeof(*chip));
	chip->fd = fd;
	chip->chip_id = strtoul(dname, NULL, 16);
	chip->next = xscom_chips;
	xscom_chips = chip;

	return chip->chip_id;
}

static bool xscom_check_dirname(const char *n)
{
	while(*n) {
		char c = toupper(*(n++));

		if ((c < 'A' || c > 'Z') &&
		    (c < '0' || c > '9'))
			return false;
	}
	return true;
}

static uint32_t xscom_scan_chips(const char *base_path)
{
	int i, nfiles;
	struct dirent **filelist;
	uint32_t lower = 0xffffffff;

	nfiles = scandir(base_path, &filelist, NULL, alphasort);
	if (nfiles < 0) {
		perror("Error accessing sysfs scom directory");
		exit(1);
	}
	if (nfiles == 0) {
		fprintf(stderr, "No SCOM dir found in sysfs\n");
		exit(1);
	}

	for (i = 0; i < nfiles; i++) {
		struct dirent *d = filelist[i];
		uint32_t id;

		if (d->d_type != DT_DIR)
			continue;
		if (!xscom_check_dirname(d->d_name))
			continue;
		id = xscom_add_chip(base_path, d->d_name);
		if (id < lower)
			lower = id;
		free(d);
	}

	free(filelist);
	return lower;
}

static struct xscom_chip *xscom_find_chip(uint32_t chip_id)
{
	struct xscom_chip *c;

	for (c = xscom_chips; c; c = c->next)
		if (c->chip_id == chip_id)
			return c;
	return NULL;
}

static uint64_t xscom_mangle_addr(uint64_t addr)
{
	uint64_t tmp;

	/*
	 * Shift the top 4 bits (indirect mode) down by 4 bits so we
	 * don't lose going through the debugfs interfaces.
	 */
	tmp = (addr & 0xf000000000000000) >> 4;
	addr &= 0x00ffffffffffffff;
	addr |= tmp;

	/* Shift up by 3 for debugfs */
	return addr << 3;
}

int xscom_read(uint32_t chip_id, uint64_t addr, uint64_t *val)
{
	struct xscom_chip *c = xscom_find_chip(chip_id);
	int rc;

	if (!c)
		return -ENODEV;
	addr = xscom_mangle_addr(addr);
	lseek64(c->fd, addr, SEEK_SET);
	rc = read(c->fd, val, 8);
	if (rc < 0)
		return -errno;
	if (rc != 8)
		return -EIO;
	return 0;
}

int xscom_write(uint32_t chip_id, uint64_t addr, uint64_t val)
{
	struct xscom_chip *c = xscom_find_chip(chip_id);
	int rc;

	if (!c)
		return -ENODEV;
	addr = xscom_mangle_addr(addr);
	lseek64(c->fd, addr, SEEK_SET);
	rc = write(c->fd, &val, 8);
	if (rc < 0)
		return -errno;
	if (rc != 8)
		return -EIO;
	return 0;
}

int xscom_read_ex(uint32_t ex_target_id, uint64_t addr, uint64_t *val)
{
	uint32_t chip_id = ex_target_id >> 4;;

	addr |= (ex_target_id & 0xf) << 24;

	/* XXX TODO: Special wakeup ? */

	return xscom_read(chip_id, addr, val);
}

int xscom_write_ex(uint32_t ex_target_id, uint64_t addr, uint64_t val)
{
	uint32_t chip_id = ex_target_id >> 4;;

	addr |= (ex_target_id & 0xf) << 24;

	/* XXX TODO: Special wakeup ? */

	return xscom_write(chip_id, addr, val);
}

bool xscom_readable(uint64_t addr)
{
	/* Top nibble 9 indicates form 1 indirect, which is write only */
	if (((addr >> 60) & 0xf) == 9)
		return false;
	return true;
}

uint32_t xscom_init(void)
{
	return xscom_scan_chips(XSCOM_BASE_PATH);
}
