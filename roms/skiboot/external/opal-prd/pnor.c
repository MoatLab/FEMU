// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * PNOR Access (/dev/mtd) for opal-prd
 *
 * Copyright 2013-2017 IBM Corp.
 */

#include <libflash/libffs.h>
#include <common/arch_flash.h>

#include <errno.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <mtd/mtd-user.h>

#include "pnor.h"
#include "opal-prd.h"

#define FDT_FLASH_PATH "/proc/device-tree/chosen/ibm,system-flash"

bool pnor_available(struct pnor *pnor)
{
	/* --pnor is specified */
	if (pnor->path) {
		if (access(pnor->path, R_OK | W_OK) == 0)
			return true;

		pr_log(LOG_ERR, "PNOR: Does not have permission to read pnor: %m");
		return false;
	}

	if (access(FDT_FLASH_PATH, R_OK) == 0)
		return true;

	return false;
}

int pnor_init(struct pnor *pnor)
{
	int rc;

	if (!pnor)
		return -1;

	rc = arch_flash_init(&(pnor->bl), pnor->path, false);
	if (rc) {
		pr_log(LOG_ERR, "PNOR: Flash init failed");
		return -1;
	}

	rc = blocklevel_get_info(pnor->bl, NULL, &(pnor->size), &(pnor->erasesize));
	if (rc) {
		pr_log(LOG_ERR, "PNOR: blocklevel_get_info() failed. Can't use PNOR");
		goto out;
	}

	rc = ffs_init(0, pnor->size, pnor->bl, &pnor->ffsh, 0);
	if (rc) {
		pr_log(LOG_ERR, "PNOR: Failed to open pnor partition table");
		goto out;
	}

	return 0;
out:
	arch_flash_close(pnor->bl, pnor->path);
	pnor->bl = NULL;
	return -1;
}

void pnor_close(struct pnor *pnor)
{
	if (!pnor)
		return;

	if (pnor->ffsh)
		ffs_close(pnor->ffsh);

	if (pnor->bl)
		arch_flash_close(pnor->bl, pnor->path);

	if (pnor->path)
		free(pnor->path);
}

void dump_parts(struct ffs_handle *ffs) {
	int i, rc;
	uint32_t start, size, act_size;
	char *name;

	pr_debug("PNOR: %10s %8s %8s %8s",
			"name", "start", "size", "act_size");
	for (i = 0; ; i++) {
		rc = ffs_part_info(ffs, i, &name, &start,
				&size, &act_size, NULL);
		if (rc)
			break;
		pr_debug("PNOR: %10s %08x %08x %08x",
				name, start, size, act_size);
		free(name);
	}
}

static int mtd_write(struct pnor *pnor, void *data, uint64_t offset,
		     size_t len)
{
	int rc;

	if (len > pnor->size || offset > pnor->size ||
	    len + offset > pnor->size)
		return -ERANGE;

	rc = blocklevel_smart_write(pnor->bl, offset, data, len);
	if (rc)
		return -errno;

	return len;
}

static int mtd_read(struct pnor *pnor, void *data, uint64_t offset,
		    size_t len)
{
	int rc;

	if (len > pnor->size || offset > pnor->size ||
	    len + offset > pnor->size)
		return -ERANGE;

	rc = blocklevel_read(pnor->bl, offset, data, len);
	if (rc)
		return -errno;

	return len;
}

/* Similar to read(2), this performs partial operations where the number of
 * bytes read/written may be less than size.
 *
 * Returns number of bytes written, or a negative value on failure. */
int pnor_operation(struct pnor *pnor, const char *name, uint64_t offset,
		   void *data, size_t requested_size, enum pnor_op op)
{
	int rc;
	uint32_t pstart, psize, idx;
	int size;

	if (!pnor->ffsh) {
		pr_log(LOG_ERR, "PNOR: ffs not initialised");
		return -EBUSY;
	}

	rc = ffs_lookup_part(pnor->ffsh, name, &idx);
	if (rc) {
		pr_log(LOG_WARNING, "PNOR: no partiton named '%s'", name);
		return -ENOENT;
	}

	ffs_part_info(pnor->ffsh, idx, NULL, &pstart, &psize, NULL, NULL);
	if (rc) {
		pr_log(LOG_ERR, "PNOR: unable to fetch partition info for %s",
				name);
		return -ENOENT;
	}

	if (offset > psize) {
		pr_log(LOG_WARNING, "PNOR: partition %s(size 0x%x) "
				"offset (0x%lx) out of bounds",
				name, psize, offset);
		return -ERANGE;
	}

	/* Large requests are trimmed */
	if (requested_size > psize)
		size = psize;
	else
		size = requested_size;

	if (size + offset > psize)
		size = psize - offset;

	if (size < 0) {
		pr_log(LOG_WARNING, "PNOR: partition %s(size 0x%x) "
				"read size (0x%zx) and offset (0x%lx) "
				"out of bounds",
				name, psize, requested_size, offset);
		return -ERANGE;
	}

	switch (op) {
	case PNOR_OP_READ:
		rc = mtd_read(pnor, data, pstart + offset, size);
		break;
	case PNOR_OP_WRITE:
		rc = mtd_write(pnor, data, pstart + offset, size);
		break;
	default:
		rc  = -EIO;
		pr_log(LOG_ERR, "PNOR: Invalid operation");
		goto out;
	}

	if (rc < 0)
		pr_log(LOG_ERR, "PNOR: MTD operation failed");
	else if (rc != size)
		pr_log(LOG_WARNING, "PNOR: mtd operation "
				"returned %d, expected %d",
				rc, size);

out:
	return rc;
}
