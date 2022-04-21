// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include <ccan/container_of/container_of.h>

#include <mtd/mtd-abi.h>

#include "libflash.h"
#include "libflash/file.h"
#include "blocklevel.h"

struct file_data {
	int fd;
	char *name;
	char *path;
	struct blocklevel_device bl;
};

static int file_release(struct blocklevel_device *bl)
{
	struct file_data *file_data = container_of(bl, struct file_data, bl);
	close(file_data->fd);
	file_data->fd = -1;
	return 0;
}

static int file_reacquire(struct blocklevel_device *bl)
{
	struct file_data *file_data = container_of(bl, struct file_data, bl);
	int fd;

	fd = open(file_data->path, O_RDWR);
	if (fd == -1)
		return FLASH_ERR_PARM_ERROR;
	file_data->fd = fd;
	return 0;
}

static int file_read(struct blocklevel_device *bl, uint64_t pos, void *buf, uint64_t len)
{
	struct file_data *file_data = container_of(bl, struct file_data, bl);
	int rc, count = 0;

	rc = lseek(file_data->fd, pos, SEEK_SET);
	/* errno should remain set */
	if (rc != pos)
		return FLASH_ERR_PARM_ERROR;

	while (count < len) {
		rc = read(file_data->fd, buf, len - count);
		/* errno should remain set */
		if (rc == -1 || rc == 0)
			return FLASH_ERR_BAD_READ;

		buf += rc;
		count += rc;
	}

	return 0;
}

static int file_write(struct blocklevel_device *bl, uint64_t dst, const void *src,
		uint64_t len)
{
	struct file_data *file_data = container_of(bl, struct file_data, bl);
	int rc, count = 0;

	rc = lseek(file_data->fd, dst, SEEK_SET);
	/* errno should remain set */
	if (rc != dst)
		return FLASH_ERR_PARM_ERROR;

	while (count < len) {
		rc = write(file_data->fd, src, len - count);
		/* errno should remain set */
		if (rc == -1)
			return FLASH_ERR_VERIFY_FAILURE;

		src += rc;
		count += rc;
	}

	return 0;
}

/*
 * Due to to the fact these interfaces are ultimately supposed to deal with
 * flash, an erase function must be implemented even when the flash images
 * are backed by regular files.
 * Also, erasing flash leaves all the bits set to 1. This may be expected
 * by higher level functions so this function should also emulate that
 */
static int file_erase(struct blocklevel_device *bl, uint64_t dst, uint64_t len)
{
	static char buf[4096];
	int i = 0;
	int rc;

	memset(buf, ~0, sizeof(buf));

	while (len - i > 0) {
		rc = file_write(bl, dst + i, buf, len - i > sizeof(buf) ? sizeof(buf) : len - i);
		if (rc)
			return rc;
		i += (len - i > sizeof(buf)) ? sizeof(buf) : len - i;
	}

	return 0;
}

static int mtd_erase(struct blocklevel_device *bl, uint64_t dst, uint64_t len)
{
	struct file_data *file_data = container_of(bl, struct file_data, bl);
	int err;

	FL_DBG("%s: dst: 0x%" PRIx64 ", len: 0x%" PRIx64 "\n", __func__, dst, len);

	/*
	 * Some kernels that pflash supports do not know about the 64bit
	 * version of the ioctl() therefore we'll just use the 32bit (which
	 * should always be supported...) unless we MUST use the 64bit and
	 * then lets just hope the kernel knows how to deal with it. If it
	 * is unsupported the ioctl() will fail and we'll report that -
	 * there is no other option.
	 *
	 * Furthermore, even very recent MTD layers and drivers aren't
	 * particularly good at not blocking in the kernel. This creates
	 * unexpected behaviour in userspace tools using these functions.
	 * In the absence of significant work inside the kernel, we'll just
	 * split stuff up here for convenience.
	 * We can assume everything is aligned here.
	 */
	while (len) {
		if (dst > UINT_MAX || len > UINT_MAX) {
			struct erase_info_user64 erase_info = {
				.start = dst,
				.length = file_data->bl.erase_mask + 1
			};

			if (ioctl(file_data->fd, MEMERASE64, &erase_info) == -1) {
				err = errno;
				if (err == 25) /* Kernel doesn't do 64bit MTD erase ioctl() */
					FL_DBG("Attempted a 64bit erase on a kernel which doesn't support it\n");
				FL_ERR("%s: IOCTL to kernel failed! %s\n", __func__, strerror(err));
				errno = err;
				return FLASH_ERR_PARM_ERROR;
			}
		} else {
			struct erase_info_user erase_info = {
				.start = dst,
				.length = file_data->bl.erase_mask + 1
			};
			if (ioctl(file_data->fd, MEMERASE, &erase_info) == -1) {
				err = errno;
				FL_ERR("%s: IOCTL to kernel failed! %s\n", __func__, strerror(err));
				errno = err;
				return FLASH_ERR_PARM_ERROR;
			}
		}
		dst += file_data->bl.erase_mask + 1;
		len -= file_data->bl.erase_mask + 1;
	}
	return 0;
}

static int get_info_name(struct file_data *file_data, char **name)
{
	char *path, *lpath;
	int len;
	struct stat st;

	if (asprintf(&path, "/proc/self/fd/%d", file_data->fd) == -1)
		return FLASH_ERR_MALLOC_FAILED;

	if (lstat(path, &st)) {
		free(path);
		return FLASH_ERR_PARM_ERROR;
	}

	lpath = malloc(st.st_size + 1);
	if (!lpath) {
		free(path);
		return FLASH_ERR_MALLOC_FAILED;
	}

	len = readlink(path, lpath, st.st_size +1);
	if (len == -1) {
		free(path);
		free(lpath);
		return FLASH_ERR_PARM_ERROR;
	}
	lpath[len] = '\0';

	*name = lpath;

	free(path);
	return 0;
}


static int mtd_get_info(struct blocklevel_device *bl, const char **name,
		uint64_t *total_size, uint32_t *erase_granule)
{
	struct file_data *file_data = container_of(bl, struct file_data, bl);
	struct mtd_info_user mtd_info;
	int rc;

	rc = ioctl(file_data->fd, MEMGETINFO, &mtd_info);
	if (rc == -1)
		return FLASH_ERR_BAD_READ;

	if (total_size)
		*total_size = mtd_info.size;

	if (erase_granule)
		*erase_granule = mtd_info.erasesize;

	if (name) {
		rc = get_info_name(file_data, &(file_data->name));
		if (rc)
			return rc;
		*name = file_data->name;
	}

	return 0;
}

static int file_get_info(struct blocklevel_device *bl, const char **name,
		uint64_t *total_size, uint32_t *erase_granule)
{
	struct file_data *file_data = container_of(bl, struct file_data, bl);
	struct stat st;
	int rc;

	if (fstat(file_data->fd, &st))
		return FLASH_ERR_PARM_ERROR;

	if (total_size)
		*total_size = st.st_size;

	if (erase_granule)
		*erase_granule = 1;

	if (name) {
		rc = get_info_name(file_data, &(file_data->name));
		if (rc)
			return rc;
		*name = file_data->name;
	}

	return 0;
}

int file_init(int fd, struct blocklevel_device **bl)
{
	struct file_data *file_data;
	struct stat sbuf;

	if (!bl)
		return FLASH_ERR_PARM_ERROR;

	*bl = NULL;

	file_data = calloc(1, sizeof(struct file_data));
	if (!file_data)
		return FLASH_ERR_MALLOC_FAILED;

	file_data->fd = fd;
	file_data->bl.reacquire = &file_reacquire;
	file_data->bl.release = &file_release;
	file_data->bl.read = &file_read;
	file_data->bl.write = &file_write;
	file_data->bl.erase = &file_erase;
	file_data->bl.get_info = &file_get_info;
	file_data->bl.erase_mask = 0;

	/*
	 * If the blocklevel_device is only inited with file_init() then keep
	 * alive is assumed, as fd will change otherwise and this may break
	 * callers assumptions.
	 */
	file_data->bl.keep_alive = 1;

	/*
	 * Unfortunately not all file descriptors are created equal...
	 * Here we check to see if the file descriptor is to an MTD device, in
	 * which case we have to erase and get the size of it differently.
	 */
	if (fstat(file_data->fd, &sbuf) == -1)
		goto out;

	/* Won't be able to handle other than MTD devices for now */
	if (S_ISCHR(sbuf.st_mode)) {
		file_data->bl.erase = &mtd_erase;
		file_data->bl.get_info = &mtd_get_info;
		file_data->bl.flags = WRITE_NEED_ERASE;
		mtd_get_info(&file_data->bl, NULL, NULL, &(file_data->bl.erase_mask));
		file_data->bl.erase_mask--;
	} else if (!S_ISREG(sbuf.st_mode)) {
		/* If not a char device or a regular file something went wrong */
		goto out;
	}

	*bl = &(file_data->bl);
	return 0;
out:
	free(file_data);
	return FLASH_ERR_PARM_ERROR;
}

int file_init_path(const char *path, int *r_fd, bool keep_alive,
		struct blocklevel_device **bl)
{
	int fd, rc;
	char *path_ptr = NULL;
	struct file_data *file_data;

	if (!path || !bl)
		return FLASH_ERR_PARM_ERROR;

	fd = open(path, O_RDWR);
	if (fd == -1)
		return FLASH_ERR_PARM_ERROR;

	/*
	 * strdup() first so don't have to deal with malloc failure after
	 * file_init()
	 */
	path_ptr = strdup(path);
	if (!path_ptr) {
		rc = FLASH_ERR_MALLOC_FAILED;
		goto out;
	}

	rc = file_init(fd, bl);
	if (rc)
		goto out;

	file_data = container_of(*bl, struct file_data, bl);
	file_data->bl.keep_alive = keep_alive;
	file_data->path = path_ptr;

	if (r_fd)
		*r_fd = fd;

	return rc;
out:
	free(path_ptr);
	close(fd);
	return rc;
}

void file_exit(struct blocklevel_device *bl)
{
	struct file_data *file_data;
	if (bl) {
		free(bl->ecc_prot.prot);
		file_data = container_of(bl, struct file_data, bl);
		free(file_data->name);
		free(file_data->path);
		free(file_data);
	}
}

void file_exit_close(struct blocklevel_device *bl)
{
	struct file_data *file_data;
	if (bl) {
		file_data = container_of(bl, struct file_data, bl);
		close(file_data->fd);
		file_exit(bl);
	}
}
