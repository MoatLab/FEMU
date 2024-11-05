// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2017 IBM Corp.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <dirent.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include <libflash/file.h>

#include "arch_flash.h"

#define FDT_FLASH_PATH "/proc/device-tree/chosen/ibm,system-flash"
#define SYSFS_MTD_PATH "/sys/class/mtd"

static inline void hint_root(void)
{
	fprintf(stderr, "Do you have permission? Are you root?\n");
}

static int get_dev_attr(const char *dev, const char *attr_file, uint32_t *attr)
{
	char *dev_path = NULL;
	int fd, rc;

	/*
	 * Needs to be large enough to hold at most uint32_t represented as a
	 * string in hex with leading 0x
	 */
	char attr_buf[10];

	rc = asprintf(&dev_path, "%s/%s/%s", SYSFS_MTD_PATH, dev, attr_file);
	if (rc < 0) {
		dev_path = NULL;
		goto out;
	}

	fd = open(dev_path, O_RDONLY);
	if (fd == -1)
		goto out;

	rc = read(fd, attr_buf, sizeof(attr_buf));
	close(fd);
	if (rc == -1)
		goto out;

	if (attr)
		*attr = strtol(attr_buf, NULL, 0);

	free(dev_path);
	return 0;

out:
	free(dev_path);
	fprintf(stderr, "Couldn't get MTD attribute '%s' from '%s'\n", dev, attr_file);
	return -1;
}

static int get_dev_mtd(const char *fdt_flash_path, char **mtd_path)
{
	struct dirent **namelist;
	char fdt_node_path[PATH_MAX];
	int count, i, rc, fd;
	bool done;

	if (!fdt_flash_path)
		return -1;

	fd = open(fdt_flash_path, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Couldn't open '%s' FDT attribute to determine which flash device to use\n",
				fdt_flash_path);
		fprintf(stderr, "Is your skiboot new enough to expose the flash through the device tree?\n");
		hint_root();
		return -1;
	}

	rc = read(fd, fdt_node_path, sizeof(fdt_node_path));
	close(fd);
	if (rc == -1) {
		fprintf(stderr, "Couldn't read flash FDT node from '%s'\n", fdt_flash_path);
		hint_root();
		return -1;
	}

	count = scandir(SYSFS_MTD_PATH, &namelist, NULL, alphasort);
	if (count == -1) {
		fprintf(stderr, "Couldn't scan '%s' for MTD\n", SYSFS_MTD_PATH);
		hint_root();
		return -1;
	}

	rc = 0;
	done = false;
	for (i = 0; i < count; i++) {
		struct dirent *dirent;
		char *dev_path;
		char fdt_node_path_tmp[PATH_MAX];

		dirent = namelist[i];

		/*
		 * The call to asprintf must happen last as when it succeeds it
		 * will allocate dev_path
		 */
		if (dirent->d_name[0] == '.' || rc || done ||
			asprintf(&dev_path, "%s/%s/device/of_node", SYSFS_MTD_PATH, dirent->d_name) < 0) {
			free(namelist[i]);
			continue;
		}

		rc = readlink(dev_path, fdt_node_path_tmp, sizeof(fdt_node_path_tmp) - 1);
		free(dev_path);
		if (rc == -1) {
			/*
			 * This might fail because it could not exist if the system has flash
			 * devices that present as mtd but don't have corresponding FDT
			 * nodes, just continue silently.
			 */
			free(namelist[i]);
			/* Should still try the next dir so reset rc */
			rc = 0;
			continue;
		}
		fdt_node_path_tmp[rc] = '\0';

		if (strstr(fdt_node_path_tmp, fdt_node_path)) {
			uint32_t flags, size;

			/*
			 * size and flags could perhaps have be gotten another way but this
			 * method is super unlikely to fail so it will do.
			 */

			/* Check to see if device is writeable */
			rc = get_dev_attr(dirent->d_name, "flags", &flags);
			if (rc) {
				free(namelist[i]);
				continue;
			}

			/* Get the size of the mtd device while we're at it */
			rc = get_dev_attr(dirent->d_name, "size", &size);
			if (rc) {
				free(namelist[i]);
				continue;
			}

			rc = asprintf(&dev_path, "/dev/%s", dirent->d_name);
			if (rc < 0) {
				free(namelist[i]);
				continue;
			}
			rc = 0;
			*mtd_path = dev_path;
			done = true;
		}
		free(namelist[i]);
	}
	free(namelist);

	if (!done) {
		fprintf(stderr, "Couldn't find '%s' corresponding MTD\n", fdt_flash_path);
		fprintf(stderr, "Is your kernel new enough to expose MTD?\n");
	}

	/* explicit negative value so as to not return a libflash code */
	return done ? rc : -1;
}

static struct blocklevel_device *arch_init_blocklevel(const char *file, bool keep_alive)
{
	int rc;
	struct blocklevel_device *new_bl = NULL;
	char *real_file = NULL;

	if (!file) {
		rc = get_dev_mtd(FDT_FLASH_PATH, &real_file);
		if (rc)
			return NULL;
	}

	rc = file_init_path(file ? file : real_file, NULL, keep_alive, &new_bl);
	if (rc)
		new_bl = NULL;
	free(real_file);
	return new_bl;
}

/* Skiboot will worry about this for us */
int __attribute__((const)) arch_flash_set_wrprotect(struct blocklevel_device *bl, int set)
{
	(void)bl;
	(void)set;

	return 0;
}

enum flash_access __attribute__((const)) arch_flash_access(struct blocklevel_device *bl,
		enum flash_access access)
{
	(void)bl;

	if (access != PNOR_MTD)
		return ACCESS_INVAL;

	return PNOR_MTD;
}

int arch_flash_init(struct blocklevel_device **r_bl, const char *file, bool keep_alive)
{
	struct blocklevel_device *new_bl;

	/*
	 * In theory here we should check that something crazy wasn't
	 * passed to arch_flash_access() and refuse to init.
	 * However, arch_flash_access won't accept anything except
	 * PNOR_MTD, if they want something different then they should
	 * have checked with arch_flash_access()
	 */
	new_bl = arch_init_blocklevel(file, keep_alive);
	if (!new_bl)
		return -1;

	*r_bl = new_bl;
	return 0;
}

void arch_flash_close(struct blocklevel_device *bl, const char *file)
{
	(void)file;

	file_exit_close(bl);
}
