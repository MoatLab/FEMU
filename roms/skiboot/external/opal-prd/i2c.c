// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * I2C operations for opal-prd
 *
 * Copyright 2013-2018 IBM Corp.
 */

#define _GNU_SOURCE         /* for aspritnf */
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/param.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>
#include <ccan/list/list.h>

#include "opal-prd.h"
#include "module.h"
#include "i2c.h"

struct i2c_bus {
	uint32_t		chip_id;
	uint8_t			engine;
	uint8_t			port;
	const char		*devpath;
	int			fd;
	struct list_node	link;
};

static struct list_head bus_list = LIST_HEAD_INIT(bus_list);

static int i2c_get_dev(uint32_t chip, uint8_t eng, uint8_t port, uint16_t dev)
{
	struct i2c_bus *b, *bus = NULL;

	list_for_each(&bus_list, b, link) {
		if (b->chip_id == chip && b->engine == eng && b->port == port) {
			bus = b;
			break;
		}
	}
	if (!bus) {
		pr_log(LOG_WARNING, "I2C: Bus %08x/%d/%d not found",
				chip, eng, port);
		return -1;
	}
	if (bus->fd < 0) {
		bus->fd = open(bus->devpath, O_RDWR);
		if (bus->fd < 0) {
			pr_log(LOG_ERR, "I2C: Failed to open %s: %m",
				bus->devpath);
			return -1;
		}
	}

	/* XXX We could use the I2C_SLAVE ioctl to check if the device
	 * is currently in use by a kernel driver...
	 */

	return bus->fd;
}

int i2c_read(uint32_t chip_id, uint8_t engine, uint8_t port,
	     uint16_t device, uint32_t offset_size, uint32_t offset,
	     uint32_t length, void* data)
{
	struct i2c_rdwr_ioctl_data ioargs;
	struct i2c_msg	msgs[2];
	uint8_t obuf[4];
	int fd, i, midx = 0;

	if (offset_size > 4) {
		pr_log(LOG_ERR, "I2C: Invalid write offset_size %d",
				offset_size);
		return -1;
	}
	fd = i2c_get_dev(chip_id, engine, port, device);
	if (fd == -1)
		return -1;

	/* If we have an offset, build a message for it */
	if (offset_size) {
		/* The offset has a variable size so let's handle this properly
		 * as it has to be laid out in memory MSB first
		 */
		for (i = 0; i < offset_size; i++)
			obuf[i] = offset >> (8 * (offset_size - i - 1));
		msgs[0].addr = device;
		msgs[0].flags = 0;
		msgs[0].buf = obuf;
		msgs[0].len = offset_size;
		midx = 1;
	}

	/* Build the message for the data portion */
	msgs[midx].addr = device;
	msgs[midx].flags = I2C_M_RD;
	msgs[midx].buf = data;
	msgs[midx].len = length;
	midx++;

	ioargs.msgs = msgs;
	ioargs.nmsgs = midx;
	if (ioctl(fd, I2C_RDWR, &ioargs) < 0) {
		pr_log(LOG_ERR, "I2C: Read error: %m");
		return -1;
	}
	pr_debug("I2C: Read from %08x:%d:%d@%02x+0x%x %d bytes ok",
	       chip_id, engine, port, device, offset_size ? offset : 0, length);

	return 0;
}

int i2c_write(uint32_t chip_id, uint8_t engine, uint8_t port,
	      uint16_t device, uint32_t offset_size, uint32_t offset,
	      uint32_t length, void* data)
{
	struct i2c_rdwr_ioctl_data ioargs;
	struct i2c_msg msg;
	int fd, size, i, rc;
	uint8_t *buf;

	if (offset_size > 4) {
		pr_log(LOG_ERR, "I2C: Invalid write offset_size %d",
				offset_size);
		return -1;
	}
	fd = i2c_get_dev(chip_id, engine, port, device);
	if (fd == -1)
		return -1;

	/* Not all kernel driver versions support breaking up a write into
	 * two components (offset, data), so we coalesce them first and
	 * issue a single write. The offset is laid out in BE format.
	 */
	size = offset_size + length;
	buf = malloc(size);
	if (!buf) {
		pr_log(LOG_ERR, "I2C: Out of memory");
		return -1;
	}

	/* The offset has a variable size so let's handle this properly
	 * as it has to be laid out in memory MSB first
	 */
	for (i = 0; i < offset_size; i++)
		buf[i] = offset >> (8 * (offset_size - i - 1));

	/* Copy the remaining data */
	memcpy(buf + offset_size, data, length);

	/* Build the message */
	msg.addr = device;
	msg.flags = 0;
	msg.buf = buf;
	msg.len = size;
	ioargs.msgs = &msg;
	ioargs.nmsgs = 1;
	rc = ioctl(fd, I2C_RDWR, &ioargs);
	free(buf);
	if (rc < 0) {
		pr_log(LOG_ERR, "I2C: Write error: %m");
		return -1;
	}

	return 0;
}

static void i2c_add_bus(uint32_t chip, uint32_t engine, uint32_t port,
			const char *devname)
{
	struct i2c_bus *b = malloc(sizeof(struct i2c_bus));
	char *dn;

	if (asprintf(&dn, "/dev/%s", devname) < 0) {
		pr_log(LOG_ERR, "I2C: Error creating devpath for %s: %m",
			devname);
		free(b);
		return;
	}

	memset(b, 0, sizeof(*b));
	b->chip_id = chip;
	b->engine = engine;
	b->port = port;
	b->devpath = dn;
	b->fd = -1;
	list_add(&bus_list, &b->link);
}

void i2c_init(void)
{
#define SYSFS	"/sys"	/* XXX Find it ? */
	DIR *devsdir;
	struct dirent *devent;
	char dpath[PATH_MAX];
	char busname[256];
	char *s;
	FILE *f;
	unsigned int chip, engine, port;

	/* Ensure i2c-dev is loaded */
	insert_module("i2c-dev");

	/* Get directory of i2c char devs in sysfs */
	devsdir = opendir(SYSFS "/class/i2c-dev");
	if (!devsdir) {
		pr_log(LOG_ERR, "I2C: Error opening "
					SYSFS "/class/i2c-dev: %m");
		return;
	}
	while ((devent = readdir(devsdir)) != NULL) {
		if (!strcmp(devent->d_name, "."))
			continue;
		if (!strcmp(devent->d_name, ".."))
			continue;

		/* Get bus name */
		sprintf(dpath, SYSFS "/class/i2c-dev/%s/name", devent->d_name);
		f = fopen(dpath, "r");
		if (!f) {
			pr_log(LOG_NOTICE, "I2C: Can't open %s: %m, skipping.",
					dpath);
			continue;
		}
		s = fgets(busname, sizeof(busname), f);
		fclose(f);
		if (!s) {
			pr_log(LOG_NOTICE, "Failed to read %s, skipping.",
					dpath);
			continue;
		}

		/* Is this a P8 or Centaur i2c bus ? No -> move on */
		if (strncmp(s, "p8_", 3) == 0)
			sscanf(s, "p8_%x_e%dp%d", &chip, &engine, &port);
		else if (strncmp(s, "cen_", 4) == 0)
			sscanf(s, "cen_%x_e%dp%d", &chip, &engine, &port);
		else
			continue;

		pr_log(LOG_INFO, "I2C: Found Chip: %08x engine %d port %d",
		       chip, engine, port);
		i2c_add_bus(chip, engine, port, devent->d_name);
	}
	closedir(devsdir);
}

