// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2017 IBM Corp. */

#ifndef __LIBFLASH_BLOCKLEVEL_H
#define __LIBFLASH_BLOCKLEVEL_H

#include <stdint.h>
#include <stdbool.h>

struct bl_prot_range {
	uint64_t start;
	uint64_t len;
};

struct blocklevel_range {
	struct bl_prot_range *prot;
	int n_prot;
	int total_prot;
};

enum blocklevel_flags {
	WRITE_NEED_ERASE = 1,
};

/*
 * libffs may be used with different backends, all should provide these for
 * libflash to get the information it needs
 */
struct blocklevel_device {
	void *priv;
	int (*reacquire)(struct blocklevel_device *bl);
	int (*release)(struct blocklevel_device *bl);
	int (*read)(struct blocklevel_device *bl, uint64_t pos, void *buf, uint64_t len);
	int (*write)(struct blocklevel_device *bl, uint64_t pos, const void *buf, uint64_t len);
	int (*erase)(struct blocklevel_device *bl, uint64_t pos, uint64_t len);
	int (*get_info)(struct blocklevel_device *bl, const char **name, uint64_t *total_size,
			uint32_t *erase_granule);
	bool (*exit)(struct blocklevel_device *bl);

	/*
	 * Keep the erase mask so that blocklevel_erase() can do sanity checking
	 */
	uint32_t erase_mask;
	bool keep_alive;
	enum blocklevel_flags flags;

	struct blocklevel_range ecc_prot;
};
int blocklevel_raw_read(struct blocklevel_device *bl, uint64_t pos, void *buf, uint64_t len);
int blocklevel_read(struct blocklevel_device *bl, uint64_t pos, void *buf, uint64_t len);
int blocklevel_raw_write(struct blocklevel_device *bl, uint64_t pos, const void *buf, uint64_t len);
int blocklevel_write(struct blocklevel_device *bl, uint64_t pos, const void *buf, uint64_t len);
int blocklevel_erase(struct blocklevel_device *bl, uint64_t pos, uint64_t len);
int blocklevel_get_info(struct blocklevel_device *bl, const char **name, uint64_t *total_size,
		uint32_t *erase_granule);

/*
 * blocklevel_smart_write() performs reads on the data to see if it
 * can skip erase or write calls. This is likely more convenient for
 * the caller since they don't need to perform these checks
 * themselves. Depending on the new and old data, this may be faster
 * or slower than the just using blocklevel_erase/write calls.
 * directly.
 */
int blocklevel_smart_write(struct blocklevel_device *bl, uint64_t pos, const void *buf, uint64_t len);

/*
 * blocklevel_smart_erase() will handle unaligned erases.
 * blocklevel_erase() expects a erase_granule aligned buffer and the
 * erase length to be an exact multiple of erase_granule,
 * blocklevel_smart_erase() solves this requirement by performing a
 * read erase write under the hood.
 */
int blocklevel_smart_erase(struct blocklevel_device *bl, uint64_t pos, uint64_t len);
/* Implemented in software at this level */
int blocklevel_ecc_protect(struct blocklevel_device *bl, uint32_t start, uint32_t len);

#endif /* __LIBFLASH_BLOCKLEVEL_H */
