// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2018 IBM Corp. */

#ifndef __LIBFFS_H
#define __LIBFFS_H

#include <libflash/libflash.h>
#include <libflash/blocklevel.h>

/* FFS handle, opaque */
struct ffs_handle;
struct ffs_hdr;
struct ffs_entry;
struct ffs_entry_user;

/**
 * struct ffs_entry_user - User data entries
 *
 * Usable in memory representation of a struct __ffs_entry_user
 *
 *  @chip:		Chip Select (0,1)
 *  @compressType:	Compression Indication/alg (0=not compressed)
 *  @dataInteg:		Indicates Data Integrity mechanism
 *  @verCheck:		Indicates Version check type
 *  @miscFlags:		Misc Partition related Flags
 */
struct ffs_entry_user {
	uint8_t chip;
	uint8_t compresstype;
	uint16_t datainteg;
	uint8_t vercheck;
	uint8_t miscflags;
};

/* Error codes:
 *
 * < 0 = flash controller errors
 *   0 = success
 * > 0 = libffs / libflash errors
 */
#define FFS_ERR_BAD_MAGIC	100
#define FFS_ERR_BAD_VERSION	101
#define FFS_ERR_BAD_CKSUM	102
#define FFS_ERR_PART_NOT_FOUND	103
#define FFS_ERR_BAD_ECC		104
#define FFS_ERR_BAD_SIZE	105
#define FFS_ERR_BAD_PART_NAME	106
#define FFS_ERR_BAD_PART_BASE	107
#define FFS_ERR_BAD_PART_SIZE	108
#define FFS_ERR_BAD_PART_PID	109

/* The maximum length of the partition name */
#define FFS_PART_NAME_MAX   15
/* Old version of the name DEPRECATED */
#define PART_NAME_MAX   15

/*
 * Flag bit definitions
 */
#define FFS_FLAGS_PROTECTED	0x0001
#define FFS_FLAGS_U_BOOT_ENV	0x0002

/* Data integrity flags */
#define FFS_ENRY_INTEG_ECC 0x8000

/*
 * User verCheck definitions
 */
#define FFS_VERCHECK_SHA512V 0x80
#define FFS_VERCHECK_SHA512EC 0x40

/*
 * User miscFlags
 */
#define FFS_MISCFLAGS_PRESERVED 0x80
#define FFS_MISCFLAGS_READONLY 0x40
#define FFS_MISCFLAGS_BACKUP 0x20
#define FFS_MISCFLAGS_REPROVISION 0x10
#define FFS_MISCFLAGS_VOLATILE 0x08
#define FFS_MISCFLAGS_CLEARECC 0x04
#define FFS_MISCFLAGS_GOLDEN 0x01


int ffs_string_to_entry_user(const char *flags, int nflags,
		struct ffs_entry_user *user);
char *ffs_entry_user_to_string(struct ffs_entry_user *user);

bool has_ecc(struct ffs_entry *ent);

bool has_flag(struct ffs_entry *ent, uint16_t flag);

/* Init */

int ffs_init(uint32_t offset, uint32_t max_size, struct blocklevel_device *bl,
		struct ffs_handle **ffs, bool mark_ecc);

/*
 * Initialise a new ffs_handle to the "OTHER SIDE".
 * Reuses the underlying blocklevel_device.
 */
int ffs_next_side(struct ffs_handle *ffs, struct ffs_handle **new_ffs,
		bool mark_ecc);

/*
 * There are quite a few ways one might consider two ffs_handles to be the
 * same. For the purposes of this function we are trying to detect a fairly
 * specific scenario:
 * Consecutive calls to ffs_next_side() may succeed but have gone circular.
 * It is possible that the OTHER_SIDE partition in one TOC actually points
 * back to the TOC of the first ffs_handle.
 * This function compares for this case, therefore the requirements are
 * simple, the underlying blocklevel_devices must be the same along with
 * the toc_offset and the max_size.
 */
bool ffs_equal(struct ffs_handle *one, struct ffs_handle *two);

void ffs_close(struct ffs_handle *ffs);

int ffs_lookup_part(struct ffs_handle *ffs, const char *name,
		    uint32_t *part_idx);

int ffs_part_info(struct ffs_handle *ffs, uint32_t part_idx,
		  char **name, uint32_t *start,
		  uint32_t *total_size, uint32_t *act_size, bool *ecc);

struct ffs_entry *ffs_entry_get(struct ffs_handle *ffs, uint32_t index);

int ffs_update_act_size(struct ffs_handle *ffs, uint32_t part_idx,
			uint32_t act_size);

int ffs_hdr_new(uint32_t block_size, uint32_t block_count,
		struct ffs_entry **e, struct ffs_hdr **r);

int ffs_hdr_add_side(struct ffs_hdr *hdr);

int ffs_entry_new(const char *name, uint32_t base, uint32_t size, struct ffs_entry **r);

struct ffs_entry *ffs_entry_put(struct ffs_entry *ent);

int ffs_entry_user_set(struct ffs_entry *ent, struct ffs_entry_user *user);

int ffs_entry_set_act_size(struct ffs_entry *ent, uint32_t actual_size);


struct ffs_entry_user ffs_entry_user_get(struct ffs_entry *ent);

int ffs_entry_add(struct ffs_hdr *hdr, struct ffs_entry *entry);

int ffs_hdr_finalise(struct blocklevel_device *bl, struct ffs_hdr *hdr);

void ffs_hdr_free(struct ffs_hdr *hdr);
#endif /* __LIBFFS_H */
