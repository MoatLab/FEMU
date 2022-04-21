// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * FSP Flash Structure
 *
 * This header defines the layout for the FSP Flash Structure.
 *
 * Copyright 2012-2018 IBM Corp.
 */

#ifndef __FFS_H__
#define __FFS_H__

/* Pull in the correct header depending on what is being built */
#ifndef __SKIBOOT__
#include <linux/types.h>
#else
#include <stdint.h>
#endif
#include <ccan/short_types/short_types.h>
#include <ccan/endian/endian.h>
#include <ccan/list/list.h>

#include "libffs.h"

/* The version of this partition implementation */
#define FFS_VERSION_1	1

/* Magic number for the partition header (ASCII 'PART') */
#define FFS_MAGIC	0x50415254

/* pid of logical partitions/containers */
#define FFS_PID_TOPLEVEL   0xFFFFFFFF

/*
 * Type of image contained w/in partition
 */
enum ffs_type {
	FFS_TYPE_DATA      = 1,
	FFS_TYPE_LOGICAL   = 2,
	FFS_TYPE_PARTITION = 3,
};

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

/**
 * struct __ffs_entry_user - On flash user data entries
 *
 * Represents the on flash layout of FFS structures
 *
 *  @chip:		Chip Select (0,1)
 *  @compressType:	Compression Indication/alg (0=not compressed)
 *  @dataInteg:		Indicates Data Integrity mechanism
 *  @verCheck:		Indicates Version check type
 *  @miscFlags:		Misc Partition related Flags
 *  @freeMisc[2]:	Unused Miscellaneious Info
 *  @freeUser[14]:	Unused User Data
 */
struct __ffs_entry_user {
	uint8_t chip;
	uint8_t compresstype;
	be16 datainteg;
	uint8_t vercheck;
	uint8_t miscflags;
	uint8_t freemisc[2];
	be32 reserved[14];
} __attribute__ ((packed));

/**
 * struct __ffs_entry - On flash partition entry
 *
 * Represents the on flash layout of FFS structures
 * Note: Unlike the in memory structures base and size of the entry are in
 * units of block_size and the actual size is in bytes
 *
 * @name:	Opaque null terminated string
 * @base:	Starting offset of partition in flash (in hdr.block_size)
 * @size:	Partition size (in hdr.block_size)
 * @pid:	Parent partition entry (FFS_PID_TOPLEVEL for toplevel)
 * @id:		Partition entry ID [1..65536]
 * @type:	Describe type of partition
 * @flags:	Partition attributes (optional)
 * @actual:	Actual partition size (in bytes)
 * @resvd:	Reserved words for future use
 * @user:	User data (optional)
 * @checksum:	Partition entry checksum (includes all above)
 */
struct __ffs_entry {
	char name[FFS_PART_NAME_MAX + 1];
	be32 base;
	be32 size;
	be32 pid;
	be32 id;
	be32 type;
	be32 flags;
	be32 actual;
	be32 resvd[4];
	struct __ffs_entry_user user;
	/* The checksum is actually endian agnostic */
	uint32_t checksum;
} __attribute__ ((packed));

/**
 * struct ffs_entry - Partition entry
 *
 * Useable in memory representation of a struct __ffs_entry
 * Note: Unlike the on flash structure, all sizes here are in bytes!
 *
 * @name:	Opaque null terminated string
 * @base:	Starting offset of partition in flash (in bytes)
 * @size:	Partition size (in bytes)
 * @actual:	Actual partition size (in bytes)
 * @pid:	Parent partition entry (FFS_PID_TOPLEVEL for toplevel)
 * @type:	Describe type of partition
 * @flags:	Partition attributes (optional)
 * @user:	User data (optional)
 * @ref:	Refcount
 */
struct ffs_entry {
	char name[FFS_PART_NAME_MAX + 1];
	uint32_t base;
	uint32_t size;
	uint32_t actual;
	uint32_t pid;
	enum ffs_type type;
	uint32_t flags;
	struct ffs_entry_user user;
	unsigned int ref;
};


/**
 * struct __ffs_hdr - On flash FSP Flash Structure header
 *
 * Represents the on flash layout of FFS structures
 * Note: Beware that the size of the partition table is in units of block_size
 *
 * @magic:		Eye catcher/corruption detector
 * @version:		Version of the structure
 * @size:		Size of partition table (in block_size)
 * @entry_size:		Size of struct ffs_entry element (in bytes)
 * @entry_count:	Number of struct ffs_entry elements in @entries array
 * @block_size:		Size of block on device (in bytes)
 * @block_count:	Number of blocks on device
 * @resvd[4]:		Reserved words for future use
 * @checksum:		Header checksum
 * @entries:		Pointer to array of partition entries
 */
struct __ffs_hdr {
	be32 magic;
	be32 version;
	be32 size;
	be32 entry_size;
	be32 entry_count;
	be32 block_size;
	be32 block_count;
	be32 resvd[4];
	/* The checksum is actually endian agnostic */
	uint32_t checksum;
	struct __ffs_entry entries[];
} __attribute__ ((packed));

/**
 * struct ffs_hdr - FSP Flash Structure header
 *
 * Useable in memory representation of a struct __ffs_hdr
 * Note: All sizes here are in bytes
 *
 * @version:		Version of the structure
 * @size:		Size of partition table (in bytes)
 * @block_size:		Size of block on device (in bytes)
 * @block_count:	Number of blocks on device.
 * @count:		Count of the number of entires
 * @entries:		Array of partition entries.
 */
struct ffs_hdr {
	uint32_t version;
	uint32_t size;
	uint32_t block_size;
	uint32_t block_count;
	uint32_t count;
	struct ffs_entry *part;
	struct ffs_entry **entries;
	unsigned int entries_size;
};

#endif /* __FFS_H__ */
