// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2017 IBM Corp. */

#ifndef __HDIF_H
#define __HDIF_H

#include <skiboot.h>
#include <types.h>
#include <ccan/endian/endian.h>

struct HDIF_common_hdr {
	__be16	d1f0;		/* 0xd1f0 */
	char	id[6];		/* eye catcher string */
	__be16	instnum;	/* instance number */
	__be16	version;	/* version */
	__be32	total_len;	/* total structure length */
	__be32	hdr_len;	/* header length (currently 0x20) */
	__be32	idptr_off;	/* offset to idata pointers */
	__be16	idptr_count;	/* number of idata pointers */
	__be16	child_count;	/* number of child structures */
	__be32	child_off;	/* offset to child structures array */
} __packed __align(0x10);

struct HDIF_idata_ptr {
	__be32	offset;
	__be32	size;
} __packed __align(0x8);

struct HDIF_array_hdr {
	__be32	offset;
	__be32	ecnt;
	__be32	esize;
	__be32	eactsz;
} __packed __align(0x4);

struct HDIF_child_ptr {
	__be32	offset;
	__be32	size;
	__be32	count;
} __packed;

#define HDIF_HDR_LEN		(sizeof(struct HDIF_common_hdr))
#define HDIF_ARRAY_OFFSET	(sizeof(struct HDIF_array_hdr))

#define HDIF_ID(_id)		.d1f0 = CPU_TO_BE16(0xd1f0), .id = _id

#define HDIF_SIMPLE_HDR(id, vers, type)			\
{							\
	HDIF_ID(id),					\
	.instnum	= CPU_TO_BE16(0),		\
	.version	= CPU_TO_BE16(vers),		\
	.total_len	= CPU_TO_BE32(sizeof(type)),	\
	.hdr_len	= CPU_TO_BE32(HDIF_HDR_LEN),	\
	.idptr_off	= CPU_TO_BE32(HDIF_HDR_LEN),	\
	.idptr_count	= CPU_TO_BE16(1),		\
	.child_count	= CPU_TO_BE16(0),		\
	.child_off	= CPU_TO_BE32(0),		\
}

#define HDIF_IDATA_PTR(_offset, _size)			\
{							\
	.offset	= CPU_TO_BE32(_offset),			\
	.size	= CPU_TO_BE32(_size),			\
}

static inline bool HDIF_check(const void *hdif, const char id[])
{
	const struct HDIF_common_hdr *hdr = hdif;

	return hdr->d1f0 == CPU_TO_BE16(0xd1f0) &&
		memcmp(hdr->id, id, sizeof(hdr->id)) == 0;
}

/* HDIF_get_idata - Get a pointer to internal data block
 *
 * @hdif  : HDIF structure pointer
 * @di    : Index of the idata pointer
 * @size  : Return the data size (or NULL if ignored)
 */
extern const void *HDIF_get_idata(const struct HDIF_common_hdr *hdif,
				  unsigned int di,
				  unsigned int *size);

/* HDIF_get_iarray - Get a pointer to an elemnt of an internal data array
 *
 * @hdif  : HDIF structure pointer
 * @di    : Index of the idata pointer
 * @ai    : Index in the resulting array
 * @size  : Return the entry actual size (or NULL if ignored)
 */
extern const void *HDIF_get_iarray_item(const struct HDIF_common_hdr *hdif,
					unsigned int di,
					unsigned int ai, unsigned int *size);

/* HDIF_get_iarray - Get a pointer to an internal array header
 *
 * @hdif  : HDIF structure pointer
 * @di    : Index of the idata pointer
 * @ai    : Index in the resulting array
 * @size  : Return the entry actual size (or NULL if ignored)
 */
extern const struct HDIF_array_hdr *HDIF_get_iarray(
		const struct HDIF_common_hdr *hdif, unsigned int di,
		unsigned int *items);

extern const void *HDIF_iarray_item(const struct HDIF_array_hdr *hdif,
				unsigned int index);

#define HDIF_iarray_for_each(arr, idx, ptr) \
	for (idx = 0, ptr = HDIF_iarray_item(arr, idx); \
		ptr; idx++, ptr = HDIF_iarray_item(arr, idx))

/* HDIF_get_iarray_size - Get the number of elements of an internal data array
 *
 * @hdif  : HDIF structure pointer
 * @di    : Index of the idata pointer
 *
 * A negative result means an error
 */
extern int HDIF_get_iarray_size(const struct HDIF_common_hdr *hdif,
				unsigned int di);

/* HDIF_child_arr - Get a child array from this HDIF.
 *
 * @hdif  : HDIF structure pointer
 * @idx	  : the child to get
 *
 * NULL means an error (not that many children).
 */
extern struct HDIF_child_ptr *
HDIF_child_arr(const struct HDIF_common_hdr *hdif, unsigned int idx);

/* HDIF_child - Deref a child_ptr entry.
 *
 * @hdif  : HDIF structure pointer
 * @child : the child returned from HDIF_child_arr
 * @idx	  : the index of the child to get (< child->count).
 * @eyecatcher: the 6-char ID expected for this child.
 *
 * NULL means an error.
 */
extern struct HDIF_common_hdr *HDIF_child(const struct HDIF_common_hdr *hdif,
					  const struct HDIF_child_ptr *child,
					  unsigned int idx,
					  const char *eyecatcher);
#endif /* __HDIF_H */
