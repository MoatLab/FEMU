// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2017 IBM Corp. */

#include "hdif.h"
#include <stack.h>

const void *HDIF_get_idata(const struct HDIF_common_hdr *hdif, unsigned int di,
			   unsigned int *size)
{
	const struct HDIF_common_hdr *hdr = hdif;
	const struct HDIF_idata_ptr *iptr;

	if (be16_to_cpu(hdr->d1f0) != 0xd1f0) {
		prerror("HDIF: Bad header format !\n");
		backtrace();
		return NULL;
	}

	if (di >= be16_to_cpu(hdr->idptr_count)) {
		prlog(PR_DEBUG, "HDIF: idata %d out of range for %.6s!\n",
			di, hdr->id);
		return NULL;
	}

	iptr = (void *)hdif + be32_to_cpu(hdr->idptr_off)
		+ di * sizeof(struct HDIF_idata_ptr);

	if (size)
		*size = be32_to_cpu(iptr->size);

	return (void *)hdif + be32_to_cpu(iptr->offset);
}

const void *HDIF_get_iarray_item(const struct HDIF_common_hdr *hdif,
				 unsigned int di, unsigned int ai,
				 unsigned int *size)
{
	const struct HDIF_array_hdr *ahdr;
	unsigned int asize;
	const void *arr;

	arr = HDIF_get_idata(hdif, di, &asize);
	if (!arr)
		return NULL;

	if (asize < sizeof(struct HDIF_array_hdr)) {
		prerror("HDIF: idata block too small for array !\n");
		backtrace();
		return NULL;
	}

	ahdr = arr;

	if (ai >= be32_to_cpu(ahdr->ecnt)) {
		prerror("HDIF: idata array index out of range !\n");
		backtrace();
		return NULL;
	}

	if (size)
		*size = be32_to_cpu(ahdr->eactsz);

	return arr + be32_to_cpu(ahdr->offset) + ai * be32_to_cpu(ahdr->esize);
}

int HDIF_get_iarray_size(const struct HDIF_common_hdr *hdif, unsigned int di)
{
	const struct HDIF_array_hdr *ahdr;
	unsigned int asize;
	const void *arr;

	arr = HDIF_get_idata(hdif, di, &asize);
	if (!arr)
		return -1;

	if (asize < sizeof(struct HDIF_array_hdr)) {
		prerror("HDIF: idata block too small for array !\n");
		backtrace();
		return -1;
	}

	ahdr = arr;
	return be32_to_cpu(ahdr->ecnt);
}

/*
 * Returns NULL and sets *items to zero when:
 *
 * a) Array extends beyond bounds (hard error)
 * b) The array is empty (soft error)
 * c) The item size is zero (soft error)
 * d) The array is missing (soft error)
 *
 * b, c) are bugs in the input data so they generate backtraces.
 *
 * If you care about the soft error cases, retrive the array header manually
 * with HDIF_get_idata().
 */
const struct HDIF_array_hdr *HDIF_get_iarray(const struct HDIF_common_hdr *hdif,
				unsigned int di, unsigned int *items)
{
	const struct HDIF_array_hdr *arr;
	unsigned int req_size, size, elements;
	unsigned int actual_sz, alloc_sz, offset;

	arr = HDIF_get_idata(hdif, di, &size);

	if(items)
		*items = 0;

	if (!arr || !size)
		return NULL;

	/* base size of an Idata array header */
	offset = be32_to_cpu(arr->offset);
	actual_sz = be32_to_cpu(arr->eactsz);
	alloc_sz = be32_to_cpu(arr->esize);
	elements = be32_to_cpu(arr->ecnt);

	/* actual size should always be smaller than allocated */
	if (alloc_sz < actual_sz) {
		prerror("HDIF %.6s iarray %u has actsz (%u) < alloc_sz (%u)\n)",
			hdif->id, di, actual_sz, alloc_sz);
		backtrace();
		return NULL;
	}

	req_size = elements * alloc_sz + offset;
	if (req_size > size) {
		prerror("HDIF: %.6s iarray %u requires %#x bytes, but only %#x are allocated!\n",
			hdif->id, di, req_size, size);
		backtrace();
		return NULL;
	}

	if (!elements || !actual_sz)
		return NULL;

	if (items)
		*items = elements;

	return arr;
}

const void *HDIF_iarray_item(const struct HDIF_array_hdr *ahdr,
				unsigned int index)
{
	if (!ahdr || index >= be32_to_cpu(ahdr->ecnt))
		return NULL;

	return (const void * )ahdr + be32_to_cpu(ahdr->offset) +
			index * be32_to_cpu(ahdr->esize);
}

struct HDIF_child_ptr *
HDIF_child_arr(const struct HDIF_common_hdr *hdif, unsigned int idx)
{
	struct HDIF_child_ptr *children;

	children = (void *)hdif + be32_to_cpu(hdif->child_off);

	if (idx >= be16_to_cpu(hdif->child_count)) {
		prerror("HDIF: child array idx out of range!\n");
		backtrace();
		return NULL;
	}

	return &children[idx];
}

struct HDIF_common_hdr *HDIF_child(const struct HDIF_common_hdr *hdif,
				   const struct HDIF_child_ptr *child,
				   unsigned int idx,
				   const char *eyecatcher)
{
	void *base = (void *)hdif;
	struct HDIF_common_hdr *ret;
	long child_off;

	/* child must be in hdif's child array */
	child_off = (void *)child - (base + be32_to_cpu(hdif->child_off));
	assert(child_off % sizeof(struct HDIF_child_ptr) == 0);
	assert(child_off / sizeof(struct HDIF_child_ptr)
	       < be16_to_cpu(hdif->child_count));

	assert(idx < be32_to_cpu(child->count));

	if (be32_to_cpu(child->size) < sizeof(struct HDIF_common_hdr)) {
		prerror("HDIF: %s child #%i too small: %u\n",
			eyecatcher, idx, be32_to_cpu(child->size));
		backtrace();
		return NULL;
	}

	ret = base + be32_to_cpu(child->offset)
		+ be32_to_cpu(child->size) * idx;
	if (!HDIF_check(ret, eyecatcher)) {
		prerror("HDIF: #%i bad type (wanted %6s, got %6s)\n",
			idx, eyecatcher, ret->id);
		backtrace();
		return NULL;
	}

	return ret;
}
