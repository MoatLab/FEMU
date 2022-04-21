// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2018 IBM Corp. */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>

#include <libflash/libflash.h>
#include <libflash/errors.h>

#include "blocklevel.h"
#include "ecc.h"

#define PROT_REALLOC_NUM 25

/* This function returns tristate values.
 * 1  - The region is ECC protected
 * 0  - The region is not ECC protected
 * -1 - Partially protected
 */
static int ecc_protected(struct blocklevel_device *bl, uint64_t pos, uint64_t len, uint64_t *start)
{
	int i;

	/* Length of 0 is nonsensical so add 1 */
	if (len == 0)
		len = 1;

	for (i = 0; i < bl->ecc_prot.n_prot; i++) {
		/* Fits entirely within the range */
		if (bl->ecc_prot.prot[i].start <= pos &&
				bl->ecc_prot.prot[i].start + bl->ecc_prot.prot[i].len >= pos + len) {
			if (start)
				*start = bl->ecc_prot.prot[i].start;
			return 1;
		}

		/*
		 * Even if ranges are merged we can't currently guarantee two
		 * contiguous regions are sanely ECC protected so a partial fit
		 * is no good.
		 */
		if ((bl->ecc_prot.prot[i].start >= pos && bl->ecc_prot.prot[i].start < pos + len) ||
		   (bl->ecc_prot.prot[i].start <= pos &&
			bl->ecc_prot.prot[i].start + bl->ecc_prot.prot[i].len > pos)) {
			if (start)
				*start = bl->ecc_prot.prot[i].start;
			return -1;
		}
	}
	return 0;
}

static uint64_t with_ecc_pos(uint64_t ecc_start, uint64_t pos)
{
	return pos + ((pos - ecc_start) / (BYTES_PER_ECC));
}

static int reacquire(struct blocklevel_device *bl)
{
	if (!bl->keep_alive && bl->reacquire)
		return bl->reacquire(bl);
	return 0;
}

static int release(struct blocklevel_device *bl)
{
	int rc = 0;
	if (!bl->keep_alive && bl->release) {
		/* This is the error return path a lot, preserve errno */
		int err = errno;
		rc = bl->release(bl);
		errno = err;
	}
	return rc;
}

int blocklevel_raw_read(struct blocklevel_device *bl, uint64_t pos, void *buf, uint64_t len)
{
	int rc;

	FL_DBG("%s: 0x%" PRIx64 "\t%p\t0x%" PRIx64 "\n", __func__, pos, buf, len);
	if (!bl || !bl->read || !buf) {
		errno = EINVAL;
		return FLASH_ERR_PARM_ERROR;
	}

	rc = reacquire(bl);
	if (rc)
		return rc;

	rc = bl->read(bl, pos, buf, len);

	release(bl);

	return rc;
}

int blocklevel_read(struct blocklevel_device *bl, uint64_t pos, void *buf, uint64_t len)
{
	int rc, ecc_protection;
	struct ecc64 *buffer;
	uint64_t ecc_pos, ecc_start, ecc_diff, ecc_len;

	FL_DBG("%s: 0x%" PRIx64 "\t%p\t0x%" PRIx64 "\n", __func__, pos, buf, len);
	if (!bl || !buf) {
		errno = EINVAL;
		return FLASH_ERR_PARM_ERROR;
	}

	ecc_protection = ecc_protected(bl, pos, len, &ecc_start);

	FL_DBG("%s: 0x%" PRIx64 " for 0x%" PRIx64 " ecc=%s\n",
		__func__, pos, len, ecc_protection ?
		(ecc_protection == -1 ? "partial" : "yes") : "no");

	if (!ecc_protection)
		return blocklevel_raw_read(bl, pos, buf, len);

	/*
	 * The region we're reading to has both ecc protection and not.
	 * Perhaps one day in the future blocklevel can cope with this.
	 */
	if (ecc_protection == -1) {
		FL_ERR("%s: Can't cope with partial ecc\n", __func__);
		errno = EINVAL;
		return FLASH_ERR_PARM_ERROR;
	}

	pos = with_ecc_pos(ecc_start, pos);

	ecc_pos = ecc_buffer_align(ecc_start, pos);
	ecc_diff = pos - ecc_pos;
	ecc_len = ecc_buffer_size(len + ecc_diff);

	FL_DBG("%s: adjusted_pos: 0x%" PRIx64 ", ecc_pos: 0x%" PRIx64
			", ecc_diff: 0x%" PRIx64 ", ecc_len: 0x%" PRIx64 "\n",
			__func__, pos, ecc_pos, ecc_diff, ecc_len);
	buffer = malloc(ecc_len);
	if (!buffer) {
		errno = ENOMEM;
		rc = FLASH_ERR_MALLOC_FAILED;
		goto out;
	}

	rc = blocklevel_raw_read(bl, ecc_pos, buffer, ecc_len);
	if (rc)
		goto out;

	/*
	 * Could optimise and simply call memcpy_from_ecc() if ecc_diff
	 * == 0 but _unaligned checks and bascially does that for us
	 */
	if (memcpy_from_ecc_unaligned(buf, buffer, len, ecc_diff)) {
		errno = EBADF;
		rc = FLASH_ERR_ECC_INVALID;
	}

out:
	free(buffer);
	return rc;
}

int blocklevel_raw_write(struct blocklevel_device *bl, uint64_t pos,
		const void *buf, uint64_t len)
{
	int rc;

	FL_DBG("%s: 0x%" PRIx64 "\t%p\t0x%" PRIx64 "\n", __func__, pos, buf, len);
	if (!bl || !bl->write || !buf) {
		errno = EINVAL;
		return FLASH_ERR_PARM_ERROR;
	}

	rc = reacquire(bl);
	if (rc)
		return rc;

	rc = bl->write(bl, pos, buf, len);

	release(bl);

	return rc;
}

int blocklevel_write(struct blocklevel_device *bl, uint64_t pos, const void *buf,
		uint64_t len)
{
	int rc, ecc_protection;
	struct ecc64 *buffer;
	uint64_t ecc_len;
	uint64_t ecc_start, ecc_pos, ecc_diff;

	FL_DBG("%s: 0x%" PRIx64 "\t%p\t0x%" PRIx64 "\n", __func__, pos, buf, len);
	if (!bl || !buf) {
		errno = EINVAL;
		return FLASH_ERR_PARM_ERROR;
	}

	ecc_protection = ecc_protected(bl, pos, len, &ecc_start);

	FL_DBG("%s: 0x%" PRIx64 " for 0x%" PRIx64 " ecc=%s\n",
		__func__, pos, len, ecc_protection ?
		(ecc_protection == -1 ? "partial" : "yes") : "no");

	if (!ecc_protection)
		return blocklevel_raw_write(bl, pos, buf, len);

	/*
	 * The region we're writing to has both ecc protection and not.
	 * Perhaps one day in the future blocklevel can cope with this.
	 */
	if (ecc_protection == -1) {
		FL_ERR("%s: Can't cope with partial ecc\n", __func__);
		errno = EINVAL;
		return FLASH_ERR_PARM_ERROR;
	}

	pos = with_ecc_pos(ecc_start, pos);

	ecc_pos = ecc_buffer_align(ecc_start, pos);
	ecc_diff = pos - ecc_pos;
	ecc_len = ecc_buffer_size(len + ecc_diff);

	FL_DBG("%s: adjusted_pos: 0x%" PRIx64 ", ecc_pos: 0x%" PRIx64
			", ecc_diff: 0x%" PRIx64 ", ecc_len: 0x%" PRIx64 "\n",
			__func__, pos, ecc_pos, ecc_diff, ecc_len);

	buffer = malloc(ecc_len);
	if (!buffer) {
		errno = ENOMEM;
		rc = FLASH_ERR_MALLOC_FAILED;
		goto out;
	}

	if (ecc_diff) {
		uint64_t start_chunk = ecc_diff;
		uint64_t end_chunk = BYTES_PER_ECC - ecc_diff;
		uint64_t end_len = ecc_len - end_chunk;

		/*
		 * Read the start bytes that memcpy_to_ecc_unaligned() will need
		 * to calculate the first ecc byte
		 */
		rc = blocklevel_raw_read(bl, ecc_pos, buffer, start_chunk);
		if (rc) {
			errno = EBADF;
			rc = FLASH_ERR_ECC_INVALID;
			goto out;
		}

		/*
		 * Read the end bytes that memcpy_to_ecc_unaligned() will need
		 * to calculate the last ecc byte
		 */
		rc = blocklevel_raw_read(bl, ecc_pos + end_len, ((char *)buffer) + end_len,
				end_chunk);
		if (rc) {
			errno = EBADF;
			rc = FLASH_ERR_ECC_INVALID;
			goto out;
		}

		if (memcpy_to_ecc_unaligned(buffer, buf, len, ecc_diff)) {
			errno = EBADF;
			rc = FLASH_ERR_ECC_INVALID;
			goto out;
		}
	} else {
		if (memcpy_to_ecc(buffer, buf, len)) {
			errno = EBADF;
			rc = FLASH_ERR_ECC_INVALID;
			goto out;
		}
	}
	rc = blocklevel_raw_write(bl, pos, buffer, ecc_len);

out:
	free(buffer);
	return rc;
}

int blocklevel_erase(struct blocklevel_device *bl, uint64_t pos, uint64_t len)
{
	int rc;
	if (!bl || !bl->erase) {
		errno = EINVAL;
		return FLASH_ERR_PARM_ERROR;
	}

	FL_DBG("%s: 0x%" PRIx64 "\t0x%" PRIx64 "\n", __func__, pos, len);

	/* Programmer may be making a horrible mistake without knowing it */
	if (pos & bl->erase_mask) {
		FL_ERR("blocklevel_erase: pos (0x%"PRIx64") is not erase block (0x%08x) aligned\n",
				pos, bl->erase_mask + 1);
		return FLASH_ERR_ERASE_BOUNDARY;
	}

	if (len & bl->erase_mask) {
		FL_ERR("blocklevel_erase: len (0x%"PRIx64") is not erase block (0x%08x) aligned\n",
				len, bl->erase_mask + 1);
		return FLASH_ERR_ERASE_BOUNDARY;
	}

	rc = reacquire(bl);
	if (rc)
		return rc;

	rc = bl->erase(bl, pos, len);

	release(bl);

	return rc;
}

int blocklevel_get_info(struct blocklevel_device *bl, const char **name, uint64_t *total_size,
		uint32_t *erase_granule)
{
	int rc;

	if (!bl || !bl->get_info) {
		errno = EINVAL;
		return FLASH_ERR_PARM_ERROR;
	}

	rc = reacquire(bl);
	if (rc)
		return rc;

	rc = bl->get_info(bl, name, total_size, erase_granule);

	/* Check the validity of what we are being told */
	if (erase_granule && *erase_granule != bl->erase_mask + 1)
		FL_ERR("blocklevel_get_info: WARNING: erase_granule (0x%08x) and erase_mask"
				" (0x%08x) don't match\n", *erase_granule, bl->erase_mask + 1);

	release(bl);

	return rc;
}

/*
 * Compare flash and memory to determine if:
 * a) Erase must happen before write
 * b) Flash and memory are identical
 * c) Flash can simply be written to
 *
 * returns -1 for a
 * returns  0 for b
 * returns  1 for c
 */
static int blocklevel_flashcmp(const void *flash_buf, const void *mem_buf, uint64_t len)
{
	uint64_t i;
	int same = true;
	const uint8_t *f_buf, *m_buf;

	f_buf = flash_buf;
	m_buf = mem_buf;

	for (i = 0; i < len; i++) {
		if (m_buf[i] & ~f_buf[i])
			return -1;
		if (same && (m_buf[i] != f_buf[i]))
			same = false;
	}

	return same ? 0 : 1;
}

int blocklevel_smart_erase(struct blocklevel_device *bl, uint64_t pos, uint64_t len)
{
	uint64_t block_size;
	void *erase_buf;
	int rc;

	if (!bl) {
		errno = EINVAL;
		return FLASH_ERR_PARM_ERROR;
	}

	FL_DBG("%s: 0x%" PRIx64 "\t0x%" PRIx64 "\n", __func__, pos, len);

	/* Nothing smart needs to be done, pos and len are aligned */
	if ((pos & bl->erase_mask) == 0 && (len & bl->erase_mask) == 0) {
		FL_DBG("%s: Skipping smarts everything is aligned 0x%" PRIx64 " 0x%" PRIx64
				"to 0x%08x\n", __func__, pos, len, bl->erase_mask);
		return blocklevel_erase(bl, pos, len);
	}
	block_size = bl->erase_mask + 1;
	erase_buf = malloc(block_size);
	if (!erase_buf) {
		errno = ENOMEM;
		return FLASH_ERR_MALLOC_FAILED;
	}

	rc = reacquire(bl);
	if (rc) {
		free(erase_buf);
		return rc;
	}

	if (pos & bl->erase_mask) {
		/*
		 * base_pos and base_len are the values in the first erase
		 * block that we need to preserve: the region up to pos.
		 */
		uint64_t base_pos = pos & ~(bl->erase_mask);
		uint64_t base_len = pos - base_pos;

		FL_DBG("%s: preserving 0x%" PRIx64 "..0x%" PRIx64 "\n",
				__func__, base_pos, base_pos + base_len);

		/*
		 * Read the entire block in case this is the ONLY block we're
		 * modifying, we may need the end chunk of it later
		 */
		rc = bl->read(bl, base_pos, erase_buf, block_size);
		if (rc)
			goto out;

		rc = bl->erase(bl, base_pos, block_size);
		if (rc)
			goto out;

		rc = bl->write(bl, base_pos, erase_buf, base_len);
		if (rc)
			goto out;

		/*
		 * The requested erase fits entirely into this erase block and
		 * so we need to write back the chunk at the end of the block
		 */
		if (base_pos + base_len + len < base_pos + block_size) {
			rc = bl->write(bl, pos + len, erase_buf + base_len + len,
					block_size - base_len - len);
			FL_DBG("%s: Early exit, everything was in one erase block\n",
					__func__);
			goto out;
		}

		pos += block_size - base_len;
		len -= block_size - base_len;
	}

	/* Now we should be aligned, best to double check */
	if (pos & bl->erase_mask) {
		FL_DBG("%s:pos 0x%" PRIx64 " isn't erase_mask 0x%08x aligned\n",
			   	__func__, pos, bl->erase_mask);
		rc = FLASH_ERR_PARM_ERROR;
		goto out;
	}

	if (len & ~(bl->erase_mask)) {
		rc = bl->erase(bl, pos, len & ~(bl->erase_mask));
		if (rc)
			goto out;

		pos += len & ~(bl->erase_mask);
		len -= len & ~(bl->erase_mask);
	}

	/* Length should be less than a block now */
	if (len > block_size) {
		FL_DBG("%s: len 0x%" PRIx64 " is still exceeds block_size 0x%" PRIx64 "\n",
				__func__, len, block_size);
		rc = FLASH_ERR_PARM_ERROR;
		goto out;
	}

	if (len & bl->erase_mask) {
		/*
		 * top_pos is the first byte that must be preserved and
		 * top_len is the length from top_pos to the end of the erase
		 * block: the region that must be preserved
		 */
		uint64_t top_pos = pos + len;
		uint64_t top_len = block_size - len;

		FL_DBG("%s: preserving 0x%" PRIx64 "..0x%" PRIx64 "\n",
				__func__, top_pos, top_pos + top_len);

		rc = bl->read(bl, top_pos, erase_buf, top_len);
		if (rc)
			goto out;

		rc = bl->erase(bl, pos, block_size);
		if (rc)
			goto out;

		rc = bl->write(bl, top_pos, erase_buf, top_len);
		if (rc)
			goto out;
	}

out:
	free(erase_buf);
	release(bl);
	return rc;
}

int blocklevel_smart_write(struct blocklevel_device *bl, uint64_t pos, const void *buf, uint64_t len)
{
	void *ecc_buf = NULL;
	uint64_t ecc_start;
	int ecc_protection;

	void *erase_buf = NULL;
	uint32_t erase_size;

	const void *write_buf;
	uint64_t write_len;
	uint64_t write_pos;

	int rc = 0;

	if (!buf || !bl) {
		errno = EINVAL;
		return FLASH_ERR_PARM_ERROR;
	}

	FL_DBG("%s: 0x%" PRIx64 "\t0x%" PRIx64 "\n", __func__, pos, len);

	if (!(bl->flags & WRITE_NEED_ERASE)) {
		FL_DBG("%s: backend doesn't need erase\n", __func__);
		return blocklevel_write(bl, pos, buf, len);
	}

	rc = blocklevel_get_info(bl, NULL, NULL, &erase_size);
	if (rc)
		return rc;

	ecc_protection = ecc_protected(bl, pos, len, &ecc_start);
	if (ecc_protection == -1) {
		FL_ERR("%s: Can't cope with partial ecc\n", __func__);
		errno = EINVAL;
		return FLASH_ERR_PARM_ERROR;
	}

	if (ecc_protection) {
		uint64_t ecc_pos, ecc_align, ecc_diff, ecc_len;

		FL_DBG("%s: region has ECC\n", __func__);

		ecc_pos = with_ecc_pos(ecc_start, pos);
		ecc_align = ecc_buffer_align(ecc_start, ecc_pos);
		ecc_diff = ecc_pos - ecc_align;
		ecc_len = ecc_buffer_size(len + ecc_diff);

		ecc_buf = malloc(ecc_len);
		if (!ecc_buf) {
			errno = ENOMEM;
			return FLASH_ERR_MALLOC_FAILED;
		}

		if (ecc_diff) {
			rc = blocklevel_read(bl, ecc_align, ecc_buf, ecc_diff);
			if (rc) {
				errno = EBADF;
				rc = FLASH_ERR_ECC_INVALID;
				goto out;
			}
		}

		rc = memcpy_to_ecc_unaligned(ecc_buf, buf, len, ecc_diff);
		if (rc) {
			free(ecc_buf);
			errno = EBADF;
			return FLASH_ERR_ECC_INVALID;
		}

		write_buf = ecc_buf;
		write_len = ecc_len;
		write_pos = ecc_pos;
	} else {
		write_buf = buf;
		write_len = len;
		write_pos = pos;
	}

	erase_buf = malloc(erase_size);
	if (!erase_buf) {
		errno = ENOMEM;
		rc = FLASH_ERR_MALLOC_FAILED;
		goto out_free;
	}

	rc = reacquire(bl);
	if (rc)
		goto out_free;

	while (write_len > 0) {
		uint32_t erase_block = write_pos & ~(erase_size - 1);
		uint32_t block_offset = write_pos & (erase_size - 1);
		uint32_t chunk_size = erase_size > write_len ?
					write_len : erase_size;
		int cmp;

		/* Write crosses an erase boundary, shrink the write to the boundary */
		if (erase_size < block_offset + chunk_size) {
			chunk_size = erase_size - block_offset;
		}

		rc = bl->read(bl, erase_block, erase_buf, erase_size);
		if (rc)
			goto out;

		cmp = blocklevel_flashcmp(erase_buf + block_offset, write_buf,
					  chunk_size);
		FL_DBG("%s: region 0x%08x..0x%08x ", __func__,
				erase_block, erase_size);
		if (cmp != 0) {
			FL_DBG("needs ");
			if (cmp == -1) {
				FL_DBG("erase and ");
				bl->erase(bl, erase_block, erase_size);
			}
			FL_DBG("write\n");
			memcpy(erase_buf + block_offset, write_buf, chunk_size);
			rc = bl->write(bl, erase_block, erase_buf, erase_size);
			if (rc)
				goto out;
		} else {
			FL_DBG("clean\n");
		}

		write_len -= chunk_size;
		write_pos += chunk_size;
		write_buf += chunk_size;
	}

out:
	release(bl);
out_free:
	free(ecc_buf);
	free(erase_buf);
	return rc;
}

static bool insert_bl_prot_range(struct blocklevel_range *ranges, struct bl_prot_range range)
{
	int i;
	uint32_t pos, len;
	struct bl_prot_range *prot = ranges->prot;

	pos = range.start;
	len = range.len;

	if (len == 0)
		return true;

	/* Check for overflow */
	if (pos + len < len)
		return false;

	for (i = 0; i < ranges->n_prot && len > 0; i++) {
		if (prot[i].start <= pos && prot[i].start + prot[i].len >= pos + len) {
			len = 0;
			break; /* Might as well, the next two conditions can't be true */
		}

		/* Can easily extend this down just by adjusting start */
		if (pos <= prot[i].start && pos + len >= prot[i].start) {
			FL_DBG("%s: extending start down\n", __func__);
			prot[i].len += prot[i].start - pos;
			prot[i].start = pos;
			pos += prot[i].len;
			if (prot[i].len >= len)
				len = 0;
			else
				len -= prot[i].len;
		}

		/*
		 * Jump over this range but the new range might be so big that
		 * theres a chunk after
		 */
		if (pos >= prot[i].start && pos < prot[i].start + prot[i].len) {
			FL_DBG("%s: fits within current range ", __func__);
			if (prot[i].start + prot[i].len - pos > len) {
				FL_DBG("but there is some extra at the end\n");
				len -= prot[i].start + prot[i].len - pos;
				pos = prot[i].start + prot[i].len;
			} else {
				FL_DBG("\n");
				len = 0;
			}
		}
		/*
		 * This condition will be true if the range is smaller than
		 * the current range, therefore it should go here!
		 */
		if (pos < prot[i].start && pos + len <= prot[i].start)
			break;
	}

	if (len) {
		int insert_pos = i;
		struct bl_prot_range *new_ranges = ranges->prot;

		FL_DBG("%s: adding 0x%08x..0x%08x\n", __func__, pos, pos + len);

		if (ranges->n_prot == ranges->total_prot) {
			new_ranges = realloc(ranges->prot,
					sizeof(range) * ((ranges->n_prot) + PROT_REALLOC_NUM));
			if (!new_ranges)
				return false;
			ranges->total_prot += PROT_REALLOC_NUM;
		}
		if (insert_pos != ranges->n_prot)
			for (i = ranges->n_prot; i > insert_pos; i--)
				memcpy(&new_ranges[i], &new_ranges[i - 1], sizeof(range));
		range.start = pos;
		range.len = len;
		memcpy(&new_ranges[insert_pos], &range, sizeof(range));
		ranges->prot = new_ranges;
		ranges->n_prot++;
		prot = new_ranges;
	}

	return true;
}

int blocklevel_ecc_protect(struct blocklevel_device *bl, uint32_t start, uint32_t len)
{
	/*
	 * Could implement this at hardware level by having an accessor to the
	 * backend in struct blocklevel_device and as a result do nothing at
	 * this level (although probably not for ecc!)
	 */
	struct bl_prot_range range = { .start = start, .len = len };

	if (len < BYTES_PER_ECC)
		return -1;
	return !insert_bl_prot_range(&bl->ecc_prot, range);
}
