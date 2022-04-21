// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Parse Vital Product Data (VPD)
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <skiboot.h>
#include <vpd.h>
#include <string.h>
#include <device.h>

#define CHECK_SPACE(_p, _n, _e) (((_e) - (_p)) >= (_n))

/* Low level keyword search in a record. Can be used when we
 * need to find the next keyword of a given type, for example
 * when having multiple MF/SM keyword pairs
 */
const void *vpd_find_keyword(const void *rec, size_t rec_sz,
			     const char *kw, uint8_t *kw_size)
{
	const uint8_t *p = rec, *end = rec + rec_sz;

	while (CHECK_SPACE(p, 3, end)) {
		uint8_t k1 = *(p++);
		uint8_t k2 = *(p++);
		uint8_t sz = *(p++);

		if (k1 == kw[0] && k2 == kw[1]) {
			if (kw_size)
				*kw_size = sz;
			return p;
		}
		p += sz;
	}
	return NULL;
}

/* vpd_valid - does some basic sanity checks to ensure a VPD blob is
 *             actually a VPD blob
 */
bool vpd_valid(const void *vvpd, size_t vpd_size)
{
	const uint8_t *vpd = vvpd;
	int size, i = 0;

	/* find the record start byte */
	while (i < vpd_size)
		if (vpd[i++] == 0x84)
			break;

	if (i >= vpd_size)
		return false;

	/* next two bytes are the record length, little endian */
	size  = 2;
	size += vpd[i];
	size += vpd[i + 1] << 8;

	i += size; /* skip to the end marker */

	if (i >= vpd_size || vpd[i] != 0x78)
		return false;

	return true;
}

/* Locate  a record in a VPD blob
 *
 * Note: This works with VPD LIDs. It will scan until it finds
 * the first 0x84, so it will skip all those 0's that the VPD
 * LIDs seem to contain
 */
const void *vpd_find_record(const void *vpd, size_t vpd_size,
			    const char *record, size_t *sz)
{
	const uint8_t *p = vpd, *end = vpd + vpd_size;
	bool first_start = true;
	size_t rec_sz;
	uint8_t namesz = 0;
	const char *rec_name;

	if (!vpd)
		return NULL;

	while (CHECK_SPACE(p, 4, end)) {
		/* Get header byte */
		if (*(p++) != 0x84) {
			/* Skip initial crap in VPD LIDs */
			if (first_start)
				continue;
			break;
		}
		first_start = false;
		rec_sz = *(p++);
		rec_sz |= *(p++) << 8;
		if (!CHECK_SPACE(p, rec_sz, end)) {
			prerror("VPD: Malformed or truncated VPD,"
				" record size doesn't fit\n");
			return NULL;
		}

		/* Find record name */
		rec_name = vpd_find_keyword(p, rec_sz, "RT", &namesz);
		if (rec_name && strncmp(record, rec_name, namesz) == 0) {
			if (sz)
				*sz = rec_sz;
			return p;
		}

		p += rec_sz;
		if (*(p++) != 0x78) {
			prerror("VPD: Malformed or truncated VPD,"
				" missing final 0x78 in record %.4s\n",
				rec_name ? rec_name : "????");
			return NULL;
		}
	}
	return NULL;
}

/* Locate a keyword in a record in a VPD blob
 *
 * Note: This works with VPD LIDs. It will scan until it finds
 * the first 0x84, so it will skip all those 0's that the VPD
 * LIDs seem to contain
 */
const void *vpd_find(const void *vpd, size_t vpd_size,
		     const char *record, const char *keyword,
		     uint8_t *sz)
{
	size_t rec_sz;
	const uint8_t *p;

	p = vpd_find_record(vpd, vpd_size, record, &rec_sz);
	if (p)
		p = vpd_find_keyword(p, rec_sz, keyword, sz);
	return p;
}
