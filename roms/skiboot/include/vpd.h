// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __VPD_H
#define __VPD_H

struct machine_info {
	const char *mtm;
	const char *name;
};

const struct machine_info *machine_info_lookup(const char *mtm);

const void *vpd_find_keyword(const void *rec, size_t rec_sz,
			     const char *kw, uint8_t *kw_size);

const void *vpd_find_record(const void *vpd, size_t vpd_size,
			    const char *record, size_t *sz);

const void *vpd_find(const void *vpd, size_t vpd_size,
		     const char *record, const char *keyword,
		     uint8_t *sz);

bool vpd_valid(const void *vvpd, size_t vpd_size);

/* Add model property to dt_root */
void add_dtb_model(void);

#define VPD_LOAD_LXRN_VINI	0xff


#endif /* __VPD_H */
