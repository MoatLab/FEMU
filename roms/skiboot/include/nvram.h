// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __NVRAM_H
#define __NVRAM_H

int nvram_format(void *nvram_image, uint32_t nvram_size);
int nvram_check(void *nvram_image, uint32_t nvram_size);
void nvram_reinit(void);
bool nvram_validate(void);
bool nvram_has_loaded(void);
bool nvram_wait_for_load(void);

const char *nvram_query_safe(const char *name);
const char *nvram_query_dangerous(const char *name);
bool nvram_query_eq_safe(const char *key, const char *value);
bool nvram_query_eq_dangerous(const char *key, const char *value);

#endif /* __NVRAM_H */
