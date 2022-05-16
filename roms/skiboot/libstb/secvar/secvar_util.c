// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2019 IBM Corp. */

#ifndef pr_fmt
#define pr_fmt(fmt) "SECVAR: " fmt
#endif

#include <stdlib.h>
#include <string.h>
#include <skiboot.h>
#include <opal.h>
#include "secvar.h"

void clear_bank_list(struct list_head *bank)
{
	struct secvar *var, *next;

	if (!bank)
		return;

	list_for_each_safe(bank, var, next, link) {
		list_del(&var->link);
		dealloc_secvar(var);
	}
}

int copy_bank_list(struct list_head *dst, struct list_head *src)
{
	struct secvar *var, *tmp;

	list_for_each(src, var, link) {
		/* Allocate new secvar using actual data size */
		tmp = new_secvar(var->key, var->key_len, var->data,
				 var->data_size, var->flags);
		/* Append to new list */
		list_add_tail(dst, &tmp->link);
	}

	return OPAL_SUCCESS;
}

struct secvar *alloc_secvar(uint64_t key_len, uint64_t data_size)
{
	struct secvar *ret;

	ret = zalloc(sizeof(struct secvar));
	if (!ret)
		return NULL;

	ret->key = zalloc(key_len);
	if (!ret->key) {
		free(ret);
		return NULL;
	}

	ret->data = zalloc(data_size);
	if (!ret->data) {
		free(ret->key);
		free(ret);
		return NULL;
	}

	ret->key_len = key_len;
	ret->data_size = data_size;

	return ret;
}

struct secvar *new_secvar(const char *key, uint64_t key_len,
			       const char *data, uint64_t data_size,
			       uint64_t flags)
{
	struct secvar *ret;

	if (!key)
		return NULL;
	if ((!key_len) || (key_len > SECVAR_MAX_KEY_LEN))
		return NULL;
	if ((!data) && (data_size))
		return NULL;

	ret = alloc_secvar(key_len, data_size);
	if (!ret)
		return NULL;

	memcpy(ret->key, key, key_len);
	ret->flags = flags;

	if (data)
		memcpy(ret->data, data, data_size);

	return ret;
}

int realloc_secvar(struct secvar *var, uint64_t size)
{
	void *tmp;

	if (var->data_size >= size)
		return 0;

	tmp = zalloc(size);
	if (!tmp)
		return -1;

	memcpy(tmp, var->data, var->data_size);
	free(var->data);
	var->data = tmp;

	return 0;
}

void dealloc_secvar(struct secvar *var)
{
	if (!var)
		return;

	free(var->key);
	free(var->data);
	free(var);
}

struct secvar *find_secvar(const char *key, uint64_t key_len, struct list_head *bank)
{
	struct secvar *var = NULL;

	list_for_each(bank, var, link) {
		// Prevent matching shorter key subsets / bail early
		if (key_len != var->key_len)
			continue;
		if (!memcmp(key, var->key, key_len))
			return var;
	}

	return NULL;
}

int is_key_empty(const char *key, uint64_t key_len)
{
	int i;
	for (i = 0; i < key_len; i++) {
		if (key[i] != 0)
			return 0;
	}

	return 1;
}

int list_length(struct list_head *bank)
{
	int ret = 0;
	struct secvar *var;

	list_for_each(bank, var, link)
		ret++;

	return ret;
}
