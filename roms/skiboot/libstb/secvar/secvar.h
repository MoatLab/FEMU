// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef _SECVAR_H_
#define _SECVAR_H_

#include <ccan/list/list.h>
#include <stdint.h>
#include <secvar.h>

#define SECVAR_MAX_KEY_LEN		1024

enum {
	SECVAR_VARIABLE_BANK,
	SECVAR_UPDATE_BANK,
};


#define SECVAR_FLAG_VOLATILE	0x1 /* Instructs storage driver to ignore variable on writes */
#define SECVAR_FLAG_PROTECTED	0x2 /* Instructs storage driver to store in lockable flash */

struct secvar {
	struct list_node link;
	uint64_t key_len;
	uint64_t data_size;
	uint64_t flags;
	char *key;
	char *data;
};

extern struct list_head variable_bank;
extern struct list_head update_bank;
extern int secvar_enabled;
extern int secvar_ready;
extern struct secvar_storage_driver secvar_storage;
extern struct secvar_backend_driver secvar_backend;

// Helper functions
void clear_bank_list(struct list_head *bank);
int copy_bank_list(struct list_head *dst, struct list_head *src);
struct secvar *alloc_secvar(uint64_t key_len, uint64_t data_size);
struct secvar *new_secvar(const char *key, uint64_t key_len,
			       const char *data, uint64_t data_size,
			       uint64_t flags);
int realloc_secvar(struct secvar *node, uint64_t size);
void dealloc_secvar(struct secvar *node);
struct secvar *find_secvar(const char *key, uint64_t key_len, struct list_head *bank);
int is_key_empty(const char *key, uint64_t key_len);
int list_length(struct list_head *bank);

#endif
