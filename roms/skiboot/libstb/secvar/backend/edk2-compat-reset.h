// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2020 IBM Corp. */

#ifndef __SECVAR_EDK2_COMPAT_CLEAR_KEYS__
#define __SECVAR_EDK2_COMPAT_CLEAR_KEYS__

#ifndef pr_fmt
#define pr_fmt(fmt) "EDK2_COMPAT: " fmt
#endif

/* clear all os keys and the timestamp*/
int reset_keystore(struct list_head *bank);

/* Compares the hw-key-hash from device tree to the value stored in
 * the protected storage to ensure it is not modified */
int verify_hw_key_hash(void);

/* Adds hw-key-hash */
int add_hw_key_hash(struct list_head *bank);

/* Delete hw-key-hash */
int delete_hw_key_hash(struct list_head *bank);

#endif
