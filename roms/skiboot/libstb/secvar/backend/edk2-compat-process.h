// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2020 IBM Corp. */

#ifndef __SECVAR_EDK2_COMPAT_PROCESS__
#define __SECVAR_EDK2_COMPAT_PROCESS__

#ifndef pr_fmt
#define pr_fmt(fmt) "EDK2_COMPAT: " fmt
#endif

#include <opal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <ccan/endian/endian.h>
#include <mbedtls/error.h>
#include <device.h>
#include "libstb/crypto/pkcs7/pkcs7.h"
#include "edk2.h"
#include "opal-api.h"
#include "../secvar.h"
#include "../secvar_devtree.h"

#define CERT_BUFFER_SIZE        2048
#define MBEDTLS_ERR_BUFFER_SIZE 1024

#define EDK2_MAX_KEY_LEN        SECVAR_MAX_KEY_LEN
#define key_equals(a,b) (!strncmp(a, b, EDK2_MAX_KEY_LEN))
#define uuid_equals(a,b) (!memcmp(a, b, UUID_SIZE))

extern bool setup_mode;
extern struct list_head staging_bank;

/* Update the variable in the variable bank with the new value. */
int update_variable_in_bank(struct secvar *update_var, const char *data,
			    uint64_t dsize, struct list_head *bank);

/* This function outputs the Authentication 2 Descriptor in the
 * auth_buffer and returns the size of the buffer. Please refer to
 * edk2.h for details on Authentication 2 Descriptor
 */
int get_auth_descriptor2(const void *buf, const size_t buflen,
			 void **auth_buffer);

/* Check the format of the ESL */
int validate_esl_list(const char *key, const char *esl, const size_t size);

/* Update the TS variable with the new timestamp */
int update_timestamp(const char *key, const struct efi_time *timestamp, char *last_timestamp);

/* Check the new timestamp against the timestamp last update was done */
int check_timestamp(const char *key, const struct efi_time *timestamp, char *last_timestamp);

/* Check the GUID of the data type */
bool is_pkcs7_sig_format(const void *data);

/* Process the update */
int process_update(const struct secvar *update, char **newesl,
		   int *neweslsize, struct efi_time *timestamp,
		   struct list_head *bank, char *last_timestamp);

#endif
