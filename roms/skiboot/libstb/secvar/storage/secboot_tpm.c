// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2020 IBM Corp. */
#ifndef pr_fmt
#define pr_fmt(fmt) "SECBOOT_TPM: " fmt
#endif

#include <stdlib.h>
#include <skiboot.h>
#include <opal.h>
#include <mbedtls/sha256.h>
#include "../secvar.h"
#include "../secvar_devtree.h"
#include "secboot_tpm.h"
#include <tssskiboot.h>
#include <ibmtss/TPM_Types.h>

#define CYCLE_BIT(b) (b^0x1)

#define SECBOOT_TPM_MAX_VAR_SIZE	8192

struct secboot *secboot_image = NULL;
struct tpmnv_vars *tpmnv_vars_image = NULL;
struct tpmnv_control *tpmnv_control_image = NULL;

const size_t tpmnv_vars_size = 2048;

/* Expected TPM NV index name field from NV_ReadPublic given our known
 * set of attributes (see tss_nv_define_space).
 * See Part 1 Section 16, and Part 2 Section 13.5 of the TPM Specification
 * for how this is calculated
 *
 * These hashes are calculated and checked BEFORE TPM2_NV_WriteLock is called,
 * which alters the hash slightly as it sets TPMA_NV_WRITELOCKED
 */
const uint8_t tpmnv_vars_name[] = {
        0x00, 0x0b, 0x7a, 0xdb, 0x70, 0xdd, 0x27, 0x94, 0x93, 0x26, 0x11, 0xe2, 0x97,
        0x00, 0x77, 0x22, 0x4d, 0x5a, 0x74, 0xf8, 0x91, 0x6f, 0xbf, 0xf8, 0x51, 0x4a,
        0x67, 0x6f, 0xd9, 0xa8, 0xc3, 0xfc, 0x39, 0xed,
};

const uint8_t tpmnv_control_name[] = {
	0x00, 0x0b, 0xad, 0x47, 0x6b, 0xa5, 0xdf, 0xb1, 0xe2, 0x18, 0x50, 0xf6, 0x05,
	0x67, 0xe8, 0x8b, 0xa9, 0x0f, 0x86, 0x1f, 0x06, 0xab, 0x43, 0x96, 0x7f, 0x6e,
	0x85, 0x33, 0x5b, 0xa6, 0xf0, 0x63, 0x73, 0xd0,
};

const uint8_t tpmnv_vars_prov_name[] = {
	0x00, 0x0b, 0x58, 0x36, 0x2c, 0xbf, 0xec, 0x0e, 0xcc, 0xbf, 0xa9, 0x41, 0x94,
	0xe9, 0x95, 0xe8, 0x3b, 0xd7, 0x8b, 0x52, 0xac, 0x61, 0x6f, 0xe6, 0x42, 0x93,
	0xbb, 0x5a, 0x79, 0x9f, 0xcc, 0x60, 0x5e, 0x8d,
};

const uint8_t tpmnv_control_prov_name[] = {
	0x00, 0x0b, 0x7b, 0xd6, 0x02, 0xac, 0xf5, 0x34, 0x54, 0x5c, 0x3e, 0xda, 0xe5,
	0xb2, 0xe4, 0x93, 0x4f, 0x36, 0xfb, 0x7f, 0xea, 0xbe, 0xfa, 0x3c, 0xfe, 0xed,
	0x6a, 0x12, 0xfb, 0xc8, 0xf7, 0x92, 0x0e, 0xd3,
};

/* Calculate a SHA256 hash over the supplied buffer */
static int calc_bank_hash(char *target_hash, const char *source_buf, uint64_t size)
{
	mbedtls_sha256_context ctx;
	int rc;

	mbedtls_sha256_init(&ctx);

	rc = mbedtls_sha256_update_ret(&ctx, source_buf, size);
	if (rc)
		goto out;

	mbedtls_sha256_finish_ret(&ctx, target_hash);
	if (rc)
		goto out;

out:
	mbedtls_sha256_free(&ctx);
	return rc;
}

/* Reformat the TPMNV space */
static int tpmnv_format(void)
{
	int rc;

	memset(tpmnv_vars_image, 0x00, tpmnv_vars_size);
	memset(tpmnv_control_image, 0x00, sizeof(struct tpmnv_control));

	tpmnv_vars_image->header.magic_number = SECBOOT_MAGIC_NUMBER;
	tpmnv_vars_image->header.version = SECBOOT_VERSION;
	tpmnv_control_image->header.magic_number = SECBOOT_MAGIC_NUMBER;
	tpmnv_control_image->header.version = SECBOOT_VERSION;

	/* Counts as first write to the TPM NV, which sets the
	 *  TPMA_NVA_WRITTEN attribute */
	rc = tpmnv_ops.write(SECBOOT_TPMNV_VARS_INDEX,
			     tpmnv_vars_image,
			     tpmnv_vars_size, 0);
	if (rc) {
		prlog(PR_ERR, "Could not write new formatted data to VARS index, rc=%d\n", rc);
		return rc;
	}

	rc = tpmnv_ops.write(SECBOOT_TPMNV_CONTROL_INDEX,
			     tpmnv_control_image,
			     sizeof(struct tpmnv_control), 0);
	if (rc)
		prlog(PR_ERR, "Could not write new formatted data to CONTROL index, rc=%d\n", rc);

	return rc;
}

/* Reformat the secboot PNOR space */
static int secboot_format(void)
{
	int rc;

	memset(secboot_image, 0x00, sizeof(struct secboot));

	secboot_image->header.magic_number = SECBOOT_MAGIC_NUMBER;
	secboot_image->header.version = SECBOOT_VERSION;

	/* Write the hash of the empty bank to the tpm so future loads work */
	rc = calc_bank_hash(tpmnv_control_image->bank_hash[0],
			    secboot_image->bank[0],
			    SECBOOT_VARIABLE_BANK_SIZE);
	if (rc) {
		prlog(PR_ERR, "Bank hash failed to calculate somehow\n");
		return rc;
	}

	rc = tpmnv_ops.write(SECBOOT_TPMNV_CONTROL_INDEX,
			     tpmnv_control_image->bank_hash[0],
			     SHA256_DIGEST_SIZE,
			     offsetof(struct tpmnv_control,
			     bank_hash[0]));
	if (rc) {
		prlog(PR_ERR, "Could not write fresh formatted bank hashes to CONTROL index, rc=%d\n", rc);
		return rc;
	}

	rc = flash_secboot_write(0, secboot_image, sizeof(struct secboot));
	if (rc)
		prlog(PR_ERR, "Could not write formatted data to PNOR, rc=%d\n", rc);

	return rc;
}


/*
 * Serialize one variable to a target memory location.
 * Returns the advanced target pointer,
 *   NULL if advanced pointer would exceed the supplied bound
 */
static char *secboot_serialize_secvar(char *target, const struct secvar *var, const char *end)
{
	if ((target + sizeof(uint64_t) + sizeof(uint64_t)
		+ var->key_len + var->data_size) > end)
		return NULL;

	*((uint64_t*) target) = cpu_to_be64(var->key_len);
	target += sizeof(var->key_len);
	*((uint64_t*) target) = cpu_to_be64(var->data_size);
	target += sizeof(var->data_size);
	memcpy(target, var->key, var->key_len);
	target += var->key_len;
	memcpy(target, var->data, var->data_size);
	target += var->data_size;

	return target;
}


/* Flattens a linked-list bank into a contiguous buffer for writing */
static int secboot_serialize_bank(const struct list_head *bank, char *target,
				  size_t target_size, int flags)
{
	struct secvar *var;
	char *end = target + target_size;

	assert(bank);
	assert(target);

	memset(target, 0x00, target_size);

	list_for_each(bank, var, link) {
		if (var->flags != flags)
			continue;

		target = secboot_serialize_secvar(target, var, end);
		if (!target) {
			prlog(PR_ERR, "Ran out of %s space, giving up!",
				(flags & SECVAR_FLAG_PROTECTED) ? "TPMNV" : "PNOR");
			return OPAL_EMPTY;
		}
	}

	return OPAL_SUCCESS;
}

/* Helper for the variable-bank specific writing logic */
static int secboot_tpm_write_variable_bank(const struct list_head *bank)
{
	int rc;
	uint64_t bit;

	bit = CYCLE_BIT(tpmnv_control_image->active_bit);
	/* Serialize TPMNV variables */
	rc = secboot_serialize_bank(bank, tpmnv_vars_image->vars, tpmnv_vars_size - sizeof(struct tpmnv_vars), SECVAR_FLAG_PROTECTED);
	if (rc)
		goto out;


	/* Write TPMNV variables to actual NV */
	rc = tpmnv_ops.write(SECBOOT_TPMNV_VARS_INDEX, tpmnv_vars_image, tpmnv_vars_size, 0);
	if (rc)
		goto out;

	/* Serialize the PNOR variables, but don't write to flash until after the bank hash */
	rc = secboot_serialize_bank(bank, secboot_image->bank[bit], SECBOOT_VARIABLE_BANK_SIZE, 0);
	if (rc)
		goto out;

	/* Calculate the bank hash, and write to TPM NV */
	rc = calc_bank_hash(tpmnv_control_image->bank_hash[bit], secboot_image->bank[bit], SECBOOT_VARIABLE_BANK_SIZE);
	if (rc)
		goto out;

	rc = tpmnv_ops.write(SECBOOT_TPMNV_CONTROL_INDEX, tpmnv_control_image->bank_hash[bit],
				SHA256_DIGEST_LENGTH, offsetof(struct tpmnv_control, bank_hash[bit]));
	if (rc)
		goto out;

	/* Write new variable bank to pnor */
	rc = flash_secboot_write(0, secboot_image, sizeof(struct secboot));
	if (rc)
		goto out;

	/* Flip the bit, and write to TPM NV */
	tpmnv_control_image->active_bit = bit;
	rc = tpmnv_ops.write(SECBOOT_TPMNV_CONTROL_INDEX,
			     &tpmnv_control_image->active_bit,
			     sizeof(tpmnv_control_image->active_bit),
			     offsetof(struct tpmnv_control, active_bit));
out:

	return rc;
}

static int secboot_tpm_write_bank(struct list_head *bank, int section)
{
	int rc;

	switch (section) {
	case SECVAR_VARIABLE_BANK:
		rc = secboot_tpm_write_variable_bank(bank);
		break;
	case SECVAR_UPDATE_BANK:
		memset(secboot_image->update, 0, SECBOOT_UPDATE_BANK_SIZE);
		rc = secboot_serialize_bank(bank, secboot_image->update,
					    SECBOOT_UPDATE_BANK_SIZE, 0);
		if (rc)
			break;

		rc = flash_secboot_write(0, secboot_image,
					    sizeof(struct secboot));
		break;
	default:
		rc = OPAL_HARDWARE;
	}

	return rc;
}


/*
 * Deserialize a single secvar from a buffer.
 * Returns an advanced pointer, and an allocated secvar in *var.
 * Returns NULL if out of bounds reached, or out of memory.
 */
static int secboot_deserialize_secvar(struct secvar **var, char **src, const char *end)
{
	uint64_t key_len;
	uint64_t data_size;
	struct secvar *ret;

	assert(var);

	/* Load in the two header values */
	key_len = be64_to_cpu(*((uint64_t *) *src));
	*src += sizeof(uint64_t);
	data_size = be64_to_cpu(*((uint64_t *) *src));
	*src += sizeof(uint64_t);

	/* Check if we've reached the last var to deserialize */
	if ((key_len == 0) && (data_size == 0)) {
		return OPAL_EMPTY;
	}

	if (key_len > SECVAR_MAX_KEY_LEN) {
		prlog(PR_ERR, "Deserialization failed: key length exceeded maximum value"
			"%llu > %u", key_len, SECVAR_MAX_KEY_LEN);
		return OPAL_RESOURCE;
	}
	if (data_size > SECBOOT_TPM_MAX_VAR_SIZE) {
		prlog(PR_ERR, "Deserialization failed: data size exceeded maximum value"
			"%llu > %u", key_len, SECBOOT_TPM_MAX_VAR_SIZE);
		return OPAL_RESOURCE;
	}

	/* Make sure these fields aren't oversized... */
	if ((*src + key_len + data_size) > end) {
		*var = NULL;
		prlog(PR_ERR, "key_len or data_size exceeded the expected bounds");
		return OPAL_RESOURCE;
	}

	ret = alloc_secvar(key_len, data_size);
	if (!ret) {
		*var = NULL;
		prlog(PR_ERR, "Out of memory, could not allocate new secvar");
		return OPAL_NO_MEM;
	}

	/* Load in variable-sized data */
	memcpy(ret->key, *src, ret->key_len);
	*src += ret->key_len;
	memcpy(ret->data, *src, ret->data_size);
	*src += ret->data_size;

	*var = ret;

	return OPAL_SUCCESS;
}


/* Load variables from a flattened buffer into a bank list */
static int secboot_tpm_deserialize_from_buffer(struct list_head *bank, char *src,
					       uint64_t size, uint64_t flags)
{
	struct secvar *var;
	char *cur;
	char *end;
	int rc = 0;

	cur = src;
	end = src + size;

	while (cur < end) {
		/* Ensure there is enough space to even check for another var header */
		if ((end - cur) < (sizeof(uint64_t) * 2))
			break;

		rc = secboot_deserialize_secvar(&var, &cur, end);
		switch (rc) {
			case OPAL_RESOURCE:
			case OPAL_NO_MEM:
				goto fail;
			case OPAL_EMPTY:
				goto done;
			default: assert(1);
		}

		var->flags |= flags;

		list_add_tail(bank, &var->link);
	}
done:
	return OPAL_SUCCESS;
fail:
	clear_bank_list(bank);
	return rc;
}

static int secboot_tpm_load_variable_bank(struct list_head *bank)
{
	char bank_hash[SHA256_DIGEST_LENGTH];
	uint64_t bit = tpmnv_control_image->active_bit;
	int rc;

	/* Check the hash of the bank we loaded from PNOR
	 *  versus the expected hash in TPM NV */
	rc = calc_bank_hash(bank_hash,
			    secboot_image->bank[bit],
			    SECBOOT_VARIABLE_BANK_SIZE);
	if (rc)
		return rc;

	if (memcmp(bank_hash,
		   tpmnv_control_image->bank_hash[bit],
		   SHA256_DIGEST_LENGTH))
		/* Tampered pnor space detected, abandon ship */
		return OPAL_PERMISSION;

	rc = secboot_tpm_deserialize_from_buffer(bank, tpmnv_vars_image->vars, tpmnv_vars_size, SECVAR_FLAG_PROTECTED);
	if (rc)
		return rc;

	return secboot_tpm_deserialize_from_buffer(bank, secboot_image->bank[bit], SECBOOT_VARIABLE_BANK_SIZE, 0);
}


static int secboot_tpm_load_bank(struct list_head *bank, int section)
{
	switch (section) {
	case SECVAR_VARIABLE_BANK:
		return secboot_tpm_load_variable_bank(bank);
	case SECVAR_UPDATE_BANK:
		return secboot_tpm_deserialize_from_buffer(bank, secboot_image->update, SECBOOT_UPDATE_BANK_SIZE, 0);
	}

	return OPAL_HARDWARE;
}

static int secboot_tpm_get_tpmnv_names(char *nv_vars_name, char *nv_control_name)
{
	TPMS_NV_PUBLIC nv_public; /* Throwaway, we only want the name field */
	TPM2B_NAME vars_tmp;
	TPM2B_NAME control_tmp;
	int rc;

	rc = tpmnv_ops.readpublic(SECBOOT_TPMNV_VARS_INDEX,
				  &nv_public,
				  &vars_tmp);
	if (rc) {
		prlog(PR_ERR, "Failed to readpublic from the VARS index, rc=%d\n", rc);
		return rc;
	}
	rc = tpmnv_ops.readpublic(SECBOOT_TPMNV_CONTROL_INDEX,
				  &nv_public,
				  &control_tmp);
	if (rc) {
		prlog(PR_ERR, "Failed to readpublic from the CONTROL index, rc=%d\n", rc);
		return rc;
	}

	memcpy(nv_vars_name, vars_tmp.t.name, MIN(sizeof(tpmnv_vars_name), vars_tmp.t.size));
	memcpy(nv_control_name, control_tmp.t.name, MIN(sizeof(tpmnv_control_name), control_tmp.t.size));

	return OPAL_SUCCESS;
}


/* Ensure the NV indices were defined with the correct set of attributes */
static int secboot_tpm_check_tpmnv_attrs(char *nv_vars_name, char *nv_control_name)
{
	if (memcmp(tpmnv_vars_name,
		   nv_vars_name,
		   sizeof(tpmnv_vars_name))) {
		prlog(PR_ERR, "VARS index not defined with the correct attributes\n");
		return OPAL_RESOURCE;
	}
	if (memcmp(tpmnv_control_name,
		   nv_control_name,
		   sizeof(tpmnv_control_name))) {
		prlog(PR_ERR, "CONTROL index not defined with the correct attributes\n");
		return OPAL_RESOURCE;
	}

	return OPAL_SUCCESS;
}

static bool secboot_tpm_check_provisioned_indices(char *nv_vars_name, char *nv_control_name)
{
	/* Check for provisioned NV indices, redefine them if detected. */
	if (!memcmp(tpmnv_vars_prov_name,
			nv_vars_name,
			sizeof(tpmnv_vars_prov_name))  &&
		!memcmp(tpmnv_control_prov_name,
			nv_control_name,
			sizeof(tpmnv_control_prov_name))) {
		return true;
	}

	/*
	 * If one matches but the other doesn't, do NOT redefine.
	 * The next step should detect they don't match the expected values
	 * and fail the boot.
	 */
	return false;
}

static int secboot_tpm_define_indices(void)
{
	int rc = OPAL_SUCCESS;

	rc = tpmnv_ops.definespace(SECBOOT_TPMNV_VARS_INDEX, tpmnv_vars_size);
	if (rc) {
		prlog(PR_ERR, "Failed to define the VARS index, rc=%d\n", rc);
		return rc;
	}

	rc = tpmnv_ops.definespace(SECBOOT_TPMNV_CONTROL_INDEX, sizeof(struct tpmnv_control));
	if (rc) {
		prlog(PR_ERR, "Failed to define the CONTROL index, rc=%d\n", rc);
		return rc;
	}

	rc = tpmnv_format();
	if (rc)
		return rc;

	/* TPM NV just got redefined, so unconditionally format the SECBOOT partition */
	return secboot_format();
}

static int secboot_tpm_undefine_indices(bool *vars_defined, bool *control_defined)
{
	int rc;

	if (vars_defined) {
		rc = tpmnv_ops.undefinespace(SECBOOT_TPMNV_VARS_INDEX);
		if (rc) {
			prlog(PR_ERR, "Failed to undefine VARS, something is seriously wrong\n");
			return rc;
		}
	}

	if (control_defined) {
		rc = tpmnv_ops.undefinespace(SECBOOT_TPMNV_CONTROL_INDEX);
		if (rc) {
			prlog(PR_ERR, "Failed to undefine CONTROL, something is seriously wrong\n");
			return rc;
		}
	}

	*vars_defined = *control_defined = false;

	return OPAL_SUCCESS;
}


static int secboot_tpm_store_init(void)
{
	int rc;
	unsigned int secboot_size;

	TPMI_RH_NV_INDEX *indices = NULL;
	char nv_vars_name[sizeof(tpmnv_vars_name)];
	char nv_control_name[sizeof(tpmnv_control_name)];
	size_t count = 0;
	bool control_defined = false;
	bool vars_defined = false;
	int i;

	if (secboot_image)
		return OPAL_SUCCESS;

	prlog(PR_DEBUG, "Initializing for pnor+tpm based platform\n");

	/* Initialize SECBOOT first, we may need to format this later */
	rc = flash_secboot_info(&secboot_size);
	if (rc) {
		prlog(PR_ERR, "error %d retrieving keystore info\n", rc);
		goto error;
	}
	if (sizeof(struct secboot) > secboot_size) {
		prlog(PR_ERR, "secboot partition %d KB too small. min=%ld\n",
		      secboot_size >> 10, sizeof(struct secboot));
		rc = OPAL_RESOURCE;
		goto error;
	}

	secboot_image = memalign(0x1000, sizeof(struct secboot));
	if (!secboot_image) {
		prlog(PR_ERR, "Failed to allocate space for the secboot image\n");
		rc = OPAL_NO_MEM;
		goto error;
	}

	/* Read in the PNOR data, bank hash is checked on call to .load_bank() */
	rc = flash_secboot_read(secboot_image, 0, sizeof(struct secboot));
	if (rc) {
		prlog(PR_ERR, "failed to read the secboot partition, rc=%d\n", rc);
		goto error;
	}

	/* Allocate the tpmnv data buffers */
	tpmnv_vars_image = zalloc(tpmnv_vars_size);
	if (!tpmnv_vars_image)
		return OPAL_NO_MEM;
	tpmnv_control_image = zalloc(sizeof(struct tpmnv_control));
	if (!tpmnv_control_image)
		return OPAL_NO_MEM;

	/* Check if the NV indices have been defined already */
	rc = tpmnv_ops.getindices(&indices, &count);
	if (rc) {
		prlog(PR_ERR, "Could not load defined indicies from TPM, rc=%d\n", rc);
		goto error;
	}

	for (i = 0; i < count; i++) {
		if (indices[i] == SECBOOT_TPMNV_VARS_INDEX)
			vars_defined = true;
		else if (indices[i] == SECBOOT_TPMNV_CONTROL_INDEX)
			control_defined = true;
	}
	free(indices);

	/* Undefine the NV indices if physical presence has been asserted */
	if (secvar_check_physical_presence()) {
		prlog(PR_INFO, "Physical presence asserted, redefining NV indices, and resetting keystore\n");
		rc = secboot_tpm_undefine_indices(&vars_defined, &control_defined);
		if (rc)
			goto error;

		rc = secboot_tpm_define_indices();
		if (rc)
			goto error;

		/* Indices got defined and formatted, we're done here */
		goto done;
	}
	/* Determine if we need to define the indices. These should BOTH be false or true */
	if (!vars_defined && !control_defined) {
		rc = secboot_tpm_define_indices();
		if (rc)
			goto error;

		/* Indices got defined and formatted, we're done here */
		goto done;
	}
	if (vars_defined ^ control_defined) {
		/* This should never happen. Both indices should be defined at the same
		 * time. Otherwise something seriously went wrong. */
		prlog(PR_ERR, "NV indices defined with unexpected attributes. Assert physical presence to clear\n");
		goto error;
	}

	/* Both indices are defined, now need to validate their contents */

	rc = secboot_tpm_get_tpmnv_names(nv_vars_name, nv_control_name);
	if (rc)
		goto error;

	/* Check for provisioned TPMNV indices, redefine them if detected */
	if (secboot_tpm_check_provisioned_indices(nv_vars_name, nv_control_name)) {
		prlog(PR_INFO, "Provisioned TPM NV indices detected, redefining NV indices, and resetting keystore\n");
		rc = secboot_tpm_undefine_indices(&vars_defined, &control_defined);
		if (rc)
			goto error;

		rc = secboot_tpm_define_indices();
		if (rc)
			goto error;

		/* Indices got defined and formatted, we're done here */
		goto done;
	}

	/* Otherwise, ensure the NV indices were defined with the correct set of attributes */
	rc = secboot_tpm_check_tpmnv_attrs(nv_vars_name, nv_control_name);
	if (rc)
		goto error;


	/* TPMNV indices exist, are correct, and weren't just formatted, so read them in */
	rc = tpmnv_ops.read(SECBOOT_TPMNV_VARS_INDEX,
			    tpmnv_vars_image,
			    tpmnv_vars_size, 0);
	if (rc) {
		prlog(PR_ERR, "Failed to read from the VARS index\n");
		goto error;
	}

	rc = tpmnv_ops.read(SECBOOT_TPMNV_CONTROL_INDEX,
			    tpmnv_control_image,
			    sizeof(struct tpmnv_control), 0);
	if (rc) {
		prlog(PR_ERR, "Failed to read from the CONTROL index\n");
		goto error;
	}

	/* Verify the header information is correct */
	if (tpmnv_vars_image->header.magic_number != SECBOOT_MAGIC_NUMBER ||
	    tpmnv_control_image->header.magic_number != SECBOOT_MAGIC_NUMBER ||
	    tpmnv_vars_image->header.version != SECBOOT_VERSION ||
	    tpmnv_control_image->header.version != SECBOOT_VERSION) {
		prlog(PR_ERR, "TPMNV indices defined, but contain bad data. Assert physical presence to clear\n");
		goto error;
	}

	/* Verify the secboot partition header information,
	 *  reformat if incorrect
	 * Note: Future variants should attempt to handle older versions safely
	 */
	if (secboot_image->header.magic_number != SECBOOT_MAGIC_NUMBER ||
	    secboot_image->header.version != SECBOOT_VERSION) {
		rc = secboot_format();
		if (rc)
			goto error;
	}

done:
	return OPAL_SUCCESS;

error:
	free(secboot_image);
	secboot_image = NULL;
	free(tpmnv_vars_image);
	tpmnv_vars_image = NULL;
	free(tpmnv_control_image);
	tpmnv_control_image = NULL;

	return rc;
}


static void secboot_tpm_lockdown(void)
{
	/* Note: While write lock is called here on the two NV indices,
	 * both indices are also defined on the platform hierarchy.
	 * The platform hierarchy auth is set later in the skiboot
	 * initialization process, and not by any secvar-related code.
	 */
	int rc;

	rc = tpmnv_ops.writelock(SECBOOT_TPMNV_VARS_INDEX);
	if (rc) {
		prlog(PR_EMERG, "TSS Write Lock failed on VARS index, halting.\n");
		abort();
	}

	rc = tpmnv_ops.writelock(SECBOOT_TPMNV_CONTROL_INDEX);
	if (rc) {
		prlog(PR_EMERG, "TSS Write Lock failed on CONTROL index, halting.\n");
		abort();
	}
}

struct secvar_storage_driver secboot_tpm_driver = {
	.load_bank = secboot_tpm_load_bank,
	.write_bank = secboot_tpm_write_bank,
	.store_init = secboot_tpm_store_init,
	.lockdown = secboot_tpm_lockdown,
	.max_var_size = SECBOOT_TPM_MAX_VAR_SIZE,
};
