// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2020 IBM Corp. */
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
#include <mbedtls/oid.h>
#include <device.h>
#include <assert.h>
#include "libstb/crypto/pkcs7/pkcs7.h"
#include "edk2.h"
#include "../secvar.h"
#include "edk2-compat-process.h"

bool setup_mode;

int update_variable_in_bank(struct secvar *update_var, const char *data,
			    const uint64_t dsize, struct list_head *bank)
{
	struct secvar *var;

	var = find_secvar(update_var->key, update_var->key_len, bank);
	if (!var)
		return OPAL_EMPTY;

        /* Reallocate the data memory, if there is change in data size */
	if (var->data_size < dsize)
		if (realloc_secvar(var, dsize))
			return OPAL_NO_MEM;

	if (dsize && data)
		memcpy(var->data, data, dsize);
	var->data_size = dsize;

        /* Clear the volatile bit only if updated with positive data size */
	if (dsize)
		var->flags &= ~SECVAR_FLAG_VOLATILE;
	else
		var->flags |= SECVAR_FLAG_VOLATILE;

	if (key_equals(update_var->key, "PK") || key_equals(update_var->key, "HWKH"))
		var->flags |= SECVAR_FLAG_PROTECTED;

	return 0;
}

/* Expand char to wide character size */
static char *char_to_wchar(const char *key, const size_t keylen)
{
	int i;
	char *str;

	str = zalloc(keylen * 2);
	if (!str)
		return NULL;

	for (i = 0; i < keylen*2; key++) {
		str[i++] = *key;
		str[i++] = '\0';
	}

	return str;
}

/* Returns the authority that can sign the given key update */
static void get_key_authority(const char *ret[3], const char *key)
{
	int i = 0;

	if (key_equals(key, "PK")) {
		ret[i++] = "PK";
	} else if (key_equals(key, "KEK")) {
		ret[i++] = "PK";
	} else if (key_equals(key, "db") || key_equals(key, "dbx")) {
		ret[i++] = "KEK";
		ret[i++] = "PK";
	}

	ret[i] = NULL;
}

static EFI_SIGNATURE_LIST* get_esl_signature_list(const char *buf, size_t buflen)
{
	EFI_SIGNATURE_LIST *list = NULL;

	if (buflen < sizeof(EFI_SIGNATURE_LIST) || !buf)
		return NULL;

	list = (EFI_SIGNATURE_LIST *)buf;

	return list;
}

/* Returns the size of the complete ESL. */
static int32_t get_esl_signature_list_size(const char *buf, const size_t buflen)
{
	EFI_SIGNATURE_LIST *list = get_esl_signature_list(buf, buflen);

	if (!list)
		return OPAL_PARAMETER;

	return le32_to_cpu(list->SignatureListSize);
}

/* 
 * Copies the certificate from the ESL into cert buffer and returns the size
 * of the certificate
 */
static int get_esl_cert(const char *buf, const size_t buflen, char **cert)
{
	size_t sig_data_offset;
	size_t size;
	EFI_SIGNATURE_LIST *list = get_esl_signature_list(buf, buflen);

	if (!list)
		return OPAL_PARAMETER;

	assert(cert != NULL);

	if (le32_to_cpu(list->SignatureSize) <= sizeof(uuid_t))
		return OPAL_PARAMETER;

	size = le32_to_cpu(list->SignatureSize) - sizeof(uuid_t);

	prlog(PR_DEBUG,"size of signature list size is %u\n",
			le32_to_cpu(list->SignatureListSize));
	prlog(PR_DEBUG, "size of signature header size is %u\n",
			le32_to_cpu(list->SignatureHeaderSize));
	prlog(PR_DEBUG, "size of signature size is %u\n",
			le32_to_cpu(list->SignatureSize));

	sig_data_offset = sizeof(EFI_SIGNATURE_LIST)
			  + le32_to_cpu(list->SignatureHeaderSize)
			  + 16 * sizeof(uint8_t);

	/* Ensure this ESL does not overflow the bounds of the buffer */
	if (sig_data_offset + size > buflen) {
		prlog(PR_ERR, "Number of bytes of ESL data is less than size specified\n");
		return OPAL_PARAMETER;
	}

	*cert = zalloc(size);
	if (!(*cert))
		return OPAL_NO_MEM;

	/* Since buf can have more than one ESL, copy only the size calculated
	 * to return single ESL */
	memcpy(*cert, buf + sig_data_offset, size);

	return size;
}

/* 
 * Extracts size of the PKCS7 signed data embedded in the
 * struct Authentication 2 Descriptor Header.
 */
static size_t get_pkcs7_len(const struct efi_variable_authentication_2 *auth)
{
	uint32_t dw_length;
	size_t size;

	assert(auth != NULL);

	dw_length = le32_to_cpu(auth->auth_info.hdr.dw_length);
	size = dw_length - (sizeof(auth->auth_info.hdr.dw_length)
			+ sizeof(auth->auth_info.hdr.w_revision)
			+ sizeof(auth->auth_info.hdr.w_certificate_type)
			+ sizeof(auth->auth_info.cert_type));

	return size;
}

int get_auth_descriptor2(const void *buf, const size_t buflen, void **auth_buffer)
{
	const struct efi_variable_authentication_2 *auth = buf;
	int auth_buffer_size;
	size_t len;

	assert(auth_buffer != NULL);
	if (buflen < sizeof(struct efi_variable_authentication_2)
	    || !buf)
			return OPAL_PARAMETER;

	len = get_pkcs7_len(auth);
	/* pkcs7 content length cannot be greater than buflen */ 
	if (len > buflen)
		return OPAL_PARAMETER;

	auth_buffer_size = sizeof(auth->timestamp) + sizeof(auth->auth_info.hdr)
			   + sizeof(auth->auth_info.cert_type) + len;

	if (auth_buffer_size > buflen)
		return OPAL_PARAMETER;

	*auth_buffer = zalloc(auth_buffer_size);
	if (!(*auth_buffer))
		return OPAL_NO_MEM;

	/*
	 * Data = auth descriptor + new ESL data.
	 * Extracts only the auth descriptor from data.
	 */
	memcpy(*auth_buffer, buf, auth_buffer_size);

	return auth_buffer_size;
}

static bool validate_cert(char *signing_cert, int signing_cert_size)
{
	mbedtls_x509_crt x509;
	char *x509_buf = NULL;
	int rc;

	mbedtls_x509_crt_init(&x509);
	rc = mbedtls_x509_crt_parse(&x509, signing_cert, signing_cert_size);

	/* If failure in parsing the certificate, exit */
	if(rc) {
		prlog(PR_ERR, "X509 certificate parsing failed %04x\n", rc);
		return false;
	}

	x509_buf = zalloc(CERT_BUFFER_SIZE);
	rc = mbedtls_x509_crt_info(x509_buf, CERT_BUFFER_SIZE, "CRT:", &x509);

	mbedtls_x509_crt_free(&x509);
	free(x509_buf);
	x509_buf = NULL;

	/* If failure in reading the certificate, exit */
	if (rc < 0)
		return false;

	return true;
}

static bool validate_hash(uuid_t type, int size)
{
        if (uuid_equals(&type, &EFI_CERT_SHA1_GUID) && (size == 20))
                return true;

        if (uuid_equals(&type, &EFI_CERT_SHA224_GUID) && (size == 28))
                return true;

        if (uuid_equals(&type, &EFI_CERT_SHA256_GUID) && (size == 32))
                return true;

        if (uuid_equals(&type, &EFI_CERT_SHA384_GUID) && (size == 48))
                return true;

        if (uuid_equals(&type, &EFI_CERT_SHA512_GUID) && (size == 64))
                return true;

        return false;
}

int validate_esl_list(const char *key, const char *esl, const size_t size)
{
	int count = 0;
	int dsize;
	char *data = NULL;
	int eslvarsize = size;
	int eslsize;
	int rc = OPAL_SUCCESS;
	EFI_SIGNATURE_LIST *list = NULL;

	while (eslvarsize > 0) {
		prlog(PR_DEBUG, "esl var size is %d offset is %lu\n", eslvarsize, size - eslvarsize);
		if (eslvarsize < sizeof(EFI_SIGNATURE_LIST)) {
			prlog(PR_ERR, "ESL with size %d is too small\n", eslvarsize);
			rc = OPAL_PARAMETER;
			break;
		}

		/* Check Supported ESL Type */
		list = get_esl_signature_list(esl, eslvarsize);

		if (!list)
			return OPAL_PARAMETER;

		/* Calculate the size of the ESL */
		eslsize = le32_to_cpu(list->SignatureListSize);

		/* If could not extract the size */
		if (eslsize <= 0) {
			prlog(PR_ERR, "Invalid size of the ESL: %u\n",
					le32_to_cpu(list->SignatureListSize));
			rc = OPAL_PARAMETER;
			break;
		}

		/* Extract the certificate from the ESL */
		dsize = get_esl_cert(esl, eslvarsize, &data);
		if (dsize < 0) {
			rc = dsize;
			break;
		}

		if (key_equals(key, "dbx")) {
			if (!validate_hash(list->SignatureType, dsize)) {
				prlog(PR_ERR, "No valid hash is found\n");
				rc = OPAL_PARAMETER;
				break;
			}
		} else {
		       if (!uuid_equals(&list->SignatureType, &EFI_CERT_X509_GUID)
			   || !validate_cert(data, dsize)) {
				prlog(PR_ERR, "No valid cert is found\n");
				rc = OPAL_PARAMETER;
				break;
		       }
		}

		count++;

		/* Look for the next ESL */
		esl = esl + eslsize;
		eslvarsize = eslvarsize - eslsize;
		free(data);
		/* Since we are going to allocate again in the next iteration */
		data = NULL;
	}

	if (rc == OPAL_SUCCESS) {
		if (key_equals(key, "PK") && (count > 1)) {
			prlog(PR_ERR, "PK can only be one\n");
			rc = OPAL_PARAMETER;
		} else {
			rc = count;
		}
	}

	free(data);

	prlog(PR_INFO, "Total ESLs are %d\n", rc);
	return rc;
}

/* Get the timestamp for the last update of the give key */
static struct efi_time *get_last_timestamp(const char *key, char *last_timestamp)
{
	struct efi_time *timestamp = (struct efi_time*)last_timestamp;

	if (!last_timestamp)
		return NULL;

	if (key_equals(key, "PK"))
		return &timestamp[0];
	else if (key_equals(key, "KEK"))
		return &timestamp[1];
	else if (key_equals(key, "db"))
		return &timestamp[2];
	else if (key_equals(key, "dbx"))
		return &timestamp[3];
	else
		return NULL;
}

int update_timestamp(const char *key, const struct efi_time *timestamp, char *last_timestamp)
{
	struct efi_time *prev;

	prev = get_last_timestamp(key, last_timestamp);
	if (prev == NULL)
		return OPAL_INTERNAL_ERROR;

	/* Update with new timestamp */
	memcpy(prev, timestamp, sizeof(struct efi_time));

	prlog(PR_DEBUG, "updated prev year is %d month %d day %d\n",
			le16_to_cpu(prev->year), prev->month, prev->day);

	return OPAL_SUCCESS;
}

static uint64_t unpack_timestamp(const struct efi_time *timestamp)
{
	uint64_t val = 0;
	uint16_t year = le16_to_cpu(timestamp->year);

	/* pad1, nanosecond, timezone, daylight and pad2 are meant to be zero */
	val |= ((uint64_t) timestamp->pad1 & 0xFF) << 0;
	val |= ((uint64_t) timestamp->second & 0xFF) << (1*8);
	val |= ((uint64_t) timestamp->minute & 0xFF) << (2*8);
	val |= ((uint64_t) timestamp->hour & 0xFF) << (3*8);
	val |= ((uint64_t) timestamp->day & 0xFF) << (4*8);
	val |= ((uint64_t) timestamp->month & 0xFF) << (5*8);
	val |= ((uint64_t) year) << (6*8);

	return val;
}

int check_timestamp(const char *key, const struct efi_time *timestamp,
		    char *last_timestamp)
{
	struct efi_time *prev;
	uint64_t new;
	uint64_t last;

	prev = get_last_timestamp(key, last_timestamp);
	if (prev == NULL)
		return OPAL_INTERNAL_ERROR;

	prlog(PR_DEBUG, "timestamp year is %d month %d day %d\n",
			le16_to_cpu(timestamp->year), timestamp->month,
			timestamp->day);
	prlog(PR_DEBUG, "prev year is %d month %d day %d\n",
			le16_to_cpu(prev->year), prev->month, prev->day);

	new = unpack_timestamp(timestamp);
	last = unpack_timestamp(prev);

	if (new > last)
		return OPAL_SUCCESS;

	return OPAL_PERMISSION;
}

/* Extract PKCS7 from the authentication header */
static mbedtls_pkcs7* get_pkcs7(const struct efi_variable_authentication_2 *auth)
{
	char *checkpkcs7cert = NULL;
	size_t len;
	mbedtls_pkcs7 *pkcs7 = NULL;
	int rc;

	len = get_pkcs7_len(auth);

	pkcs7 = malloc(sizeof(struct mbedtls_pkcs7));
	if (!pkcs7)
		return NULL;

	mbedtls_pkcs7_init(pkcs7);
	rc = mbedtls_pkcs7_parse_der( auth->auth_info.cert_data, len, pkcs7);
	if (rc <= 0) {
		prlog(PR_ERR, "Parsing pkcs7 failed %04x\n", rc);
		goto out;
	}

	checkpkcs7cert = zalloc(CERT_BUFFER_SIZE);
	if (!checkpkcs7cert)
		goto out;

	rc = mbedtls_x509_crt_info(checkpkcs7cert, CERT_BUFFER_SIZE, "CRT:",
				   &(pkcs7->signed_data.certs));
	if (rc < 0) {
		prlog(PR_ERR, "Failed to parse the certificate in PKCS7 structure\n");
		free(checkpkcs7cert);
		goto out;
	}

	prlog(PR_DEBUG, "%s \n", checkpkcs7cert);
	free(checkpkcs7cert);
	return pkcs7;

out:
	mbedtls_pkcs7_free(pkcs7);
	free(pkcs7);
	pkcs7 = NULL;
	return pkcs7;
}

/* Verify the PKCS7 signature on the signed data. */
static int verify_signature(const struct efi_variable_authentication_2 *auth,
			    const char *hash, const size_t hash_len,
			    const struct secvar *avar)
{
	mbedtls_pkcs7 *pkcs7 = NULL;
	mbedtls_x509_crt x509;
	mbedtls_md_type_t md_alg;
	char *signing_cert = NULL;
	char *x509_buf = NULL;
	int signing_cert_size;
	int rc = 0;
	char *errbuf;
	int eslvarsize;
	int eslsize;
	int offset = 0;

	if (!auth)
		return OPAL_PARAMETER;

	/* Extract the pkcs7 from the auth structure */
	pkcs7 = get_pkcs7(auth);
	/* Failure to parse pkcs7 implies bad input. */
	if (!pkcs7)
		return OPAL_PARAMETER;

	/*
	 * We only support sha256, which has a hash length of 32.
	 * If the alg is not sha256, then we should bail now.
	 */
	rc = mbedtls_oid_get_md_alg(&pkcs7->signed_data.digest_alg_identifiers,
				    &md_alg);
	if (rc != 0) {
		prlog(PR_ERR, "Failed to get the Digest Algorithm Identifier: %d\n", rc);
		rc = OPAL_PARAMETER;
		goto err_pkcs7;
	}

	if (md_alg != MBEDTLS_MD_SHA256) {
		prlog(PR_ERR, "Unexpected digest algorithm: expected %d (SHA-256), got %d\n",
		      MBEDTLS_MD_SHA256, md_alg);
		rc = OPAL_PARAMETER;
		goto err_pkcs7;
	}

	prlog(PR_INFO, "Load the signing certificate from the keystore");

	eslvarsize = avar->data_size;

	/* Variable is not empty */
	while (eslvarsize > 0) {
		prlog(PR_DEBUG, "esl var size is %d offset is %d\n", eslvarsize, offset);
		if (eslvarsize < sizeof(EFI_SIGNATURE_LIST)) {
			rc = OPAL_INTERNAL_ERROR;
			prlog(PR_ERR, "ESL data is corrupted\n");
			break;
		}

		/* Calculate the size of the ESL */
		eslsize = get_esl_signature_list_size(avar->data + offset,
						      eslvarsize);
		/* If could not extract the size */
		if (eslsize <= 0) {
			rc = OPAL_PARAMETER;
			break;
		}

		/* Extract the certificate from the ESL */
		signing_cert_size = get_esl_cert(avar->data + offset,
						 eslvarsize, &signing_cert);
		if (signing_cert_size < 0) {
			rc = signing_cert_size;
			break;
		}

		mbedtls_x509_crt_init(&x509);
		rc = mbedtls_x509_crt_parse(&x509,
					    signing_cert,
					    signing_cert_size);

		/* This should not happen, unless something corrupted in PNOR */
		if(rc) {
			prlog(PR_ERR, "X509 certificate parsing failed %04x\n", rc);
			rc = OPAL_INTERNAL_ERROR;
			break;
		}

		x509_buf = zalloc(CERT_BUFFER_SIZE);
		rc = mbedtls_x509_crt_info(x509_buf,
					   CERT_BUFFER_SIZE,
					   "CRT:",
					   &x509);

		/* This should not happen, unless something corrupted in PNOR */
		if (rc < 0) {
			free(x509_buf);
			rc = OPAL_INTERNAL_ERROR;
			break;
		}

		prlog(PR_INFO, "%s \n", x509_buf);
		free(x509_buf);
		x509_buf = NULL;

		rc = mbedtls_pkcs7_signed_hash_verify(pkcs7, &x509, hash, hash_len);

		/* If you find a signing certificate, you are done */
		if (rc == 0) {
			prlog(PR_INFO, "Signature Verification passed\n");
			mbedtls_x509_crt_free(&x509);
			break;
		} else {
			errbuf = zalloc(MBEDTLS_ERR_BUFFER_SIZE);
			mbedtls_strerror(rc, errbuf, MBEDTLS_ERR_BUFFER_SIZE);
			prlog(PR_ERR, "Signature Verification failed %02x %s\n",
					rc, errbuf);
			free(errbuf);
			rc = OPAL_PERMISSION;
		}


		/* Look for the next ESL */
		offset = offset + eslsize;
		eslvarsize = eslvarsize - eslsize;
		mbedtls_x509_crt_free(&x509);
		free(signing_cert);
		/* Since we are going to allocate again in the next iteration */
		signing_cert = NULL;

	}

	free(signing_cert);
err_pkcs7:
	mbedtls_pkcs7_free(pkcs7);
	free(pkcs7);

	return rc;
}

/* 
 * Create the hash of the buffer
 * name || vendor guid || attributes || timestamp || newcontent
 * which is submitted as signed by the user.
 * Returns the sha256 hash, else NULL.
 */
static char *get_hash_to_verify(const char *key, const char *new_data,
				const size_t new_data_size,
				const struct efi_time *timestamp)
{
	le32 attr = cpu_to_le32(SECVAR_ATTRIBUTES);
	size_t varlen;
	char *wkey;
	uuid_t guid;
	unsigned char *hash = NULL;
	const mbedtls_md_info_t *md_info;
	mbedtls_md_context_t ctx;
	int rc;

	md_info = mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 );
	mbedtls_md_init(&ctx);

	rc = mbedtls_md_setup(&ctx, md_info, 0);
	if (rc)
		goto out;

	rc = mbedtls_md_starts(&ctx);
	if (rc)
		goto out;

	if (key_equals(key, "PK")
	    || key_equals(key, "KEK"))
		guid = EFI_GLOBAL_VARIABLE_GUID;
	else if (key_equals(key, "db")
	    || key_equals(key, "dbx"))
		guid = EFI_IMAGE_SECURITY_DATABASE_GUID;
	else
		return NULL;

	/* Expand char name to wide character width */
	varlen = strlen(key) * 2;
	wkey = char_to_wchar(key, strlen(key));
	rc = mbedtls_md_update(&ctx, wkey, varlen);
	free(wkey);
	if (rc) 
		goto out;

	rc = mbedtls_md_update(&ctx, (const unsigned char *)&guid, sizeof(guid));
	if (rc)
		goto out;

	rc = mbedtls_md_update(&ctx, (const unsigned char *)&attr, sizeof(attr));
	if (rc)
		goto out;

	rc = mbedtls_md_update(&ctx, (const unsigned char *)timestamp,
			       sizeof(struct efi_time));
	if (rc)
		goto out;

	rc = mbedtls_md_update(&ctx, new_data, new_data_size);
	if (rc)
		goto out;

	hash = zalloc(32);
	if (!hash)
		return NULL;
	rc = mbedtls_md_finish(&ctx, hash);
	if (rc) {
		free(hash);
		hash = NULL;
	}

out:
	mbedtls_md_free(&ctx);
	return hash;
}

bool is_pkcs7_sig_format(const void *data)
{
	const struct efi_variable_authentication_2 *auth = data;
	uuid_t pkcs7_guid = EFI_CERT_TYPE_PKCS7_GUID;

	return !memcmp(&auth->auth_info.cert_type, &pkcs7_guid, 16);
}

int process_update(const struct secvar *update, char **newesl,
		   int *new_data_size, struct efi_time *timestamp,
		   struct list_head *bank, char *last_timestamp)
{
	struct efi_variable_authentication_2 *auth = NULL;
	void *auth_buffer = NULL;
	int auth_buffer_size = 0;
	const char *key_authority[3];
	char *hash = NULL;
	struct secvar *avar = NULL;
	int rc = 0;
	int i;

	/* We need to split data into authentication descriptor and new ESL */
	auth_buffer_size = get_auth_descriptor2(update->data,
						update->data_size,
						&auth_buffer);
	if ((auth_buffer_size < 0)
	     || (update->data_size < auth_buffer_size)) {
		prlog(PR_ERR, "Invalid auth buffer size\n");
		rc = auth_buffer_size;
		goto out;
	}

	auth = auth_buffer;

	if (!timestamp) {
		rc = OPAL_INTERNAL_ERROR;
		goto out;
	}

	memcpy(timestamp, auth_buffer, sizeof(struct efi_time));

	rc = check_timestamp(update->key, timestamp, last_timestamp);
	/* Failure implies probably an older command being resubmitted */
	if (rc != OPAL_SUCCESS) {
		prlog(PR_ERR, "Timestamp verification failed for key %s\n", update->key);
		goto out;
	}

	/* Calculate the size of new ESL data */
	*new_data_size = update->data_size - auth_buffer_size;
	if (*new_data_size < 0) {
		prlog(PR_ERR, "Invalid new ESL (new data content) size\n");
		rc = OPAL_PARAMETER;
		goto out;
	}
	*newesl = zalloc(*new_data_size);
	if (!(*newesl)) {
		rc = OPAL_NO_MEM;
		goto out;
	}
	memcpy(*newesl, update->data + auth_buffer_size, *new_data_size);

	/* Validate the new ESL is in right format */
	rc = validate_esl_list(update->key, *newesl, *new_data_size);
	if (rc < 0) {
		prlog(PR_ERR, "ESL validation failed for key %s with error %04x\n",
		      update->key, rc);
		goto out;
	}

	if (setup_mode) {
		rc = OPAL_SUCCESS;
		goto out;
	}

	/* Prepare the data to be verified */
	hash = get_hash_to_verify(update->key, *newesl, *new_data_size,
				timestamp);
	if (!hash) {
		rc = OPAL_INTERNAL_ERROR;
		goto out;
	}

	/* Get the authority to verify the signature */
	get_key_authority(key_authority, update->key);

	/*
	 * Try for all the authorities that are allowed to sign.
	 * For eg. db/dbx can be signed by both PK or KEK
	 */
	for (i = 0; key_authority[i] != NULL; i++) {
		prlog(PR_DEBUG, "key is %s\n", update->key);
		prlog(PR_DEBUG, "key authority is %s\n", key_authority[i]);
		avar = find_secvar(key_authority[i],
				    strlen(key_authority[i]) + 1,
				    bank);
		if (!avar || !avar->data_size)
			continue;

		/* Verify the signature. sha256 is 32 bytes long. */
		rc = verify_signature(auth, hash, 32, avar);

		/* Break if signature verification is successful */
		if (rc == OPAL_SUCCESS) {
			prlog(PR_INFO, "Key %s successfully verified by authority %s\n", update->key, key_authority[i]);
			break;
		}
	}

out:
	free(auth_buffer);
	free(hash);

	return rc;
}
