// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2020 IBM Corp. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <skiboot.h>
#include <opal-api.h>
#include <tssskiboot.h>
#include <tpm_chip.h>
#include <ibmtss/tssfile.h>
#include <ibmtss/TPM_Types.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tssresponsecode.h>

#define TSS_MAX_NV_BUFFER_SIZE 1024

/*
 * Helper to string-fy TSS error response codes.
 */
static void tss_error_trace(const char *function, TPM_RC rc)
{
	const char *msg;
	const char *submsg;
	const char *num;
	prlog(PR_ERR, "%s: failed, rc %08x\n", function, rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	prlog(PR_ERR, "%s%s%s\n", msg, submsg, num);
}

/*
 * @brief Reads the public and name area of a NV Index.
 * @param nv_index 		The target NV index to read public info from.
 * @param nv_public		buffer to save public are read from nv index
 * @param nv_name		buffer to save nv index name.
 */
int tss_nv_read_public(TPMI_RH_NV_INDEX nv_index, TPMS_NV_PUBLIC *nv_public,
		       TPM2B_NAME *nv_name)
{
	NV_ReadPublic_Out *out = NULL;
	NV_ReadPublic_In *in = NULL;
	TSS_CONTEXT *context = NULL;
	TPM_RC rc = OPAL_SUCCESS;

	if (!nv_public || !nv_name) {
		rc = OPAL_PARAMETER;
		goto cleanup;
	}

	in = zalloc(sizeof(NV_ReadPublic_In));
	if (!in) {
		rc = OPAL_NO_MEM;
		goto cleanup;
	}

	out = zalloc(sizeof(NV_ReadPublic_Out));
	if (!out) {
		rc = OPAL_NO_MEM;
		goto cleanup;
	}

	rc = TSS_Create(&context);
	if (rc) {
		tss_error_trace("tss_nv_read_public", rc);
		rc = OPAL_NO_MEM;
		goto cleanup;
	}

	in->nvIndex = nv_index;
	rc = TSS_Execute(context,
			 (RESPONSE_PARAMETERS *) out,
			 (COMMAND_PARAMETERS *) in,
			 NULL,
			 TPM_CC_NV_ReadPublic,
			 TPM_RH_NULL, NULL, 0);
	if (!rc) {
		memcpy(nv_public, &out->nvPublic, sizeof(TPMS_NV_PUBLIC));
		memcpy(nv_name, &out->nvName, sizeof(TPM2B_NAME));
	}
	else
		tss_error_trace("tss_nv_read_public", rc);
cleanup:
	free(in);
	free(out);
	TSS_Delete(context);
	return rc;
}

/* @brief This command reads a value from an area previously defined using
 * nv_define_space
 * @param nv_index 		The target NV index to read from.
 * @param buffer		buffer to save the data read.
 * @param buffer_size		size of the buffer, to avoid overflow.
 * @param offset		position where to start the nv read operation.
 */
int tss_nv_read(TPMI_RH_NV_INDEX nv_index, void *buffer,
		size_t buffer_size, uint16_t offset)
{
	TSS_CONTEXT *context = NULL;
	NV_Read_Out *out = NULL;
	NV_Read_In *in = NULL;
	TPM_RC rc = OPAL_SUCCESS;
	int64_t buffer_remaining;

	if (!buffer) {
		rc = OPAL_PARAMETER;
		goto cleanup;
	}

	in = zalloc(sizeof(NV_Read_In));
	if (!in) {
		rc = OPAL_NO_MEM;
		goto cleanup;
	}

	out = zalloc(sizeof(NV_Read_Out));
	if (!out) {
		rc = OPAL_NO_MEM;
		goto cleanup;
	}

	rc = TSS_Create(&context);
	if (rc) {
		tss_error_trace("tss_nv_read", rc);
		rc = OPAL_NO_MEM;
		goto cleanup;
	}

	in->nvIndex = nv_index;
	in->authHandle = nv_index;

	buffer_remaining = buffer_size;
	while (buffer_remaining > 0) {
		in->offset = offset;
		in->size = MIN(TSS_MAX_NV_BUFFER_SIZE, buffer_remaining);

		rc = TSS_Execute(context,
				 (RESPONSE_PARAMETERS *) out,
				 (COMMAND_PARAMETERS *) in,
				 NULL,
				 TPM_CC_NV_Read,
				 TPM_RS_PW, NULL, 0,
				 TPM_RH_NULL, NULL, 0);

		if (rc) {
			tss_error_trace("tss_nv_read", rc);
			goto cleanup;
		}

		memcpy(buffer, out->data.b.buffer, in->size);
		buffer += TSS_MAX_NV_BUFFER_SIZE;
		buffer_remaining -= TSS_MAX_NV_BUFFER_SIZE;
		offset += TSS_MAX_NV_BUFFER_SIZE;
	}

cleanup:
	TSS_Delete(context);
	free(in);
	free(out);
	return rc;
}

/* @brief This command writes a value in an area previously defined using
 * nv_define_space
 * @param nv_index 		The target NV index to write to.
 * @param buffer		buffer containing the data write.
 * @param buffer_size		size of the buffer to write.
 * @param offset		position where to start the nv write operation.
 */
int tss_nv_write(TPMI_RH_NV_INDEX nv_index, void *buffer,
		 size_t buffer_size, uint16_t offset)
{
	TSS_CONTEXT *context = NULL;
	NV_Write_In *in = NULL;
	TPM_RC rc = OPAL_SUCCESS;
	int64_t buffer_remaining;

	if (!buffer) {
		rc = OPAL_PARAMETER;
		goto cleanup;
	}

	in = zalloc(sizeof(NV_Write_In));
	if (!in) {
		rc = OPAL_NO_MEM;
		goto cleanup;
	}

	rc = TSS_Create(&context);
	if (rc) {
		tss_error_trace("tss_nv_write", rc);
		rc = OPAL_NO_MEM;
		goto cleanup;
	}

	in->nvIndex = nv_index;
	in->authHandle = TPM_RH_PLATFORM;

	buffer_remaining = buffer_size;
	while (buffer_remaining > 0) {
		in->offset = offset;
		rc = TSS_TPM2B_Create(&in->data.b, buffer,
				      MIN(TSS_MAX_NV_BUFFER_SIZE, buffer_remaining),
				      sizeof(in->data.t.buffer));

		if (rc) {
			tss_error_trace("tss_nv_write", rc);
			goto cleanup;
		}

		rc = TSS_Execute(context,
				 NULL,
				 (COMMAND_PARAMETERS *) in,
				 NULL,
				 TPM_CC_NV_Write,
				 TPM_RS_PW, NULL, 0,
				 TPM_RH_NULL, NULL, 0);
		if (rc) {
			tss_error_trace("tss_nv_write", rc);
			goto cleanup;
		}

		buffer += TSS_MAX_NV_BUFFER_SIZE;
		buffer_remaining -= TSS_MAX_NV_BUFFER_SIZE;
		offset += TSS_MAX_NV_BUFFER_SIZE;
	}

cleanup:
	TSS_Delete(context);
	free(in);
	return rc;
}

/*
 * @brief This command locks an area, pointed by the index and previously
 * defined using nv_define_space, preventing further writing operations on it.
 * @param nv_index 		The target NV index to lock.
 */
int tss_nv_write_lock(TPMI_RH_NV_INDEX nv_index)
{
	TSS_CONTEXT *context = NULL;
	NV_WriteLock_In *in = NULL;
	TPM_RC rc = OPAL_SUCCESS;

	in = zalloc(sizeof(NV_WriteLock_In));
	if (!in) {
		rc = OPAL_NO_MEM;
		goto cleanup;
	}

	rc = TSS_Create(&context);
	if (rc) {
		rc = OPAL_NO_MEM;
		goto cleanup;
	}

	in->authHandle = TPM_RH_PLATFORM;
	in->nvIndex = nv_index;
	rc = TSS_Execute(context,
			 NULL,
			 (COMMAND_PARAMETERS *) in,
			 NULL,
			 TPM_CC_NV_WriteLock,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
	if (rc)
		tss_error_trace("tss_nv_write_lock", rc);
cleanup:
	TSS_Delete(context);
	free(in);
	return rc;
}

 /*
 * @brief This command defines the area pointed by nv index and its attributes.
 * @param nv_index 		The target NV index to define.
 * @param data_size		size of the area to be defined.
 */
int tss_nv_define_space(TPMI_RH_NV_INDEX nv_index, uint16_t data_size)
{
	NV_DefineSpace_In *in = NULL;
	TSS_CONTEXT *context = NULL;
	TPM_RC rc = OPAL_SUCCESS;

	in = zalloc(sizeof(NV_DefineSpace_In));
	if (!in) {
		rc = OPAL_NO_MEM;
		goto cleanup;
	}

	rc = TSS_Create(&context);
	if (rc) {
		rc = OPAL_NO_MEM;
		goto cleanup;
	}

	in->authHandle = TPM_RH_PLATFORM;

	in->publicInfo.nvPublic.nvIndex = nv_index;
	in->publicInfo.nvPublic.dataSize = data_size;
	/* password is NULL so b.size is 0 */
	in->auth.b.size = 0;
	/* Empty policy, so size is 0 */
	in->publicInfo.nvPublic.authPolicy.t.size = 0;
	/* Used algorithm is SHA256 */
	in->publicInfo.nvPublic.nameAlg = TPM_ALG_SHA256;
	/*
	 * This carries the flags set according to default settings, excepting
	 * for what is set by this function parameters. Further customization
	 * will require a different setup for nvAttribute flags as is done in
	 * TSS's code.
	 */
	in->publicInfo.nvPublic.attributes.val = (TPMA_NVA_PPWRITE |
						  TPMA_NVA_ORDINARY |
						  TPMA_NVA_WRITE_STCLEAR |
						  TPMA_NVA_AUTHREAD |
						  TPMA_NVA_PLATFORMCREATE |
						  TPMA_NVA_NO_DA);

	rc = TSS_Execute(context,
			 NULL,
			 (COMMAND_PARAMETERS *)in,
			 NULL,
			 TPM_CC_NV_DefineSpace,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
	if (rc) {
		tss_error_trace("tss_nv_define_space", rc);
		switch(rc) {
			case TPM_RC_NV_DEFINED:
				rc = OPAL_WRONG_STATE;
				break;
			default:
				break;
		}
	}
cleanup:
	TSS_Delete(context);
	free(in);
	return rc;
}

/*
 * @brief Extends a PCR using the given hashes and digest
 * @param pcr_handle		The PCR to be extended
 * @param alg_hashes		A pointer to an array of hash algorithms, each
 * 				one used to extend its respective PCR bank.
 * @param alg_hash_count	The number of elements in alg_hashes array
 * @param digests		The digest data.
 */
int tss_pcr_extend(TPMI_DH_PCR pcr_handle, TPMI_ALG_HASH *alg_hashes,
		   uint8_t alg_hash_count, const uint8_t **digests)
{
	TSS_CONTEXT *context = NULL;
	uint32_t rc = OPAL_SUCCESS;
	PCR_Extend_In *in = NULL;
	uint16_t digest_size;

	if (!alg_hashes || !digests || pcr_handle >= IMPLEMENTATION_PCR) {
		rc = OPAL_PARAMETER;
		goto cleanup;
	}

	in = zalloc(sizeof(PCR_Extend_In));
	if (!in) {
		rc = OPAL_NO_MEM;
		goto cleanup;
	}

	rc = TSS_Create(&context);
	if (rc) {
		tss_error_trace("tss_pcr_extend", rc);
		rc = OPAL_NO_MEM;
		goto cleanup;
	}

	if (alg_hash_count >= HASH_COUNT) {
		rc = OPAL_PARAMETER;
		goto cleanup;
	}

	in->digests.count = alg_hash_count;
	in->pcrHandle = pcr_handle;
	for (uint8_t i=0; i < alg_hash_count; i++) {
		in->digests.digests[i].hashAlg = alg_hashes[i];
		/* memset zeroes first to assure the digest data is zero
		 * padded.*/
		memset((uint8_t*) &in->digests.digests[i].digest, 0,
		       sizeof(TPMU_HA));

		digest_size = 0;
		/* Marshal the digest in order to obtain its size. This is a
		 * commonly used pattern in TSS.
		 */
		rc = TSS_TPMU_HA_Marshalu((const TPMU_HA *)digests[i],
					  &digest_size, NULL, NULL ,
					  alg_hashes[i]);
		if (rc)
			goto cleanup;
		memcpy((uint8_t*) &in->digests.digests[i].digest, digests[i],
		       digest_size);
	}
	rc = TSS_Execute(context,
			 NULL,
			 (COMMAND_PARAMETERS *) in,
			 NULL,
			 TPM_CC_PCR_Extend,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
	if (rc)
		tss_error_trace("tss_pcr_extend", rc);
cleanup:
	TSS_Delete(context);
	free(in);
	return rc;
}

/*
 * @brief reads pcr values of a given pcr handle.
 * @param pcr_handle		The PCR to be extended
 * @param alg_hashes		A pointer to an array of hash algorithms, each
 * 				one used to extend its respective PCR bank.
 * @param alg_hash_count	The length of alg hashes array
 */
int tss_pcr_read(TPMI_DH_PCR pcr_handle, TPMI_ALG_HASH *alg_hashes,
		 uint8_t alg_hash_count)
{
	TSS_CONTEXT *context = NULL;
	PCR_Read_Out *out = NULL;
	PCR_Read_In *in = NULL;
	uint32_t rc = OPAL_SUCCESS;

	if (!alg_hashes) {
		rc = OPAL_PARAMETER;
		goto cleanup;
	}

	in = zalloc(sizeof(PCR_Read_In));
	if (!in) {
		rc = OPAL_NO_MEM;
		goto cleanup;
	}

	out = zalloc(sizeof(PCR_Read_Out));
	if (!out) {
		rc = OPAL_NO_MEM;
		goto cleanup;
	}

	rc = TSS_Create(&context);
	if (!rc) {
		tss_error_trace("tss_pcr_read", rc);
		rc = OPAL_NO_MEM;
		goto cleanup;
	}

	in->pcrSelectionIn.count = alg_hash_count;
	for (int i=0; i < alg_hash_count; i++) {
		in->pcrSelectionIn.pcrSelections[i].hash = alg_hashes[i];
		in->pcrSelectionIn.pcrSelections[i].sizeofSelect = 3;
		in->pcrSelectionIn.pcrSelections[i].pcrSelect[0] = 0;
		in->pcrSelectionIn.pcrSelections[i].pcrSelect[1] = 0;
		in->pcrSelectionIn.pcrSelections[i].pcrSelect[2] = 0;
		in->pcrSelectionIn.pcrSelections[i].pcrSelect[pcr_handle/8] = 1 << (pcr_handle % 8);
	}

	rc = TSS_Execute(context,
			 (RESPONSE_PARAMETERS *) out,
			 (COMMAND_PARAMETERS *) in,
			 NULL,
			 TPM_CC_PCR_Read,
			 TPM_RH_NULL, NULL, 0);
	if (rc)
		tss_error_trace("tss_pcr_read", rc);
cleanup:
	TSS_Delete(context);
	free(in);
	free(out);
	return rc;
}

/*
 * @brief returns next bytes_requested bytes from the TPM RNG
 * @param buffer		Buffer to save the generated numbers.
 * @param bytes_requested	How many random bytes are requested.
 */
int tss_get_random_number(void *buffer, uint16_t bytes_requested)
{
	TSS_CONTEXT *context = NULL;
	GetRandom_Out *out = NULL;
	TPM_RC rc = OPAL_SUCCESS;
	GetRandom_In *in = NULL;
	void *p_buffer = buffer;

	if (!buffer) {
		rc = OPAL_PARAMETER;
		goto cleanup;
	}

	in = zalloc(sizeof(GetRandom_In));
	if (!in) {
		rc = OPAL_NO_MEM;
		goto cleanup;
	}

	out = zalloc(sizeof(GetRandom_Out));
	if (!out) {
		rc = OPAL_NO_MEM;
		goto cleanup;
	}

	rc = TSS_Create(&context);
	if (rc) {
		tss_error_trace("tss_get_random_number", rc);
		rc = OPAL_NO_MEM;
		goto cleanup;
	}

	/*
	 * Even though we request a specific number of bytes, there is no
	 * guarantee that TPM will return that number of bytes, so we ask again
	 * until we reach the desired total of bytes or rng function fails
	 */
	for (uint16_t bytes_copied = 0; bytes_copied < bytes_requested; ) {
		in->bytesRequested = bytes_requested - bytes_copied;
		rc = TSS_Execute(context,
				 (RESPONSE_PARAMETERS *)out,
				 (COMMAND_PARAMETERS *)in,
				 NULL, TPM_CC_GetRandom,
				 TPM_RH_NULL, NULL, 0);
		if (!rc){
			memcpy(p_buffer, out->randomBytes.t.buffer,
			       out->randomBytes.t.size);
			bytes_copied += out->randomBytes.t.size;
			p_buffer += bytes_copied;
			/* explicitly clean up output's buffer from memory on
			 * every iteration, since the size will vary, to avoid
			 * some kind of exploitation.
			 */
			memset(out->randomBytes.t.buffer, 0,
			       out->randomBytes.t.size);

		}
		else {
			tss_error_trace("tss_get_random_number", rc);
			break;
		}
	}

cleanup:
	TSS_Delete(context);
	free(in);
	free(out);
	return rc;
}

/* local helper to generate random password without zeroes */
static int generate_random_passwd(char *passwd, uint16_t passwd_len)
{
	TPM_RC rc = OPAL_SUCCESS;
	char *buffer = NULL;
	int bytes_copied;
	int i;

	buffer = zalloc(passwd_len);
	if (!buffer) {
		rc = OPAL_NO_MEM;
		goto cleanup;
	}

	bytes_copied = 0;
	while ((rc == 0) && (bytes_copied < passwd_len)) {
		rc = tss_get_random_number(buffer, passwd_len);
		if (rc)
			goto cleanup;

		/* Copy as many bytes as were received or until bytes requested */
		for (i = 0; (i < passwd_len) &&
			    (bytes_copied < passwd_len); i++) {

			/* Skip zero bytes */
			if (buffer[i] == 0)
				continue;
			passwd[bytes_copied] = buffer[i];
			bytes_copied++;
		}
	}
cleanup:
	free(buffer);
	return rc;
}

/*
 * @brief This command allows the authorization secret for a hierarchy to be
 * changed.
 */
int tss_set_platform_auth(void)
{
	HierarchyChangeAuth_In *in =  NULL;
	TSS_CONTEXT *context = NULL;
	TPM_RC rc = OPAL_SUCCESS;
	char *key_passwd = NULL;

	in = zalloc(sizeof(HierarchyChangeAuth_In));
	if (!in) {
		rc = OPAL_NO_MEM;
		goto cleanup;
	}

	key_passwd = zalloc(TSS_AUTH_PASSWD_LEN + 1);
	if (!key_passwd) {
		rc = OPAL_NO_MEM;
		goto cleanup;
	}

	rc = TSS_Create(&context);
	if (rc) {
		tss_error_trace("tss_set_platform_auth", rc);
		rc = OPAL_NO_MEM;
		goto cleanup;
	}

	rc = generate_random_passwd(key_passwd,	TSS_AUTH_PASSWD_LEN);
	if (rc) {
		tss_error_trace("Failed to generate the auth password", rc);
		goto cleanup;
	}
	key_passwd[TSS_AUTH_PASSWD_LEN] = 0;

	in->authHandle = TPM_RH_PLATFORM;
	rc = TSS_TPM2B_StringCopy(&in->newAuth.b, key_passwd,
				  sizeof(in->newAuth.t.buffer));
	if (rc) {
		tss_error_trace("tss_set_platform_auth", rc);
		goto cleanup;
	}

	rc = TSS_Execute(context,
			 NULL,
			 (COMMAND_PARAMETERS *)in,
			 NULL,
			 TPM_CC_HierarchyChangeAuth,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
	if (rc)
		tss_error_trace("tss_set_platform_auth", rc);

cleanup:
	TSS_Delete(context);
	free(in);
	/* explicitly clean up password from memory to avoid some kind of
	* exploitation.
	*/
	memset(key_passwd, 0, TSS_AUTH_PASSWD_LEN + 1);
	free(key_passwd);
	return rc;
}

/*
 * @brief returns a list of defined NV indices
 * @param pcr_handle		The PCR to be extended
 * @param alg_hashes		A pointer to an array of hash algorithms, each
 * 				one used to extend its respective PCR bank.
 * @param alg_hash_count	The length of alg hashes array
 */
int tss_get_defined_nv_indices(TPMI_RH_NV_INDEX **indices, size_t *count)
{
	TSS_CONTEXT *context = NULL;
	GetCapability_In *in = NULL;
	GetCapability_Out *out = NULL;
	uint32_t rc = OPAL_SUCCESS;
	TPML_HANDLE *handles;

	in = zalloc(sizeof(GetCapability_In));
	if (!in) {
	        rc = OPAL_NO_MEM;
		goto cleanup;
	}

	out = zalloc(sizeof(GetCapability_Out));
	if (!out) {
		rc = OPAL_NO_MEM;
		goto cleanup;
	}

	rc = TSS_Create(&context);
	if (rc) {
		tss_error_trace("tss_check_nv_index", rc);
		rc = OPAL_NO_MEM;
		goto cleanup;
	}

	in->capability = 1;
	in->property = 0x01000000;
	in->propertyCount = 64;

	rc = TSS_Execute(context,
			 (RESPONSE_PARAMETERS *) out,
			 (COMMAND_PARAMETERS *) in,
			 NULL,
			 TPM_CC_GetCapability,
			 TPM_RH_NULL, NULL, 0);
	if (rc) {
		tss_error_trace("tss_check_nv_index", rc);
		goto cleanup;
	}

	handles = (TPML_HANDLE *) &out->capabilityData.data;
	*count = handles->count;
	*indices = malloc(*count * sizeof(TPMI_RH_NV_INDEX));
	if (!indices) {
		rc = OPAL_NO_MEM;
		goto cleanup;
	}

	memcpy(*indices, handles->handle, *count * sizeof(TPMI_RH_NV_INDEX));

cleanup:
	TSS_Delete(context);
	free(in);
	free(out);
	return rc;
}


int tss_nv_undefine_space(TPMI_RH_NV_INDEX nv_index)
{
	int rc;
	TSS_CONTEXT *context = NULL;
	NV_UndefineSpace_In in;

	rc = TSS_Create(&context);
	if (rc) {
		tss_error_trace("tss_check_nv_undefine_index", rc);
		rc = OPAL_NO_MEM;
		return rc;
	}

	in.authHandle = TPM_RH_PLATFORM;
	in.nvIndex = nv_index;

	rc = TSS_Execute(context, NULL,
			 (COMMAND_PARAMETERS *) &in,
			 NULL,
			 TPM_CC_NV_UndefineSpace,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
	if (rc)
		tss_error_trace("tss_check_nv_index", rc);

	TSS_Delete(context);
	return rc;
}
