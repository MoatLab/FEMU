// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2020 IBM Corp. */

#ifndef TSSSKIBOOT_H
#define TSSSKIBOOT_H

#include <ibmtss/tss.h>

#define TSS_AUTH_PASSWD_LEN 32
int tss_nv_read_public(TPMI_RH_NV_INDEX nv_index, TPMS_NV_PUBLIC *nv_public,
		       TPM2B_NAME *nv_name);
int tss_nv_read(TPMI_RH_NV_INDEX nv_index, void *buffer, size_t buffer_size,
		uint16_t offset);
int tss_nv_write(TPMI_RH_NV_INDEX nv_index, void *buffer, size_t buffer_size,
		 uint16_t offset);
int tss_nv_write_lock(TPMI_RH_NV_INDEX nv_index);
int tss_nv_define_space(TPMI_RH_NV_INDEX nv_index, uint16_t data_size);
int tss_pcr_extend(TPMI_DH_PCR pcr_handle, TPMI_ALG_HASH *alg_hashes,
		   uint8_t hashes_count, const uint8_t **digests);
int tss_pcr_read(TPMI_DH_PCR pcr_handle, TPMI_ALG_HASH *alg_hashes,
		 uint8_t hashes_count);
int tss_get_random_number(void *buffer, uint16_t bytes_requested);
int tss_set_platform_auth(void);
int tss_get_defined_nv_indices(TPMI_RH_NV_INDEX **indices, size_t *count);
int tss_nv_undefine_space(TPMI_RH_NV_INDEX nv_index);
#endif /* TSSSKIBOOT_H */
