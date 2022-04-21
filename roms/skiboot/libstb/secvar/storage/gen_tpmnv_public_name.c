#include <mbedtls/sha256.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <ibmtss/TPM_Types.h>
#include <ibmtss/tssmarshal.h>
#include <netinet/in.h>

#define TPM_TPM20
#include "../../tss2/ibmtpm20tss/utils/tssmarshal.c"
#include "../../tss2/ibmtpm20tss/utils/Unmarshal.c"

#define zalloc(a) calloc(1,a)
// Silence linking complaints
int verbose;

#define COPYRIGHT_YEAR "2020"


TPMS_NV_PUBLIC vars = {
	.nvIndex = 0x01c10190,
	.nameAlg = TPM_ALG_SHA256,
	.dataSize = 2048,
	.attributes.val = TPMA_NVA_PPWRITE		|
			  TPMA_NVA_ORDINARY             |
			  TPMA_NVA_WRITE_STCLEAR        |
			  TPMA_NVA_AUTHREAD             |
			  TPMA_NVA_NO_DA                |
			  TPMA_NVA_WRITTEN              |
			  TPMA_NVA_PLATFORMCREATE,
};

TPMS_NV_PUBLIC control = {
	.nvIndex = 0x01c10191,
	.nameAlg = TPM_ALG_SHA256,
	.dataSize = 73,
	.attributes.val = TPMA_NVA_PPWRITE		|
			  TPMA_NVA_ORDINARY             |
			  TPMA_NVA_WRITE_STCLEAR        |
			  TPMA_NVA_AUTHREAD             |
			  TPMA_NVA_NO_DA                |
			  TPMA_NVA_WRITTEN              |
			  TPMA_NVA_PLATFORMCREATE,
};

int calc_hash(TPMS_NV_PUBLIC *public, char *name)
{
	uint16_t written = 0;
	uint32_t size = 4096;
	unsigned char *buffer = zalloc(size);
	unsigned char *buffer_tmp = buffer;
	char output[34];
	mbedtls_sha256_context cxt;
	int ret = 0;
	int i;

	// Output hash includes the hash algorithm in the first two bytes
	*((uint16_t *) output) = htons(public->nameAlg);

	// Serialize the NV Public struct
	ret = TSS_TPMS_NV_PUBLIC_Marshalu(public, &written, &buffer_tmp, &size);
	if (ret) return ret;

	// Hash it
	mbedtls_sha256_init(&cxt);
	ret = mbedtls_sha256_starts_ret(&cxt, 0);
	if (ret) return ret;

	ret = mbedtls_sha256_update_ret(&cxt, buffer, written);
	if (ret) return ret;

	mbedtls_sha256_finish_ret(&cxt, output+2);
	mbedtls_sha256_free(&cxt);

	free(buffer);

	// Print it
	printf("\nconst uint8_t tpmnv_%s_name[] = {", name);
	for (i = 0; i < sizeof(output); i++) {
		if (!(i % 13))
			printf("\n\t");
		printf("0x%02x, ", output[i] & 0xff);
	}
	printf("\n};\n");

	return 0;
}


int main()
{
	printf("// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later\n");
	printf("/* Copyright " COPYRIGHT_YEAR " IBM Corp. */\n");

	printf("#ifndef _SECBOOT_TPM_PUBLIC_NAME_H_\n");
	printf("#define _SECBOOT_TPM_PUBLIC_NAME_H_\n");

	calc_hash(&vars, "vars");
	calc_hash(&control, "control");

	printf("\n");
	printf("#endif\n");

	return 0;
}

