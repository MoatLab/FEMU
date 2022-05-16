// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2020 IBM Corp. */
#ifndef _SECBOOT_TPM_H_
#define _SECBOOT_TPM_H_

#include <ibmtss/tss.h>

#define SECBOOT_VARIABLE_BANK_SIZE	32000
#define SECBOOT_UPDATE_BANK_SIZE	32000

#define SECBOOT_VARIABLE_BANK_NUM	2

/* Because mbedtls doesn't define this? */
#define SHA256_DIGEST_LENGTH	32

/* 0x5053424b = "PSBK" or Power Secure Boot Keystore */
#define SECBOOT_MAGIC_NUMBER	0x5053424b
#define SECBOOT_VERSION		1

#define SECBOOT_TPMNV_VARS_INDEX	0x01c10190
#define SECBOOT_TPMNV_CONTROL_INDEX	0x01c10191

struct secboot_header {
	uint32_t magic_number;
	uint8_t version;
	uint8_t reserved[3];	/* Fix alignment */
} __attribute__((packed));

struct secboot {
	struct secboot_header header;
	char bank[SECBOOT_VARIABLE_BANK_NUM][SECBOOT_VARIABLE_BANK_SIZE];
	char update[SECBOOT_UPDATE_BANK_SIZE];
} __attribute__((packed));

struct tpmnv_vars {
	struct secboot_header header;
	char vars[0];
} __attribute__((packed));

struct tpmnv_control {
	struct secboot_header header;
	uint8_t active_bit;
	char bank_hash[SECBOOT_VARIABLE_BANK_NUM][SHA256_DIGEST_LENGTH];
} __attribute__((packed));

struct tpmnv_ops_s {
	int (*read)(TPMI_RH_NV_INDEX nv, void*, size_t, uint16_t);
	int (*write)(TPMI_RH_NV_INDEX nv, void*, size_t, uint16_t);
	int (*writelock)(TPMI_RH_NV_INDEX);
	int (*definespace)(TPMI_RH_NV_INDEX, uint16_t);
	int (*getindices)(TPMI_RH_NV_INDEX**, size_t*);
	int (*undefinespace)(TPMI_RH_NV_INDEX);
	int (*readpublic)(TPMI_RH_NV_INDEX, TPMS_NV_PUBLIC*, TPM2B_NAME*);
};

extern struct tpmnv_ops_s tpmnv_ops;

extern const uint8_t tpmnv_vars_name[];
extern const uint8_t tpmnv_control_name[];

#endif
