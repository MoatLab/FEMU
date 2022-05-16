/*****************************************************************************
 * Copyright (c) 2015-2020 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#ifndef TCGBIOS_INT_H
#define TCGBIOS_INT_H

#include <stdint.h>

/* internal error codes */
#define TCGBIOS_OK                       0x0
#define TCGBIOS_LOGOVERFLOW              0x1
#define TCGBIOS_GENERAL_ERROR            0x2
#define TCGBIOS_FIRMWARE_ERROR           0x3
#define TCGBIOS_FATAL_COM_ERROR          0x4
#define TCGBIOS_INVALID_INPUT_PARA       0x5
#define TCGBIOS_COMMAND_ERROR            0x6
#define TCGBIOS_INTERFACE_SHUTDOWN       0x7

/*
 * event types from spec:
 * TCG PC Client Specific Implementation Specification
 * for Conventional BIOS
 */
#define EV_POST_CODE                     1
#define EV_NO_ACTION                     3
#define EV_SEPARATOR                     4
#define EV_ACTION                        5
#define EV_EVENT_TAG                     6
#define EV_S_CRTM_CONTENTS               7
#define EV_S_CRTM_VERSION                8
#define EV_IPL                          13
#define EV_IPL_PARTITION_DATA           14
#define EV_EFI_EVENT_BASE               0x80000000
#define EV_EFI_GPT_EVENT                (EV_EFI_EVENT_BASE + 0x6)

#define BCV_DEVICE_HDD                  0x80

/* hash sizes */
#define SHA1_BUFSIZE                    20
#define SHA256_BUFSIZE                  32
#define SHA384_BUFSIZE                  48
#define SHA512_BUFSIZE                  64
#define SM3_256_BUFSIZE                 32
#define SHA3_256_BUFSIZE		32
#define SHA3_384_BUFSIZE		48
#define SHA3_512_BUFSIZE		64

/*
 * Logging for TPM 2 is specified in TCG spec "TCG PC Client Platform
 * Firmware Profile Specification" in section "Event Logging" and sub-
 * section "TCG_PCR_EVENT2 structure"
 *
 * Each entry in the TPM log contains: a TCG_PCR_EVENT2_Header, a variable
 * length digest, a TCG_PCR_EVENT2_Trailer, and a variable length event.
 * The 'digest' matches what is sent to the TPM hardware via the Extend
 * command. On TPM2.0 the digest contains a TPML_DIGEST_VALUES struct
 * followed by a variable number of TPMT_HA structs (as specified by the
 * hardware via the TPM2_CAP_PCRS request).
 */
typedef struct tdTCG_PCR_EVENT2_Header {
	uint32_t pcrindex;
	uint32_t eventtype;
	uint8_t digests[0];
} __attribute__((packed)) TCG_PCR_EVENT2_Header;

typedef struct tdTCG_PCR_EVENT2_Trailer {
	uint32_t eventdatasize;
	uint8_t event[0];
} __attribute__((packed)) TCG_PCR_EVENT2_Trailer;

struct TCG_EfiSpecIdEventStruct {
	uint8_t signature[16];
	uint32_t platformClass;
#define TPM_TCPA_ACPI_CLASS_CLIENT 0
	uint8_t specVersionMinor;
	uint8_t specVersionMajor;
	uint8_t specErrata;
	uint8_t uintnSize;
	uint32_t numberOfAlgorithms;
	struct TCG_EfiSpecIdEventAlgorithmSize {
		uint16_t algorithmId;
		uint16_t digestSize;
	} digestSizes[];
	/*
	uint8_t vendorInfoSize;
	uint8_t vendorInfo[0];
	*/
} __attribute__((packed));

/* EFI related data structures for logging */
typedef struct {
	uint64_t signature;
	uint32_t revision;
	uint32_t size;
	uint32_t crc32;
	uint8_t reserved[4];
} __attribute__((packed)) UEFI_TABLE_HEADER;

typedef struct {
	UEFI_TABLE_HEADER header;
	uint64_t currentLba;
	uint64_t backupLba;
	uint64_t firstLba;
	uint64_t lastLba;
	uint8_t  diskGuid[16];
	uint64_t partEntryLba;
	uint32_t numPartEntry;
	uint32_t partEntrySize;
	uint32_t partArrayCrc32;
	uint8_t reserved[420];
} __attribute__((packed)) UEFI_PARTITION_TABLE_HEADER;

typedef struct {
	uint8_t partTypeGuid[16];
	uint8_t partGuid[16];
	uint64_t firstLba;
	uint64_t lastLba;
	uint64_t attribute;
	uint8_t partName[72];
} __attribute__((packed)) UEFI_PARTITION_ENTRY;

typedef struct {
    UEFI_PARTITION_TABLE_HEADER EfiPartitionHeader;
    uint64_t                    NumberOfPartitions;
    UEFI_PARTITION_ENTRY        Partitions[0];
} __attribute__((packed)) UEFI_GPT_DATA;

/* Input and Output headers for all TPM commands */
struct tpm_req_header {
	uint16_t tag;
	uint32_t totlen;
	uint32_t ordinal;
} __attribute__((packed));

struct tpm_rsp_header {
	uint16_t tag;
	uint32_t totlen;
	uint32_t errcode;
} __attribute__((packed));

/****************************************************************
 * TPM v2.0 hardware commands
 *
 * Relevant specs for #defines and commonly used structures:
 * - Trusted Platform Module Library; Part 2: Structures
 * Relevant specs for command structures:
 * - Trusted Platform Module Library; Part 3: Commands
 ****************************************************************/

#define TPM2_NO                     0
#define TPM2_YES                    1

#define TPM2_SU_CLEAR               0x0000
#define TPM2_SU_STATE               0x0001

#define TPM2_RH_OWNER               0x40000001
#define TPM2_RS_PW                  0x40000009
#define TPM2_RH_ENDORSEMENT         0x4000000b
#define TPM2_RH_PLATFORM            0x4000000c

#define TPM2_ALG_SHA1               0x0004
#define TPM2_ALG_SHA256             0x000b
#define TPM2_ALG_SHA384             0x000c
#define TPM2_ALG_SHA512             0x000d
#define TPM2_ALG_SM3_256            0x0012
#define TPM2_ALG_SHA3_256           0x0027
#define TPM2_ALG_SHA3_384           0x0028
#define TPM2_ALG_SHA3_512           0x0029

/* TPM 2 command tags */
#define TPM2_ST_NO_SESSIONS         0x8001
#define TPM2_ST_SESSIONS            0x8002

/* TPM 2 commands */
#define TPM2_CC_HierarchyControl    0x121
#define TPM2_CC_Clear               0x126
#define TPM2_CC_ClearControl        0x127
#define TPM2_CC_HierarchyChangeAuth 0x129
#define TPM2_CC_PCR_Allocate        0x12b
#define TPM2_CC_SelfTest            0x143
#define TPM2_CC_Startup             0x144
#define TPM2_CC_Shutdown            0x145
#define TPM2_CC_StirRandom          0x146
#define TPM2_CC_GetCapability       0x17a
#define TPM2_CC_GetRandom           0x17b
#define TPM2_CC_PCR_Extend          0x182

/* TPM 2 Capabilities */
#define TPM2_CAP_PCRS               0x00000005

/* TPM 2 data structures */

struct TPMT_HA {
	uint16_t hashAlg;
	uint8_t hash[0]; /* size depends on hashAlg */
} __attribute__((packed));

struct TPML_DIGEST_VALUES {
	uint32_t count;
	struct TPMT_HA digest[0]; /* variable number of entries */
} __attribute__((packed));

struct tpm2_req_stirrandom {
	struct tpm_req_header hdr;
	uint16_t size;
	uint64_t stir;
} __attribute__((packed));

struct tpm2_req_getrandom {
	struct tpm_req_header hdr;
	uint16_t bytesRequested;
} __attribute__((packed));

struct tpm2b_20 {
	uint16_t size;
	uint8_t buffer[20];
} __attribute__((packed));

struct tpm2_res_getrandom {
	struct tpm_rsp_header hdr;
	struct tpm2b_20 rnd;
} __attribute__((packed));

/*
 * tpm2_authblock is used in TPM 2 commands using 'Auth. Handle'
 */
struct tpm2_authblock {
	uint32_t handle;
	uint16_t noncesize;  /* always 0 */
	uint8_t contsession; /* always TPM2_YES */
	uint16_t pwdsize;    /* always 0 */
} __attribute__((packed));

struct tpm2_req_hierarchychangeauth {
	struct tpm_req_header hdr;
	uint32_t authhandle;
	uint32_t authblocksize;
	struct tpm2_authblock authblock;
	struct tpm2b_20 newAuth;
} __attribute__((packed));

struct tpm2_req_extend {
	struct tpm_req_header hdr;
	uint32_t pcrindex;
	uint32_t authblocksize;
	struct tpm2_authblock authblock;
	uint8_t digest[0];
} __attribute__((packed));

struct tpm2_req_clearcontrol {
	struct tpm_req_header hdr;
	uint32_t authhandle;
	uint32_t authblocksize;
	struct tpm2_authblock authblock;
	uint8_t disable;
} __attribute__((packed));

struct tpm2_req_clear {
	struct tpm_req_header hdr;
	uint32_t authhandle;
	uint32_t authblocksize;
	struct tpm2_authblock authblock;
} __attribute__((packed));

struct tpm2_req_hierarchycontrol {
	struct tpm_req_header hdr;
	uint32_t authhandle;
	uint32_t authblocksize;
	struct tpm2_authblock authblock;
	uint32_t enable;
	uint8_t state;
} __attribute__((packed));

struct tpm2_req_getcapability {
	struct tpm_req_header hdr;
	uint32_t capability;
	uint32_t property;
	uint32_t propertycount;
} __attribute__((packed));

struct tpm2_res_getcapability {
	struct tpm_rsp_header hdr;
	uint8_t moreData;
	uint32_t capability;
	uint8_t data[0]; /* capability dependent data */
} __attribute__((packed));

struct tpm2_req_pcr_allocate {
	struct tpm_req_header hdr;
	uint32_t authhandle;
	uint32_t authblocksize;
	struct tpm2_authblock authblock;
	uint32_t count;
	uint8_t tpms_pcr_selections[4];
} __attribute__((packed));

struct tpms_pcr_selection {
	uint16_t hashAlg;
	uint8_t sizeOfSelect;
	uint8_t pcrSelect[0];
} __attribute__((packed));

struct tpml_pcr_selection {
	uint32_t count;
	struct tpms_pcr_selection selections[0];
} __attribute__((packed));

#endif /* TCGBIOS_INT_H */
