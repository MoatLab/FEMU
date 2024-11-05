// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2018 IBM Corp. */

#ifndef __STB_CONTAINER_H
#define __STB_CONTAINER_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ccan/short_types/short_types.h>
#include <ccan/endian/endian.h>

#define SECURE_BOOT_HEADERS_SIZE	4096
#define SHA256_DIGEST_LENGTH		32

/*
 * The defines and structures below come from the secure ROM source code
 * (trusted_boot_rom). Here you will find only the ones required by the
 * secure and trusted boot implementation in skiboot.
 */

/* From trusted_boot_rom/src/sha512.h */
#define SHA512_DIGEST_LENGTH  64
typedef uint8_t __attribute__((aligned(8))) sha2_hash_t[ SHA512_DIGEST_LENGTH / sizeof(uint8_t) ];
typedef uint8_t sha2_byte; // Exactly 1 byte

/* From trusted_boot_rom/src/hw_utils.h  */
#define ECID_SIZE	16

/* From trusted_boot_rom/src/ecverify.h   */
#define EC_COORDBYTES	66     /* P-521   */
typedef uint8_t ecc_key_t[2*EC_COORDBYTES];
typedef uint8_t ecc_signature_t[2*EC_COORDBYTES];

/* From trusted_boot_rom/src/ROM.h */
#define ROM_MAGIC_NUMBER	0x17082011

typedef struct {
	be16 version;		/* (1: see versions above) */
	uint8_t hash_alg;	/* (1: SHA-512) */
	uint8_t sig_alg;	/* (1: SHA-512/ECDSA-521) */
}__attribute__((packed)) ROM_version_raw;

typedef struct {
	ROM_version_raw ver_alg;
	be64 code_start_offset;
	be64 reserved;
	be32 flags;
	uint8_t sw_key_count;
	be64 payload_size;
	sha2_hash_t payload_hash;
	uint8_t ecid_count;
	struct { uint8_t ecid[ECID_SIZE]; } ecid[0]; /* optional ecid place
				    holder ecid_count * ecid_size(128 bits) */
	/* followed by prefix data (sig,keys) key raw */
}__attribute__((packed)) ROM_prefix_header_raw;

typedef struct {
	be32 magic_number;	/* (17082011) */
	be16 version;		/* (1: see versions above) */
	be64 container_size;	/* filled by caller */
	be64 target_hrmor;	/* filled by caller */
	be64 stack_pointer;	/* filled by caller */
	/* bottom of stack -> 128k added by rom code to get real stack pointer */
	ecc_key_t hw_pkey_a;
	ecc_key_t hw_pkey_b;
	ecc_key_t hw_pkey_c;
	/* followed by sw header (if not special prefix) */
	/* followed by optional unprotected payload data */
}__attribute__((packed)) ROM_container_raw;

typedef struct {
	ecc_signature_t hw_sig_a;
	ecc_signature_t hw_sig_b;
	ecc_signature_t hw_sig_c;
	ecc_key_t sw_pkey_p;
	ecc_key_t sw_pkey_q;
	ecc_key_t sw_pkey_r;
}__attribute__((packed)) ROM_prefix_data_raw;

typedef struct {
	ROM_version_raw ver_alg;
	be64 code_start_offset;
	be64 reserved;
	be32 flags;
	uint8_t reserved_0;
	be64 payload_size;
	sha2_hash_t payload_hash;
	uint8_t ecid_count;
	struct { uint8_t ecid[ECID_SIZE]; } ecid[0]; /* optional ecid place
				    holder ecid_count * ecid_size(128 bits) */
	/* followed by sw sig raw */
}__attribute__((packed)) ROM_sw_header_raw;

typedef struct {
	ecc_signature_t sw_sig_p;
	ecc_signature_t sw_sig_q;
	ecc_signature_t sw_sig_r;
	/* followed by zero's padding to 4K */
	/* followed by protected sw payload_data */
	/* followed by unprotected sw payload_text */
}__attribute__((packed)) ROM_sw_sig_raw;

typedef enum { ROM_DONE, ROM_FAILED, PHYP_PARTIAL } ROM_response;

typedef struct {
	sha2_hash_t hw_key_hash;
	uint8_t my_ecid[ECID_SIZE];
	be64 entry_point;
	be64 log;
}__attribute__((packed)) ROM_hw_params;

struct parsed_stb_container {
	const void *buf;
	size_t bufsz;
	const ROM_container_raw *c;
	const ROM_prefix_header_raw *ph;
	const ROM_prefix_data_raw *pd;
	const ROM_sw_header_raw *sh;
	const ROM_sw_sig_raw *ssig;
};

/*
 * Helper functions
 */

/* Get the container payload eyecatcher */
uint32_t stb_payload_magic(const void *buf, size_t size);

/* Check if buf is a secure boot container */
bool stb_is_container(const void* buf, size_t size);

/* Get the pointer for the sw-payload-hash field of the container header */
const uint8_t* stb_sw_payload_hash(const void* buf, size_t size);
uint64_t       stb_sw_payload_size(const void *buf, size_t size);

int parse_stb_container(const void* data, size_t len, struct parsed_stb_container *c);

void stb_print_data(const void *data, size_t len);

void getPublicKeyRaw(ecc_key_t *pubkeyraw, char *filename);

void getSigRaw(ecc_signature_t *sigraw, char *filename);

void writeHdr(void *ph, const char *outFile, int hdr_type);

void printBytes(char *lead, unsigned char *buffer, size_t buflen, int wrap);

#endif /* __STB_CONTAINER_H */
