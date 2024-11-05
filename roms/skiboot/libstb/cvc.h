// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2017 IBM Corp. */

#ifndef __CVC_H
#define __CVC_H

enum cvc_service_id {
	CVC_SHA512_SERVICE,
	CVC_VERIFY_SERVICE,
};

void cvc_update_reserved_memory_phandle(void);
int cvc_init(void);

/************************************************************************
 * Wrappers for the services provided by the Container-Verification-Code
 ************************************************************************/

/*
 * call_cvc_verify - Call the CVC-verify service to verify the container fetched
 * from PNOR.
 *
 * @buf - buffer that has the firmware component to be verified
 * @size - number of bytes allocated for @buf
 * @hw_key_hash - hash of the three harware public keys trusted by the platform
 * owner
 * @hw_key_hash_size - number of bytes allocated for @hw_key_hash
 * @log - hexadecimal returned by the CVC. In case of verification failure, it
 * indicates what checking failed
 *
 */
int call_cvc_verify(void *buf, size_t size, const void *hw_key_hash,
		    size_t hw_key_hash_size, __be64 *log);

/*
 * call_cvc_sha512 - Call the CVC-sha512 service to calculate a sha512 hash.
 *
 * @data - buffer that has data to be hashed
 * @data_len - number of bytes from @data to be considered in the hash
 * calculation
 * @digest - buffer to store the calculated hash
 * @digest_size - number of bytes allocated for @digest
 *
 */
int call_cvc_sha512(const uint8_t *data, size_t data_len, uint8_t *digest,
		    size_t digest_size);

#endif /* __CVC_H */
