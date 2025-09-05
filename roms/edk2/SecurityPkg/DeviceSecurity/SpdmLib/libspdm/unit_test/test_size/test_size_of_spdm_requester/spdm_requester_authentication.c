/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_requester.h"

/**
 * This function sends GET_DIGEST, GET_CERTIFICATE, CHALLENGE
 * to authenticate the device.
 *
 * This function is combination of libspdm_get_digest, libspdm_get_certificate, libspdm_challenge.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  slot_mask                     The slots which deploy the CertificateChain.
 * @param  total_digest_buffer            A pointer to a destination buffer to store the digest buffer.
 * @param  slot_id                      The number of slot for the certificate chain.
 * @param  cert_chain_size                On input, indicate the size in bytes of the destination buffer to store the digest buffer.
 *                                     On output, indicate the size in bytes of the certificate chain.
 * @param  cert_chain                    A pointer to a destination buffer to store the certificate chain.
 * @param  measurement_hash_type          The type of the measurement hash.
 * @param  measurement_hash              A pointer to a destination buffer to store the measurement hash.
 *
 * @retval RETURN_SUCCESS               The authentication is got successfully.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
libspdm_return_t
spdm_authentication(void *context, uint8_t *slot_mask,
                    void *total_digest_buffer, uint8_t slot_id,
                    size_t *cert_chain_size, void *cert_chain,
                    uint8_t measurement_hash_type, void *measurement_hash,
                    uint8_t *auth_slot_mask)
{
    libspdm_return_t status;

    status = LIBSPDM_STATUS_SUCCESS;

    #if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
    status = libspdm_get_digest(context, NULL, slot_mask, total_digest_buffer);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    if (slot_id != 0xFF) {
        status = libspdm_get_certificate(context, NULL, slot_id, cert_chain_size,
                                         cert_chain);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
    }
    #endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */

    #if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
    status = libspdm_challenge(context, NULL, slot_id, measurement_hash_type,
                               measurement_hash, auth_slot_mask);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP*/
    return status;
}

/**
 * This function executes SPDM authentication.
 *
 * @param[in]  spdm_context            The SPDM context for the device.
 **/
libspdm_return_t do_authentication_via_spdm(void *spdm_context)
{
    libspdm_return_t status;
    uint8_t slot_mask;
    uint8_t total_digest_buffer[LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT];
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    uint8_t auth_slot_mask;

    libspdm_zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
    status = spdm_authentication(
        spdm_context, &slot_mask, &total_digest_buffer, 0,
        &cert_chain_size, cert_chain,
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
        measurement_hash, &auth_slot_mask);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    return LIBSPDM_STATUS_SUCCESS;
}
