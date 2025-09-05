/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

/**
 * This function checks the compatibility of the received SPDM version,
 * if received version is valid, subsequent spdm communication will follow this version.
 *
 * @param  spdm_context  A pointer to the SPDM context.
 * @param  version       The SPDM message version.
 *
 *
 * @retval true   The received SPDM version is valid.
 * @retval false  The received SPDM version is invalid.
 **/
static bool libspdm_check_request_version_compatibility(libspdm_context_t *spdm_context,
                                                        uint8_t version)
{
    uint8_t local_ver;
    size_t index;

    for (index = 0; index < spdm_context->local_context.version.spdm_version_count; index++) {
        local_ver = libspdm_get_version_from_version_number(
            spdm_context->local_context.version.spdm_version[index]);
        if (local_ver == version) {
            spdm_context->connection_info.version = version << SPDM_VERSION_NUMBER_SHIFT_BIT;
            return true;
        }
    }
    return false;
}

/**
 * This function checks the compatibility of the received GET_CAPABILITES flag.
 * Some flags are mutually inclusive/exclusive.
 *
 * @param  capabilities_flag  The received CAPABILITIES Flag.
 * @param  version            The SPDM message version.
 *
 *
 * @retval true   The received Capabilities flag is valid.
 * @retval false  The received Capabilities flag is invalid.
 **/
static bool libspdm_check_request_flag_compatibility(uint32_t capabilities_flag, uint8_t version)
{
    const uint8_t cert_cap = (uint8_t)(capabilities_flag >> 1) & 0x01;
    const uint8_t chal_cap = (uint8_t)(capabilities_flag >> 2) & 0x01;
    const uint8_t encrypt_cap = (uint8_t)(capabilities_flag >> 6) & 0x01;
    const uint8_t mac_cap = (uint8_t)(capabilities_flag >> 7) & 0x01;
    const uint8_t mut_auth_cap = (uint8_t)(capabilities_flag >> 8) & 0x01;
    const uint8_t key_ex_cap = (uint8_t)(capabilities_flag >> 9) & 0x01;
    const uint8_t psk_cap = (uint8_t)(capabilities_flag >> 10) & 0x03;
    const uint8_t encap_cap = (uint8_t)(capabilities_flag >> 12) & 0x01;
    const uint8_t hbeat_cap = (uint8_t)(capabilities_flag >> 13) & 0x01;
    const uint8_t key_upd_cap = (uint8_t)(capabilities_flag >> 14) & 0x01;
    const uint8_t handshake_in_the_clear_cap = (uint8_t)(capabilities_flag >> 15) & 0x01;
    const uint8_t pub_key_id_cap = (uint8_t)(capabilities_flag >> 16) & 0x01;
    const uint8_t ep_info_cap = (uint8_t)(capabilities_flag >> 22) & 0x03;
    const uint8_t event_cap = (uint8_t)(capabilities_flag >> 25) & 0x01;
    const uint8_t multi_key_cap = (uint8_t)(capabilities_flag >> 26) & 0x03;

    /* Checks common to 1.1 and higher */
    if (version >= SPDM_MESSAGE_VERSION_11) {
        /* Illegal to return reserved values. */
        if ((psk_cap == 2) || (psk_cap == 3)) {
            return false;
        }

        /* Checks that originate from key exchange capabilities. */
        if ((key_ex_cap == 1) || (psk_cap == 1)) {
            /* While clearing MAC_CAP and setting ENCRYPT_CAP is legal according to DSP0274, libspdm
             * also implements DSP0277 secure messages, which requires at least MAC_CAP to be set.
             */
            if (mac_cap == 0) {
                return false;
            }
        } else {
            if ((mac_cap == 1) || (encrypt_cap == 1) || (handshake_in_the_clear_cap == 1) ||
                (hbeat_cap == 1) || (key_upd_cap == 1)) {
                return false;
            }
            if (version == SPDM_MESSAGE_VERSION_13) {
                if (event_cap == 1) {
                    return false;
                }
            }
        }
        if ((key_ex_cap == 0) && (psk_cap == 1)) {
            if (handshake_in_the_clear_cap == 1) {
                return false;
            }
        }

        /* Checks that originate from certificate or public key capabilities. */
        if ((cert_cap == 1) || (pub_key_id_cap == 1)) {
            /* Certificate capabilities and public key capabilities cannot both be set. */
            if ((cert_cap == 1) && (pub_key_id_cap == 1)) {
                return false;
            }
            if ((chal_cap == 0) && (key_ex_cap == 0)) {
                return false;
            }
        } else {
            /* If certificates or public keys are not enabled then these capabilities
             * cannot be enabled. */
            if ((chal_cap == 1) || (mut_auth_cap == 1)) {
                return false;
            }
            if (version == SPDM_MESSAGE_VERSION_13) {
                if (ep_info_cap == 2) {
                    return false;
                }
            }
        }

        /* Checks that originate from mutual authentication capabilities. */
        if (mut_auth_cap == 1) {
            if ((key_ex_cap == 0) && (chal_cap == 0)) {
                return false;
            }
        }
    }

    /* Checks specific to 1.1. */
    if (version == SPDM_MESSAGE_VERSION_11) {
        if ((mut_auth_cap == 1) && (encap_cap == 0)) {
            return false;
        }
    }

    /* Checks specific to 1.3. */
    if (version == SPDM_MESSAGE_VERSION_13) {
        /* Illegal to return reserved values. */
        if ((ep_info_cap == 3) || (multi_key_cap == 3)) {
            return false;
        }
        /* check multi-key and pub_key_id */
        if ((multi_key_cap != 0) && (pub_key_id_cap == 1)) {
            return false;
        }
    }

    return true;
}

libspdm_return_t libspdm_get_response_capabilities(libspdm_context_t *spdm_context,
                                                   size_t request_size,
                                                   const void *request,
                                                   size_t *response_size,
                                                   void *response)
{
    const spdm_get_capabilities_request_t *spdm_request;
    spdm_capabilities_response_t *spdm_response;
    libspdm_return_t status;

    spdm_request = request;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(spdm_request->header.request_response_code == SPDM_GET_CAPABILITIES);

    /* -=[Verify State Phase]=- */
    if (spdm_context->response_state != LIBSPDM_RESPONSE_STATE_NORMAL) {
        return libspdm_responder_handle_response_state(
            spdm_context, spdm_request->header.request_response_code,  response_size, response);
    }
    if (spdm_context->connection_info.connection_state != LIBSPDM_CONNECTION_STATE_AFTER_VERSION) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
                                               0, response_size, response);
    }

    /* -=[Validate Request Phase]=- */
    if (!libspdm_check_request_version_compatibility(
            spdm_context, spdm_request->header.spdm_version)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_VERSION_MISMATCH, 0,
                                               response_size, response);
    }
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        if (request_size < sizeof(spdm_get_capabilities_request_t)) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
        } else {
            request_size = sizeof(spdm_get_capabilities_request_t);
        }
    } else if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        if (request_size < sizeof(spdm_get_capabilities_request_t) -
            sizeof(spdm_request->data_transfer_size) - sizeof(spdm_request->max_spdm_msg_size)) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
        } else {
            request_size = sizeof(spdm_get_capabilities_request_t) -
                           sizeof(spdm_request->data_transfer_size) -
                           sizeof(spdm_request->max_spdm_msg_size);
        }
    } else {
        if (request_size < sizeof(spdm_message_header_t)) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
        } else {
            request_size = sizeof(spdm_message_header_t);
        }
    }
    if (!libspdm_check_request_flag_compatibility(
            spdm_request->flags, spdm_request->header.spdm_version)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        if ((spdm_request->data_transfer_size < SPDM_MIN_DATA_TRANSFER_SIZE_VERSION_12) ||
            (spdm_request->data_transfer_size > spdm_request->max_spdm_msg_size)) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                   response_size, response);
        }
        if (((spdm_request->flags & SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP) == 0) &&
            (spdm_request->data_transfer_size != spdm_request->max_spdm_msg_size)) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                   response_size, response);
        }
    }
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        if (spdm_request->ct_exponent > LIBSPDM_MAX_CT_EXPONENT) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                   response_size, response);
        }
    }

    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                  spdm_request->header.request_response_code);

    /* -=[Construct Response Phase]=- */
    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_capabilities_response_t));
    *response_size = sizeof(spdm_capabilities_response_t);
    libspdm_zero_mem(response, *response_size);
    spdm_response = response;

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_CAPABILITIES;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;
    spdm_response->ct_exponent = spdm_context->local_context.capability.ct_exponent;
    spdm_response->flags = spdm_context->local_context.capability.flags;
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        spdm_response->data_transfer_size =
            spdm_context->local_context.capability.data_transfer_size;
        spdm_response->max_spdm_msg_size =
            spdm_context->local_context.capability.max_spdm_msg_size;
    }

    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        *response_size = sizeof(spdm_capabilities_response_t);
    } else {
        *response_size = sizeof(spdm_capabilities_response_t) -
                         sizeof(spdm_response->data_transfer_size) -
                         sizeof(spdm_response->max_spdm_msg_size);
    }

    /* -=[Process Request Phase]=- */
    status = libspdm_append_message_a(spdm_context, spdm_request, request_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }
    status = libspdm_append_message_a(spdm_context, spdm_response, *response_size);

    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        spdm_context->connection_info.capability.ct_exponent = spdm_request->ct_exponent;
    } else {
        spdm_context->connection_info.capability.ct_exponent = 0;
    }

    if (spdm_response->header.spdm_version == SPDM_MESSAGE_VERSION_10) {
        spdm_context->connection_info.capability.flags = 0;
    } else if (spdm_response->header.spdm_version == SPDM_MESSAGE_VERSION_11) {
        spdm_context->connection_info.capability.flags =
            spdm_request->flags & SPDM_GET_CAPABILITIES_REQUEST_FLAGS_11_MASK;
    } else if (spdm_response->header.spdm_version == SPDM_MESSAGE_VERSION_12) {
        spdm_context->connection_info.capability.flags =
            spdm_request->flags & SPDM_GET_CAPABILITIES_REQUEST_FLAGS_12_MASK;
    } else {
        spdm_context->connection_info.capability.flags =
            spdm_request->flags & SPDM_GET_CAPABILITIES_REQUEST_FLAGS_13_MASK;
    }

    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        spdm_context->connection_info.capability.data_transfer_size =
            spdm_request->data_transfer_size;
        spdm_context->connection_info.capability.max_spdm_msg_size =
            spdm_request->max_spdm_msg_size;
    } else {
        spdm_context->connection_info.capability.data_transfer_size = 0;
        spdm_context->connection_info.capability.max_spdm_msg_size = 0;
    }

    /* -=[Update State Phase]=- */
    libspdm_set_connection_state(spdm_context, LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES);

    return LIBSPDM_STATUS_SUCCESS;
}
