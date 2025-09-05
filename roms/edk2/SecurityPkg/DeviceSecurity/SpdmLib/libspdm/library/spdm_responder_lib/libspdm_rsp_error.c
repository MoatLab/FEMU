/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

libspdm_return_t libspdm_generate_error_response(const void *spdm_context,
                                                 uint8_t error_code,
                                                 uint8_t error_data,
                                                 size_t *response_size,
                                                 void *response)
{
    spdm_error_response_t *spdm_response;

    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_error_response_t));
    *response_size = sizeof(spdm_error_response_t);
    spdm_response = response;

    spdm_response->header.spdm_version = libspdm_get_connection_version (spdm_context);
    if (spdm_response->header.spdm_version == 0) {
        /* if version is not negotiated, then use default version 1.0 */
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
    }
    spdm_response->header.request_response_code = SPDM_ERROR;
    spdm_response->header.param1 = error_code;
    spdm_response->header.param2 = error_data;

    if (spdm_response->header.spdm_version <= SPDM_MESSAGE_VERSION_11) {
        LIBSPDM_ASSERT ((error_code != SPDM_ERROR_CODE_RESPONSE_TOO_LARGE) &&
                        (error_code != SPDM_ERROR_CODE_LARGE_RESPONSE));
    }

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_generate_extended_error_response(
    const void *spdm_context, uint8_t error_code, uint8_t error_data,
    size_t extended_error_data_size, const uint8_t *extended_error_data,
    size_t *response_size, void *response)
{
    spdm_error_response_t *spdm_response;
    size_t response_capacity;

    LIBSPDM_ASSERT(*response_size >=
                   sizeof(spdm_error_response_t) + extended_error_data_size);
    response_capacity = *response_size;
    *response_size = sizeof(spdm_error_response_t) + extended_error_data_size;
    spdm_response = response;

    spdm_response->header.spdm_version = libspdm_get_connection_version (spdm_context);
    spdm_response->header.request_response_code = SPDM_ERROR;
    spdm_response->header.param1 = error_code;
    spdm_response->header.param2 = error_data;
    libspdm_copy_mem(spdm_response + 1, response_capacity - sizeof(spdm_error_response_t),
                     extended_error_data, extended_error_data_size);

    return LIBSPDM_STATUS_SUCCESS;
}
