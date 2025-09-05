/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_requester.h"

#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
libspdm_return_t do_session_via_spdm(void *spdm_context)
{
    libspdm_return_t status;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];

    heartbeat_period = 0;
    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
    status = libspdm_start_session(
        spdm_context,
        false, /* KeyExchange*/
        NULL, 0,
        SPDM_KEY_EXCHANGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH, 0, 0,
        &session_id, &heartbeat_period, measurement_hash);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "libspdm_start_session - %xu\n", status));
        return status;
    }


    /* TBD - Set key*/


    status = libspdm_stop_session(spdm_context, session_id, 0);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "libspdm_stop_session - %xu\n", status));
        return status;
    }

    return status;
}
#endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */
