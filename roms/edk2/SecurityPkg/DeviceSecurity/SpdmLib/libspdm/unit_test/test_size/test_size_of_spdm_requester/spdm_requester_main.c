/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_requester.h"

#if defined(_MSC_EXTENSIONS)
#pragma optimize("", off)
#elif defined (__clang__)
#pragma clang optimize off
#endif

void spdm_dispatch(void)
{
    void *spdm_context;
    libspdm_return_t status;

    spdm_context = spdm_client_init();
    if (spdm_context == NULL) {
        return;
    }

    status = do_authentication_via_spdm(spdm_context);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return;
    }

    #if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
    status = do_session_via_spdm(spdm_context);
    #endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */

}

/**
 * Main entry point to DXE Core.
 *
 * @param  HobStart               Pointer to the beginning of the HOB List from PEI.
 *
 * @return This function should never return.
 *
 **/
void ModuleEntryPoint(void)
{
    spdm_dispatch();

    return;
}
