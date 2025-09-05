/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_responder.h"


/* Disable optimization to avoid code removal with VS2019.*/

#if defined(_MSC_EXTENSIONS)
#pragma optimize("", off)
#elif defined (__clang__)
#pragma clang optimize off
#endif

void spdm_dispatch(void)
{
    void *spdm_context;
    libspdm_return_t status;

    spdm_context = spdm_server_init();
    if (spdm_context == NULL) {
        return;
    }

    while (true) {
        status = libspdm_responder_dispatch_message(spdm_context);
        if (status != LIBSPDM_STATUS_UNSUPPORTED_CAP) {
            continue;
        }
    }
    return;
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
