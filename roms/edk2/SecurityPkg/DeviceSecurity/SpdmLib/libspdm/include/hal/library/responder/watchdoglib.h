/**
 *  Copyright Notice:
 *  Copyright 2022-2023 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/
#ifndef REQUESTER_WATCHDOGLIB_H
#define REQUESTER_WATCHDOGLIB_H

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"

#if LIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP
/**
 * Start the watchdog timer for a given session ID.
 *
 * @param  session_id  Indicate the SPDM session ID.
 * @param  timeout     Timeout value, in units of seconds.
 **/
extern bool libspdm_start_watchdog(uint32_t session_id, uint16_t timeout);

/**
 * Stop the watchdog timer for a given session ID.
 *
 * @param  session_id Indicate the SPDM session ID.
 **/
extern bool libspdm_stop_watchdog(uint32_t session_id);

/**
 * Reset the watchdog time for a given session ID.
 *
 * @param  session_id  Indicate the SPDM session ID.
 **/
extern bool libspdm_reset_watchdog(uint32_t session_id);
#endif /* LIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP */

#endif /* REQUESTER_WATCHDOGLIB_H */
