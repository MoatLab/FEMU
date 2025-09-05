/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef EVENTLIB_H
#define EVENTLIB_H

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"
#include "industry_standard/spdm.h"

#if LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP
/**
 * Populate the SupportedEventGroupsList field in the SUPPORTED_EVENT_TYPES response.
 *
 * The SPDM specification mandates that, at a minimum, the event notifier must support the DMTF
 * event types and the EventLost event.
 *
 * @param  spdm_context  A pointer to the SPDM context.
 * @param  spdm_version  Indicates the negotiated version.
 * @param  supported_event_groups_list      A pointer to the buffer that holds the list of event.
 *                                          groups.
 * @param  supported_event_groups_list_len  On input, the size, in bytes, of the buffer to hold the
 *                                          list of event groups.
 *                                          On output, the size, in bytes, of the list of event
 *                                          groups. This value must be greater than zero.
 * @param  event_group_count  The number of event groups in supported_event_groups_list. This value
 *                            must be greater than 0.
 *
 * @retval true   The event groups list was successfully populated.
 * @retval false  An error occurred when populating the event groups list.
 **/
extern bool libspdm_event_get_types(
    void *spdm_context,
    spdm_version_number_t spdm_version,
    void *supported_event_groups_list,
    uint32_t *supported_event_groups_list_len,
    uint8_t *event_group_count);
#endif /* LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP */
#endif /* EVENTLIB_H */
