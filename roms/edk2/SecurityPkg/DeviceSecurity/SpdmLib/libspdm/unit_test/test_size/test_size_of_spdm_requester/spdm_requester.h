/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __SPDM_REQUESTER_H__
#define __SPDM_REQUESTER_H__

#include "hal/base.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_mctp_lib.h"
#include "library/malloclib.h"
#include "library/spdm_crypt_lib.h"
#include "hal/library/memlib.h"
#include "hal/library/debuglib.h"

#define LIBSPDM_TRANSPORT_ADDITIONAL_SIZE    (LIBSPDM_MCTP_TRANSPORT_HEADER_SIZE + \
                                              LIBSPDM_MCTP_TRANSPORT_TAIL_SIZE)

#ifndef LIBSPDM_SENDER_BUFFER_SIZE
#define LIBSPDM_SENDER_BUFFER_SIZE (0x1100 + \
                                    LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#endif
#ifndef LIBSPDM_RECEIVER_BUFFER_SIZE
#define LIBSPDM_RECEIVER_BUFFER_SIZE (0x1200 + \
                                      LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#endif

/* Maximum size of a single SPDM message.
 * It matches DataTransferSize in SPDM specification. */
#define LIBSPDM_SENDER_DATA_TRANSFER_SIZE (LIBSPDM_SENDER_BUFFER_SIZE - \
                                           LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#define LIBSPDM_RECEIVER_DATA_TRANSFER_SIZE (LIBSPDM_RECEIVER_BUFFER_SIZE - \
                                             LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#define LIBSPDM_DATA_TRANSFER_SIZE LIBSPDM_RECEIVER_DATA_TRANSFER_SIZE

#if (LIBSPDM_SENDER_BUFFER_SIZE > LIBSPDM_RECEIVER_BUFFER_SIZE)
#define LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE LIBSPDM_SENDER_BUFFER_SIZE
#else
#define LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE LIBSPDM_RECEIVER_BUFFER_SIZE
#endif

/* Maximum size of a large SPDM message.
 * If chunk is unsupported, it must be same as DATA_TRANSFER_SIZE.
 * If chunk is supported, it must be larger than DATA_TRANSFER_SIZE.
 * It matches MaxSPDMmsgSize in SPDM specification. */
#ifndef LIBSPDM_MAX_SPDM_MSG_SIZE
#define LIBSPDM_MAX_SPDM_MSG_SIZE 0x1200
#endif

#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
#define LIBSPDM_SCRATCH_BUFFER_SECURE_MESSAGE_CAPACITY (LIBSPDM_MAX_SPDM_MSG_SIZE + \
                                                        LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#else
#define LIBSPDM_SCRATCH_BUFFER_SECURE_MESSAGE_CAPACITY 0
#endif

#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
#define LIBSPDM_SCRATCH_BUFFER_LARGE_MESSAGE_CAPACITY (LIBSPDM_MAX_SPDM_MSG_SIZE)
#else
#define LIBSPDM_SCRATCH_BUFFER_LARGE_MESSAGE_CAPACITY 0
#endif

#define LIBSPDM_SCRATCH_BUFFER_SENDER_RECEIVER_CAPACITY (LIBSPDM_MAX_SPDM_MSG_SIZE + \
                                                         LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)

#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
#define LIBSPDM_SCRATCH_BUFFER_LARGE_SENDER_RECEIVER_CAPACITY (LIBSPDM_MAX_SPDM_MSG_SIZE + \
                                                               LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#else
#define LIBSPDM_SCRATCH_BUFFER_LARGE_SENDER_RECEIVER_CAPACITY 0
#endif

#define LIBSPDM_SCRATCH_BUFFER_LAST_SPDM_REQUEST_CAPACITY (LIBSPDM_MAX_SPDM_MSG_SIZE)

#if LIBSPDM_RESPOND_IF_READY_SUPPORT
#define LIBSPDM_SCRATCH_BUFFER_CACHE_SPDM_REQUEST_CAPACITY (LIBSPDM_MAX_SPDM_MSG_SIZE)
#else
#define LIBSPDM_SCRATCH_BUFFER_CACHE_SPDM_REQUEST_CAPACITY 0
#endif

#define LIBSPDM_SCRATCH_BUFFER_SIZE (LIBSPDM_SCRATCH_BUFFER_SECURE_MESSAGE_CAPACITY + \
                                     LIBSPDM_SCRATCH_BUFFER_LARGE_MESSAGE_CAPACITY + \
                                     LIBSPDM_SCRATCH_BUFFER_SENDER_RECEIVER_CAPACITY + \
                                     LIBSPDM_SCRATCH_BUFFER_LARGE_SENDER_RECEIVER_CAPACITY + \
                                     LIBSPDM_SCRATCH_BUFFER_LAST_SPDM_REQUEST_CAPACITY + \
                                     LIBSPDM_SCRATCH_BUFFER_CACHE_SPDM_REQUEST_CAPACITY)

libspdm_return_t do_authentication_via_spdm(void *spdm_context);

libspdm_return_t do_session_via_spdm(void *spdm_context);

void *spdm_client_init(void);

#endif
