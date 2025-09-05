/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __SPDM_UNIT_FUZZING_H__
#define __SPDM_UNIT_FUZZING_H__

#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_responder_lib.h"
#include "library/spdm_common_lib.h"
#include "library/spdm_transport_test_lib.h"
#include "internal/libspdm_common_lib.h"
#include "internal/libspdm_secured_message_lib.h"

/* need redefine MAX_MESSAGE_x_BUFFER_SIZE macro if TRANSCRIPT_DATA_SUPPORT is 0,
 * because unit test uses it own way to track transcript. */
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT == 0

#define LIBSPDM_MAX_MESSAGE_B_BUFFER_SIZE (24 + \
                                           LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT + \
                                           LIBSPDM_MAX_CERT_CHAIN_SIZE)

#define LIBSPDM_MAX_MESSAGE_C_BUFFER_SIZE (78 + \
                                           LIBSPDM_MAX_HASH_SIZE * 2 + \
                                           LIBSPDM_MAX_ASYM_KEY_SIZE + SPDM_MAX_OPAQUE_DATA_SIZE)

#define LIBSPDM_MAX_MESSAGE_M_BUFFER_SIZE (47 + SPDM_NONCE_SIZE + \
                                           LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE + \
                                           LIBSPDM_MAX_ASYM_KEY_SIZE + SPDM_MAX_OPAQUE_DATA_SIZE)

#define LIBSPDM_MAX_MESSAGE_K_BUFFER_SIZE (84 + LIBSPDM_MAX_DHE_KEY_SIZE * 2 + \
                                           LIBSPDM_MAX_HASH_SIZE * 2 + LIBSPDM_MAX_ASYM_KEY_SIZE + \
                                           SPDM_MAX_OPAQUE_DATA_SIZE * 2)

#define LIBSPDM_MAX_MESSAGE_F_BUFFER_SIZE (8 + LIBSPDM_MAX_HASH_SIZE * 2 + \
                                           LIBSPDM_MAX_ASYM_KEY_SIZE)

#define LIBSPDM_MAX_MESSAGE_L1L2_BUFFER_SIZE \
    (LIBSPDM_MAX_MESSAGE_VCA_BUFFER_SIZE + LIBSPDM_MAX_MESSAGE_M_BUFFER_SIZE)

#define LIBSPDM_MAX_MESSAGE_M1M2_BUFFER_SIZE \
    (LIBSPDM_MAX_MESSAGE_VCA_BUFFER_SIZE + \
     LIBSPDM_MAX_MESSAGE_B_BUFFER_SIZE + LIBSPDM_MAX_MESSAGE_C_BUFFER_SIZE)

#define LIBSPDM_MAX_MESSAGE_TH_BUFFER_SIZE \
    (LIBSPDM_MAX_MESSAGE_VCA_BUFFER_SIZE + \
     LIBSPDM_MAX_CERT_CHAIN_SIZE + LIBSPDM_MAX_MESSAGE_K_BUFFER_SIZE + \
     LIBSPDM_MAX_CERT_CHAIN_SIZE + LIBSPDM_MAX_MESSAGE_F_BUFFER_SIZE)

typedef struct {
    size_t max_buffer_size;
    size_t buffer_size;
    uint8_t buffer[LIBSPDM_MAX_MESSAGE_TH_BUFFER_SIZE];
} libspdm_th_managed_buffer_t;

#endif

#define LIBSPDM_TRANSPORT_ADDITIONAL_SIZE    (LIBSPDM_TEST_TRANSPORT_HEADER_SIZE + \
                                              LIBSPDM_TEST_TRANSPORT_TAIL_SIZE)

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

extern uint8_t m_libspdm_use_measurement_spec;
extern uint32_t m_libspdm_use_measurement_hash_algo;
extern uint32_t m_libspdm_use_hash_algo;
extern uint32_t m_libspdm_use_asym_algo;
extern uint16_t m_libspdm_use_req_asym_algo;
extern uint16_t m_libspdm_use_dhe_algo;
extern uint16_t m_libspdm_use_aead_algo;
extern uint16_t m_libspdm_use_key_schedule_algo;

#define LIBSPDM_TEST_CONTEXT_VERSION 0x1

typedef struct {
    uint32_t version;
    bool is_requester;
    libspdm_device_send_message_func send_message;
    libspdm_device_receive_message_func receive_message;
    void *spdm_context;
    void *scratch_buffer;
    size_t scratch_buffer_size;
    void *test_buffer;
    size_t test_buffer_size;
} libspdm_test_context_t;

size_t libspdm_unit_test_group_setup(void **State);

size_t libspdm_unit_test_group_teardown(void **State);

void libspdm_setup_test_context(libspdm_test_context_t *spdm_test_context);

libspdm_test_context_t *libspdm_get_test_context(void);

bool libspdm_read_input_file(const char *file_name, void **file_data,
                             size_t *file_size);

void libspdm_dump_hex_str(const uint8_t *buffer, size_t buffer_size);

void libspdm_dump_data(const uint8_t *buffer, size_t buffer_size);

void libspdm_dump_hex(const uint8_t *buffer, size_t buffer_size);

#endif
