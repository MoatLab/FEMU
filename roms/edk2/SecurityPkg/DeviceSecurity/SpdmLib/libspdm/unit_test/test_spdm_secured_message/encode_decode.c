/**
 *  Copyright Notice:
 *  Copyright 2023 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_secured_message_lib.h"

static uint8_t m_secured_message[0x1000];
static uint8_t m_app_message[0x1000];
static libspdm_secured_message_context_t m_secured_message_context;
static libspdm_secured_message_callbacks_t m_secured_message_callbacks;

#define PARTIAL_SEQ_NUM_SIZE 8

static uint8_t get_sequence_number(uint64_t sequence_number,
                                   uint8_t *sequence_number_buffer)
{
    libspdm_copy_mem(sequence_number_buffer, (size_t)8,
                     &sequence_number, (size_t)PARTIAL_SEQ_NUM_SIZE);

    return PARTIAL_SEQ_NUM_SIZE;
}

static uint32_t get_max_random_number_count(void)
{
    return 0;
}

static spdm_version_number_t get_secured_spdm_version(spdm_version_number_t secured_message_version)
{
    return SECURED_SPDM_VERSION_11;
}

static void initialize_secured_message_context(void)
{
    m_secured_message_context.secured_message_version = SECURED_SPDM_VERSION_11;
    m_secured_message_context.aead_cipher_suite = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;
    m_secured_message_context.session_type = LIBSPDM_SESSION_TYPE_ENC_MAC;
    m_secured_message_context.session_state = LIBSPDM_SESSION_STATE_ESTABLISHED;
    m_secured_message_context.aead_tag_size = 16;
    m_secured_message_context.aead_key_size = 32;
    m_secured_message_context.aead_iv_size = 12;
    for (uint8_t index = 0; index < 32; index++) {
        m_secured_message_context.application_secret.request_data_encryption_key[index] = index;
        m_secured_message_context.application_secret.response_data_encryption_key[index] =
            32 - index;
    }
    for (uint8_t index = 0; index < 12; index++) {
        m_secured_message_context.application_secret.request_data_salt[index] = index * 2;
        m_secured_message_context.application_secret.response_data_salt[index] = index * 4;
    }
    m_secured_message_context.application_secret.request_data_sequence_number = 0;
    m_secured_message_context.application_secret.response_data_sequence_number = 0;
    m_secured_message_context.max_spdm_session_sequence_number = UINT64_MAX;
    m_secured_message_context.sequence_number_endian =
        LIBSPDM_DATA_SESSION_SEQ_NUM_ENC_LITTLE_DEC_BOTH;
    m_secured_message_callbacks.get_secured_spdm_version = get_secured_spdm_version;
    m_secured_message_callbacks.get_max_random_number_count = get_max_random_number_count;
    m_secured_message_callbacks.get_sequence_number = get_sequence_number;
}

/**
 * Test 1: Test basic encryption with sequence number set to all zeroes and little endianness.
 **/
static void libspdm_test_secured_message_encode_case1(void **state)
{
    libspdm_return_t status;
    uint8_t app_message[16];
    size_t secured_message_size = sizeof(m_secured_message);
    const uint32_t session_id = 0x00112233;
    uint8_t *ptr;

    initialize_secured_message_context();

    for (uint8_t index = 0; index < 16; index++) {
        app_message[index] = index;
    }

    status = libspdm_encode_secured_message(
        &m_secured_message_context, session_id, true,
        sizeof(app_message), app_message, &secured_message_size, &m_secured_message,
        &m_secured_message_callbacks);

    assert_int_equal(LIBSPDM_STATUS_SUCCESS, status);
    assert_memory_equal(&session_id, &m_secured_message, 4);

    /* Sequence number is all zeroes. */
    for (int index = 4; index < 4 + PARTIAL_SEQ_NUM_SIZE; index++) {
        assert_int_equal(0, m_secured_message[index]);
    }

    assert_int_equal(0x0022, *(uint16_t*)&m_secured_message[4 + PARTIAL_SEQ_NUM_SIZE]);

    ptr = (uint8_t *)&m_secured_message + 6 + PARTIAL_SEQ_NUM_SIZE;

    /* Expected values generated from https://tinyurl.com/yrx9w78w */
    uint8_t expected_cipher_text[] = {0x9b, 0xfe, 0xd3, 0xb7, 0x04, 0x3d, 0x32, 0x86, 0x60, 0x3d,
                                      0x86, 0x17, 0x33, 0xd6, 0x7f, 0x95, 0x9a, 0x20};
    uint8_t expected_mac[] = {0x3d, 0x4f, 0xac, 0x58, 0xcb, 0x70, 0x6c, 0xf5, 0xa0, 0x27, 0x0a,
                              0xf6, 0x73, 0xf0, 0xfe, 0x36};

    assert_memory_equal(expected_cipher_text, ptr, sizeof(expected_cipher_text));
    ptr += sizeof(expected_cipher_text);
    assert_memory_equal(expected_mac, ptr, sizeof(expected_mac));

    /* Sequence number is incremented by one after operation. */
    assert_int_equal(1, m_secured_message_context.application_secret.request_data_sequence_number);
}

/**
 * Test 2: Test basic encryption with sequence number set to alternating zeroes and ones and
 *         little endianness.
 **/
static void libspdm_test_secured_message_encode_case2(void **state)
{
    libspdm_return_t status;
    uint8_t app_message[16];
    size_t secured_message_size = sizeof(m_secured_message);
    const uint32_t session_id = 0x00112233;
    uint8_t *ptr;

    initialize_secured_message_context();
    m_secured_message_context.application_secret.request_data_sequence_number = 0xaa55aa55aa55aa55;

    for (uint8_t index = 0; index < 16; index++) {
        app_message[index] = index;
    }

    status = libspdm_encode_secured_message(
        &m_secured_message_context, session_id, true,
        sizeof(app_message), app_message, &secured_message_size, &m_secured_message,
        &m_secured_message_callbacks);

    assert_int_equal(LIBSPDM_STATUS_SUCCESS, status);
    assert_memory_equal(&session_id, &m_secured_message, 4);

    /* Sequence number is alternating 0x55 and 0xaa. */
    for (int index = 4; index < 4 + PARTIAL_SEQ_NUM_SIZE; index++) {
        if (index % 2 == 0) {
            assert_int_equal(0x55, m_secured_message[index]);
        } else {
            assert_int_equal(0xaa, m_secured_message[index]);
        }
    }

    assert_int_equal(0x0022, *(uint16_t*)&m_secured_message[4 + PARTIAL_SEQ_NUM_SIZE]);

    ptr = (uint8_t *)&m_secured_message + 6 + PARTIAL_SEQ_NUM_SIZE;

    /* Expected values generated from https://tinyurl.com/2amhw53e */
    uint8_t expected_cipher_text[] = {0x0d, 0xea, 0x75, 0xea, 0xc6, 0x91, 0x37, 0x49, 0x94, 0x97,
                                      0x52, 0x63, 0xf8, 0xc0, 0x8f, 0x6c, 0x1a, 0xa4};
    uint8_t expected_mac[] = {0x0d, 0xcd, 0xb4, 0x8a, 0xd6, 0xfa, 0x24, 0x04, 0x79, 0xd5, 0xd8,
                              0xd2, 0xfe, 0x28, 0x19, 0x14};

    assert_memory_equal(expected_cipher_text, ptr, sizeof(expected_cipher_text));
    ptr += sizeof(expected_cipher_text);
    assert_memory_equal(expected_mac, ptr, sizeof(expected_mac));

    /* Sequence number is incremented by one after operation. */
    assert_int_equal(0xaa55aa55aa55aa56,
                     m_secured_message_context.application_secret.request_data_sequence_number);
}

/**
 * Test 3: Test basic encryption with sequence number set to all zeroes and big endianness.
 *         This has the same result as test 1 since the sequence number is all zeroes.
 **/
static void libspdm_test_secured_message_encode_case3(void **state)
{
    libspdm_return_t status;
    uint8_t app_message[16];
    size_t secured_message_size = sizeof(m_secured_message);
    const uint32_t session_id = 0x00112233;
    uint8_t *ptr;

    initialize_secured_message_context();
    m_secured_message_context.sequence_number_endian =
        LIBSPDM_DATA_SESSION_SEQ_NUM_ENC_BIG_DEC_BOTH;

    for (uint8_t index = 0; index < 16; index++) {
        app_message[index] = index;
    }

    status = libspdm_encode_secured_message(
        &m_secured_message_context, session_id, true,
        sizeof(app_message), app_message, &secured_message_size, &m_secured_message,
        &m_secured_message_callbacks);

    assert_int_equal(LIBSPDM_STATUS_SUCCESS, status);
    assert_memory_equal(&session_id, &m_secured_message, 4);

    /* Sequence number is all zeroes. */
    for (int index = 4; index < 4 + PARTIAL_SEQ_NUM_SIZE; index++) {
        assert_int_equal(0, m_secured_message[index]);
    }

    assert_int_equal(0x0022, *(uint16_t*)&m_secured_message[4 + PARTIAL_SEQ_NUM_SIZE]);

    ptr = (uint8_t *)&m_secured_message + 6 + PARTIAL_SEQ_NUM_SIZE;

    /* Expected values generated from https://tinyurl.com/yrx9w78w */
    uint8_t expected_cipher_text[] = {0x9b, 0xfe, 0xd3, 0xb7, 0x04, 0x3d, 0x32, 0x86, 0x60, 0x3d,
                                      0x86, 0x17, 0x33, 0xd6, 0x7f, 0x95, 0x9a, 0x20};
    uint8_t expected_mac[] = {0x3d, 0x4f, 0xac, 0x58, 0xcb, 0x70, 0x6c, 0xf5, 0xa0, 0x27, 0x0a,
                              0xf6, 0x73, 0xf0, 0xfe, 0x36};

    assert_memory_equal(expected_cipher_text, ptr, sizeof(expected_cipher_text));
    ptr += sizeof(expected_cipher_text);
    assert_memory_equal(expected_mac, ptr, sizeof(expected_mac));

    /* Sequence number is incremented by one after operation. */
    assert_int_equal(1, m_secured_message_context.application_secret.request_data_sequence_number);
}

/**
 * Test 4: Test basic encryption with sequence number set to alternating zeroes and ones and
 *         big endianness.
 **/
static void libspdm_test_secured_message_encode_case4(void **state)
{
    libspdm_return_t status;
    uint8_t app_message[16];
    size_t secured_message_size = sizeof(m_secured_message);
    const uint32_t session_id = 0x00112233;
    uint8_t *ptr;

    initialize_secured_message_context();
    m_secured_message_context.application_secret.request_data_sequence_number = 0xaa55aa55aa55aa55;
    m_secured_message_context.sequence_number_endian =
        LIBSPDM_DATA_SESSION_SEQ_NUM_ENC_BIG_DEC_BOTH;

    for (uint8_t index = 0; index < 16; index++) {
        app_message[index] = index;
    }

    status = libspdm_encode_secured_message(
        &m_secured_message_context, session_id, true,
        sizeof(app_message), app_message, &secured_message_size, &m_secured_message,
        &m_secured_message_callbacks);

    assert_int_equal(LIBSPDM_STATUS_SUCCESS, status);
    assert_memory_equal(&session_id, &m_secured_message, 4);

    /* Sequence number is alternating 0x55 and 0xaa. */
    for (int index = 4; index < 4 + PARTIAL_SEQ_NUM_SIZE; index++) {
        if (index % 2 == 0) {
            assert_int_equal(0x55, m_secured_message[index]);
        } else {
            assert_int_equal(0xaa, m_secured_message[index]);
        }
    }

    assert_int_equal(0x0022, *(uint16_t*)&m_secured_message[4 + PARTIAL_SEQ_NUM_SIZE]);

    ptr = (uint8_t *)&m_secured_message + 6 + PARTIAL_SEQ_NUM_SIZE;

    /* Expected values generated from https://tinyurl.com/azaw5bab */
    uint8_t expected_cipher_text[] = {0xf6, 0x4d, 0x6b, 0x94, 0x37, 0x7a, 0x18, 0x61, 0x01, 0xce,
                                      0xfe, 0xa0, 0x8d, 0x91, 0x79, 0x8a, 0x89, 0x88};
    uint8_t expected_mac[] = {0xb6, 0x8e, 0xd3, 0x06, 0x4a, 0x95, 0x70, 0x89, 0xd4, 0xd8, 0xb9,
                              0x02, 0x9e, 0x9d, 0x72, 0x0b};

    assert_memory_equal(expected_cipher_text, ptr, sizeof(expected_cipher_text));
    ptr += sizeof(expected_cipher_text);
    assert_memory_equal(expected_mac, ptr, sizeof(expected_mac));

    /* Sequence number is incremented by one after operation. */
    assert_int_equal(0xaa55aa55aa55aa56,
                     m_secured_message_context.application_secret.request_data_sequence_number);
}

/**
 * Test 5: Test basic decryption with sequence number set to all zeroes and little endianness.
 *         This uses the same plaintext as test 1.
 **/
static void libspdm_test_secured_message_encode_case5(void **state)
{
    libspdm_return_t status;
    size_t app_message_size = sizeof(m_app_message);
    void *app_message = m_app_message;
    const uint32_t session_id = 0x00112233;

    uint8_t secured_message[] = {
        /* Session id. */
        0x33, 0x22, 0x11, 0x00,
        /* Sequence number. */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* Total length. */
        0x22, 0x00,
        /* Encrypted application data length. */
        0x9b, 0xfe,
        /* Encrypted application data. */
        0xd3, 0xb7, 0x04, 0x3d, 0x32, 0x86, 0x60, 0x3d,
        0x86, 0x17, 0x33, 0xd6, 0x7f, 0x95, 0x9a, 0x20,
        /* MAC. */
        0x3d, 0x4f, 0xac, 0x58, 0xcb, 0x70, 0x6c, 0xf5,
        0xa0, 0x27, 0x0a, 0xf6, 0x73, 0xf0, 0xfe, 0x36
    };

    initialize_secured_message_context();
    m_secured_message_context.sequence_number_endian =
        LIBSPDM_DATA_SESSION_SEQ_NUM_ENC_LITTLE_DEC_LITTLE;

    libspdm_copy_mem(m_secured_message, sizeof(m_secured_message),
                     secured_message, sizeof(secured_message));

    status = libspdm_decode_secured_message(
        &m_secured_message_context, session_id, true,
        sizeof(m_secured_message), m_secured_message, &app_message_size, &app_message,
        &m_secured_message_callbacks);

    assert_int_equal(LIBSPDM_STATUS_SUCCESS, status);

    for (int index = 0; index < 16; index++) {
        assert_int_equal(index, ((uint8_t *)app_message)[index]);
    }

    /* Sequence number is incremented by one after operation. */
    assert_int_equal(1, m_secured_message_context.application_secret.request_data_sequence_number);
}

/**
 * Test 6: Test basic decryption with sequence number set to all zeroes and big endianness.
 *         This uses the same plaintext as test 1.
 **/
static void libspdm_test_secured_message_encode_case6(void **state)
{
    libspdm_return_t status;
    size_t app_message_size = sizeof(m_app_message);
    void *app_message = m_app_message;
    const uint32_t session_id = 0x00112233;

    uint8_t secured_message[] = {
        /* Session id. */
        0x33, 0x22, 0x11, 0x00,
        /* Sequence number. */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* Total length. */
        0x22, 0x00,
        /* Encrypted application data length. */
        0x9b, 0xfe,
        /* Encrypted application data. */
        0xd3, 0xb7, 0x04, 0x3d, 0x32, 0x86, 0x60, 0x3d,
        0x86, 0x17, 0x33, 0xd6, 0x7f, 0x95, 0x9a, 0x20,
        /* MAC. */
        0x3d, 0x4f, 0xac, 0x58, 0xcb, 0x70, 0x6c, 0xf5,
        0xa0, 0x27, 0x0a, 0xf6, 0x73, 0xf0, 0xfe, 0x36
    };

    initialize_secured_message_context();
    m_secured_message_context.sequence_number_endian =
        LIBSPDM_DATA_SESSION_SEQ_NUM_ENC_BIG_DEC_BIG;

    libspdm_copy_mem(m_secured_message, sizeof(m_secured_message),
                     secured_message, sizeof(secured_message));

    status = libspdm_decode_secured_message(
        &m_secured_message_context, session_id, true,
        sizeof(m_secured_message), m_secured_message, &app_message_size, &app_message,
        &m_secured_message_callbacks);

    assert_int_equal(LIBSPDM_STATUS_SUCCESS, status);

    for (int index = 0; index < 16; index++) {
        assert_int_equal(index, ((uint8_t *)app_message)[index]);
    }

    /* Sequence number is incremented by one after operation. */
    assert_int_equal(1, m_secured_message_context.application_secret.request_data_sequence_number);
}

/**
 * Test 7: Test try-fail decryption.
 *         The message is encrypted with big-endian sequence number but decoder is set to try
 *         little-endian first. The first decryption with sequence number == 0 will pass regardless
 *         of endianness. Endianness will be detected when sequence number == 1.
 *         This uses the same plaintext as test 1.
 **/
static void libspdm_test_secured_message_encode_case7(void **state)
{
    libspdm_return_t status;
    size_t app_message_size = sizeof(m_app_message);
    void *app_message = m_app_message;
    const uint32_t session_id = 0x00112233;

    uint8_t secured_message_0[] = {
        /* Session id. */
        0x33, 0x22, 0x11, 0x00,
        /* Sequence number. */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* Total length. */
        0x22, 0x00,
        /* Encrypted application data length. */
        0x9b, 0xfe,
        /* Encrypted application data. */
        0xd3, 0xb7, 0x04, 0x3d, 0x32, 0x86, 0x60, 0x3d,
        0x86, 0x17, 0x33, 0xd6, 0x7f, 0x95, 0x9a, 0x20,
        /* MAC. */
        0x3d, 0x4f, 0xac, 0x58, 0xcb, 0x70, 0x6c, 0xf5,
        0xa0, 0x27, 0x0a, 0xf6, 0x73, 0xf0, 0xfe, 0x36
    };

    initialize_secured_message_context();
    m_secured_message_context.sequence_number_endian =
        LIBSPDM_DATA_SESSION_SEQ_NUM_ENC_LITTLE_DEC_BOTH;

    libspdm_copy_mem(m_secured_message, sizeof(m_secured_message),
                     secured_message_0, sizeof(secured_message_0));

    status = libspdm_decode_secured_message(
        &m_secured_message_context, session_id, true,
        sizeof(m_secured_message), m_secured_message, &app_message_size, &app_message,
        &m_secured_message_callbacks);

    assert_int_equal(LIBSPDM_STATUS_SUCCESS, status);

    for (int index = 0; index < 16; index++) {
        assert_int_equal(index, ((uint8_t *)app_message)[index]);
    }

    /* Sequence number is incremented by one after operation. */
    assert_int_equal(0x1,
                     m_secured_message_context.application_secret.request_data_sequence_number);

    /* Context should stay undetermined. */
    assert_int_equal(LIBSPDM_DATA_SESSION_SEQ_NUM_ENC_LITTLE_DEC_BOTH,
                     m_secured_message_context.sequence_number_endian);

    /* Increment sequence number to 1. The endianness can now be determined.
     * Generated from https://tinyurl.com/yztzj7f4 */
    uint8_t secured_message_1[] = {
        /* Session id. */
        0x33, 0x22, 0x11, 0x00,
        /* Sequence number. */
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* Total length. */
        0x22, 0x00,
        /* Encrypted application data length. */
        0x07, 0x82,
        /* Encrypted application data. */
        0x8a, 0x2d, 0xb9, 0xbf, 0x37, 0x87, 0x0f, 0xc5,
        0xb1, 0xe9, 0xb7, 0x03, 0xee, 0x1d, 0x14, 0xb4,
        /* MAC. */
        0x50, 0xa1, 0x5c, 0x3e, 0xee, 0x27, 0x8f, 0xed,
        0xed, 0xa6, 0x86, 0xaf, 0x31, 0x07, 0xd8, 0x6f
    };

    libspdm_copy_mem(m_secured_message, sizeof(m_secured_message),
                     secured_message_1, sizeof(secured_message_1));

    app_message_size = sizeof(m_app_message);
    app_message = m_app_message;

    status = libspdm_decode_secured_message(
        &m_secured_message_context, session_id, true,
        sizeof(m_secured_message), m_secured_message, &app_message_size, &app_message,
        &m_secured_message_callbacks);

    assert_int_equal(LIBSPDM_STATUS_SUCCESS, status);

    for (int index = 0; index < 16; index++) {
        assert_int_equal(index, ((uint8_t *)app_message)[index]);
    }

    /* Sequence number is incremented by one after operation. */
    assert_int_equal(0x2,
                     m_secured_message_context.application_secret.request_data_sequence_number);

    /* Context should change to big-endian only. */
    assert_int_equal(LIBSPDM_DATA_SESSION_SEQ_NUM_ENC_BIG_DEC_BIG,
                     m_secured_message_context.sequence_number_endian);
}

/**
 * Test 8: Test try-fail decryption.
 *         The message is encrypted with little-endian sequence number but decoder is set to try
 *         big-endian first. The first decryption with sequence number == 0 will pass regardless
 *         of endianness. Endianness will be detected when sequence number == 1.
 *         This uses the same plaintext as test 1.
 **/
static void libspdm_test_secured_message_encode_case8(void **state)
{
    libspdm_return_t status;
    size_t app_message_size = sizeof(m_app_message);
    void *app_message = m_app_message;
    const uint32_t session_id = 0x00112233;

    uint8_t secured_message_0[] = {
        /* Session id. */
        0x33, 0x22, 0x11, 0x00,
        /* Sequence number. */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* Total length. */
        0x22, 0x00,
        /* Encrypted application data length. */
        0x9b, 0xfe,
        /* Encrypted application data. */
        0xd3, 0xb7, 0x04, 0x3d, 0x32, 0x86, 0x60, 0x3d,
        0x86, 0x17, 0x33, 0xd6, 0x7f, 0x95, 0x9a, 0x20,
        /* MAC. */
        0x3d, 0x4f, 0xac, 0x58, 0xcb, 0x70, 0x6c, 0xf5,
        0xa0, 0x27, 0x0a, 0xf6, 0x73, 0xf0, 0xfe, 0x36
    };

    initialize_secured_message_context();
    m_secured_message_context.sequence_number_endian =
        LIBSPDM_DATA_SESSION_SEQ_NUM_ENC_BIG_DEC_BOTH;

    libspdm_copy_mem(m_secured_message, sizeof(m_secured_message),
                     secured_message_0, sizeof(secured_message_0));

    status = libspdm_decode_secured_message(
        &m_secured_message_context, session_id, true,
        sizeof(m_secured_message), m_secured_message, &app_message_size, &app_message,
        &m_secured_message_callbacks);

    assert_int_equal(LIBSPDM_STATUS_SUCCESS, status);

    for (int index = 0; index < 16; index++) {
        assert_int_equal(index, ((uint8_t *)app_message)[index]);
    }

    /* Sequence number is incremented by one after operation. */
    assert_int_equal(0x1,
                     m_secured_message_context.application_secret.request_data_sequence_number);

    /* Context should stay undetermined. */
    assert_int_equal(LIBSPDM_DATA_SESSION_SEQ_NUM_ENC_BIG_DEC_BOTH,
                     m_secured_message_context.sequence_number_endian);

    /* Increment sequence number to 1. The endianness can now be determined. */
    uint8_t secured_message_1[] = {
        /* Session id. */
        0x33, 0x22, 0x11, 0x00,
        /* Sequence number. */
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* Total length. */
        0x22, 0x00,
        /* Encrypted application data length. */
        0xf4, 0x19,
        /* Encrypted application data. */
        0x96, 0xdc, 0xc6, 0x78, 0x5e, 0x8c, 0x74, 0x72,
        0x59, 0xf4, 0x27, 0x22, 0xb9, 0x1b, 0x1f, 0x56,
        /* MAC. */
        0x1d, 0xca, 0x9f, 0x09, 0xd8, 0x80, 0x3a, 0x9a,
        0x54, 0x8e, 0xf0, 0x9b, 0x53, 0xb9, 0xab, 0x1f
    };

    libspdm_copy_mem(m_secured_message, sizeof(m_secured_message),
                     secured_message_1, sizeof(secured_message_1));

    app_message_size = sizeof(m_app_message);
    app_message = m_app_message;

    status = libspdm_decode_secured_message(
        &m_secured_message_context, session_id, true,
        sizeof(m_secured_message), m_secured_message, &app_message_size, &app_message,
        &m_secured_message_callbacks);

    assert_int_equal(LIBSPDM_STATUS_SUCCESS, status);

    for (int index = 0; index < 16; index++) {
        assert_int_equal(index, ((uint8_t *)app_message)[index]);
    }

    /* Sequence number is incremented by one after operation. */
    assert_int_equal(0x2,
                     m_secured_message_context.application_secret.request_data_sequence_number);

    /* Context should change to little-endian only. */
    assert_int_equal(LIBSPDM_DATA_SESSION_SEQ_NUM_ENC_LITTLE_DEC_LITTLE,
                     m_secured_message_context.sequence_number_endian);
}

/**
 * Test 9: Test basic encryption with sequence number set to alternating zeroes and ones
 *         encode :  little endianness.
 *         decode :  little endianness.
 **/
static void libspdm_test_secured_message_encode_case9(void **state) {
    libspdm_return_t status;
    uint8_t encode_app_message[16];
    size_t secured_message_size = sizeof(m_secured_message);
    libspdm_secured_message_context_t encode_secured_message_context;

    const uint32_t session_id = 0x00112233;

    initialize_secured_message_context();
    libspdm_copy_mem(&encode_secured_message_context, sizeof(encode_secured_message_context),
                     &m_secured_message_context, sizeof(m_secured_message_context));
    m_secured_message_context.sequence_number_endian =
        LIBSPDM_DATA_SESSION_SEQ_NUM_ENC_LITTLE_DEC_BOTH;
    encode_secured_message_context.application_secret.request_data_sequence_number =
        0xaa55aa55aa55aa55;

    for (uint8_t index = 0; index < 16; index++) {
        encode_app_message[index] = index;
    }

    libspdm_zero_mem(m_secured_message, sizeof(m_secured_message));
    status = libspdm_encode_secured_message(
        &encode_secured_message_context, session_id, true,
        sizeof(encode_app_message), encode_app_message, &secured_message_size, m_secured_message,
        &m_secured_message_callbacks);

    assert_int_equal(LIBSPDM_STATUS_SUCCESS, status);
    assert_memory_equal(&session_id, m_secured_message, 4);

    /* Sequence number is alternating 0x55 and 0xaa. */
    for (int index = 4; index < 4 + PARTIAL_SEQ_NUM_SIZE; index++) {
        if (index % 2 == 0) {
            assert_int_equal(0x55, m_secured_message[index]);
        } else {
            assert_int_equal(0xaa, m_secured_message[index]);
        }
    }

    assert_int_equal(0x0022, *(uint16_t*)&m_secured_message[4 + PARTIAL_SEQ_NUM_SIZE]);
    assert_int_equal(0xaa55aa55aa55aa56,
                     encode_secured_message_context.application_secret.request_data_sequence_number);

    void *decode_app_message = m_app_message;
    size_t decode_app_message_size = sizeof(m_app_message);
    libspdm_secured_message_context_t decode_secured_message_context;

    initialize_secured_message_context();
    libspdm_copy_mem(&decode_secured_message_context, sizeof(decode_secured_message_context),
                     &m_secured_message_context, sizeof(m_secured_message_context));
    decode_secured_message_context.sequence_number_endian =
        LIBSPDM_DATA_SESSION_SEQ_NUM_ENC_LITTLE_DEC_LITTLE;
    decode_secured_message_context.application_secret.request_data_sequence_number =
        0xaa55aa55aa55aa55;

    status = libspdm_decode_secured_message(
        &decode_secured_message_context, session_id, true,
        sizeof(m_secured_message), m_secured_message, &decode_app_message_size, &decode_app_message,
        &m_secured_message_callbacks);

    assert_int_equal(LIBSPDM_STATUS_SUCCESS, status);

    for (int index = 0; index < 16; index++) {
        assert_int_equal(index, ((uint8_t *)decode_app_message)[index]);
    }

    /* Sequence number is incremented by one after operation. */
    assert_int_equal(0xaa55aa55aa55aa56,
                     decode_secured_message_context.application_secret.request_data_sequence_number);
}

/**
 * Test 10: Test basic encryption with sequence number one and little endianness.
 *          encode : big endianness.
 *          decode : little endianness.
 **/
static void libspdm_test_secured_message_encode_case10(void **state)
{
    libspdm_return_t status;
    uint8_t encode_app_message[16];
    size_t secured_message_size = sizeof(m_secured_message);
    libspdm_secured_message_context_t encode_secured_message_context;

    const uint32_t session_id = 0x00112233;

    initialize_secured_message_context();
    libspdm_copy_mem(&encode_secured_message_context, sizeof(encode_secured_message_context),
                     &m_secured_message_context, sizeof(m_secured_message_context));

    encode_secured_message_context.sequence_number_endian =
        LIBSPDM_DATA_SESSION_SEQ_NUM_ENC_BIG_DEC_BOTH;
    encode_secured_message_context.application_secret.request_data_sequence_number =
        0x0000000000000001;

    for (uint8_t index = 0; index < 16; index++) {
        encode_app_message[index] = index;
    }

    libspdm_zero_mem(m_secured_message, sizeof(m_secured_message));
    status = libspdm_encode_secured_message(
        &encode_secured_message_context, session_id, true,
        sizeof(encode_app_message), encode_app_message, &secured_message_size, m_secured_message,
        &m_secured_message_callbacks);

    assert_int_equal(LIBSPDM_STATUS_SUCCESS, status);
    assert_memory_equal(&session_id, m_secured_message, 4);

    for (int index = 4; index < 4 + PARTIAL_SEQ_NUM_SIZE; index++) {
        if (index == 4) {
            assert_int_equal(0x01, m_secured_message[index]);
        } else {
            assert_int_equal(0x00, m_secured_message[index]);
        }
    }

    assert_int_equal(0x0022, *(uint16_t*)&m_secured_message[4 + PARTIAL_SEQ_NUM_SIZE]);
    assert_int_equal(0x000000000000002,
                     encode_secured_message_context.application_secret.request_data_sequence_number);

    void *decode_app_message = m_app_message;
    size_t decode_app_message_size = sizeof(m_app_message);
    libspdm_secured_message_context_t decode_secured_message_context;

    libspdm_copy_mem(&decode_secured_message_context, sizeof(decode_secured_message_context),
                     &m_secured_message_context, sizeof(m_secured_message_context));
    decode_secured_message_context.application_secret.request_data_sequence_number =
        0x0000000000000001;
    decode_secured_message_context.sequence_number_endian =
        LIBSPDM_DATA_SESSION_SEQ_NUM_ENC_LITTLE_DEC_BOTH;

    status = libspdm_decode_secured_message(
        &decode_secured_message_context, session_id, true,
        sizeof(m_secured_message), m_secured_message, &decode_app_message_size, &decode_app_message,
        &m_secured_message_callbacks);

    assert_int_equal(LIBSPDM_STATUS_SUCCESS, status);

    for (int index = 0; index < 16; index++) {
        assert_int_equal(index, ((uint8_t *)decode_app_message)[index]);
    }

    /* Sequence number is incremented by one after operation. */
    assert_int_equal(0x0000000000000002,
                     decode_secured_message_context.application_secret.request_data_sequence_number);
}

/**
 * Test 11: Test a message authentication only session with the sequence number set to zeroes and ones.
 *          encode :  big endianness.
 *          decode :  big endianness.
 **/
static void libspdm_test_secured_message_encode_case11(void **state)
{
    libspdm_return_t status;
    uint8_t encode_app_message[16];
    size_t secured_message_size = sizeof(m_secured_message);
    libspdm_secured_message_context_t encode_secured_message_context;

    const uint32_t session_id = 0x00112233;
    uint8_t *ptr;

    initialize_secured_message_context();
    libspdm_copy_mem(&encode_secured_message_context, sizeof(encode_secured_message_context),
                     &m_secured_message_context, sizeof(encode_secured_message_context));

    encode_secured_message_context.sequence_number_endian =
        LIBSPDM_DATA_SESSION_SEQ_NUM_ENC_BIG_DEC_BOTH;
    encode_secured_message_context.session_type = LIBSPDM_SESSION_TYPE_MAC_ONLY;
    encode_secured_message_context.application_secret.request_data_sequence_number =
        0xaa55aa55aa55aa55;

    for (uint8_t index = 0; index < 16; index++) {
        encode_app_message[index] = index;
    }

    libspdm_zero_mem(m_secured_message, sizeof(m_secured_message));
    status = libspdm_encode_secured_message(
        &encode_secured_message_context, session_id, true,
        sizeof(encode_app_message), encode_app_message, &secured_message_size, m_secured_message,
        &m_secured_message_callbacks);

    assert_int_equal(LIBSPDM_STATUS_SUCCESS, status);
    assert_memory_equal(&session_id, m_secured_message, 4);

    /* Sequence number is alternating 0x55 and 0xaa. */
    for (int index = 4; index < 4 + PARTIAL_SEQ_NUM_SIZE; index++) {
        if (index % 2 == 0) {
            assert_int_equal(0x55, m_secured_message[index]);
        } else {
            assert_int_equal(0xaa, m_secured_message[index]);
        }
    }

    assert_int_equal(0x0020, *(uint16_t*)&m_secured_message[4 + PARTIAL_SEQ_NUM_SIZE]);
    assert_int_equal(0xaa55aa55aa55aa56,
                     encode_secured_message_context.application_secret.request_data_sequence_number);

    ptr = (uint8_t *)&m_secured_message + 6 + PARTIAL_SEQ_NUM_SIZE;
    for (int index = 0; index < 16; index++) {
        assert_int_equal(index, ((uint8_t *)ptr)[index]);
    }

    void *decode_app_message = m_app_message;
    size_t decode_app_message_size = sizeof(m_app_message);
    libspdm_secured_message_context_t decode_secured_message_context;
    libspdm_copy_mem(
        &decode_secured_message_context, sizeof(encode_secured_message_context),
        &m_secured_message_context, sizeof(m_secured_message_context));

    decode_secured_message_context.sequence_number_endian =
        LIBSPDM_DATA_SESSION_SEQ_NUM_ENC_BIG_DEC_BOTH;
    decode_secured_message_context.session_type = LIBSPDM_SESSION_TYPE_MAC_ONLY;
    decode_secured_message_context.application_secret.request_data_sequence_number =
        0xaa55aa55aa55aa55;

    status = libspdm_decode_secured_message(
        &decode_secured_message_context, session_id, true,
        sizeof(m_secured_message), m_secured_message, &decode_app_message_size, &decode_app_message,
        &m_secured_message_callbacks);

    assert_int_equal(LIBSPDM_STATUS_SUCCESS, status);

    for (int index = 0; index < 16; index++) {
        assert_int_equal(index, ((uint8_t *)decode_app_message)[index]);
    }

    /* Sequence number is incremented by one after operation. */
    assert_int_equal(0xaa55aa55aa55aa56,
                     decode_secured_message_context.application_secret.request_data_sequence_number);
}

/**
 * Test 12: Test a message authentication only session with the sequence number one.
 *          encode :  little endianness.
 *          decode :  big endianness.
 **/
static void libspdm_test_secured_message_encode_case12(void **state)
{
    libspdm_return_t status;
    uint8_t encode_app_message[16];
    size_t secured_message_size = sizeof(m_secured_message);
    libspdm_secured_message_context_t encode_secured_message_context;

    const uint32_t session_id = 0x00112233;
    uint8_t *ptr;

    initialize_secured_message_context();
    libspdm_copy_mem(&encode_secured_message_context, sizeof(encode_secured_message_context),
                     &m_secured_message_context, sizeof(encode_secured_message_context));

    encode_secured_message_context.sequence_number_endian =
        LIBSPDM_DATA_SESSION_SEQ_NUM_ENC_LITTLE_DEC_BOTH;
    encode_secured_message_context.session_type = LIBSPDM_SESSION_TYPE_MAC_ONLY;
    encode_secured_message_context.application_secret.request_data_sequence_number =
        0x0000000000000001;

    for (uint8_t index = 0; index < 16; index++) {
        encode_app_message[index] = index;
    }

    libspdm_zero_mem(m_secured_message, sizeof(m_secured_message));
    status = libspdm_encode_secured_message(
        &encode_secured_message_context, session_id, true,
        sizeof(encode_app_message), encode_app_message, &secured_message_size, m_secured_message,
        &m_secured_message_callbacks);

    assert_int_equal(LIBSPDM_STATUS_SUCCESS, status);
    assert_memory_equal(&session_id, m_secured_message, 4);

    /* Sequence number is alternating 0x55 and 0xaa. */
    for (int index = 4; index < 4 + PARTIAL_SEQ_NUM_SIZE; index++) {
        if (index == 4) {
            assert_int_equal(0x01, m_secured_message[index]);
        } else {
            assert_int_equal(0x00, m_secured_message[index]);
        }
    }

    assert_int_equal(0x0020, *(uint16_t*)&m_secured_message[4 + PARTIAL_SEQ_NUM_SIZE]);
    assert_int_equal(0x0000000000000002,
                     encode_secured_message_context.application_secret.request_data_sequence_number);

    ptr = (uint8_t *)&m_secured_message + 6 + PARTIAL_SEQ_NUM_SIZE;
    for (int index = 0; index < 16; index++) {
        assert_int_equal(index, ((uint8_t *)ptr)[index]);
    }

    void *decode_app_message = m_app_message;
    size_t decode_app_message_size = sizeof(m_app_message);
    libspdm_secured_message_context_t decode_secured_message_context;
    libspdm_copy_mem(
        &decode_secured_message_context, sizeof(encode_secured_message_context),
        &m_secured_message_context, sizeof(m_secured_message_context));

    decode_secured_message_context.sequence_number_endian =
        LIBSPDM_DATA_SESSION_SEQ_NUM_ENC_BIG_DEC_BOTH;
    decode_secured_message_context.session_type = LIBSPDM_SESSION_TYPE_MAC_ONLY;
    decode_secured_message_context.application_secret.request_data_sequence_number =
        0x0000000000000001;

    status = libspdm_decode_secured_message(
        &decode_secured_message_context, session_id, true,
        sizeof(m_secured_message), m_secured_message, &decode_app_message_size, &decode_app_message,
        &m_secured_message_callbacks);

    assert_int_equal(LIBSPDM_STATUS_SUCCESS, status);

    for (int index = 0; index < 16; index++) {
        assert_int_equal(index, ((uint8_t *)decode_app_message)[index]);
    }

    /* Sequence number is incremented by one after operation. */
    assert_int_equal(0x0000000000000002,
                     decode_secured_message_context.application_secret.request_data_sequence_number);
}

libspdm_test_context_t m_libspdm_common_context_data_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    NULL,
    NULL,
};

int libspdm_secured_message_encode_decode_test_main(void)
{
    const struct CMUnitTest spdm_secured_message_encode_decode_tests[] = {
        cmocka_unit_test(libspdm_test_secured_message_encode_case1),
        cmocka_unit_test(libspdm_test_secured_message_encode_case2),
        cmocka_unit_test(libspdm_test_secured_message_encode_case3),
        cmocka_unit_test(libspdm_test_secured_message_encode_case4),
        cmocka_unit_test(libspdm_test_secured_message_encode_case5),
        cmocka_unit_test(libspdm_test_secured_message_encode_case6),
        cmocka_unit_test(libspdm_test_secured_message_encode_case7),
        cmocka_unit_test(libspdm_test_secured_message_encode_case8),
        cmocka_unit_test(libspdm_test_secured_message_encode_case9),
        cmocka_unit_test(libspdm_test_secured_message_encode_case10),
        cmocka_unit_test(libspdm_test_secured_message_encode_case11),
        cmocka_unit_test(libspdm_test_secured_message_encode_case12),
    };

    libspdm_setup_test_context(&m_libspdm_common_context_data_test_context);

    return cmocka_run_group_tests(spdm_secured_message_encode_decode_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}
