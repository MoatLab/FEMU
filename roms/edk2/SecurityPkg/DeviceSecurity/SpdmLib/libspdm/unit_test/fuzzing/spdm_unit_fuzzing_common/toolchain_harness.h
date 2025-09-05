/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef _TOOLCHAIN_HARNESS_LIB_
#define _TOOLCHAIN_HARNESS_LIB_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define LIBSPDM_TEST_ALIGNMENT 4
#define LIBSPDM_TEST_MESSAGE_TYPE_SPDM 0x01
#define LIBSPDM_TEST_MESSAGE_TYPE_SECURED_TEST 0x02
#define LIBSPDM_MAX_BUFFER_SIZE 64

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size);

size_t libspdm_get_max_buffer_size(void);

size_t libspdm_alignment_size(size_t size);

#endif
