/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#define LIBSPDM_MAX_CERT_CHAIN_SIZE 0x2000

#include "spdm_unit_test.h"
#include "library/spdm_common_lib.h"
#include "spdm_crypt_ext_lib/spdm_crypt_ext_lib.h"
#include "spdm_cert_verify_callback_sample/spdm_cert_verify_callback_internal.h"

/*read cert chain or root cert with dice extension*/
bool libspdm_read_dice_certificate_chain(
    void **data, size_t *size, bool is_cert_chain)
{
    bool res;
    void *file_data;
    size_t file_size;
    char *file;

    *data = NULL;
    *size = 0;

    if (is_cert_chain) {
        file = "dice_cert/dice_cert_chain.bin";
    } else {
        file = "dice_cert/dice_root_cert.der";
    }

    res = libspdm_read_input_file(file, &file_data, &file_size);
    if (!res) {
        return res;
    }

    *data = file_data;
    *size = file_size;

    return true;
}

void libspdm_test_spdm_verify_cert_chain_callback_function(void **state)
{
    bool status;
    libspdm_context_t *spdm_context;
    uint8_t slot_id;
    void *spdm_cert_chain_with_dicetcbinfo;
    size_t spdm_cert_chain_size_with_dicetcbinfo;
    void *spdm_root_cert_for_dicetcbinfo;
    size_t spdm_root_cert_size_for_dicetcbinfo;

    spdm_context = (void *)malloc(libspdm_get_context_size());
    if (spdm_context == NULL) {
        assert_true(false);
    }
    libspdm_init_context(spdm_context);
    spdm_context->local_context.is_requester = true;
    spdm_context->connection_info.algorithm.base_hash_algo =
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384;
    spdm_context->connection_info.algorithm.base_asym_algo =
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384;
    slot_id = 0;

    status = libspdm_read_dice_certificate_chain(&spdm_root_cert_for_dicetcbinfo,
                                                 &spdm_root_cert_size_for_dicetcbinfo, false);
    assert_true(status);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        spdm_root_cert_size_for_dicetcbinfo;
    spdm_context->local_context.peer_root_cert_provision[0] =
        (uint8_t *)spdm_root_cert_for_dicetcbinfo;

    status = libspdm_read_dice_certificate_chain(&spdm_cert_chain_with_dicetcbinfo,
                                                 &spdm_cert_chain_size_with_dicetcbinfo, true);
    assert_true(status);

    /*verify dice cert chain by using call back function*/
    status = libspdm_verify_spdm_cert_chain_with_dice(spdm_context, slot_id,
                                                      spdm_cert_chain_size_with_dicetcbinfo,
                                                      spdm_cert_chain_with_dicetcbinfo, NULL, NULL);
    assert_true(status);

    free(spdm_root_cert_for_dicetcbinfo);
    free(spdm_cert_chain_with_dicetcbinfo);
    free(spdm_context);
}

void libspdm_test_spdm_verify_cert_dicetcdinfo(void **state)
{
    bool status;
    void *file_data;
    size_t file_size;
    char *file;
    size_t cert_dice_tcb_info_size;

    file = "dice_cert/dice_cert.bin";
    cert_dice_tcb_info_size = 0;

    libspdm_read_input_file(file, &file_data, &file_size);

    /*verify dice cert*/
    status = libspdm_verify_cert_dicetcbinfo(file_data, file_size, &cert_dice_tcb_info_size);
    assert_true(status);
    free(file_data);
}

int libspdm_spdm_sample_setup(void **state)
{
    return 0;
}

int libspdm_spdm_sample_teardown(void **state)
{
    return 0;
}

int libspdm_spdm_sample_test_main(void)
{
    const struct CMUnitTest spdm_sample_tests[] = {
        cmocka_unit_test(
            libspdm_test_spdm_verify_cert_chain_callback_function),
        cmocka_unit_test(
            libspdm_test_spdm_verify_cert_dicetcdinfo),
    };

    return cmocka_run_group_tests(spdm_sample_tests,
                                  libspdm_spdm_sample_setup,
                                  libspdm_spdm_sample_teardown);
}

int main(void)
{
    int return_value = 0;

    if (libspdm_spdm_sample_test_main() != 0) {
        return_value = 1;
    }

    return return_value;
}
