/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/
#include "test_crypt.h"
#include "industry_standard/spdm.h"
#include "spdm_device_secret_lib_sample/spdm_device_secret_lib_internal.h"

static uint8_t m_libspdm_oid_subject_alt_name[] = { 0x55, 0x1D, 0x11 };

/**
 * save the CSR
 *
 * @param[out] csr_len               CSR len for DER format
 * @param[in]  csr_pointer           csr_pointer is address to store CSR.
 * @param[in]  base_asym_algo        To distinguish file
 *
 * @retval true                      successfully.
 * @retval false                     unsuccessfully.
 **/
bool libspdm_write_csr_to_file(const void * csr_pointer, size_t csr_len, uint32_t base_asym_algo)
{
    FILE *fp_out;
    char* file_name;

    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
        file_name = "rsa2048.csr";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
        file_name = "rsa3072.csr";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        file_name = "rsa4096.csr";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        file_name = "ecp256.csr";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        file_name = "ecp384.csr";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        file_name = "ecp521.csr";
        break;
    default:
        return false;
    }

    if ((fp_out = fopen(file_name, "w+b")) == NULL) {
        printf("Unable to open file %s\n", file_name);
        return false;
    }

    if ((fwrite(csr_pointer, 1, csr_len, fp_out)) != csr_len) {
        printf("Write output file error %s\n", file_name);
        fclose(fp_out);
        return false;
    }

    fclose(fp_out);

    return true;
}


/**
 * Validate Crypto X509 certificate Verify
 *
 * @retval  true  Validation succeeded.
 * @retval  false  Validation failed.
 *
 **/
bool libspdm_validate_crypt_x509(char *Path, size_t len)
{
    bool status;
    const uint8_t *leaf_cert;
    size_t leaf_cert_len;
    uint8_t *test_cert;
    size_t test_cert_len;
    uint8_t *test_ca_cert;
    size_t test_ca_cert_len;
    uint8_t *test_bundle_cert;
    size_t test_bundle_cert_len;
    uint8_t *test_end_cert;
    size_t test_end_cert_len;
    size_t subject_size;
    uint8_t *subject;
    size_t common_name_size;
    char common_name[64];
    size_t cert_version;
    uint8_t asn1_buffer[1024];
    size_t asn1_buffer_len;
    uint8_t end_cert_from[64];
    size_t end_cert_from_len;
    uint8_t end_cert_to[64];
    size_t end_cert_to_len;
    uint8_t date_time1[64];
    uint8_t date_time2[64];
    char file_name_buffer[1024];

    test_cert = NULL;
    test_ca_cert = NULL;
    test_bundle_cert = NULL;
    test_end_cert = NULL;

    libspdm_zero_mem(file_name_buffer, 1024);
    libspdm_copy_mem(file_name_buffer, sizeof(file_name_buffer), Path, len);
    libspdm_copy_mem(file_name_buffer + len - 1, sizeof(file_name_buffer) - (len - 1),
                     "/inter.cert.der", sizeof("/inter.cert.der"));
    status = libspdm_read_input_file(file_name_buffer, (void **)&test_cert,
                                     &test_cert_len);
    if (!status) {
        goto cleanup;
    }

    libspdm_zero_mem(file_name_buffer, 1024);
    libspdm_copy_mem(file_name_buffer, sizeof(file_name_buffer), Path, len);
    libspdm_copy_mem(file_name_buffer + len - 1, sizeof(file_name_buffer) - (len - 1),
                     "/ca.cert.der", sizeof("/ca.cert.der"));
    status = libspdm_read_input_file(file_name_buffer, (void **)&test_ca_cert,
                                     &test_ca_cert_len);
    if (!status) {
        goto cleanup;
    }

    libspdm_zero_mem(file_name_buffer, 1024);
    libspdm_copy_mem(file_name_buffer, sizeof(file_name_buffer), Path, len);
    libspdm_copy_mem(file_name_buffer + len - 1, sizeof(file_name_buffer) - (len - 1),
                     "/bundle_requester.certchain.der", sizeof("/bundle_requester.certchain.der"));
    status = libspdm_read_input_file(file_name_buffer, (void **)&test_bundle_cert,
                                     &test_bundle_cert_len);
    if (!status) {
        goto cleanup;
    }

    libspdm_zero_mem(file_name_buffer, 1024);
    libspdm_copy_mem(file_name_buffer, sizeof(file_name_buffer), Path, len);
    libspdm_copy_mem(file_name_buffer + len - 1, sizeof(file_name_buffer) - (len - 1),
                     "/end_requester.cert.der", sizeof("/end_requester.cert.der"));
    status = libspdm_read_input_file(file_name_buffer, (void **)&test_end_cert,
                                     &test_end_cert_len);
    if (!status) {
        goto cleanup;
    }

    /* X509 Certificate Verification.*/
    libspdm_my_print("\n- X509 Certificate Verification with Trusted CA ...");
    status = libspdm_x509_verify_cert(test_cert, test_cert_len, test_ca_cert,
                                      test_ca_cert_len);
    if (!status) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    } else {
        libspdm_my_print("[Pass]\n");
    }


    /* X509 Certificate Chain Verification.*/

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "- X509 Certificate Chain Verification ... "));
    status = libspdm_x509_verify_cert_chain((const uint8_t *)test_ca_cert, test_ca_cert_len,
                                            (const uint8_t *)test_bundle_cert,
                                            test_bundle_cert_len);
    if (!status) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    } else {
        libspdm_my_print("[Pass]\n");
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                   "- X509 Certificate CA cert verify itself Verification ... "));
    status = libspdm_x509_verify_cert_chain((const uint8_t *)test_ca_cert, test_ca_cert_len,
                                            (const uint8_t *)test_ca_cert,
                                            test_ca_cert_len);
    if (!status) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    } else {
        libspdm_my_print("[Pass]\n");
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                   "- X509 Certificate CA cert verify itself Verification with large cert len"));
    status = libspdm_x509_verify_cert_chain((const uint8_t *)test_ca_cert, test_ca_cert_len,
                                            (const uint8_t *)test_ca_cert,
                                            test_ca_cert_len + 1);
    if (!status) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    } else {
        libspdm_my_print("[Pass]\n");
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                   "- X509 Certificate end cert verify itself Verification ... "));
    status = libspdm_x509_verify_cert_chain((const uint8_t *)test_end_cert, test_end_cert_len,
                                            (const uint8_t *)test_end_cert,
                                            test_end_cert_len);
    if (status) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    } else {
        libspdm_my_print("[Pass]\n");
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                   "- X509 Certificate end cert verify itself Verification with large cert len"));
    status = libspdm_x509_verify_cert_chain((const uint8_t *)test_end_cert, test_end_cert_len,
                                            (const uint8_t *)test_end_cert,
                                            test_end_cert_len + 1);
    if (status) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    } else {
        libspdm_my_print("[Pass]\n");
    }


    /* X509 Get leaf certificate from cert_chain Verificate*/
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                   "- X509 Certificate Chain get leaf certificate Verification ... "));
    status = libspdm_x509_get_cert_from_cert_chain(test_bundle_cert,
                                                   test_bundle_cert_len, -1,
                                                   &leaf_cert, &leaf_cert_len);
    if (!status) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    }
    if (leaf_cert_len != test_end_cert_len) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    }
    if (memcmp(leaf_cert, test_end_cert, leaf_cert_len) != 0) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    } else {
        libspdm_my_print("[Pass]\n");
    }

    /* X509 Get leaf certificate from cert_chain Verificate*/
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                   "- X509 Certificate Chain get leaf certificate Verification ... "));
    status = libspdm_x509_get_cert_from_cert_chain(test_bundle_cert,
                                                   test_bundle_cert_len, 2,
                                                   &leaf_cert, &leaf_cert_len);
    if (!status) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    }
    if (leaf_cert_len != test_end_cert_len) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    }
    if (memcmp(leaf_cert, test_end_cert, leaf_cert_len) != 0) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    } else {
        libspdm_my_print("[Pass]\n");
    }

    /* X509 Get root certificate from cert_chain Verificate*/
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                   "- X509 Certificate Chain get root certificate Verification ... "));
    status = libspdm_x509_get_cert_from_cert_chain(test_bundle_cert,
                                                   test_bundle_cert_len, 0,
                                                   &leaf_cert, &leaf_cert_len);
    if (!status) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    }
    if (leaf_cert_len != test_ca_cert_len) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    }
    if (memcmp(leaf_cert, test_ca_cert, leaf_cert_len) != 0) {
        libspdm_my_print("[Fail]\n");
        goto cleanup;
    } else {
        libspdm_my_print("[Pass]\n");
    }

    /* X509 Certificate subject Retrieving.*/
    libspdm_my_print("- X509 Certificate subject Bytes Retrieving ... ");
    subject_size = 0;
    status = libspdm_x509_get_subject_name(test_cert, test_cert_len, NULL,
                                           &subject_size);
    subject = (uint8_t *)allocate_pool(subject_size);
    status = libspdm_x509_get_subject_name(test_cert, test_cert_len, subject,
                                           &subject_size);
    free_pool(subject);
    if (!status) {
        libspdm_my_print("[Fail]");
        goto cleanup;
    } else {
        libspdm_my_print("[Pass]");
    }

    libspdm_my_print("\n- X509 Certificate context Retrieving ... ");

    /* Get common_name from X509 Certificate subject*/
    common_name_size = 64;
    libspdm_zero_mem(common_name, common_name_size);
    status = libspdm_x509_get_common_name(test_cert, test_cert_len, common_name,
                                          &common_name_size);
    if (!status) {
        libspdm_my_print("\n  - Retrieving Common name - [Fail]");
        goto cleanup;
    } else {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "\n  - Retrieving Common name = \"%s\" (size = %zu)",
                       common_name, common_name_size));
        libspdm_my_print(" - [PASS]");
    }

    /* Get Issuer OrganizationName from X509 Certificate subject*/
    common_name_size = 64;
    libspdm_zero_mem(common_name, common_name_size);
    status = libspdm_x509_get_organization_name(test_cert, test_cert_len, common_name,
                                                &common_name_size);
    if (status || common_name_size != 0) {
        libspdm_my_print("\n  - Retrieving Oraganization name - [Fail]");
        goto cleanup;
    } else {
        libspdm_my_print("\n  - Retrieving Oraganization name - [PASS]");
    }

    /* Get version from X509 Certificate*/
    cert_version = 0;
    status = libspdm_x509_get_version(test_cert, test_cert_len, &cert_version);
    if (!status) {
        libspdm_my_print("\n  - Retrieving version - [Fail]");
        goto cleanup;
    } else {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n  - Retrieving version = %zu - ",
                       cert_version));
        libspdm_my_print("[Pass]");
    }

    /* Get Serial from X509 Certificate*/
    asn1_buffer_len = 1024;
    libspdm_zero_mem(asn1_buffer, asn1_buffer_len);
    status = libspdm_x509_get_serial_number(test_cert, test_cert_len, asn1_buffer,
                                            &asn1_buffer_len);
    if (!status) {
        libspdm_my_print("\n  - Retrieving serial_number - [Fail]");
        goto cleanup;
    } else {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n  - Retrieving serial_number = %llu - ",
                       *((uint64_t *)asn1_buffer)));
        libspdm_my_print("[Pass]");
    }

    /* X509 Certificate subject Retrieving.*/
    libspdm_my_print("\n  - Retrieving issuer Bytes ... ");
    subject_size = 0;
    status = libspdm_x509_get_issuer_name(test_cert, test_cert_len, NULL,
                                          &subject_size);
    subject = (uint8_t *)allocate_pool(subject_size);
    status = libspdm_x509_get_issuer_name(test_cert, test_cert_len, subject,
                                          &subject_size);
    free_pool(subject);
    if (!status) {
        libspdm_my_print("[Fail]");
        goto cleanup;
    } else {
        libspdm_my_print(" - [Pass]");
    }

    /* Get Issuer common_name from X509 Certificate subject*/
    common_name_size = 64;
    libspdm_zero_mem(common_name, common_name_size);
    status = libspdm_x509_get_issuer_common_name(test_cert, test_cert_len, common_name,
                                                 &common_name_size);
    if (!status) {
        libspdm_my_print("\n  - Retrieving Issuer Common name - [Fail]");
        goto cleanup;
    } else {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "\n  - Retrieving Issuer Common name = \"%s\" (size = %zu) - ",
                       common_name, common_name_size));
        libspdm_my_print("[Pass]");
    }

    /* Get Issuer OrganizationName from X509 Certificate subject*/
    common_name_size = 64;
    libspdm_zero_mem(common_name, common_name_size);
    status = libspdm_x509_get_issuer_orgnization_name(test_cert, test_cert_len,
                                                      common_name, &common_name_size);
    if (status || common_name_size != 0) {
        libspdm_my_print("\n  - Retrieving Issuer Oraganization name - [Fail]");
        goto cleanup;
    } else {
        libspdm_my_print("\n  - Retrieving Issuer Oraganization name - [Pass]");
    }

    /* Get X509GetSubjectAltName*/
    asn1_buffer_len = 1024;
    libspdm_zero_mem(asn1_buffer, asn1_buffer_len);
    status = libspdm_x509_get_extension_data(test_end_cert, test_end_cert_len,
                                             m_libspdm_oid_subject_alt_name,
                                             sizeof(m_libspdm_oid_subject_alt_name),
                                             asn1_buffer, &asn1_buffer_len);
    if (!status) {
        libspdm_my_print("\n  - Retrieving  SubjectAltName otherName - [Fail]");
        goto cleanup;
    } else {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "\n  - Retrieving  SubjectAltName (size = %zu) ",
                       asn1_buffer_len));
        libspdm_my_print("- [Pass]");
    }

    /* Get X509 Validity*/
    end_cert_from_len = 64;
    end_cert_to_len = 64;
    status = libspdm_x509_get_validity(test_end_cert, test_end_cert_len,
                                       end_cert_from, &end_cert_from_len,
                                       end_cert_to, &end_cert_to_len);
    if (!status) {
        libspdm_my_print("\n  - Retrieving Validity - [Fail]");
        goto cleanup;
    } else {
        libspdm_my_print("\n  - Retrieving Validity - [Pass]");
    }

    asn1_buffer_len = 64;
    status = libspdm_x509_set_date_time("19700101000000Z", date_time1,
                                        &asn1_buffer_len);
    if (status && (asn1_buffer_len != 0)) {
        libspdm_my_print("\n  - Set date_time - [Pass]");
    } else {
        libspdm_my_print("\n  - Set date_time - [Fail]");
        goto cleanup;
    }

    asn1_buffer_len = 64;
    status = libspdm_x509_set_date_time("19700201000000Z", date_time2,
                                        &asn1_buffer_len);
    if (status && (asn1_buffer_len != 0)) {
        libspdm_my_print("\n  - Set date_time - [Pass]");
    } else {
        libspdm_my_print("\n  - Set date_time - [Fail]");
        goto cleanup;
    }

    if (libspdm_x509_compare_date_time(date_time1, date_time2) < 0) {
        libspdm_my_print("\n  - Compare date_time - [Pass]");
    } else {
        libspdm_my_print("\n  - Compare date_time- [Fail]");
        goto cleanup;
    }

    libspdm_my_print("\n");
    status = true;

cleanup:
    if (test_cert != NULL) {
        free(test_cert);
    }
    if (test_ca_cert != NULL) {
        free(test_ca_cert);
    }
    if (test_bundle_cert != NULL) {
        free(test_bundle_cert);
    }
    if (test_end_cert != NULL) {
        free(test_end_cert);
    }
    return status;
}

void libspdm_dump_hex_str(const uint8_t *buffer, size_t buffer_size)
{
    size_t index;

    for (index = 0; index < buffer_size; index++) {
        printf("%02x", buffer[index]);
    }
}
