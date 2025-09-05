/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <base.h>
#include "spdm_cert_verify_callback_internal.h"

/**
 * tcg-dice-TcbInfo OID: 2.23.133.5.4.1
 * https://trustedcomputinggroup.org/wp-content/uploads/DICE-Attestation-Architecture-Version-1.1-Revision-18_pub.pdf
 **/
uint8_t m_libspdm_tcg_dice_tcbinfo_oid[] = {0x67, 0x81, 0x05, 0x05, 0x04, 0x01};

/*the cert chain must have a or more cert with DiceTcbInfo extension*/
bool m_libspdm_must_have_dice_tcb_info = true;

/*the reference cert number with DiceTcbinfo in the cert chain*/
uint8_t m_libspdm_dice_tcb_info_number = 1;

/*reference DiceTcbinfo*/

/*vendor: INTC*/
uint8_t m_libspdm_dice_tcbinfo_vendor[] = {0x49, 0x4E, 0x54, 0x43};
/*model: S3M GNR*/
uint8_t m_libspdm_dice_tcbinfo_model[] = {0x53, 0x33, 0x4D, 0x20, 0x47, 0x4E, 0x52};
/*version: 000200000000008B*/
uint8_t m_libspdm_dice_tcbinfo_version[] = {0x30, 0x30, 0x30, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30,
                                            0x30, 0x30, 0x30, 0x30, 0x30, 0x38, 0x42};
/*svn*/
uint8_t m_libspdm_dice_tcbinfo_svn[] = {0x01};
/*layer*/
uint8_t m_libspdm_dice_tcbinfo_layer[] = {0x01};
/*fwids*/
uint8_t m_libspdm_dice_tcbinfo_fwids[] = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                                          0x02, 0x02, 0x04, 0x30, 0x6B, 0x44, 0x7B, 0x5E, 0x99,
                                          0x21, 0x0A, 0x58, 0x8A, 0x7B, 0x31, 0x7D, 0xBA, 0x2D,
                                          0x4A, 0x7F, 0x75, 0xE6, 0x97, 0xF2, 0x07, 0xE0, 0xC2,
                                          0x99, 0x78, 0xF3, 0xF6, 0x2B, 0x53, 0xF5, 0xBE, 0xEB,
                                          0x73, 0xF0, 0x37, 0xB8, 0x79, 0xC1, 0xFF, 0x76, 0x2A,
                                          0x3A, 0x39, 0xCA, 0xE2, 0x8C, 0xF0, 0x56};
/*type*/
uint8_t m_libspdm_dice_tcbinfo_type[] = {0x46, 0x69, 0x72, 0x6D, 0x77, 0x61, 0x72, 0x65, 0x20,
                                         0x44, 0x69, 0x67, 0x65, 0x73, 0x74};

/*verify cert DiceTcbInfo extension*/
bool libspdm_verify_cert_dicetcbinfo(const void *cert, size_t cert_size,
                                     size_t *spdm_get_dice_tcb_info_size) {
    bool result;
    uint8_t spdm_dice_tcb_info[256];
    size_t spdm_dice_tcb_info_size;
    uint8_t *ptr;
    int32_t length;
    size_t obj_len;
    uint8_t *end;

    spdm_dice_tcb_info_size = 256;
    *spdm_get_dice_tcb_info_size = 0;
    result = libspdm_x509_get_extension_data(cert, cert_size,
                                             m_libspdm_tcg_dice_tcbinfo_oid,
                                             sizeof(m_libspdm_tcg_dice_tcbinfo_oid),
                                             spdm_dice_tcb_info, &spdm_dice_tcb_info_size);
    if (!result) {
        return false;
    } else if (spdm_dice_tcb_info_size == 0) {
        return true;
    }

    *spdm_get_dice_tcb_info_size = spdm_dice_tcb_info_size;
    length = (int32_t)spdm_dice_tcb_info_size;
    ptr = (uint8_t*)(size_t)spdm_dice_tcb_info;
    obj_len = 0;
    end = ptr + length;

    /*get DiceTcbInfo*/
    result = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                  LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!result) {
        *spdm_get_dice_tcb_info_size = 0;
        return false;
    }
    result = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                  LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!result) {
        *spdm_get_dice_tcb_info_size = 0;
        return false;
    }

    /*vendor*/
    result = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                  LIBSPDM_CRYPTO_ASN1_CONTEXT_SPECIFIC);
    if (result) {
        if ((obj_len != sizeof(m_libspdm_dice_tcbinfo_vendor)) ||
            (!libspdm_consttime_is_mem_equal(ptr, m_libspdm_dice_tcbinfo_vendor, obj_len))) {
            return false;
        }
        ptr += obj_len;
    } else {
        return false;
    }
    /*model*/
    result = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                  LIBSPDM_CRYPTO_ASN1_CONTEXT_SPECIFIC + 1);
    if (result) {
        if ((obj_len != sizeof(m_libspdm_dice_tcbinfo_model)) ||
            (!libspdm_consttime_is_mem_equal(ptr, m_libspdm_dice_tcbinfo_model, obj_len))) {
            return false;
        }
        ptr += obj_len;
    } else {
        return false;
    }
    /*version*/
    result = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                  LIBSPDM_CRYPTO_ASN1_CONTEXT_SPECIFIC + 2);
    if (result) {
        if ((obj_len != sizeof(m_libspdm_dice_tcbinfo_version)) ||
            (!libspdm_consttime_is_mem_equal(ptr, m_libspdm_dice_tcbinfo_version, obj_len))) {
            return false;
        }
        ptr += obj_len;
    } else {
        return false;
    }
    /*svn*/
    result = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                  LIBSPDM_CRYPTO_ASN1_CONTEXT_SPECIFIC + 3);
    if (result) {
        if ((obj_len != sizeof(m_libspdm_dice_tcbinfo_svn)) ||
            (!libspdm_consttime_is_mem_equal(ptr, m_libspdm_dice_tcbinfo_svn, obj_len))) {
            return false;
        }
        ptr += obj_len;
    } else {
        return false;
    }
    /*layer*/
    result = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                  LIBSPDM_CRYPTO_ASN1_CONTEXT_SPECIFIC + 4);
    if (result) {
        if ((obj_len != sizeof(m_libspdm_dice_tcbinfo_layer)) ||
            (!libspdm_consttime_is_mem_equal(ptr, m_libspdm_dice_tcbinfo_layer, obj_len))) {
            return false;
        }
        ptr += obj_len;
    }
    /*index*/
    result = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                  LIBSPDM_CRYPTO_ASN1_CONTEXT_SPECIFIC + 5);
    if (result) {
        ptr += obj_len;
    }
    /*fwids*/
    result = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                  (LIBSPDM_CRYPTO_ASN1_CONTEXT_SPECIFIC |
                                   LIBSPDM_CRYPTO_ASN1_CONSTRUCTED) + 6);
    if (result) {
        if ((obj_len != sizeof(m_libspdm_dice_tcbinfo_fwids)) ||
            (!libspdm_consttime_is_mem_equal(ptr, m_libspdm_dice_tcbinfo_fwids, obj_len))) {
            return false;
        }
        ptr += obj_len;
    } else {
        return false;
    }
    /*flags*/
    result = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                  LIBSPDM_CRYPTO_ASN1_CONTEXT_SPECIFIC + 7);
    if (result) {
        ptr += obj_len;
    }
    /*vendorInfo*/
    result = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                  LIBSPDM_CRYPTO_ASN1_CONTEXT_SPECIFIC + 8);
    if (result) {
        ptr += obj_len;
    }
    /*type*/
    result = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                  LIBSPDM_CRYPTO_ASN1_CONTEXT_SPECIFIC + 9);
    if (result) {
        if ((obj_len != sizeof(m_libspdm_dice_tcbinfo_type)) ||
            (!libspdm_consttime_is_mem_equal(ptr, m_libspdm_dice_tcbinfo_type, obj_len))) {
            return false;
        }
        ptr += obj_len;
    } else {
        return false;
    }
    /*flagMask*/
    result = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                  LIBSPDM_CRYPTO_ASN1_CONTEXT_SPECIFIC + 10);
    if (result) {
        ptr += obj_len;
    }

    if (ptr == end) {
        return true;
    } else {
        return false;
    }
}

/*callback function for verifying cert_chain DiceTcbInfo extension*/
bool libspdm_verify_spdm_cert_chain_with_dice(void *spdm_context, uint8_t slot_id,
                                              size_t cert_chain_size, const void *cert_chain,
                                              const void **trust_anchor,
                                              size_t *trust_anchor_size)
{
    bool result;
    libspdm_context_t *context;
    const uint8_t *cert_chain_data;
    size_t cert_chain_data_size;
    size_t hash_size;
    uint8_t *ptr;
    uint8_t *tem_ptr;
    int32_t length;
    size_t obj_len;
    uint8_t *end;
    size_t cert_dice_tcb_info_size;
    bool cert_chain_have_matched_dice;
    uint8_t number_dice_tcb_info;

    /*verify peer cert chain integrity*/
    result = libspdm_verify_peer_cert_chain_buffer_integrity(spdm_context, cert_chain,
                                                             cert_chain_size);
    if (!result) {
        return false;
    }

    /*verify peer cert chain authority*/
    result = libspdm_verify_peer_cert_chain_buffer_authority(spdm_context, cert_chain,
                                                             cert_chain_size, trust_anchor,
                                                             trust_anchor_size);
    if (!result) {
        return false;
    }

    context = spdm_context;
    hash_size = libspdm_get_hash_size(context->connection_info.algorithm.base_hash_algo);

    cert_chain_data = (const uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + hash_size;
    cert_chain_data_size = cert_chain_size - sizeof(spdm_cert_chain_t) - hash_size;

    length = (int32_t)cert_chain_data_size;
    ptr = (uint8_t*)(size_t)cert_chain_data;
    obj_len = 0;
    end = ptr + length;
    cert_chain_have_matched_dice = false;
    number_dice_tcb_info = 0;

    while (ptr < end) {
        cert_dice_tcb_info_size = 0;
        tem_ptr = ptr;
        result = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                      LIBSPDM_CRYPTO_ASN1_SEQUENCE |
                                      LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
        if (result) {
            /*verify Dice TCB info*/
            result = libspdm_verify_cert_dicetcbinfo(tem_ptr, obj_len + (ptr - tem_ptr),
                                                     &cert_dice_tcb_info_size);
            if (!result) {
                if (cert_dice_tcb_info_size == 0) {
                    return false;
                }
                number_dice_tcb_info++;
            } else {
                if (cert_dice_tcb_info_size != 0) {
                    cert_chain_have_matched_dice = true;
                    number_dice_tcb_info++;
                }
            }
            /* Move to next cert*/
            ptr += obj_len;
        } else {
            return false;
        }
    }

    if (m_libspdm_must_have_dice_tcb_info && !cert_chain_have_matched_dice) {
        return false;
    }

    /*check the number of cert with DiceTcbinfo in cert chain*/
    if (number_dice_tcb_info != m_libspdm_dice_tcb_info_number) {
        return false;
    }

    if (ptr == end) {
        return true;
    } else {
        return false;
    }
}
