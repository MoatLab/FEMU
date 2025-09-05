/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef SPDM_CERT_VERIFY_CALLBACK_INTERNAL_H
#define SPDM_CERT_VERIFY_CALLBACK_INTERNAL_H

#include "internal/libspdm_common_lib.h"

/**
 * The callback function for verifying cert_chain DiceTcbInfo extension.
 *
 * @param  spdm_context            A pointer to the SPDM context.
 * @param  slot_id                 The number of slot for the certificate chain.
 *                                 This params is not uesed, just for compatible in this function.
 * @param  cert_chain_size         size in bytes of the certificate chain buffer.
 * @param  cert_chain              Certificate chain buffer including spdm_cert_chain_t header.
 * @param  trust_anchor            A buffer to hold the trust_anchor which is used to validate the peer certificate, if not NULL.
 * @param  trust_anchor_size       A buffer to hold the trust_anchor_size, if not NULL.
 *
 * @retval true  The certificate chain buffer DiceTcbInfo extension verification passed.
 * @retval false The certificate chain buffer DiceTcbInfo extension verification failed.
 **/
bool libspdm_verify_spdm_cert_chain_with_dice(void *spdm_context, uint8_t slot_id,
                                              size_t cert_chain_size, const void *cert_chain,
                                              const void **trust_anchor,
                                              size_t *trust_anchor_size);

/**
 * verify cert DiceTcbInfo extension.
 *
 * @param[in]      cert                         Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size                    Size of the X509 certificate in bytes.
 * @param[in, out] spdm_get_dice_tcb_info_size  DiceTcbInfo Extension bytes size.
 *
 * @retval true   If the returned spdm_get_dice_tcb_info_size == 0, it means that cert is valid, but cert doesn't have DiceTcbInfo extension;
 *                If the returned spdm_get_dice_tcb_info_size != 0, it means that cert is valid, and the DiceTcbInfo extension is found;
 *                                                                  And the cert DiceTcbInfo extension includes all fields in the reference TcbInfo.
 * @retval false  If the returned spdm_get_dice_tcb_info_size == 0, it means that cert are invalid;
 *                If the returned spdm_get_dice_tcb_info_size != 0, it means that cert is valid, and the DiceTcbInfo extension is found;
 *                                                                  But the cert DiceTcbInfo extension doesn't include all fields in the reference TcbInfo.
 **/
bool libspdm_verify_cert_dicetcbinfo(const void *cert, size_t cert_size,
                                     size_t *spdm_get_dice_tcb_info_size);

#endif
