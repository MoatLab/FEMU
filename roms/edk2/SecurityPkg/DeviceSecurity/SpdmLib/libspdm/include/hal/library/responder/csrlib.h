/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef RESPONDER_CSRLIB_H
#define RESPONDER_CSRLIB_H

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"
#include "library/spdm_return_status.h"
#include "industry_standard/spdm.h"

#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP
/**
 * Gen CSR
 *
 * @param[in]      spdm_context          A pointer to the SPDM context.
 *
 * @param[in]      base_hash_algo        Indicates the hash algorithm.
 * @param[in]      base_asym_algo        Indicates the signing algorithm.
 * @param[in, out] need_reset            For input, it gives the value of CERT_INSTALL_RESET_CAP:
 *                                                  If true, then device needs to be reset to complete the CSR.
 *                                                  If false, the device doesn`t need to be reset to complete the CSR.
 *                                       For output, it specifies whether the device needs to be reset to complete the CSR or not.
 *
 * @param[in]      request                A pointer to the SPDM request data.
 * @param[in]      request_size           The size of SPDM request data.
 *
 * @param[in]      requester_info         Requester info to generate the CSR.
 * @param[in]      requester_info_length  The length of requester info.
 *
 * @param[in]      opaque_data            opaque data to generate the CSR.
 * @param[in]      opaque_data_length     The length of opaque data.
 *
 * @param[in, out] csr_len                For input, csr_len is the size of store CSR buffer.
 *                                        For output, csr_len is CSR len for DER format
 * @param[in, out] csr_pointer            On input, csr_pointer is buffer address to store CSR.
 *                                        On output, csr_pointer is address for stored CSR.
 *                                        The csr_pointer address will be changed.
 *
 * @param[in]       is_device_cert_model  If true, the cert chain is DeviceCert model.
 *                                        If false, the cert chain is AliasCert model.
 *
 * @retval  true   Success.
 * @retval  false  Failed to gen CSR.
 **/
extern bool libspdm_gen_csr(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
    void *spdm_context,
#endif
    uint32_t base_hash_algo, uint32_t base_asym_algo, bool *need_reset,
    const void *request, size_t request_size,
    uint8_t *requester_info, size_t requester_info_length,
    uint8_t *opaque_data, uint16_t opaque_data_length,
    size_t *csr_len, uint8_t *csr_pointer,
    bool is_device_cert_model);

/**
 * Gen CSR, which is uesd for SPDM 1.3
 *
 *   If the device need reset to gen csr, the all case is in the table.
 *   | Overwrite | Req CSRTtrackingTag | Pending CSR | Reset |             Res Action       |
 *   |-----------|---------------------|-------------|-------|------------------------------|
 *   |    No     |          0          |      No     |   -   |          ResetRequired       |
 *   |    No     |          0          |      Yes    |   -   |     ResetRequired or Busy    |
 *   |    No     |        Non-0        |   No Match  |   -   |           Unexpected         |
 *   |    No     |        Non-0        |     Match   | Before|             Busy             |
 *   |    No     |        Non-0        |     Match   | After |             CSR              |
 *   |    Yes    |          0          |      No     |   -   |          ResetRequired       |
 *   |    Yes    |          0          |      Yes    |   -   |          ResetRequired       |
 *   |    Yes    |        Non-0        |      -      |   -   |             Invalid          |
 *
 * @param[in]      spdm_context          A pointer to the SPDM context.
 *
 * @param[in]      base_hash_algo        Indicates the hash algorithm.
 * @param[in]      base_asym_algo        Indicates the signing algorithm.
 * @param[in, out] need_reset            For input, it gives the value of CERT_INSTALL_RESET_CAP:
 *                                                  If true, then device needs to be reset to complete the CSR.
 *                                                  If false, the device doesn`t need to be reset to complete the CSR.
 *                                       For output, it specifies whether the device needs to be reset to complete the CSR or not.
 *
 * @param[in]      request                A pointer to the SPDM request data.
 * @param[in]      request_size           The size of SPDM request data.
 *
 * @param[in]      requester_info         Requester info to generate the CSR.
 * @param[in]      requester_info_length  The length of requester info.
 *
 * @param[in]      opaque_data            opaque data to generate the CSR.
 * @param[in]      opaque_data_length     The length of opaque data.
 *
 * @param[in, out] csr_len                For input, csr_len is the size of store CSR buffer.
 *                                        For output, csr_len is CSR len for DER format
 * @param[in, out] csr_pointer            On input, csr_pointer is buffer address to store CSR.
 *                                        On output, csr_pointer is address for stored CSR.
 *                                        The csr_pointer address will be changed.
 *
 * @param[in]       req_cert_model        indicates the desired certificate model of the CSR
 *
 * @param[in, out]  req_csr_tracking_tag  For input, this field shall contain the CSRTrackingTag of the associated GET_CSR request.
 *                                        For output, this field indicate responder available csr_tracking_tag.
 * @param[in]       req_key_pair_id       Indicates the desired key pair associated with the CSR.
 * @param[in]       overwrite             If set, the Responder shall stop processing any existing GET_CSR request and
 *                                        overwrite it with this request
 *
 * @retval  true   Success.
 * @retval  false  Failed to gen CSR.
 **/

#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX
extern bool libspdm_gen_csr_ex(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
    void *spdm_context,
#endif
    uint32_t base_hash_algo, uint32_t base_asym_algo, bool *need_reset,
    const void *request, size_t request_size,
    uint8_t *requester_info, size_t requester_info_length,
    uint8_t *opaque_data, uint16_t opaque_data_length,
    size_t *csr_len, uint8_t *csr_pointer,
    uint8_t req_cert_model,
    uint8_t *req_csr_tracking_tag,
    uint8_t req_key_pair_id,
    bool overwrite);
#endif /*LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX*/
#endif /* LIBSPDM_ENABLE_CAPABILITY_CSR_CAP */

#endif /* RESPONDER_CSRLIB_H */
