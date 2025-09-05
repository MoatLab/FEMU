/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "library/spdm_transport_pcidoe_lib.h"
#include "industry_standard/pcidoe.h"
#include "internal/libspdm_common_lib.h"
#include "hal/library/debuglib.h"
#include "hal/library/memlib.h"

/**
 * Get sequence number in an SPDM secure message.
 *
 * This value is transport layer specific.
 *
 * @param sequence_number        The current sequence number used to encode or decode message.
 * @param sequence_number_buffer  A buffer to hold the sequence number output used in the secured message.
 *                             The size in byte of the output buffer shall be 8.
 *
 * @return size in byte of the sequence_number_buffer.
 *        It shall be no greater than 8.
 *        0 means no sequence number is required.
 **/
uint8_t libspdm_pci_doe_get_sequence_number(uint64_t sequence_number,
                                            uint8_t *sequence_number_buffer)
{
    libspdm_copy_mem(sequence_number_buffer, LIBSPDM_PCI_DOE_SEQUENCE_NUMBER_COUNT,
                     &sequence_number, LIBSPDM_PCI_DOE_SEQUENCE_NUMBER_COUNT);
    return LIBSPDM_PCI_DOE_SEQUENCE_NUMBER_COUNT;
}

/**
 * Return max random number count in an SPDM secure message.
 *
 * This value is transport layer specific.
 *
 * @return Max random number count in an SPDM secured message.
 *        0 means no random number is required.
 **/
uint32_t libspdm_pci_doe_get_max_random_number_count(void)
{
    return LIBSPDM_PCI_DOE_MAX_RANDOM_NUMBER_COUNT;
}

/**
 * This function translates the negotiated secured_message_version to a DSP0277 version.
 *
 * @param  secured_message_version  The version specified in binding specification and
 *                                  negotiated in KEY_EXCHANGE/KEY_EXCHANGE_RSP.
 *
 * @return The DSP0277 version specified in binding specification,
 *         which is bound to secured_message_version.
 */
spdm_version_number_t libspdm_pci_doe_get_secured_spdm_version(
    spdm_version_number_t secured_message_version)
{
    /* PCI-SIG uses DSP0277 version */
    return secured_message_version;
}

/**
 * Encode a normal message or secured message to a transport message.
 *
 * @param  session_id                    Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param  message_size                  size in bytes of the message data buffer.
 * @param  message                      A pointer to a source buffer to store the message.
 * @param  transport_message_size         size in bytes of the transport message data buffer.
 * @param  transport_message             A pointer to a destination buffer to store the transport message.
 *
 * @retval RETURN_SUCCESS               The message is encoded successfully.
 * @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
 **/
libspdm_return_t libspdm_pci_doe_encode_message(const uint32_t *session_id,
                                                size_t message_size, void *message,
                                                size_t *transport_message_size,
                                                void **transport_message)
{
    size_t aligned_message_size;
    size_t alignment;
    uint32_t data32;
    pci_doe_data_object_header_t *pci_doe_header;

    alignment = LIBSPDM_PCI_DOE_ALIGNMENT;
    aligned_message_size =
        (message_size + (alignment - 1)) & ~(alignment - 1);

    LIBSPDM_ASSERT(*transport_message_size >=
                   aligned_message_size + sizeof(pci_doe_data_object_header_t));
    if (*transport_message_size <
        aligned_message_size + sizeof(pci_doe_data_object_header_t)) {
        *transport_message_size = aligned_message_size +
                                  sizeof(pci_doe_data_object_header_t);
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
    }
    *transport_message_size =
        aligned_message_size + sizeof(pci_doe_data_object_header_t);
    *transport_message = (uint8_t *)message - sizeof(pci_doe_data_object_header_t);
    pci_doe_header = *transport_message;
    pci_doe_header->vendor_id = PCI_DOE_VENDOR_ID_PCISIG;
    if (session_id != NULL) {
        pci_doe_header->data_object_type =
            PCI_DOE_DATA_OBJECT_TYPE_SECURED_SPDM;
        data32 = libspdm_read_uint32((const uint8_t *)message);
        LIBSPDM_ASSERT(*session_id == data32);
        if (*session_id != data32) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
    } else {
        pci_doe_header->data_object_type =
            PCI_DOE_DATA_OBJECT_TYPE_SPDM;
    }
    pci_doe_header->reserved = 0;
    if (*transport_message_size > PCI_DOE_MAX_SIZE_IN_BYTE) {
        return LIBSPDM_STATUS_BUFFER_FULL;
    } else if (*transport_message_size == PCI_DOE_MAX_SIZE_IN_BYTE) {
        pci_doe_header->length = 0;
    } else {
        pci_doe_header->length =
            (uint32_t)*transport_message_size / sizeof(uint32_t);
    }

    libspdm_zero_mem((uint8_t *)message + message_size,
                     aligned_message_size - message_size);
    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_pci_doe_encode_discovery(size_t message_size, void *message,
                                                  size_t *transport_message_size,
                                                  void **transport_message)
{
    size_t aligned_message_size;
    size_t alignment;
    pci_doe_data_object_header_t *pci_doe_header;

    alignment = LIBSPDM_PCI_DOE_ALIGNMENT;
    aligned_message_size =
        (message_size + (alignment - 1)) & ~(alignment - 1);

    LIBSPDM_ASSERT(*transport_message_size >=
                   aligned_message_size + sizeof(pci_doe_data_object_header_t));
    if (*transport_message_size <
        aligned_message_size + sizeof(pci_doe_data_object_header_t)) {
        *transport_message_size = aligned_message_size +
                                  sizeof(pci_doe_data_object_header_t);
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
    }

    *transport_message_size =
        aligned_message_size + sizeof(pci_doe_data_object_header_t);
    *transport_message = (uint8_t *)message - sizeof(pci_doe_data_object_header_t);
    pci_doe_header = *transport_message;
    pci_doe_header->vendor_id = PCI_DOE_VENDOR_ID_PCISIG;
    pci_doe_header->data_object_type = PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY;
    pci_doe_header->reserved = 0;

    if (*transport_message_size > PCI_DOE_MAX_SIZE_IN_BYTE) {
        return LIBSPDM_STATUS_BUFFER_FULL;
    } else if (*transport_message_size == PCI_DOE_MAX_SIZE_IN_BYTE) {
        pci_doe_header->length = 0;
    } else {
        pci_doe_header->length =
            (uint32_t)*transport_message_size / sizeof(uint32_t);
    }

    libspdm_zero_mem((uint8_t *)message + message_size,
                     aligned_message_size - message_size);

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Decode a transport message to a normal message or secured message.
 *
 * @param  session_id                    Indicates if it is a secured message protected via SPDM session.
 *                                     If *session_id is NULL, it is a normal message.
 *                                     If *session_id is NOT NULL, it is a secured message.
 * @param  transport_message_size         size in bytes of the transport message data buffer.
 * @param  transport_message             A pointer to a source buffer to store the transport message.
 * @param  message_size                  size in bytes of the message data buffer.
 * @param  message                      A pointer to a destination buffer to store the message.
 *
 * @retval RETURN_SUCCESS               The message is encoded successfully.
 * @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
 **/
libspdm_return_t libspdm_pci_doe_decode_message(uint32_t **session_id,
                                                size_t transport_message_size,
                                                void *transport_message,
                                                size_t *message_size,
                                                void **message)
{
    const pci_doe_data_object_header_t *pci_doe_header;
    uint32_t length;

    LIBSPDM_ASSERT(transport_message_size > sizeof(pci_doe_data_object_header_t));
    if (transport_message_size <= sizeof(pci_doe_data_object_header_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    pci_doe_header = transport_message;
    if (pci_doe_header->vendor_id != PCI_DOE_VENDOR_ID_PCISIG) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    switch (pci_doe_header->data_object_type) {
    case PCI_DOE_DATA_OBJECT_TYPE_SECURED_SPDM:
        LIBSPDM_ASSERT(session_id != NULL);
        if (session_id == NULL) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
        if (transport_message_size <=
            sizeof(pci_doe_data_object_header_t) + sizeof(uint32_t)) {
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
        *session_id = (void *)((uint8_t *)transport_message +
                               sizeof(pci_doe_data_object_header_t));
        break;
    case PCI_DOE_DATA_OBJECT_TYPE_SPDM:
        if (session_id != NULL) {
            *session_id = NULL;
        }
        break;
    default:
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if (pci_doe_header->reserved != 0) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (pci_doe_header->length >= PCI_DOE_MAX_SIZE_IN_DW) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    } else if (pci_doe_header->length == 0) {
        length = PCI_DOE_MAX_SIZE_IN_BYTE;
    } else {
        length = pci_doe_header->length * sizeof(uint32_t);
    }
    if (length != transport_message_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    LIBSPDM_ASSERT(((transport_message_size - sizeof(pci_doe_data_object_header_t)) &
                    (LIBSPDM_PCI_DOE_ALIGNMENT - 1)) == 0);

    *message_size = transport_message_size - sizeof(pci_doe_data_object_header_t);
    *message = (uint8_t *)transport_message + sizeof(pci_doe_data_object_header_t);
    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_pci_doe_decode_discovery_request(size_t transport_message_size,
                                                          const void *transport_message,
                                                          uint8_t *index)
{
    const pci_doe_data_object_header_t *pci_doe_header;
    uint32_t length;
    const uint8_t *message;

    LIBSPDM_ASSERT(transport_message_size > sizeof(pci_doe_data_object_header_t));
    if (transport_message_size <= sizeof(pci_doe_data_object_header_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    pci_doe_header = transport_message;
    if (pci_doe_header->vendor_id != PCI_DOE_VENDOR_ID_PCISIG) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    switch (pci_doe_header->data_object_type) {
    case PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY:
        /*
         * Check to see if we received a DOE discovery message.
         * DOE discovery is not part of the SPDM spec, instead it's part
         * of the PCIe DOE spec. DOE discovery is mandatory for all
         * implementations.
         */
        message = (const uint8_t *)transport_message + sizeof(pci_doe_data_object_header_t);
        if (index != NULL) {
            *index = *message;
        }
        break;
    default:
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if (pci_doe_header->reserved != 0) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (pci_doe_header->length >= PCI_DOE_MAX_SIZE_IN_DW) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    } else if (pci_doe_header->length == 0) {
        length = PCI_DOE_MAX_SIZE_IN_BYTE;
    } else {
        length = pci_doe_header->length * sizeof(uint32_t);
    }
    if (length != transport_message_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_pci_doe_decode_discovery_response(size_t transport_message_size,
                                                           void *transport_message,
                                                           uint16_t *vendor_id,
                                                           uint8_t *protocol,
                                                           uint8_t *next_index)
{
    const pci_doe_data_object_header_t *pci_doe_header;
    uint32_t length;
    uint8_t *message;

    LIBSPDM_ASSERT(transport_message_size > sizeof(pci_doe_data_object_header_t));
    if (transport_message_size <= sizeof(pci_doe_data_object_header_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    pci_doe_header = transport_message;
    if (pci_doe_header->vendor_id != PCI_DOE_VENDOR_ID_PCISIG) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    switch (pci_doe_header->data_object_type) {
    case PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY:
        /*
         * Check to see if we received a DOE discovery message.
         * DOE discovery is not part of the SPDM spec, instead it's part
         * of the PCIe DOE spec. DOE discovery is mandatory for all
         * implementations.
         */
        message = (uint8_t *)transport_message + sizeof(pci_doe_data_object_header_t);
        if (vendor_id != NULL) {
            *vendor_id = *message;
        }
        if (protocol != NULL) {
            *protocol = *(message + sizeof(uint16_t));
        }
        if (next_index != NULL) {
            *next_index = *(message + sizeof(uint16_t) + sizeof(uint8_t));
        }
        break;
    default:
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if (pci_doe_header->reserved != 0) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (pci_doe_header->length >= PCI_DOE_MAX_SIZE_IN_DW) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    } else if (pci_doe_header->length == 0) {
        length = PCI_DOE_MAX_SIZE_IN_BYTE;
    } else {
        length = pci_doe_header->length * sizeof(uint32_t);
    }
    if (length != transport_message_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Return the maximum transport layer message header size.
 *   Transport Message Header Size + sizeof(spdm_secured_message_cipher_header_t))
 *
 *   For MCTP, Transport Message Header Size = sizeof(mctp_message_header_t)
 *   For PCI_DOE, Transport Message Header Size = sizeof(pci_doe_data_object_header_t)
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 *
 * @return size of maximum transport layer message header size
 **/
uint32_t libspdm_transport_pci_doe_get_header_size(
    void *spdm_context)
{
    return sizeof(pci_doe_data_object_header_t) + sizeof(spdm_secured_message_cipher_header_t);
}
