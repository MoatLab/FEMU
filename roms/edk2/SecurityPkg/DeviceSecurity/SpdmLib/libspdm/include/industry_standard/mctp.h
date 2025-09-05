/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Definitions of DSP0236 Management Component Transport Protocol (MCTP) Base Specification
 * version 1.3.1 in Distributed Management Task Force (DMTF).
 *
 * Definitions of DSP0239 Management Component Transport Protocol (MCTP) IDs and Codes
 * version 1.7.0 in Distributed Management Task Force (DMTF).
 *
 * Definitions of DSP0275 SPDM over MCTP Binding Specification
 * version 1.0.0 in Distributed Management Task Force (DMTF).
 *
 * Definitions of DSP0276 Secured MCTP Messages over MCTP Binding Specification
 * version 1.0.0 in Distributed Management Task Force (DMTF).
 **/

#ifndef MCTP_BINDING_H
#define MCTP_BINDING_H

#pragma pack(1)


/* MCTP header*/

typedef struct {
    /* B[0~3]: header_version
     * B[4~7]: reserved*/
    uint8_t header_version;
    uint8_t destination_id;
    uint8_t source_id;
    /* B[0~2]: message_tag
     * B[3]:   tag_owner
     * B[4~5]: packet_sequence_number
     * B[6]:   end_of_message
     * B[7]:   start_of_message*/
    uint8_t message_tag;
} mctp_header_t;

typedef struct {
    /* B[0~6]: message_type
     * B[7]  : integrity_check*/
    uint8_t message_type;
} mctp_message_header_t;

#define MCTP_MESSAGE_TYPE_MCTP_CONTROL 0x00
#define MCTP_MESSAGE_TYPE_PLDM 0x01
#define MCTP_MESSAGE_TYPE_NCSI_CONTROL 0x02
#define MCTP_MESSAGE_TYPE_ETHERNET 0x03
#define MCTP_MESSAGE_TYPE_NVME_MANAGEMENT 0x04
#define MCTP_MESSAGE_TYPE_SPDM 0x05
#define MCTP_MESSAGE_TYPE_SECURED_MCTP 0x06
#define MCTP_MESSAGE_TYPE_VENDOR_DEFINED_PCI 0x7E
#define MCTP_MESSAGE_TYPE_VENDOR_DEFINED_IANA 0x7F

#pragma pack()

#endif /* MCTP_BINDING_H */
