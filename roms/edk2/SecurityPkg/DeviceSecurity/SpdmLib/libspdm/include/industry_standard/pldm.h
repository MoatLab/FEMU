/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Definitions of DSP0240 Platform Level data Model (PLDM) Base Specification
 * version 1.0.0 in Distributed Management Task Force (DMTF).
 *
 * Definitions of DSP0245 Platform Level data Model (PLDM) IDs and Codes Specification
 * version 1.3.0 in Distributed Management Task Force (DMTF).
 **/

#ifndef PLDM_H
#define PLDM_H

#pragma pack(1)

/* PLDM Header first byte*/
#define PLDM_HEADER_REQUEST_MASK 0x80
#define PLDM_HEADER_DATAGRAM_MASK 0x40
#define PLDM_HEADER_INSTANCE_ID_MASK 0x1F

/* PLDM Header second byte*/
#define PLDM_HEADER_VERSION 0x00
#define PLDM_HEADER_VERSION_MASK 0xC0
#define PLDM_HEADER_TYPE_MASK 0x3F

typedef struct {
    uint8_t instance_id;
    uint8_t pldm_type;
    uint8_t pldm_command_code;
    /*uint8_t    payload[];*/
} pldm_message_header_t;

typedef struct {
    uint8_t pldm_completion_code;
} pldm_message_response_header_t;

#define PLDM_BASE_CODE_SUCCESS 0
#define PLDM_BASE_CODE_ERROR 1

#define PLDM_MESSAGE_TYPE_CONTROL_DISCOVERY 0x00
#define PLDM_MESSAGE_TYPE_SMBIOS 0x01
#define PLDM_MESSAGE_TYPE_PLATFORM_MONITORING_CONTROL 0x02
#define PLDM_MESSAGE_TYPE_BIOS_CONTROL_CONFIGURATION 0x03
#define PLDM_MESSAGE_TYPE_FRU_DATA 0x04
#define PLDM_MESSAGE_TYPE_FIRMWARE_UPDATE 0x05
#define PLDM_MESSAGE_TYPE_REDFISH_DEVICE_ENABLEMENT 0x06
#define PLDM_MESSAGE_TYPE_OEM 0x3F


/* PLDM_MESSAGE_TYPE_CONTROL_DISCOVERY*/

#define PLDM_CONTROL_DISCOVERY_COMMAND_SET_TID 0x01
#define PLDM_CONTROL_DISCOVERY_COMMAND_GET_TID 0x02
#define PLDM_CONTROL_DISCOVERY_COMMAND_GET_PLDM_VERSION 0x03
#define PLDM_CONTROL_DISCOVERY_COMMAND_GET_PLDM_TYPES 0x04
#define PLDM_CONTROL_DISCOVERY_COMMAND_GET_PLDM_COMMANDS 0x05

/* PLDM GET_TID request*/

typedef struct {
    pldm_message_header_t pldm_header;
} pldm_get_tid_request_t;

/* PLDM GET_TID response*/

typedef struct {
    pldm_message_header_t pldm_header;
    pldm_message_response_header_t pldm_response_header;
    uint8_t tid;
} pldm_get_tid_response_t;

#pragma pack()

#endif /* PLDM_H */
