/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Definitions in CXL 3.0 specification.
 **/

#ifndef CXL_IDE_KM_H
#define CXL_IDE_KM_H

/* Standard ID and Vendor ID for CXL*/

#define SPDM_STANDARD_ID_CXL SPDM_REGISTRY_ID_PCISIG
#define SPDM_VENDOR_ID_CXL 0x1E98

typedef pci_protocol_header_t cxl_protocol_header_t;

#define CXL_PROTOCOL_ID_IDE_KM 0x00

#pragma pack(1)

/* IDE_KM header*/

typedef struct {
    uint8_t object_id;
} cxl_ide_km_header_t;

#define CXL_IDE_KM_OBJECT_ID_QUERY 0x00
#define CXL_IDE_KM_OBJECT_ID_QUERY_RESP 0x01
#define CXL_IDE_KM_OBJECT_ID_KEY_PROG 0x02
#define CXL_IDE_KM_OBJECT_ID_KP_ACK 0x03
#define CXL_IDE_KM_OBJECT_ID_K_SET_GO 0x04
#define CXL_IDE_KM_OBJECT_ID_K_SET_STOP 0x05
#define CXL_IDE_KM_OBJECT_ID_K_SET_GOSTOP_ACK 0x06
/* new in CXL*/
#define CXL_IDE_KM_OBJECT_ID_GET_KEY 0x07
#define CXL_IDE_KM_OBJECT_ID_GET_KEY_ACK 0x08

/* IDE_KM QUERY*/

typedef struct {
    cxl_ide_km_header_t header;
    uint8_t reserved;
    uint8_t port_index;
} cxl_ide_km_query_t;

/* IDE_KM QUERY_RESP*/

typedef struct {
    cxl_ide_km_header_t header;
    uint8_t reserved;
    uint8_t port_index;
    uint8_t dev_func_num;
    uint8_t bus_num;
    uint8_t segment;
    uint8_t max_port_index;
    /* caps is new in CXL*/
    uint8_t caps;
    /*CXL IDE Extended capability*/
} cxl_ide_km_query_resp_t;

#define CXL_IDE_KM_QUERY_RESP_CAP_VERSION_MASK 0x0F
#define CXL_IDE_KM_QUERY_RESP_CAP_VERSION_1 0x01
#define CXL_IDE_KM_QUERY_RESP_IV_GEN_CAP_MASK 0x10
#define CXL_IDE_KM_QUERY_RESP_IV_GEN_CAP 0x10
#define CXL_IDE_KM_QUERY_RESP_KEY_GEN_CAP_MASK 0x20
#define CXL_IDE_KM_QUERY_RESP_KEY_GEN_CAP 0x20
#define CXL_IDE_KM_QUERY_RESP_K_SET_STOP_CAP_MASK 0x40
#define CXL_IDE_KM_QUERY_RESP_K_SET_STOP_CAP 0x40

/* IDE_KM KEY_PROG*/

typedef struct {
    cxl_ide_km_header_t header;
    uint8_t reserved[2];
    uint8_t stream_id;
    uint8_t reserved2;
    uint8_t key_sub_stream;
    uint8_t port_index;
    /*KEY 8 DW - same as PCIE IDE
     * Pending Initial IV 3 DW - ignore if IV_DEFAULT = 1*/
} cxl_ide_km_key_prog_t;

#define CXL_IDE_KM_KEY_DIRECTION_MASK 0x02
#define CXL_IDE_KM_KEY_DIRECTION_RX 0x00
#define CXL_IDE_KM_KEY_DIRECTION_TX 0x02

#define CXL_IDE_KM_KEY_IV_MASK 0x08
#define CXL_IDE_KM_KEY_IV_INITIAL 0x00
#define CXL_IDE_KM_KEY_IV_DEFAULT 0x08

#define CXL_IDE_KM_KEY_SUB_STREAM_MASK 0xF0
#define CXL_IDE_KM_KEY_SUB_STREAM_CXL 0x80

/* IDE_KM KP_ACK*/

typedef struct {
    cxl_ide_km_header_t header;
    uint8_t reserved[2];
    uint8_t stream_id;
    uint8_t status;
    uint8_t key_sub_stream;
    uint8_t port_index;
} cxl_ide_km_kp_ack_t;

#define CXL_IDE_KM_KP_ACK_STATUS_SUCCESS 0x00
#define CXL_IDE_KM_KP_ACK_STATUS_INVALID 0x01

/* IDE_KM K_SET_GO*/

typedef struct {
    cxl_ide_km_header_t header;
    uint8_t reserved[2];
    uint8_t stream_id;
    uint8_t reserved2;
    uint8_t key_sub_stream;
    uint8_t port_index;
} cxl_ide_km_k_set_go_t;

#define CXL_IDE_KM_KEY_MODE_MASK 0x08
#define CXL_IDE_KM_KEY_MODE_SKID 0x00
#define CXL_IDE_KM_KEY_MODE_CONTAINMENT 0x08

/* IDE_KM K_SET_STOP*/

typedef struct {
    cxl_ide_km_header_t header;
    uint8_t reserved[2];
    uint8_t stream_id;
    uint8_t reserved2;
    uint8_t key_sub_stream;
    uint8_t port_index;
} cxl_ide_km_k_set_stop_t;

/* IDE_KM K_GOSTOP_ACK*/

typedef struct {
    cxl_ide_km_header_t header;
    uint8_t reserved[2];
    uint8_t stream_id;
    uint8_t reserved2;
    uint8_t key_sub_stream;
    uint8_t port_index;
} cxl_ide_km_k_gostop_ack_t;

/* IDE_KM GETKEY*/

typedef struct {
    cxl_ide_km_header_t header;
    uint8_t reserved[2];
    uint8_t stream_id;
    uint8_t reserved2;
    uint8_t key_sub_stream;
    uint8_t port_index;
} cxl_ide_km_get_key_t;

/* IDE_KM GETKEY_ACK*/

typedef struct {
    cxl_ide_km_header_t header;
    uint8_t reserved[2];
    uint8_t stream_id;
    uint8_t reserved2;
    uint8_t key_sub_stream;
    uint8_t port_index;
    /*KEY 8 DW - ignore if KEY_GEN_CAP = 0
    * IV 3 DW - ignore if IV_GEN_CAP = 0*/
} cxl_ide_km_get_key_ack_t;

#pragma pack()

#endif /* CXL_IDE_KM_H */
