/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Definitions of Integrity and data Encryption (IDE) ECN in PCI-SIG.
 **/

#ifndef PCI_IDE_KM_H
#define PCI_IDE_KM_H


#pragma pack(1)

/* IDE_KM header*/

typedef struct {
    uint8_t object_id;
} pci_ide_km_header_t;

#define PCI_IDE_KM_OBJECT_ID_QUERY 0x00
#define PCI_IDE_KM_OBJECT_ID_QUERY_RESP 0x01
#define PCI_IDE_KM_OBJECT_ID_KEY_PROG 0x02
#define PCI_IDE_KM_OBJECT_ID_KP_ACK 0x03
#define PCI_IDE_KM_OBJECT_ID_K_SET_GO 0x04
#define PCI_IDE_KM_OBJECT_ID_K_SET_STOP 0x05
#define PCI_IDE_KM_OBJECT_ID_K_SET_GOSTOP_ACK 0x06


/* IDE_KM QUERY*/

typedef struct {
    pci_ide_km_header_t header;
    uint8_t reserved;
    uint8_t port_index;
} pci_ide_km_query_t;


/* IDE_KM QUERY_RESP*/

typedef struct {
    pci_ide_km_header_t header;
    uint8_t reserved;
    uint8_t port_index;
    uint8_t dev_func_num;
    uint8_t bus_num;
    uint8_t segment;
    uint8_t max_port_index;
    /*IDE Extended capability*/
} pci_ide_km_query_resp_t;

#define PCI_IDE_KM_LINK_IDE_REG_BLOCK_MAX_COUNT 8
#define PCI_IDE_KM_SELECTIVE_IDE_REG_BLOCK_MAX_COUNT 255
#define PCI_IDE_KM_SELECTIVE_IDE_ADDRESS_ASSOCIATION_REG_BLOCK_MAX_COUNT 15


/* IDE_KM KEY_PROG*/

typedef struct {
    pci_ide_km_header_t header;
    uint8_t reserved[2];
    uint8_t stream_id;
    uint8_t reserved2;
    uint8_t key_sub_stream;
    uint8_t port_index;
    /*KEY 8 DW
     * IFV(invocation field of the IV) 2 DW*/
} pci_ide_km_key_prog_t;

#define PCI_IDE_KM_KEY_SET_MASK 0x01
#define PCI_IDE_KM_KEY_SET_K0 0x00
#define PCI_IDE_KM_KEY_SET_K1 0x01

#define PCI_IDE_KM_KEY_DIRECTION_MASK 0x02
#define PCI_IDE_KM_KEY_DIRECTION_RX 0x00
#define PCI_IDE_KM_KEY_DIRECTION_TX 0x02

#define PCI_IDE_KM_KEY_SUB_STREAM_MASK 0xF0
#define PCI_IDE_KM_KEY_SUB_STREAM_PR 0x00
#define PCI_IDE_KM_KEY_SUB_STREAM_NPR 0x10
#define PCI_IDE_KM_KEY_SUB_STREAM_CPL 0x20

/* IDE_KM KP_ACK*/

typedef struct {
    pci_ide_km_header_t header;
    uint8_t reserved[2];
    uint8_t stream_id;
    uint8_t status;
    uint8_t key_sub_stream;
    uint8_t port_index;
} pci_ide_km_kp_ack_t;

#define PCI_IDE_KM_KP_ACK_STATUS_SUCCESS 0x00
#define PCI_IDE_KM_KP_ACK_STATUS_INCORRECT_LENGTH 0x01
#define PCI_IDE_KM_KP_ACK_STATUS_UNSUPPORTED_PORT_INDEX 0x02
#define PCI_IDE_KM_KP_ACK_STATUS_UNSUPPORTED_VALUE 0x03
#define PCI_IDE_KM_KP_ACK_STATUS_UNSPECIFIED_FAILURE 0x04

/* IDE_KM K_SET_GO*/

typedef struct {
    pci_ide_km_header_t header;
    uint8_t reserved[2];
    uint8_t stream_id;
    uint8_t reserved2;
    uint8_t key_sub_stream;
    uint8_t port_index;
} pci_ide_km_k_set_go_t;


/* IDE_KM K_SET_STOP*/

typedef struct {
    pci_ide_km_header_t header;
    uint8_t reserved[2];
    uint8_t stream_id;
    uint8_t reserved2;
    uint8_t key_sub_stream;
    uint8_t port_index;
} pci_ide_km_k_set_stop_t;


/* IDE_KM K_GOSTOP_ACK*/

typedef struct {
    pci_ide_km_header_t header;
    uint8_t reserved[2];
    uint8_t stream_id;
    uint8_t reserved2;
    uint8_t key_sub_stream;
    uint8_t port_index;
} pci_ide_km_k_gostop_ack_t;

#pragma pack()

#endif /* PCI_IDE_KM_H */
