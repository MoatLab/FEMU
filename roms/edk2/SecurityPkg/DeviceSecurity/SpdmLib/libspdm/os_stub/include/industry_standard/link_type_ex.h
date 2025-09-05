/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Definition for pcap link types extension for SPDM transport layer (MCTP/PCI_DOE)
 *
 * https://www.tcpdump.org/linktypes.html
 **/

#ifndef __LINK_TYPE_EX_H__
#define __LINK_TYPE_EX_H__

#pragma pack(1)


/* 0 ~ 289 are defined by https://www.tcpdump.org/linktypes.html*/



/* MCTP packet is defined in DMTF PMCI working group Management Component Transport Protocol (MCTP)
 * Base Specification (https://www.dmtf.org/sites/default/files/standards/documents/DSP0236_1.3.1.pdf)
 * 8.1 MCTP packet fields.*/

/* It starts with MCTP transport header in Figure 4 - Generic message fields.*/

#define LINKTYPE_MCTP 291 /* 0x0123*/


/* PCI data Object Exchange (DOE) is defined in PCI-SIG data Object Exchange (DOE) ECN
 * (https://members.pcisig.com/wg/PCI-SIG/document/14143) 6.xx.1 data Objects.*/

/* It starts with DOE data Object header 1 in Figure 6-x1: DOE data Object format.*/

#define LINKTYPE_PCI_DOE 292 /* 0x0124*/

#pragma pack()

#endif
