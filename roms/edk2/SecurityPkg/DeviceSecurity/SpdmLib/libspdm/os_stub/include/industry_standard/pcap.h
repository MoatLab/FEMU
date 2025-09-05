/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Definition for pcap file format and link type
 *
 * https://www.tcpdump.org/manpages/pcap-savefile.5.txt
 *
 * https://wiki.wireshark.org/Development/LibpcapFileFormat
 **/

#ifndef __PCAP_H__
#define __PCAP_H__

#pragma pack(1)


/* PCAP file format:
 * +---------------+---------------+-------------+---------------+-------------+---------------+-------------+-----+
 * | Global header | Packet header | Packet data | Packet header | Packet data | Packet header | Packet data | ... |
 * +---------------+---------------+-------------+---------------+-------------+---------------+-------------+-----+*/


typedef struct {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t this_zone;
    uint32_t sig_figs;
    uint32_t snap_len;
    uint32_t network; /* data Link Type*/
} pcap_global_header_t;

#define PCAP_GLOBAL_HEADER_MAGIC 0xa1b2c3d4
#define PCAP_GLOBAL_HEADER_MAGIC_SWAPPED 0xd4c3b2a1

#define PCAP_GLOBAL_HEADER_MAGIC_NANO 0xa1b23c4d
#define PCAP_GLOBAL_HEADER_MAGIC_NANO_SWAPPED 0x4d3cb2a1

#define PCAP_GLOBAL_HEADER_VERSION_MAJOR 0x0002
#define PCAP_GLOBAL_HEADER_VERSION_MINOR 0x0004

typedef struct {
    uint32_t ts_sec;
    /* PCAP_GLOBAL_HEADER_MAGIC      : MicroSecond
    * PCAP_GLOBAL_HEADER_MAGIC_NANO : NanoSecond*/
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_packet_header_t;

#pragma pack()

#endif
