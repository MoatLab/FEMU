// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2019 IBM Corp. */

#ifndef __NACA_H
#define __NACA_H

#include <compiler.h>
#include <inttypes.h>
#include <types.h>

struct hv_release_data {
	uint8_t	reserved_0x0[58];
	__be64	vrm;
} __packed __attribute__((aligned(0x10)));

struct hv_lid_load_table {
	__be32	w0;
	__be32	w1;
	__be32	w2;
	__be32	w3;
} __packed __attribute__((aligned(0x10)));

/*
 * NACA structure, accessed by the FSP to find the SPIRA
 */
struct naca {
	__be64	spirah_addr;		/* 0x0000 */
	uint8_t	reserved_0x8[0x10];
	__be64	hv_release_data_addr;	/* 0x0018 */
	uint8_t	reserved_0x20[0x10];
	__be64	spira_addr;		/* 0x0030 */
	__be64	lid_table_addr;		/* 0x0038 */
	uint8_t	reserved_0x40[0x60];
	__be32	spira_size;		/* 0x00a0 */
	uint8_t	reserved_0xa4[0x1c];
	__be64	hv_load_map_addr;	/* 0x00c0 */
	uint8_t	reserved_0xc8[0xe4];
	uint8_t	flags[4];		/* 0x01ac */
	uint8_t	reserved_0x1b0[0x5];
	uint8_t	attn_enabled;		/* 0x01b5 */
	uint8_t	reserved_0x1b6[0x1];
	uint8_t	pcia_supported;		/* 0x01b7 */
	__be64	__primary_thread_entry;	/* 0x01b8 */
	__be64	__secondary_thread_entry;	/* 0x01c0 */
	uint8_t	reserved_0x1d0[0xe38];

	/* Not part of the naca but it's convenient to put them here */
	struct hv_release_data hv_release_data;
	struct hv_lid_load_table hv_lid_load_table;
} __packed __attribute((aligned(0x10)));

extern struct naca naca;

#endif
