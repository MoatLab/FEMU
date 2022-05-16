// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2015 IBM Corp. */

#ifndef __FSP_ATTN_H
#define __FSP_ATTN_H

/* Per spec attn area can go up to 0x400  bytes */
#define ATTN_AREA_SZ		0x400

extern struct sp_attn_area cpu_ctl_sp_attn_area1;
extern struct sp_attn_area cpu_ctl_sp_attn_area2;

struct spat_entry {
	/* Virtual address */
	__be64	vaddr;
	/* Partition id */
	__be16	id;
	uint8_t reserved[6];
} __packed;

/* SP Address Table: Structure is not used as of today, defined to
 * keep in sync with the spec */
struct sp_addr_table {
	/* Index of last valid spat entry */
	__be32			idx;
	/* Number of SPAT entries allocated = 31 for SP */
	__be32			count;
	uint8_t			reserved1[8];
	/* SPAT entries */
	struct spat_entry	spat_entry[31];
} __packed;

/* SP Attention Areas */
struct sp_attn_area {
	/* Processor Number */
	uint8_t		processor;
	/* Attention command */
	uint8_t		attn_cmd;
	__be16		data_len;
	uint8_t		data[];
} __packed __align(ATTN_AREA_SZ);

#define	SRC_WORD_COUNT	8
#define SRC_LEN		32
/* Max limit of user data size is 940 (due to attention area size) */
#define TI_MSG_LEN	940

/* Maximum sapphire version length (approx) */
#define VERSION_LEN	80
/* Up to 10 frames each of length 40 bytes + header = 430 bytes */
#define BT_FRAME_LEN 430
/* File info length : Use the rest of the memory for file details */
#define FILE_INFO_LEN	(TI_MSG_LEN - VERSION_LEN - BT_FRAME_LEN)

struct user_data {
	char		version[VERSION_LEN];
	char		bt_buf[BT_FRAME_LEN];
	char		file_info[FILE_INFO_LEN];
} __packed;

/* Terminate Immediate Attention */
struct ti_attn {
	/* Command valid */
	uint8_t		cmd_valid;
	/* Attention command */
	uint8_t		attn_cmd;
	__be16		data_len;
	/* Controls dump actions */
	uint8_t		dump_ctrl;
	uint8_t		reserved1;
	/* Hardware dump type */
	__be16		dump_type;
	/* SRC format */
	uint8_t		src_fmt;
	/* SRC flags */
	uint8_t		src_flags;
	/* Number of ASCII words */
	uint8_t		ascii_cnt;
	/* Number of HEX words */
	uint8_t		hex_cnt;
	__be16		reserved2;
	/* SRC length */
	__be16		src_len;
	__be32		src_word[SRC_WORD_COUNT];
	/* ASCII data */
	char		src[SRC_LEN];
	__be32		msg_len;
	/* User data: Debug details */
	struct user_data msg;
} __packed __align(ATTN_AREA_SZ);

/* Hypervisor Service Routine Data area: Structure is not used as of today,
 * defined to keep in sync with the spec */
struct hsr_data_area {
	/* MS Address Compare Address */
	__be64		ms_cmp_addr;
	/* MS Address Compare Op (set/reset) */
	__be16		ms_cmp_op;
	/* MS Address Compare Length */
	__be16		ms_cmp_len;
	/* MS Address Compare Data */
	__be32		ms_cmp_data;
	/* MS Address Compare Service Routine */
	__be64		ms_cmp_sr;
	/* Pointer to MS Display / Alter HSR */
	__be64		ms_display;
	__be64		reserved1;
	/* MS Dump HSR */
	__be64		ms_dump_hsr;
	/* Pointer to Real Address Validation HSR */
	__be64		hsr_raddr;
	/* Effective Address Field */
	__be64		eaddr;
	/* Pointer to CPU Spin HSR */
	__be64		hsr_cpu_spin;
	/* Pointer to SP Glue HSR */
	__be64		hsr_sp_glue;
	uint8_t		reserved2[19];
	/* Time Base Flags
	 * bit 7 (0x01) = 0b1: hardware time base disabled
	 * other bits reserved
	 */
	uint8_t		time_flags;
	uint8_t		reserved3[12];
	/* TDE Addr Parm */
	__be64		tde_addr;
	/* SDR1 Shared Processor HSR */
	__be64		hsr_sdr1_proc;
	__be64		partition_id;
	uint8_t		reserved4[12];
	/* Address Type for Compare
	 * 1 = real address
	 * 2 = effective address
	 * 3 = virtual address
	 */
	__be16		ms_addr_type;
	uint8_t		reserved5[10];
	/* Cache Flush Service Routine Pointer */
	__be64		cfsr;
	uint8_t         reserved6[88];
} __packed;

#endif	/* __FSP_ATTN_H */
