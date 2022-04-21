// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __CAPP_H
#define __CAPP_H

/*
 * eyecatcher PHB3:  'CAPPLIDH' in ASCII
 * eyecatcher PHB4:  'CAPPLIDH' in ASCII
 */
struct capp_lid_hdr {
	be64 eyecatcher;
	be64 version;
	be64 lid_no;
	be64 pad;
	be64 ucode_offset;
	be64 total_size;
};

struct capp_ucode_data_hdr {
	be64 eyecatcher;	/* 'CAPPUCOD' in ASCII */
	u8 version;
	u8 reg;
	u8 reserved[2];
	be32 chunk_count;	/* Num of 8-byte chunks that follow */
};

struct capp_ucode_data {
	struct capp_ucode_data_hdr hdr;
	be64 data[];
};

struct capp_ucode_lid {
	be64 eyecatcher;	/* 'CAPPULID' in ASCII */
	be64 version;
	be64 data_size;		/* Total size of all capp microcode data */
	u8 reserved[40];
	struct capp_ucode_data data; /* This repeats */
};

enum capp_reg {
	apc_master_cresp		= 0x1,
	apc_master_uop_table		= 0x2,
	snp_ttype			= 0x3,
	snp_uop_table			= 0x4,
	apt_master_capi_ctrl		= 0x5,
	snoop_capi_cnfg			= 0x6,
	canned_presp_map0		= 0x7,
	canned_presp_map1		= 0x8,
	canned_presp_map2		= 0x9,
	flush_sue_state_map		= 0xA,
	apc_master_powerbus_ctrl	= 0xB
};

struct capp_info {
	unsigned int capp_index;
	unsigned int phb_index;
	uint64_t capp_fir_reg;
	uint64_t capp_fir_mask_reg;
	uint64_t capp_fir_action0_reg;
	uint64_t capp_fir_action1_reg;
	uint64_t capp_err_status_ctrl_reg;
};

struct capp_ops {
	int64_t (*get_capp_info)(int, struct phb *, struct capp_info *);
};

struct capp {
	struct phb *phb;
	unsigned int capp_index;
	uint64_t capp_xscom_offset;
	uint64_t attached_pe;
	uint64_t chip_id;
};

struct proc_chip;
extern struct lock capi_lock;
extern struct capp_ops capi_ops;

extern bool capp_ucode_loaded(struct proc_chip *chip, unsigned int index);

extern int64_t capp_load_ucode(unsigned int chip_id, uint32_t opal_id,
			       unsigned int index, u64 lid_eyecatcher,
			       uint32_t reg_offset,
			       uint64_t apc_master_addr,
			       uint64_t apc_master_write,
			       uint64_t snp_array_addr,
			       uint64_t snp_array_write);

extern int64_t capp_get_info(int chip_id, struct phb *phb,
			     struct capp_info *info);


/* Helpers to read/write capp registers */
extern int64_t capp_xscom_read(struct capp *capp, int64_t off, uint64_t *val);
extern int64_t capp_xscom_write(struct capp *capp, int64_t off, uint64_t val);
#endif /* __CAPP_H */
