// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2015 IBM Corp. */

#ifndef __OPAL_DUMP_H
#define __OPAL_DUMP_H

/*
 * Dump region ids
 *
 * 0x01 - 0x3F : OPAL
 * 0x40 - 0x7F : Reserved for future use
 * 0x80 - 0xFF : Kernel
 *
 */
#define DUMP_REGION_OPAL_START		0x01
#define DUMP_REGION_OPAL_END		0x3F
#define DUMP_REGION_HOST_START		OPAL_DUMP_REGION_HOST_START
#define DUMP_REGION_HOST_END		OPAL_DUMP_REGION_HOST_END

#define DUMP_REGION_CONSOLE	0x01
#define DUMP_REGION_HBRT_LOG	0x02
#define DUMP_REGION_OPAL_MEMORY	0x03
#define DUMP_REGION_KERNEL	0x80

/* Mainstore memory to be captured by FSP SYSDUMP */
#define DUMP_TYPE_SYSDUMP		0xF5
/* Mainstore memory to preserve during IPL */
#define DUMP_TYPE_MPIPL			0x00

/*
 *  Memory Dump Source Table
 *
 * Format of this table is same as Memory Dump Source Table (MDST)
 * defined in HDAT spec.
 */
struct mdst_table {
	__be64	addr;
	uint8_t	data_region;	/* DUMP_REGION_* */
	uint8_t dump_type;	/* DUMP_TYPE_* */
	__be16	reserved;
	__be32	size;
} __packed;

/* Memory dump destination table (MDDT) */
struct mddt_table {
	__be64	addr;
	uint8_t	data_region;
	uint8_t dump_type;
	__be16	reserved;
	__be32	size;
} __packed;

/*
 * Memory dump result table (MDRT)
 *
 * List of the memory ranges that have been included in the dump. This table is
 * filled by hostboot and passed to OPAL on second boot. OPAL/payload will use
 * this table to extract the dump.
 */
struct mdrt_table {
	__be64	src_addr;
	__be64	dest_addr;
	uint8_t	data_region;
	uint8_t dump_type;
	__be16	reserved;
	__be32	size;
	__be64	padding;
} __packed;

/*
 * Processor Dump Area
 *
 * This contains the information needed for having processor
 * state captured during a platform dump.
 */
struct proc_dump_area {
	__be32	thread_size;	/* Size of each thread register entry */
#define PROC_DUMP_AREA_FORMAT_P9	0x1	/* P9 format */
	uint8_t	version;	/* P9 - 0x1 */
	uint8_t	reserved[11];
	__be64	alloc_addr;	/* Destination memory to place register data */
	__be32	reserved2;
	__be32	alloc_size;	/* Allocated size */
	__be64	dest_addr;	/* Destination address */
	__be32	reserved3;
	__be32	act_size;	/* Actual data size */
} __packed;

struct proc_reg_data_hdr {
	/* PIR value of the thread */
	__be32	pir;
	/* 0x00 - 0x0F - The corresponding stop state of the core */
	uint8_t	core_state;
	uint8_t	reserved[3];

	uint32_t offset;	/* Offset to Register Entries array */
	uint32_t ecnt;		/* Number of entries */
	uint32_t esize;		/* Alloc size of each array entry in bytes */
	uint32_t eactsz;	/* Actual size of each array entry in bytes */
} __packed;

/* Architected register data content */
#define ARCH_REG_TYPE_GPR	0x01
#define ARCH_REG_TYPE_SPR	0x02
struct proc_reg_data {
	uint32_t reg_type;	/* ARCH_REG_TYPE_* */
	uint32_t reg_num;
	uint64_t reg_val;
} __packed;

/* Metadata to capture before triggering MPIPL */
struct mpipl_metadata {
	/* Crashing PIR is required to create OPAL dump */
	uint32_t	crashing_pir;
	/* Kernel expects OPAL to presrve tag and pass it back via OPAL API */
	uint64_t	kernel_tag;
	/* Post MPIPL kernel boot memory size */
	uint64_t	boot_mem_size;
} __packed;

/* init opal dump */
extern void opal_mpipl_init(void);

/* Save metadata before triggering MPIPL */
void opal_mpipl_save_crashing_pir(void);

/* Reserve memory to capture OPAL dump */
extern void opal_mpipl_reserve_mem(void);

/* Check MPIPL enabled or not */
extern bool is_mpipl_enabled(void);

#endif	/* __OPAL_DUMP_H */
