// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __NX_H
#define __NX_H

/*************************************/
/* Register addresses and bit fields */
/*************************************/

#define NX_P8_SAT(sat, offset)	XSCOM_SAT(0xc, sat, offset)
#define NX_P9_SAT(sat, offset)	XSCOM_SAT(0x4, sat, offset)

/* Random Number Generator */
#define NX_P8_RNG_BAR		NX_P8_SAT(0x2, 0x0d)
#define NX_P9_RNG_BAR		NX_P9_SAT(0x2, 0x0d)
#define   NX_P8_RNG_BAR_ADDR		PPC_BITMASK(14, 51)
/*
 * Section 5.30 of P9 NX Workbook Version 2.42 shows RNG BAR as:
 *	0:7	unused
 *	8:51	RNG BAR Base Address for RNG reads
 *	52	Enable bit for RNG BAR
 *	53:63	Unused
 *
 * Following macros encode that info.
 */
#define   NX_P9_RNG_BAR_ADDR		PPC_BITMASK(8, 51)
#define   NX_RNG_BAR_SIZE		PPC_BITMASK(53, 55)
#define   NX_RNG_BAR_ENABLE		PPC_BIT(52)

#define NX_P8_RNG_CFG		NX_P8_SAT(0x2, 0x12)
#define   NX_RNG_CFG_ENABLE		PPC_BIT(63)

/* Symmetric Crypto */
#define NX_P8_SYM_CFG		NX_P8_SAT(0x2, 0x0a)
#define   NX_SYM_CFG_CI			PPC_BITMASK(2, 14)
#define   NX_SYM_CFG_CT			PPC_BITMASK(18, 23)
#define   NX_SYM_CFG_FC_ENABLE		PPC_BITMASK(32, 39)
#define   NX_SYM_CFG_ENABLE		PPC_BIT(63)

/* Asymmetric Crypto */
#define NX_P8_ASYM_CFG		NX_P8_SAT(0x2, 0x0b)
#define   NX_ASYM_CFG_CI		PPC_BITMASK(2, 14)
#define   NX_ASYM_CFG_CT		PPC_BITMASK(18, 23)
#define   NX_ASYM_CFG_FC_ENABLE		PPC_BITMASK(32, 52)
#define   NX_ASYM_CFG_ENABLE		PPC_BIT(63)

/* 842 Compression. CFG is used only on P8 */
#define NX_P8_842_CFG		NX_P8_SAT(0x2, 0x0c)
#define   NX_842_CFG_CI			PPC_BITMASK(2, 14)
#define   NX_842_CFG_CT			PPC_BITMASK(18, 23)
#define   NX_842_CFG_FC_ENABLE		PPC_BITMASK(32, 36)
#define   NX_842_CFG_ENABLE		PPC_BIT(63)

/* DMA */
#define NX_P8_DMA_CFG		NX_P8_SAT(0x1, 0x02)
#define NX_P9_DMA_CFG		NX_P9_SAT(0x1, 0x02)
#define   NX_DMA_CFG_GZIP_COMPRESS_MAX_RR	PPC_BITMASK(8, 11)
#define   NX_DMA_CFG_GZIP_DECOMPRESS_MAX_RR	PPC_BITMASK(12, 15)
#define   NX_DMA_CFG_GZIP_COMPRESS_PREFETCH	PPC_BIT(16)
#define   NX_DMA_CFG_GZIP_DECOMPRESS_PREFETCH	PPC_BIT(17)
#define   NX_DMA_CFG_842_COMPRESS_PREFETCH	PPC_BIT(23)
#define   NX_DMA_CFG_842_DECOMPRESS_PREFETCH	PPC_BIT(24)
#define   NX_DMA_CFG_AES_SHA_MAX_RR		PPC_BITMASK(25, 28)
#define   NX_DMA_CFG_AMF_MAX_RR			PPC_BITMASK(29, 32)
#define   NX_DMA_CFG_842_COMPRESS_MAX_RR	PPC_BITMASK(33, 36)
#define   NX_DMA_CFG_842_DECOMPRESS_MAX_RR	PPC_BITMASK(37, 40)
#define   NX_DMA_CFG_AES_SHA_CSB_WR		PPC_BITMASK(41, 42)
#define   NX_DMA_CFG_AES_SHA_COMPLETION_MODE	PPC_BITMASK(43, 44)
#define   NX_DMA_CFG_AES_SHA_CPB_WR		PPC_BITMASK(45, 46)
#define   NX_DMA_CFG_AES_SHA_OUTPUT_DATA_WR	PPC_BIT(47)
#define   NX_DMA_CFG_AMF_CSB_WR			PPC_BITMASK(49, 50)
#define   NX_DMA_CFG_AMF_COMPLETION_MODE	PPC_BITMASK(51, 52)
#define   NX_DMA_CFG_AMF_CPB_WR			PPC_BITMASK(53, 54)
#define   NX_DMA_CFG_AMF_OUTPUT_DATA_WR		PPC_BIT(55)
#define   NX_DMA_CFG_842_SPBC			PPC_BIT(56)
#define   NX_DMA_CFG_842_CSB_WR			PPC_BITMASK(57, 58)
#define   NX_DMA_CFG_842_COMPLETION_MODE	PPC_BITMASK(59, 60)
#define   NX_DMA_CFG_842_CPB_WR			PPC_BITMASK(61, 62)
#define   NX_DMA_CFG_842_OUTPUT_DATA_WR		PPC_BIT(63)

/* Engine Enable Register */
#define NX_P8_EE_CFG		NX_P8_SAT(0x1, 0x01)
#define NX_P9_EE_CFG		NX_P9_SAT(0x1, 0x01)
#define   NX_EE_CFG_EFUSE		PPC_BIT(0)
#define   NX_EE_CFG_CH7			PPC_BIT(53) /* AMF */
#define   NX_EE_CFG_CH6			PPC_BIT(54) /* AMF */
#define   NX_EE_CFG_CH5			PPC_BIT(55) /* AMF */
#define   NX_EE_CFG_CH4			PPC_BIT(56) /* AMF */
#define   NX_EE_CFG_CH3			PPC_BIT(57) /* SYM */
#define   NX_EE_CFG_CH2			PPC_BIT(58) /* SYM */
#define   NX_P9_EE_CFG_CH4		PPC_BIT(61) /* gzip */
#define   NX_EE_CFG_CH1			PPC_BIT(62) /* 842 */
#define   NX_EE_CFG_CH0			PPC_BIT(63) /* 842 */

/* Max byte count register - P9 and later */
#define NX_P9_842_MAX_BYTE_COUNT	NX_P9_SAT(0x1, 0x19)
#define NX_P9_GZIP_MAX_BYTE_COUNT	NX_P9_SAT(0x1, 0x1b)

#define NX_P9_DMA_VAS_MMIO_BAR		NX_P9_SAT(0x1, 0x1e)
#define   NX_P9_DMA_VAS_MMIO_ADDR		PPC_BITMASK(8, 38)

/* PowerBus Registers */
#define NX_P8_CRB_IQ		NX_P8_SAT(0x2, 0x0f)
#define   NX_CRB_IQ_SYM			PPC_BITMASK(0, 2)
#define   NX_CRB_IQ_ASYM		PPC_BITMASK(3, 5)

/* UMAC registers - P9 and later */
#define NX_P9_842_HIGH_PRI_RX_FIFO_BAR		NX_P9_SAT(0x3, 0x00)
#define NX_P9_GZIP_HIGH_PRI_RX_FIFO_BAR		NX_P9_SAT(0x3, 0x02)
#define NX_P9_842_NORMAL_PRI_RX_FIFO_BAR	NX_P9_SAT(0x3, 0x09)
#define NX_P9_GZIP_NORMAL_PRI_RX_FIFO_BAR	NX_P9_SAT(0x3, 0x0b)
#define   NX_P9_RX_FIFO_BAR_ADDR			PPC_BITMASK(8, 53)
#define   NX_P9_RX_FIFO_BAR_SIZE			PPC_BITMASK(54, 56)

#define NX_P9_842_HIGH_PRI_RX_FIFO_NOTIFY_MATCH     NX_P9_SAT(0x3, 0x06)
#define NX_P9_GZIP_HIGH_PRI_RX_FIFO_NOTIFY_MATCH    NX_P9_SAT(0x3, 0x08)
#define NX_P9_842_NORMAL_PRI_RX_FIFO_NOTIFY_MATCH   NX_P9_SAT(0x3, 0x0f)
#define NX_P9_GZIP_NORMAL_PRI_RX_FIFO_NOTIFY_MATCH  NX_P9_SAT(0x3, 0x11)
#define   NX_P9_RX_FIFO_NOTIFY_MATCH_LPID		PPC_BITMASK(4, 15)
#define   NX_P9_RX_FIFO_NOTIFY_MATCH_PID		PPC_BITMASK(20, 39)
#define   NX_P9_RX_FIFO_NOTIFY_MATCH_TID		PPC_BITMASK(44, 59)
#define   NX_P9_RX_FIFO_NOTIFY_MATCH_MATCH_ENABLE	PPC_BIT(63)

#define NX_P9_842_HIGH_PRI_RX_FIFO_CTRL		NX_P9_SAT(0x3, 0x03)
#define NX_P9_GZIP_HIGH_PRI_RX_FIFO_CTRL	NX_P9_SAT(0x3, 0x05)
#define NX_P9_842_NORMAL_PRI_RX_FIFO_CTRL	NX_P9_SAT(0x3, 0x0c)
#define NX_P9_GZIP_NORMAL_PRI_RX_FIFO_CTRL	NX_P9_SAT(0x3, 0x0e)
#define	  NX_P9_RX_FIFO_CTRL_READ_OFFSET		PPC_BITMASK(4, 11)
#define   NX_P9_RX_FIFO_CTRL_QUEUED			PPC_BITMASK(15, 23)
#define   NX_P9_RX_FIFO_CTRL_HPRI_MAX_READ		PPC_BITMASK(27, 35)

#define NX_P9_UMAC_TX_WINDOW_CONTEXT_BAR	NX_P9_SAT(0x3, 0x12)
#define   NX_P9_UMAC_TX_WINDOW_CONTEXT_ADDR		PPC_BITMASK(8, 40)

#define NX_P9_UMAC_VAS_MMIO_BAR			NX_P9_SAT(0x3, 0x14)
#define   NX_P9_UMAC_VAS_MMIO_ADDR			PPC_BITMASK(8, 38)

#define NX_P9_UMAC_STATUS_CTRL			NX_P9_SAT(0x3, 0x15)
#define   NX_P9_UMAC_STATUS_CTRL_CRB_ENABLE		PPC_BIT(1)

#define NX_P9_ERAT_STATUS_CTRL			NX_P9_SAT(0x3, 0x16)

/* Introduced in P10, but P10 NX SCOM address is same as P9 */
#define	NX_P10_VAS_RMA_WRITE_BAR		NX_P9_SAT(0x3, 0x19)

/* NX Status Register */
#define NX_P8_STATUS		NX_P8_SAT(0x1, 0x00)
#define NX_P9_STATUS		NX_P9_SAT(0x1, 0x00) /* DMA Status register */
#define   NX_STATUS_HMI_ACTIVE		PPC_BIT(54)
#define   NX_STATUS_PBI_IDLE		PPC_BIT(55)
#define   NX_STATUS_DMA_CH0_IDLE	PPC_BIT(56)
#define   NX_STATUS_DMA_CH1_IDLE	PPC_BIT(57)
#define   NX_STATUS_DMA_CH2_IDLE	PPC_BIT(58)
#define   NX_STATUS_DMA_CH3_IDLE	PPC_BIT(59)
#define   NX_STATUS_DMA_CH4_IDLE	PPC_BIT(60)
#define   NX_STATUS_DMA_CH5_IDLE	PPC_BIT(61)
#define   NX_STATUS_DMA_CH6_IDLE	PPC_BIT(62)
#define   NX_STATUS_DMA_CH7_IDLE	PPC_BIT(63)

/* Channel Status Registers */
#define NX_P8_CH_CRB(ch)	NX_P8_SAT(0x1, 0x03 + ((ch) * 2))
#define NX_P9_CH_CRB(ch)	NX_P9_SAT(0x1, 0x03 + ((ch) * 2))
#define NX_P8_CH_STATUS(ch)	NX_P8_SAT(0x1, 0x04 + ((ch) * 2))
#define   NX_CH_STATUS_ABORT		PPC_BIT(0)
#define   NX_CH_STATUS_CCB_VALID	PPC_BIT(4)
#define   NX_CH_STATUS_CCB_CM		PPC_BITMASK(5, 7)
#define   NX_CH_STATUS_CCB_PRIO		PPC_BITMASK(8, 15)
#define   NX_CH_STATUS_CCB_SN		PPC_BITMASK(16, 31)
#define   NX_CH_STATUS_VALID		PPC_BIT(32)
#define   NX_CH_STATUS_LPID		PPC_BITMASK(38, 47)
#define   NX_CH_STATUS_CCB_ISN		PPC_BITMASK(50, 63)
#define   NX_CH_STATUS_CRB_SJT		PPC_BITMASK(50, 63)

/* Kill Register */
#define NX_P8_CRB_KILL		NX_P8_SAT(0x1, 0x13)
#define NX_P9_CRB_KILL		NX_P9_SAT(0x1, 0x13)
#define   NX_CRB_KILL_LPID_KILL		PPC_BIT(0)
#define   NX_CRB_KILL_LPID		PPC_BITMASK(6, 15)
#define   NX_CRB_KILL_ISN_KILL		PPC_BIT(16)
#define   NX_CRB_KILL_SJT_KILL		PPC_BIT(17)
#define   NX_CRB_KILL_ISN		PPC_BITMASK(18, 31)
#define   NX_CRB_KILL_SJT		PPC_BITMASK(18, 31)
#define   NX_CRB_KILL_DONE		PPC_BIT(32)
#define   NX_CRB_KILL_PBI_LOC		PPC_BITMASK(40, 47)
#define   NX_CRB_KILL_PREFETCH_CH	PPC_BITMASK(48, 55)
#define   NX_CRB_KILL_ALG_CH		PPC_BITMASK(56, 63)

/* Fault Isolation Registers (FIR) */
#define NX_P8_DE_FIR_DATA	NX_P8_SAT(0x4, 0x00)
#define NX_P9_DE_FIR_DATA	NX_P9_SAT(0x4, 0x00)
#define NX_P8_DE_FIR_DATA_CLR	NX_P8_SAT(0x4, 0x01)
#define NX_P9_DE_FIR_DATA_CLR	NX_P9_SAT(0x4, 0x01)
#define NX_P8_DE_FIR_DATA_SET	NX_P8_SAT(0x4, 0x02)
#define NX_P9_DE_FIR_DATA_SET	NX_P9_SAT(0x4, 0x02)
#define NX_P8_DE_FIR_MASK	NX_P8_SAT(0x4, 0x03)
#define NX_P9_DE_FIR_MASK	NX_P9_SAT(0x4, 0x03)
#define NX_P8_DE_FIR_MASK_CLR	NX_P8_SAT(0x4, 0x04)
#define NX_P9_DE_FIR_MASK_CLR	NX_P9_SAT(0x4, 0x04)
#define NX_P8_DE_FIR_MASK_SET	NX_P8_SAT(0x4, 0x05)
#define NX_P9_DE_FIR_MASK_SET	NX_P9_SAT(0x4, 0x05)
#define NX_P8_DE_FIR_ACTION0	NX_P8_SAT(0x4, 0x06)
#define NX_P9_DE_FIR_ACTION0	NX_P9_SAT(0x4, 0x06)
#define NX_P8_DE_FIR_ACTION1	NX_P8_SAT(0x4, 0x07)
#define NX_P9_DE_FIR_ACTION1	NX_P9_SAT(0x4, 0x07)
#define NX_P8_DE_FIR_WOF	NX_P8_SAT(0x4, 0x08)
#define NX_P9_PB_FIR_DATA	NX_P9_SAT(0x2, 0x00)
#define NX_P8_PB_FIR_DATA	NX_P8_SAT(0x2, 0x00)
#define NX_P8_PB_FIR_DATA_CLR	NX_P8_SAT(0x2, 0x01)
#define NX_P9_PB_FIR_DATA_CLR	NX_P9_SAT(0x2, 0x01)
#define NX_P8_PB_FIR_DATA_SET	NX_P8_SAT(0x2, 0x02)
#define NX_P9_PB_FIR_DATA_SET	NX_P9_SAT(0x2, 0x02)
#define NX_P8_PB_FIR_MASK	NX_P8_SAT(0x2, 0x03)
#define NX_P9_PB_FIR_MASK	NX_P9_SAT(0x2, 0x03)
#define NX_P8_PB_FIR_MASK_CLR	NX_P8_SAT(0x2, 0x04)
#define NX_P9_PB_FIR_MASK_CLR	NX_P9_SAT(0x2, 0x04)
#define NX_P8_PB_FIR_MASK_SET	NX_P8_SAT(0x2, 0x05)
#define NX_P9_PB_FIR_MASK_SET	NX_P9_SAT(0x2, 0x05)
#define NX_P8_PB_FIR_ACTION0	NX_P8_SAT(0x2, 0x06)
#define NX_P9_PB_FIR_ACTION0	NX_P9_SAT(0x2, 0x06)
#define NX_P8_PB_FIR_ACTION1	NX_P8_SAT(0x2, 0x07)
#define NX_P9_PB_FIR_ACTION1	NX_P9_SAT(0x2, 0x07)
#define NX_P8_PB_FIR_WOF	NX_P8_SAT(0x2, 0x08)
#define   NX_FIR_SHM_INV		PPC_BIT(1)
#define   NX_FIR_CH0_ECC_CE		PPC_BIT(4)
#define   NX_FIR_CH0_ECC_UE		PPC_BIT(5)
#define   NX_FIR_CH1_ECC_CE		PPC_BIT(6)
#define   NX_FIR_CH1_ECC_UE		PPC_BIT(7)
#define   NX_FIR_DMA_NZ_CSB_CC		PPC_BIT(8) /* lab use only */
#define   NX_FIR_DMA_ARRAY_ECC_CE	PPC_BIT(9)
#define   NX_FIR_DMA_RW_ECC_CE		PPC_BIT(10)
#define   NX_FIR_CH5_ECC_CE		PPC_BIT(11)
#define   NX_FIR_CH6_ECC_CE		PPC_BIT(12)
#define   NX_FIR_CH7_ECC_CE		PPC_BIT(13)
#define   NX_FIR_OTHER_SCOM_ERR		PPC_BIT(14)
#define   NX_FIR_DMA_INV_STATE		PPC_BITMASK(15, 16)
#define   NX_FIR_DMA_ARRAY_ECC_UE	PPC_BIT(17)
#define   NX_FIR_DMA_RW_ECC_UE		PPC_BIT(18)
#define   NX_FIR_HYP			PPC_BIT(19) /* for HYP to force HMI */
#define   NX_FIR_CH0_INV_STATE		PPC_BIT(20)
#define   NX_FIR_CH1_INV_STATE		PPC_BIT(21)
#define   NX_FIR_CH2_INV_STATE		PPC_BIT(22)
#define   NX_FIR_CH3_INV_STATE		PPC_BIT(23)
#define   NX_FIR_CH4_INV_STATE		PPC_BIT(24)
#define   NX_FIR_CH5_INV_STATE		PPC_BIT(25)
#define   NX_FIR_CH6_INV_STATE		PPC_BIT(26)
#define   NX_FIR_CH7_INV_STATE		PPC_BIT(27)
#define   NX_FIR_CH5_ECC_UE		PPC_BIT(28)
#define   NX_FIR_CH6_ECC_UE		PPC_BIT(29)
#define   NX_FIR_CH7_ECC_UE		PPC_BIT(30)
#define   NX_FIR_CRB_UE			PPC_BIT(31)
#define   NX_FIR_CRB_SUE		PPC_BIT(32)
#define   NX_FIR_DMA_RW_ECC_SUE		PPC_BIT(33)
#define   NX_FIR_CH4_ECC_CE		PPC_BIT(36) /* P8 only */
#define   NX_FIR_CH5_ECC_UE_2		PPC_BIT(37) /* P8 only */
#define   NX_FIR_P8_PARITY		PPC_BITMASK(48, 49)

/* Rx FIFO is needed for VAS which is available on P9 or later */
#define RX_FIFO_SIZE	0x8000

/**************************************/
/* Register field values/restrictions */
/**************************************/

/* Arbitrary Coprocessor Type values */
#define NX_CT_SYM	(1)
#define NX_CT_ASYM	(2) /* on P8 */
#define NX_CT_GZIP	(2) /* on P9 and later */
#define NX_CT_842	(3)

/* Coprocessor Instance counter
 * NX workbook, section 5.5.1
 * "Assigning <CT,CI> Values"
 * Only on P8
 */
#define NX_SYM_CFG_CI_MAX	(511)
#define NX_SYM_CFG_CI_LSHIFT	(2)
#define NX_ASYM_CFG_CI_MAX	(127)
#define NX_ASYM_CFG_CI_LSHIFT	(4)
#define NX_842_CFG_CI_MAX	(511)
#define NX_842_CFG_CI_LSHIFT	(2)

/* DMA configuration values
 * NX workbook, section 5.2.3, table 5-4
 * "DMA Configuration Register Bits"
 *
 * These values can be used for the AES/SHA, AMF, and 842 DMA
 * configuration fields in the DMA configuration register.
 *
 * Abbreviations used below:
 *   pDMA - "partial DMA write"
 *   fDMA - "full DMA write"
 *   CI - Cache Inject
 */
/* NX_DMA_CSB_WR values:
 * 0 = Always perform 8 or 16 byte pDMA
 * 1 = Do 128 byte CI if CSB at end of cache line, else pDMA
 * 2 = Do 128 byte fDMA if CSB at end of cache line, else pDMA
 */
#define NX_DMA_CSB_WR_PDMA		(0)
#define NX_DMA_CSB_WR_CI		(1)
#define NX_DMA_CSB_WR_FDMA		(2)
/* NX_DMA_COMPLETION_MODE values:
 * 0 = Always perform 8 byte pDMA
 * 1 = Do 128 byte CI, replicating 8 bytes across entire 128 byte cache line
 * 2 = Do 128 byte fDMA, replicating 8 bytes across entire 128 byte cache line
 */
#define NX_DMA_COMPLETION_MODE_PDMA	(0)
#define NX_DMA_COMPLETION_MODE_CI	(1)
#define NX_DMA_COMPLETION_MODE_FDMA	(2)
/* NX_DMA_CPB_WR values:
 * 0 = Always do pDMA or fDMA, based on number of bytes and alignment
 * 1 = Always do pDMA on non-aligned cache lines, fDMA on aligned cache lines
 *      (may store dummy data at the end of the aligned data)
 * 2 = Do 128 byte CI when writing 128 aligned bytes, else pDMA
 * 3 = Do 128 byte CI when writing aligned cache lines, else pDMA
 *      (may store dummy data at the end of the aligned data)
 */
#define NX_DMA_CPB_WR_DMA_NOPAD		(0)
#define NX_DMA_CPB_WR_DMA_PAD		(1)
#define NX_DMA_CPB_WR_CI_NOPAD		(2)
#define NX_DMA_CPB_WR_CI_PAD		(3)
/* NX_DMA_OUTPUT_DATA_WR values:
 * 0 = Always do pDMA or fDMA, based on number of bytes and alignment
 * 1 = Do 128 byte CI when writing 128 aligned bytes, else pDMA
 */
#define NX_DMA_OUTPUT_DATA_WR_DMA	(0)
#define NX_DMA_OUTPUT_DATA_WR_CI	(1)


/*
 * NX compression configuration settings for 842 (on p8 and later)
 * and gzip (p9 and later) engines
 */
#define DMA_COMPRESS_PREFETCH	(1) /* enable prefetching */
#define DMA_DECOMPRESS_PREFETCH	(1) /* enable prefetching */
#define DMA_COMPRESS_MAX_RR	(15) /* range 1-15 */
#define DMA_DECOMPRESS_MAX_RR	(15) /* range 1-15 */
#define DMA_SPBC		(1) /* write SPBC in CPB */

/******************************/
/* NX node creation functions */
/******************************/

extern void nx_create_rng_node(struct dt_node *);
extern void nx_create_crypto_node(struct dt_node *);
extern void nx_create_compress_node(struct dt_node *);

extern void nx_enable_842(struct dt_node *node, u32 gcid, u32 pb_base);
extern void p9_nx_enable_842(struct dt_node *node, u32 gcid, u32 pb_base);
extern void p9_nx_enable_gzip(struct dt_node *node, u32 gcid, u32 pb_base);

extern int nx_cfg_rx_fifo(struct dt_node *node, const char *compat,
			const char *priority, u32 gcid, u32 pid, u32 tid,
			u64 umac_bar, u64 umac_notify);

extern void nx_init(void);

#endif /* __NX_H */
