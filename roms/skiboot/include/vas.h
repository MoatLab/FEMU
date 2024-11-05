// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2018 IBM Corp. */

#ifndef __VAS_H
#define __VAS_H

#include <xscom.h>

/*
 * Abbreviations used in VAS:
 *	WC:	Window Context
 *	WCM:	Window Context MMIO
 *	HVWC:	Hypervisor Window Context
 *	UWC:	OS/User Window Context
 *	UWCM:	OS/User Window Context MMIO
 *	WIDM:	Window ID MMIO
 *	BAR:	Base Address Register
 *	BAMR:	Base Address Mask Register
 *	N (S):	North (South)
 *	CONTS	Contents
 *	FIR:	Fault Isolation Register
 *	RMA:	Real Mode Addressing
 *	CQ:	(Power Bus) Common Queue
 */

extern void vas_init(void);
extern __attrconst bool vas_nx_enabled(void);
extern __attrconst uint64_t vas_get_hvwc_mmio_bar(const int chipid);
extern __attrconst uint64_t vas_get_wcbs_bar(int chipid);
extern __attrconst uint64_t vas_get_rma_bar(int chipid);

/*
 * HVWC and UWC BAR.
 *
 * A Power node can have (upto?) 8 Power chips.
 *
 * There is one instance of VAS in each Power chip. Each instance of VAS
 * has 64K windows, which can be used to send/receive messages from
 * software threads and coprocessors.
 *
 * Each window is described by two types of window contexts:
 *
 *      Hypervisor Window Context (HVWC) of size VAS_HVWC_SIZE bytes
 *      OS/User Window Context (UWC) of size VAS_UWC_SIZE bytes.
 *
 * A window context can be viewed as a set of 64-bit registers. The settings
 * of these registers control/determine the behavior of the VAS hardware
 * when messages are sent/received through the window.
 *
 * Each Power chip i.e each instance of VAS, is assigned two distinct ranges
 * (one for each type of context) of Power-bus addresses (aka Base Address
 * Region or BAR) which can be used to access the window contexts in that
 * instance of VAS.
 *
 * The HVWC BAR for a chip is the contigous region of power-bus addresses
 * containing the (64K) hypervisor window contexts of the chip. Similarly,
 * the UWC BAR is the region of power-bus addresses containing the 64K
 * OS/User Window contexts of the chip. We get the start address of the
 * HVWC and UWC BAR using phys_map_get(). See also get_hvwc_mmio_bar()
 * and get_uwc_mmio_bar().
 */
/* Window Context Backing Store Size */
#define VAS_WCBS_SIZE			0x800000        /* 8MB */

/* Window context size of each window */
#define VAS_WC_SIZE			512

#define VAS_WINDOWS_PER_CHIP		65536		/* 64K */

/*
 * SCOM Base Address from P9/P10 SCOM Assignment spreadsheet
 */
#define	P9_VAS_SCOM_BASE_ADDR		0x03011800
#define VAS_SCOM_BASE_ADDR		0x02011400

/*
 * NOTE: VAS_SCOM_BASE_ADDR (0x3011800) includes the SCOM ring of 6. So,
 *	 setting the ring to 0 here.
 *
 *	 The satellite and offset values below are from "Table 3.1 VAS
 *	 Internal Register Listing" of the P9 VAS Workbook.
 */
#define VAS_P9_SAT(sat, offset)		XSCOM_SAT(0x0, sat, offset)

#define VAS_FIR0			VAS_P9_SAT(0x0, 0x0)
#define VAS_FIR_MASK			VAS_P9_SAT(0x0, 0x3)
#define VAS_FIR_ACTION0			VAS_P9_SAT(0x0, 0x6)
#define VAS_FIR_ACTION1			VAS_P9_SAT(0x0, 0x7)

#define VAS_WCM_BAR			VAS_P9_SAT(0x0, 0xA)
#define VAS_UWCM_BAR			VAS_P9_SAT(0x0, 0xB)
#define VAS_BUF_CTL			VAS_P9_SAT(0x0, 0xC)
#define VAS_MISC_N_CTL			VAS_P9_SAT(0x0,	0xD)
#define VAS_RMA_BAR			VAS_P9_SAT(0x0, 0xE)
#define VAS_RMA_BAMR			VAS_P9_SAT(0x0, 0xF)
#define VAS_WIDM_CTL			VAS_P9_SAT(0x0, 0x29)
#define VAS_WIDM_DATA			VAS_P9_SAT(0x0, 0x2A)
#define VAS_IN_CERR_RPT_CONTS		VAS_P9_SAT(0x0, 0x2B)
#define VAS_RG_CERR_RPT_CONTS		VAS_P9_SAT(0x0, 0x2C)
#define VAS_WIDM_ECC			VAS_P9_SAT(0x0, 0x31)

#define VAS_WCBS_BAR			VAS_P9_SAT(0x1, 0x0)
#define VAS_CQ_CERR_RPT_CONTS		VAS_P9_SAT(0x1, 0x8)
#define VAS_WC_CERR_RPT_CONTS		VAS_P9_SAT(0x1, 0x9)
#define VAS_EG_CERR_RPT_CONTS		VAS_P9_SAT(0x1, 0xA)

#define VAS_PB_CFG0			VAS_P9_SAT(0x1, 0xD)
#define VAS_PB_CFG1			VAS_P9_SAT(0x1, 0xE)
#define VAS_MISC_S_CTL			VAS_P9_SAT(0x1,	0xF)

#define VAS_BUF_CTL_FREE_COUNT		PPC_BITMASK(49:55)
#define VAS_BUF_CTL_USED_COUNT		PPC_BITMASK(57:63)
#define VAS_RMA_BAR_ADDR		PPC_BITMASK(8, 51)
#define VAS_RMA_BAMR_MASK		PPC_BITMASK(8, 51)

/* Some VAS Miscellaneous Status and North Control Register bits. */
#define VAS_64K_MODE_MASK		PPC_BIT(0)
#define VAS_ACCEPT_PASTE_MASK		PPC_BIT(1)
#define VAS_QUIESCE_REQ_MASK		PPC_BIT(4)
#define VAS_ENABLE_WC_MMIO_BAR		PPC_BIT(6)
#define VAS_ENABLE_UWC_MMIO_BAR		PPC_BIT(7)
#define VAS_ENABLE_RMA_MMIO_BAR		PPC_BIT(8)
#define VAS_HMI_ACTIVE_MASK		PPC_BIT(58)
#define VAS_RG_IDLE_MASK		PPC_BIT(59)

/* Some PowerBus Configuration Register 0 Bits */
#define VAS_CQ_SCOM_HANG_POLL_MAX	PPC_BITMASK(7, 10)
#define VAS_CQ_SCOM_HANG_NX_MAX		PPC_BITMASK(15, 18)

#define VAS_RMA_BAR_ADDR_MASK		PPC_BITMASK(8, 51)
#define VAS_RMA_BAMR_ADDR_MASK		PPC_BITMASK(8, 51)

#endif
