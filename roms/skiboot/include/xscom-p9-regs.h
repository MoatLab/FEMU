// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2016-2019 IBM Corp.
 */

#ifndef __XSCOM_P9_REGS_H__
#define __XSCOM_P9_REGS_H__

/* Core FIR (Fault Isolation Register) */
#define P9_CORE_FIR		0x20010A40

/* Core WOF (Whose On First) */
#define P9_CORE_WOF		0x20010A48

/* pMisc Receive Malfunction Alert Register */
#define P9_MALFUNC_ALERT	0x00090022

#define P9_NX_STATUS_REG	0x02011040 /* NX status register */
#define P9_NX_DMA_ENGINE_FIR	0x02011100 /* DMA & Engine FIR Data Register */
#define P9_NX_PBI_FIR		0x02011080 /* PowerBus Interface FIR Register */

/*
 * Bit 54 from NX status register is set to 1 when HMI interrupt is triggered
 * due to NX checksop.
 */
#define NX_HMI_ACTIVE		PPC_BIT(54)

/* Direct controls */
#define P9_EC_DIRECT_CONTROLS		0x10a9c
#define P9_THREAD_STOP(t)		PPC_BIT(7 + 8*(t))
#define P9_THREAD_CONT(t)		PPC_BIT(6 + 8*(t))
#define P9_THREAD_SRESET(t)		PPC_BIT(4 + 8*(t))
#define P9_THREAD_CLEAR_MAINT(t)	PPC_BIT(3 + 8*(t))
#define P9_THREAD_PWR(t)		PPC_BIT(32 + 8*(t))

#define P9_RAS_STATUS			0x10a02
#define P9_THREAD_QUIESCED(t)		PPC_BITMASK(0 + 8*(t), 3 + 8*(t))

#define P9_CORE_THREAD_STATE		0x10ab3
#define P9_THREAD_INFO			0x10a9b

/* EC_PPM_SPECIAL_WKUP_HYP */
#define P9_SPWKUP_SET			PPC_BIT(0)

#define P9_EC_PPM_SSHHYP		0x0114
#define P9_CORE_GATED			PPC_BIT(0)
#define P9_SPECIAL_WKUP_DONE		PPC_BIT(1)

/* EX (core pair) registers, use XSCOM_ADDR_P9_EX to access */
#define P9X_EX_NCU_STATUS_REG			0x1100f
#define P9X_EX_NCU_SPEC_BAR			0x11010
#define   P9X_EX_NCU_SPEC_BAR_ENABLE		PPC_BIT(0)
#define   P9X_EX_NCU_SPEC_BAR_256K		PPC_BIT(1)
#define   P9X_EX_NCU_SPEC_BAR_ADDRMSK		0x0fffffffffffc000ull /* naturally aligned */

#define P9X_NX_MMIO_BAR				0x201108d
#define  P9X_NX_MMIO_BAR_EN			PPC_BIT(52)
#define  P9X_NX_MMIO_OFFSET			0x00060302031d0000ull

#define P9X_NX_RNG_CFG				0x20110E0
#define  P9X_NX_RNG_CFG_EN			PPC_BIT(63)

#define P9X_EX_NCU_DARN_BAR			0x11011
#define  P9X_EX_NCU_DARN_BAR_EN			PPC_BIT(0)

#define P9_GPIO_DATA_OUT			0x00000000000B0051ull
#define P9_GPIO_DATA_OUT_ENABLE			0x00000000000B0054ull
#define P9_GPIO_INTERRUPT_STATUS		0x00000000000B0057ull
#define P9_GPIO_INTERRUPT_ENABLE		0x00000000000B005Dull
#define P9_GPIO_INTERRUPT_CONDITION		0x00000000000B005Eull

/* xscom address for SCOM Control and data Register */
/* bits 54:60 of SCOM SPRC register is used for core specific SPR selection. */
#define P9_SCOM_SPRC				0x20010A80
#define  P9_SCOMC_SPR_SELECT			PPC_BITMASK(54, 60)
#define  P9_SCOMC_TFMR_T0			0x8	/* 0b0001000 TFMR */

#define P9_SCOM_SPRD				0x20010A81

#define PB_CENT_HP_MODE_CURR			0x5011c0c
#define  PB_CFG_CHG_RATE_GP_MASTER		PPC_BIT(2)
#define  PB_CFG_PUMP_MODE			PPC_BIT(54)

/* Power 9 EC slave per-core power mgt slave registers */
#define EC_PPM_SPECIAL_WKUP_OTR		0x010A
#define EC_PPM_SPECIAL_WKUP_FSP		0x010B
#define EC_PPM_SPECIAL_WKUP_OCC		0x010C
#define EC_PPM_SPECIAL_WKUP_HYP		0x010D

#define OB_BASE(ob)				(((ob) + 9) << 24)
#define OB_CPLT_CONF1(ob)			(OB_BASE(ob) + 0x9)
#define   OB_CPLT_CONF1_NV_IOVALID(brk)		PPC_BIT(6 + (brk))
#define OB_INDIRECT(ob)				((OB_BASE(ob) + 0x10c3f) | PPC_BIT(0))

/* PPE SRAM: Indirect address/data port */
#define OB_PPE_CSAR(ob)				(OB_BASE(ob) + 0x1104d)
#define   OB_PPE_CSAR_SRAM_ADDR			PPC_BITMASK(16, 28)
#define OB_PPE_CSDR(ob)				(OB_BASE(ob) + 0x1104e)

/* PPE SRAM: Indirect registers */
#define OB_PPE_SALT_CMD				0x1fe6
#define   OB_PPE_SALT_CMD_READY			PPC_BIT(0)
#define   OB_PPE_SALT_CMD_RW			PPC_BIT(1)
#define   OB_PPE_SALT_CMD_ERR			PPC_BIT(2)
#define   OB_PPE_SALT_CMD_LINKNUM		PPC_BITMASK(15, 18)
#define   OB_PPE_SALT_CMD_REG			PPC_BITMASK(19, 31)
#define   OB_PPE_SALT_CMD_DATA			PPC_BITMASK(32, 63)

#endif /* __XSCOM_P9_REGS_H__ */
