// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2013-2019 IBM Corp.
 */

#ifndef __XSCOM_P8_REGS_H__
#define __XSCOM_P8_REGS_H__

/* Core FIR (Fault Isolation Register) */
#define P8_CORE_FIR		0x10013100

/* Direct controls */
#define P8_EX_TCTL_DIRECT_CONTROLS(t)	(0x10013000 + (t) * 0x10)
#define P8_DIRECT_CTL_STOP		PPC_BIT(63)
#define P8_DIRECT_CTL_PRENAP		PPC_BIT(47)
#define P8_DIRECT_CTL_SRESET		PPC_BIT(60)

/* pMisc Receive Malfunction Alert Register */
#define P8_MALFUNC_ALERT	0x02020011

#define P8_NX_STATUS_REG	0x02013040 /* NX status register */
#define P8_NX_DMA_ENGINE_FIR	0x02013100 /* DMA & Engine FIR Data Register */
#define P8_NX_PBI_FIR		0x02013080 /* PowerBus Interface FIR Register */

/*
 * Bit 54 from NX status register is set to 1 when HMI interrupt is triggered
 * due to NX checksop.
 */
#define NX_HMI_ACTIVE		PPC_BIT(54)

/* Per core power mgt registers */
#define PM_OHA_MODE_REG		0x1002000D
#define L2_FIR_ACTION1		0x10012807

/* EX slave per-core power mgt slave regisers */
#define EX_PM_GP0			0x0100
#define EX_PM_GP1			0x0103
#define EX_PM_CLEAR_GP1			0x0104 /* AND SCOM */
#define EX_PM_SET_GP1			0x0105 /* OR SCOM */
#define EX_PM_SPECIAL_WAKEUP_FSP	0x010B
#define EX_PM_SPECIAL_WAKEUP_OCC	0x010C
#define EX_PM_SPECIAL_WAKEUP_PHYP	0x010D
#define EX_PM_IDLE_STATE_HISTORY_PHYP	0x0110
#define EX_PM_IDLE_STATE_HISTORY_FSP	0x0111
#define EX_PM_IDLE_STATE_HISTORY_OCC	0x0112
#define EX_PM_IDLE_STATE_HISTORY_PERF	0x0113
#define EX_PM_CORE_PFET_VRET		0x0130
#define EX_PM_CORE_ECO_VRET		0x0150
#define EX_PM_PPMSR			0x0153
#define EX_PM_PPMCR			0x0159

/* Power mgt bits in GP0 */
#define EX_PM_GP0_SPECIAL_WAKEUP_DONE		PPC_BIT(31)

/* Power mgt settings in GP1 */
#define EX_PM_SETUP_GP1_FAST_SLEEP		0xD800000000000000ULL
#define EX_PM_SETUP_GP1_DEEP_SLEEP		0x2400000000000000ULL
#define EX_PM_SETUP_GP1_FAST_SLEEP_DEEP_WINKLE	0xC400000000000000ULL
#define EX_PM_GP1_SLEEP_WINKLE_MASK		0xFC00000000000000ULL
#define EX_PM_SETUP_GP1_PM_SPR_OVERRIDE_EN	0x0010000000000000ULL
#define EX_PM_SETUP_GP1_DPLL_FREQ_OVERRIDE_EN	0x0020000000000000ULL

/* Fields in history regs */
#define EX_PM_IDLE_ST_HIST_PM_STATE_MASK	PPC_BITMASK(0, 2)
#define EX_PM_IDLE_ST_HIST_PM_STATE_LSH		PPC_BITLSHIFT(2)

#endif /* __XSCOM_P8_REGS_H__ */
