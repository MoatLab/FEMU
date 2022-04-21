#ifndef __XSCOM_P10_REGS_H__
#define __XSCOM_P10_REGS_H__

/* Core FIR (Fault Isolation Register) */
#define P10_CORE_FIR		0x440

#define P10_CORE_FIRMASK_OR	0x445

/* Core WOF (Whose On First) */
#define P10_CORE_WOF		0x448

#define P10_MALFUNC_ALERT	0x00090022

#define P10_NX_STATUS_REG	0x02011040 /* NX status register */
#define P10_NX_DMA_ENGINE_FIR	0x02011100 /* DMA & Engine FIR Data Register */
#define P10_NX_PBI_FIR		0x02011080 /* PowerBus Interface FIR Register */

#define P10_EC_CORE_THREAD_STATE	0x412 /* XXX P10 is this right? */
#define P10_THREAD_STOPPED(t)		PPC_BIT(56 + (t))

#define P10_EC_THREAD_INFO		0x413
#define P10_THREAD_ACTIVE(t)		PPC_BIT(t)

#define P10_EC_RAS_STATUS		0x454
#define P10_THREAD_MAINT(t)		PPC_BIT(0 + 8*(t))
#define P10_THREAD_QUIESCED(t)		PPC_BIT(1 + 8*(t))
#define P10_THREAD_ICT_EMPTY(t)		PPC_BIT(2 + 8*(t))

#define P10_EC_DIRECT_CONTROLS		0x449
#define P10_THREAD_STOP(t)		PPC_BIT(7 + 8*(t))
#define P10_THREAD_START(t)		PPC_BIT(6 + 8*(t))
#define P10_THREAD_SRESET(t)		PPC_BIT(4 + 8*(t))
#define P10_THREAD_CLEAR_MAINT(t)	PPC_BIT(3 + 8*(t))
#define P10_THREAD_PWR(t)		PPC_BIT(32 + 8*(t))

#define P10_QME_FIR			0x000

#define P10_QME_SPWU_HYP		0x83c
#define P10_SPWU_REQ			PPC_BIT(0)
#define P10_SPWU_DONE			PPC_BIT(4)

#define P10_QME_SSH_HYP			0x82c
#define P10_SSH_CORE_GATED		PPC_BIT(0)
#define P10_SSH_SPWU_DONE		PPC_BIT(1)

#define P10_NCU_STATUS_REG		0x64f
#define P10_NCU_SPEC_BAR		0x650
#define   P10_NCU_SPEC_BAR_ENABLE	PPC_BIT(0)
#define   P10_NCU_SPEC_BAR_256K		PPC_BIT(1)
#define   P10_NCU_SPEC_BAR_ADDRMSK	0x000fffffffffc000ull /* 16k aligned */

#define P10_NCU_DARN_BAR		0x651
#define  P10_NCU_DARN_BAR_EN		PPC_BIT(0)
#define  P10_NCU_DARN_BAR_ADDRMSK	0x000ffffffffff000ull /* 4k aligned */

#endif /* __XSCOM_P10_REGS_H__ */
