// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __PROCESSOR_H
#define __PROCESSOR_H

#include <bitutils.h>

/* MSR bits */
#define MSR_SF		PPC_BIT(0)	/* 64-bit mode */
#define MSR_HV		PPC_BIT(3)	/* Hypervisor mode */
#define MSR_VEC		PPC_BIT(38)	/* VMX enable */
#define MSR_VSX		PPC_BIT(40)	/* VSX enable */
#define MSR_S		PPC_BIT(41)	/* Secure mode */
#define MSR_EE		PPC_BIT(48)	/* External Int. Enable */
#define MSR_PR		PPC_BIT(49)       	/* Problem state */
#define MSR_FP		PPC_BIT(50)	/* Floating Point Enable */
#define MSR_ME		PPC_BIT(51)	/* Machine Check Enable */
#define MSR_FE0		PPC_BIT(52)	/* FP Exception 0 */
#define MSR_SE		PPC_BIT(53)	/* Step enable */
#define MSR_BE		PPC_BIT(54)	/* Branch trace enable */
#define MSR_FE1		PPC_BIT(55)	/* FP Exception 1 */
#define MSR_IR		PPC_BIT(58)	/* Instructions reloc */
#define MSR_DR		PPC_BIT(59)	/* Data reloc */
#define MSR_PMM		PPC_BIT(61)	/* Perf Monitor */
#define MSR_RI		PPC_BIT(62)	/* Recoverable Interrupt */
#define MSR_LE		PPC_BIT(63)	/* Little Endian */

/* PIR */
#define SPR_PIR_P10_MASK	0x7fff	/* Mask of implemented bits */
#define SPR_PIR_P9_MASK		0x7fff	/* Mask of implemented bits */
#define SPR_PIR_P8_MASK		0x1fff	/* Mask of implemented bits */

/* SPR register definitions */
#define SPR_DSCR	0x011	/* RW: Data stream control reg */
#define SPR_DSISR	0x012	/* RW: Data storage interrupt status reg */
#define SPR_DAR		0x013	/* RW: Data address reg */
#define SPR_DEC		0x016	/* RW: Decrement Register */
#define SPR_SDR1	0x019
#define SPR_SRR0	0x01a	/* RW: Exception save/restore reg 0 */
#define SPR_SRR1	0x01b	/* RW: Exception save/restore reg 1 */
#define SPR_CFAR	0x01c	/* RW: Come From Address Register */
#define SPR_AMR		0x01d	/* RW: Authority Mask Register */
#define SPR_IAMR	0x03d	/* RW: Instruction Authority Mask Register */
#define SPR_RPR		0x0ba   /* RW: Relative Priority Register */
#define SPR_TBRL	0x10c	/* RO: Timebase low */
#define SPR_TBRU	0x10d	/* RO: Timebase high */
#define SPR_SPRC	0x114	/* RW: Access to uArch SPRs (ex SCOMC) */
#define SPR_SPRD	0x115	/* RW: Access to uArch SPRs (ex SCOMD) */
#define	SPR_SCOMC	0x114	/* RW: SCOM Control - old name of SPRC */
#define	SPR_SCOMD	0x115	/* RW: SCOM Data    - old name of SPRD */
#define SPR_TBWL	0x11c	/* RW: Timebase low */
#define SPR_TBWU	0x11d	/* RW: Timebase high */
#define SPR_TBU40	0x11e	/* RW: Timebase Upper 40 bit */
#define SPR_PVR		0x11f	/* RO: Processor version register */
#define SPR_HSPRG0	0x130	/* RW: Hypervisor scratch 0 */
#define SPR_HSPRG1	0x131	/* RW: Hypervisor scratch 1 */
#define SPR_SPURR	0x134	/* RW: Scaled Processor Utilization Resource */
#define SPR_PURR	0x135	/* RW: Processor Utilization Resource reg */
#define SPR_HDEC	0x136	/* RW: Hypervisor Decrementer */
#define SPR_HRMOR	0x139	/* RW: Hypervisor Real Mode Offset reg */
#define SPR_HSRR0	0x13a	/* RW: HV Exception save/restore reg 0 */
#define SPR_HSRR1	0x13b	/* RW: HV Exception save/restore reg 1 */
#define SPR_TFMR	0x13d
#define SPR_LPCR	0x13e
#define SPR_HMER	0x150	/* Hypervisor Maintenance Exception */
#define SPR_HMEER	0x151	/* HMER interrupt enable mask */
#define SPR_PCR		0x152
#define SPR_AMOR	0x15d
#define SPR_USRR0	0x1fa   /* RW: Ultravisor Save/Restore Register 0 */
#define SPR_USRR1	0x1fb   /* RW: Ultravisor Save/Restore Register 1 */
#define SPR_SMFCTRL	0x1ff   /* RW: Secure Memory Facility Control */
#define SPR_PSSCR	0x357   /* RW: Stop status and control (ISA 3) */
#define SPR_PPR32	0x382
#define SPR_TSCR	0x399
#define SPR_HID0	0x3f0
#define SPR_HID1	0x3f1
#define SPR_HID2	0x3f8
#define SPR_HID4	0x3f4
#define SPR_HID5	0x3f6
#define SPR_PIR		0x3ff	/* RO: Processor Identification */

/* Bits in SRR1 */

#define SPR_SRR1_PM_WAKE_MASK	0x3c0000	/* PM wake reason for P8/9 */
#define SPR_SRR1_PM_WAKE_SRESET	0x100000
#define SPR_SRR1_PM_WAKE_MCE	0x3c0000	/* Use reserved value for MCE */

/* Bits in LPCR */

/* Powersave Exit Cause Enable is different on each generation */
#define SPR_LPCR_P8_PECE	PPC_BITMASK(47,51)
#define SPR_LPCR_P8_PECE0	PPC_BIT(47)   /* Wake on priv doorbell */
#define SPR_LPCR_P8_PECE1	PPC_BIT(48)   /* Wake on hv doorbell */
#define SPR_LPCR_P8_PECE2	PPC_BIT(49)   /* Wake on external interrupts */
#define SPR_LPCR_P8_PECE3	PPC_BIT(50)   /* Wake on decrementer */
#define SPR_LPCR_P8_PECE4	PPC_BIT(51)   /* Wake on MCs, HMIs, etc... */

#define SPR_LPCR_P9_PECE	(PPC_BITMASK(47,51) | PPC_BITMASK(17,17))
#define SPR_LPCR_P9_PECEU0	PPC_BIT(17)   /* Wake on HVI */
#define SPR_LPCR_P9_PECEL0	PPC_BIT(47)   /* Wake on priv doorbell */
#define SPR_LPCR_P9_PECEL1	PPC_BIT(48)   /* Wake on hv doorbell */
#define SPR_LPCR_P9_PECEL2	PPC_BIT(49)   /* Wake on external interrupts */
#define SPR_LPCR_P9_PECEL3	PPC_BIT(50)   /* Wake on decrementer */
#define SPR_LPCR_P9_PECEL4	PPC_BIT(51)   /* Wake on MCs, HMIs, etc... */
#define SPR_LPCR_P9_LD		PPC_BIT(46)   /* Large decrementer mode bit */


/* Bits in TFMR - control bits */
#define SPR_TFMR_MAX_CYC_BET_STEPS	PPC_BITMASK(0,7)
#define SPR_TFMR_N_CLKS_PER_STEP	PPC_BITMASK(8,9)
#define SPR_TFMR_MASK_HMI		PPC_BIT(10)
#define SPR_TFMR_SYNC_BIT_SEL		PPC_BITMASK(11,13)
#define SPR_TFMR_TB_ECLIPZ		PPC_BIT(14)
#define SPR_TFMR_LOAD_TOD_MOD		PPC_BIT(16)
#define SPR_TFMR_MOVE_CHIP_TOD_TO_TB	PPC_BIT(18)
#define SPR_TFMR_CLEAR_TB_ERRORS	PPC_BIT(24)
/* Bits in TFMR - thread indep. status bits */
#define SPR_TFMR_TFAC_XFER_ERROR	PPC_BIT(25)
#define SPR_TFMR_HDEC_PARITY_ERROR	PPC_BIT(26)
#define SPR_TFMR_TBST_CORRUPT		PPC_BIT(27)
#define SPR_TFMR_TBST_ENCODED		PPC_BITMASK(28,31)
#define SPR_TFMR_TBST_LAST		PPC_BITMASK(32,35)
#define SPR_TFMR_TB_ENABLED		PPC_BIT(40)
#define SPR_TFMR_TB_VALID		PPC_BIT(41)
#define SPR_TFMR_TB_SYNC_OCCURED	PPC_BIT(42)
#define SPR_TFMR_TB_MISSING_SYNC	PPC_BIT(43)
#define SPR_TFMR_TB_MISSING_STEP	PPC_BIT(44)
#define SPR_TFMR_TB_RESIDUE_ERR		PPC_BIT(45)
#define SPR_TFMR_FW_CONTROL_ERR		PPC_BIT(46)
#define SPR_TFMR_CHIP_TOD_STATUS	PPC_BITMASK(47,50)
#define SPR_TFMR_CHIP_TOD_INTERRUPT	PPC_BIT(51)
#define SPR_TFMR_CHIP_TOD_TIMEOUT	PPC_BIT(54)
#define SPR_TFMR_CHIP_TOD_PARITY_ERR	PPC_BIT(56)
/* Bits in TFMR - thread specific. status bits */
#define SPR_TFMR_PURR_PARITY_ERR	PPC_BIT(57)
#define SPR_TFMR_SPURR_PARITY_ERR	PPC_BIT(58)
#define SPR_TFMR_DEC_PARITY_ERR		PPC_BIT(59)
#define SPR_TFMR_TFMR_CORRUPT		PPC_BIT(60)
#define SPR_TFMR_PURR_OVERFLOW		PPC_BIT(61)
#define SPR_TFMR_SPURR_OVERFLOW		PPC_BIT(62)

/* Bits in HMER/HMEER */
#define SPR_HMER_MALFUNCTION_ALERT	PPC_BIT(0)
#define SPR_HMER_PROC_RECV_DONE		PPC_BIT(2)
#define SPR_HMER_PROC_RECV_ERROR_MASKED	PPC_BIT(3) /* Not P10 */
#define SPR_HMER_TFAC_ERROR		PPC_BIT(4)
#define SPR_HMER_TFMR_PARITY_ERROR	PPC_BIT(5) /* P9 */
#define SPR_HMER_TFAC_SHADOW_XFER_ERROR	PPC_BIT(5) /* P10 */
#define SPR_HMER_SPURR_SCALE_LIMIT	PPC_BIT(6) /* P10 */
#define SPR_HMER_XSCOM_FAIL		PPC_BIT(8)
#define SPR_HMER_XSCOM_DONE		PPC_BIT(9)
#define SPR_HMER_PROC_RECV_AGAIN	PPC_BIT(11)
#define SPR_HMER_WARN_RISE		PPC_BIT(14) /* Not P10 */
#define SPR_HMER_WARN_FALL		PPC_BIT(15) /* Not P10 */
#define SPR_HMER_SCOM_FIR_HMI		PPC_BIT(16)
#define SPR_HMER_TRIG_FIR_HMI		PPC_BIT(17) /* Not P10 */
#define SPR_HMER_THD_WAKE_BLOCKED_TM_SUSPEND	PPC_BIT(17) /* Not P10 */
#define SPR_HMER_P10_TRIG_FIR_HMI	PPC_BIT(18)
#define SPR_HMER_HYP_RESOURCE_ERR	PPC_BIT(20) /* Not P10 */
#define SPR_HMER_XSCOM_STATUS		PPC_BITMASK(21,23)

/*
 * HMEER: initial bits for HMI interrupt enable mask.
 * Per Dave Larson, never enable 8,9,21-23
 */
#define SPR_HMEER_HMI_ENABLE_MASK	(SPR_HMER_MALFUNCTION_ALERT |\
					 SPR_HMER_HYP_RESOURCE_ERR |\
					 SPR_HMER_PROC_RECV_DONE |\
					 SPR_HMER_PROC_RECV_ERROR_MASKED |\
					 SPR_HMER_TFAC_ERROR |\
					 SPR_HMER_TFMR_PARITY_ERROR |\
					 SPR_HMER_PROC_RECV_AGAIN)

#define SPR_HMEER_P10_HMI_ENABLE_MASK	(SPR_HMER_MALFUNCTION_ALERT |\
					 SPR_HMER_PROC_RECV_DONE |\
					 SPR_HMER_TFAC_ERROR |\
					 SPR_HMER_TFAC_SHADOW_XFER_ERROR |\
					 SPR_HMER_SPURR_SCALE_LIMIT |\
					 SPR_HMER_PROC_RECV_AGAIN)

/* Bits in HID0 */
#define SPR_HID0_POWER8_4LPARMODE	PPC_BIT(2)
#define SPR_HID0_POWER8_2LPARMODE	PPC_BIT(6)
#define SPR_HID0_POWER8_DYNLPARDIS	PPC_BIT(15)
#define SPR_HID0_POWER8_HILE		PPC_BIT(19)
#define SPR_HID0_POWER9_HILE		PPC_BIT(4)
#define SPR_HID0_POWER10_HILE		PPC_BIT(4)
#define SPR_HID0_POWER8_ENABLE_ATTN	PPC_BIT(31)
#define SPR_HID0_POWER9_ENABLE_ATTN	(PPC_BIT(2) | PPC_BIT(3))
#define SPR_HID0_POWER10_ENABLE_ATTN	(PPC_BIT(2) | PPC_BIT(3))
#define SPR_HID0_POWER9_RADIX		PPC_BIT(8)

/* PVR bits */
#define SPR_PVR_TYPE			0xffff0000
#define SPR_PVR_CHIP_TYPE		0x0000f000
#define SPR_PVR_VERS_MAJ		0x00000f00
#define SPR_PVR_VERS_MIN		0x000000ff

#define PVR_TYPE(_pvr)		GETFIELD(SPR_PVR_TYPE, _pvr)
#define PVR_CHIP_TYPE(_pvr)	GETFIELD(SPR_PVR_CHIP_TYPE, _pvr)
#define PVR_VERS_MAJ(_pvr)	GETFIELD(SPR_PVR_VERS_MAJ, _pvr)
#define PVR_VERS_MIN(_pvr)	GETFIELD(SPR_PVR_VERS_MIN, _pvr)

/* PVR definitions */
#define PVR_TYPE_P8E	0x004b /* Murano */
#define PVR_TYPE_P8	0x004d /* Venice */
#define PVR_TYPE_P8NVL	0x004c /* Naples */
#define PVR_TYPE_P9	0x004e
#define PVR_TYPE_P9P	0x004f /* Axone */
#define PVR_TYPE_P10	0x0080

#ifdef __ASSEMBLY__

/* Thread priority control opcodes */
#define smt_low		or 1,1,1
#define smt_medium	or 2,2,2
#define smt_high	or 3,3,3
#define smt_medium_high	or 5,5,5
#define smt_medium_low	or 6,6,6
#define smt_extra_high	or 7,7,7
#define smt_very_low	or 31,31,31
#define smt_lowest	smt_low ; smt_very_low

#else /* __ASSEMBLY__ */

#include <ccan/str/str.h>
#include <compiler.h>
#include <stdbool.h>
#include <stdint.h>

#define PPC_INST_NOP	0x60000000UL
#define PPC_INST_TRAP	0x7fe00008UL

#define RB(b)		(((b) & 0x1f) << 11)
#define MSGSND(b)	stringify(.long 0x7c00019c | RB(b))
#define MSGCLR(b)	stringify(.long 0x7c0001dc | RB(b))
#define MSGSYNC		stringify(.long 0x7c0006ec)

static inline bool is_power9n(uint32_t version)
{
	if (PVR_TYPE(version) != PVR_TYPE_P9)
		return false;
	/*
	 * Bit 13 tells us:
	 *   0 = Scale out (aka Nimbus)
	 *   1 = Scale up  (aka Cumulus)
	 */
	if ((version >> 13) & 1)
		return false;
	return true;
}

static inline bool is_fused_core(uint32_t version)
{
	if (PVR_TYPE(version) == PVR_TYPE_P9) {
		switch(PVR_CHIP_TYPE(version)) {
			case 0:
			case 2:
				return true;
			default:
				return false;
		}

	} else if(PVR_TYPE(version) == PVR_TYPE_P10) {
		if(PVR_CHIP_TYPE(version) & 0x01)
			return false;
		else
			return true;
	} else
		return false;
}

static inline bool is_power9c(uint32_t version) 
{

	if (PVR_TYPE(version) != PVR_TYPE_P9)
		return false;
	/*
	 * Bit 13 tells us:
	 *   0 = Scale out (aka Nimbus)
	 *   1 = Scale up  (aka Cumulus)
	 */
	if (!((version >> 13) & 1))
		return false;
	return true;
}

#ifndef __TEST__

/* POWER9 and above only */
static inline void flush_erat(void)
{
	asm volatile("slbia	7");
}

/*
 * SMT priority
 */

static inline void smt_low(void)	{ asm volatile("or 1,1,1");	}
static inline void smt_medium(void) 	{ asm volatile("or 2,2,2");	}
static inline void smt_high(void)	{ asm volatile("or 3,3,3");	}
static inline void smt_medium_high(void){ asm volatile("or 5,5,5");	}
static inline void smt_medium_low(void)	{ asm volatile("or 6,6,6");	}
static inline void smt_extra_high(void)	{ asm volatile("or 7,7,7");	}
static inline void smt_very_low(void)	{ asm volatile("or 31,31,31");	}
static inline void smt_lowest(void)	{ smt_low(); smt_very_low();	}

/*
 * SPR access functions
 */

static inline unsigned long mfmsr(void)
{
	unsigned long val;
	
	asm volatile("mfmsr %0" : "=r"(val) : : "memory");
	return val;
}

static inline void mtmsr(unsigned long val)
{
	asm volatile("mtmsr %0" : : "r"(val) : "memory");
}

static inline void mtmsrd(unsigned long val, int l)
{
	asm volatile("mtmsrd %0,%1" : : "r"(val), "i"(l) : "memory");
}

static inline __attribute__((always_inline))
unsigned long mfspr(const unsigned int spr)
{
	unsigned long val;

	asm volatile("mfspr %0,%1" : "=r"(val) : "i"(spr) : "memory");
	return val;
}

static inline __attribute__((always_inline))
void mtspr(const unsigned int spr, unsigned long val)
{
	asm volatile("mtspr %0,%1" : : "i"(spr), "r"(val) : "memory");
}

/* Helpers for special sequences needed by some registers */
extern void set_hid0(unsigned long hid0);
extern void trigger_attn(void);

/*
 * Barriers
 */

static inline void eieio(void)
{
	asm volatile("eieio" : : : "memory");
}

static inline void sync(void)
{
	asm volatile("sync" : : : "memory");
}

static inline void lwsync(void)
{
	asm volatile("lwsync" : : : "memory");
}

static inline void isync(void)
{
	asm volatile("isync" : : : "memory");
}


/*
 * Cache sync
 */
static inline void sync_icache(void)
{
	asm volatile("sync; icbi 0,%0; sync; isync" : : "r" (0) : "memory");
}

/*
 * Doorbells
 */
static inline void msgclr(void)
{
	uint64_t rb = (0x05 << (63-36));
	asm volatile(MSGCLR(%0) : : "r"(rb));
}

static inline void p9_dbell_receive(void)
{
	uint64_t rb = (0x05 << (63-36));
	asm volatile(MSGCLR(%0)	";"
		     MSGSYNC	";"
		     "lwsync"
		     : : "r"(rb));
}

static inline void p9_dbell_send(uint32_t pir)
{
	uint64_t rb = (0x05 << (63-36)) | pir;
	asm volatile("sync ;"
		     MSGSND(%0)
		     : : "r"(rb));
}

/*
 * Byteswap load/stores
 */

static inline uint16_t ld_le16(const uint16_t *addr)
{
	uint16_t val;
	asm volatile("lhbrx %0,0,%1" : "=r"(val) : "r"(addr), "m"(*addr));
	return val;
}

static inline uint32_t ld_le32(const uint32_t *addr)
{
	uint32_t val;
	asm volatile("lwbrx %0,0,%1" : "=r"(val) : "r"(addr), "m"(*addr));
	return val;
}

static inline void st_le16(uint16_t *addr, uint16_t val)
{
	asm volatile("sthbrx %0,0,%1" : : "r"(val), "r"(addr), "m"(*addr));
}

static inline void st_le32(uint32_t *addr, uint32_t val)
{
	asm volatile("stwbrx %0,0,%1" : : "r"(val), "r"(addr), "m"(*addr));
}

#endif /* __TEST__ */

#endif /* __ASSEMBLY__ */

#endif /* __PROCESSOR_H */
