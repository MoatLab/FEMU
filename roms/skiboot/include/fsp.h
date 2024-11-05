// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * IBM System P FSP (Flexible Service Processor)
 *
 * Copyright 2013-2019 IBM Corp.
 */

#ifndef __FSP_H
#define __FSP_H

#include <skiboot.h>
#include <psi.h>

/* Current max number of FSPs
 * one primary and one secondary is all we support
 */
#define FSP_MAX			2

/* Command protocol.
 *
 * Commands have a byte class and a byte subcommand. With the exception
 * of some HMC related commands (class 0xe0) which we don't support,
 * only one outstanding command is allowed for a given class.
 *
 * Note: 0xCE and 0xCF fall into the same class, ie, only one of them can
 *       be outstanding.
 *
 * A command is outstanding until it has been acknowledged. This doesn't
 * imply a response, the response can come later.
 */

/* Protocol status error codes used by the protocol */
#define FSP_STATUS_SUCCESS		0x00	/* Command successful */
#define FSP_STATUS_MORE_DATA		0x02	/* Success, EOF not reached */
#define FSP_STATUS_DATA_INLINE		0x11	/* Data inline in mbox */
#define FSP_STATUS_INVALID_SUBCMD	0x20
#define FSP_STATUS_INVALID_MOD		0x21
#define FSP_STATUS_INVALID_DATA		0x22
#define FSP_STATUS_INVALID_DPOSTATE	0x23
#define FSP_STATUS_DMA_ERROR		0x24
#define FSP_STATUS_INVALID_CMD		0x2c
#define FSP_STATUS_SEQ_ERROR		0x2d
#define FSP_STATUS_BAD_STATE		0x2e
#define FSP_STATUS_NOT_SUPPORTED	0x2f
#define FSP_STATUS_FILE_TOO_LARGE	0x43
#define FSP_STATUS_FLASH_INPROGRESS	0x61
#define FSP_STATUS_FLASH_NOPROGRESS	0x62
#define FSP_STATUS_FLASH_INVALID_SIDE	0x63
#define FSP_STATUS_EOF_ERROR		0x02
#define FSP_STATUS_DMA_ERROR		0x24
#define FSP_STATUS_BUSY			0x3e
#define FSP_STATUS_FLASH_BUSY		0x3f
#define FSP_STATUS_INVALID_SUBID	0x41
#define FSP_STATUS_LENGTH_ERROR		0x42
#define FSP_STAUS_INVALID_HMC_ID	0x51
#define FSP_STATUS_SPCN_ERROR		0xA8	/* SPCN error */
#define FSP_STATUS_INVALID_LC		0xC0	/* Invalid location code */
#define FSP_STATUS_ENCL_IND_RESET	0xC2	/* Enclosure Indicator cannot be reset */
#define FSP_STATUS_TOD_RESET		0xA9	/* TOD reset due to invalid state at POR */
#define FSP_STATUS_TOD_PERMANENT_ERROR	0xAF	/* Permanent error in TOD */
#define FSP_STATUS_I2C_TRANS_ERROR	0xE4	/* I2C device / transmission error */
#define FSP_STATUS_IND_PARTIAL_SUCCESS	0xE5	/* Indicator partial success */
#define FSP_STATUS_GENERIC_ERROR	0xFE    /* Generic Failure in execution */

/*
 * FSP registers
 *
 * All of the below register definitions come from the FSP0 "Black Widow" spec
 * They are the same for FSP1 except they are presented big-endian vs
 * little-endian for FSP0 -- which used PCI
 * all regs are 4 bytes wide, and we read the larger data areas in 4 byte
 * granularity as well 
 *
 * there are actually two defined sets of MBX registers
 * MBX2 can't generate interrupts to the host and only MBX1 is currently 
 * used by firmware running on the FSP, so we're mostly ignoring MBX2
 */

/* Device Reset Control Register */
#define FSP_DRCR_REG			0x00
#define FSP_DRCR_CLR_REG		0x04

/* Bit masks for DRCR */
#define FSP_DRCR_CMD_VALID		PPC_BIT32(16)
#define FSP_DRCR_TERMINATE		PPC_BIT32(17)
#define FSP_DRCR_PREP_FOR_RESET		PPC_BIT32(23)
#define FSP_DRCR_CLEAR_DISR		PPC_BIT32(30)

/* DRCR commands need the CMD_VALID bit set */
#define FSP_PREP_FOR_RESET_CMD		(FSP_DRCR_CMD_VALID | \
						FSP_DRCR_PREP_FOR_RESET)
#define FSP_DRCR_ACK_MASK		(0xff << 8)

/* Device Immediate Status Register */
#define FSP_DISR_REG			0x08
#define FSP_DISR_CLR_REG		0x0C

/* Bit masks for DISR */
#define FSP_DISR_FSP_UNIT_CHECK		PPC_BIT32(16)
#define FSP_DISR_FSP_RUNTIME_TERM	PPC_BIT32(21)
#define FSP_DISR_FSP_RR_COMPLETE	PPC_BIT32(22)
#define FSP_DISR_FSP_FLASH_TERM		PPC_BIT32(23)
#define FSP_DISR_RUNTIME_STATE_SYNCD	PPC_BIT32(24)
#define FSP_DISR_DBG_IN_PROGRESS	PPC_BIT32(25)
#define FSP_DISR_FSP_IN_RR		PPC_BIT32(26)
#define FSP_DISR_FSP_REBOOT_IN_PROGRESS	PPC_BIT32(27)
#define FSP_DISR_CRIT_OP_IN_PROGRESS	PPC_BIT32(28)
#define FSP_DISR_STATUS_ACK_RXD		PPC_BIT32(31)

#define FSP_DISR_HIR_TRIGGER_MASK	(FSP_DISR_FSP_UNIT_CHECK | \
						FSP_DISR_FSP_RUNTIME_TERM | \
						FSP_DISR_FSP_FLASH_TERM)

/* The host version of the control register shares bits with the FSP's
 * control reg. Those bits are defined such that one side can set
 * a bit and the other side can clear it
 */
#define FSP_MBX1_HCTL_REG		0x080 /* AKA DSCR1 */
#define FSP_MBX1_FCTL_REG		0x090
#define FSP_MBX2_HCTL_REG		0x0a0 /* AKA DSCR2 */
#define FSP_MBX2_FCTL_REG		0x0b0

/* Bits in the control reg */
#define FSP_MBX_CTL_PTS			(1 << 31)
#define FSP_MBX_CTL_ABORT		(1 << 30)
#define FSP_MBX_CTL_SPPEND		(1 << 29)
#define FSP_MBX_CTL_HPEND		(1 << 28)
#define FSP_MBX_CTL_XDN			(1 << 26)
#define FSP_MBX_CTL_XUP			(1 << 25)
#define FSP_MBX_CTL_HCHOST_MASK		(0xf << 20)
#define FSP_MBX_CTL_HCHOST_SHIFT	20
#define FSP_MBX_CTL_DCHOST_MASK		(0xff << 12)
#define FSP_MBX_CTL_DCHOST_SHIFT	12
#define FSP_MBX_CTL_HCSP_MASK		(0xf << 8)
#define FSP_MBX_CTL_HCSP_SHIFT		8
#define FSP_MBX_CTL_DCSP_MASK		(0xff)
#define FSP_MBX_CTL_DCSP_SHIFT		0

/* Three header registers owned by the host */
#define FSP_MBX1_HHDR0_REG		0x84
#define FSP_MBX1_HHDR1_REG		0x88
#define FSP_MBX1_HHDR2_REG		0x8C
#define FSP_MBX2_HHDR0_REG		0xa4
#define FSP_MBX2_HHDR1_REG		0xa8
#define FSP_MBX2_HHDR2_REG		0xaC

/* SP Doorbell Error Status register */
#define FSP_SDES_REG			0xc0

/* Host Doorbell Error Status register */
#define FSP_HDES_REG			0xc4

/* Bit definitions for both SDES and HDES
 *
 * Notes:
 *
 * - CLR: is written to clear the status and always reads
 *   as 0. It can be used to detect an error state (a HB
 *   freeze will return all 1's)
 * - ILLEGAL: illegal operation such as host trying to write
 *   to an FSP only register etc...
 * - WFULL: set if host tried to write to the SP doorbell while
 *   the pending bit is still set
 * - REMPTY: tried to read while host pending bit not set
 * - PAR: SP RAM parity error
 */
#define FSP_DBERRSTAT_ILLEGAL1		(1 << 27)
#define FSP_DBERRSTAT_WFULL1		(1 << 26)
#define FSP_DBERRSTAT_REMPTY1		(1 << 25)
#define FSP_DBERRSTAT_PAR1		(1 << 24)
#define FSP_DBERRSTAT_CLR1		(1 << 16)
#define FSP_DBERRSTAT_ILLEGAL2		(1 << 11)
#define FSP_DBERRSTAT_WFULL2		(1 << 10)
#define FSP_DBERRSTAT_REMPTY2		(1 <<  9)
#define FSP_DBERRSTAT_PAR2		(1 <<  8)
#define FSP_DBERRSTAT_CLR2		(1 <<  0)

/* Host Doorbell Interrupt Register and mask
 *
 * Note that while HDIR has bits for MBX2, only
 * MBX1 can actually generate interrupts. Thus only the
 * MBX1 bits are implemented in the mask register.
 */
#define FSP_HDIR_REG			0xc8
#define FSP_HDIM_SET_REG		0xcc
#define FSP_HDIM_CLR_REG		0xd0
#define FSP_DBIRQ_ERROR2		(1 << 10)
#define FSP_DBIRQ_XUP2			(1 <<  9)
#define FSP_DBIRQ_HPEND2		(1 <<  8)
#define FSP_DBIRQ_ERROR1		(1 <<  2)
#define FSP_DBIRQ_XUP1			(1 <<  1)
#define FSP_DBIRQ_HPEND1		(1 <<  0)
#define FSP_DBIRQ_MBOX1			(FSP_DBIRQ_ERROR1 | FSP_DBIRQ_XUP1 | \
					 FSP_DBIRQ_HPEND1)
#define FSP_DBIRQ_MBOX2			(FSP_DBIRQ_ERROR2 | FSP_DBIRQ_XUP2 | \
					 FSP_DBIRQ_HPEND2)
#define FSP_DBIRQ_ALL			(FSP_DBIRQ_MBOX1 | FSP_DBIRQ_MBOX2)

/* Doorbell Interrupt Register (FSP internal interrupt latch
 * read-only on host side
 */
#define FSP_PDIR_REG			0xd4
/* And associated mask */
#define FSP_PDIM_SET_REG       		0xd8
#define FSP_PDIM_CLR_REG       		0xdc

/* Bits for the above */
#define FSP_PDIRQ_ABORT2		(1 << 7)
#define FSP_PDIRQ_ABORT1		(1 << 6)
#define FSP_PDIRQ_ERROR2		(1 << 5)
#define FSP_PDIRQ_ERROR1		(1 << 4)
#define FSP_PDIRQ_XDN2			(1 << 3)
#define FSP_PDIRQ_XDN1			(1 << 2)
#define FSP_PDIRQ_SPPEND2		(1 << 1)
#define FSP_PDIRQ_SPPEND1		(1 << 0)

/* FSP owned headers */
#define FSP_MBX1_FHDR0_REG		0x094
#define FSP_MBX1_FHDR1_REG		0x098
#define FSP_MBX1_FHDR2_REG		0x09C
#define FSP_MBX2_FHDR0_REG		0x0b4
#define FSP_MBX2_FHDR1_REG		0x0b8
#define FSP_MBX2_FHDR2_REG		0x0bC

/* Data areas, we can only write to host data, and read from FSP data
 *
 * Each area is 0x140 bytes long
 */
#define FSP_MBX1_HDATA_AREA		0x100
#define FSP_MBX1_FDATA_AREA		0x200
#define FSP_MBX2_HDATA_AREA		0x300
#define FSP_MBX2_FDATA_AREA		0x400

/* These are scratch registers */
#define FSP_SCRATCH0_REG		0xe0
#define FSP_SCRATCH1_REG		0xe4
#define FSP_SCRATCH2_REG		0xe8
#define FSP_SCRATCH3_REG		0xec

/* This is what the cmd_sub_mod will have for FSP_MCLASS_RR_EVENT */
#define FSP_RESET_START			0x1
#define FSP_RELOAD_COMPLETE		0x2

/*
 * Message classes
 */

/* The FSP_MCLASS_RR_EVENT is a special message class that doesn't
 * participate in mbox event related activities. Its relevant only
 * for hypervisor internal use. So, handle it specially for command
 * class extraction too.
 */
#define FSP_MCLASS_RR_EVENT		0xaa	/* see FSP_R/R defines above */
#define FSP_MCLASS_FIRST		0xce
#define FSP_MCLASS_SERVICE		0xce
#define FSP_MCLASS_IPL			0xcf
#define FSP_MCLASS_PCTRL_MSG		0xd0
#define FSP_MCLASS_PCTRL_ABORTS		0xd1
#define FSP_MCLASS_ERR_LOG		0xd2
#define FSP_MCLASS_CODE_UPDATE		0xd3
#define FSP_MCLASS_FETCH_SPDATA		0xd4
#define FSP_MCLASS_FETCH_HVDATA		0xd5
#define FSP_MCLASS_NVRAM		0xd6
#define FSP_MCLASS_MBOX_SURV		0xd7
#define FSP_MCLASS_RTC			0xd8
#define FSP_MCLASS_SMART_CHIP		0xd9
#define FSP_MCLASS_INDICATOR		0xda
#define FSP_MCLASS_HMC_INTFMSG		0xe0
#define FSP_MCLASS_HMC_VT		0xe1
#define FSP_MCLASS_HMC_BUFFERS		0xe2
#define FSP_MCLASS_SHARK		0xe3
#define FSP_MCLASS_MEMORY_ERR		0xe4
#define FSP_MCLASS_CUOD_EVENT		0xe5
#define FSP_MCLASS_HW_MAINT		0xe6
#define FSP_MCLASS_VIO			0xe7
#define FSP_MCLASS_SRC_MSG		0xe8
#define FSP_MCLASS_DATA_COPY		0xe9
#define FSP_MCLASS_TONE			0xea
#define FSP_MCLASS_VIRTUAL_NVRAM	0xeb
#define FSP_MCLASS_TORRENT		0xec
#define FSP_MCLASS_NODE_PDOWN		0xed
#define FSP_MCLASS_DIAG			0xee
#define FSP_MCLASS_PCIE_LINK_TOPO	0xef
#define FSP_MCLASS_OCC			0xf0
#define FSP_MCLASS_TRUSTED_BOOT		0xf1
#define FSP_MCLASS_HBRT			0xf2
#define FSP_MCLASS_LAST			0xf2

/*
 * Commands are provided in rxxyyzz form where:
 *
 *   -  r is 0: no response or 1: response expected
 *   - xx is class
 *   - yy is subcommand
 *   - zz is mod
 *
 * WARNING: We only set the r bit for HV->FSP commands
 *          long run, we want to remove use of that bit
 *          and instead have a table of all commands in
 *          the FSP driver indicating which ones take a
 *          response...
 */

/*
 * Class 0xCF
 */
#define FSP_CMD_OPL	    	0x0cf7100 /* HV->FSP: Operational Load Compl. */
#define FSP_CMD_HV_STATE_CHG	0x0cf0200 /* FSP->HV: Request HV state change */
#define FSP_RSP_HV_STATE_CHG	0x0cf8200
#define FSP_CMD_SP_NEW_ROLE	0x0cf0700 /* FSP->HV: FSP assuming a new role */
#define FSP_RSP_SP_NEW_ROLE	0x0cf8700
#define FSP_CMD_SP_RELOAD_COMP	0x0cf0102 /* FSP->HV: FSP reload complete */


/*
 * Class 0xCE
 */
#define FSP_CMD_ACK_DUMP	0x1ce0200 /* HV->FSP: Dump ack */
#define FSP_CMD_HV_QUERY_CAPS	0x1ce0400 /* HV->FSP: Query capabilities */
#define FSP_RSP_HV_QUERY_CAPS	0x1ce8400
#define FSP_CMD_SP_QUERY_CAPS	0x0ce0501 /* FSP->HV */
#define FSP_RSP_SP_QUERY_CAPS	0x0ce8500
#define FSP_CMD_GET_IPL_SIDE	0x1ce0600 /* HV->FSP: Get IPL side and speed */
#define FSP_CMD_SET_IPL_SIDE	0x1ce0780 /* HV->FSP: Set next IPL side */
#define FSP_CMD_ERRLOG_PHYP_ACK	0x1ce0800 /* HV->FSP */
#define FSP_RSP_ERRLOG_PHYP_ACK	0x0ce8800 /* FSP->HV */
#define FSP_CMD_ERRLOG_GET_PLID	0x0ce0900 /* FSP->HV: Get PLID */
#define FSP_RSP_ERRLOG_GET_PLID	0x0ce8900 /* HV->FSP */
#define FSP_CMD_SA_INDICATOR	0x1ce1000 /* HV->FSP: read/update SAI */
#define FSP_RSP_SA_INDICATOR	0x0ce9000 /* FSP->HV */
#define FSP_CMD_QUERY_SPARM	0x1ce1200 /* HV->FSP: System parameter query */
#define FSP_RSP_QUERY_SPARM	0x0ce9200 /* FSP->HV: System parameter resp */
#define FSP_CMD_SET_SPARM_1	0x1ce1301 /* HV->FSP: Set system parameter */
#define FSP_CMD_SET_SPARM_2	0x1ce1302 /* HV->FSP: Set system parameter TCE */
#define FSP_RSP_SET_SPARM	0x0ce9300 /* FSP->HV: Set system parameter resp */
#define FSP_CMD_SP_SPARM_UPD_0	0x0ce1600 /* FSP->HV: Sysparm updated no data */
#define FSP_CMD_SP_SPARM_UPD_1	0x0ce1601 /* FSP->HV: Sysparm updated data */
#define FSP_CMD_HYP_MDST_TABLE	0x1ce2600 /* HV->FSP: Sapphire MDST table */
#define FSP_CMD_TPO_READ	0x1ce4201 /* FSP->HV */
#define FSP_CMD_TPO_WRITE	0x1ce4301 /* HV->FSP */
#define FSP_CMD_TPO_DISABLE	0x1ce4400 /* HV->FSP */
#define FSP_CMD_STATUS_REQ	0x1ce4800 /* HV->FSP: Request normal panel status */
#define FSP_CMD_STATUS_EX1_REQ	0x1ce4802 /* HV->FSP: Request extended 1 panel status */
#define FSP_CMD_STATUS_EX2_REQ	0x1ce4803 /* HV->FSP: Request extended 2 panel status */
#define FSP_CMD_CONTINUE_ACK	0x0ce5700 /* HV->FSP: HV acks CONTINUE IPL */
#define FSP_CMD_HV_FUNCTNAL	0x1ce5707 /* HV->FSP: Set HV functional state */
#define FSP_CMD_FSP_FUNCTNAL	0x0ce5708 /* FSP->HV: FSP functional state */
#define FSP_CMD_CONTINUE_IPL	0x0ce7000 /* FSP->HV: HV has control */
#define FSP_RSP_SYS_DUMP_OLD	0x0ce7800 /* FSP->HV: Sys Dump Available */
#define FSP_RSP_SYS_DUMP	0x0ce7802 /* FSP->HV: Sys Dump Available */
#define FSP_RSP_RES_DUMP	0x0ce7807 /* FSP->HV: Resource Dump Available */
#define FSP_CMD_PCI_POWER_CONF	0x1ce1b00 /* HV->FSP: Send PCIe list to FSP */
#define FSP_CMD_POWERDOWN_NORM	0x1ce4d00 /* HV->FSP: Normal power down */
#define FSP_CMD_POWERDOWN_QUICK	0x1ce4d01 /* HV->FSP: Quick power down */
#define FSP_CMD_POWERDOWN_PCIRS	0x1ce4d02 /* HV->FSP: PCI cfg reset power dwn */
#define FSP_CMD_REBOOT		0x1ce4e00 /* HV->FSP: Standard IPL */
#define FSP_CMD_DEEP_REBOOT	0x1ce4e04 /* HV->FSP: Deep IPL */
#define FSP_CMD_INIT_DPO	0x0ce5b00 /* FSP->HV: Initialize Delayed Power Off */
#define FSP_RSP_INIT_DPO	0x0cedb00 /* HV->FSP: Response for DPO init command */
#define FSP_CMD_GET_HIR_PLID	0x0ce0900 /* FSP->HV: Get Platform Log ID with
					   * reason for Host Initiated Reset.
					   */
#define FSP_RSP_GET_HIR_PLID	0x0ce8900 /* HV->FSP: Reply with PLID */
#define FSP_CMD_PANELSTATUS	0x0ce5c00 /* FSP->HV */
#define FSP_CMD_PANELSTATUS_EX1	0x0ce5c02 /* FSP->HV */
#define FSP_CMD_PANELSTATUS_EX2	0x0ce5c03 /* FSP->HV */

/* SAI read/update sub commands */
#define FSP_LED_RESET_REAL_SAI		0x00
#define FSP_LED_READ_REAL_SAI		0x02
#define FSP_LED_RESET_PARTITION_SAI	0x80
#define FSP_LED_SET_PARTITION_SAI	0x81
#define FSP_LED_READ_PARTITION_SAI	0x82
#define FSP_LED_READ_PLAT_SAI		0x83
#define FSP_LED_RESET_PLAT_SAI		0x84
#define FSP_LED_SET_PLAT_SAI		0x85

/*
 * Class 0xD2
 */
#define FSP_CMD_CREATE_ERRLOG		0x1d21000 /* HV->FSP */
#define FSP_RSP_CREATE_ERRLOG		0x0d29000 /* FSP->HV */
#define FSP_CMD_ERRLOG_NOTIFICATION	0x0d25a00 /* FSP->HV */
#define FSP_RSP_ERRLOG_NOTIFICATION	0x0d2da00 /* HV->FSP */
#define FSP_RSP_ELOG_NOTIFICATION_ERROR	0x1d2dafe /* HV->FSP */
#define FSP_CMD_FSP_DUMP_INIT		0x1d21200 /* HV->FSP: FSP dump init */

/*
 * Class 0xD0
 */
#define FSP_CMD_SPCN_PASSTHRU   0x1d05400 /* HV->FSP */
#define FSP_RSP_SPCN_PASSTHRU   0x0d0d400 /* FSP->HV */

/*
 * Class 0xD3
 */
#define FSP_CMD_FLASH_START	0x01d30101 /* HV->FSP: Code update start */
#define FSP_CMD_FLASH_COMPLETE	0x01d30201 /* HV->FSP: Code update complete */
#define FSP_CMD_FLASH_ABORT	0x01d302ff /* HV->FSP: Code update complete */
#define FSP_CMD_FLASH_WRITE	0x01d30300 /* HV->FSP: Write LID */
#define FSP_CMD_FLASH_DEL	0x01d30500 /* HV->FSP: Delete LID */
#define FSP_CMD_FLASH_NORMAL	0x01d30401 /* HV->FSP: Commit (T -> P) */
#define FSP_CMD_FLASH_REMOVE	0x01d30402 /* HV->FSP: Reject (P -> T) */
#define FSP_CMD_FLASH_SWAP	0x01d30403 /* HV->FSP: Swap */
#define FSP_CMD_FLASH_OUTC	0x00d30601 /* FSP->HV: Out of band commit */
#define FSP_CMD_FLASH_OUTR	0x00d30602 /* FSP->HV: Out of band reject */
#define FSP_CMD_FLASH_OUTS	0x00d30603 /* FSP->HV: Out of band swap */
#define FSP_CMD_FLASH_OUT_RSP	0x00d38600 /* HV->FSP: Out of band Resp */
#define FSP_CMD_FLASH_CACHE	0x00d30700 /* FSP->HV: Update LID cache */
#define FSP_CMD_FLASH_CACHE_RSP	0x00d38700 /* HV->FSP: Update LID cache Resp */

/*
 * Class 0xD4
 */
#define FSP_CMD_FETCH_SP_DATA	0x1d40101 /* HV->FSP: Fetch & DMA data */
#define FSP_CMD_WRITE_SP_DATA	0x1d40201 /* HV->FSP: Fetch & DMA data */
#define FSP_CMD_FETCH_PLAT_DATA	0x1d40500 /* HV->FSP: Platform function data */
#define FSP_CMD_SEND_PLAT_DATA	0x0d40501 /* FSP->HV */
#define FSP_RSP_PLAT_DATA	0x0d48500 /* HV->FSP */

/* Data set IDs for SP data commands */
#define FSP_DATASET_SP_DUMP	0x01
#define FSP_DATASET_HW_DUMP	0x02
#define FSP_DATASET_ERRLOG	0x03	/* error log entry */
#define FSP_DATASET_MASTER_LID	0x04
#define FSP_DATASET_NONSP_LID	0x05
#define FSP_DATASET_ELID_RDATA	0x06
#define FSP_DATASET_BLADE_PARM	0x07
#define FSP_DATASET_LOC_PORTMAP	0x08
#define FSP_DATASET_SYSIND_CAP	0x09
#define FSP_DATASET_FSP_RSRCDMP	0x0a
#define FSP_DATASET_HBRT_BLOB	0x0b

/* Adjustment to get T side LIDs */
#define ADJUST_T_SIDE_LID_NO	0x8000

/*
 * Class 0xD5
 */
#define FSP_CMD_ALLOC_INBOUND	0x0d50400 /* FSP->HV: Allocate inbound buf. */
#define FSP_RSP_ALLOC_INBOUND	0x0d58400

/*
 * Class 0xD7
 */
#define FSP_CMD_SURV_HBEAT	0x1d70000 /* ? */
#define FSP_CMD_SURV_ACK	0x0d78000 /* ? */

/*
 * Class 0xD8
 */
#define FSP_CMD_READ_TOD	0x1d82000 /* HV->FSP */
#define FSP_CMD_READ_TOD_EXT	0x1d82001 /* HV->FSP */
#define FSP_CMD_WRITE_TOD	0x1d82100 /* HV->FSP */
#define FSP_CMD_WRITE_TOD_EXT	0x1d82101 /* HV->FSP */

/*
 * Class 0xDA
 */
#define FSP_CMD_GET_LED_LIST   0x00da1101 /* Location code information structure */
#define FSP_RSP_GET_LED_LIST   0x00da9100
#define FSP_CMD_RET_LED_BUFFER 0x00da1102 /* Location code buffer information */
#define FSP_RSP_RET_LED_BUFFER 0x00da9100
#define FSP_CMD_GET_LED_STATE  0x00da1103 /* Retrieve Indicator State */
#define FSP_RSP_GET_LED_STATE  0x00da9100
#define FSP_CMD_SET_LED_STATE  0x00da1104 /* Set Service Indicator State */
#define FSP_RSP_SET_LED_STATE  0x00da9100
#define FSP_CMD_GET_MTMS_LIST  0x00da1105 /* Get MTMS and config ID list */
#define FSP_RSP_GET_MTMS_LIST  0x00da9100
#define FSP_CMD_SET_ENCL_MTMS  0x00da1106 /* Set MTMS */
#define FSP_RSP_SET_ENCL_MTMS  0x00da9100
#define FSP_CMD_SET_ENCL_CNFG  0x00da1107 /* Set config ID */
#define FSP_RSP_SET_ENCL_CNFG  0x00da9100
#define FSP_CMD_CLR_INCT_ENCL  0x00da1108 /* Clear inactive address */
#define FSP_RSP_CLR_INCT_ENCL  0x00da9100
#define FSP_CMD_RET_MTMS_BUFFER  0x00da1109 /* Return MTMS buffer */
#define FSP_RSP_RET_MTMS_BUFFER  0x00da9100
#define FSP_CMD_ENCL_MCODE_INIT  0x00da110A /* Mcode update (Initiate download) */
#define FSP_RSP_ENCL_MCODE_INIT  0x00da9100
#define FSP_CMD_ENCL_MCODE_INTR  0x00da110B /* Mcode update (Interrupt download) */
#define FSP_RSP_ENCL_MCODE_INTR  0x00da9100
#define FSP_CMD_ENCL_POWR_TRACE  0x00da110D /* Enclosure power network trace */
#define FSP_RSP_ENCL_POWR_TRACE  0x00da9100
#define FSP_CMD_RET_ENCL_TRACE_BUFFER  0x00da110E /* Return power trace buffer */
#define FSP_RSP_RET_ENCL_TRACE_BUFFER  0x00da9100
#define FSP_CMD_GET_SPCN_LOOP_STATUS   0x00da110F /* Get SPCN loop status */
#define FSP_RSP_GET_SPCN_LOOP_STATUS   0x00da9100
#define FSP_CMD_INITIATE_LAMP_TEST     0x00da1300 /* Initiate LAMP test */

/*
 * Class 0xE0
 *
 * HACK ALERT: We mark E00A01 (associate serial port) as not needing
 * a response. We need to do that because the FSP will send as a result
 * an Open Virtual Serial of the same class *and* expect a reply before
 * it will respond to associate serial port. That breaks our logic of
 * supporting only one cmd/resp outstanding per class.
 */
#define FSP_CMD_HMC_INTF_QUERY	0x0e00100 /* FSP->HV */
#define FSP_RSP_HMC_INTF_QUERY	0x0e08100 /* HV->FSP */
#define FSP_CMD_ASSOC_SERIAL	0x0e00a01 /* HV->FSP: Associate with a port */
#define FSP_RSP_ASSOC_SERIAL	0x0e08a00 /* FSP->HV */
#define FSP_CMD_UNASSOC_SERIAL	0x0e00b01 /* HV->FSP: Deassociate */
#define FSP_RSP_UNASSOC_SERIAL	0x0e08b00 /* FSP->HV */
#define FSP_CMD_OPEN_VSERIAL	0x0e00601 /* FSP->HV: Open serial session */
#define FSP_RSP_OPEN_VSERIAL	0x0e08600 /* HV->FSP */
#define FSP_CMD_CLOSE_VSERIAL	0x0e00701 /* FSP->HV: Close serial session */
#define FSP_RSP_CLOSE_VSERIAL	0x0e08700 /* HV->FSP */
#define FSP_CMD_CLOSE_HMC_INTF	0x0e00300 /* FSP->HV: Close HMC interface */
#define FSP_RSP_CLOSE_HMC_INTF	0x0e08300 /* HV->FSP */

/*
 * Class E1
 */
#define FSP_CMD_VSERIAL_IN	0x0e10100 /* FSP->HV */
#define FSP_CMD_VSERIAL_OUT	0x0e10200 /* HV->FSP */

/*
 * Class E6
 */
#define FSP_CMD_TOPO_ENABLE_DISABLE	0x0e60600 /* FSP->HV */
#define FSP_RSP_TOPO_ENABLE_DISABLE	0x0e68600 /* HV->FSP */

/*
 * Class E8
 */
#define FSP_CMD_READ_SRC	0x1e84a40 /* HV->FSP */
#define FSP_CMD_DISP_SRC_INDIR	0x1e84a41 /* HV->FSP */
#define FSP_CMD_DISP_SRC_DIRECT	0x1e84a42 /* HV->FSP */
#define FSP_CMD_CLEAR_SRC	0x1e84b00 /* HV->FSP */
#define FSP_CMD_DIS_SRC_ECHO	0x1e87600 /* HV->FSP */

/*
 * Class EB
 */
#define FSP_CMD_GET_VNVRAM_SIZE	0x01eb0100 /* HV->FSP */
#define FSP_CMD_OPEN_VNVRAM	0x01eb0200 /* HV->FSP */
#define FSP_CMD_READ_VNVRAM	0x01eb0300 /* HV->FSP */
#define FSP_CMD_WRITE_VNVRAM	0x01eb0400 /* HV->FSP */
#define FSP_CMD_GET_VNV_STATS	0x00eb0500 /* FSP->HV */
#define FSP_RSP_GET_VNV_STATS	0x00eb8500
#define FSP_CMD_FREE_VNV_STATS	0x00eb0600 /* FSP->HV */
#define FSP_RSP_FREE_VNV_STATS	0x00eb8600

/*
 * Class 0xEE
 */
#define FSP_RSP_DIAG_LINK_ERROR  0x00ee1100 /* FSP->HV */
#define FSP_RSP_DIAG_ACK_TIMEOUT 0x00ee0000 /* FSP->HV */

/*
 * Class F0
 */
#define FSP_CMD_LOAD_OCC	0x00f00100 /* FSP->HV */
#define FSP_RSP_LOAD_OCC	0x00f08100 /* HV->FSP */
#define FSP_CMD_LOAD_OCC_STAT	0x01f00300 /* HV->FSP */
#define FSP_CMD_RESET_OCC	0x00f00200 /* FSP->HV */
#define FSP_RSP_RESET_OCC	0x00f08200 /* HV->FSP */
#define FSP_CMD_RESET_OCC_STAT	0x01f00400 /* HV->FSP */

/*
 * Class E4
 */
#define FSP_CMD_MEM_RES_CE	0x00e40300 /* FSP->HV: Memory resilience CE */
#define FSP_CMD_MEM_RES_UE	0x00e40301 /* FSP->HV: Memory resilience UE */
#define FSP_CMD_MEM_RES_UE_SCRB	0x00e40302 /* FSP->HV: UE detected by scrub */
#define FSP_RSP_MEM_RES		0x00e48300 /* HV->FSP */
#define FSP_CMD_MEM_DYN_DEALLOC	0x00e40500 /* FSP->HV: Dynamic mem dealloc */
#define FSP_RSP_MEM_DYN_DEALLOC	0x00e48500 /* HV->FSP */

/*
 * Class F2
 */
#define FSP_CMD_HBRT_TO_FSP	0x1f20100 /* HV->FSP: HBRT message */
#define FSP_CMD_FSP_TO_HBRT	0x0f20200 /* FSP->HV: HBRT message */
#define FSP_RSP_FSP_TO_HBRT	0x0f28200 /* HV->FSP: HBRT message */


/*
 * Functions exposed to the rest of skiboot
 */

/* An FSP message */

enum fsp_msg_state {
	fsp_msg_unused = 0,
	fsp_msg_queued,
	fsp_msg_sent,
	fsp_msg_wresp,
	fsp_msg_done,
	fsp_msg_timeout,
	fsp_msg_incoming,
	fsp_msg_response,
	fsp_msg_cancelled,
};

struct fsp_msg {
	/*
	 * User fields. Don't populate word0.seq (upper 16 bits), this
	 * will be done by fsp_queue_msg()
	 */
	u8			dlen;	/* not including word0/word1 */
	u32			word0;	/* seq << 16 | cmd */
	u32			word1;	/* mod << 8 | sub */
	union {
		__be32		words[14];
		u8		bytes[56];
	} data;

	/* Completion function. Called with no lock held */
	void (*complete)(struct fsp_msg *msg);
	void *user_data;

	/*
	 * Driver updated fields
	 */

	/* Current msg state */
	enum fsp_msg_state	state;

	/* Set if the message expects a response */
	bool			response;

	/* Response will be filed by driver when response received */
	struct fsp_msg		*resp;

	/* Internal queuing */
	struct list_node	link;
};

static inline u32 fsp_msg_get_data_word(struct fsp_msg *msg, unsigned long i)
{
	return be32_to_cpu(msg->data.words[i]);
}

static inline void fsp_msg_set_data_word(struct fsp_msg *msg, unsigned long i, u32 w)
{
	msg->data.words[i] = cpu_to_be32(w);
}

/* This checks if a message is still "in progress" in the FSP driver */
static inline bool fsp_msg_busy(struct fsp_msg *msg)
{
	switch(msg->state) {
	case fsp_msg_unused:
	case fsp_msg_done:
	case fsp_msg_timeout:
	case fsp_msg_response: /* A response is considered a completed msg */
		return false;
	default:
		break;
	}
	return true;
}

static inline u32 fsp_msg_cmd(const struct fsp_msg *msg)
{
	u32 cmd_sub_mod;
	cmd_sub_mod = (msg->word0 & 0xff) << 16;
	cmd_sub_mod |= (msg->word1 & 0xff) << 8;
	cmd_sub_mod |= (msg->word1 & 0xff00) >> 8;
	return cmd_sub_mod;
}

/* Initialize the FSP mailbox driver */
extern void fsp_init(void);

/* Perform the OPL sequence */
extern void fsp_opl(void);

/* Check if system has an FSP */
extern bool fsp_present(void);

/* Allocate and populate an fsp_msg structure
 *
 * WARNING: Do _NOT_ use free() on an fsp_msg, use fsp_freemsg()
 * instead as we will eventually use pre-allocated message pools
 */
extern struct fsp_msg *fsp_allocmsg(bool alloc_response) __warn_unused_result;
extern struct fsp_msg *fsp_mkmsg(u32 cmd_sub_mod, u32 add_words, ...) __warn_unused_result;

/* Populate a pre-allocated msg */
extern void fsp_fillmsg(struct fsp_msg *msg, u32 cmd_sub_mod, u32 add_words, ...);

/* Free a message
 *
 * WARNING: This will also free an attached response if any
 */
extern void fsp_freemsg(struct fsp_msg *msg);

/* Free a message and not the attached reply */
extern void __fsp_freemsg(struct fsp_msg *msg);

/* Cancel a message from the msg queue
 *
 * WARNING: * This is intended for use only in the FSP r/r scenario.
 * 	    * This will also free an attached response if any
 */
extern void fsp_cancelmsg(struct fsp_msg *msg);

/* Enqueue it in the appropriate FSP queue
 *
 * NOTE: This supports being called with the FSP lock already
 * held. This is the only function in this module that does so
 * and is meant to be used that way for sending serial "poke"
 * commands to the FSP.
 */
extern int fsp_queue_msg(struct fsp_msg *msg,
			 void (*comp)(struct fsp_msg *msg)) __warn_unused_result;

/* Send a fatal message to FSP
 *
 * This will *not* run pollers.
 * Use only when attempting to get the word out about how we died.
 */
extern int fsp_fatal_msg(struct fsp_msg *msg);

/* Synchronously send a command. If there's a response, the status is
 * returned as a positive number. A negative result means an error
 * sending the message.
 *
 * If autofree is set, the message and the reply (if any) are freed
 * after extracting the status. If not set, you are responsible for
 * freeing both the message and an eventual response
 *
 * NOTE: This will call fsp_queue_msg(msg, NULL), hence clearing the
 * completion field of the message. No synchronous message is expected
 * to utilize asynchronous completions.
 */
extern int fsp_sync_msg(struct fsp_msg *msg, bool autofree);

/* Handle FSP interrupts */
extern void fsp_interrupt(void);

/* An FSP client is interested in messages for a given class */
struct fsp_client {
	/* Return true to "own" the message (you can free it) */
	bool	(*message)(u32 cmd_sub_mod, struct fsp_msg *msg);
	struct list_node	link;
};

/* WARNING: Command class FSP_MCLASS_IPL is aliased to FSP_MCLASS_SERVICE,
 * thus a client of one will get both types of messages.
 *
 * WARNING: Client register/unregister takes *NO* lock. These are expected
 * to be called early at boot before CPUs are brought up and before
 * fsp_poll() can race. The client callback is called with no lock held.
 */
extern void fsp_register_client(struct fsp_client *client, u8 msgclass);
extern void fsp_unregister_client(struct fsp_client *client, u8 msgclass);

/* FSP TCE map/unmap functions */
extern void fsp_tce_map(u32 offset, void *addr, u32 size);
extern void fsp_tce_unmap(u32 offset, u32 size);
extern void *fsp_inbound_buf_from_tce(u32 tce_token);

/* Data fetch helper */
extern uint32_t fsp_adjust_lid_side(uint32_t lid_no);
extern int fsp_fetch_data(uint8_t flags, uint16_t id, uint32_t sub_id,
			  uint32_t offset, void *buffer, size_t *length);
extern int fsp_fetch_data_queue(uint8_t flags, uint16_t id, uint32_t sub_id,
				uint32_t offset, void *buffer, size_t *length,
				void (*comp)(struct fsp_msg *msg)) __warn_unused_result;
extern int fsp_start_preload_resource(enum resource_id id, uint32_t idx,
				      void *buf, size_t *size);
extern int fsp_resource_loaded(enum resource_id id, uint32_t idx);
extern int fsp_preload_lid(uint32_t lid_no, char *buf, size_t *size);
extern int fsp_wait_lid_loaded(uint32_t lid_no);

/* FSP console stuff */
extern void fsp_console_preinit(void);
extern void fsp_console_init(void);
extern void fsp_console_add_nodes(void);
extern void fsp_console_select_stdout(void);
extern void fsp_console_reset(void);
extern void fsp_console_poll(void *);

/* Mark FSP lock */
extern void fsp_used_by_console(void);

/* NVRAM */
extern int fsp_nvram_info(uint32_t *total_size);
extern int fsp_nvram_start_read(void *dst, uint32_t src, uint32_t len);
extern int fsp_nvram_write(uint32_t offset, void *src, uint32_t size);

/* RTC */
extern void fsp_rtc_init(void);

/* ELOG */
extern void fsp_elog_read_init(void);
extern void fsp_elog_write_init(void);

/* Code update */
extern void fsp_code_update_init(void);
extern void fsp_code_update_wait_vpd(bool is_boot);

/* Dump */
extern void fsp_dump_init(void);
extern void fsp_fips_dump_notify(uint32_t dump_id, uint32_t dump_len);

/* Attention Handler */
extern void fsp_attn_init(void);

/* MDST table */
extern void fsp_mdst_table_init(void);

/* This can be set by the fsp_opal_update_flash so that it can
 * get called just reboot we reboot shutdown the machine.
 */
extern int (*fsp_flash_term_hook)(void);

/* Surveillance */
extern void fsp_init_surveillance(void);
extern void fsp_surv_query(void);

/* IPMI */
extern void fsp_ipmi_init(void);

/* Reset/Reload */
extern void fsp_reinit_fsp(void);
extern void fsp_trigger_reset(uint32_t plid);
extern void fsp_reset_links(void);
extern bool fsp_in_rr(void);

/* FSP memory errors */
extern void fsp_memory_err_init(void);

/* Sensor */
extern void fsp_init_sensor(void);
extern int64_t fsp_opal_read_sensor(uint32_t sensor_hndl, int token,
					__be64 *sensor_data);

/* Diagnostic */
extern void fsp_init_diag(void);

/* LED */
extern void fsp_led_init(void);
extern void create_led_device_nodes(void);

/* EPOW */
extern void fsp_epow_init(void);

/* DPO */
extern void fsp_dpo_init(void);
extern bool fsp_dpo_pending;

/* Chiptod */
extern void fsp_chiptod_init(void);

/* Terminate immediate */
extern void __attribute__((noreturn)) ibm_fsp_terminate(const char *msg);

void fsp_op_display(enum op_severity sev, enum op_module mod, uint16_t code);

#endif /* __FSP_H */
