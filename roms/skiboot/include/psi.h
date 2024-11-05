// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * IBM System P PSI (Processor Service Interface)
 *
 * Copyright 2013-2019 IBM Corp.
 */
#ifndef __PSI_H
#define __PSI_H

#include <skiboot.h>

/*
 * PSI Host Bridge Registers (MMIO)
 *
 * The PSI interface is the bridge to the FPS, it has its own
 * registers. The FSP registers appear at an offset within the
 * aperture defined by the PSI_FSPBAR
 */
/* Base address of the PSI MMIO space and LSB is the enable/valid bit */
#define PSIHB_BBAR			0x00

/* FSP MMIO region -- this is where the mbx regs are (offset defined below) */
#define PSIHB_FSPBAR			0x08

/* FSP MMIO region mask register -- determines size of region */
#define PSIHB_FSPMMR			0x10

/* TCE address register */
#define PSIHB_TAR			0x18
#define  PSIHB_TAR_8K_ENTRIES		0
#define  PSIHB_TAR_16K_ENTRIES		1
#define  PSIHB_TAR_256K_ENTRIES		2 /* P8 only */
#define  PSIHB_TAR_512K_ENTRIES		4 /* P8 only */

/* PSI Host Bridge Control Register */
#define PSIHB_CR			0x20
#define   PSIHB_CR_FSP_CMD_ENABLE	PPC_BIT(0)
#define   PSIHB_CR_FSP_MMIO_ENABLE	PPC_BIT(1)
#define   PSIHB_CR_FSP_IRQ_ENABLE	PPC_BIT(3)
#define   PSIHB_CR_FSP_ERR_RSP_ENABLE	PPC_BIT(4)
#define   PSIHB_CR_PSI_LINK_ENABLE	PPC_BIT(5)
#define   PSIHB_CR_FSP_RESET		PPC_BIT(6)
#define   PSIHB_CR_PSIHB_RESET		PPC_BIT(7)
#define   PSIHB10_CR_STORE_EOI		PPC_BIT(12)
#define   PSIHB_CR_PSI_IRQ		PPC_BIT(16)	/* PSIHB interrupt */
#define   PSIHB_CR_FSP_IRQ		PPC_BIT(17)	/* FSP interrupt */
#define   PSIHB_CR_FSP_LINK_ACTIVE	PPC_BIT(18)	/* FSP link active */

/* Error conditions in the GXHB */
#define   PSIHB_CR_PSI_ERROR		PPC_BIT(32)	/* PSI error */
#define   PSIHB_CR_PSI_LINK_INACTIVE	PPC_BIT(33)	/* Link inactive */
#define   PSIHB_CR_FSP_ACK_TIMEOUT	PPC_BIT(34)	/* FSP ack timeout */
#define   PSIHB_CR_MMIO_LOAD_TIMEOUT	PPC_BIT(35)	/* MMIO load timeout */
#define   PSIHB_CR_MMIO_LENGTH_ERROR	PPC_BIT(36)	/* MMIO length error */
#define   PSIHB_CR_MMIO_ADDRESS_ERROR	PPC_BIT(37)	/* MMIO address error */
#define   PSIHB_CR_MMIO_TYPE_ERROR	PPC_BIT(38)	/* MMIO type error */
#define   PSIHB_CR_UE			PPC_BIT(39)	/* UE detected */
#define   PSIHB_CR_PARITY_ERROR		PPC_BIT(40)	/* Parity error */
#define   PSIHB_CR_SYNC_ERR_ALERT1	PPC_BIT(41)	/* Sync alert 1 */
#define   PSIHB_CR_SYNC_ERR_ALERT2	PPC_BIT(42)	/* Sync alert 2 */
#define   PSIHB_CR_FSP_COMMAND_ERROR	PPC_BIT(43)	/* FSP cmd error */

/* PSI Status / Error Mask Register */
#define PSIHB_SEMR			0x28

/* XIVR and BUID used for PSI interrupts on P8 */
#define PSIHB_XIVR_FSP			0x30
#define PSIHB_XIVR_OCC			0x60
#define PSIHB_XIVR_FSI			0x68
#define PSIHB_XIVR_LPC			0x70
#define PSIHB_XIVR_LOCAL_ERR		0x78
#define PSIHB_XIVR_HOST_ERR		0x80
#define PSIHB_IRSN			0x88
#define PSIHB_IRSN_COMP			PPC_BITMASK(0,18)
#define PSIHB_IRSN_IRQ_MUX		PPC_BIT(28)
#define PSIHB_IRSN_IRQ_RESET		PPC_BIT(29)
#define PSIHB_IRSN_DOWNSTREAM_EN	PPC_BIT(30)
#define PSIHB_IRSN_UPSTREAM_EN		PPC_BIT(31)
#define PSIHB_IRSN_MASK			PPC_BITMASK(32,50)

#define PSIHB_IRQ_STATUS		0x58
#define   PSIHB_IRQ_STAT_OCC		PPC_BIT(27)
#define   PSIHB_IRQ_STAT_FSI		PPC_BIT(28)
#define   PSIHB_IRQ_STAT_LPC		PPC_BIT(29)
#define   PSIHB_IRQ_STAT_LOCAL_ERR	PPC_BIT(30)
#define   PSIHB_IRQ_STAT_HOST_ERR	PPC_BIT(31)

/* Secure version of CR for P8 and P9 (TCE enable bit) */
#define PSIHB_PHBSCR			0x90
#define   PSIHB_PHBSCR_TCE_ENABLE	PPC_BIT(2)

/* P9 registers */

#define PSIHB_INTERRUPT_CONTROL		0x58
#define   PSIHB_IRQ_METHOD		PPC_BIT(0)
#define   PSIHB_IRQ_RESET		PPC_BIT(1)
#define PSIHB_ESB_CI_BASE		0x60
#define   PSIHB10_ESB_CI_64K		PPC_BIT(1)
#define   PSIHB_ESB_CI_VALID		PPC_BIT(63)
#define PSIHB_ESB_NOTIF_ADDR		0x68
#define   PSIHB_ESB_NOTIF_VALID		PPC_BIT(63)
#define PSIHB_IVT_OFFSET		0x70
#define   PSIHB_IVT_OFF_SHIFT		32
/*
 * PSI Host Bridge Registers (XSCOM)
 */
#define PSIHB_XSCOM_P8_BASE		0xa
#define   PSIHB_XSCOM_P8_HBBAR_EN	PPC_BIT(63)
#define PSIHB_XSCOM_P8_HBCSR		0xe
#define PSIHB_XSCOM_P8_HBCSR_SET	0x12
#define PSIHB_XSCOM_P8_HBCSR_CLR	0x13
#define   PSIHB_XSCOM_P8_HBSCR_FSP_IRQ 	PPC_BIT(17)

#define PSIHB_XSCOM_P9_BASE		0xa
#define   PSIHB_XSCOM_P9_HBBAR_EN	PPC_BIT(63)
#define PSIHB_XSCOM_P9_HBCSR		0xe
#define PSIHB_XSCOM_P9_HBCSR_SET	0x12
#define PSIHB_XSCOM_P9_HBCSR_CLR	0x13
#define   PSIHB_XSCOM_P9_HBSCR_FSP_IRQ 	PPC_BIT(17)

#define PSIHB_XSCOM_P10_BASE		0xa
#define   PSIHB_XSCOM_P10_HBBAR_EN	PPC_BIT(63)
#define PSIHB_XSCOM_P10_HBCSR		0xe
#define PSIHB_XSCOM_P10_HBCSR_SET	0x12
#define PSIHB_XSCOM_P10_HBCSR_CLR	0x13
#define   PSIHB_XSCOM_P10_HBSCR_FSP_IRQ 	PPC_BIT(17)

/* P9 PSI Interrupts */
#define P9_PSI_IRQ_PSI			0
#define P9_PSI_IRQ_OCC			1
#define P9_PSI_IRQ_FSI			2
#define P9_PSI_IRQ_LPCHC		3
#define P9_PSI_IRQ_LOCAL_ERR		4
#define P9_PSI_IRQ_GLOBAL_ERR		5
#define P9_PSI_IRQ_EXTERNAL		6
#define P9_PSI_IRQ_LPC_SIRQ0		7
#define P9_PSI_IRQ_LPC_SIRQ1		8
#define P9_PSI_IRQ_LPC_SIRQ2		9
#define P9_PSI_IRQ_LPC_SIRQ3		10
#define P9_PSI_IRQ_SBE_I2C		11
#define P9_PSI_IRQ_DIO			12
#define P9_PSI_IRQ_PSU			13
#define P9_PSI_NUM_IRQS			14



/*
 * Layout of the PSI DMA address space
 *
 * We use a larger mapping of 256K TCEs which provides us with a 1G window in
 * order to fit the trace buffers
 *
 * Currently we have:
 *
 *   - 4x256K serial areas (each divided in 2: in and out buffers)
 *   - 1M region for inbound buffers
 *   - 2M region for generic data fetches
 */
#define PSI_DMA_SER0_BASE		0x00000000
#define PSI_DMA_SER0_SIZE		0x00040000
#define PSI_DMA_SER1_BASE		0x00040000
#define PSI_DMA_SER1_SIZE		0x00040000
#define PSI_DMA_SER2_BASE		0x00080000
#define PSI_DMA_SER2_SIZE		0x00040000
#define PSI_DMA_SER3_BASE		0x000c0000
#define PSI_DMA_SER3_SIZE		0x00040000
#define PSI_DMA_INBOUND_BUF		0x00100000
#define PSI_DMA_INBOUND_SIZE		0x00100000
#define PSI_DMA_FETCH			0x00200000
#define PSI_DMA_FETCH_SIZE		0x00800000
#define PSI_DMA_NVRAM_BODY		0x00a00000
#define PSI_DMA_NVRAM_BODY_SZ		0x00100000
#define PSI_DMA_NVRAM_TRIPL		0x00b00000
#define PSI_DMA_NVRAM_TRIPL_SZ		0x00001000
#define PSI_DMA_OP_PANEL_MISC		0x00b01000
#define PSI_DMA_OP_PANEL_SIZE		0x00001000
#define PSI_DMA_GET_SYSPARAM		0x00b02000
#define PSI_DMA_GET_SYSPARAM_SZ		0x00001000
#define PSI_DMA_SET_SYSPARAM		0x00b03000
#define PSI_DMA_SET_SYSPARAM_SZ		0x00001000
#define PSI_DMA_ERRLOG_READ_BUF		0x00b04000
#define PSI_DMA_ERRLOG_READ_BUF_SZ	0x00040000
#define PSI_DMA_ELOG_PANIC_WRITE_BUF	0x00b44000
#define PSI_DMA_ELOG_PANIC_WRITE_BUF_SZ	0x00010000
#define PSI_DMA_ERRLOG_WRITE_BUF	0x00b54000
#define PSI_DMA_ERRLOG_WRITE_BUF_SZ	0x00040000
#define PSI_DMA_ELOG_WR_TO_HOST_BUF	0x00b94000	/* Unused */
#define PSI_DMA_ELOG_WR_TO_HOST_BUF_SZ	0x00010000
#define PSI_DMA_HBRT_LOG_WRITE_BUF	0x00ba4000
#define PSI_DMA_HBRT_LOG_WRITE_BUF_SZ	0x00001000
#define PSI_DMA_CODE_UPD		0x00c04000
#define PSI_DMA_CODE_UPD_SIZE		0x01001000
#define PSI_DMA_DUMP_DATA		0x01c05000
#define PSI_DMA_DUMP_DATA_SIZE		0x00500000
#define PSI_DMA_SENSOR_BUF		0x02105000
#define PSI_DMA_SENSOR_BUF_SZ		0x00080000
#define PSI_DMA_MDST_TABLE		0x02185000
#define PSI_DMA_MDST_TABLE_SIZE		0x00001000
#define PSI_DMA_HYP_DUMP		0x02186000
#define PSI_DMA_HYP_DUMP_SIZE		0x01000000
#define PSI_DMA_PCIE_INVENTORY		0x03186000
#define PSI_DMA_PCIE_INVENTORY_SIZE	0x00010000
#define PSI_DMA_LED_BUF			0x03196000
#define PSI_DMA_LED_BUF_SZ		0x00001000
#define PSI_DMA_LOC_COD_BUF		0x03197000
#define PSI_DMA_LOC_COD_BUF_SZ		0x00008000
#define PSI_DMA_MEMCONS			0x0319f000
#define PSI_DMA_MEMCONS_SZ		0x00001000
#define PSI_DMA_LOG_BUF			0x03200000
#define PSI_DMA_LOG_BUF_SZ		0x00100000 /* INMEM_CON_LEN */
#define PSI_DMA_PLAT_REQ_BUF		0x03300000
#define PSI_DMA_PLAT_REQ_BUF_SIZE	0x00001000
#define PSI_DMA_PLAT_RESP_BUF		0x03301000
#define PSI_DMA_PLAT_RESP_BUF_SIZE	0x00001000
/*
 * Our PRD interface can handle upto 64KB data transfer between
 * OPAL - opal-prd. Hence adding TCE size as 68KB. If we increase
 * OPAL - opal-prd message size, then we have to fix this.
 */
#define PSI_DMA_HBRT_FSP_MSG		0x03302000
#define PSI_DMA_HBRT_FSP_MSG_SIZE	0x00011000

#define PSI_DMA_TRACE_BASE		0x04000000

struct psi {
	struct list_node	list;
	uint64_t		xscom_base;
	void			*regs;
	void			*esb_mmio;
	unsigned int		chip_id;
	unsigned int		interrupt;
	bool			active;
	bool			no_lpc_irqs;
	struct dt_node		*node;
};

extern void psi_set_link_polling(bool active);

extern struct psi *first_psi;
extern void psi_init(void);
extern struct psi *psi_find_link(uint32_t chip_id);
extern void psi_init_for_fsp(struct psi *psi);
extern void psi_disable_link(struct psi *psi);
extern void psi_reset_fsp(struct psi *psi);
extern bool psi_check_link_active(struct psi *psi);
extern bool psi_poll_fsp_interrupt(struct psi *psi);
extern struct psi *psi_find_functional_chip(void);

/* Interrupts */
extern void psi_irq_reset(void);
extern void psi_enable_fsp_interrupt(struct psi *psi);
extern void psi_fsp_link_in_use(struct psi *psi);

extern struct lock psi_lock;

#endif /* __PSI_H */
