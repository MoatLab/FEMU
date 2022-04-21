// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __PHB4_H
#define __PHB4_H

#include <interrupts.h>

/*
 * Memory map
 *
 * In addition to the 4K MMIO registers window, the PBCQ will
 * forward down one or two large MMIO regions for use by the
 * PHB.
 *
 * We try to use the largest MMIO window for the M64 space and
 * the smallest for the M32 space, but we require at least 2G
 * of M32, otherwise we carve it out of M64.
 */

#define M32_PCI_START		0x080000000	/* Offset of the actual M32 window in PCI */
#define M32_PCI_SIZE		0x80000000ul	/* Size for M32 */

#if 0
/*
 * Interrupt map.
 *
 * Each PHB supports 2K interrupt sources, which is shared by
 * LSI and MSI. With default configuration, MSI would use range
 * [0, 0x7f7] and LSI would use [0x7f8, 0x7ff]. The interrupt
 * source should be combined with IRSN to form final hardware
 * IRQ.
 */
#define PHB4_MSI_IRQ_MIN		0x000
#define PHB4_MSI_IRQ_COUNT		0x7F8
#define PHB4_MSI_IRQ_MAX		(PHB4_MSI_IRQ_MIN+PHB4_MSI_IRQ_COUNT-1)
#define PHB4_LSI_IRQ_MIN		(PHB4_MSI_IRQ_COUNT)
#define PHB4_LSI_IRQ_COUNT		8
#define PHB4_LSI_IRQ_MAX		(PHB4_LSI_IRQ_MIN+PHB4_LSI_IRQ_COUNT-1)

#define PHB4_MSI_IRQ_BASE(chip, phb)	(p8_chip_irq_phb_base(chip, phb) | \
					 PHB4_MSI_IRQ_MIN)
#define PHB4_LSI_IRQ_BASE(chip, phb)	(p8_chip_irq_phb_base(chip, phb) | \
					 PHB4_LSI_IRQ_MIN)
#define PHB4_IRQ_NUM(irq)		(irq & 0x7FF)

#endif

/*
 * LSI interrupts
 *
 * The LSI interrupt block supports 8 interrupts. 4 of them are the
 * standard PCIe INTA..INTB. The rest is for additional functions
 * of the PHB
 */
#define PHB4_LSI_PCIE_INTA		0
#define PHB4_LSI_PCIE_INTB		1
#define PHB4_LSI_PCIE_INTC		2
#define PHB4_LSI_PCIE_INTD		3
#define PHB4_LSI_PCIE_INF		6
#define PHB4_LSI_PCIE_ER		7

/*
 * In-memory tables
 *
 * PHB4 requires a bunch of tables to be in memory instead of
 * arrays inside the chip (unlike previous versions of the
 * design).
 *
 * Some of them (IVT, etc...) will be provided by the OS via an
 * OPAL call, not only not all of them, we also need to make sure
 * some like PELT-V exist before we do our internal slot probing
 * or bad thing would happen on error (the whole PHB would go into
 * Fatal error state).
 *
 * So we maintain a set of tables internally for those mandatory
 * ones within our core memory. They are fairly small. They can
 * still be replaced by OS provided ones via OPAL APIs (and reset
 * to the internal ones) so the OS can provide node local allocation
 * for better performances.
 *
 * All those tables have to be naturally aligned
 */

/* RTT Table : 128KB - Maps RID to PE# 
 *
 * Entries are 2 bytes indexed by PCIe RID
 */
#define RTT_TABLE_ENTRIES	0x10000
#define RTT_TABLE_SIZE		0x20000
#define PELTV_TABLE_SIZE_MAX	0x20000

#define PHB4_RESERVED_PE_NUM(p)	((p)->num_pes - 1)

/*
 * PHB4 PCI slot state. When you're going to apply any
 * changes here, please make sure the base state isn't
 * conflicting with those defined in pci-slot.h
 */
#define PHB4_SLOT_NORMAL			PCI_SLOT_STATE_NORMAL
#define PHB4_SLOT_LINK				PCI_SLOT_STATE_LINK
#define   PHB4_SLOT_LINK_START			(PHB4_SLOT_LINK + 1)
#define   PHB4_SLOT_LINK_WAIT_ELECTRICAL	(PHB4_SLOT_LINK + 2)
#define   PHB4_SLOT_LINK_WAIT			(PHB4_SLOT_LINK + 3)
#define   PHB4_SLOT_LINK_STABLE			(PHB4_SLOT_LINK + 4)
#define PHB4_SLOT_HRESET			PCI_SLOT_STATE_HRESET
#define   PHB4_SLOT_HRESET_START		(PHB4_SLOT_HRESET + 1)
#define   PHB4_SLOT_HRESET_DELAY		(PHB4_SLOT_HRESET + 2)
#define   PHB4_SLOT_HRESET_DELAY2		(PHB4_SLOT_HRESET + 3)
#define PHB4_SLOT_FRESET			PCI_SLOT_STATE_FRESET
#define   PHB4_SLOT_FRESET_START		(PHB4_SLOT_FRESET + 1)
#define   PHB4_SLOT_FRESET_ASSERT_DELAY		(PHB4_SLOT_FRESET + 2)
#define PHB4_SLOT_CRESET			PCI_SLOT_STATE_CRESET
#define   PHB4_SLOT_CRESET_START		(PHB4_SLOT_CRESET + 1)
#define   PHB4_SLOT_CRESET_WAIT_CQ		(PHB4_SLOT_CRESET + 2)
#define   PHB4_SLOT_CRESET_REINIT		(PHB4_SLOT_CRESET + 3)
#define   PHB4_SLOT_CRESET_FRESET		(PHB4_SLOT_CRESET + 4)

/*
 * PHB4 error descriptor. Errors from all components (PBCQ, PHB)
 * will be cached to PHB4 instance. However, PBCQ errors would
 * have higher priority than those from PHB
 */
#define PHB4_ERR_SRC_NONE	0
#define PHB4_ERR_SRC_PBCQ	1
#define PHB4_ERR_SRC_PHB	2

#define PHB4_ERR_CLASS_NONE	0
#define PHB4_ERR_CLASS_DEAD	1
#define PHB4_ERR_CLASS_FENCED	2
#define PHB4_ERR_CLASS_ER	3
#define PHB4_ERR_CLASS_INF	4
#define PHB4_ERR_CLASS_LAST	5

struct phb4_err {
	uint32_t err_src;
	uint32_t err_class;
	uint32_t err_bit;
};

#define PHB4_LINK_LINK_RETRIES		4
/* Link timeouts, increments of 10ms */
#define PHB4_LINK_ELECTRICAL_RETRIES	100
#define PHB4_LINK_WAIT_RETRIES		200

#define PHB4_RX_ERR_MAX			8

/* PHB4 flags */
#define PHB4_AIB_FENCED		0x00000001
#define PHB4_CFG_USE_ASB	0x00000002
#define PHB4_CFG_BLOCKED	0x00000004
#define PHB4_CAPP_RECOVERY	0x00000008
#define PHB4_CAPP_DISABLE	0x00000010
#define PHB4_ETU_IN_RESET	0x00000020

struct phb4 {
	unsigned int		index;	    /* 0..5 index inside p9/p10 */
	unsigned int		flags;
	unsigned int		chip_id;    /* Chip ID (== GCID on p9/p10) */
	unsigned int		pec;
	bool			broken;
	unsigned int		rev;        /* 00MMmmmm */
#define PHB4_REV_NIMBUS_DD10	0xa40001
#define PHB4_REV_NIMBUS_DD20	0xa40002
	void			*regs;
	void			*int_mmio;
	uint64_t		pe_xscom;   /* XSCOM bases */
	uint64_t		pe_stk_xscom;
	uint64_t		pci_xscom;
	uint64_t		pci_stk_xscom;
	uint64_t		etu_xscom;
	struct lock		lock;
	uint64_t		mm0_base;    /* Full MM window to PHB */
	uint64_t		mm0_size;    /* '' '' '' */
	uint64_t		mm1_base;    /* Full MM window to PHB */
	uint64_t		mm1_size;    /* '' '' '' */
	uint32_t		base_msi;
	uint32_t		base_lsi;
	uint64_t		irq_port;
	uint32_t		num_pes;
	uint32_t		max_num_pes;
	uint32_t		num_irqs;
	uint64_t		creset_start_time;

	/* SkiBoot owned in-memory tables */
	__be16			*tbl_rtt;
	uint8_t			*tbl_peltv;
	uint64_t		tbl_peltv_size;
	uint64_t		tbl_pest;
	uint64_t		tbl_pest_size;

	bool			skip_perst; /* Skip first perst */
	bool			has_link;
	int64_t			ecap;	    /* cached PCI-E cap offset */
	int64_t			aercap;	    /* cached AER ecap offset */
	const __be64		*lane_eq;
	bool			lane_eq_en;
	unsigned int		max_link_speed;
	unsigned int		dt_max_link_speed;
	unsigned int		max_link_width;

	uint64_t		mrt_size;
	uint64_t		mbt_size;
	uint64_t		tvt_size;

	/* FIXME: dynamically allocate only what's needed below */
	uint64_t		tve_cache[1024];
	uint64_t		mbt_cache[32][2];
	uint64_t		mdt_cache[512]; /* max num of PEs */
	uint64_t		mist_cache[4096/4];/* max num of MSIs */
	uint64_t		pfir_cache;	/* Used by complete reset */
	uint64_t		nfir_cache;	/* Used by complete reset */
	bool			err_pending;
	struct phb4_err		err;

	/* Cache some RC registers that need to be emulated */
	uint32_t		rc_cache[4];

	/* Current NPU2 relaxed ordering state */
	bool			ro_state;

	/* Any capp instance attached to the PHB4 */
	struct capp		*capp;

	struct phb		phb;
};

static inline struct phb4 *phb_to_phb4(struct phb *phb)
{
	return container_of(phb, struct phb4, phb);
}

static inline bool phb4_err_pending(struct phb4 *p)
{
	return p->err_pending;
}

static inline void phb4_set_err_pending(struct phb4 *p, bool pending)
{
	if (!pending) {
		p->err.err_src   = PHB4_ERR_SRC_NONE;
		p->err.err_class = PHB4_ERR_CLASS_NONE;
		p->err.err_bit   = -1;
	}

	p->err_pending = pending;
}

#define MAX_PHBS_PER_CHIP_P9            6 /* Max 6 PHBs per chip on p9 */
#define MAX_PHBS_PER_CHIP_P9P           0x10 /* extra for virt PHBs */
#define MAX_PHBS_PER_CHIP_P10           0x12 /* 6 PCI + 12 opencapi */

static inline int phb4_get_opal_id(unsigned int chip_id, unsigned int index)
{
	if (proc_gen == proc_gen_p10) {
		return chip_id * MAX_PHBS_PER_CHIP_P10 + index;
	} else {
		if (PVR_TYPE(mfspr(SPR_PVR)) == PVR_TYPE_P9)
			return chip_id * MAX_PHBS_PER_CHIP_P9 + index;
		else
			return chip_id * MAX_PHBS_PER_CHIP_P9P + index;
	}
}

void phb4_pec2_dma_engine_realloc(struct phb4 *p);

#endif /* __PHB4_H */
