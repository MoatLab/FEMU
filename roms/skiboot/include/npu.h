// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2017 IBM Corp. */

#ifndef __NPU_H
#define __NPU_H

#include <io.h>

/* Number of PEs supported */
#define NPU_NUM_OF_PES	4

/* Each brick has 2 MMIO BARs at the maximum. BAR0 is always used to
 * map the 128KB TL/DL registers. BAR1 is used to map either the PL or
 * the AT registers which are not exposed to the OS.
 */
#define NPU_BRICK_NUM_OF_BARS	2
#define NPU_BRICK_TL_BAR_SIZE	0x20000
#define NPU_BRICK_PL_BAR_SIZE	0x200000

/* Bytes of the emulated NPU PCI device config space. We are
 * emulating PCI express device, not legacy one
 */
#define NPU_DEV_CFG_SIZE	0x100

/* Interrupt mapping
 *
 * NPU PHB doesn't support MSI interrupts. It only supports
 * 8 LSI interrupts: [0, 3] for bricks' DL blocks. [4, 5]
 * for reporting errors from DL blocks. [6, 7] for reporting
 * errors from TL blocks, NPCQs and AT.
 */
#define NPU_LSI_IRQ_COUNT	8
#define NPU_LSI_INT_DL0         0
#define NPU_LSI_INT_DL1         1
#define NPU_LSI_INT_DL2         2
#define NPU_LSI_INT_DL3         3
#define NPU_LSI_IRQ_MIN		0x7F0
#define NPU_LSI_IRQ_MAX		(NPU_LSI_IRQ_MIN + NPU_LSI_IRQ_COUNT - 1)
#define NPU_LSI_IRQ_BASE(chip, phb)	(P8_CHIP_IRQ_PHB_BASE(chip, phb) | NPU_LSI_IRQ_MIN)
#define NPU_IRQ_NUM(irq)		(irq & 0x7FF)

/* NPU device capability descriptor. All PCI capabilities is
 * organized as linked list. Each PCI capability has specific
 * hook to populate when initializing NPU device.
 */
struct npu_dev;
struct npu_dev_cap {
	uint16_t		id;
	uint16_t		start;
	uint16_t		end;
	struct npu_dev		*dev;
	void			(*populate)(struct npu_dev_cap *cap);
	struct list_node	link;
};

struct npu_dev_bar {
	uint32_t		flags;
	uint32_t		xscom;
	uint64_t		base;
	uint64_t		size;
	uint32_t		bar_sz;
	bool			trapped;
};

/* Each device contains 2 links. The device will be exposed as
 * standard PCIE device and the config space is emulated by skiboot.
 */
struct npu_dev {
	uint32_t		flags;
	uint32_t		index;
	uint64_t		xscom;
	void			*pl_base;
	uint64_t		pl_xscom_base;
	struct npu_dev_bar	bar;
	struct phb		*phb;

	/* The link@x node */
	struct dt_node		*dt_node;

	/* PCI virtual device and the associated GPU device */
	struct pci_virt_device	*pvd;
	struct pci_device	*pd;
	struct npu		*npu;
	struct list_head	capabilities;

	/* Which PHY lanes this device is associated with */
	uint16_t		lane_mask;

	/* Used to store the currently running procedure number for
	 * this device. */
	uint16_t		procedure_number;

	/* Used to store the step within a procedure that we are up
	 * to. */
	uint16_t		procedure_step;

	/* Arbitrary data used by each procedure to track status. */
	uint64_t		procedure_data;

	/* Used to timeout long running procedures. */
	unsigned long		procedure_tb;

	uint32_t		procedure_status;

	uint64_t		pe_number;

	/* Used to associate the NPU device with GPU PCI devices */
	const char		*slot_label;
};

/* NPU PHB descriptor */
struct npu {
	uint32_t		flags;
	uint32_t		index;
	uint32_t		chip_id;
	uint64_t		xscom_base;
	uint64_t		at_xscom;
	void			*at_regs;
	uint32_t		base_lsi;
	uint64_t		mm_base;
	uint64_t		mm_size;
	uint32_t		total_devices;
	struct npu_dev		*devices;

	/* IODA cache */
	uint64_t		lxive_cache[8];
	uint64_t		pce_cache[6];
	uint64_t		tve_cache[NPU_NUM_OF_PES];

	bool			tx_zcal_complete[2];
	bool			fenced;

	struct phb		phb;
};

static inline struct npu *phb_to_npu(struct phb *phb)
{
	return container_of(phb, struct npu, phb);
}

static inline void npu_ioda_sel(struct npu *p, uint32_t table,
				    uint32_t addr, bool autoinc)
{
	out_be64(p->at_regs + NPU_IODA_ADDR,
		 (autoinc ? NPU_IODA_AD_AUTOINC : 0)	|
		 SETFIELD(NPU_IODA_AD_TSEL, 0ul, table)	|
		 SETFIELD(NPU_IODA_AD_TADR, 0ul, addr));
}

void npu_scom_init(struct npu_dev *dev);

int64_t npu_dev_procedure(void *dev, struct pci_cfg_reg_filter *pcrf,
			  uint32_t offset, uint32_t len, uint32_t *data,
			  bool write);

void npu_set_fence_state(struct npu *p, bool fence);
void npu_dev_procedure_reset(struct npu_dev *dev);

#define NPUDBG(p, fmt, a...)	prlog(PR_DEBUG, "NPU%d: " fmt, \
				      (p)->phb.opal_id, ##a)
#define NPUINF(p, fmt, a...)	prlog(PR_INFO,  "NPU%d: " fmt, \
				      (p)->phb.opal_id, ##a)

#define NPUDEVDBG(p, fmt, a...)	NPUDBG((p)->npu, fmt, ##a)
#define NPUDEVINF(p, fmt, a...)	NPUINF((p)->npu, fmt, ##a)

#endif /* __NPU_H */
