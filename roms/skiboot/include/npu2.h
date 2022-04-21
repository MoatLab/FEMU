// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __NPU2_H
#define __NPU2_H

#include <pci.h>
#include <phys-map.h>
#include <npu2-regs.h>

/* Debugging options */
#define NPU2DBG(p, fmt, a...)	prlog(PR_DEBUG, "NPU%d: " fmt, \
				      (p)->phb_nvlink.opal_id, ##a)
#define NPU2INF(p, fmt, a...)	prlog(PR_INFO,  "NPU%d: " fmt, \
				      (p)->phb_nvlink.opal_id, ##a)
#define NPU2ERR(p, fmt, a...)	prlog(PR_ERR,   "NPU%d: " fmt, \
				      (p)->phb_nvlink.opal_id, ##a)

#define NPU2DEVLOG(l, p, fmt, a...)	prlog(l, "NPU%d:%d:%d.%d " fmt, \
					      (p)->npu->phb_nvlink.opal_id, \
					      PCI_BUS_NUM((p)->bdfn), \
					      PCI_DEV((p)->bdfn), \
					      PCI_FUNC((p)->bdfn), ##a)
#define NPU2DEVDBG(p, fmt, a...)	NPU2DEVLOG(PR_DEBUG, p, fmt, ##a)
#define NPU2DEVINF(p, fmt, a...)	NPU2DEVLOG(PR_INFO, p, fmt, ##a)
#define NPU2DEVERR(p, fmt, a...)	NPU2DEVLOG(PR_ERR, p, fmt, ##a)

#define OCAPIDBG(dev, fmt, a...)    prlog(PR_DEBUG, "OCAPI[%d:%d]: " fmt, \
					  dev->npu->chip_id, dev->brick_index, ## a)
#define OCAPIINF(dev, fmt, a...)    prlog(PR_INFO, "OCAPI[%d:%d]: " fmt, \
					  dev->npu->chip_id, dev->brick_index, ## a)
#define OCAPIERR(dev, fmt, a...)    prlog(PR_ERR, "OCAPI[%d:%d]: " fmt, \
					  dev->npu->chip_id, dev->brick_index, ## a)


/*
 * Number of PEs supported
 *
 * The NPU supports PE numbers from 0-15. At present, we only assign a maximum
 * of 1 PE per brick.
 *
 * NVLink devices are currently exposed to Linux underneath a single virtual
 * PHB. Therefore, we give NVLink half the available PEs, which is enough for
 * 6 bricks plus 1 reserved PE.
 *
 * For OpenCAPI, the BDF-to-PE registers are used exclusively for mapping
 * bricks to System Interrupt Log registers (the BDF component of those
 * registers is ignored). Currently, we allocate a fixed PE based on the brick
 * index in the upper half of the PE namespace.
 */
#define NPU2_MAX_PE_NUM		8
#define NPU2_RESERVED_PE_NUM	7
#define NPU2_OCAPI_PE(ndev) ((ndev)->brick_index + NPU2_MAX_PE_NUM)

#define NPU2_LINKS_PER_CHIP 6

/* Link flags */
#define NPU2_DEV_PCI_LINKED	0x1
#define NPU2_DEV_DL_RESET	0x2

/* Return the stack (0-2) of a device */
#define NPU2DEV_STACK(ndev) ((ndev)->brick_index / 2)

/* Return the brick number (0-1) within a stack */
#define NPU2DEV_BRICK(ndev) ((ndev)->brick_index % 2)

/* This represents the state of the actual hardware BARs not the
 * emulated PCIe BARs. The is a subtle difference between the two as
 * not all BARs are exposed outside of skiboot. */
struct npu2_bar {
	enum phys_map_type	type;
	int			index;
#define NPU2_BAR_FLAG_ENABLED	0x0010

/* Generation ID's are a single space in the hardware but we split
 * them in two for the emulated PCIe devices so we need to keep track
 * of which one has been enabled/disabled. */
#define NPU2_BAR_FLAG_ENABLED0	0x0080
#define NPU2_BAR_FLAG_ENABLED1  0x0100
	uint32_t		flags;
	uint64_t		base;
	uint64_t		size;
	uint64_t		reg;
};

/* Rpresents a BAR that is exposed via the PCIe emulated
 * devices */
struct npu2_pcie_bar {
#define NPU2_PCIE_BAR_FLAG_SIZE_HI	0x0020
#define NPU2_PCIE_BAR_FLAG_TRAPPED	0x0040
	uint32_t		flags;
	struct npu2_bar		npu2_bar;
};

enum npu2_dev_type {
	NPU2_DEV_TYPE_UNKNOWN,
	NPU2_DEV_TYPE_NVLINK,
	NPU2_DEV_TYPE_OPENCAPI,
};

struct npu2;

struct npu2_dev_nvlink {
	/* For NVLink, device and function numbers are allocated based
	 * on GPU association. Links to connected to the same GPU will
	 * be exposed as different functions of the same
	 * bus/device. */
	uint32_t		gpu_bdfn;

	/* PCI virtual device and the associated GPU device */
	struct pci_virt_device	*pvd;
	struct phb		*phb;
	struct pci_device	*pd;

	uint8_t			link_flags;

	/* Used to associate the NPU device with GPU PCI devices */
	const char		*slot_label;
};

#define NPU2_DEV_BROKEN		0x1

struct npu2_dev {
	enum npu2_dev_type	type;
	uint32_t		link_index;
	uint32_t		brick_index;
	uint64_t		pl_xscom_base;
	struct dt_node		*dt_node;
	struct npu2_pcie_bar	bars[2];
	struct npu2		*npu;
	long			flags;

	uint32_t		bdfn;

	/* Which PHY lanes this device is associated with */
	uint32_t		lane_mask;
	uint64_t		link_speed; /* not used for NVLink */

	/* Track currently running procedure and step number */
	uint16_t		procedure_number;
	uint16_t		procedure_step;
	unsigned long		procedure_tb;
	uint32_t		procedure_status;

	/* NVLink */
	struct npu2_dev_nvlink	nvlink;

	/* OpenCAPI */
	struct phb		phb_ocapi;
	uint64_t		linux_pe;
	unsigned long		train_start;
	unsigned long		train_timeout;
	uint64_t		lpc_mem_base;
	uint64_t		lpc_mem_size;
};

struct npu2 {
	uint32_t	index;
	struct dt_node	*dt_node;
	uint32_t	chip_id;
	uint64_t	xscom_base;
	void		*regs;
	uint64_t	mm_base;
	uint64_t	mm_size;
	uint32_t	base_lsi;
	uint32_t	total_devices;
	struct npu2_dev	*devices;
	enum phys_map_type gpu_map_type;
	int		ctx_ref[NPU2_XTS_BDF_MAP_SIZE];

	/* IODA cache */
	uint64_t	tve_cache[16];
	bool		tx_zcal_complete[2];

	/*
	 * Used to protect global MMIO space, in particular the XTS
	 * tables, and LPC allocation
	 */
	struct lock	lock;

	/* NVLink */
	struct phb	phb_nvlink;

	/* OCAPI */
	uint64_t	i2c_port_id_ocapi;
	struct lock	i2c_lock;
	uint8_t		i2c_pin_mode;
	uint8_t		i2c_pin_wr_state;
};

static inline struct npu2 *phb_to_npu2_nvlink(struct phb *phb)
{
	assert(phb->phb_type == phb_type_npu_v2);
	return container_of(phb, struct npu2, phb_nvlink);
}

static inline struct npu2_dev *phb_to_npu2_dev_ocapi(struct phb *phb)
{
	assert(phb->phb_type == phb_type_npu_v2_opencapi);
	return container_of(phb, struct npu2_dev, phb_ocapi);
}

static inline struct phb *npu2_dev_to_phb(struct npu2_dev *ndev)
{
	switch (ndev->type) {
	case NPU2_DEV_TYPE_NVLINK:
		return &ndev->npu->phb_nvlink;
	case NPU2_DEV_TYPE_OPENCAPI:
		return &ndev->phb_ocapi;
	default:
		assert(false);
	}
}

void npu2_i2c_presence_detect(struct npu2 *npu);
int npu2_opencapi_init_npu(struct npu2 *npu);
int npu2_nvlink_init_npu(struct npu2 *npu);
void npu2_nvlink_create_phb(struct npu2 *npu, struct dt_node *dn);

void npu2_write_4b(struct npu2 *p, uint64_t reg, uint32_t val);
uint32_t npu2_read_4b(struct npu2 *p, uint64_t reg);
void npu2_write(struct npu2 *p, uint64_t reg, uint64_t val);
uint64_t npu2_read(struct npu2 *p, uint64_t reg);
void npu2_write_mask(struct npu2 *p, uint64_t reg, uint64_t val, uint64_t mask);
void npu2_write_mask_4b(struct npu2 *p, uint64_t reg, uint32_t val, uint32_t mask);
int64_t npu2_dev_procedure(void *dev, struct pci_cfg_reg_filter *pcrf,
			   uint32_t offset, uint32_t len, uint32_t *data,
			   bool write);
void npu2_dev_procedure_reset(struct npu2_dev *dev);

void npu2_set_link_flag(struct npu2_dev *ndev, uint8_t flag);
void npu2_clear_link_flag(struct npu2_dev *ndev, uint8_t flag);
uint32_t reset_ntl(struct npu2_dev *ndev);
extern int nv_zcal_nominal;
void npu2_opencapi_phy_init(struct npu2_dev *dev);
int npu2_opencapi_phy_reset(struct npu2_dev *dev);
void npu2_opencapi_phy_prbs31(struct npu2_dev *dev);
void npu2_opencapi_bump_ui_lane(struct npu2_dev *dev);
int64_t npu2_freeze_status(struct phb *phb __unused,
			   uint64_t pe_number __unused,
			   uint8_t *freeze_state,
			   uint16_t *pci_error_type __unused,
			   uint16_t *severity __unused);
void npu2_dump_scoms(int chip_id);

int64_t npu2_init_context(struct phb *phb, uint64_t msr, uint64_t bdf);
int64_t npu2_destroy_context(struct phb *phb, uint64_t bdf);
int64_t npu2_map_lpar(struct phb *phb, uint64_t bdf, uint64_t lparid,
		      uint64_t lpcr);
int64_t npu2_set_relaxed_order(struct phb *phb, uint32_t gcid, int pec,
			       bool enable);

void npu2_opencapi_set_broken(struct npu2 *npu, int brick);

#define NPU2_PHB_INDEX_BASE 7
/* to avoid conflicts with PCI and for historical reasons */

static inline int npu2_get_phb_index(unsigned int brick_index)
{
	/*
	 * There's one virtual PHB per brick with opencapi, so we no
	 * longer have a 1-to-1 mapping between a NPU and a virtual
	 * PHB. And we want a static phb-index, as it is needed to use
	 * a slot table on some platforms. So we associate a per-chip
	 * phb-index based on the brick index.
	 *
	 * nvlink only creates one virtual PHB per chip, so it is
	 * treated as if using brick 0, which is never used by
	 * opencapi.
	 */
	return NPU2_PHB_INDEX_BASE + brick_index;
}

#endif /* __NPU2_H */
