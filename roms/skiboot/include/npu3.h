/* Copyright 2019 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __NPU3_H
#define __NPU3_H

#include <phys-map.h>
#include <pci.h>
#include <npu3-regs.h>
#include <phb4.h>

enum npu3_dev_type {
	NPU3_DEV_TYPE_UNKNOWN = 0,
	NPU3_DEV_TYPE_NVLINK,
	NPU3_DEV_TYPE_ANY = INT_MAX
};

/* Information about a currently running hw procedure */
struct npu3_procedure {
	uint16_t		number;
	uint16_t		step;
	uint32_t		status;
	unsigned long		timeout;
};

/* Used to expose a hardware BAR (or logical slice of it) outside skiboot */
struct npu3_bar {
	bool			enable;
	uint64_t		addr;
	uint64_t		size;
	uint64_t		trap;
};

struct npu3_dev_nvlink {
	/*
	 * PCI virtual device. BDFN is allocated based on NPU association.
	 * Links connected to the same NPU will be exposed as different
	 * functions of the same bus/device.
	 */
	struct pci_virt_device	*pvd;

	/* The PCI device created from pvd */
	const char		*loc_code;
	struct pci_device	*pd;

	/* The associated GPU device */
	struct pci_device	*gpu;
};

struct npu3_dev {
	enum npu3_dev_type	type;
	uint32_t		index;
	struct dt_node		*dn;
	struct npu3		*npu;
	struct npu3_procedure	proc;
	uint64_t		link_speed;

	struct npu3_bar		ntl_bar;
	struct npu3_bar		genid_bar;

	/* Associated PHY information */
	uint32_t		ob_chiplet;
	uint32_t		phy_lane_mask;

	/* For NPU3_DEV_TYPE_NVLINK */
	struct npu3_dev_nvlink	nvlink;
};

struct npu3_nvlink {
	struct phb		phb;
	uint32_t		ctx_ref[NPU3_XTS_BDF_MAP_MAX];
};

#define NPU3_LINKS_PER_NPU 4

struct npu3 {
	uint32_t		index;
	struct dt_node		*dt_node;
	uint32_t		chip_id;
	uint64_t		xscom_base;

	/* Global MMIO window (all NPU regs) */
	uint64_t		regs[2];

	uint32_t		irq_base;
	struct lock		lock;
	bool			tx_zcal_complete;

	struct npu3_dev		devices[NPU3_LINKS_PER_NPU];

	/* Shared by any NPU3_DEV_TYPE_NVLINK devices */
	struct npu3_nvlink	nvlink;
};

static inline struct npu3 *npu3_phb_to_npu(struct phb *phb)
{
	assert(phb->phb_type == phb_type_npu_v3);
	return container_of(phb, struct npu3, nvlink.phb);
}

/* Chip-scope index of the link */
static inline uint32_t npu3_chip_dev_index(struct npu3_dev *dev)
{
	return dev->npu->index * NPU3_LINKS_PER_NPU + dev->index;
}

struct npu3_dev *npu3_next_dev(struct npu3 *npu, struct npu3_dev *dev,
			       enum npu3_dev_type type);

#define npu3_for_each_dev_type(dev, npu, type) \
	for (dev = NULL; (dev = npu3_next_dev(npu, dev, type));)

#define npu3_for_each_nvlink_dev(dev, npu) \
	npu3_for_each_dev_type(dev, npu, NPU3_DEV_TYPE_NVLINK)

#define npu3_for_each_dev(dev, npu) \
	npu3_for_each_dev_type(dev, npu, NPU3_DEV_TYPE_ANY)

struct npu3 *npu3_next_nvlink_npu(struct npu3 *npu, uint32_t chip_id);

#define npu3_for_each_chip_nvlink_npu(npu, chip_id)                    \
        for (npu = NULL; (npu = npu3_next_nvlink_npu(npu, chip_id));)

#define NPU3_ANY_CHIP INT_MAX
#define npu3_for_each_nvlink_npu(npu) \
	npu3_for_each_chip_nvlink_npu(npu, NPU3_ANY_CHIP)

void npu3_init_nvlink(struct npu3 *npu);
void npu3_dev_enable_bars(struct npu3_dev *dev, bool enable);
int64_t npu3_dev_reset(struct npu3_dev *dev);

uint32_t npu3_chip_possible_gpus(void);
int32_t npu3_dev_gpu_index(struct npu3_dev *dev);

/* NPU RING register access */
void npu3_write(struct npu3 *npu, uint64_t reg, uint64_t val);
uint64_t npu3_read(struct npu3 *npu, uint64_t reg);
void npu3_write_4b(struct npu3 *npu, uint64_t reg, uint32_t val);
uint32_t npu3_read_4b(struct npu3 *npu, uint64_t reg);

/* Link flags */
#define NPU3_DEV_PCI_LINKED	0x1
#define NPU3_DEV_DL_RESET	0x2

void npu3_pvd_flag_set(struct npu3_dev *dev, uint8_t flag);
void npu3_pvd_flag_clear(struct npu3_dev *dev, uint8_t flag);

/* PHY procedures */
#define NPU3_PROC_STATUS_MASK	0xc000000f
#define NPU3_PROC_INPROGRESS	(1 << 31)
#define NPU3_PROC_COMPLETE	(1 << 30)
#define NPU3_PROC_NEXT		(1 << 29)
#define NPU3_PROC_FAILED	2
#define NPU3_PROC_ABORTED	3
#define NPU3_PROC_UNSUPPORTED	4

void npu3_dev_procedure_init(struct npu3_dev *dev, uint32_t pnum);
uint32_t npu3_dev_procedure_status(struct npu3_dev *dev);

/* OPAL entry points */
int64_t npu3_init_context(struct phb *phb, uint64_t msr, uint64_t bdf);
int64_t npu3_destroy_context(struct phb *phb, uint64_t bdf);
int64_t npu3_map_lpar(struct phb *phb, uint64_t bdf, uint64_t lparid,
		      uint64_t lpcr);
int64_t npu3_set_relaxed_order(struct phb *phb, uint32_t gcid, int pec,
			       bool enable);

#define NPU3_PHB_INDEX_BASE     6 /* immediately after real PHBs */
static inline int npu3_get_phb_index(unsigned int npu_index)
{
	return NPU3_PHB_INDEX_BASE + npu_index;
}

static inline int npu3_get_opal_id(unsigned int chip_id, unsigned int index)
{
	return phb4_get_opal_id(chip_id, index);
}

#endif /* __NPU3_H */
