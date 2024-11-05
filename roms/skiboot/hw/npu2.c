// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * NPU - NVlink and OpenCAPI
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <skiboot.h>
#include <io.h>
#include <timebase.h>
#include <pci-cfg.h>
#include <pci.h>
#include <pci-slot.h>
#include <pci-virt.h>
#include <opal.h>
#include <opal-api.h>
#include <cpu.h>
#include <device.h>
#include <ccan/str/str.h>
#include <ccan/array_size/array_size.h>
#include <affinity.h>
#include <npu2.h>
#include <lock.h>
#include <xscom.h>
#include <bitutils.h>
#include <chip.h>
#include <phys-map.h>
#include <nvram.h>
#include <xscom-p9-regs.h>
#include <phb4.h>
#include <cache-p9.h>

#define VENDOR_CAP_START    0x80
#define VENDOR_CAP_END      0x90
#define VENDOR_CAP_LEN      0x10
#define VENDOR_CAP_VERSION  0x01
#define VENDOR_CAP_PCI_DEV_OFFSET 0x0d

/*
 * NPU2 BAR layout definition. We have 3 stacks and each of them
 * contains 2 bricks. So every NPU2 has 6 bricks in total. There are 2
 * PHY BARs and each of them is shared by 3 bricks. Every brick has
 * one NTL BAR and two bricks share one GENID BAR. There is also a
 * global MMIO BAR. We only expose DL and GENID BARs to the OS and all
 * other BARs will be hidden in skiboot.
 *
 * Before the global MMIO BAR is configured, scom is the only way to
 * access the BAR registers. At NPU2 PHB probing time, we rely on scom
 * to assign all BARs until the global MMIO BAR is established.
 *
 * We need to access 4 SM registers in the same stack in order to
 * configure one particular BAR.
 */

/* Set a specific flag in the vendor config space */
void npu2_set_link_flag(struct npu2_dev *ndev, uint8_t flag)
{
	ndev->nvlink.link_flags |= flag;
	PCI_VIRT_CFG_INIT_RO(ndev->nvlink.pvd, VENDOR_CAP_START +
			     VENDOR_CAP_PCI_DEV_OFFSET, 1, ndev->nvlink.link_flags);
}

void npu2_clear_link_flag(struct npu2_dev *ndev, uint8_t flag)
{
	ndev->nvlink.link_flags &= ~flag;
	PCI_VIRT_CFG_INIT_RO(ndev->nvlink.pvd, VENDOR_CAP_START +
			     VENDOR_CAP_PCI_DEV_OFFSET, 1, ndev->nvlink.link_flags);
}

static inline void npu2_ioda_sel(struct npu2 *p, uint32_t table,
				uint32_t index, bool autoinc)
{
	out_be64(p->regs + NPU2_ATS_IODA_TBL,
		 (autoinc ? NPU2_ATS_IODA_TBL_AUTOINC : 0ul)	|
		 SETFIELD(NPU2_ATS_IODA_TBL_SELECT, 0ul, table)	|
		 SETFIELD(NPU2_ATS_IODA_TBL_INDEX,  0ul, index));
}

static struct npu2_dev *npu2_bdf_to_dev(struct npu2 *p,
					uint32_t bdfn)
{
	struct pci_virt_device *pvd;

	/* All emulated devices are attached to root bus */
	if (bdfn & ~0xff)
		return NULL;

	pvd = pci_virt_find_device(&p->phb_nvlink, bdfn);
	if (pvd)
		return pvd->data;

	return NULL;
}

static inline void npu2_get_bar(uint32_t gcid, struct npu2_bar *bar)
{
	phys_map_get(gcid, bar->type, bar->index, &bar->base, &bar->size);
}

static void npu2_read_bar(struct npu2 *p, struct npu2_bar *bar)
{
	uint64_t reg, val;
	int enabled;

	reg = NPU2_REG_OFFSET(0, NPU2_BLOCK_SM_0, bar->reg);
	val = npu2_read(p, reg);

	switch (NPU2_REG(bar->reg)) {
	case NPU2_PHY_BAR:
		bar->base = GETFIELD(NPU2_PHY_BAR_ADDR, val) << 21;
		enabled = GETFIELD(NPU2_PHY_BAR_ENABLE, val);

		if (NPU2_REG_STACK(reg) == NPU2_STACK_STCK_2)
			/* This is the global MMIO BAR */
			bar->size = 0x1000000;
		else
			bar->size = 0x200000;
		break;
	case NPU2_NTL0_BAR:
	case NPU2_NTL1_BAR:
		bar->base = GETFIELD(NPU2_NTL_BAR_ADDR, val) << 16;
		enabled = GETFIELD(NPU2_NTL_BAR_ENABLE, val);
		bar->size = 0x10000 << GETFIELD(NPU2_NTL_BAR_SIZE, val);
		break;
	case NPU2_GENID_BAR:
		bar->base = GETFIELD(NPU2_GENID_BAR_ADDR, val) << 16;
		enabled = GETFIELD(NPU2_GENID_BAR_ENABLE, val);
		bar->size = 0x20000;
		break;
	default:
		bar->base = 0ul;
		enabled = 0;
		bar->size = 0;
		break;
	}

	bar->flags = SETFIELD(NPU2_BAR_FLAG_ENABLED, bar->flags, enabled);
}

static void npu2_write_bar(struct npu2 *p,
			   struct npu2_bar *bar,
			   uint32_t gcid,
			   uint32_t scom)
{
	uint64_t reg, val, enable = !!(bar->flags & NPU2_BAR_FLAG_ENABLED);
	int block;

	switch (NPU2_REG(bar->reg)) {
	case NPU2_PHY_BAR:
		val = SETFIELD(NPU2_PHY_BAR_ADDR, 0ul, bar->base >> 21);
		val = SETFIELD(NPU2_PHY_BAR_ENABLE, val, enable);
		break;
	case NPU2_NTL0_BAR:
	case NPU2_NTL1_BAR:
		val = SETFIELD(NPU2_NTL_BAR_ADDR, 0ul, bar->base >> 16);
		val = SETFIELD(NPU2_NTL_BAR_ENABLE, val, enable);
		val = SETFIELD(NPU2_NTL_BAR_SIZE, val, 1);
		break;
	case NPU2_GENID_BAR:
		val = SETFIELD(NPU2_GENID_BAR_ADDR, 0ul, bar->base >> 16);
		val = SETFIELD(NPU2_GENID_BAR_ENABLE, val, enable);
		break;
	default:
		val = 0ul;
	}

	for (block = NPU2_BLOCK_SM_0; block <= NPU2_BLOCK_SM_3; block++) {
		reg = NPU2_REG_OFFSET(0, block, bar->reg);
		if (p)
			npu2_write(p, reg, val);
		else
			npu2_scom_write(gcid, scom, reg, NPU2_MISC_DA_LEN_8B, val);
	}
}

/* Trap for PCI command (0x4) to enable or disable device's BARs */
static int64_t npu2_cfg_write_cmd(void *dev,
				  struct pci_cfg_reg_filter *pcrf __unused,
				  uint32_t offset, uint32_t size,
				  uint32_t *data, bool write)
{
	struct pci_virt_device *pvd = dev;
	struct npu2_dev *ndev = pvd->data;
	struct npu2_bar *ntl_npu_bar, *genid_npu_bar;
	bool enabled;

	if (!write)
		return OPAL_PARTIAL;

	if (offset != PCI_CFG_CMD)
		return OPAL_PARAMETER;
	if (size != 1 && size != 2 && size != 4)
		return OPAL_PARAMETER;

	/*
	 * Enable or disable NTL and GENID BAR. Two bricks share
	 * one GENID BAR, which is exposed via the first brick.
	 */
	enabled = !!(*data & PCI_CFG_CMD_MEM_EN);
	ntl_npu_bar = &ndev->bars[0].npu2_bar;
	genid_npu_bar = &ndev->bars[1].npu2_bar;

	ntl_npu_bar->flags = SETFIELD(NPU2_BAR_FLAG_ENABLED, ntl_npu_bar->flags, enabled);
	npu2_write_bar(ndev->npu, ntl_npu_bar, 0, 0);

	/*
	 * Enable/disable the GENID BAR. Two bricks share one GENID
	 * BAR which is exposed via the first brick so we need to
	 * track the enables separately.
	 */
	if (NPU2DEV_BRICK(ndev))
		genid_npu_bar->flags = SETFIELD(NPU2_BAR_FLAG_ENABLED1, genid_npu_bar->flags,
						enabled);
	else
		genid_npu_bar->flags = SETFIELD(NPU2_BAR_FLAG_ENABLED0, genid_npu_bar->flags,
						enabled);

	/* Enable the BAR if either device requests it enabled, otherwise disable it */
	genid_npu_bar->flags = SETFIELD(NPU2_BAR_FLAG_ENABLED, genid_npu_bar->flags,
					!!(genid_npu_bar->flags & (NPU2_BAR_FLAG_ENABLED0 |
								   NPU2_BAR_FLAG_ENABLED1)));
	npu2_write_bar(ndev->npu, genid_npu_bar, 0, 0);

	return OPAL_PARTIAL;
}

static int64_t npu2_cfg_read_bar(struct npu2_dev *dev __unused,
				 struct pci_cfg_reg_filter *pcrf,
				 uint32_t offset, uint32_t size,
				 uint32_t *data)
{
	struct npu2_pcie_bar *bar = (struct npu2_pcie_bar *) pcrf->data;

	if (!(bar->flags & NPU2_PCIE_BAR_FLAG_TRAPPED))
		return OPAL_PARTIAL;

	if ((size != 4) ||
	    (offset != pcrf->start && offset != pcrf->start + 4))
		return OPAL_PARAMETER;

	if (bar->flags & NPU2_PCIE_BAR_FLAG_SIZE_HI)
		*data = bar->npu2_bar.size >> 32;
	else
		*data = bar->npu2_bar.size;
	bar->flags &= ~(NPU2_PCIE_BAR_FLAG_TRAPPED | NPU2_PCIE_BAR_FLAG_SIZE_HI);

	return OPAL_SUCCESS;
}

static int64_t npu2_cfg_write_bar(struct npu2_dev *dev,
				  struct pci_cfg_reg_filter *pcrf,
				  uint32_t offset, uint32_t size,
				  uint32_t data)
{
	struct npu2_pcie_bar *bar = (struct npu2_pcie_bar *) pcrf->data;
	struct npu2_bar old_bar, *npu2_bar = &bar->npu2_bar;

	if ((size != 4) ||
	    (offset != pcrf->start && offset != pcrf->start + 4))
		return OPAL_PARAMETER;

	/* Return BAR size on next read */
	if (data == 0xffffffff) {
		bar->flags |= NPU2_PCIE_BAR_FLAG_TRAPPED;
		if (offset == pcrf->start + 4)
			bar->flags |= NPU2_PCIE_BAR_FLAG_SIZE_HI;

		return OPAL_SUCCESS;
	}

	if (offset == pcrf->start) {
		npu2_bar->base &= 0xffffffff00000000UL;
		npu2_bar->base |= (data & 0xfffffff0);
	} else {
		npu2_bar->base &= 0x00000000ffffffffUL;
		npu2_bar->base |= ((uint64_t)data << 32);

		if (NPU2_REG(npu2_bar->reg) == NPU2_GENID_BAR && NPU2DEV_BRICK(dev))
			npu2_bar->base -= 0x10000;

		old_bar.reg = npu2_bar->reg;
		npu2_read_bar(dev->npu, &old_bar);

		/* Only allow changing the base address if the BAR is not enabled */
		if ((npu2_bar->flags & NPU2_BAR_FLAG_ENABLED) &&
		    (npu2_bar->base != old_bar.base)) {
			npu2_bar->base = old_bar.base;
			return OPAL_HARDWARE;
		}

		npu2_write_bar(dev->npu, &bar->npu2_bar, 0, 0);
	}

	/* To update the config cache */
	return OPAL_PARTIAL;
}

static int64_t npu2_dev_cfg_bar(void *dev, struct pci_cfg_reg_filter *pcrf,
				uint32_t offset, uint32_t len, uint32_t *data,
				bool write)
{
	struct pci_virt_device *pvd = dev;
	struct npu2_dev *ndev = (struct npu2_dev *) pvd->data;

	if (write)
		return npu2_cfg_write_bar(ndev, pcrf, offset, len, *data);

	return npu2_cfg_read_bar(ndev, pcrf, offset, len, data);
}

static int64_t npu2_dev_cfg_exp_devcap(void *dev,
		struct pci_cfg_reg_filter *pcrf __unused,
		uint32_t offset, uint32_t size,
		uint32_t *data, bool write)
{
	struct pci_virt_device *pvd = dev;
	struct npu2_dev *ndev = pvd->data;
	int rc;

	assert(write);

	if ((size != 2) || (offset & 1)) {
		/* Short config writes are not supported */
		prlog(PR_ERR, "NPU%d: Unsupported write to pcie control register\n",
		      ndev->nvlink.phb->opal_id);
		return OPAL_PARAMETER;
	}

	if (*data & PCICAP_EXP_DEVCTL_FUNC_RESET)
		npu2_dev_procedure_reset(ndev);

	rc = purge_l2_l3_caches();
	if (rc)
		return rc;

	return OPAL_PARTIAL;
}

#define NPU2_CFG_READ(size, type)					\
static int64_t npu2_cfg_read##size(struct phb *phb, uint32_t bdfn,	\
				   uint32_t offset, type *data)		\
{									\
	uint32_t val;							\
	int64_t ret;							\
									\
	ret = pci_virt_cfg_read(phb, bdfn, offset,			\
				sizeof(*data), &val);			\
	*data = (type)val;						\
        return ret;							\
}
#define NPU2_CFG_WRITE(size, type)					\
static int64_t npu2_cfg_write##size(struct phb *phb, uint32_t bdfn,	\
				    uint32_t offset, type data)		\
{									\
	uint32_t val = data;						\
	int64_t ret;							\
									\
	ret = pci_virt_cfg_write(phb, bdfn, offset,			\
				 sizeof(data), val);			\
	return ret;							\
}

NPU2_CFG_READ(8, u8);
NPU2_CFG_READ(16, u16);
NPU2_CFG_READ(32, u32);
NPU2_CFG_WRITE(8, u8);
NPU2_CFG_WRITE(16, u16);
NPU2_CFG_WRITE(32, u32);

static int __npu2_dev_bind_pci_dev(struct phb *phb __unused,
				  struct pci_device *pd,
				  void *data)
{
	struct npu2_dev *dev = data;
	struct dt_node *pci_dt_node;
	char *pcislot;

	/* Ignore non-nvidia PCI devices */
	if ((pd->vdid & 0xffff) != 0x10de)
		return 0;

	/* Find the PCI device's slot location */
	for (pci_dt_node = pd->dn;
	     pci_dt_node && !dt_find_property(pci_dt_node, "ibm,loc-code");
	     pci_dt_node = pci_dt_node->parent);

	if (!pci_dt_node)
		return 0;

	pcislot = (char *)dt_prop_get(pci_dt_node, "ibm,loc-code");

	NPU2DEVDBG(dev, "Comparing GPU '%s' and NPU2 '%s'\n",
		   pcislot, dev->nvlink.slot_label);

	if (streq(pcislot, dev->nvlink.slot_label))
		return 1;

	return 0;
}

static int64_t npu2_gpu_bridge_sec_bus_reset(void *dev,
		struct pci_cfg_reg_filter *pcrf __unused,
		uint32_t offset, uint32_t len,
		uint32_t *data, bool write)
{
	struct pci_device *pd = dev;
	struct pci_device *gpu;
	struct phb *npphb;
	struct npu2 *npu;
	struct dt_node *np;
	struct npu2_dev	*ndev;
	int i;

	assert(write);

	if ((len != 2) || (offset & 1)) {
		/* Short config writes are not supported */
		PCIERR(pd->phb, pd->bdfn,
		       "Unsupported write to bridge control register\n");
		return OPAL_PARAMETER;
	}

	gpu = list_top(&pd->children, struct pci_device, link);
	if (gpu && (*data & PCI_CFG_BRCTL_SECONDARY_RESET)) {
		int64_t rc;

		dt_for_each_compatible(dt_root, np, "ibm,power9-npu-pciex") {
			npphb = pci_get_phb(dt_prop_get_cell(np,
					"ibm,opal-phbid", 1));
			if (!npphb || npphb->phb_type != phb_type_npu_v2)
				continue;

			npu = phb_to_npu2_nvlink(npphb);
			for (i = 0; i < npu->total_devices; ++i) {
				ndev = &npu->devices[i];
				if (ndev->nvlink.pd == gpu)
					npu2_dev_procedure_reset(ndev);
			}
		}

		rc = purge_l2_l3_caches();
		if (rc)
			return rc;
	}

	return OPAL_PARTIAL;
}

static void npu2_dev_bind_pci_dev(struct npu2_dev *dev)
{
	struct phb *phb;
	uint32_t i;

	if (dev->nvlink.pd)
		return;

	for (i = 0; i < 64; i++) {
		if (dev->npu->phb_nvlink.opal_id == i)
			continue;

		phb = pci_get_phb(i);
		if (!phb)
			continue;

		dev->nvlink.pd = pci_walk_dev(phb, NULL, __npu2_dev_bind_pci_dev, dev);
		if (dev->nvlink.pd) {
			dev->nvlink.phb = phb;
			/* Found the device, set the bit in config space */
			npu2_set_link_flag(dev, NPU2_DEV_PCI_LINKED);

			/*
			 * We define a custom sec bus reset handler for a slot
			 * with an NVLink-connected GPU to prevent HMIs which
			 * will otherwise happen if we reset GPU before
			 * resetting NVLinks.
			 */
			if (dev->nvlink.pd->parent &&
			    dev->nvlink.pd->parent->slot)
				pci_add_cfg_reg_filter(dev->nvlink.pd->parent,
						PCI_CFG_BRCTL, 2,
						PCI_REG_FLAG_WRITE,
						npu2_gpu_bridge_sec_bus_reset);
			return;
		}
	}

	NPU2DEVINF(dev, "No PCI device found for slot '%s'\n",
		   dev->nvlink.slot_label);
}

static struct lock pci_npu_phandle_lock = LOCK_UNLOCKED;

static void npu2_append_phandle(struct dt_node *dn,
				u32 phandle)
{
	struct dt_property *prop;
	uint32_t *npu_phandles;
	size_t len;

	/*
	 * Use a lock to make sure no one else has a reference to an
	 * ibm,npu property (this assumes this is the only function
	 * that holds a reference to it)
	 */
	lock(&pci_npu_phandle_lock);

	/* This function shouldn't be called unless ibm,npu exists */
	prop = (struct dt_property *)dt_require_property(dn, "ibm,npu", -1);

	/* Need to append to the properties */
	len = prop->len + sizeof(*npu_phandles);
	dt_resize_property(&prop, len);

	npu_phandles = (uint32_t *)prop->prop;
	npu_phandles[len / sizeof(*npu_phandles) - 1] = phandle;
	unlock(&pci_npu_phandle_lock);
}

static struct dt_node *npu2_create_memory_dn(uint64_t addr, uint64_t size)
{
	struct dt_node *mem;
	static u32 chip_id = 255;

	mem = dt_find_by_name_addr(dt_root, "memory", addr);
	if (mem)
		return mem;

	mem = dt_new_addr(dt_root, "memory", addr);
	if (!mem)
		return NULL;
	dt_add_property_string(mem, "device_type", "memory");
	dt_add_property_string(mem, "compatible", "ibm,coherent-device-memory");
	dt_add_property_u64s(mem, "reg", addr, size);
	dt_add_property_cells(mem, "ibm,chip-id", chip_id);
	dt_add_property_u64s(mem, "linux,usable-memory", addr, 0);
	dt_add_property_cells(mem, "ibm,associativity", 4, chip_id, chip_id, chip_id, chip_id);
	chip_id--;

	assert(chip_id);
	return mem;
}

/* There are potentially multiple links per GPU, so lookup the GPU memory based
 * on bdfn. */
static void npu2_get_gpu_base(struct npu2_dev *ndev, uint64_t *addr, uint64_t *size)
{
	struct npu2 *p = ndev->npu;
	int group;

	group = PCI_DEV(ndev->bdfn);
	phys_map_get(ndev->npu->chip_id, p->gpu_map_type, group, addr, size);
}

static void npu2_dn_fixup_gmb(struct dt_node *pd_dn, struct npu2_dev *ndev)
{
	uint64_t gpu_base, gpu_size, gta;
	struct dt_node *mem_dn;

	npu2_get_gpu_base(ndev, &gpu_base, &gpu_size);
	mem_dn = npu2_create_memory_dn(gpu_base, gpu_size);
	assert(mem_dn);
	dt_add_property_cells(pd_dn, "memory-region", mem_dn->phandle);

	/* Coral mode address compression. This is documented in Figure 3.5
	 * "P9->GPU RA Compression (Coral) of the NPU2 workbook". */
	gta  = ((gpu_base >> 42) & 0x1) << 42;
	gta |= ((gpu_base >> 45) & 0x3) << 43;
	gta |= ((gpu_base >> 49) & 0x3) << 45;
	gta |= gpu_base & ((1UL << 43) - 1);

	dt_add_property_u64s(pd_dn, "ibm,device-tgt-addr", gta);
}

static int npu2_assign_gmb(struct npu2_dev *ndev)
{
	struct npu2 *p = ndev->npu;
	int peers, mode;
	uint32_t bdfn;
	uint64_t base, size, reg, val, gmb;

	/* Need to work out number of link peers. This amount to
	 * working out the maximum function number. So work start at
	 * the highest bdfn (fn = 6) and count back until we find a
	 * npu2_dev. */
	for (bdfn = (ndev->bdfn & ~0x7) | NPU2_LINKS_PER_CHIP;
	     PCI_FUNC(bdfn) != 0x7; bdfn = (bdfn & ~0x7) | (PCI_FUNC(bdfn) - 1))
		if (npu2_bdf_to_dev(p, bdfn))
			break;
	peers = PCI_FUNC(bdfn);

	npu2_get_gpu_base(ndev, &base, &size);

	NPU2DBG(p, "Setting BAR region dt:%llx\n", base);
	val = SETFIELD(NPU2_MEM_BAR_EN, 0ULL, 1);
	val = SETFIELD(NPU2_MEM_BAR_SEL_MEM, val, base >> (63-14));
	val = SETFIELD(NPU2_MEM_BAR_GROUP, val, base >> (63-18));
	val = SETFIELD(NPU2_MEM_BAR_CHIP, val, base >> (63-21));
	val = SETFIELD(NPU2_MEM_BAR_NODE_ADDR, val, base >> (63-33));
	val = SETFIELD(NPU2_MEM_BAR_POISON, val, 1);
	val = SETFIELD(NPU2_MEM_BAR_GRANULE, val, 0);

	/* We don't know how much memory the GPU has, so we may as well just
	 * pass the whole aperture through at this point. */
	val = SETFIELD(NPU2_MEM_BAR_BAR_SIZE, val, ilog2(size >> 30));

	switch (peers) {
	case 0:
		mode = 0;
		break;
	case 1:
		mode = 1;
		break;
	case 2:
		mode = 3;
		break;
	case 3:
		mode = 6;
		break;
	case 5:
		mode = 10;
		break;
	default:
		/* Hardware does not support this configuration */
		assert(0);
	}

	mode += PCI_FUNC(ndev->bdfn);
	val = SETFIELD(NPU2_MEM_BAR_MODE, val, mode);

	gmb = NPU2_GPU0_MEM_BAR;
	if (NPU2DEV_BRICK(ndev))
		gmb = NPU2_GPU1_MEM_BAR;

	reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_0 + NPU2DEV_STACK(ndev),
			      NPU2_BLOCK_SM_0, gmb);

	npu2_write(p, reg, val);
	reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_0 + NPU2DEV_STACK(ndev),
			      NPU2_BLOCK_SM_1, gmb);
	npu2_write(p, reg, val);
	reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_0 + NPU2DEV_STACK(ndev),
			      NPU2_BLOCK_SM_2, gmb);
	npu2_write(p, reg, val);
	reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_0 + NPU2DEV_STACK(ndev),
			      NPU2_BLOCK_SM_3, gmb);
	npu2_write(p, reg, val);

	return 0;
}

static int npu2_dn_fixup(struct phb *phb,
			 struct pci_device *pd,
			 void *data __unused)
{
	struct npu2 *p = phb_to_npu2_nvlink(phb);
	struct npu2_dev *dev;
	uint32_t speed;
	const char *label;

	dev = npu2_bdf_to_dev(p, pd->bdfn);
	assert(dev);
	if (dev->nvlink.phb || dev->nvlink.pd)
		return 0;

	npu2_assign_gmb(dev);
	npu2_dn_fixup_gmb(pd->dn, dev);
	dt_add_property_cells(pd->dn, "ibm,nvlink", dev->dt_node->phandle);

	/*
	 * NVLink supports multiple speeds and device drivers need to know what
	 * speed has been set by firmware. Hostboot does the inits that set the
	 * link speed and tell us via HDAT and we need to copy that from the
	 * link node.
	 */
	speed = dt_prop_get_u32_def(dev->dt_node, "nvidia,link-speed", 0xff);
	if (speed != 0xff)
		dt_add_property_cells(pd->dn, "ibm,nvlink-speed", speed);

	/*
	 * NPU2 devices have a slot label that indicates which GPU slot
	 * this NPU is connected to. Add a location code to the NVlink
	 * device node based on the slot label.
	 */
	label = dt_prop_get_def(dev->dt_node, "ibm,slot-label", NULL);
	if (!label) {
		/**
		 * @fwts-label NPUNoPHBSlotLabel
		 * @fwts-advice No GPU/NPU2 slot information was found.
		 * NVLink2 functionality will not work.
		 */
		prlog(PR_ERR, "NPU: Cannot find GPU slot information\n");
		return 0;
	}
	dt_add_property_string(pd->dn, "ibm,loc-code", label);

	dev->nvlink.slot_label = label;

	/*
	 * Bind the emulated PCI device with the real one, which can't
	 * be done until the PCI devices are populated. Once the real
	 * PCI device is identified, we also need fix the device-tree
	 * for it
	 */
	npu2_dev_bind_pci_dev(dev);
	if (dev->nvlink.phb && dev->nvlink.pd && dev->nvlink.pd->dn) {
		if (dt_find_property(dev->nvlink.pd->dn, "ibm,npu"))
			npu2_append_phandle(dev->nvlink.pd->dn, pd->dn->phandle);
		else
			dt_add_property_cells(dev->nvlink.pd->dn, "ibm,npu", pd->dn->phandle);

		dt_add_property_cells(pd->dn, "ibm,gpu", dev->nvlink.pd->dn->phandle);
		dev->nvlink.gpu_bdfn = dev->nvlink.pd->bdfn;
	}

	return 0;
}

static int npu2_links_per_gpu(struct phb *phb,
			      struct pci_device *pd,
			      void *data)
{
	struct npu2 *p = phb_to_npu2_nvlink(phb);
	struct npu2_dev *dev;
	int *nlinks = (int *)data;

	dev = npu2_bdf_to_dev(p, pd->bdfn);
	assert(dev);

	if (dev->nvlink.phb && dev->nvlink.pd && dev->nvlink.pd->dn) {
		const struct dt_property *prop;
		int n;

		/* The link count is the number of phandles in "ibm,npu" */
		prop = dt_find_property(dev->nvlink.pd->dn, "ibm,npu");
		if (!prop)
			return 0;

		/* Count could vary by gpu, so find the max */
		n = prop->len / sizeof(uint32_t);
		if (n > *nlinks)
			*nlinks = n;
	}

	return 0;
}

static void npu2_phb_fixup_scominit(struct dt_node *dn, int links_per_gpu)
{
	uint32_t gcid = dt_get_chip_id(dn);
	uint64_t val, mask;

	/*
	 * MRBSP settings for 2- and 3-link GPU systems. These can improve
	 * GPU peer-to-peer fully ordered write performance.
	 */
	if (links_per_gpu == 3) {
		val = PPC_BIT(30) | PPC_BIT(34) | PPC_BIT(36) | PPC_BIT(37) |
		      PPC_BIT(44) | PPC_BIT(45);
		mask = PPC_BITMASK(28,39) | PPC_BITMASK(44,47);
	} else if (links_per_gpu == 2) {
		val = PPC_BIT(46) | PPC_BIT(47);
		mask = PPC_BITMASK(44,47);
	} else
		return;

	xscom_write_mask(gcid, 0x50110c0, val, mask);
	xscom_write_mask(gcid, 0x50112c0, val, mask);
	xscom_write_mask(gcid, 0x50114c0, val, mask);
}

static void npu2_phb_final_fixup(struct phb *phb)
{
	int links_per_gpu = 0;
	struct dt_node *np;

	pci_walk_dev(phb, NULL, npu2_dn_fixup, NULL);

	/*
	 * Now that the emulated devices are bound to the real ones, we can
	 * determine links_per_gpu and do some final init.
	 */
	pci_walk_dev(phb, NULL, npu2_links_per_gpu, &links_per_gpu);
	dt_for_each_compatible(dt_root, np, "ibm,power9-npu")
		npu2_phb_fixup_scominit(np, links_per_gpu);
}

static void npu2_init_ioda_cache(struct npu2 *p)
{
	/* TVT */
	memset(p->tve_cache, 0, sizeof(p->tve_cache));
}

static int64_t npu2_ioda_reset(struct phb *phb, bool purge)
{
	struct npu2 *p = phb_to_npu2_nvlink(phb);
	uint32_t i;

	if (purge) {
		NPU2DBG(p, "Purging all IODA tables...\n");
		npu2_init_ioda_cache(p);
	}

	/* TVT */
	npu2_ioda_sel(p, NPU2_ATS_IODA_TBL_TVT, 0, true);
	for (i = 0; i < ARRAY_SIZE(p->tve_cache); i++)
		out_be64(p->regs + NPU2_ATS_IODA_DATA, p->tve_cache[i]);

	return OPAL_SUCCESS;
}

static void npu2_write_mcd(struct npu2 *p, uint64_t pcb_addr, uint64_t addr,
			   uint64_t size)
{
	uint64_t val;

	NPU2DBG(p, "Setting MCD addr:%llx\n", pcb_addr);
	assert(is_pow2(size));

	val = MCD_BANK_CN_VALID;
	val = SETFIELD(MCD_BANK_CN_SIZE, val, (size >> 25) - 1);
	val = SETFIELD(MCD_BANK_CN_ADDR, val, addr >> 25);
	xscom_write(p->chip_id, pcb_addr, val);
}

static void npu2_mcd_init(struct npu2 *p)
{
	int i;
	uint64_t size, addr, gpu_min_addr, gpu_max_addr, total_size;

	/* Init memory cache directory (MCD) registers. */
	phys_map_get(p->chip_id, p->gpu_map_type, NPU2_LINKS_PER_CHIP - 1,
			&gpu_min_addr, NULL);
	phys_map_get(p->chip_id, p->gpu_map_type, 0, &gpu_max_addr, &size);
	gpu_max_addr += size;

	/* We assume GPU memory is contiguous from the first possible GPU to the
	 * last and that the size is the same so best to check that. */
	for (i = 0; i < NPU2_LINKS_PER_CHIP; i++) {
		uint64_t tmp;
		phys_map_get(p->chip_id, p->gpu_map_type, i, &addr, &tmp);
		assert((addr >= gpu_min_addr) && (addr + tmp <= gpu_max_addr));
		assert(tmp == size);
	}

	/* We have two MCDs, so if neccessary we can split the region covered
	 * across both if total_size is not a power of two. */
	total_size = gpu_max_addr - gpu_min_addr;
	size = 1ull << ilog2(total_size);

	/* Allocate the biggest chunk first as we assume gpu_max_addr has the
	 * highest alignment. */
	addr = gpu_max_addr - size;
	npu2_write_mcd(p, MCD0_BANK0_CN3, addr, size);
	total_size -= size;
	if (total_size) {
	/* total_size was not a power of two, but the remainder should
	 * be if all GPUs were assigned the same size. */
		assert(is_pow2(total_size));
		size = 1ull << ilog2(total_size);
		addr -= size;
		assert(addr <= gpu_min_addr);
		npu2_write_mcd(p, MCD1_BANK0_CN3, addr, size);
	}
}

static void npu2_hw_init(struct npu2 *p)
{
	uint64_t reg, val;
	int s, b;

	npu2_ioda_reset(&p->phb_nvlink, false);

	/* Enable XTS retry mode */
	val = npu2_read(p, NPU2_XTS_CFG);
	npu2_write(p, NPU2_XTS_CFG, val | NPU2_XTS_CFG_MMIOSD | NPU2_XTS_CFG_TRY_ATR_RO);

	val = npu2_read(p, NPU2_XTS_CFG2);
	npu2_write(p, NPU2_XTS_CFG2, val | NPU2_XTS_CFG2_NO_FLUSH_ENA);

	/*
	 * There are three different ways we configure the MCD and memory map.
	 * 1) Old way
	 *    Skiboot configures the MCD and puts GPUs at 4TB and below
	 * 2) New way with MCD
	 *    Hostboot configures the MCD and skiboot puts GPU at 4TB and above
	 * 3) New way without MCD
	 *    No one configures the MCD and skiboot puts GPU at 4TB and below
	 *
	 * 1) Will go away evenutally as it's a configuration that can
	 *    cause an xstop or data integrity problems. We are keeping
	 *    it around to support existing hostboot. Print error
	 *    message if used.
	 * 2) Is for smaller memory configurations and will be used
	 *    initially for GPUs on Witherspoon. Supports only to
	 *    512GB of memory and 4 GPUs per socket.
	 * 3) Is for fully populated configurations of 4TB of memory
	 *    and 6GPUs per socket. May have performance impacts.
	 *
	 * The different configurations can be detected via the following scoms:
	 * 1) 0x5011c0c bit 2 = 1, 0x5011c0a bits 42:48 = 0
	 * 2) 0x5011c0c bit 2 = 1, 0x5011c0a bits 42:48 = 7
	 * 3) 0x5011c0c bit 2 = 0, 0x5011c0a bits 42:48 = 0
	 */

	/* Get 0x05011c0c bit 2 = 1 */
	xscom_read(p->chip_id, PB_CENT_HP_MODE_CURR, &val);
	if ((val & PB_CFG_CHG_RATE_GP_MASTER) != 0) {
		/* Get 0x05011c0a bits 42:48 */
		xscom_read(p->chip_id, PB_CENT_MODE, &val);
		if (GETFIELD(PB_CFG_CHIP_ADDR_EXTENSION_MASK_CENT, val) == 0) {
			/* 1) */
			NPU2DBG(p, "Using old memory map + MCD enabled in skiboot\n");
			NPU2ERR(p, "!!! Old firmware detected. Update hostboot for new MCD mapping !!!\n");
			p->gpu_map_type = GPU_MEM_4T_DOWN;
			npu2_mcd_init(p);
		} else if (GETFIELD(PB_CFG_CHIP_ADDR_EXTENSION_MASK_CENT, val) == 7) {
			/* 2) */
			NPU2DBG(p, "Using small memory map + MCD enabled\n");
			p->gpu_map_type = GPU_MEM_4T_UP;
		} else
			NPU2ERR(p, "!!! Unsupported NPU2 configuration. "
				"0x%llx!!!\n", val);
	} else {
		/* 3) */
		NPU2DBG(p, "Using large memory map + MCD disabled\n");
		p->gpu_map_type = GPU_MEM_4T_DOWN;
	}

	/* Static initialization of every relaxed-ordering cfg[2] register */
	val = NPU2_RELAXED_ORDERING_CMD_CL_DMA_W |
	      NPU2_RELAXED_ORDERING_CMD_CL_DMA_W_HP |
	      NPU2_RELAXED_ORDERING_CMD_CL_DMA_INJ |
	      NPU2_RELAXED_ORDERING_CMD_PR_DMA_INJ |
	      NPU2_RELAXED_ORDERING_CMD_DMA_PR_W |
	      NPU2_RELAXED_ORDERING_CMD_CL_RD_NC_F0 |
	      NPU2_RELAXED_ORDERING_SOURCE4_RDENA;

	for (s = NPU2_STACK_STCK_0; s <= NPU2_STACK_STCK_2; s++) {
		for (b = NPU2_BLOCK_SM_0; b <= NPU2_BLOCK_SM_3; b++) {
			reg = NPU2_REG_OFFSET(s, b, NPU2_RELAXED_ORDERING_CFG(2));
			npu2_write(p, reg, val);
		}
	}
}

static int64_t npu2_map_pe_dma_window_real(struct phb *phb,
					   uint64_t pe_num,
					   uint16_t window_id,
					   uint64_t pci_start_addr __unused,
					   uint64_t pci_mem_size __unused)
{
	struct npu2 *p = phb_to_npu2_nvlink(phb);
	uint64_t tve;

	/* Sanity check. Each PE has one corresponding TVE */
	if (pe_num >= NPU2_MAX_PE_NUM ||
	    window_id != pe_num)
		return OPAL_PARAMETER;

	if (pci_mem_size) {
		/* GPUs need to be able to access the MMIO memory space as well.
		 * On POWER9 this is above the top of ram so disable the TVT
		 * range check allowing access to all memory addresses. */
		tve = 0;
	} else {
		/* Disable */
		tve = PPC_BIT(51);
	}

	npu2_ioda_sel(p, NPU2_ATS_IODA_TBL_TVT, window_id, false);
	out_be64(p->regs + NPU2_ATS_IODA_DATA, tve);
	p->tve_cache[window_id] = tve;

	return OPAL_SUCCESS;
}

static int64_t npu2_map_pe_dma_window(struct phb *phb,
				      uint64_t pe_num,
				      uint16_t window_id,
				      uint16_t tce_levels,
				      uint64_t tce_table_addr,
				      uint64_t tce_table_size,
				      uint64_t tce_page_size)
{
	struct npu2 *p = phb_to_npu2_nvlink(phb);
	uint64_t tts_encoded;
	uint64_t data64 = 0;

	/* Sanity check. Each PE has one corresponding TVE */
	if (pe_num >= NPU2_MAX_PE_NUM ||
	    window_id != pe_num)
		return OPAL_PARAMETER;

	/*
	 * Special condition, zero TCE table size used to disable
	 * the TVE.
	 */
	if (!tce_table_size) {
		npu2_ioda_sel(p, NPU2_ATS_IODA_TBL_TVT, window_id, false);
		out_be64(p->regs + NPU2_ATS_IODA_DATA, 0ul);
		p->tve_cache[window_id] = 0ul;
		return OPAL_SUCCESS;
	}

	/* Additional arguments validation */
	if (tce_levels < 1 ||
	    tce_levels > 4 ||
	    !is_pow2(tce_table_size) ||
	    tce_table_size < 0x1000)
		return OPAL_PARAMETER;

	/* TCE table size */
	data64 = SETFIELD(NPU2_ATS_IODA_TBL_TVT_TTA, 0ul, tce_table_addr >> 12);
	tts_encoded = ilog2(tce_table_size) - 11;
	if (tts_encoded > 39)
		return OPAL_PARAMETER;
	data64 = SETFIELD(NPU2_ATS_IODA_TBL_TVT_SIZE, data64, tts_encoded);

	/* TCE page size */
	switch (tce_page_size) {
	case 0x10000:		/* 64K */
		data64 = SETFIELD(NPU2_ATS_IODA_TBL_TVT_PSIZE, data64, 5);
		break;
	case 0x1000000:		/* 16M */
		data64 = SETFIELD(NPU2_ATS_IODA_TBL_TVT_PSIZE, data64, 13);
		break;
	case 0x10000000:	/* 256M */
		data64 = SETFIELD(NPU2_ATS_IODA_TBL_TVT_PSIZE, data64, 17);
		break;
	case 0x1000:		/* 4K */
	default:
		data64 = SETFIELD(NPU2_ATS_IODA_TBL_TVT_PSIZE, data64, 1);
	}

	/* Number of levels */
	data64 = SETFIELD(NPU2_ATS_IODA_TBL_TVT_LEVEL, data64, tce_levels - 1);

	/* Update to hardware */
	npu2_ioda_sel(p, NPU2_ATS_IODA_TBL_TVT, window_id, false);
	out_be64(p->regs + NPU2_ATS_IODA_DATA, data64);
	p->tve_cache[window_id] = data64;

	return OPAL_SUCCESS;
}

static int64_t npu2_set_pe(struct phb *phb,
			   uint64_t pe_num,
			   uint64_t bdfn,
			   uint8_t bcompare,
			   uint8_t dcompare,
			   uint8_t fcompare,
			   uint8_t action)
{
	struct npu2 *p;
	struct npu2_dev *dev;
	uint64_t reg, val;

	/* Sanity check */
	if (action != OPAL_MAP_PE && action != OPAL_UNMAP_PE)
		return OPAL_PARAMETER;
	if (pe_num >= NPU2_MAX_PE_NUM)
		return OPAL_PARAMETER;
	if (bdfn >> 8)
		return OPAL_PARAMETER;
	if (bcompare != OpalPciBusAll ||
	    dcompare != OPAL_COMPARE_RID_DEVICE_NUMBER ||
	    fcompare != OPAL_COMPARE_RID_FUNCTION_NUMBER)
		return OPAL_UNSUPPORTED;
	if (phb->phb_type != phb_type_npu_v2)
		return OPAL_PARAMETER;

	p = phb_to_npu2_nvlink(phb);
	if (!p)
		return OPAL_PARAMETER;

	dev = npu2_bdf_to_dev(p, bdfn);
	if (!dev)
		return OPAL_PARAMETER;

	val = NPU2_CQ_BRICK_BDF2PE_MAP_ENABLE;
	val = SETFIELD(NPU2_CQ_BRICK_BDF2PE_MAP_PE, val, pe_num);
	val = SETFIELD(NPU2_CQ_BRICK_BDF2PE_MAP_BDF, val, dev->nvlink.gpu_bdfn);

	if (!NPU2DEV_BRICK(dev))
		reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_0 + dev->brick_index/2,
				      NPU2_BLOCK_CTL, NPU2_CQ_BRICK0_BDF2PE_MAP0);
	else
		reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_0 + dev->brick_index/2,
				      NPU2_BLOCK_CTL, NPU2_CQ_BRICK1_BDF2PE_MAP0);

	npu2_write(p, reg, val);
	val = NPU2_MISC_BRICK_BDF2PE_MAP_ENABLE;
	val = SETFIELD(NPU2_MISC_BRICK_BDF2PE_MAP_PE, val, pe_num);
	val = SETFIELD(NPU2_MISC_BRICK_BDF2PE_MAP_BDF, val, dev->nvlink.gpu_bdfn);
	reg = NPU2_REG_OFFSET(NPU2_STACK_MISC, NPU2_BLOCK_MISC,
			      NPU2_MISC_BRICK0_BDF2PE_MAP0 + (dev->brick_index * 0x18));
	npu2_write(p, reg, val);

	return OPAL_SUCCESS;
}

static int64_t npu2_get_link_state(struct pci_slot *slot __unused, uint8_t *val)
{
	/*
	 * As we're emulating all PCI stuff, the link bandwidth
	 * isn't big deal anyway.
	 */
	*val = OPAL_SHPC_LINK_UP_x1;
	return OPAL_SUCCESS;
}

static int64_t npu2_get_power_state(struct pci_slot *slot __unused, uint8_t *val)
{
	*val = PCI_SLOT_POWER_ON;
	return OPAL_SUCCESS;
}

static int64_t npu2_hreset(struct pci_slot *slot __unused)
{
	struct npu2 *p;
	int i;
	struct npu2_dev *ndev;

	p = phb_to_npu2_nvlink(slot->phb);
	NPU2INF(p, "Hreset PHB state\n");

	for (i = 0; i < p->total_devices; i++) {
		ndev = &p->devices[i];
		if (ndev) {
			NPU2DEVINF(ndev, "Resetting device\n");
			reset_ntl(ndev);
		}
	}
	return purge_l2_l3_caches();
}

static int64_t npu2_freset(struct pci_slot *slot __unused)
{
	return OPAL_SUCCESS;
}

static int64_t npu2_creset(struct pci_slot *slot)
{
	struct npu2 *p;
	int i;
	struct npu2_dev *ndev;

	p = phb_to_npu2_nvlink(slot->phb);
	NPU2INF(p, "Creset PHB state\n");

	for (i = 0; i < p->total_devices; i++) {
		ndev = &p->devices[i];
		if (ndev) {
			NPU2DEVINF(ndev, "Resetting device\n");
			reset_ntl(ndev);
		}
	}
	return OPAL_SUCCESS;
}

static struct pci_slot *npu2_slot_create(struct phb *phb)
{
	struct pci_slot *slot;

	slot = pci_slot_alloc(phb, NULL);
	if (!slot)
		return slot;

	/* Elementary functions */
	slot->ops.get_presence_state  = NULL;
	slot->ops.get_link_state      = npu2_get_link_state;
	slot->ops.get_power_state     = npu2_get_power_state;
	slot->ops.get_attention_state = NULL;
	slot->ops.get_latch_state     = NULL;
	slot->ops.set_power_state     = NULL;
	slot->ops.set_attention_state = NULL;

	slot->ops.prepare_link_change = NULL;
	slot->ops.poll_link           = NULL;
	slot->ops.hreset              = npu2_hreset;
	slot->ops.freset              = npu2_freset;
	slot->ops.creset              = npu2_creset;

	return slot;
}

int64_t npu2_freeze_status(struct phb *phb __unused,
			   uint64_t pe_number __unused,
			   uint8_t *freeze_state,
			   uint16_t *pci_error_type,
			   uint16_t *severity)
{
	/*
	 * FIXME: When it's called by skiboot PCI config accessor,
	 * the PE number is fixed to 0, which is incorrect. We need
	 * introduce another PHB callback to translate it. For now,
	 * it keeps the skiboot PCI enumeration going.
	 */
	*freeze_state = OPAL_EEH_STOPPED_NOT_FROZEN;
	*pci_error_type = OPAL_EEH_NO_ERROR;
	if (severity)
		*severity = OPAL_EEH_SEV_NO_ERROR;

	return OPAL_SUCCESS;
}

static int64_t npu2_eeh_next_error(struct phb *phb,
				   uint64_t *first_frozen_pe,
				   uint16_t *pci_error_type,
				   uint16_t *severity)
{
	struct npu2 *p = phb_to_npu2_nvlink(phb);
	int i;
	uint64_t result = 0;

	if (!first_frozen_pe || !pci_error_type || !severity)
		return OPAL_PARAMETER;

	*first_frozen_pe = -1;
	*pci_error_type = OPAL_EEH_NO_ERROR;
	*severity = OPAL_EEH_SEV_NO_ERROR;

	for (i = 0; i < NPU2_MAX_PE_NUM; i++) {
		result = npu2_read(p, NPU2_MISC_PESTB(i));
		if (result > 0) {
			*first_frozen_pe = i;
			*pci_error_type = OPAL_EEH_PE_ERROR;
			*severity = OPAL_EEH_SEV_PE_ER;
			break;
		}
	}

	return OPAL_SUCCESS;
}

static int64_t npu2_tce_kill(struct phb *phb, uint32_t kill_type,
			     uint64_t pe_number, uint32_t tce_size,
			     uint64_t dma_addr, uint32_t npages)
{
	struct npu2 *npu = phb_to_npu2_nvlink(phb);
	uint32_t tce_page_size;
	uint64_t val;

	if (pe_number > NPU2_MAX_PE_NUM)
		return OPAL_PARAMETER;

	sync();
	switch(kill_type) {
	case OPAL_PCI_TCE_KILL_PAGES:
		tce_page_size = 1ULL << (
				11 + GETFIELD(npu->tve_cache[pe_number],
					NPU2_ATS_IODA_TBL_TVT_PSIZE));
		if (tce_page_size != tce_size) {
			NPU2ERR(npu, "npu2_tce_kill: Unexpected TCE size (got 0x%x expected 0x%x)\n",
				tce_size, tce_page_size);
			return OPAL_PARAMETER;
		}

		if (npages < 128) {
			while (npages--) {
				val = SETFIELD(NPU2_ATS_TCE_KILL_PENUM, dma_addr, pe_number);
				npu2_write(npu, NPU2_ATS_TCE_KILL, NPU2_ATS_TCE_KILL_ONE | val);
				dma_addr += tce_size;
			}
			break;
		}
		/*
		 * For too many TCEs do not bother with the loop above and simply
		 * flush everything, going to be lot faster.
		 */
		/* Fall through */
	case OPAL_PCI_TCE_KILL_PE:
		/*
		 * NPU2 doesn't support killing a PE so fall through
		 * and do a kill all instead.
		 */
	case OPAL_PCI_TCE_KILL_ALL:
		npu2_write(npu, NPU2_ATS_TCE_KILL, NPU2_ATS_TCE_KILL_ALL);
		break;
	default:
		return OPAL_PARAMETER;
	}

	return OPAL_SUCCESS;
}

static const struct phb_ops npu_ops = {
	.cfg_read8		= npu2_cfg_read8,
	.cfg_read16		= npu2_cfg_read16,
	.cfg_read32		= npu2_cfg_read32,
	.cfg_write8		= npu2_cfg_write8,
	.cfg_write16		= npu2_cfg_write16,
	.cfg_write32		= npu2_cfg_write32,
	.device_init		= NULL,
	.phb_final_fixup	= npu2_phb_final_fixup,
	.ioda_reset		= npu2_ioda_reset,
	.papr_errinjct_reset	= NULL,
	.pci_reinit		= NULL,
	.set_phb_mem_window	= NULL,
	.phb_mmio_enable	= NULL,
	.map_pe_mmio_window	= NULL,
	.map_pe_dma_window	= npu2_map_pe_dma_window,
	.map_pe_dma_window_real	= npu2_map_pe_dma_window_real,
	.pci_msi_eoi		= NULL,
	.set_xive_pe		= NULL,
	.get_msi_32		= NULL,
	.get_msi_64		= NULL,
	.set_pe			= npu2_set_pe,
	.set_peltv		= NULL,
	.eeh_freeze_status	= npu2_freeze_status,
	.eeh_freeze_clear	= NULL,
	.eeh_freeze_set		= NULL,
	.next_error		= npu2_eeh_next_error,
	.err_inject		= NULL,
	.get_diag_data2		= NULL,
	.set_capi_mode		= NULL,
	.set_capp_recovery	= NULL,
	.tce_kill		= npu2_tce_kill,
};

static void assign_mmio_bars(uint64_t gcid, uint32_t scom, uint64_t reg[2], uint64_t mm_win[2])
{
	uint32_t i;
	struct npu2_bar *bar;
	struct npu2_bar npu2_bars[] = {
		/* NPU_REGS must be first in this list */
		{ .type = NPU_REGS, .index = 0,
		  .reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_0, 0, NPU2_PHY_BAR),
		  .flags = NPU2_BAR_FLAG_ENABLED },
		{ .type = NPU_PHY, .index = 0,
		  .reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_1, 0, NPU2_PHY_BAR),
		  .flags = NPU2_BAR_FLAG_ENABLED },
		{ .type = NPU_PHY, .index = 1,
		  .reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_2, 0, NPU2_PHY_BAR),
		  .flags = NPU2_BAR_FLAG_ENABLED },
		{ .type = NPU_NTL, .index = 0,
		  .reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_0, 0, NPU2_NTL0_BAR) },
		{ .type = NPU_NTL, .index = 1,
		  .reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_0, 0, NPU2_NTL1_BAR) },
		{ .type = NPU_NTL, .index = 2,
		  .reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_1, 0, NPU2_NTL0_BAR) },
		{ .type = NPU_NTL, .index = 3,
		  .reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_1, 0, NPU2_NTL1_BAR) },
		{ .type = NPU_NTL, .index = 4,
		  .reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_2, 0, NPU2_NTL0_BAR) },
		{ .type = NPU_NTL, .index = 5,
		  .reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_2, 0, NPU2_NTL1_BAR) },
		{ .type = NPU_GENID, .index = 0,
		  .reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_0, 0, NPU2_GENID_BAR) },
		{ .type = NPU_GENID, .index = 1,
		  .reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_1, 0, NPU2_GENID_BAR) },
		{ .type = NPU_GENID, .index = 2,
		  .reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_2, 0, NPU2_GENID_BAR) },
	};

	for (i = 0; i < ARRAY_SIZE(npu2_bars); i++) {
		bar = &npu2_bars[i];
		npu2_get_bar(gcid, bar);
		npu2_write_bar(NULL, bar, gcid, scom);
	}

	/* Global MMIO BAR */
	reg[0] = npu2_bars[0].base;
	reg[1] = npu2_bars[0].size;

	/* NTL and GENID BARs are exposed to kernel via the mm
	 * window */
	mm_win[0] = npu2_bars[3].base;
	mm_win[1] = npu2_bars[ARRAY_SIZE(npu2_bars) - 1].base +
		    npu2_bars[ARRAY_SIZE(npu2_bars) - 1].size -
		    mm_win[0];
}

/*
 * Set up NPU for NVLink and create PCI root device node
 * accordingly.
 */
int npu2_nvlink_init_npu(struct npu2 *npu)
{
	struct dt_node *np;
	uint64_t reg[2], mm_win[2], val, mask;

	/* TODO: Clean this up with register names, etc. when we get
	 * time. This just turns NVLink mode on in each brick and should
	 * get replaced with a patch from ajd once we've worked out how
	 * things are going to work there.
	 *
	 * Obviously if the year is now 2020 that didn't happen and you
	 * should fix this :-) */

	val = PPC_BIT(58);
	mask = PPC_BIT(58) | /* CONFIG_NVLINK_MODE */
	       PPC_BIT(40); /* CONFIG_ENABLE_SNARF_CPM */

	/*
	 * V100 GPUs are known to violate NVLink2 protocol if some GPU memory
	 * mapped by a CPU was also "linear-block" mapped by a GPU. When this
	 * happens, it breaks the NPU2 cache coherency state machine and
	 * it throws machine checkstop. Disabling snarfing fixes this so let's
	 * disable it by default.
	 */
	if (nvram_query_eq_dangerous("opal-npu2-snarf-cpm", "enable")) {
		prlog(PR_WARNING, "NPU2#%d: enabling Probe.I.MO snarfing, a bad GPU driver may crash the system!\n",
				npu->index);
		val |= PPC_BIT(40); /* CONFIG_ENABLE_SNARF_CPM */
	}

	xscom_write_mask(npu->chip_id, NPU_STCK0_CS_SM0_MISC_CONFIG0,
			 val, mask);
	xscom_write_mask(npu->chip_id, NPU_STCK0_CS_SM1_MISC_CONFIG0,
			 val, mask);
	xscom_write_mask(npu->chip_id, NPU_STCK0_CS_SM2_MISC_CONFIG0,
			 val, mask);
	xscom_write_mask(npu->chip_id, NPU_STCK0_CS_SM3_MISC_CONFIG0,
			 val, mask);
	xscom_write_mask(npu->chip_id, NPU_STCK1_CS_SM0_MISC_CONFIG0,
			 val, mask);
	xscom_write_mask(npu->chip_id, NPU_STCK1_CS_SM1_MISC_CONFIG0,
			 val, mask);
	xscom_write_mask(npu->chip_id, NPU_STCK1_CS_SM2_MISC_CONFIG0,
			 val, mask);
	xscom_write_mask(npu->chip_id, NPU_STCK1_CS_SM3_MISC_CONFIG0,
			 val, mask);
	xscom_write_mask(npu->chip_id, NPU_STCK2_CS_SM0_MISC_CONFIG0,
			 val, mask);
	xscom_write_mask(npu->chip_id, NPU_STCK2_CS_SM1_MISC_CONFIG0,
			 val, mask);
	xscom_write_mask(npu->chip_id, NPU_STCK2_CS_SM2_MISC_CONFIG0,
			 val, mask);
	xscom_write_mask(npu->chip_id, NPU_STCK2_CS_SM3_MISC_CONFIG0,
			 val, mask);

	xscom_write_mask(npu->chip_id, 0x50110c0, PPC_BIT(53), PPC_BIT(53));
	xscom_write_mask(npu->chip_id, 0x50112c0, PPC_BIT(53), PPC_BIT(53));
	xscom_write_mask(npu->chip_id, 0x50114c0, PPC_BIT(53), PPC_BIT(53));
	xscom_write_mask(npu->chip_id, 0x50110f1, PPC_BIT(41), PPC_BIT(41));
	xscom_write_mask(npu->chip_id, 0x50112f1, PPC_BIT(41), PPC_BIT(41));
	xscom_write_mask(npu->chip_id, 0x50114f1, PPC_BIT(41), PPC_BIT(41));

	val = NPU2_NTL_MISC_CFG2_BRICK_ENABLE |
	      NPU2_NTL_MISC_CFG2_NDL_TX_PARITY_ENA |
	      NPU2_NTL_MISC_CFG2_NDL_PRI_PARITY_ENA |
	      NPU2_NTL_MISC_CFG2_RCV_CREDIT_OVERFLOW_ENA;
	xscom_write_mask(npu->chip_id, 0x5011110, val, val);
	xscom_write_mask(npu->chip_id, 0x5011130, val, val);
	xscom_write_mask(npu->chip_id, 0x5011310, val, val);
	xscom_write_mask(npu->chip_id, 0x5011330, val, val);
	xscom_write_mask(npu->chip_id, 0x5011510, val, val);
	xscom_write_mask(npu->chip_id, 0x5011530, val, val);

	val = PPC_BIT(6) | PPC_BIT(7) | PPC_BIT(11);
	xscom_write_mask(npu->chip_id, 0x5011009, val, PPC_BITMASK(6,11));
	xscom_write_mask(npu->chip_id, 0x5011039, val, PPC_BITMASK(6,11));
	xscom_write_mask(npu->chip_id, 0x5011069, val, PPC_BITMASK(6,11));
	xscom_write_mask(npu->chip_id, 0x5011099, val, PPC_BITMASK(6,11));
	xscom_write_mask(npu->chip_id, 0x5011209, val, PPC_BITMASK(6,11));
	xscom_write_mask(npu->chip_id, 0x5011239, val, PPC_BITMASK(6,11));
	xscom_write_mask(npu->chip_id, 0x5011269, val, PPC_BITMASK(6,11));
	xscom_write_mask(npu->chip_id, 0x5011299, val, PPC_BITMASK(6,11));
	xscom_write_mask(npu->chip_id, 0x5011409, val, PPC_BITMASK(6,11));
	xscom_write_mask(npu->chip_id, 0x5011439, val, PPC_BITMASK(6,11));
	xscom_write_mask(npu->chip_id, 0x5011469, val, PPC_BITMASK(6,11));
	xscom_write_mask(npu->chip_id, 0x5011499, val, PPC_BITMASK(6,11));

	/* Reassign the BARs */
	assign_mmio_bars(npu->chip_id, npu->xscom_base, reg, mm_win);
	npu->regs = (void *)reg[0];
	npu->mm_base = mm_win[0];
	npu->mm_size = mm_win[1];

	if (reg[0] && reg[1])
		prlog(PR_INFO, "   Global MMIO BAR:  %016llx (%lldMB)\n",
		      reg[0], reg[1] >> 20);
	else
		prlog(PR_ERR, "    Global MMIO BAR: Disabled\n");

	/* Populate PCI root device node */
	np = dt_new_addr(dt_root, "pciex", reg[0]);
	assert(np);
	dt_add_property_strings(np,
				"compatible",
				"ibm,power9-npu-pciex",
				"ibm,ioda2-npu2-phb");
	dt_add_property_strings(np, "device_type", "pciex");
	dt_add_property(np, "reg", reg, sizeof(reg));
	dt_add_property_cells(np, "ibm,phb-index", npu2_get_phb_index(0));
	dt_add_property_cells(np, "ibm,npu-index", npu->index);
	dt_add_property_cells(np, "ibm,chip-id", npu->chip_id);
	dt_add_property_cells(np, "ibm,xscom-base", npu->xscom_base);
	dt_add_property_cells(np, "ibm,npcq", npu->dt_node->phandle);
	dt_add_property_cells(np, "ibm,links", npu->total_devices);
	dt_add_property(np, "ibm,mmio-window", mm_win, sizeof(mm_win));
	dt_add_property_cells(np, "ibm,phb-diag-data-size", 0);

	/* Disable fast reboot - not currently supported */
	disable_fast_reboot("NVLink device enabled");

	npu2_nvlink_create_phb(npu, np);

	return 0;
}

static uint32_t npu2_populate_pcie_cap(struct npu2_dev *dev,
				       uint32_t start,
				       uint32_t prev_cap)
{
	struct pci_virt_device *pvd = dev->nvlink.pvd;
	uint32_t val;

	/* Add capability list */
	PCI_VIRT_CFG_INIT_RO(pvd, prev_cap, 1, start);
	PCI_VIRT_CFG_INIT_RO(pvd, start, 1, PCI_CFG_CAP_ID_EXP);

	/* 0x00 - ID/PCIE capability */
	val = PCI_CFG_CAP_ID_EXP;
	val |= ((0x2 << 16) | (PCIE_TYPE_ENDPOINT << 20));
	PCI_VIRT_CFG_INIT_RO(pvd, start, 4, val);

	/* 0x04 - Device capability
	 *
	 * We should support FLR. Otherwise, it might have
	 * problem passing it through to userland via Linux
	 * VFIO infrastructure
	 */
	val = ((PCIE_MPSS_128) |
	       (PCIE_PHANTOM_NONE << 3) |
	       (PCIE_L0SL_MAX_NO_LIMIT << 6) |
	       (PCIE_L1L_MAX_NO_LIMIT << 9) |
	       (PCICAP_EXP_DEVCAP_FUNC_RESET));
	PCI_VIRT_CFG_INIT_RO(pvd, start + PCICAP_EXP_DEVCAP, 4, val);

	pci_virt_add_filter(pvd, start + PCICAP_EXP_DEVCTL, 2,
			    PCI_REG_FLAG_WRITE,
			    npu2_dev_cfg_exp_devcap, NULL);

	/* 0x08 - Device control and status */
	PCI_VIRT_CFG_INIT(pvd, start + PCICAP_EXP_DEVCTL, 4, 0x00002810,
			  0xffff0000, 0x000f0000);

	/* 0x0c - Link capability */
	val = (PCIE_LSPEED_VECBIT_2 | (PCIE_LWIDTH_1X << 4));
	PCI_VIRT_CFG_INIT_RO(pvd, start + PCICAP_EXP_LCAP, 4, val);

	/* 0x10 - Link control and status */
	PCI_VIRT_CFG_INIT(pvd, start + PCICAP_EXP_LCTL, 4, 0x00130000,
			 0xfffff000, 0xc0000000);

	/* 0x14 - Slot capability */
	PCI_VIRT_CFG_INIT_RO(pvd, start + PCICAP_EXP_SLOTCAP, 4, 0x00000000);

	/* 0x18 - Slot control and status */
	PCI_VIRT_CFG_INIT_RO(pvd, start + PCICAP_EXP_SLOTCTL, 4, 0x00000000);

	/* 0x1c - Root control and capability */
	PCI_VIRT_CFG_INIT(pvd, start + PCICAP_EXP_RC, 4, 0x00000000,
			  0xffffffe0, 0x00000000);

	/* 0x20 - Root status */
	PCI_VIRT_CFG_INIT(pvd, start + PCICAP_EXP_RSTAT, 4, 0x00000000,
			 0xffffffff, 0x00010000);

	/* 0x24 - Device capability 2 */
	PCI_VIRT_CFG_INIT_RO(pvd, start + PCIECAP_EXP_DCAP2, 4, 0x00000000);

	/* 0x28 - Device Control and status 2 */
	PCI_VIRT_CFG_INIT(pvd, start + PCICAP_EXP_DCTL2, 4, 0x00070000,
			 0xffff0000, 0x00000000);

	/* 0x2c - Link capability 2 */
	PCI_VIRT_CFG_INIT_RO(pvd, start + PCICAP_EXP_LCAP2, 4, 0x00000007);

	/* 0x30 - Link control and status 2 */
	PCI_VIRT_CFG_INIT(pvd, start + PCICAP_EXP_LCTL2, 4, 0x00000003,
			 0xffff0000, 0x00200000);

	/* 0x34 - Slot capability 2 */
	PCI_VIRT_CFG_INIT_RO(pvd, start + PCICAP_EXP_SCAP2, 4, 0x00000000);

	/* 0x38 - Slot control and status 2 */
	PCI_VIRT_CFG_INIT_RO(pvd, start + PCICAP_EXP_SCTL2, 4, 0x00000000);

	return start + PCICAP_EXP_SCTL2 + 8;
}

static uint32_t npu2_populate_vendor_cap(struct npu2_dev *dev,
					 uint32_t start,
					 uint32_t prev_cap)
{
	struct pci_virt_device *pvd = dev->nvlink.pvd;

	/* Capbility list */
	PCI_VIRT_CFG_INIT_RO(pvd, prev_cap, 1, start);
	PCI_VIRT_CFG_INIT_RO(pvd, start, 1, PCI_CFG_CAP_ID_VENDOR);

	/* Length and version */
	PCI_VIRT_CFG_INIT_RO(pvd, start + 2, 1, VENDOR_CAP_LEN);
	PCI_VIRT_CFG_INIT_RO(pvd, start + 3, 1, VENDOR_CAP_VERSION);

	/*
	 * Defaults when the trap can't handle the read/write (eg. due
	 * to reading/writing less than 4 bytes).
	 */
	PCI_VIRT_CFG_INIT_RO(pvd, start + 4, 4, 0);
	PCI_VIRT_CFG_INIT_RO(pvd, start + 8, 4, 0);

	/* Add NVLink2 PHY procedures trap */
	pci_virt_add_filter(pvd, start + 4, 8,
			    PCI_REG_FLAG_READ | PCI_REG_FLAG_WRITE,
			    npu2_dev_procedure,
			    NULL);

	/* Link index */
	PCI_VIRT_CFG_INIT_RO(pvd, start + 0xc, 1, dev->link_index);

	return start + VENDOR_CAP_LEN;
}

static void npu2_populate_cfg(struct npu2_dev *dev)
{
	struct pci_virt_device *pvd = dev->nvlink.pvd;
	struct npu2_pcie_bar *bar;
	uint32_t pos;

	/* 0x00 - Vendor/Device ID */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_VENDOR_ID, 4, 0x04ea1014);

	/* 0x04 - Command/Status */
	PCI_VIRT_CFG_INIT(pvd, PCI_CFG_CMD, 4, 0x00100000, 0xffb802b8,
			  0xf9000000);

	pci_virt_add_filter(pvd, PCI_CFG_CMD, 1, PCI_REG_FLAG_WRITE,
			    npu2_cfg_write_cmd, NULL);

	/* 0x08 - Rev/Class/Cache */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_REV_ID, 4, 0x06800101);

	/* 0x0c - CLS/Latency Timer/Header/BIST */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_CACHE_LINE_SIZE, 4, 0x00800000);

	/* 0x10/14 - BAR#0, NTL BAR */
	bar = &dev->bars[0];
	PCI_VIRT_CFG_INIT(pvd, PCI_CFG_BAR0, 4,
			  (bar->npu2_bar.base & 0xfffffff0) | (bar->flags & 0xF),
			  0x0000000f, 0x00000000);
	PCI_VIRT_CFG_INIT(pvd, PCI_CFG_BAR1, 4, (bar->npu2_bar.base >> 32),
			  0x00000000, 0x00000000);
	pci_virt_add_filter(pvd, PCI_CFG_BAR0, 8,
			    PCI_REG_FLAG_READ | PCI_REG_FLAG_WRITE,
			    npu2_dev_cfg_bar, bar);

	/* 0x18/1c - BAR#1, GENID BAR */
	bar = &dev->bars[1];
	if (NPU2DEV_BRICK(dev) == 0)
		PCI_VIRT_CFG_INIT(pvd, PCI_CFG_BAR2, 4, (bar->npu2_bar.base & 0xfffffff0) |
				  (bar->flags & 0xF),
				  0x0000000f, 0x00000000);
	else
		/* Brick 1 gets the upper portion of the generation id register */
		PCI_VIRT_CFG_INIT(pvd, PCI_CFG_BAR2, 4, ((bar->npu2_bar.base + 0x10000) & 0xfffffff0) |
				  (bar->flags & 0xF),
				  0x0000000f, 0x00000000);

	PCI_VIRT_CFG_INIT(pvd, PCI_CFG_BAR3, 4, (bar->npu2_bar.base >> 32), 0x00000000,
			  0x00000000);
	pci_virt_add_filter(pvd, PCI_CFG_BAR2, 8,
			    PCI_REG_FLAG_READ | PCI_REG_FLAG_WRITE,
			    npu2_dev_cfg_bar, bar);

	/* 0x20/0x24 - BARs, disabled */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_BAR4, 4, 0x00000000);
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_BAR5, 4, 0x00000000);

	/* 0x28 - Cardbus CIS pointer */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_CARDBUS_CIS, 4, 0x00000000);

	/* 0x2c - Subsystem ID */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_SUBSYS_VENDOR_ID, 4, 0x00000000);

	/* 0x30 - ROM BAR, zero sized */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_ROMBAR, 4, 0xffffffff);

	/* 0x34 - PCI Capability */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_CAP, 4, 0x00000000);

	/* 0x38 - Reserved */
	PCI_VIRT_CFG_INIT_RO(pvd, 0x38, 4, 0x00000000);

	/* 0x3c - INT line/pin/Minimal grant/Maximal latency */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_INT_LINE, 4, 0x00000100); /* INT A */

	/* PCIE and vendor specific capability */
	pos = npu2_populate_pcie_cap(dev, 0x40, PCI_CFG_CAP);
	pos = npu2_populate_vendor_cap(dev, pos, 0x41);
	PCI_VIRT_CFG_INIT_RO(pvd, pos + 1, 1, 0);
}

static uint32_t npu_allocate_bdfn(struct npu2 *p, uint32_t group)
{
	int i;
	int bdfn = (group << 3);

	for (i = 0; i < p->total_devices; i++) {
		if ((p->devices[i].bdfn & 0xf8) == (bdfn & 0xf8))
			bdfn++;
	}

	return bdfn;
}

static void npu2_populate_devices(struct npu2 *p,
				  struct dt_node *dn)
{
	struct npu2_dev *dev;
	struct dt_node *npu2_dn, *link;
	uint32_t npu_phandle, index = 0;
	int stack;

	/*
	 * Get the npu node which has the links which we expand here
	 * into pci like devices attached to our emulated phb.
	 */
	npu_phandle = dt_prop_get_u32(dn, "ibm,npcq");
	npu2_dn = dt_find_by_phandle(dt_root, npu_phandle);
	assert(npu2_dn);

	/* Walk the link@x nodes to initialize devices */
	p->total_devices = 0;
	p->phb_nvlink.scan_map = 0;
	dt_for_each_compatible(npu2_dn, link, "ibm,npu-link") {
		uint32_t group_id;
		struct npu2_bar *npu2_bar;

		dev = &p->devices[index];
		dev->type = NPU2_DEV_TYPE_NVLINK;
		dev->npu = p;
		dev->dt_node = link;
		dev->link_index = dt_prop_get_u32(link, "ibm,npu-link-index");
		dev->brick_index = dev->link_index;

		group_id = dt_prop_get_u32(link, "ibm,npu-group-id");
		dev->bdfn = npu_allocate_bdfn(p, group_id);

		/* This must be done after calling
		 * npu_allocate_bdfn() */
		p->total_devices++;
		p->phb_nvlink.scan_map |= 0x1 << ((dev->bdfn & 0xf8) >> 3);

		dev->pl_xscom_base = dt_prop_get_u64(link, "ibm,npu-phy");
		dev->lane_mask = dt_prop_get_u32(link, "ibm,npu-lane-mask");

		/* Populate BARs. BAR0/1 is the NTL bar. */
		stack = NPU2_STACK_STCK_0 + NPU2DEV_STACK(dev);
		npu2_bar = &dev->bars[0].npu2_bar;
		npu2_bar->type = NPU_NTL;
		npu2_bar->index = dev->brick_index;
		npu2_bar->reg = NPU2_REG_OFFSET(stack, 0, NPU2DEV_BRICK(dev) == 0 ?
						NPU2_NTL0_BAR : NPU2_NTL1_BAR);
	        npu2_get_bar(p->chip_id, npu2_bar);

		dev->bars[0].flags = PCI_CFG_BAR_TYPE_MEM | PCI_CFG_BAR_MEM64;

		/* BAR2/3 is the GENID bar. */
		npu2_bar = &dev->bars[1].npu2_bar;
		npu2_bar->type = NPU_GENID;
		npu2_bar->index = NPU2DEV_STACK(dev);
		npu2_bar->reg = NPU2_REG_OFFSET(stack, 0, NPU2_GENID_BAR);
	        npu2_get_bar(p->chip_id, npu2_bar);

		/* The GENID is a single physical BAR that we split
		 * for each emulated device */
		npu2_bar->size = 0x10000;
		if (NPU2DEV_BRICK(dev))
			npu2_bar->base += 0x10000;
		dev->bars[1].flags = PCI_CFG_BAR_TYPE_MEM | PCI_CFG_BAR_MEM64;

		/* Initialize PCI virtual device */
		dev->nvlink.pvd = pci_virt_add_device(&p->phb_nvlink, dev->bdfn, 0x100, dev);
		if (dev->nvlink.pvd)
			npu2_populate_cfg(dev);

		index++;
	}
}

static void npu2_add_interrupt_map(struct npu2 *p,
				  struct dt_node *dn)
{
	struct dt_node *npu2_dn, *link, *phb_dn;
	uint32_t npu2_phandle, index = 0, i;
	uint32_t icsp = get_ics_phandle();
	uint32_t *map;
	size_t map_size;
	uint32_t mask[] = {0xff00, 0x0, 0x0, 0x7};

	assert(p->phb_nvlink.dt_node);
	phb_dn = p->phb_nvlink.dt_node;

	npu2_phandle = dt_prop_get_u32(dn, "ibm,npcq");
	npu2_dn = dt_find_by_phandle(dt_root, npu2_phandle);
	assert(npu2_dn);
	map_size = 7 * sizeof(*map) * p->total_devices;
	map = malloc(map_size);
	index = 0;
	dt_for_each_compatible(npu2_dn, link, "ibm,npu-link") {
		i = index * 7;
		map[i + 0] = (p->devices[index].bdfn << 8);
		map[i + 1] = 0;
		map[i + 2] = 0;

		map[i + 3] = 1; /* INT A */
		map[i + 4] = icsp; /* interrupt-parent */
		map[i + 5] = p->base_lsi + (index * 2) + 1; /* NDL No-Stall Event */
		map[i + 6] = 0; /* 0 = EDGE, 1 = LEVEL. */
		index++;
	}
	dt_add_property(phb_dn, "interrupt-map", map, map_size);
	free(map);
	dt_add_property(phb_dn, "interrupt-map-mask", mask, sizeof(mask));
}

static void npu2_add_phb_properties(struct npu2 *p)
{
	struct dt_node *np = p->phb_nvlink.dt_node;
	uint32_t icsp = get_ics_phandle();
	uint64_t mm_base, mm_size;

	/*
	 * Add various properties that HB doesn't have to
	 * add, some of them simply because they result from
	 * policy decisions made in skiboot rather than in HB
	 * such as the MMIO windows going to PCI, interrupts,
	 * etc.
	 */
	dt_add_property_cells(np, "#address-cells", 3);
	dt_add_property_cells(np, "#size-cells", 2);
	dt_add_property_cells(np, "#interrupt-cells", 1);
	dt_add_property_cells(np, "bus-range", 0, 0xff);
	dt_add_property_cells(np, "clock-frequency", 0x200, 0);
        dt_add_property_cells(np, "interrupt-parent", icsp);

	/* NPU2 PHB properties */
	dt_add_property_cells(np, "ibm,opal-num-pes",
			      NPU2_MAX_PE_NUM);
	dt_add_property_cells(np, "ibm,opal-reserved-pe",
			      NPU2_RESERVED_PE_NUM);
	dt_add_property_cells(np, "ibm,supported-tce-sizes",
			      12, // 4K
			      16, // 64K
			      24, // 16M
			      28); // 256M

	dt_add_property_u64s(np, "ibm,mmio-atsd",
			MMIO_ATSD_ADDR(p->regs, 0),
			MMIO_ATSD_ADDR(p->regs, 1),
			MMIO_ATSD_ADDR(p->regs, 2),
			MMIO_ATSD_ADDR(p->regs, 3),
			MMIO_ATSD_ADDR(p->regs, 4),
			MMIO_ATSD_ADDR(p->regs, 5),
			MMIO_ATSD_ADDR(p->regs, 6),
			MMIO_ATSD_ADDR(p->regs, 7));

	/*
	 * Memory window is exposed as 64-bits non-prefetchable
	 * one because 64-bits prefetchable one is kind of special
	 * to kernel.
	 */
	mm_base = p->mm_base;
	mm_size = p->mm_size;
	dt_add_property_cells(np, "ranges", 0x02000000,
			      hi32(mm_base), lo32(mm_base),
			      hi32(mm_base), lo32(mm_base),
			      hi32(mm_size), lo32(mm_size));
}

void npu2_nvlink_create_phb(struct npu2 *npu, struct dt_node *dn)
{
	struct pci_slot *slot;

	/* Generic PHB */
	npu->phb_nvlink.dt_node = dn;
	npu->phb_nvlink.ops = &npu_ops;
	npu->phb_nvlink.phb_type = phb_type_npu_v2;
	init_lock(&npu->lock);
	init_lock(&npu->phb_nvlink.lock);
	list_head_init(&npu->phb_nvlink.devices);
	list_head_init(&npu->phb_nvlink.virt_devices);

	npu2_populate_devices(npu, dn);
	npu2_add_interrupt_map(npu, dn);
	npu2_add_phb_properties(npu);

	slot = npu2_slot_create(&npu->phb_nvlink);
	if (!slot)
	{
		/**
		 * @fwts-label NPUCannotCreatePHBSlot
		 * @fwts-advice Firmware probably ran out of memory creating
		 * NPU2 slot. NVLink functionality could be broken.
		 */
		prlog(PR_ERR, "NPU: Cannot create PHB slot\n");
	}

	pci_register_phb(&npu->phb_nvlink, OPAL_DYNAMIC_PHB_ID);

	npu2_init_ioda_cache(npu);
	npu2_hw_init(npu);
}

/*
 * Search a table for an entry with matching value under mask. Returns
 * the index and the current value in *value.
 */
static int npu_table_search(struct npu2 *p, uint64_t table_addr, int stride,
			    int table_size, uint64_t *value, uint64_t mask)
{
	int i;
	uint64_t val;

	assert(value);

	for (i = 0; i < table_size; i++) {
		val = npu2_read(p, table_addr + i*stride);
		if ((val & mask) == *value) {
			*value = val;
			return i;
		}
	}

	return -1;
}

/*
 * Allocate a context ID and initialise the tables with the relevant
 * information. Returns the ID on or error if one couldn't be
 * allocated.
 */
#define NPU2_VALID_ATS_MSR_BITS (MSR_DR | MSR_HV | MSR_PR | MSR_SF)
int64_t npu2_init_context(struct phb *phb, uint64_t msr, uint64_t bdf)
{
	struct npu2 *p;
	uint64_t xts_bdf, old_xts_bdf_pid, xts_bdf_pid;
	int id;

	/*
	 * MSR bits should be masked by the caller to allow for future
	 * expansion if required.
	 */
	if (msr & ~NPU2_VALID_ATS_MSR_BITS)
		return OPAL_UNSUPPORTED;

	/*
	 * Need to get LPARSHORT.
	 */
	p = phb_to_npu2_nvlink(phb);
	lock(&p->lock);
	xts_bdf = SETFIELD(NPU2_XTS_BDF_MAP_BDF, 0ul, bdf);
	if (npu_table_search(p, NPU2_XTS_BDF_MAP, 8, NPU2_XTS_BDF_MAP_SIZE,
			     &xts_bdf, NPU2_XTS_BDF_MAP_BDF) < 0) {
		NPU2ERR(p, "LPARID not associated with any GPU\n");
		id = OPAL_PARAMETER;
		goto out;
	}

	id = GETFIELD(NPU2_XTS_BDF_MAP_LPARSHORT, xts_bdf);
	NPU2DBG(p, "Found LPARSHORT = 0x%x for BDF = 0x%03llx\n", id, bdf);

	/* Enable this mapping for both real and virtual addresses */
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_VALID_ATRGPA0, 0UL, 1);
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_VALID_ATRGPA1, xts_bdf_pid, 1);

	/* Enables TLBIE/MMIOSD forwarding for this entry */
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_VALID_ATSD, xts_bdf_pid, 1);
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_LPARSHORT, xts_bdf_pid, id);

	/* Set the relevant MSR bits */
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_MSR_DR, xts_bdf_pid,
			       !!(msr & MSR_DR));
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_MSR_HV, xts_bdf_pid,
			       !!(msr & MSR_HV));
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_MSR_PR, xts_bdf_pid,
			       !!(msr & MSR_PR));

	/* We don't support anything other than 64-bit so we can safely hardcode
	 * it here */
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_MSR_SF, xts_bdf_pid, 1);

	/*
	 * Throw an error if the wildcard entry for this bdf is already set
	 * with different msr bits.
	 */
	old_xts_bdf_pid = npu2_read(p, NPU2_XTS_PID_MAP + id*0x20);
	if (old_xts_bdf_pid) {
		if (GETFIELD(NPU2_XTS_PID_MAP_MSR, old_xts_bdf_pid) !=
		    GETFIELD(NPU2_XTS_PID_MAP_MSR, xts_bdf_pid)) {
			NPU2ERR(p, "%s: Unexpected MSR value\n", __func__);
			id = OPAL_PARAMETER;
			goto out;
		} else if (!p->ctx_ref[id]) {
			NPU2ERR(p, "%s: Unexpected mapping\n", __func__);
			id = OPAL_INTERNAL_ERROR;
			goto out;
		}
	}

	/* Write the entry */
	if (!p->ctx_ref[id]) {
		NPU2DBG(p, "XTS_PID_MAP[%03d] = 0x%08llx\n", id, xts_bdf_pid);
		npu2_write(p, NPU2_XTS_PID_MAP + id*0x20, xts_bdf_pid);

		if (!GETFIELD(NPU2_XTS_BDF_MAP_VALID, xts_bdf)) {
			xts_bdf = SETFIELD(NPU2_XTS_BDF_MAP_VALID, xts_bdf, 1);
			npu2_write(p, NPU2_XTS_BDF_MAP + id*8, xts_bdf);
		}
	}
	++p->ctx_ref[id];

out:
	unlock(&p->lock);
	return id;
}

int64_t npu2_destroy_context(struct phb *phb, uint64_t bdf)
{
	struct npu2 *p;
	uint64_t xts_bdf;
	int rc = OPAL_PARAMETER, id;

	p = phb_to_npu2_nvlink(phb);
	lock(&p->lock);

	/* Need to find lparshort for this bdf */
	xts_bdf = SETFIELD(NPU2_XTS_BDF_MAP_BDF, 0ul, bdf);
	if (npu_table_search(p, NPU2_XTS_BDF_MAP, 8, NPU2_XTS_BDF_MAP_SIZE,
			     &xts_bdf, NPU2_XTS_BDF_MAP_BDF) < 0) {
		NPU2ERR(p, "LPARID not associated with any GPU\n");
	} else {
		/*
		 * The bdf/pid table contains wildcard entries and MSR bits
		 * which we need to clear between switching a device from
		 * a host to a guest or vice versa.
		 */
		id = GETFIELD(NPU2_XTS_BDF_MAP_LPARSHORT, xts_bdf);
		if (p->ctx_ref[id]) {
			--p->ctx_ref[id];
			if (!p->ctx_ref[id]) {
				NPU2DBG(p, "XTS_PID_MAP[%03d] = 0 (destroy)\n",
					id);
				npu2_write(p, NPU2_XTS_PID_MAP + id*0x20, 0);
			}
			rc = OPAL_SUCCESS;
		}
	}
	unlock(&p->lock);
	return rc;
}

/*
 * Map the given virtual bdf to lparid with given lpcr.
 */
int64_t npu2_map_lpar(struct phb *phb, uint64_t bdf, uint64_t lparid,
		      uint64_t lpcr)
{
	struct npu2 *p;
	struct npu2_dev *ndev = NULL;
	uint64_t xts_bdf_lpar, atsd_lpar, rc = OPAL_SUCCESS;
	int i;
	int id;
	static uint64_t atsd_lpar_regs[] = {
		NPU2_XTS_MMIO_ATSD0_LPARID, NPU2_XTS_MMIO_ATSD1_LPARID,
		NPU2_XTS_MMIO_ATSD2_LPARID, NPU2_XTS_MMIO_ATSD3_LPARID,
		NPU2_XTS_MMIO_ATSD4_LPARID, NPU2_XTS_MMIO_ATSD5_LPARID,
		NPU2_XTS_MMIO_ATSD6_LPARID, NPU2_XTS_MMIO_ATSD7_LPARID
	};

	if (lpcr)
		/* The LPCR bits are only required for hash based ATS,
		 * which we don't currently support but may need to in
		 * future. */
		return OPAL_UNSUPPORTED;

	p = phb_to_npu2_nvlink(phb);
	lock(&p->lock);

	/* Find any existing entries and update them */
	xts_bdf_lpar = SETFIELD(NPU2_XTS_BDF_MAP_BDF, 0L, bdf);
	id = npu_table_search(p, NPU2_XTS_BDF_MAP, 8, NPU2_XTS_BDF_MAP_SIZE,
			      &xts_bdf_lpar, NPU2_XTS_BDF_MAP_BDF);
	if (id < 0) {
		/* No existing mapping found, find space for a new one */
		xts_bdf_lpar = 0;
		id = npu_table_search(p, NPU2_XTS_BDF_MAP, 8, NPU2_XTS_BDF_MAP_SIZE,
				      &xts_bdf_lpar, -1UL);
	}

	if (id < 0) {
		/* Unable to find a free mapping */
		NPU2ERR(p, "No free XTS_BDF[] entry\n");
		rc = OPAL_RESOURCE;
		goto out;
	}

	xts_bdf_lpar = SETFIELD(NPU2_XTS_BDF_MAP_UNFILT, 0UL, 1);
	xts_bdf_lpar = SETFIELD(NPU2_XTS_BDF_MAP_BDF, xts_bdf_lpar, bdf);

	/* We only support radix for the moment */
	xts_bdf_lpar = SETFIELD(NPU2_XTS_BDF_MAP_XLAT, xts_bdf_lpar, 0x3);
	xts_bdf_lpar = SETFIELD(NPU2_XTS_BDF_MAP_LPARID, xts_bdf_lpar, lparid);
	xts_bdf_lpar = SETFIELD(NPU2_XTS_BDF_MAP_LPARSHORT, xts_bdf_lpar, id);

	/* Need to find an NVLink to send the ATSDs for this device over */
	for (i = 0; i < p->total_devices; i++) {
		if (p->devices[i].nvlink.gpu_bdfn == bdf) {
			ndev = &p->devices[i];
			break;
		}
	}

	if (!ndev) {
		NPU2ERR(p, "Unable to find nvlink for bdf %llx\n", bdf);
		rc = OPAL_PARAMETER;
		goto out;
	}

	/*
	 * We need to allocate an ATSD per NVLink bridge if possible,
	 * use the ibm,npu-link-index property for that.
	 */
	atsd_lpar = SETFIELD(NPU2_XTS_MMIO_ATSD_LPARID, 0, lparid);
	if (!lparid)
		atsd_lpar = SETFIELD(NPU2_XTS_MMIO_ATSD_MSR_HV, atsd_lpar, 1);

	if (ndev->link_index < ARRAY_SIZE(atsd_lpar_regs))
		npu2_write(p, atsd_lpar_regs[ndev->link_index], atsd_lpar);
	else
		NPU2ERR(p, "Unable to assign ATSD for link index %u\n",
				ndev->link_index);

	xts_bdf_lpar = SETFIELD(NPU2_XTS_BDF_MAP_STACK, xts_bdf_lpar,
				0x4 >> (ndev->brick_index / 2));
	xts_bdf_lpar = SETFIELD(NPU2_XTS_BDF_MAP_BRICK, xts_bdf_lpar,
				(ndev->brick_index % 2));

	NPU2DBG(p, "XTS_BDF_MAP[%03d] = 0x%08llx\n", id, xts_bdf_lpar);
	npu2_write(p, NPU2_XTS_BDF_MAP + id*8, xts_bdf_lpar);

	/* Reset wildcard in the PID map and the refcounter */
	if (npu2_read(p, NPU2_XTS_PID_MAP + id*0x20) || p->ctx_ref[id]) {
		prlog(PR_INFO, "Resetting PID MAP for LPID %lld\n", lparid);
		p->ctx_ref[id] = 0;
		npu2_write(p, NPU2_XTS_PID_MAP + id*0x20, 0);
	}

out:
	unlock(&p->lock);
	return rc;
}

static inline uint32_t npu2_relaxed_ordering_source_grpchp(uint32_t gcid)
{
	if (gcid & ~0x1b)
		return OPAL_PARAMETER;

	/* Repack 0bGGGGCCC to 0bGGCC */
	return ((gcid & 0x18) >> 1) | (gcid & 0x3);
}

static uint64_t npu2_relaxed_ordering_cfg_read(struct npu2_dev *ndev, int n)
{
	uint64_t reg = NPU2_SM_REG_OFFSET(ndev, 0, NPU2_RELAXED_ORDERING_CFG(n));

	return npu2_read(ndev->npu, reg);
}

static void npu2_relaxed_ordering_cfg_write(struct npu2_dev *ndev, int n,
					    uint64_t val)
{
	uint64_t reg;
	int sm;

	/* Set every register on our stack */
	for (sm = NPU2_BLOCK_SM_0; sm <= NPU2_BLOCK_SM_3; sm++) {
		reg = NPU2_SM_REG_OFFSET(ndev, sm, NPU2_RELAXED_ORDERING_CFG(n));
		npu2_write(ndev->npu, reg, val);
	}
}

/*
 * Parse the value of a relaxed ordering config register. Returns SOURCE0 or
 * SOURCE1 register mask if relaxed ordering is set for the given chip/pec.
 * Returns 0 if unset.
 */
static uint64_t npu2_relaxed_ordering_cfg_enabled(uint64_t val, uint32_t gcid,
						  int pec)
{
	uint32_t src, grpchp;
	uint64_t mask;
	int i;

	for (i = 0; i < 2; i++) {
		mask = NPU2_RELAXED_ORDERING_SOURCE(i);
		src = GETFIELD(mask, val);

		if (!GETFIELD(NPU2_RELAXED_ORDERING_SOURCE_ENA, src))
			continue;

		if (GETFIELD(NPU2_RELAXED_ORDERING_SOURCE_PECSEL, src) != pec)
			continue;

		grpchp = GETFIELD(NPU2_RELAXED_ORDERING_SOURCE_GRPCHP, src);
		if (grpchp == npu2_relaxed_ordering_source_grpchp(gcid))
			return mask;

		if (grpchp == 0xf) /* match all */
			return mask;
	}

	return 0;
}

static int npu2_enable_relaxed_ordering(struct npu2_dev *ndev, uint32_t gcid,
					int pec)
{
	uint64_t val, mask;
	uint32_t src;
	int rc = OPAL_RESOURCE;
	int i;

	NPU2DEVINF(ndev, "Enabling relaxed ordering for PEC %d on chip %d\n", pec, gcid);
	lock(&ndev->npu->lock);

	for (i = 0; i < 2; i++) {
		val = npu2_relaxed_ordering_cfg_read(ndev, i);
		if (!npu2_relaxed_ordering_cfg_enabled(val, gcid, pec))
			continue;

		/* Already enabled */
		rc = OPAL_SUCCESS;
		goto out;
	}

	src = NPU2_RELAXED_ORDERING_SOURCE_WRENA |
	      NPU2_RELAXED_ORDERING_SOURCE_RDENA;
	src = SETFIELD(NPU2_RELAXED_ORDERING_SOURCE_PECSEL, src, pec);
	src = SETFIELD(NPU2_RELAXED_ORDERING_SOURCE_GRPCHP, src,
		       npu2_relaxed_ordering_source_grpchp(gcid));
	src = SETFIELD(NPU2_RELAXED_ORDERING_SOURCE_WRMIN, src, 0);
	src = SETFIELD(NPU2_RELAXED_ORDERING_SOURCE_WRMAX, src, 23);
	src = SETFIELD(NPU2_RELAXED_ORDERING_SOURCE_RDMIN, src, 0);
	src = SETFIELD(NPU2_RELAXED_ORDERING_SOURCE_RDMAX, src, 47);

	/* Find somewhere to write this config */
	for (i = 0; i < 2; i++) {
		val = npu2_relaxed_ordering_cfg_read(ndev, i);

		if (!GETFIELD(NPU2_RELAXED_ORDERING_SOURCE_ENA << 32, val))
			mask = NPU2_RELAXED_ORDERING_SOURCE(0);
		else if (!GETFIELD(NPU2_RELAXED_ORDERING_SOURCE_ENA, val))
			mask = NPU2_RELAXED_ORDERING_SOURCE(1);
		else
			continue;

		val = SETFIELD(mask, val, src);
		npu2_relaxed_ordering_cfg_write(ndev, i, val);

		rc = OPAL_SUCCESS;
		break;
	}

out:
	unlock(&ndev->npu->lock);
	return rc;
}

static void npu2_disable_relaxed_ordering(struct npu2_dev *ndev, uint32_t gcid,
					  int pec)
{
	uint64_t val, mask;
	int i;

	NPU2DEVINF(ndev, "Disabling relaxed ordering for PEC %d on chip %d\n", pec, gcid);
	lock(&ndev->npu->lock);

	for (i = 0; i < 2; i++) {
		val = npu2_relaxed_ordering_cfg_read(ndev, i);

		mask = npu2_relaxed_ordering_cfg_enabled(val, gcid, pec);
		if (!mask)
			continue;

		val = SETFIELD(mask, val, 0);
		npu2_relaxed_ordering_cfg_write(ndev, i, val);
	}

	unlock(&ndev->npu->lock);
}

/*
 * Enable or disable relaxed ordering on all nvlinks for a given PEC. May leave
 * relaxed ordering partially enabled if there are insufficient HW resources to
 * enable it on all links.
 */
int64_t npu2_set_relaxed_order(struct phb *phb, uint32_t gcid, int pec,
			       bool enable)
{
	struct npu2 *npu = phb_to_npu2_nvlink(phb);
	struct npu2_dev *ndev;
	int64_t rc = OPAL_SUCCESS;

	for (int i = 0; i < npu->total_devices; i++) {
		ndev = &npu->devices[i];
		if (enable)
			rc = npu2_enable_relaxed_ordering(ndev, gcid, pec);
		else
			npu2_disable_relaxed_ordering(ndev, gcid, pec);

		if (rc != OPAL_SUCCESS) {
			NPU2DEVINF(ndev, "Insufficient resources to activate relaxed ordering mode\n");
			return OPAL_RESOURCE;
		}
	}

	return OPAL_SUCCESS;
}
