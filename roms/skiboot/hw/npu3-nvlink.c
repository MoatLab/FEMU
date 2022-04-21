// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2019 IBM Corp.
 */

#include <skiboot.h>
#include <device.h>
#include <phys-map.h>
#include <npu3.h>
#include <npu3-regs.h>
#include <pci-virt.h>
#include <xscom.h>
#include <xscom-p9-regs.h>
#include <interrupts.h>
#include <pci-cfg.h>
#include <pci-slot.h>
#include <cache-p9.h>

#define NPU3LOG(l, npu, fmt, a...)		\
	prlog(l, "NPU#%04x[%d:%d]: " fmt,	\
	      (npu)->nvlink.phb.opal_id,	\
	      (npu)->chip_id,			\
	      (npu)->index, ##a)
#define NPU3DBG(npu, fmt, a...) NPU3LOG(PR_DEBUG, npu, fmt, ##a)
#define NPU3INF(npu, fmt, a...) NPU3LOG(PR_INFO, npu, fmt, ##a)
#define NPU3ERR(npu, fmt, a...) NPU3LOG(PR_ERR, npu, fmt, ##a)

#define NPU3DEVLOG(l, dev, fmt, a...)			\
	prlog(l, "NPU#%04x:%02x:%02x.%x " fmt,		\
	      (dev)->npu->nvlink.phb.opal_id,		\
	      PCI_BUS_NUM((dev)->nvlink.pvd->bdfn),	\
	      PCI_DEV((dev)->nvlink.pvd->bdfn),	\
	      PCI_FUNC((dev)->nvlink.pvd->bdfn), ##a)
#define NPU3DEVDBG(dev, fmt, a...) NPU3DEVLOG(PR_DEBUG, dev, fmt, ##a)
#define NPU3DEVINF(dev, fmt, a...) NPU3DEVLOG(PR_INFO, dev, fmt, ##a)
#define NPU3DEVERR(dev, fmt, a...) NPU3DEVLOG(PR_ERR, dev, fmt, ##a)

#define NPU3_CFG_READ(size, type)					\
static int64_t npu3_cfg_read##size(struct phb *phb, uint32_t bdfn,	\
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

#define NPU3_CFG_WRITE(size, type)					\
static int64_t npu3_cfg_write##size(struct phb *phb, uint32_t bdfn,	\
				    uint32_t offset, type data)		\
{									\
	uint32_t val = data;						\
	int64_t ret;							\
									\
	ret = pci_virt_cfg_write(phb, bdfn, offset,			\
				 sizeof(data), val);			\
	return ret;							\
}

NPU3_CFG_READ(8, u8);
NPU3_CFG_READ(16, u16);
NPU3_CFG_READ(32, u32);
NPU3_CFG_WRITE(8, u8);
NPU3_CFG_WRITE(16, u16);
NPU3_CFG_WRITE(32, u32);

static int64_t npu3_eeh_freeze_status(struct phb *phb __unused,
				      uint64_t pe_num __unused,
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

/* Number of PEs supported */
#define NPU3_MAX_PE_NUM		16
#define NPU3_RESERVED_PE_NUM	15

static int64_t npu3_ioda_reset(struct phb *phb, bool purge __unused)
{
	struct npu3 *npu = npu3_phb_to_npu(phb);
	uint64_t val;

	val = NPU3_ATS_IODA_ADDR_AUTO_INC;
	val = SETFIELD(NPU3_ATS_IODA_ADDR_TBL_SEL, val,
		       NPU3_ATS_IODA_ADDR_TBL_TVT);
	npu3_write(npu, NPU3_ATS_IODA_ADDR, val);

	for (uint32_t i = 0; i < NPU3_MAX_PE_NUM; i++)
		npu3_write(npu, NPU3_ATS_IODA_DATA, 0ull);

	return OPAL_SUCCESS;
}

static inline void npu3_ioda_sel(struct npu3 *npu, uint32_t table,
				 uint32_t index)
{
	uint64_t val;

	val = SETFIELD(NPU3_ATS_IODA_ADDR_TBL_SEL, 0ull, table);
	val = SETFIELD(NPU3_ATS_IODA_ADDR_TBL_ADDR, val, index);
	npu3_write(npu, NPU3_ATS_IODA_ADDR, val);
}

static int64_t npu3_map_pe_dma_window(struct phb *phb,
				      uint64_t pe_num,
				      uint16_t window_id,
				      uint16_t tce_levels,
				      uint64_t tce_table_addr,
				      uint64_t tce_table_size,
				      uint64_t tce_page_size)
{
	struct npu3 *npu = npu3_phb_to_npu(phb);
	uint64_t tts_encoded, val;
	uint32_t page_size;

	/* Each PE has one corresponding TVE */
	if (window_id != pe_num || pe_num >= NPU3_MAX_PE_NUM)
		return OPAL_PARAMETER;

	npu3_ioda_sel(npu, NPU3_ATS_IODA_ADDR_TBL_TVT, pe_num);

	/* TCE table size zero is used to disable the TVE */
	if (!tce_table_size) {
		npu3_write(npu, NPU3_ATS_IODA_DATA, 0ull);
		return OPAL_SUCCESS;
	}

	/* TCE table size */
	if (!is_pow2(tce_table_size) || tce_table_size < 0x1000)
		return OPAL_PARAMETER;

	tts_encoded = ilog2(tce_table_size) - 11;
	if (tts_encoded > 39)
		return OPAL_PARAMETER;

	val = SETFIELD(NPU3_ATS_IODA_TVT_TABLE_SIZE, 0ull, tts_encoded);

	/* Number of levels */
	if (tce_levels < 1 || tce_levels > 4)
		return OPAL_PARAMETER;

	val = SETFIELD(NPU3_ATS_IODA_TVT_TABLE_LEVEL, val, tce_levels - 1);

	/* TCE page size */
	switch (tce_page_size) {
	case 256 << 20:
		page_size = 17;
		break;
	case 16 << 20:
		page_size = 13;
		break;
	case 64 << 10:
		page_size = 5;
		break;
	default:
		page_size = 1;
	}

	val = SETFIELD(NPU3_ATS_IODA_TVT_PAGE_SIZE, val, page_size);
	val = SETFIELD(NPU3_ATS_IODA_TVT_XLAT_ADDR, val, tce_table_addr >> 12);
	npu3_write(npu, NPU3_ATS_IODA_DATA, val);

	return OPAL_SUCCESS;
}

static int64_t npu3_map_pe_dma_window_real(struct phb *phb,
					   uint64_t pe_num,
					   uint16_t window_id,
					   uint64_t pci_start_addr __unused,
					   uint64_t pci_mem_size __unused)
{
	struct npu3 *npu = npu3_phb_to_npu(phb);
	uint64_t val;

	/* Each PE has one corresponding TVE */
	if (window_id != pe_num || pe_num >= NPU3_MAX_PE_NUM)
		return OPAL_PARAMETER;

	if (pci_mem_size) {
		/*
		 * GPUs need to be able to access the MMIO memory space as well.
		 * On POWER9 this is above the top of RAM, so disable the TVT
		 * range check, allowing access to all memory addresses.
		 */
		val = 0;
	} else {
		/* Disable */
		val = PPC_BIT(51);
	}

	npu3_ioda_sel(npu, NPU3_ATS_IODA_ADDR_TBL_TVT, pe_num);
	npu3_write(npu, NPU3_ATS_IODA_DATA, val);

	return OPAL_SUCCESS;
}

static int64_t npu3_next_error(struct phb *phb,
			       uint64_t *first_frozen_pe,
			       uint16_t *pci_error_type,
			       uint16_t *severity)
{
	struct npu3 *npu = npu3_phb_to_npu(phb);
	uint64_t val;
	uint32_t pe_num;

	if (!first_frozen_pe || !pci_error_type || !severity)
		return OPAL_PARAMETER;

	*first_frozen_pe = -1;
	*pci_error_type = OPAL_EEH_NO_ERROR;
	*severity = OPAL_EEH_SEV_NO_ERROR;

	for (pe_num = 0; pe_num < NPU3_MAX_PE_NUM; pe_num++) {
		val = npu3_read(npu, NPU3_MISC_PESTB_DATA(pe_num));
		if (!GETFIELD(NPU3_MISC_PESTB_DATA_DMA_STOPPED_STATE, val))
			continue;

		*first_frozen_pe = pe_num;
		*pci_error_type = OPAL_EEH_PE_ERROR;
		*severity = OPAL_EEH_SEV_PE_ER;
		break;
	}

	return OPAL_SUCCESS;
}

static struct npu3_dev *npu3_bdfn_to_dev(struct npu3 *npu, uint32_t bdfn)
{
	struct pci_virt_device *pvd;

	/* All emulated devices are attached to root bus */
	if (bdfn & ~0xff)
		return NULL;

	pvd = pci_virt_find_device(&npu->nvlink.phb, bdfn);
	if (pvd)
		return pvd->data;

	return NULL;
}

static int npu3_match_gpu(struct phb *phb __unused, struct pci_device *pd,
			  void *data)
{
	const char *slot = data;
	struct dt_node *dn;
	char *loc_code;

	/* Ignore non-NVIDIA devices */
	if (PCI_VENDOR_ID(pd->vdid) != 0x10de)
		return 0;

	/* Find the PCI device's slot location */
	for (dn = pd->dn;
	     dn && !dt_find_property(dn, "ibm,loc-code");
	     dn = dn->parent);

	if (!dn)
		return 0;

	loc_code = (char *)dt_prop_get(dn, "ibm,loc-code");
	if (streq(loc_code, slot))
		return 1;

	return 0;
}

static void npu3_dev_find_gpu(struct npu3_dev *dev)
{
	const char *slot = dev->nvlink.loc_code;
	struct phb *phb;
	struct pci_device *gpu;

	if (!slot)
		return;

	for_each_phb(phb) {
		gpu = pci_walk_dev(phb, NULL, npu3_match_gpu, (void *)slot);
		if (!gpu)
			continue;

		dev->nvlink.gpu = gpu;
		return;
	}

	NPU3DEVINF(dev, "No PCI device found for slot '%s'\n", slot);
}

#define VENDOR_CAP_START		0x80
#define VENDOR_CAP_LINK_FLAG_OFFSET	0x0d

void npu3_pvd_flag_set(struct npu3_dev *dev, uint8_t flag)
{
	uint32_t offset = VENDOR_CAP_START + VENDOR_CAP_LINK_FLAG_OFFSET;
	uint32_t flags;

	PCI_VIRT_CFG_RDONLY_RD(dev->nvlink.pvd, offset, 1, &flags);
	flags |= flag;
	PCI_VIRT_CFG_INIT_RO(dev->nvlink.pvd, offset, 1, flags);
}

void npu3_pvd_flag_clear(struct npu3_dev *dev, uint8_t flag)
{
	uint32_t offset = VENDOR_CAP_START + VENDOR_CAP_LINK_FLAG_OFFSET;
	uint32_t flags;

	PCI_VIRT_CFG_RDONLY_RD(dev->nvlink.pvd, offset, 1, &flags);
	flags &= ~flag;
	PCI_VIRT_CFG_INIT_RO(dev->nvlink.pvd, offset, 1, flags);
}

static struct lock npu3_phandle_lock = LOCK_UNLOCKED;

static void npu3_append_phandle(struct dt_node *dn, const char *name,
				uint32_t phandle)
{
	struct dt_property *prop;
	uint32_t *phandles;
	size_t len;

	prop = __dt_find_property(dn, name);
	if (!prop) {
		dt_add_property_cells(dn, name, phandle);
		return;
	}

	/*
	 * Make sure no one else has a reference to the property. Assume
	 * this is the only function that holds a reference to it.
	 */
	lock(&npu3_phandle_lock);

	/* Need to append to the property */
	len = prop->len + sizeof(*phandles);
	dt_resize_property(&prop, len);

	phandles = (uint32_t *)prop->prop;
	phandles[len / sizeof(*phandles) - 1] = phandle;

	unlock(&npu3_phandle_lock);
}

static void npu3_dev_fixup_dt(struct npu3_dev *dev)
{
	struct pci_device *pd = dev->nvlink.pd;
	struct pci_device *gpu = dev->nvlink.gpu;

	dt_add_property_cells(pd->dn, "ibm,nvlink", dev->dn->phandle);
	dt_add_property_string(pd->dn, "ibm,loc-code", dev->nvlink.loc_code);
	if (dev->link_speed != 0xff)
		dt_add_property_cells(pd->dn, "ibm,nvlink-speed",
				      lo32(dev->link_speed));

	if (!gpu)
		return;

	npu3_append_phandle(gpu->dn, "ibm,npu", pd->dn->phandle);
	dt_add_property_cells(pd->dn, "ibm,gpu", gpu->dn->phandle);
}

static int64_t npu3_gpu_bridge_sec_bus_reset(void *pdev,
				struct pci_cfg_reg_filter *pcrf __unused,
				uint32_t offset, uint32_t len,
				uint32_t *data, bool write)
{
	struct pci_device *pd = pdev;
	struct pci_device *gpu;
	struct npu3 *npu;
	struct npu3_dev *dev;
	bool purge = false;

	if (!write)
		return OPAL_PARAMETER;

	if (len != 2 || offset & 1) {
		PCIERR(pd->phb, pd->bdfn,
		       "Unsupported write to bridge control register\n");
		return OPAL_PARAMETER;
	}

	if (!(*data & PCI_CFG_BRCTL_SECONDARY_RESET))
		return OPAL_PARTIAL;

	gpu = list_top(&pd->children, struct pci_device, link);
	if (!gpu)
		return OPAL_PARTIAL;

	npu3_for_each_nvlink_npu(npu)
		npu3_for_each_nvlink_dev(dev, npu)
			if (dev->nvlink.gpu == gpu)
				if (!npu3_dev_reset(dev))
					purge = true;

	if (purge)
		purge_l2_l3_caches();

	return OPAL_PARTIAL;
}

static int npu3_dev_bind(struct phb *phb, struct pci_device *pd,
			 void *data __unused)
{
	struct npu3 *npu = npu3_phb_to_npu(phb);
	struct npu3_dev *dev = npu3_bdfn_to_dev(npu, pd->bdfn);
	struct pci_device *gpu;

	dev->nvlink.pd = pd;

	/* The slot label indicates which GPU this link is connected to */
	dev->nvlink.loc_code = dt_prop_get_def(dev->dn, "ibm,slot-label", NULL);
	if (!dev->nvlink.loc_code) {
		/**
		 * @fwts-label NPUNoPHBSlotLabel
		 * @fwts-advice No GPU/NPU slot information was found.
		 * NVLink3 functionality will not work.
		 */
		NPU3DEVERR(dev, "Cannot find GPU slot information\n");
	}

	npu3_dev_find_gpu(dev);
	npu3_dev_fixup_dt(dev);

	gpu = dev->nvlink.gpu;
	if (!gpu)
		return 0;

	/* When a GPU is reset, ensure all of its links are reset too */
	if (gpu->parent && gpu->parent->slot)
		pci_add_cfg_reg_filter(gpu->parent, PCI_CFG_BRCTL, 2,
				       PCI_REG_FLAG_WRITE,
				       npu3_gpu_bridge_sec_bus_reset);

	npu3_pvd_flag_set(dev, NPU3_DEV_PCI_LINKED);

	return 0;
}

struct npu3 *npu3_next_nvlink_npu(struct npu3 *npu, uint32_t chip_id)
{
	uint64_t phb_id = 0;
	struct phb *phb;

	if (npu)
		phb_id = npu->nvlink.phb.opal_id + 1;

	for (; (phb = __pci_next_phb_idx(&phb_id));) {
		if (phb->phb_type != phb_type_npu_v3)
			continue;

		npu = npu3_phb_to_npu(phb);
		if (npu->chip_id == chip_id || chip_id == NPU3_ANY_CHIP)
			return npu;
	}

	return NULL;
}

static struct npu3 *npu3_last_npu(void)
{
	static struct npu3 *last = NULL;
	struct npu3 *npu;

	if (last)
		return last;

	npu3_for_each_nvlink_npu(npu)
		last = npu;

	return last;
}

static uint32_t npu3_gpu_links(struct pci_device *gpu)
{
	const struct dt_property *prop;

	if (!gpu)
		return 0;

	/* The link count is the number of phandles in "ibm,npu" */
	prop = dt_find_property(gpu->dn, "ibm,npu");
	if (!prop)
		return 0;

	return prop->len / sizeof(uint32_t);
}

static uint32_t npu3_links_per_gpu(void)
{
	struct npu3 *npu;
	struct npu3_dev *dev;
	uint32_t links = 0;

	/* Use the first GPU we find to figure this out */
	npu3_for_each_nvlink_npu(npu) {
		npu3_for_each_nvlink_dev(dev, npu) {
			links = npu3_gpu_links(dev->nvlink.gpu);
			if (links)
				goto out;
		}
	}

out:
	prlog(PR_DEBUG, "NPU: %s: %d\n", __func__, links);

	return links;
}

int32_t npu3_dev_gpu_index(struct npu3_dev *dev)
{
	const char *slot;
	char *p = NULL;
	int ret;

	slot = dev->nvlink.loc_code;
	if (!slot)
		return -1;

	if (memcmp(slot, "GPU", 3))
		return -1;

	ret = strtol(slot + 3, &p, 10);
	if (*p || p == slot + 3)
		return -1;

	return ret;
}

static uint32_t npu3_chip_possible_gpu_links(void)
{
	struct proc_chip *chip;
	struct npu3 *npu;
	struct npu3_dev *dev;
	uint32_t possible = 0;

	for_each_chip(chip) {
		npu3_for_each_chip_nvlink_npu(npu, chip->id)
			npu3_for_each_nvlink_dev(dev, npu)
				if (npu3_dev_gpu_index(dev) != -1)
					possible++;

		if (possible)
			break;
	}

	prlog(PR_DEBUG, "NPU: %s: %d\n", __func__, possible);

	return possible;
}

uint32_t npu3_chip_possible_gpus(void)
{
	static uint32_t possible = -1;
	uint32_t links_per_gpu;

	/* Static value, same for all chips; only do this once */
	if (possible != -1)
		return possible;

	possible = 0;

	links_per_gpu = npu3_links_per_gpu();
	if (links_per_gpu)
		possible = npu3_chip_possible_gpu_links() / links_per_gpu;

	prlog(PR_DEBUG, "NPU: %s: %d\n", __func__, possible);

	return possible;
}

static void npu3_dev_assign_gmb(struct npu3_dev *dev, uint64_t addr,
				uint64_t size)
{
	uint32_t mode;
	uint64_t val;

	switch (npu3_gpu_links(dev->nvlink.gpu)) {
	case 0:
		return;
	case 1:
		mode = 0;
		break;
	case 2:
		mode = 1;
		break;
	case 3:
		mode = 3;
		break;
	case 4:
		mode = 6;
		break;
	case 6:
		mode = 10;
		break;
	default:
		/* Hardware does not support this configuration */
		assert(0);
	}

	mode += PCI_FUNC(dev->nvlink.pvd->bdfn);

	val = NPU3_GPU_MEM_BAR_ENABLE |
	      NPU3_GPU_MEM_BAR_POISON;
	val = SETFIELD(NPU3_GPU_MEM_BAR_ADDR, val, addr >> 30);
	val = SETFIELD(NPU3_GPU_MEM_BAR_SIZE, val, size >> 30);
	val = SETFIELD(NPU3_GPU_MEM_BAR_MODE, val, mode);

	npu3_write(dev->npu, NPU3_GPU_MEM_BAR(dev->index), val);
}

static struct dt_node *npu3_create_memory_dn(struct npu3_dev *dev,
					     uint32_t gpu_index, uint64_t addr,
					     uint64_t size)
{
	uint32_t nid = 255 - gpu_index;
	struct dt_node *mem;

	mem = dt_find_by_name_addr(dt_root, "memory", addr);
	if (mem)
		return mem;

	mem = dt_new_addr(dt_root, "memory", addr);
	assert(mem);

	dt_add_property_string(mem, "device_type", "memory");
	dt_add_property_string(mem, "compatible", "ibm,coherent-device-memory");
	dt_add_property_u64s(mem, "reg", addr, size);
	dt_add_property_u64s(mem, "linux,usable-memory", addr, 0);
	dt_add_property_cells(mem, "ibm,chip-id", nid);
	dt_add_property_cells(mem, "ibm,associativity", 4, nid, nid, nid, nid);

	NPU3INF(dev->npu, "%s mem: 0x%016llx (nid %d)\n", dev->nvlink.loc_code,
		addr, nid);

	return mem;
}

static void npu3_dev_init_gpu_mem(struct npu3_dev *dev)
{
	struct pci_device *pd = dev->nvlink.pd;
	struct npu3 *npu = dev->npu;
	struct dt_node *mem;
	uint64_t addr, size, gta;
	uint32_t gpu_index;

	if (!dev->nvlink.gpu)
		return;

	gpu_index = npu3_dev_gpu_index(dev) % npu3_chip_possible_gpus();
	phys_map_get(npu->chip_id, GPU_MEM_4T_DOWN, gpu_index, &addr, &size);

	npu3_dev_assign_gmb(dev, addr, size);
	mem = npu3_create_memory_dn(dev, gpu_index, addr, size);

	/*
	 * Coral mode address compression. This is documented in Figure 3.5 of
	 * the NPU workbook; "P9->GPU RA Compression (Coral)".
	 */
	gta  = (addr >> 42 & 0x1) << 42;
	gta |= (addr >> 45 & 0x3) << 43;
	gta |= (addr >> 49 & 0x3) << 45;
	gta |= addr & ((1ul << 43) - 1);

	dt_add_property_cells(pd->dn, "memory-region", mem->phandle);
	dt_add_property_u64s(pd->dn, "ibm,device-tgt-addr", gta);
}

static void npu3_final_fixup(void)
{
	struct npu3 *npu;
	struct npu3_dev *dev;

	npu3_for_each_nvlink_npu(npu)
		npu3_for_each_nvlink_dev(dev, npu)
			npu3_dev_init_gpu_mem(dev);
}

static void npu3_phb_final_fixup(struct phb *phb)
{
	struct npu3 *npu = npu3_phb_to_npu(phb);

	pci_walk_dev(phb, NULL, npu3_dev_bind, NULL);

	/*
	 * After every npu's devices are bound, do gpu-related fixup. This
	 * counts on npu3_last_npu() walking the phbs in the same order as
	 * the PHB final fixup loop in __pci_init_slots().
	 */
	if (npu == npu3_last_npu())
		npu3_final_fixup();
}

static int64_t npu3_set_pe(struct phb *phb,
			   uint64_t pe_num,
			   uint64_t bdfn,
			   uint8_t bcompare,
			   uint8_t dcompare,
			   uint8_t fcompare,
			   uint8_t action)
{
	struct npu3 *npu = npu3_phb_to_npu(phb);
	struct npu3_dev *dev;
	uint64_t val;

	dev = npu3_bdfn_to_dev(npu, bdfn);
	if (!dev)
		return OPAL_PARAMETER;

	if (action != OPAL_MAP_PE && action != OPAL_UNMAP_PE)
		return OPAL_PARAMETER;

	if (pe_num >= NPU3_MAX_PE_NUM)
		return OPAL_PARAMETER;

	if (bcompare != OpalPciBusAll ||
	    dcompare != OPAL_COMPARE_RID_DEVICE_NUMBER ||
	    fcompare != OPAL_COMPARE_RID_FUNCTION_NUMBER)
		return OPAL_UNSUPPORTED;

	if (!dev->nvlink.gpu)
		return OPAL_SUCCESS;

	val = NPU3_CTL_BDF2PE_CFG_ENABLE;
	val = SETFIELD(NPU3_CTL_BDF2PE_CFG_PE, val, pe_num);
	val = SETFIELD(NPU3_CTL_BDF2PE_CFG_BDF, val, dev->nvlink.gpu->bdfn);
	npu3_write(npu, NPU3_CTL_BDF2PE_CFG(pe_num), val);

	val = NPU3_MISC_BDF2PE_CFG_ENABLE;
	val = SETFIELD(NPU3_MISC_BDF2PE_CFG_PE, val, pe_num);
	val = SETFIELD(NPU3_MISC_BDF2PE_CFG_BDF, val, dev->nvlink.gpu->bdfn);
	npu3_write(npu, NPU3_MISC_BDF2PE_CFG(pe_num), val);

	return OPAL_SUCCESS;
}

static int64_t npu3_tce_kill_pages(struct npu3 *npu,
				   uint64_t pe_num,
				   uint32_t tce_size,
				   uint64_t dma_addr,
				   uint32_t npages)
{
	uint32_t check_tce_size;
	uint64_t val;

	if (pe_num >= NPU3_MAX_PE_NUM)
		return OPAL_PARAMETER;

	npu3_ioda_sel(npu, NPU3_ATS_IODA_ADDR_TBL_TVT, pe_num);
	val = npu3_read(npu, NPU3_ATS_IODA_DATA);

	check_tce_size = 0x800 << GETFIELD(NPU3_ATS_IODA_TVT_PAGE_SIZE, val);
	if (check_tce_size != tce_size) {
		NPU3ERR(npu, "%s: Unexpected TCE size (got 0x%x, expected 0x%x)\n",
			__func__, tce_size, check_tce_size);

		return OPAL_PARAMETER;
	}

	val = NPU3_ATS_TCE_KILL_ONE;
	val = SETFIELD(NPU3_ATS_TCE_KILL_PE_NUMBER, val, pe_num);

	while (npages--) {
		val = SETFIELD(NPU3_ATS_TCE_KILL_ADDRESS, val, dma_addr >> 12);
		npu3_write(npu, NPU3_ATS_TCE_KILL, val);

		dma_addr += tce_size;
	}

	return OPAL_SUCCESS;
}

static int64_t npu3_tce_kill(struct phb *phb,
			     uint32_t kill_type,
			     uint64_t pe_num,
			     uint32_t tce_size,
			     uint64_t dma_addr,
			     uint32_t npages)
{
	struct npu3 *npu = npu3_phb_to_npu(phb);

	sync();

	switch(kill_type) {
	case OPAL_PCI_TCE_KILL_PAGES:
		return npu3_tce_kill_pages(npu, pe_num, tce_size,
					   dma_addr, npages);
	case OPAL_PCI_TCE_KILL_PE:
		/*
		 * NPU doesn't support killing a PE so fall through
		 * and do a kill all instead.
		 */
	case OPAL_PCI_TCE_KILL_ALL:
		npu3_write(npu, NPU3_ATS_TCE_KILL, NPU3_ATS_TCE_KILL_ALL);
		return OPAL_SUCCESS;
	}

	return OPAL_PARAMETER;
}

static const struct phb_ops npu_ops = {
	.cfg_read8		= npu3_cfg_read8,
	.cfg_read16		= npu3_cfg_read16,
	.cfg_read32		= npu3_cfg_read32,
	.cfg_write8		= npu3_cfg_write8,
	.cfg_write16		= npu3_cfg_write16,
	.cfg_write32		= npu3_cfg_write32,
	.eeh_freeze_status	= npu3_eeh_freeze_status,
	.ioda_reset		= npu3_ioda_reset,
	.map_pe_dma_window	= npu3_map_pe_dma_window,
	.map_pe_dma_window_real	= npu3_map_pe_dma_window_real,
	.next_error		= npu3_next_error,
	.phb_final_fixup	= npu3_phb_final_fixup,
	.set_pe			= npu3_set_pe,
	.tce_kill		= npu3_tce_kill,
};

static int64_t npu3_reset(struct pci_slot *slot)
{
	struct npu3 *npu = npu3_phb_to_npu(slot->phb);
	struct npu3_dev *dev;
	int64_t rc = OPAL_SUCCESS;
	bool purge = false;

	npu3_for_each_nvlink_dev(dev, npu) {
		rc = npu3_dev_reset(dev);
		if (rc)
			break;

		purge = true;
	}

	/* No devices reset; don't purge, just return */
	if (!purge)
		return rc;

	/* All devices reset */
	if (!rc)
		return purge_l2_l3_caches();

	/* Some devices successfully reset; purge, but still return error */
	purge_l2_l3_caches();
	return rc;
}

static int64_t npu3_freset(struct pci_slot *slot __unused)
{
	return OPAL_SUCCESS;
}

static int64_t npu3_get_link_state(struct pci_slot *slot __unused,
				   uint8_t *val)
{
	*val = OPAL_SHPC_LINK_UP_x1;
	return OPAL_SUCCESS;
}

static int64_t npu3_get_power_state(struct pci_slot *slot __unused,
				    uint8_t *val)
{
	*val = PCI_SLOT_POWER_ON;
	return OPAL_SUCCESS;
}

static void npu3_create_phb_slot(struct npu3 *npu)
{
	struct pci_slot *slot;

	slot = pci_slot_alloc(&npu->nvlink.phb, NULL);
	if (!slot)
		return;

	/* Elementary functions */
	slot->ops.creset		= npu3_reset;
	slot->ops.freset		= npu3_freset;
	slot->ops.hreset		= npu3_reset;
	slot->ops.get_link_state	= npu3_get_link_state;
	slot->ops.get_power_state	= npu3_get_power_state;
}

static void npu3_create_phb(struct npu3 *npu)
{
	struct phb *phb = &npu->nvlink.phb;

	phb->phb_type = phb_type_npu_v3;
	phb->ops = &npu_ops;
	phb->dt_node = dt_new_addr(dt_root, "pciex", npu->regs[0]);
	assert(phb->dt_node);

	list_head_init(&phb->virt_devices);
	pci_register_phb(phb, npu3_get_opal_id(npu->chip_id,
					       npu3_get_phb_index(npu->index)));
	npu3_create_phb_slot(npu);
	npu3_ioda_reset(phb, true);
}

static void npu3_dev_init_hw(struct npu3_dev *dev)
{
	struct npu3 *npu = dev->npu;
	uint64_t reg, val;

	reg = NPU3_RELAXED_CFG2(dev->index);
	val = npu3_read(npu, reg);
	val |= NPU3_RELAXED_CFG2_CMD_CL_DMA_W |
	       NPU3_RELAXED_CFG2_CMD_CL_DMA_W_HP |
	       NPU3_RELAXED_CFG2_CMD_CL_DMA_INJ |
	       NPU3_RELAXED_CFG2_CMD_PR_DMA_INJ |
	       NPU3_RELAXED_CFG2_CMD_DMA_PR_W |
	       NPU3_RELAXED_CFG2_CMD_CL_RD_NC_F0 |
	       NPU3_RELAXED_CFG2_SRC_RDENA(0);
	npu3_write(npu, reg, val);

	reg = NPU3_NTL_MISC_CFG2(dev->index);
	val = npu3_read(npu, reg);
	val |= NPU3_NTL_MISC_CFG2_BRICK_ENABLE |
	       NPU3_NTL_MISC_CFG2_RCV_CREDIT_OVERFLOW_ENA;
	npu3_write(npu, reg, val);
}

static void npu3_init_hw(struct npu3 *npu)
{
	struct npu3_dev *dev;
	uint64_t reg, val;

	reg = NPU3_XTS_CFG;
	val = npu3_read(npu, reg);
	val |= NPU3_XTS_CFG_MMIOSD | NPU3_XTS_CFG_TRY_ATR_RO;
	npu3_write(npu, reg, val);

	reg = NPU3_XTS_CFG2;
	val = npu3_read(npu, reg);
	val |= NPU3_XTS_CFG2_NO_FLUSH_ENA;
	npu3_write(npu, reg, val);

	reg = NPU3_RELAXED_SRC(0);
	val = NPU3_RELAXED_SRC_MASK_NPU;
	npu3_write(npu, reg, val);

	npu3_for_each_nvlink_dev(dev, npu)
		npu3_dev_init_hw(dev);
}

/* PCI command register (BAR enable/disable) */
static int64_t npu3_cfg_cmd(void *pvd,
			    struct pci_cfg_reg_filter *pcrf __unused,
			    uint32_t offset, uint32_t size,
			    uint32_t *data, bool write)
{
	struct npu3_dev *dev = ((struct pci_virt_device *)pvd)->data;

	if (!write)
		return OPAL_PARTIAL;

	if (offset != PCI_CFG_CMD)
		return OPAL_PARAMETER;

	if (size != 1 && size != 2 && size != 4)
		return OPAL_PARAMETER;

	npu3_dev_enable_bars(dev, !!(*data & PCI_CFG_CMD_MEM_EN));

	return OPAL_PARTIAL;
}

static int64_t npu3_cfg_bar_write(struct npu3_bar *bar, uint64_t mask,
				  uint32_t data)
{
	if (data != 0xffffffff)
		return OPAL_HARDWARE;

	/* Return BAR size on next read */
	bar->trap |= mask;

	return OPAL_SUCCESS;
}

static int64_t npu3_cfg_bar_read(struct npu3_bar *bar, uint64_t mask,
				 uint32_t *data)
{
	if (!(bar->trap & mask))
		return OPAL_PARTIAL;

	*data = GETFIELD(mask, bar->size);
	bar->trap &= ~mask;

	return OPAL_SUCCESS;
}

/* PCI BAR registers (NTL/GENID) */
static int64_t npu3_cfg_bar(void *pvd __unused,
			    struct pci_cfg_reg_filter *pcrf,
			    uint32_t offset, uint32_t size, uint32_t *data,
			    bool write)
{
	struct npu3_bar *bar = (struct npu3_bar *)pcrf->data;
	uint64_t mask;

	if (size != 4)
		return OPAL_PARAMETER;

	if (offset == pcrf->start)
		mask = 0xffffffff;
	else if (offset == pcrf->start + 4)
		mask = 0xffffffffull << 32;
	else
		return OPAL_PARAMETER;

	if (write)
		return npu3_cfg_bar_write(bar, mask, *data);

	return npu3_cfg_bar_read(bar, mask, data);
}

/* PCI control register */
static int64_t npu3_cfg_devctl(void *pvd,
			       struct pci_cfg_reg_filter *pcrf __unused,
			       uint32_t offset, uint32_t size,
			       uint32_t *data, bool write)
{
	struct npu3_dev *dev = ((struct pci_virt_device *)pvd)->data;

	if (!write)
		return OPAL_HARDWARE;

	if (size != 2 || offset & 1) {
		NPU3DEVERR(dev, "Unsupported write to pcie control register\n");
		return OPAL_PARAMETER;
	}

	if (*data & PCICAP_EXP_DEVCTL_FUNC_RESET)
		if (!npu3_dev_reset(dev))
			purge_l2_l3_caches();

	return OPAL_PARTIAL;
}

static uint32_t npu3_cfg_populate_pcie_cap(struct npu3_dev *dev, uint32_t start,
					   uint32_t prev_cap)
{
	struct pci_virt_device *pvd = dev->nvlink.pvd;
	uint32_t val;

	/* Add capability list */
	PCI_VIRT_CFG_INIT_RO(pvd, prev_cap, 1, start);
	PCI_VIRT_CFG_INIT_RO(pvd, start, 1, PCI_CFG_CAP_ID_EXP);

	/* 0x00 - ID/PCIE capability */
	val = PCI_CFG_CAP_ID_EXP;
	val |= 0x2 << 16 | PCIE_TYPE_ENDPOINT << 20;
	PCI_VIRT_CFG_INIT_RO(pvd, start, 4, val);

	/* 0x04 - Device capability */
	val = PCIE_MPSS_128 |
	      PCIE_PHANTOM_NONE << 3 |
	      PCIE_L0SL_MAX_NO_LIMIT << 6 |
	      PCIE_L1L_MAX_NO_LIMIT << 9 |
	      PCICAP_EXP_DEVCAP_FUNC_RESET;
	PCI_VIRT_CFG_INIT_RO(pvd, start + PCICAP_EXP_DEVCAP, 4, val);

	pci_virt_add_filter(pvd, start + PCICAP_EXP_DEVCTL, 2,
			    PCI_REG_FLAG_WRITE,
			    npu3_cfg_devctl, NULL);

	/* 0x08 - Device control and status */
	PCI_VIRT_CFG_INIT(pvd, start + PCICAP_EXP_DEVCTL, 4, 0x00002810,
			  0xffff0000, 0x000f0000);

	/* 0x0c - Link capability */
	val = PCIE_LSPEED_VECBIT_2 | PCIE_LWIDTH_1X << 4;
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

static int64_t npu3_dev_procedure_write(struct npu3_dev *dev, uint32_t offset,
					uint32_t data)
{
	switch (offset) {
	case 0:
		NPU3DEVINF(dev, "Ignoring write to status register\n");
		break;
	case 4:
		npu3_dev_procedure_init(dev, data);
		break;
	default:
		return OPAL_PARAMETER;
	}

	return OPAL_SUCCESS;
}

static int64_t npu3_dev_procedure_read(struct npu3_dev *dev, uint32_t offset,
				       uint32_t *data)
{
	switch (offset) {
	case 0:
		*data = npu3_dev_procedure_status(dev);
		break;
	case 4:
		*data = dev->proc.number;
		break;
	default:
		*data = 0;
		return OPAL_PARAMETER;
	}

	return OPAL_SUCCESS;
}

/* Hardware procedure control/status registers */
static int64_t npu3_dev_procedure(void *pvd, struct pci_cfg_reg_filter *pcrf,
				  uint32_t offset, uint32_t size,
				  uint32_t *data, bool write)
{
	struct npu3_dev *dev = ((struct pci_virt_device *)pvd)->data;

	if (size != 4)
		return OPAL_PARAMETER;

	offset -= pcrf->start;

	if (write)
		return npu3_dev_procedure_write(dev, offset, *data);

	return npu3_dev_procedure_read(dev, offset, data);
}

/* PPE SRAM access is indirect via CSAR/CSDR */
static void npu3_dev_ppe_sram_sel(struct npu3_dev *dev, uint32_t reg)
{
	uint64_t val;

	val = SETFIELD(OB_PPE_CSAR_SRAM_ADDR, 0ull, reg);
	xscom_write(dev->npu->chip_id, OB_PPE_CSAR(dev->ob_chiplet), val);
}

static void npu3_dev_ppe_sram_write(struct npu3_dev *dev, uint32_t reg,
				    uint64_t val)
{
	npu3_dev_ppe_sram_sel(dev, reg);
	xscom_write(dev->npu->chip_id, OB_PPE_CSDR(dev->ob_chiplet), val);
}

static uint64_t npu3_dev_ppe_sram_read(struct npu3_dev *dev, uint32_t reg)
{
	uint64_t val;

	npu3_dev_ppe_sram_sel(dev, reg);
	xscom_read(dev->npu->chip_id, OB_PPE_CSDR(dev->ob_chiplet), &val);

	return val;
}

/* Software-implemented autonomous link training (SALT) */
static int64_t npu3_dev_salt(void *pvd, struct pci_cfg_reg_filter *pcrf,
			     uint32_t offset, uint32_t size, uint32_t *data,
			     bool write)
{
	struct npu3_dev *dev = ((struct pci_virt_device *)pvd)->data;
	unsigned long timeout;
	uint32_t cmd_reg;
	uint64_t val;

	if (size != 4 || offset != pcrf->start)
		return OPAL_PARAMETER;

	/* The config register before this one holds CMD_REG */
	PCI_VIRT_CFG_NORMAL_RD(pvd, pcrf->start - 4, 4, &cmd_reg);
	if (cmd_reg == 0xffffffff)
		return OPAL_PARAMETER;

	/* Check for another command in progress */
	val = npu3_dev_ppe_sram_read(dev, OB_PPE_SALT_CMD);
	if (GETFIELD(OB_PPE_SALT_CMD_READY, val)) {
		NPU3DEVINF(dev, "SALT_CMD 0x%x: Not ready\n", cmd_reg);
		return OPAL_BUSY;
	}

	val = OB_PPE_SALT_CMD_READY;
	val = SETFIELD(OB_PPE_SALT_CMD_RW, val, write);
	val = SETFIELD(OB_PPE_SALT_CMD_LINKNUM, val, npu3_chip_dev_index(dev));
	val = SETFIELD(OB_PPE_SALT_CMD_REG, val, cmd_reg);
	if (write)
		val = SETFIELD(OB_PPE_SALT_CMD_DATA, val, *data);

	npu3_dev_ppe_sram_write(dev, OB_PPE_SALT_CMD, val);

	/* Wait for the go bit to clear */
	timeout = mftb() + msecs_to_tb(1000);

	while (GETFIELD(OB_PPE_SALT_CMD_READY, val)) {
		if (tb_compare(mftb(), timeout) == TB_AAFTERB) {
			NPU3DEVINF(dev, "SALT_CMD 0x%x: Timeout\n", cmd_reg);
			return OPAL_BUSY;
		}

		val = npu3_dev_ppe_sram_read(dev, OB_PPE_SALT_CMD);
	}

	if (GETFIELD(OB_PPE_SALT_CMD_ERR, val))
		NPU3DEVINF(dev, "SALT_CMD 0x%x: Error\n", cmd_reg);

	if (!write)
		*data = GETFIELD(OB_PPE_SALT_CMD_DATA, val);

	return OPAL_SUCCESS;
}

#define VENDOR_CAP_LEN		0x1c
#define VENDOR_CAP_VERSION	0x02

static uint32_t npu3_cfg_populate_vendor_cap(struct npu3_dev *dev,
					     uint32_t start, uint32_t prev_cap)
{
	struct pci_virt_device *pvd = dev->nvlink.pvd;

	/* Capabilities list */
	PCI_VIRT_CFG_INIT_RO(pvd, prev_cap, 1, start);
	PCI_VIRT_CFG_INIT_RO(pvd, start, 1, PCI_CFG_CAP_ID_VENDOR);

	/* Length and version */
	PCI_VIRT_CFG_INIT_RO(pvd, start + 2, 1, VENDOR_CAP_LEN);
	PCI_VIRT_CFG_INIT_RO(pvd, start + 3, 1, VENDOR_CAP_VERSION);

	/*
	 * Defaults when the trap can't handle the read/write (eg. due to
	 * reading/writing less than 4 bytes).
	 */
	PCI_VIRT_CFG_INIT_RO(pvd, start + 4, 4, 0);
	PCI_VIRT_CFG_INIT_RO(pvd, start + 8, 4, 0);

	/* PHY procedure trap */
	pci_virt_add_filter(pvd, start + 4, 8,
			    PCI_REG_FLAG_READ | PCI_REG_FLAG_WRITE,
			    npu3_dev_procedure, NULL);

	/* Link index */
	PCI_VIRT_CFG_INIT_RO(pvd, start + 0xc, 1, npu3_chip_dev_index(dev));

	/* SALT registers */
	PCI_VIRT_CFG_INIT(pvd, start + 0x10, 4, 0xffffffff, 0, 0);
	PCI_VIRT_CFG_INIT_RO(pvd, start + 0x14, 4, 0);

	pci_virt_add_filter(pvd, start + 0x14, 4,
			    PCI_REG_FLAG_READ | PCI_REG_FLAG_WRITE,
			    npu3_dev_salt, NULL);

	return start + VENDOR_CAP_LEN;
}

static void npu3_cfg_populate(struct npu3_dev *dev)
{
	struct pci_virt_device *pvd = dev->nvlink.pvd;
	uint64_t addr;
	uint32_t pos;

	/* 0x00 - Vendor/Device ID */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_VENDOR_ID, 4, 0x04ea1014);

	/* 0x04 - Command/Status */
	PCI_VIRT_CFG_INIT(pvd, PCI_CFG_CMD, 4, 0x00100000, 0xffb802b8,
			  0xf9000000);

	pci_virt_add_filter(pvd, PCI_CFG_CMD, 1, PCI_REG_FLAG_WRITE,
			    npu3_cfg_cmd, NULL);

	/* 0x08 - Rev/Class/Cache */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_REV_ID, 4, 0x06800102);

	/* 0x0c - CLS/Latency Timer/Header/BIST */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_CACHE_LINE_SIZE, 4, 0x00800000);

	/* 0x10/14 - NTL BAR */
	addr = SETFIELD(0xf, dev->ntl_bar.addr,
			PCI_CFG_BAR_TYPE_MEM | PCI_CFG_BAR_MEM64);
	PCI_VIRT_CFG_INIT(pvd, PCI_CFG_BAR0, 4, lo32(addr), 0xf, 0);
	PCI_VIRT_CFG_INIT(pvd, PCI_CFG_BAR1, 4, hi32(addr), 0, 0);

	pci_virt_add_filter(pvd, PCI_CFG_BAR0, 8,
			    PCI_REG_FLAG_READ | PCI_REG_FLAG_WRITE,
			    npu3_cfg_bar, &dev->ntl_bar);

	/* 0x18/1c - GENID BAR */
	addr = SETFIELD(0xf, dev->genid_bar.addr,
			PCI_CFG_BAR_TYPE_MEM | PCI_CFG_BAR_MEM64);
	PCI_VIRT_CFG_INIT(pvd, PCI_CFG_BAR2, 4, lo32(addr), 0xf, 0);
	PCI_VIRT_CFG_INIT(pvd, PCI_CFG_BAR3, 4, hi32(addr), 0, 0);

	pci_virt_add_filter(pvd, PCI_CFG_BAR2, 8,
			    PCI_REG_FLAG_READ | PCI_REG_FLAG_WRITE,
			    npu3_cfg_bar, &dev->genid_bar);

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
	pos = npu3_cfg_populate_pcie_cap(dev, 0x40, PCI_CFG_CAP);
	pos = npu3_cfg_populate_vendor_cap(dev, pos, 0x41);
	PCI_VIRT_CFG_INIT_RO(pvd, pos + 1, 1, 0);
}

static void npu3_dev_create_pvd(struct npu3_dev *dev)
{
	struct npu3 *npu = dev->npu;
	struct phb *phb = &npu->nvlink.phb;

	dev->nvlink.pvd = pci_virt_add_device(phb, dev->index, 0x100, dev);
	if (!dev->nvlink.pvd)
		return;

	phb->scan_map |= 0x1 << GETFIELD(0xf8, dev->nvlink.pvd->bdfn);
	npu3_cfg_populate(dev);
}

static void npu3_dt_add_mmio_atsd(struct npu3 *npu)
{
	struct dt_node *dn = npu->nvlink.phb.dt_node;
	uint64_t mmio_atsd[NPU3_XTS_ATSD_MAX];

	for (uint32_t i = 0; i < NPU3_XTS_ATSD_MAX; i++)
		mmio_atsd[i] = npu->regs[0] + NPU3_XTS_ATSD_LAUNCH(i);

	dt_add_property(dn, "ibm,mmio-atsd", mmio_atsd, sizeof(mmio_atsd));
}

static void npu3_dt_add_mmio_window(struct npu3 *npu)
{
	struct dt_node *dn = npu->nvlink.phb.dt_node;
	uint32_t ntl0_index = npu->index * NPU3_LINKS_PER_NPU;
	uint64_t addr, size, win[2];

	/* Device MMIO window (NTL/GENID regs only) */
	phys_map_get(npu->chip_id, NPU_NTL, ntl0_index, &win[0], NULL);
	phys_map_get(npu->chip_id, NPU_GENID, npu->index, &addr, &size);
	win[1] = addr + size - win[0];

	dt_add_property(dn, "ibm,mmio-window", win, sizeof(win));
	dt_add_property_cells(dn, "ranges", 0x02000000,
			      hi32(win[0]), lo32(win[0]),
			      hi32(win[0]), lo32(win[0]),
			      hi32(win[1]), lo32(win[1]));
}

/* NDL No-Stall Event level */
static uint32_t npu3_dev_interrupt_level(struct npu3_dev *dev)
{
	const uint32_t level[12] = {  1,  3,  5,  7,  9, 11,
				     43, 45, 47, 49, 51, 53 };

	return level[npu3_chip_dev_index(dev)];
}

static void npu3_dt_add_interrupts(struct npu3 *npu)
{
	struct dt_node *dn = npu->nvlink.phb.dt_node;
	uint32_t *map, icsp, i = 0;
	struct npu3_dev *dev;
	size_t map_size = 0;

	npu3_for_each_nvlink_dev(dev, npu)
		map_size += sizeof(*map) * 7;

	if (!map_size)
		return;

	icsp = get_ics_phandle();
	map = zalloc(map_size);
	assert(map);

	npu3_for_each_nvlink_dev(dev, npu) {
		map[i] = dev->nvlink.pvd->bdfn << 8;
		map[i + 3] = 1;		/* INT A */
		map[i + 4] = icsp;	/* interrupt-parent */
		map[i + 5] = npu->irq_base + npu3_dev_interrupt_level(dev);
		map[i + 6] = 0;		/* 0 = EDGE, 1 = LEVEL */
		i += 7;
	}

	dt_add_property_cells(dn, "interrupt-parent", icsp);
	dt_add_property(dn, "interrupt-map", map, map_size);
	dt_add_property_cells(dn, "interrupt-map-mask", 0xff00, 0x0, 0x0, 0x7);

	free(map);
}

/* Populate PCI root device node */
static void npu3_dt_add_props(struct npu3 *npu)
{
	struct dt_node *dn = npu->nvlink.phb.dt_node;

	dt_add_property_cells(dn, "#address-cells", 3);
	dt_add_property_cells(dn, "#size-cells", 2);
	dt_add_property_cells(dn, "#interrupt-cells", 1);
	dt_add_property_cells(dn, "bus-range", 0, 0xff);
	dt_add_property_cells(dn, "clock-frequency", 0x200, 0);

	dt_add_property_strings(dn, "device_type", "pciex");

	/*
	 * To the OS, npu2 and npu3 are both ibm,ioda2-npu2-phb. The added
	 * ibm,ioda3-npu3-phb allows for possible quirks.
	 */
	dt_add_property_strings(dn, "compatible",
				"ibm,power9-npu-pciex",
				"ibm,ioda2-npu2-phb",
				"ibm,ioda2-npu3-phb");

	dt_add_property_cells(dn, "ibm,phb-index",
			      npu3_get_phb_index(npu->index));
	dt_add_property_cells(dn, "ibm,phb-diag-data-size", 0);
	dt_add_property_cells(dn, "ibm,opal-num-pes", NPU3_MAX_PE_NUM);
	dt_add_property_cells(dn, "ibm,opal-reserved-pe", NPU3_RESERVED_PE_NUM);
	dt_add_property_cells(dn, "ibm,supported-tce-sizes",
			      12, /* 4K */
			      16, /* 64K */
			      24, /* 16M */
			      28); /* 256M */

	dt_add_property_cells(dn, "ibm,chip-id", npu->chip_id);
	dt_add_property_cells(dn, "ibm,npu-index", npu->index);
	dt_add_property_cells(dn, "ibm,npcq", npu->dt_node->phandle);
	dt_add_property_cells(dn, "ibm,xscom-base", npu->xscom_base);
	dt_add_property_cells(dn, "ibm,links", NPU3_LINKS_PER_NPU);

	dt_add_property(dn, "reg", npu->regs, sizeof(npu->regs));

	npu3_dt_add_mmio_atsd(npu);
	npu3_dt_add_mmio_window(npu);
	npu3_dt_add_interrupts(npu);
}

void npu3_init_nvlink(struct npu3 *npu)
{
	struct npu3_dev *dev;

	if (!npu3_next_dev(npu, NULL, NPU3_DEV_TYPE_NVLINK))
		return;

	npu3_init_hw(npu);
	npu3_create_phb(npu);

	npu3_for_each_nvlink_dev(dev, npu)
		npu3_dev_create_pvd(dev);

	npu3_dt_add_props(npu);

	/* TODO: Sort out if/why we still can't enable this */
	disable_fast_reboot("NVLink device enabled");
}

static int64_t npu3_init_context_pid(struct npu3 *npu, uint32_t index,
				     uint64_t msr)
{
	uint64_t map, old_map;

	/* Unfiltered XTS mode; index is lparshort */
	map = SETFIELD(NPU3_XTS_PID_MAP_LPARSHORT, 0ull, index);

	/* Enable this mapping for both real and virtual addresses */
	map |= NPU3_XTS_PID_MAP_VALID_ATRGPA0 | NPU3_XTS_PID_MAP_VALID_ATRGPA1;

	/* Enable TLBIE/MMIOSD forwarding for this entry */
	map |= NPU3_XTS_PID_MAP_VALID_ATSD;

	/* Set the relevant MSR bits */
	if (msr & MSR_DR)
		map |= NPU3_XTS_PID_MAP_MSR_DR;

	if (msr & MSR_HV)
		map |= NPU3_XTS_PID_MAP_MSR_HV;

	if (msr & MSR_PR)
		map |= NPU3_XTS_PID_MAP_MSR_PR;

	/* We don't support anything other than 64-bit so hardcode it here */
	map |= NPU3_XTS_PID_MAP_MSR_SF;

	old_map = npu3_read(npu, NPU3_XTS_PID_MAP(index));

	/* Error out if this entry is already set with different msr bits */
	if (old_map && GETFIELD(NPU3_XTS_PID_MAP_MSR, old_map) !=
		       GETFIELD(NPU3_XTS_PID_MAP_MSR, map)) {
		NPU3ERR(npu, "%s: Unexpected MSR value\n", __func__);
		return OPAL_PARAMETER;
	}

	if (!old_map) {
		NPU3DBG(npu, "XTS_PID_MAP[%03d] = 0x%08llx\n", index, map);
		npu3_write(npu, NPU3_XTS_PID_MAP(index), map);
	}

	npu->nvlink.ctx_ref[index]++;

	return OPAL_SUCCESS;
}

#define NPU3_VALID_ATS_MSR_BITS (MSR_DR | MSR_HV | MSR_PR | MSR_SF)

/*
 * Allocate a context ID and initialize the tables with the relevant
 * information. Returns the ID or error if one couldn't be allocated.
 */
int64_t npu3_init_context(struct phb *phb, uint64_t msr, uint64_t bdf)
{
	struct npu3 *npu = npu3_phb_to_npu(phb);
	uint32_t lparshort, i;
	uint64_t map;
	int64_t rc;

	/*
	 * MSR bits should be masked by the caller to allow for future
	 * expansion if required.
	 */
	if (msr & ~NPU3_VALID_ATS_MSR_BITS)
		return OPAL_UNSUPPORTED;

	lock(&npu->lock);

	for (i = 0; i < NPU3_XTS_BDF_MAP_MAX; i++) {
		map = npu3_read(npu, NPU3_XTS_BDF_MAP(i));

		if (map && GETFIELD(NPU3_XTS_BDF_MAP_BDF, map) == bdf)
			break;
	}

	if (i == NPU3_XTS_BDF_MAP_MAX) {
		NPU3ERR(npu, "LPARID not associated with any GPU\n");
		rc = OPAL_PARAMETER;
		goto out;
	}

	lparshort = GETFIELD(NPU3_XTS_BDF_MAP_LPARSHORT, map);
	NPU3DBG(npu, "Found LPARSHORT 0x%x for bdf %02llx:%02llx.%llx\n",
		lparshort, PCI_BUS_NUM(bdf), PCI_DEV(bdf), PCI_FUNC(bdf));

	rc = npu3_init_context_pid(npu, lparshort, msr);
	if (rc)
		goto out;

	if (!(map & NPU3_XTS_BDF_MAP_VALID)) {
		map |= NPU3_XTS_BDF_MAP_VALID;
		npu3_write(npu, NPU3_XTS_BDF_MAP(i), map);
	}

	rc = lparshort;

out:
	unlock(&npu->lock);
	return rc;
}

static int64_t npu3_destroy_context_pid(struct npu3 *npu, uint32_t index)
{
	if (!npu->nvlink.ctx_ref[index])
		return OPAL_PARAMETER;

	/* Only destroy when refcount hits 0 */
	if (--npu->nvlink.ctx_ref[index])
		return OPAL_PARTIAL;

	NPU3DBG(npu, "XTS_PID_MAP[%03d] = 0 (destroy)\n", index);
	npu3_write(npu, NPU3_XTS_PID_MAP(index), 0ull);

	return OPAL_SUCCESS;
}

int64_t npu3_destroy_context(struct phb *phb, uint64_t bdf)
{
	struct npu3 *npu = npu3_phb_to_npu(phb);
	uint32_t lparshort, i;
	int64_t map, rc;

	lock(&npu->lock);

	for (i = 0; i < NPU3_XTS_BDF_MAP_MAX; i++) {
		map = npu3_read(npu, NPU3_XTS_BDF_MAP(i));

		if (map && GETFIELD(NPU3_XTS_BDF_MAP_BDF, map) == bdf)
			break;
	}

	if (i == NPU3_XTS_BDF_MAP_MAX) {
		NPU3ERR(npu, "LPARID not associated with any GPU\n");
		rc = OPAL_PARAMETER;
		goto out;
	}

	lparshort = GETFIELD(NPU3_XTS_BDF_MAP_LPARSHORT, map);
	rc = npu3_destroy_context_pid(npu, lparshort);

out:
	unlock(&npu->lock);
	return rc;
}

/* Map the given virtual bdf to lparid with given lpcr */
int64_t npu3_map_lpar(struct phb *phb, uint64_t bdf, uint64_t lparid,
		      uint64_t lpcr)
{
	struct npu3 *npu = npu3_phb_to_npu(phb);
	struct npu3_dev *dev;
	int64_t rc = OPAL_SUCCESS;
	uint64_t map, val;
	uint32_t i;

	/*
	 * The LPCR bits are only required for hash based ATS, which we don't
	 * currently support, but may need to in the future.
	 */
	if (lpcr)
		return OPAL_UNSUPPORTED;

	lock(&npu->lock);

	/* Update the entry if it already exists */
	for (i = 0; i < NPU3_XTS_BDF_MAP_MAX; i++) {
		map = npu3_read(npu, NPU3_XTS_BDF_MAP(i));

		if (map && GETFIELD(NPU3_XTS_BDF_MAP_BDF, map) == bdf)
			break;
	}

	if (i == NPU3_XTS_BDF_MAP_MAX) {
		/* No existing mapping found, find space for a new one */
		for (i = 0; i < NPU3_XTS_BDF_MAP_MAX; i++)
			if (!npu3_read(npu, NPU3_XTS_BDF_MAP(i)))
				break;
	}

	if (i == NPU3_XTS_BDF_MAP_MAX) {
		NPU3ERR(npu, "No free XTS_BDF[] entry\n");
		rc = OPAL_RESOURCE;
		goto out;
	}

	map = NPU3_XTS_BDF_MAP_UNFILT;
	map = SETFIELD(NPU3_XTS_BDF_MAP_BDF, map, bdf);
	map = SETFIELD(NPU3_XTS_BDF_MAP_LPARID, map, lparid);
	map = SETFIELD(NPU3_XTS_BDF_MAP_LPARSHORT, map, i);

	/* We only support radix at the moment */
	map = SETFIELD(NPU3_XTS_BDF_MAP_XLAT, map, 0x3);

	/* Find a link on which to send ATSDs for this device */
	npu3_for_each_nvlink_dev(dev, npu)
		if (dev->nvlink.gpu->bdfn == bdf)
			break;

	if (!dev || dev->nvlink.gpu->bdfn != bdf) {
		NPU3ERR(npu, "Can't find a link for bdf %02llx:%02llx.%llx\n",
			PCI_BUS_NUM(bdf), PCI_DEV(bdf), PCI_FUNC(bdf));
		rc = OPAL_PARAMETER;
		goto out;
	}

	map = SETFIELD(NPU3_XTS_BDF_MAP_BRICK, map, dev->index);

	NPU3DBG(npu, "XTS_BDF_MAP[%03d] = 0x%08llx\n", i, map);
	npu3_write(npu, NPU3_XTS_BDF_MAP(i), map);

	/* We need to allocate an ATSD per link */
	val = SETFIELD(NPU3_XTS_ATSD_HYP_LPARID, 0ull, lparid);
	if (!lparid)
		val |= NPU3_XTS_ATSD_HYP_MSR_HV;

	npu3_write(npu, NPU3_XTS_ATSD_HYP(dev->index), val);

out:
	unlock(&npu->lock);
	return rc;
}

static int64_t npu3_relaxed_order_enable(struct npu3 *npu, uint64_t src)
{
	struct npu3_dev *dev;
	uint32_t i;

	for (i = 0; i < NPU3_RELAXED_SRC_MAX; i++)
		if (npu3_read(npu, NPU3_RELAXED_SRC(i)) == src)
			return OPAL_SUCCESS; /* Already enabled */

	/* Find somewhere to write this source */
	for (i = 0; i < NPU3_RELAXED_SRC_MAX; i++)
		if (!npu3_read(npu, NPU3_RELAXED_SRC(i)))
			break;

	if (i == NPU3_RELAXED_SRC_MAX) {
		NPU3ERR(npu, "Insufficient resources to activate relaxed ordering mode\n");
		return OPAL_RESOURCE;
	}

	npu3_write(npu, NPU3_RELAXED_SRC(i), src);

	npu3_for_each_nvlink_dev(dev, npu) {
		uint64_t val = npu3_read(npu, NPU3_RELAXED_CFG2(dev->index));

		val |= NPU3_RELAXED_CFG2_SRC_WRENA(i) |
		       NPU3_RELAXED_CFG2_SRC_RDENA(i);
		npu3_write(npu, NPU3_RELAXED_CFG2(dev->index), val);
	}

	return OPAL_SUCCESS;
}

static void npu3_relaxed_order_disable(struct npu3 *npu, uint64_t src)
{
	struct npu3_dev *dev;
	uint32_t i;

	for (i = 0; i < NPU3_RELAXED_SRC_MAX; i++)
		if (npu3_read(npu, NPU3_RELAXED_SRC(i)) == src)
			break;

	if (i == NPU3_RELAXED_SRC_MAX)
		return; /* Already disabled */

	npu3_for_each_nvlink_dev(dev, npu) {
		uint64_t val = npu3_read(npu, NPU3_RELAXED_CFG2(dev->index));

		val &= ~NPU3_RELAXED_CFG2_SRC_WRENA(i);
		val &= ~NPU3_RELAXED_CFG2_SRC_RDENA(i);
		npu3_write(npu, NPU3_RELAXED_CFG2(dev->index), val);
	}

	npu3_write(npu, NPU3_RELAXED_SRC(i), 0ull);
}

/* Enable or disable relaxed ordering on all nvlinks for a given PEC. */
int64_t npu3_set_relaxed_order(struct phb *phb, uint32_t gcid, int pec,
			       bool enable)
{
	struct npu3 *npu = npu3_phb_to_npu(phb);
	int64_t rc = OPAL_SUCCESS;
	uint64_t src;

	NPU3INF(npu, "%s relaxed ordering for PEC %d on chip %d\n",
		enable ? "Enabling" : "Disabling",
		pec, gcid);

	lock(&npu->lock);

	src = SETFIELD(NPU3_RELAXED_SRC_GRPCHP, 0ull, gcid);
	src = SETFIELD(NPU3_RELAXED_SRC_PEC, src, pec);
	src = SETFIELD(NPU3_RELAXED_SRC_RDSTART, src, 0);
	src = SETFIELD(NPU3_RELAXED_SRC_RDEND, src, 47);
	src = SETFIELD(NPU3_RELAXED_SRC_WRSTART, src, 0);
	src = SETFIELD(NPU3_RELAXED_SRC_WREND, src, 23);

	if (enable)
		rc = npu3_relaxed_order_enable(npu, src);
	else
		npu3_relaxed_order_disable(npu, src);

	unlock(&npu->lock);
	return rc;
}
