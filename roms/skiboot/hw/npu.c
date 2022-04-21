// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * NVLink1, supported by the NPU (POWER8)
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <skiboot.h>
#include <io.h>
#include <timebase.h>
#include <pci.h>
#include <pci-cfg.h>
#include <pci-virt.h>
#include <pci-slot.h>
#include <interrupts.h>
#include <opal.h>
#include <opal-api.h>
#include <cpu.h>
#include <device.h>
#include <ccan/str/str.h>
#include <ccan/array_size/array_size.h>
#include <ccan/build_assert/build_assert.h>
#include <affinity.h>
#include <npu-regs.h>
#include <npu.h>
#include <xscom.h>
#include <string.h>

/*
 * Terminology:
 *
 *  Brick - A group of either 8 TX or 8 RX lanes
 *  Link - A group of 8 TX and 8 RX lanes
 *
 * Each link is represented in system software as an emulated PCI
 * device. Garrison has two chips each with 4 links, therefore there
 * are 8 emulated PCI devices in total.
 *
 *  +----------------------------------------------------------------+
 *  |              PBCQ3 (SCOM Base Address 0x2012c00)               |
 *  |               PHB3 (SCOM Base Address 0x9012c00)               |
 *  +----------------------------------------------------------------+
 *                          ||||||||  ||||||||
 *                          ||||||||  ||||||||
 *                          ||||||||  ||||||||
 *                          ||||||||  ||||||||
 *  +----------------------------------------------------------------+
 *  |                             PCIe x8                            |
 *  +----------------------------------------------------------------+
 *  |                               GPU0                             |
 *  +--------------------------------+-------------------------------+
 *  |           NV Link 1            |           NV Link 0           |
 *  +---------------+----------------+---------------+---------------+
 *  |      RX       |      TX        |      RX       |      TX       |
 *  +---------------+----------------+---------------+---------------+
 *      ||||||||        ||||||||         ||||||||        ||||||||
 *      ||||||||        ||||||||         ||||||||        ||||||||
 *      ||||||||        ||||||||         ||||||||        ||||||||
 *      ||||||||        ||||||||         ||||||||        ||||||||
 *  +---------------+----------------+---------------+---------------+
 *  |      TX       |      RX        |      TX       |      RX       |
 *  +---------------+----------------+---------------+---------------+
 *  |           Lanes [0:7]         PHY 0       Lanes [8:15]         |
 *  |               SCOM Base Address 0x8000080008010c3f             |
 *  +--------------------------------+-------------------------------+
 *  |          Link 0 NDL/NTL        |         Link 1 NTL/NDL        |
 *  |   SCOM Base Address 0x8013c00  |  SCOM Base Address 0x8013c40  |
 *  +--------------------------------+-------------------------------+
 *  |                                                                |
 *  |          Address Translation/AT (shared for all links)         |
 *  |                 SCOM Base Address 0x8013d80                    |
 *  |                                                                |
 *  +--------------------------------+-------------------------------+
 *  |          Link 3 NDL/NTL        |         Link 4 NTL/NDL        |
 *  |   SCOM Base Address 0x8013d00  |  SCOM Base Address 0x8013d40  |
 *  +--------------------------------+-------------------------------+
 *  |           Lanes [8:15]        PHY 1       Lanes [0:7]          |
 *  |               SCOM Base Address 0x8000080008010c7f             |
 *  +---------------+----------------+---------------+---------------+
 *  |      TX       |      RX        |      TX       |      RX       |
 *  +---------------+----------------+---------------+---------------+
 *      ||||||||        ||||||||         ||||||||        ||||||||
 *      ||||||||        ||||||||         ||||||||        ||||||||
 *      ||||||||        ||||||||         ||||||||        ||||||||
 *      ||||||||        ||||||||         ||||||||        ||||||||
 *  +---------------+----------------+---------------+---------------+
 *  |      RX       |      TX        |      RX       |      TX       |
 *  +---------------+----------------+---------------+---------------+
 *  |           NV Link 2            |           NV Link 3           |
 *  +--------------------------------+-------------------------------+
 *  |                               GPU1                             |
 *  +----------------------------------------------------------------+
 *  |                             PCIe x8                            |
 *  +----------------------------------------------------------------+
 *                          ||||||||  ||||||||
 *                          ||||||||  ||||||||
 *                          ||||||||  ||||||||
 *                          ||||||||  ||||||||
 *  +----------------------------------------------------------------+
 *  |               PHB2 (SCOM Base Address 0x9012800)               |
 *  |              PBCQ2 (SCOM Base Address 0x2012800)               |
 *  +----------------------------------------------------------------+
 *
 */

static struct npu_dev_cap *npu_dev_find_capability(struct npu_dev *dev,
						   uint16_t id);

#define OPAL_NPU_VERSION          0x02

#define PCIE_CAP_START	          0x40
#define PCIE_CAP_END	          0x80
#define VENDOR_CAP_START          0x80
#define VENDOR_CAP_END	          0x90

#define VENDOR_CAP_PCI_DEV_OFFSET 0x0d

/* Returns the scom base for the given link index */
static uint64_t npu_link_scom_base(struct dt_node *dn, uint32_t scom_base,
				   int index)
{
	struct dt_node *link;
	uint32_t link_index;
	char namebuf[32];

	snprintf(namebuf, sizeof(namebuf), "link@%x", index);
	link = dt_find_by_name(dn, namebuf);
	assert(link);
	link_index = dt_prop_get_u32(link, "ibm,npu-link-index");
	return scom_base + (link_index * NPU_LINK_SIZE);
}

static uint64_t get_bar_size(uint64_t bar)
{
	return (1 << GETFIELD(NX_MMIO_BAR_SIZE, bar)) * 0x10000;
}

/* Update the changes of the device BAR to link BARs */
static void npu_dev_bar_update(uint32_t gcid, struct npu_dev_bar *bar,
			       bool enable)
{
	uint64_t val;

	if (!bar->xscom)
		return;

	val = bar->base;
	val = SETFIELD(NX_MMIO_BAR_SIZE, val, ilog2(bar->size / 0x10000));
	if (enable)
		val |= NX_MMIO_BAR_ENABLE;
	xscom_write(gcid, bar->xscom, val);
}

/* Trap for PCI command (0x4) to enable or disable device's BARs */
static int64_t npu_dev_cfg_write_cmd(void *dev,
				     struct pci_cfg_reg_filter *pcrf __unused,
				     uint32_t offset, uint32_t size,
				     uint32_t *data, bool write)
{
	struct pci_virt_device *pvd = dev;
	struct npu_dev *ndev = pvd->data;
	bool enable;

	if (!write)
		return OPAL_PARTIAL;

	if (offset != PCI_CFG_CMD)
		return OPAL_PARAMETER;
	if (size != 1 && size != 2 && size != 4)
		return OPAL_PARAMETER;

	/* Update device BARs and link BARs will be syncrhonized
	 * with hardware automatically.
	 */
	enable = !!(*data & PCI_CFG_CMD_MEM_EN);
	npu_dev_bar_update(ndev->npu->chip_id, &ndev->bar, enable);

	/* Normal path to update PCI config buffer */
	return OPAL_PARTIAL;
}

/*
 * Trap for memory BARs: 0xFF's should be written to BAR register
 * prior to getting its size.
 */
static int64_t npu_dev_cfg_bar_read(struct npu_dev *dev __unused,
				    struct pci_cfg_reg_filter *pcrf,
				    uint32_t offset, uint32_t size,
				    uint32_t *data)
{
	struct npu_dev_bar *bar = (struct npu_dev_bar *)(pcrf->data);

	/* Revert to normal path if we weren't trapped for BAR size */
	if (!bar->trapped)
		return OPAL_PARTIAL;

	if (offset != pcrf->start &&
	    offset != pcrf->start + 4)
		return OPAL_PARAMETER;
	if (size != 4)
		return OPAL_PARAMETER;

	bar->trapped = false;
	*data = bar->bar_sz;
	return OPAL_SUCCESS;
}

static int64_t npu_dev_cfg_bar_write(struct npu_dev *dev,
				     struct pci_cfg_reg_filter *pcrf,
				     uint32_t offset, uint32_t size,
				     uint32_t data)
{
	struct pci_virt_device *pvd = dev->pvd;
	struct npu_dev_bar *bar = (struct npu_dev_bar *)(pcrf->data);
	uint32_t pci_cmd;

	if (offset != pcrf->start &&
	    offset != pcrf->start + 4)
		return OPAL_PARAMETER;
	if (size != 4)
		return OPAL_PARAMETER;

	/* Return BAR size on next read */
	if (data == 0xffffffff) {
		bar->trapped = true;
		if (offset == pcrf->start)
			bar->bar_sz = (bar->size & 0xffffffff);
		else
			bar->bar_sz = (bar->size >> 32);

		return OPAL_SUCCESS;
	}

	/* Update BAR base address */
	if (offset == pcrf->start) {
		bar->base &= 0xffffffff00000000UL;
		bar->base |= (data & 0xfffffff0);
	} else {
		bar->base &= 0x00000000ffffffffUL;
		bar->base |= ((uint64_t)data << 32);

		PCI_VIRT_CFG_NORMAL_RD(pvd, PCI_CFG_CMD, 4, &pci_cmd);
		npu_dev_bar_update(dev->npu->chip_id, bar,
				   !!(pci_cmd & PCI_CFG_CMD_MEM_EN));
	}

	/* We still depend on the normal path to update the
	 * cached config buffer.
	 */
	return OPAL_PARAMETER;
}

static int64_t npu_dev_cfg_bar(void *dev, struct pci_cfg_reg_filter *pcrf,
			       uint32_t offset, uint32_t len, uint32_t *data,
			       bool write)
{
	struct pci_virt_device *pvd = dev;
	struct npu_dev *ndev = pvd->data;

	if (write)
		return npu_dev_cfg_bar_write(ndev, pcrf, offset, len, *data);

	return npu_dev_cfg_bar_read(ndev, pcrf, offset, len, data);
}

static int64_t npu_dev_cfg_exp_devcap(void *dev,
		struct pci_cfg_reg_filter *pcrf __unused,
		uint32_t offset, uint32_t size,
		uint32_t *data, bool write)
{
	struct pci_virt_device *pvd = dev;
	struct npu_dev *ndev = pvd->data;

	assert(write);

	if ((size != 2) || (offset & 1)) {
		/* Short config writes are not supported */
		prlog(PR_ERR, "NPU%d: Unsupported write to pcie control register\n",
		      ndev->phb->opal_id);
		return OPAL_PARAMETER;
	}

	if (*data & PCICAP_EXP_DEVCTL_FUNC_RESET)
		npu_dev_procedure_reset(ndev);

	return OPAL_PARTIAL;
}

static struct npu_dev *bdfn_to_npu_dev(struct npu *p, uint32_t bdfn)
{
	struct pci_virt_device *pvd;

	/* Sanity check */
	if (bdfn & ~0xff)
		return NULL;

	pvd = pci_virt_find_device(&p->phb, bdfn);
	if (pvd)
		return pvd->data;

	return NULL;
}

#define NPU_CFG_READ(size, type)						\
static int64_t npu_cfg_read##size(struct phb *phb, uint32_t bdfn,		\
				  uint32_t offset, type *data)			\
{										\
	uint32_t val;								\
	int64_t ret;								\
										\
	ret = pci_virt_cfg_read(phb, bdfn, offset, sizeof(*data), &val);	\
	*data = (type)val;							\
	return ret;								\
}
#define NPU_CFG_WRITE(size, type)						\
static int64_t npu_cfg_write##size(struct phb *phb, uint32_t bdfn,		\
				   uint32_t offset, type data)			\
{										\
	uint32_t val = data;                                            	\
										\
	return pci_virt_cfg_write(phb, bdfn, offset, sizeof(data), val);	\
}

NPU_CFG_READ(8,   u8);
NPU_CFG_READ(16,  u16);
NPU_CFG_READ(32,  u32);
NPU_CFG_WRITE(8,  u8);
NPU_CFG_WRITE(16, u16);
NPU_CFG_WRITE(32, u32);

static int __npu_dev_bind_pci_dev(struct phb *phb __unused,
				  struct pci_device *pd,
				  void *data)
{
	struct npu_dev *dev = data;
	struct dt_node *pci_dt_node;
	char *pcislot;

	/* Ignore non-nvidia PCI devices */
	if ((pd->vdid & 0xffff) != 0x10de)
		return 0;

	/* Find the PCI device's slot location */
	for (pci_dt_node = pd->dn;
	     pci_dt_node && !dt_find_property(pci_dt_node, "ibm,slot-label");
	     pci_dt_node = pci_dt_node->parent);

	if (!pci_dt_node)
		return 0;

	pcislot = (char *)dt_prop_get(pci_dt_node, "ibm,slot-label");

	prlog(PR_DEBUG, "NPU: comparing GPU %s and NPU %s\n",
	      pcislot, dev->slot_label);

	if (streq(pcislot, dev->slot_label))
		return 1;

	return 0;
}

static void npu_dev_bind_pci_dev(struct npu_dev *dev)
{
	struct phb *phb;
	uint32_t i;

	if (dev->pd)
		return;

	for (i = 0; i < 64; i++) {
		if (dev->npu->phb.opal_id == i)
			continue;

		phb = pci_get_phb(i);
		if (!phb)
			continue;

		dev->pd = pci_walk_dev(phb, NULL, __npu_dev_bind_pci_dev, dev);
		if (dev->pd) {
			dev->phb = phb;
			/* Found the device, set the bit in config space */
			PCI_VIRT_CFG_INIT_RO(dev->pvd, VENDOR_CAP_START +
				VENDOR_CAP_PCI_DEV_OFFSET, 1, 0x01);
			return;
		}
	}

	prlog(PR_INFO, "%s: No PCI device for NPU device %04x:%02x:%02x.%x to bind to. If you expect a GPU to be there, this is a problem.\n",
	      __func__, dev->npu->phb.opal_id,
	      dev->pvd->bdfn >> 8 & 0xff,
	      dev->pvd->bdfn >> 3 & 0x1f,
	      dev->pvd->bdfn & 0x7);

}

static struct lock pci_npu_phandle_lock = LOCK_UNLOCKED;

/* Appends an NPU phandle to the given PCI device node ibm,npu
 * property */
static void npu_append_pci_phandle(struct dt_node *dn, u32 phandle)
{
	uint32_t *npu_phandles;
	struct dt_property *pci_npu_phandle_prop;
	size_t prop_len;

	/* Use a lock to make sure no one else has a reference to an
	 * ibm,npu property (this assumes this is the only function
	 * that holds a reference to it). */
	lock(&pci_npu_phandle_lock);

	/* This function shouldn't be called unless ibm,npu exists */
	pci_npu_phandle_prop = (struct dt_property *)
		dt_require_property(dn, "ibm,npu", -1);

	/* Need to append to the properties */
	prop_len = pci_npu_phandle_prop->len;
	prop_len += sizeof(*npu_phandles);
	dt_resize_property(&pci_npu_phandle_prop, prop_len);

	npu_phandles = (uint32_t *) pci_npu_phandle_prop->prop;
	npu_phandles[prop_len/sizeof(*npu_phandles) - 1] = phandle;
	unlock(&pci_npu_phandle_lock);
}

static int npu_dn_fixup(struct phb *phb,
			struct pci_device *pd,
			void *data __unused)
{
	struct npu *p = phb_to_npu(phb);
	struct npu_dev *dev;

	dev = bdfn_to_npu_dev(p, pd->bdfn);
	assert(dev);

	if (dev->phb || dev->pd)
		return 0;

	/* NPU devices require a slot location to associate with GPUs */
	dev->slot_label = dt_prop_get(pd->dn, "ibm,slot-label");

	/* Bind the emulated PCI device with the real one, which can't
	 * be done until the PCI devices are populated. Once the real
	 * PCI device is identified, we also need fix the device-tree
	 * for it
	 */
	npu_dev_bind_pci_dev(dev);
	if (dev->phb && dev->pd && dev->pd->dn) {
		if (dt_find_property(dev->pd->dn, "ibm,npu"))
			npu_append_pci_phandle(dev->pd->dn, pd->dn->phandle);
		else
			dt_add_property_cells(dev->pd->dn, "ibm,npu", pd->dn->phandle);

		dt_add_property_cells(pd->dn, "ibm,gpu", dev->pd->dn->phandle);
	}

	return 0;
}

static void npu_phb_final_fixup(struct phb *phb)
{
	pci_walk_dev(phb, NULL, npu_dn_fixup, NULL);
}

static void npu_ioda_init(struct npu *p)
{
	uint64_t *data64;
	uint32_t i;

	/* LXIVT - Disable all LSIs */
	for (i = 0; i < ARRAY_SIZE(p->lxive_cache); i++) {
		data64 = &p->lxive_cache[i];
		*data64 = SETFIELD(NPU_IODA_LXIVT_PRIORITY, 0ul, 0xff);
		*data64 = SETFIELD(NPU_IODA_LXIVT_SERVER, *data64, 0);
	}

	/* PCT - Reset to reserved PE# */
	for (i = 0; i < ARRAY_SIZE(p->pce_cache); i++) {
		data64 = &p->pce_cache[i];
		*data64 = SETFIELD(NPU_IODA_PCT_PE, 0ul, 0ul);
		*data64 |= NPU_IODA_PCT_LINK_ENABLED;
	}

	/* Clear TVT */
	memset(p->tve_cache, 0, sizeof(p->tve_cache));
}

static int64_t npu_ioda_reset(struct phb *phb, bool purge)
{
	struct npu *p = phb_to_npu(phb);
	uint32_t i;

	if (purge) {
		NPUDBG(p, "Purging all IODA tables...\n");
		npu_ioda_init(p);
	}

	/* LIST */
	npu_ioda_sel(p, NPU_IODA_TBL_LIST, 0, true);
	for (i = 0; i < 8; i++)
		out_be64(p->at_regs + NPU_IODA_DATA0, 0x1);

	/* LIXVT */
	npu_ioda_sel(p, NPU_IODA_TBL_LXIVT, 0, true);
	for (i = 0; i < ARRAY_SIZE(p->lxive_cache); i++)
		out_be64(p->at_regs + NPU_IODA_DATA0, p->lxive_cache[i]);

	/* PCT */
	npu_ioda_sel(p, NPU_IODA_TBL_PCT, 0, true);
	for (i = 0; i < ARRAY_SIZE(p->pce_cache); i++)
		out_be64(p->at_regs + NPU_IODA_DATA0, p->pce_cache[i]);

	/* TVT */
	npu_ioda_sel(p, NPU_IODA_TBL_TVT, 0, true);
	for (i = 0; i < ARRAY_SIZE(p->tve_cache); i++)
		out_be64(p->at_regs + NPU_IODA_DATA0, p->tve_cache[i]);

	return OPAL_SUCCESS;
}

static int npu_isn_valid(struct npu *p, uint32_t isn)
{
	if (p->chip_id != p8_irq_to_chip(isn) || p->index != 0 ||
	    NPU_IRQ_NUM(isn) < NPU_LSI_IRQ_MIN ||
	    NPU_IRQ_NUM(isn) > NPU_LSI_IRQ_MAX) {
		/**
		 * @fwts-label NPUisnInvalid
		 * @fwts-advice NVLink not functional
		 */
		prlog(PR_ERR, "NPU%d: isn 0x%x not valid for this NPU\n",
		      p->phb.opal_id, isn);
		return false;
	}

	return true;
}

static int64_t npu_lsi_get_xive(struct irq_source *is, uint32_t isn,
				uint16_t *server, uint8_t *prio)
{
	struct npu *p = is->data;
	uint32_t irq = NPU_IRQ_NUM(isn);
	uint64_t lxive;

	if (!npu_isn_valid(p, isn))
		return OPAL_PARAMETER;

	/* The content is fetched from the cache, which requires
	 * that the initial cache should be initialized with the
	 * default values
	 */
	irq -= NPU_LSI_IRQ_MIN;
	lxive = p->lxive_cache[irq];
	*server = GETFIELD(NPU_IODA_LXIVT_SERVER, lxive);
	*prio = GETFIELD(NPU_IODA_LXIVT_PRIORITY, lxive);

	return OPAL_SUCCESS;
}

static int64_t npu_lsi_set_xive(struct irq_source *is, uint32_t isn,
				uint16_t server, uint8_t prio)
{
	struct npu *p = is->data;
	uint32_t irq = NPU_IRQ_NUM(isn);
	uint64_t lxive;

	if (!npu_isn_valid(p, isn))
		return OPAL_PARAMETER;

	/* Figure out LXIVT entry */
	lxive = SETFIELD(NPU_IODA_LXIVT_SERVER, 0ul, server);
	lxive = SETFIELD(NPU_IODA_LXIVT_PRIORITY, lxive, prio);

	/* Cache LXIVT entry */
	irq -= NPU_LSI_IRQ_MIN;
	p->lxive_cache[irq] = lxive;

	/* Update to LXIVT entry */
	npu_ioda_sel(p, NPU_IODA_TBL_LXIVT, irq, false);
	lxive = in_be64(p->at_regs + NPU_IODA_DATA0);
	lxive = SETFIELD(NPU_IODA_LXIVT_SERVER, lxive, server);
	lxive = SETFIELD(NPU_IODA_LXIVT_PRIORITY, lxive, prio);
	out_be64(p->at_regs + NPU_IODA_DATA0, lxive);

	return OPAL_SUCCESS;
}

static void npu_err_interrupt(struct irq_source *is, uint32_t isn)
{
	struct npu *p = is->data;
	uint32_t irq = NPU_IRQ_NUM(isn);

	if (!npu_isn_valid(p, isn))
		return;

	/* There're 4 LSIs used for error reporting: 4/5 for data
	 * link error reporting while 6/7 for frozen PE detection
	 */
	irq -= NPU_LSI_IRQ_MIN;
	switch (irq) {
	case 4 ... 5:
		prerror("Invalid NPU error interrupt received\n");
		break;
	case 6 ... 7:
		opal_update_pending_evt(OPAL_EVENT_PCI_ERROR,
					OPAL_EVENT_PCI_ERROR);
	}
}

static uint64_t npu_lsi_attributes(struct irq_source *is, uint32_t isn)
{
	struct npu *p = is->data;
	uint32_t idx = isn - p->base_lsi;

	if (idx >= 4)
		return IRQ_ATTR_TARGET_OPAL | IRQ_ATTR_TARGET_RARE | IRQ_ATTR_TYPE_LSI;
	return IRQ_ATTR_TARGET_LINUX;
}

/* Error LSIs (skiboot owned) */
static const struct irq_source_ops npu_lsi_irq_ops = {
	.get_xive	= npu_lsi_get_xive,
	.set_xive	= npu_lsi_set_xive,
	.attributes	= npu_lsi_attributes,
	.interrupt	= npu_err_interrupt,
};

static void npu_register_irq(struct npu *p)
{
	register_irq_source(&npu_lsi_irq_ops, p, p->base_lsi, 8);
}

static void npu_hw_init(struct npu *p)
{
	/* 3 MMIO setup for AT */
	out_be64(p->at_regs + NPU_LSI_SOURCE_ID,
		 SETFIELD(NPU_LSI_SRC_ID_BASE, 0ul, NPU_LSI_IRQ_MIN >> 4));
	BUILD_ASSERT((NPU_LSI_IRQ_MIN & 0x07F0) == NPU_LSI_IRQ_MIN);
	out_be64(p->at_regs + NPU_INTREP_TIMER, 0x0ul);
	npu_ioda_reset(&p->phb, false);
}

static int64_t npu_map_pe_dma_window_real(struct phb *phb,
					   uint64_t pe_number,
					   uint16_t window_id,
					   uint64_t pci_start_addr,
					   uint64_t pci_mem_size)
{
	struct npu *p = phb_to_npu(phb);
	uint64_t end;
	uint64_t tve;

	/* Sanity check. Each PE has one corresponding TVE */
	if (pe_number >= NPU_NUM_OF_PES ||
	    window_id != pe_number)
		return OPAL_PARAMETER;

	if (pci_mem_size) {
		/* Enable */

		end = pci_start_addr + pci_mem_size;

		/* We have to be 16M aligned */
		if ((pci_start_addr & 0x00ffffff) ||
		    (pci_mem_size & 0x00ffffff))
			return OPAL_PARAMETER;

		/*
		 * It *looks* like this is the max we can support (we need
		 * to verify this. Also we are not checking for rollover,
		 * but then we aren't trying too hard to protect ourselves
		 * againt a completely broken OS.
		 */
		if (end > 0x0003ffffffffffffull)
			return OPAL_PARAMETER;

		/*
		 * Put start address bits 49:24 into TVE[52:53]||[0:23]
		 * and end address bits 49:24 into TVE[54:55]||[24:47]
		 * and set TVE[51]
		 */
		tve  = (pci_start_addr << 16) & (0xffffffull << 48);
		tve |= (pci_start_addr >> 38) & (3ull << 10);
		tve |= (end >>  8) & (0xfffffful << 16);
		tve |= (end >> 40) & (3ull << 8);
		tve |= PPC_BIT(51);
	} else {
		/* Disable */
		tve = 0;
	}

	npu_ioda_sel(p, NPU_IODA_TBL_TVT, window_id, false);
	out_be64(p->at_regs + NPU_IODA_DATA0, tve);
	p->tve_cache[window_id] = tve;

	return OPAL_SUCCESS;
}

static int64_t npu_map_pe_dma_window(struct phb *phb,
					 uint64_t pe_number,
					 uint16_t window_id,
					 uint16_t tce_levels,
					 uint64_t tce_table_addr,
					 uint64_t tce_table_size,
					 uint64_t tce_page_size)
{
	struct npu *p = phb_to_npu(phb);
	uint64_t tts_encoded;
	uint64_t data64 = 0;

	/* Sanity check. Each PE has one corresponding TVE */
	if (pe_number >= NPU_NUM_OF_PES ||
	    window_id != pe_number)
		return OPAL_PARAMETER;

	/* Special condition, zero TCE table size used to disable
	 * the TVE.
	 */
	if (!tce_table_size) {
		npu_ioda_sel(p, NPU_IODA_TBL_TVT, window_id, false);
		out_be64(p->at_regs + NPU_IODA_DATA0, 0ul);
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
	data64 = SETFIELD(NPU_IODA_TVT_TTA, 0ul, tce_table_addr >> 12);
	tts_encoded = ilog2(tce_table_size) - 11;
	if (tts_encoded > 39)
		return OPAL_PARAMETER;
	data64 = SETFIELD(NPU_IODA_TVT_SIZE, data64, tts_encoded);

	/* TCE page size */
	switch (tce_page_size) {
	case 0x10000:		/* 64K */
		data64 = SETFIELD(NPU_IODA_TVT_PSIZE, data64, 5);
		break;
	case 0x1000000:		/* 16M */
		data64 = SETFIELD(NPU_IODA_TVT_PSIZE, data64, 13);
		break;
	case 0x10000000:	/* 256M */
		data64 = SETFIELD(NPU_IODA_TVT_PSIZE, data64, 17);
		break;
	case 0x1000:		/* 4K */
	default:
		data64 = SETFIELD(NPU_IODA_TVT_PSIZE, data64, 1);
	}

	/* Number of levels */
	data64 = SETFIELD(NPU_IODA_TVT_LEVELS, data64, tce_levels - 1);

	/* Update to hardware */
	npu_ioda_sel(p, NPU_IODA_TBL_TVT, window_id, false);
	out_be64(p->at_regs + NPU_IODA_DATA0, data64);
	p->tve_cache[window_id] = data64;

	return OPAL_SUCCESS;
}

static int64_t npu_set_pe(struct phb *phb,
			      uint64_t pe_number,
			      uint64_t bdfn,
			      uint8_t bcompare,
			      uint8_t dcompare,
			      uint8_t fcompare,
			      uint8_t action)
{
	struct npu *p = phb_to_npu(phb);
	struct npu_dev *dev;
	uint32_t link_idx;
	uint64_t *data64;

	/* Sanity check */
	if (action != OPAL_MAP_PE &&
	    action != OPAL_UNMAP_PE)
		return OPAL_PARAMETER;
	if (pe_number >= NPU_NUM_OF_PES)
		return OPAL_PARAMETER;

	/* All emulated PCI devices hooked to root bus, whose
	 * bus number is zero.
	 */
	dev = bdfn_to_npu_dev(p, bdfn);
	if (PCI_BUS_NUM(bdfn) || !dev)
		return OPAL_PARAMETER;

	link_idx = dev->index;
	dev->pe_number = pe_number;

	/* Separate links will be mapped to different PEs */
	if (bcompare != OpalPciBusAll ||
	    dcompare != OPAL_COMPARE_RID_DEVICE_NUMBER ||
	    fcompare != OPAL_COMPARE_RID_FUNCTION_NUMBER)
		return OPAL_UNSUPPORTED;

	/* Map the link to the corresponding PE */
	data64 = &p->pce_cache[link_idx];
	if (action == OPAL_MAP_PE)
		*data64 = SETFIELD(NPU_IODA_PCT_PE, *data64,
				   pe_number);
	else
		*data64 = SETFIELD(NPU_IODA_PCT_PE, *data64,
				   NPU_NUM_OF_PES);

	*data64 |= NPU_IODA_PCT_LINK_ENABLED;

	npu_ioda_sel(p, NPU_IODA_TBL_PCT, link_idx, false);
	out_be64(p->at_regs + NPU_IODA_DATA0, *data64);

	return OPAL_SUCCESS;
}

static int64_t npu_get_link_state(struct pci_slot *slot __unused, uint8_t *val)
{
	/* As we're emulating all PCI stuff, the link bandwidth
	 * isn't big deal anyway.
	 */
	*val = OPAL_SHPC_LINK_UP_x1;
	return OPAL_SUCCESS;
}

static int64_t npu_get_power_state(struct pci_slot *slot __unused, uint8_t *val)
{
	*val = PCI_SLOT_POWER_ON;
	return OPAL_SUCCESS;
}

static int64_t npu_hreset(struct pci_slot *slot __unused)
{
	prlog(PR_DEBUG, "NPU: driver should call reset procedure here\n");

	return OPAL_SUCCESS;
}

static int64_t npu_freset(struct pci_slot *slot __unused)
{
	/* FIXME: PHB fundamental reset, which need to be
	 * figured out later. It's used by EEH recovery
	 * upon fenced AT.
	 */
	return OPAL_SUCCESS;
}

static struct pci_slot *npu_slot_create(struct phb *phb)
{
	struct pci_slot *slot;

	slot = pci_slot_alloc(phb, NULL);
	if (!slot)
		return slot;

	/* Elementary functions */
	slot->ops.get_presence_state  = NULL;
	slot->ops.get_link_state      = npu_get_link_state;
	slot->ops.get_power_state     = npu_get_power_state;
	slot->ops.get_attention_state = NULL;
	slot->ops.get_latch_state     = NULL;
	slot->ops.set_power_state     = NULL;
	slot->ops.set_attention_state = NULL;

	slot->ops.prepare_link_change = NULL;
	slot->ops.poll_link           = NULL;
	slot->ops.hreset              = npu_hreset;
	slot->ops.freset              = npu_freset;
	slot->ops.creset              = NULL;

	return slot;
}

static int64_t npu_freeze_status(struct phb *phb,
				     uint64_t pe_number __unused,
				     uint8_t *freeze_state,
				     uint16_t *pci_error_type __unused,
				     uint16_t *severity __unused)
{
	/* FIXME: When it's called by skiboot PCI config accessor,
	 * the PE number is fixed to 0, which is incorrect. We need
	 * introduce another PHB callback to translate it. For now,
	 * it keeps the skiboot PCI enumeration going.
	 */
	struct npu *p = phb_to_npu(phb);
	if (p->fenced)
		*freeze_state = OPAL_EEH_STOPPED_MMIO_DMA_FREEZE;
	else
		*freeze_state = OPAL_EEH_STOPPED_NOT_FROZEN;
	return OPAL_SUCCESS;
}

static int64_t npu_eeh_next_error(struct phb *phb,
				  uint64_t *first_frozen_pe,
				  uint16_t *pci_error_type,
				  uint16_t *severity)
{
	struct npu *p = phb_to_npu(phb);
	int i;
	uint64_t result = 0;
	*first_frozen_pe = -1;
	*pci_error_type = OPAL_EEH_NO_ERROR;
	*severity = OPAL_EEH_SEV_NO_ERROR;

	if (p->fenced) {
		*pci_error_type = OPAL_EEH_PHB_ERROR;
		*severity = OPAL_EEH_SEV_PHB_FENCED;
		return OPAL_SUCCESS;
	}

	npu_ioda_sel(p, NPU_IODA_TBL_PESTB, 0, true);
	for (i = 0; i < NPU_NUM_OF_PES; i++) {
		result = in_be64(p->at_regs + NPU_IODA_DATA0);
		if (result > 0) {
			*first_frozen_pe = i;
			*pci_error_type = OPAL_EEH_PE_ERROR;
			*severity = OPAL_EEH_SEV_PE_ER;
			break;
		}
	}

	return OPAL_SUCCESS;
}

/* For use in error injection and handling. */
void npu_set_fence_state(struct npu *p, bool fence) {
	p->fenced = fence;

	if (fence)
		prlog(PR_ERR, "NPU: Chip %x is fenced, reboot required.\n",
		      p->chip_id);
	else
		prlog(PR_WARNING, "NPU: un-fencing is dangerous and should \
		      only be used for development purposes.");
}

/* Sets the NPU to trigger an error when a DMA occurs */
static int64_t npu_err_inject(struct phb *phb, uint64_t pe_number,
			      uint32_t type, uint32_t func __unused,
			      uint64_t addr __unused, uint64_t mask __unused)
{
	struct npu *p = phb_to_npu(phb);
	struct npu_dev *dev = NULL;
	int i;

	if (pe_number >= NPU_NUM_OF_PES) {
		prlog(PR_ERR, "NPU: error injection failed, bad PE given\n");
		return OPAL_PARAMETER;
	}

	for (i = 0; i < p->total_devices; i++) {
		if (p->devices[i].pe_number == pe_number) {
			dev = &p->devices[i];
			break;
		}
	}

	if (!dev) {
		prlog(PR_ERR, "NPU: couldn't find device with PE%llx\n", pe_number);
		return OPAL_PARAMETER;
	}

	/* TODO: extend this to conform to OPAL injection standards */
	if (type > 1) {
		prlog(PR_ERR, "NPU: invalid error injection type\n");
		return OPAL_PARAMETER;
	} else if (type == 1) {
		/* Emulate fence mode. */
		npu_set_fence_state(p, true);
	} else {
		/* Cause a freeze with an invalid MMIO read.  If the BAR is not
		 * enabled, this will checkstop the machine.
		 */
		npu_dev_bar_update(p->chip_id, &dev->bar, true);
		in_be64((void *)dev->bar.base);
	}

	return OPAL_SUCCESS;
}

static const struct phb_ops npu_ops = {
	.cfg_read8		= npu_cfg_read8,
	.cfg_read16		= npu_cfg_read16,
	.cfg_read32		= npu_cfg_read32,
	.cfg_write8		= npu_cfg_write8,
	.cfg_write16		= npu_cfg_write16,
	.cfg_write32		= npu_cfg_write32,
	.get_reserved_pe_number	= NULL,
	.device_init		= NULL,
	.phb_final_fixup	= npu_phb_final_fixup,
	.ioda_reset		= npu_ioda_reset,
	.papr_errinjct_reset	= NULL,
	.pci_reinit		= NULL,
	.set_phb_mem_window	= NULL,
	.phb_mmio_enable	= NULL,
	.map_pe_mmio_window	= NULL,
	.map_pe_dma_window	= npu_map_pe_dma_window,
	.map_pe_dma_window_real	= npu_map_pe_dma_window_real,
	.pci_msi_eoi		= NULL,
	.set_xive_pe		= NULL,
	.get_msi_32		= NULL,
	.get_msi_64		= NULL,
	.set_pe			= npu_set_pe,
	.set_peltv		= NULL,
	.eeh_freeze_status	= npu_freeze_status,
	.eeh_freeze_clear	= NULL,
	.eeh_freeze_set		= NULL,
	.next_error		= npu_eeh_next_error,
	.err_inject		= npu_err_inject,
	.get_diag_data2		= NULL,
	.set_capi_mode		= NULL,
	.set_capp_recovery	= NULL,
};

static void assign_mmio_bars(uint32_t gcid, uint32_t xscom,
			     struct dt_node *npu_dn, uint64_t mm_win[2],
			     uint64_t at_bar[2])
{
	uint64_t mem_start, mem_end;
	struct npu_dev_bar bar;
	struct dt_node *link;

	/* Configure BAR selection.
	 *
	 * Currently, each PHY contains 2 links and each link has 2
	 * BARs. The first BAR is assigned to the DLTL region which is
	 * what the kernel uses. The second BAR is either assigned to
	 * either the PL or AT region or unassigned. The PL0/PL1/AT
	 * MMIO regions are not exposed to the kernel so we assigned
	 * them at the start of the available memory area followed by
	 * the DLTL regions. So we end up with the following memory
	 * map (assuming we're given a memory region starting at
	 * 0x3fff000000000):
	 *
	 * Link#0-BAR#0: NTL/NDL BAR (128KB) - 0x3fff000420000
	 * Link#0-BAR#1:     PL0 BAR (  2MB) - 0x3fff000000000
	 * Link#1-BAR#0: NTL/NDL BAR (128KB) - 0x3fff000440000
	 * Link#1-BAR#1:      AT BAR ( 64KB) - 0x3fff000400000
	 * Link#2-BAR#0: NTL/NDL BAR (128KB) - 0x3fff000460000
	 * Link#2-BAR#1:     PL1 BAR (  2MB) - 0x3fff000200000
	 * Link#3-BAR#0: NTL/NDL BAR (128KB) - 0x3fff000480000
	 * Link#3-BAR#1:  UNASSIGNED
	 */
	xscom_write(gcid, xscom + NPU_AT_SCOM_OFFSET + NX_BAR,
		    0x0211000043500000UL);

	xscom_read(gcid, npu_link_scom_base(npu_dn, xscom, 0) + NX_MMIO_BAR_0,
		   &mem_start);
	mem_start = GETFIELD(NX_MMIO_BAR_BASE, mem_start) << 12;

	xscom_read(gcid, npu_link_scom_base(npu_dn, xscom, 5) + NX_MMIO_BAR_0,
		   &mem_end);
	mem_end = (GETFIELD(NX_MMIO_BAR_BASE, mem_end) << 12) +
		get_bar_size(mem_end);

	/* PL0 BAR comes first at 0x3fff000000000 */
	bar.xscom = npu_link_scom_base(npu_dn, xscom, 0) + NX_MMIO_BAR_1;
	bar.base = mem_start;
	bar.size = NX_MMIO_PL_SIZE;
	npu_dev_bar_update(gcid, &bar, true);

	/* PL1 BAR */
	bar.xscom = npu_link_scom_base(npu_dn, xscom, 4) + NX_MMIO_BAR_1;
	bar.base += bar.size;
	bar.size = NX_MMIO_PL_SIZE;
	npu_dev_bar_update(gcid, &bar, true);

	/* Then the AT BAR */
	bar.xscom = npu_link_scom_base(npu_dn, xscom, 1) + NX_MMIO_BAR_1;
	bar.base += bar.size;
	bar.size = NX_MMIO_AT_SIZE;
	at_bar[0] = bar.base;
	at_bar[1] = NX_MMIO_AT_SIZE;
	npu_dev_bar_update(gcid, &bar, true);

	/* Now we configure all the DLTL BARs. These are the ones
	 * actually exposed to the kernel. */
	mm_win[0] = bar.base + bar.size;
	dt_for_each_node(npu_dn, link) {
		uint32_t index;

		index = dt_prop_get_u32(link, "ibm,npu-link-index");
		bar.xscom = npu_link_scom_base(npu_dn, xscom, index) +
			NX_MMIO_BAR_0;
		bar.base += bar.size;
		bar.size = NX_MMIO_DL_SIZE;
		bar.base = ALIGN_UP(bar.base, bar.size);
		npu_dev_bar_update(gcid, &bar, false);
	}
	mm_win[1] = (bar.base + bar.size) - mm_win[0];

	/* If we weren't given enough room to setup all the BARs we
	 * require it's better to crash here than risk creating
	 * overlapping BARs which will xstop the machine randomly in
	 * the future.*/
	assert(bar.base + bar.size <= mem_end);
}

/* Probe NPU device node and create PCI root device node
 * accordingly. The NPU deivce node should specify number
 * of links and xscom base address to access links.
 */
static void npu_probe_phb(struct dt_node *dn)
{
	struct dt_node *np;
	uint32_t gcid, index, phb_index, xscom;
	uint64_t at_bar[2], mm_win[2];
	uint32_t links;
	char *path;

	/* Retrieve chip id */
	path = dt_get_path(dn);
	gcid = dt_get_chip_id(dn);
	index = dt_prop_get_u32(dn, "ibm,npu-index");
	phb_index = dt_prop_get_u32(dn, "ibm,phb-index");
	links = dt_prop_get_u32(dn, "ibm,npu-links");
	prlog(PR_INFO, "Chip %d Found NPU%d (%d links) at %s\n",
	      gcid, index, links, path);
	free(path);

	/* Retrieve xscom base addr */
	xscom = dt_get_address(dn, 0, NULL);
	prlog(PR_INFO, "   XSCOM Base:  %08x\n", xscom);

	assign_mmio_bars(gcid, xscom, dn, mm_win, at_bar);
	prlog(PR_INFO, "   AT BAR:      %016llx (%lldKB)\n",
	      at_bar[0], at_bar[1] / 0x400);

	/* Create PCI root device node */
	np = dt_new_addr(dt_root, "pciex", at_bar[0]);
	assert(np);

	dt_add_property_strings(np, "compatible",
				"ibm,power8-npu-pciex", "ibm,ioda2-npu-phb");
	dt_add_property_strings(np, "device_type", "pciex");
	dt_add_property(np, "reg", at_bar, sizeof(at_bar));

	dt_add_property_cells(np, "ibm,phb-index", phb_index);
	dt_add_property_cells(np, "ibm,npu-index", index);
	dt_add_property_cells(np, "ibm,chip-id", gcid);
	dt_add_property_cells(np, "ibm,xscom-base", xscom);
	dt_add_property_cells(np, "ibm,npcq", dn->phandle);
	dt_add_property_cells(np, "ibm,links", links);
	dt_add_property(np, "ibm,mmio-window", mm_win, sizeof(mm_win));
	dt_add_property_cells(np, "ibm,phb-diag-data-size", 0);

	/* Disable fast reboot - not currently supported */
	disable_fast_reboot("NVLink device enabled");
}

static void npu_dev_populate_vendor_cap(struct npu_dev_cap *cap)
{
	struct npu_dev *dev = cap->dev;
	struct pci_virt_device *pvd = dev->pvd;
	uint32_t offset = cap->start;
	uint8_t val;

	/* Add length and version information */
	val = cap->end - cap->start;
	PCI_VIRT_CFG_INIT_RO(pvd, offset + 2, 1, val);
	PCI_VIRT_CFG_INIT_RO(pvd, offset + 3, 1, OPAL_NPU_VERSION);
	offset += 4;

	/* Defaults when the trap can't handle the read/write (eg. due
	 * to reading/writing less than 4 bytes). */
	val = 0x0;
	PCI_VIRT_CFG_INIT_RO(pvd, offset, 4, val);
	PCI_VIRT_CFG_INIT_RO(pvd, offset + 4, 4, val);

	/* Create a trap for AT/PL procedures */
	pci_virt_add_filter(pvd, offset, 8,
			    PCI_REG_FLAG_READ | PCI_REG_FLAG_WRITE,
			    npu_dev_procedure, NULL);
	offset += 8;

	PCI_VIRT_CFG_INIT_RO(pvd, offset, 1, dev->index);
}

static void npu_dev_populate_pcie_cap(struct npu_dev_cap *cap)
{
	struct npu_dev *dev = cap->dev;
	struct pci_virt_device *pvd = dev->pvd;
	uint32_t base = cap->start;
	uint32_t val;

	/* Sanity check on capability ID */
	if (cap->id != PCI_CFG_CAP_ID_EXP) {
		prlog(PR_NOTICE, "%s: Invalid capability ID %d (%d)\n",
		      __func__, cap->id, PCI_CFG_CAP_ID_EXP);
		return;
	}

	/* Sanity check on spanned registers */
	if ((cap->end - cap->start) < PCIE_CAP_START) {
		prlog(PR_NOTICE, "%s: Invalid reg region [%x, %x] for cap %d\n",
		      __func__, cap->start, cap->end, cap->id);
		return;
	}

	/* 0x00 - ID/PCIE capability */
	val = cap->id;
	val |= ((0x2 << 16) | (PCIE_TYPE_ENDPOINT << 20));
	PCI_VIRT_CFG_INIT_RO(pvd, base, 4, val);

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
	PCI_VIRT_CFG_INIT_RO(pvd, base + PCICAP_EXP_DEVCAP, 4, val);

	pci_virt_add_filter(pvd, base + PCICAP_EXP_DEVCTL, 2,
			    PCI_REG_FLAG_WRITE,
			    npu_dev_cfg_exp_devcap, NULL);

	/* 0x08 - Device control and status */
	PCI_VIRT_CFG_INIT(pvd, base + PCICAP_EXP_DEVCTL, 4, 0x00002810,
			 0xffff0000, 0x000f0000);

	/* 0x0c - Link capability */
	val = (PCIE_LSPEED_VECBIT_2 | (PCIE_LWIDTH_1X << 4));
	PCI_VIRT_CFG_INIT_RO(pvd, base + PCICAP_EXP_LCAP, 4, val);

	/* 0x10 - Link control and status */
	PCI_VIRT_CFG_INIT(pvd, base + PCICAP_EXP_LCTL, 4, 0x00130000,
			 0xfffff000, 0xc0000000);

	/* 0x14 - Slot capability */
	PCI_VIRT_CFG_INIT_RO(pvd, base + PCICAP_EXP_SLOTCAP, 4, 0x00000000);

	/* 0x18 - Slot control and status */
	PCI_VIRT_CFG_INIT_RO(pvd, base + PCICAP_EXP_SLOTCTL, 4, 0x00000000);

	/* 0x1c - Root control and capability */
	PCI_VIRT_CFG_INIT(pvd, base + PCICAP_EXP_RC, 4, 0x00000000,
			 0xffffffe0, 0x00000000);

	/* 0x20 - Root status */
	PCI_VIRT_CFG_INIT(pvd, base + PCICAP_EXP_RSTAT, 4, 0x00000000,
			 0xffffffff, 0x00010000);

	/* 0x24 - Device capability 2 */
	PCI_VIRT_CFG_INIT_RO(pvd, base + PCIECAP_EXP_DCAP2, 4, 0x00000000);

	/* 0x28 - Device Control and status 2 */
	PCI_VIRT_CFG_INIT(pvd, base + PCICAP_EXP_DCTL2, 4, 0x00070000,
			 0xffff0000, 0x00000000);

	/* 0x2c - Link capability 2 */
	PCI_VIRT_CFG_INIT_RO(pvd, base + PCICAP_EXP_LCAP2, 4, 0x00000007);

	/* 0x30 - Link control and status 2 */
	PCI_VIRT_CFG_INIT(pvd, base + PCICAP_EXP_LCTL2, 4, 0x00000003,
			 0xffff0000, 0x00200000);

	/* 0x34 - Slot capability 2 */
	PCI_VIRT_CFG_INIT_RO(pvd, base + PCICAP_EXP_SCAP2, 4, 0x00000000);

	/* 0x38 - Slot control and status 2 */
	PCI_VIRT_CFG_INIT_RO(pvd, base + PCICAP_EXP_SCTL2, 4, 0x00000000);
}

static struct npu_dev_cap *npu_dev_create_capability(struct npu_dev *dev,
				  void (*populate)(struct npu_dev_cap *),
				  uint16_t id,
				  uint16_t start,
				  uint16_t end)
{
	struct npu_dev_cap *cap;

	/* Check if the capability is existing */
	cap = npu_dev_find_capability(dev, id);
	if (cap)
		return cap;

	/* Allocate new one */
	cap = zalloc(sizeof(struct npu_dev_cap));
	assert(cap);

	/* Put it into the pool */
	cap->id         = id;
	cap->start      = start;
	cap->end        = end;
	cap->dev        = dev;
	cap->populate	= populate;
	list_add_tail(&dev->capabilities, &cap->link);

	return cap;
}

static struct npu_dev_cap *npu_dev_find_capability(struct npu_dev *dev,
						   uint16_t id)
{
	struct npu_dev_cap *cap;

	list_for_each(&dev->capabilities, cap, link) {
		if (cap->id == id)
			return cap;
	}

	return NULL;
}

/*
 * All capabilities should be put into the device capability
 * list according to register offset in ascending order for
 * easy access at later point.
 */
static void npu_dev_create_capabilities(struct npu_dev *dev)
{
	list_head_init(&dev->capabilities);

	/* PCI express capability */
	npu_dev_create_capability(dev, npu_dev_populate_pcie_cap,
				  PCI_CFG_CAP_ID_EXP, PCIE_CAP_START,
				  PCIE_CAP_END);

	/* Vendor specific capability */
	npu_dev_create_capability(dev, npu_dev_populate_vendor_cap,
				  PCI_CFG_CAP_ID_VENDOR, VENDOR_CAP_START,
				  VENDOR_CAP_END);
}

static void npu_dev_create_cfg(struct npu_dev *dev)
{
	struct pci_virt_device *pvd = dev->pvd;
	struct npu_dev_cap *cap;
	uint32_t offset;
	uint32_t last_cap_offset;

	/* 0x00 - Vendor/Device ID */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_VENDOR_ID, 4, 0x04ea1014);

	/* 0x04 - Command/Status
	 *
	 * Create one trap to trace toggling memory BAR enable bit
	 */
	PCI_VIRT_CFG_INIT(pvd, PCI_CFG_CMD, 4, 0x00100000, 0xffb802b8,
			 0xf9000000);

	pci_virt_add_filter(pvd, PCI_CFG_CMD, 1, PCI_REG_FLAG_WRITE,
			    npu_dev_cfg_write_cmd, NULL);

	/* 0x08 - Rev/Class/Cache */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_REV_ID, 4, 0x06800100);

	/* 0x0c - CLS/Latency Timer/Header/BIST */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_CACHE_LINE_SIZE, 4, 0x00800000);

	/* 0x10 - BARs, always 64-bits non-prefetchable
	 *
	 * Each emulated device represents one link and therefore
	 * there is one BAR for the associated DLTL region.
	 */

	/* Low 32-bits */
	PCI_VIRT_CFG_INIT(pvd, PCI_CFG_BAR0, 4,
			 (dev->bar.base & 0xfffffff0) | dev->bar.flags,
			 0x0000000f, 0x00000000);

	/* High 32-bits */
	PCI_VIRT_CFG_INIT(pvd, PCI_CFG_BAR1, 4, (dev->bar.base >> 32),
			 0x00000000, 0x00000000);

	/*
	 * Create trap. Writting 0xFF's to BAR registers should be
	 * trapped and return size on next read
	 */
	pci_virt_add_filter(pvd, PCI_CFG_BAR0, 8,
			    PCI_REG_FLAG_READ | PCI_REG_FLAG_WRITE,
			    npu_dev_cfg_bar, &dev->bar);

	/* 0x18/1c/20/24 - Disabled BAR#2/3/4/5
	 *
	 * Mark those BARs readonly so that 0x0 will be returned when
	 * probing the length and the BARs will be skipped.
	 */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_BAR2, 4, 0x00000000);
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_BAR3, 4, 0x00000000);
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_BAR4, 4, 0x00000000);
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_BAR5, 4, 0x00000000);

	/* 0x28 - Cardbus CIS pointer */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_CARDBUS_CIS, 4, 0x00000000);

	/* 0x2c - Subsystem ID */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_SUBSYS_VENDOR_ID, 4, 0x00000000);

	/* 0x30 - ROM BAR
	 *
	 * Force its size to be zero so that the kernel will skip
	 * probing the ROM BAR. We needn't emulate ROM BAR.
	 */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_ROMBAR, 4, 0xffffffff);

	/* 0x34 - PCI Capability
	 *
	 * By default, we don't have any capabilities
	 */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_CAP, 4, 0x00000000);

	last_cap_offset = PCI_CFG_CAP - 1;
	list_for_each(&dev->capabilities, cap, link) {
		offset = cap->start;

		/* Initialize config space for the capability */
		if (cap->populate)
			cap->populate(cap);

		/* Add capability header */
		PCI_VIRT_CFG_INIT_RO(pvd, offset, 2, cap->id);

		/* Update the next capability pointer */
		PCI_VIRT_CFG_NORMAL_WR(pvd, last_cap_offset + 1, 1, offset);

		last_cap_offset = offset;
	}

	/* 0x38 - Reserved */
	PCI_VIRT_CFG_INIT_RO(pvd, 0x38, 4, 0x00000000);

	/* 0x3c - INT line/pin/Minimal grant/Maximal latency */
	if (!(dev->index % 2))
		PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_INT_LINE, 4, 0x00000100);
	else
		PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_INT_LINE, 4, 0x00000200);
}

static uint32_t npu_allocate_bdfn(struct npu *p, uint32_t group)
{
	int i;
	int bdfn = (group << 3);

	for (i = 0; i < p->total_devices; i++) {
		if ((p->devices[i].pvd->bdfn & 0xf8) == (bdfn & 0xf8))
			bdfn++;
	}

	return bdfn;
}

static void npu_create_devices(struct dt_node *dn, struct npu *p)
{
	struct npu_dev *dev;
	struct dt_node *npu_dn, *link;
	uint32_t bdfn, npu_phandle, index = 0;
	uint64_t buid_reg;
	uint64_t lsisrcid;
	uint64_t buid;


	/* The bits in the LSI ID Base register are always compared and
	 * can be set to 0 in the buid base and mask fields.  The
	 * buid (bus unit id) is the full irq minus the last 4 bits. */
	lsisrcid = GETFIELD(NPU_LSI_SRC_ID_BASE, NPU_LSI_SRC_ID_BASE);
	buid = p8_chip_irq_block_base(p->chip_id, P8_IRQ_BLOCK_MISC) >> 4;

	buid_reg = SETFIELD(NP_IRQ_LEVELS, NP_BUID_ENABLE, ~0);
	buid_reg = SETFIELD(NP_BUID_MASK, buid_reg, ~lsisrcid);
	buid_reg = SETFIELD(NP_BUID_BASE, buid_reg, (buid & ~lsisrcid));

	/* Get the npu node which has the links which we expand here
	 * into pci like devices attached to our emulated phb. */
	npu_phandle = dt_prop_get_u32(dn, "ibm,npcq");
	npu_dn = dt_find_by_phandle(dt_root, npu_phandle);
	assert(npu_dn);

	/* Walk the link@x nodes to initialize devices */
	p->total_devices = 0;
	p->phb.scan_map = 0;
	list_head_init(&p->phb.virt_devices);
	dt_for_each_compatible(npu_dn, link, "ibm,npu-link") {
		struct npu_dev_bar *bar;
		uint32_t group_id;
		uint64_t val;

		dev = &p->devices[index];
		dev->index = dt_prop_get_u32(link, "ibm,npu-link-index");
		dev->xscom = npu_link_scom_base(npu_dn, p->xscom_base,
						dev->index);

		dev->npu = p;
		dev->dt_node = link;

		/* We don't support MMIO PHY access yet */
		dev->pl_base = NULL;

		group_id = dt_prop_get_u32(link, "ibm,npu-group-id");
		bdfn = npu_allocate_bdfn(p, group_id);

		/* This must be done after calling
		 * npu_allocate_bdfn() */
		p->total_devices++;
		p->phb.scan_map |= 0x1 << ((bdfn & 0xf8) >> 3);

		dev->pl_xscom_base = dt_prop_get_u64(link, "ibm,npu-phy");
		dev->lane_mask = dt_prop_get_u32(link, "ibm,npu-lane-mask");

		/* Setup BUID/ISRN */
		xscom_write(p->chip_id, dev->xscom + NX_NP_BUID, buid_reg);

		/* Create PCI virtual device */
		dev->pvd = pci_virt_add_device(&p->phb, bdfn, NPU_DEV_CFG_SIZE, dev);
		assert(dev->pvd);
		bar = &dev->bar;
		bar->flags = (PCI_CFG_BAR_TYPE_MEM |
			      PCI_CFG_BAR_MEM64);

		/* Update BAR info */
		bar->xscom = dev->xscom + NX_MMIO_BAR_0;
		xscom_read(p->chip_id, bar->xscom, &val);
		bar->base  = GETFIELD(NX_MMIO_BAR_BASE, val) << 12;
		bar->size = get_bar_size(val);

		/*
		 * The config space is initialised with the BARs
		 * disabled, so make sure it is actually disabled in
		 * hardware.
		 */
		npu_dev_bar_update(p->chip_id, bar, false);

		/* Initialize capabilities */
		npu_dev_create_capabilities(dev);

		/* Initialize config space */
		npu_dev_create_cfg(dev);

		index++;
	}
}

static void npu_add_phb_properties(struct npu *p)
{
	struct dt_node *np = p->phb.dt_node;
	uint32_t icsp = get_ics_phandle();
	uint64_t tkill, mm_base, mm_size;
	uint32_t base_lsi = p->base_lsi;
	uint32_t map[] = {
		/* Dev 0 INT#A (used by fn0) */
		0x0000, 0x0, 0x0, 0x1, icsp, base_lsi + NPU_LSI_INT_DL0, 1,
		/* Dev 0 INT#B (used by fn1) */
		0x0000, 0x0, 0x0, 0x2, icsp, base_lsi + NPU_LSI_INT_DL1, 1,
		/* Dev 1 INT#A (used by fn0) */
		0x0800, 0x0, 0x0, 0x1, icsp, base_lsi + NPU_LSI_INT_DL2, 1,
		/* Dev 1 INT#B (used by fn1) */
		0x0800, 0x0, 0x0, 0x2, icsp, base_lsi + NPU_LSI_INT_DL3, 1,
	};
	/* Mask is bus, device and INT# */
	uint32_t mask[] = {0xf800, 0x0, 0x0, 0x7};
	char slotbuf[32];

	/* Add various properties that HB doesn't have to
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

        /* DLPL Interrupts, we don't use the standard swizzle */
	p->phb.lstate.int_size = 0;
	dt_add_property(np, "interrupt-map", map, sizeof(map));
	dt_add_property(np, "interrupt-map-mask", mask, sizeof(mask));

	/* NPU PHB properties */
	/* TODO: Due to an errata TCE KILL only works when DMA traffic
	 * has been stopped. We need to implement the work around
	 * which is to do a TCE kill all instead. */
	tkill = cleanup_addr((uint64_t)p->at_regs) + NPU_TCE_KILL;
	dt_add_property_cells(np, "ibm,opal-num-pes",
			      NPU_NUM_OF_PES);
	dt_add_property_cells(np, "ibm,opal-reserved-pe",
			      0);
        dt_add_property_u64(np, "ibm,opal-tce-kill", tkill);

	/* Memory window is exposed as 32-bits non-prefetchable
	 * one because 64-bits prefetchable one is kind of special
	 * to kernel.
	 */
	mm_base = p->mm_base;
	mm_size = p->mm_size;
	dt_add_property_cells(np, "ranges", 0x02000000,
			      hi32(mm_base), lo32(mm_base),
			      hi32(mm_base), lo32(mm_base),
			      hi32(mm_size), lo32(mm_size));

	/* Set the slot location on the NPU PHB.  This PHB can contain
	 * devices that correlate with multiple physical slots, so
	 * present the chip ID instead.
	 */
	snprintf(slotbuf, sizeof(slotbuf), "NPU Chip %d", p->chip_id);
	dt_add_property_string(np, "ibm,io-base-loc-code", slotbuf);
}

static void npu_create_phb(struct dt_node *dn)
{
	const struct dt_property *prop;
	struct npu *p;
	struct pci_slot *slot;
	uint32_t links;
	void *pmem;

	/* Retrieve number of devices */
	links = dt_prop_get_u32(dn, "ibm,links");
	pmem = zalloc(sizeof(struct npu) + links * sizeof(struct npu_dev));
	assert(pmem);

	/* Populate PHB */
	p = pmem;
	p->index = dt_prop_get_u32(dn, "ibm,npu-index");
	p->chip_id = dt_prop_get_u32(dn, "ibm,chip-id");
	p->xscom_base = dt_prop_get_u32(dn, "ibm,xscom-base");
	p->total_devices = links;

	/* TODO: When hardware fences are implemented, detect them here */
	p->fenced = false;

	/* This is the AT base */
	p->at_xscom = p->xscom_base + NPU_AT_SCOM_OFFSET;
	p->at_regs = (void *)dt_get_address(dn, 0, NULL);

	prop = dt_require_property(dn, "ibm,mmio-window", -1);
	assert(prop->len >= (2 * sizeof(uint64_t)));
	p->mm_base = ((const uint64_t *)prop->prop)[0];
	p->mm_size = ((const uint64_t *)prop->prop)[1];

	p->devices = pmem + sizeof(struct npu);

	/* Interrupt */
        p->base_lsi = p8_chip_irq_block_base(p->chip_id, P8_IRQ_BLOCK_MISC) +
		NPU_LSI_IRQ_MIN;

	/* Generic PHB */
	p->phb.dt_node = dn;
	p->phb.ops = &npu_ops;
	p->phb.phb_type = phb_type_pcie_v3;

	/* Populate devices */
	npu_create_devices(dn, p);

	/* Populate extra properties */
	npu_add_phb_properties(p);

	/* Create PHB slot */
	slot = npu_slot_create(&p->phb);
	if (!slot)
	{
		/**
		 * @fwts-label NPUCannotCreatePHBSlot
		 * @fwts-advice Firmware probably ran out of memory creating
		 * NPU slot. NVLink functionality could be broken.
		 */
		prlog(PR_ERR, "NPU: Cannot create PHB slot\n");
	}

	/* Register PHB */
	pci_register_phb(&p->phb, OPAL_DYNAMIC_PHB_ID);

	/* Initialize IODA cache */
	npu_ioda_init(p);

	/* Register interrupt source */
	npu_register_irq(p);

	/* Initialize hardware */
	npu_hw_init(p);
}

void probe_npu(void)
{
	struct dt_node *np;

	/* Scan NPU XSCOM nodes */
	dt_for_each_compatible(dt_root, np, "ibm,power8-npu")
		npu_probe_phb(np);

	/* Scan newly created PHB nodes */
	dt_for_each_compatible(dt_root, np, "ibm,power8-npu-pciex")
		npu_create_phb(np);
}
