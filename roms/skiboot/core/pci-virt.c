// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Support virtual PCI devices
 *
 * Copyright 2013-2016 IBM Corp.
 */

#include <skiboot.h>
#include <pci.h>
#include <pci-virt.h>

void pci_virt_cfg_read_raw(struct pci_virt_device *pvd,
			   uint32_t space, uint32_t offset,
			   uint32_t size, uint32_t *data)
{
	uint32_t i;

	if (space >= PCI_VIRT_CFG_MAX || !pvd->config[space])
		return;

	for (*data = 0, i = 0; i < size; i++)
		*data |= ((uint32_t)(pvd->config[space][offset + i]) << (i * 8));
}

void pci_virt_cfg_write_raw(struct pci_virt_device *pvd,
			    uint32_t space, uint32_t offset,
			    uint32_t size, uint32_t data)
{
	int i;

	if (space >= PCI_VIRT_CFG_MAX || !pvd->config[space])
		return;

	for (i = 0; i < size; i++) {
		pvd->config[space][offset + i] = data;
		data = (data >> 8);
	}
}

static struct pci_cfg_reg_filter *pci_virt_find_filter(
					struct pci_virt_device *pvd,
					uint32_t start, uint32_t len)
{
	struct pci_cfg_reg_filter *pcrf;

	if (!pvd || !len || start >= pvd->cfg_size)
		return NULL;

	/* Return filter if there is overlapped region. We don't
	 * require strict matching for more flexibility. It also
	 * means the associated handler should validate the register
	 * offset and length.
	 */
	list_for_each(&pvd->pcrf, pcrf, link) {
		if (start < (pcrf->start + pcrf->len) &&
		    (start + len) > pcrf->start)
			return pcrf;
	}

	return NULL;
}

struct pci_cfg_reg_filter *pci_virt_add_filter(struct pci_virt_device *pvd,
					       uint32_t start,
					       uint32_t len,
					       uint32_t flags,
					       pci_cfg_reg_func func,
					       void *data)
{
	struct pci_cfg_reg_filter *pcrf;

	if (!pvd || !len || (start + len) >= pvd->cfg_size)
		return NULL;
	if (!(flags & PCI_REG_FLAG_MASK))
		return NULL;

	pcrf = pci_virt_find_filter(pvd, start, len);
	if (pcrf) {
		prlog(PR_ERR, "%s: Filter [%x, %x] overlapped with [%x, %x]\n",
		      __func__, start, len, pcrf->start, pcrf->len);
		return NULL;
	}

	pcrf = zalloc(sizeof(*pcrf));
	if (!pcrf) {
		prlog(PR_ERR, "%s: Out of memory!\n", __func__);
		return NULL;
	}

	pcrf->start = start;
	pcrf->len   = len;
	pcrf->flags = flags;
	pcrf->func  = func;
	pcrf->data  = data;
	list_add_tail(&pvd->pcrf, &pcrf->link);

	return pcrf;
}

struct pci_virt_device *pci_virt_find_device(struct phb *phb,
					     uint32_t bdfn)
{
	struct pci_virt_device *pvd;

	list_for_each(&phb->virt_devices, pvd, node) {
		if (pvd->bdfn == bdfn)
			return pvd;
	}

	return NULL;
}

static inline bool pci_virt_cfg_valid(struct pci_virt_device *pvd,
				      uint32_t offset, uint32_t size)
{
	if ((offset + size) > pvd->cfg_size)
		return false;

	if (!size || (size > 4))
		return false;

	if ((size & (size - 1)) || (offset & (size - 1)))
		return false;

	return true;
}

int64_t pci_virt_cfg_read(struct phb *phb, uint32_t bdfn,
			  uint32_t offset, uint32_t size,
			  uint32_t *data)
{
	struct pci_virt_device *pvd;
	struct pci_cfg_reg_filter *pcrf;
	int64_t ret = OPAL_SUCCESS;

	*data = 0xffffffff;

	/* Search for PCI virtual device */
	pvd = pci_virt_find_device(phb, bdfn);
	if (!pvd)
		return OPAL_PARAMETER;

	/* Check if config address is valid or not */
	if (!pci_virt_cfg_valid(pvd, offset, size))
		return OPAL_PARAMETER;

	/* The value is fetched from the normal config space when the
	 * trap handler returns OPAL_PARTIAL. Otherwise, the trap handler
	 * should provide the return value.
	 */
	pcrf = pci_virt_find_filter(pvd, offset, size);
	if (!pcrf || !pcrf->func || !(pcrf->flags & PCI_REG_FLAG_READ))
		goto out;

	ret = pcrf->func(pvd, pcrf, offset, size, data, false);
	if (ret != OPAL_PARTIAL)
		return ret;
out:
	pci_virt_cfg_read_raw(pvd, PCI_VIRT_CFG_NORMAL, offset, size, data);
	return OPAL_SUCCESS;
}

int64_t pci_virt_cfg_write(struct phb *phb, uint32_t bdfn,
			   uint32_t offset, uint32_t size,
			   uint32_t data)
{
	struct pci_virt_device *pvd;
	struct pci_cfg_reg_filter *pcrf;
	uint32_t val, v, r, c, i;
	int64_t ret = OPAL_SUCCESS;

	/* Search for PCI virtual device */
	pvd = pci_virt_find_device(phb, bdfn);
	if (!pvd)
		return OPAL_PARAMETER;

	/* Check if config address is valid or not */
	if (!pci_virt_cfg_valid(pvd, offset, size))
		return OPAL_PARAMETER;

	/* The value is written to the config space if the trap handler
	 * returns OPAL_PARTIAL. Otherwise, the value to be written is
	 * dropped.
	 */
	pcrf = pci_virt_find_filter(pvd, offset, size);
	if (!pcrf || !pcrf->func || !(pcrf->flags & PCI_REG_FLAG_WRITE))
		goto out;

	ret = pcrf->func(pvd, pcrf, offset, size, &data, true);
	if (ret != OPAL_PARTIAL)
		return ret;
out:
	val = data;
	for (i = 0; i < size; i++) {
		PCI_VIRT_CFG_NORMAL_RD(pvd, offset + i, 1, &v);
		PCI_VIRT_CFG_RDONLY_RD(pvd, offset + i, 1, &r);
		PCI_VIRT_CFG_W1CLR_RD(pvd, offset + i, 1, &c);

		/* Drop read-only bits */
		val &= ~(r << (i * 8));
		val |= (r & v) << (i * 8);

		/* Drop W1C bits */
		val &= ~(val & ((c & v) << (i * 8)));
	}

	PCI_VIRT_CFG_NORMAL_WR(pvd, offset, size, val);
	return OPAL_SUCCESS;
}

struct pci_virt_device *pci_virt_add_device(struct phb *phb, uint32_t bdfn,
					    uint32_t cfg_size, void *data)
{
	struct pci_virt_device *pvd;
	uint8_t *cfg;
	uint32_t i;

	/* The standard config header size is 64 bytes */
	if (!phb || (bdfn & 0xffff0000) || (cfg_size < 64))
		return NULL;

	/* Check if the bdfn is available */
	pvd = pci_virt_find_device(phb, bdfn);
	if (pvd) {
		prlog(PR_ERR, "%s: bdfn 0x%x was reserved\n",
		      __func__, bdfn);
		return NULL;
	}

	/* Populate the PCI virtual device */
	pvd = zalloc(sizeof(*pvd));
	if (!pvd) {
		prlog(PR_ERR, "%s: Cannot alloate PCI virtual device (0x%x)\n",
		      __func__, bdfn);
		return NULL;
	}

	cfg = zalloc(cfg_size * PCI_VIRT_CFG_MAX);
	if (!cfg) {
		prlog(PR_ERR, "%s: Cannot allocate config space (0x%x)\n",
		      __func__, bdfn);
		free(pvd);
		return NULL;
	}

	for (i = 0; i < PCI_VIRT_CFG_MAX; i++, cfg += cfg_size)
		pvd->config[i] = cfg;

	pvd->bdfn     = bdfn;
	pvd->cfg_size = cfg_size;
	pvd->data     = data;
	list_head_init(&pvd->pcrf);
	list_add_tail(&phb->virt_devices, &pvd->node);

	return pvd;
}
