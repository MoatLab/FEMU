// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2019 IBM Corp.
 */

#include <skiboot.h>
#include <pci.h>
#include <phb4.h>
#include <npu2.h>
#include <pau.h>

#define TL_RATE_BUF_SIZE	32

static int64_t opal_npu_init_context(uint64_t phb_id, int pid __unused,
				     uint64_t msr, uint64_t bdf)
{
	struct phb *phb = pci_get_phb(phb_id);

	if (!phb)
		return OPAL_PARAMETER;

	if (phb->phb_type == phb_type_npu_v2)
		return npu2_init_context(phb, msr, bdf);

	return OPAL_PARAMETER;
}
opal_call(OPAL_NPU_INIT_CONTEXT, opal_npu_init_context, 4);

static int64_t opal_npu_destroy_context(uint64_t phb_id, uint64_t pid __unused,
					uint64_t bdf)
{
	struct phb *phb = pci_get_phb(phb_id);

	if (!phb)
		return OPAL_PARAMETER;

	if (phb->phb_type == phb_type_npu_v2)
		return npu2_destroy_context(phb, bdf);

	return OPAL_PARAMETER;
}
opal_call(OPAL_NPU_DESTROY_CONTEXT, opal_npu_destroy_context, 3);

static int64_t opal_npu_map_lpar(uint64_t phb_id, uint64_t bdf, uint64_t lparid,
				 uint64_t lpcr)
{
	struct phb *phb = pci_get_phb(phb_id);

	if (!phb)
		return OPAL_PARAMETER;

	if (phb->phb_type == phb_type_npu_v2)
		return npu2_map_lpar(phb, bdf, lparid, lpcr);

	if (phb->phb_type == phb_type_pau_opencapi)
		return pau_opencapi_map_atsd_lpar(phb, bdf, lparid, lpcr);

	return OPAL_PARAMETER;
}
opal_call(OPAL_NPU_MAP_LPAR, opal_npu_map_lpar, 4);

static int npu_check_relaxed_ordering(struct phb *phb, struct pci_device *pd,
				      void *enable)
{
	/*
	 * IBM PCIe bridge devices (ie. the root ports) can always allow relaxed
	 * ordering
	 */
	if (pd->vdid == 0x04c11014)
		pd->allow_relaxed_ordering = true;

	PCIDBG(phb, pd->bdfn, "Checking relaxed ordering config\n");
	if (pd->allow_relaxed_ordering)
		return 0;

	PCIDBG(phb, pd->bdfn, "Relaxed ordering not allowed\n");
	*(bool *)enable = false;

	return 1;
}

static int64_t npu_set_relaxed_order(uint32_t gcid, int pec, bool enable)
{
	struct phb *phb;
	int64_t rc;

	for_each_phb(phb) {
		if (phb->phb_type != phb_type_npu_v2)
			continue;

		rc = npu2_set_relaxed_order(phb, gcid, pec, enable);
		if (rc)
			return rc;
	}

	return OPAL_SUCCESS;
}

static int64_t opal_npu_set_relaxed_order(uint64_t phb_id, uint16_t bdfn,
					  bool request_enabled)
{
	struct phb *phb = pci_get_phb(phb_id);
	struct phb4 *phb4;
	uint32_t chip_id, pec;
	struct pci_device *pd;
	bool enable = true;

	if (!phb || phb->phb_type != phb_type_pcie_v4)
		return OPAL_PARAMETER;

	phb4 = phb_to_phb4(phb);
	pec = phb4->pec;
	chip_id = phb4->chip_id;

	if (chip_id & ~0x1b)
		return OPAL_PARAMETER;

	pd = pci_find_dev(phb, bdfn);
	if (!pd)
		return OPAL_PARAMETER;

	/*
	 * Not changing state, so no need to rescan PHB devices to determine if
	 * we need to enable/disable it
	 */
	if (pd->allow_relaxed_ordering == request_enabled)
		return OPAL_SUCCESS;

	pd->allow_relaxed_ordering = request_enabled;

	/*
	 * Walk all devices on this PHB to ensure they all support relaxed
	 * ordering
	 */
	pci_walk_dev(phb, NULL, npu_check_relaxed_ordering, &enable);

	if (request_enabled && !enable) {
		/*
		 * Not all devices on this PHB support relaxed-ordering
		 * mode so we can't enable it as requested
		 */
		prlog(PR_INFO, "Cannot set relaxed ordering for PEC %d on chip %d\n",
		      pec, chip_id);
		return OPAL_CONSTRAINED;
	}

	if (npu_set_relaxed_order(chip_id, pec, request_enabled)) {
		npu_set_relaxed_order(chip_id, pec, false);
		return OPAL_RESOURCE;
	}

	phb4->ro_state = request_enabled;
	return OPAL_SUCCESS;
}
opal_call(OPAL_NPU_SET_RELAXED_ORDER, opal_npu_set_relaxed_order, 3);

static int64_t opal_npu_get_relaxed_order(uint64_t phb_id,
					  uint16_t bdfn __unused)
{
	struct phb *phb = pci_get_phb(phb_id);
	struct phb4 *phb4;

	if (!phb || phb->phb_type != phb_type_pcie_v4)
		return OPAL_PARAMETER;

	phb4 = phb_to_phb4(phb);
	return phb4->ro_state;
}
opal_call(OPAL_NPU_GET_RELAXED_ORDER, opal_npu_get_relaxed_order, 2);

#define MAX_PE_HANDLE	((1 << 15) - 1)

static int64_t opal_npu_spa_setup(uint64_t phb_id, uint32_t bdfn,
				  uint64_t addr, uint64_t PE_mask)
{
	struct phb *phb = pci_get_phb(phb_id);

	if (!phb)
		return OPAL_PARAMETER;

	/* 4k aligned */
	if (addr & 0xFFF)
		return OPAL_PARAMETER;

	if (PE_mask > 15)
		return OPAL_PARAMETER;

	if (phb->phb_type == phb_type_npu_v2_opencapi)
		return npu2_opencapi_spa_setup(phb, bdfn, addr, PE_mask);

	if (phb->phb_type == phb_type_pau_opencapi)
		return pau_opencapi_spa_setup(phb, bdfn, addr, PE_mask);

	return OPAL_PARAMETER;
}
opal_call(OPAL_NPU_SPA_SETUP, opal_npu_spa_setup, 4);

static int64_t opal_npu_spa_clear_cache(uint64_t phb_id, uint32_t bdfn,
					uint64_t PE_handle)
{
	struct phb *phb = pci_get_phb(phb_id);

	if (!phb)
		return OPAL_PARAMETER;

	if (PE_handle > MAX_PE_HANDLE)
		return OPAL_PARAMETER;

	if (phb->phb_type == phb_type_npu_v2_opencapi)
		return npu2_opencapi_spa_clear_cache(phb, bdfn, PE_handle);

	if (phb->phb_type == phb_type_pau_opencapi)
		return pau_opencapi_spa_clear_cache(phb, bdfn, PE_handle);

	return OPAL_PARAMETER;
}
opal_call(OPAL_NPU_SPA_CLEAR_CACHE, opal_npu_spa_clear_cache, 3);

static int64_t opal_npu_tl_set(uint64_t phb_id, uint32_t bdfn,
		    long capabilities, uint64_t rate_phys, int rate_sz)
{
	struct phb *phb = pci_get_phb(phb_id);
	char *rate = (char *) rate_phys;

	if (!phb)
		return OPAL_PARAMETER;

	if (!opal_addr_valid(rate) || rate_sz != TL_RATE_BUF_SIZE)
		return OPAL_PARAMETER;

	if (phb->phb_type == phb_type_npu_v2_opencapi)
		return npu2_opencapi_tl_set(phb, bdfn, capabilities,
					    rate);

	if (phb->phb_type == phb_type_pau_opencapi)
		return pau_opencapi_tl_set(phb, bdfn, capabilities,
					   rate);

	return OPAL_PARAMETER;
}
opal_call(OPAL_NPU_TL_SET, opal_npu_tl_set, 5);

static int64_t opal_npu_mem_alloc(uint64_t phb_id, uint32_t bdfn,
				  uint64_t size, uint64_t *bar)
{
	struct phb *phb = pci_get_phb(phb_id);

	if (!phb)
		return OPAL_PARAMETER;

	if (phb->phb_type == phb_type_npu_v2_opencapi)
		return npu2_opencapi_mem_alloc(phb, bdfn, size, bar);

	if (phb->phb_type == phb_type_pau_opencapi)
		return pau_opencapi_mem_alloc(phb, bdfn, size, bar);

	return OPAL_PARAMETER;
}
opal_call(OPAL_NPU_MEM_ALLOC, opal_npu_mem_alloc, 4);

static int64_t opal_npu_mem_release(uint64_t phb_id, uint32_t bdfn)
{
	struct phb *phb = pci_get_phb(phb_id);;

	if (!phb)
		return OPAL_PARAMETER;

	if (phb->phb_type == phb_type_npu_v2_opencapi)
		return npu2_opencapi_mem_release(phb, bdfn);

	if (phb->phb_type == phb_type_pau_opencapi)
		return pau_opencapi_mem_release(phb, bdfn);

	return OPAL_PARAMETER;
}
opal_call(OPAL_NPU_MEM_RELEASE, opal_npu_mem_release, 2);
