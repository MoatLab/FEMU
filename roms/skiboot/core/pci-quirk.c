// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Deal with PCI device quirks
 *
 * Copyright 2017-2018 IBM Corp.
 */

#define pr_fmt(fmt)  "PCI-QUIRK: " fmt

#include <skiboot.h>
#include <pci.h>
#include <pci-cfg.h>
#include <pci-quirk.h>
#include <platform.h>
#include <ast.h>

static int64_t cfg_block_filter(void *dev __unused,
				struct pci_cfg_reg_filter *pcrf __unused,
				uint32_t offset __unused, uint32_t len,
				uint32_t *data, bool write)
{
	if (write)
		return OPAL_SUCCESS;

	switch (len) {
	case 4:
		*data = 0x0;
		return OPAL_SUCCESS;
	case 2:
		*((uint16_t *)data) = 0x0;
		return OPAL_SUCCESS;
	case 1:
		*((uint8_t *)data) = 0x0;
		return OPAL_SUCCESS;
	}

	return OPAL_PARAMETER; /* should never happen */
}

/* blocks config accesses to registers in the range: [start, end] */
#define BLOCK_CFG_RANGE(pd, start, end) \
	pci_add_cfg_reg_filter(pd, start, end - start + 1, \
		PCI_REG_FLAG_WRITE | PCI_REG_FLAG_READ, \
		cfg_block_filter);

static void quirk_microsemi_gen4_sw(struct phb *phb, struct pci_device *pd)
{
	uint8_t data;
	bool frozen;
	int offset;
	int start;

	pci_check_clear_freeze(phb);

	/*
	 * Reading from 0xff should trigger a UR on the affected switches.
	 * If we don't get a freeze then we don't need the workaround
	 */
	pci_cfg_read8(phb, pd->bdfn, 0xff, &data);
	frozen = pci_check_clear_freeze(phb);
	if (!frozen)
		return;

	for (start = -1, offset = 0; offset < 4096; offset++) {
		pci_cfg_read8(phb, pd->bdfn, offset, &data);
		frozen = pci_check_clear_freeze(phb);

		if (start < 0 && frozen) { /* new UR range */
			start = offset;
		} else if (start >= 0 && !frozen) { /* end of range */
			BLOCK_CFG_RANGE(pd, start, offset - 1);
			PCINOTICE(phb, pd->bdfn, "Applied UR workaround to [%03x..%03x]\n", start, offset - 1);

			start = -1;
		}
	}

	/* range lasted until the end of config space */
	if (start >= 0) {
		BLOCK_CFG_RANGE(pd, start, 0xfff);
		PCINOTICE(phb, pd->bdfn, "Applied UR workaround to [%03x..fff]\n", start);
	}
}

static void quirk_astbmc_vga(struct phb *phb __unused,
			     struct pci_device *pd)
{
	struct dt_node *np = pd->dn;
	uint32_t revision, mcr_configuration, mcr_scu_mpll, mcr_scu_strap;

	if (ast_sio_is_enabled()) {
		revision = ast_ahb_readl(SCU_REVISION_ID);
		mcr_configuration = ast_ahb_readl(MCR_CONFIGURATION);
		mcr_scu_mpll = ast_ahb_readl(MCR_SCU_MPLL);
		mcr_scu_strap = ast_ahb_readl(MCR_SCU_STRAP);
	} else {
		/* Previously we would warn, now SIO disabled by design */
		prlog(PR_INFO, "Assumed platform default parameters for %s\n",
		      __func__);
		revision = bmc_platform->hw->scu_revision_id;
		mcr_configuration = bmc_platform->hw->mcr_configuration;
		mcr_scu_mpll = bmc_platform->hw->mcr_scu_mpll;
		mcr_scu_strap = bmc_platform->hw->mcr_scu_strap;
	}

	dt_add_property_cells(np, "aspeed,scu-revision-id", revision);
	dt_add_property_cells(np, "aspeed,mcr-configuration", mcr_configuration);
	dt_add_property_cells(np, "aspeed,mcr-scu-mpll", mcr_scu_mpll);
	dt_add_property_cells(np, "aspeed,mcr-scu-strap", mcr_scu_strap);
}

/* Quirks are: {fixup function, vendor ID, (device ID or PCI_ANY_ID)} */
static const struct pci_quirk quirk_table[] = {
	/* ASPEED 2400 VGA device */
	{ 0x1a03, 0x2000, &quirk_astbmc_vga },
	{ 0x11f8, 0x4052, &quirk_microsemi_gen4_sw },
	{ 0, 0, NULL }
};

static void __pci_handle_quirk(struct phb *phb, struct pci_device *pd,
			       const struct pci_quirk *quirks)
{
	while (quirks->vendor_id) {
		if (quirks->vendor_id == PCI_VENDOR_ID(pd->vdid) &&
		    (quirks->device_id == PCI_ANY_ID ||
		     quirks->device_id == PCI_DEVICE_ID(pd->vdid)))
			quirks->fixup(phb, pd);
		quirks++;
	}
}

void pci_handle_quirk(struct phb *phb, struct pci_device *pd)
{
	__pci_handle_quirk(phb, pd, quirk_table);
}
