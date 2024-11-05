// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2018 IBM Corp
 */

#include <assert.h>
#include <stdint.h>
#include <compiler.h>
#include <stdbool.h>

/* Stubs for quirk_astbmc_vga() */

struct dt_property;
struct dt_node;

static struct bmc_platform fake_bmc;
const struct bmc_platform *bmc_platform = &fake_bmc;

static int ast_sio_is_enabled(void)
{
	return 0;
}

static uint32_t ast_ahb_readl(uint32_t reg)
{
	return reg;
}

static struct dt_property *__dt_add_property_cells(
		struct dt_node *node __unused, const char *name __unused,
		int count __unused, ...)
{
	return (void *)0;
}

struct pci_device;
struct pci_cfg_reg_filter;
typedef int64_t (*pci_cfg_reg_func)(void *dev,
				    struct pci_cfg_reg_filter *pcrf,
				    uint32_t offset, uint32_t len,
				    uint32_t *data, bool write);


static struct pci_cfg_reg_filter *pci_add_cfg_reg_filter(
	struct pci_device *pd __unused,
	uint32_t start __unused,
	uint32_t len __unused,
	uint32_t flags __unused,
	pci_cfg_reg_func func __unused)
{
	return NULL;
}

#include "../pci-quirk.c"

struct pci_device test_pd;
int test_fixup_ran;

static void test_fixup(struct phb *phb __unused, struct pci_device *pd __unused)
{
	assert(PCI_VENDOR_ID(pd->vdid) == 0x1a03);
	assert(PCI_DEVICE_ID(pd->vdid) == 0x2000);
	test_fixup_ran = 1;
}

/* Quirks are: {fixup function, vendor ID, (device ID or PCI_ANY_ID)} */
static const struct pci_quirk test_quirk_table[] = {
	/* ASPEED 2400 VGA device */
	{ 0x1a03, 0x2000, &test_fixup },
	{ 0, 0, NULL }
};

#define PCI_COMPOSE_VDID(vendor, device) (((device) << 16) | (vendor))

int main(void)
{
	/* Unrecognised vendor and device ID */
	test_pd.vdid = PCI_COMPOSE_VDID(0xabcd, 0xef01);
	__pci_handle_quirk(NULL, &test_pd, test_quirk_table);
	assert(test_fixup_ran == 0);

	/* Unrecognised vendor ID, matching device ID */
	test_pd.vdid = PCI_COMPOSE_VDID(0xabcd, 0x2000);
	__pci_handle_quirk(NULL, &test_pd, test_quirk_table);
	assert(test_fixup_ran == 0);

	/* Matching vendor ID, unrecognised device ID */
	test_pd.vdid = PCI_COMPOSE_VDID(0x1a03, 0xef01);
	__pci_handle_quirk(NULL, &test_pd, test_quirk_table);
	assert(test_fixup_ran == 0);

	/* Matching vendor and device ID */
	test_pd.vdid = PCI_COMPOSE_VDID(0x1a03, 0x2000);
	__pci_handle_quirk(NULL, &test_pd, test_quirk_table);
	assert(test_fixup_ran == 1);

	return 0;
}
