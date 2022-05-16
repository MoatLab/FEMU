// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2017-2019 IBM Corp. */

#include <skiboot.h>
#include <device.h>
#include <console.h>
#include <chip.h>
#include <ipmi.h>
#include <psi.h>
#include <npu-regs.h>
#include <npu2.h>
#include <pci.h>
#include <pci-cfg.h>

#include "astbmc.h"

/* backplane slots */
static const struct slot_table_entry hdd_bay_slots[] = {
	SW_PLUGGABLE("hdd0", 0xe),
	SW_PLUGGABLE("hdd1", 0x4),
	SW_PLUGGABLE("hdd2", 0x5),
	SW_PLUGGABLE("hdd3", 0x6),
	SW_PLUGGABLE("hdd4", 0x7),
	SW_PLUGGABLE("hdd5", 0xf),
	SW_PLUGGABLE("hdd6", 0xc),
	SW_PLUGGABLE("hdd7", 0xd),
	SW_PLUGGABLE("hdd8", 0x14),
	SW_PLUGGABLE("hdd9", 0x17),
	SW_PLUGGABLE("hdd10", 0x8),
	SW_PLUGGABLE("hdd11", 0xb),
	SW_PLUGGABLE("hdd12", 0x10),
	SW_PLUGGABLE("hdd13", 0x13),
	SW_PLUGGABLE("hdd14", 0x16),
	SW_PLUGGABLE("hdd15", 0x09),
	SW_PLUGGABLE("hdd16", 0xa),
	SW_PLUGGABLE("hdd17", 0x11),
	SW_PLUGGABLE("hdd18", 0x12),
	SW_PLUGGABLE("hdd19", 0x15),

	{ .etype = st_end },
};

static void zaius_get_slot_info(struct phb *phb, struct pci_device *pd)
{
	const struct slot_table_entry *ent = NULL;

	if (!pd || pd->slot)
		return;

	/*
	 * If we find a 9797 switch then assume it's the HDD Rack. This might
	 * break if we have another 9797 in the system for some reason. This is
	 * a really dumb hack, but until we get query the BMC about whether we
	 * have a HDD rack or not we don't have much of a choice.
	 */
	if (pd->dev_type == PCIE_TYPE_SWITCH_DNPORT && pd->vdid == 0x979710b5)
		for (ent = hdd_bay_slots; ent->etype != st_end; ent++)
			if (ent->location == (pd->bdfn & 0xff))
				break;
	if (ent)
		slot_table_add_slot_info(pd, ent);
	else
		slot_table_get_slot_info(phb, pd);
}

static const struct platform_ocapi zaius_ocapi = {
	.i2c_engine          = 1,
	.i2c_port            = 4,
	.i2c_reset_addr      = 0x20,
	.i2c_reset_brick2    = (1 << 1),
	.i2c_reset_brick3    = (1 << 6),
	.i2c_reset_brick4    = 0, /* unused */
	.i2c_reset_brick5    = 0, /* unused */
	.i2c_presence_addr   = 0x20,
	.i2c_presence_brick2 = (1 << 2), /* bottom connector */
	.i2c_presence_brick3 = (1 << 7), /* top connector */
	.i2c_presence_brick4 = 0, /* unused */
	.i2c_presence_brick5 = 0, /* unused */
	.odl_phy_swap        = true,
};

ST_PLUGGABLE(pe0_slot, "PE0");
ST_PLUGGABLE(pe1_slot, "PE1");
ST_PLUGGABLE(pe2_slot, "PE2");
ST_PLUGGABLE(pe3_slot, "PE3");
ST_PLUGGABLE(pe4_slot, "PE4");
ST_PLUGGABLE(mezz_slot_a, "MEZZ A");
ST_PLUGGABLE(mezz_slot_b, "MEZZ B");

static const struct slot_table_entry zaius_phb_table[] = {
	ST_PHB_ENTRY(0, 0, pe1_slot), /* PE1 is on PHB0 */
	ST_PHB_ENTRY(0, 1, pe0_slot), /* PE0 is on PHB1 */
/*	ST_PHB_ENTRY(0, 2, builtin_sata), */
	ST_PHB_ENTRY(0, 3, pe2_slot), /* un-bifurcated 16x */

	ST_PHB_ENTRY(8, 0, pe3_slot),
	ST_PHB_ENTRY(8, 1, pe4_slot),
/*	ST_PHB_ENTRY(8, 2, builtin_usb), */

	/*
	 * The MEZZ slot is kind of weird. Conceptually it's a 16x slot, but
	 * physically it's two separate 8x slots (MEZZ A and B) which can be
	 * used as a 16x slot if the PHB is un-bifurcated. The BMC detects what
	 * to do based on the the presence detect bits of the MEZZ slots to
	 * configure the correct bifurcation at IPL time.
	 *
	 * There's some additional weirdness too since MEZZ B can be used to
	 * access the built-in BCM5719 and the BMC PCIe interface via a special
	 * module that bridges MEZZ B to an adjacent connector.
	 *
	 * We should probably detect the bifurcation setting and set the slot
	 * names appropriately, but this will do for now.
	 */
	ST_PHB_ENTRY(8, 3, mezz_slot_a),
	ST_PHB_ENTRY(8, 4, mezz_slot_b),
/*	ST_PHB_ENTRY(8, 5, builtin_bmc), */

	{ .etype = st_end },
};

#define NPU_BASE 0x5011000
#define NPU_SIZE 0x2c
#define NPU_INDIRECT0	0x8000000009010c3fUL /* OB0 - no OB3 on Zaius */

/* OpenCAPI only */
static void create_link(struct dt_node *npu, int group, int index)
{
	struct dt_node *link;
	uint32_t lane_mask;
	char namebuf[32];

	snprintf(namebuf, sizeof(namebuf), "link@%x", index);
	link = dt_new(npu, namebuf);

	dt_add_property_string(link, "compatible", "ibm,npu-link");
	dt_add_property_cells(link, "ibm,npu-link-index", index);

	switch (index) {
	case 2:
		lane_mask = 0xf1e000; /* 0-3, 7-10 */
		break;
	case 3:
		lane_mask = 0x00078f; /* 13-16, 20-23 */
		break;
	default:
		assert(0);
	}

	dt_add_property_u64s(link, "ibm,npu-phy", NPU_INDIRECT0);
	dt_add_property_cells(link, "ibm,npu-lane-mask", lane_mask);
	dt_add_property_cells(link, "ibm,npu-group-id", group);
	dt_add_property_u64s(link, "ibm,link-speed", 25000000000ul);
}

/* FIXME: Get rid of this after we get NPU information properly via HDAT/MRW */
static void zaius_create_npu(void)
{
	struct dt_node *xscom, *npu;
	int npu_index = 0;
	char namebuf[32];

	/* Abort if there's already an NPU in the device tree */
	if (dt_find_compatible_node(dt_root, NULL, "ibm,power9-npu"))
		return;

	prlog(PR_DEBUG, "OCAPI: Adding NPU device nodes\n");
	dt_for_each_compatible(dt_root, xscom, "ibm,xscom") {
		snprintf(namebuf, sizeof(namebuf), "npu@%x", NPU_BASE);
		npu = dt_new(xscom, namebuf);
		dt_add_property_cells(npu, "reg", NPU_BASE, NPU_SIZE);
		dt_add_property_strings(npu, "compatible", "ibm,power9-npu");
		dt_add_property_cells(npu, "ibm,npu-index", npu_index++);
		dt_add_property_cells(npu, "ibm,npu-links", 2);
		create_link(npu, 1, 2);
		create_link(npu, 2, 3);
	}
}

/* FIXME: Get rid of this after we get NPU information properly via HDAT/MRW */
static void zaius_create_ocapi_i2c_bus(void)
{
	struct dt_node *xscom, *i2cm, *i2c_bus;
	prlog(PR_DEBUG, "OCAPI: Adding I2C bus device node for OCAPI reset\n");
	dt_for_each_compatible(dt_root, xscom, "ibm,xscom") {
		i2cm = dt_find_by_name(xscom, "i2cm@a1000");
		if (!i2cm) {
			prlog(PR_ERR, "OCAPI: Failed to add I2C bus device node\n");
			continue;
		}

		if (dt_find_by_name(i2cm, "i2c-bus@4"))
			continue;

		i2c_bus = dt_new_addr(i2cm, "i2c-bus", 4);
		dt_add_property_cells(i2c_bus, "reg", 4);
		dt_add_property_cells(i2c_bus, "bus-frequency", 0x61a80);
		dt_add_property_strings(i2c_bus, "compatible",
					"ibm,opal-i2c", "ibm,power8-i2c-port",
					"ibm,power9-i2c-port");
	}
}

static bool zaius_probe(void)
{
	if (!dt_node_is_compatible(dt_root, "ingrasys,zaius"))
		return false;

	/* Lot of common early inits here */
	astbmc_early_init();

	/* Setup UART for direct use by Linux */
	uart_set_console_policy(UART_CONSOLE_OS);

	zaius_create_npu();
	zaius_create_ocapi_i2c_bus();

	slot_table_init(zaius_phb_table);

	return true;
}

/* Extracted from zaius1-bmc */
static const struct bmc_hw_config bmc_hw_zaius = {
	.scu_revision_id	= 0x04030303,
	.mcr_configuration	= 0x11000FD7,
	.mcr_scu_mpll		= 0x000071C1,
	.mcr_scu_strap		= 0x00000000,
};

static const struct bmc_sw_config bmc_sw_openbmc = {
	.ipmi_oem_partial_add_esel   = IPMI_CODE(0x3a, 0xf0),
	.ipmi_oem_hiomap_cmd         = IPMI_CODE(0x3a, 0x5a),
};

static const struct bmc_platform bmc_zaius_openbmc = {
	.name			= "zaius:openbmc",
	.hw			= &bmc_hw_zaius,
	.sw			= &bmc_sw_openbmc,
};

DECLARE_PLATFORM(zaius) = {
	.name			= "Zaius",
	.probe			= zaius_probe,
	.init			= astbmc_init,
	.start_preload_resource	= flash_start_preload_resource,
	.resource_loaded	= flash_resource_loaded,
	.bmc			= &bmc_zaius_openbmc,
	.pci_get_slot_info	= zaius_get_slot_info,
	.pci_probe_complete	= check_all_slot_table,
	.cec_power_down         = astbmc_ipmi_power_down,
	.cec_reboot             = astbmc_ipmi_reboot,
	.elog_commit		= ipmi_elog_commit,
	.exit			= ipmi_wdt_final_reset,
	.terminate		= ipmi_terminate,
	.ocapi			= &zaius_ocapi,
	.npu2_device_detect	= npu2_i2c_presence_detect,
	.op_display		= op_display_lpc,
};
