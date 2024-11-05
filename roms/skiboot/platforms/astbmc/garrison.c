// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#include <skiboot.h>
#include <device.h>
#include <console.h>
#include <chip.h>
#include <ipmi.h>
#include <psi.h>
#include <npu-regs.h>

#include "astbmc.h"

static const struct slot_table_entry garrison_phb0_0_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Slot3",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry garrison_phb0_1_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Slot2",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry garrison_phb0_2_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "GPU1",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry garrison_phb0_3_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "GPU2",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry garrison_npu0_slots[] = {
	{
		.etype = st_npu_slot,
		.location = ST_LOC_NPU_GROUP(0),
		.name = "GPU2",
	},
	{
		.etype = st_npu_slot,
		.location = ST_LOC_NPU_GROUP(1),
		.name = "GPU1",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry garrison_phb1_0_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Slot1",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry garrison_plx_slots[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(1,0),
		.name = "Backplane USB",
	},
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(2,0),
		.name = "Backplane SATA",
	},
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(3,0),
		.name = "Backplane BMC",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry garrison_plx_up[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.children = garrison_plx_slots,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry garrison_phb1_1_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Backplane PLX",
		.children = garrison_plx_up,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry garrison_phb1_2_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "GPU3",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry garrison_phb1_3_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "GPU4",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry garrison_npu1_slots[] = {
	{
		.etype = st_npu_slot,
		.location = ST_LOC_NPU_GROUP(0),
		.name = "GPU4",
	},
	{
		.etype = st_npu_slot,
		.location = ST_LOC_NPU_GROUP(1),
		.name = "GPU3",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry garrison_phb_table[] = {
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,0),
		.children = garrison_phb0_0_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,1),
		.children = garrison_phb0_1_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,2),
		.children = garrison_phb0_2_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,3),
		.children = garrison_phb0_3_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,4),
		.children = garrison_npu0_slots,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(1,0),
		.children = garrison_phb1_0_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(1,1),
		.children = garrison_phb1_1_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(1,2),
		.children = garrison_phb1_2_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(1,3),
		.children = garrison_phb1_3_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(1,4),
		.children = garrison_npu1_slots,
	},
	{ .etype = st_end },
};

#define NPU_BASE 0x8013c00
#define NPU_SIZE 0x2c
#define NPU_INDIRECT0	0x8000000008010c3fUL
#define NPU_INDIRECT1	0x8000000008010c7fUL

static void create_link(struct dt_node *npu, int group, int index)
{
	struct dt_node *link;
	uint32_t lane_mask;
	uint64_t phy;
	char namebuf[32];

	snprintf(namebuf, sizeof(namebuf), "link@%x", index);
	link = dt_new(npu, namebuf);

	dt_add_property_string(link, "compatible", "ibm,npu-link");
	dt_add_property_cells(link, "ibm,npu-link-index", index);

	if (index < 4) {
		phy = NPU_INDIRECT0;
		lane_mask = 0xff << (index * 8);
	} else {
		phy = NPU_INDIRECT1;
		lane_mask = 0xff0000 >> (index - 3) * 8;
	}
	dt_add_property_u64s(link, "ibm,npu-phy", phy);
	dt_add_property_cells(link, "ibm,npu-lane-mask", lane_mask);
	dt_add_property_cells(link, "ibm,npu-group-id", group);
}

static void dt_create_npu(void)
{
        struct dt_node *xscom, *npu;
        char namebuf[32];

	dt_for_each_compatible(dt_root, xscom, "ibm,xscom") {
		snprintf(namebuf, sizeof(namebuf), "npu@%x", NPU_BASE);
		npu = dt_new(xscom, namebuf);
		dt_add_property_cells(npu, "reg", NPU_BASE, NPU_SIZE);
		dt_add_property_strings(npu, "compatible", "ibm,power8-npu");

		/* Use the first available PHB index which is 4 given
		 * there are three normal PHBs. */
		dt_add_property_cells(npu, "ibm,phb-index", 4);
		dt_add_property_cells(npu, "ibm,npu-index", 0);
		dt_add_property_cells(npu, "ibm,npu-links", 4);

		/* On Garrison we have 2 links per GPU device.  These are
		 * grouped together as per the slot tables above. */
		create_link(npu, 0, 0);
		create_link(npu, 0, 1);
		create_link(npu, 1, 4);
		create_link(npu, 1, 5);
	}
}

static bool garrison_probe(void)
{
	if (!dt_node_is_compatible(dt_root, "ibm,garrison"))
		return false;

	/* Lot of common early inits here */
	astbmc_early_init();

	/* Fixups until HB get the NPU bindings */
	dt_create_npu();

	slot_table_init(garrison_phb_table);

	return true;
}

DECLARE_PLATFORM(garrison) = {
	.name			= "Garrison",
	.bmc			= &bmc_plat_ast2400_ami,
	.probe			= garrison_probe,
	.init			= astbmc_init,
	.pci_get_slot_info	= slot_table_get_slot_info,
	.pci_probe_complete	= check_all_slot_table,
	.cec_power_down         = astbmc_ipmi_power_down,
	.cec_reboot             = astbmc_ipmi_reboot,
	.elog_commit		= ipmi_elog_commit,
	.start_preload_resource	= flash_start_preload_resource,
	.resource_loaded	= flash_resource_loaded,
	.exit			= ipmi_wdt_final_reset,
	.terminate		= ipmi_terminate,
	.seeprom_update		= astbmc_seeprom_update,
	.op_display		= op_display_lpc,
};
