// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2017 Supermicro
 * Copyright 2017-2019 IBM Corp.
 */

#include <skiboot.h>
#include <device.h>
#include <console.h>
#include <chip.h>
#include <ipmi.h>
#include <psi.h>
#include <npu-regs.h>

#include "astbmc.h"

static const struct slot_table_entry p8dnu_phb0_0_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "UIO SLOT1",
	},
	{ .etype = st_end },
};


static const struct slot_table_entry p8dnu_plx_slots_00[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(1,0),
		.name = "Onboard SATA Marvell 88SE9230",
	},
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(2,0),
		.name = "Slot_DUIO ",
	},
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(8,0),
		.name = "Intel LAN X710/X557-AT",
	},
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(9,0),
		.name = "Onboard VGA AST2400",
	},
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0xa,0),
		.name = "Onboard USB TI TUSB7340",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p8dnu_plx_up_00[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.children = p8dnu_plx_slots_00,
	},
	{ .etype = st_end },
};



static const struct slot_table_entry p8dnu_phb0_1_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Backplane PLX VS0",
		.children = p8dnu_plx_up_00,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p8dnu_phb0_2_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "GPU1",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p8dnu_phb0_3_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "GPU2",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p8dnu_npu0_slots[] = {
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

static const struct slot_table_entry p8dnu_phb1_0_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "WIO SLOT1",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p8dnu_plx_slots[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(5,0),
		.name = "RSC-R1UW-E8R SLOT1",
	},
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0xd,0),
		.name = "WIO SLOT2",
	},
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0xc,0),
		.name = "WIO SLOT3",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p8dnu_plx_up[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.children = p8dnu_plx_slots,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p8dnu_phb1_1_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Backplane PLX VS1",
		.children = p8dnu_plx_up,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p8dnu_phb1_2_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "GPU3",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p8dnu_phb1_3_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "GPU4",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p8dnu_npu1_slots[] = {
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

static const struct slot_table_entry p8dnu_phb_table[] = {
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,0),
		.children = p8dnu_phb0_0_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,1),
		.children = p8dnu_phb0_1_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,2),
		.children = p8dnu_phb0_2_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,3),
		.children = p8dnu_phb0_3_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,4),
		.children = p8dnu_npu0_slots,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(1,0),
		.children = p8dnu_phb1_0_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(1,1),
		.children = p8dnu_phb1_1_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(1,2),
		.children = p8dnu_phb1_2_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(1,3),
		.children = p8dnu_phb1_3_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(1,4),
		.children = p8dnu_npu1_slots,
	},
	{ .etype = st_end },
};

#define NPU_BASE	0x8013c00
#define NPU_SIZE	0x2c
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

		/*
		 * Use the first available PHB index which is 4 given
		 * there are three normal PHBs.
		 */
		dt_add_property_cells(npu, "ibm,phb-index", 4);
		dt_add_property_cells(npu, "ibm,npu-index", 0);
		dt_add_property_cells(npu, "ibm,npu-links", 4);

		/*
		 * On p8dnu we have 2 links per GPU device.  These are
		 * grouped together as per the slot tables above.
		 */
		create_link(npu, 0, 0);
		create_link(npu, 0, 1);
		create_link(npu, 1, 4);
		create_link(npu, 1, 5);
	}
}

static bool p8dnu_probe(void)
{
	if (!dt_node_is_compatible(dt_root, "supermicro,p8dnu"))
		return false;

	/* Lot of common early inits here */
	astbmc_early_init();

	/* Fixups until HB get the NPU bindings */
	dt_create_npu();

	slot_table_init(p8dnu_phb_table);

	return true;
}

static const struct bmc_sw_config bmc_sw_smc = {
	.ipmi_oem_partial_add_esel   = IPMI_CODE(0x3a, 0xf0),
	.ipmi_oem_pnor_access_status = IPMI_CODE(0x3a, 0x07),
};

static const struct bmc_platform bmc_plat_ast2400_smc = {
	.name = "SMC",
	.hw = &bmc_hw_ast2400,
	.sw = &bmc_sw_smc,
};

DECLARE_PLATFORM(p8dnu) = {
	.name			= "P8DNU",
	.probe			= p8dnu_probe,
	.bmc			= &bmc_plat_ast2400_smc,
	.init			= astbmc_init,
	.pci_get_slot_info	= slot_table_get_slot_info,
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
