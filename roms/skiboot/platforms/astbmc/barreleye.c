// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2016 Ingrasys.
 * Copyright 2016-2019 IBM Corp.
 */

#include <skiboot.h>
#include <device.h>
#include <console.h>
#include <chip.h>
#include <ipmi.h>

#include "astbmc.h"

static const struct slot_table_entry barreleye_phb0_0_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Slot1",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry barreleye_plx_slots[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(1,0),
		.name = "IO Board SATA",
	},
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(2,0),
		.name = "IO Board USB",
	},
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(3,0),
		.name = "IO Board BMC",
	},
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(4,0),
		.name = "IO Board NIC",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry barreleye_plx_up[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.children = barreleye_plx_slots,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry barreleye_phb0_1_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "PLX Switch",
		.children = barreleye_plx_up,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry barreleye_phb0_2_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Network Mezz",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry barreleye_phb8_0_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Storage Mezz",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry barreleye_phb8_1_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Slot3",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry barreleye_phb8_2_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Slot2",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry barreleye_phb_table[] = {
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,0),
		.children = barreleye_phb0_0_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,1),
		.children = barreleye_phb0_1_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,2),
		.children = barreleye_phb0_2_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,0),
		.children = barreleye_phb8_0_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,1),
		.children = barreleye_phb8_1_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,2),
		.children = barreleye_phb8_2_slot,
	},
	{ .etype = st_end },
};

static bool barreleye_probe(void)
{
	if (!dt_node_is_compatible(dt_root, "ingrasys,barreleye"))
		return false;

	/* Lot of common early inits here */
	astbmc_early_init();
	slot_table_init(barreleye_phb_table);

	return true;
}


DECLARE_PLATFORM(barreleye) = {
	.name			= "Barreleye",
	.probe			= barreleye_probe,
	.init			= astbmc_init,
	.pci_get_slot_info	= slot_table_get_slot_info,
	.pci_probe_complete	= check_all_slot_table,
	.external_irq		= astbmc_ext_irq_serirq_cpld,
	.cec_power_down         = astbmc_ipmi_power_down,
	.cec_reboot             = astbmc_ipmi_reboot,
	.elog_commit		= ipmi_elog_commit,
	.start_preload_resource	= flash_start_preload_resource,
	.resource_loaded	= flash_resource_loaded,
	.exit			= ipmi_wdt_final_reset,
	.terminate		= ipmi_terminate,
	.op_display		= op_display_lpc,
};
