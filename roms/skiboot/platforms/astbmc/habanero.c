// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#include <skiboot.h>
#include <device.h>
#include <console.h>
#include <chip.h>
#include <ipmi.h>

#include "astbmc.h"

static const struct slot_table_entry habanero_phb0_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Slot3",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry habanero_plx_slots[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(1,0),
		.name = "Network Mezz",
	},
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(8,0),
		.name = "Storage Mezz",
	},
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(9,0),
		.name = "Backplane USB",
	},
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0xa,0),
		.name = "Backplane BMC",
	},
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0x10,0),
		.name = "Slot2",
	},
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0x11,0),
		.name = "Slot1",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry habanero_plx_up[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.children = habanero_plx_slots,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry habanero_phb1_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Backplane PLX",
		.children = habanero_plx_up,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry habanero_phb2_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Slot4",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry habanero_phb_table[] = {
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,0),
		.children = habanero_phb0_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,1),
		.children = habanero_phb1_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,2),
		.children = habanero_phb2_slot,
	},
	{ .etype = st_end },
};

static bool habanero_probe(void)
{
	const char *model;

	if (!dt_node_is_compatible(dt_root, "ibm,powernv"))
		return false;

	/* Temporary ... eventually we'll get that in compatible */
	model = dt_prop_get_def(dt_root, "model", NULL);
	if ((!model || !strstr(model, "habanero")) &&
	    (!dt_node_is_compatible(dt_root, "tyan,habanero")))
		return false;

	/* Lot of common early inits here */
	astbmc_early_init();

	slot_table_init(habanero_phb_table);

	return true;
}

DECLARE_PLATFORM(habanero) = {
	.name			= "Habanero",
	.bmc			= &bmc_plat_ast2400_ami,
	.probe			= habanero_probe,
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
	.seeprom_update		= astbmc_seeprom_update,
	.op_display		= op_display_lpc,
};
