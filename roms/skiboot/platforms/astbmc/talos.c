// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2017-2019 IBM Corp.
 * Copyright 2018-2019 Raptor Engineering, LLC
 */

#include <skiboot.h>
#include <device.h>
#include <console.h>
#include <chip.h>
#include <ipmi.h>
#include <psi.h>
#include <npu-regs.h>

#include "astbmc.h"

ST_PLUGGABLE(talos_cpu1_slot1, "CPU1 Slot1 (8x)");
ST_PLUGGABLE(talos_cpu1_slot2, "CPU1 Slot2 (16x)");

ST_PLUGGABLE(talos_cpu2_slot1, "CPU2 Slot1 (16x)");
ST_PLUGGABLE(talos_cpu2_slot2, "CPU2 Slot2 (16x)");
ST_PLUGGABLE(talos_cpu2_slot3, "CPU2 Slot3 (8x)");

ST_BUILTIN_DEV(talos_builtin_raid, "Builtin SAS");
ST_BUILTIN_DEV(talos_builtin_usb, "Builtin USB");
ST_BUILTIN_DEV(talos_builtin_ethernet, "Builtin Ethernet");
ST_BUILTIN_DEV(talos_builtin_bmc, "BMC");

static const struct slot_table_entry talos_phb_table[] = {
	ST_PHB_ENTRY(0, 0, talos_cpu1_slot2),
	ST_PHB_ENTRY(0, 1, talos_cpu1_slot1),

	ST_PHB_ENTRY(0, 2, talos_builtin_raid),
	ST_PHB_ENTRY(0, 3, talos_builtin_usb),
	ST_PHB_ENTRY(0, 4, talos_builtin_ethernet),
	ST_PHB_ENTRY(0, 5, talos_builtin_bmc),

	ST_PHB_ENTRY(8, 0, talos_cpu2_slot2), // might be swapped with 3
	ST_PHB_ENTRY(8, 1, talos_cpu2_slot3), // might be PHB1 or 2
	ST_PHB_ENTRY(8, 3, talos_cpu2_slot1),

	{ .etype = st_end },
};

static bool talos_probe(void)
{
	if (!dt_node_is_compatible(dt_root, "rcs,talos"))
		return false;

	/* Lot of common early inits here */
	astbmc_early_init();

	/* Setup UART for use by OPAL (Linux hvc) */
	uart_set_console_policy(UART_CONSOLE_OPAL);

	slot_table_init(talos_phb_table);

	return true;
}

DECLARE_PLATFORM(talos) = {
	.name			= "Talos",
	.probe			= talos_probe,
	.init			= astbmc_init,
	.start_preload_resource	= flash_start_preload_resource,
	.resource_loaded	= flash_resource_loaded,
	.bmc			= &bmc_plat_ast2500_openbmc,
	.pci_get_slot_info	= slot_table_get_slot_info,
	.pci_probe_complete	= check_all_slot_table,
	.cec_power_down         = astbmc_ipmi_power_down,
	.cec_reboot             = astbmc_ipmi_reboot,
	.elog_commit		= ipmi_elog_commit,
	.exit			= astbmc_exit,
	.terminate		= ipmi_terminate,
	.op_display		= op_display_lpc,
};
