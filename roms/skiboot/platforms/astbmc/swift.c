// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2019 IBM Corp.
 */

#include <skiboot.h>
#include <ipmi.h>
#include "astbmc.h"
#include <device.h>

static bool swift_probe(void)
{
	if (!dt_node_is_compatible(dt_root, "ibm,swift"))
		return false;

	/* Lot of common early inits here */
	astbmc_early_init();

	/* Setup UART for use by OPAL (Linux hvc) */
	uart_set_console_policy(UART_CONSOLE_OPAL);

	return true;
}

DECLARE_PLATFORM(swift) = {
	.bmc			= &bmc_plat_ast2500_openbmc,
	.cec_power_down		= astbmc_ipmi_power_down,
	.cec_reboot		= astbmc_ipmi_reboot,
	.elog_commit		= ipmi_elog_commit,
	.exit			= astbmc_exit,
	.init			= astbmc_init,
	.name			= "Swift",
	.pci_get_slot_info	= dt_slot_get_slot_info,
	.probe			= swift_probe,
	.resource_loaded	= flash_resource_loaded,
	.start_preload_resource	= flash_start_preload_resource,
	.terminate		= ipmi_terminate,
};
