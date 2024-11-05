// SPDX-License-Identifier: Apache-2.0
/* Copyright 2017 IBM Corp.
 * Copyright 2018-2019 Raptor Engineering, LLC
 * Copyright 2019 Stewart Smith
 */

#include <skiboot.h>
#include <device.h>
#include <console.h>
#include <chip.h>
#include <ipmi.h>
#include <psi.h>
#include <lpc.h>

#include "astbmc.h"

ST_PLUGGABLE(blackbird_cpu1_slot1, "SLOT1 PCIE 4.0 X16");
ST_PLUGGABLE(blackbird_cpu1_slot2, "SLOT2 PCIE 4.0 X8");

ST_BUILTIN_DEV(blackbird_builtin_sata, "Builtin SATA");
ST_BUILTIN_DEV(blackbird_builtin_usb, "Builtin USB");
ST_BUILTIN_DEV(blackbird_builtin_ethernet, "Builtin Ethernet");
ST_BUILTIN_DEV(blackbird_builtin_bmc, "BMC");

static const struct slot_table_entry blackbird_phb_table[] = {
	ST_PHB_ENTRY(0, 0, blackbird_cpu1_slot1),
	ST_PHB_ENTRY(0, 1, blackbird_cpu1_slot2),

	ST_PHB_ENTRY(0, 2, blackbird_builtin_sata),
	ST_PHB_ENTRY(0, 3, blackbird_builtin_usb),
	ST_PHB_ENTRY(0, 4, blackbird_builtin_ethernet),
	ST_PHB_ENTRY(0, 5, blackbird_builtin_bmc),

	{ .etype = st_end },
};

static bool blackbird_probe(void)
{
	if (!dt_node_is_compatible(dt_root, "rcs,blackbird"))
		return false;

	/* Lot of common early inits here */
	astbmc_early_init();

	/* Setup UART for use by OPAL (Linux hvc) */
	uart_set_console_policy(UART_CONSOLE_OPAL);

	slot_table_init(blackbird_phb_table);

	return true;
}

static int64_t blackbird_write_oppanel_async(uint64_t async_token __unused,
					     oppanel_line_t *lines,
					     uint64_t num_lines)
{
	uint8_t *line;
	int len;

	if (num_lines != 1)
		return OPAL_PARAMETER;

	line = (void *) be64_to_cpu(lines[0].line);
	len = be64_to_cpu(lines[0].line_len);

	if (len > 0)
		lpc_probe_write(OPAL_LPC_IO, 0x80, line[0], 1);
	if (len > 1)
		lpc_probe_write(OPAL_LPC_IO, 0x81, line[1], 1);
	if (len > 2)
		lpc_probe_write(OPAL_LPC_IO, 0x82, line[2], 1);

	return OPAL_SUCCESS;
}

static void blackbird_init(void)
{
	struct dt_node *oppanel;

	astbmc_init();

	opal_register(OPAL_WRITE_OPPANEL_ASYNC, blackbird_write_oppanel_async, 3);

	oppanel = dt_new(opal_node, "oppanel");
	dt_add_property_cells(oppanel, "#length", 3);
	dt_add_property_cells(oppanel, "#lines", 1);
	dt_add_property_strings(oppanel, "compatible", "ibm,opal-oppanel", "rcs,ipl-observer");

}

DECLARE_PLATFORM(blackbird) = {
	.name			= "Blackbird",
	.probe			= blackbird_probe,
	.init			= blackbird_init,
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
