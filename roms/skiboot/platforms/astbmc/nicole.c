// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright (c) 2019 YADRO
 */

#include <skiboot.h>
#include <device.h>
#include <ipmi.h>

#include "astbmc.h"

#define CHIP_ID_CPU0 0x00
#define CHIP_ID_CPU1 0x08

ST_PLUGGABLE(nicole_backplane0, "Backplane0 (16x)");
ST_PLUGGABLE(nicole_backplane1, "Backplane1 (16x)");

ST_BUILTIN_DEV(nicole_builtin_net, "Builtin Network");
ST_BUILTIN_DEV(nicole_builtin_ssd0, "Builtin SSD0");
ST_BUILTIN_DEV(nicole_builtin_ssd1, "Builtin SSD1");
ST_BUILTIN_DEV(nicole_builtin_vga, "Builtin VGA");
ST_BUILTIN_DEV(nicole_builtin_usb, "Builtin USB");

static const struct slot_table_entry nicole_phb_table[] = {
	ST_PHB_ENTRY(CHIP_ID_CPU0, 0, nicole_backplane0),
	ST_PHB_ENTRY(CHIP_ID_CPU0, 1, nicole_builtin_net),
	ST_PHB_ENTRY(CHIP_ID_CPU0, 2, nicole_builtin_ssd0),
	ST_PHB_ENTRY(CHIP_ID_CPU0, 3, nicole_backplane1),

	ST_PHB_ENTRY(CHIP_ID_CPU1, 3, nicole_builtin_ssd1),
	ST_PHB_ENTRY(CHIP_ID_CPU1, 4, nicole_builtin_vga),
	ST_PHB_ENTRY(CHIP_ID_CPU1, 5, nicole_builtin_usb),

	{ .etype = st_end },
};

/* Fixup the system VPD EEPROM size.
 *
 * Hostboot doesn't export the correct description for EEPROMs, as a result,
 * all EEPROMs in the system work in "atmel,24c128" compatibility mode (16KiB).
 * Nicole platform has 32KiB EEPROM for the system VPD.
 */
static void vpd_dt_fixup(void)
{
	struct dt_node* vpd_eeprom = dt_find_by_path(dt_root,
		"/xscom@603fc00000000/i2cm@a2000/i2c-bus@0/eeprom@50");

	if (vpd_eeprom) {
		dt_check_del_prop(vpd_eeprom, "compatible");
		dt_add_property_string(vpd_eeprom, "compatible", "atmel,24c256");

		dt_check_del_prop(vpd_eeprom, "label");
		dt_add_property_string(vpd_eeprom, "label", "system-vpd");
	}
}

static bool nicole_probe(void)
{
	if (!dt_node_is_compatible(dt_root, "YADRO,nicole"))
		return false;

	/* Lot of common early inits here */
	astbmc_early_init();

	/* Setup UART for use by OPAL (Linux hvc) */
	uart_set_console_policy(UART_CONSOLE_OPAL);

	/* Fixup system VPD EEPROM size */
	vpd_dt_fixup();

	slot_table_init(nicole_phb_table);

	return true;
}

DECLARE_PLATFORM(nicole) = {
	.name			= "Nicole",
	.probe			= nicole_probe,
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
};
