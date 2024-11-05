// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2020 Wistron Corp.
 * Copyright 2017-2019 IBM Corp.
 */

#include <skiboot.h>
#include <device.h>
#include <console.h>
#include <chip.h>
#include <ipmi.h>
#include <psi.h>
#include <npu-regs.h>
#include <secvar.h>

#include "astbmc.h"

ST_PLUGGABLE(mowgli_slot1, "Pcie Slot1");
ST_PLUGGABLE(mowgli_builtin_SAS, "Builtin SAS");
ST_BUILTIN_DEV(mowgli_builtin_bmc, "BMC");
ST_PLUGGABLE(mowgli_builtin_ethernet, "Builtin Ethernet");
ST_BUILTIN_DEV(mowgli_builtin_usb, "Builtin USB");

static const struct slot_table_entry mowgli_phb_table[] = {
	ST_PHB_ENTRY(0, 0, mowgli_slot1),
	ST_PHB_ENTRY(0, 1, mowgli_builtin_SAS),
	ST_PHB_ENTRY(0, 2, mowgli_builtin_bmc),
	ST_PHB_ENTRY(0, 3, mowgli_builtin_ethernet),
	ST_PHB_ENTRY(0, 4, mowgli_builtin_usb),

	{ .etype = st_end },
};

/*
 * HACK: Hostboot doesn't export the correct data for the system VPD EEPROM
 *       for this system. So we need to work around it here.
 */
static void vpd_dt_fixup(void)
{
	struct dt_node *n = dt_find_by_path(dt_root,
		"/xscom@603fc00000000/i2cm@a2000/i2c-bus@0/eeprom@50");

	if (n) {
		dt_check_del_prop(n, "compatible");
		dt_add_property_string(n, "compatible", "atmel,24c512");

		dt_check_del_prop(n, "label");
		dt_add_property_string(n, "label", "system-vpd");
	}
}

static void phb0_fixup(void)
{
	struct dt_node *stk;
	u32 phb_index;

	/* Limit PHB0/(pec0) to gen3 speed */
	dt_for_each_compatible(dt_root, stk, "ibm,power9-phb-stack") {
		phb_index = dt_prop_get_u32_def(stk, "ibm,phb-index", -1);
		if (phb_index == 0) {
			dt_check_del_prop(stk, "ibm,max-link-speed");
			dt_add_property_cells(stk, "ibm,max-link-speed", 3);
		}
	}
}

static bool mowgli_probe(void)
{
	if (!dt_node_is_compatible(dt_root, "ibm,mowgli"))
		return false;

	/* Lot of common early inits here */
	astbmc_early_init();

	/* Setup UART for use by OPAL (Linux hvc) */
	uart_set_console_policy(UART_CONSOLE_OPAL);

	vpd_dt_fixup();

	slot_table_init(mowgli_phb_table);
	phb0_fixup();

	return true;
}
static int mowgli_secvar_init(void)
{
	return secvar_main(secboot_tpm_driver, edk2_compatible_v1);
}


DECLARE_PLATFORM(mowgli) = {
	.name			= "Mowgli",
	.probe			= mowgli_probe,
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
	.secvar_init		= mowgli_secvar_init,
};
