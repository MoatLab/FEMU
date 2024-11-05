// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#include <skiboot.h>
#include <console.h>
#include <device.h>
#include <ipmi.h>

#include <platforms/astbmc/astbmc.h>

static bool bt_device_present;

ST_PLUGGABLE(qemu_slot0, "pcie.0");
ST_PLUGGABLE(qemu_slot1, "pcie.1");

static const struct slot_table_entry qemu_sw_down[] = {
	SW_PLUGGABLE("sw0_down0", 0x0),
	SW_BUILTIN  ("sw0_down1", 0x1),
	SW_PLUGGABLE("sw0_down2", 0x2),
	{ .etype = st_end },
};
ST_BUILTIN_DEV(qemu_sw_up,   "sw0_up", .children = qemu_sw_down);
ST_BUILTIN_DEV(qemu_sw_root, "pcie.2", .children = qemu_sw_up);

ST_PLUGGABLE(qemu_slot3, "pcie.3");
ST_PLUGGABLE(qemu_slot4, "pcie.4");
ST_PLUGGABLE(qemu_slot5, "pcie.5");

static const struct slot_table_entry qemu_phb_table[] = {
	ST_PHB_ENTRY(0, 0, qemu_slot0),
	ST_PHB_ENTRY(0, 1, qemu_slot1),
	ST_PHB_ENTRY(0, 2, qemu_sw_root),
	ST_PHB_ENTRY(0, 3, qemu_slot3),
	ST_PHB_ENTRY(0, 4, qemu_slot4),
	ST_PHB_ENTRY(0, 5, qemu_slot5),
	{ .etype = st_end },
};

static bool qemu_probe_common(const char *compat)
{
	struct dt_node *n;

	if (!dt_node_is_compatible(dt_root, compat))
		return false;

        astbmc_early_init();

	/* check if the BT device was defined by QEMU */
	dt_for_each_compatible(dt_root, n, "bt") {
		bt_device_present = true;
	}

	slot_table_init(qemu_phb_table);

	return true;
}

static bool qemu_probe(void)
{
	return qemu_probe_common("qemu,powernv");
}

static bool qemu_probe_powernv8(void)
{
	return qemu_probe_common("qemu,powernv8");
}

static bool qemu_probe_powernv9(void)
{
	return qemu_probe_common("qemu,powernv9");
}

static bool qemu_probe_powernv10(void)
{
	return qemu_probe_common("qemu,powernv10");
}

static void qemu_init(void)
{
	if (!bt_device_present) {
		set_opal_console(&uart_opal_con);
	} else {
		astbmc_init();
	}
}

DECLARE_PLATFORM(qemu) = {
	.name		= "QEMU",
	.probe		= qemu_probe,
	.init		= qemu_init,
	.external_irq   = astbmc_ext_irq_serirq_cpld,
	.cec_power_down = astbmc_ipmi_power_down,
	.cec_reboot     = astbmc_ipmi_reboot,
	.pci_get_slot_info = slot_table_get_slot_info,
	.start_preload_resource	= flash_start_preload_resource,
	.resource_loaded	= flash_resource_loaded,
	.terminate	= ipmi_terminate,
};

/*
 * For a QEMU PowerNV machine using POWER8 CPUs (Palmetto)
 */
DECLARE_PLATFORM(qemu_powernv8) = {
	.name		= "QEMU POWER8",
	.probe		= qemu_probe_powernv8,
	.bmc		= &bmc_plat_ast2400_ami,
	.init		= qemu_init,
	.external_irq   = astbmc_ext_irq_serirq_cpld,
	.cec_power_down = astbmc_ipmi_power_down,
	.cec_reboot     = astbmc_ipmi_reboot,
	.pci_get_slot_info = slot_table_get_slot_info,
	.start_preload_resource	= flash_start_preload_resource,
	.resource_loaded	= flash_resource_loaded,
	.exit			= astbmc_exit,
	.terminate	= ipmi_terminate,
};

/*
 * For a QEMU PowerNV machine using POWER9 CPUs (Witherspoon)
 */
DECLARE_PLATFORM(qemu_powernv9) = {
	.name		= "QEMU POWER9",
	.probe		= qemu_probe_powernv9,
	.bmc		= &bmc_plat_ast2500_openbmc,
	.init		= qemu_init,
	.external_irq   = astbmc_ext_irq_serirq_cpld,
	.cec_power_down = astbmc_ipmi_power_down,
	.pci_get_slot_info = slot_table_get_slot_info,
	.cec_reboot     = astbmc_ipmi_reboot,
	.start_preload_resource	= flash_start_preload_resource,
	.resource_loaded	= flash_resource_loaded,
	.exit			= astbmc_exit,
	.terminate	= ipmi_terminate,
};

/*
 * For a QEMU PowerNV machine using POWER10 CPUs (Rainier)
 */
DECLARE_PLATFORM(qemu_powernv10) = {
	.name		= "QEMU POWER10",
	.probe		= qemu_probe_powernv10,
	.bmc		= &bmc_plat_ast2500_openbmc,
	.init		= qemu_init,
	.external_irq   = astbmc_ext_irq_serirq_cpld,
	.cec_power_down = astbmc_ipmi_power_down,
	.cec_reboot     = astbmc_ipmi_reboot,
	.pci_get_slot_info = slot_table_get_slot_info,
	.start_preload_resource	= flash_start_preload_resource,
	.resource_loaded	= flash_resource_loaded,
	.exit			= astbmc_exit,
	.terminate	= ipmi_terminate,
};
