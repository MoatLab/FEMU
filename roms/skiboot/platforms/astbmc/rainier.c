// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2020 IBM
 */

#include <skiboot.h>
#include <device.h>
#include <ipmi.h>
#include <chip.h>
#include <i2c.h>
#include <timebase.h>

#include "astbmc.h"

/*
 * puti2c pu 2 1 C6 00 6 1 -quiet
 * puti2c pu 2 1 C6 54 7 1 -quiet
 * puti2c pu 2 1 C6 05 8 1 -quiet
 * puti2c pu 2 1 C6 00 9 1 -quiet
 *
 * sleep 4
 *
 * puti2c pu 2 1 C6 55 6 1 -quiet
 * puti2c pu 2 1 C6 55 7 1 -quiet
 * 	2  - engine
 * 	1  - port
 * 	C6 - slave addr
 * 	55 - data
 * 	7  - register
 * 	1  - register length?
 */

static int64_t smbus_write8(struct i2c_bus *bus, uint8_t reg, uint8_t data)
{
	struct i2c_request req;

	memset(&req, 0, sizeof(req));

	req.bus	= bus;
	req.dev_addr   = 0xC6 >> 1; /* Docs use 8bit addresses */

	req.op         = SMBUS_WRITE;
	req.offset     = reg;
	req.offset_bytes = 1;
	req.rw_buf     = &data;
	req.rw_len     = 1;
	req.timeout = 100;

	return i2c_request_sync(&req);
}

static int64_t slot_power_enable(struct i2c_bus *bus)
{
	/* FIXME: we could do this in one transaction using auto-increment */
	if (smbus_write8(bus, 0x6, 0x00))
		return -1;
	if (smbus_write8(bus, 0x7, 0x54))
		return -1;
	if (smbus_write8(bus, 0x8, 0x05))
		return -1;
	if (smbus_write8(bus, 0x9, 0x00))
		return -1;

	/* FIXME: Poll for PGOOD going high */

	if (smbus_write8(bus, 0x6, 0x55))
		return -1;
	if (smbus_write8(bus, 0x7, 0x55))
		return -1;

	return 0;
}

static void rainier_init_slot_power(void)
{
	struct proc_chip *chip;
	struct i2c_bus *bus;

	/*
	 * Controller on P0 is for slots C7 -> C11
	 *            on P2 is for slots C0 -> C4
	 * Both chips use engine 2 port 1
	 *
	 * Rainier with only one socket is officially supported, so
	 * we may not have slots C0 -> C4
	 */
	for_each_chip(chip) {
		if (chip->id % 4)
			continue;
		bus = p8_i2c_add_bus(chip->id, 2, 1, 400000);
		if (!bus) {
			prerror("Unable to find PCIe power controller I2C bus!\n");
			return;
		}
		if (slot_power_enable(bus)) {
			prerror("Error enabling PCIe slot power on chip %d\n",
				chip->id);
		}
	}
}

static void rainier_init(void)
{
	astbmc_init();
	rainier_init_slot_power();
}

static bool rainier_probe(void)
{
	if (!dt_node_is_compatible(dt_root, "ibm,rainier") &&
	    !dt_node_is_compatible(dt_root, "ibm,rainier-2s2u") &&
	    !dt_node_is_compatible(dt_root, "ibm,rainier-2s4u"))
		return false;

	/* Lot of common early inits here */
	astbmc_early_init();

	/* Setup UART for use by OPAL (Linux hvc) */
	uart_set_console_policy(UART_CONSOLE_OPAL);

	return true;
}

DECLARE_PLATFORM(rainier) = {
	.name			= "Rainier",
	.probe			= rainier_probe,
	.init			= rainier_init,
	.start_preload_resource	= flash_start_preload_resource,
	.resource_loaded	= flash_resource_loaded,
	.bmc			= &bmc_plat_ast2600_openbmc,
	.cec_power_down         = astbmc_ipmi_power_down,
	.cec_reboot             = astbmc_ipmi_reboot,
	.elog_commit		= ipmi_elog_commit,
	.exit			= astbmc_exit,
	.terminate		= ipmi_terminate,
};
