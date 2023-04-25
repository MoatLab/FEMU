// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2020 IBM
 */

#include <skiboot.h>
#include <device.h>
#include <ipmi.h>
#include <pau.h>
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

static int64_t rainier_i2c_assert_reset(uint8_t i2c_bus_id)
{
	uint8_t data;
	int64_t rc = OPAL_SUCCESS;

	/*
	 * Set the i2c reset pin in output mode (9553 device)
	 * To write a register:
	 *   puti2c pu 0 0|1 C4 <data> <offset> 1,
	 *   with data being a 2-nibble hex value and offset being the
	 *   register offset from the datasheet
	 *
	 * puti2c (-p1) 0 0|1 C4 51 5 1	     0		: i2c engine
	 *				     0|1	: i2c_port
	 *				     C4 (C4 > 1 = 62) : Address
	 *				     51		: data
	 *				     5		: register (offset)
	 *				     1		: offset byte
	 *
	 * 7.3.6 LS0 - LED selector register: default value 0x55
	 * bit 1:0 01* LED0 selected  (OpenCapi card)
	 *
	 * offset 0x05, register name: LS0, Fct: LED selector
	 * see Table 4. Control register definition (PCA9553)
	 */
	data = 0x51;
	rc = i2c_request_send(i2c_bus_id,
			      platform.ocapi->i2c_dev_addr,
			      SMBUS_WRITE, 0x5, 1,
			      &data, sizeof(data), 120);

	return rc;
}

static int64_t rainier_i2c_deassert_reset(uint8_t i2c_bus_id)
{
	uint8_t data;
	int64_t rc = OPAL_SUCCESS;

	/* puti2c (-p1) 0 0|1 C4 55 <offset> 1
	 *
	 * offset 0x05, register name: LS0, Fct: LED selector
	 * see Table 4. Control register definition (PCA9553)
	 */
	data = 0x55;
	rc = i2c_request_send(i2c_bus_id,
			      platform.ocapi->i2c_dev_addr,
			      SMBUS_WRITE, 0x5, 1,
			      &data, sizeof(data), 120);

	return rc;
}

static int get_i2c_info(struct pau_dev *dev, int *engine, int *port)
{
	uint32_t chip_id = dev->pau->chip_id;
	uint32_t pau_index = dev->pau->index;
	uint32_t link = dev->index;

	switch (chip_id) {
	case 0:
	case 4:
		/*
		 * OP3: links 0 and 1 on chip 0
		 *      link 0 only on chip 4
		 */
		if (pau_index == 1) {
			if (link == 1 && chip_id == 4)
				return -1;
			*engine = 1;
			*port = link;
			return 0;
		}
		break;
	case 2:
	case 6:
		/*
		 * OP0: links 0 and 1 on chip 2
		 *      link 1 only on chip 6
		 */
		if (pau_index == 0) {
			if (link == 0 && chip_id == 6)
				return -1;
			*engine = 1;
			*port = link;
			return 0;
		}
		break;
	}
	return -1;
}

static void rainier_i2c_presence_init(struct pau_dev *dev)
{
	char port_name[17];
	struct dt_node *np;
	int engine, port;

	/* Find I2C port */
	if (dev->i2c_bus_id)
		return;

	if (get_i2c_info(dev, &engine, &port))
		return;

	snprintf(port_name, sizeof(port_name), "p8_%08x_e%dp%d",
		 dev->pau->chip_id, engine, port);

	dt_for_each_compatible(dt_root, np, "ibm,power10-i2c-port") {
		if (streq(port_name, dt_prop_get(np, "ibm,port-name"))) {
			dev->i2c_bus_id = dt_prop_get_u32(np, "ibm,opal-id");
			break;
		}
	}
}

static int64_t rainier_i2c_dev_detect(struct pau_dev *dev,
				      bool *presence)
{
	int64_t rc = OPAL_SUCCESS;
	uint8_t detect;

	/* Read the presence value
	 * geti2c (-p1) pu 0 0|1 C4 1 <offset> 1
	 *
	 * offset 0x00, register name: INPUT, Fct: input register
	 * see Table 4. Control register definition (PCA9553)
	 */
	detect = 0x00;
	*presence = false;
	rc = i2c_request_send(dev->i2c_bus_id,
			      platform.ocapi->i2c_dev_addr,
			      SMBUS_READ, 0x00, 1,
			      &detect, 1, 120);

	/* LED0 (bit 0): a high level no card is plugged */
	if (!rc && !(detect & platform.ocapi->i2c_predetect_pin))
		*presence = true;

	return rc;
}

static void rainier_pau_device_detect(struct pau *pau)
{
	struct pau_dev *dev;
	bool presence;
	int64_t rc;

	/* OpenCapi devices are possibly connected on Optical link pair:
	 * OP0 or OP3
	 * pau_index	Interface Link - OPxA/B
	 * 0		OPT0 -- PAU0
	 *		OPT1 -- no PAU, SMP only
	 *		OPT2 -- no PAU, SMP only
	 * 1		OPT3 -- PAU3
	 * 2		OPT4 -- PAU4 by default, but can be muxed to use PAU5 - N/A on Rainier
	 * 3		OPT5 -- PAU5 by default, but can be muxed to use PAU4 - N/A on Rainier
	 * 4		OPT6 -- PAU6 by default, but can be muxed to use PAU7 - N/A on Rainier
	 * 5		OPT7 -- PAU7 by default, but can be muxed to use PAU6 - N/A on Rainier
	 */
	pau_for_each_dev(dev, pau) {
		dev->type = PAU_DEV_TYPE_UNKNOWN;

		rainier_i2c_presence_init(dev);
		if (dev->i2c_bus_id) {
			rc = rainier_i2c_dev_detect(dev, &presence);
			if (!rc && presence)
				dev->type = PAU_DEV_TYPE_OPENCAPI;
		}

		dt_add_property_u64(dev->dn, "ibm,link-speed", 25000000000ull);
	}
}

static void rainier_pau_create_i2c_bus(void)
{
	struct dt_node *xscom, *i2cm, *i2c_bus;

	prlog(PR_DEBUG, "PLAT: Adding I2C bus device node for PAU reset\n");
	dt_for_each_compatible(dt_root, xscom, "ibm,xscom") {
		i2cm = dt_find_by_name(xscom, "i2cm@a1000");
		if (!i2cm) {
			prlog(PR_DEBUG, "PLAT: Adding master @a1000\n");
			i2cm = dt_new(xscom, "i2cm@a1000");
			dt_add_property_cells(i2cm, "reg", 0xa1000, 0x1000);
			dt_add_property_strings(i2cm, "compatible",
						"ibm,power8-i2cm", "ibm,power9-i2cm");
			dt_add_property_cells(i2cm, "#size-cells", 0x0);
			dt_add_property_cells(i2cm, "#address-cells", 0x1);
			dt_add_property_cells(i2cm, "chip-engine#", 0x1);
			dt_add_property_cells(i2cm, "clock-frequency", 0x7735940);
		}

		i2c_bus = dt_find_by_name(i2cm, "i2c-bus@0");
		if (!i2c_bus) {
			prlog(PR_DEBUG, "PLAT: Adding bus 0 to master @a1000\n");
			i2c_bus = dt_new_addr(i2cm, "i2c-bus", 0);
			dt_add_property_cells(i2c_bus, "reg", 0);
			dt_add_property_cells(i2c_bus, "bus-frequency", 0x61a80);
			dt_add_property_strings(i2c_bus, "compatible",
						"ibm,opal-i2c",
						"ibm,power8-i2c-port",
						"ibm,power9-i2c-port",
						"ibm,power10-i2c-port");
		}

		i2c_bus = dt_find_by_name(i2cm, "i2c-bus@1");
		if (!i2c_bus) {
			prlog(PR_DEBUG, "PLAT: Adding bus 1 to master @a1000\n");
			i2c_bus = dt_new_addr(i2cm, "i2c-bus", 1);
			dt_add_property_cells(i2c_bus, "reg", 1);
			dt_add_property_cells(i2c_bus, "bus-frequency", 0x61a80);
			dt_add_property_strings(i2c_bus, "compatible",
						"ibm,opal-i2c",
						"ibm,power8-i2c-port",
						"ibm,power9-i2c-port",
						"ibm,power10-i2c-port");
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

	/* create i2c entries for PAU */
	rainier_pau_create_i2c_bus();

	return true;
}

static struct platform_ocapi rainier_ocapi = {
	.i2c_dev_addr		= 0x62, /* C4 >> 1 */
	.i2c_intreset_pin	= 0x02, /* PIN 2 - LED1 - INT/RESET */
	.i2c_predetect_pin	= 0x01, /* PIN 1 - LED0 - PRE-DETECT */
	/* As previously for NPU/NPU2, we use indirect functions for
	 * this platform to reset the device. This makes the code more
	 * generic in PAU.
	 */
	.i2c_assert_reset	= rainier_i2c_assert_reset,
	.i2c_deassert_reset	= rainier_i2c_deassert_reset,
};

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
	.pau_device_detect	= rainier_pau_device_detect,
	.ocapi			= &rainier_ocapi,
	.exit			= astbmc_exit,
	.terminate		= ipmi_terminate,
};
