// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#include <skiboot.h>
#include <device.h>
#include <fsp.h>
#include <pci.h>
#include <pci-cfg.h>
#include <chip.h>
#include <i2c.h>
#include <timebase.h>
#include <hostservices.h>

#include "ibm-fsp.h"
#include "lxvpd.h"

static struct dt_node *dt_create_i2c_master(struct dt_node *n, uint32_t eng_id)
{
	struct dt_node *i2cm;
	uint64_t freq;
	uint32_t clock;

	/* Each master registers set is of length 0x20 */
	i2cm = dt_new_addr(n, "i2cm", 0xa0000 + eng_id * 0x20);
	if (!i2cm)
		return NULL;

	dt_add_property_string(i2cm, "compatible",
			       "ibm,power8-i2cm");
	dt_add_property_cells(i2cm, "reg", 0xa0000 + eng_id * 0x20,
			      0x20);
	dt_add_property_cells(i2cm, "chip-engine#", eng_id);
	dt_add_property_cells(i2cm, "#address-cells", 1);
	dt_add_property_cells(i2cm, "#size-cells", 0);

	/* Derive the clock source frequency */
	freq = dt_prop_get_u64_def(n, "bus-frequency", 0);
	clock = (u32)(freq / 4);
	if (clock)
		dt_add_property_cells(i2cm, "clock-frequency", clock);
	else
		dt_add_property_cells(i2cm, "clock-frequency", 125000000);
	return i2cm;
}

static struct dt_node *dt_create_i2c_bus(struct dt_node *i2cm,
					 const char *port_name, uint32_t port_id)
{
	static struct dt_node *port;

	port = dt_new_addr(i2cm, "i2c-bus", port_id);
	if (!port)
		return NULL;

	dt_add_property_strings(port, "compatible", "ibm,power8-i2c-port",
				"ibm,opal-i2c");
	dt_add_property_string(port, "ibm,port-name", port_name);
	dt_add_property_cells(port, "reg", port_id);
	dt_add_property_cells(port, "bus-frequency", 400000);
	dt_add_property_cells(port, "#address-cells", 1);
	dt_add_property_cells(port, "#size-cells", 0);

	return port;
}

static struct dt_node *dt_create_i2c_device(struct dt_node *bus, uint8_t addr,
					    const char *name, const char *compat,
					    const char *label)
{
	struct dt_node *dev;

	dev = dt_new_addr(bus, name, addr);
	if (!dev)
		return NULL;

	dt_add_property_string(dev, "compatible", compat);
	dt_add_property_string(dev, "label", label);
	dt_add_property_cells(dev, "reg", addr);
	dt_add_property_string(dev, "status", "reserved");

	return dev;
}

static void firenze_dt_fixup_i2cm(void)
{
	struct dt_node *master, *bus, *dev;
	struct proc_chip *c;
	const uint32_t *p;
	char name[32];
	uint64_t lx;

	if (dt_find_compatible_node(dt_root, NULL, "ibm,power8-i2cm"))
		return;

	p = dt_prop_get_def(dt_root, "ibm,vpd-lx-info", NULL);
	if (!p)
		return;

	lx = ((uint64_t)p[1] << 32) | p[2];

	switch (lx) {
	case LX_VPD_2S4U_BACKPLANE:
	case LX_VPD_2S2U_BACKPLANE:
	case LX_VPD_SHARK_BACKPLANE: /* XXX confirm ? */
		/* i2c nodes on chip 0x10 */
		c = get_chip(0x10);
		if (c) {
			/* Engine 1 */
			master = dt_create_i2c_master(c->devnode, 1);
			assert(master);
			snprintf(name, sizeof(name), "p8_%08x_e%dp%d", c->id, 1, 0);
			bus = dt_create_i2c_bus(master, name, 0);
			assert(bus);
			dev = dt_create_i2c_device(bus, 0x39, "power-control",
						   "maxim,5961", "pcie-hotplug");
			assert(dev);
			dt_add_property_strings(dev, "target-list", "slot-C4",
						"slot-C5");

			dev = dt_create_i2c_device(bus, 0x3a, "power-control",
						   "maxim,5961", "pcie-hotplug");
			assert(dev);
			dt_add_property_strings(dev, "target-list", "slot-C2",
						"slot-C3");
		} else {
			prlog(PR_INFO, "PLAT: Chip not found for the id 0x10\n");
		}

	/* Fall through */
	case LX_VPD_1S4U_BACKPLANE:
	case LX_VPD_1S2U_BACKPLANE:
		/* i2c nodes on chip 0 */
		c = get_chip(0);
		if (!c) {
			prlog(PR_INFO, "PLAT: Chip not found for the id 0x0\n");
			break;
		}

		/* Engine 1*/
		master = dt_create_i2c_master(c->devnode, 1);
		assert(master);
		snprintf(name, sizeof(name), "p8_%08x_e%dp%d", c->id, 1, 0);
		bus = dt_create_i2c_bus(master, name, 0);
		assert(bus);
		dev = dt_create_i2c_device(bus, 0x32, "power-control",
					   "maxim,5961", "pcie-hotplug");
		assert(dev);
		dt_add_property_strings(dev, "target-list", "slot-C10", "slot-C11");

		dev = dt_create_i2c_device(bus, 0x35, "power-control",
					   "maxim,5961", "pcie-hotplug");
		assert(dev);
		dt_add_property_strings(dev, "target-list", "slot-C6", "slot-C7");

		dev = dt_create_i2c_device(bus, 0x36, "power-control",
					   "maxim,5961", "pcie-hotplug");
		assert(dev);
		dt_add_property_strings(dev, "target-list", "slot-C8", "slot-C9");

		dev = dt_create_i2c_device(bus, 0x39, "power-control", "maxim,5961",
					   "pcie-hotplug");
		assert(dev);
		dt_add_property_strings(dev, "target-list", "slot-C12");
		break;
	default:
		break;
	}
}

static bool firenze_probe(void)
{
	if (!dt_node_is_compatible(dt_root, "ibm,firenze"))
		return false;

	firenze_dt_fixup_i2cm();

	return true;
}

static uint32_t ibm_fsp_occ_timeout(void)
{
	/* Use a fixed 60s value for now */
	return 60;
}

static void firenze_init(void)
{
	/* We call hservices_init to relocate the hbrt image now, as the FSP
	 * may request an OCC load any time after ibm_fsp_init.
	 */
	hservices_init();

	ibm_fsp_init();
}

DECLARE_PLATFORM(firenze) = {
	.name			= "Firenze",
	.psi			= &fsp_platform_psi,
	.prd			= &fsp_platform_prd,
	.probe			= firenze_probe,
	.init			= firenze_init,
	.fast_reboot_init	= fsp_console_reset,
	.finalise_dt		= ibm_fsp_finalise_dt,
	.exit			= ibm_fsp_exit,
	.cec_power_down		= ibm_fsp_cec_power_down,
	.cec_reboot		= ibm_fsp_cec_reboot,
	.pci_setup_phb		= firenze_pci_setup_phb,
	.pci_get_slot_info	= firenze_pci_get_slot_info,
	.pci_add_loc_code	= firenze_pci_add_loc_code,
	.pci_probe_complete	= firenze_pci_send_inventory,
	.nvram_info		= fsp_nvram_info,
	.nvram_start_read	= fsp_nvram_start_read,
	.nvram_write		= fsp_nvram_write,
	.occ_timeout		= ibm_fsp_occ_timeout,
	.elog_commit		= elog_fsp_commit,
	.start_preload_resource	= fsp_start_preload_resource,
	.resource_loaded	= fsp_resource_loaded,
	.sensor_read		= ibm_fsp_sensor_read,
	.terminate		= ibm_fsp_terminate,
	.op_display		= fsp_op_display,
	.vpd_iohub_load		= vpd_iohub_load,
	.heartbeat_time		= fsp_heartbeat_time,
};
