// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2017-2019 IBM Corp. */

#include <device.h>
#include <cpu.h>
#include <vpd.h>
#include <interrupts.h>
#include <ccan/str/str.h>
#include <chip.h>
#include <i2c.h>

#include "spira.h"
#include "hdata.h"

/*
 * These should probably be in hw/p8-i2c.c. However, that would require the HDAT
 * test to #include hw/p8-i2c.c which is probably going to be more trouble than
 * it's worth. So these helpers are here instead.
 */
struct dt_node *p8_i2c_add_master_node(struct dt_node *xscom, int eng_id)
{
	uint64_t clk, size, xscom_base;
	struct dt_node *i2cm;

	dt_for_each_compatible(xscom, i2cm, "ibm,power8-i2cm")
		if (dt_prop_get_u32(i2cm, "chip-engine#") == eng_id)
			return i2cm;

	/* XXX: Might need to be updated for new chips */
	if (proc_gen >= proc_gen_p9)
		size = 0x1000;
	else
		size = 0x20;

	xscom_base = 0xa0000 + size * eng_id;

	i2cm = dt_new_addr(xscom, "i2cm", xscom_base);
	if (!i2cm)
		return NULL;

	if (proc_gen >= proc_gen_p9) {
		dt_add_property_strings(i2cm, "compatible", "ibm,power8-i2cm",
					"ibm,power9-i2cm");
	} else {
		dt_add_property_strings(i2cm, "compatible", "ibm,power8-i2cm");
	}

	dt_add_property_cells(i2cm, "reg", xscom_base, size);
	dt_add_property_cells(i2cm, "#size-cells", 0);
	dt_add_property_cells(i2cm, "#address-cells", 1);
	dt_add_property_cells(i2cm, "chip-engine#", eng_id);

	/*
	 * The i2cm runs at 1/4th the PIB frequency. If we don't know the PIB
	 * frequency then pick 150MHz which should be in the right ballpark.
	 */
	clk = dt_prop_get_u64_def(xscom, "bus-frequency", 0);
	if (clk)
		dt_add_property_cells(i2cm, "clock-frequency", clk / 4);
	else
		dt_add_property_cells(i2cm, "clock-frequency", 150000000);

	return i2cm;
}

struct dt_node *__p8_i2c_add_port_node(struct dt_node *master, int port_id,
					uint32_t bus_speed)
{
	struct dt_node *port;
	uint32_t speed;

	dt_for_each_child(master, port)
		if (dt_prop_get_u32(port, "reg") == port_id)
			goto check_speed;

	port = dt_new_addr(master, "i2c-bus", port_id);
	if (!port)
		return NULL;

	dt_add_property_cells(port, "reg", port_id);
	dt_add_property_cells(port, "#size-cells", 0);
	dt_add_property_cells(port, "#address-cells", 1);

	/* The P9 I2C master is fully compatible with the P8 one */
	if (proc_gen >= proc_gen_p9) {
		dt_add_property_strings(port, "compatible", "ibm,opal-i2c",
			"ibm,power8-i2c-port", "ibm,power9-i2c-port");
	} else {
		dt_add_property_strings(port, "compatible", "ibm,opal-i2c",
			"ibm,power8-i2c-port");
	}

check_speed:
	speed = dt_prop_get_u32_def(port, "bus-frequency", 0xffffffff);
	if (bus_speed < speed) {
		dt_check_del_prop(port, "bus-frequency");
		dt_add_property_cells(port, "bus-frequency", bus_speed);
	}

	return port;
}


struct dt_node *p8_i2c_add_port_node(struct dt_node *xscom, int eng_id,
					int port_id, uint32_t bus_freq)
{
	struct dt_node *i2cm;

	i2cm = p8_i2c_add_master_node(xscom, eng_id);
	if (!i2cm)
		return NULL;

	return __p8_i2c_add_port_node(i2cm, port_id, bus_freq);
}

struct i2c_dev {
	uint8_t i2cm_engine;
	uint8_t i2cm_port;
	__be16 i2c_bus_freq;

	/* i2c slave info */
	uint8_t type;
	uint8_t dev_addr;
	uint8_t dev_port;
	uint8_t __reserved;

	__be32 purpose;
	__be32 i2c_link;
	__be16 slca_index;
};

struct hdat_i2c_type {
	uint32_t id;
	const char *name;
	const char *compat;
};

static struct hdat_i2c_type hdat_i2c_devs[] = {
	{ 0x1, "gpio", "nxp,pca9551" },
	/* XXX: Please verify that all VPD EEPROMs are of this type */
	{ 0x2, "eeprom", "atmel,24c128" },
	{ 0x3, "tpm", "nuvoton,npct650" },
	{ 0x4, "i2c", NULL },   /* MEX-FPGA */
	{ 0x5, "i2c", NULL },   /* UCX90xx devs for PCI Hotplug */
	{ 0x6, "gpio", "nxp,pca9552" },
	{ 0x7, "gpio", "nxp,pca9553" },
	{ 0x8, "gpio", "nxp,pca9554" },
	{ 0x9, "gpio", "nxp,pca9555" },
	{ 0xa, "i2c", NULL },   /* SMP/OpenCAPI Cable */
	{ 0xb, "eeprom", "atmel,24c256" },
	{ 0xc, "i2c", NULL },   /* Thermal Sensor */
	{ 0xd, "eeprom", "atmel,24c04" },
	{ 0xe, "eeprom", "atmel,24c512" },
	{ 0xf, "eeprom", "atmel,24c32" },
	{ 0x10, "eeprom", "atmel,24c64" },
	{ 0x11, "eeprom", "atmel,24c16" },
	{ 0x12, "i2c", NULL },   /* NVDIA GPU */
	{ 0x13, "i2c", "nxp,lpc11u35" },
};

struct hdat_i2c_info {
	uint32_t id;
	bool allowed; /* true if the host may use the device */
	const char *label;
};

static struct hdat_i2c_info hdat_i2c_extra_info[] = {
	{ 0x1,  false, "led-controller" },
	{ 0x2,  false, "pci-hotplug-pgood" },
	{ 0x3,  false, "pci-hotplug-control" },
	{ 0x4,  true,  "tpm" },
	{ 0x5,  true,  "module-vpd" },
	{ 0x6,  true,  "dimm-spd" },
	{ 0x7,  true,  "proc-vpd" },
	{ 0x8,  false, "sbe-eeprom"},
	{ 0x9,  true,  "planar-vpd" },
	{ 0xa,  false, "opencapi-topology" },
	{ 0xb,  false, "opencapi-micro-reset" },
	{ 0xc,  false, "nvlink-cable" },
	{ 0xd,  false, "secure-window-open" },
	{ 0xe,  false, "physical-presence" },
	{ 0xf,  false, "mex-fpga" },
	{ 0x10, false, "thermal-sensor" },
	{ 0x11, false, "host-i2c-enable" },
	{ 0x12, false, "gpu-config" },
};

/*
 * this is pretty half-assed, to generate the labels properly we need to look
 * up associated SLCA index and determine what kind of module the device is on
 * and why
 */
static struct hdat_i2c_type *map_type(uint32_t type)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(hdat_i2c_devs); i++)
		if (hdat_i2c_devs[i].id == type)
			return &hdat_i2c_devs[i];

	return NULL;
}

static struct hdat_i2c_info *get_info(uint32_t type)
{
	static struct hdat_i2c_info no_info =
		{ .id = 0x0, .allowed = false, .label = "" };
	int i;

	for (i = 0; i < ARRAY_SIZE(hdat_i2c_extra_info); i++)
		if (hdat_i2c_extra_info[i].id == type)
			return &hdat_i2c_extra_info[i];

	return &no_info;
}

static bool is_zeros(const void *p, size_t size)
{
	const char *c = p;
	size_t i;

	for (i = 0; i < size; i++)
		if (c[i] != 0)
			return false;

	return true;
}

struct host_i2c_hdr {
	const struct HDIF_array_hdr hdr;
	__be32 version;
} __packed __align(0x4);

int parse_i2c_devs(const struct HDIF_common_hdr *hdr, int idata_index,
	struct dt_node *xscom)
{
	struct dt_node *bus, *node;
	const struct hdat_i2c_type *type;
	const struct hdat_i2c_info *info;
	const struct i2c_dev *dev;
	const char *name, *compat;
	const struct host_i2c_hdr *ahdr;
	uint32_t dev_addr;
	uint32_t version;
	uint32_t size;
	uint32_t purpose;
	int i, count;

	/*
	 * This code makes a few assumptions about XSCOM addrs, etc
	 * and will need updating for new processors
	 */
	assert(proc_gen == proc_gen_p9 || proc_gen == proc_gen_p10);

	/*
	 * Emit an error if we get a newer version. This is an interim measure
	 * until the new version format is finalised.
	 */
	ahdr = HDIF_get_idata(hdr, idata_index, &size);
	if (!ahdr || !size)
		return -1;

	/*
	 * Some hostboots don't correctly fill the version field. On these
	 * the offset from the start of the header to the start of the array
	 * is 16 bytes.
	 */
	if (be32_to_cpu(ahdr->hdr.offset) == 16) {
		version = 1;
		prerror("I2C: HDAT device array has no version! Assuming v1\n");
	} else {
		version = be32_to_cpu(ahdr->version);
	}

	if (version == 2) {
		prlog(PR_INFO, "I2C: v%d found, but not supported. Parsing as v1\n",
		      version);
	} else if (version > 2) {
		prerror("I2C: v%d found, but not supported! THIS IS A BUG\n",
			version);
		return -1;
	}

	count = HDIF_get_iarray_size(hdr, idata_index);
	for (i = 0; i < count; i++) {
		dev = HDIF_get_iarray_item(hdr, idata_index, i, &size);

		/*
		 * XXX: Some broken hostboots populate i2c devs with zeros.
		 * Workaround them for now.
		 */
		if (is_zeros(dev, size)) {
			prerror("I2C: Ignoring broken i2c dev %d\n", i);
			continue;
		}

		/*
		 * On some systems the CFAM I2C master is represented in the
		 * host I2C table as engine 6. There are only 4 (0, 1, 2, 3)
		 * engines accessible to the host via XSCOM so filter out
		 * engines outside this range so we don't create bogus
		 * i2cm@<addr> nodes.
		 */
		if (dev->i2cm_engine >= 4 &&
			(proc_gen == proc_gen_p9 || proc_gen == proc_gen_p10))
			continue;

		bus = p8_i2c_add_port_node(xscom, dev->i2cm_engine, dev->i2cm_port,
					be16_to_cpu(dev->i2c_bus_freq) * 1000);

		if (!bus) {
			prerror("Unable to add node for e%dp%d under %s\n",
				dev->i2cm_engine, dev->i2cm_port, xscom->name);
			continue;
		}

		/*
		 * Looks like hostboot gives the address as an 8 bit, left
		 * justified quantity (i.e it includes the R/W bit). So we need
		 * to strip it off to get an address linux can use.
		 */
		dev_addr = dev->dev_addr >> 1;

		purpose = be32_to_cpu(dev->purpose);
		type = map_type(dev->type);
		info = get_info(purpose);

		/* HACK: Hostboot doesn't export the correct type information
		 * for the DIMM SPD EEPROMs. This is a problem because SPD
		 * EEPROMs have a different wire protocol to the atmel,24XXXX
		 * series. The main difference being that SPD EEPROMs have an
		 * 8bit offset rather than a 16bit offset. This means that the
		 * driver will send 2 bytes when doing a random read,
		 * potentially overwriting part of the SPD information.
		 *
		 * Just to make things interested the FSP also gets the device
		 * type wrong. To work around both just set the device-type to
		 * "spd" for anything in the 0x50 to 0x57 range since that's the
		 * SPD eeprom range.
		 *
		 * XXX: Future chips might not use engine 3 for the DIMM buses.
		 */
		if (dev->i2cm_engine == 3 && dev_addr >= 0x50
		    && dev_addr < 0x58) {
			compat = "spd";
			name = "eeprom";
		} else if (type) {
			compat = type->compat;
			name = type->name;
		} else {
			name = "unknown";
			compat = NULL;
		}

		/*
		 * An i2c device is unknown if either the i2c device list is
		 * outdated or the device is marked as unknown (0xFF) in the
		 * hdat. Log both cases to see what/where/why.
		 */
		if (!type || dev->type == 0xFF) {
			prlog(PR_NOTICE, "HDAT I2C: found e%dp%d - %s@%x dp:%02x (%#x:%s)\n",
			      dev->i2cm_engine, dev->i2cm_port, name, dev_addr,
			      dev->dev_port, purpose, info->label);
			continue;
		}

		prlog(PR_DEBUG, "HDAT I2C: found e%dp%d - %s@%x dp:%02x (%#x:%s)\n",
		      dev->i2cm_engine, dev->i2cm_port, name, dev_addr,
		      dev->dev_port, purpose, info->label);

		/*
		 * Multi-port device require special handling since we need to
		 * generate the device-specific DT bindings. For now we're just
		 * going to ignore them since these devices are owned by FW
		 * any way.
		 */
		if (dev->dev_port != 0xff)
			continue;

		node = dt_new_addr(bus, name, dev_addr);
		if (!node)
			continue;

		dt_add_property_cells(node, "reg", dev_addr);
		dt_add_property_cells(node, "link-id",
			be32_to_cpu(dev->i2c_link));
		if (compat)
			dt_add_property_string(node, "compatible", compat);
		if (info->label)
			dt_add_property_string(node, "label", info->label);
		if (!info->allowed)
			dt_add_property_string(node, "status", "reserved");

		/*
		 * Set a default timeout of 2s on the ports with a TPM. This is
		 * to work around a bug with certain TPM firmwares that can
		 * clock stretch for long periods of time and will lock up
		 * until they are power cycled if a STOP condition is sent
		 * during this period.
		 */
		if (dev->type == 0x3)
			dt_add_property_cells(bus, "timeout-ms", 2000);

		/* XXX: SLCA index? */
	}

	return 0;
}
