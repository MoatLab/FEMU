// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2016-2019 IBM Corp. */

#include <skiboot.h>
#include <device.h>
#include <fsp.h>
#include <pci.h>
#include <pci-cfg.h>
#include <chip.h>
#include <i2c.h>
#include <timebase.h>
#include <hostservices.h>
#include <npu2.h>

#include "ibm-fsp.h"
#include "lxvpd.h"

static const char *zz_ocapi_slot_label(uint32_t chip_id,
				       uint32_t brick_index)
{
	const char *name = NULL;

	if (chip_id == 0) {
		if (brick_index == 2)
			name = "P1-T5";
		else
			name = "P1-T6";
	} else {
		if (brick_index == 2)
			name = "P1-T7";
		else
			name = "P1-T8";
	}
	return name;
}

/* We don't yet create NPU device nodes on ZZ, but these values are correct */
static const struct platform_ocapi zz_ocapi = {
	.i2c_engine          = 1,
	.i2c_port            = 4,
	.i2c_reset_addr      = 0x20,
	.i2c_reset_brick2    = (1 << 1),
	.i2c_reset_brick3    = (1 << 6),
	.i2c_reset_brick4    = 0, /* unused */
	.i2c_reset_brick5    = 0, /* unused */
	.i2c_presence_addr   = 0x20,
	.i2c_presence_brick2 = (1 << 2), /* bottom connector */
	.i2c_presence_brick3 = (1 << 7), /* top connector */
	.i2c_presence_brick4 = 0, /* unused */
	.i2c_presence_brick5 = 0, /* unused */
	.odl_phy_swap        = true,
	.ocapi_slot_label    = zz_ocapi_slot_label,
};

#define NPU_BASE 0x5011000
#define NPU_SIZE 0x2c
#define NPU_INDIRECT0	0x8000000009010c3f /* OB0 - no OB3 on ZZ */

static void create_link(struct dt_node *npu, int group, int index)
{
	struct dt_node *link;
	uint32_t lane_mask;

	switch (index) {
	case 2:
		lane_mask = 0xf1e000; /* 0-3, 7-10 */
		break;
	case 3:
		lane_mask = 0x00078f; /* 13-16, 20-23 */
		break;
	default:
		assert(0);
	}

	link = dt_new_addr(npu, "link", index);
	dt_add_property_string(link, "compatible", "ibm,npu-link");
	dt_add_property_cells(link, "ibm,npu-link-index", index);
	dt_add_property_u64s(link, "ibm,npu-phy", NPU_INDIRECT0);
	dt_add_property_cells(link, "ibm,npu-lane-mask", lane_mask);
	dt_add_property_cells(link, "ibm,npu-group-id", group);
	dt_add_property_u64s(link, "ibm,link-speed", 25000000000ul);
}

static void add_opencapi_dt_nodes(void)
{
	struct dt_node *npu, *xscom;
	int npu_index = 0;

	/*
	 * In an ideal world, we should get all the NPU links
	 * information from HDAT. But after some effort, HDAT is still
	 * giving incorrect information for opencapi. As of this
	 * writing:
	 * 1. link usage is wrong for most FPGA cards (0xFFFF vs. 2)
	 * 2. the 24-bit lane mask is aligned differently than on
	 *    other platforms (witherspoon)
	 * 3. connecting a link entry in HDAT to the real physical
	 *    link will need extra work:
	 *    - HDAT does presence detection and only lists links with
	 *      an adapter, so we cannot use default ordering like on
	 *      witherspoon
	 *    - best option is probably the brick ID field (offset 8).
	 *      It's coming straight from the MRW, but seems to match
	 *      what we expect (2 or 3). Would need to be checked.
	 *
	 * To make things more fun, any change in the HDAT data needs
	 * to be coordinated with PHYP, which is using (some of) those
	 * fields.
	 *
	 * As a consequence:
	 * 1. the hdat parsing code in skiboot remains disabled (for
	 *    opencapi)
	 * 2. we hard-code the NPU and links entries in the device
	 *    tree.
	 *
	 * Getting the data from HDAT would have the advantage of
	 * providing the real link speed (20.0 vs. 25.78125 gbps),
	 * which is useful as there's one speed-dependent setting we
	 * need to do when initializing the NPU. Our hard coded
	 * definition assumes the higher speed and may need tuning in
	 * debug scenario using a lower link speed.
	 */
	dt_for_each_compatible(dt_root, xscom, "ibm,xscom") {
		/*
		 * our hdat parsing code may create NPU nodes with no
		 * links, so let's make sure we start from a clean
		 * state
		 */
		npu = dt_find_by_name_addr(xscom, "npu", NPU_BASE);
		if (npu)
			dt_free(npu);

		npu = dt_new_addr(xscom, "npu", NPU_BASE);
		dt_add_property_cells(npu, "reg", NPU_BASE, NPU_SIZE);
		dt_add_property_strings(npu, "compatible", "ibm,power9-npu");
		dt_add_property_cells(npu, "ibm,npu-index", npu_index++);
		dt_add_property_cells(npu, "ibm,npu-links", 2);

		create_link(npu, 1, 2);
		create_link(npu, 2, 3);
	}
}

static bool zz_probe(void)
{
	/* FIXME: make this neater when the dust settles */
	if (dt_node_is_compatible(dt_root, "ibm,zz-1s2u") ||
	    dt_node_is_compatible(dt_root, "ibm,zz-1s4u") ||
	    dt_node_is_compatible(dt_root, "ibm,zz-2s2u") ||
	    dt_node_is_compatible(dt_root, "ibm,zz-2s4u") ||
	    dt_node_is_compatible(dt_root, "ibm,zz-1s4u+gen4") ||
	    dt_node_is_compatible(dt_root, "ibm,zz-2s2u+gen4") ||
	    dt_node_is_compatible(dt_root, "ibm,zz-2s4u+gen4")) {

		add_opencapi_dt_nodes();
		return true;
	}

	/* Add Fleetwood FSP platform and map it to ZZ */
	if (dt_node_is_compatible(dt_root, "ibm,fleetwood-m9s")) {
		return true;
        }

	/* Add Denali FSP platform and map it to ZZ */
	if (dt_node_is_compatible(dt_root, "ibm,denali")) {
		return true;
        }

	return false;
}

static uint32_t ibm_fsp_occ_timeout(void)
{
	/* Use a fixed 60s value for now */
	return 60;
}

static void zz_init(void)
{
	ibm_fsp_init();
	hservice_fsp_init();
}

DECLARE_PLATFORM(zz) = {
	.name			= "ZZ",
	.psi			= &fsp_platform_psi,
	.prd			= &fsp_platform_prd,
	.probe			= zz_probe,
	.init			= zz_init,
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
	.ocapi			= &zz_ocapi,
	.npu2_device_detect	= npu2_i2c_presence_detect,
	.op_display		= fsp_op_display,
	.vpd_iohub_load		= vpd_iohub_load,
	.heartbeat_time		= fsp_heartbeat_time,
};
