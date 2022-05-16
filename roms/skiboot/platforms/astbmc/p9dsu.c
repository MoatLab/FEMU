// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2017 Supermicro Inc.
 * Copyright 2018-2019 IBM Corp.
 */

#include <skiboot.h>
#include <device.h>
#include <console.h>
#include <chip.h>
#include <ipmi.h>
#include <psi.h>
#include <npu-regs.h>
#include <opal-internal.h>
#include <cpu.h>
#include <timebase.h>

#include "astbmc.h"

static bool p9dsu_riser_found = false;

static const struct slot_table_entry p9dsu1u_phb0_0_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "UIO Slot1",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu1u_phb0_1_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "UIO Slot2",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu1u_phb0_2_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Onboard LAN",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu1u_phb0_3_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Onboard SAS",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu1u_phb0_4_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Onboard BMC",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu1u_phb0_5_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Onboard USB",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu1u_phb8_0_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "WIO Slot1",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu1u_phb8_1_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "WIO-R Slot",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu1u_phb8_2_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "WIO Slot3",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu1u_phb8_3_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "WIO Slot2",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu1u_phb_table[] = {
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,0),
		.children = p9dsu1u_phb0_0_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,1),
		.children = p9dsu1u_phb0_1_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,2),
		.children = p9dsu1u_phb0_2_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,3),
		.children = p9dsu1u_phb0_3_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,4),
		.children = p9dsu1u_phb0_4_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,5),
		.children = p9dsu1u_phb0_5_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,0),
		.children = p9dsu1u_phb8_0_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,1),
		.children = p9dsu1u_phb8_1_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,2),
		.children = p9dsu1u_phb8_2_slot,
	},
		{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,3),
		.children = p9dsu1u_phb8_3_slot,
	},
	{ .etype = st_end },
};


static const struct slot_table_entry p9dsu2u_phb0_0_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "UIO Slot1",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2u_phb0_1_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "UIO Slot2",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2u_phb0_2_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Onboard LAN",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2u_phb0_3_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Onboard SAS",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2u_phb0_4_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Onboard BMC",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2u_phb0_5_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Onboard USB",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2u_phb8_0_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "WIO Slot1",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2u_phb8_1_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "WIO-R Slot",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2u_phb8_2_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "WIO Slot3",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2u_phb8_3_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "WIO Slot3",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2u_phb8_4_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "WIO Slot2",
		.power_limit = 75,
	},
	{ .etype = st_end },
};


static const struct slot_table_entry p9dsu2u_phb_table[] = {
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,0),
		.children = p9dsu2u_phb0_0_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,1),
		.children = p9dsu2u_phb0_1_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,2),
		.children = p9dsu2u_phb0_2_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,3),
		.children = p9dsu2u_phb0_3_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,4),
		.children = p9dsu2u_phb0_4_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,5),
		.children = p9dsu2u_phb0_5_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,0),
		.children = p9dsu2u_phb8_0_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,1),
		.children = p9dsu2u_phb8_1_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,2),
		.children = p9dsu2u_phb8_2_slot,
	},
		{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,3),
		.children = p9dsu2u_phb8_3_slot,
	},
			{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,4),
		.children = p9dsu2u_phb8_4_slot,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_uio_plx_down[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0x1,0),
		.name = "UIO Slot2",
		.power_limit = 75,
	},
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0x8,0),
		.name = "PLX switch",
		.power_limit = 75,
	},
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0x9,0),
		.name = "Onboard LAN",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_uio_plx_up[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.children = p9dsu2uess_uio_plx_down,
		.name = "PLX up",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_wio_plx_down[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0x1,0),
		.name = "WIO Slot1",
		.power_limit = 75,
	},
    	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0x8,0),
		.name = "PLX switch",
		.power_limit = 75,
	},
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0x9,0),
		.name = "WIO Slot2",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_wio_plx_up[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.children = p9dsu2uess_wio_plx_down,
		.name = "PLX up",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_phb0_0_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "UIO Slot1",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_phb0_1_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.children = p9dsu2uess_uio_plx_up,
		.name = "PLX",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_phb0_2_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "UIO Slot3",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_phb0_3_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Onboard SAS",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_phb0_4_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Onboard BMC",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_phb0_5_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Onboard USB",
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_phb8_0_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "WIO Slot3",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_phb8_1_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "WIO-R Slot",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_phb8_2_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.children = p9dsu2uess_wio_plx_up,
		.name = "PLX",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_phb8_3_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "WIO Slot4",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_phb8_4_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "WIO Slot5",
		.power_limit = 75,
	},
	{ .etype = st_end },
};

static const struct slot_table_entry p9dsu2uess_phb_table[] = {
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,0),
		.children = p9dsu2uess_phb0_0_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,1),
		.children = p9dsu2uess_phb0_1_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,2),
		.children = p9dsu2uess_phb0_2_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,3),
		.children = p9dsu2uess_phb0_3_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,4),
		.children = p9dsu2uess_phb0_4_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(0,5),
		.children = p9dsu2uess_phb0_5_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,0),
		.children = p9dsu2uess_phb8_0_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,1),
		.children = p9dsu2uess_phb8_1_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,2),
		.children = p9dsu2uess_phb8_2_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,3),
		.children = p9dsu2uess_phb8_3_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(8,4),
		.children = p9dsu2uess_phb8_4_slot,
	},
	{ .etype = st_end },
};


/*
 * HACK: Hostboot doesn't export the correct data for the system VPD EEPROM
 *       for this system. So we need to work around it here.
 */
static void p9dsu_dt_fixups(void)
{
	struct dt_node *n = dt_find_by_path(dt_root,
		"/xscom@603fc00000000/i2cm@a2000/i2c-bus@0/eeprom@50");

	if (n) {
		dt_check_del_prop(n, "compatible");
		dt_add_property_string(n, "compatible", "atmel,24c256");

		dt_check_del_prop(n, "label");
		dt_add_property_string(n, "label", "system-vpd");
	}
}

static bool p9dsu_probe(void)
{
	if (!(dt_node_is_compatible(dt_root, "supermicro,p9dsu") ||
	      dt_node_is_compatible(dt_root, "supermicro,p9dsu1u") ||
	      dt_node_is_compatible(dt_root, "supermicro,p9dsu2u") ||
	      dt_node_is_compatible(dt_root, "supermicro,p9dsu2uess")))
		return false;

	p9dsu_riser_found = true;

	/* Lot of common early inits here */
	astbmc_early_init();

	/* Setup UART for use by OPAL (Linux hvc) */
	uart_set_console_policy(UART_CONSOLE_OPAL);

	p9dsu_dt_fixups();

	if (dt_node_is_compatible(dt_root, "supermicro,p9dsu1u")) {
		prlog(PR_INFO, "Detected p9dsu1u variant\n");
		slot_table_init(p9dsu1u_phb_table);
	} else if (dt_node_is_compatible(dt_root, "supermicro,p9dsu2u")) {
		prlog(PR_INFO, "Detected p9dsu2u variant\n");
		slot_table_init(p9dsu2u_phb_table);
	} else if (dt_node_is_compatible(dt_root, "supermicro,p9dsu2uess")) {
		prlog(PR_INFO, "Detected p9dsu2uess variant\n");
		slot_table_init(p9dsu2uess_phb_table);
	} else {
	/*
	 * else we need to ask the BMC what subtype we are, but we need IPMI
	 * which we don't get until astbmc_init(), so we delay setting up the
	 * slot table until later.
	 *
	 * This only applies if you're using a Hostboot that doesn't do this
	 * for us.
	 */
	p9dsu_riser_found = false;
	}

	return true;
}

static void p9dsu_riser_query_complete(struct ipmi_msg *m)
{
	u8 *riser_id = (u8*)m->user_data;
	lwsync();
	*riser_id = m->data[0];
	ipmi_free_msg(m);
}

static void p9dsu_init(void)
{
	u8 smc_riser_req[] = {0x03, 0x70, 0x01, 0x02};
	struct ipmi_msg *ipmi_msg;
	u8 riser_id = 0;
	const char *p9dsu_variant;
	int timeout_ms = 3000;

	astbmc_init();
	/*
	 * Now we have IPMI up and running we can ask the BMC for what p9dsu
	 * variant we are if Hostboot isn't the patched one that does this
	 * for us.
	 */
	if (!p9dsu_riser_found) {
		ipmi_msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE,
				      IPMI_CODE(IPMI_NETFN_APP, 0x52),
				      p9dsu_riser_query_complete,
				      &riser_id,
				      smc_riser_req, sizeof(smc_riser_req), 1);
		ipmi_queue_msg(ipmi_msg);
		while(riser_id==0 && timeout_ms > 0) {
			time_wait_ms(10);
			timeout_ms -= 10;
		}
		switch (riser_id) {
		case 0x9:
			p9dsu_variant = "supermicro,p9dsu1u";
			slot_table_init(p9dsu1u_phb_table);
			break;
		case 0x19:
			p9dsu_variant = "supermicro,p9dsu2u";
			slot_table_init(p9dsu2u_phb_table);
			break;
		case 0x1D:
			p9dsu_variant = "supermicro,p9dsu2uess";
			slot_table_init(p9dsu2uess_phb_table);
			break;
		default:
			prlog(PR_ERR, "Defaulting to p9dsu2uess\n");
			p9dsu_variant = "supermicro,p9dsu2uess";
			slot_table_init(p9dsu2uess_phb_table);
			break;
		}
		prlog(PR_INFO,"Detected %s variant via IPMI\n", p9dsu_variant);
		dt_check_del_prop(dt_root, "compatible");
		dt_add_property_strings(dt_root, "compatible", "ibm,powernv",
					"supermicro,p9dsu", p9dsu_variant);
	}
}

static const struct bmc_sw_config bmc_sw_smc = {
	.ipmi_oem_partial_add_esel   = IPMI_CODE(0x3a, 0xf0),
	.ipmi_oem_hiomap_cmd         = IPMI_CODE(0x3a, 0x5a),
};

/* Provided by Eric Chen (SMC) */
static const struct bmc_hw_config p9dsu_bmc_hw = {
	.scu_revision_id = 0x04030303,
	.mcr_configuration = 0x11000756,
	.mcr_scu_mpll = 0x000071c1,
	.mcr_scu_strap = 0x00000000,
};

static const struct bmc_platform bmc_plat_ast2500_smc = {
	.name = "SMC",
	.hw = &p9dsu_bmc_hw,
	.sw = &bmc_sw_smc,
};

DECLARE_PLATFORM(p9dsu1u) = {
	.name			= "p9dsu",
	.probe			= p9dsu_probe,
	.init			= p9dsu_init,
	.start_preload_resource	= flash_start_preload_resource,
	.resource_loaded	= flash_resource_loaded,
	.bmc			= &bmc_plat_ast2500_smc,
	.pci_get_slot_info	= slot_table_get_slot_info,
	.cec_power_down         = astbmc_ipmi_power_down,
	.cec_reboot             = astbmc_ipmi_reboot,
	.elog_commit		= ipmi_elog_commit,
	.exit			= ipmi_wdt_final_reset,
	.terminate		= ipmi_terminate,
	.op_display		= op_display_lpc,
};
