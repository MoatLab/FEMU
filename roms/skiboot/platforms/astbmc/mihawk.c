// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2019 Wistron Corp.
 * Copyright 2017 IBM Corp.
 */

#include <skiboot.h>
#include <device.h>
#include <console.h>
#include <chip.h>
#include <ipmi.h>
#include <psi.h>
#include <npu-regs.h>
#include <npu2.h>
#include <pci.h>
#include <pci-cfg.h>

#include <timebase.h>

#include "astbmc.h"

/* IPMI message code for Riser-F query (OEM). */
#define IPMI_RISERF_QUERY	IPMI_CODE(0x32, 0x01)

static bool mihawk_riserF_found = false;
static bool bmc_query_waiting = false;

#define OPAL_ID_SLOT2	0x01
#define OPAL_ID_SLOT4	0x03
#define OPAL_ID_SLOT7	0x31
#define OPAL_ID_SLOT9	0x33

/* nvme backplane slots */
static const struct slot_table_entry hdd_bay_s2_slots[] = {
        SW_PLUGGABLE("nvme13", 0x0),
        SW_PLUGGABLE("nvme14", 0x1),
        SW_PLUGGABLE("nvme15", 0x2),
        SW_PLUGGABLE("nvme16", 0x3),

        { .etype = st_end },
};

static const struct slot_table_entry hdd_bay_s4_slots[] = {
        SW_PLUGGABLE("nvme17", 0x0),
        SW_PLUGGABLE("nvme18", 0x1),
        SW_PLUGGABLE("nvme19", 0x2),
        SW_PLUGGABLE("nvme20", 0x3),
        SW_PLUGGABLE("nvme21", 0x4),
        SW_PLUGGABLE("nvme22", 0x5),
        SW_PLUGGABLE("nvme23", 0x6),
        SW_PLUGGABLE("nvme24", 0x7),

        { .etype = st_end },
};

static const struct slot_table_entry hdd_bay_s7_slots[] = {
        SW_PLUGGABLE("nvme9", 0x0),
        SW_PLUGGABLE("nvme10", 0x1),
        SW_PLUGGABLE("nvme11", 0x2),
        SW_PLUGGABLE("nvme12", 0x3),

        { .etype = st_end },
};

static const struct slot_table_entry hdd_bay_s9_slots[] = {
        SW_PLUGGABLE("nvme1", 0x0),
        SW_PLUGGABLE("nvme2", 0x1),
        SW_PLUGGABLE("nvme3", 0x2),
        SW_PLUGGABLE("nvme4", 0x3),
        SW_PLUGGABLE("nvme5", 0x4),
        SW_PLUGGABLE("nvme6", 0x5),
        SW_PLUGGABLE("nvme7", 0x6),
        SW_PLUGGABLE("nvme8", 0x7),

        { .etype = st_end },
};

static void mihawk_get_slot_info(struct phb *phb, struct pci_device *pd)
{
	const struct slot_table_entry *ent = NULL;

	if (!pd || pd->slot)
		return;

	/*
	 * If we find a 8533 or c012 switch then assume it's the NVMe Rack.
	 * This might break if we have another switch with the same vdid in
	 * the system for some reason. This is a really dumb hack, but until
	 * we get query the BMC about wether we have a HDD rack or not we
	 * don't have much of a choice.
	 */
	if (pd->dev_type == PCIE_TYPE_SWITCH_DNPORT) {
		if (pd->vdid == 0x853311f8) { // for microsemi controller
			for (ent = hdd_bay_s9_slots; ent->etype != st_end; ent++)
				if (ent->location == (pd->bdfn & 0xff))
					break;
		} else if (pd->vdid == 0xc0121000) { // for broadcom nvme hba
			switch (phb->opal_id) {
			case OPAL_ID_SLOT2:
				ent = hdd_bay_s2_slots;
				break;
			case OPAL_ID_SLOT4:
				ent = hdd_bay_s4_slots;
				break;
			case OPAL_ID_SLOT7:
				ent = hdd_bay_s7_slots;
				break;
			case OPAL_ID_SLOT9:
			default:
				ent = hdd_bay_s9_slots;
				break;
			}

			for (; ent->etype != st_end; ent++)
				if (ent->location == (pd->bdfn & 0xff))
					break;
		}
	}

	if (ent)
		slot_table_add_slot_info(pd, ent);
	else
		slot_table_get_slot_info(phb, pd);
}

static const char *mihawk_ocapi_slot_label(uint32_t chip_id,
					   uint32_t brick_index)
{
	const char *name = NULL;

	if (chip_id == 0) {
		if (brick_index == 2)
			name = "JP90NVB1";
		else
			name = "JP90NVT1";
	} else {
		if (brick_index == 2)
			name = "JP91NVB1";
		else
			name = "JP91NVT1";
	}
	return name;
}

static const struct ocapi_phy_setup mihawk_phy = {
	.tx_ffe_pre_coeff = 0x3,
	.tx_ffe_post_coeff = 0x14,
	.tx_ffe_boost_en = 0,
};

static const struct platform_ocapi mihawk_ocapi = {
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
	.ocapi_slot_label    = mihawk_ocapi_slot_label,
	.phy_setup           = &mihawk_phy,
};

static const struct slot_table_entry P1E1A_x8_PLX8748_RiserA_down[] = {
        SW_PLUGGABLE("Slot7", 0x10),
        SW_PLUGGABLE("Slot8", 0x8),
        SW_PLUGGABLE("Slot10", 0x9),

        { .etype = st_end }
};

static const struct slot_table_entry P1E1A_x8_PLX8748_RiserA_up[] = {
        {
                .etype = st_builtin_dev,
                .location = ST_LOC_DEVFN(0,0),
                .children = P1E1A_x8_PLX8748_RiserA_down,
        },
        { .etype = st_end }
};

static const struct slot_table_entry p1phb1_rA_slot[] = {
        {
                .etype = st_builtin_dev,
                .location = ST_LOC_DEVFN(0,0),
                .children = P1E1A_x8_PLX8748_RiserA_up,
        },
        { .etype = st_end },
};

static const struct slot_table_entry P0E1A_x8_PLX8748_RiserA_down[] = {
        SW_PLUGGABLE("Slot2", 0x10),
        SW_PLUGGABLE("Slot3", 0x8),
        SW_PLUGGABLE("Slot5", 0x9),

        { .etype = st_end }
};

static const struct slot_table_entry P0E1A_x8_PLX8748_RiserA_up[] = {
        {
                .etype = st_builtin_dev,
                .location = ST_LOC_DEVFN(0,0),
                .children = P0E1A_x8_PLX8748_RiserA_down,
        },
        { .etype = st_end }
};

static const struct slot_table_entry p0phb1_rA_slot[] = {
        {
                .etype = st_builtin_dev,
                .location = ST_LOC_DEVFN(0,0),
                .children = P0E1A_x8_PLX8748_RiserA_up,
        },
        { .etype = st_end },
};

static const struct slot_table_entry P1E1A_x8_PLX8748_RiserF_down[] = {
        SW_PLUGGABLE("Slot7", 0x10),
        SW_PLUGGABLE("Slot10", 0x9),

        { .etype = st_end }
};

static const struct slot_table_entry P1E1A_x8_PLX8748_RiserF_up[] = {
        {
                .etype = st_builtin_dev,
                .location = ST_LOC_DEVFN(0,0),
                .children = P1E1A_x8_PLX8748_RiserF_down,
        },
        { .etype = st_end }
};

static const struct slot_table_entry p1phb1_rF_slot[] = {
        {
                .etype = st_builtin_dev,
                .location = ST_LOC_DEVFN(0,0),
                .children = P1E1A_x8_PLX8748_RiserF_up,
        },
        { .etype = st_end },
};

static const struct slot_table_entry P0E1A_x8_PLX8748_RiserF_down[] = {
        SW_PLUGGABLE("Slot2", 0x10),
        SW_PLUGGABLE("Slot5", 0x9),

        { .etype = st_end }
};

static const struct slot_table_entry P0E1A_x8_PLX8748_RiserF_up[] = {
        {
                .etype = st_builtin_dev,
                .location = ST_LOC_DEVFN(0,0),
                .children = P0E1A_x8_PLX8748_RiserF_down,
        },
        { .etype = st_end }
};

static const struct slot_table_entry p0phb1_rF_slot[] = {
        {
                .etype = st_builtin_dev,
                .location = ST_LOC_DEVFN(0,0),
                .children = P0E1A_x8_PLX8748_RiserF_up,
        },
        { .etype = st_end },
};

static const struct slot_table_entry P1E2_x16_Switch_down[] = {
        SW_PLUGGABLE("Slot8", 0x1),
        SW_PLUGGABLE("Slot9", 0x0),

        { .etype = st_end }
};

static const struct slot_table_entry P1E2_x16_Switch_up[] = {
        {
                .etype = st_builtin_dev,
                .location = ST_LOC_DEVFN(0,0),
                .children = P1E2_x16_Switch_down,
        },
        { .etype = st_end }
};

static const struct slot_table_entry p1phb3_switch_slot[] = {
        {
                .etype = st_builtin_dev,
                .location = ST_LOC_DEVFN(0,0),
                .children = P1E2_x16_Switch_up,
        },
        { .etype = st_end },
};

static const struct slot_table_entry P0E2_x16_Switch_down[] = {
        SW_PLUGGABLE("Slot3", 0x1),
        SW_PLUGGABLE("Slot4", 0x0),

        { .etype = st_end }
};

static const struct slot_table_entry P0E2_x16_Switch_up[] = {
        {
                .etype = st_builtin_dev,
                .location = ST_LOC_DEVFN(0,0),
                .children = P0E2_x16_Switch_down,
        },
        { .etype = st_end }
};

static const struct slot_table_entry p0phb3_switch_slot[] = {
        {
                .etype = st_builtin_dev,
                .location = ST_LOC_DEVFN(0,0),
                .children = P0E2_x16_Switch_up,
        },
        { .etype = st_end },
};

ST_PLUGGABLE(p0phb0_slot, "Slot1");
ST_PLUGGABLE(p0phb3_slot, "Slot4");
ST_PLUGGABLE(p1phb0_slot, "Slot6");
ST_PLUGGABLE(p1phb3_slot, "Slot9");

static const struct slot_table_entry mihawk_riserA_phb_table[] = {
        /* ==== CPU0 ==== */
        ST_PHB_ENTRY(0, 0, p0phb0_slot),    /* P0E0_x16_Slot1 */
        ST_PHB_ENTRY(0, 1, p0phb1_rA_slot), /* P0E1A_x8_PLX8748-1_Slot2-3-5 */
        //ST_PHB_ENTRY(0, 2, p0phb2_slot),  /* P0E1B_x8_USBTI7340 */
        ST_PHB_ENTRY(0, 3, p0phb3_slot),    /* P0E2_x16_Slot4 */

        /* ==== CPU1 ==== */
        ST_PHB_ENTRY(8, 0, p1phb0_slot),    /* P1E0_x16_Slot6 */
        ST_PHB_ENTRY(8, 1, p1phb1_rA_slot), /* P1E1A_x8_PLX8748-2_Slot7-8-10 */
        //ST_PHB_ENTRY(8, 2, p1phb2_slot),  /* P1E1B_x8_NA */
        ST_PHB_ENTRY(8, 3, p1phb3_slot),    /* P1E2_x16_Slot9 */

        { .etype = st_end },
};

static const struct slot_table_entry mihawk_riserF_phb_table[] = {
        /* ==== CPU0 ==== */
        ST_PHB_ENTRY(0, 0, p0phb0_slot),       /* P0E0_x16_Slot1 */
        ST_PHB_ENTRY(0, 1, p0phb1_rF_slot),    /* P0E1A_x8_PLX8748-1_Slot2-5 */
        //ST_PHB_ENTRY(0, 2, p0phb2_slot),     /* P0E1B_x8_USBTI7340 */
        ST_PHB_ENTRY(0, 3, p0phb3_switch_slot),/* P0E2_x16_SWITCH_Slot3-4 */

        /* ==== CPU1 ==== */
        ST_PHB_ENTRY(8, 0, p1phb0_slot),       /* P1E0_x16_Slot6 */
        ST_PHB_ENTRY(8, 1, p1phb1_rF_slot),    /* P1E1A_x8_PLX8748-2_Slot7-10 */
        //ST_PHB_ENTRY(8, 2, p1phb2_slot),     /* P1E1B_x8_NA */
        ST_PHB_ENTRY(8, 3, p1phb3_switch_slot),/* P1E2_x16_SWITCH_Slot8-9 */

        { .etype = st_end },
};

#define NPU_BASE 0x5011000
#define NPU_SIZE 0x2c
#define NPU_INDIRECT0	0x8000000009010c3fUL /* OB0 - no OB3 on Mihawk */

/* OpenCAPI only */
static void create_link(struct dt_node *npu, int group, int index)
{
	struct dt_node *link;
	uint32_t lane_mask;
	char namebuf[32];

	snprintf(namebuf, sizeof(namebuf), "link@%x", index);
	link = dt_new(npu, namebuf);
	assert(link);

	dt_add_property_string(link, "compatible", "ibm,npu-link");
	dt_add_property_cells(link, "ibm,npu-link-index", index);

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

	dt_add_property_u64s(link, "ibm,npu-phy", NPU_INDIRECT0);
	dt_add_property_cells(link, "ibm,npu-lane-mask", lane_mask);
	dt_add_property_cells(link, "ibm,npu-group-id", group);
	dt_add_property_u64s(link, "ibm,link-speed", 25000000000ul);
}

/* FIXME: Get rid of this after we get NPU information properly via HDAT/MRW */
static void mihawk_create_npu(void)
{
	struct dt_node *xscom, *npu;
	int npu_index = 0;
	char namebuf[32];

	/* Return if there's already an NPU in the device tree */
	if (dt_find_compatible_node(dt_root, NULL, "ibm,power9-npu"))
		return;

	prlog(PR_DEBUG, "OCAPI: Adding NPU device nodes\n");
	dt_for_each_compatible(dt_root, xscom, "ibm,xscom") {
		snprintf(namebuf, sizeof(namebuf), "npu@%x", NPU_BASE);
		npu = dt_new(xscom, namebuf);
		dt_add_property_cells(npu, "reg", NPU_BASE, NPU_SIZE);
		dt_add_property_strings(npu, "compatible", "ibm,power9-npu");
		dt_add_property_cells(npu, "ibm,npu-index", npu_index++);
		dt_add_property_cells(npu, "ibm,npu-links", 2);
		create_link(npu, 1, 2);
		create_link(npu, 2, 3);
	}
}

/* FIXME: Get rid of this after we get NPU information properly via HDAT/MRW */
static void mihawk_create_ocapi_i2c_bus(void)
{
	struct dt_node *xscom, *i2cm, *i2c_bus;
	prlog(PR_DEBUG, "OCAPI: Adding I2C bus device node for OCAPI reset\n");
	dt_for_each_compatible(dt_root, xscom, "ibm,xscom") {
		i2cm = dt_find_by_name(xscom, "i2cm@a1000");
		if (!i2cm) {
			prlog(PR_ERR, "OCAPI: Failed to get I2C bus device node\n");
			continue;
		}

		if (dt_find_by_name(i2cm, "i2c-bus@4"))
			continue;

		i2c_bus = dt_new_addr(i2cm, "i2c-bus", 4);
		dt_add_property_cells(i2c_bus, "reg", 4);
		dt_add_property_cells(i2c_bus, "bus-frequency", 0x61a80);
		dt_add_property_strings(i2c_bus, "compatible",
					"ibm,opal-i2c", "ibm,power8-i2c-port",
					"ibm,power9-i2c-port");
	}
}

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

static bool mihawk_probe(void)
{
	if (!dt_node_is_compatible(dt_root, "ibm,mihawk") &&
	    !dt_node_is_compatible(dt_root, "wistron,mihawk"))
		return false;

	/* Lot of common early inits here */
	astbmc_early_init();

	/* Setup UART for use by OPAL (Linux hvc) */
	uart_set_console_policy(UART_CONSOLE_OPAL);

	vpd_dt_fixup();

	mihawk_create_npu();
	mihawk_create_ocapi_i2c_bus();

	return true;
}

static void mihawk_riser_query_complete(struct ipmi_msg *msg)
{
	uint8_t *riser_state;

	if (msg->cc != IPMI_CC_NO_ERROR) {
		prlog(PR_ERR, "Mihawk: IPMI riser query returned error. cmd=0x%02x,"
			" netfn=0x%02x, rc=0x%x\n", msg->cmd, msg->netfn, msg->cc);
		bmc_query_waiting = false;
		ipmi_free_msg(msg);
		return;
	}

	prlog(PR_DEBUG, "Mihawk: IPMI Got riser query result. p0:%02x, p1:%02x\n"
		, msg->data[0], msg->data[1]);

	riser_state = (uint8_t*)msg->user_data;
	lwsync();
	*riser_state = msg->data[0] << 4 | msg->data[1];

	bmc_query_waiting = false;
	ipmi_free_msg(msg);
}

static void mihawk_init(void)
{
	struct ipmi_msg *ipmi_msg;
	uint8_t riser_state = 0;
	int timeout_ms = 3000;

	astbmc_init();

	/*
	 * We use IPMI to ask BMC if Riser-F is installed and set up the
	 * corresponding slot table.
	 */
	ipmi_msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE,
				  IPMI_RISERF_QUERY,
				  mihawk_riser_query_complete,
				  &riser_state, NULL, 0, 2);

	if (!ipmi_msg) {
		prlog(PR_ERR, "Mihawk: Couldn't create ipmi msg.");
	} else {
		ipmi_msg->error = mihawk_riser_query_complete;
		ipmi_queue_msg(ipmi_msg);
		bmc_query_waiting = true;

		prlog(PR_DEBUG, "Mihawk: Requesting IPMI_RISERF_QUERY (netfn "
			"%02x, cmd %02x)\n", ipmi_msg->netfn, ipmi_msg->cmd);

		while (bmc_query_waiting) {
			time_wait_ms(10);
			timeout_ms -= 10;

			if (timeout_ms == 0)
				break;
		}
	}

	prlog(PR_DEBUG, "Mihawk: IPMI_RISERF_QUERY finish. riser_state: %02x"
		", waiting: %d\n", riser_state, bmc_query_waiting);

	if (riser_state != 0) {
		mihawk_riserF_found = true;
		slot_table_init(mihawk_riserF_phb_table);
		prlog(PR_DEBUG, "Mihawk: Detect Riser-F via IPMI\n");
	} else {
		slot_table_init(mihawk_riserA_phb_table);
		prlog(PR_DEBUG, "Mihawk: No Riser-F found, use Riser-A table\n");
	}
}

DECLARE_PLATFORM(mihawk) = {
	.name			= "Mihawk",
	.probe			= mihawk_probe,
	.init			= mihawk_init,
	.start_preload_resource	= flash_start_preload_resource,
	.resource_loaded	= flash_resource_loaded,
	.bmc			= &bmc_plat_ast2500_openbmc,
	.pci_get_slot_info	= mihawk_get_slot_info,
	.pci_probe_complete	= check_all_slot_table,
	.cec_power_down         = astbmc_ipmi_power_down,
	.cec_reboot             = astbmc_ipmi_reboot,
	.elog_commit		= ipmi_elog_commit,
	.exit			= ipmi_wdt_final_reset,
	.terminate		= ipmi_terminate,
	.ocapi			= &mihawk_ocapi,
	.npu2_device_detect     = npu2_i2c_presence_detect,
};
