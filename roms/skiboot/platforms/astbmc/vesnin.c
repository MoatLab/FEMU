// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright (c) 2018 YADRO
 * Copyright 2018-2019 IBM Corp.
 */

#include <skiboot.h>
#include <device.h>
#include <console.h>
#include <chip.h>
#include <ipmi.h>
#include <pci.h>
#include <pci-cfg.h>

#include "astbmc.h"

#define CHIP_ID_CPU0 0x00
#define CHIP_ID_CPU1 0x08
#define CHIP_ID_CPU2 0x10
#define CHIP_ID_CPU3 0x18

/* IPMI message code for PCI inventory (OEM). */
#define PCIINV_IPMI_CODE	IPMI_CODE(0x2e, 0x2a)
/* IANA number used to identify IPMI OEM command group. */
#define PCIINV_OEM_IANA		49769 /* YADRO */

/**
 * struct pciinv_device - PCI device inventory description.
 * @domain_num: Domain number.
 * @bus_num: Bus number.
 * @device_num: Device number.
 * @func_num: Function number.
 * @vendor_id: Vendor Id.
 * @device_id: Device Id.
 * @class_code: Device class code.
 * @revision: Revision number.
 *
 * All fields have Big Endian byte order.
 */
struct pciinv_device {
	beint16_t	domain_num;
	uint8_t		bus_num;
	uint8_t		device_num;
	uint8_t		func_num;
	beint16_t	vendor_id;
	beint16_t	device_id;
	beint32_t	class_code;
	uint8_t		revision;
} __packed;

/**
 * struct pciinv_message - IPMI message packet data.
 * @iana: IANA id for OEM message, must be set to PCIINV_OEM_IANA.
 * @reset: Reset flag.
 * @device: PCI device description.
 */
struct pciinv_message {
	uint8_t iana[3];
	uint8_t reset;
	struct pciinv_device device;
} __packed;


static const struct slot_table_entry vesnin_phb0_0_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "AUX connector00",
	},
	{ .etype = st_end }
};


static const struct slot_table_entry vesnin_plx_slots[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0x01,0),
		.name = "Backplane SSD0",
	},
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0x02,0),
		.name = "Backplane SSD1",
	},
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0x03,0),
		.name = "Backplane LAN",
	},
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0x04,0),
		.name = "Backplane BMC",
	},
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0x05,0),
		.name = "Backplane USB",
	},
	{ .etype = st_end }
};

static const struct slot_table_entry vesnin_plx_up[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.children = vesnin_plx_slots,
	},
	{ .etype = st_end }
};

static const struct slot_table_entry vesnin_phb0_1_slot[] = {
	{
		.etype = st_builtin_dev,
		.location = ST_LOC_DEVFN(0,0),
		.name = "Backplane PLX",
		.children = vesnin_plx_up,
	},
	{ .etype = st_end }
};

static const struct slot_table_entry vesnin_phb0_2_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "PCIE0_x8_CPU0",
	},
	{ .etype = st_end }
};

static const struct slot_table_entry vesnin_phb8_0_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "PCIE1_x16_CPU1",
	},
	{ .etype = st_end }
};

static const struct slot_table_entry vesnin_phb8_1_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "AUX connector10",
	},
	{ .etype = st_end }
};

static const struct slot_table_entry vesnin_phb9_0_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "AUX connector30",
	},
	{ .etype = st_end }
};

static const struct slot_table_entry vesnin_phb9_1_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "PCIE3_x8_CPU2",
	},
	{ .etype = st_end }
};

static const struct slot_table_entry vesnin_phb9_2_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "PCIE2_x8_CPU2",
	},
	{ .etype = st_end }
};

static const struct slot_table_entry vesnin_phbA_0_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "PCIE4_x16_CPU3",
	},
	{ .etype = st_end }
};

static const struct slot_table_entry vesnin_phbA_1_slot[] = {
	{
		.etype = st_pluggable_slot,
		.location = ST_LOC_DEVFN(0,0),
		.name = "AUX connector40",
	},
	{ .etype = st_end }
};

static const struct slot_table_entry vesnin_phb_table[] = {
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(CHIP_ID_CPU0,0),
		.children = vesnin_phb0_0_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(CHIP_ID_CPU0,1),
		.children = vesnin_phb0_1_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(CHIP_ID_CPU0,2),
		.children = vesnin_phb0_2_slot,
	},

	{
		.etype = st_phb,
		.location = ST_LOC_PHB(CHIP_ID_CPU1,0),
		.children = vesnin_phb8_0_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(CHIP_ID_CPU1,1),
		.children = vesnin_phb8_1_slot,
	},

	{
		.etype = st_phb,
		.location = ST_LOC_PHB(CHIP_ID_CPU2,0),
		.children = vesnin_phb9_0_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(CHIP_ID_CPU2,1),
		.children = vesnin_phb9_1_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(CHIP_ID_CPU2,2),
		.children = vesnin_phb9_2_slot,
	},

	{
		.etype = st_phb,
		.location = ST_LOC_PHB(CHIP_ID_CPU3,0),
		.children = vesnin_phbA_0_slot,
	},
	{
		.etype = st_phb,
		.location = ST_LOC_PHB(CHIP_ID_CPU3,1),
		.children = vesnin_phbA_1_slot,
	},
	{ .etype = st_end }
};

/**
 * pciinv_walk() - Callback from PCI enumerator, see :c:func:`pci_walk_dev`.
 * User data parameter is interpreted as a pointer to pciinv_message structure.
 */
static int pciinv_walk(struct phb *phb, struct pci_device *pd, void *data)
{
	struct ipmi_msg *msg;
	struct pciinv_message* pack = (struct pciinv_message*)data;

	/* PCI device filter: Skip non-EP devices */
	if (pci_has_cap(pd, PCI_CFG_CAP_ID_EXP, false)) {
		if (pd->dev_type != PCIE_TYPE_ENDPOINT)
			return OPAL_SUCCESS;
	}
	else if (pd->is_bridge)
		return OPAL_SUCCESS;

	/* Fill the PCI device inventory description */
	pack->device.domain_num = cpu_to_be16(phb->opal_id & 0xffff);
	pack->device.bus_num = PCI_BUS_NUM(pd->bdfn);
	pack->device.device_num = PCI_DEV(pd->bdfn);
	pack->device.func_num = PCI_FUNC(pd->bdfn);
	pack->device.vendor_id = cpu_to_be16(PCI_VENDOR_ID(pd->vdid));
	pack->device.device_id = cpu_to_be16(PCI_DEVICE_ID(pd->vdid));
	pack->device.class_code = cpu_to_be32(pd->class & 0xffffff);
	pci_cfg_read8(phb, pd->bdfn, PCI_CFG_REV_ID, &pack->device.revision);

	msg = ipmi_mkmsg_simple(PCIINV_IPMI_CODE, pack, sizeof(*pack));
	if (!msg)
		return OPAL_HARDWARE;

	ipmi_queue_msg(msg);

	/* Disable reset flag for further messages in the current session. */
	pack->reset = 0;

	return OPAL_SUCCESS;
}

static void vesnin_pci_probe_complete(void)
{
	struct phb *phb;

	/* IPMI message packet instance.
	 * PCI device description will be filled in the PCI enumerator, see
	 * `pciinv_walk()` function.
	 * For each first message in a session, the Reset flag is turned on,
	 * this indicates that the list of existing PCI devices must be
	 * cleaned. */
	struct pciinv_message pack = {
		.iana = {
			PCIINV_OEM_IANA & 0xff,
			(PCIINV_OEM_IANA >> 8) & 0xff,
			(PCIINV_OEM_IANA >> 16) & 0xff
		},
		.reset = 1
	};

	check_all_slot_table();

	/* Send PCI device list to the BMC */
	prlog(PR_INFO, "Send PCI device list\n");
	for_each_phb(phb) {
		pci_walk_dev(phb, NULL, &pciinv_walk, &pack);
	}
}

static bool vesnin_probe(void)
{
	if (!dt_node_is_compatible(dt_root, "YADRO,vesnin"))
		return false;

	/* Lot of common early inits here */
	astbmc_early_init();
	slot_table_init(vesnin_phb_table);

	return true;
}

DECLARE_PLATFORM(vesnin) = {
	.name			= "vesnin",
	.bmc			= &bmc_plat_ast2400_ami,
	.probe			= vesnin_probe,
	.init			= astbmc_init,
	.pci_get_slot_info	= slot_table_get_slot_info,
	.pci_probe_complete	= vesnin_pci_probe_complete,
	.external_irq		= astbmc_ext_irq_serirq_cpld,
	.cec_power_down		= astbmc_ipmi_power_down,
	.cec_reboot		= astbmc_ipmi_reboot,
	.elog_commit		= ipmi_elog_commit,
	.start_preload_resource	= flash_start_preload_resource,
	.resource_loaded	= flash_resource_loaded,
	.exit			= ipmi_wdt_final_reset,
	.terminate		= ipmi_terminate,
	.op_display		= op_display_lpc,
};
