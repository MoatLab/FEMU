// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2019 IBM Corp.
 */

#include <skiboot.h>
#include <ipmi.h>
#include <npu3.h>
#include "astbmc.h"

/* nvidia,link-speed uses a magic driver value */
#define NVIDIA_LINK_SPEED_20000000000_BPS 3
#define NVIDIA_LINK_SPEED_25781250000_BPS 8
#define NVIDIA_LINK_SPEED_25000000000_BPS 9

static void swift_npu3_device_detect(struct npu3 *npu)
{
	struct npu3_dev *dev;
	uint32_t node, gpu_index;
	char slot[6];

	node = P9_GCID2NODEID(npu->chip_id);

	switch (npu->index) {
	case 0:
		gpu_index = node * 2 + 1;
		break;
	case 2:
		gpu_index = node * 2;
		break;
	default:
		return;
	}

	snprintf(slot, sizeof(slot), "GPU%d", gpu_index);

	npu3_for_each_dev(dev, npu) {
		dev->type = NPU3_DEV_TYPE_NVLINK;
		dt_add_property_string(dev->dn, "ibm,slot-label", slot);
		dt_add_property_u64(dev->dn, "ibm,link-speed", 25000000000ull);
		dt_add_property_cells(dev->dn, "nvidia,link-speed",
				      NVIDIA_LINK_SPEED_25000000000_BPS);
	}
}

#define SWIFT_POSSIBLE_GPUS 4

#define G(g)	(devs[g] ? devs[g]->nvlink.gpu->dn->phandle : 0)
#define N(g)	(devs[g] ? devs[g]->npu->nvlink.phb.dt_node->phandle : 0)

#define add_peers_prop(g, p...)					\
	if (devs[g])  						\
		dt_add_property_cells(devs[g]->nvlink.gpu->dn,	\
				      "ibm,nvlink-peers", ##p)

static void swift_finalise_dt(bool is_reboot)
{
	struct npu3 *npu;
	struct npu3_dev *dev;
	struct npu3_dev *devs[SWIFT_POSSIBLE_GPUS] = {};
	int32_t index;

	if (is_reboot)
		return;

	/* Collect the first link we find for each GPU */
	npu3_for_each_nvlink_npu(npu) {
		npu3_for_each_nvlink_dev(dev, npu) {
			index = npu3_dev_gpu_index(dev);
			if (index == -1 || index >= ARRAY_SIZE(devs))
				continue;

			if (dev->nvlink.gpu && !devs[index])
				devs[index] = dev;
		}
	}

	/* Add GPU interconnect properties */
	add_peers_prop(0, G(3), G(2), G(2), G(2),
			  G(3), G(1), G(1), G(1),
			  N(0), N(0), N(0), N(0));

	add_peers_prop(1, G(2), G(3), G(3), G(3),
			  G(0), G(0), G(0), G(2),
			  N(1), N(1), N(1), N(1));

	add_peers_prop(2, G(1), G(3), G(3), G(3),
			  G(0), G(0), G(0), G(1),
			  N(2), N(2), N(2), N(2));

	add_peers_prop(3, G(2), G(2), G(2), G(0),
			  G(1), G(1), G(0), G(1),
			  N(3), N(3), N(3), N(3));
}

static bool swift_probe(void)
{
	if (!dt_node_is_compatible(dt_root, "ibm,swift"))
		return false;

	/* Lot of common early inits here */
	astbmc_early_init();

	/* Setup UART for use by OPAL (Linux hvc) */
	uart_set_console_policy(UART_CONSOLE_OPAL);

	return true;
}

DECLARE_PLATFORM(swift) = {
	.bmc			= &bmc_plat_ast2500_openbmc,
	.cec_power_down		= astbmc_ipmi_power_down,
	.cec_reboot		= astbmc_ipmi_reboot,
	.elog_commit		= ipmi_elog_commit,
	.exit			= astbmc_exit,
	.finalise_dt		= swift_finalise_dt,
	.init			= astbmc_init,
	.name			= "Swift",
	.npu3_device_detect	= swift_npu3_device_detect,
	.pci_get_slot_info	= dt_slot_get_slot_info,
	.probe			= swift_probe,
	.resource_loaded	= flash_resource_loaded,
	.start_preload_resource	= flash_start_preload_resource,
	.terminate		= ipmi_terminate,
};
