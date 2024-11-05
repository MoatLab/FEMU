// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

/*
 *
 * We currently construct our associativity properties as such:
 *
 * - For "chip" devices (bridges, memory, ...), 4 entries:
 *
 *     - CCM node ID
 *     - HW card ID
 *     - HW module ID
 *     - Chip ID
 *
 *   The information is constructed based on the chip ID which (unlike
 *   pHyp) is our HW chip ID (aka "XSCOM" chip ID). We use it to retrieve
 *   the other properties from the corresponding chip/xscom node in the
 *   device-tree. If those properties are absent, 0 is used.
 *
 * - For "core" devices, we add a 5th entry:
 *
 *     - Core ID
 *
 *   Here too, we do not use the "cooked" HW processor ID from HDAT but
 *   instead use the real HW core ID which is basically the interrupt
 *   server number of thread 0 on that core.
 *
 *
 * The ibm,associativity-reference-points property is currently set to
 * 4,4 indicating that the chip ID is our only reference point. This
 * should be extended to encompass the node IDs eventually.
 */
#include <skiboot.h>
#include <opal.h>
#include <device.h>
#include <console.h>
#include <trace.h>
#include <chip.h>
#include <cpu.h>
#include <affinity.h>

static uint32_t get_chip_node_id(struct proc_chip *chip)
{
	/* If the xscom node has an ibm,ccm-node-id property, use it */
	if (dt_has_node_property(chip->devnode, "ibm,ccm-node-id", NULL))
		return dt_prop_get_u32(chip->devnode, "ibm,ccm-node-id");

	/*
	 * Else use the 3 top bits of the chip ID which should be
	 * the node on P8
	 */
	return chip->id >> 3;
}

void add_associativity_ref_point(void)
{
	int ref2 = 0x4;

	/*
	 * Note about our use of reference points:
	 *
	 * Linux currently supports up to three levels of NUMA. We use the
	 * first reference point for the node ID and the second reference
	 * point for a second level of affinity. We always use the chip ID
	 * (4) for the first reference point.
	 *
	 * Choosing the second level of affinity is model specific
	 * unfortunately. Current POWER8E models should use the DCM
	 * as a second level of NUMA.
	 *
	 * If there is a way to obtain this information from the FSP
	 * that would be ideal, but for now hardwire our POWER8E setting.
	 *
	 * For GPU nodes we add a third level of NUMA, such that the
	 * distance of the GPU node from all other nodes is uniformly
	 * the highest.
	 */
	if (PVR_TYPE(mfspr(SPR_PVR)) == PVR_TYPE_P8E)
		ref2 = 0x3;

	dt_add_property_cells(opal_node, "ibm,associativity-reference-points",
			      0x4, ref2, 0x2);
}

void add_chip_dev_associativity(struct dt_node *dev)
{
	uint32_t chip_id = dt_get_chip_id(dev);
	struct proc_chip *chip = get_chip(chip_id);
	uint32_t hw_cid, hw_mid;

	if (!chip)
		return;

	hw_cid = dt_prop_get_u32_def(chip->devnode, "ibm,hw-card-id", 0);
	hw_mid = dt_prop_get_u32_def(chip->devnode, "ibm,hw-module-id", 0);

	dt_add_property_cells(dev, "ibm,associativity", 4,
			      get_chip_node_id(chip),
			      hw_cid, hw_mid, chip_id);
}

void add_core_associativity(struct cpu_thread *cpu)
{
	struct proc_chip *chip = get_chip(cpu->chip_id);
	uint32_t hw_cid, hw_mid, core_id;

	if (!chip)
		return;

	if (proc_gen == proc_gen_p8)
		core_id = (cpu->pir >> 3) & 0xf;
	else if (proc_gen == proc_gen_p9)
		core_id = (cpu->pir >> 2) & 0x1f;
	else if (proc_gen == proc_gen_p10)
		core_id = (cpu->pir >> 2) & 0x1f;
	else
		return;

	hw_cid = dt_prop_get_u32_def(chip->devnode, "ibm,hw-card-id", 0);
	hw_mid = dt_prop_get_u32_def(chip->devnode, "ibm,hw-module-id", 0);

	dt_add_property_cells(cpu->node, "ibm,associativity", 5,
			      get_chip_node_id(chip),
			      hw_cid, hw_mid, chip->id, core_id);
}
