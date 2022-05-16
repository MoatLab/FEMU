// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#include <skiboot.h>
#include <chip.h>
#include <console.h>
#include <device.h>
#include <timebase.h>
#include <cpu.h>

static struct proc_chip *chips[MAX_CHIPS];
enum proc_chip_quirks proc_chip_quirks;

uint32_t pir_to_chip_id(uint32_t pir)
{
	if (proc_gen == proc_gen_p10)
		return P10_PIR2GCID(pir);
	else if (proc_gen == proc_gen_p9)
		return P9_PIR2GCID(pir);
	else if (proc_gen == proc_gen_p8)
		return P8_PIR2GCID(pir);
	else
		assert(false);
}

uint32_t pir_to_core_id(uint32_t pir)
{
	if (proc_gen == proc_gen_p10) {
		if (this_cpu()->is_fused_core)
			return P10_PIRFUSED2NORMALCOREID(pir);
		else
			return P10_PIR2COREID(pir);
	} else if (proc_gen == proc_gen_p9) {
		if (this_cpu()->is_fused_core)
			return P9_PIRFUSED2NORMALCOREID(pir);
		else
			return P9_PIR2COREID(pir);
	} else if (proc_gen == proc_gen_p8) {
		return P8_PIR2COREID(pir);
	} else {
		assert(false);
	}
}

uint32_t pir_to_fused_core_id(uint32_t pir)
{
	if (proc_gen == proc_gen_p10) {
		if (this_cpu()->is_fused_core)
			return P10_PIR2FUSEDCOREID(pir);
		else
			return P10_PIR2COREID(pir);
	} else if (proc_gen == proc_gen_p9) {
		if (this_cpu()->is_fused_core)
			return P9_PIR2FUSEDCOREID(pir);
		else
			return P9_PIR2COREID(pir);
	} else if (proc_gen == proc_gen_p8) {
		return P8_PIR2COREID(pir);
	} else {
		assert(false);
	}
}

uint32_t pir_to_thread_id(uint32_t pir)
{
	if (proc_gen == proc_gen_p10) {
		if (this_cpu()->is_fused_core)
			return P10_PIRFUSED2NORMALTHREADID(pir);
		else
			return P10_PIR2THREADID(pir);
	} else if (proc_gen == proc_gen_p9) {
		if (this_cpu()->is_fused_core)
			return P9_PIRFUSED2NORMALTHREADID(pir);
		else
			return P9_PIR2THREADID(pir);
	} else if (proc_gen == proc_gen_p8) {
		return P8_PIR2THREADID(pir);
	} else {
		assert(false);
	}
}

struct proc_chip *next_chip(struct proc_chip *chip)
{
	unsigned int i;

	for (i = chip ? (chip->id + 1) : 0; i < MAX_CHIPS; i++)
		if (chips[i])
			return chips[i];
	return NULL;
}


struct proc_chip *get_chip(uint32_t chip_id)
{
	if (chip_id >= MAX_CHIPS)
		return NULL;
	return chips[chip_id];
}

static void init_chip(struct dt_node *dn)
{
	struct proc_chip *chip;
	uint32_t id;
	const char *lc = NULL;

	id = dt_get_chip_id(dn);
	assert(id < MAX_CHIPS);
	assert(chips[id] == NULL);

	chip = zalloc(sizeof(struct proc_chip));
	assert(chip);

	chip->id = id;
	chip->devnode = dn;

	chip->dbob_id = dt_prop_get_u32_def(dn, "ibm,dbob-id", 0xffffffff);
	chip->pcid = dt_prop_get_u32_def(dn, "ibm,proc-chip-id", 0xffffffff);

	if (dt_prop_get_u32_def(dn, "ibm,occ-functional-state", 0))
		chip->occ_functional = true;
	else
		chip->occ_functional = false;

	list_head_init(&chip->i2cms);

	/* Update the location code for this chip. */
	if (dt_has_node_property(dn, "ibm,loc-code", NULL))
		lc = dt_prop_get(dn, "ibm,loc-code");
	else if (dt_has_node_property(dn, "ibm,slot-location-code", NULL))
		lc = dt_prop_get(dn, "ibm,slot-location-code");

	if (lc)
		chip->loc_code = strdup(lc);

	chip->primary_topology = dt_prop_get_u32_def(dn,
		"ibm,primary-topology-index", 0xffffffff);

	prlog(PR_INFO, "CHIP: Initialised chip %d from %s\n", id, dn->name);
	chips[id] = chip;
}

void init_chips(void)
{
	struct dt_node *xn;

	/* Detect mambo chip */
	if (dt_find_by_path(dt_root, "/mambo")) {
		proc_chip_quirks |= QUIRK_NO_CHIPTOD | QUIRK_MAMBO_CALLOUTS
			| QUIRK_NO_F000F | QUIRK_NO_PBA | QUIRK_NO_OCC_IRQ
			| QUIRK_NO_RNG;

		enable_mambo_console();

		prlog(PR_NOTICE, "CHIP: Detected Mambo simulator\n");

		dt_for_each_compatible(dt_root, xn, "ibm,mambo-chip")
			init_chip(xn);
	}

	/* Detect simics */
	if (dt_find_by_path(dt_root, "/simics")) {
		proc_chip_quirks |= QUIRK_SIMICS
			| QUIRK_NO_PBA | QUIRK_NO_OCC_IRQ | QUIRK_SLOW_SIM;
		tb_hz = 512000;
		prlog(PR_NOTICE, "CHIP: Detected Simics simulator\n");
	}
	/* Detect Awan emulator */
	if (dt_find_by_path(dt_root, "/awan")) {
		proc_chip_quirks |= QUIRK_NO_CHIPTOD | QUIRK_NO_F000F
			| QUIRK_NO_PBA | QUIRK_NO_OCC_IRQ | QUIRK_SLOW_SIM;
		tb_hz = 512000;
		prlog(PR_NOTICE, "CHIP: Detected Awan emulator\n");
	}
	/* Detect Qemu */
	if (dt_node_is_compatible(dt_root, "qemu,powernv") ||
	    dt_node_is_compatible(dt_root, "qemu,powernv8") ||
	    dt_node_is_compatible(dt_root, "qemu,powernv9") ||
	    dt_node_is_compatible(dt_root, "qemu,powernv10") ||
	    dt_find_by_path(dt_root, "/qemu")) {
		proc_chip_quirks |= QUIRK_QEMU | QUIRK_NO_CHIPTOD
			| QUIRK_NO_DIRECT_CTL | QUIRK_NO_RNG;
		prlog(PR_NOTICE, "CHIP: Detected QEMU simulator\n");
	}

	/* We walk the chips based on xscom nodes in the tree */
	dt_for_each_compatible(dt_root, xn, "ibm,xscom") {
		init_chip(xn);
	}
}
