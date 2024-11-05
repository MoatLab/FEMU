// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2015-2018 IBM Corp. */

#include <skiboot.h>
#include <device.h>
#include <console.h>
#include <chip.h>
#include <pci-cfg.h>
#include <pci.h>
#include <pci-slot.h>

#include "astbmc.h"

static const struct slot_table_entry *slot_top_table;

void slot_table_init(const struct slot_table_entry *top_table)
{
	slot_top_table = top_table;
}

static const struct slot_table_entry *match_slot_phb_entry(struct phb *phb)
{
	uint32_t chip_id = dt_get_chip_id(phb->dt_node);
	uint32_t phb_idx = dt_prop_get_u32_def(phb->dt_node,
					       "ibm,phb-index", 0);
	const struct slot_table_entry *ent;

	if (!slot_top_table)
		return NULL;

	for (ent = slot_top_table; ent->etype != st_end; ent++) {
		if (ent->etype != st_phb) {
			prerror("SLOT: Bad DEV entry type in table !\n");
			continue;
		}
		if (ent->location == ST_LOC_PHB(chip_id, phb_idx))
			return ent;
	}
	return NULL;
}

static const struct slot_table_entry *match_slot_dev_entry(struct phb *phb,
							   struct pci_device *pd)
{
	const struct slot_table_entry *parent, *ent;
	uint32_t bdfn;

	/* Find a parent recursively */
	if (pd->parent)
		parent = match_slot_dev_entry(phb, pd->parent);
	else {
		/* No parent, this is a root complex, find the PHB */
		parent = match_slot_phb_entry(phb);
	}
	/* No parent ? Oops ... */
	if (!parent || !parent->children)
		return NULL;
	for (ent = parent->children; ent->etype != st_end; ent++) {
		if (ent->etype == st_phb) {
			prerror("SLOT: Bad PHB entry type in table !\n");
			continue;
		}

		/* NPU slots match on device, not function */
		if (ent->etype == st_npu_slot)
			bdfn = pd->bdfn & 0xf8;
		else
			bdfn = pd->bdfn & 0xff;

		if (ent->location == bdfn)
			return ent;
	}
	return NULL;
}

static void slot_table_add_properties(struct pci_slot *slot,
				struct dt_node *np)
{
	struct slot_table_entry *ent = slot->data;

	if (ent)
		pci_slot_add_loc(slot, np, ent->name);
	else
		pci_slot_add_loc(slot, np, NULL);
}

void slot_table_add_slot_info(struct pci_device *pd,
		const struct slot_table_entry *ent)
{
	struct pci_slot *slot;

	if (!ent || !ent->name) {
		slot = pcie_slot_create_dynamic(pd->phb, pd);
		if (slot) {
			slot->ops.add_properties = slot_table_add_properties;
			slot->pluggable = true;
		}

		return;
	}

	slot = pcie_slot_create(pd->phb, pd);
	assert(slot);

	slot->pluggable = !!(ent->etype == st_pluggable_slot);
	slot->ops.add_properties = slot_table_add_properties;
	slot->power_limit = ent->power_limit;
	slot->data = (void *)ent;
}

void slot_table_get_slot_info(struct phb *phb, struct pci_device *pd)
{
	const struct slot_table_entry *ent;

	if (!pd || pd->slot)
		return;

	ent = match_slot_dev_entry(phb, pd);
	slot_table_add_slot_info(pd, ent);
}

static void dt_slot_add_properties(struct pci_slot *slot,
				struct dt_node *np)
{
	struct dt_node *slot_np = slot->data;
	const char *label = NULL;

	if (slot_np)
		label = dt_prop_get_def(slot_np, "ibm,slot-label", NULL);

	pci_slot_add_loc(slot, np, label);
}

void dt_slot_get_slot_info(struct phb *phb, struct pci_device *pd)
{
	struct dt_node *slot_np;
	struct pci_slot *slot;
	const char *name = NULL;
	uint32_t power_limit = 0;
	bool pluggable = false;

	if (!pd || pd->slot)
		return;

	slot_np = map_pci_dev_to_slot(phb, pd);
	if (slot_np) {
		pluggable = dt_has_node_property(slot_np,
					"ibm,pluggable", NULL);
		power_limit = dt_prop_get_u32_def(slot_np,
					"ibm,power-limit", 0);
		name = dt_prop_get_def(slot_np, "ibm,slot-label", NULL);
	}

	if (!slot_np || !name) {
		slot = pcie_slot_create_dynamic(phb, pd);
		if (slot) {
			slot->ops.add_properties = dt_slot_add_properties;
			slot->pluggable = true;
			slot->data = (void *)slot_np;
		}

		return;
	}

	slot = pcie_slot_create(phb, pd);
	assert(slot);

	slot->ops.add_properties = dt_slot_add_properties;
	slot->pluggable = pluggable;
	slot->power_limit = power_limit;
	slot->data = (void *)slot_np;
}

static int __pci_find_dev_by_location(struct phb *phb,
				      struct pci_device *pd, void *userdata)
{
	uint16_t location = *((uint16_t *)userdata);

	if (!phb || !pd)
		return 0;

	if ((pd->bdfn & 0xff) == location)
		return 1;

	return 0;
}

static struct pci_device *pci_find_dev_by_location(struct phb *phb, uint16_t location)
{
	return pci_walk_dev(phb, NULL, __pci_find_dev_by_location, &location);
}

static struct phb* get_phb_by_location(uint32_t location)
{
	struct phb *phb = NULL;
	uint32_t chip_id, phb_idx;

	for_each_phb(phb) {
		chip_id = dt_get_chip_id(phb->dt_node);
		phb_idx = dt_prop_get_u32_def(phb->dt_node,
					      "ibm,phb-index", 0);
		if (location == ST_LOC_PHB(chip_id, phb_idx))
			break;
	}

	return phb;
}

static int check_slot_table(struct phb *phb,
			    const struct slot_table_entry *parent)
{
	const struct slot_table_entry *ent;
	struct pci_device *dev = NULL;
	int r = 0;

	if (parent == NULL)
		return 0;

	for (ent = parent; ent->etype != st_end; ent++) {
		switch (ent->etype) {
		case st_phb:
			phb = get_phb_by_location(ent->location);
			if (!phb) {
				prlog(PR_ERR, "PCI: PHB %s (%x) not found\n",
				      ent->name, ent->location);
				r++;
			}
			break;
		case st_pluggable_slot:
		case st_builtin_dev:
			if (!phb)
				break;
			phb_lock(phb);
			dev = pci_find_dev_by_location(phb, ent->location);
			phb_unlock(phb);
			if (!dev) {
				prlog(PR_ERR, "PCI: built-in device not found: %s (loc: %x)\n",
				      ent->name, ent->location);
				r++;
			}
			break;
		case st_end:
		case st_npu_slot:
			break;
		}
		if (ent->children)
			r+= check_slot_table(phb, ent->children);
	}
	return r;
}

void check_all_slot_table(void)
{
	if (!slot_top_table)
		return;

	prlog(PR_DEBUG, "PCI: Checking slot table against detected devices\n");
	check_slot_table(NULL, slot_top_table);
}
