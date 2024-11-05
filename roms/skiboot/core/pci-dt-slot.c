// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * PCI slots in the device tree.
 *
 * Copyright 2017-2018 IBM Corp.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

#include <skiboot.h>
#include <device.h>

#include <pci.h>
#include <pci-cfg.h>
#include <pci-slot.h>
#include <ccan/list/list.h>

#undef pr_fmt
#define pr_fmt(fmt) "DT-SLOT: " fmt

struct dt_node *dt_slots;

static struct dt_node *map_phb_to_slot(struct phb *phb)
{
	uint32_t chip_id = dt_get_chip_id(phb->dt_node);
	uint32_t phb_idx = dt_prop_get_u32_def(phb->dt_node,
					       "ibm,phb-index", 0);
	struct dt_node *slot_node;

	if (!dt_slots)
		dt_slots = dt_find_by_path(dt_root, "/ibm,pcie-slots");

	if (!dt_slots)
		return NULL;

	dt_for_each_child(dt_slots, slot_node) {
		u32 reg[2];

		if (!dt_node_is_compatible(slot_node, "ibm,pcie-root-port"))
			continue;

		reg[0] = dt_prop_get_cell(slot_node, "reg", 0);
		reg[1] = dt_prop_get_cell(slot_node, "reg", 1);

		if (reg[0] == chip_id && reg[1] == phb_idx)
			return slot_node;
	}

	return NULL;
}

static struct dt_node *find_devfn(struct dt_node *bus, uint32_t bdfn)
{
	uint32_t port_dev_id = PCI_DEV(bdfn);
	struct dt_node *child;

	dt_for_each_child(bus, child)
		if (dt_prop_get_u32_def(child, "reg", ~0u) == port_dev_id)
			return child;

	return NULL;
}

/* Looks for a device device under this slot. */
static struct dt_node *find_dev_under_slot(struct dt_node *slot,
					   struct pci_device *pd)
{
	struct dt_node *child, *wildcard = NULL;

	/* find the device in the parent bus node */
	dt_for_each_child(slot, child) {
		u32 vdid;

		/* "pluggable" and "builtin" without unit addrs are wildcards */
		if (!dt_has_node_property(child, "reg", NULL)) {
			if (wildcard)
				prerror("Duplicate wildcard entry! Already have %s, found %s",
					wildcard->name, child->name);

			wildcard = child;
			continue;
		}

		/* NB: the pci_device vdid is did,vid rather than vid,did */
		vdid = dt_prop_get_cell(child, "reg", 1) << 16 |
			dt_prop_get_cell(child, "reg", 0);

		if (vdid == pd->vdid)
			return child;
	}

	if (!wildcard)
		PCIDBG(pd->phb, pd->bdfn,
			"Unable to find a slot for device %.4x:%.4x\n",
			(pd->vdid & 0xffff0000) >> 16, pd->vdid & 0xffff);

	return wildcard;
}

/*
 * If the `pd` is a bridge this returns a node with a compatible of
 * ibm,pcie-port to indicate it's a "slot node".
 */
static struct dt_node *find_node_for_dev(struct phb *phb,
					 struct pci_device *pd)
{
	struct dt_node *sw_slot, *sw_up;

	assert(pd);

	if (pd->slot && pd->slot->data)
		return pd->slot->data;

	/*
	 * Example DT:
	 *	 /root-complex@8,5/switch-up@10b5,8725/down-port@4
	 */
	switch (pd->dev_type) {
	case PCIE_TYPE_ROOT_PORT: // find the root-complex@<chip>,<phb> node
		return map_phb_to_slot(phb);

	case PCIE_TYPE_SWITCH_DNPORT: // grab the down-port@<devfn>
		/*
		 * Walk up the topology to find the slot that contains
		 * the switch upstream port is connected to. In the example
		 * this would be the root-complex@8,5 node.
		 */
		sw_slot = find_node_for_dev(phb, pd->parent->parent);
		if (!sw_slot)
			return NULL;

		/* find the per-device node for this switch */
		sw_up = find_dev_under_slot(sw_slot, pd->parent);
		if (!sw_up)
			return NULL;

		/* find this down port */
		return find_devfn(sw_up, pd->bdfn);

	default:
		PCIDBG(phb, pd->bdfn,
			"Trying to find a slot for non-pcie bridge type %d\n",
			pd->dev_type);
		assert(0);
	}

	return NULL;
}

struct dt_node *map_pci_dev_to_slot(struct phb *phb, struct pci_device *pd)
{
	struct dt_node *n;
	char *path;

	assert(pd);

	/*
	 * Having a slot only makes sense for root and switch downstream ports.
	 * We don't care about PCI-X.
	 */
	if (pd->dev_type != PCIE_TYPE_SWITCH_DNPORT &&
	    pd->dev_type != PCIE_TYPE_ROOT_PORT)
		return NULL;

	PCIDBG(phb, pd->bdfn, "Finding slot\n");

	n = find_node_for_dev(phb, pd);
	if (!n) {
		PCIDBG(phb, pd->bdfn, "No slot found!\n");
	} else {
		path = dt_get_path(n);
		PCIDBG(phb, pd->bdfn, "Slot found %s\n", path);
		free(path);
	}

	return n;
}

int __print_slot(struct phb *phb, struct pci_device *pd, void *userdata);
int __print_slot(struct phb *phb, struct pci_device *pd,
			void __unused *userdata)
{
	struct dt_node *node;
	struct dt_node *pnode;
	char *c = NULL;
	u32 phandle = 0;

	if (!pd)
		return 0;

	node = map_pci_dev_to_slot(phb, pd);

	/* at this point all node associations should be done */
	if (pd->dn && dt_has_node_property(pd->dn, "ibm,pcie-slot", NULL)) {
		phandle = dt_prop_get_u32(pd->dn, "ibm,pcie-slot");
		pnode = dt_find_by_phandle(dt_root, phandle);

		assert(node == pnode);
	}

	if (node)
		c = dt_get_path(node);

	PCIDBG(phb, pd->bdfn, "Mapped to slot %s (%x)\n",
		c ? c : "<null>", phandle);

	free(c);

	return 0;
}
