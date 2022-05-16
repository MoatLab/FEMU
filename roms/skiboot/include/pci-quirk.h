// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2016-2017 IBM Corp. */

#ifndef __PCI_QUIRK_H
#define __PCI_QUIRK_H

#include <pci.h>

#define PCI_ANY_ID 0xFFFF

struct pci_quirk {
	uint16_t vendor_id;
	uint16_t device_id;
	void (*fixup)(struct phb *, struct pci_device *);
};

void pci_handle_quirk(struct phb *phb, struct pci_device *pd);

#endif /* __PCI_QUIRK_H */
