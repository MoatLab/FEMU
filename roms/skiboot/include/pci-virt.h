// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2016 IBM Corp. */

#ifndef __PCI_VIRT_H
#define __PCI_VIRT_H

#include <ccan/list/list.h>

enum {
	PCI_VIRT_CFG_NORMAL,
	PCI_VIRT_CFG_RDONLY,
	PCI_VIRT_CFG_W1CLR,
	PCI_VIRT_CFG_MAX
};

struct pci_virt_device {
	uint32_t		bdfn;
	uint32_t		cfg_size;
	uint8_t			*config[PCI_VIRT_CFG_MAX];
	struct list_head	pcrf;
	struct list_node	node;
	void			*data;
};

extern void pci_virt_cfg_read_raw(struct pci_virt_device *pvd,
				  uint32_t space, uint32_t offset,
				  uint32_t size, uint32_t *data);
extern void pci_virt_cfg_write_raw(struct pci_virt_device *pvd,
				   uint32_t space, uint32_t offset,
				   uint32_t size, uint32_t data);
extern struct pci_cfg_reg_filter *pci_virt_add_filter(
					struct pci_virt_device *pvd,
					uint32_t start, uint32_t len,
					uint32_t flags, pci_cfg_reg_func func,
					void *data);
extern int64_t pci_virt_cfg_read(struct phb *phb, uint32_t bdfn,
				 uint32_t offset, uint32_t size,
				 uint32_t *data);
extern int64_t pci_virt_cfg_write(struct phb *phb, uint32_t bdfn,
				  uint32_t offset, uint32_t size,
				  uint32_t data);
extern struct pci_virt_device *pci_virt_find_device(struct phb *phb,
						    uint32_t bdfn);
extern struct pci_virt_device *pci_virt_add_device(struct phb *phb,
						   uint32_t bdfn,
						   uint32_t cfg_size,
						   void *data);

/* Config space accessors */
#define PCI_VIRT_CFG_NORMAL_RD(d, o, s, v)	\
	pci_virt_cfg_read_raw(d, PCI_VIRT_CFG_NORMAL, o, s, v)
#define PCI_VIRT_CFG_NORMAL_WR(d, o, s, v)	\
	pci_virt_cfg_write_raw(d, PCI_VIRT_CFG_NORMAL, o, s, v)
#define PCI_VIRT_CFG_RDONLY_RD(d, o, s, v)	\
	pci_virt_cfg_read_raw(d, PCI_VIRT_CFG_RDONLY, o, s, v)
#define PCI_VIRT_CFG_RDONLY_WR(d, o, s, v)	\
	pci_virt_cfg_write_raw(d, PCI_VIRT_CFG_RDONLY, o, s, v)
#define PCI_VIRT_CFG_W1CLR_RD(d, o, s, v)	\
	pci_virt_cfg_read_raw(d, PCI_VIRT_CFG_W1CLR, o, s, v)
#define PCI_VIRT_CFG_W1CLR_WR(d, o, s, v)	\
	pci_virt_cfg_write_raw(d, PCI_VIRT_CFG_W1CLR, o, s, v)

#define PCI_VIRT_CFG_INIT(d, o, s, v, r, w)		\
	do {						\
		PCI_VIRT_CFG_NORMAL_WR(d, o, s, v);	\
		PCI_VIRT_CFG_RDONLY_WR(d, o, s, r);	\
		PCI_VIRT_CFG_W1CLR_WR(d, o, s, w);	\
	} while (0)
#define PCI_VIRT_CFG_INIT_RO(d, o, s, v)		\
	PCI_VIRT_CFG_INIT(d, o, s, v, 0xffffffff, 0)

#endif /* __VIRT_PCI_H */
