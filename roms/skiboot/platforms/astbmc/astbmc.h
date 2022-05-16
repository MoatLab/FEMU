// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __ASTBMC_H
#define __ASTBMC_H

#include <platform.h>

#define ST_LOC_PHB(chip_id, phb_idx)    ((chip_id) << 16 | (phb_idx))
#define ST_LOC_DEVFN(dev, fn)	        ((dev) << 3 | (fn))
/*
 * NPU groups are used to allocate device numbers.  There is a 1 to 1
 * correlation between a NPU group and a physical GPU.  Links within a group
 * are allocated as functions within a device, so groups must be numbered
 * sequentially starting at 0.
 */
#define ST_LOC_NPU_GROUP(group_id)	(group_id << 3)

struct slot_table_entry {
	enum slot_table_etype {
		st_end,		/* End of list */
		st_phb,
		st_pluggable_slot,
		st_builtin_dev,
		st_npu_slot
	} etype;
	uint32_t location;
	const char *name;
	const struct slot_table_entry *children;
	uint8_t power_limit;
};

/*
 * Helper to reduce the noise in the PHB table
 */
#define ST_PHB_ENTRY(chip_id, phb_id, child_table) \
{ \
	.etype = st_phb, \
	.location = ST_LOC_PHB(chip_id, phb_id), \
	.children = child_table \
}

/*
 * For the most part the "table" isn't really a table and only contains
 * a single real entry and the etype = st_end terminator. In these cases
 * we can use these helpers. If you need something special in the slot
 * table for each slot (e.g. power limit, devfn != 0) then you need to
 * define the actual structure.
 */
#define ST_BUILTIN_DEV(st_name, slot_name, ...) \
static struct slot_table_entry st_name[] = \
{ \
	{ \
		.etype = st_pluggable_slot, \
		.name = slot_name, \
		##__VA_ARGS__ \
	}, \
	{ .etype = st_end }, \
}

#define ST_PLUGGABLE(st_name, slot_name, ...) \
static struct slot_table_entry st_name[] = \
{ \
	{ \
		.etype = st_pluggable_slot, \
		.name = slot_name, \
		##__VA_ARGS__ \
	}, \
	{ .etype = st_end }, \
}

#define SW_PLUGGABLE(slot_name, port, ...) \
{ \
	.etype = st_pluggable_slot, \
	.name = slot_name, \
	.location = ST_LOC_DEVFN(port, 0), \
	##__VA_ARGS__ \
}

#define SW_BUILTIN(slot_name, port, ...) \
{ \
	.etype = st_builtin_dev, \
	.name = slot_name, \
	.location = ST_LOC_DEVFN(port, 0), \
	##__VA_ARGS__ \
}

extern const struct bmc_hw_config bmc_hw_ast2400;
extern const struct bmc_hw_config bmc_hw_ast2500;
extern const struct bmc_hw_config bmc_hw_ast2600;
extern const struct bmc_platform bmc_plat_ast2400_ami;
extern const struct bmc_platform bmc_plat_ast2500_ami;
extern const struct bmc_platform bmc_plat_ast2500_openbmc;
extern const struct bmc_platform bmc_plat_ast2600_openbmc;

extern void astbmc_early_init(void);
extern int64_t astbmc_ipmi_reboot(void);
extern int64_t astbmc_ipmi_power_down(uint64_t request);
extern void astbmc_init(void);
extern void astbmc_ext_irq_serirq_cpld(unsigned int chip_id);
extern int pnor_init(void);
extern void check_all_slot_table(void);
extern void astbmc_exit(void);
extern void astbmc_seeprom_update(void);

extern void slot_table_init(const struct slot_table_entry *top_table);
extern void slot_table_get_slot_info(struct phb *phb, struct pci_device * pd);
void slot_table_add_slot_info(struct pci_device *pd,
		const struct slot_table_entry *ent);

void dt_slot_get_slot_info(struct phb *phb, struct pci_device *pd);

#endif /* __ASTBMC_H */
