// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2018 IBM Corp. */

#ifndef __HDATA_H
#define __HDATA_H

#include <processor.h>
#include "hdif.h"
#include "spira.h"

struct dt_node;

extern void memory_parse(void);
extern bool pcia_parse(void);
extern void fsp_parse(void);
extern void bmc_parse(void);
extern void io_parse(void);
extern void dt_init_vpd_node(void);
extern struct dt_node *dt_add_vpd_node(const struct HDIF_common_hdr *hdr,
				       int indx_fru, int indx_vpd);
extern void vpd_parse(void);
extern void vpd_data_parse(struct dt_node *node,
			   const void *fruvpd, u32 fruvpd_sz);

extern struct dt_node *find_xscom_for_chip(uint32_t chip_id);
extern uint32_t pcid_to_chip_id(uint32_t proc_chip_id);
extern uint32_t pcid_to_topology_idx(uint32_t proc_chip_id);
extern uint32_t get_xscom_id(const struct sppcrd_chip_info *cinfo);

extern struct dt_node *add_core_common(struct dt_node *cpus,
				       const struct sppcia_cpu_cache *cache,
				       const struct sppcia_cpu_timebase *tb,
				       uint32_t int_server, bool okay);
extern void add_core_attr(struct dt_node *cpu, uint32_t attr);
extern uint32_t add_core_cache_info(struct dt_node *cpus,
				    const struct sppcia_cpu_cache *cache,
				    uint32_t int_server, int okay);
extern const struct slca_entry *slca_get_entry(uint16_t slca_index);
extern const char *slca_get_vpd_name(uint16_t slca_index);
extern const char *slca_get_loc_code_index(uint16_t slca_index);
extern void slca_vpd_add_loc_code(struct dt_node *node, uint16_t slca_index);
extern void slca_dt_add_sai_node(void);
extern void dt_add_proc_vendor(struct dt_node *proc_node,
			       const void *mvpd, unsigned int mvpd_sz);

extern bool hservices_from_hdat(const void *fdt, size_t size);
int parse_i2c_devs(const struct HDIF_common_hdr *hdr, int idata_index,
	struct dt_node *xscom);
extern void node_stb_parse(void);

/* used to look up the device-tree node representing a slot */
struct dt_node *find_slot_entry_node(struct dt_node *root, u32 entry_id);

#endif /* __HDATA_H */

