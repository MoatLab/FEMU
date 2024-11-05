// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __IBM_FSP_COMMON_H
#define __IBM_FSP_COMMON_H

extern void ibm_fsp_init(void);
extern void ibm_fsp_exit(void);
void ibm_fsp_finalise_dt(bool is_reboot);

extern int64_t ibm_fsp_cec_power_down(uint64_t request);
extern int64_t ibm_fsp_cec_reboot(void);

struct errorlog;
extern int elog_fsp_commit(struct errorlog *buf);

extern int64_t ibm_fsp_sensor_read(uint32_t sensor_hndl, int token,
					__be64 *sensor_data);

/* Apollo PCI support */
extern void apollo_pci_setup_phb(struct phb *phb,
				 unsigned int index);
extern void apollo_pci_get_slot_info(struct phb *phb,
				     struct pci_device *pd);

/* Firenze PCI support */
extern void firenze_pci_send_inventory(void);
extern void firenze_pci_setup_phb(struct phb *phb,
				  unsigned int index);
extern void firenze_pci_get_slot_info(struct phb *phb,
				      struct pci_device *pd);
extern void firenze_pci_add_loc_code(struct dt_node *np,
				      struct pci_device *pd);

/* VPD support */
void vpd_iohub_load(struct dt_node *hub_node);
void vpd_preload(struct dt_node *hub_node);

/* Platform heartbeat time */
int __attrconst fsp_heartbeat_time(void);

extern struct platform_psi fsp_platform_psi;
extern struct platform_prd fsp_platform_prd;

#endif /*  __IBM_FSP_COMMON_H */
