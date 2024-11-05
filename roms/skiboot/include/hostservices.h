// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __HOSTSERVICES_H
#define __HOSTSERVICES_H

bool hservices_init(void);
void hservices_lid_preload(void);
bool hservices_lid_preload_complete(void);

int host_services_occ_load(void);
int host_services_occ_start(void);
int host_services_occ_stop(void);

/* No LID can be larger than 16M, but OCC lid is less than 1 MB */

#define HBRT_LOAD_LID_SIZE     0x100000 /* 1MB */

/* TODO: Detect OCC lid size at runtime */

/* Homer and OCC area size */
#define HOMER_IMAGE_SIZE	0x400000 /* 4MB per-chip */
#define OCC_COMMON_SIZE		0x800000 /* 8MB */

int hservice_send_error_log(uint32_t plid, uint32_t dsize, void *data);
int hservice_wakeup(uint32_t i_core, uint32_t i_mode);
int fsp_occ_reset_status(u64 chipid, s64 status);
int fsp_occ_load_start_status(u64 chipid, s64 status);
int hservice_send_hbrt_msg(void *data, u64 dsize);
void hservice_hbrt_msg_response(uint32_t rc);
void hservice_fsp_init(void);

#endif /* __HOSTSERVICES_H */
