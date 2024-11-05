// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2014 IBM Corp. */

#ifndef __FSI_MASTER_H
#define __FSI_MASTER_H

/*
 * Definition of the MFSI masters
 */
#define MFSI_cMFSI0	0
#define MFSI_cMFSI1	1
#define MFSI_hMFSI0	2

extern int64_t mfsi_read(uint32_t chip, uint32_t mfsi, uint32_t port,
			 uint32_t fsi_addr, uint32_t *data);

extern int64_t mfsi_write(uint32_t chip, uint32_t mfsi, uint32_t port,
			  uint32_t fsi_addr, uint32_t data);

extern void mfsi_init(void);

#endif /* __FSI_MASTER_H */

