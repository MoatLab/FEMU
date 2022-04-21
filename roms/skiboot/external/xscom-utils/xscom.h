// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2014-2017 IBM Corp.
 */

#ifndef __XSCOM_H
#define __XSCOM_H

#include <stdint.h>

extern int xscom_read(uint32_t chip_id, uint64_t addr, uint64_t *val);
extern int xscom_write(uint32_t chip_id, uint64_t addr, uint64_t val);

extern int xscom_read_ex(uint32_t ex_target_id, uint64_t addr, uint64_t *val);
extern int xscom_write_ex(uint32_t ex_target_id, uint64_t addr, uint64_t val);

extern void xscom_for_each_chip(void (*cb)(uint32_t chip_id));

extern bool xscom_readable(uint64_t addr);

extern uint32_t xscom_init(void);

#ifndef PPC_BIT
#define PPC_BIT(bit)		(0x8000000000000000UL >> (bit))
#endif

#endif /* __XSCOM_H */
