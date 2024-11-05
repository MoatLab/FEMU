// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2014-2016 IBM Corp. */

#ifndef __SRAM_H
#define __SRAM_H

#include <stdint.h>

extern int sram_read(uint32_t chip_id, int chan, uint64_t addr, uint64_t *val);
extern int sram_write(uint32_t chip_id, int chan, uint64_t addr, uint64_t val);

extern void sram_for_each_chip(void (*cb)(uint32_t chip_id));

#endif /* __SRAM_H */
