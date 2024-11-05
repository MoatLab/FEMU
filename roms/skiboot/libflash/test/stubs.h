// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2018 IBM Corp. */

#include <lock.h>
#include <stdint.h>

#include "../../include/lpc-mbox.h"

void check_timers(bool unused);
void time_wait_ms(unsigned long ms);
unsigned long mftb(void);
void _prlog(int log_level, const char* fmt, ...);
void bmc_put_u16(struct bmc_mbox_msg *msg, int offset, uint16_t data);
void bmc_put_u32(struct bmc_mbox_msg *msg, int offset, uint32_t data);
u16 bmc_get_u16(struct bmc_mbox_msg *msg, int offset);
u32 bmc_get_u32(struct bmc_mbox_msg *msg, int offset);
void *__zalloc(size_t sz);
void __free(const void *p);
void lock_caller(struct lock *l, const char *caller);
void unlock(struct lock *l);
