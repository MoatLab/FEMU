// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2017-2019 IBM Corp. */

#ifndef __SBE_H
#define __SBE_H

#include <skiboot.h>

/* SBE update timer function */
extern void sbe_update_timer_expiry(uint64_t target);

/* Is SBE timer available ? */
extern bool sbe_timer_present(void);

/* Is SBE timer keeping good time ? */
extern bool sbe_timer_ok(void);

extern bool sbe_has_timer;
extern bool sbe_timer_good;

#endif	/* __SBE_P9_H */
