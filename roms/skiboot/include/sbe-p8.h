// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2018 IBM Corp. */

#ifndef __SBE_P8_H
#define __SBE_P8_H

/* P8 SBE update timer function */
extern void p8_sbe_update_timer_expiry(uint64_t new_target);

/* Is SBE timer available ? */
extern bool p8_sbe_timer_ok(void);

/* Initialize SBE timer */
extern void p8_sbe_init_timer(void);

#endif /* __SBE_P8_H */
