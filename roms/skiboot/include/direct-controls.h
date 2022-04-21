// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2017 IBM Corp. */

#ifndef __DIRECT_CONTROLS_H
#define __DIRECT_CONTROLS_H

#include <skiboot.h>
#include <opal.h>
#include <cpu.h>

/* fast reboot APIs */
extern int sreset_all_prepare(void);
extern int sreset_all_others(void);
extern void sreset_all_finish(void);

#endif /* __DIRECT_CONTROLS_H */
