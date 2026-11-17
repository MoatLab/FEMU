/*
 * QEMU page protection (system emulation)
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#ifndef SYSTEM_PAGE_PROTECTION_H
#define SYSTEM_PAGE_PROTECTION_H

#include "system/ram_addr.h"

void tlb_protect_code(ram_addr_t ram_addr);
void tlb_unprotect_code(ram_addr_t ram_addr);

#endif

