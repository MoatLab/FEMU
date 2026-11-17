/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef USER_MMAP_MIN_ADDR_H
#define USER_MMAP_MIN_ADDR_H

#ifndef CONFIG_USER_ONLY
#error Cannot include this header from system emulation
#endif

extern uintptr_t mmap_min_addr;

#endif
