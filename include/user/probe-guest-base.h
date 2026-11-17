/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef USER_PROBE_GUEST_BASE_H
#define USER_PROBE_GUEST_BASE_H

#ifndef CONFIG_USER_ONLY
#error Cannot include this header from system emulation
#endif

#include "exec/vaddr.h"

typedef struct PGBRange {
    vaddr lo;
    vaddr hi;
} PGBRange;

/**
 * probe_guest_base:
 * @image_name: the executable being loaded
 * @image_range: the fixed addresses within the executable
 *
 * Creates the initial guest address space in the host memory space.
 *
 * If @image_range is NULL, then no address in the executable is fixed,
 * i.e. it is fully relocatable.
 *
 * This function will not return if a valid value for guest_base
 * cannot be chosen.  On return, the executable loader can expect
 *
 *    target_mmap(i->lo, i->hi - i->lo + 1, ...)
 *
 * to succeed.
 */
void probe_guest_base(const char *image_name, const PGBRange *image_range,
                      const PGBRange *commpage_range);

#endif
