/*
 * Copyright Red Hat, Inc. 2026
 * Author(s): Igor Mammedov <imammedo@redhat.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/acpi/wdat-gwdt.h"

void build_gwdt_wdat(GArray *table_data, BIOSLinker *linker, const char *oem_id,
                     const char *oem_table_id, uint64_t rbase, uint64_t cbase,
                     uint64_t freq)
{
    g_assert_not_reached();
}
