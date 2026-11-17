/*
 * GWDT Watchdog Action Table (WDAT) definition
 *
 * Copyright Red Hat, Inc. 2026
 * Author(s): Igor Mammedov <imammedo@redhat.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef QEMU_HW_ACPI_WDAT_GWDT_H
#define QEMU_HW_ACPI_WDAT_GWDT_H

#include "hw/acpi/aml-build.h"
#include "hw/watchdog/sbsa_gwdt.h"

void build_gwdt_wdat(GArray *table_data, BIOSLinker *linker, const char *oem_id,
                     const char *oem_table_id, uint64_t rbase, uint64_t cbase,
                     uint64_t freq);

#endif /* QEMU_HW_ACPI_WDAT_GWDT_H */
