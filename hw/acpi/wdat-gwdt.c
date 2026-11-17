/*
 * SBSA GWDT Watchdog Action Table (WDAT)
 *
 * Copyright Red Hat, Inc. 2026
 * Author(s): Igor Mammedov <imammedo@redhat.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/acpi/aml-build.h"
#include "hw/acpi/wdat-gwdt.h"
#include "hw/acpi/wdat.h"
#include "hw/watchdog/sbsa_gwdt.h"

#define GWDT_REG(base, reg_offset, reg_width) { \
                 .space_id = AML_AS_SYSTEM_MEMORY, \
                 .address = base + reg_offset, .bit_width = reg_width, \
                 .access_width = AML_DWORD_ACC };

/*
 *   "Hardware Watchdog Timers Design Specification"
 *       https://uefi.org/acpi 'Watchdog Action Table (WDAT)'
 */
void build_gwdt_wdat(GArray *table_data, BIOSLinker *linker, const char *oem_id,
                     const char *oem_table_id, uint64_t rbase, uint64_t cbase,
                     uint64_t freq)
{
    AcpiTable table = { .sig = "WDAT", .rev = 1, .oem_id = oem_id,
                        .oem_table_id = oem_table_id };

    struct AcpiGenericAddress wrr =  GWDT_REG(rbase, 0x0, 32);
    struct AcpiGenericAddress wor_l =  GWDT_REG(cbase, SBSA_GWDT_WOR, 32);
    struct AcpiGenericAddress wcs =  GWDT_REG(cbase, SBSA_GWDT_WCS, 32);

    acpi_table_begin(&table, table_data);
    build_append_int_noprefix(table_data, 0x20, 4); /* Watchdog Header Length */
    /*
     * PCI location fields are set to 0xff to indicate
     * that the watchdog is not a PCI device.
     */
    build_append_int_noprefix(table_data, 0xff, 2); /* PCI Segment */
    build_append_int_noprefix(table_data, 0xff, 1); /* PCI Bus Number */
    build_append_int_noprefix(table_data, 0xff, 1); /* PCI Device Number */
    build_append_int_noprefix(table_data, 0xff, 1); /* PCI Function Number */
    build_append_int_noprefix(table_data, 0, 3);    /* Reserved */
    /*
     * WDAT spec: "The clock interval that the WDT uses must be
     * greater than or equal to 1 millisecond."
     */
    g_assert(freq <= 1000);
    /* Timer Period, ms */
    build_append_int_noprefix(table_data, 1000 / freq, 4);
    /*
     * WDAT spec: "The time-out period before the WDT fires is recommended
     * to be at least 5 minutes."
     * Set max count to 10min and min count to 5sec.
     */
    build_append_int_noprefix(table_data, 600 * freq, 4); /* Maximum Count */
    build_append_int_noprefix(table_data, 5 * freq, 4);   /* Minimum Count */
    /*
     * WATCHDOG_ENABLED | WATCHDOG_STOPPED_IN_SLEEP_STATE
     */
    build_append_int_noprefix(table_data, 0x81, 1); /* Watchdog Flags */
    build_append_int_noprefix(table_data, 0, 3);    /* Reserved */
    /*
     * watchdog instruction entries
     */
    build_append_int_noprefix(table_data, 8, 4);
    /* Action table: WCS (control/status) register actions */
    build_append_wdat_ins(table_data, WDAT_ACTION_QUERY_RUNNING_STATE,
        WDAT_INS_READ_VALUE,
        wcs, 0x1, 0x1);
    build_append_wdat_ins(table_data, WDAT_ACTION_SET_RUNNING_STATE,
        WDAT_INS_WRITE_VALUE | WDAT_INS_PRESERVE_REGISTER,
        wcs, 1, 0x00000001);
    build_append_wdat_ins(table_data, WDAT_ACTION_QUERY_STOPPED_STATE,
        WDAT_INS_READ_VALUE,
        wcs, 0x0, 0x00000001);
    build_append_wdat_ins(table_data, WDAT_ACTION_SET_STOPPED_STATE,
        WDAT_INS_WRITE_VALUE | WDAT_INS_PRESERVE_REGISTER,
        wcs, 0x0, 0x00000001);
    build_append_wdat_ins(table_data, WDAT_ACTION_QUERY_WATCHDOG_STATUS,
        WDAT_INS_READ_VALUE,
        wcs, 0x4, 0x00000004);
    /* WOR (offset) and WRR (refresh) register actions */
    build_append_wdat_ins(table_data, WDAT_ACTION_SET_COUNTDOWN_PERIOD,
        WDAT_INS_WRITE_COUNTDOWN,
        wor_l, 0, 0xffffffff);
    /* WRR: any write refreshes the watchdog, value is ignored */
    build_append_wdat_ins(table_data, WDAT_ACTION_RESET,
        WDAT_INS_WRITE_VALUE,
        wrr, 0x1, 0x1);
    build_append_wdat_ins(table_data, WDAT_ACTION_SET_WATCHDOG_STATUS,
        WDAT_INS_WRITE_VALUE | WDAT_INS_PRESERVE_REGISTER,
        wrr, 0x4, 0x4);

    acpi_table_end(linker, &table);
}
