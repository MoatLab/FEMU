#ifndef HW_I386_ACPI_COMMON_H
#define HW_I386_ACPI_COMMON_H

#include "hw/acpi/acpi_dev_interface.h"
#include "hw/acpi/bios-linker-loader.h"
#include "hw/i386/x86.h"

/* Default IOAPIC ID */
#define ACPI_BUILD_IOAPIC_ID 0x0

void acpi_build_madt(GArray *table_data, BIOSLinker *linker,
                     X86MachineState *x86ms, AcpiDeviceIf *adev,
                     const char *oem_id, const char *oem_table_id);

#endif
