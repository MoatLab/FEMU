/*
 * Copyright (c) 2019 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef HW_I386_X86_H
#define HW_I386_X86_H

#include "qemu-common.h"
#include "exec/hwaddr.h"
#include "qemu/notify.h"

#include "hw/i386/topology.h"
#include "hw/boards.h"
#include "hw/nmi.h"
#include "hw/isa/isa.h"
#include "hw/i386/ioapic.h"
#include "qom/object.h"

struct X86MachineClass {
    /*< private >*/
    MachineClass parent;

    /*< public >*/

    /* TSC rate migration: */
    bool save_tsc_khz;
    /* Enables contiguous-apic-ID mode */
    bool compat_apic_id_mode;
};

struct X86MachineState {
    /*< private >*/
    MachineState parent;

    /*< public >*/

    /* Pointers to devices and objects: */
    ISADevice *rtc;
    FWCfgState *fw_cfg;
    qemu_irq *gsi;
    GMappedFile *initrd_mapped_file;
    HotplugHandler *acpi_dev;

    /* RAM information (sizes, addresses, configuration): */
    ram_addr_t below_4g_mem_size, above_4g_mem_size;

    /* CPU and apic information: */
    bool apic_xrupt_override;
    unsigned pci_irq_mask;
    unsigned apic_id_limit;
    uint16_t boot_cpus;
    unsigned smp_dies;

    OnOffAuto smm;
    OnOffAuto acpi;

    /*
     * Address space used by IOAPIC device. All IOAPIC interrupts
     * will be translated to MSI messages in the address space.
     */
    AddressSpace *ioapic_as;
};

#define X86_MACHINE_SMM              "smm"
#define X86_MACHINE_ACPI             "acpi"

#define TYPE_X86_MACHINE   MACHINE_TYPE_NAME("x86")
OBJECT_DECLARE_TYPE(X86MachineState, X86MachineClass, X86_MACHINE)

void init_topo_info(X86CPUTopoInfo *topo_info, const X86MachineState *x86ms);

uint32_t x86_cpu_apic_id_from_index(X86MachineState *pcms,
                                    unsigned int cpu_index);

void x86_cpu_new(X86MachineState *pcms, int64_t apic_id, Error **errp);
void x86_cpus_init(X86MachineState *pcms, int default_cpu_version);
CpuInstanceProperties x86_cpu_index_to_props(MachineState *ms,
                                             unsigned cpu_index);
int64_t x86_get_default_cpu_node_id(const MachineState *ms, int idx);
const CPUArchIdList *x86_possible_cpu_arch_ids(MachineState *ms);
CPUArchId *x86_find_cpu_slot(MachineState *ms, uint32_t id, int *idx);
void x86_rtc_set_cpus_count(ISADevice *rtc, uint16_t cpus_count);
void x86_cpu_pre_plug(HotplugHandler *hotplug_dev,
                      DeviceState *dev, Error **errp);
void x86_cpu_plug(HotplugHandler *hotplug_dev,
                  DeviceState *dev, Error **errp);
void x86_cpu_unplug_request_cb(HotplugHandler *hotplug_dev,
                               DeviceState *dev, Error **errp);
void x86_cpu_unplug_cb(HotplugHandler *hotplug_dev,
                       DeviceState *dev, Error **errp);

void x86_bios_rom_init(MemoryRegion *rom_memory, bool isapc_ram_fw);

void x86_load_linux(X86MachineState *x86ms,
                    FWCfgState *fw_cfg,
                    int acpi_data_size,
                    bool pvh_enabled,
                    bool linuxboot_dma_enabled);

bool x86_machine_is_smm_enabled(const X86MachineState *x86ms);
bool x86_machine_is_acpi_enabled(const X86MachineState *x86ms);

/* Global System Interrupts */

#define GSI_NUM_PINS IOAPIC_NUM_PINS
#define ACPI_BUILD_PCI_IRQS ((1<<5) | (1<<9) | (1<<10) | (1<<11))

typedef struct GSIState {
    qemu_irq i8259_irq[ISA_NUM_IRQS];
    qemu_irq ioapic_irq[IOAPIC_NUM_PINS];
} GSIState;

qemu_irq x86_allocate_cpu_irq(void);
void gsi_handler(void *opaque, int n, int level);
void ioapic_init_gsi(GSIState *gsi_state, const char *parent_name);

#endif
