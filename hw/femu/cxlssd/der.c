/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "system/kvm.h"
#include "system/hostmem.h"
#include "hw/cxl/cxl.h"
#include "hw/cxl/cxl_host.h"
#include "hw/pci/pci_bus.h"
#include "hw/pci/pci_bridge.h"
#include "hw/pci/pci_host.h"
#include "der.h"

/* Layouts from the public CylonLinux include/linux/kvm_ext.h. */
#ifdef CONFIG_KVM
#include <linux/kvm.h>

typedef struct CylonSpteFlag {
    uint64_t gpa;
    uint64_t flag;
    uint64_t lpn;
} CylonSpteFlag;

typedef struct CylonLinearSpt {
    uint64_t *spt;
    int npages;
    int offset;
} CylonLinearSpt;

typedef struct CylonGetLinearSpt {
    CylonLinearSpt spt_list[60];
    void *backend_ptr;
    uint64_t gfn;
    int n;
} CylonGetLinearSpt;

#define CYLON_SET_SPTE_FLAG _IOW(KVMIO, 0xdd, CylonSpteFlag)
#define CYLON_GET_LINEAR_SPT _IOWR(KVMIO, 0xde, CylonGetLinearSpt)

static bool der_probe(void)
{
    CylonGetLinearSpt spt = { .gfn = UINT64_MAX };
    CylonSpteFlag flag = { .gpa = UINT64_MAX & ~4095ULL };
    CPUState *cpu;

    if (!kvm_enabled() || qemu_real_host_page_size() != 4096) {
        return false;
    }
    /* An absent GFN returns before the kernel dereferences slot->aux. */
    if (kvm_vm_ioctl(kvm_state, CYLON_GET_LINEAR_SPT, &spt) != -EINVAL) {
        return false;
    }
    cpu = qemu_get_cpu(0);
    return cpu && kvm_vcpu_ioctl(cpu, CYLON_SET_SPTE_FLAG, &flag) == 0;
}
#else
static bool der_probe(void)
{
    return false;
}
#endif

typedef struct FemuCxlMap {
    uint64_t lpn;
    MemoryRegion mr;
    MemoryRegion *container;
} FemuCxlMap;

void femu_cxl_der_init(FemuCxlDer *der, CXLType3Dev *dev, bool enabled)
{
    der->dev = dev;
    der->maps = g_hash_table_new(g_int64_hash, g_int64_equal);
    if (enabled) {
        der->probes++;
        der->available = der_probe();
        if (!der->available) {
            info_report("FEMU CXL DER unavailable; using MMIO");
        }
    }
}

/* Limit direct mappings to a single endpoint on a decoderless host bridge. */
static CXLFixedWindow *der_window(FemuCxlDer *der, uint64_t hpa)
{
    GSList *windows = cxl_fmws_get_all_sorted();
    GSList *it;
    CXLFixedWindow *found = NULL;
    PCIBus *bus = pci_get_bus(PCI_DEVICE(der->dev));
    PCIDevice *rp = bus->parent_dev;
    uint32_t *regs = der->dev->cxl_cstate.crb.cache_mem_registers;
    unsigned i;

    for (i = 0; i < CXL_HDM_DECODER_COUNT; i++) {
        uint32_t ctrl = ldl_le_p(regs + R_CXL_HDM_DECODER0_CTRL + i * 8);

        if (FIELD_EX32(ctrl, CXL_HDM_DECODER0_CTRL, COMMITTED) &&
            FIELD_EX32(ctrl, CXL_HDM_DECODER0_CTRL, IW)) {
            goto out;
        }
    }
    if (!rp || !object_dynamic_cast(OBJECT(rp), "cxl-rp")) {
        goto out;
    }
    for (it = windows; it; it = it->next) {
        CXLFixedWindow *fw = CXL_FMW(it->data);
        PCIHostState *hb;

        if (fw->num_targets != 1 || hpa < fw->base ||
            hpa - fw->base >= fw->size) {
            continue;
        }
        hb = PCI_HOST_BRIDGE(fw->target_hbs[0]->cxl_host_bridge);
        if (hb->bus == pci_get_bus(rp) && cxl_get_hb_passthrough(hb)) {
            found = fw;
            break;
        }
    }
out:
    g_slist_free(windows);
    return found;
}

bool femu_cxl_der_map(FemuCxlDer *der, uint64_t hpa, uint64_t dpa)
{
    uint64_t lpn = dpa / 4096;
    FemuCxlMap *map;
    CXLFixedWindow *fw;
    MemoryRegion *ram;

    if (!der->available || (hpa & 4095) != (dpa & 4095)) {
        return false;
    }
    if (g_hash_table_contains(der->maps, &lpn)) {
        return true;
    }
#ifdef CONFIG_KVM
    /* Leave room for splits in the KVM listener's existing regions. */
    if (kvm_enabled() && kvm_get_free_memslots() < 8) {
        return false;
    }
#endif
    fw = der_window(der, hpa);
    if (!fw) {
        return false;
    }
    ram = host_memory_backend_get_memory(der->dev->hostvmem);
    map = g_new0(FemuCxlMap, 1);
    map->lpn = lpn;
    map->container = &fw->mr;
    memory_region_init_alias(&map->mr, OBJECT(der->dev), "femu-cxl-hit",
                              ram, lpn * 4096, 4096);
    /* QEMU owns slot allocation, revocation and TLB invalidation. */
    memory_region_add_subregion_overlap(map->container,
                      (hpa & ~4095ULL) - fw->base, &map->mr, 1);
    g_hash_table_insert(der->maps, &map->lpn, map);
    der->mapped++;
    return true;
}

void femu_cxl_der_remove(FemuCxlDer *der, uint64_t lpn)
{
    FemuCxlMap *map = g_hash_table_lookup(der->maps, &lpn);

    if (!map) {
        return;
    }
    memory_region_del_subregion(map->container, &map->mr);
    g_hash_table_remove(der->maps, &lpn);
    object_unparent(OBJECT(&map->mr));
    g_free(map);
    der->mapped--;
}

void femu_cxl_der_clear(FemuCxlDer *der)
{
    GHashTableIter it;
    gpointer key;

    while (g_hash_table_size(der->maps)) {
        g_hash_table_iter_init(&it, der->maps);
        g_hash_table_iter_next(&it, &key, NULL);
        femu_cxl_der_remove(der, *(uint64_t *)key);
    }
}

void femu_cxl_der_destroy(FemuCxlDer *der)
{
    femu_cxl_der_clear(der);
    g_hash_table_destroy(der->maps);
}
