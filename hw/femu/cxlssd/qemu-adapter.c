/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "qemu/module.h"
#include "qemu/units.h"
#include "qemu/main-loop.h"
#include "hw/qdev-properties.h"
#include "hw/cxl/cxl_device.h"
#include "system/hostmem.h"
#include "system/qtest.h"
#include "migration/vmstate.h"
#include "../bbssd/ftl.h"
#include "cache.h"
#include "qemu-adapter.h"

#include "qemu/error-report.h"
#include "qemu/guest-random.h"
#include "hw/boards.h"
#include "system/system.h"
#include "hw/pci/pcie_port.h"
#include "hw/resettable.h"
#include "hw/cxl/cxl.h"
#include "hw/cxl/cxl_host.h"
#include "hw/pci/pci_bus.h"
#include "hw/pci/pci_bridge.h"
#include "hw/pci/pci_host.h"
#include "system/kvm.h"
#include "system/address-spaces.h"
#include "qemu/atomic.h"
#include "qemu/rcu.h"
#include "system/cpus.h"
#include "system/runstate.h"
#include "spte.h"
#include "trace/control.h"

#define TYPE_FEMU_CXL_SSD "femu-cxl-ssd"
OBJECT_DECLARE_SIMPLE_TYPE(FemuCxlSsd, FEMU_CXL_SSD)

struct FemuCxlSsd {
    CXLType3Dev parent_obj;
    FemuCxlMedia media;
    MemoryRegion component_overlay;
    Notifier machine_done;
    bool attached;
    bool test_change_dpa;
    size_t lsa_limit;
};

static void (*parent_realize)(PCIDevice *dev, Error **errp);
static void (*parent_exit)(PCIDevice *dev);
static void (*parent_config_write)(PCIDevice *, uint32_t, uint32_t, int);
static ResettablePhases parent_reset;
static uint64_t (*parent_lsa_size)(CXLType3Dev *);
static uint64_t (*parent_get_lsa)(CXLType3Dev *, void *, uint64_t, uint64_t);
static void (*parent_set_lsa)(CXLType3Dev *, const void *, uint64_t, uint64_t);
static void cxl_dump_spt(FemuCxlDer *der, FILE *file);
static void cxl_ratio(FemuCxlSsd *dev, uint64_t ratio, Error **errp);
static void cylon_ratio_revoke(FemuCxlDer *der);
static void cylon_ratio_apply(FemuCxlDer *der, CXLFixedWindow *fw);

#define FEMU_CXL_LSA_SIZE (128 * MiB)

static FemuCylon *femu_cylon_prepare(FemuCxlDer *der, const char **reason);
static bool femu_cylon_map(FemuCxlDer *der, CXLFixedWindow *fw,
                           uint64_t hpa, uint64_t dpa);
static void femu_cylon_remove(FemuCxlDer *der, uint64_t lpn);
static void femu_cylon_destroy(FemuCxlDer *der);
static void femu_cylon_clear(FemuCxlDer *der);


/* Resolve targets before machine-init-done has linked the fixed windows. */
static PCIHostState *adapter_host(CXLFixedWindow *fw, unsigned index)
{
    Object *obj = object_resolve_path_type(fw->targets[index],
                                          TYPE_PXB_CXL_DEV, NULL);

    return obj ? PCI_HOST_BRIDGE(PXB_CXL_DEV(obj)->cxl_host_bridge) : NULL;
}

static bool adapter_hdm_find_target(uint32_t *cache_mem, hwaddr addr,
                                uint8_t *target)
{
    int hdm_inc = R_CXL_HDM_DECODER1_BASE_LO - R_CXL_HDM_DECODER0_BASE_LO;
    unsigned int hdm_count;
    bool found = false;
    int i;
    uint32_t cap;

    cap = ldl_le_p(cache_mem + R_CXL_HDM_DECODER_CAPABILITY);
    hdm_count = cxl_decoder_count_dec(FIELD_EX32(cap,
                                                 CXL_HDM_DECODER_CAPABILITY,
                                                 DECODER_COUNT));
    for (i = 0; i < hdm_count; i++) {
        uint32_t ctrl;
        uint32_t ig_enc;
        uint32_t iw_enc;
        uint32_t target_idx;
        uint32_t low;
        uint32_t high;
        uint64_t base;
        uint64_t size;

        low = ldl_le_p(cache_mem + R_CXL_HDM_DECODER0_BASE_LO + i * hdm_inc);
        high = ldl_le_p(cache_mem + R_CXL_HDM_DECODER0_BASE_HI + i * hdm_inc);
        base = (low & 0xf0000000) | ((uint64_t)high << 32);
        low = ldl_le_p(cache_mem + R_CXL_HDM_DECODER0_SIZE_LO + i * hdm_inc);
        high = ldl_le_p(cache_mem + R_CXL_HDM_DECODER0_SIZE_HI + i * hdm_inc);
        size = (low & 0xf0000000) | ((uint64_t)high << 32);
        if (addr < base || addr >= base + size) {
            continue;
        }

        ctrl = ldl_le_p(cache_mem + R_CXL_HDM_DECODER0_CTRL + i * hdm_inc);
        if (!FIELD_EX32(ctrl, CXL_HDM_DECODER0_CTRL, COMMITTED)) {
            return false;
        }
        found = true;
        ig_enc = FIELD_EX32(ctrl, CXL_HDM_DECODER0_CTRL, IG);
        iw_enc = FIELD_EX32(ctrl, CXL_HDM_DECODER0_CTRL, IW);
        target_idx = (addr / cxl_decode_ig(ig_enc)) % (1 << iw_enc);

        if (target_idx < 4) {
            uint32_t val = ldl_le_p(cache_mem +
                                    R_CXL_HDM_DECODER0_TARGET_LIST_LO +
                                    i * hdm_inc);
            *target = extract32(val, target_idx * 8, 8);
        } else {
            uint32_t val = ldl_le_p(cache_mem +
                                    R_CXL_HDM_DECODER0_TARGET_LIST_HI +
                                    i * hdm_inc);
            *target = extract32(val, (target_idx - 4) * 8, 8);
        }
        break;
    }

    return found;
}

static PCIDevice *adapter_route(CXLFixedWindow *fw, hwaddr addr)
{
    CXLComponentState *hb_cstate;
    CXLComponentState *usp_cstate;
    PCIHostState *hb;
    CXLUpstreamPort *usp;
    int rb_index;
    uint32_t *cache_mem;
    uint8_t target;
    bool target_found;
    PCIDevice *rp;
    PCIDevice *d;

    /* Address is relative to memory region. Convert to HPA */
    addr += fw->base;

    rb_index = (addr / cxl_decode_ig(fw->enc_int_gran)) % fw->num_targets;
    hb = adapter_host(fw, rb_index);
    if (!hb || !hb->bus || !pci_bus_is_cxl(hb->bus)) {
        return NULL;
    }

    if (cxl_get_hb_passthrough(hb)) {
        rp = pcie_find_port_first(hb->bus);
        if (!rp) {
            return NULL;
        }
    } else {
        hb_cstate = cxl_get_hb_cstate(hb);
        if (!hb_cstate) {
            return NULL;
        }

        cache_mem = hb_cstate->crb.cache_mem_registers;

        target_found = adapter_hdm_find_target(cache_mem, addr, &target);
        if (!target_found) {
            return NULL;
        }

        rp = pcie_find_port_by_pn(hb->bus, target);
        if (!rp) {
            return NULL;
        }
    }

    d = pci_bridge_get_sec_bus(PCI_BRIDGE(rp))->devices[0];
    if (!d) {
        return NULL;
    }

    if (object_dynamic_cast(OBJECT(d), TYPE_CXL_TYPE3)) {
        return d;
    }

    /*
     * Could also be a switch.  Note only one level of switching currently
     * supported.
     */
    if (!object_dynamic_cast(OBJECT(d), TYPE_CXL_USP)) {
        return NULL;
    }
    usp = CXL_USP(d);

    usp_cstate = cxl_usp_to_cstate(usp);
    if (!usp_cstate) {
        return NULL;
    }

    cache_mem = usp_cstate->crb.cache_mem_registers;

    target_found = adapter_hdm_find_target(cache_mem, addr, &target);
    if (!target_found) {
        return NULL;
    }

    d = pcie_find_port_by_pn(&PCI_BRIDGE(d)->sec_bus, target);
    if (!d) {
        return NULL;
    }

    d = pci_bridge_get_sec_bus(PCI_BRIDGE(d))->devices[0];
    if (!d) {
        return NULL;
    }

    if (!object_dynamic_cast(OBJECT(d), TYPE_CXL_TYPE3)) {
        return NULL;
    }

    return d;
}

static PCIDevice *adapter_target(CXLFixedWindow *fw)
{
    PCIHostState *hb;
    PCIDevice *rp;

    if (fw->num_targets != 1) {
        return NULL;
    }
    hb = adapter_host(fw, 0);
    if (!hb || !hb->bus || !cxl_get_hb_passthrough(hb)) {
        return NULL;
    }
    rp = pcie_find_port_first(hb->bus);
    return rp ? pci_bridge_get_sec_bus(PCI_BRIDGE(rp))->devices[0] : NULL;
}

static bool adapter_topology(PCIDevice *dev, Error **errp)
{
    PCIBus *bus = pci_get_bus(dev);
    PCIDevice *rp = bus->parent_dev;
    GSList *windows = cxl_fmws_get_all_sorted();
    GSList *it;
    bool found = false;
    bool valid = rp && object_dynamic_cast(OBJECT(rp), "cxl-rp");

    for (it = windows; valid && it; it = it->next) {
        CXLFixedWindow *fw = CXL_FMW(it->data);
        unsigned i;

        for (i = 0; i < fw->num_targets; i++) {
            PCIHostState *hb = adapter_host(fw, i);

            if (hb && hb->bus == pci_get_bus(rp)) {
                found = true;
                valid = fw->num_targets == 1 && dev->devfn == 0;
                if (!valid) {
                    break;
                }
            }
        }
    }
    g_slist_free(windows);
    if (!valid || !found) {
        error_setg(errp, "FEMU requires a single-target window and an endpoint "
                   "directly below a CXL root port");
        return false;
    }
    return true;
}

/* FEMU accepts volatile media and non-interleaved endpoint decoders only. */
static bool adapter_translate(CXLType3Dev *dev, uint64_t hpa,
                               unsigned size, uint64_t *dpa)
{
    uint32_t *regs = dev->cxl_cstate.crb.cache_mem_registers;
    uint64_t base = 0;
    unsigned i;

    for (i = 0; i < CXL_HDM_DECODER_COUNT; i++) {
        uint32_t *r = regs + i * 8;
        uint32_t ctrl = ldl_le_p(r + R_CXL_HDM_DECODER0_CTRL);
        uint64_t start = (uint64_t)ldl_le_p(r +
                            R_CXL_HDM_DECODER0_BASE_HI) << 32 |
                        (ldl_le_p(r + R_CXL_HDM_DECODER0_BASE_LO) & 0xf0000000);
        uint64_t length = (uint64_t)ldl_le_p(r +
                            R_CXL_HDM_DECODER0_SIZE_HI) << 32 |
                         (ldl_le_p(r + R_CXL_HDM_DECODER0_SIZE_LO) &
                          0xf0000000);
        uint64_t skip = (uint64_t)ldl_le_p(r +
                            R_CXL_HDM_DECODER0_DPA_SKIP_HI) << 32 |
                       (ldl_le_p(r + R_CXL_HDM_DECODER0_DPA_SKIP_LO) &
                        0xf0000000);

        if (!FIELD_EX32(ctrl, CXL_HDM_DECODER0_CTRL, COMMITTED) ||
            FIELD_EX32(ctrl, CXL_HDM_DECODER0_CTRL, IW) ||
            skip > UINT64_MAX - base) {
            return false;
        }
        base += skip;
        if (hpa >= start && hpa - start < length) {
            uint64_t offset = hpa - start;
            uint64_t capacity = dev->cxl_dstate.vmem_size;

            if (offset > UINT64_MAX - base || base + offset >= capacity ||
                size > capacity - (base + offset)) {
                return false;
            }
            *dpa = base + offset;
            return true;
        }
        if (length > UINT64_MAX - base) {
            return false;
        }
        base += length;
    }
    return false;
}

#ifdef CONFIG_KVM
static bool adapter_linear(CXLType3Dev *dev, uint64_t base, uint64_t size)
{
    uint32_t *regs = dev->cxl_cstate.crb.cache_mem_registers;
    uint64_t cursor = base;
    unsigned i;

    if (size > UINT64_MAX - base) {
        return false;
    }
    for (i = 0; i < CXL_HDM_DECODER_COUNT && cursor < base + size; i++) {
        uint32_t *r = regs + i * 8;
        uint64_t start = (uint64_t)ldl_le_p(r +
                            R_CXL_HDM_DECODER0_BASE_HI) << 32 |
                        (ldl_le_p(r + R_CXL_HDM_DECODER0_BASE_LO) & 0xf0000000);
        uint64_t length = (uint64_t)ldl_le_p(r +
                            R_CXL_HDM_DECODER0_SIZE_HI) << 32 |
                         (ldl_le_p(r + R_CXL_HDM_DECODER0_SIZE_LO) &
                          0xf0000000);
        uint64_t dpa;

        if (cursor < start || cursor - start >= length) {
            continue;
        }
        if (!adapter_translate(dev, cursor, 1, &dpa) || dpa != cursor - base) {
            return false;
        }
        cursor += MIN(length - (cursor - start), base + size - cursor);
        if (!adapter_translate(dev, cursor - 1, 1, &dpa) ||
            dpa != cursor - 1 - base) {
            return false;
        }
    }
    return cursor == base + size;
}

#endif

typedef struct FemuCxlWindow {
    struct rcu_head rcu;
    CXLFixedWindow *fw;
    MemoryRegion io;
    QLIST_ENTRY(FemuCxlWindow) next;
} FemuCxlWindow;

static QLIST_HEAD(, FemuCxlWindow) adapter_windows =
    QLIST_HEAD_INITIALIZER(adapter_windows);
static unsigned adapter_users;

static MemTxResult adapter_access(FemuCxlWindow *w, hwaddr offset,
                                   uint64_t *data, unsigned size, bool write,
                                   MemTxAttrs attrs)
{
    PCIDevice *dev = adapter_route(w->fw, offset);
    FemuCxlMedia *s;
    CXLType3Dev *ct3d;
    uint64_t hpa = w->fw->base + offset;
    uint64_t dpa;
    uint64_t current_dpa;
    MemTxResult result = MEMTX_ERROR;

    if (!dev || !object_dynamic_cast(OBJECT(dev), TYPE_FEMU_CXL_SSD)) {
        return write ? memory_region_dispatch_write(&w->fw->mr, offset,
                            *data, size_memop(size), attrs) :
                       memory_region_dispatch_read(&w->fw->mr, offset,
                            data, size_memop(size), attrs);
    }
    ct3d = CXL_TYPE3(dev);
    s = &FEMU_CXL_SSD(dev)->media;
    if (!adapter_translate(ct3d, hpa, size, &dpa)) {
        return MEMTX_ERROR;
    }
    if (cxl_dev_media_disabled(&ct3d->cxl_dstate)) {
        if (!write) {
            qemu_guest_getrandom_nofail(data, size);
        }
        return MEMTX_OK;
    }
    /* Inject a decoder change between the two translation snapshots. */
    if (FEMU_CXL_SSD(dev)->test_change_dpa) {
        uint32_t *regs = ct3d->cxl_cstate.crb.cache_mem_registers;

        FEMU_CXL_SSD(dev)->test_change_dpa = false;
        stl_le_p(regs + R_CXL_HDM_DECODER0_DPA_SKIP_LO, 256 * MiB);
    }
    object_ref(OBJECT(dev));
    femu_cxl_enter(s);
    if (s->started && !s->closing && hpa == w->fw->base + offset &&
        adapter_route(w->fw, offset) == dev &&
        !cxl_dev_media_disabled(&ct3d->cxl_dstate) &&
        adapter_translate(ct3d, hpa, size, &current_dpa) &&
        current_dpa == dpa) {
        result = femu_cxl_access(s, hpa, dpa, data, size, write);
    }
    femu_cxl_leave(s);
    object_unref(OBJECT(dev));
    return result;
}

static MemTxResult adapter_read(void *opaque, hwaddr offset, uint64_t *data,
                                unsigned size, MemTxAttrs attrs)
{
    return adapter_access(opaque, offset, data, size, false, attrs);
}

static MemTxResult adapter_write(void *opaque, hwaddr offset, uint64_t data,
                                 unsigned size, MemTxAttrs attrs)
{
    return adapter_access(opaque, offset, &data, size, true, attrs);
}

static const MemoryRegionOps adapter_ops = {
    .read_with_attrs = adapter_read,
    .write_with_attrs = adapter_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 8, .unaligned = true },
    .impl = { .min_access_size = 1, .max_access_size = 8, .unaligned = true },
};

static void adapter_machine_done(Notifier *notifier, void *opaque)
{
    FemuCxlSsd *dev = container_of(notifier, FemuCxlSsd, machine_done);
    GSList *windows = cxl_fmws_get_all_sorted();
    GSList *it;

    dev->attached = true;
    adapter_users++;
    for (it = windows; it; it = it->next) {
        CXLFixedWindow *fw = CXL_FMW(it->data);
        FemuCxlWindow *w;
        bool found = false;

        QLIST_FOREACH(w, &adapter_windows, next) {
            if (w->fw == fw) {
                found = true;
                break;
            }
        }
        if (found) {
            continue;
        }
        w = g_new0(FemuCxlWindow, 1);
        w->fw = fw;
        memory_region_init_io(&w->io, OBJECT(fw), &adapter_ops, w,
                              "femu-cxl-media", fw->size);
        w->io.disable_reentrancy_guard = true;
        memory_region_add_subregion_overlap(&fw->mr, 0, &w->io, 0);
        QLIST_INSERT_HEAD(&adapter_windows, w, next);
    }
    g_slist_free(windows);
}

static void adapter_detach(FemuCxlSsd *dev)
{
    qemu_remove_machine_init_done_notifier(&dev->machine_done);
    if (dev->attached && !--adapter_users) {
        FemuCxlWindow *w;
        FemuCxlWindow *next;

        QLIST_FOREACH_SAFE(w, &adapter_windows, next, next) {
            memory_region_del_subregion(&w->fw->mr, &w->io);
            object_unparent(OBJECT(&w->io));
            QLIST_REMOVE(w, next);
            g_free_rcu(w, rcu);
        }
    }
    dev->attached = false;
}

static void cxl_invalidate(CXLType3Dev *ct3d)
{
    FemuCxlMedia *s = &FEMU_CXL_SSD(ct3d)->media;

    /*
     * The caller touches PCI state after this returns, so teardown waits for
     * waiters; once it starts, stop waiting for the operation it drains.
     */
    s->invalidation_waiters++;
    while (s->busy && !s->closing) {
        qemu_cond_wait_bql(&s->idle);
    }
    if (!s->busy) {
        s->busy = true;
        if (s->started) {
            femu_cxl_der_clear(&s->direct);
        }
        s->busy = false;
    }
    s->invalidation_waiters--;
    qemu_cond_broadcast(&s->idle);
}

static void adapter_config_write(PCIDevice *dev, uint32_t addr,
                                   uint32_t value, int size)
{
    object_ref(OBJECT(dev));
    cxl_invalidate(CXL_TYPE3(dev));
    parent_config_write(dev, addr, value, size);
    object_unref(OBJECT(dev));
}

static MemTxResult adapter_component_read(void *opaque, hwaddr offset,
                                          uint64_t *data, unsigned size,
                                          MemTxAttrs attrs)
{
    CXLType3Dev *dev = CXL_TYPE3(opaque);

    return memory_region_dispatch_read(&dev->cxl_cstate.crb.cache_mem,
                                       offset, data, size_memop(size), attrs);
}

static MemTxResult adapter_component_write(void *opaque, hwaddr offset,
                                           uint64_t data, unsigned size,
                                           MemTxAttrs attrs)
{
    CXLType3Dev *dev = CXL_TYPE3(opaque);
    MemTxResult result;

    object_ref(OBJECT(dev));
    cxl_invalidate(dev);
    result = memory_region_dispatch_write(&dev->cxl_cstate.crb.cache_mem,
                                         offset, data, size_memop(size), attrs);
    object_unref(OBJECT(dev));
    return result;
}

static const MemoryRegionOps adapter_component_ops = {
    .read_with_attrs = adapter_component_read,
    .write_with_attrs = adapter_component_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 8 },
    .impl = { .min_access_size = 4, .max_access_size = 8 },
};

static void adapter_pre_command(void *opaque)
{
    CXLCCI *cci = opaque;
    CXLType3Dev *dev = CXL_TYPE3(cci->d);
    uint64_t command = dev->cxl_dstate.mbox_reg_state64[R_CXL_DEV_MAILBOX_CMD];

    if (cci == &dev->cci && FEMU_CXL_SSD(dev)->media.lsa_control &&
        (command & 0xffff) == 0x4102) {
        FEMU_CXL_SSD(dev)->lsa_limit = cci->payload_max;
        return;
    }
    object_ref(OBJECT(dev));
    cxl_invalidate(dev);
    FEMU_CXL_SSD(dev)->lsa_limit = cci->payload_max;
    object_unref(OBJECT(dev));
}

static void adapter_cci_hook(CXLCCI *cci, CXLType3Dev *dev)
{
    cci->pre_command = adapter_pre_command;
    cci->pre_command_opaque = cci;
}

/* The upstream parent destroys only the primary mutex on exit. */
static void adapter_cci_dispose(CXLCCI *cci, bool parent_destroys)
{
    if (!cci->initialized) {
        return;
    }
    timer_free(cci->bg.timer);
    cci->bg.timer = NULL;
    if (cci->bg.runtime && cci->bg.opcode == 0x4402) {
        g_clear_pointer(&CXL_TYPE3(cci->d)->media_op_sanitize, g_free);
    }
    cci->bg.runtime = 0;
    if (!parent_destroys) {
        qemu_mutex_destroy(&cci->bg.lock);
        cci->initialized = false;
    }
}

static void adapter_reset_hold(Object *obj, ResetType type)
{
    CXLType3Dev *dev = CXL_TYPE3(obj);

    object_ref(obj);
    cxl_invalidate(dev);
    adapter_cci_dispose(&dev->cci, false);
    adapter_cci_dispose(&dev->vdm_fm_owned_ld_mctp_cci, false);
    adapter_cci_dispose(&dev->ld0_cci, false);
    if (parent_reset.hold) {
        parent_reset.hold(obj, type);
    }
    adapter_cci_hook(&dev->cci, dev);
    adapter_cci_hook(&dev->vdm_fm_owned_ld_mctp_cci, dev);
    adapter_cci_hook(&dev->ld0_cci, dev);
    object_unref(obj);
}

static void cxl_flush(Object *obj, bool value, Error **errp)
{
    FemuCxlMedia *s = &FEMU_CXL_SSD(obj)->media;

    object_ref(obj);
    femu_cxl_enter(s);
    if (!s->started || s->closing || !value) {
        goto out;
    }
    s->access_ns = 0;
    femu_cxl_der_clear(&s->direct);
    if (!femu_cxl_cache_clear(&s->cache, femu_cxl_evict, s)) {
        error_setg(errp, "CXL cache cannot flush: NAND is full");
    }
    s->cache_entries = g_hash_table_size(s->cache.entries);
    if (s->access_ns) {
        femu_cxl_delay(s->access_ns);
    }
out:
    femu_cxl_leave(s);
    object_unref(obj);
}

static void cxl_stats_reset(Object *obj, bool value, Error **errp)
{
    FemuCxlMedia *s = &FEMU_CXL_SSD(obj)->media;

    object_ref(obj);
    femu_cxl_enter(s);
    if (value) {
        s->snapshot[0] = s->read_hits;
        s->snapshot[1] = s->read_misses;
        s->snapshot[2] = s->write_hits;
        s->snapshot[3] = s->write_misses;
        s->snapshot[4] = s->cache.inserts;
        s->snapshot[5] = s->cache.evictions;
        s->snapshot[6] = s->cache_entries;
        s->snapshot[7] = s->prefetch_inserts;
        s->read_hits = s->read_misses = 0;
        s->write_hits = s->write_misses = 0;
        s->cache.hits = s->cache.misses = 0;
        s->cache.inserts = s->cache.evictions = 0;
        s->prefetch_inserts = 0;
    }
    femu_cxl_leave(s);
    object_unref(obj);
}

static void cxl_runtime_get(Object *obj, Visitor *v, const char *name,
                            void *opaque, Error **errp)
{
    FemuCxlMedia *s = &FEMU_CXL_SSD(obj)->media;
    uint32_t value = !strcmp(name, "cache-ways") ? s->cache_ways :
                     !strcmp(name, "prefetch-degree") ? s->prefetch_degree :
                     s->prefetch_stride;

    visit_type_uint32(v, name, &value, errp);
}

static void cxl_runtime_set(Object *obj, Visitor *v, const char *name,
                            void *opaque, Error **errp)
{
    FemuCxlMedia *s = &FEMU_CXL_SSD(obj)->media;
    uint32_t value;

    if (!visit_type_uint32(v, name, &value, errp)) {
        return;
    }
    object_ref(obj);
    femu_cxl_enter(s);
    if (!strcmp(name, "cache-ways")) {
        if (!value || (s->started && s->cache_pages &&
                       (value > s->cache_pages || s->cache_pages % value))) {
            error_setg(errp, "cache-ways must divide cache-pages");
            goto out;
        }
        if (s->started && !s->closing) {
            FemuCxlPolicy policy = s->cache.policy;
            FemuCxlCache previous;

            s->access_ns = 0;
            femu_cxl_der_clear(&s->direct);
            if (!femu_cxl_cache_clear(&s->cache, femu_cxl_evict, s)) {
                error_setg(errp, "CXL cache cannot rebuild: NAND is full");
                goto out;
            }
            previous = s->cache;
            femu_cxl_cache_destroy(&s->cache);
            femu_cxl_cache_init(&s->cache, s->cache_pages, value, policy);
            s->cache.hits = previous.hits;
            s->cache.misses = previous.misses;
            s->cache.inserts = previous.inserts;
            s->cache.evictions = previous.evictions;
            s->cache_entries = 0;
            if (s->access_ns) {
                femu_cxl_delay(s->access_ns);
            }
        }
        s->cache_ways = value;
    } else {
        uint64_t limit = s->started ? s->backend.size / 4096 :
                                     120 * GiB / 4096;

        if (value > limit) {
            error_setg(errp, "prefetch value exceeds media pages");
            goto out;
        }
        if (!strcmp(name, "prefetch-degree")) {
            s->prefetch_degree = value;
        } else {
            s->prefetch_stride = value;
        }
    }
out:
    femu_cxl_leave(s);
    object_unref(obj);
}

static FILE *cxl_log_open(FemuCxlMedia *s, const char *dir,
                          const char *name, const char *mode)
{
    g_autofree char *path = g_build_filename(dir && *dir ? dir : ".",
                                            name, NULL);
    FILE *file = fopen(path, mode);

    if (!file && !s->log_warned) {
        warn_report("CXL cannot open %s: %s", path, strerror(errno));
        s->log_warned = true;
    }
    return file;
}

static void cxl_command(Object *obj, uint64_t command, uint64_t argument,
                         Error **errp)
{
    FemuCxlMedia *s = &FEMU_CXL_SSD(obj)->media;
    FILE *file;

    if (!s->started || s->closing) {
        error_setg(errp, "CXL control requires a realized device");
        return;
    }
    switch (command) {
    case 2:
    case 9:
    case 11:
        cxl_flush(obj, true, errp);
        return;
    case 3:
        if (argument > 5) {
            error_setg(errp, "Cylon ways selector must be 0..5");
            return;
        }
        object_property_set_int(obj, "cache-ways",
                                argument == 5 ? s->cache_pages : 1 << argument,
                                errp);
        return;
    case 5:
    case 7:
        object_property_set_int(obj, command == 5 ? "prefetch-degree" :
                                "prefetch-stride", argument, errp);
        return;
    case 80:
    case 90:
        cxl_ratio(FEMU_CXL_SSD(obj), command == 80 ? 0 : argument, errp);
        return;
    }
    object_ref(obj);
    femu_cxl_enter(s);
    switch (command) {
    case 1:
        file = cxl_log_open(s, s->log_dir, "cxlssd-stats.log", "a");
        if (file) {
            fprintf(file, "tag=%" PRIu64 " read=%" PRIu64 "/%" PRIu64
                    " write=%" PRIu64 "/%" PRIu64 " insert=%" PRIu64
                    " evict=%" PRIu64 " entries=%" PRIu64
                    " prefetch=%" PRIu64 "\n", argument,
                    s->read_hits, s->read_misses, s->write_hits,
                    s->write_misses, s->cache.inserts, s->cache.evictions,
                    s->cache_entries, s->prefetch_inserts);
            fclose(file);
        }
        femu_cxl_leave(s);
        cxl_stats_reset(obj, true, errp);
        object_unref(obj);
        return;
    case 13:
        if (s->io_log) {
            fclose(s->io_log);
        }
        {
            g_autofree char *name = g_strdup_printf("cxlssd-io-%u.log",
                                                     ++s->log_sequence);

            s->io_log = cxl_log_open(s, s->log_dir, name, "w");
        }
        break;
    case 15:
        if (s->io_log) {
            fclose(s->io_log);
            s->io_log = NULL;
        }
        break;
    case 17:
        file = cxl_log_open(s, s->log_dir, "cxlssd-spt.log", "w");
        if (file) {
            cxl_dump_spt(&s->direct, file);
            fclose(file);
        }
        break;
    case 81:
    case 91:
        s->tracing = command == 91;
        trace_event_set_state_dynamic(
            trace_event_name("memory_region_ops_read"), s->tracing);
        trace_event_set_state_dynamic(
            trace_event_name("memory_region_ops_write"), s->tracing);
        if (s->tracefs_dir && *s->tracefs_dir) {
            file = cxl_log_open(s, s->tracefs_dir, "tracing_on", "w");
            if (file) {
                fprintf(file, "%u\n", s->tracing);
                fclose(file);
            }
        }
        break;
    default:
        error_setg(errp, "unknown CXL control command %" PRIu64, command);
        break;
    }
    femu_cxl_leave(s);
    object_unref(obj);
}

static void cxl_control_get(Object *obj, Visitor *v, const char *name,
                            void *opaque, Error **errp)
{
    FemuCxlMedia *s = &FEMU_CXL_SSD(obj)->media;
    uint64_t value = !strcmp(name, "der-ratio") ? s->direct.ratio :
                     !strcmp(name, "control-command") ? s->control_command :
                                                        s->control_argument;

    visit_type_uint64(v, name, &value, errp);
}

static void cxl_control_set(Object *obj, Visitor *v, const char *name,
                            void *opaque, Error **errp)
{
    FemuCxlMedia *s = &FEMU_CXL_SSD(obj)->media;
    uint64_t value;
    Error *local_err = NULL;

    if (!visit_type_uint64(v, name, &value, errp)) {
        return;
    }
    if (!strcmp(name, "der-ratio")) {
        if (!s->started || s->closing) {
            error_setg(errp, "der-ratio requires a realized device");
            return;
        }
        cxl_ratio(FEMU_CXL_SSD(obj), value, errp);
        return;
    }
    if (!strcmp(name, "control-argument")) {
        s->control_argument = value;
        return;
    }
    s->control_command = value;
    cxl_command(obj, value, s->control_argument, &local_err);
    s->control_status = local_err != NULL;
    error_propagate(errp, local_err);
}

static uint64_t cxl_lsa_size(CXLType3Dev *dev)
{
    return FEMU_CXL_SSD(dev)->media.lsa_control ? FEMU_CXL_LSA_SIZE :
                                               parent_lsa_size(dev);
}

static uint64_t cxl_get_lsa(CXLType3Dev *dev, void *buf, uint64_t size,
                           uint64_t offset)
{
    FemuCxlMedia *s = &FEMU_CXL_SSD(dev)->media;
    Error *err = NULL;

    if (size > FEMU_CXL_SSD(dev)->lsa_limit) {
        s->control_status = 1;
        return 0;
    }
    if (!size) {
        return 0;
    }
    if (!s->lsa_control) {
        return parent_get_lsa(dev, buf, size, offset);
    }
    if (!size || offset >= FEMU_CXL_LSA_SIZE ||
        size > FEMU_CXL_LSA_SIZE - offset) {
        return 0;
    }
    s->control_command = size;
    s->control_argument = offset;
    cxl_command(OBJECT(dev), size, offset, &err);
    s->control_status = err != NULL;
    error_free(err);
    memcpy(buf, s->labels + offset, size);
    ((uint8_t *)buf)[0] = s->control_status;
    return size;
}

static void cxl_set_lsa(CXLType3Dev *dev, const void *buf, uint64_t size,
                       uint64_t offset)
{
    FemuCxlMedia *s = &FEMU_CXL_SSD(dev)->media;

    if (!s->lsa_control) {
        if (size) {
            parent_set_lsa(dev, buf, size, offset);
        }
    } else if (offset < FEMU_CXL_LSA_SIZE &&
               size <= FEMU_CXL_LSA_SIZE - offset) {
        memcpy(s->labels + offset, buf, size);
    }
}

static void cxl_realize(PCIDevice *dev, Error **errp)
{
    FemuCxlMedia *s = &FEMU_CXL_SSD(dev)->media;
    CXLType3Dev *ct3d = CXL_TYPE3(dev);
    FemuCxlPolicy policy;
    MemoryRegion *mr;
    Error *local_err = NULL;
    uint64_t size;

    if (s->der && strcmp(s->der, "off") && strcmp(s->der, "memslot") &&
        strcmp(s->der, "cylon")) {
        error_setg(errp, "der must be off, memslot or cylon");
        return;
    }
    if (s->der && !strcmp(s->der, "cylon") && !s->cylon_kernel_ack) {
        error_setg(errp, "der=cylon requires cylon-kernel-ack=on after "
                   "reviewing the host dual-mode leaf lifetime fix");
        return;
    }
    if (!ct3d->hostvmem || ct3d->hostmem || ct3d->hostpmem ||
        ct3d->dc.num_regions || ct3d->dc.host_dc ||
        (ct3d->lsa && s->lsa_control)) {
        error_setg(errp, "femu-cxl-ssd requires only volatile-memdev");
        return;
    }
    mr = host_memory_backend_get_memory(ct3d->hostvmem);
    if (!mr || host_memory_backend_is_mapped(ct3d->hostvmem)) {
        error_setg(errp, "volatile memory backend cannot be used "
                   "multiple times");
        return;
    }
    size = memory_region_size(mr);
    if (!size || size % (256 * MiB) || size > 120 * GiB) {
        error_setg(errp, "CXL media size must be a multiple of 256 MiB, "
                   "at most 120 GiB");
        return;
    }
    if (s->prefetch_degree > size / 4096 ||
        s->prefetch_stride > size / 4096) {
        error_setg(errp, "prefetch value exceeds media pages");
        return;
    }
    if (!s->cache_ways || s->cache_ways > size / 4096 ||
        (s->cache_pages && (s->cache_pages % s->cache_ways ||
                           s->cache_pages > size / 4096))) {
        error_setg(errp, "cache-pages must fit the media and be divisible by "
                   "cache-ways");
        return;
    }
    if (!femu_cxl_policy(s->cache_policy ? s->cache_policy : "fifo", &policy)) {
        error_setg(errp, "cache-policy must be fifo, lifo, clock or s3-fifo");
        return;
    }
    if (s->read_ns > NANOSECONDS_PER_SECOND ||
        s->program_ns > NANOSECONDS_PER_SECOND ||
        s->erase_ns > NANOSECONDS_PER_SECOND) {
        error_setg(errp, "NAND timing must be at most one second");
        return;
    }
    if (!femu_cxl_geometry(s, size, errp) ||
        !adapter_topology(dev, errp)) {
        return;
    }
    parent_realize(dev, &local_err);
    if (local_err) {
        host_memory_backend_set_mapped(ct3d->hostvmem, false);
        error_propagate(errp, local_err);
        return;
    }
    if (s->lsa_control) {
        s->labels = g_malloc0(FEMU_CXL_LSA_SIZE);
    }
    femu_cxl_start(s, memory_region_get_ram_ptr(mr), size, policy);
    femu_cxl_der_init(&s->direct, FEMU_CXL_SSD(dev), s->der, &s->cache);
    s->closing = false;
    s->started = true;
    memory_region_init_io(&FEMU_CXL_SSD(dev)->component_overlay, OBJECT(dev),
                          &adapter_component_ops, ct3d, "femu-cxl-component",
                          CXL2_COMPONENT_CM_REGION_SIZE);
    FEMU_CXL_SSD(dev)->component_overlay.disable_reentrancy_guard = true;
    memory_region_add_subregion_overlap(&ct3d->cxl_cstate.crb.cache_mem, 0,
                           &FEMU_CXL_SSD(dev)->component_overlay, 1);
    adapter_cci_hook(&ct3d->cci, ct3d);
    FEMU_CXL_SSD(dev)->machine_done.notify = adapter_machine_done;
    qemu_add_machine_init_done_notifier(&FEMU_CXL_SSD(dev)->machine_done);
}

static void cxl_exit(PCIDevice *dev)
{
    FemuCxlMedia *s = &FEMU_CXL_SSD(dev)->media;

    /* Callers of cxl_invalidate() finish under the BQL before we proceed. */
    s->closing = true;
    qemu_cond_broadcast(&s->idle);
    while (s->busy || s->invalidation_waiters) {
        qemu_cond_wait_bql(&s->idle);
    }
    s->busy = true;
    femu_cxl_der_destroy(&s->direct);
    femu_cxl_stop(s);
    g_clear_pointer(&s->labels, g_free);
    if (s->io_log) {
        fclose(s->io_log);
        s->io_log = NULL;
    }
    adapter_detach(FEMU_CXL_SSD(dev));
    memory_region_del_subregion(&CXL_TYPE3(dev)->cxl_cstate.crb.cache_mem,
                                &FEMU_CXL_SSD(dev)->component_overlay);
    object_unparent(OBJECT(&FEMU_CXL_SSD(dev)->component_overlay));
    adapter_cci_dispose(&CXL_TYPE3(dev)->cci, true);
    adapter_cci_dispose(&CXL_TYPE3(dev)->vdm_fm_owned_ld_mctp_cci, false);
    adapter_cci_dispose(&CXL_TYPE3(dev)->ld0_cci, false);
    parent_exit(dev);
    host_memory_backend_set_mapped(CXL_TYPE3(dev)->hostvmem, false);
    femu_cxl_leave(s);
}

static bool cxl_der_active(Object *obj, Error **errp)
{
    return FEMU_CXL_SSD(obj)->media.direct.available;
}

/* Exercise the real listener allocator without a custom kernel or guest. */
static bool adapter_reservation_test(Object *obj, Error **errp)
{
#ifdef CONFIG_KVM
    typedef struct SlotTestRegion {
        struct rcu_head rcu;
        MemoryRegion mr;
    } SlotTestRegion;
    KVMSlotReservation *first;
    KVMSlotReservation *next;
    KVMSlotReservation *again;
    SlotTestRegion *test;
    unsigned free_before;
    unsigned id;
    bool result;

    if (!kvm_enabled()) {
        return false;
    }
    free_before = kvm_get_free_memslots();
    first = kvm_reserve_memslot();
    if (!first) {
        return false;
    }
    id = kvm_reserved_memslot_id(first);
    test = g_new0(SlotTestRegion, 1);
    memory_region_init_ram(&test->mr, obj, "femu-slot-test", 4096,
                           &error_abort);
    memory_region_add_subregion(get_system_memory(), 8 * GiB, &test->mr);
    next = kvm_reserve_memslot();
    result = next && kvm_reserved_memslot_id(next) == id + 2 &&
             kvm_get_free_memslots() == free_before - 3;
    kvm_release_memslot(first);
    again = kvm_reserve_memslot();
    result = result && again && kvm_reserved_memslot_id(again) == id;
    if (again) {
        kvm_release_memslot(again);
    }
    if (next) {
        kvm_release_memslot(next);
    }
    memory_region_del_subregion(get_system_memory(), &test->mr);
    object_unparent(OBJECT(&test->mr));
    g_free_rcu(test, rcu);
    return result && kvm_get_free_memslots() == free_before;
#else
    return false;
#endif
}

static void adapter_test_change_dpa(Object *obj, bool value, Error **errp)
{
    FEMU_CXL_SSD(obj)->test_change_dpa = value;
}

static void cxl_init(Object *obj)
{
    FemuCxlMedia *s = &FEMU_CXL_SSD(obj)->media;

    if (qtest_driver()) {
        object_property_add_bool(obj, "test-change-dpa", NULL,
                                 adapter_test_change_dpa);
        object_property_add_bool(obj, "test-slot-reservation",
                                 adapter_reservation_test, NULL);
    }
    FEMU_CXL_SSD(obj)->lsa_limit = CXL_MAILBOX_MAX_PAYLOAD_SIZE;
    qemu_cond_init(&s->idle);
    s->der = g_strdup("off");
    object_property_add(obj, "der-ratio", "uint64", cxl_control_get,
                        cxl_control_set, NULL, NULL);
    object_property_add(obj, "control-command", "uint64", cxl_control_get,
                        cxl_control_set, NULL, NULL);
    object_property_add(obj, "control-argument", "uint64", cxl_control_get,
                        cxl_control_set, NULL, NULL);
    object_property_add_uint64_ptr(obj, "control-status", &s->control_status,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "last-read-hits", &s->snapshot[0],
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "last-read-misses", &s->snapshot[1],
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "last-write-hits", &s->snapshot[2],
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "last-write-misses", &s->snapshot[3],
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "last-inserts", &s->snapshot[4],
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "last-evictions", &s->snapshot[5],
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "last-entries", &s->snapshot[6],
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "last-prefetch-inserts",
                                   &s->snapshot[7],
                                   OBJ_PROP_FLAG_READ);
    s->cache_ways = 16;
    s->prefetch_stride = 1;
    object_property_add(obj, "cache-ways", "uint32", cxl_runtime_get,
                        cxl_runtime_set, NULL, NULL);
    object_property_add(obj, "prefetch-degree", "uint32", cxl_runtime_get,
                        cxl_runtime_set, NULL, NULL);
    object_property_add(obj, "prefetch-stride", "uint32", cxl_runtime_get,
                        cxl_runtime_set, NULL, NULL);
    object_property_add_bool(obj, "stats-reset", NULL, cxl_stats_reset);
    object_property_add_uint64_ptr(obj, "prefetch-inserts",
                                   &s->prefetch_inserts,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "cache-entries", &s->cache_entries,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "write-misses", &s->write_misses,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "write-hits", &s->write_hits,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "read-misses", &s->read_misses,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "read-hits", &s->read_hits,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "invalidation-waiters",
                                   &s->invalidation_waiters,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_bool(obj, "der-active", cxl_der_active, NULL);
    object_property_add_uint64_ptr(obj, "der-remaps", &s->direct.remaps,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "der-revocations",
                                   &s->direct.revocations, OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "der-fallbacks", &s->direct.fallbacks,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_bool(obj, "flush-cache", NULL, cxl_flush);
    object_property_add_uint64_ptr(obj, "der-probes", &s->direct.probes,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "der-mapped", &s->direct.mapped,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "media-time-ns", &s->media_ns,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "media-reads", &s->media_reads,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "media-writes", &s->media_writes,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "cache-hits", &s->cache.hits,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "cache-misses", &s->cache.misses,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "cache-inserts", &s->cache.inserts,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "cache-evictions", &s->cache.evictions,
                                   OBJ_PROP_FLAG_READ);
}

static const Property cxl_props[] = {
    DEFINE_PROP_UINT32("cache-pages", FemuCxlSsd, media.cache_pages, 1024),
    DEFINE_PROP_STRING("cache-policy", FemuCxlSsd, media.cache_policy),
    DEFINE_PROP_BOOL("lsa-control", FemuCxlSsd, media.lsa_control, false),
    DEFINE_PROP_STRING("log-dir", FemuCxlSsd, media.log_dir),
    DEFINE_PROP_STRING("tracefs-dir", FemuCxlSsd, media.tracefs_dir),
    DEFINE_PROP_BOOL("ftl", FemuCxlSsd, media.ftl, true),
    DEFINE_PROP_BOOL("cylon-first-touch-program", FemuCxlSsd,
                     media.first_touch_program, false),
    DEFINE_PROP_BOOL("cylon-free-writeback", FemuCxlSsd,
                     media.free_writeback, false),
    DEFINE_PROP_UINT32("channels", FemuCxlSsd, media.channels, 4),
    DEFINE_PROP_UINT32("luns-per-channel", FemuCxlSsd,
                       media.luns_per_channel, 4),
    DEFINE_PROP_UINT32("blocks-per-plane", FemuCxlSsd,
                       media.blocks_per_plane, 0),
    DEFINE_PROP_UINT32("pages-per-block", FemuCxlSsd,
                       media.pages_per_block, 256),
    DEFINE_PROP_UINT32("gc-threshold", FemuCxlSsd, media.gc_threshold, 75),
    DEFINE_PROP_UINT32("gc-threshold-high", FemuCxlSsd,
                       media.gc_threshold_high, 95),
    DEFINE_PROP_UINT64("channel-ns", FemuCxlSsd, media.channel_ns, 0),
    DEFINE_PROP_STRING("der", FemuCxlSsd, media.der),
    DEFINE_PROP_BOOL("cylon-kernel-ack", FemuCxlSsd,
                     media.cylon_kernel_ack, false),
    DEFINE_PROP_UINT64("read-ns", FemuCxlSsd, media.read_ns, 40000),
    DEFINE_PROP_UINT64("program-ns", FemuCxlSsd, media.program_ns, 200000),
    DEFINE_PROP_UINT64("erase-ns", FemuCxlSsd, media.erase_ns, 2000000),
};

static const VMStateDescription cxl_vmstate = {
    .name = TYPE_FEMU_CXL_SSD,
    .unmigratable = true,
};

static void cxl_class_init(ObjectClass *oc, const void *data)
{
    CXLType3Class *cvc = CXL_TYPE3_CLASS(oc);
    PCIDeviceClass *pc = PCI_DEVICE_CLASS(oc);
    DeviceClass *dc = DEVICE_CLASS(oc);
    ResettableClass *rc = RESETTABLE_CLASS(oc);

    parent_lsa_size = cvc->get_lsa_size;
    parent_get_lsa = cvc->get_lsa;
    parent_set_lsa = cvc->set_lsa;
    cvc->get_lsa_size = cxl_lsa_size;
    cvc->get_lsa = cxl_get_lsa;
    cvc->set_lsa = cxl_set_lsa;
    parent_realize = pc->realize;
    parent_exit = pc->exit;
    pc->realize = cxl_realize;
    pc->exit = cxl_exit;
    dc->desc = "FEMU CXL SSD";
    dc->vmsd = &cxl_vmstate;
    device_class_set_props(dc, cxl_props);
    parent_config_write = pc->config_write;
    pc->config_write = adapter_config_write;
    resettable_class_set_parent_phases(rc, NULL, adapter_reset_hold, NULL,
                                      &parent_reset);
}

static void cxl_finalize(Object *obj)
{
    qemu_cond_destroy(&FEMU_CXL_SSD(obj)->media.idle);
}

static const TypeInfo cxl_info = {
    .name = TYPE_FEMU_CXL_SSD,
    .parent = TYPE_CXL_TYPE3,
    .instance_size = sizeof(FemuCxlSsd),
    .instance_init = cxl_init,
    .instance_finalize = cxl_finalize,
    .class_init = cxl_class_init,
};

static void cxl_register_types(void)
{
    type_register_static(&cxl_info);
}

type_init(cxl_register_types);

typedef struct FemuCxlMap {
    uint64_t lpn;
    uint64_t pages;
    MemoryRegion mr;
    MemoryRegion *container;
} FemuCxlMap;

void femu_cxl_der_fallback(FemuCxlDer *der, const char *reason)
{
    der->available = false;
    der->fallbacks++;
    if (!der->warned) {
        der->warned = true;
        warn_report("FEMU CXL DER unavailable: %s; using MMIO", reason);
    }
}

void femu_cxl_der_init(FemuCxlDer *der, FemuCxlSsd *dev, const char *mode,
                       FemuCxlCache *cache)
{
    const char *reason = NULL;

    der->dev = dev;
    der->cache = cache;
    der->maps = g_hash_table_new(g_int64_hash, g_int64_equal);
    der->cylon = mode && !strcmp(mode, "cylon");
    if (der->cylon) {
        der->probes++;
        der->fast = femu_cylon_prepare(der, &reason);
        if (!der->fast) {
            femu_cxl_der_fallback(der, reason);
        }
    } else {
        der->available = mode && !strcmp(mode, "memslot");
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
    uint32_t *regs = der->dev->parent_obj.cxl_cstate.crb.cache_mem_registers;
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
        if (hb->bus == pci_get_bus(rp) && cxl_get_hb_passthrough(hb) &&
            adapter_target(fw) == PCI_DEVICE(der->dev)) {
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

    if (der->ratio && !femu_cxl_ratio_selected(der->ratio, lpn)) {
        return false;
    }
    if ((!der->available && !der->fast) || (hpa & 4095) != (dpa & 4095)) {
        return false;
    }
    if (!der->cylon && g_hash_table_contains(der->maps, &lpn)) {
        return true;
    }
    fw = der_window(der, hpa);
    if (!fw) {
        der->fallbacks++;
        return false;
    }
    if (der->cylon) {
        return femu_cylon_map(der, fw, hpa, dpa);
    }
#ifdef CONFIG_KVM
    /* Leave room for splits in the KVM listener's existing regions. */
    if (kvm_enabled() && kvm_get_free_memslots() < 8) {
        der->fallbacks++;
        return false;
    }
#endif
    ram = host_memory_backend_get_memory(der->dev->parent_obj.hostvmem);
    map = g_new0(FemuCxlMap, 1);
    map->lpn = lpn;
    map->pages = 1;
    map->container = &fw->mr;
    memory_region_init_alias(&map->mr, OBJECT(der->dev), "femu-cxl-hit",
                              ram, lpn * 4096, 4096);
    /* QEMU owns slot allocation, revocation and TLB invalidation. */
    memory_region_add_subregion_overlap(map->container,
                      (hpa & ~4095ULL) - fw->base, &map->mr, 1);
    g_hash_table_insert(der->maps, &map->lpn, map);
    der->mapped++;
    der->remaps++;
    return true;
}

static void cxl_ratio(FemuCxlSsd *dev, uint64_t ratio, Error **errp)
{
    FemuCxlMedia *s = &dev->media;
    FemuCxlDer *der = &s->direct;
    GSList *windows;
    GSList *it;
    CXLFixedWindow *fw = NULL;
    uint64_t lpn;
    uint64_t pages = s->backend.size / 4096;

    switch (ratio) {
    case 0:
    case 50:
    case 75:
    case 90:
    case 95:
    case 97:
    case 98:
    case 99:
    case 100:
    case 995:
    case 999:
        break;
    default:
        error_setg(errp, "unsupported Cylon direct ratio");
        return;
    }
    object_ref(OBJECT(dev));
    femu_cxl_enter(s);
    if (der->cylon) {
        cylon_ratio_revoke(der);
    } else {
        femu_cxl_der_clear(der);
    }
    der->ratio = ratio;
    if (!ratio || (!der->available && !der->fast)) {
        goto out;
    }
    windows = cxl_fmws_get_all_sorted();
    for (it = windows; it; it = it->next) {
        CXLFixedWindow *candidate = CXL_FMW(it->data);

        if (der_window(der, candidate->base) == candidate &&
            adapter_linear(&dev->parent_obj, candidate->base,
                           s->backend.size)) {
            fw = candidate;
            break;
        }
    }
    g_slist_free(windows);
    if (!fw) {
        error_setg(errp, "DER ratio requires a decoded linear window");
        der->ratio = 0;
        goto out;
    }
    if (der->cylon) {
        cylon_ratio_apply(der, fw);
        goto out;
    }
    for (lpn = 0; lpn < pages; lpn++) {
        if (!femu_cxl_ratio_selected(ratio, lpn)) {
            continue;
        }
        {
            uint64_t end = lpn + 1;
            FemuCxlMap *map;
            MemoryRegion *ram;

#ifdef CONFIG_KVM
            if (kvm_enabled() && kvm_get_free_memslots() < 8) {
                der->fallbacks++;
                break;
            }
#endif
            while (end < pages && femu_cxl_ratio_selected(ratio, end)) {
                end++;
            }
            ram = host_memory_backend_get_memory(dev->parent_obj.hostvmem);
            map = g_new0(FemuCxlMap, 1);
            map->lpn = lpn;
            map->pages = end - lpn;
            map->container = &fw->mr;
            memory_region_init_alias(&map->mr, OBJECT(dev), "femu-cxl-ratio",
                                      ram, lpn * 4096, map->pages * 4096);
            memory_region_add_subregion_overlap(&fw->mr, lpn * 4096,
                                                 &map->mr, 1);
            g_hash_table_insert(der->maps, &map->lpn, map);
            der->mapped += map->pages;
            der->remaps += map->pages;
            lpn = end - 1;
        }
    }
out:
    femu_cxl_leave(s);
    object_unref(OBJECT(dev));
}

void femu_cxl_der_remove(FemuCxlDer *der, uint64_t lpn)
{
    FemuCxlMap *map = g_hash_table_lookup(der->maps, &lpn);

    if (der->cylon) {
        femu_cylon_remove(der, lpn);
        return;
    }
    if (!map) {
        return;
    }
    memory_region_del_subregion(map->container, &map->mr);
    g_hash_table_remove(der->maps, &lpn);
    object_unparent(OBJECT(&map->mr));
    der->mapped -= map->pages;
    der->revocations += map->pages;
    g_free(map);
}

void femu_cxl_der_clear(FemuCxlDer *der)
{
    GHashTableIter it;
    gpointer key;

    if (der->cylon) {
        femu_cylon_clear(der);
        return;
    }
    while (g_hash_table_size(der->maps)) {
        g_hash_table_iter_init(&it, der->maps);
        g_hash_table_iter_next(&it, &key, NULL);
        femu_cxl_der_remove(der, *(uint64_t *)key);
    }
}

void femu_cxl_der_destroy(FemuCxlDer *der)
{
    femu_cxl_der_clear(der);
    femu_cylon_destroy(der);
    der->available = false;
    g_hash_table_destroy(der->maps);
}

#ifdef CONFIG_KVM
#include <linux/kvm.h>
#include <linux/magic.h>
#include <sys/vfs.h>
#include <sys/mman.h>

#include "spt.h"
#define KVM_CYLON_DUAL_MODE (1U << 17)
#define CYLON_PAGEMAP_PRESENT (UINT64_C(1) << 63)
#define CYLON_PAGEMAP_PFN ((UINT64_C(1) << 55) - 1)

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
    CylonLinearSpt spt_list[CYLON_SPT_CHUNKS];
    void *backend_ptr;
    uint64_t gfn;
    int n;
} CylonGetLinearSpt;

#define CYLON_SET_SPTE_FLAG _IOW(KVMIO, 0xdd, CylonSpteFlag)
#define CYLON_GET_LINEAR_SPT _IOWR(KVMIO, 0xde, CylonGetLinearSpt)

typedef struct CylonPage {
    uint64_t lpn;
    uint64_t mmio;
    uint64_t *sptep;
} CylonPage;

struct FemuCylon {
    struct rcu_head rcu;
    FemuCxlDer *der;
    CXLFixedWindow *pending_window;
    bool detached;
    int pagemap;
    KVMSlotReservation *reservation;
    MemoryListener listener;
    uint64_t generation;
    uint64_t pending_generation;
    bool installing;
    CXLFixedWindow *window;
    CylonGetLinearSpt spt;
    void *areas[CYLON_SPT_CHUNKS];
    uint64_t area_sizes[CYLON_SPT_CHUNKS];
    uint64_t size;
    uint64_t huge_size;
    uint64_t *huge;
    void *ram;
    bool installed;
    bool locked;
    bool failed;
    bool batch;
};

static void cylon_listener_begin(MemoryListener *listener);
static void cylon_listener_commit(MemoryListener *listener);
static bool cylon_log_start(MemoryListener *listener, Error **errp);

static bool cylon_coverage(FemuCylon *c, CXLFixedWindow *fw)
{
    FemuCxlWindow *w;
    bool found = false;

    if (fw->size != c->size || adapter_target(fw) != PCI_DEVICE(c->der->dev) ||
        !adapter_linear(&c->der->dev->parent_obj, fw->base, fw->size)) {
        return false;
    }
    QLIST_FOREACH(w, &adapter_windows, next) {
        if (w->fw == fw) {
            MemoryRegionSection section = memory_region_find(
                get_system_memory(), fw->base, fw->size);

            found = section.mr == &w->io && !section.readonly &&
                    section.offset_within_region == 0 &&
                    int128_eq(section.size, int128_make64(fw->size));
            if (section.mr) {
                memory_region_unref(section.mr);
            }
            break;
        }
    }
    return found;
}

static bool cylon_flush(uint64_t gpa)
{
    CylonSpteFlag flag = { .gpa = gpa };
    CPUState *cpu = first_cpu;

    return cpu && !kvm_vcpu_ioctl(cpu, CYLON_SET_SPTE_FLAG, &flag);
}

static bool cylon_parameter(const char *path)
{
    g_autofree char *value = NULL;

    return g_file_get_contents(path, &value, NULL, NULL) &&
           (value[0] == 'Y' || value[0] == '1');
}

static void cylon_release(FemuCylon *c)
{
    unsigned i;

    if (c->installed) {
        struct kvm_userspace_memory_region region = {
            .slot = kvm_reserved_memslot_id(c->reservation),
        };
        int ret = kvm_vm_ioctl(kvm_state, KVM_SET_USER_MEMORY_REGION, &region);

        if (ret) {
            error_report("FEMU cannot delete external KVM slot: %s",
                         strerror(-ret));
            abort();
        }
        c->installed = false;
    }
    c->der->available = false;
    for (i = 0; i < CYLON_SPT_CHUNKS; i++) {
        if (c->areas[i]) {
            munmap(c->areas[i], c->area_sizes[i]);
            c->areas[i] = NULL;
        }
    }
    memset(&c->spt, 0, sizeof(c->spt));
}

static FemuCylon *femu_cylon_prepare(FemuCxlDer *der, const char **reason)
{
    CylonGetLinearSpt probe = { .gfn = UINT64_MAX };
    HostMemoryBackend *backend = der->dev->parent_obj.hostvmem;
    MemoryRegion *mr = host_memory_backend_get_memory(backend);
    struct statfs fs;
    FemuCylon *c;
    uint64_t count;
    uint64_t i;
    int fd;
    int get_result;
    bool set_result;

    *reason = "Cylon GET_LINEAR_SPT/SET_SPTE_FLAG require a Cylon KVM host";
    if (!kvm_enabled() || qemu_real_host_page_size() != CYLON_PAGE_SIZE) {
        return NULL;
    }
    *reason = "Cylon external slots cannot use dirty-ring logging";
    if (kvm_dirty_ring_enabled()) {
        return NULL;
    }
    *reason = "Cylon GET_LINEAR_SPT/SET_SPTE_FLAG require a Cylon KVM host";
    get_result = kvm_vm_ioctl(kvm_state, CYLON_GET_LINEAR_SPT, &probe);
    set_result = cylon_flush(UINT64_MAX & ~(CYLON_PAGE_SIZE - 1));
    if (get_result != -EINVAL || !set_result) {
        return NULL;
    }
    *reason = "Cylon requires Intel EPT, EPT A/D and the TDP MMU";
    if (!cylon_parameter("/sys/module/kvm_intel/parameters/ept") ||
        !cylon_parameter("/sys/module/kvm_intel/parameters/eptad") ||
        !cylon_parameter("/sys/module/kvm/parameters/tdp_mmu") ||
        !cylon_parameter("/sys/module/kvm/parameters/mmio_caching")) {
        return NULL;
    }
    *reason = "Cylon requires shared, preallocated hugetlb backing";
    fd = memory_region_get_fd(mr);
    if (!backend->share || !backend->prealloc || fd < 0 ||
        fstatfs(fd, &fs) || fs.f_type != HUGETLBFS_MAGIC) {
        return NULL;
    }
    c = g_new0(FemuCylon, 1);
    c->pagemap = -1;
    c->der = der;
    c->size = memory_region_size(mr);
    c->ram = memory_region_get_ram_ptr(mr);
    c->huge_size = host_memory_backend_pagesize(backend);
    if (c->huge_size < CYLON_PAGE_SIZE ||
        (c->huge_size & (c->huge_size - 1)) ||
        c->size % c->huge_size || (uintptr_t)c->ram % c->huge_size) {
        goto fail;
    }
    *reason = "Cylon cannot lock the hugetlb backing (check memlock limit)";
    if (mlock(c->ram, c->size)) {
        goto fail;
    }
    c->locked = true;
    *reason = "Cylon needs readable, present nonzero pagemap PFNs "
              "(CAP_SYS_ADMIN)";
    fd = open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        goto fail;
    }
    count = c->size / c->huge_size;
    c->huge = g_new0(uint64_t, count);
    for (i = 0; i < count; i++) {
        uint64_t entry;
        uint64_t pa;
        off_t offset = ((uintptr_t)c->ram + i * c->huge_size) /
                       CYLON_PAGE_SIZE * sizeof(entry);

        if (pread(fd, &entry, sizeof(entry), offset) != sizeof(entry) ||
            !(entry & CYLON_PAGEMAP_PRESENT) ||
            !(entry & CYLON_PAGEMAP_PFN) ||
            (entry & CYLON_PAGEMAP_PFN) > CYLON_ADDR_MASK / CYLON_PAGE_SIZE) {
            close(fd);
            goto fail;
        }
        c->huge[i] = (entry & CYLON_PAGEMAP_PFN) * CYLON_PAGE_SIZE;
        if (!cylon_page_address(c->huge, count, c->huge_size,
                               i * c->huge_size, &pa)) {
            close(fd);
            goto fail;
        }
    }
    c->pagemap = fd;
    c->listener.begin = cylon_listener_begin;
    c->listener.commit = cylon_listener_commit;
    c->listener.log_global_start = cylon_log_start;
    c->listener.name = "femu-cxl-external-slot";
    c->listener.priority = 20;
    der->fast = c;
    memory_listener_register(&c->listener, &address_space_memory);
    return c;
fail:
    if (c->locked) {
        munlock(c->ram, c->size);
    }
    g_free(c->huge);
    g_free(c);
    return NULL;
}

static bool cylon_install(FemuCxlDer *der, CXLFixedWindow *fw)
{
    FemuCylon *c = der->fast;
    uint64_t bytes = c->size / CYLON_PAGE_SIZE * sizeof(uint64_t);
    uint64_t covered = 0;
    unsigned i;

    if (!cylon_coverage(c, fw) || kvm_get_free_memslots() < 8 ||
        DIV_ROUND_UP(bytes, CYLON_SPT_CHUNK_SIZE) > CYLON_SPT_CHUNKS) {
        return false;
    }
    c->window = fw;
    for (i = 0; i < DIV_ROUND_UP(bytes, CYLON_SPT_CHUNK_SIZE); i++) {
        uint64_t length = cylon_spt_area_size(bytes, i);
        void *area = cylon_spt_area(length);

        if (area == MAP_FAILED) {
            return false;
        }
        c->areas[i] = area;
        c->area_sizes[i] = length;
        c->spt.spt_list[i].spt = area;
    }
    if (!c->reservation) {
        c->reservation = kvm_reserve_memslot();
        if (!c->reservation) {
            return false;
        }
    }
    {
        struct kvm_userspace_memory_region region = {
            .slot = kvm_reserved_memslot_id(c->reservation),
            .flags = KVM_CYLON_DUAL_MODE,
            .guest_phys_addr = fw->base,
            .memory_size = c->size,
            .userspace_addr = (uintptr_t)c->ram,
        };

        if (kvm_vm_ioctl(kvm_state, KVM_SET_USER_MEMORY_REGION, &region)) {
            return false;
        }
    }
    c->installed = true;
    c->spt.gfn = fw->base / CYLON_PAGE_SIZE;
    if (kvm_vm_ioctl(kvm_state, CYLON_GET_LINEAR_SPT, &c->spt) ||
        c->spt.n <= 0 || c->spt.n > CYLON_SPT_CHUNKS) {
        return false;
    }
    for (i = 0; i < c->spt.n; i++) {
        CylonLinearSpt *part = &c->spt.spt_list[i];

        if (part->spt != c->areas[i] ||
            (uint64_t)part->npages * CYLON_PAGE_SIZE != c->area_sizes[i] ||
            !cylon_spt_chunk(part->offset, part->npages, bytes, &covered) ||
            !cylon_spt_mapped(c->areas[i], c->area_sizes[i])) {
            return false;
        }
    }
    if (covered != bytes) {
        return false;
    }
    der->available = true;
    return true;
}

static uint64_t *cylon_sptep(FemuCylon *c, uint64_t index)
{
    unsigned i;

    if (!c->installed || index >= c->size / CYLON_PAGE_SIZE ||
        !c->reservation) {
        return NULL;
    }
    for (i = 0; i < c->spt.n; i++) {
        CylonLinearSpt *part = &c->spt.spt_list[i];
        uint64_t first = (uint64_t)part->offset * 512;
        uint64_t entries = (uint64_t)part->npages * 512;

        if (index >= first && index - first < entries) {
            return part->spt + index - first;
        }
    }
    return NULL;
}

static void cylon_fail(FemuCxlDer *der)
{
    FemuCylon *c = der->fast;
    GHashTableIter it;
    gpointer value;

    g_hash_table_iter_init(&it, der->maps);
    while (g_hash_table_iter_next(&it, NULL, &value)) {
        CylonPage *page = value;
        FemuCxlEntry *entry = g_hash_table_lookup(der->cache->entries,
                                                 &page->lpn);

        if (entry) {
            entry->dirty = true;
        }
        if (page->sptep == cylon_sptep(c, page->lpn)) {
            uint64_t old = qatomic_read(page->sptep);

            while (!cylon_spte_revoked(old) &&
                   !cylon_spte_install(page->sptep, old, page->mmio)) {
                old = qatomic_read(page->sptep);
            }
            cylon_flush(c->window->base + page->lpn * CYLON_PAGE_SIZE);
        }
        der->revocations++;
        g_hash_table_iter_remove(&it);
        g_free(page);
    }
    der->mapped = 0;
    c->failed = true;
    cylon_release(c);
    femu_cxl_der_fallback(der, "Cylon slot, SPT bounds or ioctl failure");
}

/* Slot publication precedes aux initialization in the host kernel. */
static void cylon_install_bh(void *opaque)
{
    FemuCylon *c = opaque;

    pause_all_vcpus();
    if (!c->detached && !c->failed &&
        c->generation == c->pending_generation &&
        cylon_coverage(c, c->pending_window) &&
        !cylon_install(c->der, c->pending_window)) {
        cylon_fail(c->der);
    }
    object_unref(OBJECT(c->pending_window));
    c->installing = false;
    if (!c->detached && c->installed) {
        if (c->der->ratio) {
            cylon_ratio_apply(c->der, c->window);
        } else {
            GHashTableIter it;
            gpointer key;

            g_hash_table_iter_init(&it, c->der->cache->entries);
            while (c->installed && g_hash_table_iter_next(&it, &key, NULL)) {
                uint64_t lpn = *(uint64_t *)key;

                femu_cylon_map(c->der, c->window,
                               c->window->base + lpn * 4096, lpn * 4096);
            }
        }
    }
    resume_all_vcpus();
    if (c->detached) {
        g_free_rcu(c, rcu);
    }
}

static void cylon_drop(FemuCxlDer *der, CylonPage *page, bool dirty)
{
    FemuCxlEntry *entry = g_hash_table_lookup(der->cache->entries,
                                             &page->lpn);

    if (entry && dirty) {
        entry->dirty = true;
    }
    /* A kernel zap can be visible before its remote flush has completed. */
    if (dirty && !cylon_flush(der->fast->window->base +
                              page->lpn * CYLON_PAGE_SIZE)) {
        cylon_fail(der);
        return;
    }
    g_hash_table_remove(der->maps, &page->lpn);
    g_free(page);
    der->mapped--;
    der->revocations++;
}

/* Detect migration already visible at admission; this cannot pin a PFN. */
static bool cylon_pfn_current(FemuCylon *c, uint64_t dpa)
{
    uint64_t index = dpa / c->huge_size;
    uint64_t entry;
    off_t offset = ((uintptr_t)c->ram + index * c->huge_size) /
                   CYLON_PAGE_SIZE * sizeof(entry);

    return pread(c->pagemap, &entry, sizeof(entry), offset) == sizeof(entry) &&
           (entry & CYLON_PAGEMAP_PRESENT) &&
           (entry & CYLON_PAGEMAP_PFN) * CYLON_PAGE_SIZE == c->huge[index];
}

static bool femu_cylon_map(FemuCxlDer *der, CXLFixedWindow *fw,
                    uint64_t hpa, uint64_t dpa)
{
    FemuCylon *c = der->fast;
    uint64_t index;
    uint64_t pa;
    uint64_t *sptep = NULL;
    uint64_t old;
    CylonPage *page;

    if (!c || c->failed || c->installing) {
        return false;
    }
    if (hpa < fw->base || hpa - fw->base != dpa ||
        !cylon_page_index(dpa, c->size, c->size / CYLON_PAGE_SIZE, &index) ||
        !cylon_page_address(c->huge, c->size / c->huge_size, c->huge_size,
                            index * CYLON_PAGE_SIZE, &pa)) {
        cylon_fail(der);
        return false;
    }
    if (!cylon_pfn_current(c, dpa)) {
        cylon_fail(der);
        return false;
    }
    if (!c->installed) {
        c->installing = true;
        c->pending_window = fw;
        c->pending_generation = c->generation;
        object_ref(OBJECT(fw));
        aio_bh_schedule_oneshot(qemu_get_aio_context(), cylon_install_bh, c);
        return false;
    }
    if (c->window != fw || !c->reservation) {
        cylon_fail(der);
        return false;
    }
    sptep = cylon_sptep(c, index);
    if (!sptep) {
        cylon_fail(der);
        return false;
    }
    old = qatomic_read(sptep);
    page = g_hash_table_lookup(der->maps, &index);
    if (page && page->sptep == sptep && cylon_spte_revoked(old)) {
        cylon_drop(der, page, true);
        return false;
    }
    if (page) {
        if (page->sptep != sptep ||
            (old & ~CYLON_EPT_DIRTY) != cylon_direct_spte(pa)) {
            cylon_fail(der);
            return false;
        }
        return true;
    }
    /* Empty leaves can be restored to zero without guessing a generation. */
    if (old == CYLON_REMOVED_SPTE) {
        return false;
    }
    if (old && ((old & 7) != CYLON_MMIO_VALUE ||
                (old & CYLON_MMU_PRESENT))) {
        cylon_fail(der);
        return false;
    }
    if (!cylon_spte_install(sptep, old, cylon_direct_spte(pa))) {
        return false;
    }
    page = g_new0(CylonPage, 1);
    page->lpn = index;
    page->mmio = old;
    page->sptep = sptep;
    g_hash_table_insert(der->maps, &page->lpn, page);
    der->mapped++;
    if (!c->batch && !cylon_flush(hpa & ~(CYLON_PAGE_SIZE - 1))) {
        cylon_fail(der);
        return false;
    }
    der->remaps++;
    return true;
}

static void cylon_ratio_apply(FemuCxlDer *der, CXLFixedWindow *fw)
{
    FemuCylon *c = der->fast;
    uint64_t lpn;

    if (!c || c->failed) {
        return;
    }
    if (!c->installed) {
        femu_cylon_map(der, fw, fw->base, 0);
        return;
    }
    c->batch = true;
    for (lpn = 0; c->installed && lpn < c->size / 4096; lpn++) {
        if (femu_cxl_ratio_selected(der->ratio, lpn)) {
            femu_cylon_map(der, fw, fw->base + lpn * 4096, lpn * 4096);
        }
    }
    c->batch = false;
    if (c->installed && !cylon_flush(fw->base)) {
        cylon_fail(der);
    }
}

static void cylon_remove_page(FemuCxlDer *der, uint64_t lpn)
{
    CylonPage *page = g_hash_table_lookup(der->maps, &lpn);
    FemuCylon *c = der->fast;
    FemuCxlEntry *entry;
    uint64_t old;
    uint64_t gpa;
    uint64_t pa;

    if (!page) {
        return;
    }
    if (page->sptep != cylon_sptep(c, lpn) ||
        !cylon_page_address(c->huge, c->size / c->huge_size, c->huge_size,
                            lpn * CYLON_PAGE_SIZE, &pa)) {
        cylon_fail(der);
        return;
    }
    old = qatomic_read(page->sptep);
    if (cylon_spte_revoked(old)) {
        cylon_drop(der, page, true);
        return;
    }
    if ((old & ~CYLON_EPT_DIRTY) != cylon_direct_spte(pa)) {
        cylon_fail(der);
        return;
    }
    gpa = c->window->base + lpn * CYLON_PAGE_SIZE;
    /* Stop hardware and fast-fault writes before sampling D. */
    while (!cylon_spte_install(page->sptep, old, cylon_spte_readonly(old))) {
        old = qatomic_read(page->sptep);
        if (cylon_spte_revoked(old)) {
            cylon_drop(der, page, true);
            return;
        }
        if ((old & ~CYLON_EPT_DIRTY) != cylon_direct_spte(pa)) {
            cylon_fail(der);
            return;
        }
    }
    if (!cylon_flush(gpa)) {
        cylon_fail(der);
        return;
    }
    old = qatomic_read(page->sptep);
    while (!cylon_spte_revoked(old)) {
        if ((old & ~CYLON_EPT_DIRTY) !=
            cylon_spte_readonly(cylon_direct_spte(pa))) {
            cylon_fail(der);
            return;
        }
        if (cylon_spte_install(page->sptep, old, page->mmio)) {
            break;
        }
        old = qatomic_read(page->sptep);
    }
    entry = g_hash_table_lookup(der->cache->entries, &lpn);
    if (entry && ((old & CYLON_EPT_DIRTY) || !(old & CYLON_MMU_PRESENT))) {
        entry->dirty = true;
    }
    if (!cylon_flush(gpa)) {
        cylon_fail(der);
        return;
    }
    cylon_drop(der, page, false);
}

static void cylon_ratio_revoke(FemuCxlDer *der)
{
    while (g_hash_table_size(der->maps)) {
        GHashTableIter it;
        gpointer key;

        g_hash_table_iter_init(&it, der->maps);
        g_hash_table_iter_next(&it, &key, NULL);
        cylon_remove_page(der, *(uint64_t *)key);
    }
}

static void femu_cylon_clear(FemuCxlDer *der)
{
    FemuCylon *c = der->fast;

    if (!c) {
        return;
    }
    c->generation++;
    while (g_hash_table_size(der->maps)) {
        GHashTableIter it;
        gpointer key;

        g_hash_table_iter_init(&it, der->maps);
        g_hash_table_iter_next(&it, &key, NULL);
        cylon_remove_page(der, *(uint64_t *)key);
    }
    cylon_release(c);
}

static void femu_cylon_remove(FemuCxlDer *der, uint64_t lpn)
{
    femu_cylon_clear(der);
}

/* Delete before the KVM listener can expose overlapping RAM. */
static void cylon_listener_begin(MemoryListener *listener)
{
    FemuCylon *c = container_of(listener, FemuCylon, listener);

    femu_cylon_clear(c->der);
}

static void cylon_listener_commit(MemoryListener *listener)
{
    FemuCylon *c = container_of(listener, FemuCylon, listener);

    if (c->window && !c->detached && !c->failed && !c->installing &&
        cylon_coverage(c, c->window)) {
        femu_cylon_map(c->der, c->window, c->window->base, 0);
    }
}

static bool cylon_log_start(MemoryListener *listener, Error **errp)
{
    FemuCylon *c = container_of(listener, FemuCylon, listener);

    femu_cylon_clear(c->der);
    c->failed = true;
    femu_cxl_der_fallback(c->der, "external slots cannot track dirty logging");
    return true;
}

static void femu_cylon_destroy(FemuCxlDer *der)
{
    FemuCylon *c = der->fast;

    if (c) {
        c->detached = true;
        memory_listener_unregister(&c->listener);
        cylon_release(c);
        if (c->reservation) {
            kvm_release_memslot(c->reservation);
        }
        if (c->locked) {
            munlock(c->ram, c->size);
        }
        g_free(c->huge);
        close(c->pagemap);
        if (!c->installing) {
            g_free_rcu(c, rcu);
        }
        der->fast = NULL;
    }
}
#else
static void cylon_ratio_apply(FemuCxlDer *der, CXLFixedWindow *fw)
{
}

static void cylon_ratio_revoke(FemuCxlDer *der)
{
}

static FemuCylon *femu_cylon_prepare(FemuCxlDer *der, const char **reason)
{
    *reason = "Cylon requires KVM";
    return NULL;
}

static bool femu_cylon_map(FemuCxlDer *der, CXLFixedWindow *fw,
                    uint64_t hpa, uint64_t dpa)
{
    return false;
}

static void femu_cylon_remove(FemuCxlDer *der, uint64_t lpn)
{
}

static void femu_cylon_destroy(FemuCxlDer *der)
{
}
static void femu_cylon_clear(FemuCxlDer *der)
{
}
#endif

static void cxl_dump_spt(FemuCxlDer *der, FILE *file)
{
    GHashTableIter it;
    gpointer value;

    fprintf(file, "mode=%s ratio=%" PRIu64 " mapped=%" PRIu64 "\n",
            der->cylon ? "cylon" : "memslot", der->ratio, der->mapped);
    g_hash_table_iter_init(&it, der->maps);
    while (g_hash_table_iter_next(&it, NULL, &value)) {
#ifdef CONFIG_KVM
        if (der->cylon) {
            CylonPage *page = value;

            fprintf(file, "lpn=%" PRIu64 " spte=%016" PRIx64 "\n",
                    page->lpn, qatomic_read(page->sptep));
        } else
#endif
        {
            FemuCxlMap *map = value;

            fprintf(file, "lpn=%" PRIu64 " pages=%" PRIu64 "\n",
                    map->lpn, map->pages);
        }
    }
}
