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
#include "system/tcg.h"
#include "migration/vmstate.h"
#include "../bbssd/ftl.h"
#include "cache.h"
#include "qemu-adapter.h"
#include "../femu-props.h"

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

OBJECT_DECLARE_SIMPLE_TYPE(FemuCxlSsd, FEMU_CXL_SSD)

struct FemuCxlSsd {
    CXLType3Dev parent_obj;
    FemuCxlMedia media;
    MemoryRegion component_overlay;
    Notifier machine_done;
    bool attached;
    bool test_change_dpa;
    bool test_media_disabled;
    size_t lsa_limit;
    /* Get LSA control commands left to a bottom half, oldest first. */
    GQueue lsa_queue;
    bool lsa_running;
};

typedef struct FemuCxlLsaCommand {
    uint64_t command;
    uint64_t argument;
} FemuCxlLsaCommand;

/* Get LSA byte 0 for a command left to run after the read returns. */
#define FEMU_CXL_LSA_QUEUED 2

static void (*parent_realize)(PCIDevice *dev, Error **errp);
static void (*parent_exit)(PCIDevice *dev);
static void (*parent_config_write)(PCIDevice *, uint32_t, uint32_t, int);
static ResettablePhases parent_reset;
static uint64_t (*parent_lsa_size)(CXLType3Dev *);
static uint64_t (*parent_get_lsa)(CXLType3Dev *, void *, uint64_t, uint64_t);
static void (*parent_set_lsa)(CXLType3Dev *, const void *, uint64_t, uint64_t);
static void cxl_dump_spt(FemuCxlDer *der, FILE *file, uint64_t limit);
static void cxl_ratio(FemuCxlSsd *dev, uint64_t ratio, Error **errp);
static void cxl_ratio_restore(FemuCxlSsd *dev, Error **errp);
static void cylon_ratio_revoke(FemuCxlDer *der);
static void cylon_ratio_apply(FemuCxlDer *der, CXLFixedWindow *fw);

#define FEMU_CXL_LSA_SIZE (128 * MiB)
#define FEMU_CXL_IO_LOGS 64
/* Statistics appends a guest can cause: a burst, then this many a second. */
#define FEMU_CXL_STATS_BURST 64
#define FEMU_CXL_STATS_RATE 100
/*
 * Each alias and the MMIO gap beside it are separate sections, and a
 * dispatch map holds fewer than 4096 sections for the whole address space.
 */
#define FEMU_CXL_DER_ALIASES 1024
/*
 * An alias add or removal rebuilds the flat view, about a millisecond with
 * a full budget, and a KVM slot deletion kicks every vCPU. A page must have
 * spent that much in MMIO exits before it may displace a mapping.
 */
#define FEMU_CXL_DER_HOT 256
/*
 * A displaced page coming back means churn and doubles the interval, up to
 * 256 times; it halves again only after a run of new hot pages.
 */
#define FEMU_CXL_DER_BACKOFF 8
#define FEMU_CXL_DER_CLEAN 8

static FemuCylon *femu_cylon_prepare(FemuCxlDer *der, const char **reason);
static bool femu_cylon_map(FemuCxlDer *der, CXLFixedWindow *fw,
                           uint64_t hpa, uint64_t dpa);
static void femu_cylon_remove(FemuCxlDer *der, uint64_t lpn);
static void femu_cylon_destroy(FemuCxlDer *der);
static void femu_cylon_clear(FemuCxlDer *der);
static void femu_cylon_reset(FemuCxlDer *der);
static bool femu_cylon_sample(FemuCxlDer *der, uint64_t lpn);


/* Resolve by path only until machine-init-done has linked the targets. */
static PCIHostState *adapter_host(CXLFixedWindow *fw, unsigned index)
{
    Object *obj = fw->target_hbs[index] ? OBJECT(fw->target_hbs[index]) :
                  object_resolve_path_type(fw->targets[index],
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
        /* The list holds eight targets; a guest can program more ways. */
        if (target_idx >= 8) {
            return false;
        }

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

/* Whether a target host bridge of @fw is above @dev, even across a switch. */
static bool adapter_reaches(CXLFixedWindow *fw, PCIDevice *dev)
{
    unsigned i;

    for (i = 0; i < fw->num_targets; i++) {
        PCIHostState *hb = adapter_host(fw, i);
        PCIBus *bus = pci_get_bus(dev);

        while (hb && bus) {
            if (bus == hb->bus) {
                return true;
            }
            bus = bus->parent_dev ? pci_get_bus(bus->parent_dev) : NULL;
        }
    }
    return false;
}

/*
 * HPA to DPA through the endpoint decoders, including interleave, as
 * cxl_type3_dpa() does; an invalid way encoding fails the access instead
 * of exiting. The whole access must fall inside the volatile capacity.
 */
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
        unsigned iw = FIELD_EX32(ctrl, CXL_HDM_DECODER0_CTRL, IW);
        unsigned ig = FIELD_EX32(ctrl, CXL_HDM_DECODER0_CTRL, IG);
        int ways = cxl_interleave_ways_dec(iw, NULL);
        uint64_t capacity = dev->cxl_dstate.vmem_size;
        uint64_t offset;
        uint64_t local;

        if (!FIELD_EX32(ctrl, CXL_HDM_DECODER0_CTRL, COMMITTED) || !ways ||
            skip > UINT64_MAX - base) {
            return false;
        }
        base += skip;
        if (hpa < start || hpa - start >= length) {
            if (length / ways > UINT64_MAX - base) {
                return false;
            }
            base += length / ways;
            continue;
        }
        offset = hpa - start;
        if (iw < 8) {
            local = (offset & MAKE_64BIT_MASK(0, 8 + ig)) |
                    ((offset & MAKE_64BIT_MASK(8 + ig + iw,
                                               64 - 8 - ig - iw)) >> iw);
        } else {
            local = (offset & MAKE_64BIT_MASK(0, 8 + ig)) |
                    ((((offset & MAKE_64BIT_MASK(ig + iw, 64 - ig - iw)) >>
                       (ig + iw)) / 3) << (ig + 8));
        }
        if (local > UINT64_MAX - base || base + local >= capacity ||
            size > capacity - (base + local)) {
            return false;
        }
        *dpa = base + local;
        return true;
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
    uint64_t hpa = w->fw->base + offset;

    for (;;) {
        PCIDevice *dev = adapter_route(w->fw, offset);
        FemuCxlMedia *s;
        CXLType3Dev *ct3d;
        uint64_t dpa;
        MemTxResult result;
        bool shared;

        /*
         * Nothing decodes the address: answer as the window would, without
         * letting its own router see decoder values that make it assert.
         */
        if (!dev) {
            if (!write) {
                *data = 0;
            }
            return write ? MEMTX_OK : MEMTX_ERROR;
        }
        if (!object_dynamic_cast(OBJECT(dev), TYPE_FEMU_CXL_SSD)) {
            return write ? memory_region_dispatch_write(&w->fw->mr, offset,
                                *data, size_memop(size) | MO_LE, attrs) :
                           memory_region_dispatch_read(&w->fw->mr, offset,
                                data, size_memop(size) | MO_LE, attrs);
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
        /* Inject a decoder change while this access waits for the gate. */
        if (FEMU_CXL_SSD(dev)->test_change_dpa) {
            uint32_t *regs = ct3d->cxl_cstate.crb.cache_mem_registers;

            FEMU_CXL_SSD(dev)->test_change_dpa = false;
            stl_le_p(regs + R_CXL_HDM_DECODER0_DPA_SKIP_LO, 256 * MiB);
        }
        object_ref(OBJECT(dev));
        shared = femu_cxl_concurrent(s);
        if (shared) {
            femu_cxl_enter_access(s);
        } else {
            femu_cxl_enter(s);
        }
        /* Decoders may have changed while waiting; complete as they are now. */
        if (adapter_route(w->fw, offset) != dev) {
            if (shared) {
                femu_cxl_leave_access(s);
            } else {
                femu_cxl_leave(s);
            }
            object_unref(OBJECT(dev));
            continue;
        }
        if (!s->started || s->closing ||
            !adapter_translate(ct3d, hpa, size, &dpa)) {
            result = MEMTX_ERROR;
        } else if (cxl_dev_media_disabled(&ct3d->cxl_dstate)) {
            if (!write) {
                qemu_guest_getrandom_nofail(data, size);
            }
            result = MEMTX_OK;
        } else {
            /* Invalidation revoked a memslot ratio; map it again first. */
            if (s->direct.ratio && !s->direct.cylon && !s->direct.ratio_end) {
                cxl_ratio_restore(FEMU_CXL_SSD(dev), NULL);
            }
            result = femu_cxl_access(s, hpa, dpa, data, size, write);
        }
        if (shared) {
            femu_cxl_leave_access(s);
        } else {
            femu_cxl_leave(s);
        }
        object_unref(OBJECT(dev));
        return result;
    }
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

        /* Other windows never route here; leave their accesses untouched. */
        if (!adapter_reaches(fw, PCI_DEVICE(dev))) {
            continue;
        }
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

/*
 * Callers run inside another owner's dispatch guard, so never wait here.
 * Revoke now; an access in flight sees the new generation and does not
 * install a mapping it translated before the change.
 */
static void cxl_invalidate(CXLType3Dev *ct3d)
{
    FemuCxlMedia *s = &FEMU_CXL_SSD(ct3d)->media;

    s->invalidations++;
    if (s->started) {
        femu_cxl_der_clear(&s->direct);
    }
}

static void adapter_config_write(PCIDevice *dev, uint32_t addr,
                                   uint32_t value, int size)
{
    cxl_invalidate(CXL_TYPE3(dev));
    parent_config_write(dev, addr, value, size);
}

static MemTxResult adapter_component_read(void *opaque, hwaddr offset,
                                          uint64_t *data, unsigned size,
                                          MemTxAttrs attrs)
{
    CXLType3Dev *dev = CXL_TYPE3(opaque);

    return memory_region_dispatch_read(&dev->cxl_cstate.crb.cache_mem, offset,
                                       data, size_memop(size) | MO_LE, attrs);
}

static MemTxResult adapter_component_write(void *opaque, hwaddr offset,
                                           uint64_t data, unsigned size,
                                           MemTxAttrs attrs)
{
    CXLType3Dev *dev = CXL_TYPE3(opaque);

    cxl_invalidate(dev);
    return memory_region_dispatch_write(&dev->cxl_cstate.crb.cache_mem, offset,
                                        data, size_memop(size) | MO_LE, attrs);
}

static const MemoryRegionOps adapter_component_ops = {
    .read_with_attrs = adapter_component_read,
    .write_with_attrs = adapter_component_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 8 },
    .impl = { .min_access_size = 4, .max_access_size = 8 },
};

static void adapter_pre_command(void *opaque, uint8_t set, uint8_t cmd)
{
    CXLCCI *cci = opaque;
    CXLType3Dev *dev = CXL_TYPE3(cci->d);

    /* Get LSA carries a control command, not a configuration change. */
    if (cci == &dev->cci && FEMU_CXL_SSD(dev)->media.lsa_control &&
        (set << 8 | cmd) == 0x4102) {
        FEMU_CXL_SSD(dev)->lsa_limit = cci->payload_max;
        return;
    }
    cxl_invalidate(dev);
    FEMU_CXL_SSD(dev)->lsa_limit = cci->payload_max;
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

    cxl_invalidate(dev);
    femu_cylon_reset(&FEMU_CXL_SSD(dev)->media.direct);
    /* A reboot loses the library state behind pins and uncached ranges. */
    femu_cxl_cca_reset(&FEMU_CXL_SSD(dev)->media, CCA_RESET_ALL);
    adapter_cci_dispose(&dev->cci, false);
    adapter_cci_dispose(&dev->vdm_fm_owned_ld_mctp_cci, false);
    adapter_cci_dispose(&dev->ld0_cci, false);
    if (parent_reset.hold) {
        parent_reset.hold(obj, type);
    }
    adapter_cci_hook(&dev->cci, dev);
    adapter_cci_hook(&dev->vdm_fm_owned_ld_mctp_cci, dev);
    adapter_cci_hook(&dev->ld0_cci, dev);
}

static void cxl_flush(Object *obj, bool value, Error **errp)
{
    FemuCxlMedia *s = &FEMU_CXL_SSD(obj)->media;
    FemuCxlOp op = { .s = s };

    object_ref(obj);
    femu_cxl_enter(s);
    if (!s->started || s->closing || !value) {
        goto out;
    }
    femu_cxl_der_clear(&s->direct);
    /* Pinned pages are written back but stay resident. */
    if (!femu_cxl_cache_clear(&s->cache, femu_cxl_evict, &op) ||
        !femu_cxl_cache_clean_pinned(&s->cache, femu_cxl_evict, &op)) {
        error_setg(errp, "CXL cache cannot flush: NAND is full");
    }
    s->cache_entries = g_hash_table_size(s->cache.entries);
    cxl_ratio_restore(FEMU_CXL_SSD(obj), errp);
    if (op.ns) {
        femu_cxl_delay(op.ns);
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
        femu_cxl_cca_stats_reset(&s->cca);
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
            /* Refuse before anything is flushed if pins cannot follow. */
            if (!femu_cxl_cache_pins_fit(&s->cache, s->cache_pages, value)) {
                error_setg(errp, "pinned pages do not fit %u cache ways",
                           value);
                goto out;
            }
            FemuCxlOp op = { .s = s };

            femu_cxl_der_clear(&s->direct);
            if (!femu_cxl_cache_clear(&s->cache, femu_cxl_evict, &op) ||
                !femu_cxl_cache_clean_pinned(&s->cache, femu_cxl_evict, &op)) {
                error_setg(errp, "CXL cache cannot rebuild: NAND is full");
                goto out;
            }
            /* Pinned pages never left DRAM; they return without media cost. */
            femu_cxl_cache_rebuild(&s->cache, s->cache_pages, value);
            s->cache_entries = g_hash_table_size(s->cache.entries);
            cxl_ratio_restore(FEMU_CXL_SSD(obj), errp);
            if (op.ns) {
                femu_cxl_delay(op.ns);
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

    /* Warn once per file so one bad path does not hide another. */
    if (!file) {
        if (!s->log_warned) {
            s->log_warned = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                  g_free, NULL);
        }
        if (g_hash_table_add(s->log_warned, g_strdup(path))) {
            warn_report("CXL cannot open %s: %s", path, strerror(errno));
        }
    }
    return file;
}

/*
 * Open the statistics log for one append, or refuse and count it when the
 * guest has used up its token bucket or the file is at its limit.
 */
static FILE *cxl_stats_open(FemuCxlMedia *s)
{
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    uint64_t refill;
    FILE *file;
    long size;

    if (!s->stats_last) {
        s->stats_tokens = FEMU_CXL_STATS_BURST;
        s->stats_last = now;
    }
    refill = (now - s->stats_last) * FEMU_CXL_STATS_RATE /
             NANOSECONDS_PER_SECOND;
    if (refill) {
        s->stats_tokens = MIN(s->stats_tokens + refill, FEMU_CXL_STATS_BURST);
        s->stats_last = now;
    }
    if (!s->stats_tokens) {
        s->log_dropped++;
        return NULL;
    }
    file = cxl_log_open(s, s->log_dir, "cxlssd-stats.log", "a");
    if (!file) {
        return NULL;
    }
    size = fseek(file, 0, SEEK_END) ? -1 : ftell(file);
    if (size < 0 || size >= s->log_limit) {
        fclose(file);
        s->log_dropped++;
        return NULL;
    }
    s->stats_tokens--;
    return file;
}

static const char *cxl_policy_name(FemuCxlPolicy policy)
{
    static const char *const names[] = {
        [FEMU_CXL_FIFO] = "FIFO",
        [FEMU_CXL_LIFO] = "LIFO",
        [FEMU_CXL_CLOCK] = "CLOCK",
        [FEMU_CXL_S3FIFO] = "S3FIFO",
    };

    return names[policy];
}

/* Cylon's cxlssd_buffer.txt header, so its parsers read FEMU output too. */
static void cxl_stats_header(FemuCxlMedia *s, FILE *file, uint64_t tag)
{
    fprintf(file, "NAND size: %" PRIu64 " MB, Buffer size: %u MB, "
            "eviction: %s, prefetch: %u, way: %u, == %" PRIu64 " ==\n",
            s->backend.size / MiB, s->cache_pages / 256,
            cxl_policy_name(s->cache.policy), s->prefetch_degree,
            s->cache_ways, tag);
}

/* Record a Cylon settings change in the statistics file. */
static void cxl_stats_note(Object *obj, uint64_t command, uint64_t argument)
{
    FemuCxlMedia *s = &FEMU_CXL_SSD(obj)->media;
    FILE *file = cxl_stats_open(s);

    if (!file) {
        return;
    }
    if (command == 3) {
        fprintf(file, "[Set way] eviction: %s, prefetch: %u, way: %u\n",
                cxl_policy_name(s->cache.policy), s->prefetch_degree,
                s->cache_ways);
    } else {
        /* Cylon's exact bytes, including the space before the newline. */
        fprintf(file, "[Set %s]\x20\n\t",
                command == 5 ? "degree" : "stride");
        cxl_stats_header(s, file, argument);
    }
    fclose(file);
}

/* Cylon's buffer_clear drops these counters along with the cache. */
static void cxl_counters_clear(Object *obj)
{
    FemuCxlMedia *s = &FEMU_CXL_SSD(obj)->media;

    object_ref(obj);
    femu_cxl_enter(s);
    s->read_hits = s->read_misses = 0;
    s->write_hits = s->write_misses = 0;
    s->cache.hits = s->cache.misses = 0;
    s->cache.inserts = s->cache.evictions = 0;
    femu_cxl_leave(s);
    object_unref(obj);
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
        if (!s->closing) {
            cxl_counters_clear(obj);
        }
        return;
    case 3:
        if (argument > 5) {
            error_setg(errp, "Cylon ways selector must be 0..5");
            return;
        }
        if (object_property_set_int(obj, "cache-ways",
                                    argument == 5 ? s->cache_pages :
                                    1 << argument, errp) && !s->closing) {
            cxl_counters_clear(obj);
            cxl_stats_note(obj, command, argument);
        }
        return;
    case 5:
    case 7:
        if (object_property_set_int(obj, command == 5 ? "prefetch-degree" :
                                    "prefetch-stride", argument, errp)) {
            cxl_stats_note(obj, command, argument);
        }
        return;
    case 80:
    case 90:
        /* Cylon's command 90 maps every page for argument zero. */
        cxl_ratio(FEMU_CXL_SSD(obj),
                  command == 80 ? 0 : argument ? argument : 100, errp);
        return;
    }
    object_ref(obj);
    femu_cxl_enter(s);
    if (!s->started || s->closing) {
        error_setg(errp, "CXL control requires a realized device");
        femu_cxl_leave(s);
        object_unref(obj);
        return;
    }
    switch (command) {
    case 1:
        file = cxl_stats_open(s);
        if (file) {
            cxl_stats_header(s, file, argument);
            fprintf(file, "Entry cnt: %" PRIu64 "/%u\n", s->cache_entries,
                    s->cache_pages);
            fprintf(file, "Buffer read: %" PRIu64 " hit/ %" PRIu64 " miss\n",
                    s->read_hits, s->read_misses);
            fprintf(file, "Buffer write: %" PRIu64 " hit/ %" PRIu64 " miss\n",
                    s->write_hits, s->write_misses);
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
            /*
             * Reuse a bounded set of names, each capped at log-limit, so
             * runs cannot fill a disk.
             */
            g_autofree char *name = g_strdup_printf("cxlssd-io-%u.log",
                                s->log_sequence++ % FEMU_CXL_IO_LOGS + 1);

            s->io_log = NULL;
            s->io_log_bytes = 0;
            if (s->log_limit) {
                s->io_log = cxl_log_open(s, s->log_dir, name, "w");
            } else {
                s->log_dropped++;
            }
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
            cxl_dump_spt(&s->direct, file, s->log_limit);
            fclose(file);
        }
        break;
    case 81:
    case 91:
        /*
         * As in Cylon, drive only the host tracefs; QEMU trace events are
         * global and belong to the -trace configuration.
         */
        s->tracing = command == 91;
        if (s->tracefs_dir && *s->tracefs_dir) {
            if (s->tracing) {
                file = cxl_log_open(s, s->tracefs_dir, "trace", "w");
                if (file) {
                    fclose(file);
                }
            }
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
    /* A command may sleep through an unplug; keep the object until done. */
    object_ref(obj);
    s->control_command = value;
    cxl_command(obj, value, s->control_argument, &local_err);
    s->control_status = local_err != NULL;
    error_propagate(errp, local_err);
    object_unref(obj);
}

/*
 * Commands that never drop the BQL, so they can finish inside the mailbox
 * handler once the gate is free. Flushes and way changes wait for the media.
 */
static bool cxl_lsa_inline(uint64_t command)
{
    switch (command) {
    case 1:
    case 5:
    case 7:
    case 13:
    case 15:
    case 17:
    case 80:
    case 81:
    case 90:
    case 91:
        return true;
    default:
        return false;
    }
}

static void cxl_lsa_bh(void *opaque)
{
    FemuCxlSsd *dev = opaque;
    FemuCxlMedia *s = &dev->media;
    FemuCxlLsaCommand *c;

    /* Commands queued while one sleeps join this pass, in order. */
    while ((c = g_queue_pop_head(&dev->lsa_queue))) {
        Error *err = NULL;

        s->control_command = c->command;
        s->control_argument = c->argument;
        cxl_command(OBJECT(dev), c->command, c->argument, &err);
        s->control_status = err != NULL;
        error_free(err);
        g_free(c);
    }
    dev->lsa_running = false;
    object_unref(OBJECT(dev));
}

static uint64_t cxl_lsa_size(CXLType3Dev *dev)
{
    return FEMU_CXL_SSD(dev)->media.lsa_control ? FEMU_CXL_LSA_SIZE :
                                               parent_lsa_size(dev);
}

static uint64_t cxl_get_lsa(CXLType3Dev *dev, void *buf, uint64_t size,
                           uint64_t offset)
{
    FemuCxlSsd *cxl = FEMU_CXL_SSD(dev);
    FemuCxlMedia *s = &cxl->media;
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
    if (!s->labels) {
        s->control_status = 1;
        return 0;
    }
    /*
     * The mailbox handler runs with this device's re-entrancy guard held,
     * so nothing here may wait: other vCPUs' MSI-X, mailbox and component
     * accesses would be refused meanwhile. Run a command now only if it
     * cannot wait and nothing is ahead of it; else leave it to a bottom
     * half and report it queued.
     */
    if (cxl_lsa_inline(size) && !s->busy && !s->accesses &&
        !cxl->lsa_running) {
        s->control_command = size;
        s->control_argument = offset;
        cxl_command(OBJECT(dev), size, offset, &err);
        s->control_status = err != NULL;
        error_free(err);
    } else {
        FemuCxlLsaCommand *c = g_new(FemuCxlLsaCommand, 1);

        c->command = size;
        c->argument = offset;
        g_queue_push_tail(&cxl->lsa_queue, c);
        s->control_status = FEMU_CXL_LSA_QUEUED;
        if (!cxl->lsa_running) {
            cxl->lsa_running = true;
            object_ref(OBJECT(dev));
            aio_bh_schedule_oneshot(qemu_get_aio_context(), cxl_lsa_bh, cxl);
        }
    }
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

static bool adapter_media_enabled(FemuCxlMedia *s)
{
    FemuCxlSsd *dev = container_of(s, FemuCxlSsd, media);

    return !dev->test_media_disabled &&
           !cxl_dev_media_disabled(&dev->parent_obj.cxl_dstate);
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
    /*
     * Under TCG a memslot alias changes the dispatch map from inside a vCPU's
     * MMIO handler while other vCPUs still hold TLB entries indexing the old
     * map, which trips iotlb_to_section(). Ratio mappings use the same
     * aliases, so refuse the mode rather than any later mapping.
     */
    if (s->der && !strcmp(s->der, "memslot") && tcg_enabled()) {
        error_setg(errp, "der=memslot is not supported with TCG; use KVM, "
                   "or der=off");
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
    if (!femu_cxl_geometry(s, size, errp)) {
        return;
    }
    if (s->cca_enabled && !femu_cxl_cca_alloc(s, OBJECT(dev), errp)) {
        return;
    }
    parent_realize(dev, &local_err);
    if (local_err) {
        if (s->cca_enabled) {
            object_unparent(OBJECT(&s->cca.shm));
        }
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
    /* The thread starts last: nothing after it can fail. */
    if (s->cca_enabled) {
        femu_cxl_cca_start(s, dev, OBJECT(dev), adapter_media_enabled);
    }
}

/* Free the media once no operation holds the gate. */
static void cxl_media_release(FemuCxlMedia *s)
{
    femu_cxl_der_destroy(&s->direct);
    femu_cxl_stop(s);
    g_clear_pointer(&s->labels, g_free);
    if (s->io_log) {
        fclose(s->io_log);
        s->io_log = NULL;
    }
}

static void cxl_exit(PCIDevice *dev)
{
    FemuCxlMedia *s = &FEMU_CXL_SSD(dev)->media;

    femu_cxl_cca_stop(s);
    /*
     * A guest unplug arrives inside the host bridge's dispatch guard, so do
     * not wait for an access sleeping in its media delay. Revoke now; that
     * access holds a reference and frees the media as it leaves the gate.
     */
    s->closing = true;
    if (s->busy || s->accesses) {
        femu_cxl_der_disable(&s->direct);
        s->release = cxl_media_release;
    } else {
        s->busy = true;
        cxl_media_release(s);
        femu_cxl_leave(s);
    }
    adapter_detach(FEMU_CXL_SSD(dev));
    memory_region_del_subregion(&CXL_TYPE3(dev)->cxl_cstate.crb.cache_mem,
                                &FEMU_CXL_SSD(dev)->component_overlay);
    object_unparent(OBJECT(&FEMU_CXL_SSD(dev)->component_overlay));
    adapter_cci_dispose(&CXL_TYPE3(dev)->cci, true);
    adapter_cci_dispose(&CXL_TYPE3(dev)->vdm_fm_owned_ld_mctp_cci, false);
    adapter_cci_dispose(&CXL_TYPE3(dev)->ld0_cci, false);
    /* The parent destroys this lock even if no reset initialized it. */
    if (!CXL_TYPE3(dev)->cci.initialized) {
        qemu_mutex_init(&CXL_TYPE3(dev)->cci.bg.lock);
    }
    parent_exit(dev);
    /* A linked controller keeps using the payload; it releases it. */
    if (!s->nvme) {
        host_memory_backend_set_mapped(CXL_TYPE3(dev)->hostvmem, false);
    }
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

/*
 * cxl_dev_media_disabled() reads a mailbox register that sanitize never
 * sets, so no command can disable media here; let tests do it for CCA.
 */
static void adapter_test_media_disabled(Object *obj, bool value, Error **errp)
{
    FEMU_CXL_SSD(obj)->test_media_disabled = value;
}

static void cxl_init(Object *obj)
{
    FemuCxlMedia *s = &FEMU_CXL_SSD(obj)->media;

    if (qtest_driver()) {
        object_property_add_bool(obj, "test-change-dpa", NULL,
                                 adapter_test_change_dpa);
        object_property_add_bool(obj, "test-slot-reservation",
                                 adapter_reservation_test, NULL);
        object_property_add_bool(obj, "test-media-disabled", NULL,
                                 adapter_test_media_disabled);
    }
    FEMU_CXL_SSD(obj)->lsa_limit = CXL_MAILBOX_MAX_PAYLOAD_SIZE;
    qemu_cond_init(&s->idle);
    s->pages = g_hash_table_new(g_int64_hash, g_int64_equal);
    femu_cxl_cca_init(&s->cca);
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
    object_property_add_uint64_ptr(obj, "invalidations", &s->invalidations,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "nvme-drops", &s->nvme_drops,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "log-dropped", &s->log_dropped,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_bool(obj, "der-active", cxl_der_active, NULL);
    object_property_add_uint64_ptr(obj, "der-remaps", &s->direct.remaps,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "der-revocations",
                                   &s->direct.revocations, OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "der-quiet-revocations",
                                   &s->direct.quiet_revocations,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "der-fallbacks", &s->direct.fallbacks,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "der-replacements",
                                   &s->direct.replacements, OBJ_PROP_FLAG_READ);
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
    object_property_add_uint64_ptr(obj, "media-full", &s->media_full,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "cache-hits", &s->cache.hits,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "cache-misses", &s->cache.misses,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "cache-inserts", &s->cache.inserts,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "cache-evictions", &s->cache.evictions,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "cca-commands", &s->cca.commands,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "cca-errors", &s->cca.errors,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "cca-pinned", &s->cache.pinned,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "cca-uncached", &s->cca.uncached,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "cca-pin-fills", &s->cca.pin_fills,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "cca-writebacks", &s->cca.writebacks,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "cca-dropped", &s->cca.dropped,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "cca-pinned-set-misses",
                                   &s->cca.pinned_set_misses,
                                   OBJ_PROP_FLAG_READ);
    femu_cxl_describe_runtime(obj);
}

static const Property cxl_props[] = {
    DEFINE_PROP_UINT32("cache-pages", FemuCxlSsd, media.cache_pages, 1024),
    DEFINE_PROP_STRING("cache-policy", FemuCxlSsd, media.cache_policy),
    DEFINE_PROP_BOOL("lsa-control", FemuCxlSsd, media.lsa_control, false),
    DEFINE_PROP_STRING("log-dir", FemuCxlSsd, media.log_dir),
    DEFINE_PROP_STRING("tracefs-dir", FemuCxlSsd, media.tracefs_dir),
    DEFINE_PROP_SIZE("log-limit", FemuCxlSsd, media.log_limit, 64 * MiB),
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
    DEFINE_PROP_UINT32("der-replace-rate", FemuCxlSsd,
                       media.direct.replace_rate, 64),
    DEFINE_PROP_BOOL("cylon-kernel-ack", FemuCxlSsd,
                     media.cylon_kernel_ack, false),
    DEFINE_PROP_ON_OFF_AUTO("concurrent-misses", FemuCxlSsd, media.concurrent,
                            ON_OFF_AUTO_AUTO),
    DEFINE_PROP_UINT64("read-ns", FemuCxlSsd, media.read_ns, 40000),
    DEFINE_PROP_UINT64("program-ns", FemuCxlSsd, media.program_ns, 200000),
    DEFINE_PROP_UINT64("erase-ns", FemuCxlSsd, media.erase_ns, 2000000),
    DEFINE_PROP_BOOL("cca", FemuCxlSsd, media.cca_enabled, false),
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
    femu_cxl_describe_props(oc);
    parent_config_write = pc->config_write;
    pc->config_write = adapter_config_write;
    resettable_class_set_parent_phases(rc, NULL, adapter_reset_hold, NULL,
                                      &parent_reset);
}

static void cxl_finalize(Object *obj)
{
    g_queue_clear_full(&FEMU_CXL_SSD(obj)->lsa_queue, g_free);
    g_clear_pointer(&FEMU_CXL_SSD(obj)->media.log_warned,
                    g_hash_table_destroy);
    g_hash_table_destroy(FEMU_CXL_SSD(obj)->media.pages);
    qemu_cond_destroy(&FEMU_CXL_SSD(obj)->media.idle);
    femu_cxl_cca_finalize(&FEMU_CXL_SSD(obj)->media.cca);
}

static const TypeInfo cxl_info = {
    .name = TYPE_FEMU_CXL_SSD,
    .parent = TYPE_CXL_TYPE3,
    .instance_size = sizeof(FemuCxlSsd),
    .instance_init = cxl_init,
    .instance_finalize = cxl_finalize,
    .class_init = cxl_class_init,
};

/* Lend the medium to a bbssd controller; see "NVMe front end" in cxlssd.md. */
static bool cxl_nvme_prepare(FemuCtrl *n, Error **errp)
{
    FemuCxlSsd *dev = FEMU_CXL_SSD(n->cxl_dev);
    FemuCxlMedia *s = &dev->media;
    uint64_t mib = s->backend.size / MiB;
    const char *id = DEVICE(n)->id ? DEVICE(n)->id : "femu";

    if (!DEVICE(dev)->realized || !s->started || s->closing) {
        error_setg(errp, "cxl_ssd must name a realized femu-cxl-ssd");
        return false;
    }
    if (!s->ftl) {
        error_setg(errp, "cxl_ssd requires the femu-cxl-ssd to have ftl=on");
        return false;
    }
    if (s->nvme) {
        error_setg(errp, "the femu-cxl-ssd already serves an NVMe controller");
        return false;
    }
    /* 1024 is devsz_mb's default; the medium decides the size. */
    if (n->memsz != 1024 && n->memsz != mib) {
        error_setg(errp, "devsz_mb must be unset or %" PRIu64 ", the size "
                   "of the femu-cxl-ssd", mib);
        return false;
    }
    n->memsz = mib;
    n->mbe = &s->backend;
    n->cxl_ssd = s->ns.ssd;
    s->nvme = n;
    error_setg(&s->nvme_blocker, "femu-cxl-ssd is in use by NVMe "
               "controller %s", id);
    qdev_add_unplug_blocker(DEVICE(dev), s->nvme_blocker);
    if (!s->nvme_bh) {
        s->nvme_bh = qemu_bh_new(femu_cxl_nvme_bh, s);
    }
    return true;
}

static void cxl_nvme_attach(FemuCtrl *n, NvmeNamespace *ns)
{
    FemuCxlMedia *s = &FEMU_CXL_SSD(n->cxl_dev)->media;

    s->nvme_ns = ns;
    n->cxl_done = &s->nvme_done;
    n->cxl_media = s;
    /* The bitmap cannot tell which pages earlier CXL traffic wrote. */
    if (s->entries || s->direct.mapped || s->direct.ratio) {
        femu_cxl_nvme_mark(s, 0, s->backend.size);
    }
}

/* The controller's threads are stopped; it may never have attached. */
static void cxl_nvme_detach(FemuCtrl *n)
{
    FemuCxlSsd *dev = FEMU_CXL_SSD(n->cxl_dev);
    FemuCxlMedia *s = &dev->media;

    if (s->nvme != n) {
        return;
    }
    if (s->nvme_owns_ftl) {
        /* The device went away first and left its FTL to this controller. */
        n->ssd = NULL;
        n->namespaces[0].ssd = NULL;
        ssd_free(s->ns.ssd);
        g_clear_pointer(&s->ns.ssd, g_free);
        g_clear_pointer(&s->ctrl, g_free);
        s->nvme_owns_ftl = false;
    }
    /* Unplug left the backend mapped for this controller; release it. */
    if (s->closing) {
        host_memory_backend_set_mapped(dev->parent_obj.hostvmem, false);
    }
    qdev_del_unplug_blocker(DEVICE(dev), s->nvme_blocker);
    g_clear_pointer(&s->nvme_blocker, error_free);
    s->nvme = NULL;
    s->nvme_ns = NULL;
    n->cxl_media = NULL;
    n->cxl_done = NULL;
    n->cxl_ssd = NULL;
}

static const FemuCxlNvmeOps cxl_nvme_ops = {
    .prepare = cxl_nvme_prepare,
    .attach = cxl_nvme_attach,
    .detach = cxl_nvme_detach,
    .ftl = femu_cxl_nvme_ftl,
    .flip = femu_cxl_nvme_flip,
};

static void cxl_register_types(void)
{
    type_register_static(&cxl_info);
    femu_cxl_nvme_ops = &cxl_nvme_ops;
}

type_init(cxl_register_types);

typedef struct FemuCxlMap {
    /* g_free_rcu() needs the head at a small offset. */
    struct rcu_head rcu;
    uint64_t lpn;
    uint64_t pages;
    MemoryRegion mr;
    MemoryRegion *container;
    /* Node in FemuCxlDer.installed; data is NULL for ratio runs. */
    GList link;
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
    der->windows = g_ptr_array_new();
    g_queue_init(&der->installed);
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
static void der_windows_scan(FemuCxlDer *der)
{
    GSList *windows = cxl_fmws_get_all_sorted();
    GSList *it;
    PCIBus *bus = pci_get_bus(PCI_DEVICE(der->dev));
    PCIDevice *rp = bus->parent_dev;
    uint32_t *regs = der->dev->parent_obj.cxl_cstate.crb.cache_mem_registers;
    unsigned i;

    g_ptr_array_set_size(der->windows, 0);
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

        if (fw->num_targets != 1) {
            continue;
        }
        hb = PCI_HOST_BRIDGE(fw->target_hbs[0]->cxl_host_bridge);
        if (hb->bus == pci_get_bus(rp) && cxl_get_hb_passthrough(hb) &&
            adapter_target(fw) == PCI_DEVICE(der->dev)) {
            g_ptr_array_add(der->windows, fw);
        }
    }
out:
    g_slist_free(windows);
}

/*
 * Finding the windows walks the whole QOM tree, far too slow for every
 * access. Windows and topology are fixed once the machine is built, and
 * every decoder, config, CCI or reset write bumps the generation.
 */
static CXLFixedWindow *der_window(FemuCxlDer *der, uint64_t hpa)
{
    uint64_t generation = der->dev->media.invalidations;
    unsigned i;

    if (!der->windows_valid || der->windows_generation != generation) {
        der_windows_scan(der);
        der->windows_generation = generation;
        der->windows_valid = true;
    }
    for (i = 0; i < der->windows->len; i++) {
        CXLFixedWindow *fw = g_ptr_array_index(der->windows, i);

        if (hpa >= fw->base && hpa - fw->base < fw->size) {
            return fw;
        }
    }
    return NULL;
}

/* Every device's aliases share address_space_memory's section limit. */
static uint64_t der_aliases;

static uint64_t der_alias_budget(void)
{
    uint64_t budget = der_aliases < FEMU_CXL_DER_ALIASES ?
                      FEMU_CXL_DER_ALIASES - der_aliases : 0;

#ifdef CONFIG_KVM
    /* Each alias is a KVM slot; keep room for splits of existing regions. */
    if (kvm_enabled()) {
        unsigned free = kvm_get_free_memslots();

        budget = MIN(budget, free > 8 ? free - 8 : 0);
    }
#endif
    return budget;
}

/* A unique name lets QOM add the child without probing indexes. */
static FemuCxlMap *der_alias(FemuCxlDer *der, MemoryRegion *container,
                             uint64_t offset, const char *kind, uint64_t lpn,
                             uint64_t pages)
{
    MemoryRegion *ram =
        host_memory_backend_get_memory(der->dev->parent_obj.hostvmem);
    g_autofree char *name = g_strdup_printf("%s-%" PRIx64, kind, lpn);
    FemuCxlMap *map = g_new0(FemuCxlMap, 1);

    map->lpn = lpn;
    map->pages = pages;
    map->container = container;
    memory_region_init_alias(&map->mr, OBJECT(der->dev), name, ram,
                             lpn * 4096, pages * 4096);
    /* QEMU owns slot allocation, revocation and TLB invalidation. */
    memory_region_add_subregion_overlap(container, offset, &map->mr, 1);
    g_hash_table_insert(der->maps, &map->lpn, map);
    der_aliases++;
    der->mapped += pages;
    der->remaps += pages;
    return map;
}

/*
 * With the budget full, let a page that keeps missing the direct path
 * displace the oldest cache alias of this device, at a bounded rate.
 * Accesses through an alias never reach QEMU, so installation order is
 * the only recency available.
 */
static bool der_replace_due(FemuCxlDer *der, FemuCxlEntry *e)
{
    int64_t now;

    if (!e || !der->replace_rate || ++e->der_hits < FEMU_CXL_DER_HOT ||
        g_queue_is_empty(&der->installed)) {
        return false;
    }
    now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    return !der->replace_last ||
           now - der->replace_last >= (NANOSECONDS_PER_SECOND /
                                       der->replace_rate) <<
                                      der->replace_backoff;
}

/* The oldest cache alias whose page is not pinned; CCA pins stay direct. */
static FemuCxlMap *der_replace_victim(FemuCxlDer *der)
{
    GList *link;

    for (link = der->installed.head; link; link = link->next) {
        FemuCxlMap *map = link->data;
        FemuCxlEntry *e = g_hash_table_lookup(der->cache->entries, &map->lpn);

        if (!e || e->queue != FEMU_CXL_PINNED) {
            return map;
        }
    }
    return NULL;
}

/* A hot set larger than the budget only rotates; back off when it does. */
static void der_displace(FemuCxlDer *der, FemuCxlMap *victim, FemuCxlEntry *e)
{
    /* A lookup, not an access: leave the hit counters and recency alone. */
    FemuCxlEntry *old = g_hash_table_lookup(der->cache->entries, &victim->lpn);

    if (e->der_displaced) {
        der->replace_backoff = MIN(der->replace_backoff + 1,
                                   FEMU_CXL_DER_BACKOFF);
        der->replace_clean = 0;
    } else if (der->replace_backoff &&
               ++der->replace_clean == FEMU_CXL_DER_CLEAN) {
        der->replace_backoff--;
        der->replace_clean = 0;
    }
    e->der_displaced = false;
    if (old) {
        old->der_displaced = true;
        old->der_hits = 0;
    }
    femu_cxl_der_remove(der, victim->lpn);
    der->replace_last = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    der->replacements++;
}

bool femu_cxl_der_map(FemuCxlDer *der, uint64_t hpa, uint64_t dpa,
                      FemuCxlEntry *e)
{
    uint64_t lpn = dpa / 4096;
    FemuCxlMap *map;
    FemuCxlMap *victim = NULL;
    CXLFixedWindow *fw;
    uint64_t check;

    /* As in Cylon, a ratio adds to cached mappings instead of limiting them. */
    if ((!der->available && !der->fast) || (hpa & 4095) != (dpa & 4095)) {
        return false;
    }
    /*
     * Callers derive @hpa for pages they did not access, such as prefetches;
     * several decoders or a DPA skip can put that page elsewhere or nowhere.
     */
    if (!adapter_translate(&der->dev->parent_obj, hpa & ~4095ULL, 4096,
                           &check) || check != (dpa & ~4095ULL)) {
        der->fallbacks++;
        return false;
    }
    if (!der->cylon && g_hash_table_contains(der->maps, &lpn)) {
        return true;
    }
    /* A ratio run covers selected pages; never add one-page aliases there. */
    if (!der->cylon && femu_cxl_ratio_selected(der->ratio, lpn)) {
        return lpn < der->ratio_end;
    }
    /* A full budget is the common refusal; decide it before the window. */
    if (!der->cylon && !der_alias_budget()) {
        victim = der_replace_due(der, e) ? der_replace_victim(der) : NULL;
        if (!victim) {
            der->fallbacks++;
            return false;
        }
    }
    fw = der_window(der, hpa);
    if (!fw) {
        der->fallbacks++;
        return false;
    }
    if (der->cylon) {
        return femu_cylon_map(der, fw, hpa, dpa);
    }
    /* One transaction, so the swap rebuilds the flat view once. */
    memory_region_transaction_begin();
    if (victim) {
        der_displace(der, victim, e);
    }
    map = der_alias(der, &fw->mr, (hpa & ~4095ULL) - fw->base,
                    "femu-cxl-hit", lpn, 1);
    memory_region_transaction_commit();
    map->link.data = map;
    g_queue_push_tail_link(&der->installed, &map->link);
    return true;
}

/* Runs are the gaps between multiples of the period, or one whole run. */
static uint64_t der_ratio_runs(uint64_t period, uint64_t pages)
{
    if (period == 1) {
        return pages ? 1 : 0;
    }
    return pages > 1 ? DIV_ROUND_UP(pages - 1, period) : 0;
}

/* Map every run in one transaction, or nothing when the runs cannot fit. */
static bool der_ratio_apply(FemuCxlSsd *dev, CXLFixedWindow *fw, Error **errp)
{
    FemuCxlDer *der = &dev->media.direct;
    uint64_t pages = dev->media.backend.size / 4096;
    uint64_t period = femu_cxl_ratio_period(der->ratio);
    uint64_t runs = der_ratio_runs(period, pages);
    uint64_t budget = der_alias_budget();
    uint64_t run;
    GHashTableIter entries;
    gpointer value;

    if (runs > budget) {
        der->fallbacks++;
        error_setg(errp, "DER ratio needs %" PRIu64 " mappings, at most %"
                   PRIu64 " are available", runs, budget);
        return false;
    }
    memory_region_transaction_begin();
    for (run = 0; run < runs; run++) {
        uint64_t lpn = period == 1 ? 0 : run * period + 1;
        uint64_t end = period == 1 ? pages : MIN((run + 1) * period, pages);

        der_alias(der, &fw->mr, lpn * 4096, "femu-cxl-ratio", lpn, end - lpn);
    }
    memory_region_transaction_commit();
    der->ratio_end = pages;
    g_hash_table_iter_init(&entries, dev->media.cache.entries);
    while (g_hash_table_iter_next(&entries, NULL, &value)) {
        FemuCxlEntry *entry = value;

        if (femu_cxl_ratio_selected(der->ratio, entry->lpn)) {
            /* Alias writes cannot notify the resident cache metadata. */
            entry->dirty = true;
        }
    }
    return true;
}

/* Map the current ratio; the caller holds the gate and revoked everything. */
static bool cxl_ratio_map(FemuCxlSsd *dev, Error **errp)
{
    FemuCxlMedia *s = &dev->media;
    FemuCxlDer *der = &s->direct;
    GSList *windows;
    GSList *it;
    CXLFixedWindow *fw = NULL;

    /* After unplug the device has no bus to route a window through. */
    if (!der->ratio || s->closing || (!der->available && !der->fast)) {
        return true;
    }
    /* Refuse on the count first: a retry on every access must stay cheap. */
    if (!der->cylon) {
        uint64_t runs = der_ratio_runs(femu_cxl_ratio_period(der->ratio),
                                       s->backend.size / 4096);
        uint64_t budget = der_alias_budget();

        if (runs > budget) {
            der->fallbacks++;
            error_setg(errp, "DER ratio needs %" PRIu64 " mappings, at most %"
                       PRIu64 " are available", runs, budget);
            return false;
        }
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
        return false;
    }
    if (der->cylon) {
        cylon_ratio_apply(der, fw);
        return true;
    }
    return der_ratio_apply(dev, fw, errp);
}

/*
 * Re-map a ratio that a flush, cache rebuild or invalidation revoked. The
 * shared budget may be taken meanwhile; keep the ratio configured, serve
 * its pages by MMIO, and let the next access try again.
 */
static void cxl_ratio_restore(FemuCxlSsd *dev, Error **errp)
{
    FemuCxlDer *der = &dev->media.direct;
    Error *err = NULL;

    if (!cxl_ratio_map(dev, &err)) {
        if (!errp && !der->ratio_warned) {
            der->ratio_warned = true;
            warn_report_err(error_copy(err));
        }
        error_propagate(errp, err);
    } else {
        der->ratio_warned = false;
    }
}

static void cxl_ratio(FemuCxlSsd *dev, uint64_t ratio, Error **errp)
{
    FemuCxlMedia *s = &dev->media;
    FemuCxlDer *der = &s->direct;

    if (ratio != 100 && femu_cxl_ratio_period(ratio) == 1) {
        error_setg(errp, "unsupported Cylon direct ratio");
        return;
    }
    if (ratio && (!s->der || !strcmp(s->der, "off"))) {
        error_setg(errp, "a direct ratio requires der=memslot or der=cylon");
        return;
    }
    object_ref(OBJECT(dev));
    femu_cxl_enter(s);
    if (!s->started || s->closing) {
        error_setg(errp, "der-ratio requires a realized device");
        goto out;
    }
    /* A ratio mapping would serve an uncached page at DRAM speed. */
    if (ratio && s->cca.uncached) {
        error_setg(errp, "a direct ratio cannot be set while CCA uncached "
                   "ranges exist");
        goto out;
    }
    if (der->cylon) {
        cylon_ratio_revoke(der);
    } else {
        femu_cxl_der_clear(der);
    }
    der->ratio = ratio;
    if (!cxl_ratio_map(dev, errp)) {
        der->ratio = 0;
    } else {
        /* Stores to selected pages never reach this device. */
        femu_cxl_nvme_mark_ratio(s, 0, s->backend.size / 4096 - 1);
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
    if (map->link.data) {
        g_queue_unlink(&der->installed, &map->link);
    }
    memory_region_del_subregion(map->container, &map->mr);
    g_hash_table_remove(der->maps, &lpn);
    der_aliases--;
    object_unparent(OBJECT(&map->mr));
    der->mapped -= map->pages;
    der->revocations += map->pages;
    /* A reader on the previous flat view may still reach the region. */
    g_free_rcu(map, rcu);
}

/*
 * Whether a direct ratio page was written since the last sample. Memslot
 * cannot tell and keeps such entries dirty; Cylon reads the EPT dirty bit
 * and keeps the page mapped.
 */
bool femu_cxl_der_sample(FemuCxlDer *der, uint64_t lpn)
{
    return der->cylon && femu_cylon_sample(der, lpn);
}

void femu_cxl_der_clear(FemuCxlDer *der)
{
    GHashTableIter it;
    gpointer key;

    if (der->cylon) {
        femu_cylon_clear(der);
        return;
    }
    der->ratio_end = 0;
    memory_region_transaction_begin();
    while (g_hash_table_size(der->maps)) {
        g_hash_table_iter_init(&it, der->maps);
        g_hash_table_iter_next(&it, &key, NULL);
        femu_cxl_der_remove(der, *(uint64_t *)key);
    }
    memory_region_transaction_commit();
}

/* Revoke everything and refuse new mappings, keeping state for teardown. */
void femu_cxl_der_disable(FemuCxlDer *der)
{
    femu_cxl_der_clear(der);
    der->available = false;
    /* Unlock the backing now; a new device may reuse and lock it. */
    femu_cylon_destroy(der);
}

void femu_cxl_der_destroy(FemuCxlDer *der)
{
    femu_cxl_der_clear(der);
    femu_cylon_destroy(der);
    der->available = false;
    g_hash_table_destroy(der->maps);
    g_ptr_array_free(der->windows, true);
}

#ifdef CONFIG_KVM
#include <linux/kvm.h>
#include <linux/magic.h>
#include <sys/vfs.h>
#include <sys/mman.h>

#include "spt.h"
#define KVM_CYLON_DUAL_MODE (1U << 17)

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
    bool installing;
    bool rearm;
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
    bool logging;
    bool batch;
    /* During a batch, the last huge page whose frame was found current. */
    uint64_t checked_huge;
};

static void cylon_region_change(MemoryListener *listener,
                                MemoryRegionSection *section);
static void cylon_listener_commit(MemoryListener *listener);
static bool cylon_log_start(MemoryListener *listener, Error **errp);
static void cylon_log_stop(MemoryListener *listener);

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

/* The kernel slot is already deleted, so give the ID back to QEMU. */
static void cylon_unreserve(FemuCylon *c)
{
    if (c->reservation) {
        kvm_release_memslot(c->reservation);
        c->reservation = NULL;
    }
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
    c->listener.region_add = cylon_region_change;
    c->listener.region_del = cylon_region_change;
    c->listener.commit = cylon_listener_commit;
    c->listener.log_global_start = cylon_log_start;
    c->listener.log_global_stop = cylon_log_stop;
    c->listener.name = "femu-cxl-external-slot";
    /* Forward order: delete before the KVM listener can add overlapping RAM. */
    c->listener.priority = MEMORY_LISTENER_PRIORITY_ACCEL - 1;
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
    cylon_unreserve(c);
    femu_cxl_der_fallback(der, "Cylon slot, SPT bounds or ioctl failure");
}

/* Slot publication precedes aux initialization in the host kernel. */
static void cylon_install_bh(void *opaque)
{
    FemuCylon *c = opaque;

    pause_all_vcpus();
    /* Checked after the pause, so changes made while it waited count. */
    if (!c->detached && !c->failed &&
        cylon_coverage(c, c->pending_window) &&
        !cylon_install(c->der, c->pending_window)) {
        cylon_fail(c->der);
    }
    object_unref(OBJECT(c->pending_window));
    c->installing = false;
    /* Disabled media must keep trapping, so map nothing until re-enabled. */
    /* Cached pages map lazily on their next access; only a ratio is eager. */
    if (!c->detached && c->installed && c->der->ratio &&
        !cxl_dev_media_disabled(&c->der->dev->parent_obj.cxl_dstate)) {
        cylon_ratio_apply(c->der, c->window);
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
    /* A DPA skip or offset base is valid but cannot use the identity slot. */
    if (hpa < fw->base || hpa - fw->base != dpa) {
        der->fallbacks++;
        return false;
    }
    if (!cylon_page_index(dpa, c->size, c->size / CYLON_PAGE_SIZE, &index) ||
        !cylon_page_address(c->huge, c->size / c->huge_size, c->huge_size,
                            index * CYLON_PAGE_SIZE, &pa)) {
        cylon_fail(der);
        return false;
    }
    /* A ratio batch reads the pagemap once per huge page, not per page. */
    if (!cylon_pfn_current(c->pagemap, c->huge, (uintptr_t)c->ram,
                           c->huge_size, dpa,
                           c->batch ? &c->checked_huge : NULL)) {
        cylon_fail(der);
        return false;
    }
    if (!c->installed) {
        c->installing = true;
        c->pending_window = fw;
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
        if (page->sptep != sptep || !cylon_spte_is_direct(old, pa)) {
            cylon_fail(der);
            return false;
        }
        return true;
    }
    /*
     * Only a ratio pre-maps pages the guest never touched. An empty leaf can
     * be restored to zero without guessing a generation; elsewhere let KVM's
     * first fault create the MMIO entry, as before ratios existed.
     */
    if (old == CYLON_REMOVED_SPTE || (!old && !c->batch)) {
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
    /*
     * No flush: the replaced MMIO entry is not present, so no TLB holds a
     * translation from it. KVM does not flush when a fault fills such an entry.
     */
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
    c->checked_huge = UINT64_MAX;
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

/*
 * With @flush false the caller deletes the slot next, which flushes every
 * translation, so the flush after restoring MMIO would be redundant.
 */
static void cylon_remove_page(FemuCxlDer *der, uint64_t lpn, bool flush)
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
    if (!cylon_spte_is_direct(old, pa)) {
        cylon_fail(der);
        return;
    }
    /*
     * A clear: no page walk has used the entry since it was installed, so no
     * TLB holds a translation from it, and D is clear too. Swap in the MMIO
     * entry without flushing; if the CPU sets A first, the exchange fails and
     * the full revocation below runs.
     */
    if (!(old & CYLON_EPT_ACCESSED) &&
        cylon_spte_install(page->sptep, old, page->mmio)) {
        der->quiet_revocations++;
        cylon_drop(der, page, false);
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
        if (!cylon_spte_is_direct(old, pa)) {
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
        if (!cylon_spte_is_readonly_direct(old, pa)) {
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
    if (flush && !cylon_flush(gpa)) {
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
        cylon_remove_page(der, *(uint64_t *)key, true);
    }
}

static void femu_cylon_clear(FemuCxlDer *der)
{
    FemuCylon *c = der->fast;

    if (!c) {
        return;
    }
    while (g_hash_table_size(der->maps)) {
        GHashTableIter it;
        gpointer key;

        g_hash_table_iter_init(&it, der->maps);
        g_hash_table_iter_next(&it, &key, NULL);
        cylon_remove_page(der, *(uint64_t *)key, false);
    }
    cylon_release(c);
}

/* Evict one page and keep the slot, so other direct pages stay mapped. */
static void femu_cylon_remove(FemuCxlDer *der, uint64_t lpn)
{
    if (der->fast && der->fast->installed) {
        cylon_remove_page(der, lpn, true);
    }
}

static bool femu_cylon_sample(FemuCxlDer *der, uint64_t lpn)
{
    FemuCylon *c = der->fast;
    CylonPage *page;
    bool dirty;
    uint64_t pa;

    if (!c || !c->installed) {
        return false;
    }
    page = g_hash_table_lookup(der->maps, &lpn);
    if (!page) {
        return false;
    }
    if (page->sptep != cylon_sptep(c, lpn) ||
        !cylon_page_address(c->huge, c->size / c->huge_size, c->huge_size,
                            lpn * CYLON_PAGE_SIZE, &pa)) {
        cylon_fail(der);
        return false;
    }
    if (!cylon_spte_take_dirty(page->sptep, cylon_direct_spte(pa), &dirty)) {
        /* KVM revoked it, which counts as dirty; anything else is fatal. */
        if (cylon_spte_revoked(qatomic_read(page->sptep))) {
            cylon_drop(der, page, true);
        } else {
            cylon_fail(der);
        }
        return false;
    }
    /* A TLB entry that already has D set would not set it again. */
    if (dirty && !cylon_flush(c->window->base + lpn * CYLON_PAGE_SIZE)) {
        cylon_fail(der);
    }
    return dirty;
}

/* Only map changes over the installed window can expose overlapping RAM. */
static void cylon_region_change(MemoryListener *listener,
                                MemoryRegionSection *section)
{
    FemuCylon *c = container_of(listener, FemuCylon, listener);
    uint64_t start = section->offset_within_address_space;
    uint64_t size = int128_get64(section->size);

    if (c->installed && size && start < c->window->base + c->window->size &&
        c->window->base < start + size) {
        femu_cylon_clear(c->der);
        c->rearm = true;
    }
}

static void cylon_listener_commit(MemoryListener *listener)
{
    FemuCylon *c = container_of(listener, FemuCylon, listener);

    if (c->rearm && !c->detached && !c->failed && !c->installing &&
        cylon_coverage(c, c->window)) {
        c->rearm = false;
        femu_cylon_map(c->der, c->window, c->window->base, 0);
    }
}

static bool cylon_log_start(MemoryListener *listener, Error **errp)
{
    FemuCylon *c = container_of(listener, FemuCylon, listener);

    femu_cylon_clear(c->der);
    cylon_unreserve(c);
    c->failed = true;
    c->logging = true;
    femu_cxl_der_fallback(c->der, "external slots cannot track dirty logging");
    return true;
}

static void cylon_log_stop(MemoryListener *listener)
{
    FemuCylon *c = container_of(listener, FemuCylon, listener);

    c->logging = false;
}

/* Retry after reset; the slot is gone, so no stale translation survives. */
static void femu_cylon_reset(FemuCxlDer *der)
{
    FemuCylon *c = der->fast;

    if (c && c->failed && !c->logging && !c->installed) {
        c->failed = false;
    }
}

static void femu_cylon_destroy(FemuCxlDer *der)
{
    FemuCylon *c = der->fast;

    if (c) {
        c->detached = true;
        memory_listener_unregister(&c->listener);
        cylon_release(c);
        cylon_unreserve(c);
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

static void femu_cylon_reset(FemuCxlDer *der)
{
}

static bool femu_cylon_sample(FemuCxlDer *der, uint64_t lpn)
{
    return false;
}
#endif

/*
 * A Cylon ratio maps up to one entry per media page, so stop at @limit
 * bytes: the dump runs under the BQL.
 */
static void cxl_dump_spt(FemuCxlDer *der, FILE *file, uint64_t limit)
{
    GHashTableIter it;
    gpointer value;
    uint64_t bytes;
    int n;

    n = fprintf(file, "mode=%s ratio=%" PRIu64 " mapped=%" PRIu64 "\n",
                der->cylon ? "cylon" : "memslot", der->ratio, der->mapped);
    bytes = MAX(n, 0);
    g_hash_table_iter_init(&it, der->maps);
    while (g_hash_table_iter_next(&it, NULL, &value)) {
        if (bytes >= limit) {
            fprintf(file, "truncated at log-limit\n");
            der->dev->media.log_dropped++;
            return;
        }
#ifdef CONFIG_KVM
        if (der->cylon) {
            CylonPage *page = value;

            n = fprintf(file, "lpn=%" PRIu64 " spte=%016" PRIx64 "\n",
                        page->lpn, qatomic_read(page->sptep));
        } else
#endif
        {
            FemuCxlMap *map = value;

            n = fprintf(file, "lpn=%" PRIu64 " pages=%" PRIu64 "\n",
                        map->lpn, map->pages);
        }
        bytes += MAX(n, 0);
    }
}
