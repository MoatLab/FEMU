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
#include "hw/i386/x86.h"
#include "hw/pci/pci_bus.h"
#include "hw/pci/pci_bridge.h"
#include "hw/pci/pci_host.h"
#include "system/kvm.h"
#include "system/address-spaces.h"
#include "qemu/atomic.h"
#include "qemu/rcu.h"
#include "system/cpus.h"
#include "system/runstate.h"
#include "system/reset.h"
#include "spte.h"

OBJECT_DECLARE_SIMPLE_TYPE(FemuCxlSsd, FEMU_CXL_SSD)

struct FemuCxlSsd {
    CXLType3Dev parent_obj;
    FemuCxlMedia media;
    MemoryRegion component_overlay;
    /* The bridge above the device, set while it is in adapter_live. */
    PCIDevice *port;
    Notifier machine_done;
    bool attached;
    bool test_change_dpa;
    bool test_media_disabled;
    /* How often the next test-fault or test-fault-decode exit repeats. */
    uint64_t test_fault_repeats;
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

/* Default cylon-fault-stop: repeated exits at one RIP that stop the VM. */
#define CYLON_FAULT_STOP 100000

static FemuCylon *femu_cylon_prepare(FemuCxlDer *der, const char **reason);
/* Version 2 of the Cylon fault exit is on for the VM (per VM). CXL lock. */
static bool cylon_v2;
/* The first Cylon slot of the VM chose the fault exit version. CXL lock. */
static bool cylon_version_fixed;
static bool femu_cylon_map(FemuCxlDer *der, CXLFixedWindow *fw,
                           uint64_t hpa, uint64_t dpa);
static void femu_cylon_remove(FemuCxlDer *der, uint64_t lpn);
static unsigned femu_cylon_batch(FemuCxlDer *der, uint64_t lpn);
static void femu_cylon_remove_batch(FemuCxlDer *der, uint64_t lpn,
                                    const uint64_t *ahead, unsigned n);
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

typedef struct FemuCxlWindow {
    struct rcu_head rcu;
    CXLFixedWindow *fw;
    MemoryRegion io;
    /*
     * The root port below the window's one passthrough host bridge, once a
     * route under the BQL found it, else NULL. Root ports on a pxb-cxl bus
     * take no hotplug, and a host bridge becomes passthrough at its first
     * reset and stays so.
     */
    PCIDevice *port;
    QLIST_ENTRY(FemuCxlWindow) next;
} FemuCxlWindow;

/* Decoder changes a fill waits through before it gives up. */
#define ADAPTER_FILL_REROUTES 8
/* Not a MemTxResult: the decoders changed while the access waited. */
#define ADAPTER_REROUTE (1U << 30)

static MemTxResult adapter_media_access(FemuCxlWindow *w, hwaddr offset,
                                        FemuCxlSsd *cxl, uint64_t *data,
                                        unsigned size, bool write,
                                        bool *mapped, unsigned flags);
static bool der_windows_stale(FemuCxlDer *der);

static void cxl_unref_bh(void *opaque)
{
    object_unref(opaque);
}

/*
 * Drop a reference that a fault exit took on @dev. The last reference
 * finalizes the device, which needs the BQL. Until unplug sets @closing
 * (under the CXL lock, which the caller holds) the parent holds one, so
 * only a closing device's reference goes to a bottom half.
 */
static void cxl_unref(FemuCxlSsd *dev)
{
    assert(femu_cxl_locked());
    if (!bql_locked() && dev->media.closing) {
        aio_bh_schedule_oneshot(qemu_get_aio_context(), cxl_unref_bh,
                                OBJECT(dev));
        return;
    }
    object_unref(OBJECT(dev));
}

static QLIST_HEAD(, FemuCxlWindow) adapter_windows =
    QLIST_HEAD_INITIALIZER(adapter_windows);
static unsigned adapter_users;

/*
 * Realized femu-cxl-ssd devices, under the CXL lock: added at the end of
 * realize, removed at the start of unplug, so one in the list is alive.
 */
static GPtrArray *adapter_live;

/*
 * Let fault exits take the CXL lock without the BQL. Until now a thread
 * asleep in a gate, page or fill wait sleeps on the BQL; wake every such
 * thread, so that it waits on the CXL lock's mutex from now on. BQL and CXL
 * lock.
 */
static void adapter_lock_bql_free(void)
{
    unsigned i;

    assert(femu_cxl_locked());
    if (femu_cxl_lock_is_bql_free()) {
        return;
    }
    femu_cxl_lock_bql_free();
    for (i = 0; adapter_live && i < adapter_live->len; i++) {
        FemuCxlSsd *dev = g_ptr_array_index(adapter_live, i);

        qemu_cond_broadcast(&dev->media.idle);
    }
}

/*
 * Whether the slot that @m installs asks for version 2 of the Cylon fault
 * exit, when the host kernel offers @version of KVM_CAP_CYLON_FAULT_EXIT
 * (0 for none). Only the first slot of the VM chooses: the pages of its
 * slot hold version 1 state otherwise. cylon-never-emulate=auto takes
 * version 2 when the kernel offers it; on also does, and warns when it
 * cannot. A kernel without the capability gets its own warning when the
 * slot enables it.
 */
static bool cylon_fault_version(const FemuCxlMedia *m, int version)
{
    bool first = !cylon_version_fixed;

    cylon_version_fixed = true;
    if (!first) {
        if (m->cylon_never_emulate == ON_OFF_AUTO_ON && !cylon_v2) {
            warn_report_once("femu-cxl-ssd: cylon-never-emulate must be on "
                             "for the first Cylon device of the VM; it stays "
                             "off");
        }
        return false;
    }
    if (m->cylon_never_emulate == ON_OFF_AUTO_OFF || !m->cylon_emul_exit) {
        return false;
    }
    if (version >= 2) {
        return true;
    }
    if (m->cylon_never_emulate == ON_OFF_AUTO_ON) {
        warn_report_once("femu-cxl-ssd: the host kernel lacks version 2 of "
                         "KVM_CAP_CYLON_FAULT_EXIT; cylon-never-emulate is "
                         "off and KVM emulates cold pages");
    } else if (version == 1) {
        warn_report_once("femu-cxl-ssd: the host kernel offers only version "
                         "1 of KVM_CAP_CYLON_FAULT_EXIT, so KVM emulates "
                         "accesses to cold pages, and instructions it cannot "
                         "emulate can fail in the guest; version 2 needs a "
                         "Cylon kernel that reports it (cylon-never-emulate="
                         "off hides this warning)");
    }
    return false;
}

static PCIDevice *adapter_pci(FemuCxlSsd *dev)
{
    return &dev->parent_obj.parent_obj;
}

/*
 * adapter_route() for a thread without the BQL, under the CXL lock. It
 * reads no decoder and no bus: a window with one passthrough host bridge
 * routes everything to that bridge's root port, and the device there is
 * the live femu-cxl-ssd whose parent port it is, if any. Anything else (an
 * interleaved or decoding window, a switch, another device or none) needs
 * the full walk under the BQL: the caller is told so with
 * femu_cxl_need_bql().
 */
static PCIDevice *adapter_route_fast(FemuCxlWindow *w)
{
    unsigned i;

    assert(femu_cxl_locked());
    for (i = 0; w->port && adapter_live && i < adapter_live->len; i++) {
        FemuCxlSsd *dev = g_ptr_array_index(adapter_live, i);

        if (dev->port == w->port) {
            return adapter_pci(dev);
        }
    }
    femu_cxl_need_bql();
    return NULL;
}

/* Publish @w's root port for adapter_route_fast(); BQL and CXL lock. */
static void adapter_window_port(FemuCxlWindow *w)
{
    PCIHostState *hb;

    if (w->port || w->fw->num_targets != 1 || !femu_cxl_locked()) {
        return;
    }
    hb = adapter_host(w->fw, 0);
    if (hb && hb->bus && pci_bus_is_cxl(hb->bus) &&
        cxl_get_hb_passthrough(hb)) {
        w->port = pcie_find_port_first(hb->bus);
    }
}

/* Route with the BQL if this thread holds it, else under the CXL lock. */
static PCIDevice *adapter_route_locked(FemuCxlWindow *w, hwaddr addr)
{
    if (bql_locked()) {
        adapter_window_port(w);
        return adapter_route(w->fw, addr);
    }
    return adapter_route_fast(w);
}

/*
 * With @mapped, fill the page instead of moving data, and report whether it
 * is now mapped directly; anything that cannot be mapped is an error.
 * @flags (FEMU_CXL_FILL_*) go to the fill.
 */
static MemTxResult adapter_access(FemuCxlWindow *w, hwaddr offset,
                                   uint64_t *data, unsigned size, bool write,
                                   MemTxAttrs attrs, bool *mapped,
                                   unsigned flags)
{
    unsigned reroutes = 0;

    for (;;) {
        PCIDevice *dev = adapter_route_locked(w, offset);
        /* The route without the BQL finds only femu-cxl-ssd devices. */
        bool femu = dev && (!bql_locked() ||
                            object_dynamic_cast(OBJECT(dev),
                                                TYPE_FEMU_CXL_SSD));
        MemTxResult result;

        /*
         * Nothing decodes the address: answer as the window would, without
         * letting its own router see decoder values that make it assert.
         */
        if (mapped && !femu) {
            return MEMTX_ERROR;
        }
        if (!dev) {
            if (!write) {
                *data = 0;
            }
            return write ? MEMTX_OK : MEMTX_ERROR;
        }
        if (!femu) {
            return write ? memory_region_dispatch_write(&w->fw->mr, offset,
                                *data, size_memop(size) | MO_LE, attrs) :
                           memory_region_dispatch_read(&w->fw->mr, offset,
                                data, size_memop(size) | MO_LE, attrs);
        }
        femu_cxl_lock();
        result = adapter_media_access(w, offset,
                                      container_of(dev, FemuCxlSsd,
                                                   parent_obj.parent_obj),
                                      data, size, write, mapped, flags);
        femu_cxl_unlock();
        if (result != ADAPTER_REROUTE) {
            return result;
        }
        /* A fill is retried by its caller; never spin here for it. */
        if (mapped && ++reroutes > ADAPTER_FILL_REROUTES) {
            return MEMTX_ERROR;
        }
    }
}

/*
 * The part of adapter_access() for a femu-cxl-ssd, under the CXL lock.
 * Returns ADAPTER_REROUTE when the decoders changed while it waited for the
 * gate, so the caller routes the access again.
 */
static MemTxResult adapter_media_access(FemuCxlWindow *w, hwaddr offset,
                                        FemuCxlSsd *cxl, uint64_t *data,
                                        unsigned size, bool write,
                                        bool *mapped, unsigned flags)
{
    uint64_t hpa = w->fw->base + offset;
    FemuCxlMedia *s = &cxl->media;
    CXLType3Dev *ct3d = CXL_TYPE3(cxl);
    MemTxResult result;
    uint64_t dpa;
    bool shared;

    /* Memslot mappings and ratios rebuild the memory map: BQL. */
    if (!bql_locked() && s->direct.memslot) {
        femu_cxl_need_bql();
        return MEMTX_ERROR;
    }
    if (!adapter_translate(ct3d, hpa, size, &dpa)) {
        return MEMTX_ERROR;
    }
    if (cxl_dev_media_disabled(&ct3d->cxl_dstate)) {
        /* Disabled media keeps trapping, so it is never mapped. */
        if (mapped) {
            return MEMTX_ERROR;
        }
        if (!write) {
            qemu_guest_getrandom_nofail(data, size);
        }
        return MEMTX_OK;
    }
    /*
     * Inside a device's re-entrancy guard, typically another device's DMA,
     * waiting would release the BQL, and that device would then refuse
     * other threads' accesses as re-entrant. See femu_cxl_access_nowait().
     */
    if (qemu_in_guarded_io()) {
        if (mapped || !s->started || s->closing) {
            return MEMTX_ERROR;
        }
        return femu_cxl_access_nowait(s, dpa, data, size, write);
    }
    /* Inject a decoder change while this access waits for the gate. */
    if (cxl->test_change_dpa) {
        uint32_t *regs = ct3d->cxl_cstate.crb.cache_mem_registers;

        cxl->test_change_dpa = false;
        stl_le_p(regs + R_CXL_HDM_DECODER0_DPA_SKIP_LO, 256 * MiB);
    }
    object_ref(OBJECT(cxl));
    shared = femu_cxl_concurrent(s);
    if (shared) {
        femu_cxl_enter_access(s);
    } else {
        femu_cxl_enter(s);
    }
    /* Decoders may have changed while waiting; complete as they are now. */
    if (adapter_route_locked(w, offset) != adapter_pci(cxl)) {
        result = ADAPTER_REROUTE;
    } else if (mapped && !bql_locked() && s->direct.fast &&
               der_windows_stale(&s->direct)) {
        /*
         * An invalidation while this fill waited for the gate: its map
         * would scan the windows, so it runs under the BQL instead, before
         * it counts anything.
         */
        femu_cxl_need_bql();
        result = MEMTX_ERROR;
    } else if (!s->started || s->closing ||
               !adapter_translate(ct3d, hpa, size, &dpa)) {
        result = MEMTX_ERROR;
    } else if (cxl_dev_media_disabled(&ct3d->cxl_dstate)) {
        if (mapped) {
            result = MEMTX_ERROR;
        } else {
            if (!write) {
                qemu_guest_getrandom_nofail(data, size);
            }
            result = MEMTX_OK;
        }
    } else {
        /* Invalidation revoked a memslot ratio; map it again first. */
        if (s->direct.ratio && !s->direct.cylon && !s->direct.ratio_end) {
            cxl_ratio_restore(cxl, NULL);
        }
        result = mapped ? femu_cxl_fill(s, hpa, dpa, mapped, flags) :
                 femu_cxl_access(s, hpa, dpa, data, size, write);
    }
    if (shared) {
        femu_cxl_leave_access(s);
    } else {
        femu_cxl_leave(s);
    }
    cxl_unref(cxl);
    return result;
}

static MemTxResult adapter_read(void *opaque, hwaddr offset, uint64_t *data,
                                unsigned size, MemTxAttrs attrs)
{
    return adapter_access(opaque, offset, data, size, false, attrs, NULL, 0);
}

static MemTxResult adapter_write(void *opaque, hwaddr offset, uint64_t data,
                                 unsigned size, MemTxAttrs attrs)
{
    return adapter_access(opaque, offset, &data, size, true, attrs, NULL, 0);
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
    FEMU_CXL_LOCK_GUARD();

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

/* The CXL lock protects the window list, which BQL-free fault exits read. */
static void adapter_detach(FemuCxlSsd *dev)
{
    assert(femu_cxl_locked());
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

    assert(femu_cxl_locked());
    s->invalidations++;
    if (s->started) {
        femu_cxl_der_clear(&s->direct);
    }
}

/*
 * A configuration write that changes routing runs between two
 * invalidations. The CXL lock is not held across the parent's write, which
 * can rebuild the memory map; a fault exit that routes while it changes
 * installs no mapping that the second invalidation does not revoke, and one
 * that starts after it sees the new routing.
 */
static void adapter_config_write(PCIDevice *dev, uint32_t addr,
                                   uint32_t value, int size)
{
    WITH_FEMU_CXL_LOCK() {
        cxl_invalidate(CXL_TYPE3(dev));
    }
    parent_config_write(dev, addr, value, size);
    WITH_FEMU_CXL_LOCK() {
        cxl_invalidate(CXL_TYPE3(dev));
    }
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
    FEMU_CXL_LOCK_GUARD();

    /* The decoders change under the lock that fault exits read them with. */
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

/* Get LSA carries a control command, not a configuration change. */
static bool adapter_command_changes(CXLCCI *cci, uint8_t set, uint8_t cmd)
{
    CXLType3Dev *dev = CXL_TYPE3(cci->d);

    return !(cci == &dev->cci && FEMU_CXL_SSD(dev)->media.lsa_control &&
             (set << 8 | cmd) == 0x4102);
}

/*
 * A mailbox command runs under the CXL lock, from this hook to the post hook,
 * so a fault exit never sees the media state or capacity it changes half
 * way. The handlers never wait for vCPUs; a Get LSA control command that
 * waits lets the lock go like any wait.
 */
static void adapter_pre_command(void *opaque, uint8_t set, uint8_t cmd)
{
    CXLCCI *cci = opaque;
    CXLType3Dev *dev = CXL_TYPE3(cci->d);

    femu_cxl_lock();
    if (adapter_command_changes(cci, set, cmd)) {
        cxl_invalidate(dev);
    }
    FEMU_CXL_SSD(dev)->lsa_limit = cci->payload_max;
}

static void adapter_post_command(void *opaque, uint8_t set, uint8_t cmd)
{
    femu_cxl_unlock();
}

static void adapter_cci_hook(CXLCCI *cci, CXLType3Dev *dev)
{
    cci->pre_command = adapter_pre_command;
    cci->post_command = adapter_post_command;
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

/* The lock covers the parent's reset too: it clears the decoders. */
static void adapter_reset_hold(Object *obj, ResetType type)
{
    CXLType3Dev *dev = CXL_TYPE3(obj);
    FEMU_CXL_LOCK_GUARD();

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
    FEMU_CXL_LOCK_GUARD();

    object_ref(obj);
    femu_cxl_enter(s);
    if (!s->started || s->closing || !value) {
        goto out;
    }
    femu_cxl_der_clear(&s->direct);
    /* Pinned pages are written back but stay resident. */
    if (!femu_cxl_cache_clear(&s->cache, femu_cxl_evict, &op) ||
        !femu_cxl_cache_clean_pinned(&s->cache, femu_cxl_evict, &op)) {
        error_setg(errp, "CXL cache cannot flush: a page is in use");
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

static bool cxl_fast_load_get(Object *obj, Error **errp)
{
    FEMU_CXL_LOCK_GUARD();

    return FEMU_CXL_SSD(obj)->media.fast_load;
}

/*
 * Turning fast load off is a barrier: the gate waits for admitted accesses,
 * then the NAND work they queued drains, so measurement starts on an idle
 * model. The cache stays as loaded.
 */
static void cxl_fast_load_set(Object *obj, bool value, Error **errp)
{
    FemuCxlMedia *s = &FEMU_CXL_SSD(obj)->media;
    FEMU_CXL_LOCK_GUARD();

    object_ref(obj);
    femu_cxl_enter(s);
    if (value == s->fast_load) {
        goto out;
    }
    if (!value) {
        s->fast_load_drain_ns = s->started && !s->closing ?
                                femu_cxl_drain(s) : 0;
    }
    s->fast_load = value;
out:
    femu_cxl_leave(s);
    object_unref(obj);
}

static void cxl_stats_reset(Object *obj, bool value, Error **errp)
{
    FemuCxlMedia *s = &FEMU_CXL_SSD(obj)->media;
    FEMU_CXL_LOCK_GUARD();

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
    uint32_t value;

    WITH_FEMU_CXL_LOCK() {
        value = !strcmp(name, "cache-ways") ? s->cache_ways :
                !strcmp(name, "prefetch-degree") ? s->prefetch_degree :
                s->prefetch_stride;
    }
    visit_type_uint32(v, name, &value, errp);
}

/* The FTL worker adds to this without the BQL. */
static void cxl_dma_media_ns_get(Object *obj, Visitor *v, const char *name,
                                 void *opaque, Error **errp)
{
    uint64_t value = qatomic_read(&FEMU_CXL_SSD(obj)->media.dma_media_ns);

    visit_type_uint64(v, name, &value, errp);
}

static void cxl_runtime_set(Object *obj, Visitor *v, const char *name,
                            void *opaque, Error **errp)
{
    FemuCxlMedia *s = &FEMU_CXL_SSD(obj)->media;
    uint32_t value;
    FEMU_CXL_LOCK_GUARD();

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
                error_setg(errp, "CXL cache cannot rebuild: a page is in use");
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
    FEMU_CXL_LOCK_GUARD();

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
    FEMU_CXL_LOCK_GUARD();

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
    uint64_t value;

    WITH_FEMU_CXL_LOCK() {
        value = !strcmp(name, "der-ratio") ? s->direct.ratio :
                !strcmp(name, "control-command") ? s->control_command :
                                                   s->control_argument;
    }
    visit_type_uint64(v, name, &value, errp);
}

static void cxl_control_set(Object *obj, Visitor *v, const char *name,
                            void *opaque, Error **errp)
{
    FemuCxlMedia *s = &FEMU_CXL_SSD(obj)->media;
    uint64_t value;
    Error *local_err = NULL;
    FEMU_CXL_LOCK_GUARD();

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
 * Commands that never drop the locks, so they can finish inside the mailbox
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
    FEMU_CXL_LOCK_GUARD();

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
    FEMU_CXL_LOCK_GUARD();

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
    FEMU_CXL_LOCK_GUARD();

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
     * Under TCG other vCPUs keep TLB entries for a revoked alias until their
     * queued flush runs, so they keep reaching the page directly after the
     * device has taken it back. Ratio mappings use the same aliases, so
     * refuse the mode rather than any later mapping.
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
    if (!s->direct.revoke_batch ||
        s->direct.revoke_batch > FEMU_CXL_REVOKE_BATCH_MAX) {
        error_setg(errp, "cylon-revoke-batch must be 1 to %d",
                   FEMU_CXL_REVOKE_BATCH_MAX);
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
    WITH_FEMU_CXL_LOCK() {
        femu_cxl_start(s, memory_region_get_ram_ptr(mr), size, policy);
        femu_cxl_der_init(&s->direct, FEMU_CXL_SSD(dev), s->der, &s->cache);
        s->closing = false;
        s->started = true;
        if (!adapter_live) {
            adapter_live = g_ptr_array_new();
        }
        FEMU_CXL_SSD(dev)->port = pci_get_bus(dev)->parent_dev;
        g_ptr_array_add(adapter_live, dev);
    }
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
    FEMU_CXL_LOCK_GUARD();

    /* A BQL-free fault exit no longer routes here; see adapter_route_fast(). */
    g_ptr_array_remove(adapter_live, dev);
    femu_cxl_cca_stop(s);
    /*
     * A guest unplug arrives inside the host bridge's dispatch guard, so do
     * not wait for an access sleeping in its media delay. Revoke now; that
     * access holds a reference and frees the media as it leaves the gate.
     * With the gate idle, the teardown still waits for the worker, which
     * can be in device DMA work and a long collection: inside a guard, a
     * bottom half runs it.
     */
    s->closing = true;
    if (s->busy || s->accesses || qemu_in_guarded_io()) {
        femu_cxl_der_disable(&s->direct);
        s->release = cxl_media_release;
        if (!s->busy && !s->accesses) {
            femu_cxl_release_later(s);
        }
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

static bool cxl_der_emul_exit(Object *obj, Error **errp)
{
    FEMU_CXL_LOCK_GUARD();

    return FEMU_CXL_SSD(obj)->media.direct.emul_exit;
}

/* The version is per VM: every device reports the VM's state. */
static bool cxl_der_emul_v2(Object *obj, Error **errp)
{
    FEMU_CXL_LOCK_GUARD();

    return cylon_v2;
}

static bool cxl_der_active(Object *obj, Error **errp)
{
    FEMU_CXL_LOCK_GUARD();

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

/*
 * qtest hooks for the Cylon fill path: fill a page as a fault exit would
 * (test-fill, a DPA), protect or release a page (test-protect,
 * test-unprotect, an LPN), all for the vCPU that test-owner names, and race
 * the next fill (test-fill-race). test-revoke-ahead and
 * test-revoke-ahead-keep fail when a fill, or a refault fill, of test-owner
 * could not revoke an LPN ahead of its eviction. test-fault-fill serves a
 * fault exit at a GPA, with its waits; test-protect-window sets how long
 * another vCPU's protection stops a fill.
 */
static void adapter_test_fill(Object *obj, Visitor *v, const char *name,
                              void *opaque, Error **errp)
{
    FemuCxlMedia *s = &FEMU_CXL_SSD(obj)->media;
    uint64_t value;
    bool mapped;
    FEMU_CXL_LOCK_GUARD();

    if (!visit_type_uint64(v, name, &value, errp)) {
        return;
    }
    object_ref(obj);
    femu_cxl_enter(s);
    if (!s->started || s->closing) {
        error_setg(errp, "the device is not running");
    } else if (!strcmp(name, "test-fill")) {
        /* As a refault fills: the vCPU's protected pages stay. */
        if (femu_cxl_fill(s, value, value, &mapped,
                          FEMU_CXL_FILL_KEEP_OWN) != MEMTX_OK) {
            error_setg(errp, "the fill failed");
        }
    } else if (!strcmp(name, "test-protect")) {
        femu_cxl_protect(s, s->test_owner, value);
    } else if (g_str_has_prefix(name, "test-revoke-ahead")) {
        FemuCxlOp op = {
            .s = s, .owner = s->test_owner, .demand = true, .fill = true,
            .keep_own = !strcmp(name, "test-revoke-ahead-keep"),
        };

        if (!femu_cxl_revoke_ahead_ok(s, &op, value,
                                      qemu_clock_get_ns(QEMU_CLOCK_REALTIME))) {
            error_setg(errp, "a revocation cannot take the page ahead");
        }
    } else {
        femu_cxl_unprotect(s, s->test_owner, value);
    }
    femu_cxl_leave(s);
    object_unref(obj);
}

static void adapter_test_owner(Object *obj, Visitor *v, const char *name,
                               void *opaque, Error **errp)
{
    int32_t value;
    FEMU_CXL_LOCK_GUARD();

    if (!visit_type_int32(v, name, &value, errp)) {
        return;
    }
    if (value < -1) {
        error_setg(errp, "test-owner must be -1 or a vCPU index");
        return;
    }
    FEMU_CXL_SSD(obj)->media.test_owner = value;
}

static void adapter_test_protect_window(Object *obj, Visitor *v,
                                        const char *name, void *opaque,
                                        Error **errp)
{
    uint64_t value;
    FEMU_CXL_LOCK_GUARD();

    if (!visit_type_uint64(v, name, &value, errp)) {
        return;
    }
    /* Keeps since + window far from INT64_MAX. */
    if (value > 3600 * NANOSECONDS_PER_SECOND) {
        error_setg(errp, "test-protect-window is at most one hour");
        return;
    }
    FEMU_CXL_SSD(obj)->media.protect_window_ns = value;
}

/*
 * qtest only. test-guarded-write writes the GPA as its own value inside a
 * re-entrancy guard, as a device's DMA does. test-ftl-hold makes the
 * worker hold the FTL mutex in its next request until it is set to 0 (or
 * for at most that many ms), and test-ftl-holding reports whether it
 * holds. test-ftl-delay makes each device DMA operation take that many ms
 * more under the FTL mutex. test-posted-done counts device DMA operations
 * run. test-lock-mutex reports whether the CXL lock is a mutex, and
 * setting it makes it one, as version 2 does.
 */
static void adapter_test_guarded_write(Object *obj, Visitor *v,
                                       const char *name, void *opaque,
                                       Error **errp)
{
    uint64_t value;
    MemTxResult result;

    if (!visit_type_uint64(v, name, &value, errp)) {
        return;
    }
    qemu_guarded_io_enter();
    address_space_stq_le(&address_space_memory, value, value,
                         MEMTXATTRS_UNSPECIFIED, &result);
    qemu_guarded_io_leave();
    if (result != MEMTX_OK) {
        error_setg(errp, "the guarded write failed");
    }
}

static void adapter_test_ftl_hold(Object *obj, Visitor *v, const char *name,
                                  void *opaque, Error **errp)
{
    FemuCxlMedia *s = &FEMU_CXL_SSD(obj)->media;
    uint64_t *ms = !strcmp(name, "test-ftl-hold") ? &s->test_ftl_hold_ms :
                                                    &s->test_ftl_delay_ms;
    uint64_t value;

    if (!visit_type_uint64(v, name, &value, errp)) {
        return;
    }
    if (value > 60000) {
        error_setg(errp, "%s is at most 60000 ms", name);
        return;
    }
    qatomic_set(ms, value);
}

static bool adapter_test_ftl_holding(Object *obj, Error **errp)
{
    return qatomic_read(&FEMU_CXL_SSD(obj)->media.test_ftl_holding);
}

static void adapter_test_posted_done(Object *obj, Visitor *v,
                                     const char *name, void *opaque,
                                     Error **errp)
{
    FemuCxlMedia *s = &FEMU_CXL_SSD(obj)->media;
    uint64_t value = 0;

    if (s->ftl && s->started) {
        qemu_mutex_lock(&s->post_lock);
        value = s->posted_done;
        qemu_mutex_unlock(&s->post_lock);
    }
    visit_type_uint64(v, name, &value, errp);
}

/*
 * Choose the fault exit version as the first Cylon slot of the VM does, as
 * if the host kernel offered the given version of KVM_CAP_CYLON_FAULT_EXIT.
 * KVM is not asked or changed.
 */
static void adapter_test_fault_version(Object *obj, Visitor *v,
                                       const char *name, void *opaque,
                                       Error **errp)
{
    int64_t version;
    FEMU_CXL_LOCK_GUARD();

    if (!visit_type_int64(v, name, &version, errp)) {
        return;
    }
    if (cylon_fault_version(&FEMU_CXL_SSD(obj)->media,
                            MIN(MAX(version, 0), 2))) {
        adapter_lock_bql_free();
        cylon_v2 = true;
    }
}

static bool adapter_test_lock_mutex(Object *obj, Error **errp)
{
    return femu_cxl_lock_is_bql_free();
}

static void adapter_test_lock_mutex_set(Object *obj, bool value,
                                        Error **errp)
{
    FEMU_CXL_LOCK_GUARD();

    if (value) {
        adapter_lock_bql_free();
    }
}

static bool cylon_test_fault_fill(uint64_t gpa, Error **errp);
static bool cylon_test_fault(FemuCxlSsd *dev, uint64_t gpa, bool decode,
                             Error **errp);
static void cylon_storm_start(FemuCxlSsd *dev, const char *spec,
                              Error **errp);
static void cylon_storm_wait(void);
static const char *cylon_storm_check(FemuCxlSsd *dev);
static uint64_t cylon_storm_result(const char *name);

/*
 * test-storm starts threads that send fault exits without the BQL (see
 * cylon_storm_start()); test-storm-wait joins them and fails if the shared
 * bookkeeping does not add up; test-storm-served, -stops and -ns report.
 */
static void adapter_test_storm(Object *obj, const char *value, Error **errp)
{
    cylon_storm_start(FEMU_CXL_SSD(obj), value, errp);
}

static void adapter_test_storm_wait(Object *obj, bool value, Error **errp)
{
    const char *why;

    cylon_storm_wait();
    WITH_FEMU_CXL_LOCK() {
        why = cylon_storm_check(FEMU_CXL_SSD(obj));
    }
    if (why) {
        error_setg(errp, "%s", why);
    }
}

static void adapter_test_storm_get(Object *obj, Visitor *v, const char *name,
                                   void *opaque, Error **errp)
{
    uint64_t value = cylon_storm_result(name);

    visit_type_uint64(v, name, &value, errp);
}

static void adapter_test_map(Object *obj, bool value, Error **errp)
{
    FEMU_CXL_LOCK_GUARD();

    FEMU_CXL_SSD(obj)->media.test_map = value;
}

static void adapter_test_rip(Object *obj, Visitor *v, const char *name,
                             void *opaque, Error **errp)
{
    FEMU_CXL_LOCK_GUARD();

    visit_type_uint64(v, name, &FEMU_CXL_SSD(obj)->media.test_rip, errp);
}

static void adapter_test_fault(Object *obj, Visitor *v, const char *name,
                               void *opaque, Error **errp)
{
    uint64_t gpa;
    FEMU_CXL_LOCK_GUARD();

    if (visit_type_uint64(v, name, &gpa, errp)) {
        FemuCxlSsd *dev = FEMU_CXL_SSD(obj);
        uint64_t n = MAX(dev->test_fault_repeats, 1);

        dev->test_fault_repeats = 0;
        object_ref(obj);
        while (n-- && cylon_test_fault(dev, gpa,
                                       !strcmp(name, "test-fault-decode"),
                                       errp)) {
            continue;
        }
        object_unref(obj);
    }
}

static void adapter_test_fault_repeats(Object *obj, Visitor *v,
                                       const char *name, void *opaque,
                                       Error **errp)
{
    uint64_t n;
    FEMU_CXL_LOCK_GUARD();

    if (visit_type_uint64(v, name, &n, errp)) {
        FEMU_CXL_SSD(obj)->test_fault_repeats = n;
    }
}

/* Serve a fault exit at a GPA as the vCPU that test-owner names would. */
static void adapter_test_fault_fill(Object *obj, Visitor *v, const char *name,
                                    void *opaque, Error **errp)
{
    uint64_t gpa;
    FEMU_CXL_LOCK_GUARD();

    if (visit_type_uint64(v, name, &gpa, errp)) {
        object_ref(obj);
        cylon_test_fault_fill(gpa, errp);
        object_unref(obj);
    }
}

static void adapter_test_fill_race(Object *obj, bool value, Error **errp)
{
    FEMU_CXL_LOCK_GUARD();

    FEMU_CXL_SSD(obj)->media.test_fill_race = value;
}

static void adapter_test_prefetch_race(Object *obj, Visitor *v,
                                       const char *name, void *opaque,
                                       Error **errp)
{
    FEMU_CXL_LOCK_GUARD();

    visit_type_uint64(v, name, &FEMU_CXL_SSD(obj)->media.test_prefetch_race,
                      errp);
}

/* The other access's fill fails: it drops its entry and its hold. */
static void adapter_test_prefetch_race_end(Object *obj, bool value,
                                           Error **errp)
{
    FemuCxlMedia *s = &FEMU_CXL_SSD(obj)->media;
    FemuCxlEntry *e;
    FEMU_CXL_LOCK_GUARD();

    object_ref(obj);
    femu_cxl_enter(s);
    if (s->test_race_active) {
        s->test_race_active = false;
        e = g_hash_table_lookup(s->cache.entries, &s->test_race_lpn);
        femu_cxl_fill_failed(s, s->test_race_lpn, e);
        g_hash_table_remove(s->pages, &s->test_race_lpn);
        qemu_cond_broadcast(&s->idle);
        s->cache_entries = g_hash_table_size(s->cache.entries);
    }
    femu_cxl_leave(s);
    object_unref(obj);
}

static void adapter_test_change_dpa(Object *obj, bool value, Error **errp)
{
    FEMU_CXL_LOCK_GUARD();

    FEMU_CXL_SSD(obj)->test_change_dpa = value;
}

/*
 * Sanitize disables the media only while its background operation runs;
 * let tests keep it disabled for the caching API.
 */
static void adapter_test_media_disabled(Object *obj, bool value, Error **errp)
{
    FEMU_CXL_LOCK_GUARD();

    FEMU_CXL_SSD(obj)->test_media_disabled = value;
}

/*
 * Fault exits update counters without the BQL, so a reader takes the CXL
 * lock, as every writer holds it.
 */
static void cxl_counter_get(Object *obj, Visitor *v, const char *name,
                            void *opaque, Error **errp)
{
    uint64_t value;

    WITH_FEMU_CXL_LOCK() {
        value = *(uint64_t *)opaque;
    }
    visit_type_uint64(v, name, &value, errp);
}

static void cxl_add_counter(Object *obj, const char *name, uint64_t *counter)
{
    object_property_add(obj, name, "uint64", cxl_counter_get, NULL, NULL,
                        counter);
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
        object_property_add(obj, "test-fill", "uint64", NULL,
                            adapter_test_fill, NULL, NULL);
        object_property_add(obj, "test-protect", "uint64", NULL,
                            adapter_test_fill, NULL, NULL);
        object_property_add(obj, "test-unprotect", "uint64", NULL,
                            adapter_test_fill, NULL, NULL);
        object_property_add(obj, "test-revoke-ahead", "uint64", NULL,
                            adapter_test_fill, NULL, NULL);
        object_property_add(obj, "test-revoke-ahead-keep", "uint64", NULL,
                            adapter_test_fill, NULL, NULL);
        object_property_add(obj, "test-owner", "int32", NULL,
                            adapter_test_owner, NULL, NULL);
        object_property_add(obj, "test-protect-window", "uint64", NULL,
                            adapter_test_protect_window, NULL, NULL);
        object_property_add(obj, "test-fault-fill", "uint64", NULL,
                            adapter_test_fault_fill, NULL, NULL);
        object_property_add(obj, "test-fault", "uint64", NULL,
                            adapter_test_fault, NULL, NULL);
        object_property_add(obj, "test-fault-decode", "uint64", NULL,
                            adapter_test_fault, NULL, NULL);
        object_property_add(obj, "test-fault-repeats", "uint64", NULL,
                            adapter_test_fault_repeats, NULL, NULL);
        object_property_add_bool(obj, "test-map", NULL, adapter_test_map);
        object_property_add(obj, "test-rip", "uint64", NULL,
                            adapter_test_rip, NULL, NULL);
        object_property_add_bool(obj, "test-fill-race", NULL,
                                 adapter_test_fill_race);
        object_property_add(obj, "test-prefetch-race", "uint64", NULL,
                            adapter_test_prefetch_race, NULL, NULL);
        object_property_add_bool(obj, "test-prefetch-race-end", NULL,
                                 adapter_test_prefetch_race_end);
        object_property_add_str(obj, "test-storm", NULL, adapter_test_storm);
        object_property_add_bool(obj, "test-storm-wait", NULL,
                                 adapter_test_storm_wait);
        object_property_add(obj, "test-storm-served", "uint64",
                            adapter_test_storm_get, NULL, NULL, NULL);
        object_property_add(obj, "test-storm-stops", "uint64",
                            adapter_test_storm_get, NULL, NULL, NULL);
        object_property_add(obj, "test-storm-ns", "uint64",
                            adapter_test_storm_get, NULL, NULL, NULL);
        object_property_add(obj, "test-guarded-write", "uint64", NULL,
                            adapter_test_guarded_write, NULL, NULL);
        object_property_add(obj, "test-ftl-hold", "uint64", NULL,
                            adapter_test_ftl_hold, NULL, NULL);
        object_property_add(obj, "test-ftl-delay", "uint64", NULL,
                            adapter_test_ftl_hold, NULL, NULL);
        object_property_add_bool(obj, "test-ftl-holding",
                                 adapter_test_ftl_holding, NULL);
        object_property_add(obj, "test-posted-done", "uint64",
                            adapter_test_posted_done, NULL, NULL, NULL);
        object_property_add(obj, "test-fault-version", "int64", NULL,
                            adapter_test_fault_version, NULL, NULL);
        object_property_add_bool(obj, "test-lock-mutex",
                                 adapter_test_lock_mutex,
                                 adapter_test_lock_mutex_set);
    }
    FEMU_CXL_SSD(obj)->lsa_limit = CXL_MAILBOX_MAX_PAYLOAD_SIZE;
    s->owner = obj;
    /* No vCPU: outside qtest, accesses from other threads match nothing. */
    s->test_owner = -1;
    s->protect_window_ns = FEMU_CXL_PROTECT_WINDOW_NS;
    s->test_rip = 0x1000;
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
    cxl_add_counter(obj, "control-status", &s->control_status);
    cxl_add_counter(obj, "last-read-hits", &s->snapshot[0]);
    cxl_add_counter(obj, "last-read-misses", &s->snapshot[1]);
    cxl_add_counter(obj, "last-write-hits", &s->snapshot[2]);
    cxl_add_counter(obj, "last-write-misses", &s->snapshot[3]);
    cxl_add_counter(obj, "last-inserts", &s->snapshot[4]);
    cxl_add_counter(obj, "last-evictions", &s->snapshot[5]);
    cxl_add_counter(obj, "last-entries", &s->snapshot[6]);
    cxl_add_counter(obj, "last-prefetch-inserts", &s->snapshot[7]);
    s->cache_ways = 16;
    s->prefetch_stride = 1;
    object_property_add(obj, "cache-ways", "uint32", cxl_runtime_get,
                        cxl_runtime_set, NULL, NULL);
    object_property_add(obj, "prefetch-degree", "uint32", cxl_runtime_get,
                        cxl_runtime_set, NULL, NULL);
    object_property_add(obj, "prefetch-stride", "uint32", cxl_runtime_get,
                        cxl_runtime_set, NULL, NULL);
    object_property_add_bool(obj, "stats-reset", NULL, cxl_stats_reset);
    object_property_add_bool(obj, "fast-load", cxl_fast_load_get,
                             cxl_fast_load_set);
    cxl_add_counter(obj, "fast-load-drain-ns", &s->fast_load_drain_ns);
    cxl_add_counter(obj, "prefetch-inserts", &s->prefetch_inserts);
    cxl_add_counter(obj, "cache-entries", &s->cache_entries);
    cxl_add_counter(obj, "write-misses", &s->write_misses);
    cxl_add_counter(obj, "write-hits", &s->write_hits);
    cxl_add_counter(obj, "read-misses", &s->read_misses);
    cxl_add_counter(obj, "read-hits", &s->read_hits);
    cxl_add_counter(obj, "invalidations", &s->invalidations);
    cxl_add_counter(obj, "nvme-drops", &s->nvme_drops);
    cxl_add_counter(obj, "log-dropped", &s->log_dropped);
    object_property_add_bool(obj, "der-active", cxl_der_active, NULL);
    cxl_add_counter(obj, "der-remaps", &s->direct.remaps);
    cxl_add_counter(obj, "der-revocations", &s->direct.revocations);
    cxl_add_counter(obj, "der-quiet-revocations", &s->direct.quiet_revocations);
    cxl_add_counter(obj, "der-fallbacks", &s->direct.fallbacks);
    object_property_add_bool(obj, "der-emul-exit", cxl_der_emul_exit, NULL);
    object_property_add_bool(obj, "der-emul-v2", cxl_der_emul_v2, NULL);
    cxl_add_counter(obj, "der-fault-reads", &s->direct.fault_reads);
    cxl_add_counter(obj, "der-fault-writes", &s->direct.fault_writes);
    cxl_add_counter(obj, "der-fault-fetches", &s->direct.fault_fetches);
    cxl_add_counter(obj, "der-fault-page-walks", &s->direct.fault_walks);
    cxl_add_counter(obj, "der-fault-emulated", &s->direct.fault_emulated);
    cxl_add_counter(obj, "der-fault-unprotected", &s->direct.fault_unprotected);
    cxl_add_counter(obj, "der-fault-conflicts", &s->direct.fault_conflicts);
    cxl_add_counter(obj, "der-fault-overflows", &s->direct.fault_overflows);
    cxl_add_counter(obj, "der-revoke-flushes", &s->direct.revoke_flushes);
    cxl_add_counter(obj, "der-revoked-ahead", &s->direct.revoked_ahead);
    cxl_add_counter(obj, "der-ahead-remaps", &s->direct.ahead_remaps);
    cxl_add_counter(obj, "der-fault-bql", &s->direct.fault_bql);
    cxl_add_counter(obj, "der-emul-fills", &s->direct.emul_fills);
    cxl_add_counter(obj, "der-emul-fetch-fills", &s->direct.emul_fetch_fills);
    cxl_add_counter(obj, "der-emul-failures", &s->direct.emul_failures);
    cxl_add_counter(obj, "der-replacements", &s->direct.replacements);
    object_property_add_bool(obj, "flush-cache", NULL, cxl_flush);
    cxl_add_counter(obj, "der-probes", &s->direct.probes);
    cxl_add_counter(obj, "der-mapped", &s->direct.mapped);
    cxl_add_counter(obj, "media-time-ns", &s->media_ns);
    cxl_add_counter(obj, "media-reads", &s->media_reads);
    cxl_add_counter(obj, "media-writes", &s->media_writes);
    cxl_add_counter(obj, "media-full", &s->media_full);
    cxl_add_counter(obj, "gc-stalls", &s->gc_stalls);
    cxl_add_counter(obj, "gc-stall-ns", &s->gc_stall_ns);
    cxl_add_counter(obj, "gc-stall-max-ns", &s->gc_stall_max_ns);
    cxl_add_counter(obj, "dma-accesses", &s->dma_accesses);
    cxl_add_counter(obj, "dma-media-ops", &s->dma_media_ops);
    object_property_add(obj, "dma-media-time-ns", "uint64",
                        cxl_dma_media_ns_get, NULL, NULL, NULL);
    cxl_add_counter(obj, "cache-hits", &s->cache.hits);
    cxl_add_counter(obj, "cache-misses", &s->cache.misses);
    cxl_add_counter(obj, "cache-inserts", &s->cache.inserts);
    cxl_add_counter(obj, "cache-evictions", &s->cache.evictions);
    cxl_add_counter(obj, "cca-commands", &s->cca.commands);
    cxl_add_counter(obj, "cca-errors", &s->cca.errors);
    cxl_add_counter(obj, "cca-pinned", &s->cache.pinned);
    cxl_add_counter(obj, "cca-uncached", &s->cca.uncached);
    cxl_add_counter(obj, "cca-pin-fills", &s->cca.pin_fills);
    cxl_add_counter(obj, "cca-writebacks", &s->cca.writebacks);
    cxl_add_counter(obj, "cca-dropped", &s->cca.dropped);
    cxl_add_counter(obj, "cca-pinned-set-misses", &s->cca.pinned_set_misses);
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
    DEFINE_PROP_BOOL("cylon-emul-exit", FemuCxlSsd,
                     media.cylon_emul_exit, true),
    DEFINE_PROP_ON_OFF_AUTO("cylon-never-emulate", FemuCxlSsd,
                            media.cylon_never_emulate, ON_OFF_AUTO_AUTO),
    DEFINE_PROP_UINT32("cylon-fault-stop", FemuCxlSsd,
                       media.cylon_fault_stop, CYLON_FAULT_STOP),
    DEFINE_PROP_UINT32("cylon-revoke-batch", FemuCxlSsd,
                       media.direct.revoke_batch, 32),
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
    g_clear_pointer(&FEMU_CXL_SSD(obj)->media.protect, g_hash_table_destroy);
    g_clear_pointer(&FEMU_CXL_SSD(obj)->media.overflow, g_hash_table_destroy);
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
    FEMU_CXL_LOCK_GUARD();

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
    FEMU_CXL_LOCK_GUARD();

    s->nvme_ns = ns;
    n->cxl_done = &s->nvme_done;
    n->cxl_media = s;
    /* The bitmap cannot tell which pages earlier CXL traffic wrote. */
    if (s->entries || s->dma_accesses || s->direct.mapped ||
        s->direct.ratio) {
        femu_cxl_nvme_mark(s, 0, s->backend.size);
    }
}

/* The controller's threads are stopped; it may never have attached. */
static void cxl_nvme_detach(FemuCtrl *n)
{
    FemuCxlSsd *dev = FEMU_CXL_SSD(n->cxl_dev);
    FemuCxlMedia *s = &dev->media;
    FEMU_CXL_LOCK_GUARD();

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
        der->memslot = mode && !strcmp(mode, "memslot");
        der->available = der->memslot;
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

/* Whether der_window() must scan again, which needs the BQL. */
static bool der_windows_stale(FemuCxlDer *der)
{
    return !der->windows_valid ||
           der->windows_generation != der->dev->media.invalidations;
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

    if (der_windows_stale(der)) {
        /* The scan walks the QOM tree and the topology. */
        if (!bql_locked()) {
            femu_cxl_need_bql();
            return NULL;
        }
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

    assert(femu_cxl_locked());
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
        der->fallbacks += !femu_cxl_bql_needed();
        return false;
    }
    if (der->cylon) {
        return femu_cylon_map(der, fw, hpa, dpa);
    }
    /* Alias changes rebuild the memory map. */
    if (!bql_locked()) {
        femu_cxl_need_bql();
        return false;
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
    /*
     * Disabled media must keep trapping. The ratio stays set: the first
     * access after the media is enabled maps a memslot ratio again, and a
     * Cylon ratio maps page by page on access, or all at once at the next
     * flush.
     */
    if (cxl_dev_media_disabled(&dev->parent_obj.cxl_dstate)) {
        return true;
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
    if (ratio && cxl_dev_media_disabled(&dev->parent_obj.cxl_dstate)) {
        error_setg(errp, "a direct ratio cannot be set while the media is "
                   "disabled (sanitize)");
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

    assert(femu_cxl_locked());
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
 * How many more pages a revocation of the victim @lpn can take with its
 * own TLB flushes: zero unless Cylon version 2 batches revocations and
 * @lpn is mapped with an entry that needs the flushes.
 */
unsigned femu_cxl_der_batch(FemuCxlDer *der, uint64_t lpn)
{
    return der->cylon ? femu_cylon_batch(der, lpn) : 0;
}

/*
 * Revoke the victim @lpn and, sharing its flushes, the mappings of the
 * pages @ahead that the cache evicts next; those stay cached.
 */
void femu_cxl_der_remove_batch(FemuCxlDer *der, uint64_t lpn,
                               const uint64_t *ahead, unsigned n)
{
    if (der->cylon && n) {
        femu_cylon_remove_batch(der, lpn, ahead, n);
        return;
    }
    femu_cxl_der_remove(der, lpn);
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
#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#endif

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

/*
 * The pagemap descriptor. The slot holds one reference, and a fill that
 * checks a frame without the locks holds another, so unplug cannot close
 * it, and its number cannot be reused, under that read.
 */
typedef struct CylonPagemap {
    int fd;
    unsigned refs;
} CylonPagemap;

static void cylon_pagemap_put(CylonPagemap *pm)
{
    if (qatomic_fetch_dec(&pm->refs) == 1) {
        close(pm->fd);
        g_free(pm);
    }
}

struct FemuCylon {
    struct rcu_head rcu;
    FemuCxlDer *der;
    CXLFixedWindow *pending_window;
    bool detached;
    int pagemap;
    /* @pagemap, shared with fills that read it without the locks. */
    struct CylonPagemap *pm;
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
    /* The flush ioctl invalidates every translation of the VM. */
    bool flush_vm;
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

/*
 * KVM implements the flush ioctl with kvm_flush_remote_tlbs_range(), which
 * on VMX falls back to a flush of the whole VM: every vCPU is kicked and
 * runs a global INVEPT before it enters the guest again. Only a host that
 * itself runs on Hyper-V gets a flush of the one GFN, through the Hyper-V
 * range flush; there each revocation must keep its own flushes.
 */
static bool cylon_flush_covers_vm(void)
{
#if defined(__x86_64__) || defined(__i386__)
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    char vendor[13];

    __cpuid(1, eax, ebx, ecx, edx);
    if (!(ecx & (1U << 31))) {
        return true;
    }
    __cpuid(0x40000000, eax, ebx, ecx, edx);
    memcpy(vendor, &ebx, 4);
    memcpy(vendor + 4, &ecx, 4);
    memcpy(vendor + 8, &edx, 4);
    vendor[12] = 0;
    return strcmp(vendor, "Microsoft Hv");
#else
    return false;
#endif
}

static bool cylon_parameter(const char *path)
{
    g_autofree char *value = NULL;

    return g_file_get_contents(path, &value, NULL, NULL) &&
           (value[0] == 'Y' || value[0] == '1');
}

/*
 * Delete the slot. A fault exit may do this without the BQL: the slot is
 * outside QEMU's memory map (its ID is only reserved there, under the KVM
 * slots lock), and the kernel serializes slot updates itself.
 */
static void cylon_release(FemuCylon *c)
{
    unsigned i;

    assert(femu_cxl_locked());
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
    assert(femu_cxl_locked());
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
    /*
     * In SMM the vCPUs use another address space and another root, which
     * the shared leaf tables do not serve.
     */
    if (object_dynamic_cast(OBJECT(current_machine), TYPE_X86_MACHINE) &&
        x86_machine_is_smm_enabled(X86_MACHINE(current_machine))) {
        *reason = "Cylon requires -machine smm=off";
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
    c->flush_vm = cylon_flush_covers_vm();
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
    c->pm = g_new(CylonPagemap, 1);
    c->pm->fd = fd;
    c->pm->refs = 1;
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

/*
 * Exit reason and capability of the Cylon host kernel: an access to an
 * unmapped page of the dual-mode slot whose instruction KVM cannot emulate
 * (VEX/EVEX, most SSE with a memory operand) returns here with the GPA.
 */
#define CYLON_EXIT_FAULT 0x4359
#define CYLON_CAP_FAULT_EXIT 0x4359
/* RIP lies on the unmapped page: map it for the code, do not emulate. */
#define CYLON_FAULT_FETCH (1U << 1)
/*
 * Version 2: an access to a page whose leaf is not present, with its exact
 * type; KVM emulated nothing. Enable bits for KVM_ENABLE_CAP.
 */
#define CYLON_FAULT_ACCESS (1U << 2)
#define CYLON_FAULT_READ (1U << 3)
#define CYLON_FAULT_WRITE (1U << 4)
#define CYLON_FAULT_PAGE_WALK (1U << 6)
#define CYLON_FAULT_EXIT_ON 1
#define CYLON_FAULT_EXIT_V2 2


static uint64_t *cylon_sptep(FemuCylon *c, uint64_t index);

typedef struct CylonFault {
    uint64_t gpa;
    uint64_t rip;
    uint32_t flags;
    uint8_t insn_len;
    uint8_t insn_bytes;
    uint8_t pad[2];
    uint8_t insn[16];
} CylonFault;

QEMU_BUILD_BUG_ON(sizeof(CylonFault) > sizeof(((struct kvm_run *)0)->padding));

/*
 * Retries cover a revoked entry, a decoder change during the fill, and a
 * fill that waited for a way; the waits of one exit end within
 * CYLON_FAULT_WAIT_NS, after which the page goes to the emulator.
 */
#define CYLON_FAULT_TRIES 3
#define CYLON_FAULT_WAIT_NS (100 * 1000 * 1000)
/*
 * Progress across exits. KVM reports exits, not retired instructions, so a
 * repeat at one RIP may be a healthy loop whose page another vCPU evicted.
 * Count consecutive exits at one RIP whose page was already filled for that
 * RIP; the set of filled pages is cleared only when the RIP changes, so
 * cycling through pages cannot erase it. A livelock reaches the stop bound
 * (cylon-fault-stop, by default CYLON_FAULT_STOP) within seconds; a healthy
 * loop rarely exits that often back to back at one RIP with no exit
 * anywhere else. It is a watchdog, not proof: see cxlssd.md.
 */
#define CYLON_FAULT_WARN 1000
/*
 * The pages filled at one RIP, oldest dropped first: a set that is full
 * still records each new page, so a page that keeps failing is always in it.
 */
#define CYLON_FAULT_SET_MAX 4096
/* Consecutive exits at one RIP that FEMU served without a mapping. */
#define CYLON_FAULT_UNSERVED 1000
#define CYLON_FAULT_RECENT 8
/*
 * Version 2 working-set protection. KVM reports exits, not retired
 * instructions, so FEMU cannot tell one execution of a RIP from the next.
 * It keeps the 64 latest pages a vCPU filled at one RIP (enough for a
 * gather whose elements cross pages), oldest released first, and uses them
 * only as evidence: a fill evicts them freely, as a loop over distinct
 * pages needs, until the vCPU faults again on a page it already filled at
 * that RIP. That refault is the sign that the instruction needs pages that
 * evict each other; such a fill keeps the vCPU's protected pages, and a
 * page that then cannot stay goes to the emulator, which completes the
 * instruction. Fills of other vCPUs pass over the pages for a moment only:
 * a vCPU that stops faulting must not close a set to the others.
 */
#define CYLON_PROTECT_PAGES 64
/*
 * Pages mapped without a cache way for one instruction that the emulator
 * cannot run and whose pages do not fit in their set; see
 * cylon_fault_overflow().
 */
#define CYLON_OVERFLOW_PAGES 16

typedef struct CylonProtect {
    FemuCxlSsd *dev;
    uint64_t lpn;
    int owner;
    /* The fill was for a write fault. */
    bool write;
} CylonProtect;

/* Per vCPU, under the CXL lock. */
typedef struct CylonFaultTrack {
    CPUState *cpu;
    uint64_t rip;
    /* Page GPAs filled at @rip, and the same pages in fill order. */
    GHashTable *pages;
    GQueue order;
    uint64_t repeats;
    uint64_t unserved;
    /* The latest exit is on a page already filled at @rip. */
    bool refault;
    /* The latest exit's type is counted (it may be served twice). */
    bool counted;
    /* The latest exit GPAs at @rip, for reports. */
    uint64_t recent[CYLON_FAULT_RECENT];
    unsigned nrecent;
    int64_t warned_ms;
    /* The pages protected for @rip, oldest first (version 2). */
    CylonProtect protect[CYLON_PROTECT_PAGES];
    unsigned nprotect;
    /* Pages mapped outside the cache for the instruction at @rip. */
    CylonProtect overflow[CYLON_OVERFLOW_PAGES];
    unsigned noverflow;
} CylonFaultTrack;

/* Sized once for every possible vCPU, so entries never move. */
static CylonFaultTrack *cylon_fault_tracks;

static void cylon_fault_unprotect(CylonFaultTrack *t)
{
    while (t->nprotect) {
        CylonProtect *p = &t->protect[--t->nprotect];

        femu_cxl_unprotect(&p->dev->media, p->owner, p->lpn);
        cxl_unref(p->dev);
    }
}

static void cylon_overflow_release(CylonProtect *p)
{
    femu_cxl_overflow_release(&p->dev->media, p->lpn);
    cxl_unref(p->dev);
}

/* Release the overflow pages of the instruction; see cylon_fault_overflow(). */
static void cylon_fault_unoverflow(CylonFaultTrack *t)
{
    while (t->noverflow) {
        cylon_overflow_release(&t->overflow[--t->noverflow]);
    }
}

/*
 * Protect @lpn for the instruction at the vCPU's RIP. A page already held is
 * not taken twice, but a refill restarts its window for other vCPUs; at the
 * bound, the oldest page is released (counted).
 */
static void cylon_fault_protect(CylonFaultTrack *t, FemuCxlSsd *dev,
                                uint64_t lpn, bool write)
{
    unsigned i;

    for (i = 0; i < t->nprotect; i++) {
        if (t->protect[i].dev == dev && t->protect[i].lpn == lpn) {
            CylonProtect p = t->protect[i];

            /* The newest again: the window releases the oldest first. */
            memmove(&t->protect[i], &t->protect[i + 1],
                    (t->nprotect - i - 1) * sizeof(t->protect[0]));
            p.write |= write;
            t->protect[t->nprotect - 1] = p;
            femu_cxl_protect_renew(&dev->media, p.owner, lpn);
            return;
        }
    }
    if (t->nprotect == CYLON_PROTECT_PAGES) {
        CylonProtect *p = &t->protect[0];

        p->dev->media.direct.fault_unprotected++;
        femu_cxl_unprotect(&p->dev->media, p->owner, p->lpn);
        cxl_unref(p->dev);
        memmove(&t->protect[0], &t->protect[1],
                --t->nprotect * sizeof(t->protect[0]));
    }
    femu_cxl_protect(&dev->media, t->cpu->cpu_index, lpn);
    object_ref(OBJECT(dev));
    t->protect[t->nprotect++] = (CylonProtect) {
        .dev = dev, .lpn = lpn, .owner = t->cpu->cpu_index, .write = write,
    };
}

static void cylon_fault_track_clear(CylonFaultTrack *t)
{
    if (t->pages) {
        g_hash_table_remove_all(t->pages);
    }
    g_queue_clear(&t->order);
    cylon_fault_unprotect(t);
    cylon_fault_unoverflow(t);
    t->rip = 0;
    t->repeats = 0;
    t->unserved = 0;
    t->refault = false;
    t->nrecent = 0;
}

/* Drop every protection on @dev: it is reset or going away. BQL. */
static void cylon_fault_forget(FemuCxlSsd *dev)
{
    unsigned i;
    unsigned j;

    for (i = 0; cylon_fault_tracks && i < current_machine->smp.max_cpus;
         i++) {
        CylonFaultTrack *t = &cylon_fault_tracks[i];

        for (j = 0; j < t->nprotect;) {
            CylonProtect p = t->protect[j];

            if (p.dev != dev) {
                j++;
                continue;
            }
            memmove(&t->protect[j], &t->protect[j + 1],
                    (--t->nprotect - j) * sizeof(t->protect[0]));
            femu_cxl_unprotect(&dev->media, p.owner, p.lpn);
            object_unref(OBJECT(dev));
        }
        /* Reset and unplug drop the mappings themselves. */
        for (j = 0; j < t->noverflow;) {
            if (t->overflow[j].dev != dev) {
                j++;
                continue;
            }
            memmove(&t->overflow[j], &t->overflow[j + 1],
                    (--t->noverflow - j) * sizeof(t->overflow[0]));
            object_unref(OBJECT(dev));
        }
    }
    if (dev->media.overflow) {
        g_hash_table_remove_all(dev->media.overflow);
    }
}

/*
 * A destroyed vCPU (unplug, exit) releases what its last instruction held.
 * The next vCPU with its index starts clean, whatever its address.
 */
static void cylon_fault_vcpu_destroyed(CPUState *cpu)
{
    FEMU_CXL_LOCK_GUARD();

    if (cylon_fault_tracks && cpu->cpu_index < current_machine->smp.max_cpus) {
        cylon_fault_track_clear(&cylon_fault_tracks[cpu->cpu_index]);
        cylon_fault_tracks[cpu->cpu_index].cpu = NULL;
    }
}

/* A system reset restarts every vCPU. */
static void cylon_fault_tracks_reset(void *opaque)
{
    unsigned i;
    FEMU_CXL_LOCK_GUARD();

    for (i = 0; i < current_machine->smp.max_cpus; i++) {
        cylon_fault_track_clear(&cylon_fault_tracks[i]);
    }
}

/* Allocated with the BQL, before the first fault exit can arrive. */
static void cylon_fault_tracks_init(void)
{
    assert(bql_locked());
    if (!cylon_fault_tracks) {
        cylon_fault_tracks = g_new0(CylonFaultTrack,
                                    current_machine->smp.max_cpus);
        qemu_register_reset(cylon_fault_tracks_reset, NULL);
    }
}

static CylonFaultTrack *cylon_fault_track(CPUState *cpu)
{
    CylonFaultTrack *t;

    assert(femu_cxl_locked());
    if (!cylon_fault_tracks) {
        cylon_fault_tracks_init();
    }
    assert(cpu->cpu_index < current_machine->smp.max_cpus);
    t = &cylon_fault_tracks[cpu->cpu_index];
    if (!t->pages) {
        t->pages = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                         g_free, NULL);
    }
    /*
     * The destroy hook clears a removed vCPU's track; this check only
     * covers a vCPU that left without it.
     */
    if (t->cpu != cpu) {
        cylon_fault_track_clear(t);
        t->cpu = cpu;
    }
    return t;
}

/* Record an exit; returns the consecutive repeats at this RIP. */
static uint64_t cylon_fault_note(CylonFaultTrack *t, uint64_t rip,
                                 uint64_t gpa)
{
    uint64_t page = gpa & ~4095ULL;
    uint64_t *key;

    if (t->rip != rip) {
        cylon_fault_track_clear(t);
        t->rip = rip;
    }
    t->recent[t->nrecent++ % CYLON_FAULT_RECENT] = gpa;
    t->counted = false;
    t->refault = g_hash_table_contains(t->pages, &page);
    if (t->refault) {
        return ++t->repeats;
    }
    t->repeats = 0;
    if (g_hash_table_size(t->pages) == CYLON_FAULT_SET_MAX) {
        uint64_t *oldest = g_queue_pop_head(&t->order);

        g_hash_table_remove(t->pages, oldest);
    }
    key = g_memdup2(&page, sizeof(page));
    g_hash_table_add(t->pages, key);
    g_queue_push_tail(&t->order, key);
    return 0;
}

static char *cylon_fault_recent(const CylonFaultTrack *t)
{
    GString *list = g_string_new(NULL);
    unsigned n = MIN(t->nrecent, CYLON_FAULT_RECENT);
    unsigned i;

    for (i = 0; i < n; i++) {
        g_string_append_printf(list, " 0x%" PRIx64,
                               t->recent[(t->nrecent - n + i) %
                                         CYLON_FAULT_RECENT]);
    }
    if (!n) {
        g_string_append(list, " none");
    }
    return g_string_free(list, false);
}

/*
 * The CXL lock protects the list; the caller's RCU read section keeps the
 * result alive across a fill that drops the lock.
 */
static FemuCxlWindow *cylon_fault_window(uint64_t gpa)
{
    FemuCxlWindow *w;

    QLIST_FOREACH(w, &adapter_windows, next) {
        if (gpa >= w->fw->base && gpa - w->fw->base < w->fw->size) {
            return w;
        }
    }
    return NULL;
}

/* The device that decodes @gpa now, if it is a femu-cxl-ssd. */
static FemuCxlSsd *cylon_fault_device(uint64_t gpa)
{
    FemuCxlWindow *w = cylon_fault_window(gpa);
    PCIDevice *dev = w ? adapter_route_locked(w, gpa - w->fw->base) : NULL;

    if (!dev || !object_dynamic_cast(OBJECT(dev), TYPE_FEMU_CXL_SSD)) {
        return NULL;
    }
    return FEMU_CXL_SSD(dev);
}

/*
 * Without the BQL, whether a map on @dev would first scan its windows,
 * which needs the BQL. Checked before a fill attempt counts anything, so
 * the attempt runs once, under the BQL, as it did before.
 */
static bool cylon_fault_scan_due(FemuCxlSsd *dev)
{
    return !bql_locked() && dev && dev->media.direct.fast &&
           der_windows_stale(&dev->media.direct);
}

static const char *cylon_fault_reason(uint64_t gpa, MemTxResult result)
{
    FemuCxlSsd *dev = cylon_fault_device(gpa);
    FemuCxlMedia *s;
    uint64_t dpa;
    uint64_t lpn;

    if (!dev) {
        return "no femu-cxl-ssd decodes it";
    }
    s = &dev->media;
    if (!adapter_translate(CXL_TYPE3(dev), gpa, 1, &dpa)) {
        return "the endpoint decoders do not translate it";
    }
    lpn = dpa / 4096;
    if (cxl_dev_media_disabled(&CXL_TYPE3(dev)->cxl_dstate)) {
        return "the media is disabled while a sanitize runs";
    }
    if (!s->direct.cylon || !s->direct.available) {
        return "Cylon direct mapping is not active";
    }
    if (femu_cxl_cca_uncached(&s->cca, lpn)) {
        return "it is in a caching API uncached range";
    }
    if (!s->cache.nsets) {
        return "the device has no cache";
    }
    if (!g_hash_table_contains(s->cache.entries, &lpn) &&
        femu_cxl_cache_all_pinned(&s->cache, lpn)) {
        return "every way of its cache set is pinned";
    }
    if (result != MEMTX_OK) {
        return "the media read failed";
    }
    return "the cache could not keep it or the mapping was refused";
}

static void cylon_fault_report(CPUState *cpu, const CylonFault *f,
                               const CylonFaultTrack *t, const char *why)
{
    g_autoptr(GString) bytes = g_string_new(NULL);
    g_autofree char *recent = cylon_fault_recent(t);
    unsigned i;

    for (i = 0; i < MIN(f->insn_bytes, sizeof(f->insn)); i++) {
        g_string_append_printf(bytes, " %02x", f->insn[i]);
    }
    error_report("femu-cxl-ssd: vCPU %d at RIP 0x%" PRIx64 " %s GPA 0x%"
                 PRIx64 " (bytes:%s; latest GPAs at this RIP:%s): %s. "
                 "Stopping the VM.", cpu->cpu_index, f->rip,
                 f->flags & CYLON_FAULT_FETCH ? "executed code from" :
                 "used an instruction KVM cannot decode on", f->gpa,
                 bytes->len ? bytes->str : " none", recent, why);
}

/*
 * Count an exit of @cpu against the repeat bound of its RIP. From
 * CYLON_FAULT_WARN repeats warn, at most once a second; at @dev's
 * cylon-fault-stop (never when it is 0) report, count a failure, and
 * return false: the VM must stop.
 */
static bool cylon_fault_budget(CPUState *cpu, const CylonFault *f,
                               CylonFaultTrack *t, FemuCxlSsd *dev)
{
    uint32_t stop = dev ? dev->media.cylon_fault_stop : CYLON_FAULT_STOP;
    uint64_t repeats = cylon_fault_note(t, f->rip, f->gpa);

    if (stop && repeats >= stop) {
        g_autofree char *why = g_strdup_printf(
            "retry budget exhausted: %" PRIu64 " consecutive exits at this "
            "RIP on pages already filled for it (cylon-fault-stop)", repeats);

        if (dev) {
            dev->media.direct.emul_failures++;
        }
        cylon_fault_report(cpu, f, t, why);
        cylon_fault_track_clear(t);
        return false;
    }
    if (repeats >= CYLON_FAULT_WARN) {
        int64_t now = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);

        if (now - t->warned_ms >= 1000) {
            g_autofree char *recent = cylon_fault_recent(t);

            t->warned_ms = now;
            if (stop) {
                warn_report("femu-cxl-ssd: vCPU %d has refilled pages %"
                            PRIu64 " times in a row at RIP 0x%" PRIx64
                            " (latest GPAs:%s); the VM stops at %" PRIu32
                            " (cylon-fault-stop)", cpu->cpu_index, repeats,
                            f->rip, recent, stop);
            } else {
                warn_report("femu-cxl-ssd: vCPU %d has refilled pages %"
                            PRIu64 " times in a row at RIP 0x%" PRIx64
                            " (latest GPAs:%s); cylon-fault-stop is 0, so "
                            "the VM does not stop", cpu->cpu_index, repeats,
                            f->rip, recent);
            }
        }
    }
    return true;
}

/* The leaf of @gpa in the Cylon slot of @dev, if the slot is installed. */
static uint64_t *cylon_fault_sptep(FemuCxlSsd *dev, uint64_t gpa)
{
    FemuCylon *c = dev->media.direct.cylon ? dev->media.direct.fast : NULL;

    if (!c || !c->installed || c->failed || gpa < c->window->base ||
        gpa - c->window->base >= c->size) {
        return NULL;
    }
    return cylon_sptep(c, (gpa - c->window->base) / CYLON_PAGE_SIZE);
}

/*
 * Version 2: hand a page FEMU cannot map back to KVM's emulator for its next
 * accesses. Only a cold (zero) leaf changes; any other value means another
 * vCPU or a KVM update got there first, and the guest simply retries.
 */
static bool cylon_fault_emulate(FemuCxlSsd *dev, uint64_t gpa,
                                bool *installed)
{
    uint64_t *sptep = cylon_fault_sptep(dev, gpa);

    *installed = false;
    if (!sptep && dev->media.test_map) {
        FemuCxlWindow *w = cylon_fault_window(gpa);
        uint64_t data;

        /* qtest: the emulator's access, as an MMIO read would make it. */
        dev->media.direct.fault_emulated++;
        if (w) {
            adapter_access(w, gpa - w->fw->base, &data, 8, false,
                           MEMTXATTRS_UNSPECIFIED, NULL, 0);
        }
        *installed = true;
        return true;
    }
    if (!sptep) {
        return false;
    }
    if (cylon_spte_install(sptep, 0, CYLON_EMULATE_SPTE)) {
        dev->media.direct.fault_emulated++;
        *installed = true;
    }
    return true;
}

/*
 * Fill the page at @gpa as a read miss and map it, for a fault exit of the
 * current vCPU. A retry runs for a page that is now resident, which is a
 * cache hit and charges no media time again (a revoked leaf, a decoder
 * change during the fill), or after a wait: a fill that kept nothing charged
 * nothing, and femu_cxl_fill_wait() found that another access or a recent
 * protection of another vCPU was the only obstacle and is gone. Before a
 * retry the page must still decode to the same device and page and be
 * admissible. @flags (FEMU_CXL_FILL_*) go to the fill. CXL lock, in an RCU
 * read section. Returns whether the page is mapped; @result is the last
 * access result.
 */
static bool cylon_fault_fill(uint64_t gpa, unsigned flags,
                             MemTxResult *result)
{
    int64_t deadline = qemu_clock_get_ns(QEMU_CLOCK_REALTIME) +
                       CYLON_FAULT_WAIT_NS;
    FemuCxlSsd *dev = cylon_fault_device(gpa);
    bool mapped = false;
    bool ready = false;
    uint64_t lpn = 0;
    unsigned i;

    *result = MEMTX_ERROR;
    for (i = 0; i < CYLON_FAULT_TRIES && !mapped; i++) {
        FemuCxlWindow *w = cylon_fault_window(gpa);
        FemuCxlSsd *now = cylon_fault_device(gpa);
        uint64_t dpa;

        if (!w || !now || now != dev || femu_cxl_bql_needed() ||
            !adapter_translate(CXL_TYPE3(now), gpa, 1, &dpa) ||
            (i && (dpa / 4096 != lpn ||
                   !femu_cxl_admissible(&now->media, lpn) ||
                   (!ready && !g_hash_table_contains(now->media.cache.entries,
                                                     &lpn))))) {
            break;
        }
        /* An invalidation during a wait: retry under the BQL only. */
        if (cylon_fault_scan_due(now)) {
            femu_cxl_need_bql();
            break;
        }
        lpn = dpa / 4096;
        ready = false;
        *result = adapter_access(w, gpa - w->fw->base, NULL, 1, false,
                                 MEMTXATTRS_UNSPECIFIED, &mapped, flags);
        if (*result != MEMTX_OK || mapped || i + 1 == CYLON_FAULT_TRIES ||
            cylon_fault_device(gpa) != dev || femu_cxl_bql_needed()) {
            break;
        }
        /* The wait drops the locks; the reference keeps the device. */
        object_ref(OBJECT(dev));
        ready = femu_cxl_fill_wait(&dev->media, lpn, deadline,
                                   flags & FEMU_CXL_FILL_KEEP_OWN);
        cxl_unref(dev);
    }
    return mapped;
}

static bool cylon_test_fault_fill(uint64_t gpa, Error **errp)
{
    MemTxResult result;

    WITH_RCU_READ_LOCK_GUARD() {
        cylon_fault_fill(gpa, 0, &result);
    }
    if (result != MEMTX_OK) {
        error_setg(errp, "the fill failed");
        return false;
    }
    return true;
}

/*
 * KVM's emulator reaches the instruction's other pages through host memory,
 * not through FEMU and not through the EPT dirty bit. Before handing a
 * conflicting page to it, mark the resident pages that this instruction
 * faulted on for a write dirty, so their write-back is charged as the
 * emulated store would make it.
 */
static void cylon_fault_conflict_dirty(CylonFaultTrack *t, FemuCxlSsd *dev)
{
    unsigned i;

    for (i = 0; i < t->nprotect; i++) {
        CylonProtect *p = &t->protect[i];
        FemuCxlEntry *e;

        if (p->dev != dev || !p->write) {
            continue;
        }
        e = g_hash_table_lookup(dev->media.cache.entries, &p->lpn);
        if (e) {
            e->dirty = true;
        }
    }
}

/*
 * The emulator cannot run an instruction (undecodable, or a code fetch)
 * whose page cannot keep a way because the instruction's own pages fill its
 * set. Map the page without a cache way for this instruction, charged as
 * one fill, until the vCPU faults at another RIP or 16 newer overflow pages
 * replace it. A model deviation, counted in der-fault-overflows: writes
 * through that mapping are not charged, and other vCPUs reach the page
 * uncounted meanwhile. The alternative, refilling into the set, evicts a
 * page the instruction needs and never ends.
 */
static bool cylon_fault_overflow(CylonFaultTrack *t, uint64_t gpa,
                                 MemTxResult *result)
{
    FemuCxlSsd *dev = cylon_fault_device(gpa);
    uint64_t dpa;
    uint64_t lpn;
    unsigned i;

    if (!t->refault || !dev ||
        !adapter_translate(CXL_TYPE3(dev), gpa, 1, &dpa) ||
        !femu_cxl_admissible(&dev->media, dpa / 4096) ||
        !femu_cxl_fill_conflict(&dev->media, dpa / 4096)) {
        return false;
    }
    dev->media.direct.fault_conflicts++;
    if (!cylon_fault_fill(gpa, FEMU_CXL_FILL_KEEP_OWN |
                          FEMU_CXL_FILL_OVERFLOW, result)) {
        return false;
    }
    dev = cylon_fault_device(gpa);
    if (!dev || femu_cxl_bql_needed() ||
        !adapter_translate(CXL_TYPE3(dev), gpa, 1, &dpa)) {
        return false;
    }
    lpn = dpa / 4096;
    if (g_hash_table_contains(dev->media.cache.entries, &lpn)) {
        return true;
    }
    dev->media.direct.fault_overflows++;
    for (i = 0; i < t->noverflow; i++) {
        if (t->overflow[i].dev == dev && t->overflow[i].lpn == lpn) {
            return true;
        }
    }
    if (t->noverflow == CYLON_OVERFLOW_PAGES) {
        cylon_overflow_release(&t->overflow[0]);
        memmove(&t->overflow[0], &t->overflow[1],
                --t->noverflow * sizeof(t->overflow[0]));
    }
    femu_cxl_overflow_add(&dev->media, lpn);
    object_ref(OBJECT(dev));
    t->overflow[t->noverflow++] = (CylonProtect) {
        .dev = dev, .lpn = lpn, .owner = t->cpu->cpu_index,
    };
    return true;
}

/*
 * Version 1 exit (an instruction the emulator cannot decode, or a code
 * fetch): fill and map the page. In version 2 the page is protected for the
 * instruction like any fill, and a refault whose instruction's own pages
 * fill the set maps outside the cache. Returns whether the page is mapped.
 */
static bool cylon_fault_decode(CylonFaultTrack *t, const CylonFault *f,
                               MemTxResult *result)
{
    uint64_t generation = 0;
    FemuCxlSsd *dev = cylon_fault_device(f->gpa);
    uint64_t dpa;
    bool mapped;

    if (dev) {
        generation = dev->media.invalidations;
    }
    mapped = cylon_fault_fill(f->gpa,
                              t->refault ? FEMU_CXL_FILL_KEEP_OWN : 0,
                              result);
    if (!mapped && !femu_cxl_bql_needed()) {
        mapped = cylon_fault_overflow(t, f->gpa, result);
    }
    dev = cylon_fault_device(f->gpa);
    if (!mapped || !dev || femu_cxl_bql_needed()) {
        return mapped && !femu_cxl_bql_needed();
    }
    dev->media.direct.emul_fills++;
    dev->media.direct.emul_fetch_fills += !!(f->flags & CYLON_FAULT_FETCH);
    if (cylon_v2 && dev->media.invalidations == generation &&
        adapter_translate(CXL_TYPE3(dev), f->gpa, 1, &dpa) &&
        g_hash_table_contains(dev->media.cache.entries,
                              &(uint64_t){dpa / 4096})) {
        cylon_fault_protect(t, dev, dpa / 4096, false);
    }
    t->unserved = 0;
    return true;
}

static bool cylon_fault_access(CylonFaultTrack *t, const CylonFault *f,
                               const char **why);

/*
 * A fault exit of vCPU test-owner at a fixed RIP, as KVM sends it: a
 * version 2 read, or with @decode an instruction the emulator cannot decode.
 */
static bool cylon_test_fault(FemuCxlSsd *dev, uint64_t gpa, bool decode,
                             Error **errp)
{
    CPUState *cpu = qemu_get_cpu(MAX(dev->media.test_owner, 0));
    CylonFault f = {
        .gpa = gpa,
        .rip = dev->media.test_rip,
        .flags = decode ? 0 : CYLON_FAULT_ACCESS | CYLON_FAULT_READ,
    };
    MemTxResult result;
    const char *why = NULL;
    bool ok = false;

    if (!cpu) {
        error_setg(errp, "no vCPU %d", dev->media.test_owner);
        return false;
    }
    WITH_RCU_READ_LOCK_GUARD() {
        CylonFaultTrack *t = cylon_fault_track(cpu);

        if (!cylon_fault_budget(cpu, &f, t, dev)) {
            why = "retry budget exhausted (cylon-fault-stop)";
        } else if (decode) {
            ok = cylon_fault_decode(t, &f, &result);
        } else {
            ok = cylon_fault_access(t, &f, &why);
        }
    }
    if (!ok) {
        error_setg(errp, "%s", why ? why : "the fault failed");
    }
    return ok;
}

/*
 * Version 2 exit: the type is exact and nothing was emulated. Map an
 * admissible page (fill as a read miss; a store through the mapping sets the
 * EPT dirty bit) and protect it for this instruction. A page that cannot be
 * mapped goes back to KVM's emulator (version 1 path). Returns false to stop
 * the VM, with @why set.
 */
static bool cylon_fault_access(CylonFaultTrack *t, const CylonFault *f,
                               const char **why)
{
    FemuCxlSsd *dev = cylon_fault_device(f->gpa);
    MemTxResult result = MEMTX_ERROR;
    uint64_t generation;
    bool installed;
    bool mapped;
    uint64_t *sptep;
    uint64_t dpa;
    uint64_t old;

    if (!dev || femu_cxl_bql_needed() ||
        !adapter_translate(CXL_TYPE3(dev), f->gpa, 1, &dpa)) {
        *why = cylon_fault_reason(f->gpa, MEMTX_ERROR);
        return false;
    }
    if (!t->counted) {
        t->counted = true;
        dev->media.direct.fault_reads += !!(f->flags & CYLON_FAULT_READ);
        dev->media.direct.fault_writes += !!(f->flags & CYLON_FAULT_WRITE);
        dev->media.direct.fault_fetches += !!(f->flags & CYLON_FAULT_FETCH);
        dev->media.direct.fault_walks += !!(f->flags & CYLON_FAULT_PAGE_WALK);
    }
    /* Decide before charging media time: emulation charges each access. */
    if (!femu_cxl_admissible(&dev->media, dpa / 4096)) {
        if (cylon_fault_emulate(dev, f->gpa, &installed)) {
            return true;
        }
        *why = cylon_fault_reason(f->gpa, MEMTX_ERROR);
        return false;
    }
    generation = dev->media.invalidations;
    mapped = cylon_fault_fill(f->gpa,
                              t->refault ? FEMU_CXL_FILL_KEEP_OWN : 0,
                              &result);
    dev = cylon_fault_device(f->gpa);
    /* Decide nothing that the run under the BQL would decide again. */
    if (femu_cxl_bql_needed()) {
        return false;
    }
    if (!dev || !adapter_translate(CXL_TYPE3(dev), f->gpa, 1, &dpa)) {
        *why = cylon_fault_reason(f->gpa, result);
        return false;
    }
    if (mapped) {
        dev->media.direct.emul_fills++;
        dev->media.direct.emul_fetch_fills += !!(f->flags & CYLON_FAULT_FETCH);
        /* A reset or decoder change during the fill: protect nothing. */
        if (dev->media.invalidations == generation) {
            cylon_fault_protect(t, dev, dpa / 4096,
                                f->flags & CYLON_FAULT_WRITE);
        }
        t->unserved = 0;
        /*
         * A refault fill kept the vCPU's own pages, so it is not the
         * ping-pong the repeat bound looks for: another vCPU evicted the
         * page, and the instruction can run.
         */
        if (t->refault) {
            t->repeats = 0;
        }
        return true;
    }
    /*
     * The instruction's own pages fill the set (more pages of one set than
     * ways): the emulator completes it, one charged access at a time, as a
     * device that serves each access does. Refilling here would evict a page
     * the instruction still needs, for ever.
     */
    if (t->refault && femu_cxl_fill_conflict(&dev->media, dpa / 4096)) {
        dev->media.direct.fault_conflicts++;
        cylon_fault_conflict_dirty(t, dev);
    }
    /* A frozen or newly present leaf: KVM or another vCPU acted; retry. */
    sptep = cylon_fault_sptep(dev, f->gpa);
    old = sptep ? qatomic_read(sptep) : 0;
    if (old != CYLON_REMOVED_SPTE && !(old & CYLON_MMU_PRESENT)) {
        /* Also a held victim that showed in the fill, or a failed read. */
        if (!cylon_fault_emulate(dev, f->gpa, &installed)) {
            *why = cylon_fault_reason(f->gpa, result);
            return false;
        }
        /* The handoff serves the access: the budgets restart. */
        if (installed) {
            t->unserved = 0;
            t->repeats = 0;
            return true;
        }
    }
    /* A bounded budget for exits served without a mapping or a handoff. */
    if (++t->unserved > CYLON_FAULT_UNSERVED) {
        *why = "retry budget exhausted: 1000 consecutive exits at this RIP "
               "served without a mapping";
        return false;
    }
    return true;
}

typedef enum CylonServe {
    CYLON_SERVED,
    CYLON_STOP,
    /* Something on the way needs the BQL; nothing was decided. */
    CYLON_NEED_BQL,
} CylonServe;

/*
 * Serve one fault exit under the CXL lock, with or without the BQL. The
 * exit is recorded once (@noted), even when it is served a second time
 * under the BQL. Reports and stops only when it decided to.
 */
static CylonServe cylon_fault_serve(CPUState *cpu, const CylonFault *f,
                                    bool *noted)
{
    FemuCxlSsd *dev = cylon_fault_device(f->gpa);
    MemTxResult result = MEMTX_ERROR;
    const char *why = NULL;
    CylonFaultTrack *t;
    bool mapped;

    assert(femu_cxl_locked());
    /*
     * Ask for the BQL before anything is charged: a route it must walk, the
     * first fault, or a window scan that the mapping would need (a scan can
     * only become due with an invalidation, which also stops the mapping).
     */
    if (femu_cxl_bql_needed() || cylon_fault_scan_due(dev) ||
        (!bql_locked() && !cylon_fault_tracks)) {
        return CYLON_NEED_BQL;
    }
    t = cylon_fault_track(cpu);
    if (!*noted) {
        *noted = true;
        if (!cylon_fault_budget(cpu, f, t, dev)) {
            return CYLON_STOP;
        }
    }
    if (f->flags & CYLON_FAULT_ACCESS) {
        mapped = cylon_fault_access(t, f, &why);
    } else {
        mapped = cylon_fault_decode(t, f, &result);
    }
    if (mapped) {
        return CYLON_SERVED;
    }
    if (femu_cxl_bql_needed()) {
        return CYLON_NEED_BQL;
    }
    dev = cylon_fault_device(f->gpa);
    if (dev) {
        dev->media.direct.emul_failures++;
    }
    cylon_fault_report(cpu, f, t, why ? why :
                       cylon_fault_reason(f->gpa, result));
    cylon_fault_track_clear(t);
    return CYLON_STOP;
}

/*
 * Fill the page as a read miss and map it; the guest then executes the
 * instruction again, natively. A page that must stay uncached cannot be
 * served this way, and an instruction that keeps faulting at one RIP makes
 * no progress: both stop the VM instead of returning to the same fault.
 *
 * KVM calls this outside the BQL. With version 2 the fault is served under
 * the CXL lock alone, so misses of different vCPUs never wait for the BQL
 * or for each other's media time. Version 1 exits are rare and take the
 * BQL, so the CXL lock takes no mutex for version 1 MMIO. What needs the
 * BQL (a route through a switch or to another device, a window scan after
 * an invalidation) makes the service stop before it decides anything, and
 * the fault is served again under the BQL as before. As for MMIO dispatch,
 * an RCU read section keeps an unplugged window alive while the fill
 * waits; the window is looked up again by GPA after every wait instead of
 * trusting an earlier pointer.
 */
static bool cylon_fault_handle(CPUState *cpu, const CylonFault *f)
{
    /* Without version 2 the CXL lock is the BQL's (femu_cxl_lock()). */
    bool take = !bql_locked() && !femu_cxl_lock_is_bql_free();
    bool bql = bql_locked() || take;
    CylonServe served;
    bool noted = false;

    if (take) {
        bql_lock();
    }
    WITH_RCU_READ_LOCK_GUARD() {
        femu_cxl_lock();
        femu_cxl_clear_need_bql();
        served = cylon_fault_serve(cpu, f, &noted);
        femu_cxl_clear_need_bql();
        if (served == CYLON_NEED_BQL) {
            FemuCxlSsd *dev;

            assert(!bql);
            femu_cxl_unlock();
            bql_lock();
            femu_cxl_lock();
            dev = cylon_fault_device(f->gpa);
            if (dev) {
                dev->media.direct.fault_bql++;
            }
            served = cylon_fault_serve(cpu, f, &noted);
            assert(served != CYLON_NEED_BQL);
            femu_cxl_unlock();
            bql_unlock();
        } else {
            femu_cxl_unlock();
        }
    }
    if (take) {
        bql_unlock();
    }
    return served == CYLON_SERVED;
}

static bool cylon_fault_exit(CPUState *cpu, struct kvm_run *run)
{
    CylonFault f;

    memcpy(&f, run->padding, sizeof(f));
    return cylon_fault_handle(cpu, &f);
}

/*
 * qtest only: threads that act as vCPUs 0..n-1 and send fault exits at
 * random pages of a window, through the same service and locking as KVM's
 * exits, while the test changes the device under them. Mode 0 serves them
 * without the BQL, as KVM does with version 2; mode 1 holds the BQL for
 * each, as before; mode 2 calls the service without the BQL, as KVM does
 * with version 1, and leaves the CXL lock as it is.
 * A real vCPU cannot be unplugged inside its own exit, but these threads
 * are not the vCPUs: a test must not unplug a vCPU during a storm.
 */
typedef struct CylonStorm {
    QemuThread *threads;
    /* vCPUs 0..n-1, referenced while the threads run. */
    CPUState **cpus;
    unsigned nthreads;
    uint64_t base;
    uint64_t pages;
    uint64_t iters;
    uint32_t mode;
    uint32_t seed;
    uint64_t served;
    uint64_t stops;
    int64_t start_ns;
    uint64_t ns;
} CylonStorm;

static CylonStorm cylon_storm;

static void *cylon_storm_thread(void *opaque)
{
    unsigned index = (uintptr_t)opaque;
    CPUState *cpu = cylon_storm.cpus[index];
    GRand *rand = g_rand_new_with_seed(cylon_storm.seed + index);
    uint64_t i;

    rcu_register_thread();
    current_cpu = cpu;
    for (i = 0; i < cylon_storm.iters; i++) {
        uint32_t kind = g_rand_int_range(rand, 0, 16);
        CylonFault f = {
            .gpa = cylon_storm.base +
                   g_rand_int_range(rand, 0, cylon_storm.pages) * 4096 +
                   g_rand_int_range(rand, 0, 512) * 8,
            .rip = 0x1000 + index * 64 + (kind == 0 ? 16 : 0),
            .flags = kind == 0 ? 0 : CYLON_FAULT_ACCESS |
                     (kind < 4 ? CYLON_FAULT_WRITE : CYLON_FAULT_READ),
        };
        bool ok;

        if (cylon_storm.mode == 1) {
            bql_lock();
        }
        ok = cylon_fault_handle(cpu, &f);
        if (cylon_storm.mode == 1) {
            bql_unlock();
        }
        qatomic_inc(ok ? &cylon_storm.served : &cylon_storm.stops);
    }
    current_cpu = NULL;
    rcu_unregister_thread();
    g_rand_free(rand);
    return NULL;
}

/* "threads,pages,iters,mode,seed": start a storm on this device's window. */
static void cylon_storm_start(FemuCxlSsd *dev, const char *spec,
                              Error **errp)
{
    unsigned threads;
    uint64_t pages;
    uint64_t iters;
    uint32_t mode;
    uint32_t seed;
    FemuCxlWindow *w;
    unsigned i;

    if (sscanf(spec, "%u,%" SCNu64 ",%" SCNu64 ",%" SCNu32 ",%" SCNu32,
               &threads, &pages, &iters, &mode, &seed) != 5 || !threads ||
        threads > current_machine->smp.max_cpus || !pages || mode > 2) {
        error_setg(errp, "test-storm is threads,pages,iters,mode,seed with "
                   "at most one thread per vCPU");
        return;
    }
    if (cylon_storm.threads) {
        error_setg(errp, "a storm is running");
        return;
    }
    for (i = 0; i < threads; i++) {
        if (!qemu_get_cpu(i)) {
            error_setg(errp, "test-storm needs vCPU %u", i);
            return;
        }
    }
    WITH_FEMU_CXL_LOCK() {
        w = QLIST_FIRST(&adapter_windows);
        if (w) {
            cylon_storm.base = w->fw->base;
            pages = MIN(pages, w->fw->size / 4096);
        }
        cylon_fault_tracks_init();
        /*
         * Mode 0 serves exits without the BQL, as version 2 does; mode 2
         * leaves the CXL lock as it is, so while it is no mutex the exits
         * take the BQL themselves, as version 1 exits do.
         */
        if (w && !mode) {
            adapter_lock_bql_free();
        }
    }
    if (!w) {
        error_setg(errp, "no window");
        return;
    }
    cylon_storm.nthreads = threads;
    cylon_storm.pages = pages;
    cylon_storm.iters = iters;
    cylon_storm.mode = mode;
    cylon_storm.seed = seed;
    cylon_storm.served = 0;
    cylon_storm.stops = 0;
    cylon_storm.start_ns = get_clock();
    cylon_storm.cpus = g_new0(CPUState *, threads);
    for (i = 0; i < threads; i++) {
        cylon_storm.cpus[i] = qemu_get_cpu(i);
        object_ref(OBJECT(cylon_storm.cpus[i]));
    }
    cylon_storm.threads = g_new0(QemuThread, threads);
    for (i = 0; i < threads; i++) {
        qemu_thread_create(&cylon_storm.threads[i], "femu-cxl-storm",
                           cylon_storm_thread, (void *)(uintptr_t)i,
                           QEMU_THREAD_JOINABLE);
    }
}

/* Join the storm; the threads may need the BQL meanwhile. */
static void cylon_storm_wait(void)
{
    unsigned i;

    if (!cylon_storm.threads) {
        return;
    }
    bql_unlock();
    for (i = 0; i < cylon_storm.nthreads; i++) {
        qemu_thread_join(&cylon_storm.threads[i]);
    }
    bql_lock();
    cylon_storm.ns = get_clock() - cylon_storm.start_ns;
    for (i = 0; i < cylon_storm.nthreads; i++) {
        object_unref(OBJECT(cylon_storm.cpus[i]));
    }
    g_clear_pointer(&cylon_storm.cpus, g_free);
    g_clear_pointer(&cylon_storm.threads, g_free);
}

static uint64_t cylon_storm_result(const char *name)
{
    return !strcmp(name, "test-storm-served") ?
               qatomic_read(&cylon_storm.served) :
           !strcmp(name, "test-storm-stops") ?
               qatomic_read(&cylon_storm.stops) : cylon_storm.ns;
}

/*
 * qtest only: the bookkeeping that concurrent faults share must add up once
 * they are idle: the gate and page holds are free, every set's queues hold
 * the cache's entries, and each protection and overflow count matches the
 * vCPU records that own it. Returns what is wrong, or NULL.
 */
static const char *cylon_storm_check(FemuCxlSsd *dev)
{
    FemuCxlMedia *s = &dev->media;
    uint64_t queued = 0;
    GHashTableIter it;
    gpointer key;
    gpointer value;
    unsigned i;
    unsigned j;

    assert(femu_cxl_locked());
    if (s->busy || s->accesses || s->waiters || s->exclusive_waiters ||
        g_hash_table_size(s->pages)) {
        return "the gate or a page hold is still taken";
    }
    for (i = 0; s->started && i < s->cache.nsets; i++) {
        FemuCxlSet *set = &s->cache.sets[i];
        uint64_t n = set->small.length + set->main.length +
                     set->pinned.length;

        if (n > s->cache.ways) {
            return "a set holds more entries than ways";
        }
        queued += n;
    }
    if (s->started && (queued != g_hash_table_size(s->cache.entries) ||
                       s->cache_entries != queued)) {
        return "the set queues and the entry table disagree";
    }
    if (s->protect) {
        g_hash_table_iter_init(&it, s->protect);
        while (g_hash_table_iter_next(&it, &key, &value)) {
            GArray *guards = value;
            uint64_t lpn = *(uint64_t *)key;

            for (i = 0; i < guards->len; i++) {
                FemuCxlGuard *g = &g_array_index(guards, FemuCxlGuard, i);
                unsigned owned = 0;

                if (g->owner < 0 ||
                    g->owner >= current_machine->smp.max_cpus) {
                    return "a protection has no vCPU";
                }
                for (j = 0; j < cylon_fault_tracks[g->owner].nprotect; j++) {
                    CylonProtect *p = &cylon_fault_tracks[g->owner].protect[j];

                    owned += p->dev == dev && p->lpn == lpn;
                }
                if (owned != g->count) {
                    return "a protection count differs from its records";
                }
            }
        }
    }
    for (i = 0; cylon_fault_tracks && i < current_machine->smp.max_cpus;
         i++) {
        CylonFaultTrack *t = &cylon_fault_tracks[i];

        for (j = 0; j < t->nprotect; j++) {
            if (t->protect[j].dev == dev &&
                !femu_cxl_protected_by(s, i, t->protect[j].lpn)) {
                return "a vCPU record has no protection";
            }
        }
    }
    if (s->overflow) {
        g_hash_table_iter_init(&it, s->overflow);
        while (g_hash_table_iter_next(&it, &key, &value)) {
            uint64_t lpn = *(uint64_t *)key;
            unsigned owned = 0;

            for (i = 0; i < current_machine->smp.max_cpus; i++) {
                CylonFaultTrack *t = &cylon_fault_tracks[i];

                for (j = 0; j < t->noverflow; j++) {
                    owned += t->overflow[j].dev == dev &&
                             t->overflow[j].lpn == lpn;
                }
            }
            if (owned != GPOINTER_TO_UINT(value)) {
                return "an overflow count differs from its records";
            }
        }
    }
    return NULL;
}

/*
 * Per VM: the first slot whose device has cylon-emul-exit on turns it on.
 * Off, the kernel keeps stock KVM behaviour on such an access: #UD in guest
 * user mode, an internal-error exit in guest kernel mode. The first slot
 * also fixes the version, even with exits off (cylon_fault_version()); a
 * later device cannot change it.
 */
static void cylon_fault_exit_enable(FemuCxlDer *der)
{
    static bool enabled;
    int version = kvm_check_extension(kvm_state, CYLON_CAP_FAULT_EXIT);
    bool want_v2 = cylon_fault_version(&der->dev->media, version);

    if (!der->dev->media.cylon_emul_exit) {
        return;
    }
    if (!enabled) {
        /*
         * Version 2 exits run without the BQL. Version 1 exits are rare
         * (undecodable instructions) and take the BQL, so with version 1
         * every holder of the CXL lock holds the BQL.
         */
        if (want_v2) {
            adapter_lock_bql_free();
        }
        if (version < 1 ||
            kvm_vm_enable_cap(kvm_state, CYLON_CAP_FAULT_EXIT, 0,
                              CYLON_FAULT_EXIT_ON |
                              (want_v2 ? CYLON_FAULT_EXIT_V2 : 0))) {
            warn_report_once("femu-cxl-ssd: the host kernel lacks "
                             "KVM_CAP_CYLON_FAULT_EXIT; an instruction KVM "
                             "cannot decode on an unmapped Cylon page fails "
                             "in the guest");
            return;
        }
        cylon_fault_tracks_init();
        kvm_set_exit_handler(CYLON_EXIT_FAULT, cylon_fault_exit);
        kvm_set_vcpu_destroy_hook(cylon_fault_vcpu_destroyed);
        cylon_v2 = want_v2;
        enabled = true;
    }
    der->emul_exit = true;
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
    cylon_fault_exit_enable(der);
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

    /*
     * A paused vCPU is outside every fault exit, so the pause is a full
     * barrier. Take the CXL lock only after it: a vCPU that waits for the
     * lock cannot pause.
     */
    pause_all_vcpus();
    femu_cxl_lock();
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
    if (c->detached) {
        g_free_rcu(c, rcu);
    }
    femu_cxl_unlock();
    resume_all_vcpus();
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

/*
 * The frame check of the page that a fill maps next, made by the fill
 * itself while it waits for the media without the locks: a pagemap read
 * costs about 2 us. Its inputs are copied under the CXL lock; the slot may
 * be destroyed meanwhile, so the map trusts a passed check only if the
 * slot's inputs are still the same, and checks again under the lock
 * otherwise. Per thread: a thread runs one fill at a time.
 */
typedef struct CylonPfnCheck {
    bool pending;
    bool passed;
    CylonPagemap *pm;
    uintptr_t ram;
    uint64_t huge_size;
    uint64_t index;
    uint64_t frame;
} CylonPfnCheck;

static __thread CylonPfnCheck cylon_pfn_check;

/* An access ends: no later map may use its check. */
void femu_cxl_der_precheck_drop(void)
{
    CylonPfnCheck *p = &cylon_pfn_check;

    if (p->pending) {
        cylon_pagemap_put(p->pm);
    }
    p->pending = false;
    p->passed = false;
    p->pm = NULL;
}

void femu_cxl_der_precheck(FemuCxlDer *der, uint64_t lpn)
{
    FemuCylon *c = der->fast;

    assert(femu_cxl_locked());
    femu_cxl_der_precheck_drop();
    if (!der->cylon || !c || !c->installed || c->failed || c->batch ||
        lpn >= c->size / CYLON_PAGE_SIZE) {
        return;
    }
    qatomic_inc(&c->pm->refs);
    cylon_pfn_check = (CylonPfnCheck) {
        .pending = true,
        .pm = c->pm,
        .ram = (uintptr_t)c->ram,
        .huge_size = c->huge_size,
        .index = lpn * CYLON_PAGE_SIZE / c->huge_size,
        .frame = c->huge[lpn * CYLON_PAGE_SIZE / c->huge_size],
    };
}

/* Without locks; the reference keeps the descriptor open. */
void femu_cxl_der_precheck_run(void)
{
    CylonPfnCheck *p = &cylon_pfn_check;

    if (p->pending) {
        p->pending = false;
        p->passed = cylon_frame_current(p->pm->fd, p->ram, p->huge_size,
                                        p->index, p->frame);
        cylon_pagemap_put(p->pm);
    }
}

/* Whether this thread's check covers the frame of @dpa in @c; used once. */
static bool cylon_pfn_prechecked(FemuCylon *c, uint64_t dpa)
{
    CylonPfnCheck p = cylon_pfn_check;
    uint64_t index = dpa / c->huge_size;

    femu_cxl_der_precheck_drop();
    return p.passed && p.pm == c->pm && p.ram == (uintptr_t)c->ram &&
           p.huge_size == c->huge_size && p.index == index &&
           p.frame == c->huge[index];
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
    if (!cylon_pfn_prechecked(c, dpa) &&
        !cylon_pfn_current(c->pagemap, c->huge, (uintptr_t)c->ram,
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
     * Version 1: only a ratio pre-maps pages the guest never touched. An
     * empty leaf can be restored to zero without guessing a generation;
     * elsewhere let KVM's first fault create the MMIO entry, as before
     * ratios existed. Version 2: an empty leaf is the cold state.
     */
    if (old == CYLON_REMOVED_SPTE || (!old && !c->batch && !cylon_v2)) {
        return false;
    }
    if (old && old != CYLON_EMULATE_SPTE &&
        ((old & 7) != CYLON_MMIO_VALUE || (old & CYLON_MMU_PRESENT))) {
        cylon_fail(der);
        return false;
    }
    if (!cylon_spte_install(sptep, old, cylon_direct_spte(pa))) {
        return false;
    }
    page = g_new0(CylonPage, 1);
    page->lpn = index;
    /* Version 2 revokes to the cold state, never to an MMIO entry. */
    page->mmio = cylon_v2 ? 0 : old;
    page->sptep = sptep;
    g_hash_table_insert(der->maps, &page->lpn, page);
    der->mapped++;
    if (cylon_v2) {
        FemuCxlEntry *entry = g_hash_table_lookup(der->cache->entries, &index);

        /* Revoked ahead of an eviction that has not come. */
        if (entry && entry->der_ahead) {
            entry->der_ahead = false;
            der->ahead_remaps++;
        }
    }
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

typedef struct CylonRevokeFlush {
    FemuCxlDer *der;
    /* The victim's: where the flush covers one GFN, that is the one. */
    uint64_t gpa;
} CylonRevokeFlush;

static bool cylon_revoke_flush(void *opaque, unsigned step)
{
    CylonRevokeFlush *f = opaque;

    f->der->revoke_flushes++;
    return cylon_flush(f->gpa);
}

static bool cylon_listed(CylonPage **pages, unsigned n, CylonPage *page)
{
    unsigned i;

    for (i = 0; i < n; i++) {
        if (pages[i] == page) {
            return true;
        }
    }
    return false;
}

/*
 * A page that a revocation of another page can take along: tracked, cached,
 * and mapped by our direct entry with A set (one with A clear is revoked
 * later without a flush). Anything unexpected is left for the page's own
 * revocation to find.
 */
static bool cylon_ahead(FemuCxlDer *der, uint64_t lpn, CylonPage **pagep,
                        uint64_t *pa)
{
    FemuCylon *c = der->fast;
    CylonPage *page = g_hash_table_lookup(der->maps, &lpn);
    uint64_t old;

    if (!page || page->sptep != cylon_sptep(c, lpn) ||
        !g_hash_table_contains(der->cache->entries, &lpn) ||
        !cylon_page_address(c->huge, c->size / c->huge_size, c->huge_size,
                            lpn * CYLON_PAGE_SIZE, pa)) {
        return false;
    }
    old = qatomic_read(page->sptep);
    *pagep = page;
    return cylon_spte_is_direct(old, *pa) && (old & CYLON_EPT_ACCESSED);
}

/*
 * Revoke @lpn; with @n pages @ahead (version 2 only), revoke those in the
 * same two flushes. They keep their cache entries, with the dirty state
 * sampled here, and their next access maps them again as a hit.
 *
 * With @flush false the caller deletes the slot next, which flushes every
 * translation, so the flush after the swap would be redundant.
 */
static void cylon_remove_pages(FemuCxlDer *der, uint64_t lpn,
                               const uint64_t *ahead, unsigned n, bool flush)
{
    CylonPage *page = g_hash_table_lookup(der->maps, &lpn);
    FemuCylon *c = der->fast;
    CylonRevoke r[FEMU_CXL_REVOKE_BATCH_MAX];
    CylonPage *pages[FEMU_CXL_REVOKE_BATCH_MAX];
    CylonRevokeFlush f = { .der = der };
    unsigned count = 1;
    unsigned i;
    uint64_t old;
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
    r[0] = (CylonRevoke) { .sptep = page->sptep, .pa = pa,
                           .cold = page->mmio };
    pages[0] = page;
    if (!cylon_v2 || !c->flush_vm) {
        n = 0;
    }
    for (i = 0; i < n && count < MIN(der->revoke_batch,
                                     FEMU_CXL_REVOKE_BATCH_MAX); i++) {
        CylonPage *next;
        uint64_t next_pa;

        if (cylon_ahead(der, ahead[i], &next, &next_pa) &&
            !cylon_listed(pages, count, next)) {
            r[count] = (CylonRevoke) { .sptep = next->sptep, .pa = next_pa,
                                       .cold = next->mmio };
            pages[count++] = next;
        }
    }
    f.gpa = c->window->base + lpn * CYLON_PAGE_SIZE;
    if (!cylon_revoke(r, count, flush, cylon_revoke_flush, &f)) {
        cylon_fail(der);
        return;
    }
    for (i = 0; i < count; i++) {
        FemuCxlEntry *entry = g_hash_table_lookup(der->cache->entries,
                                                 &pages[i]->lpn);

        if (entry && r[i].dirty) {
            entry->dirty = true;
        }
        if (entry && i) {
            entry->der_ahead = true;
        }
        cylon_drop(der, pages[i], false);
    }
    der->revoked_ahead += count - 1;
}

static void cylon_remove_page(FemuCxlDer *der, uint64_t lpn, bool flush)
{
    cylon_remove_pages(der, lpn, NULL, 0, flush);
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

/*
 * Version 2 maps every filled page and the guest then uses it, so A is set
 * at nearly every eviction and each revocation flushes the VM twice. Those
 * flushes cover every page, so pages evicted soon after can share them.
 */
static unsigned femu_cylon_batch(FemuCxlDer *der, uint64_t lpn)
{
    FemuCylon *c = der->fast;
    CylonPage *page;
    uint64_t old;

    if (!cylon_v2 || !c || !c->installed || !c->flush_vm ||
        der->revoke_batch < 2) {
        return 0;
    }
    page = g_hash_table_lookup(der->maps, &lpn);
    if (!page || page->sptep != cylon_sptep(c, lpn)) {
        return 0;
    }
    old = qatomic_read(page->sptep);
    if (cylon_spte_revoked(old) || !(old & CYLON_EPT_ACCESSED)) {
        return 0;
    }
    return MIN(der->revoke_batch, FEMU_CXL_REVOKE_BATCH_MAX) - 1;
}

static void femu_cylon_remove_batch(FemuCxlDer *der, uint64_t lpn,
                                    const uint64_t *ahead, unsigned n)
{
    if (der->fast && der->fast->installed) {
        cylon_remove_pages(der, lpn, ahead, n, true);
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
    FEMU_CXL_LOCK_GUARD();

    if (c->installed && size && start < c->window->base + c->window->size &&
        c->window->base < start + size) {
        femu_cylon_clear(c->der);
        c->rearm = true;
    }
}

static void cylon_listener_commit(MemoryListener *listener)
{
    FemuCylon *c = container_of(listener, FemuCylon, listener);
    FEMU_CXL_LOCK_GUARD();

    if (c->rearm && !c->detached && !c->failed && !c->installing &&
        cylon_coverage(c, c->window)) {
        c->rearm = false;
        femu_cylon_map(c->der, c->window, c->window->base, 0);
    }
}

static bool cylon_log_start(MemoryListener *listener, Error **errp)
{
    FemuCylon *c = container_of(listener, FemuCylon, listener);
    FEMU_CXL_LOCK_GUARD();

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
    FEMU_CXL_LOCK_GUARD();

    c->logging = false;
}

/* Retry after reset; the slot is gone, so no stale translation survives. */
static void femu_cylon_reset(FemuCxlDer *der)
{
    FemuCylon *c = der->fast;

    cylon_fault_forget(der->dev);
    if (c && c->failed && !c->logging && !c->installed) {
        c->failed = false;
    }
}

static void femu_cylon_destroy(FemuCxlDer *der)
{
    FemuCylon *c = der->fast;

    cylon_fault_forget(der->dev);
    if (c) {
        c->detached = true;
        memory_listener_unregister(&c->listener);
        cylon_release(c);
        cylon_unreserve(c);
        if (c->locked) {
            munlock(c->ram, c->size);
        }
        g_free(c->huge);
        cylon_pagemap_put(c->pm);
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

static unsigned femu_cylon_batch(FemuCxlDer *der, uint64_t lpn)
{
    return 0;
}

static void femu_cylon_remove_batch(FemuCxlDer *der, uint64_t lpn,
                                    const uint64_t *ahead, unsigned n)
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

void femu_cxl_der_precheck(FemuCxlDer *der, uint64_t lpn)
{
}

void femu_cxl_der_precheck_run(void)
{
}

void femu_cxl_der_precheck_drop(void)
{
}

static bool cylon_test_fault_fill(uint64_t gpa, Error **errp)
{
    error_setg(errp, "fault exits need KVM support");
    return false;
}

static bool cylon_test_fault(FemuCxlSsd *dev, uint64_t gpa, bool decode,
                             Error **errp)
{
    error_setg(errp, "fault exits need KVM support");
    return false;
}

static void cylon_storm_start(FemuCxlSsd *dev, const char *spec,
                              Error **errp)
{
    error_setg(errp, "fault exits need KVM support");
}

static void cylon_storm_wait(void)
{
}

static const char *cylon_storm_check(FemuCxlSsd *dev)
{
    return NULL;
}

static uint64_t cylon_storm_result(const char *name)
{
    return 0;
}
#endif

/*
 * A Cylon ratio maps up to one entry per media page, so stop at @limit
 * bytes: the dump runs under the locks.
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
