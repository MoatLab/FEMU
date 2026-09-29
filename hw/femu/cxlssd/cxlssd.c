/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "qapi/error.h"
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
#include "der.h"

#define TYPE_FEMU_CXL_SSD "femu-cxl-ssd"
OBJECT_DECLARE_SIMPLE_TYPE(FemuCxlSsd, FEMU_CXL_SSD)

typedef struct FemuCxlWork {
    NvmeRequest req;
    uint64_t latency;
    bool done;
    QSIMPLEQ_ENTRY(FemuCxlWork) next;
} FemuCxlWork;

/* One access, flush or eviction chain: the media time it has accumulated. */
typedef struct FemuCxlOp {
    struct FemuCxlSsd *s;
    uint64_t ns;
    bool held;
} FemuCxlOp;

struct FemuCxlSsd {
    CXLType3Dev parent_obj;
    FemuCtrl *ctrl;
    NvmeNamespace ns;
    SsdDramBackend backend;
    FemuCxlCache cache;
    uint32_t cache_pages;
    uint32_t cache_ways;
    char *cache_policy;
    bool ftl;
    char *der;
    bool cylon_kernel_ack;
    OnOffAuto concurrent;
    bool busy;
    bool closing;
    uint64_t accesses;
    uint64_t exclusive_waiters;
    uint64_t invalidation_waiters;
    GHashTable *pages;
    QemuCond idle;
    FemuCxlDer direct;
    uint64_t read_ns;
    uint64_t program_ns;
    uint64_t erase_ns;
    uint64_t media_ns;
    uint64_t media_reads;
    uint64_t media_writes;
    QemuMutex lock;
    QemuCond wake;
    QemuThread worker;
    QSIMPLEQ_HEAD(, FemuCxlWork) work;
    bool stopping;
    bool started;
};

static void (*parent_realize)(PCIDevice *dev, Error **errp);
static void (*parent_exit)(PCIDevice *dev);

/*
 * BQL protects the gate. Accesses share it, so misses to different pages
 * wait for the media together; flush, invalidation and teardown take it
 * alone, after the accesses in progress, and new accesses wait for them.
 */
static void cxl_enter(FemuCxlSsd *s)
{
    s->exclusive_waiters++;
    while (s->busy || s->accesses) {
        qemu_cond_wait_bql(&s->idle);
    }
    s->exclusive_waiters--;
    s->busy = true;
}

static void cxl_leave(FemuCxlSsd *s)
{
    s->busy = false;
    qemu_cond_broadcast(&s->idle);
}

/*
 * With der=off a guest's lock-prefixed read-modify-write reaches the device as
 * a read and a separate write, so it is never atomic. Serializing accesses
 * keeps other vCPUs out from between the two most of the time; overlapping
 * misses make it common. A direct mode resolves the write on the mapped page,
 * where KVM exchanges and retries, so by default misses overlap only while
 * direct mapping is active.
 */
static bool cxl_concurrent(FemuCxlSsd *s)
{
    return s->concurrent == ON_OFF_AUTO_ON ||
           (s->concurrent == ON_OFF_AUTO_AUTO && s->direct.available);
}

static void cxl_enter_access(FemuCxlSsd *s)
{
    while (s->busy || s->exclusive_waiters) {
        qemu_cond_wait_bql(&s->idle);
    }
    s->accesses++;
}

static void cxl_leave_access(FemuCxlSsd *s)
{
    s->accesses--;
    qemu_cond_broadcast(&s->idle);
}

static void cxl_delay(uint64_t ns)
{
    bql_unlock();
    g_usleep(DIV_ROUND_UP(ns, 1000));
    bql_lock();
}

/* Only metadata reaches the worker; the vCPU owns all payload access. */
static void *cxl_worker(void *opaque)
{
    FemuCxlSsd *s = opaque;

    qemu_mutex_lock(&s->lock);
    while (!s->stopping) {
        FemuCxlWork *work = QSIMPLEQ_FIRST(&s->work);

        if (!work) {
            qemu_cond_wait(&s->wake, &s->lock);
            continue;
        }
        QSIMPLEQ_REMOVE_HEAD(&s->work, next);
        work->latency = bb_ftl_process_req(s->ctrl, &s->ns, &work->req);
        work->done = true;
        qemu_cond_broadcast(&s->wake);
    }
    qemu_mutex_unlock(&s->lock);
    return NULL;
}

/*
 * Requests from different accesses queue for the worker in arrival order; the
 * NAND model overlaps them where they reach different LUNs.
 */
static bool cxl_media(FemuCxlOp *op, uint64_t lpn, bool write)
{
    FemuCxlSsd *s = op->s;
    FemuCxlWork work = {
        .req = {
            .cmd.opcode = write ? NVME_CMD_WRITE : NVME_CMD_READ,
            .ns = &s->ns,
            .slba = lpn * 8,
            .nlb = 8,
            .stime = qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + op->ns,
        },
    };

    if (!s->ftl) {
        return true;
    }
    bql_unlock();
    qemu_mutex_lock(&s->lock);
    QSIMPLEQ_INSERT_TAIL(&s->work, &work, next);
    qemu_cond_broadcast(&s->wake);
    while (!work.done) {
        qemu_cond_wait(&s->wake, &s->lock);
    }
    qemu_mutex_unlock(&s->lock);
    bql_lock();
    s->media_ns += work.latency;
    op->ns += work.latency;
    if (write) {
        s->media_writes = ssd_nand_write_pages(s->ns.ssd);
    } else {
        s->media_reads++;
    }
    return work.req.status == NVME_SUCCESS;
}

static bool cxl_evict(void *opaque, FemuCxlEntry *e)
{
    FemuCxlOp *op = opaque;
    FemuCxlSsd *s = op->s;
    bool ok;

    /* Another access holds the page; keep it and let the caller go uncached. */
    if (g_hash_table_contains(s->pages, &e->lpn)) {
        op->held = true;
        return false;
    }
    femu_cxl_der_remove(&s->direct, e->lpn);
    if (!e->dirty) {
        return true;
    }
    /* The write-back drops the BQL; accesses to the page wait until it ends. */
    g_hash_table_add(s->pages, &e->lpn);
    ok = cxl_media(op, e->lpn, true);
    g_hash_table_remove(s->pages, &e->lpn);
    qemu_cond_broadcast(&s->idle);
    return ok;
}

static MemTxResult cxl_access_locked(CXLType3Dev *ct3d, hwaddr hpa,
                                    uint64_t dpa, uint64_t *data, unsigned size,
                                    bool write, MemTxAttrs attrs)
{
    FemuCxlSsd *s = FEMU_CXL_SSD(ct3d);
    FemuCxlOp op = { .s = s };
    MemTxResult result = MEMTX_ERROR;
    uint64_t pages[2];
    uint64_t first = dpa / 4096;
    uint64_t last;
    uint64_t lpn;
    int64_t start = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    int64_t remaining;
    unsigned n = 0;
    unsigned i;

    if (!size || size > sizeof(*data) || dpa >= s->backend.size ||
        size > s->backend.size - dpa) {
        return MEMTX_ERROR;
    }
    last = (dpa + size - 1) / 4096;
    /*
     * Hold the pages, in ascending order, so accesses to a page stay ordered
     * and a second miss to it waits for the first fill instead of repeating it.
     */
    for (lpn = first; lpn <= last; lpn++) {
        pages[n] = lpn;
        while (g_hash_table_contains(s->pages, &pages[n])) {
            qemu_cond_wait_bql(&s->idle);
        }
        g_hash_table_add(s->pages, &pages[n++]);
    }
    for (lpn = first; lpn <= last; lpn++) {
        FemuCxlEntry *e = femu_cxl_cache_find(&s->cache, lpn);

        if (!e) {
            if (!cxl_media(&op, lpn, write && !s->cache.nsets)) {
                goto out;
            }
            op.held = false;
            e = femu_cxl_cache_insert(&s->cache, lpn, cxl_evict, &op);
            if (s->cache.nsets && !e && !op.held) {
                goto out;
            }
            /* The victim was held: this access bypasses the cache. */
            if (!e && op.held && write && !cxl_media(&op, lpn, true)) {
                goto out;
            }
        }
        if (e && write) {
            e->dirty = true;
        }
    }
    remaining = op.ns - (qemu_clock_get_ns(QEMU_CLOCK_REALTIME) - start);
    if (remaining > 0) {
        cxl_delay(remaining);
    }
    if (write) {
        memcpy((uint8_t *)s->backend.logical_space + dpa, data, size);
    } else {
        memcpy(data, (uint8_t *)s->backend.logical_space + dpa, size);
    }
    if (first == last && s->cache.nsets) {
        FemuCxlEntry *e = g_hash_table_lookup(s->cache.entries, &first);

        if (e && femu_cxl_der_map(&s->direct, hpa, dpa) &&
            !s->direct.cylon) {
            /* Direct writes cannot update metadata, so charge on eviction. */
            e->dirty = true;
        }
    }
    result = MEMTX_OK;
out:
    for (i = 0; i < n; i++) {
        g_hash_table_remove(s->pages, &pages[i]);
    }
    qemu_cond_broadcast(&s->idle);
    return result;
}

static MemTxResult cxl_access(CXLType3Dev *ct3d, hwaddr hpa, uint64_t dpa,
                               uint64_t *data, unsigned size, bool write,
                               MemTxAttrs attrs)
{
    FemuCxlSsd *s = FEMU_CXL_SSD(ct3d);
    MemTxResult result = MEMTX_ERROR;
    AddressSpace *as;
    uint64_t current_dpa;
    bool shared = cxl_concurrent(s);

    object_ref(OBJECT(s));
    if (shared) {
        cxl_enter_access(s);
    } else {
        cxl_enter(s);
    }
    if (s->started && !s->closing &&
        !cxl_dev_media_disabled(&ct3d->cxl_dstate) &&
        !cxl_type3_hpa_to_as_and_dpa(ct3d, hpa, size, &as, &current_dpa) &&
        current_dpa == dpa) {
        result = cxl_access_locked(ct3d, hpa, dpa, data, size, write, attrs);
    }
    if (shared) {
        cxl_leave_access(s);
    } else {
        cxl_leave(s);
    }
    object_unref(OBJECT(s));
    return result;
}

static void cxl_invalidate(CXLType3Dev *ct3d)
{
    FemuCxlSsd *s = FEMU_CXL_SSD(ct3d);

    /*
     * The caller touches PCI state after this returns, so teardown waits for
     * waiters; once it starts, stop waiting for the operation it drains.
     */
    s->invalidation_waiters++;
    s->exclusive_waiters++;
    while ((s->busy || s->accesses) && !s->closing) {
        qemu_cond_wait_bql(&s->idle);
    }
    s->exclusive_waiters--;
    if (!s->busy && !s->accesses) {
        s->busy = true;
        if (s->started) {
            femu_cxl_der_clear(&s->direct);
        }
        s->busy = false;
    }
    s->invalidation_waiters--;
    qemu_cond_broadcast(&s->idle);
}

static void cxl_flush(Object *obj, bool value, Error **errp)
{
    FemuCxlSsd *s = FEMU_CXL_SSD(obj);
    FemuCxlOp op = { .s = s };

    object_ref(obj);
    cxl_enter(s);
    if (!s->started || s->closing || !value) {
        goto out;
    }
    if (!femu_cxl_cache_clear(&s->cache, cxl_evict, &op)) {
        error_setg(errp, "CXL cache cannot flush: NAND is full");
    }
    if (op.ns) {
        cxl_delay(op.ns);
    }
out:
    cxl_leave(s);
    object_unref(obj);
}

static void cxl_realize(PCIDevice *dev, Error **errp)
{
    FemuCxlSsd *s = FEMU_CXL_SSD(dev);
    CXLType3Dev *ct3d = CXL_TYPE3(dev);
    FemuCxlPolicy policy;
    FemuCtrl *n;
    BbCtrlParams *p;
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
        ct3d->dc.num_regions || ct3d->dc.host_dc || ct3d->lsa) {
        error_setg(errp, "femu-cxl-ssd requires only volatile-memdev");
        return;
    }
    mr = host_memory_backend_get_memory(ct3d->hostvmem);
    size = memory_region_size(mr);
    if (!size || size % (256 * MiB) || size > 64 * GiB) {
        error_setg(errp, "CXL media size must be a multiple of 256 MiB, "
                   "at most 64 GiB");
        return;
    }
    if (!s->cache_ways || s->cache_ways > 1024 ||
        (s->cache_pages && (s->cache_pages % s->cache_ways ||
                           s->cache_pages > size / 4096))) {
        error_setg(errp, "cache-pages must fit the media and be divisible by "
                   "cache-ways (1..1024)");
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
    parent_realize(dev, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }
    s->backend.size = size;
    s->backend.logical_space = memory_region_get_ram_ptr(mr);
    femu_cxl_cache_init(&s->cache, s->cache_pages, s->cache_ways, policy);
    s->ctrl = n = g_new0(FemuCtrl, 1);
    n->mbe = &s->backend;
    p = &n->bb_params;
    p->secsz = 512;
    p->secs_per_pg = 8;
    p->pgs_per_blk = 256;
    p->blks_per_pl = size / (16 * MiB) * 5 / 4 + 4;
    p->pls_per_lun = 1;
    p->luns_per_ch = 4;
    p->nchs = 4;
    p->pg_rd_lat = s->read_ns;
    p->pg_wr_lat = s->program_ns;
    p->blk_er_lat = s->erase_ns;
    p->gc_thres_pcent = 75;
    p->gc_thres_pcent_high = 95;
    s->ns.ctrl = n;
    s->ns.lbaf.lbads = 9;
    s->ns.ssd = g_new0(struct ssd, 1);
    pstrcpy(n->devname, sizeof(n->devname), TYPE_FEMU_CXL_SSD);
    s->ns.ssd->ssdname = n->devname;
    ssd_init(n, &s->ns);
    qemu_mutex_init(&s->lock);
    qemu_cond_init(&s->wake);
    QSIMPLEQ_INIT(&s->work);
    s->stopping = false;
    qemu_thread_create(&s->worker, "femu-cxl-ftl", cxl_worker, s,
                       QEMU_THREAD_JOINABLE);
    femu_cxl_der_init(&s->direct, ct3d, s->der, &s->cache);
    s->closing = false;
    s->started = true;
}

static void cxl_exit(PCIDevice *dev)
{
    FemuCxlSsd *s = FEMU_CXL_SSD(dev);

    /* Callers of cxl_invalidate() finish under the BQL before we proceed. */
    s->closing = true;
    qemu_cond_broadcast(&s->idle);
    while (s->busy || s->accesses || s->invalidation_waiters) {
        qemu_cond_wait_bql(&s->idle);
    }
    s->busy = true;
    femu_cxl_der_destroy(&s->direct);
    qemu_mutex_lock(&s->lock);
    s->stopping = true;
    qemu_cond_broadcast(&s->wake);
    qemu_mutex_unlock(&s->lock);
    qemu_thread_join(&s->worker);
    qemu_cond_destroy(&s->wake);
    qemu_mutex_destroy(&s->lock);
    s->started = false;
    femu_cxl_cache_destroy(&s->cache);
    ssd_free(s->ns.ssd);
    g_free(s->ns.ssd);
    g_free(s->ctrl);
    parent_exit(dev);
    host_memory_backend_set_mapped(s->parent_obj.hostvmem, false);
    cxl_leave(s);
}

static bool cxl_der_active(Object *obj, Error **errp)
{
    return FEMU_CXL_SSD(obj)->direct.available;
}

static void cxl_init(Object *obj)
{
    FemuCxlSsd *s = FEMU_CXL_SSD(obj);

    qemu_cond_init(&s->idle);
    s->pages = g_hash_table_new(g_int64_hash, g_int64_equal);
    s->der = g_strdup("off");
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
    DEFINE_PROP_UINT32("cache-pages", FemuCxlSsd, cache_pages, 1024),
    DEFINE_PROP_UINT32("cache-ways", FemuCxlSsd, cache_ways, 16),
    DEFINE_PROP_STRING("cache-policy", FemuCxlSsd, cache_policy),
    DEFINE_PROP_BOOL("ftl", FemuCxlSsd, ftl, true),
    DEFINE_PROP_STRING("der", FemuCxlSsd, der),
    DEFINE_PROP_BOOL("cylon-kernel-ack", FemuCxlSsd, cylon_kernel_ack, false),
    DEFINE_PROP_ON_OFF_AUTO("concurrent-misses", FemuCxlSsd, concurrent,
                            ON_OFF_AUTO_AUTO),
    DEFINE_PROP_UINT64("read-ns", FemuCxlSsd, read_ns, 40000),
    DEFINE_PROP_UINT64("program-ns", FemuCxlSsd, program_ns, 200000),
    DEFINE_PROP_UINT64("erase-ns", FemuCxlSsd, erase_ns, 2000000),
};

static const VMStateDescription cxl_vmstate = {
    .name = TYPE_FEMU_CXL_SSD,
    .unmigratable = true,
};

static void cxl_class_init(ObjectClass *oc, const void *data)
{
    PCIDeviceClass *pc = PCI_DEVICE_CLASS(oc);
    DeviceClass *dc = DEVICE_CLASS(oc);
    CXLType3Class *cc = CXL_TYPE3_CLASS(oc);

    parent_realize = pc->realize;
    parent_exit = pc->exit;
    pc->realize = cxl_realize;
    pc->exit = cxl_exit;
    dc->desc = "FEMU CXL SSD";
    dc->vmsd = &cxl_vmstate;
    device_class_set_props(dc, cxl_props);
    cc->mem_access = cxl_access;
    cc->invalidate = cxl_invalidate;
}

static void cxl_finalize(Object *obj)
{
    FemuCxlSsd *s = FEMU_CXL_SSD(obj);

    g_hash_table_destroy(s->pages);
    qemu_cond_destroy(&s->idle);
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
