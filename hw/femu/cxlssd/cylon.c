/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "system/kvm.h"
#include "system/hostmem.h"
#include "system/cpus.h"
#include "system/runstate.h"
#include "der.h"
#include "spte.h"

#ifdef CONFIG_KVM
#include <linux/kvm.h>
#include <linux/magic.h>
#include <sys/vfs.h>
#include <sys/mman.h>

#define CYLON_SPT_CHUNKS 60
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
    MemoryRegion io;
    MemoryRegion trap;
    void *trap_ram;
    bool installing;
    CXLFixedWindow *window;
    CylonGetLinearSpt spt;
    void *areas[CYLON_SPT_CHUNKS];
    uint64_t area_size;
    uint64_t size;
    uint64_t huge_size;
    uint64_t *huge;
    void *ram;
    bool installed;
    bool locked;
    bool failed;
};

static bool cylon_flush(uint64_t gpa)
{
    CylonSpteFlag flag = { .gpa = gpa };
    CPUState *cpu = qemu_get_cpu(0);

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
        /* Slot removal invalidates all translations even if SET failed. */
        memory_region_del_subregion(&c->window->mr, &c->io);
        object_unparent(OBJECT(&c->io));
        c->installed = false;
    }
    if (c->trap_ram) {
        object_unparent(OBJECT(&c->trap));
        munmap(c->trap_ram, c->size);
        c->trap_ram = NULL;
    }
    for (i = 0; i < CYLON_SPT_CHUNKS; i++) {
        if (c->areas[i]) {
            munmap(c->areas[i], c->area_size);
            c->areas[i] = NULL;
        }
    }
}

FemuCylon *femu_cylon_prepare(FemuCxlDer *der, const char **reason)
{
    CylonGetLinearSpt probe = { .gfn = UINT64_MAX };
    HostMemoryBackend *backend = der->dev->hostvmem;
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
    close(fd);
    return c;
fail:
    if (c->locked) {
        munlock(c->ram, c->size);
    }
    g_free(c->huge);
    g_free(c);
    return NULL;
}

/* The listener sees a dual-mode slot, while QEMU still dispatches CXL I/O. */
static MemTxResult cylon_read(void *opaque, hwaddr offset, uint64_t *value,
                              unsigned size, MemTxAttrs attrs)
{
    FemuCylon *c = opaque;

    return memory_region_dispatch_read(&c->window->mr, offset, value,
                                       size_memop(size), attrs);
}

static MemTxResult cylon_write(void *opaque, hwaddr offset, uint64_t value,
                               unsigned size, MemTxAttrs attrs)
{
    FemuCylon *c = opaque;

    return memory_region_dispatch_write(&c->window->mr, offset, value,
                                        size_memop(size), attrs);
}

static const MemoryRegionOps cylon_ops = {
    .read_with_attrs = cylon_read,
    .write_with_attrs = cylon_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 8, .unaligned = true },
    .impl = { .min_access_size = 1, .max_access_size = 8, .unaligned = true },
};

static bool cylon_install(FemuCxlDer *der, CXLFixedWindow *fw)
{
    FemuCylon *c = der->fast;
    uint64_t bytes = c->size / CYLON_PAGE_SIZE * sizeof(uint64_t);
    uint64_t covered = 0;
    unsigned i;

    if (fw->size != c->size || kvm_get_free_memslots() < 8) {
        return false;
    }
    c->window = fw;
    c->area_size = bytes + 2 * CYLON_PAGE_SIZE;
    /* Guarded VMAs prevent merging and avoid assuming kernel MAX_ORDER. */
    for (i = 0; i < CYLON_SPT_CHUNKS; i++) {
        void *area = mmap(NULL, c->area_size, PROT_NONE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        uint64_t *spt;

        if (area == MAP_FAILED) {
            return false;
        }
        c->areas[i] = area;
        spt = area + CYLON_PAGE_SIZE;
        if (mprotect(spt, bytes, PROT_READ | PROT_WRITE)) {
            return false;
        }
        *spt = UINT64_MAX;
        c->spt.spt_list[i].spt = spt;
    }
    /* Anonymous, non-THP backing forces KVM's leaf level to 4 KiB. */
    c->trap_ram = mmap(NULL, c->size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (c->trap_ram == MAP_FAILED) {
        c->trap_ram = NULL;
        return false;
    }
    memory_region_init_ram_ptr(&c->trap, OBJECT(der->dev), "femu-cxl-traps",
                               c->size, c->trap_ram);
    if (madvise(c->trap_ram, c->size, MADV_NOHUGEPAGE)) {
        return false;
    }
    memory_region_init_io(&c->io, OBJECT(der->dev), &cylon_ops, c,
                          "femu-cxl-cylon", c->size);
    c->io.cylon_backing = &c->trap;
    memory_region_add_subregion_overlap(&fw->mr, 0, &c->io, 1);
    c->installed = true;
    if (c->io.cylon_error || !kvm_cylon_slot(fw->base, c->size, c->trap_ram)) {
        return false;
    }
    c->spt.gfn = fw->base / CYLON_PAGE_SIZE;
    if (kvm_vm_ioctl(kvm_state, CYLON_GET_LINEAR_SPT, &c->spt) ||
        c->spt.n <= 0 || c->spt.n > CYLON_SPT_CHUNKS) {
        return false;
    }
    for (i = 0; i < c->spt.n; i++) {
        CylonLinearSpt *part = &c->spt.spt_list[i];

        if (part->spt != c->areas[i] + CYLON_PAGE_SIZE ||
            !cylon_spt_chunk(part->offset, part->npages, bytes, &covered) ||
            *part->spt == UINT64_MAX) {
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
        !kvm_cylon_slot(c->window->base, c->size, c->trap_ram)) {
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
            qatomic_set(page->sptep, page->mmio);
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

bool femu_cylon_map(FemuCxlDer *der, CXLFixedWindow *fw,
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
    if (!c->installed) {
        bool running = runstate_is_running();
        bool installed;

        /* The Cylon kernel initializes slot->aux after publishing the slot. */
        c->installing = true;
        pause_all_vcpus();
        installed = cylon_install(der, fw);
        if (!installed) {
            cylon_fail(der);
        }
        c->installing = false;
        if (running) {
            resume_all_vcpus();
        }
        return false;
    }
    if (c->window != fw || !kvm_cylon_slot(fw->base, c->size, c->trap_ram)) {
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
    if (page) {
        if (page->sptep != sptep ||
            (old & ~CYLON_EPT_DIRTY) != cylon_direct_spte(pa)) {
            cylon_fail(der);
            return false;
        }
        return true;
    }
    /* First access installs the slot; a later KVM fault supplies its SPTE. */
    if (!old) {
        return false;
    }
    if ((old & 7) != CYLON_MMIO_VALUE || (old & CYLON_MMU_PRESENT)) {
        cylon_fail(der);
        return false;
    }
    page = g_new0(CylonPage, 1);
    page->lpn = index;
    page->mmio = old;
    page->sptep = sptep;
    g_hash_table_insert(der->maps, &page->lpn, page);
    der->mapped++;
    qatomic_set(sptep, cylon_direct_spte(pa));
    if (!cylon_flush(hpa & ~(CYLON_PAGE_SIZE - 1))) {
        cylon_fail(der);
        return false;
    }
    der->remaps++;
    return true;
}

void femu_cylon_remove(FemuCxlDer *der, uint64_t lpn)
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
                            lpn * CYLON_PAGE_SIZE, &pa) ||
        (qatomic_read(page->sptep) & ~CYLON_EPT_DIRTY) !=
        cylon_direct_spte(pa)) {
        cylon_fail(der);
        return;
    }
    gpa = c->window->base + lpn * CYLON_PAGE_SIZE;
    /* Stop writes, then sample D after all stale writable TLBs are gone. */
    qatomic_and(page->sptep, ~CYLON_EPT_WRITE);
    if (!cylon_flush(gpa)) {
        cylon_fail(der);
        return;
    }
    old = qatomic_xchg(page->sptep, page->mmio);
    entry = g_hash_table_lookup(der->cache->entries, &lpn);
    if (entry && ((old & CYLON_EPT_DIRTY) || !(old & CYLON_MMU_PRESENT))) {
        entry->dirty = true;
    }
    if (!cylon_flush(gpa)) {
        cylon_fail(der);
        return;
    }
    g_hash_table_remove(der->maps, &lpn);
    g_free(page);
    der->mapped--;
    der->revocations++;
}

void femu_cylon_destroy(FemuCxlDer *der)
{
    FemuCylon *c = der->fast;

    if (c) {
        cylon_release(c);
        if (c->locked) {
            munlock(c->ram, c->size);
        }
        g_free(c->huge);
        g_free(c);
        der->fast = NULL;
    }
}
#else
FemuCylon *femu_cylon_prepare(FemuCxlDer *der, const char **reason)
{
    *reason = "Cylon requires KVM";
    return NULL;
}

bool femu_cylon_map(FemuCxlDer *der, CXLFixedWindow *fw,
                    uint64_t hpa, uint64_t dpa)
{
    return false;
}

void femu_cylon_remove(FemuCxlDer *der, uint64_t lpn)
{
}

void femu_cylon_destroy(FemuCxlDer *der)
{
}
#endif
