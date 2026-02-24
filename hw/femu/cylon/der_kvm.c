#include "der_kvm.h"
#include "cache/cache_backend.h"
#include "hw/core/cpu.h"
#include "sysemu/kvm.h"
/* kvm.h declares kvm_vm_ioctl only inside #ifdef NEED_CPU_H; provide it when building without */
#ifndef NEED_CPU_H
extern int kvm_vm_ioctl(KVMState *s, int type, ...);
#endif
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#define DIRECT_MASK  0x600000000000977ULL
#define MMIO_MASK    0x0000000586ULL

static inline u64 get_leaf_ept_idx(u64 lpn)
{
    return (lpn * sizeof(u64 *)) >> (MAX_ORDER + PAGE_SHIFT);
}

/* Allocate and fetch linear EPT (full CXL_SSD space). */
static int init_leaf_ept(DerKvmState *s)
{
    KVMState *kvm = kvm_state;
    u64 size = (s->memory_size >> PAGE_SHIFT) * sizeof(u64 *);
    int idx = 0;
    int ret;

    while (size > 0) {
        u64 sz = (size > MAX_CONT_ALLOC_SZ) ? MAX_CONT_ALLOC_SZ : size;
        s->ept.ept_list[idx].ept = mmap(NULL, (size_t)sz, PROT_READ | PROT_WRITE,
                                       MAP_ANONYMOUS | MAP_SHARED, -1, 0);
        if (s->ept.ept_list[idx].ept == MAP_FAILED) {
            perror("der_kvm: mmap ept failed");
            abort();
        }
        size -= sz;
        idx++;
    }

    s->ept.gfn = s->guest_phys_addr >> PAGE_SHIFT;
    s->ept.backend_ptr = s->userspace_addr;

    ret = kvm_vm_ioctl(kvm, KVM_GET_LINEAR_EPT, &s->ept);
    if (ret < 0) {
        perror("der_kvm: KVM_GET_LINEAR_EPT");
        abort();
    }
    fprintf(stderr, "Cylon DER-KVM: init_leaf_ept done (gfn 0x%" PRIx64 ", size %" PRIu64 " pages)\n",
            (uint64_t)s->ept.gfn, (uint64_t)(s->memory_size >> PAGE_SHIFT));
    return 0;
}

static u64 *get_eptep(DerKvmState *s, u64 lpn)
{
    if (!s || !s->init_done) {
        return NULL;
    }
    u64 idx = get_leaf_ept_idx(lpn);
    u64 off = lpn - (u64)s->ept.ept_list[idx].offset * 512;
    return s->ept.ept_list[idx].ept + off;
}

int der_kvm_epte_set_trap(Cxlssd *ctx, uint64_t lpn)
{
    DerKvmState *s = ctx ? ctx->der_kvm : NULL;
    if (!s) {
        return -1;
    }
    uint64_t gfn = (s->guest_phys_addr >> PAGE_SHIFT) + lpn;
    u64 *eptep = get_eptep(s, lpn);
    if (eptep) {
        *eptep = (gfn << PAGE_SHIFT) | MMIO_MASK;
        fprintf(stderr, "Cylon DER-KVM: set trap EPTE for page %lld (gfn 0x%llx)\n",
                (long long)lpn, (long long)gfn);
        return 0;
    }
    return -1;
}

int der_kvm_epte_set_driect(Cxlssd *ctx, uint64_t lpn, uint64_t hpa)
{
    DerKvmState *s = ctx ? ctx->der_kvm : NULL;
    u64 *eptep = s ? get_eptep(s, lpn) : NULL;
    if (eptep) {
        *eptep = (hpa & ~(uint64_t)(4096 - 1)) | DIRECT_MASK;
        fprintf(stderr, "Cylon DER-KVM: set direct EPTE for page %lld (hpa 0x%llx)\n",
                (long long)lpn, (long long)hpa);
        return 0;
    }
    return -1;
}

/*
 * Register the KVM memslot for the NAND region (full CXL SSD space).
 * DER then controls each page's EPTE: in-cache -> direct to cache backend HPA,
 * not in cache -> MMIO (trap to QEMU). init_leaf_ept() builds EPT for this same
 * range so we can set/clear direct/trap per page in O(1) time.
 */
int der_kvm_set_user_memory_region(const FemuCtrl *n)
{
    KVMState *kvm = kvm_state;
    struct kvm_userspace_memory_region mem;
    Cxlssd *ctx = cxlssd_ctx_from_ctrl((FemuCtrl *)n);
    DerKvmState *s;
    int ret;

    if (!n || !n->mbe) {
        return -1;
    }
    if (!ctx || !ctx->der_kvm) {
        return -1;
    }
    s = ctx->der_kvm;

    /* Memslot = NAND region (full CXL_SSD space); EPTEs updated per-page for cache vs trap */
    s->guest_phys_addr = n->base_gpa ? n->base_gpa : femu_get_base_gpa();
    if (!s->guest_phys_addr) {
        fprintf(stderr, "Cylon DER-KVM: guest_phys_addr is 0 (base_gpa not set)\n");
        return -1;
    }
    s->memory_size = n->mbe->size;
    s->userspace_addr = n->mbe->logical_space;
    s->hpa_base = 0; /* direct HPA is passed per-page in der_kvm_epte_set_driect() */

    mem.slot = DER_KVM_SLOT_ID;
    mem.guest_phys_addr = s->guest_phys_addr;
    mem.memory_size = s->memory_size;
    mem.userspace_addr = (uint64_t)(uintptr_t)s->userspace_addr;
    mem.flags = KVM_MEMSLOT_DUAL_MODE;

    fprintf(stderr, "Cylon DER-KVM: KVM_SET_USER_MEMORY_REGION: slot %u, gpa 0x%llx, size %lld, ua 0x%llx\n",
            mem.slot, mem.guest_phys_addr, mem.memory_size, mem.userspace_addr);    
    ret = kvm_vm_ioctl(kvm, KVM_SET_USER_MEMORY_REGION, &mem);
    if (ret < 0) {
        perror("Cylon DER-KVM: KVM_SET_USER_MEMORY_REGION");
        fprintf(stderr, "Cylon DER-KVM: KVM_SET_USER_MEMORY_REGION failed: %d\n", ret);
        return -1;
    }

    fprintf(stderr, "Cylon DER-KVM: NAND memslot registered (gpa 0x%" PRIx64 " size %" PRIu64 ")\n",
            (uint64_t)s->guest_phys_addr, (uint64_t)s->memory_size);
    init_leaf_ept(s);
    s->init_done = true;
    return 0;
}

/* Remove the NAND memslot and release the slot id. */
int der_kvm_del_user_memory_region(const FemuCtrl *n)
{
    KVMState *kvm = kvm_state;
    struct kvm_userspace_memory_region mem;
    Cxlssd *ctx = cxlssd_ctx_from_ctrl((FemuCtrl *)n);
    int ret = 0;

    if (!n || !n->mbe) {
        return -1;
    }
    if (ctx && ctx->der_kvm) {
        mem.slot = DER_KVM_SLOT_ID;
        mem.guest_phys_addr = n->base_gpa;
        mem.memory_size = 0;
        mem.userspace_addr = 0;
        mem.flags = 0;
        ret = kvm_vm_ioctl(kvm, KVM_SET_USER_MEMORY_REGION, &mem);
        ctx->der_kvm->init_done = false;
    }
    return ret;
}
