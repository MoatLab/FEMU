#ifndef __FEMU_KVM_EXT_H_
#define __FEMU_KVM_EXT_H_

#include "hw/femu/femu.h"
#include "cxlssd.h"

#include <linux/kvm.h>
#include "sysemu/kvm.h"

#define KVM_MEMSLOT_DUAL_MODE	(1UL << 17)
#define PAGE_SHIFT 12
#define MAX_ORDER 10
#define MAX_CONT_ALLOC_SZ (1<< (MAX_ORDER + PAGE_SHIFT))

typedef unsigned long long u64;
typedef uint64_t lpn_t;

struct kvm_set_epte_flag {
    uint64_t gpa;
    uint64_t flag;
    lpn_t lpn;
};

/* LEAF EPT entries */
struct kvm_memslot_linear_ept {
    u64* ept;
    int npages;
    int offset;
};

struct kvm_memslot_get_linear_ept {
    struct kvm_memslot_linear_ept ept_list[60];
    void *backend_ptr;
    u64 gfn;
    int n;
};

#define DER_KVM_SLOT_ID (0x2AU)

/* Per-CXLSSD KVM memslot/EPT state (lives in Cxlssd.der_kvm) */
typedef struct DerKvmState {
    struct kvm_memslot_get_linear_ept ept;
    bool init_done;
    void *userspace_addr;
    uint64_t memory_size;
    uint64_t guest_phys_addr;
    uint64_t hpa_base;
} DerKvmState;

#define KVM_SET_EPTE_FLAG		  _IOW(KVMIO, 0xdd, struct kvm_set_epte_flag)
#define KVM_GET_LINEAR_EPT		  _IOWR(KVMIO, 0xde, struct kvm_memslot_get_linear_ept)

int der_kvm_epte_set_trap(Cxlssd *ctx, uint64_t lpn);
int der_kvm_epte_set_driect(Cxlssd *ctx, uint64_t lpn, uint64_t hpa);

int der_kvm_set_user_memory_region(const FemuCtrl *n);
int der_kvm_del_user_memory_region(const FemuCtrl *n);

#endif