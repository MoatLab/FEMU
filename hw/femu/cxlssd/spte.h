/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FEMU_CXL_SPTE_H
#define FEMU_CXL_SPTE_H

#include <stdbool.h>
#include <stdint.h>

/* CylonLinux arch/x86/kvm/mmu/spte.h and Intel EPT definitions. */
#define CYLON_PAGE_SIZE UINT64_C(4096)
#define CYLON_ADDR_MASK UINT64_C(0x000ffffffffff000)
#define CYLON_EPT_READ UINT64_C(1)
#define CYLON_EPT_WRITE UINT64_C(2)
#define CYLON_EPT_EXEC UINT64_C(4)
#define CYLON_EPT_WB (UINT64_C(6) << 3)
#define CYLON_EPT_IPAT (UINT64_C(1) << 6)
#define CYLON_EPT_ACCESSED (UINT64_C(1) << 8)
#define CYLON_EPT_DIRTY (UINT64_C(1) << 9)
#define CYLON_MMU_PRESENT (UINT64_C(1) << 11)
#define CYLON_HOST_WRITABLE (UINT64_C(1) << 57)
#define CYLON_MMU_WRITABLE (UINT64_C(1) << 58)
#define CYLON_MMIO_GEN_MASK UINT64_C(0x7ffff)
#define CYLON_MMIO_GEN_LOW UINT64_C(0xff)
#define CYLON_MMIO_GEN_HIGH UINT64_C(0x7ff00)
#define CYLON_MMIO_VALUE (CYLON_EPT_WRITE | CYLON_EPT_EXEC)
#define CYLON_EPT_AD (CYLON_EPT_ACCESSED | CYLON_EPT_DIRTY)
/* A and D start clear and are the CPU's to set. */
#define CYLON_DIRECT_FLAGS (CYLON_EPT_READ | CYLON_EPT_WRITE | \
    CYLON_EPT_EXEC | CYLON_EPT_WB | CYLON_EPT_IPAT | \
    CYLON_MMU_PRESENT | CYLON_HOST_WRITABLE | CYLON_MMU_WRITABLE)

#define CYLON_REMOVED_SPTE UINT64_C(0x5a0)

static inline bool cylon_spte_revoked(uint64_t spte)
{
    return !spte || spte == CYLON_REMOVED_SPTE ||
           ((spte & 7) == CYLON_MMIO_VALUE && !(spte & CYLON_MMU_PRESENT));
}

static inline uint64_t cylon_spte_readonly(uint64_t spte)
{
    return spte & ~(CYLON_EPT_WRITE | CYLON_MMU_WRITABLE);
}

static inline bool cylon_spte_install(uint64_t *sptep, uint64_t old,
                                      uint64_t value)
{
    return __atomic_compare_exchange_n(sptep, &old, value, false,
                                        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}

static inline uint64_t cylon_direct_spte(uint64_t pa)
{
    return pa | CYLON_DIRECT_FLAGS;
}

/* Whether @spte is our direct entry for @pa, whatever A and D the CPU set. */
static inline bool cylon_spte_is_direct(uint64_t spte, uint64_t pa)
{
    return (spte & ~CYLON_EPT_AD) == cylon_direct_spte(pa);
}

static inline bool cylon_spte_is_readonly_direct(uint64_t spte, uint64_t pa)
{
    return (spte & ~CYLON_EPT_AD) == cylon_spte_readonly(cylon_direct_spte(pa));
}

static inline uint64_t cylon_mmio_spte(uint64_t gpa, uint64_t generation)
{
    return gpa | CYLON_MMIO_VALUE |
        ((generation & CYLON_MMIO_GEN_LOW) << 3) |
        ((generation & CYLON_MMIO_GEN_HIGH) << 44);
}

static inline uint64_t cylon_mmio_generation(uint64_t spte)
{
    return ((spte >> 3) & CYLON_MMIO_GEN_LOW) |
           ((spte >> 44) & CYLON_MMIO_GEN_HIGH);
}

static inline bool cylon_spt_chunk(int offset, int npages, uint64_t total,
                                   uint64_t *covered)
{
    uint64_t length;

    if (offset < 0 || npages <= 0 || *covered > total ||
        (uint64_t)offset * CYLON_PAGE_SIZE != *covered) {
        return false;
    }
    length = (uint64_t)npages * CYLON_PAGE_SIZE;
    if (length > total - *covered) {
        return false;
    }
    *covered += length;
    return true;
}

static inline bool cylon_page_index(uint64_t offset, uint64_t window_size,
                                    uint64_t entries, uint64_t *index)
{
    if (offset >= window_size || offset / CYLON_PAGE_SIZE >= entries) {
        return false;
    }
    *index = offset / CYLON_PAGE_SIZE;
    return true;
}

static inline bool cylon_page_address(const uint64_t *huge, uint64_t count,
                                      uint64_t huge_size, uint64_t offset,
                                      uint64_t *pa)
{
    uint64_t base;
    uint64_t within;

    if (huge_size < CYLON_PAGE_SIZE || (huge_size & (huge_size - 1)) ||
        offset / huge_size >= count || (offset & (CYLON_PAGE_SIZE - 1))) {
        return false;
    }
    base = huge[offset / huge_size];
    within = offset % huge_size;
    if (!base || (base & (huge_size - 1)) ||
        (base & ~CYLON_ADDR_MASK) || within > CYLON_ADDR_MASK - base) {
        return false;
    }
    *pa = base + within;
    return true;
}
#endif
