/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "../cxlssd/spte.h"
#include "../cxlssd/spt.h"
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static void test_spt_areas(void)
{
    uint64_t bytes = UINT64_C(64) * 1024 * 1024 * 1024 / 512;
    uint64_t size = cylon_spt_area_size(bytes, 0);
    unsigned char *resident = calloc(size / 4096, 1);
    void *area = cylon_spt_area(size);
    FILE *maps;
    char line[512];
    bool found = false;
    unsigned i;

    assert(area != MAP_FAILED);
    assert(size == 4 * 1024 * 1024);
    assert(cylon_spt_area_size(bytes, 31) == size);
    assert(cylon_spt_area_size(bytes, 32) == 0);
    assert(cylon_spt_area_size(UINT64_MAX, 60) == 0);
    assert(cylon_spt_area_size(256 * 1024 * 1024 / 512, 0) == 524288);
    assert(!mincore(area, size, resident));
    for (i = 0; i < size / 4096; i++) {
        assert(!(resident[i] & 1));
    }
    maps = fopen("/proc/self/maps", "r");
    assert(maps);
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start;
        unsigned long end;
        char perms[5];

        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3 &&
            start == (uintptr_t)area) {
            assert(end == start + size);
            assert(!strcmp(perms, "rw-s"));
            found = true;
            break;
        }
    }
    assert(found);
    fclose(maps);
    assert(!cylon_spt_mapped(area, size));
    munmap(area, size);
    free(resident);
}

static void test_spte_transitions(void)
{
    uint64_t direct = cylon_direct_spte(0x200000);
    uint64_t mmio = cylon_mmio_spte(0x110000000, 7);
    uint64_t spte = CYLON_REMOVED_SPTE;

    assert(cylon_spte_revoked(0));
    assert(cylon_spte_revoked(mmio));
    assert(cylon_spte_revoked(CYLON_REMOVED_SPTE));
    assert(!cylon_spte_revoked(direct));
    /*
     * The version 2 emulation marker: not present to the CPU (no R/W/X, no
     * MMU-present bit), not an MMIO entry, not KVM's frozen value.
     */
    assert(cylon_spte_revoked(CYLON_EMULATE_SPTE));
    assert(!(CYLON_EMULATE_SPTE & 7));
    assert(!(CYLON_EMULATE_SPTE & CYLON_MMU_PRESENT));
    assert(CYLON_EMULATE_SPTE != CYLON_REMOVED_SPTE);
    assert(!cylon_spte_install(&spte, mmio, direct));
    assert(spte == CYLON_REMOVED_SPTE);
    spte = mmio;
    assert(cylon_spte_install(&spte, mmio, direct));
    assert(spte == direct);
    /* A clear: revocation swaps the entry back without a flush. */
    assert(!(spte & CYLON_EPT_ACCESSED));
    assert(cylon_spte_install(&spte, direct, mmio));
    assert(spte == mmio);
    spte = direct | CYLON_EPT_ACCESSED;
    assert(cylon_spte_is_direct(spte, 0x200000));
    assert(!cylon_spte_install(&spte, direct, mmio));
    spte |= CYLON_EPT_DIRTY;
    assert(cylon_spte_is_direct(spte, 0x200000));
    assert(!cylon_spte_is_direct(spte, 0x400000));
    assert(cylon_spte_is_readonly_direct(cylon_spte_readonly(spte), 0x200000));
    assert(!cylon_spte_is_readonly_direct(spte, 0x200000));
    assert(!cylon_spte_install(&spte, direct, mmio));
    assert(cylon_spte_readonly(spte) & CYLON_EPT_DIRTY);
    assert(!(cylon_spte_readonly(spte) &
             (CYLON_EPT_WRITE | CYLON_MMU_WRITABLE)));
}

/* Sampling a mapped page's dirty bit keeps it mapped and writable. */
static void test_spte_take_dirty(void)
{
    uint64_t direct = cylon_direct_spte(0x200000);
    uint64_t spte = direct;
    bool dirty = true;

    assert(cylon_spte_take_dirty(&spte, direct, &dirty) && !dirty);
    assert(spte == direct);
    spte |= CYLON_EPT_DIRTY;
    assert(cylon_spte_take_dirty(&spte, direct, &dirty) && dirty);
    assert(spte == direct);
    assert(cylon_spte_take_dirty(&spte, direct, &dirty) && !dirty);
    /* The CPU sets A on first use; the entry is still ours and keeps A. */
    spte = direct | CYLON_EPT_AD;
    assert(cylon_spte_take_dirty(&spte, direct, &dirty) && dirty);
    assert(spte == (direct | CYLON_EPT_ACCESSED));
    /* Revoked, or another page's mapping: nothing is changed. */
    spte = CYLON_REMOVED_SPTE;
    assert(!cylon_spte_take_dirty(&spte, direct, &dirty));
    assert(spte == CYLON_REMOVED_SPTE);
    spte = cylon_direct_spte(0x400000) | CYLON_EPT_DIRTY;
    assert(!cylon_spte_take_dirty(&spte, direct, &dirty));
    assert(spte == (cylon_direct_spte(0x400000) | CYLON_EPT_DIRTY));
}

/* Store a pagemap entry for the huge page at @ram + @offset. */
static void put_entry(int fd, uintptr_t ram, uint64_t offset, uint64_t entry)
{
    if (pwrite(fd, &entry, sizeof(entry), (ram + offset) / CYLON_PAGE_SIZE *
               sizeof(entry)) != sizeof(entry)) {
        abort();
    }
}

static double seconds(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/*
 * The frame check reads the pagemap once per huge page when the caller
 * walks pages in order, and a ratio apply walks millions of pages.
 */
static void test_pfn_current(void)
{
    enum { HUGE_PAGES = 64, HUGE = 2 << 20 };
    char path[] = "/tmp/femu-pagemap-XXXXXX";
    uintptr_t ram = UINT64_C(0x40000000);
    uint64_t huge[HUGE_PAGES];
    uint64_t checked = UINT64_MAX;
    uint64_t offset;
    double t0;
    double per_page;
    double per_huge;
    unsigned i;
    int fd = mkstemp(path);

    assert(fd >= 0);
    unlink(path);
    for (i = 0; i < HUGE_PAGES; i++) {
        huge[i] = (UINT64_C(0x100000) + i) * HUGE;
        put_entry(fd, ram, i * (uint64_t)HUGE,
                  CYLON_PAGEMAP_PRESENT | huge[i] / CYLON_PAGE_SIZE);
    }
    assert(cylon_pfn_current(fd, huge, ram, HUGE, 4096, &checked));
    assert(checked == 0);
    /* The frame moves: a cached walk has checked it already, others see it. */
    put_entry(fd, ram, 0,
              CYLON_PAGEMAP_PRESENT | (huge[0] + HUGE) / CYLON_PAGE_SIZE);
    assert(cylon_pfn_current(fd, huge, ram, HUGE, 8192, &checked));
    assert(!cylon_pfn_current(fd, huge, ram, HUGE, 8192, NULL));
    checked = UINT64_MAX;
    assert(!cylon_pfn_current(fd, huge, ram, HUGE, 8192, &checked));
    assert(checked == UINT64_MAX);
    assert(cylon_pfn_current(fd, huge, ram, HUGE, HUGE + 4096, &checked));
    assert(checked == 1);
    /* Not present. */
    put_entry(fd, ram, 2 * (uint64_t)HUGE, 0);
    assert(!cylon_pfn_current(fd, huge, ram, HUGE, 2 * HUGE, NULL));
    put_entry(fd, ram, 0, CYLON_PAGEMAP_PRESENT | huge[0] / CYLON_PAGE_SIZE);
    put_entry(fd, ram, 2 * (uint64_t)HUGE,
              CYLON_PAGEMAP_PRESENT | huge[2] / CYLON_PAGE_SIZE);

    /* Microbenchmark: every 4 KiB page of the backing, both ways. */
    t0 = seconds();
    for (offset = 0; offset < HUGE_PAGES * (uint64_t)HUGE; offset += 4096) {
        assert(cylon_pfn_current(fd, huge, ram, HUGE, offset, NULL));
    }
    per_page = seconds() - t0;
    checked = UINT64_MAX;
    t0 = seconds();
    for (offset = 0; offset < HUGE_PAGES * (uint64_t)HUGE; offset += 4096) {
        assert(cylon_pfn_current(fd, huge, ram, HUGE, offset, &checked));
    }
    per_huge = seconds() - t0;
    printf("CXL frame check over %u pages: %.0f ns/page read per page, "
           "%.1f ns/page read per huge page\n", HUGE_PAGES * HUGE / 4096,
           per_page * 1e9 / (HUGE_PAGES * HUGE / 4096),
           per_huge * 1e9 / (HUGE_PAGES * HUGE / 4096));
    assert(per_huge * 4 < per_page);
    close(fd);
}

int main(void)
{
    uint64_t huge[] = { 0x200000, 0x1000000, 0x600000 };
    uint64_t pa;
    uint64_t index;
    uint64_t generation;
    uint64_t covered = 0;

    test_spt_areas();
    test_spte_transitions();
    test_spte_take_dirty();
    test_pfn_current();

    /* spte.h: RWX, WB, IPAT, MMU-present, host/MMU writable; A, D clear. */
    assert(cylon_direct_spte(0x12345000) == UINT64_C(0x600000012345877));
    assert(!(cylon_direct_spte(0x12345000) & CYLON_EPT_AD));
    assert((cylon_direct_spte(0x12345000) | CYLON_EPT_AD) ==
           UINT64_C(0x600000012345b77));
    /* The prototype's 0x586 encodes generation 0xb0, not a fixed mask. */
    assert(cylon_mmio_spte(0x110001000, 0xb0) == UINT64_C(0x110001586));
    assert(cylon_mmio_spte(0x110001000, 0) == UINT64_C(0x110001006));
    assert(cylon_mmio_spte(0x110001000, 0x7ffff) ==
           UINT64_C(0x7ff00001100017fe));
    for (generation = 0; generation <= CYLON_MMIO_GEN_MASK; generation++) {
        assert(cylon_mmio_generation(cylon_mmio_spte(0x110001000,
                                                   generation)) == generation);
    }
    assert(cylon_page_address(huge, 3, 0x200000, 0x1ff000, &pa));
    assert(pa == 0x3ff000);
    assert(cylon_page_address(huge, 3, 0x200000, 0x200000, &pa));
    assert(pa == 0x1000000);
    assert(cylon_page_address(huge, 3, 0x200000, 0x5ff000, &pa));
    assert(pa == 0x7ff000);
    assert(!cylon_page_address(huge, 3, 0x200000, 0x600000, &pa));
    assert(!cylon_page_address(huge, 3, 0x200000, UINT64_MAX, &pa));
    assert(!cylon_page_address(huge, 3, 0x200000, 1, &pa));
    assert(!cylon_page_address(huge, 3, 0, 0, &pa));
    assert(!cylon_page_address(huge, 3, 0x300000, 0, &pa));
    huge[0] = 0;
    assert(!cylon_page_address(huge, 3, 0x200000, 0, &pa));
    huge[0] = UINT64_MAX & ~UINT64_C(0x1fffff);
    assert(!cylon_page_address(huge, 3, 0x200000, 0, &pa));
    assert(cylon_page_index(8191, 8192, 2, &index) && index == 1);
    assert(!cylon_page_index(8192, 8192, 2, &index));
    assert(!cylon_page_index(4096, 8192, 1, &index));
    assert(!cylon_page_index(UINT64_MAX, 8192, 2, &index));
    assert(!cylon_page_index(0, 0, 0, &index));
    assert(cylon_spt_chunk(0, 1, 8192, &covered) && covered == 4096);
    assert(!cylon_spt_chunk(0, 1, 8192, &covered));
    assert(!cylon_spt_chunk(2, 1, 8192, &covered));
    assert(!cylon_spt_chunk(-1, 1, 8192, &covered));
    assert(!cylon_spt_chunk(1, -1, 8192, &covered));
    assert(!cylon_spt_chunk(1, 2, 8192, &covered));
    assert(cylon_spt_chunk(1, 1, 8192, &covered) && covered == 8192);
    assert(!cylon_spt_chunk(2, 1, 8192, &covered));
    puts("CXL SPTE encoders, generation, huge-page addresses and bounds: PASS");
    return 0;
}
