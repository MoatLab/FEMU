/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "../cxlssd/spte.h"
#include "../cxlssd/spt.h"
#include <stdlib.h>
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
    assert(!cylon_spte_install(&spte, mmio, direct));
    assert(spte == CYLON_REMOVED_SPTE);
    spte = mmio;
    assert(cylon_spte_install(&spte, mmio, direct));
    assert(spte == direct);
    spte |= CYLON_EPT_DIRTY;
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
    /* Revoked, or another page's mapping: nothing is changed. */
    spte = CYLON_REMOVED_SPTE;
    assert(!cylon_spte_take_dirty(&spte, direct, &dirty));
    assert(spte == CYLON_REMOVED_SPTE);
    spte = cylon_direct_spte(0x400000) | CYLON_EPT_DIRTY;
    assert(!cylon_spte_take_dirty(&spte, direct, &dirty));
    assert(spte == (cylon_direct_spte(0x400000) | CYLON_EPT_DIRTY));
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

    /* spte.h: RWX, WB, IPAT, A, MMU-present, host/MMU writable. */
    assert(cylon_direct_spte(0x12345000) == UINT64_C(0x600000012345977));
    assert(!(cylon_direct_spte(0x12345000) & CYLON_EPT_DIRTY));
    assert((cylon_direct_spte(0x12345000) | CYLON_EPT_DIRTY) ==
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
