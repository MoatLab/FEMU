/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "../cxlssd/spte.h"

int main(void)
{
    uint64_t huge[] = { 0x200000, 0x1000000, 0x600000 };
    uint64_t pa;
    uint64_t index;
    uint64_t generation;
    uint64_t covered = 0;

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
