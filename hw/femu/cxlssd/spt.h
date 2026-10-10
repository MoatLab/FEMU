/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FEMU_CXL_SPT_H
#define FEMU_CXL_SPT_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

/* The published x86 Cylon ABI uses MAX_ORDER=10, PAGE_SHIFT=12. */
#define CYLON_SPT_CHUNKS 60
#define CYLON_SPT_CHUNK_SIZE (UINT64_C(1) << 22)

static inline uint64_t cylon_spt_area_size(uint64_t bytes, unsigned i)
{
    uint64_t offset = (uint64_t)i * CYLON_SPT_CHUNK_SIZE;

    if (i >= CYLON_SPT_CHUNKS || offset >= bytes) {
        return 0;
    }
    return bytes - offset < CYLON_SPT_CHUNK_SIZE ?
           bytes - offset : CYLON_SPT_CHUNK_SIZE;
}

static inline void *cylon_spt_area(uint64_t size)
{
    /* Faulting even one PTE here makes the kernel remap unsafe. */
    return mmap(NULL, size, PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_ANONYMOUS, -1, 0);
}

/*
 * Whether the kernel mapped its tables over @area: older Cylon kernels map
 * them as raw PFNs ("pf"), newer ones as refcounted pages ("mm").
 */
static inline bool cylon_spt_mapped(void *area, uint64_t size)
{
    FILE *file = fopen("/proc/self/smaps", "r");
    char line[512];
    unsigned long start;
    unsigned long end;
    bool match = false;
    bool mapped = false;

    if (!file) {
        return false;
    }
    while (fgets(line, sizeof(line), file)) {
        if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
            match = start == (uintptr_t)area && end - start == size;
        } else if (match && !strncmp(line, "VmFlags:", 8)) {
            mapped = strstr(line, " pf ") || strstr(line, " mm ");
            break;
        }
    }
    fclose(file);
    return mapped;
}
#endif
