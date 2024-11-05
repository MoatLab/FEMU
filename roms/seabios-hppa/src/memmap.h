#ifndef __MEMMAP_H
#define __MEMMAP_H

#include "types.h" // u32

// A typical OS page size
#define PAGE_SIZE 4096
#define PAGE_SHIFT 12

static inline unsigned long virt_to_phys(void *v) {
    return (unsigned long)v;
}
static inline void *memremap(unsigned long addr, u32 len) {
    return (void*)addr;
}

// Return the value of a linker script symbol (see scripts/layoutrom.py)
#define SYMBOL(SYM) ({ extern char SYM; (unsigned long)&SYM; })
#define VSYMBOL(SYM) ((void*)SYMBOL(SYM))

#endif // memmap.h
