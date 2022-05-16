// Internal dynamic memory allocations.
//
// Copyright (C) 2009-2013  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_BDA
#include "config.h" // BUILD_BIOS_ADDR
#include "e820map.h" // struct e820entry
#include "list.h" // hlist_node
#include "malloc.h" // _malloc
#include "memmap.h" // PAGE_SIZE
#include "output.h" // dprintf
#include "stacks.h" // wait_preempt
#include "std/optionrom.h" // OPTION_ROM_ALIGN
#include "string.h" // memset

static unsigned long stackptr;

/****************************************************************
 * tracked memory allocations
 ****************************************************************/

// Allocate physical memory from the given zone and track it as a PMM allocation
unsigned long
malloc_palloc(struct zone_s *zone, u32 size, u32 align)
{
    unsigned long data;

    ASSERT32FLAT();
    if (!size)
        return 0;

    stackptr = (stackptr + align-1) & ~(align-1);
    data = stackptr;
    stackptr += size;

    dprintf(8, "size=%d align=%d ret=0x%lx\n" , size, align, data);

    return data;
}

// Allocate virtual memory from the given zone
void * __malloc
parisc_malloc(u32 size, u32 align)
{
    return (void*) malloc_palloc(NULL, size, align);
}

// Free a data block allocated with phys_alloc
int
malloc_pfree(u32 data)
{
    return 0;
}

void
free(void *data)
{
}



/****************************************************************
 * Setup
 ****************************************************************/

void
malloc_preinit(void)
{
    ASSERT32FLAT();
    dprintf(3, "malloc preinit\n");
    extern u8 _ebss;
    stackptr = (unsigned long) &_ebss;
}

u32 LegacyRamSize VARFSEG;

void
malloc_init(void)
{
    ASSERT32FLAT();
    dprintf(3, "malloc init\n");
}

void
malloc_prepboot(void)
{
    ASSERT32FLAT();
    dprintf(3, "malloc finalize\n");
}
