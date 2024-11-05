// Memory access to BIOS variables.
//
// Copyright (C) 2008-2013  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.
#ifndef __BIOSVAR_H
#define __BIOSVAR_H

#include "autoconf.h" // CONFIG_*
#include "config.h" // SEG_BDA
#include "farptr.h" // GET_FARVAR
#include "memmap.h" // SYMBOL
#include "std/bda.h" // struct bios_data_area_s


/****************************************************************
 * Interrupt vector table
 ****************************************************************/

#if CONFIG_X86
#define GET_IVT(vector)                                         \
    GET_FARVAR(SEG_IVT, ((struct rmode_IVT *)0)->ivec[vector])
#define SET_IVT(vector, segoff)                                         \
    SET_FARVAR(SEG_IVT, ((struct rmode_IVT *)0)->ivec[vector], segoff)

#define FUNC16(func) ({                                 \
        ASSERT32FLAT();                                 \
        extern void func (void);                        \
        SEGOFF(SEG_BIOS, (u32)func - BUILD_BIOS_ADDR);  \
    })
#elif CONFIG_PARISC
extern struct segoff_s ivt_table[256];

#define GET_IVT(vector)		ivt_table[vector]
#define SET_IVT(vector, segoff)	ivt_table[vector] = (segoff)

#define FUNC16(func) ({ SEGOFF(0, 0); })
#endif


/****************************************************************
 * Bios Data Area (BDA)
 ****************************************************************/

static inline struct bios_data_area_s *
get_bda_ptr(void)
{
#if CONFIG_X86
    return MAKE_FLATPTR(SEG_BDA, 0);
#elif CONFIG_PARISC
    extern struct bios_data_area_s bios_data_area;
    return &bios_data_area;
#endif
}

// Accessor functions
#if CONFIG_X86
#define GET_BDA(var) \
    GET_FARVAR(SEG_BDA, ((struct bios_data_area_s *)0)->var)
#define SET_BDA(var, val) \
    SET_FARVAR(SEG_BDA, ((struct bios_data_area_s *)0)->var, (val))
#elif CONFIG_PARISC
#define GET_BDA(var)		get_bda_ptr()->var
#define SET_BDA(var, val)	get_bda_ptr()->var = (val)
#endif

// Helper function to set the bits of the equipment_list_flags variable.
static inline void set_equipment_flags(u16 clear, u16 set) {
    u16 eqf = GET_BDA(equipment_list_flags);
    SET_BDA(equipment_list_flags, (eqf & ~clear) | set);
}


/****************************************************************
 * Extended Bios Data Area (EBDA)
 ****************************************************************/

// The initial size and location of EBDA
#define EBDA_SIZE_START \
    DIV_ROUND_UP(sizeof(struct extended_bios_data_area_s), 1024)
#define EBDA_SEGMENT_START \
    FLATPTR_TO_SEG(BUILD_LOWRAM_END - EBDA_SIZE_START*1024)

// Accessor functions
static inline u16 get_ebda_seg(void) {
    return GET_BDA(ebda_seg);
}
static inline struct extended_bios_data_area_s *
get_ebda_ptr(void)
{
    ASSERT32FLAT();
    return MAKE_FLATPTR(get_ebda_seg(), 0);
}
#define GET_EBDA(eseg, var)                                             \
    GET_FARVAR(eseg, ((struct extended_bios_data_area_s *)0)->var)
#define SET_EBDA(eseg, var, val)                                        \
    SET_FARVAR(eseg, ((struct extended_bios_data_area_s *)0)->var, (val))


/****************************************************************
 * Global variables
 ****************************************************************/

#if MODE16 == 0 && MODESEGMENT == 1
// In 32bit segmented mode %cs may not be readable and the code may be
// relocated.  The entry code sets up %gs with a readable segment and
// the code offset can be determined by get_global_offset().
#define GLOBAL_SEGREG GS
static inline u32 __attribute_const get_global_offset(void) {
    u32 ret;
    asm("  calll 1f\n"
        "1:popl %0\n"
        "  subl $1b, %0"
        : "=r"(ret));
    return ret;
}
#else
#define GLOBAL_SEGREG CS
static inline u32 __attribute_const get_global_offset(void) {
    return 0;
}
#endif
static inline u16 get_global_seg(void) {
    return GET_SEG(GLOBAL_SEGREG);
}
#if CONFIG_X86
#define GET_GLOBAL(var)                                                 \
    GET_VAR(GLOBAL_SEGREG, *(typeof(&(var)))((void*)&(var)              \
                                             + get_global_offset()))
#elif CONFIG_PARISC
#define GET_GLOBAL(var) (var)
#endif

#if MODESEGMENT
#define GLOBALFLAT2GLOBAL(var) ((typeof(var))((void*)(var) - BUILD_BIOS_ADDR))
#else
#define GLOBALFLAT2GLOBAL(var) (var)
#endif
// Access a "flat" pointer known to point to the f-segment.
#define GET_GLOBALFLAT(var) GET_GLOBAL(*GLOBALFLAT2GLOBAL(&(var)))


/****************************************************************
 * "Low" memory variables
 ****************************************************************/

#define SEG_LOW SYMBOL(_zonelow_seg)

#if MODESEGMENT
#define GET_LOW(var)            GET_FARVAR(SEG_LOW, (var))
#define SET_LOW(var, val)       SET_FARVAR(SEG_LOW, (var), (val))
#define LOWFLAT2LOW(var) ((typeof(var))((void*)(var) - SYMBOL(zonelow_base)))
#else
#define GET_LOW(var)            (var)
#define SET_LOW(var, val)       do { (var) = (val); } while (0)
#define LOWFLAT2LOW(var) (var)
#endif
#define GET_LOWFLAT(var) GET_LOW(*LOWFLAT2LOW(&(var)))
#define SET_LOWFLAT(var, val) SET_LOW(*LOWFLAT2LOW(&(var)), (val))

#endif // __BIOSVAR_H
