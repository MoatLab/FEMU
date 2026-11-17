/* Declarations for use for CPU state serialization.  */

#ifndef MIGRATION_CPU_H
#define MIGRATION_CPU_H

#include "exec/cpu-defs.h"
#include "migration/vmstate.h"

#if TARGET_LONG_BITS == 64
#define VMSTATE_UINTTL_V(_f, _s, _v)                                  \
    VMSTATE_UINT64_V(_f, _s, _v)
#define VMSTATE_UINTTL_ARRAY_V(_f, _s, _n, _v)                        \
    VMSTATE_UINT64_ARRAY_V(_f, _s, _n, _v)
#define VMSTATE_UINTTL_SUB_ARRAY(_f, _s, _start, _num)                \
    VMSTATE_UINT64_SUB_ARRAY(_f, _s, _start, _num)
#else
#define VMSTATE_UINTTL_V(_f, _s, _v)                                  \
    VMSTATE_UINT32_V(_f, _s, _v)
#define VMSTATE_UINTTL_ARRAY_V(_f, _s, _n, _v)                        \
    VMSTATE_UINT32_ARRAY_V(_f, _s, _n, _v)
#define VMSTATE_UINTTL_SUB_ARRAY(_f, _s, _start, _num)                \
    VMSTATE_UINT32_SUB_ARRAY(_f, _s, _start, _num)
#endif

#define VMSTATE_UINTTL(_f, _s)                                        \
    VMSTATE_UINTTL_V(_f, _s, 0)
#define VMSTATE_UINTTL_ARRAY(_f, _s, _n)                              \
    VMSTATE_UINTTL_ARRAY_V(_f, _s, _n, 0)

#endif
