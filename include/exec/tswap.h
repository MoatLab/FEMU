/*
 * Macros for swapping a value if the endianness is different
 * between the target and the host.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef TSWAP_H
#define TSWAP_H

#include "qemu/bswap.h"
#include "qemu/target-info.h"
#include "hw/core/cpu.h"

/*
 * If we're in target-specific code, we can hard-code the swapping
 * condition, otherwise we have to do (slower) run-time checks.
 */
#ifdef COMPILING_PER_TARGET
#define target_needs_bswap()  (HOST_BIG_ENDIAN != TARGET_BIG_ENDIAN)
#else
#define target_needs_bswap()  (HOST_BIG_ENDIAN != target_big_endian())
#endif /* COMPILING_PER_TARGET */

#if defined(CONFIG_USER_ONLY) \
    || !defined(TARGET_NOT_USING_LEGACY_NATIVE_ENDIAN_API)
static inline uint16_t tswap16(uint16_t s)
{
    if (target_needs_bswap()) {
        return bswap16(s);
    } else {
        return s;
    }
}

static inline uint32_t tswap32(uint32_t s)
{
    if (target_needs_bswap()) {
        return bswap32(s);
    } else {
        return s;
    }
}

static inline uint64_t tswap64(uint64_t s)
{
    if (target_needs_bswap()) {
        return bswap64(s);
    } else {
        return s;
    }
}

static inline void tswap16s(uint16_t *s)
{
    if (target_needs_bswap()) {
        *s = bswap16(*s);
    }
}

static inline void tswap32s(uint32_t *s)
{
    if (target_needs_bswap()) {
        *s = bswap32(*s);
    }
}

static inline void tswap64s(uint64_t *s)
{
    if (target_needs_bswap()) {
        *s = bswap64(*s);
    }
}
#endif

/*
 * If we're in semihosting code, have to swap depending on the currently
 * configured endianness of the CPU. These functions should not be used in
 * other contexts.
 */
#define cpu_internal_needs_bswap(cpu) \
    (HOST_BIG_ENDIAN != cpu_internal_is_big_endian(cpu))

static inline uint16_t cpu_internal_tswap16(CPUState *cpu, uint16_t s)
{
    if (cpu_internal_needs_bswap(cpu)) {
        return bswap16(s);
    } else {
        return s;
    }
}

static inline uint32_t cpu_internal_tswap32(CPUState *cpu, uint32_t s)
{
    if (cpu_internal_needs_bswap(cpu)) {
        return bswap32(s);
    } else {
        return s;
    }
}

static inline uint64_t cpu_internal_tswap64(CPUState *cpu, uint64_t s)
{
    if (cpu_internal_needs_bswap(cpu)) {
        return bswap64(s);
    } else {
        return s;
    }
}

#endif  /* TSWAP_H */
