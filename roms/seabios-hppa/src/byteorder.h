#ifndef __BYTEORDER_H
#define __BYTEORDER_H

#include "autoconf.h"
#include "types.h" // u32

#if CONFIG_X86
#define TARGET_LITTLE_ENDIAN
#elif CONFIG_PARISC
#define TARGET_BIG_ENDIAN
#else
#error "unknown endianess"
#endif

static inline u16 __swab16_constant(u16 val) {
    return (val<<8) | (val>>8);
}
static inline u32 __swab32_constant(u32 val) {
    return (val<<24) | ((val&0xff00)<<8) | ((val&0xff0000)>>8) | (val>>24);
}
static inline u64 __swab64_constant(u64 val) {
    return ((u64)__swab32_constant(val) << 32) | __swab32_constant(val>>32);
}
static inline u32 __swab32(u32 val) {
#if CONFIG_X86
    asm("bswapl %0" : "+r"(val));
#elif CONFIG_PARISC
    unsigned int temp;
    asm("shd %0, %0, 16, %1\n\t"	/* shift abcdabcd -> cdab */
        "dep %1, 15, 8, %1\n\t"		/* deposit cdab -> cbab */
        "shd %0, %1, 8, %0"		/* shift abcdcbab -> dcba */
        : "=r" (val), "=&r" (temp)
        : "0" (val));
#else
    #error "unknown arch"
#endif
    return val;
}
static inline u64 __swab64(u64 val) {
    union u64_u32_u i, o;
    i.val = val;
    o.lo = __swab32(i.hi);
    o.hi = __swab32(i.lo);
    return o.val;
}

#define swab16(x) __swab16_constant(x)
#define swab32(x) (__builtin_constant_p((u32)(x)) \
                   ? __swab32_constant(x) : __swab32(x))
#define swab64(x) (__builtin_constant_p((u64)(x)) \
                   ? __swab64_constant(x) : __swab64(x))

#if defined(TARGET_BIG_ENDIAN)
static inline u16 cpu_to_le16(u16 x) {
    return swab16(x);
}
static inline u32 cpu_to_le32(u32 x) {
    return swab32(x);
}
static inline u64 cpu_to_le64(u64 x) {
    return swab64(x);
}
static inline u16 le16_to_cpu(u16 x) {
    return swab16(x);
}
static inline u32 le32_to_cpu(u32 x) {
    return swab32(x);
}
static inline u64 le64_to_cpu(u64 x) {
    return swab64(x);
}

static inline u16 cpu_to_be16(u16 x) {
    return x;
}
static inline u32 cpu_to_be32(u32 x) {
    return x;
}
static inline u64 cpu_to_be64(u64 x) {
    return x;
}
static inline u16 be16_to_cpu(u16 x) {
    return x;
}
static inline u32 be32_to_cpu(u32 x) {
    return x;
}
static inline u64 be64_to_cpu(u64 x) {
    return x;
}

static inline void convert_to_le32(u32 *script, unsigned long bytes)
{
    while (bytes > 0) {
	*script = cpu_to_le32(*script);
	script++;
	bytes -= sizeof(u32);
    }
}

#else /* defined(TARGET_LITTLE_ENDIAN) */
static inline u16 cpu_to_le16(u16 x) {
    return x;
}
static inline u32 cpu_to_le32(u32 x) {
    return x;
}
static inline u64 cpu_to_le64(u64 x) {
    return x;
}
static inline u16 le16_to_cpu(u16 x) {
    return x;
}
static inline u32 le32_to_cpu(u32 x) {
    return x;
}
static inline u64 le64_to_cpu(u64 x) {
    return x;
}

static inline u16 cpu_to_be16(u16 x) {
    return swab16(x);
}
static inline u32 cpu_to_be32(u32 x) {
    return swab32(x);
}
static inline u64 cpu_to_be64(u64 x) {
    return swab64(x);
}
static inline u16 be16_to_cpu(u16 x) {
    return swab16(x);
}
static inline u32 be32_to_cpu(u32 x) {
    return swab32(x);
}
static inline u64 be64_to_cpu(u64 x) {
    return swab64(x);
}

static inline void convert_to_le32(u32 *script, unsigned long bytes)
{
}
#endif

#endif // byteorder.h
