// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2017 IBM Corp. */

#ifndef __IO_H
#define __IO_H

#ifndef __ASSEMBLY__

#include <compiler.h>
#include <stdint.h>
#include <processor.h>
#include <types.h>
#include <ccan/endian/endian.h>

/*
 * IO access functions
 *
 * __in_beXX() / __out_beXX() : non-byteswap, no barrier
 * in_beXX() / out_beXX()     : non-byteswap, barrier
 * in_leXX() / out_leXX()     : byteswap, barrier
 */

static inline uint8_t __in_8(const volatile uint8_t *addr)
{
	uint8_t val;
	asm volatile("lbzcix %0,0,%1" :
		     "=r"(val) : "r"(addr), "m"(*addr) : "memory");
	return val;
}

static inline uint8_t in_8(const volatile uint8_t *addr)
{
	sync();
	return __in_8(addr);
}

static inline uint16_t __in_be16(const volatile beint16_t *addr)
{
	__be16 val;
	asm volatile("lhzcix %0,0,%1" :
		     "=r"(val) : "r"(addr), "m"(*addr) : "memory");
	return be16_to_cpu(val);
}

static inline uint16_t in_be16(const volatile beint16_t *addr)
{
	sync();
	return __in_be16(addr);
}

static inline uint16_t __in_le16(const volatile leint16_t *addr)
{
	__le16 val;
	asm volatile("lhzcix %0,0,%1" :
		     "=r"(val) : "r"(addr), "m"(*addr) : "memory");
	return le16_to_cpu(val);
}

static inline uint16_t in_le16(const volatile leint16_t *addr)
{
	sync();
	return __in_le16(addr);
}

static inline uint32_t __in_be32(const volatile beint32_t *addr)
{
	__be32 val;
	asm volatile("lwzcix %0,0,%1" :
		     "=r"(val) : "r"(addr), "m"(*addr) : "memory");
	return be32_to_cpu(val);
}

static inline uint32_t in_be32(const volatile beint32_t *addr)
{
	sync();
	return __in_be32(addr);
}

static inline uint32_t __in_le32(const volatile leint32_t *addr)
{
	__le32 val;
	asm volatile("lwzcix %0,0,%1" :
		     "=r"(val) : "r"(addr), "m"(*addr) : "memory");
	return le32_to_cpu(val);
}

static inline uint32_t in_le32(const volatile leint32_t *addr)
{
	sync();
	return __in_le32(addr);
}

static inline uint64_t __in_be64(const volatile beint64_t *addr)
{
	__be64 val;
	asm volatile("ldcix %0,0,%1" :
		     "=r"(val) : "r"(addr), "m"(*addr) : "memory");
	return be64_to_cpu(val);
}

static inline uint64_t in_be64(const volatile beint64_t *addr)
{
	sync();
	return __in_be64(addr);
}

static inline uint64_t __in_le64(const volatile leint64_t *addr)
{
	__le64 val;
	asm volatile("ldcix %0,0,%1" :
		     "=r"(val) : "r"(addr), "m"(*addr) : "memory");
	return le64_to_cpu(val);
}

static inline uint64_t in_le64(const volatile leint64_t *addr)
{
	sync();
	return __in_le64(addr);
}

static inline void __out_8(volatile uint8_t *addr, uint8_t val)
{
	asm volatile("stbcix %0,0,%1"
		     : : "r"(val), "r"(addr), "m"(*addr) : "memory");
}

static inline void out_8(volatile uint8_t *addr, uint8_t val)
{
	sync();
	return __out_8(addr, val);
}

static inline void __out_be16(volatile beint16_t *addr, uint16_t val)
{
	asm volatile("sthcix %0,0,%1"
		     : : "r"(cpu_to_be16(val)), "r"(addr), "m"(*addr) : "memory");
}

static inline void out_be16(volatile beint16_t *addr, uint16_t val)
{
	sync();
	return __out_be16(addr, val);
}

static inline void __out_le16(volatile leint16_t *addr, uint16_t val)
{
	asm volatile("sthcix %0,0,%1"
		     : : "r"(cpu_to_le16(val)), "r"(addr), "m"(*addr) : "memory");
}

static inline void out_le16(volatile leint16_t *addr, uint16_t val)
{
	sync();
	return __out_le16(addr, val);
}

static inline void __out_be32(volatile beint32_t *addr, uint32_t val)
{
	asm volatile("stwcix %0,0,%1"
		     : : "r"(cpu_to_be32(val)), "r"(addr), "m"(*addr) : "memory");
}

static inline void out_be32(volatile beint32_t *addr, uint32_t val)
{
	sync();
	return __out_be32(addr, val);
}

static inline void __out_le32(volatile leint32_t *addr, uint32_t val)
{
	asm volatile("stwcix %0,0,%1"
		     : : "r"(cpu_to_le32(val)), "r"(addr), "m"(*addr) : "memory");
}

static inline void out_le32(volatile leint32_t *addr, uint32_t val)
{
	sync();
	return __out_le32(addr, val);
}

static inline void __out_be64(volatile beint64_t *addr, uint64_t val)
{
	asm volatile("stdcix %0,0,%1"
		     : : "r"(cpu_to_be64(val)), "r"(addr), "m"(*addr) : "memory");
}

static inline void out_be64(volatile beint64_t *addr, uint64_t val)
{
	sync();
	return __out_be64(addr, val);
}

static inline void __out_le64(volatile leint64_t *addr, uint64_t val)
{
	asm volatile("stdcix %0,0,%1"
		     : : "r"(cpu_to_le64(val)), "r"(addr), "m"(*addr) : "memory");
}

static inline void out_le64(volatile leint64_t *addr, uint64_t val)
{
	sync();
	return __out_le64(addr, val);
}

/* Assistant to macros used to access PCI config space */
#define in_le8	in_8
#define out_le8	out_8

/* Ensure completion of a load (ie, value returned to CPU)
 * before continuing execution
 */
static inline void load_wait(uint64_t data)
{
	asm volatile("twi 0,%0,0;isync" : : "r" (data) : "memory");
}

#endif /* __ASSEMBLY__ */

#endif /* __IO_H */
