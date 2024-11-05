#include <common.h>
#include <asm/processor.h>
#include <linux/ctype.h>
#include "memio.h"

static __inline__ unsigned long
get_msr(void)
{
	unsigned long msr;

	asm volatile("mfmsr %0" : "=r" (msr) :);
	return msr;
}

static __inline__ void
set_msr(unsigned long msr)
{
	asm volatile("mtmsr %0" : : "r" (msr));
}

static __inline__ unsigned long
get_dec(void)
{
	unsigned long val;

	asm volatile("mfdec %0" : "=r" (val) :);
	return val;
}


static __inline__ void
set_dec(unsigned long val)
{
	asm volatile("mtdec %0" : : "r" (val));
}


void
enable_interrupts(void)
{
    set_msr (get_msr() | MSR_EE);
}

/* returns flag if MSR_EE was set before */
int
disable_interrupts(void)
{
    ulong msr;

    msr = get_msr();
    set_msr (msr & ~MSR_EE);
    return ((msr & MSR_EE) != 0);
}

u8 in8(u32 port)
{
    return in_byte(port);
}

void out8(u32 port, u8 val)
{
    out_byte(port, val);
}

unsigned long in32(u32 port)
{
    return in_long(port);
}

static inline void
soft_restart(unsigned long addr)
{
	/* SRR0 has system reset vector, SRR1 has default MSR value */
	/* rfi restores MSR from SRR1 and sets the PC to the SRR0 value */

	__asm__ __volatile__ ("mtspr    26, %0"         :: "r" (addr));
	__asm__ __volatile__ ("li       4, (1 << 6)"    ::: "r4");
	__asm__ __volatile__ ("mtspr    27, 4");
	__asm__ __volatile__ ("rfi");

	while(1);       /* not reached */
}
