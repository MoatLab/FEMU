/*
 * Taken from kernel for decoupling from <asm/page.h>. --zaitcev
 *
 * $Id: pgtsrmmu.h,v 1.2 1999/04/19 01:04:31 zaitcev Exp $
 * pgtsrmmu.h:  SRMMU page table defines and code.
 *
 * Copyright (C) 1995 David S. Miller (davem@caip.rutgers.edu)
 */

#ifndef _PGTSRMMU_H
#define _PGTSRMMU_H

/* PMD_SHIFT determines the size of the area a second-level page table can map */
#define SRMMU_PMD_SHIFT         18
#define SRMMU_PMD_SIZE          (1UL << SRMMU_PMD_SHIFT)
#define SRMMU_PMD_MASK          (~(SRMMU_PMD_SIZE-1))
#define SRMMU_PMD_ALIGN(addr)   (((addr)+SRMMU_PMD_SIZE-1)&SRMMU_PMD_MASK)

/* PGDIR_SHIFT determines what a third-level page table entry can map */
#define SRMMU_PGDIR_SHIFT       24
#define SRMMU_PGDIR_SIZE        (1UL << SRMMU_PGDIR_SHIFT)
#define SRMMU_PGDIR_MASK        (~(SRMMU_PGDIR_SIZE-1))
#define SRMMU_PGDIR_ALIGN(addr) (((addr)+SRMMU_PGDIR_SIZE-1)&SRMMU_PGDIR_MASK)

#define SRMMU_PTRS_PER_PTE      64
#define SRMMU_PTRS_PER_PMD      64
#define SRMMU_PTRS_PER_PGD      256

#define SRMMU_PTE_TABLE_SIZE    0x100 /* 64 entries, 4 bytes a piece */
#define SRMMU_PMD_TABLE_SIZE    0x100 /* 64 entries, 4 bytes a piece */
#define SRMMU_PGD_TABLE_SIZE    0x400 /* 256 entries, 4 bytes a piece */

#define SRMMU_VMALLOC_START   (0xfe300000)
#define SRMMU_VMALLOC_END     ~0x0UL

/* Definition of the values in the ET field of PTD's and PTE's */
#define SRMMU_ET_MASK         0x3
#define SRMMU_ET_INVALID      0x0
#define SRMMU_ET_PTD          0x1
#define SRMMU_ET_PTE          0x2
#define SRMMU_ET_REPTE        0x3 /* AIEEE, SuperSparc II reverse endian page! */

/* Physical page extraction from PTP's and PTE's. */
#define SRMMU_CTX_PMASK    0xfffffff0
#define SRMMU_PTD_PMASK    0xfffffff0
#define SRMMU_PTE_PMASK    0xffffff00

/* The pte non-page bits.  Some notes:
 * 1) cache, dirty, valid, and ref are frobbable
 *    for both supervisor and user pages.
 * 2) exec and write will only give the desired effect
 *    on user pages
 * 3) use priv and priv_readonly for changing the
 *    characteristics of supervisor ptes
 */
#define SRMMU_CACHE        0x80
#define SRMMU_DIRTY        0x40
#define SRMMU_REF          0x20
#define SRMMU_EXEC         0x08
#define SRMMU_WRITE        0x04
#define SRMMU_VALID        0x02 /* SRMMU_ET_PTE */
#define SRMMU_PRIV         0x1c
#define SRMMU_PRIV_RDONLY  0x18

#define SRMMU_CHG_MASK    (0xffffff00 | SRMMU_REF | SRMMU_DIRTY)

/* SRMMU Register addresses in ASI 0x4.  These are valid for all
 * current SRMMU implementations that exist.
 */
#define SRMMU_CTRL_REG           0x00000000
#define SRMMU_CTXTBL_PTR         0x00000100
#define SRMMU_CTX_REG            0x00000200
#define SRMMU_FAULT_STATUS       0x00000300
#define SRMMU_FAULT_ADDR         0x00000400

#ifndef __ASSEMBLY__

/* Accessing the MMU control register. */
static __inline__ unsigned int srmmu_get_mmureg(void)
{
        unsigned int retval;
	__asm__ __volatile__("lda [%%g0] %1, %0\n\t" :
			     "=r" (retval) :
			     "i" (ASI_M_MMUREGS));
	return retval;
}

static __inline__ void srmmu_set_mmureg(unsigned long regval)
{
	__asm__ __volatile__("sta %0, [%%g0] %1\n\t" : :
			     "r" (regval), "i" (ASI_M_MMUREGS) : "memory");

}

static __inline__ void srmmu_set_ctable_ptr(unsigned long paddr)
{
	paddr = ((paddr >> 4) & SRMMU_CTX_PMASK);
	__asm__ __volatile__("sta %0, [%1] %2\n\t" : :
			     "r" (paddr), "r" (SRMMU_CTXTBL_PTR),
			     "i" (ASI_M_MMUREGS) :
			     "memory");
}

static __inline__ unsigned long srmmu_get_ctable_ptr(void)
{
	unsigned int retval;

	__asm__ __volatile__("lda [%1] %2, %0\n\t" :
			     "=r" (retval) :
			     "r" (SRMMU_CTXTBL_PTR),
			     "i" (ASI_M_MMUREGS));
	return (retval & SRMMU_CTX_PMASK) << 4;
}

static __inline__ void srmmu_set_context(int context)
{
	__asm__ __volatile__("sta %0, [%1] %2\n\t" : :
			     "r" (context), "r" (SRMMU_CTX_REG),
			     "i" (ASI_M_MMUREGS) : "memory");
}

static __inline__ int srmmu_get_context(void)
{
	register int retval;
	__asm__ __volatile__("lda [%1] %2, %0\n\t" :
			     "=r" (retval) :
			     "r" (SRMMU_CTX_REG),
			     "i" (ASI_M_MMUREGS));
	return retval;
}

static __inline__ unsigned int srmmu_get_fstatus(void)
{
	unsigned int retval;

	__asm__ __volatile__("lda [%1] %2, %0\n\t" :
			     "=r" (retval) :
			     "r" (SRMMU_FAULT_STATUS), "i" (ASI_M_MMUREGS));
	return retval;
}

static __inline__ unsigned int srmmu_get_faddr(void)
{
	unsigned int retval;

	__asm__ __volatile__("lda [%1] %2, %0\n\t" :
			     "=r" (retval) :
			     "r" (SRMMU_FAULT_ADDR), "i" (ASI_M_MMUREGS));
	return retval;
}

/* This is guaranteed on all SRMMU's. */
static __inline__ void srmmu_flush_whole_tlb(void)
{
	__asm__ __volatile__("sta %%g0, [%0] %1\n\t": :
			     "r" (0x400),        /* Flush entire TLB!! */
			     "i" (ASI_M_FLUSH_PROBE) : "memory");

}

/* These flush types are not available on all chips... */
static __inline__ void srmmu_flush_tlb_ctx(void)
{
	__asm__ __volatile__("sta %%g0, [%0] %1\n\t": :
			     "r" (0x300),        /* Flush TLB ctx.. */
			     "i" (ASI_M_FLUSH_PROBE) : "memory");

}

static __inline__ void srmmu_flush_tlb_region(unsigned long addr)
{
	addr &= SRMMU_PGDIR_MASK;
	__asm__ __volatile__("sta %%g0, [%0] %1\n\t": :
			     "r" (addr | 0x200), /* Flush TLB region.. */
			     "i" (ASI_M_FLUSH_PROBE) : "memory");

}


static __inline__ void srmmu_flush_tlb_segment(unsigned long addr)
{
	addr &= SRMMU_PMD_MASK;
	__asm__ __volatile__("sta %%g0, [%0] %1\n\t": :
			     "r" (addr | 0x100), /* Flush TLB segment.. */
			     "i" (ASI_M_FLUSH_PROBE) : "memory");

}

static __inline__ void srmmu_flush_tlb_page(unsigned long page)
{
	page &= PAGE_MASK;
	__asm__ __volatile__("sta %%g0, [%0] %1\n\t": :
			     "r" (page),        /* Flush TLB page.. */
			     "i" (ASI_M_FLUSH_PROBE) : "memory");

}

static __inline__ unsigned long srmmu_hwprobe(unsigned long vaddr)
{
	unsigned long retval;

	vaddr &= PAGE_MASK;
	__asm__ __volatile__("lda [%1] %2, %0\n\t" :
			     "=r" (retval) :
			     "r" (vaddr | 0x400), "i" (ASI_M_FLUSH_PROBE));

	return retval;
}

static __inline__ int
srmmu_get_pte (unsigned long addr)
{
	register unsigned long entry;

	__asm__ __volatile__("\n\tlda [%1] %2,%0\n\t" :
				"=r" (entry):
				"r" ((addr & 0xfffff000) | 0x400), "i" (ASI_M_FLUSH_PROBE));
	return entry;
}

#endif /* !(__ASSEMBLY__) */

#endif /* !(_SPARC_PGTSRMMU_H) */
