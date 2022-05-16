/**
 ** Proll (PROM replacement)
 ** iommu.c: Functions for DVMA management.
 ** Copyright 1999 Pete Zaitcev
 ** This code is licensed under GNU General Public License.
 **/
#include "config.h"
#include "libopenbios/bindings.h"
#include "libopenbios/ofmem.h"
#include "drivers/drivers.h"
#include "iommu.h"
#include "arch/sparc32/ofmem_sparc32.h"
#include "arch/sparc32/asi.h"
#include "arch/sparc32/pgtsrmmu.h"

#ifdef CONFIG_DEBUG_IOMMU
#define DPRINTF(fmt, args...)                   \
    do { printk(fmt , ##args); } while (0)
#else
#define DPRINTF(fmt, args...)
#endif

/*
 * IOMMU parameters
 */
struct iommu {
    struct iommu_regs *regs;
    unsigned int *page_table;
    unsigned long plow;     /* Base bus address */
    unsigned long pphys;    /* Base phys address */
};

static struct iommu ciommu;

static void
iommu_invalidate(struct iommu_regs *iregs)
{
    iregs->tlbflush = 0;
}

/*
 * XXX This is a problematic interface. We alloc _memory_ which is uncached.
 * So if we ever reuse allocations somebody is going to get uncached pages.
 * Returned address is always aligned by page.
 * BTW, we were not going to give away anonymous storage, were we not?
 */
void *
dvma_alloc(int size)
{
    void *va;
    unsigned int pa, iova;
    unsigned int npages;
    unsigned int mva, mpa;
    unsigned int i;
    unsigned int *iopte;
    struct iommu *t = &ciommu;

    npages = (size + (PAGE_SIZE-1)) / PAGE_SIZE;
    iova = (unsigned int)mem_alloc(&cdvmem, npages * PAGE_SIZE, PAGE_SIZE);
    if (iova == 0)
        return NULL;

    pa = t->pphys + (iova - t->plow);
    va = (void *)pa2va((unsigned long)pa);

    /*
     * Change page attributes in MMU to uncached.
     */
    mva = (unsigned int) va;
    mpa = (unsigned int) pa;
    ofmem_arch_map_pages(mpa, mva, npages * PAGE_SIZE, ofmem_arch_io_translation_mode(mpa));

    /*
     * Map into IOMMU page table.
     */
    mpa = (unsigned int) pa;
    iopte = &t->page_table[(iova - t->plow) / PAGE_SIZE];
    for (i = 0; i < npages; i++) {
        *iopte++ = MKIOPTE(mpa);
        mpa += PAGE_SIZE;
    }

    return va;
}

void
dvma_sync(unsigned char *va, int size)
{
    /* Synchronise the VA address region after DMA */
    unsigned long virt = pointer2cell(va);
    unsigned long page;

    for (page = (unsigned long)virt; page < virt + size; page += PAGE_SIZE) {
        srmmu_flush_tlb_page(page);
    }
}

unsigned int
dvma_map_in(unsigned char *va)
{
    /* Convert from VA to IOVA */
    unsigned int pa, iova;
    struct iommu *t = &ciommu;

    pa = va2pa((unsigned int)va);
    iova = t->plow + (pa - t->pphys);

    return iova;
}

#define DVMA_SIZE 0x4000

/*
 * Initialize IOMMU
 * This looks like initialization of CPU MMU but
 * the routine is higher in food chain.
 */
static struct iommu_regs *
iommu_init(struct iommu *t, uint64_t base)
{
    unsigned int *ptab, pva;
    int ptsize;
#ifdef CONFIG_DEBUG_IOMMU
    unsigned int impl, vers;
#endif
    unsigned int tmp;
    struct iommu_regs *regs;
    int ret;
    unsigned long vasize;

    regs = (struct iommu_regs *)ofmem_map_io(base, IOMMU_REGS);
    if (regs == NULL) {
        DPRINTF("Cannot map IOMMU\n");
        for (;;) { }
    }
    t->regs = regs;
#ifdef CONFIG_DEBUG_IOMMU
    impl = (regs->control & IOMMU_CTRL_IMPL) >> 28;
    vers = (regs->control & IOMMU_CTRL_VERS) >> 24;
#endif

    tmp = regs->control;
    tmp &= ~(IOMMU_CTRL_RNGE);

    tmp |= (IOMMU_RNGE_32MB | IOMMU_CTRL_ENAB);
    t->plow = 0xfe000000;		/* End - 32 MB */
    /* Size of VA region that we manage */
    vasize = 0x2000000; /* 32 MB */

    regs->control = tmp;
    iommu_invalidate(regs);

    /* Allocate IOMMU page table */
    /* Tremendous alignment causes great waste... */
    ptsize = (vasize / PAGE_SIZE) * sizeof(int);
    ret = ofmem_posix_memalign((void *)&ptab, ptsize, ptsize);
    if (ret != 0) {
        DPRINTF("Cannot allocate IOMMU table [0x%x]\n", ptsize);
        for (;;) { }
    }
    t->page_table = ptab;

    /* flush_cache_all(); */
    /** flush_tlb_all(); **/
    tmp = (unsigned int)va2pa((unsigned long)ptab);
    regs->base = tmp >> 4;
    iommu_invalidate(regs);

    DPRINTF("IOMMU: impl %d vers %d page table at 0x%p (pa 0x%x) of size %d bytes\n",
            impl, vers, t->page_table, tmp, ptsize);

    mem_init(&cdvmem, (char*)t->plow, (char *)(t->plow + DVMA_SIZE));
    ret = ofmem_posix_memalign((void *)&pva, DVMA_SIZE, PAGE_SIZE);
    if (ret != 0) {
        DPRINTF("Cannot allocate IOMMU phys size [0x%x]\n", DVMA_SIZE);
        for (;;) { }
    }
    t->pphys = va2pa(pva);
    return regs;
}

/* ( addr.lo addr.hi size -- virt ) */

static void
ob_iommu_map_in(void)
{
    phys_addr_t phys;
    ucell size, virt;

    size = POP();
    phys = POP();
    phys = (phys << 32) + POP();

    virt = ofmem_map_io(phys, size);

    PUSH(virt);
}

/* ( virt size ) */

static void
ob_iommu_map_out(void)
{
    ucell size = POP();
    ucell virt = POP();

    ofmem_release_io(virt, size);
}

static void
ob_iommu_dma_alloc(void)
{
    call_parent_method("dma-alloc");
}

static void
ob_iommu_dma_free(void)
{
    call_parent_method("dma-free");
}

static void
ob_iommu_dma_map_in(void)
{
    call_parent_method("dma-map-in");
}

static void
ob_iommu_dma_map_out(void)
{
    call_parent_method("dma-map-out");
}

static void
ob_iommu_dma_sync(void)
{
    call_parent_method("dma-sync");
}

void
ob_init_iommu(uint64_t base)
{
    struct iommu_regs *regs;

    regs = iommu_init(&ciommu, base);

    push_str("/iommu");
    fword("find-device");
    PUSH((unsigned long)regs);
    fword("encode-int");
    push_str("address");
    fword("property");

    PUSH(base >> 32);
    fword("encode-int");
    PUSH(base & 0xffffffff);
    fword("encode-int");
    fword("encode+");
    PUSH(IOMMU_REGS);
    fword("encode-int");
    fword("encode+");
    push_str("reg");
    fword("property");

    bind_func("map-in", ob_iommu_map_in);
    bind_func("map-out", ob_iommu_map_out);
    bind_func("dma-alloc", ob_iommu_dma_alloc);
    bind_func("dma-free", ob_iommu_dma_free);
    bind_func("dma-map-in", ob_iommu_dma_map_in);
    bind_func("dma-map-out", ob_iommu_dma_map_out);
    bind_func("dma-sync", ob_iommu_dma_sync);
}
