#include "../nvme.h"
#include "exec/hwaddr.h"
#include <stdlib.h>
#include <string.h>

#define BACKEND_PAGE_SIZE  4096

/* For CXL/DER: GPA → host ptr (used by softmmu/physmem.c, set from hw/i386/pc.c) */
static struct {
    void *ptr;
    uint64_t base_gpa;
    uint64_t size;
} femu_backend = { .ptr = NULL, .base_gpa = (uint64_t)-1, .size = 0 };

void femu_set_base_gpa(hwaddr base)
{
    femu_backend.base_gpa = base;
}

hwaddr femu_get_base_gpa(void)
{
    return (femu_backend.base_gpa != (uint64_t)-1) ? (hwaddr)femu_backend.base_gpa : 0;
}

void *femu_get_backend_ptr_from_gpa(hwaddr addr)
{
    if (femu_backend.ptr == NULL || femu_backend.base_gpa == (uint64_t)-1) {
        return NULL;
    }
    if (addr < femu_backend.base_gpa) {
        return NULL;
    }
    uint64_t offset = addr - femu_backend.base_gpa;
    if (offset >= femu_backend.size) {
        return NULL;
    }
    return (char *)femu_backend.ptr + offset;
}

/* Coperd: FEMU Memory Backend (mbe) for emulated SSD; normal allocation, page-aligned */

/* Allocate page-aligned memory for NAND backend */
static void *page_aligned_alloc(size_t size)
{
    void *p = NULL;
    if (posix_memalign(&p, BACKEND_PAGE_SIZE, size) != 0) {
        return NULL;
    }
    memset(p, 0, size);
    return p;
}

int init_dram_backend(FemuCtrl *n)
{
    int64_t nbytes = ((int64_t)n->memsz) * 1024 * 1024;
    SsdDramBackend *b = n->mbe = g_malloc0(sizeof(SsdDramBackend));

    b->size = nbytes;
    b->femu_mode = n->femu_mode;
    b->logical_space = page_aligned_alloc((size_t)nbytes);
    if (!b->logical_space) {
        femu_err("Failed to allocate NAND backend\n");
        g_free(b);
        n->mbe = NULL;
        return -1;
    }

    if (mlock(b->logical_space, (size_t)nbytes) == -1) {
        femu_err("Failed to pin the memory backend to the host DRAM\n");
        free(b->logical_space);
        b->logical_space = NULL;
        g_free(b);
        n->mbe = NULL;
        abort();
    }

    femu_backend.ptr = b->logical_space;
    femu_backend.size = (uint64_t)nbytes;
    if (femu_backend.base_gpa != (uint64_t)-1) {
        n->base_gpa = femu_backend.base_gpa;
    }

    return 0;
}

void free_dram_backend(SsdDramBackend *b)
{
    if (!b) {
        return;
    }
    if (b->logical_space) {
        munlock(b->logical_space, (size_t)b->size);
        free(b->logical_space);
        b->logical_space = NULL;
    }
    g_free(b);
}

int backend_rw(SsdDramBackend *b, QEMUSGList *qsg, uint64_t *lbal, bool is_write)
{
    int sg_cur_index = 0;
    dma_addr_t sg_cur_byte = 0;
    dma_addr_t cur_addr, cur_len;
    uint64_t mb_oft = lbal[0];
    void *mb = b->logical_space;

    DMADirection dir = DMA_DIRECTION_FROM_DEVICE;

    if (is_write) {
        dir = DMA_DIRECTION_TO_DEVICE;
    }

    while (sg_cur_index < qsg->nsg) {
        cur_addr = qsg->sg[sg_cur_index].base + sg_cur_byte;
        cur_len = qsg->sg[sg_cur_index].len - sg_cur_byte;
        if (dma_memory_rw(qsg->as, cur_addr, mb + mb_oft, cur_len, dir, MEMTXATTRS_UNSPECIFIED)) {
            femu_err("dma_memory_rw error\n");
        }

        sg_cur_byte += cur_len;
        if (sg_cur_byte == qsg->sg[sg_cur_index].len) {
            sg_cur_byte = 0;
            ++sg_cur_index;
        }

        if (b->femu_mode == FEMU_OCSSD_MODE) {
            mb_oft = lbal[sg_cur_index];
        } else if (b->femu_mode == FEMU_BBSSD_MODE ||
                   b->femu_mode == FEMU_NOSSD_MODE ||
                   b->femu_mode == FEMU_ZNSSD_MODE ||
                   b->femu_mode == FEMU_CXLSSD_MODE) {
            mb_oft += cur_len;
        } else {
            assert(0);
        }
    }

    qemu_sglist_destroy(qsg);

    return 0;
}