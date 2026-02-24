#include "../nvme.h"

#include <fcntl.h>
#include <stdlib.h>
// #include <omp.h>

#define LENGTH (2UL << 30)

struct femu_backend_info {
    void *ptr;
    uint64_t base_gpa;
    uint64_t size;
};


static struct femu_backend_info femu_backend = {
    .ptr = NULL,
    .base_gpa = -1,
    .size = 0
};

void femu_set_base_gpa(hwaddr base)
{
    femu_backend.base_gpa = base;
}

void *femu_get_backend_ptr(off_t offset) {
    // if (femu_backend.ptr == NULL) {
    //     femu_backend.ptr = mmap(NULL, 96UL*1024*1024*1024, PROT_READ | PROT_WRITE, MAP_ANONYMOUS, -1, 0);
    // }
    return femu_backend.ptr + offset;
}
 
void *femu_get_backend_ptr_from_gpa(hwaddr addr) {
    uint64_t offset = addr - femu_backend.base_gpa;
    assert(offset < femu_backend.size);

    return femu_get_backend_ptr(offset);
}


void *alloc_backend_memory(const char *devname, uint64_t offset, uint64_t size) {
    // if (femu_backend.ptr != NULL) {
    //     return femu_backend.ptr;
    // }

    void *ptr = NULL;
    int devfd = open(devname, O_RDWR);
    if (devfd < 0) {
        perror("open: ");
        femu_err("%s,Open [%s] failed, not able to allocate FEMU Backend DRAM", __func__, devname);
        abort();
    }

    ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, devfd, offset);
    if (ptr == MAP_FAILED || ptr == NULL) {
        perror("mmap ");
        femu_err("DRAM backend [%s],mmap [%s] failed", __func__, devname);
        abort();
    }

    if (mlock(ptr, size) != 0) {
        perror("mlock");
        abort();
    }

    printf("[%s] backend address: 0x%lx\n",devname, (uint64_t)ptr);
    memset(ptr, 0, 4096);

    femu_backend.size = size;
    return femu_backend.ptr = ptr;
}

/* Coperd: FEMU Memory Backend (mbe) for emulated SSD */
#include "qemu/mmap-alloc.h"
int init_dram_backend(FemuCtrl *n)
{
    // int hfd;
    // void *ptr = NULL;
    uint64_t nbytes, buf_size;
    SsdDramBackend *b = n->mbe = g_malloc0(sizeof(SsdDramBackend));
    // char stack[0x4000];
    nbytes = ((uint64_t)n->memsz) * 1024 * 1024;
    buf_size = ((uint64_t)n->bufsz) * 1024 * 1024;
    nbytes = (nbytes + LENGTH - 1) & ~(LENGTH - 1);
    b->size = nbytes;
    b->buf_size = buf_size;
    
    femu_log("FEMU Backend DRAM size=%ld, buf size=%.1fGB\n", nbytes, buf_size/1024./1024./1024.);
    b->logical_space = alloc_backend_memory(n->bdev_name, n->bdev_offset, nbytes);

    b->buf_space = b->logical_space;
    
    assert(femu_backend.base_gpa != -1);
    b->base_gpa = n->base_gpa = femu_backend.base_gpa;

    return 0;
}

void free_dram_backend(SsdDramBackend *b)
{
    if (b->logical_space) {
        munmap(b->logical_space, b->size);
    }

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
        if (1 && dma_memory_rw(qsg->as, cur_addr, mb + mb_oft, cur_len, dir, MEMTXATTRS_UNSPECIFIED)) {
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







