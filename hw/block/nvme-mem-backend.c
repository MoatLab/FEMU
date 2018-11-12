#include "qemu/osdep.h"
#include "block/block_int.h"
#include "block/qapi.h"
#include "exec/memory.h"
#include "hw/block/block.h"
#include "hw/hw.h"
#include "sysemu/kvm.h"
#include "hw/pci/msix.h"
#include "hw/pci/msi.h"
#include "hw/pci/pci.h"
#include "qapi/visitor.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/bitops.h"
#include "qemu/bitmap.h"
#include "qom/object.h"
#include "sysemu/sysemu.h"
#include "sysemu/block-backend.h"
#include <qemu/main-loop.h>

#include "nvme.h"
#include "trace-root.h"
#include "trace.h"

#include "god.h"

void nvme_mem_backend_init(NvmeCtrl *n, int64_t nbytes)
{
    assert(!n->mem_backend);

    n->bs_size = nbytes;
    n->mem_backend = g_malloc0(nbytes);
    if (n->mem_backend == NULL) {
        error_report("FEMU: cannot allocate %" PRId64 " bytes for emulating SSD,"
                "make sure you have enough free DRAM in your host\n", nbytes);
        exit(EXIT_FAILURE);
    }

    if (mlock(n->mem_backend, nbytes) == -1) {
        error_report("FEMU: failed to pin %" PRId64 " bytes ...\n", nbytes);
    }
}

void nvme_mem_backend_destroy(NvmeCtrl *n)
{
    if (n->mem_backend) {
        munlock(n->mem_backend, n->bs_size);
        g_free(n->mem_backend);
    }
}

uint64_t nvme_mem_backend_rw(NvmeCtrl *n, NvmeNamespace *ns,
        NvmeCmd *cmd, NvmeRequest *req)
{
    QEMUIOVector iov;
    int sg_cur_index = 0;
    dma_addr_t sg_cur_byte = 0;
    int i;
    void *hs = n->mem_backend;
    void *mem;
    dma_addr_t cur_addr, cur_len;
    DMADirection dir = req->is_write ? DMA_DIRECTION_TO_DEVICE : 
        DMA_DIRECTION_FROM_DEVICE;
    qemu_iovec_init(&iov, req->qsg.nsg);

    // this is dma_blk_unmap()
    for (i = 0; i < iov.niov; ++i) {
        dma_memory_unmap(req->qsg.as, iov.iov[i].iov_base, iov.iov[i].iov_len,
                dir, iov.iov[i].iov_len);
    }
    qemu_iovec_reset(&iov);

    while (sg_cur_index < req->qsg.nsg) {
        cur_addr = req->qsg.sg[sg_cur_index].base + sg_cur_byte;
        cur_len = req->qsg.sg[sg_cur_index].len - sg_cur_byte;
        mem = dma_memory_map(req->qsg.as, cur_addr, &cur_len, dir);
        if (!mem)
            break;
        qemu_iovec_add(&iov, mem, cur_len);
        sg_cur_byte += cur_len;
        if (sg_cur_byte == req->qsg.sg[sg_cur_index].len) {
            sg_cur_byte = 0;
            ++sg_cur_index;
        }
    }

    if (iov.size == 0) {
        printf("Coperd, you poor boy, DMA mapping failed!\n");
    }

    if (!QEMU_IS_ALIGNED(iov.size, BDRV_SECTOR_SIZE)) {
        qemu_iovec_discard_back(&iov, QEMU_ALIGN_DOWN(iov.size, BDRV_SECTOR_SIZE));
    }

    // copy data from or write data to "heap_storage"
    // heap_storage[data_offset] .. heap_storage[data_offset+data_size]
    int64_t hs_oft = req->data_offset;
    if (req->is_write) {
        // iov -> heap storage
        for (i = 0; i < iov.niov; ++i) {
            memcpy(hs + hs_oft, iov.iov[i].iov_base, iov.iov[i].iov_len);
            hs_oft += iov.iov[i].iov_len;
        }
    } else {
        // heap storage -> iov
        for (i = 0; i < iov.niov; ++i) {
            memcpy(iov.iov[i].iov_base, hs + hs_oft, iov.iov[i].iov_len);
            hs_oft += iov.iov[i].iov_len;
        }
    }

    // dma_blk_unmap()
    for (i = 0; i < iov.niov; ++i) {
        dma_memory_unmap(req->qsg.as, iov.iov[i].iov_base, iov.iov[i].iov_len,
                dir, iov.iov[i].iov_len);
    }
    qemu_iovec_reset(&iov);

    return NVME_SUCCESS;
}
