#include "../nvme.h"

/* Coperd: FEMU Memory Backend (mbe) for emulated SSD */

void init_dram_backend_logical_space(SsdDramBackend **mbe, int idx, int64_t nbytes)
{
    SsdDramBackend *b = *mbe;
    if (b->logical_space[idx]) {
        munlock(b->logical_space[idx], b->sizes[idx]);
        g_free(b->logical_space[idx]);
    }
    b->sizes[idx] = nbytes;
    b->logical_space[idx] = g_malloc0(b->sizes[idx]);
    if (mlock(b->logical_space[idx], b->sizes[idx]) == -1){
        femu_err("Failed to pin the memory backend to the host DRAM\n");
        g_free(b->logical_space[idx]);
        abort();
    }
}

int init_dram_backend(SsdDramBackend **mbe, int64_t nbytes, uint32_t num_namespaces)
{
    SsdDramBackend *b = *mbe = g_malloc0(sizeof(SsdDramBackend));

    b->num_namespaces = num_namespaces;
    b->sizes = g_malloc0(sizeof(int64_t)*num_namespaces);
    b->logical_space = g_malloc0(sizeof(SsdDramBackend*)*num_namespaces);

    return 0;
}

void free_dram_backend(SsdDramBackend *b)
{
    for (int i = 0; i < b->num_namespaces; i++){
        if (b->logical_space[i]) {
            munlock(b->logical_space[i], b->sizes[i]);
            g_free(b->logical_space[i]);
        }
    }
}

int backend_rw_namespace(SsdDramBackend *b, QEMUSGList *qsg, uint64_t *lbal, bool is_write, uint32_t nsid)
{
    int sg_cur_index = 0;
    dma_addr_t sg_cur_byte = 0;
    dma_addr_t cur_addr, cur_len;
    uint64_t mb_oft = lbal[0];
    void *mb = b->logical_space[nsid-1];

    DMADirection dir = DMA_DIRECTION_FROM_DEVICE;

    if (is_write) {
        dir = DMA_DIRECTION_TO_DEVICE;
    }

    while (sg_cur_index < qsg->nsg) {
        cur_addr = qsg->sg[sg_cur_index].base + sg_cur_byte;
        cur_len = qsg->sg[sg_cur_index].len - sg_cur_byte;
        if (dma_memory_rw(qsg->as, cur_addr, mb + mb_oft, cur_len, dir, MEMTXATTRS_UNSPECIFIED)) {
            femu_err("FEMU: dma_memory_rw error");
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
                   b->femu_mode == FEMU_ZNSSD_MODE) {
            mb_oft += cur_len;
        } else {
            assert(0);
        }
    }

    qemu_sglist_destroy(qsg);

    return 0;
}

/* For compatibility with the original (No NS) version */
int backend_rw(SsdDramBackend *b, QEMUSGList *qsg, uint64_t *lbal, bool is_write){
    return backend_rw_namespace(b, qsg, lbal, is_write, 1);
}