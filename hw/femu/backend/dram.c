#include "../nvme.h"

/* Coperd: FEMU Memory Backend (mbe) for emulated SSD */

int init_dram_backend(SsdDramBackend** mbe, int64_t nbytes, int stripesize, int pagesize)
{
    SsdDramBackend *b = *mbe = g_malloc0(sizeof(SsdDramBackend));

    b->stripesize = stripesize;
    b->pagesize = pagesize;
    if (stripesize > 1) {
        b->size = nbytes / (stripesize - 1) * stripesize;
        b->parity_start = nbytes;
    } else {
        b->size = nbytes;
        b->parity_start = 0;
    }
    b->logical_space = g_malloc0(b->size);

    if (mlock(b->logical_space, b->size) == -1) {
        femu_err("Failed to pin the memory backend to the host DRAM\n");
        g_free(b->logical_space);
        abort();
    }
    memset(b->logical_space, 0, b->size);


    printf("backend size: %ld\n", b->size);


    return 0;
}

void free_dram_backend(SsdDramBackend *b)
{
    if (b->logical_space) {
        munlock(b->logical_space, b->size);
        g_free(b->logical_space);
    }
}

static inline void update_parity(char* page_addr, char* parity_addr, int pagesize) {
    for (int i = 0;i < pagesize;i += 1) {
        parity_addr[i] ^= page_addr[i];
    }
}

int backend_rw(SsdDramBackend* b, QEMUSGList* qsg, uint64_t* lbal, bool is_write)
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

    uint64_t parity_offset = 0;
    while (sg_cur_index < qsg->nsg) {
        cur_addr = qsg->sg[sg_cur_index].base + sg_cur_byte;
        cur_len = qsg->sg[sg_cur_index].len - sg_cur_byte;

        if (b->stripesize > 1 && is_write) {
            assert(cur_len == b->pagesize);
            assert(mb_oft % b->pagesize == 0);
            uint64_t stripe_id = mb_oft / b->pagesize / (b->stripesize - 1);
            parity_offset = b->parity_start + stripe_id * b->pagesize;
            update_parity(mb + mb_oft, mb + parity_offset, b->pagesize);
        }

        if (dma_memory_rw(qsg->as, cur_addr, mb + mb_oft, cur_len, dir, MEMTXATTRS_UNSPECIFIED)) {
            femu_err("dma_memory_rw error\n");
        }

        if (b->stripesize > 1 && is_write) {
            update_parity(mb + mb_oft, mb + parity_offset, b->pagesize);
        }

        sg_cur_byte += cur_len;
        if (sg_cur_byte == qsg->sg[sg_cur_index].len) {
            sg_cur_byte = 0;
            ++sg_cur_index;
        } else {


            printf("?????????????? backend rw index not ++ ???????????\n");


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


        if (cur_len < 16) {
            if (is_write) {
                printf("written less than 16\n");
            } else {
                printf("read less than 16\n");
            }
        } else {
            if (sg_cur_index == 1) {
                char buf[17];
                buf[16] = '\0';
                memcpy(buf, mb + mb_oft - cur_len, 16);
                printf("\n[ backend ]\n");
                for (int i = 0;i < 16;i += 1) {
                    printf("\\%d", (int)buf[i]);
                }
                printf("\nchar: %s\n", buf);
            }
            if (sg_cur_index == qsg->nsg) {
                char buf[17];
                buf[16] = '\0';
                memcpy(buf, mb + mb_oft - 16, 16);
                printf("......\nint: ");
                for (int i = 0;i < 16;i += 1) {
                    printf("\\%d", (int)buf[i]);
                }
                printf("\nchar: %s\n", buf);
                if (is_write) {
                    printf("written len: %lu\n", mb_oft - lbal[0]);
                } else {
                    printf("read len: %lu\n", mb_oft - lbal[0]);
                }
            }
        }
        // printf("sg index: %d/%d, curr len: %d, offset: %d\n", sg_cur_index, qsg->nsg, (int)cur_len, (int)mb_oft);


    }

    qemu_sglist_destroy(qsg);

    return 0;
}
