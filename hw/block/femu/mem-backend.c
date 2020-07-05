#include "qemu/osdep.h"
#include "hw/block/block.h"
#include "hw/pci/pci.h"
#include "qemu/error-report.h"

#include "mem-backend.h"
#include "computation.h"

extern uint64_t iscos_counter;


/* Coperd: FEMU Memory Backend (mbe) for emulated SSD */

void femu_init_mem_backend(struct femu_mbe *mbe, int64_t nbytes)
{
    assert(!mbe->mem_backend);

    mbe->size = nbytes;
    mbe->mem_backend = g_malloc0(nbytes);
    if (mbe->mem_backend == NULL) {
        error_report("FEMU: cannot allocate %" PRId64 " bytes for emulating SSD,"
                "make sure you have enough free DRAM in your host\n", nbytes);
        abort();
    }

    if (mlock(mbe->mem_backend, nbytes) == -1) {
        error_report("FEMU: failed to pin %" PRId64 " bytes ...\n", nbytes);
        g_free(mbe->mem_backend);
        abort();
    }
}

void femu_destroy_mem_backend(struct femu_mbe *mbe)
{
    if (mbe->mem_backend) {
        munlock(mbe->mem_backend, mbe->size);
        g_free(mbe->mem_backend);
    }
}

#define WRITE_LATENCY 5000
#define READ_LATENCY 8000

/* Coperd: directly read/write to memory backend from blackbox mode */
int femu_rw_mem_backend_bb(struct femu_mbe *mbe, QEMUSGList *qsg,
        uint64_t data_offset, bool is_write, int computational_fd_send, int computational_fd_recv)
{
    int sg_cur_index = 0;
    dma_addr_t sg_cur_byte = 0;
    dma_addr_t cur_addr, cur_len;
    uint64_t mb_oft = data_offset;
    void *mb = mbe->mem_backend;

    DMADirection dir = DMA_DIRECTION_FROM_DEVICE;

    if (is_write) {
        dir = DMA_DIRECTION_TO_DEVICE;
    }

    while (sg_cur_index < qsg->nsg) {
        cur_addr = qsg->sg[sg_cur_index].base + sg_cur_byte;
        cur_len = qsg->sg[sg_cur_index].len - sg_cur_byte;

	if (mbe->nscdelay_mode) {
		if (is_write) {
			add_delay(WRITE_LATENCY);
		} else {
			add_delay(READ_LATENCY);
		}
	}

	// address_space, current_address, buffer, length_of_dma_address, read_or_write_direction
        if (dma_memory_rw(qsg->as, cur_addr, mb + mb_oft, cur_len, dir)) {
            error_report("FEMU: dma_memory_rw error");
        }

	if (mbe->computation_mode) {
		// WRITE Complete
		if (is_write && ((mb + mb_oft) != NULL) ) {
		//	iscos_counter += count_bits(mb+mb_oft, cur_len);
		//	printf("%s():read count = %d\n",__func__, c);
		}
		// READ Complete
		if (!is_write && ((mb + mb_oft) != NULL) ) {
		//	int c = count_bits(mb+mb_oft, cur_len);
		//	printf("%s():write count after = %d\n",__func__, c);
			int ret = write(computational_fd_send, mb + mb_oft , 4096);
			if (ret < 0 ) {
				printf("write on pipe failed %s\n", strerror(errno));
			}else {
		//		printf("wrote data on computational thread\n");
			}
			uint64_t c=0;
			read(computational_fd_recv, &c, sizeof(c));
		//	iscos_counter += c;
		//	printf("main thread block_pointer %d\n", c);
			#ifdef POINTER_CHASING
			while (c != 0 && c != END_BLOCK_MAGIC) {
				off_t new_offset = c * BLOCK_SIZE;
				if (mb+new_offset != NULL) {
					if (mbe->nscdelay_mode) {
						add_delay(READ_LATENCY);
					}
					if (dma_memory_rw(qsg->as, cur_addr, mb + new_offset, cur_len, dir)) {
						error_report("FEMU: dma_memory_rw error");
					}
					int ret = write(computational_fd_send, mb + new_offset, 4096);
					if ( ret < 0) {
						printf("write on pipe failed %s\n", strerror(errno));
					}
					c = 0;
					read(computational_fd_recv, &c, sizeof(c));
		//			printf("next block_pointer %d\n", c);
				}
			}
			#endif
		}
	}

        mb_oft += cur_len;

        sg_cur_byte += cur_len;
        if (sg_cur_byte == qsg->sg[sg_cur_index].len) {
            sg_cur_byte = 0;
            ++sg_cur_index;
        }
    }

    qemu_sglist_destroy(qsg);

    return 0;
}

/* Coperd: directly read/write to memory backend from whitebox mode */
int femu_rw_mem_backend_oc(struct femu_mbe *mbe, QEMUSGList *qsg,
        uint64_t *data_offset, bool is_write)
{
    int sg_cur_index = 0;
    dma_addr_t sg_cur_byte = 0;
    dma_addr_t cur_addr, cur_len;
    uint64_t mb_oft = data_offset[0];
    void *mb = mbe->mem_backend;

    DMADirection dir = DMA_DIRECTION_FROM_DEVICE;

    if (is_write) {
        dir = DMA_DIRECTION_TO_DEVICE;
    }

    while (sg_cur_index < qsg->nsg) {
        cur_addr = qsg->sg[sg_cur_index].base + sg_cur_byte;
        cur_len = qsg->sg[sg_cur_index].len - sg_cur_byte;
        if (dma_memory_rw(qsg->as, cur_addr, mb + mb_oft, cur_len, dir)) {
            error_report("FEMU: dma_memory_rw error");
        }

        sg_cur_byte += cur_len;
        if (sg_cur_byte == qsg->sg[sg_cur_index].len) {
            sg_cur_byte = 0;
            ++sg_cur_index;
        }

        /*
         * Coperd: update drive LBA to r/w next time
         * for OC: all LBAs are in data_offset[]
         * for BB: LBAs are continuous
         */
        mb_oft = data_offset[sg_cur_index];
	printf("mb_oft %d sg_cur_index %d\n", mb_oft, sg_cur_index);
    }

    qemu_sglist_destroy(qsg);

    return 0;
}
