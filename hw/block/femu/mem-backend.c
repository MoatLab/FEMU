#include "qemu/osdep.h"
#include "hw/block/block.h"
#include "hw/pci/pci.h"
#include "qemu/error-report.h"

#include "mem-backend.h"
#include "computation.h"

extern uint64_t iscos_counter;

uint64_t do_pointer_chase(int computational_fd_send, int computational_fd_recv, void *mb, 
		uint64_t mb_oft, dma_addr_t cur_len, AddressSpace *as, dma_addr_t *cur_addr, uint32_t read_delay);

uint64_t do_count(int computational_fd_send, int computational_fd_recv, void *mb , uint64_t mb_oft, dma_addr_t cur_len);

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

inline static void add_delay(uint32_t micro_seconds) {
	unsigned long long current_time, req_time;
	current_time = cpu_get_host_ticks();
	req_time = current_time + (micro_seconds);
	while( cpu_get_host_ticks()  < req_time);
}

uint64_t do_pointer_chase(int computational_fd_send, int computational_fd_recv, void *mb, uint64_t mb_oft, dma_addr_t cur_len, AddressSpace *as, dma_addr_t *cur_addr, uint32_t read_delay)
{
	uint64_t new_offset = mb_oft;
	uint64_t c;
	DMADirection dir = DMA_DIRECTION_FROM_DEVICE;

	int ret = write(computational_fd_send, mb + new_offset, 4096);
	if ( ret < 0) {
		printf("write on pipe failed %s\n", strerror(errno));
	}
	c = 0;
	ret = read(computational_fd_recv, &c, sizeof(c));
	if (ret < 0) {
		printf("read from pipe failed %s\n", strerror(errno));	
	}

	while (c != 0 && c!= END_BLOCK_MAGIC)
	{
		if (mb + new_offset != NULL) {
			new_offset = c * BLOCK_SIZE;
			add_delay(read_delay);
			if (dma_memory_rw(as, *cur_addr, mb + new_offset, cur_len, dir)) {
				error_report("FEMU: dma_memory_rw error");
			}
			int ret = write(computational_fd_send, mb + new_offset, 4096);
			if ( ret < 0) {
				printf("write on pipe failed %s\n", strerror(errno));
			}
			c = 0;
			ret = read(computational_fd_recv, &c, sizeof(c));
			if (ret < 0) {
				printf("read from pipe failed %s\n", strerror(errno));
			}
			printf("next block_pointer %lu\n", c);
		}else {
			return c;
		}
	}
	return c;
}

uint64_t do_count(int computational_fd_send, int computational_fd_recv, void *mb , uint64_t mb_oft, dma_addr_t cur_len)
{
	int ret = write(computational_fd_send, mb + mb_oft , cur_len);
	if (ret < 0 ) {
		printf("write on pipe failed %s\n", strerror(errno));
	}
	uint64_t c=0;
	ret = read(computational_fd_recv, &c, sizeof(c));
	if (ret < 0) {
		printf("read from pipe failed %s\n", strerror(errno));
	}
	printf("number of bytes in current block %lu\n", c);
	return c;
}

/* Coperd: directly read/write to memory backend from blackbox mode */
int femu_rw_mem_backend_bb(struct femu_mbe *mbe, QEMUSGList *qsg,
        uint64_t data_offset, bool is_write, int computational_fd_send, int computational_fd_recv)
{
    int sg_cur_index = 0;
    dma_addr_t sg_cur_byte = 0;
    dma_addr_t cur_addr, cur_len;
    uint64_t mb_oft = data_offset;
    void *mb = mbe->mem_backend;

	uint32_t flash_read_delay = mbe->flash_read_latency;
	uint32_t flash_write_delay = mbe->flash_write_latency;

	int ret;
    DMADirection dir = DMA_DIRECTION_FROM_DEVICE;

    if (is_write) {
        dir = DMA_DIRECTION_TO_DEVICE;
    }

    while (sg_cur_index < qsg->nsg) {
        cur_addr = qsg->sg[sg_cur_index].base + sg_cur_byte;
        cur_len = qsg->sg[sg_cur_index].len - sg_cur_byte;

	// make first I/O irrespective of compute mode.
	if (is_write) {
		add_delay(flash_write_delay);
	} else {
		add_delay(flash_read_delay);
	}
        if (dma_memory_rw(qsg->as, cur_addr, mb + mb_oft, cur_len, dir)) {
		error_report("FEMU: dma_memory_rw error");
        }

	if (mbe->computation_mode) {
		// if (is_write) : Write Based computation, eg. compression. else:
		if (!is_write && ((mb + mb_oft) != NULL) ) {
			#ifdef COUNTING
			ret = do_count(computational_fd_send, computational_fd_recv, mb, mb_oft, cur_len);
			if (ret < 0) {
				printf("Error occured while counting %s\n", strerror(ret));
			}
			#endif
			#ifdef POINTER_CHASING
			ret = do_pointer_chase(computational_fd_send, computational_fd_recv, mb, mb_oft, cur_len, qsg->as, &cur_addr, flash_read_delay);
			if (ret < 0) {
				printf("Error occured while counting %s\n", strerror(ret));
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
	printf("mb_oft %lu sg_cur_index %d\n", mb_oft, sg_cur_index);
    }

    qemu_sglist_destroy(qsg);

    return 0;
}
