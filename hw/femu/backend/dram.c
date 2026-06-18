#include <sys/syscall.h>
#include "../nvme.h"

/* Coperd: FEMU Memory Backend (mbe) for emulated SSD */

/*
 * Optionally bind the emulated-SSD backend buffer to a NUMA node before it is
 * first touched. FEMU_MBE_INTERLEAVE=<n> binds every page to node n
 * (MPOL_BIND); =on interleaves across nodes 0-1 (MPOL_INTERLEAVE). This is the
 * device-side half of the strict socket-isolation setup: pin the guest's vCPUs
 * and RAM to one socket and the FEMU poller threads + this backend to the
 * other, so the only thing crossing the inter-socket link is the per-I/O
 * emulation copy and the two DRAM-bandwidth domains do not contend. A direct
 * mbind(2) syscall avoids a libnuma build dependency. No-op (default) when the
 * env var is unset, so existing single-socket setups are unchanged.
 */
static void mbe_numa_bind(void *addr, int64_t len)
{
    const char *il = getenv("FEMU_MBE_INTERLEAVE");
    if (!il || !il[0]) {
        return;
    }
    if (strcmp(il, "on") && strcmp(il, "0") && strcmp(il, "1")) {
        femu_err("backend: ignoring FEMU_MBE_INTERLEAVE=%s (want on|0|1)\n", il);
        return;
    }
    int mode = strcmp(il, "on") ? 2 /* MPOL_BIND */ : 3 /* MPOL_INTERLEAVE */;
    unsigned long nodemask = strcmp(il, "on") ? (1ul << atoi(il)) : 0x3ul;

    /*
     * mbind(2) requires a page-aligned start address; g_malloc0 returns only
     * malloc alignment. Round the start down and the length up to whole pages
     * so the policy covers every page backing the buffer. (Touching the shared
     * boundary pages is harmless: the policy only steers where not-yet-faulted
     * pages land, and the prealloc below faults our buffer immediately.)
     */
    long pgsz = sysconf(_SC_PAGESIZE);
    uintptr_t start = (uintptr_t)addr & ~((uintptr_t)pgsz - 1);
    uintptr_t end = ((uintptr_t)addr + len + pgsz - 1) & ~((uintptr_t)pgsz - 1);
    /*
     * MPOL_MF_MOVE (0x2): g_malloc0 has already zeroed (hence faulted) the
     * pages onto the default node, so a plain mbind would not relocate them.
     * MF_MOVE migrates the already-resident pages to the target node now.
     */
    if (syscall(SYS_mbind, (void *)start, end - start, mode, &nodemask,
                sizeof(nodemask) * 8, 0x2 /* MPOL_MF_MOVE */)) {
        femu_err("backend: mbind(FEMU_MBE_INTERLEAVE=%s) failed: %s\n",
                 il, strerror(errno));
    } else {
        femu_log("backend: %ld MB bound via FEMU_MBE_INTERLEAVE=%s\n",
                 (long)(len >> 20), il);
    }
}

int init_dram_backend(SsdDramBackend **mbe, int64_t nbytes)
{
    SsdDramBackend *b = *mbe = g_malloc0(sizeof(SsdDramBackend));

    b->size = nbytes;
    b->logical_space = g_malloc0(nbytes);

    /* bind to the requested NUMA node before mlock faults the pages in */
    mbe_numa_bind(b->logical_space, nbytes);

    if (mlock(b->logical_space, nbytes) == -1) {
        femu_err("Failed to pin the memory backend to the host DRAM\n");
        g_free(b->logical_space);
        abort();
    }

    return 0;
}

void free_dram_backend(SsdDramBackend *b)
{
    if (b->logical_space) {
        munlock(b->logical_space, b->size);
        g_free(b->logical_space);
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
                   b->femu_mode == FEMU_CSD_MODE) {
            mb_oft += cur_len;
        } else {
            assert(0);
        }
    }

    qemu_sglist_destroy(qsg);

    return 0;
}
