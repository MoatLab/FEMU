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

    /*
     * Pinning keeps page faults out of the emulated latency, but it needs
     * RLIMIT_MEMLOCK to cover the backend, which an unprivileged run rarely
     * has. Say what that costs and carry on rather than refuse to start: the
     * device works either way, only its timing is then subject to faults.
     */
    if (mlock(b->logical_space, nbytes) == -1) {
        femu_err("cannot pin the %" PRId64 " MiB memory backend (%s); "
                 "latencies may jitter until RLIMIT_MEMLOCK allows it\n",
                 nbytes / MiB, strerror(errno));
    }

    backend_init_range_locks(b);

    return 0;
}

/* A backend another device lends takes its locks from the borrower. */
void backend_init_range_locks(SsdDramBackend *b)
{
    if (b->range_locks) {
        return;
    }
    b->range_locks = g_new(QemuMutex, BACKEND_RANGE_LOCKS);
    for (int i = 0; i < BACKEND_RANGE_LOCKS; i++) {
        qemu_mutex_init(&b->range_locks[i]);
    }
}

void backend_free_range_locks(SsdDramBackend *b)
{
    if (!b || !b->range_locks) {
        return;
    }
    for (int i = 0; i < BACKEND_RANGE_LOCKS; i++) {
        qemu_mutex_destroy(&b->range_locks[i]);
    }
    g_free(b->range_locks);
    b->range_locks = NULL;
}

void free_dram_backend(SsdDramBackend *b)
{
    if (!b) {
        return;
    }
    if (b->logical_space) {
        munlock(b->logical_space, b->size);
        g_free(b->logical_space);
    }
    backend_free_range_locks(b);
    g_free(b);
}

/*
 * The locks of [off, off + len) as one or two runs of lock indexes, lowest
 * first. Every access takes its locks in index order, so two accesses never
 * wait on each other in a cycle.
 */
static int backend_range_runs(uint64_t off, uint64_t len, int run[2][2])
{
    uint64_t g0 = off >> BACKEND_RANGE_SHIFT;
    uint64_t g1 = (off + len - 1) >> BACKEND_RANGE_SHIFT;
    int s0 = g0 % BACKEND_RANGE_LOCKS;
    int s1 = g1 % BACKEND_RANGE_LOCKS;

    if (g1 - g0 >= BACKEND_RANGE_LOCKS - 1) {
        run[0][0] = 0;
        run[0][1] = BACKEND_RANGE_LOCKS - 1;
        return 1;
    }
    if (s0 <= s1) {
        run[0][0] = s0;
        run[0][1] = s1;
        return 1;
    }
    run[0][0] = 0;
    run[0][1] = s1;
    run[1][0] = s0;
    run[1][1] = BACKEND_RANGE_LOCKS - 1;
    return 2;
}

/*
 * Make an access to [off, off + len) of the backing store atomic with
 * respect to every other access that takes the locks of its range.
 */
void backend_lock_range(SsdDramBackend *b, uint64_t off, uint64_t len)
{
    int run[2][2];
    int nr, r, i;

    if (!b || !b->range_locks || !len) {
        return;
    }
    nr = backend_range_runs(off, len, run);
    for (r = 0; r < nr; r++) {
        for (i = run[r][0]; i <= run[r][1]; i++) {
            if (qemu_mutex_trylock(&b->range_locks[i])) {
                qatomic_inc(&b->range_waits);
                qemu_mutex_lock(&b->range_locks[i]);
            }
        }
    }
}

void backend_unlock_range(SsdDramBackend *b, uint64_t off, uint64_t len)
{
    int run[2][2];
    int nr, r, i;

    if (!b || !b->range_locks || !len) {
        return;
    }
    nr = backend_range_runs(off, len, run);
    for (r = 0; r < nr; r++) {
        for (i = run[r][0]; i <= run[r][1]; i++) {
            qemu_mutex_unlock(&b->range_locks[i]);
        }
    }
}

/*
 * qtest only: stop a write halfway through its copy while x-copy-hold is set,
 * at most 60 s, and show the stop in x-copy-held. A read sent meanwhile meets
 * a half-written block unless the range locks keep it out.
 */
void femu_test_copy_hold(FemuCtrl *n)
{
    int ms;

    qatomic_store_release(&n->test_copy_held, 1);
    for (ms = 0; ms < 60000 && qatomic_load_acquire(&n->test_copy_hold);
         ms++) {
        g_usleep(1000);
    }
    qatomic_store_release(&n->test_copy_held, 0);
}

/* One guest transfer; a write split in two when a qtest asks for it. */
static MemTxResult backend_copy(FemuCtrl *n, dma_addr_t addr, void *ptr,
                                dma_addr_t len, bool to_host)
{
    dma_addr_t half = len / 2;

    if (likely(!qatomic_read(&n->test_copy_hold)) || to_host || !half) {
        return femu_dma_rw(n, addr, ptr, len, to_host);
    }
    if (femu_dma_rw(n, addr, ptr, half, false)) {
        return MEMTX_ERROR;
    }
    femu_test_copy_hold(n);
    return femu_dma_rw(n, addr + half, (uint8_t *)ptr + half, len - half,
                       false);
}

/*
 * Copy between guest memory and the backing store. The scatter list is
 * consumed whatever the outcome. Returns 0, -ERANGE when a mode's address
 * translation leaves the backing store, or -EIO when guest memory could not
 * be reached.
 */
int backend_rw(SsdDramBackend *b, QEMUSGList *qsg, uint64_t *lbal, bool is_write)
{
    int sg_cur_index = 0;
    dma_addr_t sg_cur_byte = 0;
    dma_addr_t cur_addr, cur_len;
    uint64_t mb_oft = lbal[0];
    void *mb = b->logical_space;

    DMADirection dir = DMA_DIRECTION_FROM_DEVICE;
    /* OCSSD takes one offset per entry; every other mode, one range */
    bool per_entry = b->femu_mode == FEMU_OCSSD_MODE;
    uint64_t lock_oft = mb_oft;
    uint64_t lock_len = qsg->size;
    int ret = 0;

    if (is_write) {
        dir = DMA_DIRECTION_TO_DEVICE;
    }

    if (!per_entry) {
        backend_lock_range(b, lock_oft, lock_len);
    }
    while (sg_cur_index < qsg->nsg) {
        cur_addr = qsg->sg[sg_cur_index].base + sg_cur_byte;
        cur_len = qsg->sg[sg_cur_index].len - sg_cur_byte;
        /*
         * The offset comes from a mode's own address translation. Refuse one
         * that leaves the backing store rather than reading or writing past it,
         * which corrupts the heap and takes QEMU down with it.
         */
        if (mb_oft > (uint64_t)b->size ||
            cur_len > (uint64_t)b->size - mb_oft) {
            femu_err("backend: %" PRIu64 "+%" PRIu64 " is outside the %" PRId64
                     " byte backing store\n", (uint64_t)mb_oft,
                     (uint64_t)cur_len, b->size);
            ret = -ERANGE;
            break;
        }
        if (per_entry) {
            backend_lock_range(b, mb_oft, cur_len);
        }
        if (backend_copy(container_of(qsg->dev, FemuCtrl, parent_obj.qdev),
                         cur_addr, mb + mb_oft, cur_len,
                         dir == DMA_DIRECTION_FROM_DEVICE)) {
            ret = -EIO;
        }
        if (per_entry) {
            backend_unlock_range(b, mb_oft, cur_len);
        }
        if (ret) {
            break;
        }

        sg_cur_byte += cur_len;
        if (sg_cur_byte == qsg->sg[sg_cur_index].len) {
            sg_cur_byte = 0;
            ++sg_cur_index;
        }

        if (b->femu_mode == FEMU_OCSSD_MODE) {
            /*
             * One offset per scatter-gather entry. Reading the next one after
             * the index has passed the last entry reads one element off the
             * end of the list: the value went unused, but the read did not.
             */
            if (sg_cur_index < qsg->nsg) {
                mb_oft = lbal[sg_cur_index];
            }
        } else if (b->femu_mode == FEMU_BBSSD_MODE ||
                   b->femu_mode == FEMU_NOSSD_MODE ||
                   b->femu_mode == FEMU_ZNSSD_MODE ||
                   b->femu_mode == FEMU_CSD_MODE ||
                   b->femu_mode == FEMU_KVSSD_MODE) {
            mb_oft += cur_len;
        } else {
            assert(0);
        }
    }

    if (!per_entry) {
        backend_unlock_range(b, lock_oft, lock_len);
    }
    qemu_sglist_destroy(qsg);

    return ret;
}
