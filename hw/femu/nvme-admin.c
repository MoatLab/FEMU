#include "./nvme.h"
#include "./kvssd/kvssd.h"

#define NVME_IDENTIFY_DATA_SIZE 4096

/*
 * Which features the controller answers, and what a host may do with each.
 * Nothing is saveable: there is no persistent store behind Set Features, so
 * Select = Saved reads the defaults, as it does in hw/nvme.
 */
static const bool nvme_feature_support[NVME_FID_MAX] = {
    [NVME_ARBITRATION]              = true,
    [NVME_POWER_MANAGEMENT]         = true,
    [NVME_LBA_RANGE_TYPE]           = true,
    [NVME_TEMPERATURE_THRESHOLD]    = true,
    [NVME_ERROR_RECOVERY]           = true,
    [NVME_VOLATILE_WRITE_CACHE]     = true,
    [NVME_NUMBER_OF_QUEUES]         = true,
    [NVME_INTERRUPT_COALESCING]     = true,
    [NVME_INTERRUPT_VECTOR_CONF]    = true,
    [NVME_WRITE_ATOMICITY]          = true,
    [NVME_ASYNCHRONOUS_EVENT_CONF]  = true,
    [NVME_FDP_MODE]                 = true,
    [NVME_FDP_EVENTS]               = true,
    [NVME_KV_FEAT_CONFIG]           = true,
    [NVME_SOFTWARE_PROGRESS_MARKER] = true,
};

static const uint32_t nvme_feature_cap[NVME_FID_MAX] = {
    [NVME_ARBITRATION]              = NVME_FEAT_CAP_CHANGE,
    [NVME_POWER_MANAGEMENT]         = NVME_FEAT_CAP_CHANGE,
    [NVME_LBA_RANGE_TYPE]           = NVME_FEAT_CAP_CHANGE | NVME_FEAT_CAP_NS,
    [NVME_TEMPERATURE_THRESHOLD]    = NVME_FEAT_CAP_CHANGE,
    [NVME_ERROR_RECOVERY]           = NVME_FEAT_CAP_CHANGE | NVME_FEAT_CAP_NS,
    [NVME_VOLATILE_WRITE_CACHE]     = NVME_FEAT_CAP_CHANGE,
    [NVME_NUMBER_OF_QUEUES]         = NVME_FEAT_CAP_CHANGE,
    [NVME_INTERRUPT_COALESCING]     = NVME_FEAT_CAP_CHANGE,
    [NVME_INTERRUPT_VECTOR_CONF]    = NVME_FEAT_CAP_CHANGE,
    [NVME_WRITE_ATOMICITY]          = NVME_FEAT_CAP_CHANGE,
    [NVME_ASYNCHRONOUS_EVENT_CONF]  = NVME_FEAT_CAP_CHANGE,
    [NVME_FDP_MODE]                 = NVME_FEAT_CAP_CHANGE,
    [NVME_FDP_EVENTS]               = NVME_FEAT_CAP_CHANGE | NVME_FEAT_CAP_NS,
    [NVME_KV_FEAT_CONFIG]           = NVME_FEAT_CAP_CHANGE | NVME_FEAT_CAP_NS,
    [NVME_SOFTWARE_PROGRESS_MARKER] = NVME_FEAT_CAP_CHANGE,
};

static const uint32_t nvme_cse_acs[256] = {
    [NVME_ADM_CMD_DELETE_SQ]        = NVME_CMD_EFF_CSUPP,
    [NVME_ADM_CMD_CREATE_SQ]        = NVME_CMD_EFF_CSUPP,
    [NVME_ADM_CMD_GET_LOG_PAGE]     = NVME_CMD_EFF_CSUPP,
    [NVME_ADM_CMD_DELETE_CQ]        = NVME_CMD_EFF_CSUPP,
    [NVME_ADM_CMD_CREATE_CQ]        = NVME_CMD_EFF_CSUPP,
    [NVME_ADM_CMD_IDENTIFY]         = NVME_CMD_EFF_CSUPP,
    [NVME_ADM_CMD_ABORT]            = NVME_CMD_EFF_CSUPP,
    [NVME_ADM_CMD_SET_FEATURES]     = NVME_CMD_EFF_CSUPP,
    [NVME_ADM_CMD_GET_FEATURES]     = NVME_CMD_EFF_CSUPP,
    [NVME_ADM_CMD_ASYNC_EV_REQ]     = NVME_CMD_EFF_CSUPP,
};

//static const uint32_t nvme_cse_iocs_none[256];

static const uint32_t nvme_cse_iocs_nvm[256] = {
    [NVME_CMD_FLUSH]                = NVME_CMD_EFF_CSUPP | NVME_CMD_EFF_LBCC,
    [NVME_CMD_WRITE_ZEROES]         = NVME_CMD_EFF_CSUPP | NVME_CMD_EFF_LBCC,
    [NVME_CMD_WRITE]                = NVME_CMD_EFF_CSUPP | NVME_CMD_EFF_LBCC,
    [NVME_CMD_READ]                 = NVME_CMD_EFF_CSUPP,
    [NVME_CMD_DSM]                  = NVME_CMD_EFF_CSUPP | NVME_CMD_EFF_LBCC,
    [NVME_CMD_COMPARE]              = NVME_CMD_EFF_CSUPP,
};

static const uint32_t nvme_cse_iocs_zoned[256] = {
    [NVME_CMD_FLUSH]                = NVME_CMD_EFF_CSUPP | NVME_CMD_EFF_LBCC,
    [NVME_CMD_WRITE_ZEROES]         = NVME_CMD_EFF_CSUPP | NVME_CMD_EFF_LBCC,
    [NVME_CMD_WRITE]                = NVME_CMD_EFF_CSUPP | NVME_CMD_EFF_LBCC,
    [NVME_CMD_READ]                 = NVME_CMD_EFF_CSUPP,
    [NVME_CMD_DSM]                  = NVME_CMD_EFF_CSUPP | NVME_CMD_EFF_LBCC,
    [NVME_CMD_COMPARE]              = NVME_CMD_EFF_CSUPP,
    [NVME_CMD_ZONE_APPEND]          = NVME_CMD_EFF_CSUPP | NVME_CMD_EFF_LBCC,
    [NVME_CMD_ZONE_MGMT_SEND]       = NVME_CMD_EFF_CSUPP | NVME_CMD_EFF_LBCC,
    [NVME_CMD_ZONE_MGMT_RECV]       = NVME_CMD_EFF_CSUPP,
};

static uint16_t nvme_del_sq(FemuCtrl *n, NvmeCmd *cmd)
{
    NvmeDeleteQ *c = (NvmeDeleteQ *)cmd;
    NvmeRequest *req, *next;
    NvmeSQueue *sq;
    NvmeCQueue *cq;
    uint16_t qid = le16_to_cpu(c->qid);
    bool resume;

    if (!qid || nvme_check_sqid(n, qid)) {
        return NVME_INVALID_QID | NVME_DNR;
    }

    sq = n->sq[qid];
    if (!sq->is_active) {
        return NVME_INVALID_QID | NVME_DNR;
    }

    /*
     * Stop the dataplane before taking the queue apart. The request array
     * about to be freed is reachable from the rings and from the poller's
     * pending completions, and the FTL thread may be holding one of its
     * requests right now.
     */
    resume = nvme_pause_pollers(n);
    sq->is_active = false;
    if (!nvme_check_cqid(n, sq->cqid)) {
        cq = n->cq[sq->cqid];
        QTAILQ_REMOVE(&cq->sq_list, sq, entry);

        nvme_post_cqes_io(cq);
        QTAILQ_FOREACH_SAFE(req, &cq->req_list, entry, next) {
            if (req->sq == sq) {
                QTAILQ_REMOVE(&cq->req_list, req, entry);
                QTAILQ_INSERT_TAIL(&sq->req_list, req, entry);
            }
        }
    }

    nvme_drain_sq(n, sq);
    nvme_free_sq(sq, n);
    nvme_resume_pollers(n, resume);

    return NVME_SUCCESS;
}

static uint16_t nvme_create_sq(FemuCtrl *n, NvmeCmd *cmd)
{
    NvmeSQueue *sq;
    NvmeCreateSq *c = (NvmeCreateSq *)cmd;

    uint16_t cqid = le16_to_cpu(c->cqid);
    uint16_t sqid = le16_to_cpu(c->sqid);
    uint16_t qsize = le16_to_cpu(c->qsize);
    uint16_t qflags = le16_to_cpu(c->sq_flags);
    uint64_t prp1 = le64_to_cpu(c->prp1);

    if (!cqid || nvme_check_cqid(n, cqid)) {
        return NVME_INVALID_CQID | NVME_DNR;
    }
    /*
     * n->sq is sized nr_io_queues + 1. nvme_check_sqid() returns nonzero both
     * for an out-of-range id and for an id with no live queue, so it cannot by
     * itself reject an out-of-range id here; bound sqid explicitly before it is
     * used to index n->sq in nvme_init_sq().
     */
    if (!sqid || sqid > n->nr_io_queues || !nvme_check_sqid(n, sqid)) {
        return NVME_INVALID_QID | NVME_DNR;
    }
    if (!qsize || qsize > NVME_CAP_MQES(n->bar.cap)) {
        return NVME_MAX_QSIZE_EXCEEDED | NVME_DNR;
    }
    if (!prp1 || prp1 & (n->page_size - 1)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (!(NVME_SQ_FLAGS_PC(qflags)) && NVME_CAP_CQR(n->bar.cap)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    sq = g_malloc0(sizeof(*sq));
    if (nvme_init_sq(sq, n, prp1, sqid, cqid, qsize + 1,
                NVME_SQ_FLAGS_QPRIO(qflags),
                NVME_SQ_FLAGS_PC(qflags))) {
        g_free(sq);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    assert(sq->is_active == false);
    /*
     * Publish is_active LAST, after a write barrier, so a concurrent poller
     * that observes is_active==true is guaranteed to see a fully-initialized
     * SQ (size / dma_addr_hva / io_req filled by nvme_init_sq, which also
     * publishes n->sq[sqid] before returning). Without this, at high
     * queue-creation rates (e.g. SPDK with many reactors) a poller could race
     * a half-initialized SQ and segfault on a stale dma_addr_hva. The matching
     * acquire barrier is the smp_rmb() in nvme_poller().
     */
    smp_wmb();
    sq->is_active = true;

    return NVME_SUCCESS;
}

static uint16_t nvme_create_cq(FemuCtrl *n, NvmeCmd *cmd)
{
    NvmeCQueue *cq;
    NvmeCreateCq *c = (NvmeCreateCq *)cmd;
    uint16_t cqid = le16_to_cpu(c->cqid);
    uint16_t vector = le16_to_cpu(c->irq_vector);
    uint16_t qsize = le16_to_cpu(c->qsize);
    uint16_t qflags = le16_to_cpu(c->cq_flags);
    uint64_t prp1 = le64_to_cpu(c->prp1);

    /*
     * Bound cqid before it indexes n->cq (sized nr_io_queues + 1); see the
     * matching note in nvme_create_sq(). nvme_check_cqid() returns 0 when the
     * queue already exists, so this also rejects a duplicate identifier, and
     * the slot is guaranteed free below.
     */
    if (!cqid || cqid > n->nr_io_queues || !nvme_check_cqid(n, cqid)) {
        return NVME_INVALID_CQID | NVME_DNR;
    }
    if (!qsize || qsize > NVME_CAP_MQES(n->bar.cap)) {
        return NVME_MAX_QSIZE_EXCEEDED | NVME_DNR;
    }
    if (!prp1) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (vector > n->nr_io_queues) {
        return NVME_INVALID_IRQ_VECTOR | NVME_DNR;
    }
    /*
     * MSI is limited to the number of vectors the guest has enabled (at most
     * 32). If MSI is active, a completion-queue vector at or beyond that count
     * has no MSI vector and would make msi_notify() assert when the queue
     * fires; reject it as an invalid interrupt vector instead.
     */
    if (msi_enabled(&n->parent_obj) &&
        vector >= msi_nr_vectors_allocated(&n->parent_obj)) {
        return NVME_INVALID_IRQ_VECTOR | NVME_DNR;
    }
    if (!(NVME_CQ_FLAGS_PC(qflags)) && NVME_CAP_CQR(n->bar.cap)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    cq = g_malloc0(sizeof(*cq));
    assert(cq != NULL);
    if (nvme_init_cq(cq, n, prp1, cqid, vector, qsize + 1,
                     NVME_CQ_FLAGS_IEN(qflags), NVME_CQ_FLAGS_PC(qflags))) {
        g_free(cq);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    /*
     * A failure here means no interrupt route of its own: without KVM there is
     * none to take, and the completion path then notifies through MSI-X
     * directly. The queue is still usable, so the command is not refused.
     */
    nvme_setup_virq(n, cq);

    assert(cq->is_active == false);
    cq->is_active = true;

    return NVME_SUCCESS;
}

static uint16_t nvme_del_cq(FemuCtrl *n, NvmeCmd *cmd)
{
    NvmeDeleteQ *c = (NvmeDeleteQ *)cmd;
    NvmeCQueue *cq;
    uint16_t qid = le16_to_cpu(c->qid);
    bool resume;

    if (!qid || nvme_check_cqid(n, qid)) {
        return NVME_INVALID_CQID | NVME_DNR;
    }

    cq = n->cq[qid];
    assert(cq->is_active == true);
    /* refused while a submission queue still uses it, and then left as it was */
    if (!QTAILQ_EMPTY(&cq->sq_list)) {
        return NVME_INVALID_QUEUE_DEL;
    }
    /*
     * The pollers reach this queue through n->cq[], so take the dataplane down
     * before it goes, exactly as deleting a submission queue does. Without it
     * a poller can load the pointer and read through it after the free.
     */
    resume = nvme_pause_pollers(n);
    cq->is_active = false;
    nvme_free_cq(cq, n);
    nvme_resume_pollers(n, resume);

    return NVME_SUCCESS;
}

static int cmp_pri(pqueue_pri_t next, pqueue_pri_t curr)
{
    return (next > curr);
}

static pqueue_pri_t get_pri(void *a)
{
    return ((NvmeRequest *)a)->expire_time;
}

static void set_pri(void *a, pqueue_pri_t pri)
{
    ((NvmeRequest *)a)->expire_time = pri;
}

static size_t get_pos(void *a)
{
    return ((NvmeRequest *)a)->pos;
}

static void set_pos(void *a, size_t pos)
{
    ((NvmeRequest *)a)->pos = pos;
}

static void nvme_init_poller(FemuCtrl *n)
{
    int i;

    n->should_isr = g_malloc0(sizeof(bool) * (n->nr_io_queues + 1));

    /*
     * M:N poller<->queue mapping. With multipoller enabled, spawn
     * nr_pollers = ceil(nr_io_queues / poller_ratio) threads; each poller
     * sweeps a round-robin shard of the queues (see nvme_poller). ratio == 1
     * (the default) gives nr_pollers == nr_io_queues, i.e. one poller per
     * queue -- bit-identical to the original 1:1 behavior. ratio > 1 trades
     * fewer busy-spinning poller threads (less core oversubscription) for more
     * queues per poller.
     */
    if (n->multipoller_enabled) {
        uint32_t r = n->poller_ratio ? n->poller_ratio : 1;
        n->nr_pollers = (n->nr_io_queues + r - 1) / r;
    } else {
        n->nr_pollers = 1;
    }

    /* poller quiesce flags (1-based poller indices); see poller_in_sweep */
    if (!n->poller_in_sweep) {
        n->poller_in_sweep = g_malloc0(sizeof(bool) * (n->nr_pollers + 1));
    }

    /*
     * per-poller I/O counters, cacheline-isolated (1-based); see FemuPollerCtr.
     * qemu_memalign(64) so each slot's QEMU_ALIGNED(64) padding actually lands
     * on its own cacheline (g_malloc0 would not guarantee 64-byte alignment).
     */
    if (!n->poller_ctr) {
        size_t ctr_sz = sizeof(FemuPollerCtr) * (n->nr_pollers + 1);
        n->poller_ctr = qemu_memalign(64, ctr_sz);
        memset(n->poller_ctr, 0, ctr_sz);
    }

    /* Coperd: we put NvmeRequest into these rings */
    n->to_ftl = g_malloc0(sizeof(struct rte_ring *) * (n->nr_pollers + 1));
    for (i = 1; i <= n->nr_pollers; i++) {
        n->to_ftl[i] = femu_ring_create(FEMU_RING_TYPE_MP_SC, FEMU_MAX_INF_REQS);
        if (!n->to_ftl[i]) {
            femu_err("Failed to create ring (n->to_ftl) ...\n");
            abort();
        }
        assert(rte_ring_empty(n->to_ftl[i]));
    }

    n->to_poller = g_malloc0(sizeof(struct rte_ring *) * (n->nr_pollers + 1));
    for (i = 1; i <= n->nr_pollers; i++) {
        n->to_poller[i] = femu_ring_create(FEMU_RING_TYPE_MP_SC, FEMU_MAX_INF_REQS);
        if (!n->to_poller[i]) {
            femu_err("Failed to create ring (n->to_poller) ...\n");
            abort();
        }
        assert(rte_ring_empty(n->to_poller[i]));
    }

    n->pq = g_malloc0(sizeof(pqueue_t *) * (n->nr_pollers + 1));
    for (i = 1; i <= n->nr_pollers; i++) {
        n->pq[i] = pqueue_init(FEMU_MAX_INF_REQS, cmp_pri, get_pri, set_pri,
                               get_pos, set_pos);
        if (!n->pq[i]) {
            femu_err("Failed to create pqueue (n->pq) ...\n");
            abort();
        }
    }

    n->poller = g_malloc0(sizeof(QemuThread) * (n->nr_pollers + 1));
    NvmePollerThreadArgument *args = malloc(sizeof(NvmePollerThreadArgument) *
                                            (n->nr_pollers + 1));
    for (i = 1; i <= n->nr_pollers; i++) {
        args[i].n = n;
        args[i].index = i;
        /*
         * Thread name must fit the kernel's 15-char TASK_COMM_LEN limit
         * (incl. NUL), or pthread_setname_np() silently fails and the poller
         * inherits its creator's comm (e.g. "CPU N/KVM"). That misnames the
         * pollers, breaking per-thread identification and CPU pinning. Keep
         * "femu-poller" (11 chars) rather than the 16-char "femu-nvme-poller".
         */
        qemu_thread_create(&n->poller[i], "femu-poller", nvme_poller,
                &args[i], QEMU_THREAD_JOINABLE);
        femu_debug("femu-poller [%d] created ...\n", i - 1);
    }
}

/*
 * Start serving the I/O queues. Called when the host enables the controller:
 * the shadow doorbell buffer is an optional host optimisation, and a host that
 * never configures one drives the doorbell registers instead. The poller
 * threads are created once and survive a reset, which only clears
 * dataplane_started until the next enable.
 */
void nvme_start_dataplane(FemuCtrl *n)
{
    if (!n->poller_on) {
        nvme_init_poller(n);
        n->poller_on = true;
    }
    n->dataplane_started = true;
}

static uint16_t nvme_set_db_memory(FemuCtrl *n, const NvmeCmd *cmd)
{
    uint64_t dbs_addr = le64_to_cpu(cmd->dptr.prp1);
    uint64_t eis_addr = le64_to_cpu(cmd->dptr.prp2);
    uint8_t stride = n->db_stride;
    int dbbuf_entry_sz = 1 << (2 + stride);
    AddressSpace *as = pci_get_address_space(&n->parent_obj);
    void *dbs_hva, *eis_hva;
    int i;


    dma_addr_t dbs_tlen = n->page_size, eis_tlen = n->page_size;

    /* Addresses should not be NULL and should be page aligned. */
    if (dbs_addr == 0 || dbs_addr & (n->page_size - 1) || eis_addr == 0 ||
            eis_addr & (n->page_size - 1)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    /* the buffers are set once per controller enable; a second one is refused */
    if (n->dbs_addr) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    /*
     * Each buffer is one memory page and holds two entries per queue plus the
     * admin pair, so a controller with more queues than fit cannot use them.
     * The loop below wrote past the mapping rather than saying so.
     */
    if ((2ULL * n->nr_io_queues + 1) * dbbuf_entry_sz > n->page_size) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    dbs_hva = dma_memory_map(as, dbs_addr, &dbs_tlen, DMA_DIRECTION_FROM_DEVICE,
                             MEMTXATTRS_UNSPECIFIED);
    eis_hva = dma_memory_map(as, eis_addr, &eis_tlen, DMA_DIRECTION_FROM_DEVICE,
                             MEMTXATTRS_UNSPECIFIED);
    /*
     * The host may name an address that cannot be mapped, or one backed by
     * something that does not hand out a whole page. Refuse the command in
     * that case: the pollers dereference these pointers on every sweep, so
     * accepting a short or absent mapping is a wild write from a guest
     * command. Nothing is recorded until both succeed, so the host can retry.
     */
    if (!dbs_hva || !eis_hva || dbs_tlen < n->page_size ||
        eis_tlen < n->page_size) {
        if (dbs_hva) {
            dma_memory_unmap(as, dbs_hva, dbs_tlen,
                             DMA_DIRECTION_FROM_DEVICE, 0);
        }
        if (eis_hva) {
            dma_memory_unmap(as, eis_hva, eis_tlen,
                             DMA_DIRECTION_FROM_DEVICE, 0);
        }
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    n->dbs_addr = dbs_addr;
    n->eis_addr = eis_addr;
    n->dbs_addr_hva = (uint64_t)dbs_hva;
    n->eis_addr_hva = (uint64_t)eis_hva;
    n->dbbuf_map_len = n->page_size;

    for (i = 1; i <= n->nr_io_queues; i++) {
        NvmeSQueue *sq = n->sq[i];
        NvmeCQueue *cq = n->cq[i];
        uint64_t db_hva, eventidx_hva;

        if (sq) {
            /* Submission queue tail pointer location, 2 * QID * stride. */
            db_hva = n->dbs_addr_hva + 2 * i * dbbuf_entry_sz;
            eventidx_hva = n->eis_addr_hva + 2 * i * dbbuf_entry_sz;
            /*
             * The buffer the host just handed over is zeroed, but the queue
             * may already have advanced through the doorbell registers, so
             * seed it with where the queue actually stands. Seed before
             * publishing: a poller reads the shadow from the moment
             * db_addr_hva is set, and one that sweeps in between takes the
             * zero as the tail, overwrites sq->tail with it and leaves the
             * queue stalled until the host submits again.
             */
            *((uint32_t *)db_hva) = sq->tail;
            smp_wmb();  /* seed the shadow before a poller can find it */
            sq->eventidx_addr = eis_addr + 2 * i * dbbuf_entry_sz;
            sq->eventidx_addr_hva = eventidx_hva;
            sq->db_addr = dbs_addr + 2 * i * dbbuf_entry_sz;
            sq->db_addr_hva = db_hva;
            femu_debug("DBBUF,sq[%d]:db=%" PRIu64 ",ei=%" PRIu64 "\n", i,
                    sq->db_addr, sq->eventidx_addr);
        }
        if (cq) {
            /* Completion queue head pointer location, (2 * QID + 1) * stride. */
            db_hva = n->dbs_addr_hva + (2 * i + 1) * dbbuf_entry_sz;
            eventidx_hva = n->eis_addr_hva + (2 * i + 1) * dbbuf_entry_sz;
            *((uint32_t *)db_hva) = cq->head;
            smp_wmb();  /* seed the shadow before a poller can find it */
            cq->eventidx_addr = eis_addr + (2 * i + 1) * dbbuf_entry_sz;
            cq->eventidx_addr_hva = eventidx_hva;
            cq->db_addr = dbs_addr + (2 * i + 1) * dbbuf_entry_sz;
            cq->db_addr_hva = db_hva;
            femu_debug("DBBUF,cq[%d]:db=%" PRIu64 ",ei=%" PRIu64 "\n", i,
                    cq->db_addr, cq->eventidx_addr);
        }
    }

    femu_debug("nvme_set_db_memory returns SUCCESS!\n");

    return NVME_SUCCESS;
}

static bool nvme_nsid_valid(FemuCtrl *n, uint32_t nsid)
{
    return nsid && (nsid == NVME_NSID_BROADCAST || nsid <= n->num_namespaces);
}

static inline NvmeNamespace *nvme_ns(FemuCtrl *n, uint32_t nsid)
{
    if (!nsid || nsid > n->num_namespaces) {
        return NULL;
    }

    return &n->namespaces[nsid - 1];
}

static uint16_t nvme_rpt_empty_id_struct(FemuCtrl *n, NvmeCmd *cmd)
{
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);
    uint8_t id[NVME_IDENTIFY_DATA_SIZE] = {};

    return dma_read_prp(n, id, sizeof(id), prp1, prp2);
}

static inline bool nvme_csi_has_nvm_support(NvmeNamespace *ns)
{
    switch (ns->csi) {
    case NVME_CSI_NVM:
    case NVME_CSI_ZONED:
        return true;
    }

    return false;
}

static uint16_t nvme_identify_ns(FemuCtrl *n, NvmeCmd *cmd)
{
    NvmeNamespace *ns;
    NvmeIdentify *c = (NvmeIdentify *)cmd;
    uint32_t nsid = le32_to_cpu(c->nsid);
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);

    if (!nvme_nsid_valid(n, nsid) || nsid == NVME_NSID_BROADCAST) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ns = nvme_ns(n, nsid);
    if (unlikely(!ns)) {
        return nvme_rpt_empty_id_struct(n, cmd);
    }

    /*
     * This structure describes the namespace's size and format, which an active
     * namespace has whatever command set it runs, and which a host needs before
     * it can attach the namespace and ask for the command-set-specific pages
     * below. Report it for any active namespace rather than only for the command
     * sets built on the NVM one, otherwise a namespace of another kind cannot be
     * attached at all.
     */
    if (c->csi == NVME_CSI_NVM) {
        return dma_read_prp(n, (uint8_t *)&ns->id_ns, sizeof(NvmeIdNs),
                                 prp1, prp2);
    }

    return NVME_INVALID_CMD_SET | NVME_DNR;
}

static uint16_t nvme_identify_ns_csi(FemuCtrl *n, NvmeCmd *cmd)
{
    NvmeNamespace *ns;
    NvmeIdentify *c = (NvmeIdentify *)cmd;
    uint32_t nsid = le32_to_cpu(c->nsid);
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);

    if (!nvme_nsid_valid(n, nsid) || nsid == NVME_NSID_BROADCAST) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ns = nvme_ns(n, nsid);
    if (unlikely(!ns)) {
        return nvme_rpt_empty_id_struct(n, cmd);
    }

    if (c->csi == NVME_CSI_NVM && nvme_csi_has_nvm_support(ns)) {
        return nvme_rpt_empty_id_struct(n, cmd);
    } else if (c->csi == NVME_CSI_ZONED && ns->csi == NVME_CSI_ZONED) {
        /*
         * An Identify data structure is 4096 bytes. This transferred the
         * host's memory page size instead, which a guest sets through CC.MPS
         * and can raise above that whenever the controller advertises it,
         * reading past the end of the structure.
         */
        return dma_read_prp(n, (uint8_t *)ns->id_ns_zoned,
                            NVME_IDENTIFY_DATA_SIZE, prp1, prp2);
    } else if (c->csi == NVME_CSI_KV && ns->csi == NVME_CSI_KV) {
        return kvssd_identify_ns_csi(n, ns, cmd);
    }

    return NVME_INVALID_FIELD | NVME_DNR;
}

static uint16_t nvme_identify_ctrl(FemuCtrl *n, NvmeCmd *cmd)
{
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);

    return dma_read_prp(n, (uint8_t *)&n->id_ctrl, sizeof(n->id_ctrl),
                             prp1, prp2);
}

static uint16_t nvme_identify_ctrl_csi(FemuCtrl *n, NvmeCmd *cmd)
{
    NvmeIdentify *c = (NvmeIdentify *)cmd;
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);

    typedef struct NvmeIdCtrlZoned {
        uint8_t     zasl;
        uint8_t     rsvd1[4095];
    } NvmeIdCtrlZoned;

    NvmeIdCtrlZoned id = {};

    if (c->csi == NVME_CSI_NVM) {
        return nvme_rpt_empty_id_struct(n, cmd);
    } else if (c->csi == NVME_CSI_ZONED) {
        if (n->zasl_bs) {
            id.zasl = n->zasl;
        }
        return dma_read_prp(n, (uint8_t *)&id, sizeof(id), prp1, prp2);
    } else if (c->csi == NVME_CSI_KV) {
        return kvssd_identify_ctrl_csi(n, cmd);
    }

    return NVME_INVALID_FIELD | NVME_DNR;
}

static uint16_t nvme_identify_nslist(FemuCtrl *n, NvmeCmd *cmd)
{
    NvmeNamespace *ns;
    NvmeIdentify *c = (NvmeIdentify *)cmd;
    uint32_t min_nsid = le32_to_cpu(c->nsid);
    uint8_t list[NVME_IDENTIFY_DATA_SIZE] = {};
    static const int data_len = sizeof(list);
    uint32_t *list_ptr = (uint32_t *)list;
    int i, j = 0;
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);

    /*
     * Both 0xffffffff (NVME_NSID_BROADCAST) and 0xfffffffe are invalid values
     * since the Active Namespace ID List should return namespaces with ids
     * *higher* than the NSID specified in the command. This is also specified
     * in the spec (NVM Express v1.3d, Section 5.15.4).
     */
    if (min_nsid >= NVME_NSID_BROADCAST - 1) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    for (i = 1; i <= n->num_namespaces; i++) {
        ns = nvme_ns(n, i);
        if (!ns) {
            continue;
        }
        if (ns->id <= min_nsid) {
            continue;
        }
        list_ptr[j++] = cpu_to_le32(ns->id);
        if (j == data_len / sizeof(uint32_t)) {
            break;
        }
    }

    return dma_read_prp(n, list, data_len, prp1, prp2);
}

static uint16_t nvme_identify_nslist_csi(FemuCtrl *n, NvmeCmd *cmd)
{
    NvmeNamespace *ns;
    NvmeIdentify *c = (NvmeIdentify *)cmd;
    uint32_t min_nsid = le32_to_cpu(c->nsid);
    uint8_t list[NVME_IDENTIFY_DATA_SIZE] = {};
    static const int data_len = sizeof(list);
    uint32_t *list_ptr = (uint32_t *)list;
    int i, j = 0;
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);

    if (min_nsid >= NVME_NSID_BROADCAST - 1) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    if (c->csi != NVME_CSI_NVM && c->csi != NVME_CSI_ZONED &&
        c->csi != NVME_CSI_KV) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    for (i = 1; i <= n->num_namespaces; i++) {
        ns = nvme_ns(n, i);
        if (!ns) {
            continue;
        }
        if (ns->id <= min_nsid || c->csi != ns->csi) {
            continue;
        }
        list_ptr[j++] = cpu_to_le32(ns->id);
        if (j == data_len / sizeof(uint32_t)) {
            break;
        }
    }

    return dma_read_prp(n, list, data_len, prp1, prp2);
}

static uint16_t nvme_identify_ns_descr_list(FemuCtrl *n, NvmeCmd *cmd)
{
    NvmeNamespace *ns;
    NvmeIdentify *c = (NvmeIdentify *)cmd;
    uint32_t nsid = le32_to_cpu(c->nsid);
    uint8_t list[NVME_IDENTIFY_DATA_SIZE] = {};
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);

    struct data {
        struct {
            NvmeIdNsDescr hdr;
            uint8_t v[NVME_NIDL_UUID];
        } uuid;
        struct {
            NvmeIdNsDescr hdr;
            uint8_t v;
        } csi;
    };

    struct data *ns_descrs = (struct data *)list;

    if (!nvme_nsid_valid(n, nsid) || nsid == NVME_NSID_BROADCAST) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ns = nvme_ns(n, nsid);
    if (unlikely(!ns)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    ns_descrs->uuid.hdr.nidt = NVME_NIDT_UUID;
    ns_descrs->uuid.hdr.nidl = NVME_NIDL_UUID;
    memcpy(&ns_descrs->uuid.v, n->uuid.data, NVME_NIDL_UUID);

    ns_descrs->csi.hdr.nidt = NVME_NIDT_CSI;
    ns_descrs->csi.hdr.nidl = NVME_NIDL_CSI;
    ns_descrs->csi.v = ns->csi;

    return dma_read_prp(n, list, sizeof(list), prp1, prp2);
}

static uint16_t nvme_identify_cmd_set(FemuCtrl *n, NvmeCmd *cmd)
{
    uint8_t list[NVME_IDENTIFY_DATA_SIZE] = {};
    static const int data_len = sizeof(list);
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);

    NVME_SET_CSI(*list, NVME_CSI_NVM);
    NVME_SET_CSI(*list, NVME_CSI_ZONED);

    return dma_read_prp(n, list, data_len, prp1, prp2);
}

static uint16_t nvme_identify(FemuCtrl *n, NvmeCmd *cmd)
{
    NvmeIdentify *c = (NvmeIdentify *)cmd;
    uint32_t cns  = le32_to_cpu(c->cns);

    switch (cns) {
    case NVME_ID_CNS_NS:
    case NVME_ID_CNS_NS_PRESENT:
        return nvme_identify_ns(n, cmd);
    case NVME_ID_CNS_CS_NS:
    case NVME_ID_CNS_CS_NS_PRESENT:
        return nvme_identify_ns_csi(n, cmd);
    case NVME_ID_CNS_CTRL:
        return nvme_identify_ctrl(n, cmd);
    case NVME_ID_CNS_CS_CTRL:
        return nvme_identify_ctrl_csi(n, cmd);
    case NVME_ID_CNS_CS_NS_FMT:
        /*
         * Key-value format-index identify: the command names a format index in
         * CDW11 rather than a namespace, so it is answered from the first
         * key-value namespace the controller has. Namespace zero is not one on
         * a controller in another mode, and the key-value code would then be
         * handed that mode's state object.
         */
        if (c->csi == NVME_CSI_KV) {
            for (int i = 0; i < n->num_namespaces; i++) {
                if (NS_KVSSD(&n->namespaces[i])) {
                    return kvssd_identify_ns_csi_fmt(n, &n->namespaces[i], cmd);
                }
            }
        }
        return NVME_INVALID_FIELD | NVME_DNR;
    case NVME_ID_CNS_NS_ACTIVE_LIST:
    case NVME_ID_CNS_NS_PRESENT_LIST:
        return nvme_identify_nslist(n, cmd);
    case NVME_ID_CNS_CS_NS_ACTIVE_LIST:
    case NVME_ID_CNS_CS_NS_PRESENT_LIST:
        return nvme_identify_nslist_csi(n, cmd);
    case NVME_ID_CNS_NS_DESCR_LIST:
        return nvme_identify_ns_descr_list(n, cmd);
    case NVME_ID_CNS_IO_COMMAND_SET:
        return nvme_identify_cmd_set(n, cmd);
    default:
        return NVME_INVALID_FIELD | NVME_DNR;
    }
}

/* true when some namespace answers the key-value command set */
/*
 * The value a feature has before the host changes it: what realize set, so
 * Select = Default agrees with the first Get after a reset.
 */
static uint16_t nvme_get_feature_default(FemuCtrl *n, NvmeCmd *cmd,
                                         uint8_t fid, uint32_t dw11,
                                         NvmeCqe *cqe)
{
    uint32_t result = 0;

    switch (fid) {
    case NVME_LBA_RANGE_TYPE: {
        /*
         * This feature answers with a descriptor list rather than a value, so
         * it has to transfer one here too. Reporting success without writing
         * the buffer would leave the host parsing whatever it had there, and
         * the count in dword 0 is 0's based, so zero still claims one entry.
         * The default state is a single unused range.
         */
        NvmeRangeType rt;

        memset(&rt, 0, sizeof(rt));
        cqe->n.result = 0;
        return dma_read_prp(n, (uint8_t *)&rt, sizeof(rt),
                            le64_to_cpu(cmd->dptr.prp1),
                            le64_to_cpu(cmd->dptr.prp2));
    }
    case NVME_ARBITRATION:
        result = 0x1f0f0706;
        break;
    case NVME_TEMPERATURE_THRESHOLD:
        /*
         * Only the composite sensor is implemented, so every other one reads
         * zero, and the under-temperature threshold starts there too.
         */
        if (((dw11 >> 16) & 0xf) != 0 || (dw11 & (1 << 20))) {
            result = 0;
            break;
        }
        result = 0x14d;
        break;
    case NVME_VOLATILE_WRITE_CACHE:
        result = n->vwc;
        break;
    case NVME_NUMBER_OF_QUEUES:
        result = (n->nr_io_queues - 1) | ((n->nr_io_queues - 1) << 16);
        break;
    case NVME_INTERRUPT_COALESCING:
        result = n->intc_thresh | (n->intc_time << 8);
        break;
    case NVME_INTERRUPT_VECTOR_CONF:
        if ((dw11 & 0xffff) > n->nr_io_queues) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        result = (dw11 & 0xffff) | (n->intc << 16);
        break;
    case NVME_FDP_MODE:
        /* the same gate the current-value path applies */
        if (!n->subsys || !n->subsys->endgrp.fdp.enabled) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        result = 1;
        break;
    default:
        /* every other feature starts at zero, including an empty event list */
        break;
    }

    cqe->n.result = cpu_to_le32(result);
    return NVME_SUCCESS;
}

static uint16_t nvme_get_feature(FemuCtrl *n, NvmeCmd *cmd, NvmeCqe *cqe)
{
    NvmeRangeType *rt;
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint32_t dw11 = le32_to_cpu(cmd->cdw11);
    uint32_t nsid = le32_to_cpu(cmd->nsid);
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);
    uint8_t fid = NVME_GETSETFEAT_FID(dw10);
    uint8_t sel = NVME_GETFEAT_SELECT(dw10);

    if (!nvme_feature_support[fid]) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (nvme_feature_cap[fid] & NVME_FEAT_CAP_NS) {
        if (!nvme_nsid_valid(n, nsid) || nsid == NVME_NSID_BROADCAST) {
            return NVME_INVALID_NSID | NVME_DNR;
        }
        if (!nvme_ns(n, nsid)) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
    }

    switch (sel) {
    case NVME_GETFEAT_SELECT_CURRENT:
        break;
    case NVME_GETFEAT_SELECT_SAVED:
        /* nothing is saved, so the saved value is the default */
    case NVME_GETFEAT_SELECT_DEFAULT:
        return nvme_get_feature_default(n, cmd, fid, dw11, cqe);
    case NVME_GETFEAT_SELECT_CAP:
        cqe->n.result = cpu_to_le32(nvme_feature_cap[fid]);
        return NVME_SUCCESS;
    default:
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    switch (fid) {
    case NVME_KV_FEAT_CONFIG: {
        /* the mode that owns the namespace answers this one */
        NvmeNamespace *kv_ns = nvme_ns(n, nsid);

        if (!kv_ns || kv_ns->csi != NVME_CSI_KV) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        return kvssd_get_feature(n, kv_ns, cmd, cqe);
    }
    case NVME_ARBITRATION:
        cqe->n.result = cpu_to_le32(n->features.arbitration);
        break;
    case NVME_POWER_MANAGEMENT:
        cqe->n.result = cpu_to_le32(n->features.power_mgmt);
        break;
    case NVME_LBA_RANGE_TYPE: {
        /*
         * The number of ranges is a 0's based count, so a host asking for one
         * range put zero in the field and this transferred nothing at all.
         * The cap was one range's worth rather than the whole table, so a
         * host asking for more than one got only the first either way.
         */
        NvmeNamespace *rt_ns = &n->namespaces[nsid - 1];
        uint32_t nr = (dw11 & 0x3f) + 1;

        rt = rt_ns->lba_range;
        return dma_read_prp(n, (uint8_t *)rt,
                MIN(sizeof(rt_ns->lba_range), nr * sizeof(*rt)),
                prp1, prp2);
    }
    case NVME_NUMBER_OF_QUEUES:
        cqe->n.result = cpu_to_le32((n->nr_io_queues - 1) |
                ((n->nr_io_queues - 1) << 16));
        break;
    case NVME_TEMPERATURE_THRESHOLD:
        /* one composite sensor; THSEL picks the over or under threshold */
        if (((dw11 >> 16) & 0xf) != 0 && ((dw11 >> 16) & 0xf) != 0xf) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        cqe->n.result = cpu_to_le32((dw11 & (1 << 20)) ?
                                    n->features.temp_thresh_under :
                                    n->features.temp_thresh);
        break;
    case NVME_ERROR_RECOVERY:
        cqe->n.result = cpu_to_le32(nvme_ns(n, nsid)->err_rec);
        break;
    case NVME_VOLATILE_WRITE_CACHE:
        cqe->n.result = cpu_to_le32(n->features.volatile_wc);
        break;
    case NVME_INTERRUPT_COALESCING:
        cqe->n.result = cpu_to_le32(n->features.int_coalescing);
        break;
    case NVME_INTERRUPT_VECTOR_CONF:
        if ((dw11 & 0xffff) > n->nr_io_queues) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        cqe->n.result = cpu_to_le32(n->features.int_vector_config[dw11 & 0xffff]);
        break;
    case NVME_WRITE_ATOMICITY:
        cqe->n.result = cpu_to_le32(n->features.write_atomicity);
        break;
    case NVME_ASYNCHRONOUS_EVENT_CONF:
        cqe->n.result = cpu_to_le32(n->features.async_config);
        break;
    case NVME_SOFTWARE_PROGRESS_MARKER:
        cqe->n.result = cpu_to_le32(n->features.sw_prog_marker);
        break;
    case NVME_FDP_MODE:
        if (!n->subsys || !n->subsys->endgrp.fdp.enabled) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        /*
         * The mode may only change while the endurance group holds no
         * namespaces, and FEMU builds them at realize, so it never can.
         */
        return NVME_CMD_SEQ_ERROR | NVME_DNR;
    case NVME_FDP_EVENTS: {
        if (!n->subsys || !n->subsys->endgrp.fdp.enabled) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        NvmeEnduranceGroup *endgrp = &n->subsys->endgrp;
        uint8_t ruhid_idx = dw11 & 0xff;
        uint32_t nentries = 0;
        NvmeFdpEventDescr edescr[6];

        if (ruhid_idx >= endgrp->fdp.nruh) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }

        NvmeRuHandle *ruh = &endgrp->fdp.ruhs[ruhid_idx];
        memset(edescr, 0, sizeof(edescr));

        /* report enabled event types for this RUH */
        for (int ev = 0; ev < FDP_EVT_MAX && nentries < 6; ev++) {
            if ((ruh->event_filter >> nvme_fdp_evf_shifts[ev]) & 0x1) {
                edescr[nentries].evt = ev;
                edescr[nentries].evta = 1;
                nentries++;
            }
        }
        cqe->n.result = cpu_to_le32(nentries);
        if (nentries > 0) {
            uint32_t trans = MIN(nentries * sizeof(NvmeFdpEventDescr),
                                 (dw11 >> 16) ? (dw11 >> 16) : 4096);
            return dma_read_prp(n, (uint8_t *)edescr, trans, prp1, prp2);
        }
        break;
    }
    default:
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    return NVME_SUCCESS;
}

static uint16_t nvme_set_feature(FemuCtrl *n, NvmeCmd *cmd, NvmeCqe *cqe)
{
    NvmeRangeType *rt;
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint32_t dw11 = le32_to_cpu(cmd->cdw11);
    uint32_t nsid = le32_to_cpu(cmd->nsid);
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);
    uint8_t fid = NVME_GETSETFEAT_FID(dw10);
    uint8_t save = NVME_SETFEAT_SAVE(dw10);

    if (save && !(nvme_feature_cap[fid] & NVME_FEAT_CAP_SAVE)) {
        return NVME_FID_NOT_SAVEABLE | NVME_DNR;
    }

    if (!nvme_feature_support[fid]) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (nvme_feature_cap[fid] & NVME_FEAT_CAP_NS) {
        if (nsid != NVME_NSID_BROADCAST) {
            if (!nvme_nsid_valid(n, nsid)) {
                return NVME_INVALID_NSID | NVME_DNR;
            }
            if (!nvme_ns(n, nsid)) {
                return NVME_INVALID_FIELD | NVME_DNR;
            }
        }
    } else if (nsid && nsid != NVME_NSID_BROADCAST) {
        if (!nvme_nsid_valid(n, nsid)) {
            return NVME_INVALID_NSID | NVME_DNR;
        }
        return NVME_FID_NOT_NSID_SPEC | NVME_DNR;
    }

    if (!(nvme_feature_cap[fid] & NVME_FEAT_CAP_CHANGE)) {
        return NVME_FEAT_NOT_CHANGEABLE | NVME_DNR;
    }

    switch (fid) {
    case NVME_KV_FEAT_CONFIG: {
        /* the mode that owns the namespace handles this one */
        NvmeNamespace *kv_ns = nvme_ns(n, nsid);

        if (!kv_ns || kv_ns->csi != NVME_CSI_KV) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        return kvssd_set_feature(n, kv_ns, cmd, cqe);
    }
    case NVME_ARBITRATION:
        n->features.arbitration = dw11;
        break;
    case NVME_POWER_MANAGEMENT:
        n->features.power_mgmt = dw11;
        break;
    case NVME_LBA_RANGE_TYPE:
        if (nsid == NVME_NSID_BROADCAST) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        {
            /* the same 0's based count, see the matching get above */
            NvmeNamespace *rt_ns = &n->namespaces[nsid - 1];
            uint32_t nr = (dw11 & 0x3f) + 1;

            rt = rt_ns->lba_range;
            return dma_write_prp(n, (uint8_t *)rt,
                    MIN(sizeof(rt_ns->lba_range), nr * sizeof(*rt)),
                    prp1, prp2);
        }
    case NVME_NUMBER_OF_QUEUES:
        /* Coperd: nr_io_queues is 0-based */
        cqe->n.result = cpu_to_le32((n->nr_io_queues - 1) |
                ((n->nr_io_queues - 1) << 16));
        break;
    case NVME_TEMPERATURE_THRESHOLD:
        /*
         * dw11 carries the threshold in its low half and, above it, which
         * sensor (TMPSEL) and which side (THSEL) it applies to. There is one
         * composite sensor, and only its over threshold feeds the warning.
         */
        if (((dw11 >> 16) & 0xf) != 0 && ((dw11 >> 16) & 0xf) != 0xf) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        if (dw11 & (1 << 20)) {
            n->features.temp_thresh_under = dw11 & 0xffff;
            break;
        }
        n->features.temp_thresh = dw11 & 0xffff;
        /*
         * Crossing the threshold raises a SMART event once, pointing the host
         * at the health log. It is armed again when the threshold moves back
         * above the temperature and the previous event has been read.
         */
        if (n->features.temp_thresh <= n->temperature && !n->temp_warn_issued) {
            n->temp_warn_issued = 1;
            if (NVME_AEC_SMART(n->features.async_config) &
                NVME_SMART_TEMPERATURE) {
                nvme_enqueue_event(n, NVME_AER_TYPE_SMART,
                                   NVME_AER_INFO_SMART_TEMP_THRESH,
                                   NVME_LOG_SMART_INFO);
            }
        } else if (n->features.temp_thresh > n->temperature &&
                !(n->aer_mask & 1 << NVME_AER_TYPE_SMART)) {
            n->temp_warn_issued = 0;
        }
        break;
    case NVME_ERROR_RECOVERY: {
        /*
         * The read path tests this on the pollers to decide whether an
         * unwritten block is an error, so change it with the dataplane
         * stopped, as the write cache setting alongside does.
         */
        bool resume = nvme_pause_pollers(n);

        if (nsid == NVME_NSID_BROADCAST) {
            for (uint32_t i = 0; i < n->num_namespaces; i++) {
                n->namespaces[i].err_rec = dw11;
            }
        } else {
            nvme_ns(n, nsid)->err_rec = dw11;
        }
        nvme_resume_pollers(n, resume);
        break;
    }
    case NVME_VOLATILE_WRITE_CACHE: {
        /*
         * buffer_enabled() reads this on the FTL thread to decide whether the
         * write buffer may still accept pages, so change it with the dataplane
         * stopped rather than under a request in flight.
         */
        bool resume = nvme_pause_pollers(n);

        n->features.volatile_wc = dw11;
        nvme_resume_pollers(n, resume);
        break;
    }
    case NVME_INTERRUPT_COALESCING:
        n->features.int_coalescing = dw11;
        break;
    case NVME_INTERRUPT_VECTOR_CONF:
        if ((dw11 & 0xffff) > n->nr_io_queues) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        n->features.int_vector_config[dw11 & 0xffff] = dw11 & 0x1ffff;
        break;
    case NVME_WRITE_ATOMICITY:
        n->features.write_atomicity = dw11;
        break;
    case NVME_ASYNCHRONOUS_EVENT_CONF:
        n->features.async_config = dw11;
        break;
    case NVME_SOFTWARE_PROGRESS_MARKER:
        n->features.sw_prog_marker = dw11;
        break;
    case NVME_FDP_EVENTS: {
        if (!n->subsys || !n->subsys->endgrp.fdp.enabled) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        NvmeEnduranceGroup *endgrp = &n->subsys->endgrp;
        uint32_t cdw12 = le32_to_cpu(cmd->cdw12);
        uint8_t ruhid_idx = dw11 & 0xff;
        uint8_t enable = (dw11 >> 8) & 0x1;
        uint8_t nevents = (cdw12 >> 16) & 0xff;

        if (ruhid_idx >= endgrp->fdp.nruh) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }

        NvmeRuHandle *ruh = &endgrp->fdp.ruhs[ruhid_idx];

        if (nevents > 0) {
            NvmeFdpEventDescr edescr[6];
            uint32_t trans = MIN(nevents * sizeof(NvmeFdpEventDescr),
                                 sizeof(edescr));
            uint16_t status = dma_write_prp(n, (uint8_t *)edescr, trans,
                                             prp1, prp2);
            if (status) {
                return status;
            }
            for (int i = 0; i < (int)MIN(nevents, 6); i++) {
                uint8_t ev = edescr[i].evt;
                if (ev < FDP_EVT_MAX) {
                    if (enable) {
                        ruh->event_filter |=
                            (1ULL << nvme_fdp_evf_shifts[ev]);
                    } else {
                        ruh->event_filter &=
                            ~(1ULL << nvme_fdp_evf_shifts[ev]);
                    }
                }
            }
        }
        break;
    }
    default:
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    return NVME_SUCCESS;
}

static uint16_t nvme_fw_log_info(FemuCtrl *n, NvmeCmd *cmd, uint32_t buf_len,
                                 uint64_t off)
{
    uint32_t trans_len;
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);
    NvmeFwSlotInfoLog fw_log = {0};

    if (off >= sizeof(fw_log)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    /* one firmware slot, active, carrying the revision Identify reports */
    fw_log.afi = 0x1;
    memcpy(fw_log.frs1, n->id_ctrl.fr, MIN(sizeof(fw_log.frs1),
                                          sizeof(n->id_ctrl.fr)));
    trans_len = MIN(sizeof(fw_log) - off, buf_len);

    return dma_read_prp(n, (uint8_t *)&fw_log + off, trans_len, prp1, prp2);
}

static uint16_t nvme_error_log_info(FemuCtrl *n, NvmeCmd *cmd, uint32_t buf_len,
                                    uint64_t off)
{
    uint32_t trans_len;
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);
    uint64_t log_len = sizeof(*n->elpes) * (n->elpe + 1);

    /*
     * The offset in Get Log Page is how a host reads a page in pieces, and this
     * one ignored it: every chunk came back as the first. The other pages apply
     * it; these two were missed.
     */
    if (off >= log_len) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    trans_len = MIN(log_len - off, buf_len);
    n->aer_mask &= ~(1 << NVME_AER_TYPE_ERROR);

    return dma_read_prp(n, (uint8_t *)n->elpes + off, trans_len, prp1, prp2);
}

/*
 * Supported Log Pages (00h): one 32 bit LID Supported and Effects structure
 * per log page identifier, with bit 0 set for each identifier this controller
 * answers. NVMe Base 2.3 lists the page as mandatory, and it is how a host
 * finds the vendor page without being told about it out of band.
 *
 * A page is reported as supported only where it would really answer: the
 * endurance group and placement pages need a subsystem, and the changed zone
 * list needs a zoned namespace.
 */
static uint16_t nvme_supported_log_pages(FemuCtrl *n, NvmeCmd *cmd,
                                         uint32_t buf_len, uint64_t off)
{
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);
    uint32_t lids[256] = {};
    uint32_t trans_len;
    bool zoned = false;
    int i;

    QEMU_BUILD_BUG_ON(sizeof(lids) != 1024);

    if (off >= sizeof(lids)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    lids[NVME_LOG_SUPPORTED]    = cpu_to_le32(NVME_LIDS_LSUPP);
    lids[NVME_LOG_ERROR_INFO]   = cpu_to_le32(NVME_LIDS_LSUPP);
    lids[NVME_LOG_SMART_INFO]   = cpu_to_le32(NVME_LIDS_LSUPP);
    lids[NVME_LOG_FW_SLOT_INFO] = cpu_to_le32(NVME_LIDS_LSUPP);
    lids[NVME_LOG_CMD_EFFECTS]  = cpu_to_le32(NVME_LIDS_LSUPP);
    lids[NVME_LOG_FEMU_STATS]   = cpu_to_le32(NVME_LIDS_LSUPP);

    if (n->subsys) {
        lids[NVME_LOG_ENDGRP]        = cpu_to_le32(NVME_LIDS_LSUPP);
        lids[NVME_LOG_FDP_CONFS]     = cpu_to_le32(NVME_LIDS_LSUPP);
        lids[NVME_LOG_FDP_RUH_USAGE] = cpu_to_le32(NVME_LIDS_LSUPP);
        lids[NVME_LOG_FDP_STATS]     = cpu_to_le32(NVME_LIDS_LSUPP);
        lids[NVME_LOG_FDP_EVENTS]    = cpu_to_le32(NVME_LIDS_LSUPP);
    }

    for (i = 0; n->namespaces && i < n->num_namespaces; i++) {
        if (NS_ZNSSD(&n->namespaces[i])) {
            zoned = true;
            break;
        }
    }
    if (zoned) {
        lids[NVME_LOG_CHANGED_ZONE_LIST] = cpu_to_le32(NVME_LIDS_LSUPP);
    }

    trans_len = MIN(sizeof(lids) - off, buf_len);

    return dma_read_prp(n, (uint8_t *)lids + off, trans_len, prp1, prp2);
}

/*
 * Host and media totals, as the SMART log, the vendor counter page and the
 * endurance group log all report them. Host figures come from the per-poller
 * shards the I/O path keeps; media figures from the namespaces that have an
 * FTL, since this is device-wide.
 */
typedef struct FemuMediaStats {
    uint64_t rd_bytes, wr_bytes, rd_cmds, wr_cmds;
    uint64_t host_pages, gc_pages, nand_pages;
    uint64_t max_block_reads, read_reclaims, retention_refreshes;
    uint64_t buf_reads, buf_read_hits, buf_writes, buf_write_hits;
    uint64_t media_errors;      /* summed over every namespace */
    uint64_t media_bytes;       /* host and relocated writes, in bytes */
    uint8_t  available_spare;   /* worst namespace */
    uint8_t  percentage_used;   /* most worn namespace */
} FemuMediaStats;

static void nvme_collect_media_stats(FemuCtrl *n, FemuMediaStats *st)
{
    uint32_t p;
    int i;

    memset(st, 0, sizeof(*st));
    st->available_spare = 100;

    for (p = 1; n->poller_ctr && p <= n->nr_pollers; p++) {
        st->rd_cmds  += n->poller_ctr[p].nr_host_rd_cmds;
        st->wr_cmds  += n->poller_ctr[p].nr_host_wr_cmds;
        st->rd_bytes += n->poller_ctr[p].nr_host_rd_bytes;
        st->wr_bytes += n->poller_ctr[p].nr_host_wr_bytes;
    }

    for (i = 0; n->namespaces && i < n->num_namespaces; i++) {
        NvmeNamespace *ns = &n->namespaces[i];
        uint8_t spare, used;

        st->media_errors += zns_media_errors(ns);

        if (!ns->ssd) {
            continue;
        }
        st->media_errors += ssd_media_errors(ns->ssd);
        spare = ssd_available_spare(ns->ssd);
        if (spare < st->available_spare) {
            st->available_spare = spare;
        }
        used = ssd_percentage_used(ns->ssd);
        if (used > st->percentage_used) {
            st->percentage_used = used;
        }

        if (!(NS_BBSSD(ns) || NS_CSD(ns) || NS_KVSSD(ns))) {
            continue;
        }
        st->host_pages += ssd_host_write_pages(ns->ssd);
        st->gc_pages   += ssd_gc_write_pages(ns->ssd);
        st->nand_pages += ssd_nand_write_pages(ns->ssd);
        st->media_bytes += (ssd_nand_write_pages(ns->ssd) +
                            ssd_gc_write_pages(ns->ssd)) *
                           (uint64_t)ssd_page_size(ns->ssd);
        if (ssd_max_block_reads(ns->ssd) > st->max_block_reads) {
            st->max_block_reads = ssd_max_block_reads(ns->ssd);
        }
        st->read_reclaims += ssd_read_reclaims(ns->ssd);
        st->retention_refreshes += ssd_retention_refreshes(ns->ssd);
        st->buf_reads += ssd_buffer_reads(ns->ssd);
        st->buf_read_hits += ssd_buffer_read_hits(ns->ssd);
        st->buf_writes += ssd_buffer_writes(ns->ssd);
        st->buf_write_hits += ssd_buffer_write_hits(ns->ssd);
    }
}

/*
 * Vendor-specific log page C0h: the emulator's media counters. Read it with
 *   nvme get-log /dev/nvme0 --log-id=0xc0 --log-len=512 -b
 * and the fields sit at the offsets FemuStatsLog declares.
 */
static uint16_t nvme_femu_stats_info(FemuCtrl *n, NvmeCmd *cmd,
                                     uint32_t buf_len, uint64_t off)
{
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);
    FemuMediaStats st;
    FemuStatsLog stats;
    uint32_t trans_len;

    if (off >= sizeof(stats)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    trans_len = MIN(sizeof(stats) - off, buf_len);
    memset(&stats, 0x0, sizeof(stats));
    nvme_collect_media_stats(n, &st);

    /*
     * Amplification needs a host write to divide by; the rest are counts and
     * are reported whether or not anything has been written, so a read-only
     * workload can still read its block read counts back.
     */
    if (st.host_pages) {
        stats.waf_x1000 = cpu_to_le32((uint32_t)
            (((st.nand_pages + st.gc_pages) * 1000ull) / st.host_pages));
    }
    stats.host_write_pages = cpu_to_le64(st.host_pages);
    stats.gc_write_pages = cpu_to_le64(st.gc_pages);
    stats.nand_write_pages = cpu_to_le64(st.nand_pages);
    stats.max_block_reads = cpu_to_le64(st.max_block_reads);
    stats.read_reclaims = cpu_to_le64(st.read_reclaims);
    stats.retention_refreshes = cpu_to_le64(st.retention_refreshes);
    stats.buffer_reads = cpu_to_le64(st.buf_reads);
    stats.buffer_read_hits = cpu_to_le64(st.buf_read_hits);
    stats.buffer_writes = cpu_to_le64(st.buf_writes);
    stats.buffer_write_hits = cpu_to_le64(st.buf_write_hits);

    return dma_read_prp(n, (uint8_t *)&stats + off, trans_len, prp1, prp2);
}

static uint16_t nvme_smart_info(FemuCtrl *n, NvmeCmd *cmd, uint32_t buf_len,
                                uint64_t off, bool rae)
{
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);

    uint32_t trans_len;
    time_t current_seconds;
    FemuMediaStats st;
    NvmeSmartLog smart;

    /*
     * A host may read a log page in pieces, from the offset in the command.
     * Both of these used to hand back the start of the page whatever was
     * asked for, so a second read returned the first bytes again.
     */
    if (off >= sizeof(smart)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    trans_len = MIN(sizeof(smart) - off, buf_len);
    memset(&smart, 0x0, sizeof(smart));
    nvme_collect_media_stats(n, &st);

    /*
     * The log reports data units in thousands of 512 byte units, rounded up,
     * so a workload that moved anything at all reports at least one unit
     * rather than the zero these fields used to carry.
     */
    smart.data_units_read[0] =
        cpu_to_le64(DIV_ROUND_UP(st.rd_bytes / 512, 1000));
    smart.data_units_written[0] =
        cpu_to_le64(DIV_ROUND_UP(st.wr_bytes / 512, 1000));
    smart.host_read_commands[0] = cpu_to_le64(st.rd_cmds);
    smart.host_write_commands[0] = cpu_to_le64(st.wr_cmds);

    smart.number_of_error_log_entries[0] = cpu_to_le64(n->num_errors);
    smart.media_errors[0] = cpu_to_le64(st.media_errors);
    smart.temperature[0] = n->temperature & 0xff;
    smart.temperature[1] = (n->temperature >> 8) & 0xff;

    /* both are controller-wide, so the worst namespace speaks for the device */
    smart.available_spare = st.available_spare;
    smart.percentage_used = st.percentage_used;

    /*
     * Reading this log without Retain Asynchronous Event is what clears a
     * SMART event: the host has now seen the state the event was pointing at.
     */
    if (!rae) {
        nvme_clear_events(n, NVME_AER_TYPE_SMART);
    }

    current_seconds = time(NULL);
    smart.power_on_hours[0] = cpu_to_le64(
        ((current_seconds - n->start_time) / 60) / 60);

    smart.available_spare_threshold = NVME_SPARE_THRESHOLD;
    if (smart.available_spare <= NVME_SPARE_THRESHOLD) {
        smart.critical_warning |= NVME_SMART_SPARE;
    }
    if (n->features.temp_thresh <= n->temperature) {
        smart.critical_warning |= NVME_SMART_TEMPERATURE;
    }

    n->aer_mask &= ~(1 << NVME_AER_TYPE_SMART);

    return dma_read_prp(n, (uint8_t *)&smart + off, trans_len, prp1, prp2);
}

/* ========== FDP Log Pages ========== */

static size_t sizeof_fdp_conf_descr(size_t nruh, size_t vss)
{
    size_t entry_siz = sizeof(NvmeFdpDescrHdr) + nruh * sizeof(NvmeRuhDescr)
                       + vss;
    return ROUND_UP(entry_siz, 8);
}

static uint16_t nvme_endgrp_info(FemuCtrl *n, uint32_t buf_len,
                                 uint64_t off, NvmeCmd *cmd)
{
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);
    uint32_t dw11 = le32_to_cpu(cmd->cdw11);
    uint16_t endgrpid = (dw11 >> 16) & 0xffff;
    NvmeEndGrpLog info = {};
    FemuMediaStats st;

    if (!n->subsys || endgrpid != 0x1) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (off >= sizeof(info)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    /*
     * One endurance group covers the whole device here, so it reports the
     * same totals the SMART log does. The page used to come back as zeroes.
     * Media units written is what actually reached the flash, relocations
     * included, which is the difference this log is for.
     */
    nvme_collect_media_stats(n, &st);
    info.avail_spare = st.available_spare;
    info.avail_spare_thres = NVME_SPARE_THRESHOLD;
    info.percet_used = st.percentage_used;
    if (st.available_spare <= NVME_SPARE_THRESHOLD) {
        info.critical_warning |= NVME_SMART_SPARE;
    }
    /*
     * This log counts bytes in billions, rounded up -- not the thousands of
     * 512 byte units the SMART log uses. Media units written covers what the
     * device actually programmed, relocations included.
     */
    info.data_units_read[0] =
        cpu_to_le64(DIV_ROUND_UP(st.rd_bytes, 1000000000));
    info.data_units_written[0] =
        cpu_to_le64(DIV_ROUND_UP(st.wr_bytes, 1000000000));
    info.media_units_written[0] =
        cpu_to_le64(DIV_ROUND_UP(st.media_bytes, 1000000000));
    info.host_read_commands[0] = cpu_to_le64(st.rd_cmds);
    info.host_write_commands[0] = cpu_to_le64(st.wr_cmds);
    info.media_integrity_errors[0] = cpu_to_le64(st.media_errors);
    info.no_err_info_log_entries[0] = cpu_to_le64(n->num_errors);

    buf_len = MIN(sizeof(info) - off, buf_len);
    return dma_read_prp(n, (uint8_t *)&info + off, buf_len, prp1, prp2);
}

static uint16_t nvme_fdp_confs(FemuCtrl *n, uint32_t endgrpid,
                               uint32_t buf_len, uint64_t off, NvmeCmd *cmd)
{
    uint32_t log_size, trans_len;
    g_autofree uint8_t *buf = NULL;
    NvmeFdpDescrHdr *hdr;
    NvmeRuhDescr *ruhd;
    NvmeEnduranceGroup *endgrp;
    NvmeFdpConfsHdr *log;
    size_t nruh, fdp_descr_size;
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);
    int i;

    if (endgrpid != 1 || !n->subsys) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    endgrp = &n->subsys->endgrp;

    if (endgrp->fdp.enabled) {
        nruh = endgrp->fdp.nruh;
    } else {
        nruh = 1;
    }

    fdp_descr_size = sizeof_fdp_conf_descr(nruh, FDPVSS);
    log_size = sizeof(NvmeFdpConfsHdr) + fdp_descr_size;

    if (off >= log_size) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    trans_len = MIN(log_size - off, buf_len);

    buf = g_malloc0(log_size);
    log = (NvmeFdpConfsHdr *)buf;
    hdr = (NvmeFdpDescrHdr *)(log + 1);
    ruhd = (NvmeRuhDescr *)(buf + sizeof(*log) + sizeof(*hdr));

    log->num_confs = cpu_to_le16(0);
    log->size = cpu_to_le32(log_size);

    hdr->descr_size = cpu_to_le16(fdp_descr_size);
    if (endgrp->fdp.enabled) {
        hdr->fdpa = FIELD_DP8(hdr->fdpa, FDPA, VALID, 1);
        hdr->fdpa = FIELD_DP8(hdr->fdpa, FDPA, RGIF, endgrp->fdp.rgif);
        hdr->nrg = cpu_to_le16(endgrp->fdp.nrg);
        hdr->nruh = cpu_to_le16(endgrp->fdp.nruh);
        hdr->maxpids = cpu_to_le16(NVME_FDP_MAXPIDS - 1);
        hdr->nnss = cpu_to_le32(NVME_MAX_NAMESPACES);
        hdr->runs = cpu_to_le64(endgrp->fdp.runs);

        for (i = 0; i < (int)nruh; i++) {
            ruhd->ruht = endgrp->fdp.ruhs[i].ruht;
            ruhd++;
        }
    } else {
        hdr->nrg = cpu_to_le16(1);
        hdr->nruh = cpu_to_le16(1);
        hdr->maxpids = cpu_to_le16(NVME_FDP_MAXPIDS - 1);
        hdr->nnss = cpu_to_le32(1);
        hdr->runs = cpu_to_le64(96 * MiB);
        ruhd->ruht = NVME_RUHT_INITIALLY_ISOLATED;
    }

    return dma_read_prp(n, (uint8_t *)buf + off, trans_len, prp1, prp2);
}

static uint16_t nvme_fdp_ruh_usage(FemuCtrl *n, uint32_t endgrpid,
                                   uint32_t buf_len, uint64_t off,
                                   NvmeCmd *cmd)
{
    NvmeRuHandle *ruh;
    NvmeRuhuLog *hdr;
    NvmeRuhuDescr *ruhud;
    NvmeEnduranceGroup *endgrp;
    g_autofree uint8_t *buf = NULL;
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);
    uint32_t log_size, trans_len;
    uint16_t i;

    if (endgrpid != 1 || !n->subsys) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    endgrp = &n->subsys->endgrp;

    if (!endgrp->fdp.enabled) {
        return NVME_FDP_DISABLED | NVME_DNR;
    }

    log_size = sizeof(NvmeRuhuLog) + endgrp->fdp.nruh * sizeof(NvmeRuhuDescr);

    if (off >= log_size) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    trans_len = MIN(log_size - off, buf_len);

    buf = g_malloc0(log_size);
    hdr = (NvmeRuhuLog *)buf;
    ruhud = (NvmeRuhuDescr *)(hdr + 1);

    ruh = endgrp->fdp.ruhs;
    hdr->nruh = cpu_to_le16(endgrp->fdp.nruh);

    for (i = 0; i < endgrp->fdp.nruh; i++, ruhud++, ruh++) {
        ruhud->ruha = ruh->ruha;
        ruhud->hbmw = ruh->hbmw;
        ruhud->mbmw = ruh->mbmw;
    }

    return dma_read_prp(n, (uint8_t *)buf + off, trans_len, prp1, prp2);
}

static uint16_t nvme_fdp_stats(FemuCtrl *n, uint32_t endgrpid,
                               uint32_t buf_len, uint64_t off, NvmeCmd *cmd)
{
    NvmeEnduranceGroup *endgrp;
    NvmeFdpStatsLog log = {};
    uint32_t trans_len;
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);

    if (off >= sizeof(NvmeFdpStatsLog)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (endgrpid != 1 || !n->subsys) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (!n->subsys->endgrp.fdp.enabled) {
        return NVME_FDP_DISABLED | NVME_DNR;
    }

    endgrp = &n->subsys->endgrp;
    trans_len = MIN(sizeof(log) - off, buf_len);

    /* spec value is 128 bit, we only use low 64 bit */
    log.hbmw[0] = cpu_to_le64(endgrp->fdp.hbmw);
    log.mbmw[0] = cpu_to_le64(endgrp->fdp.mbmw);
    log.mbe[0] = cpu_to_le64(endgrp->fdp.mbe);

    return dma_read_prp(n, (uint8_t *)&log + off, trans_len, prp1, prp2);
}

static uint16_t nvme_fdp_events(FemuCtrl *n, uint32_t endgrpid,
                                uint32_t buf_len, uint64_t off, NvmeCmd *cmd)
{
    NvmeEnduranceGroup *endgrp;
    bool host_events = (le32_to_cpu(cmd->cdw10) >> 8) & 0x1;
    uint32_t log_size, trans_len;
    unsigned int nelems, start, next;
    NvmeFdpEventBuffer *ebuf;
    g_autofree NvmeFdpEventsLog *elog = NULL;
    NvmeFdpEvent *event;
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);

    if (endgrpid != 1 || !n->subsys) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    endgrp = &n->subsys->endgrp;

    if (!endgrp->fdp.enabled) {
        return NVME_FDP_DISABLED | NVME_DNR;
    }

    if (host_events) {
        ebuf = &endgrp->fdp.host_events;
    } else {
        ebuf = &endgrp->fdp.ctrl_events;
    }

    /*
     * Take the ring's three indices once. Events are appended by a poller
     * thread and by the FTL thread, so reading nelems to size the buffer and
     * then reading start and next again to size the copy let an append that
     * landed in between drive the copy past the allocation.
     */
    nelems = ebuf->nelems;
    start = ebuf->start;
    next = ebuf->next;
    if (nelems > NVME_FDP_MAX_EVENTS) {
        nelems = NVME_FDP_MAX_EVENTS;
    }
    if (start >= NVME_FDP_MAX_EVENTS || next > NVME_FDP_MAX_EVENTS) {
        return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }

    log_size = sizeof(NvmeFdpEventsLog) + nelems * sizeof(NvmeFdpEvent);
    if (off >= log_size) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    trans_len = MIN(log_size - off, buf_len);
    elog = g_malloc0(log_size);
    elog->num_events = cpu_to_le32(nelems);
    event = (NvmeFdpEvent *)(elog + 1);

    /* every copy below is bounded by the nelems the buffer was sized for */
    if (nelems && start == next) {
        unsigned int first = MIN(NVME_FDP_MAX_EVENTS - start, nelems);

        memcpy(event, &ebuf->events[start], sizeof(NvmeFdpEvent) * first);
        if (nelems > first) {
            memcpy(event + first, ebuf->events,
                   sizeof(NvmeFdpEvent) * (nelems - first));
        }
    } else if (start < next) {
        unsigned int cnt = MIN(next - start, nelems);

        memcpy(event, &ebuf->events[start], sizeof(NvmeFdpEvent) * cnt);
    }

    return dma_read_prp(n, (uint8_t *)elog + off, trans_len, prp1, prp2);
}

/* ========== End FDP Log Pages ========== */

static uint16_t nvme_cmd_effects(FemuCtrl *n, NvmeCmd *cmd, uint8_t csi,
                                 uint32_t buf_len, uint64_t off)
{
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);
    NvmeEffectsLog log = {};
    const uint32_t *src_iocs = NULL;
    uint32_t trans_len;

    if (off >= sizeof(log)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    switch (NVME_CC_CSS(n->bar.cc)) {
    case NVME_CC_CSS_NVM:
        src_iocs = nvme_cse_iocs_nvm;
    case NVME_CC_CSS_ADMIN_ONLY:
        break;
    case NVME_CC_CSS_CSI:
        switch (csi) {
        case NVME_CSI_NVM:
            src_iocs = nvme_cse_iocs_nvm;
            break;
        case NVME_CSI_ZONED:
            src_iocs = nvme_cse_iocs_zoned;
            break;
        }
    }

    memcpy(log.acs, nvme_cse_acs, sizeof(nvme_cse_acs));
    /* the optional commands are reported as OACS and ONCS actually offer them */
    if (n->oacs & NVME_OACS_FORMAT) {
        log.acs[NVME_ADM_CMD_FORMAT_NVM] = NVME_CMD_EFF_CSUPP |
                                           NVME_CMD_EFF_LBCC | NVME_CMD_EFF_NCC;
    }
    log.acs[NVME_ADM_CMD_SET_DB_MEMORY] = NVME_CMD_EFF_CSUPP;

    if (src_iocs) {
        memcpy(log.iocs, src_iocs, sizeof(log.iocs));
        if (!(n->oncs & NVME_ONCS_COMPARE)) {
            log.iocs[NVME_CMD_COMPARE] = 0;
        }
        if (!(n->oncs & NVME_ONCS_WRITE_ZEROS)) {
            log.iocs[NVME_CMD_WRITE_ZEROES] = 0;
        }
        if (!(n->oncs & NVME_ONCS_DSM)) {
            log.iocs[NVME_CMD_DSM] = 0;
        }
    }

    trans_len = MIN(sizeof(log) - off, buf_len);

    return dma_read_prp(n, ((uint8_t *)&log) + off, trans_len, prp1, prp2);
}

static uint16_t nvme_get_log(FemuCtrl *n, NvmeCmd *cmd)
{
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint32_t dw11 = le32_to_cpu(cmd->cdw11);
    uint32_t dw12 = le32_to_cpu(cmd->cdw12);
    uint32_t dw13 = le32_to_cpu(cmd->cdw13);
    /*
     * Command Dword 10 packs more than the identifier: bits 7:0 are the Log
     * Page Identifier, 13:8 the Log Specific Field, and bit 15 Retain
     * Asynchronous Event. Masking the whole low half made a host that set
     * Retain Asynchronous Event -- the ordinary way to read a log without
     * clearing the event behind it -- miss every identifier below and be told
     * the log page was invalid.
     */
    uint8_t lid = dw10 & 0xff;
    bool rae = (dw10 >> 15) & 0x1;   /* Retain Asynchronous Event */
    uint8_t  csi = le32_to_cpu(cmd->cdw14) >> 24;
    uint16_t lspi = (dw11 >> 16) & 0xffff;
    uint32_t len;
    uint64_t off, lpol, lpou;
    uint32_t numdl, numdu;
    int status;

    numdl = (dw10 >> 16);
    numdu = (dw11 & 0xffff);
    lpol = dw12;
    lpou = dw13;

    len = (((numdu << 16) | numdl) + 1) << 2;
    off = (lpou << 32ULL) | lpol;

    if (off & 0x3) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    status = nvme_check_mdts(n, len);
    if (status) {
        return status;
    }

    switch (lid) {
    case NVME_LOG_SUPPORTED:
        return nvme_supported_log_pages(n, cmd, len, off);
    case NVME_LOG_ERROR_INFO:
        return nvme_error_log_info(n, cmd, len, off);
    case NVME_LOG_SMART_INFO:
        return nvme_smart_info(n, cmd, len, off, rae);
    case NVME_LOG_FEMU_STATS:
        return nvme_femu_stats_info(n, cmd, len, off);
    case NVME_LOG_FW_SLOT_INFO:
        return nvme_fw_log_info(n, cmd, len, off);
    case NVME_LOG_CMD_EFFECTS:
        return nvme_cmd_effects(n, cmd, csi, len, off);
    case NVME_LOG_ENDGRP:
        return nvme_endgrp_info(n, len, off, cmd);
    case NVME_LOG_FDP_CONFS:
        return nvme_fdp_confs(n, lspi, len, off, cmd);
    case NVME_LOG_FDP_RUH_USAGE:
        return nvme_fdp_ruh_usage(n, lspi, len, off, cmd);
    case NVME_LOG_FDP_STATS:
        return nvme_fdp_stats(n, lspi, len, off, cmd);
    case NVME_LOG_FDP_EVENTS:
        return nvme_fdp_events(n, lspi, len, off, cmd);
    default: {
        /*
         * A namespace-specific log page belongs to the mode that namespace
         * runs, which is not necessarily the controller's once namespaces run
         * different modes. Offer the command to the named namespace's handler
         * first, then fall back to the controller's for controller-wide logs.
         */
        uint32_t nsid = le32_to_cpu(cmd->nsid);

        if (nsid && nsid != NVME_NSID_BROADCAST && nsid <= n->num_namespaces) {
            NvmeNamespace *ns = &n->namespaces[nsid - 1];

            if (ns->ext_ops.get_log) {
                return ns->ext_ops.get_log(n, cmd);
            }
        }
        if (n->ext_ops.get_log) {
            return n->ext_ops.get_log(n, cmd);
        }
        return NVME_INVALID_LOG_ID | NVME_DNR;
    }
    }
}

static uint16_t nvme_abort_req(FemuCtrl *n, NvmeCmd *cmd, uint32_t *result)
{
    uint32_t index = 0;
    uint16_t sqid = cmd->cdw10 & 0xffff;
    uint16_t cid = (cmd->cdw10 >> 16) & 0xffff;
    NvmeSQueue *sq;

    *result = 1;
    if (nvme_check_sqid(n, sqid)) {
        return NVME_SUCCESS;
    }

    sq = n->sq[sqid];

    /*
     * Step at most once round the ring: the modulo index below only ever takes
     * values inside it, so a tail outside it would never be reached and this
     * runs on the thread holding the big lock.
     */
    while (index < sq->size && (sq->head + index) % sq->size != sq->tail) {
        NvmeCmd abort_cmd;
        hwaddr addr;

        if (sq->phys_contig) {
            addr = sq->dma_addr + ((sq->head + index) % sq->size) *
                n->sqe_size;
        } else {
            addr = nvme_discontig(sq->prp_list, (sq->head + index) % sq->size,
                n->page_size, n->sqe_size);
        }
        nvme_addr_read(n, addr, (void *)&abort_cmd, sizeof(abort_cmd));
        if (abort_cmd.cid == cid) {
            /*
             * Mark the entry; the poller completes it as aborted when it
             * reaches it, with a request taken from the free list then.
             */
            *result = 0;
            abort_cmd.opcode = NVME_OP_ABORTED;
            nvme_addr_write(n, addr, (void *)&abort_cmd,
                sizeof(abort_cmd));

            return NVME_SUCCESS;
        }

        ++index;
    }

    return NVME_SUCCESS;
}

/*
 * A format changes how many logical blocks the namespace has, so everything
 * sized in blocks has to be rebuilt: the per-block bitmaps are indexed by LBA
 * on every read and write, and a format from a large block size to a small one
 * used to leave them sized for the smaller count, which the next write walked
 * past.
 */
static uint16_t nvme_format_resize(NvmeNamespace *ns, uint64_t blks)
{
    unsigned long *util, *uncorrectable;

    util = bitmap_new(blks);
    uncorrectable = bitmap_new(blks);
    if (!util || !uncorrectable) {
        g_free(util);
        g_free(uncorrectable);
        return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }

    g_free(ns->util);
    g_free(ns->uncorrectable);
    ns->util = util;
    ns->uncorrectable = uncorrectable;

    return NVME_SUCCESS;
}

/*
 * Whether this namespace can be formatted as asked, decided without changing
 * anything. Every namespace a command names is put through this before any of
 * them is touched, so a refusal cannot leave some already reformatted.
 */
static uint16_t nvme_format_check(NvmeNamespace *ns, uint8_t lba_idx,
                                  uint8_t meta_loc, uint8_t pil, uint8_t pi)
{
    uint16_t ms;

    /*
     * A format redefines the namespace in terms of logical blocks, which only
     * a plain block namespace is described by. Every other mode derives its
     * capacity from a geometry of its own -- zones, key space, or the physical
     * addresses an open-channel host manages itself -- and reformatting it
     * would leave the two disagreeing, or hand the host a size its own address
     * space does not have.
     */
    if (!NS_BBSSD(ns) && !NS_NOSSD(ns)) {
        return NVME_INVALID_FORMAT | NVME_DNR;
    }

    if (lba_idx > ns->id_ns.nlbaf) {
        return NVME_INVALID_FORMAT | NVME_DNR;
    }

    ms = le16_to_cpu(ns->id_ns.lbaf[lba_idx].ms);
    if (pi) {
        if (pil && !NVME_ID_NS_DPC_LAST_EIGHT(ns->id_ns.dpc)) {
            return NVME_INVALID_FORMAT | NVME_DNR;
        }
        if (!pil && !NVME_ID_NS_DPC_FIRST_EIGHT(ns->id_ns.dpc)) {
            return NVME_INVALID_FORMAT | NVME_DNR;
        }
        if (!((ns->id_ns.dpc & 0x7) & (1 << (pi - 1)))) {
            return NVME_INVALID_FORMAT | NVME_DNR;
        }
    }
    if (meta_loc && ms && !NVME_ID_NS_MC_EXTENDED(ns->id_ns.mc)) {
        return NVME_INVALID_FORMAT | NVME_DNR;
    }
    if (!meta_loc && ms && !NVME_ID_NS_MC_SEPARATE(ns->id_ns.mc)) {
        return NVME_INVALID_FORMAT | NVME_DNR;
    }

    return NVME_SUCCESS;
}

static uint16_t nvme_format_namespace(NvmeNamespace *ns, uint8_t lba_idx,
                                      uint8_t meta_loc, uint8_t pil, uint8_t pi,
                                      uint8_t sec_erase)
{
    NvmeIdNs *id_ns = &ns->id_ns;
    FemuCtrl *n = ns->ctrl;
    uint64_t blks;
    uint16_t status;

    blks = ns->size / (1 << id_ns->lbaf[lba_idx].lbads);
    status = nvme_format_resize(ns, blks);
    if (status != NVME_SUCCESS) {
        return status;
    }

    /*
     * The block count and the state sized to it are changed together. Nothing
     * observes them half-updated because the caller holds the pollers off for
     * the whole of this; without that, a shrinking format would expose a window
     * where the host still reads the old count against the new bitmaps.
     */
    id_ns->nuse = id_ns->ncap = id_ns->nsze = cpu_to_le64(blks);
    ns->id_ns.flbas = lba_idx | meta_loc;
    ns->id_ns.dps = pil | pi;
    /* the copy Flexible Data Placement derives its unit sizes from */
    ns->lbaf = id_ns->lbaf[lba_idx];
    ns->ns_blks = ns_blks(ns, lba_idx);
    nvme_ns_refresh_fdp(ns);

    /*
     * A format ends the life of the data whatever the erase settings say, so
     * a read of any block must not return what was written before it. The
     * bitmaps above are already clear, which makes every block deallocated;
     * clear the backing store with them so a controller with the
     * deallocated-block error disabled reads zeros rather than stale data.
     */
    if (n->mbe && n->mbe->logical_space) {
        memset((uint8_t *)n->mbe->logical_space + ns->backend_offset, 0,
               ns->size);
    }

    return NVME_SUCCESS;
}

static uint16_t nvme_format(FemuCtrl *n, NvmeCmd *cmd)
{
    NvmeNamespace *ns;
    uint16_t status;
    bool resume;
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint32_t nsid = le32_to_cpu(cmd->nsid);

    uint8_t lba_idx = dw10 & 0xf;
    uint8_t meta_loc = dw10 & 0x10;
    uint8_t pil = (dw10 >> 5) & 0x8;
    uint8_t pi = (dw10 >> 5) & 0x7;
    uint8_t sec_erase = (dw10 >> 8) & 0x7;

    if (nsid != 0xffffffff && (nsid == 0 || nsid > n->num_namespaces)) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    /*
     * Decide on every namespace before touching any of them. This used to
     * format each in turn and return on the first refusal, so a controller
     * mixing command sets could lose the data of the namespaces already done
     * and still report that the command failed.
     */
    if (nsid == 0xffffffff) {
        for (uint32_t i = 0; i < n->num_namespaces; ++i) {
            status = nvme_format_check(&n->namespaces[i], lba_idx, meta_loc,
                                       pil, pi);
            if (status != NVME_SUCCESS) {
                return status;
            }
        }
    } else {
        status = nvme_format_check(&n->namespaces[nsid - 1], lba_idx, meta_loc,
                                   pil, pi);
        if (status != NVME_SUCCESS) {
            return status;
        }
    }

    /*
     * The bitmaps about to be replaced are indexed by every read and write, so
     * no poller may be inside a sweep while they are swapped and the backing
     * store is cleared.
     */
    resume = nvme_pause_pollers(n);

    if (nsid == 0xffffffff) {
        for (uint32_t i = 0; i < n->num_namespaces; ++i) {
            ns = &n->namespaces[i];
            status = nvme_format_namespace(ns, lba_idx, meta_loc, pil, pi,
                                           sec_erase);
            if (status != NVME_SUCCESS) {
                break;
            }
        }
    } else {
        ns = &n->namespaces[nsid - 1];
        status = nvme_format_namespace(ns, lba_idx, meta_loc, pil, pi,
                                       sec_erase);
    }

    nvme_resume_pollers(n, resume);

    return status;
}

static uint16_t nvme_admin_cmd(FemuCtrl *n, NvmeCmd *cmd, NvmeCqe *cqe)
{
    switch (cmd->opcode) {
    case NVME_ADM_CMD_FEMU_DEBUG:
        n->upg_rd_lat_ns = le64_to_cpu(cmd->cdw10);
        n->lpg_rd_lat_ns = le64_to_cpu(cmd->cdw11);
        n->upg_wr_lat_ns = le64_to_cpu(cmd->cdw12);
        n->lpg_wr_lat_ns = le64_to_cpu(cmd->cdw13);
        n->blk_er_lat_ns = le64_to_cpu(cmd->cdw14);
        n->chnl_pg_xfer_lat_ns = le64_to_cpu(cmd->cdw15);
        femu_log("tRu=%" PRId64 ", tRl=%" PRId64 ", tWu=%" PRId64 ", "
                "tWl=%" PRId64 ", tBERS=%" PRId64 ", tCHNL=%" PRId64 "\n",
                n->upg_rd_lat_ns, n->lpg_rd_lat_ns, n->upg_wr_lat_ns,
                n->lpg_wr_lat_ns, n->blk_er_lat_ns, n->chnl_pg_xfer_lat_ns);
        return NVME_SUCCESS;
    case NVME_ADM_CMD_DELETE_SQ:
        femu_debug("admin cmd,del_sq\n");
        return nvme_del_sq(n, cmd);
    case NVME_ADM_CMD_CREATE_SQ:
        femu_debug("admin cmd,create_sq\n");
        return nvme_create_sq(n, cmd);
    case NVME_ADM_CMD_DELETE_CQ:
        femu_debug("admin cmd,del_cq\n");
        return nvme_del_cq(n, cmd);
    case NVME_ADM_CMD_CREATE_CQ:
        femu_debug("admin cmd,create_cq\n");
        return nvme_create_cq(n, cmd);
    case NVME_ADM_CMD_IDENTIFY:
        femu_debug("admin cmd,identify\n");
        return nvme_identify(n, cmd);
    case NVME_ADM_CMD_SET_FEATURES:
        femu_debug("admin cmd,set_feature\n");
        return nvme_set_feature(n, cmd, cqe);
    case NVME_ADM_CMD_GET_FEATURES:
        femu_debug("admin cmd,get_feature\n");
        return nvme_get_feature(n, cmd, cqe);
    case NVME_ADM_CMD_GET_LOG_PAGE:
        femu_debug("admin cmd,get_log_page\n");
        return nvme_get_log(n, cmd);
    case NVME_ADM_CMD_ABORT:
        femu_debug("admin cmd,abort\n");
        return nvme_abort_req(n, cmd, &cqe->n.result);
    case NVME_ADM_CMD_FORMAT_NVM:
        femu_debug("admin cmd,format_nvm\n");
        if (NVME_OACS_FORMAT & n->oacs) {
            return nvme_format(n, cmd);
        }
        return NVME_INVALID_OPCODE | NVME_DNR;
    case NVME_ADM_CMD_SET_DB_MEMORY:
        femu_debug("admin cmd,set_db_memory\n");
        return nvme_set_db_memory(n, cmd);
    case NVME_ADM_CMD_ASYNC_EV_REQ:
        /*
         * Async Event Request: the controller holds it outstanding until an
         * async event occurs. FEMU generates no async events, so keep it
         * pending (never complete it) by returning NVME_NO_COMPLETE. This is
         * correct NVMe behaviour and stops drivers (e.g. SPDK) that post AERs
         * at init from getting INVALID_OPCODE and retrying in a tight loop
         * (which otherwise floods the controller and stalls the benchmark).
         */
        femu_debug("admin cmd,async_event_request (held pending)\n");
        if (n->outstanding_aers > n->aerl) {
            return NVME_AER_LIMIT_EXCEEDED;
        }
        return NVME_NO_COMPLETE;
    case NVME_ADM_CMD_ACTIVATE_FW:
    case NVME_ADM_CMD_DOWNLOAD_FW:
    case NVME_ADM_CMD_SECURITY_SEND:
    case NVME_ADM_CMD_SECURITY_RECV:
        return NVME_INVALID_OPCODE | NVME_DNR;
    default:
        if (n->ext_ops.admin_cmd_cqe) {
            return n->ext_ops.admin_cmd_cqe(n, cmd, cqe);
        }
        if (n->ext_ops.admin_cmd) {
            return n->ext_ops.admin_cmd(n, cmd);
        }

        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

/* an event is dropped rather than growing this queue without bound */
#define FEMU_AER_MAX_QUEUED 16

/* Post one admin completion for an entry the controller had been holding. */
static void nvme_post_held_cqe(FemuCtrl *n, const NvmeAerHold *hold,
                               const NvmeAerResult *result)
{
    NvmeCQueue *cq = n->cq[hold->cqid];
    NvmeCqe cqe;
    hwaddr addr;

    /*
     * is_active is not checked here: it marks a queue brought up by Create I/O
     * Completion Queue, and the admin queue an Async Event Request arrives on
     * is built at controller enable instead, so it never carries the flag.
     */
    if (!cq) {
        return;
    }

    memset(&cqe, 0, sizeof(cqe));
    memcpy(&cqe.n.result, result, sizeof(*result));
    cqe.cid = hold->cid;
    cqe.status = cpu_to_le16(NVME_SUCCESS << 1 | cq->phase);
    cqe.sq_id = cpu_to_le16(hold->sqid);
    cqe.sq_head = cpu_to_le16(hold->sq_head);

    if (cq->phys_contig) {
        addr = cq->dma_addr + cq->tail * n->cqe_size;
    } else {
        addr = nvme_discontig(cq->prp_list, cq->tail, n->page_size,
                              n->cqe_size);
    }
    nvme_addr_write(n, addr, (void *)&cqe, sizeof(cqe));
    nvme_inc_cq_tail(cq);
    nvme_isr_notify_admin(cq);
}

/*
 * Hand queued events to the Async Event Requests the host has outstanding.
 *
 * One event of a given type is reported at a time: posting sets that type in
 * aer_mask, and the mask is only cleared when the host reads the log page the
 * event pointed at. Until then further events of that type stay queued, so the
 * host is not told the same thing twice before it has looked.
 */
/*
 * Post queued events. Only ever called from the vCPU thread or from the
 * aer_bh bottom half, both of which hold the BQL, so outstanding_aers,
 * aer_mask and aer_held need no lock of their own. aer_lock covers just the
 * queue and its count, which a poller thread also appends to.
 */
void nvme_process_aers(FemuCtrl *n)
{
    for (;;) {
        NvmeAsyncEvent *event = NULL, *cand, *next;

        qemu_mutex_lock(&n->aer_lock);
        QSIMPLEQ_FOREACH_SAFE(cand, &n->aer_queue, entry, next) {
            if (!n->outstanding_aers) {
                break;          /* nothing to complete it with */
            }
            if (n->aer_mask & (1 << cand->result.event_type)) {
                continue;       /* already reported, awaiting the log read */
            }
            QSIMPLEQ_REMOVE(&n->aer_queue, cand, NvmeAsyncEvent, entry);
            n->aer_queued--;
            event = cand;
            break;
        }
        qemu_mutex_unlock(&n->aer_lock);

        if (!event) {
            return;
        }

        n->aer_mask |= 1 << event->result.event_type;
        n->outstanding_aers--;

        nvme_post_held_cqe(n, &n->aer_held[n->outstanding_aers],
                           &event->result);
        g_free(event);
    }
}

/* Raise an asynchronous event, reporting it as soon as an AER is available. */
void nvme_enqueue_event(FemuCtrl *n, uint8_t event_type, uint8_t event_info,
                        uint8_t log_page)
{
    NvmeAsyncEvent *event;

    event = g_new0(NvmeAsyncEvent, 1);
    event->result.event_type = event_type;
    event->result.event_info = event_info;
    event->result.log_page = log_page;

    qemu_mutex_lock(&n->aer_lock);
    if (n->aer_queued >= FEMU_AER_MAX_QUEUED) {
        qemu_mutex_unlock(&n->aer_lock);
        g_free(event);
        return;
    }
    QSIMPLEQ_INSERT_TAIL(&n->aer_queue, event, entry);
    n->aer_queued++;
    qemu_mutex_unlock(&n->aer_lock);

    /*
     * Posting happens in the bottom half. A zoned namespace raises events from
     * its I/O handler, which runs on a poller thread, and that thread must not
     * touch the admin completion queue the vCPU thread is serving.
     */
    qemu_bh_schedule(n->aer_bh);
}

/*
 * The host has read the log page an event pointed at, so that type may be
 * reported again. Drop any still-queued events of the type as well: the host
 * has just seen the state they describe.
 */
void nvme_clear_events(FemuCtrl *n, uint8_t event_type)
{
    NvmeAsyncEvent *event, *next;

    n->aer_mask &= ~(1 << event_type);

    /*
     * Every other place that touches the queue holds this, because a poller
     * can be appending to it: the zoned mode reports a zone taken read only
     * from there. Walking it unlocked can free an entry the bottom half is
     * about to post and leaves the count out of step with the list.
     */
    qemu_mutex_lock(&n->aer_lock);
    QSIMPLEQ_FOREACH_SAFE(event, &n->aer_queue, entry, next) {
        if (event->result.event_type == event_type) {
            QSIMPLEQ_REMOVE(&n->aer_queue, event, NvmeAsyncEvent, entry);
            n->aer_queued--;
            g_free(event);
        }
    }
    qemu_mutex_unlock(&n->aer_lock);
}

void nvme_process_sq_admin(void *opaque)
{
    NvmeSQueue *sq = opaque;
    FemuCtrl *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];

    uint16_t status;
    hwaddr addr;
    NvmeCmd cmd;
    NvmeCqe cqe;

    while (!(nvme_sq_empty(sq))) {
        if (sq->phys_contig) {
            addr = sq->dma_addr + sq->head * n->sqe_size;
        } else {
            addr = nvme_discontig(sq->prp_list, sq->head, n->page_size,
                    n->sqe_size);
        }
        nvme_addr_read(n, addr, (void *)&cmd, sizeof(cmd));
        nvme_inc_sq_head(sq);

        memset(&cqe, 0, sizeof(cqe));

        status = nvme_admin_cmd(n, &cmd, &cqe);
        if (status == NVME_NO_COMPLETE) {
            /*
             * Held pending: no completion now. An Async Event Request is
             * recorded here rather than in the handler because the entry it
             * will eventually be completed with is identified by the queue it
             * arrived on, which the handler does not see.
             */
            if (cmd.opcode == NVME_ADM_CMD_ASYNC_EV_REQ) {
                NvmeAerHold *hold = &n->aer_held[n->outstanding_aers++];

                hold->cid = cmd.cid;
                hold->sqid = sq->sqid;
                hold->cqid = sq->cqid;
                hold->sq_head = sq->head;
                if (!QSIMPLEQ_EMPTY(&n->aer_queue)) {
                    nvme_process_aers(n);
                }
            }
            continue;
        }
        cqe.cid = cmd.cid;
        cqe.status = cpu_to_le16(status << 1 | cq->phase);
        cqe.sq_id = cpu_to_le16(sq->sqid);
        cqe.sq_head = cpu_to_le16(sq->head);

        if (cq->phys_contig) {
            addr = cq->dma_addr + cq->tail * n->cqe_size;
        } else {
            addr = nvme_discontig(cq->prp_list, cq->tail, n->page_size, n->cqe_size);
        }
        nvme_addr_write(n, addr, (void *)&cqe, sizeof(cqe));
        nvme_inc_cq_tail(cq);
        nvme_isr_notify_admin(cq);
    }
}
