#include "./nvme.h"

#define NVME_IDENTIFY_DATA_SIZE 4096

#if 0
static const bool nvme_feature_support[NVME_FID_MAX] = {
    [NVME_ARBITRATION]              = true,
    [NVME_POWER_MANAGEMENT]         = true,
    [NVME_TEMPERATURE_THRESHOLD]    = true,
    [NVME_ERROR_RECOVERY]           = true,
    [NVME_VOLATILE_WRITE_CACHE]     = true,
    [NVME_NUMBER_OF_QUEUES]         = true,
    [NVME_INTERRUPT_COALESCING]     = true,
    [NVME_INTERRUPT_VECTOR_CONF]    = true,
    [NVME_WRITE_ATOMICITY]          = true,
    [NVME_ASYNCHRONOUS_EVENT_CONF]  = true,
    [NVME_TIMESTAMP]                = true,
};
#endif

#if 0
static const uint32_t nvme_feature_cap[NVME_FID_MAX] = {
    [NVME_TEMPERATURE_THRESHOLD]    = NVME_FEAT_CAP_CHANGE,
    [NVME_ERROR_RECOVERY]           = NVME_FEAT_CAP_CHANGE | NVME_FEAT_CAP_NS,
    [NVME_VOLATILE_WRITE_CACHE]     = NVME_FEAT_CAP_CHANGE,
    [NVME_NUMBER_OF_QUEUES]         = NVME_FEAT_CAP_CHANGE,
    [NVME_ASYNCHRONOUS_EVENT_CONF]  = NVME_FEAT_CAP_CHANGE,
    [NVME_TIMESTAMP]                = NVME_FEAT_CAP_CHANGE,
};
#endif

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

    if (!qid || nvme_check_sqid(n, qid)) {
        return NVME_INVALID_QID | NVME_DNR;
    }

    sq = n->sq[qid];
    assert(sq->is_active == true);
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

    nvme_free_sq(sq, n);
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
    if (!sqid || (sqid && !nvme_check_sqid(n, sqid))) {
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

    if (!cqid || (cqid && !nvme_check_cqid(n, cqid))) {
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
    if (!(NVME_CQ_FLAGS_PC(qflags)) && NVME_CAP_CQR(n->bar.cap)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (n->cq[cqid] != NULL) {
        nvme_free_cq(n->cq[cqid], n);
    }

    cq = g_malloc0(sizeof(*cq));
    assert(cq != NULL);
    if (nvme_init_cq(cq, n, prp1, cqid, vector, qsize + 1,
                     NVME_CQ_FLAGS_IEN(qflags), NVME_CQ_FLAGS_PC(qflags))) {
        g_free(cq);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

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

    if (!qid || nvme_check_cqid(n, qid)) {
        return NVME_INVALID_CQID | NVME_DNR;
    }

    cq = n->cq[qid];
    assert(cq->is_active == true);
    cq->is_active = false;
    if (!QTAILQ_EMPTY(&cq->sq_list)) {
        return NVME_INVALID_QUEUE_DEL;
    }

    nvme_free_cq(cq, n);

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

    n->nr_pollers = n->multipoller_enabled ? n->nr_io_queues : 1;
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
        qemu_thread_create(&n->poller[i], "femu-nvme-poller", nvme_poller,
                &args[i], QEMU_THREAD_JOINABLE);
        femu_debug("femu-nvme-poller [%d] created ...\n", i - 1);
    }
}

static uint16_t nvme_set_db_memory(FemuCtrl *n, const NvmeCmd *cmd)
{
    uint64_t dbs_addr = le64_to_cpu(cmd->dptr.prp1);
    uint64_t eis_addr = le64_to_cpu(cmd->dptr.prp2);
    uint8_t stride = n->db_stride;
    int dbbuf_entry_sz = 1 << (2 + stride);
    AddressSpace *as = pci_get_address_space(&n->parent_obj);
    int i;


    dma_addr_t dbs_tlen = n->page_size, eis_tlen = n->page_size;

    /* Addresses should not be NULL and should be page aligned. */
    if (dbs_addr == 0 || dbs_addr & (n->page_size - 1) || eis_addr == 0 ||
            eis_addr & (n->page_size - 1)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    n->dbs_addr = dbs_addr;
    n->eis_addr = eis_addr;
    n->dbs_addr_hva = (uint64_t)dma_memory_map(as, dbs_addr, &dbs_tlen, 0, MEMTXATTRS_UNSPECIFIED);
    n->eis_addr_hva = (uint64_t)dma_memory_map(as, eis_addr, &eis_tlen, 0, MEMTXATTRS_UNSPECIFIED);

    for (i = 1; i <= n->nr_io_queues; i++) {
        NvmeSQueue *sq = n->sq[i];
        NvmeCQueue *cq = n->cq[i];

        if (sq) {
            /* Submission queue tail pointer location, 2 * QID * stride. */
            sq->db_addr = dbs_addr + 2 * i * dbbuf_entry_sz;
            sq->db_addr_hva = n->dbs_addr_hva + 2 * i * dbbuf_entry_sz;
            sq->eventidx_addr = eis_addr + 2 * i * dbbuf_entry_sz;
            sq->eventidx_addr_hva = n->eis_addr_hva + 2 * i * dbbuf_entry_sz;
            femu_debug("DBBUF,sq[%d]:db=%" PRIu64 ",ei=%" PRIu64 "\n", i,
                    sq->db_addr, sq->eventidx_addr);
        }
        if (cq) {
            /* Completion queue head pointer location, (2 * QID + 1) * stride. */
            cq->db_addr = dbs_addr + (2 * i + 1) * dbbuf_entry_sz;
            cq->db_addr_hva = n->dbs_addr_hva + (2 * i + 1) * dbbuf_entry_sz;
            cq->eventidx_addr = eis_addr + (2 * i + 1) * dbbuf_entry_sz;
            cq->eventidx_addr_hva = n->eis_addr_hva + (2 * i + 1) * dbbuf_entry_sz;
            femu_debug("DBBUF,cq[%d]:db=%" PRIu64 ",ei=%" PRIu64 "\n", i,
                    cq->db_addr, cq->eventidx_addr);
        }
    }

    assert(n->dataplane_started == false);
    if (!n->poller_on) {
        /* Coperd: make sure this only runs once across all controller resets */
        nvme_init_poller(n);
        n->poller_on = true;
    }
    n->dataplane_started = true;
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
    FemuCtrl *n = ns->ctrl;
    switch (n->csi) {
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

    if (c->csi == NVME_CSI_NVM && nvme_csi_has_nvm_support(ns)) {
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
    int pgsz = n->page_size;

    if (!nvme_nsid_valid(n, nsid) || nsid == NVME_NSID_BROADCAST) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ns = nvme_ns(n, nsid);
    if (unlikely(!ns)) {
        return nvme_rpt_empty_id_struct(n, cmd);
    }

    if (c->csi == NVME_CSI_NVM && nvme_csi_has_nvm_support(ns)) {
        return nvme_rpt_empty_id_struct(n, cmd);
    } else if (c->csi == NVME_CSI_ZONED && n->csi == NVME_CSI_ZONED) {
        return dma_read_prp(n, (uint8_t *)n->id_ns_zoned, pgsz, prp1, prp2);
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

    if (c->csi != NVME_CSI_NVM && c->csi != NVME_CSI_ZONED) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    for (i = 1; i <= n->num_namespaces; i++) {
        ns = nvme_ns(n, i);
        if (!ns) {
            continue;
        }
        if (ns->id <= min_nsid || c->csi != n->csi) {
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
    ns_descrs->csi.v = n->csi;

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

static uint16_t nvme_get_feature(FemuCtrl *n, NvmeCmd *cmd, NvmeCqe *cqe)
{
    NvmeRangeType *rt;
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint32_t dw11 = le32_to_cpu(cmd->cdw11);
    uint32_t nsid = le32_to_cpu(cmd->nsid);
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);

    switch (dw10) {
    case NVME_ARBITRATION:
        cqe->n.result = cpu_to_le32(n->features.arbitration);
        break;
    case NVME_POWER_MANAGEMENT:
        cqe->n.result = cpu_to_le32(n->features.power_mgmt);
        break;
    case NVME_LBA_RANGE_TYPE:
        if (nsid == 0 || nsid > n->num_namespaces) {
            return NVME_INVALID_NSID | NVME_DNR;
        }
        rt = n->namespaces[nsid - 1].lba_range;
        return dma_read_prp(n, (uint8_t *)rt,
                MIN(sizeof(*rt), (dw11 & 0x3f) * sizeof(*rt)),
                prp1, prp2);
    case NVME_NUMBER_OF_QUEUES:
        cqe->n.result = cpu_to_le32((n->nr_io_queues - 1) |
                ((n->nr_io_queues - 1) << 16));
        break;
    case NVME_TEMPERATURE_THRESHOLD:
        cqe->n.result = cpu_to_le32(n->features.temp_thresh);
        break;
    case NVME_ERROR_RECOVERY:
        cqe->n.result = cpu_to_le32(n->features.err_rec);
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

    switch (dw10) {
    case NVME_ARBITRATION:
        cqe->n.result = cpu_to_le32(n->features.arbitration);
        n->features.arbitration = dw11;
        break;
    case NVME_POWER_MANAGEMENT:
        n->features.power_mgmt = dw11;
        break;
    case NVME_LBA_RANGE_TYPE:
        if (nsid == 0 || nsid > n->num_namespaces) {
            return NVME_INVALID_NSID | NVME_DNR;
        }
        rt = n->namespaces[nsid - 1].lba_range;
        return dma_write_prp(n, (uint8_t *)rt,
                MIN(sizeof(*rt), (dw11 & 0x3f) * sizeof(*rt)),
                prp1, prp2);
    case NVME_NUMBER_OF_QUEUES:
        /* Coperd: nr_io_queues is 0-based */
        cqe->n.result = cpu_to_le32((n->nr_io_queues - 1) |
                ((n->nr_io_queues - 1) << 16));
        break;
    case NVME_TEMPERATURE_THRESHOLD:
        n->features.temp_thresh = dw11;
        if (n->features.temp_thresh <= n->temperature && !n->temp_warn_issued) {
            n->temp_warn_issued = 1;
        } else if (n->features.temp_thresh > n->temperature &&
                !(n->aer_mask & 1 << NVME_AER_TYPE_SMART)) {
            n->temp_warn_issued = 0;
        }
        break;
    case NVME_ERROR_RECOVERY:
        n->features.err_rec = dw11;
        break;
    case NVME_VOLATILE_WRITE_CACHE:
        n->features.volatile_wc = dw11;
        break;
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
    default:
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    return NVME_SUCCESS;
}

static uint16_t nvme_fw_log_info(FemuCtrl *n, NvmeCmd *cmd, uint32_t buf_len)
{
    uint32_t trans_len;
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);
    NvmeFwSlotInfoLog fw_log;

    trans_len = MIN(sizeof(fw_log), buf_len);

    return dma_read_prp(n, (uint8_t *)&fw_log, trans_len, prp1, prp2);
}

static uint16_t nvme_error_log_info(FemuCtrl *n, NvmeCmd *cmd, uint32_t buf_len)
{
    uint32_t trans_len;
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);

    trans_len = MIN(sizeof(*n->elpes) * n->elpe, buf_len);
    n->aer_mask &= ~(1 << NVME_AER_TYPE_ERROR);

    return dma_read_prp(n, (uint8_t *)n->elpes, trans_len, prp1, prp2);
}

static uint16_t nvme_smart_info(FemuCtrl *n, NvmeCmd *cmd, uint32_t buf_len)
{
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);

    uint32_t trans_len;
    time_t current_seconds;
    NvmeSmartLog smart;

    trans_len = MIN(sizeof(smart), buf_len);
    memset(&smart, 0x0, sizeof(smart));
    smart.data_units_read[0] = cpu_to_le64(0);
    smart.data_units_written[0] = cpu_to_le64(0);
    smart.host_read_commands[0] = cpu_to_le64(0);
    smart.host_write_commands[0] = cpu_to_le64(0);

    smart.number_of_error_log_entries[0] = cpu_to_le64(n->num_errors);
    smart.temperature[0] = n->temperature & 0xff;
    smart.temperature[1] = (n->temperature >> 8) & 0xff;

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

    return dma_read_prp(n, (uint8_t *)&smart, trans_len, prp1, prp2);
}

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

    if (src_iocs) {
        memcpy(log.iocs, src_iocs, sizeof(log.iocs));
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
    uint16_t lid = dw10 & 0xffff;
    uint8_t  csi = le32_to_cpu(cmd->cdw14) >> 24;
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
    case NVME_LOG_ERROR_INFO:
        return nvme_error_log_info(n, cmd, len);
    case NVME_LOG_SMART_INFO:
        return nvme_smart_info(n, cmd, len);
    case NVME_LOG_FW_SLOT_INFO:
        return nvme_fw_log_info(n, cmd, len);
    case NVME_LOG_CMD_EFFECTS:
        return nvme_cmd_effects(n, cmd, csi, len, off);
    default:
        if (n->ext_ops.get_log) {
            return n->ext_ops.get_log(n, cmd);
        }
        return NVME_INVALID_LOG_ID | NVME_DNR;
    }
}

static uint16_t nvme_abort_req(FemuCtrl *n, NvmeCmd *cmd, uint32_t *result)
{
    uint32_t index = 0;
    uint16_t sqid = cmd->cdw10 & 0xffff;
    uint16_t cid = (cmd->cdw10 >> 16) & 0xffff;
    NvmeSQueue *sq;
    NvmeRequest *req;

    *result = 1;
    if (nvme_check_sqid(n, sqid)) {
        return NVME_SUCCESS;
    }

    sq = n->sq[sqid];

    while ((sq->head + index) % sq->size != sq->tail) {
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
            *result = 0;
            req = QTAILQ_FIRST(&sq->req_list);
            QTAILQ_REMOVE(&sq->req_list, req, entry);
            QTAILQ_INSERT_TAIL(&sq->out_req_list, req, entry);

            memset(&req->cqe, 0, sizeof(req->cqe));
            req->cqe.cid = cid;
            req->status = NVME_CMD_ABORT_REQ;

            abort_cmd.opcode = NVME_OP_ABORTED;
            nvme_addr_write(n, addr, (void *)&abort_cmd,
                sizeof(abort_cmd));

            return NVME_SUCCESS;
        }

        ++index;
    }

    return NVME_SUCCESS;
}

static uint16_t nvme_format_namespace(NvmeNamespace *ns, uint8_t lba_idx,
                                      uint8_t meta_loc, uint8_t pil, uint8_t pi,
                                      uint8_t sec_erase)
{
    NvmeIdNs *id_ns = &ns->id_ns;
    uint16_t ms = le16_to_cpu(ns->id_ns.lbaf[lba_idx].ms);

    if (lba_idx > ns->id_ns.nlbaf) {
        return NVME_INVALID_FORMAT | NVME_DNR;
    }
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

    ns->id_ns.flbas = lba_idx | meta_loc;
    ns->id_ns.dps = pil | pi;

    femu_debug("nvme_format_namespace\n");
    ns->ns_blks = ns_blks(ns, lba_idx);
    id_ns->nuse = id_ns->ncap = id_ns->nsze = cpu_to_le64(ns->ns_blks);

    return NVME_SUCCESS;
}

static uint16_t nvme_format(FemuCtrl *n, NvmeCmd *cmd)
{
    NvmeNamespace *ns;
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint32_t nsid = le32_to_cpu(cmd->nsid);

    uint8_t lba_idx = dw10 & 0xf;
    uint8_t meta_loc = dw10 & 0x10;
    uint8_t pil = (dw10 >> 5) & 0x8;
    uint8_t pi = (dw10 >> 5) & 0x7;
    uint8_t sec_erase = (dw10 >> 8) & 0x7;

    if (nsid == 0xffffffff) {
        uint16_t ret = NVME_SUCCESS;

        for (uint32_t i = 0; i < n->num_namespaces; ++i) {
            ns = &n->namespaces[i];
            ret = nvme_format_namespace(ns, lba_idx, meta_loc, pil, pi,
                    sec_erase);
            if (ret != NVME_SUCCESS) {
                return ret;
            }
        }
        return ret;
    }

    if (nsid == 0 || nsid > n->num_namespaces) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ns = &n->namespaces[nsid - 1];

    return nvme_format_namespace(ns, lba_idx, meta_loc, pil, pi, sec_erase);
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
    case NVME_ADM_CMD_ACTIVATE_FW:
    case NVME_ADM_CMD_DOWNLOAD_FW:
    case NVME_ADM_CMD_SECURITY_SEND:
    case NVME_ADM_CMD_SECURITY_RECV:
        return NVME_INVALID_OPCODE | NVME_DNR;
    default:
        if (n->ext_ops.admin_cmd) {
            return n->ext_ops.admin_cmd(n, cmd);
        }

        return NVME_INVALID_OPCODE | NVME_DNR;
    }
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

