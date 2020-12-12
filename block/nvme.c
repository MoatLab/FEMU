/*
 * NVMe block driver based on vfio
 *
 * Copyright 2016 - 2018 Red Hat, Inc.
 *
 * Authors:
 *   Fam Zheng <famz@redhat.com>
 *   Paolo Bonzini <pbonzini@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include <linux/vfio.h>
#include "qapi/error.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qstring.h"
#include "qemu/error-report.h"
#include "qemu/main-loop.h"
#include "qemu/module.h"
#include "qemu/cutils.h"
#include "qemu/option.h"
#include "qemu/vfio-helpers.h"
#include "block/block_int.h"
#include "sysemu/replay.h"
#include "trace.h"

#include "block/nvme.h"

#define NVME_SQ_ENTRY_BYTES 64
#define NVME_CQ_ENTRY_BYTES 16
#define NVME_QUEUE_SIZE 128
#define NVME_DOORBELL_SIZE 4096

/*
 * We have to leave one slot empty as that is the full queue case where
 * head == tail + 1.
 */
#define NVME_NUM_REQS (NVME_QUEUE_SIZE - 1)

typedef struct BDRVNVMeState BDRVNVMeState;

/* Same index is used for queues and IRQs */
#define INDEX_ADMIN     0
#define INDEX_IO(n)     (1 + n)

/* This driver shares a single MSIX IRQ for the admin and I/O queues */
enum {
    MSIX_SHARED_IRQ_IDX = 0,
    MSIX_IRQ_COUNT = 1
};

typedef struct {
    int32_t  head, tail;
    uint8_t  *queue;
    uint64_t iova;
    /* Hardware MMIO register */
    volatile uint32_t *doorbell;
} NVMeQueue;

typedef struct {
    BlockCompletionFunc *cb;
    void *opaque;
    int cid;
    void *prp_list_page;
    uint64_t prp_list_iova;
    int free_req_next; /* q->reqs[] index of next free req */
} NVMeRequest;

typedef struct {
    QemuMutex   lock;

    /* Read from I/O code path, initialized under BQL */
    BDRVNVMeState   *s;
    int             index;

    /* Fields protected by BQL */
    uint8_t     *prp_list_pages;

    /* Fields protected by @lock */
    CoQueue     free_req_queue;
    NVMeQueue   sq, cq;
    int         cq_phase;
    int         free_req_head;
    NVMeRequest reqs[NVME_NUM_REQS];
    int         need_kick;
    int         inflight;

    /* Thread-safe, no lock necessary */
    QEMUBH      *completion_bh;
} NVMeQueuePair;

struct BDRVNVMeState {
    AioContext *aio_context;
    QEMUVFIOState *vfio;
    void *bar0_wo_map;
    /* Memory mapped registers */
    volatile struct {
        uint32_t sq_tail;
        uint32_t cq_head;
    } *doorbells;
    /* The submission/completion queue pairs.
     * [0]: admin queue.
     * [1..]: io queues.
     */
    NVMeQueuePair **queues;
    unsigned queue_count;
    size_t page_size;
    /* How many uint32_t elements does each doorbell entry take. */
    size_t doorbell_scale;
    bool write_cache_supported;
    EventNotifier irq_notifier[MSIX_IRQ_COUNT];

    uint64_t nsze; /* Namespace size reported by identify command */
    int nsid;      /* The namespace id to read/write data. */
    int blkshift;

    uint64_t max_transfer;
    bool plugged;

    bool supports_write_zeroes;
    bool supports_discard;

    CoMutex dma_map_lock;
    CoQueue dma_flush_queue;

    /* Total size of mapped qiov, accessed under dma_map_lock */
    int dma_map_count;

    /* PCI address (required for nvme_refresh_filename()) */
    char *device;

    struct {
        uint64_t completion_errors;
        uint64_t aligned_accesses;
        uint64_t unaligned_accesses;
    } stats;
};

#define NVME_BLOCK_OPT_DEVICE "device"
#define NVME_BLOCK_OPT_NAMESPACE "namespace"

static void nvme_process_completion_bh(void *opaque);

static QemuOptsList runtime_opts = {
    .name = "nvme",
    .head = QTAILQ_HEAD_INITIALIZER(runtime_opts.head),
    .desc = {
        {
            .name = NVME_BLOCK_OPT_DEVICE,
            .type = QEMU_OPT_STRING,
            .help = "NVMe PCI device address",
        },
        {
            .name = NVME_BLOCK_OPT_NAMESPACE,
            .type = QEMU_OPT_NUMBER,
            .help = "NVMe namespace",
        },
        { /* end of list */ }
    },
};

/* Returns true on success, false on failure. */
static bool nvme_init_queue(BDRVNVMeState *s, NVMeQueue *q,
                            unsigned nentries, size_t entry_bytes, Error **errp)
{
    size_t bytes;
    int r;

    bytes = ROUND_UP(nentries * entry_bytes, qemu_real_host_page_size);
    q->head = q->tail = 0;
    q->queue = qemu_try_memalign(qemu_real_host_page_size, bytes);
    if (!q->queue) {
        error_setg(errp, "Cannot allocate queue");
        return false;
    }
    memset(q->queue, 0, bytes);
    r = qemu_vfio_dma_map(s->vfio, q->queue, bytes, false, &q->iova);
    if (r) {
        error_setg(errp, "Cannot map queue");
        return false;
    }
    return true;
}

static void nvme_free_queue_pair(NVMeQueuePair *q)
{
    trace_nvme_free_queue_pair(q->index, q);
    if (q->completion_bh) {
        qemu_bh_delete(q->completion_bh);
    }
    qemu_vfree(q->prp_list_pages);
    qemu_vfree(q->sq.queue);
    qemu_vfree(q->cq.queue);
    qemu_mutex_destroy(&q->lock);
    g_free(q);
}

static void nvme_free_req_queue_cb(void *opaque)
{
    NVMeQueuePair *q = opaque;

    qemu_mutex_lock(&q->lock);
    while (qemu_co_enter_next(&q->free_req_queue, &q->lock)) {
        /* Retry all pending requests */
    }
    qemu_mutex_unlock(&q->lock);
}

static NVMeQueuePair *nvme_create_queue_pair(BDRVNVMeState *s,
                                             AioContext *aio_context,
                                             unsigned idx, size_t size,
                                             Error **errp)
{
    int i, r;
    NVMeQueuePair *q;
    uint64_t prp_list_iova;
    size_t bytes;

    q = g_try_new0(NVMeQueuePair, 1);
    if (!q) {
        return NULL;
    }
    trace_nvme_create_queue_pair(idx, q, size, aio_context,
                                 event_notifier_get_fd(s->irq_notifier));
    bytes = QEMU_ALIGN_UP(s->page_size * NVME_NUM_REQS,
                          qemu_real_host_page_size);
    q->prp_list_pages = qemu_try_memalign(qemu_real_host_page_size, bytes);
    if (!q->prp_list_pages) {
        goto fail;
    }
    memset(q->prp_list_pages, 0, bytes);
    qemu_mutex_init(&q->lock);
    q->s = s;
    q->index = idx;
    qemu_co_queue_init(&q->free_req_queue);
    q->completion_bh = aio_bh_new(aio_context, nvme_process_completion_bh, q);
    r = qemu_vfio_dma_map(s->vfio, q->prp_list_pages, bytes,
                          false, &prp_list_iova);
    if (r) {
        goto fail;
    }
    q->free_req_head = -1;
    for (i = 0; i < NVME_NUM_REQS; i++) {
        NVMeRequest *req = &q->reqs[i];
        req->cid = i + 1;
        req->free_req_next = q->free_req_head;
        q->free_req_head = i;
        req->prp_list_page = q->prp_list_pages + i * s->page_size;
        req->prp_list_iova = prp_list_iova + i * s->page_size;
    }

    if (!nvme_init_queue(s, &q->sq, size, NVME_SQ_ENTRY_BYTES, errp)) {
        goto fail;
    }
    q->sq.doorbell = &s->doorbells[idx * s->doorbell_scale].sq_tail;

    if (!nvme_init_queue(s, &q->cq, size, NVME_CQ_ENTRY_BYTES, errp)) {
        goto fail;
    }
    q->cq.doorbell = &s->doorbells[idx * s->doorbell_scale].cq_head;

    return q;
fail:
    nvme_free_queue_pair(q);
    return NULL;
}

/* With q->lock */
static void nvme_kick(NVMeQueuePair *q)
{
    BDRVNVMeState *s = q->s;

    if (s->plugged || !q->need_kick) {
        return;
    }
    trace_nvme_kick(s, q->index);
    assert(!(q->sq.tail & 0xFF00));
    /* Fence the write to submission queue entry before notifying the device. */
    smp_wmb();
    *q->sq.doorbell = cpu_to_le32(q->sq.tail);
    q->inflight += q->need_kick;
    q->need_kick = 0;
}

/* Find a free request element if any, otherwise:
 * a) if in coroutine context, try to wait for one to become available;
 * b) if not in coroutine, return NULL;
 */
static NVMeRequest *nvme_get_free_req(NVMeQueuePair *q)
{
    NVMeRequest *req;

    qemu_mutex_lock(&q->lock);

    while (q->free_req_head == -1) {
        if (qemu_in_coroutine()) {
            trace_nvme_free_req_queue_wait(q->s, q->index);
            qemu_co_queue_wait(&q->free_req_queue, &q->lock);
        } else {
            qemu_mutex_unlock(&q->lock);
            return NULL;
        }
    }

    req = &q->reqs[q->free_req_head];
    q->free_req_head = req->free_req_next;
    req->free_req_next = -1;

    qemu_mutex_unlock(&q->lock);
    return req;
}

/* With q->lock */
static void nvme_put_free_req_locked(NVMeQueuePair *q, NVMeRequest *req)
{
    req->free_req_next = q->free_req_head;
    q->free_req_head = req - q->reqs;
}

/* With q->lock */
static void nvme_wake_free_req_locked(NVMeQueuePair *q)
{
    if (!qemu_co_queue_empty(&q->free_req_queue)) {
        replay_bh_schedule_oneshot_event(q->s->aio_context,
                nvme_free_req_queue_cb, q);
    }
}

/* Insert a request in the freelist and wake waiters */
static void nvme_put_free_req_and_wake(NVMeQueuePair *q, NVMeRequest *req)
{
    qemu_mutex_lock(&q->lock);
    nvme_put_free_req_locked(q, req);
    nvme_wake_free_req_locked(q);
    qemu_mutex_unlock(&q->lock);
}

static inline int nvme_translate_error(const NvmeCqe *c)
{
    uint16_t status = (le16_to_cpu(c->status) >> 1) & 0xFF;
    if (status) {
        trace_nvme_error(le32_to_cpu(c->result),
                         le16_to_cpu(c->sq_head),
                         le16_to_cpu(c->sq_id),
                         le16_to_cpu(c->cid),
                         le16_to_cpu(status));
    }
    switch (status) {
    case 0:
        return 0;
    case 1:
        return -ENOSYS;
    case 2:
        return -EINVAL;
    default:
        return -EIO;
    }
}

/* With q->lock */
static bool nvme_process_completion(NVMeQueuePair *q)
{
    BDRVNVMeState *s = q->s;
    bool progress = false;
    NVMeRequest *preq;
    NVMeRequest req;
    NvmeCqe *c;

    trace_nvme_process_completion(s, q->index, q->inflight);
    if (s->plugged) {
        trace_nvme_process_completion_queue_plugged(s, q->index);
        return false;
    }

    /*
     * Support re-entrancy when a request cb() function invokes aio_poll().
     * Pending completions must be visible to aio_poll() so that a cb()
     * function can wait for the completion of another request.
     *
     * The aio_poll() loop will execute our BH and we'll resume completion
     * processing there.
     */
    qemu_bh_schedule(q->completion_bh);

    assert(q->inflight >= 0);
    while (q->inflight) {
        int ret;
        int16_t cid;

        c = (NvmeCqe *)&q->cq.queue[q->cq.head * NVME_CQ_ENTRY_BYTES];
        if ((le16_to_cpu(c->status) & 0x1) == q->cq_phase) {
            break;
        }
        ret = nvme_translate_error(c);
        if (ret) {
            s->stats.completion_errors++;
        }
        q->cq.head = (q->cq.head + 1) % NVME_QUEUE_SIZE;
        if (!q->cq.head) {
            q->cq_phase = !q->cq_phase;
        }
        cid = le16_to_cpu(c->cid);
        if (cid == 0 || cid > NVME_QUEUE_SIZE) {
            warn_report("NVMe: Unexpected CID in completion queue: %"PRIu32", "
                        "queue size: %u", cid, NVME_QUEUE_SIZE);
            continue;
        }
        trace_nvme_complete_command(s, q->index, cid);
        preq = &q->reqs[cid - 1];
        req = *preq;
        assert(req.cid == cid);
        assert(req.cb);
        nvme_put_free_req_locked(q, preq);
        preq->cb = preq->opaque = NULL;
        q->inflight--;
        qemu_mutex_unlock(&q->lock);
        req.cb(req.opaque, ret);
        qemu_mutex_lock(&q->lock);
        progress = true;
    }
    if (progress) {
        /* Notify the device so it can post more completions. */
        smp_mb_release();
        *q->cq.doorbell = cpu_to_le32(q->cq.head);
        nvme_wake_free_req_locked(q);
    }

    qemu_bh_cancel(q->completion_bh);

    return progress;
}

static void nvme_process_completion_bh(void *opaque)
{
    NVMeQueuePair *q = opaque;

    /*
     * We're being invoked because a nvme_process_completion() cb() function
     * called aio_poll(). The callback may be waiting for further completions
     * so notify the device that it has space to fill in more completions now.
     */
    smp_mb_release();
    *q->cq.doorbell = cpu_to_le32(q->cq.head);
    nvme_wake_free_req_locked(q);

    nvme_process_completion(q);
}

static void nvme_trace_command(const NvmeCmd *cmd)
{
    int i;

    if (!trace_event_get_state_backends(TRACE_NVME_SUBMIT_COMMAND_RAW)) {
        return;
    }
    for (i = 0; i < 8; ++i) {
        uint8_t *cmdp = (uint8_t *)cmd + i * 8;
        trace_nvme_submit_command_raw(cmdp[0], cmdp[1], cmdp[2], cmdp[3],
                                      cmdp[4], cmdp[5], cmdp[6], cmdp[7]);
    }
}

static void nvme_submit_command(NVMeQueuePair *q, NVMeRequest *req,
                                NvmeCmd *cmd, BlockCompletionFunc cb,
                                void *opaque)
{
    assert(!req->cb);
    req->cb = cb;
    req->opaque = opaque;
    cmd->cid = cpu_to_le16(req->cid);

    trace_nvme_submit_command(q->s, q->index, req->cid);
    nvme_trace_command(cmd);
    qemu_mutex_lock(&q->lock);
    memcpy((uint8_t *)q->sq.queue +
           q->sq.tail * NVME_SQ_ENTRY_BYTES, cmd, sizeof(*cmd));
    q->sq.tail = (q->sq.tail + 1) % NVME_QUEUE_SIZE;
    q->need_kick++;
    nvme_kick(q);
    nvme_process_completion(q);
    qemu_mutex_unlock(&q->lock);
}

static void nvme_admin_cmd_sync_cb(void *opaque, int ret)
{
    int *pret = opaque;
    *pret = ret;
    aio_wait_kick();
}

static int nvme_admin_cmd_sync(BlockDriverState *bs, NvmeCmd *cmd)
{
    BDRVNVMeState *s = bs->opaque;
    NVMeQueuePair *q = s->queues[INDEX_ADMIN];
    AioContext *aio_context = bdrv_get_aio_context(bs);
    NVMeRequest *req;
    int ret = -EINPROGRESS;
    req = nvme_get_free_req(q);
    if (!req) {
        return -EBUSY;
    }
    nvme_submit_command(q, req, cmd, nvme_admin_cmd_sync_cb, &ret);

    AIO_WAIT_WHILE(aio_context, ret == -EINPROGRESS);
    return ret;
}

/* Returns true on success, false on failure. */
static bool nvme_identify(BlockDriverState *bs, int namespace, Error **errp)
{
    BDRVNVMeState *s = bs->opaque;
    bool ret = false;
    union {
        NvmeIdCtrl ctrl;
        NvmeIdNs ns;
    } *id;
    NvmeLBAF *lbaf;
    uint16_t oncs;
    int r;
    uint64_t iova;
    NvmeCmd cmd = {
        .opcode = NVME_ADM_CMD_IDENTIFY,
        .cdw10 = cpu_to_le32(0x1),
    };
    size_t id_size = QEMU_ALIGN_UP(sizeof(*id), qemu_real_host_page_size);

    id = qemu_try_memalign(qemu_real_host_page_size, id_size);
    if (!id) {
        error_setg(errp, "Cannot allocate buffer for identify response");
        goto out;
    }
    r = qemu_vfio_dma_map(s->vfio, id, id_size, true, &iova);
    if (r) {
        error_setg(errp, "Cannot map buffer for DMA");
        goto out;
    }

    memset(id, 0, id_size);
    cmd.dptr.prp1 = cpu_to_le64(iova);
    if (nvme_admin_cmd_sync(bs, &cmd)) {
        error_setg(errp, "Failed to identify controller");
        goto out;
    }

    if (le32_to_cpu(id->ctrl.nn) < namespace) {
        error_setg(errp, "Invalid namespace");
        goto out;
    }
    s->write_cache_supported = le32_to_cpu(id->ctrl.vwc) & 0x1;
    s->max_transfer = (id->ctrl.mdts ? 1 << id->ctrl.mdts : 0) * s->page_size;
    /* For now the page list buffer per command is one page, to hold at most
     * s->page_size / sizeof(uint64_t) entries. */
    s->max_transfer = MIN_NON_ZERO(s->max_transfer,
                          s->page_size / sizeof(uint64_t) * s->page_size);

    oncs = le16_to_cpu(id->ctrl.oncs);
    s->supports_write_zeroes = !!(oncs & NVME_ONCS_WRITE_ZEROES);
    s->supports_discard = !!(oncs & NVME_ONCS_DSM);

    memset(id, 0, id_size);
    cmd.cdw10 = 0;
    cmd.nsid = cpu_to_le32(namespace);
    if (nvme_admin_cmd_sync(bs, &cmd)) {
        error_setg(errp, "Failed to identify namespace");
        goto out;
    }

    s->nsze = le64_to_cpu(id->ns.nsze);
    lbaf = &id->ns.lbaf[NVME_ID_NS_FLBAS_INDEX(id->ns.flbas)];

    if (NVME_ID_NS_DLFEAT_WRITE_ZEROES(id->ns.dlfeat) &&
            NVME_ID_NS_DLFEAT_READ_BEHAVIOR(id->ns.dlfeat) ==
                    NVME_ID_NS_DLFEAT_READ_BEHAVIOR_ZEROES) {
        bs->supported_write_flags |= BDRV_REQ_MAY_UNMAP;
    }

    if (lbaf->ms) {
        error_setg(errp, "Namespaces with metadata are not yet supported");
        goto out;
    }

    if (lbaf->ds < BDRV_SECTOR_BITS || lbaf->ds > 12 ||
        (1 << lbaf->ds) > s->page_size)
    {
        error_setg(errp, "Namespace has unsupported block size (2^%d)",
                   lbaf->ds);
        goto out;
    }

    ret = true;
    s->blkshift = lbaf->ds;
out:
    qemu_vfio_dma_unmap(s->vfio, id);
    qemu_vfree(id);

    return ret;
}

static bool nvme_poll_queue(NVMeQueuePair *q)
{
    bool progress = false;

    const size_t cqe_offset = q->cq.head * NVME_CQ_ENTRY_BYTES;
    NvmeCqe *cqe = (NvmeCqe *)&q->cq.queue[cqe_offset];

    trace_nvme_poll_queue(q->s, q->index);
    /*
     * Do an early check for completions. q->lock isn't needed because
     * nvme_process_completion() only runs in the event loop thread and
     * cannot race with itself.
     */
    if ((le16_to_cpu(cqe->status) & 0x1) == q->cq_phase) {
        return false;
    }

    qemu_mutex_lock(&q->lock);
    while (nvme_process_completion(q)) {
        /* Keep polling */
        progress = true;
    }
    qemu_mutex_unlock(&q->lock);

    return progress;
}

static bool nvme_poll_queues(BDRVNVMeState *s)
{
    bool progress = false;
    int i;

    for (i = 0; i < s->queue_count; i++) {
        if (nvme_poll_queue(s->queues[i])) {
            progress = true;
        }
    }
    return progress;
}

static void nvme_handle_event(EventNotifier *n)
{
    BDRVNVMeState *s = container_of(n, BDRVNVMeState,
                                    irq_notifier[MSIX_SHARED_IRQ_IDX]);

    trace_nvme_handle_event(s);
    event_notifier_test_and_clear(n);
    nvme_poll_queues(s);
}

static bool nvme_add_io_queue(BlockDriverState *bs, Error **errp)
{
    BDRVNVMeState *s = bs->opaque;
    unsigned n = s->queue_count;
    NVMeQueuePair *q;
    NvmeCmd cmd;
    unsigned queue_size = NVME_QUEUE_SIZE;

    assert(n <= UINT16_MAX);
    q = nvme_create_queue_pair(s, bdrv_get_aio_context(bs),
                               n, queue_size, errp);
    if (!q) {
        return false;
    }
    cmd = (NvmeCmd) {
        .opcode = NVME_ADM_CMD_CREATE_CQ,
        .dptr.prp1 = cpu_to_le64(q->cq.iova),
        .cdw10 = cpu_to_le32(((queue_size - 1) << 16) | n),
        .cdw11 = cpu_to_le32(NVME_CQ_IEN | NVME_CQ_PC),
    };
    if (nvme_admin_cmd_sync(bs, &cmd)) {
        error_setg(errp, "Failed to create CQ io queue [%u]", n);
        goto out_error;
    }
    cmd = (NvmeCmd) {
        .opcode = NVME_ADM_CMD_CREATE_SQ,
        .dptr.prp1 = cpu_to_le64(q->sq.iova),
        .cdw10 = cpu_to_le32(((queue_size - 1) << 16) | n),
        .cdw11 = cpu_to_le32(NVME_SQ_PC | (n << 16)),
    };
    if (nvme_admin_cmd_sync(bs, &cmd)) {
        error_setg(errp, "Failed to create SQ io queue [%u]", n);
        goto out_error;
    }
    s->queues = g_renew(NVMeQueuePair *, s->queues, n + 1);
    s->queues[n] = q;
    s->queue_count++;
    return true;
out_error:
    nvme_free_queue_pair(q);
    return false;
}

static bool nvme_poll_cb(void *opaque)
{
    EventNotifier *e = opaque;
    BDRVNVMeState *s = container_of(e, BDRVNVMeState,
                                    irq_notifier[MSIX_SHARED_IRQ_IDX]);

    return nvme_poll_queues(s);
}

static int nvme_init(BlockDriverState *bs, const char *device, int namespace,
                     Error **errp)
{
    BDRVNVMeState *s = bs->opaque;
    NVMeQueuePair *q;
    AioContext *aio_context = bdrv_get_aio_context(bs);
    int ret;
    uint64_t cap;
    uint64_t timeout_ms;
    uint64_t deadline, now;
    volatile NvmeBar *regs = NULL;

    qemu_co_mutex_init(&s->dma_map_lock);
    qemu_co_queue_init(&s->dma_flush_queue);
    s->device = g_strdup(device);
    s->nsid = namespace;
    s->aio_context = bdrv_get_aio_context(bs);
    ret = event_notifier_init(&s->irq_notifier[MSIX_SHARED_IRQ_IDX], 0);
    if (ret) {
        error_setg(errp, "Failed to init event notifier");
        return ret;
    }

    s->vfio = qemu_vfio_open_pci(device, errp);
    if (!s->vfio) {
        ret = -EINVAL;
        goto out;
    }

    regs = qemu_vfio_pci_map_bar(s->vfio, 0, 0, sizeof(NvmeBar),
                                 PROT_READ | PROT_WRITE, errp);
    if (!regs) {
        ret = -EINVAL;
        goto out;
    }
    /* Perform initialize sequence as described in NVMe spec "7.6.1
     * Initialization". */

    cap = le64_to_cpu(regs->cap);
    trace_nvme_controller_capability_raw(cap);
    trace_nvme_controller_capability("Maximum Queue Entries Supported",
                                     1 + NVME_CAP_MQES(cap));
    trace_nvme_controller_capability("Contiguous Queues Required",
                                     NVME_CAP_CQR(cap));
    trace_nvme_controller_capability("Doorbell Stride",
                                     2 << (2 + NVME_CAP_DSTRD(cap)));
    trace_nvme_controller_capability("Subsystem Reset Supported",
                                     NVME_CAP_NSSRS(cap));
    trace_nvme_controller_capability("Memory Page Size Minimum",
                                     1 << (12 + NVME_CAP_MPSMIN(cap)));
    trace_nvme_controller_capability("Memory Page Size Maximum",
                                     1 << (12 + NVME_CAP_MPSMAX(cap)));
    if (!NVME_CAP_CSS(cap)) {
        error_setg(errp, "Device doesn't support NVMe command set");
        ret = -EINVAL;
        goto out;
    }

    s->page_size = 1u << (12 + NVME_CAP_MPSMIN(cap));
    s->doorbell_scale = (4 << NVME_CAP_DSTRD(cap)) / sizeof(uint32_t);
    bs->bl.opt_mem_alignment = s->page_size;
    bs->bl.request_alignment = s->page_size;
    timeout_ms = MIN(500 * NVME_CAP_TO(cap), 30000);

    /* Reset device to get a clean state. */
    regs->cc = cpu_to_le32(le32_to_cpu(regs->cc) & 0xFE);
    /* Wait for CSTS.RDY = 0. */
    deadline = qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + timeout_ms * SCALE_MS;
    while (NVME_CSTS_RDY(le32_to_cpu(regs->csts))) {
        if (qemu_clock_get_ns(QEMU_CLOCK_REALTIME) > deadline) {
            error_setg(errp, "Timeout while waiting for device to reset (%"
                             PRId64 " ms)",
                       timeout_ms);
            ret = -ETIMEDOUT;
            goto out;
        }
    }

    s->bar0_wo_map = qemu_vfio_pci_map_bar(s->vfio, 0, 0,
                                           sizeof(NvmeBar) + NVME_DOORBELL_SIZE,
                                           PROT_WRITE, errp);
    s->doorbells = (void *)((uintptr_t)s->bar0_wo_map + sizeof(NvmeBar));
    if (!s->doorbells) {
        ret = -EINVAL;
        goto out;
    }

    /* Set up admin queue. */
    s->queues = g_new(NVMeQueuePair *, 1);
    q = nvme_create_queue_pair(s, aio_context, 0, NVME_QUEUE_SIZE, errp);
    if (!q) {
        ret = -EINVAL;
        goto out;
    }
    s->queues[INDEX_ADMIN] = q;
    s->queue_count = 1;
    QEMU_BUILD_BUG_ON((NVME_QUEUE_SIZE - 1) & 0xF000);
    regs->aqa = cpu_to_le32(((NVME_QUEUE_SIZE - 1) << AQA_ACQS_SHIFT) |
                            ((NVME_QUEUE_SIZE - 1) << AQA_ASQS_SHIFT));
    regs->asq = cpu_to_le64(q->sq.iova);
    regs->acq = cpu_to_le64(q->cq.iova);

    /* After setting up all control registers we can enable device now. */
    regs->cc = cpu_to_le32((ctz32(NVME_CQ_ENTRY_BYTES) << CC_IOCQES_SHIFT) |
                           (ctz32(NVME_SQ_ENTRY_BYTES) << CC_IOSQES_SHIFT) |
                           CC_EN_MASK);
    /* Wait for CSTS.RDY = 1. */
    now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    deadline = now + timeout_ms * SCALE_MS;
    while (!NVME_CSTS_RDY(le32_to_cpu(regs->csts))) {
        if (qemu_clock_get_ns(QEMU_CLOCK_REALTIME) > deadline) {
            error_setg(errp, "Timeout while waiting for device to start (%"
                             PRId64 " ms)",
                       timeout_ms);
            ret = -ETIMEDOUT;
            goto out;
        }
    }

    ret = qemu_vfio_pci_init_irq(s->vfio, s->irq_notifier,
                                 VFIO_PCI_MSIX_IRQ_INDEX, errp);
    if (ret) {
        goto out;
    }
    aio_set_event_notifier(bdrv_get_aio_context(bs),
                           &s->irq_notifier[MSIX_SHARED_IRQ_IDX],
                           false, nvme_handle_event, nvme_poll_cb);

    if (!nvme_identify(bs, namespace, errp)) {
        ret = -EIO;
        goto out;
    }

    /* Set up command queues. */
    if (!nvme_add_io_queue(bs, errp)) {
        ret = -EIO;
    }
out:
    if (regs) {
        qemu_vfio_pci_unmap_bar(s->vfio, 0, (void *)regs, 0, sizeof(NvmeBar));
    }

    /* Cleaning up is done in nvme_file_open() upon error. */
    return ret;
}

/* Parse a filename in the format of nvme://XXXX:XX:XX.X/X. Example:
 *
 *     nvme://0000:44:00.0/1
 *
 * where the "nvme://" is a fixed form of the protocol prefix, the middle part
 * is the PCI address, and the last part is the namespace number starting from
 * 1 according to the NVMe spec. */
static void nvme_parse_filename(const char *filename, QDict *options,
                                Error **errp)
{
    int pref = strlen("nvme://");

    if (strlen(filename) > pref && !strncmp(filename, "nvme://", pref)) {
        const char *tmp = filename + pref;
        char *device;
        const char *namespace;
        unsigned long ns;
        const char *slash = strchr(tmp, '/');
        if (!slash) {
            qdict_put_str(options, NVME_BLOCK_OPT_DEVICE, tmp);
            return;
        }
        device = g_strndup(tmp, slash - tmp);
        qdict_put_str(options, NVME_BLOCK_OPT_DEVICE, device);
        g_free(device);
        namespace = slash + 1;
        if (*namespace && qemu_strtoul(namespace, NULL, 10, &ns)) {
            error_setg(errp, "Invalid namespace '%s', positive number expected",
                       namespace);
            return;
        }
        qdict_put_str(options, NVME_BLOCK_OPT_NAMESPACE,
                      *namespace ? namespace : "1");
    }
}

static int nvme_enable_disable_write_cache(BlockDriverState *bs, bool enable,
                                           Error **errp)
{
    int ret;
    BDRVNVMeState *s = bs->opaque;
    NvmeCmd cmd = {
        .opcode = NVME_ADM_CMD_SET_FEATURES,
        .nsid = cpu_to_le32(s->nsid),
        .cdw10 = cpu_to_le32(0x06),
        .cdw11 = cpu_to_le32(enable ? 0x01 : 0x00),
    };

    ret = nvme_admin_cmd_sync(bs, &cmd);
    if (ret) {
        error_setg(errp, "Failed to configure NVMe write cache");
    }
    return ret;
}

static void nvme_close(BlockDriverState *bs)
{
    BDRVNVMeState *s = bs->opaque;

    for (unsigned i = 0; i < s->queue_count; ++i) {
        nvme_free_queue_pair(s->queues[i]);
    }
    g_free(s->queues);
    aio_set_event_notifier(bdrv_get_aio_context(bs),
                           &s->irq_notifier[MSIX_SHARED_IRQ_IDX],
                           false, NULL, NULL);
    event_notifier_cleanup(&s->irq_notifier[MSIX_SHARED_IRQ_IDX]);
    qemu_vfio_pci_unmap_bar(s->vfio, 0, s->bar0_wo_map,
                            0, sizeof(NvmeBar) + NVME_DOORBELL_SIZE);
    qemu_vfio_close(s->vfio);

    g_free(s->device);
}

static int nvme_file_open(BlockDriverState *bs, QDict *options, int flags,
                          Error **errp)
{
    const char *device;
    QemuOpts *opts;
    int namespace;
    int ret;
    BDRVNVMeState *s = bs->opaque;

    bs->supported_write_flags = BDRV_REQ_FUA;

    opts = qemu_opts_create(&runtime_opts, NULL, 0, &error_abort);
    qemu_opts_absorb_qdict(opts, options, &error_abort);
    device = qemu_opt_get(opts, NVME_BLOCK_OPT_DEVICE);
    if (!device) {
        error_setg(errp, "'" NVME_BLOCK_OPT_DEVICE "' option is required");
        qemu_opts_del(opts);
        return -EINVAL;
    }

    namespace = qemu_opt_get_number(opts, NVME_BLOCK_OPT_NAMESPACE, 1);
    ret = nvme_init(bs, device, namespace, errp);
    qemu_opts_del(opts);
    if (ret) {
        goto fail;
    }
    if (flags & BDRV_O_NOCACHE) {
        if (!s->write_cache_supported) {
            error_setg(errp,
                       "NVMe controller doesn't support write cache configuration");
            ret = -EINVAL;
        } else {
            ret = nvme_enable_disable_write_cache(bs, !(flags & BDRV_O_NOCACHE),
                                                  errp);
        }
        if (ret) {
            goto fail;
        }
    }
    return 0;
fail:
    nvme_close(bs);
    return ret;
}

static int64_t nvme_getlength(BlockDriverState *bs)
{
    BDRVNVMeState *s = bs->opaque;
    return s->nsze << s->blkshift;
}

static uint32_t nvme_get_blocksize(BlockDriverState *bs)
{
    BDRVNVMeState *s = bs->opaque;
    assert(s->blkshift >= BDRV_SECTOR_BITS && s->blkshift <= 12);
    return UINT32_C(1) << s->blkshift;
}

static int nvme_probe_blocksizes(BlockDriverState *bs, BlockSizes *bsz)
{
    uint32_t blocksize = nvme_get_blocksize(bs);
    bsz->phys = blocksize;
    bsz->log = blocksize;
    return 0;
}

/* Called with s->dma_map_lock */
static coroutine_fn int nvme_cmd_unmap_qiov(BlockDriverState *bs,
                                            QEMUIOVector *qiov)
{
    int r = 0;
    BDRVNVMeState *s = bs->opaque;

    s->dma_map_count -= qiov->size;
    if (!s->dma_map_count && !qemu_co_queue_empty(&s->dma_flush_queue)) {
        r = qemu_vfio_dma_reset_temporary(s->vfio);
        if (!r) {
            qemu_co_queue_restart_all(&s->dma_flush_queue);
        }
    }
    return r;
}

/* Called with s->dma_map_lock */
static coroutine_fn int nvme_cmd_map_qiov(BlockDriverState *bs, NvmeCmd *cmd,
                                          NVMeRequest *req, QEMUIOVector *qiov)
{
    BDRVNVMeState *s = bs->opaque;
    uint64_t *pagelist = req->prp_list_page;
    int i, j, r;
    int entries = 0;

    assert(qiov->size);
    assert(QEMU_IS_ALIGNED(qiov->size, s->page_size));
    assert(qiov->size / s->page_size <= s->page_size / sizeof(uint64_t));
    for (i = 0; i < qiov->niov; ++i) {
        bool retry = true;
        uint64_t iova;
        size_t len = QEMU_ALIGN_UP(qiov->iov[i].iov_len,
                                   qemu_real_host_page_size);
try_map:
        r = qemu_vfio_dma_map(s->vfio,
                              qiov->iov[i].iov_base,
                              len, true, &iova);
        if (r == -ENOMEM && retry) {
            retry = false;
            trace_nvme_dma_flush_queue_wait(s);
            if (s->dma_map_count) {
                trace_nvme_dma_map_flush(s);
                qemu_co_queue_wait(&s->dma_flush_queue, &s->dma_map_lock);
            } else {
                r = qemu_vfio_dma_reset_temporary(s->vfio);
                if (r) {
                    goto fail;
                }
            }
            goto try_map;
        }
        if (r) {
            goto fail;
        }

        for (j = 0; j < qiov->iov[i].iov_len / s->page_size; j++) {
            pagelist[entries++] = cpu_to_le64(iova + j * s->page_size);
        }
        trace_nvme_cmd_map_qiov_iov(s, i, qiov->iov[i].iov_base,
                                    qiov->iov[i].iov_len / s->page_size);
    }

    s->dma_map_count += qiov->size;

    assert(entries <= s->page_size / sizeof(uint64_t));
    switch (entries) {
    case 0:
        abort();
    case 1:
        cmd->dptr.prp1 = pagelist[0];
        cmd->dptr.prp2 = 0;
        break;
    case 2:
        cmd->dptr.prp1 = pagelist[0];
        cmd->dptr.prp2 = pagelist[1];
        break;
    default:
        cmd->dptr.prp1 = pagelist[0];
        cmd->dptr.prp2 = cpu_to_le64(req->prp_list_iova + sizeof(uint64_t));
        break;
    }
    trace_nvme_cmd_map_qiov(s, cmd, req, qiov, entries);
    for (i = 0; i < entries; ++i) {
        trace_nvme_cmd_map_qiov_pages(s, i, pagelist[i]);
    }
    return 0;
fail:
    /* No need to unmap [0 - i) iovs even if we've failed, since we don't
     * increment s->dma_map_count. This is okay for fixed mapping memory areas
     * because they are already mapped before calling this function; for
     * temporary mappings, a later nvme_cmd_(un)map_qiov will reclaim by
     * calling qemu_vfio_dma_reset_temporary when necessary. */
    return r;
}

typedef struct {
    Coroutine *co;
    int ret;
    AioContext *ctx;
} NVMeCoData;

static void nvme_rw_cb_bh(void *opaque)
{
    NVMeCoData *data = opaque;
    qemu_coroutine_enter(data->co);
}

static void nvme_rw_cb(void *opaque, int ret)
{
    NVMeCoData *data = opaque;
    data->ret = ret;
    if (!data->co) {
        /* The rw coroutine hasn't yielded, don't try to enter. */
        return;
    }
    replay_bh_schedule_oneshot_event(data->ctx, nvme_rw_cb_bh, data);
}

static coroutine_fn int nvme_co_prw_aligned(BlockDriverState *bs,
                                            uint64_t offset, uint64_t bytes,
                                            QEMUIOVector *qiov,
                                            bool is_write,
                                            int flags)
{
    int r;
    BDRVNVMeState *s = bs->opaque;
    NVMeQueuePair *ioq = s->queues[INDEX_IO(0)];
    NVMeRequest *req;

    uint32_t cdw12 = (((bytes >> s->blkshift) - 1) & 0xFFFF) |
                       (flags & BDRV_REQ_FUA ? 1 << 30 : 0);
    NvmeCmd cmd = {
        .opcode = is_write ? NVME_CMD_WRITE : NVME_CMD_READ,
        .nsid = cpu_to_le32(s->nsid),
        .cdw10 = cpu_to_le32((offset >> s->blkshift) & 0xFFFFFFFF),
        .cdw11 = cpu_to_le32(((offset >> s->blkshift) >> 32) & 0xFFFFFFFF),
        .cdw12 = cpu_to_le32(cdw12),
    };
    NVMeCoData data = {
        .ctx = bdrv_get_aio_context(bs),
        .ret = -EINPROGRESS,
    };

    trace_nvme_prw_aligned(s, is_write, offset, bytes, flags, qiov->niov);
    assert(s->queue_count > 1);
    req = nvme_get_free_req(ioq);
    assert(req);

    qemu_co_mutex_lock(&s->dma_map_lock);
    r = nvme_cmd_map_qiov(bs, &cmd, req, qiov);
    qemu_co_mutex_unlock(&s->dma_map_lock);
    if (r) {
        nvme_put_free_req_and_wake(ioq, req);
        return r;
    }
    nvme_submit_command(ioq, req, &cmd, nvme_rw_cb, &data);

    data.co = qemu_coroutine_self();
    while (data.ret == -EINPROGRESS) {
        qemu_coroutine_yield();
    }

    qemu_co_mutex_lock(&s->dma_map_lock);
    r = nvme_cmd_unmap_qiov(bs, qiov);
    qemu_co_mutex_unlock(&s->dma_map_lock);
    if (r) {
        return r;
    }

    trace_nvme_rw_done(s, is_write, offset, bytes, data.ret);
    return data.ret;
}

static inline bool nvme_qiov_aligned(BlockDriverState *bs,
                                     const QEMUIOVector *qiov)
{
    int i;
    BDRVNVMeState *s = bs->opaque;

    for (i = 0; i < qiov->niov; ++i) {
        if (!QEMU_PTR_IS_ALIGNED(qiov->iov[i].iov_base,
                                 qemu_real_host_page_size) ||
            !QEMU_IS_ALIGNED(qiov->iov[i].iov_len, qemu_real_host_page_size)) {
            trace_nvme_qiov_unaligned(qiov, i, qiov->iov[i].iov_base,
                                      qiov->iov[i].iov_len, s->page_size);
            return false;
        }
    }
    return true;
}

static int nvme_co_prw(BlockDriverState *bs, uint64_t offset, uint64_t bytes,
                       QEMUIOVector *qiov, bool is_write, int flags)
{
    BDRVNVMeState *s = bs->opaque;
    int r;
    uint8_t *buf = NULL;
    QEMUIOVector local_qiov;
    size_t len = QEMU_ALIGN_UP(bytes, qemu_real_host_page_size);
    assert(QEMU_IS_ALIGNED(offset, s->page_size));
    assert(QEMU_IS_ALIGNED(bytes, s->page_size));
    assert(bytes <= s->max_transfer);
    if (nvme_qiov_aligned(bs, qiov)) {
        s->stats.aligned_accesses++;
        return nvme_co_prw_aligned(bs, offset, bytes, qiov, is_write, flags);
    }
    s->stats.unaligned_accesses++;
    trace_nvme_prw_buffered(s, offset, bytes, qiov->niov, is_write);
    buf = qemu_try_memalign(qemu_real_host_page_size, len);

    if (!buf) {
        return -ENOMEM;
    }
    qemu_iovec_init(&local_qiov, 1);
    if (is_write) {
        qemu_iovec_to_buf(qiov, 0, buf, bytes);
    }
    qemu_iovec_add(&local_qiov, buf, bytes);
    r = nvme_co_prw_aligned(bs, offset, bytes, &local_qiov, is_write, flags);
    qemu_iovec_destroy(&local_qiov);
    if (!r && !is_write) {
        qemu_iovec_from_buf(qiov, 0, buf, bytes);
    }
    qemu_vfree(buf);
    return r;
}

static coroutine_fn int nvme_co_preadv(BlockDriverState *bs,
                                       uint64_t offset, uint64_t bytes,
                                       QEMUIOVector *qiov, int flags)
{
    return nvme_co_prw(bs, offset, bytes, qiov, false, flags);
}

static coroutine_fn int nvme_co_pwritev(BlockDriverState *bs,
                                        uint64_t offset, uint64_t bytes,
                                        QEMUIOVector *qiov, int flags)
{
    return nvme_co_prw(bs, offset, bytes, qiov, true, flags);
}

static coroutine_fn int nvme_co_flush(BlockDriverState *bs)
{
    BDRVNVMeState *s = bs->opaque;
    NVMeQueuePair *ioq = s->queues[INDEX_IO(0)];
    NVMeRequest *req;
    NvmeCmd cmd = {
        .opcode = NVME_CMD_FLUSH,
        .nsid = cpu_to_le32(s->nsid),
    };
    NVMeCoData data = {
        .ctx = bdrv_get_aio_context(bs),
        .ret = -EINPROGRESS,
    };

    assert(s->queue_count > 1);
    req = nvme_get_free_req(ioq);
    assert(req);
    nvme_submit_command(ioq, req, &cmd, nvme_rw_cb, &data);

    data.co = qemu_coroutine_self();
    if (data.ret == -EINPROGRESS) {
        qemu_coroutine_yield();
    }

    return data.ret;
}


static coroutine_fn int nvme_co_pwrite_zeroes(BlockDriverState *bs,
                                              int64_t offset,
                                              int bytes,
                                              BdrvRequestFlags flags)
{
    BDRVNVMeState *s = bs->opaque;
    NVMeQueuePair *ioq = s->queues[INDEX_IO(0)];
    NVMeRequest *req;

    uint32_t cdw12 = ((bytes >> s->blkshift) - 1) & 0xFFFF;

    if (!s->supports_write_zeroes) {
        return -ENOTSUP;
    }

    NvmeCmd cmd = {
        .opcode = NVME_CMD_WRITE_ZEROES,
        .nsid = cpu_to_le32(s->nsid),
        .cdw10 = cpu_to_le32((offset >> s->blkshift) & 0xFFFFFFFF),
        .cdw11 = cpu_to_le32(((offset >> s->blkshift) >> 32) & 0xFFFFFFFF),
    };

    NVMeCoData data = {
        .ctx = bdrv_get_aio_context(bs),
        .ret = -EINPROGRESS,
    };

    if (flags & BDRV_REQ_MAY_UNMAP) {
        cdw12 |= (1 << 25);
    }

    if (flags & BDRV_REQ_FUA) {
        cdw12 |= (1 << 30);
    }

    cmd.cdw12 = cpu_to_le32(cdw12);

    trace_nvme_write_zeroes(s, offset, bytes, flags);
    assert(s->queue_count > 1);
    req = nvme_get_free_req(ioq);
    assert(req);

    nvme_submit_command(ioq, req, &cmd, nvme_rw_cb, &data);

    data.co = qemu_coroutine_self();
    while (data.ret == -EINPROGRESS) {
        qemu_coroutine_yield();
    }

    trace_nvme_rw_done(s, true, offset, bytes, data.ret);
    return data.ret;
}


static int coroutine_fn nvme_co_pdiscard(BlockDriverState *bs,
                                         int64_t offset,
                                         int bytes)
{
    BDRVNVMeState *s = bs->opaque;
    NVMeQueuePair *ioq = s->queues[INDEX_IO(0)];
    NVMeRequest *req;
    NvmeDsmRange *buf;
    QEMUIOVector local_qiov;
    int ret;

    NvmeCmd cmd = {
        .opcode = NVME_CMD_DSM,
        .nsid = cpu_to_le32(s->nsid),
        .cdw10 = cpu_to_le32(0), /*number of ranges - 0 based*/
        .cdw11 = cpu_to_le32(1 << 2), /*deallocate bit*/
    };

    NVMeCoData data = {
        .ctx = bdrv_get_aio_context(bs),
        .ret = -EINPROGRESS,
    };

    if (!s->supports_discard) {
        return -ENOTSUP;
    }

    assert(s->queue_count > 1);

    buf = qemu_try_memalign(s->page_size, s->page_size);
    if (!buf) {
        return -ENOMEM;
    }
    memset(buf, 0, s->page_size);
    buf->nlb = cpu_to_le32(bytes >> s->blkshift);
    buf->slba = cpu_to_le64(offset >> s->blkshift);
    buf->cattr = 0;

    qemu_iovec_init(&local_qiov, 1);
    qemu_iovec_add(&local_qiov, buf, 4096);

    req = nvme_get_free_req(ioq);
    assert(req);

    qemu_co_mutex_lock(&s->dma_map_lock);
    ret = nvme_cmd_map_qiov(bs, &cmd, req, &local_qiov);
    qemu_co_mutex_unlock(&s->dma_map_lock);

    if (ret) {
        nvme_put_free_req_and_wake(ioq, req);
        goto out;
    }

    trace_nvme_dsm(s, offset, bytes);

    nvme_submit_command(ioq, req, &cmd, nvme_rw_cb, &data);

    data.co = qemu_coroutine_self();
    while (data.ret == -EINPROGRESS) {
        qemu_coroutine_yield();
    }

    qemu_co_mutex_lock(&s->dma_map_lock);
    ret = nvme_cmd_unmap_qiov(bs, &local_qiov);
    qemu_co_mutex_unlock(&s->dma_map_lock);

    if (ret) {
        goto out;
    }

    ret = data.ret;
    trace_nvme_dsm_done(s, offset, bytes, ret);
out:
    qemu_iovec_destroy(&local_qiov);
    qemu_vfree(buf);
    return ret;

}


static int nvme_reopen_prepare(BDRVReopenState *reopen_state,
                               BlockReopenQueue *queue, Error **errp)
{
    return 0;
}

static void nvme_refresh_filename(BlockDriverState *bs)
{
    BDRVNVMeState *s = bs->opaque;

    snprintf(bs->exact_filename, sizeof(bs->exact_filename), "nvme://%s/%i",
             s->device, s->nsid);
}

static void nvme_refresh_limits(BlockDriverState *bs, Error **errp)
{
    BDRVNVMeState *s = bs->opaque;

    bs->bl.opt_mem_alignment = s->page_size;
    bs->bl.request_alignment = s->page_size;
    bs->bl.max_transfer = s->max_transfer;
}

static void nvme_detach_aio_context(BlockDriverState *bs)
{
    BDRVNVMeState *s = bs->opaque;

    for (unsigned i = 0; i < s->queue_count; i++) {
        NVMeQueuePair *q = s->queues[i];

        qemu_bh_delete(q->completion_bh);
        q->completion_bh = NULL;
    }

    aio_set_event_notifier(bdrv_get_aio_context(bs),
                           &s->irq_notifier[MSIX_SHARED_IRQ_IDX],
                           false, NULL, NULL);
}

static void nvme_attach_aio_context(BlockDriverState *bs,
                                    AioContext *new_context)
{
    BDRVNVMeState *s = bs->opaque;

    s->aio_context = new_context;
    aio_set_event_notifier(new_context, &s->irq_notifier[MSIX_SHARED_IRQ_IDX],
                           false, nvme_handle_event, nvme_poll_cb);

    for (unsigned i = 0; i < s->queue_count; i++) {
        NVMeQueuePair *q = s->queues[i];

        q->completion_bh =
            aio_bh_new(new_context, nvme_process_completion_bh, q);
    }
}

static void nvme_aio_plug(BlockDriverState *bs)
{
    BDRVNVMeState *s = bs->opaque;
    assert(!s->plugged);
    s->plugged = true;
}

static void nvme_aio_unplug(BlockDriverState *bs)
{
    BDRVNVMeState *s = bs->opaque;
    assert(s->plugged);
    s->plugged = false;
    for (unsigned i = INDEX_IO(0); i < s->queue_count; i++) {
        NVMeQueuePair *q = s->queues[i];
        qemu_mutex_lock(&q->lock);
        nvme_kick(q);
        nvme_process_completion(q);
        qemu_mutex_unlock(&q->lock);
    }
}

static void nvme_register_buf(BlockDriverState *bs, void *host, size_t size)
{
    int ret;
    BDRVNVMeState *s = bs->opaque;

    ret = qemu_vfio_dma_map(s->vfio, host, size, false, NULL);
    if (ret) {
        /* FIXME: we may run out of IOVA addresses after repeated
         * bdrv_register_buf/bdrv_unregister_buf, because nvme_vfio_dma_unmap
         * doesn't reclaim addresses for fixed mappings. */
        error_report("nvme_register_buf failed: %s", strerror(-ret));
    }
}

static void nvme_unregister_buf(BlockDriverState *bs, void *host)
{
    BDRVNVMeState *s = bs->opaque;

    qemu_vfio_dma_unmap(s->vfio, host);
}

static BlockStatsSpecific *nvme_get_specific_stats(BlockDriverState *bs)
{
    BlockStatsSpecific *stats = g_new(BlockStatsSpecific, 1);
    BDRVNVMeState *s = bs->opaque;

    stats->driver = BLOCKDEV_DRIVER_NVME;
    stats->u.nvme = (BlockStatsSpecificNvme) {
        .completion_errors = s->stats.completion_errors,
        .aligned_accesses = s->stats.aligned_accesses,
        .unaligned_accesses = s->stats.unaligned_accesses,
    };

    return stats;
}

static const char *const nvme_strong_runtime_opts[] = {
    NVME_BLOCK_OPT_DEVICE,
    NVME_BLOCK_OPT_NAMESPACE,

    NULL
};

static BlockDriver bdrv_nvme = {
    .format_name              = "nvme",
    .protocol_name            = "nvme",
    .instance_size            = sizeof(BDRVNVMeState),

    .bdrv_co_create_opts      = bdrv_co_create_opts_simple,
    .create_opts              = &bdrv_create_opts_simple,

    .bdrv_parse_filename      = nvme_parse_filename,
    .bdrv_file_open           = nvme_file_open,
    .bdrv_close               = nvme_close,
    .bdrv_getlength           = nvme_getlength,
    .bdrv_probe_blocksizes    = nvme_probe_blocksizes,

    .bdrv_co_preadv           = nvme_co_preadv,
    .bdrv_co_pwritev          = nvme_co_pwritev,

    .bdrv_co_pwrite_zeroes    = nvme_co_pwrite_zeroes,
    .bdrv_co_pdiscard         = nvme_co_pdiscard,

    .bdrv_co_flush_to_disk    = nvme_co_flush,
    .bdrv_reopen_prepare      = nvme_reopen_prepare,

    .bdrv_refresh_filename    = nvme_refresh_filename,
    .bdrv_refresh_limits      = nvme_refresh_limits,
    .strong_runtime_opts      = nvme_strong_runtime_opts,
    .bdrv_get_specific_stats  = nvme_get_specific_stats,

    .bdrv_detach_aio_context  = nvme_detach_aio_context,
    .bdrv_attach_aio_context  = nvme_attach_aio_context,

    .bdrv_io_plug             = nvme_aio_plug,
    .bdrv_io_unplug           = nvme_aio_unplug,

    .bdrv_register_buf        = nvme_register_buf,
    .bdrv_unregister_buf      = nvme_unregister_buf,
};

static void bdrv_nvme_init(void)
{
    bdrv_register(&bdrv_nvme);
}

block_init(bdrv_nvme_init);
