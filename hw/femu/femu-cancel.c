/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Cancel (Base 2.3, 7.1) with cancel=on: an I/O command that aborts the
 * commands of its own Submission Queue, one by CID or all of a namespace.
 *
 *   poller: fetch 18h --> checks --> fail: its CQE through the backlog
 *                                --> pass: cancel_list, cancel_bh
 *   cancel_bh, dataplane paused, each held Cancel in fetch order:
 *     look on the poller that owns the SQ:
 *       backlog, to_poller, pq, a held Cancel --> Command Abort
 *         Requested now (immediate abort, CMDA)
 *       to_ftl --> req->cancel (deferred abort, CEDA); the status
 *         changes when the request enters pq, after its FTL step
 *     its CQE goes through the backlog of that poller
 *
 * A request past its FTL step has moved its data and changed the mapping:
 * only its CQE is left, so an immediate abort leaves no effect after the
 * Cancel completes (5.2.1.1). Realize refuses the options that keep work
 * after that step: the write buffer, a mapping other than page (dirty
 * translation pages), cxl_ssd and ocp. A request in to_ftl keeps its FTL
 * step, so the mapping and the backend agree; only its status changes.
 * A Cancel that ran is not aborted by a later one: its effects exist.
 * NoSSD I/O that completes in the fetch sweep is never outstanding, so
 * a Cancel finds it only in a backlog.
 */

#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "qemu/main-loop.h"
#include "qapi/error.h"
#include "nvme.h"

/**
 * femu_cancel_check - validate cancel at realize
 * @n: the controller
 * @errp: set on a refusal
 *
 * One controller keeps every request of a queue on one poller. The
 * refused options keep work after the FTL step (see the file comment).
 */
bool femu_cancel_check(FemuCtrl *n, Error **errp)
{
    const char *map = n->bb_params.mapping_scheme;
    const char *why = NULL;

    if (!n->cancel) {
        return true;
    }
    if ((n->femu_mode != FEMU_BBSSD_MODE &&
         n->femu_mode != FEMU_NOSSD_MODE) || n->namespace_modes) {
        why = "a mode other than bbssd or NoSSD";
    } else if (n->subsys) {
        why = "a femu-subsys";
    } else if (n->bb_params.buffer_size > 0) {
        why = "buffer_size";
    } else if (n->femu_mode == FEMU_BBSSD_MODE && map && *map &&
               strcmp(map, "page")) {
        why = "a mapping other than page";
    } else if (n->cxl_dev) {
        why = "cxl_ssd";
    } else if (n->ocp) {
        why = "ocp";
    } else if (n->power_loss) {
        why = "power_loss";
    }
    if (why) {
        error_setg(errp, "femu: cancel is not supported with %s", why);
        return false;
    }
    return true;
}

/* the poller that owns @sq, as the sweep assigns queues */
static int femu_cancel_poller(FemuCtrl *n, NvmeSQueue *sq)
{
    return 1 + (sq->sqid - 1) % n->nr_pollers;
}

/*
 * The state of namespace @ns that fails I/O to it: an ANA state without
 * access (8.1.1), or a Sanitize Namespace in progress (8.1.26.5).
 */
static uint16_t femu_cancel_ns_state(FemuCtrl *n, NvmeNamespace *ns)
{
    if (unlikely(n->ana)) {
        uint16_t status = nvme_ana_io_check(n, ns);

        if (status) {
            return status;
        }
    }
    if (qatomic_read(&ns->san_busy)) {
        return NVME_SANITIZE_NS_IN_PROGRESS;
    }
    return NVME_SUCCESS;
}

/*
 * Cancel (Figures 590 and 591). NVME_NO_COMPLETE holds it for cancel_bh;
 * any other status is its result. The caller took the Abort and Sanitize
 * marks first, so a marked Cancel never runs.
 */
uint16_t femu_cancel_cmd(FemuCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    uint32_t nsid = le32_to_cpu(cmd->nsid);
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint16_t cid = dw10 >> 16;
    NvmeNamespace *ns;
    uint16_t status;

    if (cmd->fuse) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (nvme_sanitize_busy(n)) {
        return NVME_SANITIZE_IN_PROGRESS;
    }
    if (!nsid || (nsid != NVME_NSID_BROADCAST && nsid > n->namespace_limit)) {
        return NVME_INVALID_NSID | NVME_DNR;
    }
    if (nsid != NVME_NSID_BROADCAST) {
        ns = nvme_ns(n, nsid);
        if (!ns) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        status = femu_cancel_ns_state(n, ns);
        if (status) {
            return status;
        }
    }
    if ((dw10 & 0xffff) != req->sq->sqid) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    switch (le32_to_cpu(cmd->cdw11) & 0x3) {
    case 0x0:   /* Single Command Cancel */
        if (cid == le16_to_cpu(cmd->cid)) {
            return NVME_CANCEL_INVALID_CID | NVME_DNR;
        }
        break;
    case 0x1:   /* Multiple Command Cancel */
        if (cid != 0xffff) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        break;
    default:
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    return NVME_NO_COMPLETE;
}

/*
 * The poller that fetched Cancel @req: a held one waits for cancel_bh,
 * any other completes through the backlog, without the FTL.
 */
void femu_cancel_fetched(FemuCtrl *n, NvmeRequest *req, int poller)
{
    if (req->status != NVME_NO_COMPLETE) {
        QTAILQ_INSERT_TAIL(&n->cpl_backlog[poller], req, entry);
        return;
    }
    req->status = NVME_SUCCESS;
    qemu_mutex_lock(&n->cancel_lock);
    QTAILQ_INSERT_TAIL(&n->cancel_list, req, entry);
    qemu_mutex_unlock(&n->cancel_lock);
    qemu_bh_schedule(n->cancel_bh);
}

typedef QTAILQ_HEAD(, NvmeRequest) FemuCancelBatch;

typedef struct FemuCancelOp {
    NvmeRequest *c;             /* the Cancel */
    FemuCancelBatch *batch;     /* held Cancels, not run yet */
    int p;                      /* the poller that owns its SQ */
    bool single;
    uint16_t cid;
    uint32_t nsid;
    NvmeRequest *target;        /* single: the request found by CID */
    bool find;                  /* look only: set target, change nothing */
    uint32_t cmda;
    uint32_t ceda;
} FemuCancelOp;

static bool femu_cancel_match(FemuCancelOp *op, NvmeRequest *t)
{
    if (t == op->c || t->sq != op->c->sq) {
        return false;
    }
    if (op->find) {
        return le16_to_cpu(t->cqe.cid) == op->cid;
    }
    if (op->single) {
        return t == op->target;
    }
    return op->nsid == NVME_NSID_BROADCAST ||
           le32_to_cpu(t->cmd.nsid) == op->nsid;
}

/*
 * @t matches. In find mode record it; otherwise say whether to abort it:
 * a command that already failed keeps its status, and a Cancel that ran
 * keeps its effects.
 */
static bool femu_cancel_take(FemuCancelOp *op, NvmeRequest *t, bool held)
{
    if (op->find) {
        if (!op->target) {
            op->target = t;
        }
        return false;
    }
    return t->status == NVME_SUCCESS &&
           (held || t->cmd_opcode != NVME_CMD_CANCEL);
}

static void femu_cancel_abort(FemuCtrl *n, FemuCancelOp *op, NvmeRequest *t)
{
    int64_t now = femu_io_now(n);

    t->status = NVME_CMD_ABORT_REQ;
    t->cqe.res64 = 0;
    t->cancel = false;
    /*
     * It completes now, before the time its model gave it: the stage
     * times (io_stages) end at the abort, so they still add up.
     */
    if (t->expire_time > now) {
        t->expire_time = now;
    }
    op->cmda++;
}

/*
 * One pass over the requests of the Cancel's SQ. The backlog comes first,
 * so a request moved there by this pass is not seen twice.
 */
static void femu_cancel_walk(FemuCtrl *n, FemuCancelOp *op)
{
    struct rte_ring *done = n->use_ftl_thread ? n->to_poller[op->p] : NULL;
    struct rte_ring *ftl = n->to_ftl[op->p];
    union cq_req_list *backlog = &n->cpl_backlog[op->p];
    pqueue_t *pq = n->pq[op->p];
    NvmeRequest **kept;
    NvmeRequest *t;
    NvmeRequest *next;
    size_t count;
    size_t nkept;
    size_t i;

    QTAILQ_FOREACH(t, backlog, entry) {
        if (femu_cancel_match(op, t) && femu_cancel_take(op, t, false)) {
            femu_cancel_abort(n, op, t);
        }
    }
    /* past the FTL: abort now and complete through the backlog */
    count = done ? femu_ring_count(done) : 0;
    for (i = 0; i < count; i++) {
        int rc = femu_ring_dequeue(done, (void **)&t, 1);

        assert(rc == 1);
        if (femu_cancel_match(op, t) && femu_cancel_take(op, t, false)) {
            /* the poller stamps this when it takes the ring; Cancel does */
            if (n->stage_sets && !t->t_return) {
                t->t_return = femu_io_now(n);
            }
            femu_cancel_abort(n, op, t);
            nvme_req_release_ranges(t);
            QTAILQ_INSERT_TAIL(backlog, t, entry);
        } else {
            rc = femu_ring_enqueue(done, (void **)&t, 1);
            assert(rc == 1);
        }
    }
    count = pq ? pqueue_size(pq) : 0;
    kept = g_new(NvmeRequest *, count + 1);
    nkept = 0;
    while (pq && (t = pqueue_pop(pq))) {
        if (femu_cancel_match(op, t) && femu_cancel_take(op, t, false)) {
            femu_cancel_abort(n, op, t);
            nvme_req_release_ranges(t);
            QTAILQ_INSERT_TAIL(backlog, t, entry);
        } else {
            kept[nkept++] = t;
        }
    }
    for (i = 0; i < nkept; i++) {
        pqueue_insert(pq, kept[i]);
    }
    g_free(kept);
    /* a held Cancel has done nothing yet: it never runs */
    QTAILQ_FOREACH_SAFE(t, op->batch, entry, next) {
        if (femu_cancel_match(op, t) && femu_cancel_take(op, t, true)) {
            QTAILQ_REMOVE(op->batch, t, entry);
            femu_cancel_abort(n, op, t);
            QTAILQ_INSERT_TAIL(backlog, t, entry);
        }
    }
    /* before the FTL step: the step runs, then the status changes */
    count = femu_ring_count(ftl);
    for (i = 0; i < count; i++) {
        int rc = femu_ring_dequeue(ftl, (void **)&t, 1);

        assert(rc == 1);
        if (femu_cancel_match(op, t) && femu_cancel_take(op, t, false)) {
            t->cancel = true;
            op->ceda++;
        }
        rc = femu_ring_enqueue(ftl, (void **)&t, 1);
        assert(rc == 1);
    }
}

/* run Cancel @c with the dataplane paused; @batch holds the later ones */
static void femu_cancel_run(FemuCtrl *n, NvmeRequest *c,
                            FemuCancelBatch *batch)
{
    uint32_t dw10 = le32_to_cpu(c->cmd.cdw10);
    FemuCancelOp op = {
        .c = c,
        .batch = batch,
        .p = femu_cancel_poller(n, c->sq),
        .single = !(le32_to_cpu(c->cmd.cdw11) & 0x3),
        .cid = dw10 >> 16,
        .nsid = le32_to_cpu(c->cmd.nsid),
    };
    NvmeNamespace *ns;

    /* a sanitize or an ANA change may have come since the fetch */
    if (nvme_sanitize_busy(n)) {
        c->status = NVME_SANITIZE_IN_PROGRESS;
        return;
    }
    if (op.nsid != NVME_NSID_BROADCAST) {
        ns = nvme_ns(n, op.nsid);
        if (!ns) {
            c->status = NVME_INVALID_FIELD | NVME_DNR;
            return;
        }
        c->status = femu_cancel_ns_state(n, ns);
        if (c->status) {
            return;
        }
    }
    if (op.single) {
        /* find it, check its namespace, then change it (Figure 591) */
        op.find = true;
        femu_cancel_walk(n, &op);
        op.find = false;
        if (!op.target) {
            c->cqe.res64 = 0;
            return;
        }
        if (op.nsid != NVME_NSID_BROADCAST &&
            le32_to_cpu(op.target->cmd.nsid) != op.nsid) {
            c->status = NVME_INVALID_FIELD | NVME_DNR;
            return;
        }
    }
    femu_cancel_walk(n, &op);
    c->cqe.res64 = 0;
    c->cqe.n.result = cpu_to_le32(MIN(op.ceda, 0xffff) << 16 |
                                  MIN(op.cmda, 0xffff));
}

/* move every held Cancel to @batch; the caller paused the dataplane */
static void femu_cancel_detach(FemuCtrl *n, FemuCancelBatch *batch)
{
    NvmeRequest *t;

    qemu_mutex_lock(&n->cancel_lock);
    while ((t = QTAILQ_FIRST(&n->cancel_list))) {
        QTAILQ_REMOVE(&n->cancel_list, t, entry);
        QTAILQ_INSERT_TAIL(batch, t, entry);
    }
    qemu_mutex_unlock(&n->cancel_lock);
}

/*
 * The pause comes first: a poller may need cancel_lock to finish the
 * sweep that the pause waits for.
 */
static void femu_cancel_bh(void *opaque)
{
    FemuCtrl *n = opaque;
    FemuCancelBatch batch = QTAILQ_HEAD_INITIALIZER(batch);
    NvmeRequest *c;
    bool resume;

    resume = nvme_pause_pollers(n);
    femu_cancel_detach(n, &batch);
    while ((c = QTAILQ_FIRST(&batch))) {
        QTAILQ_REMOVE(&batch, c, entry);
        femu_cancel_run(n, c, &batch);
        QTAILQ_INSERT_TAIL(&n->cpl_backlog[femu_cancel_poller(n, c->sq)], c,
                           entry);
    }
    nvme_resume_pollers(n, resume);
}

/* the held Cancels of @sq go with it (the dataplane is paused) */
void femu_cancel_drop_sq(FemuCtrl *n, NvmeSQueue *sq)
{
    NvmeRequest *t;
    NvmeRequest *next;

    if (!n->cancel) {
        return;
    }
    qemu_mutex_lock(&n->cancel_lock);
    QTAILQ_FOREACH_SAFE(t, &n->cancel_list, entry, next) {
        if (t->sq == sq) {
            QTAILQ_REMOVE(&n->cancel_list, t, entry);
        }
    }
    qemu_mutex_unlock(&n->cancel_lock);
}

/*
 * Namespace @ns retires its requests with @status (the dataplane is
 * paused): a held Cancel that names it completes with that status and
 * never runs. One for all namespaces runs later and finds nothing there.
 */
void femu_cancel_retire_ns(FemuCtrl *n, NvmeNamespace *ns, uint16_t status)
{
    NvmeRequest *t;
    NvmeRequest *next;

    if (!n->cancel) {
        return;
    }
    qemu_mutex_lock(&n->cancel_lock);
    QTAILQ_FOREACH_SAFE(t, &n->cancel_list, entry, next) {
        if (le32_to_cpu(t->cmd.nsid) == ns->id) {
            QTAILQ_REMOVE(&n->cancel_list, t, entry);
            t->status = status;
            t->cqe.res64 = 0;
            QTAILQ_INSERT_TAIL(&n->cpl_backlog[femu_cancel_poller(n, t->sq)],
                               t, entry);
        }
    }
    qemu_mutex_unlock(&n->cancel_lock);
}

/*
 * qtest only: the requests that wait for their CQE in a ring or in pq.
 * Without an FTL thread the pollers read to_ftl, so it counts there.
 */
uint32_t femu_cancel_cpl_count(FemuCtrl *n)
{
    bool resume = nvme_pause_pollers(n);
    uint32_t sum = 0;

    for (int p = 1; n->pq && p <= n->nr_pollers; p++) {
        sum += n->pq[p] ? pqueue_size(n->pq[p]) : 0;
        if (n->use_ftl_thread && n->to_poller) {
            sum += femu_ring_count(n->to_poller[p]);
        } else if (n->to_ftl) {
            sum += femu_ring_count(n->to_ftl[p]);
        }
    }
    nvme_resume_pollers(n, resume);
    return sum;
}

void femu_cancel_init(FemuCtrl *n)
{
    qemu_mutex_init(&n->cancel_lock);
    QTAILQ_INIT(&n->cancel_list);
    n->cancel_bh = qemu_bh_new_guarded(femu_cancel_bh, n,
                                       &DEVICE(n)->mem_reentrancy_guard);
}

void femu_cancel_exit(FemuCtrl *n)
{
    if (n->cancel_bh) {
        qemu_bh_delete(n->cancel_bh);
        n->cancel_bh = NULL;
        qemu_mutex_destroy(&n->cancel_lock);
    }
}
