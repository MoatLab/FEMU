#include "qemu/osdep.h"
#include "qemu/thread.h"
#include "hw/block/block.h"
#include "hw/pci/msix.h"
#include "hw/pci/msi.h"
#include "qapi/visitor.h"
#include "qapi/error.h"
#include <sys/types.h>

#include <immintrin.h>
#include "nvme.h"

#include <unistd.h>
#include <sys/syscall.h>
#include "computation.h"
#include "computation.c"

extern uint64_t iscos_counter;
void computational_thread (void);

static void nvme_post_cqe(NvmeCQueue *cq, NvmeRequest *req)
{
    FemuCtrl *n = cq->ctrl;
    NvmeSQueue *sq = req->sq;
    NvmeCqe *cqe = &req->cqe;
    uint8_t phase = cq->phase;
    hwaddr addr;

    cqe->res64 = req->gcrt;

    if (n->print_log) {
        femu_debug("%s,req,lba:%lu,lat:%lu\n", n->devname, req->slba, req->reqlat);
    }

    if (!req->is_write && req->tifa_cmd_flag == 911 && n->print_log)
        femu_debug("%s,GCT,cqe->res64=%lu\n", n->devname, cqe->res64);
    if (req->gcrt) {
        /* Coperd: For TIFA, force error back to host */
        req->status = NVME_DNR;
        cqe->status = cpu_to_le16((req->status << 1) | phase);
    } else {
        cqe->status = cpu_to_le16((req->status << 1) | phase);
    }
    cqe->sq_id = cpu_to_le16(sq->sqid);
    cqe->sq_head = cpu_to_le16(sq->head);

    if (cq->phys_contig) {
        addr = cq->dma_addr + cq->tail * n->cqe_size;
        ((NvmeCqe *)cq->dma_addr_hva)[cq->tail] = *cqe;
    } else {
        addr = nvme_discontig(cq->prp_list, cq->tail, n->page_size, n->cqe_size);
        femu_nvme_addr_write(n, addr, (void *)cqe, sizeof(*cqe));
    }

    nvme_inc_cq_tail(cq);
}

static void nvme_process_cq_cpl(void *arg, int index_poller)
{
    FemuCtrl *n = (FemuCtrl *)arg;
    NvmeCQueue *cq = NULL;
    NvmeRequest *req = NULL;
    struct rte_ring *rp = n->to_ftl[index_poller];
    pqueue_t *pq = n->pq[index_poller];
    uint64_t now;
    int processed = 0;
    int rc;
    int i;

    if (n->femu_mode == FEMU_BLACKBOX_MODE) {
        rp = n->to_poller[index_poller];
    }

    while (femu_ring_count(rp)) {
        req = NULL;
        rc = femu_ring_dequeue(rp, (void *)&req, 1);
        if (rc != 1) {
            femu_err("dequeue from to_poller request failed\n");
        }
        assert(req);

        pqueue_insert(pq, req);
    }

    while ((req = pqueue_peek(pq))) {
        now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
        if (now < req->expire_time) {
            break;
        }

        cq = n->cq[req->sq->sqid];
        if (!cq->is_active)
            continue;
        nvme_post_cqe(cq, req);
        QTAILQ_INSERT_TAIL(&req->sq->req_list, req, entry);
        pqueue_pop(pq);
        processed++;
        n->nr_tt_ios++;
        if (now - req->expire_time >= 20000) {
            n->nr_tt_late_ios++;
            if (n->print_log) {
                femu_debug("%s,diff,pq.count=%lu,%" PRId64 ", %lu/%lu\n",
                        n->devname, pqueue_size(*(n->pq)), now - req->expire_time,
                        n->nr_tt_late_ios, n->nr_tt_ios);
            }
        }
        n->should_isr[req->sq->sqid] = true;
    }

    if (processed == 0)
        return;

    switch (n->multipoller_enabled) {
        case 1:
            nvme_isr_notify_io(n->cq[index_poller]);
            break;

        default:
            for (i = 1; i <= n->num_io_queues; i++) {
                if (n->should_isr[i]) {
                    nvme_isr_notify_io(n->cq[i]);
                    n->should_isr[i] = false;
                }
            }
            break;
    }
}

void computational_thread (void)
{
	printf("COMPUTATIONAL THREAD PID = %d\n", getpid());
	int fd_get = open ("computational_pipe_send", 0666);
	if (fd_get < 0) {
		perror("Opening send pipe Failed\n");
		exit (1);
	}

	int fd_put = open ("computational_pipe_recv", 0666);
	if (fd_put < 0) {
		perror("Opening send pipe Failed\n");
		exit (1);
	}

	char buf[4096];
        int ret;
	uint64_t counter;

        while (1)
        {
//		printf("comp thread - waiting to read\n");
                ret = read(fd_get, buf, 4096);
                if (ret < 0) {
                        printf("error reading in child\n");
                        exit (1);
                }
		#ifdef COUNTING
		counter = count_bits(buf);
		#endif
		#ifdef POINTER_CHASING
		counter = get_disk_pointer(buf);
		#endif
//		printf("comp thread - waiting to write\n");
                ret = write(fd_put, &counter, sizeof(counter));
//		printf("written\n");
        }
	return;
}

static void *nvme_poller(void *arg)
{
	FemuCtrl *n = ((NvmePollerThreadArgument *)arg)->n;
	int index = ((NvmePollerThreadArgument *)arg)->index;

	int computational_fd_send = 0;
	int computational_fd_recv = 0;

	pid_t child_pid;

	unlink("computational_pipe_send");
	unlink("computational_pipe_recv");

	int ret = mkfifo("computational_pipe_send", 0666);
	if (ret < 0 ) {
		printf("Creating Pipe Failed\n");
	}else {
		printf("Pipe Created\n");
	}

	ret = mkfifo("computational_pipe_recv", 0666);
	if (ret < 0 ) {
		printf("Creating Pipe Failed\n");
	}else {
		printf("Pipe Created\n");
	}

	if (n->computation_mode == FEMU_COMPUTE_ON) {
		printf("forking Computational Process...\n");
		child_pid = fork();

		if (child_pid == 0) {
			computational_thread();
		}
		else {
			computational_fd_send = open("computational_pipe_send", O_RDWR);
			if (computational_fd_send < 0) {
				printf("error opening computational_fd \n");
			}
			computational_fd_recv = open("computational_pipe_recv", O_RDWR);
			if (computational_fd_recv < 0) {
				printf("error opening computational_fd \n");
			}
		}
	}

	switch (n->multipoller_enabled) {
        case 1:
            while (1) {
                if ((!n->dataplane_started)) {
                    usleep(1000);
                    continue;
                }

                NvmeSQueue *sq = n->sq[index];
                NvmeCQueue *cq = n->cq[index];
                if (sq && sq->is_active && cq && cq->is_active) {
                    nvme_process_sq_io(sq, index, computational_fd_send, computational_fd_recv);
                }
                nvme_process_cq_cpl(n, index);
            }
            break;

        default:
            while (1) {
                if ((!n->dataplane_started)) {
                    usleep(1000);
                    continue;
                }

                for (int i = 1; i <= n->num_io_queues; i++) {
                    NvmeSQueue *sq = n->sq[i];
                    NvmeCQueue *cq = n->cq[i];
                    if (sq && sq->is_active && cq && cq->is_active) {
                        nvme_process_sq_io(sq, index, computational_fd_send, computational_fd_recv);
                    }
                }
                nvme_process_cq_cpl(n, index);
            }
            break;
	}

	printf("%s(): iscos_counter = %lu\n", __func__,iscos_counter);
	return NULL;
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

void femu_create_nvme_poller(FemuCtrl *n)
{
    n->should_isr = g_malloc0(sizeof(bool) * (n->num_io_queues + 1));

    n->num_poller = n->multipoller_enabled ? n->num_io_queues : 1;
    /* Coperd: we put NvmeRequest into these rings */
    n->to_ftl = malloc(sizeof(struct rte_ring *) * (n->num_poller + 1));
    for (int i = 1; i <= n->num_poller; i++) {
        n->to_ftl[i] = femu_ring_create(FEMU_RING_TYPE_MP_SC, FEMU_MAX_INF_REQS);
        if (!n->to_ftl[i]) {
            femu_err("failed to create ring (n->to_ftl) ...\n");
            abort();
        }
        assert(rte_ring_empty(n->to_ftl[i]));
    }
#if 1
    n->ssd.to_ftl = n->to_ftl;
    femu_debug("ssd->to_ftl=%p, n->to_ftl=%p\n", n->ssd.to_ftl, n->to_ftl);
#endif

    n->to_poller = malloc(sizeof(struct rte_ring *) * (n->num_poller + 1));
    for (int i = 1; i <= n->num_poller; i++) {
        n->to_poller[i] = femu_ring_create(FEMU_RING_TYPE_MP_SC, FEMU_MAX_INF_REQS);
        if (!n->to_poller[i]) {
            femu_err("failed to create ring (n->to_poller) ...\n");
            abort();
        }
        assert(rte_ring_empty(n->to_poller[i]));
    }
#if 1
    n->ssd.to_poller = n->to_poller;
    femu_debug("ssd->to_poller=%p, n->to_poller=%p\n", n->ssd.to_poller, n->to_poller);
#endif

    n->pq = malloc(sizeof(pqueue_t *) * (n->num_poller + 1));
    for (int i = 1; i <= n->num_poller; i++) {
        n->pq[i] = pqueue_init(FEMU_MAX_INF_REQS, cmp_pri, get_pri, set_pri, get_pos, set_pos);
        if (!n->pq[i]) {
            femu_err("failed to create pqueue (n->pq) ...\n");
            abort();
        }
    }

    n->poller = malloc(sizeof(QemuThread) * (n->num_poller + 1));
    NvmePollerThreadArgument *args = malloc(sizeof(NvmePollerThreadArgument) * (n->num_poller + 1));
    for (int i = 1; i <= n->num_poller; i++) {
        args[i].n = n;
        args[i].index = i;
        qemu_thread_create(&n->poller[i], "nvme-poller", nvme_poller, &args[i], QEMU_THREAD_JOINABLE);
        femu_debug("nvme-poller created ...\n");
    }
}

static void femu_destroy_nvme_poller(FemuCtrl *n)
{
    femu_debug("destroying NVMe poller !!\n");
    for (int i = 1; i <= n->num_poller; i++) {
        qemu_thread_join(&n->poller[i]);
    }
    for (int i = 1; i <= n->num_poller; i++) {
        pqueue_free(n->pq[i]);
        femu_ring_free(n->to_poller[i]);
        femu_ring_free(n->to_ftl[i]);
    }
    g_free(n->should_isr);
}

static int femu_rw_mem_backend_nossd(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)cmd;
    uint32_t nlb  = le16_to_cpu(rw->nlb) + 1;
    uint64_t slba = le64_to_cpu(rw->slba);
    uint64_t prp1 = le64_to_cpu(rw->prp1);
    uint64_t prp2 = le64_to_cpu(rw->prp2);
    const uint8_t lba_index = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    const uint8_t data_shift = ns->id_ns.lbaf[lba_index].ds;
    uint64_t data_size = (uint64_t)nlb << data_shift;
    uint64_t data_offset = slba << data_shift;

    hwaddr len = n->page_size;
    uint64_t iteration = data_size / len;
    /* Processing prp1 */
    void *buf = n->mbe.mem_backend + data_offset;
    bool is_write = (rw->opcode == NVME_CMD_WRITE) ? false : true;
    address_space_rw(&address_space_memory, prp1, MEMTXATTRS_UNSPECIFIED, buf, len, is_write);
    /* Processing prp2 and its list if exist */
    if (iteration == 2) {
        buf += len;
        address_space_rw(&address_space_memory, prp2, MEMTXATTRS_UNSPECIFIED, buf, len, is_write);
    } else if (iteration > 2) {
        uint64_t prp_list[n->max_prp_ents];
        femu_nvme_addr_read(n, prp2, (void *)prp_list, (iteration - 1) * sizeof(uint64_t));
        for (int i = 0; i < iteration - 1; i++) {
            buf += len;
            address_space_rw(&address_space_memory, prp_list[0], MEMTXATTRS_UNSPECIFIED, buf, len, is_write);
        }
    }

    return NVME_SUCCESS;
}

void nvme_post_cqes_io(void *opaque)
{
    NvmeCQueue *cq = opaque;
    NvmeRequest *req, *next;
    int64_t cur_time, ntt = 0;
    int processed = 0;

    QTAILQ_FOREACH_SAFE(req, &cq->req_list, entry, next) {
        if (nvme_cq_full(cq)) {
            break;
        }

        /*
         * Coperd: decide whether to return I/O based on its expire_time
         * Set a 5us grace time period as overhead of QEMU-to-guest is not
         * included in delay emulation (TODO: optimize this)
         */
        cur_time = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
        if (cq->cqid != 0 && cur_time < req->expire_time) {
            ntt = req->expire_time;
            break;
        }

        //QTAILQ_REMOVE(&cq->req_list, req, entry);
        nvme_post_cqe(cq, req);
        processed++;
    }

    if (ntt == 0) {
        ntt = qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + CQ_POLLING_PERIOD_NS;
    }

    /* Coperd: only interrupt guest when we "do" complete some I/Os */
    if (processed > 0) {
        nvme_isr_notify_io(cq);
    }
}

int nvme_found_in_str_list(NvmeDirStrNsStat *str_ns_stat, uint16_t dspec)
{
   int i;
   
   if (str_ns_stat->cnt == 0)
       return -1;
   
   for (i=0; i<str_ns_stat->cnt; i++)
       if (str_ns_stat->id[i] == dspec)
          return i;
   return -1;

}

void nvme_add_to_str_list(NvmeDirStrNsStat *str_ns_stat, uint16_t dspec)
{
   str_ns_stat->id[str_ns_stat->cnt] = dspec;
   str_ns_stat->cnt++;
}

void nvme_del_from_str_list(NvmeDirStrNsStat *str_ns_stat, int pos)
{
   int i;

   if (str_ns_stat->cnt == 0)
       return;
   str_ns_stat->cnt--;
   for (i=pos; i<str_ns_stat->cnt; i++)
       str_ns_stat->id[i] = str_ns_stat->id[i+1];
   str_ns_stat->id[str_ns_stat->cnt] = 0;
}

void nvme_update_str_stat(FemuCtrl *n, NvmeNamespace *ns, uint16_t dspec)
{
   NvmeDirStrNsStat *st = ns->str_ns_stat;
   if (dspec == 0) /* skip if normal write */
       return;
   if (nvme_found_in_str_list(st, dspec) < 0) { /* not found */
       /* delete the first if max out */
       if (n->str_sys_param->nsso == n->str_sys_param->msl) {
          ns->str_ns_param->nso--;
          n->str_sys_param->nsso--;
          nvme_del_from_str_list(st, 0);
       }
       nvme_add_to_str_list(st, dspec);
       ns->str_ns_param->nso++;
       n->str_sys_param->nsso++;
   }
   return;
}

static uint16_t nvme_rw(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req, int computational_fd_send, int computational_fd_recv)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)cmd;
    uint16_t ctrl = le16_to_cpu(rw->control);
    uint32_t nlb  = le16_to_cpu(rw->nlb) + 1;
    uint64_t slba = le64_to_cpu(rw->slba);
    uint64_t prp1 = le64_to_cpu(rw->prp1);
    uint64_t prp2 = le64_to_cpu(rw->prp2);
    uint16_t control = le16_to_cpu(rw->control);
    uint32_t dsmgmt = le32_to_cpu(rw->dsmgmt);
    uint8_t  dtype = (control >> 4) & 0xF;
    uint16_t dspec = (dsmgmt >> 16) & 0xFFFF;

    const uint8_t lba_index = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    const uint16_t ms = le16_to_cpu(ns->id_ns.lbaf[lba_index].ms);
    const uint8_t data_shift = ns->id_ns.lbaf[lba_index].ds;
    uint64_t data_size = (uint64_t)nlb << data_shift;
    uint64_t data_offset = slba << data_shift;
    uint64_t meta_size = nlb * ms;
    uint64_t elba = slba + nlb;
    uint16_t err;
    int ret;

    req->data_offset = data_offset;
    req->is_write = (rw->opcode == NVME_CMD_WRITE) ? 1 : 0;

    err = femu_nvme_rw_check_req(n, ns, cmd, req, slba, elba, nlb, ctrl, data_size,
            meta_size);
    if (err)
        return err;

    if (nvme_map_prp(&req->qsg, &req->iov, prp1, prp2, data_size, n)) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
                offsetof(NvmeRwCmd, prp1), 0, ns->id);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    assert((nlb << data_shift) == req->qsg.size);

    if (req->is_write) {
       femu_debug("%s, opcode:%#x, offset:%#lx, size:%#lx, dtype:%#x, dspec:%#x\n",
               __func__, rw->opcode, data_offset, data_size, dtype, dspec);
       if (dtype) {
		printf("dtype detected %d\n", dtype);
          nvme_update_str_stat(n, ns, dspec);
	}
    }

    req->slba = slba;
    req->meta_size = 0;
    req->status = NVME_SUCCESS;
    req->nlb = nlb;
    req->ns = ns;

    ret = femu_rw_mem_backend_bb(&n->mbe, &req->qsg, data_offset, req->is_write, computational_fd_send, computational_fd_recv);
    if (!ret) {
        return NVME_SUCCESS;
    }

    return NVME_DNR;
}

static uint16_t nvme_io_cmd(FemuCtrl *n, NvmeCmd *cmd, NvmeRequest *req, int computational_fd_send, int computational_fd_recv)
{
    NvmeNamespace *ns;
    uint32_t nsid = le32_to_cpu(cmd->nsid);

    if (nsid == 0 || nsid > n->num_namespaces) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ns = &n->namespaces[nsid - 1];

    switch (cmd->opcode) {
    case NVME_CMD_READ:
    case NVME_CMD_WRITE:
        if (n->femu_mode == FEMU_BLACKBOX_MODE) {
            	return nvme_rw(n, ns, cmd, req, computational_fd_send, computational_fd_recv);
	}
        else {
            	return femu_rw_mem_backend_nossd(n, ns, cmd);
	}

    case NVME_CMD_FLUSH:
        if (!n->id_ctrl.vwc || !n->features.volatile_wc) {
            return NVME_SUCCESS;
        }
        return nvme_flush(n, ns, cmd, req);

    case NVME_CMD_DSM:
        if (NVME_ONCS_DSM & n->oncs) {
            return nvme_dsm(n, ns, cmd, req);
        }
        return NVME_INVALID_OPCODE | NVME_DNR;

    case NVME_CMD_COMPARE:
        if (NVME_ONCS_COMPARE & n->oncs) {
            return nvme_compare(n, ns, cmd, req);
        }
        return NVME_INVALID_OPCODE | NVME_DNR;

    case NVME_CMD_WRITE_ZEROS:
        if (NVME_ONCS_WRITE_ZEROS & n->oncs) {
            return nvme_write_zeros(n, ns, cmd, req);
        }
        return NVME_INVALID_OPCODE | NVME_DNR;

    case NVME_CMD_WRITE_UNCOR:
        if (NVME_ONCS_WRITE_UNCORR & n->oncs) {
            return nvme_write_uncor(n, ns, cmd, req);
        }
        return NVME_INVALID_OPCODE | NVME_DNR;

    /* Coperd: FEMU OC command handling */
    case FEMU_OC12_CMD_PHYS_READ:
    case FEMU_OC12_CMD_PHYS_WRITE:
        return femu_oc12_rw(n, ns, cmd, req);
    case FEMU_OC12_CMD_ERASE_ASYNC:
        return femu_oc12_erase_async(n, ns, cmd, req);

    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

static void nvme_update_sq_eventidx(const NvmeSQueue *sq)
{
    if (sq->eventidx_addr_hva) {
        *((uint32_t *)(sq->eventidx_addr_hva)) = sq->tail;
        return;
    }

    if (sq->eventidx_addr) {
        femu_nvme_addr_write(sq->ctrl, sq->eventidx_addr, (void *)&sq->tail,
                sizeof(sq->tail));
    }
}

static inline void nvme_copy_cmd(NvmeCmd *dst, NvmeCmd *src)
{
#if defined(__AVX__)
    __m256i *d256 = (__m256i *)dst;
    const __m256i *s256 = (const __m256i *)src;

    _mm256_store_si256(&d256[0], _mm256_load_si256(&s256[0]));
    _mm256_store_si256(&d256[1], _mm256_load_si256(&s256[1]));
#elif defined(__SSE2__)
    __m128i *d128 = (__m128i *)dst;
    const __m128i *s128 = (const __m128i *)src;

    _mm_store_si128(&d128[0], _mm_load_si128(&s128[0]));
    _mm_store_si128(&d128[1], _mm_load_si128(&s128[1]));
    _mm_store_si128(&d128[2], _mm_load_si128(&s128[2]));
    _mm_store_si128(&d128[3], _mm_load_si128(&s128[3]));
#else
    *dst = *src;
#endif
}

void nvme_process_sq_io(void *opaque, int index_poller, int computational_fd_send, int computational_fd_recv)
{
    NvmeSQueue *sq = opaque;
    FemuCtrl *n = sq->ctrl;

    uint16_t status;
    hwaddr addr;
    NvmeCmd cmd;
    NvmeRequest *req;
    int processed = 0;

    nvme_update_sq_tail(sq);
    while (!(nvme_sq_empty(sq))) {
        if (sq->phys_contig) {
            addr = sq->dma_addr + sq->head * n->sqe_size;
            nvme_copy_cmd(&cmd, (void *)&(((NvmeCmd *)sq->dma_addr_hva)[sq->head]));
        } else {
            addr = nvme_discontig(sq->prp_list, sq->head, n->page_size,
                    n->sqe_size);
            femu_nvme_addr_read(n, addr, (void *)&cmd, sizeof(cmd));
        }
        nvme_inc_sq_head(sq);

        req = QTAILQ_FIRST(&sq->req_list);
        QTAILQ_REMOVE(&sq->req_list, req, entry);
        memset(&req->cqe, 0, sizeof(req->cqe));
        /* Coperd: record req->stime at earliest convenience */
        req->expire_time = req->stime = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
        req->cqe.cid = cmd.cid;

        if (n->print_log) {
            femu_debug("%s,cid:%d\n", __func__, cmd.cid);
        }

        /* Coperd: For TIFA */
        req->tifa_cmd_flag = ((NvmeRwCmd *)&cmd)->rsvd2;

        status = nvme_io_cmd(n, &cmd, req, computational_fd_send, computational_fd_recv);
        if (1 || status == NVME_SUCCESS) {
            req->status = status;

            int rc = femu_ring_enqueue(n->to_ftl[index_poller], (void *)&req, 1);
            if (rc != 1) {
                femu_err("enqueue failed, ret=%d\n", rc);
            }
        } else {
            femu_err("Error IO processed!\n");
        }

        processed++;
    }

    nvme_update_sq_eventidx(sq);
    sq->completed += processed;
}

static void nvme_clear_ctrl(FemuCtrl *n, bool shutdown)
{
    int i;

    /* Coperd: pause nvme poller at earliest convenience */
    n->dataplane_started = false;

    if (shutdown) {
        femu_debug("shutting down NVMe Controller ...\n");
    } else {
        femu_debug("disabling NVMe Controller ...\n");
    }

	printf("%s():iscos_counter = %lu\n", __func__,iscos_counter);

    if (shutdown) {
        femu_debug("%s,clear_guest_notifier\n", __func__);
        nvme_clear_guest_notifier(n);
    }

    for (i = 0; i <= n->num_io_queues; i++) {
        if (n->sq[i] != NULL) {
            nvme_free_sq(n->sq[i], n);
        }
    }
    for (i = 0; i <= n->num_io_queues; i++) {
        if (n->cq[i] != NULL) {
            nvme_free_cq(n->cq[i], n);
        }
    }

    n->bar.cc = 0;
    n->features.temp_thresh = 0x14d;
    n->temp_warn_issued = 0;
    n->dbs_addr = 0;
    n->dbs_addr_hva = 0;
    n->eis_addr = 0;
    n->eis_addr_hva = 0;
}

static int nvme_start_ctrl(FemuCtrl *n)
{
    uint32_t page_bits = NVME_CC_MPS(n->bar.cc) + 12;
    uint32_t page_size = 1 << page_bits;

    if (n->cq[0] || n->sq[0] || !n->bar.asq || !n->bar.acq ||
            n->bar.asq & (page_size - 1) || n->bar.acq & (page_size - 1) ||
            NVME_CC_MPS(n->bar.cc) < NVME_CAP_MPSMIN(n->bar.cap) ||
            NVME_CC_MPS(n->bar.cc) > NVME_CAP_MPSMAX(n->bar.cap) ||
            NVME_CC_IOCQES(n->bar.cc) < NVME_CTRL_CQES_MIN(n->id_ctrl.cqes) ||
            NVME_CC_IOCQES(n->bar.cc) > NVME_CTRL_CQES_MAX(n->id_ctrl.cqes) ||
            NVME_CC_IOSQES(n->bar.cc) < NVME_CTRL_SQES_MIN(n->id_ctrl.sqes) ||
            NVME_CC_IOSQES(n->bar.cc) > NVME_CTRL_SQES_MAX(n->id_ctrl.sqes) ||
            !NVME_AQA_ASQS(n->bar.aqa) || NVME_AQA_ASQS(n->bar.aqa) > 4095 ||
            !NVME_AQA_ACQS(n->bar.aqa) || NVME_AQA_ACQS(n->bar.aqa) > 4095) {
        return -1;
    }

    n->page_bits = page_bits;
    n->page_size = 1 << n->page_bits;
    n->max_prp_ents = n->page_size / sizeof(uint64_t);
    n->cqe_size = 1 << NVME_CC_IOCQES(n->bar.cc);
    n->sqe_size = 1 << NVME_CC_IOSQES(n->bar.cc);

    nvme_init_cq(&n->admin_cq, n, n->bar.acq, 0, 0,
            NVME_AQA_ACQS(n->bar.aqa) + 1, 1, 1);
    nvme_init_sq(&n->admin_sq, n, n->bar.asq, 0, 0,
            NVME_AQA_ASQS(n->bar.aqa) + 1, NVME_Q_PRIO_HIGH, 1);
    femu_debug("nvme_start_ctrl,created admin SQ/CQ success\n");

    return 0;
}

static void nvme_write_bar(FemuCtrl *n, hwaddr offset, uint64_t data,
    unsigned size)
{
    switch (offset) {
    case 0xc:
        n->bar.intms |= data & 0xffffffff;
        n->bar.intmc = n->bar.intms;
        break;
    case 0x10:
        n->bar.intms &= ~(data & 0xffffffff);
        n->bar.intmc = n->bar.intms;
        break;
    case 0x14:
        if (NVME_CC_EN(data) && !NVME_CC_EN(n->bar.cc)) {
            n->bar.cc = data;
            if (nvme_start_ctrl(n)) {
                n->bar.csts = NVME_CSTS_FAILED;
            } else {
                n->bar.csts = NVME_CSTS_READY;
            }
        } else if (!NVME_CC_EN(data) && NVME_CC_EN(n->bar.cc)) {
            nvme_clear_ctrl(n, false);
            n->bar.csts &= ~NVME_CSTS_READY;
        }
        if (NVME_CC_SHN(data) && !(NVME_CC_SHN(n->bar.cc))) {
            nvme_clear_ctrl(n, true);
            n->bar.cc = data;
            n->bar.csts |= NVME_CSTS_SHST_COMPLETE;
        } else if (!NVME_CC_SHN(data) && NVME_CC_SHN(n->bar.cc)) {
            n->bar.csts &= ~NVME_CSTS_SHST_COMPLETE;
            n->bar.cc = data;
        }
        break;
    case 0x24:
        n->bar.aqa = data & 0xffffffff;
        break;
    case 0x28:
        n->bar.asq = data;
        break;
    case 0x2c:
        n->bar.asq |= data << 32;
        break;
    case 0x30:
        n->bar.acq = data;
        break;
    case 0x34:
        n->bar.acq |= data << 32;
        break;
    default:
        break;
    }
}

static uint64_t nvme_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    FemuCtrl *n = (FemuCtrl *)opaque;
    uint8_t *ptr = (uint8_t *)&n->bar;
    uint64_t val = 0;

    if (addr < sizeof(n->bar)) {
        memcpy(&val, ptr + addr, size);
    }

    return val;
}

static void nvme_process_db_admin(FemuCtrl *n, hwaddr addr, int val)
{
    uint32_t qid;
    uint16_t new_val = val & 0xffff;
    NvmeSQueue *sq;

    if (((addr - 0x1000) >> (2 + n->db_stride)) & 1) {
        NvmeCQueue *cq;

        qid = (addr - (0x1000 + (1 << (2 + n->db_stride)))) >>
            (3 + n->db_stride);
        if (nvme_check_cqid(n, qid)) {
            return;
        }

        cq = n->cq[qid];
        if (new_val >= cq->size) {
            return;
        }

        cq->head = new_val;

        if (cq->tail != cq->head) {
            nvme_isr_notify_admin(cq);
        }
    } else {
        qid = (addr - 0x1000) >> (3 + n->db_stride);
        if (nvme_check_sqid(n, qid)) {
            return;
        }
        sq = n->sq[qid];
        if (new_val >= sq->size) {
            return;
        }

        sq->tail = new_val;
        nvme_process_sq_admin(sq);
    }
}

static void nvme_process_db_io(FemuCtrl *n, hwaddr addr, int val)
{
    uint32_t qid;
    uint16_t new_val = val & 0xffff;
    NvmeSQueue *sq;

    if (n->dataplane_started) {
        return;
    }

    if (addr & ((1 << (2 + n->db_stride)) - 1)) {
        return;
    }

    if (((addr - 0x1000) >> (2 + n->db_stride)) & 1) {
        NvmeCQueue *cq;

        qid = (addr - (0x1000 + (1 << (2 + n->db_stride)))) >>
            (3 + n->db_stride);
        if (nvme_check_cqid(n, qid)) {
            return;
        }

        cq = n->cq[qid];
        if (new_val >= cq->size) {
            return;
        }

        if (!cq->db_addr) {
            cq->head = new_val;
        }

        if (cq->tail != cq->head) {
            nvme_isr_notify_io(cq);
        }
    } else {
        qid = (addr - 0x1000) >> (3 + n->db_stride);
        if (nvme_check_sqid(n, qid)) {
            return;
        }
        sq = n->sq[qid];
        if (new_val >= sq->size) {
            return;
        }

        if (!sq->db_addr) {
            sq->tail = new_val;
        }
    }
}

static void nvme_mmio_write(void *opaque, hwaddr addr, uint64_t data,
        unsigned size)
{
    FemuCtrl *n = (FemuCtrl *)opaque;
    if (addr < sizeof(n->bar)) {
        nvme_write_bar(n, addr, data, size);
    } else if (addr >= 0x1000 && addr < 0x1008) {
        nvme_process_db_admin(n, addr, data);
    } else {
        nvme_process_db_io(n, addr, data);
    }
}

static const MemoryRegionOps nvme_cmb_ops = {
    .read = nvme_cmb_read,
    .write = nvme_cmb_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 2,
        .max_access_size = 8,
    },
};

static const MemoryRegionOps nvme_mmio_ops = {
    .read = nvme_mmio_read,
    .write = nvme_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 2,
        .max_access_size = 8,
    },
};

static int nvme_check_constraints(FemuCtrl *n)
{
    /* FEMU doesn't depend on image file: !(n->conf.blk), !(n->serial) || */
    if ((n->num_namespaces == 0 || n->num_namespaces > NVME_MAX_NUM_NAMESPACES)
        || (n->num_io_queues < 1 || n->num_io_queues > NVME_MAX_QS) ||
        (n->db_stride > NVME_MAX_STRIDE) ||
        (n->max_q_ents < 1) ||
        (n->max_sqes > NVME_MAX_QUEUE_ES || n->max_cqes > NVME_MAX_QUEUE_ES ||
            n->max_sqes < NVME_MIN_SQUEUE_ES || n->max_cqes < NVME_MIN_CQUEUE_ES) ||
        (n->vwc > 1 || n->intc > 1 || n->cqr > 1 || n->extended > 1) ||
        (n->nlbaf > 16) ||
        (n->lba_index >= n->nlbaf) ||
        (n->meta && !n->mc) ||
        (n->extended && !(NVME_ID_NS_MC_EXTENDED(n->mc))) ||
        (!n->extended && n->meta && !(NVME_ID_NS_MC_SEPARATE(n->mc))) ||
        (n->dps && n->meta < 8) ||
        (n->dps && ((n->dps & DPS_FIRST_EIGHT) &&
            !NVME_ID_NS_DPC_FIRST_EIGHT(n->dpc))) ||
        (n->dps && !(n->dps & DPS_FIRST_EIGHT) &&
            !NVME_ID_NS_DPC_LAST_EIGHT(n->dpc)) ||
        (n->dps & DPS_TYPE_MASK && !((n->dpc & NVME_ID_NS_DPC_TYPE_MASK) &
            (1 << ((n->dps & DPS_TYPE_MASK) - 1)))) ||
        (n->mpsmax > 0xf || n->mpsmax > n->mpsmin) ||
        (n->oacs & ~(NVME_OACS_FORMAT)) ||
        (n->oncs & ~(NVME_ONCS_COMPARE | NVME_ONCS_WRITE_UNCORR |
            NVME_ONCS_DSM | NVME_ONCS_WRITE_ZEROS))) {
        return -1;
    }

    return 0;
}

uint64_t ns_blks(NvmeNamespace *ns, uint8_t lba_idx)
{
    FemuCtrl *n = ns->ctrl;
    NvmeIdNs *id_ns = &ns->id_ns;
    uint64_t ns_size = n->ns_size;

    uint32_t lba_ds = (1 << id_ns->lbaf[lba_idx].ds);
    uint32_t lba_sz = lba_ds + n->meta;

    femu_debug("ns_size=%ld,lba_ds=%d,lba_sz=%d\n", ns_size, lba_ds, lba_sz);
    return ns_size / lba_sz;
}

static uint64_t ns_bdrv_blks(NvmeNamespace *ns, uint64_t blks, uint8_t lba_idx)
{
    NvmeIdNs *id_ns = &ns->id_ns;

    return blks << (id_ns->lbaf[lba_idx].ds - BDRV_SECTOR_BITS);
}

void nvme_partition_ns(NvmeNamespace *ns, uint8_t lba_idx)
{
    FemuCtrl *n = ns->ctrl;
    NvmeIdNs *id_ns = &ns->id_ns;
    uint64_t blks;
    uint64_t bdrv_blks;

    blks = ns->ns_blks;
    bdrv_blks = ns_bdrv_blks(ns, ns->ns_blks, lba_idx);

    if (OCSSD(n)) {
        ns->tbl_dsk_start_offset = (ns->start_block + bdrv_blks) << BDRV_SECTOR_BITS;
        ns->tbl_entries = blks;
        if (ns->tbl) {
            g_free(ns->tbl);
        }
        ns->tbl = qemu_memalign(4096, femu_oc12_tbl_size(ns));
        femu_oc12_tbl_initialize(ns);
    } else {
        ns->tbl = NULL;
        ns->tbl_entries = 0;
    }

    id_ns->nuse = id_ns->ncap = id_ns->nsze = cpu_to_le64(blks);
    ns->meta_start_offset =
        ((ns->start_block + bdrv_blks) << BDRV_SECTOR_BITS) + femu_oc12_tbl_size(ns);

    if (ns->util)
        g_free(ns->util);
    ns->util = bitmap_new(blks);
    if (ns->uncorrectable)
        g_free(ns->uncorrectable);
    ns->uncorrectable = bitmap_new(blks);
}

static void nvme_init_namespaces(FemuCtrl *n)
{
	NvmeIdCtrl *id = &n->id_ctrl;
    int i, j, k;
    int ji = n->meta ? 2 : 1;

    for (i = 0; i < n->num_namespaces; i++) {
        uint64_t blks;
        int lba_index;
        NvmeNamespace *ns = &n->namespaces[i];
        NvmeIdNs *id_ns = &ns->id_ns;

        id_ns->nsfeat = 0x0;
        id_ns->nlbaf = n->nlbaf - 1;
        id_ns->flbas = n->lba_index | (n->extended << 4);
        id_ns->mc = n->mc;
        id_ns->dpc = n->dpc;
        id_ns->dps = n->dps;

        if (OCSSD(n)) {
            id_ns->vs[0] = 0x1;
        }

        for (j = 0; j < ji; j++) {
            for (k = 0; k < n->nlbaf / ji; k++) {
                id_ns->lbaf[k + (n->nlbaf / ji) * j].ds = BDRV_SECTOR_BITS + k;
                if (j) {
                    id_ns->lbaf[k + (n->nlbaf / ji)].ms = cpu_to_le16(n->meta);
                }
            }
        }

        lba_index = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
        blks = n->ns_size / ((1 << id_ns->lbaf[lba_index].ds));
        id_ns->nuse = id_ns->ncap = id_ns->nsze = cpu_to_le64(blks);

        ns->id = i + 1;
        ns->ctrl = n;
        ns->start_block = i * n->ns_size >> BDRV_SECTOR_BITS;
        ns->ns_blks = ns_blks(ns, lba_index);
        ns->util = bitmap_new(blks);
        ns->uncorrectable = bitmap_new(blks);
        nvme_partition_ns(ns, lba_index);

        if (id->oacs & NVME_OACS_DIR) {
            ns->id_dir = g_new0(NvmeDirId, 1);
            ns->id_dir->dir_support[0] = NVME_DIR_IDF_IDENTIFY | NVME_DIR_IDF_STREAMS;
            ns->id_dir->dir_enable[0] = NVME_DIR_IDF_IDENTIFY;
            ns->str_ns_param = g_new0(NvmeDirStrParam, 1);
            ns->str_ns_param->sws = cpu_to_le32(32);
            ns->str_ns_param->sgs = cpu_to_le16(36864);
            ns->str_ns_param->nsa = 0;
            ns->str_ns_param->nso = 0;
            ns->str_ns_stat = g_new0(NvmeDirStrNsStat, 1);
            ns->str_ns_stat->cnt = 0;
        }
    }
}

/* Coperd: info shown in "nvme list" */
static void femu_set_ctrl_info(FemuCtrl *n)
{
    static int fsid_voc = 0;
    static int fsid_vssd = 0;

    NvmeIdCtrl *id = &n->id_ctrl;
    char serial[20], tmp[4];
    const char *vocssd_mn = "FEMU OpenChannel-SSD Controller";
    const char *vssd_mn   = "FEMU BlackBox-SSD Controller";
    const char *vocssd_sn = "vOCSSD";
    const char *vssd_sn   = "vSSD";

    memset(serial, 0, 20);
    if (n->femu_mode == FEMU_WHITEBOX_MODE) {
        sprintf(tmp, "%d", fsid_voc);
        fsid_voc++;
        strcat(serial, vocssd_sn);
        strcat(serial, tmp);
        strpadcpy((char *)id->mn, sizeof(id->mn), vocssd_mn, ' ');
    } else {
        sprintf(tmp, "%d", fsid_vssd);
        fsid_vssd++;
        strcat(serial, vssd_sn);
        strcat(serial, tmp);
        strpadcpy((char *)id->mn, sizeof(id->mn), vssd_mn, ' ');
    }

    memset(n->devname, 0, 64);
    strcpy(n->devname, serial);

    strpadcpy((char *)id->sn, sizeof(id->sn), serial, ' ');
    strpadcpy((char *)id->fr, sizeof(id->fr), "1.0", ' ');
}

static void nvme_init_ctrl(FemuCtrl *n)
{
    NvmeIdCtrl *id = &n->id_ctrl;
    uint8_t *pci_conf = n->parent_obj.config;
    int i;

    id->vid = cpu_to_le16(pci_get_word(pci_conf + PCI_VENDOR_ID));
    id->ssvid = cpu_to_le16(pci_get_word(pci_conf + PCI_SUBSYSTEM_VENDOR_ID));

    femu_set_ctrl_info(n);

    id->rab = 6;
    id->ieee[0] = 0x00;
    id->ieee[1] = 0x02;
    id->ieee[2] = 0xb3;
    id->cmic = 0;
    id->mdts = n->mdts;
//  id->oacs = cpu_to_le16(n->oacs | NVME_OACS_DBBUF);
	if (n->computation_mode) {
		id->oacs = cpu_to_le16(n->oacs | NVME_OACS_DBBUF | NVME_OACS_DIR);
	}else {
		id->oacs = cpu_to_le16(n->oacs | NVME_OACS_DBBUF);
	}
    id->acl = n->acl;
    id->aerl = n->aerl;
    id->frmw = 7 << 1 | 1;
    id->lpa = 0 << 0;
    id->elpe = n->elpe;
    id->npss = 0;
    id->sqes = (n->max_sqes << 4) | 0x6;
    id->cqes = (n->max_cqes << 4) | 0x4;
    id->nn = cpu_to_le32(n->num_namespaces);
    id->oncs = cpu_to_le16(n->oncs);
    id->fuses = cpu_to_le16(0);
    id->fna = 0;
    id->vwc = n->vwc;
    id->awun = cpu_to_le16(0);
    id->awupf = cpu_to_le16(0);
    id->psd[0].mp = cpu_to_le16(0x9c4);
    id->psd[0].enlat = cpu_to_le32(0x10);
    id->psd[0].exlat = cpu_to_le32(0x4);
	strpadcpy((char *)id->fr, sizeof(id->fr), "1.3", ' ');

    if (id->oacs & NVME_OACS_DIR) {
       n->str_sys_param = g_new0(NvmeDirStrParam, 1);
       n->str_sys_param->msl = cpu_to_le16(8);
       n->str_sys_param->nssa = cpu_to_le16(8);
       n->str_sys_param->nsso = 0;
    }

    n->features.arbitration     = 0x1f0f0706;
    n->features.power_mgmt      = 0;
    n->features.temp_thresh     = 0x14d;
    n->features.err_rec         = 0;
    n->features.volatile_wc     = n->vwc;
    n->features.num_io_queues   = (n->num_io_queues - 1) |
        ((n->num_io_queues - 1) << 16);
    n->features.int_coalescing  = n->intc_thresh | (n->intc_time << 8);
    n->features.write_atomicity = 0;
    n->features.async_config    = 0x0;
    n->features.sw_prog_marker  = 0;

    for (i = 0; i <= n->num_io_queues; i++) {
        n->features.int_vector_config[i] = i | (n->intc << 16);
    }

    n->bar.cap = 0;
    NVME_CAP_SET_MQES(n->bar.cap, n->max_q_ents);
    NVME_CAP_SET_CQR(n->bar.cap, n->cqr);
    NVME_CAP_SET_AMS(n->bar.cap, 1);
    NVME_CAP_SET_TO(n->bar.cap, 0xf);
    NVME_CAP_SET_DSTRD(n->bar.cap, n->db_stride);
    NVME_CAP_SET_NSSRS(n->bar.cap, 0);
    NVME_CAP_SET_CSS(n->bar.cap, 1);
    if (OCSSD(n)) {
        NVME_CAP_SET_FEMU_OC12(n->bar.cap, 1);
    }

    NVME_CAP_SET_MPSMIN(n->bar.cap, n->mpsmin);
    NVME_CAP_SET_MPSMAX(n->bar.cap, n->mpsmax);

    if (n->cmbsz)
        n->bar.vs = 0x00010200;
    else
        n->bar.vs = 0x00010100;
    n->bar.intmc = n->bar.intms = 0;
    n->temperature = NVME_TEMPERATURE;
}

static void nvme_init_cmb(FemuCtrl *n)
{
    n->bar.cmbloc = n->cmbloc;
    n->bar.cmbsz  = n->cmbsz;

    n->cmbuf = g_malloc0(NVME_CMBSZ_GETSIZE(n->bar.cmbsz));
    memory_region_init_io(&n->ctrl_mem, OBJECT(n), &nvme_cmb_ops, n, "nvme-cmb",
            NVME_CMBSZ_GETSIZE(n->bar.cmbsz));
    pci_register_bar(&n->parent_obj, NVME_CMBLOC_BIR(n->bar.cmbloc),
            PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64,
            &n->ctrl_mem);
}

static void nvme_init_pci(FemuCtrl *n)
{
    uint8_t *pci_conf = n->parent_obj.config;

    pci_conf[PCI_INTERRUPT_PIN] = 1;
    /* Coperd: QEMU-OCSSD(0x1d1d,0x1f1f), QEMU-NVMe(0x8086,0x5845) */
    pci_config_set_prog_interface(pci_conf, 0x2);
    pci_config_set_vendor_id(pci_conf, n->vid);
    pci_config_set_device_id(pci_conf, n->did);
    pci_config_set_class(pci_conf, PCI_CLASS_STORAGE_EXPRESS);
    pcie_endpoint_cap_init(&n->parent_obj, 0x80);

    memory_region_init_io(&n->iomem, OBJECT(n), &nvme_mmio_ops, n, "nvme",
            n->reg_size);
    pci_register_bar(&n->parent_obj, 0,
            PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64,
            &n->iomem);
    msix_init_exclusive_bar(&n->parent_obj, n->num_io_queues, 4, NULL);
    msi_init(&n->parent_obj, 0x50, 32, true, false, NULL);

    if (n->cmbsz) {
        nvme_init_cmb(n);
    }
}

static void femu_realize(PCIDevice *pci_dev, Error **errp)
{
    FemuCtrl *n = FEMU(pci_dev);
    int64_t bs_size;

    nvme_check_size();

    if (nvme_check_constraints(n)) {
        return;
    }

    bs_size = ((int64_t)n->memsz) * 1024 * 1024;

    femu_init_mem_backend(&n->mbe, bs_size);
    n->mbe.femu_mode = n->femu_mode;
	n->mbe.computation_mode = n->computation_mode;
	n->mbe.flash_read_latency = n->flash_read_latency;
	n->mbe.flash_write_latency = n->flash_write_latency;

    n->completed = 0;
    n->start_time = time(NULL);
    n->reg_size = pow2ceil(0x1004 + 2 * (n->num_io_queues + 1) * 4);
    n->ns_size = bs_size / (uint64_t)n->num_namespaces;

    /* Coperd: [1..num_io_queues] are used for IO queues */
    n->sq = g_malloc0(sizeof(*n->sq) * (n->num_io_queues + 1));
    n->cq = g_malloc0(sizeof(*n->cq) * (n->num_io_queues + 1));
    n->namespaces = g_malloc0(sizeof(*n->namespaces) * n->num_namespaces);
    n->elpes = g_malloc0((n->elpe + 1) * sizeof(*n->elpes));
    n->aer_reqs = g_malloc0((n->aerl + 1) * sizeof(*n->aer_reqs));
    n->features.int_vector_config = g_malloc0((n->num_io_queues + 1) *
            sizeof(*n->features.int_vector_config));

    nvme_init_pci(n);
    nvme_init_ctrl(n);
    nvme_init_namespaces(n);

    if (OCSSD(n)) {
        femu_debug("starting in OCSSD mode ..\n");
        femu_oc12_init(n);
    } else if (BBSSD(n)) {
        struct ssd *ssd = &(n->ssd);
        memset(ssd, 0, sizeof(struct ssd));
        ssd->dataplane_started_ptr = &n->dataplane_started;
        ssd->ssdname = (char *)n->devname;
        femu_debug("starting in blackbox SSD mode ..\n");
        ssd_init(n);
    }
}

static void femu_exit(PCIDevice *pci_dev)
{
    FemuCtrl *n = FEMU(pci_dev);

	NvmeNamespace *ns = n->namespaces;
    int i;

    for (i = 0; i < n->num_namespaces; i++) {
        g_free(ns->id_dir);
        g_free(ns->str_ns_param);
        g_free(ns->str_ns_stat);
       ns++;
    }

    femu_debug("femu_exit starting!\n");

    nvme_clear_ctrl(n, true);

    femu_destroy_nvme_poller(n);
    femu_destroy_mem_backend(&n->mbe);

    g_free(n->namespaces);
	g_free(n->str_sys_param);
    g_free(n->features.int_vector_config);
    g_free(n->aer_reqs);
    g_free(n->elpes);
    g_free(n->cq);
    g_free(n->sq);
    msix_uninit_exclusive_bar(pci_dev);
    memory_region_unref(&n->iomem);
    if (n->cmbsz) {
        memory_region_unref(&n->ctrl_mem);
    }

    if (n->femu_mode == FEMU_WHITEBOX_MODE) {
        femu_oc12_exit(n);
    }
}

static Property femu_props[] = {
    DEFINE_PROP_STRING("serial", FemuCtrl, serial),
    DEFINE_PROP_UINT32("devsz_mb", FemuCtrl, memsz, 1024), /* Coperd: in MB */
    DEFINE_PROP_UINT32("namespaces", FemuCtrl, num_namespaces, 1),
    DEFINE_PROP_UINT32("queues", FemuCtrl, num_io_queues, 1),
    DEFINE_PROP_UINT32("entries", FemuCtrl, max_q_ents, 0x7ff),
    DEFINE_PROP_UINT8("multipoller_enabled", FemuCtrl, multipoller_enabled, 0),
    DEFINE_PROP_UINT8("max_cqes", FemuCtrl, max_cqes, 0x4),
    DEFINE_PROP_UINT8("max_sqes", FemuCtrl, max_sqes, 0x6),
    DEFINE_PROP_UINT8("stride", FemuCtrl, db_stride, 0),
    DEFINE_PROP_UINT8("aerl", FemuCtrl, aerl, 3),
    DEFINE_PROP_UINT8("acl", FemuCtrl, acl, 3),
    DEFINE_PROP_UINT8("elpe", FemuCtrl, elpe, 3),
    DEFINE_PROP_UINT8("mdts", FemuCtrl, mdts, 10),
    DEFINE_PROP_UINT8("cqr", FemuCtrl, cqr, 1),
    DEFINE_PROP_UINT8("vwc", FemuCtrl, vwc, 0),
    DEFINE_PROP_UINT8("intc", FemuCtrl, intc, 0),
    DEFINE_PROP_UINT8("intc_thresh", FemuCtrl, intc_thresh, 0),
    DEFINE_PROP_UINT8("intc_time", FemuCtrl, intc_time, 0),
    DEFINE_PROP_UINT8("mpsmin", FemuCtrl, mpsmin, 0),
    DEFINE_PROP_UINT8("mpsmax", FemuCtrl, mpsmax, 0),
    DEFINE_PROP_UINT8("nlbaf", FemuCtrl, nlbaf, 5),
    DEFINE_PROP_UINT8("lba_index", FemuCtrl, lba_index, 0),
    DEFINE_PROP_UINT8("extended", FemuCtrl, extended, 0),
    DEFINE_PROP_UINT8("dpc", FemuCtrl, dpc, 0),
    DEFINE_PROP_UINT8("dps", FemuCtrl, dps, 0),
    DEFINE_PROP_UINT8("mc", FemuCtrl, mc, 0),
    DEFINE_PROP_UINT8("meta", FemuCtrl, meta, 0),
    DEFINE_PROP_UINT32("cmbsz", FemuCtrl, cmbsz, 0),
    DEFINE_PROP_UINT32("cmbloc", FemuCtrl, cmbloc, 0),
    DEFINE_PROP_UINT16("oacs", FemuCtrl, oacs, NVME_OACS_FORMAT),
    DEFINE_PROP_UINT16("oncs", FemuCtrl, oncs, NVME_ONCS_DSM),
    DEFINE_PROP_UINT16("vid", FemuCtrl, vid, 0x1d1d),
    DEFINE_PROP_UINT16("did", FemuCtrl, did, 0x1f1f),
    DEFINE_PROP_UINT8("femu_mode", FemuCtrl, femu_mode, FEMU_DEF_NOSSD_MODE),
    DEFINE_PROP_UINT8("computation_mode", FemuCtrl, computation_mode, FEMU_DEF_NOCOMPUTATION_MODE),
    DEFINE_PROP_UINT32("flash_read_latency", FemuCtrl, flash_read_latency, 0),
    DEFINE_PROP_UINT32("flash_write_latency", FemuCtrl, flash_write_latency, 0),
    DEFINE_PROP_UINT16("lsec_size", FemuCtrl, femu_oc12_ctrl.params.sec_size, 4096),
    DEFINE_PROP_UINT8("lsecs_per_pg", FemuCtrl, femu_oc12_ctrl.params.sec_per_pg, 1),
    DEFINE_PROP_UINT16("lpgs_per_blk", FemuCtrl, femu_oc12_ctrl.params.pgs_per_blk, 256),
    DEFINE_PROP_UINT8("lmax_sec_per_rq", FemuCtrl, femu_oc12_ctrl.params.max_sec_per_rq, 64),
    DEFINE_PROP_UINT8("lnum_ch", FemuCtrl, femu_oc12_ctrl.params.num_ch, 1),
    DEFINE_PROP_UINT8("lnum_lun", FemuCtrl, femu_oc12_ctrl.params.num_lun, 1),
    DEFINE_PROP_UINT8("lnum_pln", FemuCtrl, femu_oc12_ctrl.params.num_pln, 1),
    DEFINE_PROP_UINT16("lmetasize", FemuCtrl, femu_oc12_ctrl.params.sos, 16),
    DEFINE_PROP_END_OF_LIST(),
};

static const VMStateDescription femu_vmstate = {
    .name = "femu",
    .unmigratable = 1,
};

static void femu_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    PCIDeviceClass *pc = PCI_DEVICE_CLASS(oc);

    pc->realize = femu_realize;
    pc->exit = femu_exit;
    pc->class_id = PCI_CLASS_STORAGE_EXPRESS;
    /* Coperd: change from PCI_VENDOR_ID_INTEL to 0x1d1d for OCSSD */
    pc->vendor_id = 0x1d1d;
    pc->device_id = 0x1f1f;
    pc->revision = 2;

    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    dc->desc = "FEMU Non-Volatile Memory Express";
    dc->props = femu_props;
    dc->vmsd = &femu_vmstate;
}

static const TypeInfo femu_info = {
    .name          = "femu",
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(FemuCtrl),
    .class_init    = femu_class_init,
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_PCIE_DEVICE },
        { }
    },
};

static void femu_register_types(void)
{
    type_register_static(&femu_info);
}

type_init(femu_register_types)
