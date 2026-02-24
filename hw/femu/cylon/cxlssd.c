#include "../nvme.h"
#include "../ftl/ftl.h"
#include "der_kvm.h"
#include "cxlssd.h"
#include "cache/cache_plugin.h"
#include "cache/cache_backend.h"
#include "hw/femu/inc/rte_ring.h"
#include "exec/memory.h"
#include "sysemu/hostmem.h"
#include <inttypes.h>

static void cxlssd_set_cache_plugin(struct ssd *ssd, struct cache_plugin *plugin)
{
    Cxlssd *ctx = (Cxlssd *)ssd->opaque;
    if (ctx) {
        ctx->cache = plugin;
    }
}

Cxlssd *cxlssd_ctx_from_ssd(struct ssd *ssd)
{
    return ssd && ssd->opaque ? (Cxlssd *)ssd->opaque : NULL;
}

Cxlssd *cxlssd_ctx_from_ctrl(struct FemuCtrl *n)
{
    return n && n->ssd ? cxlssd_ctx_from_ssd(n->ssd) : NULL;
}

static void cxlssd_init_ctrl_str(FemuCtrl *n)
{
    static int fsid_vcxlssd = 0;
    const char *vcxlssdssd_mn = "FEMU CXL-SSD Controller";
    const char *vcxlssdssd_sn = "vSSD";

    nvme_set_ctrl_name(n, vcxlssdssd_mn, vcxlssdssd_sn, &fsid_vcxlssd);
}

static int cmp_pri(pqueue_pri_t next, pqueue_pri_t curr)
{
    return (next > curr);
}

static pqueue_pri_t get_pri(void *a)
{
    return ((struct cxl_req *)a)->expire_time;
}

static void set_pri(void *a, pqueue_pri_t pri)
{
    ((struct cxl_req *)a)->expire_time = pri;
}

static size_t get_pos(void *a)
{
    return ((struct cxl_req *)a)->pos;
}

static void set_pos(void *a, size_t pos)
{
    ((struct cxl_req *)a)->pos = pos;
}


/* cxlssd <= [bb <=> black-box] */
static void cxlssd_init(FemuCtrl *n, Error **errp)
{
    Cxlssd *ctx;
    struct ssd *ssd;

    ssd = n->ssd = g_malloc0(sizeof(struct ssd));
    cxlssd_init_ctrl_str(n);

    ssd->dataplane_started_ptr = &n->dataplane_started;
    ssd->ssdname = (char *)n->devname;
    ssd->opaque = NULL;
    ssd->set_cache_plugin = cxlssd_set_cache_plugin;
    ssd->cache = NULL;

    ctx = g_malloc0(sizeof(Cxlssd));
    ssd->opaque = ctx;

    femu_log("Cylon CXL-SSD init: starting (memsz %u MB, NAND backend %p size %" PRId64 ")\n",
             n->memsz, (void *)n->mbe, n->mbe ? n->mbe->size : 0);

    /* Cache backend (DER or mbe) into ctx */
    if (cylon_cache_backend_init(n, &ctx->cache_backend) != 0) {
        femu_err("Cylon cache backend init failed; cache disabled\n");
    } else if (ctx->cache_backend.buf_size > 0) {
        femu_log("Cylon cache backend: enabled, buf_size %" PRId64 " MB\n",
                 ctx->cache_backend.buf_size / (1024 * 1024));
    } else {
        femu_log("Cylon cache backend: disabled (no cache_backend_dev or bufsz)\n");
    }

    /* CXL rings and pqueue */
    ctx->cxl_req = femu_ring_create(FEMU_RING_TYPE_MP_SC, FEMU_MAX_INF_REQS);
    if (!ctx->cxl_req) {
        femu_err("Failed to create ring (cxl_req) ...\n");
        abort();
    }
    ctx->cxl_resp = femu_ring_create(FEMU_RING_TYPE_MP_SC, FEMU_MAX_INF_REQS);
    if (!ctx->cxl_resp) {
        femu_err("Failed to create ring (cxl_resp) ...\n");
        abort();
    }
    ctx->cxl_pq = pqueue_init(FEMU_MAX_INF_REQS, cmp_pri, get_pri, set_pri, get_pos, set_pos);
    if (!ctx->cxl_pq) {
        femu_err("Failed to create pqueue (cxl_pq) ...\n");
        abort();
    }
    /* Keep n->cxl_* for existing callers (io path) */
    n->cxl_req = ctx->cxl_req;
    n->cxl_resp = ctx->cxl_resp;
    n->cxl_pq = ctx->cxl_pq;
    femu_log("Cylon CXL-SSD init: rings and pqueue created\n");

    /* CCA ivshmem: layout control rings for userspace library when cca_dev set */
    if (n->cca_dev) {
        HostMemoryBackend *be = n->cca_dev;
        void *base = memory_region_get_ram_ptr(&be->mr);
        size_t total = (size_t)memory_region_size(&be->mr);
        struct cca_shmem_header *hdr = (struct cca_shmem_header *)base;
        size_t ring_sz = (size_t)rte_ring_get_memsize(CCA_RING_COUNT);
        size_t slot_sz = CCA_RING_COUNT * sizeof(struct cca_ctrl_slot_s);
        size_t need = sizeof(*hdr) + 2 * ring_sz + slot_sz;

        if (total >= need) {
            memset(base, 0, (size_t)total);
            hdr->magic = CCA_SHMEM_MAGIC;
            hdr->version = CCA_LAYOUT_VERSION;
            hdr->ring_count = CCA_RING_COUNT;
            hdr->offset_ctrl_req_ring = sizeof(*hdr);
            hdr->offset_ctrl_resp_ring = sizeof(*hdr) + ring_sz;
            hdr->offset_ctrl_slot_pool = sizeof(*hdr) + 2 * ring_sz;
            hdr->offset_req_ring = 0;
            hdr->offset_resp_ring = 0;
            hdr->offset_req_pool = 0;
            hdr->offset_data_region = 0;
            hdr->size_data_region = 0;

            ctx->cca_base = base;
            ctx->cca_ctrl_req_ring = (struct rte_ring *)((char *)base + hdr->offset_ctrl_req_ring);
            ctx->cca_ctrl_resp_ring = (struct rte_ring *)((char *)base + hdr->offset_ctrl_resp_ring);
            ctx->cca_ctrl_slots = (struct cca_ctrl_slot_s *)((char *)base + hdr->offset_ctrl_slot_pool);
            ctx->cca_ring_count = CCA_RING_COUNT;

            if (rte_ring_init(ctx->cca_ctrl_req_ring, "cca_ctrl_req", CCA_RING_COUNT, RING_F_SC_DEQ) == 0 &&
                rte_ring_init(ctx->cca_ctrl_resp_ring, "cca_ctrl_resp", CCA_RING_COUNT, RING_F_SC_DEQ) == 0) {
                femu_log("Cylon CCA: ivshmem layout initialized (ctrl rings + slot pool)\n");
            } else {
                ctx->cca_base = NULL;
                ctx->cca_ctrl_req_ring = NULL;
                ctx->cca_ctrl_resp_ring = NULL;
                ctx->cca_ctrl_slots = NULL;
                femu_err("Cylon CCA: rte_ring_init in ivshmem failed\n");
            }
        } else {
            femu_err("Cylon CCA: ivshmem too small (need %zu, have %zu)\n", need, total);
        }
    }

    ctx->der_kvm = g_malloc0(sizeof(DerKvmState));
    if (der_kvm_set_user_memory_region(n) != 0) {
        femu_err("Cylon DER-KVM: der_kvm_set_user_memory_region failed\n");
        abort();
    } else {
        femu_log("Cylon DER-KVM: memslot and EPT initialized (base_gpa 0x%" PRIx64 ", size %" PRId64 ")\n",
                 n->base_gpa, n->mbe ? n->mbe->size : 0);
    }

    ssd_init(n);
    femu_log("Cylon CXL-SSD init: FTL (ssd_init) done\n");

    ctx->cache = NULL;
    if (n->bufsz > 0 && n->rep < POLICY_MAX) {
        struct cache_plugin *plugin = cylon_cache_plugin_create(n);
        if (plugin) {
            ftl_register_cache_plugin(ssd, plugin);  /* sets ctx->cache via setter */
            femu_log("Cylon CXL-SSD init: cache plugin registered (policy %u, bufsz %u MB)\n",
                     (unsigned)n->rep, n->bufsz);
        }
    } else {
        femu_log("Cylon CXL-SSD init: cache plugin disabled (bufsz=%u rep=%u)\n", n->bufsz, n->rep);
    }
    femu_log("Cylon CXL-SSD init: complete\n");
}

static void cxlssd_exit(FemuCtrl *n)
{
    Cxlssd *ctx = cxlssd_ctx_from_ctrl(n);
    if (ctx) {
        femu_log("Cylon CXL-SSD exit: tearing down\n");
        if (ctx->cache) {
            cylon_cache_plugin_destroy(ctx->cache);
            ctx->cache = NULL;
        }
        der_kvm_del_user_memory_region(n);
        g_free(ctx->der_kvm);
        ctx->der_kvm = NULL;
        ctx->cca_base = NULL;
        ctx->cca_ctrl_req_ring = NULL;
        ctx->cca_ctrl_resp_ring = NULL;
        ctx->cca_ctrl_slots = NULL;
        cylon_cache_backend_fini(&ctx->cache_backend);
        femu_ring_free(ctx->cxl_req);
        femu_ring_free(ctx->cxl_resp);
        pqueue_free(ctx->cxl_pq);
        g_free(ctx);
        n->ssd->opaque = NULL;
        n->cxl_req = NULL;
        n->cxl_resp = NULL;
        n->cxl_pq = NULL;
        femu_log("Cylon CXL-SSD exit: done\n");
    }
}

static void cxlssd_flip(FemuCtrl *n, NvmeCmd *cmd)
{
    struct ssd *ssd = n->ssd;
    int64_t cdw10 = le64_to_cpu(cmd->cdw10);

    switch (cdw10) {
    case FEMU_ENABLE_GC_DELAY:
        ssd->sp.enable_gc_delay = true;
        femu_log("%s,FEMU GC Delay Emulation [Enabled]!\n", n->devname);
        break;
    case FEMU_DISABLE_GC_DELAY:
        ssd->sp.enable_gc_delay = false;
        femu_log("%s,FEMU GC Delay Emulation [Disabled]!\n", n->devname);
        break;
    case FEMU_ENABLE_DELAY_EMU:
        ssd->sp.pg_rd_lat = NAND_READ_LATENCY;
        ssd->sp.pg_wr_lat = NAND_PROG_LATENCY;
        ssd->sp.blk_er_lat = NAND_ERASE_LATENCY;
        ssd->sp.ch_xfer_lat = 0;
        femu_log("%s,FEMU Delay Emulation [Enabled]!\n", n->devname);
        break;
    case FEMU_DISABLE_DELAY_EMU:
        ssd->sp.pg_rd_lat = 0;
        ssd->sp.pg_wr_lat = 0;
        ssd->sp.blk_er_lat = 0;
        ssd->sp.ch_xfer_lat = 0;
        femu_log("%s,FEMU Delay Emulation [Disabled]!\n", n->devname);
        break;
    case FEMU_RESET_ACCT:
        n->nr_tt_ios = 0;
        n->nr_tt_late_ios = 0;
        femu_log("%s,Reset tt_late_ios/tt_ios,%lu/%lu\n", n->devname,
                n->nr_tt_late_ios, n->nr_tt_ios);
        break;
    case FEMU_ENABLE_LOG:
        n->print_log = true;
        femu_log("%s,Log print [Enabled]!\n", n->devname);
        break;
    case FEMU_DISABLE_LOG:
        n->print_log = false;
        femu_log("%s,Log print [Disabled]!\n", n->devname);
        break;
    default:
        printf("FEMU:%s,Not implemented flip cmd (%lu)\n", n->devname, cdw10);
    }
}

static uint16_t cxlssd_nvme_rw(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                        NvmeRequest *req)
{
    return nvme_rw(n, ns, cmd, req);
}

static uint16_t cxlssd_io_cmd(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                        NvmeRequest *req)
{
    switch (cmd->opcode) {
    case NVME_CMD_READ:
    case NVME_CMD_WRITE:
        return cxlssd_nvme_rw(n, ns, cmd, req);
    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

static uint16_t cxlssd_admin_cmd(FemuCtrl *n, NvmeCmd *cmd)
{
    switch (cmd->opcode) {
    case NVME_ADM_CMD_FEMU_FLIP:
        cxlssd_flip(n, cmd);
        return NVME_SUCCESS;
    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

/* Enqueue CXL memory request and wait for FTL to complete (cache fetch + memcpy). */
static void wait_for_buf_update(FemuCtrl *n, uint64_t addr, int c, unsigned size, void *data_ptr)
{
    int rc;
    uint64_t now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);

    struct cxl_req *myreq = g_malloc(sizeof(struct cxl_req));
    *myreq = (struct cxl_req) {
        .addr = addr,
        .size = size,
        .data_ptr = data_ptr,
        .is_read = (unsigned)(c == CXL_READ),
        .start_time = now,
        .expire_time = now,
    };
    // &creq;
    struct cxl_req *req = NULL;

    /* send requesst*/
    // qemu_mutex_lock(&n->mutex);
    rc = femu_ring_enqueue(n->cxl_req, (void *)&myreq, 1);
    // qemu_mutex_unlock(&n->mutex);
    if (rc != 1) {
        femu_err("enqueue failed, ret=%d\n", rc);
    }
    
    pqueue_t *pq = n->cxl_pq;
    struct rte_ring *rp = n->cxl_resp;
    bool recvd = false;

    while (!recvd) {
        /* flush response Q */
        while (femu_ring_count(rp)) {
            
            req = NULL;
            rc = femu_ring_dequeue(rp, (void *)&req, 1);
            if (rc != 1) {
                femu_err("dequeue from to_poller request failed\n");
            }
            assert(req);
    
            pqueue_insert(pq, req);
        }

        /* Wait for my response */
        while ((req = pqueue_peek(pq))) {
            if (myreq != req) {
                continue;
            }
            
            recvd = true;
            pqueue_pop(pq);
            do {
                now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
            } while (now < req->expire_time);
            break;
        }
    }

    g_free(myreq);
}

int cnt = 0;
char str[128];
uint64_t prev = 0;
static MemTxResult cxlssd_mem_read(void *opaque, uint64_t addr, uint64_t *data, unsigned size, MemTxAttrs attrs)
{
    FemuCtrl *n = (FemuCtrl *)opaque;
    assert(addr < n->mbe->size);

    if (n->cxl_skip_ftl) {
        memcpy(data, (const char *)n->mbe->logical_space + addr, size);
        return MEMTX_OK;
    }
    wait_for_buf_update(n, addr, CXL_READ, size, data);
    return MEMTX_OK;
}

static MemTxResult cxlssd_mem_write(void *opaque, uint64_t addr, uint64_t data, unsigned size, MemTxAttrs attrs)
{
    FemuCtrl *n = (FemuCtrl *)opaque;
    assert(addr < n->mbe->size);

    if (n->cxl_skip_ftl) {
        memcpy((char *)n->mbe->logical_space + addr, &data, size);
        return MEMTX_OK;
    }
    wait_for_buf_update(n, addr, CXL_WRITE, size, &data);
    return MEMTX_OK;
}

#ifdef LSA_TROLL
G_GNUC_UNUSED static void req_ftl(FemuCtrl *n, int c)
{
    int rc;
    struct cxl_req creq = (struct cxl_req) {
        .addr = 0,
        .size = 0,
        .data_ptr = NULL,
        .is_read = (unsigned)(c == CXL_READ),
        .start_time = 0,
        .expire_time = 0,
        .pos = 0,
    };

    struct cxl_req *myreq = &creq;
    struct cxl_req *req = NULL;

    /* send requesst*/
    rc = femu_ring_enqueue(n->cxl_req, (void *)&myreq, 1);
    if (rc != 1) {
        femu_err("enqueue failed, ret=%d\n", rc);
    }

    pqueue_t *pq = n->cxl_pq;
    struct rte_ring *rp = n->cxl_resp;
    bool recvd = false;

    while (!recvd) {
        /* flush response Q */
        while (femu_ring_count(rp)) {
            req = NULL;
            rc = femu_ring_dequeue(rp, (void *)&req, 1);
            if (rc != 1) {
                femu_err("dequeue from to_poller request failed\n");
            }
            assert(req);
            
            pqueue_insert(pq, req);
        }

        /* Wait for my response */
        while ((req = pqueue_peek(pq))) {
            if (myreq != req)
                continue;

            recvd = true;
            pqueue_pop(pq);
            break;
        }
    }
}
#endif

static uint16_t get_lsa(struct FemuCtrl *n, void *buf, uint64_t size, uint64_t offset)
{
    void *backend_buf = n->mbe->logical_space;
    if (!backend_buf) {
        return 0;
    }
    memcpy(buf, (char *)backend_buf + offset, size);
    return size;
}
static uint16_t set_lsa(struct FemuCtrl *n, const void *buf, uint64_t size, uint64_t offset)
{
    void *backend_buf = n->mbe->logical_space;
    if (!backend_buf) {
        return 0;
    }
    memcpy((char *)backend_buf + offset, buf, size);
    return size;
}

int nvme_register_cxlssd(FemuCtrl *n)
{
    n->ext_ops = (FemuExtCtrlOps) {
        .state            = NULL,
        .init             = cxlssd_init,
        .exit             = cxlssd_exit,
        .rw_check_req     = NULL,
        .admin_cmd        = cxlssd_admin_cmd,
        .io_cmd           = cxlssd_io_cmd,
        .get_log          = NULL,
    };

    /* CXL support */
    SsdDramBackend *mbe = n->mbe;
    memory_region_init_ram_ptr(&n->cxl_mr, OBJECT(n), "femu-cxlssd", mbe->size, mbe->logical_space);
    address_space_init(&n->cxl_as, &n->cxl_mr, "cxlssd address space");

    n->cxl_mem_ops = (FemuCXLOps) {
        .get_lsa          = get_lsa,
        .set_lsa          = set_lsa,
        .read             = cxlssd_mem_read,
        .write            = cxlssd_mem_write
    };
    return 0;
}

