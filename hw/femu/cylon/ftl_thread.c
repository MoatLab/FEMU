#include "../nvme.h"
#include "../ftl/ftl.h"
#include "cxlssd.h"
#include "cca_shmem.h"
#include "cache/cache_plugin.h"
#include "cache/cache.h"
#include <errno.h>

#define INSERT_NO_PREFETCH  0
#define INSERT_PREFETCH     1

static void handle_cca_ctrl_cmd(Cxlssd *ctx, struct cca_ctrl_slot_s *slot)
{
    struct cca_ctrl_resp_s *resp = &slot->resp;
    resp->lpn_start = slot->cmd.lpn_start;
    resp->lpn_count = slot->cmd.lpn_count;

    switch ((enum cca_ctrl_cmd)slot->cmd.cmd) {
    case CCA_CTRL_NOP:
        resp->status = 0;
        break;
    case CCA_CTRL_CACHE_ENABLE:
    case CCA_CTRL_CACHE_DISABLE:
        /* Cache on/off is configuration; report success */
        resp->status = 0;
        break;
    case CCA_CTRL_PIN:
    case CCA_CTRL_UNPIN:
    case CCA_CTRL_INVALIDATE:
        /* Stub: cache plugin could implement pin/invalidate later */
        resp->status = 0;
        break;
    default:
        resp->status = -EINVAL;
        break;
    }
}

/* CXLSSD FTL thread - handles both NVMe and CXL requests */
void *ftl_thread_cxlssd(void *arg)
{
    FemuCtrl *n = (FemuCtrl *)arg;
    struct ssd *ssd = n->ssd;
    Cxlssd *ctx = cxlssd_ctx_from_ssd(ssd);
    NvmeRequest *req = NULL;
    uint64_t lat = 0;
    int rc;
    int i;

    while (!*(ssd->dataplane_started_ptr)) {
        usleep(100000);
    }

    ssd->to_ftl = n->to_ftl;
    ssd->to_poller = n->to_poller;

    while (1) {
        /* CCA control ring: userspace library -> FEMU (caching control) */
        if (ctx && ctx->cca_ctrl_req_ring && femu_ring_count(ctx->cca_ctrl_req_ring)) {
            void *obj = NULL;
            rc = femu_ring_dequeue(ctx->cca_ctrl_req_ring, &obj, 1);
            if (rc == 1 && obj) {
                uint32_t slot_idx = (uint32_t)(uintptr_t)obj;
                if (slot_idx < ctx->cca_ring_count) {
                    struct cca_ctrl_slot_s *slot = &ctx->cca_ctrl_slots[slot_idx];
                    handle_cca_ctrl_cmd(ctx, slot);
                    obj = (void *)(uintptr_t)slot_idx;
                    femu_ring_enqueue(ctx->cca_ctrl_resp_ring, (void *)&obj, 1);
                }
            }
        }

        /* CXLSSD FTL: CXL requests and CCA (Cylon Caching API) */
        if (ctx && ctx->cache && ctx->cxl_req && femu_ring_count(ctx->cxl_req)) {
            struct cxl_req *creq = NULL;
            struct ppa ppa;
            struct cache_entry *centry;
            lpn_t lpn;
            bool read;

            rc = femu_ring_dequeue(ctx->cxl_req, (void *)&creq, 1);
            if (rc != 1) {
                printf("FEMU: FTL cxl_req dequeue failed\n");
                continue;
            }
            assert(creq != NULL);

            lpn = creq->addr >> 12;
            lat = 0;
            read = (bool)creq->is_read;

            centry = ctx->cache->ops.lookup(ctx->cache->cache_data, lpn);
            if (centry) {
                ctx->cache->ops.set_dirty(centry,
                    (ctx->cache->ops.is_dirty(centry) || !read));
                ctx->cache->ops.insert(ctx->cache->cache_data, centry, INSERT_NO_PREFETCH);
            } else {
                struct nand_cmd ncmd = {
                    .type = USER_IO,
                    .cmd = read ? NAND_READ : NAND_WRITE,
                    .stime = (int64_t)creq->start_time,
                };

                centry = ctx->cache->ops.entry_init(ctx->cache->cache_data, lpn);
                ctx->cache->ops.set_dirty(centry, !read);

                ppa = get_maptbl_ent(ssd, lpn);
                if (mapped_ppa(&ppa) && valid_ppa(ssd, &ppa)) {
                    ncmd.cmd = NAND_READ;
                    lat += ssd_advance_status(ssd, &ppa, &ncmd);
                } else {
                    struct ppa new_ppa;
                    ftl_assert(valid_lpn(ssd, lpn));
                    new_ppa = get_new_page(ssd);
                    set_maptbl_ent(ssd, lpn, &new_ppa);
                    set_rmap_ent(ssd, lpn, &new_ppa);
                    mark_page_valid(ssd, &new_ppa);
                    ssd_advance_write_pointer(ssd);
                    ncmd.cmd = NAND_WRITE;
                    lat += ssd_advance_status(ssd, &new_ppa, &ncmd);
                }
                creq->expire_time += lat;
                ctx->cache->ops.insert(ctx->cache->cache_data, centry, INSERT_PREFETCH);
            }

            /* Memory operation: copy between cache backend slot and guest (data_ptr) */
            if (creq->data_ptr && creq->size && ctx->cache_backend.buf_space) {
                uint32_t slot_id = ctx->cache->ops.get_slot_id(centry);
                uint64_t off = creq->addr % CACHE_PAGE_SIZE;
                char *slot_ptr = (char *)ctx->cache_backend.buf_space
                    + (size_t)slot_id * CACHE_PAGE_SIZE + (size_t)off;
                if (read) {
                    memcpy(creq->data_ptr, slot_ptr, creq->size);
                } else {
                    memcpy(slot_ptr, creq->data_ptr, creq->size);
                }
            }

            rc = femu_ring_enqueue(ctx->cxl_resp, (void *)&creq, 1);

            /* Clean one line if needed (in the background) */
            if (should_gc(ssd)) {
                do_gc(ssd, false);
            }
        }

        /* BBSSD FTL. Handling NVMe requests. */
        for (i = 1; i <= n->nr_pollers; i++) {
            if (!ssd->to_ftl[i] || !femu_ring_count(ssd->to_ftl[i]))
                continue;

            rc = femu_ring_dequeue(ssd->to_ftl[i], (void *)&req, 1);
            if (rc != 1) {
                printf("FEMU: FTL to_ftl dequeue failed\n");
            }

            ftl_assert(req);
            switch (req->cmd.opcode) {
            case NVME_CMD_WRITE:
                lat = ssd_write(ssd, req);
                break;
            case NVME_CMD_READ:
                lat = ssd_read(ssd, req);
                break;
            case NVME_CMD_DSM:
                lat = 0;
                break;
            default:
                //ftl_err("FTL received unkown request type, ERROR\n");
                ;
            }

            req->reqlat = lat;
            req->expire_time += lat;

            rc = femu_ring_enqueue(ssd->to_poller[i], (void *)&req, 1);
            if (rc != 1) {
                ftl_err("FTL to_poller enqueue failed\n");
            }

            /* clean one line if needed (in the background) */
            if (should_gc(ssd)) {
                do_gc(ssd, false);
            }
        }
    }

    return NULL;
}
