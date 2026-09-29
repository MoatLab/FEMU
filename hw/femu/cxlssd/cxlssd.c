/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "qapi/error.h"
#include "qemu-adapter.h"

/* BQL protects the gate; waiters must let the current operation finish. */
void femu_cxl_enter(FemuCxlMedia *s)
{
    while (s->busy) {
        qemu_cond_wait_bql(&s->idle);
    }
    s->busy = true;
}

void femu_cxl_leave(FemuCxlMedia *s)
{
    s->busy = false;
    qemu_cond_broadcast(&s->idle);
}

/* Spin only this close to the deadline; sleeps can overshoot by this much. */
#define FEMU_CXL_SPIN_NS (100 * SCALE_US)

void femu_cxl_delay(uint64_t ns)
{
    int64_t deadline = qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + ns;
    int64_t remaining;

    bql_unlock();
    remaining = deadline - qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    if (remaining > FEMU_CXL_SPIN_NS) {
        g_usleep((remaining - FEMU_CXL_SPIN_NS) / SCALE_US);
    }
    while (qemu_clock_get_ns(QEMU_CLOCK_REALTIME) < deadline) {
        cpu_relax();
    }
    bql_lock();
}

/* Only metadata reaches the worker; the vCPU owns all payload access. */
static void *cxl_worker(void *opaque)
{
    FemuCxlMedia *s = opaque;

    qemu_mutex_lock(&s->lock);
    while (!s->stopping) {
        FemuCxlWork *work = s->work;

        if (!work) {
            qemu_cond_wait(&s->wake, &s->lock);
            continue;
        }
        if (s->first_touch_program &&
            work->req.cmd.opcode == NVME_CMD_READ &&
            s->ns.ssd->maptbl[work->req.slba / 8].ppa == UNMAPPED_PPA) {
            work->req.cmd.opcode = NVME_CMD_WRITE;
        }
        work->latency = bb_ftl_process_req(s->ctrl, &s->ns, &work->req);
        work->done = true;
        s->work = NULL;
        qemu_cond_broadcast(&s->wake);
    }
    qemu_mutex_unlock(&s->lock);
    return NULL;
}

static bool cxl_media(FemuCxlMedia *s, uint64_t lpn, bool write)
{
    FemuCxlWork work = {
        .req = {
            .cmd.opcode = write ? NVME_CMD_WRITE : NVME_CMD_READ,
            .ns = &s->ns,
            .slba = lpn * 8,
            .nlb = 8,
            .stime = qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + s->access_ns,
        },
    };

    if (!s->ftl) {
        return true;
    }
    bql_unlock();
    qemu_mutex_lock(&s->lock);
    assert(!s->work);
    s->work = &work;
    qemu_cond_broadcast(&s->wake);
    while (!work.done) {
        qemu_cond_wait(&s->wake, &s->lock);
    }
    qemu_mutex_unlock(&s->lock);
    bql_lock();
    s->media_ns += work.latency;
    s->access_ns += work.latency;
    s->media_writes = ssd_nand_write_pages(s->ns.ssd);
    if (work.req.cmd.opcode == NVME_CMD_READ) {
        s->media_reads++;
    }
    return work.req.status == NVME_SUCCESS;
}

bool femu_cxl_evict(void *opaque, FemuCxlEntry *e)
{
    FemuCxlMedia *s = opaque;

    if (!femu_cxl_ratio_selected(s->direct.ratio, e->lpn)) {
        femu_cxl_der_remove(&s->direct, e->lpn);
    }
    return !e->dirty || s->free_writeback || cxl_media(s, e->lpn, true);
}

/* The media delay drops the BQL, so a decoder change may have intervened. */
static bool cxl_map(FemuCxlMedia *s, uint64_t generation, uint64_t hpa,
                    uint64_t dpa)
{
    return s->invalidations == generation &&
           femu_cxl_der_map(&s->direct, hpa, dpa);
}

MemTxResult femu_cxl_access(FemuCxlMedia *s, uint64_t hpa, uint64_t dpa,
                            uint64_t *data, unsigned size, bool write)
{
    uint64_t generation = s->invalidations;
    uint64_t first = dpa / 4096;
    uint64_t last;
    uint64_t lpn;
    int64_t start = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    int64_t remaining;

    if (!size || size > sizeof(*data) || dpa >= s->backend.size ||
        size > s->backend.size - dpa) {
        return MEMTX_ERROR;
    }
    last = (dpa + size - 1) / 4096;
    s->access_ns = 0;
    for (lpn = first; lpn <= last; lpn++) {
        FemuCxlEntry *e = femu_cxl_cache_find(&s->cache, lpn);

        bool miss = !e;

        if (write) {
            s->write_hits += !miss;
            s->write_misses += miss;
        } else {
            s->read_hits += !miss;
            s->read_misses += miss;
        }
        if (!e) {
            if (!cxl_media(s, lpn, write && !s->cache.nsets)) {
                return MEMTX_ERROR;
            }
            e = femu_cxl_cache_insert(&s->cache, lpn, femu_cxl_evict, s);
            if (s->cache.nsets && !e) {
                return MEMTX_ERROR;
            }
        }
        if (e && write) {
            e->dirty = true;
        }
        if (e && miss) {
            uint64_t next;
            uint64_t end = MIN(s->backend.size / 4096,
                              lpn + s->prefetch_stride + s->prefetch_degree);

            for (next = lpn + s->prefetch_stride; next < end; next++) {
                FemuCxlEntry *prefetched;
                uint64_t next_hpa = hpa - dpa + next * 4096;

                if (g_hash_table_contains(s->cache.entries, &next)) {
                    continue;
                }
                prefetched = femu_cxl_cache_insert(&s->cache, next,
                                                   femu_cxl_evict, s);
                if (!prefetched) {
                    return MEMTX_ERROR;
                }
                s->prefetch_inserts++;
                if (cxl_map(s, generation, next_hpa, next * 4096) &&
                    !s->direct.cylon) {
                    prefetched->dirty = true;
                }
            }
        }
        s->cache_entries = g_hash_table_size(s->cache.entries);
    }
    remaining = s->access_ns -
                (qemu_clock_get_ns(QEMU_CLOCK_REALTIME) - start);
    if (remaining > 0) {
        femu_cxl_delay(remaining);
    }
    if (write) {
        memcpy((uint8_t *)s->backend.logical_space + dpa, data, size);
    } else {
        memcpy(data, (uint8_t *)s->backend.logical_space + dpa, size);
    }
    if (first == last && (s->cache.nsets || s->direct.ratio)) {
        FemuCxlEntry *e = g_hash_table_lookup(s->cache.entries, &first);

        if ((e || femu_cxl_ratio_selected(s->direct.ratio, first)) &&
            cxl_map(s, generation, hpa, dpa) &&
            !s->direct.cylon && e) {
            /* Direct writes cannot update metadata, so charge on eviction. */
            e->dirty = true;
        }
    }
    if (s->io_log) {
        fprintf(s->io_log, "%" PRId64 ",%c,%" PRIu64 ",%u,%" PRIu64 "\n",
                start, write ? 'W' : 'R', dpa, size, s->access_ns);
    }
    return MEMTX_OK;
}

bool femu_cxl_geometry(FemuCxlMedia *s, uint64_t size, Error **errp)
{
    uint64_t pages;
    uint64_t line;

    if (!s->channels || s->channels > (1 << CH_BITS) ||
        !s->luns_per_channel || s->luns_per_channel > (1 << LUN_BITS) ||
        !s->pages_per_block || s->pages_per_block > (1 << PG_BITS) ||
        s->blocks_per_plane > (1 << BLK_BITS) ||
        !s->gc_threshold || s->gc_threshold > 100 ||
        s->gc_threshold_high < s->gc_threshold || s->gc_threshold_high > 100 ||
        s->channel_ns > NANOSECONDS_PER_SECOND) {
        error_setg(errp, "invalid NAND geometry, GC thresholds or timing");
        return false;
    }
    line = (uint64_t)s->channels * s->luns_per_channel * s->pages_per_block;
    if (!s->blocks_per_plane) {
        s->blocks_per_plane = DIV_ROUND_UP(size / 4096 * 5 / 4, line) + 4;
    }
    pages = line * s->blocks_per_plane;
    if (s->blocks_per_plane > (1 << BLK_BITS) || pages > INT_MAX / 8 ||
        pages < size / 4096 || s->blocks_per_plane < 2) {
        error_setg(errp, "NAND geometry must cover media and fit FTL limits");
        return false;
    }
    return true;
}

void femu_cxl_start(FemuCxlMedia *s, void *payload, uint64_t size,
                     FemuCxlPolicy policy)
{
    FemuCtrl *n;
    BbCtrlParams *p;

    s->backend.size = size;
    s->backend.logical_space = payload;
    femu_cxl_cache_init(&s->cache, s->cache_pages, s->cache_ways, policy);
    if (!s->ftl) {
        return;
    }
    s->ctrl = n = g_new0(FemuCtrl, 1);
    n->mbe = &s->backend;
    p = &n->bb_params;
    p->secsz = 512;
    p->secs_per_pg = 8;
    p->pgs_per_blk = s->pages_per_block;
    p->blks_per_pl = s->blocks_per_plane;
    p->pls_per_lun = 1;
    p->luns_per_ch = s->luns_per_channel;
    p->nchs = s->channels;
    p->pg_rd_lat = s->read_ns;
    p->pg_wr_lat = s->program_ns;
    p->blk_er_lat = s->erase_ns;
    p->ch_xfer_lat = s->channel_ns;
    p->gc_thres_pcent = s->gc_threshold;
    p->gc_thres_pcent_high = s->gc_threshold_high;
    s->ns.ctrl = n;
    s->ns.lbaf.lbads = 9;
    s->ns.ssd = g_new0(struct ssd, 1);
    pstrcpy(n->devname, sizeof(n->devname), "femu-cxl-ssd");
    s->ns.ssd->ssdname = n->devname;
    ssd_init(n, &s->ns);
    qemu_mutex_init(&s->lock);
    qemu_cond_init(&s->wake);
    s->stopping = false;
    qemu_thread_create(&s->worker, "femu-cxl-ftl", cxl_worker, s,
                       QEMU_THREAD_JOINABLE);
}

void femu_cxl_stop(FemuCxlMedia *s)
{
    if (!s->ftl) {
        s->started = false;
        femu_cxl_cache_destroy(&s->cache);
        return;
    }
    qemu_mutex_lock(&s->lock);
    s->stopping = true;
    qemu_cond_broadcast(&s->wake);
    qemu_mutex_unlock(&s->lock);
    qemu_thread_join(&s->worker);
    qemu_cond_destroy(&s->wake);
    qemu_mutex_destroy(&s->lock);
    s->started = false;
    femu_cxl_cache_destroy(&s->cache);
    ssd_free(s->ns.ssd);
    g_free(s->ns.ssd);
    g_free(s->ctrl);
}
