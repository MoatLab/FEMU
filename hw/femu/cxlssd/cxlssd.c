/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "qapi/error.h"
#include "qemu-adapter.h"

/* BQL protects the gate; waiters must let the current operation finish. */
void femu_cxl_enter(FemuCxlMedia *s)
{
    s->waiters++;
    while (s->busy) {
        qemu_cond_wait_bql(&s->idle);
    }
    s->waiters--;
    s->entries++;
    s->busy = true;
}

void femu_cxl_leave(FemuCxlMedia *s)
{
    /* Teardown deferred by an unplug runs while the gate is still held. */
    if (s->release) {
        void (*release)(FemuCxlMedia *) = s->release;

        s->release = NULL;
        release(s);
    }
    s->busy = false;
    /* Invalidation found the gate taken and did not wait for it. */
    if (s->nvme_kick && s->nvme_bh) {
        s->nvme_kick = false;
        qemu_bh_schedule(s->nvme_bh);
    }
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

bool femu_cxl_media(FemuCxlMedia *s, uint64_t lpn, bool write)
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
    return !e->dirty || s->free_writeback || femu_cxl_media(s, e->lpn, true);
}

/*
 * Linked NVMe reads check these bits for DULBE and LBA status; a CXL store
 * writes those blocks too. Pollers read the bitmap concurrently.
 */
void femu_cxl_nvme_mark(FemuCxlMedia *s, uint64_t dpa, uint64_t len)
{
    NvmeNamespace *ns = s->nvme_ns;
    uint64_t lba;
    uint64_t end;

    if (!ns || !ns->util || !len || !ns->ns_blks) {
        return;
    }
    lba = dpa >> ns->lbaf.lbads;
    end = MIN((dpa + len - 1) >> ns->lbaf.lbads, ns->ns_blks - 1);
    for (; lba <= end; lba++) {
        set_bit_atomic(lba, ns->util);
    }
}

/* The media delay drops the BQL, so a decoder change may have intervened. */
static bool cxl_map(FemuCxlMedia *s, uint64_t generation, uint64_t hpa,
                    uint64_t dpa, FemuCxlEntry *e)
{
    if (s->invalidations != generation || s->closing ||
        !femu_cxl_der_map(&s->direct, hpa, dpa, e)) {
        return false;
    }
    /* Stores through the mapping never reach this device. */
    femu_cxl_nvme_mark(s, dpa & ~4095ULL, 4096);
    return true;
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
            /*
             * Without a cache, for a bypassed page, or when every way of
             * the set is pinned, each access goes to the media.
             */
            bool bypassed = femu_cxl_cca_bypassed(&s->cca, lpn);
            bool uncached = !s->cache.nsets || bypassed ||
                            femu_cxl_cache_all_pinned(&s->cache, lpn);

            if (s->cache.nsets && uncached && !bypassed) {
                s->cca.pinned_set_misses++;
            }
            if (!femu_cxl_media(s, lpn, write && uncached)) {
                return MEMTX_ERROR;
            }
            if (!uncached) {
                e = femu_cxl_cache_insert(&s->cache, lpn, femu_cxl_evict, s);
                if (!e) {
                    return MEMTX_ERROR;
                }
            }
        }
        if (e && write) {
            e->dirty = true;
        }
        if (e && miss) {
            uint64_t next;
            /* More than the cache holds only evicts what was just fetched. */
            uint64_t degree = MIN(s->prefetch_degree, s->cache_pages);
            uint64_t end = MIN(s->backend.size / 4096,
                              lpn + s->prefetch_stride + degree);

            for (next = lpn + s->prefetch_stride; next < end; next++) {
                FemuCxlEntry *prefetched;
                uint64_t next_hpa = hpa - dpa + next * 4096;

                if (g_hash_table_contains(s->cache.entries, &next) ||
                    femu_cxl_cca_bypassed(&s->cca, next) ||
                    femu_cxl_cache_all_pinned(&s->cache, next)) {
                    continue;
                }
                prefetched = femu_cxl_cache_insert(&s->cache, next,
                                                   femu_cxl_evict, s);
                /* A prefetch is optional; never fail the demand access. */
                if (!prefetched) {
                    break;
                }
                s->prefetch_inserts++;
                if (cxl_map(s, generation, next_hpa, next * 4096, NULL) &&
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
    /* Unplugged during the wait: the backend may already serve a new device. */
    if (s->closing) {
        return MEMTX_ERROR;
    }
    if (write) {
        memcpy((uint8_t *)s->backend.logical_space + dpa, data, size);
        femu_cxl_nvme_mark(s, dpa, size);
    } else {
        memcpy(data, (uint8_t *)s->backend.logical_space + dpa, size);
    }
    if (first == last && (s->cache.nsets || s->direct.ratio)) {
        FemuCxlEntry *e = g_hash_table_lookup(s->cache.entries, &first);

        if ((e || femu_cxl_ratio_selected(s->direct.ratio, first)) &&
            cxl_map(s, generation, hpa, dpa, e) &&
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

/* Queue [slba, slba + nlb) of @ns for dropping; called under @lock. */
static bool cxl_nvme_record(FemuCxlMedia *s, NvmeNamespace *ns, uint64_t slba,
                            uint64_t nlb)
{
    uint64_t off = slba << ns->lbaf.lbads;
    FemuCxlRange r = {
        .first = off / 4096,
        .last = (off + (nlb << ns->lbaf.lbads) - 1) / 4096,
    };

    if (nlb) {
        g_array_append_val(s->nvme_ranges, r);
    }
    return nlb;
}

/*
 * Run a linked NVMe request on the medium's FTL. The medium's worker holds
 * @lock for each of its requests, so the two never interleave. The pollers'
 * pause waits for this thread, so it must never need the BQL; the cache is
 * updated later by a main-loop bottom half instead.
 */
uint64_t femu_cxl_nvme_ftl(FemuCtrl *n, NvmeNamespace *ns, NvmeRequest *req)
{
    FemuCxlMedia *s = n->cxl_media;
    const NvmeRwCmd *rw = (const NvmeRwCmd *)&req->cmd;
    bool recorded = false;
    uint64_t lat;
    int i;

    assert(!bql_locked());
    qemu_mutex_lock(&s->lock);
    /*
     * The poller already changed the payload, whatever the FTL decides.
     * Record from the command: the FTL frees DSM ranges as it trims.
     */
    switch (req->status == NVME_SUCCESS ? req->cmd.opcode : 0) {
    case NVME_CMD_WRITE:
    case NVME_CMD_WRITE_ZEROES:
        recorded = cxl_nvme_record(s, ns, le64_to_cpu(rw->slba),
                                   le16_to_cpu(rw->nlb) + 1);
        break;
    case NVME_CMD_COPY:
        recorded = cxl_nvme_record(s, ns, le32_to_cpu(req->cmd.cdw10) |
                                   (uint64_t)le32_to_cpu(req->cmd.cdw11) << 32,
                                   req->nlb);
        break;
    case NVME_CMD_DSM:
        for (i = 0; req->dsm_ranges && i < req->dsm_nr_ranges; i++) {
            recorded |= cxl_nvme_record(s, ns,
                                        le64_to_cpu(req->dsm_ranges[i].slba),
                                        le32_to_cpu(req->dsm_ranges[i].nlb));
        }
        break;
    default:
        break;
    }
    /* The request completes once the bottom half took this batch. */
    if (recorded) {
        req->cxl_seq = s->nvme_taken + 1;
    }
    lat = bb_ftl_process_req(n, ns, req);
    qemu_mutex_unlock(&s->lock);
    if (req->cxl_seq) {
        qemu_bh_schedule(s->nvme_bh);
    }
    return lat;
}

/* Revoking page by page costs two VM-wide flushes each under Cylon. */
#define FEMU_CXL_NVME_CLEAR 64

/*
 * The NVMe command already programmed or unmapped these pages, so a cached
 * copy must not be written back: that would program them twice, or map a
 * deallocated page again. Revoke direct mappings first so Cylon's dirty
 * sample is discarded with the entry. Pinned pages stay resident and pinned,
 * as the caching API promised, but clean.
 */
static void cxl_nvme_drop(FemuCxlMedia *s, uint64_t first, uint64_t last)
{
    g_autoptr(GPtrArray) victims = g_ptr_array_new();
    uint64_t pages = s->backend.size / 4096;
    FemuCxlEntry *e;
    uint64_t lpn;
    bool clear;
    guint i;

    if (first >= pages) {
        return;
    }
    last = MIN(last, pages - 1);
    /* A clear would also revoke ratio mappings, which rule 1 keeps. */
    clear = last - first + 1 > FEMU_CXL_NVME_CLEAR && s->direct.mapped &&
            !s->direct.ratio;
    if (clear) {
        femu_cxl_der_clear(&s->direct);
    }
    if (last - first + 1 <= g_hash_table_size(s->cache.entries)) {
        for (lpn = first; lpn <= last; lpn++) {
            e = g_hash_table_lookup(s->cache.entries, &lpn);
            if (e) {
                g_ptr_array_add(victims, e);
            }
        }
    } else {
        GHashTableIter it;
        gpointer value;

        g_hash_table_iter_init(&it, s->cache.entries);
        while (g_hash_table_iter_next(&it, NULL, &value)) {
            e = value;
            if (e->lpn >= first && e->lpn <= last) {
                g_ptr_array_add(victims, e);
            }
        }
    }
    for (i = 0; i < victims->len; i++) {
        e = g_ptr_array_index(victims, i);
        if (!clear && !femu_cxl_ratio_selected(s->direct.ratio, e->lpn)) {
            femu_cxl_der_remove(&s->direct, e->lpn);
        }
        s->nvme_drops++;
        if (e->queue == FEMU_CXL_PINNED) {
            e->dirty = false;
        } else {
            femu_cxl_cache_remove(&s->cache, e, NULL, NULL);
        }
    }
}

/*
 * Apply what linked NVMe writes replaced. Invalidation never waits for the
 * gate: when it is taken, the holder reschedules this as it leaves.
 */
void femu_cxl_nvme_bh(void *opaque)
{
    FemuCxlMedia *s = opaque;
    GArray *ranges;
    uint64_t done;
    guint i;

    if (s->busy) {
        s->nvme_kick = true;
        return;
    }
    femu_cxl_enter(s);
    qemu_mutex_lock(&s->lock);
    ranges = s->nvme_ranges;
    s->nvme_ranges = g_array_new(false, false, sizeof(FemuCxlRange));
    done = ++s->nvme_taken;
    qemu_mutex_unlock(&s->lock);
    if (!s->direct.cylon) {
        memory_region_transaction_begin();
    }
    for (i = 0; i < ranges->len; i++) {
        FemuCxlRange *r = &g_array_index(ranges, FemuCxlRange, i);

        cxl_nvme_drop(s, r->first, r->last);
    }
    if (!s->direct.cylon) {
        memory_region_transaction_commit();
    }
    g_array_free(ranges, true);
    s->cache_entries = g_hash_table_size(s->cache.entries);
    s->media_writes = ssd_nand_write_pages(s->ns.ssd);
    qatomic_store_release(&s->nvme_done, done);
    femu_cxl_leave(s);
}

/*
 * Flip from the linked controller. The timings are shared with the medium's
 * worker, which reads them under @lock. Restoring delays uses the values this
 * device was configured with, not the compile-time defaults.
 */
void femu_cxl_nvme_flip(FemuCtrl *n, int64_t cdw10)
{
    FemuCxlMedia *s = n->cxl_media;
    struct ssdparams *sp = &s->ns.ssd->sp;
    bool zero = cdw10 == FEMU_DISABLE_DELAY_EMU;

    qemu_mutex_lock(&s->lock);
    switch (cdw10) {
    case FEMU_ENABLE_GC_DELAY:
    case FEMU_DISABLE_GC_DELAY:
        sp->enable_gc_delay = cdw10 == FEMU_ENABLE_GC_DELAY;
        break;
    case FEMU_ENABLE_DELAY_EMU:
    case FEMU_DISABLE_DELAY_EMU:
        sp->pg_rd_lat = zero ? 0 : s->read_ns;
        sp->pg_wr_lat = zero ? 0 : s->program_ns;
        sp->blk_er_lat = zero ? 0 : s->erase_ns;
        sp->ch_xfer_lat = zero ? 0 : s->channel_ns;
        bb_nand_media_refresh_timing(s->ns.ssd);
        break;
    default:
        break;
    }
    qemu_mutex_unlock(&s->lock);
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
    s->nvme_ranges = g_array_new(false, false, sizeof(FemuCxlRange));
    s->stopping = false;
    qemu_thread_create(&s->worker, "femu-cxl-ftl", cxl_worker, s,
                       QEMU_THREAD_JOINABLE);
}

void femu_cxl_stop(FemuCxlMedia *s)
{
    FemuCtrl *nvme = s->nvme;
    bool resume = false;

    if (!s->ftl) {
        s->started = false;
        femu_cxl_cache_destroy(&s->cache);
        return;
    }
    /*
     * A guest can power the slot off without asking management, which
     * skips the unplug blocker. Quiesce a linked controller so nothing is
     * in the FTL, then leave the FTL and payload to it.
     */
    if (nvme) {
        resume = nvme_pause_pollers(nvme);
    }
    qemu_mutex_lock(&s->lock);
    s->stopping = true;
    qemu_cond_broadcast(&s->wake);
    qemu_mutex_unlock(&s->lock);
    qemu_thread_join(&s->worker);
    qemu_cond_destroy(&s->wake);
    qemu_mutex_destroy(&s->lock);
    g_clear_pointer(&s->nvme_bh, qemu_bh_delete);
    g_array_free(s->nvme_ranges, true);
    s->nvme_ranges = NULL;
    s->started = false;
    femu_cxl_cache_destroy(&s->cache);
    if (nvme) {
        qatomic_set(&nvme->cxl_done, NULL);
        nvme->cxl_media = NULL;
        s->nvme_ns = NULL;
        s->nvme_owns_ftl = true;
        nvme_resume_pollers(nvme, resume);
        return;
    }
    ssd_free(s->ns.ssd);
    g_free(s->ns.ssd);
    g_free(s->ctrl);
}
