/*
 * bbssd FTL datapath: the non-FDP host read / write / trim handlers run by the
 * FTL thread. They translate an LBA request into page mapping lookups and
 * updates, drive the NAND media timing, and trigger GC when the device runs low
 * on free lines. Split out of ftl.c; mapping, line/GC, timing, and the debug
 * hooks come from ftl-internal.h and the media layer.
 */
#include "qemu/osdep.h"
#include "ftl.h"
#include "ftl-internal.h"
#include "../femu-fsched.h"

/*
 * Order buffer entries by logical page number. Compared rather than
 * subtracted: a page number is 64-bit and the difference between two of them
 * does not fit the int this has to return, so subtracting misorders the tree
 * for pages far enough apart and loses entries that are still in it.
 */
int comp_buffer(const void *a, const void *b)
{
    uint64_t la = ((const struct buffer_entry *)a)->lpn;
    uint64_t lb = ((const struct buffer_entry *)b)->lpn;

    if (la < lb) {
        return -1;
    }
    return la > lb;
}

/*
 * The write buffer models a DRAM staging area in front of the NAND: a host
 * write is accepted into it and only programmed later, so repeated writes to
 * the same page cost one program rather than several, and the program cost is
 * charged to whichever later event forces the page out.
 *
 * Normally it holds only page numbers. With power_loss enabled, payload
 * access also runs on the FTL thread. Each dirty entry saves the previous
 * durable bytes and per-LBA validity before the backend changes. Removing an
 * entry after programming commits those bytes; a power cut restores them.
 * This undo log consumes at most buffer_size pages plus their LBA state,
 * instead of duplicating the entire backend. FUA programs a full NAND page,
 * so dirty neighboring LBAs in that page become durable too.
 *
 * Everything below runs on the FTL thread, which is the only owner of the
 * buffer, the mapping, the line management and the NAND status. None of it is
 * serialised against the poller thread and none of it may be called from there.
 */
bool ssd_buffer_enabled(struct ssd *ssd)
{
    /*
     * Without a cache the host can see, a power_loss buffer is one that
     * plp protects. A failed protection in WTM mode writes through.
     */
    if ((ssd->n->power_loss && !ssd->n->vwc && !ssd->n->plp) ||
        ssd->sp.buffer_size <= 0 || !ssd->wb_tree ||
        unlikely(qatomic_read(&ssd->n->plp_wt))) {
        return false;
    }

    /*
     * A controller that advertises a volatile write cache lets the host turn
     * it off (Set Features, Volatile Write Cache). A device whose cache is
     * disabled may not hold writes back, so the buffer stops accepting them
     * and ssd_write() drains what it still holds before going direct. A
     * controller that advertises no cache has nothing for the host to disable
     * and keeps buffering, which is what buffer_size alone has always meant.
     */
    if (ssd->n && ssd->n->vwc && !ssd->n->features.volatile_wc) {
        return false;
    }

    return true;
}

/* fill level at which the buffer starts writing pages back */
static int buffer_watermark(struct ssd *ssd)
{
    int wm = (int)(ssd->sp.buffer_size * ssd->sp.buffer_thres_pcent);

    /*
     * A threshold that rounds down to zero would write every page back as soon
     * as it arrived; a buffer of any size holds at least one page first.
     */
    return wm > 0 ? wm : 1;
}

static uint64_t buffer_destage(struct ssd *ssd, int budget, uint64_t stime,
                               bool bg);

/* the idle write-back has pages to write: the buffer is above its low mark */
bool ssd_buffer_bg_wants(struct ssd *ssd)
{
    int low = (int)(ssd->sp.buffer_size * ssd->sp.buffer_low_pcent);

    return ssd->sp.buffer_low_pcent > 0 && ssd_buffer_enabled(ssd) &&
           ssd->write_buffer_cnt > low;
}

/*
 * Background write-back (buffer_low_pcent): on an idle FTL thread, once
 * every die has finished its booked work, write back as many pages as
 * there are dies. Repeated while idle, this drains the buffer to the low
 * watermark at the speed of the media, so later reads meet dies that are
 * as busy as the write-back made them. It returns the latency of the
 * step, 0 for none.
 */
uint64_t ssd_buffer_bg_step(struct ssd *ssd, uint64_t now)
{
    int low = (int)(ssd->sp.buffer_size * ssd->sp.buffer_low_pcent);
    int dies = ssd->sp.nchs * ssd->sp.luns_per_ch;
    int before = ssd->write_buffer_cnt;
    uint64_t lat;

    /* a plm DTWIN holds it; a full buffer and a Flush still destage */
    if (!ssd_buffer_bg_wants(ssd) || unlikely(ssd->plm_hold) ||
        ssd_media_last_end(ssd) > now) {
        return 0;
    }
    lat = buffer_destage(ssd, MIN(before - low, dies), now, true);
    ssd->buffer_bg_pages += before - ssd->write_buffer_cnt;
    /* the pages left the buffer, but a Flush must still wait for them */
    ssd->buffer_bg_fence = MAX(ssd->buffer_bg_fence, now + lat);
    return lat;
}

bool ssd_buffer_at_watermark(struct ssd *ssd)
{
    return ssd->write_buffer_cnt >= buffer_watermark(ssd);
}

/*
 * How many pages to write back once the watermark is reached. The batch is the
 * slack above it, so a buffer set to start writing back at 90% full moves 10%
 * of its pages each time it gets there, and the fill level oscillates in that
 * band instead of tracking the watermark exactly. Writing back in batches is
 * most of what makes a buffer worth modelling: pages that leave together can be
 * spread over channels and LUNs, which one-in-one-out eviction cannot do.
 */
int ssd_buffer_batch(struct ssd *ssd)
{
    int batch = ssd->sp.buffer_size - buffer_watermark(ssd);

    return batch > 0 ? batch : 1;
}

/* free a buffer entry once its page no longer needs the buffer */
static void buffer_remove(struct ssd *ssd, struct buffer_entry *entry)
{
    QTAILQ_REMOVE(&ssd->write_buffer, entry, b_entry);
    g_tree_remove(ssd->wb_tree, entry);
    g_free(entry->undo);
    g_free(entry->lba_state);
    g_free(entry->written);
    g_free(entry);
    ssd->write_buffer_cnt--;
}

/*
 * Accept a page into the buffer and return its entry. *@held tells whether
 * the page was already held, which is the case the buffer exists for: the
 * earlier write is superseded and no extra program is owed. A page that is
 * already held keeps its identity and is only moved to the tail, so
 * occupancy cannot grow on a repeat write.
 */
struct buffer_entry *ssd_buffer_insert(struct ssd *ssd, uint64_t lpn,
                                       bool *held)
{
    struct buffer_entry target = { .lpn = lpn };
    struct buffer_entry *entry = g_tree_lookup(ssd->wb_tree, &target);

    *held = entry != NULL;
    if (entry) {
        QTAILQ_REMOVE(&ssd->write_buffer, entry, b_entry);
        QTAILQ_INSERT_TAIL(&ssd->write_buffer, entry, b_entry);
        return entry;
    }

    entry = g_new0(struct buffer_entry, 1);
    entry->lpn = lpn;
    g_tree_insert(ssd->wb_tree, entry, entry);
    QTAILQ_INSERT_TAIL(&ssd->write_buffer, entry, b_entry);
    ssd->write_buffer_cnt++;

    return entry;
}

/* the entry holding @lpn, or NULL */
struct buffer_entry *ssd_buffer_lookup(struct ssd *ssd, uint64_t lpn)
{
    struct buffer_entry target = { .lpn = lpn };

    return ssd->wb_tree ? g_tree_lookup(ssd->wb_tree, &target) : NULL;
}

/*
 * Drop a page from the buffer without programming it. A page the host has
 * deallocated must be removed: otherwise the pending program runs later and
 * data the host discarded reappears. Returns whether the page was held.
 */
bool ssd_buffer_discard(struct ssd *ssd, uint64_t lpn)
{
    struct buffer_entry target = { .lpn = lpn };
    struct buffer_entry *held;

    if (!ssd->wb_tree) {
        return false;
    }

    held = g_tree_lookup(ssd->wb_tree, &target);
    if (!held) {
        return false;
    }

    buffer_remove(ssd, held);
    return true;
}

/* a read served from the buffer does not reach the media */
bool ssd_buffer_hit(struct ssd *ssd, uint64_t lpn)
{
    struct buffer_entry target = { .lpn = lpn };

    return g_tree_lookup(ssd->wb_tree, &target) != NULL;
}

/*
 * Cost of touching the buffer rather than the media, for both a write it
 * accepts and a read it answers. Derived from the page read time the same way
 * the read cache derives its own hit latency, so the two agree on what DRAM
 * costs relative to NAND on this device.
 *
 * This is a duration, not a completion time: every latency the datapath returns
 * is added to the request's expire_time by the FTL thread.
 */
uint64_t ssd_buffer_hit_lat(struct ssd *ssd)
{
    uint64_t lat;

    /* the controller DRAM time of a page, when the user gives one */
    if (ssd->sp.dram_hit_ns) {
        return ssd->sp.dram_hit_ns;
    }
    lat = ssd->sp.pg_rd_lat ? ssd->sp.pg_rd_lat / 16 : 1000;

    /* a configured page read time under 16ns would otherwise round to free */
    return lat > 0 ? lat : 1;
}

/*
 * Release the buffer. Safe only because femu_exit() joins the FTL thread first;
 * the pages it still owes are meaningless once the volatile backing store goes.
 */
void ssd_free_write_buffer(struct ssd *ssd)
{
    struct buffer_entry *entry;

    while ((entry = QTAILQ_FIRST(&ssd->write_buffer)) != NULL) {
        QTAILQ_REMOVE(&ssd->write_buffer, entry, b_entry);
        g_free(entry->undo);
        g_free(entry->lba_state);
        g_free(entry->written);
        g_free(entry);
    }
    ssd->write_buffer_cnt = 0;
    if (ssd->wb_tree) {
        g_tree_destroy(ssd->wb_tree);
        ssd->wb_tree = NULL;
    }
}

/* the namespace whose slice of the backend holds page @lpn */
static NvmeNamespace *ssd_lpn_ns(struct ssd *ssd, uint64_t lpn)
{
    uint64_t byte = lpn * ssd_page_size(ssd);
    FemuCtrl *n = ssd->n;

    for (uint32_t i = 0; i < n->namespace_limit; i++) {
        NvmeNamespace *ns = &n->namespaces[i];

        if (ns->allocated && ns->ssd == ssd && byte >= ns->backend_offset &&
            byte < ns->backend_offset + ns->size) {
            return ns;
        }
    }
    return ssd->ns;
}

/* the bytes and LBA states of page @lpn of @ns, as they are now */
static void ssd_page_snapshot(struct ssd *ssd, NvmeNamespace *ns,
                              uint64_t lpn, uint8_t **undo, uint8_t **state)
{
    uint32_t page_size = ssd_page_size(ssd);
    uint8_t shift = ns->lbaf.lbads;
    uint64_t offset = lpn * page_size - ns->backend_offset;
    uint64_t slba = offset >> shift;
    uint32_t count = page_size >> shift;
    uint8_t *base = (uint8_t *)ssd->n->mbe->logical_space + ns->backend_offset;

    *undo = g_memdup2(base + offset, page_size);
    *state = g_malloc(count);
    for (uint32_t i = 0; i < count; i++) {
        (*state)[i] = test_bit(slba + i, ns->util) |
                      (test_bit(slba + i, ns->uncorrectable) << 1) |
                      ((ns->sdc && test_bit(slba + i, ns->sdc)) << 2);
    }
}

/*
 * A direct (FUA or cache-off) write of page @lpn was booked. A buffered
 * copy of the page that this write replaces never reached the media, so
 * the generation keeps the bytes from before that copy, which stay the
 * last durable ones; else the page as it was before this write.
 */
static void ssd_durable_direct(struct ssd *ssd, NvmeNamespace *ns,
                               uint64_t lpn, uint8_t **snap,
                               uint8_t **snap_state)
{
    struct buffer_entry target = { .lpn = lpn };
    struct buffer_entry *entry = ssd->wb_tree ?
        g_tree_lookup(ssd->wb_tree, &target) : NULL;

    if (entry && entry->undo) {
        ssd_durable_push(ssd, ns, lpn, entry->undo, entry->lba_state,
                         ssd->last_prog_done);
        entry->undo = NULL;
        entry->lba_state = NULL;
        g_clear_pointer(snap, g_free);
        g_clear_pointer(snap_state, g_free);
        return;
    }
    ssd_durable_push(ssd, ns, lpn, *snap, *snap_state, ssd->last_prog_done);
    *snap = NULL;
    *snap_state = NULL;
}

/*
 * sdc misdirect: the bytes of [@first, @end) of this write land at the same
 * offsets of the first page after the command, in this namespace; those
 * blocks now hold data of another LBA. A namespace too small to have such
 * a page keeps the fault a lost write.
 */
static void buffer_misdirect(NvmeNamespace *ns, NvmeRequest *req,
                             uint32_t page_size, uint64_t first, uint64_t end)
{
    uint8_t shift = ns->lbaf.lbads;
    uint64_t pages = (ns->ns_blks << shift) / page_size;
    uint64_t lo = (req->slba << shift) / page_size;
    uint64_t hi = (((req->slba + req->nlb) << shift) - 1) / page_size;
    uint64_t y = (hi + 1) % MAX(pages, 1);
    uint64_t off;
    uint8_t *base = (uint8_t *)ns->ctrl->mbe->logical_space +
                    ns->backend_offset;

    if (pages <= hi - lo + 1) {
        return;
    }
    off = y * page_size + first % page_size;
    backend_lock_range(ns->ctrl->mbe, ns->backend_offset + y * page_size,
                       page_size);
    memcpy(base + off, req->write_data + first - (req->slba << shift),
           end - first);
    bitmap_set(ns->util, off >> shift, (end - first) >> shift);
    bitmap_set(ns->sdc, off >> shift, (end - first) >> shift);
    backend_unlock_range(ns->ctrl->mbe, ns->backend_offset + y * page_size,
                         page_size);
}

/* Save the last durable bytes once, then apply only this write's LBAs. */
static void buffer_write_data(struct ssd *ssd, NvmeRequest *req, uint64_t lpn,
                              bool buffered)
{
    NvmeNamespace *ns = req->ns;
    uint32_t page_size = ssd_page_size(ssd);
    uint8_t idx = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    uint8_t shift = ns->id_ns.lbaf[idx].lbads;
    uint64_t page_start = lpn * page_size - ns->backend_offset;
    uint64_t first = MAX(page_start, req->slba << shift);
    uint64_t end = MIN(page_start + page_size,
                       (req->slba + req->nlb) << shift);
    uint8_t *base = (uint8_t *)ssd->n->mbe->logical_space + ns->backend_offset;
    uint64_t flip_lba = 0;
    int fault;

    if (!req->write_data) {
        return;
    }
    /* a read on another poller sees the page before or after, never part */
    backend_lock_range(ssd->n->mbe, ns->backend_offset + page_start, page_size);
    if (buffered) {
        struct buffer_entry target = { .lpn = lpn };
        struct buffer_entry *entry = g_tree_lookup(ssd->wb_tree, &target);
        uint32_t count = page_size >> shift;
        uint64_t slba = page_start >> shift;

        if (!entry->undo) {
            entry->undo = g_memdup2(base + page_start, page_size);
            entry->lba_state = g_malloc(count);
            for (uint32_t i = 0; i < count; i++) {
                entry->lba_state[i] = test_bit(slba + i, ns->util) |
                    (test_bit(slba + i, ns->uncorrectable) << 1) |
                    ((ns->sdc && test_bit(slba + i, ns->sdc)) << 2);
            }
        }
    }
    fault = femu_sdc_fault(ns, first >> shift, end >> shift, &flip_lba);
    if (fault != FEMU_SDC_LOST && fault != FEMU_SDC_MISDIRECT) {
        memcpy(base + first, req->write_data + first - (req->slba << shift),
               end - first);
    }
    nvme_mark_written(ns, first >> shift, (end - first) >> shift);
    if (fault == FEMU_SDC_FLIP) {
        base[flip_lba << shift] ^= 1;
        set_bit(flip_lba, ns->sdc);
    } else if (fault) {
        /* the old bytes stay: an older version than the host wrote */
        bitmap_set(ns->sdc, first >> shift, (end - first) >> shift);
    }
    backend_unlock_range(ssd->n->mbe, ns->backend_offset + page_start,
                         page_size);
    if (fault == FEMU_SDC_MISDIRECT) {
        buffer_misdirect(ns, req, page_size, first, end);
    }
}

/* The caller is the FTL thread or an admin handler with processing paused. */
uint16_t bbssd_drain_namespace(NvmeNamespace *ns, uint64_t stime, int64_t *lat)
{
    int64_t elapsed;

    if (!ns->ctrl->power_loss || !ns->ssd) {
        return NVME_SUCCESS;
    }
    elapsed = ssd_buffer_destage(ns->ssd, 0, stime);
    if (lat) {
        *lat = MAX(*lat, elapsed);
    }
    return ns->ssd->write_buffer_cnt ? NVME_CAP_EXCEEDED | NVME_DNR :
                                      NVME_SUCCESS;
}

/*
 * Admin callers hold both pollers and the FTL thread paused. Every
 * namespace is written back, also after one fails; the first failure is
 * the result.
 */
uint16_t bbssd_flush_all(FemuCtrl *n)
{
    uint64_t now = femu_dev_now(n);
    uint16_t status = NVME_SUCCESS;

    for (uint32_t i = 0; i < n->namespace_limit; i++) {
        NvmeNamespace *ns = &n->namespaces[i];

        /*
         * A KV namespace has an ssd for timing, but no buffer or lines. A
         * shared namespace has the buffer of the controller that made it.
         */
        if (ns->allocated && ns->ssd && (NS_BBSSD(ns) || NS_CSD(ns)) &&
            ns->ssd->sp.buffer_size > 0) {
            struct ssd *ssd = ns->ssd;
            uint64_t lat = ssd_buffer_destage(ssd, 0, now);

            /* no command waits for these programs; a later Flush does */
            ssd->buffer_bg_fence = MAX(ssd->buffer_bg_fence, now + lat);
            if (ssd->write_buffer_cnt && !status) {
                status = NVME_CAP_EXCEEDED | NVME_DNR;
            }
        }
    }
    return status;
}

/*
 * Called with the controller stopped; old mappings still name durable pages.
 * Returns true when the cut dropped a buffered page.
 */
bool bbssd_power_loss(NvmeNamespace *ns)
{
    bool lost = false;
    struct ssd *ssd = ns->ssd;
    struct buffer_entry *entry;
    uint32_t page_size = ssd_page_size(ssd);
    uint8_t idx = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    uint8_t shift = ns->id_ns.lbaf[idx].lbads;
    uint8_t *base = (uint8_t *)ssd->n->mbe->logical_space + ns->backend_offset;

    /* OCP SMART-21 resets on a power cycle */
    qatomic_set(&ssd->unaligned_writes, 0);
    QTAILQ_FOREACH(entry, &ssd->write_buffer, b_entry) {
        uint64_t offset = entry->lpn * page_size - ns->backend_offset;
        uint64_t slba = offset >> shift;
        uint64_t added = 0;
        uint64_t gone = 0;

        if (!entry->undo) {
            continue;
        }
        lost = true;
        /* an acknowledged version that a lie kept volatile is gone */
        if (entry->lie) {
            ssd->n->fault_lie_lost++;
        }
        memcpy(base + offset, entry->undo, page_size);
        for (uint32_t i = 0; i < page_size >> shift; i++) {
            if (entry->lba_state[i] & 1) {
                set_bit(slba + i, ns->util);
            } else {
                clear_bit(slba + i, ns->util);
            }
            femu_lsi_restore(ns, slba + i, entry->lba_state[i] & 2, &added,
                             &gone);
            if (ns->sdc && (entry->lba_state[i] & 4)) {
                set_bit(slba + i, ns->sdc);
            } else if (ns->sdc) {
                clear_bit(slba + i, ns->sdc);
            }
        }
        femu_lsi_changed(ns, added, gone);
        rcache_invalidate(ssd, entry->lpn);
    }
    /* durable_at_done: programs that had not ended give their pages back */
    if (ssd_durable_on(ssd) && ssd->ns == ns) {
        lost |= ssd_durable_cut(ssd, ssd->n->durable_cut);
    }
    while ((entry = QTAILQ_FIRST(&ssd->write_buffer))) {
        ssd_buffer_discard(ssd, entry->lpn);
    }
    return lost;
}

/*
 * awupf_lbas: a write of at most N blocks keeps the before-image of each
 * page it changes (see ssd_write()).
 */
static bool ssd_write_snap_all(struct ssd *ssd, NvmeRequest *req,
                               uint32_t nlb)
{
    return ssd->n->awupf_lbas && req->write_data &&
           nlb <= ssd->n->awupf_lbas;
}

/* such a write over more than one page is one transaction off the buffer */
static bool ssd_write_txn(struct ssd *ssd, NvmeRequest *req, uint32_t nlb,
                          uint64_t start_lpn, uint64_t end_lpn)
{
    return ssd_write_snap_all(ssd, req, nlb) && start_lpn != end_lpn;
}

/* the facts of a lie in this FTL step, before the FUA pages count */
static void ssd_lie_facts(NvmeNamespace *ns, uint8_t act, bool failed,
                          FemuFsLie *s)
{
    *s = (FemuFsLie) {
        .act = act,
        .failed = failed,
        .plp = femu_plp_ok(ns->ctrl),
        .buffer = ssd_buffer_enabled(ns->ssd),
    };
    /* a Flush exposes what the buffer holds; empty, it claims nothing */
    if (act == FEMU_FS_ACT_FLUSH_LIE) {
        s->pages = ns->ssd->write_buffer_cnt;
    }
}

/**
 * bbssd_flush_lie - whether a Flush that flush-lie selected skips its destage
 * @ns: the namespace of the Flush, which passed its checks
 *
 * The FTL thread asks before the destage; bbssd_lie_apply() asks the
 * same in the same step, so the two agree.
 */
bool bbssd_flush_lie(NvmeNamespace *ns)
{
    FemuFsLie s;

    ssd_lie_facts(ns, FEMU_FS_ACT_FLUSH_LIE, false, &s);
    return femu_fs_lie_why(&s) == FEMU_FS_WHY_NONE;
}

/**
 * bbssd_lie_apply - mark the pages a lie left volatile
 * @ns: the namespace of the command, or NULL
 * @req: the command, which the FTL has run
 * @act: FEMU_FS_ACT_FLUSH_LIE or FEMU_FS_ACT_FUA_LIE
 * @slba: the first block of a FUA Write, as the command line saw it
 * @nlb: its blocks
 * @pages: the buffered pages that took the lie mark
 *
 * A lying Flush skipped its destage, so every page in the buffer is one
 * the host now counts as durable. A lying FUA Write took the buffered
 * path, so each of its pages still in the buffer is such a page. A page
 * that a write-back in the command programmed is durable and stays
 * unmarked. With no such page the lie has no effect, reason durable.
 *
 * Returns FEMU_FS_WHY_NONE when the lie had its effect, else the reason.
 */
uint8_t bbssd_lie_apply(NvmeNamespace *ns, NvmeRequest *req, uint8_t act,
                        uint64_t slba, uint32_t nlb, uint32_t *pages)
{
    struct buffer_entry *entry;
    struct ssd *ssd;
    FemuFsLie s;
    uint64_t start_lpn;
    uint64_t end_lpn;
    uint8_t why;

    *pages = 0;
    if (!ns || !ns->ssd) {
        return FEMU_FS_WHY_CMD_FAILED;
    }
    ssd = ns->ssd;
    ssd_lie_facts(ns, act, req->status != NVME_SUCCESS, &s);
    if (act == FEMU_FS_ACT_FUA_LIE && !s.failed && !s.plp && s.buffer) {
        ssd_lpn_range(ssd, req, slba, nlb, &start_lpn, &end_lpn);
        s.atomic = ssd_write_txn(ssd, req, nlb, start_lpn, end_lpn);
        for (uint64_t lpn = start_lpn; !s.atomic && lpn <= end_lpn; lpn++) {
            entry = ssd_buffer_lookup(ssd, lpn);
            if (entry) {
                entry->lie = true;
                s.pages++;
            }
        }
    }
    why = femu_fs_lie_why(&s);
    if (why != FEMU_FS_WHY_NONE) {
        return why;
    }
    if (act == FEMU_FS_ACT_FLUSH_LIE) {
        QTAILQ_FOREACH(entry, &ssd->write_buffer, b_entry) {
            entry->lie = true;
        }
    }
    *pages = s.pages;
    return why;
}

/*
 * Queue the line holding a page that has just been read for a rewrite if
 * read stress or retention age calls for one.
 */
void ssd_read_check_wear(struct ssd *ssd, struct ppa *ppa, uint64_t stime)
{
    struct ssdparams *spp = &ssd->sp;
    struct nand_block *blk = get_blk(ssd, ppa);

    /*
     * A block that is only part programmed takes read stress worse than a
     * full one, so firmware refreshes it at a lower read count. Checked
     * first: it is the lower limit. It also takes over a request already
     * queued for the same line, which only a refresh for this reason may
     * take out of a write pointer.
     */
    if (spp->pd_open_read_limit &&
        (!ssd->read_reclaim_line ||
         ssd->read_reclaim_line == get_line(ssd, ppa)) &&
        blk->wp > 0 && blk->wp < spp->pgs_per_blk &&
        blk->read_cnt >= (uint64_t)spp->pd_open_read_limit) {
        ssd->read_reclaim_line = get_line(ssd, ppa);
        ssd->reclaim_why = RECLAIM_OPEN;
    }

    /*
     * Enough reads against this block to be worth refreshing the line it
     * belongs to. Only note it here -- the rewrite happens on a write,
     * where relocation already costs something, rather than stalling this
     * read behind a whole line of it. One line is queued at a time, which
     * is the rate limit.
     */
    if (spp->read_reclaim_limit && !ssd->read_reclaim_line &&
        blk->read_cnt >= (uint64_t)spp->read_reclaim_limit) {
        ssd->read_reclaim_line = get_line(ssd, ppa);
        ssd->reclaim_why = RECLAIM_READS;
    }

    /*
     * Charge leaks out of a cell whether or not anything reads it, so data
     * that has merely sat programmed long enough is refreshed as well. A
     * line's close_time is when it was filled; one still being written has
     * none yet and cannot be old. Queued here and rewritten on a write for
     * the same reason as read stress: that is where relocation belongs.
     */
    if (spp->retention_limit_sec && !ssd->read_reclaim_line) {
        struct line *aged = get_line(ssd, ppa);
        uint64_t limit = (uint64_t)spp->retention_limit_sec *
                         NANOSECONDS_PER_SECOND;

        if (ssd_data_age_ns(ssd, aged->close_time, stime) >= limit) {
            ssd->read_reclaim_line = aged;
            ssd->reclaim_why = RECLAIM_AGE;
        }
    }
}

/*
 * Multi-plane commands. NAND can program or read the same page of one block
 * on several planes of a LUN with one command: the per-plane command,
 * address and data phases still take turns on the channel, but the array
 * work runs once on all the planes. Placement is unchanged; pages are held
 * per LUN until they stop forming such a group, then charged together.
 */
/* FDP shares this read path but keeps its own timing, so it is left alone */
static inline bool ssd_mp_reads(struct ssd *ssd)
{
    return ssd->sp.mp_read && !ssd->fdp_enabled;
}

static bool ssd_mp_fits(struct ssd_mp_batch *b, struct ppa *ppa,
                        uint64_t stime)
{
    struct ppa *first = &b->ppa[0];
    int i;

    if (b->stime != stime || first->g.ch != ppa->g.ch ||
        first->g.lun != ppa->g.lun || first->g.blk != ppa->g.blk ||
        first->g.pg != ppa->g.pg) {
        return false;
    }
    for (i = 0; i < b->n; i++) {
        if (b->ppa[i].g.pl == ppa->g.pl) {
            return false;
        }
    }
    return true;
}

/* charge a LUN's held pages as one command and empty the batch */
static uint64_t ssd_mp_charge(struct ssd *ssd, struct ssd_mp_batch *b,
                              int cmd)
{
    struct nand_cmd ncmd;
    uint64_t lat;
    int i;

    if (!b->n) {
        return 0;
    }
    ncmd.type = USER_IO;
    ncmd.cmd = cmd;
    ncmd.stime = b->stime;
    lat = ssd_advance_status_multiplane(ssd, b->ppa, b->n, &ncmd) +
          (b->stime - b->base);
    if (cmd == NAND_READ) {
        for (i = 0; i < b->n; i++) {
            ssd_read_check_wear(ssd, &b->ppa[i], b->stime);
        }
    }
    b->n = 0;
    return lat;
}

/*
 * Hold one page for a multi-plane command that starts at @stime, for a
 * request that started at @base; returns what any charge cost from @base.
 */
static uint64_t ssd_mp_add(struct ssd *ssd, struct ppa *ppa, uint64_t stime,
                           uint64_t base, int cmd)
{
    struct nand_lun *lun = get_lun(ssd, ppa);
    struct ssd_mp_batch *b = cmd == NAND_READ ? &lun->mp_rd : &lun->mp_prog;
    uint64_t lat = 0;

    if (b->n && !ssd_mp_fits(b, ppa, stime)) {
        lat = ssd_mp_charge(ssd, b, cmd);
    }
    if (!b->n) {
        b->stime = stime;
        b->base = base;
    }
    b->ppa[b->n++] = *ppa;
    if (b->n == ssd->sp.pls_per_lun) {
        lat = MAX(lat, ssd_mp_charge(ssd, b, cmd));
    }
    return lat;
}

/* charge every held page of one kind; returns the longest latency */
static uint64_t ssd_mp_flush(struct ssd *ssd, int cmd);

/**
 * ssd_mp_drain_programs - charge every held multi-plane program now
 * @ssd: the FTL
 *
 * For a pSLC fold, which reads and erases pool pages: a page whose program
 * is still held would be read before it is written. Returns the latency
 * from the start of the request that holds them; 0 without mp_program.
 */
uint64_t ssd_mp_drain_programs(struct ssd *ssd)
{
    return ssd_mp_flush(ssd, NAND_WRITE);
}

static uint64_t ssd_mp_flush(struct ssd *ssd, int cmd)
{
    struct ssdparams *spp = &ssd->sp;
    uint64_t lat = 0;
    int ch, lun;

    if (!(cmd == NAND_READ ? ssd_mp_reads(ssd) : spp->mp_program)) {
        return 0;
    }
    for (ch = 0; ch < spp->nchs; ch++) {
        for (lun = 0; lun < spp->luns_per_ch; lun++) {
            struct nand_lun *l = &ssd->ch[ch].lun[lun];

            lat = MAX(lat, ssd_mp_charge(ssd, cmd == NAND_READ ?
                                         &l->mp_rd : &l->mp_prog, cmd));
        }
    }
    return lat;
}

/*
 * What the translation of @lpn adds to an access that starts at @stime, as
 * a duration; nothing without mapping=dftl. With translation pages on flash
 * the CMT reads and writes them where they are, otherwise (FDP) it charges
 * placeholder pages.
 */
/*
 * io_causes: the parts of a translation that took @T beyond the DRAM
 * lookup. The waits of the TP read it booked keep their owners; the rest
 * (the TP read itself, the wait for its earlier read or program, a TP read
 * in flight) is the map part.
 */
static void ssd_map_parts(struct ssd *ssd, uint64_t T)
{
    uint64_t w = 0;

    memset(&ssd->wc_map, 0, sizeof(ssd->wc_map));
    if (ssd->wc_tp_set) {
        ssd->wc_map = ssd->wc_tp;
        for (int c = 0; c < FEMU_WAIT_NCAT; c++) {
            w += ssd->wc_tp.ns[c];
        }
    }
    ssd->wc_map.ns[FEMU_WAIT_MAP] += T > w ? T - w : 0;
}

/*
 * The same, and with io_causes the parts in wc_map (none for a DRAM-only
 * lookup).
 */
static uint64_t ssd_map_lat(struct ssd *ssd, uint64_t lpn, uint64_t stime,
                            bool is_write)
{
    /* the controller DRAM access of the lookup itself (l2p_dram_ns) */
    uint64_t dram = ssd->sp.l2p_dram_ns;
    uint64_t t;
    uint64_t T;

    if (ssd->wc_on) {
        memset(&ssd->wc_map, 0, sizeof(ssd->wc_map));
    }
    if (!ssd->cmt.capacity) {
        return dram;
    }
    /* the whole table in the host's memory (HMB): one PCIe round trip */
    if (ssd->n && qatomic_read(&ssd->n->hmb_active)) {
        if (ssd->wc_on) {
            ssd->wc_map.ns[FEMU_WAIT_MAP] = ssd->n->hmb_ns;
        }
        return dram + ssd->n->hmb_ns;
    }
    if (!ssd->tp_on) {
        return dram + cmt_touch(ssd, lpn, stime, is_write);
    }
    t = stime ? stime : ssd_now(ssd);
    ssd->wc_tp_set = false;
    T = cmt_access(ssd, lpn, t, is_write) - t;
    if (ssd->wc_on) {
        ssd_map_parts(ssd, T);
    }
    return dram + T;
}

/*
 * Translate and program @lpn for a host write or a write-back that starts
 * at @stime. Placement waits for the translation only when it depends on
 * the old mapping (hot/cold separation, with translation pages on flash);
 * otherwise the two run in parallel and the later one ends the page.
 */
static uint64_t ssd_program_lpn(struct ssd *ssd, uint64_t lpn, uint64_t stime,
                                uint64_t base, int stream, bool *placed);

static uint64_t ssd_map_and_program(struct ssd *ssd, uint64_t lpn,
                                    uint64_t stime, int stream, bool *placed);
static uint64_t ssd_gc_until_clear(struct ssd *ssd);

/* one merge of a log-block mapping, as one collection pass */
static uint64_t ssd_map_reclaim(struct ssd *ssd)
{
    bool opened = ssd_gc_pass_begin(ssd);
    uint64_t lat = ssd->mapping->reclaim(ssd, 1);

    ssd_gc_pass_end(ssd, opened);
    return lat;
}

/*
 * An indirection unit of iu_pages pages (QLC drives map 16 KiB or more):
 * a write that covers only part of a unit reads the unit's other mapped
 * pages and programs them again with it. The reads go first; the programs
 * of the kept pages start when they end. Returns the latency, 0 when the
 * write covers whole units.
 */
static uint64_t ssd_iu_rmw(struct ssd *ssd, uint64_t start_lpn,
                           uint64_t end_lpn, uint64_t stime, int stream)
{
    uint64_t iu = ssd->sp.iu_pages;
    uint64_t first = start_lpn / iu * iu;
    uint64_t last = MIN((end_lpn / iu + 1) * iu, (uint64_t)ssd->sp.tt_pgs) - 1;
    uint64_t rd = 0;
    uint64_t maxlat = 0;

    for (int pass = 0; pass < 2; pass++) {
        for (uint64_t lpn = first; lpn <= last; lpn++) {
            struct ppa ppa;

            if (lpn >= start_lpn && lpn <= end_lpn) {
                continue;
            }
            ppa = get_maptbl_ent(ssd, lpn);
            if (!mapped_ppa(&ppa) || !valid_ppa(ssd, &ppa)) {
                continue;
            }
            if (pass == 0) {
                struct nand_cmd r = {
                    .type = GC_IO, .cmd = NAND_READ, .stime = stime,
                };

                rd = MAX(rd, ssd_advance_status(ssd, &ppa, &r));
            } else {
                if (ssd_host_out_of_lines(ssd)) {
                    break;
                }
                bool placed;

                maxlat = MAX(maxlat, ssd_gc_until_clear(ssd));
                maxlat = MAX(maxlat, rd + ssd_map_and_program(ssd, lpn,
                                                              stime + rd,
                                                              stream, &placed));
                /* an unplaced page keeps its old mapping, which still reads */
                if (!placed) {
                    break;
                }
                ssd->iu_rmw_pages++;
            }
        }
    }
    return maxlat;
}

static uint64_t ssd_map_and_program(struct ssd *ssd, uint64_t lpn,
                                    uint64_t stime, int stream, bool *placed)
{
    uint64_t map = ssd_map_lat(ssd, lpn, stime, true);
    uint64_t t = stime ? stime : ssd_now(ssd);
    /* the program helpers overwrite wc_map with their own lookups */
    FemuWaitParts mp = ssd->wc_map;

    /* a translation program is not the data page: @placed is the program's */
    if (ssd->tp_on && ssd->sp.hot_cold_sep && map) {
        uint64_t p = ssd_program_lpn(ssd, lpn, t + map, t, stream, placed);

        /* serial: the program waits for the translation */
        if (ssd->wc_on) {
            for (int c = 0; c < FEMU_WAIT_NCAT; c++) {
                ssd->wc_last.ns[c] += mp.ns[c];
            }
        }
        return p;
    }
    {
        uint64_t p = ssd_program_lpn(ssd, lpn, stime, stime, stream, placed);

        /* parallel: the later one ends the page; the lookup wins a tie */
        if (ssd->wc_on && p <= map) {
            ssd->wc_last = mp;
        }
        return MAX(map, p);
    }
}

/*
 * Program one logical page: choose placement through the mapping scheme,
 * commit it, and charge the media. Shared by the ordinary write path and by
 * the eviction of a buffered page, so both cost the same. The program starts
 * at @stime, which is later than the request start @base when placement had
 * to wait for the translation; the latency counts from @base.
 */
static uint64_t ssd_program_lpn(struct ssd *ssd, uint64_t lpn, uint64_t stime,
                                uint64_t base, int stream, bool *placed)
{
    struct map_write_plan plan;
    struct nand_cmd swr;
    struct ppa ppa;
    uint64_t lat;
    uint64_t more;
    bool pslc = false;
    FemuWaitParts mine;

    /* io_causes: a page that finds no place has no media wait */
    if (ssd->wc_on) {
        memset(&ssd->wc_last, 0, sizeof(ssd->wc_last));
    }

    /* log the overwrite before commit_write invalidates the old mapping */
    if (exp_lpn_watched(lpn)) {
        struct ppa old = ssd->mapping->translate(ssd, lpn);
        if (mapped_ppa(&old))
            EXP_LOG("[INVALIDATE:overwrite] lpn=%lu old " PPA_FMT "\n",
                    lpn, PPA_ARG(&old));
    }

    /*
     * x-place-fail: qtest makes this page find no place, before any change;
     * x-place-skip lets that many placements pass first.
     */
    if (unlikely(ssd->n && qatomic_read(&ssd->n->test_place_skip))) {
        uint32_t *skip = &ssd->n->test_place_skip;
        uint32_t v = qatomic_read(skip);

        /* a qom-set to 0 in between takes none */
        while (v && qatomic_cmpxchg(skip, v, v - 1) != v) {
            v = qatomic_read(skip);
        }
    } else if (unlikely(ssd->n && qatomic_read(&ssd->n->test_place_fail))) {
        uint32_t *left = &ssd->n->test_place_fail;
        uint32_t v = qatomic_read(left);

        /* take one count; a qom-set to 0 in between takes none */
        while (v && qatomic_cmpxchg(left, v, v - 1) != v) {
            v = qatomic_read(left);
        }
        if (v) {
            *placed = false;
            return stime > base ? stime - base : 0;
        }
    }

    /* mapping scheme picks placement (page/dftl: data class, no reclaim) */
    plan = ssd->mapping->prepare_write(ssd, lpn, USER_IO);

    /* the page content changes: drop any stale read-cache entry for it */
    rcache_invalidate(ssd, lpn);

    /* allocate from the class the scheme asked for and commit the mapping */
    if (stream >= 0) {
        /* Sub-SWS writes share their FTL page and line with its other LBAs. */
        ppa = ssd_stream_page(ssd, stream,
                              ssd->n->stream_slots[stream].tag);
    } else if (unlikely(ssd->tier) &&
               ftl_tier_host_page(ssd, &ppa, &stime, &base)) {
        /* a pSLC tier page, taken before the mapping changes */
        pslc = true;
    } else {
        ppa = get_new_page_class(ssd, plan.target_class);
        /* a through fold can take the dense page the caller secured */
        if (unlikely(ssd->tier) && !mapped_ppa(&ppa)) {
            if (ssd_out_of_lines(ssd)) {
                ftl_tier_place_failed(ssd);
                *placed = false;
                return MAX(stime > base ? stime - base : 0,
                           ftl_tier_take_drain(ssd));
            }
            ppa = get_new_page_class(ssd, plan.target_class);
        }
    }
    ssd->mapping->commit_write(ssd, lpn, &ppa);
    /*
     * Placed: the mapping names a new page and its program is booked. A
     * program held for a multi-plane batch counts; the caller's
     * ssd_mp_flush() charges it.
     */
    *placed = true;

    mark_page_valid(ssd, &ppa);
    ssd->nand_write_pages++; /* write amplification: a user page programmed */
    if (unlikely(ssd->nr_ns_slices)) {
        ssd_ns_ctr_of(ssd, lpn)->nand_write_pages++;
    }
    /* only log + track pages that carry the marker string */
    if (femu_dbg_lpn_has_secret(ssd, lpn)) {
        exp_watch_lpn_add(lpn);
        exp_watch_blk[ppa.g.blk] = 1;
        EXP_LOG("[WRITE] lpn=%lu -> " PPA_FMT " (secret)\n",
                lpn, PPA_ARG(&ppa));
    }

    /* need to advance the write pointer here */
    if (stream >= 0) {
        ssd_stream_advance(ssd, stream);
    } else if (pslc) {
        ftl_tier_advance(ssd);
    } else {
        ssd_advance_write_pointer_class(ssd, plan.target_class);
    }

    if (ssd->sp.mp_program) {
        lat = ssd_mp_add(ssd, &ppa, stime, base, NAND_WRITE);
        memset(&mine, 0, sizeof(mine));
    } else {
        swr.type = USER_IO;
        swr.cmd = NAND_WRITE;
        swr.stime = stime;
        lat = ssd_advance_status(ssd, &ppa, &swr) + (stime - base);
        mine = ssd->wc_last;
    }
    /* held programs a fold for this page charged belong to this request */
    if (unlikely(ssd->tier)) {
        wc_max(ssd, &lat, &mine, ftl_tier_take_drain(ssd), NULL);
    }
    /* A full logical log cannot accept another program in this command. */
    if (ssd->mapping->reclaim_per_page &&
        ssd->mapping->needs_reclaim(ssd)) {
        /* the merge reads pages this command may still hold */
        more = ssd_mp_flush(ssd, NAND_WRITE);
        wc_max(ssd, &lat, &mine, more, NULL);
        more = ssd_map_reclaim(ssd);
        /* io_causes: the command does this collection itself, all gc */
        {
            FemuWaitParts gc = { .ns[FEMU_WAIT_GC] = more };

            wc_max(ssd, &lat, &mine, more, &gc);
        }
    }
    /* paced collection copies its share after the host page has its slot */
    if (ssd->sp.gc_pace) {
        ssd_pace_program(ssd);
    }
    if (ssd->wc_on) {
        ssd->wc_last = mine;
    }
    return lat;
}

/*
 * Force collection while free lines sit at the watermark, or until it stalls.
 * Held programs are charged first, since they were issued before the
 * collection. Returns what that charge cost.
 */
static uint64_t ssd_gc_until_clear(struct ssd *ssd)
{
    uint64_t lat = 0;
    bool opened;

    if (should_gc_high(ssd)) {
        lat = ssd_mp_flush(ssd, NAND_WRITE);
    }
    /* one clock for the loop: host time between victims adds nothing */
    opened = ssd_gc_pass_begin(ssd);
    while (should_gc_high(ssd)) {
        if (do_gc(ssd, true) == -1) {
            break;
        }
        ssd->gc_stall_passes++;
    }
    ssd_gc_pass_end(ssd, opened);
    return lat;
}

/*
 * Write buffered pages back to the media. This is the one place a buffered page
 * becomes a programmed one, and it owns everything that owning a host write
 * entails: GC backpressure, the mapping translation cost, the program itself,
 * and the mapping scheme's own reclaim. The direct write path charges the same
 * things, so a page costs the same whether it was buffered or not -- only when
 * it is charged differs.
 *
 * budget caps how many pages one call may program, or is 0 for "all of them".
 * The returned latency is charged to whichever event forced the progress: a
 * host write that found the buffer full, a flush, or teardown of the cache.
 */
static uint64_t buffer_destage(struct ssd *ssd, int budget, uint64_t stime,
                               bool bg)
{
    struct buffer_entry *victim;
    uint64_t maxlat = 0, curlat;
    uint64_t book;
    uint64_t wait;
    bool protect;
    bool placed;
    int done = 0;
    uint64_t media0 = unlikely(ssd->tier) ? ssd_media_last_end(ssd) : 0;

    /* under FDP each page goes to the unit of its own placement handle */
    if (ssd->fdp_enabled) {
        return fdp_buffer_destage(ssd, budget, stime);
    }

    while (budget <= 0 || done < budget) {
        /* no line left: nothing can be placed */
        if (ssd_out_of_lines(ssd)) {
            break;
        }
        /*
         * An idle write-back with the pSLC tier stays bounded: it runs no
         * forced GC and no fold. If the next page needs one, it stops and
         * leaves the fold to upkeep, or the GC to a later write.
         */
        if (bg && unlikely(ssd->tier)) {
            enum ftl_tier_place where;

            if (should_gc_high(ssd)) {
                break;
            }
            where = ftl_tier_place_query(ssd, stime);
            if (where == FTL_TIER_PLACE_FOLD) {
                ftl_tier_bg_deferred(ssd);
                break;
            }
            if (where == FTL_TIER_PLACE_WAIT) {
                break;
            }
        }

        /*
         * Free space is consumed as pages are programmed, not as they are
         * accepted, so a long write-back has to keep checking rather than rely
         * on the single check the host write already made.
         */
        curlat = ssd_gc_until_clear(ssd);
        maxlat = (curlat > maxlat) ? curlat : maxlat;
        /* the collection above can consume the last line, so ask again */
        if (ssd_out_of_lines(ssd)) {
            break;
        }

        victim = QTAILQ_FIRST(&ssd->write_buffer);
        if (!victim) {
            break;
        }
        /*
         * durable_at_done: no program without room for its generation,
         * and none before a journal slot is free.
         */
        protect = ssd_durable_on(ssd) && victim->undo;
        book = stime;
        wait = 0;
        if (protect) {
            if (!ssd_durable_room(ssd)) {
                break;
            }
            wait = ssd_durable_start(ssd, stime, &book);
        }

        /* with dftl, the translation goes with the program */
        curlat = wait + ssd_map_and_program(ssd, victim->lpn, book, -1,
                                            &placed);
        maxlat = (curlat > maxlat) ? curlat : maxlat;
        /*
         * The entry leaves only once its page is placed. One with nowhere
         * to go keeps its place at the head and the write-back stops.
         */
        if (!placed) {
            break;
        }
        /* its bytes before the buffered write stay until the program ends */
        if (protect) {
            ssd_durable_slot_used(ssd, ssd->last_prog_done);
            ssd_durable_push(ssd, ssd_lpn_ns(ssd, victim->lpn), victim->lpn,
                             victim->undo, victim->lba_state,
                             ssd->last_prog_done);
            victim->undo = NULL;
            victim->lba_state = NULL;
        }
        buffer_remove(ssd, victim);
        done++;
    }
    curlat = ssd_mp_flush(ssd, NAND_WRITE);
    maxlat = (curlat > maxlat) ? curlat : maxlat;
    /* pe_suspend: a read can move these programs until a Flush seals them */
    if (done) {
        ssd->buffer_unsealed = true;
    }

    /*
     * Schemes without per-page reclaim get one merge per batch: for a
     * log-block scheme that is a merge, and its NAND cost is charged inside
     * reclaim(). page and dftl have no reclaim and skip this.
     */
    if (done && !ssd->mapping->reclaim_per_page &&
        ssd->mapping->needs_reclaim && ssd->mapping->reclaim &&
        ssd->mapping->needs_reclaim(ssd)) {
        curlat = ssd_map_reclaim(ssd);
        maxlat = (curlat > maxlat) ? curlat : maxlat;
    }

    if (unlikely(ssd->tier)) {
        uint64_t end = ssd_media_last_end(ssd);

        ftl_tier_destaged(ssd, MAX(end, (stime ? stime : ssd_now(ssd)) +
                                        maxlat), done > 0 || end > media0);
    }
    return maxlat;
}

uint64_t ssd_buffer_destage(struct ssd *ssd, int budget, uint64_t stime)
{
    return buffer_destage(ssd, budget, stime, false);
}

/**
 * ssd_buffer_flush_seal - make the write-back programs stay where they are
 * @ssd: the device
 * @stime: start time of the Flush
 *
 * With pe_suspend, a read suspends a program on its LUN, and the program
 * then ends after its booked end. A Flush that waited for the booked end
 * would complete before its data is on the media. So the Flush waits for
 * the live end of the work on each LUN and seals the LUN there: no read
 * moves that work again (ssd_media_seal()).
 *
 *   booked  [prog 1][prog 2]           Flush waits until F
 *   a read before the Flush moved prog 1:
 *   live    [p][rd][prog 1 ][prog 2]|  seal at the live end: F moves here
 *   a read after the Flush, before F:   it starts at the seal
 *
 * All LUNs get a seal: a write-back also books collection, translation
 * pages and parity on other LUNs. Returns how long the Flush waits: 0 with
 * pe_suspend off, and 0 when the sealed work ended before @stime.
 */
uint64_t ssd_buffer_flush_seal(struct ssd *ssd, uint64_t stime)
{
    struct ssdparams *spp = &ssd->sp;
    struct ppa ppa = { .ppa = 0 };
    uint64_t end = 0;
    int ch;
    int lun;

    if (!spp->pe_suspend) {
        return 0;
    }
    if (ssd->buffer_unsealed) {
        for (ch = 0; ch < spp->nchs; ch++) {
            for (lun = 0; lun < spp->luns_per_ch; lun++) {
                ppa.g.ch = ch;
                ppa.g.lun = lun;
                end = MAX(end, ssd_media_seal(ssd, &ppa));
            }
        }
        ssd->buffer_flush_fence = MAX(ssd->buffer_flush_fence, end);
        ssd->buffer_unsealed = false;
        ssd->flush_seals++;
    }
    return ssd->buffer_flush_fence > stime ?
           ssd->buffer_flush_fence - stime : 0;
}

/**
 * ssd_flush_report - the Flush state under pe_suspend, for tests
 * @ssd: the device
 *
 * Four numbers in model time: the Flushes that sealed the LUNs, when the
 * newest Flush completes, when the newest program or erase ends, and the
 * reads that a seal made wait. All 0 with pe_suspend off. After a Flush,
 * with no write-back since, the third is at most the second.
 */
char *ssd_flush_report(struct ssd *ssd)
{
    return g_strdup_printf("%" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64,
                           ssd->flush_seals, ssd->flush_done,
                           nand_media_pe_end(&ssd->media),
                           ssd->media.seal_waits);
}

/*
 * Charge the media reads of one command that onfi_cache_read held back:
 * the pages of each LUN, in LPN order, as one read cache sequence. Their
 * counts and wear checks already ran in LPN order.
 */
static uint64_t ssd_read_seq_charge(struct ssd *ssd, const NandLoc *pend,
                                    uint32_t n, uint64_t stime)
{
    g_autofree NandLoc *grp = g_new(NandLoc, n);
    g_autofree bool *done = g_new0(bool, n);
    uint64_t lat, maxlat = 0;
    uint32_t i, j, k;

    for (i = 0; i < n; i++) {
        if (done[i]) {
            continue;
        }
        for (k = 0, j = i; j < n; j++) {
            if (!done[j] && pend[j].ch == pend[i].ch &&
                pend[j].lun == pend[i].lun) {
                grp[k++] = pend[j];
                done[j] = true;
            }
        }
        lat = ssd_advance_status_seq(ssd, grp, k, stime);
        maxlat = MAX(maxlat, lat);
    }
    return maxlat;
}

uint64_t ssd_read(struct ssd *ssd, NvmeRequest *req)
{
    struct ssdparams *spp = &ssd->sp;
    struct ppa ppa;
    uint64_t start_lpn, end_lpn;
    uint64_t lpn;
    uint64_t sublat, maxlat = 0;
    /*
     * The request start the media latencies count from. A start of 0 means
     * now; only a translation that delays the page needs that time at once.
     */
    uint64_t base = req->stime || !ssd->tp_on ? req->stime :
                    ssd_now(ssd);
    uint64_t map, dstart, wait;
    g_autofree NandLoc *pend = NULL;
    uint32_t npend = 0;
    uint64_t seq_stime = 0;
    /* an offline die with no parity has lost its pages (OCP event 0016h) */
    int lost_die = ssd_parity_on(spp) ? -1 : ssd_offline_die(ssd);
    bool lost = false;
    bool failed;
    FemuWaitParts best = { 0 };

    /* the Read Recovery Level bounds host Read commands only */
    ssd->rber_failed = false;
    ssd->rrl_read = req->cmd.opcode == NVME_CMD_READ;

    ssd_lpn_range(ssd, req, req->slba, req->nlb, &start_lpn, &end_lpn);

    if (end_lpn >= spp->tt_pgs) {
        ftl_err("read past device geometry: end_lpn=%" PRIu64 " tt_pgs=%"
                PRId64 "\n",
                end_lpn, ssd->sp.tt_pgs);
        req->status = NVME_LBA_RANGE | NVME_DNR;
        return 0;
    }

    /* normal IO read path */
    ssd->sp.read_cnt += end_lpn - start_lpn + 1;
    if (spp->onfi_cache_read) {
        pend = g_new(NandLoc, end_lpn - start_lpn + 1);
        /* as ssd_advance_status(): no start time means now */
        seq_stime = req->stime ? req->stime :
                    ssd_now(ssd);
    }
    for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
        /*
         * A page the write buffer is still holding is served from there: it
         * costs a DRAM access and does not reach the media. The buffer is
         * checked even when it has stopped accepting writes, since it can still
         * be holding pages that have not been written back yet.
         */
        if (ssd->write_buffer_cnt && ssd_buffer_hit(ssd, lpn)) {
            sublat = ssd_buffer_hit_lat(ssd);
            wc_max(ssd, &maxlat, &best, sublat, NULL);
            ssd->sp.read_hit_cnt++;
            continue;
        }

        /* dump the FEMU_DUMP_LPN page on every read (config read once at init) */
        if (exp_dump_lpn_set && lpn == exp_dump_lpn)
            femu_dbg_dump_lpn(ssd, lpn);

        /*
         * dftl: the translation of the page. With translation pages on
         * flash the media read of the page waits for it; under FDP the
         * placeholder cost runs in parallel, as it always has.
         */
        map = ssd_map_lat(ssd, lpn, base, false);
        /* a translation alone can end the page: unmapped, or a cache hit */
        wc_max(ssd, &maxlat, &best, map, &ssd->wc_map);
        /* the media read follows the DRAM lookup (l2p_dram_ns, default 0) */
        dstart = base + (ssd->tp_on ? map : ssd->sp.l2p_dram_ns);
        wait = ssd->tp_on ? map : ssd->sp.l2p_dram_ns;

        ppa = ssd->mapping->translate(ssd, lpn);
        if (!mapped_ppa(&ppa) || !valid_ppa(ssd, &ppa)) {
            continue;
        }

        /*
         * Optional DRAM read cache: a hit returns at DRAM latency and skips the
         * NAND read (and its channel/LUN occupancy); a miss inserts the LPN and
         * falls through to the media. No-op when disabled (bit-identical default).
         */
        sublat = rcache_touch(ssd, lpn);
        if (sublat) {
            wc_max(ssd, &maxlat, &best, sublat, NULL);
            continue;
        }
        /*
         * A page on the lost die does not decode, unless the fine pass of
         * its wordline has not run and the buffer still holds it. The
         * failed read leaves nothing in the read cache.
         */
        if (unlikely(lost_die >= 0) &&
            ppa.g.ch * spp->luns_per_ch + ppa.g.lun == lost_die &&
            !(spp->prog_pass2_ns && ssd_pass2_staged(ssd, &ppa))) {
            lost = true;
            rcache_invalidate(ssd, lpn);
        }

        if (ssd_mp_reads(ssd)) {
            sublat = ssd_mp_add(ssd, &ppa, dstart, base, NAND_READ);
            wc_max(ssd, &maxlat, &best, sublat, NULL);
            continue;
        }
        /* the media times the pages of each LUN after the loop */
        if (pend) {
            pend[npend++] = ssd_read_hold(ssd, &ppa, seq_stime);
            ssd_read_check_wear(ssd, &ppa, req->stime);
            continue;
        }

        struct nand_cmd srd;
        srd.type = USER_IO;
        srd.cmd = NAND_READ;
        srd.stime = dstart;
        /* the flag holds this page's outcome, then the command's */
        failed = ssd->rber_failed;
        ssd->rber_failed = false;
        sublat = ssd_advance_status(ssd, &ppa, &srd) + wait;
        /* with TPs on flash the data read follows the translation */
        if (ssd->wc_on && ssd->tp_on) {
            for (int c = 0; c < FEMU_WAIT_NCAT; c++) {
                ssd->wc_last.ns[c] += ssd->wc_map.ns[c];
            }
        }
        wc_max(ssd, &maxlat, &best, sublat, &ssd->wc_last);
        /* a page that did not decode is not in the read cache either */
        if (unlikely(ssd->rber_failed)) {
            rcache_invalidate(ssd, lpn);
        }
        ssd->rber_failed |= failed;
        ssd_read_check_wear(ssd, &ppa, req->stime);
    }
    sublat = ssd_mp_flush(ssd, NAND_READ);
    wc_max(ssd, &maxlat, &best, sublat, NULL);
    if (npend) {
        sublat = ssd_read_seq_charge(ssd, pend, npend, seq_stime);
        wc_max(ssd, &maxlat, &best, sublat, NULL);
    }
    if (ssd->wc_on) {
        ssd->wc_last = best;
    }
    /*
     * The media was read and its pages did not decode.
     * bb_ftl_process_req() counts and logs it by the final status.
     */
    if (unlikely(lost)) {
        req->status = NVME_UNRECOVERED_READ | NVME_DNR;
    } else if (unlikely(ssd->rber_failed)) {
        /* no decode corrected a codeword at this Read Recovery Level */
        req->status = NVME_UNRECOVERED_READ | NVME_DNR;
    }

    return maxlat;
}

/*
 * Host pages count when the device takes them. The namespace that owns
 * @lpn takes the same count.
 */
static void ssd_host_pages(struct ssd *ssd, uint64_t lpn, uint64_t pages)
{
    ssd->host_write_pages += pages;
    ssd->plm_wr_total += pages;
    if (unlikely(ssd->nr_ns_slices)) {
        ssd_ns_ctr_of(ssd, lpn)->host_write_pages += pages;
    }
}

/* give back the @pages from @lpn that a failed command never placed */
static void ssd_host_pages_back(struct ssd *ssd, uint64_t lpn, uint64_t pages)
{
    ssd->host_write_pages -= pages;
    if (unlikely(ssd->nr_ns_slices)) {
        ssd_ns_ctr_of(ssd, lpn)->host_write_pages -= pages;
    }
}

uint64_t ssd_write(struct ssd *ssd, NvmeRequest *req)
{
    struct ssdparams *spp = &ssd->sp;
    uint64_t start_lpn, end_lpn;
    uint64_t lpn;
    uint64_t curlat = 0, maxlat = 0;
    const NvmeRwCmd *rw = (const NvmeRwCmd *)&req->cmd;
    /* events_file fua-lie: the write takes the buffered path */
    bool fua = (le16_to_cpu(rw->control) & NVME_RW_FUA) &&
               likely(req->fs_lie != FEMU_FS_ACT_FUA_LIE);
    int stream = ssd->n->streams && req->cmd.opcode == NVME_CMD_WRITE ?
                 nvme_streams_open(req->ns, &req->cmd) : -1;
    int r;
    bool wl_done;
    bool opened;
    uint64_t passes = ssd->gc_stall_passes;
    uint8_t *snap = NULL;
    uint8_t *snap_state = NULL;
    bool buffer_full = false;
    uint64_t book;
    uint64_t wait;
    bool placed;
    bool drain;
    bool txn;
    bool snap_all;
    uint8_t **txn_undo = NULL;
    uint8_t **txn_state = NULL;
    FemuWaitParts best = { 0 };
    FemuWaitParts buf = { 0 };
    FemuWaitParts stall = { 0 };

    ssd_lpn_range(ssd, req, req->slba, req->nlb, &start_lpn, &end_lpn);
    /*
     * awupf_lbas: a write of at most N blocks over more than one page runs
     * as one transaction. It skips the buffer, where its pages could commit
     * one at a time, and keeps every page's before-image until all are
     * placed. This request is one FTL step and a cut comes only between
     * steps, so a cut finds the write all old or all new. A short write
     * inside one page may buffer, but on the direct path it keeps its
     * before-image too, so a failed placement leaves no new byte.
     */
    snap_all = ssd_write_snap_all(ssd, req, req->nlb);
    txn = ssd_write_txn(ssd, req, req->nlb, start_lpn, end_lpn);

    if (end_lpn >= spp->tt_pgs) {
        ftl_err("write past device geometry: end_lpn=%" PRIu64 " tt_pgs=%"
                PRId64 "\n",
                end_lpn, ssd->sp.tt_pgs);
        req->status = NVME_LBA_RANGE | NVME_DNR;
        return 0;
    }

    /* one clock for the loop: host time between victims adds nothing */
    opened = ssd_gc_pass_begin(ssd);
    while (should_gc_high(ssd)) {
        /* perform GC here until !should_gc(ssd) */
        r = do_gc(ssd, true);
        if (r == -1)
            break;
        ssd->gc_stall_passes++;
    }
    ssd_gc_pass_end(ssd, opened);

    /* refresh at most one read-stressed line per write */
    do_read_reclaim(ssd);
    /* and move at most one line off a failed die (rain_rebuild) */
    ssd_rain_rebuild_step(ssd);
    wl_done = do_wear_level(ssd) == 0;

    /* pages the host wrote, whether or not the buffer absorbs them */
    ssd_host_pages(ssd, start_lpn, end_lpn - start_lpn + 1);
    ssd_count_partial_pages(ssd, req, req->slba, req->nlb);
    ssd->sp.write_cnt += end_lpn - start_lpn + 1;

    /*
     * With a write buffer configured the pages are accepted into it rather than
     * programmed, and what gets programmed is whatever they push past the
     * watermark. Without one the loop below programs each page directly,
     * exactly as it always has.
     *
     * Force Unit Access is the host asking for this write to be on the media
     * before it completes, so an FUA write takes the direct path even when the
     * buffer is on. Any copy the buffer is holding is dropped on the way past,
     * below: leaving it there would program the superseded version after this
     * one.
     */
    /* Program stream writes directly even when a cache is enabled. */
    /* with working plp the buffer is as durable as FUA asks (OCP NVMe-IO-3) */
    if (ssd_buffer_enabled(ssd) && (!fua || femu_plp_ok(ssd->n)) &&
        stream < 0 && !txn &&
        (!ssd->n->power_loss || req->write_data)) {
        int batch = ssd_buffer_batch(ssd);

        for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
            /*
             * Admission control, per page rather than once per request: a
             * request larger than the buffer must not be able to push
             * occupancy past the configured size. Writing back a bounded batch
             * also bounds the latency a single command can absorb.
             */
            if (!ssd_buffer_hit(ssd, lpn) && ssd_buffer_at_watermark(ssd)) {
                int before = ssd->write_buffer_cnt;

                buffer_full = true;
                curlat = ssd_buffer_destage(ssd, batch, req->stime);
                /* a write-back that sets the latency is the one cause */
                buf.ns[FEMU_WAIT_BUFFER] = curlat;
                wc_max(ssd, &maxlat, &best, curlat, &buf);
                /*
                 * The write-back could not free anything, so the buffer is at
                 * its limit and no page found a place. Accepting more here
                 * would grow it past its configured size and report success
                 * for pages that can never be programmed; the direct path
                 * tells the host instead, and so does this one.
                 */
                if (ssd->write_buffer_cnt >= before &&
                    ssd_buffer_at_watermark(ssd)) {
                    req->status = NVME_CAP_EXCEEDED | NVME_DNR;
                    ssd_host_pages_back(ssd, lpn, end_lpn - lpn + 1);
                    break;
                }
            }

            bool held;

            ssd_buffer_insert(ssd, lpn, &held);
            if (held) {
                ssd->sp.write_hit_cnt++;
            }
            buffer_write_data(ssd, req, lpn, true);
        }

        /* accepting into DRAM is not free, even though it is not a program */
        curlat = ssd_buffer_hit_lat(ssd);
        wc_max(ssd, &maxlat, &best, curlat, NULL);

        ssd->buffer_full_destages += buffer_full;
        ssd_note_gc_stall(ssd, passes);
        if (ssd->wc_on) {
            ssd->wc_last = best;
        }
        return maxlat;
    }

    /*
     * Going direct while pages are still buffered: either the host disabled
     * the write cache, or this is an FUA write. Anything the buffer holds for
     * a page this request also writes must not be programmed after it, as
     * that would put the older version on the media. Each such entry goes
     * once its page is placed below; one whose page finds no place stays
     * owed. A disabled cache then writes back the rest.
     */
    drain = ssd->write_buffer_cnt && !ssd_buffer_enabled(ssd);

    /* a partial indirection unit: read and rewrite the rest of it */
    if (unlikely(spp->iu_pages > 1)) {
        curlat = ssd_iu_rmw(ssd, start_lpn, end_lpn, req->stime, stream);
        wc_max(ssd, &maxlat, &best, curlat, NULL);
    }

    if (snap_all) {
        txn_undo = g_new0(uint8_t *, end_lpn - start_lpn + 1);
        txn_state = g_new0(uint8_t *, end_lpn - start_lpn + 1);
        for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
            ssd_page_snapshot(ssd, req->ns, lpn, &txn_undo[lpn - start_lpn],
                              &txn_state[lpn - start_lpn]);
        }
    }
    for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
        struct ppa target = { .ppa = INVALID_PPA };

        /*
         * Collect per page, as write-back does: one command can span more
         * lines than the watermark keeps free, and a collection that starts
         * after the last line is gone has nowhere to move pages to.
         */
        curlat = ssd_gc_until_clear(ssd);
        /* a foreground collection that sets the latency is the one cause */
        stall.ns[FEMU_WAIT_GC] = curlat;
        wc_max(ssd, &maxlat, &best, curlat, &stall);

        /*
         * Garbage collection could not free a line, so there is nowhere to
         * put this page. Tell the host instead of programming through a write
         * pointer that no longer addresses anything.
         */
        if (stream >= 0) {
            target = ssd_stream_page(ssd, stream,
                                     ssd->n->stream_slots[stream].tag);
        }
        if (stream >= 0 ? !mapped_ppa(&target) : ssd_host_out_of_lines(ssd)) {
            req->status = NVME_CAP_EXCEEDED | NVME_DNR;
            ssd_host_pages_back(ssd, lpn, end_lpn - lpn + 1);
            break;
        }

        /*
         * durable_at_done: the page as it is now, before this write, so a
         * failed placement can put it back; no write without room for its
         * generation.
         */
        book = req->stime;
        wait = 0;
        if (ssd_durable_on(ssd) && req->write_data) {
            if (!ssd_durable_room(ssd)) {
                req->status = NVME_CAP_EXCEEDED | NVME_DNR;
                ssd_host_pages_back(ssd, lpn, end_lpn - lpn + 1);
                break;
            }
            ssd_page_snapshot(ssd, req->ns, lpn, &snap, &snap_state);
            /* the program waits for a journal slot; the host sees the wait */
            wait = ssd_durable_start(ssd, req->stime, &book);
        }
        /*
         * Under power_loss a buffered copy keeps its undo record until this
         * page is placed: a cut after a failed placement restores it.
         */
        buffer_write_data(ssd, req, lpn, false);
        /* with dftl, the translation goes with the program */
        curlat = wait + ssd_map_and_program(ssd, lpn, book, stream, &placed);
        wc_max(ssd, &maxlat, &best, curlat, &ssd->wc_last);
        if (!placed) {
            req->status = NVME_CAP_EXCEEDED | NVME_DNR;
            ssd_host_pages_back(ssd, lpn, end_lpn - lpn + 1);
            /* the write did not happen: the page is as it was */
            if (snap) {
                ssd_page_restore(ssd, req->ns, lpn, snap, snap_state);
                g_clear_pointer(&snap, g_free);
                g_clear_pointer(&snap_state, g_free);
            }
            break;
        }
        if (snap) {
            ssd_durable_slot_used(ssd, ssd->last_prog_done);
            ssd_durable_direct(ssd, req->ns, lpn, &snap, &snap_state);
        }
        /*
         * pe_suspend: the program holds the bytes of a buffered write the
         * host saw complete, so the next Flush must seal it.
         */
        if (ssd->write_buffer_cnt && ssd_buffer_discard(ssd, lpn)) {
            ssd->buffer_unsealed = true;
        }

        /*
         * Wear levelling needs the data pointer on a fresh line, and a long
         * write can cross that point at the same offset every time, so look
         * again here, once per command.
         */
        if (spp->wl_spread) {
            ssd->wl_credit = MIN(ssd->wl_credit + 1,
                                 4ull * spp->pgs_per_line);
            if (!wl_done) {
                wl_done = do_wear_level(ssd) == 0;
            }
        }
    }
    if (snap_all) {
        /*
         * A page found no room: the write fails whole, so the pages it
         * changed get their bytes and LBA states back. Buffered copies it
         * dropped on the way stay as the restored bytes hold them.
         */
        for (uint64_t i = 0; i <= end_lpn - start_lpn; i++) {
            if (lpn <= end_lpn && start_lpn + i <= lpn) {
                ssd_page_restore(ssd, req->ns, start_lpn + i, txn_undo[i],
                                 txn_state[i]);
            }
            g_free(txn_undo[i]);
            g_free(txn_state[i]);
        }
        g_free(txn_undo);
        g_free(txn_state);
    }
    curlat = ssd_mp_flush(ssd, NAND_WRITE);
    wc_max(ssd, &maxlat, &best, curlat, NULL);
    /* a disabled write cache must not keep pages back at all */
    if (drain && ssd->write_buffer_cnt) {
        curlat = ssd_buffer_destage(ssd, 0, req->stime);
        buf.ns[FEMU_WAIT_BUFFER] = curlat;
        wc_max(ssd, &maxlat, &best, curlat, &buf);
    }
    /* the write waited for collection to make room */
    ssd_note_gc_stall(ssd, passes);

    /*
     * Let schemes without per-page reclaim collect once the writes have
     * committed -- for a log-block scheme that is a merge. The NAND cost is
     * charged inside reclaim(). One reclaim per request bounds the latency a
     * single command can absorb; page and dftl have no reclaim and skip this.
     */
    if (!ssd->mapping->reclaim_per_page &&
        ssd->mapping->needs_reclaim && ssd->mapping->reclaim &&
        ssd->mapping->needs_reclaim(ssd)) {
        FemuWaitParts gc;

        curlat = ssd_map_reclaim(ssd);
        /* io_causes: as in ssd_program_lpn(), a merge is all gc */
        memset(&gc, 0, sizeof(gc));
        gc.ns[FEMU_WAIT_GC] = curlat;
        wc_max(ssd, &maxlat, &best, curlat, &gc);
    }

    if (ssd->wc_on) {
        ssd->wc_last = best;
    }
    return maxlat;
}

/*
 * Deallocate the logical pages in [start_lpn, end_lpn]: drop whatever the write
 * buffer still owes for them, unmap them, and invalidate the media pages they
 * held. Shared by DSM Deallocate and by Write Zeroes with the Deallocate bit,
 * which owe the device exactly the same thing.
 *
 * Returns the number of pages that had a mapping to invalidate and counts the
 * rest through already_invalid.
 */
static uint64_t ssd_deallocate_lpns(struct ssd *ssd, uint64_t start_lpn,
                                    uint64_t end_lpn,
                                    uint64_t *already_invalid)
{
    uint64_t deallocated = 0;
    uint64_t lpn;

    for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
        struct ppa ppa = get_maptbl_ent(ssd, lpn);

        /*
         * Drop any copy the write buffer is holding first, before the
         * mapped-page test below can skip past it. A page that was accepted
         * into the buffer and not yet written back has no mapping at all, so
         * testing the mapping first would leave the pending program in place
         * and the data the host just discarded would reach the media after it
         * had been deallocated.
         */
        ssd_buffer_discard(ssd, lpn);

        /* nothing mapped to invalidate; the buffer entry is already gone */
        if (!mapped_ppa(&ppa) || !valid_ppa(ssd, &ppa)) {
            (*already_invalid)++;
            continue;
        }

        if (exp_lpn_watched(lpn))
            EXP_LOG("[INVALIDATE:trim] lpn=%lu old " PPA_FMT "\n",
                    lpn, PPA_ARG(&ppa));

        /*
         * Hand the unmap to the mapping scheme when it keeps state of its own,
         * so a log-block scheme drops the page from its logs as well. The hook
         * does the same flat invalidation; without one, do it here.
         */
        if (ssd->mapping->trim) {
            ssd->mapping->trim(ssd, lpn);
        } else {
            mark_page_invalid(ssd, &ppa);
            set_rmap_ent(ssd, INVALID_LPN, &ppa);
            ppa.ppa = UNMAPPED_PPA;
            set_maptbl_ent(ssd, lpn, &ppa);
        }

        /* drop any stale read-cache entry for the deallocated page */
        rcache_invalidate(ssd, lpn);

        deallocated++;
    }
    /*
     * plm: a stalled preparation counts these toward its retry. DSM and
     * Write Zeroes with DEAC come here; a Copy counts as host pages, and
     * Format and Sanitize clear the stall in bbssd_deallocate_all().
     */
    ssd->plm_trim_pages += deallocated;

    return deallocated;
}

/*
 * Write the translation pages a deallocate changed and has no CMT slot for:
 * one read and one program per TP for the whole command, charged to it.
 * Returns that time, or 0 without translation pages on flash.
 */
static uint64_t ssd_publish_cmd(struct ssd *ssd, uint64_t stime)
{
    uint64_t t = stime ? stime : ssd_now(ssd);

    if (!ssd->tp_on || !ssd->tp_fifo_cnt) {
        return 0;
    }
    return tp_publish(ssd, t, true) - t;
}

/*
 * Write Zeroes with the Deallocate bit: the blocks become deallocated, so the
 * FTL owes the same unmap DSM Deallocate does. The I/O layer has already zeroed
 * the backing store and cleared the allocation bits; without this the mapping
 * and the write buffer would still be holding the old pages.
 */
uint64_t ssd_write_zeroes(struct ssd *ssd, NvmeRequest *req)
{
    struct ssdparams *spp = &ssd->sp;
    const NvmeRwCmd *rw = (const NvmeRwCmd *)&req->cmd;
    uint64_t start_lpn, end_lpn;
    uint64_t already_invalid = 0;

    ssd_lpn_range(ssd, req, le64_to_cpu(rw->slba), le16_to_cpu(rw->nlb) + 1,
                  &start_lpn, &end_lpn);

    if (!(le16_to_cpu(rw->control) & NVME_WZ_DEAC)) {
        uint64_t lpn, curlat, maxlat = 0;
        uint64_t passes = ssd->gc_stall_passes;
        bool wl_done;
        bool opened;
        bool placed;

        /* durable_at_done staged the zeros: they are a write's payload */
        if (req->write_data) {
            return ssd_write(ssd, req);
        }

        /*
         * Without the bit the blocks hold written zeros rather than becoming
         * deallocated: the host reads zeros back, so the device has to put
         * them somewhere. Program the range as a write would. The I/O layer
         * has already zeroed the backing store; what is owed here is the media
         * cost and the page counts, which the command used to escape entirely.
         *
         * It goes straight to the media rather than through the write buffer,
         * since the host handed over no data to hold.
         */
        if (end_lpn >= spp->tt_pgs) {
            return 0;
        }

        opened = ssd_gc_pass_begin(ssd);
        while (should_gc_high(ssd)) {
            if (do_gc(ssd, true) == -1) {
                break;
            }
            ssd->gc_stall_passes++;
        }
        ssd_gc_pass_end(ssd, opened);
        wl_done = do_wear_level(ssd) == 0;

        ssd_host_pages(ssd, start_lpn, end_lpn - start_lpn + 1);
        /* the pair an ordinary write bumps; these pages are programmed too */
        ssd->sp.write_cnt += end_lpn - start_lpn + 1;
        ssd_count_partial_pages(ssd, req, le64_to_cpu(rw->slba),
                                le16_to_cpu(rw->nlb) + 1);

        for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
            /* per page, for the reason ssd_write() gives */
            curlat = ssd_gc_until_clear(ssd);
            maxlat = (curlat > maxlat) ? curlat : maxlat;
            if (ssd_host_out_of_lines(ssd)) {
                req->status = NVME_CAP_EXCEEDED | NVME_DNR;
                ssd_host_pages_back(ssd, lpn, end_lpn - lpn + 1);
                break;
            }
            /* with dftl, the translation goes with the program */
            curlat = ssd_map_and_program(ssd, lpn, req->stime, -1, &placed);
            maxlat = (curlat > maxlat) ? curlat : maxlat;
            if (!placed) {
                req->status = NVME_CAP_EXCEEDED | NVME_DNR;
                ssd_host_pages_back(ssd, lpn, end_lpn - lpn + 1);
                break;
            }
            /*
             * This goes straight to the media, so a buffered copy of the page
             * goes once the page is placed, as on the direct write path:
             * left there, it programs the superseded version afterwards.
             */
            if (ssd->write_buffer_cnt && ssd_buffer_discard(ssd, lpn)) {
                ssd->buffer_unsealed = true;
            }
            /* the pages are programmed, so wear levelling sees them too */
            if (spp->wl_spread) {
                ssd->wl_credit = MIN(ssd->wl_credit + 1,
                                     4ull * spp->pgs_per_line);
                if (!wl_done) {
                    wl_done = do_wear_level(ssd) == 0;
                }
            }
        }
        curlat = ssd_mp_flush(ssd, NAND_WRITE);
        maxlat = (curlat > maxlat) ? curlat : maxlat;
        ssd_note_gc_stall(ssd, passes);
        ssd_rain_rebuild_step(ssd);

        return maxlat;
    }

    /* only the pages the range covers in full lose their mapping */
    if (!ssd_lpn_range_full(ssd, req, le64_to_cpu(rw->slba),
                            le16_to_cpu(rw->nlb) + 1, &start_lpn, &end_lpn)) {
        return ssd_publish_cmd(ssd, req->stime);
    }
    if (end_lpn >= spp->tt_pgs) {
        return 0;
    }

    ssd_deallocate_lpns(ssd, start_lpn, end_lpn, &already_invalid);

    return ssd_publish_cmd(ssd, req->stime);
}

/*
 * Drop the mappings of the NAND pages [slba, slba + nlb) of @ns covers in
 * full, as a TCG erase needs (nvme-opal.c). A page it covers in part keeps
 * its mapping for the other LBAs. The caller has the dataplane and the FTL
 * thread stopped.
 */
void bbssd_deallocate_lbas(NvmeNamespace *ns, uint64_t slba, uint64_t nlb)
{
    struct ssd *ssd = ns->ssd;
    NvmeRequest req = { .ns = ns };
    uint64_t start_lpn;
    uint64_t end_lpn;
    uint64_t already_invalid = 0;

    if (!ssd || !ssd->sp.tt_pgs || !nlb ||
        !ssd_lpn_range_full(ssd, &req, slba, nlb, &start_lpn, &end_lpn) ||
        start_lpn >= ssd->sp.tt_pgs) {
        return;
    }
    ssd_deallocate_lpns(ssd, start_lpn,
                        MIN(end_lpn, (uint64_t)ssd->sp.tt_pgs - 1),
                        &already_invalid);
}

/*
 * Drop every mapping the namespace's FTL holds, as Format erases it. The host's
 * data is gone, so the pages it occupied are invalid: left mapped, garbage
 * collection would keep relocating data nobody can read any more. The caller
 * has the dataplane and the FTL thread paused.
 */
void bbssd_deallocate_all(NvmeNamespace *ns)
{
    struct ssd *ssd = ns->ssd;
    uint64_t already_invalid = 0;

    if (!ssd || !ssd->sp.tt_pgs) {
        return;
    }
    /* plm: every line may be free now, so the preparation tries again */
    qatomic_set(&ssd->plm_stalled, false);
    /* durable_at_done: the namespace's data is gone, and so is its history */
    if (ssd_durable_on(ssd)) {
        ssd_durable_drop_ns(ssd, ns);
    }
    if (ssd->fdp_enabled) {
        ssd_deallocate_fdp_ns(ssd, ns);
    } else if (ssd->n->shared_ftl) {
        /*
         * Only the slice of @ns goes. The other namespaces keep their
         * pages, their buffered entries and the write-back fence their
         * Flush waits for. Page mapping only: no translation page.
         */
        uint64_t pg = (uint64_t)ssd->sp.secsz * ssd->sp.secs_per_pg;
        uint64_t base = ssd_ns_byte_base(ssd, ns);
        uint64_t last = MIN(DIV_ROUND_UP(base + ns->size, pg),
                            (uint64_t)ssd->sp.tt_pgs);

        if (last > base / pg) {
            ssd_deallocate_lpns(ssd, base / pg, last - 1, &already_invalid);
        }
    } else {
        ssd_deallocate_lpns(ssd, 0, ssd->sp.tt_pgs - 1, &already_invalid);
        /* the translation pages go with the data, unwritten */
        tp_discard_all(ssd);
        /* the data a pending write-back held is gone: Flush owes it nothing */
        ssd->buffer_bg_fence = 0;
        ssd->buffer_unsealed = false;
        ssd->buffer_flush_fence = 0;
    }
    /* plm: log 0Ah shows the new room at once, not at the next step */
    if (ssd->plm) {
        femu_plm_publish(ssd->n);
    }
}

uint64_t ssd_trim(struct ssd *ssd, NvmeRequest *req)
{
    struct ssdparams *spp = &ssd->sp;
    NvmeDsmRange *ranges = req->dsm_ranges;
    int nr_ranges = req->dsm_nr_ranges;

    if (!ranges || nr_ranges <= 0) {
        printf("TRIM: Invalid ranges or count\n");
        return 0;
    }

    for (int range_idx = 0; range_idx < nr_ranges; range_idx++) {
        uint64_t start_lpn, end_lpn;
        uint64_t already_invalid = 0;

        /* only the pages the range covers in full lose their mapping */
        if (!ssd_lpn_range_full(ssd, req,
                                le64_to_cpu(ranges[range_idx].slba),
                                le32_to_cpu(ranges[range_idx].nlb),
                                &start_lpn, &end_lpn)) {
            continue;
        }

        /* Boundary check */
        if (end_lpn >= spp->tt_pgs) {
            ftl_err("TRIM: Range %d exceeds FTL capacity - end_lpn=%" PRIu64
                    ", tt_pgs=%" PRId64 "\n",
                   range_idx, end_lpn, spp->tt_pgs);
            continue;  /* Skip this range, continue with others */
        }

        /* Process each LPN in this range */
        ssd_deallocate_lpns(ssd, start_lpn, end_lpn, &already_invalid);
    }

    /* Free the ranges array */
    g_free(ranges);
    req->dsm_ranges = NULL;
    req->dsm_nr_ranges = 0;
    req->dsm_attributes = 0;

    /* right after a TRIM, check whether the marker still remains in the backend */
    if (exp_log_enabled)
        femu_dbg_scan_secret(ssd, "after_trim");

    /*
     * Optional modeled TRIM cost: trim_lat_ns per processed DSM range, for the
     * metadata map updates a real SSD incurs on deallocate. Default 0 keeps TRIM
     * instant, bit-identical to the prior behavior.
     */
    if (spp->trim_lat_ns > 0) {
        return MAX((uint64_t)spp->trim_lat_ns * nr_ranges,
                   ssd_publish_cmd(ssd, req->stime));
    }
    return ssd_publish_cmd(ssd, req->stime);
}
