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
 * It holds page numbers, not page contents. The host's bytes have already been
 * placed in the backing store by the time the FTL sees the request, so what is
 * buffered here is the obligation to program a page, not the data itself. That
 * is enough to model timing, occupancy, coalescing and the write-back cost; it
 * is not enough to model losing data on power failure, and nothing here should
 * be read as claiming otherwise.
 *
 * Everything below runs on the FTL thread, which is the only owner of the
 * buffer, the mapping, the line management and the NAND status. None of it is
 * serialised against the poller thread and none of it may be called from there.
 */
static bool buffer_enabled(struct ssd *ssd)
{
    if (ssd->sp.buffer_size <= 0 || !ssd->wb_tree) {
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
    if (ssd->n && ssd->n->id_ctrl.vwc && !ssd->n->features.volatile_wc) {
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

static bool buffer_at_watermark(struct ssd *ssd)
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
static int buffer_destage_batch(struct ssd *ssd)
{
    int batch = ssd->sp.buffer_size - buffer_watermark(ssd);

    return batch > 0 ? batch : 1;
}

/* take the least recently written page out of the buffer */
static bool buffer_select_victim(struct ssd *ssd, uint64_t *lpn)
{
    struct buffer_entry *victim = QTAILQ_FIRST(&ssd->write_buffer);

    if (!victim) {
        return false;
    }

    *lpn = victim->lpn;
    QTAILQ_REMOVE(&ssd->write_buffer, victim, b_entry);
    g_tree_remove(ssd->wb_tree, victim);
    g_free(victim);
    ssd->write_buffer_cnt--;

    return true;
}

/*
 * Accept a page into the buffer. Returns true when the page was already held,
 * which is the case the buffer exists for: the earlier write is superseded and
 * no extra program is owed. A page that is already held keeps its identity and
 * is only moved to the tail, so occupancy cannot grow on a repeat write.
 */
static bool buffer_insert(struct ssd *ssd, uint64_t lpn)
{
    struct buffer_entry target = { .lpn = lpn };
    struct buffer_entry *held = g_tree_lookup(ssd->wb_tree, &target);
    struct buffer_entry *entry;

    if (held) {
        QTAILQ_REMOVE(&ssd->write_buffer, held, b_entry);
        QTAILQ_INSERT_TAIL(&ssd->write_buffer, held, b_entry);
        return true;
    }

    entry = g_new0(struct buffer_entry, 1);
    entry->lpn = lpn;
    g_tree_insert(ssd->wb_tree, entry, entry);
    QTAILQ_INSERT_TAIL(&ssd->write_buffer, entry, b_entry);
    ssd->write_buffer_cnt++;

    return false;
}

/*
 * Drop a page from the buffer without programming it. A page the host has
 * deallocated must be removed: otherwise the pending program runs later and
 * data the host discarded reappears.
 */
static void buffer_discard(struct ssd *ssd, uint64_t lpn)
{
    struct buffer_entry target = { .lpn = lpn };
    struct buffer_entry *held;

    if (!ssd->wb_tree) {
        return;
    }

    held = g_tree_lookup(ssd->wb_tree, &target);
    if (!held) {
        return;
    }

    QTAILQ_REMOVE(&ssd->write_buffer, held, b_entry);
    g_tree_remove(ssd->wb_tree, held);
    g_free(held);
    ssd->write_buffer_cnt--;
}

/* a read served from the buffer does not reach the media */
static bool buffer_hit(struct ssd *ssd, uint64_t lpn)
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
static uint64_t buffer_hit_lat(struct ssd *ssd)
{
    uint64_t lat = ssd->sp.pg_rd_lat ? ssd->sp.pg_rd_lat / 16 : 1000;

    /* a configured page read time under 16ns would otherwise round to free */
    return lat > 0 ? lat : 1;
}

/*
 * Teardown deliberately does not touch the buffer.
 *
 * femu_exit() runs the extension exit hook before nvme_clear_ctrl() stops the
 * dataplane, and the FTL thread has no stop condition and is never joined, so
 * it can still be inside a lookup, an insert or a write-back here. Freeing the
 * entries, or the tree, from the exit path is a use-after-free -- not merely a
 * loss of the pages the buffer still owes. Those pages are meaningless at this
 * point anyway: the backing store is volatile and goes with the device.
 *
 * Releasing this safely needs a shutdown protocol that quiesces and joins the
 * FTL thread before anything it owns is freed. That is a gap in the generic
 * teardown -- the same thread also outlives the rings, the namespaces and the
 * backend that femu_exit() frees straight after this -- and belongs with that
 * fix rather than here.
 */
void ssd_free_write_buffer(struct ssd *ssd)
{
}

/*
 * Program one logical page: choose placement through the mapping scheme,
 * commit it, and charge the media. Shared by the ordinary write path and by
 * the eviction of a buffered page, so both cost the same.
 */
static uint64_t ssd_program_lpn(struct ssd *ssd, uint64_t lpn, uint64_t stime)
{
    struct map_write_plan plan;
    struct nand_cmd swr;
    struct ppa ppa;

    /* log the overwrite before commit_write invalidates the old mapping */
    if (exp_lpn_watched(lpn)) {
        struct ppa old = ssd->mapping->translate(ssd, lpn);
        if (mapped_ppa(&old))
            EXP_LOG("[INVALIDATE:overwrite] lpn=%lu old " PPA_FMT "\n",
                    lpn, PPA_ARG(&old));
    }

    /* mapping scheme picks placement (page/dftl: data class, no reclaim) */
    plan = ssd->mapping->prepare_write(ssd, lpn, USER_IO);

    /* the page content changes: drop any stale read-cache entry for it */
    rcache_invalidate(ssd, lpn);

    /* allocate from the class the scheme asked for and commit the mapping */
    ppa = get_new_page_class(ssd, plan.target_class);
    ssd->mapping->commit_write(ssd, lpn, &ppa);

    mark_page_valid(ssd, &ppa);
    ssd->nand_write_pages++; /* write amplification: a user page programmed */
    /* only log + track pages that carry the marker string */
    if (femu_dbg_lpn_has_secret(ssd, lpn)) {
        exp_watch_lpn_add(lpn);
        exp_watch_blk[ppa.g.blk] = 1;
        EXP_LOG("[WRITE] lpn=%lu -> " PPA_FMT " (secret)\n",
                lpn, PPA_ARG(&ppa));
    }

    /* need to advance the write pointer here */
    ssd_advance_write_pointer_class(ssd, plan.target_class);

    swr.type = USER_IO;
    swr.cmd = NAND_WRITE;
    swr.stime = stime;

    return ssd_advance_status(ssd, &ppa, &swr);
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
uint64_t ssd_buffer_destage(struct ssd *ssd, int budget, uint64_t stime)
{
    uint64_t maxlat = 0, curlat;
    uint64_t lpn;
    int done = 0;

    while (budget <= 0 || done < budget) {
        if (!buffer_select_victim(ssd, &lpn)) {
            break;
        }

        /*
         * Free space is consumed as pages are programmed, not as they are
         * accepted, so a long write-back has to keep checking rather than rely
         * on the single check the host write already made.
         *
         * As on the direct write path, a GC that cannot make progress does not
         * stop the program that follows: there is nowhere to put the page back.
         * Turning that into real backpressure means being able to refuse a
         * write, which no path here can do yet.
         */
        while (should_gc_high(ssd)) {
            if (do_gc(ssd, true) == -1) {
                break;
            }
        }

        /* dftl: demand-cache translation cost (no-op when disabled) */
        if (ssd->cmt.capacity) {
            curlat = cmt_touch(ssd, lpn, stime, true);
            maxlat = (curlat > maxlat) ? curlat : maxlat;
        }

        curlat = ssd_program_lpn(ssd, lpn, stime);
        maxlat = (curlat > maxlat) ? curlat : maxlat;
        done++;
    }

    /*
     * One reclaim per batch, as the direct path does one per request: for a
     * log-block scheme that is a merge, and its NAND cost is charged inside
     * reclaim(). page and dftl have no reclaim and skip this.
     */
    if (done && ssd->mapping->needs_reclaim && ssd->mapping->reclaim &&
        ssd->mapping->needs_reclaim(ssd)) {
        curlat = ssd->mapping->reclaim(ssd, 1);
        maxlat = (curlat > maxlat) ? curlat : maxlat;
    }

    return maxlat;
}

uint64_t ssd_read(struct ssd *ssd, NvmeRequest *req)
{
    struct ssdparams *spp = &ssd->sp;
    uint64_t lba = req->slba + ssd_ns_lba_base(ssd, req);
    int nsecs = req->nlb;
    struct ppa ppa;
    uint64_t start_lpn = lba / spp->secs_per_pg;
    uint64_t end_lpn = (lba + nsecs - 1) / spp->secs_per_pg;
    uint64_t lpn;
    uint64_t sublat, maxlat = 0;

    if (end_lpn >= spp->tt_pgs) {
        ftl_err("read past device geometry: end_lpn=%"PRIu64" tt_pgs=%d\n",
                end_lpn, ssd->sp.tt_pgs);
        req->status = NVME_LBA_RANGE | NVME_DNR;
        return 0;
    }

    /* normal IO read path */
    ssd->sp.read_cnt += end_lpn - start_lpn + 1;
    for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
        /*
         * A page the write buffer is still holding is served from there: it
         * costs a DRAM access and does not reach the media. The buffer is
         * checked even when it has stopped accepting writes, since it can still
         * be holding pages that have not been written back yet.
         */
        if (ssd->write_buffer_cnt && buffer_hit(ssd, lpn)) {
            sublat = buffer_hit_lat(ssd);
            maxlat = (sublat > maxlat) ? sublat : maxlat;
            ssd->sp.read_hit_cnt++;
            continue;
        }

        /* dump the FEMU_DUMP_LPN page on every read (config read once at init) */
        if (exp_dump_lpn_set && lpn == exp_dump_lpn)
            femu_dbg_dump_lpn(ssd, lpn);

        /* dftl: charge the demand-cache translation cost (no-op when disabled) */
        if (ssd->cmt.capacity) {
            uint64_t clat = cmt_touch(ssd, lpn, req->stime, false);
            maxlat = (clat > maxlat) ? clat : maxlat;
        }

        ppa = ssd->mapping->translate(ssd, lpn);
        if (!mapped_ppa(&ppa) || !valid_ppa(ssd, &ppa)) {
            //printf("%s,lpn(%" PRId64 ") not mapped to valid ppa\n", ssd->ssdname, lpn);
            //printf("Invalid ppa,ch:%d,lun:%d,blk:%d,pl:%d,pg:%d,sec:%d\n",
            //ppa.g.ch, ppa.g.lun, ppa.g.blk, ppa.g.pl, ppa.g.pg, ppa.g.sec);
            continue;
        }

        /*
         * Optional DRAM read cache: a hit returns at DRAM latency and skips the
         * NAND read (and its channel/LUN occupancy); a miss inserts the LPN and
         * falls through to the media. No-op when disabled (bit-identical default).
         */
        sublat = rcache_touch(ssd, lpn);
        if (sublat) {
            maxlat = (sublat > maxlat) ? sublat : maxlat;
            continue;
        }

        struct nand_cmd srd;
        srd.type = USER_IO;
        srd.cmd = NAND_READ;
        srd.stime = req->stime;
        sublat = ssd_advance_status(ssd, &ppa, &srd);
        maxlat = (sublat > maxlat) ? sublat : maxlat;
    }

    return maxlat;
}

uint64_t ssd_write(struct ssd *ssd, NvmeRequest *req)
{
    uint64_t lba = req->slba + ssd_ns_lba_base(ssd, req);
    struct ssdparams *spp = &ssd->sp;
    int len = req->nlb;
    uint64_t start_lpn = lba / spp->secs_per_pg;
    uint64_t end_lpn = (lba + len - 1) / spp->secs_per_pg;
    uint64_t lpn;
    uint64_t curlat = 0, maxlat = 0;
    const NvmeRwCmd *rw = (const NvmeRwCmd *)&req->cmd;
    bool fua = le16_to_cpu(rw->control) & NVME_RW_FUA;
    int r;

    if (end_lpn >= spp->tt_pgs) {
        ftl_err("write past device geometry: end_lpn=%"PRIu64" tt_pgs=%d\n",
                end_lpn, ssd->sp.tt_pgs);
        req->status = NVME_LBA_RANGE | NVME_DNR;
        return 0;
    }

    while (should_gc_high(ssd)) {
        /* perform GC here until !should_gc(ssd) */
        r = do_gc(ssd, true);
        if (r == -1)
            break;
    }

    /* pages the host wrote, whether or not the buffer absorbs them */
    ssd->host_write_pages += end_lpn - start_lpn + 1;
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
    if (buffer_enabled(ssd) && !fua) {
        int batch = buffer_destage_batch(ssd);

        for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
            /*
             * Admission control, per page rather than once per request: a
             * request larger than the buffer must not be able to push
             * occupancy past the configured size. Writing back a bounded batch
             * also bounds the latency a single command can absorb.
             */
            if (!buffer_hit(ssd, lpn) && buffer_at_watermark(ssd)) {
                curlat = ssd_buffer_destage(ssd, batch, req->stime);
                maxlat = (curlat > maxlat) ? curlat : maxlat;
            }

            if (buffer_insert(ssd, lpn)) {
                ssd->sp.write_hit_cnt++;
            }
        }

        /* accepting into DRAM is not free, even though it is not a program */
        curlat = buffer_hit_lat(ssd);
        maxlat = (curlat > maxlat) ? curlat : maxlat;

        return maxlat;
    }

    /*
     * Going direct while pages are still buffered: either the host disabled
     * the write cache, or this is an FUA write. Anything the buffer holds for
     * a page this request also writes has to go first -- programming it
     * afterwards would put the older version on the media. Dropping the entry
     * is enough, since the program below writes the newer version anyway.
     */
    if (ssd->write_buffer_cnt) {
        for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
            buffer_discard(ssd, lpn);
        }
        /*
         * A disabled write cache must not keep pages back at all, so drain the
         * rest too. An FUA write only owes its own pages and leaves them.
         */
        if (!buffer_enabled(ssd)) {
            curlat = ssd_buffer_destage(ssd, 0, req->stime);
            maxlat = (curlat > maxlat) ? curlat : maxlat;
        }
    }

    for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
        /* dftl: charge the demand-cache translation cost (no-op when disabled) */
        if (ssd->cmt.capacity) {
            uint64_t clat = cmt_touch(ssd, lpn, req->stime, true);
            maxlat = (clat > maxlat) ? clat : maxlat;
        }

        curlat = ssd_program_lpn(ssd, lpn, req->stime);
        maxlat = (curlat > maxlat) ? curlat : maxlat;
    }

    /*
     * Let the mapping scheme reclaim its own structures once the writes have
     * committed -- for a log-block scheme that is a merge. The NAND cost is
     * charged inside reclaim(). One reclaim per request bounds the latency a
     * single command can absorb; page and dftl have no reclaim and skip this.
     */
    if (ssd->mapping->needs_reclaim && ssd->mapping->reclaim &&
        ssd->mapping->needs_reclaim(ssd)) {
        curlat = ssd->mapping->reclaim(ssd, 1);
        maxlat = (curlat > maxlat) ? curlat : maxlat;
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
static int ssd_deallocate_lpns(struct ssd *ssd, uint64_t start_lpn,
                               uint64_t end_lpn, int *already_invalid)
{
    int deallocated = 0;
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
        buffer_discard(ssd, lpn);

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

    return deallocated;
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
    uint64_t lba = le64_to_cpu(rw->slba) + ssd_ns_lba_base(ssd, req);
    uint32_t nlb = le16_to_cpu(rw->nlb) + 1;
    uint64_t start_lpn = lba / spp->secs_per_pg;
    uint64_t end_lpn = (lba + nlb - 1) / spp->secs_per_pg;
    int already_invalid = 0;

    if (!(le16_to_cpu(rw->control) & NVME_WZ_DEAC)) {
        /*
         * Without the bit the blocks hold written zeros rather than becoming
         * deallocated. The I/O layer writes them to the backing store, but the
         * FTL does not model them as programmed pages; that gap predates the
         * write buffer and is left alone here.
         */
        return 0;
    }

    if (end_lpn >= spp->tt_pgs) {
        return 0;
    }

    ssd_deallocate_lpns(ssd, start_lpn, end_lpn, &already_invalid);

    return 0;
}

uint64_t ssd_trim(struct ssd *ssd, NvmeRequest *req)
{
    struct ssdparams *spp = &ssd->sp;
    NvmeDsmRange *ranges = req->dsm_ranges;
    int nr_ranges = req->dsm_nr_ranges;
    // uint32_t attributes = req->dsm_attributes;
    
    int total_trimmed_pages = 0;
    int total_already_invalid = 0;
    int total_out_of_bounds = 0;
    
    if (!ranges || nr_ranges <= 0) {
        printf("TRIM: Invalid ranges or count\n");
        return 0;
    }
    
    // printf("TRIM: Processing %d ranges (attributes=0x%x)\n", nr_ranges, attributes);
    
    for (int range_idx = 0; range_idx < nr_ranges; range_idx++) {
        /* shift into this namespace's slice of the FTL, as read and write do */
        uint64_t slba = le64_to_cpu(ranges[range_idx].slba) +
                        ssd_ns_lba_base(ssd, req);
        uint32_t nlb = le32_to_cpu(ranges[range_idx].nlb);
        // uint32_t cattr = le32_to_cpu(ranges[range_idx].cattr);
        
        uint64_t start_lpn = slba / spp->secs_per_pg;
        uint64_t end_lpn = (slba + nlb - 1) / spp->secs_per_pg;
        int trimmed_pages;
        int already_invalid = 0;

        // ftl_debug("TRIM Range %d: LBA %lu + %u sectors, LPN range %lu-%lu (%lu pages), cattr=0x%x\n", 
        //        range_idx, slba, nlb, start_lpn, end_lpn, end_lpn - start_lpn + 1, cattr);

        // Boundary check
        if (end_lpn >= spp->tt_pgs) {
            ftl_err("TRIM: Range %d exceeds FTL capacity - end_lpn=%lu, tt_pgs=%d\n", 
                   range_idx, end_lpn, spp->tt_pgs);
            total_out_of_bounds++;
            continue;  // Skip this range, continue with others
        }

        // Process each LPN in this range
        trimmed_pages = ssd_deallocate_lpns(ssd, start_lpn, end_lpn,
                                            &already_invalid);
        
        total_trimmed_pages += trimmed_pages;
        total_already_invalid += already_invalid;
        
        // ftl_debug("TRIM Range %d: %d pages trimmed, %d already invalid\n", 
        //        range_idx, trimmed_pages, already_invalid);
    }

    // ftl_debug("TRIM: Completed - %d pages trimmed, %d already invalid, %d out of bounds across %d ranges\n", 
    //        total_trimmed_pages, total_already_invalid, total_out_of_bounds, nr_ranges);

    // Free the ranges array
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
        return (uint64_t)spp->trim_lat_ns * nr_ranges;
    }
    return 0;
}
