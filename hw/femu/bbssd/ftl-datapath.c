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

/* order buffer entries by logical page number */
int comp_buffer(const void *a, const void *b)
{
    return ((buffer_entry *)a)->lpn - ((buffer_entry *)b)->lpn;
}

static bool buffer_enabled(struct ssd *ssd)
{
    return ssd->sp.buffer_size > 0 && ssd->wb_tree != NULL;
}

static bool buffer_full(struct ssd *ssd)
{
    return ssd->sp.buffer_size * ssd->sp.buffer_thres_pcent <=
           ssd->write_buffer_cnt;
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
    free(victim);
    ssd->write_buffer_cnt--;

    return true;
}

/* returns true when the page was already buffered, so this write hits */
static bool buffer_insert_entry(struct ssd *ssd, struct buffer_entry *entry)
{
    struct buffer_entry *old = g_tree_lookup(ssd->wb_tree, entry);

    if (old) {
        g_tree_remove(ssd->wb_tree, old);
        QTAILQ_REMOVE(&ssd->write_buffer, old, b_entry);
        free(old);
        g_tree_insert(ssd->wb_tree, entry, entry);
        QTAILQ_INSERT_TAIL(&ssd->write_buffer, entry, b_entry);
        return true;
    }

    g_tree_insert(ssd->wb_tree, entry, entry);
    QTAILQ_INSERT_TAIL(&ssd->write_buffer, entry, b_entry);
    ssd->write_buffer_cnt++;

    return false;
}

/* a read served from the buffer does not reach the media */
static bool buffer_hit(struct ssd *ssd, uint64_t lpn)
{
    struct buffer_entry target;

    target.lpn = lpn;

    return g_tree_lookup(ssd->wb_tree, &target) != NULL;
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
    ssd->host_write_pages++; /* write amplification: a host-programmed page */
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
    bool all_buffered = true;

    if (end_lpn >= spp->tt_pgs) {
        ftl_err("read past device geometry: end_lpn=%"PRIu64" tt_pgs=%d\n",
                end_lpn, ssd->sp.tt_pgs);
        req->status = NVME_LBA_RANGE | NVME_DNR;
        return 0;
    }

    /* normal IO read path */
    ssd->sp.read_cnt++;
    for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
        /* a page still in the write buffer is served from there */
        if (buffer_enabled(ssd) && buffer_hit(ssd, lpn)) {
            continue;
        }
        all_buffered = false;

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

    if (all_buffered) {
        ssd->sp.read_hit_cnt++;
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

    /*
     * With a write buffer configured the pages are held rather than programmed,
     * and what gets programmed is whatever they displace. Without one the loop
     * below programs each page directly, exactly as it always has.
     */
    if (buffer_enabled(ssd)) {
        uint64_t victim_lpn;
        bool all_hit = true;

        while (buffer_full(ssd) && buffer_select_victim(ssd, &victim_lpn)) {
            curlat = ssd_program_lpn(ssd, victim_lpn, req->stime);
            maxlat = (curlat > maxlat) ? curlat : maxlat;
        }

        ssd->sp.write_cnt++;
        for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
            struct buffer_entry *entry = malloc(sizeof(*entry));

            entry->lpn = lpn;
            all_hit = buffer_insert_entry(ssd, entry) && all_hit;
        }
        if (all_hit) {
            ssd->sp.write_hit_cnt++;
        }

        return maxlat;
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
        uint64_t lpn;
        struct ppa ppa;
        int trimmed_pages = 0;
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
        for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
            ppa = get_maptbl_ent(ssd, lpn);
            
            // Skip already unmapped/invalid pages
            if (!mapped_ppa(&ppa) || !valid_ppa(ssd, &ppa)) {
                already_invalid++;
                continue;
            }

            // Invalidate the existing mapped page
            if (exp_lpn_watched(lpn))
                EXP_LOG("[INVALIDATE:trim] lpn=%lu old " PPA_FMT "\n",
                        lpn, PPA_ARG(&ppa));

            /*
             * Hand the unmap to the mapping scheme when it keeps state of its
             * own, so a log-block scheme drops the page from its logs as well.
             * The hook does the same flat invalidation; without one, do it here.
             */
            if (ssd->mapping->trim) {
                ssd->mapping->trim(ssd, lpn);
            } else {
                mark_page_invalid(ssd, &ppa);

                // Clear reverse mapping
                set_rmap_ent(ssd, INVALID_LPN, &ppa);

                // Set mapping table entry as unmapped
                ppa.ppa = UNMAPPED_PPA;
                set_maptbl_ent(ssd, lpn, &ppa);
            }

            /* drop any stale read-cache entry for the trimmed page */
            rcache_invalidate(ssd, lpn);

            trimmed_pages++;
        }
        
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
