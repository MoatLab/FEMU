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
    for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
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
    struct ppa ppa;
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

    for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
        /* dftl: charge the demand-cache translation cost (no-op when disabled) */
        if (ssd->cmt.capacity) {
            uint64_t clat = cmt_touch(ssd, lpn, req->stime, true);
            maxlat = (clat > maxlat) ? clat : maxlat;
        }

        /* log the overwrite before commit_write invalidates the old mapping */
        if (exp_lpn_watched(lpn)) {
            struct ppa old = ssd->mapping->translate(ssd, lpn);
            if (mapped_ppa(&old))
                EXP_LOG("[INVALIDATE:overwrite] lpn=%lu old " PPA_FMT "\n",
                        lpn, PPA_ARG(&old));
        }

        /* mapping scheme picks placement (page/dftl: data class, no reclaim) */
        struct map_write_plan plan = ssd->mapping->prepare_write(ssd, lpn, USER_IO);
        (void)plan;

        /* the page content changes: drop any stale read-cache entry for it */
        rcache_invalidate(ssd, lpn);

        /* allocate the new page and commit the mapping (invalidates the old) */
        ppa = get_new_page(ssd);
        ssd->mapping->commit_write(ssd, lpn, &ppa);

        mark_page_valid(ssd, &ppa);
        /* only log + track pages that carry the marker string */
        if (femu_dbg_lpn_has_secret(ssd, lpn)) {
            exp_watch_lpn_add(lpn);
            exp_watch_blk[ppa.g.blk] = 1;
            EXP_LOG("[WRITE] lpn=%lu -> " PPA_FMT " (secret)\n",
                    lpn, PPA_ARG(&ppa));
        }

        /* need to advance the write pointer here */
        ssd_advance_write_pointer(ssd);

        struct nand_cmd swr;
        swr.type = USER_IO;
        swr.cmd = NAND_WRITE;
        swr.stime = req->stime;
        /* get latency statistics */
        curlat = ssd_advance_status(ssd, &ppa, &swr);
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
            mark_page_invalid(ssd, &ppa);

            // Clear reverse mapping
            set_rmap_ent(ssd, INVALID_LPN, &ppa);

            // Set mapping table entry as unmapped
            ppa.ppa = UNMAPPED_PPA;
            set_maptbl_ent(ssd, lpn, &ppa);

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
