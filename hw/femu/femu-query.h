/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * query-femu: the request the QMP command hands to a controller's FTL
 * thread, and the copy of namespace state the thread fills in.
 */
#ifndef HW_FEMU_FEMU_QUERY_H
#define HW_FEMU_FEMU_QUERY_H

#include "qapi/qapi-types-femu.h"

/* The most line records one call reports per namespace. */
#define FEMU_QUERY_MAX_LINES        4096
#define FEMU_QUERY_DEFAULT_LINES    256

typedef struct FemuQueryLine {
    uint32_t id;
    uint32_t vpc;
    uint32_t ipc;
    uint32_t erase_min;
    uint32_t erase_max;
    FemuLineState state;
} FemuQueryLine;

/*
 * One namespace. The caller fills nsid, generation, offset, max_lines and
 * the two buffers; the FTL thread fills the rest. The buffers are sized
 * from the geometry before the request is posted, so the FTL thread never
 * allocates.
 */
typedef struct FemuQueryNs {
    uint32_t nsid;
    uint64_t generation;
    int status;                 /* 0, or -ENOENT when the namespace changed */

    uint32_t nchs;
    uint32_t luns_per_ch;
    uint32_t pls_per_lun;
    uint32_t blks_per_pl;
    uint32_t pgs_per_blk;
    uint32_t page_size;
    uint32_t pgs_per_line;
    uint32_t tt_lines;

    uint64_t host_pages;
    uint64_t nand_pages;
    uint64_t gc_pages;
    uint64_t erases;

    uint32_t free_lines;
    uint32_t victim_lines;
    uint32_t full_lines;
    uint32_t retired_lines;
    uint32_t spare_lines;

    uint32_t offset;
    uint32_t max_lines;
    uint32_t nr_lines;
    FemuQueryLine *lines;       /* max_lines entries, or NULL for a summary */
    uint8_t *state;             /* state_cap entries, or NULL for a summary */
    uint32_t state_cap;
} FemuQueryNs;

typedef struct FemuQueryReq {
    uint32_t nr_ns;
    FemuQueryNs *ns;
    int status;                 /* 0, or -ENODEV when the device went away */
    bool done;                  /* set last, with release order */
} FemuQueryReq;

struct FemuCtrl;
struct ssd;

/* Run on the FTL thread between two requests. */
void femu_query_service(struct FemuCtrl *n, FemuQueryReq *req);
/* Fail a request no FTL thread will serve any more. */
void femu_query_cancel(FemuQueryReq *req);
/* Copy one bbssd namespace into @q. FTL thread only. */
void ssd_query_collect(struct ssd *ssd, FemuQueryNs *q);

#endif
