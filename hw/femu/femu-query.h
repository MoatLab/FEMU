/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * query-femu: the request the QMP command hands to a controller's FTL
 * thread, the copy of namespace state the thread fills in, and the copy of
 * a zoned namespace that the main loop takes under the zone lock.
 */
#ifndef HW_FEMU_FEMU_QUERY_H
#define HW_FEMU_FEMU_QUERY_H

#include "qapi/qapi-types-femu.h"
#include "nand/nand-media.h"

/* The most line or zone records one call reports per namespace. */
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

typedef struct FemuQueryRuh {
    uint32_t id;
    FemuRuHandleType type;
    uint64_t host_bytes;
    uint64_t media_bytes;
} FemuQueryRuh;

typedef struct FemuQueryRu {
    uint32_t group;
    uint32_t unit;
    uint32_t handle;
    uint32_t vpc;
    uint32_t ipc;
    uint32_t erase_min;
    uint32_t erase_max;
    FemuReclaimUnitState state;
    bool has_handle;
} FemuQueryRu;

/*
 * One namespace. The caller fills nsid, generation, offset, max_lines and
 * the buffers; the FTL thread fills the rest. The buffers are sized from
 * the geometry before the request is posted, so the FTL thread never
 * allocates. With flexible data placement, the reclaim unit fields replace
 * the line fields.
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
    uint64_t pad_pages;
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

    bool fdp;
    uint32_t nrg;
    uint32_t rus_per_rg;
    uint32_t pgs_per_ru;
    uint32_t ru_counts[FEMU_RECLAIM_UNIT_STATE__MAX];
    uint32_t nr_ruhs;
    FemuQueryRuh *ruhs;         /* nr_ruhs entries, sized by the caller */
    uint32_t max_rus;
    uint32_t nr_rus;
    FemuQueryRu *rus;           /* max_rus entries, or NULL for a summary */
    uint8_t *ru_state;          /* ru_state_cap entries, or NULL */
    uint32_t ru_state_cap;
    uint16_t nr_phs;
    uint16_t *phs;              /* the namespace's placement handle list */
    uint32_t ftl_nsid;          /* the namespace whose FTL this is */
} FemuQueryNs;

typedef struct FemuQueryReq {
    uint32_t nr_ns;
    FemuQueryNs *ns;
    int status;                 /* 0, or -ENODEV when the device went away */
    bool done;                  /* set last, with release order */
} FemuQueryReq;

typedef struct FemuQueryZone {
    uint64_t slba;
    uint64_t cap;
    uint64_t wp;
    uint32_t index;
    FemuZoneState state;
    FemuZoneType type;
    bool wp_valid;
    bool zrwa;
} FemuQueryZone;

/*
 * One zoned namespace. The caller fills nsid, generation, offset, max_zones
 * and the buffer; zns_query_collect() fills the rest.
 */
typedef struct FemuQueryZoned {
    uint32_t nsid;
    uint64_t generation;

    uint32_t lba_size;
    uint64_t zone_size;
    uint64_t zone_cap;
    uint32_t max_open;
    uint32_t max_active;
    uint32_t num_zones;
    uint32_t counts[FEMU_ZONE_STATE__MAX];

    uint32_t offset;
    uint32_t max_zones;
    uint32_t nr_zones;
    FemuQueryZone *zones;       /* max_zones entries, or NULL for a summary */
} FemuQueryZoned;

struct FemuCtrl;
struct ssd;
struct NvmeNamespace;

/* Run on the FTL thread between two requests. */
void femu_query_service(struct FemuCtrl *n, FemuQueryReq *req);
/* Fail a request no FTL thread will serve any more. */
void femu_query_cancel(FemuQueryReq *req);
/* Copy one bbssd namespace into @q. FTL thread only. */
void ssd_query_collect(struct ssd *ssd, FemuQueryNs *q);
uint32_t ssd_owner_nsid(struct ssd *ssd);
/*
 * Copy one zoned namespace into @q under its zone lock. Main loop only.
 * Returns false, with @q unchanged, when a poller holds the lock.
 */
bool zns_query_collect(struct NvmeNamespace *ns, FemuQueryZoned *q);
/* The media layer of a zoned namespace or an OCSSD controller, or NULL. */
const NandMedia *zns_query_media(struct NvmeNamespace *ns);
const NandMedia *oc_query_media(struct FemuCtrl *n);

#endif
