#ifndef __FEMU_NAND_MEDIA_H
#define __FEMU_NAND_MEDIA_H

/*
 * Uniform NAND media-layer API.
 *
 * NAND is the composable media layer: SLC/MLC/TLC/QLC/PLC chips with per-type
 * read/program/erase timing, organized across channels x LUNs x planes. Every FEMU
 * SSD controller (bbssd, bbssd+FDP, ZNS, OCSSD, CSD) runs its FTL/firmware on top and
 * talks to the NAND backend through this one interface. The media owns the timing
 * policy and the busy-timeline op math; it never includes any controller header and
 * never branches on controller type -- a controller normalizes its own address into a
 * NandLoc and configures the media's policy/timing to reproduce its behavior.
 *
 * The per-resource availability accumulators (next_*_avail_time) physically live in the
 * controller's own device-state structs for now and are accessed through the
 * NandTimelineOps vtable; the media reads/writes them but does not allocate them.
 */

#include <stdint.h>
#include <stdbool.h>

#define NAND_MEDIA_MAX_FLASH  6   /* matches MAX_FLASH_TYPE in nand.h */
#define NAND_MEDIA_MAX_PGTYPE 6

typedef enum NandMediaOp {
    NAND_MEDIA_READ = 0,
    NAND_MEDIA_PROGRAM,
    NAND_MEDIA_ERASE,
    NAND_MEDIA_COPYBACK,
} NandMediaOp;

/* which array-level resource gates the op (controller-specific, set at init) */
typedef enum NandArrayGate {
    NAND_GATE_LUN_ONLY = 0,    /* bbssd legacy, OCSSD chip */
    NAND_GATE_PLANE_ONLY,      /* ZNS: plane gate, no lun gate */
    NAND_GATE_LUN_AND_PLANE,   /* bbssd staged channel mode */
} NandArrayGate;

typedef enum NandChannelMode {
    NAND_CH_OFF = 0,           /* ZNS: no channel accounting */
    NAND_CH_NOOP,              /* OCSSD: channel advance returns now() unchanged */
    NAND_CH_STAGED,            /* bbssd: cmd/addr, data-xfer, status bus phases */
} NandChannelMode;

/*
 * Normalized physical location + per-op metadata. The controller's decode() fills
 * every field: flash_type (ZNS: per-block nand_type; else the device default),
 * page_type (bbssd: pg % cell_pages; ZNS/OC20: 0), pe_cycles (bbssd blk->erase_cnt
 * for ECC wear; else 0).
 */
typedef struct NandLoc {
    uint32_t ch;
    uint32_t lun;
    uint32_t pl;
    uint32_t blk;
    uint32_t pg;
    uint8_t  flash_type;
    uint8_t  page_type;
    uint32_t pe_cycles;
} NandLoc;

typedef struct NandMediaTiming {
    /* flat scalars (bbssd-compat) */
    int64_t rd_ns;
    int64_t wr_ns;
    int64_t er_ns;
    /* flash-type-indexed table (ZNS/OCSSD) */
    int64_t rd_table_ns[NAND_MEDIA_MAX_FLASH][NAND_MEDIA_MAX_PGTYPE];
    int64_t wr_table_ns[NAND_MEDIA_MAX_FLASH][NAND_MEDIA_MAX_PGTYPE];
    int64_t er_table_ns[NAND_MEDIA_MAX_FLASH];
    /* bbssd page-type program multiplier (pgtype_lat): mult x1000 by page_type */
    int32_t pgtype_mult[NAND_MEDIA_MAX_PGTYPE];
    bool    pgtype_lat;
    /* channel bus phases (bbssd staged) */
    int64_t cmd_addr_ns;
    int64_t page_xfer_ns;
    int64_t status_ns;
    /* multi-plane inter-plane busy */
    int64_t tplpbsy_ns;
    int64_t tplrbsy_ns;
    int64_t tplebsy_ns;
    /* cache read busy */
    int64_t trcbsy_ns;
    /* ECC wear-on-read */
    int64_t ecc_step_ns;
    int32_t ecc_pe_per_tier;
    int32_t ecc_max_tiers;
    /* program/erase suspend overhead (ns) for an urgent read to preempt an in-flight P/E */
    int64_t tsusp_ns;
} NandMediaTiming;

typedef struct NandMediaPolicy {
    NandArrayGate   array_gate;
    NandChannelMode channel_mode;
    bool            cache_read;
    bool            pe_suspend;   /* reads preempt an in-flight program/erase on the LUN */
    bool            copyback_skips_bus;
    bool            ecc_on_read;
    bool            use_flat_timing;  /* true: scalar fields; false: table */
    /*
     * Array busy-extend semantics (OCSSD): when the resource is busy at op arrival,
     * extend its availability by the full op latency (avail += lat) instead of the
     * default avail = max(now, avail) + lat. Both reduce to now+lat when idle; they
     * differ only when now > avail after a gap. Default false (max model).
     */
    bool            array_busy_extends;
    /*
     * page_type provided by the caller in NandLoc.page_type (used for the latency
     * table index). When false the media derives nothing; callers using the flat
     * timing path leave page_type 0.
     */
    bool            caller_page_type;
} NandMediaPolicy;

/*
 * Busy-timeline accessors. Each controller returns pointers into its own per-(ch,lun,
 * plane) device-state. page_reg_ready may be NULL when cache_read is off.
 */
typedef struct NandTimelineOps {
    uint64_t *(*ch_avail)(void *opaque, uint32_t ch);
    uint64_t *(*lun_avail)(void *opaque, const NandLoc *loc);
    uint64_t *(*plane_avail)(void *opaque, const NandLoc *loc);
    uint64_t *(*page_reg_ready)(void *opaque, const NandLoc *loc);
    /* optional per-LUN lock around the array reservation (OCSSD multi-threaded
     * Open-Channel path); both NULL = no locking (bbssd/ZNS single FTL thread). */
    void      (*lock_lun)(void *opaque, const NandLoc *loc);
    void      (*unlock_lun)(void *opaque, const NandLoc *loc);
} NandTimelineOps;

typedef struct NandMediaConfig {
    uint32_t nchs;
    uint32_t luns_per_ch;
    uint32_t planes_per_lun;
    NandMediaTiming  timing;
    NandMediaPolicy  policy;
    const NandTimelineOps *timeline;
    void                  *timeline_opaque;
} NandMediaConfig;

typedef struct NandMedia {
    NandMediaConfig cfg;
} NandMedia;

typedef struct NandOpCompletion {
    uint64_t done_ns;
    uint64_t latency_ns;
} NandOpCompletion;

void nand_media_init(NandMedia *m, const NandMediaConfig *cfg);

/* single-chip op; returns completion (done_ns absolute, latency_ns = done - stime) */
NandOpCompletion nand_media_op(NandMedia *m, const NandLoc *loc,
                               NandMediaOp op, uint64_t stime);

/*
 * Multi-plane group: one parallel array op + per-plane bus + inter-plane busy.
 * No caller yet. The bbssd allocator addresses planes now, so a group can be
 * built; what is still missing is batching the pages of one request that land
 * in different planes of a LUN into a single operation.
 */
NandOpCompletion nand_media_multiplane(NandMedia *m, const NandLoc *locs, int nlocs,
                                       NandMediaOp op, uint64_t stime);

/*
 * On-chip copyback: src read + dst program, skips the bus when configured.
 * No caller yet -- GC picks its destination from the striped write pointer, so
 * source and destination almost never share a LUN, which copyback requires.
 */
NandOpCompletion nand_media_copyback(NandMedia *m, const NandLoc *src,
                                     const NandLoc *dst, uint64_t stime);

#endif /* __FEMU_NAND_MEDIA_H */
