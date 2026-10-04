#ifndef __FEMU_NAND_MEDIA_H
#define __FEMU_NAND_MEDIA_H

/*
 * Uniform NAND media-layer API.
 *
 * NAND is the composable media layer: SLC/MLC/TLC/QLC/PLC chips with per-type
 * read/program/erase timing, organized across channels x LUNs x planes. The
 * bbssd FTL (with FDP, CSD, KV and CXL on top of it) and ZNS run on top and
 * talk to the NAND backend through this one interface; OCSSD keeps its own
 * model in timing-model/timing.c. The media owns the timing
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

/*
 * Which array-level resource gates the op, set at init. OCSSD keeps its own
 * timing model (timing-model/timing.c) and uses neither enum.
 */
typedef enum NandArrayGate {
    NAND_GATE_LUN_ONLY = 0,    /* bbssd, CSD, KV, CXL: one gate per LUN */
    NAND_GATE_PLANE_ONLY,      /* ZNS: plane gate, no lun gate */
    NAND_GATE_LUN_AND_PLANE,   /* no mode selects it */
} NandArrayGate;

/* bbssd and ZNS both pick STAGED when any bus phase is set, else OFF */
typedef enum NandChannelMode {
    NAND_CH_OFF = 0,           /* no channel accounting */
    NAND_CH_NOOP,              /* no mode selects it */
    NAND_CH_STAGED,            /* cmd/addr, data-xfer, status bus phases */
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
    uint32_t age_sec;   /* seconds since the data was programmed; 0 = untracked */
    /*
     * Sectors the data phase moves, when the controller transfers part of a
     * page (OC 1.2); 0 = the whole page. Needs cfg.secs_per_page.
     */
    uint32_t xfer_secs;
} NandLoc;

typedef struct NandMediaTiming {
    /* flat scalars (bbssd-compat) */
    int64_t rd_ns;
    int64_t wr_ns;
    int64_t er_ns;
    /* flash-type-indexed table (ZNS, and bbssd with nand_cell_type) */
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
    int32_t ecc_retention_per_tier_sec;
    /* program/erase suspend overhead (ns) paid by a read that preempts an
     * in-flight P/E on its LUN/plane (policy.pe_suspend); 0 = free suspend */
    int64_t tsusp_ns;
} NandMediaTiming;

typedef struct NandMediaPolicy {
    NandArrayGate   array_gate;
    NandChannelMode channel_mode;
    bool            cache_read;
    bool            pe_suspend;   /* reads preempt an in-flight program/erase on the
                                   * LUN/plane (all gates, staged or plain channel) */
    bool            ecc_on_read;
    bool            use_flat_timing;  /* true: scalar fields; false: table */
    /*
     * Book every read's data-out window, however many are outstanding, in a
     * list that grows; false keeps the 32-entry list and its fallback.
     */
    bool            bus_res_unbounded;
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
    /*
     * Optional per-LUN lock around the array reservation; both NULL = no
     * locking. No mode sets them: bbssd and ZNS each have one FTL thread.
     */
    void      (*lock_lun)(void *opaque, const NandLoc *loc);
    void      (*unlock_lun)(void *opaque, const NandLoc *loc);
} NandTimelineOps;

typedef struct NandMediaConfig {
    uint32_t nchs;
    uint32_t luns_per_ch;
    uint32_t planes_per_lun;
    uint32_t secs_per_page;   /* divides NandLoc.xfer_secs; 0 = whole pages */
    NandMediaTiming  timing;
    NandMediaPolicy  policy;
    const NandTimelineOps *timeline;
    void                  *timeline_opaque;
} NandMediaConfig;

/*
 * A read's data-out is booked on the channel for the window in which it will
 * happen, [array done, +xfer), not from the moment the read was issued. The
 * windows live here, per channel; the controller's ch_avail accumulator keeps
 * meaning "the bus is busy until", for phases that use it now. Bounded so the
 * lookup stays a short scan; a channel that has more reads in flight than this
 * falls back to booking the bus from now, as before. policy.bus_res_unbounded
 * lifts the bound for a controller whose model never had it.
 */
#define NAND_BUS_RES_MAX 32

typedef struct NandBusRes {
    uint64_t start;
    uint64_t end;
} NandBusRes;

typedef struct NandBusResList {
    NandBusRes r[NAND_BUS_RES_MAX];
    int n;
    /* policy.bus_res_unbounded: the windows live here instead of in r[] */
    NandBusRes *grown;
    int cap;
} NandBusResList;

/*
 * What occupies an array position, which the busy-until timelines do not say:
 * when the latest program or erase there ends, and when the latest read there
 * ends. Program/erase suspend needs both to let a read preempt only a program
 * or erase. One per LUN, or per plane under a plane-only gate.
 */
typedef struct NandSuspendState {
    uint64_t pe_end;
    uint64_t rd_end;
} NandSuspendState;

typedef struct NandMedia {
    NandMediaConfig cfg;
    NandBusResList *bus_res;   /* nchs entries; NULL unless NAND_CH_STAGED */
    NandSuspendState *susp;    /* NULL unless policy.pe_suspend */
} NandMedia;

typedef struct NandOpCompletion {
    uint64_t done_ns;
    uint64_t latency_ns;
} NandOpCompletion;

void nand_media_init(NandMedia *m, const NandMediaConfig *cfg);
void nand_media_destroy(NandMedia *m);

/* single-chip op; returns completion (done_ns absolute, latency_ns = done - stime) */
NandOpCompletion nand_media_op(NandMedia *m, const NandLoc *loc,
                               NandMediaOp op, uint64_t stime);

/*
 * Multi-plane group: one parallel array op + per-plane bus + inter-plane busy.
 * Used for erases: line GC, FDP GC and KV reclaim erase a block on every plane
 * of a LUN at once. Host reads and programs still go one page at a time.
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
