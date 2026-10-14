#ifndef __FEMU_NAND_MEDIA_H
#define __FEMU_NAND_MEDIA_H

/*
 * Uniform NAND media-layer API.
 *
 * NAND is the composable media layer: SLC/MLC/TLC/QLC/PLC chips with per-type
 * read/program/erase timing, organized across channels x LUNs x planes. The
 * bbssd FTL (with FDP, CSD, KV and CXL on top of it) and ZNS run on top and
 * talk to the NAND backend through this one interface, as do Open-Channel
 * 1.2 and 2.0. The media owns the timing
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
 * Which array-level resource holds the op, set at init. OCSSD uses the LUN
 * rule.
 */
typedef enum NandArrayContend {
    NAND_CONTEND_LUN_ONLY = 0,    /* bbssd, CSD, KV, CXL: one rule per LUN */
    NAND_CONTEND_PLANE_ONLY,      /* ZNS: plane rule, no lun rule */
    NAND_CONTEND_LUN_AND_PLANE,   /* ZNS with zns_lun_contention */
} NandArrayContend;

/*
 * bbssd and ZNS both pick STAGED when any bus phase is set, else OFF; OCSSD
 * 1.2 picks STAGED with oc12_channel_timing on.
 */
typedef enum NandChannelMode {
    NAND_CH_OFF = 0,           /* no channel accounting */
    NAND_CH_NOOP,              /* no mode selects it */
    NAND_CH_STAGED,            /* cmd/addr, data-xfer, status bus phases */
} NandChannelMode;

/*
 * Normalized physical location + per-op metadata. The controller's decode() fills
 * every field: flash_type (ZNS: per-block nand_type; else the device default),
 * page_type (bbssd: pg % cell_pages; OC12: from the page; ZNS/OC20: 0),
 * pe_cycles (bbssd blk->erase_cnt for ECC wear; else 0).
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
     * ECC tiers the caller adds for a read, on top of the wear and age tiers,
     * under the same cap; 0 for every mode that does not set it.
     */
    uint8_t  extra_tiers;
    /*
     * Sectors the data phase moves, when the controller transfers part of a
     * page (OC 1.2); 0 = the whole page. Needs cfg.secs_per_page.
     */
    uint32_t xfer_secs;
} NandLoc;

/*
 * ECC read time wear model shared by the modes: a read pays ecc_step_ns
 * more for each NAND_ECC_PE_PER_TIER erases of its block, up to
 * NAND_ECC_MAX_TIERS steps.
 */
enum {
    NAND_ECC_PE_PER_TIER = 750,
    NAND_ECC_MAX_TIERS   = 4,
};

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
    /*
     * Per-op bus phases of the ONFI profile (nand/onfi.c). Each is 0 unless
     * the profile is on; a 0 command field falls back to cmd_addr_ns and a
     * 0 extra adds nothing, so the staged model keeps its lengths.
     */
    int64_t rd_cmd_ns;       /* read command and address, tWB */
    int64_t wr_cmd_ns;       /* program command and address, tADL */
    int64_t er_cmd_ns;       /* erase command and address, tWB */
    int64_t cb_rd_cmd_ns;    /* copyback read command and address, tWB */
    int64_t cb_wr_cmd_ns;    /* copyback program command, no data, tWB */
    int64_t din_burst_ns;    /* write preamble and postamble of a data in */
    int64_t wr_post_ns;      /* confirm cycle after data in, tWB */
    int64_t dout_pre_ns;     /* command and preamble before a data out */
    int64_t dout_post_ns;    /* postamble hold and tRHW after a data out */
    int64_t dout_mp_pre_ns;  /* per-plane column select of a multi-plane read */
    /*
     * SCA only (policy.ca_separate). The command, status and select
     * fields above are then CA bus lengths. A data burst owns the DQ bus
     * from its SCE packet to the hold after its SCT packet: din_burst_ns
     * (write) or dout_edge_ns (read) plus the page.
     */
    int64_t din_gap_ns;      /* program command end to its burst (tCDL) */
    int64_t dout_edge_ns;    /* read burst without the page */
    int64_t ccs_ns;          /* column select end to the read burst */
    int64_t sca_packet_ns;   /* the SCE and SCT packets on the CA bus */
    int64_t sca_tail_ns;     /* SCT start to the end of its burst */
    /*
     * Read cache sequence (policy.cache_read): the busy time of each 31h
     * or 3Fh copy, the 31h or 3Fh cycle with tWB, and the 78h status that
     * selects the LUN before it when several LUNs share the channel.
     */
    int64_t trcbsy_ns;
    int64_t rc_step_ns;
    int64_t rc_sel_ns;
    /* multi-plane inter-plane busy */
    int64_t tplpbsy_ns;
    int64_t tplrbsy_ns;
    int64_t tplebsy_ns;
    /* ECC wear-on-read: see NAND_ECC_PE_PER_TIER for the usual tier size */
    int64_t ecc_step_ns;
    int32_t ecc_pe_per_tier;
    int32_t ecc_max_tiers;
    int32_t ecc_retention_per_tier_sec;
    /* program/erase suspend overhead (ns) paid by a read that preempts an
     * in-flight P/E on its LUN/plane (policy.pe_suspend); 0 = free suspend */
    int64_t tsusp_ns;
} NandMediaTiming;

typedef struct NandMediaPolicy {
    NandArrayContend   array_contend;
    NandChannelMode channel_mode;
    bool            pe_suspend;   /* reads preempt an in-flight program/erase on the
                                   * LUN/plane (all rules, staged or plain channel) */
    bool            ecc_on_read;
    bool            use_flat_timing;  /* true: scalar fields; false: table */
    /*
     * Book every read's data-out window, however many are outstanding, in a
     * list that grows; false keeps the 32-entry list and its fallback.
     */
    bool            bus_res_unbounded;
    /*
     * ONFI profile ordering (staged bus only). onfi_order: a read sends its
     * status before its data out, and a program ends at its status.
     * page_reg_hold: an op sends its command only when its LUN is ready,
     * and holds the LUN until its data out (read) or status (program,
     * erase, copyback) ends. mp_status_per_plane: a multi-plane program or
     * erase reads one status per plane (78h with several LUNs).
     */
    bool            onfi_order;
    bool            page_reg_hold;
    bool            mp_status_per_plane;
    /*
     * SCA protocol (staged bus, with the ONFI bits): commands, addresses
     * and status use a CA bus per channel, and the channel bus carries
     * only data bursts. Init grows the window lists.
     */
    bool            ca_separate;
    /*
     * Read cache (staged bus, with the ONFI bits): nand_media_read_seq()
     * times the reads of one LUN as one cache sequence.
     */
    bool            cache_read;
} NandMediaPolicy;

/*
 * Busy-timeline accessors. Each controller returns pointers into its own per-(ch,lun,
 * plane) device-state.
 */
typedef struct NandTimelineOps {
    uint64_t *(*ch_avail)(void *opaque, uint32_t ch);
    uint64_t *(*lun_avail)(void *opaque, const NandLoc *loc);
    uint64_t *(*plane_avail)(void *opaque, const NandLoc *loc);
    /*
     * Optional per-LUN lock around the array reservation; both NULL = no
     * locking. Only OCSSD 1.2 sets them, to its channel lock, since several
     * pollers time its commands; bbssd and ZNS each have one FTL thread.
     */
    void      (*lock_lun)(void *opaque, const NandLoc *loc);
    void      (*unlock_lun)(void *opaque, const NandLoc *loc);
    /*
     * Optional: told of each bus phase of non-zero length, [start, end) on
     * @ch. No controller sets it; the unit tests use it to check that no
     * two phases overlap.
     */
    void      (*bus_phase)(void *opaque, uint32_t ch, uint64_t start,
                           uint64_t end);
    /* optional, as bus_phase, for each CA bus phase (policy.ca_separate) */
    void      (*ca_phase)(void *opaque, uint32_t ch, uint64_t start,
                          uint64_t end);
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

/*
 * ONFI ordering with a grown list: when an op starts and more than this
 * many windows end at or before the latest op start time, the channel
 * keeps the newest half of the cap. The op can then add a few more. An
 * op older than what is left starts no earlier than the end of the
 * newest window that went (NandBusResList.low).
 */
#define NAND_BUS_HISTORY_MAX 1024

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
    /*
     * ONFI ordering only. @high is the latest op start time seen on the
     * channel. No phase of a later op starts before @low, and @low never
     * falls, so windows that end at or before it can go. A bounded list
     * keeps @low at @high. A grown list raises @low only when more than
     * @hist_cap windows end at or before @high, so an older op can still
     * use an idle gap before @high.
     */
    uint64_t high;
    uint64_t low;
    uint32_t hist_cap;
} NandBusResList;

/*
 * What occupies an array position, which the busy-until timelines do not say:
 * when the latest program or erase there ends, and when the latest read there
 * ends. Program/erase suspend needs both to let a read preempt only a program
 * or erase. One per LUN, or per plane under a plane-only rule.
 */
typedef struct NandSuspendState {
    uint64_t pe_end;
    uint64_t rd_end;
} NandSuspendState;

typedef struct NandMedia {
    NandMediaConfig cfg;
    NandBusResList *bus_res;   /* nchs entries; NULL unless NAND_CH_STAGED */
    NandBusResList *ca_res;    /* nchs CA buses; NULL unless ca_separate */
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
 * On-chip copyback: src read + dst program on one die, with no data phase on
 * the channel. In the staged model the read books its command/address and
 * status phases and the program its command/address. The caller checks that
 * src and dst share a die and a plane; bbssd line collection calls this when
 * gc_copyback is set.
 */
NandOpCompletion nand_media_copyback(NandMedia *m, const NandLoc *src,
                                     const NandLoc *dst, uint64_t stime);

/**
 * nand_media_read_cache_seq - time reads of one LUN as a read cache sequence
 * @m: the media
 * @locs: @n pages of one LUN, in the order the host asked for them
 * @n: number of pages, at least 1
 * @stime: start time of every page
 * @out: @n completions, one per page; may be NULL
 *
 * With policy.cache_read and more than one page: 00h-30h for the first
 * page, then 31h for the next page of a block, 00h-addr-31h for any other
 * page, and 3Fh after the last (ONFI 6.0 Section 6.15). Otherwise each
 * page is a nand_media_op() read, in order. Returns the last completion.
 * The sequence runs even when plain reads would end first; callers other
 * than tests use nand_media_read_seq().
 */
NandOpCompletion nand_media_read_cache_seq(NandMedia *m, const NandLoc *locs,
                                           int n, uint64_t stime,
                                           NandOpCompletion *out);

/**
 * nand_media_read_seq_cost - idle durations of a group of reads
 * @m: the media
 * @locs: @n pages of one LUN, as for nand_media_read_seq()
 * @n: number of pages, at least 1
 * @plain: the time @n plain reads take, one after another
 * @seq: the time one read cache sequence takes
 *
 * Both start on an idle LUN and idle buses. They use the phase lengths
 * that the two engines book. With at least two pages, policy.cache_read,
 * the ONFI order, the page register hold and LUN contention (the checks
 * nand_media_read_seq() makes), they equal the engines' end times on a
 * fresh media. Outside those conditions they are estimates only.
 */
void nand_media_read_seq_cost(NandMedia *m, const NandLoc *locs, int n,
                              uint64_t *plain, uint64_t *seq);

/**
 * nand_media_read_seq - time reads of one LUN, as a sequence if it is faster
 * @m: the media
 * @locs: @n pages of one LUN, in the order the host asked for them
 * @n: number of pages, at least 1
 * @stime: start time of every page
 * @out: @n completions, one per page; may be NULL
 *
 * As nand_media_read_cache_seq(), but when the idle sequence of
 * nand_media_read_seq_cost() would end after the plain reads, each page is
 * a nand_media_op() read, in order. The choice uses only timing fields and
 * the page list, so it does not change with bus traffic. Returns the last
 * completion.
 */
NandOpCompletion nand_media_read_seq(NandMedia *m, const NandLoc *locs, int n,
                                     uint64_t stime, NandOpCompletion *out);

/* the extra correction time a read of @loc takes; 0 when the model is off */
uint64_t nand_media_read_ecc_ns(NandMedia *m, const NandLoc *loc);

/*
 * The bus phase lengths an op is charged, after the fallbacks: a command
 * field of 0 takes cmd_addr_ns, and every bus phase is 0 when the staged
 * bus is off. The tPL*BSY gaps apply with the bus on or off.
 */
typedef struct NandMediaPhases {
    bool     staged;              /* channel_mode is NAND_CH_STAGED */
    bool     onfi_order;
    bool     page_reg_hold;
    bool     mp_status_per_plane;
    bool     sca;                 /* commands and status use the CA bus */
    bool     cache_read;          /* reads of one LUN form cache sequences */
    uint64_t page_xfer_ns;
    uint64_t rd_cmd_ns;
    uint64_t wr_cmd_ns;
    uint64_t er_cmd_ns;
    uint64_t cb_rd_cmd_ns;
    uint64_t cb_wr_cmd_ns;
    uint64_t status_ns;
    uint64_t dout_pre_ns;
    uint64_t dout_post_ns;
    uint64_t dout_mp_pre_ns;      /* per-plane select of a multi-plane read */
    uint64_t din_burst_ns;
    uint64_t wr_post_ns;
    uint64_t din_gap_ns;          /* SCA: program command end to its burst */
    uint64_t dout_edge_ns;        /* SCA: read burst without the page */
    uint64_t trcbsy_ns;           /* the next three are 0 without cache_read */
    uint64_t rc_step_ns;
    uint64_t rc_sel_ns;
    uint64_t tplrbsy_ns;
    uint64_t tplpbsy_ns;
    uint64_t tplebsy_ns;
} NandMediaPhases;

void nand_media_phases(const NandMedia *m, NandMediaPhases *out);

#endif /* __FEMU_NAND_MEDIA_H */
