#ifndef __FEMU_FTL_H
#define __FEMU_FTL_H

#include "../nvme.h"
#include "../nand/nand-media.h"

#define INVALID_PPA     (~(0ULL))
#define INVALID_LPN     (~(0ULL))
#define UNMAPPED_PPA    (~(0ULL))

/* forward declarations for FDP types */
typedef struct FemuReclaimGroup FemuReclaimGroup;
typedef struct FemuRuHandle FemuRuHandle;
typedef struct FemuReclaimUnit FemuReclaimUnit;

enum {
    NAND_READ =  0,
    NAND_WRITE = 1,
    NAND_ERASE = 2,

    NAND_READ_LATENCY = 40000,
    NAND_PROG_LATENCY = 200000,
    NAND_ERASE_LATENCY = 2000000,
};

/* ECC read-latency wear model: P/E cycles per latency tier, and the tier cap */
enum {
    FEMU_ECC_PE_PER_TIER = 750,
    FEMU_ECC_MAX_TIERS   = 4,
};

enum {
    USER_IO = 0,
    GC_IO = 1,
};

enum {
    SEC_FREE = 0,
    SEC_INVALID = 1,
    SEC_VALID = 2,

    PG_FREE = 0,
    PG_INVALID = 1,
    PG_VALID = 2
};

enum {
    FEMU_ENABLE_GC_DELAY = 1,
    FEMU_DISABLE_GC_DELAY = 2,

    FEMU_ENABLE_DELAY_EMU = 3,
    FEMU_DISABLE_DELAY_EMU = 4,

    FEMU_RESET_ACCT = 5,
    FEMU_ENABLE_LOG = 6,
    FEMU_DISABLE_LOG = 7,
};


#define BLK_BITS    (16)
#define PG_BITS     (16)
#define SEC_BITS    (8)
#define PL_BITS     (4)
#define LUN_BITS    (7)
#define CH_BITS     (12)

/* describe a physical page addr */
struct ppa {
    union {
        struct {
            uint64_t blk : BLK_BITS;
            uint64_t pg  : PG_BITS;
            uint64_t sec : SEC_BITS;
            uint64_t pl  : PL_BITS;
            uint64_t lun : LUN_BITS;
            uint64_t ch  : CH_BITS;
            uint64_t rsv : 1;
        } g;

        uint64_t ppa;
    };
};

typedef int nand_sec_status_t;

struct nand_page {
    nand_sec_status_t *sec;
    int nsecs;
    int status;
};

struct nand_block {
    struct nand_page *pg;
    int npgs;
    int ipc; /* invalid page count */
    int vpc; /* valid page count */
    int erase_cnt;
    /*
     * Reads of this block since it was last erased. Reading a page stresses the
     * others in the block, so this is the pressure a real device watches to
     * decide when data has to be rewritten before it decays. Reported only; no
     * behaviour hangs off it yet.
     */
    uint64_t read_cnt;
    int wp; /* current write pointer */
};

struct nand_plane {
    struct nand_block *blk;
    int nblks;
};

struct nand_lun {
    struct nand_plane *pl;
    int npls;
    uint64_t next_lun_avail_time;
    bool busy;
    uint64_t gc_endtime;
};

struct ssd_channel {
    struct nand_lun *lun;
    int nluns;
    uint64_t next_ch_avail_time;
    bool busy;
    uint64_t gc_endtime;
};

struct ssdparams {
    int secsz;        /* sector size in bytes */
    int secs_per_pg;  /* # of sectors per page */
    int pgs_per_blk;  /* # of NAND pages per block */
    int blks_per_pl;  /* # of blocks per plane */
    int pls_per_lun;  /* # of planes per LUN (Die) */
    int luns_per_ch;  /* # of LUNs per channel */
    int nchs;         /* # of channels in the SSD */

    int pg_rd_lat;    /* NAND page read latency in nanoseconds */
    int pg_wr_lat;    /* NAND page program latency in nanoseconds */
    int blk_er_lat;   /* NAND block erase latency in nanoseconds */
    int ch_xfer_lat;  /* channel transfer latency for one page in nanoseconds
                       * this defines the channel bandwith
                       */

    /* optional richer NAND timing model (all 0 = off, flat per-page latency) */
    int cell_pages;   /* pages per wordline = bits/cell: 1 SLC..5 PLC; 0 = off */
    int pgtype_lat;   /* model per-page-type (LSB/CSB/MSB) program latency, 0=off */
    int ecc_step_ns;  /* per-tier ECC read-latency adder vs P/E wear, 0=off */
    int cmd_addr_lat; /* command+address bus phase (ns); 0 = off */
    int pg_xfer_lat;  /* page data-in/data-out bus phase (ns); 0 = off */
    int status_lat;   /* status/ready-poll bus phase (ns); 0 = off */
    int tplpbsy;      /* multi-plane program inter-plane busy (ns); 0 = off */
    int tplrbsy;      /* multi-plane read inter-plane busy (ns); 0 = off */
    int tplebsy;      /* multi-plane erase inter-plane busy (ns); 0 = off */
    int trcbsy;       /* cache read busy (next-page array overlap), ns; 0 = off */
    int trim_lat_ns;  /* modeled cost per processed DSM/TRIM range, ns; 0 = off */

    double gc_thres_pcent;
    int gc_thres_lines;
    double gc_thres_pcent_high;
    int gc_thres_lines_high;
    bool enable_gc_delay;

    /* below are all calculated values */
    int secs_per_blk; /* # of sectors per block */
    int secs_per_pl;  /* # of sectors per plane */
    int secs_per_lun; /* # of sectors per LUN */
    int secs_per_ch;  /* # of sectors per channel */
    int tt_secs;      /* # of sectors in the SSD */

    int pgs_per_pl;   /* # of pages per plane */
    int pgs_per_lun;  /* # of pages per LUN (Die) */
    int pgs_per_ch;   /* # of pages per channel */
    int tt_pgs;       /* total # of pages in the SSD */

    int blks_per_lun; /* # of blocks per LUN */
    int blks_per_ch;  /* # of blocks per channel */
    int tt_blks;      /* total # of blocks in the SSD */

    int secs_per_line;
    int pgs_per_line;
    int blks_per_line;
    int tt_lines;

    int pls_per_ch;   /* # of planes per channel */
    int tt_pls;       /* total # of planes in the SSD */

    int tt_luns;      /* total # of LUNs in the SSD */

    bool hot_cold_sep;  /* place overwrites in blocks of their own */

    /* DRAM write buffer: pages held before they are programmed */
    int buffer_size;
    double buffer_thres_pcent;

    /* buffer/cache effectiveness; 64-bit, a long run overflows an int */
    uint64_t read_hit_cnt;
    uint64_t read_cnt;
    uint64_t write_hit_cnt;
    uint64_t write_cnt;

    /* FDP: reclaim unit geometry */
    int lines_per_ru;
    int total_ru_cnt;
};

typedef struct line {
    int id;  /* line id, the same as corresponding block id */
    int ipc; /* invalid page count in this line */
    int vpc; /* valid page count in this line */
    QTAILQ_ENTRY(line) entry; /* in either {free,victim,full} list */
    /* position in the priority queue for victim lines */
    size_t                  pos;
    /* FDP: owning reclaim unit (NULL in non-FDP mode) */
    FemuReclaimUnit *my_ru;
    /* time the line filled, in ns; used by age-based GC policies */
    uint64_t close_time;
} line;

/* wp: record next write addr */
struct write_pointer {
    struct line *curline;
    int ch;
    int lun;
    int pg;
    int blk;
    int pl;
};

struct line_mgmt {
    struct line *lines;
    /* free line list, we only need to maintain a list of blk numbers */
    QTAILQ_HEAD(free_line_list, line) free_line_list;
    pqueue_t *victim_line_pq;
    //QTAILQ_HEAD(victim_line_list, line) victim_line_list;
    QTAILQ_HEAD(full_line_list, line) full_line_list;
    int tt_lines;
    int free_line_cnt;
    int victim_line_cnt;
    int full_line_cnt;
};

typedef struct buffer_entry {
    uint64_t lpn;
    QTAILQ_ENTRY(buffer_entry) b_entry;
} buffer_entry;

struct nand_cmd {
    int type;
    int cmd;
    int64_t stime; /* Coperd: request arrival time */
};

/* ========== FDP FTL Structures ========== */

/* FDP GC strategy selection */
enum {
    GC_GLOBAL_GREEDY              = 0,
    GC_GLOBAL_CB                  = 1,
    GC_GLOBAL_RAND                = 2,
    GC_GLOBAL_WARM                = 3,
    GC_NOISY_RUH_CUSTOM           = 4,
    GC_SELECTIVE_RUH              = 10,
    GC_SELECTIVE_RUH_ADV          = 11,
    GC_SELECTIVE_MIDAS_OP         = 12,
    GC_SELECTIVE_RUH_SOCIAL_WELFARE = 13,
    GC_EXPLOIT_SEQUENTIAL         = 14,
    GC_BIT_POPULATION             = 15,
};

typedef struct ru_mgmt {
    int mgmt_type; /* GC strategy: GC_GLOBAL_GREEDY, etc. */

    QTAILQ_HEAD(free_ru_list, FemuReclaimUnit) free_ru_list;
    pqueue_t *victim_ru_pq;  /* greedy/random victim selection */
    pqueue_t *victim_ru_cb;  /* cost-benefit victim selection */
    QTAILQ_HEAD(full_ru_list, FemuReclaimUnit) full_ru_list;
    uint64_t tt_rus;
    uint64_t free_ru_cnt;
    int victim_ru_cnt;
    int full_ru_cnt;
    int custom_gc_threshold;

    uint64_t gc_thres_rus;
    uint64_t gc_thres_rus_high;
    double gc_thres_pcent;
    double gc_thres_pcent_high;

    /* runtime WAF tracking */
    bool is_gc_triggered;
    bool is_force_gc_triggered;
    float waf_score_global;
    float waf_score_transitory;
    float utilization_overall;
} ru_mgmt;

struct FemuReclaimUnit {
    uint16_t ruidx;
    uint16_t rgidx;
    NvmeReclaimUnit *nvme_ru;
    FemuRuHandle *ruh;
    struct write_pointer *ssd_wptr;
    struct line **lines;
    QTAILQ_ENTRY(FemuReclaimUnit) entry;
    int vpc;
    int ipc;
    int pos;       /* heap index in the per-RG (global) victim pqueue */
    int ruh_pos;   /* heap index in the per-RUH victim pqueue (PI RUHs) */
    int n_lines;
    int next_line_index;
    int npages;
    int chance_token;
    float utilization;

    /* cost-benefit GC attributes */
    uint64_t last_init_time;
    uint64_t last_invalidated_time;
    int erase_cnt;
    float my_cb;
};

struct FemuRuHandle {
    uint16_t ruh_type;
    uint16_t ruhid;
    int ru_in_use_cnt;
    int ruh_live_pages_cnt;
    uint16_t curr_rg;
    NvmeRuHandle *ruh;
    FemuReclaimUnit **rus;
    FemuReclaimUnit *curr_ru;
    FemuReclaimUnit *gc_ru;
    struct ru_mgmt *ru_mgmt;
    uint64_t hbmw;
    uint64_t mbmw;
    uint64_t mbe;
};

struct FemuReclaimGroup {
    int rgidx;
    FemuReclaimUnit *rus;
    int tt_nru;
    struct ru_mgmt *ru_mgmt;
};

/*
 * Pluggable GC victim-selection policy (vtable). Alternative policies coexist
 * without forking the GC path; the default ("greedy") is the original behavior
 * verbatim. Selected by the gc_policy device property; the FDP RU GC path
 * (do_gc_fdp_style) is separate and unaffected.
 */
struct femu_ftl_policy_ops {
    const char *name;
    struct line *(*select_victim_line)(struct ssd *ssd, bool force);
};

/*
 * Allocation class chosen for a new write. Page and dftl use DATA, or DATA and
 * HOT when hot/cold separation is on; a log-block scheme puts its overwrites in
 * LOG so they land in blocks of their own rather than mixed in with data.
 */
enum { FEMU_MAP_CLASS_DATA = 0, FEMU_MAP_CLASS_LOG = 1,
       FEMU_MAP_CLASS_HOT = 2 };

struct map_write_plan {
    int target_class;      /* allocation class for the new page */
    bool may_need_reclaim; /* the scheme may have to reclaim before committing */
};

/*
 * Pluggable L2P mapping scheme (vtable). The default "page" scheme is the
 * original full-DRAM mapping, bit-identical; "dftl" adds a demand-cached
 * translation table (the CMT cost model in ftl-map-cmt.c). Selected by the
 * mapping device property. The flat maptbl/rmap stay the source of truth.
 */
struct femu_mapping_ops {
    const char *name;
    bool uses_cmt;          /* dftl-style demand-cached translation table */

    /* allocate and release scheme-private state in ssd->map_priv */
    void (*init)(struct ssd *ssd);
    void (*exit)(struct ssd *ssd);

    /* translate a read: lpn -> ppa (unmapped if absent) */
    struct ppa (*translate)(struct ssd *ssd, uint64_t lpn);

    /*
     * write split: choose placement, then commit the new mapping and invalidate
     * the old one
     */
    struct map_write_plan (*prepare_write)(struct ssd *ssd, uint64_t lpn,
                                           int io_type);
    void (*commit_write)(struct ssd *ssd, uint64_t lpn, struct ppa *new_ppa);

    /*
     * Reclaim of the scheme's own structures, such as a log-block merge. The
     * NAND cost it incurs is charged inside reclaim(), which returns the latency
     * to add to the request that triggered it. A scheme with nothing to reclaim
     * leaves both hooks NULL.
     */
    bool (*needs_reclaim)(struct ssd *ssd);
    uint64_t (*reclaim)(struct ssd *ssd, int budget);

    /* GC relocation: point lpn at its relocated ppa (victim policy is separate) */
    void (*gc_relocate_commit)(struct ssd *ssd, uint64_t lpn,
                               struct ppa *old_ppa, struct ppa *new_ppa);

    /* unmap an lpn on DSM deallocate; NULL falls back to the flat invalidation */
    void (*trim)(struct ssd *ssd, uint64_t lpn);
};

/* one slot of the optional DRAM read cache (ftl-cache.c) */
struct rcache_slot {
    uint64_t lpn;
    uint64_t last_used;  /* recency tick for true-LRU eviction */
    bool valid;
    bool ref;            /* CLOCK reference bit */
};

/* one slot of the optional DFTL cached mapping table (ftl-map-cmt.c) */
struct cmt_slot {
    uint64_t tp_id;
    bool valid;
    bool ref;   /* CLOCK reference bit */
    bool dirty; /* dirty TP: eviction costs a write-back */
};

struct ssd {
    char *ssdname;
    struct ssdparams sp;
    NandMedia media;    /* uniform NAND media-layer timing handle */
    struct ssd_channel *ch;
    struct ppa *maptbl; /* page level mapping table */
    uint64_t *rmap;     /* reverse mapptbl, assume it's stored in OOB */
    struct write_pointer wp;
    QTAILQ_HEAD(write_buffer, buffer_entry) write_buffer;   /* LRU order */
    GTree *wb_tree;                                         /* lpn lookup */
    int write_buffer_cnt;
    struct write_pointer log_wp; /* LOG class; its line is taken on first use */
    struct write_pointer hot_wp; /* HOT class; likewise */
    struct line_mgmt lm;

    /* lockless ring for communication with NVMe IO thread */
    struct rte_ring **to_ftl;
    struct rte_ring **to_poller;
    bool *dataplane_started_ptr;
    QemuThread ftl_thread;

    /* FDP: reclaim group/unit/handle management */
    FemuReclaimGroup *rg;
    uint64_t nrg;
    FemuReclaimUnit **rus;
    uint64_t nrus;
    FemuRuHandle *ruhs;
    uint64_t nruhs;
    bool fdp_enabled;
    bool fdp_debug;    /* enable FDP FTL tracing */

    /*
     * Optional DRAM read cache (timing-only; capacity 0 = disabled). It models
     * the latency benefit of a controller read cache but holds no data. Single
     * FTL thread, so no locking. See ftl-cache.c.
     */
    struct {
        uint32_t capacity;   /* number of cached pages (0 = off) */
        uint32_t used;
        uint32_t hand;       /* CLOCK hand */
        uint32_t evict_policy; /* 0 = CLOCK, 1 = random, 2 = LRU, 3 = 2Q */
        uint64_t rand_state; /* LCG state for reproducible random eviction */
        uint64_t tick;       /* monotonic recency counter for LRU */
        uint64_t hit_lat;    /* DRAM read-hit latency (ns) */
        uint64_t hits;
        uint64_t misses;
        struct rcache_slot *slots;
        int32_t *hash;       /* lpn hash -> slot idx, -1 empty */
        uint32_t hash_sz;
    } rcache;

    /*
     * Optional cached mapping table (DFTL/CMT) cost model (capacity 0 = disabled,
     * bit-identical). Demand-caches translation pages over the flat maptbl; a miss
     * charges a translation-page NAND read. Timing-only: maptbl stays the source
     * of truth. Single FTL thread, so no locking. See ftl-map-cmt.c.
     */
    struct {
        uint32_t capacity;   /* cached translation pages (0 = off) */
        uint32_t used;
        uint32_t hand;       /* CLOCK hand */
        uint32_t lpn_per_tp; /* LPNs covered by one translation page */
        uint64_t hits;
        uint64_t misses;
        struct cmt_slot *slots;
        int32_t *hash;       /* tp_id hash -> slot idx, -1 empty */
        uint32_t hash_sz;
    } cmt;

    /* active L2P mapping scheme (page by default) + its opaque private state */
    const struct femu_mapping_ops *mapping;
    void *map_priv;

    /* base-path GC victim policy (greedy by default) */
    const struct femu_ftl_policy_ops *policy;

    uint32_t bad_blocks; /* factory bad-block count, reported via SMART; 0 = none */

    /*
     * Write-amplification accounting: NAND pages programmed on behalf of the
     * host, and pages programmed to relocate data the device already held. WAF
     * is (host + relocated) / host.
     */
    uint64_t host_write_pages;  /* pages the host wrote (WAF denominator) */
    uint64_t nand_write_pages;  /* user pages programmed into NAND */
    uint64_t gc_write_pages;    /* pages the device relocated itself */

    bool debug_ftl; /* check FTL invariants on the GC path (off by default) */

    /*
     * Fault insertion, off by default. A period of N returns a media error on
     * every Nth read or write, counted rather than randomised so a run
     * reproduces exactly.
     */
    uint32_t err_read_unc_period;
    uint64_t err_read_counter;
    uint64_t err_read_injected;
    uint32_t err_write_fail_period;
    uint64_t err_write_counter;
    uint64_t err_write_injected;

    FemuCtrl *n;
};

int bb_check_geometry(FemuCtrl *n, Error **errp);
void ssd_free_write_buffer(struct ssd *ssd);
uint64_t ssd_buffer_destage(struct ssd *ssd, int budget, uint64_t stime);
uint64_t ssd_write_zeroes(struct ssd *ssd, NvmeRequest *req);
void ssd_init(FemuCtrl *n, NvmeNamespace *ns);

/* NAND media-layer bridge (hw/femu/bbssd/ftl-media.c) */
void bb_nand_media_init(struct ssd *ssd);
void bb_nand_media_refresh_timing(struct ssd *ssd);
uint64_t ssd_advance_status(struct ssd *ssd, struct ppa *ppa,
                            struct nand_cmd *ncmd);

#ifdef FEMU_DEBUG_FTL
#define ftl_debug(fmt, ...) \
    do { printf("[FEMU] FTL-Dbg: " fmt, ## __VA_ARGS__); } while (0)
#else
#define ftl_debug(fmt, ...) \
    do { } while (0)
#endif

#define ftl_err(fmt, ...) \
    do { fprintf(stderr, "[FEMU] FTL-Err: " fmt, ## __VA_ARGS__); } while (0)

#define ftl_log(fmt, ...) \
    do { printf("[FEMU] FTL-Log: " fmt, ## __VA_ARGS__); } while (0)


/* FEMU assert() */
#ifdef FEMU_DEBUG_FTL
#define ftl_assert(expression) assert(expression)
#else
#define ftl_assert(expression)
#endif

/* FDP debug logging */
#define fdp_log(fmt, ...) \
    do { fprintf(stderr, "[FEMU] FDP-Log: " fmt, ## __VA_ARGS__); } while (0)

/* FDP conditional trace: only emits when ssd->fdp_debug is set */
#define FDP_TRACE(ssd, fmt, ...) do { \
    if ((ssd)->fdp_debug) \
        fprintf(stderr, "[FEMU] FDP-Trace: " fmt, ## __VA_ARGS__); \
} while (0)

#endif
