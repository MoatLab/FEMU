#ifndef __FEMU_FTL_H
#define __FEMU_FTL_H

#include "../nvme.h"

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
#define PL_BITS     (8)
#define LUN_BITS    (8)
#define CH_BITS     (7)

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
    int pos;
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

struct ssd {
    char *ssdname;
    struct ssdparams sp;
    struct ssd_channel *ch;
    struct ppa *maptbl; /* page level mapping table */
    uint64_t *rmap;     /* reverse mapptbl, assume it's stored in OOB */
    struct write_pointer wp;
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

    FemuCtrl *n;
};

void ssd_init(FemuCtrl *n);

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
