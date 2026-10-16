#ifndef __FEMU_ZNS_H
#define __FEMU_ZNS_H

#define SPG_BITS    (2)
#define PG_BITS     (16)
#define BLK_BITS    (16)
#define PL_BITS     (3)
#define FC_BITS     (8)
#define CH_BITS     (7)

#include "../nvme.h"
#include "zftl.h"
#include "../nand/nand-media.h"

#define LOGICAL_PAGE_SIZE (4*KiB)
#define ZNS_PAGE_SIZE (16*KiB)
#define ZNS_DEFAULT_NUM_WRITE_CACHE (3)
#define ZNS_DEFAULT_L2P_CACHE_SIZE (1*MiB)

//chunk size = 4MiB = 256*16KiB
#define ZNS_LOG_CHUNK_SIZE (8)

#define UNMAPPED_PPA    (~(0ULL))
#define INVALID_LPN     (~(0ULL))
#define INVALID_PPA     (~(0ULL))
#define INVALID_SBLK     (~(0ULL))

/**
 * REFERENCE
 * slc: [ISSCC 2020] A 128Gb 1b/Cell 96-Word-Line-Layer 3D Flash Memory to Improve Random Read Latency with tPROG=75µs and tR=4µs
 * tlc: one-step program, plat_us = 1e6×PageSize×3÷(ProgramThroughput/# of planes) [ISSCC 2024] A 1Tb Density 3b/Cell 3D-NAND Flash on a 2YY-Tier Technology with a 300MB/s Write Throughput
 * qlc: two-step program, plat_us = 2×1e6×PageSize×4÷(ProgramThroughput/# of planes) [ISSCC 2024] A 280-Layer 1Tb 4b/cell 3D-NAND Flash Memory with a 28.5Gb/mm2 Areal Density and a 3.2GB/s High-Speed IO Rate
 */
#define SLC_PROGRAM_LATENCY_NS (75000)
#define TLC_PROGRAM_LATENCY_NS (937500)
#define QLC_PROGRAM_LATENCY_NS (12196000)

/* the largest zns_pg_rd_lat (with page types) and zns_ecc_step_ns: 1 hour */
#define ZNS_TIMING_MAX_NS   (3600LL * 1000 * 1000 * 1000)

#define SLC_READ_LATENCY_NS (4000)
#define TLC_READ_LATENCY_NS (32000)
#define QLC_READ_LATENCY_NS (85000)

/**
 * just to emulate very small read/write latency
 */
#define SRAM_WRITE_LATENCY_NS (1000)
#define SRAM_READ_LATENCY_NS (1000)

enum {
    NAND_READ =  0,
    NAND_WRITE = 1,
    NAND_ERASE = 2,
};

enum {
    USER_IO = 0,
    GC_IO = 1,
};

typedef struct QEMU_PACKED NvmeZonedResult {
    uint64_t slba;
} NvmeZonedResult;

typedef struct NvmeIdCtrlZoned {
    uint8_t     zasl;
    uint8_t     rsvd1[4095];
} NvmeIdCtrlZoned;

struct ppa {
    union {
        struct {
        uint64_t spg  : SPG_BITS;
        uint64_t pg   : PG_BITS;
	    uint64_t blk  : BLK_BITS;
	    uint64_t fc   : FC_BITS;
        uint64_t pl   : PL_BITS;
	    uint64_t ch   : CH_BITS;
        uint64_t V    : 1;
        uint64_t rsv  : 8;
        } g;

	uint64_t ppa;
    };
};

struct write_pointer {
    uint64_t ch;
    uint64_t lun;
};

struct nand_cmd {
    int cmd;
    int type;
    uint64_t stime;
};


struct zns_blk {
    int nand_type;
    uint64_t next_blk_avail_time;
    uint64_t page_wp; //next free page
    uint32_t erase_cnt;     /* erases by Zone Reset; FTL thread only */
};

struct zns_plane{
    struct zns_blk *blk;
    uint64_t next_plane_avail_time;
};

struct zns_fc {
    struct zns_plane *plane;
    uint64_t next_fc_avail_time;
};

struct zns_ch {
    struct zns_fc *fc;
    uint64_t next_ch_avail_time;
};


typedef struct SSDNandFlashTiming {
    uint64_t pg_rd_lat[MAX_FLASH_TYPE];  /* NAND page read latency in nanoseconds */
    uint64_t pg_wr_lat[MAX_FLASH_TYPE]; /* NAND page program latency in nanoseconds */
    uint64_t blk_er_lat[MAX_FLASH_TYPE]; /* NAND block erase latency in nanoseconds */
    /* channel bus phases shared by every die on a channel; all 0 = no bus */
    uint64_t cmd_addr_lat;  /* command and address cycles */
    uint64_t pg_xfer_lat;   /* page data-in (program) / data-out (read) */
    uint64_t status_lat;    /* status read after a read or erase */
    /* program/erase suspend: a read preempts a busy plane (0 = off) */
    bool     pe_suspend;
    uint64_t tsusp_ns;
    /* one array op at a time per LUN, as on a real die (false = per plane) */
    bool     lun_contention;
    /* a zone reset erases only the blocks that hold programmed pages */
    bool     reset_by_fill;
    /* a read takes the latency of its page type, around the mean above */
    bool     page_types;
    /* ECC read time per wear step (ns); 0 = off */
    int64_t  ecc_step_ns;
} SSDNandFlashTiming;

struct zns_write_cache{
    uint64_t sblk; //idx of corresponding superblock
    uint64_t used; 
    uint64_t cap;
    uint64_t* lpns; //identify the cached data
};

struct zns_sram{
    int num_wc;
    struct zns_write_cache* write_cache;
};

typedef struct ZnsFinEvent {
    uint64_t ns;        /* when the zone finished */
    uint32_t zone;
    uint32_t gen;
} ZnsFinEvent;

struct zns_ssd {
    uint64_t num_ch;
    uint64_t num_lun;
    uint64_t num_plane;
    uint64_t num_blk;
    uint64_t num_page;

    struct zns_ch *ch;
    struct write_pointer wp;

    SSDNandFlashTiming timing; /*Misao: accurate  timing emulation for zns ssd.*/
    NandMedia media;           /* shared NAND op timing (hw/femu/nand) */

    /*
     * Zones whose descriptor changed for a reason the host did not cause, and
     * the counters behind the optional write-fault injection that produces
     * them. The list holds ZSLBAs; a full page is reported as an overflow so
     * the host rescans rather than trusting a truncated list.
     */
    /*
     * Zone descriptors, the lists and counters behind them, and the changed
     * list below are read and written by whichever poller thread holds the
     * queue a command arrived on, and read by the thread serving Get Log Page.
     * Nothing orders those against each other, so they take this.
     */
    QemuMutex zone_lock;
    /*
     * Zone Management Send waits on this, with zone_lock, until the writes
     * it can touch are finalized; new writes wait while draining is set.
     * inflight_total sums every zone's inflight count.
     */
    QemuCond zone_cond;
    uint32_t draining;
    uint32_t inflight_total;

    /*
     * Zones in each state, indexed by the state code. Kept with every state
     * change, under the zone lock, so query-femu need not walk the zones.
     */
    uint32_t zone_states[16];

    uint64_t changed_zones[511];
    /*
     * change_seq counts recorded changes; each entry keeps the count of its
     * last change, and notice_seq the count when a notice was last raised.
     * A read acknowledges only what its snapshot held.
     */
    uint64_t changed_seqs[511];
    uint64_t change_seq;
    uint64_t notice_seq;
    uint32_t nr_changed_zones;
    bool     changed_zone_overflow;
    uint32_t err_write_fail_period;   /* fail one write in N; 0 = off */
    uint64_t err_write_counter;
    uint64_t err_write_injected;
    /*
     * Finish Zone Recommended (ZNS 1.4, 5.5) and Zone Active Excursions
     * (5.6): a zone written but not finished for fzr_sec gets FZR, and
     * frl_sec later the controller finishes it. Checked once a second.
     */
    uint32_t fzr_sec;
    uint32_t frl_sec;
    QEMUTimer *fzr_timer;
    uint64_t fzr_set;
    uint64_t zae_done;
    /*
     * Wear: block erases by Zone Reset, summed for SMART Percentage Used.
     * The FTL thread adds to it and the log thread reads it, so it is atomic.
     */
    uint64_t total_erases;
    uint32_t rated_pe_cycles;   /* 0: no rating, no life estimate */
    int flash_type;
    uint64_t program_unit;
    uint64_t stripe_unit;
    struct zns_sram cache;

    /*Misao: we still need a ftl in consumer devices*/
    uint64_t l2p_sz; /* = # of 4KiB pages*/
    struct ppa *maptbl; /* (page - chunk - block) hybrid L2P mapping table */

    /* lockless ring for communication with NVMe IO thread */
    struct rte_ring **to_ftl;
    struct rte_ring **to_poller;
    bool *dataplane_started_ptr;
    QemuThread ftl_thread;

    uint32_t lbasz;
    uint32_t active_zone;

    /*
     * Zone-to-parallelism mapping. A zone spans chnls_per_zone channels;
     * chnls_per_zone == num_ch is the full-width default. Narrower zones let
     * num_ch/chnls_per_zone zones share one physical block index, each bound to
     * its own channel group, so per-channel page use is unchanged. Placement
     * progress is tracked per zone, since zones fill independently.
     */
    uint64_t chnls_per_zone;
    /*
     * LUNs a zone spans on each of its channels; luns_per_zone == num_lun is
     * the default. Zones that sit on different LUN groups of one channel
     * group also share a block index. zone_order_lun steps a zone's slots
     * through its LUNs before its channels.
     */
    uint64_t luns_per_zone;
    bool zone_order_lun;
    uint64_t *zone_wp_slot;
    /*
     * First plane of the zone's current die slot that holds no data yet. A
     * flush of a partial cache (an eviction) stops mid-die; the zone's next
     * flush continues there instead of starting over at plane 0.
     */
    uint8_t *zone_wp_plane;
    /*
     * Finished zones whose write caches the FTL thread programs. Each
     * reset starts a new generation of the zone. Under zone_lock, zgen
     * counts them and each finish adds a record to fin_ev (fin_lock).
     * The FTL thread owns the rest: ftl_gen is the generation of its last
     * reset of the zone, ftl_fin and ftl_fin_ns tell that this generation
     * finished and when, fin_done when its programs end, and fin_wait
     * keeps the newest record of each zone whose reset it has not seen
     * yet; ftl_wait_new tells a reset may have made one current. ftl_late
     * lists finished zones whose cache took a write since: the next
     * command that is not a read programs them.
     */
    QemuMutex fin_lock;
    GArray *fin_ev;
    GArray *ftl_late;
    bool ftl_wait_new;
    int fin_any;
    uint32_t *zgen;
    uint32_t *ftl_gen;
    unsigned long *ftl_fin;
    uint64_t *ftl_fin_ns;
    uint64_t *fin_done;
    GArray *fin_wait;
};

enum NvmeZoneAttr {
    NVME_ZA_FINISHED_BY_CTLR         = 1 << 0,
    NVME_ZA_FINISH_RECOMMENDED       = 1 << 1,
    NVME_ZA_RESET_RECOMMENDED        = 1 << 2,
    NVME_ZA_ZRWA_VALID               = 1 << 3,
    NVME_ZA_ZD_EXT_VALID             = 1 << 7,
};

typedef struct QEMU_PACKED NvmeZoneReportHeader {
    uint64_t    nr_zones;
    uint8_t     rsvd[56];
} NvmeZoneReportHeader;

enum NvmeZoneReceiveAction {
    NVME_ZONE_REPORT                 = 0,
    NVME_ZONE_REPORT_EXTENDED        = 1,
};

enum NvmeZoneReportType {
    NVME_ZONE_REPORT_ALL             = 0,
    NVME_ZONE_REPORT_EMPTY           = 1,
    NVME_ZONE_REPORT_IMPLICITLY_OPEN = 2,
    NVME_ZONE_REPORT_EXPLICITLY_OPEN = 3,
    NVME_ZONE_REPORT_CLOSED          = 4,
    NVME_ZONE_REPORT_FULL            = 5,
    NVME_ZONE_REPORT_READ_ONLY       = 6,
    NVME_ZONE_REPORT_OFFLINE         = 7,
};

enum NvmeZoneType {
    NVME_ZONE_TYPE_RESERVED          = 0x00,
    NVME_ZONE_TYPE_CONVENTIONAL      = 0x01,
    NVME_ZONE_TYPE_SEQ_WRITE         = 0x02,
};

enum NvmeZoneSendAction {
    NVME_ZONE_ACTION_RSD             = 0x00,
    NVME_ZONE_ACTION_CLOSE           = 0x01,
    NVME_ZONE_ACTION_FINISH          = 0x02,
    NVME_ZONE_ACTION_OPEN            = 0x03,
    NVME_ZONE_ACTION_RESET           = 0x04,
    NVME_ZONE_ACTION_OFFLINE         = 0x05,
    NVME_ZONE_ACTION_SET_ZD_EXT      = 0x10,
    NVME_ZONE_ACTION_FLUSH_ZRWA      = 0x11,
};

typedef struct QEMU_PACKED NvmeZoneDescr {
    uint8_t     zt;
    uint8_t     zs;
    uint8_t     za;
    uint8_t     rsvd3[5];
    uint64_t    zcap;
    uint64_t    zslba;
    uint64_t    wp;
    uint8_t     rsvd32[32];
} NvmeZoneDescr;

typedef enum NvmeZoneState {
    NVME_ZONE_STATE_RESERVED         = 0x00,
    NVME_ZONE_STATE_EMPTY            = 0x01,
    NVME_ZONE_STATE_IMPLICITLY_OPEN  = 0x02,
    NVME_ZONE_STATE_EXPLICITLY_OPEN  = 0x03,
    NVME_ZONE_STATE_CLOSED           = 0x04,
    NVME_ZONE_STATE_READ_ONLY        = 0x0D,
    NVME_ZONE_STATE_FULL             = 0x0E,
    NVME_ZONE_STATE_OFFLINE          = 0x0F,
} NvmeZoneState;

#define NVME_SET_CSI(vec, csi) (vec |= (uint8_t)(1 << (csi)))

typedef struct QEMU_PACKED NvmeLBAFE {
    uint64_t    zsze;
    uint8_t     zdes;
    uint8_t     rsvd9[7];
} NvmeLBAFE;

enum NvmeIdNsZonedFlags {
    NVME_ID_NS_ZONED_OZCS_RAZB      = 1 << 0, /* read across zone boundaries */
    NVME_ID_NS_ZONED_ZOC_ZAE             = 1 << 1, /* zone active excursions */
    NVME_ID_NS_ZONED_OZCS_ZRWASUP        = 1 << 1, /* ZRWA supported */
    NVME_ID_NS_ZONED_ZRWACAP_EXPFLUSHSUP = 1 << 0, /* explicit ZRWA flush */
};

/* Zone Mgmt Send cdw13 bit 9: allocate a ZRWA when opening the zone */
#define NVME_ZSFLAG_ZRWA_ALLOC (1 << 9)

typedef struct QEMU_PACKED NvmeIdNsZoned {
    uint16_t    zoc;
    uint16_t    ozcs;
    uint32_t    mar;
    uint32_t    mor;
    uint32_t    rrl;
    uint32_t    frl;
    /*
     * ZRWA fields sit at their spec byte offsets inside what was reserved space
     * (numzrwa@44, zrwafg@48, zrwas@50, zrwacap@52). The reserved bytes around
     * them keep lbafe[] at offset 2816: 24 + 4 + 2 + 2 + 1 + 2763 = 2796.
     */
    uint8_t     rsvd20[24];
    uint32_t    numzrwa;
    uint16_t    zrwafg;
    uint16_t    zrwas;
    uint8_t     zrwacap;
    uint8_t     rsvd53[2763];
    NvmeLBAFE   lbafe[16];
    uint8_t     rsvd3072[768];
    uint8_t     vs[256];
} NvmeIdNsZoned;

QEMU_BUILD_BUG_ON(sizeof(NvmeIdNsZoned) != 4096);
QEMU_BUILD_BUG_ON(offsetof(NvmeIdNsZoned, numzrwa) != 44);
QEMU_BUILD_BUG_ON(offsetof(NvmeIdNsZoned, lbafe) != 2816);

typedef struct NvmeZone {
    NvmeZoneDescr   d;
    uint64_t        w_ptr;
    /* first write since the zone was empty, ns; 0 = nothing written */
    uint64_t        act_ns;
    /* when Finish Zone Recommended was set, ns; 0 = not set */
    uint64_t        fzr_ns;
    /* writes admitted and not yet finalized, under zone_lock */
    uint32_t        inflight;
    QTAILQ_ENTRY(NvmeZone) entry;
} NvmeZone;

typedef struct NvmeNamespaceParams {
    uint32_t nsid;
    QemuUUID uuid;

    bool     zoned;
    bool     cross_zone_read;
    uint64_t zone_size_bs;
    uint64_t zone_cap_bs;
    uint32_t max_active_zones;
    uint32_t max_open_zones;
    uint32_t zd_extension_size;

    struct zns_ssd *zns;
} NvmeNamespaceParams;

static inline uint32_t zns_nsid(NvmeNamespace *ns)
{
    if (ns) {
        return ns->id;
    }

    return -1;
}

static inline NvmeLBAF *zns_ns_lbaf(NvmeNamespace *ns)
{
    NvmeIdNs *id_ns = &ns->id_ns;
    return &id_ns->lbaf[NVME_ID_NS_FLBAS_INDEX(id_ns->flbas)];
}

static inline uint8_t zns_ns_lbads(NvmeNamespace *ns)
{
    /* NvmeLBAF */
    return zns_ns_lbaf(ns)->lbads;
}

/* calculate the number of LBAs that the namespace can accomodate */
static inline uint64_t zns_ns_nlbas(NvmeNamespace *ns)
{
    return ns->size >> zns_ns_lbads(ns);
}

/* convert an LBA to the equivalent in bytes */
static inline size_t zns_l2b(NvmeNamespace *ns, uint64_t lba)
{
    return lba << zns_ns_lbads(ns);
}

static inline NvmeZoneState zns_get_zone_state(NvmeZone *zone)
{
    return zone->d.zs >> 4;
}

static inline void zns_set_zone_state(NvmeNamespace *ns, NvmeZone *zone,
                                      NvmeZoneState state)
{
    uint32_t *count = ns->zns->zone_states;

    /* a zone not yet set up has state 0 and is in no count */
    if (zns_get_zone_state(zone)) {
        count[zns_get_zone_state(zone)]--;
    }
    zone->d.zs = state << 4;
    count[state]++;
}

static inline uint64_t zns_zone_rd_boundary(NvmeNamespace *ns, NvmeZone *zone)
{
    return zone->d.zslba + ns->zone_size;
}

static inline uint64_t zns_zone_wr_boundary(NvmeZone *zone)
{
    return zone->d.zslba + zone->d.zcap;
}

static inline bool zns_wp_is_valid(NvmeZone *zone)
{
    uint8_t st = zns_get_zone_state(zone);

    /* a conventional zone has no write pointer; it is reported as all-ones */
    if (zone->d.zt == NVME_ZONE_TYPE_CONVENTIONAL) {
        return false;
    }

    return st != NVME_ZONE_STATE_FULL &&
           st != NVME_ZONE_STATE_READ_ONLY &&
           st != NVME_ZONE_STATE_OFFLINE;
}

static inline uint8_t *zns_get_zd_extension(NvmeNamespace *ns, uint32_t zone_idx)
{
    return &ns->zd_extensions[zone_idx * ns->zd_extension_size];
}

static inline void zns_aor_inc_open(NvmeNamespace *ns)
{
    assert(ns->nr_open_zones >= 0);
    if (ns->max_open_zones) {
        ns->nr_open_zones++;
        assert(ns->nr_open_zones <= ns->max_open_zones);
    }
}

static inline void zns_aor_dec_open(NvmeNamespace *ns)
{
    if (ns->max_open_zones) {
        assert(ns->nr_open_zones > 0);
        ns->nr_open_zones--;
    }
    assert(ns->nr_open_zones >= 0);
}

static inline void zns_aor_inc_active(NvmeNamespace *ns)
{
    assert(ns->nr_active_zones >= 0);
    if (ns->max_active_zones) {
        ns->nr_active_zones++;
        assert(ns->nr_active_zones <= ns->max_active_zones);
    }
}

static inline void zns_aor_dec_active(NvmeNamespace *ns)
{
    if (ns->max_active_zones) {
        assert(ns->nr_active_zones > 0);
        ns->nr_active_zones--;
        assert(ns->nr_active_zones >= ns->nr_open_zones);
    }
    assert(ns->nr_active_zones >= 0);
}

void zns_ns_shutdown(NvmeNamespace *ns);
void zns_ns_cleanup(NvmeNamespace *ns);

#endif
