#ifndef __FEMU_ZNS_H
#define __FEMU_ZNS_H

#define SPG_BITS    (2)
#define PG_BITS     (16)
#define BLK_BITS    (32)
#define PL_BITS     (1)
#define FC_BITS     (2)
#define CH_BITS     (1)

#include "../nvme.h"
#include "zftl.h"

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

struct zns_ssd {
    uint64_t num_ch;
    uint64_t num_lun;
    uint64_t num_plane;
    uint64_t num_blk;
    uint64_t num_page;

    struct zns_ch *ch;
    struct write_pointer wp;

    SSDNandFlashTiming timing; /*Misao: accurate  timing emulation for zns ssd.*/
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
};

enum NvmeZoneAttr {
    NVME_ZA_FINISHED_BY_CTLR         = 1 << 0,
    NVME_ZA_FINISH_RECOMMENDED       = 1 << 1,
    NVME_ZA_RESET_RECOMMENDED        = 1 << 2,
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

typedef struct QEMU_PACKED NvmeIdNsZoned {
    uint16_t    zoc;
    uint16_t    ozcs;
    uint32_t    mar;
    uint32_t    mor;
    uint32_t    rrl;
    uint32_t    frl;
    uint8_t     rsvd20[2796];
    NvmeLBAFE   lbafe[16];
    uint8_t     rsvd3072[768];
    uint8_t     vs[256];
} NvmeIdNsZoned;

typedef struct NvmeZone {
    NvmeZoneDescr   d;
    uint64_t        w_ptr;
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

static inline void zns_set_zone_state(NvmeZone *zone, NvmeZoneState state)
{
    zone->d.zs = state << 4;
}

static inline uint64_t zns_zone_rd_boundary(NvmeNamespace *ns, NvmeZone *zone)
{
    return zone->d.zslba + ns->ctrl->zone_size;
}

static inline uint64_t zns_zone_wr_boundary(NvmeZone *zone)
{
    return zone->d.zslba + zone->d.zcap;
}

static inline bool zns_wp_is_valid(NvmeZone *zone)
{
    uint8_t st = zns_get_zone_state(zone);

    return st != NVME_ZONE_STATE_FULL &&
           st != NVME_ZONE_STATE_READ_ONLY &&
           st != NVME_ZONE_STATE_OFFLINE;
}

static inline uint8_t *zns_get_zd_extension(NvmeNamespace *ns, uint32_t zone_idx)
{
    return &ns->ctrl->zd_extensions[zone_idx * ns->ctrl->zd_extension_size];
}

static inline void zns_aor_inc_open(NvmeNamespace *ns)
{
    FemuCtrl *n = ns->ctrl;
    assert(n->nr_open_zones >= 0);
    if (n->max_open_zones) {
        n->nr_open_zones++;
        assert(n->nr_open_zones <= n->max_open_zones);
    }
}

static inline void zns_aor_dec_open(NvmeNamespace *ns)
{
    FemuCtrl *n = ns->ctrl;
    if (n->max_open_zones) {
        assert(n->nr_open_zones > 0);
        n->nr_open_zones--;
    }
    assert(n->nr_open_zones >= 0);
}

static inline void zns_aor_inc_active(NvmeNamespace *ns)
{
    FemuCtrl *n = ns->ctrl;
    assert(n->nr_active_zones >= 0);
    if (n->max_active_zones) {
        n->nr_active_zones++;
        assert(n->nr_active_zones <= n->max_active_zones);
    }
}

static inline void zns_aor_dec_active(NvmeNamespace *ns)
{
    FemuCtrl *n = ns->ctrl;
    if (n->max_active_zones) {
        assert(n->nr_active_zones > 0);
        n->nr_active_zones--;
        assert(n->nr_active_zones >= n->nr_open_zones);
    }
    assert(n->nr_active_zones >= 0);
}

void zns_ns_shutdown(NvmeNamespace *ns);
void zns_ns_cleanup(NvmeNamespace *ns);

#endif
