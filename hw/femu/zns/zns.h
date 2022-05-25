#ifndef __FEMU_ZNS_H
#define __FEMU_ZNS_H

#include "../nvme.h"

enum {
    NAND_READ =  0,
    NAND_WRITE = 1,
    NAND_ERASE = 2,

 /* FIXME: Just simply add SLC NAND latency numbers in nanoseconds in nand.h for now,(Inhoinno) */
    NAND_READ_LATENCY  = 65000/4,  //65us TLC_tREAD(65us : 16K page time)   =16.25
    NAND_PROG_LATENCY  = 450000/12,//450us TLC_tProg(450us: 16K page(/4),TLC(/3) time)  =37.5
    NAND_ERASE_LATENCY = SLC_BLOCK_ERASE_LATENCY_NS,//2000000
    NAND_CHNL_PAGE_TRANSFER_LATENCY = 2441, // =2.5? 1200MT
    //SK Hynix read : 400Mb/s for 1 chip..
    //ZEMU read     : 
    //SK Hynix write: 100Mb/s for 1 chip..
    //ZEMU write    : 5Mb/s for 1 chip...

/* As best I know, ZONE RESET time is way more faster than ERASE_LAT (Inhoinno) */
    ZONE_RESET_LATENCY =  200000,
};


/**
 * @brief 
 * inhoinno: to implement controller-level zone mapping in zns ssd, 
 * struct ssd_channel is neccesary
 * so simply extends 'struct ssd_channel' in ../bbssd/ftl.h:102
 */
typedef struct zns_ssd_channel {
    int nzones;
    uint64_t next_ch_avail_time; 
    bool busy;
}zns_ssd_channel;

/**
 * @brief 
 * inhoinno: to implement Multi way in ZNS, ssd_chip structure is required.
 * This zns_ssd_chip structure follows 'struct ssd_lun' in ../bbssd/ftl.h:94
 * but differnce is ZNS does not do ftl jobs such as badblock management, GC 
 * so this structure only contains minimum fields
 */
typedef struct zns_ssd_lun {
    uint64_t next_avail_time; // in nanoseconds
    bool busy;
}zns_ssd_lun;

/**
 * @brief 
 * inhoinno: to emulate latency in zns ssd, struct znsssd is needed
 * extends 'struct ssdparams' in ../bbssd/ftl.h:110
 */
struct zns_ssdparams{
    uint16_t register_model;    /* =1 single register =2 double register */
    uint64_t nchnls;            /* # of channels in the SSD */
    uint64_t ways;              /* # of ways in the SSD */
    uint64_t zones;             /* # of zones in ZNS SSD */
    uint64_t chnls_per_zone;    /* ZNS Association degree. # of zones per channel, must be divisor of nchnls */
    uint64_t csze_pages;        /* #of Pages in Chip (Inhoinno:I guess lun in femu)*/
    uint64_t nchips;            /* # of chips in SSD*/

    uint64_t pg_rd_lat;         /* NAND page read latency in nanoseconds */
    uint64_t pg_wr_lat;         /* NAND page program latency in nanoseconds */
    uint64_t blk_er_lat;        /* NAND block erase latency in nanoseconds */
    uint64_t zone_reset_lat;    /* ZNS SSD ZONE reset latency in nanoseconds */
    uint64_t ch_xfer_lat;       /* channel transfer latency for one page in nanoseconds*/
};
/**
 * @brief 
 * inhoinno: latency emulation with zns ssd, struct znsssd is needed
 * extends 'struct ssd' in ../bbssd/ftl.h:197 
 */
typedef struct zns {
    /*members from struct ssd*/
    char                *ssdname;
    struct zns_ssdparams    sp;
    struct zns_ssd_channel *ch;
    struct zns_ssd_lun *chips;

    /*new members for znsssd*/
    struct NvmeNamespace    * namespaces;      //FEMU only support 1 namespace For now, 
    struct NvmeZone      * zone_array;                  
    uint32_t            num_zones;

    QemuThread          zns_thread;


}ZNS;

typedef struct QEMU_PACKED NvmeZonedResult {
    uint64_t slba;
} NvmeZonedResult;

typedef struct NvmeIdCtrlZoned {
    uint8_t     zasl;           
    uint8_t     rsvd1[4095];   
} NvmeIdCtrlZoned;

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
    //for test, inhoinno
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
};
//NvmeZoneDescripstor
typedef struct QEMU_PACKED NvmeZoneDescr {
    uint8_t     zt;     //Zone Type(does sequential wirte required? NVME TP4053a section 2.3.1)
    uint8_t     zs;     //Zone State 
    uint8_t     za;
    uint8_t     rsvd3[5];
    uint64_t    zcap;
    uint64_t    zslba;  //Zone Start Logical Block Address
    uint64_t    wp;     //Write pointer
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


//get_zone(Namespace, req)
//get_ch(Zone, req)

void znsssd_init(FemuCtrl * n);
static int zns_advance_status(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd, NvmeRequest *req);

#endif
