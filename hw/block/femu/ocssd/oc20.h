#ifndef __FEMU_OC20_H
#define __FEMU_OC20_H

#include "../nvme.h"

#define OC20_VID            (0x1d1d)
#define OC20_DID            (0x1f1f)
#define OC20_MAGIC          ('L' << 24 | 'N' << 16 | 'V' << 8 | 'M')
#define OC20_CMD_MAX_LBAS   (64)

#define OC20_NS_LOGPAGE_CHUNK_INFO_BLK_OFFSET(ns)                             \
    ((ns)->blk.begin + sizeof(Oc20NamespaceGeometry))

#define OC20_LBA_GET_SECTR(lbaf, lba) \
    ((lba & (lbaf)->sec_mask) \
        >> (lbaf)->sec_offset)

#define OC20_LBA_GET_CHUNK(lbaf, lba) \
    ((lba & (lbaf)->chk_mask) \
        >> (lbaf)->chk_offset)

#define OC20_LBA_GET_PUNIT(lbaf, lba) \
    ((lba & (lbaf)->lun_mask) \
        >> (lbaf)->lun_offset)

#define OC20_LBA_GET_GROUP(lbaf, lba) \
    (lba >> (lbaf)->grp_offset)

#define OC20_LBA(lbaf, group, punit, chunk, sectr) \
    (sectr << (lbaf)->sec_offset \
        | chunk << (lbaf)->chk_offset \
        | punit << (lbaf)->lun_offset \
        | group << (lbaf)->grp_offset)

#define OC20_GROUP_FROM_CHUNK_INDEX(lns, idx)                             \
    (idx / (lns)->chks_per_grp)

#define OC20_PUNIT_FROM_CHUNK_INDEX(lns, idx)                             \
    (idx % (lns)->chks_per_grp / (lns)->chks_per_lun)

#define OC20_CHUNK_FROM_CHUNK_INDEX(lns, idx)                             \
    (idx % (lns)->chks_per_lun)

#define OC20_LBA_FROM_CHUNK_INDEX(lns, idx)                               \
    (OC20_GROUP_FROM_CHUNK_INDEX(lns, idx)                                \
        << (lns)->lbaf.grp_offset                                              \
        | OC20_PUNIT_FROM_CHUNK_INDEX(lns, idx)                           \
            << (lns)->lbaf.lun_offset                                          \
        | OC20_CHUNK_FROM_CHUNK_INDEX(lns, idx)                           \
            << (lns)->lbaf.chk_offset)

#define OC20_LBA_FORMAT_TEMPLATE \
    "lba 0xffffffffffffffff pugrp 255 punit 255 chunk 65535 sectr 4294967295"

#define OC20_CHUNK_RESETABLE \
    (OC20_CHUNK_FREE | OC20_CHUNK_CLOSED | OC20_CHUNK_OPEN)

enum Oc20IoCommands {
    OC20_CMD_VECT_ERASE = 0x90,
    OC20_CMD_VECT_WRITE = 0x91,
    OC20_CMD_VECT_READ  = 0x92,
};

enum Oc20MetaStates {
    OC20_SEC_UNKNOWN = 0x0,
    OC20_SEC_WRITTEN = 0xAC,
    OC20_SEC_ERASED  = 0xDC,
};

enum Oc20ChunkStates {
    OC20_CHUNK_FREE    = 1 << 0,
    OC20_CHUNK_CLOSED  = 1 << 1,
    OC20_CHUNK_OPEN    = 1 << 2,
    OC20_CHUNK_OFFLINE = 1 << 3,
};

enum Oc20ChunkTypes {
    OC20_CHUNK_TYPE_SEQ = 1 << 0,
    OC20_CHUNK_TYPE_RAN = 1 << 1,
    OC20_CHUNK_TYPE_SRK = 1 << 4,
};

enum Oc20StatusCodes {
    OC20_LBAL_SGL_LENGTH_INVALID = 0x01c1,
    OC20_WRITE_NEXT_UNIT         = 0x02f0,
    OC20_CHUNK_EARLY_CLOSE       = 0x02f1,
    OC20_OUT_OF_ORDER_WRITE      = 0x02f2,
    OC20_OFFLINE_CHUNK           = 0x02c0,
    OC20_INVALID_RESET           = 0x02c1,
};

typedef struct Oc20ChunkState {
    uint8_t state;
    uint8_t type;
    uint8_t wear_index;
    uint8_t rsvd[5];
    uint64_t slba;
    uint64_t cnlb;
    uint64_t wp;
} Oc20CS;

typedef struct Oc20RwCmd {
    uint16_t    opcode :  8;
    uint16_t    fuse   :  2;
    uint16_t    rsvd1  :  4;
    uint16_t    psdt   :  2;
    uint16_t    cid;
    uint32_t    nsid;
    uint64_t    rsvd2;
    uint64_t    metadata;
    NvmeCmdDptr dptr;
    uint64_t    lbal;
    uint16_t    nlb;
    uint16_t    control;
    uint32_t    rsvd3;
    uint64_t    rsvd4;
} Oc20RwCmd;

typedef struct Oc20DmCmd {
    uint8_t  opcode;
    uint8_t  flags;
    uint16_t cid;
    uint32_t nsid;
    uint32_t rsvd1[8];
    uint64_t spba;
    uint32_t nlb;
    uint32_t rsvd2[3];
} Oc20DmCmd;

typedef struct Oc20AddrF {
    uint64_t grp_mask;
    uint64_t lun_mask;
    uint64_t chk_mask;
    uint64_t sec_mask;
    uint8_t  grp_offset;
    uint8_t  lun_offset;
    uint8_t  chk_offset;
    uint8_t  sec_offset;
} Oc20AddrF;

typedef struct Oc20IdGeo {
    uint16_t num_grp;
    uint16_t num_lun;
    uint32_t num_chk;
    uint32_t clba;
    uint8_t  rsvd[52];
} Oc20IdGeo;

typedef struct Oc20IdWrt {
    uint32_t ws_min;
    uint32_t ws_opt;
    uint32_t mw_cunits;
    uint32_t max_open_chks;
    uint32_t max_open_punits;
    uint8_t  rsvd[44];
} Oc20IdWrt;

typedef struct Oc20IdPerf {
    uint32_t trdt;
    uint32_t trdm;
    uint32_t tprt;
    uint32_t tprm;
    uint32_t tbet;
    uint32_t tbem;
    uint8_t  rsvd[40];
} Oc20IdPerf;

typedef struct Oc20IdLBAF {
    uint8_t grp_len;
    uint8_t lun_len;
    uint8_t chk_len;
    uint8_t sec_len;
    uint8_t rsvd[4];
} Oc20IdLBAF;

typedef struct Oc20Header {
    uint32_t magic;
    uint32_t version;
    uint32_t num_namespaces;
    uint32_t rsvd;
    uint64_t sector_size;
    uint32_t md_size;
    uint64_t ns_size;
} Oc20Header;

typedef struct Oc20NamespaceGeometry {
    struct {
        uint8_t major;
        uint8_t minor;
    } ver;
    uint8_t    rsvd1[6];
    Oc20IdLBAF lbaf;
    uint32_t   mccap;
    uint8_t    rsvd2[12];
    uint8_t    wit;
    uint8_t    rsvd3[31];
    Oc20IdGeo  geo;
    Oc20IdWrt  wrt;
    Oc20IdPerf perf;
    uint8_t    rsvd4[3840];
} Oc20NamespaceGeometry;

enum Oc20ParamsMccap {
    OC20_PARAMS_MCCAP_MULTIPLE_RESETS = 0x1 << 1,
    /* OCSSD 2.0 spec de-facto extension */
    OC20_PARAMS_MCCAP_EARLY_RESET = 0x1 << 2,
};

enum Oc20LogPage {
    OC20_CHUNK_INFO = 0xCA,
};

typedef struct Oc20Ctrl {
    Oc20Header blk_hdr;
} Oc20Ctrl;

typedef struct Oc20Namespace {
    Oc20NamespaceGeometry id_ctrl;
    Oc20AddrF  lbaf;

    /* reset and write fail error probabilities indexed by namespace */
    uint8_t *resetfail;
    uint8_t *writefail;

    /* derived values (for convenience) */
    uint32_t chks_per_grp;
    uint32_t chks_total;
    uint32_t secs_per_chk;
    uint32_t secs_per_lun;
    uint32_t secs_per_grp;
    uint32_t secs_total;

    /* chunk info log page */
    uint64_t chunkinfo_size;
    Oc20CS *chunk_info;
} Oc20Namespace;

typedef struct Oc20AddrBucket {
    int  ch;
    int  lun;
    int  pg;
    uint8_t page_type;
    int  cnt;
} Oc20AddrBucket;

typedef struct NvmeRequest NvmeRequest;
typedef struct FemuCtrl FemuCtrl;

static inline void _oc20_check_size(void)
{
    QEMU_BUILD_BUG_ON(sizeof(Oc20IdLBAF) != 8);
    QEMU_BUILD_BUG_ON(sizeof(Oc20IdGeo)  != 64);
    QEMU_BUILD_BUG_ON(sizeof(Oc20IdWrt)  != 64);
    QEMU_BUILD_BUG_ON(sizeof(Oc20IdPerf) != 64);
    QEMU_BUILD_BUG_ON(sizeof(Oc20RwCmd)  != 64);
    QEMU_BUILD_BUG_ON(sizeof(Oc20DmCmd)  != 64);
    QEMU_BUILD_BUG_ON(sizeof(Oc20NamespaceGeometry) != 4096);
    QEMU_BUILD_BUG_ON(sizeof(Oc20CS)     != 32);
}

static inline int nvme_rw_is_write(NvmeRequest *req)
{
    return req->cmd_opcode == NVME_CMD_WRITE;
}

static inline int oc20_rw_is_write(NvmeRequest *req)
{
    return nvme_rw_is_write(req) || req->cmd_opcode == OC20_CMD_VECT_WRITE;
}

static inline uint64_t nvme_lba_to_sector_index(FemuCtrl *n, NvmeNamespace *ns,
                                                uint64_t lba)
{
    return lba;
}

static inline int oc20_lba_valid(FemuCtrl *n, NvmeNamespace *ns, uint64_t lba)
{
    Oc20Namespace *lns = ns->state;
    Oc20IdGeo *geo = &lns->id_ctrl.geo;
    Oc20AddrF *addrf = &lns->lbaf;

    return (OC20_LBA_GET_SECTR(addrf, lba) < geo->clba &&
            OC20_LBA_GET_CHUNK(addrf, lba) < geo->num_chk &&
            OC20_LBA_GET_PUNIT(addrf, lba) < geo->num_lun &&
            OC20_LBA_GET_GROUP(addrf, lba) < geo->num_grp);
}

static inline uint64_t oc20_lba_to_chunk_index(FemuCtrl *n, NvmeNamespace *ns,
                                               uint64_t lba)
{
    Oc20Namespace *lns = ns->state;
    Oc20IdGeo *geo = &lns->id_ctrl.geo;
    Oc20AddrF *addrf = &lns->lbaf;

    return (OC20_LBA_GET_CHUNK(addrf, lba) +
            OC20_LBA_GET_PUNIT(addrf, lba) * geo->num_chk +
            OC20_LBA_GET_GROUP(addrf, lba) * lns->chks_per_grp);
}

static inline uint64_t oc20_lba_to_sector_index(FemuCtrl *n, NvmeNamespace *ns,
                                                uint64_t lba)
{
    Oc20Namespace *lns = ns->state;
    Oc20AddrF *addrf = &lns->lbaf;

    return (OC20_LBA_GET_SECTR(addrf, lba) +
            OC20_LBA_GET_CHUNK(addrf, lba) * lns->secs_per_chk +
            OC20_LBA_GET_PUNIT(addrf, lba) * lns->secs_per_lun +
            OC20_LBA_GET_GROUP(addrf, lba) * lns->secs_per_grp);
}

#endif
