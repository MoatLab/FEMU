#ifndef __FEMU_OC12_H
#define __FEMU_OC12_H

#include "../nvme.h"

enum Oc12AdminCommands {
    OC12_ADM_CMD_IDENTITY    = 0xe2,
    OC12_ADM_CMD_GET_L2P_TBL = 0xea,
    OC12_ADM_CMD_GET_BB_TBL  = 0xf2,
    OC12_ADM_CMD_SET_BB_TBL  = 0xf1,
};

enum Oc12DmCommands {
    OC12_CMD_WRITE = 0x91,
    OC12_CMD_READ  = 0x92,
    OC12_CMD_ERASE = 0x90,
};

enum Oc12MetaState {
    OC12_SEC_UNKNOWN = 0x0,
    OC12_SEC_WRITTEN = 0xAC,
    OC12_SEC_ERASED  = 0xDC,
};

typedef struct Oc12GetL2PTbl {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    nsid;
    uint32_t    rsvd1[4];
    uint64_t    prp1;
    uint64_t    prp2;
    uint64_t    slba;
    uint32_t    nlb;
    uint16_t    rsvd2[6];
} Oc12GetL2PTbl;

typedef struct Oc12BbtGet {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    nsid;
    uint64_t    rsvd1[2];
    uint64_t    prp1;
    uint64_t    prp2;
    uint64_t    spba;
    uint32_t    rsvd4[4]; // DW15, 14, 13, 12
} Oc12BbtGet;

typedef struct Oc12BbtSet {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    nsid;
    uint64_t    rsvd1[2];
    uint64_t    prp1;
    uint64_t    prp2;
    uint64_t    spba;
    uint16_t    nlb;
    uint8_t     value;
    uint8_t     rsvd3;
    uint32_t    rsvd4[3];
} Oc12BbtSet;

typedef struct Oc12RwCmd {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    nsid;
    uint64_t    rsvd2;
    uint64_t    metadata; /* OOB */
    uint64_t    prp1;
    uint64_t    prp2;
    uint64_t    spba;     /* PPA list */
    uint16_t    nlb;
    uint16_t    control;  /* For Suspend, SLC mode, Scramble, FUA, LR control */
    uint32_t    dsmgmt;
    uint64_t    slba;     /* ! this is actually not used by OC12 */
} Oc12RwCmd;

typedef struct Oc12DmCmd {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    nsid;
    uint32_t    rsvd1[8];
    uint64_t    spba;
    uint32_t    nlb;
    uint32_t    rsvd2[3];
} Oc12DmCmd;

typedef struct Oc12IdAddrFormat {
    uint8_t     ch_offset;
    uint8_t     ch_len;
    uint8_t     lun_offset;
    uint8_t     lun_len;
    uint8_t     pln_offset;
    uint8_t     pln_len;
    uint8_t     blk_offset;
    uint8_t     blk_len;
    uint8_t     pg_offset;
    uint8_t     pg_len;
    uint8_t     sect_offset;
    uint8_t     sect_len;
    uint8_t     res[4];
} QEMU_PACKED Oc12IdAddrFormat;

typedef struct Oc12AddrF {
	uint64_t	ch_mask;
	uint64_t	lun_mask;
	uint64_t	pln_mask;
	uint64_t	blk_mask;
	uint64_t	pg_mask;
	uint64_t	sec_mask;
	uint8_t     ch_offset;
	uint8_t     lun_offset;
	uint8_t     pln_offset;
	uint8_t     blk_offset;
	uint8_t	    pg_offset;
	uint8_t	    sec_offset;
} Oc12AddrF;

typedef struct Oc12IdGroup {
    uint8_t     mtype;
    uint8_t     fmtype;
    uint16_t    res16;
    uint8_t     num_ch;
    uint8_t     num_lun;
    uint8_t     num_pln;
    uint8_t     rsvd1;
    uint16_t    num_blk;
    uint16_t    num_pg;
    uint16_t    fpg_sz;
    uint16_t    csecs;
    uint16_t    sos;
    uint16_t    rsvd2;
    uint32_t    trdt;
    uint32_t    trdm;
    uint32_t    tprt;
    uint32_t    tprm;
    uint32_t    tbet;
    uint32_t    tbem;
    uint32_t    mpos;
    uint32_t    mccap;
    uint16_t    cpar;
    uint8_t     res[906];
} QEMU_PACKED Oc12IdGroup;

typedef struct Oc12IdCtrl {
    uint8_t     ver_id;
    uint8_t     vmnt;
    uint8_t     cgrps;
    uint8_t     res;
    uint32_t    cap;
    uint32_t    dom;
    struct Oc12IdAddrFormat ppaf;
    uint8_t     resv[228];
    Oc12IdGroup groups[4];
} QEMU_PACKED Oc12IdCtrl;

typedef struct Oc12Bbt {
    uint8_t     tblid[4];
    uint16_t    verid;
    uint16_t    revid;
    uint32_t    rsvd1;
    uint32_t    tblks;
    uint32_t    tfact;
    uint32_t    tgrown;
    uint32_t    tdresv;
    uint32_t    thresv;
    uint32_t    rsvd2[8];
    uint8_t     blk[0];
} QEMU_PACKED Oc12Bbt;

/* Parameters passed on to QEMU to configure the characteristics of the drive */
typedef struct Oc12Params {
    /* configurable device characteristics */
    uint16_t    pgs_per_blk;
    uint16_t    sec_size;
    uint8_t     sec_per_pg;
    uint8_t     max_sec_per_rq;
    /* configurable parameters for Oc12IdGroup */
    uint8_t     mtype;
    uint8_t     fmtype;
    uint8_t     num_ch;
    uint8_t     num_pln;
    uint8_t     num_lun;
    uint16_t    sos;
    /* calculated values */
    uint32_t    sec_per_pl;
    uint32_t    sec_per_blk;
    uint32_t    sec_per_lun;
    uint32_t    sec_per_ch;
    uint32_t    total_secs;
    uint32_t    blk_per_pl;
    /* Calculated unit values for ordering */
    uint32_t    pl_units;
    uint32_t    pg_units;
    uint32_t    blk_units;
    uint32_t    lun_units;
    uint32_t    ch_units;
    uint32_t    total_units;
} QEMU_PACKED Oc12Params;

enum Oc12Pmode {
    Oc12PMODE_SNGL = 0x0,      ///< Single-plane
    Oc12PMODE_DUAL = 0x1,      ///< Dual-plane (NVM_IO_DUAL_ACCESS)
    Oc12PMODE_QUAD = 0x2       ///< Quad-plane (NVM_IO_QUAD_ACCESS)
};

enum Oc12Responsibility {
    Oc12RSP_L2P = 1 << 0,
    Oc12RSP_ECC = 1 << 1,
};

typedef struct Oc12Ctrl {
    Oc12Params  params;
    Oc12IdCtrl  id_ctrl;
    Oc12AddrF   ppaf;
    uint8_t     read_l2p_tbl;
    uint8_t     bbt_gen_freq;
    uint8_t     bbt_auto_gen;
    uint8_t     meta_auto_gen;
    uint8_t     debug;
    uint8_t     strict;
    uint8_t     *meta_buf;
    int         meta_tbytes;
    int         meta_len;
    uint8_t     int_meta_size;       // # of bytes for "internal" metadata
} Oc12Ctrl;

struct oc12_metadata_format {
    uint32_t state;
    uint64_t rsv[2];
} __attribute__((__packed__));

struct oc12_tgt_meta {
    uint64_t lba;
    uint64_t rsvd;
} __attribute__((__packed__));

typedef struct AddrBucket {
    int  ch;
    int  lun;
    int  pg;
    uint8_t  page_type;
    int  cnt;
} AddrBucket;

#define OC12_MAX_GRPS_PR_IDENT (20)
#define OC12_FEAT_EXT_START 64
#define OC12_FEAT_EXT_END 127
#define OC12_PBA_UNMAPPED UINT64_MAX
#define OC12_LBA_UNMAPPED UINT64_MAX

static inline void oc12_check_size(void)
{
    QEMU_BUILD_BUG_ON(sizeof(Oc12GetL2PTbl) != 64);
    QEMU_BUILD_BUG_ON(sizeof(Oc12BbtGet) != 64);
    QEMU_BUILD_BUG_ON(sizeof(Oc12BbtSet) != 64);
    QEMU_BUILD_BUG_ON(sizeof(Oc12RwCmd) != 64);
    QEMU_BUILD_BUG_ON(sizeof(Oc12DmCmd) != 64);
    QEMU_BUILD_BUG_ON(sizeof(Oc12IdCtrl) != 4096);
    QEMU_BUILD_BUG_ON(sizeof(Oc12IdAddrFormat) != 16);
    QEMU_BUILD_BUG_ON(sizeof(Oc12IdGroup) != 960);
}

#endif
