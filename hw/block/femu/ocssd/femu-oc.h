#ifndef __FEMU_OC
#define __FEMU_OC

enum FEMU_OC_AdminCommands {
    FEMU_OC_ADM_CMD_IDENTITY          = 0xe2,
    FEMU_OC_ADM_CMD_GET_L2P_TBL       = 0xea,
    FEMU_OC_ADM_CMD_GET_BB_TBL        = 0xf2,
    FEMU_OC_ADM_CMD_SET_BB_TBL        = 0xf1,
};

enum FEMU_OC_DmCommands {
    FEMU_OC_CMD_HYBRID_WRITE      = 0x81,
    FEMU_OC_CMD_HYBRID_READ       = 0x02,
    FEMU_OC_CMD_PHYS_WRITE        = 0x91,
    FEMU_OC_CMD_PHYS_READ         = 0x92,
    FEMU_OC_CMD_ERASE_ASYNC       = 0x90,
};

enum FEMU_OC_MetaState {
    FEMU_OC_SEC_UNKNOWN = 0x0,
    FEMU_OC_SEC_WRITTEN = 0xAC,
    FEMU_OC_SEC_ERASED  = 0xDC,
};

typedef struct FEMU_OC_GetL2PTbl {
    uint8_t opcode;
    uint8_t flags;
    uint16_t cid;
    uint32_t nsid;
    uint32_t rsvd1[4];
    uint64_t prp1;
    uint64_t prp2;
    uint64_t slba;
    uint32_t nlb;
    uint16_t rsvd2[6];
} FEMU_OC_GetL2PTbl;

typedef struct FEMU_OC_BbtGet {
  uint8_t opcode;
  uint8_t flags;
  uint16_t cid;
  uint32_t nsid;
  uint64_t rsvd1[2];
  uint64_t prp1;
  uint64_t prp2;
  uint64_t spba;
  uint32_t rsvd4[4]; // DW15, 14, 13, 12
} FEMU_OC_BbtGet;

typedef struct FEMU_OC_BbtSet {
  uint8_t opcode;
  uint8_t flags;
  uint16_t cid;
  uint32_t nsid;
  uint64_t rsvd1[2];
  uint64_t prp1;
  uint64_t prp2;
  uint64_t spba;
  uint16_t nlb;
  uint8_t value;
  uint8_t rsvd3;
  uint32_t rsvd4[3];
} FEMU_OC_BbtSet;

typedef struct FEMU_OC_RwCmd {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    nsid;
    uint64_t    rsvd2;
    uint64_t    metadata;
    uint64_t    prp1;
    uint64_t    prp2;
    uint64_t    spba;
    uint16_t    nlb;
    uint16_t    control;
    uint32_t    dsmgmt;
    uint64_t    slba;
} FEMU_OC_RwCmd;

typedef struct FEMU_OC_DmCmd {
  uint8_t opcode;
  uint8_t flags;
  uint16_t cid;
  uint32_t nsid;
  uint32_t rsvd1[8];
  uint64_t spba;
  uint32_t nlb;
  uint32_t rsvd2[3];
} FEMU_OC_DmCmd;

typedef struct FEMU_OC_IdAddrFormat {
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
} QEMU_PACKED FEMU_OC_IdAddrFormat;

typedef struct FEMU_OC_AddrF {
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
} FEMU_OC_AddrF;

typedef struct FEMU_OC_IdGroup {
    uint8_t    mtype;
    uint8_t    fmtype;
    uint16_t   res16;
    uint8_t    num_ch;
    uint8_t    num_lun;
    uint8_t    num_pln;
    uint8_t    rsvd1;
    uint16_t   num_blk;
    uint16_t   num_pg;
    uint16_t   fpg_sz;
    uint16_t   csecs;
    uint16_t   sos;
    uint16_t   rsvd2;
    uint32_t   trdt;
    uint32_t   trdm;
    uint32_t   tprt;
    uint32_t   tprm;
    uint32_t   tbet;
    uint32_t   tbem;
    uint32_t   mpos;
    uint32_t   mccap;
    uint16_t   cpar;
    uint8_t    res[906];
} QEMU_PACKED FEMU_OC_IdGroup;

typedef struct FEMU_OC_IdCtrl {
    uint8_t       ver_id;
    uint8_t       vmnt;
    uint8_t       cgrps;
    uint8_t       res;
    uint32_t      cap;
    uint32_t      dom;
    struct FEMU_OC_IdAddrFormat ppaf;
    uint8_t       resv[228];
    FEMU_OC_IdGroup   groups[4];
} QEMU_PACKED FEMU_OC_IdCtrl;

typedef struct FEMU_OC_Bbt {
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
} QEMU_PACKED FEMU_OC_Bbt;

/* Parameters passed on to QEMU to configure the characteristics of the drive */
typedef struct FEMU_OC_Params {
    /* configurable device characteristics */
    uint16_t    pgs_per_blk;
    uint16_t    sec_size;
    uint8_t     sec_per_pg;
    uint8_t     max_sec_per_rq;
    /* configurable parameters for FEMU_OC_IdGroup */
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
    /* Calculated unit values for ordering */
    uint32_t    pl_units;
    uint32_t    pg_units;
    uint32_t    blk_units;
    uint32_t    lun_units;
    uint32_t    ch_units;
    uint32_t    total_units;
} QEMU_PACKED FEMU_OC_Params;

enum FEMU_OC_Pmode {
    FEMU_OC_PMODE_SNGL = 0x0,      ///< Single-plane
    FEMU_OC_PMODE_DUAL = 0x1,      ///< Dual-plane (NVM_IO_DUAL_ACCESS)
    FEMU_OC_PMODE_QUAD = 0x2       ///< Quad-plane (NVM_IO_QUAD_ACCESS)
};

enum FEMU_OC_Responsibility {
    FEMU_OC_RSP_L2P       = 1 << 0,
    FEMU_OC_RSP_ECC       = 1 << 1,
};

typedef struct FEMU_OC_Ctrl {
    FEMU_OC_Params     params;
    FEMU_OC_IdCtrl     id_ctrl;
    FEMU_OC_AddrF      ppaf;
    uint8_t        read_l2p_tbl;
    uint8_t        bbt_gen_freq;
    uint8_t        bbt_auto_gen;
    uint8_t        meta_auto_gen;
    uint8_t        debug;
    uint8_t        strict;
    char           *bbt_fname;
    char           *meta_fname;
    FILE           *bbt_fp;
    uint32_t       err_write;
    uint32_t       n_err_write;
    uint32_t       err_write_cnt;
    FILE           *metadata;
    uint8_t        *meta_buf;
    int            meta_tbytes;
    int            meta_len;
    uint8_t        int_meta_size;       // # of bytes for "internal" metadata
} FEMU_OC_Ctrl;

struct femu_oc_metadata_format {
    uint32_t state;
    uint64_t rsv[2];
} __attribute__((__packed__));

struct femu_oc_tgt_meta {
    uint64_t lba;
    uint64_t rsvd;
} __attribute__((__packed__));

#define FEMU_OC_MAX_GRPS_PR_IDENT (20)
#define FEMU_OC_FEAT_EXT_START 64
#define FEMU_OC_FEAT_EXT_END 127
#define FEMU_OC_PBA_UNMAPPED UINT64_MAX
#define FEMU_OC_LBA_UNMAPPED UINT64_MAX

void femu_oc_check_size(void);


#endif
