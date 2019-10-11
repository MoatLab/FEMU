/*
 * QEMU OpenChannel 2.0 Controller
 *
 * Copyright (c) 2019 CNEX Labs, Inc.
 *
 * Thank you to the following people for their contributions to the original
 * qemu-nvme (github.com/OpenChannelSSD/qemu-nvme) implementation.
 *
 *   Matias Bjørling <mb@lightnvm.io>
 *   Javier González <javier@javigon.com>
 *   Simon Andreas Frimann Lund <ocssd@safl.dk>
 *   Hans Holmberg <hans@owltronix.com>
 *   Jesper Devantier <contact@pseudonymous.me>
 *   Young Tack Jin <youngtack.jin@circuitblvd.com>
 *
 * This code is licensed under the GNU GPL v2 or later.
 */

#ifndef BLOCK_OCSSD_H
#define BLOCK_OCSSD_H

#include "block/nvme.h"

#define OCSSD_MAGIC ('O' << 24 | 'C' << 16 | '2' << 8 | '0')

enum OcssdAdminCommands {
    OCSSD_ADM_CMD_GEOMETRY = 0xe2,
};

enum OcssdIoCommands {
    OCSSD_CMD_VECT_RESET = 0x90,
    OCSSD_CMD_VECT_WRITE = 0x91,
    OCSSD_CMD_VECT_READ  = 0x92,
    OCSSD_CMD_VECT_COPY  = 0x93,
};

typedef enum OcssdChunkState {
    OCSSD_CHUNK_FREE    = 1 << 0,
    OCSSD_CHUNK_CLOSED  = 1 << 1,
    OCSSD_CHUNK_OPEN    = 1 << 2,
    OCSSD_CHUNK_OFFLINE = 1 << 3,
} OcssdChunkState;

#define OCSSD_CHUNK_RESETABLE \
    (OCSSD_CHUNK_FREE | OCSSD_CHUNK_CLOSED | OCSSD_CHUNK_OPEN)

typedef enum OcssdChunkType {
    OCSSD_CHUNK_TYPE_SEQUENTIAL = 1 << 0,
    OCSSD_CHUNK_TYPE_RANDOM     = 1 << 1,
    OCSSD_CHUNK_TYPE_SHRINKED   = 1 << 4,
} OcssdChunkType;

enum OcssdStatusCodes {
    OCSSD_LBAL_SGL_LENGTH_INVALID = 0x01c1,

    OCSSD_WRITE_NEXT_UNIT         = 0x02f0,
    OCSSD_CHUNK_EARLY_CLOSE       = 0x02f1,
    OCSSD_OUT_OF_ORDER_WRITE      = 0x02f2,
    OCSSD_OFFLINE_CHUNK           = 0x02c0,
    OCSSD_INVALID_RESET           = 0x02c1,
};

typedef struct OcssdFeatureVal {
    uint32_t media_feedback;
} OcssdFeatureVal;

#define OCSSD_MEDIA_FEEDBACK_VHECC(media_feedback) (media_feedback & 0x2)
#define OCSSD_MEDIA_FEEDBACK_HECC(media_feedback)  (media_feedback & 0x1)

enum OcssdFeatureIds {
    OCSSD_MEDIA_FEEDBACK = 0xca,
};

typedef struct OcssdChunkDescriptor {
    uint8_t  state;
    uint8_t  type;
    uint8_t  wear_index;
    uint8_t  rsvd7[5];
    uint64_t slba;
    uint64_t cnlb;
    uint64_t wp;
} OcssdChunkDescriptor;

enum OcssdChunkNotificationState {
    OCSSD_CHUNK_NOTIFICATION_STATE_LOW       = 1 << 0,
    OCSSD_CHUNK_NOTIFICATION_STATE_MID       = 1 << 1,
    OCSSD_CHUNK_NOTIFICATION_STATE_HIGH      = 1 << 2,
    OCSSD_CHUNK_NOTIFICATION_STATE_UNREC     = 1 << 3,
    OCSSD_CHUNK_NOTIFICATION_STATE_REFRESHED = 1 << 4,
    OCSSD_CHUNK_NOTIFICATION_STATE_WLI       = 1 << 8
};

enum OcssdChunkNotificationMask {
    OCSSD_CHUNK_NOTIFICATION_MASK_SECTOR = 1 << 0,
    OCSSD_CHUNK_NOTIFICATION_MASK_CHUNK  = 1 << 1,
    OCSSD_CHUNK_NOTIFICATION_MASK_PUNIT  = 1 << 2
};

typedef struct OcssdChunkNotification {
    uint64_t    nc;
    uint64_t    lba;
    uint32_t    nsid;
    uint16_t    state;
    uint8_t     mask;
    uint8_t     rsvd31[9];
    uint16_t    nlb;
    uint8_t     rsvd63[30];
} OcssdChunkNotification;

typedef struct OcssdRwCmd {
    uint8_t     opcode;
    uint8_t     flags;
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
} OcssdRwCmd;

typedef struct OcssdCopyCmd {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    nsid;
    uint64_t    rsvd2;
    uint64_t    metadata;
    NvmeCmdDptr dptr;
    uint64_t    lbal;
    uint16_t    nlb;
    uint16_t    control;
    uint32_t    rsvd3;
    uint64_t    dlbal;
} OcssdCopyCmd;

typedef struct OcssdIdGeo {
    uint16_t num_grp;
    uint16_t num_pu;
    uint32_t num_chk;
    uint32_t clba;
    uint8_t  rsvd63[52];
} OcssdIdGeo;

typedef struct OcssdIdWrt {
    uint32_t ws_min;
    uint32_t ws_opt;
    uint32_t mw_cunits;
    uint8_t  rsvd63[52];
} OcssdIdWrt;

typedef struct OcssdIdPerf {
    uint32_t trdt;
    uint32_t trdm;
    uint32_t tprt;
    uint32_t tprm;
    uint32_t tbet;
    uint32_t tbem;
    uint8_t  rsvd63[40];
} OcssdIdPerf;

typedef struct OcssdIdLBAF {
    uint8_t grp_len;
    uint8_t pu_len;
    uint8_t chk_len;
    uint8_t sec_len;
    uint8_t rsvd7[4];
} OcssdIdLBAF;

typedef struct OcssdFormatHeader {
    uint32_t    magic;
    uint32_t    version;
    uint32_t    rsvd7;
    uint32_t    md_size;
    uint64_t    sector_size;
    uint64_t    ns_size;
    uint32_t    pe_cycles;
    OcssdIdLBAF lbaf;
    uint8_t     rsvd4095[4052];
} OcssdFormatHeader;

typedef struct OcssdIdentity {
    struct {
        uint8_t major;
        uint8_t minor;
    } ver;
    uint8_t     rsvd1[6];
    OcssdIdLBAF lbaf;
    uint32_t    mccap;
    uint8_t     rsvd2[12];
    uint8_t     wit;
    uint8_t     rsvd3[31];
    OcssdIdGeo  geo;
    OcssdIdWrt  wrt;
    OcssdIdPerf perf;
    uint8_t     rsvd4[3840];
} OcssdIdentity;

enum OcssdIdentityMccap {
    OCSSD_IDENTITY_MCCAP_MULTIPLE_RESETS = 0x1 << 1,

    /* OCSSD 2.0 spec de-facto extension */
    OCSSD_IDENTITY_MCCAP_EARLY_RESET = 0x1 << 2,
};

enum OcssdLogPage {
    OCSSD_CHUNK_INFO         = 0xCA,
    OCSSD_CHUNK_NOTIFICATION = 0xD0,
};

static inline void _ocssd_check_sizes(void)
{
    QEMU_BUILD_BUG_ON(sizeof(OcssdIdLBAF)            != 8);
    QEMU_BUILD_BUG_ON(sizeof(OcssdIdGeo)             != 64);
    QEMU_BUILD_BUG_ON(sizeof(OcssdIdWrt)             != 64);
    QEMU_BUILD_BUG_ON(sizeof(OcssdIdPerf)            != 64);
    QEMU_BUILD_BUG_ON(sizeof(OcssdRwCmd)             != 64);
    QEMU_BUILD_BUG_ON(sizeof(OcssdIdentity)          != 4096);
    QEMU_BUILD_BUG_ON(sizeof(OcssdChunkDescriptor)   != 32);
    QEMU_BUILD_BUG_ON(sizeof(OcssdChunkNotification) != 64);
    QEMU_BUILD_BUG_ON(sizeof(OcssdFormatHeader)      != 4096);
}

#endif
