#ifndef __FEMU_NVME_H
#define __FEMU_NVME_H

#include "qemu/cutils.h"
#include "qemu/bitops.h"
#include "hw/virtio/vhost.h"
#include "sysemu/hostmem.h"
#include "mem-backend.h"
#include "include/rte_ring.h"
#include "include/pqueue.h"

#include "ftl/ftl.h"

typedef struct NvmeBar {
    uint64_t    cap;
    uint32_t    vs;
    uint32_t    intms;
    uint32_t    intmc;
    uint32_t    cc;
    uint32_t    rsvd1;
    uint32_t    csts;
    uint32_t    nssrc;
    uint32_t    aqa;
    uint64_t    asq;
    uint64_t    acq;
    uint32_t    cmbloc;
    uint32_t    cmbsz;
} NvmeBar;

enum NvmeCapShift {
    CAP_MQES_SHIFT      = 0,
    CAP_CQR_SHIFT       = 16,
    CAP_AMS_SHIFT       = 17,
    CAP_TO_SHIFT        = 24,
    CAP_DSTRD_SHIFT     = 32,
    CAP_NSSRS_SHIFT     = 33,
    CAP_CSS_SHIFT       = 37,
    CAP_FEMU_OC12_SHIFT = 44,
    CAP_MPSMIN_SHIFT    = 48,
    CAP_MPSMAX_SHIFT    = 52,
};

enum NvmeCapMask {
    CAP_MQES_MASK      = 0xffff,
    CAP_CQR_MASK       = 0x1,
    CAP_AMS_MASK       = 0x3,
    CAP_TO_MASK        = 0xff,
    CAP_DSTRD_MASK     = 0xf,
    CAP_NSSRS_MASK     = 0x1,
    CAP_CSS_MASK       = 0xff,
    CAP_FEMU_OC12_MASK = 0x1,
    CAP_MPSMIN_MASK    = 0xf,
    CAP_MPSMAX_MASK    = 0xf,
};

#define NVME_MAX_QS PCI_MSIX_FLAGS_QSIZE
#define NVME_MAX_QUEUE_ENTRIES  0xffff
#define NVME_MAX_STRIDE         12
#define NVME_MAX_NUM_NAMESPACES 256
#define NVME_MAX_QUEUE_ES       0xf
#define NVME_MIN_CQUEUE_ES      0x4
#define NVME_MIN_SQUEUE_ES      0x6
#define NVME_SPARE_THRESHOLD    20
#define NVME_TEMPERATURE        0x143
#define NVME_OP_ABORTED         0xff

#define NVME_CAP_MQES(cap)  (((cap) >> CAP_MQES_SHIFT)   & CAP_MQES_MASK)
#define NVME_CAP_CQR(cap)   (((cap) >> CAP_CQR_SHIFT)    & CAP_CQR_MASK)
#define NVME_CAP_AMS(cap)   (((cap) >> CAP_AMS_SHIFT)    & CAP_AMS_MASK)
#define NVME_CAP_TO(cap)    (((cap) >> CAP_TO_SHIFT)     & CAP_TO_MASK)
#define NVME_CAP_DSTRD(cap) (((cap) >> CAP_DSTRD_SHIFT)  & CAP_DSTRD_MASK)
#define NVME_CAP_NSSRS(cap) (((cap) >> CAP_NSSRS_SHIFT)  & CAP_NSSRS_MASK)
#define NVME_CAP_CSS(cap)   (((cap) >> CAP_CSS_SHIFT)    & CAP_CSS_MASK)
#define NVME_CAP_FEMU_OC12(cap)  (((cap) >> CAP_FEMU_OC12_SHIFT) & CAP_FEMU_OC12_MASK)
#define NVME_CAP_MPSMIN(cap)(((cap) >> CAP_MPSMIN_SHIFT) & CAP_MPSMIN_MASK)
#define NVME_CAP_MPSMAX(cap)(((cap) >> CAP_MPSMAX_SHIFT) & CAP_MPSMAX_MASK)

#define NVME_CAP_SET_MQES(cap, val)   (cap |= (uint64_t)(val & CAP_MQES_MASK)  \
                                                           << CAP_MQES_SHIFT)
#define NVME_CAP_SET_CQR(cap, val)    (cap |= (uint64_t)(val & CAP_CQR_MASK)   \
                                                           << CAP_CQR_SHIFT)
#define NVME_CAP_SET_AMS(cap, val)    (cap |= (uint64_t)(val & CAP_AMS_MASK)   \
                                                           << CAP_AMS_SHIFT)
#define NVME_CAP_SET_TO(cap, val)     (cap |= (uint64_t)(val & CAP_TO_MASK)    \
                                                           << CAP_TO_SHIFT)
#define NVME_CAP_SET_DSTRD(cap, val)  (cap |= (uint64_t)(val & CAP_DSTRD_MASK) \
                                                           << CAP_DSTRD_SHIFT)
#define NVME_CAP_SET_NSSRS(cap, val)  (cap |= (uint64_t)(val & CAP_NSSRS_MASK) \
                                                           << CAP_NSSRS_SHIFT)
#define NVME_CAP_SET_CSS(cap, val)    (cap |= (uint64_t)(val & CAP_CSS_MASK)   \
                                                           << CAP_CSS_SHIFT)
#define NVME_CAP_SET_FEMU_OC12(cap, val)   (cap |= (uint64_t)(val & CAP_FEMU_OC12_MASK)\
                                                            << CAP_FEMU_OC12_SHIFT)
#define NVME_CAP_SET_MPSMIN(cap, val) (cap |= (uint64_t)(val & CAP_MPSMIN_MASK)\
                                                           << CAP_MPSMIN_SHIFT)
#define NVME_CAP_SET_MPSMAX(cap, val) (cap |= (uint64_t)(val & CAP_MPSMAX_MASK)\
                                                            << CAP_MPSMAX_SHIFT)

enum NvmeCcShift {
    CC_EN_SHIFT     = 0,
    CC_CSS_SHIFT    = 4,
    CC_MPS_SHIFT    = 7,
    CC_AMS_SHIFT    = 11,
    CC_SHN_SHIFT    = 14,
    CC_IOSQES_SHIFT = 16,
    CC_IOCQES_SHIFT = 20,
};

enum NvmeCcMask {
    CC_EN_MASK      = 0x1,
    CC_CSS_MASK     = 0x7,
    CC_MPS_MASK     = 0xf,
    CC_AMS_MASK     = 0x7,
    CC_SHN_MASK     = 0x3,
    CC_IOSQES_MASK  = 0xf,
    CC_IOCQES_MASK  = 0xf,
};

#define NVME_CC_EN(cc)     ((cc >> CC_EN_SHIFT)     & CC_EN_MASK)
#define NVME_CC_CSS(cc)    ((cc >> CC_CSS_SHIFT)    & CC_CSS_MASK)
#define NVME_CC_MPS(cc)    ((cc >> CC_MPS_SHIFT)    & CC_MPS_MASK)
#define NVME_CC_AMS(cc)    ((cc >> CC_AMS_SHIFT)    & CC_AMS_MASK)
#define NVME_CC_SHN(cc)    ((cc >> CC_SHN_SHIFT)    & CC_SHN_MASK)
#define NVME_CC_IOSQES(cc) ((cc >> CC_IOSQES_SHIFT) & CC_IOSQES_MASK)
#define NVME_CC_IOCQES(cc) ((cc >> CC_IOCQES_SHIFT) & CC_IOCQES_MASK)

enum NvmeCstsShift {
    CSTS_RDY_SHIFT      = 0,
    CSTS_CFS_SHIFT      = 1,
    CSTS_SHST_SHIFT     = 2,
    CSTS_NSSRO_SHIFT    = 4,
};

enum NvmeCstsMask {
    CSTS_RDY_MASK   = 0x1,
    CSTS_CFS_MASK   = 0x1,
    CSTS_SHST_MASK  = 0x3,
    CSTS_NSSRO_MASK = 0x1,
};

enum NvmeCsts {
    NVME_CSTS_READY         = 1 << CSTS_RDY_SHIFT,
    NVME_CSTS_FAILED        = 1 << CSTS_CFS_SHIFT,
    NVME_CSTS_SHST_NORMAL   = 0 << CSTS_SHST_SHIFT,
    NVME_CSTS_SHST_PROGRESS = 1 << CSTS_SHST_SHIFT,
    NVME_CSTS_SHST_COMPLETE = 2 << CSTS_SHST_SHIFT,
    NVME_CSTS_NSSRO         = 1 << CSTS_NSSRO_SHIFT,
};

#define NVME_CSTS_RDY(csts)     ((csts >> CSTS_RDY_SHIFT)   & CSTS_RDY_MASK)
#define NVME_CSTS_CFS(csts)     ((csts >> CSTS_CFS_SHIFT)   & CSTS_CFS_MASK)
#define NVME_CSTS_SHST(csts)    ((csts >> CSTS_SHST_SHIFT)  & CSTS_SHST_MASK)
#define NVME_CSTS_NSSRO(csts)   ((csts >> CSTS_NSSRO_SHIFT) & CSTS_NSSRO_MASK)

enum NvmeAqaShift {
    AQA_ASQS_SHIFT  = 0,
    AQA_ACQS_SHIFT  = 16,
};

enum NvmeAqaMask {
    AQA_ASQS_MASK   = 0xfff,
    AQA_ACQS_MASK   = 0xfff,
};

#define NVME_AQA_ASQS(aqa) ((aqa >> AQA_ASQS_SHIFT) & AQA_ASQS_MASK)
#define NVME_AQA_ACQS(aqa) ((aqa >> AQA_ACQS_SHIFT) & AQA_ACQS_MASK)

enum NvmeCmblocShift {
    CMBLOC_BIR_SHIFT  = 0,
    CMBLOC_OFST_SHIFT = 12,
};

enum NvmeCmblocMask {
    CMBLOC_BIR_MASK  = 0x7,
    CMBLOC_OFST_MASK = 0xfffff,
};

#define NVME_CMBLOC_BIR(cmbloc) ((cmbloc >> CMBLOC_BIR_SHIFT)  & CMBLOC_BIR_MASK)
#define NVME_CMBLOC_OFST(cmbloc)((cmbloc >> CMBLOC_OFST_SHIFT) & CMBLOC_OFST_MASK)

#define NVME_CMBLOC_SET_BIR(cmbloc, val)   (cmbloc |= (uint64_t)(val & CMBLOC_BIR_MASK)  \
                                                                   << CMBLOC_BIR_SHIFT)
#define NVME_CMBLOC_SET_OFST(cmbloc, val)  (cmbloc |= (uint64_t)(val & CMBLOC_OFST_MASK)  \
                                                                   << CMBLOC_OFST_SHIFT)
enum NvmeCmbszShift {
    CMBSZ_SQS_SHIFT   = 0,
    CMBSZ_CQS_SHIFT   = 1,
    CMBSZ_LISTS_SHIFT = 2,
    CMBSZ_RDS_SHIFT   = 3,
    CMBSZ_WDS_SHIFT   = 4,
    CMBSZ_SZU_SHIFT   = 8,
    CMBSZ_SZ_SHIFT    = 12,
};

enum NvmeCmbszMask {
    CMBSZ_SQS_MASK   = 0x1,
    CMBSZ_CQS_MASK   = 0x1,
    CMBSZ_LISTS_MASK = 0x1,
    CMBSZ_RDS_MASK   = 0x1,
    CMBSZ_WDS_MASK   = 0x1,
    CMBSZ_SZU_MASK   = 0xf,
    CMBSZ_SZ_MASK    = 0xfffff,
};

#define NVME_CMBSZ_SQS(cmbsz)  ((cmbsz >> CMBSZ_SQS_SHIFT)   & CMBSZ_SQS_MASK)
#define NVME_CMBSZ_CQS(cmbsz)  ((cmbsz >> CMBSZ_CQS_SHIFT)   & CMBSZ_CQS_MASK)
#define NVME_CMBSZ_LISTS(cmbsz)((cmbsz >> CMBSZ_LISTS_SHIFT) & CMBSZ_LISTS_MASK)
#define NVME_CMBSZ_RDS(cmbsz)  ((cmbsz >> CMBSZ_RDS_SHIFT)   & CMBSZ_RDS_MASK)
#define NVME_CMBSZ_WDS(cmbsz)  ((cmbsz >> CMBSZ_WDS_SHIFT)   & CMBSZ_WDS_MASK)
#define NVME_CMBSZ_SZU(cmbsz)  ((cmbsz >> CMBSZ_SZU_SHIFT)   & CMBSZ_SZU_MASK)
#define NVME_CMBSZ_SZ(cmbsz)   ((cmbsz >> CMBSZ_SZ_SHIFT)    & CMBSZ_SZ_MASK)

#define NVME_CMBSZ_SET_SQS(cmbsz, val)   (cmbsz |= (uint64_t)(val & CMBSZ_SQS_MASK)  \
                                                                << CMBSZ_SQS_SHIFT)
#define NVME_CMBSZ_SET_CQS(cmbsz, val)   (cmbsz |= (uint64_t)(val & CMBSZ_CQS_MASK)  \
                                                                 << CMBSZ_CQS_SHIFT)
#define NVME_CMBSZ_SET_LISTS(cmbsz, val) (cmbsz |= (uint64_t)(val & CMBSZ_LISTS_MASK)  \
                                                                << CMBSZ_LISTS_SHIFT)
#define NVME_CMBSZ_SET_RDS(cmbsz, val)   (cmbsz |= (uint64_t)(val & CMBSZ_RDS_MASK)  \
                                                                << CMBSZ_RDS_SHIFT)
#define NVME_CMBSZ_SET_WDS(cmbsz, val)   (cmbsz |= (uint64_t)(val & CMBSZ_WDS_MASK)  \
                                                                << CMBSZ_WDS_SHIFT)
#define NVME_CMBSZ_SET_SZU(cmbsz, val)   (cmbsz |= (uint64_t)(val & CMBSZ_SZU_MASK)  \
                                                                << CMBSZ_SZU_SHIFT)
#define NVME_CMBSZ_SET_SZ(cmbsz, val)    (cmbsz |= (uint64_t)(val & CMBSZ_SZ_MASK)  \
                                                                << CMBSZ_SZ_SHIFT)

#define NVME_CMBSZ_GETSIZE(cmbsz) (NVME_CMBSZ_SZ(cmbsz) * (1<<(12+4*NVME_CMBSZ_SZU(cmbsz))))

typedef struct NvmeCmd {
    uint8_t     opcode;
    uint8_t     fuse;
    uint16_t    cid;
    uint32_t    nsid;
    uint64_t    res1;
    uint64_t    mptr;
    uint64_t    prp1;
    uint64_t    prp2;
    uint32_t    cdw10;
    uint32_t    cdw11;
    uint32_t    cdw12;
    uint32_t    cdw13;
    uint32_t    cdw14;
    uint32_t    cdw15;
} NvmeCmd;

enum NvmeAdminCommands {
    NVME_ADM_CMD_DELETE_SQ      = 0x00,
    NVME_ADM_CMD_CREATE_SQ      = 0x01,
    NVME_ADM_CMD_GET_LOG_PAGE   = 0x02,
    NVME_ADM_CMD_DELETE_CQ      = 0x04,
    NVME_ADM_CMD_CREATE_CQ      = 0x05,
    NVME_ADM_CMD_IDENTIFY       = 0x06,
    NVME_ADM_CMD_ABORT          = 0x08,
    NVME_ADM_CMD_SET_FEATURES   = 0x09,
    NVME_ADM_CMD_GET_FEATURES   = 0x0a,
    NVME_ADM_CMD_ASYNC_EV_REQ   = 0x0c,
    NVME_ADM_CMD_ACTIVATE_FW    = 0x10,
    NVME_ADM_CMD_DOWNLOAD_FW    = 0x11,
    NVME_ADM_CMD_DIR_SEND       = 0x19,
    NVME_ADM_CMD_DIR_RECEIVE    = 0x1a,
    NVME_ADM_CMD_FORMAT_NVM     = 0x80,
    NVME_ADM_CMD_SECURITY_SEND  = 0x81,
    NVME_ADM_CMD_SECURITY_RECV  = 0x82,
    NVME_ADM_CMD_SET_DB_MEMORY  = 0x7c,
    NVME_ADM_CMD_FEMU_DEBUG     = 0xee,
    NVME_ADM_CMD_FEMU_FLIP      = 0xef,
};

enum NvmeIoCommands {
    NVME_CMD_FLUSH              = 0x00,
    NVME_CMD_WRITE              = 0x01,
    NVME_CMD_READ               = 0x02,
    NVME_CMD_WRITE_UNCOR        = 0x04,
    NVME_CMD_COMPARE            = 0x05,
    NVME_CMD_WRITE_ZEROS        = 0x08,
    NVME_CMD_DSM                = 0x09,
};

typedef struct NvmeDeleteQ {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    rsvd1[9];
    uint16_t    qid;
    uint16_t    rsvd10;
    uint32_t    rsvd11[5];
} NvmeDeleteQ;

typedef struct NvmeCreateCq {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    rsvd1[5];
    uint64_t    prp1;
    uint64_t    rsvd8;
    uint16_t    cqid;
    uint16_t    qsize;
    uint16_t    cq_flags;
    uint16_t    irq_vector;
    uint32_t    rsvd12[4];
} NvmeCreateCq;

#define NVME_CQ_FLAGS_PC(cq_flags)  (cq_flags & 0x1)
#define NVME_CQ_FLAGS_IEN(cq_flags) ((cq_flags >> 1) & 0x1)

typedef struct NvmeCreateSq {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    rsvd1[5];
    uint64_t    prp1;
    uint64_t    rsvd8;
    uint16_t    sqid;
    uint16_t    qsize;
    uint16_t    sq_flags;
    uint16_t    cqid;
    uint32_t    rsvd12[4];
} NvmeCreateSq;

#define NVME_SQ_FLAGS_PC(sq_flags)      (sq_flags & 0x1)
#define NVME_SQ_FLAGS_QPRIO(sq_flags)   ((sq_flags >> 1) & 0x3)

enum NvmeQueueFlags {
    NVME_Q_PC           = 1,
    NVME_Q_PRIO_URGENT  = 0,
    NVME_Q_PRIO_HIGH    = 1,
    NVME_Q_PRIO_NORMAL  = 2,
    NVME_Q_PRIO_LOW     = 3,
};

typedef struct NvmeIdentity {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    nsid;
    uint64_t    rsvd2[2];
    uint64_t    prp1;
    uint64_t    prp2;
    uint32_t    cns;
    uint32_t    rsvd11[5];
} NvmeIdentify;

typedef struct NvmeRwCmd {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    nsid;
    uint64_t    rsvd2;
    uint64_t    mptr;
    uint64_t    prp1;
    uint64_t    prp2;
    uint64_t    slba;
    uint16_t    nlb;
    uint16_t    control;
    uint32_t    dsmgmt;
    uint32_t    reftag;
    uint16_t    apptag;
    uint16_t    appmask;
} NvmeRwCmd;

enum {
    NVME_RW_LR                  = 1 << 15,
    NVME_RW_FUA                 = 1 << 14,
    NVME_RW_DSM_FREQ_UNSPEC     = 0,
    NVME_RW_DSM_FREQ_TYPICAL    = 1,
    NVME_RW_DSM_FREQ_RARE       = 2,
    NVME_RW_DSM_FREQ_READS      = 3,
    NVME_RW_DSM_FREQ_WRITES     = 4,
    NVME_RW_DSM_FREQ_RW         = 5,
    NVME_RW_DSM_FREQ_ONCE       = 6,
    NVME_RW_DSM_FREQ_PREFETCH   = 7,
    NVME_RW_DSM_FREQ_TEMP       = 8,
    NVME_RW_DSM_LATENCY_NONE    = 0 << 4,
    NVME_RW_DSM_LATENCY_IDLE    = 1 << 4,
    NVME_RW_DSM_LATENCY_NORM    = 2 << 4,
    NVME_RW_DSM_LATENCY_LOW     = 3 << 4,
    NVME_RW_DSM_SEQ_REQ         = 1 << 6,
    NVME_RW_DSM_COMPRESSED      = 1 << 7,
    NVME_RW_PRINFO_PRACT        = 1 << 13,
    NVME_RW_PRINFO_PRCHK_GUARD  = 1 << 12,
    NVME_RW_PRINFO_PRCHK_APP    = 1 << 11,
    NVME_RW_PRINFO_PRCHK_REF    = 1 << 10,
};

typedef struct NvmeDsmCmd {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    nsid;
    uint64_t    rsvd2[2];
    uint64_t    prp1;
    uint64_t    prp2;
    uint32_t    nr;
    uint32_t    attributes;
    uint32_t    rsvd12[4];
} NvmeDsmCmd;

enum {
    NVME_DSMGMT_IDR = 1 << 0,
    NVME_DSMGMT_IDW = 1 << 1,
    NVME_DSMGMT_AD  = 1 << 2,
};

typedef struct NvmeDsmRange {
    uint32_t    cattr;
    uint32_t    nlb;
    uint64_t    slba;
} NvmeDsmRange;

enum NvmeAsyncEventRequest {
    NVME_AER_TYPE_ERROR                     = 0,
    NVME_AER_TYPE_SMART                     = 1,
    NVME_AER_TYPE_IO_SPECIFIC               = 6,
    NVME_AER_TYPE_VENDOR_SPECIFIC           = 7,
    NVME_AER_INFO_ERR_INVALID_SQ            = 0,
    NVME_AER_INFO_ERR_INVALID_DB            = 1,
    NVME_AER_INFO_ERR_DIAG_FAIL             = 2,
    NVME_AER_INFO_ERR_PERS_INTERNAL_ERR     = 3,
    NVME_AER_INFO_ERR_TRANS_INTERNAL_ERR    = 4,
    NVME_AER_INFO_ERR_FW_IMG_LOAD_ERR       = 5,
    NVME_AER_INFO_SMART_RELIABILITY         = 0,
    NVME_AER_INFO_SMART_TEMP_THRESH         = 1,
    NVME_AER_INFO_SMART_SPARE_THRESH        = 2,
};

typedef struct NvmeAerResult {
    uint8_t event_type;
    uint8_t event_info;
    uint8_t log_page;
    uint8_t resv;
} NvmeAerResult;

typedef struct NvmeCqe {
    union {
        struct {
            uint32_t    result;
            uint32_t    rsvd;
        } n;
        uint64_t res64;
    };
    uint16_t    sq_head;
    uint16_t    sq_id;
    uint16_t    cid;
    uint16_t    status;
} NvmeCqe;

enum NvmeStatusCodes {
    NVME_SUCCESS                = 0x0000,
    NVME_INVALID_OPCODE         = 0x0001,
    NVME_INVALID_FIELD          = 0x0002,
    NVME_CID_CONFLICT           = 0x0003,
    NVME_DATA_TRAS_ERROR        = 0x0004,
    NVME_POWER_LOSS_ABORT       = 0x0005,
    NVME_INTERNAL_DEV_ERROR     = 0x0006,
    NVME_CMD_ABORT_REQ          = 0x0007,
    NVME_CMD_ABORT_SQ_DEL       = 0x0008,
    NVME_CMD_ABORT_FAILED_FUSE  = 0x0009,
    NVME_CMD_ABORT_MISSING_FUSE = 0x000a,
    NVME_INVALID_NSID           = 0x000b,
    NVME_CMD_SEQ_ERROR          = 0x000c,
	NVME_DIR_STREAM_ALLOC_ERROR = 0x007f,
    NVME_LBA_RANGE              = 0x0080,
    NVME_CAP_EXCEEDED           = 0x0081,
    NVME_NS_NOT_READY           = 0x0082,
    NVME_NS_RESV_CONFLICT       = 0x0083,
    NVME_INVALID_CQID           = 0x0100,
    NVME_INVALID_QID            = 0x0101,
    NVME_MAX_QSIZE_EXCEEDED     = 0x0102,
    NVME_ACL_EXCEEDED           = 0x0103,
    NVME_RESERVED               = 0x0104,
    NVME_AER_LIMIT_EXCEEDED     = 0x0105,
    NVME_INVALID_FW_SLOT        = 0x0106,
    NVME_INVALID_FW_IMAGE       = 0x0107,
    NVME_INVALID_IRQ_VECTOR     = 0x0108,
    NVME_INVALID_LOG_ID         = 0x0109,
    NVME_INVALID_FORMAT         = 0x010a,
    NVME_FW_REQ_RESET           = 0x010b,
    NVME_INVALID_QUEUE_DEL      = 0x010c,
    NVME_FID_NOT_SAVEABLE       = 0x010d,
    NVME_FID_NOT_NSID_SPEC      = 0x010f,
    NVME_FW_REQ_SUSYSTEM_RESET  = 0x0110,
    NVME_CONFLICTING_ATTRS      = 0x0180,
    NVME_INVALID_PROT_INFO      = 0x0181,
    NVME_WRITE_TO_RO            = 0x0182,
    NVME_INVALID_MEMORY_ADDRESS = 0x01C0,
    NVME_WRITE_FAULT            = 0x0280,
    NVME_UNRECOVERED_READ       = 0x0281,
    NVME_E2E_GUARD_ERROR        = 0x0282,
    NVME_E2E_APP_ERROR          = 0x0283,
    NVME_E2E_REF_ERROR          = 0x0284,
    NVME_CMP_FAILURE            = 0x0285,
    NVME_ACCESS_DENIED          = 0x0286,
    NVME_MORE                   = 0x2000,
    NVME_DNR                    = 0x4000,
    NVME_NO_COMPLETE            = 0xffff,
};

typedef struct NvmeFwSlotInfoLog {
    uint8_t     afi;
    uint8_t     reserved1[7];
    uint8_t     frs1[8];
    uint8_t     frs2[8];
    uint8_t     frs3[8];
    uint8_t     frs4[8];
    uint8_t     frs5[8];
    uint8_t     frs6[8];
    uint8_t     frs7[8];
    uint8_t     reserved2[448];
} NvmeFwSlotInfoLog;

typedef struct NvmeErrorLog {
    uint64_t    error_count;
    uint16_t    sqid;
    uint16_t    cid;
    uint16_t    status_field;
    uint16_t    param_error_location;
    uint64_t    lba;
    uint32_t    nsid;
    uint8_t     vs;
    uint8_t     resv[35];
} NvmeErrorLog;

typedef struct NvmeSmartLog {
    uint8_t     critical_warning;
    uint8_t     temperature[2];
    uint8_t     available_spare;
    uint8_t     available_spare_threshold;
    uint8_t     percentage_used;
    uint8_t     reserved1[26];
    uint64_t    data_units_read[2];
    uint64_t    data_units_written[2];
    uint64_t    host_read_commands[2];
    uint64_t    host_write_commands[2];
    uint64_t    controller_busy_time[2];
    uint64_t    power_cycles[2];
    uint64_t    power_on_hours[2];
    uint64_t    unsafe_shutdowns[2];
    uint64_t    media_errors[2];
    uint64_t    number_of_error_log_entries[2];
    uint8_t     reserved2[320];
} NvmeSmartLog;

enum NvmeSmartWarn {
    NVME_SMART_SPARE                  = 1 << 0,
    NVME_SMART_TEMPERATURE            = 1 << 1,
    NVME_SMART_RELIABILITY            = 1 << 2,
    NVME_SMART_MEDIA_READ_ONLY        = 1 << 3,
    NVME_SMART_FAILED_VOLATILE_MEDIA  = 1 << 4,
};

enum LogIdentifier {
    NVME_LOG_ERROR_INFO     = 0x01,
    NVME_LOG_SMART_INFO     = 0x02,
    NVME_LOG_FW_SLOT_INFO   = 0x03,
};

typedef struct NvmePSD {
    uint16_t    mp;
    uint16_t    reserved;
    uint32_t    enlat;
    uint32_t    exlat;
    uint8_t     rrt;
    uint8_t     rrl;
    uint8_t     rwt;
    uint8_t     rwl;
    uint8_t     resv[16];
} NvmePSD;

typedef struct NvmeIdCtrl {
    uint16_t    vid;
    uint16_t    ssvid;
    uint8_t     sn[20];
    uint8_t     mn[40];
    uint8_t     fr[8];
    uint8_t     rab;
    uint8_t     ieee[3];
    uint8_t     cmic;
    uint8_t     mdts;
    uint8_t     rsvd255[178];
    uint16_t    oacs;
    uint8_t     acl;
    uint8_t     aerl;
    uint8_t     frmw;
    uint8_t     lpa;
    uint8_t     elpe;
    uint8_t     npss;
    uint8_t     rsvd511[248];
    uint8_t     sqes;
    uint8_t     cqes;
    uint16_t    rsvd515;
    uint32_t    nn;
    uint16_t    oncs;
    uint16_t    fuses;
    uint8_t     fna;
    uint8_t     vwc;
    uint16_t    awun;
    uint16_t    awupf;
    uint8_t     rsvd703[174];
    uint8_t     rsvd2047[1344];
    NvmePSD     psd[32];
    uint8_t     vs[1024];
} NvmeIdCtrl;

enum NvmeIdCtrlOacs {
    NVME_OACS_SECURITY      = 1 << 0,
    NVME_OACS_FORMAT        = 1 << 1,
    NVME_OACS_FW            = 1 << 2,
	NVME_OACS_DIR       	= 1 << 5,
    NVME_OACS_FEMU_OC12_DEV = 1 << 3,
    NVME_OACS_DBBUF         = 1 << 8,
};

enum NvmeIdCtrlOncs {
    NVME_ONCS_COMPARE       = 1 << 0,
    NVME_ONCS_WRITE_UNCORR  = 1 << 1,
    NVME_ONCS_DSM           = 1 << 2,
    NVME_ONCS_WRITE_ZEROS   = 1 << 3,
    NVME_ONCS_FEATURES      = 1 << 4,
    NVME_ONCS_RESRVATIONS   = 1 << 5,
};

#define NVME_CTRL_SQES_MIN(sqes) ((sqes) & 0xf)
#define NVME_CTRL_SQES_MAX(sqes) (((sqes) >> 4) & 0xf)
#define NVME_CTRL_CQES_MIN(cqes) ((cqes) & 0xf)
#define NVME_CTRL_CQES_MAX(cqes) (((cqes) >> 4) & 0xf)

typedef struct NvmeFeatureVal {
    uint32_t    arbitration;
    uint32_t    power_mgmt;
    uint32_t    temp_thresh;
    uint32_t    err_rec;
    uint32_t    volatile_wc;
    uint32_t    num_io_queues;
    uint32_t    int_coalescing;
    uint32_t    *int_vector_config;
    uint32_t    write_atomicity;
    uint32_t    async_config;
    uint32_t    sw_prog_marker;
} NvmeFeatureVal;

#define NVME_ARB_AB(arb)    (arb & 0x7)
#define NVME_ARB_LPW(arb)   ((arb >> 8) & 0xff)
#define NVME_ARB_MPW(arb)   ((arb >> 16) & 0xff)
#define NVME_ARB_HPW(arb)   ((arb >> 24) & 0xff)

#define NVME_INTC_THR(intc)     (intc & 0xff)
#define NVME_INTC_TIME(intc)    ((intc >> 8) & 0xff)

enum NvmeFeatureIds {
    NVME_ARBITRATION                = 0x1,
    NVME_POWER_MANAGEMENT           = 0x2,
    NVME_LBA_RANGE_TYPE             = 0x3,
    NVME_TEMPERATURE_THRESHOLD      = 0x4,
    NVME_ERROR_RECOVERY             = 0x5,
    NVME_VOLATILE_WRITE_CACHE       = 0x6,
    NVME_NUMBER_OF_QUEUES           = 0x7,
    NVME_INTERRUPT_COALESCING       = 0x8,
    NVME_INTERRUPT_VECTOR_CONF      = 0x9,
    NVME_WRITE_ATOMICITY            = 0xa,
    NVME_ASYNCHRONOUS_EVENT_CONF    = 0xb,
    NVME_SOFTWARE_PROGRESS_MARKER   = 0x80
};

enum NvmeDirectiveType {
    NVME_DIR_TYPE_IDENTIFY          = 0x00,
    NVME_DIR_TYPE_STREAMS           = 0x01,
};

enum NvmeDirectiveOps {
    NVME_DIR_SND_ID_OP_ENABLE       = 0x01,
    NVME_DIR_SND_ST_OP_REL_ID       = 0x01,
    NVME_DIR_SND_ST_OP_REL_RSC      = 0x02,
    NVME_DIR_RCV_ID_OP_PARAM        = 0x01,
    NVME_DIR_RCV_ST_OP_PARAM        = 0x01,
    NVME_DIR_RCV_ST_OP_STATUS       = 0x02,
    NVME_DIR_RCV_ST_OP_RESOURCE     = 0x03,
};

enum NvmeDirectiveEnable {
    NVME_DIR_ENDIR                  = 0x01,
};

enum NvmeDirectiveExists {
    NVME_DIR_IDF_IDENTIFY = 0x1,
    NVME_DIR_IDF_STREAMS = 0x2,
};

typedef struct NvmeDirId {
       uint8_t dir_support[32];
       uint8_t dir_enable[32];
       uint8_t res[4032];
} NvmeDirId;

typedef struct NvmeDirStrParam {
    uint16_t     msl;
    uint16_t     nssa;
    uint16_t     nsso;
    uint8_t      res10[10];
    uint32_t     sws;
    uint16_t     sgs;
    uint16_t     nsa;
    uint16_t     nso;
    uint8_t      res6[6];
} NvmeDirStrParam;

typedef struct NvmeDirStrNsStat {
       uint16_t  cnt;
       uint16_t  id[65535];
} NvmeDirStrNsStat;

typedef struct NvmeRangeType {
    uint8_t     type;
    uint8_t     attributes;
    uint8_t     rsvd2[14];
    uint64_t    slba;
    uint64_t    nlb;
    uint8_t     guid[16];
    uint8_t     rsvd48[16];
} NvmeRangeType;

typedef struct NvmeLBAF {
    uint16_t    ms;
    uint8_t     ds;
    uint8_t     rp;
} NvmeLBAF;

typedef struct NvmeIdNs {
    uint64_t    nsze;
    uint64_t    ncap;
    uint64_t    nuse;
    uint8_t     nsfeat;
    uint8_t     nlbaf;
    uint8_t     flbas;
    uint8_t     mc;
    uint8_t     dpc;
    uint8_t     dps;
    uint8_t     res30[98];
    NvmeLBAF    lbaf[16];
    uint8_t     res192[192];
    uint8_t     vs[3712];
} NvmeIdNs;

#define NVME_ID_NS_NSFEAT_THIN(nsfeat)      ((nsfeat & 0x1))
#define NVME_ID_NS_FLBAS_EXTENDED(flbas)    ((flbas >> 4) & 0x1)
#define NVME_ID_NS_FLBAS_INDEX(flbas)       ((flbas & 0xf))
#define NVME_ID_NS_MC_SEPARATE(mc)          ((mc >> 1) & 0x1)
#define NVME_ID_NS_MC_EXTENDED(mc)          ((mc & 0x1))
#define NVME_ID_NS_DPC_LAST_EIGHT(dpc)      ((dpc >> 4) & 0x1)
#define NVME_ID_NS_DPC_FIRST_EIGHT(dpc)     ((dpc >> 3) & 0x1)
#define NVME_ID_NS_DPC_TYPE_3(dpc)          ((dpc >> 2) & 0x1)
#define NVME_ID_NS_DPC_TYPE_2(dpc)          ((dpc >> 1) & 0x1)
#define NVME_ID_NS_DPC_TYPE_1(dpc)          ((dpc & 0x1))
#define NVME_ID_NS_DPC_TYPE_MASK            0x7

enum NvmeIdNsDps {
    DPS_TYPE_NONE   = 0,
    DPS_TYPE_1      = 1,
    DPS_TYPE_2      = 2,
    DPS_TYPE_3      = 3,
    DPS_TYPE_MASK   = 0x7,
    DPS_FIRST_EIGHT = 8,
};

enum FEMU_OC12_AdminCommands {
    FEMU_OC12_ADM_CMD_IDENTITY          = 0xe2,
    FEMU_OC12_ADM_CMD_GET_L2P_TBL       = 0xea,
    FEMU_OC12_ADM_CMD_GET_BB_TBL        = 0xf2,
    FEMU_OC12_ADM_CMD_SET_BB_TBL        = 0xf1,
};

enum FEMU_OC12_DmCommands {
    FEMU_OC12_CMD_PHYS_WRITE        = 0x91,
    FEMU_OC12_CMD_PHYS_READ         = 0x92,
    FEMU_OC12_CMD_ERASE_ASYNC       = 0x90,
};

enum FEMU_OC12_MetaState {
    FEMU_OC12_SEC_UNKNOWN = 0x0,
    FEMU_OC12_SEC_WRITTEN = 0xAC,
    FEMU_OC12_SEC_ERASED  = 0xDC,
};

typedef struct FEMU_OC12_GetL2PTbl {
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
} FEMU_OC12_GetL2PTbl;

typedef struct FEMU_OC12_BbtGet {
  uint8_t opcode;
  uint8_t flags;
  uint16_t cid;
  uint32_t nsid;
  uint64_t rsvd1[2];
  uint64_t prp1;
  uint64_t prp2;
  uint64_t spba;
  uint32_t rsvd4[4]; // DW15, 14, 13, 12
} FEMU_OC12_BbtGet;

typedef struct FEMU_OC12_BbtSet {
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
} FEMU_OC12_BbtSet;

typedef struct FEMU_OC12_RwCmd {
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
} FEMU_OC12_RwCmd;

typedef struct FEMU_OC12_DmCmd {
  uint8_t opcode;
  uint8_t flags;
  uint16_t cid;
  uint32_t nsid;
  uint32_t rsvd1[8];
  uint64_t spba;
  uint32_t nlb;
  uint32_t rsvd2[3];
} FEMU_OC12_DmCmd;

typedef struct FEMU_OC12_IdAddrFormat {
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
} QEMU_PACKED FEMU_OC12_IdAddrFormat;

typedef struct FEMU_OC12_AddrF {
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
} FEMU_OC12_AddrF;

typedef struct FEMU_OC12_IdGroup {
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
} QEMU_PACKED FEMU_OC12_IdGroup;

typedef struct FEMU_OC12_IdCtrl {
    uint8_t       ver_id;
    uint8_t       vmnt;
    uint8_t       cgrps;
    uint8_t       res;
    uint32_t      cap;
    uint32_t      dom;
    struct FEMU_OC12_IdAddrFormat ppaf;
    uint8_t       resv[228];
    FEMU_OC12_IdGroup   groups[4];
} QEMU_PACKED FEMU_OC12_IdCtrl;

typedef struct FEMU_OC12_Bbt {
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
} QEMU_PACKED FEMU_OC12_Bbt;

/* Parameters passed on to QEMU to configure the characteristics of the drive */
typedef struct FEMU_OC12_Params {
    /* configurable device characteristics */
    uint16_t    pgs_per_blk;
    uint16_t    sec_size;
    uint8_t     sec_per_pg;
    uint8_t     max_sec_per_rq;
    /* configurable parameters for FEMU_OC12_IdGroup */
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
} QEMU_PACKED FEMU_OC12_Params;

enum FEMU_OC12_Pmode {
    FEMU_OC12_PMODE_SNGL = 0x0,      ///< Single-plane
    FEMU_OC12_PMODE_DUAL = 0x1,      ///< Dual-plane (NVM_IO_DUAL_ACCESS)
    FEMU_OC12_PMODE_QUAD = 0x2       ///< Quad-plane (NVM_IO_QUAD_ACCESS)
};

enum FEMU_OC12_Responsibility {
    FEMU_OC12_RSP_L2P       = 1 << 0,
    FEMU_OC12_RSP_ECC       = 1 << 1,
};

typedef struct FEMU_OC12_Ctrl {
    FEMU_OC12_Params     params;
    FEMU_OC12_IdCtrl     id_ctrl;
    FEMU_OC12_AddrF      ppaf;
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
} FEMU_OC12_Ctrl;

struct femu_oc12_metadata_format {
    uint32_t state;
    uint64_t rsv[2];
} __attribute__((__packed__));

struct femu_oc12_tgt_meta {
    uint64_t lba;
    uint64_t rsvd;
} __attribute__((__packed__));

#define FEMU_OC12_MAX_GRPS_PR_IDENT (20)
#define FEMU_OC12_FEAT_EXT_START 64
#define FEMU_OC12_FEAT_EXT_END 127
#define FEMU_OC12_PBA_UNMAPPED UINT64_MAX
#define FEMU_OC12_LBA_UNMAPPED UINT64_MAX

static inline void femu_oc12_check_size(void)
{
    QEMU_BUILD_BUG_ON(sizeof(FEMU_OC12_GetL2PTbl) != 64);
    QEMU_BUILD_BUG_ON(sizeof(FEMU_OC12_BbtGet) != 64);
    QEMU_BUILD_BUG_ON(sizeof(FEMU_OC12_BbtSet) != 64);
    QEMU_BUILD_BUG_ON(sizeof(FEMU_OC12_RwCmd) != 64);
    QEMU_BUILD_BUG_ON(sizeof(FEMU_OC12_DmCmd) != 64);
    QEMU_BUILD_BUG_ON(sizeof(FEMU_OC12_IdCtrl) != 4096);
    QEMU_BUILD_BUG_ON(sizeof(FEMU_OC12_IdAddrFormat) != 16);
    QEMU_BUILD_BUG_ON(sizeof(FEMU_OC12_IdGroup) != 960);
}


static inline void nvme_check_size(void)
{
    QEMU_BUILD_BUG_ON(sizeof(NvmeAerResult) != 4);
    QEMU_BUILD_BUG_ON(sizeof(NvmeCqe) != 16);
    QEMU_BUILD_BUG_ON(sizeof(NvmeDsmRange) != 16);
    QEMU_BUILD_BUG_ON(sizeof(NvmeCmd) != 64);
    QEMU_BUILD_BUG_ON(sizeof(NvmeDeleteQ) != 64);
    QEMU_BUILD_BUG_ON(sizeof(NvmeCreateCq) != 64);
    QEMU_BUILD_BUG_ON(sizeof(NvmeCreateSq) != 64);
    QEMU_BUILD_BUG_ON(sizeof(NvmeIdentify) != 64);
    QEMU_BUILD_BUG_ON(sizeof(NvmeRwCmd) != 64);
    QEMU_BUILD_BUG_ON(sizeof(NvmeDsmCmd) != 64);
    QEMU_BUILD_BUG_ON(sizeof(NvmeRangeType) != 64);
    QEMU_BUILD_BUG_ON(sizeof(NvmeErrorLog) != 64);
    QEMU_BUILD_BUG_ON(sizeof(NvmeFwSlotInfoLog) != 512);
    QEMU_BUILD_BUG_ON(sizeof(NvmeSmartLog) != 512);
    QEMU_BUILD_BUG_ON(sizeof(NvmeIdCtrl) != 4096);
    QEMU_BUILD_BUG_ON(sizeof(NvmeIdNs) != 4096);
	QEMU_BUILD_BUG_ON(sizeof(NvmeDirId) != 4096);
    QEMU_BUILD_BUG_ON(sizeof(NvmeDirStrParam) != 32);
    QEMU_BUILD_BUG_ON(sizeof(NvmeDirStrNsStat) != 131072);

    /* Coperd: check FEMU OC structure size */
    femu_oc12_check_size();
}

typedef struct NvmeAsyncEvent {
    QSIMPLEQ_ENTRY(NvmeAsyncEvent) entry;
    NvmeAerResult result;
} NvmeAsyncEvent;

typedef struct NvmeRequest {
    struct NvmeSQueue       *sq;
    struct NvmeCQueue       *cq;
    struct NvmeNamespace    *ns;
    uint16_t                status;
    uint64_t                slba;
    uint16_t                is_write;
    uint16_t                nlb;
    uint16_t                ctrl;
    uint64_t                meta_size;
    uint64_t                mptr;
    void                    *meta_buf;
    uint64_t                femu_oc12_slba;
    uint64_t                *femu_oc12_ppa_list;
    NvmeCqe                 cqe;
    QEMUSGList              qsg;
    QEMUIOVector            iov;
    QTAILQ_ENTRY(NvmeRequest)entry;
    int64_t                 stime;
    int64_t                 reqlat;
    int64_t                 gcrt;
    int64_t                 expire_time;
    int64_t                 data_offset;
    int64_t                 tifa_cmd_flag;
    int                     lunid;
    int                     chnl;

    /* position in the priority queue for delay emulation */
    size_t                  pos;
} NvmeRequest;

typedef struct DMAOff {
    QEMUSGList *qsg;
    int ndx;
    dma_addr_t ptr;
    dma_addr_t len;
} DMAOff;

typedef struct NvmeSQueue {
    struct FemuCtrl *ctrl;
    uint8_t     phys_contig;
    uint8_t     arb_burst;
    uint16_t    sqid;
    uint16_t    cqid;
    uint32_t    head;
    uint32_t    tail;
    uint32_t    size;
    uint64_t    dma_addr;
    uint64_t    dma_addr_hva;
    uint64_t    completed;
    uint64_t    *prp_list;
    NvmeRequest *io_req;
    QTAILQ_HEAD(sq_req_list, NvmeRequest) req_list;
    QTAILQ_HEAD(out_req_list, NvmeRequest) out_req_list;
    QTAILQ_ENTRY(NvmeSQueue) entry;

    uint64_t    db_addr;
    uint64_t    db_addr_hva;
    uint64_t    eventidx_addr;
    uint64_t    eventidx_addr_hva;
    bool        is_active;
} NvmeSQueue;

typedef struct NvmeCQueue {
    struct FemuCtrl *ctrl;
    uint8_t     phys_contig;
    uint8_t     phase;
    uint16_t    cqid;
    uint16_t    irq_enabled;
    uint32_t    head;
    uint32_t    tail;
    int32_t     virq;
    uint32_t    vector;
    uint32_t    size;
    uint64_t    dma_addr;
    uint64_t    dma_addr_hva;
    uint64_t    *prp_list;
    EventNotifier guest_notifier;
    QEMUTimer   *timer;
    QTAILQ_HEAD(sq_list, NvmeSQueue) sq_list;
    QTAILQ_HEAD(cq_req_list, NvmeRequest) req_list;
    uint64_t    db_addr;
    uint64_t    db_addr_hva;
    uint64_t    eventidx_addr;
    uint64_t    eventidx_addr_hva;
    bool        is_active;
} NvmeCQueue;

typedef struct NvmeNamespace {
    struct FemuCtrl *ctrl;
    NvmeIdNs        id_ns;
    NvmeDirId       *id_dir;
    NvmeDirStrParam *str_ns_param;
    NvmeDirStrNsStat  *str_ns_stat;
    NvmeRangeType   lba_range[64];
    unsigned long   *util;
    unsigned long   *uncorrectable;
    uint32_t        id;
    uint64_t        ns_blks;
    uint64_t        start_block;
    uint64_t        meta_start_offset;
    uint64_t        tbl_dsk_start_offset;
    uint32_t        tbl_entries;
    uint64_t        *tbl;
    FEMU_OC12_Bbt   **bbtbl;
} NvmeNamespace;

#define TYPE_NVME "femu"
#define FEMU(obj) OBJECT_CHECK(FemuCtrl, (obj), TYPE_NVME)

typedef struct FemuCtrl {
    PCIDevice    parent_obj;
    MemoryRegion iomem;
    MemoryRegion ctrl_mem;
    NvmeBar      bar;

    time_t      start_time;
    uint16_t    temperature;
    uint16_t    page_size;
    uint16_t    page_bits;
    uint16_t    max_prp_ents;
    uint16_t    cqe_size;
    uint16_t    sqe_size;
    uint16_t    oacs;
    uint16_t    oncs;
    uint32_t    reg_size;
    uint32_t    num_namespaces;
    uint32_t    num_io_queues;
    uint32_t    max_q_ents;
    uint64_t    ns_size;
    uint8_t     db_stride;
    uint8_t     aerl;
    uint8_t     acl;
    uint8_t     elpe;
    uint8_t     elp_index;
    uint8_t     error_count;
    uint8_t     mdts;
    uint8_t     cqr;
    uint8_t     max_sqes;
    uint8_t     max_cqes;
    uint8_t     meta;
    uint8_t     vwc;
    uint8_t     mc;
    uint8_t     dpc;
    uint8_t     dps;
    uint8_t     nlbaf;
    uint8_t     extended;
    uint8_t     lba_index;
    uint8_t     mpsmin;
    uint8_t     mpsmax;
    uint8_t     intc;
    uint8_t     intc_thresh;
    uint8_t     intc_time;
    uint8_t     outstanding_aers;
    uint8_t     temp_warn_issued;
    uint8_t     num_errors;
    uint8_t     cqes_pending;
    uint16_t    vid;
    uint16_t    did;
    uint32_t    cmbsz;
    uint32_t    cmbloc;
    uint8_t     *cmbuf;

    QemuThread  *poller;
    bool        dataplane_started;
    bool        vector_poll_started;

    char            *serial;
    NvmeErrorLog    *elpes;
    NvmeRequest     **aer_reqs;
    NvmeNamespace   *namespaces;
    NvmeSQueue      **sq;
    NvmeCQueue      **cq;
    NvmeSQueue      admin_sq;
    NvmeCQueue      admin_cq;
    NvmeFeatureVal  features;
    NvmeIdCtrl      id_ctrl;
	NvmeDirStrParam *str_sys_param;

    QSIMPLEQ_HEAD(aer_queue, NvmeAsyncEvent) aer_queue;
    QEMUTimer       *aer_timer;
    uint8_t         aer_mask;

	uint64_t		dbs_addr;
	uint64_t		eis_addr;
    uint64_t        dbs_addr_hva;
    uint64_t        eis_addr_hva;

    uint8_t         femu_mode;
	uint8_t		computation_mode;
	uint32_t		flash_read_latency;
	uint32_t		flash_write_latency;
    uint32_t        memsz;
    FEMU_OC12_Ctrl  femu_oc12_ctrl;
    struct ssd      ssd;
    struct femu_mbe mbe;
    int             completed;

    char            devname[64];
    struct rte_ring **to_ftl;
    struct rte_ring **to_poller;
    pqueue_t        **pq;
    bool            *should_isr;
    bool            poller_on;

    int64_t         nr_tt_ios;
    int64_t         nr_tt_late_ios;
    bool            print_log;

    uint8_t         multipoller_enabled;
    uint32_t        num_poller;
} FemuCtrl;

typedef struct NvmePollerThreadArgument {
    FemuCtrl        *n;
    int             index;
} NvmePollerThreadArgument;

typedef struct NvmeDifTuple {
    uint16_t guard_tag;
    uint16_t app_tag;
    uint32_t ref_tag;
} NvmeDifTuple;

#define SQ_POLLING_PERIOD_NS	(5000)
#define CQ_POLLING_PERIOD_NS	(5000)
#define FEMU_MAX_INF_REQS       (65536)

enum {
    FEMU_WHITEBOX_MODE = 0,
    FEMU_BLACKBOX_MODE,
    FEMU_DEF_NOSSD_MODE,
};

enum {
	FEMU_COMPUTE_OFF = 0,
	FEMU_COMPUTE_ON,
	FEMU_DEF_NOCOMPUTATION_MODE,
};

static inline bool OCSSD(FemuCtrl *n)
{
    return (n->femu_mode == FEMU_WHITEBOX_MODE);
}

static inline bool BBSSD(FemuCtrl *n)
{
    return (n->femu_mode == FEMU_BLACKBOX_MODE);
}

extern void ssd_init(FemuCtrl *n);
extern uint64_t ssd_read(struct ssd *ssd, NvmeRequest *req);
extern uint64_t ssd_write(struct ssd *ssd, NvmeRequest *req);


void femu_oc12_exit(FemuCtrl *n);
int femu_oc12_init(FemuCtrl *n);
int femu_oc12_flush_tbls(FemuCtrl *n);
uint16_t femu_oc12_bbt_set(FemuCtrl *n, NvmeCmd *cmd, NvmeCqe *cqe);
uint16_t femu_oc12_bbt_get(FemuCtrl *n, NvmeCmd *cmd, NvmeCqe *cqe);
uint16_t femu_oc12_get_l2p_tbl(FemuCtrl *n, NvmeCmd *cmd, NvmeCqe *cqe);
uint16_t femu_oc12_identity(FemuCtrl *n, NvmeCmd *cmd);
void femu_oc12_tbl_initialize(NvmeNamespace *ns);
uint16_t femu_oc12_rw(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req);
uint16_t femu_oc12_erase_async(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req);
uint32_t femu_oc12_tbl_size(NvmeNamespace *ns);


void nvme_process_sq_admin(void *opaque);
void nvme_process_sq_io(void *opaque, int index_poller, int computational_fd_send, int computational_fd_recv);

void femu_nvme_addr_read(FemuCtrl *n, hwaddr addr, void *buf, int size);
void femu_nvme_addr_write(FemuCtrl *n, hwaddr addr, void *buf, int size);
int nvme_check_sqid(FemuCtrl *n, uint16_t sqid);
int nvme_check_cqid(FemuCtrl *n, uint16_t cqid);
void nvme_inc_cq_tail(NvmeCQueue *cq);
void nvme_inc_sq_head(NvmeSQueue *sq);
void nvme_update_cq_head(NvmeCQueue *cq);
uint8_t nvme_cq_full(NvmeCQueue *cq);
uint8_t nvme_sq_empty(NvmeSQueue *sq);
void nvme_isr_notify_legacy(void *opaque);
void nvme_isr_notify_admin(void *opaque);
void nvme_isr_notify_io(void *opaque);
uint64_t *nvme_setup_discontig(FemuCtrl *n, uint64_t prp_addr,
    uint16_t queue_depth, uint16_t entry_size);
hwaddr nvme_discontig(uint64_t *dma_addr, uint16_t page_size,
    uint16_t queue_idx, uint16_t entry_size);
uint16_t nvme_map_prp(QEMUSGList *qsg, QEMUIOVector *iov,
        uint64_t prp1, uint64_t prp2, uint32_t len, FemuCtrl *n);
uint16_t nvme_dma_write_prp(FemuCtrl *n, uint8_t *ptr, uint32_t len,
        uint64_t prp1, uint64_t prp2);
uint16_t nvme_dma_read_prp(FemuCtrl *n, uint8_t *ptr, uint32_t len,
        uint64_t prp1, uint64_t prp2);
void nvme_set_error_page(FemuCtrl *n, uint16_t sqid, uint16_t cid,
        uint16_t status, uint16_t location, uint64_t lba, uint32_t nsid);
uint16_t femu_nvme_rw_check_req(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
        NvmeRequest *req, uint64_t slba, uint64_t elba, uint32_t nlb,
        uint16_t ctrl, uint64_t data_size, uint64_t meta_size);
int nvme_add_kvm_msi_virq(FemuCtrl *n, NvmeCQueue *cq);
void nvme_remove_kvm_msi_virq(NvmeCQueue *cq);
int nvme_set_guest_notifier(FemuCtrl *n, EventNotifier *notifier, uint32_t qid);
int nvme_vector_unmask(PCIDevice *dev, unsigned vector, MSIMessage msg);
void nvme_vector_mask(PCIDevice *dev, unsigned vector);
void nvme_vector_poll(PCIDevice *dev, unsigned int vector_start,
        unsigned int vector_end);
uint16_t nvme_create_cq(FemuCtrl *n, NvmeCmd *cmd);
uint16_t nvme_set_db_memory(FemuCtrl *n, const NvmeCmd *cmd);
void nvme_clear_guest_notifier(FemuCtrl *n);
void nvme_update_sq_tail(NvmeSQueue *sq);
uint64_t nvme_cmb_read(void *opaque, hwaddr addr, unsigned size);
void nvme_cmb_write(void *opaque, hwaddr addr, uint64_t data, unsigned size);


uint16_t nvme_init_sq(NvmeSQueue *sq, FemuCtrl *n, uint64_t dma_addr,
    uint16_t sqid, uint16_t cqid, uint16_t size, enum NvmeQueueFlags prio,
    int contig);

uint16_t nvme_create_sq(FemuCtrl *n, NvmeCmd *cmd);
void nvme_free_sq(NvmeSQueue *sq, FemuCtrl *n);
void nvme_free_cq(NvmeCQueue *cq, FemuCtrl *n);
uint16_t nvme_del_sq(FemuCtrl *n, NvmeCmd *cmd);
uint16_t nvme_del_cq(FemuCtrl *n, NvmeCmd *cmd);
uint16_t nvme_init_cq(NvmeCQueue *cq, FemuCtrl *n, uint64_t dma_addr,
    uint16_t cqid, uint16_t vector, uint16_t size, uint16_t irq_enabled,
    int contig);

uint16_t nvme_identify(FemuCtrl *n, NvmeCmd *cmd);
uint16_t femu_nvme_get_feature(FemuCtrl *n, NvmeCmd *cmd, NvmeCqe *cqe);
uint16_t femu_nvme_set_feature(FemuCtrl *n, NvmeCmd *cmd, NvmeCqe *cqe);
uint16_t nvme_smart_info(FemuCtrl *n, NvmeCmd *cmd, uint32_t buf_len);
uint16_t nvme_fw_log_info(FemuCtrl *n, NvmeCmd *cmd, uint32_t buf_len);
uint16_t nvme_error_log_info(FemuCtrl *n, NvmeCmd *cmd, uint32_t buf_len);
uint16_t femu_nvme_get_log(FemuCtrl *n, NvmeCmd *cmd);
uint16_t nvme_dsm(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd, NvmeRequest *req);
uint16_t nvme_compare(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req);
uint16_t nvme_flush(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req);
uint16_t nvme_write_zeros(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req);
uint16_t nvme_write_uncor(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req);


uint64_t ns_blks(NvmeNamespace *ns, uint8_t lba_idx);
void nvme_partition_ns(NvmeNamespace *ns, uint8_t lba_idx);
void nvme_post_cqes_io(void *opaque);

void femu_create_nvme_poller(FemuCtrl *n);

int nvme_found_in_str_list(NvmeDirStrNsStat *str_ns_stat, uint16_t dspec);
void nvme_del_from_str_list(NvmeDirStrNsStat *str_ns_stat, int pos);
void nvme_add_to_str_list(NvmeDirStrNsStat *str_ns_stat, uint16_t dspec);
void nvme_update_str_stat(FemuCtrl *n, NvmeNamespace *ns, uint16_t dspec);


extern int64_t nand_read_upper_t;
extern int64_t nand_read_lower_t;
extern int64_t nand_write_upper_t;
extern int64_t nand_write_lower_t;
extern int64_t nand_erase_t;
extern int64_t chnl_page_tr_t;

#define DEBUG_FEMU_FTL
#ifdef DEBUG_FEMU_FTL
#define femu_debug(fmt, ...) \
    do { printf("FEMU: " fmt, ## __VA_ARGS__); } while (0)
#else
#define femu_debug(fmt, ...) \
    do { } while (0)
#endif

#define femu_err(fmt, ...) \
    do { fprintf(stderr, "FEMU: " fmt, ## __VA_ARGS__); } while (0)

#define femu_log(fmt, ...) \
    do { printf("FEMU: " fmt, ## __VA_ARGS__); } while (0)


#endif /* __FEMU_NVME_H */

