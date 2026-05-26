#ifndef FEMU_CSD_H
#define FEMU_CSD_H

#include "../nvme.h"

enum FemuCsdIoCommands {
    NVME_CMD_CSD_ALLOC_FDM      = 0xb0,
    NVME_CMD_CSD_DEALLOC_AFDM   = 0xc0,
    NVME_CMD_CSD_NVM_TO_AFDM    = 0xd0,
    NVME_CMD_CSD_EXEC           = 0xe0,
    NVME_CMD_CSD_READ_AFDM      = 0xf2,
    NVME_CMD_CSD_WRITE_AFDM     = 0xf5,
    NVME_CMD_CSD_CREATE_GROUP   = 0xf6,
    NVME_CMD_CSD_SET_QOS        = 0xf7,
    NVME_CMD_CSD_DELETE_GROUP   = 0xf8,
};

enum FemuCsdAdminCommands {
    NVME_ADM_CMD_CSD_COMPUTE_LOAD     = 0x22,
    NVME_ADM_CMD_CSD_COMPUTE_ACTIVATE = 0x23,
};

enum FemuCsdFdmType {
    NVME_CSD_FDM_TYPE_HOST = 0,
};

enum FemuCsdCsfType {
    NVME_CSD_CSF_TYPE_PHANTOM = 0,
    NVME_CSD_CSF_TYPE_EBPF = 1,
    NVME_CSD_CSF_TYPE_BITSTREAM = 2,
    NVME_CSD_CSF_TYPE_SHARED_LIB = 3,
};

typedef struct QEMU_PACKED NvmeCsdLoadProgramCmd {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    nsid;
    uint16_t    jit:1;
    uint16_t    rsvd_ctrl:15;
    uint16_t    runtime_scale;
    uint32_t    runtime;
    uint32_t    rsvd4[2];
    uint64_t    prp1;
    uint64_t    prp2;
    uint16_t    pind;
    uint8_t     ptype;
    uint8_t     sel:1;
    uint8_t     pit:3;
    uint8_t     indirect:1;
    uint8_t     rsvd10:3;
    uint32_t    psize;
    uint64_t    pid;
    uint32_t    numb;
    uint32_t    loff;
} NvmeCsdLoadProgramCmd;

typedef struct QEMU_PACKED NvmeCsdProgramActivationCmd {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    nsid;
    uint32_t    rsvd[4];
    uint64_t    prp1;
    uint64_t    prp2;
    uint32_t    pind:16;
    uint32_t    sel:4;
    uint32_t    rsvd10:12;
    uint32_t    runtime;
    uint32_t    rsvd12[4];
} NvmeCsdProgramActivationCmd;

typedef struct QEMU_PACKED NvmeCsdAllocFdmCmd {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    nsid;
    uint64_t    rsvd2[2];
    uint64_t    prp1;
    uint64_t    prp2;
    uint64_t    size;
    uint8_t     type;
    uint8_t     rsvd14[7];
    uint64_t    rsvd15;
} NvmeCsdAllocFdmCmd;

typedef struct QEMU_PACKED NvmeCsdDeallocAfdmCmd {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    nsid;
    uint64_t    rsvd2[2];
    uint64_t    prp1;
    uint64_t    prp2;
    uint32_t    id;
    uint32_t    rsvd11[5];
} NvmeCsdDeallocAfdmCmd;

typedef struct QEMU_PACKED NvmeCsdNvmToAfdmCmd {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    nsid;
    uint64_t    rsvd2[2];
    uint64_t    prp1;
    uint64_t    prp2;
    uint64_t    slba;
    uint16_t    nlb;
    uint16_t    rsvd12;
    uint32_t    id;
    uint64_t    offset;
} NvmeCsdNvmToAfdmCmd;

typedef struct QEMU_PACKED NvmeCsdExecCmd {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    nsid;
    uint64_t    rsvd2[2];
    uint64_t    prp1;
    uint64_t    prp2;
    uint32_t    csf_id;
    uint32_t    in_afdm_id;
    uint32_t    out_afdm_id;
    uint32_t    group;
    uint32_t    cparam1;
    uint32_t    runtime;
} NvmeCsdExecCmd;

typedef struct FemuCsdArgs {
    int numr;
    void **mr_addr;
    long long *mr_len;
    long long cparam1;
    long long cparam2;
    void *data_buffer;
    long long buffer_len;
} QEMU_PACKED FemuCsdArgs;

typedef struct QEMU_PACKED NvmeCsdReadAfdmCmd {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    nsid;
    uint64_t    rsvd2[2];
    uint64_t    prp1;
    uint64_t    prp2;
    uint64_t    offset;
    uint64_t    size;
    uint32_t    id;
    uint32_t    rsvd15;
} NvmeCsdReadAfdmCmd;

typedef struct QEMU_PACKED NvmeCsdWriteAfdmCmd {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    nsid;
    uint64_t    rsvd2[2];
    uint64_t    prp1;
    uint64_t    prp2;
    uint64_t    offset;
    uint64_t    size;
    uint32_t    id;
    uint32_t    rsvd15;
} NvmeCsdWriteAfdmCmd;

typedef struct QEMU_PACKED NvmeCsdCreateGroupCmd {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    nsid;
    uint64_t    rsvd2[2];
    uint64_t    prp1;
    uint64_t    prp2;
    int8_t      prio;
    uint8_t     qos_flags;
    uint16_t    rsvd10;
    uint32_t    bandwidth;
    uint32_t    deadline;
    uint32_t    rsvd14[3];
} NvmeCsdCreateGroupCmd;

typedef struct QEMU_PACKED NvmeCsdSetQosCmd {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    nsid;
    uint64_t    rsvd2[2];
    uint64_t    prp1;
    uint64_t    prp2;
    int8_t      prio;
    uint8_t     qos_flags;
    uint16_t    rsvd10;
    uint32_t    bandwidth;
    uint32_t    deadline;
    uint32_t    id;
    uint32_t    rsvd15[2];
} NvmeCsdSetQosCmd;

typedef struct QEMU_PACKED NvmeCsdDeleteGroupCmd {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    nsid;
    uint64_t    rsvd2[2];
    uint64_t    prp1;
    uint64_t    prp2;
    uint32_t    id;
    uint32_t    rsvd11[5];
} NvmeCsdDeleteGroupCmd;

#endif
