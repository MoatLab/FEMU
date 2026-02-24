/*
 * CCA (Cylon Caching API) shared memory layout for ivshmem.
 * Must match cca-lib/include/cca_layout.h.
 */
#ifndef FEMU_CYLON_CCA_SHMEM_H
#define FEMU_CYLON_CCA_SHMEM_H

#include "qemu/osdep.h"

#define CCA_SHMEM_MAGIC  0x43434131
#define CCA_LAYOUT_VERSION  1
#define CCA_RING_COUNT  2048

enum cca_ctrl_cmd {
    CCA_CTRL_NOP = 0,
    CCA_CTRL_CACHE_ENABLE,
    CCA_CTRL_CACHE_DISABLE,
    CCA_CTRL_PIN,
    CCA_CTRL_UNPIN,
    CCA_CTRL_INVALIDATE,
    CCA_CTRL_MAX
};

struct cca_ctrl_cmd_s {
    uint32_t cmd;
    uint32_t reserved;
    uint64_t lpn_start;
    uint64_t lpn_count;
};

struct cca_ctrl_resp_s {
    int32_t  status;
    uint32_t reserved;
    uint64_t lpn_start;
    uint64_t lpn_count;
};

struct cca_ctrl_slot_s {
    struct cca_ctrl_cmd_s  cmd;
    struct cca_ctrl_resp_s resp;
};

struct cca_shmem_header {
    uint32_t magic;
    uint32_t version;
    uint32_t ring_count;
    uint32_t _pad;
    uint64_t offset_ctrl_req_ring;
    uint64_t offset_ctrl_resp_ring;
    uint64_t offset_ctrl_slot_pool;
    uint64_t offset_req_ring;
    uint64_t offset_resp_ring;
    uint64_t offset_req_pool;
    uint64_t offset_data_region;
    uint64_t size_data_region;
};

#endif
