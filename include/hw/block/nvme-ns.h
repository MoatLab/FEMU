#ifndef NVME_NS_H
#define NVME_NS_H

#include "hw/block/block.h"

#define TYPE_NVME_NS "nvme-ns"
#define NVME_NS(obj) \
    OBJECT_CHECK(NvmeNamespace, (obj), TYPE_NVME_NS)

#define DEFINE_NVME_NS_PROPERTIES(_state, _props) \
    DEFINE_PROP_UINT32("nsid", _state, _props.nsid, 0), \
    DEFINE_PROP_UINT8("ms", _state, _props.ms, 0)

typedef struct NvmeNamespaceParams {
    uint32_t nsid;
    uint8_t  ms;
} NvmeNamespaceParams;

typedef struct NvmeNamespace {
    DeviceState parent_obj;
    BlockConf   conf;
    int64_t     size;
    uint64_t    blk_offset;
    uint64_t    blk_offset_md;

    NvmeIdNs            id_ns;
    NvmeNamespaceParams params;
} NvmeNamespace;

static inline uint8_t nvme_ns_lbads(NvmeNamespace *ns)
{
    NvmeIdNs *id = &ns->id_ns;
    return id->lbaf[NVME_ID_NS_FLBAS_INDEX(id->flbas)].ds;
}

static inline size_t nvme_ns_lbads_bytes(NvmeNamespace *ns)
{
    return 1 << nvme_ns_lbads(ns);
}

static inline uint16_t nvme_ns_ms(NvmeNamespace *ns)
{
    NvmeIdNs *id = &ns->id_ns;
    return le16_to_cpu(id->lbaf[NVME_ID_NS_FLBAS_INDEX(id->flbas)].ms);
}

int nvme_ns_init_blk(NvmeNamespace *ns, NvmeIdCtrl *id, Error **errp);
void nvme_ns_init_identify(NvmeNamespace *ns);
int nvme_ns_check_constraints(NvmeNamespace *ns, Error **errp);

#endif /* NVME_NS_H */
