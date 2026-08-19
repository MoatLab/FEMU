#include "qemu/osdep.h"

#include "kvssd.h"
#include "../nvme.h"

/*
 * KV admin: the Key Value Command Set Identify data structures and the Key Value
 * Configuration feature. Per NVMe-KV 1.3 section 4.1.5, a KV namespace is
 * discovered via CNS 05h/06h/0Ah with CSI=01h. These builders are called from the
 * controller's Identify handler (nvme-admin.c) when CSI==NVME_CSI_KV.
 */

/* Figure 42: KV Format Data Structure (16 bytes) */
typedef struct QEMU_PACKED NvmeKvFormat {
    uint16_t kv_key_max_len;           /* KVKML: max key bytes (<=16) */
    uint8_t  rsvd2;
    uint8_t  afo;                       /* Additional Format Options / RP */
    uint32_t kv_value_max_len;          /* KVVML: max value bytes */
    uint32_t max_num_keys;              /* MNKS: 0 = no max */
    uint32_t rsvd12;
} NvmeKvFormat;

/* Figure 41: I/O Command Set specific Identify Namespace, Key Value (4096 bytes) */
typedef struct QEMU_PACKED NvmeIdNsKv {
    uint64_t nsze;                      /* total namespace size in BYTES */
    uint64_t ncap;                      /* unused for KV reporting -> capacity bytes */
    uint64_t nuse;                      /* bytes in use for keys+values */
    uint8_t  nsfeat;
    uint8_t  nkvf;                      /* number of KV formats, 0's based */
    uint8_t  nmic;
    uint8_t  rescap;
    uint8_t  fpi;
    uint8_t  kvfc;                      /* KV format capabilities: [3:0]=format index */
    uint8_t  rsvd30[2];
    uint32_t novg;                      /* optimal value granularity */
    uint8_t  rsvd36[36];               /* ANAGRPID..EUI64 (unsupported -> 0) */
    NvmeKvFormat kvf[16];              /* bytes 72..327: KV Format 0..15 */
    uint8_t  rsvd328[3512];
    uint8_t  vs[256];
} NvmeIdNsKv;

/* Figure 43/44: I/O Command Set specific Identify Controller, Key Value */
typedef struct QEMU_PACKED NvmeIdCtrlKv {
    uint8_t  ver_ter;                  /* VER: Specification Version Descriptor */
    uint8_t  ver_mnr;
    uint16_t ver_mjr;
    uint8_t  rsvd4[4092];
} NvmeIdCtrlKv;

QEMU_BUILD_BUG_ON(sizeof(NvmeKvFormat) != 16);
QEMU_BUILD_BUG_ON(sizeof(NvmeIdNsKv) != 4096);
QEMU_BUILD_BUG_ON(sizeof(NvmeIdCtrlKv) != 4096);
QEMU_BUILD_BUG_ON(offsetof(NvmeIdNsKv, nsze) != 0);
QEMU_BUILD_BUG_ON(offsetof(NvmeIdNsKv, nkvf) != 25);
QEMU_BUILD_BUG_ON(offsetof(NvmeIdNsKv, kvfc) != 29);
QEMU_BUILD_BUG_ON(offsetof(NvmeIdNsKv, kvf) != 72);

static void kvssd_fill_id_ns(FemuKvssdState *s, NvmeIdNsKv *id)
{
    memset(id, 0, sizeof(*id));
    id->nsze = cpu_to_le64(s->value_capacity);
    id->ncap = cpu_to_le64(s->value_capacity);
    id->nuse = cpu_to_le64(s->value_used + s->key_used);
    id->nkvf = 0;                      /* one KV format (0's based) */
    id->kvfc = 0;                      /* formatted with KV Format Index 0 */
    /* KV Format 0: the active format */
    id->kvf[0].kv_key_max_len = cpu_to_le16((uint16_t)s->kv_key_max);
    id->kvf[0].kv_value_max_len = cpu_to_le32(s->kv_value_max);
    id->kvf[0].max_num_keys = cpu_to_le32((uint32_t)s->kv_max_keys);
}

uint16_t kvssd_identify_ns_csi(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd)
{
    FemuKvssdState *s = (n->femu_mode == FEMU_KVSSD_MODE) ?
                        n->ext_ops.state : ns->ext_ops.state;
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);
    NvmeIdNsKv id;

    if (!s) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    qemu_mutex_lock(&s->lock);
    kvssd_fill_id_ns(s, &id);
    qemu_mutex_unlock(&s->lock);
    return dma_read_prp(n, (uint8_t *)&id, sizeof(id), prp1, prp2);
}

uint16_t kvssd_identify_ctrl_csi(FemuCtrl *n, NvmeCmd *cmd)
{
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);
    NvmeIdCtrlKv id = {};

    /* Version 1.3 (MJR=1, MNR=3, TER=0) per Figure 44 */
    id.ver_mjr = cpu_to_le16(1);
    id.ver_mnr = 3;
    id.ver_ter = 0;
    return dma_read_prp(n, (uint8_t *)&id, sizeof(id), prp1, prp2);
}

/*
 * CNS 0Ah: I/O Command Set specific Identify Namespace for a Format Index. FEMU
 * exposes a single KV format, so report it for index 0 (CNS-specific identifier
 * in CDW11[15:0]); other indices return a zeroed structure per spec.
 */
uint16_t kvssd_identify_ns_csi_fmt(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd)
{
    FemuKvssdState *s = (n->femu_mode == FEMU_KVSSD_MODE) ?
                        n->ext_ops.state : (ns ? ns->ext_ops.state : NULL);
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);
    uint16_t fidx = le32_to_cpu(cmd->cdw11) & 0xffff;
    NvmeIdNsKv id;

    if (!s) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    memset(&id, 0, sizeof(id));
    if (fidx == 0) {
        qemu_mutex_lock(&s->lock);
        kvssd_fill_id_ns(s, &id);
        qemu_mutex_unlock(&s->lock);
        id.nuse = 0;                   /* format-index query: NUSE not meaningful */
    }
    return dma_read_prp(n, (uint8_t *)&id, sizeof(id), prp1, prp2);
}

/* Key Value Configuration feature (20h): EDNEK in CDW11[0]. (FID in nvme.h) */
#define NVME_KV_CFG_EDNEK   (1u << 0)

uint16_t kvssd_set_feature(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                           NvmeCqe *cqe)
{
    FemuKvssdState *s = (n->femu_mode == FEMU_KVSSD_MODE) ?
                        n->ext_ops.state : (ns ? ns->ext_ops.state : NULL);
    uint32_t dw11 = le32_to_cpu(cmd->cdw11);

    if (!s) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    qemu_mutex_lock(&s->lock);
    s->ednek = (dw11 & NVME_KV_CFG_EDNEK) != 0;
    qemu_mutex_unlock(&s->lock);
    cqe->n.result = cpu_to_le32(0);
    return NVME_SUCCESS;
}

uint16_t kvssd_get_feature(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                           NvmeCqe *cqe)
{
    FemuKvssdState *s = (n->femu_mode == FEMU_KVSSD_MODE) ?
                        n->ext_ops.state : (ns ? ns->ext_ops.state : NULL);

    if (!s) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    qemu_mutex_lock(&s->lock);
    cqe->n.result = cpu_to_le32(s->ednek ? NVME_KV_CFG_EDNEK : 0);
    qemu_mutex_unlock(&s->lock);
    return NVME_SUCCESS;
}

/* No KV-specific admin command needs the generic fallback path today. */
uint16_t kvssd_admin_cmd(FemuCtrl *n, NvmeCmd *cmd)
{
    (void)n;
    (void)cmd;
    return NVME_INVALID_OPCODE | NVME_DNR;
}
