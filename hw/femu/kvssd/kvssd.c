#include "qemu/osdep.h"

#include "kvssd.h"
#include "../nvme.h"
#include "../bbssd/ftl.h"

/*
 * FEMU Key Value SSD mode.
 *
 * Interface: NVM Express Key Value Command Set Specification, Revision 1.3 (the
 * spec is the ground truth for wire behavior). Commands use the Common Command
 * Format: the KV key lives in CDW2/CDW3 (key[63:0]) and CDW14/CDW15 (key[127:64]),
 * Key Length in CDW11[7:0], Value Size / Host Buffer Size in CDW10, command
 * options in CDW11[15:8], and the value buffer via the standard DPTR (PRP/SGL).
 *
 * Firmware: a small KV-FTL (kvssd-ftl.c) owns the key->location index and the
 * value-space allocator, and charges every value page through FEMU's NAND media
 * model (channels/LUNs/planes) so KV latency reflects flash internals, not a flat
 * constant. This file is the controller layer: parse + validate per spec, then
 * call the FTL.
 */

/* NVMe-KV 1.3 Figure 5: opcodes for the Key Value Command Set */
enum NvmeKvOpcode {
    NVME_KV_CMD_STORE    = 0x01,
    NVME_KV_CMD_RETRIEVE = 0x02,
    NVME_KV_CMD_LIST     = 0x06,
    NVME_KV_CMD_DELETE   = 0x10,
    NVME_KV_CMD_EXIST    = 0x14,
};

/* Store Option (CDW11[15:8]) bits (Figure 30) */
#define NVME_KV_STORE_SIKE   (1 << 0)   /* bit 8: store only if key exists */
#define NVME_KV_STORE_SINKE  (1 << 1)   /* bit 9: store only if key absent */
#define NVME_KV_STORE_NOCOMP (1 << 2)   /* bit 10: no compression */

#define NVME_KV_MAX_KEY_LEN  16         /* spec: max KV key is 16 bytes */

/*
 * Spec command view over the Common Command Format. The KV key is split across
 * CDW2/3 (low) and CDW14/15 (high); NvmeCmd packs CDW2+CDW3 into the res2 field.
 */
static void kv_get_key(const NvmeCmd *cmd, uint8_t key[NVME_KV_MAX_KEY_LEN])
{
    uint64_t lo = le64_to_cpu(cmd->res2);                 /* CDW2 | CDW3<<32 */
    uint64_t hi = ((uint64_t)le32_to_cpu(cmd->cdw15) << 32) |
                  le32_to_cpu(cmd->cdw14);                /* CDW14 | CDW15<<32 */

    stq_le_p(key, lo);
    stq_le_p(key + 8, hi);
}

static inline uint8_t kv_key_len(const NvmeCmd *cmd)
{
    return le32_to_cpu(cmd->cdw11) & 0xff;                /* CDW11[7:0] */
}

static inline uint8_t kv_store_option(const NvmeCmd *cmd)
{
    return (le32_to_cpu(cmd->cdw11) >> 8) & 0xff;         /* CDW11[15:8] */
}

static inline uint32_t kv_value_size(const NvmeCmd *cmd)
{
    return le32_to_cpu(cmd->cdw10);                       /* CDW10: VS / HBS, bytes */
}

FemuKvssdState *kvssd_ns_state(FemuCtrl *n, NvmeNamespace *ns)
{
    if (ns && ns->ext_ops.state) {
        return ns->ext_ops.state;
    }
    return n->ext_ops.state;
}

static FemuKvssdState *kvssd_state(FemuCtrl *n, NvmeNamespace *ns)
{
    return kvssd_ns_state(n, ns);
}

/*
 * Validate the common KV key fields and copy the key out. Per spec, a key length
 * greater than 16 is aborted with Invalid Field in Command; a key size of 0 is an
 * invalid key size for the commands that key on a value.
 */
static uint16_t kv_load_key(const NvmeCmd *cmd, uint8_t key[NVME_KV_MAX_KEY_LEN],
                            uint8_t *key_len)
{
    uint8_t kl = kv_key_len(cmd);

    if (kl > NVME_KV_MAX_KEY_LEN) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (kl == 0) {
        return NVME_KV_INVALID_KEY_SIZE | NVME_DNR;
    }
    kv_get_key(cmd, key);
    *key_len = kl;
    return NVME_SUCCESS;
}

static uint16_t kvssd_store(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                            NvmeRequest *req)
{
    FemuKvssdState *kvssd = kvssd_state(n, ns);
    uint8_t key[NVME_KV_MAX_KEY_LEN];
    uint8_t key_len = 0;
    uint8_t opt = kv_store_option(cmd);
    uint32_t vsize = kv_value_size(cmd);
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);
    bool sike = opt & NVME_KV_STORE_SIKE;
    bool sinke = opt & NVME_KV_STORE_SINKE;
    uint16_t status;

    if (!kvssd) {
        return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }

    status = kv_load_key(cmd, key, &key_len);
    if (status) {
        return status;
    }
    if (vsize > kvssd_ftl_max_value(kvssd)) {
        return NVME_KV_INVALID_VALUE_SIZE | NVME_DNR;
    }

    /* The FTL allocates value space, drives the host DMA, programs NAND (and
     * charges its latency on req), and commits the index. */
    status = kvssd_ftl_store(n, kvssd, req, key, key_len, vsize, prp1, prp2,
                             sike, sinke);
    if (status) {
        return status;
    }

    req->cqe.n.result = cpu_to_le32(vsize);
    return NVME_SUCCESS;
}

static uint16_t kvssd_retrieve(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                               NvmeRequest *req)
{
    FemuKvssdState *kvssd = kvssd_state(n, ns);
    uint8_t key[NVME_KV_MAX_KEY_LEN];
    uint8_t key_len = 0;
    uint32_t hbs = kv_value_size(cmd);     /* CDW10 = Host Buffer Size */
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);
    uint32_t full_len = 0;
    uint16_t status;

    if (!kvssd) {
        return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }
    status = kv_load_key(cmd, key, &key_len);
    if (status) {
        return status;
    }

    status = kvssd_ftl_retrieve(n, kvssd, req, key, key_len, hbs, prp1, prp2,
                                &full_len);
    if (status) {
        return status;
    }

    /*
     * Spec: CQE Dword0 reports the FULL KV value size in bytes. If HBS < value,
     * the host receives the leading HBS bytes and re-issues with a larger buffer.
     */
    req->cqe.n.result = cpu_to_le32(full_len);
    return NVME_SUCCESS;
}

static uint16_t kvssd_delete(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                             NvmeRequest *req)
{
    FemuKvssdState *kvssd = kvssd_state(n, ns);
    uint8_t key[NVME_KV_MAX_KEY_LEN];
    uint8_t key_len = 0;
    bool deleted;
    uint16_t status;

    if (!kvssd) {
        return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }
    status = kv_load_key(cmd, key, &key_len);
    if (status) {
        return status;
    }

    deleted = kvssd_ftl_delete(n, kvssd, req, key, key_len);
    if (!deleted) {
        bool ednek;

        qemu_mutex_lock(&kvssd->lock);
        ednek = kvssd->ednek;
        qemu_mutex_unlock(&kvssd->lock);
        /*
         * Delete of a non-existent key: behavior is gated by the EDNEK bit of the
         * Key Value Configuration feature (20h). EDNEK=1 -> abort KV Key Does Not
         * Exist; EDNEK=0 -> complete successfully as if it existed and was deleted.
         */
        if (ednek) {
            return NVME_KV_KEY_NOT_EXIST | NVME_DNR;
        }
    }
    return NVME_SUCCESS;
}

static uint16_t kvssd_exist(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                            NvmeRequest *req)
{
    FemuKvssdState *kvssd = kvssd_state(n, ns);
    uint8_t key[NVME_KV_MAX_KEY_LEN];
    uint8_t key_len = 0;
    uint16_t status;

    if (!kvssd) {
        return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }
    status = kv_load_key(cmd, key, &key_len);
    if (status) {
        return status;
    }

    return kvssd_ftl_exist(n, kvssd, req, key, key_len);
}

/*
 * List: return KV keys present in the namespace starting at the specified key,
 * up to the host buffer size (CDW10). Return structure (Figure 15/16): a 4-byte
 * Number of Returned Keys (NRK) header, then per-key {2-byte Key Length, key
 * bytes}; the whole structure is padded to a 4-byte boundary.
 */
static uint16_t kvssd_list(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                           NvmeRequest *req)
{
    FemuKvssdState *kvssd = kvssd_state(n, ns);
    uint8_t start_key[NVME_KV_MAX_KEY_LEN];
    uint8_t kl = kv_key_len(cmd);
    uint8_t start_len = kl;
    uint32_t hbs = kv_value_size(cmd);
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);

    if (!kvssd) {
        return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }
    if (kl > NVME_KV_MAX_KEY_LEN) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    kv_get_key(cmd, start_key);

    return kvssd_ftl_list(n, kvssd, req, start_key, start_len, hbs, prp1, prp2);
}

static uint16_t kvssd_io_cmd(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                             NvmeRequest *req)
{
    /* Spec: NSID FFFFFFFFh is not supported for KV I/O commands. */
    if (le32_to_cpu(cmd->nsid) == NVME_NSID_BROADCAST) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    switch (cmd->opcode) {
    case NVME_KV_CMD_STORE:
        return kvssd_store(n, ns, cmd, req);
    case NVME_KV_CMD_RETRIEVE:
        return kvssd_retrieve(n, ns, cmd, req);
    case NVME_KV_CMD_LIST:
        return kvssd_list(n, ns, cmd, req);
    case NVME_KV_CMD_DELETE:
        return kvssd_delete(n, ns, cmd, req);
    case NVME_KV_CMD_EXIST:
        return kvssd_exist(n, ns, cmd, req);
    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

static void kvssd_init_ctrl_str(FemuCtrl *n)
{
    static int kvssd_id;
    const char *mn = "FEMU KV-SSD Controller";
    const char *sn = "vKVSSD";

    nvme_set_ctrl_name(n, mn, sn, &kvssd_id);
}

static void kvssd_init(FemuCtrl *n, NvmeNamespace *ns, Error **errp)
{
    FemuKvssdState *kvssd;

    /* Same shared geometry, same bounds check as bbssd (see csd_init). */
    if (bb_check_geometry(n, errp)) {
        return;
    }

    /*
     * Every namespace running the KV command set reports it, whether or not it
     * is the first one brought up, and owns its own key space and value store.
     * The store is sized from the namespace, so one per namespace is what the
     * capacity accounting already assumes.
     */
    ns->csi = NVME_CSI_KV;

    if (ns->ext_ops.state) {
        return;
    }

    kvssd = kvssd_ftl_alloc(n, ns, errp);
    if (!kvssd) {
        return;
    }

    ns->ext_ops.state = kvssd;
    /* the first KV namespace also answers admin paths that name none */
    if (!n->ext_ops.state) {
        n->ext_ops.state = kvssd;
    }

    if (ns == &n->namespaces[0]) {
        kvssd_init_ctrl_str(n);
    }
}

static void kvssd_exit(FemuCtrl *n)
{
    int i, j;

    /*
     * Each KV namespace owns its state, so free them all rather than only the
     * one the controller points at. A state can be reached from more than one
     * namespace pointer only if something aliased them, so clear every matching
     * pointer before freeing to keep this safe against that.
     */
    for (i = 0; i < n->num_namespaces; i++) {
        FemuKvssdState *kvssd = n->namespaces[i].ext_ops.state;

        if (!kvssd) {
            continue;
        }
        for (j = i; j < n->num_namespaces; j++) {
            if (n->namespaces[j].ext_ops.state == kvssd) {
                n->namespaces[j].ext_ops.state = NULL;
            }
        }
        if (n->ext_ops.state == kvssd) {
            n->ext_ops.state = NULL;
        }
        kvssd_ftl_free(kvssd);
    }
    n->ext_ops.state = NULL;
}

int nvme_register_kvssd(FemuCtrl *n)
{
    n->ext_ops = (FemuExtCtrlOps) {
        .state            = NULL,
        .init             = kvssd_init,
        .exit             = kvssd_exit,
        .rw_check_req     = NULL,
        .start_ctrl       = NULL,
        .admin_cmd        = kvssd_admin_cmd,
        .admin_cmd_cqe    = NULL,
        .io_cmd           = kvssd_io_cmd,
        .get_log          = NULL,
    };

    return 0;
}
