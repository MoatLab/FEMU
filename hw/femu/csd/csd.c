#include "qemu/osdep.h"
#include "qapi/error.h"
#include <gmodule.h>

#include "csd.h"

#ifdef CONFIG_FEMU_CSD_UBPF
#include <ubpf.h>
#endif

typedef int64_t (*FemuCsdSharedLibFn)(FemuCsdArgs *args);

typedef struct FemuCsdAfdm {
    uint32_t id;
    uint64_t size;
    uint8_t *data;
} FemuCsdAfdm;

typedef struct FemuCsdProgram {
    uint32_t id;
    uint8_t type;
    uint32_t runtime;
    uint16_t runtime_scale;
    uint64_t size;
    uint8_t *data;
    GModule *module;
    FemuCsdSharedLibFn shared_lib_fn;
#ifdef CONFIG_FEMU_CSD_UBPF
    struct ubpf_vm *ubpf_vm;
    ubpf_jit_fn ubpf_jit_fn;
#endif
} FemuCsdProgram;

typedef struct FemuCsdGroup {
    uint32_t id;
    int8_t prio;
    uint8_t qos_flags;
    uint32_t bandwidth;
    uint32_t deadline;
} FemuCsdGroup;

typedef struct FemuCsdState {
    CsdCtrlParams params;
    uint64_t fdm_capacity;
    uint64_t fdm_used;
    uint32_t next_afdm_id;
    uint32_t next_csf_id;
    uint32_t next_group_id;
    GHashTable *afdms;
    GHashTable *programs;
    GHashTable *groups;
    QemuMutex lock;
} FemuCsdState;

static void csd_check_size(void)
{
    QEMU_BUILD_BUG_ON(sizeof(NvmeCsdDownloadCmd) != 64);
    QEMU_BUILD_BUG_ON(sizeof(NvmeCsdAllocFdmCmd) != 64);
    QEMU_BUILD_BUG_ON(sizeof(NvmeCsdDeallocAfdmCmd) != 64);
    QEMU_BUILD_BUG_ON(sizeof(NvmeCsdNvmToAfdmCmd) != 64);
    QEMU_BUILD_BUG_ON(sizeof(NvmeCsdExecCmd) != 64);
    QEMU_BUILD_BUG_ON(sizeof(NvmeCsdReadAfdmCmd) != 64);
    QEMU_BUILD_BUG_ON(sizeof(NvmeCsdWriteAfdmCmd) != 64);
    QEMU_BUILD_BUG_ON(sizeof(NvmeCsdCreateGroupCmd) != 64);
    QEMU_BUILD_BUG_ON(sizeof(NvmeCsdSetQosCmd) != 64);
    QEMU_BUILD_BUG_ON(sizeof(NvmeCsdDeleteGroupCmd) != 64);
}

static FemuCsdState *csd_state(FemuCtrl *n)
{
    return n->ext_ops.state;
}

static void csd_afdm_free(gpointer opaque)
{
    FemuCsdAfdm *afdm = opaque;

    if (!afdm) {
        return;
    }

    g_free(afdm->data);
    g_free(afdm);
}

static void csd_program_unload(FemuCsdProgram *program)
{
    if (program->module) {
        g_module_close(program->module);
        program->module = NULL;
        program->shared_lib_fn = NULL;
    }

#ifdef CONFIG_FEMU_CSD_UBPF
    if (program->ubpf_vm) {
        ubpf_destroy(program->ubpf_vm);
        program->ubpf_vm = NULL;
        program->ubpf_jit_fn = NULL;
    }
#endif
}

static void csd_program_free(gpointer opaque)
{
    FemuCsdProgram *program = opaque;

    if (!program) {
        return;
    }

    csd_program_unload(program);
    g_free(program->data);
    g_free(program);
}

static void csd_init_ctrl_str(FemuCtrl *n)
{
    static int csd_id;
    const char *mn = "FEMU Computational Storage Controller";
    const char *sn = "vCSD";

    nvme_set_ctrl_name(n, mn, sn, &csd_id);
}

static void csd_init(FemuCtrl *n, Error **errp)
{
    FemuCsdState *csd;

    csd_check_size();

    if (n->csd_params.fdm_size_mb == 0) {
        error_setg(errp, "CSD mode requires fdm_size to be non-zero");
        return;
    }

    if (n->csd_params.fdm_size_mb > UINT64_MAX / MiB) {
        error_setg(errp, "CSD fdm_size is too large");
        return;
    }

    if (n->csd_params.nr_cu == 0 || n->csd_params.nr_cu > 64) {
        error_setg(errp, "CSD nr_cu must be in range [1, 64]");
        return;
    }

    if (n->csd_params.nr_thread == 0) {
        error_setg(errp, "CSD nr_thread must be non-zero");
        return;
    }

    if (n->csd_params.csf_runtime_scale == 0) {
        error_setg(errp, "CSD csf_runtime_scale must be non-zero");
        return;
    }

    csd_init_ctrl_str(n);

    csd = g_new0(FemuCsdState, 1);
    csd->params = n->csd_params;
    csd->fdm_capacity = n->csd_params.fdm_size_mb * MiB;
    csd->next_afdm_id = 1;
    csd->next_csf_id = 1;
    csd->next_group_id = 1;
    csd->afdms = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                                       csd_afdm_free);
    csd->programs = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                                          csd_program_free);
    csd->groups = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                                        g_free);
    qemu_mutex_init(&csd->lock);
    n->ext_ops.state = csd;

    femu_log("%s,CSD mode initialized: fdm=%" PRIu64 "MB, "
             "nr_cu=%u, nr_thread=%u\n",
             n->devname, csd->params.fdm_size_mb, csd->params.nr_cu,
             csd->params.nr_thread);
}

static void csd_exit(FemuCtrl *n)
{
    FemuCsdState *csd = csd_state(n);

    if (!csd) {
        return;
    }

    g_hash_table_destroy(csd->afdms);
    g_hash_table_destroy(csd->programs);
    g_hash_table_destroy(csd->groups);
    qemu_mutex_destroy(&csd->lock);
    g_free(csd);
    n->ext_ops.state = NULL;
}

static FemuCsdProgram *csd_get_program_locked(FemuCsdState *csd, uint32_t id)
{
    if (id == 0) {
        return NULL;
    }

    return g_hash_table_lookup(csd->programs, GUINT_TO_POINTER(id));
}

static FemuCsdAfdm *csd_get_afdm_locked(FemuCsdState *csd, uint32_t id)
{
    if (id == 0) {
        return NULL;
    }

    return g_hash_table_lookup(csd->afdms, GUINT_TO_POINTER(id));
}

static FemuCsdGroup *csd_get_group_locked(FemuCsdState *csd, uint32_t id)
{
    if (id == 0) {
        return NULL;
    }

    return g_hash_table_lookup(csd->groups, GUINT_TO_POINTER(id));
}

static uint16_t csd_check_afdm_range(FemuCsdAfdm *afdm, uint64_t offset,
                                     uint64_t size)
{
    if (!afdm || size == 0 || offset > afdm->size ||
        size > afdm->size - offset) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (size > UINT32_MAX) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    return NVME_SUCCESS;
}

static uint16_t csd_parse_program(FemuCsdProgram *program, const char **path,
                                  const char **symbol)
{
    char *name;
    size_t path_len;
    size_t symbol_len;

    if (!program->data || program->size < 3) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    name = memchr(program->data, '\0', program->size);
    if (!name || name == (char *)program->data) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    path_len = name - (char *)program->data;
    if (path_len + 1 >= program->size) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    *path = (const char *)program->data;
    *symbol = name + 1;
    symbol_len = strnlen(*symbol, program->size - path_len - 1);
    if (symbol_len == 0 || path_len + symbol_len + 2 > program->size) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    return NVME_SUCCESS;
}

static uint16_t csd_load_shared_lib(FemuCsdProgram *program)
{
    const char *path;
    const char *symbol;
    gpointer fn = NULL;
    uint16_t status;

    status = csd_parse_program(program, &path, &symbol);
    if (status) {
        return status;
    }

    program->module = g_module_open(path, G_MODULE_BIND_LOCAL);
    if (!program->module) {
        femu_err("CSD: failed to load shared library %s: %s\n", path,
                 g_module_error());
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (!g_module_symbol(program->module, symbol, &fn) || !fn) {
        femu_err("CSD: failed to find shared library symbol %s: %s\n", symbol,
                 g_module_error());
        csd_program_unload(program);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    program->shared_lib_fn = (FemuCsdSharedLibFn)fn;
    return NVME_SUCCESS;
}

static uint16_t csd_load_ubpf(FemuCsdProgram *program, bool jit)
{
#ifdef CONFIG_FEMU_CSD_UBPF
    const char *path;
    const char *symbol;
    g_autofree char *elf = NULL;
    gsize elf_size = 0;
    g_autoptr(GError) err = NULL;
    char *errmsg = NULL;
    uint16_t status;

    status = csd_parse_program(program, &path, &symbol);
    if (status) {
        return status;
    }

    if (!g_file_get_contents(path, &elf, &elf_size, &err)) {
        femu_err("CSD: failed to read uBPF program %s: %s\n", path,
                 err ? err->message : "unknown error");
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    program->ubpf_vm = ubpf_create();
    if (!program->ubpf_vm) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (ubpf_load_elf(program->ubpf_vm, elf, elf_size, symbol, &errmsg) < 0) {
        femu_err("CSD: failed to load uBPF ELF %s:%s: %s\n", path, symbol,
                 errmsg ? errmsg : "unknown error");
        free(errmsg);
        csd_program_unload(program);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (jit) {
        program->ubpf_jit_fn = ubpf_compile(program->ubpf_vm, &errmsg);
        if (!program->ubpf_jit_fn) {
            femu_err("CSD: failed to JIT uBPF ELF %s:%s: %s\n", path, symbol,
                     errmsg ? errmsg : "unknown error");
            free(errmsg);
            csd_program_unload(program);
            return NVME_INVALID_FIELD | NVME_DNR;
        }
    }

    return NVME_SUCCESS;
#else
    return NVME_INVALID_FIELD | NVME_DNR;
#endif
}

static uint16_t csd_download(FemuCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    FemuCsdState *csd = csd_state(n);
    NvmeCsdDownloadCmd *download = (NvmeCsdDownloadCmd *)cmd;
    uint64_t size = le64_to_cpu(download->size);
    uint64_t prp1 = le64_to_cpu(download->prp1);
    uint64_t prp2 = le64_to_cpu(download->prp2);
    FemuCsdProgram *program;
    uint32_t id;
    uint16_t status = NVME_SUCCESS;

    if (size > UINT32_MAX) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    switch (download->csf_type) {
    case NVME_CSD_CSF_TYPE_PHANTOM:
    case NVME_CSD_CSF_TYPE_EBPF:
    case NVME_CSD_CSF_TYPE_SHARED_LIB:
        break;
    default:
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    program = g_new0(FemuCsdProgram, 1);
    program->type = download->csf_type;
    program->runtime = le32_to_cpu(download->runtime);
    program->runtime_scale = le16_to_cpu(download->runtime_scale);
    program->size = size;

    if (size) {
        program->data = g_malloc0(size);
        status = dma_write_prp(n, program->data, size, prp1, prp2);
        if (status) {
            csd_program_free(program);
            return status | NVME_DNR;
        }
    }

    switch (program->type) {
    case NVME_CSD_CSF_TYPE_PHANTOM:
        break;
    case NVME_CSD_CSF_TYPE_SHARED_LIB:
        status = csd_load_shared_lib(program);
        break;
    case NVME_CSD_CSF_TYPE_EBPF:
        status = csd_load_ubpf(program, download->csf_flags & 0x1);
        break;
    default:
        status = NVME_INVALID_FIELD | NVME_DNR;
        break;
    }
    if (status) {
        csd_program_free(program);
        return status;
    }

    qemu_mutex_lock(&csd->lock);
    id = csd->next_csf_id++;
    if (id == 0) {
        csd->next_csf_id = 1;
        id = csd->next_csf_id++;
    }
    program->id = id;
    g_hash_table_insert(csd->programs, GUINT_TO_POINTER(id), program);
    qemu_mutex_unlock(&csd->lock);

    req->cqe.n.result = id;
    return NVME_SUCCESS;
}

static uint16_t csd_exec(FemuCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    FemuCsdState *csd = csd_state(n);
    NvmeCsdExecCmd *exec = (NvmeCsdExecCmd *)cmd;
    uint32_t csf_id = le32_to_cpu(exec->csf_id);
    uint32_t in_id = le32_to_cpu(exec->in_afdm_id);
    uint32_t out_id = le32_to_cpu(exec->out_afdm_id);
    uint32_t group_id = le32_to_cpu(exec->group);
    uint32_t cparam1 = le32_to_cpu(exec->cparam1);
    uint32_t runtime = le32_to_cpu(exec->runtime);
    FemuCsdProgram *program;
    FemuCsdAfdm *in = NULL;
    FemuCsdAfdm *out = NULL;
    uint64_t copy_size;
    void *mr_addr[2] = { 0 };
    long long mr_len[2] = { 0 };
    FemuCsdArgs args = { 0 };
    int64_t result = 0;
    uint16_t status = NVME_SUCCESS;

    qemu_mutex_lock(&csd->lock);
    program = csd_get_program_locked(csd, csf_id);
    if (!program) {
        qemu_mutex_unlock(&csd->lock);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (group_id != 0 && !csd_get_group_locked(csd, group_id)) {
        qemu_mutex_unlock(&csd->lock);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    in = in_id ? csd_get_afdm_locked(csd, in_id) : NULL;
    out = out_id ? csd_get_afdm_locked(csd, out_id) : NULL;
    if ((in_id && !in) || (out_id && !out)) {
        qemu_mutex_unlock(&csd->lock);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (runtime == 0) {
        runtime = program->runtime;
    }

    switch (program->type) {
    case NVME_CSD_CSF_TYPE_PHANTOM:
        if (in && out) {
            copy_size = MIN(in->size, out->size);
            memcpy(out->data, in->data, copy_size);
            result = copy_size > UINT32_MAX ? UINT32_MAX : copy_size;
        }
        break;
    case NVME_CSD_CSF_TYPE_SHARED_LIB:
        if (!program->shared_lib_fn || !in || !out) {
            status = NVME_INVALID_FIELD | NVME_DNR;
            break;
        }
        mr_addr[0] = out->data;
        mr_addr[1] = in->data;
        mr_len[0] = out->size;
        mr_len[1] = in->size;
        args.numr = 2;
        args.mr_addr = mr_addr;
        args.mr_len = mr_len;
        args.cparam1 = cparam1;
        result = program->shared_lib_fn(&args);
        break;
    case NVME_CSD_CSF_TYPE_EBPF:
#ifdef CONFIG_FEMU_CSD_UBPF
        if (!program->ubpf_vm || !in || !out) {
            status = NVME_INVALID_FIELD | NVME_DNR;
            break;
        }
        mr_addr[0] = out->data;
        mr_addr[1] = in->data;
        mr_len[0] = out->size;
        mr_len[1] = in->size;
        args.numr = 2;
        args.mr_addr = mr_addr;
        args.mr_len = mr_len;
        args.cparam1 = cparam1;
        if (program->ubpf_jit_fn) {
            result = program->ubpf_jit_fn(&args, sizeof(args));
        } else {
            uint64_t ubpf_result;

            if (ubpf_exec(program->ubpf_vm, &args, sizeof(args),
                          &ubpf_result) < 0) {
                status = NVME_INVALID_FIELD | NVME_DNR;
                break;
            }
            result = ubpf_result;
        }
#else
        status = NVME_INVALID_FIELD | NVME_DNR;
#endif
        break;
    default:
        status = NVME_INVALID_FIELD | NVME_DNR;
        break;
    }
    if (!status) {
        req->cqe.n.result = result > UINT32_MAX ? UINT32_MAX : result;
    }
    qemu_mutex_unlock(&csd->lock);

    if (status) {
        return status;
    }

    if (runtime) {
        req->reqlat += runtime;
        req->expire_time += runtime;
    }

    return NVME_SUCCESS;
}

static uint16_t csd_normalize_prio(int8_t *prio)
{
    if (*prio == 0) {
        *prio = 5;
    }

    if (*prio < 1 || *prio > 9) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    return NVME_SUCCESS;
}

static uint16_t csd_create_group(FemuCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    FemuCsdState *csd = csd_state(n);
    NvmeCsdCreateGroupCmd *create = (NvmeCsdCreateGroupCmd *)cmd;
    FemuCsdGroup *group;
    uint32_t id;
    int8_t prio = create->prio;
    uint16_t status;

    status = csd_normalize_prio(&prio);
    if (status) {
        return status;
    }

    group = g_new0(FemuCsdGroup, 1);
    group->prio = prio;
    group->qos_flags = create->qos_flags;
    group->bandwidth = le32_to_cpu(create->bandwidth);
    group->deadline = le32_to_cpu(create->deadline);

    qemu_mutex_lock(&csd->lock);
    id = csd->next_group_id++;
    if (id == 0) {
        csd->next_group_id = 1;
        id = csd->next_group_id++;
    }
    group->id = id;
    g_hash_table_insert(csd->groups, GUINT_TO_POINTER(id), group);
    qemu_mutex_unlock(&csd->lock);

    req->cqe.n.result = id;
    return NVME_SUCCESS;
}

static uint16_t csd_set_qos(FemuCtrl *n, NvmeCmd *cmd)
{
    FemuCsdState *csd = csd_state(n);
    NvmeCsdSetQosCmd *set = (NvmeCsdSetQosCmd *)cmd;
    uint32_t id = le32_to_cpu(set->id);
    int8_t prio = set->prio;
    FemuCsdGroup *group;
    uint16_t status;

    status = csd_normalize_prio(&prio);
    if (status) {
        return status;
    }

    qemu_mutex_lock(&csd->lock);
    group = csd_get_group_locked(csd, id);
    if (!group) {
        qemu_mutex_unlock(&csd->lock);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    group->prio = prio;
    group->qos_flags = set->qos_flags;
    group->bandwidth = le32_to_cpu(set->bandwidth);
    group->deadline = le32_to_cpu(set->deadline);
    qemu_mutex_unlock(&csd->lock);

    return NVME_SUCCESS;
}

static uint16_t csd_delete_group(FemuCtrl *n, NvmeCmd *cmd)
{
    FemuCsdState *csd = csd_state(n);
    NvmeCsdDeleteGroupCmd *delete = (NvmeCsdDeleteGroupCmd *)cmd;
    uint32_t id = le32_to_cpu(delete->id);

    qemu_mutex_lock(&csd->lock);
    if (!csd_get_group_locked(csd, id)) {
        qemu_mutex_unlock(&csd->lock);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    g_hash_table_remove(csd->groups, GUINT_TO_POINTER(id));
    qemu_mutex_unlock(&csd->lock);

    return NVME_SUCCESS;
}

static uint16_t csd_alloc_fdm(FemuCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    FemuCsdState *csd = csd_state(n);
    NvmeCsdAllocFdmCmd *alloc = (NvmeCsdAllocFdmCmd *)cmd;
    FemuCsdAfdm *afdm;
    uint64_t size = le64_to_cpu(alloc->size);
    uint32_t id;

    if (alloc->type != NVME_CSD_FDM_TYPE_HOST || size == 0) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    qemu_mutex_lock(&csd->lock);
    if (size > csd->fdm_capacity - csd->fdm_used) {
        qemu_mutex_unlock(&csd->lock);
        return NVME_CAP_EXCEEDED | NVME_DNR;
    }

    id = csd->next_afdm_id++;
    if (id == 0) {
        csd->next_afdm_id = 1;
        id = csd->next_afdm_id++;
    }

    afdm = g_new0(FemuCsdAfdm, 1);
    afdm->id = id;
    afdm->size = size;
    afdm->data = g_malloc0(size);

    g_hash_table_insert(csd->afdms, GUINT_TO_POINTER(id), afdm);
    csd->fdm_used += size;
    qemu_mutex_unlock(&csd->lock);

    req->cqe.n.result = id;
    return NVME_SUCCESS;
}

static uint16_t csd_dealloc_afdm(FemuCtrl *n, NvmeCmd *cmd)
{
    FemuCsdState *csd = csd_state(n);
    NvmeCsdDeallocAfdmCmd *dealloc = (NvmeCsdDeallocAfdmCmd *)cmd;
    uint32_t id = le32_to_cpu(dealloc->id);
    FemuCsdAfdm *afdm;

    qemu_mutex_lock(&csd->lock);
    afdm = csd_get_afdm_locked(csd, id);
    if (!afdm) {
        qemu_mutex_unlock(&csd->lock);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    csd->fdm_used -= afdm->size;
    g_hash_table_remove(csd->afdms, GUINT_TO_POINTER(id));
    qemu_mutex_unlock(&csd->lock);

    return NVME_SUCCESS;
}

static uint16_t csd_read_afdm(FemuCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    FemuCsdState *csd = csd_state(n);
    NvmeCsdReadAfdmCmd *read = (NvmeCsdReadAfdmCmd *)cmd;
    uint32_t id = le32_to_cpu(read->id);
    uint64_t offset = le64_to_cpu(read->offset);
    uint64_t size = le64_to_cpu(read->size);
    uint64_t prp1 = le64_to_cpu(read->prp1);
    uint64_t prp2 = le64_to_cpu(read->prp2);
    FemuCsdAfdm *afdm;
    uint16_t status;

    qemu_mutex_lock(&csd->lock);
    afdm = csd_get_afdm_locked(csd, id);
    status = csd_check_afdm_range(afdm, offset, size);
    if (!status) {
        status = dma_read_prp(n, afdm->data + offset, size, prp1, prp2);
    }
    qemu_mutex_unlock(&csd->lock);

    if (status) {
        return status | NVME_DNR;
    }

    req->cqe.n.result = size;
    return NVME_SUCCESS;
}

static uint16_t csd_write_afdm(FemuCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    FemuCsdState *csd = csd_state(n);
    NvmeCsdWriteAfdmCmd *write = (NvmeCsdWriteAfdmCmd *)cmd;
    uint32_t id = le32_to_cpu(write->id);
    uint64_t offset = le64_to_cpu(write->offset);
    uint64_t size = le64_to_cpu(write->size);
    uint64_t prp1 = le64_to_cpu(write->prp1);
    uint64_t prp2 = le64_to_cpu(write->prp2);
    FemuCsdAfdm *afdm;
    uint16_t status;

    qemu_mutex_lock(&csd->lock);
    afdm = csd_get_afdm_locked(csd, id);
    status = csd_check_afdm_range(afdm, offset, size);
    if (!status) {
        status = dma_write_prp(n, afdm->data + offset, size, prp1, prp2);
    }
    qemu_mutex_unlock(&csd->lock);

    if (status) {
        return status | NVME_DNR;
    }

    req->cqe.n.result = size;
    return NVME_SUCCESS;
}

static uint16_t csd_nvm_to_afdm(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                                NvmeRequest *req)
{
    FemuCsdState *csd = csd_state(n);
    NvmeCsdNvmToAfdmCmd *copy = (NvmeCsdNvmToAfdmCmd *)cmd;
    const uint8_t lba_index = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    const uint8_t data_shift = ns->id_ns.lbaf[lba_index].lbads;
    uint32_t id = le32_to_cpu(copy->id);
    uint64_t offset = le64_to_cpu(copy->offset);
    uint64_t slba = le64_to_cpu(copy->slba);
    uint64_t nlb = le16_to_cpu(copy->nlb) + 1;
    uint64_t size = nlb << data_shift;
    uint64_t nvm_offset = slba << data_shift;
    FemuCsdAfdm *afdm;
    uint16_t status;

    if (slba + nlb > le64_to_cpu(ns->id_ns.nsze) ||
        nvm_offset > n->mbe->size || size > n->mbe->size - nvm_offset) {
        return NVME_LBA_RANGE | NVME_DNR;
    }

    qemu_mutex_lock(&csd->lock);
    afdm = csd_get_afdm_locked(csd, id);
    status = csd_check_afdm_range(afdm, offset, size);
    if (!status) {
        memcpy(afdm->data + offset,
               (uint8_t *)n->mbe->logical_space + nvm_offset, size);
    }
    qemu_mutex_unlock(&csd->lock);

    if (status) {
        return status;
    }

    req->cqe.n.result = size;
    return NVME_SUCCESS;
}

static uint16_t csd_io_cmd(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                           NvmeRequest *req)
{
    switch (cmd->opcode) {
    case NVME_CMD_READ:
    case NVME_CMD_WRITE:
        return nvme_rw(n, ns, cmd, req);
    case NVME_CMD_CSD_DOWNLOAD:
        return csd_download(n, cmd, req);
    case NVME_CMD_CSD_ALLOC_FDM:
        return csd_alloc_fdm(n, cmd, req);
    case NVME_CMD_CSD_DEALLOC_AFDM:
        return csd_dealloc_afdm(n, cmd);
    case NVME_CMD_CSD_NVM_TO_AFDM:
        return csd_nvm_to_afdm(n, ns, cmd, req);
    case NVME_CMD_CSD_EXEC:
        return csd_exec(n, cmd, req);
    case NVME_CMD_CSD_READ_AFDM:
        return csd_read_afdm(n, cmd, req);
    case NVME_CMD_CSD_WRITE_AFDM:
        return csd_write_afdm(n, cmd, req);
    case NVME_CMD_CSD_CREATE_GROUP:
        return csd_create_group(n, cmd, req);
    case NVME_CMD_CSD_SET_QOS:
        return csd_set_qos(n, cmd);
    case NVME_CMD_CSD_DELETE_GROUP:
        return csd_delete_group(n, cmd);
    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

int nvme_register_csd(FemuCtrl *n)
{
    n->ext_ops = (FemuExtCtrlOps) {
        .state            = NULL,
        .init             = csd_init,
        .exit             = csd_exit,
        .rw_check_req     = NULL,
        .start_ctrl       = NULL,
        .admin_cmd        = NULL,
        .io_cmd           = csd_io_cmd,
        .get_log          = NULL,
    };

    return 0;
}
