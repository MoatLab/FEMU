#include "qemu/osdep.h"
#include "qapi/error.h"
#include <gmodule.h>

#include "csd.h"
#include "../bbssd/ftl.h"

#ifdef CONFIG_FEMU_CSD_UBPF
#include <ubpf.h>
#endif

typedef int64_t (*FemuCsdSharedLibFn)(FemuCsdArgs *args);

#define CSD_EXEC_DATA_MAX (1U << 20)

typedef struct FemuCsdAfdm {
    uint32_t id;
    uint64_t size;
    uint8_t *data;
} FemuCsdAfdm;

typedef struct FemuCsdProgram {
    uint32_t id;
    uint8_t type;
    bool active;
    bool indirect;
    bool loading;
    uint32_t runtime;
    uint16_t runtime_scale;
    uint64_t size;
    uint64_t load_size;
    uint64_t pid;
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
    uint32_t next_group_id;
    GHashTable *afdms;
    GHashTable *programs;
    GHashTable *groups;
    QemuMutex lock;
} FemuCsdState;

static void csd_check_size(void)
{
    QEMU_BUILD_BUG_ON(sizeof(NvmeCsdAllocFdmCmd) != 64);
    QEMU_BUILD_BUG_ON(sizeof(NvmeCsdDeallocAfdmCmd) != 64);
    QEMU_BUILD_BUG_ON(sizeof(NvmeCsdNvmToAfdmCmd) != 64);
    QEMU_BUILD_BUG_ON(sizeof(NvmeCsdExecCmd) != 64);
    QEMU_BUILD_BUG_ON(sizeof(NvmeCsdMemoryRange) != 32);
    QEMU_BUILD_BUG_ON(sizeof(NvmeCsdReadAfdmCmd) != 64);
    QEMU_BUILD_BUG_ON(sizeof(NvmeCsdWriteAfdmCmd) != 64);
    QEMU_BUILD_BUG_ON(sizeof(NvmeCsdCreateGroupCmd) != 64);
    QEMU_BUILD_BUG_ON(sizeof(NvmeCsdSetQosCmd) != 64);
    QEMU_BUILD_BUG_ON(sizeof(NvmeCsdDeleteGroupCmd) != 64);
    QEMU_BUILD_BUG_ON(sizeof(NvmeCsdLoadProgramCmd) != 64);
    QEMU_BUILD_BUG_ON(sizeof(NvmeCsdProgramActivationCmd) != 64);
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
    struct ssd *ssd;

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

    ssd = n->ssd = g_malloc0(sizeof(*ssd));
    ssd->dataplane_started_ptr = &n->dataplane_started;
    ssd->ssdname = (char *)n->devname;
    ssd_init(n);

    csd = g_new0(FemuCsdState, 1);
    csd->params = n->csd_params;
    csd->fdm_capacity = n->csd_params.fdm_size_mb * MiB;
    csd->next_afdm_id = 1;
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

static uint16_t csd_check_nvm_ftl_range(FemuCtrl *n, uint64_t slba,
                                        uint64_t nlb, uint64_t *mapped_pages)
{
    struct ssd *ssd = n->ssd;
    struct ssdparams *spp;
    uint64_t start_lpn;
    uint64_t end_lpn;

    if (!ssd || !ssd->maptbl) {
        return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }

    spp = &ssd->sp;
    if (spp->secs_per_pg <= 0 || spp->tt_pgs == 0 || nlb == 0) {
        return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }

    start_lpn = slba / spp->secs_per_pg;
    if (slba > UINT64_MAX - nlb + 1) {
        return NVME_LBA_RANGE | NVME_DNR;
    }

    end_lpn = (slba + nlb - 1) / spp->secs_per_pg;
    if (end_lpn >= spp->tt_pgs) {
        return NVME_LBA_RANGE | NVME_DNR;
    }

    *mapped_pages = 0;
    for (uint64_t lpn = start_lpn; lpn <= end_lpn; lpn++) {
        if (ssd->maptbl[lpn].ppa != UNMAPPED_PPA) {
            (*mapped_pages)++;
        }
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

    if (ubpf_load_elf_ex(program->ubpf_vm, elf, elf_size, symbol, &errmsg) < 0) {
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

static uint16_t csd_load_program_data(FemuCsdProgram *program, bool jit)
{
    switch (program->type) {
    case NVME_CSD_CSF_TYPE_PHANTOM:
        return NVME_SUCCESS;
    case NVME_CSD_CSF_TYPE_SHARED_LIB:
        return csd_load_shared_lib(program);
    case NVME_CSD_CSF_TYPE_EBPF:
        return csd_load_ubpf(program, jit);
    default:
        return NVME_INVALID_FIELD | NVME_DNR;
    }
}

static uint16_t csd_compute_load(FemuCtrl *n, NvmeCmd *cmd)
{
    FemuCsdState *csd = csd_state(n);
    NvmeCsdLoadProgramCmd *load = (NvmeCsdLoadProgramCmd *)cmd;
    uint16_t pind = le16_to_cpu(load->pind);
    uint32_t psize = le32_to_cpu(load->psize);
    uint32_t numb = le32_to_cpu(load->numb);
    uint32_t loff = le32_to_cpu(load->loff);
    uint64_t pid = le64_to_cpu(load->pid);
    uint64_t prp1 = le64_to_cpu(load->prp1);
    uint64_t prp2 = le64_to_cpu(load->prp2);
    FemuCsdProgram *program;
    uint16_t status = NVME_SUCCESS;

    if (pind == 0 || psize > UINT32_MAX || loff > psize ||
        numb > psize - loff) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    qemu_mutex_lock(&csd->lock);

    if (load->sel) {
        program = csd_get_program_locked(csd, pind);
        if (!program) {
            qemu_mutex_unlock(&csd->lock);
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        if (program->active) {
            qemu_mutex_unlock(&csd->lock);
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        g_hash_table_remove(csd->programs, GUINT_TO_POINTER((uint32_t)pind));
        qemu_mutex_unlock(&csd->lock);
        return NVME_SUCCESS;
    }

    if (loff == 0) {
        program = g_new0(FemuCsdProgram, 1);
        program->id = pind;
        program->type = load->ptype;
        program->runtime = le32_to_cpu(load->runtime);
        program->runtime_scale = le16_to_cpu(load->runtime_scale);
        program->size = psize;
        program->pid = pid;
        program->indirect = load->indirect;
        program->loading = true;
        if (psize) {
            program->data = g_malloc0(psize);
        }
        g_hash_table_replace(csd->programs, GUINT_TO_POINTER((uint32_t)pind),
                             program);
    } else {
        program = csd_get_program_locked(csd, pind);
        if (!program || program->size != psize ||
            (load->pit == 1 && program->pid != pid) ||
            program->type != load->ptype) {
            qemu_mutex_unlock(&csd->lock);
            return NVME_INVALID_FIELD | NVME_DNR;
        }
    }

    if (numb) {
        status = dma_write_prp(n, program->data + loff, numb, prp1, prp2);
        if (status) {
            qemu_mutex_unlock(&csd->lock);
            return status | NVME_DNR;
        }
        program->load_size += numb;
    }

    if (program->load_size == program->size) {
        status = csd_load_program_data(program, load->jit);
        if (!status) {
            program->loading = false;
            program->active = false;
        }
    }

    qemu_mutex_unlock(&csd->lock);
    return status;
}

static uint16_t csd_compute_activate(FemuCtrl *n, NvmeCmd *cmd)
{
    FemuCsdState *csd = csd_state(n);
    NvmeCsdProgramActivationCmd *activation =
        (NvmeCsdProgramActivationCmd *)cmd;
    uint16_t pind = activation->pind;
    uint8_t sel = activation->sel;
    FemuCsdProgram *program;

    if (pind == 0) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    qemu_mutex_lock(&csd->lock);
    program = csd_get_program_locked(csd, pind);
    if (!program || program->loading) {
        qemu_mutex_unlock(&csd->lock);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    switch (sel) {
    case 0:
        program->active = false;
        break;
    case 1:
        program->active = true;
        break;
    default:
        qemu_mutex_unlock(&csd->lock);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    qemu_mutex_unlock(&csd->lock);
    return NVME_SUCCESS;
}

static uint16_t csd_build_exec_args_locked(FemuCsdState *csd,
                                           NvmeCsdMemoryRange *ranges,
                                           uint32_t numr,
                                           FemuCsdArgs *args,
                                           void ***mr_addrp,
                                           long long **mr_lenp)
{
    void **mr_addr = g_new0(void *, numr);
    long long *mr_len = g_new0(long long, numr);

    for (uint32_t i = 0; i < numr; i++) {
        uint32_t nsid = le32_to_cpu(ranges[i].nsid);
        uint32_t len = le32_to_cpu(ranges[i].len);
        uint64_t sb = le64_to_cpu(ranges[i].sb);
        FemuCsdAfdm *afdm;

        if (nsid != NVME_CSD_MR_AFDM_NSID) {
            g_free(mr_addr);
            g_free(mr_len);
            return NVME_INVALID_FIELD | NVME_DNR;
        }

        afdm = csd_get_afdm_locked(csd, sb);
        if (!afdm) {
            g_free(mr_addr);
            g_free(mr_len);
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        if (len == 0) {
            len = afdm->size > UINT32_MAX ? UINT32_MAX : afdm->size;
        }
        if (len > afdm->size) {
            g_free(mr_addr);
            g_free(mr_len);
            return NVME_INVALID_FIELD | NVME_DNR;
        }

        mr_addr[i] = afdm->data;
        mr_len[i] = len;
    }

    args->numr = numr;
    args->mr_addr = mr_addr;
    args->mr_len = mr_len;
    *mr_addrp = mr_addr;
    *mr_lenp = mr_len;

    return NVME_SUCCESS;
}

static uint16_t csd_exec(FemuCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    FemuCsdState *csd = csd_state(n);
    NvmeCsdExecCmd *exec = (NvmeCsdExecCmd *)cmd;
    uint16_t pind = le16_to_cpu(exec->pind);
    uint16_t rsid = le16_to_cpu(exec->rsid);
    uint32_t numr = le32_to_cpu(exec->numr);
    uint32_t dlen = le32_to_cpu(exec->dlen);
    uint64_t cparam1 = le64_to_cpu(exec->cparam1);
    uint64_t cparam2 = le64_to_cpu(exec->cparam2);
    uint32_t group_id = exec->group;
    uint32_t runtime = le32_to_cpu(exec->runtime);
    uint64_t prp1 = le64_to_cpu(exec->prp1);
    uint64_t prp2 = le64_to_cpu(exec->prp2);
    FemuCsdProgram *program;
    uint64_t copy_size;
    uint8_t *data = NULL;
    NvmeCsdMemoryRange *ranges = NULL;
    void **mr_addr = NULL;
    long long *mr_len = NULL;
    FemuCsdArgs args = { 0 };
    int64_t result = 0;
    uint16_t status = NVME_SUCCESS;

    if (dlen == 0 && numr > 0) {
        dlen = numr * sizeof(NvmeCsdMemoryRange);
    }

    if (pind == 0 || rsid != 0 || numr == 0 ||
        numr > CSD_EXEC_DATA_MAX / sizeof(NvmeCsdMemoryRange)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (dlen < numr * sizeof(NvmeCsdMemoryRange) || dlen > CSD_EXEC_DATA_MAX) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    data = g_malloc0(dlen);
    status = dma_write_prp(n, data, dlen, prp1, prp2);
    if (status) {
        g_free(data);
        return status;
    }
    ranges = (NvmeCsdMemoryRange *)data;

    qemu_mutex_lock(&csd->lock);
    program = csd_get_program_locked(csd, pind);
    if (!program) {
        qemu_mutex_unlock(&csd->lock);
        status = NVME_INVALID_FIELD | NVME_DNR;
        goto out;
    }
    if (!program->active) {
        qemu_mutex_unlock(&csd->lock);
        status = NVME_INVALID_FIELD | NVME_DNR;
        goto out;
    }

    if (group_id != 0 && !csd_get_group_locked(csd, group_id)) {
        qemu_mutex_unlock(&csd->lock);
        status = NVME_INVALID_FIELD | NVME_DNR;
        goto out;
    }

    if (runtime == 0) {
        runtime = program->runtime;
    }

    status = csd_build_exec_args_locked(csd, ranges, numr, &args,
                                        &mr_addr, &mr_len);
    if (status) {
        qemu_mutex_unlock(&csd->lock);
        goto out;
    }
    args.cparam1 = cparam1;
    args.cparam2 = cparam2;
    args.data_buffer = dlen > numr * sizeof(NvmeCsdMemoryRange) ?
                       data + numr * sizeof(NvmeCsdMemoryRange) : NULL;
    args.buffer_len = args.data_buffer ?
                      dlen - numr * sizeof(NvmeCsdMemoryRange) : 0;

    switch (program->type) {
    case NVME_CSD_CSF_TYPE_PHANTOM:
        if (args.numr >= 2) {
            copy_size = MIN(args.mr_len[0], args.mr_len[1]);
            memcpy(args.mr_addr[0], args.mr_addr[1], copy_size);
            result = copy_size > INT64_MAX ? INT64_MAX : copy_size;
        }
        break;
    case NVME_CSD_CSF_TYPE_SHARED_LIB:
        if (!program->shared_lib_fn) {
            status = NVME_INVALID_FIELD | NVME_DNR;
            break;
        }
        result = program->shared_lib_fn(&args);
        break;
    case NVME_CSD_CSF_TYPE_EBPF:
#ifdef CONFIG_FEMU_CSD_UBPF
        if (!program->ubpf_vm) {
            status = NVME_INVALID_FIELD | NVME_DNR;
            break;
        }
        if (program->ubpf_jit_fn) {
            result = program->ubpf_jit_fn((struct ubpf_jit_args *)&args);
        } else {
            uint64_t ubpf_result;

            if (ubpf_exec(program->ubpf_vm, (struct ubpf_jit_args *)&args,
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
    g_free(mr_addr);
    g_free(mr_len);
    qemu_mutex_unlock(&csd->lock);

    if (status) {
        goto out;
    }

    if (runtime) {
        req->reqlat += runtime;
        req->expire_time += runtime;
    }

out:
    g_free(data);
    return status;
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
    uint64_t mapped_pages;
    FemuCsdAfdm *afdm;
    uint16_t status;

    if (slba > le64_to_cpu(ns->id_ns.nsze) ||
        nlb > le64_to_cpu(ns->id_ns.nsze) - slba ||
        nvm_offset > n->mbe->size || size > n->mbe->size - nvm_offset) {
        return NVME_LBA_RANGE | NVME_DNR;
    }

    status = csd_check_nvm_ftl_range(n, slba, nlb, &mapped_pages);
    if (status) {
        return status;
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
    if (mapped_pages) {
        req->reqlat += n->ssd->sp.pg_rd_lat;
        req->expire_time += n->ssd->sp.pg_rd_lat;
    }
    return NVME_SUCCESS;
}

static uint16_t csd_io_cmd(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                           NvmeRequest *req)
{
    switch (cmd->opcode) {
    case NVME_CMD_READ:
    case NVME_CMD_WRITE:
        return nvme_rw(n, ns, cmd, req);
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

static uint16_t csd_admin_cmd(FemuCtrl *n, NvmeCmd *cmd)
{
    switch (cmd->opcode) {
    case NVME_ADM_CMD_CSD_COMPUTE_LOAD:
    case NVME_ADM_CMD_CSD_COMPUTE_LOAD_DATA:
        return csd_compute_load(n, cmd);
    case NVME_ADM_CMD_CSD_COMPUTE_ACTIVATE:
        return csd_compute_activate(n, cmd);
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
        .admin_cmd        = csd_admin_cmd,
        .io_cmd           = csd_io_cmd,
        .get_log          = NULL,
    };

    return 0;
}
