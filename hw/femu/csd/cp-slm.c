/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * The NVMe Subsystem Local Memory (SLM 1.2, CSI 03h) and Computational
 * Programs (CP 1.2, CSI 04h) command sets of CSD mode.
 *
 * csd_slm_size adds one memory namespace after the configured ones, and
 * csd_cp one compute namespace after that. They share the compute unit
 * threads, the job queue and the lock of the CEMU commands in csd.c, but have
 * their own programs, Memory Range Sets and memory. The CEMU commands stay on
 * the block namespace; dispatch by command set keeps the opcodes apart.
 *
 *   host --Memory Write/Copy--> SLM <--copy in/write back-- program (CU thread)
 *   host <--Memory Read-------- SLM --Copy format 4h--> block namespace
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/bitmap.h"
#include "qemu/units.h"
#include "csd-int.h"
#include "../nvme-pi.h"

#define CSD_DESC_SIZE           32
/* CP Figure 36: ranges are dword granular, as is a Load Program piece */
#define CSD_CP_MRSG             2
#define CSD_CP_LPG              2
#define CSD_SPEC_VERSION_1_2    0x00010200

/* the Fast Copy Only bit of a source range, SOPT bit 15 (byte 23 bit 7) */
#define CSD_SOPT_FCO_BYTE       23
#define CSD_SOPT_FCO            0x80

/* req->csd_use: bit 32 set, RSID in 31:16, PIND in 15:0 */
#define CSD_USE_VALID           (1ULL << 32)

/* ========== namespaces ========== */

int femu_csd_check_namespaces(FemuCtrl *n, int n_csd, Error **errp)
{
    CsdCtrlParams *p = &n->csd_params;

    if (p->legacy_opcodes && !n_csd) {
        error_setg(errp, "csd_legacy_opcodes needs a CSD namespace");
        return 1;
    }
    if (!p->slm_size_mb && !p->cp) {
        return 0;
    }
    if (!CSD(n)) {
        error_setg(errp, "csd_slm_size and csd_cp need femu_mode=4");
        return 1;
    }
    if (n_csd != 1) {
        error_setg(errp, "csd_slm_size and csd_cp need a CSD namespace");
        return 1;
    }
    if (p->cp && !p->slm_size_mb) {
        error_setg(errp, "csd_cp needs a memory namespace: set csd_slm_size");
        return 1;
    }
    if (p->slm_size_mb > CSD_SLM_MAX_MB) {
        error_setg(errp, "csd_slm_size must be at most %u MiB",
                   CSD_SLM_MAX_MB);
        return 1;
    }
    /*
     * The added namespaces have no place in a namespace table that is
     * managed or shared. A subsystem is fine. They belong to no endurance
     * group (SLM 1.2 2.1.2, CP 1.2 2.1.1). nvme_init_subsys() keeps the
     * controller alone in it, as Reachability Reporting needs.
     */
    if (n->ns_mgmt || n->power_loss || n->cxl_dev) {
        error_setg(errp, "csd_slm_size and csd_cp cannot be used with "
                   "ns_mgmt, power_loss or a CXL link");
        return 1;
    }
    if (n->num_namespaces + 1 + p->cp > NVME_MAX_NUM_NAMESPACES) {
        error_setg(errp, "csd_slm_size and csd_cp need room for %u more "
                   "namespaces", 1 + p->cp);
        return 1;
    }
    return 0;
}

static void csd_add_namespace(FemuCtrl *n, uint32_t nsid, uint8_t csi)
{
    NvmeNamespace *ns = &n->namespaces[nsid - 1];

    ns->id = nsid;
    ns->ctrl = n;
    ns->allocated = true;
    ns->attached = true;
    ns->femu_mode = FEMU_CSD_MODE;
    ns->csi = csi;
}

/*
 * Append the memory and compute namespaces. They take no slice of the
 * backend and no FTL, so the block namespace loops, which stop at
 * num_namespaces, never see them. csd_init() gives them its handlers.
 */
void femu_csd_add_namespaces(FemuCtrl *n)
{
    uint32_t nsid = n->num_namespaces;

    if (!CSD_SLM(n)) {
        return;
    }
    csd_add_namespace(n, ++nsid, NVME_CSI_SLM);
    if (CSD_CP(n)) {
        csd_add_namespace(n, ++nsid, NVME_CSI_CP);
    }
    n->namespace_limit = nsid;
    n->id_ctrl.nn = cpu_to_le32(nsid);
    /* Reachability Reporting, with a group identifier that never changes */
    n->id_ctrl.crcap = 0x3;
    n->id_ctrl.oaes |= cpu_to_le32(NVME_AEC_RGCNS);
}

static FemuCsdProgram *csd_cp_builtin(FemuCsdState *csd, uint16_t pind,
                                      uint8_t kind)
{
    FemuCsdProgram *program = g_new0(FemuCsdProgram, 1);

    program->id = pind;
    program->refs = 1;
    program->csd = csd;
    program->cp = true;
    program->builtin = true;
    program->type = kind;
    return program;
}

static void csd_cp_mrs_free(gpointer opaque)
{
    FemuCsdCpMrs *mrs = opaque;

    g_free(mrs->ranges);
    g_free(mrs);
}

void csd_cp_slm_init(FemuCtrl *n, FemuCsdState *csd, NvmeNamespace *ns,
                     uint8_t *slm)
{
    uint32_t i;

    if (!slm) {
        return;
    }
    csd->slm = slm;
    csd->slm_size = (uint64_t)n->csd_params.slm_size_mb * MiB;
    qemu_mutex_init(&csd->slm_lock);
    csd->slm_nsid = n->num_namespaces + 1;
    csd->cp_nsid = CSD_CP(n) ? csd->slm_nsid + 1 : 0;
    for (i = csd->slm_nsid; i <= n->namespace_limit; i++) {
        NvmeNamespace *aux = &n->namespaces[i - 1];

        aux->ext_ops = ns->ext_ops;
        aux->ext_ops.init = NULL;
        aux->ext_ops.state = NULL;
    }
    if (csd->cp_nsid) {
        csd->cp_prog[0] = csd_cp_builtin(csd, 0, CSD_KIND_CP_COPY);
        csd->cp_prog[1] = csd_cp_builtin(csd, 1, CSD_KIND_CP_FNV64);
        csd->cp_mrs = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                            NULL, csd_cp_mrs_free);
        csd->cp_next_rsid = 1;
    }
}

/* after the compute unit threads are joined, before the dead list goes */
void csd_cp_slm_exit(FemuCsdState *csd)
{
    if (!csd->slm) {
        return;
    }
    for (int i = 0; i < CSD_CP_NPIND; i++) {
        if (csd->cp_prog[i]) {
            csd_program_unref(csd->cp_prog[i]);
            csd->cp_prog[i] = NULL;
        }
    }
    if (csd->cp_mrs) {
        g_hash_table_destroy(csd->cp_mrs);
        csd->cp_mrs = NULL;
    }
    qemu_mutex_destroy(&csd->slm_lock);
    g_free(csd->slm);
    csd->slm = NULL;
}

void femu_csd_slm_clear(FemuCtrl *n)
{
    FemuCsdState *csd = csd_state(n);

    if (csd && csd->slm) {
        qemu_mutex_lock(&csd->slm_lock);
        memset(csd->slm, 0, csd->slm_size);
        qemu_mutex_unlock(&csd->slm_lock);
    }
}

/* whether [off, off + len) lies in the memory namespace */
static bool csd_slm_in(FemuCsdState *csd, uint64_t off, uint64_t len)
{
    return off <= csd->slm_size && len <= csd->slm_size - off;
}

/* the source of a Copy format 4h on a block namespace */
uint16_t femu_csd_slm_read(FemuCtrl *n, uint32_t nsid, uint64_t off,
                           uint64_t len, uint8_t *dst)
{
    FemuCsdState *csd = csd_state(n);

    if (!csd || !csd->slm || nsid != csd->slm_nsid ||
        !csd_slm_in(csd, off, len)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    /* NBYTE may be 0, and then the caller's buffer may be NULL */
    if (!len) {
        return NVME_SUCCESS;
    }
    qemu_mutex_lock(&csd->slm_lock);
    memcpy(dst, csd->slm + off, len);
    qemu_mutex_unlock(&csd->slm_lock);
    return NVME_SUCCESS;
}

/* ========== Identify ========== */

uint16_t femu_csd_identify_ns(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd)
{
    FemuCsdState *csd = csd_state(n);
    uint8_t id[NVME_IDENTIFY_DATA_SIZE] = { 0 };

    if (NS_SLM(ns)) {
        /* SLM Figure 25: sizes in bytes, one format of byte granularity */
        stq_le_p(&id[0], csd->slm_size);            /* NSZE */
        id[8] = 0;                                  /* NF: one format */
        stl_le_p(&id[9], 0);                        /* NOWG: one dword */
        stq_le_p(&id[13], CSD_SLM_COPY_MAX);        /* MCMCL */
        stl_le_p(&id[21], CSD_SLM_COPY_MAX);        /* MCMSSRL */
        id[25] = CSD_SLM_COPY_MSRC;                 /* MCMSRC, 0's based */
        id[527] = 0x80;                             /* format 0: VAL, DS 0 */
    } else {
        /* CP Figure 36 */
        stw_le_p(&id[0], csd->params.nr_cu);        /* MAXACT */
        stw_le_p(&id[2], CSD_CP_MAXMEMRS);          /* MAXMEMRS */
        stw_le_p(&id[4], CSD_CP_MRSG);              /* MRSG */
        id[6] = CSD_CP_MAXMEMR;                     /* MAXMEMR */
        stq_le_p(&id[8], CSD_PROGRAM_TOTAL_MAX / MiB);  /* MAXPB, MiB */
        id[16] = CSD_CP_LPG;                        /* LPG */
    }
    return dma_read_prp(n, id, sizeof(id), le64_to_cpu(cmd->dptr.prp1),
                        le64_to_cpu(cmd->dptr.prp2));
}

/* SLM Figure 27 and CP Figure 37: the version alone, 1.2 */
uint16_t femu_csd_identify_ctrl(FemuCtrl *n, NvmeCmd *cmd)
{
    uint8_t id[NVME_IDENTIFY_DATA_SIZE] = { 0 };

    stl_le_p(&id[0], CSD_SPEC_VERSION_1_2);
    return dma_read_prp(n, id, sizeof(id), le64_to_cpu(cmd->dptr.prp1),
                        le64_to_cpu(cmd->dptr.prp2));
}

/* ========== SLM I/O commands ========== */

/*
 * Commands of these sets run only when CC.CSS enables every I/O command set
 * (Base 2.3, 5.2.26.1.17), and neither set has a fused operation.
 */
static uint16_t csd_cp_slm_check_cmd(FemuCtrl *n, NvmeCmd *cmd)
{
    if (NVME_CC_CSS(n->bar.cc) != NVME_CC_CSS_CSI) {
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
    if (cmd->fuse) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    return NVME_SUCCESS;
}

static uint64_t csd_cmd_sb(NvmeCmd *cmd)
{
    return ((uint64_t)le32_to_cpu(cmd->cdw11) << 32) | le32_to_cpu(cmd->cdw10);
}

/* Memory Read and Memory Write (SLM 3.2.3 and 3.2.4) */
static uint16_t csd_slm_rw(FemuCtrl *n, FemuCsdState *csd, NvmeCmd *cmd,
                           NvmeRequest *req, bool write)
{
    uint64_t sb = csd_cmd_sb(cmd);
    uint32_t len = le32_to_cpu(cmd->cdw12);
    g_autofree uint8_t *buf = NULL;
    uint16_t status;

    if ((sb | len) & 3 || !csd_slm_in(csd, sb, len)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (!len) {
        return NVME_SUCCESS;
    }
    status = nvme_check_mdts(n, len);
    if (status) {
        return status;
    }
    req->is_write = write;
    req->xfer_bytes = len;
    /*
     * The transfer goes through a buffer, so a DMA that fails part of the way
     * leaves the memory as it was, and the lock is never held across a DMA.
     */
    buf = g_try_malloc(len);
    if (!buf) {
        return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }
    if (write) {
        status = dma_write_cmd(n, cmd, buf, len);
        if (!status) {
            qemu_mutex_lock(&csd->slm_lock);
            memcpy(csd->slm + sb, buf, len);
            qemu_mutex_unlock(&csd->slm_lock);
        }
    } else {
        qemu_mutex_lock(&csd->slm_lock);
        memcpy(buf, csd->slm + sb, len);
        qemu_mutex_unlock(&csd->slm_lock);
        status = dma_read_cmd(n, cmd, buf, len);
    }
    return status;
}

/* Memory Fill (SLM 3.2.2): no data moves, so MDTS does not apply */
static uint16_t csd_slm_fill(FemuCsdState *csd, NvmeCmd *cmd)
{
    uint64_t sb = csd_cmd_sb(cmd);
    uint32_t fl = le32_to_cpu(cmd->cdw12);

    if ((sb | fl) & 3 || !csd_slm_in(csd, sb, fl)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    qemu_mutex_lock(&csd->slm_lock);
    memset(csd->slm + sb, 0, fl);
    qemu_mutex_unlock(&csd->slm_lock);
    return NVME_SUCCESS;
}

/*
 * The block namespace a format 2h range reads, and where its bytes are. The
 * SNSID rules are those of SLM 3.2.1, which differ from the NVM Copy ones.
 */
static uint16_t csd_slm_copy_lba_src(FemuCtrl *n, NvmeNamespace *ns,
                                     const NvmeCopyRange *r, uint64_t *off,
                                     uint64_t *bytes, NvmeDsmRange *src)
{
    uint32_t snsid = le32_to_cpu(r->snsid);
    uint64_t slba = le64_to_cpu(r->slba);
    uint32_t nlb = le16_to_cpu(r->nlb) + 1;
    NvmeNamespace *s;
    uint64_t nsze;
    uint8_t lbads;
    uint16_t status;

    if (snsid == ns->id) {
        return NVME_NS_INCOMPATIBLE | NVME_DNR;
    }
    if (!snsid || snsid == NVME_NSID_BROADCAST || !nvme_nsid_valid(n, snsid)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    s = nvme_ns(n, snsid);
    if (!s) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    /* the block namespaces whose data and media timing FEMU can reach */
    if (!(NS_BBSSD(s) || NS_NOSSD(s) || NS_CSD(s))) {
        return NVME_INVALID_NSID | NVME_DNR;
    }
    /* stripping protection information is not offered */
    if (femu_pi_type(s)) {
        return NVME_NS_INCOMPATIBLE | NVME_DNR;
    }
    nsze = le64_to_cpu(s->id_ns.nsze);
    lbads = s->id_ns.lbaf[NVME_ID_NS_FLBAS_INDEX(s->id_ns.flbas)].lbads;
    if ((uint64_t)nlb << lbads > CSD_SLM_COPY_MAX) {
        return NVME_CMD_SIZE_LIMIT | NVME_DNR;
    }
    if (slba >= nsze || nlb > nsze - slba) {
        return NVME_LBA_RANGE | NVME_DNR;
    }
    if (find_next_bit(s->uncorrectable, slba + nlb, slba) < slba + nlb) {
        return NVME_UNRECOVERED_READ | NVME_DNR;
    }
    status = nvme_check_dulbe(n, s, slba, slba + nlb);
    if (status) {
        return status;
    }
    *off = s->backend_offset + (slba << lbads);
    *bytes = (uint64_t)nlb << lbads;
    src->cattr = cpu_to_le32(snsid);
    src->slba = cpu_to_le64(slba);
    src->nlb = cpu_to_le32(nlb);
    return NVME_SUCCESS;
}

/* a format 4h range: bytes of the memory namespace */
static uint16_t csd_slm_copy_mem_src(FemuCtrl *n, FemuCsdState *csd,
                                     const NvmeSlmCopyRange *r, uint64_t *off,
                                     uint64_t *bytes)
{
    uint32_t snsid = le32_to_cpu(r->snsid);
    uint64_t saddr = le64_to_cpu(r->saddr);
    uint32_t nbyte = le32_to_cpu(r->nbyte);
    NvmeNamespace *s;

    if (!snsid || snsid == NVME_NSID_BROADCAST || !nvme_nsid_valid(n, snsid)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    s = nvme_ns(n, snsid);
    if (!s) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (!NS_SLM(s)) {
        return NVME_INVALID_NSID | NVME_DNR;
    }
    if ((saddr | nbyte) & 3) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (nbyte > CSD_SLM_COPY_MAX) {
        return NVME_CMD_SIZE_LIMIT | NVME_DNR;
    }
    if (!csd_slm_in(csd, saddr, nbyte)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    *off = saddr;
    *bytes = nbyte;
    return NVME_SUCCESS;
}

/*
 * Memory Copy (SLM 3.2.1): source ranges, of blocks (format 2h) or of memory
 * (format 4h), to one run of memory at SDADDR. Every range is checked before
 * any byte moves, so a failed command wrote nothing and DW0 is 0h. Reads of
 * block ranges are charged on the FTL thread through req->dsm_ranges.
 */
static uint16_t csd_slm_copy(FemuCtrl *n, FemuCsdState *csd,
                             NvmeNamespace *ns, NvmeCmd *cmd,
                             NvmeRequest *req)
{
    uint32_t dw12 = le32_to_cpu(cmd->cdw12);
    uint64_t len = le64_to_cpu(cmd->res2);
    uint64_t sdaddr = csd_cmd_sb(cmd);
    uint8_t nr = dw12 & 0xff;
    uint8_t fmt = (dw12 >> 8) & 0xf;
    uint32_t count = nr + 1;
    g_autofree uint8_t *desc = NULL;
    g_autofree uint64_t *off = NULL;
    g_autofree uint64_t *bytes = NULL;
    g_autofree NvmeDsmRange *src = NULL;
    uint64_t total = 0;
    uint64_t done = 0;
    uint16_t status;
    uint32_t i;

    if ((fmt != 2 && fmt != 4) ||
        !(n->features.host_behavior[4] & (1 << fmt))) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if ((len | sdaddr) & 3) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (nr > CSD_SLM_COPY_MSRC) {
        return NVME_CMD_SIZE_LIMIT | NVME_DNR;
    }
    status = nvme_check_mdts(n, count * CSD_DESC_SIZE);
    if (status) {
        return status;
    }
    desc = g_malloc(count * CSD_DESC_SIZE);
    req->is_write = true;
    req->xfer_bytes = count * CSD_DESC_SIZE;
    status = dma_write_cmd(n, cmd, desc, count * CSD_DESC_SIZE);
    if (status) {
        return status;
    }

    off = g_new(uint64_t, count);
    bytes = g_new(uint64_t, count);
    src = g_new0(NvmeDsmRange, count);
    for (i = 0; i < count; i++) {
        uint8_t *d = desc + i * CSD_DESC_SIZE;

        if (d[CSD_SOPT_FCO_BYTE] & CSD_SOPT_FCO) {
            /* nothing here is a fast copy (NVM 3.3.2.1) */
            return NVME_SLM_FAST_COPY_NOT_POSSIBLE | NVME_DNR;
        }
        status = fmt == 2 ?
            csd_slm_copy_lba_src(n, ns, (NvmeCopyRange *)d, &off[i],
                                 &bytes[i], &src[i]) :
            csd_slm_copy_mem_src(n, csd, (NvmeSlmCopyRange *)d, &off[i],
                                 &bytes[i]);
        if (status) {
            return status;
        }
        total += bytes[i];
        if (total > CSD_SLM_COPY_MAX) {
            return NVME_CMD_SIZE_LIMIT | NVME_DNR;
        }
    }
    if (total != len || !csd_slm_in(csd, sdaddr, len)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    for (i = 0; fmt == 4 && i < count; i++) {
        if (bytes[i] && off[i] < sdaddr + len && sdaddr < off[i] + bytes[i]) {
            return NVME_CMD_OVERLAP_IO_RANGE | NVME_DNR;
        }
    }

    qemu_mutex_lock(&csd->slm_lock);
    for (i = 0; i < count; i++) {
        uint8_t *dst = csd->slm + sdaddr + done;

        if (fmt == 2) {
            backend_lock_range(n->mbe, off[i], bytes[i]);
            memcpy(dst, (uint8_t *)n->mbe->logical_space + off[i], bytes[i]);
            backend_unlock_range(n->mbe, off[i], bytes[i]);
        } else {
            memcpy(dst, csd->slm + off[i], bytes[i]);
        }
        done += bytes[i];
    }
    qemu_mutex_unlock(&csd->slm_lock);

    if (fmt == 2) {
        req->dsm_ranges = g_steal_pointer(&src);
        req->dsm_nr_ranges = count;
    }
    return NVME_SUCCESS;
}

uint16_t csd_slm_io_cmd(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                        NvmeRequest *req)
{
    FemuCsdState *csd = csd_state(n);
    uint16_t status = csd_cp_slm_check_cmd(n, cmd);

    if (status) {
        return status;
    }
    switch (cmd->opcode) {
    case NVME_CMD_FLUSH:
        /* memory is volatile; Flush has no effect (SLM 2.1.3) */
        return NVME_SUCCESS;
    case NVME_SLM_CMD_COPY:
        return csd_slm_copy(n, csd, ns, cmd, req);
    case NVME_SLM_CMD_READ:
        return csd_slm_rw(n, csd, cmd, req, false);
    case NVME_SLM_CMD_WRITE:
        return csd_slm_rw(n, csd, cmd, req, true);
    case NVME_SLM_CMD_FILL:
        return csd_slm_fill(csd, cmd);
    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

/* ========== CP programs ========== */

static bool csd_cp_ptype_offered(FemuCtrl *n, uint8_t ptype)
{
    const char *dir = n->csd_params.program_dir;

    if (!dir || !dir[0]) {
        return false;
    }
    switch (ptype) {
    case NVME_CP_PTYPE_FEMU_SHLIB:
        return true;
#ifdef CONFIG_FEMU_CSD_UBPF
    case NVME_CP_PTYPE_FEMU_EBPF:
        return true;
#endif
    default:
        return false;
    }
}

static void csd_cp_drop_locked(FemuCsdState *csd, uint16_t pind)
{
    FemuCsdProgram *program = csd->cp_prog[pind];

    csd->cp_prog[pind] = NULL;
    if (program) {
        g_free(program->loaded);
        program->loaded = NULL;
        csd_program_unref(program);
    }
}

/*
 * Unload (CP 4.2.1, SEL 1). A device-defined program cannot go, and neither
 * can one an Execute still holds; FFFFh unloads every downloaded program or,
 * when one is held, none.
 */
static uint16_t csd_cp_unload_locked(FemuCsdState *csd, uint16_t pind)
{
    FemuCsdProgram *program;

    if (pind == CSD_CP_ALL) {
        for (int i = CSD_CP_NBUILTIN; i < CSD_CP_NPIND; i++) {
            if (csd->cp_prog[i] && csd->cp_prog[i]->use) {
                return NVME_CP_PROGRAM_IN_USE | NVME_DNR;
            }
        }
        for (int i = CSD_CP_NBUILTIN; i < CSD_CP_NPIND; i++) {
            csd_cp_drop_locked(csd, i);
        }
        return NVME_SUCCESS;
    }
    if (pind >= CSD_CP_NPIND) {
        return NVME_CP_INVALID_PIND | NVME_DNR;
    }
    if (pind < CSD_CP_NBUILTIN) {
        return NVME_CP_NOT_DOWNLOADABLE | NVME_DNR;
    }
    program = csd->cp_prog[pind];
    if (!program) {
        return NVME_CP_NO_PROGRAM | NVME_DNR;
    }
    if (program->use) {
        return NVME_CP_PROGRAM_IN_USE | NVME_DNR;
    }
    csd_cp_drop_locked(csd, pind);
    return NVME_SUCCESS;
}

/* a first piece (LOFF 0h) starts the program over at its index */
static uint16_t csd_cp_load_first_locked(FemuCtrl *n, FemuCsdState *csd,
                                         uint16_t pind, uint32_t dw10,
                                         uint32_t psize, uint64_t pid)
{
    uint8_t ptype = (dw10 >> 16) & 0xff;
    uint8_t pit = (dw10 >> 25) & 0x7;
    FemuCsdProgram *held = csd->cp_prog[pind];
    uint64_t used = csd->cp_prog_used;
    uint64_t dwords = DIV_ROUND_UP(psize, 4);
    FemuCsdProgram *program;
    uint8_t *data;
    unsigned long *loaded;

    if (!csd_cp_ptype_offered(n, ptype)) {
        return NVME_CP_INVALID_PROGRAM_TYPE | NVME_DNR;
    }
    if (pit > 1 || !psize) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (psize > CSD_PROGRAM_MAX) {
        return NVME_CP_PROGRAM_TOO_BIG | NVME_DNR;
    }
    if (held && held->use) {
        return NVME_CP_PROGRAM_IN_USE | NVME_DNR;
    }
    /*
     * The program this one replaces gives its bytes back, unless a compute
     * unit still runs it for a dropped command and holds them until it
     * returns.
     */
    if (held && held->refs == 1) {
        used -= held->size;
    }
    if (used > CSD_PROGRAM_TOTAL_MAX ||
        psize > CSD_PROGRAM_TOTAL_MAX - used) {
        return NVME_CP_MAX_PROGRAM_BYTES | NVME_DNR;
    }
    data = g_try_malloc0(dwords * 4);
    loaded = g_try_new0(unsigned long, BITS_TO_LONGS(dwords));
    if (!data || !loaded) {
        g_free(data);
        g_free(loaded);
        return NVME_CP_INSUFFICIENT_RESOURCES | NVME_DNR;
    }

    csd_cp_drop_locked(csd, pind);
    program = g_new0(FemuCsdProgram, 1);
    program->id = pind;
    program->refs = 1;
    program->csd = csd;
    program->cp = true;
    program->ptype = ptype;
    program->type = ptype == NVME_CP_PTYPE_FEMU_EBPF ?
                    NVME_CSD_CSF_TYPE_EBPF : NVME_CSD_CSF_TYPE_SHARED_LIB;
    program->pit = pit;
    program->pid = pit ? pid : 0;
    program->size = psize;
    program->loading = true;
    program->data = data;
    program->loaded = loaded;
    csd->cp_prog[pind] = program;
    csd->cp_prog_used += psize;
    return NVME_SUCCESS;
}

/*
 * Load Program (CP 4.2.1). Pieces after the first may come in any order and
 * may repeat; the program is checked once every dword of it has arrived. A
 * piece that fails empties the index, since the program is incomplete.
 */
static uint16_t csd_cp_load(FemuCtrl *n, FemuCsdState *csd, NvmeCmd *cmd)
{
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint16_t pind = dw10 & 0xffff;
    bool unload = (dw10 >> 24) & 0x1;
    uint32_t psize = le32_to_cpu(cmd->cdw11);
    uint64_t pid = ((uint64_t)le32_to_cpu(cmd->cdw13) << 32) |
                   le32_to_cpu(cmd->cdw12);
    uint32_t numb = le32_to_cpu(cmd->cdw14);
    uint32_t loff = le32_to_cpu(cmd->cdw15);
    FemuCsdProgram *program;
    uint64_t dwords;
    uint16_t status;

    qemu_mutex_lock(&csd->lock);
    if (unload) {
        status = csd_cp_unload_locked(csd, pind);
        qemu_mutex_unlock(&csd->lock);
        return status;
    }

    if (pind >= CSD_CP_NPIND) {
        status = NVME_CP_INVALID_PIND | NVME_DNR;
        goto out;
    }
    if (pind < CSD_CP_NBUILTIN) {
        status = NVME_CP_NOT_DOWNLOADABLE | NVME_DNR;
        goto out;
    }
    if ((numb | loff) & 3) {
        status = NVME_INVALID_FIELD | NVME_DNR;
        goto out;
    }
    status = nvme_check_mdts(n, numb);
    if (status) {
        goto out;
    }
    if (!loff) {
        if (numb > ROUND_UP((uint64_t)psize, 4)) {
            status = NVME_INVALID_FIELD | NVME_DNR;
            goto out;
        }
        status = csd_cp_load_first_locked(n, csd, pind, dw10, psize, pid);
        if (status) {
            goto out;
        }
    }

    program = csd->cp_prog[pind];
    if (!program || !program->loading) {
        status = NVME_CP_NO_PROGRAM | NVME_DNR;
        goto out;
    }
    dwords = DIV_ROUND_UP(program->size, 4);
    if (loff > dwords * 4 || numb > dwords * 4 - loff) {
        status = NVME_INVALID_FIELD | NVME_DNR;
        goto drop;
    }
    if (numb) {
        status = dma_write_prp(n, program->data + loff, numb,
                               le64_to_cpu(cmd->dptr.prp1),
                               le64_to_cpu(cmd->dptr.prp2));
        if (status) {
            status |= NVME_DNR;
            goto drop;
        }
        bitmap_set(program->loaded, loff / 4, numb / 4);
        program->nloaded = bitmap_count_one(program->loaded, dwords);
    }
    if (program->nloaded < dwords) {
        goto out;
    }

    /*
     * Opening a library runs its constructors, which may take any time, so
     * the lock is free meanwhile. The program is still loading, so nothing
     * runs it, and admin commands, the only ones that change programs, are
     * serialized by the BQL.
     */
    program->refs++;
    qemu_mutex_unlock(&csd->lock);
    status = csd_load_program_data(n, program, false);
    qemu_mutex_lock(&csd->lock);
    if (status) {
        status = NVME_CP_INVALID_PROGRAM_DATA | NVME_DNR;
    } else {
        program->loading = false;
        g_free(program->loaded);
        program->loaded = NULL;
    }
    csd_program_unref(program);
    if (!status) {
        goto out;
    }
drop:
    csd_cp_drop_locked(csd, pind);
out:
    qemu_mutex_unlock(&csd->lock);
    return status;
}

/* Program Activation Management (CP 4.2.3) */
static uint16_t csd_cp_activate(FemuCsdState *csd, NvmeCmd *cmd)
{
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint16_t pind = dw10 & 0xffff;
    uint8_t sel = (dw10 >> 16) & 0xf;
    FemuCsdProgram *program;
    uint16_t status = NVME_SUCCESS;
    uint32_t active = 0;
    int i;

    if (sel > 1) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    qemu_mutex_lock(&csd->lock);
    if (!sel && pind == CSD_CP_ALL) {
        for (i = 0; i < CSD_CP_NPIND; i++) {
            program = csd->cp_prog[i];
            if (program && program->active && program->use) {
                status = NVME_CP_PROGRAM_IN_USE | NVME_DNR;
                goto out;
            }
        }
        for (i = 0; i < CSD_CP_NPIND; i++) {
            if (csd->cp_prog[i]) {
                csd->cp_prog[i]->active = false;
            }
        }
        goto out;
    }
    /* Figure 14 gives 8Fh for this; Figure 53 says 8Ch */
    if (pind >= CSD_CP_NPIND) {
        status = NVME_CP_INVALID_PIND | NVME_DNR;
        goto out;
    }
    program = csd->cp_prog[pind];
    if (!program || program->loading) {
        status = NVME_CP_NO_PROGRAM | NVME_DNR;
        goto out;
    }
    if (!sel) {
        if (program->active && program->use) {
            status = NVME_CP_PROGRAM_IN_USE | NVME_DNR;
        } else {
            program->active = false;
        }
        goto out;
    }
    if (program->active) {
        goto out;
    }
    /* one activated program per compute unit (MAXACT) */
    for (i = 0; i < CSD_CP_NPIND; i++) {
        active += csd->cp_prog[i] && csd->cp_prog[i]->active;
    }
    if (active >= csd->params.nr_cu) {
        status = NVME_CP_MAX_ACTIVATED | NVME_DNR;
        goto out;
    }
    program->active = true;
out:
    qemu_mutex_unlock(&csd->lock);
    return status;
}

/* ========== Memory Range Sets ========== */

/*
 * A range of an MRS create or of an Execute: in the memory namespace, and
 * not overlapping an earlier one. @create applies the granularity check of
 * MRSG, which an Execute reports as an invalid field.
 */
static uint16_t csd_cp_check_ranges(FemuCsdState *csd,
                                    const NvmeCsdMemoryRange *r,
                                    uint32_t numr, bool create)
{
    uint16_t bad = create ? NVME_CP_INVALID_MRS : NVME_INVALID_FIELD;

    for (uint32_t i = 0; i < numr; i++) {
        uint64_t sb = le64_to_cpu(r[i].sb);
        uint32_t len = le32_to_cpu(r[i].len);

        if (le32_to_cpu(r[i].nsid) != csd->slm_nsid) {
            return NVME_CP_INVALID_MEMORY_NS | NVME_DNR;
        }
        if (!len || len % (1 << CSD_CP_MRSG) || !csd_slm_in(csd, sb, len)) {
            return bad | NVME_DNR;
        }
        for (uint32_t j = 0; j < i; j++) {
            uint64_t osb = le64_to_cpu(r[j].sb);
            uint32_t olen = le32_to_cpu(r[j].len);

            if (sb < osb + olen && osb < sb + len) {
                return NVME_CP_OVERLAPPING_RANGES | NVME_DNR;
            }
        }
    }
    return NVME_SUCCESS;
}

static uint16_t csd_cp_mrs_delete_locked(FemuCsdState *csd, uint16_t rsid)
{
    FemuCsdCpMrs *mrs;
    GHashTableIter it;
    gpointer value;

    if (rsid == CSD_CP_ALL) {
        g_hash_table_iter_init(&it, csd->cp_mrs);
        while (g_hash_table_iter_next(&it, NULL, &value)) {
            if (((FemuCsdCpMrs *)value)->use) {
                return NVME_CP_MRS_IN_USE | NVME_DNR;
            }
        }
        g_hash_table_remove_all(csd->cp_mrs);
        return NVME_SUCCESS;
    }
    mrs = rsid ? g_hash_table_lookup(csd->cp_mrs, GUINT_TO_POINTER(rsid)) :
                 NULL;
    if (!mrs) {
        return NVME_CP_INVALID_RSID | NVME_DNR;
    }
    if (mrs->use) {
        return NVME_CP_MRS_IN_USE | NVME_DNR;
    }
    g_hash_table_remove(csd->cp_mrs, GUINT_TO_POINTER(rsid));
    return NVME_SUCCESS;
}

/* Memory Range Set Management (CP 4.2.2) */
static uint16_t csd_cp_mrs_mgmt(FemuCtrl *n, FemuCsdState *csd, NvmeCmd *cmd,
                                NvmeCqe *cqe)
{
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint8_t sel = dw10 & 0xf;
    uint16_t rsid = dw10 >> 16;
    uint32_t numr = le32_to_cpu(cmd->cdw11) & 0xff;
    g_autofree NvmeCsdMemoryRange *ranges = NULL;
    FemuCsdCpMrs *mrs;
    uint16_t status;

    if (sel == 1) {
        qemu_mutex_lock(&csd->lock);
        status = csd_cp_mrs_delete_locked(csd, rsid);
        qemu_mutex_unlock(&csd->lock);
        return status;
    }
    /* the host clears RSID on a create; the controller picks it */
    if (sel || rsid || !numr || numr > CSD_CP_MAXMEMR) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    ranges = g_new(NvmeCsdMemoryRange, numr);
    status = dma_write_prp(n, (uint8_t *)ranges, numr * sizeof(*ranges),
                           le64_to_cpu(cmd->dptr.prp1),
                           le64_to_cpu(cmd->dptr.prp2));
    if (status) {
        return status | NVME_DNR;
    }

    qemu_mutex_lock(&csd->lock);
    if (g_hash_table_size(csd->cp_mrs) >= CSD_CP_MAXMEMRS) {
        status = NVME_CP_MAX_MRS | NVME_DNR;
        goto out;
    }
    status = csd_cp_check_ranges(csd, ranges, numr, true);
    if (status) {
        goto out;
    }
    while (!csd->cp_next_rsid || csd->cp_next_rsid == CSD_CP_ALL ||
           g_hash_table_contains(csd->cp_mrs,
                                 GUINT_TO_POINTER(csd->cp_next_rsid))) {
        csd->cp_next_rsid++;
    }
    mrs = g_new0(FemuCsdCpMrs, 1);
    mrs->rsid = csd->cp_next_rsid++;
    mrs->numr = numr;
    mrs->ranges = g_steal_pointer(&ranges);
    g_hash_table_insert(csd->cp_mrs, GUINT_TO_POINTER(mrs->rsid), mrs);
    cqe->n.result = cpu_to_le32(mrs->rsid);
out:
    qemu_mutex_unlock(&csd->lock);
    return status;
}

uint16_t csd_cp_admin_cmd(FemuCtrl *n, NvmeCmd *cmd, NvmeCqe *cqe)
{
    FemuCsdState *csd = csd_state(n);

    /* programs and range sets belong to the compute namespace */
    if (le32_to_cpu(cmd->nsid) != csd->cp_nsid) {
        return NVME_INVALID_NSID | NVME_DNR;
    }
    switch (cmd->opcode) {
    case NVME_ADM_CMD_CP_LOAD_PROGRAM:
        return csd_cp_load(n, csd, cmd);
    case NVME_ADM_CMD_CP_PROGRAM_ACT:
        return csd_cp_activate(csd, cmd);
    case NVME_ADM_CMD_CP_MRS_MGMT:
        return csd_cp_mrs_mgmt(n, csd, cmd, cqe);
    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

/* ========== CP log pages ========== */

static uint8_t *csd_cp_program_list(FemuCsdState *csd, uint32_t *size)
{
    uint8_t *log;

    *size = 64 + CSD_CP_NPIND * 64;
    log = g_malloc0(*size);
    stl_le_p(log, CSD_CP_NPIND);
    for (int i = 0; i < CSD_CP_NPIND; i++) {
        FemuCsdProgram *program = csd->cp_prog[i];
        uint8_t *d = log + 64 + i * 64;

        /* an index still loading holds no program yet */
        if (!program || program->loading) {
            continue;
        }
        d[0] = (program->builtin ? 0x2 : 0x1) |
               (program->active ? 1 << 2 : 0) | program->pit << 3;
        d[1] = program->ptype;
        stq_le_p(d + 8, program->pid);
    }
    return log;
}

static uint8_t *csd_cp_program_types(FemuCtrl *n, uint32_t *size)
{
    static const uint8_t types[] = {
        NVME_CP_PTYPE_FEMU_EBPF, NVME_CP_PTYPE_FEMU_SHLIB,
    };
    uint8_t *log = g_malloc0(32 + ARRAY_SIZE(types) * 32);
    uint32_t numd = 0;

    for (int i = 0; i < ARRAY_SIZE(types); i++) {
        if (csd_cp_ptype_offered(n, types[i])) {
            log[32 + numd++ * 32] = types[i];   /* PTYPE; VER 0h */
        }
    }
    stl_le_p(log, numd);
    *size = 32 + numd * 32;
    return log;
}

static int csd_cp_rsid_cmp(const void *a, const void *b)
{
    return (int)((const FemuCsdCpMrs *const *)a)[0]->rsid -
           (int)((const FemuCsdCpMrs *const *)b)[0]->rsid;
}

/* @rio: Return Identifiers Only, no range descriptors */
static uint8_t *csd_cp_mrs_list(FemuCsdState *csd, bool rio, uint32_t *size)
{
    guint count = g_hash_table_size(csd->cp_mrs);
    g_autofree FemuCsdCpMrs **sets = g_new(FemuCsdCpMrs *, count + 1);
    GHashTableIter it;
    gpointer value;
    uint32_t len = 4 + 32;
    uint8_t *log;
    uint8_t *d;
    guint i = 0;

    g_hash_table_iter_init(&it, csd->cp_mrs);
    while (g_hash_table_iter_next(&it, NULL, &value)) {
        sets[i++] = value;
        len += 32 + (rio ? 0 : ((FemuCsdCpMrs *)value)->numr * 32);
    }
    qsort(sets, count, sizeof(*sets), csd_cp_rsid_cmp);
    log = g_malloc0(len);
    /* the descriptor of RSID 0h, the Execute data buffer, comes first */
    stl_le_p(log, 1 + count);
    d = log + 4 + 32;
    for (i = 0; i < count; i++) {
        stw_le_p(d, sets[i]->rsid);
        if (!rio) {
            stl_le_p(d + 2, sets[i]->numr);
            memcpy(d + 32, sets[i]->ranges, sets[i]->numr * 32);
        }
        d += 32 + (rio ? 0 : sets[i]->numr * 32);
    }
    *size = len;
    return log;
}

/*
 * Program List (82h), Downloadable Program Types List (83h) and Memory Range
 * Set List (84h), CP 4.1.4. They describe the compute namespace, which the
 * command must name. Each is built under the lock and copied out after.
 */
uint16_t csd_cp_get_log(FemuCtrl *n, NvmeCmd *cmd)
{
    FemuCsdState *csd = csd_state(n);
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint32_t dw11 = le32_to_cpu(cmd->cdw11);
    uint8_t lid = dw10 & 0xff;
    bool only = (dw10 >> 8) & 0x1;
    uint64_t len = ((((uint64_t)(dw11 & 0xffff) << 16) | (dw10 >> 16)) + 1)
                   << 2;
    uint64_t off = ((uint64_t)le32_to_cpu(cmd->cdw13) << 32) |
                   le32_to_cpu(cmd->cdw12);
    g_autofree uint8_t *log = NULL;
    uint32_t size;

    if (!csd || !csd->cp_nsid) {
        return NVME_INVALID_LOG_ID | NVME_DNR;
    }
    if (le32_to_cpu(cmd->nsid) != csd->cp_nsid) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    qemu_mutex_lock(&csd->lock);
    switch (lid) {
    case NVME_LOG_CP_PROGRAM_LIST:
        log = csd_cp_program_list(csd, &size);
        break;
    case NVME_LOG_CP_PROGRAM_TYPES:
        log = csd_cp_program_types(n, &size);
        break;
    case NVME_LOG_CP_MRS_LIST:
        log = csd_cp_mrs_list(csd, only, &size);
        break;
    default:
        qemu_mutex_unlock(&csd->lock);
        return NVME_INVALID_LOG_ID | NVME_DNR;
    }
    qemu_mutex_unlock(&csd->lock);
    if (off > size) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    return dma_read_prp(n, log + off, MIN(len, size - off),
                        le64_to_cpu(cmd->dptr.prp1),
                        le64_to_cpu(cmd->dptr.prp2));
}

/* ========== Execute Program ========== */

/*
 * Execute Program (CP 3.2.1). The command is checked here on the poller, the
 * program and the set it uses are marked in use until the completion is
 * posted, and a compute unit thread runs it on copies of its ranges.
 */
static uint16_t csd_cp_exec(FemuCtrl *n, FemuCsdState *csd, NvmeCmd *cmd,
                            NvmeRequest *req)
{
    uint64_t dw23 = le64_to_cpu(cmd->res2);
    uint16_t pind = dw23 & 0xffff;
    uint16_t rsid = (dw23 >> 16) & 0xffff;
    uint32_t numr = dw23 >> 32;
    uint32_t dlen = (uint32_t)le64_to_cpu(cmd->mptr);
    g_autofree uint8_t *data = NULL;
    const NvmeCsdMemoryRange *ranges;
    uint32_t nranges;
    FemuCsdProgram *program;
    FemuCsdCpMrs *mrs = NULL;
    FemuCsdJob *job;
    uint16_t status;

    req->is_write = true;
    if (pind >= CSD_CP_NPIND) {
        return NVME_CP_INVALID_PIND | NVME_DNR;
    }
    if (rsid && numr) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (numr > CSD_CP_MAXMEMR) {
        return NVME_CP_MAX_MEMORY_RANGES | NVME_DNR;
    }
    if (dlen < numr * CSD_DESC_SIZE) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    status = nvme_check_mdts(n, dlen);
    if (status) {
        return status;
    }
    if (dlen) {
        /* with MDTS 0h a buffer has no bound but the host's memory */
        data = g_try_malloc(dlen);
        if (!data) {
            return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
        }
        req->xfer_bytes = dlen;
        status = dma_write_cmd(n, cmd, data, dlen);
        if (status) {
            return status;
        }
    }

    qemu_mutex_lock(&csd->lock);
    program = csd->cp_prog[pind];
    if (!program || program->loading) {
        status = NVME_CP_NO_PROGRAM | NVME_DNR;
        goto fail;
    }
    if (!program->active) {
        status = NVME_CP_NOT_ACTIVATED | NVME_DNR;
        goto fail;
    }
    if (rsid) {
        mrs = g_hash_table_lookup(csd->cp_mrs, GUINT_TO_POINTER(rsid));
        if (!mrs) {
            status = NVME_CP_INVALID_RSID | NVME_DNR;
            goto fail;
        }
        ranges = mrs->ranges;
        nranges = mrs->numr;
    } else {
        ranges = (NvmeCsdMemoryRange *)data;
        nranges = numr;
        status = csd_cp_check_ranges(csd, ranges, nranges, false);
        if (status) {
            goto fail;
        }
    }

    job = g_new0(FemuCsdJob, 1);
    job->cp = true;
    job->cp_numr = nranges;
    job->cp_sb = g_new(uint64_t, nranges);
    job->cp_len = g_new(uint32_t, nranges);
    for (uint32_t i = 0; i < nranges; i++) {
        job->cp_sb[i] = le64_to_cpu(ranges[i].sb);
        job->cp_len[i] = le32_to_cpu(ranges[i].len);
    }
    program->refs++;
    program->use++;
    if (mrs) {
        mrs->use++;
    }
    req->csd_use = CSD_USE_VALID | (uint64_t)rsid << 16 | pind;
    qemu_mutex_unlock(&csd->lock);

    job->program = program;
    job->args.cparam1 = ((uint64_t)le32_to_cpu(cmd->cdw11) << 32) |
                        le32_to_cpu(cmd->cdw10);
    job->args.cparam2 = ((uint64_t)le32_to_cpu(cmd->cdw13) << 32) |
                        le32_to_cpu(cmd->cdw12);
    if (dlen > numr * CSD_DESC_SIZE) {
        job->args.data_buffer = data + numr * CSD_DESC_SIZE;
        job->args.buffer_len = dlen - numr * CSD_DESC_SIZE;
    }
    job->data = g_steal_pointer(&data);
    job->arrival = req->expire_time;
    job->req = req;
    req->opaque = job;
    req->defer = csd_exec_defer;
    return NVME_SUCCESS;

fail:
    qemu_mutex_unlock(&csd->lock);
    return status;
}

uint16_t csd_cp_io_cmd(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                       NvmeRequest *req)
{
    uint16_t status = csd_cp_slm_check_cmd(n, cmd);

    if (status) {
        return status;
    }
    switch (cmd->opcode) {
    case NVME_CMD_FLUSH:
        return NVME_SUCCESS;
    case NVME_CP_CMD_EXECUTE:
        return csd_cp_exec(n, csd_state(n), cmd, req);
    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

/* release what an Execute held; @use is its req->csd_use */
static void csd_cp_use_done_locked(FemuCsdState *csd, uint64_t use)
{
    uint16_t pind = use & 0xffff;
    uint16_t rsid = (use >> 16) & 0xffff;
    FemuCsdProgram *program;
    FemuCsdCpMrs *mrs;

    if (pind >= CSD_CP_NPIND) {
        return;
    }
    program = csd->cp_prog[pind];
    if (program && program->use) {
        program->use--;
    }
    mrs = rsid ? g_hash_table_lookup(csd->cp_mrs, GUINT_TO_POINTER(rsid)) :
                 NULL;
    if (mrs && mrs->use) {
        mrs->use--;
    }
}

/* an Execute dropped with its queue or by a reset */
void femu_csd_req_done(FemuCtrl *n, NvmeRequest *req)
{
    FemuCsdState *csd = csd_state(n);
    uint64_t use = req->csd_use;

    req->csd_use = 0;
    if (!csd || !csd->cp_nsid) {
        return;
    }
    qemu_mutex_lock(&csd->lock);
    csd_cp_use_done_locked(csd, use);
    qemu_mutex_unlock(&csd->lock);
}

/*
 * Post the completion of an Execute. The entry is written and the use ends
 * under csd->lock, so no admin command sees the command complete while its
 * program or set is still in use, or the reverse.
 */
void femu_csd_post_cqe(FemuCtrl *n, NvmeCQueue *cq, NvmeRequest *req)
{
    FemuCsdState *csd = csd_state(n);
    uint64_t use = req->csd_use;

    req->csd_use = 0;
    if (!csd || !csd->cp_nsid) {
        nvme_write_cqe(n, cq, &req->cqe);
        return;
    }
    qemu_mutex_lock(&csd->lock);
    nvme_write_cqe(n, cq, &req->cqe);
    csd_cp_use_done_locked(csd, use);
    qemu_mutex_unlock(&csd->lock);
}

/*
 * On the compute unit thread, before the run: copy each range out of the
 * memory namespace, twice, so the program never holds an address in it and
 * the write-back can tell what the program changed.
 */
uint16_t csd_cp_job_prepare(FemuCsdState *csd, FemuCsdJob *job)
{
    uint64_t total = 0;
    uint64_t o = 0;
    uint32_t i;

    for (i = 0; i < job->cp_numr; i++) {
        total += job->cp_len[i];
    }
    if (total) {
        job->cp_scratch = g_try_malloc(total * 2);
        if (!job->cp_scratch) {
            return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
        }
    }
    job->cp_total = total;
    job->args.numr = job->cp_numr;
    job->args.mr_addr = g_new0(void *, job->cp_numr);
    job->args.mr_len = g_new0(long long, job->cp_numr);

    qemu_mutex_lock(&csd->slm_lock);
    for (i = 0; i < job->cp_numr; i++) {
        /* with no bytes in any range there is no scratch buffer */
        if (job->cp_len[i]) {
            memcpy(job->cp_scratch + o, csd->slm + job->cp_sb[i],
                   job->cp_len[i]);
        }
        job->args.mr_addr[i] = job->cp_scratch + o;
        job->args.mr_len[i] = job->cp_len[i];
        o += job->cp_len[i];
    }
    qemu_mutex_unlock(&csd->slm_lock);
    if (total) {
        memcpy(job->cp_scratch + total, job->cp_scratch, total);
    }
    return NVME_SUCCESS;
}

/*
 * After the run, with csd->lock held: write back the bytes the program
 * changed. A command dropped meanwhile (queue deleted, controller reset) has
 * job->req cleared under the same lock, and then nothing is written.
 */
void csd_cp_job_commit_locked(FemuCsdState *csd, FemuCsdJob *job)
{
    const uint64_t chunk = 4096;
    uint64_t o = 0;

    if (!job->req || !job->cp_total) {
        return;
    }
    qemu_mutex_lock(&csd->slm_lock);
    for (uint32_t i = 0; i < job->cp_numr; i++) {
        uint8_t *cur = job->cp_scratch + o;
        uint8_t *was = job->cp_scratch + job->cp_total + o;
        uint8_t *dst = csd->slm + job->cp_sb[i];

        for (uint64_t c = 0; c < job->cp_len[i]; c += chunk) {
            uint64_t n = MIN(chunk, job->cp_len[i] - c);

            if (!memcmp(cur + c, was + c, n)) {
                continue;
            }
            for (uint64_t b = c; b < c + n; b++) {
                if (cur[b] != was[b]) {
                    dst[b] = cur[b];
                }
            }
        }
        o += job->cp_len[i];
    }
    qemu_mutex_unlock(&csd->slm_lock);
}

/*
 * The device-defined programs. Copy (PIND 0) copies Memory Range 1 into
 * Memory Range 2 and returns the bytes copied. FNV-1a (PIND 1) hashes every
 * range in order, then the program data, and returns the 64-bit hash.
 */
uint16_t csd_cp_run_builtin(FemuCsdProgram *program, FemuCsdArgs *args,
                            int64_t *result)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    uint64_t copy;

    switch (program->type) {
    case CSD_KIND_CP_COPY:
        if (args->numr < 2) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        copy = MIN(args->mr_len[0], args->mr_len[1]);
        memcpy(args->mr_addr[1], args->mr_addr[0], copy);
        *result = copy;
        return NVME_SUCCESS;
    case CSD_KIND_CP_FNV64:
        for (int i = 0; i < args->numr; i++) {
            const uint8_t *p = args->mr_addr[i];

            for (long long j = 0; j < args->mr_len[i]; j++) {
                h = (h ^ p[j]) * 0x100000001b3ULL;
            }
        }
        for (long long j = 0; j < args->buffer_len; j++) {
            h = (h ^ ((uint8_t *)args->data_buffer)[j]) * 0x100000001b3ULL;
        }
        *result = (int64_t)h;
        return NVME_SUCCESS;
    default:
        return NVME_INVALID_FIELD | NVME_DNR;
    }
}
