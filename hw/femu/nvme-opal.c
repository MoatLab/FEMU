/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * The data path side of x-opal (TCG SIIS 1.20, 6.7): lock checks of the
 * I/O commands, the MBR shadow, the erase that a new key or a new owner
 * causes, and the Format, Sanitize and reset rules. The engine
 * (femu-opal.c) owns the state; the pollers read only a copy of its lock
 * view, which changes only while they are stopped.
 *
 *   admin (BQL)                                  pollers
 *   Security Send --> freeze + drain             (stopped)
 *     engine --> erase --> view copy
 *   resume, thaw                                 read n->opal_view
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "system/reset.h"
#include "crypto/random.h"
#include "nvme-opal.h"
#include "bbssd/ftl.h"

#define FEMU_OPAL_DRAIN_US  (10 * G_USEC_PER_SEC)

/* x-opal allows one namespace only (femu_opal_config_check) */
static NvmeNamespace *opal_ns(FemuCtrl *n)
{
    return nvme_ns_allocated(n, 1);
}

/*
 * The engine erases [slba, slba + nlb) of the current format when a range
 * gets a new key or a new owner (Opal 2.30, 4.3.6.6). The data, the
 * written state and the lost, uncorrectable and LSI marks go. A NAND page
 * the extent covers in part keeps its mapping for the neighbour LBAs.
 */
static void opal_erase(void *opaque, uint64_t slba, uint64_t nlb)
{
    FemuCtrl *n = opaque;
    NvmeNamespace *ns = opal_ns(n);
    uint64_t done = 0;

    if (!ns) {
        return;
    }
    while (done < nlb) {
        uint32_t step = MIN(nlb - done, UINT32_MAX);

        nvme_deallocate_range(n, ns, slba + done, step);
        done += step;
    }
    femu_lsi_clear(ns, slba, nlb);
    if (NS_BBSSD(ns)) {
        bbssd_deallocate_lbas(ns, slba, nlb);
    }
}

/* the namespace geometry, then a new view for the pollers; quiet only */
void femu_opal_publish(FemuCtrl *n)
{
    NvmeNamespace *ns = opal_ns(n);

    if (ns) {
        n->opal_tper->cfg.lba_size = NVME_ID_NS_LBADS_BYTES(ns);
        n->opal_tper->cfg.nlbas = le64_to_cpu(ns->id_ns.nsze);
    }
    femu_opal_view(n->opal_tper, n->opal_view);
}

/*
 * A machine reset is a PCIe warm reset: a TCG Hardware Reset (SIIS Table
 * 20). The device reset callback also serves an FLR and a bridge hot
 * reset, which are no TCG reset, so this hook runs on a machine reset
 * only.
 */
static void opal_machine_reset(void *opaque)
{
    FemuCtrl *n = opaque;
    bool resume = nvme_pause_pollers(n);

    femu_opal_hw_reset(n->opal_tper);
    femu_opal_publish(n);
    nvme_resume_pollers(n, resume);
}

static bool opal_rand(void *opaque, uint8_t *buf, size_t len)
{
    return !qcrypto_random_bytes(buf, len, NULL);
}

/* the engine at realize, before the dataplane runs */
void femu_opal_start(FemuCtrl *n, FemuOpalCfg *cfg)
{
    cfg->erase = opal_erase;
    cfg->rand = opal_rand;
    cfg->opaque = n;
    n->opal_tper = g_new(FemuOpal, 1);
    n->opal_view = g_new0(FemuOpalView, 1);
    femu_opal_init(n->opal_tper, cfg);
    femu_opal_publish(n);
    qemu_register_reset(opal_machine_reset, n);
}

/*
 * A TCG power cycle for the qtest: QMP system_reset is a hardware reset
 * (opal_machine_reset). False when the I/O did not drain.
 */
bool femu_opal_test_power_cycle(FemuCtrl *n)
{
    bool resume;

    if (!n->opal_tper || !femu_opal_quiet(n, &resume)) {
        return false;
    }
    femu_opal_power_cycle(n->opal_tper);
    femu_opal_publish(n);
    femu_opal_loud(n, resume);
    return true;
}

void femu_opal_stop(FemuCtrl *n)
{
    if (n->opal_tper) {
        qemu_unregister_reset(opal_machine_reset, n);
    }
    g_clear_pointer(&n->opal_tper, femu_opal_free);
    g_clear_pointer(&n->opal_view, g_free);
}

/*
 * Stop new I/O and wait for the I/O already taken. Returns false when it
 * did not drain in time; then nothing is stopped.
 */
bool femu_opal_quiet(FemuCtrl *n, bool *resume)
{
    bool held = qatomic_read(&n->test_ftl_hold) == 2;
    Error *err = NULL;

    if (!nvme_freeze_drain(n, g_get_monotonic_time() + FEMU_OPAL_DRAIN_US,
                           resume, &err)) {
        error_free(err);
        return false;
    }
    if (held) {
        femu_ftl_hold_put(n, 2);
    }
    return true;
}

void femu_opal_loud(FemuCtrl *n, bool resume)
{
    nvme_resume_pollers(n, resume);
    nvme_thaw(n);
}

/*
 * Security Send (SECP 01h and 02h). Every Send can change locks, keys or
 * MBR bytes, and a STACK_RESET can roll back a transaction, so the engine
 * runs only while no I/O is in flight.
 */
FemuOpalIf femu_opal_quiet_send(FemuCtrl *n, uint8_t secp, uint16_t spsp,
                                const uint8_t *buf, uint32_t len,
                                bool *timeout)
{
    FemuOpalIf r;
    bool resume;

    *timeout = !femu_opal_quiet(n, &resume);
    if (*timeout) {
        return FEMU_OPAL_IF_GOOD;
    }
    femu_opal_publish(n);
    r = femu_opal_send(n->opal_tper, secp, spsp, buf, len);
    femu_opal_publish(n);
    femu_opal_loud(n, resume);
    return r;
}

/*
 * The lock check of Read, Write, Write Zeroes, Write Uncorrectable, Compare
 * and Verify, which give SLBA and NLB at the same place. Returns true when
 * the command ends here with *status: refused, or served from the MBR
 * shadow or as zeros. A range past the namespace or past MDTS goes on, so
 * that its handler reports it.
 */
bool femu_opal_io(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                  NvmeRequest *req, uint16_t *status)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)cmd;
    uint64_t slba = le64_to_cpu(rw->slba);
    uint32_t nlb = le16_to_cpu(rw->nlb) + 1;
    uint64_t nsze = le64_to_cpu(ns->id_ns.nsze);
    uint64_t size = (uint64_t)nlb << NVME_ID_NS_LBADS(ns);
    g_autofree uint8_t *buf = NULL;
    g_autofree uint8_t *host = NULL;
    FemuOpalAccess a;
    FemuOpalOp op;

    switch (cmd->opcode) {
    case NVME_CMD_READ:
        op = FEMU_OPAL_OP_READ;
        break;
    case NVME_CMD_COMPARE:
    case NVME_CMD_VERIFY:
        op = FEMU_OPAL_OP_VERIFY;
        break;
    case NVME_CMD_WRITE:
    case NVME_CMD_WRITE_ZEROES:
    case NVME_CMD_WRITE_UNCOR:
        op = FEMU_OPAL_OP_WRITE;
        break;
    default:
        return false;
    }
    if (cmd->opcode != NVME_CMD_READ && cmd->opcode != NVME_CMD_WRITE &&
        !nvme_ns_io_effects(n, ns, cmd->opcode)) {
        return false;
    }
    if (slba > nsze || nlb > nsze - slba) {
        return false;
    }
    /* a structural error comes before the lock result */
    if ((cmd->opcode == NVME_CMD_READ || cmd->opcode == NVME_CMD_WRITE ||
         cmd->opcode == NVME_CMD_COMPARE) && nvme_check_mdts(n, size)) {
        return false;
    }
    a = femu_opal_access(n->opal_view, op, slba, nlb);
    if (a == FEMU_OPAL_MEDIA) {
        return false;
    }
    if (a == FEMU_OPAL_DENY) {
        *status = NVME_ACCESS_DENIED | NVME_DNR;
        return true;
    }
    /* no media: the FTL charges one page read (femu_opal_synth_lat) */
    req->is_write = 0;
    req->slba = slba;
    req->nlb = nlb;
    req->opal_synth = true;
    *status = NVME_SUCCESS;
    if (cmd->opcode == NVME_CMD_VERIFY) {
        return true;
    }
    buf = g_malloc0(size);
    if (a == FEMU_OPAL_SHADOW) {
        femu_opal_mbr_read(n->opal_tper, slba * NVME_ID_NS_LBADS_BYTES(ns),
                           buf, size);
    }
    if (cmd->opcode == NVME_CMD_READ) {
        *status = dma_read_cmd(n, cmd, buf, size);
        return true;
    }
    host = g_malloc(size);
    *status = dma_write_cmd(n, cmd, host, size);
    if (!*status && memcmp(host, buf, size)) {
        *status = NVME_CMP_FAILURE | NVME_DNR;
    }
    return true;
}

/* one page read for a command served from the MBR shadow or as zeros */
uint64_t femu_opal_synth_lat(NvmeRequest *req)
{
    uint16_t sc = req->status & 0x7ff;

    if (sc != NVME_SUCCESS && sc != NVME_CMP_FAILURE) {
        return 0;
    }
    return req->ns && NS_BBSSD(req->ns) && req->ns->ssd ?
           req->ns->ssd->sp.pg_rd_lat : 0;
}

/*
 * Format NVM is refused when an LBA it formats has a write-locked owner
 * (SIIS 6.7.3). The MBR shadow plays no part, and a range past the end
 * or an empty one owns no LBA.
 */
bool femu_opal_format_ok(FemuCtrl *n)
{
    NvmeNamespace *ns = opal_ns(n);
    FemuOpalView v = *n->opal_view;
    uint64_t nsze;

    if (!ns) {
        return true;
    }
    nsze = le64_to_cpu(ns->id_ns.nsze);
    v.shadow = false;
    return !nsze ||
           femu_opal_access(&v, FEMU_OPAL_OP_WRITE, 0, nsze) != FEMU_OPAL_DENY;
}

/* Sanitize is refused while the Locking SP is active (SIIS 6.7.4) */
bool femu_opal_owned(FemuCtrl *n)
{
    return n->opal_view && n->opal_view->enabled;
}
