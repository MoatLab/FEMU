#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "hw/qdev-properties.h"

#include "./nvme.h"

#define NVME_SPEC_VER (0x00010400)

/* ========== NVMe Subsystem (femu-subsys) QOM Device ========== */

int femu_subsys_register_ctrl(FemuCtrl *n)
{
    NvmeSubsystem *subsys = n->subsys;
    int cntlid;

    for (cntlid = 0; cntlid < ARRAY_SIZE(subsys->ctrls); cntlid++) {
        if (!subsys->ctrls[cntlid]) {
            break;
        }
    }

    if (cntlid == ARRAY_SIZE(subsys->ctrls)) {
        return -1;
    }

    if (!subsys->serial) {
        subsys->serial = g_strdup(n->serial);
    }

    subsys->ctrls[cntlid] = n;

    return cntlid;
}

void femu_subsys_unregister_ctrl(NvmeSubsystem *subsys, FemuCtrl *n)
{
    subsys->ctrls[n->cntlid] = NULL;
    n->cntlid = -1;
}

static bool nvme_calc_rgif(uint16_t nruh, uint16_t nrg, uint8_t *rgif)
{
    uint16_t val;
    unsigned int i;

    if (unlikely(nrg == 1)) {
        *rgif = 0;
        return true;
    }

    val = nrg;
    i = 0;
    while (val) {
        val >>= 1;
        i++;
    }
    *rgif = i;

    if (unlikely((UINT16_MAX >> i) < nruh)) {
        *rgif = 0;
        return false;
    }

    return true;
}

static bool nvme_subsys_setup_fdp(NvmeSubsystem *subsys, Error **errp)
{
    NvmeEnduranceGroup *endgrp = &subsys->endgrp;
    uint64_t tt_nru = subsys->params.fdp.nru;
    uint16_t ruhid;

    if (!subsys->params.fdp.runs) {
        error_setg(errp, "fdp.runs must be non-zero");
        return false;
    }
    endgrp->fdp.runs = subsys->params.fdp.runs;
    endgrp->fdp.nru = subsys->params.fdp.nru;

    if (!subsys->params.fdp.nrg) {
        error_setg(errp, "fdp.nrg must be non-zero");
        return false;
    }
    endgrp->fdp.nrg = subsys->params.fdp.nrg;

    if (!subsys->params.fdp.nruh) {
        error_setg(errp, "fdp.nruh must be non-zero");
        return false;
    }
    if (subsys->params.fdp.nruh > tt_nru) {
        error_setg(errp, "fdp.nruh (%u) must not exceed fdp.nru (%"PRIu64")",
                   subsys->params.fdp.nruh, tt_nru);
        return false;
    }
    endgrp->fdp.nruh = subsys->params.fdp.nruh;

    if (!nvme_calc_rgif(endgrp->fdp.nruh, endgrp->fdp.nrg,
                        &endgrp->fdp.rgif)) {
        error_setg(errp, "cannot derive a valid rgif "
                   "(nruh %"PRIu16" nrg %"PRIu16")",
                   endgrp->fdp.nruh, endgrp->fdp.nrg);
        return false;
    }

    endgrp->fdp.rus = g_new(NvmeReclaimUnit *, endgrp->fdp.nrg);
    for (int i = 0; i < endgrp->fdp.nrg; i++) {
        endgrp->fdp.rus[i] = g_new0(NvmeReclaimUnit, tt_nru);
    }

    endgrp->fdp.ruhs = g_new0(NvmeRuHandle, endgrp->fdp.nruh);

    for (ruhid = 0; ruhid < endgrp->fdp.nruh; ruhid++) {
        /*
         * isolation_mode=0 (default): all RUHs are Persistently Isolated (PI).
         * isolation_mode=1: last RUH is Initially Isolated (II), rest are PI.
         * This matches the fdp.isolation_mode QOM property.
         */
        uint8_t ruht = NVME_RUHT_PERSISTENTLY_ISOLATED;
        if (subsys->params.fdp.isolation_mode &&
            ruhid == endgrp->fdp.nruh - 1) {
            ruht = NVME_RUHT_INITIALLY_ISOLATED;
        }
        endgrp->fdp.ruhs[ruhid] = (NvmeRuHandle) {
            .ruht = ruht,
            .ruha = NVME_RUHA_UNUSED,
            /* enable all FDP event types by default */
            .event_filter = UINT64_MAX,
        };
        endgrp->fdp.ruhs[ruhid].rus =
            g_new(NvmeReclaimUnit *, endgrp->fdp.nrg);
        for (int rg = 0; rg < endgrp->fdp.nrg; rg++) {
            endgrp->fdp.ruhs[ruhid].rus[rg] =
                &endgrp->fdp.rus[rg][ruhid];
        }
    }

    endgrp->fdp.enabled = true;
    femu_log("FDP enabled: nruh=%u, nrg=%u, runs=%lu, nru=%lu\n",
             endgrp->fdp.nruh, endgrp->fdp.nrg,
             endgrp->fdp.runs, endgrp->fdp.nru);

    return true;
}

static bool nvme_subsys_setup(NvmeSubsystem *subsys, Error **errp)
{
    const char *nqn = subsys->params.nqn ?
        subsys->params.nqn : subsys->parent_obj.id;

    snprintf((char *)subsys->subnqn, sizeof(subsys->subnqn),
             "nqn.2019-08.org.qemu:%s", nqn);

    if (subsys->params.fdp.enabled &&
        !nvme_subsys_setup_fdp(subsys, errp)) {
        return false;
    }

    return true;
}

static void nvme_subsys_realize(DeviceState *dev, Error **errp)
{
    NvmeSubsystem *subsys = NVME_SUBSYS(dev);

    qbus_init(&subsys->bus, sizeof(NvmeBus), TYPE_NVME_BUS, dev, dev->id);
    nvme_subsys_setup(subsys, errp);
}

static const Property nvme_subsystem_props[] = {
    DEFINE_PROP_STRING("nqn", NvmeSubsystem, params.nqn),
    DEFINE_PROP_BOOL("fdp", NvmeSubsystem, params.fdp.enabled, false),
    DEFINE_PROP_SIZE("fdp.runs", NvmeSubsystem, params.fdp.runs,
                     NVME_DEFAULT_RU_SIZE),
    DEFINE_PROP_UINT32("fdp.nrg", NvmeSubsystem, params.fdp.nrg, 1),
    DEFINE_PROP_UINT16("fdp.nruh", NvmeSubsystem, params.fdp.nruh, 0),
    DEFINE_PROP_UINT64("fdp.nru", NvmeSubsystem, params.fdp.nru, 128),
    DEFINE_PROP_UINT32("fdp.isolation_mode", NvmeSubsystem,
                       params.fdp.isolation_mode, 0),
};

static void nvme_subsys_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);

    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    dc->realize = nvme_subsys_realize;
    dc->desc = "FEMU NVMe Subsystem (FDP)";
    device_class_set_props(dc, nvme_subsystem_props);
}

static const TypeInfo nvme_subsys_info = {
    .name          = TYPE_NVME_SUBSYS,
    .parent        = TYPE_DEVICE,
    .instance_size = sizeof(NvmeSubsystem),
    .class_init    = nvme_subsys_class_init,
};

/* ========== FDP Namespace Init ========== */

static bool nvme_ns_init_fdp(NvmeNamespace *ns, Error **errp)
{
    NvmeEnduranceGroup *endgrp = ns->endgrp;
    NvmeRuHandle *ruh;
    uint8_t lbafi = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    uint16_t *ph;

    if (!endgrp || !endgrp->fdp.enabled) {
        return true;
    }

    /*
     * Auto-assign all RUHs to this namespace sequentially.
     * Each RUH gets a placement handle index.
     */
    ns->fdp.nphs = endgrp->fdp.nruh;
    ph = ns->fdp.phs = g_new(uint16_t, ns->fdp.nphs);

    for (uint16_t i = 0; i < ns->fdp.nphs; i++, ph++) {
        ruh = &endgrp->fdp.ruhs[i];

        if (ruh->ruha == NVME_RUHA_UNUSED) {
            ruh->ruha = NVME_RUHA_HOST;
            ruh->lbafi = lbafi;
            ruh->ruamw = endgrp->fdp.runs >> ns->lbaf.lbads;
            ruh->hbmw = 0;
            ruh->mbmw = 0;
            ruh->mbe = 0;

            for (uint16_t rg = 0; rg < endgrp->fdp.nrg; rg++) {
                for (uint64_t j = 0; j < endgrp->fdp.nru; j++) {
                    endgrp->fdp.rus[rg][j].ruamw = ruh->ruamw;
                }
            }
        }

        *ph = i;
    }

    femu_log("FDP ns init: nphs=%u, ruamw=%lu\n",
             ns->fdp.nphs,
             endgrp->fdp.ruhs[0].ruamw);
    return true;
}

/* ========== FDP Subsystem Registration ========== */

static int nvme_init_subsys(FemuCtrl *n)
{
    int cntlid;

    if (!n->subsys) {
        return 0;
    }

    cntlid = femu_subsys_register_ctrl(n);
    if (cntlid < 0) {
        return -1;
    }

    n->cntlid = cntlid;

    return 0;
}

/* ========== End FDP Subsystem ========== */

static void nvme_clear_ctrl(FemuCtrl *n, bool shutdown)
{
    NvmeAsyncEvent *event;
    int i;

    /* Coperd: pause nvme poller at earliest convenience */
    n->dataplane_started = false;

    /*
     * Drop every Async Event Request the controller was holding, along with any
     * event queued for one. A reset ends the commands the host had outstanding,
     * so completing one afterwards would post to an entry the host has already
     * reclaimed -- which the driver takes as a completion for a request it no
     * longer owns.
     */
    while ((event = QSIMPLEQ_FIRST(&n->aer_queue)) != NULL) {
        QSIMPLEQ_REMOVE_HEAD(&n->aer_queue, entry);
        g_free(event);
    }
    n->aer_queued = 0;
    n->aer_mask = 0;
    n->outstanding_aers = 0;
    n->temp_warn_issued = 0;

    /*
     * Quiesce the pollers before freeing queues / unmapping the dbbuf shadow
     * regions below. Without this, a poller mid-sweep can write a freed
     * eventidx_addr_hva (use-after-free segfault on guest reboot / controller
     * reset). Pair with the Dekker-style handshake in nvme_poller():
     * dataplane_started is now false + barrier, so any poller will observe it
     * and clear its in_sweep flag; wait here until all are idle.
     */
    smp_mb();
    if (n->poller_on && n->poller_in_sweep) {
        int p;
        bool busy;
        do {
            busy = false;
            for (p = 1; p <= (int)n->nr_pollers; p++) {
                if (n->poller_in_sweep[p]) {
                    busy = true;
                    break;
                }
            }
            if (busy) {
                usleep(100);
            }
        } while (busy);
    }

    if (shutdown) {
        femu_debug("shutting down NVMe Controller ...\n");
    } else {
        femu_debug("disabling NVMe Controller ...\n");
    }

    if (shutdown) {
        femu_debug("%s,clear_guest_notifier\n", __func__);
        nvme_clear_virq(n);
    }

    for (i = 0; i <= n->nr_io_queues; i++) {
        if (n->sq[i] != NULL) {
            nvme_free_sq(n->sq[i], n);
        }
    }
    for (i = 0; i <= n->nr_io_queues; i++) {
        if (n->cq[i] != NULL) {
            nvme_free_cq(n->cq[i], n);
        }
    }

    n->bar.cc = 0;
    n->features.temp_thresh = 0x14d;
    n->temp_warn_issued = 0;
    n->dbs_addr = 0;
    n->dbs_addr_hva = 0;
    n->eis_addr = 0;
    n->eis_addr_hva = 0;
}

static int nvme_start_ctrl(FemuCtrl *n)
{
    uint32_t page_bits = NVME_CC_MPS(n->bar.cc) + 12;
    uint32_t page_size = 1 << page_bits;

    if (n->cq[0] || n->sq[0] || !n->bar.asq || !n->bar.acq ||
        n->bar.asq & (page_size - 1) || n->bar.acq & (page_size - 1) ||
        NVME_CC_MPS(n->bar.cc) < NVME_CAP_MPSMIN(n->bar.cap) ||
        NVME_CC_MPS(n->bar.cc) > NVME_CAP_MPSMAX(n->bar.cap) ||
        NVME_CC_IOCQES(n->bar.cc) < NVME_CTRL_CQES_MIN(n->id_ctrl.cqes) ||
        NVME_CC_IOCQES(n->bar.cc) > NVME_CTRL_CQES_MAX(n->id_ctrl.cqes) ||
        NVME_CC_IOSQES(n->bar.cc) < NVME_CTRL_SQES_MIN(n->id_ctrl.sqes) ||
        NVME_CC_IOSQES(n->bar.cc) > NVME_CTRL_SQES_MAX(n->id_ctrl.sqes) ||
        !NVME_AQA_ASQS(n->bar.aqa) || NVME_AQA_ASQS(n->bar.aqa) > 4095 ||
        !NVME_AQA_ACQS(n->bar.aqa) || NVME_AQA_ACQS(n->bar.aqa) > 4095) {
        return -1;
    }

    n->page_bits = page_bits;
    n->page_size = 1 << n->page_bits;
    n->max_prp_ents = n->page_size / sizeof(uint64_t);
    n->cqe_size = 1 << NVME_CC_IOCQES(n->bar.cc);
    n->sqe_size = 1 << NVME_CC_IOSQES(n->bar.cc);

    nvme_init_cq(&n->admin_cq, n, n->bar.acq, 0, 0, NVME_AQA_ACQS(n->bar.aqa) +
                 1, 1, 1);
    nvme_init_sq(&n->admin_sq, n, n->bar.asq, 0, 0, NVME_AQA_ASQS(n->bar.aqa) +
                 1, NVME_Q_PRIO_HIGH, 1);

    /* Currently only used by FEMU ZNS extension */
    if (n->ext_ops.start_ctrl) {
        n->ext_ops.start_ctrl(n);
    }

    return 0;
}

static void nvme_write_bar(FemuCtrl *n, hwaddr offset, uint64_t data, unsigned size)
{
    switch (offset) {
    case 0xc:
        n->bar.intms |= data & 0xffffffff;
        n->bar.intmc = n->bar.intms;
        break;
    case 0x10:
        n->bar.intms &= ~(data & 0xffffffff);
        n->bar.intmc = n->bar.intms;
        break;
    case 0x14:
        /* If first sending data, then sending enable bit */
        if (!NVME_CC_EN(data) && !NVME_CC_EN(n->bar.cc) &&
                !NVME_CC_SHN(data) && !NVME_CC_SHN(n->bar.cc))
        {
            n->bar.cc = data;
        }

        if (NVME_CC_EN(data) && !NVME_CC_EN(n->bar.cc)) {
            n->bar.cc = data;
            if (nvme_start_ctrl(n)) {
                n->bar.csts = NVME_CSTS_FAILED;
            } else {
                n->bar.csts = NVME_CSTS_READY;
            }
        } else if (!NVME_CC_EN(data) && NVME_CC_EN(n->bar.cc)) {
            nvme_clear_ctrl(n, false);
            n->bar.csts &= ~NVME_CSTS_READY;
        }
        if (NVME_CC_SHN(data) && !(NVME_CC_SHN(n->bar.cc))) {
            nvme_clear_ctrl(n, true);
            n->bar.cc = data;
            n->bar.csts |= NVME_CSTS_SHST_COMPLETE;
        } else if (!NVME_CC_SHN(data) && NVME_CC_SHN(n->bar.cc)) {
            n->bar.csts &= ~NVME_CSTS_SHST_COMPLETE;
            n->bar.cc = data;
        }
        break;
    case 0x24:
        n->bar.aqa = data & 0xffffffff;
        break;
    case 0x28:
        n->bar.asq = data;
        break;
    case 0x2c:
        n->bar.asq |= data << 32;
        break;
    case 0x30:
        n->bar.acq = data;
        break;
    case 0x34:
        n->bar.acq |= data << 32;
        break;
    default:
        break;
    }
}

static uint64_t nvme_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    FemuCtrl *n = (FemuCtrl *)opaque;
    uint8_t *ptr = (uint8_t *)&n->bar;
    uint64_t val = 0;

    if (addr < sizeof(n->bar)) {
        memcpy(&val, ptr + addr, size);
    }

    return val;
}

static void nvme_process_db_admin(FemuCtrl *n, hwaddr addr, int val)
{
    uint32_t qid;
    uint16_t new_val = val & 0xffff;
    NvmeSQueue *sq;

    if (((addr - 0x1000) >> (2 + n->db_stride)) & 1) {
        NvmeCQueue *cq;

        qid = ((addr - (0x1000 + (1 << (2 + n->db_stride)))) >> (3 +
                                                                 n->db_stride));
        if (nvme_check_cqid(n, qid)) {
            return;
        }

        cq = n->cq[qid];
        if (new_val >= cq->size) {
            return;
        }

        cq->head = new_val;

        if (cq->tail != cq->head) {
            nvme_isr_notify_admin(cq);
        }
    } else {
        qid = (addr - 0x1000) >> (3 + n->db_stride);
        if (nvme_check_sqid(n, qid)) {
            return;
        }
        sq = n->sq[qid];
        if (new_val >= sq->size) {
            return;
        }

        sq->tail = new_val;
        nvme_process_sq_admin(sq);
    }
}

static void nvme_process_db_io(FemuCtrl *n, hwaddr addr, int val)
{
    uint32_t qid;
    uint16_t new_val = val & 0xffff;
    NvmeSQueue *sq;

    if (n->dataplane_started) {
        return;
    }

    if (addr & ((1 << (2 + n->db_stride)) - 1)) {
        return;
    }

    if (((addr - 0x1000) >> (2 + n->db_stride)) & 1) {
        NvmeCQueue *cq;

        qid = ((addr - (0x1000 + (1 << (2 + n->db_stride)))) >> (3 +
                                                                 n->db_stride));
        if (nvme_check_cqid(n, qid)) {
            return;
        }

        cq = n->cq[qid];
        if (new_val >= cq->size) {
            return;
        }

        if (!cq->db_addr) {
            cq->head = new_val;
        }

        if (cq->tail != cq->head) {
            nvme_isr_notify_io(cq);
        }
    } else {
        qid = (addr - 0x1000) >> (3 + n->db_stride);
        if (nvme_check_sqid(n, qid)) {
            return;
        }
        sq = n->sq[qid];
        if (new_val >= sq->size) {
            return;
        }

        if (!sq->db_addr) {
            sq->tail = new_val;
        }
    }
}

static void nvme_mmio_write(void *opaque, hwaddr addr, uint64_t data, unsigned size)
{
    FemuCtrl *n = (FemuCtrl *)opaque;
    if (addr < sizeof(n->bar)) {
        nvme_write_bar(n, addr, data, size);
    } else if (addr >= 0x1000 && addr < 0x1008) {
        nvme_process_db_admin(n, addr, data);
    } else {
        nvme_process_db_io(n, addr, data);
    }
}

static void nvme_cmb_write(void *opaque, hwaddr addr, uint64_t data, unsigned size)
{
    FemuCtrl *n = (FemuCtrl *)opaque;

    memcpy(&n->cmbuf[addr], &data, size);
}

static uint64_t nvme_cmb_read(void *opaque, hwaddr addr, unsigned size)
{
    uint64_t val;
    FemuCtrl *n = (FemuCtrl *)opaque;

    memcpy(&val, &n->cmbuf[addr], size);

    return val;
}

static const MemoryRegionOps nvme_cmb_ops = {
    .read = nvme_cmb_read,
    .write = nvme_cmb_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 2,
        .max_access_size = 8,
    },
};

static const MemoryRegionOps nvme_mmio_ops = {
    .read = nvme_mmio_read,
    .write = nvme_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 2,
        .max_access_size = 8,
    },
};

static bool nvme_check_constraints(FemuCtrl *n, Error **errp)
{
    if (n->num_namespaces == 0 ||
        n->num_namespaces > NVME_MAX_NUM_NAMESPACES) {
        error_setg(errp, "namespaces must be in [1, %d]",
                   NVME_MAX_NUM_NAMESPACES);
        return false;
    }
    if (n->nr_io_queues < 1 || n->nr_io_queues > NVME_MAX_QS) {
        error_setg(errp, "queues must be in [1, %d]", NVME_MAX_QS);
        return false;
    }
    if (n->db_stride > NVME_MAX_STRIDE) {
        error_setg(errp, "stride must not exceed %d", NVME_MAX_STRIDE);
        return false;
    }
    if (n->max_q_ents < 1) {
        error_setg(errp, "entries must be at least 1");
        return false;
    }
    if (n->max_sqes > NVME_MAX_QUEUE_ES || n->max_cqes > NVME_MAX_QUEUE_ES ||
        n->max_sqes < NVME_MIN_SQUEUE_ES || n->max_cqes < NVME_MIN_CQUEUE_ES) {
        error_setg(errp, "max_sqes must be in [%d, %d] and max_cqes in [%d, %d]",
                   NVME_MIN_SQUEUE_ES, NVME_MAX_QUEUE_ES,
                   NVME_MIN_CQUEUE_ES, NVME_MAX_QUEUE_ES);
        return false;
    }
    if (n->vwc > 1 || n->intc > 1 || n->cqr > 1 || n->extended > 1) {
        error_setg(errp, "vwc, intc, cqr and extended are single bits");
        return false;
    }
    if (n->nlbaf > 16 || n->lba_index >= n->nlbaf) {
        error_setg(errp, "nlbaf must be in [1, 16] and lba_index below it");
        return false;
    }
    if ((n->meta && !n->mc) ||
        (n->extended && !NVME_ID_NS_MC_EXTENDED(n->mc)) ||
        (!n->extended && n->meta && !NVME_ID_NS_MC_SEPARATE(n->mc))) {
        error_setg(errp, "meta/extended need a matching metadata capability (mc)");
        return false;
    }
    if ((n->dps && n->meta < 8) ||
        (n->dps && (n->dps & DPS_FIRST_EIGHT) &&
         !NVME_ID_NS_DPC_FIRST_EIGHT(n->dpc)) ||
        (n->dps && !(n->dps & DPS_FIRST_EIGHT) &&
         !NVME_ID_NS_DPC_LAST_EIGHT(n->dpc)) ||
        ((n->dps & DPS_TYPE_MASK) &&
         !((n->dpc & NVME_ID_NS_DPC_TYPE_MASK) &
           (1 << ((n->dps & DPS_TYPE_MASK) - 1))))) {
        error_setg(errp, "dps needs 8 bytes of metadata and a matching dpc");
        return false;
    }
    if (n->mpsmax > 0xf || n->mpsmax < n->mpsmin) {
        error_setg(errp, "mpsmax must be in [mpsmin, 15]");
        return false;
    }
    if (n->oacs & ~NVME_OACS_FORMAT) {
        error_setg(errp, "oacs may only set Format NVM (0x%x)", NVME_OACS_FORMAT);
        return false;
    }
    if (n->oncs & ~(NVME_ONCS_COMPARE | NVME_ONCS_WRITE_UNCORR |
                    NVME_ONCS_DSM | NVME_ONCS_WRITE_ZEROS)) {
        error_setg(errp, "oncs may only set Compare, Write Uncorrectable, "
                   "DSM and Write Zeroes");
        return false;
    }

    return true;
}

static void nvme_ns_init_identify(FemuCtrl *n, NvmeIdNs *id_ns)
{
    int npdg;
    int i;

    /* NSFEAT Bit 3: Support the Deallocated or Unwritten Logical Block error */
    id_ns->nsfeat        |= (0x4 | 0x10);
    id_ns->nlbaf         = n->nlbaf - 1;
    id_ns->flbas         = n->lba_index | (n->extended << 4);
    id_ns->mc            = n->mc;
    id_ns->dpc           = n->dpc;
    id_ns->dps           = n->dps;
    id_ns->dlfeat        = 0x9;
    id_ns->lbaf[0].lbads = 9;
    id_ns->lbaf[0].ms    = 0;

    npdg = 1;
    id_ns->npda = id_ns->npdg = npdg - 1;

    for (i = 0; i < n->nlbaf; i++) {
        id_ns->lbaf[i].lbads = BDRV_SECTOR_BITS + i;
        id_ns->lbaf[i].ms    = cpu_to_le16(n->meta);
    }
}

static int nvme_init_namespace(FemuCtrl *n, NvmeNamespace *ns, Error **errp)
{
    NvmeIdNs *id_ns = &ns->id_ns;
    uint64_t num_blks;
    int lba_index;

    nvme_ns_init_identify(n, id_ns);

    lba_index = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    /* size this namespace from its own backend slice, not the whole backend */
    num_blks = ns->size / ((1 << id_ns->lbaf[lba_index].lbads));
    id_ns->nuse = id_ns->ncap = id_ns->nsze = cpu_to_le64(num_blks);

    ns->ctrl = n;
    ns->ns_blks = ns_blks(ns, lba_index);
    ns->util = bitmap_new(num_blks);
    ns->uncorrectable = bitmap_new(num_blks);

    /* FDP: cache lbaf for this namespace */
    ns->lbaf = id_ns->lbaf[lba_index];

    /* FDP: connect subsystem and endurance group, then init FDP state */
    if (n->subsys) {
        ns->subsys = n->subsys;
        ns->endgrp = &n->subsys->endgrp;
        if (!nvme_ns_init_fdp(ns, errp)) {
            return -1;
        }
    }

    return 0;
}

/* map a namespace_modes token to a femu_mode; returns -1 on an unknown token */
static int nvme_mode_from_token(const char *tok)
{
    if (!strcmp(tok, "nossd"))  return FEMU_NOSSD_MODE;
    if (!strcmp(tok, "bbssd"))  return FEMU_BBSSD_MODE;
    if (!strcmp(tok, "znssd"))  return FEMU_ZNSSD_MODE;
    if (!strcmp(tok, "ocssd"))  return FEMU_OCSSD_MODE;
    if (!strcmp(tok, "csd"))    return FEMU_CSD_MODE;
    if (!strcmp(tok, "kvssd"))  return FEMU_KVSSD_MODE;
    return -1;
}

/*
 * Resolve each namespace's mode. With namespace_modes unset every namespace runs
 * the controller's femu_mode, which is the homogeneous behavior. When set, it is
 * a comma-separated per-namespace list (e.g. "znssd,bbssd") whose count must
 * equal namespaces.
 */
static int nvme_resolve_ns_modes(FemuCtrl *n, uint8_t *out_modes, Error **errp)
{
    char *dup, *saveptr = NULL, *tok;
    int i;

    if (!n->namespace_modes || !n->namespace_modes[0]) {
        for (i = 0; i < n->num_namespaces; i++) {
            out_modes[i] = n->femu_mode;
        }
        return 0;
    }

    dup = g_strdup(n->namespace_modes);
    tok = strtok_r(dup, ",", &saveptr);
    i = 0;
    while (tok && i < n->num_namespaces) {
        int m = nvme_mode_from_token(tok);

        if (m < 0) {
            error_setg(errp, "namespace_modes: unknown mode '%s'", tok);
            g_free(dup);
            return -1;
        }
        out_modes[i++] = (uint8_t)m;
        tok = strtok_r(NULL, ",", &saveptr);
    }
    if (i != n->num_namespaces || tok) {
        error_setg(errp, "namespace_modes count must equal namespaces=%u",
                   n->num_namespaces);
        g_free(dup);
        return -1;
    }
    g_free(dup);

    return 0;
}

/*
 * Resolve each namespace's byte size. With namespace_sizes unset the backend is
 * split equally, which for a single namespace hands it the whole backend. When
 * set, it is a comma-separated per-namespace list (e.g. "8G,4G") whose count must
 * equal namespaces, each entry at least one sector, and whose sum must fit the
 * backend. Sizes are rounded down to a sector so slices stay sector-aligned.
 */
static int nvme_resolve_ns_sizes(FemuCtrl *n, uint64_t total, uint64_t *out_sizes,
                                 Error **errp)
{
    char *dup, *saveptr = NULL, *tok;
    uint64_t sum = 0;
    int i;

    if (!n->namespace_sizes || !n->namespace_sizes[0]) {
        uint64_t each = total / n->num_namespaces;

        each &= ~((uint64_t)(1 << BDRV_SECTOR_BITS) - 1);
        if (each == 0) {
            error_setg(errp, "backend capacity %" PRIu64 " B is too small for %u "
                       "namespaces", total, n->num_namespaces);
            return -1;
        }
        for (i = 0; i < n->num_namespaces; i++) {
            out_sizes[i] = each;
        }
        return 0;
    }

    dup = g_strdup(n->namespace_sizes);
    tok = strtok_r(dup, ",", &saveptr);
    i = 0;
    while (tok && i < n->num_namespaces) {
        uint64_t sz;

        if (qemu_strtosz(tok, NULL, &sz) < 0 || sz == 0) {
            error_setg(errp, "namespace_sizes: invalid size '%s'", tok);
            g_free(dup);
            return -1;
        }
        sz &= ~((uint64_t)(1 << BDRV_SECTOR_BITS) - 1);
        if (sz == 0) {
            error_setg(errp, "namespace_sizes: '%s' is smaller than a sector", tok);
            g_free(dup);
            return -1;
        }
        out_sizes[i++] = sz;
        sum += sz;
        tok = strtok_r(NULL, ",", &saveptr);
    }
    if (i != n->num_namespaces || tok) {
        error_setg(errp, "namespace_sizes count must equal namespaces=%u",
                   n->num_namespaces);
        g_free(dup);
        return -1;
    }
    g_free(dup);

    if (sum > total) {
        error_setg(errp, "namespace_sizes sum (%" PRIu64 " B) exceeds the backend "
                   "capacity (%" PRIu64 " B)", sum, total);
        return -1;
    }

    return 0;
}

static int nvme_init_namespaces(FemuCtrl *n, Error **errp)
{
    uint64_t *ns_sizes;
    uint8_t *ns_modes;
    uint64_t backend_total = n->ns_size * (uint64_t)n->num_namespaces;
    uint64_t running_offset = 0;
    int i;

    /*
     * FDP keeps its reclaim groups and unit handles on the controller and places
     * writes through its own path, which addresses the flash by the raw command
     * LBA rather than the namespace slice. Sharing that between namespaces would
     * let them land on the same logical pages, so keep FDP to one namespace.
     */
    if (n->num_namespaces > 1 && n->subsys && n->subsys->params.fdp.enabled) {
        error_setg(errp, "FDP supports a single namespace; set namespaces=1 or "
                   "disable FDP on the subsystem");
        return 1;
    }

    ns_sizes = g_new0(uint64_t, n->num_namespaces);
    ns_modes = g_new0(uint8_t, n->num_namespaces);
    if (nvme_resolve_ns_sizes(n, backend_total, ns_sizes, errp) ||
        nvme_resolve_ns_modes(n, ns_modes, errp)) {
        g_free(ns_sizes);
        g_free(ns_modes);
        return 1;
    }

    for (i = 0; i < n->num_namespaces; i++) {
        /*
         * Open-Channel keeps its tables on the controller and cannot be one mode
         * among several, so it stays a single-namespace controller.
         */
        if (n->num_namespaces > 1 && ns_modes[i] == FEMU_OCSSD_MODE) {
            error_setg(errp, "ocssd supports a single namespace");
            g_free(ns_sizes);
            g_free(ns_modes);
            return 1;
        }
    }

    /*
     * CSD keeps its FDM pool and its AFDM/group/program tables in one
     * controller-wide state object (n->ext_ops.state). ext_ops.init runs once
     * per namespace of a given mode, so a second CSD namespace would overwrite
     * that pointer with a fresh object, leaking the first and aliasing both
     * namespaces onto the second's tables. Unlike OCSSD, CSD can coexist with
     * other modes on the same controller -- only a second CSD namespace is the
     * problem -- so count CSD namespaces rather than rejecting the mode outright.
     */
    {
        int n_csd = 0;

        for (i = 0; i < n->num_namespaces; i++) {
            n_csd += (ns_modes[i] == FEMU_CSD_MODE);
        }
        if (n_csd > 1) {
            error_setg(errp, "csd supports at most one namespace per controller");
            g_free(ns_sizes);
            g_free(ns_modes);
            return 1;
        }
    }

    for (i = 0; i < n->num_namespaces; i++) {
        NvmeNamespace *ns = &n->namespaces[i];

        /*
         * Pack the slices in order: each namespace starts where the previous one
         * ended, so variable sizes leave no gap and no overlap. With one namespace
         * the offset is 0 and the size is the whole backend, exactly as before.
         */
        ns->size = ns_sizes[i];
        ns->backend_offset = running_offset;
        ns->start_block = running_offset >> BDRV_SECTOR_BITS;
        running_offset += ns_sizes[i];
        ns->id = i + 1;

        /* mode and command set for this namespace */
        ns->femu_mode = ns_modes[i];
        ns->csi = (ns_modes[i] == FEMU_ZNSSD_MODE) ? NVME_CSI_ZONED :
                                                     NVME_CSI_NVM;

        /* the zone geometry properties are shared; each zoned namespace keeps
         * its own copy of the limits it enforces */
        ns->max_active_zones = n->zns_params.zns_max_active;
        ns->max_open_zones = n->zns_params.zns_max_open;
        ns->zd_extension_size = n->zns_params.zns_zd_ext_size;
        ns->num_conv_zones = n->zns_params.zns_num_conv_zones;
        ns->zone_cap_bs = n->zns_params.zns_zone_cap;
        ns->zns_chnls_per_zone = n->zns_params.zns_chnls_per_zone;
        ns->zrwa_size = n->zns_params.zns_zrwa_size;
        ns->zrwafg_size = n->zns_params.zns_zrwafg_size;
        ns->zrwa_num = n->zns_params.zns_zrwa_num;
        ns->zrwa_avail = n->zns_params.zns_zrwa_num;
        ns->cross_zone_read = n->zns_params.zns_cross_zone_read;

        if (nvme_init_namespace(n, ns, errp)) {
            g_free(ns_sizes);
            g_free(ns_modes);
            return 1;
        }
    }
    g_free(ns_sizes);
    g_free(ns_modes);

    return 0;
}

static void nvme_init_ctrl(FemuCtrl *n)
{
    NvmeIdCtrl *id = &n->id_ctrl;
    uint8_t *pci_conf = n->parent_obj.config;
    char *subnqn;
    int i;

    id->vid = cpu_to_le16(pci_get_word(pci_conf + PCI_VENDOR_ID));
    id->ssvid = cpu_to_le16(pci_get_word(pci_conf + PCI_SUBSYSTEM_VENDOR_ID));

    id->rab          = 6;
    id->ieee[0]      = 0x00;
    id->ieee[1]      = 0x02;
    id->ieee[2]      = 0xb3;
    id->cmic         = 0;
    id->mdts         = n->mdts;
    id->ver          = 0x00010300;

    /* FDP: set Controller Attributes for FDP support */
    if (n->subsys && n->subsys->endgrp.fdp.enabled) {
        id->ctratt = cpu_to_le32(NVME_CTRATT_ENDGRPS | NVME_CTRATT_FDPS);
        id->endgidmax = cpu_to_le16(0);
        femu_log("FDP: CTRATT=0x%x (ENDGRPS|FDPS), endgidmax=0\n",
                 NVME_CTRATT_ENDGRPS | NVME_CTRATT_FDPS);
    }

    /* TODO: NVME_OACS_NS_MGMT */
    id->oacs         = cpu_to_le16(n->oacs | NVME_OACS_DBBUF);
    id->acl          = n->acl;
    id->aerl         = n->aerl;
    id->frmw         = 7 << 1 | 1;
    id->lpa          = NVME_LPA_NS_SMART | NVME_LPA_CSE | NVME_LPA_EXTENDED;
    id->elpe         = n->elpe;
    id->npss         = 0;
    id->sqes         = (n->max_sqes << 4) | 0x6;
    id->cqes         = (n->max_cqes << 4) | 0x4;
    id->nn           = cpu_to_le32(n->num_namespaces);
    id->oncs         = cpu_to_le16(n->oncs);
    if (n->sgl) {
        id->sgls     = cpu_to_le32(0x1);   /* advertise address-SGL support */
    }
    subnqn           = g_strdup_printf("nqn.2019-08.org.qemu:%s", n->serial);
    strpadcpy((char *)id->subnqn, sizeof(id->subnqn), subnqn, '\0');
    id->fuses        = cpu_to_le16(0);
    id->fna          = 0;
    id->vwc          = n->vwc;
    id->awun         = cpu_to_le16(0);
    id->awupf        = cpu_to_le16(0);
    id->psd[0].mp    = cpu_to_le16(0x9c4);
    id->psd[0].enlat = cpu_to_le32(0x10);
    id->psd[0].exlat = cpu_to_le32(0x4);

    n->features.arbitration     = 0x1f0f0706;
    n->features.power_mgmt      = 0;
    n->features.temp_thresh     = 0x14d;
    n->features.err_rec         = 0;
    n->features.volatile_wc     = n->vwc;
    n->features.nr_io_queues   = ((n->nr_io_queues - 1) | ((n->nr_io_queues -
                                                              1) << 16));
    n->features.int_coalescing  = n->intc_thresh | (n->intc_time << 8);
    n->features.write_atomicity = 0;
    n->features.async_config    = 0x0;
    n->features.sw_prog_marker  = 0;

    for (i = 0; i <= n->nr_io_queues; i++) {
        n->features.int_vector_config[i] = i | (n->intc << 16);
    }

    n->bar.cap = 0;
    NVME_CAP_SET_MQES(n->bar.cap, n->max_q_ents);
    NVME_CAP_SET_CQR(n->bar.cap, n->cqr);
    NVME_CAP_SET_AMS(n->bar.cap, 1);
    NVME_CAP_SET_TO(n->bar.cap, 0xf);
    NVME_CAP_SET_DSTRD(n->bar.cap, n->db_stride);
    NVME_CAP_SET_NSSRS(n->bar.cap, 0);
    NVME_CAP_SET_CSS(n->bar.cap, 1);
    NVME_CAP_SET_CSS(n->bar.cap, NVME_CAP_CSS_CSI_SUPP);
    NVME_CAP_SET_CSS(n->bar.cap, NVME_CAP_CSS_ADMIN_ONLY);

    NVME_CAP_SET_MPSMIN(n->bar.cap, n->mpsmin);
    NVME_CAP_SET_MPSMAX(n->bar.cap, n->mpsmax);

    n->bar.vs = NVME_SPEC_VER;
    n->bar.intmc = n->bar.intms = 0;
    /* n->temperature comes from the device property; do not overwrite it */
}

static void nvme_init_cmb(FemuCtrl *n)
{
    n->bar.cmbloc = n->cmbloc;
    n->bar.cmbsz  = n->cmbsz;

    n->cmbuf = g_malloc0(NVME_CMBSZ_GETSIZE(n->bar.cmbsz));
    memory_region_init_io(&n->ctrl_mem, OBJECT(n), &nvme_cmb_ops, n, "nvme-cmb",
                          NVME_CMBSZ_GETSIZE(n->bar.cmbsz));
    pci_register_bar(&n->parent_obj, NVME_CMBLOC_BIR(n->bar.cmbloc),
                     PCI_BASE_ADDRESS_SPACE_MEMORY |
                     PCI_BASE_ADDRESS_MEM_TYPE_64, &n->ctrl_mem);
}

static void nvme_init_pci(FemuCtrl *n)
{
    uint8_t *pci_conf = n->parent_obj.config;

    pci_conf[PCI_INTERRUPT_PIN] = 1;
    /* Coperd: QEMU-OCSSD(0x1d1d,0x1f1f), QEMU-NVMe(0x8086,0x5845) */
    pci_config_set_prog_interface(pci_conf, 0x2);
    pci_config_set_vendor_id(pci_conf, n->vid);
    pci_config_set_device_id(pci_conf, n->did);
    pci_config_set_class(pci_conf, PCI_CLASS_STORAGE_EXPRESS);
    pcie_endpoint_cap_init(&n->parent_obj, 0x80);

    memory_region_init_io(&n->iomem, OBJECT(n), &nvme_mmio_ops, n, "nvme",
                          n->reg_size);
    pci_register_bar(&n->parent_obj, 0, PCI_BASE_ADDRESS_SPACE_MEMORY |
                     PCI_BASE_ADDRESS_MEM_TYPE_64, &n->iomem);
    if (msix_init_exclusive_bar(&n->parent_obj, n->nr_io_queues + 1, 4, NULL)) {
        return;
    }
    msi_init(&n->parent_obj, 0x50, 32, true, false, NULL);

    if (n->cmbsz) {
        nvme_init_cmb(n);
    }
}

/*
 * Hand one request to the backend that serves its namespace. Namespaces may run
 * different modes, so the backend is chosen per request rather than per
 * controller.
 */
static uint64_t femu_ftl_process_req(FemuCtrl *n, NvmeRequest *req)
{
    NvmeNamespace *ns = req->ns;

    if (!ns) {
        return 0;
    }

    if (NS_ZNSSD(ns)) {
        return zns_ftl_process_req(ns, req);
    }
    if (NS_BBSSD(ns)) {
        return bb_ftl_process_req(n, ns, req);
    }

    return 0;
}

/*
 * The controller's FTL thread. It drains the rings the pollers feed and routes
 * each request to its namespace's backend. There is one of these per controller
 * rather than one per mode, so that a controller whose namespaces do not share a
 * mode still has a single reader per ring.
 */
static void *femu_ftl_thread(void *arg)
{
    FemuCtrl *n = (FemuCtrl *)arg;
    NvmeRequest *req = NULL;
    uint64_t lat;
    int rc, i;

    while (!n->dataplane_started) {
        if (n->ftl_stopping) {
            return NULL;
        }
        usleep(100000);
    }

    while (!n->ftl_stopping) {
        for (i = 1; i <= n->nr_pollers; i++) {
            if (!n->to_ftl[i] || !femu_ring_count(n->to_ftl[i])) {
                continue;
            }

            rc = femu_ring_dequeue(n->to_ftl[i], (void *)&req, 1);
            if (rc != 1) {
                femu_err("FEMU: FTL to_ftl dequeue failed\n");
                continue;
            }

            lat = femu_ftl_process_req(n, req);
            req->reqlat = lat;
            req->expire_time += lat;

            rc = femu_ring_enqueue(n->to_poller[i], (void *)&req, 1);
            if (rc != 1) {
                femu_err("FEMU: FTL to_poller enqueue failed\n");
            }
        }
    }

    return NULL;
}

/* true when some namespace needs the controller's FTL thread running */
static bool femu_needs_ftl_thread(FemuCtrl *n)
{
    int i;

    for (i = 0; i < n->num_namespaces; i++) {
        NvmeNamespace *ns = &n->namespaces[i];

        if (NS_BBSSD(ns) || NS_ZNSSD(ns)) {
            return true;
        }
    }

    return false;
}

static int nvme_register_extensions(FemuCtrl *n)
{
    if (OCSSD(n)) {
        switch (n->lver) {
        case OCSSD12:
            nvme_register_ocssd12(n);
            break;
        case OCSSD20:
            nvme_register_ocssd20(n);
            break;
        default:
            break;
        }
    } else if (NOSSD(n)) {
        nvme_register_nossd(n);
    } else if (BBSSD(n)) {
        nvme_register_bbssd(n);
    } else if (ZNSSD(n)) {
        nvme_register_znssd(n);
    } else if (CSD(n)) {
        nvme_register_csd(n);
    } else if (KVSSD(n)) {
        nvme_register_kvssd(n);
    } else {
        /* TODO: For future extensions */
    }

    return 0;
}

/*
 * Select the handler table for one namespace. The per-mode registration writes
 * into the controller, so borrow it for the namespace's mode and take a copy;
 * the controller keeps the table for its own mode, which still answers the
 * admin and start-up paths.
 */
static void nvme_register_extensions_ns(FemuCtrl *n, NvmeNamespace *ns)
{
    FemuExtCtrlOps saved_ops = n->ext_ops;
    uint8_t saved_mode = n->femu_mode;

    n->femu_mode = ns->femu_mode;
    nvme_register_extensions(n);
    ns->ext_ops = n->ext_ops;

    n->femu_mode = saved_mode;
    n->ext_ops = saved_ops;
}

static void femu_realize(PCIDevice *pci_dev, Error **errp)
{
    FemuCtrl *n = FEMU(pci_dev);
    int64_t bs_size;
    uint64_t nand_cap = 0;

    nvme_check_size();

    if (!nvme_check_constraints(n, errp)) {
        return;
    }

    bs_size = ((int64_t)n->memsz) * 1024 * 1024;

    /*
     * Explicit over-provisioning (bbssd only). Without it, the spare area is just
     * the incidental gap between the NAND capacity implied by the geometry and the
     * devsz_mb-derived namespace. With op_pcent set, back the device with the full
     * NAND capacity and expose a namespace op_pcent smaller, so the over-provision
     * ratio is a known fraction. op_pcent == 0 keeps the devsz_mb-based sizing.
     */
    if (BBSSD(n) && n->op_pcent) {
        BbCtrlParams *bb = &n->bb_params;
        nand_cap = (uint64_t)bb->nchs * bb->luns_per_ch * bb->pls_per_lun *
                   bb->blks_per_pl * bb->pgs_per_blk * bb->secs_per_pg * bb->secsz;
        bs_size = nand_cap;
    }

    init_dram_backend(&n->mbe, bs_size);
    n->mbe->femu_mode = n->femu_mode;

    /* the host-link model is armed only when a knob asks for it */
    n->pcie_enabled = (n->pcie_bandwidth_mbps || n->pcie_prop_delay_ns);
    n->pcie_tx_next_avail_time = 0;
    n->pcie_rx_next_avail_time = 0;
    n->fw_cpu_next_avail_time = 0;
    pthread_spin_init(&n->pcie_lock, PTHREAD_PROCESS_PRIVATE);
    pthread_spin_init(&n->fw_cpu_lock, PTHREAD_PROCESS_PRIVATE);

    n->completed = 0;
    n->start_time = time(NULL);
    n->reg_size = pow2ceil(0x1004 + 2 * (n->nr_io_queues + 1) * 4);
    /* ns_size is the per-namespace share of the exposed capacity */
    n->ns_size = bs_size / (uint64_t)n->num_namespaces;
    if (BBSSD(n) && n->op_pcent) {
        n->ns_size = (nand_cap * 100 / (100ULL + n->op_pcent)) /
                     (uint64_t)n->num_namespaces;
        n->ns_size &= ~((1ULL << BDRV_SECTOR_BITS) - 1);
    }

    /* Coperd: [1..nr_io_queues] are used as IO queues */
    n->sq = g_malloc0(sizeof(*n->sq) * (n->nr_io_queues + 1));
    n->cq = g_malloc0(sizeof(*n->cq) * (n->nr_io_queues + 1));
    n->namespaces = g_malloc0(sizeof(*n->namespaces) * n->num_namespaces);
    n->elpes = g_malloc0(sizeof(*n->elpes) * (n->elpe + 1));
    n->aer_held = g_malloc0(sizeof(*n->aer_held) * (n->aerl + 1));
    QSIMPLEQ_INIT(&n->aer_queue);
    n->features.int_vector_config = g_malloc0(sizeof(*n->features.int_vector_config) * (n->nr_io_queues + 1));

    nvme_init_pci(n);

    /* FDP: register controller with subsystem if linked */
    if (nvme_init_subsys(n)) {
        error_setg(errp, "failed to register controller with subsystem");
        return;
    }

    nvme_init_ctrl(n);
    /*
     * Stop here if the namespaces did not come up. The mode init below builds on
     * initialized namespace state and would otherwise run against half-built
     * namespaces, and it takes the same Error argument, which must not already
     * carry an error.
     */
    if (nvme_init_namespaces(n, errp)) {
        return;
    }

    nvme_register_extensions(n);

    /*
     * Bring up each namespace under its own mode. The controller keeps the table
     * for its own femu_mode for the admin paths, while each namespace gets the
     * one matching the mode it runs.
     */
    for (int i = 0; i < n->num_namespaces; i++) {
        NvmeNamespace *ns = &n->namespaces[i];

        nvme_register_extensions_ns(n, ns);
        if (ns->ext_ops.init) {
            Error *local_err = NULL;

            ns->ext_ops.init(n, ns, &local_err);
            if (local_err) {
                error_propagate(errp, local_err);
                return;
            }
        }
    }

    /*
     * One FTL thread serves every namespace that needs one. It is started after
     * all namespaces are built, so it never runs against half-initialized state,
     * and only once every geometry check has passed.
     */
    if (femu_needs_ftl_thread(n)) {
        qemu_thread_create(&n->ftl_thread, "FEMU-FTL-Thread", femu_ftl_thread,
                           n, QEMU_THREAD_JOINABLE);
        n->ftl_thread_running = true;
    }
}

/*
 * Stop and join the FTL thread. The rings, namespaces, FTL state and backend it
 * works on are all freed right after this, so it must no longer be running.
 */
static void femu_stop_ftl_thread(FemuCtrl *n)
{
    if (!n->ftl_thread_running) {
        return;
    }

    n->ftl_stopping = true;
    smp_mb();   /* publish the flag before waiting on the thread to see it */
    qemu_thread_join(&n->ftl_thread);
    n->ftl_thread_running = false;
}

static void nvme_destroy_poller(FemuCtrl *n)
{
    int i;
    femu_debug("Destroying NVMe poller !!\n");

    for (i = 1; i <= n->nr_pollers; i++) {
        qemu_thread_join(&n->poller[i]);
    }

    for (i = 1; i <= n->nr_pollers; i++) {
        pqueue_free(n->pq[i]);
        femu_ring_free(n->to_poller[i]);
        femu_ring_free(n->to_ftl[i]);
    }

    g_free(n->should_isr);
    g_free((void *)n->poller_in_sweep);
    n->poller_in_sweep = NULL;
    qemu_vfree(n->poller_ctr);   /* allocated with qemu_memalign */
    n->poller_ctr = NULL;
}

/*
 * Run each mode's exit once. A namespace may run a mode other than the
 * controller's, and every mode's exit walks the namespaces itself, so dispatch
 * over the distinct handlers rather than once per namespace.
 */
static void femu_exit_extensions(FemuCtrl *n)
{
    void (*seen[FEMU_NR_MODES])(struct FemuCtrl *);
    int nseen = 0, i, j;

    if (n->ext_ops.exit) {
        seen[nseen++] = n->ext_ops.exit;
    }

    for (i = 0; n->namespaces && i < n->num_namespaces; i++) {
        void (*ex)(struct FemuCtrl *) = n->namespaces[i].ext_ops.exit;

        if (!ex) {
            continue;
        }
        for (j = 0; j < nseen; j++) {
            if (seen[j] == ex) {
                break;
            }
        }
        if (j == nseen && nseen < (int)ARRAY_SIZE(seen)) {
            seen[nseen++] = ex;
        }
    }

    for (j = 0; j < nseen; j++) {
        seen[j](n);
    }
}

static void femu_exit(PCIDevice *pci_dev)
{
    FemuCtrl *n = FEMU(pci_dev);

    femu_debug("femu_exit starting!\n");

    femu_stop_ftl_thread(n);
    femu_exit_extensions(n);

    nvme_clear_ctrl(n, true);
    nvme_destroy_poller(n);
    free_dram_backend(n->mbe);

    /* FDP: free namespace FDP placement handles */
    if (n->namespaces) {
        for (int i = 0; i < n->num_namespaces; i++) {
            g_free(n->namespaces[i].fdp.phs);
        }
    }

    /* FDP: unregister controller from subsystem */
    if (n->subsys) {
        femu_subsys_unregister_ctrl(n->subsys, n);
    }

    g_free(n->namespaces);
    g_free(n->features.int_vector_config);
    {
        NvmeAsyncEvent *event;

        while ((event = QSIMPLEQ_FIRST(&n->aer_queue)) != NULL) {
            QSIMPLEQ_REMOVE_HEAD(&n->aer_queue, entry);
            g_free(event);
        }
    }
    g_free(n->aer_held);
    g_free(n->elpes);
    g_free(n->cq);
    g_free(n->sq);
    msix_uninit_exclusive_bar(pci_dev);
    memory_region_unref(&n->iomem);
    if (n->cmbsz) {
        memory_region_unref(&n->ctrl_mem);
    }
}

static const Property femu_props[] = {
    //DEFINE_BLOCK_PROPERTIES(FemuCtrl, blkconf),
    DEFINE_PROP_STRING("serial", FemuCtrl, serial),
    DEFINE_PROP_UINT32("devsz_mb", FemuCtrl, memsz, 1024), /* in MB */
    DEFINE_PROP_UINT32("namespaces", FemuCtrl, num_namespaces, 1),
    DEFINE_PROP_UINT32("queues", FemuCtrl, nr_io_queues, 8),
    DEFINE_PROP_UINT32("entries", FemuCtrl, max_q_ents, 0x7ff),
    DEFINE_PROP_UINT8("multipoller_enabled", FemuCtrl, multipoller_enabled, 0),
    DEFINE_PROP_UINT32("poller_ratio", FemuCtrl, poller_ratio, 1),
    DEFINE_PROP_BOOL("hiops_inline", FemuCtrl, hiops_inline, true),
    DEFINE_PROP_UINT8("max_cqes", FemuCtrl, max_cqes, 0x4),
    DEFINE_PROP_UINT8("max_sqes", FemuCtrl, max_sqes, 0x6),
    DEFINE_PROP_UINT8("stride", FemuCtrl, db_stride, 0),
    DEFINE_PROP_UINT8("aerl", FemuCtrl, aerl, 3),
    DEFINE_PROP_UINT8("acl", FemuCtrl, acl, 3),
    DEFINE_PROP_UINT8("elpe", FemuCtrl, elpe, 3),
    DEFINE_PROP_UINT8("mdts", FemuCtrl, mdts, 10),
    DEFINE_PROP_UINT8("cqr", FemuCtrl, cqr, 1),
    DEFINE_PROP_UINT8("vwc", FemuCtrl, vwc, 0),
    DEFINE_PROP_UINT8("intc", FemuCtrl, intc, 0),
    DEFINE_PROP_UINT8("intc_thresh", FemuCtrl, intc_thresh, 0),
    DEFINE_PROP_UINT8("intc_time", FemuCtrl, intc_time, 0),
    DEFINE_PROP_UINT8("ms", FemuCtrl, ms, 16),
    DEFINE_PROP_UINT8("ms_max", FemuCtrl, ms_max, 64),
    DEFINE_PROP_UINT8("dlfeat", FemuCtrl, dlfeat, 1),
    /* reported temperature in Kelvin; 0x143 (50 C) is the NVMe default */
    DEFINE_PROP_UINT16("temperature", FemuCtrl, temperature,
                       NVME_TEMPERATURE),
    DEFINE_PROP_UINT8("mpsmin", FemuCtrl, mpsmin, 0),
    DEFINE_PROP_UINT8("mpsmax", FemuCtrl, mpsmax, 0),
    DEFINE_PROP_UINT8("nlbaf", FemuCtrl, nlbaf, 5),
    DEFINE_PROP_UINT8("lba_index", FemuCtrl, lba_index, 0),
    DEFINE_PROP_UINT8("extended", FemuCtrl, extended, 0),
    DEFINE_PROP_UINT8("dpc", FemuCtrl, dpc, 0),
    DEFINE_PROP_UINT8("dps", FemuCtrl, dps, 0),
    DEFINE_PROP_UINT8("mc", FemuCtrl, mc, 0),
    DEFINE_PROP_UINT8("meta", FemuCtrl, meta, 0),
    DEFINE_PROP_UINT32("cmbsz", FemuCtrl, cmbsz, 0),
    DEFINE_PROP_UINT32("cmbloc", FemuCtrl, cmbloc, 0),
    DEFINE_PROP_UINT16("oacs", FemuCtrl, oacs, NVME_OACS_FORMAT),
    DEFINE_PROP_UINT16("oncs", FemuCtrl, oncs, NVME_ONCS_DSM),
    DEFINE_PROP_BOOL("sgl", FemuCtrl, sgl, false),
    DEFINE_PROP_UINT16("vid", FemuCtrl, vid, 0x1d1d),
    DEFINE_PROP_UINT16("did", FemuCtrl, did, 0x1f1f),
    DEFINE_PROP_UINT8("femu_mode", FemuCtrl, femu_mode, FEMU_NOSSD_MODE),
    DEFINE_PROP_UINT8("flash_type", FemuCtrl, flash_type, MLC),
    DEFINE_PROP_UINT8("lver", FemuCtrl, lver, 0x2),
    DEFINE_PROP_UINT16("lsec_size", FemuCtrl, oc_params.sec_size, 4096),
    DEFINE_PROP_UINT8("lsecs_per_pg", FemuCtrl, oc_params.secs_per_pg, 4),
    DEFINE_PROP_UINT16("lpgs_per_blk", FemuCtrl, oc_params.pgs_per_blk, 512),
    DEFINE_PROP_UINT8("lmax_sec_per_rq", FemuCtrl, oc_params.max_sec_per_rq, 64),
    DEFINE_PROP_UINT8("lnum_ch", FemuCtrl, oc_params.num_ch, 2),
    DEFINE_PROP_UINT8("lnum_lun", FemuCtrl, oc_params.num_lun, 8),
    DEFINE_PROP_UINT8("lnum_pln", FemuCtrl, oc_params.num_pln, 2),
    DEFINE_PROP_UINT16("lmetasize", FemuCtrl, oc_params.sos, 16),
    DEFINE_PROP_UINT64("fdm_size", FemuCtrl, csd_params.fdm_size_mb, 0),
    DEFINE_PROP_UINT8("nr_cu", FemuCtrl, csd_params.nr_cu, 4),
    DEFINE_PROP_UINT8("nr_thread", FemuCtrl, csd_params.nr_thread, 4),
    DEFINE_PROP_UINT64("time_slice", FemuCtrl, csd_params.time_slice, 200000),
    DEFINE_PROP_UINT64("context_switch_time", FemuCtrl,
                       csd_params.context_switch_time, 200),
    DEFINE_PROP_UINT16("csf_runtime_scale", FemuCtrl,
                       csd_params.csf_runtime_scale, 3),
    DEFINE_PROP_UINT8("zns_num_ch", FemuCtrl, zns_params.zns_num_ch, 2),
    DEFINE_PROP_UINT8("zns_num_lun", FemuCtrl, zns_params.zns_num_lun, 4),
    DEFINE_PROP_UINT8("zns_num_plane", FemuCtrl, zns_params.zns_num_plane, 2),
    DEFINE_PROP_UINT8("zns_num_blk", FemuCtrl, zns_params.zns_num_blk, 32),
    DEFINE_PROP_INT32("zns_flash_type", FemuCtrl, zns_params.zns_flash_type, QLC),
    DEFINE_PROP_INT64("zns_pg_rd_lat", FemuCtrl, zns_params.zns_pg_rd_lat, 0),
    DEFINE_PROP_INT64("zns_pg_wr_lat", FemuCtrl, zns_params.zns_pg_wr_lat, 0),
    DEFINE_PROP_INT64("zns_blk_er_lat", FemuCtrl, zns_params.zns_blk_er_lat, 0),
    DEFINE_PROP_UINT32("zns_max_active", FemuCtrl, zns_params.zns_max_active, 0),
    DEFINE_PROP_UINT32("zns_max_open", FemuCtrl, zns_params.zns_max_open, 0),
    DEFINE_PROP_UINT32("zns_zd_ext_size", FemuCtrl, zns_params.zns_zd_ext_size, 0),
    DEFINE_PROP_UINT32("zns_num_conv_zones", FemuCtrl,
                       zns_params.zns_num_conv_zones, 0),
    DEFINE_PROP_SIZE("zns_zone_cap", FemuCtrl, zns_params.zns_zone_cap, 0),
    DEFINE_PROP_UINT32("zns_chnls_per_zone", FemuCtrl,
                       zns_params.zns_chnls_per_zone, 0),
    DEFINE_PROP_UINT64("zns_zrwa_size", FemuCtrl, zns_params.zns_zrwa_size, 0),
    DEFINE_PROP_UINT64("zns_zrwafg_size", FemuCtrl,
                       zns_params.zns_zrwafg_size, 0),
    DEFINE_PROP_UINT32("zns_zrwa_num", FemuCtrl, zns_params.zns_zrwa_num, 0),
    DEFINE_PROP_BOOL("zns_cross_zone_read", FemuCtrl,
                     zns_params.zns_cross_zone_read, false),
    /* max Zone Append transfer; 0 follows MDTS. 128 KiB was the fixed value */
    DEFINE_PROP_UINT32("zns_zasl_bs", FemuCtrl, zns_params.zns_zasl_bs,
                       128 * 1024),
    DEFINE_PROP_INT32("secsz", FemuCtrl, bb_params.secsz, 512),
    DEFINE_PROP_INT32("secs_per_pg", FemuCtrl, bb_params.secs_per_pg, 8),
    DEFINE_PROP_INT32("pgs_per_blk", FemuCtrl, bb_params.pgs_per_blk, 256),
    DEFINE_PROP_INT32("blks_per_pl", FemuCtrl, bb_params.blks_per_pl, 256),
    DEFINE_PROP_INT32("pls_per_lun", FemuCtrl, bb_params.pls_per_lun, 1),
    DEFINE_PROP_INT32("luns_per_ch", FemuCtrl, bb_params.luns_per_ch, 8),
    DEFINE_PROP_INT32("nchs", FemuCtrl, bb_params.nchs, 8),
    DEFINE_PROP_INT32("pg_rd_lat", FemuCtrl, bb_params.pg_rd_lat, 40000),
    DEFINE_PROP_INT32("pg_wr_lat", FemuCtrl, bb_params.pg_wr_lat, 200000),
    DEFINE_PROP_INT32("blk_er_lat", FemuCtrl, bb_params.blk_er_lat, 2000000),
    DEFINE_PROP_INT32("ch_xfer_lat", FemuCtrl, bb_params.ch_xfer_lat, 0),
    DEFINE_PROP_INT32("gc_thres_pcent", FemuCtrl, bb_params.gc_thres_pcent, 75),
    DEFINE_PROP_INT32("gc_thres_pcent_high", FemuCtrl, bb_params.gc_thres_pcent_high, 95),
    DEFINE_PROP_INT32("gc_strategy", FemuCtrl, bb_params.gc_strategy, 0),
    DEFINE_PROP_STRING("gc_policy", FemuCtrl, bb_params.gc_policy),
    DEFINE_PROP_UINT32("read_cache_mb", FemuCtrl, read_cache_mb, 0),
    DEFINE_PROP_STRING("cache_evict", FemuCtrl, bb_params.cache_evict),
    DEFINE_PROP_STRING("mapping", FemuCtrl, bb_params.mapping_scheme),
    DEFINE_PROP_UINT32("mapping_cache_mb", FemuCtrl, mapping_cache_mb, 0),
    DEFINE_PROP_UINT8("nand_cell_type", FemuCtrl, nand_cell_type, 0),
    DEFINE_PROP_INT32("cell_pages", FemuCtrl, bb_params.cell_pages, 0),
    DEFINE_PROP_INT32("pgtype_lat", FemuCtrl, bb_params.pgtype_lat, 0),
    DEFINE_PROP_INT32("ecc_step_ns", FemuCtrl, bb_params.ecc_step_ns, 0),
    DEFINE_PROP_INT32("ecc_retention_sec", FemuCtrl,
                      bb_params.ecc_retention_sec, 0),
    DEFINE_PROP_INT32("cmd_addr_lat", FemuCtrl, bb_params.cmd_addr_lat, 0),
    DEFINE_PROP_INT32("pg_xfer_lat", FemuCtrl, bb_params.pg_xfer_lat, 0),
    DEFINE_PROP_INT32("status_lat", FemuCtrl, bb_params.status_lat, 0),
    DEFINE_PROP_INT32("tplpbsy", FemuCtrl, bb_params.tplpbsy, 0),
    DEFINE_PROP_INT32("tplrbsy", FemuCtrl, bb_params.tplrbsy, 0),
    DEFINE_PROP_INT32("tplebsy", FemuCtrl, bb_params.tplebsy, 0),
    DEFINE_PROP_INT32("trcbsy", FemuCtrl, bb_params.trcbsy, 0),
    DEFINE_PROP_INT32("trim_lat_ns", FemuCtrl, bb_params.trim_lat_ns, 0),
    DEFINE_PROP_UINT32("nand_bad_blocks", FemuCtrl, nand_bad_blocks, 0),
    DEFINE_PROP_UINT32("op_pcent", FemuCtrl, op_pcent, 0),
    DEFINE_PROP_BOOL("debug_ftl", FemuCtrl, debug_ftl, false),
    DEFINE_PROP_UINT32("err_read_unc_ppm", FemuCtrl, err_read_unc_ppm, 0),
    DEFINE_PROP_UINT32("err_write_fail_ppm", FemuCtrl, err_write_fail_ppm, 0),
    DEFINE_PROP_UINT32("pcie_bandwidth_mbps", FemuCtrl, pcie_bandwidth_mbps, 0),
    DEFINE_PROP_UINT32("pcie_prop_delay_ns", FemuCtrl, pcie_prop_delay_ns, 0),
    DEFINE_PROP_UINT64("fw_cpu_ns", FemuCtrl, fw_cpu_ns, 0),
    DEFINE_PROP_STRING("namespace_sizes", FemuCtrl, namespace_sizes),
    DEFINE_PROP_STRING("namespace_modes", FemuCtrl, namespace_modes),
    DEFINE_PROP_INT32("fdp_trim_erase_all", FemuCtrl,
                      bb_params.fdp_trim_erase_all, 0),
    DEFINE_PROP_LINK("subsys", FemuCtrl, subsys, TYPE_NVME_SUBSYS,
                     NvmeSubsystem *),
    /* pages held in the DRAM write buffer; 0 programs every write directly */
    DEFINE_PROP_BOOL("hot_cold_sep", FemuCtrl, bb_params.hot_cold_sep, false),
    DEFINE_PROP_INT32("read_reclaim_limit", FemuCtrl,
                      bb_params.read_reclaim_limit, 0),
    DEFINE_PROP_INT32("retention_limit_sec", FemuCtrl,
                      bb_params.retention_limit_sec, 0),
    DEFINE_PROP_INT32("buffer_size", FemuCtrl, bb_params.buffer_size, 0),
    DEFINE_PROP_INT32("buffer_thres_pcent", FemuCtrl,
                      bb_params.buffer_thres_pcent, 90),
};

static const VMStateDescription femu_vmstate = {
    .name = "femu",
    .unmigratable = 1,
};

static void femu_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    PCIDeviceClass *pc = PCI_DEVICE_CLASS(oc);

    pc->realize = femu_realize;
    pc->exit = femu_exit;
    pc->class_id = PCI_CLASS_STORAGE_EXPRESS;
    pc->vendor_id = PCI_VENDOR_ID_INTEL;
    pc->device_id = 0x5845;
    pc->revision = 2;

    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    dc->desc = "FEMU Non-Volatile Memory Express";
    device_class_set_props(dc, femu_props);
    dc->vmsd = &femu_vmstate;
}

static const TypeInfo femu_info = {
    .name          = "femu",
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(FemuCtrl),
    .class_init    = femu_class_init,
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_PCIE_DEVICE },
        { }
    },
};

static void femu_register_types(void)
{
    type_register_static(&nvme_subsys_info);
    type_register_static(&femu_info);
}

type_init(femu_register_types)
