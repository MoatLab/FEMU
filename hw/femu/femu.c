#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "system/qtest.h"
#include "hw/qdev-properties.h"
#include "qom/qom-qobject.h"
#include "qobject/qobject.h"
#include "qobject/qstring.h"

#include "./nvme.h"
#include "./bbssd/ftl.h"
#include "./femu-props.h"

#define NVME_SPEC_VER (0x00010400)

/* ========== NVMe Subsystem (femu-subsys) QOM Device ========== */

static void nvme_subsys_release_storage(NvmeSubsystem *subsys);

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
    /*
     * Clear only the slot this controller actually holds. cntlid is unsigned,
     * so the -1 this used to leave behind reads back as 65535, and a second
     * call -- a controller that never registered, or one torn down twice --
     * indexed past the array.
     */
    if (n->cntlid < NVME_MAX_CONTROLLERS && subsys->ctrls[n->cntlid] == n) {
        subsys->ctrls[n->cntlid] = NULL;
    }
    if (subsys->ns_release_pending) {
        nvme_subsys_release_storage(subsys);
    }
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

    /* zero lets the controller say; a bbssd controller uses its superblock */
    endgrp->fdp.runs = subsys->params.fdp.runs ?: NVME_DEFAULT_RU_SIZE;
    endgrp->fdp.nru = subsys->params.fdp.nru;

    /*
     * One active reclaim unit per placement handle, not one per handle and
     * reclaim group. A write that names a group other than the first is given
     * the first group's unit anyway -- the assignment that reads the named
     * group is overwritten on the next line -- and that unit is then filed in
     * the named group's queue, where its recorded position indexes a heap it
     * does not belong to. The check that would have caught it is an ftl_assert,
     * which is compiled out. Until the model holds a unit per handle and group,
     * say so rather than corrupt the queues quietly.
     */
    if (subsys->params.fdp.nrg > 1) {
        error_setg(errp, "fdp.nrg must be 1: placement into a reclaim group "
                   "other than the first is not implemented");
        return false;
    }
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
    /*
     * The count sizes an array per reclaim group straight away, and the device
     * cannot have more reclaim units than it has lines -- a block index in an
     * address is sixteen bits. Unbounded, a mistyped property was an allocation
     * failure at realize rather than a refusal.
     */
    if (tt_nru > NVME_FDP_MAX_NRU) {
        error_setg(errp, "fdp.nru (%"PRIu64") must not exceed %u", tt_nru,
                   NVME_FDP_MAX_NRU);
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

    qemu_mutex_init(&endgrp->fdp.events_lock);
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

static void nvme_ns_release(FemuCtrl *n, NvmeNamespace *ns);
static FemuCtrl *nvme_subsys_take_storage(FemuCtrl *n);

static void nvme_subsys_realize(DeviceState *dev, Error **errp)
{
    NvmeSubsystem *subsys = NVME_SUBSYS(dev);

    if (subsys->ns_mgmt && subsys->params.fdp.enabled) {
        error_setg(errp, "namespace management does not support FDP");
        return;
    }
    if (subsys->ns_lock_init) {
        error_setg(errp, "controllers still reference the subsystem");
        return;
    }
    qemu_mutex_init(&subsys->ns_lock);
    subsys->ns_lock_init = true;
    subsys->ns_release_pending = false;
    qbus_init(&subsys->bus, sizeof(NvmeBus), TYPE_NVME_BUS, dev, dev->id);
    nvme_subsys_setup(subsys, errp);
}

static void nvme_subsys_release_storage(NvmeSubsystem *subsys)
{
    FemuCtrl *storage = subsys->storage;

    for (uint32_t i = 0; i < NVME_MAX_CONTROLLERS; i++) {
        if (nvme_subsys_ctrl(subsys, i)) {
            return;
        }
    }
    if (storage) {
        for (uint32_t i = 0; i < storage->namespace_limit; i++) {
            nvme_ns_release(storage, &storage->namespaces[i]);
        }
        g_free(storage->namespaces);
        storage->namespaces = NULL;
        free_dram_backend(storage->mbe);
        storage->mbe = NULL;
        subsys->storage = NULL;
        object_unref(OBJECT(storage));
    }
    if (subsys->ns_lock_init) {
        qemu_mutex_destroy(&subsys->ns_lock);
        subsys->ns_lock_init = false;
    }
}

static void nvme_subsys_unrealize(DeviceState *dev)
{
    NvmeSubsystem *subsys = NVME_SUBSYS(dev);

    /* PCI transports may be torn down after their subsystem. */
    subsys->ns_release_pending = true;
    nvme_subsys_release_storage(subsys);
}

static const Property nvme_subsystem_props[] = {
    DEFINE_PROP_BOOL("ns_mgmt", NvmeSubsystem, ns_mgmt, false),
    DEFINE_PROP_STRING("nqn", NvmeSubsystem, params.nqn),
    DEFINE_PROP_BOOL("fdp", NvmeSubsystem, params.fdp.enabled, false),
    DEFINE_PROP_SIZE("fdp.runs", NvmeSubsystem, params.fdp.runs, 0),
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
    dc->unrealize = nvme_subsys_unrealize;
    dc->desc = "FEMU NVMe Subsystem (FDP)";
    device_class_set_props(dc, nvme_subsystem_props);
    femu_subsys_describe_props(oc);
}

static const TypeInfo nvme_subsys_info = {
    .name          = TYPE_NVME_SUBSYS,
    .parent        = TYPE_DEVICE,
    .instance_size = sizeof(NvmeSubsystem),
    .class_init    = nvme_subsys_class_init,
};

/* ========== FDP Namespace Init ========== */

/*
 * Reclaim units are measured in logical blocks, so a format that changes the
 * block size changes how many of them a unit holds. Recompute the sizes the
 * placement handles were given at init; leaving them makes a unit look eight
 * times smaller than it is after a 4 KiB namespace is reformatted to 512
 * bytes, and the write that crosses it rotates a unit early ever after.
 *
 * A format ends the life of the data, so the remaining-write counters go back
 * to a full unit along with the sizes.
 */
void nvme_ns_refresh_fdp(NvmeNamespace *ns)
{
    NvmeEnduranceGroup *endgrp = ns->endgrp;
    uint8_t lbafi = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    NvmeRuHandle *ruh;

    if (!endgrp || !endgrp->fdp.enabled || !ns->fdp.phs) {
        return;
    }

    for (uint16_t i = 0; i < ns->fdp.nphs; i++) {
        ruh = &endgrp->fdp.ruhs[i];
        if (ruh->ruha != NVME_RUHA_HOST) {
            continue;
        }

        ruh->lbafi = lbafi;
        ruh->ruamw = endgrp->fdp.runs >> ns->lbaf.lbads;

        for (uint16_t rg = 0; rg < endgrp->fdp.nrg; rg++) {
            for (uint64_t j = 0; j < endgrp->fdp.nru; j++) {
                endgrp->fdp.rus[rg][j].ruamw = ruh->ruamw;
            }
        }
    }
}

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
    ns->id_ns.endgid = cpu_to_le16(1);
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

static int nvme_init_subsys(FemuCtrl *n, Error **errp)
{
    int cntlid;

    if (!n->subsys) {
        return 0;
    }

    /*
     * The reclaim units and handles hold one controller's FTL state, reclaim
     * unit size included; a second controller would rebuild them over the
     * first one's.
     */
    if (n->subsys->endgrp.fdp.enabled) {
        for (cntlid = 0; cntlid < ARRAY_SIZE(n->subsys->ctrls); cntlid++) {
            if (n->subsys->ctrls[cntlid]) {
                error_setg(errp, "femu-subsys with fdp=on takes a single "
                           "controller");
                return -1;
            }
        }
    }

    /* Streams resources and frontiers belong to one controller. */
    for (cntlid = 0; cntlid < ARRAY_SIZE(n->subsys->ctrls); cntlid++) {
        FemuCtrl *other = n->subsys->ctrls[cntlid];

        if (other && (n->streams || other->streams)) {
            error_setg(errp, "a Streams subsystem takes a single controller");
            return -1;
        }
    }

    cntlid = femu_subsys_register_ctrl(n);
    if (cntlid < 0) {
        error_setg(errp, "failed to register controller with subsystem");
        return -1;
    }

    n->cntlid = cntlid;

    return 0;
}

/* ========== End FDP Subsystem ========== */

/*
 * Feature values a Controller Level Reset returns to their defaults (Base 2.3,
 * 4.4). None of these is saveable. The Software Progress Marker is left alone:
 * it exists to be read back after a reset.
 */
static void nvme_reset_features(FemuCtrl *n)
{
    int i;

    n->features.arbitration     = 0x1f0f0706;
    n->features.power_mgmt      = 0;
    n->features.temp_thresh     = 0x14d;
    n->features.temp_thresh_under = 0;
    n->features.volatile_wc     = n->vwc;
    n->features.nr_io_queues    = (n->nr_io_queues - 1) |
                                  ((n->nr_io_queues - 1) << 16);
    n->features.int_coalescing  = n->intc_thresh | (n->intc_time << 8);
    n->features.write_atomicity = 0;
    n->features.async_config    = 0x0;
    memset(n->features.host_behavior, 0, sizeof(n->features.host_behavior));

    for (i = 0; i <= n->nr_io_queues; i++) {
        n->features.int_vector_config[i] = i | (n->intc << 16);
    }
    for (i = 0; i < n->namespace_limit; i++) {
        if (!nvme_ns_shared(n) && n->namespaces[i].allocated) {
            n->namespaces[i].err_rec = 0;
        }
    }
}

static void nvme_clear_ctrl(FemuCtrl *n, bool shutdown)
{
    NvmeAsyncEvent *event;
    int i;
    bool resume;

    /*
     * Stop the dataplane before anything below runs. Waiting for the pollers
     * alone is not enough: the FTL thread holds a request for the whole of its
     * media-latency calculation, and requests sit in each poller's pending
     * list, so the request arrays freed further down stay reachable from both.
     *
     * nvme_pause_pollers() clears dataplane_started itself and then waits for
     * both to go quiet. Clearing the flag here first made it return at its own
     * first line without waiting for anything, which is what this call was
     * added to do.
     */
    resume = nvme_pause_pollers(n);

    /*
     * Drop every Async Event Request the controller was holding, along with any
     * event queued for one. A reset ends the commands the host had outstanding,
     * so completing one afterwards would post to an entry the host has already
     * reclaimed -- which the driver takes as a completion for a request it no
     * longer owns.
     */
    qemu_mutex_lock(&n->aer_lock);
    while ((event = QSIMPLEQ_FIRST(&n->aer_queue)) != NULL) {
        QSIMPLEQ_REMOVE_HEAD(&n->aer_queue, entry);
        g_free(event);
    }
    n->aer_queued = 0;
    qemu_mutex_unlock(&n->aer_lock);
    n->aer_mask = 0;
    n->ns_notice_pending = false;
    n->ns_notice_masked = false;
    n->outstanding_aers = 0;
    n->temp_warn_issued = 0;

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
            nvme_drain_sq(n, n->sq[i]);
            nvme_free_sq(n->sq[i], n);
        }
    }
    for (i = 0; i <= n->nr_io_queues; i++) {
        if (n->cq[i] != NULL) {
            nvme_free_cq(n->cq[i], n);
        }
    }
    n->irq_status = 0;
    pci_irq_deassert(&n->parent_obj);

    if (n->streams) {
        for (i = 0; i < n->namespace_limit; i++) {
            nvme_streams_release(&n->namespaces[i], true);
            n->namespaces[i].streams_enabled = false;
        }
    }
    n->bar.cc = 0;
    nvme_reset_features(n);
    n->temp_warn_issued = 0;
    /*
     * Release the doorbell buffers as well as forgetting them: each enable and
     * configure took a mapping reference that only the device going away gave
     * back, so a guest that resets repeatedly kept one reference per cycle.
     */
    if (n->dbs_addr_hva) {
        AddressSpace *as = pci_get_address_space(&n->parent_obj);

        dma_memory_unmap(as, (void *)n->dbs_addr_hva, n->dbbuf_map_len,
                         DMA_DIRECTION_FROM_DEVICE, 0);
        dma_memory_unmap(as, (void *)n->eis_addr_hva, n->dbbuf_map_len,
                         DMA_DIRECTION_FROM_DEVICE, 0);
    }
    n->dbs_addr = 0;
    n->dbs_addr_hva = 0;
    n->eis_addr = 0;
    n->eis_addr_hva = 0;
    n->dbbuf_map_len = 0;
    if (nvme_ns_shared(n)) {
        n->subsys->ns_resume[n->cntlid] = false;
        nvme_resume_pollers(n, resume);
    }
}

/*
 * Every distinct mode the controller serves gets a say in whether it can run
 * with the settings the host has chosen, and derives from them what it needs.
 * Only the controller's own hook was called, so a namespace whose mode differs
 * from the controller's never ran: a zoned namespace on a controller in any
 * other mode came ready with a zero append limit, which rejects every append
 * larger than one host page while Identify reports no limit at all, and without
 * the memory-page size it refuses.
 */
static int femu_start_ctrl_extensions(FemuCtrl *n)
{
    int (*seen[FEMU_NR_MODES])(struct FemuCtrl *);
    int nseen = 0, i, j;

    if (n->ext_ops.start_ctrl) {
        seen[nseen++] = n->ext_ops.start_ctrl;
    }

    for (i = 0; n->namespaces && i < n->namespace_limit; i++) {
        int (*sc)(struct FemuCtrl *) = n->namespaces[i].ext_ops.start_ctrl;

        if (!n->namespaces[i].allocated || !sc) {
            continue;
        }
        for (j = 0; j < nseen; j++) {
            if (seen[j] == sc) {
                break;
            }
        }
        if (j == nseen && nseen < (int)ARRAY_SIZE(seen)) {
            seen[nseen++] = sc;
        }
    }

    for (j = 0; j < nseen; j++) {
        if (seen[j](n)) {
            return -1;
        }
    }

    return 0;
}

static int nvme_start_ctrl(FemuCtrl *n)
{
    uint32_t page_bits = NVME_CC_MPS(n->bar.cc) + 12;
    uint32_t page_size = 1 << page_bits;

    if (n->cq[0] || n->sq[0] || !n->bar.asq || !n->bar.acq ||
        n->bar.asq & (page_size - 1) || n->bar.acq & (page_size - 1) ||
        NVME_CC_MPS(n->bar.cc) < NVME_CAP_MPSMIN(n->bar.cap) ||
        NVME_CC_MPS(n->bar.cc) > NVME_CAP_MPSMAX(n->bar.cap) ||
        (NVME_CC_IOCQES(n->bar.cc) &&
         (NVME_CC_IOCQES(n->bar.cc) < NVME_CTRL_CQES_MIN(n->id_ctrl.cqes) ||
          NVME_CC_IOCQES(n->bar.cc) > NVME_CTRL_CQES_MAX(n->id_ctrl.cqes))) ||
        (NVME_CC_IOSQES(n->bar.cc) &&
         (NVME_CC_IOSQES(n->bar.cc) < NVME_CTRL_SQES_MIN(n->id_ctrl.sqes) ||
          NVME_CC_IOSQES(n->bar.cc) > NVME_CTRL_SQES_MAX(n->id_ctrl.sqes))) ||
        !NVME_AQA_ASQS(n->bar.aqa) || NVME_AQA_ASQS(n->bar.aqa) > 4095 ||
        !NVME_AQA_ACQS(n->bar.aqa) || NVME_AQA_ACQS(n->bar.aqa) > 4095) {
        return -1;
    }
    /* a command set selection CAP.CSS does not offer is reserved */
    if (!(NVME_CAP_CSS(n->bar.cap) & (1 << NVME_CC_CSS(n->bar.cc)))) {
        return -1;
    }

    n->page_bits = page_bits;
    n->page_size = 1 << n->page_bits;
    n->max_prp_ents = n->page_size / sizeof(uint64_t);
    /*
     * The host may leave the I/O entry sizes at 0 until it creates an I/O
     * queue, and the admin queue's entries have a fixed size anyway. Realize
     * allows no other size, so every queue uses these.
     */
    n->cqe_size = 1 << NVME_MIN_CQUEUE_ES;
    n->sqe_size = 1 << NVME_MIN_SQUEUE_ES;

    /*
     * Either admin queue can fail to come up: the host chooses both addresses
     * and both sizes, and a ring that cannot be mapped whole is refused. The
     * results were discarded, so a completion queue that failed left the
     * submission queue asserting on it, and a submission queue that failed let
     * the controller report itself ready with no queue to take commands.
     */
    if (nvme_init_cq(&n->admin_cq, n, n->bar.acq, 0, 0,
                     NVME_AQA_ACQS(n->bar.aqa) + 1, 1, 1)) {
        return -1;
    }
    if (nvme_init_sq(&n->admin_sq, n, n->bar.asq, 0, 0,
                     NVME_AQA_ASQS(n->bar.aqa) + 1, NVME_Q_PRIO_HIGH, 1)) {
        nvme_free_cq(&n->admin_cq, n);
        return -1;
    }

    /*
     * A mode that cannot serve the settings the host has chosen says so here,
     * and the controller must then not come ready. The result used to be
     * discarded, so it started anyway.
     */
    if (femu_start_ctrl_extensions(n)) {
        return -1;
    }

    nvme_start_dataplane(n);

    return 0;
}

static void nvme_write_bar(FemuCtrl *n, hwaddr offset, uint64_t data, unsigned size)
{
    switch (offset) {
    case 0xc:
        n->bar.intms |= data & 0xffffffff;
        n->bar.intmc = n->bar.intms;
        nvme_irq_mask_changed(n, 0);
        break;
    case 0x10:
        n->bar.intms &= ~(data & 0xffffffff);
        n->bar.intmc = n->bar.intms;
        nvme_irq_mask_changed(n, data & 0xffffffff);
        break;
    case 0x14: {
        /*
         * Compare against the value before this write. Each branch used to
         * update n->bar.cc before the next one looked at it, so a write that
         * cleared EN and set SHN at once never reported the shutdown.
         */
        uint32_t cc = n->bar.cc;
        bool reset = !NVME_CC_EN(data) && NVME_CC_EN(cc);
        bool shutdown = NVME_CC_SHN(data) && !NVME_CC_SHN(cc);

        if (n->power_loss && shutdown && NVME_CC_SHN(data) == 1) {
            bool resume = nvme_pause_pollers(n);
            uint16_t status = bbssd_flush_all(n);

            if (status) {
                nvme_resume_pollers(n, resume);
                n->bar.csts |= NVME_CSTS_FAILED;
                break;
            }
        }

        /* reserved bits, and CRIME, which CAP.CRMS does not offer */
        data &= 0x00fffff1;

        if (NVME_CC_EN(data) && !NVME_CC_EN(cc)) {
            n->bar.cc = data;
            if (nvme_start_ctrl(n)) {
                n->bar.csts = NVME_CSTS_FAILED;
            } else {
                n->bar.csts = NVME_CSTS_READY;
            }
        } else if (reset) {
            /*
             * A reset clears the fatal and shutdown status as well as ready;
             * left set, a controller that failed to start could never be
             * recovered. A shutdown asked for in the same write still
             * completes below.
             */
            nvme_clear_ctrl(n, shutdown);
            n->bar.csts &= ~(NVME_CSTS_READY | NVME_CSTS_FAILED |
                             (CSTS_SHST_MASK << CSTS_SHST_SHIFT));
            /* the Timestamp is not kept across a Controller Level Reset */
            nvme_timestamp_set(n, 0, 0);
            n->clr_ms = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
            femu_pel_reset(n);
            n->bar.cc = data;
        } else if (!NVME_CC_EN(data)) {
            /* the other fields are the host's to set while disabled */
            n->bar.cc = data;
        }

        if (shutdown) {
            if (!reset) {
                nvme_clear_ctrl(n, true);
            }
            n->bar.cc = data;
            n->bar.csts |= NVME_CSTS_SHST_COMPLETE;
        } else if (!NVME_CC_SHN(data) && NVME_CC_SHN(cc)) {
            n->bar.csts &= ~(CSTS_SHST_MASK << CSTS_SHST_SHIFT);
            n->bar.cc = data;
        }
        break;
    }
    case 0x24:
        n->bar.aqa = data & 0x0fff0fff;
        break;
    /*
     * ASQ and ACQ may be written as two dwords in either order, so each half
     * keeps the other. The low 12 bits are reserved.
     */
    case 0x28:
        n->bar.asq = size == 8 ? data :
                     (n->bar.asq & ~0xffffffffULL) | (uint32_t)data;
        n->bar.asq &= ~0xfffULL;
        break;
    case 0x2c:
        n->bar.asq = (n->bar.asq & 0xffffffffULL) | (data << 32);
        break;
    case 0x30:
        n->bar.acq = size == 8 ? data :
                     (n->bar.acq & ~0xffffffffULL) | (uint32_t)data;
        n->bar.acq &= ~0xfffULL;
        break;
    case 0x34:
        n->bar.acq = (n->bar.acq & 0xffffffffULL) | (data << 32);
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

    /*
     * The core widens a one-byte access to this region's two-byte minimum, so
     * a read of the last register byte asks for one byte past the block. Copy
     * only the bytes that exist; the caller keeps just the one it asked for.
     */
    if (addr < sizeof(n->bar)) {
        memcpy(&val, ptr + addr, MIN(size, sizeof(n->bar) - addr));
    }

    return val;
}

static void femu_aer_bh(void *opaque);
static void femu_exit_extensions(FemuCtrl *n);
static void femu_free_namespace_bitmaps(FemuCtrl *n);

/*
 * A write to a doorbell that does not exist, or of a value past the end of the
 * queue, is reported as an Error event (Base 2.3, Figure 152). It used to be
 * dropped without a word.
 */
static void nvme_bad_doorbell(FemuCtrl *n, uint8_t info)
{
    if (n->bar.csts & NVME_CSTS_READY) {
        nvme_enqueue_event(n, NVME_AER_TYPE_ERROR, info, NVME_LOG_ERROR_INFO);
    }
}

/*
 * The admin queue is driven through its doorbell registers even with a shadow
 * doorbell buffer, so keep its EventIdx at the value just written: a host
 * following Annex B.5 then always rings the register.
 */
static void nvme_publish_admin_eventidx(uint64_t hva, uint32_t val)
{
    if (hva) {
        stl_le_p((void *)hva, val);
    }
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
            nvme_bad_doorbell(n, NVME_AER_INFO_ERR_INVALID_SQ);
            return;
        }

        cq = n->cq[qid];
        if (new_val >= cq->size) {
            nvme_bad_doorbell(n, NVME_AER_INFO_ERR_INVALID_DB);
            return;
        }

        cq->head = new_val;

        if (cq->tail != cq->head) {
            nvme_isr_notify_admin(cq);
        }
        nvme_irq_update(n);

        nvme_publish_admin_eventidx(cq->eventidx_addr_hva, cq->head);

        /* the host made room: resume what waited for it */
        if (n->sq[0]) {
            nvme_process_sq_admin(n->sq[0]);
        }
        nvme_process_aers(n);
    } else {
        qid = (addr - 0x1000) >> (3 + n->db_stride);
        if (nvme_check_sqid(n, qid)) {
            nvme_bad_doorbell(n, NVME_AER_INFO_ERR_INVALID_SQ);
            return;
        }
        sq = n->sq[qid];
        if (new_val >= sq->size) {
            nvme_bad_doorbell(n, NVME_AER_INFO_ERR_INVALID_DB);
            return;
        }

        sq->tail = new_val;
        nvme_process_sq_admin(sq);
        nvme_publish_admin_eventidx(sq->eventidx_addr_hva, sq->tail);
    }
}

static void nvme_process_db_io(FemuCtrl *n, hwaddr addr, int val)
{
    uint32_t qid;
    uint16_t new_val = val & 0xffff;
    NvmeSQueue *sq;

    if (addr & ((1 << (2 + n->db_stride)) - 1)) {
        return;
    }

    if (((addr - 0x1000) >> (2 + n->db_stride)) & 1) {
        NvmeCQueue *cq;

        qid = ((addr - (0x1000 + (1 << (2 + n->db_stride)))) >> (3 +
                                                                 n->db_stride));
        if (nvme_check_cqid(n, qid)) {
            nvme_bad_doorbell(n, NVME_AER_INFO_ERR_INVALID_SQ);
            return;
        }

        cq = n->cq[qid];
        /*
         * A queue with a shadow doorbell is driven from the shadow instead.
         * The host still rings the register when EventIdx asks it to, and on
         * the pin that is the moment to drop the level: left asserted after
         * the host has caught up, the line storms and the host disables it.
         */
        if (cq->db_addr) {
            nvme_irq_update(n);
            return;
        }
        if (new_val >= cq->size) {
            nvme_bad_doorbell(n, NVME_AER_INFO_ERR_INVALID_DB);
            return;
        }

        cq->head = new_val;

        if (cq->tail != cq->head) {
            nvme_isr_notify_io(cq);
        }
        nvme_irq_update(n);
    } else {
        qid = (addr - 0x1000) >> (3 + n->db_stride);
        if (nvme_check_sqid(n, qid)) {
            nvme_bad_doorbell(n, NVME_AER_INFO_ERR_INVALID_SQ);
            return;
        }
        sq = n->sq[qid];
        if (sq->db_addr) {
            return;
        }
        if (new_val >= sq->size) {
            nvme_bad_doorbell(n, NVME_AER_INFO_ERR_INVALID_DB);
            return;
        }

        sq->tail = new_val;
    }
}

static void nvme_mmio_write(void *opaque, hwaddr addr, uint64_t data, unsigned size)
{
    FemuCtrl *n = (FemuCtrl *)opaque;
    if (addr < sizeof(n->bar)) {
        nvme_write_bar(n, addr, data, size);
    } else if (addr >= 0x1000 && addr < 0x1000 + 2 * (4 << n->db_stride)) {
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
    /*
     * A mode no extension registers for realized a controller with no command
     * handlers. FEMU_SMARTSSD_MODE has none either, so the bound is the last
     * mode that does, not FEMU_NR_MODES.
     */
    if (n->femu_mode > FEMU_KVSSD_MODE) {
        error_setg(errp, "femu_mode must be 0 (OpenChannel), 1 (black-box), "
                   "2 (no-SSD), 3 (zoned), 4 (computational storage) or "
                   "5 (key-value)");
        return false;
    }
    /* any other version registered no Open-Channel handlers */
    if (n->femu_mode == FEMU_OCSSD_MODE && n->lver != OCSSD12 &&
        n->lver != OCSSD20) {
        error_setg(errp, "lver must be 1 (Open-Channel 1.2) or "
                   "2 (Open-Channel 2.0)");
        return false;
    }
    /*
     * The timing code indexes its per-cell-type tables with this value, and
     * only SLC to QLC have entries in them.
     */
    if (n->femu_mode == FEMU_OCSSD_MODE &&
        (n->flash_type < SLC || n->flash_type > QLC)) {
        error_setg(errp, "flash_type must be 1 (SLC), 2 (MLC), 3 (TLC) or "
                   "4 (QLC)");
        return false;
    }
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
    /*
     * A poller fetches commands without a lock, so every queue needs a single
     * owner. Values above 1 started one poller per shard but had each sweep
     * every queue, and two pollers then ran and completed the same command.
     */
    if (n->multipoller_enabled > 1) {
        error_setg(errp, "multipoller_enabled must be 0 (one poller for all "
                   "queues) or 1 (each poller owns poller_ratio queues)");
        return false;
    }
    /*
     * CAP.MQES is 0's based and a queue's size is kept in 16 bits, so a queue
     * of MQES + 1 entries has to fit in them.
     */
    if (n->max_q_ents < 1 || n->max_q_ents > 0xfffe) {
        error_setg(errp, "entries must be in [1, 65534]");
        return false;
    }
    /*
     * The controller memory buffer becomes a PCI base address register, which
     * has to be a non-zero power of two, and the register field the size comes
     * from is a count of units rather than a size. A cmbsz whose count field
     * is zero or is not a power of two tripped an assertion inside
     * pci_register_bar() and killed the process at realize.
     */
    if (n->cmbsz) {
        uint64_t cmb_size = NVME_CMBSZ_GETSIZE(n->cmbsz);
        uint8_t bir = NVME_CMBLOC_BIR(n->cmbloc);

        if (!cmb_size || !is_power_of_2(cmb_size)) {
            error_setg(errp, "cmbsz describes a %" PRIu64 " byte buffer; the "
                       "size field (bits 31:12) times the unit (bits 11:8) "
                       "must come to a non-zero power of two", cmb_size);
            return false;
        }
        /*
         * The buffer is a 64-bit BAR, so it takes two slots. The registers
         * hold 0 and 1 and the MSI-X table 4 and 5, which leaves 2: BAR 4
         * tripped an assertion in pci_register_bar(), and 3 and 5 overlap the
         * MSI-X BAR's halves.
         */
        if (bir != 2) {
            error_setg(errp, "cmbloc selects base address register %u; the "
                       "controller registers use 0 and 1 and the MSI-X "
                       "table 4 and 5, so it must be 2", bir);
            return false;
        }
    }
    /*
     * Queues are indexed as 64- and 16-byte entries throughout, and admin
     * queues were addressed with the I/O sizes, so larger entries misplaced
     * completions.
     */
    if (n->max_sqes != NVME_MIN_SQUEUE_ES ||
        n->max_cqes != NVME_MIN_CQUEUE_ES) {
        error_setg(errp, "max_sqes must be %d and max_cqes %d, the entry sizes "
                   "of the NVM command set", NVME_MIN_SQUEUE_ES,
                   NVME_MIN_CQUEUE_ES);
        return false;
    }
    if (n->power_loss && (n->femu_mode != FEMU_BBSSD_MODE ||
        n->namespace_modes || n->ns_mgmt || n->subsys || n->meta || n->pi ||
        n->bb_params.buffer_size <= 0)) {
        error_setg(errp, "power_loss requires bbssd, buffer_size > 0, "
                   "and no metadata, namespace management or subsystem");
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
    /*
     * Metadata is kept in a store of its own and moved either through MPTR
     * or interleaved with the data, as mc allows (checked below). Each block
     * size is offered with and without it; metadata formats take the second
     * half of the list.
     */
    if (n->meta && (n->dpc || n->dps)) {
        error_setg(errp, "meta: protection information (dpc, dps) is not "
                   "supported");
        return false;
    }
    if (n->meta && n->nlbaf > 8) {
        error_setg(errp, "meta: at most 8 block sizes (nlbaf), each is also "
                   "offered with metadata");
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
    if (n->streams && (!n->streams_max || n->streams_max > 32)) {
        error_setg(errp, "streams.max must be between 1 and 32");
        return false;
    }
    if (n->streams && ((!BBSSD(n) && !NOSSD(n)) ||
        (n->subsys && n->subsys->params.fdp.enabled))) {
        error_setg(errp, "streams requires bbssd or NoSSD with FDP disabled");
        return false;
    }
    if (n->oacs & ~NVME_OACS_FORMAT) {
        error_setg(errp, "oacs may only set Format NVM (0x%x)", NVME_OACS_FORMAT);
        return false;
    }
    if (n->oncs & ~(NVME_ONCS_COMPARE | NVME_ONCS_WRITE_UNCORR |
                    NVME_ONCS_DSM | NVME_ONCS_WRITE_ZEROS |
                    NVME_ONCS_FEATURES | NVME_ONCS_VERIFY | NVME_ONCS_COPY)) {
        error_setg(errp, "oncs may only set Compare, Write Uncorrectable, "
                   "DSM, Write Zeroes, Save/Select Feature Support, "
                   "Verify and Copy");
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
    id_ns->nlbaf         = (n->meta ? 2 * n->nlbaf : n->nlbaf) - 1;
    if (n->oncs & NVME_ONCS_COPY) {
        id_ns->mssrl     = cpu_to_le16(FEMU_COPY_MSSRL);
        id_ns->mcl       = cpu_to_le32(FEMU_COPY_MCL);
        id_ns->msrc      = FEMU_COPY_MSRC;
    }
    id_ns->flbas         = (n->meta ? n->nlbaf + n->lba_index : n->lba_index) |
                           (n->extended << 4);
    id_ns->nmic          = nvme_ns_shared(n) ? 1 : 0;
    id_ns->mc            = n->mc;
    id_ns->dpc           = n->pi ? (n->meta >= 8 ? 0x1f : 0) : n->dpc;
    id_ns->dps           = n->dps;
    id_ns->dlfeat        = 0x9;
    id_ns->lbaf[0].lbads = 9;
    id_ns->lbaf[0].ms    = 0;

    npdg = 1;
    id_ns->npda = id_ns->npdg = npdg - 1;

    for (i = 0; i < n->nlbaf; i++) {
        id_ns->lbaf[i].lbads = BDRV_SECTOR_BITS + i;
        id_ns->lbaf[i].ms    = 0;
        if (n->meta) {
            id_ns->lbaf[n->nlbaf + i].lbads = BDRV_SECTOR_BITS + i;
            id_ns->lbaf[n->nlbaf + i].ms    = cpu_to_le16(n->meta);
        }
    }
}

void nvme_ns_common_identify(FemuCtrl *n, NvmeIdNs *id)
{
    NvmeIdNs caps = { 0 };

    nvme_ns_init_identify(n, &caps);
    memset(id, 0, sizeof(*id));
    /* the fields NVM 1.2 Figure 114 marks Reported */
    id->nlbaf = caps.nlbaf;
    id->mc = caps.mc;
    id->dpc = caps.dpc;
    id->nmic = caps.nmic;
    memcpy(id->lbaf, caps.lbaf, sizeof(id->lbaf));
}

static void nvme_ns_release(FemuCtrl *n, NvmeNamespace *ns)
{
    nvme_streams_release(ns, true);
    if (ns->ext_ops.ns_exit) {
        ns->ext_ops.ns_exit(n, ns);
    }
    g_free(ns->util);
    g_free(ns->uncorrectable);
    g_free(ns->mdata);
    g_free(ns->fdp.phs);
    if (ns->mdata_lock_init) {
        qemu_mutex_destroy(&ns->mdata_lock);
    }
    memset(ns, 0, sizeof(*ns));
}

static int nvme_init_namespace(FemuCtrl *n, NvmeNamespace *ns, Error **errp)
{
    NvmeIdNs *id_ns = &ns->id_ns;
    uint64_t num_blks;
    int lba_index;

    lba_index = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    /* size this namespace from its own backend slice, not the whole backend */
    num_blks = ns->size / ((1 << id_ns->lbaf[lba_index].lbads));
    id_ns->nuse = id_ns->ncap = id_ns->nsze = cpu_to_le64(num_blks);

    ns->ctrl = n;
    ns->ns_blks = ns_blks(ns, lba_index);
    /*
     * KV capacity is measured in bytes, independent of the block format. A
     * slice smaller than one block leaves an empty namespace, as it always
     * has; Namespace Management refuses a zero size on its own.
     */
    if (!NS_KVSSD(ns) &&
        (num_blks > LONG_MAX ||
         num_blks > SIZE_MAX /
             MAX(1, le16_to_cpu(id_ns->lbaf[lba_index].ms)))) {
        error_setg(errp, "namespace allocation size is not representable");
        return -1;
    }
    ns->util = g_try_new0(unsigned long, BITS_TO_LONGS(num_blks));
    ns->uncorrectable = g_try_new0(unsigned long, BITS_TO_LONGS(num_blks));
    if (num_blks && (!ns->util || !ns->uncorrectable)) {
        error_setg(errp, "cannot allocate namespace bitmaps");
        return -1;
    }
    if (n->meta) {
        qemu_mutex_init(&ns->mdata_lock);
        ns->mdata_lock_init = true;
    }
    ns->mdata_len = num_blks * le16_to_cpu(id_ns->lbaf[lba_index].ms);
    if (ns->mdata_len) {
        ns->mdata = g_try_malloc0(ns->mdata_len);
        if (!ns->mdata) {
            error_setg(errp, "cannot allocate %" PRIu64 " bytes of metadata",
                       ns->mdata_len);
            return -1;
        }
    }

    /* the block format the FTL and Flexible Data Placement size units by */
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
 * Resolve each namespace's byte size. With namespace_sizes unset the exposed
 * capacity is split equally, which for a single namespace hands it the whole
 * of it. When set, it is a comma-separated per-namespace list (e.g. "8G,4G")
 * whose count must equal namespaces, each entry at least one sector, and whose
 * sum must fit the exposed capacity. Each size is then rounded down to whole
 * logical blocks, so no slice ends in part of a block the host cannot address
 * and every slice starts on a block boundary. A key-value namespace is sized
 * in bytes, so it is rounded to a sector only. A size below one block leaves
 * an empty namespace. Capacity no namespace takes stays unused.
 */
static uint64_t nvme_ns_size_align(FemuCtrl *n, uint8_t mode)
{
    if (mode == FEMU_KVSSD_MODE) {
        return 1ULL << BDRV_SECTOR_BITS;
    }
    return 1ULL << (BDRV_SECTOR_BITS + n->lba_index);
}

static int nvme_resolve_ns_sizes(FemuCtrl *n, uint64_t total,
                                 const uint8_t *modes, uint64_t *out_sizes,
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
            out_sizes[i] = QEMU_ALIGN_DOWN(each,
                                           nvme_ns_size_align(n, modes[i]));
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
        if (sz < (1ULL << BDRV_SECTOR_BITS)) {
            error_setg(errp, "namespace_sizes: '%s' is smaller than a sector", tok);
            g_free(dup);
            return -1;
        }
        sz = QEMU_ALIGN_DOWN(sz, nvme_ns_size_align(n, modes[i]));
        out_sizes[i++] = sz;
        sum = sz > UINT64_MAX - sum ? UINT64_MAX : sum + sz;
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

/*
 * Report the total and unallocated NVM capacity, in bytes, as Identify
 * Controller asks for them: 128-bit little-endian. Called once the namespaces
 * are sized, since nvme_init_ctrl() runs before that and would only ever see
 * zero -- which is what `nvme id-ctrl` used to print.
 *
 * The exposed boot pool stays fixed as extents are returned and reused.
 */
static void nvme_set_ctrl_capacity(FemuCtrl *n)
{
    uint64_t total = 0;
    int i;

    for (i = 0; i < n->namespace_limit; i++) {
        if (n->namespaces[i].allocated) {
            total += n->namespaces[i].extent_size;
        }
    }

    memset(n->id_ctrl.tnvmcap, 0, sizeof(n->id_ctrl.tnvmcap));
    memset(n->id_ctrl.unvmcap, 0, sizeof(n->id_ctrl.unvmcap));
    stq_le_p(n->id_ctrl.tnvmcap, n->namespace_pool_size);
    stq_le_p(n->id_ctrl.unvmcap, n->namespace_pool_size - total);
    if (nvme_ns_shared(n)) {
        for (i = 0; i < NVME_MAX_CONTROLLERS; i++) {
            FemuCtrl *ctrl = nvme_subsys_ctrl(n->subsys, i);

            if (ctrl) {
                memcpy(ctrl->id_ctrl.tnvmcap, n->id_ctrl.tnvmcap, 16);
                memcpy(ctrl->id_ctrl.unvmcap, n->id_ctrl.unvmcap, 16);
            }
        }
    }
}

bool nvme_ns_mgmt_supported(FemuCtrl *n)
{
    uint32_t i;

    if (!n->ns_mgmt || (!NOSSD(n) && !BBSSD(n)) || n->dps ||
        (n->subsys && !n->subsys->ns_mgmt)) {
        return false;
    }
    for (i = 0; i < n->namespace_limit; i++) {
        if (n->namespaces[i].allocated &&
            n->namespaces[i].femu_mode != n->femu_mode) {
            return false;
        }
    }
    return true;
}

static int nvme_init_namespaces(FemuCtrl *n, Error **errp)
{
    uint64_t *ns_sizes;
    uint8_t *ns_modes;
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
    if (nvme_resolve_ns_modes(n, ns_modes, errp) ||
        nvme_resolve_ns_sizes(n, n->ns_capacity, ns_modes, ns_sizes, errp)) {
        g_free(ns_sizes);
        g_free(ns_modes);
        return 1;
    }

    if (n->ns_mgmt && BBSSD(n)) {
        for (i = 0; i < n->num_namespaces; i++) {
            if (ns_modes[i] != FEMU_BBSSD_MODE) {
                break;
            }
        }
        if (i == n->num_namespaces &&
            (!n->bbssd_ns_limit ||
             n->bbssd_ns_limit > NVME_MAX_NUM_NAMESPACES ||
             n->num_namespaces > n->bbssd_ns_limit)) {
            error_setg(errp, "bbssd_ns_limit must be between 1 and %u and "
                       "cover the boot namespaces", NVME_MAX_NUM_NAMESPACES);
            g_free(ns_sizes);
            g_free(ns_modes);
            return 1;
        }
    }

    for (i = 0; i < n->num_namespaces; i++) {
        if (n->streams && ns_modes[i] != FEMU_BBSSD_MODE &&
            ns_modes[i] != FEMU_NOSSD_MODE) {
            error_setg(errp, "streams requires NVM namespaces");
            g_free(ns_sizes);
            g_free(ns_modes);
            return 1;
        }
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
        /*
         * The same tables are reached through the controller's handler table,
         * which namespace_modes does not change. Naming ocssd for a namespace
         * of a controller in another mode therefore looks up another mode's
         * state and dereferences it as its own, and naming another mode for
         * every namespace of an ocssd controller leaves those tables
         * uninitialized under the admin commands that still read them.
         */
        if ((ns_modes[i] == FEMU_OCSSD_MODE) != OCSSD(n)) {
            error_setg(errp, "ocssd is a controller mode: femu_mode and "
                       "namespace_modes must both select it, or neither");
            g_free(ns_sizes);
            g_free(ns_modes);
            return 1;
        }
        /*
         * Placement takes every line for its reclaim units and leaves the
         * single write pointer the key-value store uses without one, so every
         * store of a value fails for want of capacity on an empty namespace
         * while Identify reports the whole of it free. Refuse the pair rather
         * than present a namespace that cannot be written.
         */
        if (ns_modes[i] == FEMU_KVSSD_MODE && n->subsys &&
            n->subsys->params.fdp.enabled) {
            error_setg(errp, "the key-value command set and FDP cannot share a "
                       "controller: placement owns every reclaim unit and the "
                       "key-value store is left with no write pointer");
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
    /* metadata is carried by the plain block data path only */
    if (n->meta) {
        for (i = 0; i < n->num_namespaces; i++) {
            if (ns_modes[i] != FEMU_BBSSD_MODE &&
                ns_modes[i] != FEMU_NOSSD_MODE) {
                error_setg(errp, "meta: namespace %d runs a mode without "
                           "metadata support (block or no-SSD only)", i + 1);
                g_free(ns_sizes);
                g_free(ns_modes);
                return 1;
            }
        }
        if (n->subsys && n->subsys->endgrp.fdp.enabled) {
            error_setg(errp, "meta: not supported with placement (fdp)");
            g_free(ns_sizes);
            g_free(ns_modes);
            return 1;
        }
    }

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
        ns->extent_size = ns_sizes[i];
        ns->backend_offset = running_offset;
        ns->start_block = running_offset >> BDRV_SECTOR_BITS;
        running_offset += ns_sizes[i];
        ns->id = i + 1;
        ns->attached = true;
        ns->allocated = true;

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

        nvme_ns_init_identify(n, &ns->id_ns);
        if (nvme_init_namespace(n, ns, errp)) {
            g_free(ns_sizes);
            g_free(ns_modes);
            return 1;
        }
    }
    g_free(ns_sizes);
    g_free(ns_modes);

    for (i = 0; i < n->num_namespaces; i++) {
        n->namespace_pool_size += n->namespaces[i].extent_size;
    }
    if (nvme_ns_mgmt_supported(n)) {
        n->namespace_limit = NVME_MAX_NUM_NAMESPACES;
        n->id_ctrl.nn = cpu_to_le32(n->namespace_limit);
        n->id_ctrl.oaes |= cpu_to_le32(NVME_AEC_NS_ATTR);
        for (i = 0; i < n->num_namespaces; i++) {
            stq_le_p(n->namespaces[i].id_ns.nvmcap,
                     n->namespaces[i].extent_size);
        }
    }
    nvme_set_ctrl_capacity(n);

    return 0;
}

static void nvme_init_ctrl(FemuCtrl *n)
{
    NvmeIdCtrl *id = &n->id_ctrl;
    uint8_t *pci_conf = n->parent_obj.config;
    char *subnqn;

    id->vid = cpu_to_le16(pci_get_word(pci_conf + PCI_VENDOR_ID));
    id->ssvid = cpu_to_le16(pci_get_word(pci_conf + PCI_SUBSYSTEM_VENDOR_ID));

    id->rab          = 6;
    id->cntrltype    = 0x1;     /* an I/O controller */
    id->wctemp       = cpu_to_le16(NVME_TEMPERATURE_WARNING);
    id->cctemp       = cpu_to_le16(NVME_TEMPERATURE_CRITICAL);
    id->ieee[0]      = 0x00;
    id->ieee[1]      = 0x02;
    id->ieee[2]      = 0xb3;
    id->cmic         = nvme_ns_shared(n) ? 2 : 0;
    id->mdts         = n->mdts;
    id->ver          = NVME_SPEC_VER;
    /* OACS, ONCS, OCFS, LPA and SANICAP: nvme_caps_id_ctrl() at realize */

    /* FDP: set Controller Attributes for FDP support */
    if (n->subsys && n->subsys->endgrp.fdp.enabled) {
        id->ctratt = cpu_to_le32(NVME_CTRATT_ENDGRPS | NVME_CTRATT_FDPS);
        /* the subsystem's one endurance group, which every namespace is in */
        id->endgidmax = cpu_to_le16(1);
    }

    /* an extended self-test takes a minute at most; both complete at once */
    id->edstt        = cpu_to_le16(1);
    id->acl          = n->acl;
    id->aerl         = n->aerl;
    /* one read-only slot: the firmware log fills one, and nothing updates it */
    id->frmw         = 1 << 1 | 1;
    id->pels         = cpu_to_le32(1);
    id->elpe         = n->elpe;
    id->npss         = 0;
    id->sqes         = (n->max_sqes << 4) | 0x6;
    id->cqes         = (n->max_cqes << 4) | 0x4;
    id->nn           = cpu_to_le32(n->num_namespaces);
    /* the Open-Channel commands take PRPs only, so they get no SGLs */
    if (n->sgl && !OCSSD(n)) {
        id->sgls     = cpu_to_le32(0x1);   /* advertise address-SGL support */
    }
    subnqn           = g_strdup_printf("nqn.2019-08.org.qemu:%s", n->serial);
    strpadcpy((char *)id->subnqn, sizeof(id->subnqn), subnqn, '\0');
    g_free(subnqn);
    id->fuses        = cpu_to_le16(0);
    id->fna          = 0;
    /*
     * Flush Behavior 10b: a Flush to every namespace at once (NSID FFFFFFFFh)
     * is refused, which is what the I/O path does.
     */
    id->vwc          = n->vwc | (0x2 << 1);
    id->awun         = cpu_to_le16(0);
    id->awupf        = cpu_to_le16(0);
    id->psd[0].mp    = cpu_to_le16(0x9c4);
    id->psd[0].enlat = cpu_to_le32(0x10);
    id->psd[0].exlat = cpu_to_le32(0x4);

    n->features.sw_prog_marker  = 0;
    nvme_reset_features(n);

    n->bar.cap = 0;
    NVME_CAP_SET_MQES(n->bar.cap, n->max_q_ents);
    NVME_CAP_SET_CQR(n->bar.cap, n->cqr);
    NVME_CAP_SET_AMS(n->bar.cap, 1);
    NVME_CAP_SET_TO(n->bar.cap, 0xf);
    NVME_CAP_SET_DSTRD(n->bar.cap, n->db_stride);
    NVME_CAP_SET_NSSRS(n->bar.cap, 0);
    /* NVM plus sets chosen by CSI; NOIOCSS would claim no I/O set at all */
    NVME_CAP_SET_CSS(n->bar.cap, 1);
    NVME_CAP_SET_CSS(n->bar.cap, NVME_CAP_CSS_CSI_SUPP);

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
    uint64_t lat = 0;

    if (!ns) {
        return 0;
    }

    /* The medium's own worker uses the same FTL; it serializes both. */
    if (n->cxl_media && ns->ssd_borrowed) {
        return femu_cxl_nvme_ops->ftl(n, ns, req);
    }

    if (n->power_loss) {
        if (req->status != NVME_SUCCESS) {
            return 0;
        }
        req->reqlat = 0;
        req->status = nvme_power_io(n, req);
        lat = req->reqlat;
    }

    if (NS_ZNSSD(ns)) {
        return zns_ftl_process_req(ns, req);
    }
    if (NS_BBSSD(ns) || NS_CSD(ns)) {
        return MAX(lat, bb_ftl_process_req(n, ns, req));
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
        /*
         * Pair with nvme_pause_pollers(): publish that this pass is running,
         * then re-read the flag, so a caller that cleared it either sees this
         * pass and waits for it, or is seen here and the pass is skipped. An
         * admin command that frees queue state relies on that to know nothing
         * holds a request.
         */
        if (!n->dataplane_started) {
            n->ftl_in_sweep = false;
            usleep(100);
            continue;
        }

        for (i = 1; i <= n->nr_pollers; i++) {
            if (!n->to_ftl[i] || !femu_ring_count(n->to_ftl[i])) {
                continue;
            }

            /*
             * Publish the flag only around a request actually being handled.
             * Doing it once per pass would put a barrier in the idle spin,
             * which changes how this thread and the pollers interleave.
             */
            n->ftl_in_sweep = true;
            smp_mb();   /* publish the flag before re-reading the pause state */
            if (!n->dataplane_started) {
                n->ftl_in_sweep = false;
                break;
            }

            rc = femu_ring_dequeue(n->to_ftl[i], (void *)&req, 1);
            if (rc != 1) {
                femu_err("FEMU: FTL to_ftl dequeue failed\n");
                n->ftl_in_sweep = false;
                continue;
            }

            if (nvme_ns_shared(n)) {
                qemu_mutex_lock(&n->subsys->ns_lock);
                n->subsys->storage->features.volatile_wc =
                    n->features.volatile_wc;
            }
            lat = femu_ftl_process_req(n, req);
            g_clear_pointer(&req->write_data, g_free);
            if (n->power_loss && req->status == NVME_SUCCESS && req->ns) {
                FemuPollerCtr *ctr = &n->poller_ctr[i];
                uint8_t idx = NVME_ID_NS_FLBAS_INDEX(req->ns->id_ns.flbas);
                uint64_t bytes = (uint64_t)req->nlb <<
                                 req->ns->id_ns.lbaf[idx].lbads;

                if (req->cmd.opcode == NVME_CMD_WRITE) {
                    ctr->nr_host_wr_cmds++;
                    ctr->nr_host_wr_bytes += bytes;
                } else if (req->cmd.opcode == NVME_CMD_READ) {
                    ctr->nr_host_rd_cmds++;
                    ctr->nr_host_rd_bytes += bytes;
                }
            }
            if (nvme_ns_shared(n)) {
                qemu_mutex_unlock(&n->subsys->ns_lock);
            }
            req->reqlat = lat;
            req->expire_time += lat;

            rc = femu_ring_enqueue(n->to_poller[i], (void *)&req, 1);
            if (rc != 1) {
                femu_err("FEMU: FTL to_poller enqueue failed\n");
            }

            n->ftl_in_sweep = false;
        }
    }

    return NULL;
}

/* true when some namespace needs the controller's FTL thread running */
static bool femu_needs_ftl_thread(FemuCtrl *n)
{
    int i;

    if (nvme_ns_shared(n) && BBSSD(n)) {
        return true;
    }
    for (i = 0; i < n->namespace_limit; i++) {
        NvmeNamespace *ns = &n->namespaces[i];

        if (ns->allocated && (NS_BBSSD(ns) || NS_ZNSSD(ns) || NS_CSD(ns))) {
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
 *
 * The state slot holds a per-namespace object and is left empty for the
 * namespace's own init to fill. Copying it gave the second namespace of a mode
 * the first one's before its init ran, and an init that reads a filled slot as
 * already done then left the two sharing one object -- for the key-value mode
 * one key space and one value store behind two namespaces, so a key stored on
 * either overwrote the other's.
 */
static void nvme_register_extensions_ns(FemuCtrl *n, NvmeNamespace *ns)
{
    FemuExtCtrlOps saved_ops = n->ext_ops;
    uint8_t saved_mode = n->femu_mode;

    if (ns->femu_mode == n->femu_mode) {
        /*
         * Registering the controller's own mode a second time would build the
         * same table again, and for a mode that allocates controller-wide
         * state it would allocate a second copy that nothing ever reads.
         */
        ns->ext_ops = n->ext_ops;
        ns->ext_ops.state = NULL;
        return;
    }

    n->femu_mode = ns->femu_mode;
    nvme_register_extensions(n);
    ns->ext_ops = n->ext_ops;
    ns->ext_ops.state = NULL;

    n->femu_mode = saved_mode;
    n->ext_ops = saved_ops;
}

void nvme_ns_destroy(FemuCtrl *n, NvmeNamespace *ns)
{
    if (nvme_ns_shared(n)) {
        n = n->subsys->storage;
    }
    nvme_ns_release(n, ns);
    nvme_set_ctrl_capacity(n);
}

/* The complement of owned extents coalesces automatically on removal. */
static bool nvme_ns_find_extent(FemuCtrl *n, uint64_t length, uint64_t *offset)
{
    uint64_t start = 0;
    uint32_t i = 0;

    while (i < n->namespace_limit) {
        NvmeNamespace *ns = &n->namespaces[i++];

        if (length > n->namespace_pool_size - start) {
            return false;
        }
        if (ns->allocated && start < ns->backend_offset + ns->extent_size &&
            ns->backend_offset < start + length) {
            start = ns->backend_offset + ns->extent_size;
            i = 0;
        }
    }
    if (length > n->namespace_pool_size - start) {
        return false;
    }
    *offset = start;
    return true;
}

int nvme_ns_create(FemuCtrl *n, uint32_t nsid, uint64_t nsze, uint8_t flbas,
                   uint8_t mode, bool attached, Error **errp)
{
    NvmeNamespace *ns;
    NvmeIdNs id_ns = { 0 };
    uint64_t bytes;
    uint64_t unit = 4096;
    uint64_t length;
    uint64_t offset;
    uint8_t ds;
    uint32_t i;

    if (nvme_ns_shared(n) && n->subsys->storage) {
        n = n->subsys->storage;
    }
    if (!nsid || nsid > n->namespace_limit || nvme_ns_allocated(n, nsid)) {
        error_setg(errp, "namespace slot is unavailable");
        return -1;
    }
    if ((mode != FEMU_NOSSD_MODE && mode != FEMU_BBSSD_MODE) ||
        (n->subsys && n->subsys->endgrp.fdp.enabled) || n->dps ||
        (mode == FEMU_BBSSD_MODE && !nvme_ns_shared(n) &&
         !n->ftl_thread_running)) {
        error_setg(errp, "namespace lifecycle is unsupported for this mode");
        return -1;
    }
    for (i = 0; i < n->namespace_limit; i++) {
        if (n->namespaces[i].allocated && n->namespaces[i].femu_mode != mode) {
            error_setg(errp, "namespace lifecycle requires a homogeneous mode");
            return -1;
        }
    }
    nvme_ns_init_identify(n, &id_ns);
    if ((flbas & 0xe0) || NVME_ID_NS_FLBAS_INDEX(flbas) > id_ns.nlbaf ||
        !nsze) {
        error_setg(errp, "invalid namespace format or size");
        return -1;
    }
    ds = id_ns.lbaf[NVME_ID_NS_FLBAS_INDEX(flbas)].lbads;
    if (ds >= 64 || nsze > (UINT64_MAX >> ds)) {
        error_setg(errp, "namespace size overflows");
        return -1;
    }
    bytes = nsze << ds;
    if (mode == FEMU_BBSSD_MODE) {
        unit = (uint64_t)n->bb_params.secs_per_pg * n->bb_params.secsz;
    }
    if (!unit || bytes > UINT64_MAX - (unit - 1)) {
        error_setg(errp, "namespace extent overflows");
        return -1;
    }
    length = DIV_ROUND_UP(bytes, unit) * unit;
    if (!nvme_ns_find_extent(n, length, &offset)) {
        error_setg(errp, "insufficient namespace capacity");
        return -ENOSPC;
    }
    ns = &n->namespaces[nsid - 1];
    ns->ctrl = n;
    ns->id = nsid;
    ns->size = bytes;
    ns->extent_size = length;
    ns->backend_offset = offset;
    ns->start_block = offset >> BDRV_SECTOR_BITS;
    ns->femu_mode = mode;
    ns->csi = NVME_CSI_NVM;
    ns->id_ns = id_ns;
    ns->id_ns.flbas = flbas;
    if (nvme_init_namespace(n, ns, errp)) {
        goto fail;
    }
    nvme_register_extensions_ns(n, ns);
    if (ns->ext_ops.init) {
        Error *local_err = NULL;

        ns->ext_ops.init(n, ns, &local_err);
        if (local_err) {
            error_propagate(errp, local_err);
            goto fail;
        }
    }
    if (qtest_enabled() && n->test_ns_fail) {
        n->test_ns_fail = false;
        error_setg(errp, "injected namespace initialization failure");
        goto fail;
    }
    memset((uint8_t *)n->mbe->logical_space + offset, 0, length);
    if (nvme_ns_mgmt_supported(n)) {
        stq_le_p(ns->id_ns.nvmcap, length);
    }
    ns->creation_generation = ++n->ns_creation_generation;
    ns->attached = attached;
    if (attached && nvme_ns_shared(n)) {
        set_bit(nsid - 1, n->attached_ns);
    }
    ns->allocated = true;
    nvme_set_ctrl_capacity(n);
    return 0;

fail:
    nvme_ns_release(n, ns);
    return -1;
}

const FemuCxlNvmeOps *femu_cxl_nvme_ops;

/*
 * The linked medium supplies the FTL and its geometry, so only a plain
 * single-namespace bbssd controller can front it.
 */
static bool femu_cxl_link_check(FemuCtrl *n, Error **errp)
{
    const char *why = NULL;

    if (!femu_cxl_nvme_ops) {
        why = "a build with the CXL SSD";
    } else if (!BBSSD(n)) {
        why = "femu_mode=1";
    } else if (n->num_namespaces != 1 || n->namespace_modes ||
               n->namespace_sizes) {
        why = "a single bbssd namespace";
    } else if (n->ns_mgmt || n->subsys) {
        why = "no namespace management or subsystem";
    } else if (n->streams || n->power_loss || n->bb_params.buffer_size ||
               n->op_pcent) {
        why = "no streams, power_loss, buffer_size or op_pcent";
    } else if (n->meta || n->pi || n->dps) {
        why = "no metadata or protection information";
    }
    if (why) {
        error_setg(errp, "cxl_ssd requires %s", why);
        return false;
    }
    return true;
}

/*
 * Give back what realize has taken. QEMU does not call the exit callback for a
 * device that never realized, and a device_add that fails validation is an
 * ordinary outcome -- the monitor reports it and the user tries again -- so a
 * rejected configuration otherwise kept its whole memory backend, pinned.
 */
static void femu_realize_undo(FemuCtrl *n)
{
    /*
     * Namespaces that did come up own an FTL and its channel tree, which is
     * the largest allocation here. Every mode's exit tests the state it frees
     * before touching it, so running them over a controller that got part way
     * is safe, and it has to happen before the namespace array goes.
     */
    if (n->cxl_dev && femu_cxl_nvme_ops) {
        femu_cxl_nvme_ops->detach(n);
    }
    if (!n->shared_storage) {
        femu_exit_extensions(n);
    }

    if (n->subsys) {
        femu_subsys_unregister_ctrl(n->subsys, n);
    }
    if (n->aer_bh) {
        qemu_bh_delete(n->aer_bh);
        n->aer_bh = NULL;
        qemu_mutex_destroy(&n->aer_lock);
        qemu_mutex_destroy(&n->streams_lock);
    }
    g_free(n->features.int_vector_config);
    n->features.int_vector_config = NULL;
    g_free(n->cmbuf);
    n->cmbuf = NULL;
    if (!n->shared_storage) {
        femu_free_namespace_bitmaps(n);
    }
    g_free(n->aer_held);
    n->aer_held = NULL;
    g_free(n->elpes);
    n->elpes = NULL;
    if (!n->shared_storage) {
        g_free(n->namespaces);
    }
    n->namespaces = NULL;
    g_free(n->cq);
    n->cq = NULL;
    g_free(n->sq);
    n->sq = NULL;
    if (!n->shared_storage && !n->cxl_dev) {
        free_dram_backend(n->mbe);
    }
    n->mbe = NULL;

    /*
     * QEMU frees only the config space of a device whose realize failed, and
     * the interrupt table regions MSI-X adds under its exclusive bar each hold
     * a reference on the controller they belong to. Left in place, a refused
     * device_add never reached finalize at all, so the whole object leaked,
     * not only the tables.
     */
    if (msix_present(&n->parent_obj)) {
        msix_uninit_exclusive_bar(&n->parent_obj);
    }
}

/*
 * Properties that nothing reads. They stay accepted so old command lines
 * still start, but a value other than the default changes nothing, and the
 * user should hear that once rather than trust it.
 */
static const struct {
    const char *name;
    const char *instead;
} femu_ignored_props[] = {
    { "serial", NULL },
    { "ms", "meta sets the metadata size" },
    { "ms_max", NULL },
    { "dlfeat", NULL },
    { "tplpbsy", NULL },
    { "tplrbsy", NULL },
    { "trcbsy", NULL },
    { "nr_thread", NULL },
    { "time_slice", NULL },
    { "context_switch_time", NULL },
};

static void femu_warn_ignored_props(FemuCtrl *n)
{
    Object *obj = OBJECT(n);

    for (int i = 0; i < ARRAY_SIZE(femu_ignored_props); i++) {
        const char *name = femu_ignored_props[i].name;
        const char *instead = femu_ignored_props[i].instead;
        ObjectProperty *op = object_property_find(obj, name);
        QObject *val = object_property_get_qobject(obj, name, &error_abort);
        QString *str = qobject_to(QString, val);
        bool set;

        /* A string property has no default; unset reads back as "". */
        if (op->defval) {
            set = !qobject_is_equal(val, op->defval);
        } else {
            set = str && *qstring_get_str(str);
        }
        qobject_unref(val);
        if (set) {
            warn_report("femu: %s has no effect and is accepted only for "
                        "compatibility%s%s", name,
                        instead ? "; " : "", instead ? instead : "");
        }
    }
}

static void femu_realize(PCIDevice *pci_dev, Error **errp)
{
    FemuCtrl *n = FEMU(pci_dev);
    int64_t bs_size;
    uint64_t nand_cap = 0;

    if (nvme_ns_shared(n)) {
        FemuCtrl *storage = n->subsys->storage;

        if (!DEVICE(n->subsys)->realized) {
            error_setg(errp, "realize the subsystem before its controllers");
            return;
        }
        n->ns_mgmt = true;
        if ((!NOSSD(n) && !BBSSD(n)) || n->streams || n->dps ||
            n->namespace_modes) {
            error_setg(errp, "shared namespaces require homogeneous NoSSD or "
                       "bbssd without Streams or default protection");
            return;
        }
        if (storage && (n->femu_mode != storage->femu_mode ||
                        n->meta != storage->meta || n->pi != storage->pi ||
                        n->mc != storage->mc || n->dpc != storage->dpc ||
                        n->nlbaf != storage->nlbaf ||
                        n->vwc != storage->vwc || n->oncs != storage->oncs)) {
            error_setg(errp, "shared namespace mode and capabilities "
                       "must match");
            return;
        }
    }
    if (n->ns_mgmt && n->subsys && !n->subsys->ns_mgmt) {
        error_setg(errp, "ns_mgmt=on does not support subsys; "
                   "use a standalone controller");
        return;
    }

    nvme_check_size();

    if (!nvme_check_constraints(n, errp)) {
        return;
    }
    femu_warn_ignored_props(n);

    /* Format and Sanitize would rewrite the whole medium under its cache. */
    if (n->cxl_dev) {
        if (!femu_cxl_link_check(n, errp) ||
            !femu_cxl_nvme_ops->prepare(n, errp)) {
            return;
        }
        n->oacs &= ~NVME_OACS_FORMAT;
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

    if (nvme_ns_shared(n) && n->subsys->storage) {
        n->mbe = n->subsys->storage->mbe;
        n->shared_storage = true;
    } else if (n->cxl_dev) {
        /* prepare() lent the medium's backend */
    } else {
        init_dram_backend(&n->mbe, bs_size);
        n->mbe->femu_mode = n->femu_mode;
    }

    /* the host-link model is armed only when a knob asks for it */
    n->pcie_enabled = (n->pcie_bandwidth_mbps || n->pcie_prop_delay_ns);
    n->pcie_tx_next_avail_time = 0;
    n->pcie_rx_next_avail_time = 0;
    n->fw_cpu_next_avail_time = 0;
    pthread_spin_init(&n->pcie_lock, PTHREAD_PROCESS_PRIVATE);
    pthread_spin_init(&n->fw_cpu_lock, PTHREAD_PROCESS_PRIVATE);

    n->completed = 0;
    n->power_on_ms = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
    /* doorbells start at 0x1000, two per queue, each 4 << stride bytes apart */
    /*
     * The transport makes BAR0 bits 13:4 read only, so the registers take at
     * least 16 KiB whatever the doorbells need (PCIe Transport 1.3, 3.8.1.10).
     */
    n->reg_size = MAX(16 * KiB, pow2ceil(0x1000 + 2 * (n->nr_io_queues + 1) *
                                         (4 << n->db_stride)));
    /* ns_size is the per-namespace share of the exposed capacity */
    n->ns_capacity = bs_size;
    if (BBSSD(n) && n->op_pcent) {
        n->ns_capacity = nand_cap * 100 / (100ULL + n->op_pcent);
    }
    n->ns_size = n->ns_capacity / (uint64_t)n->num_namespaces;
    if (BBSSD(n) && n->op_pcent) {
        n->ns_size &= ~((1ULL << BDRV_SECTOR_BITS) - 1);
    }

    /* Coperd: [1..nr_io_queues] are used as IO queues */
    n->sq = g_malloc0(sizeof(*n->sq) * (n->nr_io_queues + 1));
    n->cq = g_malloc0(sizeof(*n->cq) * (n->nr_io_queues + 1));
    n->namespace_limit = n->num_namespaces;
    n->namespaces = n->shared_storage ? n->subsys->storage->namespaces :
                    g_new0(NvmeNamespace, NVME_MAX_NUM_NAMESPACES);
    n->elpes = g_malloc0(sizeof(*n->elpes) * (n->elpe + 1));
    qemu_spin_init(&n->elp_lock);
    for (int d = 0; d < NVME_DST_RESULTS; d++) {
        n->dst_results[d].status = 0xf;     /* entry is empty */
    }
    /* the backing store starts empty, as if never written */
    if (!n->shared_storage) {
        nvme_sanitize_state(n)->sstat = NVME_SSTAT_GDE;
        if (nvme_ns_shared(n)) {
            nvme_sanitize_state(n)->cdw10 = 0;
        }
    }
    seqlock_init(&n->ts_seq);
    nvme_timestamp_set(n, 0, 0);
    n->clr_ms = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
    n->aer_held = g_malloc0(sizeof(*n->aer_held) * (n->aerl + 1));
    QSIMPLEQ_INIT(&n->aer_queue);
    qemu_mutex_init(&n->aer_lock);
    qemu_mutex_init(&n->streams_lock);
    n->aer_bh = qemu_bh_new_guarded(femu_aer_bh, n,
                                    &DEVICE(n)->mem_reentrancy_guard);
    n->features.int_vector_config = g_malloc0(sizeof(*n->features.int_vector_config) * (n->nr_io_queues + 1));

    nvme_init_pci(n);

    /* FDP: register controller with subsystem if linked */
    if (nvme_init_subsys(n, errp)) {
        femu_realize_undo(n);
        return;
    }

    nvme_init_ctrl(n);
    /*
     * Stop here if the namespaces did not come up. The mode init below builds on
     * initialized namespace state and would otherwise run against half-built
     * namespaces, and it takes the same Error argument, which must not already
     * carry an error.
     */
    if (n->shared_storage) {
        n->namespace_limit = NVME_MAX_NUM_NAMESPACES;
        n->namespace_pool_size = n->subsys->storage->namespace_pool_size;
        n->id_ctrl.nn = cpu_to_le32(n->namespace_limit);
        n->id_ctrl.oaes |= cpu_to_le32(NVME_AEC_NS_ATTR);
        nvme_set_ctrl_capacity(n);
    } else if (nvme_init_namespaces(n, errp)) {
        femu_realize_undo(n);
        return;
    }
    /*
     * Fill the capabilities once the namespaces exist, before any FTL runs:
     * a managed bbssd namespace reads OACS to pick its addressing, and the
     * shared storage object copies these fields.
     */
    nvme_caps_id_ctrl(n, &n->id_ctrl);

    nvme_register_extensions(n);

    /*
     * Bring up each namespace under its own mode. The controller keeps the table
     * for its own femu_mode for the admin paths, while each namespace gets the
     * one matching the mode it runs.
     */
    for (int i = 0; !n->shared_storage && i < n->num_namespaces; i++) {
        NvmeNamespace *ns = &n->namespaces[i];
        uint8_t idx = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
        uint64_t page_size = (uint64_t)n->bb_params.secsz *
                            n->bb_params.secs_per_pg;

        if (n->power_loss && (!page_size ||
            page_size % (1ULL << ns->id_ns.lbaf[idx].lbads) ||
            ns->backend_offset % page_size || ns->size % page_size)) {
            error_setg(errp, "power_loss requires page-aligned namespaces "
                       "and whole LBAs per NAND page");
            femu_realize_undo(n);
            return;
        }
        nvme_register_extensions_ns(n, ns);
        if (ns->ext_ops.init) {
            Error *local_err = NULL;

            ns->ext_ops.init(n, ns, &local_err);
            if (local_err) {
                error_propagate(errp, local_err);
                femu_realize_undo(n);
                return;
            }
        }
    }

    /* Managed devices name boot namespaces once, never during Create. */
    for (int i = 0; !n->shared_storage && i < n->num_namespaces; i++) {
        NvmeNamespace *ns = &n->namespaces[i];

        if (n->ns_mgmt && ns->ext_ops.init_ctrl_name) {
            ns->ext_ops.init_ctrl_name(n, ns);
        }
    }

    /* No namespace runs the controller's own mode: name it from that mode. */
    if (!n->shared_storage && n->num_namespaces && !n->devname[0] &&
        n->ext_ops.init_ctrl_name) {
        n->ext_ops.init_ctrl_name(n, NULL);
    }

    /* Validate retention before starting threads that would need unwinding. */
    if (!femu_pel_init(n, errp)) {
        femu_realize_undo(n);
        return;
    }

    if (nvme_ns_shared(n)) {
        if (!n->subsys->storage) {
            n->subsys->storage = nvme_subsys_take_storage(n);
            for (uint32_t i = 0; i < n->num_namespaces; i++) {
                set_bit(i, n->attached_ns);
            }
            n->shared_storage = true;
        }
        memcpy(n->id_ctrl.sn, n->subsys->storage->id_ctrl.sn,
               sizeof(n->id_ctrl.sn));
        memcpy(n->id_ctrl.mn, n->subsys->storage->id_ctrl.mn,
               sizeof(n->id_ctrl.mn));
        memcpy(n->id_ctrl.fr, n->subsys->storage->id_ctrl.fr,
               sizeof(n->id_ctrl.fr));
        memcpy(n->id_ctrl.subnqn, n->subsys->subnqn,
               sizeof(n->id_ctrl.subnqn));
    }

    /*
     * One FTL thread serves every namespace that needs one. It is started after
     * all namespaces are built, so it never runs against half-initialized state,
     * and only once every geometry check has passed.
     */
    if (n->cxl_dev) {
        femu_cxl_nvme_ops->attach(n, &n->namespaces[0]);
    }

    n->use_ftl_thread = femu_needs_ftl_thread(n);
    if (n->use_ftl_thread) {
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

/*
 * Stop and join the poller threads. Everything they reach -- the queues, the
 * rings, and each namespace's mode state -- is freed during teardown, so they
 * must be gone before any of it is released.
 */
static void femu_stop_pollers(FemuCtrl *n)
{
    int i;

    if (!n->poller) {
        return;   /* the host never enabled the controller */
    }

    n->poller_stopping = true;
    smp_mb();   /* publish the flag before waiting on the threads to see it */
    for (i = 1; i <= n->nr_pollers; i++) {
        qemu_thread_join(&n->poller[i]);
    }
    g_free(n->poller);
    n->poller = NULL;
}

static void nvme_destroy_poller(FemuCtrl *n)
{
    int i;
    femu_debug("Destroying NVMe poller !!\n");

    for (i = 1; i <= n->nr_pollers; i++) {
        pqueue_free(n->pq[i]);
        femu_ring_free(n->to_poller[i]);
        femu_ring_free(n->to_ftl[i]);
    }

    g_free(n->pq);
    n->pq = NULL;
    g_free(n->to_poller);
    n->to_poller = NULL;
    g_free(n->to_ftl);
    n->to_ftl = NULL;
    /* the threads are joined by now, so what they were reading can go */
    g_free(n->poller_args);
    n->poller_args = NULL;
    g_free(n->should_isr);
    g_free(n->cpl_backlog);
    g_free((void *)n->poller_in_sweep);
    n->poller_in_sweep = NULL;
    qemu_vfree(n->poller_ctr);   /* allocated with qemu_memalign */
    n->poller_ctr = NULL;
}

/*
 * The allocation map and the uncorrectable-block map of every namespace. They
 * are sized from the block count, so a large device leaks tens of megabytes per
 * add and remove without this.
 */
static void femu_free_namespace_bitmaps(FemuCtrl *n)
{
    int i;

    for (i = 0; n->namespaces && i < n->namespace_limit; i++) {
        nvme_ns_release(n, &n->namespaces[i]);
    }
}

/*
 * Run each mode's exit once. A namespace may run a mode other than the
 * controller's, and every mode's exit walks the namespaces itself, so dispatch
 * over the distinct handlers rather than once per namespace.
 */
/* Post whatever events are queued, from the main loop rather than a poller. */
static void femu_aer_bh(void *opaque)
{
    nvme_process_aers(opaque);
}

static void femu_exit_extensions(FemuCtrl *n)
{
    void (*seen[FEMU_NR_MODES])(struct FemuCtrl *);
    int nseen = 0, i, j;

    if (n->ext_ops.exit) {
        seen[nseen++] = n->ext_ops.exit;
    }

    for (i = 0; n->namespaces && i < n->namespace_limit; i++) {
        void (*ex)(struct FemuCtrl *) = n->namespaces[i].ext_ops.exit;

        if (!n->namespaces[i].allocated || !ex) {
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

    /*
     * Stop every thread first. femu_exit_extensions() releases each mode's FTL
     * and namespace state, which the pollers read on the I/O path, and
     * nvme_destroy_poller() then frees the rings and joins nothing.
     *
     * Pollers before the FTL thread: they are what feeds it, so stopping the
     * consumer first leaves them enqueueing into a ring nothing drains, which
     * fills and then complains once per request.
     */
    femu_stop_pollers(n);
    femu_stop_ftl_thread(n);
    femu_pel_exit(n);
    if (n->cxl_dev) {
        femu_cxl_nvme_ops->detach(n);
    }
    if (!n->shared_storage) {
        femu_exit_extensions(n);
    }

    nvme_clear_ctrl(n, true);
    nvme_destroy_poller(n);
    /* the pollers are gone, so nothing can wake the bottom half any more */
    qemu_bh_delete(n->aer_bh);
    n->aer_bh = NULL;
    qemu_mutex_destroy(&n->aer_lock);
    qemu_mutex_destroy(&n->streams_lock);
    if (!n->shared_storage && !n->cxl_dev) {
        free_dram_backend(n->mbe);
    }

    if (!n->shared_storage) {
        femu_free_namespace_bitmaps(n);
    }
    pthread_spin_destroy(&n->pcie_lock);
    pthread_spin_destroy(&n->fw_cpu_lock);

    /* FDP: unregister controller from subsystem */
    if (n->subsys) {
        femu_subsys_unregister_ctrl(n->subsys, n);
    }

    if (!n->shared_storage) {
        g_free(n->namespaces);
    }
    g_free(n->cmbuf);   /* the controller memory buffer, if configured */
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
    /*
     * The BAR regions are owned by this device and were never referenced by
     * it, so there is nothing here to release: a memory region holds a
     * reference on its owner, not the other way round. Dropping one per BAR
     * took the controller's reference count below what the address space
     * still held, and the flatview that outlives the eject then finalized the
     * device from inside its own teardown loop, freeing this object while it
     * was still walking regions embedded in it.
     */
    msix_uninit_exclusive_bar(pci_dev);
}

static const Property femu_props[] = {
    //DEFINE_BLOCK_PROPERTIES(FemuCtrl, blkconf),
    DEFINE_PROP_STRING("serial", FemuCtrl, serial),
    DEFINE_PROP_STRING("pel_file", FemuCtrl, pel_file),
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
    DEFINE_PROP_BOOL("power_loss", FemuCtrl, power_loss, false),
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
    DEFINE_PROP_BOOL("pi", FemuCtrl, pi, false),
    DEFINE_PROP_UINT8("dpc", FemuCtrl, dpc, 0),
    DEFINE_PROP_UINT8("dps", FemuCtrl, dps, 0),
    DEFINE_PROP_UINT8("mc", FemuCtrl, mc, 0),
    DEFINE_PROP_UINT8("meta", FemuCtrl, meta, 0),
    DEFINE_PROP_UINT32("cmbsz", FemuCtrl, cmbsz, 0),
    DEFINE_PROP_UINT32("cmbloc", FemuCtrl, cmbloc, 0),
    DEFINE_PROP_BOOL("ns_mgmt", FemuCtrl, ns_mgmt, false),
    /*
     * With ns_mgmt, each bbssd namespace owns a full-geometry FTL: 20 bytes
     * per NAND page for maps and page state (80 MiB at default geometry),
     * plus block/line state and optional caches, apart from the shared backend.
     * Bound allocated namespaces, including detached ones, before FTL setup.
     */
    DEFINE_PROP_UINT32("bbssd_ns_limit", FemuCtrl, bbssd_ns_limit, 4),
    DEFINE_PROP_BOOL("streams", FemuCtrl, streams, false),
    DEFINE_PROP_UINT16("streams.max", FemuCtrl, streams_max, 8),
    DEFINE_PROP_UINT16("oacs", FemuCtrl, oacs, NVME_OACS_FORMAT),
    /*
     * Save/Select Feature Support is how a host learns it may use the Select
     * field and the Save bit of Get/Set Features, which the controller serves,
     * so it is on by default; the rest stay opt-in.
     */
    DEFINE_PROP_UINT16("oncs", FemuCtrl, oncs,
                       NVME_ONCS_DSM | NVME_ONCS_FEATURES),
    DEFINE_PROP_BOOL("sgl", FemuCtrl, sgl, false),
    DEFINE_PROP_UINT16("vid", FemuCtrl, vid, 0x1d1d),
    DEFINE_PROP_UINT16("did", FemuCtrl, did, 0x1f1f),
    DEFINE_PROP_UINT8("femu_mode", FemuCtrl, femu_mode, FEMU_NOSSD_MODE),
    DEFINE_PROP_UINT8("flash_type", FemuCtrl, flash_type, MLC),
    DEFINE_PROP_UINT8("lver", FemuCtrl, lver, 0x2),
    DEFINE_PROP_BOOL("oc12_channel_timing", FemuCtrl,
                     oc_params.channel_timing, false),
    DEFINE_PROP_UINT16("lsec_size", FemuCtrl, oc_params.sec_size, 4096),
    DEFINE_PROP_UINT8("lsecs_per_pg", FemuCtrl, oc_params.secs_per_pg, 4),
    DEFINE_PROP_UINT16("lpgs_per_blk", FemuCtrl, oc_params.pgs_per_blk, 512),
    DEFINE_PROP_UINT8("lmax_sec_per_rq", FemuCtrl, oc_params.max_sec_per_rq, 64),
    DEFINE_PROP_UINT8("lnum_ch", FemuCtrl, oc_params.num_ch, 2),
    DEFINE_PROP_UINT8("lnum_lun", FemuCtrl, oc_params.num_lun, 8),
    DEFINE_PROP_UINT8("lnum_pln", FemuCtrl, oc_params.num_pln, 2),
    DEFINE_PROP_UINT16("lmetasize", FemuCtrl, oc_params.sos, 16),
    /*
     * Open-Channel 2.0 lets a host reset a chunk it has not filled only when
     * the controller says it can. The capability was built but nothing could
     * turn it on, so every such reset was refused.
     */
    DEFINE_PROP_UINT8("learly_reset", FemuCtrl, params.oc20.early_reset, 0),
    DEFINE_PROP_UINT64("fdm_size", FemuCtrl, csd_params.fdm_size_mb, 0),
    DEFINE_PROP_UINT8("nr_cu", FemuCtrl, csd_params.nr_cu, 4),
    DEFINE_PROP_UINT8("nr_thread", FemuCtrl, csd_params.nr_thread, 4),
    DEFINE_PROP_UINT64("time_slice", FemuCtrl, csd_params.time_slice, 200000),
    DEFINE_PROP_UINT64("context_switch_time", FemuCtrl,
                       csd_params.context_switch_time, 200),
    DEFINE_PROP_UINT16("csf_runtime_scale", FemuCtrl,
                       csd_params.csf_runtime_scale, 3),
    DEFINE_PROP_STRING("csd_program_dir", FemuCtrl, csd_params.program_dir),
    DEFINE_PROP_UINT8("zns_num_ch", FemuCtrl, zns_params.zns_num_ch, 2),
    DEFINE_PROP_UINT8("zns_num_lun", FemuCtrl, zns_params.zns_num_lun, 4),
    DEFINE_PROP_UINT8("zns_num_plane", FemuCtrl, zns_params.zns_num_plane, 2),
    DEFINE_PROP_UINT8("zns_num_blk", FemuCtrl, zns_params.zns_num_blk, 32),
    DEFINE_PROP_INT32("zns_flash_type", FemuCtrl, zns_params.zns_flash_type, QLC),
    DEFINE_PROP_INT64("zns_pg_rd_lat", FemuCtrl, zns_params.zns_pg_rd_lat, 0),
    DEFINE_PROP_INT64("zns_pg_wr_lat", FemuCtrl, zns_params.zns_pg_wr_lat, 0),
    DEFINE_PROP_INT64("zns_blk_er_lat", FemuCtrl, zns_params.zns_blk_er_lat, 0),
    DEFINE_PROP_INT64("zns_cmd_addr_lat", FemuCtrl, zns_params.zns_cmd_addr_lat, 0),
    DEFINE_PROP_INT64("zns_pg_xfer_lat", FemuCtrl, zns_params.zns_pg_xfer_lat, 0),
    DEFINE_PROP_INT64("zns_status_lat", FemuCtrl, zns_params.zns_status_lat, 0),
    DEFINE_PROP_INT32("zns_pe_suspend", FemuCtrl, zns_params.zns_pe_suspend, 0),
    DEFINE_PROP_INT64("zns_tsusp_ns", FemuCtrl, zns_params.zns_tsusp_ns, 0),
    DEFINE_PROP_UINT32("zns_max_active", FemuCtrl, zns_params.zns_max_active, 0),
    DEFINE_PROP_UINT32("zns_max_open", FemuCtrl, zns_params.zns_max_open, 0),
    DEFINE_PROP_UINT32("zns_num_wc", FemuCtrl, zns_params.zns_num_wc, 0),
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
    DEFINE_PROP_UINT64("gc_seed", FemuCtrl, gc_seed, 0),
    DEFINE_PROP_UINT32("read_cache_mb", FemuCtrl, read_cache_mb, 0),
    DEFINE_PROP_STRING("cache_evict", FemuCtrl, bb_params.cache_evict),
    DEFINE_PROP_STRING("mapping", FemuCtrl, bb_params.mapping_scheme),
    DEFINE_PROP_UINT32("mapping_cache_mb", FemuCtrl, mapping_cache_mb, 0),
    DEFINE_PROP_UINT8("nand_cell_type", FemuCtrl, nand_cell_type, 0),
    DEFINE_PROP_UINT32("pe_cycles_rated", FemuCtrl, pe_cycles_rated, 0),
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
    DEFINE_PROP_INT32("pe_suspend", FemuCtrl, bb_params.pe_suspend, 0),
    DEFINE_PROP_INT32("tsusp_ns", FemuCtrl, bb_params.tsusp_ns, 0),
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
    DEFINE_PROP_LINK("cxl_ssd", FemuCtrl, cxl_dev, TYPE_FEMU_CXL_SSD,
                     DeviceState *),
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

/* A configuration object has no PCI transport, queues or worker threads. */
static FemuCtrl *nvme_subsys_take_storage(FemuCtrl *n)
{
    FemuCtrl *storage = FEMU(object_new(TYPE_NVME));

    for (size_t i = 0; i < ARRAY_SIZE(femu_props); i++) {
        const char *name = femu_props[i].name;
        QObject *value = object_property_get_qobject(OBJECT(n), name,
                                                     &error_abort);

        object_property_set_qobject(OBJECT(storage), name, value, &error_abort);
        qobject_unref(value);
    }
    storage->namespaces = n->namespaces;
    storage->namespace_limit = n->namespace_limit;
    storage->namespace_pool_size = n->namespace_pool_size;
    storage->mbe = n->mbe;
    storage->id_ctrl = n->id_ctrl;
    storage->ext_ops = n->ext_ops;
    memcpy(storage->devname, n->devname, sizeof(storage->devname));
    for (uint32_t i = 0; i < n->namespace_limit; i++) {
        NvmeNamespace *ns = &n->namespaces[i];

        if (!ns->allocated) {
            continue;
        }
        ns->ctrl = storage;
        if (ns->ssd) {
            ns->ssd->n = storage;
            ns->ssd->ssdname = storage->devname;
            ns->ssd->dataplane_started_ptr = &storage->dataplane_started;
        }
    }
    n->ssd = NULL;
    return storage;
}

static const VMStateDescription femu_vmstate = {
    .name = "femu",
    .unmigratable = 1,
};

/* Faults and transient queue states cannot be requested by an NVMe host. */
static void femu_test_namespace(Object *obj, const char *value, Error **errp)
{
    FemuCtrl *n = FEMU(obj);

    if (!n->sq[0] && !strcmp(value, "check-large-namespace")) {
        NvmeNamespace ns = { 0 };
        uint64_t blocks = (1ULL << 31) + 8;

        /* Exercise construction without allocating a terabyte of backend. */
        ns.size = blocks << BDRV_SECTOR_BITS;
        nvme_ns_init_identify(n, &ns.id_ns);
        if (!nvme_init_namespace(n, &ns, errp)) {
            bitmap_set(ns.util, blocks - 1, 1);
            bitmap_set(ns.uncorrectable, blocks - 1, 1);
            if (le64_to_cpu(ns.id_ns.nsze) != blocks ||
                !test_bit(blocks - 1, ns.util) || test_bit(7, ns.util) ||
                !test_bit(blocks - 1, ns.uncorrectable)) {
                error_setg(errp, "large namespace block count was truncated");
            }
        }
        nvme_ns_release(n, &ns);
        return;
    }
    if (!n->sq[0] && !strcmp(value, "seed-sanitize")) {
        memset(n->mbe->logical_space, 0x5a, n->mbe->size);
        return;
    }
    if (!n->sq[0] && !strcmp(value, "check-sanitize")) {
        const uint8_t *bytes = n->mbe->logical_space;

        for (uint64_t i = 0; i < n->mbe->size; i++) {
            uint8_t expected = i < n->namespace_pool_size ? 0 : 0x5a;

            if (bytes[i] != expected) {
                error_setg(errp, "sanitize byte at %" PRIu64
                           " is %u, expected %u", i, bytes[i], expected);
                return;
            }
        }
        return;
    }
    if (!nvme_ns_mgmt_supported(n)) {
        error_setg(errp, "namespace fixture requires namespace management");
        return;
    }
    if (!strcmp(value, "retire")) {
        n->test_ns_seed = true;
    } else if (!strcmp(value, "changed-list-full")) {
        /* The controller's slot limit cannot fill a 1,024-entry log. */
        n->changed_ns_count = ARRAY_SIZE(n->changed_nsids);
        for (uint32_t i = 0; i < n->changed_ns_count; i++) {
            n->changed_nsids[i] = i + 2;
        }
    } else if (!strcmp(value, "fail-create")) {
        n->test_ns_fail = true;
    } else if (!strcmp(value, "check-erased") && !n->sq[0]) {
        const uint8_t *bytes = n->mbe->logical_space;

        /* A create would erase this extent and conceal a failed sanitize. */
        for (uint64_t i = 0; i < n->mbe->size; i++) {
            if (bytes[i]) {
                error_setg(errp, "backend still contains data at %" PRIu64, i);
                return;
            }
        }
    } else {
        error_setg(errp, "unknown namespace fixture");
    }
}

/* The FTL's mapping of namespace 1 against its media; see ssd_check_mapping */
static char *femu_test_ftl_check(Object *obj, Error **errp)
{
    FemuCtrl *n = FEMU(obj);
    NvmeNamespace *ns = nvme_ns(n, 1);
    uint64_t mapped;
    uint64_t lost;
    uint64_t orphans;
    bool resume;

    if (!ns || !NS_BBSSD(ns) || !ns->ssd) {
        error_setg(errp, "FTL check requires a bbssd namespace 1");
        return NULL;
    }
    resume = nvme_pause_pollers(n);
    ssd_check_mapping(ns->ssd, &mapped, &lost, &orphans);
    nvme_resume_pollers(n, resume);
    return g_strdup_printf("%" PRIu64 " %" PRIu64 " %" PRIu64,
                           mapped, lost, orphans);
}

static void femu_test_oc12_clock(Object *obj, bool value, Error **errp)
{
    FemuCtrl *n = FEMU(obj);

    if (n->femu_mode != FEMU_OCSSD_MODE || n->lver != 1 || n->sq[0]) {
        error_setg(errp, "test clock requires a disabled OC 1.2 controller");
        return;
    }
    n->test_oc12_clock = value;
}

/* A cut resets command state; the caller must enable the controller again. */
static void femu_simulate_power_loss(Object *obj, bool value, Error **errp)
{
    FemuCtrl *n = FEMU(obj);

    if (!n->power_loss || !DEVICE(obj)->realized) {
        error_setg(errp, "simulated power loss requires a realized "
                   "power_loss device");
        return;
    }
    if (!value) {
        return;
    }
    nvme_clear_ctrl(n, false);
    for (uint32_t i = 0; i < n->namespace_limit; i++) {
        if (n->namespaces[i].allocated) {
            bbssd_power_loss(&n->namespaces[i]);
        }
    }
    n->bar.csts = 0;
    if (n->unsafe_shutdowns[0] != UINT64_MAX ||
        n->unsafe_shutdowns[1] != UINT64_MAX) {
        if (++n->unsafe_shutdowns[0] == 0) {
            n->unsafe_shutdowns[1]++;
        }
    }
    nvme_timestamp_set(n, 0, 0);
    n->clr_ms = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
    femu_pel_reset(n);
    femu_pel_power_loss(n);
}

static void femu_instance_init(Object *obj)
{
    object_property_add_bool(obj, "simulate-power-loss", NULL,
                             femu_simulate_power_loss);
    femu_ctrl_describe_runtime(obj);
    if (qtest_enabled()) {
        object_property_add_bool(obj, "x-oc12-clock", NULL,
                                 femu_test_oc12_clock);
        object_property_add_str(obj, "x-stream-test", nvme_streams_test, NULL);
        object_property_add_str(obj, "x-ns-test", NULL, femu_test_namespace);
        object_property_add_str(obj, "x-ftl-check", femu_test_ftl_check, NULL);
    }
}

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
    femu_ctrl_describe_props(oc);
    dc->vmsd = &femu_vmstate;
}

static const TypeInfo femu_info = {
    .name          = "femu",
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(FemuCtrl),
    .class_init    = femu_class_init,
    .instance_init = femu_instance_init,
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
