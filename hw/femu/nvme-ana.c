/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Asymmetric Namespace Access reporting (Base 2.3, 8.1.1) with ana=on.
 *
 * Each namespace is its own ANA group, with the namespace ID as the group
 * ID. Each controller keeps the state of every group as seen through it,
 * which a multipath study changes at run time:
 *
 *   qom-set <ctrl> ana-state "g:s"     s: 1 Optimized, 2 Non-Optimized,
 *                                         3 Inaccessible, 4 Persistent Loss
 *     --> log 0Ch changes (Change Counts move), and the ANA Change notice
 *         goes out if AEC bit 11 is set
 *   I/O to group g: Inaccessible --> 302h, Persistent Loss --> 301h
 *   Persistent Loss is final for the group through this controller
 *
 * Open gaps: admin commands run in every state (Figure 622 restricts some),
 * and attach, detach and delete do not move the Change Counts.
 */

#include "./nvme.h"

#define ANA_OPTIMIZED       1
#define ANA_PERSISTENT_LOSS 4

QEMU_BUILD_BUG_ON(offsetof(NvmeIdNs, anagrpid) != 92);
QEMU_BUILD_BUG_ON(offsetof(NvmeIdCtrl, anatt) != 342);
QEMU_BUILD_BUG_ON(offsetof(NvmeIdCtrl, nanagrpid) != 348);

bool nvme_ana_check_props(FemuCtrl *n, Error **errp)
{
    for (int i = 0; i < NVME_MAX_NAMESPACES; i++) {
        n->ana_state[i] = ANA_OPTIMIZED;
        n->ana_gchgc[i] = 1;
    }
    /* every controller of a subsystem reports ANA alike (Figure 328) */
    for (int i = 0; n->subsys && i < NVME_MAX_CONTROLLERS; i++) {
        FemuCtrl *c = n->subsys->ctrls[i];

        if (c && c != n && c->ana != n->ana) {
            error_setg(errp, "ana must be the same on every controller of a "
                       "femu-subsys");
            return false;
        }
    }
    return true;
}

void nvme_ana_id(FemuCtrl *n, NvmeIdCtrl *id)
{
    if (!n->ana) {
        return;
    }
    id->cmic |= 1 << 3;
    id->anatt = 10;
    id->anacap = 0x0f;          /* Optimized to Persistent Loss */
    id->anagrpmax = cpu_to_le32(n->namespace_limit);
    id->nanagrpid = cpu_to_le32(n->namespace_limit);
    id->oaes |= cpu_to_le32(NVME_AEC_ANA_CHANGE);
}

/* the group of a namespace, in its Identify Namespace data */
void nvme_ana_ns(FemuCtrl *n, NvmeNamespace *ns)
{
    if (n->ana) {
        ns->id_ns.anagrpid = cpu_to_le32(ns->id);
    }
}

/* the status of an I/O command to @ns through @n */
uint16_t nvme_ana_io_check(FemuCtrl *n, NvmeNamespace *ns)
{
    switch (qatomic_read(&n->ana_state[ns->id - 1])) {
    case 3:
        return NVME_ANA_INACCESSIBLE;
    case ANA_PERSISTENT_LOSS:
        return NVME_ANA_PERSISTENT_LOSS;
    default:
        return NVME_SUCCESS;
    }
}

/*
 * Log 0Ch (Figure 227): one descriptor per group with a namespace attached
 * to this controller, in ascending order. LSP bit 0 (RGO) leaves out the
 * namespace lists. A read without RAE clears the ANA Change event.
 */
uint16_t nvme_ana_log(FemuCtrl *n, NvmeCmd *cmd, uint32_t len, uint64_t off,
                      bool rae)
{
    bool rgo = (le32_to_cpu(cmd->cdw10) >> 8) & 0x1;
    g_autofree uint8_t *log = NULL;
    size_t size = 16;
    size_t p = 16;
    uint16_t ngrp = 0;
    uint16_t status;

    for (uint32_t i = 1; n->namespaces && i <= n->namespace_limit; i++) {
        if (nvme_ns(n, i)) {
            size += 32 + (rgo ? 0 : 4);
        }
    }
    if (off > size) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    log = g_malloc0(size);
    stq_le_p(log, n->ana_chgc);
    for (uint32_t i = 1; n->namespaces && i <= n->namespace_limit; i++) {
        if (!nvme_ns(n, i)) {
            continue;
        }
        stl_le_p(log + p, i);
        stl_le_p(log + p + 4, rgo ? 0 : 1);
        stq_le_p(log + p + 8, n->ana_gchgc[i - 1]);
        log[p + 16] = qatomic_read(&n->ana_state[i - 1]);
        p += 32;
        if (!rgo) {
            stl_le_p(log + p, i);
            p += 4;
        }
        ngrp++;
    }
    stw_le_p(log + 8, ngrp);

    status = dma_read_prp(n, log + off, MIN(size - off, len),
                          le64_to_cpu(cmd->dptr.prp1),
                          le64_to_cpu(cmd->dptr.prp2));
    if (!status && !rae) {
        n->ana_pending = false;
        nvme_clear_ns_events(n, NVME_AER_TYPE_NOTICE, NVME_LOG_ANA, 0, true);
        qemu_bh_schedule(n->aer_bh);
    }
    return status;
}

/* Controller Level Reset: the counts restart; the path states stay */
void nvme_ana_reset(FemuCtrl *n)
{
    n->ana_chgc = 0;
    n->ana_pending = false;
    for (int i = 0; i < NVME_MAX_NAMESPACES; i++) {
        n->ana_gchgc[i] = 1;
    }
}

static char *nvme_ana_state_get(Object *obj, Error **errp)
{
    FemuCtrl *n = FEMU(obj);
    GString *out = g_string_new("");

    for (uint32_t i = 1; n->namespaces && i <= n->namespace_limit; i++) {
        if (nvme_ns_allocated(n, i)) {
            g_string_append_printf(out, "%s%u:%u", out->len ? " " : "", i,
                                   qatomic_read(&n->ana_state[i - 1]));
        }
    }
    return g_string_free(out, false);
}

/* "g:s": the state of group g through this controller becomes s */
static void nvme_ana_state_set(Object *obj, const char *value, Error **errp)
{
    FemuCtrl *n = FEMU(obj);
    unsigned int g;
    unsigned int s;

    if (!n->ana || !DEVICE(obj)->realized) {
        error_setg(errp, "ana-state needs a realized controller with ana=on");
        return;
    }
    if (sscanf(value, "%u:%u", &g, &s) != 2 || !g ||
        g > n->namespace_limit || s < ANA_OPTIMIZED ||
        s > ANA_PERSISTENT_LOSS || !nvme_ns_allocated(n, g)) {
        error_setg(errp, "ana-state takes \"group:state\", a group of an "
                   "allocated namespace and a state 1 to 4");
        return;
    }
    if (qatomic_read(&n->ana_state[g - 1]) == s) {
        return;
    }
    /* nothing leaves Persistent Loss (8.1.1.7) */
    if (qatomic_read(&n->ana_state[g - 1]) == ANA_PERSISTENT_LOSS) {
        error_setg(errp, "ana-state: group %u is in Persistent Loss", g);
        return;
    }
    /* pollers read the state; they see the old or the new one whole */
    qatomic_set(&n->ana_state[g - 1], s);
    n->ana_pending = true;
    n->ana_chgc++;                      /* FFFFFFFF_FFFFFFFFh rolls to 0 */
    if (++n->ana_gchgc[g - 1] == 0) {
        n->ana_gchgc[g - 1] = 1;
    }
    if (n->features.async_config & NVME_AEC_ANA_CHANGE) {
        nvme_enqueue_event(n, NVME_AER_TYPE_NOTICE, NVME_AER_INFO_ANA_CHANGE,
                           NVME_LOG_ANA);
    }
}

void nvme_ana_add_props(Object *obj)
{
    object_property_add_str(obj, "ana-state", nvme_ana_state_get,
                            nvme_ana_state_set);
}
