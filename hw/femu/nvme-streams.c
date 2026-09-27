/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "nvme.h"
#include "bbssd/ftl.h"

/* Callers either hold streams_lock or have stopped the dataplane. */
static void nvme_stream_close(FemuCtrl *n, unsigned slot)
{
    n->stream_slots[slot].nsid = 0;
    n->stream_slots[slot].sid = 0;
}

void nvme_streams_release(NvmeNamespace *ns, bool resources)
{
    FemuCtrl *n = ns->ctrl;
    unsigned i;

    if (!n || !n->streams) {
        return;
    }
    for (i = 0; i < n->streams_max; i++) {
        if (n->stream_slots[i].nsid == ns->id) {
            nvme_stream_close(n, i);
        }
    }
    if (resources) {
        ns->streams_allocated = 0;
    }
}

static unsigned nvme_streams_available(FemuCtrl *n)
{
    unsigned available = n->streams_max;
    unsigned i;

    for (i = 0; i < n->namespace_limit; i++) {
        available -= n->namespaces[i].streams_allocated;
    }
    return available;
}

static unsigned nvme_streams_count(FemuCtrl *n, NvmeNamespace *ns)
{
    unsigned count = 0;
    unsigned i;

    for (i = 0; i < n->streams_max; i++) {
        NvmeNamespace *owner = nvme_ns_allocated(n, n->stream_slots[i].nsid);

        if (owner && (ns ? owner == ns : !owner->streams_allocated)) {
            count++;
        }
    }
    return count;
}

static uint16_t nvme_streams_receive(FemuCtrl *n, NvmeNamespace *ns,
                                   NvmeCmd *cmd, NvmeCqe *cqe)
{
    uint8_t operation = le32_to_cpu(cmd->cdw11);
    uint16_t requested = le32_to_cpu(cmd->cdw12);
    uint8_t params[32] = { 0 };
    g_autofree uint16_t *status = NULL;
    unsigned available = nvme_streams_available(n);
    uint64_t len = ((uint64_t)le32_to_cpu(cmd->cdw10) + 1) * 4;
    void *buf = params;
    unsigned size = sizeof(params);
    unsigned count = 0;
    unsigned i;
    unsigned j;

    switch (operation) {
    case 1:
        stw_le_p(params, n->streams_max);
        stw_le_p(params + 2, available);
        stw_le_p(params + 4, nvme_streams_count(n, NULL));
        if (ns) {
            uint32_t sws = 1;
            uint16_t sgs = 1;

            /* NoSSD accepts Streams but has no physical placement effect. */
            if (NS_BBSSD(ns)) {
                struct ssdparams *sp = &ns->ssd->sp;

                sws = MAX(1, (sp->secs_per_pg * sp->secsz) >> ns->lbaf.lbads);
                sgs = sp->pgs_per_line;
            }
            stl_le_p(params + 16, sws);
            stw_le_p(params + 20, sgs);
            stw_le_p(params + 22, ns->streams_allocated);
            stw_le_p(params + 24, nvme_streams_count(n, ns));
        }
        break;
    case 2:
        status = g_new0(uint16_t, 65536);
        for (i = 0; i < n->streams_max; i++) {
            NvmeNamespace *owner =
                nvme_ns_allocated(n, n->stream_slots[i].nsid);
            uint16_t sid = n->stream_slots[i].sid;

            if (!owner || (ns ? owner != ns : owner->streams_allocated)) {
                continue;
            }
            for (j = 1; j <= count && status[j] < sid; j++) {
                ;
            }
            if (j <= count && status[j] == sid) {
                continue;
            }
            memmove(&status[j + 1], &status[j],
                    (count + 1 - j) * sizeof(status[0]));
            status[j] = sid;
            count++;
        }
        status[0] = count;
        for (i = 0; i <= count; i++) {
            status[i] = cpu_to_le16(status[i]);
        }
        buf = status;
        size = 131072;
        break;
    case 3:
        if (!ns || ns->streams_allocated) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        if (!available) {
            return 0x17f;
        }
        if (requested) {
            nvme_streams_release(ns, false);
            ns->streams_allocated = MIN(requested, available);
            available -= ns->streams_allocated;
            /* Exclusive reservations take precedence over shared resources. */
            for (i = 0; i < n->streams_max &&
                        nvme_streams_count(n, NULL) > available; i++) {
                NvmeNamespace *owner =
                    nvme_ns_allocated(n, n->stream_slots[i].nsid);

                if (owner && !owner->streams_allocated) {
                    nvme_stream_close(n, i);
                }
            }
        }
        cqe->n.result = cpu_to_le32(ns->streams_allocated);
        return NVME_SUCCESS;
    default:
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    return dma_read_prp(n, buf, MIN(len, size),
                        le64_to_cpu(cmd->dptr.prp1),
                        le64_to_cpu(cmd->dptr.prp2));
}

static uint16_t nvme_directive_locked(FemuCtrl *n, NvmeCmd *cmd, NvmeCqe *cqe)
{
    uint32_t nsid = le32_to_cpu(cmd->nsid);
    uint32_t dw11 = le32_to_cpu(cmd->cdw11);
    uint32_t dw12 = le32_to_cpu(cmd->cdw12);
    uint8_t dtype = dw11 >> 8;
    uint8_t operation = dw11;
    bool receive = cmd->opcode == NVME_ADM_CMD_DIRECTIVE_RECV;
    NvmeNamespace *ns = nvme_ns(n, nsid);
    uint8_t params[4096] = { 0 };
    uint64_t len = ((uint64_t)le32_to_cpu(cmd->cdw10) + 1) * 4;
    uint32_t i;

    if (nsid != NVME_NSID_BROADCAST && !ns) {
        return NVME_INVALID_NSID | NVME_DNR;
    }
    if (dtype == 1) {
        bool enabled = ns && ns->streams_enabled;

        if (!ns) {
            for (i = 0; i < n->namespace_limit; i++) {
                enabled |= n->namespaces[i].streams_enabled;
            }
        }
        if (!enabled) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        if (receive) {
            return nvme_streams_receive(n, ns, cmd, cqe);
        }
        if (!ns) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        if (operation == 1) {
            for (i = 0; i < n->streams_max; i++) {
                if (n->stream_slots[i].nsid == nsid &&
                    n->stream_slots[i].sid == (dw11 >> 16)) {
                    nvme_stream_close(n, i);
                }
            }
        } else if (operation == 2) {
            if (ns->streams_allocated) {
                nvme_streams_release(ns, true);
            }
        } else {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        return NVME_SUCCESS;
    }
    if (dtype || operation != 1 || (receive && !ns)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (receive) {
        params[0] = 3;
        params[32] = ns->streams_enabled ? 3 : 1;
        return dma_read_prp(n, params, MIN(len, sizeof(params)),
                            le64_to_cpu(cmd->dptr.prp1),
                            le64_to_cpu(cmd->dptr.prp2));
    }
    if (((dw12 >> 8) & 0xff) != 1) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    for (i = 0; i < n->namespace_limit; i++) {
        NvmeNamespace *target = nvme_ns(n, i + 1);

        if (target && (!ns || target == ns)) {
            if (!(dw12 & 1)) {
                nvme_streams_release(target, true);
            }
            target->streams_enabled = dw12 & 1;
        }
    }
    return NVME_SUCCESS;
}

uint16_t nvme_directive(FemuCtrl *n, NvmeCmd *cmd, NvmeCqe *cqe)
{
    bool resume = nvme_pause_pollers(n);
    uint16_t status = nvme_directive_locked(n, cmd, cqe);

    nvme_resume_pollers(n, resume);
    return status;
}
