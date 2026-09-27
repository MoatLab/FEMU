/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "nvme.h"

uint16_t nvme_directive(FemuCtrl *n, NvmeCmd *cmd, NvmeCqe *cqe)
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
    bool resume;
    uint32_t i;

    if (nsid != NVME_NSID_BROADCAST && !ns) {
        return NVME_INVALID_NSID | NVME_DNR;
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
    resume = nvme_pause_pollers(n);
    for (i = 0; i < n->namespace_limit; i++) {
        NvmeNamespace *target = nvme_ns(n, i + 1);

        if (target && (!ns || target == ns)) {
            target->streams_enabled = dw12 & 1;
        }
    }
    nvme_resume_pollers(n, resume);
    return NVME_SUCCESS;
}
