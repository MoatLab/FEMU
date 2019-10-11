/*
 * QEMU OpenChannel 2.0 Controller
 *
 * Copyright (c) 2019 CNEX Labs, Inc.
 *
 * Thank you to the following people for their contributions to the original
 * qemu-nvme (github.com/OpenChannelSSD/qemu-nvme) implementation.
 *
 *   Matias Bjørling <mb@lightnvm.io>
 *   Javier González <javier@javigon.com>
 *   Simon Andreas Frimann Lund <ocssd@safl.dk>
 *   Hans Holmberg <hans@owltronix.com>
 *   Jesper Devantier <contact@pseudonymous.me>
 *   Young Tack Jin <youngtack.jin@circuitblvd.com>
 *
 * This code is licensed under the GNU GPL v2 or later.
 */

#ifndef HW_NVME_OCSSD_H
#define HW_NVME_OCSSD_H

#include "block/ocssd.h"
#include "hw/block/nvme.h"
#include "hw/block/ocssd-ns.h"

#define OCSSD_MAX_VECTOR_COMMAND_LBAS 64
#define OCSSD_MAX_CHUNK_NOTIFICATIONS 64

#define TYPE_OCSSD "ocssd"
#define OCSSD(obj) \
        OBJECT_CHECK(OcssdCtrl, (obj), TYPE_OCSSD)

typedef struct OcssdCtrl {
    NvmeCtrl nvme;

    OcssdFeatureVal   features;

    uint64_t notifications_count;
    uint16_t notifications_index;
    uint16_t notifications_max;
    OcssdChunkNotification notifications[OCSSD_MAX_CHUNK_NOTIFICATIONS];
} OcssdCtrl;

static inline void ocssd_ns_optimal_addrf(OcssdAddrF *addrf, OcssdIdLBAF *lbaf)
{
    addrf->sec_offset = 0;
    addrf->chk_offset = lbaf->sec_len;
    addrf->pu_offset  = lbaf->sec_len + lbaf->chk_len;
    addrf->grp_offset = lbaf->sec_len + lbaf->chk_len + lbaf->pu_len;

    addrf->grp_mask = ((1 << lbaf->grp_len) - 1) << addrf->grp_offset;
    addrf->pu_mask  = ((1 << lbaf->pu_len)  - 1) << addrf->pu_offset;
    addrf->chk_mask = ((1 << lbaf->chk_len) - 1) << addrf->chk_offset;
    addrf->sec_mask = ((1 << lbaf->sec_len) - 1) << addrf->sec_offset;
}

#endif /* HW_NVME_OCSSD_H */
