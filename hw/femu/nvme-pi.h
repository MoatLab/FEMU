/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FEMU_NVME_PI_H
#define FEMU_NVME_PI_H

#include "nvme.h"

static inline uint8_t femu_pi_type(NvmeNamespace *ns)
{
    return ns->id_ns.dps & DPS_TYPE_MASK;
}

/* the 64-bit guard format (NVM 1.2, PIF 10b) on every PI format, pif=2 */
static inline bool femu_pi_64(NvmeNamespace *ns)
{
    return ns->ctrl && ns->ctrl->pif == 2;
}

/* the PI tuple: 8 bytes, or 16 with the 64-bit guard */
static inline uint16_t femu_pi_size(NvmeNamespace *ns)
{
    return femu_pi_64(ns) ? 16 : 8;
}

static inline uint16_t femu_pi_offset(NvmeNamespace *ns)
{
    return ns->id_ns.dps & DPS_FIRST_EIGHT ? 0 :
           nvme_ns_ms(ns) - femu_pi_size(ns);
}

/*
 * The expected initial reference tag: CDW14, and with the 64-bit guard
 * (48-bit tag, STS 0) CDW3 bits 15:0 above it.
 */
static inline uint64_t femu_pi_ref(NvmeNamespace *ns, NvmeRwCmd *rw)
{
    uint64_t ref = le32_to_cpu(rw->reftag);

    if (femu_pi_64(ns)) {
        ref |= (uint64_t)(le32_to_cpu(rw->cdw3) & 0xffff) << 32;
    }
    return ref;
}

uint16_t femu_pi_check_ref(NvmeNamespace *ns, uint16_t control,
                           uint64_t slba, uint64_t ref);
uint16_t femu_pi_check(NvmeNamespace *ns, const uint8_t *data,
                       const uint8_t *meta, uint32_t nlb, uint16_t control,
                       uint64_t slba, uint64_t ref, uint16_t app,
                       uint16_t mask);
void femu_pi_snapshot(NvmeNamespace *ns, uint64_t slba, uint32_t nlb,
                       uint8_t *data, uint8_t *meta);

void femu_pi_generate(NvmeNamespace *ns, const uint8_t *data, uint8_t *meta,
                       uint32_t nlb, uint64_t ref, uint16_t app);
uint16_t femu_pi_transfer(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                          uint8_t *data, uint8_t *meta, bool to_host);
uint16_t femu_pi_rw(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                    NvmeRequest *req);

uint16_t femu_pi_compare(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd);
uint16_t femu_pi_zeroes(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd);

uint16_t femu_pi_copy_compatible(NvmeNamespace *src, NvmeNamespace *dst,
                                 uint16_t read_control, uint16_t write_control);

#endif
