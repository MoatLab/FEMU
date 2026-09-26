/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FEMU_NVME_PI_H
#define FEMU_NVME_PI_H

#include "nvme.h"

static inline uint8_t femu_pi_type(NvmeNamespace *ns)
{
    return ns->id_ns.dps & DPS_TYPE_MASK;
}

static inline uint16_t femu_pi_offset(NvmeNamespace *ns)
{
    return ns->id_ns.dps & DPS_FIRST_EIGHT ? 0 : nvme_ns_ms(ns) - 8;
}

uint16_t femu_pi_check_ref(NvmeNamespace *ns, uint16_t control,
                           uint64_t slba, uint32_t ref);
uint16_t femu_pi_check(NvmeNamespace *ns, const uint8_t *data,
                       const uint8_t *meta, uint32_t nlb, uint16_t control,
                       uint64_t slba, uint32_t ref, uint16_t app,
                       uint16_t mask);
void femu_pi_snapshot(NvmeNamespace *ns, uint64_t slba, uint32_t nlb,
                       uint8_t *data, uint8_t *meta);

void femu_pi_generate(NvmeNamespace *ns, const uint8_t *data, uint8_t *meta,
                       uint32_t nlb, uint32_t ref, uint16_t app);
uint16_t femu_pi_transfer(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                          uint8_t *data, uint8_t *meta, bool to_host);
uint16_t femu_pi_rw(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                    NvmeRequest *req);

uint16_t femu_pi_compare(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd);
uint16_t femu_pi_zeroes(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd);

uint16_t femu_pi_copy_compatible(NvmeNamespace *src, NvmeNamespace *dst,
                                 uint16_t read_control, uint16_t write_control);

#endif
