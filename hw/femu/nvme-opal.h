/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * The data path side of x-opal (nvme-opal.c), between the NVMe layer and
 * the TCG engine (femu-opal.c).
 */

#ifndef NVME_OPAL_H
#define NVME_OPAL_H

#include "nvme.h"
#include "femu-opal.h"

void femu_opal_start(FemuCtrl *n, FemuOpalCfg *cfg);
void femu_opal_stop(FemuCtrl *n);
void femu_opal_publish(FemuCtrl *n);
bool femu_opal_quiet(FemuCtrl *n, bool *resume);
void femu_opal_loud(FemuCtrl *n, bool resume);
FemuOpalIf femu_opal_quiet_send(FemuCtrl *n, uint8_t secp, uint16_t spsp,
                                const uint8_t *buf, uint32_t len,
                                bool *timeout);
bool femu_opal_io(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                  NvmeRequest *req, uint16_t *status);
uint64_t femu_opal_synth_lat(NvmeRequest *req);
bool femu_opal_format_ok(FemuCtrl *n);
bool femu_opal_owned(FemuCtrl *n);

#endif
