/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Device side of the CCA rings. It keeps its own cursors and reads each
 * shared index once, so nothing the guest writes can move an access
 * outside the RAM it was given. No QEMU dependency: the ring unit test
 * links this file directly.
 */
#ifndef FEMU_CXL_CCA_RING_H
#define FEMU_CXL_CCA_RING_H

#include <stdbool.h>
#include "cca-abi.h"

typedef struct CcaRingHost {
    uint8_t *shm;                   /* CCA_SHM_SIZE bytes */
    uint32_t req_tail;
    uint32_t resp_head;
    uint32_t fatal;                 /* CCA_FATAL_* or 0 */
} CcaRingHost;

void cca_ring_format(CcaRingHost *h, uint8_t *shm);
int cca_ring_pop(CcaRingHost *h, uint32_t *slot, struct cca_ctrl_cmd_s *cmd);
bool cca_ring_complete(CcaRingHost *h, uint32_t slot,
                       const struct cca_ctrl_resp_s *resp);

#endif
