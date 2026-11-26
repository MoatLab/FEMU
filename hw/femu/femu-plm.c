/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * NVM Sets (Base 2.3, 3.2.2) for Predictable Latency Mode with plm=on.
 *
 * Predictable Latency Mode (8.1.20) works per NVM Set, and a set lives in
 * one Endurance Group, which FEMU reports only with a femu-subsys. So
 * plm=on gives one set, NVMSETID 1, in Endurance Group 1, over the one
 * bbssd FTL of the controller:
 *
 *   femu-subsys --- controller (rrl=on, plm=on)
 *                     namespace 1 --> NVM Set 1 --> Endurance Group 1
 *
 *   Identify Controller   CTRATT.NSETS, NSETIDMAX 1
 *   Identify Namespace    NVMSETID 1 (CNS 00h and 08h)
 *   CNS 04h               the NVM Set List: one entry
 *   Feature 12h           NVM Set scope: CDW11 NVMSETID must be 1
 *
 * With plm=off, none of this changes what the controller reports.
 */

#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "qapi/error.h"
#include "nvme.h"
#include "bbssd/ftl.h"

/* bytes of one NVM Set Attributes Entry (Figure 334) */
#define FEMU_PLM_SET_ENTRY  128

/**
 * femu_plm_check - validate plm at realize
 * @n: the controller
 * @errp: set on a refusal
 *
 * One namespace on one page-mapped bbssd FTL, with Read Recovery Levels
 * (8.1.20 needs them) and a femu-subsys (a set needs an Endurance Group).
 * The refused features keep GC state of their own, or change media work
 * outside the host commands; the later windows could not hold it back.
 */
bool femu_plm_check(FemuCtrl *n, Error **errp)
{
    const BbCtrlParams *p = &n->bb_params;
    const char *map = p->mapping_scheme;
    const char *tier = p->tier_mode;
    const char *why = NULL;

    if (!n->plm) {
        return true;
    }
    if (n->femu_mode != FEMU_BBSSD_MODE) {
        why = "a femu_mode other than 1";
    } else if (n->namespace_modes && n->namespace_modes[0]) {
        why = "namespace_modes";
    } else if (n->ns_mgmt || nvme_ns_shared(n)) {
        why = "managed or shared namespaces";
    } else if (n->subsys && n->subsys->endgrp.fdp.enabled) {
        why = "FDP";
    } else if (n->ocp) {
        why = "ocp";
    } else if (p->gc_pace) {
        why = "gc_pace";
    } else if (n->streams) {
        why = "streams";
    } else if (tier && *tier && strcmp(tier, "off")) {
        why = "tier_mode";
    } else if (n->cxl_dev) {
        why = "cxl_ssd";
    } else if (n->power_loss) {
        why = "power_loss";
    } else if (n->persist_file) {
        why = "persist_file";
    }
    if (why) {
        error_setg(errp, "femu: plm is not supported with %s", why);
        return false;
    }
    if (!n->rrl) {
        why = "rrl=on";
    } else if (!n->subsys) {
        why = "a femu-subsys";
    } else if (n->num_namespaces != 1) {
        why = "exactly one namespace";
    } else if (map && *map && strcmp(map, "page")) {
        why = "mapping=page";
    }
    if (why) {
        error_setg(errp, "femu: plm needs %s", why);
        return false;
    }
    return true;
}

/*
 * R4KRT, in 100 ns: one NAND page read and the channel time of 4 KiB, the
 * time of a lone 4 KiB read that meets no other work.
 */
static uint32_t femu_plm_r4krt(FemuCtrl *n, struct ssd *ssd)
{
    const BbCtrlParams *p = &n->bb_params;
    uint64_t page_b = (uint64_t)p->secs_per_pg * p->secsz;
    uint64_t t;

    if (!ssd || !page_b) {
        return 0;
    }
    t = (uint64_t)MAX(ssd->sp.pg_rd_lat, 0) +
        (uint64_t)MAX(ssd->sp.ch_xfer_lat, 0) * 4096 / page_b;
    return MIN(DIV_ROUND_UP(t, 100), UINT32_MAX);
}

/*
 * OWS in bytes: NOWS + 1 blocks. With no NOWS hint (perf_hints off) it is
 * 0h, which Figure 334 defines as not specified.
 */
static uint32_t femu_plm_ows(NvmeNamespace *ns)
{
    uint64_t nows = le16_to_cpu(ns->id_ns.nows);

    if (!nows) {
        return 0;
    }
    return MIN((nows + 1) << NVME_ID_NS_LBADS(ns), UINT32_MAX);
}

/**
 * femu_plm_nvmset_list - Identify CNS 04h, the NVM Set List
 * @n: the controller
 * @cmd: the Identify command
 *
 * The sets from NVMSETID CDW11 bits 15:0 on (Figure 332). Set 1 is the
 * only one, so a start of 0 or 1 lists it and a higher start lists none.
 * TNVMSC is the capacity of the one namespace, as TNVMCAP; with no
 * Namespace Management, UNVMSC is 0.
 */
uint16_t femu_plm_nvmset_list(FemuCtrl *n, NvmeCmd *cmd)
{
    uint8_t list[NVME_IDENTIFY_DATA_SIZE] = {};
    uint16_t start = le32_to_cpu(cmd->cdw11) & 0xffff;
    NvmeNamespace *ns = &n->namespaces[0];
    uint8_t *e = list + FEMU_PLM_SET_ENTRY;

    if (!n->plm) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (start <= FEMU_PLM_NVMSETID) {
        list[0] = 1;                                    /* NUMENT */
        stw_le_p(e, FEMU_PLM_NVMSETID);                 /* NSETID */
        stw_le_p(e + 2, 1);                             /* ENDGID */
        stl_le_p(e + 8, femu_plm_r4krt(n, ns->ssd));    /* R4KRT */
        stl_le_p(e + 12, femu_plm_ows(ns));             /* OWS */
        memcpy(e + 16, n->id_ctrl.tnvmcap, 16);         /* TNVMSC */
    }
    return dma_read_prp(n, list, sizeof(list), le64_to_cpu(cmd->dptr.prp1),
                        le64_to_cpu(cmd->dptr.prp2));
}
