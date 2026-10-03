/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * What the controller says it handles. The Commands Supported and Effects log,
 * the Supported Log Pages log and the Identify Controller fields that sum them
 * up are all built from the functions here, and the dispatch of the optional
 * commands asks the same functions. The caps qtests check the result against
 * what every mode actually answers.
 */

#include "./nvme.h"

static const uint32_t nvme_cse_acs[256] = {
    [NVME_ADM_CMD_DELETE_SQ]        = NVME_CMD_EFF_CSUPP,
    [NVME_ADM_CMD_CREATE_SQ]        = NVME_CMD_EFF_CSUPP,
    [NVME_ADM_CMD_GET_LOG_PAGE]     = NVME_CMD_EFF_CSUPP,
    [NVME_ADM_CMD_DELETE_CQ]        = NVME_CMD_EFF_CSUPP,
    [NVME_ADM_CMD_CREATE_CQ]        = NVME_CMD_EFF_CSUPP,
    [NVME_ADM_CMD_IDENTIFY]         = NVME_CMD_EFF_CSUPP,
    [NVME_ADM_CMD_ABORT]            = NVME_CMD_EFF_CSUPP,
    [NVME_ADM_CMD_SET_FEATURES]     = NVME_CMD_EFF_CSUPP,
    [NVME_ADM_CMD_GET_FEATURES]     = NVME_CMD_EFF_CSUPP,
    [NVME_ADM_CMD_ASYNC_EV_REQ]     = NVME_CMD_EFF_CSUPP,
    [NVME_ADM_CMD_DEV_SELF_TEST]    = NVME_CMD_EFF_CSUPP,
    [NVME_ADM_CMD_SET_DB_MEMORY]    = NVME_CMD_EFF_CSUPP,
    [NVME_ADM_CMD_GET_LBA_STATUS]   = NVME_CMD_EFF_CSUPP,
};

/* the commands each command set always has; the optional ones are below */
static const uint32_t nvme_cse_iocs_nvm[256] = {
    [NVME_CMD_FLUSH]                = NVME_CMD_EFF_CSUPP | NVME_CMD_EFF_LBCC,
    [NVME_CMD_WRITE]                = NVME_CMD_EFF_CSUPP | NVME_CMD_EFF_LBCC,
    [NVME_CMD_READ]                 = NVME_CMD_EFF_CSUPP,
};

static const uint32_t nvme_cse_iocs_zoned[256] = {
    [NVME_CMD_FLUSH]                = NVME_CMD_EFF_CSUPP | NVME_CMD_EFF_LBCC,
    [NVME_CMD_WRITE]                = NVME_CMD_EFF_CSUPP | NVME_CMD_EFF_LBCC,
    [NVME_CMD_READ]                 = NVME_CMD_EFF_CSUPP,
    [NVME_CMD_ZONE_APPEND]          = NVME_CMD_EFF_CSUPP | NVME_CMD_EFF_LBCC,
    [NVME_CMD_ZONE_MGMT_SEND]       = NVME_CMD_EFF_CSUPP | NVME_CMD_EFF_LBCC,
    [NVME_CMD_ZONE_MGMT_RECV]       = NVME_CMD_EFF_CSUPP,
};

/*
 * The Key Value command set. A key is not a logical block, so the commands
 * that replace or remove a value are the ones that change what a read returns.
 */
static const uint32_t nvme_cse_iocs_kv[256] = {
    [NVME_KV_CMD_STORE]             = NVME_CMD_EFF_CSUPP | NVME_CMD_EFF_LBCC,
    [NVME_KV_CMD_RETRIEVE]          = NVME_CMD_EFF_CSUPP,
    [NVME_KV_CMD_LIST]              = NVME_CMD_EFF_CSUPP,
    [NVME_KV_CMD_DELETE]            = NVME_CMD_EFF_CSUPP | NVME_CMD_EFF_LBCC,
    [NVME_KV_CMD_EXIST]             = NVME_CMD_EFF_CSUPP,
};

uint32_t nvme_admin_effects(FemuCtrl *n, uint8_t opc)
{
    switch (opc) {
    case NVME_ADM_CMD_FORMAT_NVM:
        return n->oacs & NVME_OACS_FORMAT ?
               NVME_CMD_EFF_CSUPP | NVME_CMD_EFF_LBCC | NVME_CMD_EFF_NCC : 0;
    case NVME_ADM_CMD_SANITIZE:
        return nvme_can_sanitize(n) ?
               NVME_CMD_EFF_CSUPP | NVME_CMD_EFF_LBCC : 0;
    case NVME_ADM_CMD_NS_MGMT:
        return nvme_ns_mgmt_supported(n) ?
               NVME_CMD_EFF_CSUPP | NVME_CMD_EFF_LBCC | NVME_CMD_EFF_NIC : 0;
    case NVME_ADM_CMD_NS_ATTACHMENT:
        return nvme_ns_mgmt_supported(n) ?
               NVME_CMD_EFF_CSUPP | NVME_CMD_EFF_NIC : 0;
    case NVME_ADM_CMD_DIRECTIVE_SEND:
    case NVME_ADM_CMD_DIRECTIVE_RECV:
        return n->streams ? NVME_CMD_EFF_CSUPP : 0;
    default:
        return nvme_cse_acs[opc];
    }
}

/*
 * The optional commands, each turned on by its ONCS bit. Key value namespaces
 * have none of them. Dataset Management, Write Zeroes, Copy and Write
 * Uncorrectable change logical blocks without going through the zone state
 * machine, so zoned namespaces refuse them.
 */
static uint32_t nvme_optional_effects(FemuCtrl *n, uint8_t csi, uint8_t opc,
                                      bool *optional)
{
    bool nvm = csi == NVME_CSI_NVM;
    uint16_t bit;
    uint32_t eff = NVME_CMD_EFF_CSUPP | NVME_CMD_EFF_LBCC;

    *optional = true;
    switch (opc) {
    case NVME_CMD_COMPARE:
        bit = NVME_ONCS_COMPARE;
        nvm |= csi == NVME_CSI_ZONED;
        eff = NVME_CMD_EFF_CSUPP;
        break;
    case NVME_CMD_VERIFY:
        bit = NVME_ONCS_VERIFY;
        nvm |= csi == NVME_CSI_ZONED;
        eff = NVME_CMD_EFF_CSUPP;
        break;
    case NVME_CMD_DSM:
        bit = NVME_ONCS_DSM;
        break;
    case NVME_CMD_WRITE_ZEROES:
        bit = NVME_ONCS_WRITE_ZEROS;
        break;
    case NVME_CMD_COPY:
        bit = NVME_ONCS_COPY;
        break;
    case NVME_CMD_WRITE_UNCOR:
        bit = NVME_ONCS_WRITE_UNCORR;
        break;
    default:
        *optional = false;
        return 0;
    }

    return nvm && (n->oncs & bit) ? eff : 0;
}

uint32_t nvme_io_effects(FemuCtrl *n, uint8_t csi, uint8_t opc)
{
    bool optional;
    uint32_t eff = nvme_optional_effects(n, csi, opc, &optional);

    if (optional) {
        return eff;
    }

    switch (opc) {
    case NVME_CMD_IO_MGMT_RECV:
    case NVME_CMD_IO_MGMT_SEND:
        return csi == NVME_CSI_NVM && n->subsys &&
               n->subsys->endgrp.fdp.enabled ? NVME_CMD_EFF_CSUPP : 0;
    }

    switch (csi) {
    case NVME_CSI_NVM:
        return nvme_cse_iocs_nvm[opc];
    case NVME_CSI_ZONED:
        return nvme_cse_iocs_zoned[opc];
    case NVME_CSI_KV:
        return nvme_cse_iocs_kv[opc];
    default:
        return 0;
    }
}

static bool nvme_has_zoned_ns(FemuCtrl *n)
{
    for (int i = 0; n->namespaces && i < n->namespace_limit; i++) {
        if (n->namespaces[i].allocated && NS_ZNSSD(&n->namespaces[i])) {
            return true;
        }
    }
    return false;
}

/*
 * A page is listed only where it would really answer: the endurance group and
 * placement pages need a subsystem, and a command set's own pages are listed
 * for that command set only.
 */
uint32_t nvme_log_support(FemuCtrl *n, uint8_t csi, uint8_t lid)
{
    switch (lid) {
    case NVME_LOG_SUPPORTED:
    case NVME_LOG_ERROR_INFO:
    case NVME_LOG_SMART_INFO:
    case NVME_LOG_FW_SLOT_INFO:
    case NVME_LOG_CMD_EFFECTS:
    case NVME_LOG_DEV_SELF_TEST:
    case NVME_LOG_TELEMETRY_HOST:
    case NVME_LOG_TELEMETRY_CTRL:
    case NVME_LOG_LBA_STATUS:
    case NVME_LOG_FID_EFFECTS:
    case NVME_LOG_MI_EFFECTS:
    case NVME_LOG_FEMU_STATS:
        return NVME_LIDS_LSUPP;
    case NVME_LOG_PERSISTENT_EVENT:
        /* its LID specific parameter: Establish Context and Read Header */
        return NVME_LIDS_LSUPP | 1 << 16;
    case NVME_LOG_CHANGED_NS_LIST:
        return nvme_ns_mgmt_supported(n) ? NVME_LIDS_LSUPP : 0;
    case NVME_LOG_SANITIZE:
        return nvme_can_sanitize(n) ? NVME_LIDS_LSUPP : 0;
    case NVME_LOG_ENDGRP:
        return n->subsys ? NVME_LIDS_LSUPP : 0;
    case NVME_LOG_FDP_CONFS:
    case NVME_LOG_FDP_RUH_USAGE:
    case NVME_LOG_FDP_STATS:
    case NVME_LOG_FDP_EVENTS:
        /* the placement pages answer only while placement is on */
        return n->subsys && n->subsys->endgrp.fdp.enabled ?
               NVME_LIDS_LSUPP : 0;
    case NVME_LOG_CHANGED_ZONE_LIST:
        return csi == NVME_CSI_ZONED && nvme_has_zoned_ns(n) ?
               NVME_LIDS_LSUPP : 0;
    default:
        return 0;
    }
}

/*
 * The Identify Controller fields that sum up the logs: OACS from the admin
 * commands, ONCS and OCFS from the NVM command set, LPA from the log pages and
 * SANICAP from Sanitize.
 */
void nvme_caps_id_ctrl(FemuCtrl *n, NvmeIdCtrl *id)
{
    static const struct {
        uint8_t opc;
        uint16_t bit;
    } oacs[] = {
        { NVME_ADM_CMD_SECURITY_SEND,   NVME_OACS_SECURITY },
        { NVME_ADM_CMD_FORMAT_NVM,      NVME_OACS_FORMAT },
        { NVME_ADM_CMD_DOWNLOAD_FW,     NVME_OACS_FW },
        { NVME_ADM_CMD_NS_MGMT,         NVME_OACS_NS_MGMT },
        { NVME_ADM_CMD_DEV_SELF_TEST,   NVME_OACS_DST },
        { NVME_ADM_CMD_DIRECTIVE_SEND,  NVME_OACS_DIRECTIVES },
        { NVME_ADM_CMD_SET_DB_MEMORY,   NVME_OACS_DBBUF },
        { NVME_ADM_CMD_GET_LBA_STATUS,  NVME_OACS_GLSS },
    }, oncs[] = {
        { NVME_CMD_COMPARE,             NVME_ONCS_COMPARE },
        { NVME_CMD_WRITE_UNCOR,         NVME_ONCS_WRITE_UNCORR },
        { NVME_CMD_DSM,                 NVME_ONCS_DSM },
        { NVME_CMD_WRITE_ZEROES,        NVME_ONCS_WRITE_ZEROS },
        { NVME_CMD_VERIFY,              NVME_ONCS_VERIFY },
        { NVME_CMD_COPY,                NVME_ONCS_COPY },
    };
    uint16_t a = 0;
    uint16_t o = n->oncs & NVME_ONCS_FEATURES;
    uint8_t lpa = NVME_LPA_NS_SMART | NVME_LPA_EXTENDED;
    int i;

    for (i = 0; i < ARRAY_SIZE(oacs); i++) {
        if (nvme_admin_effects(n, oacs[i].opc)) {
            a |= oacs[i].bit;
        }
    }
    for (i = 0; i < ARRAY_SIZE(oncs); i++) {
        if (nvme_io_effects(n, NVME_CSI_NVM, oncs[i].opc)) {
            o |= oncs[i].bit;
        }
    }
    if (nvme_fid_supported(n, NVME_TIMESTAMP)) {
        o |= NVME_ONCS_TIMESTAMP;
    }
    /* a Copy's write portion is one write here, so it is single-atomic */
    if (o & NVME_ONCS_COPY) {
        o |= NVME_ONCS_NVMCSA;
    }

    if (nvme_log_support(n, NVME_CSI_NVM, NVME_LOG_CMD_EFFECTS)) {
        lpa |= NVME_LPA_CSE;
    }
    if (nvme_log_support(n, NVME_CSI_NVM, NVME_LOG_TELEMETRY_HOST) &&
        nvme_log_support(n, NVME_CSI_NVM, NVME_LOG_TELEMETRY_CTRL)) {
        lpa |= NVME_LPA_TELEMETRY;
    }
    if (nvme_log_support(n, NVME_CSI_NVM, NVME_LOG_PERSISTENT_EVENT)) {
        lpa |= NVME_LPA_PERSISTENT_EVENT;
    }

    id->oacs = cpu_to_le16(a);
    id->oncs = cpu_to_le16(o);
    /* descriptor formats 0 and 2 (the latter names a source namespace) */
    id->ocfs = cpu_to_le16(o & NVME_ONCS_COPY ? 0x5 : 0);
    id->lpa = lpa;
    /* block erase only */
    id->sanicap = cpu_to_le32(nvme_admin_effects(n, NVME_ADM_CMD_SANITIZE) ?
                              1 << 1 : 0);
}
