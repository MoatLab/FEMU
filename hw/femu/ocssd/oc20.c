#include "./oc20.h"

static inline bool is_oc20_admin_cmd(uint8_t opcode)
{
    return (opcode == OC20_ADM_CMD_IDENTIFY ||
            opcode == OC20_ADM_CMD_SET_LOG_PAGE);
}

static uint16_t oc20_dma_read(FemuCtrl *n, uint8_t *ptr, uint32_t len,
                              NvmeCmd *cmd)
{
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);

    return dma_read_prp(n, ptr, len, prp1, prp2);
}

static uint16_t oc20_dma_write(FemuCtrl *n, uint8_t *ptr, uint32_t len,
                               NvmeCmd *cmd)
{
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);

    return dma_write_prp(n, ptr, len, prp1, prp2);
}

#ifdef DEBUG_OC20
static int oc20_lba_str(char *buf, FemuCtrl *n, NvmeNamespace *ns, uint64_t lba)
{
    Oc20Namespace *lns = ns->state;
    Oc20AddrF *addrf = &lns->lbaf;

    uint8_t pugrp, punit;
    uint16_t chunk;
    uint32_t sectr;

    pugrp = OC20_LBA_GET_GROUP(addrf, lba);
    punit = OC20_LBA_GET_PUNIT(addrf, lba);
    chunk = OC20_LBA_GET_CHUNK(addrf, lba);
    sectr = OC20_LBA_GET_SECTR(addrf, lba);

    return sprintf(buf, "lba 0x%016"PRIx64" pugrp %"PRIu8" punit %"PRIu8
                   " chunk %"PRIu16" sectr %"PRIu32, lba, pugrp, punit, chunk,
                   sectr);
}
#endif

#ifdef DEBUG_OC20
static void pr_lba(Oc20Namespace *lns, uint64_t lba)
{
    Oc20AddrF *addrf = &lns->lbaf;

    uint64_t grp = OC20_LBA_GET_SECTR(addrf, lba);
    uint64_t lun = OC20_LBA_GET_CHUNK(addrf, lba);
    uint64_t chk = OC20_LBA_GET_PUNIT(addrf, lba);
    uint64_t sec = OC20_LBA_GET_GROUP(addrf, lba);

    femu_log("LBA(0x%lx): ch(%lu), lun(%lu), blk(%lu), sec(%lu)\n", lba, grp,
             lun, chk, sec);
}
#endif

static uint16_t oc20_init_chunk_info(Oc20Namespace *lns)
{
    Oc20CS *cs = lns->chunk_info;
    int chunks = lns->id_ctrl.geo.num_chk;
    int punits = lns->id_ctrl.geo.num_lun;
    int sectors = lns->id_ctrl.geo.clba;
    int i;

    Oc20AddrF addrf = lns->lbaf;
    for (i = 0; i < lns->chks_total; i++) {
        cs[i].state = OC20_CHUNK_FREE;
        cs[i].type = OC20_CHUNK_TYPE_SEQ;
        cs[i].wear_index = 0;
        cs[i].slba = (i / (chunks * punits)) << addrf.grp_offset |
                     (i % (chunks * punits) / chunks) << addrf.lun_offset |
                     (i % chunks) << addrf.chk_offset;
        cs[i].cnlb = sectors;
        cs[i].wp = 0;
    }

    return NVME_SUCCESS;
}

static Oc20CS *oc20_chunk_get_state(FemuCtrl *n, NvmeNamespace *ns, uint64_t lba)
{
    Oc20Namespace *lns = ns->state;

    if (!oc20_lba_valid(n, ns, lba)) {
        return NULL;
    }

    return &lns->chunk_info[oc20_lba_to_chunk_index(n, ns, lba)];
}

static uint16_t oc20_advance_wp(FemuCtrl *n, NvmeNamespace *ns, uint64_t lba,
                                uint16_t nlb, NvmeRequest *req)
{
    Oc20CS *chunk_meta;

    chunk_meta = oc20_chunk_get_state(n, req->ns, lba);
    if (!chunk_meta) {
        return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }

    if (chunk_meta->type == OC20_CHUNK_TYPE_RAN) {
        /* do not modify the chunk state or write pointer for random chunks */
        return NVME_SUCCESS;
    }

    if (chunk_meta->state == OC20_CHUNK_FREE) {
        chunk_meta->state = OC20_CHUNK_OPEN;
    }

    if (chunk_meta->state != OC20_CHUNK_OPEN) {
        return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }

    if ((chunk_meta->wp += nlb) == chunk_meta->cnlb) {
        chunk_meta->state = OC20_CHUNK_CLOSED;
    }

    return NVME_SUCCESS;
}

/*
 * Given the LBA list within a command, get the statistics about the access
 * frequency to different NAND flash pages, this helps us later decide how much
 * latency to emulate for the entire command.
 *
 * Results are stored in @bucket and @n
 */
static void oc20_parse_lba_list(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                                NvmeRequest *req, Oc20AddrBucket *bucket,
                                int *nr)
{
    Oc20RwCmd *ocrw = (Oc20RwCmd *)cmd;
    Oc20Namespace *lns = ns->state;
    Oc20AddrF *addrf = &lns->lbaf;
    uint16_t nlb  = le16_to_cpu(ocrw->nlb) + 1;
    int max_sec_per_rq = 64;
    uint64_t cur_pg_addr, prev_pg_addr = ~(0ULL);
    int secs_idx = -1;
    uint64_t lba;
    int i;

    memset(bucket, 0, sizeof(Oc20AddrBucket) * max_sec_per_rq);
    for (i = 0; i < nlb; i++) {
        lba = ((uint64_t *)(req->slba))[i];
        cur_pg_addr = (lba & (~(lns->lbaf.sec_mask)));
        if (cur_pg_addr == prev_pg_addr) {
            /* Accessing another secotr in the same NAND page */
            bucket[secs_idx].cnt++;
        } else {
            /* Accessing a new NAND page addr */
            secs_idx++;
            bucket[secs_idx].cnt++;
            bucket[secs_idx].ch = OC20_LBA_GET_GROUP(addrf, lba);
            bucket[secs_idx].lun = OC20_LBA_GET_PUNIT(addrf, lba);
            bucket[secs_idx].pg = OC20_LBA_GET_SECTR(addrf, lba);

            prev_pg_addr = cur_pg_addr;
        }
    }

    *nr = secs_idx + 1;
}

static int oc20_advance_status(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                               NvmeRequest *req)
{
    Oc20Namespace *lns = ns->state;
    Oc20RwCmd *ocrw = (Oc20RwCmd *)cmd;
    uint8_t opcode = ocrw->opcode;
    uint16_t nlb = le16_to_cpu(ocrw->nlb) + 1;
    int ch, lun, lunid;
    int64_t io_done_ts = 0;
    int64_t total_time_need_to_emulate = 0;
    int64_t cur_time_need_to_emulate;
    int max_sec_per_rq = 64;
    int num_ch = lns->id_ctrl.geo.num_chk;
    int num_lun = lns->id_ctrl.geo.num_lun;
    Oc20AddrF *addrf = &lns->lbaf;
    int i;

    int64_t now = req->stime;
    uint64_t lba;

    /* Erase */
    if (opcode == OC20_CMD_VECT_ERASE) {
        /* FIXME: vector erase */
        for (i = 0; i < nlb; i++) {
            lba = ((uint64_t *)req->slba)[i];
            ch = OC20_LBA_GET_GROUP(addrf, lba);
            lun = OC20_LBA_GET_PUNIT(addrf, lba);
            lunid = ch * num_ch + lun;

            int64_t ts = advance_chip_timestamp(n, lunid, now, opcode, 0);
            if (ts > req->expire_time) {
                req->expire_time = ts;
            }
        }

        return 0;
    }

    int secs_idx = -1;
    int si = 0;
    int nb_secs_to_one_chip = 0;

    Oc20AddrBucket addr_bucket[max_sec_per_rq];
    oc20_parse_lba_list(n, ns, cmd, req, addr_bucket, &secs_idx);

    /* Read & Write */
    assert(opcode == NVME_CMD_READ || opcode == OC20_CMD_VECT_READ ||
           opcode == NVME_CMD_WRITE || opcode == OC20_CMD_VECT_WRITE);
    assert(secs_idx > 0);
    for (i = 0; i < secs_idx; i++) {
        lba = ((uint64_t *)(req->slba))[si];
        nb_secs_to_one_chip = addr_bucket[i].cnt;
        si += nb_secs_to_one_chip;

        ch = addr_bucket[i].ch;
        lun = addr_bucket[i].lun;
        lunid = ch * num_lun + lun;

        io_done_ts = 0;
        int64_t chnl_end_ts, chip_end_ts;
        if (req->is_write) {
            /* Write data needs to be transferred through the channel first */
            chnl_end_ts = advance_channel_timestamp(n, ch, now, opcode);
            /* Then issue NAND Program to the target flash chip */
            io_done_ts = advance_chip_timestamp(n, lunid, chnl_end_ts, opcode, 0);
        } else {
            chip_end_ts = advance_chip_timestamp(n, lunid, now, opcode, 0);
            io_done_ts = advance_channel_timestamp(n, ch, chip_end_ts, opcode);
        }

        /* Coperd: the time need to emulate is (io_done_ts - now) */
        cur_time_need_to_emulate = io_done_ts - now;
        if (cur_time_need_to_emulate > total_time_need_to_emulate) {
            total_time_need_to_emulate = cur_time_need_to_emulate;
        }
    }

    req->expire_time = now + total_time_need_to_emulate;

    return 0;
}

static uint16_t oc20_rw_check_chunk_write(FemuCtrl *n, NvmeCmd *cmd,
                                          uint64_t lba, uint32_t ws,
                                          NvmeRequest *req)
{
    NvmeNamespace *ns = req->ns;
    Oc20Namespace *lns = ns->state;

    Oc20CS *cnk = oc20_chunk_get_state(n, ns, lba);
    if (!cnk) {
        lba &= ~lns->lbaf.sec_mask;
        return NVME_WRITE_FAULT | NVME_DNR;
    }

    uint32_t start_sectr = lba & lns->lbaf.sec_mask;
    uint32_t end_sectr = start_sectr + ws;

    if (cnk->state & OC20_CHUNK_OFFLINE || cnk->state & OC20_CHUNK_CLOSED) {
        return NVME_WRITE_FAULT | NVME_DNR;
    }

    if (end_sectr > cnk->cnlb) {
        return NVME_WRITE_FAULT | NVME_DNR;
    }

    if (cnk->type == OC20_CHUNK_TYPE_RAN) {
        if (cnk->state != OC20_CHUNK_OPEN) {
            return NVME_WRITE_FAULT | NVME_DNR;
        }

        return NVME_SUCCESS;
    }

    /* Silent the ws vs. ws_min size check to make SPDK happy */
#if 0
    Oc20Params *params = &n->params.oc20;
    if (ws < params->ws_min || (ws % params->ws_min) != 0) {
        Oc20RwCmd *lrw = (Oc20RwCmd *)cmd;
        nvme_set_error_page(n, req->sq->sqid, req->cqe.cid,
                            NVME_INVALID_FIELD, offsetof(Oc20RwCmd, lbal),
                            lrw->lbal + req->nlb, req->ns->id);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
#endif

    if (start_sectr != cnk->wp) {
        return OC20_OUT_OF_ORDER_WRITE | NVME_DNR;
    }

    return NVME_SUCCESS;
}

static uint16_t oc20_rw_check_write_req(FemuCtrl *n, NvmeCmd *cmd,
                                        NvmeRequest *req)
{
    NvmeNamespace *ns = req->ns;
    Oc20Namespace *lns = ns->state;
    Oc20AddrF *addrf = &lns->lbaf;

    uint64_t lba = ((uint64_t *) req->slba)[0];
    uint64_t cidx = oc20_lba_to_chunk_index(n, ns, lba);
    uint32_t sectr = OC20_LBA_GET_SECTR(addrf, lba);
    uint16_t ws = 1;

    for (uint16_t i = 1; i < req->nlb; i++) {
        uint64_t next_cidx;
        uint64_t next_lba = ((uint64_t *) req->slba)[i];

        /* it is assumed that LBAs for different chunks are laid out
           contiguously and sorted with increasing addresses. */
        next_cidx = oc20_lba_to_chunk_index(n, ns, next_lba);
        if (cidx != next_cidx) {
            uint16_t err = oc20_rw_check_chunk_write(n, cmd, lba, ws, req);
            if (err) {
                return err;
            }

            lba = ((uint64_t *) req->slba)[i];
            cidx = next_cidx;
            sectr = OC20_LBA_GET_SECTR(addrf, lba);
            ws = 1;

            continue;
        }

        if (++sectr != OC20_LBA_GET_SECTR(addrf, next_lba)) {
            return OC20_OUT_OF_ORDER_WRITE | NVME_DNR;
        }

        ws++;
    }

    return oc20_rw_check_chunk_write(n, cmd, lba, ws, req);
}

static uint16_t oc20_rw_check_chunk_read(FemuCtrl *n, NvmeCmd *cmd,
                                         NvmeRequest *req, uint64_t lba)
{
    NvmeNamespace *ns = req->ns;
    Oc20Namespace *lns = ns->state;
    Oc20AddrF *addrf = &lns->lbaf;
    Oc20Params *params = &n->params.oc20;

    uint64_t sectr, mw_cunits, wp;
    uint8_t state;

    Oc20CS *cnk = oc20_chunk_get_state(n, req->ns, lba);
    if (!cnk) {
        return NVME_DULB;
    }

    sectr = OC20_LBA_GET_SECTR(addrf, lba);
    mw_cunits = params->mw_cunits;
    wp = cnk->wp;
    state = cnk->state;

    if (cnk->type == OC20_CHUNK_TYPE_RAN) {
        /* for OC20_CHUNK_TYPE_RAN it is sufficient to ensure that the chunk is
           OPEN and that we are reading a valid LBA */
        if (state != OC20_CHUNK_OPEN || sectr >= cnk->cnlb) {
            return NVME_DULB;
        }

        return NVME_SUCCESS;
    }

    if (state == OC20_CHUNK_CLOSED && sectr < wp) {
        return NVME_SUCCESS;
    }

    if (state == OC20_CHUNK_OPEN) {
        if (wp < mw_cunits) {
            return NVME_DULB;
        }

        if (sectr < (wp - mw_cunits)) {
            return NVME_SUCCESS;
        }
    }

    return NVME_DULB;
}

static uint16_t oc20_rw_check_read_req(FemuCtrl *n, NvmeCmd *cmd,
                                       NvmeRequest *req)
{
    uint16_t err;
    int i;

    for (i = 0; i < req->nlb; i++) {
        err = oc20_rw_check_chunk_read(n, cmd, req, ((uint64_t *) req->slba)[i]);
        if (err) {
            if (err & NVME_DULB) {
                req->predef |= (1 << i);
                continue;
            }

            return err;
        }
    }

    return NVME_SUCCESS;
}

static uint16_t oc20_rw_check_vector_req(FemuCtrl *n, NvmeCmd *cmd,
                                         NvmeRequest *req)
{
    if (req->is_write) {
        return oc20_rw_check_write_req(n, cmd, req);
    }

    return oc20_rw_check_read_req(n, cmd, req);
}

static uint16_t oc20_chunk_set_free(FemuCtrl *n, NvmeNamespace *ns,
                                    uint64_t lba, hwaddr mptr, NvmeRequest *req)
{
    Oc20Params *params = &n->params.oc20;
    Oc20Namespace *lns = ns->state;

    Oc20CS *chunk_meta;
    uint32_t resetfail_prob = 0;

    chunk_meta = oc20_chunk_get_state(n, ns, lba);
    if (!chunk_meta) {
        return OC20_INVALID_RESET | NVME_DNR;
    }

    if (lns->resetfail) {
        resetfail_prob = lns->resetfail[oc20_lba_to_chunk_index(n, ns, lba)];
    }

    if (resetfail_prob) {
        if ((rand() % 100) < resetfail_prob) {
            chunk_meta->state = OC20_CHUNK_OFFLINE;
            chunk_meta->wp = 0xffff;
            return OC20_INVALID_RESET | NVME_DNR;
        }
    }

    if (chunk_meta->state & OC20_CHUNK_RESETABLE) {
        switch (chunk_meta->state) {
        case OC20_CHUNK_FREE:
            if (!(params->mccap & OC20_PARAMS_MCCAP_MULTIPLE_RESETS)) {
                return OC20_INVALID_RESET | NVME_DNR;
            }
            break;
        case OC20_CHUNK_OPEN:
            if (!(params->mccap & OC20_PARAMS_MCCAP_EARLY_RESET)) {
                return OC20_INVALID_RESET | NVME_DNR;
            }
            break;
        }

        chunk_meta->state = OC20_CHUNK_FREE;
        chunk_meta->wear_index++;
        chunk_meta->wp = 0;

        if (mptr) {
            nvme_addr_write(n, mptr, chunk_meta, sizeof(*chunk_meta));
        }

        return NVME_SUCCESS;
    }

    return NVME_DNR | OC20_OFFLINE_CHUNK;
}

static uint16_t oc20_rw_check_req(FemuCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    Oc20RwCmd *rw = (Oc20RwCmd *) cmd;
    Oc20Params *params = &n->params.oc20;

    uint16_t err;
    uint16_t nlb  = le16_to_cpu(rw->nlb) + 1;
    uint64_t slba = le64_to_cpu(rw->lbal);
    int i;

    switch (rw->opcode) {
    case NVME_CMD_WRITE:
        if (nlb < params->ws_min || nlb % params->ws_min != 0) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }

        err = oc20_rw_check_chunk_write(n, cmd, slba, nlb, req);
        if (err) {
            return err;
        }
        break;
    case NVME_CMD_READ:
        for (i = 0; i < nlb; i++) {
            err = oc20_rw_check_chunk_read(n, cmd, req, slba + i);
            if (err) {
                if (err & NVME_DULB) {
                    req->predef = slba + i;
                    if (NVME_ERR_REC_DULBE(n->features.err_rec)) {
                        return NVME_DULB | NVME_DNR;
                    }

                    break;
                }

                return err;
            }
        }

        break;
    }

    return NVME_SUCCESS;
}

static unsigned get_unsigned(char *string, const char *key, unsigned int *value)
{
    char *keyvalue = strstr(string, key);
    if (!keyvalue) {
        return 0;
    }
    return sscanf(keyvalue + strlen(key), "%u", value);
}

static int get_ch_lun_chk(char *chunkinfo, unsigned int *grp, unsigned int *lun,
                          unsigned int *chk)
{
    if (!get_unsigned(chunkinfo, "grp=", grp)) {
        return 0;
    }

    if (!get_unsigned(chunkinfo, "pu=", lun)) {
        return 0;
    }

    if (!get_unsigned(chunkinfo, "chk=", chk)) {
        return 0;
    }

    return 1;
}

static int get_chunk_meta_index(FemuCtrl *n, NvmeNamespace *ns,
                                unsigned int grp, unsigned int lun,
                                unsigned int chk)
{
    Oc20Namespace *lns = ns->state;
    Oc20IdGeo *geo = &lns->id_ctrl.geo;

    if (chk >= geo->num_chk) {
        return -1;
    }

    if (lun >= geo->num_lun) {
        return -1;
    }

    if (grp >= geo->num_grp) {
        return -1;
    }

    return geo->num_chk * (grp * geo->num_lun + lun) + chk;
}

static int set_resetfail_chunk(FemuCtrl *n, NvmeNamespace *ns, char *chunkinfo)
{
    Oc20Namespace *lns = ns->state;
    unsigned int ch, lun, chk, resetfail_prob;
    int i;

    if (!get_ch_lun_chk(chunkinfo, &ch, &lun, &chk)) {
        return 1;
    }

    if (!get_unsigned(chunkinfo, "resetfail_prob=", &resetfail_prob)) {
        return 1;
    }

    if (resetfail_prob > 100) {
        return 1;
    }

    i = get_chunk_meta_index(n, ns, ch, lun, chk);
    if (i < 0) {
        return 1;
    }

    lns->resetfail[i] = resetfail_prob;

    return 0;
}

static int set_writefail_sector(FemuCtrl *n, NvmeNamespace *ns, char *secinfo)
{
    Oc20Namespace *lns = ns->state;
    Oc20AddrF *addrf = &lns->lbaf;
    Oc20IdGeo *geo = &lns->id_ctrl.geo;
    unsigned int ch, lun, chk, sec, writefail_prob;
    uint64_t lba;

    if (!get_ch_lun_chk(secinfo, &ch, &lun, &chk)) {
        return 1;
    }

    if (!get_unsigned(secinfo, "sec=", &sec)) {
        return 1;
    }

    if (sec >= geo->clba) {
        return 1;
    }

    if (!get_unsigned(secinfo, "writefail_prob=", &writefail_prob)) {
        return 1;
    }

    if (writefail_prob > 100) {
        return 1;
    }

    lba = OC20_LBA(addrf, ch, lun, chk, sec);
    lns->writefail[oc20_lba_to_sector_index(n, ns, lba)] = writefail_prob;

    return 0;
}

static int oc20_resetfail_load(FemuCtrl *n, NvmeNamespace *ns, Error **errp)
{
    Oc20Params *params = &n->params.oc20;
    FILE *fp;
    char line[256];

    if (!params->resetfail_fname) {
        return 0;
    }

    fp = fopen(params->resetfail_fname, "r");
    if (!fp) {
        femu_err("Could not open resetfail file");
        return 1;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (set_resetfail_chunk(n, ns, line)) {
            femu_err("Could not parse resetfail line: %s", line);
            return 1;
        }
    }

    fclose(fp);
    return 0;
}

static int oc20_writefail_load(FemuCtrl *n, NvmeNamespace *ns, Error **errp)
{
    Oc20Params *params = &n->params.oc20;
    FILE *fp;
    char line[256];

    if (!params->writefail_fname) {
        return 0;
    }

    fp = fopen(params->writefail_fname, "r");
    if (!fp) {
        femu_err("Could not open writefail file");
        return 1;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (set_writefail_sector(n, ns, line)) {
            femu_err("Could not parse writefail line: %s", line);
            return 1;
        }
    }

    fclose(fp);
    return 0;
}

static inline Oc20Namespace *cmd_lns(FemuCtrl *n, NvmeCmd *cmd)
{
    uint32_t nsid = le32_to_cpu(cmd->nsid);
    NvmeNamespace *ns = &n->namespaces[nsid - 1];

    return (ns->state);
}

static inline NvmeNamespace *cmd_ns(FemuCtrl *n, NvmeCmd *cmd)
{
    uint32_t nsid = le32_to_cpu(cmd->nsid);
    NvmeNamespace *ns = &n->namespaces[nsid - 1];

    return ns;
}

static uint16_t oc20_rw(FemuCtrl *n, NvmeCmd *cmd, NvmeRequest *req, bool vector)
{
    Oc20RwCmd *lrw = (Oc20RwCmd *)cmd;
    NvmeNamespace *ns = cmd_ns(n, cmd);
    uint64_t prp1 = le64_to_cpu(lrw->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(lrw->dptr.prp2);
    uint32_t nlb  = le16_to_cpu(lrw->nlb) + 1;
    uint64_t lbal = le64_to_cpu(lrw->lbal);
    int lbads = NVME_ID_NS_LBADS(ns);
    uint16_t err;
    int i;

    if (nlb > OC20_CMD_MAX_LBAS) {
        nvme_set_error_page(n, req->sq->sqid, req->cqe.cid, NVME_INVALID_FIELD,
                            offsetof(Oc20RwCmd, lbal), 0, req->ns->id);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    req->predef = 0;
    req->nlb = nlb;
    req->slba = (uint64_t)g_malloc0(sizeof(uint64_t) * nlb);
    req->is_write = oc20_rw_is_write(req) ? true : false;

    if (vector) {
        if (nlb > 1) {
            uint32_t len = nlb * sizeof(uint64_t);
            nvme_addr_read(n, lbal, (void *)req->slba, len);
        } else {
            ((uint64_t *)req->slba)[0] = lbal;
        }
    } else { /* For SPDK quirks */
        for (i = 0; i < nlb; i++) {
            ((uint64_t *)req->slba)[i] = lbal + i;
        }
    }

    err = oc20_rw_check_vector_req(n, cmd, req);
    if (err) {
        goto fail_free;
    }

    if (nvme_map_prp(&req->qsg, &req->iov, prp1, prp2, nlb << lbads, n)) {
        femu_err("%s,malformed prp\n", __func__);
        err = NVME_INVALID_FIELD | NVME_DNR;
        goto fail_free;
    }

    uint64_t aio_sector_list[OC20_CMD_MAX_LBAS];
    for (i = 0; i < nlb; i++) {
#ifdef DEBUG_OC20
        pr_lba(lns, ((uint64_t *)req->slba)[i]);
#endif
        aio_sector_list[i] = (((uint64_t *)req->slba)[i] << lbads);
    }
    backend_rw(n->mbe, &req->qsg, aio_sector_list, req->is_write);

    oc20_advance_status(n, ns, cmd, req);

    if (req->is_write) {
        oc20_advance_wp(n, ns, ((uint64_t *)req->slba)[0], nlb, req);
    }

    g_free((void *)req->slba);

    return NVME_SUCCESS;

fail_free:
    g_free((void *)req->slba);
    return err;
}

static uint16_t oc20_identify(FemuCtrl *n, NvmeCmd *cmd)
{
    NvmeNamespace *ns;
    uint32_t nsid = le32_to_cpu(cmd->nsid);

    if (unlikely(nsid == 0 || nsid > n->num_namespaces)) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ns = &n->namespaces[nsid - 1];

    return oc20_dma_read(n, (uint8_t *) &((Oc20Namespace *)ns->state)->id_ctrl,
                         sizeof(Oc20NamespaceGeometry), cmd);
}

static uint16_t oc20_erase(FemuCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    Oc20RwCmd *dm = (Oc20RwCmd *)cmd;
    hwaddr mptr = le64_to_cpu(cmd->mptr);
    uint64_t lbal = le64_to_cpu(dm->lbal);
    uint32_t nlb = le16_to_cpu(dm->nlb) + 1;
    int i;

    req->nlb = nlb;
    req->slba = (uint64_t)g_malloc0(nlb * sizeof(uint64_t));

    if (nlb > 1) {
        nvme_addr_read(n, lbal, (void *) req->slba, nlb * sizeof(void *));
    } else {
        ((uint64_t *)req->slba)[0] = lbal;
    }

    for (i = 0; i < nlb; i++) {
        Oc20CS *cs;
        if (NULL == (cs = oc20_chunk_get_state(n, req->ns, ((uint64_t *)
                                                            req->slba)[i]))) {
            return OC20_INVALID_RESET;
        }

        int err = oc20_chunk_set_free(n, req->ns, ((uint64_t *) req->slba)[i],
                                      mptr, req);
        if (err) {
            return err;
        }

        if (mptr) {
            mptr += sizeof(Oc20CS);
        }
    }

    return NVME_SUCCESS;
}

static uint16_t oc20_chunk_info(FemuCtrl *n, NvmeCmd *cmd, uint32_t buf_len,
                                uint64_t off)
{
    NvmeNamespace *ns;
    Oc20Namespace *lns;
    uint8_t *log_page;
    uint32_t log_len, trans_len, nsid;
    uint16_t ret;

    nsid = le32_to_cpu(cmd->nsid);
    if (unlikely(nsid == 0 || nsid > n->num_namespaces)) {
        abort();
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ns = &n->namespaces[nsid - 1];

    lns = ns->state;

    log_len = lns->chks_total * sizeof(Oc20CS);
    trans_len = MIN(log_len, buf_len);

    if (unlikely(log_len < off + buf_len)) {
        abort();
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    log_page = (uint8_t *) lns->chunk_info + off;

    if (cmd->opcode == NVME_ADM_CMD_GET_LOG_PAGE) {
        return oc20_dma_read(n, log_page, trans_len, cmd);
    }

    /* Coperd: TODO, set_log_page */
    ret = oc20_dma_write(n, log_page, trans_len, cmd);
    if (ret) {
        return ret;
    }

    return NVME_SUCCESS;
}

static uint16_t oc20_get_log(FemuCtrl *n, NvmeCmd *cmd)
{
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint32_t dw11 = le32_to_cpu(cmd->cdw11);
    uint32_t dw12 = le32_to_cpu(cmd->cdw12);
    uint32_t dw13 = le32_to_cpu(cmd->cdw13);
    uint16_t lid = dw10 & 0xff;
    uint32_t numdl, numdu, len;
    uint64_t off, lpol, lpou;

    numdl = (dw10 >> 16);
    numdu = (dw11 & 0xffff);
    lpol = dw12;
    lpou = dw13;

    len = (((numdu << 16) | numdl) + 1) << 2;
    off = (lpou << 32ULL) | lpol;

    switch (lid) {
    case OC20_CHUNK_INFO:
        return oc20_chunk_info(n, cmd, len, off);
    default:
        return NVME_INVALID_LOG_ID | NVME_DNR;
    }
}

static uint16_t oc20_set_log(FemuCtrl *n, NvmeCmd *cmd)
{
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint32_t dw11 = le32_to_cpu(cmd->cdw11);
    uint32_t dw12 = le32_to_cpu(cmd->cdw12);
    uint32_t dw13 = le32_to_cpu(cmd->cdw13);
    uint16_t lid = dw10 & 0xff;
    uint32_t numdl, numdu, len;
    uint64_t off, lpol, lpou;

    /* NVMe R1.3 */
    numdl = (dw10 >> 16);
    numdu = (dw11 & 0xffff);
    lpol = dw12;
    lpou = dw13;

    len = (((numdu << 16) | numdl) + 1) << 2;
    off = (lpou << 32ULL) | lpol;

    switch (lid) {
    case OC20_CHUNK_INFO:
        return oc20_chunk_info(n, cmd, len, off);
    default:
        return NVME_INVALID_LOG_ID | NVME_DNR;
    }
}

static uint16_t oc20_admin_cmd(FemuCtrl *n, NvmeCmd *cmd)
{
    switch (cmd->opcode) {
    case OC20_ADM_CMD_IDENTIFY:
        femu_debug("oc20_identify\n");
        return oc20_identify(n, cmd);
    case OC20_ADM_CMD_SET_LOG_PAGE:
        return oc20_set_log(n, cmd);
    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

#if 0
static uint16_t oc20_nvme_rw(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                             NvmeRequest *req)
{
    /* Note: this is not the read/write path for OCSSD */
    return NVME_DNR;
}
#endif

static uint16_t oc20_io_cmd(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                            NvmeRequest *req)
{
    switch (cmd->opcode) {
    case NVME_CMD_READ:
    case NVME_CMD_WRITE:
        /*
         * SPDK quirk: Somehow SPDK relies on NVME_CMD_{READ,WRITE} for its
         * libftl on OCSSD2.0, so let's enable it here
         */
        return oc20_rw(n, cmd, req, false);
    case OC20_CMD_VECT_READ:
    case OC20_CMD_VECT_WRITE:
        return oc20_rw(n, cmd, req, true);
    case OC20_CMD_VECT_ERASE:
        return oc20_erase(n, cmd, req);
    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

static void oc20_free_namespace(FemuCtrl *n, NvmeNamespace *ns)
{
    Oc20Namespace *lns = ns->state;

    g_free(lns->writefail);
    g_free(lns->resetfail);
}

static void oc20_nvme_ns_init_identify(FemuCtrl *n, NvmeIdNs *id_ns)
{
    NvmeParams *params;
    uint16_t ms_min;
    int i;

    params = &n->params;

    /* Supports the Deallocated or Unwritten Logical Block error */
    id_ns->nsfeat = 0x4;
    id_ns->nlbaf = 0; /* 0's based value */
    id_ns->flbas = params->extended << 4;
    id_ns->vs[0] = 0x1;
    id_ns->lbaf[0].lbads = 12;
    id_ns->lbaf[0].ms = 0;

    /* Coperd: OC2.0, setup all supported LBA format, shouldn't hurt */
    ms_min = 8;
    for (i = 1; i < 16 && ms_min <= n->ms_max; i++) {
        id_ns->lbaf[i].lbads = 12;
        id_ns->lbaf[i].ms = ms_min;

        if (params->ms == ms_min) {
            id_ns->flbas = i | (params->extended << 4);
        }

        ms_min *= 2;
        id_ns->nlbaf++;
    }
}

static uint64_t nvme_ns_calc_blks(FemuCtrl *n, NvmeNamespace *ns)
{
    return n->ns_size / ((1 << NVME_ID_NS_LBADS(ns)) + NVME_ID_NS_MS(ns));
}

static void nvme_ns_init_predef(FemuCtrl *n, NvmeNamespace *ns)
{
    uint8_t *pbuf = g_malloc(NVME_ID_NS_LBADS_BYTES(ns));

    switch (n->params.dlfeat) {
    case 0x1:
        memset(pbuf, 0x00, NVME_ID_NS_LBADS_BYTES(ns));
        break;
    case 0x2:
        pbuf = g_malloc(NVME_ID_NS_LBADS_BYTES(ns));
        memset(pbuf, 0xff, NVME_ID_NS_LBADS_BYTES(ns));
        break;
    default:
        break;
    }
}

static void femu_oc20_init_id_ctrl(FemuCtrl *n, NvmeNamespace *ns,
                                   Oc20NamespaceGeometry *ln)
{
    uint8_t mjr, mnr;
    uint16_t num_groups, num_punits;
    uint32_t num_chunks, num_secs_per_chunk;
    uint32_t mccap, wit, ws_min, ws_opt, mw_cunits;
    uint32_t trdt, trdm, twrt, twrm, tcrst, tcrsm;
    uint32_t max_open_chks, max_open_punits;

    uint8_t sec_per_pg = n->oc_params.secs_per_pg;
    uint16_t pgs_per_blk = n->oc_params.pgs_per_blk;
    uint8_t num_ch = n->oc_params.num_ch;
    uint8_t num_lun = n->oc_params.num_lun;
    uint8_t num_pln = n->oc_params.num_pln;

    /* 
     * Byte 0: Major Version Number (MJR)
     * - Value 1: OCSSD Revision 1.2
     * - Value 2: OCSSD Revision 2.0
     */
    mjr = 2;

    /* Byte 1: Minor Version Number (MNR) */
    mnr = 0;

    /* Byte 2-7: Reserved */

    /*
     * Byte 8-15: LBA Format (LBAF)
     * 8 : Group bit length - Number of bits assigned to Group addressing
     * 9 : PU bit length - number of bits assigned to PU addressing
     * 10: Chunk bit length - number of bits assigned to Chunk addressing
     * 11: Logical block bit length - number of bits assigned to logical blocks
     *     within Chunk
     * 12-15: Reserved
     */
    /* Coperd: lbaf is auto-calculated below */

    /* 
     * Byte 16-19: Media and Controller Capabilities (MCCAP): 
     * Bit 0: Support for Vector Chunk Copy IO Command 
     * Bit 1: Support for multi-resets when a chunk is in free state
     */
    mccap = 0x0;

    /* Byte 20-31: Reserved */

    /* Byte 32: Wear-level Index Delta Threshold (WIT) */
    wit = 0;

    /* Byte 33-63: Reserved */

    /* Byte 64-65: Number of Groups (NUM_GRP) */
    num_groups = num_ch;

    /* Byte 66-67: Number of parallel units per group (NUM_PU)  */
    num_punits = num_lun;

    /* Byte 68-71: Number of chunks per parallel unit (NUM_CHK) */
    num_chunks = ns->ns_blks / (sec_per_pg * pgs_per_blk * num_ch * num_lun * num_pln);

    /* Byte 72-75: Chunk Size (CLBA) - Number of sectors per chunk */
    num_secs_per_chunk = sec_per_pg * pgs_per_blk * num_pln;

    /* Byte 73-127: Reserved */

    /* Byte 128-131: Minimum Write Size (WS_MIN) */
    ws_min = 4;

    /* Byte 132-135: Optimal Write Size (WS_OPT) */
    ws_opt = 8;

    /* Byte 136-139: Cache Minimum Write Size Units (MW_CUNITS) */
    mw_cunits = 24;

    /* Byte 140-143: Maximum Open Chunks (MAXOC) */
    max_open_chks = 0; /* 0 indicates all available chunks can be open at any
                          given time */

    /* Byte 144-147: Maximum Open Chunks per PU (MAXOCPU) */
    max_open_punits = 0; /* If zero, the maximum open chunks defines the upper
                            limit of open chunks available in a parallel unit */

    /* Byte 148:191 Reserved */

    /* Byte 192-195: tRD Typical - Typical time to read a write unit (in ns) */
    trdt = 70000;
    /* Byte 196-199: RD Max (TRDM) - Max time to read a write unit (in ns) */
    trdm = 100000;
    /* Byte 200-203: tWR Typical - Typical time to write a write unit (in ns) */
    twrt = 1900000;
    /* Byte 204-207: tWR Max (TWRM) - Max time to write a write time (in ns) */
    twrm = 3500000;
    /* Byte 208-211: tCRS Typical (TCRST) - Typical chunk reset time (in ns) */
    tcrst = 3000000;
    /* Byte 212-215: tCRS Max (TCRSM) - Max chunk reset time (in ns) */
    tcrsm = 3000000;

    /* Byte 255-216: Reserved */
    /* Byte 3071-256: Reserved */
    /* Byte 3072-4095: Vendor Specific */

    *ln = (Oc20NamespaceGeometry) {
        .ver.major = mjr,
        .ver.minor = mnr,
        .lbaf = (Oc20IdLBAF) {
            .grp_len = 32 - clz32(num_groups - 1),
            .lun_len = 32 - clz32(num_punits - 1),
            .chk_len = 32 - clz32(num_chunks - 1),
            .sec_len = 32 - clz32(num_secs_per_chunk - 1),
        },
        .mccap = mccap,
        .wit   = wit,
        .geo = (Oc20IdGeo) {
            .num_grp = num_groups,
            .num_lun = num_punits,
            .num_chk = num_chunks,
            .clba    = num_secs_per_chunk,
        },
        .wrt = (Oc20IdWrt) {
            .ws_min = ws_min,
            .ws_opt = ws_opt,
            .mw_cunits = mw_cunits,
            .max_open_chks = max_open_chks,
            .max_open_punits = max_open_punits,
        },
        .perf = (Oc20IdPerf) {
            .trdt = cpu_to_le32(trdt),
            .trdm = cpu_to_le32(trdm),
            .tprt = cpu_to_le32(twrt),
            .tprm = cpu_to_le32(twrm),
            .tbet = cpu_to_le32(tcrst),
            .tbem = cpu_to_le32(tcrsm),
        },
    };
}

static int oc20_init_namespace(FemuCtrl *n, NvmeNamespace *ns, Error **errp)
{
    Oc20Ctrl *ln = n->ext_ops.state;
    NvmeIdNs *id_ns = &ns->id_ns;
    Oc20Params *params = &n->params.oc20;
    Oc20NamespaceGeometry *id_ctrl;
    Oc20IdGeo *id_geo;
    Oc20AddrF *lbaf;
    Oc20Namespace *lns;

    oc20_nvme_ns_init_identify(n, id_ns);

    lns = ns->state = g_malloc0(sizeof(Oc20Namespace));

    lbaf = &lns->lbaf;
    id_ctrl = &lns->id_ctrl;
    id_geo = &lns->id_ctrl.geo;

    femu_oc20_init_id_ctrl(n, ns, id_ctrl);

    params->mccap = id_ctrl->mccap;
    params->ws_min = id_ctrl->wrt.ws_min;
    params->ws_opt = id_ctrl->wrt.ws_opt;
    params->mw_cunits = id_ctrl->wrt.mw_cunits;

    id_ns->lbaf[0].lbads = 63 - clz64(ln->blk_hdr.sector_size);
    id_ns->lbaf[0].ms = ln->blk_hdr.md_size;
    id_ns->nlbaf = 0;
    id_ns->flbas = 0;

    uint64_t chks_total = (id_ctrl->geo.num_grp * id_ctrl->geo.num_lun *
                           id_ctrl->geo.num_chk);
    lns->chunkinfo_size = QEMU_ALIGN_UP(chks_total * sizeof(Oc20CS),
                                        ln->blk_hdr.sector_size);
    lns->chunk_info = g_malloc0(lns->chunkinfo_size);
    ns->ns_blks = nvme_ns_calc_blks(n, ns) - (2 + lns->chunkinfo_size /
                                              NVME_ID_NS_LBADS_BYTES(ns));

    ns->blk.predef = ns->blk.begin + sizeof(Oc20NamespaceGeometry) +
        lns->chunkinfo_size + NVME_ID_NS_LBADS_BYTES(ns);
    ns->blk.data = ns->blk.begin + (2 * NVME_ID_NS_LBADS_BYTES(ns)) +
        lns->chunkinfo_size;
    ns->blk.meta = ns->blk.data + NVME_ID_NS_LBADS_BYTES(ns) * ns->ns_blks;

    nvme_ns_init_predef(n, ns);

    if (params->early_reset) {
        params->mccap |= OC20_PARAMS_MCCAP_EARLY_RESET;
    }

    lns->id_ctrl.mccap = cpu_to_le32(params->mccap);

    /* calculated values */
    lns->chks_per_grp = id_geo->num_chk * id_geo->num_lun;
    lns->chks_total   = lns->chks_per_grp * id_geo->num_grp;
    lns->secs_per_chk = id_geo->clba;
    lns->secs_per_lun = lns->secs_per_chk * id_geo->num_chk;
    lns->secs_per_grp = lns->secs_per_lun * id_geo->num_lun;
    lns->secs_total   = lns->secs_per_grp * id_geo->clba;

    /* Address format: GRP | LUN | CHK | SEC */
    lbaf->sec_offset = 0;
    lbaf->chk_offset = id_ctrl->lbaf.sec_len;
    lbaf->lun_offset = id_ctrl->lbaf.sec_len + id_ctrl->lbaf.chk_len;
    lbaf->grp_offset = (id_ctrl->lbaf.sec_len + id_ctrl->lbaf.chk_len +
                        id_ctrl->lbaf.lun_len);

    /* Address component selection MASK */
    lbaf->grp_mask = ((1 << id_ctrl->lbaf.grp_len) - 1) << lbaf->grp_offset;
    lbaf->lun_mask = ((1 << id_ctrl->lbaf.lun_len) - 1) << lbaf->lun_offset;
    lbaf->chk_mask = ((1 << id_ctrl->lbaf.chk_len) - 1) << lbaf->chk_offset;
    lbaf->sec_mask = ((1 << id_ctrl->lbaf.sec_len) - 1) << lbaf->sec_offset;

    /* report size of address space */
    id_ns->nuse = id_ns->ncap = id_ns->nsze =
        1ULL << (id_ctrl->lbaf.sec_len + id_ctrl->lbaf.chk_len +
                 id_ctrl->lbaf.lun_len + id_ctrl->lbaf.grp_len);

    if (oc20_init_chunk_info(lns)) {
        femu_err("Could not load chunk info");
        return 1;
    }

    lns->resetfail = NULL;
    if (params->resetfail_fname) {
        lns->resetfail = g_malloc0_n(lns->chks_total, sizeof(*lns->resetfail));
        if (oc20_resetfail_load(n, ns, errp)) {
            return 1;
        }
    }

    lns->writefail = NULL;
    if (params->writefail_fname) {
        abort();
        lns->writefail = g_malloc0_n(ns->ns_blks, sizeof(*lns->writefail));
        if (oc20_writefail_load(n, ns, errp)) {
            return 1;
        }

        /* 
         * We fail resets for a chunk after a write failure to it, so make sure
         * to allocate the resetfailure buffer if it has not been already
         */
        if (!lns->resetfail) {
            lns->resetfail = g_malloc0_n(lns->chks_total, sizeof(*lns->resetfail));
        }
    }

    return 0;
}

static int oc20_init_namespaces(FemuCtrl *n, Error **errp)
{
    Oc20Ctrl *ln = n->ext_ops.state;
    int i;

    ln->blk_hdr = (Oc20Header) {
        .magic = OC20_MAGIC,
        .version = 0x1,
        .num_namespaces = 1,
        .ns_size = n->ns_size,
        .sector_size = 4096,
        .md_size = 16,
    };

    for (i = 0; i < n->num_namespaces; i++) {
        NvmeNamespace *ns = &n->namespaces[i];
        NvmeIdNs *id_ns = &ns->id_ns;
        id_ns->vs[0] = 0x1;
        ns->blk.begin = ln->blk_hdr.sector_size + i * ln->blk_hdr.ns_size;

        if (oc20_init_namespace(n, ns, errp)) {
            return 1;
        }
    }

    return 0;
}

static void oc20_set_ctrl_str(FemuCtrl *n)
{
    static int fsid_voc20 = 0;
    const char *vocssd20_mn = "FEMU OpenChannel-SSD Controller (v2.0)";
    const char *vocssd20_sn = "vOCSSD";

    nvme_set_ctrl_name(n, vocssd20_mn, vocssd20_sn, &fsid_voc20);
}

static void oc20_release_locks(FemuCtrl *n)
{
    int ret;
    int i;

    for (i = 0; i < FEMU_MAX_NUM_CHNLS; i++) {
        ret = pthread_spin_destroy(&n->chnl_locks[i]);
        assert(ret == 0);
    }

    for (i = 0; i < FEMU_MAX_NUM_CHIPS; i++) {
        ret = pthread_spin_destroy(&n->chip_locks[i]);
        assert(ret == 0);
    }
}

static int oc20_init_misc(FemuCtrl *n)
{
    int ret;
    int i;

	set_latency(n);

    for (i = 0; i < FEMU_MAX_NUM_CHNLS; i++) {
        n->chnl_next_avail_time[i] = 0;

        /* FIXME: Can we use PTHREAD_PROCESS_PRIVATE here? */
        ret = pthread_spin_init(&n->chnl_locks[i], PTHREAD_PROCESS_SHARED);
        assert(ret == 0);
    }

    for (i = 0; i < FEMU_MAX_NUM_CHIPS; i++) {
        n->chip_next_avail_time[i] = 0;

        /* FIXME: Can we use PTHREAD_PROCESS_PRIVATE here? */
        ret = pthread_spin_init(&n->chip_locks[i], PTHREAD_PROCESS_SHARED);
        assert(ret == 0);
    }

    return 0;
}

static void oc20_init(FemuCtrl *n, Error **errp)
{
    NVME_CAP_SET_OC(n->bar.cap, 1);
    oc20_set_ctrl_str(n);
    oc20_init_namespaces(n, errp);

    oc20_init_misc(n);
}

static void oc20_exit(FemuCtrl *n)
{
    int i;

    for (i = 0; i < n->num_namespaces; i++) {
        NvmeNamespace *ns = &n->namespaces[i];
        oc20_free_namespace(n, ns);
    }

    oc20_release_locks(n);
}

int nvme_register_ocssd20(FemuCtrl *n)
{
    Oc20Ctrl *ln = g_malloc0(sizeof(Oc20Ctrl));
    n->ext_ops = (FemuExtCtrlOps) {
        .state            = ln,
        .init             = oc20_init,
        .exit             = oc20_exit,
        .rw_check_req     = oc20_rw_check_req,
        .admin_cmd        = oc20_admin_cmd,
        .io_cmd           = oc20_io_cmd,
        .get_log          = oc20_get_log,
    };

    return 0;
}

