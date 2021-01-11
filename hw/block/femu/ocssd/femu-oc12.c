#include "qemu/osdep.h"
#include "hw/block/block.h"
#include "hw/pci/msix.h"
#include "qemu/error-report.h"

#include "../nvme.h"

int64_t chip_next_avail_time[128]; /* Coperd: when chip will be not busy */
int64_t chnl_next_avail_time[16]; /* Coperd: when chnl will be free */

#define LOWER_NAND_PAGE_READ_TIME   48000
#define UPPER_NAND_PAGE_READ_TIME   64000
#define LOWER_NAND_PAGE_WRITE_TIME  850000
#define UPPER_NAND_PAGE_WRITE_TIME  2300000
#define CHNL_PAGE_TRANSFER_TIME     52433
#define NAND_BLOCK_ERASE_TIME       5000000

int64_t nand_read_upper_t = UPPER_NAND_PAGE_READ_TIME;
int64_t nand_read_lower_t = LOWER_NAND_PAGE_READ_TIME;
int64_t nand_write_upper_t = UPPER_NAND_PAGE_WRITE_TIME;
int64_t nand_write_lower_t = LOWER_NAND_PAGE_WRITE_TIME;
int64_t nand_erase_t = NAND_BLOCK_ERASE_TIME;
int64_t chnl_page_tr_t = CHNL_PAGE_TRANSFER_TIME;

int mlc_tbl[511];
#define MLC_LOWER_PAGE  0
#define MLC_UPPER_PAGE  1

static int qemu_fls(int i)
{
    return 32 - clz32(i);
}

/* Coperd: L95B lower/upper page layout in one block */
static void femu_init_nand_low_upp_layout(FemuCtrl *n)
{
    int i;
    int lowp[] = {0, 1, 2, 3, 4, 5, 7, 8, 502, 503, 506, 507, 509, 510};
    int uppp[] = {6, 9, 504, 505, 508, 511};
    int lpflag = MLC_LOWER_PAGE;

    for (i = 0; i < sizeof(lowp)/sizeof(lowp[0]); i++)
        mlc_tbl[lowp[i]] = MLC_LOWER_PAGE;

    for (i = 0; i < sizeof(uppp)/sizeof(uppp[0]); i++)
        mlc_tbl[uppp[i]] = MLC_UPPER_PAGE;

    for (i = 10; i <= 500; i += 2) {
        mlc_tbl[i] = mlc_tbl[i+1] = lpflag;
        lpflag = (lpflag == MLC_LOWER_PAGE) ? MLC_UPPER_PAGE : MLC_LOWER_PAGE;
    }
}

static inline int is_upper_page(int pg)
{
    return mlc_tbl[pg];
}

void femu_oc12_tbl_initialize(NvmeNamespace *ns)
{
    uint32_t len = ns->tbl_entries;
    uint32_t i;

    for (i = 0; i < len; i++) {
        ns->tbl[i] = FEMU_OC12_LBA_UNMAPPED;
    }
}

static void pr_ppa(FEMU_OC12_Ctrl *ln, uint64_t ppa)
{
    uint64_t ch = (ppa & ln->ppaf.ch_mask) >> ln->ppaf.ch_offset;
    uint64_t lun = (ppa & ln->ppaf.lun_mask) >> ln->ppaf.lun_offset;
    uint64_t blk = (ppa & ln->ppaf.blk_mask) >> ln->ppaf.blk_offset;
    uint64_t pg = (ppa & ln->ppaf.pg_mask) >> ln->ppaf.pg_offset;
    uint64_t pln = (ppa & ln->ppaf.pln_mask) >> ln->ppaf.pln_offset;
    uint64_t sec = (ppa & ln->ppaf.sec_mask) >> ln->ppaf.sec_offset;

    femu_log("ppa: ch(%lu), lun(%lu), blk(%lu), pg(%lu), pl(%lu), sec(%lu)\n",
            ch, lun, blk, pg, pln, sec);
}

/*
 * Write a single out-of-bound area entry
 *
 * NOTE: Ensure that `femu_oc12_set_written_state` has been called prior to this
 * function to ensure correct file offset of ln->metadata?
 */
static int femu_oc12_meta_write(FEMU_OC12_Ctrl *ln, void *meta)
{
    memcpy(ln->meta_buf, meta, ln->params.sos);
    return 0;
}

/*
 * Read a single out-of-bound area entry
 *
 * NOTE: Ensure that `femu_oc12_meta_state_get` has been called to have the correct
 * file offset in ln->metadata?
 */
static int femu_oc12_meta_read(FEMU_OC12_Ctrl *ln, void *meta)
{
    memcpy(meta, ln->meta_buf, ln->params.sos);

    return 0;
}

#if 0
int64_t femu_oc12_ppa_to_off(FEMU_OC12_Ctrl *ln, uint64_t r)
{
    return r;
    uint64_t ch = (r & ln->ppaf.ch_mask) >> ln->ppaf.ch_offset;
    uint64_t lun = (r & ln->ppaf.lun_mask) >> ln->ppaf.lun_offset;
    uint64_t pln = (r & ln->ppaf.pln_mask) >> ln->ppaf.pln_offset;
    uint64_t blk = (r & ln->ppaf.blk_mask) >> ln->ppaf.blk_offset;
    uint64_t pg = (r & ln->ppaf.pg_mask) >> ln->ppaf.pg_offset;
    uint64_t sec = (r & ln->ppaf.sec_mask) >> ln->ppaf.sec_offset;

    uint64_t off = sec;

    off += pln * ln->params.pl_units;
    off += pg * ln->params.pg_units;
    off += blk * ln->params.blk_units;
    off += lun * ln->params.lun_units;
    off += ch * ln->params.ch_units;

    if (off > ln->params.total_units) {
        printf("ERROR femu_oc12: ppa OOB:ch:%lu,lun:%lu,blk:%lu,pg:%lu,pl:%lu,sec:%lu\n",
                ch, lun, blk, pg, pln, sec);
        return -1;
    }

    return off;
}
#endif

static int femu_oc12_meta_state_get(FEMU_OC12_Ctrl *ln, uint64_t ppa, uint32_t *state)
{
    uint32_t oft = ppa * ln->meta_len;

    assert(oft + ln->meta_len <= ln->meta_tbytes);
    /* Coperd: only need the internal oob area */
    memcpy(state, &ln->meta_buf[oft], ln->int_meta_size);

    return 0;
}

/*
 * Similar to femu_oc12_meta_set_written, however, this function sets not a single
 * but multiple ppas, also checks if a block is marked bad
 */
#if 0
static int femu_oc12_meta_blk_set_erased(NvmeNamespace *ns, FEMU_OC12_Ctrl *ln,
                                  uint64_t *psl, int nr_ppas, int pmode)
{
    FEMU_OC12_IdGroup *c = &ln->id_ctrl.groups[0];
    int i;

    uint64_t mask = 0;

#if 0
    if (ln->strict && nr_ppas != 1) {
        printf("_erase_meta: Erase command unfolds on device\n");
        return NVME_INVALID_FIELD | NVME_DNR;
    }
#endif

    switch (pmode) {     // Check that pmode is supported
    case FEMU_OC12_PMODE_DUAL:
        if (c->num_pln != 2) {
            printf("_erase_meta: Unsupported pmode(%d) for num_pln(%d)\n",
                   pmode, c->num_pln);
            return -1;
        }
        break;
    case FEMU_OC12_PMODE_QUAD:
        if (c->num_pln != 4) {
            printf("_erase_meta: Unsupported pmode(%d) for num_pln(%d)\n",
                   pmode, c->num_pln);
            return -1;
        }
        break;
    case FEMU_OC12_PMODE_SNGL:
        break;
    default:
        printf("_erase_meta: Unsupported pmode(%d)\n", pmode);
    }

    mask |= ln->ppaf.ch_mask;   // Construct mask
    mask |= ln->ppaf.lun_mask;
    mask |= ln->ppaf.blk_mask;

    for (i = 0; i < nr_ppas; ++i) {
        uint64_t ppa = psl[i];
        size_t pl_bgn, pl_end;
        size_t pl;

        if (pmode) {
            pl_bgn = 0;
            pl_end = c->num_pln - 1;
        } else {
            pl_bgn = (ppa & ln->ppaf.pln_mask) >> ln->ppaf.pln_offset;
            pl_end = pl_bgn;
        }

        for (pl = pl_bgn; pl <= pl_end; ++pl) {
            //uint32_t cur_state = 0;
            uint64_t ppa_pl;

            ppa_pl = ppa & mask;
            ppa_pl |= pl << ln->ppaf.pln_offset;

            /* Coperd: TODO: Need to support Bad Block Mgnt later */
#if 0
            // Check bad-block-table to error on bad blocks
            if (ns->bbtbl[femu_oc12_bbt_pos_get(ln, ppa_pl)]) {
                printf("_erase_meta: failed -- block is bad\n");
                return -1;
            }
#endif


            /* Coperd: for now, we skip the checking */
#if 0
            // Check state of first sector to error on double-erase
            if (femu_oc12_meta_state_get(ln, ppa_pl, &cur_state)) {
                printf("_erase_meta: failed: reading current state\n");
                return -1;
            }
            if (cur_state == FEMU_OC12_SEC_ERASED) {
                printf("_erase_meta: failed -- already erased\n");
            }
#endif

            /* Coperd: we don't save the state to each oob area for each pg */
#if 0
            for (pg = 0; pg < ln->params.pgs_per_blk; ++pg) {
                for (sec = 0; sec < ln->params.sec_per_pg; ++sec) {
                    uint64_t ppa_sec, off;

                    ppa_sec = ppa & mask;
                    ppa_sec |= pg << ln->ppaf.pg_offset;
                    ppa_sec |= pl << ln->ppaf.pln_offset;
                    ppa_sec |= sec << ln->ppaf.sec_offset;

                    //printf("Coperd,erase,ppa=%lld\n", ppa_sec);
                    //pr_ppa(ln, ppa_sec);
                    off = femu_oc12_ppa_to_off(ln, ppa_sec);
                    memcpy(&ln->meta_buf[off * ln->meta_len], &meta, ln->meta_len);

#if 0
                    if (fseek(meta_fp, off * meta_len, SEEK_SET)) {
                        perror("_set_erased: fseek");
                        return -1;
                    }

                    if (fwrite(&meta, meta_len, 1, meta_fp) != 1) {
                        perror("_erase_meta: fwrite");
                        printf("_erase_meta: ppa(%016lx), off(%lu)\n", ppa_sec,
                                                                        off);
                    }
#endif
                }
            }
#endif
        }
    }

#if 0
    if (fflush(meta_fp)) {
        perror("_erase_meta: fflush");
        return -1;
    }
#endif

    return 0;
}
#endif

static int femu_oc12_meta_state_set_written(FEMU_OC12_Ctrl *ln, uint64_t ppa)
{
    uint32_t oft = ppa * ln->meta_len;
    uint32_t state;

    state = FEMU_OC12_SEC_WRITTEN;
    memcpy(&ln->meta_buf[oft], &state, ln->int_meta_size);

    return 0;
}

static void *femu_oc12_meta_index(FEMU_OC12_Ctrl *ln, void *meta, uint32_t index)
{
    return meta + (index * ln->params.sos);
}

uint16_t femu_oc12_rw(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd, NvmeRequest *req)
{
    FEMU_OC12_Ctrl *ln = &n->femu_oc12_ctrl;
    FEMU_OC12_IdGroup *c = &ln->id_ctrl.groups[0];
    FEMU_OC12_RwCmd *ocrw = (FEMU_OC12_RwCmd *)cmd;
    NvmeCqe *cqe = &req->cqe;
    uint64_t psl[ln->params.max_sec_per_rq];
    int secs_layout[ln->params.max_sec_per_rq];
    uint64_t aio_sector_list[ln->params.max_sec_per_rq];
    void *msl;
    uint64_t ppa;
    uint16_t nlb  = le16_to_cpu(ocrw->nlb) + 1;
    uint64_t prp1 = le64_to_cpu(ocrw->prp1);
    uint64_t prp2 = le64_to_cpu(ocrw->prp2);
    uint64_t spba = le64_to_cpu(ocrw->spba);
    uint64_t meta = le64_to_cpu(ocrw->metadata);
    const uint8_t lba_index = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    const uint8_t data_shift = ns->id_ns.lbaf[lba_index].ds;
    const uint16_t ms = le16_to_cpu(ns->id_ns.lbaf[lba_index].ms);
    uint64_t data_size = nlb << data_shift;
    uint64_t meta_size = nlb * ms;
    uint32_t n_pages = data_size / ln->params.sec_size;
    uint16_t is_write = (ocrw->opcode == FEMU_OC12_CMD_PHYS_WRITE);
    uint16_t ctrl = 0;
    uint16_t err;
    uint8_t i;
    int64_t now;

    memset(secs_layout, 0, sizeof(int) * ln->params.max_sec_per_rq);

    msl = g_malloc0(ln->params.sos * ln->params.max_sec_per_rq);
    if (!msl) {
        femu_err("femu_oc12_rw: ENOMEM\n");
        return -ENOMEM;
    }

    if (n_pages > ln->params.max_sec_per_rq) {
        femu_err("femu_oc12_rw: npages too large (%u). Max:%u supported\n",
                n_pages, ln->params.max_sec_per_rq);
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_LBA_RANGE,
                offsetof(FEMU_OC12_RwCmd, spba), ocrw->slba + nlb, ns->id);
        err = NVME_INVALID_FIELD | NVME_DNR;
        goto fail_free_msl;
    } else if ((is_write) && (n_pages < ln->params.sec_per_pl)) {
        femu_err("femu_oc12_rw: I/O does not respect device write constrains."
                "Sectors send: (%u). Min:%u sectors required\n",
                n_pages, ln->params.sec_per_pl);
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_LBA_RANGE,
                offsetof(FEMU_OC12_RwCmd, spba), ocrw->slba + nlb, ns->id);
        err = NVME_INVALID_FIELD | NVME_DNR;
        goto fail_free_msl;
    } else if (n_pages > 1) {
        femu_nvme_addr_read(n, spba, (void *)psl, n_pages * sizeof(void *));
    } else {
        psl[0] = spba;
    }

    if (spba == FEMU_OC12_PBA_UNMAPPED) {
        femu_err("femu_oc12_rw: unmapped PBA\n");
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_LBA_RANGE,
                offsetof(FEMU_OC12_RwCmd, spba), ocrw->slba + nlb, ns->id);
        err = NVME_INVALID_FIELD | NVME_DNR;
        goto fail_free_msl;
    }

    ctrl = le16_to_cpu(ocrw->control);
    req->femu_oc12_ppa_list = psl;
    req->femu_oc12_slba = le64_to_cpu(ocrw->slba);
    req->is_write = is_write;

    /* Reuse check logic from nvme_rw */
    err = femu_oc_rw_check_req(n, ns, cmd, req, psl, n_pages, nlb, ctrl,
            data_size, meta_size);
    if (err) {
        femu_err("femu_oc12_rw: failed nvme_rw_check (0x%x)\n", err);
        goto fail_free_msl;
    }

    if (meta && is_write)
        femu_nvme_addr_read(n, meta, (void *)msl, n_pages * ln->params.sos);

    /* If several LUNs are set up, the ppa list sent by the host will not be
     * sequential. In this case, we need to pass on the list of ppas to the dma
     * handlers to write/read data to/from the right physical sector
     */
    int64_t max = 0;
    int ch, lun, pg, lunid;
    //int pl, blk, sec;
    int64_t io_done_ts = 0, start_data_transfer_ts = 0;
    int64_t need_to_emulate_tt = 0;
    //printf("Coperd,opcode=%d,n_pages=%d\n", req->cmd_opcode, n_pages);

    if (is_write) {
        /* Coperd: LightNVM only issues 32KB I/O writes */
        ppa = psl[0];
        ch = (ppa & ln->ppaf.ch_mask) >> ln->ppaf.ch_offset;
        lun = (ppa & ln->ppaf.lun_mask) >> ln->ppaf.lun_offset;
        pg = (ppa & ln->ppaf.pg_mask) >> ln->ppaf.pg_offset;
        lunid = ch * c->num_lun + lun;
        io_done_ts = 0;
        start_data_transfer_ts = 0;

        assert(ch < c->num_ch && lun < c->num_lun);
        now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);

        /* Coperd: for writes, transfer data through channel first and then do
         * NAND write by moving data from data register to NAND
         */
        if (now < chnl_next_avail_time[ch]) {
            start_data_transfer_ts = chnl_next_avail_time[ch];
        } else {
            start_data_transfer_ts = now;
        }
        chnl_next_avail_time[ch] = start_data_transfer_ts + chnl_page_tr_t * 2;

        if (chnl_next_avail_time[ch] < chip_next_avail_time[lunid]) {
            if (is_upper_page(pg)) {
                chip_next_avail_time[lunid] += nand_write_upper_t;
            } else {
                chip_next_avail_time[lunid] += nand_write_lower_t;
            }
        } else {
            if (is_upper_page(pg)) {
                chip_next_avail_time[lunid] = chnl_next_avail_time[ch] + nand_write_upper_t;
            } else {
                chip_next_avail_time[lunid] = chnl_next_avail_time[ch] + nand_write_lower_t;
            }
        }

        io_done_ts = chip_next_avail_time[lunid];

        /* Coperd: the time need to emulate is (io_done_ts - now) */
        need_to_emulate_tt = io_done_ts - now;
        if (need_to_emulate_tt > max)
            max = need_to_emulate_tt;
    } else {
        /* Coperd: reads, LightNVM only issues SNGL reads */
        memset(secs_layout, 0, sizeof(int) * 64);
        int secs_idx = -1;
        int64_t prev_pg_addr = -1, cur_pg_addr;
        for (i = 0; i < n_pages; i++) {
            ppa = psl[i];
            cur_pg_addr = (ppa & (~(ln->ppaf.sec_mask)));
            if (cur_pg_addr == prev_pg_addr) {
                secs_layout[secs_idx]++;
            } else {
                secs_idx++;
                secs_layout[secs_idx]++;
                prev_pg_addr = cur_pg_addr;
            }
        }

        /* Coperd: these are NAND pages we need to handle */
        int si = 0;
        int nb_secs_to_read = 0;
        now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
        for (i = 0; i <= secs_idx; i++) {
            ppa = psl[si];
            nb_secs_to_read = secs_layout[i];
            //printf("Coperd,secs_layout[%d]=%d,si=%d\n", i, nb_secs_to_read, si);
            si += nb_secs_to_read;

            ch = (ppa & ln->ppaf.ch_mask) >> ln->ppaf.ch_offset;
            lun = (ppa & ln->ppaf.lun_mask) >> ln->ppaf.lun_offset;
            //pl = (ppa & ln->ppaf.pln_mask) >> ln->ppaf.pln_offset;
            //blk = (ppa & ln->ppaf.blk_mask) >> ln->ppaf.blk_offset;
            pg = (ppa & ln->ppaf.pg_mask) >> ln->ppaf.pg_offset;
            //sec = (ppa & ln->ppaf.sec_mask) >> ln->ppaf.sec_offset;
            lunid = ch * c->num_lun + lun;

            io_done_ts = 0;
            start_data_transfer_ts = 0;
            assert(ch < c->num_ch && lun < c->num_lun);
            if (now < chip_next_avail_time[lunid]) {
                /* Coperd: need to wait for target chip to be free */
                if (is_upper_page(pg)) {
                    chip_next_avail_time[lunid] += nand_read_upper_t;
                } else {
                    chip_next_avail_time[lunid] += nand_read_lower_t;
                }
            } else {
                /* Coperd: target chip is free */
                if (is_upper_page(pg)) {
                    chip_next_avail_time[lunid] = now + nand_read_upper_t;
                } else {
                    chip_next_avail_time[lunid] = now + nand_read_lower_t;
                }
            }
            start_data_transfer_ts = chip_next_avail_time[lunid];
            /* Coperd: TODO: replace 4 with a calculated value (c->num_sec) */
            assert(nb_secs_to_read <= 8 && nb_secs_to_read >= 1);
            int chnl_transfer_time = chnl_page_tr_t * nb_secs_to_read / 4;

            if (start_data_transfer_ts < chnl_next_avail_time[ch]) {
                /* Coperd: need to wait for channel to be free */
                chnl_next_avail_time[ch] += chnl_transfer_time;
            } else {
                /* Coperd: use the chnl immediately after reading from NAND */
                chnl_next_avail_time[ch] = start_data_transfer_ts + chnl_transfer_time;
            }

            chip_next_avail_time[lunid] = chnl_next_avail_time[ch];
            io_done_ts = chnl_next_avail_time[ch];

            /* Coperd: the time need to emulate is (io_done_ts - now) */
            need_to_emulate_tt = io_done_ts - now;
            if (need_to_emulate_tt > max)
                max = need_to_emulate_tt;
        }
    }

    for (i = 0; i < n_pages; i++) {
        ppa = psl[i];
        ch = (ppa & ln->ppaf.ch_mask) >> ln->ppaf.ch_offset;
        lun = (ppa & ln->ppaf.lun_mask) >> ln->ppaf.lun_offset;
        //pl = (ppa & ln->ppaf.pln_mask) >> ln->ppaf.pln_offset;
        //blk = (ppa & ln->ppaf.blk_mask) >> ln->ppaf.blk_offset;
        pg = (ppa & ln->ppaf.pg_mask) >> ln->ppaf.pg_offset;
        //sec = (ppa & ln->ppaf.sec_mask) >> ln->ppaf.sec_offset;
        lunid = ch * c->num_lun + lun;
        //printf("    Coperd,ppa[%d],ch:%d,lun:%d,pl:%d,blk:%d,pg:%d,sec:%d\n", i, ch, lun, pl, blk, pg, sec);

        req->lunid = lunid;
        req->chnl = ch;

        aio_sector_list[i] = ns->start_block + (ppa << data_shift);

        if (is_write) {
#if 1
            if (femu_oc12_meta_state_set_written(ln, ppa)) {
                femu_err("femu_oc12_rw: set written status failed\n");
                pr_ppa(ln, psl[i]);
                err = NVME_INVALID_FIELD | NVME_DNR;
                goto fail_free_msl;
            }
#endif

            if (meta) {
                if (femu_oc12_meta_write(ln, femu_oc12_meta_index(ln, msl, i))) {
                    femu_err("femu_oc12_rw: write metadata failed\n");
                    pr_ppa(ln, psl[i]);
                    err = NVME_INVALID_FIELD | NVME_DNR;
                    goto fail_free_msl;
                }
            }
        } else if (!is_write){
            uint32_t state;

            if (femu_oc12_meta_state_get(ln, ppa, &state)) {
                femu_err("femu_oc12_rw: read status failed\n");
                pr_ppa(ln, psl[i]);
                err = NVME_INVALID_FIELD | NVME_DNR;
                goto fail_free_msl;
            }

            if (state != FEMU_OC12_SEC_WRITTEN) {
                bitmap_set(&cqe->res64, i, n_pages - i);
                req->status = 0x42ff;

                /* Copy what has been read from the OOB area */
                if (meta)
                    femu_nvme_addr_write(n, meta, (void *)msl,
                            n_pages * ln->params.sos);
                err = 0x42ff;
                //printf("Coperd,%s,reading unwritten LBA\n", __func__);
                goto fail_free_msl;
            }

            if (meta) {
                if (femu_oc12_meta_read(ln, femu_oc12_meta_index(ln, msl, i))) {
                    femu_err("femu_oc12_rw: read metadata failed\n");
                    pr_ppa(ln, psl[i]);
                    err = NVME_INVALID_FIELD | NVME_DNR;
                    goto fail_free_msl;
                }
            }
        }
    }

    req->expire_time = qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + max;

	/* Coperd: TOFIX, fix the meta buf later. For now, comment out the part to
	 * mask LightNVM corrupted read LBA warnings */
#if 0
	if (meta && !is_write) femu_nvme_addr_write(n, meta, (void *)msl, n_pages *
		ln->params.sos);
#endif

    g_free(msl);

    if (nvme_map_prp(&req->qsg, &req->iov, prp1, prp2, data_size, n)) {
        femu_err("femu_oc12_rw: malformed prp (sz:%lu), w:%d\n", data_size, is_write);
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
                offsetof(NvmeRwCmd, prp1), 0, ns->id);
        err = NVME_INVALID_FIELD | NVME_DNR;
        goto fail_free_msl;
    }

    req->slba = psl[0];
    req->meta_size = 0;
    req->status = NVME_SUCCESS;
    req->nlb = nlb;
    req->ns = ns;

    femu_rw_mem_backend_oc(&n->mbe, &req->qsg, aio_sector_list, req->is_write);

    return NVME_SUCCESS;

fail_free_msl:
    g_free(msl);

    return err;
}

uint32_t femu_oc12_tbl_size(NvmeNamespace *ns)
{
    return ns->tbl_entries * sizeof(*(ns->tbl));
}

uint16_t femu_oc12_identity(FemuCtrl *n, NvmeCmd *cmd)
{
    NvmeIdentify *c = (NvmeIdentify *)cmd;
    uint32_t nsid = le32_to_cpu(c->nsid);
    uint64_t prp1 = le64_to_cpu(c->prp1);
    uint64_t prp2 = le64_to_cpu(c->prp2);

    if (nsid == 0 || nsid > n->num_namespaces) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    return nvme_dma_read_prp(n, (uint8_t *)&n->femu_oc12_ctrl.id_ctrl,
            sizeof(FEMU_OC12_IdCtrl), prp1, prp2);
}

uint16_t femu_oc12_get_l2p_tbl(FemuCtrl *n, NvmeCmd *cmd, NvmeCqe *cqe)
{
    NvmeNamespace *ns;
    FEMU_OC12_GetL2PTbl *gtbl = (FEMU_OC12_GetL2PTbl*)cmd;
    uint64_t slba = le64_to_cpu(gtbl->slba);
    uint32_t nlb = le32_to_cpu(gtbl->nlb);
    uint64_t prp1 = le64_to_cpu(gtbl->prp1);
    uint64_t prp2 = le64_to_cpu(gtbl->prp2);
    uint32_t nsid = le32_to_cpu(gtbl->nsid);
    uint64_t xfer_len = nlb * sizeof(*(ns->tbl));

    if (nsid == 0 || nsid > n->num_namespaces) {
        return NVME_INVALID_NSID | NVME_DNR;
    }
    ns = &n->namespaces[nsid - 1];

    if (slba >= ns->tbl_entries) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if ((slba + nlb) > ns->tbl_entries) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (nvme_dma_read_prp(n, (uint8_t *)&ns->tbl[slba], xfer_len,
                          prp1, prp2)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    return NVME_SUCCESS;
}

uint16_t femu_oc12_bbt_get(FemuCtrl *n, NvmeCmd *cmd, NvmeCqe *cqe)
{
    NvmeNamespace *ns;
    FEMU_OC12_Ctrl *ln = &n->femu_oc12_ctrl;
    FEMU_OC12_IdGroup *c = &ln->id_ctrl.groups[0];
    FEMU_OC12_BbtGet *bbt_cmd = (FEMU_OC12_BbtGet*)cmd;

    uint32_t nsid = le32_to_cpu(bbt_cmd->nsid);
    uint64_t prp1 = le64_to_cpu(bbt_cmd->prp1);
    uint64_t prp2 = le64_to_cpu(bbt_cmd->prp2);
    uint64_t ppa = le64_to_cpu(bbt_cmd->spba);
    int blks_per_lun = c->num_blk * c->num_pln;
    int lun, ch, lunid;
    FEMU_OC12_Bbt *bbt;
    int ret = NVME_SUCCESS;

    if (nsid == 0 || nsid > n->num_namespaces) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ns = &n->namespaces[nsid - 1];
    ch = (ppa & ln->ppaf.ch_mask) >> ln->ppaf.ch_offset;
    lun = (ppa & ln->ppaf.lun_mask) >> ln->ppaf.lun_offset;
    lunid = ch * c->num_lun + lun;
    bbt = ns->bbtbl[lunid];

    if (nvme_dma_read_prp(n, (uint8_t*)bbt, sizeof(FEMU_OC12_Bbt) + blks_per_lun,
                prp1, prp2)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    return ret;
}

uint16_t femu_oc12_bbt_set(FemuCtrl *n, NvmeCmd *cmd, NvmeCqe *cqe)
{
    NvmeNamespace *ns;
    FEMU_OC12_Ctrl *ln = &n->femu_oc12_ctrl;
    FEMU_OC12_IdGroup *c = &ln->id_ctrl.groups[0];
    FEMU_OC12_BbtSet *bbt_cmd = (FEMU_OC12_BbtSet *)cmd;

    uint32_t nsid = le32_to_cpu(bbt_cmd->nsid);
    uint64_t prp2 = le64_to_cpu(bbt_cmd->prp2);
    uint32_t nlb  = le16_to_cpu(bbt_cmd->nlb) + 1;
    uint64_t spba = le64_to_cpu(bbt_cmd->spba);
    uint8_t value = bbt_cmd->value;
    uint64_t ppas[ln->params.max_sec_per_rq];
    int ch, lun, lunid, blk;
    int i;

    if (nsid == 0 || nsid > n->num_namespaces) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ns = &n->namespaces[nsid - 1];

    if (nlb == 1) {
        ppas[0] = spba;
        ch = (ppas[0] & ln->ppaf.ch_mask) >> ln->ppaf.ch_offset;
        lun = (ppas[0] & ln->ppaf.lun_mask) >> ln->ppaf.lun_offset;
        blk = (ppas[0] & ln->ppaf.blk_mask) >> ln->ppaf.blk_offset;
        lunid = ch * c->num_lun + lun;
        ns->bbtbl[lunid]->blk[blk] = value;

    } else {
        if (nvme_dma_write_prp(n, (uint8_t *)ppas, nlb * 8, spba, prp2)) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }

        for (i = 0; i < nlb; i++) {
            ch = (ppas[i] & ln->ppaf.ch_mask) >> ln->ppaf.ch_offset;
            lun = (ppas[i] & ln->ppaf.lun_mask) >> ln->ppaf.lun_offset;
            blk = (ppas[i] & ln->ppaf.blk_mask) >> ln->ppaf.blk_offset;
            lunid = ch * c->num_lun + lun;
            ns->bbtbl[lunid]->blk[blk] = value;
        }
    }

    return NVME_SUCCESS;
}

static int femu_oc12_read_tbls(FemuCtrl *n)
{
    uint32_t i;

    for (i = 0; i < n->num_namespaces; i++) {
        NvmeNamespace *ns = &n->namespaces[i];
        uint32_t tbl_size = femu_oc12_tbl_size(ns);
        femu_debug("tbl_size=%d\n", tbl_size);
        assert(tbl_size);
    }

    return 0;
}

int femu_oc12_flush_tbls(FemuCtrl *n)
{
    return 0;
}

uint16_t femu_oc12_erase_async(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req)
{
    FEMU_OC12_Ctrl *ln = &n->femu_oc12_ctrl;
    FEMU_OC12_RwCmd *dm = (FEMU_OC12_RwCmd *)cmd;
    uint64_t spba = le64_to_cpu(dm->spba);
    uint64_t psl[ln->params.max_sec_per_rq];
    uint32_t nlb = le16_to_cpu(dm->nlb) + 1;
    //int pmode = le16_to_cpu(dm->control) & (FEMU_OC12_PMODE_DUAL | FEMU_OC12_PMODE_QUAD);

    if (nlb > 1) {
        femu_nvme_addr_read(n, spba, (void *)psl, nlb * sizeof(void *));
    } else {
        psl[0] = spba;
    }

    req->slba = spba;
    req->meta_size = 0;
    req->status = NVME_SUCCESS;
    req->nlb = nlb;
    req->ns = ns;

    /* Coperd: consider this later */
#if 0
    if (femu_oc12_meta_blk_set_erased(ns, ln, psl, nlb, pmode)) {
        printf("femu_oc12_erase_async: failed: ");
        pr_ppa(ln, psl[0]);
        req->status = 0x40ff;

        return NVME_INVALID_FIELD | NVME_DNR;
    }
#endif

    int ch = (psl[0] & ln->ppaf.ch_mask) >> ln->ppaf.ch_offset;
    int lun = (psl[0] & ln->ppaf.lun_mask) >> ln->ppaf.lun_offset;
    //int num_ch = ln->id_ctrl.groups[0].num_ch;
    int num_lun = ln->id_ctrl.groups[0].num_lun;
    int lunid = ch * num_lun + lun;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);

    if (now < chip_next_avail_time[lunid]) {
        chip_next_avail_time[lunid] += nand_erase_t;
    } else {
        chip_next_avail_time[lunid] = now + nand_erase_t;
    }

    req->expire_time = chip_next_avail_time[lunid];

    req->status = NVME_SUCCESS;

    return NVME_SUCCESS;
}

static void femu_oc12_init_id_ctrl(FEMU_OC12_Ctrl *ln)
{
    FEMU_OC12_IdCtrl *ln_id = &ln->id_ctrl;

    ln_id->ver_id = 1;
    ln_id->dom = 0;
    ln_id->vmnt = 0;
    ln_id->cgrps = 1;
    ln_id->cap = cpu_to_le32(0x3);

    /* format: CHANNEL | LUN | BLOCK | PAGE | PLANE | SECTOR */

    ln_id->ppaf.sect_offset = 0;
    ln_id->ppaf.sect_len = qemu_fls(cpu_to_le16(ln->params.sec_per_pg) - 1);
    ln_id->ppaf.pln_offset = ln_id->ppaf.sect_offset + ln_id->ppaf.sect_len;
    ln_id->ppaf.pln_len = qemu_fls(cpu_to_le16(ln->params.num_pln) - 1);
    ln_id->ppaf.pg_offset = ln_id->ppaf.pln_offset + ln_id->ppaf.pln_len;
    ln_id->ppaf.pg_len = qemu_fls(cpu_to_le16(ln->params.pgs_per_blk) - 1);
    ln_id->ppaf.blk_offset = ln_id->ppaf.pg_offset + ln_id->ppaf.pg_len;
    ln_id->ppaf.blk_len = qemu_fls(cpu_to_le16(ln->id_ctrl.groups[0].num_blk) - 1);
    ln_id->ppaf.lun_offset = ln_id->ppaf.blk_offset + ln_id->ppaf.blk_len;
    ln_id->ppaf.lun_len = qemu_fls(cpu_to_le16(ln->params.num_lun) - 1);
    ln_id->ppaf.ch_offset = ln_id->ppaf.lun_offset + ln_id->ppaf.lun_len;
    ln_id->ppaf.ch_len = qemu_fls(cpu_to_le16(ln->params.num_ch) - 1);
}

static int femu_oc12_init_meta(FEMU_OC12_Ctrl *ln)
{
    /* Internal meta (state: ERASED / WRITTEN) */
    ln->int_meta_size = 4;

    /*
     * Internal meta are the first "ln->int_meta_size" bytes
     * Then comes the tgt_oob_len which is the following ln->param.sos bytes
     */
    ln->meta_len = ln->int_meta_size + ln->params.sos;
    ln->meta_tbytes = ln->meta_len * ln->params.total_secs;
    /* Coperd: we put all the meta data into this buffer */
    femu_debug("allocating meta_buf: %d MB\n", ln->meta_tbytes / 1024 / 1024);
    ln->meta_buf = g_malloc0(ln->meta_tbytes);
    if (!ln->meta_buf) {
        femu_err("meta buffer allocation failed!\n");
        exit(1);
    }
    memset(ln->meta_buf, FEMU_OC12_SEC_UNKNOWN, ln->meta_tbytes);

    return 0;
}

static int femu_oc12_bbtbl_init(FemuCtrl *n, NvmeNamespace *ns)
{
    FEMU_OC12_Ctrl *ln = &n->femu_oc12_ctrl;
    FEMU_OC12_IdGroup *c = &ln->id_ctrl.groups[0];
    uint32_t nr_tt_luns;
    uint32_t blks_per_lun;
    int i;
    int ret = 0;

    nr_tt_luns = c->num_ch * c->num_lun;
    blks_per_lun = c->num_blk * c->num_pln;

    ns->bbtbl = g_malloc0(sizeof(FEMU_OC12_Bbt *) * nr_tt_luns);
    if (!ns->bbtbl) {
        error_report("FEMU: cannot allocate ns->bbtbl list\n");
        return -ENOMEM;
    }

    for (i = 0; i < nr_tt_luns; i++) {
        /* Coperd: init per-lun bbtbl */
        FEMU_OC12_Bbt *bbt = g_malloc0(sizeof(FEMU_OC12_Bbt) + blks_per_lun);
        if (!bbt) {
            error_report("FEMU: cannot allocate bitmap for bad block table\n");
            ret = -ENOMEM;
            goto fail_bbt;
        }

        bbt->tblid[0] = 'B';
        bbt->tblid[1] = 'B';
        bbt->tblid[2] = 'L';
        bbt->tblid[3] = 'T';
        bbt->verid = cpu_to_le16(1);
        bbt->tblks = cpu_to_le32(blks_per_lun);

        ns->bbtbl[i] = bbt;
    }

    return ret;

fail_bbt:
    --i;
    for (; i >= 0; i--) {
        g_free(ns->bbtbl[i]);
    }
    g_free(ns->bbtbl);

    return ret;
}

int femu_oc12_init(FemuCtrl *n)
{
    FEMU_OC12_Ctrl *ln;
    FEMU_OC12_IdGroup *c;
    NvmeNamespace *ns;
    struct FEMU_OC12_IdAddrFormat *ppaf;
    FEMU_OC12_Params *lps;
    unsigned int i;
    uint64_t chnl_blks;
    int ret = 0;

    ln = &n->femu_oc12_ctrl;
    ppaf = &ln->id_ctrl.ppaf;
    lps = &ln->params;

    if (lps->mtype != 0)
        error_report("FEMU: Only NAND Flash Memory supported at the moment\n");

    if ((lps->num_pln > 4) || (lps->num_pln == 3))
        error_report("FEMU: Only 1/2/4-plane modes supported\n");

    for (i = 0; i < n->num_namespaces; i++) {
        ns = &n->namespaces[i];
        chnl_blks = ns->ns_blks / (lps->sec_per_pg * lps->pgs_per_blk) / lps->num_ch;

        femu_debug("chnl_blks=%" PRIu64 ",ns_blks=%" PRIu64
                ",sec_per_pg=%d,pgs_per_blk=%d\n", chnl_blks, ns->ns_blks,
                lps->sec_per_pg, lps->pgs_per_blk);

        c = &ln->id_ctrl.groups[0];
        c->mtype = lps->mtype;
        c->fmtype = lps->fmtype;
        c->num_ch = lps->num_ch;
        c->num_lun = lps->num_lun;
        c->num_pln = lps->num_pln;

        c->num_blk = cpu_to_le16(chnl_blks) / (c->num_lun * c->num_pln);
        c->num_pg = cpu_to_le16(lps->pgs_per_blk);
        c->csecs = cpu_to_le16(lps->sec_size);
        c->fpg_sz = cpu_to_le16(lps->sec_size * lps->sec_per_pg);
        c->sos = cpu_to_le16(lps->sos);

        femu_debug("num_ch=%d,num_lun=%d,num_pln=%d,num_blk=%d,num_pg=%d,"
                "pg_sz=%d,sos=%d,csecs=%d\n",
                c->num_ch, c->num_lun, c->num_pln, c->num_blk, c->num_pg,
                c->fpg_sz, c->sos, c->csecs);

        c->trdt = cpu_to_le32(40000);
        c->trdm = cpu_to_le32(80000);
        c->tprt = cpu_to_le32(1500000);
        c->tprm = cpu_to_le32(3700000);
        c->tbet = cpu_to_le32(6000000);
        c->tbem = cpu_to_le32(20000000);

        switch (c->num_pln) {
        case 1:
            c->mpos = cpu_to_le32(0x10101); /* single plane */
            break;
        case 2:
            c->mpos = cpu_to_le32(0x20202); /* dual plane */
            break;
        case 4:
            c->mpos = cpu_to_le32(0x40404); /* quad plane */
            break;
        default:
            error_report("FEMU: Invalid plane mode\n");
            return -EINVAL;
        }

        c->cpar = cpu_to_le16(0);
        c->mccap = 1;
        ret = femu_oc12_bbtbl_init(n, ns);
        if (ret)
            return ret;

        /* calculated values */
        lps->sec_per_pl = lps->sec_per_pg * c->num_pln;
        lps->sec_per_blk = lps->sec_per_pl * lps->pgs_per_blk;
        lps->sec_per_lun = lps->sec_per_blk * c->num_blk;
        lps->sec_per_ch = lps->sec_per_lun * c->num_lun;
        lps->total_secs = lps->sec_per_ch * c->num_ch;

        femu_debug("sec_per_pl=%d,sec_per_blk=%d,sec_per_lun=%d,total_secs=%d\n",
                lps->sec_per_pl, lps->sec_per_blk, lps->sec_per_lun,
                lps->total_secs);

        /* Calculated unit values for ordering */
        lps->pl_units = lps->sec_per_pg;
        lps->pg_units = lps->pl_units * c->num_pln;
        lps->blk_units = lps->pg_units * lps->pgs_per_blk;
        lps->lun_units = lps->blk_units * c->num_blk;
        lps->ch_units = lps->lun_units * c->num_lun;
        lps->total_units = lps->ch_units * c->num_ch;

        femu_debug("pl_units=%d,pg_units=%d,blk_units=%d,lun_units=%d,"
                "ch_units=%d,total_units=%d\n", lps->pl_units, lps->pg_units,
                lps->blk_units, lps->lun_units, lps->ch_units,
                lps->total_units);

        femu_oc12_init_id_ctrl(ln);

        /* Address format: CH | LUN | BLK | PG | PL | SEC */
        ln->ppaf.sec_offset = ppaf->sect_offset;
        ln->ppaf.pln_offset = ppaf->pln_offset;
        ln->ppaf.pg_offset = ppaf->pg_offset;
        ln->ppaf.blk_offset = ppaf->blk_offset;
        ln->ppaf.lun_offset = ppaf->lun_offset;
        ln->ppaf.ch_offset = ppaf->ch_offset;

        /* Address component selection MASK */
        ln->ppaf.sec_mask = ((1 << ppaf->sect_len) - 1) << ln->ppaf.sec_offset;
        ln->ppaf.pln_mask = ((1 << ppaf->pln_len) - 1) << ln->ppaf.pln_offset;
        ln->ppaf.pg_mask = ((1 << ppaf->pg_len) - 1) << ln->ppaf.pg_offset;
        ln->ppaf.blk_mask = ((1 << ppaf->blk_len) - 1) << ln->ppaf.blk_offset;
        ln->ppaf.lun_mask = ((1 << ppaf->lun_len) -1) << ln->ppaf.lun_offset;
        ln->ppaf.ch_mask = ((1 << ppaf->ch_len) - 1) << ln->ppaf.ch_offset;
    }

    femu_init_nand_low_upp_layout(n);

    ret = femu_oc12_init_meta(ln);
    if (ret) {
        error_report("FEMU: femu_oc12_init_meta: failed\n");
        return ret;
    }

    ret = (n->femu_oc12_ctrl.read_l2p_tbl) ? femu_oc12_read_tbls(n) : 0;
    if (ret) {
        error_report("FEMU: cannot read l2p table\n");
        return ret;
    }

    return 0;
}

void femu_oc12_exit(FemuCtrl *n)
{
    FEMU_OC12_Ctrl *ln = &n->femu_oc12_ctrl;

    /* Coperd: TODO */
    ln->metadata = NULL;
}
