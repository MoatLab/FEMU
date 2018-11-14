#include "qemu/osdep.h"
#include "block/block_int.h"
#include "block/qapi.h"
#include "exec/memory.h"
#include "hw/block/block.h"
#include "hw/hw.h"
#include "hw/pci/msix.h"
#include "hw/pci/msi.h"
#include "hw/pci/pci.h"
#include "qapi/visitor.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/bitops.h"
#include "qemu/bitmap.h"
#include "qom/object.h"
#include "sysemu/sysemu.h"
#include "sysemu/block-backend.h"
#include <qemu/main-loop.h>

#include "../nvme.h"
#include "god.h"
#include "femu-oc.h"

int is_upper_page(int pg);
void init_low_upp_layout(FemuCtrl *n);
//uint8_t femu_oc_dev(FemuCtrl *n);
//uint8_t femu_oc_hybrid_dev(FemuCtrl *n);
//uint16_t femu_oc_rw(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    //NvmeRequest *req);
//void femu_oc_post_cqe(FemuCtrl *n, NvmeCqe *cqe);
void print_ppa(FEMU_OC_Ctrl *ln, uint64_t ppa);
int femu_oc_meta_write(FEMU_OC_Ctrl *ln, void *meta);
int femu_oc_meta_read(FEMU_OC_Ctrl *ln, void *meta);
int64_t femu_oc_ppa_to_off(FEMU_OC_Ctrl *ln, uint64_t r);
int femu_oc_meta_state_get(FEMU_OC_Ctrl *ln, uint64_t ppa, uint32_t *state);
int femu_oc_meta_blk_set_erased(NvmeNamespace *ns, FEMU_OC_Ctrl *ln,
                                  uint64_t *psl, int nr_ppas, int pmode);
void femu_oc_erase_io_complete_cb(void *opaque, int ret);
int femu_oc_meta_state_set_written(FEMU_OC_Ctrl *ln, uint64_t ppa);
void femu_oc_init_id_ctrl(FEMU_OC_Ctrl *ln);
int femu_oc_init_meta(FEMU_OC_Ctrl *ln);
int femu_oc_bbtbl_init(FemuCtrl *n, NvmeNamespace *ns);

int64_t chip_next_avail_time[128]; /* Coperd: when chip will be not busy */
int64_t chnl_next_avail_time[16]; /* Coperd: when chnl will be free */

int secs_layout[64];

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

/* Coperd: L95B lower/upper page layout in one block */
void init_low_upp_layout(FemuCtrl *n)
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

int is_upper_page(int pg)
{
    return mlc_tbl[pg];
}

uint8_t femu_oc_dev(FemuCtrl *n)
{
    return (n->femu_oc_ctrl.id_ctrl.ver_id != 0);
}

void femu_oc_check_size(void)
{
    QEMU_BUILD_BUG_ON(sizeof(FEMU_OC_GetL2PTbl) != 64);
    QEMU_BUILD_BUG_ON(sizeof(FEMU_OC_BbtGet) != 64);
    QEMU_BUILD_BUG_ON(sizeof(FEMU_OC_BbtSet) != 64);
    QEMU_BUILD_BUG_ON(sizeof(FEMU_OC_RwCmd) != 64);
    QEMU_BUILD_BUG_ON(sizeof(FEMU_OC_DmCmd) != 64);
    QEMU_BUILD_BUG_ON(sizeof(FEMU_OC_IdCtrl) != 4096);
    QEMU_BUILD_BUG_ON(sizeof(FEMU_OC_IdAddrFormat) != 16);
    QEMU_BUILD_BUG_ON(sizeof(FEMU_OC_IdGroup) != 960);
}

uint8_t femu_oc_hybrid_dev(FemuCtrl *n)
{
    return (n->femu_oc_ctrl.id_ctrl.dom == 1);
}

void femu_oc_tbl_initialize(NvmeNamespace *ns)
{
    uint32_t len = ns->tbl_entries;
    uint32_t i;

    for (i = 0; i < len; i++)
        ns->tbl[i] = FEMU_OC_LBA_UNMAPPED;
}

void print_ppa(FEMU_OC_Ctrl *ln, uint64_t ppa)
{
    uint64_t ch = (ppa & ln->ppaf.ch_mask) >> ln->ppaf.ch_offset;
    uint64_t lun = (ppa & ln->ppaf.lun_mask) >> ln->ppaf.lun_offset;
    uint64_t blk = (ppa & ln->ppaf.blk_mask) >> ln->ppaf.blk_offset;
    uint64_t pg = (ppa & ln->ppaf.pg_mask) >> ln->ppaf.pg_offset;
    uint64_t pln = (ppa & ln->ppaf.pln_mask) >> ln->ppaf.pln_offset;
    uint64_t sec = (ppa & ln->ppaf.sec_mask) >> ln->ppaf.sec_offset;

    printf("    ppa: ch(%lu), lun(%lu), blk(%lu), pg(%lu), pl(%lu), sec(%lu)\n",
                                                    ch, lun, blk, pg, pln, sec);
}

/**
 * Write a single out-of-bound area entry
 *
 * NOTE: Ensure that `femu_oc_set_written_state` has been called prior to this
 * function to ensure correct file offset of ln->metadata?
 */
int femu_oc_meta_write(FEMU_OC_Ctrl *ln, void *meta)
{
#if 0
    FILE *meta_fp = ln->metadata;
    size_t tgt_oob_len = ln->params.sos;
    size_t ret;
#endif

    memcpy(ln->meta_buf, meta, ln->params.sos);
    return 0;

#if 0
    ret = fwrite(meta, tgt_oob_len, 1, meta_fp);
    if (ret != 1) {
        perror("femu_oc_meta_write: fwrite");
        return -1;
    }

    if (fflush(meta_fp)) {
        perror("femu_oc_meta_write: fflush");
        return -1;
    }

    return 0;
#endif
}

/**
 * Read a single out-of-bound area entry
 *
 * NOTE: Ensure that `femu_oc_meta_state_get` has been called to have the correct
 * file offset in ln->metadata?
 */
int femu_oc_meta_read(FEMU_OC_Ctrl *ln, void *meta)
{
#if 0
    FILE *meta_fp = ln->metadata;
    size_t tgt_oob_len = ln->params.sos;
    size_t ret;
#endif

    memcpy(meta, ln->meta_buf, ln->params.sos);
    return 0;

#if 0
    ret = fread(meta, tgt_oob_len, 1, meta_fp);
    if (ret != 1) {
        if (errno == EAGAIN)
            return 0;
        perror("femu_oc_meta_read: fread");
        return -1;
    }

    return 0;
#endif
}

int64_t femu_oc_ppa_to_off(FEMU_OC_Ctrl *ln, uint64_t r)
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
    //printf("Coperd,lun_units=%d,blk_units=%d,pg_units=%d,pl_units=%d\n", ln->params.lun_units, ln->params.blk_units, ln->params.pg_units, ln->params.pl_units);
    //printf("Coperd,femu_oc_ppa_to_off:(ppa:%ld,off:%ld) ppa OOB:ch:%lu,lun:%lu,blk:%lu,pg:%lu,pl:%lu,sec:%lu\n", r, off,
            //ch, lun, blk, pg, pln, sec);

    if (off > ln->params.total_units) {
        printf("ERROR femu_oc: ppa OOB:ch:%lu,lun:%lu,blk:%lu,pg:%lu,pl:%lu,sec:%lu\n",
                ch, lun, blk, pg, pln, sec);
        return -1;
    }

    return off;
}

int femu_oc_meta_state_get(FEMU_OC_Ctrl *ln, uint64_t ppa,
        uint32_t *state)
{
#if 0
    FILE *meta_fp = ln->metadata;
    size_t tgt_oob_len = ln->params.sos;
    size_t int_oob_len = ln->int_meta_size;
    size_t meta_len = tgt_oob_len + int_oob_len;
    size_t ret;
#endif
    uint32_t oft = ppa * ln->meta_len;

    assert(oft + ln->meta_len <= ln->meta_tbytes);
    /* Coperd: only need the internal oob area */
    memcpy(state, &ln->meta_buf[oft], ln->int_meta_size);
    return 0;

#if 0
    if (fseek(meta_fp, seek, SEEK_SET)) {
        perror("femu_oc_meta_state_get: fseek");
        printf("Could not seek to offset in metadata file\n");
        return -1;
    }

    ret = fread(state, int_oob_len, 1, meta_fp);
    //printf("Coperd,%s,fread-ret,%d\n", __func__, ret);
    if (ret != 1) {
        if (errno == EAGAIN) {
            //printf("femu_oc_meta_state_get: Why is this not an error?\n");
            return 0;
        }
        perror("femu_oc_meta_state_get: fread");
        printf("femu_oc_meta_state_get: ppa(%lu), ret(%lu)\n", ppa, ret);
        return -1;
    }

    return 0;
#endif
}

/**
 * Similar to femu_oc_meta_set_written, however, this function sets not a single
 * but multiple ppas, also checks if a block is marked bad
 */
int femu_oc_meta_blk_set_erased(NvmeNamespace *ns, FEMU_OC_Ctrl *ln,
                                  uint64_t *psl, int nr_ppas, int pmode)
{
    FEMU_OC_IdGroup *c = &ln->id_ctrl.groups[0];
#if 0
    struct femu_oc_metadata_format meta = {.state = FEMU_OC_SEC_ERASED};
    FILE *meta_fp = ln->metadata;
    size_t tgt_oob_len = ln->params.sos;
    size_t int_oob_len = ln->int_meta_size;
    size_t meta_len = tgt_oob_len + int_oob_len;
#endif
    int i;

    uint64_t mask = 0;

#if 0
    if (ln->strict && nr_ppas != 1) {
        printf("_erase_meta: Erase command unfolds on device\n");
        return NVME_INVALID_FIELD | NVME_DNR;
    }
#endif

    switch(pmode) {     // Check that pmode is supported
    case FEMU_OC_PMODE_DUAL:
        if (c->num_pln != 2) {
            printf("_erase_meta: Unsupported pmode(%d) for num_pln(%d)\n",
                   pmode, c->num_pln);
            return -1;
        }
        break;
    case FEMU_OC_PMODE_QUAD:
        if (c->num_pln != 4) {
            printf("_erase_meta: Unsupported pmode(%d) for num_pln(%d)\n",
                   pmode, c->num_pln);
            return -1;
        }
        break;
    case FEMU_OC_PMODE_SNGL:
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
            if (ns->bbtbl[femu_oc_bbt_pos_get(ln, ppa_pl)]) {
                printf("_erase_meta: failed -- block is bad\n");
                return -1;
            }
#endif


            /* Coperd: for now, we skip the checking */
#if 0
            // Check state of first sector to error on double-erase
            if (femu_oc_meta_state_get(ln, ppa_pl, &cur_state)) {
                printf("_erase_meta: failed: reading current state\n");
                return -1;
            }
            if (cur_state == FEMU_OC_SEC_ERASED) {
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
                    //print_ppa(ln, ppa_sec);
                    off = femu_oc_ppa_to_off(ln, ppa_sec);
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

int femu_oc_meta_state_set_written(FEMU_OC_Ctrl *ln, uint64_t ppa)
{
#if 0
    FILE *meta_fp = ln->metadata;
    size_t tgt_oob_len = ln->params.sos;
    size_t int_oob_len = ln->int_meta_size;
    size_t meta_len = tgt_oob_len + int_oob_len;
#endif
    uint32_t oft = ppa * ln->meta_len;
    uint32_t state;
    //size_t ret;

#if 0
    /* Coperd: TODO: is uint32_t safe for large meta ?? */
    if (femu_oc_meta_state_get(ln, ppa, &state)) {
        printf("_set_written: femu_oc_meta_state_get failed\n");
        return -1;
    }

    if (state != FEMU_OC_SEC_ERASED) {
        printf("_set_written: Invalid block state(%02x)\n", state);
        return -1;
    }
#endif

#if 0
    if (fseek(meta_fp, seek, SEEK_SET)) {
        perror("_set_written: fseek");
        return -1;
    }
#endif

    state = FEMU_OC_SEC_WRITTEN;
    memcpy(&ln->meta_buf[oft], &state, ln->int_meta_size);

#if 0
    ret = fwrite(&state, int_oob_len, 1, meta_fp);
    if (ret != 1) {
        perror("_set_written: fwrite");
        return -1;
    }

    if (fflush(meta_fp)) {
        perror("_set_written: fflush");
        return -1;
    }
#endif

    return 0;
}

static void *femu_oc_meta_index(FEMU_OC_Ctrl *ln, void *meta, uint32_t index)
{
    return meta + (index * ln->params.sos);
}

uint16_t femu_oc_rw(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req)
{
    FEMU_OC_Ctrl *ln = &n->femu_oc_ctrl;
    FEMU_OC_IdGroup *c = &ln->id_ctrl.groups[0];
    FEMU_OC_RwCmd *lrw = (FEMU_OC_RwCmd *)cmd;
    NvmeCqe *cqe = &req->cqe;
    uint64_t psl[ln->params.max_sec_per_rq];
    void *msl;
    uint64_t sppa;
    uint64_t eppa;
    uint64_t ppa;
    uint64_t aio_sector_list[ln->params.max_sec_per_rq];
    uint16_t nlb  = le16_to_cpu(lrw->nlb) + 1;
    uint64_t prp1 = le64_to_cpu(lrw->prp1);
    uint64_t prp2 = le64_to_cpu(lrw->prp2);
    uint64_t spba = le64_to_cpu(lrw->spba);
    uint64_t meta = le64_to_cpu(lrw->metadata);
    uint64_t gtsc = le64_to_cpu(lrw->rsvd2);
    const uint8_t lba_index = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    const uint8_t data_shift = ns->id_ns.lbaf[lba_index].ds;
    const uint16_t ms = le16_to_cpu(ns->id_ns.lbaf[lba_index].ms);
    uint64_t data_size = nlb << data_shift;
    uint64_t meta_size = nlb * ms;
    uint32_t n_pages = data_size / ln->params.sec_size;
    uint16_t is_write = (lrw->opcode == FEMU_OC_CMD_PHYS_WRITE ||
            lrw->opcode == FEMU_OC_CMD_HYBRID_WRITE);
    uint16_t ctrl = 0;
    uint16_t err;
    uint8_t i;
    int64_t overhead = 0;
    int64_t now;

    msl = g_malloc0(ln->params.sos * ln->params.max_sec_per_rq);
    if (!msl) {
        printf("femu_oc_rw: ENOMEM\n");
        return -ENOMEM;
    }

    if (n_pages > ln->params.max_sec_per_rq) {
        printf("femu_oc_rw: npages too large (%u). Max:%u supported\n",
                n_pages, ln->params.max_sec_per_rq);
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_LBA_RANGE,
                offsetof(FEMU_OC_RwCmd, spba), lrw->slba + nlb, ns->id);
        err = NVME_INVALID_FIELD | NVME_DNR;
        goto fail_free_msl;
    } else if ((is_write) && (!ln->id_ctrl.dom)
            && (n_pages < ln->params.sec_per_pl)) {
        printf("femu_oc_rw: I/O does not respect device write constrains."
                "Sectors send: (%u). Min:%u sectors required\n",
                n_pages, ln->params.sec_per_pl);
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_LBA_RANGE,
                offsetof(FEMU_OC_RwCmd, spba), lrw->slba + nlb, ns->id);
        err = NVME_INVALID_FIELD | NVME_DNR;
        goto fail_free_msl;
    } else if (n_pages > 1) {
        nvme_addr_read(n, spba, (void *)psl, n_pages * sizeof(void *));
    } else {
        psl[0] = spba;
    }

    if (spba == FEMU_OC_PBA_UNMAPPED) {
        printf("femu_oc_rw: unmapped PBA\n");
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_LBA_RANGE,
                offsetof(FEMU_OC_RwCmd, spba), lrw->slba + nlb, ns->id);
        err = NVME_INVALID_FIELD | NVME_DNR;
        goto fail_free_msl;
    }

    ctrl = le16_to_cpu(lrw->control);
#if 0
    int pmode = ctrl & (FEMU_OC_PMODE_DUAL|FEMU_OC_PMODE_QUAD);
    if (pmode == FEMU_OC_PMODE_DUAL) {
        printf("Coperd,femu_oc_rw,DUAL\n");
    } else {
        printf("Coperd,femu_oc_rw,SNGL\n");
    }
#endif
    req->femu_oc_ppa_list = psl;
    req->femu_oc_slba = le64_to_cpu(lrw->slba);
    req->is_write = is_write;
    if (gtsc > 0) {
        overhead = cyc2ns(rdtscp() + tsc_offset - gtsc);
    }

    sppa = psl[0];
    eppa = psl[n_pages - 1];
    if (sppa == -1 || eppa == -1) {
        printf("femu_oc_rw: EINVAL\n");
        err = -EINVAL;
        goto fail_free_msl;
    }

    /* Reuse check logic from nvme_rw */
    err = nvme_rw_check_req(n, ns, cmd, req, sppa, eppa, nlb, ctrl,
            data_size, meta_size);
    if (err) {
        printf("femu_oc_rw: failed nvme_rw_check\n");
        goto fail_free_msl;
    }

    if (meta && is_write)
        nvme_addr_read(n, meta, (void *)msl, n_pages * ln->params.sos);

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
            if (!femu_oc_hybrid_dev(n) && femu_oc_meta_state_set_written(ln, ppa)) {
                printf("femu_oc_rw: set written status failed\n");
                print_ppa(ln, psl[i]);
                err = NVME_INVALID_FIELD | NVME_DNR;
                goto fail_free_msl;
            }
#endif

            if (meta) {
                if (femu_oc_meta_write(ln, femu_oc_meta_index(ln, msl, i))) {
                    printf("femu_oc_rw: write metadata failed\n");
                    print_ppa(ln, psl[i]);
                    err = NVME_INVALID_FIELD | NVME_DNR;
                    goto fail_free_msl;
                }
            }
        } else if (!is_write){
            uint32_t state;

            if (!femu_oc_hybrid_dev(n) && femu_oc_meta_state_get(ln, ppa, &state)) {
                printf("femu_oc_rw: read status failed\n");
                print_ppa(ln, psl[i]);
                err = NVME_INVALID_FIELD | NVME_DNR;
                goto fail_free_msl;
            }

            if (state != FEMU_OC_SEC_WRITTEN) {
                bitmap_set(&cqe->res64, i, n_pages - i);
                req->status = 0x42ff;

                /* Copy what has been read from the OOB area */
                if (meta)
                    nvme_addr_write(n, meta, (void *)msl,
                            n_pages * ln->params.sos);
                err = 0x42ff;
                goto fail_free_msl;
            }

            if (meta) {
                if (femu_oc_meta_read(ln, femu_oc_meta_index(ln, msl, i))) {
                    printf("femu_oc_rw: read metadata failed\n");
                    print_ppa(ln, psl[i]);
                    err = NVME_INVALID_FIELD | NVME_DNR;
                    goto fail_free_msl;
                }
            }
        }
    }

    req->expire_time = qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + max - overhead;
    //printf("Coperd,should,%" PRId64 "\n", max);

	/* Coperd: TOFIX, fix the meta buf later. For now, comment out the part to
	 * mask LightNVM corrupted read LBA warnings */
#if 0
	if (meta && !is_write) nvme_addr_write(n, meta, (void *)msl, n_pages *
		ln->params.sos);
#endif

    g_free(msl);

    if (nvme_map_prp(&req->qsg, &req->iov, prp1, prp2, data_size, n)) {
        printf("femu_oc_rw: malformed prp (size:%lu), w:%d\n", data_size, is_write);

            nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
                    offsetof(NvmeRwCmd, prp1), 0, ns->id);
        err = NVME_INVALID_FIELD | NVME_DNR;
        goto fail_free_msl;
    }

    req->slba = sppa;
    req->meta_size = 0;
    req->status = NVME_SUCCESS;
    req->nlb = nlb;
    req->ns = ns;

    ///////////////////////////////////////////////////////////////////////////
    // should add DMA emulation through buffer here
    QEMUIOVector iov;
    int sg_cur_index = 0;
    dma_addr_t sg_cur_byte = 0;
    void *mem;
    dma_addr_t cur_addr, cur_len;
    DMADirection dir = req->is_write ? DMA_DIRECTION_TO_DEVICE : DMA_DIRECTION_FROM_DEVICE;
    qemu_iovec_init(&iov, req->qsg.nsg);

    // this is dma_blk_unmap()
    for (i = 0; i < iov.niov; ++i) {
        dma_memory_unmap(req->qsg.as, iov.iov[i].iov_base, iov.iov[i].iov_len,
                dir, iov.iov[i].iov_len);
    }
    qemu_iovec_reset(&iov);

    assert(req->qsg.nsg == n_pages);
    while (sg_cur_index < req->qsg.nsg) {
        cur_addr = req->qsg.sg[sg_cur_index].base + sg_cur_byte;
        cur_len = req->qsg.sg[sg_cur_index].len - sg_cur_byte;
        mem = dma_memory_map(req->qsg.as, cur_addr, &cur_len, dir);
        if (!mem) {
            printf("Coperd, holy crap!\n");
            break;
        }
        qemu_iovec_add(&iov, mem, cur_len);
        sg_cur_byte += cur_len;
        if (sg_cur_byte == req->qsg.sg[sg_cur_index].len) {
            sg_cur_byte = 0;
            ++sg_cur_index;
        }
    }

    if (iov.size == 0) {
        printf("Coperd, you poor boy, DMA mapping failed!\n");
    }

    if (!QEMU_IS_ALIGNED(iov.size, BDRV_SECTOR_SIZE)) {
        qemu_iovec_discard_back(&iov, QEMU_ALIGN_DOWN(iov.size, BDRV_SECTOR_SIZE));
    }

    // copy data from or write data to "heap_storage"
    // heap_storage[data_offset] .. heap_storage[data_offset+data_size]
    void *hs = n->mbe.mem_backend;
    for (i = 0; i < n_pages; i++) {
        int64_t hs_oft = aio_sector_list[i];
        if (req->is_write) {
            // iov -> heap storage
            memcpy(hs + hs_oft, iov.iov[i].iov_base, iov.iov[i].iov_len);
        } else {
            // heap storage -> iov
            memcpy(iov.iov[i].iov_base, hs + hs_oft, iov.iov[i].iov_len);
        }
    }

    // dma_blk_unmap()
    for (i = 0; i < iov.niov; ++i) {
        dma_memory_unmap(req->qsg.as, iov.iov[i].iov_base, iov.iov[i].iov_len,
                dir, iov.iov[i].iov_len);
    }
    qemu_iovec_reset(&iov);
    qemu_iovec_destroy(&iov);

    if (req->qsg.nsg) {
        qemu_sglist_destroy(&req->qsg);
    } else {
        qemu_iovec_destroy(&req->iov);
    }

    return NVME_SUCCESS;

fail_free_msl:
    g_free(msl);

    return err;
}

uint32_t femu_oc_tbl_size(NvmeNamespace *ns)
{
    return ns->tbl_entries * sizeof(*(ns->tbl));
}

uint16_t femu_oc_identity(FemuCtrl *n, NvmeCmd *cmd)
{
    NvmeIdentify *c = (NvmeIdentify *)cmd;
    uint32_t nsid = le32_to_cpu(c->nsid);
    uint64_t prp1 = le64_to_cpu(c->prp1);
    uint64_t prp2 = le64_to_cpu(c->prp2);

    if (nsid == 0 || nsid > n->num_namespaces) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    return nvme_dma_read_prp(n, (uint8_t *)&n->femu_oc_ctrl.id_ctrl,
                                    sizeof(FEMU_OC_IdCtrl), prp1, prp2);
}

uint16_t femu_oc_get_l2p_tbl(FemuCtrl *n, NvmeCmd *cmd, NvmeCqe *cqe)
{
    NvmeNamespace *ns;
    FEMU_OC_GetL2PTbl *gtbl = (FEMU_OC_GetL2PTbl*)cmd;
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

uint16_t femu_oc_bbt_get(FemuCtrl *n, NvmeCmd *cmd, NvmeCqe *cqe)
{
    NvmeNamespace *ns;
    FEMU_OC_Ctrl *ln = &n->femu_oc_ctrl;
    FEMU_OC_IdGroup *c = &ln->id_ctrl.groups[0];
    FEMU_OC_BbtGet *bbt_cmd = (FEMU_OC_BbtGet*)cmd;

    uint32_t nsid = le32_to_cpu(bbt_cmd->nsid);
    uint64_t prp1 = le64_to_cpu(bbt_cmd->prp1);
    uint64_t prp2 = le64_to_cpu(bbt_cmd->prp2);
    uint64_t ppa = le64_to_cpu(bbt_cmd->spba);
    int blks_per_lun = c->num_blk * c->num_pln;
    int lun, ch, lunid;
    FEMU_OC_Bbt *bbt;
    int ret = NVME_SUCCESS;

    if (nsid == 0 || nsid > n->num_namespaces) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ns = &n->namespaces[nsid - 1];
    ch = (ppa & ln->ppaf.ch_mask) >> ln->ppaf.ch_offset;
    lun = (ppa & ln->ppaf.lun_mask) >> ln->ppaf.lun_offset;
    lunid = ch * c->num_lun + lun;
    bbt = ns->bbtbl[lunid];

    if (nvme_dma_read_prp(n, (uint8_t*)bbt, sizeof(FEMU_OC_Bbt) + blks_per_lun,
                prp1, prp2)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    return ret;
}

uint16_t femu_oc_bbt_set(FemuCtrl *n, NvmeCmd *cmd, NvmeCqe *cqe)
{
    NvmeNamespace *ns;
    FEMU_OC_Ctrl *ln = &n->femu_oc_ctrl;
    FEMU_OC_IdGroup *c = &ln->id_ctrl.groups[0];
    FEMU_OC_BbtSet *bbt_cmd = (FEMU_OC_BbtSet *)cmd;

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

static int femu_oc_read_tbls(FemuCtrl *n)
{
    uint32_t i;

    for (i = 0; i < n->num_namespaces; i++) {
        NvmeNamespace *ns = &n->namespaces[i];
        uint32_t tbl_size = femu_oc_tbl_size(ns);
        printf("Coperd: tbl_size=%d\n", tbl_size);
        assert(tbl_size);
    }

    return 0;
}

int femu_oc_flush_tbls(FemuCtrl *n)
{
    return 0;
}

void femu_oc_erase_io_complete_cb(void *opaque, int ret)
{
    NvmeRequest *req = opaque;
    //NvmeSQueue *sq = req->sq;
    //FemuCtrl *n = sq->ctrl;
    //NvmeCQueue *cq = n->cq[sq->cqid];

    //block_acct_done(blk_get_stats(n->conf.blk), &req->acct);
    if (!ret) {
        req->status = NVME_SUCCESS;
    } else {
        req->status = 0x40ff;
    }

    //nvme_enqueue_req_completion_io(cq, req);
}

uint16_t femu_oc_erase_async(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req)
{
    FEMU_OC_Ctrl *ln = &n->femu_oc_ctrl;
    FEMU_OC_RwCmd *dm = (FEMU_OC_RwCmd *)cmd;
    uint64_t spba = le64_to_cpu(dm->spba);
    uint64_t psl[ln->params.max_sec_per_rq];
    uint32_t nlb = le16_to_cpu(dm->nlb) + 1;
    //int pmode = le16_to_cpu(dm->control) & (FEMU_OC_PMODE_DUAL | FEMU_OC_PMODE_QUAD);
    uint64_t gtsc = le64_to_cpu(dm->rsvd2);
    int64_t overhead = 0;
    if (gtsc > 0) {
        overhead = cyc2ns(rdtscp() + tsc_offset - gtsc);
    }

    if (nlb > 1) {
        nvme_addr_read(n, spba, (void *)psl, nlb * sizeof(void *));
    } else {
        psl[0] = spba;
    }

#if 0
    int i;
    for (i = 0; i < nlb; i++) {
        print_ppa(ln, psl[i]);
    }
#endif

    req->slba = spba;
    req->meta_size = 0;
    req->status = NVME_SUCCESS;
    req->nlb = nlb;
    req->ns = ns;

    /* Coperd: consider this later */
#if 0
    if (femu_oc_meta_blk_set_erased(ns, ln, psl, nlb, pmode)) {
        printf("femu_oc_erase_async: failed: ");
        print_ppa(ln, psl[0]);
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
    //printf("Coperd,in erase, meta ops time: %" PRId64 ", overhead=%" PRId64 "\n", now - req->st, overhead);
    if (now < chip_next_avail_time[lunid]) {
        chip_next_avail_time[lunid] += nand_erase_t;
    } else {
        chip_next_avail_time[lunid] = now + nand_erase_t;
    }

    req->expire_time = chip_next_avail_time[lunid] - overhead;
    //printf("Coperd,erase-need-to=%" PRId64 "\n", req->expire_time - now);

    req->status = NVME_SUCCESS;

    //femu_oc_erase_io_complete_cb(req, 0);
    return NVME_SUCCESS;
    //return NVME_NO_COMPLETE;
}

void femu_oc_init_id_ctrl(FEMU_OC_Ctrl *ln)
{
    FEMU_OC_IdCtrl *ln_id = &ln->id_ctrl;

    ln_id->ver_id = 1;
    ln_id->vmnt = 0;
    ln_id->cgrps = 1;
    ln_id->cap = cpu_to_le32(0x3);

    /* Previous format
    ln_id->ppaf.blk_offset = 0;
    ln_id->ppaf.blk_len = 12;
    ln_id->ppaf.pg_offset = ln_id->ppaf.blk_offset + ln_id->ppaf.blk_len;
    ln_id->ppaf.pg_len = qemu_fls(cpu_to_le16(ln->params.pgs_per_blk) - 1);
    ln_id->ppaf.sect_offset = ln_id->ppaf.pg_offset + ln_id->ppaf.pg_len;
    ln_id->ppaf.sect_len = qemu_fls(cpu_to_le16(ln->params.sec_per_pg) - 1);
    ln_id->ppaf.pln_offset = ln_id->ppaf.sect_offset + ln_id->ppaf.sect_len;
    ln_id->ppaf.pln_len = qemu_fls(cpu_to_le16(ln->params.num_pln) - 1);
    ln_id->ppaf.lun_offset = ln_id->ppaf.pln_offset + ln_id->ppaf.pln_len;
    ln_id->ppaf.lun_len = qemu_fls(cpu_to_le16(ln->params.num_lun) - 1);
    ln_id->ppaf.ch_offset = ln_id->ppaf.lun_offset + ln_id->ppaf.lun_len;
    ln_id->ppaf.ch_len = qemu_fls(cpu_to_le16(ln->params.num_ch) - 1);
    */

    /* new format: CHANNEL | LUN | BLOCK | PAGE | PLANE | SECTOR */

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

    //FEMU_OC_IdAddrFormat ppaf = ln_id->ppaf;
    //printf("Coperd,ppaf,ch_len=%d,ch_offset=%d,lun_len=%d,lun_offset=%d,blk_len=%d,blk_offset=%d,pg_len=%d,pg_offset=%d,pln_len=%d,pln_offset=%d,sec_len=%d,sec_offset=%d\n", ppaf.ch_len, ppaf.ch_offset, ppaf.lun_len, ppaf.lun_offset, ppaf.blk_len, ppaf.blk_offset, ppaf.pg_len, ppaf.pg_offset, ppaf.pln_len, ppaf.pln_offset, ppaf.sect_len, ppaf.sect_offset);
}

int femu_oc_init_meta(FEMU_OC_Ctrl *ln)
{
    //char *state = NULL;
    //struct stat buf;
    //size_t res;

    ln->int_meta_size = 4;      // Internal meta (state: ERASED / WRITTEN)

    //
    // Internal meta are the first "ln->int_meta_size" bytes
    // Then comes the tgt_oob_len with is the following ln->param.sos bytes
    //

    ln->meta_len = ln->int_meta_size + ln->params.sos;
    ln->meta_tbytes = ln->meta_len * ln->params.total_secs;
    /* Coperd: we put all the meta data into this buffer */
    printf("Coperd,allocating meta_buf: %d MB\n", ln->meta_tbytes/1024/1024);
    ln->meta_buf = malloc(ln->meta_tbytes);
    if (!ln->meta_buf) {
        printf("Coperd, meta buffer allocation failed!\n");
        exit(1);
    }
    memset(ln->meta_buf, FEMU_OC_SEC_UNKNOWN, ln->meta_tbytes);

#if 0
    if (!ln->meta_fname) {      // Default meta file
        ln->meta_auto_gen = 1;
        ln->meta_fname = malloc(10);
        if (!ln->meta_fname)
            return -ENOMEM;
        strncpy(ln->meta_fname, "meta.qemu\0", 10);
        printf("Coperd,femu_oc_init_meta, setting meta_fname=%s\n", ln->meta_fname);
    } else {
        ln->meta_auto_gen = 0;
    }

    ln->metadata = fopen(ln->meta_fname, "w+"); // Open the metadata file
    if (!ln->metadata) {
        error_report("nvme: femu_oc_init_meta: fopen(%s)\n", ln->meta_fname);
        return -EEXIST;
    }

    if (fstat(fileno(ln->metadata), &buf)) {
        error_report("nvme: femu_oc_init_meta: fstat(%s)\n", ln->meta_fname);
        return -1;
    }

    if (buf.st_size == meta_tbytes)             // All good
        return 0;

    printf("Coperd,meta file size != meta_tbytes[%ld]\n", meta_tbytes);
    //
    // Create meta-data file when it is empty or invalid
    //
    if (ftruncate(fileno(ln->metadata), 0)) {
        error_report("nvme: femu_oc_init_meta: ftrunca(%s)\n", ln->meta_fname);
        return -1;
    }

    state = malloc(meta_tbytes);
    if (!state) {
        error_report("nvme: femu_oc_init_meta: malloc f(%s)\n", ln->meta_fname);
        return -ENOMEM;
    }

    memset(state, FEMU_OC_SEC_UNKNOWN, meta_tbytes);

    printf("Coperd, init metadata file with all FEMU_OC_SEC_UNKNOWN\n");
    res = fwrite(state, 1, meta_tbytes, ln->metadata);

    free(state);

    if (res != meta_tbytes) {
        error_report("nvme: femu_oc_init_meta: fwrite(%s), res(%lu)\n",
                     ln->meta_fname, res);
        return -1;
     }

    rewind(ln->metadata);
#endif

    return 0;
 }

int femu_oc_bbtbl_init(FemuCtrl *n, NvmeNamespace *ns)
{
    FEMU_OC_Ctrl *ln = &n->femu_oc_ctrl;
    FEMU_OC_IdGroup *c = &ln->id_ctrl.groups[0];
    uint32_t nr_tt_luns;
    uint32_t blks_per_lun;
    int i;
    int ret = 0;

    nr_tt_luns = c->num_ch * c->num_lun;
    blks_per_lun = c->num_blk * c->num_pln;

    ns->bbtbl = g_malloc0(sizeof(FEMU_OC_Bbt *) * nr_tt_luns);
    if (!ns->bbtbl) {
        error_report("femu_oc: cannot allocate ns->bbtbl list\n");
        return -ENOMEM;
    }

    for (i = 0; i < nr_tt_luns; i++) {
        /* Coperd: init per-lun bbtbl */
        FEMU_OC_Bbt *bbt = g_malloc0(sizeof(FEMU_OC_Bbt) + blks_per_lun);
        if (!bbt) {
            error_report("femu_oc: cannot allocate bitmap for bad block table\n");
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

int femu_oc_init(FemuCtrl *n)
{
    FEMU_OC_Ctrl *ln;
    FEMU_OC_IdGroup *c;
    NvmeNamespace *ns;
    unsigned int i;
    uint64_t chnl_blks;
    int ret = 0;

    ln = &n->femu_oc_ctrl;

    if (ln->params.mtype != 0)
        error_report("nvme: Only NAND Flash Memory supported at the moment\n");
#if 0
    if (ln->params.fmtype != 0)
        error_report("nvme: Only SLC Flash is supported at the moment\n");
    if (ln->params.num_ch != 1)
        error_report("nvme: Only 1 channel is supported at the moment\n");
#endif
    if ((ln->params.num_pln > 4) || (ln->params.num_pln == 3))
        error_report("nvme: Only single, dual and quad plane modes supported \n");

    printf("Coperd,num_namespaces=%d\n", n->num_namespaces);
    for (i = 0; i < n->num_namespaces; i++) {
        ns = &n->namespaces[i];
        chnl_blks = ns->ns_blks / (ln->params.sec_per_pg * ln->params.pgs_per_blk) / ln->params.num_ch;
        printf("Coperd,chnl_blks=%" PRIu64 ",ns_blks=%" PRIu64 ",sec_per_pg=%d,pgs_per_blk=%d\n", chnl_blks, ns->ns_blks, ln->params.sec_per_pg, ln->params.pgs_per_blk);

        c = &ln->id_ctrl.groups[0];
        c->mtype = ln->params.mtype;
        c->fmtype = ln->params.fmtype;
        c->num_ch = ln->params.num_ch;
        c->num_lun = ln->params.num_lun;
        c->num_pln = ln->params.num_pln;

        c->num_blk = cpu_to_le16(chnl_blks) / (c->num_lun * c->num_pln);
        c->num_pg = cpu_to_le16(ln->params.pgs_per_blk);
        c->csecs = cpu_to_le16(ln->params.sec_size);
        c->fpg_sz = cpu_to_le16(ln->params.sec_size * ln->params.sec_per_pg);
        c->sos = cpu_to_le16(ln->params.sos);
        printf("Coperd,num_ch=%d,num_lun=%d,num_pln=%d,num_blk=%d,num_pg=%d,pg_sz=%d,sos=%d,csecs=%d\n", c->num_ch, c->num_lun, c->num_pln, c->num_blk, c->num_pg, c->fpg_sz, c->sos, c->csecs);

        c->trdt = cpu_to_le32(40000);
        c->trdm = cpu_to_le32(80000);
        c->tprt = cpu_to_le32(1900000);
        c->tprm = cpu_to_le32(3700000);
        c->tbet = cpu_to_le32(7000000);
        c->tbem = cpu_to_le32(20000000);

        switch(c->num_pln) {
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
                error_report("nvme: Invalid plane mode\n");
                return -EINVAL;
        }

        c->cpar = cpu_to_le16(0);
        c->mccap = 1;
        ret = femu_oc_bbtbl_init(n, ns);
        if (ret)
            return ret;

        /* We devide the address space linearly to be able to fit into the 4KB
         * sectors that the nvme driver divides the backend file. We do the
         * division in LUNS - BLOCKS - PLANES - PAGES - SECTORS.
         *
         * For example a quad plane configuration is layed out as:
         * -----------------------------------------------------------
         * |                        QUAD PLANE                       |
         * -------------- -------------- -------------- --------------
         * |   LUN 00   | |   LUN 01   | |   LUN 02   | |   LUN 03   |
         * -------------- -------------- -------------- --------------
         * |   BLOCKS            |          ...          |   BLOCKS  |
         * ----------------------
         * |   PLANES   |              ...               |   PLANES  |
         * -------------                                 -------------
         * | PAGES |                 ...                 |   PAGES   |
         * -----------------------------------------------------------
         * |                        ALL SECTORS                      |
         * -----------------------------------------------------------
         */

        /* calculated values */
        ln->params.sec_per_pl = ln->params.sec_per_pg * c->num_pln;
        ln->params.sec_per_blk = ln->params.sec_per_pl * ln->params.pgs_per_blk;
        ln->params.sec_per_lun = ln->params.sec_per_blk * c->num_blk;
        ln->params.sec_per_ch = ln->params.sec_per_lun * c->num_lun;
        ln->params.total_secs = ln->params.sec_per_ch * c->num_ch;
        printf("Coperd,sec_per_pl=%d,sec_per_blk=%d,sec_per_lun=%d,total_secs=%d\n", ln->params.sec_per_pl, ln->params.sec_per_blk, ln->params.sec_per_lun, ln->params.total_secs);

        /* Calculated unit values for ordering */
        ln->params.pl_units = ln->params.sec_per_pg;
        ln->params.pg_units = ln->params.pl_units * c->num_pln;
        ln->params.blk_units = ln->params.pg_units * ln->params.pgs_per_blk;
        ln->params.lun_units = ln->params.blk_units * c->num_blk;
        ln->params.ch_units = ln->params.lun_units * c->num_lun;
        ln->params.total_units = ln->params.ch_units * c->num_ch;
        printf("Coperd,pl_units=%d,pg_units=%d,blk_units=%d,lun_units=%d,ch_units=%d,total_units=%d\n", ln->params.pl_units, ln->params.pg_units, ln->params.blk_units, ln->params.lun_units, ln->params.ch_units, ln->params.total_units);

        femu_oc_init_id_ctrl(ln);
        /* Address format: CH | LUN | BLK | PG | PL | SEC */
        ln->ppaf.sec_offset = ln->id_ctrl.ppaf.sect_offset;
        ln->ppaf.pln_offset = ln->id_ctrl.ppaf.pln_offset;
        ln->ppaf.pg_offset = ln->id_ctrl.ppaf.pg_offset;
        ln->ppaf.blk_offset = ln->id_ctrl.ppaf.blk_offset;
        ln->ppaf.lun_offset = ln->id_ctrl.ppaf.lun_offset;
        ln->ppaf.ch_offset = ln->id_ctrl.ppaf.ch_offset;

        /* Address component selection MASK */
        ln->ppaf.sec_mask = ((1 << ln->id_ctrl.ppaf.sect_len) - 1) <<
            ln->ppaf.sec_offset;
        ln->ppaf.pln_mask = ((1 << ln->id_ctrl.ppaf.pln_len) - 1) <<
            ln->ppaf.pln_offset;
        ln->ppaf.pg_mask = ((1 << ln->id_ctrl.ppaf.pg_len) - 1) <<
            ln->ppaf.pg_offset;
        ln->ppaf.blk_mask = ((1 << ln->id_ctrl.ppaf.blk_len) - 1) <<
            ln->ppaf.blk_offset;
        ln->ppaf.lun_mask = ((1 << ln->id_ctrl.ppaf.lun_len) -1) <<
            ln->ppaf.lun_offset;
        ln->ppaf.ch_mask = ((1 << ln->id_ctrl.ppaf.ch_len) - 1) <<
            ln->ppaf.ch_offset;
    }

    init_low_upp_layout(n);

    ret = femu_oc_init_meta(ln);   // Initialize metadata file
    if (ret) {
        error_report("nvme: femu_oc_init_meta: failed\n");
        return ret;
    }

    printf("Coperd,read_l2p_tbl=%d\n", n->femu_oc_ctrl.read_l2p_tbl);
    ret = (n->femu_oc_ctrl.read_l2p_tbl) ? femu_oc_read_tbls(n) : 0;
    if (ret) {
        error_report("nvme: cannot read l2p table\n");
        return ret;
    }

    return 0;
}

void femu_oc_exit(FemuCtrl *n)
{
    FEMU_OC_Ctrl *ln = &n->femu_oc_ctrl;

    if (ln->bbt_auto_gen)
        free(ln->bbt_fname);
    if (ln->meta_auto_gen)
        free(ln->meta_fname);
    fclose(n->femu_oc_ctrl.bbt_fp);
    fclose(n->femu_oc_ctrl.metadata);
    n->femu_oc_ctrl.bbt_fp = NULL;
    n->femu_oc_ctrl.metadata = NULL;
}
