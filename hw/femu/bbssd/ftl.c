#include "ftl.h"

//#define FEMU_DEBUG_FTL

static void *ftl_thread(void *arg);

static inline bool should_gc(struct NvmeNamespace *ns)
{
    struct line_mgmt *lm = ns->lm;
    return ((*lm).free_line_cnt <= ns->sp.gc_thres_lines);
}

static inline bool should_gc_high(struct NvmeNamespace *ns)
{
    struct line_mgmt *lm = ns->lm;
    return ((*lm).free_line_cnt <= ns->sp.gc_thres_lines_high);
}

/* Must be dependent on Namespace policy */ 
static void set_ns_start_lpn(struct NvmeNamespace *ns)
{
    int lpn = 0;
    for( int i = 0 ; i < ns->id-1 ; i++){
        uint64_t ch = ns->ctrl->namespaces[i].sp.nchs;
        uint64_t pgs = ns->ctrl->namespaces[i].sp.pgs_per_ch;
        lpn += ch*pgs;
    }
    ns->start_lpn = lpn;
}

static uint64_t get_ns_start_lpn(struct NvmeNamespace *ns)
{
    return ns->start_lpn;
}
 
/* Maping Table Functions */
static inline struct ppa get_maptbl_ent(struct NvmeNamespace *ns, uint64_t lpn)
{
    struct ssd *ssd = (struct ssd*)ns->ssd;
    uint64_t lpn_margin = get_ns_start_lpn(ns);
    return ssd->maptbl[lpn+lpn_margin];
}

static inline void set_maptbl_ent(struct NvmeNamespace *ns, uint64_t lpn, struct ppa *ppa)
{
    struct ssd *ssd = (struct ssd*)ns->ssd;
    uint64_t lpn_margin = get_ns_start_lpn(ns);
    ftl_assert(lpn+lpn_margin < ssd->sp.tt_pgs);
    ssd->maptbl[lpn+lpn_margin] = *ppa;
}

static uint64_t ppa2pgidx(struct NvmeNamespace *ns, struct ppa *ppa)
{
    struct ssd *ssd = (struct ssd*)ns->ssd;
    struct ssdparams *spp = &ssd->sp;
    uint64_t pgidx;

    pgidx = ppa->g.ch  * spp->pgs_per_ch  + \
            ppa->g.lun * spp->pgs_per_lun + \
            ppa->g.pl  * spp->pgs_per_pl  + \
            ppa->g.blk * spp->pgs_per_blk + \
            ppa->g.pg;

    ftl_assert(pgidx < spp->tt_pgs);

    return pgidx;
}

static inline uint64_t get_rmap_ent(struct NvmeNamespace *ns, struct ppa *ppa)
{
    struct ssd *ssd = (struct ssd*)ns->ssd;
    uint64_t pgidx = ppa2pgidx(ns, ppa);
    uint64_t lpn_margin = get_ns_start_lpn(ns);

    return ssd->rmap[pgidx] - lpn_margin;
}

/* set rmap[page_no(ppa)] -> lpn */
static inline void set_rmap_ent(struct NvmeNamespace *ns, uint64_t lpn, struct ppa *ppa)
{
    struct ssd *ssd = (struct ssd*)ns->ssd;
    uint64_t pgidx = ppa2pgidx(ns, ppa);
    uint64_t lpn_margin = get_ns_start_lpn(ns);

    ssd->rmap[pgidx] = lpn + lpn_margin;
}

static inline int victim_line_cmp_pri(pqueue_pri_t next, pqueue_pri_t curr)
{
    return (next > curr);
}

static inline pqueue_pri_t victim_line_get_pri(void *a)
{
    return ((struct line *)a)->vpc;
}

static inline void victim_line_set_pri(void *a, pqueue_pri_t pri)
{
    ((struct line *)a)->vpc = pri;
}

static inline size_t victim_line_get_pos(void *a)
{
    return ((struct line *)a)->pos;
}

static inline void victim_line_set_pos(void *a, size_t pos)
{
    ((struct line *)a)->pos = pos;
}

static void ssd_init_lines(struct NvmeNamespace *ns)
{
    struct namespace_params *spp = &ns->sp;
    struct line_mgmt *lm = ns->lm;
    struct line *line;

    lm->tt_lines = spp->blks_per_pl;
    ftl_assert(lm->tt_lines == spp->tt_lines);
    lm->lines = g_malloc0(sizeof(struct line) * lm->tt_lines);

    QTAILQ_INIT(&lm->free_line_list);
    lm->victim_line_pq = pqueue_init(spp->tt_lines, victim_line_cmp_pri,
            victim_line_get_pri, victim_line_set_pri,
            victim_line_get_pos, victim_line_set_pos);
    QTAILQ_INIT(&lm->full_line_list);

    lm->free_line_cnt = 0;
    for (int i = 0; i < lm->tt_lines; i++) {
        line = &lm->lines[i];
        line->id = i;
        line->ipc = 0;
        line->vpc = 0;
        line->pos = 0;
        /* initialize all the lines as free lines */
        QTAILQ_INSERT_TAIL(&lm->free_line_list, line, entry);
        lm->free_line_cnt++;
    }

    ftl_assert(lm->free_line_cnt == lm->tt_lines);
    lm->victim_line_cnt = 0;
    lm->full_line_cnt = 0;
}

static void ssd_init_write_pointer(struct NvmeNamespace *ns)
{
    struct write_pointer *wpp = ns->wp;
    struct line_mgmt *lm = ns->lm;
    struct line *curline = NULL;

    curline = QTAILQ_FIRST(&lm->free_line_list);
    QTAILQ_REMOVE(&lm->free_line_list, curline, entry);
    lm->free_line_cnt--;

    /* wpp->curline is always our next-to-write super-block */
    wpp->curline = curline;
    wpp->ch = 0;
    wpp->lun = 0;
    wpp->pg = 0;
    wpp->blk = 0;
    wpp->pl = 0;
}

static inline void check_addr(int a, int max)
{
    ftl_assert(a >= 0 && a < max);
}

static struct line *get_next_free_line(struct NvmeNamespace *ns)
{
    struct line_mgmt *lm = ns->lm;
    struct line *curline = NULL;

    curline = QTAILQ_FIRST(&lm->free_line_list);
    if (!curline) {
        ftl_err("No free lines left in [nsid:%d] !!!!\n", ns->id);
        return NULL;
    }

    QTAILQ_REMOVE(&lm->free_line_list, curline, entry);
    lm->free_line_cnt--;
    return curline;
}

static void ssd_advance_write_pointer(struct NvmeNamespace *ns)
{
    struct namespace_params *spp = &ns->sp;
    struct write_pointer *wpp = ns->wp;
    struct line_mgmt *lm = ns->lm;

    check_addr(wpp->ch, spp->nchs);
    // if(ssd->ch[wpp->ch].next != NULL ){
    //     wpp->ch = ssd->ch[wpp->ch].next->id;
    // }else{
    wpp->ch++;
    if( wpp->ch == spp->nchs){
        wpp->ch = 0;
        check_addr(wpp->lun, spp->luns_per_ch);
        wpp->lun++;
        /* in this case, we should go to next lun */
        if (wpp->lun == spp->luns_per_ch) {
            wpp->lun = 0;
            /* go to next page in the block */
            check_addr(wpp->pg, spp->pgs_per_blk);
            wpp->pg++;
            if (wpp->pg == spp->pgs_per_blk) {
                wpp->pg = 0;
                /* move current line to {victim,full} line list */
                if (wpp->curline->vpc == spp->pgs_per_line) {
                    /* all pgs are still valid, move to full line list */
                    ftl_assert(wpp->curline->ipc == 0);
                    QTAILQ_INSERT_TAIL(&lm->full_line_list, wpp->curline, entry);
                    lm->full_line_cnt++;
                } else {
                    ftl_assert(wpp->curline->vpc >= 0 && wpp->curline->vpc < spp->pgs_per_line);
                    /* there must be some invalid pages in this line */
                    ftl_assert(wpp->curline->ipc > 0);
                    pqueue_insert(lm->victim_line_pq, wpp->curline);
                    lm->victim_line_cnt++;
                }
                /* current line is used up, pick another empty line */
                check_addr(wpp->blk, spp->blks_per_pl);
                wpp->curline = NULL;
                wpp->curline = get_next_free_line(ns);
                if (!wpp->curline) {
                    /* TODO */
                    abort();
                }
                wpp->blk = wpp->curline->id;    // <--!! critical point!! block id only
                check_addr(wpp->blk, spp->blks_per_pl);
                /* make sure we are starting from page 0 in the super block */
                ftl_assert(wpp->pg == 0);
                ftl_assert(wpp->lun == 0);
                ftl_assert(wpp->ch == 0);
                /* TODO: assume # of pl_per_lun is 1, fix later */
                ftl_assert(wpp->pl == 0);
            }
        }
    }
}

static void check_params(struct ssdparams *spp)
{
    /*
     * we are using a general write pointer increment method now, no need to
     * force luns_per_ch and nchs to be power of 2
     */

    //ftl_assert(is_power_of_2(spp->luns_per_ch));
    //ftl_assert(is_power_of_2(spp->nchs));
}


static void ssd_init_params(struct ssdparams *spp, FemuCtrl *n)
{
    spp->secsz = n->bb_params.secsz; // 512
    spp->secs_per_pg = n->bb_params.secs_per_pg; // 8
    spp->pgs_per_blk = n->bb_params.pgs_per_blk; //256
    spp->blks_per_pl = n->bb_params.blks_per_pl; /* 256 16GB */
    spp->pls_per_lun = n->bb_params.pls_per_lun; // 1
    spp->luns_per_ch = n->bb_params.luns_per_ch; // 8
    spp->nchs = n->bb_params.nchs; // 8

    spp->pg_rd_lat = n->bb_params.pg_rd_lat;
    spp->pg_wr_lat = n->bb_params.pg_wr_lat;
    spp->blk_er_lat = n->bb_params.blk_er_lat;
    spp->ch_xfer_lat = n->bb_params.ch_xfer_lat;

    /* calculated values */
    spp->secs_per_blk = spp->secs_per_pg * spp->pgs_per_blk;
    spp->secs_per_pl = spp->secs_per_blk * spp->blks_per_pl;
    spp->secs_per_lun = spp->secs_per_pl * spp->pls_per_lun;
    spp->secs_per_ch = spp->secs_per_lun * spp->luns_per_ch;
    spp->tt_secs = spp->secs_per_ch * spp->nchs;

    spp->pgs_per_pl = spp->pgs_per_blk * spp->blks_per_pl;
    spp->pgs_per_lun = spp->pgs_per_pl * spp->pls_per_lun;
    spp->pgs_per_ch = spp->pgs_per_lun * spp->luns_per_ch;
    spp->tt_pgs = spp->pgs_per_ch * spp->nchs;

    spp->blks_per_lun = spp->blks_per_pl * spp->pls_per_lun;
    spp->blks_per_ch = spp->blks_per_lun * spp->luns_per_ch;
    spp->tt_blks = spp->blks_per_ch * spp->nchs;

    spp->pls_per_ch =  spp->pls_per_lun * spp->luns_per_ch;
    spp->tt_pls = spp->pls_per_ch * spp->nchs;

    spp->tt_luns = spp->luns_per_ch * spp->nchs;

    /* line is special, put it at the end */
    spp->blks_per_line = spp->tt_luns; /* TODO: to fix under multiplanes */
    spp->pgs_per_line = spp->blks_per_line * spp->pgs_per_blk;
    spp->secs_per_line = spp->pgs_per_line * spp->secs_per_pg;
    spp->tt_lines = spp->blks_per_lun; /* TODO: to fix under multiplanes */

    spp->gc_thres_pcent = n->bb_params.gc_thres_pcent/100.0;
    spp->gc_thres_lines = (int)((1 - spp->gc_thres_pcent) * spp->tt_lines);
    spp->gc_thres_pcent_high = n->bb_params.gc_thres_pcent_high/100.0;
    spp->gc_thres_lines_high = (int)((1 - spp->gc_thres_pcent_high) * spp->tt_lines);
    spp->enable_gc_delay = true;


    check_params(spp);
}

static void namespace_init_params(struct namespace_params *spp, struct ssdparams *ssdp, uint64_t size)
{
    spp->secsz = ssdp->secsz;
    spp->secs_per_pg = ssdp->secs_per_pg;
    spp->pgs_per_blk = ssdp->pgs_per_blk;
    spp->blks_per_pl = ssdp->blks_per_pl;
    spp->pls_per_lun = ssdp->pls_per_lun;
    spp->luns_per_ch = ssdp->luns_per_ch;
    spp->nchs = (size/ssdp->secs_per_ch)/spp->secsz;

    spp->pg_rd_lat = NAND_READ_LATENCY;
    spp->pg_wr_lat = NAND_PROG_LATENCY;
    spp->blk_er_lat = NAND_ERASE_LATENCY;
    spp->ch_xfer_lat = 0;

    /* calculated values */
    spp->secs_per_blk   = ssdp->secs_per_blk;
    spp->secs_per_pl    = ssdp->secs_per_pl;
    spp->secs_per_lun   = ssdp->secs_per_lun;
    spp->secs_per_ch    = ssdp->secs_per_ch;

    spp->pgs_per_pl     = ssdp->pgs_per_pl;
    spp->pgs_per_lun    = ssdp->pgs_per_lun;
    spp->pgs_per_ch     = ssdp->pgs_per_ch;

    spp->blks_per_lun   = ssdp->blks_per_lun;
    spp->blks_per_ch    = ssdp->blks_per_ch;

    spp->pls_per_ch     = ssdp->pls_per_ch;

    spp->tt_secs    = spp->secs_per_ch  * spp->nchs;
    spp->tt_pgs     = spp->pgs_per_ch   * spp->nchs;
    spp->tt_blks    = spp->blks_per_ch  * spp->nchs;
    spp->tt_pls     = spp->pls_per_ch   * spp->nchs;
    spp->tt_luns    = spp->luns_per_ch  * spp->nchs;

    /* line is special, put it at the end */
    spp->blks_per_line  = spp->tt_luns; /* TODO: to fix under multiplanes */
    spp->pgs_per_line   = spp->blks_per_line * spp->pgs_per_blk;
    spp->secs_per_line  = spp->pgs_per_line * spp->secs_per_pg;
    spp->tt_lines       = spp->blks_per_lun; /* TODO: to fix under multiplanes */

    spp->gc_thres_pcent         = 0.75;
    spp->gc_thres_lines         = (int)((1 - spp->gc_thres_pcent) * spp->tt_lines);
    spp->gc_thres_pcent_high    = 0.95;
    spp->gc_thres_lines_high    = (int)((1 - spp->gc_thres_pcent_high) * spp->tt_lines);
    spp->enable_gc_delay        = true;
}

static void ssd_init_nand_page(struct nand_page *pg, struct ssdparams *spp)
{
    pg->nsecs = spp->secs_per_pg;
    pg->sec = g_malloc0(sizeof(nand_sec_status_t) * pg->nsecs);
    for (int i = 0; i < pg->nsecs; i++) {
        pg->sec[i] = SEC_FREE;
    }
    pg->status = PG_FREE;
}

static void ssd_init_nand_blk(struct nand_block *blk, struct ssdparams *spp)
{
    blk->npgs = spp->pgs_per_blk;
    blk->pg = g_malloc0(sizeof(struct nand_page) * blk->npgs);
    for (int i = 0; i < blk->npgs; i++) {
        ssd_init_nand_page(&blk->pg[i], spp);
    }
    blk->ipc = 0;
    blk->vpc = 0;
    blk->erase_cnt = 0;
    blk->wp = 0;
}

static void ssd_init_nand_plane(struct nand_plane *pl, struct ssdparams *spp)
{
    pl->nblks = spp->blks_per_pl;
    pl->blk = g_malloc0(sizeof(struct nand_block) * pl->nblks);
    for (int i = 0; i < pl->nblks; i++) {
        ssd_init_nand_blk(&pl->blk[i], spp);
    }
}

static void ssd_init_nand_lun(struct nand_lun *lun, struct ssdparams *spp)
{
    lun->npls = spp->pls_per_lun;
    lun->pl = g_malloc0(sizeof(struct nand_plane) * lun->npls);
    for (int i = 0; i < lun->npls; i++) {
        ssd_init_nand_plane(&lun->pl[i], spp);
    }
    lun->next_lun_avail_time = 0;
    lun->busy = false;
}

static void ssd_init_ch(struct ssd_channel *ch, struct ssdparams *spp)
{
    ch->nluns = spp->luns_per_ch;
    ch->lun = g_malloc0(sizeof(struct nand_lun) * ch->nluns);
    for (int i = 0; i < ch->nluns; i++) {
        ssd_init_nand_lun(&ch->lun[i], spp);
    }
    ch->next_ch_avail_time = 0;
    ch->busy = 0;
}

static void ssd_init_maptbl(struct ssd *ssd)
{
    struct ssdparams *spp = &ssd->sp;

    ssd->maptbl = g_malloc0(sizeof(struct ppa) * spp->tt_pgs);
    for (int i = 0; i < spp->tt_pgs; i++) {
        ssd->maptbl[i].ppa = UNMAPPED_PPA;
    }
}

static void ssd_init_rmap(struct ssd *ssd)
{
    struct ssdparams *spp = &ssd->sp;

    ssd->rmap = g_malloc0(sizeof(uint64_t) * spp->tt_pgs);
    for (int i = 0; i < spp->tt_pgs; i++) {
        ssd->rmap[i] = INVALID_LPN;
    }
}

void ssd_init(FemuCtrl *n)
{
    struct ssd *ssd = n->ssd;
    struct ssdparams *spp = &ssd->sp;

    ftl_assert(ssd);

    ssd_init_params(spp, n);

    /* initialize ssd internal layout architecture */
    ssd->ch = g_malloc0(sizeof(struct ssd_channel) * spp->nchs);
    for (int i = 0; i < spp->nchs; i++) {
        ssd_init_ch(&ssd->ch[i], spp);
    }

    /* initialize maptbl */
    ssd_init_maptbl(ssd);

    /* initialize rmap */
    ssd_init_rmap(ssd);

    // assign first ch to first namespace
    n->namespaces[0].start_ch_idx = 0;
    for( int  i = 0; i < n->num_namespaces ; i ++){
        n->namespaces[i].ssd = ssd;
        n->namespaces[i].lm = g_malloc0(sizeof(struct write_pointer));
        n->namespaces[i].wp = g_malloc0(sizeof(struct line_mgmt));
        namespace_init_params(&n->namespaces[i].sp, spp, n->namespaces[i].size);

        // assign rest ch to rest namespace
        if( i > 0 ){
            n->namespaces[i].start_ch_idx = n->namespaces[i-1].start_ch_idx + n->namespaces[i-1].sp.nchs;
        }
        set_ns_start_lpn(&n->namespaces[i]);
        ssd_init_lines(&n->namespaces[i]);
        ssd_init_write_pointer(&n->namespaces[i]);
    }

    qemu_thread_create(&ssd->ftl_thread, "FEMU-FTL-Thread", ftl_thread, n,
                       QEMU_THREAD_JOINABLE);
}

static inline bool valid_ppa(struct NvmeNamespace *ns, struct ppa *ppa)
{
    struct ssd *ssd = (struct ssd *)ns->ssd;
    struct ssdparams *spp = &ssd->sp;
    int ch = ppa->g.ch;
    int lun = ppa->g.lun;
    int pl = ppa->g.pl;
    int blk = ppa->g.blk;
    int pg = ppa->g.pg;
    int sec = ppa->g.sec;

    if (ch >= 0 && ch < spp->nchs && lun >= 0 && lun < spp->luns_per_ch && pl >=
        0 && pl < spp->pls_per_lun && blk >= 0 && blk < spp->blks_per_pl && pg
        >= 0 && pg < spp->pgs_per_blk && sec >= 0 && sec < spp->secs_per_pg)
        return true;

    return false;
}

static inline bool valid_lpn(struct NvmeNamespace *ns, uint64_t lpn)
{
    return (lpn < ns->sp.tt_pgs);
}

static inline bool mapped_ppa(struct ppa *ppa)
{
    return !(ppa->ppa == UNMAPPED_PPA);
}

static inline struct ssd_channel *get_ch(struct NvmeNamespace *ns, struct ppa *ppa)
{
    struct ssd *ssd = (struct ssd*)ns->ssd;
    return &(ssd->ch[ppa->g.ch]);
}

static inline struct nand_lun *get_lun(struct NvmeNamespace *ns, struct ppa *ppa)
{
    struct ssd_channel *ch = get_ch(ns, ppa);
    return &(ch->lun[ppa->g.lun]);
}

static inline struct nand_plane *get_pl(struct NvmeNamespace *ns, struct ppa *ppa)
{
    struct nand_lun *lun = get_lun(ns, ppa);
    return &(lun->pl[ppa->g.pl]);
}

static inline struct nand_block *get_blk(struct NvmeNamespace *ns, struct ppa *ppa)
{
    struct nand_plane *pl = get_pl(ns, ppa);
    return &(pl->blk[ppa->g.blk]);
}

static inline struct line *get_line(NvmeNamespace *ns, struct ppa *ppa)
{
    struct line_mgmt *lm = ns->lm;
    return &((*lm).lines[ppa->g.blk]);
}

static inline struct nand_page *get_pg(struct NvmeNamespace *ns, struct ppa *ppa)
{
    struct nand_block *blk = get_blk(ns, ppa);
    return &(blk->pg[ppa->g.pg]);
}

static uint64_t ssd_advance_status(struct NvmeNamespace *ns, struct ppa *ppa, struct
        nand_cmd *ncmd)
{
    int c = ncmd->cmd;
    uint64_t cmd_stime = (ncmd->stime == 0) ? \
        qemu_clock_get_ns(QEMU_CLOCK_REALTIME) : ncmd->stime;
    uint64_t nand_stime;
    struct namespace_params *spp = &ns->sp;
    struct nand_lun *lun = get_lun(ns, ppa);
    uint64_t lat = 0;

    switch (c) {
    case NAND_READ:
        /* read: perform NAND cmd first */
        nand_stime = (lun->next_lun_avail_time < cmd_stime) ? cmd_stime : \
                     lun->next_lun_avail_time;
        lun->next_lun_avail_time = nand_stime + spp->pg_rd_lat;
        lat = lun->next_lun_avail_time - cmd_stime;

        break;

    case NAND_WRITE:
        /* write: transfer data through channel first */
        nand_stime = (lun->next_lun_avail_time < cmd_stime) ? cmd_stime : \
                     lun->next_lun_avail_time;
        if (ncmd->type == USER_IO) {
            lun->next_lun_avail_time = nand_stime + spp->pg_wr_lat;
        } else {
            lun->next_lun_avail_time = nand_stime + spp->pg_wr_lat;
        }
        lat = lun->next_lun_avail_time - cmd_stime;

        break;

    case NAND_ERASE:
        /* erase: only need to advance NAND status */
        nand_stime = (lun->next_lun_avail_time < cmd_stime) ? cmd_stime : \
                     lun->next_lun_avail_time;
        lun->next_lun_avail_time = nand_stime + spp->blk_er_lat;

        lat = lun->next_lun_avail_time - cmd_stime;
        break;

    default:
        ftl_err("Unsupported NAND command: 0x%x\n", c);
    }

    return lat;
}

static struct ppa get_new_page(struct NvmeNamespace *ns)
{
    struct write_pointer *wpp = ns->wp;
    struct ppa ppa;


    ppa.ppa = 0;
    ppa.g.ch = wpp->ch;
    ppa.g.lun = wpp->lun;
    ppa.g.pg = wpp->pg;
    ppa.g.blk = wpp->blk;
    ppa.g.pl = wpp->pl;
    ftl_assert(ppa.g.pl == 0);

    return ppa;
}

/* update SSD status about one page from PG_VALID -> PG_VALID */
static void mark_page_invalid(struct NvmeNamespace *ns, struct ppa *ppa)
{
    struct line_mgmt *lm = ns->lm;
    struct namespace_params *spp = &ns->sp;
    struct nand_block *blk = NULL;
    struct nand_page *pg = NULL;
    bool was_full_line = false;
    struct line *line;

    /* update corresponding page status */
    pg = get_pg(ns, ppa);
    ftl_assert(pg->status == PG_VALID);
    pg->status = PG_INVALID;

    /* update corresponding block status */
    blk = get_blk(ns, ppa);
    ftl_assert(blk->ipc >= 0 && blk->ipc < spp->pgs_per_blk);
    blk->ipc++;
    ftl_assert(blk->vpc > 0 && blk->vpc <= spp->pgs_per_blk);
    blk->vpc--;

    /* update corresponding line status */
    line = get_line(ns, ppa);
    ftl_assert(line->ipc >= 0 && line->ipc < spp->pgs_per_line);
    if (line->vpc == spp->pgs_per_line) {
        ftl_assert(line->ipc == 0);
        was_full_line = true;
    }
    line->ipc++;
    ftl_assert(line->vpc > 0 && line->vpc <= spp->pgs_per_line);
    /* Adjust the position of the victime line in the pq under over-writes */
    if (line->pos) {
        /* Note that line->vpc will be updated by this call */
        pqueue_change_priority(lm->victim_line_pq, line->vpc - 1, line);
    } else {
        line->vpc--;
    }

    if (was_full_line) {
        /* move line: "full" -> "victim" */
        QTAILQ_REMOVE(&lm->full_line_list, line, entry);
        lm->full_line_cnt--;
        pqueue_insert(lm->victim_line_pq, line);
        lm->victim_line_cnt++;
    }
}

static void mark_page_valid(struct NvmeNamespace *ns, struct ppa *ppa)
{
    struct nand_block *blk = NULL;
    struct nand_page *pg = NULL;
    struct line *line;

    /* update page status */
    pg = get_pg(ns, ppa);
    ftl_assert(pg->status == PG_FREE);
    pg->status = PG_VALID;

    /* update corresponding block status */
    blk = get_blk(ns, ppa);
    ftl_assert(blk->vpc >= 0 && blk->vpc < ns->sp.pgs_per_blk);
    blk->vpc++;

    /* update corresponding line status */
    line = get_line(ns, ppa);
    ftl_assert(line->vpc >= 0 && line->vpc < ns->sp.pgs_per_line);
    line->vpc++;
}

static void mark_block_free(struct NvmeNamespace *ns, struct ppa *ppa)
{
    struct namespace_params *spp = &ns->sp;
    struct nand_block *blk = get_blk(ns, ppa);
    struct nand_page *pg = NULL;

    for (int i = 0; i < spp->pgs_per_blk; i++) {
        /* reset page status */
        pg = &blk->pg[i];
        ftl_assert(pg->nsecs == spp->secs_per_pg);
        pg->status = PG_FREE;
    }

    /* reset block status */
    ftl_assert(blk->npgs == spp->pgs_per_blk);
    blk->ipc = 0;
    blk->vpc = 0;
    blk->erase_cnt++;
}

static void gc_read_page(NvmeNamespace *ns, struct ppa *ppa)
{
    /* advance ssd status, we don't care about how long it takes */
    if (ns->sp.enable_gc_delay) {
        struct nand_cmd gcr;
        gcr.type = GC_IO;
        gcr.cmd = NAND_READ;
        gcr.stime = 0;
        ssd_advance_status(ns, ppa, &gcr);
    }
}

/* move valid page data (already in DRAM) from victim line to a new page */
static uint64_t gc_write_page(struct NvmeNamespace *ns, struct ppa *old_ppa)
{
    struct ppa new_ppa;
    struct nand_lun *new_lun;
    uint64_t lpn = get_rmap_ent(ns, old_ppa);

    ftl_assert(valid_lpn(ns, lpn));
    new_ppa = get_new_page(ns);
    /* update maptbl */
    set_maptbl_ent(ns, lpn, &new_ppa);
    /* update rmap */
    set_rmap_ent(ns, lpn, &new_ppa);

    mark_page_valid(ns, &new_ppa);

    /* need to advance the write pointer here */
    ssd_advance_write_pointer(ns);

    if (ns->sp.enable_gc_delay) {
        struct nand_cmd gcw;
        gcw.type = GC_IO;
        gcw.cmd = NAND_WRITE;
        gcw.stime = 0;
        ssd_advance_status(ns, &new_ppa, &gcw);
    }

    new_lun = get_lun(ns, &new_ppa);
    new_lun->gc_endtime = new_lun->next_lun_avail_time;

    return 0;
}

static struct line *select_victim_line(struct NvmeNamespace *ns, bool force)
{
    struct line_mgmt *lm = ns->lm;
    struct line *victim_line = NULL;

    victim_line = pqueue_peek(lm->victim_line_pq);
    if (!victim_line) {
        return NULL;
    }

    if (!force && victim_line->ipc < ns->sp.pgs_per_line / 8) {
        return NULL;
    }

    pqueue_pop(lm->victim_line_pq);
    victim_line->pos = 0;
    lm->victim_line_cnt--;

    /* victim_line is a danggling node now */
    return victim_line;
}

/* here ppa identifies the block we want to clean */
static void clean_one_block(struct NvmeNamespace *ns, struct ppa *ppa)
{
    struct namespace_params *spp = &ns->sp;
    struct nand_page *pg_iter = NULL;
    int cnt = 0;

    for (int pg = 0; pg < spp->pgs_per_blk; pg++) {
        ppa->g.pg = pg;
        pg_iter = get_pg(ns, ppa);
        /* there shouldn't be any free page in victim blocks */
        // ftl_assert(pg_iter->status != PG_FREE);  // not suitable for wear-leveling 
        if (pg_iter->status == PG_VALID) {
            gc_read_page(ns, ppa);
            /* delay the maptbl update until "write" happens */
            gc_write_page(ns, ppa);
            cnt++;
        }
    }

    ftl_assert(get_blk(ns, ppa)->vpc == cnt);
}

static void mark_line_free(struct NvmeNamespace *ns, struct ppa *ppa)
{
    struct line_mgmt *lm = ns->lm;
    struct line *line = get_line(ns, ppa);
    line->ipc = 0;
    line->vpc = 0;
    /* move this line to free line list */
    QTAILQ_INSERT_TAIL(&lm->free_line_list, line, entry);
    lm->free_line_cnt++;
}

static void free_line(struct NvmeNamespace *ns, int id)
{    
    struct namespace_params *spp = &ns->sp;
    struct nand_lun *lunp;
    struct ppa ppa;
    int ch, lun;
    ppa.g.blk = id;

    /* copy back valid data */
    for (ch = 0; ch < spp->nchs; ch++) {
        for (lun = 0; lun < spp->luns_per_ch; lun++) {
            ppa.g.ch = ch;
            ppa.g.lun = lun;
            ppa.g.pl = 0;
            lunp = get_lun(ns, &ppa);
            clean_one_block(ns, &ppa);
            mark_block_free(ns, &ppa);

            if (spp->enable_gc_delay) {
                struct nand_cmd gce;
                gce.type = GC_IO;
                gce.cmd = NAND_ERASE;
                gce.stime = 0;
                ssd_advance_status(ns, &ppa, &gce);
            }

            lunp->gc_endtime = lunp->next_lun_avail_time;
        }
    }

    /* update line status */
    mark_line_free(ns, &ppa);
}
static int do_gc(struct NvmeNamespace *ns, bool force)
{
    struct line *victim_line = NULL;
    victim_line = select_victim_line(ns, force);
    if (!victim_line) {
        return -1;
    }

    free_line(ns, victim_line->id);

    return 0;
}

static uint64_t ssd_read(struct ssd *ssd, NvmeRequest *req)
{
    struct NvmeNamespace * ns = req->ns;        // <- get Namespace!!
    struct namespace_params *spp = &ns->sp;
    uint64_t lba = req->slba;
    int nsecs = req->nlb;
    struct ppa ppa;
    uint64_t start_lpn = lba / spp->secs_per_pg;
    uint64_t end_lpn = (lba + nsecs - 1) / spp->secs_per_pg;
    uint64_t lpn;
    uint64_t sublat, maxlat = 0;

    if (end_lpn >= spp->tt_pgs) {
        ftl_err("start_lpn=%"PRIu64",tt_pgs=%d\n", start_lpn, ns->sp.tt_pgs);
    }

    /* normal IO read path */
    for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
        ppa = get_maptbl_ent(ns, lpn);
        if (!mapped_ppa(&ppa) || !valid_ppa(ns, &ppa)) {
            //printf("%s,lpn(%" PRId64 ") not mapped to valid ppa\n", ssd->ssdname, lpn);
            //printf("Invalid ppa,ch:%d,lun:%d,blk:%d,pl:%d,pg:%d,sec:%d\n",
            //ppa.g.ch, ppa.g.lun, ppa.g.blk, ppa.g.pl, ppa.g.pg, ppa.g.sec);
            continue;
        }        
        struct nand_cmd srd;
        srd.type = USER_IO;
        srd.cmd = NAND_READ;
        srd.stime = req->stime;
        sublat = ssd_advance_status(ns, &ppa, &srd);
        maxlat = (sublat > maxlat) ? sublat : maxlat;
    }

    return maxlat;
}

static uint64_t ssd_write(struct ssd *ssd, NvmeRequest *req)
{
    uint64_t lba = req->slba;
    struct NvmeNamespace * ns = req->ns;        // <- get Namespace!!
    struct namespace_params *spp = &ns->sp;
    int len = req->nlb;
    uint64_t start_lpn = lba / spp->secs_per_pg;
    uint64_t end_lpn = (lba + len - 1) / spp->secs_per_pg;
    struct ppa ppa;
    uint64_t lpn;
    uint64_t curlat = 0, maxlat = 0;
    int r;

    if (end_lpn >= spp->tt_pgs) {
        ftl_err("start_lpn=%"PRIu64",tt_pgs=%d\n", start_lpn, ns->sp.tt_pgs);
    }

    while (should_gc_high(ns)) {
        /* perform GC here until !should_gc(ssd) */
        r = do_gc(ns, true);
        if (r == -1)
            break;
    }

    for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
        ppa = get_maptbl_ent(ns, lpn);
        if (mapped_ppa(&ppa)) {
            /* update old page information first */
            mark_page_invalid(ns, &ppa);
            set_rmap_ent(ns, INVALID_LPN, &ppa);
        }

        /* new write */
        ppa = get_new_page(ns);
        /* update maptbl */
        set_maptbl_ent(ns, lpn, &ppa);
        /* update rmap */
        set_rmap_ent(ns, lpn, &ppa);

        mark_page_valid(ns, &ppa);

        /* need to advance the write pointer here */
        ssd_advance_write_pointer(ns);

        struct nand_cmd swr;
        swr.type = USER_IO;
        swr.cmd = NAND_WRITE;
        swr.stime = req->stime;
        /* get latency statistics */
        curlat = ssd_advance_status(ns, &ppa, &swr);
        maxlat = (curlat > maxlat) ? curlat : maxlat;
    }

    return maxlat;
}

static void *ftl_thread(void *arg)
{
    FemuCtrl *n = (FemuCtrl *)arg;
    struct ssd *ssd = n->ssd;
    NvmeRequest *req = NULL;
    uint64_t lat = 0;
    int rc;
    int i;

    while (!*(ssd->dataplane_started_ptr)) {
        usleep(100000);
    }

    /* FIXME: not safe, to handle ->to_ftl and ->to_poller gracefully */
    ssd->to_ftl = n->to_ftl;
    ssd->to_poller = n->to_poller;

    while (1) {
        for (i = 1; i <= n->nr_pollers; i++) {
            if (!ssd->to_ftl[i] || !femu_ring_count(ssd->to_ftl[i]))
                continue;

            rc = femu_ring_dequeue(ssd->to_ftl[i], (void *)&req, 1);
            if (rc != 1) {
                printf("FEMU: FTL to_ftl dequeue failed\n");
            }

            ftl_assert(req);

            // struct NvmeNamespace *ns = req->ns;
            switch (req->cmd.opcode) {
            case NVME_CMD_WRITE:
                lat = ssd_write(ssd, req);
                break;
            case NVME_CMD_READ:
                lat = ssd_read(ssd, req);
                break;
            case NVME_CMD_DSM:
                lat = 0;
                break;
            default:
                //ftl_err("FTL received unkown request type, ERROR\n");
                ;
            }

            req->reqlat = lat;
            req->expire_time += lat;

            rc = femu_ring_enqueue(ssd->to_poller[i], (void *)&req, 1);
            if (rc != 1) {
                ftl_err("FTL to_poller enqueue failed\n");
            }

            /* clean one line if needed (in the background) */
            for (int i = 0; i < n->num_namespaces; i++)
            {
                if (should_gc(&n->namespaces[i])) {
                    do_gc(&n->namespaces[i], false);
                }
            }
        }
    }

    return NULL;
}
