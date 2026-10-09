#ifndef __FEMU_BBSSD_FTL_INTERNAL_H
#define __FEMU_BBSSD_FTL_INTERNAL_H

#include "ftl.h"

/* geometry / validity / resource accessors -- hot-path inlines */
static inline void check_addr(int a, int max)
{
    ftl_assert(a >= 0 && a < max);
}

/* point a write pointer at the first page of @line */
static inline void ssd_wp_reset(struct write_pointer *wpp, struct line *line)
{
    wpp->curline = line;
    wpp->ch = 0;
    wpp->lun = 0;
    wpp->pl = 0;
    wpp->pg = 0;
    wpp->blk = line->id;
}

/*
 * Move a write pointer to the next page of its line: channel first, then LUN,
 * then plane, then page. Returns true when the step wrapped past the line's
 * last page, leaving the pointer at page 0 for the caller to retire the line.
 */
static inline bool ssd_wp_step(struct ssdparams *spp, struct write_pointer *wpp)
{
    check_addr(wpp->ch, spp->nchs);
    if (++wpp->ch < spp->nchs) {
        return false;
    }
    wpp->ch = 0;
    check_addr(wpp->lun, spp->luns_per_ch);
    if (++wpp->lun < spp->luns_per_ch) {
        return false;
    }
    wpp->lun = 0;
    check_addr(wpp->pl, spp->pls_per_lun);
    if (++wpp->pl < spp->pls_per_lun) {
        return false;
    }
    wpp->pl = 0;
    check_addr(wpp->pg, spp->pgs_per_blk);
    if (++wpp->pg < spp->pgs_per_blk) {
        return false;
    }
    wpp->pg = 0;
    return true;
}

/* fold the id of a collected line or reclaim unit into the victim digest */
static inline void ftl_note_victim(struct ssd *ssd, uint64_t id)
{
    ssd->victim_digest = (ssd->victim_digest ^ (id + 1)) *
                         0x100000001b3ULL;
}

static inline bool valid_ppa(struct ssd *ssd, struct ppa *ppa)
{
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

static inline bool valid_lpn(struct ssd *ssd, uint64_t lpn)
{
    return (lpn < ssd->sp.tt_pgs);
}

static inline bool mapped_ppa(struct ppa *ppa)
{
    return !(ppa->ppa == UNMAPPED_PPA);
}

static inline struct ssd_channel *get_ch(struct ssd *ssd, struct ppa *ppa)
{
    return &(ssd->ch[ppa->g.ch]);
}

static inline struct nand_lun *get_lun(struct ssd *ssd, struct ppa *ppa)
{
    struct ssd_channel *ch = get_ch(ssd, ppa);
    return &(ch->lun[ppa->g.lun]);
}

static inline struct nand_plane *get_pl(struct ssd *ssd, struct ppa *ppa)
{
    struct nand_lun *lun = get_lun(ssd, ppa);
    return &(lun->pl[ppa->g.pl]);
}

static inline struct nand_block *get_blk(struct ssd *ssd, struct ppa *ppa)
{
    struct nand_plane *pl = get_pl(ssd, ppa);
    return &(pl->blk[ppa->g.blk]);
}

/*
 * How long a line's data has sat programmed at @now, in ns, aged age_scale
 * times faster than wall time so a lifetime study runs in hours. Only the
 * physics of data age reads this: I/O timing and collection order do not.
 * A line still being written has no age yet.
 */
static inline uint64_t ssd_data_age_ns(struct ssd *ssd, uint64_t close_time,
                                       uint64_t now)
{
    uint64_t age;
    uint64_t scale = ssd->sp.age_scale > 1 ? ssd->sp.age_scale : 1;

    if (!close_time || now <= close_time) {
        return 0;
    }
    age = now - close_time;
    return age > UINT64_MAX / scale ? UINT64_MAX : age * scale;
}

static inline struct line *get_line(struct ssd *ssd, struct ppa *ppa)
{
    return &(ssd->lm.lines[ppa->g.blk]);
}

static inline struct nand_page *get_pg(struct ssd *ssd, struct ppa *ppa)
{
    struct nand_block *blk = get_blk(ssd, ppa);
    return &(blk->pg[ppa->g.pg]);
}

/* mapping accessors (maptbl / rmap) -- hot-path inlines */
static inline struct ppa get_maptbl_ent(struct ssd *ssd, uint64_t lpn)
{
    return ssd->maptbl[lpn];
}

static inline void set_maptbl_ent(struct ssd *ssd, uint64_t lpn, struct ppa *ppa)
{
    ftl_assert(lpn < ssd->sp.tt_pgs);
    ssd->maptbl[lpn] = *ppa;
}

static inline uint64_t ppa2pgidx(struct ssd *ssd, struct ppa *ppa)
{
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

static inline uint64_t get_rmap_ent(struct ssd *ssd, struct ppa *ppa)
{
    uint64_t pgidx = ppa2pgidx(ssd, ppa);

    return ssd->rmap[pgidx];
}

/* set rmap[page_no(ppa)] -> lpn */
static inline void set_rmap_ent(struct ssd *ssd, uint64_t lpn, struct ppa *ppa)
{
    uint64_t pgidx = ppa2pgidx(ssd, ppa);

    ssd->rmap[pgidx] = lpn;
}

/* geometry setup (hw/femu/bbssd/ftl-geom.c) */
void ssd_init_params(struct ssdparams *spp, FemuCtrl *n);
void ssd_init_ch(struct ssd_channel *ch, struct ssdparams *spp);

/* page mapping table init + mapping-scheme registry (hw/femu/bbssd/ftl-map.c) */
void ssd_init_maptbl(struct ssd *ssd);
void ssd_init_rmap(struct ssd *ssd);
const struct femu_mapping_ops *femu_mapping_scheme_lookup(const char *name);
bool femu_mapping_scheme_uses_cmt(const struct femu_mapping_ops *ops);

/* DFTL cached mapping table cost model (hw/femu/bbssd/ftl-map-cmt.c) */
void cmt_init(struct ssd *ssd, uint32_t cache_mb);
uint64_t cmt_touch(struct ssd *ssd, uint64_t lpn, uint64_t stime, bool is_write);

/*
 * Data-remanence experiment logging (debug; off unless FEMU_EXP_LOG / FEMU_DUMP_LPN
 * are set). Shared by the datapath, GC, and init; the code and state live in
 * hw/femu/bbssd/ftl-exp.c.
 */
extern bool exp_log_enabled;
extern uint8_t exp_watch_blk[];   /* block (line) id -> carries the marker? */
extern uint64_t exp_dump_lpn;
extern bool exp_dump_lpn_set;
void exp_load_cfg(void);
bool exp_lpn_watched(uint64_t lpn);
void exp_watch_lpn_add(uint64_t lpn);
void femu_dbg_dump_lpn(struct ssd *ssd, uint64_t lpn);
void femu_dbg_scan_secret(struct ssd *ssd, const char *tag);
bool femu_dbg_lpn_has_secret(struct ssd *ssd, uint64_t lpn);
#define EXP_LOG(fmt, ...) do { \
    if (exp_log_enabled) \
        fprintf(stderr, "[EXP] " fmt, ## __VA_ARGS__); \
} while (0)
#define PPA_FMT "ch=%u lun=%u pl=%u blk=%u pg=%u"
#define PPA_ARG(p) (unsigned)(p)->g.ch, (unsigned)(p)->g.lun, \
                   (unsigned)(p)->g.pl, (unsigned)(p)->g.blk, (unsigned)(p)->g.pg

bool ssd_out_of_lines(struct ssd *ssd);

/* GC trigger predicates (used by the datapath and GC) */
static inline bool should_gc(struct ssd *ssd)
{
    return (ssd->lm.free_line_cnt <= ssd->sp.gc_thres_lines);
}

static inline bool should_gc_high(struct ssd *ssd)
{
    return (ssd->lm.free_line_cnt <= ssd->sp.gc_thres_lines_high);
}

/* FDP GC decision: returns rg index if GC needed, -1 otherwise */
static inline int16_t should_gc_fdp_style(struct ssd *ssd)
{
    for (int i = 0; i < (int)ssd->nrg; i++) {
        if (ssd->rg[i].ru_mgmt->free_ru_cnt <=
            ssd->rg[i].ru_mgmt->gc_thres_rus) {
            return i;
        }
    }
    return -1;
}

static inline int should_gc_high_fdp_style(struct ssd *ssd)
{
    for (int i = 0; i < (int)ssd->nrg; i++) {
        if (ssd->rg[i].ru_mgmt->free_ru_cnt <=
            ssd->rg[i].ru_mgmt->gc_thres_rus_high) {
            return i;
        }
    }
    return -1;
}

/* line management + garbage collection (hw/femu/bbssd/ftl-line-gc.c) */
struct line *get_next_free_line(struct ssd *ssd);
void ssd_init_lines(struct ssd *ssd);
void ssd_init_write_pointer(struct ssd *ssd);
struct ppa ssd_stream_page(struct ssd *ssd, unsigned slot, uint64_t tag);
void ssd_stream_advance(struct ssd *ssd, unsigned slot);
void ssd_advance_write_pointer(struct ssd *ssd);
struct ppa get_new_page(struct ssd *ssd);
struct ppa get_new_page_class(struct ssd *ssd, int klass);
void ssd_advance_write_pointer_class(struct ssd *ssd, int klass);
void mark_page_invalid(struct ssd *ssd, struct ppa *ppa);
void mark_page_valid(struct ssd *ssd, struct ppa *ppa);
void mark_block_free(struct ssd *ssd, struct ppa *ppa);
uint64_t ssd_erase_lun_block(struct ssd *ssd, int ch, int lun, int blk,
                             bool charge, int64_t stime);
void mark_line_free(struct ssd *ssd, struct ppa *ppa);
void gc_read_page(struct ssd *ssd, struct ppa *ppa);

/* how a mode marks pages when collection moves one (ssd_gc_move_page) */
struct ssd_gc_move_ops {
    void (*mark_valid)(struct ssd *ssd, struct ppa *ppa, void *dest);
    void (*mark_invalid)(struct ssd *ssd, struct ppa *ppa);
};
void ssd_gc_move_page(struct ssd *ssd, uint64_t lpn, struct ppa *old_ppa,
                      struct ppa *new_ppa, const struct ssd_gc_move_ops *ops,
                      void *dest);
void ssd_gc_charge_move(struct ssd *ssd, struct ppa *new_ppa);
int do_gc(struct ssd *ssd, bool force);
int do_read_reclaim(struct ssd *ssd);
int do_wear_level(struct ssd *ssd);
const struct femu_ftl_policy_ops *femu_ftl_policy_lookup(const char *name);
uint64_t ftl_gc_rand(struct ssd *ssd);

/* log-block mapping schemes (hw/femu/bbssd/ftl-map-hybrid.c) */
extern const struct femu_mapping_ops femu_mapping_hybrid_ops;
extern const struct femu_mapping_ops femu_mapping_fast_ops;

/*
 * Translate blocks [slba, slba + nlb) using the namespace's current format.
 * Fixed namespaces retain device-relative numbering; managed namespaces use
 * their private FTL address spaces.
 */
/* byte offset of block @slba of the request's namespace in the FTL */
static inline uint64_t ssd_lba_byte_offset(struct ssd *ssd, NvmeRequest *req,
                                           uint64_t slba)
{
    uint8_t lbads = req->ns ? req->ns->lbaf.lbads : BDRV_SECTOR_BITS;
    uint64_t off = req->ns ? req->ns->backend_offset : 0;

    /* Managed namespaces index their private FTL independently of placement. */
    if (ssd->n->ns_mgmt &&
        (le16_to_cpu(ssd->n->id_ctrl.oacs) & NVME_OACS_NS_MGMT)) {
        off = 0;
    }
    return off + (slba << lbads);
}

static inline void ssd_lpn_range(struct ssd *ssd, NvmeRequest *req,
                                 uint64_t slba, uint64_t nlb,
                                 uint64_t *start_lpn, uint64_t *end_lpn)
{
    uint64_t pg = (uint64_t)ssd->sp.secsz * ssd->sp.secs_per_pg;
    uint8_t lbads = req->ns ? req->ns->lbaf.lbads : BDRV_SECTOR_BITS;
    uint64_t off = ssd_lba_byte_offset(ssd, req, slba);

    *start_lpn = off / pg;
    *end_lpn = (off + (nlb << lbads) - 1) / pg;
}

/*
 * Count the NAND pages a host write covers only in part: its first page when
 * it starts inside one, its last when it ends inside one. A device has to read
 * such a page to program it again; this model does not charge that read, so
 * the count shows how much it leaves out.
 */
static inline void ssd_count_partial_pages(struct ssd *ssd, NvmeRequest *req,
                                           uint64_t slba, uint64_t nlb)
{
    uint64_t pg = (uint64_t)ssd->sp.secsz * ssd->sp.secs_per_pg;
    uint8_t lbads = req->ns ? req->ns->lbaf.lbads : BDRV_SECTOR_BITS;
    uint64_t start = ssd_lba_byte_offset(ssd, req, slba);
    uint64_t end = start + (nlb << lbads);

    if (!nlb) {
        return;
    }
    if (start / pg == (end - 1) / pg) {
        ssd->partial_page_writes += start % pg || end % pg;
        return;
    }
    ssd->partial_page_writes += (start % pg != 0) + (end % pg != 0);
}

/* a host write that ran forced collection before it got room counts once */
static inline void ssd_note_gc_stall(struct ssd *ssd, uint64_t passes_before)
{
    if (ssd->gc_stall_passes != passes_before) {
        ssd->gc_stalled_writes++;
    }
}

/* DRAM write buffer ordering (hw/femu/bbssd/ftl-datapath.c) */
int comp_buffer(const void *a, const void *b);

/* non-FDP host datapath (hw/femu/bbssd/ftl-datapath.c) */
uint64_t ssd_read(struct ssd *ssd, NvmeRequest *req);
uint64_t ssd_write(struct ssd *ssd, NvmeRequest *req);
uint64_t ssd_trim(struct ssd *ssd, NvmeRequest *req);

/* optional DRAM read cache (hw/femu/bbssd/ftl-cache.c) */
void rcache_init(struct ssd *ssd, uint32_t read_cache_mb, uint32_t evict_policy);
uint64_t rcache_touch(struct ssd *ssd, uint64_t lpn);
void rcache_invalidate(struct ssd *ssd, uint64_t lpn);

/* Flexible Data Placement (hw/femu/bbssd/ftl-fdp.c) */
void ssd_init_fdp_params(struct ssdparams *spp, FemuCtrl *n);
void femu_fdp_ssd_init_reclaim_group(FemuCtrl *n, struct ssd *ssd);
void femu_fdp_ssd_init_ru_handles(FemuCtrl *n, struct ssd *ssd);
void femu_fdp_ssd_free(struct ssd *ssd);
void rcache_destroy(struct ssd *ssd);
void cmt_destroy(struct ssd *ssd);
void ssd_free_lines(struct ssd *ssd);
void ssd_free_ch(struct ssd_channel *ch, struct ssdparams *spp);
/* nvme_do_write_fdp() is declared in nvme.h (included via ftl.h) */
int do_gc_fdp_style(struct ssd *ssd, uint16_t rgid, uint16_t ruhid, bool force);
uint64_t ssd_write_zeroes_fdp_style(FemuCtrl *n, NvmeRequest *req);
void ssd_fdp_update_ruhs(FemuCtrl *n, NvmeRequest *req);
void ssd_trim_fdp_style(FemuCtrl *n, NvmeRequest *req, uint64_t slba,
                        uint32_t nlb);

#endif /* __FEMU_BBSSD_FTL_INTERNAL_H */
