#ifndef __FEMU_BBSSD_FTL_INTERNAL_H
#define __FEMU_BBSSD_FTL_INTERNAL_H

#include "ftl.h"

/* geometry / validity / resource accessors -- hot-path inlines */
static inline void check_addr(int a, int max)
{
    ftl_assert(a >= 0 && a < max);
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
void ssd_advance_write_pointer(struct ssd *ssd);
struct ppa get_new_page(struct ssd *ssd);
struct ppa get_new_page_class(struct ssd *ssd, int klass);
void ssd_advance_write_pointer_class(struct ssd *ssd, int klass);
void mark_page_invalid(struct ssd *ssd, struct ppa *ppa);
void mark_page_valid(struct ssd *ssd, struct ppa *ppa);
void mark_block_free(struct ssd *ssd, struct ppa *ppa);
void mark_line_free(struct ssd *ssd, struct ppa *ppa);
void gc_read_page(struct ssd *ssd, struct ppa *ppa);
int do_gc(struct ssd *ssd, bool force);
const struct femu_ftl_policy_ops *femu_ftl_policy_lookup(const char *name);

/* log-block mapping schemes (hw/femu/bbssd/ftl-map-hybrid.c) */
extern const struct femu_mapping_ops femu_mapping_hybrid_ops;
extern const struct femu_mapping_ops femu_mapping_fast_ops;

/*
 * Base LBA of a request's namespace inside the FTL address space. One FTL maps a
 * single flat logical page space over the whole device, so each namespace has to
 * be shifted into its own slice; otherwise namespaces would map onto the same
 * logical pages and overwrite each other. The slice offset is a byte count, and
 * the FTL treats an LBA as a sector of spp->secsz, so convert between the two.
 * Returns 0 for the first namespace, leaving single-namespace mapping unchanged.
 */
static inline uint64_t ssd_ns_lba_base(struct ssd *ssd, NvmeRequest *req)
{
    if (!req->ns || req->ns->backend_offset == 0) {
        return 0;
    }

    return req->ns->backend_offset / ssd->sp.secsz;
}

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
/* nvme_do_write_fdp() is declared in nvme.h (included via ftl.h) */
int do_gc_fdp_style(struct ssd *ssd, uint16_t rgid, uint16_t ruhid, bool force);
void ssd_trim_fdp_style(FemuCtrl *n, NvmeRequest *req, uint64_t slba,
                        uint32_t nlb);

#endif /* __FEMU_BBSSD_FTL_INTERNAL_H */
