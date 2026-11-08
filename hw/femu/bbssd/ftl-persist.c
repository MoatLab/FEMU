/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * The bbssd FTL state in a persist_file (persist_ftl): one section per
 * namespace, little-endian, with a CRC-32C. Scope: mapping=page, without
 * the features femu-persist.c refuses, so the state below is all of it.
 *
 *   header   magic, schema, digest, page / block / line counts
 *   maptbl   per LPN: page index, or all ones
 *   rmap     per page: LPN, or all ones
 *   status   per page: free, invalid, valid
 *   blocks   erase_cnt ipc vpc wp read_cnt
 *   lines    ipc vpc close_seq close_age open_age flags state
 *   lists    free ids, full ids, victim heap ids (array order)
 *   pointer  line id ch lun pl pg
 *   scalars  the counters of ssd_persist_scalars()
 *   crc32c
 *
 * A load reads and checks every record first; only a section that passes
 * reaches ssd_persist_load() with commit set.
 */
#include "qemu/osdep.h"
#include "qemu/crc32c.h"
#include "qapi/error.h"
#include "ftl.h"
#include "ftl-internal.h"

#define FTLP_MAGIC      "FEMUFTL1"
#define FTLP_SCHEMA     1
#define FTLP_NONE       UINT64_MAX
#define FTLP_HDR        56
#define FTLP_BLK        24
#define FTLP_LINE       40

enum {
    FTLP_FREE = 0,
    FTLP_FULL = 1,
    FTLP_VICTIM = 2,
    FTLP_ACTIVE = 3,
    FTLP_SPARE = 4,     /* a spare or reserve line, held out of the lists */
};

#define FTLP_CLOSE_SET  0x1
#define FTLP_OPEN_SET   0x2

#define FTLP_NSCALARS   22

/* the counters a section carries, in this order */
static void ftlp_scalars(struct ssd *ssd, uint64_t *v[FTLP_NSCALARS])
{
    uint64_t *list[FTLP_NSCALARS] = {
        &ssd->lm.next_close_seq, &ssd->gc_rng, &ssd->victim_digest,
        &ssd->host_write_pages, &ssd->nand_write_pages,
        &ssd->gc_write_pages, &ssd->total_erases,
        &ssd->media_ops[0], &ssd->media_ops[1], &ssd->media_ops[2],
        &ssd->media_plane_ops[0], &ssd->media_plane_ops[1],
        &ssd->media_plane_ops[2],
        &ssd->sp.read_cnt, &ssd->sp.write_cnt, &ssd->sp.read_hit_cnt,
        &ssd->sp.write_hit_cnt, &ssd->partial_page_writes,
        &ssd->unaligned_writes, &ssd->gc_stalled_writes,
        &ssd->gc_stall_passes, &ssd->forced_gc_timed,
    };

    memcpy(v, list, sizeof(list));
}

typedef struct FtlpCursor {
    const uint8_t *b;
    size_t len;
    size_t off;
    bool bad;
} FtlpCursor;

static const uint8_t *ftlp_take(FtlpCursor *c, size_t n)
{
    const uint8_t *p;

    if (c->bad || n > c->len - c->off) {
        c->bad = true;
        return NULL;
    }
    p = c->b + c->off;
    c->off += n;
    return p;
}

static uint64_t ftlp_u64(FtlpCursor *c)
{
    const uint8_t *p = ftlp_take(c, 8);

    return p ? ldq_le_p(p) : 0;
}

static uint32_t ftlp_u32(FtlpCursor *c)
{
    const uint8_t *p = ftlp_take(c, 4);

    return p ? ldl_le_p(p) : 0;
}

static uint8_t ftlp_u8(FtlpCursor *c)
{
    const uint8_t *p = ftlp_take(c, 1);

    return p ? *p : 0;
}

static void ftlp_put64(GByteArray *g, uint64_t v)
{
    uint8_t b[8];

    stq_le_p(b, v);
    g_byte_array_append(g, b, 8);
}

static void ftlp_put32(GByteArray *g, uint32_t v)
{
    uint8_t b[4];

    stl_le_p(b, v);
    g_byte_array_append(g, b, 4);
}

static void ftlp_put8(GByteArray *g, uint8_t v)
{
    g_byte_array_append(g, &v, 1);
}

static struct nand_block *ftlp_blk(struct ssd *ssd, uint64_t b)
{
    struct ssdparams *spp = &ssd->sp;
    int blk = b % spp->blks_per_pl;
    int pl = (b / spp->blks_per_pl) % spp->pls_per_lun;
    int lun = (b / spp->blks_per_lun) % spp->luns_per_ch;
    int ch = b / spp->blks_per_ch;

    return &ssd->ch[ch].lun[lun].pl[pl].blk[blk];
}

/* the block index of the block of line @line on die position @c, @l, @p */
static uint64_t ftlp_line_blk(struct ssdparams *spp, int c, int l, int p,
                              int line)
{
    return (uint64_t)c * spp->blks_per_ch + (uint64_t)l * spp->blks_per_lun +
           (uint64_t)p * spp->blks_per_pl + line;
}

static struct ppa ftlp_idx_ppa(struct ssd *ssd, uint64_t idx)
{
    struct ssdparams *spp = &ssd->sp;
    struct ppa ppa = { .ppa = 0 };

    ppa.g.pg = idx % spp->pgs_per_blk;
    ppa.g.blk = (idx / spp->pgs_per_blk) % spp->blks_per_pl;
    ppa.g.pl = (idx / spp->pgs_per_pl) % spp->pls_per_lun;
    ppa.g.lun = (idx / spp->pgs_per_lun) % spp->luns_per_ch;
    ppa.g.ch = idx / spp->pgs_per_ch;
    return ppa;
}

/* CRC-32C of a section, which can be longer than crc32c() takes at once */
static uint32_t ftlp_crc(const uint8_t *b, size_t len)
{
    uint32_t crc = 0xffffffff;

    /* crc32c() returns its state complemented, as iov_crc32c() undoes */
    while (len) {
        unsigned int n = MIN(len, (size_t)1 << 30);

        crc = crc32c(crc, b, n) ^ 0xffffffff;
        b += n;
        len -= n;
    }
    return crc ^ 0xffffffff;
}

static uint64_t ftlp_age(uint64_t now, uint64_t t)
{
    return now > t ? now - t : 0;
}

/* the line state of @line as the lists hold it now */
static uint8_t ftlp_line_state(struct ssd *ssd, struct line *line)
{
    struct line_mgmt *lm = &ssd->lm;
    struct line *l;

    if (line->spare || line->reserve) {
        return FTLP_SPARE;
    }
    if (ssd->wp.curline == line) {
        return FTLP_ACTIVE;
    }
    QTAILQ_FOREACH(l, &lm->free_line_list, entry) {
        if (l == line) {
            return FTLP_FREE;
        }
    }
    QTAILQ_FOREACH(l, &lm->full_line_list, entry) {
        if (l == line) {
            return FTLP_FULL;
        }
    }
    return FTLP_VICTIM;
}

/* the longest section @ssd can have: what a loader may allocate */
uint64_t ssd_persist_max_len(struct ssd *ssd)
{
    struct ssdparams *spp = &ssd->sp;
    uint64_t lines = ssd->lm.tt_lines;

    return FTLP_HDR + (uint64_t)spp->tt_pgs * 17 +
           (uint64_t)spp->tt_blks * FTLP_BLK + lines * (FTLP_LINE + 4) +
           3 * 8 + 5 * 4 + FTLP_NSCALARS * 8 + 4;
}

/*
 * The section of @ssd. The caller holds the workers paused with no request
 * between fetch and the FTL, so no list is in motion.
 */
GByteArray *ssd_persist_save(struct ssd *ssd, uint64_t digest)
{
    struct ssdparams *spp = &ssd->sp;
    struct line_mgmt *lm = &ssd->lm;
    GByteArray *g = g_byte_array_new();
    uint64_t now = ssd_now(ssd);
    uint64_t *sv[FTLP_NSCALARS];
    struct line *line;
    uint64_t n;

    g_byte_array_append(g, (const uint8_t *)FTLP_MAGIC, 8);
    ftlp_put32(g, FTLP_SCHEMA);
    ftlp_put32(g, 0);
    ftlp_put64(g, digest);
    ftlp_put64(g, spp->tt_pgs);
    ftlp_put64(g, spp->tt_blks);
    ftlp_put64(g, lm->tt_lines);
    ftlp_put64(g, FTLP_NSCALARS);

    for (uint64_t i = 0; i < spp->tt_pgs; i++) {
        ftlp_put64(g, mapped_ppa(&ssd->maptbl[i]) ?
                   ppa2pgidx(ssd, &ssd->maptbl[i]) : FTLP_NONE);
    }
    for (uint64_t i = 0; i < spp->tt_pgs; i++) {
        ftlp_put64(g, ssd->rmap[i]);
    }
    for (uint64_t b = 0; b < (uint64_t)spp->tt_blks; b++) {
        struct nand_block *blk = ftlp_blk(ssd, b);

        for (int pg = 0; pg < spp->pgs_per_blk; pg++) {
            ftlp_put8(g, blk->pg[pg].status);
        }
    }
    for (uint64_t b = 0; b < (uint64_t)spp->tt_blks; b++) {
        struct nand_block *blk = ftlp_blk(ssd, b);

        ftlp_put32(g, blk->erase_cnt);
        ftlp_put32(g, blk->ipc);
        ftlp_put32(g, blk->vpc);
        ftlp_put32(g, blk->wp);
        ftlp_put64(g, blk->read_cnt);
    }
    for (int i = 0; i < lm->tt_lines; i++) {
        line = &lm->lines[i];
        ftlp_put32(g, line->ipc);
        ftlp_put32(g, line->vpc);
        ftlp_put64(g, line->close_seq);
        ftlp_put64(g, ftlp_age(now, line->close_time));
        ftlp_put64(g, ftlp_age(now, line->open_time));
        ftlp_put8(g, (line->close_time ? FTLP_CLOSE_SET : 0) |
                     (line->open_time ? FTLP_OPEN_SET : 0));
        ftlp_put8(g, ftlp_line_state(ssd, line));
        for (int k = 0; k < 6; k++) {
            ftlp_put8(g, 0);
        }
    }
    ftlp_put64(g, lm->free_line_cnt);
    QTAILQ_FOREACH(line, &lm->free_line_list, entry) {
        ftlp_put32(g, line->id);
    }
    ftlp_put64(g, lm->full_line_cnt);
    QTAILQ_FOREACH(line, &lm->full_line_list, entry) {
        ftlp_put32(g, line->id);
    }
    n = pqueue_size(lm->victim_line_pq);
    ftlp_put64(g, n);
    for (uint64_t i = 1; i <= n; i++) {
        ftlp_put32(g, ((struct line *)lm->victim_line_pq->d[i])->id);
    }
    ftlp_put32(g, ssd->wp.curline ? (uint32_t)ssd->wp.curline->id :
                                    UINT32_MAX);
    ftlp_put32(g, ssd->wp.ch);
    ftlp_put32(g, ssd->wp.lun);
    ftlp_put32(g, ssd->wp.pl);
    ftlp_put32(g, ssd->wp.pg);
    ftlp_scalars(ssd, sv);
    for (int i = 0; i < FTLP_NSCALARS; i++) {
        ftlp_put64(g, *sv[i]);
    }
    ftlp_put32(g, ftlp_crc(g->data, g->len));
    assert(g->len <= ssd_persist_max_len(ssd));
    return g;
}

typedef struct FtlpBlk {
    uint32_t erase_cnt;
    uint32_t ipc;
    uint32_t vpc;
    uint32_t wp;
    uint64_t read_cnt;
} FtlpBlk;

typedef struct FtlpLine {
    uint32_t ipc;
    uint32_t vpc;
    uint64_t close_seq;
    uint64_t close_age;
    uint64_t open_age;
    uint8_t flags;
    uint8_t state;
} FtlpLine;

/* the decoded section, owned by ssd_persist_load() */
typedef struct FtlpState {
    uint64_t *map;
    uint64_t *rmap;
    uint8_t *st;
    FtlpBlk *blk;
    FtlpLine *line;
    uint32_t *order[3];     /* free, full, victim heap */
    uint64_t norder[3];
    uint32_t wp_line;
    uint32_t wp_ch;
    uint32_t wp_lun;
    uint32_t wp_pl;
    uint32_t wp_pg;
    uint64_t scalars[FTLP_NSCALARS];
} FtlpState;

static void ftlp_free(FtlpState *s)
{
    g_free(s->map);
    g_free(s->rmap);
    g_free(s->st);
    g_free(s->blk);
    g_free(s->line);
    for (int i = 0; i < 3; i++) {
        g_free(s->order[i]);
    }
}

static bool ftlp_decode(struct ssd *ssd, const uint8_t *buf, size_t len,
                        uint64_t digest, FtlpState *s, Error **errp)
{
    struct ssdparams *spp = &ssd->sp;
    uint64_t tt_pgs = spp->tt_pgs;
    uint64_t tt_blks = spp->tt_blks;
    uint64_t tt_lines = ssd->lm.tt_lines;
    FtlpCursor c = { .b = buf, .len = len };
    const uint8_t *p;

    if (len < FTLP_HDR + 4 ||
        ldl_le_p(buf + len - 4) != ftlp_crc(buf, len - 4)) {
        error_setg(errp, "the FTL section is short or its CRC is wrong");
        return false;
    }
    c.len = len - 4;
    p = ftlp_take(&c, 8);
    if (!p || memcmp(p, FTLP_MAGIC, 8) || ftlp_u32(&c) != FTLP_SCHEMA ||
        ftlp_u32(&c) != 0) {
        error_setg(errp, "the FTL section has another format");
        return false;
    }
    if (ftlp_u64(&c) != digest) {
        error_setg(errp, "the FTL section comes from other FTL properties "
                   "(geometry, mapping, GC or NAND timing)");
        return false;
    }
    if (ftlp_u64(&c) != tt_pgs || ftlp_u64(&c) != tt_blks ||
        ftlp_u64(&c) != tt_lines || ftlp_u64(&c) != FTLP_NSCALARS) {
        error_setg(errp, "the FTL section has another geometry");
        return false;
    }
    /* each array must fit before it is allocated */
    if (len - c.off < tt_pgs * 17 + tt_blks * FTLP_BLK +
                      tt_lines * FTLP_LINE) {
        error_setg(errp, "the FTL section is short");
        return false;
    }
    s->map = g_new(uint64_t, tt_pgs);
    s->rmap = g_new(uint64_t, tt_pgs);
    s->st = g_new(uint8_t, tt_pgs);
    s->blk = g_new(FtlpBlk, tt_blks);
    s->line = g_new(FtlpLine, tt_lines);
    for (uint64_t i = 0; i < tt_pgs; i++) {
        s->map[i] = ftlp_u64(&c);
    }
    for (uint64_t i = 0; i < tt_pgs; i++) {
        s->rmap[i] = ftlp_u64(&c);
    }
    for (uint64_t i = 0; i < tt_pgs; i++) {
        s->st[i] = ftlp_u8(&c);
    }
    for (uint64_t b = 0; b < tt_blks; b++) {
        s->blk[b].erase_cnt = ftlp_u32(&c);
        s->blk[b].ipc = ftlp_u32(&c);
        s->blk[b].vpc = ftlp_u32(&c);
        s->blk[b].wp = ftlp_u32(&c);
        s->blk[b].read_cnt = ftlp_u64(&c);
    }
    for (uint64_t i = 0; i < tt_lines; i++) {
        s->line[i].ipc = ftlp_u32(&c);
        s->line[i].vpc = ftlp_u32(&c);
        s->line[i].close_seq = ftlp_u64(&c);
        s->line[i].close_age = ftlp_u64(&c);
        s->line[i].open_age = ftlp_u64(&c);
        s->line[i].flags = ftlp_u8(&c);
        s->line[i].state = ftlp_u8(&c);
        ftlp_take(&c, 6);
    }
    for (int k = 0; k < 3; k++) {
        s->norder[k] = ftlp_u64(&c);
        if (c.bad || s->norder[k] > tt_lines) {
            error_setg(errp, "the FTL section has a bad line list");
            return false;
        }
        s->order[k] = g_new(uint32_t, s->norder[k] + 1);
        for (uint64_t i = 0; i < s->norder[k]; i++) {
            s->order[k][i] = ftlp_u32(&c);
        }
    }
    s->wp_line = ftlp_u32(&c);
    s->wp_ch = ftlp_u32(&c);
    s->wp_lun = ftlp_u32(&c);
    s->wp_pl = ftlp_u32(&c);
    s->wp_pg = ftlp_u32(&c);
    for (int i = 0; i < FTLP_NSCALARS; i++) {
        s->scalars[i] = ftlp_u64(&c);
    }
    if (c.bad || c.off != c.len) {
        error_setg(errp, "the FTL section has the wrong length");
        return false;
    }
    return true;
}

/* the order key of a die position in the pointer's traversal */
static uint64_t ftlp_key(struct ssdparams *spp, int c, int l, int p)
{
    return ((uint64_t)p * spp->luns_per_ch + l) * spp->nchs + c;
}

static bool ftlp_check(struct ssd *ssd, FtlpState *s, Error **errp)
{
    struct ssdparams *spp = &ssd->sp;
    struct line_mgmt *lm = &ssd->lm;
    uint64_t tt_pgs = spp->tt_pgs;
    uint64_t pk = 0;
    int active = 0;
    g_autofree uint8_t *seen = g_new0(uint8_t, lm->tt_lines);
    g_autofree uint8_t *owned = g_new0(uint8_t, tt_pgs);
    uint64_t pgsz = (uint64_t)spp->secsz * spp->secs_per_pg;
    uint64_t lpn_lo = ssd_ns_byte_base(ssd, ssd->ns) / pgsz;
    uint64_t lpn_hi = ssd->ns ? lpn_lo + DIV_ROUND_UP(ssd->ns->size, pgsz) :
                                tt_pgs;
    const char *why = NULL;

    /*
     * Forward and reverse mapping. The LPNs of a namespace count from its
     * slice of the backend, as ssd_lpn_range() numbers them.
     */
    for (uint64_t l = 0; l < tt_pgs && !why; l++) {
        uint64_t i = s->map[l];

        if (i == FTLP_NONE) {
            continue;
        }
        if (l < lpn_lo || l >= lpn_hi) {
            why = "a mapped LPN is outside the namespace";
        } else if (i >= tt_pgs || s->st[i] != PG_VALID || s->rmap[i] != l ||
            owned[i]) {
            why = "a mapped LPN names a page that is not its own";
        } else {
            owned[i] = 1;
        }
    }
    for (uint64_t i = 0; i < tt_pgs && !why; i++) {
        if (s->st[i] > PG_VALID) {
            why = "a page status is out of range";
        } else if (s->st[i] == PG_VALID && !owned[i]) {
            why = "a valid page has no LPN that maps to it";
        } else if (s->st[i] != PG_VALID && s->rmap[i] != INVALID_LPN) {
            why = "a free or invalid page names an LPN";
        }
    }
    /* blocks: programmed pages first, counts that match them */
    for (uint64_t b = 0; b < (uint64_t)spp->tt_blks && !why; b++) {
        FtlpBlk *bk = &s->blk[b];
        const uint8_t *st = s->st + b * spp->pgs_per_blk;
        uint32_t v = 0, inv = 0;

        if (bk->wp > (uint32_t)spp->pgs_per_blk) {
            why = "a block write pointer is out of range";
            break;
        }
        for (uint32_t pg = 0; pg < (uint32_t)spp->pgs_per_blk; pg++) {
            if ((pg < bk->wp) != (st[pg] != PG_FREE)) {
                why = "a block has a free page before its write pointer";
                break;
            }
            v += st[pg] == PG_VALID;
            inv += st[pg] == PG_INVALID;
        }
        if (!why && (bk->vpc != v || bk->ipc != inv)) {
            why = "a block count does not match its pages";
        }
    }
    /* the pointer */
    if (!why && s->wp_line != UINT32_MAX) {
        if (s->wp_line >= (uint32_t)lm->tt_lines ||
            s->wp_ch >= (uint32_t)spp->nchs ||
            s->wp_lun >= (uint32_t)spp->luns_per_ch ||
            s->wp_pl >= (uint32_t)spp->pls_per_lun ||
            s->wp_pg >= (uint32_t)spp->pgs_per_blk) {
            why = "the write pointer is out of range";
        } else {
            pk = ftlp_key(spp, s->wp_ch, s->wp_lun, s->wp_pl);
        }
    }
    /* lines: their blocks agree with their state */
    for (int i = 0; i < lm->tt_lines && !why; i++) {
        FtlpLine *ln = &s->line[i];
        struct line *live = &lm->lines[i];
        uint64_t v = 0, inv = 0;
        bool erased = true, full = true, front = true;

        for (int c = 0; c < spp->nchs; c++) {
            for (int l = 0; l < spp->luns_per_ch; l++) {
                for (int p = 0; p < spp->pls_per_lun; p++) {
                    FtlpBlk *bk = &s->blk[ftlp_line_blk(spp, c, l, p, i)];
                    uint32_t want = s->wp_pg +
                                    (ftlp_key(spp, c, l, p) < pk ? 1 : 0);

                    v += bk->vpc;
                    inv += bk->ipc;
                    erased &= bk->wp == 0;
                    full &= bk->wp == (uint32_t)spp->pgs_per_blk;
                    front &= bk->wp == want;
                }
            }
        }
        if (ln->flags & ~(FTLP_CLOSE_SET | FTLP_OPEN_SET)) {
            why = "a line has unknown flags";
        } else if ((ln->state == FTLP_FULL || ln->state == FTLP_VICTIM) &&
                   ln->close_seq >= s->scalars[0]) {
            why = "a closed line is newer than the next close sequence";
        } else if (v != ln->vpc || inv != ln->ipc) {
            why = "a line count does not match its blocks";
        } else if ((live->spare || live->reserve) !=
                   (ln->state == FTLP_SPARE)) {
            why = "a spare or reserve line differs from this device's";
        } else if (ln->state == FTLP_SPARE || ln->state == FTLP_FREE) {
            if (!erased) {
                why = "a free line holds programmed pages";
            }
        } else if (ln->state == FTLP_FULL) {
            if (!full || inv) {
                why = "a full line is not full of valid pages";
            }
        } else if (ln->state == FTLP_VICTIM) {
            if (!full || !inv) {
                why = "a victim line has no invalid page or is open";
            }
        } else if (ln->state == FTLP_ACTIVE) {
            active++;
            if ((uint32_t)i != s->wp_line || !front) {
                why = "the open line does not end at the write pointer";
            }
        } else {
            why = "a line state is out of range";
        }
    }
    if (!why && active != (s->wp_line != UINT32_MAX)) {
        why = "the write pointer line is not the one open line";
    }
    /* the lists hold exactly the lines of their state, each once */
    for (int k = 0; k < 3 && !why; k++) {
        static const uint8_t state[3] = {
            FTLP_FREE, FTLP_FULL, FTLP_VICTIM,
        };
        uint64_t want = 0;

        for (int i = 0; i < lm->tt_lines; i++) {
            want += s->line[i].state == state[k];
        }
        if (want != s->norder[k]) {
            why = "a line list does not hold its lines";
            break;
        }
        for (uint64_t j = 0; j < s->norder[k]; j++) {
            uint32_t id = s->order[k][j];

            if (id >= (uint32_t)lm->tt_lines || seen[id] ||
                s->line[id].state != state[k]) {
                why = "a line list names a line twice or of another state";
                break;
            }
            seen[id] = 1;
        }
    }
    /* the victim heap: no parent above its child (pqueue order) */
    for (uint64_t j = 2; j <= s->norder[2] && !why; j++) {
        FtlpLine *child = &s->line[s->order[2][j - 1]];
        FtlpLine *parent = &s->line[s->order[2][j / 2 - 1]];
        uint64_t cp = ssd->policy->by_close_order ? child->close_seq :
                                                    child->vpc;
        uint64_t pp = ssd->policy->by_close_order ? parent->close_seq :
                                                    parent->vpc;

        if (pp > cp) {
            why = "the victim heap is out of order";
        }
    }
    if (why) {
        error_setg(errp, "the FTL section is not consistent: %s", why);
        return false;
    }
    return true;
}

static uint64_t ftlp_rebase(uint64_t now, uint64_t age, bool set)
{
    if (!set) {
        return 0;
    }
    return now > age ? now - age : 1;
}

static void ftlp_commit(struct ssd *ssd, FtlpState *s)
{
    struct ssdparams *spp = &ssd->sp;
    struct line_mgmt *lm = &ssd->lm;
    uint64_t now = ssd_now(ssd);
    uint64_t *sv[FTLP_NSCALARS];

    for (uint64_t l = 0; l < (uint64_t)spp->tt_pgs; l++) {
        if (s->map[l] == FTLP_NONE) {
            ssd->maptbl[l].ppa = UNMAPPED_PPA;
        } else {
            ssd->maptbl[l] = ftlp_idx_ppa(ssd, s->map[l]);
        }
        ssd->rmap[l] = s->rmap[l];
    }
    for (uint64_t b = 0; b < (uint64_t)spp->tt_blks; b++) {
        struct nand_block *blk = ftlp_blk(ssd, b);

        for (int pg = 0; pg < spp->pgs_per_blk; pg++) {
            blk->pg[pg].status = s->st[b * spp->pgs_per_blk + pg];
        }
        blk->erase_cnt = s->blk[b].erase_cnt;
        blk->ipc = s->blk[b].ipc;
        blk->vpc = s->blk[b].vpc;
        blk->wp = s->blk[b].wp;
        blk->read_cnt = s->blk[b].read_cnt;
    }
    /* rebuild the lists from the fresh FTL's: none of them holds a victim */
    while (pqueue_size(lm->victim_line_pq)) {
        pqueue_pop(lm->victim_line_pq);
    }
    QTAILQ_INIT(&lm->free_line_list);
    QTAILQ_INIT(&lm->full_line_list);
    for (int i = 0; i < lm->tt_lines; i++) {
        struct line *line = &lm->lines[i];
        FtlpLine *ln = &s->line[i];

        line->ipc = ln->ipc;
        line->vpc = ln->vpc;
        line->close_seq = ln->close_seq;
        line->close_time = ftlp_rebase(now, ln->close_age,
                                       ln->flags & FTLP_CLOSE_SET);
        line->open_time = ftlp_rebase(now, ln->open_age,
                                      ln->flags & FTLP_OPEN_SET);
        line->pos = 0;
    }
    for (uint64_t j = 0; j < s->norder[0]; j++) {
        QTAILQ_INSERT_TAIL(&lm->free_line_list, &lm->lines[s->order[0][j]],
                           entry);
    }
    lm->free_line_cnt = s->norder[0];
    for (uint64_t j = 0; j < s->norder[1]; j++) {
        QTAILQ_INSERT_TAIL(&lm->full_line_list, &lm->lines[s->order[1][j]],
                           entry);
    }
    lm->full_line_cnt = s->norder[1];
    /* in heap order, each insert stays where it lands: the array returns */
    for (uint64_t j = 0; j < s->norder[2]; j++) {
        pqueue_insert(lm->victim_line_pq, &lm->lines[s->order[2][j]]);
    }
    if (s->wp_line == UINT32_MAX) {
        ssd->wp.curline = NULL;
    } else {
        ssd->wp.curline = &lm->lines[s->wp_line];
        ssd->wp.blk = s->wp_line;
        ssd->wp.ch = s->wp_ch;
        ssd->wp.lun = s->wp_lun;
        ssd->wp.pl = s->wp_pl;
        ssd->wp.pg = s->wp_pg;
    }
    ftlp_scalars(ssd, sv);
    for (int i = 0; i < FTLP_NSCALARS; i++) {
        *sv[i] = s->scalars[i];
    }
}

/*
 * Check the section @buf against @ssd and, with @commit, replace the fresh
 * FTL's state with it. A check that fails leaves @ssd as it was.
 */
bool ssd_persist_load(struct ssd *ssd, const uint8_t *buf, size_t len,
                      uint64_t digest, bool commit, Error **errp)
{
    FtlpState s = { 0 };
    bool ok;

    ok = ftlp_decode(ssd, buf, len, digest, &s, errp) &&
         ftlp_check(ssd, &s, errp);
    if (ok && commit) {
        ftlp_commit(ssd, &s);
    }
    ftlp_free(&s);
    return ok;
}
