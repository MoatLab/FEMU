/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LBA Status Information log (NVM 1.2, 4.1.4.5) and its generation counter.
 *
 * The tracked blocks are the uncorrectable bitmap of each namespace. The
 * log lists, for each attached namespace with a tracked block, its runs as
 * LBA Range Descriptors (RATYPE 11h), or FFFFFFFFh descriptors when more
 * than 256 are needed.
 *
 *   capture (pollers paused) --> page S, generation G_S
 *   successful read, any RAE  --> R = what S listed, G_R = G_S
 *   RAE=0                     --> S dropped; the next read captures again
 *
 * The generation is a function of state: S held gives G_S; otherwise
 * max(G_pub, G_R + 1 if the live blocks hold one that R did not list).
 * G_pub is the highest generation the host was given. So no event steps
 * a counter, and a reset or a dropped S cannot step LSGC twice.
 *
 * For a namespace that R listed with FFFFFFFFh descriptors, the next page
 * is new when it lists descriptors, or when it again has FFFFFFFFh and a
 * block was added since that read. Figure 109 compares descriptors only,
 * so this is the FEMU rule for an element with none.
 */

#include "./nvme.h"

#define LSI_HDR             16
#define LSI_ELEM_HDR        16
#define LSI_DESC            16
#define LSI_MAX_DESC        256
#define LSI_NLRD_ALL        0xffffffffu
#define LSI_RATYPE_TRACKED  0x11

uint64_t femu_lsi_incarnation(void)
{
    static uint64_t next;

    return qatomic_fetch_inc(&next) + 1;
}

/* the mask of the bits of [start, start + nr) in the word of @start */
static unsigned long lsi_word_mask(uint64_t start, uint64_t nr,
                                   unsigned int *cnt)
{
    unsigned int off = start % BITS_PER_LONG;

    *cnt = MIN(nr, (uint64_t)(BITS_PER_LONG - off));
    return (*cnt == BITS_PER_LONG ? ~0UL : ((1UL << *cnt) - 1)) << off;
}

/* set [start, start + nr); the count of bits that went from 0 to 1 */
static uint64_t lsi_test_and_set(unsigned long *map, uint64_t start,
                                 uint64_t nr)
{
    uint64_t added = 0;

    while (nr) {
        unsigned int cnt;
        unsigned long mask = lsi_word_mask(start, nr, &cnt);

        added += ctpopl(~qatomic_fetch_or(map + BIT_WORD(start), mask) &
                        mask);
        start += cnt;
        nr -= cnt;
    }
    return added;
}

/* clear [start, start + nr); the count of bits that went from 1 to 0 */
static uint64_t lsi_test_and_clear(unsigned long *map, uint64_t start,
                                   uint64_t nr)
{
    uint64_t gone = 0;

    while (nr) {
        unsigned int cnt;
        unsigned long mask = lsi_word_mask(start, nr, &cnt);

        gone += ctpopl(qatomic_fetch_and(map + BIT_WORD(start), ~mask) &
                       mask);
        start += cnt;
        nr -= cnt;
    }
    return gone;
}

/*
 * Publish a change of the tracked bits, after the bits. nr_unc is exact
 * only while the pollers are paused. add_ver steps before media_ver, with
 * a write barrier, so a reader that sees the new media_ver also sees the
 * bits and the new add_ver.
 */
void femu_lsi_changed(NvmeNamespace *ns, uint64_t added, uint64_t gone)
{
    if (!added && !gone) {
        return;
    }
    qatomic_add(&ns->lsi_nr_unc, added - gone);
    if (added) {
        qatomic_inc(&ns->lsi_add_ver);
    }
    smp_wmb();  /* pairs with the acquire of media_ver before a scan */
    qatomic_inc(&ns->lsi_media_ver);
}

/* mark blocks tracked; a block already tracked is no change */
void femu_lsi_mark(NvmeNamespace *ns, uint64_t slba, uint64_t nlb)
{
    femu_lsi_changed(ns, lsi_test_and_set(ns->uncorrectable, slba, nlb), 0);
}

/* blocks read back again: they are no longer tracked */
void femu_lsi_clear(NvmeNamespace *ns, uint64_t slba, uint64_t nlb)
{
    if (ns->uncorrectable) {
        femu_lsi_changed(ns, 0,
                         lsi_test_and_clear(ns->uncorrectable, slba, nlb));
    }
}

/* the whole map was cleared, with the pollers paused */
void femu_lsi_zeroed(NvmeNamespace *ns)
{
    femu_lsi_changed(ns, 0, qatomic_read(&ns->lsi_nr_unc));
}

/* the map came from a file, before the dataplane runs */
void femu_lsi_loaded(NvmeNamespace *ns)
{
    uint64_t nr = bitmap_count_one(ns->uncorrectable, ns->ns_blks);

    ns->lsi_nr_unc = 0;
    femu_lsi_changed(ns, nr, 0);
}

/*
 * A rollback set tracked bit @lba to @on, with the pollers paused. Call
 * femu_lsi_changed() with the sums after the loop.
 */
void femu_lsi_restore(NvmeNamespace *ns, uint64_t lba, bool on,
                      uint64_t *added, uint64_t *gone)
{
    if (on) {
        *added += !test_and_set_bit(lba, ns->uncorrectable);
    } else {
        *gone += test_and_clear_bit(lba, ns->uncorrectable);
    }
}

static uint8_t lsi_lbads(NvmeNamespace *ns)
{
    return ns->id_ns.lbaf[NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas)].lbads;
}

static void lsi_cov_clear(FemuLsiCov *c)
{
    g_free(c->runs);
    memset(c, 0, sizeof(*c));
}

static void lsi_page_free(FemuLsiPage *s)
{
    if (!s) {
        return;
    }
    for (uint32_t i = 0; i < s->ncov; i++) {
        g_free(s->cov[i].runs);
    }
    g_free(s->cov);
    g_free(s->buf);
    g_free(s);
}

/*
 * The runs of @ns as wire descriptors, at most LSI_MAX_DESC; a run longer
 * than 2^32 blocks takes several. Returns false when more are needed.
 */
static bool lsi_scan(NvmeNamespace *ns, FemuLsiRun *runs, uint32_t *nruns,
                     uint64_t *blocks)
{
    uint64_t nsze = le64_to_cpu(ns->id_ns.nsze);
    uint64_t lba = 0;

    *nruns = 0;
    *blocks = 0;
    while (lba < nsze) {
        uint64_t first = find_next_bit(ns->uncorrectable, nsze, lba);
        uint64_t last;

        if (first >= nsze) {
            break;
        }
        last = find_next_zero_bit(ns->uncorrectable, nsze, first);
        *blocks += last - first;
        while (first < last) {
            uint64_t nlb = MIN(last - first, (uint64_t)UINT32_MAX + 1);

            if (*nruns == LSI_MAX_DESC) {
                *blocks = bitmap_count_one(ns->uncorrectable, nsze);
                return false;
            }
            runs[*nruns].slba = first;
            runs[*nruns].nlb = nlb;
            (*nruns)++;
            first += nlb;
        }
        lba = last;
    }
    return true;
}

/* does the page element @p list a block that the last read @r did not? */
static bool lsi_cov_new(NvmeNamespace *ns, const FemuLsiCov *p,
                        const FemuLsiCov *r)
{
    uint64_t nsze = le64_to_cpu(ns->id_ns.nsze);
    uint64_t pos = 0;

    if (!r->inc || r->inc != p->inc || r->lbads != p->lbads) {
        return true;
    }
    if (r->sentinel) {
        return !p->sentinel || p->add_ver != r->add_ver;
    }
    for (uint32_t k = 0; k < r->nruns; k++) {
        if (find_next_bit(ns->uncorrectable, r->runs[k].slba, pos) <
            r->runs[k].slba) {
            return true;
        }
        pos = r->runs[k].slba + r->runs[k].nlb;
    }
    return find_next_bit(ns->uncorrectable, nsze, pos) < nsze;
}

/* the current generation when no page is held; pollers paused */
static FemuLsiPage *lsi_capture(FemuCtrl *n)
{
    g_autofree FemuLsiRun *runs = g_try_new(FemuLsiRun, LSI_MAX_DESC);
    FemuLsiPage *s = g_try_new0(FemuLsiPage, 1);
    uint64_t estulb = 0;
    bool fresh = false;
    uint32_t len = LSI_HDR;
    uint8_t *p;

    if (s) {
        s->cov = g_try_new0(FemuLsiCov, n->namespace_limit);
    }
    if (!runs || !s || !s->cov) {
        lsi_page_free(s);
        return NULL;
    }
    for (uint32_t i = 0; i < n->namespace_limit; i++) {
        NvmeNamespace *ns = nvme_ns(n, i + 1);
        FemuLsiCov *c = &s->cov[s->ncov];
        uint32_t nruns;
        uint64_t blocks;
        bool exact;

        if (!ns || !ns->uncorrectable || !qatomic_read(&ns->lsi_nr_unc)) {
            continue;
        }
        c->add_ver = qatomic_read(&ns->lsi_add_ver);
        exact = lsi_scan(ns, runs, &nruns, &blocks);
        if (!blocks) {
            continue;
        }
        c->nsid = i + 1;
        c->inc = ns->lsi_inc;
        c->lbads = lsi_lbads(ns);
        c->sentinel = !exact;
        if (exact) {
            c->runs = g_try_new(FemuLsiRun, nruns);
            if (!c->runs) {
                lsi_page_free(s);
                return NULL;
            }
            memcpy(c->runs, runs, nruns * sizeof(*runs));
            c->nruns = nruns;
        }
        s->ncov++;
        fresh |= lsi_cov_new(ns, c, &n->lsi_r[i]);
        estulb += blocks;
        len += LSI_ELEM_HDR + LSI_DESC * c->nruns;
    }

    s->gen = MAX(n->lsi_g_pub, n->lsi_g_r + fresh);
    s->len = len;
    s->buf = g_try_malloc0(len);
    if (!s->buf) {
        lsi_page_free(s);
        return NULL;
    }
    stl_le_p(s->buf, len);
    stl_le_p(s->buf + 4, s->ncov);
    stl_le_p(s->buf + 8, MIN(estulb, (uint64_t)UINT32_MAX - 1));
    stw_le_p(s->buf + 14, s->gen);
    p = s->buf + LSI_HDR;
    for (uint32_t e = 0; e < s->ncov; e++) {
        FemuLsiCov *c = &s->cov[e];

        stl_le_p(p, c->nsid);
        stl_le_p(p + 4, c->sentinel ? LSI_NLRD_ALL : c->nruns);
        p[8] = LSI_RATYPE_TRACKED;
        p += LSI_ELEM_HDR;
        c->boff = p - s->buf;
        for (uint32_t k = 0; k < c->nruns; k++, p += LSI_DESC) {
            stq_le_p(p, c->runs[k].slba);
            stl_le_p(p + 8, c->runs[k].nlb - 1);
        }
        /* the bytes hold the runs from here on */
        g_clear_pointer(&c->runs, g_free);
    }
    return s;
}

/*
 * The coverage a successful read of @s leaves as R. An element of a
 * namespace that was deleted or recreated since the capture installs
 * nothing. Built before the transfer, so a failed allocation fails the
 * command with no state change.
 */
static FemuLsiCov *lsi_build_r(FemuCtrl *n, const FemuLsiPage *s)
{
    FemuLsiCov *r = g_try_new0(FemuLsiCov, n->namespace_limit);

    if (!r) {
        return NULL;
    }
    for (uint32_t e = 0; e < s->ncov; e++) {
        const FemuLsiCov *c = &s->cov[e];
        NvmeNamespace *ns = nvme_ns_allocated(n, c->nsid);
        FemuLsiCov *d = &r[c->nsid - 1];
        const uint8_t *p = s->buf + c->boff;

        if (!ns || ns->lsi_inc != c->inc || lsi_lbads(ns) != c->lbads) {
            continue;
        }
        *d = *c;
        if (c->nruns) {
            d->runs = g_try_new(FemuLsiRun, c->nruns);
            if (!d->runs) {
                femu_lsi_free_cov(n, r);
                return NULL;
            }
        }
        for (uint32_t k = 0; k < c->nruns; k++, p += LSI_DESC) {
            d->runs[k].slba = ldq_le_p(p);
            d->runs[k].nlb = (uint64_t)ldl_le_p(p + 8) + 1;
        }
    }
    return r;
}

void femu_lsi_free_cov(FemuCtrl *n, FemuLsiCov *r)
{
    if (!r) {
        return;
    }
    for (uint32_t i = 0; i < n->namespace_limit; i++) {
        lsi_cov_clear(&r[i]);
    }
    g_free(r);
}

uint16_t femu_lsi_log(FemuCtrl *n, NvmeCmd *cmd, uint32_t buf_len,
                      uint64_t off, bool rae)
{
    FemuLsiPage *s = n->lsi_s;
    bool fresh = !s;
    FemuLsiCov *r;
    uint16_t status;

    if (fresh) {
        bool resume = nvme_pause_pollers(n);

        s = lsi_capture(n);
        nvme_resume_pollers(n, resume);
        if (!s) {
            return NVME_INTERNAL_DEV_ERROR;
        }
    }
    r = off < s->len ? lsi_build_r(n, s) : NULL;
    if (off >= s->len) {
        status = NVME_INVALID_FIELD | NVME_DNR;
    } else if (!r) {
        status = NVME_INTERNAL_DEV_ERROR;
    } else {
        status = dma_read_prp(n, s->buf + off, MIN(s->len - off, buf_len),
                              le64_to_cpu(cmd->dptr.prp1),
                              le64_to_cpu(cmd->dptr.prp2));
    }
    if (status) {
        femu_lsi_free_cov(n, r);
        if (fresh) {
            lsi_page_free(s);
        }
        return status;
    }

    /* the transfer worked: the host has read this page */
    femu_lsi_free_cov(n, n->lsi_r);
    n->lsi_r = r;
    n->lsi_g_r = s->gen;
    n->lsi_g_pub = MAX(n->lsi_g_pub, s->gen);
    if (rae) {
        n->lsi_s = s;
    } else {
        n->lsi_s = NULL;
        lsi_page_free(s);
    }
    return NVME_SUCCESS;
}

/* a deleted namespace leaves R on every controller that read it */
void femu_lsi_ns_gone(FemuCtrl *n, NvmeNamespace *ns)
{
    for (uint32_t i = 0; i < NVME_MAX_CONTROLLERS; i++) {
        FemuCtrl *ctrl = nvme_ns_shared(n) ? nvme_subsys_ctrl(n->subsys, i) :
                         (i ? NULL : n);
        FemuLsiCov *r;

        if (!ctrl || !ctrl->lsi_r || ns->id > ctrl->namespace_limit) {
            continue;
        }
        r = &ctrl->lsi_r[ns->id - 1];
        if (r->inc == ns->lsi_inc) {
            lsi_cov_clear(r);
        }
    }
}

void femu_lsi_init(FemuCtrl *n)
{
    n->lsi_r = g_new0(FemuLsiCov, n->namespace_limit);
}

/* a controller reset ends a retained read; R and the counters stay */
void femu_lsi_reset(FemuCtrl *n)
{
    lsi_page_free(n->lsi_s);
    n->lsi_s = NULL;
}

void femu_lsi_exit(FemuCtrl *n)
{
    femu_lsi_reset(n);
    femu_lsi_free_cov(n, n->lsi_r);
    n->lsi_r = NULL;
}
