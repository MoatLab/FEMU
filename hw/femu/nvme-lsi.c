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
#include "qemu/main-loop.h"
#include "qapi/error.h"
#include "qapi/visitor.h"

#define LSI_HDR             16
#define LSI_ELEM_HDR        16
#define LSI_DESC            16
#define LSI_MAX_DESC        256
#define LSI_NLRD_ALL        0xffffffffu
#define LSI_RATYPE_TRACKED  0x11
#define LSI_INFO_ALERT      0x05        /* notice: LBA Status Information */
#define LSI_AEC             (1u << 13)  /* AEC: LBA Status Information */
#define LSI_UNIT_NS         (100 * SCALE_MS)
#define LSI_SCAN_GAP_NS     (100 * SCALE_MS)
#define LSI_STOP_HELD       0x100
#define LSI_STOP_LIMIT_NS   (5 * NANOSECONDS_PER_SECOND)

enum { LSI_IDLE, LSI_QUEUED, LSI_REPORTED };

/*
 * Every realized controller, for the kick: a namespace can be shared, and
 * the controller its pollers run on is not the only one that reports it.
 * Only the main loop walks or changes the list.
 */
static QLIST_HEAD(, FemuCtrl) lsi_ctrls = QLIST_HEAD_INITIALIZER(lsi_ctrls);
static QEMUBH *lsi_kick_bh;
static uint64_t lsi_topo;       /* steps on attach, detach and delete */

static void lsi_stop_point(NvmeNamespace *ns, uint32_t stage);

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
        lsi_stop_point(ns, 2);
    }
    smp_wmb();  /* pairs with the acquire of media_ver before a scan */
    qatomic_inc(&ns->lsi_media_ver);
    if (qatomic_read(&lsi_kick_bh)) {
        qemu_bh_schedule(lsi_kick_bh);
    }
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
        if (last == first) {
            /* a write cleared it after the first search */
            lba = first + 1;
            continue;
        }
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

static int64_t lsi_now(void)
{
    return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
}

static int64_t lsi_deadline(FemuCtrl *n)
{
    return n->lsi_last_clear + (int64_t)n->features.lsiri * LSI_UNIT_NS;
}

/*
 * A test stops one Write Uncorrectable at @stage: 1 before its bits are
 * set, 2 between its add_ver and media_ver steps. The first WU to reach
 * the stage takes it; the test releases it, or 5 s of real time does.
 */
static void lsi_stop_point(NvmeNamespace *ns, uint32_t stage)
{
    FemuCtrl *n = ns->ctrl;
    int64_t end;

    if (!n || qatomic_read(&n->lsi_wu_stop) != stage ||
        qatomic_cmpxchg(&n->lsi_wu_stop, stage, stage | LSI_STOP_HELD) !=
        stage) {
        return;
    }
    end = get_clock_realtime() + LSI_STOP_LIMIT_NS;
    while (qatomic_read(&n->lsi_wu_stop) == (stage | LSI_STOP_HELD) &&
           get_clock_realtime() < end) {
        g_usleep(100);
    }
    qatomic_cmpxchg(&n->lsi_wu_stop, stage | LSI_STOP_HELD, 0);
}

void femu_lsi_wu_stop(NvmeNamespace *ns)
{
    lsi_stop_point(ns, 1);
}

static bool lsi_cache_valid(FemuCtrl *n)
{
    if (!n->lsi_cache_ok || n->lsi_cache_rver != n->lsi_r_ver ||
        n->lsi_cache_topo != qatomic_read(&lsi_topo)) {
        return false;
    }
    for (uint32_t i = 0; i < n->namespace_limit; i++) {
        NvmeNamespace *ns = nvme_ns(n, i + 1);
        uint64_t v = ns ? qatomic_load_acquire(&ns->lsi_media_ver) : 0;

        if (v != n->lsi_cache_mver[i]) {
            return false;
        }
    }
    return true;
}

/*
 * The generation and "tracked blocks exist" of the page a capture would
 * make now, with the pollers running. The key is sampled before the scan,
 * so a change that the scan misses moves media_ver past the key.
 */
static void lsi_eval_scan(FemuCtrl *n)
{
    g_autofree FemuLsiRun *runs = g_new(FemuLsiRun, LSI_MAX_DESC);
    bool fresh = false;

    n->lsi_cache_tracked = false;
    n->lsi_cache_rver = n->lsi_r_ver;
    n->lsi_cache_topo = qatomic_read(&lsi_topo);
    for (uint32_t i = 0; i < n->namespace_limit; i++) {
        NvmeNamespace *ns = nvme_ns(n, i + 1);
        FemuLsiCov c = { 0 };
        uint32_t nruns;
        uint64_t blocks;
        bool exact;

        n->lsi_cache_mver[i] = ns ? qatomic_load_acquire(&ns->lsi_media_ver) :
                               0;
        if (!ns || !ns->uncorrectable) {
            continue;
        }
        c.add_ver = qatomic_read(&ns->lsi_add_ver);
        exact = lsi_scan(ns, runs, &nruns, &blocks);
        if (!blocks) {
            continue;
        }
        c.inc = ns->lsi_inc;
        c.lbads = lsi_lbads(ns);
        c.sentinel = !exact;
        n->lsi_cache_tracked = true;
        fresh |= lsi_cov_new(ns, &c, &n->lsi_r[i]);
    }
    n->lsi_cache_gen = MAX(n->lsi_g_pub, n->lsi_g_r + fresh);
    n->lsi_cache_ok = true;
}

static void lsi_arm(FemuCtrl *n, int64_t when)
{
    if (!timer_pending(n->lsi_timer) ||
        timer_expire_time_ns(n->lsi_timer) > when) {
        timer_mod(n->lsi_timer, when);
    }
}

/*
 * Admit an alert (design 11.3, 12.1): AEC bit 13 set, none queued or
 * reported, and a component failure, or LSIRI passed since the last clear
 * with tracked blocks in a page of a newer generation than the last alert.
 */
void femu_lsi_eval(FemuCtrl *n)
{
    int64_t now = lsi_now();
    bool tracked;
    uint64_t gen;

    if (!n->lsi_timer || n->lsi_alert != LSI_IDLE ||
        !(n->features.async_config & LSI_AEC) || !NVME_CC_EN(n->bar.cc)) {
        return;
    }
    if (!n->lsi_comp_pending) {
        if (now < lsi_deadline(n)) {
            lsi_arm(n, lsi_deadline(n));
            return;
        }
        if (n->lsi_s) {
            tracked = n->lsi_s->ncov;
            gen = n->lsi_s->gen;
        } else {
            if (!lsi_cache_valid(n)) {
                if (now < n->lsi_last_scan + LSI_SCAN_GAP_NS) {
                    lsi_arm(n, n->lsi_last_scan + LSI_SCAN_GAP_NS);
                    return;
                }
                n->lsi_last_scan = now;
                lsi_eval_scan(n);
            }
            tracked = n->lsi_cache_tracked;
            gen = n->lsi_cache_gen;
        }
        if (!tracked || gen <= n->lsi_alert_gen) {
            return;
        }
    }
    if (nvme_enqueue_event(n, NVME_AER_TYPE_NOTICE, LSI_INFO_ALERT,
                           NVME_LOG_LBA_STATUS)) {
        n->lsi_alert = LSI_QUEUED;
    } else {
        n->lsi_rejects++;
    }
}

static void lsi_timer_cb(void *opaque)
{
    femu_lsi_eval(opaque);
}

static void lsi_kick(void *opaque)
{
    FemuCtrl *n;

    QLIST_FOREACH(n, &lsi_ctrls, lsi_link) {
        femu_lsi_eval(n);
    }
}

bool femu_lsi_is_alert(NvmeAsyncEvent *e)
{
    return e->result.event_type == NVME_AER_TYPE_NOTICE &&
           e->result.event_info == LSI_INFO_ALERT &&
           e->result.log_page == NVME_LOG_LBA_STATUS;
}

/*
 * The queued alert is about to be posted (BQL). The page and its
 * generation come from one capture, and the alert is checked against
 * that page. A failed check drops the event; returns whether to post.
 */
bool femu_lsi_post(FemuCtrl *n)
{
    FemuLsiPage *s = n->lsi_s;
    bool fresh = !s;
    bool ok;

    if (fresh) {
        bool resume = nvme_pause_pollers(n);

        s = lsi_capture(n);
        nvme_resume_pollers(n, resume);
    }
    n->lsi_alert = LSI_IDLE;
    if (!s) {
        lsi_arm(n, lsi_now() + LSI_SCAN_GAP_NS);
        return false;
    }
    ok = (n->features.async_config & LSI_AEC) &&
         (n->lsi_comp_pending ||
          (lsi_now() >= lsi_deadline(n) && s->ncov &&
           s->gen > n->lsi_alert_gen));
    if (!ok) {
        if (fresh) {
            lsi_page_free(s);
        }
        n->lsi_cache_ok = false;
        qemu_bh_schedule(lsi_kick_bh);
        return false;
    }
    n->lsi_s = s;
    n->lsi_alert_gen = s->gen;
    n->lsi_g_pub = MAX(n->lsi_g_pub, s->gen);
    n->lsi_alert = LSI_REPORTED;
    n->lsi_comp_unacked = n->lsi_comp_pending;
    n->lsi_comp_pending = false;
    return true;
}

/* CC.EN 0 to 1 (design 9.7): LSIRI counts from here, not from ready */
void femu_lsi_start(FemuCtrl *n)
{
    n->lsi_last_clear = lsi_now();
}

/* an event left the queue, so there is room for a refused alert */
void femu_lsi_room(FemuCtrl *n)
{
    if (n->lsi_alert == LSI_IDLE && lsi_kick_bh) {
        qemu_bh_schedule(lsi_kick_bh);
    }
}

/* a successful RAE=0 read: the alert clears and LSIRI starts again */
static void lsi_cleared(FemuCtrl *n)
{
    nvme_clear_ns_events(n, NVME_AER_TYPE_NOTICE, NVME_LOG_LBA_STATUS, 0,
                         true);
    n->lsi_alert = LSI_IDLE;
    n->lsi_comp_unacked = false;
    n->lsi_last_clear = lsi_now();
    femu_lsi_eval(n);
    qemu_bh_schedule(n->aer_bh);
}

/* Set Features: AEC changed from @old, or LSIRI changed */
void femu_lsi_config(FemuCtrl *n, uint32_t old)
{
    if ((old & LSI_AEC) && !(n->features.async_config & LSI_AEC) &&
        n->lsi_alert == LSI_QUEUED) {
        uint8_t mask = n->aer_mask;

        /* an unsent alert goes; a sent one stays unacknowledged */
        nvme_clear_ns_events(n, NVME_AER_TYPE_NOTICE, NVME_LOG_LBA_STATUS, 0,
                             true);
        n->aer_mask = mask;
        n->lsi_alert = LSI_IDLE;
    }
    if (n->lsi_timer) {
        timer_del(n->lsi_timer);
    }
    femu_lsi_eval(n);
}

/* a media failure that may have made blocks unrecoverable (R2b) */
void femu_lsi_component(FemuCtrl *n, NvmeNamespace *ns)
{
    FemuCtrl *c;

    QLIST_FOREACH(c, &lsi_ctrls, lsi_link) {
        if (c == n || (nvme_ns_shared(n) && c->subsys == n->subsys &&
                       nvme_ns(c, ns->id))) {
            c->lsi_comp_pending = true;
            femu_lsi_eval(c);
        }
    }
}

void femu_lsi_topology(void)
{
    qatomic_inc(&lsi_topo);
    if (lsi_kick_bh) {
        qemu_bh_schedule(lsi_kick_bh);
    }
}

static void lsi_state_get(Object *obj, Visitor *v, const char *name,
                          void *opaque, Error **errp)
{
    FemuCtrl *n = FEMU(obj);
    NvmeNamespace *ns = nvme_ns_allocated(n, 1);
    g_autofree char *s = g_strdup_printf(
        "alert=%u g_r=%" PRIu64 " g_pub=%" PRIu64 " alert_gen=%" PRIu64
        " comp=%u unacked=%u rejects=%" PRIu64 " add=%" PRIu64
        " media=%" PRIu64 " unc=%" PRIu64 " stop=%u",
        n->lsi_alert, n->lsi_g_r, n->lsi_g_pub, n->lsi_alert_gen,
        n->lsi_comp_pending, n->lsi_comp_unacked, n->lsi_rejects,
        ns ? qatomic_read(&ns->lsi_add_ver) : 0,
        ns ? qatomic_read(&ns->lsi_media_ver) : 0,
        ns ? qatomic_read(&ns->lsi_nr_unc) : 0,
        qatomic_read(&n->lsi_wu_stop));

    visit_type_str(v, name, &s, errp);
}

/*
 * Test commands: "stop:S" stops the next WU at stage S (0 releases);
 * "component:NSID" reports a component failure; "gen:G" sets every
 * generation to G; "glsrace:1" clears the start bit of the next Get LBA
 * Status run; "fill:K" queues K distinct vendor events; "eval:1" runs an
 * admission check.
 */
static void lsi_test_set(Object *obj, const char *value, Error **errp)
{
    FemuCtrl *n = FEMU(obj);
    g_auto(GStrv) f = g_strsplit(value, ":", 2);
    uint64_t v;
    NvmeNamespace *ns;

    if (g_strv_length(f) != 2 || qemu_strtou64(f[1], NULL, 0, &v)) {
        error_setg(errp, "x-lsi: bad command '%s'", value);
        return;
    }
    ns = v && v <= UINT32_MAX ? nvme_ns(n, v) : NULL;
    if (!strcmp(f[0], "stop") && v <= 2) {
        qatomic_set(&n->lsi_wu_stop, v);
    } else if (!strcmp(f[0], "component") && ns) {
        femu_lsi_component(n, ns);
    } else if (!strcmp(f[0], "gen")) {
        n->lsi_g_r = n->lsi_g_pub = n->lsi_alert_gen = v;
        n->lsi_cache_ok = false;
    } else if (!strcmp(f[0], "eval")) {
        femu_lsi_eval(n);
    } else if (!strcmp(f[0], "glsrace")) {
        n->lsi_gls_race = v;
    } else if (!strcmp(f[0], "fill") && v <= 64) {
        for (uint64_t i = 0; i < v; i++) {
            nvme_enqueue_event(n, NVME_AER_TYPE_VENDOR_SPECIFIC, 0x10 + i,
                               0);
        }
    } else {
        error_setg(errp, "x-lsi: bad command '%s'", value);
    }
}

void femu_lsi_add_props(Object *obj)
{
    object_property_add(obj, "x-lsi-state", "str", lsi_state_get, NULL,
                        NULL, NULL);
    object_property_add_str(obj, "x-lsi", NULL, lsi_test_set);
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
    n->lsi_r_ver++;
    if (rae) {
        n->lsi_s = s;
    } else {
        n->lsi_s = NULL;
        lsi_page_free(s);
        lsi_cleared(n);
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
    n->lsi_cache_mver = g_new0(uint64_t, n->namespace_limit);
    n->lsi_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, lsi_timer_cb, n);
    n->lsi_last_clear = lsi_now();
    n->id_ctrl.oaes |= cpu_to_le32(LSI_AEC);
    if (!lsi_kick_bh) {
        qatomic_set(&lsi_kick_bh, qemu_bh_new(lsi_kick, NULL));
    }
    QLIST_INSERT_HEAD(&lsi_ctrls, n, lsi_link);
    n->lsi_listed = true;
}

/*
 * Controller reset (design 9.7): the AER queue and mask are gone. An
 * alert the host did not acknowledge comes back after the deadline; an
 * acknowledged state gives no new one, since alert_gen <= G_R.
 */
void femu_lsi_reset(FemuCtrl *n)
{
    lsi_page_free(n->lsi_s);
    n->lsi_s = NULL;
    if (n->lsi_alert == LSI_REPORTED) {
        n->lsi_alert_gen = MIN(n->lsi_alert_gen, n->lsi_g_r);
    }
    n->lsi_alert = LSI_IDLE;
    n->lsi_comp_pending |= n->lsi_comp_unacked;
    n->lsi_comp_unacked = false;
    n->lsi_cache_ok = false;
    n->lsi_last_clear = lsi_now();
    if (n->lsi_timer) {
        timer_del(n->lsi_timer);
    }
}

void femu_lsi_exit(FemuCtrl *n)
{
    lsi_page_free(n->lsi_s);
    n->lsi_s = NULL;
    if (n->lsi_listed) {
        QLIST_REMOVE(n, lsi_link);
        n->lsi_listed = false;
    }
    g_clear_pointer(&n->lsi_timer, timer_free);
    g_clear_pointer(&n->lsi_cache_mver, g_free);
    femu_lsi_free_cov(n, n->lsi_r);
    n->lsi_r = NULL;
}
