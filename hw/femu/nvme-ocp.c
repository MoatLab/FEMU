/*
 * OCP Datacenter NVMe SSD 2.7 latency monitor (ocp=on): feature C5h, log C3h
 * and the collector on the completion path (OCP 2.7 4.8.8, 4.8.9, 4.15.11,
 * 4.15.12 and section 22).
 *
 *   completion (any poller)    d < A: nothing, no lock
 *                              d >= A: lock, seqlock write, update, unlock
 *   Set Features C5h, 0Eh      lock, seqlock write
 *   Get Log C3h                seqlock read only: it never blocks a poller
 *
 * One state per controller, so the minimum window of each bucket and
 * opcode pair is shared by every poller.
 */

#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "./nvme.h"

#define LM_MS               1000000LL
#define LM_INTERVAL_NS      (300LL * 1000 * LM_MS)  /* timer step: 5 minutes */
#define LM_STAMP_INVALID    UINT64_MAX

/* the clock of the monitor; x-ocp-lat-skew-ms moves it forward under qtest */
static int64_t femu_ocp_lat_now(FemuCtrl *n)
{
    return femu_io_now(n) +
           (int64_t)qatomic_read(&n->test_ocp_lat_skew_ms) * LM_MS;
}

/* threshold byte v is (v + 1) x 5 ms */
static int64_t lm_threshold_ns(uint8_t v)
{
    return ((int64_t)v + 1) * 5 * LM_MS;
}

static void lm_clear_set(FemuOcpLatSet *s)
{
    memset(s, 0, sizeof(*s));
    for (int b = 0; b < 4; b++) {
        for (int o = 0; o < 3; o++) {
            s->stamp[b][o] = LM_STAMP_INVALID;
        }
    }
}

/* the factory defaults of LMDATA-1 to LMDATA-10, both sets cleared */
void femu_ocp_lat_init(FemuCtrl *n)
{
    FemuOcpLatState *s = &n->ocp_lat.s;

    memset(s, 0, sizeof(*s));
    s->enabled = true;
    s->timer_threshold = 0x07e0;
    s->thr[0] = 0x05;
    s->thr[1] = 0x13;
    s->thr[2] = 0x1e;
    s->thr[3] = 0x2e;
    s->config = 0x0fff;
    s->min_window = 0x0a;
    s->epoch_ns = femu_ocp_lat_now(n);
    s->cfg_t = s->epoch_ns;
    s->pon_ms = nvme_timestamp_now_ms(n);
    lm_clear_set(&s->act);
    lm_clear_set(&s->st);
}

static void lm_write_begin(FemuOcpLat *lm)
{
    qemu_mutex_lock(&lm->lock);
    seqlock_write_begin(&lm->seq);
}

static void lm_write_end(FemuOcpLat *lm)
{
    seqlock_write_end(&lm->seq);
    qemu_mutex_unlock(&lm->lock);
}

/*
 * A power cycle restarts every minimum window (22.2.3.6, 22.5.1) and the
 * power-on time. The counts and the host baseline stay (LMLOG-1, 22.2.3.4).
 */
void femu_ocp_lat_power_cycle(FemuCtrl *n)
{
    FemuOcpLat *lm = &n->ocp_lat;

    lm_write_begin(lm);
    memset(lm->s.act.win_end, 0, sizeof(lm->s.act.win_end));
    memset(lm->s.st.win_end, 0, sizeof(lm->s.st.win_end));
    lm->s.pon_ms = nvme_timestamp_now_ms(n);
    lm_write_end(lm);
}

/*
 * Set Features Timestamp: the new baseline of the latency stamps. The one
 * before stays for a completion that came before this set.
 */
void femu_ocp_lat_host_ts(FemuCtrl *n, uint64_t value)
{
    FemuOcpLat *lm = &n->ocp_lat;

    lm_write_begin(lm);
    lm->s.prev = lm->s.base;
    lm->s.base.set = true;
    lm->s.base.ms = value & ((1ULL << 48) - 1);
    lm->s.base.anchor_ms = nvme_timestamp_now_ms(n);
    lm->s.base.t = femu_ocp_lat_now(n);
    lm_write_end(lm);
}

/*
 * Move the active set to the static one for every whole timer interval
 * since the epoch. After two or more intervals the last one was empty, so
 * the static set is empty too. The remainder stays in the epoch.
 */
static void lm_rotate(FemuOcpLatState *s, int64_t now)
{
    int64_t period = (int64_t)s->timer_threshold * LM_INTERVAL_NS;
    int64_t k;

    if (!period || now - s->epoch_ns < period) {
        return;
    }
    k = (now - s->epoch_ns) / period;
    if (k == 1) {
        s->st = s->act;
    } else {
        lm_clear_set(&s->st);
    }
    lm_clear_set(&s->act);
    s->epoch_ns += k * period;
}

/* the opcode slot of a monitored command, or -1: Read, Write, DSM with AD */
static int lm_opcode(NvmeRequest *req)
{
    switch (req->cmd_opcode) {
    case NVME_CMD_READ:
        return 0;
    case NVME_CMD_WRITE:
        return 1;
    case NVME_CMD_DSM:
        return le32_to_cpu(req->cmd.cdw11) & NVME_DSMGMT_AD ? 2 : -1;
    default:
        return -1;
    }
}

/*
 * Count one I/O command whose CQE was written at @post. Every decision
 * uses the completion, not the time this thread got the lock:
 *
 *   t = post on the monitor clock;  ms = power-on milliseconds at entry
 *   t < cfg_t             --> it belongs to the configuration before C5h
 *   t >= epoch            --> active set (after a rotation to t)
 *   epoch - period <= t   --> static set: a completion that waited behind
 *                             a rotation still counts in its own interval
 *   older                 --> its interval is gone; nothing
 *   stamp = baseline that was in force at t, plus (ms - its anchor)
 *
 * Mode 0 keeps the earliest completion. Mode 1 keeps the largest latency,
 * at most once per minimum window from the completion time.
 */
void femu_ocp_lat_note(FemuCtrl *n, NvmeRequest *req, int64_t post)
{
    FemuOcpLat *lm = &n->ocp_lat;
    FemuOcpLatState *s = &lm->s;
    int64_t d = post - req->t_submit;
    int64_t t = post + (int64_t)qatomic_read(&n->test_ocp_lat_skew_ms) * LM_MS;
    int64_t ms = nvme_timestamp_now_ms(n);
    const FemuOcpLatBase *base;
    int o = lm_opcode(req);
    FemuOcpLatSet *set;
    int64_t period;
    int b, bit;

    if (o < 0 || !qatomic_read(&s->enabled) ||
        d < lm_threshold_ns(qatomic_read(&s->thr[0]))) {
        return;
    }
    lm_write_begin(lm);
    if (!s->enabled || d < lm_threshold_ns(s->thr[0]) || t < s->cfg_t) {
        goto out;
    }
    lm_rotate(s, t);
    period = (int64_t)s->timer_threshold * LM_INTERVAL_NS;
    if (t >= s->epoch_ns) {
        set = &s->act;
    } else if (period && t >= s->epoch_ns - period) {
        set = &s->st;
    } else {
        goto out;
    }
    for (b = 3; b > 0 && d < lm_threshold_ns(s->thr[b]); b--) {
    }
    bit = 1 << (3 * b + o);
    if (set->count[b][o] != UINT32_MAX) {
        set->count[b][o]++;
    }
    if (!(s->config & bit)) {
        if (set->stamp[b][o] != LM_STAMP_INVALID && set->done_ns[b][o] <= t) {
            goto out;
        }
    } else if (!s->min_window) {
        if (d <= set->lat_ns[b][o]) {
            goto out;
        }
    } else {
        if (t < set->win_end[b][o] || d <= set->lat_ns[b][o]) {
            goto out;
        }
        set->win_end[b][o] = t + (int64_t)s->min_window * 100 * LM_MS;
    }
    base = s->base.set && t >= s->base.t ? &s->base :
           s->prev.set && t >= s->prev.t ? &s->prev : NULL;
    set->lat_ns[b][o] = d;
    set->done_ns[b][o] = t;
    set->lat_ms[b][o] = MIN(d / LM_MS, UINT16_MAX);
    if (base) {
        set->stamp[b][o] = (base->ms + (ms - base->anchor_ms)) &
                           ((1ULL << 48) - 1);
        set->units |= bit;
    } else {
        set->stamp[b][o] = MAX(ms - s->pon_ms, 0) & ((1ULL << 48) - 1);
        set->units &= ~bit;
    }
out:
    lm_write_end(lm);
}

static const uint8_t lm_guid[16] = {
    0x92, 0x7a, 0xc0, 0x8c, 0xd0, 0x84, 0x6c, 0x9c,
    0x70, 0x43, 0xe6, 0xd4, 0x58, 0x5e, 0xd4, 0x85,
};

/*
 * One bucket set into the page at @base (32 active, 240 static). In each
 * 16-byte counter record the order is reserved, Deallocate, Write, Read;
 * the stamps and latencies run in reverse: pair i = 3 x bucket + opcode
 * sits at 184 - 8 i and 214 - 2 i from the active base.
 */
static void lm_put_set(uint8_t *log, int shift, const FemuOcpLatSet *s)
{
    for (int b = 0; b < 4; b++) {
        for (int o = 0; o < 3; o++) {
            int i = 3 * b + o;

            stl_le_p(&log[shift + 32 + 16 * b + 12 - 4 * o], s->count[b][o]);
            stq_le_p(&log[shift + 184 - 8 * i], s->stamp[b][o]);
            stw_le_p(&log[shift + 214 - 2 * i], s->lat_ms[b][o]);
        }
    }
    stw_le_p(&log[shift + 216], s->units);
}

/*
 * Log C3h: 512 bytes, version 0005h; bytes 512 to 4095 read as zeros. The
 * read copies the state under the seqlock and rotates the copy, so it
 * never takes the lock a poller takes (LMLOG-4).
 */
uint16_t femu_ocp_lat_log(FemuCtrl *n, NvmeCmd *cmd, uint32_t len,
                          uint64_t off)
{
    FemuOcpLat *lm = &n->ocp_lat;
    g_autofree FemuOcpLatState *c = g_new(FemuOcpLatState, 1);
    g_autofree uint8_t *log = NULL;
    int64_t now;
    int64_t steps;
    unsigned seq;

    if (off >= 4096) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    do {
        seq = seqlock_read_begin(&lm->seq);
        *c = lm->s;
    } while (seqlock_read_retry(&lm->seq, seq));
    now = femu_ocp_lat_now(n);
    lm_rotate(c, now);

    log = g_malloc0(4096);
    /* bit 0 enabled, 1 mode 1, 2 measured latency, 3 telemetry format */
    log[0] = (c->enabled ? 0x1 : 0) | 0x2 | 0x4;
    steps = (now - c->epoch_ns) / LM_INTERVAL_NS;
    stw_le_p(&log[2], MIN(MAX(steps, 0), UINT16_MAX));
    stw_le_p(&log[4], c->timer_threshold);
    memcpy(&log[6], c->thr, 4);
    stw_le_p(&log[10], c->config);
    log[12] = c->min_window;
    lm_put_set(log, 0, &c->act);
    lm_put_set(log, 208, &c->st);
    stw_le_p(&log[448], c->debug_enable);
    stq_le_p(&log[452], LM_STAMP_INVALID);      /* no debug log yet */
    stw_le_p(&log[460], 0xca);
    stw_le_p(&log[494], 5);
    memcpy(&log[496], lm_guid, sizeof(lm_guid));

    len = MIN(4096 - off, len);
    return dma_read_prp(n, log + off, len, le64_to_cpu(cmd->dptr.prp1),
                        le64_to_cpu(cmd->dptr.prp2));
}

/*
 * Set Features C5h with a 4096-byte payload. Discard (byte 11 = 02h) drops
 * only the debug log. Otherwise every field is checked first, then the
 * configuration loads and both sets clear (LMLOG-6, LMLOG-14). A
 * completion before this set then counts nowhere.
 */
uint16_t femu_ocp_lat_set(FemuCtrl *n, NvmeCmd *cmd)
{
    FemuOcpLat *lm = &n->ocp_lat;
    FemuOcpLatState *s = &lm->s;
    g_autofree uint8_t *p = g_malloc0(4096);
    uint16_t status;

    status = dma_write_prp(n, p, 4096, le64_to_cpu(cmd->dptr.prp1),
                           le64_to_cpu(cmd->dptr.prp2));
    if (status) {
        return status;
    }
    if (p[11] == 0x02) {
        return NVME_SUCCESS;                    /* no debug log is held */
    }
    /* LMLOG-11: A < B < C < D; reserved bits and values are refused */
    if (!(p[2] < p[3] && p[3] < p[4] && p[4] < p[5]) || p[11] > 1 ||
        p[12] > 1 || (lduw_le_p(&p[6]) & 0xf000) ||
        (lduw_le_p(&p[9]) & 0xf000) || !buffer_is_zero(&p[13], 4083)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    lm_write_begin(lm);
    qatomic_set(&s->enabled, p[12] == 1);
    s->timer_threshold = lduw_le_p(&p[0]);
    for (int i = 0; i < 4; i++) {
        qatomic_set(&s->thr[i], p[2 + i]);
    }
    s->config = lduw_le_p(&p[6]);
    s->min_window = p[8];
    s->debug_enable = lduw_le_p(&p[9]);
    s->epoch_ns = femu_ocp_lat_now(n);
    s->cfg_t = s->epoch_ns;
    lm_clear_set(&s->act);
    lm_clear_set(&s->st);
    lm_write_end(lm);
    return NVME_SUCCESS;
}
