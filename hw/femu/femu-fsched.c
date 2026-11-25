/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Command lines of events_file: parse at realize, match on the FTL thread.
 *
 *   realize:   each '@' line --> femu_fs_parse() --> FemuFsLine
 *   FTL step:  SQE copy --> view --> femu_fs_view_ok() --> femu_fs_match()
 *              --> per line: count, draw, group --> outcome per line
 *
 * Nothing here reads guest memory or device state, so the same code runs
 * in the unit test (hw/femu/tests/unit/test-fsched.c) with no QEMU.
 */
#include "qemu/osdep.h"
#include "femu-fsched.h"

#define FS_MAX_TOKENS   16
#define FS_MAX_TEXT     512

/* bits of FemuFsLine.op that an action accepts */
#define FS_OPS(x)       (1u << FEMU_FS_OP_##x)
#define FS_OPS_ALL      (FS_OPS(ANY) | FS_OPS(READ) | FS_OPS(WRITE) | \
                         FS_OPS(FUA) | FS_OPS(FLUSH) | FS_OPS(WZERO))

/* options of an action, as bits */
enum {
    FS_OPT_AT = 1u << 0,
    FS_OPT_KEEP = 1u << 1,
    FS_OPT_GRAIN = 1u << 2,
    FS_OPT_SEED = 1u << 3,
    FS_OPT_MODE = 1u << 4,
    FS_OPT_REPORT = 1u << 5,
    FS_OPT_AER = 1u << 6,
    FS_OPT_KIND = 1u << 7,
    FS_OPT_LBA = 1u << 8,
    FS_OPT_MS = 1u << 9,
};

typedef struct FsAction {
    const char *name;
    uint8_t act;
    uint8_t grp;
    uint32_t ops;               /* FS_OPS() the action accepts */
    const char *ops_text;       /* the same, for the message */
    uint32_t opts;              /* FS_OPT_* it takes */
    uint32_t need;              /* FS_OPT_* it must have */
} FsAction;

static const FsAction fs_actions[] = {
    { "power-loss", FEMU_FS_ACT_POWER_LOSS, FEMU_FS_GRP_TERMINAL, FS_OPS_ALL,
      NULL, FS_OPT_AT | FS_OPT_KEEP | FS_OPT_GRAIN | FS_OPT_SEED, 0 },
    { "cfs", FEMU_FS_ACT_CFS, FEMU_FS_GRP_TERMINAL, FS_OPS_ALL, NULL,
      FS_OPT_AT, 0 },
    { "hang", FEMU_FS_ACT_HANG, FEMU_FS_GRP_TERMINAL, FS_OPS_ALL, NULL, 0, 0 },
    { "write-fail", FEMU_FS_ACT_WRITE_FAIL, FEMU_FS_GRP_DATA,
      FS_OPS(WRITE) | FS_OPS(FUA) | FS_OPS(WZERO), "@write, @fua or @wzero",
      0, 0 },
    { "wb-fail", FEMU_FS_ACT_WB_FAIL, FEMU_FS_GRP_DATA, FS_OPS(WRITE),
      "@write", FS_OPT_MODE | FS_OPT_REPORT | FS_OPT_AER, 0 },
    { "fua-lie", FEMU_FS_ACT_FUA_LIE, FEMU_FS_GRP_DATA, FS_OPS(FUA), "@fua",
      0, 0 },
    { "read-unc", FEMU_FS_ACT_READ_UNC, FEMU_FS_GRP_DATA, FS_OPS(READ),
      "@read", 0, 0 },
    { "flush-lie", FEMU_FS_ACT_FLUSH_LIE, FEMU_FS_GRP_DATA, FS_OPS(FLUSH),
      "@flush", 0, 0 },
    { "sdc", FEMU_FS_ACT_SDC, FEMU_FS_GRP_SDC, FS_OPS(WRITE), "@write",
      FS_OPT_KIND | FS_OPT_LBA, FS_OPT_KIND },
    { "delay", FEMU_FS_ACT_DELAY, FEMU_FS_GRP_TIMING, FS_OPS_ALL, NULL,
      FS_OPT_MS, FS_OPT_MS },
};

static const char *const fs_op_names[] = {
    [FEMU_FS_OP_ANY] = "any",
    [FEMU_FS_OP_READ] = "read",
    [FEMU_FS_OP_WRITE] = "write",
    [FEMU_FS_OP_FUA] = "fua",
    [FEMU_FS_OP_FLUSH] = "flush",
    [FEMU_FS_OP_WZERO] = "wzero",
};

static const char *const fs_opt_names[] = {
    "at", "keep", "grain", "seed", "mode", "report", "aer", "kind", "lba",
    "ms",
};

uint64_t femu_fs_splitmix64(uint64_t *x)
{
    uint64_t z = (*x += 0x9e3779b97f4a7c15ULL);

    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

const char *femu_fs_act_name(uint8_t act)
{
    if (act == FEMU_FS_ACT_ANA) {
        return "ana";
    }
    if (act == FEMU_FS_ACT_SLOW) {
        return "slow";
    }
    for (size_t i = 0; i < ARRAY_SIZE(fs_actions); i++) {
        if (fs_actions[i].act == act) {
            return fs_actions[i].name;
        }
    }
    return "?";
}

uint32_t femu_fs_draw(uint64_t *rng)
{
    return femu_fs_splitmix64(rng) % FEMU_FS_PPM_ONE;
}

/* the main loop reads the counters while the FTL thread moves them */
static inline void fs_set(uint64_t *p, uint64_t v)
{
    __atomic_store_n(p, v, __ATOMIC_RELAXED);
}

static inline bool fs_done(const FemuFsLine *l)
{
    return __atomic_load_n(&l->done, __ATOMIC_RELAXED);
}

/*
 * A decimal number of at most @max, and the text after it. It never
 * wraps: a value past @max, however long, is refused.
 */
static bool fs_num(const char *s, const char **end, uint64_t max,
                   uint64_t *v)
{
    uint64_t x = 0;

    if (*s < '0' || *s > '9') {
        return false;
    }
    for (; *s >= '0' && *s <= '9'; s++) {
        unsigned d = *s - '0';

        if (d > max || x > (max - d) / 10) {
            return false;
        }
        x = x * 10 + d;
    }
    *end = s;
    *v = x;
    return true;
}

/* a whole token that is a number of at most @max */
static bool fs_num_all(const char *s, uint64_t max, uint64_t *v)
{
    const char *e;

    return fs_num(s, &e, max, v) && !*e;
}

static bool fs_fail(char *err, size_t errlen, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static bool fs_fail(char *err, size_t errlen, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
    return false;
}

/* the largest namespace, for an lba= with no ns= */
static uint64_t fs_nsze(const FemuFsDev *dev, const FemuFsLine *l)
{
    uint64_t max = 0;

    if (l->has_ns) {
        return dev->nsze[l->nsid - 1];
    }
    for (uint32_t i = 0; i < dev->nr_ns; i++) {
        if (dev->nsze[i] > max) {
            max = dev->nsze[i];
        }
    }
    return max;
}

/* "@op[,key=value]...(#N | %PPM~SEED)" */
static bool fs_trigger(const FemuFsDev *dev, char *t, FemuFsLine *l,
                       char *err, size_t errlen)
{
    const char *p;
    char *name = t + 1;
    size_t n = strcspn(name, ",#%");
    uint64_t v;
    uint64_t w;
    int op = -1;

    for (size_t i = 0; i < ARRAY_SIZE(fs_op_names); i++) {
        if (strlen(fs_op_names[i]) == n && !strncmp(name, fs_op_names[i], n)) {
            op = i;
        }
    }
    if (op < 0) {
        if ((n == 3 && !strncmp(name, "dsm", 3)) ||
            (n == 4 && !strncmp(name, "copy", 4))) {
            return fs_fail(err, errlen, "@%.*s: Dataset Management and Copy "
                           "are not matchable", (int)n, name);
        }
        return fs_fail(err, errlen, "unknown op '@%.*s'; ops are any, read, "
                       "write, fua, flush and wzero", (int)n, name);
    }
    l->op = op;
    p = name + n;
    while (*p == ',') {
        p++;
        if (!strncmp(p, "ns=", 3)) {
            if (l->has_ns) {
                return fs_fail(err, errlen, "ns= given twice");
            }
            if (!fs_num(p + 3, &p, UINT32_MAX, &v) || !v ||
                v > dev->nr_ns || !dev->nsze[v - 1]) {
                return fs_fail(err, errlen, "ns= names no namespace");
            }
            l->has_ns = true;
            l->nsid = v;
        } else if (!strncmp(p, "lba=", 4)) {
            if (l->has_lba) {
                return fs_fail(err, errlen, "lba= given twice");
            }
            if (!fs_num(p + 4, &p, UINT64_MAX, &v) || *p != '-' ||
                !fs_num(p + 1, &p, UINT64_MAX, &w) || v > w) {
                return fs_fail(err, errlen, "lba= takes <first>-<last>, "
                               "first <= last");
            }
            l->has_lba = true;
            l->lba_lo = v;
            l->lba_hi = w;
        } else {
            return fs_fail(err, errlen, "unknown match key at '%.*s'; keys "
                           "are ns= and lba=", (int)strcspn(p, ",#%"), p);
        }
    }
    if (l->has_lba && l->op == FEMU_FS_OP_FLUSH) {
        return fs_fail(err, errlen, "@flush has no LBA range");
    }
    if (l->has_lba && l->lba_hi >= fs_nsze(dev, l)) {
        return fs_fail(err, errlen, "lba= %" PRIu64 "-%" PRIu64 " is past the "
                       "namespace", l->lba_lo, l->lba_hi);
    }
    if (*p == '#') {
        if (!fs_num_all(p + 1, UINT64_MAX, &v) || !v) {
            return fs_fail(err, errlen, "#N takes N from 1 to %" PRIu64,
                           UINT64_MAX);
        }
        l->nth = v;
        return true;
    }
    if (*p == '%') {
        if (!fs_num(p + 1, &p, FEMU_FS_PPM_ONE, &v) || *p != '~' ||
            !fs_num_all(p + 1, FEMU_FS_SEED_MAX, &w)) {
            return fs_fail(err, errlen, "%%PPM~SEED takes PPM 0 to %u and "
                           "SEED 0 to %" PRIu64, FEMU_FS_PPM_ONE,
                           FEMU_FS_SEED_MAX);
        }
        l->ppm_trigger = true;
        l->ppm = v;
        l->seed = w;
        l->rng = w;
        return true;
    }
    return fs_fail(err, errlen, "a command trigger ends in #N or %%PPM~SEED");
}

/* one "key=value" option of action @a */
static bool fs_option(const FemuFsDev *dev, const FsAction *a, char *o,
                      uint32_t *seen, FemuFsLine *l, char *err,
                      size_t errlen)
{
    char *val = strchr(o, '=');
    uint64_t v;
    int k = -1;

    if (val) {
        *val++ = '\0';
        for (size_t i = 0; i < ARRAY_SIZE(fs_opt_names); i++) {
            if (!strcmp(o, fs_opt_names[i])) {
                k = i;
            }
        }
    }
    if (k < 0 || !(a->opts & (1u << k))) {
        return fs_fail(err, errlen, "%s takes no option '%s'", a->name, o);
    }
    if (*seen & (1u << k)) {
        return fs_fail(err, errlen, "%s= given twice", o);
    }
    *seen |= 1u << k;
    switch (1u << k) {
    case FS_OPT_AT:
        /* the dispatch boundary is the only cut point with a model */
        if (strcmp(val, "pre")) {
            return fs_fail(err, errlen, "at= takes pre");
        }
        return true;
    case FS_OPT_KEEP:
        if (!fs_num_all(val, FEMU_FS_PPM_ONE, &v)) {
            return fs_fail(err, errlen, "keep= takes 0 to %u", FEMU_FS_PPM_ONE);
        }
        l->has_keep = true;
        l->keep = v;
        return true;
    case FS_OPT_GRAIN:
        if (!strcmp(val, "page")) {
            l->grain = FEMU_FS_GRAIN_PAGE;
        } else if (!strcmp(val, "lba")) {
            l->grain = FEMU_FS_GRAIN_LBA;
        } else {
            return fs_fail(err, errlen, "grain= takes page or lba");
        }
        return true;
    case FS_OPT_SEED:
        if (!fs_num_all(val, FEMU_FS_SEED_MAX, &v)) {
            return fs_fail(err, errlen, "seed= takes 0 to %" PRIu64,
                           FEMU_FS_SEED_MAX);
        }
        l->keep_seed = v;
        return true;
    case FS_OPT_MODE:
        if (!strcmp(val, "unc")) {
            l->wb_mode = FEMU_FS_WB_UNC;
        } else if (!strcmp(val, "old")) {
            l->wb_mode = FEMU_FS_WB_OLD;
        } else {
            return fs_fail(err, errlen, "mode= takes unc or old");
        }
        return true;
    case FS_OPT_REPORT:
        if (!strcmp(val, "sticky")) {
            l->wb_report = FEMU_FS_REPORT_STICKY;
        } else if (!strcmp(val, "once")) {
            l->wb_report = FEMU_FS_REPORT_ONCE;
        } else {
            return fs_fail(err, errlen, "report= takes sticky or once");
        }
        return true;
    case FS_OPT_AER:
        if (!strcmp(val, "off") || !strcmp(val, "on")) {
            l->wb_aer = !strcmp(val, "on");
            return true;
        }
        return fs_fail(err, errlen, "aer= takes off or on");
    case FS_OPT_KIND:
        if (!strcmp(val, "flip")) {
            l->sdc_kind = FEMU_FS_SDC_FLIP;
        } else if (!strcmp(val, "lost")) {
            l->sdc_kind = FEMU_FS_SDC_LOST;
        } else if (!strcmp(val, "misdirect")) {
            l->sdc_kind = FEMU_FS_SDC_MISDIRECT;
        } else {
            return fs_fail(err, errlen, "kind= takes flip, lost or misdirect");
        }
        return true;
    case FS_OPT_LBA:
        if (!fs_num_all(val, UINT64_MAX, &v) || v >= fs_nsze(dev, l)) {
            return fs_fail(err, errlen, "lba= of sdc names no block of the "
                           "namespace");
        }
        l->has_sdc_lba = true;
        l->sdc_lba = v;
        return true;
    case FS_OPT_MS:
        if (!fs_num_all(val, FEMU_FS_DELAY_MAX, &v) || !v) {
            return fs_fail(err, errlen, "ms= takes 1 to %u", FEMU_FS_DELAY_MAX);
        }
        l->delay_ms = v;
        return true;
    }
    return fs_fail(err, errlen, "%s takes no option '%s'", a->name, o);
}

/* what the device must have, or must not have, for action @a */
static bool fs_needs(const FemuFsDev *dev, const FsAction *a,
                     const FemuFsLine *l, char *err, size_t errlen)
{
    bool pl = a->act == FEMU_FS_ACT_POWER_LOSS || a->act == FEMU_FS_ACT_CFS ||
              a->act == FEMU_FS_ACT_WB_FAIL || a->act == FEMU_FS_ACT_FUA_LIE ||
              a->act == FEMU_FS_ACT_FLUSH_LIE;
    bool cache = a->act == FEMU_FS_ACT_WB_FAIL ||
                 a->act == FEMU_FS_ACT_FLUSH_LIE;

    if (pl && !dev->power_loss) {
        return fs_fail(err, errlen, "action %s needs power_loss=on", a->name);
    }
    if (cache && !dev->vwc) {
        return fs_fail(err, errlen, "action %s needs vwc=1", a->name);
    }
    /* no restore model for the generations durable_at_done keeps */
    if (a->act != FEMU_FS_ACT_CFS && pl && dev->durable_at_done) {
        return fs_fail(err, errlen, "action %s is not supported with "
                       "durable_at_done", a->name);
    }
    if (a->act == FEMU_FS_ACT_WB_FAIL && (dev->buffer_low || dev->fdp)) {
        return fs_fail(err, errlen, "action wb-fail is not supported with %s",
                       dev->buffer_low ? "buffer_low_pcent" : "FDP");
    }
    /*
     * The FDP destage skips a blocked page and programs later ones, so
     * a page the draw rolled back could still become durable.
     */
    if (l->keep && dev->fdp) {
        return fs_fail(err, errlen, "keep= is not supported with FDP");
    }
    /* a short atomic write in one page buffers, so a block tear breaks it */
    if (l->grain == FEMU_FS_GRAIN_LBA && dev->awupf_lbas > 1) {
        return fs_fail(err, errlen, "grain=lba needs awupf_lbas of 0 or 1");
    }
    if (a->act == FEMU_FS_ACT_SDC && !dev->sdc) {
        return fs_fail(err, errlen, "action sdc needs sdc=on");
    }
    return true;
}

/* the modes and layouts whose commands the FTL step model covers */
static bool fs_device(const FemuFsDev *dev, char *err, size_t errlen)
{
    const char *why = !dev->bbssd ? "a mode other than bbssd" :
                      dev->ns_mgmt ? "ns_mgmt" :
                      dev->namespace_modes ? "namespace_modes" :
                      dev->subsys ? "subsys" :
                      dev->shared_ftl ? "shared_ftl" :
                      dev->cxl_ssd ? "cxl_ssd" : NULL;

    if (why) {
        return fs_fail(err, errlen, "command lines are not supported with %s",
                       why);
    }
    return true;
}

bool femu_fs_parse(const FemuFsDev *dev, const char *s, int lineno,
                   FemuFsLine *l, char *err, size_t errlen)
{
    char text[FS_MAX_TEXT];
    char *tok[FS_MAX_TOKENS];
    const FsAction *a = NULL;
    uint32_t seen = 0;
    int nt = 0;
    char *p;

    memset(l, 0, sizeof(*l));
    l->line = lineno;
    if (!fs_device(dev, err, errlen)) {
        return false;
    }
    if (strlen(s) >= sizeof(text)) {
        return fs_fail(err, errlen, "the line is too long");
    }
    strcpy(text, s);
    for (p = text; *p;) {
        p += strspn(p, " \t");
        if (!*p) {
            break;
        }
        if (nt == FS_MAX_TOKENS) {
            return fs_fail(err, errlen, "more than %d options",
                           FS_MAX_TOKENS - 2);
        }
        tok[nt++] = p;
        p += strcspn(p, " \t");
        if (*p) {
            *p++ = '\0';
        }
    }
    if (nt < 2 || tok[0][0] != '@') {
        return fs_fail(err, errlen, "a command line is '@<match>#N <action>' "
                       "or '@<match>%%PPM~SEED <action>'");
    }
    if (!fs_trigger(dev, tok[0], l, err, errlen)) {
        return false;
    }
    if (!strncmp(tok[1], "ana=", 4) || !strncmp(tok[1], "slow=", 5)) {
        if (strlen(tok[1]) >= sizeof(l->action)) {
            return fs_fail(err, errlen, "unknown action '%s'", tok[1]);
        }
        if (nt > 2) {
            return fs_fail(err, errlen, "%s takes no option '%s'", tok[1],
                           tok[2]);
        }
        l->act = tok[1][0] == 'a' ? FEMU_FS_ACT_ANA : FEMU_FS_ACT_SLOW;
        l->grp = FEMU_FS_GRP_NONE;
        strcpy(l->action, tok[1]);
        return true;
    }
    for (size_t i = 0; i < ARRAY_SIZE(fs_actions); i++) {
        if (!strcmp(tok[1], fs_actions[i].name)) {
            a = &fs_actions[i];
        }
    }
    if (!a) {
        return fs_fail(err, errlen, "unknown action '%s'", tok[1]);
    }
    l->act = a->act;
    l->grp = a->grp;
    if (!(a->ops & (1u << l->op))) {
        return fs_fail(err, errlen, "action %s takes %s only", a->name,
                       a->ops_text);
    }
    for (int i = 2; i < nt; i++) {
        if (!fs_option(dev, a, tok[i], &seen, l, err, errlen)) {
            return false;
        }
    }
    if ((seen & a->need) != a->need) {
        return fs_fail(err, errlen, "action %s needs %s=", a->name,
                       a->need & FS_OPT_MS ? "ms" : "kind");
    }
    if (!fs_needs(dev, a, l, err, errlen)) {
        return false;
    }
    /* keep= draws from their own stream, which each cut moves on */
    l->keep_rng = l->keep_seed;
    return true;
}

uint32_t femu_fs_xfer_ms(uint16_t ms, bool extended, uint8_t pi_type,
                         uint16_t pi_size, bool pract)
{
    if (!ms || !extended || (pi_type && ms == pi_size && pract)) {
        return 0;
    }
    return ms;
}

bool femu_fs_view_ok(const FemuFsView *v, uint64_t nsze, unsigned lbads,
                     uint32_t xfer_ms, unsigned mdts_shift)
{
    switch (v->opc) {
    case FEMU_FS_OPC_FLUSH:
        return true;
    case FEMU_FS_OPC_READ:
    case FEMU_FS_OPC_WRITE:
    case FEMU_FS_OPC_WZERO:
        break;
    default:
        return false;
    }
    if (!v->nlb || v->slba >= nsze || v->nlb > nsze - v->slba) {
        return false;
    }
    /* Write Zeroes moves no data, so MDTS does not limit it */
    if (v->opc != FEMU_FS_OPC_WZERO && mdts_shift && mdts_shift < 64 &&
        ((uint64_t)v->nlb << lbads) + (uint64_t)v->nlb * xfer_ms >
        (UINT64_C(1) << mdts_shift)) {
        return false;
    }
    return true;
}

static bool fs_line_matches(const FemuFsLine *l, const FemuFsView *v)
{
    static const uint8_t opc[] = {
        [FEMU_FS_OP_READ] = FEMU_FS_OPC_READ,
        [FEMU_FS_OP_WRITE] = FEMU_FS_OPC_WRITE,
        [FEMU_FS_OP_FUA] = FEMU_FS_OPC_WRITE,
        [FEMU_FS_OP_FLUSH] = FEMU_FS_OPC_FLUSH,
        [FEMU_FS_OP_WZERO] = FEMU_FS_OPC_WZERO,
    };

    if (l->op != FEMU_FS_OP_ANY && v->opc != opc[l->op]) {
        return false;
    }
    if (l->op == FEMU_FS_OP_FUA && !v->fua) {
        return false;
    }
    if (l->has_ns && v->nsid != l->nsid) {
        return false;
    }
    /* overlap: any block of the command in [lba_lo, lba_hi] */
    if (l->has_lba && (v->opc == FEMU_FS_OPC_FLUSH ||
                       v->slba > l->lba_hi ||
                       v->slba + v->nlb - 1 < l->lba_lo)) {
        return false;
    }
    return true;
}

/*
 * Whether the original command allows a winning action. A FUA Write
 * never enters the write buffer, so a write-back failure has no page.
 */
static bool fs_allowed(const FemuFsLine *l, const FemuFsView *v)
{
    return !(l->act == FEMU_FS_ACT_WB_FAIL && v->fua);
}

void femu_fs_match(FemuFsLine *l, int nr, const FemuFsView *v,
                   uint8_t *out, uint8_t *why, FemuFsView *eff)
{
    int win[FEMU_FS_GRP_NR];
    bool pre = false;
    bool hang = false;
    int t;

    for (int g = 0; g < FEMU_FS_GRP_NR; g++) {
        win[g] = -1;
    }
    for (int i = 0; i < nr; i++) {
        FemuFsLine *x = &l[i];
        uint64_t m;
        bool sel;

        out[i] = FEMU_FS_OUT_NONE;
        if (why) {
            why[i] = FEMU_FS_WHY_NONE;
        }
        if (!fs_line_matches(x, v)) {
            continue;
        }
        m = x->matched + 1;
        fs_set(&x->matched, m);
        if (x->ppm_trigger) {
            sel = femu_fs_draw(&x->rng) < x->ppm;
        } else {
            sel = !x->done && m == x->nth;
            if (sel) {
                __atomic_store_n(&x->done, true, __ATOMIC_RELAXED);
            }
        }
        if (!sel) {
            continue;
        }
        fs_set(&x->selected, x->selected + 1);
        if (x->grp != FEMU_FS_GRP_NONE) {
            if (win[x->grp] >= 0) {
                out[i] = FEMU_FS_OUT_SUPERSEDED;
                continue;
            }
            win[x->grp] = i;
        }
        if (fs_allowed(x, v)) {
            out[i] = FEMU_FS_OUT_APPLIED;
        } else {
            out[i] = FEMU_FS_OUT_NO_EFFECT;
            if (why) {
                why[i] = FEMU_FS_WHY_FUA;
            }
        }
    }

    t = win[FEMU_FS_GRP_TERMINAL];
    if (t >= 0 && out[t] == FEMU_FS_OUT_APPLIED) {
        pre = l[t].act != FEMU_FS_ACT_HANG;
        hang = l[t].act == FEMU_FS_ACT_HANG;
    }
    *eff = *v;
    for (int i = 0; i < nr; i++) {
        FemuFsLine *x = &l[i];

        /* a cut or cfs at pre: the command never runs */
        if (out[i] == FEMU_FS_OUT_APPLIED && i != t &&
            (pre || (hang && x->grp == FEMU_FS_GRP_TIMING))) {
            out[i] = FEMU_FS_OUT_NO_EFFECT;
            if (why) {
                why[i] = pre ? FEMU_FS_WHY_PRE : FEMU_FS_WHY_HANG;
            }
        }
        switch (out[i]) {
        case FEMU_FS_OUT_APPLIED:
            fs_set(&x->applied, x->applied + 1);
            /* the lie takes the buffered path: the FTL sees no FUA */
            if (x->act == FEMU_FS_ACT_FUA_LIE) {
                eff->fua = false;
            }
            break;
        case FEMU_FS_OUT_SUPERSEDED:
            fs_set(&x->superseded, x->superseded + 1);
            break;
        case FEMU_FS_OUT_NO_EFFECT:
            fs_set(&x->no_effect, x->no_effect + 1);
            break;
        }
    }
}

uint8_t femu_fs_terminal(const FemuFsLine *l, int nr, const uint8_t *out)
{
    for (int i = 0; i < nr; i++) {
        if (l[i].grp == FEMU_FS_GRP_TERMINAL &&
            out[i] == FEMU_FS_OUT_APPLIED) {
            return l[i].act;
        }
    }
    return FEMU_FS_ACT_NR;
}

uint8_t femu_fs_lie_why(const FemuFsLie *s)
{
    if (s->failed) {
        return FEMU_FS_WHY_CMD_FAILED;
    }
    /* the cut writes a protected buffer back, so nothing is exposed */
    if (s->plp) {
        return FEMU_FS_WHY_PLP;
    }
    if (!s->buffer) {
        return FEMU_FS_WHY_NO_BUFFER;
    }
    if (s->act == FEMU_FS_ACT_FUA_LIE && s->atomic) {
        return FEMU_FS_WHY_ATOMIC;
    }
    /*
     * No page is left volatile: the buffer of a Flush is empty, or a
     * stream write or a write-back in the command programmed the write.
     */
    if (!s->pages) {
        return FEMU_FS_WHY_DURABLE;
    }
    return FEMU_FS_WHY_NONE;
}

bool femu_fs_done(const FemuFsLine *l, int nr)
{
    for (int i = 0; i < nr; i++) {
        if (l[i].ppm_trigger || !fs_done(&l[i])) {
            return false;
        }
    }
    return true;
}

uint32_t femu_fs_cut_draw(FemuFsCut *c, uint8_t *keep, uint32_t lbas)
{
    uint32_t kept = 0;

    /* a time line or QMP cut keeps nothing and draws nothing */
    if (!c->rng) {
        memset(keep, 0, lbas);
        return 0;
    }
    for (uint32_t i = 0; i < lbas; i++) {
        /* grain=page: the first draw decides each block */
        if (i && c->grain == FEMU_FS_GRAIN_PAGE) {
            keep[i] = keep[0];
        } else {
            keep[i] = femu_fs_draw(c->rng) < c->keep;
        }
        kept += keep[i];
    }
    return kept;
}

static int fs_range_cmp(const void *a, const void *b)
{
    const FemuFsRange *x = a;
    const FemuFsRange *y = b;

    if (x->nsid != y->nsid) {
        return x->nsid < y->nsid ? -1 : 1;
    }
    if (x->slba != y->slba) {
        return x->slba < y->slba ? -1 : 1;
    }
    return 0;
}

/*
 * Sort the stored ranges of @kind by namespace and block, and merge the
 * ones that touch or overlap. Pages leave the buffer interleaved, so a
 * merge with the previous range alone keeps neighbours apart and fills
 * the store with fragments of one extent.
 */
static void fs_cut_compact(FemuFsCut *c, uint8_t kind)
{
    FemuFsRange *r = c->r[kind];
    uint32_t nr = c->nr[kind];
    uint32_t out = 0;

    if (nr < 2) {
        return;
    }
    qsort(r, nr, sizeof(*r), fs_range_cmp);
    for (uint32_t i = 1; i < nr; i++) {
        FemuFsRange *p = &r[out];
        uint64_t end = p->slba + p->nlb;
        uint64_t rend = r[i].slba + r[i].nlb;

        if (r[i].nsid == p->nsid && r[i].slba <= end &&
            (rend <= end || rend - p->slba <= UINT32_MAX)) {
            if (rend > end) {
                p->nlb = rend - p->slba;
            }
            continue;
        }
        r[++out] = r[i];
    }
    c->nr[kind] = out + 1;
}

/* store the open range of @kind; a full store compacts before a drop */
static void fs_cut_close(FemuFsCut *c, uint8_t kind)
{
    if (!c->open[kind]) {
        return;
    }
    c->open[kind] = false;
    if (c->nr[kind] == FEMU_FS_CUT_MAX) {
        fs_cut_compact(c, kind);
    }
    if (c->nr[kind] < FEMU_FS_CUT_MAX) {
        c->r[kind][c->nr[kind]++] = c->cur[kind];
    } else {
        c->dropped++;
    }
}

/* add blocks @slba to @slba + @nlb - 1 to the ranges of @kind */
static void fs_cut_range(FemuFsCut *c, uint8_t kind, uint16_t nsid,
                         uint64_t slba, uint32_t nlb)
{
    FemuFsRange *cur = &c->cur[kind];

    if (c->open[kind] && cur->nsid == nsid && cur->slba + cur->nlb == slba &&
        cur->nlb <= UINT32_MAX - nlb) {
        cur->nlb += nlb;
        return;
    }
    fs_cut_close(c, kind);
    *cur = (FemuFsRange) {
        .slba = slba, .nlb = nlb, .nsid = nsid, .kind = kind,
    };
    c->open[kind] = true;
}

void femu_fs_cut_page(FemuFsCut *c, uint16_t nsid, uint64_t slba,
                      const uint8_t *keep, uint32_t lbas, bool lie)
{
    bool kept = false;
    bool rolled = false;
    uint32_t i = 0;

    while (i < lbas) {
        uint8_t k = keep && keep[i];
        uint32_t j = i + 1;

        while (j < lbas && (keep && keep[j]) == k) {
            j++;
        }
        fs_cut_range(c, k ? FEMU_FS_KIND_KEPT : FEMU_FS_KIND_ROLLED_BACK,
                     nsid, slba + i, j - i);
        kept |= k;
        rolled |= !k;
        i = j;
    }
    c->kept_pages += kept;
    c->rolled_back_pages += rolled;
    c->rolled_back_lie_pages += rolled && lie;
}

/* the chunks the stored ranges of @kind take */
static uint32_t fs_cut_kind_chunks(const FemuFsCut *c, uint8_t kind)
{
    return (c->nr[kind] + FEMU_FS_CUT_RANGES - 1) / FEMU_FS_CUT_RANGES;
}

uint32_t femu_fs_cut_end(FemuFsCut *c, bool *truncated)
{
    uint32_t want;

    for (uint8_t k = 0; k < FEMU_FS_KINDS; k++) {
        fs_cut_close(c, k);
        fs_cut_compact(c, k);
    }
    want = fs_cut_kind_chunks(c, FEMU_FS_KIND_ROLLED_BACK) +
           fs_cut_kind_chunks(c, FEMU_FS_KIND_KEPT);
    /* a dropped range might have merged: the count is an upper bound */
    c->ranges = c->nr[FEMU_FS_KIND_ROLLED_BACK] + c->nr[FEMU_FS_KIND_KEPT] +
                c->dropped;
    *truncated = want > FEMU_FS_CUT_CHUNKS || c->dropped || c->partial;
    return want < FEMU_FS_CUT_CHUNKS ? want : FEMU_FS_CUT_CHUNKS;
}

uint32_t femu_fs_cut_chunk(const FemuFsCut *c, uint32_t i, FemuFsRange *out)
{
    uint32_t rb = fs_cut_kind_chunks(c, FEMU_FS_KIND_ROLLED_BACK);
    uint8_t kind = i < rb ? FEMU_FS_KIND_ROLLED_BACK : FEMU_FS_KIND_KEPT;
    uint32_t first = (i < rb ? i : i - rb) * FEMU_FS_CUT_RANGES;
    uint32_t nr;

    if (first >= c->nr[kind]) {
        return 0;
    }
    nr = c->nr[kind] - first;
    if (nr > FEMU_FS_CUT_RANGES) {
        nr = FEMU_FS_CUT_RANGES;
    }
    memcpy(out, &c->r[kind][first], nr * sizeof(*out));
    return nr;
}

int femu_fs_run_start(FemuFsRun *r, int64_t now)
{
    if (!r->started) {
        r->started = true;
        r->epoch = now;
        return FEMU_FS_RUN_OK;
    }
    if (!r->stopped) {
        return FEMU_FS_RUN_RUNNING;
    }
    /* the stop takes no time from the schedule */
    r->epoch += now - r->stop_at;
    r->stopped = false;
    return FEMU_FS_RUN_OK;
}

int femu_fs_run_stop(FemuFsRun *r, int64_t now)
{
    if (!r->started) {
        return FEMU_FS_RUN_WAITING;
    }
    if (r->stopped) {
        return FEMU_FS_RUN_STOPPED;
    }
    r->stopped = true;
    r->stop_at = now;
    return FEMU_FS_RUN_OK;
}

int femu_wb_slot_get(FemuWbTab *t)
{
    for (int s = 0; s < FEMU_WB_SLOTS; s++) {
        if (!t->slot[s].refs) {
            memset(&t->slot[s], 0, sizeof(t->slot[s]));
            t->slot[s].refs = 1;
            return s;
        }
    }
    return -1;
}

void femu_wb_slot_put(FemuWbTab *t, int s)
{
    if (s < 0 || s >= FEMU_WB_SLOTS || !t->slot[s].refs) {
        return;
    }
    if (!--t->slot[s].refs) {
        memset(&t->slot[s], 0, sizeof(t->slot[s]));
    }
}

void femu_wb_fail_add(FemuWbTab *t, const FemuWbFail *f)
{
    FemuWbFail *x = &t->fail[t->nr++];

    *x = *f;
    x->state = FEMU_WB_PENDING;
    x->tok = 0;
}

static bool wb_in_scope(const FemuWbFail *f, uint32_t nsid)
{
    return !nsid || f->nsid == nsid;
}

bool femu_wb_pending(const FemuWbTab *t, uint32_t nsid)
{
    for (uint32_t i = 0; i < t->nr; i++) {
        if (t->fail[i].state == FEMU_WB_PENDING &&
            wb_in_scope(&t->fail[i], nsid)) {
            return true;
        }
    }
    return false;
}

uint16_t femu_wb_collect(FemuWbTab *t, uint32_t nsid, uint64_t tok,
                         bool admin, bool *held)
{
    bool any = false;
    bool dnr = false;

    *held = false;
    for (uint32_t i = 0; i < t->nr; i++) {
        FemuWbFail *f = &t->fail[i];

        if (f->state != FEMU_WB_PENDING || !wb_in_scope(f, nsid)) {
            continue;
        }
        any = true;
        f->tok = tok;
        if (f->report == FEMU_FS_REPORT_ONCE) {
            f->state = FEMU_WB_RESERVED;
            *held = true;
        } else {
            dnr = true;
        }
    }
    if (!any) {
        return 0;
    }
    return (admin ? FEMU_WB_SC_INTERNAL : FEMU_WB_SC_WF) |
           (dnr ? FEMU_WB_SC_DNR : 0);
}

/* remove failure @i; the last one moves into its place */
static void wb_fail_del(FemuWbTab *t, uint32_t i)
{
    femu_wb_slot_put(t, t->fail[i].slot);
    t->fail[i] = t->fail[--t->nr];
}

uint32_t femu_wb_publish(FemuWbTab *t, uint64_t tok)
{
    uint32_t done = 0;
    uint32_t i = 0;

    while (i < t->nr) {
        if (t->fail[i].state == FEMU_WB_RESERVED && t->fail[i].tok == tok) {
            wb_fail_del(t, i);
            done++;
        } else {
            i++;
        }
    }
    return done;
}

uint32_t femu_wb_unreserve(FemuWbTab *t, uint64_t tok)
{
    uint32_t back = 0;

    for (uint32_t i = 0; i < t->nr; i++) {
        if (t->fail[i].state == FEMU_WB_RESERVED && t->fail[i].tok == tok) {
            t->fail[i].state = FEMU_WB_PENDING;
            back++;
        }
    }
    return back;
}

void femu_wb_clear(FemuWbTab *t, bool slots)
{
    while (t->nr) {
        wb_fail_del(t, t->nr - 1);
    }
    if (slots) {
        memset(t->slot, 0, sizeof(t->slot));
    }
}

bool femu_wb_lba_lost(const uint8_t *now, const uint8_t *undo,
                      const uint8_t *st_now, const uint8_t *st_undo,
                      uint32_t i, uint32_t lba_bytes)
{
    return st_now[i] != st_undo[i] ||
           memcmp(now + (size_t)i * lba_bytes, undo + (size_t)i * lba_bytes,
                  lba_bytes) != 0;
}

uint8_t femu_wb_apply_why(bool slot, bool failed, bool buffer, bool atomic,
                          bool marked, uint32_t pages)
{
    if (!slot) {
        return FEMU_FS_WHY_SLOTS_FULL;
    }
    if (pages) {
        return FEMU_FS_WHY_NONE;
    }
    if (failed) {
        return FEMU_FS_WHY_CMD_FAILED;
    }
    if (!buffer) {
        return FEMU_FS_WHY_NO_BUFFER;
    }
    if (atomic) {
        return FEMU_FS_WHY_ATOMIC;
    }
    if (marked) {
        return FEMU_FS_WHY_MARKED;
    }
    /* a stream write programs directly */
    return FEMU_FS_WHY_DURABLE;
}
