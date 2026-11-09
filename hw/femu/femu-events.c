/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * events_file: a timed list of actions on the controller, for experiments.
 *
 *   realize: read and check the file, compile each time once (WAITING)
 *   first successful enable: epoch = femu_io_now(n), start the timer
 *   timer: run each event whose time has come, set it for the next one
 *   last event run, or one failed: DONE; resets keep epoch and cursor
 *
 * A line is "<ms> <action>" or "<ms>+<window>~<seed> <action>"; the second
 * draws its time once, from splitmix64 seeded with <seed>. Actions:
 *   ana=<group>:<state>   ANA state 1, 2 or 3, as the ana-state property
 *   power-loss            a power cut, as simulate-power-loss=true
 *   slow=<ch>:<lun>:<pct> the array time of a LUN, as the die-slow property
 * The timeline is host time: events run while the VM is stopped too.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-femu.h"
#include "qapi/visitor.h"
#include "qom/object.h"
#include "qemu/timer.h"
#include "nvme.h"
#include "femu-query.h"
#include "trace.h"

#define FEMU_EVENTS_MAX_LINES   1024    /* lines of the file, and events */
#define FEMU_EVENTS_MAX_LINE    256
#define FEMU_EVENTS_MAX_FILE    (64 * KiB)
/* times below 2^62 ns, so epoch plus a time stays signed */
#define FEMU_EVENTS_MAX_MS      (INT64_MAX / SCALE_MS / 2)

enum {
    FEMU_EVENT_ANA = 0,
    FEMU_EVENT_POWER_LOSS,
    FEMU_EVENT_SLOW,
};

typedef struct FemuEvent {
    int line;
    int kind;
    unsigned int grp;
    unsigned int state;
    unsigned int ch;            /* slow= */
    unsigned int lun;
    unsigned int pct;
    int64_t deadline_ns;        /* after the epoch */
    int64_t ran_ns;             /* after the epoch; -1 until it runs */
    FemuEventResult result;
    char *error;
    char *action;
} FemuEvent;

struct FemuEventSched {
    FemuEvent *ev;
    int nr;
    int cursor;
    bool started;
    bool test_clock;            /* qtest: x-events-now runs the events */
    int64_t epoch;
    QEMUTimer *timer;
};

static uint64_t femu_splitmix64(uint64_t *x)
{
    uint64_t z = (*x += 0x9e3779b97f4a7c15ULL);

    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

/* a decimal number of at most @max, and the text after it */
static bool femu_events_num(const char *s, const char **end, uint64_t max,
                            uint64_t *v)
{
    char *e;

    if (!g_ascii_isdigit(*s)) {
        return false;
    }
    errno = 0;
    *v = g_ascii_strtoull(s, &e, 10);
    if (errno || *v > max) {
        return false;
    }
    *end = e;
    return true;
}

static bool femu_events_action(FemuCtrl *n, const char *a, FemuEvent *ev,
                               Error **errp)
{
    if (!strcmp(a, "power-loss")) {
        if (!n->power_loss) {
            error_setg(errp, "action power-loss needs power_loss=on");
            return false;
        }
        ev->kind = FEMU_EVENT_POWER_LOSS;
        return true;
    }
    if (g_str_has_prefix(a, "ana=")) {
        const char *p = a + 4;
        uint64_t g;
        uint64_t st;

        if (!femu_events_num(p, &p, UINT32_MAX, &g) || *p != ':' ||
            !femu_events_num(p + 1, &p, UINT32_MAX, &st) || *p) {
            error_setg(errp, "ana takes <group>:<state>");
            return false;
        }
        ev->grp = g;
        ev->state = st;
        if (!n->ana) {
            error_setg(errp, "action ana needs ana=on");
            return false;
        }
        if (!ev->grp || ev->grp > n->namespace_limit ||
            !nvme_ns_allocated(n, ev->grp)) {
            error_setg(errp, "ana group %u is not a namespace", ev->grp);
            return false;
        }
        /* 4, Persistent Loss, cannot be left: no event may set it */
        if (ev->state < 1 || ev->state > 3) {
            error_setg(errp, "ana state must be 1, 2 or 3");
            return false;
        }
        ev->kind = FEMU_EVENT_ANA;
        return true;
    }
    if (g_str_has_prefix(a, "slow=")) {
        const char *p = a + 5;
        uint64_t v[3];

        for (int i = 0; i < 3; i++) {
            if (!femu_events_num(p, &p, UINT32_MAX, &v[i]) ||
                *p != (i < 2 ? ':' : '\0')) {
                error_setg(errp, "slow takes <ch>:<lun>:<pct>");
                return false;
            }
            p++;
        }
        if (!n->die_slow_pct) {
            error_setg(errp, "action slow needs die_slow=on");
            return false;
        }
        if (v[0] >= (uint64_t)n->bb_params.nchs ||
            v[1] >= (uint64_t)n->bb_params.luns_per_ch ||
            v[2] < 100 || v[2] > 10000) {
            error_setg(errp, "slow needs a channel below %d, a LUN below %d "
                       "and a percent 100 to 10000", n->bb_params.nchs,
                       n->bb_params.luns_per_ch);
            return false;
        }
        ev->ch = v[0];
        ev->lun = v[1];
        ev->pct = v[2];
        ev->kind = FEMU_EVENT_SLOW;
        return true;
    }
    error_setg(errp, "unknown action '%s'", a);
    return false;
}

static bool femu_events_line(FemuCtrl *n, char *s, int line, FemuEvent *ev,
                             Error **errp)
{
    const char *p = s;
    uint64_t ms;
    uint64_t win = 0;
    uint64_t seed = 0;
    g_auto(GStrv) tok = NULL;

    if (!femu_events_num(p, &p, FEMU_EVENTS_MAX_MS, &ms)) {
        error_setg(errp, "a time in ms");
        return false;
    }
    if (*p == '+') {
        if (!femu_events_num(p + 1, &p, FEMU_EVENTS_MAX_MS, &win) ||
            !win || *p != '~' ||
            !femu_events_num(p + 1, &p, INT64_MAX, &seed)) {
            error_setg(errp, "a window is <ms>+<window>~<seed>, window > 0");
            return false;
        }
        if (ms + win > FEMU_EVENTS_MAX_MS) {
            error_setg(errp, "the time and window are too large");
            return false;
        }
        ms += femu_splitmix64(&seed) % win;
    }
    if (*p != ' ' && *p != '\t') {
        error_setg(errp, "a space after the time");
        return false;
    }
    tok = g_strsplit_set(g_strstrip((char *)p), " \t", -1);
    if (g_strv_length(tok) != 1 || !*tok[0]) {
        error_setg(errp, "one action after the time");
        return false;
    }
    if (!femu_events_action(n, tok[0], ev, errp)) {
        return false;
    }
    ev->line = line;
    ev->deadline_ns = (int64_t)ms * SCALE_MS;
    ev->ran_ns = -1;
    ev->result = FEMU_EVENT_RESULT_PENDING;
    ev->action = g_strdup(tok[0]);
    return true;
}

/* events of equal time keep their file order */
static int femu_events_cmp(const void *a, const void *b)
{
    const FemuEvent *x = a;
    const FemuEvent *y = b;

    if (x->deadline_ns != y->deadline_ns) {
        return x->deadline_ns < y->deadline_ns ? -1 : 1;
    }
    return x->line - y->line;
}

/**
 * femu_events_init - read and compile events_file at realize
 * @n: the controller, its namespaces allocated
 * @errp: the error, with the line, of a file that is refused
 *
 * Returns true with no file, or with a schedule waiting for the first
 * enable. Refused with csd_pause, whose frozen clock the timer does not
 * follow.
 */
bool femu_events_init(FemuCtrl *n, Error **errp)
{
    g_autofree char *text = NULL;
    g_auto(GStrv) lines = NULL;
    struct FemuEventSched *s;
    size_t len;
    FILE *f;

    if (!n->events_file) {
        return true;
    }
    if (n->csd_params.pause) {
        error_setg(errp, "events_file does not work with csd_pause");
        return false;
    }
    f = fopen(n->events_file, "r");
    if (!f) {
        error_setg_errno(errp, errno, "events_file %s", n->events_file);
        return false;
    }
    /* read at most one byte past the limit, so a large file costs nothing */
    text = g_malloc(FEMU_EVENTS_MAX_FILE + 2);
    len = fread(text, 1, FEMU_EVENTS_MAX_FILE + 1, f);
    fclose(f);
    text[len] = '\0';
    if (len > FEMU_EVENTS_MAX_FILE || memchr(text, '\0', len)) {
        error_setg(errp, "events_file: a text file of at most %d KiB",
                   (int)(FEMU_EVENTS_MAX_FILE / KiB));
        return false;
    }
    lines = g_strsplit(text, "\n", -1);
    if (g_strv_length(lines) > FEMU_EVENTS_MAX_LINES + 1) {
        error_setg(errp, "events_file: more than %d lines",
                   FEMU_EVENTS_MAX_LINES);
        return false;
    }
    s = g_new0(struct FemuEventSched, 1);
    s->ev = g_new0(FemuEvent, FEMU_EVENTS_MAX_LINES);
    for (int i = 0; lines[i]; i++) {
        char *l = lines[i];
        Error *err = NULL;

        if (strlen(l) > FEMU_EVENTS_MAX_LINE) {
            error_setg(errp, "events_file line %d: longer than %d bytes",
                       i + 1, FEMU_EVENTS_MAX_LINE);
            goto fail;
        }
        g_strstrip(l);
        if (!*l || *l == '#') {
            continue;
        }
        if (s->nr == FEMU_EVENTS_MAX_LINES) {
            error_setg(errp, "events_file: more than %d events",
                       FEMU_EVENTS_MAX_LINES);
            goto fail;
        }
        if (!femu_events_line(n, l, i + 1, &s->ev[s->nr], &err)) {
            error_setg(errp, "events_file line %d: %s", i + 1,
                       error_get_pretty(err));
            error_free(err);
            goto fail;
        }
        s->nr++;
    }
    qsort(s->ev, s->nr, sizeof(*s->ev), femu_events_cmp);
    n->events = s;
    return true;

fail:
    for (int i = 0; i < s->nr; i++) {
        g_free(s->ev[i].action);
    }
    g_free(s->ev);
    g_free(s);
    return false;
}

static void femu_events_one(FemuCtrl *n, FemuEvent *ev, int64_t now)
{
    Object *obj = OBJECT(n);
    Error *err = NULL;

    switch (ev->kind) {
    case FEMU_EVENT_ANA: {
        g_autofree char *v = g_strdup_printf("%u:%u", ev->grp, ev->state);

        object_property_set_str(obj, "ana-state", v, &err);
        break;
    }
    case FEMU_EVENT_SLOW: {
        g_autofree char *v = g_strdup_printf("%u:%u:%u", ev->ch, ev->lun,
                                             ev->pct);

        object_property_set_str(obj, "die-slow", v, &err);
        break;
    }
    case FEMU_EVENT_POWER_LOSS:
        object_property_set_bool(obj, "simulate-power-loss", true, &err);
        break;
    default:
        g_assert_not_reached();
    }
    ev->ran_ns = now;
    if (err) {
        ev->result = FEMU_EVENT_RESULT_FAILED;
        ev->error = g_strdup(error_get_pretty(err));
        error_free(err);
    } else {
        ev->result = FEMU_EVENT_RESULT_DONE;
    }
    trace_femu_event(ev->line, ev->action, ev->deadline_ns, now,
                     ev->result == FEMU_EVENT_RESULT_DONE);
}

/*
 * Run every event due by @now, after the epoch; a failure stops them all.
 * With @real the time is read again before each action, since one action
 * (a power cut) can take long: each event records when it really ran.
 */
static void femu_events_run(FemuCtrl *n, int64_t now, bool real)
{
    struct FemuEventSched *s = n->events;

    while (s->cursor < s->nr && s->ev[s->cursor].deadline_ns <= now) {
        FemuEvent *ev = &s->ev[s->cursor++];

        femu_events_one(n, ev, now);
        if (real) {
            now = femu_io_now(n) - s->epoch;
        }
        if (ev->result == FEMU_EVENT_RESULT_FAILED) {
            s->cursor = s->nr;
            return;
        }
    }
}

/* set the timer for the next event, or stop it when none is left */
static void femu_events_set_timer(FemuCtrl *n)
{
    struct FemuEventSched *s = n->events;

    if (s->test_clock || s->cursor >= s->nr) {
        timer_del(s->timer);
        return;
    }
    timer_mod(s->timer, s->epoch + s->ev[s->cursor].deadline_ns);
}

static void femu_events_fire(void *opaque)
{
    FemuCtrl *n = opaque;
    struct FemuEventSched *s = n->events;

    if (!s || s->test_clock) {
        return;
    }
    femu_events_run(n, femu_io_now(n) - s->epoch, true);
    femu_events_set_timer(n);
}

/* the controller became ready: the first time starts the schedule */
void femu_events_start(FemuCtrl *n)
{
    struct FemuEventSched *s = n->events;

    if (!s || s->started) {
        return;
    }
    s->started = true;
    s->epoch = femu_io_now(n);
    s->timer = timer_new_ns(QEMU_CLOCK_REALTIME, femu_events_fire, n);
    /* the last time must still fit after the epoch */
    if (s->nr && s->ev[s->nr - 1].deadline_ns > INT64_MAX - s->epoch) {
        for (int i = 0; i < s->nr; i++) {
            s->ev[i].result = FEMU_EVENT_RESULT_FAILED;
            s->ev[i].error = g_strdup("its time does not fit after the "
                                      "first enable");
        }
        s->cursor = s->nr;
        return;
    }
    femu_events_set_timer(n);
}

/* realize undo and unplug: the timer goes before anything it reaches */
void femu_events_exit(FemuCtrl *n)
{
    struct FemuEventSched *s = n->events;

    if (!s) {
        return;
    }
    if (s->timer) {
        timer_free(s->timer);
    }
    for (int i = 0; i < s->nr; i++) {
        g_free(s->ev[i].action);
        g_free(s->ev[i].error);
    }
    g_free(s->ev);
    g_free(s);
    n->events = NULL;
}

/*
 * x-events-now (qtest): from now on the real timer never runs events.
 * Once started, run the events due by @value ms after the epoch, with
 * that as the time. Set before the first enable, it only stops the timer,
 * so no event runs on host time before the test steps it.
 */
static void femu_events_test_now(Object *obj, Visitor *v, const char *name,
                                 void *opaque, Error **errp)
{
    FemuCtrl *n = FEMU(obj);
    struct FemuEventSched *s = n->events;
    uint32_t ms;

    if (!visit_type_uint32(v, name, &ms, errp)) {
        return;
    }
    if (!s) {
        error_setg(errp, "x-events-now needs an events_file");
        return;
    }
    s->test_clock = true;
    if (!s->started) {
        return;
    }
    timer_del(s->timer);
    femu_events_run(n, (int64_t)ms * SCALE_MS, false);
}

void femu_events_add_test_props(Object *obj)
{
    object_property_add(obj, "x-events-now", "uint32", NULL,
                        femu_events_test_now, NULL, NULL);
}

/* the events of @n for query-femu-events */
FemuEvents *femu_events_info(FemuCtrl *n, Error **errp)
{
    struct FemuEventSched *s = n->events;
    FemuEvents *info;
    FemuEventInfoList **tail;

    if (!s) {
        error_setg(errp, "the femu device has no events_file");
        return NULL;
    }
    info = g_new0(FemuEvents, 1);
    info->path = object_get_canonical_path(OBJECT(n));
    info->state = !s->started ? FEMU_EVENTS_STATE_WAITING :
                  s->cursor < s->nr ? FEMU_EVENTS_STATE_RUNNING :
                                      FEMU_EVENTS_STATE_DONE;
    tail = &info->events;
    for (int i = 0; i < s->nr; i++) {
        FemuEvent *ev = &s->ev[i];
        FemuEventInfo *e = g_new0(FemuEventInfo, 1);

        e->line = ev->line;
        e->action = g_strdup(ev->action);
        e->time_ms = ev->deadline_ns / SCALE_MS;
        if (ev->ran_ns >= 0) {
            e->has_ran_ms = true;
            e->ran_ms = ev->ran_ns / SCALE_MS;
        }
        e->result = ev->result;
        e->error = g_strdup(ev->error);
        QAPI_LIST_APPEND(tail, e);
    }
    return info;
}

bool femu_events_installed(FemuCtrl *n)
{
    return n->events != NULL;
}
