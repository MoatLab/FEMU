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
 *
 * A line that starts with '@' names commands, not a time (femu-fsched.c).
 * The FTL thread matches each command against those lines after the first
 * enable. No action has an effect yet: a selection moves the counters of
 * its line, which x-fault-sel reports, and writes one record per line it
 * concerns to the fault record ring (femu-frec.c):
 *
 *   FTL thread: step++, match --> femu_fr_put() per line --> wake writer
 *   writer thread (events_log only): pop, write a JSON line, free
 *   query-femu-events (main loop): femu_fr_read(), no lock taken
 *
 * The file writes run on their own thread, so a slow file never holds the
 * main loop. Unplug and QEMU exit stop the writer after it writes what the
 * ring holds at that time, and report the records it could not write.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-femu.h"
#include "qapi/visitor.h"
#include "qom/object.h"
#include "qemu/timer.h"
#include "qemu/error-report.h"
#include "qemu/thread.h"
#include "system/system.h"
#include "nvme.h"
#include "femu-query.h"
#include "femu-fsched.h"
#include "femu-frec.h"
#include "nvme-pi.h"
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

/* the command lines; the FTL thread reads them, so they outlive it */
struct FemuFsched {
    FemuFsLine *l;
    int nr;
    uint8_t *out;               /* FTL thread: the outcome of each line */
    uint8_t *why;               /* FTL thread: why a winner has no effect */
    bool running;               /* set at the first enable */
    uint64_t step;              /* FTL thread: commands taken, atomic */

    /* the FTL thread is the one producer of the ring */
    FemuFrRing ring;
    FemuFrSlot *slots;
    bool has_log;               /* events_log is set; fixed at realize */
    int log_fd;                 /* events_log; -1 for none or closed */
    bool log_failed;            /* writer: write nothing after an error */
    uint64_t log_unwritten;     /* writer: records freed after an error */
    char *log_error;            /* set once, published with a release */
    bool log_running;           /* the writer thread exists */
    bool log_stop;              /* main loop asks the writer to end */
    QemuThread log_thread;
    QemuEvent log_ev;           /* a record or a stop waits */
    Notifier log_exit;
    FemuCtrl *ctrl;             /* for the exit notifier */
};

/* records the writer takes in one pass before it looks at stop and hold */
#define FEMU_FSCHED_LOG_BATCH   256

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
        ms += femu_fs_splitmix64(&seed) % win;
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

/* the facts of @n that decide which command lines realize accepts */
static void femu_fsched_dev(FemuCtrl *n, FemuFsDev *d, uint64_t *nsze)
{
    for (uint32_t i = 0; i < n->namespace_limit; i++) {
        NvmeNamespace *ns = nvme_ns_allocated(n, i + 1);

        nsze[i] = ns ? le64_to_cpu(ns->id_ns.nsze) : 0;
    }
    *d = (FemuFsDev) {
        .bbssd = BBSSD(n),
        .ns_mgmt = n->ns_mgmt,
        .namespace_modes = n->namespace_modes != NULL,
        .subsys = n->subsys != NULL,
        .shared_ftl = n->shared_ftl,
        .cxl_ssd = n->cxl_dev || n->cxl_media,
        .power_loss = n->power_loss,
        .vwc = n->vwc,
        .durable_at_done = n->durable_at_done,
        .fdp = nvme_fdp_directive(n),
        .buffer_low = n->bb_params.buffer_low_pcent != 0,
        .sdc = n->sdc,
        .awupf_lbas = n->awupf_lbas,
        .nr_ns = n->namespace_limit,
        .nsze = nsze,
    };
}

/* one command line; an ana= or slow= action is checked as on a time line */
static bool femu_fsched_line(FemuCtrl *n, const FemuFsDev *d, char *s,
                             int line, FemuFsLine *l, Error **errp)
{
    char why[FEMU_FS_ERR_LEN];
    FemuEvent ev = { 0 };

    if (!femu_fs_parse(d, s, line, l, why, sizeof(why))) {
        error_setg(errp, "%s", why);
        return false;
    }
    if (l->act == FEMU_FS_ACT_ANA || l->act == FEMU_FS_ACT_SLOW) {
        return femu_events_action(n, l->action, &ev, errp);
    }
    return true;
}

/* the first error of events_log: kept for the query, and said once */
static void femu_fsched_log_fail(FemuCtrl *n, const char *op, int err)
{
    struct FemuFsched *f = n->fsched;
    char *msg;

    f->log_failed = true;
    if (qatomic_read(&f->log_error)) {
        return;
    }
    msg = g_strdup_printf("events_log %s: %s failed: %s", n->evlog_path, op,
                          strerror(err));
    error_report("femu: %s; later records are not written", msg);
    qatomic_store_release(&f->log_error, msg);
}

/* the whole line, or the error of the write that failed */
static int femu_fsched_log_write(int fd, const char *buf, size_t len)
{
    while (len) {
        ssize_t w = write(fd, buf, len);

        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return errno;
        }
        buf += w;
        len -= w;
    }
    return 0;
}

/*
 * Take at most @max records and write each as one line. A write error
 * stops the file, not the run: later records free their slots unwritten.
 * Returns the number taken.
 */
static uint64_t femu_fsched_log_batch(FemuCtrl *n, uint64_t max)
{
    struct FemuFsched *f = n->fsched;
    char line[FEMU_FR_JSON_MAX];
    FemuFrRec rec;
    uint64_t i;

    /* a slot is freed once its line is written, so the query lags the file */
    for (i = 0; i < max && femu_fr_peek(&f->ring, &rec); i++) {
        if (!f->log_failed) {
            int len = femu_fr_json(&rec, line, sizeof(line));
            int err = femu_fsched_log_write(f->log_fd, line, len);

            if (err) {
                femu_fsched_log_fail(n, "a write", err);
            }
        }
        if (f->log_failed) {
            f->log_unwritten++;
        }
        femu_fr_release(&f->ring);
    }
    return i;
}

/*
 * The writer. x-fault-log-hold (qtest) leaves the records in the ring, so
 * it fills and drops. A stop writes what the ring holds when the stop is
 * seen, held or not, so a busy producer cannot keep the writer alive.
 */
static void *femu_fsched_log_thread(void *opaque)
{
    FemuCtrl *n = opaque;
    struct FemuFsched *f = n->fsched;

    for (;;) {
        qemu_event_reset(&f->log_ev);
        if (qatomic_load_acquire(&f->log_stop)) {
            femu_fsched_log_batch(n, femu_fr_pending(&f->ring));
            return NULL;
        }
        while (!qatomic_read(&n->test_fs_log_hold) &&
               femu_fsched_log_batch(n, FEMU_FSCHED_LOG_BATCH) ==
               FEMU_FSCHED_LOG_BATCH &&
               !qatomic_read(&f->log_stop)) {
            /* more waits: go on, a batch at a time */
        }
        if (!qatomic_read(&f->log_stop)) {
            qemu_event_wait(&f->log_ev);
        }
    }
}

/*
 * Unplug or QEMU exit: stop the writer after it writes the ring as it is
 * now, close the file, and say how many records did not reach it. The
 * FTL thread may still add records at exit; those are counted too.
 */
static void femu_fsched_log_finish(FemuCtrl *n)
{
    struct FemuFsched *f = n->fsched;
    uint64_t lost;

    if (!f->log_running) {
        return;
    }
    qatomic_store_release(&f->log_stop, true);
    qemu_event_set(&f->log_ev);
    qemu_thread_join(&f->log_thread);
    f->log_running = false;
    /* the writer has ended, so its count is safe to read */
    lost = femu_fr_pending(&f->ring) + qatomic_read(&f->ring.dropped) +
           f->log_unwritten;
    if (close(f->log_fd) < 0) {
        femu_fsched_log_fail(n, "the close", errno);
    }
    f->log_fd = -1;
    if (lost) {
        warn_report("femu: events_log %s: %" PRIu64 " records not written",
                    n->evlog_path, lost);
    }
}

static void femu_fsched_log_exit(Notifier *notifier, void *data)
{
    struct FemuFsched *f = container_of(notifier, struct FemuFsched,
                                        log_exit);

    femu_fsched_log_finish(f->ctrl);
}

/* /dev/null or /dev/full: the only devices events_log takes */
static bool femu_fsched_log_dev(const struct stat *st)
{
    static const char *const ok[] = { "/dev/null", "/dev/full" };
    struct stat d;

    if (!S_ISCHR(st->st_mode)) {
        return false;
    }
    for (size_t i = 0; i < ARRAY_SIZE(ok); i++) {
        if (stat(ok[i], &d) == 0 && S_ISCHR(d.st_mode) &&
            d.st_rdev == st->st_rdev) {
            return true;
        }
    }
    return false;
}

/* whether @file of this device is a link to the inode @st describes */
static bool femu_fsched_log_same(const char *file, const struct stat *st)
{
    struct stat o;

    return file && stat(file, &o) == 0 && o.st_dev == st->st_dev &&
           o.st_ino == st->st_ino;
}

/*
 * The last byte of a regular file, by a read-only open of its own, as the
 * log is opened write-only. A file that cannot be read is not refused.
 */
static bool femu_fsched_log_partial(const char *path, off_t size)
{
    char last;
    bool partial;
    int fd;

    if (size <= 0) {
        return false;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        return false;
    }
    partial = pread(fd, &last, 1, size - 1) == 1 && last != '\n';
    close(fd);
    return partial;
}

/*
 * Realize: open events_log to append. Only a regular file, /dev/null or
 * /dev/full: a FIFO with no reader would stall the writer and with it the
 * exit. Refused: a regular file that another femu file uses, by path or
 * by a hard link, as a save by rename would replace the log or lines
 * would mix; and a file whose last line has no newline, as the next
 * record would join that partial line.
 */
static int femu_fsched_log_open(FemuCtrl *n, Error **errp)
{
    g_autofree char *path = NULL;
    g_autofree char *evf = NULL;
    struct stat st;
    int fd;

    if (!*n->events_log) {
        error_setg(errp, "events_log must not be empty");
        return -1;
    }
    if (lstat(n->events_log, &st) == 0 && S_ISLNK(st.st_mode) &&
        stat(n->events_log, &st) < 0) {
        error_setg(errp, "events_log: '%s' is a link to nothing",
                   n->events_log);
        return -1;
    }
    path = femu_path_resolve(n->events_log);
    if (!path) {
        error_setg(errp, "events_log: no directory for '%s'", n->events_log);
        return -1;
    }
    if (stat(path, &st) == 0 && !S_ISREG(st.st_mode) &&
        !femu_fsched_log_dev(&st)) {
        goto bad_type;
    }
    /* devices are shared, so only a file can collide */
    evf = femu_path_resolve(n->events_file);
    if ((stat(path, &st) < 0 || S_ISREG(st.st_mode)) &&
        ((evf && !strcmp(evf, path)) ||
         (n->iotrace_path && !strcmp(n->iotrace_path, path)) ||
         femu_path_in_use(n, path, false))) {
        goto in_use;
    }
    /* O_NONBLOCK: a FIFO made after the check fails here, never blocks */
    fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NONBLOCK,
              0644);
    if (fd < 0) {
        error_setg_errno(errp, errno, "events_log: cannot open '%s'", path);
        return -1;
    }
    if (fstat(fd, &st) < 0 ||
        (!S_ISREG(st.st_mode) && !femu_fsched_log_dev(&st))) {
        close(fd);
        goto bad_type;
    }
    if (S_ISREG(st.st_mode)) {
        if (femu_fsched_log_same(n->events_file, &st) ||
            femu_fsched_log_same(n->iotrace_path, &st) ||
            femu_inode_in_use(n, &st, false)) {
            close(fd);
            goto in_use;
        }
        if (femu_fsched_log_partial(path, st.st_size)) {
            error_setg(errp, "events_log: '%s' ends in a partial line, "
                       "which the next record would join", path);
            close(fd);
            return -1;
        }
    }
    n->evlog_path = g_steal_pointer(&path);
    return fd;

bad_type:
    error_setg(errp, "events_log: '%s' is not a regular file, /dev/null or "
               "/dev/full", path);
    return -1;
in_use:
    error_setg(errp, "events_log: '%s' is the events_file, or a "
               "persist_file, pel_file, io_trace or events_log of a "
               "device", path);
    return -1;
}

/* the writer has stopped, or never started */
static void femu_fsched_free(struct FemuFsched *f)
{
    if (f) {
        if (f->log_exit.notify) {
            qemu_remove_exit_notifier(&f->log_exit);
            qemu_event_destroy(&f->log_ev);
        }
        if (f->log_fd >= 0) {
            close(f->log_fd);
        }
        g_free(f->log_error);
        g_free(f->slots);
        g_free(f->l);
        g_free(f->out);
        g_free(f->why);
        g_free(f);
    }
}

/**
 * femu_events_init - read and compile events_file at realize
 * @n: the controller, its namespaces allocated
 * @errp: the error, with the line, of a file that is refused
 *
 * Returns true with no file, or with a schedule waiting for the first
 * enable. Refused with csd_pause, whose frozen clock the timer does not
 * follow. Time lines and command lines share the limit of 1024. Only a
 * schedule with a command line gets a record ring and events_log.
 */
bool femu_events_init(FemuCtrl *n, Error **errp)
{
    g_autofree char *text = NULL;
    g_autofree uint64_t *nsze = NULL;
    g_auto(GStrv) lines = NULL;
    struct FemuEventSched *s;
    struct FemuFsched *f;
    FemuFsDev dev;
    guint nr_lines;
    size_t len;
    FILE *f_in;

    if (n->events_max_faults < FEMU_FR_SLOTS_MIN ||
        n->events_max_faults > FEMU_FR_SLOTS_MAX) {
        error_setg(errp, "events_max_faults takes %u to %u",
                   FEMU_FR_SLOTS_MIN, FEMU_FR_SLOTS_MAX);
        return false;
    }
    if (!n->events_file) {
        if (n->events_log) {
            error_setg(errp, "events_log needs events_file");
            return false;
        }
        return true;
    }
    if (n->csd_params.pause) {
        error_setg(errp, "events_file does not work with csd_pause");
        return false;
    }
    f_in = fopen(n->events_file, "r");
    if (!f_in) {
        error_setg_errno(errp, errno, "events_file %s", n->events_file);
        return false;
    }
    /* read at most one byte past the limit, so a large file costs nothing */
    text = g_malloc(FEMU_EVENTS_MAX_FILE + 2);
    len = fread(text, 1, FEMU_EVENTS_MAX_FILE + 1, f_in);
    /* a read that fails part way (a directory, an I/O error) is no file */
    if (ferror(f_in)) {
        int err = errno;

        fclose(f_in);
        error_setg_errno(errp, err, "events_file %s: read failed",
                         n->events_file);
        return false;
    }
    fclose(f_in);
    text[len] = '\0';
    if (len > FEMU_EVENTS_MAX_FILE || memchr(text, '\0', len)) {
        error_setg(errp, "events_file: a text file of at most %d KiB",
                   (int)(FEMU_EVENTS_MAX_FILE / KiB));
        return false;
    }
    lines = g_strsplit(text, "\n", -1);
    nr_lines = g_strv_length(lines);
    /* a final newline leaves one empty piece, which is no line */
    if (nr_lines && !*lines[nr_lines - 1]) {
        nr_lines--;
    }
    if (nr_lines > FEMU_EVENTS_MAX_LINES) {
        error_setg(errp, "events_file: more than %d lines",
                   FEMU_EVENTS_MAX_LINES);
        return false;
    }
    nsze = g_new0(uint64_t, MAX(n->namespace_limit, 1));
    femu_fsched_dev(n, &dev, nsze);
    s = g_new0(struct FemuEventSched, 1);
    s->ev = g_new0(FemuEvent, FEMU_EVENTS_MAX_LINES);
    f = g_new0(struct FemuFsched, 1);
    f->log_fd = -1;
    f->ctrl = n;
    f->l = g_new0(FemuFsLine, FEMU_EVENTS_MAX_LINES);
    for (int i = 0; lines[i]; i++) {
        char *l = lines[i];
        Error *err = NULL;
        bool ok;

        if (strlen(l) > FEMU_EVENTS_MAX_LINE) {
            error_setg(errp, "events_file line %d: longer than %d bytes",
                       i + 1, FEMU_EVENTS_MAX_LINE);
            goto fail;
        }
        g_strstrip(l);
        if (!*l || *l == '#') {
            continue;
        }
        if (s->nr + f->nr == FEMU_EVENTS_MAX_LINES) {
            error_setg(errp, "events_file: more than %d events",
                       FEMU_EVENTS_MAX_LINES);
            goto fail;
        }
        if (*l == '@') {
            ok = femu_fsched_line(n, &dev, l, i + 1, &f->l[f->nr], &err);
        } else {
            ok = femu_events_line(n, l, i + 1, &s->ev[s->nr], &err);
        }
        if (!ok) {
            error_setg(errp, "events_file line %d: %s", i + 1,
                       error_get_pretty(err));
            error_free(err);
            goto fail;
        }
        if (*l == '@') {
            f->nr++;
        } else {
            s->nr++;
        }
    }
    qsort(s->ev, s->nr, sizeof(*s->ev), femu_events_cmp);
    n->events = s;
    /* no command line: the FTL thread sees no schedule and does no work */
    if (!f->nr) {
        femu_fsched_free(f);
        if (n->events_log) {
            error_setg(errp, "events_log needs a command line in events_file");
            goto fail_events;
        }
        return true;
    }
    if (n->events_log) {
        f->log_fd = femu_fsched_log_open(n, errp);
        if (f->log_fd < 0) {
            goto fail;
        }
    }
    f->out = g_new0(uint8_t, f->nr);
    f->why = g_new0(uint8_t, f->nr);
    f->slots = g_new0(FemuFrSlot, n->events_max_faults);
    femu_fr_init(&f->ring, f->slots, n->events_max_faults, f->log_fd < 0);
    n->fsched = f;
    if (f->log_fd >= 0) {
        f->has_log = true;
        qemu_event_init(&f->log_ev, false);
        f->log_exit.notify = femu_fsched_log_exit;
        qemu_add_exit_notifier(&f->log_exit);
        f->log_running = true;
        qemu_thread_create(&f->log_thread, "femu-events-log",
                           femu_fsched_log_thread, n, QEMU_THREAD_JOINABLE);
    }
    return true;

fail:
    femu_fsched_free(f);
fail_events:
    g_clear_pointer(&n->evlog_path, g_free);
    for (int i = 0; i < s->nr; i++) {
        g_free(s->ev[i].action);
    }
    g_free(s->ev);
    g_free(s);
    n->events = NULL;
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
    if (n->fsched) {
        /* commands count from here; the FTL thread reads this once a step */
        qatomic_set(&n->fsched->running, true);
    }
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

/*
 * Realize undo and unplug, first step: the timer stops before anything it
 * reaches goes. The FTL thread may still read the command lines.
 */
void femu_events_cancel(FemuCtrl *n)
{
    struct FemuEventSched *s = n->events;

    if (n->fsched) {
        qatomic_set(&n->fsched->running, false);
    }
    if (s && s->timer) {
        timer_del(s->timer);
    }
}

/*
 * Second step, once no FTL thread or poller runs: free the schedule. A
 * reader on those threads may still hold it until they stop.
 */
void femu_events_free(FemuCtrl *n)
{
    struct FemuEventSched *s = n->events;

    /* the last records reach events_log, even under x-fault-log-hold */
    if (n->fsched) {
        femu_fsched_log_finish(n);
    }
    femu_fsched_free(n->fsched);
    g_clear_pointer(&n->evlog_path, g_free);
    n->fsched = NULL;
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
 * The effect of a selected line. None is modelled yet: each case only
 * names what it will do, and a selection moves the counters alone. @eff
 * is the command as the winners of its groups leave it.
 */
static void femu_fsched_act(FemuCtrl *n, NvmeRequest *req,
                            const FemuFsLine *l, const FemuFsView *eff)
{
    switch (l->act) {
    case FEMU_FS_ACT_POWER_LOSS:    /* not modelled yet: a cut at pre */
    case FEMU_FS_ACT_CFS:           /* not modelled yet: CSTS.CFS at pre */
    case FEMU_FS_ACT_HANG:          /* not modelled yet: no CQE */
    case FEMU_FS_ACT_WRITE_FAIL:    /* not modelled yet: Write Fault */
    case FEMU_FS_ACT_WB_FAIL:       /* not modelled yet: write-back error */
    case FEMU_FS_ACT_FUA_LIE:       /* not modelled yet: FUA buffers */
    case FEMU_FS_ACT_READ_UNC:      /* not modelled yet: Unrecovered Read */
    case FEMU_FS_ACT_FLUSH_LIE:     /* not modelled yet: no destage */
    case FEMU_FS_ACT_SDC:           /* not modelled yet: sdc override */
    case FEMU_FS_ACT_DELAY:         /* not modelled yet: a later CQE */
    case FEMU_FS_ACT_SLOW:          /* not modelled yet: die-slow by BH */
    case FEMU_FS_ACT_ANA:           /* not modelled yet: ana-state by BH */
        break;
    default:
        g_assert_not_reached();
    }
}

static uint8_t femu_fsched_outcome(uint8_t out)
{
    switch (out) {
    case FEMU_FS_OUT_APPLIED:
        return FEMU_FR_OUT_SELECTED;
    case FEMU_FS_OUT_SUPERSEDED:
        return FEMU_FR_OUT_SUPERSEDED;
    default:
        return FEMU_FR_OUT_NO_EFFECT;
    }
}

/*
 * One select record per line that selected @req. The FTL thread is the
 * only producer, so the ring needs no lock here.
 */
static void femu_fsched_record(FemuCtrl *n, NvmeRequest *req,
                               const FemuFsView *v, int i)
{
    struct FemuFsched *f = n->fsched;
    const FemuFsLine *l = &f->l[i];
    FemuFrRec rec = {
        .step = f->step,
        .match = l->matched,
        .slba = v->slba,
        .nlb = v->nlb,
        .nsid = v->nsid,
        .line = l->line,
        .sqid = req->sq ? req->sq->sqid : 0,
        .cid = le16_to_cpu(req->cmd.cid),
        .origin = FEMU_FR_ORIGIN_SCHED_CMD,
        .phase = FEMU_FR_PHASE_SELECT,
        .act = l->act,
        .outcome = femu_fsched_outcome(f->out[i]),
        .why = f->why[i],
        .opc = v->opc,
        .fua = v->fua,
    };

    femu_fr_put(&f->ring, &rec);
    /* a no-op while the writer is already awake, or after it ended */
    if (f->has_log) {
        qemu_event_set(&f->log_ev);
    }
}

/**
 * femu_fsched_step - match one command against the command lines
 * @n: the controller, with command lines
 * @req: the request just taken from a to_ftl ring, not yet run
 *
 * Runs on the FTL thread only. The view comes from the SQE copy and the
 * namespace, never from fields the FTL or nvme_power_io() fill later. A
 * command outside the matchable set, or one that fails the view checks,
 * counts for no line. Each command counts as one step, matched or not.
 */
void femu_fsched_step(FemuCtrl *n, NvmeRequest *req)
{
    struct FemuFsched *f = n->fsched;
    const NvmeRwCmd *rw = (const NvmeRwCmd *)&req->cmd;
    FemuFsView v = {
        .opc = req->cmd.opcode,
        .nsid = le32_to_cpu(req->cmd.nsid),
    };
    NvmeNamespace *ns;
    FemuFsView eff;
    uint64_t nsze = 0;
    unsigned lbads = 0;
    unsigned mdts = 0;
    uint32_t xfer_ms = 0;
    uint32_t hold;

    qatomic_set(&f->step, f->step + 1);
    if (!qatomic_read(&f->running)) {
        return;
    }
    switch (v.opc) {
    case NVME_CMD_FLUSH:
        if (v.nsid != NVME_NSID_BROADCAST && !nvme_ns(n, v.nsid)) {
            return;
        }
        break;
    case NVME_CMD_READ:
    case NVME_CMD_WRITE:
    case NVME_CMD_WRITE_ZEROES:
        ns = nvme_ns(n, v.nsid);
        if (!ns) {
            return;
        }
        v.slba = le64_to_cpu(rw->slba);
        v.nlb = le16_to_cpu(rw->nlb) + 1;
        v.fua = v.opc == NVME_CMD_WRITE &&
                (le16_to_cpu(rw->control) & NVME_RW_FUA);
        nsze = le64_to_cpu(ns->id_ns.nsze);
        lbads = ns->id_ns.lbaf[NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas)].lbads;
        /* the transfer nvme_rw() checks against MDTS, metadata and all */
        xfer_ms = femu_fs_xfer_ms(
            le16_to_cpu(ns->id_ns.lbaf[NVME_ID_NS_FLBAS_INDEX(
                ns->id_ns.flbas)].ms),
            NVME_ID_NS_FLBAS_EXTENDED(ns->id_ns.flbas), femu_pi_type(ns),
            femu_pi_size(ns),
            le16_to_cpu(rw->control) & NVME_RW_PRINFO_PRACT);
        break;
    default:
        return;
    }
    /* as nvme_check_mdts(): in the minimum page size, not the CC one */
    if (n->mdts) {
        mdts = 12 + NVME_CAP_MPSMIN(n->bar.cap) + n->mdts;
    }
    if (!femu_fs_view_ok(&v, nsze, lbads, xfer_ms, mdts)) {
        return;
    }
    /*
     * qtest x-fault-hold: park here, the schedule in hand, for that many
     * ms. The time runs out on this thread, so an unplug that waits for
     * it on the main loop still ends.
     */
    hold = qatomic_read(&n->test_fs_hold_ms);
    if (unlikely(hold)) {
        qatomic_set(&n->test_fs_hold_ms, 0);
        qatomic_set(&n->test_fs_held, 1);
        g_usleep((gulong)hold * 1000);
        qatomic_set(&n->test_fs_held, 2);
    }
    femu_fs_match(f->l, f->nr, &v, f->out, f->why, &eff);
    for (int i = 0; i < f->nr; i++) {
        if (f->out[i] == FEMU_FS_OUT_NONE) {
            continue;
        }
        femu_fsched_record(n, req, &v, i);
        if (f->out[i] == FEMU_FS_OUT_APPLIED) {
            femu_fsched_act(n, req, &f->l[i], &eff);
        }
    }
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

/*
 * x-fault-sel (qtest): per command line, in file order,
 * "<line>:<matched>:<selected>:<applied>:<superseded>:<no-effect>",
 * separated by spaces.
 */
static char *femu_fsched_test_sel(Object *obj, Error **errp)
{
    struct FemuFsched *f = FEMU(obj)->fsched;
    GString *g;

    if (!f) {
        error_setg(errp, "x-fault-sel needs a command line in events_file");
        return NULL;
    }
    g = g_string_new(NULL);
    for (int i = 0; i < f->nr; i++) {
        FemuFsLine *l = &f->l[i];

        g_string_append_printf(g, "%s%d:%" PRIu64 ":%" PRIu64 ":%" PRIu64
                               ":%" PRIu64 ":%" PRIu64, i ? " " : "",
                               l->line, qatomic_read(&l->matched),
                               qatomic_read(&l->selected),
                               qatomic_read(&l->applied),
                               qatomic_read(&l->superseded),
                               qatomic_read(&l->no_effect));
    }
    return g_string_free(g, false);
}

/*
 * x-fault-draw (qtest): a set gives the seed, and each get returns the
 * next draw, 0 to 999999, that a %PPM~SEED line with that seed makes. A
 * test picks seeds whose draws hit the ends of the range.
 */
static void femu_fsched_test_draw_get(Object *obj, Visitor *v,
                                      const char *name, void *opaque,
                                      Error **errp)
{
    FemuCtrl *n = FEMU(obj);
    uint32_t d = femu_fs_draw(&n->test_fs_rng);

    visit_type_uint32(v, name, &d, errp);
}

static void femu_fsched_test_draw_set(Object *obj, Visitor *v,
                                      const char *name, void *opaque,
                                      Error **errp)
{
    uint64_t seed;

    if (visit_type_uint64(v, name, &seed, errp)) {
        FEMU(obj)->test_fs_rng = seed;
    }
}

/*
 * x-fault-log-hold (qtest): while set, the events_log writer frees no
 * slot, so the ring fills and drops. Clearing it wakes the writer.
 */
static void femu_fsched_test_log_hold_get(Object *obj, Visitor *v,
                                          const char *name, void *opaque,
                                          Error **errp)
{
    bool hold = qatomic_read(&FEMU(obj)->test_fs_log_hold);

    visit_type_bool(v, name, &hold, errp);
}

static void femu_fsched_test_log_hold_set(Object *obj, Visitor *v,
                                          const char *name, void *opaque,
                                          Error **errp)
{
    FemuCtrl *n = FEMU(obj);
    bool hold;

    if (!visit_type_bool(v, name, &hold, errp)) {
        return;
    }
    if (!n->fsched || !n->fsched->log_running) {
        error_setg(errp, "x-fault-log-hold needs an events_log");
        return;
    }
    qatomic_set(&n->test_fs_log_hold, hold);
    if (!hold) {
        qemu_event_set(&n->fsched->log_ev);
    }
}

void femu_events_add_test_props(Object *obj)
{
    FemuCtrl *n = FEMU(obj);

    object_property_add(obj, "x-events-now", "uint32", NULL,
                        femu_events_test_now, NULL, NULL);
    /* the next matched command parks the FTL thread this many ms */
    object_property_add_uint32_ptr(obj, "x-fault-hold", &n->test_fs_hold_ms,
                                   OBJ_PROP_FLAG_READWRITE);
    /* 1 while parked by x-fault-hold, 2 after */
    object_property_add_uint32_ptr(obj, "x-fault-held", &n->test_fs_held,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_str(obj, "x-fault-sel", femu_fsched_test_sel, NULL);
    object_property_add(obj, "x-fault-draw", "uint64",
                        femu_fsched_test_draw_get, femu_fsched_test_draw_set,
                        NULL, NULL);
    object_property_add(obj, "x-fault-log-hold", "bool",
                        femu_fsched_test_log_hold_get,
                        femu_fsched_test_log_hold_set, NULL, NULL);
}

/* the fault records and their counters, for query-femu-events */
static void femu_fsched_info(FemuCtrl *n, FemuEvents *info)
{
    struct FemuFsched *f = n->fsched;
    g_autofree FemuFrRec *rec = g_new(FemuFrRec, f->ring.size);
    FemuFrIdRange drop[FEMU_FR_DROP_RANGES];
    FemuFaultRecordList **tail = &info->faults;
    FemuIdRangeList **dtail = &info->dropped_ids;
    uint32_t nr = femu_fr_read(&f->ring, rec, f->ring.size);
    uint32_t nd = femu_fr_dropped_ids(&f->ring, drop);

    info->has_step = true;
    info->step = qatomic_read(&f->step);
    info->has_last_id = true;
    info->last_id = qatomic_read(&f->ring.next_id);
    info->has_dropped = true;
    info->dropped = qatomic_read(&f->ring.dropped);
    info->has_overwritten = true;
    info->overwritten = qatomic_read(&f->ring.overwritten);
    info->log_error = g_strdup(qatomic_load_acquire(&f->log_error));
    info->has_faults = true;
    for (uint32_t i = 0; i < nr; i++) {
        FemuFaultRecord *e = g_new0(FemuFaultRecord, 1);
        const FemuFrRec *r = &rec[i];

        e->id = r->id;
        e->has_cause = r->cause != 0;
        e->cause = r->cause;
        e->origin = g_strdup(femu_fr_name_origin(r->origin));
        e->line = r->line;
        e->match = r->match;
        e->action = g_strdup(femu_fs_act_name(r->act));
        e->phase = g_strdup(femu_fr_name_phase(r->phase));
        e->step = r->step;
        e->nsid = r->nsid;
        e->sqid = r->sqid;
        e->cid = r->cid;
        e->opc = r->opc;
        e->fua = r->fua;
        e->slba = r->slba;
        e->nlb = r->nlb;
        e->outcome = g_strdup(femu_fr_name_outcome(r->outcome));
        if (r->outcome == FEMU_FR_OUT_NO_EFFECT) {
            e->reason = g_strdup(femu_fr_name_why(r->why));
        }
        e->has_status = r->status != 0;
        e->status = r->status;
        QAPI_LIST_APPEND(tail, e);
    }
    info->has_dropped_ids = true;
    for (uint32_t i = 0; i < nd; i++) {
        FemuIdRange *d = g_new0(FemuIdRange, 1);

        d->lo = drop[i].lo;
        d->hi = drop[i].hi;
        QAPI_LIST_APPEND(dtail, d);
    }
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
    /* a command line that can still select keeps the schedule running */
    info->state = !s->started ? FEMU_EVENTS_STATE_WAITING :
                  s->cursor < s->nr ||
                  (n->fsched && !femu_fs_done(n->fsched->l, n->fsched->nr)) ?
                  FEMU_EVENTS_STATE_RUNNING : FEMU_EVENTS_STATE_DONE;
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
    if (n->fsched) {
        femu_fsched_info(n, info);
    }
    return info;
}

bool femu_events_installed(FemuCtrl *n)
{
    return n->events != NULL;
}
