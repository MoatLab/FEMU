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
 * enable. A selection moves the counters of its line, which x-fault-sel
 * reports, and writes one record per line it concerns to the fault record
 * ring (femu-frec.c). flush-lie, fua-lie, wb-fail, hang and cfs have an
 * effect so far: after the FTL runs their command, an apply record tells
 * what came of it. A wb-fail mark fails at a later write-back, and a
 * later completion reports it (see "wb-fail" below). A hang or a cfs
 * holds its command with no CQE (see "hang and cfs" below).
 *
 *   FTL thread: step++, match --> femu_fr_put() per line --> FTL call
 *               --> post: lie or wb-fail apply, wb-fail report
 *               --> wake writer
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
#include "qemu/main-loop.h"
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

    /*
     * FTL thread: the lie selected in this step, for its apply record
     * once the FTL has run the command. One command per step, so one.
     */
    int lie_line;               /* index into @l */
    uint64_t lie_cause;         /* id of its select record */
    FemuFsView lie_view;        /* the command as the line saw it */

    /* FTL thread: the wb-fail selected in this step, as for a lie */
    bool wbf_sel;
    int wbf_line;
    uint64_t wbf_cause;
    int wbf_slot;               /* its fault slot, or -1 for none free */
    FemuFsView wbf_view;

    /*
     * The FTL thread, the pollers (hang) and the main loop (wb-fail
     * reports and write-backs, a cut, a cfs, a reclaim) write records, so
     * each producer takes this lock.
     */
    QemuSpin put_lock;

    /*
     * cfs. The FTL thread parks the command and schedules cfs_bh; the
     * main loop does the rest. gen counts what ends a park: a reclaim of
     * the parked command and every controller clear. cfs_gen is the gen
     * of the park the BH serves, 0 for none. The park_* fields keep the
     * command as the line saw it, for its records.
     */
    bool cfs_sel;               /* FTL thread: a cfs won in this step */
    QEMUBH *cfs_bh;
    uint32_t gen;               /* main loop writes, FTL thread reads */
    uint32_t cfs_gen;
    bool bh_held;               /* x-fault-bh-hold kept the BH from running */
    int park_line;              /* index into @l */
    uint64_t park_match;
    uint64_t park_cause;        /* id of its select record */
    uint16_t park_sqid;
    uint16_t park_cid;
    FemuFsView park_view;

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

/*
 * wb-fail. One lock guards the slots and the failures; the FTL thread,
 * the main loop and the pollers (at CQE post) take it. The lock order is
 * this lock, then the ring's put_lock, then the error log lock.
 *
 *   select (FTL step) --> slot, req->fs_wbf --> ssd_write marks pages
 *   write-back meets a mark --> fail record, error log, AER --> pending
 *   draining completion --> collect: status, report record, error log
 *   CQE posted --> once: consumed | SQ freed --> pending again
 */
struct FemuWbf {
    QemuSpin lock;
    FemuWbTab t;
    bool cutting;               /* a power cut: no AER */
    uint64_t seq;               /* stamps and completion tokens, atomic */
};

/*
 * The stamp of the drain that runs on this thread: an FTL step or an
 * Admin command; 0 for a write-back no command asked for.
 */
static __thread uint64_t femu_wbf_cur;

/*
 * Main loop: end the park a cfs BH may still serve. gen is never 0, so
 * a cfs_gen of 0 matches no gen.
 */
static void femu_fsched_gen_next(struct FemuFsched *f)
{
    uint32_t g = f->gen + 1;

    qatomic_set(&f->gen, g ? g : 1);
}

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
static void femu_wbf_free(FemuCtrl *n)
{
    if (n->wbf) {
        g_free(n->wbf->t.fail);
        g_clear_pointer(&n->wbf, g_free);
    }
}

static void femu_fsched_cfs_bh(void *opaque);

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
        if (f->cfs_bh) {
            qemu_bh_delete(f->cfs_bh);
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
    qemu_spin_init(&f->put_lock);
    f->gen = 1;
    /* no wb-fail line: none of its hooks runs; no cfs line: no BH */
    for (int i = 0; i < f->nr; i++) {
        if (f->l[i].act == FEMU_FS_ACT_WB_FAIL && !n->wbf) {
            n->wbf = g_new0(struct FemuWbf, 1);
            qemu_spin_init(&n->wbf->lock);
        }
        if (f->l[i].act == FEMU_FS_ACT_CFS && !f->cfs_bh) {
            f->cfs_bh = qemu_bh_new(femu_fsched_cfs_bh, n);
        }
    }
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
        /* a cfs BH that is still due finds its park gone */
        femu_fsched_gen_next(n->fsched);
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

    /*
     * Unplug gives back what a hang or a cfs holds; then the last records
     * reach events_log, even under x-fault-log-hold.
     */
    if (n->fsched) {
        femu_fsched_reclaim(n, NULL, FEMU_FS_WHY_UNPLUG);
        femu_fsched_log_finish(n);
    }
    femu_fsched_free(n->fsched);
    femu_wbf_free(n);
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

/* one record to the ring; every producer comes here */
static uint64_t femu_fsched_put(FemuCtrl *n, FemuFrRec *rec)
{
    struct FemuFsched *f = n->fsched;
    uint64_t id;

    qemu_spin_lock(&f->put_lock);
    id = femu_fr_put(&f->ring, rec);
    qemu_spin_unlock(&f->put_lock);
    /* a no-op while the writer is already awake, or after it ended */
    if (f->has_log) {
        qemu_event_set(&f->log_ev);
    }
    return id;
}

/* a wb-fail record of slot @s, with what its select record saw */
static FemuFrRec femu_wbf_rec(FemuCtrl *n, const FemuWbSlot *slot, int s,
                              uint8_t phase, uint8_t outcome)
{
    return (FemuFrRec) {
        .cause = slot->sel_id,
        .step = qatomic_read(&n->fsched->step),
        .match = slot->match,
        .slba = slot->slba,
        .nlb = slot->nlb,
        .nsid = slot->nsid,
        .line = slot->line,
        .sqid = slot->sqid,
        .cid = slot->cid,
        .origin = FEMU_FR_ORIGIN_SCHED_CMD,
        .phase = phase,
        .act = FEMU_FS_ACT_WB_FAIL,
        .outcome = outcome,
        .opc = FEMU_FS_OPC_WRITE,
        .fslot = s + 1,
    };
}

/*
 * FTL thread: wb-fail line @i won on the Write @req. The Write marks the
 * pages it buffers with the slot; femu_fsched_post() records the result.
 */
static void femu_wbf_select(FemuCtrl *n, NvmeRequest *req, int i,
                            const FemuFsView *v, uint64_t id)
{
    struct FemuFsched *f = n->fsched;
    const FemuFsLine *l = &f->l[i];
    struct FemuWbf *w = n->wbf;
    int s;

    qemu_spin_lock(&w->lock);
    s = femu_wb_slot_get(&w->t);
    if (s >= 0) {
        FemuWbSlot *slot = &w->t.slot[s];

        slot->mode = l->wb_mode;
        slot->report = l->wb_report;
        slot->aer = l->wb_aer;
        slot->line = l->line;
        slot->match = l->matched;
        slot->sqid = req->sq ? req->sq->sqid : 0;
        slot->cid = le16_to_cpu(req->cmd.cid);
        slot->nsid = v->nsid;
        slot->slba = v->slba;
        slot->nlb = v->nlb;
        slot->sel_id = id;
        req->fs_wbf = s + 1;
    }
    qemu_spin_unlock(&w->lock);
    f->wbf_sel = true;
    f->wbf_line = i;
    f->wbf_cause = id;
    f->wbf_slot = s;
    f->wbf_view = *v;
}

/* FTL thread: the apply record of the wb-fail of this step */
static void femu_wbf_apply(FemuCtrl *n, NvmeRequest *req)
{
    struct FemuFsched *f = n->fsched;
    const FemuFsLine *l = &f->l[f->wbf_line];
    const FemuFsView *v = &f->wbf_view;
    struct FemuWbf *w = n->wbf;
    int s = f->wbf_slot;
    uint32_t pages = 0;
    bool skipped = false;
    bool atomic;
    bool buffer;
    uint8_t why;
    FemuFrRec rec;

    f->wbf_sel = false;
    req->fs_wbf = 0;
    buffer = bbssd_wbf_facts(req->ns, req, v->slba, v->nlb, &atomic);
    qemu_spin_lock(&w->lock);
    if (s >= 0) {
        pages = w->t.slot[s].marked;
        skipped = w->t.slot[s].skipped;
    }
    why = femu_wb_apply_why(s >= 0, req->status != NVME_SUCCESS, buffer,
                            atomic, skipped, pages);
    /* the selection lets go; each mark keeps its own reference */
    femu_wb_slot_put(&w->t, s);
    qemu_spin_unlock(&w->lock);
    rec = (FemuFrRec) {
        .cause = f->wbf_cause,
        .step = f->step,
        .match = l->matched,
        .slba = v->slba,
        .nlb = v->nlb,
        .nsid = v->nsid,
        .line = l->line,
        .sqid = req->sq ? req->sq->sqid : 0,
        .cid = le16_to_cpu(req->cmd.cid),
        .origin = FEMU_FR_ORIGIN_SCHED_CMD,
        .phase = FEMU_FR_PHASE_APPLY,
        .act = FEMU_FS_ACT_WB_FAIL,
        .outcome = why == FEMU_FS_WHY_NONE ? FEMU_FR_OUT_MARKED :
                                             FEMU_FR_OUT_NO_EFFECT,
        .why = why,
        .opc = v->opc,
        .fua = v->fua,
        .pages = pages,
        .fslot = s >= 0 ? s + 1 : 0,
    };
    femu_fsched_put(n, &rec);
}

/**
 * femu_wbf_mark - a Write of slot @fslot buffered a page
 * @n: the controller
 * @fslot: the slot, from 1
 * @marked: the page took the mark; false when it kept an older one
 */
void femu_wbf_mark(FemuCtrl *n, uint16_t fslot, bool marked)
{
    struct FemuWbf *w = n->wbf;
    FemuWbSlot *slot = &w->t.slot[fslot - 1];

    qemu_spin_lock(&w->lock);
    if (marked) {
        slot->marked++;
        slot->refs++;
    } else {
        slot->skipped = true;
    }
    qemu_spin_unlock(&w->lock);
}

/**
 * femu_wbf_mode - the mode of slot @fslot
 * @n: the controller
 * @fslot: the slot, from 1, which a mark holds
 *
 * Returns FEMU_FS_WB_UNC or FEMU_FS_WB_OLD.
 */
uint8_t femu_wbf_mode(FemuCtrl *n, uint16_t fslot)
{
    struct FemuWbf *w = n->wbf;
    uint8_t mode;

    qemu_spin_lock(&w->lock);
    mode = w->t.slot[fslot - 1].mode;
    qemu_spin_unlock(&w->lock);
    return mode;
}

/**
 * femu_wbf_unmark - a marked page left the buffer with no write-back
 * @n: the controller
 * @fslot: the slot of the mark, from 1
 * @req: the Write that replaced the whole page, or NULL
 * @nsid: the namespace of the page
 * @page_slba: the first block of the page
 *
 * With @req the mark never fails, and a supersede record says so.
 */
void femu_wbf_unmark(FemuCtrl *n, uint16_t fslot, NvmeRequest *req,
                     uint32_t nsid, uint64_t page_slba)
{
    struct FemuWbf *w = n->wbf;
    int s = fslot - 1;
    FemuFrRec rec;

    /* unplug frees the schedule before the buffer */
    if (!w) {
        return;
    }
    qemu_spin_lock(&w->lock);
    rec = femu_wbf_rec(n, &w->t.slot[s], s, FEMU_FR_PHASE_SUPERSEDE,
                       FEMU_FR_OUT_SUPERSEDED);
    femu_wb_slot_put(&w->t, s);
    qemu_spin_unlock(&w->lock);
    if (!req) {
        return;
    }
    rec.sqid = req->sq ? req->sq->sqid : 0;
    rec.cid = le16_to_cpu(req->cmd.cid);
    rec.nsid = nsid;
    rec.slba = page_slba;
    rec.nlb = 0;
    femu_fsched_put(n, &rec);
}

/*
 * Room for one more failure in the table of @w, which the caller locks.
 * The allocation runs with the lock dropped, so the lock may be released
 * and taken again before this returns.
 */
static void femu_wbf_room(struct FemuWbf *w)
{
    while (w->t.nr == w->t.cap) {
        uint32_t cap = MAX(16, w->t.cap * 2);
        FemuWbFail *a;

        qemu_spin_unlock(&w->lock);
        a = g_new(FemuWbFail, cap);
        qemu_spin_lock(&w->lock);
        if (w->t.cap < cap) {
            FemuWbFail *old = w->t.fail;

            /* the first growth has no old table to copy */
            if (w->t.nr) {
                memcpy(a, old, w->t.nr * sizeof(*a));
            }
            w->t.fail = a;
            w->t.cap = cap;
            a = old;
        }
        qemu_spin_unlock(&w->lock);
        g_free(a);
        qemu_spin_lock(&w->lock);
    }
}

/**
 * femu_wbf_fail - a write-back met the mark of slot @fslot
 * @n: the controller
 * @fslot: the slot, from 1; the failure takes the reference of the mark
 * @ns: the namespace of the page
 * @page_slba: the first block of the page
 * @lbas: the blocks of the page
 * @mask: bit i for block @page_slba + i that the failure lost, i < 64
 * @lost: the blocks the failure lost
 * @first_lost: the first lost block, or @page_slba for none
 *
 * Writes the fail record and an Error Information entry with SQID, CID
 * and location FFFFh, for every failure. The completion that reports it
 * adds an entry of its own. aer=on then queues an AER, except at a
 * power cut, so the host always finds the entry the AER names.
 */
void femu_wbf_fail(FemuCtrl *n, uint16_t fslot, NvmeNamespace *ns,
                   uint64_t page_slba, uint32_t lbas, uint64_t mask,
                   uint32_t lost, uint64_t first_lost)
{
    struct FemuWbf *w = n->wbf;
    int s = fslot - 1;
    FemuWbFail fail = {
        .slot = s,
        .nsid = ns->id,
        .lbas = lbas,
        .page_slba = page_slba,
        .found = femu_wbf_cur,
    };
    FemuWbSlot *slot = &w->t.slot[s];
    FemuFrRec rec;
    bool aer;

    qemu_spin_lock(&w->lock);
    rec = femu_wbf_rec(n, slot, s, FEMU_FR_PHASE_FAIL,
                       slot->mode == FEMU_FS_WB_UNC ? FEMU_FR_OUT_UNC :
                                                      FEMU_FR_OUT_OLD);
    fail.report = slot->report;
    /* a cut drops every event; a controller after cfs sends none */
    aer = slot->aer && !w->cutting && !qatomic_read(&n->fs_cfs);
    qemu_spin_unlock(&w->lock);
    rec.found = femu_wbf_cur ? FEMU_FR_FOUND_CMD : FEMU_FR_FOUND_BG;
    rec.slba = page_slba;
    rec.nlb = lbas;
    rec.lba_mask = mask;
    rec.lost = lost;
    rec.status = NVME_WRITE_FAULT;
    fail.fail_id = femu_fsched_put(n, &rec);
    qemu_spin_lock(&w->lock);
    femu_wbf_room(w);
    femu_wb_fail_add(&w->t, &fail);
    qemu_spin_unlock(&w->lock);
    nvme_set_error_info(n, 0xffff, 0xffff, NVME_WRITE_FAULT, 0xffff,
                        first_lost, ns->id, fslot, 0, ns->csi);
    if (aer && nvme_enqueue_event(n, NVME_AER_TYPE_ERROR,
                                  NVME_AER_INFO_ERR_TRANS_INTERNAL_ERR,
                                  NVME_LOG_ERROR_INFO)) {
        qatomic_inc(&n->fault_wbf_aer);
    }
}

/**
 * femu_wbf_pending - whether a drain of @nsid fails
 * @n: the controller, with a wb-fail line
 * @nsid: the namespace, or 0 for all
 */
bool femu_wbf_pending(FemuCtrl *n, uint32_t nsid)
{
    struct FemuWbf *w = n->wbf;
    bool pending;

    qemu_spin_lock(&w->lock);
    pending = femu_wb_pending(&w->t, nsid);
    qemu_spin_unlock(&w->lock);
    return pending;
}

/*
 * A draining completion reports what is pending for @nsid. One report
 * record per failure, and one Error Information entry for the command.
 * The records are built under the lock and written after it.
 * Returns the status, or 0 for nothing.
 */
static uint16_t femu_wbf_collect(FemuCtrl *n, uint32_t nsid, uint16_t sqid,
                                 uint16_t cid, uint8_t opc, bool admin,
                                 uint64_t *held_tok)
{
    struct FemuWbf *w = n->wbf;
    uint64_t tok = qatomic_fetch_inc(&w->seq) + 1;
    g_autofree FemuFrRec *recs = NULL;
    uint32_t room = 0;
    uint32_t nr = 0;
    uint64_t lba = 0;
    uint32_t fnsid = 0;
    uint16_t fslot = 0;
    uint16_t status;
    uint8_t csi = 0;
    bool held;

    *held_tok = 0;
    qemu_spin_lock(&w->lock);
    /* one record per failure at most; allocate with the lock dropped */
    while (room < w->t.nr) {
        room = w->t.nr;
        qemu_spin_unlock(&w->lock);
        g_free(recs);
        recs = g_new(FemuFrRec, room);
        qemu_spin_lock(&w->lock);
    }
    status = femu_wb_collect(&w->t, nsid, tok, admin, &held);
    for (uint32_t i = 0; status && i < w->t.nr; i++) {
        const FemuWbFail *x = &w->t.fail[i];
        FemuFrRec *rec = &recs[nr];

        if (x->tok != tok) {
            continue;
        }
        *rec = femu_wbf_rec(n, &w->t.slot[x->slot], x->slot,
                            FEMU_FR_PHASE_REPORT, FEMU_FR_OUT_REPORTED);
        rec->cause = x->fail_id;
        rec->sqid = sqid;
        rec->cid = cid;
        rec->opc = opc;
        rec->nsid = x->nsid;
        rec->slba = x->page_slba;
        rec->nlb = x->lbas;
        rec->status = status;
        rec->found = femu_wbf_cur && x->found == femu_wbf_cur ?
                     FEMU_FR_FOUND_SELF : FEMU_FR_FOUND_PENDING;
        if (!nr) {
            lba = x->page_slba;
            fnsid = x->nsid;
            fslot = x->slot + 1;
        }
        nr++;
    }
    qemu_spin_unlock(&w->lock);
    for (uint32_t i = 0; i < nr; i++) {
        femu_fsched_put(n, &recs[i]);
    }
    if (!status) {
        return 0;
    }
    if (fnsid && nvme_ns(n, fnsid)) {
        csi = nvme_ns(n, fnsid)->csi;
    }
    /* an Admin entry keeps the namespace, block and slot too */
    nvme_set_error_info(n, sqid, cpu_to_le16(cid), status & ~NVME_DNR,
                        0xffff, lba, fnsid, fslot, opc, csi);
    *held_tok = held ? tok : 0;
    return status;
}

/* FTL thread: a draining I/O completion reports */
static void femu_wbf_report_io(FemuCtrl *n, NvmeRequest *req, bool lied)
{
    uint8_t opc = req->cmd.opcode;
    uint32_t nsid = le32_to_cpu(req->cmd.nsid);
    uint16_t sc = req->status & ~NVME_DNR;
    uint16_t status;
    uint64_t tok = 0;

    /* a lying Flush drains nothing; another command must have drained */
    if (opc == NVME_CMD_FLUSH ? lied : !n->wbf_drained) {
        return;
    }
    /* a command that failed for its own reason reports nothing */
    if (sc != NVME_SUCCESS && sc != NVME_CAP_EXCEEDED &&
        sc != NVME_WRITE_FAULT) {
        return;
    }
    if (opc == NVME_CMD_FLUSH && nsid == NVME_NSID_BROADCAST) {
        nsid = 0;
    }
    status = femu_wbf_collect(n, nsid, req->sq ? req->sq->sqid : 0,
                              le16_to_cpu(req->cmd.cid), opc, false, &tok);
    if (status) {
        req->status = status;
        req->wbf_tok = tok;
    }
}

/**
 * femu_wbf_posted - the CQE of @req reached the host
 * @n: the controller
 * @req: the completion, which holds report=once failures
 */
void femu_wbf_posted(FemuCtrl *n, NvmeRequest *req)
{
    struct FemuWbf *w = n->wbf;

    qemu_spin_lock(&w->lock);
    femu_wb_publish(&w->t, req->wbf_tok);
    qemu_spin_unlock(&w->lock);
    req->wbf_tok = 0;
}

/**
 * femu_wbf_dropped - the CQE of @req will never post
 * @n: the controller
 * @req: the completion, which holds report=once failures
 */
void femu_wbf_dropped(FemuCtrl *n, NvmeRequest *req)
{
    struct FemuWbf *w = n->wbf;

    /* unplug frees the schedule before the queues */
    if (!w) {
        req->wbf_tok = 0;
        return;
    }
    qemu_spin_lock(&w->lock);
    femu_wb_unreserve(&w->t, req->wbf_tok);
    qemu_spin_unlock(&w->lock);
    req->wbf_tok = 0;
}

/* an Admin drain of the namespace in CDW1 alone */
static bool femu_wbf_scoped(const NvmeCmd *cmd)
{
    if (cmd->opcode == NVME_ADM_CMD_FORMAT_NVM) {
        return true;
    }
    return cmd->opcode == NVME_ADM_CMD_SET_FEATURES &&
           (le32_to_cpu(cmd->cdw10) & 0xff) == NVME_NS_WRITE_PROTECT;
}

/**
 * femu_wbf_admin_begin - an Admin command starts on the main loop
 * @n: the controller, with a wb-fail line
 */
void femu_wbf_admin_begin(FemuCtrl *n)
{
    femu_wbf_cur = qatomic_fetch_inc(&n->wbf->seq) + 1;
}

/**
 * femu_wbf_admin_end - the status of an Admin command, after wb-fail
 * @n: the controller, with a wb-fail line
 * @cmd: the command
 * @status: what the command returned
 *
 * A drain that met a failure returns Write Fault. An Admin command says
 * Internal Error instead, with DNR under report=sticky. Its CQE
 * posts now, so report=once is spent at once.
 *
 * Returns the status to post.
 */
uint16_t femu_wbf_admin_end(FemuCtrl *n, const NvmeCmd *cmd, uint16_t status)
{
    struct FemuWbf *w = n->wbf;
    uint32_t nsid = le32_to_cpu(cmd->nsid);
    uint16_t got;
    uint64_t tok = 0;

    if ((status & ~NVME_DNR) == NVME_WRITE_FAULT) {
        /*
         * Format and Write Protect drain the namespace they name; the
         * rest, and FFFFFFFFh, drain all of them.
         */
        if (!femu_wbf_scoped(cmd) || nsid == NVME_NSID_BROADCAST) {
            nsid = 0;
        }
        got = femu_wbf_collect(n, nsid, 0, le16_to_cpu(cmd->cid),
                               cmd->opcode, true, &tok);
        status = got ? got : NVME_INTERNAL_DEV_ERROR;
        if (got && tok) {
            qemu_spin_lock(&w->lock);
            femu_wb_publish(&w->t, tok);
            qemu_spin_unlock(&w->lock);
        }
    }
    femu_wbf_cur = 0;
    return status;
}

/**
 * femu_wbf_reset - a Controller Reset ends every report
 * @n: the controller, with a wb-fail line
 *
 * The marks stay: their pages are still in the buffer.
 */
void femu_wbf_reset(FemuCtrl *n)
{
    struct FemuWbf *w = n->wbf;

    qemu_spin_lock(&w->lock);
    femu_wb_clear(&w->t, false);
    qemu_spin_unlock(&w->lock);
}

/**
 * femu_wbf_cut - a power cut starts or ends
 * @n: the controller, with a wb-fail line
 * @start: true before the PLP write-back, false after the rollback
 *
 * At the end no host is left to tell: every slot and report goes.
 */
void femu_wbf_cut(FemuCtrl *n, bool start)
{
    struct FemuWbf *w = n->wbf;

    qemu_spin_lock(&w->lock);
    w->cutting = start;
    if (!start) {
        femu_wb_clear(&w->t, true);
    }
    qemu_spin_unlock(&w->lock);
}

/*
 * The effect of line @i, which won its group on @req, seen as @v; @id
 * is its select record. The lies, wb-fail, hang and cfs are modelled:
 * each other case names what it will do, and its selection moves the
 * counters alone. Returns true when the FTL step must call
 * femu_fsched_post().
 */
static bool femu_fsched_act(FemuCtrl *n, NvmeRequest *req, int i,
                            const FemuFsView *v, uint64_t id)
{
    struct FemuFsched *f = n->fsched;
    const FemuFsLine *l = &f->l[i];

    switch (l->act) {
    case FEMU_FS_ACT_FUA_LIE:
    case FEMU_FS_ACT_FLUSH_LIE:
        /*
         * The FTL reads req->fs_lie: ssd_write() then takes the buffered
         * path though the command keeps its FUA bit. The data group has
         * one winner, so a command has one lie.
         */
        req->fs_lie = l->act;
        f->lie_line = i;
        f->lie_cause = id;
        f->lie_view = *v;
        return true;
    case FEMU_FS_ACT_WB_FAIL:
        femu_wbf_select(n, req, i, v, id);
        return true;
    case FEMU_FS_ACT_HANG:
        /* femu_fsched_match() sets req->fs_hang once the group is known */
        req->fs_line = l->line;
        req->fs_match = l->matched;
        req->fs_cause = id;
        return false;
    case FEMU_FS_ACT_CFS:
        /* the request is reused after a reclaim: keep what the line saw */
        f->park_line = i;
        f->park_match = l->matched;
        f->park_cause = id;
        f->park_view = *v;
        return false;
    case FEMU_FS_ACT_POWER_LOSS:    /* not modelled yet: a cut at pre */
    case FEMU_FS_ACT_WRITE_FAIL:    /* not modelled yet: Write Fault */
    case FEMU_FS_ACT_READ_UNC:      /* not modelled yet: Unrecovered Read */
    case FEMU_FS_ACT_SDC:           /* not modelled yet: sdc override */
    case FEMU_FS_ACT_DELAY:         /* not modelled yet: a later CQE */
    case FEMU_FS_ACT_SLOW:          /* not modelled yet: die-slow by BH */
    case FEMU_FS_ACT_ANA:           /* not modelled yet: ana-state by BH */
        return false;
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

/* one select record per line that selected @req; returns its id */
static uint64_t femu_fsched_record(FemuCtrl *n, NvmeRequest *req,
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

    return femu_fsched_put(n, &rec);
}

/*
 * The apply record of a lie, after the FTL ran it. It marks the buffered
 * pages that the lie left volatile and writes one record whose cause is
 * the select record: "done" with the pages, or "no-effect" with the
 * reason.
 */
static void femu_fsched_lie(FemuCtrl *n, NvmeRequest *req)
{
    struct FemuFsched *f = n->fsched;
    const FemuFsLine *l = &f->l[f->lie_line];
    const FemuFsView *v = &f->lie_view;
    uint8_t act = req->fs_lie;
    uint32_t pages;
    uint8_t why;
    FemuFrRec rec;

    /* the FTL call is over: no later code may take the request for a lie */
    req->fs_lie = 0;
    why = bbssd_lie_apply(req->ns, req, act, v->slba, v->nlb, &pages);
    rec = (FemuFrRec) {
        .cause = f->lie_cause,
        .step = f->step,
        .match = l->matched,
        .slba = v->slba,
        .nlb = v->nlb,
        .nsid = v->nsid,
        .line = l->line,
        .sqid = req->sq ? req->sq->sqid : 0,
        .cid = le16_to_cpu(req->cmd.cid),
        .origin = FEMU_FR_ORIGIN_SCHED_CMD,
        .phase = FEMU_FR_PHASE_APPLY,
        .act = act,
        .outcome = why == FEMU_FS_WHY_NONE ? FEMU_FR_OUT_DONE :
                                             FEMU_FR_OUT_NO_EFFECT,
        .why = why,
        .opc = v->opc,
        .fua = v->fua,
        .pages = pages,
    };

    femu_fsched_put(n, &rec);
}

/**
 * femu_fsched_post - the FTL ran a command that femu_fsched_step() saw
 * @n: the controller, with command lines
 * @req: the command
 * @report: a wb-fail failure may fail @req; false for a fused pair
 *
 * Runs on the FTL thread, in the step of @req, after the FTL call and
 * before the CQE. It writes the apply record of a lie or a wb-fail, then
 * lets a draining command report a failed write-back.
 */
void femu_fsched_post(FemuCtrl *n, NvmeRequest *req, bool report)
{
    bool lied = req->fs_lie == FEMU_FS_ACT_FLUSH_LIE;

    if (req->fs_lie) {
        femu_fsched_lie(n, req);
    }
    if (n->wbf) {
        if (n->fsched->wbf_sel) {
            femu_wbf_apply(n, req);
        }
        /* a hung command never posts, so it reports nothing */
        if (report && !req->fs_hang) {
            femu_wbf_report_io(n, req, lied);
        }
        femu_wbf_cur = 0;
    }
}

/*
 * Match @req against the command lines. The view comes from the SQE copy
 * and the namespace, never from fields the FTL or nvme_power_io() fill
 * later. A command outside the matchable set, or one that fails the view
 * checks, counts for no line. Each command counts as one step, matched
 * or not. Returns true when a line needs femu_fsched_post().
 */
static bool femu_fsched_match(FemuCtrl *n, NvmeRequest *req)
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
    bool lie = false;

    qatomic_set(&f->step, f->step + 1);
    if (!qatomic_read(&f->running)) {
        return false;
    }
    switch (v.opc) {
    case NVME_CMD_FLUSH:
        if (v.nsid != NVME_NSID_BROADCAST && !nvme_ns(n, v.nsid)) {
            return false;
        }
        break;
    case NVME_CMD_READ:
    case NVME_CMD_WRITE:
    case NVME_CMD_WRITE_ZEROES:
        ns = nvme_ns(n, v.nsid);
        if (!ns) {
            return false;
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
        return false;
    }
    /* as nvme_check_mdts(): in the minimum page size, not the CC one */
    if (n->mdts) {
        mdts = 12 + NVME_CAP_MPSMIN(n->bar.cap) + n->mdts;
    }
    if (!femu_fs_view_ok(&v, nsze, lbads, xfer_ms, mdts)) {
        return false;
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
        uint64_t id;

        if (f->out[i] == FEMU_FS_OUT_NONE) {
            continue;
        }
        id = femu_fsched_record(n, req, &v, i);
        if (f->out[i] == FEMU_FS_OUT_APPLIED) {
            lie |= femu_fsched_act(n, req, i, &v, id);
        }
    }
    /*
     * A hang lets the command run, and its poller then holds it. A cfs
     * parks it before it runs. A power-loss is not modelled yet.
     */
    switch (femu_fs_terminal(f->l, f->nr, f->out)) {
    case FEMU_FS_ACT_HANG:
        req->fs_hang = 1;
        break;
    case FEMU_FS_ACT_CFS:
        f->cfs_sel = true;
        break;
    }
    return lie;
}

/*
 * FTL thread: a cfs holds @req before it runs. With power_loss the
 * poller applied no data, so the command changes nothing. The FTL takes
 * no request while one is parked; the BH stops the controller.
 */
static void femu_fsched_park(FemuCtrl *n, NvmeRequest *req)
{
    struct FemuFsched *f = n->fsched;

    f->park_sqid = req->sq ? req->sq->sqid : 0;
    f->park_cid = le16_to_cpu(req->cmd.cid);
    qatomic_set(&f->cfs_gen, qatomic_read(&f->gen));
    qatomic_store_release(&n->fs_parked, req);
    qemu_bh_schedule(f->cfs_bh);
}

/**
 * femu_fsched_step - match one command against the command lines
 * @n: the controller, with command lines
 * @req: the request just taken from a to_ftl ring, not yet run
 *
 * Runs on the FTL thread only. With a wb-fail line every command is a
 * possible drain, so each step gets a stamp and a femu_fsched_post().
 *
 * Returns FEMU_FS_STEP_PARK when a cfs holds @req: the caller runs
 * nothing, and takes no request until the park ends. Returns
 * FEMU_FS_STEP_POST when the caller must run femu_fsched_post() right
 * after the FTL call, else FEMU_FS_STEP_RUN.
 */
int femu_fsched_step(FemuCtrl *n, NvmeRequest *req)
{
    struct FemuFsched *f = n->fsched;
    bool post = femu_fsched_match(n, req);

    if (unlikely(f->cfs_sel)) {
        f->cfs_sel = false;
        femu_wbf_cur = 0;
        femu_fsched_park(n, req);
        return FEMU_FS_STEP_PARK;
    }
    if (unlikely(n->wbf)) {
        n->wbf_drained = false;
        femu_wbf_cur = qatomic_fetch_inc(&n->wbf->seq) + 1;
        return FEMU_FS_STEP_POST;
    }
    return post ? FEMU_FS_STEP_POST : FEMU_FS_STEP_RUN;
}

/*
 * hang and cfs. A hang lets its command run in the FTL, then the poller
 * keeps it on a list of its own in place of the pqueue: no CQE. A cfs
 * parks its command before it runs, and a BH sets CSTS.CFS and leaves
 * the dataplane stopped. Each command goes back on a reclaim.
 *
 *   hang: FTL step --> poller: fs_hung[p], apply record, x-fault-hung++
 *   cfs:  FTL step --> fs_parked, cfs_bh --> pause, CSTS.CFS, apply record
 *   reclaim: Delete SQ (its commands), Controller Reset, shutdown, power
 *            cut, unplug (all) --> SQ request list, reclaim record
 *
 * An Abort finds no hung command in its SQ, so it is not performed. A
 * hung command reports no wb-fail failure: its CQE never posts, so the
 * failure stays pending for the next draining completion.
 */

/* the fields of @cmd that a record names, as a line saw them */
static FemuFsView femu_fsched_cmd_view(const NvmeCmd *cmd)
{
    const NvmeRwCmd *rw = (const NvmeRwCmd *)cmd;
    FemuFsView v = {
        .opc = cmd->opcode,
        .nsid = le32_to_cpu(cmd->nsid),
    };

    if (v.opc != NVME_CMD_FLUSH) {
        v.slba = le64_to_cpu(rw->slba);
        v.nlb = le16_to_cpu(rw->nlb) + 1;
        v.fua = v.opc == NVME_CMD_WRITE &&
                (le16_to_cpu(rw->control) & NVME_RW_FUA);
    }
    return v;
}

/* a record of the hung command @req */
static FemuFrRec femu_fsched_hang_rec(FemuCtrl *n, NvmeRequest *req,
                                      uint8_t phase, uint8_t outcome)
{
    FemuFsView v = femu_fsched_cmd_view(&req->cmd);

    return (FemuFrRec) {
        .cause = req->fs_cause,
        .step = qatomic_read(&n->fsched->step),
        .match = req->fs_match,
        .slba = v.slba,
        .nlb = v.nlb,
        .nsid = v.nsid,
        .line = req->fs_line,
        .sqid = req->sq ? req->sq->sqid : 0,
        .cid = le16_to_cpu(req->cmd.cid),
        .origin = FEMU_FR_ORIGIN_SCHED_CMD,
        .phase = phase,
        .act = FEMU_FS_ACT_HANG,
        .outcome = outcome,
        .opc = v.opc,
        .fua = v.fua,
    };
}

/* a record of the parked command */
static FemuFrRec femu_fsched_park_rec(FemuCtrl *n, uint8_t phase,
                                      uint8_t outcome)
{
    struct FemuFsched *f = n->fsched;

    return (FemuFrRec) {
        .cause = f->park_cause,
        .step = qatomic_read(&f->step),
        .match = f->park_match,
        .slba = f->park_view.slba,
        .nlb = f->park_view.nlb,
        .nsid = f->park_view.nsid,
        .line = f->l[f->park_line].line,
        .sqid = f->park_sqid,
        .cid = f->park_cid,
        .origin = FEMU_FR_ORIGIN_SCHED_CMD,
        .phase = phase,
        .act = FEMU_FS_ACT_CFS,
        .outcome = outcome,
        .opc = f->park_view.opc,
        .fua = f->park_view.fua,
    };
}

/**
 * femu_fsched_hang - a poller holds a command that a hang selected
 * @n: the controller, with command lines
 * @poller: the poller, from 1
 * @req: the command, back from its FTL step
 *
 * The command did its work, so its ranges go back and other commands on
 * the same blocks run. Only its CQE is withheld, an error status too.
 * The apply record carries that status.
 */
void femu_fsched_hang(FemuCtrl *n, int poller, NvmeRequest *req)
{
    FemuFrRec rec = femu_fsched_hang_rec(n, req, FEMU_FR_PHASE_APPLY,
                                         FEMU_FR_OUT_DONE);

    req->fs_hang = 0;
    rec.status = req->status;
    nvme_req_release_ranges(req);
    QTAILQ_INSERT_TAIL(&n->fs_hung[poller], req, entry);
    qatomic_inc(&n->fault_hung);
    femu_fsched_put(n, &rec);
}

/*
 * A hung request of @sq (NULL: any) that waits in to_poller[@p] has not
 * reached its poller yet. Hold it now, so the reclaim below gives it back
 * with its apply and reclaim records, as if the poller had seen it.
 */
static void femu_fsched_hang_ring(FemuCtrl *n, int p, NvmeSQueue *sq)
{
    struct rte_ring *r = n->to_poller ? n->to_poller[p] : NULL;
    size_t count = r ? femu_ring_count(r) : 0;
    NvmeRequest *req;

    for (size_t i = 0; i < count; i++) {
        if (femu_ring_dequeue(r, (void **)&req, 1) != 1) {
            break;
        }
        if (req->fs_hang && (!sq || req->sq == sq)) {
            femu_fsched_hang(n, p, req);
            continue;
        }
        /* one rotation keeps the order of the others */
        femu_ring_enqueue(r, (void **)&req, 1);
    }
}

/* main loop: CSTS.CFS for the parked command, unless its park ended */
static void femu_fsched_cfs_bh(void *opaque)
{
    FemuCtrl *n = opaque;
    struct FemuFsched *f = n->fsched;
    uint32_t g = qatomic_read(&f->cfs_gen);
    FemuFrRec rec;

    if (qatomic_read(&n->test_fs_bh_hold)) {
        f->bh_held = true;
        return;
    }
    /* a reclaim or a controller clear came first */
    if (!g || g != qatomic_read(&f->gen)) {
        return;
    }
    qatomic_set(&f->cfs_gen, 0);
    /*
     * The controller stops here, and nothing resumes it: a Controller
     * Reset clears the state, and the next enable starts the dataplane.
     * Command lines refuse a shared subsystem, so this pauses one
     * controller. The pause has no deadline: the FTL thread is out of
     * its sweep while a command is parked, and each poller ends its
     * sweep in bounded time.
     */
    nvme_pause_pollers(n);
    n->fs_cfs = true;
    n->bar.csts |= NVME_CSTS_FAILED;
    rec = femu_fsched_park_rec(n, FEMU_FR_PHASE_APPLY, FEMU_FR_OUT_DONE);
    femu_fsched_put(n, &rec);
}

/**
 * femu_fsched_reclaim - give back the commands a hang or a cfs holds
 * @n: the controller, with its dataplane paused or its threads stopped
 * @sq: only the commands of this queue; NULL for all, a controller clear
 * @why: the path, a FEMU_FS_WHY_* reclaim reason
 *
 * Each command goes back to its SQ request list with no CQE and writes a
 * reclaim record. A controller clear also ends the CSTS.CFS of a cfs,
 * and with a reclaimed park it makes a pending cfs BH a no-op.
 */
void femu_fsched_reclaim(FemuCtrl *n, NvmeSQueue *sq, uint8_t why)
{
    struct FemuFsched *f = n->fsched;
    NvmeRequest *req = n->fs_parked;
    NvmeRequest *next;
    FemuFrRec rec;

    if (req && (!sq || req->sq == sq)) {
        qatomic_set(&n->fs_parked, NULL);
        /* as a drop from to_ftl: the FTL never saw what it may have put */
        n->persist_torn = true;
        /* the FTL step that would free these never runs */
        nvme_eol_release(req);
        g_clear_pointer(&req->write_data, g_free);
        QTAILQ_INSERT_TAIL(&req->sq->req_list, req, entry);
        rec = femu_fsched_park_rec(n, FEMU_FR_PHASE_RECLAIM,
                                   FEMU_FR_OUT_RECLAIMED);
        rec.why = why;
        femu_fsched_put(n, &rec);
        femu_fsched_gen_next(f);
    }
    if (!sq) {
        n->fs_cfs = false;
        femu_fsched_gen_next(f);
    }
    for (int p = 1; n->fs_hung && p <= (int)n->nr_pollers; p++) {
        femu_fsched_hang_ring(n, p, sq);
        QTAILQ_FOREACH_SAFE(req, &n->fs_hung[p], entry, next) {
            if (sq && req->sq != sq) {
                continue;
            }
            QTAILQ_REMOVE(&n->fs_hung[p], req, entry);
            QTAILQ_INSERT_TAIL(&req->sq->req_list, req, entry);
            qatomic_dec(&n->fault_hung);
            rec = femu_fsched_hang_rec(n, req, FEMU_FR_PHASE_RECLAIM,
                                       FEMU_FR_OUT_RECLAIMED);
            rec.why = why;
            femu_fsched_put(n, &rec);
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

/*
 * x-fault-bh-hold (qtest): while set, a cfs BH that runs does nothing
 * but note it. Clearing it schedules the BH again, so a test can put a
 * reset or a queue deletion between the park and the BH.
 */
static void femu_fsched_test_bh_hold_get(Object *obj, Visitor *v,
                                         const char *name, void *opaque,
                                         Error **errp)
{
    uint32_t hold = qatomic_read(&FEMU(obj)->test_fs_bh_hold);

    visit_type_uint32(v, name, &hold, errp);
}

static void femu_fsched_test_bh_hold_set(Object *obj, Visitor *v,
                                         const char *name, void *opaque,
                                         Error **errp)
{
    FemuCtrl *n = FEMU(obj);
    struct FemuFsched *f = n->fsched;
    uint32_t hold;

    if (!visit_type_uint32(v, name, &hold, errp)) {
        return;
    }
    if (!f || !f->cfs_bh) {
        error_setg(errp, "x-fault-bh-hold needs a cfs line in events_file");
        return;
    }
    qatomic_set(&n->test_fs_bh_hold, hold);
    if (!hold && f->bh_held) {
        f->bh_held = false;
        qemu_bh_schedule(f->cfs_bh);
    }
}

/* x-fault-parked (qtest): true while a cfs holds a command */
static bool femu_fsched_test_parked(Object *obj, Error **errp)
{
    return qatomic_read(&FEMU(obj)->fs_parked) != NULL;
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
    /* buffered pages with the lie mark that power cuts rolled back */
    object_property_add_uint64_ptr(obj, "x-fault-lie-lost",
                                   &n->fault_lie_lost, OBJ_PROP_FLAG_READ);
    /* AERs that wb-fail queued: a host reset can drop them unseen */
    object_property_add_uint64_ptr(obj, "x-fault-wbf-aer",
                                   &n->fault_wbf_aer, OBJ_PROP_FLAG_READ);
    object_property_add(obj, "x-fault-draw", "uint64",
                        femu_fsched_test_draw_get, femu_fsched_test_draw_set,
                        NULL, NULL);
    object_property_add(obj, "x-fault-log-hold", "bool",
                        femu_fsched_test_log_hold_get,
                        femu_fsched_test_log_hold_set, NULL, NULL);
    /* requests that a hang holds now; a reclaim takes it back to 0 */
    object_property_add_uint64_ptr(obj, "x-fault-hung", &n->fault_hung,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_bool(obj, "x-fault-parked", femu_fsched_test_parked,
                             NULL);
    object_property_add(obj, "x-fault-bh-hold", "uint32",
                        femu_fsched_test_bh_hold_get,
                        femu_fsched_test_bh_hold_set, NULL, NULL);
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
        if (r->outcome == FEMU_FR_OUT_NO_EFFECT ||
            r->outcome == FEMU_FR_OUT_RECLAIMED) {
            e->reason = g_strdup(femu_fr_name_why(r->why));
        }
        e->has_status = r->status != 0;
        e->status = r->status;
        if (r->phase == FEMU_FR_PHASE_APPLY &&
            r->outcome == FEMU_FR_OUT_DONE &&
            (r->act == FEMU_FS_ACT_FLUSH_LIE ||
             r->act == FEMU_FS_ACT_FUA_LIE)) {
            if (r->act == FEMU_FS_ACT_FLUSH_LIE) {
                e->has_buffered_at_flush_lie = true;
                e->buffered_at_flush_lie = r->pages;
            } else {
                e->has_lie_pages = true;
                e->lie_pages = r->pages;
            }
        }
        if (r->act == FEMU_FS_ACT_WB_FAIL && r->fslot) {
            e->has_slot = true;
            e->slot = r->fslot;
            if (r->phase == FEMU_FR_PHASE_APPLY) {
                e->has_pages = true;
                e->pages = r->pages;
            }
            if (r->phase == FEMU_FR_PHASE_FAIL) {
                e->has_lba_mask = true;
                e->lba_mask = r->lba_mask;
                e->has_lost = true;
                e->lost = r->lost;
            }
            if (r->found) {
                e->found = g_strdup(femu_fr_name_found(r->found));
            }
        }
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
