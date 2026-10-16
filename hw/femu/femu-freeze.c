/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "qemu/error-report.h"
#include "qemu/main-loop.h"
#include "qemu/seqlock.h"
#include "qemu/thread.h"
#include "qemu/timer.h"
#include "hw/core/cpu.h"
#include "exec/icount.h"
#include "system/cpus.h"
#include "system/cpu-timers.h"
#include "system/kvm.h"
#include "system/qtest.h"
#include "system/reset.h"
#include "system/runstate.h"
#include "femu-freeze.h"

/*
 * One service for the whole process: two devices that each stopped and
 * restarted the guest would restore each other's clocks.
 *
 * The lock guards what the workers share with the main loop. It is a leaf:
 * nothing else is taken while it is held, and it is never held across
 * pause_all_vcpus(), which drops the BQL while it waits. The rest belongs
 * to the main loop and the BQL; the seqlock lets the I/O threads read the
 * device clock without a lock.
 */
static struct {
    QemuMutex lock;
    QemuCond cond;
    uint32_t users;     /* begin calls not yet ended */
    uint64_t asked;     /* the id of the last begin call */
    uint64_t served;    /* begin calls up to this id are answered */
    uint32_t max_ms;    /* the smallest limit among the users of a stop */
    bool expired;       /* a stop hit its limit; none until users drops to 0 */
    FemuFreezeStats st;

    /* written by the main loop only */
    bool ready;
    bool kvm;           /* the device clock is the raw clock less hidden */
    bool frozen;
    bool spoiled;       /* the guest may have run during the stop */
    bool vm_stopped;    /* the device clock stands for a VM stop */
    bool broken;        /* the guest clocks disagree; never resume */
    int ncpus;
    QemuSeqLock seq;
    int64_t frozen_at;  /* raw clock when the device clock stopped; or 0 */
    int64_t hidden;     /* the span of every stop so far */
    QEMUBH *bh;
    QEMUTimer *limit;
    int64_t start_ms;   /* REALTIME when the stop began */
    Notifier suspend;
    Notifier wakeup;
} fz;

/*
 * The kvmclock counts host TSC cycles, at the rate of the raw monotonic
 * clock. Hide spans of it from the raw clock, so the device clock and the
 * guest clock run at one rate and never move apart.
 */
static int64_t femu_freeze_raw(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return ts.tv_sec * NANOSECONDS_PER_SECOND + ts.tv_nsec;
}

int64_t femu_freeze_now(void)
{
    int64_t now;
    unsigned seq;

    if (!fz.kvm) {
        return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    }
    /* sample the raw clock inside the retry, so a stop in between counts */
    do {
        seq = seqlock_read_begin(&fz.seq);
        now = (fz.frozen_at ? fz.frozen_at : femu_freeze_raw()) - fz.hidden;
    } while (seqlock_read_retry(&fz.seq, seq));
    return now;
}

/* stop the device clock where it stands; main loop, BQL held */
static void femu_freeze_clock_stop(void)
{
    seqlock_write_begin(&fz.seq);
    if (!fz.frozen_at) {
        fz.frozen_at = femu_freeze_raw();
    }
    seqlock_write_end(&fz.seq);
}

/*
 * Run the device clock again, with @span of the stop hidden. The rest of
 * the stop shows, so the clock never steps back.
 */
static void femu_freeze_clock_start(int64_t span)
{
    seqlock_write_begin(&fz.seq);
    if (fz.frozen_at) {
        fz.hidden += MIN(span, femu_freeze_raw() - fz.frozen_at);
        fz.frozen_at = 0;
    }
    seqlock_write_end(&fz.seq);
}

/* the counts are read by other threads, so they change under the lock */
static void femu_freeze_count(uint64_t *count)
{
    qemu_mutex_lock(&fz.lock);
    (*count)++;
    qemu_mutex_unlock(&fz.lock);
}

static int femu_freeze_vcpus(bool *all_stopped)
{
    CPUState *cpu;
    int n = 0;

    *all_stopped = true;
    CPU_FOREACH(cpu) {
        *all_stopped &= cpu->stopped;
        n++;
    }
    return n;
}

static void femu_freeze_stop(uint32_t max_ms)
{
    bool stopped;

    if (fz.broken || !runstate_is_running()) {
        femu_freeze_count(&fz.st.skipped);
        return;
    }
    pause_all_vcpus();
    /* the BQL was dropped while the vCPUs stopped; a VM stop may have won */
    if (!runstate_is_running()) {
        femu_freeze_count(&fz.st.skipped);
        return;
    }
    femu_freeze_clock_stop();
    if (femu_freeze_kvm_save() < 0) {
        femu_freeze_clock_start(0);
        resume_all_vcpus();
        femu_freeze_count(&fz.st.skipped);
        return;
    }
    cpu_disable_ticks();
    fz.ncpus = femu_freeze_vcpus(&stopped);
    fz.frozen = true;
    fz.spoiled = false;
    femu_freeze_count(&fz.st.freezes);
    fz.start_ms = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
    timer_mod(fz.limit, fz.start_ms + max_ms);
}

/*
 * End the stop. Hide its span only if the guest cannot have run since. A
 * reset, a wakeup, a hot plug or another pauser may have resumed the
 * vCPUs; a VM stop or a suspend that follows can then stop them again,
 * so those mark the stop spoiled too.
 */
static void femu_freeze_thaw(void)
{
    uint64_t span = 0;
    bool stopped;
    int ret = -1;

    timer_del(fz.limit);
    fz.frozen = false;
    if (!fz.spoiled && runstate_is_running() &&
        femu_freeze_vcpus(&stopped) == fz.ncpus && stopped) {
        ret = femu_freeze_kvm_restore(&span);
    }
    femu_freeze_clock_start(ret == 0 ? span : 0);
    femu_freeze_count(ret == 0 ? &fz.st.thaws : &fz.st.lost);

    if (ret == FEMU_FREEZE_KVM_FATAL) {
        /*
         * The vCPUs disagree on the time; they must not run again. Stop
         * the VM here, on the main loop, so no callback that runs first
         * can resume them while the run state still says running.
         */
        error_report("femu: csd_pause could not restore the guest clocks; "
                     "stopping the VM");
        fz.broken = true;
        vm_stop(RUN_STATE_INTERNAL_ERROR);
        return;
    }
    cpu_enable_ticks();
    resume_all_vcpus();
}

/* Move the guest to the state the users ask for, and answer them. */
static void femu_freeze_bh(void *opaque)
{
    uint64_t upto;
    uint32_t max_ms;
    bool want;

    qemu_mutex_lock(&fz.lock);
    upto = fz.asked;
    want = fz.users && !fz.expired;
    max_ms = fz.max_ms;
    qemu_mutex_unlock(&fz.lock);

    if (want && !fz.frozen) {
        femu_freeze_stop(max_ms);
    } else if (want) {
        /* a user that joined a stop may bring a shorter limit */
        if (timer_expire_time_ns(fz.limit) >
            (fz.start_ms + max_ms) * SCALE_MS) {
            timer_mod(fz.limit, fz.start_ms + max_ms);
        }
    } else if (fz.frozen) {
        femu_freeze_thaw();
    }

    qemu_mutex_lock(&fz.lock);
    fz.served = MAX(fz.served, upto);
    qemu_cond_broadcast(&fz.cond);
    qemu_mutex_unlock(&fz.lock);
}

static void femu_freeze_limit(void *opaque)
{
    /* a limit hit after the last user left must not hold up the next one */
    qemu_mutex_lock(&fz.lock);
    if (fz.users) {
        fz.expired = true;
    }
    fz.st.expired++;
    qemu_mutex_unlock(&fz.lock);
    warn_report_once("femu: a program ran past csd_pause_max_ms; the guest "
                     "runs again and sees the rest of its host time");
    if (fz.frozen) {
        femu_freeze_thaw();
    }
}

/*
 * Runs before the kvmclock handler when the VM stops, through a higher
 * priority, so it acts before that handler saves the kvmclock.
 *
 * A stop during a freeze ends it with no clock step: the guest may have run
 * before this stop, so its span shows. The ticks and vCPUs stay stopped for
 * the VM stop. The device clock then stands for the stop, as the kvmclock
 * does, and runs again at the start.
 */
static void femu_freeze_vm_state(void *opaque, bool running, RunState state)
{
    uint32_t users;

    if (!running) {
        if (fz.frozen) {
            timer_del(fz.limit);
            fz.frozen = false;
            femu_freeze_clock_start(0);
            femu_freeze_count(&fz.st.lost);
        }
        femu_freeze_clock_stop();
        fz.vm_stopped = true;
        return;
    }
    if (fz.vm_stopped) {
        fz.vm_stopped = false;
        femu_freeze_clock_start(INT64_MAX);
    }
    /* a run that began while the VM was stopped is still going */
    qemu_mutex_lock(&fz.lock);
    users = fz.users;
    qemu_mutex_unlock(&fz.lock);
    if (users) {
        qemu_bh_schedule(fz.bh);
    }
}

static void femu_freeze_reset(void *opaque)
{
    if (fz.frozen) {
        fz.spoiled = true;
    }
}

static void femu_freeze_suspend(Notifier *notifier, void *data)
{
    femu_freeze_reset(NULL);
}

/* a wakeup resumes the vCPUs with no VM start, so ask for a freeze here */
static void femu_freeze_wakeup(Notifier *notifier, void *data)
{
    femu_freeze_vm_state(NULL, true, RUN_STATE_RUNNING);
}

bool femu_freeze_init(Error **errp)
{
    if (!kvm_enabled() && !qtest_enabled()) {
        error_setg(errp, "csd_pause needs KVM");
        return false;
    }
    if (icount_enabled()) {
        error_setg(errp, "csd_pause does not support icount");
        return false;
    }
    if (!femu_freeze_kvm_check(errp)) {
        return false;
    }
    if (fz.ready) {
        return true;
    }
    qemu_mutex_init(&fz.lock);
    qemu_cond_init(&fz.cond);
    seqlock_init(&fz.seq);
    fz.kvm = kvm_enabled();
    fz.bh = qemu_bh_new(femu_freeze_bh, NULL);
    fz.limit = timer_new_ms(QEMU_CLOCK_REALTIME, femu_freeze_limit, NULL);
    qemu_add_vm_change_state_handler_prio(femu_freeze_vm_state, NULL, 1);
    qemu_register_reset(femu_freeze_reset, NULL);
    fz.suspend.notify = femu_freeze_suspend;
    qemu_register_suspend_notifier(&fz.suspend);
    fz.wakeup.notify = femu_freeze_wakeup;
    qemu_register_wakeup_notifier(&fz.wakeup);
    fz.ready = true;
    return true;
}

bool femu_freeze_begin(const bool *cancel, uint32_t max_ms)
{
    uint64_t id;
    bool granted;

    qemu_mutex_lock(&fz.lock);
    fz.max_ms = fz.users ? MIN(fz.max_ms, max_ms) : max_ms;
    fz.users++;
    id = ++fz.asked;
    qemu_bh_schedule(fz.bh);
    /*
     * The canceller sets *cancel, then takes this lock to wake us. We test
     * it under the lock before each wait, so the wake cannot fall between.
     */
    while (fz.served < id && !qatomic_read(cancel)) {
        qemu_cond_wait(&fz.cond, &fz.lock);
    }
    /* a cancel wins over an answer that came at the same time */
    granted = !qatomic_read(cancel);
    qemu_mutex_unlock(&fz.lock);
    return granted;
}

void femu_freeze_end(void)
{
    qemu_mutex_lock(&fz.lock);
    assert(fz.users);
    if (!--fz.users) {
        /* the next run may stop the guest again, after a time limit */
        fz.expired = false;
        qemu_bh_schedule(fz.bh);
    }
    qemu_mutex_unlock(&fz.lock);
}

void femu_freeze_kick(void)
{
    if (!fz.ready) {
        return;
    }
    qemu_mutex_lock(&fz.lock);
    qemu_cond_broadcast(&fz.cond);
    qemu_mutex_unlock(&fz.lock);
}

void femu_freeze_stats(FemuFreezeStats *stats)
{
    if (!fz.ready) {
        memset(stats, 0, sizeof(*stats));
        return;
    }
    qemu_mutex_lock(&fz.lock);
    *stats = fz.st;
    stats->users = fz.users;
    qemu_mutex_unlock(&fz.lock);
}
