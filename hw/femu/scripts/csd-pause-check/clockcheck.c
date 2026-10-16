/*
 * Guest side of the csd_pause check: watch the guest clocks while freezes
 * run.
 *
 * - One reader on each vCPU but the first and the last switches between
 *   the vDSO and the syscall for CLOCK_MONOTONIC, and counts each step
 *   back. vCPU 0 stays idle, so it halts: the vDSO then reads its old
 *   pvclock page. The last vCPU is left to the sleeper and to csdlat.
 * - The sleeper asks for 1 ms sleeps and counts each sleep that ends
 *   early.
 * - At the end, the TSC time and the MONOTONIC time since the start must
 *   agree: a freeze that hid one and not the other leaves a gap.
 *
 * Usage: clockcheck SECONDS
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <x86intrin.h>

static volatile int stop;

static uint64_t mono(int sys)
{
    struct timespec ts;

    if (sys) {
        syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &ts);
    } else {
        clock_gettime(CLOCK_MONOTONIC, &ts);
    }
    return ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

typedef struct Reader {
    int cpu;
    uint64_t reads;
    uint64_t back;
    int64_t worst;
} Reader;

static void *reader(void *opaque)
{
    Reader *r = opaque;
    cpu_set_t set;
    uint64_t last = 0;
    uint64_t now;
    uint64_t i = 0;

    CPU_ZERO(&set);
    CPU_SET(r->cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
    while (!stop) {
        now = mono((i++ >> 4) & 1);
        if (now < last) {
            r->back++;
            if ((int64_t)(now - last) < r->worst) {
                r->worst = now - last;
            }
        }
        last = now;
        r->reads++;
    }
    return NULL;
}

static uint64_t sleeps;
static uint64_t early;

static void *sleeper(void *opaque)
{
    struct timespec ts = { 0, 1000000 };
    int cpu = *(int *)opaque;
    cpu_set_t set;
    uint64_t t;

    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
    while (!stop) {
        t = mono(1);
        nanosleep(&ts, NULL);
        if (mono(1) - t < 1000000) {
            early++;
        }
        sleeps++;
    }
    return NULL;
}

int main(int argc, char **argv)
{
    int secs = argc > 1 ? atoi(argv[1]) : 30;
    int n = sysconf(_SC_NPROCESSORS_ONLN);
    pthread_t th[64];
    pthread_t sl;
    Reader r[64] = { 0 };
    struct timespec cal = { 0, 200000000 };
    uint64_t m0, m1, t0, t1, c0, c1, back = 0, reads = 0;
    double khz, tsc_ms, mono_ms;
    int64_t worst = 0;
    cpu_set_t set;
    int last;
    int nr;
    int i;

    c0 = mono(1);
    t0 = __rdtsc();
    nanosleep(&cal, NULL);
    c1 = mono(1);
    t1 = __rdtsc();
    khz = (double)(t1 - t0) / ((c1 - c0) / 1e6);

    m0 = mono(1);
    t0 = __rdtsc();
    /* keep the main thread and its children off vCPU 0 */
    last = n > 1 ? n - 1 : 0;
    CPU_ZERO(&set);
    CPU_SET(last, &set);
    sched_setaffinity(0, sizeof(set), &set);
    nr = n > 2 ? n - 1 : n;
    for (i = 1; i < nr && i < 64; i++) {
        r[i].cpu = i;
        pthread_create(&th[i], NULL, reader, &r[i]);
    }
    pthread_create(&sl, NULL, sleeper, &last);
    sleep(secs);
    stop = 1;
    for (i = 1; i < nr && i < 64; i++) {
        pthread_join(th[i], NULL);
        back += r[i].back;
        reads += r[i].reads;
        if (r[i].worst < worst) {
            worst = r[i].worst;
        }
    }
    pthread_join(sl, NULL);
    m1 = mono(1);
    t1 = __rdtsc();
    tsc_ms = (t1 - t0) / khz;
    mono_ms = (m1 - m0) / 1e6;
    printf("CLOCKCHECK readers=%d reads=%llu back=%llu worst_back_ns=%lld "
           "sleeps=%llu early=%llu tsc_ms=%.3f mono_ms=%.3f diff_us=%.1f\n",
           nr - 1, (unsigned long long)reads, (unsigned long long)back,
           (long long)worst, (unsigned long long)sleeps,
           (unsigned long long)early, tsc_ms, mono_ms,
           (tsc_ms - mono_ms) * 1e3);
    return 0;
}
