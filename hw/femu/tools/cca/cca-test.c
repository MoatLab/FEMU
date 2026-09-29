/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Guest self-test for the femu-cxl-ssd caching API. Run as root on an
 * x86-64 guest with the memdev's region in devdax mode:
 *
 *   cca-test [-d mem0] [-x dax0.0] [CASE...]
 *
 * Cases: info nop query thrash invalidate disable errors threads crash,
 * plus before-reboot and after-reboot, which a runner calls around a
 * guest reboot. With no case, all but the reboot pair run. Each case
 * prints PASS, FAIL or SKIP; the exit status is 1 if any failed.
 * "CCA-MARK" lines let a host runner read its counters between steps.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "cca.h"

#define PAGE            4096u
#define SAMPLES         101
#define THREADS         8
#define THREAD_CMDS     100000u
#define MAP_LIMIT       (1ull << 30)

static const char *dev_name;
static const char *dax_name;
static struct cca_dev *dev;
static struct cca_info info;
static uint8_t *map;
static size_t map_len;
static int failures;

#define CHECK(cond, ...) do { \
    if (!(cond)) { \
        printf("  check failed at line %d: %s: ", __LINE__, #cond); \
        printf(__VA_ARGS__); \
        printf("\n"); \
        return -1; \
    } \
} while (0)

static void mark(const char *what)
{
    printf("CCA-MARK %s\n", what);
    fflush(stdout);
}

/* Single loads and stores the compiler may not merge or drop. */
static uint64_t peek(const void *p)
{
    return __atomic_load_n((const uint64_t *)p, __ATOMIC_RELAXED);
}

static void poke(void *p, uint64_t value)
{
    __atomic_store_n((uint64_t *)p, value, __ATOMIC_RELAXED);
}

static uint64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000u + ts.tv_nsec;
}

/*
 * Where KVM emulates the access (no direct mapping), CLFLUSH reads its
 * operand from the device, so flushing a dropped page already misses.
 */
static void flush_line(const void *p)
{
    __builtin_ia32_clflush(p);
    __builtin_ia32_mfence();
}

/* One timed load; the caller has flushed the line from the CPU cache. */
static uint64_t timed_load_ns(const void *p)
{
    uint64_t start;
    uint64_t value;

    start = now_ns();
    value = __atomic_load_n((const uint64_t *)p, __ATOMIC_RELAXED);
    __builtin_ia32_mfence();
    (void)value;
    return now_ns() - start;
}

/* One load from memory, not from the CPU cache. */
static uint64_t load_ns(const void *p)
{
    flush_line(p);
    return timed_load_ns(p);
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;

    return x < y ? -1 : x > y;
}

static uint64_t median(uint64_t *v, unsigned n)
{
    qsort(v, n, sizeof(*v), cmp_u64);
    return v[n / 2];
}

static uint64_t lpn_of(const void *p)
{
    uint64_t lpn = UINT64_MAX;

    cca_lpn_of(dev, p, &lpn);
    return lpn;
}

static int map_dax(void)
{
    char path[256];
    uint64_t size = 0;
    FILE *f;
    int fd;

    if (!dax_name) {
        return -ENOENT;
    }
    snprintf(path, sizeof(path), "/sys/bus/dax/devices/%s/size", dax_name);
    f = fopen(path, "re");
    if (!f || fscanf(f, "%" SCNu64, &size) != 1) {
        if (f) {
            fclose(f);
        }
        return -ENODEV;
    }
    fclose(f);
    /* devdax needs 2 MiB granularity; a gigabyte is plenty for these tests. */
    map_len = (size < MAP_LIMIT ? size : MAP_LIMIT) & ~((2u << 20) - 1);
    if (!map_len) {
        return -ENOSPC;
    }
    snprintf(path, sizeof(path), "/dev/%s", dax_name);
    fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        return -errno;
    }
    map = mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (map == MAP_FAILED) {
        map = NULL;
        return -errno;
    }
    return cca_attach_dax(dev, dax_name, map, map_len);
}

static int case_info(void)
{
    CHECK(info.version == CCA_LAYOUT_VERSION, "version %u", info.version);
    CHECK(info.media_pages > 0, "no media");
    CHECK(info.pin_limit == (info.cache_pages ? info.cache_ways : 0),
          "pin limit %u", info.pin_limit);
    printf("  media_pages=%" PRIu64 " cache_pages=%u cache_ways=%u "
           "pin_limit=%u\n", info.media_pages, info.cache_pages,
           info.cache_ways, info.pin_limit);
    return 0;
}

static int case_nop(void)
{
    struct cca_info after;
    unsigned i;

    for (i = 0; i < 5000; i++) {
        int rc = cca_nop(dev);

        CHECK(!rc, "nop %u: %s", i, cca_strerror(rc));
    }
    cca_info(dev, &after);
    CHECK(after.completed - info.completed >= 5000, "completed %" PRIu64,
          after.completed - info.completed);
    return 0;
}

static int case_query(void)
{
    struct cca_result r;
    uint8_t *p = map + map_len / 2;

    CHECK(!cca_invalidate_addr(dev, p, PAGE, CCA_FLAG_FORCE, &r), "%s",
          cca_strerror(r.status));
    poke(p, 0x5151);
    CHECK(!cca_query_addr(dev, p, PAGE, &r), "%s", cca_strerror(r.status));
    CHECK(r.resident == 1, "resident %" PRIu64, r.resident);
    CHECK(r.dirty == 1, "dirty %" PRIu64, r.dirty);
    return 0;
}

/* A pinned page stays at hit latency while 4x the cache streams past. */
static int case_thrash(void)
{
    uint64_t pinned[SAMPLES];
    uint64_t missed[SAMPLES];
    size_t stream = (size_t)info.cache_pages * 4 * PAGE;
    uint8_t *p = map;
    uint8_t *q = map + PAGE;
    struct cca_result r;
    uint64_t mp;
    uint64_t mq;
    size_t off;
    unsigned i;

    if (!info.cache_pages) {
        printf("  no cache\n");
        return 1;
    }
    if (stream + 2 * PAGE > map_len) {
        stream = map_len - 2 * PAGE;
        printf("  streaming only %zu pages, the mapping limit\n",
               stream / PAGE);
    }
    CHECK(!cca_invalidate(dev, 0, CCA_WHOLE, CCA_FLAG_FORCE, &r), "%s",
          cca_strerror(r.status));
    poke(p, 1);
    poke(q, 2);
    /* Program the control, so every sample reads a mapped NAND page. */
    CHECK(!cca_invalidate_addr(dev, q, PAGE, 0, &r), "%s",
          cca_strerror(r.status));
    CHECK(r.pages == 1, "control not written back: pages %" PRIu64, r.pages);
    CHECK(!cca_pin_addr(dev, p, PAGE, &r), "%s", cca_strerror(r.status));
    for (off = 2 * PAGE; off < stream + 2 * PAGE; off += PAGE) {
        peek(map + off);
    }
    CHECK(!cca_query_addr(dev, p, PAGE, &r), "%s", cca_strerror(r.status));
    CHECK(r.resident == 1 && r.pinned == 1, "resident %" PRIu64
          " pinned %" PRIu64, r.resident, r.pinned);
    for (i = 0; i < SAMPLES; i++) {
        pinned[i] = load_ns(p);
        /*
         * Evict the control every time so each sample is a miss. Flush
         * first: the flush of a dropped page would take the miss itself.
         */
        flush_line(q);
        CHECK(!cca_invalidate_addr(dev, q, PAGE, 0, &r), "%s",
              cca_strerror(r.status));
        missed[i] = timed_load_ns(q);
    }
    CHECK(peek(q) == 2, "control read 0x%" PRIx64, peek(q));
    mp = median(pinned, SAMPLES);
    mq = median(missed, SAMPLES);
    printf("  median load: pinned %" PRIu64 " ns, invalidated control %"
           PRIu64 " ns\n", mp, mq);
    CHECK(mq >= 5 * mp, "control only %.1fx slower", (double)mq / mp);
    CHECK(!cca_unpin_addr(dev, p, PAGE, &r), "%s", cca_strerror(r.status));
    return 0;
}

/* Dirty pages are programmed, dropped, and read back unchanged. */
static int case_invalidate(void)
{
    const unsigned n = 64;
    uint8_t *base = map + 16 * PAGE;
    struct cca_result r;
    unsigned i;

    CHECK(!cca_invalidate_addr(dev, base, n * PAGE, CCA_FLAG_FORCE, &r), "%s",
          cca_strerror(r.status));
    for (i = 0; i < n; i++) {
        poke(base + i * PAGE, 0xabc0000ull + i);
    }
    CHECK(!cca_query_addr(dev, base, n * PAGE, &r), "%s",
          cca_strerror(r.status));
    CHECK(r.resident == n && r.dirty == n, "resident %" PRIu64 " dirty %"
          PRIu64, r.resident, r.dirty);
    mark("invalidate-begin");
    CHECK(!cca_invalidate_addr(dev, base, n * PAGE, 0, &r), "%s",
          cca_strerror(r.status));
    mark("invalidate-end expect media-writes +64");
    CHECK(r.pages == n, "pages %" PRIu64, r.pages);
    CHECK(!cca_query_addr(dev, base, n * PAGE, &r), "%s",
          cca_strerror(r.status));
    CHECK(r.resident == 0, "resident %" PRIu64, r.resident);
    for (i = 0; i < n; i++) {
        uint64_t v = peek(base + i * PAGE);

        CHECK(v == 0xabc0000ull + i, "page %u read 0x%" PRIx64, i, v);
    }
    return 0;
}

/* A disabled page misses on every access; enabling restores hits. */
static int case_disable(void)
{
    uint64_t off[SAMPLES];
    uint64_t on[SAMPLES];
    uint8_t *p = map + 8 * PAGE;
    struct cca_result r;
    uint64_t moff;
    uint64_t mon;
    unsigned i;

    CHECK(!cca_invalidate_addr(dev, p, PAGE, CCA_FLAG_FORCE, &r), "%s",
          cca_strerror(r.status));
    CHECK(!cca_cache_disable(dev, lpn_of(p), 1, 0, &r), "%s",
          cca_strerror(r.status));
    for (i = 0; i < SAMPLES; i++) {
        off[i] = load_ns(p);
    }
    CHECK(!cca_query_addr(dev, p, PAGE, &r), "%s", cca_strerror(r.status));
    CHECK(r.resident == 0 && r.uncached == 1, "resident %" PRIu64
          " uncached %" PRIu64, r.resident, r.uncached);
    CHECK(!cca_cache_enable(dev, lpn_of(p), 1, &r), "%s",
          cca_strerror(r.status));
    peek(p);
    for (i = 0; i < SAMPLES; i++) {
        on[i] = load_ns(p);
    }
    moff = median(off, SAMPLES);
    mon = median(on, SAMPLES);
    printf("  median load: disabled %" PRIu64 " ns, enabled %" PRIu64
           " ns\n", moff, mon);
    CHECK(moff >= 5 * mon, "disabled only %.1fx slower", (double)moff / mon);
    return 0;
}

static int case_errors(void)
{
    uint64_t nsets = info.cache_ways ? info.cache_pages / info.cache_ways : 0;
    struct cca_result r;
    uint32_t i;
    int rc;

    rc = cca_query(dev, info.media_pages, 1, &r);
    CHECK(rc == -ERANGE, "query past the end: %s", cca_strerror(rc));
    if (!nsets) {
        printf("  no cache: pin checks skipped\n");
        return 0;
    }
    CHECK(!cca_unpin(dev, 0, CCA_WHOLE, &r), "%s", cca_strerror(r.status));
    CHECK(!cca_invalidate(dev, 0, CCA_WHOLE, CCA_FLAG_FORCE, &r), "%s",
          cca_strerror(r.status));
    /* Fill every way of set 0, then one page more. */
    for (i = 0; i < info.pin_limit; i++) {
        rc = cca_pin(dev, i * nsets, 1, &r);
        CHECK(!rc, "pin way %u: %s", i, cca_strerror(rc));
    }
    rc = cca_pin(dev, (uint64_t)info.pin_limit * nsets, 1, &r);
    CHECK(rc == -ENOSPC, "pin past the set: %s", cca_strerror(rc));
    rc = cca_invalidate(dev, 0, 1, 0, &r);
    CHECK(rc == -EBUSY, "invalidate a pinned page: %s", cca_strerror(rc));
    CHECK(!cca_invalidate(dev, 0, CCA_WHOLE, CCA_FLAG_FORCE, &r), "%s",
          cca_strerror(r.status));
    CHECK(r.pages >= info.pin_limit, "pages %" PRIu64, r.pages);
    return 0;
}

static uint8_t *seen;
static unsigned long reaped;

static void *thread_main(void *opaque)
{
    uintptr_t id = (uintptr_t)opaque;
    struct cca_completion done[64];
    unsigned sent = 0;

    while (__atomic_load_n(&reaped, __ATOMIC_ACQUIRE) <
           THREADS * THREAD_CMDS) {
        int n;
        int i;

        if (sent < THREAD_CMDS) {
            uint64_t tag = id * THREAD_CMDS + sent;

            if (!cca_submit(dev, CCA_CTRL_NOP, 0, 0, 0, tag)) {
                sent++;
                continue;
            }
        }
        n = cca_reap(dev, done, 64, 10);
        for (i = 0; i < n; i++) {
            uint64_t tag = done[i].tag;

            if (tag >= THREADS * THREAD_CMDS || done[i].r.status ||
                __atomic_exchange_n(&seen[tag], 1, __ATOMIC_ACQ_REL)) {
                /* Mark a stray, duplicate or failed tag for the check. */
                __atomic_store_n(&seen[THREADS * THREAD_CMDS], 1,
                                 __ATOMIC_RELEASE);
            }
        }
        if (n > 0) {
            __atomic_add_fetch(&reaped, n, __ATOMIC_ACQ_REL);
        } else if (n < 0) {
            break;
        }
    }
    return NULL;
}

static int case_threads(void)
{
    pthread_t threads[THREADS];
    struct cca_info before;
    struct cca_info after;
    uintptr_t i;
    unsigned long missing = 0;

    seen = calloc(THREADS * THREAD_CMDS + 1, 1);
    CHECK(seen, "no memory");
    reaped = 0;
    cca_info(dev, &before);
    for (i = 0; i < THREADS; i++) {
        pthread_create(&threads[i], NULL, thread_main, (void *)i);
    }
    for (i = 0; i < THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    cca_info(dev, &after);
    for (i = 0; i < THREADS * THREAD_CMDS; i++) {
        missing += !seen[i];
    }
    CHECK(!seen[THREADS * THREAD_CMDS], "stray, duplicate or failed tag");
    free(seen);
    CHECK(!missing, "%lu tags never completed", missing);
    CHECK(reaped == THREADS * THREAD_CMDS, "reaped %lu", reaped);
    CHECK(after.completed - before.completed == THREADS * THREAD_CMDS,
          "completed %" PRIu64, after.completed - before.completed);
    return 0;
}

/* A holder killed mid-batch must not wedge the next owner. */
static int case_crash(void)
{
    int ready[2];
    pid_t child;
    char byte;
    int status;
    int rc;

    cca_close(dev);
    dev = NULL;
    CHECK(!pipe(ready), "pipe");
    child = fork();
    CHECK(child >= 0, "fork");
    if (!child) {
        struct cca_dev *d;
        unsigned i;

        if (cca_open(dev_name, &d)) {
            _exit(1);
        }
        for (i = 0; i < 1000; i++) {
            cca_submit(d, CCA_CTRL_NOP, CCA_SUBMIT_DEFER, 0, 0, i);
        }
        cca_kick(d);
        if (write(ready[1], "r", 1) != 1) {
            _exit(1);
        }
        for (;;) {
            pause();
        }
    }
    close(ready[1]);
    rc = read(ready[0], &byte, 1);
    close(ready[0]);
    kill(child, SIGKILL);
    waitpid(child, &status, 0);
    CHECK(rc == 1, "child could not open the device");
    rc = cca_open(dev_name, &dev);
    CHECK(!rc, "reopen: %s", cca_strerror(rc));
    rc = cca_nop(dev);
    CHECK(!rc, "nop after reopen: %s", cca_strerror(rc));
    return 0;
}

/* Leave pins and an uncached page for after-reboot to find gone. */
static int case_before_reboot(void)
{
    struct cca_result r;

    CHECK(info.cache_pages, "no cache");
    CHECK(!cca_pin(dev, 0, 1, &r), "%s", cca_strerror(r.status));
    CHECK(!cca_cache_disable(dev, 1, 1, CCA_FLAG_FORCE, &r), "%s",
          cca_strerror(r.status));
    CHECK(!cca_query(dev, 0, CCA_WHOLE, &r), "%s", cca_strerror(r.status));
    CHECK(r.pinned == 1 && r.uncached == 1, "pinned %" PRIu64 " uncached %"
          PRIu64, r.pinned, r.uncached);
    return 0;
}

static int case_after_reboot(void)
{
    struct cca_result r;

    CHECK(!cca_query(dev, 0, CCA_WHOLE, &r), "%s", cca_strerror(r.status));
    CHECK(r.pinned == 0 && r.uncached == 0, "pinned %" PRIu64 " uncached %"
          PRIu64, r.pinned, r.uncached);
    return 0;
}

static const struct {
    const char *name;
    int (*run)(void);
    int needs_dax;
    int by_default;
} cases[] = {
    { "info", case_info, 0, 1 },
    { "nop", case_nop, 0, 1 },
    { "query", case_query, 1, 1 },
    { "thrash", case_thrash, 1, 1 },
    { "invalidate", case_invalidate, 1, 1 },
    { "disable", case_disable, 1, 1 },
    { "errors", case_errors, 0, 1 },
    { "threads", case_threads, 0, 1 },
    { "crash", case_crash, 0, 1 },
    { "before-reboot", case_before_reboot, 0, 0 },
    { "after-reboot", case_after_reboot, 0, 0 },
};

static void run_case(unsigned i, int dax_rc)
{
    int rc;

    printf("case %s\n", cases[i].name);
    fflush(stdout);
    if (cases[i].needs_dax && dax_rc) {
        printf("SKIP %s: no devdax mapping (%s)\n", cases[i].name,
               cca_strerror(dax_rc));
        return;
    }
    rc = cases[i].run();
    if (!dev) {
        printf("FAIL %s: device lost\n", cases[i].name);
        failures++;
        return;
    }
    if (rc > 0) {
        printf("SKIP %s\n", cases[i].name);
    } else if (rc < 0) {
        printf("FAIL %s\n", cases[i].name);
        failures++;
    } else {
        printf("PASS %s\n", cases[i].name);
    }
    fflush(stdout);
}

int main(int argc, char **argv)
{
    unsigned i;
    int dax_rc;
    int opt;
    int rc;

    setvbuf(stdout, NULL, _IOLBF, 0);
    while ((opt = getopt(argc, argv, "d:x:h")) != -1) {
        switch (opt) {
        case 'd':
            dev_name = optarg;
            break;
        case 'x':
            dax_name = optarg;
            break;
        default:
            fprintf(stderr, "usage: cca-test [-d mem0] [-x dax0.0] "
                    "[CASE...]\n");
            return 2;
        }
    }
    rc = cca_open(dev_name, &dev);
    if (rc) {
        printf("FAIL open %s: %s\n", dev_name ? dev_name : "(auto)",
               cca_strerror(rc));
        return 1;
    }
    cca_info(dev, &info);
    dax_rc = map_dax();
    if (optind == argc) {
        for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            if (cases[i].by_default) {
                run_case(i, dax_rc);
            }
        }
    }
    for (; optind < argc; optind++) {
        for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            if (!strcmp(argv[optind], cases[i].name)) {
                run_case(i, dax_rc);
                break;
            }
        }
        if (i == sizeof(cases) / sizeof(cases[0])) {
            printf("FAIL unknown case %s\n", argv[optind]);
            failures++;
        }
    }
    if (map) {
        munmap(map, map_len);
    }
    cca_close(dev);
    printf("%s: %d failed\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
