/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * CCA guest library. One mutex makes this process the single producer
 * and single consumer of both rings, as the device requires; flock() on
 * resource5 keeps other processes out.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "cca.h"

#define N CCA_RING_COUNT

enum {
    SLOT_FREE,
    SLOT_ASYNC,         /* completion goes to the parked queue */
    SLOT_SYNC,          /* a synchronous caller waits on it */
    SLOT_DONE,          /* synchronous result ready for its caller */
    SLOT_ABANDONED,     /* caller gave up; free it when it completes */
};

struct cca_dev {
    int fd;
    uint8_t *bar;
    uint8_t *regs;                      /* MMIO: only __atomic accesses */
    struct cca_ring *req;
    struct cca_ring *resp;
    struct cca_ctrl_slot_s *slots;
    pthread_mutex_t lock;
    uint32_t req_head;
    uint32_t resp_tail;
    uint64_t epoch;                     /* bumped by cca_reset() */
    int timeout_ms;
    uint32_t nfree;
    uint16_t free_list[N];
    uint8_t state[N];
    struct cca_result done[N];
    struct cca_completion park[N];
    uint32_t park_head;
    uint32_t park_len;
    char memdev[PATH_MAX];              /* realpath of memN, or empty */
    bool dax;
    uintptr_t dax_base;
    size_t dax_len;
    uint64_t dax_hpa;
    uint64_t dec_start;
    uint64_t dec_size;
    uint64_t dpa_base;
};

/* Relaxed atomics give exactly one load or store per register access. */
static uint32_t reg32(struct cca_dev *d, unsigned off)
{
    return __atomic_load_n((uint32_t *)(d->regs + off), __ATOMIC_RELAXED);
}

static uint64_t reg64(struct cca_dev *d, unsigned off)
{
    return __atomic_load_n((uint64_t *)(d->regs + off), __ATOMIC_RELAXED);
}

static void reg_write(struct cca_dev *d, unsigned off, uint32_t value)
{
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    __atomic_store_n((uint32_t *)(d->regs + off), value, __ATOMIC_RELAXED);
}

static int64_t now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Spin briefly, then yield, then sleep up to 1 ms per round. */
struct backoff {
    unsigned rounds;
    long ns;
};

static void backoff(struct backoff *b)
{
    if (b->rounds < 64) {
        __atomic_signal_fence(__ATOMIC_SEQ_CST);
        b->rounds++;
    } else if (b->rounds < 128) {
        sched_yield();
        b->rounds++;
    } else {
        struct timespec ts = { 0, b->ns };

        b->ns = b->ns ? (b->ns * 2 > 1000000 ? 1000000 : b->ns * 2) : 1000;
        ts.tv_nsec = b->ns;
        nanosleep(&ts, NULL);
    }
}

static bool expired(int64_t deadline)
{
    return deadline >= 0 && now_ms() >= deadline;
}

static int64_t deadline_of(int timeout_ms)
{
    return timeout_ms < 0 ? -1 : now_ms() + timeout_ms;
}

static bool dev_fatal(struct cca_dev *d)
{
    return reg32(d, CCA_REG_STATUS) & CCA_STATUS_FATAL;
}

static int wait_ready(struct cca_dev *d, int timeout_ms)
{
    int64_t deadline = deadline_of(timeout_ms);
    struct backoff b = { 0, 0 };

    while (!(reg32(d, CCA_REG_STATUS) & CCA_STATUS_READY)) {
        if (expired(deadline)) {
            return -ETIMEDOUT;
        }
        backoff(&b);
    }
    return 0;
}

static void slots_reset(struct cca_dev *d)
{
    uint32_t i;

    d->req_head = 0;
    d->resp_tail = 0;
    d->park_head = 0;
    d->park_len = 0;
    d->nfree = N;
    for (i = 0; i < N; i++) {
        /* Lowest slots first, so slot 0 is used and reused early. */
        d->free_list[i] = N - 1 - i;
        d->state[i] = SLOT_FREE;
    }
}

static void slot_free(struct cca_dev *d, uint32_t slot)
{
    d->state[slot] = SLOT_FREE;
    d->free_list[d->nfree++] = slot;
}

static void to_result(const struct cca_ctrl_resp_s *resp, struct cca_result *r)
{
    r->status = resp->status;
    r->pages = resp->lpn_count;
    r->resident = resp->resident;
    r->dirty = resp->dirty;
    r->pinned = resp->pinned;
    r->bypassed = resp->bypassed;
}

/* Drain the response ring; the device is trusted no further than here. */
static int reap_locked(struct cca_dev *d)
{
    uint32_t head = __atomic_load_n(&d->resp->head, __ATOMIC_ACQUIRE);
    int n = 0;

    if (head - d->resp_tail > N) {
        return -EPROTO;
    }
    while (d->resp_tail != head) {
        uint32_t slot = __atomic_load_n(&d->resp->entries[d->resp_tail % N],
                                        __ATOMIC_RELAXED);
        struct cca_ctrl_resp_s resp;

        if (slot >= N) {
            return -EPROTO;
        }
        memcpy(&resp, &d->slots[slot].resp, sizeof(resp));
        d->resp_tail++;
        switch (d->state[slot]) {
        case SLOT_SYNC:
            to_result(&resp, &d->done[slot]);
            d->state[slot] = SLOT_DONE;
            break;
        case SLOT_ASYNC: {
            struct cca_completion *c = &d->park[(d->park_head + d->park_len) %
                                                N];

            c->tag = resp.tag;
            to_result(&resp, &c->r);
            d->park_len++;
            slot_free(d, slot);
            break;
        }
        case SLOT_ABANDONED:
            slot_free(d, slot);
            break;
        default:
            break;
        }
        n++;
    }
    __atomic_store_n(&d->resp->tail, d->resp_tail, __ATOMIC_RELEASE);
    return n;
}

static int post_locked(struct cca_dev *d, const struct cca_ctrl_cmd_s *cmd,
                       int state, uint32_t *slot)
{
    uint32_t i;

    if (!d->nfree) {
        return -EAGAIN;
    }
    i = d->free_list[--d->nfree];
    memcpy(&d->slots[i].cmd, cmd, sizeof(*cmd));
    d->state[i] = state;
    __atomic_store_n(&d->req->entries[d->req_head % N], i, __ATOMIC_RELAXED);
    d->req_head++;
    __atomic_store_n(&d->req->head, d->req_head, __ATOMIC_RELEASE);
    *slot = i;
    return 0;
}

static int build(struct cca_ctrl_cmd_s *c, uint32_t cmd, unsigned flags,
                 uint64_t lpn, uint64_t count, uint64_t tag)
{
    memset(c, 0, sizeof(*c));
    if (flags & ~(CCA_FLAG_FORCE | CCA_SUBMIT_DEFER)) {
        return -EINVAL;
    }
    c->cmd = cmd;
    c->tag = tag;
    c->flags = flags & CCA_FLAG_FORCE ? CCA_F_FORCE : 0;
    if (count == CCA_WHOLE) {
        if (lpn) {
            return -EINVAL;
        }
        c->flags |= CCA_F_ALL;
    } else {
        c->lpn_start = lpn;
        c->lpn_count = count;
    }
    return 0;
}

int cca_call_raw(struct cca_dev *d, const struct cca_ctrl_cmd_s *cmd,
                 struct cca_result *r)
{
    int64_t deadline;
    struct backoff b = { 0, 0 };
    struct cca_result local;
    uint64_t epoch;
    uint32_t slot;
    int rc;

    if (!r) {
        r = &local;
    }
    memset(r, 0, sizeof(*r));
    pthread_mutex_lock(&d->lock);
    deadline = deadline_of(d->timeout_ms);
    epoch = d->epoch;
    while ((rc = post_locked(d, cmd, SLOT_SYNC, &slot)) == -EAGAIN) {
        rc = reap_locked(d);
        if (rc < 0 || d->nfree) {
            if (rc < 0) {
                goto out;
            }
            continue;
        }
        if (dev_fatal(d)) {
            rc = -EPROTO;
            goto out;
        }
        if (expired(deadline) || d->epoch != epoch) {
            rc = -ETIMEDOUT;
            goto out;
        }
        pthread_mutex_unlock(&d->lock);
        backoff(&b);
        pthread_mutex_lock(&d->lock);
    }
    reg_write(d, CCA_REG_DOORBELL, 1);
    b = (struct backoff){ 0, 0 };
    for (;;) {
        if (d->epoch != epoch) {
            /* A reset freed every slot; this one is gone with it. */
            rc = -ECANCELED;
            break;
        }
        rc = reap_locked(d);
        if (rc < 0) {
            break;
        }
        if (d->state[slot] == SLOT_DONE) {
            *r = d->done[slot];
            slot_free(d, slot);
            rc = r->status;
            break;
        }
        if (dev_fatal(d)) {
            d->state[slot] = SLOT_ABANDONED;
            rc = -EPROTO;
            break;
        }
        if (expired(deadline)) {
            d->state[slot] = SLOT_ABANDONED;
            rc = -ETIMEDOUT;
            break;
        }
        pthread_mutex_unlock(&d->lock);
        backoff(&b);
        pthread_mutex_lock(&d->lock);
    }
out:
    pthread_mutex_unlock(&d->lock);
    return rc;
}

static int call(struct cca_dev *d, uint32_t cmd, unsigned flags, uint64_t lpn,
                uint64_t count, struct cca_result *r)
{
    struct cca_ctrl_cmd_s c;
    int rc = build(&c, cmd, flags, lpn, count, 0);

    if (rc) {
        if (r) {
            memset(r, 0, sizeof(*r));
            r->status = rc;
        }
        return rc;
    }
    return cca_call_raw(d, &c, r);
}

int cca_nop(struct cca_dev *d)
{
    struct cca_ctrl_cmd_s c = { .cmd = CCA_CTRL_NOP };

    return cca_call_raw(d, &c, NULL);
}

int cca_pin(struct cca_dev *d, uint64_t lpn, uint64_t count,
            struct cca_result *r)
{
    return call(d, CCA_CTRL_PIN, 0, lpn, count, r);
}

int cca_unpin(struct cca_dev *d, uint64_t lpn, uint64_t count,
              struct cca_result *r)
{
    return call(d, CCA_CTRL_UNPIN, 0, lpn, count, r);
}

int cca_invalidate(struct cca_dev *d, uint64_t lpn, uint64_t count,
                   unsigned flags, struct cca_result *r)
{
    return call(d, CCA_CTRL_INVALIDATE, flags, lpn, count, r);
}

int cca_cache_disable(struct cca_dev *d, uint64_t lpn, uint64_t count,
                      unsigned flags, struct cca_result *r)
{
    return call(d, CCA_CTRL_CACHE_DISABLE, flags, lpn, count, r);
}

int cca_cache_enable(struct cca_dev *d, uint64_t lpn, uint64_t count,
                     struct cca_result *r)
{
    return call(d, CCA_CTRL_CACHE_ENABLE, 0, lpn, count, r);
}

int cca_query(struct cca_dev *d, uint64_t lpn, uint64_t count,
              struct cca_result *r)
{
    return call(d, CCA_CTRL_QUERY, 0, lpn, count, r);
}

int cca_submit(struct cca_dev *d, uint32_t cmd, unsigned flags, uint64_t lpn,
               uint64_t count, uint64_t tag)
{
    struct cca_ctrl_cmd_s c;
    uint32_t slot;
    int rc = build(&c, cmd, flags, lpn, count, tag);

    if (rc) {
        return rc;
    }
    pthread_mutex_lock(&d->lock);
    rc = post_locked(d, &c, SLOT_ASYNC, &slot);
    if (rc == -EAGAIN && reap_locked(d) > 0) {
        rc = post_locked(d, &c, SLOT_ASYNC, &slot);
    }
    pthread_mutex_unlock(&d->lock);
    if (!rc && !(flags & CCA_SUBMIT_DEFER)) {
        cca_kick(d);
    }
    return rc;
}

void cca_kick(struct cca_dev *d)
{
    reg_write(d, CCA_REG_DOORBELL, 1);
}

int cca_reap(struct cca_dev *d, struct cca_completion *out, unsigned max,
             int timeout_ms)
{
    int64_t deadline = deadline_of(timeout_ms);
    struct backoff b = { 0, 0 };
    unsigned n = 0;
    int rc = 0;

    pthread_mutex_lock(&d->lock);
    for (;;) {
        rc = reap_locked(d);
        if (rc < 0) {
            break;
        }
        while (n < max && d->park_len) {
            out[n++] = d->park[d->park_head];
            d->park_head = (d->park_head + 1) % N;
            d->park_len--;
        }
        if (n || !max) {
            rc = n;
            break;
        }
        if (dev_fatal(d)) {
            rc = -EPROTO;
            break;
        }
        if (expired(deadline)) {
            rc = 0;
            break;
        }
        pthread_mutex_unlock(&d->lock);
        backoff(&b);
        pthread_mutex_lock(&d->lock);
    }
    pthread_mutex_unlock(&d->lock);
    return rc;
}

int cca_reset(struct cca_dev *d, int all)
{
    int rc;

    pthread_mutex_lock(&d->lock);
    reg_write(d, CCA_REG_RESET, all ? CCA_RESET_ALL : CCA_RESET_RINGS);
    /* The device empties the rings before the write completes. */
    slots_reset(d);
    d->epoch++;
    rc = wait_ready(d, d->timeout_ms < 0 ? -1 : 1000 + d->timeout_ms);
    pthread_mutex_unlock(&d->lock);
    return rc;
}

static bool header_ok(struct cca_dev *d)
{
    const struct cca_shmem_header *h =
        (const struct cca_shmem_header *)(d->bar + CCA_SHM_OFFSET);

    return h->magic == CCA_SHMEM_MAGIC && h->version == CCA_LAYOUT_VERSION &&
           h->ring_count == CCA_RING_COUNT && h->slot_size == CCA_SLOT_SIZE &&
           h->offset_ctrl_req_ring == CCA_REQ_RING_OFFSET &&
           h->offset_ctrl_resp_ring == CCA_RESP_RING_OFFSET &&
           h->offset_ctrl_slot_pool == CCA_SLOT_POOL_OFFSET;
}

static int attach(struct cca_dev *d, void *bar)
{
    uint8_t *shm = (uint8_t *)bar + CCA_SHM_OFFSET;
    int rc;

    d->bar = bar;
    d->regs = bar;
    d->req = (struct cca_ring *)(shm + CCA_REQ_RING_OFFSET);
    d->resp = (struct cca_ring *)(shm + CCA_RESP_RING_OFFSET);
    d->slots = (struct cca_ctrl_slot_s *)(shm + CCA_SLOT_POOL_OFFSET);
    d->timeout_ms = 10000;
    pthread_mutex_init(&d->lock, NULL);
    slots_reset(d);
    if (reg32(d, CCA_REG_MAGIC) != CCA_SHMEM_MAGIC) {
        return -ENODEV;
    }
    if (reg32(d, CCA_REG_VERSION) != CCA_LAYOUT_VERSION) {
        return -EPROTO;
    }
    rc = wait_ready(d, 1000);
    if (rc) {
        return rc;
    }
    /* A previous owner left work behind, or the header was overwritten. */
    if (!header_ok(d) || d->req->head || d->req->tail || d->resp->head ||
        d->resp->tail || dev_fatal(d)) {
        reg_write(d, CCA_REG_RESET, CCA_RESET_RINGS);
        rc = wait_ready(d, 1000);
        if (rc) {
            return rc;
        }
    }
    return header_ok(d) ? 0 : -EPROTO;
}

int cca_open_map(void *bar, struct cca_dev **out)
{
    struct cca_dev *d = calloc(1, sizeof(*d));
    int rc;

    if (!d) {
        return -ENOMEM;
    }
    d->fd = -1;
    rc = attach(d, bar);
    if (rc) {
        pthread_mutex_destroy(&d->lock);
        free(d);
        return rc;
    }
    *out = d;
    return 0;
}

/* On overflow the path is left empty, so opening it fails cleanly. */
static void join(char *out, const char *dir, const char *name)
{
    int n = snprintf(out, PATH_MAX, "%s/%s", dir, name);

    if (n < 0 || n >= PATH_MAX) {
        out[0] = 0;
    }
}

static int read_text(const char *path, char *buf, size_t len)
{
    FILE *f = fopen(path, "re");
    size_t n;

    if (!f) {
        return -errno;
    }
    n = fread(buf, 1, len - 1, f);
    fclose(f);
    buf[n] = 0;
    while (n && (buf[n - 1] == '\n' || buf[n - 1] == ' ')) {
        buf[--n] = 0;
    }
    return 0;
}

/* sysfs prints these in decimal or with a 0x prefix. */
static int read_u64(const char *path, uint64_t *value)
{
    char buf[64];
    const char *p = buf;
    unsigned base = 10;
    uint64_t v = 0;
    int rc = read_text(path, buf, sizeof(buf));

    if (rc) {
        return rc;
    }
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        base = 16;
        p += 2;
    }
    if (!*p) {
        return -EINVAL;
    }
    for (; *p; p++) {
        unsigned digit;

        if (*p >= '0' && *p <= '9') {
            digit = *p - '0';
        } else if (base == 16 && *p >= 'a' && *p <= 'f') {
            digit = *p - 'a' + 10;
        } else if (base == 16 && *p >= 'A' && *p <= 'F') {
            digit = *p - 'A' + 10;
        } else {
            return -EINVAL;
        }
        if (digit >= base || v > (UINT64_MAX - digit) / base) {
            return -EINVAL;
        }
        v = v * base + digit;
    }
    *value = v;
    return 0;
}

/* The memN child of a PCI function directory, if any. */
static void find_memdev(const char *pcidir, char *out, size_t len)
{
    DIR *dir = opendir(pcidir);
    struct dirent *e;

    out[0] = 0;
    if (!dir) {
        return;
    }
    while ((e = readdir(dir))) {
        char path[PATH_MAX];

        if (strncmp(e->d_name, "mem", 3) || e->d_name[3] < '0' ||
            e->d_name[3] > '9') {
            continue;
        }
        snprintf(path, sizeof(path), "%s/%s", pcidir, e->d_name);
        if (realpath(path, out) && strlen(out) < len) {
            break;
        }
        out[0] = 0;
    }
    closedir(dir);
}

static bool is_cca(const char *pcidir)
{
    char path[PATH_MAX];
    uint64_t class;
    struct stat st;
    void *map;
    int fd;
    bool ok;

    /* Only CXL memory devices; never probe BARs of anything else. */
    join(path, pcidir, "class");
    if (read_u64(path, &class) || class != 0x050210) {
        return false;
    }
    join(path, pcidir, "resource5");
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    if (fstat(fd, &st) || st.st_size < (off_t)CCA_BAR_SIZE) {
        close(fd);
        return false;
    }
    map = mmap(NULL, CCA_REG_SIZE, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (map == MAP_FAILED) {
        return false;
    }
    ok = __atomic_load_n((uint32_t *)map, __ATOMIC_RELAXED) == CCA_SHMEM_MAGIC;
    munmap(map, CCA_REG_SIZE);
    return ok;
}

static int find_only(char *pcidir, size_t len)
{
    DIR *dir = opendir("/sys/bus/pci/devices");
    struct dirent *e;
    int found = 0;

    if (!dir) {
        return -ENODEV;
    }
    while ((e = readdir(dir))) {
        char path[PATH_MAX];

        if (e->d_name[0] == '.') {
            continue;
        }
        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s", e->d_name);
        if (is_cca(path)) {
            if (found++) {
                break;
            }
            if (!realpath(path, pcidir) || strlen(pcidir) >= len) {
                found = 0;
                break;
            }
        }
    }
    closedir(dir);
    return found == 1 ? 0 : found ? -ENOTUNIQ : -ENODEV;
}

static int resolve(const char *which, char *pcidir, char *resource,
                   char *memdev)
{
    char path[PATH_MAX];
    char *slash;
    int rc;

    memdev[0] = 0;
    if (!which) {
        rc = find_only(pcidir, PATH_MAX);
        if (rc) {
            return rc;
        }
    } else if (which[0] == '/') {
        if (!realpath(which, resource)) {
            return -errno;
        }
        snprintf(pcidir, PATH_MAX, "%s", resource);
        slash = strrchr(pcidir, '/');
        *slash = 0;
        find_memdev(pcidir, memdev, PATH_MAX);
        return 0;
    } else if (!strncmp(which, "mem", 3)) {
        snprintf(path, sizeof(path), "/sys/bus/cxl/devices/%s", which);
        if (!realpath(path, memdev)) {
            return errno == ENOENT ? -ENODEV : -errno;
        }
        snprintf(pcidir, PATH_MAX, "%s", memdev);
        slash = strrchr(pcidir, '/');
        *slash = 0;
    } else {
        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s", which);
        if (!realpath(path, pcidir)) {
            return errno == ENOENT ? -ENODEV : -errno;
        }
    }
    if (!memdev[0]) {
        find_memdev(pcidir, memdev, PATH_MAX);
    }
    if ((size_t)snprintf(resource, PATH_MAX, "%s/resource5", pcidir) >=
        PATH_MAX) {
        return -ENAMETOOLONG;
    }
    return 0;
}

int cca_open(const char *which, struct cca_dev **out)
{
    char pcidir[PATH_MAX];
    char resource[PATH_MAX];
    char memdev[PATH_MAX];
    struct cca_dev *d;
    struct stat st;
    void *map;
    int fd;
    int rc;

    rc = resolve(which, pcidir, resource, memdev);
    if (rc) {
        return rc;
    }
    fd = open(resource, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        return errno == ENOENT ? -ENODEV : -errno;
    }
    if (flock(fd, LOCK_EX | LOCK_NB)) {
        rc = errno == EWOULDBLOCK ? -EBUSY : -errno;
        close(fd);
        return rc;
    }
    if (fstat(fd, &st) || st.st_size < (off_t)CCA_BAR_SIZE) {
        close(fd);
        return -ENODEV;
    }
    map = mmap(NULL, CCA_BAR_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        rc = -errno;
        close(fd);
        return rc;
    }
    rc = cca_open_map(map, &d);
    if (rc) {
        munmap(map, CCA_BAR_SIZE);
        close(fd);
        return rc;
    }
    d->fd = fd;
    snprintf(d->memdev, sizeof(d->memdev), "%s", memdev);
    *out = d;
    return 0;
}

void cca_close(struct cca_dev *d)
{
    if (!d) {
        return;
    }
    if (d->fd >= 0) {
        munmap(d->bar, CCA_BAR_SIZE);
        close(d->fd);
    }
    pthread_mutex_destroy(&d->lock);
    free(d);
}

int cca_info(struct cca_dev *d, struct cca_info *out)
{
    out->version = reg32(d, CCA_REG_VERSION);
    out->media_pages = reg64(d, CCA_REG_MEDIA_PAGES);
    out->cache_pages = reg32(d, CCA_REG_CACHE_PAGES);
    out->cache_ways = reg32(d, CCA_REG_CACHE_WAYS);
    out->pin_limit = reg32(d, CCA_REG_PIN_LIMIT);
    out->completed = reg64(d, CCA_REG_COMPLETED);
    return 0;
}

void cca_set_timeout(struct cca_dev *d, int timeout_ms)
{
    pthread_mutex_lock(&d->lock);
    d->timeout_ms = timeout_ms;
    pthread_mutex_unlock(&d->lock);
}

int cca_attach_dax(struct cca_dev *d, const char *dax, void *base, size_t len)
{
    char path[PATH_MAX];
    char daxdir[PATH_MAX];
    char region[PATH_MAX];
    char decoder[64];
    char dec[PATH_MAX];
    char owner[PATH_MAX];
    uint64_t ways;
    uint64_t size;
    char *slash;

    snprintf(path, sizeof(path), "/sys/bus/dax/devices/%s", dax);
    if (!realpath(path, daxdir)) {
        return -ENODEV;
    }
    /* .../regionN/dax_regionN/daxN.M */
    snprintf(region, sizeof(region), "%s", daxdir);
    slash = strrchr(region, '/');
    *slash = 0;
    slash = strrchr(region, '/');
    *slash = 0;
    slash = strrchr(region, '/');
    if (!slash || strncmp(slash + 1, "region", 6)) {
        return -EOPNOTSUPP;
    }
    join(path, daxdir, "resource");
    if (read_u64(path, &d->dax_hpa)) {
        return -EOPNOTSUPP;
    }
    join(path, daxdir, "size");
    if (read_u64(path, &size) || len > size) {
        return -EINVAL;
    }
    join(path, region, "interleave_ways");
    if (read_u64(path, &ways) || ways != 1) {
        return -EOPNOTSUPP;
    }
    join(path, region, "target0");
    if (read_text(path, decoder, sizeof(decoder)) || !decoder[0] ||
        strchr(decoder, '/')) {
        return -EOPNOTSUPP;
    }
    snprintf(path, sizeof(path), "/sys/bus/cxl/devices/%s", decoder);
    if (!realpath(path, dec)) {
        return -EOPNOTSUPP;
    }
    /* The endpoint decoder must belong to the memdev this handle drives. */
    join(path, dec, "../uport");
    if (!d->memdev[0] || !realpath(path, owner) || strcmp(owner, d->memdev)) {
        return -EOPNOTSUPP;
    }
    join(path, dec, "start");
    if (read_u64(path, &d->dec_start)) {
        return -EOPNOTSUPP;
    }
    join(path, dec, "size");
    if (read_u64(path, &d->dec_size)) {
        return -EOPNOTSUPP;
    }
    join(path, dec, "dpa_resource");
    if (read_u64(path, &d->dpa_base)) {
        return -EOPNOTSUPP;
    }
    if (d->dax_hpa < d->dec_start ||
        d->dax_hpa - d->dec_start + len > d->dec_size) {
        return -EOPNOTSUPP;
    }
    d->dax_base = (uintptr_t)base;
    d->dax_len = len;
    d->dax = true;
    return 0;
}

int cca_lpn_of(struct cca_dev *d, const void *addr, uint64_t *lpn)
{
    uintptr_t a = (uintptr_t)addr;

    if (!d->dax) {
        return -EOPNOTSUPP;
    }
    if (a < d->dax_base || a - d->dax_base >= d->dax_len) {
        return -ERANGE;
    }
    *lpn = (d->dpa_base + d->dax_hpa - d->dec_start + (a - d->dax_base)) >>
           CCA_PAGE_SHIFT;
    return 0;
}

static int addr_range(struct cca_dev *d, const void *addr, size_t len,
                      uint64_t *lpn, uint64_t *count)
{
    uint64_t last;
    int rc;

    if (!len) {
        return -EINVAL;
    }
    rc = cca_lpn_of(d, addr, lpn);
    if (!rc) {
        rc = cca_lpn_of(d, (const uint8_t *)addr + len - 1, &last);
    }
    if (!rc) {
        *count = last - *lpn + 1;
    }
    return rc;
}

static int addr_call(struct cca_dev *d, uint32_t cmd, const void *addr,
                     size_t len, unsigned flags, struct cca_result *r)
{
    uint64_t lpn;
    uint64_t count;
    int rc = addr_range(d, addr, len, &lpn, &count);

    if (rc) {
        if (r) {
            memset(r, 0, sizeof(*r));
            r->status = rc;
        }
        return rc;
    }
    return call(d, cmd, flags, lpn, count, r);
}

int cca_pin_addr(struct cca_dev *d, const void *addr, size_t len,
                 struct cca_result *r)
{
    return addr_call(d, CCA_CTRL_PIN, addr, len, 0, r);
}

int cca_unpin_addr(struct cca_dev *d, const void *addr, size_t len,
                   struct cca_result *r)
{
    return addr_call(d, CCA_CTRL_UNPIN, addr, len, 0, r);
}

int cca_invalidate_addr(struct cca_dev *d, const void *addr, size_t len,
                        unsigned flags, struct cca_result *r)
{
    return addr_call(d, CCA_CTRL_INVALIDATE, addr, len, flags, r);
}

int cca_query_addr(struct cca_dev *d, const void *addr, size_t len,
                   struct cca_result *r)
{
    return addr_call(d, CCA_CTRL_QUERY, addr, len, 0, r);
}

const char *cca_strerror(int status)
{
    switch (-status) {
    case 0:
        return "success";
    case ENOSPC:
        return "no room left to pin in a cache set";
    case EBUSY:
        return "range has pinned pages or conflicts with a direct ratio";
    case ERANGE:
        return "range exceeds the media";
    case EOPNOTSUPP:
        return "not supported by this configuration";
    case ENODEV:
        return "media disabled or no CCA device";
    case EPROTO:
        return "device reported a fatal ring error; reset it";
    case EAGAIN:
        return "cache geometry changed during the command";
    default:
        return strerror(-status);
    }
}
