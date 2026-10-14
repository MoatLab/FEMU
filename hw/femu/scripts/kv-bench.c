/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * kv-bench: a key-value benchmark and checker for FEMU's NVMe-KV mode.
 *
 * It sends the ratified NVMe-KV commands (Store 01h, Retrieve 02h, List
 * 06h, Delete 10h, Exist 14h) through the I/O passthrough ioctl of the
 * namespace's generic node /dev/ngXnY, and keeps a model of every key on
 * the host to check each answer:
 *
 *   load    store every key once
 *   mixed   random Store, Retrieve, Delete and Exist by the --mix shares;
 *           each Retrieve compares the value bytes and the size in the
 *           completion, each Exist and Retrieve of a deleted key expects
 *           Key Does Not Exist
 *   verify  Exist and Retrieve of every key
 *   list    List walks the whole namespace; the keys must be exactly the
 *           live keys of the model
 *   delete  delete every second live key, then Exist, Retrieve and List
 *           must show them gone
 *   cleanup delete the other keys; List must then return no key
 *
 * The namespace must hold no key at the start, so that List can show
 * exactly this run's keys.
 *
 * Each thread owns its own keys, so the model needs no lock. A key starts
 * with its 4-byte index, which makes every key unique and lets List map a
 * key back to the model. Values are a pseudo-random stream of the key
 * index and a store count.
 *
 * The workload knobs follow Samsung's kvbench: key count, key length,
 * value sizes with ratios, and operation shares. kvbench itself is
 * Apache-2.0 and speaks the Samsung driver opcodes (81h, 90h, A1h, B1h),
 * so this is a new program, not a port.
 *
 * Controls, to show that the checks fail when they should:
 *   --control legacy-opcodes  send the Samsung opcodes instead
 *   --control corrupt-model   change one byte of one expected value
 *
 * Build (in the guest): gcc -O2 -pthread -o kv-bench kv-bench.c
 * Run:                  sudo ./kv-bench [options] /dev/ngXnY
 *
 * Exit status: 0 when every check passed, 1 when a check failed, 2 on a
 * usage or setup error.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

/* The passthrough structure and ioctls of <linux/nvme_ioctl.h>. */
struct nvme_passthru_cmd {
    uint8_t  opcode;
    uint8_t  flags;
    uint16_t rsvd1;
    uint32_t nsid;
    uint32_t cdw2;
    uint32_t cdw3;
    uint64_t metadata;
    uint64_t addr;
    uint32_t metadata_len;
    uint32_t data_len;
    uint32_t cdw10;
    uint32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
    uint32_t timeout_ms;
    uint32_t result;
};
#define NVME_IOCTL_ID      _IO('N', 0x40)
#define NVME_IOCTL_IO_CMD  _IOWR('N', 0x43, struct nvme_passthru_cmd)

#define KV_MAX_KEY      16
#define KV_INDEX_BYTES  4
#define SC_SUCCESS      0x000
#define SC_KEY_ABSENT   0x087           /* KV Key Does Not Exist */
#define SC_MASK         0x7ff           /* status code and type, no DNR/M */
#define MAX_SIZES       8
#define MAX_ERR_PRINT   10
#define MAX_ERR_THREAD  100
#define POISON          0x5a
#define MAX_KEYS        (1u << 24)
#define MAX_VALUE       (16u << 20)
#define MAX_THREADS     256
#define MAX_SHARE       1000000u

enum op { OP_STORE, OP_RETRIEVE, OP_DELETE, OP_EXIST, OP_LIST, OP_NR };

static const char *op_name[OP_NR] = {
    "store", "retrieve", "delete", "exist", "list"
};
static const uint8_t ratified_op[OP_NR] = { 0x01, 0x02, 0x10, 0x14, 0x06 };
/* Samsung KVSSD driver opcodes; the list slot takes Iterate Read. */
static const uint8_t legacy_op[OP_NR] = { 0x81, 0x90, 0xa1, 0xb3, 0xb2 };

struct key_state {
    uint32_t version;                   /* stores so far; 0: never stored */
    uint32_t len;                       /* value length of this version */
    uint8_t  live;
};

struct lat {
    uint64_t *ns;
    uint64_t n;
    uint64_t cap;
};

struct worker {
    pthread_t tid;
    int id;
    uint32_t first;                     /* first key index of this thread */
    uint32_t count;
    uint64_t rng;
    uint8_t *wbuf;
    uint8_t *rbuf;
    uint8_t *ebuf;
    struct lat lat[OP_NR];
    uint64_t ops[OP_NR];
    uint64_t errors;
    uint64_t mismatches;
};

static int fd;
static uint32_t nsid;
static const uint8_t *opcode = ratified_op;
static struct key_state *model;
static uint32_t nkeys = 20000;
static uint64_t ops_per_thread = 25000;
static int nthreads = 4;
static int key_min = 16;
static int key_max = 16;
static uint32_t sizes[MAX_SIZES] = { 512, 2048, 4096 };
static uint32_t ratios[MAX_SIZES] = { 10, 50, 40 };
static int nsizes = 3;
static uint32_t max_value = 4096;
static int mix[4] = { 30, 50, 10, 10 };     /* store retrieve delete exist */
static uint64_t seed = 1;
static int corrupt_key = -1;
static pthread_mutex_t print_lock = PTHREAD_MUTEX_INITIALIZER;

static uint64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static uint64_t xorshift(uint64_t *s)
{
    uint64_t x = *s;

    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    return x;
}

static uint64_t mix64(uint64_t x)
{
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdull;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ull;
    x ^= x >> 33;
    return x ? x : 1;
}

/* Key of index @idx: 4 index bytes, then filler from the index. */
static int make_key(uint32_t idx, uint8_t key[KV_MAX_KEY])
{
    uint64_t s = mix64(seed ^ ((uint64_t)idx << 20) ^ 0x6b6579);
    int len = key_min + (int)(mix64(idx ^ seed) % (uint64_t)(key_max - key_min + 1));

    key[0] = idx >> 24;
    key[1] = idx >> 16;
    key[2] = idx >> 8;
    key[3] = idx;
    for (int i = KV_INDEX_BYTES; i < len; i++) {
        key[i] = (uint8_t)xorshift(&s);
    }
    return len;
}

/* Value of key @idx after store number @version. */
static void make_value(uint32_t idx, uint32_t version, uint32_t len,
                      uint8_t *buf)
{
    uint64_t s = mix64(seed ^ ((uint64_t)idx << 32) ^ version);
    uint32_t i = 0;

    while (len - i >= 8) {
        uint64_t r = xorshift(&s);

        memcpy(buf + i, &r, 8);
        i += 8;
    }
    if (i < len) {
        uint64_t r = xorshift(&s);

        memcpy(buf + i, &r, len - i);
    }
}

/* What the checks expect; --control corrupt-model changes one key. */
static void expected_value(uint32_t idx, uint32_t version, uint32_t len,
                           uint8_t *buf)
{
    make_value(idx, version, len, buf);
    if ((int)idx == corrupt_key && len > 0) {
        buf[0] ^= 0xff;
    }
}

static uint32_t pick_size(struct worker *w)
{
    uint64_t total = 0;
    uint64_t r;

    for (int i = 0; i < nsizes; i++) {
        total += ratios[i];
    }
    r = xorshift(&w->rng) % total;
    for (int i = 0; i < nsizes; i++) {
        if (r < ratios[i]) {
            return sizes[i];
        }
        r -= ratios[i];
    }
    return sizes[nsizes - 1];
}

static void lat_add(struct lat *l, uint64_t ns)
{
    if (l->n == l->cap) {
        uint64_t cap = l->cap ? l->cap * 2 : 4096;
        uint64_t *p = realloc(l->ns, cap * sizeof(*p));

        if (!p) {
            return;
        }
        l->ns = p;
        l->cap = cap;
    }
    l->ns[l->n++] = ns;
}

/*
 * Send one KV command. Key bytes 0-7 go in CDW2-CDW3 and 8-15 in
 * CDW14-CDW15, the key length in CDW11[7:0], and the value size or the
 * host buffer size in CDW10. Return the status code (no DNR or More bit),
 * or -1 when the ioctl failed.
 */
static int kv_cmd(struct worker *w, enum op op, const uint8_t *key, int kl,
                  void *buf, uint32_t len, uint32_t *result)
{
    struct nvme_passthru_cmd c;
    uint8_t k[KV_MAX_KEY] = { 0 };
    uint64_t t0;
    int ret;

    memcpy(k, key, (size_t)kl);
    memset(&c, 0, sizeof(c));
    c.opcode = opcode[op];
    c.nsid = nsid;
    c.addr = (uint64_t)(uintptr_t)buf;
    c.data_len = len;
    c.cdw10 = len;
    c.cdw11 = (uint32_t)kl;
    c.cdw2 = (uint32_t)k[0] | k[1] << 8 | k[2] << 16 | (uint32_t)k[3] << 24;
    c.cdw3 = (uint32_t)k[4] | k[5] << 8 | k[6] << 16 | (uint32_t)k[7] << 24;
    c.cdw14 = (uint32_t)k[8] | k[9] << 8 | k[10] << 16 | (uint32_t)k[11] << 24;
    c.cdw15 = (uint32_t)k[12] | k[13] << 8 | k[14] << 16 |
              (uint32_t)k[15] << 24;
    c.timeout_ms = 10000;

    t0 = now_ns();
    ret = ioctl(fd, NVME_IOCTL_IO_CMD, &c);
    if (w) {
        lat_add(&w->lat[op], now_ns() - t0);
        w->ops[op]++;
    }
    if (result) {
        *result = c.result;
    }
    if (ret < 0) {
        return -1;
    }
    return ret & SC_MASK;
}

static void report(struct worker *w, int is_mismatch, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void report(struct worker *w, int is_mismatch, const char *fmt, ...)
{
    uint64_t n;
    va_list ap;

    if (is_mismatch) {
        n = ++w->mismatches;
    } else {
        n = ++w->errors;
    }
    if (n > MAX_ERR_PRINT) {
        return;
    }
    pthread_mutex_lock(&print_lock);
    printf("KVBENCH_%s thread=%d ", is_mismatch ? "MISMATCH" : "ERROR", w->id);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    pthread_mutex_unlock(&print_lock);
}

static int too_many(struct worker *w)
{
    return w->errors + w->mismatches >= MAX_ERR_THREAD;
}

static void do_store(struct worker *w, uint32_t idx)
{
    struct key_state *ks = &model[idx];
    uint8_t key[KV_MAX_KEY];
    int kl = make_key(idx, key);
    uint32_t len = pick_size(w);
    uint32_t version = ks->version + 1;
    int st;

    make_value(idx, version, len, w->wbuf);
    st = kv_cmd(w, OP_STORE, key, kl, w->wbuf, len, NULL);
    if (st != SC_SUCCESS) {
        report(w, 0, "op=store key=%u len=%u status=%d errno=%d",
               idx, len, st, st < 0 ? errno : 0);
        return;
    }
    ks->version = version;
    ks->len = len;
    ks->live = 1;
}

static void do_retrieve(struct worker *w, uint32_t idx)
{
    struct key_state *ks = &model[idx];
    uint8_t key[KV_MAX_KEY];
    int kl = make_key(idx, key);
    uint32_t result = 0;
    int st;

    /*
     * Fill the buffer so that a byte the device does not write cannot
     * match: the value span gets the true value inverted, the rest a
     * pattern that must stay.
     */
    if (ks->live) {
        make_value(idx, ks->version, ks->len, w->ebuf);
        for (uint32_t i = 0; i < ks->len; i++) {
            w->rbuf[i] = (uint8_t)~w->ebuf[i];
        }
        memset(w->rbuf + ks->len, POISON, max_value - ks->len);
    }
    st = kv_cmd(w, OP_RETRIEVE, key, kl, w->rbuf, max_value, &result);
    if (!ks->live) {
        if (st != SC_KEY_ABSENT) {
            report(w, 1, "op=retrieve key=%u deleted, status=%d want=0x%x",
                   idx, st, SC_KEY_ABSENT);
        }
        return;
    }
    if (st != SC_SUCCESS) {
        report(w, 0, "op=retrieve key=%u status=%d errno=%d", idx, st,
               st < 0 ? errno : 0);
        return;
    }
    if (result != ks->len) {
        report(w, 1, "op=retrieve key=%u size=%u want=%u", idx, result,
               ks->len);
        return;
    }
    for (uint32_t i = ks->len; i < max_value; i++) {
        if (w->rbuf[i] != POISON) {
            report(w, 1, "op=retrieve key=%u len=%u wrote byte %u past the value",
                   idx, ks->len, i);
            return;
        }
    }
    expected_value(idx, ks->version, ks->len, w->ebuf);
    if (memcmp(w->rbuf, w->ebuf, ks->len) != 0) {
        uint32_t at = 0;

        while (at < ks->len && w->rbuf[at] == w->ebuf[at]) {
            at++;
        }
        report(w, 1, "op=retrieve key=%u version=%u len=%u differs at byte %u",
               idx, ks->version, ks->len, at);
    }
}

static void do_delete(struct worker *w, uint32_t idx)
{
    struct key_state *ks = &model[idx];
    uint8_t key[KV_MAX_KEY];
    int kl = make_key(idx, key);
    int st;

    st = kv_cmd(w, OP_DELETE, key, kl, NULL, 0, NULL);
    if (st != SC_SUCCESS) {
        report(w, 0, "op=delete key=%u status=%d errno=%d", idx, st,
               st < 0 ? errno : 0);
        return;
    }
    ks->live = 0;
}

static void do_exist(struct worker *w, uint32_t idx)
{
    uint8_t key[KV_MAX_KEY];
    int kl = make_key(idx, key);
    int want = model[idx].live ? SC_SUCCESS : SC_KEY_ABSENT;
    int st;

    st = kv_cmd(w, OP_EXIST, key, kl, NULL, 0, NULL);
    if (st < 0) {
        report(w, 0, "op=exist key=%u errno=%d", idx, errno);
    } else if (st != want) {
        report(w, 1, "op=exist key=%u status=0x%x want=0x%x", idx, st, want);
    }
}

static void *load_main(void *arg)
{
    struct worker *w = arg;

    for (uint32_t i = 0; i < w->count && !too_many(w); i++) {
        do_store(w, w->first + i);
    }
    return NULL;
}

static void *mixed_main(void *arg)
{
    struct worker *w = arg;
    int total = mix[0] + mix[1] + mix[2] + mix[3];

    for (uint64_t n = 0; n < ops_per_thread && !too_many(w); n++) {
        uint32_t idx = w->first + (uint32_t)(xorshift(&w->rng) % w->count);
        int r = (int)(xorshift(&w->rng) % (uint64_t)total);

        if (r < mix[0]) {
            do_store(w, idx);
        } else if (r < mix[0] + mix[1]) {
            do_retrieve(w, idx);
        } else if (r < mix[0] + mix[1] + mix[2] && model[idx].live) {
            do_delete(w, idx);
        } else {
            /* Exist, also in place of a Delete of a deleted key. */
            do_exist(w, idx);
        }
    }
    return NULL;
}

static void *verify_main(void *arg)
{
    struct worker *w = arg;

    for (uint32_t i = 0; i < w->count && !too_many(w); i++) {
        do_exist(w, w->first + i);
        do_retrieve(w, w->first + i);
    }
    return NULL;
}

static void *delete_main(void *arg)
{
    struct worker *w = arg;
    int odd = 0;

    for (uint32_t i = 0; i < w->count && !too_many(w); i++) {
        uint32_t idx = w->first + i;

        if (model[idx].live && (odd ^= 1)) {
            do_delete(w, idx);
        }
    }
    return NULL;
}

/* Run @fn on every worker and print the phase rate. */
static void run_phase(const char *name, struct worker *ws,
                      void *(*fn)(void *))
{
    uint64_t before = 0;
    uint64_t after = 0;
    uint64_t t0;
    double secs;

    for (int t = 0; t < nthreads; t++) {
        for (int o = 0; o < OP_NR; o++) {
            before += ws[t].ops[o];
        }
    }
    t0 = now_ns();
    for (int t = 0; t < nthreads; t++) {
        if (pthread_create(&ws[t].tid, NULL, fn, &ws[t]) != 0) {
            printf("KVBENCH_SETUP=pthread_create\n");
            exit(2);
        }
    }
    for (int t = 0; t < nthreads; t++) {
        pthread_join(ws[t].tid, NULL);
    }
    secs = (double)(now_ns() - t0) / 1e9;
    for (int t = 0; t < nthreads; t++) {
        for (int o = 0; o < OP_NR; o++) {
            after += ws[t].ops[o];
        }
    }
    printf("KVBENCH_PHASE %s commands=%" PRIu64 " secs=%.2f kiops=%.1f\n",
           name, after - before, secs,
           secs > 0 ? (double)(after - before) / secs / 1000.0 : 0.0);
    fflush(stdout);
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;

    return x < y ? -1 : x > y;
}

static void print_latency(struct worker *ws)
{
    for (int o = 0; o < OP_NR; o++) {
        uint64_t n = 0;
        uint64_t sum = 0;
        uint64_t *all;
        uint64_t k = 0;

        for (int t = 0; t < nthreads; t++) {
            n += ws[t].lat[o].n;
        }
        if (!n) {
            continue;
        }
        all = malloc(n * sizeof(*all));
        if (!all) {
            continue;
        }
        for (int t = 0; t < nthreads; t++) {
            memcpy(all + k, ws[t].lat[o].ns, ws[t].lat[o].n * sizeof(*all));
            k += ws[t].lat[o].n;
        }
        qsort(all, n, sizeof(*all), cmp_u64);
        for (uint64_t i = 0; i < n; i++) {
            sum += all[i];
        }
        printf("KVBENCH_LAT %s n=%" PRIu64 " avg_us=%.1f p50_us=%.1f "
               "p99_us=%.1f max_us=%.1f\n", op_name[o], n,
               (double)sum / (double)n / 1e3, (double)all[n / 2] / 1e3,
               (double)all[n * 99 / 100] / 1e3, (double)all[n - 1] / 1e3);
        free(all);
    }
}

/*
 * Walk the namespace with List and compare the keys to the live keys of
 * the model. Each page starts at the last key of the page before; a live
 * start key must come back first, and is then skipped. FEMU returns keys
 * in table order (kv_index=hash) or byte order (kv_index=lsm) and wraps,
 * so the walk ends on the page where the first key of the walk comes back. Every entry of every page is checked: a key
 * this run never stored, a deleted key, or a key twice in one page is a
 * problem. Return the number of problems, or -1 when a List failed.
 */
static int64_t check_list(struct worker *w, const char *when)
{
    const uint32_t hbs = 256 * 1024;
    uint8_t *buf;
    uint8_t *seen;
    uint32_t *page_of;
    uint8_t start[KV_MAX_KEY] = { 0 };
    uint8_t first[KV_MAX_KEY] = { 0 };
    int start_len = 0;
    int first_len = 0;
    uint64_t returned = 0;
    uint64_t unknown = 0;
    uint64_t dup = 0;
    uint64_t missing = 0;
    uint64_t bad = 0;
    uint64_t live = 0;
    uint32_t pages = 0;
    int64_t problems;
    int cmd_failed = 0;
    int done = 0;

    if (posix_memalign((void **)&buf, 4096, hbs) != 0) {
        printf("KVBENCH_SETUP=list-buffer\n");
        exit(2);
    }
    seen = calloc(nkeys, 1);
    page_of = calloc(nkeys, sizeof(*page_of));
    if (!seen || !page_of) {
        printf("KVBENCH_SETUP=list-buffer\n");
        exit(2);
    }
    while (!done && pages < nkeys + 2u) {
        uint32_t nrk;
        uint32_t pos = 4;
        uint32_t added = 0;
        int start_live = 0;
        int wrapped = 0;
        int st;

        pages++;
        if (start_len >= KV_INDEX_BYTES) {
            uint32_t sidx = (uint32_t)start[0] << 24 | (uint32_t)start[1] << 16 |
                            (uint32_t)start[2] << 8 | start[3];

            start_live = sidx < nkeys && model[sidx].live;
        }
        memset(buf, POISON, hbs);
        st = kv_cmd(w, OP_LIST, start, start_len, buf, hbs, NULL);
        if (st != SC_SUCCESS) {
            report(w, 0, "op=list status=%d errno=%d", st, st < 0 ? errno : 0);
            cmd_failed = 1;
            break;
        }
        memcpy(&nrk, buf, 4);
        if (nrk == 0 && start_live) {
            bad++;
            report(w, 1, "op=list returned no key from a live start key");
        }
        for (uint32_t i = 0; i < nrk; i++) {
            const uint8_t *k = buf + pos + 2;
            uint8_t want[KV_MAX_KEY];
            uint16_t kl;
            uint32_t idx;

            if (pos + 2 > hbs) {
                bad++;
                report(w, 1, "op=list entry %u of %u runs past the buffer", i, nrk);
                done = 1;
                break;
            }
            memcpy(&kl, buf + pos, 2);
            if (kl < 1 || kl > KV_MAX_KEY || pos + 2 + kl > hbs) {
                bad++;
                report(w, 1, "op=list entry %u of %u has key length %u", i, nrk, kl);
                done = 1;
                break;
            }
            pos = (pos + 2 + kl + 3) & ~3u;
            idx = kl < KV_INDEX_BYTES ? UINT32_MAX :
                  (uint32_t)k[0] << 24 | (uint32_t)k[1] << 16 |
                  (uint32_t)k[2] << 8 | k[3];
            if (i == 0 && start_live) {
                if (kl != start_len || memcmp(start, k, kl) != 0) {
                    bad++;
                    report(w, 1, "op=list did not return the live start key first");
                } else {
                    /* Counted on the page before; it may not come back. */
                    page_of[idx] = pages;
                    continue;
                }
            }
            if (idx >= nkeys || make_key(idx, want) != kl ||
                memcmp(want, k, kl) != 0) {
                unknown++;
                report(w, 1, "op=list returned a key this run never stored");
                continue;
            }
            if (page_of[idx] == pages) {
                dup++;
                report(w, 1, "op=list returned key %u twice in one page", idx);
                continue;
            }
            page_of[idx] = pages;
            if (!model[idx].live) {
                unknown++;
                report(w, 1, "op=list returned deleted key %u", idx);
            }
            if (first_len && kl == first_len && memcmp(first, k, kl) == 0) {
                wrapped = 1;
            }
            if (!first_len) {
                memcpy(first, k, kl);
                first_len = kl;
            }
            if (wrapped) {
                /* Past the wrap every key must be one seen before. */
                if (!seen[idx]) {
                    bad++;
                    report(w, 1, "op=list returned new key %u after the wrap", idx);
                }
                continue;
            }
            if (seen[idx]) {
                dup++;
                report(w, 1, "op=list returned key %u twice", idx);
                continue;
            }
            seen[idx] = 1;
            returned++;
            added++;
            memcpy(start, k, kl);
            start_len = kl;
        }
        if (!added || wrapped) {
            done = 1;
        }
    }
    for (uint32_t i = 0; i < nkeys; i++) {
        if (model[i].live) {
            live++;
            if (!seen[i]) {
                missing++;
            }
        }
    }
    if (missing && !cmd_failed) {
        report(w, 1, "op=list %" PRIu64 " live keys missing", missing);
    }
    problems = (int64_t)(unknown + dup + missing + bad);
    printf("KVBENCH_CHECK list(%s) returned=%" PRIu64 " live=%" PRIu64
           " missing=%" PRIu64 " unknown=%" PRIu64 " duplicate=%" PRIu64
           " malformed=%" PRIu64 " %s\n", when, returned, live, missing,
           unknown, dup, bad,
           cmd_failed ? "LIST-FAILED" : problems ? "FAIL" : "ok");
    free(page_of);
    free(seen);
    free(buf);
    return cmd_failed ? -1 : problems;
}

static void *cleanup_main(void *arg)
{
    struct worker *w = arg;

    for (uint32_t i = 0; i < w->count && !too_many(w); i++) {
        if (model[w->first + i].live) {
            do_delete(w, w->first + i);
        }
    }
    return NULL;
}

/* Parse one number in [@min, @max] into @out; return -1 on bad input. */
static int parse_u64(const char *str, uint64_t min, uint64_t max,
                     uint64_t *out)
{
    char *end;
    unsigned long long v;

    errno = 0;
    v = strtoull(str, &end, 0);
    if (errno || end == str || *end || str[0] == '-' || v < min || v > max) {
        return -1;
    }
    *out = v;
    return 0;
}

/* Parse "A,B,C" or "A:B:C" with each value in [@min, @vmax]. */
static int parse_list(const char *s, uint32_t *out, int max, unsigned long min,
                      unsigned long vmax)
{
    int n = 0;
    char *copy = strdup(s);
    char *save = NULL;

    for (char *tok = strtok_r(copy, ",:", &save); tok;
         tok = strtok_r(NULL, ",:", &save)) {
        char *end;
        unsigned long v = strtoul(tok, &end, 0);

        if (n == max || end == tok || *end || tok[0] == '-' || v < min ||
            v > vmax) {
            free(copy);
            return -1;
        }
        out[n++] = (uint32_t)v;
    }
    free(copy);
    return n;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s [options] /dev/ngXnY\n"
        "  -k, --keys N          keys (default 20000)\n"
        "  -o, --ops N           mixed commands per thread (default 25000)\n"
        "  -t, --threads N       threads (default 4)\n"
        "  -l, --key-len A[-B]   key length, 4 to 16 (default 16)\n"
        "  -v, --values LIST     value sizes (default 512,2048,4096)\n"
        "  -r, --ratio LIST      shares of the value sizes (default 10:50:40)\n"
        "  -m, --mix S:R:D:E     Store:Retrieve:Delete:Exist shares\n"
        "                        (default 30:50:10:10)\n"
        "  -s, --seed N          seed (default 1)\n"
        "  -c, --control NAME    legacy-opcodes or corrupt-model\n", prog);
    exit(2);
}

int main(int argc, char **argv)
{
    static const struct option opts[] = {
        { "keys", required_argument, NULL, 'k' },
        { "ops", required_argument, NULL, 'o' },
        { "threads", required_argument, NULL, 't' },
        { "key-len", required_argument, NULL, 'l' },
        { "values", required_argument, NULL, 'v' },
        { "ratio", required_argument, NULL, 'r' },
        { "mix", required_argument, NULL, 'm' },
        { "seed", required_argument, NULL, 's' },
        { "control", required_argument, NULL, 'c' },
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 },
    };
    const char *control = "none";
    struct worker *ws;
    struct worker *w0;
    int nratios = 0;
    int sizes_given = 0;
    uint32_t mixv[4];
    uint64_t errors = 0;
    uint64_t mismatches = 0;
    uint64_t still = 0;
    uint64_t num;
    int ret;
    int c;

    while ((c = getopt_long(argc, argv, "k:o:t:l:v:r:m:s:c:h", opts,
                            NULL)) != -1) {
        switch (c) {
        case 'k':
            if (parse_u64(optarg, 1, MAX_KEYS, &num)) {
                usage(argv[0]);
            }
            nkeys = (uint32_t)num;
            break;
        case 'o':
            if (parse_u64(optarg, 0, 1ull << 40, &ops_per_thread)) {
                usage(argv[0]);
            }
            break;
        case 't':
            if (parse_u64(optarg, 1, MAX_THREADS, &num)) {
                usage(argv[0]);
            }
            nthreads = (int)num;
            break;
        case 'l': {
            char *dash = strchr(optarg, '-');
            uint64_t lo;
            uint64_t hi;

            if (dash) {
                *dash = '\0';
            }
            if (parse_u64(optarg, KV_INDEX_BYTES, KV_MAX_KEY, &lo) ||
                parse_u64(dash ? dash + 1 : optarg, KV_INDEX_BYTES,
                          KV_MAX_KEY, &hi)) {
                usage(argv[0]);
            }
            key_min = (int)lo;
            key_max = (int)hi;
            break;
        }
        case 'v':
            nsizes = parse_list(optarg, sizes, MAX_SIZES, 1, MAX_VALUE);
            sizes_given = 1;
            break;
        case 'r':
            nratios = parse_list(optarg, ratios, MAX_SIZES, 1, MAX_SHARE);
            if (nratios < 0) {
                usage(argv[0]);
            }
            break;
        case 'm':
            if (parse_list(optarg, mixv, 4, 0, MAX_SHARE) != 4 ||
                mixv[0] + mixv[1] + mixv[2] + mixv[3] == 0) {
                usage(argv[0]);
            }
            for (int i = 0; i < 4; i++) {
                mix[i] = (int)mixv[i];
            }
            break;
        case 's':
            if (parse_u64(optarg, 1, UINT64_MAX, &seed)) {
                usage(argv[0]);
            }
            break;
        case 'c':
            control = optarg;
            break;
        default:
            usage(argv[0]);
        }
    }
    if (optind != argc - 1 || nkeys == 0 || nthreads < 1 ||
        (uint32_t)nthreads > nkeys || nsizes < 1 || key_min < KV_INDEX_BYTES ||
        key_max > KV_MAX_KEY || key_min > key_max || seed == 0) {
        usage(argv[0]);
    }
    /* Sizes without shares get equal shares. */
    if (nratios == 0 && sizes_given) {
        for (int i = 0; i < nsizes; i++) {
            ratios[i] = 1;
        }
    } else if (nratios != 0 && nratios != nsizes) {
        usage(argv[0]);
    }
    max_value = 0;
    for (int i = 0; i < nsizes; i++) {
        max_value = sizes[i] > max_value ? sizes[i] : max_value;
    }
    if (strcmp(control, "legacy-opcodes") == 0) {
        opcode = legacy_op;
    } else if (strcmp(control, "corrupt-model") == 0) {
        corrupt_key = (int)(nkeys / 2);
    } else if (strcmp(control, "none") != 0) {
        usage(argv[0]);
    }

    fd = open(argv[optind], O_RDWR);
    if (fd < 0) {
        printf("KVBENCH_SETUP=open-%s errno=%d\n", argv[optind], errno);
        return 2;
    }
    ret = ioctl(fd, NVME_IOCTL_ID);
    if (ret <= 0) {
        printf("KVBENCH_SETUP=nsid errno=%d (use a /dev/ngXnY node)\n", errno);
        return 2;
    }
    nsid = (uint32_t)ret;
    model = calloc(nkeys, sizeof(*model));
    ws = calloc((size_t)nthreads, sizeof(*ws));
    if (!model || !ws) {
        printf("KVBENCH_SETUP=memory\n");
        return 2;
    }
    for (int t = 0; t < nthreads; t++) {
        struct worker *w = &ws[t];
        uint32_t per = nkeys / (uint32_t)nthreads;

        w->id = t;
        w->first = (uint32_t)t * per;
        w->count = t == nthreads - 1 ? nkeys - w->first : per;
        w->rng = mix64(seed * 0x9e3779b97f4a7c15ull + (uint64_t)t);
        if (posix_memalign((void **)&w->wbuf, 4096, max_value) ||
            posix_memalign((void **)&w->rbuf, 4096, max_value) ||
            posix_memalign((void **)&w->ebuf, 4096, max_value)) {
            printf("KVBENCH_SETUP=memory\n");
            return 2;
        }
    }

    printf("KVBENCH_CONFIG dev=%s nsid=%u keys=%u ops_per_thread=%" PRIu64
           " threads=%d key_len=%d-%d values=", argv[optind], nsid, nkeys,
           ops_per_thread, nthreads, key_min, key_max);
    for (int i = 0; i < nsizes; i++) {
        printf("%s%u:%u", i ? "," : "", sizes[i], ratios[i]);
    }
    printf(" mix=%d:%d:%d:%d seed=%" PRIu64 " control=%s\n", mix[0], mix[1],
           mix[2], mix[3], seed, control);
    fflush(stdout);

    /*
     * The checks of List need a namespace that holds only this run's keys,
     * and the run deletes its keys at the end.
     */
    w0 = &ws[0];
    if (check_list(w0, "before") > 0) {
        printf("KVBENCH_SETUP=namespace-not-empty\n");
        return 2;
    }
    run_phase("load", ws, load_main);
    if (corrupt_key >= 0) {
        /* Check the changed key before the mixed phase can delete it. */
        struct worker *owner = &ws[nthreads - 1];

        for (int t = 0; t < nthreads; t++) {
            if ((uint32_t)corrupt_key >= ws[t].first &&
                (uint32_t)corrupt_key < ws[t].first + ws[t].count) {
                owner = &ws[t];
            }
        }
        do_retrieve(owner, (uint32_t)corrupt_key);
    }
    run_phase("mixed", ws, mixed_main);
    print_latency(ws);
    run_phase("verify", ws, verify_main);
    check_list(w0, "after-verify");
    run_phase("delete", ws, delete_main);
    run_phase("verify-after-delete", ws, verify_main);
    check_list(w0, "after-delete");
    run_phase("cleanup", ws, cleanup_main);
    check_list(w0, "after-cleanup");

    for (int t = 0; t < nthreads; t++) {
        errors += ws[t].errors;
        mismatches += ws[t].mismatches;
    }
    for (uint32_t i = 0; i < nkeys; i++) {
        still += model[i].live;
    }
    printf("KVBENCH_COUNTS");
    for (int o = 0; o < OP_NR; o++) {
        uint64_t n = 0;

        for (int t = 0; t < nthreads; t++) {
            n += ws[t].ops[o];
        }
        printf(" %s=%" PRIu64, op_name[o], n);
    }
    printf(" live_keys=%" PRIu64 "\n", still);
    printf("KVBENCH_ERRORS=%" PRIu64 "\n", errors);
    printf("KVBENCH_MISMATCHES=%" PRIu64 "\n", mismatches);
    printf("KVBENCH_RESULT=%s\n", errors || mismatches ? "FAIL" : "PASS");
    close(fd);
    return errors || mismatches ? 1 : 0;
}
