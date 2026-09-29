/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * The guest library against the device's ring consumer, with a thread
 * standing in for the register page. The BAR is allocated at its exact
 * size so a sanitizer build catches any access outside it.
 */
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "cca-ring.h"
#include "cca.h"

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, \
                #cond); \
        abort(); \
    } \
} while (0)

#define NOPS 1000000u

static uint8_t *bar;
static CcaRingHost host;
static pthread_t host_thread;
static int host_stop;
static int host_paused;
static int host_idle;

static uint32_t *reg(unsigned off)
{
    return (uint32_t *)(bar + off);
}

static uint8_t *shm(void)
{
    return bar + CCA_SHM_OFFSET;
}

static struct cca_ring *ring(uint32_t off)
{
    return (struct cca_ring *)(shm() + off);
}

static void host_format(void)
{
    cca_ring_format(&host, shm());
    __atomic_store_n(reg(CCA_REG_FATAL_REASON), 0, __ATOMIC_SEQ_CST);
    __atomic_store_n((uint64_t *)(bar + CCA_REG_COMPLETED), 0,
                     __ATOMIC_SEQ_CST);
    __atomic_store_n(reg(CCA_REG_STATUS), CCA_STATUS_READY, __ATOMIC_SEQ_CST);
}

/* Answer NOP with 0 and everything else with -EINVAL, echoing the tag. */
static void *host_main(void *opaque)
{
    (void)opaque;
    while (!__atomic_load_n(&host_stop, __ATOMIC_ACQUIRE)) {
        struct cca_ctrl_cmd_s cmd;
        uint32_t slot;
        int rc;

        if (__atomic_exchange_n(reg(CCA_REG_RESET), 0, __ATOMIC_SEQ_CST)) {
            host_format();
        }
        if (__atomic_load_n(&host_paused, __ATOMIC_ACQUIRE)) {
            __atomic_store_n(&host_idle, 1, __ATOMIC_RELEASE);
            sched_yield();
            continue;
        }
        while ((rc = cca_ring_pop(&host, &slot, &cmd)) == 1) {
            struct cca_ctrl_resp_s resp = {
                .status = cmd.cmd == CCA_CTRL_NOP ? 0 : -EINVAL,
                .lpn_start = cmd.lpn_start,
                .tag = cmd.tag,
            };

            if (!cca_ring_complete(&host, slot, &resp)) {
                break;
            }
            __atomic_add_fetch((uint64_t *)(bar + CCA_REG_COMPLETED), 1,
                               __ATOMIC_SEQ_CST);
        }
        if (host.fatal) {
            __atomic_store_n(reg(CCA_REG_FATAL_REASON), host.fatal,
                             __ATOMIC_SEQ_CST);
            __atomic_or_fetch(reg(CCA_REG_STATUS), CCA_STATUS_FATAL,
                              __ATOMIC_SEQ_CST);
        }
        if (rc == 0) {
            sched_yield();
        }
    }
    return NULL;
}

/* Returns once the host thread has come round and seen the pause. */
static void pause_host(int paused)
{
    __atomic_store_n(&host_idle, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&host_paused, paused, __ATOMIC_SEQ_CST);
    while (paused && !__atomic_load_n(&host_idle, __ATOMIC_SEQ_CST)) {
        sched_yield();
    }
}

/*
 * The device applies RESET inside the register write; this page cannot
 * trap it, so let the host thread go round once before continuing.
 */
static void ring_reset(struct cca_dev *d)
{
    CHECK(cca_reset(d, 0) == 0);
    pause_host(1);
    pause_host(0);
}

static void wait_fatal(uint32_t reason)
{
    while (!(__atomic_load_n(reg(CCA_REG_STATUS), __ATOMIC_ACQUIRE) &
             CCA_STATUS_FATAL)) {
        sched_yield();
    }
    CHECK(*reg(CCA_REG_FATAL_REASON) == reason);
}

static uint64_t completed(void)
{
    return __atomic_load_n((uint64_t *)(bar + CCA_REG_COMPLETED),
                           __ATOMIC_ACQUIRE);
}

/* A million NOPs, synchronous and batched, across many ring wraps. */
static void nops(struct cca_dev *d)
{
    static unsigned char seen[CCA_RING_COUNT];
    struct cca_completion done[256];
    uint64_t base = completed();
    uint64_t sent = 0;
    unsigned i;

    for (i = 0; i < 5000; i++) {
        CHECK(cca_nop(d) == 0);
    }
    sent += 5000;
    while (sent < NOPS) {
        unsigned batch = 1 + (unsigned)(sent % CCA_RING_COUNT);
        unsigned got = 0;

        if (sent + batch > NOPS) {
            batch = NOPS - sent;
        }
        memset(seen, 0, sizeof(seen));
        for (i = 0; i < batch; i++) {
            CHECK(cca_submit(d, CCA_CTRL_NOP, CCA_SUBMIT_DEFER, 0, 0,
                             ((sent + i) << 12) | i) == 0);
        }
        cca_kick(d);
        while (got < batch) {
            int n = cca_reap(d, done, 256, 5000);

            CHECK(n > 0);
            for (i = 0; i < (unsigned)n; i++) {
                uint64_t idx = done[i].tag & 0xfff;

                CHECK(done[i].r.status == 0);
                CHECK(idx < batch && (done[i].tag >> 12) == sent + idx);
                CHECK(!seen[idx]);
                seen[idx] = 1;
            }
            got += n;
        }
        sent += batch;
    }
    CHECK(completed() - base == NOPS);
}

/* All 2048 slots in flight at once, then one too many. */
static void all_slots(struct cca_dev *d)
{
    static unsigned char seen[CCA_RING_COUNT];
    struct cca_completion done[CCA_RING_COUNT];
    unsigned got = 0;
    unsigned i;

    ring_reset(d);
    pause_host(1);
    for (i = 0; i < CCA_RING_COUNT; i++) {
        CHECK(cca_submit(d, CCA_CTRL_NOP, 0, 0, 0, i) == 0);
    }
    CHECK(cca_submit(d, CCA_CTRL_NOP, 0, 0, 0, 9999) == -EAGAIN);
    memset(seen, 0, sizeof(seen));
    for (i = 0; i < CCA_RING_COUNT; i++) {
        uint32_t slot = ring(CCA_REQ_RING_OFFSET)->entries[i];

        CHECK(slot < CCA_RING_COUNT && !seen[slot]);
        seen[slot] = 1;
    }
    CHECK(seen[0] && seen[CCA_RING_COUNT - 1]);
    pause_host(0);
    memset(seen, 0, sizeof(seen));
    while (got < CCA_RING_COUNT) {
        int n = cca_reap(d, done, CCA_RING_COUNT, 5000);

        CHECK(n > 0);
        for (i = 0; i < (unsigned)n; i++) {
            CHECK(done[i].tag < CCA_RING_COUNT && !seen[done[i].tag]);
            seen[done[i].tag] = 1;
        }
        got += n;
    }
    CHECK(cca_nop(d) == 0);
}

/* Device errors come back as statuses, not transport failures. */
static void statuses(struct cca_dev *d)
{
    struct cca_ctrl_cmd_s cmd = { .cmd = 7, .tag = 42 };
    struct cca_result r;

    CHECK(cca_call_raw(d, &cmd, &r) == -EINVAL && r.status == -EINVAL);
    CHECK(cca_pin(d, 1, CCA_WHOLE, &r) == -EINVAL);
    CHECK(cca_submit(d, CCA_CTRL_NOP, 0x8000, 0, 0, 0) == -EINVAL);
}

static void fatal_ring(struct cca_dev *d)
{
    struct cca_ring *req = ring(CCA_REQ_RING_OFFSET);

    ring_reset(d);
    pause_host(1);
    __atomic_store_n(&req->head, 5000, __ATOMIC_RELEASE);
    pause_host(0);
    wait_fatal(CCA_FATAL_RING);
    CHECK(cca_nop(d) == -EPROTO);
    ring_reset(d);
    CHECK(!(*reg(CCA_REG_STATUS) & CCA_STATUS_FATAL));
    CHECK(cca_nop(d) == 0);
}

static void fatal_slot(struct cca_dev *d)
{
    struct cca_ring *req = ring(CCA_REQ_RING_OFFSET);

    ring_reset(d);
    pause_host(1);
    req->entries[0] = CCA_RING_COUNT;
    __atomic_store_n(&req->head, 1, __ATOMIC_RELEASE);
    pause_host(0);
    wait_fatal(CCA_FATAL_SLOT);
    ring_reset(d);
    CHECK(cca_nop(d) == 0);
}

/* A guest that never reaps overflows the response ring. */
static void fatal_response(struct cca_dev *d)
{
    struct cca_ring *req = ring(CCA_REQ_RING_OFFSET);
    struct cca_ring *resp = ring(CCA_RESP_RING_OFFSET);
    uint32_t i;

    ring_reset(d);
    pause_host(1);
    for (i = 0; i < CCA_RING_COUNT; i++) {
        req->entries[i] = i;
    }
    __atomic_store_n(&req->head, CCA_RING_COUNT, __ATOMIC_RELEASE);
    pause_host(0);
    while (__atomic_load_n(&resp->head, __ATOMIC_ACQUIRE) != CCA_RING_COUNT) {
        sched_yield();
    }
    req->entries[0] = 0;
    __atomic_store_n(&req->head, CCA_RING_COUNT + 1, __ATOMIC_RELEASE);
    wait_fatal(CCA_FATAL_RESPONSE);
    ring_reset(d);
    CHECK(cca_nop(d) == 0);
}

static uint64_t rng = 88172645463325252ull;

static uint32_t next_random(void)
{
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return (uint32_t)rng;
}

/*
 * Arbitrary guest writes to every shared index: the consumer must only
 * stop with a reason, never touch memory beyond the buffer.
 */
static void fuzz(void)
{
    uint8_t *mem = malloc(CCA_SHM_SIZE);
    CcaRingHost h;
    struct cca_ring *req;
    struct cca_ring *resp;
    unsigned i;
    unsigned fatal = 0;
    unsigned done = 0;

    CHECK(mem);
    cca_ring_format(&h, mem);
    req = (struct cca_ring *)(mem + CCA_REQ_RING_OFFSET);
    resp = (struct cca_ring *)(mem + CCA_RESP_RING_OFFSET);
    for (i = 0; i < 200000; i++) {
        struct cca_ctrl_cmd_s cmd;
        struct cca_ctrl_resp_s r = { 0 };
        uint32_t slot;
        uint32_t pick = next_random() % 8;
        int rc;

        if (pick == 0) {
            req->head = next_random();
        } else if (pick == 1) {
            req->head = h.req_tail + next_random() % 4;
        } else if (pick == 2) {
            resp->tail = next_random();
        } else if (pick == 3) {
            resp->tail = h.resp_head - next_random() % 4;
        } else if (pick == 4) {
            /* Anything a guest could store in the ring headers. */
            uint32_t *word = (uint32_t *)(next_random() % 2 ? req : resp);

            word[next_random() % 32] = next_random();
        }
        req->entries[next_random() % CCA_RING_COUNT] =
            next_random() % 5 ? next_random() % CCA_RING_COUNT : next_random();
        rc = cca_ring_pop(&h, &slot, &cmd);
        if (rc == 1) {
            CHECK(slot < CCA_RING_COUNT);
            if (cca_ring_complete(&h, slot, &r)) {
                done++;
            }
        }
        if (h.fatal) {
            CHECK(h.fatal >= CCA_FATAL_RING && h.fatal <= CCA_FATAL_RESPONSE);
            fatal++;
            cca_ring_format(&h, mem);
        }
    }
    CHECK(fatal > 0 && done > 0);
    free(mem);
}

int main(void)
{
    struct cca_dev *d;

    bar = malloc(CCA_BAR_SIZE);
    CHECK(bar);
    memset(bar, 0, CCA_BAR_SIZE);
    *reg(CCA_REG_MAGIC) = CCA_SHMEM_MAGIC;
    *reg(CCA_REG_VERSION) = CCA_LAYOUT_VERSION;
    host_format();
    CHECK(pthread_create(&host_thread, NULL, host_main, NULL) == 0);

    CHECK(cca_open_map(bar, &d) == 0);
    nops(d);
    all_slots(d);
    statuses(d);
    fatal_ring(d);
    fatal_slot(d);
    fatal_response(d);
    CHECK(cca_nop(d) == 0);
    cca_close(d);

    /* A leftover owner's indices force a ring reset on open. */
    pause_host(1);
    ring(CCA_REQ_RING_OFFSET)->head = 3;
    ring(CCA_REQ_RING_OFFSET)->tail = 3;
    pause_host(0);
    CHECK(cca_open_map(bar, &d) == 0);
    pause_host(1);
    CHECK(ring(CCA_REQ_RING_OFFSET)->head == 0);
    pause_host(0);
    CHECK(cca_nop(d) == 0);
    cca_close(d);

    __atomic_store_n(&host_stop, 1, __ATOMIC_RELEASE);
    pthread_join(host_thread, NULL);
    fuzz();
    free(bar);
    puts("CXL CCA ring: 1M NOPs, all slots, fatal reasons, reset, fuzz PASS");
    return 0;
}
