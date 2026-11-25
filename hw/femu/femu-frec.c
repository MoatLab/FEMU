/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * The fault record ring of events_file (femu-frec.h).
 *
 * Each slot carries its own sequence word, as a seqlock with one record
 * under it. A reader checks that the word names the record it expects
 * before and after its copy, so a slot that the producer reuses in a
 * window is skipped. The producer never waits for a reader.
 *
 * The record moves as 64-bit words with relaxed atomic loads and stores.
 * A copy that overlaps a reuse then reads stale or mixed words, never
 * undefined ones, and the second look at the sequence word rejects it:
 *
 *   producer                          reader
 *   seq = 2k+1 (relaxed)              s1 = seq (acquire)
 *   release fence                     words (relaxed)
 *   words (relaxed)                   acquire fence
 *   seq = 2k+2 (release)              s2 = seq; keep if s1 == s2 == 2k+2
 */
#include "qemu/osdep.h"
#include "femu-fsched.h"
#include "femu-frec.h"

static inline uint64_t fr_load(const uint64_t *p)
{
    return __atomic_load_n(p, __ATOMIC_ACQUIRE);
}

static inline void fr_store(uint64_t *p, uint64_t v)
{
    __atomic_store_n(p, v, __ATOMIC_RELEASE);
}

#ifdef FEMU_FR_TEST_HOOKS
/* unit test: runs inside a copy, between its words and its second look */
static void (*fr_test_mid_copy)(void);
/* unit test: runs between the tail load and the head load */
static void (*fr_test_mid_ends)(const FemuFrRing *r);
#endif

/*
 * Tail first, then head: the consumer only moves the tail up to a head it
 * has seen, so a head loaded later is never below the tail. The other
 * order lets the tail pass a stale head, and head - tail wraps.
 */
static uint64_t fr_ends(const FemuFrRing *r, uint64_t *t)
{
    *t = fr_load(&r->tail);
#ifdef FEMU_FR_TEST_HOOKS
    if (fr_test_mid_ends) {
        fr_test_mid_ends(r);
    }
#endif
    return fr_load(&r->head);
}

static void fr_words_put(FemuFrSlot *s, const FemuFrRec *rec)
{
    uint64_t w[FEMU_FR_WORDS];

    memcpy(w, rec, sizeof(w));
    for (size_t i = 0; i < FEMU_FR_WORDS; i++) {
        __atomic_store_n(&s->w[i], w[i], __ATOMIC_RELAXED);
    }
}

static void fr_words_get(const FemuFrSlot *s, FemuFrRec *out)
{
    uint64_t w[FEMU_FR_WORDS];

    for (size_t i = 0; i < FEMU_FR_WORDS; i++) {
        w[i] = __atomic_load_n(&s->w[i], __ATOMIC_RELAXED);
    }
    memcpy(out, w, sizeof(w));
}

void femu_fr_init(FemuFrRing *r, FemuFrSlot *slot, uint32_t size,
                  bool window)
{
    memset(r, 0, sizeof(*r));
    r->slot = slot;
    r->size = size;
    r->window = window;
}

/* the first FEMU_FR_DROP_RANGES ranges; a run of ids extends the last */
static void fr_note_drop(FemuFrRing *r, uint64_t id)
{
    uint32_t n = r->nr_drop;

    if (n && r->drop[n - 1].hi + 1 == id) {
        fr_store(&r->drop[n - 1].hi, id);
        return;
    }
    if (n == FEMU_FR_DROP_RANGES) {
        return;
    }
    r->drop[n].lo = id;
    fr_store(&r->drop[n].hi, id);
    __atomic_store_n(&r->nr_drop, n + 1, __ATOMIC_RELEASE);
}

uint64_t femu_fr_put(FemuFrRing *r, FemuFrRec *rec)
{
    uint64_t id = r->next_id + 1;
    uint64_t k = r->head;
    FemuFrSlot *s;

    /* every record takes an id, so a child can name a dropped parent */
    fr_store(&r->next_id, id);
    rec->id = id;
    if (r->window) {
        if (k >= r->size) {
            fr_store(&r->overwritten, r->overwritten + 1);
        }
    } else if (k - fr_load(&r->tail) >= r->size) {
        /* the consumer is behind: drop the new record, never an old one */
        fr_store(&r->dropped, r->dropped + 1);
        fr_note_drop(r, id);
        return id;
    }
    s = &r->slot[k % r->size];
    __atomic_store_n(&s->seq, 2 * k + 1, __ATOMIC_RELAXED);
    /* a reader that sees the record also sees the odd word before it */
    __atomic_thread_fence(__ATOMIC_RELEASE);
    fr_words_put(s, rec);
    fr_store(&s->seq, 2 * k + 2);
    fr_store(&r->head, k + 1);
    return id;
}

/* record @k from its slot; false when the producer has reused the slot */
static bool fr_copy(const FemuFrRing *r, uint64_t k, FemuFrRec *out)
{
    const FemuFrSlot *s = &r->slot[k % r->size];
    uint64_t want = 2 * k + 2;

    if (fr_load(&s->seq) != want) {
        return false;
    }
    fr_words_get(s, out);
#ifdef FEMU_FR_TEST_HOOKS
    if (fr_test_mid_copy) {
        fr_test_mid_copy();
    }
#endif
    /* the words are read before the second look at the sequence word */
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    return __atomic_load_n(&s->seq, __ATOMIC_RELAXED) == want;
}

uint32_t femu_fr_read(const FemuFrRing *r, FemuFrRec *out, uint32_t max)
{
    uint64_t t;
    uint64_t h = fr_ends(r, &t);
    uint32_t n = 0;

    if (r->window) {
        t = h > r->size ? h - r->size : 0;
    }
    if (h - t > max) {
        t = h - max;
    }
    for (uint64_t k = t; k < h; k++) {
        if (fr_copy(r, k, &out[n])) {
            n++;
        }
    }
    return n;
}

bool femu_fr_peek(const FemuFrRing *r, FemuFrRec *out)
{
    uint64_t t = r->tail;

    if (t == fr_load(&r->head)) {
        return false;
    }
    /* the producer does not reuse this slot before the tail moves */
    fr_words_get(&r->slot[t % r->size], out);
    return true;
}

void femu_fr_release(FemuFrRing *r)
{
    fr_store(&r->tail, r->tail + 1);
}

bool femu_fr_pop(FemuFrRing *r, FemuFrRec *out)
{
    if (!femu_fr_peek(r, out)) {
        return false;
    }
    femu_fr_release(r);
    return true;
}

uint64_t femu_fr_pending(const FemuFrRing *r)
{
    uint64_t t;
    uint64_t h = fr_ends(r, &t);

    return h - t;
}

uint32_t femu_fr_dropped_ids(const FemuFrRing *r, FemuFrIdRange *out)
{
    uint32_t n = __atomic_load_n(&r->nr_drop, __ATOMIC_ACQUIRE);

    for (uint32_t i = 0; i < n; i++) {
        out[i].lo = r->drop[i].lo;
        out[i].hi = fr_load(&r->drop[i].hi);
    }
    return n;
}

const char *femu_fr_name_origin(uint8_t v)
{
    return v == FEMU_FR_ORIGIN_SCHED_CMD ? "sched-cmd" : "?";
}

const char *femu_fr_name_phase(uint8_t v)
{
    switch (v) {
    case FEMU_FR_PHASE_SELECT:
        return "select";
    case FEMU_FR_PHASE_APPLY:
        return "apply";
    }
    return "?";
}

const char *femu_fr_name_outcome(uint8_t v)
{
    switch (v) {
    case FEMU_FR_OUT_SELECTED:
        return "selected";
    case FEMU_FR_OUT_SUPERSEDED:
        return "superseded";
    case FEMU_FR_OUT_NO_EFFECT:
        return "no-effect";
    case FEMU_FR_OUT_DONE:
        return "done";
    }
    return "?";
}

const char *femu_fr_name_why(uint8_t v)
{
    switch (v) {
    case FEMU_FS_WHY_FUA:
        return "fua";
    case FEMU_FS_WHY_PRE:
        return "pre";
    case FEMU_FS_WHY_HANG:
        return "hang";
    case FEMU_FS_WHY_PLP:
        return "plp";
    case FEMU_FS_WHY_ATOMIC:
        return "atomic";
    case FEMU_FS_WHY_NO_BUFFER:
        return "no-buffer";
    case FEMU_FS_WHY_CMD_FAILED:
        return "cmd-failed";
    case FEMU_FS_WHY_DURABLE:
        return "durable";
    }
    return "?";
}

int femu_fr_json(const FemuFrRec *rec, char *buf, size_t len)
{
    char cause[32] = "";
    char status[24] = "";
    char why[32] = "";
    char pages[40] = "";
    int n;

    if (rec->cause) {
        snprintf(cause, sizeof(cause), ",\"cause\":%" PRIu64, rec->cause);
    }
    if (rec->status) {
        snprintf(status, sizeof(status), ",\"status\":%u", rec->status);
    }
    if (rec->outcome == FEMU_FR_OUT_NO_EFFECT) {
        snprintf(why, sizeof(why), ",\"reason\":\"%s\"",
                 femu_fr_name_why(rec->why));
    }
    /* the exposure a lie left: buffered pages a cut would roll back */
    if (rec->phase == FEMU_FR_PHASE_APPLY &&
        rec->outcome == FEMU_FR_OUT_DONE) {
        snprintf(pages, sizeof(pages), ",\"%s\":%u",
                 rec->act == FEMU_FS_ACT_FLUSH_LIE ?
                 "buffered_at_flush_lie" : "lie_pages", rec->pages);
    }
    n = snprintf(buf, len,
                 "{\"id\":%" PRIu64 "%s,\"origin\":\"%s\",\"line\":%u,"
                 "\"match\":%" PRIu64 ",\"action\":\"%s\",\"phase\":\"%s\","
                 "\"step\":%" PRIu64 ",\"nsid\":%u,\"sqid\":%u,\"cid\":%u,"
                 "\"opc\":%u,\"fua\":%s,\"slba\":%" PRIu64 ",\"nlb\":%u,"
                 "\"outcome\":\"%s\"%s%s%s}\n",
                 rec->id, cause, femu_fr_name_origin(rec->origin), rec->line,
                 rec->match, femu_fs_act_name(rec->act),
                 femu_fr_name_phase(rec->phase), rec->step, rec->nsid,
                 rec->sqid, rec->cid, rec->opc, rec->fua ? "true" : "false",
                 rec->slba, rec->nlb, femu_fr_name_outcome(rec->outcome), why,
                 pages, status);
    return n;
}
