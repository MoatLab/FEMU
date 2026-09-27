/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FEMU_HYBRID_ORACLE_H
#define FEMU_HYBRID_ORACLE_H

#include <assert.h>

/*
 * Reference for FEMU's simplified BAST policy, independent of its L2P and
 * allocator. Store the actual program history rather than fill/sequence
 * counters. An invalidated program still occupies its slot until a merge.
 *
 * Every media write enters a dedicated logical-block log, including initial
 * writes. After each program, merge the fullest log if it is full or all logs
 * are occupied; ties use the first slot. A complete ordered history switches;
 * otherwise copy each live logical page once. Physical line GC, allocation
 * failure and buffer coalescing are outside this model. Call write only for
 * pages reaching NAND, not for writes still held in the volatile cache.
 */
typedef struct HybridOracle {
    unsigned pages_per_block;
    unsigned log_count;
    unsigned logical_pages;
    int64_t *history;
    bool *live;
    uint64_t programs;
    uint64_t copies;
    uint64_t switches;
    uint64_t merges;
} HybridOracle;

static inline void hybrid_oracle_init(HybridOracle *o, unsigned pages,
                                      unsigned logs, unsigned logical_pages)
{
    unsigned i;

    assert(pages && logs && logical_pages && logical_pages % pages == 0);
    memset(o, 0, sizeof(*o));
    o->pages_per_block = pages;
    o->log_count = logs;
    o->logical_pages = logical_pages;
    o->history = malloc(sizeof(*o->history) * pages * logs);
    o->live = calloc(logical_pages, sizeof(*o->live));
    assert(o->history && o->live);
    for (i = 0; i < pages * logs; i++) {
        o->history[i] = -1;
    }
}

static inline void hybrid_oracle_trim(HybridOracle *o, unsigned lpn)
{
    assert(lpn < o->logical_pages);
    o->live[lpn] = false;
}

static inline void hybrid_oracle_write(HybridOracle *o, unsigned lpn)
{
    unsigned pages = o->pages_per_block;
    unsigned log;
    unsigned slot;
    unsigned active = 0;
    unsigned fullest = 0;
    unsigned victim = 0;
    unsigned base;
    bool ordered = true;

    assert(lpn < o->logical_pages);
    for (log = 0; log < o->log_count; log++) {
        int64_t first = o->history[log * pages];

        if (first >= 0 && first / pages == lpn / pages) {
            break;
        }
    }
    if (log == o->log_count) {
        for (log = 0; log < o->log_count; log++) {
            if (o->history[log * pages] < 0) {
                break;
            }
        }
    }
    assert(log < o->log_count);
    for (slot = 0; slot < pages; slot++) {
        if (o->history[log * pages + slot] < 0) {
            break;
        }
    }
    assert(slot < pages);
    o->history[log * pages + slot] = lpn;
    o->live[lpn] = true;
    o->programs++;

    for (log = 0; log < o->log_count; log++) {
        for (slot = 0; slot < pages; slot++) {
            if (o->history[log * pages + slot] < 0) {
                break;
            }
        }
        active += slot != 0;
        if (slot > fullest) {
            fullest = slot;
            victim = log;
        }
    }
    if (fullest < pages && active < o->log_count) {
        return;
    }

    base = o->history[victim * pages] / pages * pages;
    for (slot = 0; slot < pages; slot++) {
        if (o->history[victim * pages + slot] != base + slot) {
            ordered = false;
        }
    }
    if (ordered) {
        o->switches++;
    } else {
        o->merges++;
        for (slot = 0; slot < pages; slot++) {
            o->copies += o->live[base + slot];
        }
    }
    for (slot = 0; slot < pages; slot++) {
        o->history[victim * pages + slot] = -1;
    }
}

static inline void hybrid_oracle_destroy(HybridOracle *o)
{
    free(o->history);
    free(o->live);
}

#endif
