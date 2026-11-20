/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * The write plan of bbssd preconditioning (precon_fill_pct). Pure
 * functions with no FTL state: the FTL, the unit test
 * (tests/unit/test-precon-math.c) and the qtest that replays the plan
 * through NVMe writes all use this header, so all three write the same
 * pages in the same order.
 *
 * Phase 1 writes logical pages 0 to fill - 1 once, in order. Phase 2
 * writes overwrite more pages, each one of the filled pages: in order
 * and round again for "seq", or a uniform draw for "rand".
 */
#ifndef __FEMU_BBSSD_FTL_PRECON_MATH_H
#define __FEMU_BBSSD_FTL_PRECON_MATH_H

#include <stdint.h>
#include <stdbool.h>

/* the most phase 2 writes, in percent of the filled pages */
#define PRECON_OVERWRITE_MAX_PCT 1000

/* step of the splitmix64 sequence */
#define PRECON_GOLDEN 0x9e3779b97f4a7c15ULL

typedef struct PreconPlan {
    uint64_t fill;          /* phase 1 pages */
    uint64_t overwrite;     /* phase 2 writes */
    bool seq;               /* phase 2 in LPN order */
    uint64_t state;         /* rand: the splitmix64 state */
    uint64_t done;          /* writes planned so far, both phases */
} PreconPlan;

/* phase 1 pages: @fill_pct percent of @pages logical pages, rounded down */
static inline uint64_t precon_fill_pages(uint64_t pages, uint32_t fill_pct)
{
    return (uint64_t)(((unsigned __int128)pages * fill_pct) / 100);
}

/* phase 2 writes: @pct percent of @fill, rounded down */
static inline uint64_t precon_overwrite_pages(uint64_t fill, uint32_t pct)
{
    return (uint64_t)(((unsigned __int128)fill * pct) / 100);
}

static inline void precon_plan_init(PreconPlan *p, uint64_t pages,
                                    uint32_t fill_pct, uint32_t overwrite_pct,
                                    bool seq, uint64_t seed)
{
    p->fill = precon_fill_pages(pages, fill_pct);
    p->overwrite = precon_overwrite_pages(p->fill, overwrite_pct);
    p->seq = seq;
    p->state = seed;
    p->done = 0;
}

/* writes of the whole plan */
static inline uint64_t precon_plan_total(const PreconPlan *p)
{
    return p->fill + p->overwrite;
}

/* the splitmix64 output after one step of @state */
static inline uint64_t precon_rand_next(uint64_t *state)
{
    uint64_t z = (*state += PRECON_GOLDEN);

    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

/* a uniform value below @n from a 64-bit draw, with no modulo bias */
static inline uint64_t precon_scale(uint64_t z, uint64_t n)
{
    return (uint64_t)(((unsigned __int128)z * n) >> 64);
}

/*
 * The logical page of the next write, or false when the plan is done.
 * The caller writes the pages in the order this returns them.
 */
static inline bool precon_plan_next(PreconPlan *p, uint64_t *lpn)
{
    uint64_t i = p->done;

    if (i >= precon_plan_total(p)) {
        return false;
    }
    p->done++;
    if (i < p->fill) {
        *lpn = i;
    } else if (p->seq) {
        *lpn = (i - p->fill) % p->fill;
    } else {
        *lpn = precon_scale(precon_rand_next(&p->state), p->fill);
    }
    return true;
}

#endif
