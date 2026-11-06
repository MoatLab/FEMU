/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Math of the bbssd raw bit error model (rber_ppb). Pure functions with no
 * FTL state, so the unit test (tests/unit/test-rber-math.c) builds them
 * alone.
 */
#ifndef __FEMU_BBSSD_FTL_RBER_MATH_H
#define __FEMU_BBSSD_FTL_RBER_MATH_H

#include <stdbool.h>
#include <stdint.h>
#include <math.h>

/* ln(j) for j = 0 .. @max into @logj; logj[0] is not used */
static inline void rber_fill_logj(double *logj, uint32_t max)
{
    logj[0] = 0;
    for (uint32_t j = 1; j <= max; j++) {
        logj[j] = log((double)j);
    }
}

/*
 * rber_cdf - P(X <= t) for X ~ Poisson(lam)
 * @logj: ln(j) for j up to @t
 *
 * Each log term builds on the one before: ln p(j) = ln p(j-1) + ln(lam) -
 * ln(j). The sum runs in log space (log-sum-exp), so a large mean does not
 * underflow. Past a Chernoff bound the result rounds to 1 or 0 in double
 * anyway, so it is returned at once. F(t; 0) is 1. The result is in [0, 1].
 */
static inline double rber_cdf(uint32_t t, double lam, const double *logj)
{
    double ll;
    double top = -INFINITY;
    double sum = 0;
    double term;

    if (lam <= 0) {
        return 1.0;
    }
    ll = log(lam);
    if (t + 1.0 > lam && -lam + (t + 1.0) * (1 + ll - log(t + 1.0)) < -45) {
        return 1.0;
    }
    if (t > 0 && t < lam && -lam + t * (1 + ll - logj[t]) < -745) {
        return 0.0;
    }
    term = -lam;
    for (uint32_t j = 0; j <= t; j++) {
        if (j) {
            term += ll - logj[j];
        }
        top = fmax(top, term);
    }
    term = -lam;
    for (uint32_t j = 0; j <= t; j++) {
        if (j) {
            term += ll - logj[j];
        }
        sum += exp(term - top);
    }
    return fmin(1.0, fmax(0.0, exp(top + log(sum))));
}

/* a decode attempt passes when the draw is below its pass chance */
static inline bool rber_pass(double u, double f)
{
    return u < f;
}

/* one splitmix64 step on @state */
static inline uint64_t rber_splitmix(uint64_t *state)
{
    uint64_t z = (*state += 0x9e3779b97f4a7c15ULL);

    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

/* a draw in [0, 1) from the top 53 bits of a generator value */
static inline double rber_unit(uint64_t v)
{
    return (double)(v >> 11) * 0x1.0p-53;
}

#endif
