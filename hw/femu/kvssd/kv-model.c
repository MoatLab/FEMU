/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * FEMU KV-SSD workload-mix timing model (kv_timing=model).
 *
 * The feature list and the default coefficients come from the Samsung KVSSD
 * PDK emulator (core/src/device_abstract_layer/include/private/history.hpp),
 * which carries this notice:
 *
 *   BSD LICENSE
 *
 *   Copyright (c) 2018 Samsung Electronics Co., Ltd.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Samsung Electronics Co., Ltd. nor the names of
 *       its contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The PDK evaluates x0^2 and x0^3 in 32-bit integers: x0^3 wraps above a
 * value size of 1625 bytes and x0^2 above 65535. This file evaluates every
 * term in double. At 4 KiB its result is 0.24 kIOPS higher than the PDK's,
 * at 16 KiB 15 kIOPS.
 */
#include "qemu/osdep.h"
#include <math.h>

#include "kv-model.h"

static const FemuKvModel kv_model_samsung = {
    .intercept = 93.55536664,
    .coef = {
         9.73333650e-03, -7.48332780e-04, -1.02151073e+01, -3.25414892e+01,
         4.27551652e+01, -1.37097247e-03,  5.35734352e-04,  6.63934171e-05,
        -5.98786540e-03,  6.59822790e+01, -9.08029926e+01,  1.46061898e+01,
         1.26562873e+01,  4.56136757e+01, -1.74634825e+01,  3.45057316e-12,
         1.37099315e-03,  1.37105773e-03,  1.37092722e-03, -7.66785198e-03,
         1.28200988e-02, -4.76358522e-03, -5.57416593e-03, -4.75173882e-03,
         3.58063105e-03, -9.87217038e+00,  6.72385443e+01,  8.61728612e+00,
        -1.39270618e+02, -1.87756101e+01,  2.47645398e+01,  7.51414174e+01,
         7.67858478e+01, -1.23967843e+01, -2.98320336e+01,
    },
};

void kv_model_default(FemuKvModel *m)
{
    *m = kv_model_samsung;
}

int kv_model_parse(const char *s, FemuKvModel *m, const char **why)
{
    double v[1 + KV_MODEL_TERMS];
    const char *p = s;
    int n = 0;
    int i;

    for (;;) {
        char *end;
        double d;

        if (n == 1 + KV_MODEL_TERMS) {
            *why = "more than 36 numbers";
            return -1;
        }
        d = strtod(p, &end);
        if (end == p) {
            *why = "a field is not a number";
            return -1;
        }
        if (!isfinite(d)) {
            *why = "a number is not finite";
            return -1;
        }
        v[n++] = d;
        while (*end == ' ' || *end == '\t') {
            end++;
        }
        if (*end == '\0') {
            break;
        }
        if (*end != ',') {
            *why = "numbers must be separated by commas";
            return -1;
        }
        p = end + 1;
    }
    if (n != 1 + KV_MODEL_TERMS) {
        *why = "fewer than 36 numbers";
        return -1;
    }
    m->intercept = v[0];
    for (i = 0; i < KV_MODEL_TERMS; i++) {
        m->coef[i] = v[i + 1];
    }
    return 0;
}

/*
 * Terms in the PDK order, with x0 the value size and x1, x2, x3 the insert,
 * read and update shares: 1, x0..x3, then every degree-2 and degree-3
 * product in lexicographic order. The PDK adds the intercept on top of the
 * constant term.
 */
double kv_model_kiops(const FemuKvModel *m, double vlen, double insert,
                      double read, double update)
{
    const double x[4] = { vlen, insert, read, update };
    double f[KV_MODEL_TERMS];
    double sum = m->intercept;
    int n = 0;
    int a, b, c;

    f[n++] = 1;
    for (a = 0; a < 4; a++) {
        f[n++] = x[a];
    }
    for (a = 0; a < 4; a++) {
        for (b = a; b < 4; b++) {
            f[n++] = x[a] * x[b];
        }
    }
    for (a = 0; a < 4; a++) {
        for (b = a; b < 4; b++) {
            for (c = b; c < 4; c++) {
                f[n++] = x[a] * x[b] * x[c];
            }
        }
    }
    for (a = 0; a < KV_MODEL_TERMS; a++) {
        sum += m->coef[a] * f[a];
    }
    return sum;
}

void kv_window_add(FemuKvWindow *w, FemuKvOp op, uint32_t vlen)
{
    if (w->len == KV_MODEL_WINDOW) {
        w->count[w->op[w->next]]--;
        w->vlen_sum -= w->vlen[w->next];
    } else {
        w->len++;
    }
    w->op[w->next] = op;
    w->vlen[w->next] = vlen;
    w->count[op]++;
    w->vlen_sum += vlen;
    w->next = (w->next + 1) % KV_MODEL_WINDOW;
}

uint64_t kv_model_latency_ns(const FemuKvModel *m, const FemuKvWindow *w,
                             bool *floored)
{
    uint64_t mean;
    uint64_t fit;
    double len = w->len;
    double kiops;
    double ns;

    *floored = false;
    if (!w->len) {
        return 0;
    }
    /* the PDK rounds the mean value size to the nearest byte */
    mean = (2 * w->vlen_sum + w->len) / (2 * (uint64_t)w->len);
    fit = mean < KV_MODEL_MAX_VLEN ? mean : KV_MODEL_MAX_VLEN;

    kiops = kv_model_kiops(m, fit, w->count[KV_OP_INSERT] / len,
                           w->count[KV_OP_READ] / len,
                           w->count[KV_OP_UPDATE] / len);
    /* finite coefficients can still overflow to an infinite throughput */
    *floored = !(isfinite(kiops) && kiops >= KV_MODEL_MIN_KIOPS);
    if (*floored) {
        kiops = KV_MODEL_MIN_KIOPS;
    }
    ns = 1e6 / kiops;
    /* the fit is not valid past 16 KiB: the transfer time grows with size */
    if (mean > fit) {
        ns = ns * mean / fit;
    }
    /* a very high custom throughput still costs a nanosecond */
    return ns < 1 ? 1 : (uint64_t)ns;
}
