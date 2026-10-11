/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Unit test for the KV-SSD workload-mix timing model (kvssd/kv-model.c).
 * The expected values come from an independent Python evaluation of the
 * PDK feature list in double precision.
 */
#include "qemu/osdep.h"
#include <math.h>

#include "hw/femu/kvssd/kv-model.h"

/* TAP output, as meson runs this test with the TAP protocol */
static int ntests;
static int failures;

#define CHECK(cond) do {                                                \
    ntests++;                                                           \
    if (cond) {                                                         \
        printf("ok %d - line %d\n", ntests, __LINE__);                  \
    } else {                                                            \
        printf("not ok %d - line %d: %s\n", ntests, __LINE__, #cond);   \
        failures++;                                                     \
    }                                                                   \
} while (0)

static void check_kiops(const FemuKvModel *m, double v, double i, double r,
                        double u, double want)
{
    double got = kv_model_kiops(m, v, i, r, u);

    ntests++;
    if (fabs(got - want) > 1e-6) {
        printf("not ok %d - kiops(%g, %g, %g, %g) = %.9f, want %.9f\n",
               ntests, v, i, r, u, got, want);
        failures++;
    } else {
        printf("ok %d - kiops(%g, %g, %g, %g) = %.9f\n", ntests, v, i, r, u,
               got);
    }
}

static uint64_t window_ns(const FemuKvModel *m, FemuKvOp op, uint32_t vlen,
                          int n, bool *floored)
{
    FemuKvWindow w = { 0 };
    int k;

    for (k = 0; k < n; k++) {
        kv_window_add(&w, op, vlen);
    }
    return kv_model_latency_ns(m, &w, floored);
}

static void test_default_values(void)
{
    FemuKvModel m;
    bool fl;

    kv_model_default(&m);
    check_kiops(&m, 4096, 1, 0, 0, 107.7658508342062);
    check_kiops(&m, 4096, 0, 1, 0, 124.86385521493565);
    check_kiops(&m, 4096, 0, 0, 1, 75.57749867001391);
    check_kiops(&m, 1024, 0.5, 0.5, 0, 67.79357527083785);
    check_kiops(&m, 64, 0, 0.25, 0.75, 107.17649496414316);
    check_kiops(&m, 16384, 1, 0, 0, 31.073828289550548);

    /* 1e6 / kIOPS ns per command */
    CHECK(window_ns(&m, KV_OP_INSERT, 4096, 16, &fl) == 9279 && !fl);
    CHECK(window_ns(&m, KV_OP_READ, 4096, 16, &fl) == 8008 && !fl);
    CHECK(window_ns(&m, KV_OP_UPDATE, 4096, 16, &fl) == 13231 && !fl);
    /* the fit stops at 16 KiB: 64 KiB is four times the 16 KiB time */
    CHECK(window_ns(&m, KV_OP_INSERT, 16384, 16, &fl) == 32181);
    CHECK(window_ns(&m, KV_OP_INSERT, 65536, 16, &fl) == 128725);
}

static void test_window(void)
{
    FemuKvModel m;
    FemuKvWindow w = { 0 };
    bool fl;
    int k;

    kv_model_default(&m);
    /* 8 inserts then 8 reads of 1 KiB: half and half */
    for (k = 0; k < 8; k++) {
        kv_window_add(&w, KV_OP_INSERT, 1024);
    }
    for (k = 0; k < 8; k++) {
        kv_window_add(&w, KV_OP_READ, 1024);
    }
    CHECK(w.len == 16);
    CHECK(kv_model_latency_ns(&m, &w, &fl) == 14750);

    /* 16 more reads push every insert out of the window */
    for (k = 0; k < 16; k++) {
        kv_window_add(&w, KV_OP_READ, 4096);
    }
    CHECK(w.len == 16);
    CHECK(w.count[KV_OP_INSERT] == 0 && w.count[KV_OP_READ] == 16);
    CHECK(w.vlen_sum == 16 * 4096);
    CHECK(kv_model_latency_ns(&m, &w, &fl) == 8008);

    /* a part-full window uses only what it holds */
    memset(&w, 0, sizeof(w));
    kv_window_add(&w, KV_OP_UPDATE, 4096);
    CHECK(w.len == 1);
    CHECK(kv_model_latency_ns(&m, &w, &fl) == 13231);

    /*
     * The mean rounds to the nearest byte, as in the PDK: with kIOPS equal
     * to the size, sizes 1 and 2 give a mean of 2, so 1e6 / 2 ns.
     */
    {
        FemuKvModel lin = { .coef = { [1] = 1 } };

        memset(&w, 0, sizeof(w));
        kv_window_add(&w, KV_OP_READ, 1);
        kv_window_add(&w, KV_OP_READ, 2);
        CHECK(kv_model_latency_ns(&lin, &w, &fl) == 500000 && !fl);
    }

    memset(&w, 0, sizeof(w));
    CHECK(kv_model_latency_ns(&m, &w, &fl) == 0 && !fl);
}

static void test_floor(void)
{
    FemuKvModel m = { .intercept = -5 };
    bool fl;

    /* a negative throughput is raised to the floor: 1e6 / 0.01 ns */
    CHECK(window_ns(&m, KV_OP_INSERT, 4096, 4, &fl) == 100000000 && fl);
    m.intercept = 0.25;
    CHECK(window_ns(&m, KV_OP_INSERT, 4096, 4, &fl) == 4000000 && !fl);

    /* a finite but huge throughput costs one nanosecond, not zero */
    m.intercept = 1e308;
    CHECK(window_ns(&m, KV_OP_INSERT, 4096, 4, &fl) == 1 && !fl);
    m.intercept = 0.25;

    /* finite coefficients that overflow to infinity take the floor too */
    m.coef[15] = 1e308;
    CHECK(window_ns(&m, KV_OP_INSERT, 4096, 4, &fl) == 100000000 && fl);
}

static void test_parse(void)
{
    char buf[1024];
    FemuKvModel m;
    FemuKvModel d;
    const char *why = NULL;
    int len = 0;
    int k;

    /* the default printed back parses to the same model */
    kv_model_default(&d);
    len += snprintf(buf + len, sizeof(buf) - len, "%.17g", d.intercept);
    for (k = 0; k < KV_MODEL_TERMS; k++) {
        len += snprintf(buf + len, sizeof(buf) - len, ", %.17g", d.coef[k]);
    }
    CHECK(kv_model_parse(buf, &m, &why) == 0);
    CHECK(memcmp(&m, &d, sizeof(m)) == 0);

    /* one number too many */
    snprintf(buf + len, sizeof(buf) - len, ",1");
    CHECK(kv_model_parse(buf, &m, &why) == -1);

    CHECK(kv_model_parse("1,2,3", &m, &why) == -1);
    CHECK(kv_model_parse("", &m, &why) == -1);
    CHECK(kv_model_parse("1,,2", &m, &why) == -1);
    CHECK(kv_model_parse("1;2", &m, &why) == -1);

    /* 36 numbers with one infinite */
    len = snprintf(buf, sizeof(buf), "inf");
    for (k = 0; k < KV_MODEL_TERMS; k++) {
        len += snprintf(buf + len, sizeof(buf) - len, ",0");
    }
    CHECK(kv_model_parse(buf, &m, &why) == -1);
    buf[0] = '1';
    buf[1] = ' ';
    buf[2] = ' ';
    CHECK(kv_model_parse(buf, &m, &why) == 0 && m.intercept == 1);
}

int main(void)
{
    test_default_values();
    test_window();
    test_floor();
    test_parse();
    printf("1..%d\n", ntests);
    return failures ? 1 : 0;
}
