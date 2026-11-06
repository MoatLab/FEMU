/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Math of the bbssd raw bit error model (bbssd/ftl-rber-math.h)
 */

#include "qemu/osdep.h"
#include "hw/femu/bbssd/ftl-rber-math.h"

static double logj[1025];

/* P(X <= t) by plain summation of the Poisson terms, for small means */
static double direct_cdf(uint32_t t, double lam)
{
    double p = exp(-lam);
    double sum = p;

    for (uint32_t j = 1; j <= t; j++) {
        p *= lam / j;
        sum += p;
    }
    return sum;
}

/* F against direct summation where both are exact enough */
static void test_cdf_values(void)
{
    static const struct {
        uint32_t t;
        double lam;
    } cases[] = {
        { 0, 0.5 }, { 3, 2.0 }, { 40, 20.0 }, { 40, 40.0 }, { 40, 60.0 },
        { 72, 50.0 }, { 72, 72.0 }, { 72, 100.0 }, { 10, 30.0 },
    };

    for (size_t i = 0; i < G_N_ELEMENTS(cases); i++) {
        double want = direct_cdf(cases[i].t, cases[i].lam);
        double got = rber_cdf(cases[i].t, cases[i].lam, logj);

        g_assert_cmpfloat(fabs(got - want), <=, 1e-12 + 1e-9 * want);
    }
}

/* the edges: no errors, a far tail, a large mean, the clamp */
static void test_cdf_edges(void)
{
    g_assert_cmpfloat(rber_cdf(40, 0, logj), ==, 1.0);
    g_assert_cmpfloat(rber_cdf(0, 0, logj), ==, 1.0);
    g_assert_cmpfloat(rber_cdf(1024, 1.0, logj), ==, 1.0);
    g_assert_cmpfloat(rber_cdf(40, 4096.0, logj), ==, 0.0);
    g_assert_cmpfloat(rber_cdf(1024, 4096.0, logj), >=, 0.0);
    g_assert_cmpfloat(rber_cdf(1024, 4096.0, logj), <, 1e-300);
    for (double lam = 0.25; lam < 2000; lam *= 1.7) {
        double f = rber_cdf(72, lam, logj);

        g_assert_cmpfloat(f, >=, 0.0);
        g_assert_cmpfloat(f, <=, 1.0);
    }
}

/* F grows with the threshold and falls with the mean */
static void test_cdf_monotone(void)
{
    double last = 0;

    for (uint32_t t = 0; t <= 100; t++) {
        double f = rber_cdf(t, 40.0, logj);

        g_assert_cmpfloat(f, >=, last);
        last = f;
    }
    last = 1.0;
    for (double lam = 1; lam <= 200; lam += 3) {
        double f = rber_cdf(40, lam, logj);

        g_assert_cmpfloat(f, <=, last);
        last = f;
    }
}

/* a draw passes only strictly below its chance: u = F fails, F = 0 fails */
static void test_pass(void)
{
    g_assert_true(rber_pass(0.25, 0.5));
    g_assert_false(rber_pass(0.5, 0.5));
    g_assert_false(rber_pass(0.0, 0.0));
    g_assert_true(rber_pass(0.0, 1e-300));
    g_assert_true(rber_pass(1.0 - 0x1.0p-53, 1.0));
}

/* the generator: fixed vectors, and draws in [0, 1) */
static void test_generator(void)
{
    uint64_t s = 1;
    uint64_t a = rber_splitmix(&s);
    uint64_t b = rber_splitmix(&s);
    uint64_t t = 1;

    g_assert_cmphex(a, !=, b);
    g_assert_cmphex(rber_splitmix(&t), ==, a);
    g_assert_cmphex(rber_splitmix(&t), ==, b);
    /* splitmix64 from a state of 0: the published first output */
    t = 0;
    g_assert_cmphex(rber_splitmix(&t), ==, 0xe220a8397b1dcdafULL);
    g_assert_cmpfloat(rber_unit(0), ==, 0.0);
    g_assert_cmpfloat(rber_unit(UINT64_MAX), <, 1.0);
    g_assert_cmpfloat(rber_unit(UINT64_MAX), ==, 1.0 - 0x1.0p-53);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    rber_fill_logj(logj, 1024);
    g_test_add_func("/femu/rber/cdf-values", test_cdf_values);
    g_test_add_func("/femu/rber/cdf-edges", test_cdf_edges);
    g_test_add_func("/femu/rber/cdf-monotone", test_cdf_monotone);
    g_test_add_func("/femu/rber/pass", test_pass);
    g_test_add_func("/femu/rber/generator", test_generator);
    return g_test_run();
}
