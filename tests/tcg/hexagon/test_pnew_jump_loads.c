/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Exhaustive test for predicated .new branches with non-standard predicate
 * values (non-all-0, non-all-1).
 *
 * Hexagon predicates are 8 bits wide but conditional branches evaluate only
 * bit 0 (the LSB).  A predicate value like 0xFE is non-zero yet has bit 0
 * clear, so it must evaluate as "false".
 *
 * This test covers the distinct TCG code paths for predicated .new ops:
 *
 *   1. gen_cond_jump      - J2_jumptnewpt / J2_jumpfnewpt  (p0..p3)
 *   2. gen_cond_jumpr     - J2_jumprtnewpt / J2_jumprfnewpt
 *   3. gen_cond_jumpr31   - SL2_jumpr31_tnew / SL2_jumpr31_fnew (duplex)
 *   4. gen_testbit0_jumpnv - J4_tstbit0_t/f_jumpnv_t
 *   5. Conditional .new loads and stores
 */

#include <stdio.h>
#include <stdint.h>

int err;

#include "hex_test.h"

/*
 * Non-standard predicate: non-zero (0xFE) but bit 0 clear => false.
 * This distinguishes correct LSB evaluation from incorrect non-zero checks.
 */
#define PRED_VAL    0xFEu
#define SENTINEL    0xDEADBEEFu
#define LOAD_VAL    0xAAAABBBBu

/* gen_cond_jump (J2_jumptnewpt) */

/*
 * Macro to test jumptnew across predicate registers p0..p3.
 * { Pn = and(Pn, Pn); if (Pn.new) jump:t TARGET }
 *
 * Pn.new = PRED_VAL & PRED_VAL = 0xFE => bit0=0 => not taken.
 * Different predicate registers produce different instruction encodings.
 */
#define TEST_JUMPTNEW(PREG)                                     \
static void test_jumptnew_##PREG(void)                          \
{                                                               \
    uint32_t jumped;                                            \
    asm(                                                        \
        #PREG " = %[pred]\n"                                    \
        "{ " #PREG " = and(" #PREG ", " #PREG ")\n"            \
        "  if (" #PREG ".new) jump:t 1f }\n"                   \
        "%[jumped] = #0\n"                                      \
        "jump 2f\n"                                             \
        "1:\n"                                                  \
        "%[jumped] = #1\n"                                      \
        "2:\n"                                                  \
        : [jumped] "=r"(jumped)                                 \
        : [pred] "r"(PRED_VAL)                                  \
        : #PREG                                                 \
    );                                                          \
    check32(jumped, 0);                                         \
}

TEST_JUMPTNEW(p0)
TEST_JUMPTNEW(p1)
TEST_JUMPTNEW(p2)
TEST_JUMPTNEW(p3)

/* jumpfnew: bit0=0 => condition "false" => negated => jump IS taken */
static void test_jumpfnew_p0(void)
{
    uint32_t jumped;

    asm(
        "p0 = %[pred]\n"
        "{ p0 = and(p0, p0)\n"
        "  if (!p0.new) jump:t 1f }\n"
        "%[jumped] = #0\n"
        "jump 2f\n"
        "1:\n"
        "%[jumped] = #1\n"
        "2:\n"
        : [jumped] "=r"(jumped)
        : [pred] "r"(PRED_VAL)
        : "p0"
    );
    check32(jumped, 1);
}

/* gen_cond_jumpr (J2_jumprtnewpt) */

static void test_jumprtnew_p0(void)
{
    uint32_t jumped;

    asm(
        "p0 = %[pred]\n"
        "r0 = ##1f\n"
        "{ p0 = and(p0, p0)\n"
        "  if (p0.new) jumpr:t r0 }\n"
        "%[jumped] = #0\n"
        "jump 2f\n"
        "1:\n"
        "%[jumped] = #1\n"
        "2:\n"
        : [jumped] "=r"(jumped)
        : [pred] "r"(PRED_VAL)
        : "p0", "r0"
    );
    check32(jumped, 0);
}

static void test_jumprfnew_p0(void)
{
    uint32_t jumped;

    asm(
        "p0 = %[pred]\n"
        "r0 = ##1f\n"
        "{ p0 = and(p0, p0)\n"
        "  if (!p0.new) jumpr:t r0 }\n"
        "%[jumped] = #0\n"
        "jump 2f\n"
        "1:\n"
        "%[jumped] = #1\n"
        "2:\n"
        : [jumped] "=r"(jumped)
        : [pred] "r"(PRED_VAL)
        : "p0", "r0"
    );
    check32(jumped, 1);
}

/* gen_cond_jumpr31 (SL2_jumpr31_tnew) */

/*
 * Duplex sub-instructions: only SA1_cmpeqi and similar can produce .new
 * predicates in a duplex packet, and those only yield 0x00/0xFF.
 * We test with standard values to exercise the duplex decode path.
 *
 * { p0 = cmp.eq(r0, #0); if (p0.new) jumpr:nt r31 }
 * With r0=0: p0.new = 0xFF => bit0=1 => taken.
 */
static void test_jumpr31_tnew(void)
{
    uint32_t jumped;

    asm(
        "r0 = #0\n"
        "r31 = ##1f\n"
        "{ p0 = cmp.eq(r0, #0)\n"
        "  if (p0.new) jumpr:nt r31 }\n"
        "%[jumped] = #0\n"
        "jump 2f\n"
        "1:\n"
        "%[jumped] = #1\n"
        "2:\n"
        : [jumped] "=r"(jumped)
        :
        : "r0", "r31", "p0"
    );
    check32(jumped, 1);
}

/* p0.new = 0xFF => bit0=1 => !true => not taken */
static void test_jumpr31_fnew(void)
{
    uint32_t jumped;

    asm(
        "r0 = #0\n"
        "r31 = ##1f\n"
        "{ p0 = cmp.eq(r0, #0)\n"
        "  if (!p0.new) jumpr:nt r31 }\n"
        "%[jumped] = #0\n"
        "jump 2f\n"
        "1:\n"
        "%[jumped] = #1\n"
        "2:\n"
        : [jumped] "=r"(jumped)
        :
        : "r0", "r31", "p0"
    );
    check32(jumped, 0);
}

/* gen_testbit0_jumpnv (J4_tstbit0) */

/*
 * { r0 = #0xFE; if (tstbit(r0.new, #0)) jump:t TARGET }
 * r0.new = 0xFE => bit0=0 => tstbit false => not taken.
 */
static void test_tstbit0_t_jumpnv(void)
{
    uint32_t jumped;

    asm(
        "{ r0 = #0xFE\n"
        "  if (tstbit(r0.new, #0)) jump:t 1f }\n"
        "%[jumped] = #0\n"
        "jump 2f\n"
        "1:\n"
        "%[jumped] = #1\n"
        "2:\n"
        : [jumped] "=r"(jumped)
        :
        : "r0"
    );
    check32(jumped, 0);
}

/* bit0=0 => tstbit false => negated => taken */
static void test_tstbit0_f_jumpnv(void)
{
    uint32_t jumped;

    asm(
        "{ r0 = #0xFE\n"
        "  if (!tstbit(r0.new, #0)) jump:t 1f }\n"
        "%[jumped] = #0\n"
        "jump 2f\n"
        "1:\n"
        "%[jumped] = #1\n"
        "2:\n"
        : [jumped] "=r"(jumped)
        :
        : "r0"
    );
    check32(jumped, 1);
}

/* conditional .new loads and stores */

static uint32_t load_val;
static uint32_t store_dst;

/* bit0=0 => condition false => load skipped => sentinel remains */
static void test_cond_load_tnew(void)
{
    uint32_t result;

    load_val = LOAD_VAL;
    asm(
        "p0 = %[pred]\n"
        "%[res] = %[sentinel]\n"
        "{ p0 = and(p0, p0)\n"
        "  if (p0.new) %[res] = memw(%[addr]+#0) }\n"
        : [res] "=&r"(result)
        : [pred] "r"(PRED_VAL),
          [addr] "r"(&load_val),
          [sentinel] "r"(SENTINEL)
        : "p0", "memory"
    );
    check32(result, SENTINEL);
}

/* bit0=0 => condition false => negated => load executed */
static void test_cond_load_fnew(void)
{
    uint32_t result;

    load_val = LOAD_VAL;
    asm(
        "p0 = %[pred]\n"
        "%[res] = %[sentinel]\n"
        "{ p0 = and(p0, p0)\n"
        "  if (!p0.new) %[res] = memw(%[addr]+#0) }\n"
        : [res] "=&r"(result)
        : [pred] "r"(PRED_VAL),
          [addr] "r"(&load_val),
          [sentinel] "r"(SENTINEL)
        : "p0", "memory"
    );
    check32(result, LOAD_VAL);
}

/* bit0=0 => condition false => store skipped => sentinel remains */
static void test_cond_store_tnew(void)
{
    store_dst = SENTINEL;
    asm(
        "p0 = %[pred]\n"
        "{ p0 = and(p0, p0)\n"
        "  if (p0.new) memw(%[addr]+#0) = %[val] }\n"
        :
        : [pred] "r"(PRED_VAL),
          [addr] "r"(&store_dst),
          [val] "r"(LOAD_VAL)
        : "p0", "memory"
    );
    check32(store_dst, SENTINEL);
}

/* bit0=0 => condition false => negated => store executed */
static void test_cond_store_fnew(void)
{
    store_dst = SENTINEL;
    asm(
        "p0 = %[pred]\n"
        "{ p0 = and(p0, p0)\n"
        "  if (!p0.new) memw(%[addr]+#0) = %[val] }\n"
        :
        : [pred] "r"(PRED_VAL),
          [addr] "r"(&store_dst),
          [val] "r"(LOAD_VAL)
        : "p0", "memory"
    );
    check32(store_dst, LOAD_VAL);
}

int main(void)
{
    /* gen_cond_jump with all predicate registers */
    test_jumptnew_p0();
    test_jumptnew_p1();
    test_jumptnew_p2();
    test_jumptnew_p3();
    test_jumpfnew_p0();

    /* gen_cond_jumpr */
    test_jumprtnew_p0();
    test_jumprfnew_p0();

    /* gen_cond_jumpr31 (duplex, standard values) */
    test_jumpr31_tnew();
    test_jumpr31_fnew();

    /* gen_testbit0_jumpnv */
    test_tstbit0_t_jumpnv();
    test_tstbit0_f_jumpnv();

    /* conditional .new loads and stores */
    test_cond_load_tnew();
    test_cond_load_fnew();
    test_cond_store_tnew();
    test_cond_store_fnew();

    puts(err ? "FAIL" : "PASS");
    return err ? 1 : 0;
}
