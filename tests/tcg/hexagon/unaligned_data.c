/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Test that unaligned scalar loads raise SIGBUS.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <setjmp.h>
#include <signal.h>

int err;

#include "hex_test.h"

static bool sigbus_caught;
static sigjmp_buf jmp_env;
static uint64_t buf[2] = { 0, 0 };

static void sigbus_handler(int sig, siginfo_t *info, void *puc)
{
    check32(sig, SIGBUS);
    sigbus_caught = true;
    siglongjmp(jmp_env, 1);
}

static void test_unaligned_load(int size, int offset)
{
    char *p = (char *)buf + offset;
    uint32_t dummy32;
    uint64_t dummy64;

    sigbus_caught = false;
    if (sigsetjmp(jmp_env, 1) == 0) {
        switch (size) {
        case 2:
            asm volatile("%[dst] = memh(%[src])\n\t"
                          : [dst] "=r"(dummy32) : [src] "r"(p) : "memory");
            break;
        case 4:
            asm volatile("%[dst] = memw(%[src])\n\t"
                          : [dst] "=r"(dummy32) : [src] "r"(p) : "memory");
            break;
        case 8:
            asm volatile("%[dst] = memd(%[src])\n\t"
                          : [dst] "=r"(dummy64) : [src] "r"(p) : "memory");
            break;
        default:
            abort();
        }
    }
    check32(sigbus_caught, true);
}

static void test_unaligned_store(int size, int offset)
{
    char *p = (char *)buf + offset;
    uint32_t val32 = 0x11223344;
    uint64_t val64 = 0x1122334455667788ULL;

    sigbus_caught = false;
    if (sigsetjmp(jmp_env, 1) == 0) {
        switch (size) {
        case 2:
            asm volatile("memh(%[addr]) = %[val]\n\t"
                          : : [addr] "r"(p), [val] "r"(val32) : "memory");
            break;
        case 4:
            asm volatile("memw(%[addr]) = %[val]\n\t"
                          : : [addr] "r"(p), [val] "r"(val32) : "memory");
            break;
        case 8:
            asm volatile("memd(%[addr]) = %[val]\n\t"
                          : : [addr] "r"(p), [val] "r"(val64) : "memory");
            break;
        default:
            abort();
        }
    }
    check32(sigbus_caught, true);
}

int main()
{
    struct sigaction act;

    act.sa_sigaction = sigbus_handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_SIGINFO;
    chk_error(sigaction(SIGBUS, &act, NULL));

    test_unaligned_load(2, 1);
    test_unaligned_load(4, 1);
    test_unaligned_load(4, 2);
    test_unaligned_load(4, 3);
    test_unaligned_load(8, 1);
    test_unaligned_load(8, 4);

    test_unaligned_store(2, 1);
    test_unaligned_store(4, 1);
    test_unaligned_store(4, 2);
    test_unaligned_store(4, 3);
    test_unaligned_store(8, 1);
    test_unaligned_store(8, 4);

    act.sa_handler = SIG_DFL;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    chk_error(sigaction(SIGBUS, &act, NULL));

    puts(err ? "FAIL" : "PASS");
    return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
