/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 * FEAT_RME_GDI Feature presence and enabled bits test
 *
 * Copyright (c) 2026 Linaro Ltd
 *
 */

#include <stdint.h>
#include <minilib.h>

#define ID_AA64PFR0_EL1 "S3_0_C0_C4_0"
#define ID_AA64MMFR4_EL1 "S3_0_C0_C7_4"

int main()
{
    uint64_t mmfr4;
    uint64_t pfr0;
    int rme_status;
    int rmegdi_status;

    asm("mrs %[pfr0], " ID_AA64PFR0_EL1 "\n\t"
        : [pfr0] "=r" (pfr0));

    /* rme_status is 1 for RME, 2 for RME + GPC2, 3 for RME+GPC3 */
    rme_status = (pfr0 >> 52) & 0xF;

    asm("mrs %[mmfr4], " ID_AA64MMFR4_EL1 "\n\t"
        : [mmfr4] "=r" (mmfr4));

    rmegdi_status = ((mmfr4 >> 28) & 0xF);

    if (rmegdi_status < 1) {
        ml_printf("SKIP: GDI not implemented\n");
        return 0;
    }

    /* Check FEAT_RME and FEAT_RME_GPC2 also present */
    if (rme_status < 2) {
        ml_printf("FAIL: GDI is %d, but RME is %d; RME should be >= 2\n",
                  rmegdi_status, rme_status);
        return 1;
    }
    return 0;
}
