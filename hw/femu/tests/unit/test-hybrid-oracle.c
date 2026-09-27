/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "hybrid-oracle.h"

static unsigned checks;

static void check(const char *name, uint64_t got, uint64_t expected)
{
    checks++;
    printf("%s %u - %s\n", got == expected ? "ok" : "not ok", checks,
           name);
    assert(got == expected);
}

int main(void)
{
    HybridOracle o;

    printf("TAP version 13\n");
    hybrid_oracle_init(&o, 4, 2, 16);
    hybrid_oracle_write(&o, 0);
    hybrid_oracle_trim(&o, 0);
    hybrid_oracle_write(&o, 1);
    hybrid_oracle_write(&o, 1);
    hybrid_oracle_write(&o, 1);
    check("trim leaves all four program slots occupied", o.programs, 4);
    check("trimmed page is not copied", o.copies, 1);
    check("hot rewrite requires a full merge", o.merges, 1);
    check("hot rewrite cannot switch", o.switches, 0);
    hybrid_oracle_destroy(&o);
    printf("1..%u\n", checks);
    return 0;
}
