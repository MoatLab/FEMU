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
    unsigned i;
    unsigned pages;

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
    check("full merge defers erasure to line GC", o.erases, 0);
    hybrid_oracle_destroy(&o);
    hybrid_oracle_init(&o, 4, 2, 16);
    for (i = 0; i < 4; i++) {
        hybrid_oracle_write(&o, i);
    }
    hybrid_oracle_write(&o, 0);
    hybrid_oracle_trim(&o, 0);
    for (i = 1; i < 4; i++) {
        hybrid_oracle_write(&o, i);
    }
    check("trimmed sequential history still switches", o.switches, 2);
    check("trim cannot remove a switch erase", o.erases, 2);
    check("trimmed sequential history needs no copies", o.copies, 0);
    hybrid_oracle_destroy(&o);
    /* Literal four-page examples also distinguish switch from full merges. */
    hybrid_oracle_init(&o, 4, 2, 16);
    for (i = 0; i < 8; i++) {
        hybrid_oracle_write(&o, i % 4);
    }
    check("two sequential passes program eight pages", o.programs, 8);
    check("sequential passes switch twice", o.switches, 2);
    check("switches copy no pages", o.copies, 0);
    check("sequential passes need no full merge", o.merges, 0);
    check("each sequential pass charges an erase", o.erases, 2);
    hybrid_oracle_destroy(&o);

    hybrid_oracle_init(&o, 4, 2, 16);
    hybrid_oracle_write(&o, 0);
    hybrid_oracle_write(&o, 2);
    hybrid_oracle_write(&o, 1);
    hybrid_oracle_write(&o, 3);
    check("permuted block needs a full merge", o.merges, 1);
    check("permuted block copies all four live pages", o.copies, 4);
    hybrid_oracle_write(&o, 1);
    hybrid_oracle_write(&o, 1);
    hybrid_oracle_write(&o, 1);
    hybrid_oracle_write(&o, 1);
    check("hot updates retain earlier data pages", o.copies, 8);
    check("hot updates cannot switch", o.switches, 0);
    hybrid_oracle_destroy(&o);

    hybrid_oracle_init(&o, 4, 2, 16);
    hybrid_oracle_write(&o, 0);
    hybrid_oracle_write(&o, 4);
    check("pool pressure merges a partial log", o.merges, 1);
    check("partial merge copies only live pages", o.copies, 1);
    hybrid_oracle_write(&o, 5);
    hybrid_oracle_write(&o, 8);
    check("fullest log is the victim", o.copies, 3);
    hybrid_oracle_destroy(&o);

    for (pages = 1; pages <= 16; pages *= 2) {
        hybrid_oracle_init(&o, pages, 2, pages * 4);
        for (i = 0; i < pages * 2; i++) {
            hybrid_oracle_write(&o, pages - 1);
        }
        check("hot programs scale with geometry", o.programs, pages * 2);
        check("hot logs fill twice", o.merges + o.switches, 2);
        check("one-page log switches, larger hot logs copy", o.copies,
              pages == 1 ? 0 : 2);
        check("only switches charge merge erases", o.erases,
              pages == 1 ? 2 : 0);
        hybrid_oracle_destroy(&o);
    }
    printf("1..%u\n", checks);
    return 0;
}
