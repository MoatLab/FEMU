/* Host unit test for the QLC page-pairing table.
 *
 * The expert plane-major layout assigns bit-plane Bn to QLC class n-1, so every
 * predicted address depends on qlc_tbl matching the device exactly. A mismatch
 * is silent: the mapper still emits a plan, the device still serves the reads,
 * and only the latency is wrong. Checking the table before booting is far
 * cheaper than reading it back out of a FEMU WRITE log.
 *
 * init_qlc_page_pairing() is static and its translation unit pulls in QEMU, so
 * the function text is extracted from nand.c at build time (see the Makefile
 * rule) rather than copied here, which would let the two drift apart.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct FemuCtrl FemuCtrl;
#include "../nand.h"

int slc_tbl[MAX_SUPPORTED_PAGES_PER_BLOCK];
int mlc_tbl[MAX_SUPPORTED_PAGES_PER_BLOCK];
int tlc_tbl[MAX_SUPPORTED_PAGES_PER_BLOCK];
int qlc_tbl[MAX_SUPPORTED_PAGES_PER_BLOCK];
struct NandFlashTiming nand_flash_timing;

/* Upstream's own style: size_t/int comparisons and the unused FemuCtrl argument.
 * Our test code stays under -Wall -Wextra -Werror; the extracted text does not. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include "pairing_extract.inc"
#pragma GCC diagnostic pop

static int fails;

static void check(int cond, const char *what)
{
    if (!cond) { printf("FAIL %s\n", what); fails++; }
}

int main(void)
{
    int pg, counts[4] = {0};

    memset(qlc_tbl, -1, sizeof(qlc_tbl));
    init_qlc_page_pairing(NULL);

    /* Prologue: the shadow-programming sequence leaves pages 0..7 special. */
    for (pg = 0; pg < 6; pg++)
        check(qlc_tbl[pg] == QLC_LOWER_PAGE, "prologue pg 0..5 is class 0");
    for (pg = 6; pg < 8; pg++)
        check(qlc_tbl[pg] == QLC_LOWER_CENTER_PAGE, "prologue pg 6..7 is class 1");

    /* From page 8 the cycle is 0 0 1 1 2 2 3 3, to the last page of the block. */
    for (pg = 8; pg < MAX_SUPPORTED_PAGES_PER_BLOCK; pg++) {
        int want = ((pg - 8) % 8) / 2;
        if (qlc_tbl[pg] != want) {
            printf("FAIL pg %d: class %d, expected %d\n", pg, qlc_tbl[pg], want);
            fails++;
            break;
        }
    }

    /* No page may keep the -1 poison: rows-3 used to leave 496..511 untouched,
     * where the zero-initialised global reads as a valid QLC_LOWER_PAGE. */
    for (pg = 0; pg < MAX_SUPPORTED_PAGES_PER_BLOCK; pg++) {
        if (qlc_tbl[pg] < 0 || qlc_tbl[pg] > 3) {
            printf("FAIL pg %d never assigned (%d)\n", pg, qlc_tbl[pg]);
            fails++;
            break;
        }
        counts[qlc_tbl[pg]]++;
    }

    printf("class page counts: %d %d %d %d\n",
           counts[0], counts[1], counts[2], counts[3]);
    check(counts[0] == 132 && counts[1] == 128 &&
          counts[2] == 126 && counts[3] == 126, "class counts for 512 pages");

    printf(fails ? "test_pairing: %d failure(s)\n" : "test_pairing: ok\n", fails);
    return fails != 0;
}
