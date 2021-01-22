#include "qemu/osdep.h"
#include "hw/pci/msix.h"
#include "qemu/error-report.h"

#include "../nvme.h"
#include "./nand.h"

/* Profiled from Micron L95B MLC NAND chips */

/*
 * Lower/Upper page pairing in one block
 * It is what it is.
 */
void init_nand_page_pairing(FemuCtrl *n)
{
    int i;
    int lowp[] = {0, 1, 2, 3, 4, 5, 7, 8, 502, 503, 506, 507, 509, 510};
    int uppp[] = {6, 9, 504, 505, 508, 511};
    int lpflag = MLC_LOWER_PAGE;

    for (i = 0; i < sizeof(lowp)/sizeof(lowp[0]); i++)
        mlc_tbl[lowp[i]] = MLC_LOWER_PAGE;

    for (i = 0; i < sizeof(uppp)/sizeof(uppp[0]); i++)
        mlc_tbl[uppp[i]] = MLC_UPPER_PAGE;

    for (i = 10; i <= MAX_SUPPORTED_PAGES_PER_BLOCK - 12; i += 2) {
        mlc_tbl[i] = mlc_tbl[i+1] = lpflag;
        lpflag = (lpflag == MLC_LOWER_PAGE) ? MLC_UPPER_PAGE : MLC_LOWER_PAGE;
    }
}

