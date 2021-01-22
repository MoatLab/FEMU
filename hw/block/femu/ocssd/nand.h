#ifndef __FEMU_NAND_H
#define __FEMU_NAND_H

/* L95B MLC NAND latency numbers in nanoseconds */
#define NAND_LOWER_PAGE_READ_LATENCY_NS   (48000)
#define NAND_UPPER_PAGE_READ_LATENCY_NS   (64000)
#define NAND_LOWER_PAGE_WRITE_LATENCY_NS  (850000)
#define NAND_UPPER_PAGE_WRITE_LATENCY_NS  (2300000)
#define CHNL_PAGE_TRANSFER_LATENCY_NS     (52433)
#define NAND_BLOCK_ERASE_LATENCY_NS       (3000000)

#define MLC_LOWER_PAGE  (0)
#define MLC_UPPER_PAGE  (1)

#define PPA_CH(ln, ppa)  ((ppa & ln->ppaf.ch_mask) >> ln->ppaf.ch_offset)
#define PPA_LUN(ln, ppa) ((ppa & ln->ppaf.lun_mask) >> ln->ppaf.lun_offset)
#define PPA_PLN(ln, ppa) ((ppa & ln->ppaf.pln_mask) >> ln->ppaf.pln_offset)
#define PPA_BLK(ln, ppa) ((ppa & ln->ppaf.blk_mask) >> ln->ppaf.blk_offset)
#define PPA_PG(ln, ppa)  ((ppa & ln->ppaf.pg_mask) >> ln->ppaf.pg_offset)
#define PPA_SEC(ln, ppa) ((ppa & ln->ppaf.sec_mask) >> ln->ppaf.sec_offset)

#define MAX_SUPPORTED_PAGES_PER_BLOCK (512)
/* Lower/Upper page format within one block */
static int mlc_tbl[MAX_SUPPORTED_PAGES_PER_BLOCK];

static inline bool is_upg(int pg)
{
    return mlc_tbl[pg];
}

void init_nand_page_pairing(FemuCtrl *n);

#endif

