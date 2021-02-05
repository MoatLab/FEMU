#ifndef __FEMU_NAND_H
#define __FEMU_NAND_H

/* L95B MLC NAND latency numbers in nanoseconds */
#define NAND_LOWER_PAGE_READ_LATENCY_NS   (48000)
#define NAND_UPPER_PAGE_READ_LATENCY_NS   (64000)
#define NAND_LOWER_PAGE_WRITE_LATENCY_NS  (850000)
#define NAND_UPPER_PAGE_WRITE_LATENCY_NS  (2300000)
#define CHNL_PAGE_TRANSFER_LATENCY_NS     (52433)
#define NAND_BLOCK_ERASE_LATENCY_NS       (3000000)

/* TLC NAND latency numbers in nanoseconds
   Based on the paper:
   SimpleSSD: Modeling Solid State Drives for Holistic System Simulation
*/

#define TLC_LOWER_PAGE_READ_LATENCY_NS   (56500)
#define TLC_CENTER_PAGE_READ_LATENCY_NS   (77500)
#define TLC_UPPER_PAGE_READ_LATENCY_NS   (106000)

#define TLC_LOWER_PAGE_WRITE_LATENCY_NS  (820500)
#define TLC_CENTER_PAGE_WRITE_LATENCY_NS  (2225000)
#define TLC_UPPER_PAGE_WRITE_LATENCY_NS  (5734000)

#define TLC_CHNL_PAGE_TRANSFER_LATENCY_NS     (52433)
#define TLC_BLOCK_ERASE_LATENCY_NS       (3000000)

/* QLC NAND latency numbers in nanoseconds
   Read Latency is extrapolated from TLC drives based on Micron FMS'19 Presentation:
   Component-Level Characterization of 3D TLC, QLC, and Low-Latency NAND
   Write Latency is increased similar to read latencies, but may be higher in practice.
*/

#define QLC_LOWER_PAGE_READ_LATENCY_NS   (TLC_LOWER_PAGE_READ_LATENCY_NS * 1.05)
#define QLC_CENTER_LOWER_PAGE_READ_LATENCY_NS   (TLC_CENTER_PAGE_READ_LATENCY_NS * 1.1)
#define QLC_CENTER_UPPER_PAGE_READ_LATENCY_NS   (TLC_UPPER_PAGE_READ_LATENCY_NS * 1.2)
#define QLC_UPPER_PAGE_READ_LATENCY_NS   (TLC_UPPER_PAGE_READ_LATENCY_NS * 1.6)

#define QLC_LOWER_PAGE_WRITE_LATENCY_NS  (TLC_LOWER_PAGE_WRITE_LATENCY_NS * 1.05)
#define QLC_CENTER_LOWER_PAGE_WRITE_LATENCY_NS  (TLC_CENTER_PAGE_WRITE_LATENCY_NS * 1.1)
#define QLC_CENTER_UPPER_PAGE_WRITE_LATENCY_NS  (TLC_UPPER_PAGE_WRITE_LATENCY_NS * 1.2)
#define QLC_UPPER_PAGE_WRITE_LATENCY_NS  (TLC_UPPER_PAGE_WRITE_LATENCY_NS * 1.6)

#define QLC_CHNL_PAGE_TRANSFER_LATENCY_NS	(52433)
#define QLC_BLOCK_ERASE_LATENCY_NS       (3000000)

#define MLC_LOWER_PAGE  (0)
#define MLC_UPPER_PAGE  (1)

#define TLC_LOWER_PAGE (0)
#define TLC_CENTER_PAGE (1)
#define TLC_UPPER_PAGE (2)

#define QLC_LOWER_PAGE (0)
#define QLC_LOWER_CENTER_PAGE (1)
#define QLC_UPPER_CENTER_PAGE (2)
#define QLC_UPPER_PAGE (3)

#define PPA_CH(ln, ppa)  ((ppa & ln->ppaf.ch_mask) >> ln->ppaf.ch_offset)
#define PPA_LUN(ln, ppa) ((ppa & ln->ppaf.lun_mask) >> ln->ppaf.lun_offset)
#define PPA_PLN(ln, ppa) ((ppa & ln->ppaf.pln_mask) >> ln->ppaf.pln_offset)
#define PPA_BLK(ln, ppa) ((ppa & ln->ppaf.blk_mask) >> ln->ppaf.blk_offset)
#define PPA_PG(ln, ppa)  ((ppa & ln->ppaf.pg_mask) >> ln->ppaf.pg_offset)
#define PPA_SEC(ln, ppa) ((ppa & ln->ppaf.sec_mask) >> ln->ppaf.sec_offset)

#define MAX_SUPPORTED_PAGES_PER_BLOCK (512)
/* Lower/Upper page format within one block */
static int mlc_tbl[MAX_SUPPORTED_PAGES_PER_BLOCK];
static int tlc_tbl[MAX_SUPPORTED_PAGES_PER_BLOCK];
static int qlc_tbl[MAX_SUPPORTED_PAGES_PER_BLOCK];

static inline uint8_t get_page_type(FemuCtrl *n, int pg)
{
    switch (n->cell_type) {
        case TLC_CELL:
            return tlc_tbl[pg];
        case QLC_CELL:
            return qlc_tbl[pg];
        default:
            return mlc_tbl[pg];
    }
}

void init_nand_page_pairing(FemuCtrl *n);
void init_tlc_page_pairing(FemuCtrl *n);
void init_qlc_page_pairing(FemuCtrl *n);

#endif

