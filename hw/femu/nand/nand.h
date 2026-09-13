#ifndef __FEMU_NAND_H
#define __FEMU_NAND_H

#define MAX_SUPPORTED_PAGES_PER_BLOCK (512)

/*
 * SLC NAND latency numbers in naoseconds
 */
#define SLC_PAGE_READ_LATENCY_NS          (40000)
#define SLC_PAGE_WRITE_LATENCY_NS         (800000)
#define SLC_BLOCK_ERASE_LATENCY_NS        (2000000)
#define SLC_CHNL_PAGE_TRANSFER_LATENCY_NS (20000)

/*
 * MLC NAND latency numbers in nanoseconds
 *
 * Profiled from Micron L95B MLC NAND Flash chips used in CNEX OCSSD
 */
#define MLC_LOWER_PAGE_READ_LATENCY_NS    (48000)
#define MLC_UPPER_PAGE_READ_LATENCY_NS    (64000)
#define MLC_LOWER_PAGE_WRITE_LATENCY_NS   (850000)
#define MLC_UPPER_PAGE_WRITE_LATENCY_NS   (2300000)
#define MLC_CHNL_PAGE_TRANSFER_LATENCY_NS (52433)
#define MLC_BLOCK_ERASE_LATENCY_NS        (3000000)

/*
 * TLC NAND latency numbers in nanoseconds
 *
 * Based on the paper: "SimpleSSD: Modeling Solid State Drives for Holistic
 *                      System Simulation"
 */
#define TLC_LOWER_PAGE_READ_LATENCY_NS    (56500)
#define TLC_CENTER_PAGE_READ_LATENCY_NS   (77500)
#define TLC_UPPER_PAGE_READ_LATENCY_NS    (106000)

#define TLC_LOWER_PAGE_WRITE_LATENCY_NS   (820500)
#define TLC_CENTER_PAGE_WRITE_LATENCY_NS  (2225000)
#define TLC_UPPER_PAGE_WRITE_LATENCY_NS   (5734000)

#define TLC_CHNL_PAGE_TRANSFER_LATENCY_NS (52433)
#define TLC_BLOCK_ERASE_LATENCY_NS        (3000000)

/*
 * QLC NAND latency numbers in nanoseconds
 *
 * Measured on Intel 96-layer 3D QLC gen3 (1024Q3D3A):
 *   Q. Chen et al., "PACA: A Page Type Aware Read Cache Scheme in QLC
 *   Flash-based SSDs", ICCD 2022, Fig. 2 and Table I.
 *
 * PACA reports one average program latency rather than a value for each page
 * class. Keep the four program entries equal so only measured page-class
 * variation is represented.
 */

#define QLC_LOWER_PAGE_READ_LATENCY_NS          (47900)
#define QLC_CENTER_LOWER_PAGE_READ_LATENCY_NS   (76200)
#define QLC_CENTER_UPPER_PAGE_READ_LATENCY_NS   (134600)
#define QLC_UPPER_PAGE_READ_LATENCY_NS          (228100)

#define QLC_LOWER_PAGE_WRITE_LATENCY_NS         (1860000)
#define QLC_CENTER_LOWER_PAGE_WRITE_LATENCY_NS  (1860000)
#define QLC_CENTER_UPPER_PAGE_WRITE_LATENCY_NS  (1860000)
#define QLC_UPPER_PAGE_WRITE_LATENCY_NS         (1860000)

/* 16 KiB at 800 MT/s. Sweep 40960/20480/13653 ns for 400/800/1200 MT/s. */
#define QLC_CHNL_PAGE_TRANSFER_LATENCY_NS        (20480)
#define QLC_BLOCK_ERASE_LATENCY_NS               (6340000)

enum {
    SLC_PAGE              = 0,

    MLC_LOWER_PAGE        = 0,
    MLC_UPPER_PAGE        = 1,

    TLC_LOWER_PAGE        = 0,
    TLC_CENTER_PAGE       = 1,
    TLC_UPPER_PAGE        = 2,

    QLC_LOWER_PAGE        = 0,
    QLC_LOWER_CENTER_PAGE = 1,
    QLC_UPPER_CENTER_PAGE = 2,
    QLC_UPPER_PAGE        = 3,
};

/*
 * Rated program/erase endurance per cell type, in cycles. Each extra bit per
 * cell costs roughly a factor of three; these are the usual published orders
 * of magnitude rather than any one part's datasheet. SMART's percentage_used
 * divides the rating into the cycles the media has actually taken.
 */
#define SLC_RATED_PE_CYCLES     (100000)
#define MLC_RATED_PE_CYCLES     (3000)
#define TLC_RATED_PE_CYCLES     (1000)
#define QLC_RATED_PE_CYCLES     (300)
#define PLC_RATED_PE_CYCLES     (100)

typedef enum FlashType {
    SLC            = 1,
    MLC            = 2,
    TLC            = 3,
    QLC            = 4,
    PLC            = 5,
    MAX_FLASH_TYPE = 6,
} FlashType;

/*
 * This is a cheat sheet of the timing parameters for all the supported NAND
 * flash types: SLC/MLC/TLC/QLC/PLC
 */
typedef struct NandFlashTiming {
    int64_t pg_rd_lat[MAX_FLASH_TYPE][MAX_FLASH_TYPE];
    int64_t pg_wr_lat[MAX_FLASH_TYPE][MAX_FLASH_TYPE];
    int64_t blk_er_lat[MAX_FLASH_TYPE];
    int64_t chnl_pg_xfer_lat[MAX_FLASH_TYPE];
} NandFlashTiming;

/*
 * Shared NAND physics state lives once in nand.c (a single compiled unit) and is
 * referenced everywhere via these extern declarations. It used to be header-static,
 * which gave every including translation unit its own zero-initialized copy: only
 * nand.c's copy was ever initialized, so other readers (oc12.c, timing.c) saw
 * zeros. Making it a real linker symbol shares one initialized copy across modes.
 */
extern struct NandFlashTiming nand_flash_timing;

struct NandFlash {
    uint8_t flash_type;
    int64_t page_rd_lat[MAX_FLASH_TYPE];
    int64_t page_wr_lat[MAX_FLASH_TYPE];
    int64_t blk_er_lat;
    int64_t chnl_pg_xfer_lat;
};

#define PPA_CH(ln, ppa)  ((ppa & ln->ppaf.ch_mask) >> ln->ppaf.ch_offset)
#define PPA_LUN(ln, ppa) ((ppa & ln->ppaf.lun_mask) >> ln->ppaf.lun_offset)
#define PPA_PLN(ln, ppa) ((ppa & ln->ppaf.pln_mask) >> ln->ppaf.pln_offset)
#define PPA_BLK(ln, ppa) ((ppa & ln->ppaf.blk_mask) >> ln->ppaf.blk_offset)
#define PPA_PG(ln, ppa)  ((ppa & ln->ppaf.pg_mask) >> ln->ppaf.pg_offset)
#define PPA_SEC(ln, ppa) ((ppa & ln->ppaf.sec_mask) >> ln->ppaf.sec_offset)

/* Lower/Upper page-type table within one block, defined once in nand.c */
extern int slc_tbl[MAX_SUPPORTED_PAGES_PER_BLOCK];
extern int mlc_tbl[MAX_SUPPORTED_PAGES_PER_BLOCK];
extern int tlc_tbl[MAX_SUPPORTED_PAGES_PER_BLOCK];
extern int qlc_tbl[MAX_SUPPORTED_PAGES_PER_BLOCK];

uint8_t get_page_type(int flash_type, int pg);
int64_t get_page_read_latency(int flash_type, int page_type);
int64_t get_page_write_latency(int flash_type, int page_type);
int64_t get_blk_erase_latency(int flash_type);
uint32_t get_rated_pe_cycles(int flash_type);

int init_nand_flash(void *opaque);

#endif
