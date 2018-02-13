// File: vssim_config_manager.h
// Date: 2014. 12. 03.
// Author: Jinsoo Yoo (jedisty@hanyang.ac.kr)
// Copyright(c)2014
// Hanyang University, Seoul, Korea
// Embedded Software Systems Laboratory. All right reserved

#ifndef _CONFIG_MANAGER_H_
#define _CONFIG_MANAGER_H_

#include "common.h"

struct ssdconf {
    /* SSD Configuration */
    int SECTOR_SIZE;
    int PAGE_SIZE;

    int64_t SECTOR_NB;
    int PAGE_NB;
    int FLASH_NB;
    int BLOCK_NB;
    int CHANNEL_NB;
    int PLANES_PER_FLASH;

    int SECTORS_PER_PAGE;
    int PAGES_PER_FLASH;
    int64_t PAGES_IN_SSD;

    /* Coperd: add gc related structure */
    int GC_MODE; //= CHANNEL_BLOCKING; /* Coperd: by default we use channel blocking */
    //int64_t *gc_slot;

    int WAY_NB;
    int OVP;

    /* Mapping Table */
    int DATA_BLOCK_NB;
    int64_t BLOCK_MAPPING_ENTRY_NB;		

#ifdef PAGE_MAP
    int64_t PAGE_MAPPING_ENTRY_NB;
#endif

#if defined PAGE_MAP || defined BLOCK_MAP
    int64_t EACH_EMPTY_TABLE_ENTRY_NB;
    int EMPTY_TABLE_ENTRY_NB;
    int VICTIM_TABLE_ENTRY_NB;
#endif

#if defined FAST_FTL || defined LAST_FTL
    int LOG_RAND_BLOCK_NB;
    int LOG_SEQ_BLOCK_NB;

    int64_t DATA_MAPPING_ENTRY_NB;
    int64_t RAN_MAPPING_ENTRY_NB;
    int64_t SEQ_MAPPING_ENTRY_NB;
    int64_t RAN_LOG_MAPPING_ENTRY_NB;
    int64_t EACH_EMPTY_BLOCK_ENTRY_NB;

    int EMPTY_BLOCK_TABLE_NB;
#endif

#ifdef DA_MAP
    int64_t DA_PAGE_MAPPING_ENTRY_NB;
    int64_t DA_BLOCK_MAPPING_ENTRY_NB;
    int64_t EACH_EMPTY_TABLE_ENTRY_NB;
    int EMPTY_TABLE_ENTRY_NB;
    int VICTIM_TABLE_ENTRY_NB;
#endif

    /* NAND Flash Delay */
    int REG_WRITE_DELAY;
    int CELL_PROGRAM_DELAY;
    int REG_READ_DELAY;
    int CELL_READ_DELAY;
    int BLOCK_ERASE_DELAY;
    int CHANNEL_SWITCH_DELAY_W;
    int CHANNEL_SWITCH_DELAY_R;

    int DSM_TRIM_ENABLE;
    int IO_PARALLELISM;

    /* Garbage Collection */
#if defined PAGE_MAP || defined BLOCK_MAP || defined DA_MAP
    double GC_THRESHOLD;			
    double GC_THRESHOLD_HARD;	
    int GC_THRESHOLD_BLOCK_NB;
    int GC_THRESHOLD_BLOCK_NB_HARD;	
    int GC_THRESHOLD_BLOCK_NB_EACH;	
    int GC_VICTIM_NB;
#endif

    /* Write Buffer */
    uint64_t WRITE_BUFFER_FRAME_NB;		// 8192 for 4MB with 512B Sector size
    uint64_t READ_BUFFER_FRAME_NB;

    /* Map Cache */
#if defined FTL_MAP_CACHE || defined Polymorphic_FTL
    int CACHE_IDX_SIZE;
#endif

#ifdef FTL_MAP_CACHE
    uint64_t MAP_ENTRY_SIZE;
    uint64_t MAP_ENTRIES_PER_PAGE;
    uint64_t MAP_ENTRY_NB;
#endif

    /* HOST Event Queue */
#ifdef HOST_QUEUE
    uint64_t HOST_QUEUE_ENTRY_NB;
#endif

    /* Rand Log Block Write policy */
#if defined FAST_FTL || defined LAST_FTL
    int PARAL_DEGREE;                       // added by js
    int PARAL_COUNT;                        // added by js
#endif

    /* LAST FTL */
#ifdef LAST_FTL
    int HOT_PAGE_NB_THRESHOLD;              // added by js
    int SEQ_THRESHOLD;                      // added by js
#endif

    /* Polymorphic FTL */
#ifdef Polymorphic_FTL
    int PHY_SPARE_SIZE;

    int64_t NR_PHY_BLOCKS;
    int64_t NR_PHY_PAGES;
    int64_t NR_PHY_SECTORS;

    int NR_RESERVED_PHY_SUPER_BLOCKS;
    int NR_RESERVED_PHY_BLOCKS;
    int NR_RESERVED_PHY_PAGES;
#endif

    char FILE_NAME_HDA[1024]; // = {0,};
    char FILE_NAME_HDB[1024]; // = {0,};
};

struct ssdstate {
    struct ssdconf ssdparams;
    char ssdname[64];
    char conffile[64];
    char warmupfile[64];
    int in_warmup_stage;
    int64_t *gc_slot;
    FILE *statfp;
    char statfile[64];

    int64_t stat_last_ts;// = 0;
    int fail_cnt;// = 0;
    int64_t nb_total_reads; // = 0, nb_blocked_reads = 0;
    int64_t nb_blocked_reads;
    int64_t nb_blocked_writes;
    int64_t nb_total_writes; // = 0;
    int64_t nb_total_wr_sz;  //= 0, nb_total_rd_sz = 0;
    int64_t nb_total_rd_sz;
    int64_t last_time; // = 0;
    int gc_count; // = 0;
    int stacking_gc_count;
    int last_gc_cnt; // = 0;
    int64_t mygc_cnt;// = 0;
    int64_t mycopy_page_nb;// = 0;
    int64_t time_nvme_rw;// = 0; 
    int64_t time_ssd_write;// = 0; 
    int64_t time_ssd_read; // = 0;
    int64_t time_gc; // = 0; 
    int64_t time_svb; 
    int64_t time_cp; 
    int64_t time_up;
    int64_t nb_nvme_rw;// = 0;

    int g_init; // = 0;

    int64_t *mapping_table;

    int* reg_io_cmd;	// READ, WRITE, ERASE
    int* reg_io_type;	// SEQ, RAN, MERGE, GC, etc..

    int64_t* reg_io_time;
    int64_t* cell_io_time;

    int** access_nb;
    int64_t* io_overhead;

    int old_channel_nb;
    int old_channel_cmd;
    int64_t old_channel_time;

    int64_t init_diff_reg; //=0;

    int64_t io_alloc_overhead; //=0;
    int64_t io_update_overhead; //=0;


    int64_t* inverse_mapping_table;
    void* block_state_table;

    void* empty_block_list;
    void* victim_block_list;

    int64_t total_empty_block_nb;
    int64_t total_victim_block_nb;
    unsigned int empty_block_table_index;

    /* Average IO Time */
    double avg_write_delay;
    double total_write_count;
    double total_write_delay;

    double avg_read_delay;
    double total_read_count;
    double total_read_delay;

    double avg_gc_write_delay;
    double total_gc_write_count;
    double total_gc_write_delay;

    double avg_gc_read_delay;
    double total_gc_read_count;
    double total_gc_read_delay;

    double avg_seq_write_delay;
    double total_seq_write_count;
    double total_seq_write_delay;

    double avg_ran_write_delay;
    double total_ran_write_count;
    double total_ran_write_delay;

    double avg_ran_cold_write_delay;
    double total_ran_cold_write_count;
    double total_ran_cold_write_delay;

    double avg_ran_hot_write_delay;
    double total_ran_hot_write_count;
    double total_ran_hot_write_delay;

    double avg_seq_merge_read_delay;
    double total_seq_merge_read_count;
    double total_seq_merge_read_delay;

    double avg_ran_merge_read_delay;
    double total_ran_merge_read_count;
    double total_ran_merge_read_delay;

    double avg_seq_merge_write_delay;
    double total_seq_merge_write_count;
    double total_seq_merge_write_delay;

    double avg_ran_merge_write_delay;
    double total_ran_merge_write_count;
    double total_ran_merge_write_delay;

    double avg_ran_cold_merge_write_delay;
    double total_ran_cold_merge_write_count;
    double total_ran_cold_merge_write_delay;

    double avg_ran_hot_merge_write_delay;
    double total_ran_hot_merge_write_count;
    double total_ran_hot_merge_write_delay;

    /* IO Latency */
    unsigned int io_request_nb;
    unsigned int io_request_seq_nb;

    struct io_request* io_request_start;
    struct io_request* io_request_end;

    /* Calculate IO Latency */
    double read_latency_count;
    double write_latency_count;

    double avg_read_latency;
    double avg_write_latency;

    /* SSD Util */
    double ssd_util;
    int64_t written_page_nb;

    /* timestamps for channels and chips */
    int64_t *chnl_next_avail_time;
    int64_t *chip_next_avail_time;
};


/* SSD Configuration */
//extern int SECTOR_SIZE;
//extern int PAGE_SIZE;

//extern int64_t SECTOR_NB;
//extern int PAGE_NB;
//extern int FLASH_NB;
//extern int BLOCK_NB;
//extern int CHANNEL_NB;
//extern int PLANES_PER_FLASH;

//extern int SECTORS_PER_PAGE;
//extern int PAGES_PER_FLASH;
//extern int64_t PAGES_IN_SSD;

//extern int WAY_NB;
//extern int OVP;

/* Mapping Table */
//extern int DATA_BLOCK_NB;
//extern int64_t BLOCK_MAPPING_ENTRY_NB;

#ifdef PAGE_MAP
//extern int64_t PAGE_MAPPING_ENTRY_NB;
#endif

#if defined PAGE_MAP || defined BLOCK_MAP
//extern int64_t EACH_EMPTY_TABLE_ENTRY_NB;
//extern int EMPTY_TABLE_ENTRY_NB;
//extern int VICTIM_TABLE_ENTRY_NB;
#endif

#if defined FAST_FTL || defined LAST_FTL
//extern int LOG_RAND_BLOCK_NB;
//extern int LOG_SEQ_BLOCK_NB;

//extern int64_t DATA_MAPPING_ENTRY_NB;          // added by js
//extern int64_t RAN_MAPPING_ENTRY_NB;           // added by js
//extern int64_t SEQ_MAPPING_ENTRY_NB;           // added by js
//extern int64_t RAN_LOG_MAPPING_ENTRY_NB;       // added by js
//extern int64_t EACH_EMPTY_BLOCK_ENTRY_NB;      // added by js

//extern int EMPTY_BLOCK_TABLE_NB;
#endif

#ifdef DA_MAP
//extern int64_t DA_PAGE_MAPPING_ENTRY_NB;
//extern int64_t DA_BLOCK_MAPPING_ENTRY_NB;
//extern int64_t EACH_EMPTY_TABLE_ENTRY_NB;
//extern int EMPTY_TABLE_ENTRY_NB;
//extern int VICTIM_TABLE_ENTRY_NB;
#endif

/* NAND Flash Delay */
//extern int REG_WRITE_DELAY;
//extern int CELL_PROGRAM_DELAY;
//extern int REG_READ_DELAY;
//extern int CELL_READ_DELAY;
//extern int BLOCK_ERASE_DELAY;
//extern int CHANNEL_SWITCH_DELAY_R;
//extern int CHANNEL_SWITCH_DELAY_W;

//extern int DSM_TRIM_ENABLE;
//extern int IO_PARALLELISM;

/* Garbage Collection */
#if defined PAGE_MAP || defined BLOCK_MAP || defined DA_MAP
//extern double GC_THRESHOLD;
//extern int GC_THRESHOLD_BLOCK_NB;
//extern int GC_THRESHOLD_BLOCK_NB_HARD;
//extern int GC_THRESHOLD_BLOCK_NB_EACH;
//extern int GC_VICTIM_NB;
#endif

/* Read / Write Buffer */
//extern uint64_t WRITE_BUFFER_FRAME_NB;		// 8192 for 32MB with 4KB Page size
//extern uint64_t READ_BUFFER_FRAME_NB;

/* Map Cache */
#if defined FTL_MAP_CACHE || defined Polymorphic_FTL
//extern int CACHE_IDX_SIZE;
#endif

#ifdef FTL_MAP_CACHE
//extern uint64_t MAP_ENTRY_SIZE;
//extern uint64_t MAP_ENTRIES_PER_PAGE;
//extern uint64_t MAP_ENTRY_NB;
#endif

/* HOST event queue */
#ifdef HOST_QUEUE
//extern uint64_t HOST_QUEUE_ENTRY_NB;
#endif

/* FAST Perf TEST */
#if defined FAST_FTL || defined LAST_FTL
//extern int PARAL_DEGREE;                       // added by js
//extern int PARAL_COUNT;                        // added by js
#endif

/* LAST FTL */
#ifdef LAST_FTL
//extern int HOT_PAGE_NB_THRESHOLD;              // added by js
//extern int SEQ_THRESHOLD;                      // added by js
#endif

/* Polymorphic FTL */
#ifdef Polymorphic_FTL
//extern int PHY_SPARE_SIZE;

//extern int64_t NR_PHY_BLOCKS;
//extern int64_t NR_PHY_PAGES;
//extern int64_t NR_PHY_SECTORS;

//extern int NR_RESERVED_PHY_SUPER_BLOCKS;
//extern int NR_RESERVED_PHY_BLOCKS;
//extern int NR_RESERVED_PHY_PAGES;
#endif

void INIT_SSD_CONFIG(struct ssdstate *ssd);

#ifdef DA_MAP
int64_t CALC_DA_PM_ENTRY_NB(struct ssdstate *ssd);
int64_t CALC_DA_BM_ENTRY_NB(struct ssdstate *ssd);
#endif

#endif
