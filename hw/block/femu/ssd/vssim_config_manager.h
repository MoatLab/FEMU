// File: vssim_config_manager.h
// Date: 2014. 12. 03.
// Author: Jinsoo Yoo (jedisty@hanyang.ac.kr)
// Copyright(c)2014
// Hanyang University, Seoul, Korea
// Embedded Software Systems Laboratory. All right reserved

#ifndef _CONFIG_MANAGER_H_
#define _CONFIG_MANAGER_H_

#include "qemu/osdep.h"
#include "qemu/thread.h"
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
    int GC_MODE;
    int OVP;

    /* Mapping Table */
    int DATA_BLOCK_NB;
    int64_t BLOCK_MAPPING_ENTRY_NB;		

    int64_t PAGE_MAPPING_ENTRY_NB;

    int64_t EACH_EMPTY_TABLE_ENTRY_NB;
    int EMPTY_TABLE_ENTRY_NB;
    int VICTIM_TABLE_ENTRY_NB;

    /* NAND Flash Delay */
    int REG_WRITE_DELAY;
    int CELL_PROGRAM_DELAY;
    int REG_READ_DELAY;
    int CELL_READ_DELAY;
    int BLOCK_ERASE_DELAY;
    int CHANNEL_SWITCH_DELAY_W;
    int CHANNEL_SWITCH_DELAY_R;

    int IO_PARALLELISM;

    /* Garbage Collection */
    double GC_THRESHOLD;			
    double GC_THRESHOLD_HARD;	
    int GC_THRESHOLD_BLOCK_NB;
    int GC_THRESHOLD_BLOCK_NB_HARD;	
    int GC_THRESHOLD_BLOCK_NB_EACH;	
    int GC_VICTIM_NB;
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

    int64_t *inverse_mapping_table;
    void *block_state_table;

    void *empty_block_list;
    void *victim_block_list;

    int64_t total_empty_block_nb;
    int64_t total_victim_block_nb;
    unsigned int empty_block_table_index;

    /* timestamps for channels and chips */
    int64_t *chnl_next_avail_time;
    int64_t *chip_next_avail_time;

    struct rte_ring *to_ftl;
    struct rte_ring *to_poller;
   
    QemuThread ftl_thread;
    bool *dataplane_started_ptr;
};

void INIT_SSD_CONFIG(struct ssdstate *ssd);

#endif
