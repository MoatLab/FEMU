// File: ftl_gc_manager.c
// Date: 2014. 12. 03.
// Author: Jinsoo Yoo (jedisty@hanyang.ac.kr)
// Copyright(c)2014
// Hanyang University, Seoul, Korea
// Embedded Software Systems Laboratory. All right reserved

#include "common.h"

//#define FTL_DEBUG

void GC_CHECK(struct ssdstate *ssd, unsigned int phy_flash_nb, unsigned int phy_block_nb)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int GC_VICTIM_NB = sc->GC_VICTIM_NB;
    int i, ret;

    if (ssd->total_empty_block_nb < sc->GC_THRESHOLD_BLOCK_NB) {
        for (i = 0; i < GC_VICTIM_NB; i++) {
            ret = GARBAGE_COLLECTION(ssd);
            if (ret == FAIL) {
                break;
            }
        }
    }
}

int GARBAGE_COLLECTION(struct ssdstate *ssd)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int FLASH_NB = sc->FLASH_NB;
    int PAGE_NB = sc->PAGE_NB;
    int PLANES_PER_FLASH = sc->PLANES_PER_FLASH;
    int EMPTY_TABLE_ENTRY_NB = sc->EMPTY_TABLE_ENTRY_NB;
    int BLOCK_ERASE_DELAY = sc->BLOCK_ERASE_DELAY;
    int GC_MODE = sc->GC_MODE;
    int CHANNEL_NB = sc->CHANNEL_NB;
    int64_t *gc_slot = ssd->gc_slot;

    int64_t gc_start = get_ts_in_ns();

    int i;
    int ret;
    int64_t lpn;
    int64_t old_ppn;
    int64_t new_ppn;

    unsigned int victim_phy_flash_nb = FLASH_NB;
    unsigned int victim_phy_block_nb = 0;

    char *valid_array;
    int copy_page_nb = 0;

    block_state_entry* b_s_entry;

    int64_t svb_start = get_ts_in_ns();
    ret = SELECT_VICTIM_BLOCK(ssd, &victim_phy_flash_nb, &victim_phy_block_nb);
    ssd->time_svb += get_ts_in_ns() - svb_start;

    if (ret == FAIL) {
        abort();
        return FAIL;
    }

    b_s_entry = GET_BLOCK_STATE_ENTRY(ssd, victim_phy_flash_nb, victim_phy_block_nb);
    valid_array = b_s_entry->valid_array;

    int64_t cp_start = get_ts_in_ns();

    /* Coperd: we only need one emtpy block */
#if 0
    empty_block_entry *gc_empty_block = GET_EMPTY_BLOCK(ssd, VICTIM_OVERALL, EMPTY_TABLE_ENTRY_NB);
    int64_t new_ppn_base = gc_empty_block->phy_flash_nb*BLOCK_NB*PAGE_NB \
                           + gc_empty_block->phy_block_nb*PAGE_NB \
                           + gc_empty_block->curr_phy_page_nb;

    gc_empty_block->curr_phy_page_nb += 1;
#endif

    //int64_t victim_block_base_ppn = victim_phy_flash_nb*PAGES_PER_FLASH + victim_phy_block_nb*PAGE_NB;

    for (i = 0; i < PAGE_NB; i++) {
        if (valid_array[i] == 'V') {
            ret = GET_NEW_PAGE(ssd, VICTIM_OVERALL, EMPTY_TABLE_ENTRY_NB, &new_ppn);
            //new_ppn = new_ppn_base;
            //new_ppn_base++;
            if (ret == FAIL) {
                printf("ERROR[%s] Get new page fail\n", __FUNCTION__);
                return FAIL;
            }

            /* Read a Valid Page from the Victim NAND Block */
            //n_io_info = CREATE_NAND_IO_INFO(ssd, i, GC_READ, -1, ssd->io_request_seq_nb);
            SSD_PAGE_READ(ssd, victim_phy_flash_nb, victim_phy_block_nb, i);

            /* Write the Valid Page*/
            //n_io_info = CREATE_NAND_IO_INFO(ssd, i, GC_WRITE, -1, ssd->io_request_seq_nb);
            SSD_PAGE_WRITE(ssd, CALC_FLASH(ssd, new_ppn), CALC_BLOCK(ssd, new_ppn), CALC_PAGE(ssd, new_ppn));

            //old_ppn =  victim_block_base_ppn  + i;
            old_ppn = victim_phy_flash_nb*sc->PAGES_PER_FLASH + victim_phy_block_nb*sc->PAGE_NB + i;

            //			lpn = inverse_page_mapping_table[old_ppn];
            lpn = GET_INVERSE_MAPPING_INFO(ssd, old_ppn);
            UPDATE_NEW_PAGE_MAPPING(ssd, lpn, new_ppn);

            copy_page_nb++;
        }
    }
    ssd->time_cp += get_ts_in_ns() - cp_start;

    if (copy_page_nb != b_s_entry->valid_page_nb) {
        abort();
        return FAIL;
    }

#ifdef FTL_DEBUG
    printf("[%s] [f: %d, b: %d] Copy Page : %d, total victim : %ld, total empty : %ld \n",__FUNCTION__, victim_phy_flash_nb, victim_phy_block_nb,  copy_page_nb, total_victim_block_nb, total_empty_block_nb);
#endif
    /* Coperd: keep track of #copy-pages of last GC */
    ssd->mycopy_page_nb += copy_page_nb; 

    int64_t up_start = get_ts_in_ns();
    SSD_BLOCK_ERASE(ssd, victim_phy_flash_nb, victim_phy_block_nb);
    UPDATE_BLOCK_STATE(ssd, victim_phy_flash_nb, victim_phy_block_nb, EMPTY_BLOCK);
    INSERT_EMPTY_BLOCK(ssd, victim_phy_flash_nb, victim_phy_block_nb);
    ssd->time_up += get_ts_in_ns() - up_start;

    ssd->gc_count++;

    /* Coperd: keep trace of #gc of last time */
    ssd->mygc_cnt += 1; 

    int64_t gc_time = BLOCK_ERASE_DELAY + copy_page_nb * 920 + 64 * 920;
    int slot = 0;
    if (GC_MODE == WHOLE_BLOCKING) {
        slot = 0;
    } else if (GC_MODE == CHANNEL_BLOCKING) {
        slot = victim_phy_flash_nb % CHANNEL_NB;
    } else if (GC_MODE == CHIP_BLOCKING) {
        slot = victim_phy_flash_nb * PLANES_PER_FLASH + victim_phy_block_nb % PLANES_PER_FLASH;
    } else {
        printf("Coperd, slot=%d, Impossible!\n", slot);
    }

    int64_t curtime = get_usec();
    if (gc_slot[slot] <= curtime) {
        gc_slot[slot] = curtime + gc_time;
    } else {
        gc_slot[slot] += gc_time;
        ssd->stacking_gc_count++;
    }

    if (ssd->gc_count % 100 == 0) {
        printf("[%s],real_blocking_gc=%d,total_gc_cal=%d, avg_copy_pages=%d, "
                "total_stacking_gc=%d\n", ssd->ssdname, 
                ssd->gc_count-ssd->stacking_gc_count, ssd->gc_count, 
                copy_page_nb, ssd->stacking_gc_count);
    }

    ssd->time_gc += get_ts_in_ns() - gc_start;

    return SUCCESS;
}

/* Greedy Garbage Collection Algorithm */
int SELECT_VICTIM_BLOCK(struct ssdstate *ssd, unsigned int *phy_flash_nb,
        unsigned int *phy_block_nb)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int PAGE_NB = sc->PAGE_NB;
    int VICTIM_TABLE_ENTRY_NB = sc->VICTIM_TABLE_ENTRY_NB;

    void *victim_block_list = ssd->victim_block_list;

    int i, j;
    int entry_nb = 0;

    victim_block_root *curr_v_b_root;
    victim_block_entry *curr_v_b_entry;
    victim_block_entry *victim_block = NULL;

    block_state_entry *b_s_entry;
    int curr_valid_page_nb;

    if (ssd->total_victim_block_nb == 0) {
        printf("FEMU-FTL: no victim block left\n");
        return FAIL;
    }

    curr_v_b_root = (victim_block_root *)victim_block_list;

    for (i = 0; i < VICTIM_TABLE_ENTRY_NB; i++) {
        if (curr_v_b_root->victim_block_nb != 0) {
            entry_nb = curr_v_b_root->victim_block_nb;
            curr_v_b_entry = curr_v_b_root->head;
            if (victim_block == NULL) {
                victim_block = curr_v_b_root->head;
                b_s_entry = GET_BLOCK_STATE_ENTRY(ssd, victim_block->phy_flash_nb, victim_block->phy_block_nb);
                curr_valid_page_nb = b_s_entry->valid_page_nb;
            }
        } else {
            entry_nb = 0;
        }

        for (j = 0; j < entry_nb; j++) {
            b_s_entry = GET_BLOCK_STATE_ENTRY(ssd, curr_v_b_entry->phy_flash_nb, curr_v_b_entry->phy_block_nb);
            if (curr_valid_page_nb > b_s_entry->valid_page_nb) {
                victim_block = curr_v_b_entry;
                curr_valid_page_nb = b_s_entry->valid_page_nb;
            }
            curr_v_b_entry = curr_v_b_entry->next;
        }

        curr_v_b_root += 1;
    }

    if (curr_valid_page_nb == PAGE_NB) {
        ssd->fail_cnt++;
        return FAIL;
    }

    *phy_flash_nb = victim_block->phy_flash_nb;
    *phy_block_nb = victim_block->phy_block_nb;
    EJECT_VICTIM_BLOCK(ssd, victim_block);

    return SUCCESS;
}
