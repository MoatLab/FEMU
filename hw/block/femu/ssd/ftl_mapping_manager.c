// File: ftl_mapping_manager.c
// Date: 2014. 12. 03.
// Author: Jinsoo Yoo (jedisty@hanyang.ac.kr)
// Copyright(c)2014
// Hanyang University, Seoul, Korea
// Embedded Software Systems Laboratory. All right reserved

#include "common.h"

int64_t* mapping_table;
void* block_table_start;

void INIT_MAPPING_TABLE(struct ssdstate *ssd)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int i;	

    /* Allocation Memory for Mapping Table */
    ssd->mapping_table = (int64_t*)calloc(sc->PAGE_MAPPING_ENTRY_NB, sizeof(int64_t));
    if(ssd->mapping_table == NULL){
        printf("ERROR[%s] Calloc mapping table fail\n", __FUNCTION__);
        return;
    }

    /* Initialization Mapping Table */
    for(i=0;i<sc->PAGE_MAPPING_ENTRY_NB;i++){
        ssd->mapping_table[i] = -1;
    }
}

void TERM_MAPPING_TABLE(struct ssdstate *ssd)
{
	/* Free memory for mapping table */
	free(ssd->mapping_table);
}

int64_t GET_MAPPING_INFO(struct ssdstate *ssd, int64_t lpn)
{
    int64_t *mapping_table = ssd->mapping_table;
	int64_t ppn = mapping_table[lpn];

	return ppn;
}

int GET_NEW_PAGE(struct ssdstate *ssd, int mode, int mapping_index, int64_t* ppn)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int BLOCK_NB = sc->BLOCK_NB;
    int PAGE_NB = sc->PAGE_NB;


	empty_block_entry* curr_empty_block;

	curr_empty_block = GET_EMPTY_BLOCK(ssd, mode, mapping_index);

	/* If the flash memory has no empty block,
                Get empty block from the other flash memories */
        if(mode == VICTIM_INCHIP && curr_empty_block == NULL){
                /* Try again */
                curr_empty_block = GET_EMPTY_BLOCK(ssd, VICTIM_OVERALL, mapping_index);
        }

	if(curr_empty_block == NULL){
		printf("ERROR[%s] fail\n", __FUNCTION__);
		return FAIL;
	}

	*ppn = curr_empty_block->phy_flash_nb*BLOCK_NB*PAGE_NB \
	       + curr_empty_block->phy_block_nb*PAGE_NB \
	       + curr_empty_block->curr_phy_page_nb;

	curr_empty_block->curr_phy_page_nb += 1;

	return SUCCESS;
}

int UPDATE_OLD_PAGE_MAPPING(struct ssdstate *ssd, int64_t lpn)
{
	int64_t old_ppn;

	old_ppn = GET_MAPPING_INFO(ssd, lpn);

	if (old_ppn == -1) {
		return SUCCESS;
    } else {
        UPDATE_BLOCK_STATE_ENTRY(ssd, CALC_FLASH(ssd, old_ppn), CALC_BLOCK(ssd, old_ppn), CALC_PAGE(ssd, old_ppn), INVALID);
        UPDATE_INVERSE_MAPPING(ssd, old_ppn, -1);
    }

	return SUCCESS;
}

int UPDATE_NEW_PAGE_MAPPING(struct ssdstate *ssd, int64_t lpn, int64_t ppn)
{
    int64_t *mapping_table = ssd->mapping_table;

	mapping_table[lpn] = ppn;

	/* Update Inverse Page Mapping Table */
	UPDATE_BLOCK_STATE_ENTRY(ssd, CALC_FLASH(ssd, ppn), CALC_BLOCK(ssd, ppn), CALC_PAGE(ssd, ppn), VALID);
	UPDATE_BLOCK_STATE(ssd, CALC_FLASH(ssd, ppn), CALC_BLOCK(ssd, ppn), DATA_BLOCK);
	UPDATE_INVERSE_MAPPING(ssd, ppn, lpn);

	return SUCCESS;
}

unsigned int CALC_FLASH(struct ssdstate *ssd, int64_t ppn)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int BLOCK_NB = sc->BLOCK_NB;
    int PAGE_NB = sc->PAGE_NB;
    int FLASH_NB = sc->FLASH_NB;

	unsigned int flash_nb = (ppn / PAGE_NB) / BLOCK_NB;

	if (flash_nb >= FLASH_NB) {
		printf("FEMU-FTL:%s,invalid flash#:%d (>%d)\n", __func__, flash_nb, FLASH_NB);
        abort();
	}

	return flash_nb;
}

unsigned int CALC_BLOCK(struct ssdstate *ssd, int64_t ppn)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int BLOCK_NB = sc->BLOCK_NB;
    int PAGE_NB = sc->PAGE_NB;

	unsigned int block_nb = (ppn / PAGE_NB) % BLOCK_NB;
	if (block_nb >= BLOCK_NB) {
		printf("FEMU-FTL:%s,invalid block#:%d (>%d)\n", __func__, block_nb, BLOCK_NB);
        abort();
	}

	return block_nb;
}

unsigned int CALC_PAGE(struct ssdstate *ssd, int64_t ppn)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int PAGE_NB = sc->PAGE_NB;

	unsigned int page_nb = ppn % PAGE_NB;

	return page_nb;
}
