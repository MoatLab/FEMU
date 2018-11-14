// File: ftl_inverse_mapping_manager.c
// Date: 2014. 12. 03.
// Author: Jinsoo Yoo (jedisty@hanyang.ac.kr)
// Copyright(c)2014
// Hanyang University, Seoul, Korea
// Embedded Software Systems Laboratory. All right reserved

#include "common.h"

void INIT_INVERSE_MAPPING_TABLE(struct ssdstate *ssd)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int64_t PAGE_MAPPING_ENTRY_NB = sc->PAGE_MAPPING_ENTRY_NB;

	/* Allocation Memory for Inverse Page Mapping Table */
	ssd->inverse_mapping_table = (void*)calloc(PAGE_MAPPING_ENTRY_NB, sizeof(int64_t));
	if(ssd->inverse_mapping_table == NULL){
		printf("ERROR[%s] Calloc mapping table fail\n", __FUNCTION__);
		return;
	}

	/* Initialization Inverse Page Mapping Table */
	FILE* fp = fopen("./data/inverse_mapping.dat","r");
	if(fp != NULL){
		fread(ssd->inverse_mapping_table, sizeof(int64_t), PAGE_MAPPING_ENTRY_NB, fp);
	}
	else{
		int i;
		for(i=0;i<PAGE_MAPPING_ENTRY_NB;i++){
			ssd->inverse_mapping_table[i] = -1;
		}
	}
}

void INIT_BLOCK_STATE_TABLE(struct ssdstate *ssd)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int64_t BLOCK_MAPPING_ENTRY_NB = sc->BLOCK_MAPPING_ENTRY_NB;
    int64_t PAGE_MAPPING_ENTRY_NB = sc->PAGE_MAPPING_ENTRY_NB;

	/* Allocation Memory for Inverse Block Mapping Table */
	ssd->block_state_table = (void*)calloc(BLOCK_MAPPING_ENTRY_NB, sizeof(block_state_entry));
	if(ssd->block_state_table == NULL){
		printf("ERROR[%s] Calloc mapping table fail\n", __FUNCTION__);
		return;
	}

	/* Initialization Inverse Block Mapping Table */
	FILE* fp = fopen("./data/block_state_table.dat","r");
	if(fp != NULL){
		fread(ssd->block_state_table, sizeof(block_state_entry), BLOCK_MAPPING_ENTRY_NB, fp);
	}
	else{
		int i;
		block_state_entry* curr_b_s_entry = (block_state_entry*)ssd->block_state_table;

		for(i=0;i<BLOCK_MAPPING_ENTRY_NB;i++){
			curr_b_s_entry->type		= EMPTY_BLOCK;
			curr_b_s_entry->valid_page_nb	= 0;
			curr_b_s_entry->erase_count		= 0;
			curr_b_s_entry += 1;
		}
	}
}

void INIT_VALID_ARRAY(struct ssdstate *ssd)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    void *block_state_table = ssd->block_state_table;
    int BLOCK_MAPPING_ENTRY_NB = sc->BLOCK_MAPPING_ENTRY_NB;
    int PAGE_NB = sc->PAGE_NB;

	int i;
	block_state_entry* curr_b_s_entry = (block_state_entry*)block_state_table;
	char* valid_array;

	FILE* fp = fopen("./data/valid_array.dat","r");
	if(fp != NULL){
		for(i=0;i<BLOCK_MAPPING_ENTRY_NB;i++){
			valid_array = (char*)calloc(PAGE_NB, sizeof(char));
			fread(valid_array, sizeof(char), PAGE_NB, fp);
			curr_b_s_entry->valid_array = valid_array;

			curr_b_s_entry += 1;
		}
	}
	else{
		for(i=0;i<BLOCK_MAPPING_ENTRY_NB;i++){
			valid_array = (char*)calloc(PAGE_NB, sizeof(char));
			memset(valid_array,0,PAGE_NB);
			curr_b_s_entry->valid_array = valid_array;

			curr_b_s_entry += 1;
		}			
	}
}

void INIT_EMPTY_BLOCK_LIST(struct ssdstate *ssd)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int BLOCK_MAPPING_ENTRY_NB = sc->BLOCK_MAPPING_ENTRY_NB;
    int PLANES_PER_FLASH = sc->PLANES_PER_FLASH;
    int FLASH_NB = sc->FLASH_NB;
    int BLOCK_NB = sc->BLOCK_NB;
    int PAGE_NB = sc->PAGE_NB;
	int i, j, k;

	empty_block_entry* curr_entry;
	empty_block_root* curr_root;

	ssd->empty_block_list = (void*)calloc(PLANES_PER_FLASH * FLASH_NB, sizeof(empty_block_root));
	if(ssd->empty_block_list == NULL){
		printf("ERROR[%s] Calloc mapping table fail\n", __FUNCTION__);
		return;
	}

	FILE* fp = fopen("./data/empty_block_list.dat","r");
	if(fp != NULL){
		ssd->total_empty_block_nb = 0;
		fread(ssd->empty_block_list,sizeof(empty_block_root),PLANES_PER_FLASH*FLASH_NB, fp);
		curr_root = (empty_block_root*)ssd->empty_block_list;

		for(i=0;i<PLANES_PER_FLASH;i++){

			for(j=0;j<FLASH_NB;j++){

				ssd->total_empty_block_nb += curr_root->empty_block_nb;
				k = curr_root->empty_block_nb;
				while(k > 0){
					curr_entry = (empty_block_entry*)calloc(1, sizeof(empty_block_entry));
					if(curr_entry == NULL){
						printf("ERROR[%s] Calloc fail\n", __FUNCTION__);
						break;
					}

					fread(curr_entry, sizeof(empty_block_entry), 1, fp);
					curr_entry->next = NULL;

					if(k == curr_root->empty_block_nb){
						curr_root->head = curr_entry;
						curr_root->tail = curr_entry;
					}					
					else{
						curr_root->tail->next = curr_entry;
						curr_root->tail = curr_entry;
					}
					k--;
				}
				curr_root += 1;
			}
		}
		ssd->empty_block_table_index = 0;
	}
	else{
		curr_root = (empty_block_root*)ssd->empty_block_list;		

		for(i=0;i<PLANES_PER_FLASH;i++){

			for(j=0;j<FLASH_NB;j++){

				for(k=i;k<BLOCK_NB;k+=PLANES_PER_FLASH){

					curr_entry = (empty_block_entry*)calloc(1, sizeof(empty_block_entry));	
					if(curr_entry == NULL){
						printf("ERROR[%s] Calloc fail\n", __FUNCTION__);
						break;
					}
	
					if(k==i){
						curr_root->head = curr_entry;
						curr_root->tail = curr_entry;

						curr_root->tail->phy_flash_nb = j;
						curr_root->tail->phy_block_nb = k;
						curr_root->tail->curr_phy_page_nb = 0;
					}
					else{
						curr_root->tail->next = curr_entry;
						curr_root->tail = curr_entry;

						curr_root->tail->phy_flash_nb = j;
						curr_root->tail->phy_block_nb = k;
						curr_root->tail->curr_phy_page_nb = 0;
					}
					UPDATE_BLOCK_STATE(ssd, j, k, EMPTY_BLOCK);
				}
				curr_root->empty_block_nb = (unsigned int)sc->EACH_EMPTY_TABLE_ENTRY_NB;
				curr_root += 1;
			}
		}
		ssd->total_empty_block_nb = (int64_t)BLOCK_MAPPING_ENTRY_NB;
		ssd->empty_block_table_index = 0;
	}
}

void INIT_VICTIM_BLOCK_LIST(struct ssdstate *ssd)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int BLOCK_MAPPING_ENTRY_NB = sc->BLOCK_MAPPING_ENTRY_NB;
    int PLANES_PER_FLASH = sc->PLANES_PER_FLASH;
    int FLASH_NB = sc->FLASH_NB;
    int PAGE_NB = sc->PAGE_NB;
    int64_t EACH_EMPTY_TABLE_ENTRY_NB = sc->EACH_EMPTY_TABLE_ENTRY_NB;

	int i, j, k;

	victim_block_entry* curr_entry;
	victim_block_root* curr_root;

	ssd->victim_block_list = (void*)calloc(PLANES_PER_FLASH * FLASH_NB, sizeof(victim_block_root));
	if(ssd->victim_block_list == NULL){
		printf("ERROR[%s] Calloc mapping table fail\n", __FUNCTION__);
		return;
	}

	FILE* fp = fopen("./data/victim_block_list.dat","r");
	if(fp != NULL){
		ssd->total_victim_block_nb = 0;
		fread(ssd->victim_block_list, sizeof(victim_block_root), PLANES_PER_FLASH*FLASH_NB, fp);
		curr_root = (victim_block_root*)ssd->victim_block_list;

		for(i=0;i<PLANES_PER_FLASH;i++){

			for(j=0;j<FLASH_NB;j++){

				ssd->total_victim_block_nb += curr_root->victim_block_nb;
				k = curr_root->victim_block_nb;
				while(k > 0){
					curr_entry = (victim_block_entry*)calloc(1, sizeof(victim_block_entry));
					if(curr_entry == NULL){
						printf("ERROR[%s] Calloc fail\n", __FUNCTION__);
						break;
					}

					fread(curr_entry, sizeof(victim_block_entry), 1, fp);
					curr_entry->next = NULL;
					curr_entry->prev = NULL;

					if(k == curr_root->victim_block_nb){
						curr_root->head = curr_entry;
						curr_root->tail = curr_entry;
					}					
					else{
						curr_root->tail->next = curr_entry;
						curr_entry->prev = curr_root->tail;
						curr_root->tail = curr_entry;
					}
					k--;
				}
				curr_root += 1;
			}
		}
	}
	else{
		curr_root = (victim_block_root*)ssd->victim_block_list;		

		for(i=0;i<PLANES_PER_FLASH;i++){

			for(j=0;j<FLASH_NB;j++){

				curr_root->head = NULL;
				curr_root->tail = NULL;
				curr_root->victim_block_nb = 0;

				curr_root += 1;
			}
		}
		ssd->total_victim_block_nb = 0;
	}
}

void TERM_INVERSE_MAPPING_TABLE(struct ssdstate *ssd)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    void *inverse_mapping_table = ssd->inverse_mapping_table;
    int64_t PAGE_MAPPING_ENTRY_NB = sc->PAGE_MAPPING_ENTRY_NB;

	FILE* fp = fopen("./data/inverse_mapping.dat", "w");
	if(fp==NULL){
		printf("ERROR[%s] File open fail\n", __FUNCTION__);
		return;
	}

	/* Write The inverse page table to file */
	fwrite(inverse_mapping_table, sizeof(int64_t), PAGE_MAPPING_ENTRY_NB, fp);

	/* Free the inverse page table memory */
	free(inverse_mapping_table);
}

#if 0
void TERM_BLOCK_STATE_TABLE(struct ssdstate *ssd)
{
	FILE* fp = fopen("./data/block_state_table.dat","w");
	if(fp==NULL){
		printf("ERROR[%s] File open fail\n", __FUNCTION__);
		return;
	}

	/* Write The inverse block table to file */
	fwrite(block_state_table, sizeof(block_state_entry), BLOCK_MAPPING_ENTRY_NB, fp);

	/* Free The inverse block table memory */
	free(block_state_table);
}
#endif

#if 0
void TERM_VALID_ARRAY(void)
{
	int i;
	block_state_entry* curr_b_s_entry = (block_state_entry*)block_state_table;
	char* valid_array;

	FILE* fp = fopen("./data/valid_array.dat","w");
        if(fp == NULL){
		printf("ERROR[%s] File open fail\n", __FUNCTION__);
		return;
	}
 
	for(i=0;i<BLOCK_MAPPING_ENTRY_NB;i++){
		valid_array = curr_b_s_entry->valid_array;
		fwrite(valid_array, sizeof(char), PAGE_NB, fp);
		curr_b_s_entry += 1;
	}
}
#endif

#if 0
void TERM_EMPTY_BLOCK_LIST(void)
{
	int i, j, k;

	empty_block_entry* curr_entry;
	empty_block_root* curr_root;

	FILE* fp = fopen("./data/empty_block_list.dat","w");
	if(fp==NULL){
		printf("ERROR[%s] File open fail\n", __FUNCTION__);
	}

	fwrite(empty_block_list,sizeof(empty_block_root),PLANES_PER_FLASH*FLASH_NB, fp);

	curr_root = (empty_block_root*)empty_block_list;
	for(i=0;i<PLANES_PER_FLASH;i++){

		for(j=0;j<FLASH_NB;j++){

			k = curr_root->empty_block_nb;
			if(k != 0){
				curr_entry = (empty_block_entry*)curr_root->head;
			}
			while(k > 0){

				fwrite(curr_entry, sizeof(empty_block_entry), 1, fp);

				if(k != 1){
					curr_entry = curr_entry->next;
				}
				k--;
			}
			curr_root += 1;
		}
	}
}
#endif

#if 0
void TERM_VICTIM_BLOCK_LIST(void)
{
	int i, j, k;

	victim_block_entry* curr_entry;
	victim_block_root* curr_root;

	FILE* fp = fopen("./data/victim_block_list.dat","w");
	if(fp==NULL){
		printf("ERROR[%s] File open fail\n", __FUNCTION__);
	}

	fwrite(victim_block_list, sizeof(victim_block_root), PLANES_PER_FLASH*FLASH_NB, fp);

	curr_root = (victim_block_root*)victim_block_list;
	for(i=0;i<PLANES_PER_FLASH;i++){

		for(j=0;j<FLASH_NB;j++){

			k = curr_root->victim_block_nb;
			if(k != 0){
				curr_entry = (victim_block_entry*)curr_root->head;
			}
			while(k > 0){

				fwrite(curr_entry, sizeof(victim_block_entry), 1, fp);

				if(k != 1){
					curr_entry = curr_entry->next;
				}
				k--;
			}
			curr_root += 1;
		}
	}
}
#endif

empty_block_entry* GET_EMPTY_BLOCK(struct ssdstate *ssd, int mode, int mapping_index)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    void *empty_block_list = ssd->empty_block_list;
    int64_t EMPTY_TABLE_ENTRY_NB = sc->EMPTY_TABLE_ENTRY_NB;
    int PAGE_NB = sc->PAGE_NB;
    int PLANES_PER_FLASH = sc->PLANES_PER_FLASH;

    if(ssd->total_empty_block_nb == 0){
        printf("ERROR[%s] There is no empty block\n", __FUNCTION__);
        return NULL;
    }

    int input_mapping_index = mapping_index;

    empty_block_entry* curr_empty_block;
    empty_block_root* curr_root_entry;

    while(ssd->total_empty_block_nb != 0){

        if(mode == VICTIM_OVERALL){
            curr_root_entry = (empty_block_root*)empty_block_list + ssd->empty_block_table_index;

            if(curr_root_entry->empty_block_nb == 0){
                ssd->empty_block_table_index++;
                if(ssd->empty_block_table_index == EMPTY_TABLE_ENTRY_NB){
                    ssd->empty_block_table_index = 0;
                }
                continue;
            }
            else{
                curr_empty_block = curr_root_entry->head;
                if(curr_empty_block->curr_phy_page_nb == PAGE_NB){

                    /* Update Empty Block List */
                    if(curr_root_entry->empty_block_nb == 1){
                        curr_root_entry->head = NULL;
                        curr_root_entry->empty_block_nb = 0;
                    }
                    else{
                        curr_root_entry->head = curr_empty_block->next;
                        curr_root_entry->empty_block_nb -= 1;
                    }

                    /* Eject Empty Block from the list */
                    INSERT_VICTIM_BLOCK(ssd, curr_empty_block);

                    /* Update The total number of empty block */
                    ssd->total_empty_block_nb--;

                    ssd->empty_block_table_index++;
                    if(ssd->empty_block_table_index == EMPTY_TABLE_ENTRY_NB){
                        ssd->empty_block_table_index = 0;
                    }
                    continue;
                }
                ssd->empty_block_table_index++;
                if(ssd->empty_block_table_index == EMPTY_TABLE_ENTRY_NB){
                    ssd->empty_block_table_index = 0;
                }
                return curr_empty_block;
            }
        }
        else if(mode == VICTIM_INCHIP){
            curr_root_entry = (empty_block_root*)empty_block_list + mapping_index;
            if(curr_root_entry->empty_block_nb == 0){

                /* If the flash memory has multiple planes, move index */
                if(PLANES_PER_FLASH != 1){
                    mapping_index++;
                    if(mapping_index % PLANES_PER_FLASH == 0){
                        mapping_index = mapping_index - (PLANES_PER_FLASH-1);
                    }
                    if(mapping_index == input_mapping_index){
                        printf("ERROR[%s] There is no empty block\n",__FUNCTION__);
                        return NULL;
                    }
                }
                /* If there is no empty block in the flash memory, return fail */
                else{
#ifdef FTL_DEBUG
                    printf("ERROR[%s]-INCHIP There is no empty block\n",__FUNCTION__);
#endif
                    return NULL;
                }

                continue;
            }
            else{
                curr_empty_block = curr_root_entry->head;
                if(curr_empty_block->curr_phy_page_nb == PAGE_NB){

                    /* Update Empty Block List */
                    if(curr_root_entry->empty_block_nb == 1){
                        curr_root_entry->head = NULL;
                        curr_root_entry->empty_block_nb = 0;
                    }
                    else{
                        curr_root_entry->head = curr_empty_block->next;
                        curr_root_entry->empty_block_nb -= 1;
                    }

                    /* Eject Empty Block from the list */
                    INSERT_VICTIM_BLOCK(ssd, curr_empty_block);

                    /* Update The total number of empty block */
                    ssd->total_empty_block_nb--;

                    continue;
                }
                else{
                    curr_empty_block = curr_root_entry->head;
                }

                return curr_empty_block;
            }	
        }

        else if(mode == VICTIM_NOPARAL){
            curr_root_entry = (empty_block_root*)empty_block_list + mapping_index;
            if(curr_root_entry->empty_block_nb == 0){

                mapping_index++;
                ssd->empty_block_table_index++;
                if(mapping_index == EMPTY_TABLE_ENTRY_NB){
                    mapping_index = 0;
                    ssd->empty_block_table_index = 0;
                }
                continue;
            }
            else{
                curr_empty_block = curr_root_entry->head;
                if(curr_empty_block->curr_phy_page_nb == PAGE_NB){

                    /* Update Empty Block List */
                    if(curr_root_entry->empty_block_nb == 1){
                        curr_root_entry->head = NULL;
                        curr_root_entry->empty_block_nb = 0;
                    }
                    else{
                        curr_root_entry->head = curr_empty_block->next;
                        curr_root_entry->empty_block_nb -= 1;
                    }

                    /* Eject Empty Block from the list */
                    INSERT_VICTIM_BLOCK(ssd, curr_empty_block);

                    /* Update The total number of empty block */
                    ssd->total_empty_block_nb--;

                    continue;
                }
                else{
                    curr_empty_block = curr_root_entry->head;
                }

                return curr_empty_block;
            }	
        }
    }

    printf("ERROR[%s] There is no empty block\n", __FUNCTION__);
    return NULL;
}

int INSERT_EMPTY_BLOCK(struct ssdstate *ssd, unsigned int phy_flash_nb, unsigned int phy_block_nb)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int FLASH_NB = sc->FLASH_NB;
    int PLANES_PER_FLASH = sc->PLANES_PER_FLASH;

    void *empty_block_list = ssd->empty_block_list;

	int mapping_index;
	int plane_nb;

	empty_block_root* curr_root_entry;
	empty_block_entry* new_empty_block;

	new_empty_block = (empty_block_entry*)calloc(1, sizeof(empty_block_entry));
	if(new_empty_block == NULL){
		printf("ERROR[%s] Alloc new empty block fail\n", __FUNCTION__);
		return FAIL;
	}

	/* Init New empty block */
	new_empty_block->phy_flash_nb = phy_flash_nb;
	new_empty_block->phy_block_nb = phy_block_nb;
	new_empty_block->curr_phy_page_nb = 0;
	new_empty_block->next = NULL;

	plane_nb = phy_block_nb % PLANES_PER_FLASH;
	mapping_index = plane_nb * FLASH_NB + phy_flash_nb;

	curr_root_entry = (empty_block_root*)empty_block_list + mapping_index;

	if(curr_root_entry->empty_block_nb == 0){
		curr_root_entry->head = new_empty_block;
		curr_root_entry->tail = new_empty_block;
		curr_root_entry->empty_block_nb = 1;
	}
	else{
		curr_root_entry->tail->next = new_empty_block;
		curr_root_entry->tail = new_empty_block;
		curr_root_entry->empty_block_nb++;
	}
	ssd->total_empty_block_nb++;

	return SUCCESS;
}

int INSERT_VICTIM_BLOCK(struct ssdstate *ssd, empty_block_entry* full_block)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int FLASH_NB = sc->FLASH_NB;
    int PLANES_PER_FLASH = sc->PLANES_PER_FLASH;

    void *victim_block_list = ssd->victim_block_list;

	int mapping_index;
	int plane_nb;

	victim_block_root* curr_v_b_root;
	victim_block_entry* new_v_b_entry;

	/* Alloc New victim block entry */
	new_v_b_entry = (victim_block_entry*)calloc(1, sizeof(victim_block_entry));
	if(new_v_b_entry == NULL){
		printf("ERROR[%s] Calloc fail\n", __FUNCTION__);
		return FAIL;
	}

	/* Copy the full block address */
	new_v_b_entry->phy_flash_nb = full_block->phy_flash_nb;
	new_v_b_entry->phy_block_nb = full_block->phy_block_nb;
	new_v_b_entry->prev = NULL;
	new_v_b_entry->next = NULL;

	plane_nb = full_block->phy_block_nb % PLANES_PER_FLASH;
	mapping_index = plane_nb * FLASH_NB + full_block->phy_flash_nb;

	curr_v_b_root = (victim_block_root*)victim_block_list + mapping_index;

	/* Update victim block list */
	if(curr_v_b_root->victim_block_nb == 0){
		curr_v_b_root->head = new_v_b_entry;
		curr_v_b_root->tail = new_v_b_entry;
		curr_v_b_root->victim_block_nb = 1;
	}
	else{
		curr_v_b_root->tail->next = new_v_b_entry;
		new_v_b_entry->prev = curr_v_b_root->tail;
		curr_v_b_root->tail = new_v_b_entry;
		curr_v_b_root->victim_block_nb++;
	}

	/* Free the full empty block entry */
	free(full_block);

	/* Update the total number of victim block */
	ssd->total_victim_block_nb++;

	return SUCCESS;
}

int EJECT_VICTIM_BLOCK(struct ssdstate *ssd, victim_block_entry* victim_block)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int64_t PLANES_PER_FLASH = sc->PLANES_PER_FLASH;
    int FLASH_NB = sc->FLASH_NB;
    void *victim_block_list = ssd->victim_block_list;

	int mapping_index;
	int plane_nb;

	victim_block_root* curr_v_b_root;

	plane_nb = victim_block->phy_block_nb % PLANES_PER_FLASH;
	mapping_index = plane_nb * FLASH_NB + victim_block->phy_flash_nb;

	curr_v_b_root = (victim_block_root*)victim_block_list + mapping_index;

	/* Update victim block list */
	if(victim_block == curr_v_b_root->head){
		if(curr_v_b_root->victim_block_nb == 1){
			curr_v_b_root->head = NULL;
			curr_v_b_root->tail = NULL;
		}
		else{
			curr_v_b_root->head = victim_block->next;
			curr_v_b_root->head->prev = NULL;
		}
	}
	else if(victim_block == curr_v_b_root->tail){
		curr_v_b_root->tail = victim_block->prev;
		curr_v_b_root->tail->next = NULL;
	}
	else{
		victim_block->prev->next = victim_block->next;
		victim_block->next->prev = victim_block->prev;
	}

	curr_v_b_root->victim_block_nb--;
	ssd->total_victim_block_nb--;

	/* Free the victim block */
	free(victim_block);

	return SUCCESS;
}

block_state_entry* GET_BLOCK_STATE_ENTRY(struct ssdstate *ssd, unsigned int phy_flash_nb, unsigned int phy_block_nb)
{
    void *block_state_table = ssd->block_state_table;
    void *victim_block_list = ssd->victim_block_list;
    struct ssdconf *sc = &(ssd->ssdparams);
    int BLOCK_NB = sc->BLOCK_NB;

	int64_t mapping_index = phy_flash_nb * BLOCK_NB + phy_block_nb;

	block_state_entry* mapping_entry = (block_state_entry*)block_state_table + mapping_index;

	return mapping_entry;
}

int64_t GET_INVERSE_MAPPING_INFO(struct ssdstate *ssd, int64_t ppn)
{
    int64_t *inverse_mapping_table = ssd->inverse_mapping_table;
	int64_t lpn = inverse_mapping_table[ppn];

	return lpn;
}

// NEED MODIFY
int UPDATE_INVERSE_MAPPING(struct ssdstate *ssd, int64_t ppn,  int64_t lpn)
{
    int64_t *inverse_mapping_table = ssd->inverse_mapping_table;
#ifdef FTL_MAP_CACHE
	CACHE_UPDATE_LPN(lpn, ppn);
#else
	inverse_mapping_table[ppn] = lpn;
#endif

	return SUCCESS;
}

int UPDATE_BLOCK_STATE(struct ssdstate *ssd, unsigned int phy_flash_nb, unsigned int phy_block_nb, int type)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int64_t PLANES_PER_FLASH = sc->PLANES_PER_FLASH;
    int FLASH_NB = sc->FLASH_NB;
    int PAGE_NB = sc->PAGE_NB;

        int i;
        block_state_entry* b_s_entry = GET_BLOCK_STATE_ENTRY(ssd, phy_flash_nb, phy_block_nb);

	b_s_entry->type = type;
	
        if(type == EMPTY_BLOCK){
            char *valid_array = b_s_entry->valid_array;
                for(i=0;i<PAGE_NB;i++){
                        UPDATE_BLOCK_STATE_ENTRY(ssd, phy_flash_nb, phy_block_nb, i, 0);
                        //valid_array[i] = '0';
                }
                //////////////b_s_entry->valid_page_nb = PAGE_NB;
        }

        return SUCCESS;
}

int UPDATE_BLOCK_STATE_ENTRY(struct ssdstate *ssd, unsigned int phy_flash_nb, unsigned int phy_block_nb, unsigned int phy_page_nb, int valid)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int BLOCK_NB = sc->BLOCK_NB;
    int PAGE_NB = sc->PAGE_NB;
    int FLASH_NB = sc->FLASH_NB;

	if(phy_flash_nb >= FLASH_NB || phy_block_nb >= BLOCK_NB || phy_page_nb >= PAGE_NB){
		printf("ERROR[%s] Wrong physical address\n", __FUNCTION__);
		return FAIL;
	}

	int i;
	int valid_count = 0;
	block_state_entry* b_s_entry = GET_BLOCK_STATE_ENTRY(ssd, phy_flash_nb, phy_block_nb);

	char* valid_array = b_s_entry->valid_array;

	if(valid == VALID){
		valid_array[phy_page_nb] = 'V';
	}
	else if(valid == INVALID){
		valid_array[phy_page_nb] = 'I';
	}
	else if(valid == 0){
		valid_array[phy_page_nb] = '0';
	}
	else{
		printf("ERROR[%s] Wrong valid value\n", __FUNCTION__);
	}

	/* Update valid_page_nb */
	for(i=0;i<PAGE_NB;i++){
		if(valid_array[i] == 'V'){
			valid_count++;
		}
	}
	b_s_entry->valid_page_nb = valid_count;

	return SUCCESS;
}

#if 0
void PRINT_VALID_ARRAY(unsigned int phy_flash_nb, unsigned int phy_block_nb)
{
	int i;
	int cnt = 0;
	block_state_entry* b_s_entry = GET_BLOCK_STATE_ENTRY(phy_flash_nb, phy_block_nb);

	printf("Type %d [%d][%d]valid array:\n", b_s_entry->type,  phy_flash_nb, phy_block_nb);
	for(i=0;i<PAGE_NB;i++){
		printf("%c ",b_s_entry->valid_array[i]);
		cnt++;
		if(cnt == 10){
			printf("\n");
		}
	}
	printf("\n");
}
#endif
