// File: ftl_inverse_mapping_manager.h
// Date: 2014. 12. 03.
// Author: Jinsoo Yoo (jedisty@hanyang.ac.kr)
// Copyright(c)2014
// Hanyang University, Seoul, Korea
// Embedded Software Systems Laboratory. All right reserved

#ifndef _INVERSE_MAPPING_MANAGER_H_
#define _INVERSE_MAPPING_MANAGER_H_

#include "vssim_config_manager.h"

struct ssdstate;

//extern int64_t* inverse_mapping_table;
//extern void* block_state_table;

//extern int64_t total_empty_block_nb;
//extern int64_t total_victim_block_nb;

//extern void* empty_block_list;
//extern void* victim_block_list;

//extern unsigned int empty_block_list_index;

typedef struct block_state_entry
{
	int valid_page_nb;
	int type;
	unsigned int erase_count;
	char* valid_array;

}block_state_entry;

typedef struct empty_block_root
{
	struct empty_block_entry* head;
	struct empty_block_entry* tail;
	unsigned int empty_block_nb;
}empty_block_root;

typedef struct empty_block_entry
{
	unsigned int phy_flash_nb;
	unsigned int phy_block_nb;
	unsigned int curr_phy_page_nb;
	struct empty_block_entry* next;

}empty_block_entry;

typedef struct victim_block_root
{
	struct victim_block_entry* head;
	struct victim_block_entry* tail;
	unsigned int victim_block_nb;
}victim_block_root;

typedef struct victim_block_entry
{
	unsigned int phy_flash_nb;
	unsigned int phy_block_nb;
	struct victim_block_entry* prev;
	struct victim_block_entry* next;
}victim_block_entry;

//extern victim_block_entry* victim_block_list_head;
//extern victim_block_entry* victim_block_list_tail;

void INIT_INVERSE_MAPPING_TABLE(struct ssdstate *ssd);
void INIT_BLOCK_STATE_TABLE(struct ssdstate *ssd);
void INIT_EMPTY_BLOCK_LIST(struct ssdstate *ssd);
void INIT_VICTIM_BLOCK_LIST(struct ssdstate *ssd);
void INIT_VALID_ARRAY(struct ssdstate *ssd);

void TERM_INVERSE_MAPPING_TABLE(struct ssdstate *ssd);
void TERM_BLOCK_STATE_TABLE(struct ssdstate *ssd);
void TERM_EMPTY_BLOCK_LIST(struct ssdstate *ssd);
void TERM_VICTIM_BLOCK_LIST(struct ssdstate *ssd);
void TERM_VALID_ARRAY(struct ssdstate *ssd);

empty_block_entry* GET_EMPTY_BLOCK(struct ssdstate *ssd, int mode, int mapping_index);
int INSERT_EMPTY_BLOCK(struct ssdstate *ssd, unsigned int phy_flash_nb, unsigned int phy_block_nb);

int INSERT_VICTIM_BLOCK(struct ssdstate *ssd, empty_block_entry* full_block);
int EJECT_VICTIM_BLOCK(struct ssdstate *ssd, victim_block_entry* victim_block);

block_state_entry* GET_BLOCK_STATE_ENTRY(struct ssdstate *ssd, unsigned int phy_flash_nb, unsigned int phy_block_nb);

int64_t GET_INVERSE_MAPPING_INFO(struct ssdstate *ssd, int64_t lpn);
int UPDATE_INVERSE_MAPPING(struct ssdstate *ssd, int64_t ppn, int64_t lpn);
int UPDATE_BLOCK_STATE(struct ssdstate *ssd, unsigned int phy_flash_nb, unsigned int phy_block_nb, int type);
int UPDATE_BLOCK_STATE_ENTRY(struct ssdstate *ssd, unsigned int phy_flash_nb, unsigned int phy_block_nb, unsigned int phy_page_nb, int valid);

void PRINT_VALID_ARRAY(struct ssdstate *ssd, unsigned int phy_flash_nb, unsigned int phy_block_nb);

#endif
