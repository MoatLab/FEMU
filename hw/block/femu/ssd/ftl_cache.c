// File: ftl_cache.c
// Date: 2014. 12. 03.
// Author: Jinsoo Yoo (jedisty@hanyang.ac.kr)
// Copyright(c)2014
// Hanyang University, Seoul, Korea
// Embedded Software Systems Laboratory. All right reserved

#include "common.h"

#ifdef FTL_MAP_CACHE

struct map_data* cache_map_data_start;
struct map_data* cache_map_data_end;

uint64_t cache_map_data_nb;
cache_idx_entry* cache_idx_table;
map_state_entry* map_state_table;
static uint64_t clock_hand;

void INIT_CACHE(void)
{
	int i;
	FILE* fp = fopen("./data/cache_map_data.dat","r");
	cache_idx_entry* curr_idx_entry;
	map_state_entry* curr_map_entry;

	if(fp != NULL){
	}
	else{

		/* Initialize cache index table */
		cache_idx_table = (cache_idx_entry*)calloc(CACHE_IDX_SIZE, sizeof(cache_idx_entry));
		if(cache_idx_table == NULL){
			printf("ERROR[%s] calloc fail\n",__FUNCTION__);
			return;
		}

		curr_idx_entry = (cache_idx_entry *)cache_idx_table;
		for(i=0; i<CACHE_IDX_SIZE;i++){
			curr_idx_entry->map_num = 0;
			curr_idx_entry->clock_bit = 0;
			curr_idx_entry->map_type = 0;
			curr_idx_entry->update_bit = 0;
			
			curr_idx_entry->data = (void*)calloc(1, PAGE_SIZE);

			curr_idx_entry += 1;
		}

		clock_hand = 0;

		/* Initialize map state table */
		map_state_table = (map_state_entry*)calloc(MAP_ENTRY_NB, sizeof(map_state_entry));
		if(map_state_table == NULL){
			printf("ERROR[%s] calloc fail\n",__FUNCTION__);
			return;
		}

		int64_t new_ppn;
		int ret;
		curr_map_entry = map_state_table;
		for(i=0; i<MAP_ENTRY_NB;i++){
#ifdef WRITE_NOPARAL
	                ret = GET_NEW_PAGE(VICTIM_NOPARAL, empty_block_table_index, &new_ppn);
#else
	                ret = GET_NEW_PAGE(VICTIM_OVERALL, EMPTY_TABLE_ENTRY_NB, &new_ppn);
#endif
			curr_map_entry->ppn = new_ppn;
			curr_map_entry->is_cached = 0;
			curr_map_entry->cache_entry = NULL;

			curr_map_entry += 1;
		}

		cache_map_data_start = NULL;
		cache_map_data_end = NULL;
		cache_map_data_nb = 0;
	}
}

int64_t CACHE_GET_PPN(int64_t lpn)
{
#ifdef FTL_CACHE_DEBUG
	printf("[%s] start\n",__FUNCTION__);
#endif
	uint64_t map_index = lpn / MAP_ENTRIES_PER_PAGE;
	int64_t* map_data = NULL;
	int64_t ppn;

	CACHE_GET_MAP(map_index, MAP, map_data);

	ppn = GET_MAPPING_INFO(lpn);

#ifdef FTL_CACHE_DEBUG
	printf("[%s] end\n",__FUNCTION__);
#endif
	return ppn;
}

int64_t CACHE_GET_LPN(int64_t ppn)
{
#ifdef FTL_CACHE_DEBUG
	printf("[%s] start\n",__FUNCTION__);
#endif
	uint64_t map_index = ppn / MAP_ENTRIES_PER_PAGE;
	int64_t* map_data = NULL;
	int64_t lpn;

	CACHE_GET_MAP(map_index, INV_MAP, map_data);

	lpn = GET_INVERSE_MAPPING_INFO(ppn);

#ifdef FTL_CACHE_DEBUG
	printf("[%s] end\n",__FUNCTION__);
#endif
	return lpn;
}

int CACHE_UPDATE_PPN(int64_t lpn, int64_t ppn)
{
	cache_idx_entry* cache_entry = NULL;
	uint64_t map_index = lpn / MAP_ENTRIES_PER_PAGE;
	int64_t* map_data = NULL;

	cache_entry = CACHE_GET_MAP(map_index, MAP, map_data);
	cache_entry->update_bit = 1;

	mapping_table[lpn] = ppn;

	return SUCCESS;
}

int CACHE_UPDATE_LPN(int64_t lpn, int64_t ppn)
{
	cache_idx_entry* cache_entry = NULL;
	uint64_t map_index = ppn / MAP_ENTRIES_PER_PAGE;
	int64_t* map_data = NULL;

	cache_entry = CACHE_GET_MAP(map_index, INV_MAP, map_data);
	cache_entry->update_bit = 1;

	inverse_page_mapping_table[ppn] = lpn;

	return SUCCESS;
}

cache_idx_entry* CACHE_GET_MAP(uint64_t map_index, uint64_t map_type, int64_t* map_data)
{
#ifdef FTL_CACHE_DEBUG
	printf("[%s] start\n",__FUNCTION__);
#endif
	cache_idx_entry* curr_idx_entry = NULL;
	uint64_t victim_index;

	curr_idx_entry = LOOKUP_CACHE(map_index, map_type);
	if(curr_idx_entry != NULL){
		map_data = (int64_t*)curr_idx_entry->data;
		curr_idx_entry->clock_bit = 1;
	}
	else{
		victim_index = CACHE_EVICT_MAP();
		curr_idx_entry = CACHE_INSERT_MAP(map_index, map_type, victim_index);
		map_data = (int64_t*)curr_idx_entry->data;
	}

#ifdef FTL_CACHE_DEBUG
	printf("[%s] end\n",__FUNCTION__);
#endif
	return curr_idx_entry;
}

cache_idx_entry* LOOKUP_CACHE(uint64_t map_index, uint64_t map_type)
{
#ifdef FTL_CACHE_DEBUG
	printf("[%s] start\n",__FUNCTION__);
#endif
	map_state_entry* curr_map_entry = (map_state_entry*)map_state_table + map_index;
	cache_idx_entry* curr_idx_entry;

	if(curr_map_entry->is_cached){

		curr_idx_entry = curr_map_entry->cache_entry;

		if(map_type == MAP){
			if(curr_idx_entry->map_type == MAP && curr_idx_entry->map_num == map_index)
				return curr_idx_entry;
		}
		else if(map_type == INV_MAP){
			if(curr_idx_entry->map_type == INV_MAP && curr_idx_entry->map_num == map_index)
				return curr_idx_entry;
		}
	}

#ifdef FTL_CACHE_DEBUG
	printf("[%s] end\n",__FUNCTION__);
#endif
	return NULL;
}

cache_idx_entry* CACHE_INSERT_MAP(uint64_t map_index, uint64_t map_type, uint64_t victim_index)
{
#ifdef FTL_CACHE_DEBUG
	printf("[%s] start\n",__FUNCTION__);
#endif
	int64_t* map_data;
	int index = map_index * MAP_ENTRIES_PER_PAGE;
	int ppn;

	cache_idx_entry* curr_idx_entry = (cache_idx_entry*)cache_idx_table + victim_index;
	map_state_entry* curr_map_entry = (map_state_entry*)map_state_table + map_index;
	ppn = curr_map_entry->ppn;

	if(map_type == MAP){
		map_data = (int64_t*)mapping_table + index;
		memcpy(curr_idx_entry->data, map_data, MAP_ENTRIES_PER_PAGE*sizeof(int64_t));
		curr_idx_entry->map_type = MAP;
	}
	else if(map_type == INV_MAP){
		map_data = (int64_t*)inverse_page_mapping_table + index;
		memcpy(curr_idx_entry->data, map_data, MAP_ENTRIES_PER_PAGE*sizeof(int64_t));
		curr_idx_entry->map_type = INV_MAP;
	}

//	READ_MAP();
	CELL_READ(CALC_FLASH(ppn), CALC_BLOCK(ppn), CALC_PAGE(ppn), 0, MAP_READ);

	curr_idx_entry->map_num = map_index;
	curr_idx_entry->clock_bit = 1;
	curr_idx_entry->update_bit = 0;

	curr_map_entry->is_cached = 1;
	curr_map_entry->cache_entry = curr_idx_entry;

#ifdef FTL_CACHE_DEBUG
	printf("[%s] end\n",__FUNCTION__);
#endif
	return curr_idx_entry;
}

uint64_t CACHE_EVICT_MAP(void)
{
#ifdef FTL_CACHE_DEBUG
	printf("[%s] start\n",__FUNCTION__);
#endif
	int ret;
	int64_t new_ppn;

	uint64_t victim_index = CACHE_SELECT_VICTIM();
	cache_idx_entry* curr_idx_entry = (cache_idx_entry*)cache_idx_table + victim_index;

	int map_index = curr_idx_entry->map_num;
	map_state_entry* curr_map_entry = (map_state_entry*)map_state_table + map_index;

	if(curr_idx_entry->update_bit){
#ifdef WRITE_NOPARAL
		ret = GET_NEW_PAGE(VICTIM_NOPARAL, empty_block_table_index, &new_ppn);
#else
		ret = GET_NEW_PAGE(VICTIM_OVERALL, EMPTY_TABLE_ENTRY_NB, &new_ppn);
#endif
		WRITE_MAP(new_ppn, curr_idx_entry->data);
	
		curr_map_entry->ppn = new_ppn;
	}

	curr_map_entry->is_cached = 0;
	curr_map_entry->cache_entry = NULL;

	curr_idx_entry->map_num = 0;
	curr_idx_entry->clock_bit = 0;
	curr_idx_entry->update_bit = 0;

#ifdef FTL_CACHE_DEBUG
	printf("[%s] end\n",__FUNCTION__);
#endif
	return victim_index;
}

uint64_t CACHE_SELECT_VICTIM(void)
{
#ifdef FTL_CACHE_DEBUG
	printf("[%s] start\n",__FUNCTION__);
#endif
	uint64_t idx;
	uint64_t evict_cache_num = -1;

	while(1)
	{
		idx = clock_hand;
		
		if (idx == CACHE_IDX_SIZE)
			idx = 0;

		if (++clock_hand == CACHE_IDX_SIZE)
			clock_hand = 0;

		if (cache_idx_table[idx].clock_bit)
		{
			cache_idx_table[idx].clock_bit = 0;
		}
		else
		{
			cache_idx_table[idx].clock_bit = 1;
			evict_cache_num = idx;
			return evict_cache_num;
		}
	}
#ifdef FTL_CACHE_DEBUG
	printf("[%s] end\n",__FUNCTION__);
#endif
}

int WRITE_MAP(uint64_t page_nb, void* buf)
{
#ifdef FTL_CACHE_DEBUG
	printf("[%s] start\n",__FUNCTION__);
#endif
	map_data* curr_map_data_entry;
//	pm_map* curr_pm_map = LOOKUP_PM_MAP_ENTRY(page_nb);

//	if(curr_pm_map != NULL){
//		memcpy(curr_pm_map->map_data, buf, PAGE_SIZE);
//		printf("ERROR[WRITE_MAP] hit?\n");
//	}
//	else{
		curr_map_data_entry = (map_data*)calloc(1, sizeof(map_data));
		curr_map_data_entry->data = (void*)calloc(1, PAGE_SIZE);

		curr_map_data_entry->ppn = page_nb;
		curr_map_data_entry->prev = NULL;
		curr_map_data_entry->next = NULL;

		memcpy(curr_map_data_entry->data, buf, PAGE_SIZE);

		cache_map_data_nb++;
	
		REARRANGE_MAP_DATA_ENTRY(curr_map_data_entry);
//	}

	CELL_WRITE(CALC_FLASH(page_nb), CALC_BLOCK(page_nb), CALC_PAGE(page_nb), 0, MAP_WRITE);

#ifdef FTL_CACHE_DEBUG
	printf("[%s] end\n",__FUNCTION__);
#endif
	return SUCCESS;
}

void* READ_MAP(uint64_t page_nb)
{
	map_data* curr_map_data_entry = LOOKUP_MAP_DATA_ENTRY(page_nb);

	if(curr_map_data_entry == NULL){
		printf("ERROR[READ_MAP] There is no such map \n");
		return NULL;
	}
	else{
		return curr_map_data_entry->data;
	}
}

map_data* LOOKUP_MAP_DATA_ENTRY(uint64_t page_nb)
{
	map_data* curr_map_data_entry = cache_map_data_start;
	int i;

	if(cache_map_data_nb <= 0 || curr_map_data_entry == NULL)
		printf("ERROR[LOOKUP_MAP_DATA_ENTRY] %d \n", cache_map_data_nb);

	for(i=0; i<cache_map_data_nb; i++){
		if( curr_map_data_entry->ppn == page_nb){
			return curr_map_data_entry;
		}
		else{
			curr_map_data_entry = curr_map_data_entry->next;
		}
	}
	return NULL;
}

int REARRANGE_MAP_DATA_ENTRY(struct map_data* new_entry)
{
	if(cache_map_data_start == NULL){
		cache_map_data_start = new_entry;
		cache_map_data_end = new_entry;
	}
	else{
		cache_map_data_end->next = new_entry;
		new_entry->prev = cache_map_data_end;
		cache_map_data_end = new_entry;
	}

	return SUCCESS;
}

#endif
