// File: ftl_cache.h
// Date: 2014. 12. 03.
// Author: Jinsoo Yoo (jedisty@hanyang.ac.kr)
// Copyright(c)2014
// Hanyang University, Seoul, Korea
// Embedded Software Systems Laboratory. All right reserved

#ifndef _VSSIM_CACHE_H_
#define _VSSIM_CACHE_H_

#define CACHE_MAP_SIZE	(PASE_SIZE * CACHE_IDX_SIZE)

#define MAP	0
#define INV_MAP	1

extern struct map_data* cache_map_data_start;
extern struct map_data* cache_map_data_end;
extern uint64_t cache_map_data_nb; 

typedef struct map_data
{
	uint64_t ppn;
	void* data;
	struct map_data* prev;
	struct map_data* next;
}map_data;

typedef struct cache_idx_entry
{
	uint64_t map_num	:29;
	uint64_t clock_bit	:1;
	uint64_t map_type	:1;	// map (0), inv_map(1)
	uint64_t update_bit	:1;
	void* data;
}cache_idx_entry;

typedef struct map_state_entry
{
	int64_t ppn;
	uint64_t is_cached; // cached (1) not cached(0)
	cache_idx_entry* cache_entry;
}map_state_entry;

void INIT_CACHE(void);

int64_t CACHE_GET_PPN(int64_t lpn);
int64_t CACHE_GET_LPN(int64_t ppn);
int CACHE_UPDATE_PPN(int64_t lpn, int64_t ppn);
int CACHE_UPDATE_LPN(int64_t lpn, int64_t ppn);

cache_idx_entry* CACHE_GET_MAP(uint64_t map_index, uint64_t map_type, int64_t* map_data);
cache_idx_entry* LOOKUP_CACHE(uint64_t map_index, uint64_t map_type);
cache_idx_entry* CACHE_INSERT_MAP(uint64_t map_index, uint64_t map_type, uint64_t victim_index);
uint64_t CACHE_EVICT_MAP(void); 
uint64_t CACHE_SELECT_VICTIM(void);

int WRITE_MAP(uint64_t page_nb, void* buf);
void* READ_MAP(uint64_t page_nb);
map_data* LOOKUP_MAP_DATA_ENTRY(uint64_t page_nb);
int REARRANGE_MAP_DATA_ENTRY(struct map_data* new_entry);
#endif
