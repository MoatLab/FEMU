// File: ssd_trim_manager.h
// Date: 2014. 12. 03.
// Author: Jinsoo Yoo (jedisty@hanyang.ac.kr)
// Copyright(c)2014
// Hanyang University, Seoul, Korea
// Embedded Software Systems Laboratory. All right reserved

#ifndef _TRIM_MANAGER_H_
#define _TRIM_MANAGER_H_

#ifndef VSSIM_BENCH
#include "ssd_util.h"
#endif

#include <stdint.h>

typedef struct sector_entry
{
	int64_t sector_nb;
	unsigned long long int length;

	struct sector_entry* prev;
	struct sector_entry* next;	
}sector_entry;

sector_entry* new_sector_entry(void);
void add_sector_list(sector_entry* List, sector_entry* SE);
void release_sector_list(sector_entry* SE);
void remove_sector_entry(sector_entry* SE);

void INSERT_TRIM_SECTORS(sector_entry* pSE);
int	EXIST_IN_TRIM_LIST(int64_t sector_nb);
int	REMOVE_TRIM_SECTOR(int64_t sector_nb);
//int	REMOVE_TRIM_SECTOR2(int64_t sector_nb, unsigned int length);


void INIT_TRIM(void);
void TERM_TRIM(void);

#endif
