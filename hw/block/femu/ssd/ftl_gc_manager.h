// File: ftl_gc_manager.h
// Date: 2014. 12. 03.
// Author: Jinsoo Yoo (jedisty@hanyang.ac.kr)
// Copyright(c)2014
// Hanyang University, Seoul, Korea
// Embedded Software Systems Laboratory. All right reserved

#ifndef _GC_MANAGER_H_
#define _GC_MANAGER_H_

#include "vssim_config_manager.h"

//extern unsigned int gc_count;

struct ssdstate;

void GC_CHECK(struct ssdstate *ssd, unsigned int phy_flash_nb, unsigned int phy_block_nb);

int GARBAGE_COLLECTION(struct ssdstate *ssd, int chip);
int SELECT_VICTIM_BLOCK(struct ssdstate *ssd, int chip, unsigned int* phy_flash_nb, unsigned int* phy_block_nb);

#endif
