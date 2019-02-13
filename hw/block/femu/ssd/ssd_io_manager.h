// File: ssd_io_manager.h
// Date: 2014. 12. 11.
// Author: Jinsoo Yoo (jedisty@hanyang.ac.kr)
// Copyright(c)2014
// Hanyang University, Seoul, Korea
// Embedded Software Systems Laboratory. All right reserved

#ifndef _SSD_IO_MANAGER_H
#define _SSD_IO_MANAGER_H

#include "vssim_config_manager.h"

struct ssdstate;

/* Get Current time in micro second */
int64_t get_usec(void);

/* GET IO from FTL */
int64_t SSD_PAGE_READ(struct ssdstate *ssd, unsigned int flash_nb, unsigned int block_nb, unsigned int page_nb);
int64_t SSD_PAGE_WRITE(struct ssdstate *ssd, unsigned int flash_nb, unsigned int block_nb, unsigned int page_nb);
int SSD_BLOCK_ERASE(struct ssdstate *ssd, unsigned int flash_nb, unsigned int block_nb);

#endif
