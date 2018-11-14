// File: ftl.h
// Date: 2014. 12. 03.
// Author: Jinsoo Yoo (jedisty@hanyang.ac.kr)
// Copyright(c)2014
// Hanyang University, Seoul, Korea
// Embedded Software Systems Laboratory. All right reserved

#ifndef _FTL_H_
#define _FTL_H_

#include "common.h"
#include "vssim_config_manager.h"
#include <stdint.h>

struct ssdstate;

//extern int64_t blocking_to;

void FTL_INIT(struct ssdstate *ssd);
void FTL_TERM(struct ssdstate *ssd);

int64_t FTL_READ(struct ssdstate *ssd, int64_t sector_nb, unsigned int length);
int64_t FTL_WRITE(struct ssdstate *ssd, int64_t sector_nb, unsigned int length);

int64_t _FTL_READ(struct ssdstate *ssd, int64_t sector_nb, unsigned int length);
int64_t _FTL_WRITE(struct ssdstate *ssd, int64_t sector_nb, unsigned int length);
#endif
