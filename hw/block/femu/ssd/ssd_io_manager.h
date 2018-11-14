// File: ssd_io_manager.h
// Date: 2014. 12. 11.
// Author: Jinsoo Yoo (jedisty@hanyang.ac.kr)
// Copyright(c)2014
// Hanyang University, Seoul, Korea
// Embedded Software Systems Laboratory. All right reserved

#ifndef _SSD_IO_MANAGER_H
#define _SSD_IO_MANAGER_H

#include "vssim_config_manager.h"

#ifndef VSSIM_BENCH
#include "ssd_util.h"
#endif

struct ssdstate;

//extern int old_channel_nb;
//extern int64_t io_alloc_overhead;
//extern int64_t io_update_overhead;

/* Get Current time in micro second */
int64_t get_usec(void);

/* Initialize SSD Module */
int SSD_IO_INIT(struct ssdstate *ssd);

/* GET IO from FTL */
int64_t SSD_PAGE_READ(struct ssdstate *ssd, unsigned int flash_nb, unsigned int block_nb, unsigned int page_nb, nand_io_info* n_io_info);
int64_t SSD_PAGE_WRITE(struct ssdstate *ssd, unsigned int flash_nb, unsigned int block_nb, unsigned int page_nb, nand_io_info* n_io_info);
int SSD_BLOCK_ERASE(struct ssdstate *ssd, unsigned int flash_nb, unsigned int block_nb);
int64_t SSD_PAGE_PARTIAL_WRITE(struct ssdstate *ssd, unsigned int old_flash_nb, unsigned int old_block_nb, \
	unsigned int old_page_nb, unsigned new_flash_nb, \
	unsigned int new_block_nb, unsigned int new_page_nb, \
	nand_io_info* n_io_info);

/* Channel Access Delay */
int SSD_CH_ENABLE(struct ssdstate *ssd, int channel);

/* Flash or Register Access */
int SSD_FLASH_ACCESS(struct ssdstate *ssd, unsigned int flash_nb, int reg);
int SSD_REG_ACCESS(struct ssdstate *ssd, int reg);

/* Channel Delay */
int64_t SSD_CH_SWITCH_DELAY(struct ssdstate *ssd, int channel);

/* Register Delay */
int SSD_REG_WRITE_DELAY(struct ssdstate *ssd, int reg);
int SSD_REG_READ_DELAY(struct ssdstate *ssd, int reg);

/* Cell Delay */
int SSD_CELL_WRITE_DELAY(struct ssdstate *ssd, int reg);
int SSD_CELL_READ_DELAY(struct ssdstate *ssd, int reg);

/* Erase Delay */
int SSD_BLOCK_ERASE_DELAY(struct ssdstate *ssd, int reg);

/* Mark Time Stamp */
int SSD_CH_RECORD(struct ssdstate *ssd, int channel, int cmd, int ret, nand_io_info* n_io_info);
int SSD_REG_RECORD(struct ssdstate *ssd, int reg, int cmd, int channel, nand_io_info* n_io_info);
int SSD_CELL_RECORD(struct ssdstate *ssd, int reg, int cmd);

/* Check Read Operation in the Same Channel  */
int SSD_CH_ACCESS(struct ssdstate *ssd, int channel);
int64_t SSD_GET_CH_ACCESS_TIME_FOR_READ(struct ssdstate *ssd, int channel, int reg);
void SSD_UPDATE_CH_ACCESS_TIME(struct ssdstate *ssd, int channel, int64_t current_time);

/* Correction Delay */
void SSD_UPDATE_IO_REQUEST(struct ssdstate *ssd, int reg);
void SSD_UPDATE_IO_OVERHEAD(struct ssdstate *ssd, int reg, int64_t overhead_time);
void SSD_REMAIN_IO_DELAY(struct ssdstate *ssd, int reg);
void SSD_UPDATE_QEMU_OVERHEAD(struct ssdstate *ssd, int64_t delay);

/* SSD Module Debugging */
//void SSD_PRINT_STAMP(void);

#endif
