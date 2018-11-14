// File: ssd_io_manager.c
// Date: 2014. 12. 11.
// Author: Jinsoo Yoo (jedisty@hanyang.ac.kr)
// Copyright(c)2014
// Hanyang University, Seoul, Korea
// Embedded Software Systems Laboratory. All right reserved

#include "qemu/osdep.h"
#include "block/block_int.h"
#include "block/qapi.h"
#include "exec/memory.h"
#include "hw/block/block.h"
#include "hw/hw.h"
#include "hw/pci/msix.h"
#include "hw/pci/msi.h"
#include "hw/pci/pci.h"
#include "qapi/visitor.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/bitops.h"
#include "qemu/bitmap.h"
#include "qom/object.h"
#include "sysemu/sysemu.h"
#include "sysemu/block-backend.h"
#include <qemu/main-loop.h>
#include "block/block_int.h"
#include "common.h"

#ifndef VSSIM_BENCH
#endif

char ssd_version[4] = "1.1";
char ssd_date[9] = "16.03.04";

int64_t get_usec(void)
{
	int64_t t = 0;
	struct timeval tv;
	struct timezone tz;

	gettimeofday(&tv, &tz);
	t = tv.tv_sec;
	t *= 1000000;
	t += tv.tv_usec;

	return t;
}

int SSD_IO_INIT(struct ssdstate *ssd)
{

    struct ssdconf *sc = &(ssd->ssdparams);
    int CHANNEL_NB = sc->CHANNEL_NB;
    int FLASH_NB = sc->FLASH_NB;
    int PLANES_PER_FLASH = sc->PLANES_PER_FLASH;

	int i= 0;

	/* Print SSD version */
	//printf("[%s] SSD Version: %s ver. (%s)\n", __FUNCTION__, ssd_version, ssd_date);

	/* Init Variable for Channel Switch Delay */
	ssd->old_channel_nb = CHANNEL_NB;
	ssd->old_channel_cmd = NOOP;
	ssd->old_channel_time = 0;

	/* Init Variable for Time-stamp */

	/* Init Command and Command type */
	ssd->reg_io_cmd = (int *)malloc(sizeof(int) * FLASH_NB * PLANES_PER_FLASH);
	for(i=0; i< FLASH_NB*PLANES_PER_FLASH; i++){
		*(ssd->reg_io_cmd + i) = NOOP;
	}

	ssd->reg_io_type = (int *)malloc(sizeof(int) * FLASH_NB * PLANES_PER_FLASH);
	for(i=0; i< FLASH_NB*PLANES_PER_FLASH; i++){
		*(ssd->reg_io_type + i) = NOOP;
	}

	/* Init Register and Flash IO Time */
	ssd->reg_io_time = (int64_t *)malloc(sizeof(int64_t) * FLASH_NB * PLANES_PER_FLASH);
	for(i=0; i<FLASH_NB*PLANES_PER_FLASH; i++){
		*(ssd->reg_io_time +i)= -1;
	}

	ssd->cell_io_time = (int64_t *)malloc(sizeof(int64_t) * FLASH_NB * PLANES_PER_FLASH);
	for(i=0; i< FLASH_NB*PLANES_PER_FLASH; i++){
		*(ssd->cell_io_time + i) = -1;
	}
  
	/* Init Access sequence_nb */
	ssd->access_nb = (int **)malloc(sizeof(int*) * FLASH_NB * PLANES_PER_FLASH);
	for(i=0; i< FLASH_NB*PLANES_PER_FLASH; i++){
		*(ssd->access_nb + i) = (int*)malloc(sizeof(int)*2);
		ssd->access_nb[i][0] = -1;
		ssd->access_nb[i][1] = -1;
	}

	/* Init IO Overhead */
	ssd->io_overhead = (int64_t *)malloc(sizeof(int64_t) * FLASH_NB * PLANES_PER_FLASH);
	for(i=0; i< FLASH_NB*PLANES_PER_FLASH; i++){
		*(ssd->io_overhead + i) = 0;
	}

	return 0;
}

int64_t SSD_PAGE_WRITE(struct ssdstate *ssd, unsigned int flash_nb,
        unsigned int block_nb, unsigned int page_nb, nand_io_info* n_io_info)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int CHANNEL_NB = sc->CHANNEL_NB;
    int PLANES_PER_FLASH = sc->PLANES_PER_FLASH;
    int IO_PARALLELISM = sc->IO_PARALLELISM;
    int64_t *chnl_next_avail_time = ssd->chnl_next_avail_time;
    int64_t *chip_next_avail_time = ssd->chip_next_avail_time;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    int64_t cur_need_to_emulate_tt = 0;

    int num_channel, reg, num_flash = flash_nb;
    int ret = FAIL;
    int delay_ret;

    /* Calculate ch & reg */
    num_channel = flash_nb % CHANNEL_NB;

    reg = flash_nb*PLANES_PER_FLASH + block_nb%PLANES_PER_FLASH;

    // update key timestamps
    int64_t start_data_transfer_ts = 0;
    if (now < chnl_next_avail_time[num_channel]) {
        start_data_transfer_ts = chnl_next_avail_time[num_channel];
    } else {
        start_data_transfer_ts = now;
    }
    chnl_next_avail_time[num_channel] = start_data_transfer_ts + sc->REG_WRITE_DELAY;

    if (chnl_next_avail_time[num_channel] < chip_next_avail_time[num_flash]) {
        chip_next_avail_time[num_flash] += sc->CELL_PROGRAM_DELAY;
    } else {
        chip_next_avail_time[num_flash] = chnl_next_avail_time[num_channel] + sc->CELL_PROGRAM_DELAY;
    }

    cur_need_to_emulate_tt = chip_next_avail_time[num_flash] - now;

    return cur_need_to_emulate_tt;

#if 0
    /* Delay Operation */
    SSD_CH_ENABLE(ssd, channel);	// channel enable	

    if( IO_PARALLELISM == 0 ){
        delay_ret = SSD_FLASH_ACCESS(ssd, flash_nb, reg);
    }
    else{
        delay_ret = SSD_REG_ACCESS(ssd, reg);
    }	

    /* Check Channel Operation */
    while(ret == FAIL){
        ret = SSD_CH_ACCESS(ssd, channel);
    }

    /* Record Time Stamp */
    SSD_CH_RECORD(ssd, channel, WRITE, delay_ret, n_io_info);
    SSD_REG_RECORD(ssd, reg, WRITE, channel, n_io_info);
    SSD_CELL_RECORD(ssd, reg, WRITE);

#ifdef O_DIRECT_VSSIM
    if(offset == (n_io_info->io_page_nb-1)){
        SSD_REMAIN_IO_DELAY(ssd, reg);
    }
#endif

    if(n_io_info != NULL){
        free(n_io_info);
    }

    //	printf("WRITE reg %d\tch %d\toff %d\n", reg, channel, offset);
    //	SSD_PRINT_STAMP();
#endif

    return SUCCESS;
}

int64_t SSD_PAGE_PARTIAL_WRITE(struct ssdstate *ssd, unsigned int old_flash_nb, unsigned int old_block_nb, \
	unsigned int old_page_nb, unsigned int new_flash_nb, unsigned int new_block_nb, \
	unsigned int new_page_nb, nand_io_info* n_io_info)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int CHANNEL_NB = sc->CHANNEL_NB;
    int PLANES_PER_FLASH = sc->PLANES_PER_FLASH;
    int IO_PARALLELISM = sc->IO_PARALLELISM;
    int64_t *chnl_next_avail_time = ssd->chnl_next_avail_time;
    int64_t *chip_next_avail_time = ssd->chip_next_avail_time;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    int64_t cur_need_to_emulate_tt = 0;

    int num_channel, reg, num_flash = old_flash_nb;
    int ret = FAIL;
    int delay_ret;

    /* READ Partial Data */

    /* Calculate ch & reg */
    num_channel = old_flash_nb % CHANNEL_NB;
    reg = old_flash_nb*PLANES_PER_FLASH + old_block_nb%PLANES_PER_FLASH;

    // update key timestamps
    int64_t start_data_transfer_ts = 0;
    if (now < chnl_next_avail_time[num_channel]) {
        start_data_transfer_ts = chnl_next_avail_time[num_channel];
    } else {
        start_data_transfer_ts = now;
    }
    chnl_next_avail_time[num_channel] = start_data_transfer_ts + sc->REG_WRITE_DELAY;

    if (chnl_next_avail_time[num_channel] < chip_next_avail_time[num_flash]) {
        chip_next_avail_time[num_flash] += sc->CELL_PROGRAM_DELAY;
    } else {
        chip_next_avail_time[num_flash] = chnl_next_avail_time[num_channel] + sc->CELL_PROGRAM_DELAY;
    }

    cur_need_to_emulate_tt = chip_next_avail_time[num_flash] - now;

    return cur_need_to_emulate_tt;

#if 0
    /* Delay Operation */
    SSD_CH_ENABLE(ssd, channel);	// channel enable	

    if( IO_PARALLELISM == 0 ){
        delay_ret = SSD_FLASH_ACCESS(ssd, old_flash_nb, reg);
    }
    else{
        delay_ret = SSD_REG_ACCESS(ssd, reg);
    }	

    /* Check Channel Operation */
    while(ret == FAIL){
        ret = SSD_CH_ACCESS(ssd, channel);
    }

    /* Record Time Stamp */
    SSD_CH_RECORD(ssd, channel, READ, delay_ret, n_io_info);
    SSD_REG_RECORD(ssd, reg, READ, channel, n_io_info);
    SSD_CELL_RECORD(ssd, reg, READ);

    SSD_REMAIN_IO_DELAY(ssd, reg);

    /* Write 1 Page */

    /* Calculate ch & reg */
    channel = new_flash_nb % CHANNEL_NB;
    reg = new_flash_nb*PLANES_PER_FLASH + new_block_nb%PLANES_PER_FLASH;

    /* Delay Operation */
    SSD_CH_ENABLE(ssd, channel);	// channel enable	

    if( IO_PARALLELISM == 0 ){
        delay_ret = SSD_FLASH_ACCESS(ssd, new_flash_nb, reg);
    }
    else{
        delay_ret = SSD_REG_ACCESS(ssd, reg);
    }	

    /* Check Channel Operation */
    while(ret == FAIL){
        ret = SSD_CH_ACCESS(ssd, channel);
    }

    /* Record Time Stamp */
    SSD_CH_RECORD(ssd, channel, WRITE, delay_ret, n_io_info);
    SSD_REG_RECORD(ssd, reg, WRITE, channel, n_io_info);
    SSD_CELL_RECORD(ssd, reg, WRITE);

#ifdef O_DIRECT_VSSIM
    if(offset == (n_io_info->io_page_nb-1)){
        SSD_REMAIN_IO_DELAY(ssd, reg);
    }
#endif

    if(n_io_info != NULL){
        free(n_io_info);
    }

    return SUCCESS;	
#endif
}

int64_t SSD_PAGE_READ(struct ssdstate *ssd, unsigned int flash_nb, 
        unsigned int block_nb, unsigned int page_nb, nand_io_info* n_io_info)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int CHANNEL_NB = sc->CHANNEL_NB;
    int PLANES_PER_FLASH = sc->PLANES_PER_FLASH;
    int IO_PARALLELISM = sc->IO_PARALLELISM;
    int channel, reg;
    int delay_ret;
    int num_channel = flash_nb % CHANNEL_NB;
    int num_flash = flash_nb;
    int64_t *chnl_next_avail_time = ssd->chnl_next_avail_time;
    int64_t *chip_next_avail_time = ssd->chip_next_avail_time;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    int64_t cur_need_to_emulate_tt = 0;


    /* Calculate ch & reg */
    channel = flash_nb % CHANNEL_NB;
    reg = flash_nb*PLANES_PER_FLASH + block_nb%PLANES_PER_FLASH;

    if (now < chip_next_avail_time[num_flash]) {
        chip_next_avail_time[num_flash] += sc->CELL_READ_DELAY;
    } else {
        chip_next_avail_time[num_flash] = now + sc->CELL_READ_DELAY;
    }
    int64_t start_data_transfer_ts = chip_next_avail_time[num_flash];
    if (start_data_transfer_ts < chnl_next_avail_time[num_channel]) {
        chnl_next_avail_time[num_channel] += sc->REG_READ_DELAY;
    } else {
        chnl_next_avail_time[num_channel] = start_data_transfer_ts + sc->REG_READ_DELAY;
    }
    chip_next_avail_time[num_flash] = chnl_next_avail_time[num_channel];
    cur_need_to_emulate_tt = chnl_next_avail_time[num_channel] - now;

    return cur_need_to_emulate_tt;

#if 0
    /* Delay Operation */
    SSD_CH_ENABLE(ssd, channel);	// channel enable

    /* Access Register */
    if( IO_PARALLELISM == 0 ){
        delay_ret = SSD_FLASH_ACCESS(ssd, flash_nb, reg);
    }
    else{
        delay_ret = SSD_REG_ACCESS(ssd, reg);
    }

    /* Record Time Stamp */
    SSD_CH_RECORD(ssd, channel, READ, delay_ret, n_io_info);
    SSD_CELL_RECORD(ssd, reg, READ);
    SSD_REG_RECORD(ssd, reg, READ, channel, n_io_info);

    //	printf("READ reg %d\tch %d\toff %d\n", reg, channel, offset);
    //	SSD_PRINT_STAMP();

#ifdef O_DIRECT_VSSIM
    if(offset == (n_io_info->io_page_nb - 1)){
        SSD_REMAIN_IO_DELAY(ssd, reg);
    }
#endif

    if(n_io_info != NULL){
        free(n_io_info);
    }

    return SUCCESS;
#endif
}

int SSD_BLOCK_ERASE(struct ssdstate *ssd, unsigned int flash_nb, unsigned int block_nb)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int CHANNEL_NB = sc->CHANNEL_NB;
    int PLANES_PER_FLASH = sc->PLANES_PER_FLASH;
    int IO_PARALLELISM = sc->IO_PARALLELISM;
    int64_t *chnl_next_avail_time = ssd->chnl_next_avail_time;
    int64_t *chip_next_avail_time = ssd->chip_next_avail_time;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    int64_t cur_need_to_emulate_tt = 0;

	int num_channel, reg;

	/* Calculate ch & reg */
	num_channel = flash_nb % CHANNEL_NB;
	reg = flash_nb*PLANES_PER_FLASH + block_nb%PLANES_PER_FLASH;

    int64_t ss = now;
    if (chnl_next_avail_time[num_channel] > now) {
        ss = chnl_next_avail_time[num_channel];
    }

    if (ss < chip_next_avail_time[flash_nb]) {
        chip_next_avail_time[flash_nb] += sc->BLOCK_ERASE_DELAY;
    } else {
        chip_next_avail_time[flash_nb] = ss + sc->BLOCK_ERASE_DELAY;
    }

#if 0
	/* Delay Operation */
	if( IO_PARALLELISM == 0 ){
		SSD_FLASH_ACCESS(ssd, flash_nb, reg);
	}
	else{
		SSD_REG_ACCESS(ssd, reg);
	}

       	/* Record Time Stamp */
	SSD_REG_RECORD(ssd, reg, ERASE, channel, NULL);
	SSD_CELL_RECORD(ssd, reg, ERASE);
#endif

	return SUCCESS;
}

int SSD_FLASH_ACCESS(struct ssdstate *ssd, unsigned int flash_nb, int reg)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int CHANNEL_NB = sc->CHANNEL_NB;
    int PLANES_PER_FLASH = sc->PLANES_PER_FLASH;
    int IO_PARALLELISM = sc->IO_PARALLELISM;
    int **access_nb = ssd->access_nb;

	int i;
	int r_num = flash_nb * PLANES_PER_FLASH;
	int ret = 0;

	for(i=0;i<PLANES_PER_FLASH;i++){
//		if(r_num != reg && access_nb[r_num][0] == io_request_seq_nb){
		if(access_nb[r_num][0] == -1){
			/* That's OK */
		}
		else{
			ret = SSD_REG_ACCESS(ssd, r_num);
		}
	
		r_num++;
	}	

	return ret;
}

int SSD_REG_ACCESS(struct ssdstate *ssd, int reg)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int CHANNEL_NB = sc->CHANNEL_NB;
    int PLANES_PER_FLASH = sc->PLANES_PER_FLASH;
    int IO_PARALLELISM = sc->IO_PARALLELISM;
    int **access_nb = ssd->access_nb;
    int *reg_io_cmd = ssd->reg_io_cmd;

	int reg_cmd = reg_io_cmd[reg];
	int ret = 0;

	if( reg_cmd == NOOP ){
		/* That's OK */
	}
	else if( reg_cmd == READ ){
		ret = SSD_CELL_READ_DELAY(ssd, reg);
		ret = SSD_REG_READ_DELAY(ssd, reg);
	}
	else if( reg_cmd == WRITE ){
		ret = SSD_REG_WRITE_DELAY(ssd, reg);
		ret = SSD_CELL_WRITE_DELAY(ssd, reg);
	}
	else if( reg_cmd == ERASE ){
		ret = SSD_BLOCK_ERASE_DELAY(ssd, reg);
	}
	else{
		printf("ERROR[%s] Command Error! %d\n", __FUNCTION__, reg_io_cmd[reg]);
	}

	return ret;
}

int SSD_CH_ENABLE(struct ssdstate *ssd, int channel)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int CHANNEL_NB = sc->CHANNEL_NB;
    int PLANES_PER_FLASH = sc->PLANES_PER_FLASH;
    int IO_PARALLELISM = sc->IO_PARALLELISM;
    int CHANNEL_SWITCH_DELAY_R = sc->CHANNEL_SWITCH_DELAY_R;
    int CHANNEL_SWITCH_DELAY_W = sc->CHANNEL_SWITCH_DELAY_W;

	int64_t do_delay = 0;

	if(CHANNEL_SWITCH_DELAY_R == 0 && CHANNEL_SWITCH_DELAY_W == 0)
		return SUCCESS;

	if(ssd->old_channel_nb != channel){
		do_delay = SSD_CH_SWITCH_DELAY(ssd, channel);
	}
	
	return SUCCESS;
}

int SSD_CH_RECORD(struct ssdstate *ssd, int channel, int cmd, int ret, nand_io_info* n_io_info)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int CHANNEL_NB = sc->CHANNEL_NB;
    int PLANES_PER_FLASH = sc->PLANES_PER_FLASH;
    int IO_PARALLELISM = sc->IO_PARALLELISM;
    int CHANNEL_SWITCH_DELAY_R = sc->CHANNEL_SWITCH_DELAY_R;
    int CHANNEL_SWITCH_DELAY_W = sc->CHANNEL_SWITCH_DELAY_W;

	ssd->old_channel_nb = channel;
	ssd->old_channel_cmd = cmd;
	int offset = n_io_info->offset;

	if(cmd == READ && offset != 0 && ret == 0){
		ssd->old_channel_time += CHANNEL_SWITCH_DELAY_R;
	}
	else if(cmd == WRITE && offset != 0 && ret == 0){
		ssd->old_channel_time += CHANNEL_SWITCH_DELAY_W;
	}
	else{
		ssd->old_channel_time = get_usec();
	}

	return SUCCESS;
}

int SSD_REG_RECORD(struct ssdstate *ssd, int reg, int cmd, int channel, nand_io_info* n_io_info)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int CHANNEL_NB = sc->CHANNEL_NB;
    int PLANES_PER_FLASH = sc->PLANES_PER_FLASH;
    int IO_PARALLELISM = sc->IO_PARALLELISM;
    int CHANNEL_SWITCH_DELAY_R = sc->CHANNEL_SWITCH_DELAY_R;
    int CHANNEL_SWITCH_DELAY_W = sc->CHANNEL_SWITCH_DELAY_W;
    int *reg_io_cmd = ssd->reg_io_cmd;
    int *reg_io_type = ssd->reg_io_type;
    int64_t *reg_io_time = ssd->reg_io_time;
    int **access_nb = ssd->access_nb;

	int type = -1;
	int offset = -1;
	int io_seq_nb = -1;

	if(n_io_info != NULL){
		type = n_io_info->type;
		offset = n_io_info->offset;
		io_seq_nb = n_io_info->io_seq_nb;
	}

	reg_io_cmd[reg] = cmd;
	reg_io_type[reg] = type;

	if(cmd == WRITE){
		reg_io_time[reg] = ssd->old_channel_time+CHANNEL_SWITCH_DELAY_W;
		SSD_UPDATE_CH_ACCESS_TIME(ssd, channel, reg_io_time[reg]);

		/* Update SATA request Info */
		if(type == WRITE || type == SEQ_WRITE || type == RAN_WRITE || type == RAN_COLD_WRITE || type == RAN_HOT_WRITE){
			access_nb[reg][0] = io_seq_nb;
			access_nb[reg][1] = offset;
			ssd->io_update_overhead = UPDATE_IO_REQUEST(ssd, io_seq_nb, offset, ssd->old_channel_time, UPDATE_START_TIME);
			SSD_UPDATE_IO_OVERHEAD(ssd, reg, ssd->io_update_overhead);
		}
		else{
			access_nb[reg][0] = -1;
			access_nb[reg][1] = -1;
		}
	}
	else if(cmd == READ){
		reg_io_time[reg] = SSD_GET_CH_ACCESS_TIME_FOR_READ(ssd, channel, reg);

		/* Update SATA request Info */
		if(type == READ){
			access_nb[reg][0] = io_seq_nb;
			access_nb[reg][1] = offset;
			ssd->io_update_overhead = UPDATE_IO_REQUEST(ssd, io_seq_nb, offset, ssd->old_channel_time, UPDATE_START_TIME);
			SSD_UPDATE_IO_OVERHEAD(ssd, reg, ssd->io_update_overhead);
		}
		else{
			access_nb[reg][0] = -1;
			access_nb[reg][1] = -1;
		}
	}
	else if(cmd == ERASE){
		/* Update SATA request Info */
		access_nb[reg][0] = -1;
		access_nb[reg][1] = -1;
	}	

	return SUCCESS;
}

int SSD_CELL_RECORD(struct ssdstate *ssd, int reg, int cmd)
{
    struct ssdconf *sc = &(ssd->ssdparams);

    int64_t *cell_io_time = ssd->cell_io_time;
    int REG_WRITE_DELAY = sc->REG_WRITE_DELAY;
    int64_t *reg_io_time = ssd->reg_io_time;
    int CHANNEL_SWITCH_DELAY_R = sc->CHANNEL_SWITCH_DELAY_R;

	if(cmd == WRITE){
		cell_io_time[reg] = reg_io_time[reg] + REG_WRITE_DELAY;
	}
	else if(cmd == READ){
		cell_io_time[reg] = ssd->old_channel_time + CHANNEL_SWITCH_DELAY_R;
	}
	else if(cmd == ERASE){
		cell_io_time[reg] = get_usec();
	}

	return SUCCESS;
}

int SSD_CH_ACCESS(struct ssdstate *ssd, int channel)
{
    struct ssdconf *sc = &(ssd->ssdparams);

    int64_t *cell_io_time = ssd->cell_io_time;
    int REG_WRITE_DELAY = sc->REG_WRITE_DELAY;
    int64_t *reg_io_time = ssd->reg_io_time;
    int CHANNEL_SWITCH_DELAY_R = sc->CHANNEL_SWITCH_DELAY_R;
    int *reg_io_cmd = ssd->reg_io_cmd;
    int CHANNEL_NB = sc->CHANNEL_NB;
    int WAY_NB = sc->WAY_NB;
    int PLANES_PER_FLASH = sc->PLANES_PER_FLASH;

	int i, j;
	int ret = SUCCESS;
	int r_num;

	for(i=0;i<WAY_NB;i++){
		r_num = channel*PLANES_PER_FLASH + i*CHANNEL_NB*PLANES_PER_FLASH; 
		for(j=0;j<PLANES_PER_FLASH;j++){
			if(reg_io_time[r_num] <= get_usec() && reg_io_time[r_num] != -1){
				if(reg_io_cmd[r_num] == READ){
					SSD_CELL_READ_DELAY(ssd, r_num);
					SSD_REG_READ_DELAY(ssd, r_num);
					ret = FAIL;
				}
				else if(reg_io_cmd[r_num] == WRITE){
					SSD_REG_WRITE_DELAY(ssd, r_num);
					ret = FAIL;
				}
			}
			r_num++;	
		}
	}

	return ret;
}

void SSD_UPDATE_IO_OVERHEAD(struct ssdstate *ssd, int reg, int64_t overhead_time)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int64_t *io_overhead = ssd->io_overhead;

	io_overhead[reg] += overhead_time;
	ssd->io_alloc_overhead = 0;
	ssd->io_update_overhead = 0;
//	printf("%ld\n",io_overhead[reg]);
}

int64_t SSD_CH_SWITCH_DELAY(struct ssdstate *ssd, int channel)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int64_t *io_overhead = ssd->io_overhead;
    int REG_WRITE_DELAY = sc->REG_WRITE_DELAY;
    int64_t *reg_io_time = ssd->reg_io_time;
    int CHANNEL_SWITCH_DELAY_R = sc->CHANNEL_SWITCH_DELAY_R;
    int CHANNEL_SWITCH_DELAY_W = sc->CHANNEL_SWITCH_DELAY_W;
    
	int64_t start = 0;
       	int64_t	end = 0;
	int64_t diff = 0;

	int64_t switch_delay = 0;

	if(ssd->old_channel_cmd == READ){
		switch_delay = CHANNEL_SWITCH_DELAY_R;
	}
	else if(ssd->old_channel_cmd == WRITE){
		switch_delay = CHANNEL_SWITCH_DELAY_W;
	}
	else{
		return 0;
	}

	start = get_usec();
	diff = start - ssd->old_channel_time;

#ifndef VSSIM_BENCH
  #ifdef DEL_QEMU_OVERHEAD
	if(diff < switch_delay){
		SSD_UPDATE_QEMU_OVERHEAD(switch_delay-diff);
	}
	diff = start - old_channel_time;
  #endif
#endif
	if (diff < switch_delay){
        /*
         * Coperd: will this affect the timestamp state machine ???
		while( diff < switch_delay ){
			diff = get_usec() - old_channel_time;
		}
        */
	}
	end = get_usec();

	return end-start;
}

int SSD_REG_WRITE_DELAY(struct ssdstate *ssd, int reg)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int64_t *io_overhead = ssd->io_overhead;
    int REG_WRITE_DELAY = sc->REG_WRITE_DELAY;
    int64_t *reg_io_time = ssd->reg_io_time;
    int *reg_io_type = ssd->reg_io_type;
    int CHANNEL_SWITCH_DELAY_R = sc->CHANNEL_SWITCH_DELAY_R;

	int ret = 0;
	int64_t start = 0;
       	int64_t	end = 0;
	int64_t diff = 0;
	int64_t time_stamp = reg_io_time[reg];

	if (time_stamp == -1)
		return 0;

	/* Reg Write Delay */
	start = get_usec();
	diff = start - time_stamp;

#ifndef VSSIM_BENCH
  #ifdef DEL_QEMU_OVERHEAD
	if(diff < REG_WRITE_DELAY){
		SSD_UPDATE_QEMU_OVERHEAD(ssd, REG_WRITE_DELAY-diff);
	}
	diff = start - reg_io_time[reg];
  #endif
#endif

	if (diff < REG_WRITE_DELAY){
        /*
		while( diff < REG_WRITE_DELAY ){
			diff = get_usec() - time_stamp;
		}
        */
		ret = 1;
	}
	end = get_usec();

	/* Send Delay Info To Perf Checker */
	SEND_TO_PERF_CHECKER(ssd, reg_io_type[reg], end-start, CH_OP);

	/* Update Time Stamp Struct */
	reg_io_time[reg] = -1;

//TEMPs
//	FILE* fp_temp = fopen("./data/write.txt","a");
//	fprintf(fp_temp,"%ld\n",end-start);
//	fclose(fp_temp);
//TEMPe

	return ret;
}

int SSD_REG_READ_DELAY(struct ssdstate *ssd, int reg)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int64_t *io_overhead = ssd->io_overhead;
    int REG_WRITE_DELAY = sc->REG_WRITE_DELAY;
    int64_t *reg_io_time = ssd->reg_io_time;
    int CHANNEL_SWITCH_DELAY_R = sc->CHANNEL_SWITCH_DELAY_R;
    int *reg_io_cmd = ssd->reg_io_cmd;
    int *reg_io_type = ssd->reg_io_type;
    int REG_READ_DELAY = sc->REG_READ_DELAY;

	int ret = 0;
	int64_t start = 0;
	int64_t end = 0;
	int64_t diff = 0;
	int64_t time_stamp = reg_io_time[reg];

	if (time_stamp == -1)
		return 0;

	/* Reg Read Delay */
	start = get_usec();
	diff = start - time_stamp;

#ifndef VSSIM_BENCH
  #ifdef DEL_QEMU_OVERHEAD
	if(diff < REG_READ_DELAY){
		SSD_UPDATE_QEMU_OVERHEAD(ssd, REG_READ_DELAY-diff);
	}
	diff = start - reg_io_time[reg];
  #endif
#endif

	if(diff < REG_READ_DELAY){
        /*
		while(diff < REG_READ_DELAY){
			diff = get_usec() - time_stamp;
		}
        */
		ret = 1;
	}
	end = get_usec();


	/* Send Delay Info To Perf Checker */
	SEND_TO_PERF_CHECKER(ssd, reg_io_type[reg], end-start, CH_OP);
	SSD_UPDATE_IO_REQUEST(ssd, reg);
	
	/* Update Time Stamp Struct */
	reg_io_time[reg] = -1;
	reg_io_cmd[reg] = NOOP;
	reg_io_type[reg] = NOOP;

	return ret;
}

int SSD_CELL_WRITE_DELAY(struct ssdstate *ssd, int reg)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int64_t *io_overhead = ssd->io_overhead;
    int REG_WRITE_DELAY = sc->REG_WRITE_DELAY;
    int64_t *reg_io_time = ssd->reg_io_time;
    int CHANNEL_SWITCH_DELAY_R = sc->CHANNEL_SWITCH_DELAY_R;
    int *reg_io_cmd = ssd->reg_io_cmd;
    int64_t *cell_io_time = ssd->cell_io_time;

	int ret = 0;
	int64_t start = 0;
	int64_t end = 0;
	int64_t diff = 0;
	int64_t time_stamp = cell_io_time[reg];
    int64_t init_diff_reg = diff;
    int CELL_PROGRAM_DELAY = sc->CELL_PROGRAM_DELAY;
    int *reg_io_type = ssd->reg_io_type;

	if( time_stamp == -1 )
		return 0;

	/* Cell Write Delay */
	start = get_usec();
	diff = start - time_stamp + io_overhead[reg];

#ifndef VSSIM_BENCH
  #ifdef DEL_QEMU_OVERHEAD
	if(diff < CELL_PROGRAM_DELAY){
		SSD_UPDATE_QEMU_OVERHEAD(CELL_PROGRAM_DELAY-diff);
	}
	diff = start - cell_io_time[reg] + io_overhead[reg];
  #endif
#endif


	if( diff < CELL_PROGRAM_DELAY){
		init_diff_reg = diff;
        /*
		while(diff < CELL_PROGRAM_DELAY){
			diff = get_usec() - time_stamp + io_overhead[reg];
		}
        */
		ret = 1;
	}
	end = get_usec();

	/* Send Delay Info To Perf Checker */
	SEND_TO_PERF_CHECKER(ssd, reg_io_type[reg], end-start, REG_OP);
	SSD_UPDATE_IO_REQUEST(ssd, reg);

	/* Update Time Stamp Struct */
	cell_io_time[reg] = -1;
	reg_io_cmd[reg] = NOOP;
	reg_io_type[reg] = NOOP;

	/* Update IO Overhead */
	io_overhead[reg] = 0;

	return ret;
}

int SSD_CELL_READ_DELAY(struct ssdstate *ssd, int reg)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int64_t *cell_io_time = ssd->cell_io_time;
    int64_t *io_overhead = ssd->io_overhead;
    int CELL_READ_DELAY = sc->CELL_READ_DELAY;

	int ret = 0;
	int64_t start = 0;
	int64_t end = 0;
	int64_t diff = 0;
	int64_t time_stamp = cell_io_time[reg];
    int *reg_io_type = ssd->reg_io_type;

	int64_t REG_DELAY = CELL_READ_DELAY;

	if( time_stamp == -1)
		return 0;

	/* Cell Read Delay */
	start = get_usec();
	diff = start - time_stamp + io_overhead[reg];

#ifndef VSSIM_BENCH
  #ifdef DEL_QEMU_OVERHEAD
	if( diff < REG_DELAY){
		SSD_UPDATE_QEMU_OVERHEAD(ssd, REG_DELAY-diff);
	}
	diff = start - cell_io_time[reg] + io_overhead[reg];
  #endif
#endif

	if( diff < REG_DELAY){
		ssd->init_diff_reg = diff;
        /*
		while( diff < REG_DELAY ){
			diff = get_usec() - time_stamp + io_overhead[reg];
		}
        */
		ret = 1;

	}
	end = get_usec();

	/* Send Delay Info To Perf Checker */
	SEND_TO_PERF_CHECKER(ssd, reg_io_type[reg], end-start, REG_OP);

	/* Update Time Stamp Struct */
	cell_io_time[reg] = -1;

	/* Update IO Overhead */
	io_overhead[reg] = 0;

	return ret;
}

int SSD_BLOCK_ERASE_DELAY(struct ssdstate *ssd, int reg)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int64_t *cell_io_time = ssd->cell_io_time;
    int64_t *io_overhead = ssd->io_overhead;
    int CELL_READ_DELAY = sc->CELL_READ_DELAY;
    int BLOCK_ERASE_DELAY = sc->BLOCK_ERASE_DELAY;
    int *reg_io_cmd = ssd->reg_io_cmd;
    int *reg_io_type = ssd->reg_io_type;

	int ret = 0;
	int64_t start = 0;
	int64_t end = 0;
	int64_t diff;
	int64_t time_stamp = cell_io_time[reg];

	if( time_stamp == -1)
		return 0;

	/* Block Erase Delay */
	start = get_usec();
	diff = get_usec() - cell_io_time[reg];
	if( diff < BLOCK_ERASE_DELAY){
        /*
		while(diff < BLOCK_ERASE_DELAY){
			diff = get_usec() - time_stamp;
	  	}
        */
		ret = 1;
	}
	end = get_usec();

	/* Send Delay Info to Perf Checker */
	SEND_TO_PERF_CHECKER(ssd, ssd->reg_io_type[reg], end-start, REG_OP);

	/* Update IO Overhead */
	cell_io_time[reg] = -1;
	reg_io_cmd[reg] = NOOP;
	reg_io_type[reg] = NOOP;

	return ret;
}

int64_t SSD_GET_CH_ACCESS_TIME_FOR_READ(struct ssdstate *ssd, int channel, int reg)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int64_t *cell_io_time = ssd->cell_io_time;
    int64_t *io_overhead = ssd->io_overhead;
    int CELL_READ_DELAY = sc->CELL_READ_DELAY;
    int REG_WRITE_DELAY = sc->REG_WRITE_DELAY;
    int BLOCK_ERASE_DELAY = sc->BLOCK_ERASE_DELAY;
    int *reg_io_cmd = ssd->reg_io_cmd;
    int64_t *reg_io_time = ssd->reg_io_time;
    int PLANES_PER_FLASH = sc->PLANES_PER_FLASH;
    int CHANNEL_NB = sc->CHANNEL_NB;
    int WAY_NB = sc->WAY_NB;
    int REG_READ_DELAY = sc->REG_READ_DELAY;

	int i, j;
	int r_num;
	int64_t latest_time = cell_io_time[reg] + CELL_READ_DELAY;
	int64_t temp_time = 0;

	for(i=0;i<WAY_NB;i++){
		r_num = channel*PLANES_PER_FLASH + i*CHANNEL_NB*PLANES_PER_FLASH; 
		for(j=0;j<PLANES_PER_FLASH;j++){
			temp_time = 0;

			if(reg_io_cmd[r_num] == READ){
				temp_time = reg_io_time[r_num] + REG_READ_DELAY;	
			}
			else if(reg_io_cmd[r_num] == WRITE){
				temp_time = reg_io_time[r_num] + REG_WRITE_DELAY;
			}
	
			if( temp_time > latest_time ){
				latest_time = temp_time;
			}
			r_num++;
		}
	}
//TEMP
//	FILE* fp_temp = fopen("./data/temp_read.txt","a");
//	fprintf(fp_temp,"%ld\n", latest_time - (cell_io_time[reg] + CELL_READ_DELAY));
//	fclose(fp_temp);
	return latest_time;
}

void SSD_UPDATE_CH_ACCESS_TIME(struct ssdstate *ssd, int channel, int64_t current_time)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int64_t *cell_io_time = ssd->cell_io_time;
    int64_t *io_overhead = ssd->io_overhead;
    int CELL_READ_DELAY = sc->CELL_READ_DELAY;
    int REG_WRITE_DELAY = sc->REG_WRITE_DELAY;
    int BLOCK_ERASE_DELAY = sc->BLOCK_ERASE_DELAY;
    int *reg_io_cmd = ssd->reg_io_cmd;
    int64_t *reg_io_time = ssd->reg_io_time;
    int PLANES_PER_FLASH = sc->PLANES_PER_FLASH;
    int CHANNEL_NB = sc->CHANNEL_NB;
    int WAY_NB = sc->WAY_NB;

	int i, j;
	int r_num;

	for(i=0;i<WAY_NB;i++){
		r_num = channel*PLANES_PER_FLASH + i*CHANNEL_NB*PLANES_PER_FLASH; 
		for(j=0;j<PLANES_PER_FLASH;j++){
			if(reg_io_cmd[r_num] == READ && reg_io_time[r_num] > current_time ){
				reg_io_time[r_num] += REG_WRITE_DELAY;
			}
			r_num++;	
		}
	}
}

void SSD_UPDATE_IO_REQUEST(struct ssdstate *ssd, int reg)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int64_t *cell_io_time = ssd->cell_io_time;
    int64_t *io_overhead = ssd->io_overhead;
    int CELL_READ_DELAY = sc->CELL_READ_DELAY;
    int REG_WRITE_DELAY = sc->REG_WRITE_DELAY;
    int BLOCK_ERASE_DELAY = sc->BLOCK_ERASE_DELAY;
    int *reg_io_cmd = ssd->reg_io_cmd;
    int64_t *reg_io_time = ssd->reg_io_time;
    int **access_nb = ssd->access_nb;

	int64_t curr_time = get_usec();
	if(ssd->init_diff_reg != 0){
		ssd->io_update_overhead = UPDATE_IO_REQUEST(ssd, access_nb[reg][0], access_nb[reg][1], curr_time, UPDATE_END_TIME);
		SSD_UPDATE_IO_OVERHEAD(ssd, reg, ssd->io_update_overhead);
		access_nb[reg][0] = -1;
	}
	else{
		ssd->io_update_overhead = UPDATE_IO_REQUEST(ssd, access_nb[reg][0], access_nb[reg][1], 0, UPDATE_END_TIME);
		SSD_UPDATE_IO_OVERHEAD(ssd, reg, ssd->io_update_overhead);
		access_nb[reg][0] = -1;
	}
}

void SSD_REMAIN_IO_DELAY(struct ssdstate *ssd, int reg)
{
	SSD_REG_ACCESS(ssd, reg);
}

#ifndef VSSIM_BENCH
void SSD_UPDATE_QEMU_OVERHEAD(struct ssdstate *ssd, int64_t delay)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int64_t *cell_io_time = ssd->cell_io_time;
    int CELL_READ_DELAY = sc->CELL_READ_DELAY;
    int REG_WRITE_DELAY = sc->REG_WRITE_DELAY;
    int BLOCK_ERASE_DELAY = sc->BLOCK_ERASE_DELAY;
    int *reg_io_cmd = ssd->reg_io_cmd;
    int64_t *reg_io_time = ssd->reg_io_time;
    int PLANES_PER_FLASH = sc->PLANES_PER_FLASH;
    int FLASH_NB = sc->FLASH_NB;

	int i;
	int p_num = FLASH_NB * PLANES_PER_FLASH;
	int64_t diff = delay;

    /* 
     * Coperd: remove qemu_overhead for compilation for now
	if(qemu_overhead == 0){
		return;
	}
	else{
		if(diff > qemu_overhead){
			diff = qemu_overhead;
		}
	}
    */

	ssd->old_channel_time -= diff;
	for(i=0;i<p_num;i++){
		cell_io_time[i] -= diff;
		reg_io_time[i] -= diff;
	}

    /*
	qemu_overhead -= diff;
    */
}
#endif

#if 0
void SSD_PRINT_STAMP(void)
{
	int i, j, k;
	int op;
	int r_num;

//	FILE* fp_temp = fopen("./data/stamp.txt","a");

	r_num = 0;
	for(i=0;i<CHANNEL_NB;i++){
		for(j=0;j<WAY_NB;j++){
			r_num = i*PLANES_PER_FLASH + j*CHANNEL_NB*PLANES_PER_FLASH; 
			for(k=0;k<PLANES_PER_FLASH;k++){

				op = reg_io_type[r_num];
				if(op == NOOP)
					printf("[      ]");
				else if(op == READ)
					printf("[READ%2d]",access_nb[r_num][1]);
				else if(op == WRITE)
					printf("[PROG%2d]",access_nb[r_num][1]);
				else if(op == SEQ_WRITE)
					printf("[SEQW%2d]",access_nb[r_num][1]);
				else if(op == RAN_WRITE)
					printf("[RNDW%2d]",access_nb[r_num][1]);
				else if(op == RAN_COLD_WRITE)
					printf("[RNCW%2d]",access_nb[r_num][1]);
				else if(op == RAN_HOT_WRITE)
					printf("[RNHW%2d]",access_nb[r_num][1]);
				else if(op == SEQ_MERGE_WRITE)
					printf("[SMGW%2d]",access_nb[r_num][1]);
				else if(op == RAN_MERGE_WRITE)
					printf("[RMGW%2d]",access_nb[r_num][1]);
				else if(op == SEQ_MERGE_READ)
					printf("[SMGR%2d]",access_nb[r_num][1]);
				else if(op == RAN_MERGE_READ)
					printf("[RMGR%2d]",access_nb[r_num][1]);
				else
					printf("[ %d ]",op);
				
				r_num ++;
			}
		}
		printf("\t");
	}
	printf("\n\n");

//	fclose(fp_temp);
}
#endif
