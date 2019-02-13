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

int64_t SSD_PAGE_WRITE(struct ssdstate *ssd, unsigned int flash_nb,
        unsigned int block_nb, unsigned int page_nb)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int CHANNEL_NB = sc->CHANNEL_NB;
    int64_t *chnl_next_avail_time = ssd->chnl_next_avail_time;
    int64_t *chip_next_avail_time = ssd->chip_next_avail_time;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    int64_t cur_need_to_emulate_tt = 0;

    int num_channel, num_flash = flash_nb;

    /* Calculate ch & reg */
    num_channel = flash_nb % CHANNEL_NB;

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
}

int64_t SSD_PAGE_READ(struct ssdstate *ssd, unsigned int flash_nb, 
        unsigned int block_nb, unsigned int page_nb)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int CHANNEL_NB = sc->CHANNEL_NB;
    int num_channel = flash_nb % CHANNEL_NB;
    int num_flash = flash_nb;
    int64_t *chnl_next_avail_time = ssd->chnl_next_avail_time;
    int64_t *chip_next_avail_time = ssd->chip_next_avail_time;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    int64_t cur_need_to_emulate_tt = 0;

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
}

int SSD_BLOCK_ERASE(struct ssdstate *ssd, unsigned int flash_nb, unsigned int block_nb)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int CHANNEL_NB = sc->CHANNEL_NB;
    int64_t *chnl_next_avail_time = ssd->chnl_next_avail_time;
    int64_t *chip_next_avail_time = ssd->chip_next_avail_time;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);

    int num_channel;

    /* Calculate ch & reg */
    num_channel = flash_nb % CHANNEL_NB;

    int64_t ss = now;
    if (chnl_next_avail_time[num_channel] > now) {
        ss = chnl_next_avail_time[num_channel];
    }

    if (ss < chip_next_avail_time[flash_nb]) {
        chip_next_avail_time[flash_nb] += sc->BLOCK_ERASE_DELAY;
    } else {
        chip_next_avail_time[flash_nb] = ss + sc->BLOCK_ERASE_DELAY;
    }

    return SUCCESS;
}
