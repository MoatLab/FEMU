// File: ftl.c
// Date: 2014. 12. 03.
// Author: Jinsoo Yoo (jedisty@hanyang.ac.kr)
// Copyright(c)2014
// Hanyang University, Seoul, Korea
// Embedded Software Systems Laboratory. All right reserved

#include "common.h"

void FTL_INIT(struct ssdstate *ssd)
{
    if (ssd->g_init == 1) {
        printf("FEMU: FTL already initialized !!!!!\n");
        assert(0);
    }

    INIT_SSD_CONFIG(ssd);

    INIT_MAPPING_TABLE(ssd);
    INIT_INVERSE_MAPPING_TABLE(ssd);
    INIT_BLOCK_STATE_TABLE(ssd);
    INIT_VALID_ARRAY(ssd);
    INIT_EMPTY_BLOCK_LIST(ssd);
    INIT_VICTIM_BLOCK_LIST(ssd);

    ssd->g_init = 1;
}

void FTL_TERM(struct ssdstate *ssd)
{
	printf("[%s] start\n", __FUNCTION__);

#if 0
#ifdef FIRM_IO_BUFFER
	TERM_IO_BUFFER();
#endif

	TERM_MAPPING_TABLE(ssd);
	TERM_INVERSE_MAPPING_TABLE(ssd);
	TERM_VALID_ARRAY(ssd);
	TERM_BLOCK_STATE_TABLE(ssd);
	TERM_EMPTY_BLOCK_LIST(ssd);
	TERM_VICTIM_BLOCK_LIST(ssd);
	TERM_PERF_CHECKER(ssd);

#endif
	printf("[%s] complete\n", __FUNCTION__);
}

int64_t FTL_READ(struct ssdstate *ssd, int64_t sector_nb, unsigned int length)
{
    return _FTL_READ(ssd, sector_nb, length);
}

int64_t FTL_WRITE(struct ssdstate *ssd, int64_t sector_nb, unsigned int length)
{
    return _FTL_WRITE(ssd, sector_nb, length);
}

static int get_gc_slot(struct ssdstate *ssd, int64_t ppn, int mode)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int slot;

    int num_flash = CALC_FLASH(ssd, ppn);
    int num_channel = num_flash %  sc->CHANNEL_NB;

    if (mode == WHOLE_BLOCKING) {
        slot = 0;
    } else if (mode == CHANNEL_BLOCKING) {
        slot = num_channel;
    } else if (mode == CHIP_BLOCKING) {
        slot = num_flash;
    } else {
        slot = -1;
    }

    return slot;
}

int64_t _FTL_READ(struct ssdstate *ssd, int64_t sector_nb, unsigned int length)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int64_t SECTOR_NB = sc->SECTOR_NB;
    int64_t SECTORS_PER_PAGE = sc->SECTORS_PER_PAGE;
    int FLASH_NB = sc->FLASH_NB;
    int GC_MODE = sc->GC_MODE;
    int64_t cur_need_to_emulate_tt = 0, max_need_to_emulate_tt = 0;

    /* Coperd: FTL layer blocked reads statistics */
    ssd->nb_total_reads++;
    ssd->nb_total_rd_sz += length;

    if (sector_nb + length > SECTOR_NB){
        printf("Error[%s] Exceed Sector number\n", __FUNCTION__); 
        return FAIL;	
    }

    int64_t lpn;
    int64_t ppn;
    int64_t lba = sector_nb;
    unsigned int remain = length;
    unsigned int left_skip = sector_nb % SECTORS_PER_PAGE;
    unsigned int right_skip;
    unsigned int read_sects;

    int read_page_nb = 0;
    int num_flash = 0, num_blk = 0;
    int slot = -1;

    remain = length;
    lba = sector_nb;
    left_skip = sector_nb % SECTORS_PER_PAGE;

    while (remain > 0) {

        if (remain > SECTORS_PER_PAGE - left_skip) {
            right_skip = 0;
        } else {
            right_skip = SECTORS_PER_PAGE - left_skip - remain;
        }
        read_sects = SECTORS_PER_PAGE - left_skip - right_skip;

        lpn = lba / (int64_t)SECTORS_PER_PAGE;
        ppn = GET_MAPPING_INFO(ssd, lpn);
        if (ppn == -1) {
            printf("FEMU-FTL: No Mapping info for LPN:%" PRId64 "\n", lpn);
        }

        slot = get_gc_slot(ssd, ppn, GC_MODE);
        assert(slot >= 0 && slot < FLASH_NB);
        //printf("%d,", slot);

        cur_need_to_emulate_tt = SSD_PAGE_READ(ssd, num_flash, num_blk, CALC_PAGE(ssd, ppn));

        if (cur_need_to_emulate_tt > max_need_to_emulate_tt) {
            max_need_to_emulate_tt = cur_need_to_emulate_tt;
        }

        read_page_nb++;

        lba += read_sects;
        remain -= read_sects;
        left_skip = 0;
    }

    return max_need_to_emulate_tt;
}

int64_t _FTL_WRITE(struct ssdstate *ssd, int64_t sector_nb, unsigned int length)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int64_t SECTOR_NB = sc->SECTOR_NB;
    int64_t SECTORS_PER_PAGE = sc->SECTORS_PER_PAGE;
    int FLASH_NB = sc->FLASH_NB;
    int GC_MODE = sc->GC_MODE;
    int EMPTY_TABLE_ENTRY_NB = sc->EMPTY_TABLE_ENTRY_NB;
    int64_t cur_need_to_emulate_tt = 0, max_need_to_emulate_tt = 0;

    if (ssd->in_warmup_stage == 0) {
        ssd->nb_total_writes++;
        ssd->nb_total_wr_sz += length;
    }

    if (sector_nb + length > SECTOR_NB) {
        printf("FEMU-FTL: Writing to %"PRId64" beyond SSD range (%"PRId64")\n",
                sector_nb, sc->SECTOR_NB);
    }

    int64_t lba = sector_nb;
    int64_t lpn;
    int64_t new_ppn;

    unsigned int remain = length;
    unsigned int left_skip = sector_nb % SECTORS_PER_PAGE;
    unsigned int right_skip;
    unsigned int write_sects;

    unsigned int ret = FAIL;
    int slot = -1;

    while (remain > 0) {
        if (remain > SECTORS_PER_PAGE - left_skip) {
            right_skip = 0;
        } else {
            right_skip = SECTORS_PER_PAGE - left_skip - remain;
        }
        write_sects = SECTORS_PER_PAGE - left_skip - right_skip;

        ret = GET_NEW_PAGE(ssd, VICTIM_OVERALL, EMPTY_TABLE_ENTRY_NB, &new_ppn);
        if (ret == FAIL) {
            printf("FEMU-FTL:%s,get new page failed! \n", __func__);
            abort();
        }

        lpn = lba / (int64_t)SECTORS_PER_PAGE;

        slot = get_gc_slot(ssd, new_ppn, GC_MODE);
        assert(slot >= 0 && slot < FLASH_NB);
        //printf("%d,", slot);

        cur_need_to_emulate_tt = SSD_PAGE_WRITE(ssd, CALC_FLASH(ssd, new_ppn), CALC_BLOCK(ssd, new_ppn), CALC_PAGE(ssd, new_ppn));

        if (cur_need_to_emulate_tt > max_need_to_emulate_tt) {
            max_need_to_emulate_tt = cur_need_to_emulate_tt;
        }

        //printf("FTL-WRITE: lpn -> ppn: %"PRId64" -> %"PRId64"\n", lpn, new_ppn);

        UPDATE_OLD_PAGE_MAPPING(ssd, lpn);
        UPDATE_NEW_PAGE_MAPPING(ssd, lpn, new_ppn);

        lba += write_sects;
        remain -= write_sects;
        left_skip = 0;
    }

    GC_CHECK(ssd, CALC_FLASH(ssd, new_ppn), CALC_BLOCK(ssd, new_ppn));

    return max_need_to_emulate_tt; 
}
