// File: vssim_config_manager.c
// Date: 2014. 12. 03.
// Author: Jinsoo Yoo (jedisty@hanyang.ac.kr)
// Copyright(c)2014
// Hanyang University, Seoul, Korea
// Embedded Software Systems Laboratory. All right reserved

#include "common.h"

static void parse_ssd_params(struct ssdconf *sc, FILE *cf)
{
    int r;
    char *curline = NULL;

    curline = malloc(1024);
    memset(curline, 0, 1024);

    while (fscanf(cf, "%s", curline) != EOF) {
        if (strcmp(curline, "PAGE_SIZE") == 0) {
            r = fscanf(cf, "%d", &sc->PAGE_SIZE);
        } else if (strcmp(curline, "PAGE_NB") == 0) {
            r = fscanf(cf, "%d", &sc->PAGE_NB);
        } else if (strcmp(curline, "SECTOR_SIZE") == 0) {
            r = fscanf(cf, "%d", &sc->SECTOR_SIZE);
        } else if (strcmp(curline, "FLASH_NB") == 0) {
            r = fscanf(cf, "%d", &sc->FLASH_NB);
        } else if (strcmp(curline, "BLOCK_NB") == 0) {
            r = fscanf(cf, "%d", &sc->BLOCK_NB);
        } else if (strcmp(curline, "PLANES_PER_FLASH") == 0) {
            r = fscanf(cf, "%d", &sc->PLANES_PER_FLASH);
        } else if (strcmp(curline, "REG_WRITE_DELAY") == 0) {
            r = fscanf(cf, "%d", &sc->REG_WRITE_DELAY);
        } else if (strcmp(curline, "CELL_PROGRAM_DELAY") == 0) {
            r = fscanf(cf, "%d", &sc->CELL_PROGRAM_DELAY);
        } else if (strcmp(curline, "REG_READ_DELAY") == 0) {
            r = fscanf(cf, "%d", &sc->REG_READ_DELAY);
        } else if (strcmp(curline, "CELL_READ_DELAY") == 0) {
            r = fscanf(cf, "%d", &sc->CELL_READ_DELAY);
        } else if (strcmp(curline, "BLOCK_ERASE_DELAY") == 0) {
            r = fscanf(cf, "%d", &sc->BLOCK_ERASE_DELAY);
        } else if (strcmp(curline, "CHANNEL_SWITCH_DELAY_R") == 0) {
            r = fscanf(cf, "%d", &sc->CHANNEL_SWITCH_DELAY_R);
        } else if (strcmp(curline, "CHANNEL_SWITCH_DELAY_W") == 0) {
            r = fscanf(cf, "%d", &sc->CHANNEL_SWITCH_DELAY_W);
        } else if (strcmp(curline, "IO_PARALLELISM") == 0) {
            r = fscanf(cf, "%d", &sc->IO_PARALLELISM);
        } else if (strcmp(curline, "CHANNEL_NB") == 0) {
            r = fscanf(cf, "%d", &sc->CHANNEL_NB);
        } else if (strcmp(curline, "OVP") == 0) {
            r = fscanf(cf, "%d", &sc->OVP);
        } else if (strcmp(curline, "GC_MODE") == 0) {
            r = fscanf(cf, "%d", &sc->GC_MODE);
        }

        assert(r == 1);
        memset(curline, 0x00, 1024);
    }

    free(curline);
}

static int check_ssd_params(struct ssdstate *ssd)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int ret = 0;

    if (sc->FLASH_NB < sc->CHANNEL_NB) {
        printf("FEMU-FTL: Wrong CHANNEL_NB %d\n", sc->CHANNEL_NB);
        ret = -1;
        goto err;
    }

    if (sc->PLANES_PER_FLASH != 1) {
        printf("FEMU-FTL: only support 1 plane/chip");
        ret = -1;
        goto err;
    }

    /* SSD Configuration */
    sc->SECTORS_PER_PAGE = sc->PAGE_SIZE / sc->SECTOR_SIZE;
    sc->PAGES_PER_FLASH = sc->PAGE_NB * sc->BLOCK_NB;
    sc->SECTOR_NB = (int64_t)sc->SECTORS_PER_PAGE * (int64_t)sc->PAGE_NB * (int64_t)sc->BLOCK_NB * (int64_t)sc->FLASH_NB;
    printf("FEMU: %s->sector_nb = %" PRId64 "\n", ssd->ssdname, sc->SECTOR_NB);

    /* Mapping Table */
    sc->BLOCK_MAPPING_ENTRY_NB = (int64_t)sc->BLOCK_NB * (int64_t)sc->FLASH_NB;
    sc->PAGES_IN_SSD = (int64_t)sc->PAGE_NB * (int64_t)sc->BLOCK_NB * (int64_t)sc->FLASH_NB;

    sc->PAGE_MAPPING_ENTRY_NB = sc->PAGES_IN_SSD;

    sc->EACH_EMPTY_TABLE_ENTRY_NB = (int64_t)sc->BLOCK_NB / (int64_t)sc->PLANES_PER_FLASH;
    sc->EMPTY_TABLE_ENTRY_NB = sc->FLASH_NB * sc->PLANES_PER_FLASH;
    sc->VICTIM_TABLE_ENTRY_NB = sc->FLASH_NB * sc->PLANES_PER_FLASH;

    sc->DATA_BLOCK_NB = sc->BLOCK_NB;

    /* Garbage Collection */
    sc->GC_THRESHOLD = 0.75; // 0.7 for 70%, 0.9 for 90%
    sc->GC_THRESHOLD_HARD = 0.78;
    sc->GC_THRESHOLD_BLOCK_NB = (int)((1-sc->GC_THRESHOLD) * (double)sc->BLOCK_MAPPING_ENTRY_NB);
    sc->GC_THRESHOLD_BLOCK_NB_HARD = (int)((1-sc->GC_THRESHOLD_HARD) * (double)sc->BLOCK_MAPPING_ENTRY_NB);
    sc->GC_THRESHOLD_BLOCK_NB_EACH = (int)((1-sc->GC_THRESHOLD) * (double)sc->EACH_EMPTY_TABLE_ENTRY_NB);
    if (sc->OVP != 0) {
        sc->GC_VICTIM_NB = sc->FLASH_NB * sc->BLOCK_NB * sc->OVP / 100 / 2;
    } else {
        sc->GC_VICTIM_NB = 1;
    }

    /* Coperd: allocate GC_SLOT structure here */
    int num_gc_slots = 0;
    if (sc->GC_MODE == WHOLE_BLOCKING) {
        num_gc_slots = 1;
    } else if (sc->GC_MODE == CHANNEL_BLOCKING) {
        num_gc_slots = sc->CHANNEL_NB;
    } else if (sc->GC_MODE == CHIP_BLOCKING) {
        num_gc_slots = sc->FLASH_NB * sc->PLANES_PER_FLASH;
    } else {
        printf("Unsupported GC MODE: %d!\n", sc->GC_MODE);
        abort();
    }

    assert(num_gc_slots != 0);
    ssd->gc_slot = calloc(num_gc_slots, sizeof(int64_t));

    ssd->chnl_next_avail_time = malloc(sizeof(int64_t) * sc->CHANNEL_NB);
    memset(ssd->chnl_next_avail_time, 0, sizeof(int64_t) * sc->CHANNEL_NB);
    ssd->chip_next_avail_time = malloc(sizeof(int64_t) * sc->FLASH_NB);
    memset(ssd->chip_next_avail_time, 0, sizeof(int64_t) * sc->FLASH_NB);

err:
    return ret;
}

void INIT_SSD_CONFIG(struct ssdstate *ssd)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    FILE *cf;
    int ret;

    cf = fopen(ssd->conffile, "r");
    if (!cf) {
        printf("FEMU-FTL: failed to open ssd conf file:%s\n", ssd->conffile);
        abort();
    }

    parse_ssd_params(sc, cf);

    fclose(cf);

    ret = check_ssd_params(ssd);
    if (ret == -1) {
        abort();
    }
}
