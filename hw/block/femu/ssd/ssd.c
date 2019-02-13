// File: ssd.c
// Date: 2014. 12. 03.
// Author: Jinsoo Yoo (jedisty@hanyang.ac.kr)
// Copyright(c)2014
// Hanyang University, Seoul, Korea
// Embedded Software Systems Laboratory. All right reserved

#include "ssd.h"

static int ssd_num = 1;

/* Coperd: SSD FTL thread */
static void *ftl_thread(void *arg)
{
    struct ssdstate *ssd = (struct ssdstate *)arg;
    NvmeRequest *req = NULL;
    int64_t lat = 0;
    int rc;
    
    while (!*(ssd->dataplane_started_ptr)) {
        //printf("Coperd, waiting for NVMe dataplane to be up ...\n");
        usleep(100000);
    }

    printf("FEMU, FTL thread woke up from sleeping !!!!!!!!!!\n");
    printf("FEMU, FTL thread woke up from sleeping !!!!!!!!!!\n");
    printf("FEMU, FTL thread woke up from sleeping !!!!!!!!!!\n");
    printf("FEMU, FTL thread woke up from sleeping !!!!!!!!!!\n");
    printf("FEMU, FTL thread woke up from sleeping !!!!!!!!!!\n");
    printf("FEMU, FTL thread woke up from sleeping !!!!!!!!!!\n");
    printf("FEMU, FTL thread woke up from sleeping !!!!!!!!!!\n");
    printf("FEMU, FTL thread woke up from sleeping !!!!!!!!!!\n");
    printf("FEMU, FTL thread woke up from sleeping !!!!!!!!!!\n");
    printf("FEMU, FTL thread woke up from sleeping !!!!!!!!!!\n");
    printf("FEMU, FTL thread woke up from sleeping !!!!!!!!!!\n");
    printf("FEMU, FTL thread woke up from sleeping !!!!!!!!!!\n");

    while (1) {
        if (!ssd->to_ftl || !femu_ring_count(ssd->to_ftl))
            continue;

        rc = femu_ring_dequeue(ssd->to_ftl, (void *)&req, 1);
        if (rc != 1) {
            printf("FEMU: FTL to_ftl dequeue failed\n");
        }
        assert(req);
        //printf("FEMU: FTL gets a requests from poller threads ...\n");
        /* process one request */
        uint64_t lst, let;
        switch (req->is_write) {
            case 1:
                lat = SSD_WRITE(ssd, req->data_offset >> 9, req->nlb << 3);
                break;
            case 0:
                lst = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
                lat = SSD_READ(ssd, req->data_offset >> 9, req->nlb << 3);
                let = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
                printf("Coperd,ftl-oh,read,%" PRId64 "\n", let - lst);
                break;
            default:
                printf("FEMU: FTL received unkown request type, ERROR\n");
        }

        req->expire_time += lat;

        /* Coperd: greedly wait for to_poller to be ready */
        //while (!ssd->to_poller);
        /* Coperd: now it's time to put the request back to poller thread */
        rc = femu_ring_enqueue(ssd->to_poller, (void *)&req, 1);
        if (rc != 1) {
            printf("FEMU: FTL to_poller enqueue failed\n");
        }
    }
}

#if 0
static void do_warmup(struct ssdstate *ssd)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int GC_THRESHOLD_BLOCK_NB = sc->GC_THRESHOLD_BLOCK_NB;

    ssd->in_warmup_stage = true;
    const char *tfname = "./data/warmup.trace";

    FILE *tfp = fopen(tfname, "r");
    if (tfp == NULL) {
        printf("CANNOT open trace file [%s], skipping warmup\n", tfname);
        return;
    }

    int64_t w_sector_num;
    int w_length, w_type;

    int t_nb_sects = 0;
    int t_ios = 0;
    int ntraverses = 0;

    int64_t ssd_sz = 24 * 1024 * 1024 * 2 - 50 * 1024 * 2;

    printf("=======[%s] WARMUP from %s=======\n", "nvme ssd", tfname);
    while (1) {
        int sr = fscanf(tfp, "%*f%*d%" PRId64 "%d%d\n", &w_sector_num, 
                &w_length, &w_type);
        if ((sr == EOF) && (ntraverses <= 0)) {
            ntraverses++;
            fseek(tfp, 0, SEEK_SET);
        } else if (sr == EOF) {
            break;
        }
        if (w_type == 0) /* skip writes */
            //continue;
            SSD_WRITE(ssd, w_length, w_sector_num % ssd_sz);
        t_nb_sects += w_length;
        t_ios++;
        //mylog("write: (%"PRId64", %d)\n", w_sector_num, w_length);
    }
    fclose(tfp);
    printf("========[%s] SSD WARMUP ENDS %"PRId64"/%d blocks, %d I/Os,"
            "%d MB========\n", get_ssd_name(), ssd->total_empty_block_nb, GC_THRESHOLD_BLOCK_NB, t_ios, t_nb_sects*512/1024/1024);

    ssd->in_warmup_stage = false;
}
#endif

static void do_rand_warmup(struct ssdstate *ssd)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int GC_THRESHOLD_BLOCK_NB = sc->GC_THRESHOLD_BLOCK_NB;
    //double GC_THRESHOLD = sc->GC_THRESHOLD;

    int i;
    int nios = 10;
    int *io = (int *)malloc(sizeof(int)*nios);
    for (i = 0; i < nios; i++) {
        io[i] = 1 << i;
    }
    int64_t ssd_sz_in_sects = sc->PAGES_IN_SSD * sc->PAGE_SIZE / 512 - 8192;
    //printf("ssd size: %ld\n", ssd_sz_in_sects);
    srand(time(NULL));
    int io_sz;          // in sectors
    int64_t io_oft;     // in sectors
    int64_t written_sz_in_sects = 0;

    /* Coperd: 0 -> read from warmup file, 1 -> generate warmup file */
    int warmup_mode = 0;


    if (warmup_mode == 0) {
        printf("=======[%s] Random WARMUP Begins=======\n", ssd->ssdname);
        FILE *fp = fopen(ssd->warmupfile, "r");
        if (fp == NULL) {
            fprintf(stderr, "CANNOT open warmup file [%s], skipping it ..\n", ssd->warmupfile);
            return;
        }

        ssd->in_warmup_stage = 1;
        while(fscanf(fp, "%"PRId64"%d\n", &io_oft, &io_sz) != EOF) {
            SSD_WRITE(ssd, io_oft, io_sz);
            written_sz_in_sects += io_sz;
        }
        ssd->in_warmup_stage = 0;
        printf("========[%s] WARMUP ENDS %"PRId64"/%d blocks,"
                "%" PRId64 " MB========\n", ssd->ssdname, ssd->total_empty_block_nb, 
                GC_THRESHOLD_BLOCK_NB, written_sz_in_sects*512/1024/1024);

    } else {
        printf("=======[%s] Generating WARMUP File Begins=======\n", ssd->ssdname);
        FILE *fp = fopen(ssd->warmupfile, "w");
        if (fp == NULL) {
            fprintf(stderr, "CANNOT open warmup file [%s]\n", ssd->warmupfile);
            exit(EXIT_FAILURE);
        }

        while (written_sz_in_sects <= ssd_sz_in_sects * (sc->GC_THRESHOLD - 0.02)) {
            io_sz = io[rand() % nios] * 2; 
            io_oft = (rand() % (ssd_sz_in_sects / 4)) * 4;
            SSD_WRITE(ssd, io_oft, io_sz);
            //printf("%"PRId64", %d\n", io_oft, io_sz);
            written_sz_in_sects += io_sz;

            fprintf(fp, "%ld\t%d\n", io_oft, io_sz);
        }
        printf("========[%s] Generating WARMUP File ENDS %"PRId64"/%d blocks,"
                "%" PRId64 " MB========\n", ssd->ssdname, ssd->total_empty_block_nb, 
                GC_THRESHOLD_BLOCK_NB, written_sz_in_sects*512/1024/1024);
    }


    if (warmup_mode == 1) {
        if (ssd_num == 5)
            exit(EXIT_FAILURE);
    }
}

//sector_entry* PARSE_SECTOR_LIST(trim_data, length);
void SSD_INIT(struct ssdstate *ssd)
{
    //memset(ssd, 0, sizeof(struct ssdstate));

    /* Coperd: ssdstate structure initialization */
    strcpy(ssd->ssdname, "vssd");
    char ftmp[64] = {'\0'};
    sprintf(ftmp, "%d", ssd_num++);
    strcat(ssd->ssdname, ftmp);
    strcpy(ssd->conffile, ssd->ssdname);
    strcat(ssd->conffile, ".conf");
    strcpy(ssd->statfile, ssd->ssdname);
    strcat(ssd->statfile, ".csv");
    strcpy(ssd->warmupfile, ssd->ssdname);
    strcat(ssd->warmupfile, ".trace");

    printf("[%s] is up\n", ssd->ssdname);
    sleep(1);

	FTL_INIT(ssd);

    ssd->statfp = fopen(ssd->statfile, "w+");
    if (ssd->statfp == NULL) {
        fprintf(stderr, "Error creating stat files!!!\n");
        exit(EXIT_FAILURE);
    }
    setvbuf(ssd->statfp, NULL, _IONBF, 0);
    fprintf(ssd->statfp, "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n", 
            "#br","#r", "rd-sz", "#bw", "#w", "wr-sz", "#nvme-rw", 
            "lat-nvme-rw", "lat-ssd-rd", "lat-ssd-wr",
            "#gc", "cb-pg", 
            "lat-each-gc", "lat-svb", "lat-cp", "lat-up");
    fflush(ssd->statfp);

    /* Coperd: do warmup immediately after SSD structures are initialized */
    do_rand_warmup(ssd);

    /* Coperd: let's kick start FTL thread for user request processing */
    qemu_thread_create(&ssd->ftl_thread, "ftl-thread", ftl_thread, ssd,
            QEMU_THREAD_JOINABLE);
}

#if 0
static void SSD_TERM(struct ssdstate *ssd)
{	
	FTL_TERM(ssd);
}
#endif

int64_t SSD_WRITE(struct ssdstate *ssd, int64_t sector_nb, unsigned int length)
{
	return FTL_WRITE(ssd, sector_nb, length);
}

int64_t SSD_READ(struct ssdstate *ssd, int64_t sector_nb, unsigned int length)
{
    return FTL_READ(ssd, sector_nb, length);
}
