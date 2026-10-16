/*
 * Guest side of the csd_pause check: load a program that sleeps, then time
 * each Execute on the guest clock. The program sleeps for HOST_MS on the host
 * and declares a run time of MODEL_US. Without csd_pause the guest sees about
 * HOST_MS; with it, about MODEL_US.
 *
 * Usage: csdlat CTRL NS HOST_MS MODEL_US COUNT
 *   CTRL is /dev/nvme0, NS is /dev/nvme0n1; the program is slow.so:run in
 *   csd_program_dir.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#include <linux/nvme_ioctl.h>

#define CSD_ALLOC_FDM   0xb0
#define CSD_EXEC        0xe1
#define CSD_LOAD        0xc5
#define CSD_ACTIVATE    0xc8
#define CSD_SHARED_LIB  3

static uint64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

static int run(int fd, unsigned long req, struct nvme_passthru_cmd *c,
               const char *what)
{
    int ret = ioctl(fd, req, c);

    if (ret) {
        fprintf(stderr, "CSDLAT %s failed: ret=%d errno=%d\n", what, ret,
                errno);
        exit(1);
    }
    return ret;
}

static int cmp(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;

    return x < y ? -1 : x > y;
}

int main(int argc, char **argv)
{
    static char buf[4096] __attribute__((aligned(4096)));
    static uint32_t mr[8] __attribute__((aligned(4096)));
    struct nvme_passthru_cmd c;
    const char name[] = "slow.so";
    const char sym[] = "run";
    int ctrl, ns, count, i;
    uint32_t host_ms, model_us, id;
    uint64_t *lat, t;

    if (argc != 6) {
        fprintf(stderr, "usage: csdlat CTRL NS HOST_MS MODEL_US COUNT\n");
        return 2;
    }
    ctrl = open(argv[1], O_RDWR);
    ns = open(argv[2], O_RDWR);
    if (ctrl < 0 || ns < 0) {
        perror("open");
        return 1;
    }
    host_ms = atoi(argv[3]);
    model_us = atoi(argv[4]);
    count = atoi(argv[5]);
    lat = calloc(count, sizeof(*lat));

    memset(buf, 0, sizeof(buf));
    memcpy(buf, name, sizeof(name));
    memcpy(buf + sizeof(name), sym, sizeof(sym));
    memset(&c, 0, sizeof(c));
    c.opcode = CSD_LOAD;
    c.addr = (uintptr_t)buf;
    c.data_len = 4096;
    c.cdw10 = 1 | (CSD_SHARED_LIB << 16);
    c.cdw11 = sizeof(name) + sizeof(sym);
    c.cdw14 = sizeof(name) + sizeof(sym);
    run(ctrl, NVME_IOCTL_ADMIN_CMD, &c, "load");

    memset(&c, 0, sizeof(c));
    c.opcode = CSD_ACTIVATE;
    c.cdw10 = 1 | (1 << 16);
    run(ctrl, NVME_IOCTL_ADMIN_CMD, &c, "activate");

    memset(&c, 0, sizeof(c));
    c.opcode = CSD_ALLOC_FDM;
    c.nsid = 1;
    c.cdw10 = 4096;
    run(ns, NVME_IOCTL_IO_CMD, &c, "alloc");
    id = c.result;

    memset(mr, 0, sizeof(mr));
    mr[2] = id;
    for (i = 0; i < count; i++) {
        memset(&c, 0, sizeof(c));
        c.opcode = CSD_EXEC;
        c.nsid = 1;
        c.cdw2 = 1;                     /* program index */
        c.cdw3 = 1;                     /* one memory range */
        c.addr = (uintptr_t)mr;
        c.data_len = 4096;
        c.cdw10 = host_ms;              /* cparam1: host sleep */
        c.cdw15 = model_us * 1000;      /* declared run time, ns */
        t = now_ns();
        run(ns, NVME_IOCTL_IO_CMD, &c, "exec");
        lat[i] = now_ns() - t;
        if (c.result != 7) {
            fprintf(stderr, "CSDLAT bad result %u\n", c.result);
            return 1;
        }
    }
    qsort(lat, count, sizeof(*lat), cmp);
    printf("CSDLAT host_ms=%u model_us=%u n=%d min=%.1f p50=%.1f max=%.1f us\n",
           host_ms, model_us, count, lat[0] / 1e3, lat[count / 2] / 1e3,
           lat[count - 1] / 1e3);
    return 0;
}
