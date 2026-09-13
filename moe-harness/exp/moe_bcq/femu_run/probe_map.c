/* Measure the LPN -> QLC page-class mapping the device actually uses.
 *
 * The layout planner predicts a class for every page it places, and the whole
 * experiment rests on that prediction matching the device. Read latency is the
 * one signal that reports the class directly: the four classes are 47.9, 76.2,
 * 134.6 and 228.1 us apart, far enough to separate under any constant host
 * overhead. So time single-page reads at known LPNs and read the class back off
 * the clock instead of trusting a model of the write pointer.
 *
 * The device must already be filled: a read of an unmapped LPN never reaches the
 * media, so it would time as class 0 and look like a mapping that starts fast.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define PGSZ (16 * 1024)
static const double EXPECT_US[4] = {47.9, 76.2, 134.6, 228.1};

static int cmp(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

static double now_us(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC_RAW, &t);
    return t.tv_sec * 1e6 + t.tv_nsec / 1e3;
}

int main(int argc, char **argv)
{
    const char *dev = argc > 1 ? argv[1] : "/dev/nvme0n1";
    long first = argc > 2 ? atol(argv[2]) : 0;
    long count = argc > 3 ? atol(argv[3]) : 1024;
    int reps = argc > 4 ? atoi(argv[4]) : 5;

    int fd = open(dev, O_RDONLY | O_DIRECT);
    if (fd < 0) { perror(dev); return 1; }
    void *buf;
    if (posix_memalign(&buf, 4096, PGSZ)) { perror("memalign"); return 1; }

    double *med = malloc(count * sizeof *med);
    double *s = malloc(reps * sizeof *s);
    if (!med || !s) { fprintf(stderr, "oom\n"); return 1; }

    /* Sweep repetition-major rather than LPN-major: consecutive reads of the
     * same page would sit behind one another on the same LUN and measure queue
     * time as well as array time. */
    for (long i = 0; i < count; i++) med[i] = 0;
    for (int r = 0; r < reps; r++) {
        for (long i = 0; i < count; i++) {
            off_t off = (off_t)(first + i) * PGSZ;
            double t0 = now_us();
            if (pread(fd, buf, PGSZ, off) != PGSZ) { perror("pread"); return 1; }
            double dt = now_us() - t0;
            /* keep the running minimum: the cleanest estimate of array time */
            if (r == 0 || dt < med[i]) med[i] = dt;
        }
    }

    /* Calibrate the constant host overhead from the observed spread, then class
     * each page by nearest expected latency. The offset is whatever makes the
     * fastest pages land on class 0. */
    double *sorted = malloc(count * sizeof *sorted);
    memcpy(sorted, med, count * sizeof *sorted);
    qsort(sorted, count, sizeof *sorted, cmp);
    double floor_us = sorted[count / 100];          /* 1st percentile */
    double offset = floor_us - EXPECT_US[0];

    printf("PROBE dev=%s first=%ld count=%ld reps=%d\n", dev, first, count, reps);
    printf("PROBE floor=%.1fus implied_host_offset=%.1fus\n", floor_us, offset);
    printf("PROBE quartiles %.1f %.1f %.1f %.1f\n",
           sorted[count / 8], sorted[count * 3 / 8],
           sorted[count * 5 / 8], sorted[count * 7 / 8]);

    long hist[4] = {0};
    printf("CLASSMAP %ld ", first);
    for (long i = 0; i < count; i++) {
        int best = 0;
        double bd = 1e18;
        for (int c = 0; c < 4; c++) {
            double d = med[i] - offset - EXPECT_US[c];
            if (d < 0) d = -d;
            if (d < bd) { bd = d; best = c; }
        }
        hist[best]++;
        putchar('0' + best);
        if ((i + 1) % 128 == 0 && i + 1 < count) printf("\nCLASSMAP %ld ", first + i + 1);
    }
    printf("\nPROBE counts %ld %ld %ld %ld\n", hist[0], hist[1], hist[2], hist[3]);

    /* A few raw samples so the classification can be audited by hand. */
    printf("PROBE raw");
    for (long i = 0; i < 16 && i < count; i++) printf(" %ld:%.1f", first + i, med[i]);
    printf("\n");
    return 0;
}
