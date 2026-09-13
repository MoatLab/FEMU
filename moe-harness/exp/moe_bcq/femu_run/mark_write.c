/* Write marker-bearing pages so FEMU logs the real LPN -> PPA for each one.
 *
 * Every attempt to predict the physical page class from the LPN has been a model
 * of the write pointer, and the counters say the model is wrong. FEMU will name
 * the physical address itself for any page whose content carries the marker
 * string it was started with, so write that string into each page and read the
 * mapping out of the emulator's log rather than inferring it.
 *
 * Write sequentially from LPN 0 on a fresh device: that is exactly the fill the
 * layout assumes, so the logged addresses are the ones the layout would get.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PGSZ (16 * 1024)

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s DEV MARKER COUNT [FIRST] [PAGES_PER_WRITE]\n"
                "  PAGES_PER_WRITE > 1 issues one multi-page command, the way a\n"
                "  bulk fill does, rather than a command per page.\n", argv[0]);
        return 2;
    }
    const char *dev = argv[1], *marker = argv[2];
    long count = atol(argv[3]);
    long first = argc > 4 ? atol(argv[4]) : 0;
    long batch = argc > 5 ? atol(argv[5]) : 1;
    if (batch < 1) batch = 1;

    int fd = open(dev, O_WRONLY | O_DIRECT);
    if (fd < 0) { perror(dev); return 1; }
    void *buf;
    size_t span = (size_t)batch * PGSZ;
    if (posix_memalign(&buf, 4096, span)) { perror("memalign"); return 1; }

    for (long i = 0; i < count; i += batch) {
        long n = count - i < batch ? count - i : batch;
        memset(buf, 0, span);
        /* the marker plus the LPN, so a dump can be checked against the write */
        for (long j = 0; j < n; j++)
            snprintf((char *)buf + (size_t)j * PGSZ, PGSZ, "%s lpn=%ld",
                     marker, first + i + j);
        size_t want = (size_t)n * PGSZ;
        if (pwrite(fd, buf, want, (off_t)(first + i) * PGSZ) != (ssize_t)want) {
            perror("pwrite");
            return 1;
        }
    }
    if (fsync(fd)) { perror("fsync"); return 1; }
    printf("MARKWRITE first=%ld count=%ld pages_per_write=%ld marker=%s\n",
           first, count, batch, marker);
    return 0;
}
