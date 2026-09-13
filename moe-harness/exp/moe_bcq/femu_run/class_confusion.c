/* Read a chosen set of LPNs so FEMU's own per-class counters report which
 * physical page classes they actually landed on.
 *
 * The latency probe infers a class from a measured time and can be fooled by
 * host jitter. The device counts every physical page read by class itself, so
 * reading only the LPNs a layout model calls class k turns the counter vector
 * into that model's confusion row exactly, with no timing inference at all.
 *
 * Counters are reset here and snapshotted at the end, so the vector covers this
 * program's reads and nothing else. The snapshot is written by FEMU to the path
 * it was started with; this program cannot see it.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/nvme_ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define PGSZ (16 * 1024)
#define PGS_PER_BLK 512
#define LPN_PER_PAGE_INDEX 8        /* nchs * luns_per_ch, the modelled stride */
#define FEMU_FLIP_OPCODE 0xef
#define FEMU_RESET_QLC 8
#define FEMU_SNAP_QLC 9

static int femu_flip(const char *ctrl, int selector)
{
    int fd = open(ctrl, O_RDONLY);
    if (fd < 0) { perror(ctrl); return -1; }
    struct nvme_admin_cmd cmd;
    memset(&cmd, 0, sizeof cmd);
    cmd.opcode = FEMU_FLIP_OPCODE;
    cmd.cdw10 = selector;
    int rc = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
    close(fd);
    return rc;
}

/* mirrors init_qlc_page_pairing() with the rows-1 fix */
static int page_class(long pg)
{
    if (pg < 6) return 0;
    if (pg < 8) return 1;
    return (int)(((pg - 8) % 8) / 2);
}

int main(int argc, char **argv)
{
    if (argc < 5) {
        fprintf(stderr, "usage: %s DEV CTRL WANT_CLASS LPN_LIMIT\n"
                "  reads every LPN below LPN_LIMIT the model calls WANT_CLASS\n",
                argv[0]);
        return 2;
    }
    const char *dev = argv[1], *ctrl = argv[2];
    int want = atoi(argv[3]);
    long limit = atol(argv[4]);

    int fd = open(dev, O_RDONLY | O_DIRECT);
    if (fd < 0) { perror(dev); return 1; }
    void *buf;
    if (posix_memalign(&buf, 4096, PGSZ)) { perror("memalign"); return 1; }

    if (femu_flip(ctrl, FEMU_RESET_QLC)) {
        fprintf(stderr, "fatal: QLC counter reset failed\n");
        return 1;
    }

    long n = 0;
    for (long lpn = 0; lpn < limit; lpn++) {
        if (page_class((lpn / LPN_PER_PAGE_INDEX) % PGS_PER_BLK) != want) continue;
        if (pread(fd, buf, PGSZ, (off_t)lpn * PGSZ) != PGSZ) { perror("pread"); return 1; }
        n++;
    }

    if (femu_flip(ctrl, FEMU_SNAP_QLC)) {
        fprintf(stderr, "fatal: QLC counter snapshot failed\n");
        return 1;
    }
    printf("CONFUSION want_class=%d lpn_limit=%ld reads=%ld\n", want, limit, n);
    return 0;
}
