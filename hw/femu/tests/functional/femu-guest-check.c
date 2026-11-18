/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The guest side of the FEMU boot test. /init runs it once with the mode
 * and the controller serial. It prints one line per check and stops at
 * the first failure:
 *
 *   FEMU-CHECK <name> ok
 *   FEMU-CHECK <name> fail <reason> errno=<n>
 *
 * The dev check prints the namespace size in bytes; the host compares
 * it with the size of the device line.
 *
 *   nossd, bbssd: dev serial queues data
 *   fdp:          dev serial queues fdp data
 *   zns:          dev serial queues zone
 *   kv:           kvdev serial irq kv
 *
 * Built static on the host (gcc -static), so the initramfs needs no
 * shared libraries.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/blkzoned.h>
#include <linux/fs.h>
#include <linux/nvme_ioctl.h>

#define BLK         4096
#define THREADS     2
#define ZONE_BLKS   16

static const char *g_mode;
static uint64_t g_size;           /* bytes, from /sys/block */
static const char *g_serial;

static int fail(const char *name, const char *why)
{
    printf("FEMU-CHECK %s fail %s errno=%d\n", name, why, errno);
    fflush(stdout);
    return 1;
}

static int ok(const char *name)
{
    printf("FEMU-CHECK %s ok\n", name);
    fflush(stdout);
    return 0;
}

/* read a small sysfs file into @buf; trailing blanks and newlines go */
static bool read_line(const char *path, char *buf, size_t n)
{
    FILE *f = fopen(path, "r");
    size_t len;

    if (!f) {
        return false;
    }
    len = fread(buf, 1, n - 1, f);
    fclose(f);
    buf[len] = 0;
    while (len && (buf[len - 1] == '\n' || buf[len - 1] == ' ')) {
        buf[--len] = 0;
    }
    return true;
}

/* wait up to 10 s for @path to exist with the file type @type */
static bool wait_node(const char *path, mode_t type)
{
    struct stat st;
    int i;

    for (i = 0; i < 100; i++) {
        if (!stat(path, &st) && (st.st_mode & S_IFMT) == type) {
            return true;
        }
        usleep(100000);
    }
    return false;
}

static int check_dev(void)
{
    char buf[64];

    if (!wait_node("/dev/nvme0n1", S_IFBLK)) {
        return fail("dev", "no-block-device");
    }
    if (!read_line("/sys/block/nvme0n1/size", buf, sizeof(buf))) {
        return fail("dev", "no-size");
    }
    if (sscanf(buf, "%" SCNu64, &g_size) != 1) {
        errno = 0;
        return fail("dev", "bad-size");
    }
    g_size *= 512;
    if (g_size < BLK * 64) {
        errno = 0;
        return fail("dev", "too-small");
    }
    printf("FEMU-CHECK dev ok size=%" PRIu64 "\n", g_size);
    fflush(stdout);
    return 0;
}

static int check_kvdev(void)
{
    if (!wait_node("/dev/ng0n1", S_IFCHR)) {
        return fail("kvdev", "no-generic-node");
    }
    return ok("kvdev");
}

/* each FEMU mode names its controller: vSSD0, vZNSSD0 and so on */
static int check_serial(void)
{
    char buf[64];

    if (!read_line("/sys/class/nvme/nvme0/serial", buf, sizeof(buf))) {
        return fail("serial", "no-serial");
    }
    if (strcmp(buf, g_serial)) {
        errno = 0;
        return fail("serial", "serial-differs");
    }
    return ok("serial");
}

/*
 * The chip name in /proc/interrupts is PCI-MSI on Linux 6.1 for MSI-X
 * too, and PCI-MSIX later, so the vector mode comes from sysfs.
 */
static bool irq_is_msix(int irq)
{
    char path[80];
    char buf[16];

    snprintf(path, sizeof(path),
             "/sys/class/nvme/nvme0/device/msi_irqs/%d", irq);
    return read_line(path, buf, sizeof(buf)) && !strcmp(buf, "msix");
}

/* interrupts of the MSI-X vector of I/O queue @q, or -1 without one */
static long long irq_count(int q)
{
    FILE *f = fopen("/proc/interrupts", "r");
    char line[512];
    char name[16];
    long long n = -1;

    if (!f) {
        return -1;
    }
    snprintf(name, sizeof(name), "nvme0q%d\n", q);
    while (fgets(line, sizeof(line), f)) {
        char *p = strchr(line, ':');

        if (!p || !strstr(line, name) || !irq_is_msix(atoi(line))) {
            continue;
        }
        n = 0;
        /* one count per CPU column, up to the chip name */
        for (p++; ; ) {
            long long v;
            int used;

            if (sscanf(p, " %lld%n", &v, &used) != 1) {
                break;
            }
            n += v;
            p += used;
        }
    }
    fclose(f);
    return n;
}

static bool irq_ok(void)
{
    return irq_count(1) >= 0 && irq_count(2) >= 0;
}

/* hardware queue @hctx serves exactly CPU @cpu */
static bool hctx_cpu(int hctx, const char *cpu)
{
    char path[64];
    char buf[16];

    snprintf(path, sizeof(path), "/sys/block/nvme0n1/mq/%d/cpu_list", hctx);
    return read_line(path, buf, sizeof(buf)) && !strcmp(buf, cpu);
}

static int check_queues(bool blk)
{
    const char *name = blk ? "queues" : "irq";
    char buf[16];
    DIR *d;
    struct dirent *e;
    int n = 0;

    if (!read_line("/sys/devices/system/cpu/online", buf, sizeof(buf)) ||
        strcmp(buf, "0-1")) {
        errno = 0;
        return fail(name, "not-two-cpus");
    }
    if (blk) {
        d = opendir("/sys/block/nvme0n1/mq");
        if (!d) {
            return fail(name, "no-mq");
        }
        while ((e = readdir(d))) {
            n += e->d_name[0] != '.';
        }
        closedir(d);
        /*
         * One hardware queue per CPU, in either order: Linux 7.x spreads
         * the CPUs over the vectors with new code and gives hctx 0 to
         * CPU 1. The data check needs only both queues busy.
         */
        if (n != 2 || !((hctx_cpu(0, "0") && hctx_cpu(1, "1")) ||
                        (hctx_cpu(0, "1") && hctx_cpu(1, "0")))) {
            char c0[16] = "none";
            char c1[16] = "none";
            char why[64];

            read_line("/sys/block/nvme0n1/mq/0/cpu_list", c0, sizeof(c0));
            read_line("/sys/block/nvme0n1/mq/1/cpu_list", c1, sizeof(c1));
            snprintf(why, sizeof(why), "queue-cpu-map hctx=%d q0=%s q1=%s",
                     n, c0, c1);
            errno = 0;
            return fail(name, why);
        }
    }
    if (!irq_ok()) {
        errno = 0;
        return fail(name, "no-msix-q1-q2");
    }
    return ok(name);
}

/* the bytes of block @lba in @epoch: no zero word, unique per block */
static void fill(uint64_t *p, uint64_t lba, uint64_t epoch)
{
    uint64_t x = lba * 0x9E3779B97F4A7C15ull ^ (epoch + 1) * 0xC2B2AE3D27D4EB4Full;
    size_t i;

    for (i = 0; i < BLK / 8; i++) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        p[i] = x | 1;
    }
}

typedef struct Job {
    int cpu;
    int fd;
    uint64_t first;
    uint64_t nblk;
    uint64_t epoch;
    bool even_only;
    bool write;
    const uint8_t *epochs;      /* the epoch each block holds, for reads */
    int err;
    int bad;
} Job;

static void *run_job(void *opaque)
{
    Job *j = opaque;
    uint64_t *buf;
    uint64_t *want;
    uint64_t b;

    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(j->cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set)) {
        j->err = errno;
        return NULL;
    }
    if (posix_memalign((void **)&buf, BLK, BLK) ||
        posix_memalign((void **)&want, BLK, BLK)) {
        j->err = ENOMEM;
        return NULL;
    }
    for (b = j->first; b < j->first + j->nblk; b++) {
        off_t off = (off_t)b * BLK;

        if (j->write) {
            if (j->even_only && (b & 1)) {
                continue;
            }
            fill(buf, b, j->epoch);
            if (pwrite(j->fd, buf, BLK, off) != BLK) {
                j->err = errno ? errno : EIO;
                break;
            }
        } else {
            if (pread(j->fd, buf, BLK, off) != BLK) {
                j->err = errno ? errno : EIO;
                break;
            }
            fill(want, b, j->epochs[b]);
            if (memcmp(buf, want, BLK)) {
                j->bad++;
                break;
            }
        }
    }
    free(buf);
    free(want);
    return NULL;
}

/* @write or verify every block with THREADS threads; 0 or -errno */
static int pass(int fd, uint64_t nblk, uint64_t epoch, bool even_only,
                bool write, const uint8_t *epochs, int *bad)
{
    pthread_t t[THREADS];
    Job j[THREADS];
    uint64_t per = nblk / THREADS;
    int i;
    int err = 0;

    for (i = 0; i < THREADS; i++) {
        j[i] = (Job) {
            .cpu = i, .fd = fd, .first = per * i,
            .nblk = i == THREADS - 1 ? nblk - per * i : per,
            .epoch = epoch, .even_only = even_only, .write = write,
            .epochs = epochs,
        };
        if (pthread_create(&t[i], NULL, run_job, &j[i])) {
            return -EAGAIN;
        }
    }
    for (i = 0; i < THREADS; i++) {
        pthread_join(t[i], NULL);
        if (j[i].err && !err) {
            err = -j[i].err;
        }
        *bad += j[i].bad;
    }
    return err;
}

/*
 * Epoch 0 writes every block; epochs 1 and 2 write the even blocks
 * again, so bbssd lines hold valid and invalid pages and GC runs. Every
 * block is read back after each epoch. O_DIRECT keeps the page cache
 * out, so each read reaches the device.
 */
static int check_data(void)
{
    uint64_t nblk = g_size / BLK;
    uint8_t *epochs = calloc(nblk, 1);
    int fd = open("/dev/nvme0n1", O_RDWR | O_DIRECT);
    long long q1 = irq_count(1);
    long long q2 = irq_count(2);
    uint64_t e;
    uint64_t b;
    int bad = 0;
    int err;

    if (fd < 0 || !epochs) {
        return fail("data", "open");
    }
    for (e = 0; e < 3; e++) {
        err = pass(fd, nblk, e, e > 0, true, NULL, &bad);
        if (!err && fsync(fd)) {
            err = -errno;
        }
        if (err) {
            errno = -err;
            return fail("data", "write");
        }
        for (b = 0; b < nblk; b++) {
            if (e == 0 || !(b & 1)) {
                epochs[b] = e;
            }
        }
        err = pass(fd, nblk, 0, false, false, epochs, &bad);
        if (err) {
            errno = -err;
            return fail("data", "read");
        }
        if (bad) {
            errno = 0;
            return fail("data", "bytes-differ");
        }
    }
    close(fd);
    free(epochs);
    /* each worker runs on its own CPU, so each queue completes its I/O */
    q1 = irq_count(1) - q1;
    q2 = irq_count(2) - q2;
    printf("FEMU-CHECK data irq q1=%lld q2=%lld\n", q1, q2);
    if (q1 < 256 || q2 < 256) {
        errno = 0;
        return fail("data", "idle-queue");
    }
    return ok("data");
}

/* the zone that holds @sector; false on a failed report */
static bool zone_at(int fd, uint64_t sector, struct blk_zone *z,
                    uint32_t *flags)
{
    struct {
        struct blk_zone_report r;
        struct blk_zone z;
    } rep = { .r = { .sector = sector, .nr_zones = 1 } };

    if (ioctl(fd, BLKREPORTZONE, &rep) || rep.r.nr_zones != 1) {
        return false;
    }
    *z = rep.z;
    if (flags) {
        *flags = rep.r.flags;
    }
    return true;
}

static bool zone0(int fd, struct blk_zone *z)
{
    return zone_at(fd, 0, z, NULL);
}

/* @n blocks of @epoch from byte @base */
static int zone_write_n(int fd, off_t base, uint64_t n, uint64_t epoch)
{
    uint64_t *buf;
    uint64_t b;

    if (posix_memalign((void **)&buf, BLK, BLK)) {
        return -ENOMEM;
    }
    for (b = 0; b < n; b++) {
        fill(buf, b, epoch);
        if (pwrite(fd, buf, BLK, base + (off_t)b * BLK) != BLK) {
            free(buf);
            return errno ? -errno : -EIO;
        }
    }
    free(buf);
    return 0;
}

static int zone_write(int fd, uint64_t epoch)
{
    return zone_write_n(fd, 0, ZONE_BLKS, epoch);
}

static int zone_verify_n(int fd, off_t base, uint64_t n, uint64_t epoch)
{
    uint64_t *buf;
    uint64_t *want;
    uint64_t b;
    int r = 0;

    if (posix_memalign((void **)&buf, BLK, BLK) ||
        posix_memalign((void **)&want, BLK, BLK)) {
        return -1;
    }
    for (b = 0; b < n && !r; b++) {
        fill(want, b, epoch);
        if (pread(fd, buf, BLK, base + (off_t)b * BLK) != BLK ||
            memcmp(buf, want, BLK)) {
            r = -1;
        }
    }
    free(buf);
    free(want);
    return r;
}

static int zone_verify(int fd, uint64_t epoch)
{
    return zone_verify_n(fd, 0, ZONE_BLKS, epoch);
}

/*
 * One I/O command on namespace 1 through passthru, @len bytes at LBA
 * @slba. Returns the NVMe status without DNR (0 is success), or -1 for
 * a transport error. Passthru errors are quiet, so an expected failure
 * prints no block layer I/O error.
 */
static int io_cmd(int fd, uint8_t opc, uint64_t slba, void *data,
                  uint32_t len, int lbasz, uint32_t cdw12, uint32_t cdw13)
{
    struct nvme_passthru_cmd c = { 0 };
    int r;

    c.opcode = opc;
    c.nsid = 1;
    c.addr = (uintptr_t)data;
    c.data_len = len;
    c.cdw10 = (uint32_t)slba;
    c.cdw11 = (uint32_t)(slba >> 32);
    c.cdw12 = (len / lbasz - 1) | cdw12;
    c.cdw13 = cdw13;
    r = ioctl(fd, NVME_IOCTL_IO_CMD, &c);
    return r < 0 ? -1 : (r & 0x7ff);
}

#define NVME_SC_ZONE_FULL   0x1b9   /* SCT 1h, SC B9h: Zone Is Full */

/*
 * Zone 1, written to its capacity: the zone is Full, the bytes read
 * back, and a passthru write into it fails with Zone Is Full. The block
 * layer of Linux 6.10 and later stops a plain write to a Full zone
 * before the device sees it, so passthru is the one way to test the
 * device. The host checks one Full zone.
 */
static int zone_fill(int fd, struct blk_zone *z0)
{
    struct blk_zone z;
    uint32_t flags = 0;
    uint64_t n;
    uint64_t *buf;
    int lbasz = 0;
    int err;

    if (!zone_at(fd, z0->start + z0->len, &z, &flags)) {
        return fail("zone", "report-1");
    }
    if (!(flags & BLK_ZONE_REP_CAPACITY) || !z.capacity ||
        z.capacity % (BLK / 512) || z.wp != z.start) {
        errno = 0;
        return fail("zone", "zone-1-not-empty");
    }
    n = z.capacity * 512 / BLK;
    err = zone_write_n(fd, (off_t)z.start * 512, n, 3);
    if (err) {
        errno = -err;
        return fail("zone", "fill");
    }
    if (!zone_at(fd, z.start, &z, NULL) || z.cond != BLK_ZONE_COND_FULL) {
        errno = 0;
        return fail("zone", "not-full");
    }
    if (zone_verify_n(fd, (off_t)z.start * 512, n, 3)) {
        errno = 0;
        return fail("zone", "fill-bytes-differ");
    }
    if (posix_memalign((void **)&buf, BLK, BLK)) {
        return fail("zone", "alloc");
    }
    if (ioctl(fd, BLKSSZGET, &lbasz) || lbasz <= 0 || BLK % lbasz) {
        free(buf);
        return fail("zone", "lba-size");
    }
    fill(buf, 0, 4);
    err = io_cmd(fd, 0x01, z.start * 512 / lbasz, buf, BLK, lbasz, 0, 0);
    free(buf);
    if (err != NVME_SC_ZONE_FULL) {
        printf("FEMU-CHECK zone write-into-full status=0x%x\n", err);
        errno = 0;
        return fail("zone", "write-into-full");
    }
    printf("FEMU-CHECK zone full cap=%llu\n", (unsigned long long)n);
    return 0;
}

/*
 * Zone 0: sequential writes move the write pointer, the data reads back,
 * a reset moves the pointer back, and a second epoch writes again. Then
 * zone 1 is written to its capacity (zone_fill).
 */
static int check_zone(void)
{
    char buf[32];
    struct blk_zone z;
    struct blk_zone_range range;
    int fd = open("/dev/nvme0n1", O_RDWR | O_DIRECT);
    int err;

    if (fd < 0) {
        return fail("zone", "open");
    }
    if (!read_line("/sys/block/nvme0n1/queue/zoned", buf, sizeof(buf)) ||
        strcmp(buf, "host-managed")) {
        errno = 0;
        return fail("zone", "not-host-managed");
    }
    if (!zone0(fd, &z)) {
        return fail("zone", "report");
    }
    range = (struct blk_zone_range) { .sector = z.start, .nr_sectors = z.len };
    if (ioctl(fd, BLKRESETZONE, &range)) {
        return fail("zone", "reset");
    }
    err = zone_write(fd, 1);
    if (err) {
        errno = -err;
        return fail("zone", "write");
    }
    if (!zone0(fd, &z) || z.wp != z.start + ZONE_BLKS * BLK / 512) {
        errno = 0;
        return fail("zone", "wp-after-write");
    }
    if (zone_verify(fd, 1)) {
        errno = 0;
        return fail("zone", "bytes-differ");
    }
    if (ioctl(fd, BLKRESETZONE, &range)) {
        return fail("zone", "reset");
    }
    if (!zone0(fd, &z) || z.wp != z.start) {
        errno = 0;
        return fail("zone", "wp-after-reset");
    }
    err = zone_write(fd, 2);
    if (err || zone_verify(fd, 2)) {
        errno = -err;
        return fail("zone", "rewrite");
    }
    if (zone_fill(fd, &z)) {
        return 1;
    }
    close(fd);
    return ok("zone");
}

#define FDP_NRUH    4       /* fdp.nruh of the host's femu-subsys */

static int admin(int fd, uint8_t opc, uint32_t nsid, uint32_t cdw10,
                 uint32_t cdw11, void *data, uint32_t len, uint32_t *result)
{
    struct nvme_admin_cmd c = { 0 };
    int r;

    c.opcode = opc;
    c.nsid = nsid;
    c.cdw10 = cdw10;
    c.cdw11 = cdw11;
    c.addr = (uintptr_t)data;
    c.data_len = len;
    r = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &c);
    if (result) {
        *result = c.result;
    }
    return r;
}

/* RUAMW of each placement handle, from I/O Management Receive */
static int ruh_status(int fd, uint64_t ruamw[FDP_NRUH], uint16_t *nruhsd)
{
    struct nvme_passthru_cmd c = { 0 };
    uint8_t st[16 + 32 * FDP_NRUH] __attribute__((aligned(8)));
    int i;

    memset(st, 0, sizeof(st));
    c.opcode = 0x12;
    c.nsid = 1;
    c.cdw10 = 1;                        /* RUH Status */
    c.cdw11 = sizeof(st) / 4 - 1;
    c.addr = (uintptr_t)st;
    c.data_len = sizeof(st);
    if (ioctl(fd, NVME_IOCTL_IO_CMD, &c)) {
        return -1;
    }
    memcpy(nruhsd, st + 14, 2);
    for (i = 0; i < FDP_NRUH; i++) {
        uint16_t pid;

        memcpy(&pid, st + 16 + 32 * i, 2);
        if (pid != i) {
            return -1;
        }
        memcpy(&ruamw[i], st + 16 + 32 * i + 8, 8);
    }
    return 0;
}

/*
 * FDP: Identify says FDP is supported, the FDP feature of the namespace's
 * endurance group is on, RUH Status has FDP_NRUH handles, and a write
 * with directive type 2 (data placement), placement handle 1 uses only
 * the RU of handle 1.
 */
static int check_fdp(void)
{
    uint8_t *id;
    uint32_t ctratt;
    uint32_t res = 0;
    uint16_t endgid;
    uint16_t nruhsd = 0;
    uint64_t before[FDP_NRUH];
    uint64_t after[FDP_NRUH];
    int lbasz = 0;
    int ctl = open("/dev/nvme0", O_RDWR);
    int fd = open("/dev/nvme0n1", O_RDWR);
    int i;

    if (ctl < 0 || fd < 0 || posix_memalign((void **)&id, BLK, BLK)) {
        return fail("fdp", "open");
    }
    if (admin(ctl, 0x06, 0, 1, 0, id, BLK, NULL)) {
        return fail("fdp", "identify-ctrl");
    }
    memcpy(&ctratt, id + 96, 4);
    if (!(ctratt & (1u << 19))) {
        errno = 0;
        return fail("fdp", "no-fdps");
    }
    if (admin(ctl, 0x06, 1, 0, 0, id, BLK, NULL)) {
        return fail("fdp", "identify-ns");
    }
    memcpy(&endgid, id + 102, 2);
    if (!endgid) {
        errno = 0;
        return fail("fdp", "no-endgid");
    }
    if (admin(ctl, 0x0a, 0, 0x1d, endgid, NULL, 0, &res)) {
        return fail("fdp", "get-feature");
    }
    if (!(res & 1)) {
        errno = 0;
        return fail("fdp", "fdpe-off");
    }
    if (ruh_status(fd, before, &nruhsd) || nruhsd != FDP_NRUH) {
        errno = 0;
        return fail("fdp", "ruh-status");
    }
    if (ioctl(fd, BLKSSZGET, &lbasz) || lbasz <= 0 || BLK % lbasz) {
        return fail("fdp", "lba-size");
    }
    memset(id, 0x5a, BLK);
    /* DTYPE 2 (data placement) in CDW12, DSPEC handle 1 in CDW13 */
    if (io_cmd(fd, 0x01, 0, id, BLK, lbasz, 2u << 20, 1u << 16)) {
        errno = 0;
        return fail("fdp", "placed-write");
    }
    memset(id, 0, BLK);
    if (io_cmd(fd, 0x02, 0, id, BLK, lbasz, 0, 0) || id[0] != 0x5a ||
        memcmp(id, id + 1, BLK - 1)) {
        errno = 0;
        return fail("fdp", "placed-bytes-differ");
    }
    nruhsd = 0;
    if (ruh_status(fd, after, &nruhsd) || nruhsd != FDP_NRUH) {
        errno = 0;
        return fail("fdp", "ruh-status-2");
    }
    for (i = 0; i < FDP_NRUH; i++) {
        if ((i == 1) != (after[i] < before[i]) ||
            (i != 1 && after[i] != before[i])) {
            printf("FEMU-CHECK fdp ruamw h%d %llu to %llu\n", i,
                   (unsigned long long)before[i],
                   (unsigned long long)after[i]);
            errno = 0;
            return fail("fdp", "wrong-handle");
        }
    }
    printf("FEMU-CHECK fdp handle-1 ruamw %llu to %llu\n",
           (unsigned long long)before[1], (unsigned long long)after[1]);
    free(id);
    close(fd);
    close(ctl);
    return ok("fdp");
}

/*
 * One KV command. Returns the NVMe status without DNR (0 is success),
 * or -1 for a transport error; @result gets completion Dword 0.
 */
static int kv_cmd(int fd, uint8_t opc, const char *key, void *data,
                  uint32_t len, uint32_t *result)
{
    struct nvme_passthru_cmd c = { 0 };
    uint8_t k[16] = { 0 };
    size_t kl = strlen(key);
    int r;

    memcpy(k, key, kl);
    c.opcode = opc;
    c.nsid = 1;
    memcpy(&c.cdw2, k, 4);
    memcpy(&c.cdw3, k + 4, 4);
    memcpy(&c.cdw14, k + 8, 4);
    memcpy(&c.cdw15, k + 12, 4);
    c.cdw10 = len;
    c.cdw11 = kl;
    c.addr = (uintptr_t)data;
    c.data_len = len;
    r = ioctl(fd, NVME_IOCTL_IO_CMD, &c);
    *result = c.result;
    return r < 0 ? -1 : (r & 0x7ff);
}

/* STORE, RETRIEVE equal bytes, DELETE, then RETRIEVE gives 87h */
static int check_kv(void)
{
    uint64_t val[BLK / 8];
    uint64_t got[BLK / 8];
    int fd = open("/dev/ng0n1", O_RDWR);
    uint32_t res;
    int st;

    if (fd < 0) {
        return fail("kv", "open");
    }
    fill(val, 7, 1);
    if (kv_cmd(fd, 0x01, "femu-key-1", val, sizeof(val), &res)) {
        return fail("kv", "store");
    }
    memset(got, 0, sizeof(got));
    if (kv_cmd(fd, 0x02, "femu-key-1", got, sizeof(got), &res)) {
        return fail("kv", "retrieve");
    }
    /* Dword 0 of RETRIEVE holds the full length of the value */
    if (res != sizeof(val)) {
        errno = 0;
        return fail("kv", "value-length");
    }
    if (memcmp(val, got, sizeof(val))) {
        errno = 0;
        return fail("kv", "bytes-differ");
    }
    if (kv_cmd(fd, 0x10, "femu-key-1", NULL, 0, &res)) {
        return fail("kv", "delete");
    }
    st = kv_cmd(fd, 0x02, "femu-key-1", got, sizeof(got), &res);
    if (st != 0x87) {
        errno = 0;
        return fail("kv", "deleted-key-found");
    }
    close(fd);
    return ok("kv");
}

int main(int argc, char **argv)
{
    bool kv;

    if (argc != 3) {
        errno = EINVAL;
        return fail("args", "usage");
    }
    g_mode = argv[1];
    g_serial = argv[2];
    kv = !strcmp(g_mode, "kv");
    if (kv) {
        return check_kvdev() || check_serial() || check_queues(false) ||
               check_kv();
    }
    if (check_dev() || check_serial() || check_queues(true)) {
        return 1;
    }
    if (!strcmp(g_mode, "zns")) {
        return check_zone();
    }
    if (!strcmp(g_mode, "fdp") && check_fdp()) {
        return 1;
    }
    return check_data();
}
