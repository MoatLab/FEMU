/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Async Event Request probe: arm an AER, cross the temperature threshold, and
 * check the controller reports it and then re-arms once the log is read.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>

struct nvme_admin_cmd {
    uint8_t opcode; uint8_t flags; uint16_t rsvd1; uint32_t nsid;
    uint32_t cdw2; uint32_t cdw3; uint64_t metadata; uint64_t addr;
    uint32_t metadata_len; uint32_t data_len;
    uint32_t cdw10, cdw11, cdw12, cdw13, cdw14, cdw15;
    uint32_t timeout_ms; uint32_t result;
};
#define NVME_IOCTL_ADMIN_CMD _IOWR('N', 0x41, struct nvme_admin_cmd)

#define ADM_SET_FEATURES 0x09
#define ADM_GET_LOG      0x02
#define ADM_AER          0x0c
#define FEAT_TEMP_THRESH 0x04
#define FEAT_AEC         0x0b

static int fd, fails;

static int adm(struct nvme_admin_cmd *c)
{
    return ioctl(fd, NVME_IOCTL_ADMIN_CMD, c);
}

static int set_feature(uint32_t fid, uint32_t val)
{
    struct nvme_admin_cmd c = {0};
    c.opcode = ADM_SET_FEATURES;
    c.cdw10 = fid; c.cdw11 = val; c.timeout_ms = 5000;
    return adm(&c);
}

static int read_smart(int rae)
{
    struct nvme_admin_cmd c = {0};
    uint8_t buf[512];
    c.opcode = ADM_GET_LOG;
    c.nsid = 0xffffffff;
    c.addr = (uint64_t)(uintptr_t)buf;
    c.data_len = sizeof(buf);
    /* numd (zero-based dwords) in 31:16, RAE in bit 15, LID in 7:0 */
    c.cdw10 = 0x02 | ((sizeof(buf) / 4 - 1) << 16) |
              (rae ? (1u << 15) : 0);
    c.timeout_ms = 5000;
    return adm(&c);
}

static void alarm_handler(int sig)
{
    (void)sig;
}

/* arm an AER and wait up to `secs` for it to complete */
static int wait_aer(uint32_t *result, int secs)
{
    struct nvme_admin_cmd c = {0};
    struct sigaction sa = {0};
    int ret;

    c.opcode = ADM_AER;
    c.timeout_ms = 0;
    /* sigaction, not signal: the handler must interrupt rather than restart */
    sa.sa_handler = alarm_handler;
    sigaction(SIGALRM, &sa, NULL);
    alarm(secs);
    ret = adm(&c);
    alarm(0);
    if (ret >= 0) {
        *result = c.result;
    }
    return ret;
}

static void ck(const char *name, int ok, const char *detail)
{
    printf("  %s %-30s %s\n", ok ? "PASS" : "FAIL", name, detail ? detail : "");
    if (!ok) {
        fails++;
    }
}

int main(int argc, char **argv)
{
    const char *dev = argc > 1 ? argv[1] : "/dev/nvme0";
    uint32_t res = 0;
    char buf[96];
    int ret;

    fd = open(dev, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    printf("AERPROBE_BEGIN dev=%s\n", dev);

    /* let temperature warnings raise an event */
    ck("enable SMART temp AEN", set_feature(FEAT_AEC, 0x02) >= 0, NULL);

    /* threshold below the reported temperature -> event */
    ck("set threshold below temp",
       set_feature(FEAT_TEMP_THRESH, 200) >= 0, NULL);

    ret = wait_aer(&res, 5);
    if (ret < 0) {
        ck("AER completes", 0, "timed out / errno");
    } else {
        snprintf(buf, sizeof(buf), "type=%u info=%u log=%u",
                 res & 0x7, (res >> 8) & 0xff, (res >> 16) & 0xff);
        ck("AER completes", 1, buf);
        ck("  type is SMART(1)",      (res & 0x7) == 1, NULL);
        ck("  info is temp thresh(1)", ((res >> 8) & 0xff) == 1, NULL);
        ck("  log page is SMART(2)",   ((res >> 16) & 0xff) == 2, NULL);
    }

    /* reading the log without RAE clears it, so the event can fire again */
    ck("read SMART log (rae=0)", read_smart(0) >= 0, NULL);
    ck("set threshold above temp",
       set_feature(FEAT_TEMP_THRESH, 500) >= 0, NULL);
    ck("re-arm below temp", set_feature(FEAT_TEMP_THRESH, 200) >= 0, NULL);
    ret = wait_aer(&res, 5);
    ck("event fires again", ret >= 0, ret >= 0 ? "re-armed" : "no event");

    /*
     * Last, and the reason this probe wants a freshly booted controller each
     * run: it abandons an Async Event Request. The interrupted ioctl gives up
     * on the host side while the controller still legitimately holds the entry
     * -- NVMe gives a host no way to withdraw one short of an abort or a reset
     * -- so a later event would complete a command the driver has reclaimed.
     * Re-arming the same event must not complete a second time before the log
     * has been read.
     */
    ck("read SMART log (rae=0)", read_smart(0) >= 0, NULL);
    ck("set threshold above temp",
       set_feature(FEAT_TEMP_THRESH, 500) >= 0, NULL);
    ck("re-arm below temp", set_feature(FEAT_TEMP_THRESH, 200) >= 0, NULL);
    ck("first report arrives", wait_aer(&res, 5) >= 0, NULL);
    ck("no repeat before log read", wait_aer(&res, 2) < 0, "still outstanding");

    printf("AERPROBE_DONE fails=%d\n", fails);
    return fails ? 1 : 0;
}
