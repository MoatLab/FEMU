/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Check that a zone taken read only raises the Zone Descriptor Changed notice.
 * The event is queued when it happens, so the writes come first and the Async
 * Event Request is armed afterwards: it is completed from the queue at once.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/ioctl.h>

struct nvme_admin_cmd {
    uint8_t opcode; uint8_t flags; uint16_t rsvd1; uint32_t nsid;
    uint32_t cdw2, cdw3; uint64_t metadata, addr;
    uint32_t metadata_len, data_len;
    uint32_t cdw10, cdw11, cdw12, cdw13, cdw14, cdw15;
    uint32_t timeout_ms, result;
};
#define NVME_IOCTL_ADMIN_CMD _IOWR('N', 0x41, struct nvme_admin_cmd)

int main(int argc, char **argv)
{
    const char *ctrl = argc > 1 ? argv[1] : "/dev/nvme0";
    const char *blk  = argc > 2 ? argv[2] : "/dev/nvme0n1";
    struct nvme_admin_cmd c = {0};
    void *buf;
    int fd, bfd, ret, i;

    fd = open(ctrl, O_RDONLY);
    if (fd < 0) {
        perror("open ctrl");
        return 1;
    }

    /* write until the injection takes a zone read only */
    bfd = open(blk, O_WRONLY | O_DIRECT);
    if (bfd < 0) {
        perror("open blk");
        return 1;
    }
    /* O_DIRECT needs an aligned buffer; a stack array is not one */
    if (posix_memalign(&buf, 4096, 4096)) {
        perror("posix_memalign");
        return 1;
    }
    memset(buf, 0, 4096);
    for (i = 0; i < 256; i++) {
        if (write(bfd, buf, 4096) < 0) {
            break;
        }
    }
    close(bfd);
    printf("  wrote %d blocks, then: %s\n", i, strerror(errno));

    /* the event is already queued, so this is completed immediately */
    c.opcode = 0x0c;
    c.timeout_ms = 5000;
    ret = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &c);
    printf("  AER ret=%d result=0x%08x -> type=%u info=0x%02x log=0x%02x\n",
           ret, c.result, c.result & 0x7, (c.result >> 8) & 0xff,
           (c.result >> 16) & 0xff);

    if (ret >= 0 && (c.result & 0x7) == 2 &&
        ((c.result >> 8) & 0xff) == 0xef && ((c.result >> 16) & 0xff) == 0xbf) {
        printf("ZAEN PASS  (Notice / Zone Descriptor Changed / log BFh)\n");
        return 0;
    }
    printf("ZAEN FAIL\n");
    return 1;
}
