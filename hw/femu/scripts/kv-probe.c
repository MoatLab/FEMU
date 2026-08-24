/*
 * KV passthru probe: drive FEMU's NVMe-KV mode end-to-end via the IO passthru
 * ioctl on the controller node (/dev/nvme0), skipping the block layer (the
 * stock
 * Linux nvme driver does not bring up a CSI=01h namespace). Issues a full KV
 * lifecycle against the spec wire format: Store 01h, Exist 14h, Retrieve 02h
 * (full + short read), Delete 10h, then Retrieve-miss; checks status + data.
 *
 * Key per NVMe-KV: CDW2/CDW3 = key[63:0], CDW14/CDW15 = key[127:64]; Key Length
 * in CDW11[7:0]; Value Size / Host Buffer Size in CDW10; value via DPTR.
 *
 * Build (in guest): gcc -O2 -o kv-probe kv-probe.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>

/*
 * Self-contained passthru struct/ioctl (avoid depending on header version).
 *
 * This uses the 32-bit NVME_IOCTL_IO_CMD rather than the 64-bit variant on
 * purpose. A key-value namespace reports CSI 01h, which the kernel's NVM driver
 * does not attach, so there is no namespace node to send an I/O command to and
 * the controller node is the only way in -- and nvme_dev_ioctl() wires
 * NVME_IOCTL_IO_CMD there but not NVME_IOCTL_IO64_CMD, which returns ENOTTY.
 */
struct nvme_passthru_cmd {
    uint8_t  opcode;
    uint8_t  flags;
    uint16_t rsvd1;
    uint32_t nsid;
    uint32_t cdw2;
    uint32_t cdw3;
    uint64_t metadata;
    uint64_t addr;
    uint32_t metadata_len;
    uint32_t data_len;
    uint32_t cdw10;
    uint32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
    uint32_t timeout_ms;
    uint32_t result;
};
#define NVME_IOCTL_IO_CMD _IOWR('N', 0x43, struct nvme_passthru_cmd)

enum { KV_STORE = 0x01, KV_RETRIEVE = 0x02, KV_LIST = 0x06,
       KV_DELETE = 0x10, KV_EXIST = 0x14 };

static int fd;
static int fails;

/* split a <=16B key into the four command dwords */
static void set_key(struct nvme_passthru_cmd *c, const uint8_t *k, int kl)
{
    uint8_t b[16] = {0};
    /* the wire still carries KL=kl in cdw11 */
    int copy = kl > 16 ? 16 : kl;
    memcpy(b, k, copy);
    c->cdw2  = (uint32_t)b[0] | b[1] << 8 | b[2] << 16 | (uint32_t)b[3] << 24;
    c->cdw3  = (uint32_t)b[4] | b[5] << 8 | b[6] << 16 | (uint32_t)b[7] << 24;
    c->cdw14 = (uint32_t)b[8] | b[9] << 8 | b[10] << 16 | (uint32_t)b[11] << 24;
    c->cdw15 = (uint32_t)b[12] | b[13] << 8 | b[14] << 16 |
               (uint32_t)b[15] << 24;
    c->cdw11 = (c->cdw11 & ~0xffu) | (uint32_t)(kl & 0xff);
}

static int kv_cmd(uint8_t op, const uint8_t *key, int kl, void *buf,
                  uint32_t buflen, uint32_t cdw10, uint32_t opt,
                  uint64_t *result)
{
    struct nvme_passthru_cmd c;
    int ret;
    memset(&c, 0, sizeof(c));
    c.opcode = op;
    c.nsid = 1;
    c.addr = (uint64_t)(uintptr_t)buf;
    c.data_len = buflen;
    c.cdw10 = cdw10;
    c.cdw11 = ((uint32_t)opt << 8);
    set_key(&c, key, kl);
    c.timeout_ms = 5000;
    ret = ioctl(fd, NVME_IOCTL_IO_CMD, &c);
    if (result) {
        *result = c.result;
    }
    return ret;            /* >=0: NVMe status code; <0: ioctl/errno failure */
}

/*
 * Compare against the status code alone. The controller sets Do Not Retry
 * alongside these codes, which is correct -- a missing key does not become
 * present on a retry -- but DNR is a retry hint rather than part of the code's
 * identity, so mask it before comparing.
 */
#define NVME_STATUS_DNR 0x4000

static void check(const char *name, int got, int want_status)
{
    if (got >= 0 && (got & ~NVME_STATUS_DNR) == want_status) {
        printf("  PASS %-22s status=0x%x\n", name, got);
    } else {
        printf("  FAIL %-22s got=0x%x (errno=%d) want=0x%x\n",
               name, got, errno, want_status);
        fails++;
    }
}

int main(int argc, char **argv)
{
    const char *dev = argc > 1 ? argv[1] : "/dev/nvme0";
    uint8_t key[6] = { 'h', 'e', 'l', 'l', 'o', 0 };
    int kl = 5;
    char wbuf[4096], rbuf[4096];
    uint64_t result;
    int st;

    fd = open(dev, O_RDWR);
    if (fd < 0) {
        printf("KVPROBE_OPEN_FAIL %s errno=%d\n", dev, errno);
        return 2;
    }
    memset(wbuf, 0, sizeof(wbuf));
    strcpy(wbuf, "the quick brown fox jumps over the lazy KV-SSD");
    uint32_t vlen = (uint32_t)strlen(wbuf) + 1;

    printf("KVPROBE_BEGIN dev=%s key=%s vlen=%u\n", dev, key, vlen);

    /* 1. Store the pair */
    st = kv_cmd(KV_STORE, key, kl, wbuf, vlen, vlen, 0, &result);
    check("store", st, 0x0);

    /* 2. Exist -> present */
    st = kv_cmd(KV_EXIST, key, kl, NULL, 0, 0, 0, &result);
    check("exist(present)", st, 0x0);

    /* 3. Retrieve full -> data matches, CQE result = full value size */
    memset(rbuf, 0, sizeof(rbuf));
    st = kv_cmd(KV_RETRIEVE, key, kl, rbuf, sizeof(rbuf), sizeof(rbuf), 0,
                &result);
    check("retrieve(full)", st, 0x0);
    if (memcmp(rbuf, wbuf, vlen) != 0) {
        printf("  FAIL retrieve(data)        mismatch\n"); fails++;
    } else {
        printf("  PASS retrieve(data)        '%s'\n", rbuf);
    }
    if (result != vlen) {
        printf("  FAIL retrieve(cqe-size)    got=%llu want=%u\n",
               (unsigned long long)result, vlen); fails++;
    } else {
        printf("  PASS retrieve(cqe-size)    %llu\n",
               (unsigned long long)result);
    }

    /* 4. Short read: HBS=8 -> 8 bytes transferred, CQE reports full size */
    memset(rbuf, 0, sizeof(rbuf));
    st = kv_cmd(KV_RETRIEVE, key, kl, rbuf, 8, 8, 0, &result);
    check("retrieve(short)", st, 0x0);
    if (result == vlen && memcmp(rbuf, wbuf, 8) == 0) {
        printf("  PASS retrieve(short-size)  cqe=%llu, 8B ok\n",
               (unsigned long long)result);
    } else {
        printf("  FAIL retrieve(short-size)  cqe=%llu\n",
               (unsigned long long)result); fails++;
    }

    /* 5. SINKE (store-if-no-key-exists) on existing key -> Key Exists (0x89) */
    st = kv_cmd(KV_STORE, key, kl, wbuf, vlen, vlen, 0x02 /*SINKE*/, &result);
    check("store(SINKE,exists)", st, 0x89);

    /* 6. Delete -> success */
    st = kv_cmd(KV_DELETE, key, kl, NULL, 0, 0, 0, &result);
    check("delete", st, 0x0);

    /* 7. Retrieve after delete -> Key Does Not Exist (0x87) */
    st = kv_cmd(KV_RETRIEVE, key, kl, rbuf, sizeof(rbuf), sizeof(rbuf), 0,
                &result);
    check("retrieve(deleted)", st, 0x87);

    /* 8. SIKE (store-if-key-exists) on absent key -> Key Not Exist (0x87) */
    st = kv_cmd(KV_STORE, key, kl, wbuf, vlen, vlen, 0x01 /*SIKE*/, &result);
    check("store(SIKE,absent)", st, 0x87);

    /* 9. Over-long key (>16) -> Invalid Field (0x2) */
    {
        uint8_t big[17] = {0};
        memset(big, 'x', 17);
        st = kv_cmd(KV_STORE, big, 17, wbuf, vlen, vlen, 0, &result);
        check("store(key>16)", st, 0x2);
    }

    printf("KVPROBE_DONE fails=%d\n", fails);
    close(fd);
    return fails ? 1 : 0;
}
