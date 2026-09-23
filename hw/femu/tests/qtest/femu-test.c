/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QTest testcase for the FEMU SSD emulator
 *
 * Drives the controller the way a host without the shadow doorbell buffer
 * does: queues are created through admin commands, commands are submitted by
 * writing the doorbell registers, and completions are found by polling the
 * completion queue in guest memory. No interrupt is enabled, so the test
 * depends on nothing but the memory-mapped register interface.
 */

#include "qemu/osdep.h"
#include "qemu/module.h"
#include "libqtest.h"
#include "libqos/qgraph.h"
#include "libqos/pci.h"
#include "libqos/libqos-malloc.h"
#include "block/nvme.h"
#include "standard-headers/linux/pci_regs.h"

#define FEMU_QSIZE          16
#define FEMU_DATA_SIZE      4096
#define FEMU_POLL_LIMIT_MS  10000
/* the femu device's queues property default, which these tests do not set */
#define FEMU_DEFAULT_IO_QUEUES  8

/* not in QEMU's own block/nvme.h */
#define FEMU_CNS_CS_NS_FMT  0x0a    /* command-set NS for a format index */
#define FEMU_CSI_KV         0x01    /* key-value command set */
#define FEMU_ZONE_ACTION_RESET  0x04
#define FEMU_DSM_AD             0x04    /* Dataset Management: deallocate */
#define FEMU_OC20_IDENTIFY      0xe2    /* Open-Channel 2.0 geometry */
#define FEMU_OC20_VECT_WRITE    0x91
#define FEMU_OC20_VECT_READ     0x92
#define FEMU_OC20_VECT_ERASE    0x90
/* sectors the write cache holds back before a read can see them */
#define FEMU_OC20_MW_CUNITS     24
#define FEMU_KV_CMD_STORE       0x01
#define FEMU_CMD_IO_MGMT_SEND   0x1d
#define FEMU_IOMS_RUH_UPDATE    0x01
#define FEMU_CMD_IO_MGMT_RECV   0x12
#define FEMU_IOMR_RUH_STATUS    0x01
#define FEMU_FDP_EVT_RU_NOT_FULLY_WRITTEN 0x00
#define FEMU_KV_CMD_RETRIEVE    0x02
#define FEMU_KV_CMD_EXIST       0x14
#define FEMU_KV_CMD_LIST        0x06
#define FEMU_KV_CMD_DELETE      0x10
#define FEMU_CNS_CS_CTRL    0x06    /* command-set controller identify */
#define FEMU_CSI_ZONED      0x02    /* zoned namespace command set */
#define FEMU_CSI_KV         0x01    /* key value command set */
#define FEMU_CNS_IO_CMD_SET 0x1c    /* the command sets the controller has */
#define FEMU_LOG_CMD_EFFECTS 0x05
#define FEMU_CC_CSS_CSI     0x06    /* CC.CSS: a command set is selected */
#define FEMU_FEAT_CMD_SET_PROFILE       0x19
#define FEMU_IOCS_COMBINATION_REJECTED  0x12b
#define FEMU_CQ_IEN         0x02    /* Create CQ: interrupts enabled */

typedef struct QFemu QFemu;

struct QFemu {
    QOSGraphObject obj;
    QPCIDevice dev;
};

/* one submission/completion pair and where its cursors are */
typedef struct FemuQueue {
    uint16_t qid;
    uint64_t sq_addr;
    uint64_t cq_addr;
    uint16_t sq_tail;
    uint16_t cq_head;
    uint8_t phase;
} FemuQueue;

typedef struct FemuCtrlState {
    QPCIDevice *pdev;
    QPCIBar bar;
    QGuestAllocator *alloc;
    uint32_t db_stride;
    uint16_t cid;
    FemuQueue admin;
    FemuQueue io;
    /* bytes per logical block of namespace 1, as last formatted */
    uint32_t lba_size;
    /* shadow doorbell pages, once Doorbell Buffer Config has been issued */
    uint64_t dbs_addr;
    /* admin completion queue entries when not FEMU_QSIZE */
    uint16_t acq_entries;
} FemuCtrlState;

static void *femu_get_driver(void *obj, const char *interface)
{
    QFemu *femu = obj;

    if (!g_strcmp0(interface, "pci-device")) {
        return &femu->dev;
    }

    fprintf(stderr, "%s not present in femu\n", interface);
    g_assert_not_reached();
}

static void *femu_create(void *pci_bus, QGuestAllocator *alloc, void *addr)
{
    QFemu *femu = g_new0(QFemu, 1);
    QPCIBus *bus = pci_bus;

    qpci_device_init(&femu->dev, bus, addr);
    femu->obj.get_driver = femu_get_driver;

    return &femu->obj;
}

static uint64_t femu_sq_doorbell(FemuCtrlState *c, uint16_t qid)
{
    return 0x1000 + (2 * qid) * (4 << c->db_stride);
}

static uint64_t femu_cq_doorbell(FemuCtrlState *c, uint16_t qid)
{
    return 0x1000 + (2 * qid + 1) * (4 << c->db_stride);
}

static void femu_queue_init(FemuCtrlState *c, FemuQueue *q, uint16_t qid)
{
    q->qid = qid;
    q->sq_addr = guest_alloc(c->alloc, FEMU_QSIZE * sizeof(NvmeCmd));
    q->cq_addr = guest_alloc(c->alloc, FEMU_QSIZE * sizeof(NvmeCqe));
    q->sq_tail = 0;
    q->cq_head = 0;
    q->phase = 1;
    qtest_memset(c->pdev->bus->qts, q->cq_addr, 0,
                 FEMU_QSIZE * sizeof(NvmeCqe));
}

static void femu_queue_free(FemuCtrlState *c, FemuQueue *q)
{
    guest_free(c->alloc, q->sq_addr);
    guest_free(c->alloc, q->cq_addr);
}

/* queue the command and ring the controller, by register or by shadow */
static void femu_submit(FemuCtrlState *c, FemuQueue *q, NvmeCmd *cmd)
{
    cmd->cid = cpu_to_le16(c->cid++);
    qtest_memwrite(c->pdev->bus->qts,
                   q->sq_addr + q->sq_tail * sizeof(NvmeCmd), cmd,
                   sizeof(*cmd));
    q->sq_tail = (q->sq_tail + 1) % FEMU_QSIZE;

    if (c->dbs_addr && q->qid) {
        uint32_t tail = q->sq_tail;

        qtest_memwrite(c->pdev->bus->qts,
                       c->dbs_addr + femu_sq_doorbell(c, q->qid) - 0x1000,
                       &tail, sizeof(tail));
        return;
    }
    qpci_io_writel(c->pdev, c->bar, femu_sq_doorbell(c, q->qid), q->sq_tail);
}

/* status codes come back with the phase bit dropped; this strips DNR too */
#define FEMU_SC(status)     ((status) & 0x7ff)

/*
 * Wait for the next completion and return its status with the phase bit
 * removed; hand back the identifier and dword 0 when asked.
 */
static uint16_t femu_complete(FemuCtrlState *c, FemuQueue *q, uint16_t *cid,
                              uint32_t *result)
{
    uint64_t slot = q->cq_addr + q->cq_head * sizeof(NvmeCqe);
    NvmeCqe cqe, again;
    int waited = 0;

    /*
     * The controller writes the whole entry, phase bit included, with no
     * ordering between the fields, so seeing the phase flip does not mean the
     * rest of the entry has landed. Reading it once can return a new phase
     * beside a stale identifier -- which happens on a machine with few cores,
     * where the poller and this thread interleave more finely.
     *
     * Wait for the phase, then require two consecutive reads to agree before
     * believing the contents.
     */
    for (;;) {
        qtest_memread(c->pdev->bus->qts, slot, &cqe, sizeof(cqe));
        if ((le16_to_cpu(cqe.status) & 1) == q->phase) {
            qtest_memread(c->pdev->bus->qts, slot, &again, sizeof(again));
            if (memcmp(&cqe, &again, sizeof(cqe)) == 0) {
                break;
            }
        }
        g_assert_cmpint(waited, <, FEMU_POLL_LIMIT_MS);
        g_usleep(1000);
        waited++;
    }

    if (cid) {
        *cid = le16_to_cpu(cqe.cid);
    }
    if (result) {
        *result = le32_to_cpu(cqe.result);
    }
    q->cq_head = (q->cq_head + 1) % FEMU_QSIZE;
    if (q->cq_head == 0) {
        q->phase ^= 1;
    }

    if (c->dbs_addr && q->qid) {
        uint32_t head = q->cq_head;

        qtest_memwrite(c->pdev->bus->qts,
                       c->dbs_addr + femu_cq_doorbell(c, q->qid) - 0x1000,
                       &head, sizeof(head));
    } else {
        qpci_io_writel(c->pdev, c->bar, femu_cq_doorbell(c, q->qid),
                       q->cq_head);
    }

    return le16_to_cpu(cqe.status) >> 1;
}

static uint16_t femu_admin_result(FemuCtrlState *c, NvmeCmd *cmd,
                                  uint32_t *result)
{
    uint16_t want = c->cid;
    uint16_t got;
    uint16_t status;

    femu_submit(c, &c->admin, cmd);
    status = femu_complete(c, &c->admin, &got, result);
    g_assert_cmpint(got, ==, want);

    return status;
}

static uint16_t femu_admin(FemuCtrlState *c, NvmeCmd *cmd)
{
    return femu_admin_result(c, cmd, NULL);
}

static void femu_enable_cc(FemuCtrlState *c, QPCIDevice *pdev,
                           QGuestAllocator *alloc, uint32_t cc)
{
    uint64_t cap;
    uint32_t csts;
    uint32_t acq;
    int waited = 0;

    c->pdev = pdev;
    c->alloc = alloc;
    qpci_device_enable(pdev);
    c->bar = qpci_iomap(pdev, 0, NULL);

    cap = qpci_io_readq(pdev, c->bar, 0x0);
    c->db_stride = (cap >> 32) & 0xf;
    c->lba_size = 512;

    acq = c->acq_entries ? c->acq_entries : FEMU_QSIZE;
    qpci_io_writel(pdev, c->bar, 0x24, ((acq - 1) << 16) | (FEMU_QSIZE - 1));
    qpci_io_writeq(pdev, c->bar, 0x28, c->admin.sq_addr);
    qpci_io_writeq(pdev, c->bar, 0x30, c->admin.cq_addr);

    qpci_io_writel(pdev, c->bar, 0x14, cc);
    for (;;) {
        csts = qpci_io_readl(pdev, c->bar, 0x1c);
        if (csts & NVME_CSTS_READY) {
            break;
        }
        g_assert_cmpint(csts & NVME_CSTS_FAILED, ==, 0);
        g_assert_cmpint(waited, <, FEMU_POLL_LIMIT_MS);
        g_usleep(1000);
        waited++;
    }
}

/* enable, NVM command set, 4 KiB pages, 64-byte SQEs, 16-byte CQEs */
static void femu_enable(FemuCtrlState *c, QPCIDevice *pdev,
                        QGuestAllocator *alloc)
{
    c->pdev = pdev;
    c->alloc = alloc;
    femu_queue_init(c, &c->admin, 0);
    femu_enable_cc(c, pdev, alloc, (6 << 16) | (4 << 20) | 1);
}

static void femu_disable(FemuCtrlState *c)
{
    qpci_io_writel(c->pdev, c->bar, 0x14, 0);
    femu_queue_free(c, &c->admin);
    qpci_iounmap(c->pdev, c->bar);
}

/* one I/O queue pair with interrupts left off: completions are polled */
static void femu_create_io_queues(FemuCtrlState *c)
{
    NvmeCmd cmd;

    femu_queue_init(c, &c->io, 1);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_CREATE_CQ;
    cmd.dptr.prp1 = cpu_to_le64(c->io.cq_addr);
    cmd.cdw10 = cpu_to_le32(((FEMU_QSIZE - 1) << 16) | c->io.qid);
    cmd.cdw11 = cpu_to_le32(NVME_CQ_PC);
    g_assert_cmpint(femu_admin(c, &cmd), ==, NVME_SUCCESS);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_CREATE_SQ;
    cmd.dptr.prp1 = cpu_to_le64(c->io.sq_addr);
    cmd.cdw10 = cpu_to_le32(((FEMU_QSIZE - 1) << 16) | c->io.qid);
    cmd.cdw11 = cpu_to_le32((c->io.qid << 16) | NVME_SQ_PC);
    g_assert_cmpint(femu_admin(c, &cmd), ==, NVME_SUCCESS);
}

static uint16_t femu_rw(FemuCtrlState *c, uint8_t opcode, uint64_t slba,
                        uint64_t data)
{
    NvmeRwCmd rw;
    NvmeCmd *cmd = (NvmeCmd *)&rw;
    uint16_t want = c->cid;
    uint16_t got;
    uint16_t status;

    memset(&rw, 0, sizeof(rw));
    rw.opcode = opcode;
    rw.nsid = cpu_to_le32(1);
    rw.dptr.prp1 = cpu_to_le64(data);
    rw.slba = cpu_to_le64(slba);
    rw.nlb = cpu_to_le16(FEMU_DATA_SIZE / c->lba_size - 1);

    femu_submit(c, &c->io, cmd);
    status = femu_complete(c, &c->io, &got, NULL);
    g_assert_cmpint(got, ==, want);

    return status;
}

/* write a pattern, read it back, and expect the same bytes */
static void femu_round_trip(FemuCtrlState *c, uint8_t seed)
{
    uint64_t data = guest_alloc(c->alloc, FEMU_DATA_SIZE);
    uint8_t *wbuf = g_malloc(FEMU_DATA_SIZE);
    uint8_t *rbuf = g_malloc0(FEMU_DATA_SIZE);
    int i;

    for (i = 0; i < FEMU_DATA_SIZE; i++) {
        wbuf[i] = (uint8_t)(seed + i * 7);
    }
    qtest_memwrite(c->pdev->bus->qts, data, wbuf, FEMU_DATA_SIZE);
    g_assert_cmpint(femu_rw(c, NVME_CMD_WRITE, 8 * seed, data), ==,
                    NVME_SUCCESS);

    qtest_memset(c->pdev->bus->qts, data, 0, FEMU_DATA_SIZE);
    g_assert_cmpint(femu_rw(c, NVME_CMD_READ, 8 * seed, data), ==,
                    NVME_SUCCESS);
    qtest_memread(c->pdev->bus->qts, data, rbuf, FEMU_DATA_SIZE);
    g_assert_cmpint(memcmp(wbuf, rbuf, FEMU_DATA_SIZE), ==, 0);

    g_free(rbuf);
    g_free(wbuf);
    guest_free(c->alloc, data);
}

/* Writes recover only the invalid blocks they replace (NVM 1.2, 3.3.7). */
static void femu_uncorrectable_recovery(FemuCtrlState *c)
{
    static const uint8_t repair[] = {
        NVME_CMD_WRITE, NVME_CMD_WRITE_ZEROES,
    };
    QTestState *qts = c->pdev->bus->qts;
    uint64_t buf = guest_alloc(c->alloc, FEMU_DATA_SIZE);
    uint64_t stride = FEMU_DATA_SIZE / c->lba_size;
    uint8_t actual[FEMU_DATA_SIZE];
    NvmeCmd cmd = { 0 };
    unsigned int i;
    unsigned int j;

    for (i = 0; i < G_N_ELEMENTS(repair); i++) {
        qtest_memset(qts, buf, 0x5a, FEMU_DATA_SIZE);
        for (j = 0; j < 3; j++) {
            g_assert_cmpint(FEMU_SC(femu_rw(c, NVME_CMD_WRITE_UNCOR,
                                            j * stride, 0)), ==, NVME_SUCCESS);
        }
        g_assert_cmpint(FEMU_SC(femu_rw(c, NVME_CMD_READ, stride, buf)),
                        ==, NVME_UNRECOVERED_READ);
        g_assert_cmpint(FEMU_SC(femu_rw(c, repair[i], stride, buf)),
                        ==, NVME_SUCCESS);
        qtest_memset(qts, buf, 0xff, FEMU_DATA_SIZE);
        g_assert_cmpint(FEMU_SC(femu_rw(c, NVME_CMD_READ, stride, buf)),
                        ==, NVME_SUCCESS);
        qtest_memread(qts, buf, actual, sizeof(actual));
        for (j = 0; j < sizeof(actual); j++) {
            g_assert_cmpint(actual[j], ==,
                            repair[i] == NVME_CMD_WRITE ? 0x5a : 0);
        }
        g_assert_cmpint(FEMU_SC(femu_rw(c, NVME_CMD_COMPARE, stride, buf)),
                        ==, NVME_SUCCESS);
        g_assert_cmpint(FEMU_SC(femu_rw(c, NVME_CMD_READ, 0, buf)),
                        ==, NVME_UNRECOVERED_READ);
        g_assert_cmpint(FEMU_SC(femu_rw(c, NVME_CMD_READ, 2 * stride, buf)),
                        ==, NVME_UNRECOVERED_READ);
    }

    /* An invalid block is allocated, so Compare must not report DULB. */
    cmd.opcode = NVME_ADM_CMD_SET_FEATURES;
    cmd.nsid = cpu_to_le32(1);
    cmd.cdw10 = cpu_to_le32(NVME_ERROR_RECOVERY);
    cmd.cdw11 = cpu_to_le32(1 << 16);
    g_assert_cmpint(FEMU_SC(femu_admin(c, &cmd)), ==, NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_rw(c, NVME_CMD_WRITE_UNCOR,
                                    4 * stride, 0)), ==, NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_rw(c, NVME_CMD_COMPARE, 4 * stride, buf)),
                    ==, NVME_UNRECOVERED_READ);
    cmd.cdw11 = 0;
    g_assert_cmpint(FEMU_SC(femu_admin(c, &cmd)), ==, NVME_SUCCESS);
    guest_free(c->alloc, buf);
}

/*
 * A host that never issues Doorbell Buffer Config must still get its I/O
 * served. The controller used to start its data path only from that command.
 */
static void femu_test_io_by_doorbell(void *obj, void *data,
                                     QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_round_trip(&c, 1);
    femu_round_trip(&c, 2);
    femu_uncorrectable_recovery(&c);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * The shadow doorbell path must keep working once the host configures it:
 * after Doorbell Buffer Config the queue is driven from the shadow page and
 * the register writes are ignored.
 */
/*
 * Identify for a command set the controller does not implement must be refused.
 * The format-index query names a format rather than a namespace, and answering
 * it from namespace zero handed the key-value code whatever object the mode
 * this controller really runs keeps in the same slot.
 */
static void femu_test_identify_other_csi(void *obj, void *data,
                                         QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd;
    uint64_t buf;

    femu_enable(&c, &femu->dev, alloc);
    buf = guest_alloc(alloc, 4096);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_IDENTIFY;
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(FEMU_CNS_CS_NS_FMT);
    cmd.cdw11 = cpu_to_le32(FEMU_CSI_KV << 24);
    g_assert_cmpint(femu_admin(&c, &cmd), !=, NVME_SUCCESS);

    /* the controller is still answering, so it did not take the bad path */
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_IDENTIFY;
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(NVME_ID_CNS_CTRL);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);

    guest_free(alloc, buf);
    femu_disable(&c);
}

/*
 * An admin queue the controller cannot map whole must stop it coming ready. The
 * host chooses both addresses and both sizes, so a completion queue that failed
 * left the submission queue asserting on it and took the process down.
 */
static void femu_test_admin_queue_refused(void *obj, void *data,
                                          QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QPCIDevice *pdev = &femu->dev;
    QPCIBar bar;
    uint64_t sq_addr;
    uint32_t csts;
    int waited = 0;

    qpci_device_enable(pdev);
    bar = qpci_iomap(pdev, 0, NULL);

    sq_addr = guest_alloc(alloc, 4096);
    qtest_memset(femu->dev.bus->qts, sq_addr, 0, 4096);

    /*
     * A completion queue of four thousand entries is sixty-four kilobytes, and
     * nothing is assigned at this address, so the whole ring cannot be mapped.
     */
    qpci_io_writel(pdev, bar, 0x24, (4095 << 16) | (FEMU_QSIZE - 1));
    qpci_io_writeq(pdev, bar, 0x28, sq_addr);
    qpci_io_writeq(pdev, bar, 0x30, 0xffffffff00000000ULL);
    qpci_io_writel(pdev, bar, 0x14, (6 << 16) | (4 << 20) | 1);

    for (;;) {
        csts = qpci_io_readl(pdev, bar, 0x1c);
        if (csts & NVME_CSTS_FAILED) {
            break;
        }
        g_assert_cmpint(csts & NVME_CSTS_READY, ==, 0);
        g_assert_cmpint(waited, <, FEMU_POLL_LIMIT_MS);
        qtest_clock_step(femu->dev.bus->qts, 1000000);
        waited++;
    }

    /*
     * Leave the controller as it was found. A disable is a reset, so the fatal
     * status goes with it and the next test on this machine can enable -- the
     * tests share one QEMU when they share device options, which is how this
     * test left the one after it unable to start.
     */
    qpci_io_writel(pdev, bar, 0x14, 0);
    csts = qpci_io_readl(pdev, bar, 0x1c);
    g_assert_cmpint(csts & NVME_CSTS_FAILED, ==, 0);

    guest_free(alloc, sq_addr);
}

/*
 * A non-contiguous queue divides by the entries per page, and a 64 KiB page
 * truncated to zero in a 16-bit field.
 */
#define FEMU_64K    0x10000ULL

static uint64_t femu_alloc_64k(QGuestAllocator *alloc, uint64_t *raw)
{
    *raw = guest_alloc(alloc, 4 * FEMU_64K);
    return (*raw + FEMU_64K - 1) & ~(FEMU_64K - 1);
}

static void femu_test_discontig_64k_pages(void *obj, void *data,
                                          QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd;
    uint64_t raw[5];
    uint64_t list, cq_page;
    uint64_t entry;
    uint16_t want, got;

    /* every queue page sits on a 64 KiB boundary; the helpers align to 4 KiB */
    c.pdev = &femu->dev;
    c.alloc = alloc;
    c.admin.qid = 0;
    c.admin.sq_addr = femu_alloc_64k(alloc, &raw[0]);
    c.admin.cq_addr = femu_alloc_64k(alloc, &raw[1]);
    c.admin.phase = 1;
    qtest_memset(qts, c.admin.cq_addr, 0, FEMU_QSIZE * sizeof(NvmeCqe));

    /* 64-byte SQEs, 16-byte CQEs, memory page size 2^(12 + 4) */
    femu_enable_cc(&c, &femu->dev, alloc, (6 << 16) | (4 << 20) | (4 << 7) | 1);

    /* a one-page list naming the page the completion queue lives on */
    list = femu_alloc_64k(alloc, &raw[2]);
    cq_page = femu_alloc_64k(alloc, &raw[3]);
    qtest_memset(qts, list, 0, 64);
    qtest_memset(qts, cq_page, 0, FEMU_QSIZE * sizeof(NvmeCqe));
    entry = cpu_to_le64(cq_page);
    qtest_memwrite(qts, list, &entry, sizeof(entry));

    c.io.qid = 1;
    c.io.sq_addr = femu_alloc_64k(alloc, &raw[4]);
    c.io.cq_addr = cq_page;
    c.io.phase = 1;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_CREATE_CQ;
    cmd.dptr.prp1 = cpu_to_le64(list);
    cmd.cdw10 = cpu_to_le32(((FEMU_QSIZE - 1) << 16) | c.io.qid);
    cmd.cdw11 = 0;                          /* not physically contiguous */
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_CREATE_SQ;
    cmd.dptr.prp1 = cpu_to_le64(c.io.sq_addr);
    cmd.cdw10 = cpu_to_le32(((FEMU_QSIZE - 1) << 16) | c.io.qid);
    cmd.cdw11 = cpu_to_le32((c.io.qid << 16) | NVME_SQ_PC);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);

    /* the completion lands on the listed page, entry zero */
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_CMD_FLUSH;
    cmd.nsid = cpu_to_le32(1);
    want = c.cid;
    femu_submit(&c, &c.io, &cmd);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(got, ==, want);

    qpci_io_writel(c.pdev, c.bar, 0x14, 0);
    qpci_iounmap(c.pdev, c.bar);
    for (int i = 0; i < 5; i++) {
        guest_free(alloc, raw[i]);
    }
}

/*
 * A queue the controller cannot map must be refused. The ring is addressed
 * through a host pointer the mapping returns, so accepting the command leaves
 * the poller writing completions through whatever came back -- a null pointer
 * for an address that is not memory at all, and a short mapping for one that
 * is not all memory.
 */
static void femu_test_queue_mapping(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd;

    femu_enable(&c, &femu->dev, alloc);
    femu_queue_init(&c, &c.io, 1);

    /*
     * Nothing is assigned at this address, so the whole ring cannot be mapped:
     * a thousand entries of sixteen bytes is past what a bounce buffer holds.
     * Asking for the entry count instead of the byte length made a ring this
     * size fit in its own entry count of bytes and the command was accepted.
     */
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_CREATE_CQ;
    cmd.dptr.prp1 = cpu_to_le64(0xffffffff00000000ULL);
    cmd.cdw10 = cpu_to_le32((1023 << 16) | c.io.qid);
    cmd.cdw11 = cpu_to_le32(NVME_CQ_PC);
    g_assert_cmpint(femu_admin(&c, &cmd), !=, NVME_SUCCESS);

    /* the real one still works, so the refusal above left nothing behind */
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_CREATE_CQ;
    cmd.dptr.prp1 = cpu_to_le64(c.io.cq_addr);
    cmd.cdw10 = cpu_to_le32(((FEMU_QSIZE - 1) << 16) | c.io.qid);
    cmd.cdw11 = cpu_to_le32(NVME_CQ_PC);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_CREATE_SQ;
    cmd.dptr.prp1 = cpu_to_le64(0xffffffff00000000ULL);
    cmd.cdw10 = cpu_to_le32((1023 << 16) | c.io.qid);
    cmd.cdw11 = cpu_to_le32((c.io.qid << 16) | NVME_SQ_PC);
    g_assert_cmpint(femu_admin(&c, &cmd), !=, NVME_SUCCESS);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_CREATE_SQ;
    cmd.dptr.prp1 = cpu_to_le64(c.io.sq_addr);
    cmd.cdw10 = cpu_to_le32(((FEMU_QSIZE - 1) << 16) | c.io.qid);
    cmd.cdw11 = cpu_to_le32((c.io.qid << 16) | NVME_SQ_PC);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);

    femu_round_trip(&c, 1);

    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static void femu_test_io_by_shadow_doorbell(void *obj, void *data,
                                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd;
    uint64_t eis_addr;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_round_trip(&c, 3);

    c.dbs_addr = guest_alloc(alloc, 4096);
    eis_addr = guest_alloc(alloc, 4096);
    qtest_memset(c.pdev->bus->qts, c.dbs_addr, 0, 4096);
    qtest_memset(c.pdev->bus->qts, eis_addr, 0, 4096);

    /*
     * The buffer handed over is zeroed while the queue has already advanced
     * through the registers, so the controller has to publish the current
     * cursors into it. If it does not, it reads a stale zero and replays
     * every command submitted so far.
     */
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_DBBUF_CONFIG;
    cmd.dptr.prp1 = cpu_to_le64(c.dbs_addr);
    cmd.dptr.prp2 = cpu_to_le64(eis_addr);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);

    /* a second configuration is refused */
    g_assert_cmpint(femu_admin(&c, &cmd), !=, NVME_SUCCESS);

    /* the controller published the cursors rather than leaving them zero */
    {
        uint32_t tail = 0, head = 0;

        qtest_memread(c.pdev->bus->qts,
                      c.dbs_addr + femu_sq_doorbell(&c, 1) - 0x1000,
                      &tail, sizeof(tail));
        qtest_memread(c.pdev->bus->qts,
                      c.dbs_addr + femu_cq_doorbell(&c, 1) - 0x1000,
                      &head, sizeof(head));
        g_assert_cmpint(tail, ==, c.io.sq_tail);
        g_assert_cmpint(head, ==, c.io.cq_head);
    }

    /* an address the controller cannot map is refused, not accepted */
    {
        NvmeCmd bad;

        memset(&bad, 0, sizeof(bad));
        bad.opcode = NVME_ADM_CMD_DBBUF_CONFIG;
        bad.dptr.prp1 = cpu_to_le64(0xffffffff00000000ULL);
        bad.dptr.prp2 = cpu_to_le64(0xffffffff00001000ULL);
        g_assert_cmpint(femu_admin(&c, &bad), !=, NVME_SUCCESS);
    }

    /*
     * A doorbell is a position in the ring. The register path drops a write at
     * or past the queue size; the shadow doorbell is guest memory, so the same
     * value can be put there directly. Abort walks the ring towards the tail
     * one slot at a time, so a tail outside it is never reached and the walk
     * runs on the thread holding the big lock: the command has to come back.
     */
    {
        uint32_t bogus = 0xffffffffU;
        uint32_t good;
        NvmeCmd abort;

        good = c.io.sq_tail;
        qtest_memwrite(c.pdev->bus->qts,
                       c.dbs_addr + femu_sq_doorbell(&c, 1) - 0x1000,
                       &bogus, sizeof(bogus));

        memset(&abort, 0, sizeof(abort));
        abort.opcode = NVME_ADM_CMD_ABORT;
        abort.cdw10 = cpu_to_le32(1);
        g_assert_cmpint(femu_admin(&c, &abort), ==, NVME_SUCCESS);

        qtest_memwrite(c.pdev->bus->qts,
                       c.dbs_addr + femu_sq_doorbell(&c, 1) - 0x1000,
                       &good, sizeof(good));
    }

    femu_round_trip(&c, 4);
    femu_round_trip(&c, 5);

    guest_free(alloc, eis_addr);
    guest_free(alloc, c.dbs_addr);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * The shadow doorbell buffers are one memory page each, holding two entries per
 * queue. A controller with more queues than a page holds cannot use them, and
 * the seeding loop wrote past the mapping instead of saying so.
 */
static void femu_test_dbbuf_too_many_queues(void *obj, void *data,
                                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd;
    uint64_t dbs, eis;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    dbs = guest_alloc(alloc, 4096);
    eis = guest_alloc(alloc, 4096);
    qtest_memset(femu->dev.bus->qts, dbs, 0, 4096);
    qtest_memset(femu->dev.bus->qts, eis, 0, 4096);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_DBBUF_CONFIG;
    cmd.dptr.prp1 = cpu_to_le64(dbs);
    cmd.dptr.prp2 = cpu_to_le64(eis);
    g_assert_cmpint(femu_admin(&c, &cmd), !=, NVME_SUCCESS);

    /* the registers still drive the queue */
    femu_round_trip(&c, 1);

    guest_free(alloc, eis);
    guest_free(alloc, dbs);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * Creating and deleting a completion queue repeatedly must not cost the host
 * anything that it keeps. Each create took an interrupt route and a file
 * descriptor and only the controller shutdown gave them back, and the delete
 * freed the queue while the pollers could still reach it.
 */
static void femu_test_cq_churn(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_round_trip(&c, 1);

    for (i = 0; i < 64; i++) {
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = NVME_ADM_CMD_CREATE_CQ;
        cmd.dptr.prp1 = cpu_to_le64(c.io.cq_addr);
        cmd.cdw10 = cpu_to_le32(((FEMU_QSIZE - 1) << 16) | 2);
        cmd.cdw11 = cpu_to_le32(NVME_CQ_PC | FEMU_CQ_IEN);
        g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);

        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = NVME_ADM_CMD_DELETE_CQ;
        cmd.cdw10 = cpu_to_le32(2);
        g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    }

    /* the queue that was there all along still works */
    femu_round_trip(&c, 2);

    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * A data buffer inside the controller memory buffer is described by an iovec
 * rather than a scatter list, and the media path takes the scatter list, so the
 * transfer moves nothing. The assertion that the two agreed aborted the process
 * on a guest command; it has to be refused.
 */
static void femu_test_cmb_data_buffer(void *obj, void *data,
                                      QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    QPCIBar cmb;
    uint64_t buf;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    cmb = qpci_iomap(&femu->dev, 2, NULL);

    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 0, cmb.addr)), !=,
                    NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_READ, 0, cmb.addr)), !=,
                    NVME_SUCCESS);

    /* an ordinary buffer on the same controller still works */
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    qtest_memset(femu->dev.bus->qts, buf, 0x33, FEMU_DATA_SIZE);
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 0, buf)), ==,
                    NVME_SUCCESS);

    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * The zone append size limit is derived when the controller starts, by the hook
 * belonging to the mode that needs it. Only the controller's own hook was ever
 * called, so on a controller whose mode is something else the limit stayed at
 * zero -- which Identify reports as no limit at all while the write path
 * rejects anything over one host page.
 */
static void femu_test_zoned_append_limit(void *obj, void *data,
                                         QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd;
    uint64_t buf;
    uint8_t page[64];

    femu_enable(&c, &femu->dev, alloc);
    buf = guest_alloc(alloc, 4096);
    qtest_memset(femu->dev.bus->qts, buf, 0xff, 4096);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_IDENTIFY;
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(FEMU_CNS_CS_CTRL);
    cmd.cdw11 = cpu_to_le32(FEMU_CSI_ZONED << 24);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    qtest_memread(femu->dev.bus->qts, buf, page, sizeof(page));
    g_assert_cmpint(page[0], >, 0);

    guest_free(alloc, buf);
    femu_disable(&c);
}

/*
 * The zone size lives in the entry for the format index the namespace is
 * formatted to. It was written into the first entry whatever the index, so a
 * namespace formatted to any other index reported a zone size of zero, which a
 * host reads as a namespace it cannot use.
 */
static void femu_test_zoned_format_index(void *obj, void *data,
                                         QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd;
    uint64_t buf, zsze = 0;

    femu_enable(&c, &femu->dev, alloc);
    buf = guest_alloc(alloc, 4096);
    qtest_memset(femu->dev.bus->qts, buf, 0, 4096);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_IDENTIFY;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(NVME_ID_CNS_CS_NS);
    cmd.cdw11 = cpu_to_le32(FEMU_CSI_ZONED << 24);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);

    /* lbafe starts at 2816, sixteen bytes an entry; the device uses index 1 */
    qtest_memread(femu->dev.bus->qts, buf + 2816 + 16, &zsze, sizeof(zsze));
    g_assert_cmpint(le64_to_cpu(zsze), >, 0);

    guest_free(alloc, buf);
    femu_disable(&c);
}

/* the key-value Identify reports a namespace's used bytes at offset 16 */
static uint64_t femu_kv_ns_used(FemuCtrlState *c, uint64_t buf, uint32_t nsid)
{
    NvmeCmd cmd;
    uint64_t nuse = 0;

    qtest_memset(c->pdev->bus->qts, buf, 0xff, 4096);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_IDENTIFY;
    cmd.nsid = cpu_to_le32(nsid);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(NVME_ID_CNS_CS_NS);
    cmd.cdw11 = cpu_to_le32(FEMU_CSI_KV << 24);
    g_assert_cmpint(femu_admin(c, &cmd), ==, NVME_SUCCESS);
    qtest_memread(c->pdev->bus->qts, buf + 16, &nuse, sizeof(nuse));

    return le64_to_cpu(nuse);
}

/*
 * Each key-value namespace owns its own key space and value store. The state
 * slot was copied into the namespace before its own setup ran, and a setup that
 * takes a filled slot as "already done" then left two namespaces sharing one
 * store, so a key stored on either overwrote the other's.
 */
static void femu_test_kv_namespaces_are_separate(void *obj, void *data,
                                                 QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd;
    uint64_t buf, id, used1, used2;
    uint16_t want, got;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    buf = guest_alloc(alloc, 4096);
    qtest_memset(femu->dev.bus->qts, buf, 0x71, 4096);

    /* store one key with a page of value on the first namespace only */
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_KV_CMD_STORE;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.res1 = cpu_to_le64(0x4b4b4b4b4b4b4b4bULL);   /* the key */
    cmd.cdw10 = cpu_to_le32(4096);                   /* value bytes */
    cmd.cdw11 = cpu_to_le32(8);                      /* key bytes */
    want = c.cid;
    femu_submit(&c, &c.io, &cmd);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(got, ==, want);

    id = guest_alloc(alloc, 4096);
    used1 = femu_kv_ns_used(&c, id, 1);
    used2 = femu_kv_ns_used(&c, id, 2);

    /* the store landed on the first namespace and nowhere else */
    g_assert_cmpint(used1, >, 0);
    g_assert_cmpint(used2, ==, 0);

    guest_free(alloc, id);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * Open-Channel 2.0's vector read and write, which nothing has ever driven: the
 * mode presents no block device to a modern Linux, so the guest cells reach its
 * admin surface only and every memory-safety fix on this path was made by
 * reading it. The address format comes from the geometry the device reports, so
 * the test does not have to rederive it from the properties.
 */
static void femu_test_oc20_vector_io(void *obj, void *data,
                                     QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd;
    uint64_t geo, buf, lba, other, outside;
    uint8_t g[128], out[4096];
    uint8_t grp_len, lun_len, chk_len, sec_len;
    uint16_t num_grp, want, got;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    geo = guest_alloc(alloc, 4096);
    qtest_memset(femu->dev.bus->qts, geo, 0, 4096);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_OC20_IDENTIFY;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(geo);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    qtest_memread(femu->dev.bus->qts, geo, g, sizeof(g));

    grp_len = g[8];
    lun_len = g[9];
    chk_len = g[10];
    sec_len = g[11];
    num_grp = lduw_le_p(g + 64);

    /*
     * The out-of-geometry address below is only representable when the group
     * count is not a power of two -- with powers of two every field of any
     * address is inside the geometry and the check would prove nothing.
     */
    g_assert_cmpint(sec_len, >, 0);
    g_assert_cmpint(num_grp, >, 0);
    g_assert_cmpint(num_grp, <, 1 << grp_len);
    g_assert_cmpint(lun_len, >, 0);

    lba = 0;                /* group 0, unit 0, chunk 0, sector 0 */
    /*
     * The first sector of the next parallel unit. An address is sparse -- the
     * fields sit at fixed bit offsets with gaps the geometry does not fill --
     * so it has to be turned into a position before it can index the backing
     * store, and for this one the raw value and the position differ. Both
     * addresses are written with their own pattern and both are read back, so
     * using the raw value shows up either as one overwriting the other or as a
     * transfer past the end of the store.
     *
     * The geometry can describe more media than the device backs, so stay
     * inside the first group, which is the part that is certainly backed.
     */
    other = (uint64_t)1 << (sec_len + chk_len);
    outside = (uint64_t)num_grp << (sec_len + chk_len + lun_len);

    buf = guest_alloc(alloc, 4096);
    qtest_memset(femu->dev.bus->qts, buf, 0x6b, 4096);

    /*
     * A sector is only readable once the write pointer has moved MW_CUNITS
     * sectors past it -- until then it is still in the device's write cache
     * and reads of it are answered as unwritten. Write the whole window so
     * the first sector of each chunk is readable below.
     */
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_OC20_VECT_WRITE;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    for (i = 0; i <= FEMU_OC20_MW_CUNITS; i++) {
        cmd.cdw10 = cpu_to_le32((uint32_t)(lba + i));
        cmd.cdw11 = cpu_to_le32((uint32_t)((lba + i) >> 32));
        want = c.cid;
        femu_submit(&c, &c.io, &cmd);
        g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), ==,
                        NVME_SUCCESS);
        g_assert_cmpint(got, ==, want);
    }

    /* a different pattern at the same sectors of the next parallel unit */
    qtest_memset(femu->dev.bus->qts, buf, 0x3c, 4096);
    for (i = 0; i <= FEMU_OC20_MW_CUNITS; i++) {
        cmd.cdw10 = cpu_to_le32((uint32_t)(other + i));
        cmd.cdw11 = cpu_to_le32((uint32_t)((other + i) >> 32));
        want = c.cid;
        femu_submit(&c, &c.io, &cmd);
        g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), ==,
                        NVME_SUCCESS);
        g_assert_cmpint(got, ==, want);
    }

    /* each address gives back its own sector, not the other's */
    cmd.opcode = FEMU_OC20_VECT_READ;
    qtest_memset(femu->dev.bus->qts, buf, 0, 4096);
    cmd.cdw10 = cpu_to_le32((uint32_t)lba);
    cmd.cdw11 = cpu_to_le32((uint32_t)(lba >> 32));
    want = c.cid;
    femu_submit(&c, &c.io, &cmd);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(got, ==, want);
    qtest_memread(femu->dev.bus->qts, buf, out, sizeof(out));
    g_assert_cmpint(out[0], ==, 0x6b);
    g_assert_cmpint(out[sizeof(out) - 1], ==, 0x6b);

    qtest_memset(femu->dev.bus->qts, buf, 0, 4096);
    cmd.cdw10 = cpu_to_le32((uint32_t)other);
    cmd.cdw11 = cpu_to_le32((uint32_t)(other >> 32));
    want = c.cid;
    femu_submit(&c, &c.io, &cmd);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(got, ==, want);
    qtest_memread(femu->dev.bus->qts, buf, out, sizeof(out));
    g_assert_cmpint(out[0], ==, 0x3c);
    g_assert_cmpint(out[sizeof(out) - 1], ==, 0x3c);

    /*
     * A chunk that has been reset holds nothing, so a read of it owes the
     * host the pattern the namespace reports, not the data written before the
     * reset. The address is read back through the same path that just
     * returned 0x6b from the media.
     */
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_OC20_VECT_ERASE;
    cmd.nsid = cpu_to_le32(1);
    cmd.cdw10 = cpu_to_le32((uint32_t)lba);
    cmd.cdw11 = cpu_to_le32((uint32_t)(lba >> 32));
    want = c.cid;
    femu_submit(&c, &c.io, &cmd);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(got, ==, want);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_OC20_VECT_READ;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    qtest_memset(femu->dev.bus->qts, buf, 0x11, 4096);
    cmd.cdw10 = cpu_to_le32((uint32_t)lba);
    cmd.cdw11 = cpu_to_le32((uint32_t)(lba >> 32));
    want = c.cid;
    femu_submit(&c, &c.io, &cmd);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(got, ==, want);
    qtest_memread(femu->dev.bus->qts, buf, out, sizeof(out));
    /* this namespace reports that a deallocated block reads as zeros */
    g_assert_cmpint(out[0], ==, 0);
    g_assert_cmpint(out[sizeof(out) - 1], ==, 0);

    /*
     * Erasing a block takes the die for as long as an erase takes, so resets
     * of chunks on one parallel unit queue up behind each other. They used to
     * cost nothing: the model was there but the reset path never called it.
     */
    {
        int64_t start;
        uint64_t chunk;

        for (i = 0; i < 8; i++) {
            chunk = (uint64_t)(i + 1) << sec_len;
            cmd.opcode = FEMU_OC20_VECT_WRITE;
            cmd.dptr.prp1 = cpu_to_le64(buf);
            cmd.cdw10 = cpu_to_le32((uint32_t)chunk);
            cmd.cdw11 = cpu_to_le32((uint32_t)(chunk >> 32));
            want = c.cid;
            femu_submit(&c, &c.io, &cmd);
            g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), ==,
                            NVME_SUCCESS);
            g_assert_cmpint(got, ==, want);
        }

        start = g_get_monotonic_time();
        for (i = 0; i < 8; i++) {
            chunk = (uint64_t)(i + 1) << sec_len;
            memset(&cmd, 0, sizeof(cmd));
            cmd.opcode = FEMU_OC20_VECT_ERASE;
            cmd.nsid = cpu_to_le32(1);
            cmd.cdw10 = cpu_to_le32((uint32_t)chunk);
            cmd.cdw11 = cpu_to_le32((uint32_t)(chunk >> 32));
            want = c.cid;
            femu_submit(&c, &c.io, &cmd);
            g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), ==,
                            NVME_SUCCESS);
            g_assert_cmpint(got, ==, want);
        }
        /* eight erases of one unit, each milliseconds long on this media */
        g_assert_cmpint(g_get_monotonic_time() - start, >, 8000);
    }

    /*
     * An address the geometry does not have must be refused with nothing
     * transferred. A bitmask test on the helper's status let such a read come
     * back with another sector's data and a success code.
     */
    qtest_memset(femu->dev.bus->qts, buf, 0, 4096);
    cmd.cdw10 = cpu_to_le32((uint32_t)outside);
    cmd.cdw11 = cpu_to_le32((uint32_t)(outside >> 32));
    want = c.cid;
    femu_submit(&c, &c.io, &cmd);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), !=,
                    NVME_SUCCESS);
    g_assert_cmpint(got, ==, want);
    qtest_memread(femu->dev.bus->qts, buf, out, sizeof(out));
    for (i = 0; i < (int)sizeof(out); i++) {
        g_assert_cmpint(out[i], ==, 0);
    }

    guest_free(alloc, buf);
    guest_free(alloc, geo);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static uint16_t femu_zone_action(FemuCtrlState *c, uint64_t slba,
                                  uint32_t action)
{
    NvmeCmd cmd = { 0 };
    uint16_t got;

    cmd.opcode = NVME_CMD_ZONE_MGMT_SEND;
    cmd.nsid = cpu_to_le32(1);
    cmd.cdw10 = cpu_to_le32(slba);
    cmd.cdw11 = cpu_to_le32(slba >> 32);
    cmd.cdw13 = cpu_to_le32(action);
    femu_submit(c, &c->io, &cmd);
    return FEMU_SC(femu_complete(c, &c->io, &got, NULL));
}

static void femu_zone_report(FemuCtrlState *c, uint64_t buf, uint8_t *report)
{
    NvmeCmd cmd = { 0 };
    uint16_t got;

    cmd.opcode = NVME_CMD_ZONE_MGMT_RECV;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw12 = cpu_to_le32(47); /* header and two zone descriptors */
    femu_submit(c, &c->io, &cmd);
    g_assert_cmpint(FEMU_SC(femu_complete(c, &c->io, &got, NULL)), ==,
                    NVME_SUCCESS);
    qtest_memread(c->pdev->bus->qts, buf, report, 192);
}

static void femu_test_zrwa_reopen(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf, second;
    uint8_t report[192];
    uint32_t open = NVME_ZONE_ACTION_OPEN | (NVME_ZSFLAG_ZRWA_ALLOC << 8);
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, 4096);
    femu_zone_report(&c, buf, report);
    g_assert_cmpuint(ldq_le_p(report), >=, 2);
    second = ldq_le_p(report + 128 + 16);
    g_assert_cmpuint(second, >, 0);

    g_assert_cmpint(femu_zone_action(&c, 0, open), ==, NVME_SUCCESS);
    for (i = 0; i < 4; i++) {
        g_assert_cmpint(femu_zone_action(&c, 0, NVME_ZONE_ACTION_CLOSE), ==,
                        NVME_SUCCESS);
        femu_zone_report(&c, buf, report);
        g_assert_cmpint(report[65] >> 4, ==, NVME_ZONE_STATE_CLOSED);
        g_assert_cmpint(femu_zone_action(&c, 0, open), ==, NVME_SUCCESS);
        femu_zone_report(&c, buf, report);
        g_assert_cmpint(report[65] >> 4, ==, NVME_ZONE_STATE_EXPLICITLY_OPEN);
        g_assert_cmpint(report[66] & NVME_ZA_ZRWA_VALID, !=, 0);
    }
    /* Reopening must neither release nor consume another resource. */
    g_assert_cmpint(femu_zone_action(&c, second, open), ==, NVME_NOZRWA);
    g_assert_cmpint(femu_zone_action(&c, 0, NVME_ZONE_ACTION_RESET), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_zone_action(&c, second, open), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_zone_action(&c, second, NVME_ZONE_ACTION_RESET), ==,
                    NVME_SUCCESS);

    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * A zone that has been reset holds no data. This controller reports that a
 * deallocated block reads as zeros, and the read path goes straight to the
 * backing store by logical block, so resetting the write pointer alone leaves
 * the old content there to be read back.
 */
static void femu_test_zone_reset(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd;
    uint64_t buf;
    uint8_t out[FEMU_DATA_SIZE];
    uint16_t want, got;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    qtest_memset(femu->dev.bus->qts, buf, 0x5a, FEMU_DATA_SIZE);
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 0, buf)), ==,
                    NVME_SUCCESS);

    qtest_memset(femu->dev.bus->qts, buf, 0, FEMU_DATA_SIZE);
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_READ, 0, buf)), ==,
                    NVME_SUCCESS);
    qtest_memread(femu->dev.bus->qts, buf, out, sizeof(out));
    g_assert_cmpint(out[0], ==, 0x5a);
    g_assert_cmpint(out[FEMU_DATA_SIZE - 1], ==, 0x5a);

    /*
     * Deallocate is the other way to make blocks read as zeros, and it does not
     * go through the zone state machine: accepted, it zeroed a sequential
     * zone's data while the descriptor still reported the write pointer.
     * It has to be refused, and the data has to survive the refusal.
     */
    {
        uint64_t ranges = guest_alloc(alloc, 4096);
        uint8_t desc[16] = { 0 };

        stl_le_p(desc + 4, FEMU_DATA_SIZE / c.lba_size);
        qtest_memwrite(femu->dev.bus->qts, ranges, desc, sizeof(desc));

        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = NVME_CMD_DSM;
        cmd.nsid = cpu_to_le32(1);
        cmd.dptr.prp1 = cpu_to_le64(ranges);
        cmd.cdw11 = cpu_to_le32(FEMU_DSM_AD);
        want = c.cid;
        femu_submit(&c, &c.io, &cmd);
        g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), !=,
                        NVME_SUCCESS);
        g_assert_cmpint(got, ==, want);
        guest_free(alloc, ranges);
    }

    qtest_memset(femu->dev.bus->qts, buf, 0, FEMU_DATA_SIZE);
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_READ, 0, buf)), ==,
                    NVME_SUCCESS);
    qtest_memread(femu->dev.bus->qts, buf, out, sizeof(out));
    g_assert_cmpint(out[0], ==, 0x5a);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_CMD_ZONE_MGMT_SEND;
    cmd.nsid = cpu_to_le32(1);
    cmd.cdw13 = cpu_to_le32(FEMU_ZONE_ACTION_RESET);
    want = c.cid;
    femu_submit(&c, &c.io, &cmd);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(got, ==, want);

    qtest_memset(femu->dev.bus->qts, buf, 0xff, FEMU_DATA_SIZE);
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_READ, 0, buf)), ==,
                    NVME_SUCCESS);
    qtest_memread(femu->dev.bus->qts, buf, out, sizeof(out));
    for (i = 0; i < FEMU_DATA_SIZE; i++) {
        g_assert_cmpint(out[i], ==, 0);
    }

    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static uint16_t femu_get_feature(FemuCtrlState *c, uint8_t fid, uint8_t sel,
                                 uint32_t nsid, uint32_t dw11,
                                 uint32_t *result)
{
    NvmeCmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_GET_FEATURES;
    cmd.nsid = cpu_to_le32(nsid);
    cmd.cdw10 = cpu_to_le32(fid | (sel << 8));
    cmd.cdw11 = cpu_to_le32(dw11);
    return femu_admin_result(c, &cmd, result);
}

static uint16_t femu_set_feature(FemuCtrlState *c, uint8_t fid, bool save,
                                 uint32_t nsid, uint32_t dw11,
                                 uint32_t *result)
{
    NvmeCmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_SET_FEATURES;
    cmd.nsid = cpu_to_le32(nsid);
    cmd.cdw10 = cpu_to_le32(fid | (save ? 1u << 31 : 0));
    cmd.cdw11 = cpu_to_le32(dw11);
    return femu_admin_result(c, &cmd, result);
}

/*
 * Get and Set Features carry the identifier in the low byte of CDW10 and a
 * selector or the save bit above it. The selector chooses the current,
 * default, saved or capability value; a save request must be refused rather
 * than obeyed, and an identifier the controller does not implement is an
 * invalid field.
 */
static void femu_test_features(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint32_t result;

    femu_enable(&c, &femu->dev, alloc);

    g_assert_cmpint(FEMU_SC(femu_get_feature(&c, NVME_TEMPERATURE_THRESHOLD,
                            NVME_GETFEAT_SELECT_CURRENT, 0, 0, &result)),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(result, ==, 0x14d);

    /* the one command set combination there is may be selected, no other */
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, FEMU_FEAT_CMD_SET_PROFILE,
                            false, 0, 0, NULL)), ==, NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, FEMU_FEAT_CMD_SET_PROFILE,
                            false, 0, 1, NULL)), ==,
                    FEMU_IOCS_COMBINATION_REJECTED);
    g_assert_cmpint(FEMU_SC(femu_get_feature(&c, FEMU_FEAT_CMD_SET_PROFILE,
                            NVME_GETFEAT_SELECT_CURRENT, 0, 0, &result)),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(result, ==, 0);

    g_assert_cmpint(FEMU_SC(femu_get_feature(&c, NVME_TEMPERATURE_THRESHOLD,
                            NVME_GETFEAT_SELECT_CAP, 0, 0, &result)),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(result & NVME_FEAT_CAP_CHANGE, !=, 0);
    g_assert_cmpint(result & NVME_FEAT_CAP_SAVE, ==, 0);

    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_TEMPERATURE_THRESHOLD,
                            false, 0, 0x150, NULL)), ==, NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_get_feature(&c, NVME_TEMPERATURE_THRESHOLD,
                            NVME_GETFEAT_SELECT_CURRENT, 0, 0, &result)),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(result, ==, 0x150);
    g_assert_cmpint(FEMU_SC(femu_get_feature(&c, NVME_TEMPERATURE_THRESHOLD,
                            NVME_GETFEAT_SELECT_DEFAULT, 0, 0, &result)),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(result, ==, 0x14d);
    g_assert_cmpint(FEMU_SC(femu_get_feature(&c, NVME_TEMPERATURE_THRESHOLD,
                            NVME_GETFEAT_SELECT_SAVED, 0, 0, &result)),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(result, ==, 0x14d);

    /* nothing is saveable */
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_TEMPERATURE_THRESHOLD,
                            true, 0, 0x150, NULL)),
                    ==, NVME_FID_NOT_SAVEABLE);

    /* a selector the specification does not define */
    g_assert_cmpint(FEMU_SC(femu_get_feature(&c, NVME_TEMPERATURE_THRESHOLD,
                            4, 0, 0, &result)), ==, NVME_INVALID_FIELD);

    /* autonomous power state transitions are not implemented */
    g_assert_cmpint(FEMU_SC(femu_get_feature(&c, 0x0c,
                            NVME_GETFEAT_SELECT_CURRENT, 0, 0, &result)),
                    ==, NVME_INVALID_FIELD);

    /* a controller-wide feature addressed to one namespace */
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_VOLATILE_WRITE_CACHE,
                            false, 1, 0, NULL)),
                    ==, NVME_FEAT_NOT_NS_SPEC);

    /*
     * A host learns it may use the Select field and the Save bit from
     * Save/Select Feature Support in Identify Controller. Serving them while
     * reporting the bit clear leaves the whole path unreachable for a host
     * that checks first.
     */
    {
        uint64_t buf = guest_alloc(alloc, 4096);
        NvmeIdCtrl id;
        NvmeCmd cmd;

        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = NVME_ADM_CMD_IDENTIFY;
        cmd.dptr.prp1 = cpu_to_le64(buf);
        cmd.cdw10 = cpu_to_le32(NVME_ID_CNS_CTRL);
        g_assert_cmpint(FEMU_SC(femu_admin(&c, &cmd)), ==, NVME_SUCCESS);
        qtest_memread(c.pdev->bus->qts, buf, &id, sizeof(id));
        g_assert_cmpint(le16_to_cpu(id.oncs) & NVME_ONCS_FEATURES, !=, 0);
        guest_free(alloc, buf);
    }

    /*
     * LBA Range Type answers with a descriptor list, not a value, so the
     * default and saved selectors have to transfer one. Returning success
     * without writing the buffer leaves the host parsing what was already
     * there.
     */
    {
        uint64_t buf = guest_alloc(alloc, 4096);
        uint8_t rt[64];
        NvmeCmd cmd;
        int i;

        qtest_memset(c.pdev->bus->qts, buf, 0xff, sizeof(rt));
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = NVME_ADM_CMD_GET_FEATURES;
        cmd.nsid = cpu_to_le32(1);
        cmd.dptr.prp1 = cpu_to_le64(buf);
        cmd.cdw10 = cpu_to_le32(NVME_LBA_RANGE_TYPE |
                                (NVME_GETFEAT_SELECT_DEFAULT << 8));
        cmd.cdw11 = cpu_to_le32(1);
        g_assert_cmpint(FEMU_SC(femu_admin(&c, &cmd)), ==, NVME_SUCCESS);
        qtest_memread(c.pdev->bus->qts, buf, rt, sizeof(rt));
        for (i = 0; i < (int)sizeof(rt); i++) {
            g_assert_cmpint(rt[i], ==, 0);
        }
        guest_free(alloc, buf);
    }

    /*
     * Only the composite sensor exists, so every other selector's default is
     * zero rather than the composite's threshold.
     */
    g_assert_cmpint(FEMU_SC(femu_get_feature(&c, NVME_TEMPERATURE_THRESHOLD,
                            NVME_GETFEAT_SELECT_DEFAULT, 0, 3 << 16, &result)),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(result, ==, 0);

    /*
     * Error Recovery is namespace-scoped, so a value set on one namespace must
     * not be what another reads back. This device has one namespace, so the
     * check that survives here is that the value round-trips through it.
     */
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_ERROR_RECOVERY,
                            false, 1, 0x10005, NULL)), ==, NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_get_feature(&c, NVME_ERROR_RECOVERY,
                            NVME_GETFEAT_SELECT_CURRENT, 1, 0, &result)),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(result, ==, 0x10005);
    /* and its default is still zero */
    g_assert_cmpint(FEMU_SC(femu_get_feature(&c, NVME_ERROR_RECOVERY,
                            NVME_GETFEAT_SELECT_DEFAULT, 1, 0, &result)),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(result, ==, 0);

    /* a device with no Flexible Data Placement refuses the feature outright */
    g_assert_cmpint(FEMU_SC(femu_get_feature(&c, NVME_FDP_MODE,
                            NVME_GETFEAT_SELECT_CURRENT, 0, 0, &result)),
                    ==, NVME_INVALID_FIELD);
    g_assert_cmpint(FEMU_SC(femu_get_feature(&c, NVME_FDP_MODE,
                            NVME_GETFEAT_SELECT_DEFAULT, 0, 0, &result)),
                    ==, NVME_INVALID_FIELD);

    /*
     * The queue count comes back in dword 0 of the completion, as the number
     * allocated rather than the number asked for, and 0's based in both
     * halves. This controller allocates its queues property's worth however
     * many the host requests, so ask for four and expect the default eight.
     * Comparing the two halves to each other passes on a pair of zeroes.
     */
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_NUMBER_OF_QUEUES,
                            false, 0, 0x00030003, &result)), ==, NVME_SUCCESS);
    g_assert_cmpint(result, ==, (FEMU_DEFAULT_IO_QUEUES - 1) |
                                ((FEMU_DEFAULT_IO_QUEUES - 1) << 16));

    femu_disable(&c);
}

/*
 * Log page identifiers as hw/femu/nvme.h numbers them. This test compiles
 * against QEMU's own block/nvme.h, which names neither the mandatory
 * supported-pages list nor FEMU's vendor page.
 */
#define FEMU_LOG_SUPPORTED          0x00
#define FEMU_LOG_CHANGED_ZONE_LIST  0xbf
#define FEMU_LOG_FEMU_STATS         0xc0
#define FEMU_LOG_FDP_EVENTS         0x23
#define FEMU_LIDS_LSUPP             (1u << 0)   /* LID Supported */

/*
 * Get Log Page. Length is a 0's based dword count split across two command
 * fields, and the offset is a byte offset split the same way.
 */
static uint16_t femu_get_log(FemuCtrlState *c, uint8_t lid, uint64_t buf,
                             uint32_t len, uint64_t off)
{
    uint32_t numd = (len >> 2) - 1;
    NvmeCmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_GET_LOG_PAGE;
    cmd.nsid = cpu_to_le32(NVME_NSID_BROADCAST);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(lid | ((numd & 0xffff) << 16));
    cmd.cdw11 = cpu_to_le32((numd >> 16) & 0xffff);
    cmd.cdw12 = cpu_to_le32((uint32_t)off);
    cmd.cdw13 = cpu_to_le32((uint32_t)(off >> 32));

    return femu_admin(c, &cmd);
}

/*
 * What the health log says a key-value namespace read, and what the most-read
 * block figure says it touched. The size field in a retrieve is the host's
 * buffer, not what the device put in it, and the per-command base cost was
 * charged as a read of block zero.
 */
static void femu_test_kv_accounting(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd;
    uint64_t buf, log, units_before, units_after, most_reads;
    uint8_t page[512];
    uint16_t want, got;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    buf = guest_alloc(alloc, 4096);
    log = guest_alloc(alloc, 4096);
    qtest_memset(femu->dev.bus->qts, buf, 0x71, 4096);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_KV_CMD_STORE;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.res1 = cpu_to_le64(0x4b4b4b4b4b4b4b4bULL);
    cmd.cdw10 = cpu_to_le32(4096);
    cmd.cdw11 = cpu_to_le32(8);
    want = c.cid;
    femu_submit(&c, &c.io, &cmd);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(got, ==, want);

    g_assert_cmpint(FEMU_SC(femu_get_log(&c, NVME_LOG_SMART_INFO, log,
                                         sizeof(page), 0)), ==, NVME_SUCCESS);
    qtest_memread(femu->dev.bus->qts, log, page, sizeof(page));
    units_before = ldq_le_p(page + 32);

    /* four retrieves of the same page, each naming a four-gigabyte buffer */
    for (i = 0; i < 4; i++) {
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = FEMU_KV_CMD_RETRIEVE;
        cmd.nsid = cpu_to_le32(1);
        cmd.dptr.prp1 = cpu_to_le64(buf);
        cmd.res1 = cpu_to_le64(0x4b4b4b4b4b4b4b4bULL);
        cmd.cdw10 = cpu_to_le32(0xffffffffU);
        cmd.cdw11 = cpu_to_le32(8);
        want = c.cid;
        femu_submit(&c, &c.io, &cmd);
        g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), ==,
                        NVME_SUCCESS);
        g_assert_cmpint(got, ==, want);
    }

    g_assert_cmpint(FEMU_SC(femu_get_log(&c, NVME_LOG_SMART_INFO, log,
                                         sizeof(page), 0)), ==, NVME_SUCCESS);
    qtest_memread(femu->dev.bus->qts, log, page, sizeof(page));
    units_after = ldq_le_p(page + 32);

    /*
     * Sixteen kilobytes really moved, which is under one reported unit. With
     * the buffer size counted instead this grows by millions.
     */
    g_assert_cmpint(units_after - units_before, <, 1000);

    g_assert_cmpint(FEMU_SC(femu_get_log(&c, FEMU_LOG_FEMU_STATS, log,
                                         sizeof(page), 0)), ==, NVME_SUCCESS);
    qtest_memread(femu->dev.bus->qts, log, page, sizeof(page));
    most_reads = ldq_le_p(page + 32);

    /*
     * The format reports the key limit the device enforces. Reported as zero,
     * which the field defines as no maximum, a host is told it may store keys
     * the device then refuses for want of capacity.
     */
    {
        uint64_t idbuf = guest_alloc(alloc, 4096);
        uint8_t kvfmt[128];
        NvmeCmd id;

        qtest_memset(femu->dev.bus->qts, idbuf, 0, 4096);
        memset(&id, 0, sizeof(id));
        id.opcode = NVME_ADM_CMD_IDENTIFY;
        id.nsid = cpu_to_le32(1);
        id.dptr.prp1 = cpu_to_le64(idbuf);
        id.cdw10 = cpu_to_le32(NVME_ID_CNS_CS_NS);
        id.cdw11 = cpu_to_le32(FEMU_CSI_KV << 24);
        g_assert_cmpint(femu_admin(&c, &id), ==, NVME_SUCCESS);
        qtest_memread(femu->dev.bus->qts, idbuf, kvfmt, sizeof(kvfmt));
        /*
         * The format array starts at 72 and the key count is eight bytes into
         * its first entry, after the key length, the options byte and the value
         * length.
         */
        g_assert_cmpint(ldl_le_p(kvfmt + 72 + 8), >, 0);
        guest_free(alloc, idbuf);
    }

    /* a lookup for a key that is not there reads nothing from the media */
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_KV_CMD_EXIST;
    cmd.nsid = cpu_to_le32(1);
    cmd.res1 = cpu_to_le64(0x6d6d6d6d6d6d6d6dULL);
    cmd.cdw11 = cpu_to_le32(8);
    want = c.cid;
    femu_submit(&c, &c.io, &cmd);
    femu_complete(&c, &c.io, &got, NULL);
    g_assert_cmpint(got, ==, want);

    /*
     * The figure counts reads of the most-read block, and the value above does
     * live in a block, so it is not expected to be zero -- only not to move for
     * a command that reads no data. The per-command base cost was charged as a
     * user read of block zero, so it moved for every command.
     */
    g_assert_cmpint(FEMU_SC(femu_get_log(&c, FEMU_LOG_FEMU_STATS, log,
                                         sizeof(page), 0)), ==, NVME_SUCCESS);
    qtest_memread(femu->dev.bus->qts, log, page, sizeof(page));
    g_assert_cmpint(ldq_le_p(page + 32), ==, most_reads);

    guest_free(alloc, log);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * Flexible Data Placement events reach the host through a ring that a poller
 * and the FTL thread both append to. A reclaim unit handle update that names
 * handles whose units are not yet full records one event per handle; both must
 * arrive whole, in order, and stamped.
 *
 * The update names two identifiers, which also covers the count's decoding:
 * it is the field at bits 31:16, and reading it from the wrong bits refused
 * every update that named more than one.
 */
/* a Reclaim Unit Handle Update naming npid identifiers listed at pids */
static uint16_t femu_ruh_update(FemuCtrlState *c, uint64_t pids, uint16_t npid)
{
    NvmeCmd cmd;
    uint16_t want = c->cid;
    uint16_t got;
    uint16_t status;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_CMD_IO_MGMT_SEND;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(pids);
    /* the count is 0's based */
    cmd.cdw10 = cpu_to_le32(FEMU_IOMS_RUH_UPDATE | ((npid - 1) << 16));
    femu_submit(c, &c->io, &cmd);
    status = femu_complete(c, &c->io, &got, NULL);
    g_assert_cmpint(got, ==, want);
    return FEMU_SC(status);
}

static void femu_test_fdp_events(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd;
    uint64_t pids, log;
    uint16_t list[2] = { cpu_to_le16(0), cpu_to_le16(1) };
    uint8_t buf[64 + 2 * 64];
    uint32_t numd = sizeof(buf) / 4 - 1;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    pids = guest_alloc(alloc, 4096);
    qtest_memwrite(femu->dev.bus->qts, pids, list, sizeof(list));
    g_assert_cmpint(femu_ruh_update(&c, pids, 2), ==, NVME_SUCCESS);

    log = guest_alloc(alloc, 4096);
    qtest_memset(femu->dev.bus->qts, log, 0xff, 4096);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_GET_LOG_PAGE;
    cmd.nsid = cpu_to_le32(NVME_NSID_BROADCAST);
    cmd.dptr.prp1 = cpu_to_le64(log);
    /* host events (LSP bit 0); endurance group 1 in the specific identifier */
    cmd.cdw10 = cpu_to_le32(FEMU_LOG_FDP_EVENTS | (1 << 8) |
                            ((numd & 0xffff) << 16));
    cmd.cdw11 = cpu_to_le32(1 << 16);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    qtest_memread(femu->dev.bus->qts, log, buf, sizeof(buf));

    g_assert_cmpint(ldl_le_p(buf), ==, 2);
    for (i = 0; i < 2; i++) {
        const uint8_t *ev = buf + 64 + i * 64;

        g_assert_cmpint(ev[0], ==, FEMU_FDP_EVT_RU_NOT_FULLY_WRITTEN);
        /* placement id, namespace id and reclaim unit fields are all valid */
        g_assert_cmpint(ev[1], ==, 0x7);
        g_assert_cmpint(lduw_le_p(ev + 2), ==, i);
        g_assert_cmpint(ldq_le_p(ev + 4) & ((1ull << 48) - 1), !=, 0);
        g_assert_cmpint(ldl_le_p(ev + 12), ==, 1);
    }

    guest_free(alloc, log);
    guest_free(alloc, pids);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * Supported Log Pages says which identifiers the controller answers, and the
 * media counters live on their own page rather than in the SMART log's
 * temperature fields. Both must agree with what Get Log Page actually does,
 * and both must serve a request from the offset it was given -- returning the
 * start of the page whatever was asked for is the failure this covers.
 */
static void femu_test_log_pages(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { .pdev = &femu->dev, .alloc = alloc };
    uint64_t buf;
    uint32_t lids[256];
    uint8_t page[512], slice[64];
    int i;

    femu_enable(&c, &femu->dev, alloc);
    buf = guest_alloc(alloc, 4096);

    /* the supported-pages list itself */
    g_assert_cmpint(FEMU_SC(femu_get_log(&c, FEMU_LOG_SUPPORTED, buf,
                                         sizeof(lids), 0)), ==, NVME_SUCCESS);
    qtest_memread(femu->dev.bus->qts, buf, lids, sizeof(lids));

    g_assert_cmpint(le32_to_cpu(lids[FEMU_LOG_SUPPORTED]) & FEMU_LIDS_LSUPP,
                    ==, FEMU_LIDS_LSUPP);
    g_assert_cmpint(le32_to_cpu(lids[NVME_LOG_SMART_INFO]) & FEMU_LIDS_LSUPP,
                    ==, FEMU_LIDS_LSUPP);
    g_assert_cmpint(le32_to_cpu(lids[FEMU_LOG_FEMU_STATS]) & FEMU_LIDS_LSUPP,
                    ==, FEMU_LIDS_LSUPP);
    /*
     * This controller has no subsystem and no zoned namespace, so the pages
     * that need one must be reported as unsupported rather than listed
     * unconditionally.
     */
    g_assert_cmpint(le32_to_cpu(lids[NVME_LOG_ENDGRP]), ==, 0);
    g_assert_cmpint(le32_to_cpu(lids[FEMU_LOG_CHANGED_ZONE_LIST]), ==, 0);

    /* every identifier claimed must actually answer */
    for (i = 0; i < 256; i++) {
        if (!(le32_to_cpu(lids[i]) & FEMU_LIDS_LSUPP)) {
            continue;
        }
        g_assert_cmpint(FEMU_SC(femu_get_log(&c, i, buf, 512, 0)),
                        ==, NVME_SUCCESS);
    }

    /*
     * A read from an offset must start there. Use the SMART log rather than
     * the counter page: this controller has no FTL, so every counter is zero
     * and comparing one run of zeroes against another proves nothing. SMART
     * carries the spare figures, so the assertion below has something to bite
     * on -- which the check right after it confirms before relying on it.
     */
    g_assert_cmpint(FEMU_SC(femu_get_log(&c, NVME_LOG_SMART_INFO, buf,
                                         sizeof(page), 0)), ==, NVME_SUCCESS);
    qtest_memread(femu->dev.bus->qts, buf, page, sizeof(page));
    g_assert_cmpint(page[4], !=, page[0]);

    g_assert_cmpint(FEMU_SC(femu_get_log(&c, NVME_LOG_SMART_INFO, buf,
                                         sizeof(slice), 4)), ==, NVME_SUCCESS);
    qtest_memread(femu->dev.bus->qts, buf, slice, sizeof(slice));
    g_assert_cmpint(memcmp(slice, page + 4, sizeof(slice)), ==, 0);

    /*
     * The firmware slot log the same way. Its active-slot byte is at the front
     * and the revision string eight bytes in, so a read from eight starts on
     * something different from a read from zero -- which the first assertion
     * below establishes before the second relies on it.
     */
    g_assert_cmpint(FEMU_SC(femu_get_log(&c, NVME_LOG_FW_SLOT_INFO, buf,
                                         sizeof(page), 0)), ==, NVME_SUCCESS);
    qtest_memread(femu->dev.bus->qts, buf, page, sizeof(page));
    g_assert_cmpint(page[8], !=, page[0]);

    g_assert_cmpint(FEMU_SC(femu_get_log(&c, NVME_LOG_FW_SLOT_INFO, buf,
                                         sizeof(slice), 8)), ==, NVME_SUCCESS);
    qtest_memread(femu->dev.bus->qts, buf, slice, sizeof(slice));
    g_assert_cmpint(memcmp(slice, page + 8, sizeof(slice)), ==, 0);

    /* an offset past the end is a bad field, not a wrapped read */
    g_assert_cmpint(FEMU_SC(femu_get_log(&c, NVME_LOG_SMART_INFO, buf, 64,
                                         4096)), ==, NVME_INVALID_FIELD);
    g_assert_cmpint(FEMU_SC(femu_get_log(&c, FEMU_LOG_FEMU_STATS, buf, 64,
                                         4096)), ==, NVME_INVALID_FIELD);
    g_assert_cmpint(FEMU_SC(femu_get_log(&c, NVME_LOG_FW_SLOT_INFO, buf, 64,
                                         4096)), ==, NVME_INVALID_FIELD);
    g_assert_cmpint(FEMU_SC(femu_get_log(&c, NVME_LOG_ERROR_INFO, buf, 64,
                                         4096)), ==, NVME_INVALID_FIELD);

    guest_free(alloc, buf);
    femu_disable(&c);
}

/* Large dword counts must not wrap to a small, successful transfer. */
static void femu_test_log_length(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd = { 0 };
    uint64_t buf;
    const uint32_t counts[] = { 0x40000000, 0x3fffffff, 0xffffffff };
    size_t i;

    femu_enable(&c, &femu->dev, alloc);
    buf = guest_alloc(alloc, 4096);
    qtest_memset(femu->dev.bus->qts, buf, 0xa5, 4096);
    cmd.opcode = NVME_ADM_CMD_GET_LOG_PAGE;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);

    for (i = 0; i < G_N_ELEMENTS(counts); i++) {
        cmd.cdw10 = cpu_to_le32(NVME_LOG_SMART_INFO |
                                ((counts[i] & 0xffff) << 16));
        cmd.cdw11 = cpu_to_le32(counts[i] >> 16);
        g_assert_cmpint(FEMU_SC(femu_admin(&c, &cmd)), ==, NVME_INVALID_FIELD);
    }
    g_assert_cmpint(qtest_readb(femu->dev.bus->qts, buf), ==, 0xa5);
    cmd.cdw10 = cpu_to_le32(NVME_LOG_SMART_INFO | (127 << 16));
    cmd.cdw11 = 0;
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);

    guest_free(alloc, buf);
    femu_disable(&c);
}

static void femu_test_oc20_log_length(void *obj, void *data,
                                      QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd = { 0 };
    uint64_t buf;
    const uint32_t counts[] = { 0x40000000, 0x3fffffff, 0xffffffff };
    size_t i;

    femu_enable(&c, &femu->dev, alloc);
    buf = guest_alloc(alloc, 4096);
    cmd.opcode = NVME_ADM_CMD_GET_LOG_PAGE;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(0xca | (7 << 16)); /* one chunk descriptor */
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);

    /* Use the original descriptor so even a broken set leaves it intact. */
    cmd.opcode = 0xc1; /* Open-Channel Set Log Page */
    for (i = 0; i < G_N_ELEMENTS(counts); i++) {
        cmd.cdw10 = cpu_to_le32(0xca | ((counts[i] & 0xffff) << 16));
        cmd.cdw11 = cpu_to_le32(counts[i] >> 16);
        g_assert_cmpint(FEMU_SC(femu_admin(&c, &cmd)), ==, NVME_INVALID_FIELD);
    }
    cmd.cdw10 = cpu_to_le32(0xca | (7 << 16));
    cmd.cdw11 = 0;
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);

    guest_free(alloc, buf);
    femu_disable(&c);
}

static void femu_test_report_length(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd = { 0 };
    bool zoned = data != NULL;
    uint64_t buf;
    uint16_t got;
    const uint32_t counts[] = { 0x4000001f, 0x3fffffff, 0xffffffff };
    size_t i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, 4096);
    qtest_memset(femu->dev.bus->qts, buf, 0xa5, 4096);
    cmd.opcode = zoned ? NVME_CMD_ZONE_MGMT_RECV : FEMU_CMD_IO_MGMT_RECV;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    if (!zoned) {
        cmd.cdw10 = cpu_to_le32(FEMU_IOMR_RUH_STATUS);
    }
    for (i = 0; i < G_N_ELEMENTS(counts); i++) {
        if (zoned) {
            cmd.cdw12 = cpu_to_le32(counts[i]);
        } else {
            cmd.cdw11 = cpu_to_le32(counts[i]);
        }
        femu_submit(&c, &c.io, &cmd);
        g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), ==,
                        NVME_INVALID_FIELD);
    }
    g_assert_cmpint(qtest_readb(femu->dev.bus->qts, buf), ==, 0xa5);
    if (zoned) {
        cmd.cdw12 = cpu_to_le32(127);
    } else {
        cmd.cdw11 = cpu_to_le32(127);
    }
    femu_submit(&c, &c.io, &cmd);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(qtest_readb(femu->dev.bus->qts, buf), !=, 0xa5);

    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static uint16_t femu_format(FemuCtrlState *c, uint32_t nsid, uint8_t lba_idx,
                            uint8_t ses)
{
    NvmeCmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_FORMAT_NVM;
    cmd.nsid = cpu_to_le32(nsid);
    cmd.cdw10 = cpu_to_le32(lba_idx | (ses << 9));
    return femu_admin(c, &cmd);
}

/* Identify Namespace: the logical block count and the size of one block */
static void femu_identify_ns(FemuCtrlState *c, uint64_t *nsze,
                             uint32_t *lba_size)
{
    NvmeCmd cmd;
    uint64_t buf = guest_alloc(c->alloc, 4096);
    NvmeIdNs id;
    uint8_t idx;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_IDENTIFY;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(NVME_ID_CNS_NS);
    g_assert_cmpint(FEMU_SC(femu_admin(c, &cmd)), ==, NVME_SUCCESS);
    qtest_memread(c->pdev->bus->qts, buf, &id, sizeof(id));
    guest_free(c->alloc, buf);

    idx = NVME_ID_NS_FLBAS_INDEX(id.flbas);
    *nsze = le64_to_cpu(id.nsze);
    *lba_size = 1u << id.lbaf[idx].ds;
}

/*
 * Format NVM changes the logical block size, so the block count and the
 * per-block bookkeeping the controller keeps must follow it, and the data
 * that was there must be gone.
 *
 * The namespace starts with 4 KiB blocks here (lba_index=3) so that
 * formatting to 512-byte blocks multiplies the block count by eight. The
 * per-LBA bitmaps were sized once at realize, so a write near the end of the
 * larger space used to run off them.
 */
static void femu_test_format(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t nsze_4k, nsze_512;
    uint32_t lba_size;
    uint64_t buf;
    uint8_t *rbuf = g_malloc(FEMU_DATA_SIZE);
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    femu_identify_ns(&c, &nsze_4k, &lba_size);
    g_assert_cmpint(lba_size, ==, 4096);
    c.lba_size = lba_size;

    femu_round_trip(&c, 1);

    /* an index past the formats the namespace offers */
    g_assert_cmpint(FEMU_SC(femu_format(&c, 1, 15, 0)), ==,
                    NVME_INVALID_FORMAT);

    /* the same format again: the data must not survive */
    g_assert_cmpint(FEMU_SC(femu_format(&c, 1, 3, 0)), ==, NVME_SUCCESS);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    qtest_memset(c.pdev->bus->qts, buf, 0xa5, FEMU_DATA_SIZE);
    g_assert_cmpint(femu_rw(&c, NVME_CMD_READ, 8, buf), ==, NVME_SUCCESS);
    qtest_memread(c.pdev->bus->qts, buf, rbuf, FEMU_DATA_SIZE);
    for (i = 0; i < FEMU_DATA_SIZE; i++) {
        g_assert_cmpint(rbuf[i], ==, 0);
    }
    guest_free(alloc, buf);

    /* 512-byte blocks: eight times the count, and I/O at the new size works */
    g_assert_cmpint(FEMU_SC(femu_format(&c, 1, 0, 0)), ==, NVME_SUCCESS);
    femu_identify_ns(&c, &nsze_512, &lba_size);
    g_assert_cmpint(lba_size, ==, 512);
    g_assert_cmpint(nsze_512, ==, nsze_4k * 8);
    c.lba_size = lba_size;
    femu_round_trip(&c, 2);

    /*
     * The last blocks of the grown space are the ones the old bookkeeping did
     * not cover. Writing and reading them is what walks off the bitmaps.
     */
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE,
                            nsze_512 - FEMU_DATA_SIZE / 512, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_rw(&c, NVME_CMD_READ,
                            nsze_512 - FEMU_DATA_SIZE / 512, buf), ==,
                    NVME_SUCCESS);
    /* and one block past the end is refused */
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_READ, nsze_512, buf)), ==,
                    NVME_LBA_RANGE);
    guest_free(alloc, buf);

    /* back to 4 KiB blocks: the smaller count returns */
    g_assert_cmpint(FEMU_SC(femu_format(&c, 1, 3, 0)), ==, NVME_SUCCESS);
    femu_identify_ns(&c, &nsze_512, &lba_size);
    g_assert_cmpint(lba_size, ==, 4096);
    g_assert_cmpint(nsze_512, ==, nsze_4k);
    c.lba_size = lba_size;
    femu_round_trip(&c, 3);

    g_free(rbuf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * The media counters are the emulator's own numbers, and the vendor page is
 * the only place they are reported. A page that answers with zeroes looks the
 * same as one that answers correctly on a device that has done no work, so
 * this writes first and then requires the counters to have moved -- and
 * requires the amplification factor to be consistent with them, which is what
 * a caller actually reads the page for.
 */
static void femu_test_media_counters(void *obj, void *data,
                                     QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf, pattern;
    uint32_t waf;
    uint64_t host, gc, nand;
    uint8_t page[512];
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    buf = guest_alloc(alloc, sizeof(page));
    g_assert_cmpint(FEMU_SC(femu_get_log(&c, FEMU_LOG_FEMU_STATS, buf,
                                         sizeof(page), 0)), ==, NVME_SUCCESS);
    qtest_memread(femu->dev.bus->qts, buf, page, sizeof(page));
    host = ldq_le_p(page + 8);
    g_assert_cmpint(host, ==, 0);

    /* enough writes that the counter cannot stay where it was */
    pattern = guest_alloc(alloc, FEMU_DATA_SIZE);
    qtest_memset(femu->dev.bus->qts, pattern, 0x5a, FEMU_DATA_SIZE);
    for (i = 0; i < 16; i++) {
        g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE,
                                        i * (FEMU_DATA_SIZE / c.lba_size),
                                        pattern)), ==, NVME_SUCCESS);
    }
    guest_free(alloc, pattern);

    g_assert_cmpint(FEMU_SC(femu_get_log(&c, FEMU_LOG_FEMU_STATS, buf,
                                         sizeof(page), 0)), ==, NVME_SUCCESS);
    qtest_memread(femu->dev.bus->qts, buf, page, sizeof(page));

    waf  = ldl_le_p(page);
    host = ldq_le_p(page + 8);
    gc   = ldq_le_p(page + 16);
    nand = ldq_le_p(page + 24);

    g_assert_cmpint(host, >, 0);
    g_assert_cmpint(nand, >=, host);
    /* nothing has been rewritten yet, so the device has relocated nothing */
    g_assert_cmpint(gc, ==, 0);
    /* the factor is (programmed + relocated) / host, scaled by a thousand */
    g_assert_cmpint(waf, ==, ((nand + gc) * 1000ull) / host);

    /*
     * This device has no write buffer, so it is the control for the buffered
     * test below: the pages the buffer would have been asked about are still
     * counted, and none of them can be a hit.
     */
    g_assert_cmpint(ldq_le_p(page + 72), ==, host);
    g_assert_cmpint(ldq_le_p(page + 80), ==, 0);
    g_assert_cmpint(ldq_le_p(page + 56), ==, 0);

    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_READ, 0, buf)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_get_log(&c, FEMU_LOG_FEMU_STATS, buf,
                                         sizeof(page), 0)), ==, NVME_SUCCESS);
    qtest_memread(femu->dev.bus->qts, buf, page, sizeof(page));
    g_assert_cmpint(ldq_le_p(page + 56), >, 0);
    g_assert_cmpint(ldq_le_p(page + 64), ==, 0);

    guest_free(alloc, buf);
    femu_disable(&c);
}

/*
 * The same counters on a device that has a write buffer. Rewriting a page the
 * buffer is still holding owes no extra program, and reading it is answered
 * without the media; both show up as hits, which the unbuffered test above
 * requires to stay at zero.
 */
static void femu_test_buffer_counters(void *obj, void *data,
                                      QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf, pattern;
    uint8_t page[512];
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    buf = guest_alloc(alloc, sizeof(page));
    pattern = guest_alloc(alloc, FEMU_DATA_SIZE);
    qtest_memset(femu->dev.bus->qts, pattern, 0xa5, FEMU_DATA_SIZE);

    /* the same page four times: three of them find it already held */
    for (i = 0; i < 4; i++) {
        g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 0, pattern)), ==,
                        NVME_SUCCESS);
    }
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_READ, 0, pattern)), ==,
                    NVME_SUCCESS);
    guest_free(alloc, pattern);

    g_assert_cmpint(FEMU_SC(femu_get_log(&c, FEMU_LOG_FEMU_STATS, buf,
                                         sizeof(page), 0)), ==, NVME_SUCCESS);
    qtest_memread(femu->dev.bus->qts, buf, page, sizeof(page));

    g_assert_cmpint(ldq_le_p(page + 72), >, 0);
    g_assert_cmpint(ldq_le_p(page + 80), >, 0);
    g_assert_cmpint(ldq_le_p(page + 80), <=, ldq_le_p(page + 72));
    g_assert_cmpint(ldq_le_p(page + 64), >, 0);
    g_assert_cmpint(ldq_le_p(page + 64), <=, ldq_le_p(page + 56));

    guest_free(alloc, buf);
    femu_disable(&c);
}

static uint16_t femu_delete_sq(FemuCtrlState *c, uint16_t qid)
{
    NvmeCmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_DELETE_SQ;
    cmd.cdw10 = cpu_to_le32(qid);
    return femu_admin(c, &cmd);
}

/*
 * Delete a submission queue while its commands are still in flight.
 *
 * The controller frees the queue's request array as part of the delete. A
 * request from that queue can still be sitting in a poller's completion
 * priority queue or in the ring between the poller and the FTL, so the next
 * sweep pops a pointer into freed memory. The test does not assert on the
 * outcome of the outstanding commands -- they are allowed to be lost -- only
 * that the controller survives, which under a sanitizer build means the freed
 * memory was never touched again.
 */
static void femu_test_delete_sq_in_flight(void *obj, void *data,
                                          QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf;
    NvmeRwCmd rw;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    qtest_memset(c.pdev->bus->qts, buf, 0x5a, FEMU_DATA_SIZE);

    /*
     * Fill the queue without collecting any completion, so the commands are
     * still outstanding when the delete arrives.
     */
    for (i = 0; i < FEMU_QSIZE - 2; i++) {
        memset(&rw, 0, sizeof(rw));
        rw.opcode = NVME_CMD_WRITE;
        rw.nsid = cpu_to_le32(1);
        rw.dptr.prp1 = cpu_to_le64(buf);
        rw.slba = cpu_to_le64(8 * i);
        rw.nlb = cpu_to_le16(FEMU_DATA_SIZE / c.lba_size - 1);
        femu_submit(&c, &c.io, (NvmeCmd *)&rw);
    }

    g_assert_cmpint(FEMU_SC(femu_delete_sq(&c, c.io.qid)), ==, NVME_SUCCESS);

    /*
     * Give the pollers a chance to sweep after the free. Without the drain
     * this is where the freed request array is read.
     */
    g_usleep(200000);

    /* the controller is still answering, which is the whole point */
    {
        NvmeCmd cmd;
        uint64_t idbuf = guest_alloc(alloc, 4096);

        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = NVME_ADM_CMD_IDENTIFY;
        cmd.dptr.prp1 = cpu_to_le64(idbuf);
        cmd.cdw10 = cpu_to_le32(NVME_ID_CNS_CTRL);
        g_assert_cmpint(FEMU_SC(femu_admin(&c, &cmd)), ==, NVME_SUCCESS);
        guest_free(alloc, idbuf);
    }

    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * The FTL maps bytes, so an 8 KiB write is two 4 KiB pages whatever the block
 * size, and a placement handle loses one block of writable capacity per block
 * written. Both used to take a block for a 512-byte sector.
 */
typedef struct FemuWideLba {
    uint8_t lbads;
    bool fdp;
} FemuWideLba;

static FemuWideLba femu_wide_4k = { .lbads = 12 };
static FemuWideLba femu_wide_8k = { .lbads = 13 };
static FemuWideLba femu_wide_fdp = { .lbads = 12, .fdp = true };

static uint64_t femu_ruh0_ruamw(FemuCtrlState *c, uint64_t buf)
{
    NvmeCmd cmd;
    uint8_t st[16 + 32];
    uint16_t want, got;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_CMD_IO_MGMT_RECV;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(FEMU_IOMR_RUH_STATUS);
    cmd.cdw11 = cpu_to_le32(sizeof(st) / 4 - 1);
    want = c->cid;
    femu_submit(c, &c->io, &cmd);
    g_assert_cmpint(FEMU_SC(femu_complete(c, &c->io, &got, NULL)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(got, ==, want);
    qtest_memread(c->pdev->bus->qts, buf, st, sizeof(st));
    /* the first descriptor is placement id 0, where unplaced writes go */
    g_assert_cmpint(lduw_le_p(st + 16), ==, 0);
    return ldq_le_p(st + 16 + 8);
}

/* nlb blocks at slba, from the two 4 KiB pages at buf */
static uint16_t femu_write_8k(FemuCtrlState *c, uint64_t buf, uint64_t slba,
                              uint32_t nlb)
{
    NvmeRwCmd rw;
    uint16_t want = c->cid;
    uint16_t got;
    uint16_t status;

    memset(&rw, 0, sizeof(rw));
    rw.opcode = NVME_CMD_WRITE;
    rw.nsid = cpu_to_le32(1);
    rw.dptr.prp1 = cpu_to_le64(buf);
    rw.dptr.prp2 = cpu_to_le64(buf + 4096);
    rw.slba = cpu_to_le64(slba);
    rw.nlb = cpu_to_le16(nlb - 1);
    femu_submit(c, &c->io, (NvmeCmd *)&rw);
    status = femu_complete(c, &c->io, &got, NULL);
    g_assert_cmpint(got, ==, want);
    return FEMU_SC(status);
}

static void femu_test_wide_lba(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    const FemuWideLba *w = data;
    FemuCtrlState c = { 0 };
    uint64_t buf, log;
    uint64_t ruamw = 0;
    uint32_t nlb = 8192 >> w->lbads;
    uint8_t page[512];

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    buf = guest_alloc(alloc, 2 * 4096);
    log = guest_alloc(alloc, sizeof(page));
    if (w->fdp) {
        ruamw = femu_ruh0_ruamw(&c, log);
        /* a unit is one superblock: 16 LUNs of 16 pages of 4 KiB */
        g_assert_cmpint(ruamw, ==, (16ull * 16 * 4096) >> w->lbads);
    }

    /* 8 KiB at block 1, so the first page of the device is not touched */
    qtest_memset(qts, buf, 0x5a, 2 * 4096);
    g_assert_cmpint(femu_write_8k(&c, buf, 1, nlb), ==, NVME_SUCCESS);

    g_assert_cmpint(FEMU_SC(femu_get_log(&c, FEMU_LOG_FEMU_STATS, log,
                                         sizeof(page), 0)), ==, NVME_SUCCESS);
    qtest_memread(qts, log, page, sizeof(page));
    g_assert_cmpint(ldq_le_p(page + 8), ==, 2);
    g_assert_cmpint(ldq_le_p(page + 24), ==, 2);

    if (w->fdp) {
        g_assert_cmpint(femu_ruh0_ruamw(&c, log), ==, ruamw - nlb);
    }

    guest_free(alloc, log);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * An SGL descriptor has its type in the high nibble and a subtype in the low
 * one, and over PCIe only the address subtype exists; a segment is a whole
 * number of 16-byte descriptors. Lists breaking either rule were mapped.
 */
static uint16_t femu_sgl_write(FemuCtrlState *c, const NvmeSglDescriptor *sgl)
{
    NvmeRwCmd rw;
    uint16_t want = c->cid;
    uint16_t got;
    uint16_t status;

    memset(&rw, 0, sizeof(rw));
    rw.opcode = NVME_CMD_WRITE;
    rw.flags = 1 << 6;                      /* PSDT: SGL */
    rw.nsid = cpu_to_le32(1);
    memcpy(&rw.dptr.sgl, sgl, sizeof(*sgl));
    rw.nlb = cpu_to_le16(FEMU_DATA_SIZE / c->lba_size - 1);

    femu_submit(c, &c->io, (NvmeCmd *)&rw);
    status = femu_complete(c, &c->io, &got, NULL);
    g_assert_cmpint(got, ==, want);
    return FEMU_SC(status);
}

static void femu_test_sgl(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    NvmeSglDescriptor blk = { 0 };
    NvmeSglDescriptor seg = { 0 };
    uint64_t buf, list;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    list = guest_alloc(alloc, 4096);
    qtest_memset(qts, buf, 0x5a, FEMU_DATA_SIZE);

    /* one data block, then the same block through a last segment */
    blk.addr = cpu_to_le64(buf);
    blk.len = cpu_to_le32(FEMU_DATA_SIZE);
    g_assert_cmpint(femu_sgl_write(&c, &blk), ==, NVME_SUCCESS);
    qtest_memwrite(qts, list, &blk, sizeof(blk));
    seg.addr = cpu_to_le64(list);
    seg.len = cpu_to_le32(sizeof(blk));
    seg.type = NVME_SGL_DESCR_TYPE_LAST_SEGMENT << 4;
    g_assert_cmpint(femu_sgl_write(&c, &seg), ==, NVME_SUCCESS);

    /* a segment length that is not a whole number of descriptors */
    seg.len = cpu_to_le32(sizeof(blk) + 4);
    g_assert_cmpint(femu_sgl_write(&c, &seg), ==, NVME_INVALID_SGL_SEG_DESCR);
    seg.len = cpu_to_le32(sizeof(blk));

    /* a block shorter than the transfer, with nothing after it */
    blk.len = cpu_to_le32(FEMU_DATA_SIZE / 2);
    g_assert_cmpint(femu_sgl_write(&c, &blk), ==, NVME_DATA_SGL_LEN_INVALID);
    blk.len = cpu_to_le32(FEMU_DATA_SIZE);

    /* the offset subtype, which only fabrics define, directly and listed */
    blk.type = 0x1;
    g_assert_cmpint(femu_sgl_write(&c, &blk), ==, NVME_SGL_DESCR_TYPE_INVALID);
    qtest_memwrite(qts, list, &blk, sizeof(blk));
    g_assert_cmpint(femu_sgl_write(&c, &seg), ==, NVME_SGL_DESCR_TYPE_INVALID);
    seg.type |= 0x1;
    blk.type = 0;
    qtest_memwrite(qts, list, &blk, sizeof(blk));
    g_assert_cmpint(femu_sgl_write(&c, &seg), ==, NVME_SGL_DESCR_TYPE_INVALID);

    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * A handle update moves the handle to a fresh reclaim unit. Only the unit's
 * remaining-writes count used to be reset, while the FTL went on writing into
 * the old unit, so the count ran out of step with the media. Units left part
 * written are then collected like any other.
 */
static void femu_test_fdp_ruh_update(void *obj, void *data,
                                     QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint16_t all[4] = {
        cpu_to_le16(0), cpu_to_le16(1), cpu_to_le16(2), cpu_to_le16(3)
    };
    uint64_t buf, log, pids;
    uint64_t full, i;
    uint8_t page[512];

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    buf = guest_alloc(alloc, 2 * 4096);
    log = guest_alloc(alloc, 4096);
    pids = guest_alloc(alloc, 4096);
    qtest_memset(qts, buf, 0x5a, 2 * 4096);
    qtest_memwrite(qts, pids, all, sizeof(all));

    full = femu_ruh0_ruamw(&c, log);
    g_assert_cmpint(femu_write_8k(&c, buf, 0, 2), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ruh0_ruamw(&c, log), ==, full - 2);

    /* every handle at once, which the advertised count allows */
    g_assert_cmpint(femu_ruh_update(&c, pids, 4), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ruh0_ruamw(&c, log), ==, full);

    /* the old unit had room for all of these; the new one keeps two blocks */
    for (i = 2; i < full; i += 2) {
        g_assert_cmpint(femu_write_8k(&c, buf, i, 2), ==, NVME_SUCCESS);
    }
    g_assert_cmpint(femu_ruh0_ruamw(&c, log), ==, 2);

    /* one block per unit, until collection has to take those units back */
    for (i = 0; i < 100; i++) {
        g_assert_cmpint(femu_write_8k(&c, buf, full + i, 1), ==,
                        NVME_SUCCESS);
        g_assert_cmpint(femu_ruh_update(&c, pids, 1), ==, NVME_SUCCESS);
    }
    g_assert_cmpint(FEMU_SC(femu_get_log(&c, FEMU_LOG_FEMU_STATS, log,
                                         sizeof(page), 0)), ==, NVME_SUCCESS);
    qtest_memread(qts, log, page, sizeof(page));
    g_assert_cmpint(ldq_le_p(page + 16), >, 0);

    guest_free(alloc, pids);
    guest_free(alloc, log);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * With collection held off until no unit is free, an update eventually finds
 * none to move to. It must then fail: it used to report success and leave the
 * handle writing into the unit it had been asked to leave.
 */
static void femu_test_fdp_ruh_update_full(void *obj, void *data,
                                          QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint16_t pid0 = cpu_to_le16(0);
    uint64_t buf, log, pids;
    uint64_t full, i;
    uint16_t sc = NVME_SUCCESS;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    buf = guest_alloc(alloc, 2 * 4096);
    log = guest_alloc(alloc, 4096);
    pids = guest_alloc(alloc, 4096);
    qtest_memset(qts, buf, 0x5a, 2 * 4096);
    qtest_memwrite(qts, pids, &pid0, sizeof(pid0));
    full = femu_ruh0_ruamw(&c, log);

    for (i = 0; i < 4096; i++) {
        g_assert_cmpint(femu_write_8k(&c, buf, i, 1), ==, NVME_SUCCESS);
        sc = femu_ruh_update(&c, pids, 1);
        if (sc != NVME_SUCCESS) {
            break;
        }
        g_assert_cmpint(femu_ruh0_ruamw(&c, log), ==, full);
    }
    g_assert_cmpint(sc, ==, NVME_CAP_EXCEEDED);

    guest_free(alloc, pids);
    guest_free(alloc, log);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * A Zone Append reads the zone's write pointer to decide where it lands and
 * then moves it. On queues that different pollers serve, two of them read the
 * same pointer unless the zone state is held still, and the controller reports
 * the same blocks to both: one write is lost. Appending from two queues at
 * once reported a duplicate on half the runs before the zone state took a
 * lock.
 */
/* entries per queue, so 255 commands can be in flight on each */
#define ZAP_QDEPTH  256
#define ZAP_PER_Q   (ZAP_QDEPTH - 1)
#define ZAP_ROUNDS  150

/*
 * A queue pair of its own depth, deep enough to keep a poller working while
 * the other one is given its own batch. The shared helpers are fixed at
 * FEMU_QSIZE entries, so this test carries its own submit and collect.
 */
static void femu_zap_create_queue(FemuCtrlState *c, FemuQueue *q, uint16_t qid)
{
    NvmeCmd cmd;

    q->qid = qid;
    q->sq_addr = guest_alloc(c->alloc, ZAP_QDEPTH * sizeof(NvmeCmd));
    q->cq_addr = guest_alloc(c->alloc, ZAP_QDEPTH * sizeof(NvmeCqe));
    q->sq_tail = 0;
    q->cq_head = 0;
    q->phase = 1;
    qtest_memset(c->pdev->bus->qts, q->cq_addr, 0,
                 ZAP_QDEPTH * sizeof(NvmeCqe));

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_CREATE_CQ;
    cmd.dptr.prp1 = cpu_to_le64(q->cq_addr);
    cmd.cdw10 = cpu_to_le32(((ZAP_QDEPTH - 1) << 16) | qid);
    cmd.cdw11 = cpu_to_le32(NVME_CQ_PC);
    g_assert_cmpint(femu_admin(c, &cmd), ==, NVME_SUCCESS);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_CREATE_SQ;
    cmd.dptr.prp1 = cpu_to_le64(q->sq_addr);
    cmd.cdw10 = cpu_to_le32(((ZAP_QDEPTH - 1) << 16) | qid);
    cmd.cdw11 = cpu_to_le32((qid << 16) | NVME_SQ_PC);
    g_assert_cmpint(femu_admin(c, &cmd), ==, NVME_SUCCESS);
}

/* collect one completion from a deep queue and hand back dword 0 */
static uint16_t femu_zap_complete(FemuCtrlState *c, FemuQueue *q,
                                  uint32_t *result)
{
    uint64_t slot = q->cq_addr + q->cq_head * sizeof(NvmeCqe);
    NvmeCqe cqe, again;
    int waited = 0;

    for (;;) {
        qtest_memread(c->pdev->bus->qts, slot, &cqe, sizeof(cqe));
        if ((le16_to_cpu(cqe.status) & 1) == q->phase) {
            qtest_memread(c->pdev->bus->qts, slot, &again, sizeof(again));
            if (memcmp(&cqe, &again, sizeof(cqe)) == 0) {
                break;
            }
        }
        g_assert_cmpint(waited, <, FEMU_POLL_LIMIT_MS);
        g_usleep(1000);
        waited++;
    }

    if (result) {
        *result = le32_to_cpu(cqe.result);
    }
    q->cq_head = (q->cq_head + 1) % ZAP_QDEPTH;
    if (q->cq_head == 0) {
        q->phase ^= 1;
    }
    qpci_io_writel(c->pdev, c->bar, femu_cq_doorbell(c, q->qid), q->cq_head);

    return FEMU_SC(le16_to_cpu(cqe.status) >> 1);
}

/* queue a command without ringing, so a whole batch can start at once */
static void femu_zap_queue(FemuCtrlState *c, FemuQueue *q, NvmeCmd *cmd)
{
    cmd->cid = cpu_to_le16(c->cid++);
    qtest_memwrite(c->pdev->bus->qts,
                   q->sq_addr + q->sq_tail * sizeof(NvmeCmd), cmd,
                   sizeof(*cmd));
    q->sq_tail = (q->sq_tail + 1) % ZAP_QDEPTH;
}

static void femu_zap_ring(FemuCtrlState *c, FemuQueue *q)
{
    qpci_io_writel(c->pdev, c->bar, femu_sq_doorbell(c, q->qid), q->sq_tail);
}

static void femu_test_zone_append_parallel(void *obj, void *data,
                                           QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    FemuQueue q1, q2;
    NvmeCmd cmd;
    uint64_t buf;
    uint32_t *seen = g_new(uint32_t, 2 * ZAP_PER_Q);
    int round, i, j;

    femu_enable(&c, &femu->dev, alloc);
    femu_zap_create_queue(&c, &q1, 1);
    femu_zap_create_queue(&c, &q2, 2);

    buf = guest_alloc(alloc, 4096);
    qtest_memset(qts, buf, 0x5a, 4096);

    for (round = 0; round < ZAP_ROUNDS; round++) {
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = NVME_CMD_ZONE_APPEND;
        cmd.nsid = cpu_to_le32(1);
        cmd.dptr.prp1 = cpu_to_le64(buf);
        cmd.cdw10 = 0;                 /* zone 0 starts at LBA 0 */
        cmd.cdw11 = 0;
        cmd.cdw12 = 0;                 /* one block */

        for (i = 0; i < ZAP_PER_Q; i++) {
            femu_zap_queue(&c, &q1, &cmd);
            femu_zap_queue(&c, &q2, &cmd);
        }
        femu_zap_ring(&c, &q1);
        femu_zap_ring(&c, &q2);
        for (i = 0; i < ZAP_PER_Q; i++) {
            uint32_t r1 = 0, r2 = 0;

            g_assert_cmpint(femu_zap_complete(&c, &q1, &r1), ==, NVME_SUCCESS);
            g_assert_cmpint(femu_zap_complete(&c, &q2, &r2), ==, NVME_SUCCESS);
            seen[2 * i] = r1;
            seen[2 * i + 1] = r2;
        }
        /* every append must have been placed on a block of its own */
        for (i = 0; i < 2 * ZAP_PER_Q; i++) {
            for (j = i + 1; j < 2 * ZAP_PER_Q; j++) {
                if (seen[i] == seen[j]) {
                    g_test_message("round %d: appends %d and %d both at %u",
                                   round, i, j, seen[i]);
                }
                g_assert_cmpint(seen[i], !=, seen[j]);
            }
            g_assert_cmpint(seen[i], <, 2 * ZAP_PER_Q);
        }
        /* start the next round from an empty zone, well short of capacity */
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = NVME_CMD_ZONE_MGMT_SEND;
        cmd.nsid = cpu_to_le32(1);
        cmd.cdw13 = cpu_to_le32(NVME_ZONE_ACTION_RESET);
        femu_zap_queue(&c, &q1, &cmd);
        femu_zap_ring(&c, &q1);
        g_assert_cmpint(femu_zap_complete(&c, &q1, NULL), ==, NVME_SUCCESS);
    }

    g_free(seen);
    guest_free(alloc, buf);
    femu_queue_free(&c, &q2);
    femu_queue_free(&c, &q1);
    femu_disable(&c);
}

/*
 * A host finds the Key Value command set by asking which sets the controller
 * has, then what the commands of that set do. Neither answered: the set was
 * missing from the list, and its effects log came back with no command
 * supported at all, which is a host's cue to issue none of them.
 */
static void femu_test_kv_discovery(void *obj, void *data,
                                   QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd;
    uint64_t buf;
    uint8_t sets[8];
    uint32_t eff;

    c.pdev = &femu->dev;
    c.alloc = alloc;
    femu_queue_init(&c, &c.admin, 0);
    /* enable with a command set selected, which is how anything but NVM runs */
    femu_enable_cc(&c, &femu->dev, alloc,
                   (6 << 16) | (4 << 20) | (FEMU_CC_CSS_CSI << 4) | 1);

    buf = guest_alloc(alloc, 4096);
    qtest_memset(qts, buf, 0, 4096);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_IDENTIFY;
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(FEMU_CNS_IO_CMD_SET);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, sets, sizeof(sets));
    /* one bit per command set identifier: NVM, key value, zoned */
    g_assert_cmpint(sets[0] & 0x7, ==, 0x7);

    qtest_memset(qts, buf, 0, 4096);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_GET_LOG_PAGE;
    cmd.nsid = cpu_to_le32(NVME_NSID_BROADCAST);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(FEMU_LOG_CMD_EFFECTS | ((1024 - 1) << 16));
    cmd.cdw14 = cpu_to_le32(FEMU_CSI_KV << 24);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);

    /* the per-command entries follow the 256 admin ones */
#define FEMU_KV_EFF(op) \
    ({ qtest_memread(qts, buf + 1024 + 4 * (op), &eff, sizeof(eff)); \
       le32_to_cpu(eff); })
    /* supported, and the two that replace or remove a value change data */
    g_assert_cmpint(FEMU_KV_EFF(FEMU_KV_CMD_STORE), ==, 0x3);
    g_assert_cmpint(FEMU_KV_EFF(FEMU_KV_CMD_RETRIEVE), ==, 0x1);
    g_assert_cmpint(FEMU_KV_EFF(FEMU_KV_CMD_LIST), ==, 0x1);
    g_assert_cmpint(FEMU_KV_EFF(FEMU_KV_CMD_DELETE), ==, 0x3);
    g_assert_cmpint(FEMU_KV_EFF(FEMU_KV_CMD_EXIST), ==, 0x1);
#undef FEMU_KV_EFF

    guest_free(alloc, buf);
    femu_disable(&c);
}

/*
 * Write Zeroes without the deallocate bit leaves the blocks holding written
 * zeros, so the device owes the programs that put them there. The placement
 * path returned without touching the media at all, so the command cost
 * nothing and counted nothing, while the ordinary path programmed the range.
 */
static void femu_test_fdp_write_zeroes(void *obj, void *data,
                                       QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    NvmeRwCmd rw;
    uint64_t buf;
    uint8_t page[512];
    uint64_t host_before, nand_before, host_after, nand_after;
    uint32_t blocks = 32;               /* 32 blocks of 4 KiB is 32 pages */
    uint16_t want, got;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    c.lba_size = 4096;

    buf = guest_alloc(alloc, 4096);
    g_assert_cmpint(FEMU_SC(femu_get_log(&c, FEMU_LOG_FEMU_STATS, buf,
                                         sizeof(page), 0)), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, page, sizeof(page));
    host_before = ldq_le_p(page + 8);
    nand_before = ldq_le_p(page + 24);

    /* no deallocate bit: the blocks keep written zeros */
    memset(&rw, 0, sizeof(rw));
    rw.opcode = NVME_CMD_WRITE_ZEROES;
    rw.nsid = cpu_to_le32(1);
    rw.slba = cpu_to_le64(0);
    rw.nlb = cpu_to_le16(blocks - 1);
    want = c.cid;
    femu_submit(&c, &c.io, (NvmeCmd *)&rw);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(got, ==, want);

    g_assert_cmpint(FEMU_SC(femu_get_log(&c, FEMU_LOG_FEMU_STATS, buf,
                                         sizeof(page), 0)), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, page, sizeof(page));
    host_after = ldq_le_p(page + 8);
    nand_after = ldq_le_p(page + 24);

    /* one page per block, programmed and counted like any other write */
    g_assert_cmpint(host_after - host_before, ==, blocks);
    g_assert_cmpint(nand_after - nand_before, ==, blocks);

    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * Submission queues 1 and 2 both report to completion queue 1, and there is no
 * completion queue 2 (Base 2.3, 3.3.1). The second queue has to be served
 * anyway, and its completions have to land in queue 1 naming queue 2.
 */
static void femu_test_shared_cq(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    FemuQueue sq2;
    NvmeRwCmd rw;
    NvmeCmd cmd;
    NvmeCqe cqe;
    uint64_t buf;
    uint8_t *wbuf = g_malloc(FEMU_DATA_SIZE);
    uint8_t *rbuf = g_malloc0(FEMU_DATA_SIZE);
    uint16_t want;
    uint16_t got;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_queue_init(&c, &sq2, 2);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_CREATE_SQ;
    cmd.dptr.prp1 = cpu_to_le64(sq2.sq_addr);
    cmd.cdw10 = cpu_to_le32(((FEMU_QSIZE - 1) << 16) | sq2.qid);
    cmd.cdw11 = cpu_to_le32((c.io.qid << 16) | NVME_SQ_PC);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);

    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    for (i = 0; i < FEMU_DATA_SIZE; i++) {
        wbuf[i] = (uint8_t)(i * 13 + 5);
    }
    qtest_memwrite(qts, buf, wbuf, FEMU_DATA_SIZE);

    memset(&rw, 0, sizeof(rw));
    rw.opcode = NVME_CMD_WRITE;
    rw.nsid = cpu_to_le32(1);
    rw.dptr.prp1 = cpu_to_le64(buf);
    rw.slba = cpu_to_le64(64);
    rw.nlb = cpu_to_le16(FEMU_DATA_SIZE / c.lba_size - 1);
    want = c.cid;
    femu_submit(&c, &sq2, (NvmeCmd *)&rw);
    qtest_memread(qts, c.io.cq_addr + c.io.cq_head * sizeof(NvmeCqe), &cqe,
                  sizeof(cqe));
    g_assert_cmpint(femu_complete(&c, &c.io, &got, NULL), ==, NVME_SUCCESS);
    g_assert_cmpint(got, ==, want);
    qtest_memread(qts, c.io.cq_addr +
                  ((c.io.cq_head + FEMU_QSIZE - 1) % FEMU_QSIZE) *
                  sizeof(NvmeCqe), &cqe, sizeof(cqe));
    g_assert_cmpint(le16_to_cpu(cqe.sq_id), ==, sq2.qid);

    /* and what went in through queue 2 reads back through queue 1 */
    qtest_memset(qts, buf, 0, FEMU_DATA_SIZE);
    g_assert_cmpint(femu_rw(&c, NVME_CMD_READ, 64, buf), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, rbuf, FEMU_DATA_SIZE);
    g_assert_cmpint(memcmp(wbuf, rbuf, FEMU_DATA_SIZE), ==, 0);

    g_assert_cmpint(femu_delete_sq(&c, sq2.qid), ==, NVME_SUCCESS);
    guest_free(alloc, buf);
    femu_queue_free(&c, &sq2);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    g_free(rbuf);
    g_free(wbuf);
}

/*
 * Check a completion queue of FEMU_SMALL_CQ entries that the host has not
 * read from, after more commands than it can hold were submitted: it holds
 * one entry fewer than its size, the first commands in order, and the last
 * slot untouched (Base 2.3, 3.3.1.2.1). Then read it one entry at a time,
 * returning each slot, and expect every command to complete in order.
 */
#define FEMU_SMALL_CQ   4

static void femu_check_held_back(FemuCtrlState *c, uint64_t cq_addr,
                                 uint16_t qid, uint16_t first_cid, int total)
{
    QTestState *qts = c->pdev->bus->qts;
    uint16_t head = 0;
    uint8_t phase = 1;
    NvmeCqe cqe;
    int waited = 0;
    int i;

    /* wait for the entries that fit, then give the rest time to overrun */
    for (;;) {
        qtest_memread(qts, cq_addr + (FEMU_SMALL_CQ - 2) * sizeof(cqe), &cqe,
                      sizeof(cqe));
        if (le16_to_cpu(cqe.status) & 1) {
            break;
        }
        g_assert_cmpint(waited, <, FEMU_POLL_LIMIT_MS);
        g_usleep(1000);
        waited++;
    }
    g_usleep(200 * 1000);

    for (i = 0; i < FEMU_SMALL_CQ - 1; i++) {
        qtest_memread(qts, cq_addr + i * sizeof(cqe), &cqe, sizeof(cqe));
        g_assert_cmpint(le16_to_cpu(cqe.status) & 1, ==, 1);
        g_assert_cmpint(le16_to_cpu(cqe.cid), ==, first_cid + i);
    }
    qtest_memread(qts, cq_addr + (FEMU_SMALL_CQ - 1) * sizeof(cqe), &cqe,
                  sizeof(cqe));
    g_assert_cmpint(le16_to_cpu(cqe.status), ==, 0);
    g_assert_cmpint(le16_to_cpu(cqe.cid), ==, 0);

    for (i = 0; i < total; i++) {
        uint64_t slot = cq_addr + head * sizeof(cqe);

        waited = 0;
        for (;;) {
            qtest_memread(qts, slot, &cqe, sizeof(cqe));
            if ((le16_to_cpu(cqe.status) & 1) == phase) {
                break;
            }
            g_assert_cmpint(waited, <, FEMU_POLL_LIMIT_MS);
            g_usleep(1000);
            waited++;
        }
        g_assert_cmpint(le16_to_cpu(cqe.cid), ==, first_cid + i);
        g_assert_cmpint(le16_to_cpu(cqe.status) >> 1, ==, NVME_SUCCESS);
        head = (head + 1) % FEMU_SMALL_CQ;
        if (head == 0) {
            phase ^= 1;
        }
        qpci_io_writel(c->pdev, c->bar, femu_cq_doorbell(c, qid), head);
    }
}

static void femu_test_cq_full(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { .acq_entries = FEMU_SMALL_CQ };
    const int total = 8;
    uint64_t buf;
    uint16_t first;
    NvmeCmd cmd;
    int i;

    /* the admin queue: sixteen submission entries, four completion entries */
    femu_enable(&c, &femu->dev, alloc);
    buf = guest_alloc(alloc, 4096);
    first = c.cid;
    for (i = 0; i < total; i++) {
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = NVME_ADM_CMD_IDENTIFY;
        cmd.dptr.prp1 = cpu_to_le64(buf);
        cmd.cdw10 = cpu_to_le32(NVME_ID_CNS_CTRL);
        femu_submit(&c, &c.admin, &cmd);
    }
    femu_check_held_back(&c, c.admin.cq_addr, 0, first, total);
    femu_disable(&c);

    /* an I/O queue pair of the same shape */
    memset(&c, 0, sizeof(c));
    femu_enable(&c, &femu->dev, alloc);
    femu_queue_init(&c, &c.io, 1);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_CREATE_CQ;
    cmd.dptr.prp1 = cpu_to_le64(c.io.cq_addr);
    cmd.cdw10 = cpu_to_le32(((FEMU_SMALL_CQ - 1) << 16) | c.io.qid);
    cmd.cdw11 = cpu_to_le32(NVME_CQ_PC);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_CREATE_SQ;
    cmd.dptr.prp1 = cpu_to_le64(c.io.sq_addr);
    cmd.cdw10 = cpu_to_le32(((FEMU_QSIZE - 1) << 16) | c.io.qid);
    cmd.cdw11 = cpu_to_le32((c.io.qid << 16) | NVME_SQ_PC);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);

    qtest_memset(qts, c.io.cq_addr, 0, FEMU_QSIZE * sizeof(NvmeCqe));
    first = c.cid;
    for (i = 0; i < total; i++) {
        NvmeRwCmd rw;

        memset(&rw, 0, sizeof(rw));
        rw.opcode = NVME_CMD_READ;
        rw.nsid = cpu_to_le32(1);
        rw.dptr.prp1 = cpu_to_le64(buf);
        rw.slba = cpu_to_le64(i * 8);
        rw.nlb = cpu_to_le16(7);
        femu_submit(&c, &c.io, (NvmeCmd *)&rw);
    }
    femu_check_held_back(&c, c.io.cq_addr, c.io.qid, first, total);

    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/* one queue pair whose completion queue interrupts on the given vector */
static void femu_create_io_queues_irq(FemuCtrlState *c, uint16_t vector)
{
    NvmeCmd cmd;

    femu_queue_init(c, &c->io, 1);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_CREATE_CQ;
    cmd.dptr.prp1 = cpu_to_le64(c->io.cq_addr);
    cmd.cdw10 = cpu_to_le32(((FEMU_QSIZE - 1) << 16) | c->io.qid);
    cmd.cdw11 = cpu_to_le32((vector << 16) | NVME_CQ_PC | FEMU_CQ_IEN);
    g_assert_cmpint(femu_admin(c, &cmd), ==, NVME_SUCCESS);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_CREATE_SQ;
    cmd.dptr.prp1 = cpu_to_le64(c->io.sq_addr);
    cmd.cdw10 = cpu_to_le32(((FEMU_QSIZE - 1) << 16) | c->io.qid);
    cmd.cdw11 = cpu_to_le32((c->io.qid << 16) | NVME_SQ_PC);
    g_assert_cmpint(femu_admin(c, &cmd), ==, NVME_SUCCESS);
}

/* submit one read on the I/O queue and wait for its entry, unconsumed */
static void femu_read_unconsumed(FemuCtrlState *c, uint64_t buf)
{
    uint64_t slot = c->io.cq_addr + c->io.cq_head * sizeof(NvmeCqe);
    NvmeRwCmd rw;
    uint16_t status;
    int waited = 0;

    memset(&rw, 0, sizeof(rw));
    rw.opcode = NVME_CMD_READ;
    rw.nsid = cpu_to_le32(1);
    rw.dptr.prp1 = cpu_to_le64(buf);
    rw.nlb = cpu_to_le16(7);
    femu_submit(c, &c->io, (NvmeCmd *)&rw);

    for (;;) {
        status = qtest_readw(c->pdev->bus->qts, slot + 14);
        if ((le16_to_cpu(status) & 1) == c->io.phase) {
            break;
        }
        g_assert_cmpint(waited, <, FEMU_POLL_LIMIT_MS);
        g_usleep(1000);
        waited++;
    }
}

static bool femu_intx_asserted(FemuCtrlState *c)
{
    return qpci_config_readw(c->pdev, PCI_STATUS) & PCI_STATUS_INTERRUPT;
}

/* wait for a condition the main loop makes true from a bottom half */
#define FEMU_WAIT_FOR(cond)                                 \
    do {                                                    \
        int waited_ = 0;                                    \
        while (!(cond)) {                                   \
            g_assert_cmpint(waited_, <, FEMU_POLL_LIMIT_MS); \
            g_usleep(1000);                                 \
            waited_++;                                      \
        }                                                   \
    } while (0)

/*
 * I/O completions interrupt the host without a KVM route of their own, by
 * each of the three mechanisms the device offers: the pin, which is level
 * triggered and masked by INTMS; MSI, held back while INTMS masks its vector;
 * and MSI-X, which records a masked vector as pending.
 */
static void femu_test_io_interrupts(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QPCIDevice *dev = &femu->dev;
    QTestState *qts = dev->bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf;
    uint64_t msi_addr;
    uint8_t msi;
    uint16_t flags;

    /* pin based */
    femu_enable(&c, dev, alloc);
    buf = guest_alloc(alloc, 4096);
    femu_create_io_queues_irq(&c, 0);
    g_assert_false(femu_intx_asserted(&c));
    femu_read_unconsumed(&c, buf);
    FEMU_WAIT_FOR(femu_intx_asserted(&c));
    qpci_io_writel(dev, c.bar, 0xc, 1);         /* INTMS */
    g_assert_false(femu_intx_asserted(&c));
    qpci_io_writel(dev, c.bar, 0x10, 1);        /* INTMC */
    g_assert_true(femu_intx_asserted(&c));
    g_assert_cmpint(femu_complete(&c, &c.io, NULL, NULL), ==, NVME_SUCCESS);
    g_assert_false(femu_intx_asserted(&c));
    femu_queue_free(&c, &c.io);
    femu_disable(&c);

    /* MSI, one vector, delivered into guest memory the test can read */
    msi = qpci_find_capability(dev, PCI_CAP_ID_MSI, 0);
    g_assert_cmpint(msi, !=, 0);
    msi_addr = guest_alloc(alloc, 4096);
    qtest_writel(qts, msi_addr, 0);
    qpci_config_writel(dev, msi + PCI_MSI_ADDRESS_LO, (uint32_t)msi_addr);
    qpci_config_writel(dev, msi + PCI_MSI_ADDRESS_HI, msi_addr >> 32);
    qpci_config_writew(dev, msi + PCI_MSI_DATA_64, 0x4321);
    flags = qpci_config_readw(dev, msi + PCI_MSI_FLAGS);
    qpci_config_writew(dev, msi + PCI_MSI_FLAGS,
                       (flags & ~PCI_MSI_FLAGS_QSIZE) | PCI_MSI_FLAGS_ENABLE);

    memset(&c, 0, sizeof(c));
    femu_enable(&c, dev, alloc);
    femu_create_io_queues_irq(&c, 0);
    qpci_io_writel(dev, c.bar, 0xc, 1);         /* INTMS */
    qtest_writel(qts, msi_addr, 0);
    femu_read_unconsumed(&c, buf);
    g_usleep(100 * 1000);
    g_assert_cmphex(qtest_readl(qts, msi_addr), ==, 0);
    qpci_io_writel(dev, c.bar, 0x10, 1);        /* INTMC */
    g_assert_cmphex(qtest_readl(qts, msi_addr), ==, 0x4321);
    qtest_writel(qts, msi_addr, 0);
    g_assert_cmpint(femu_complete(&c, &c.io, NULL, NULL), ==, NVME_SUCCESS);
    femu_read_unconsumed(&c, buf);
    FEMU_WAIT_FOR(qtest_readl(qts, msi_addr) == 0x4321);
    g_assert_cmpint(femu_complete(&c, &c.io, NULL, NULL), ==, NVME_SUCCESS);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    flags = qpci_config_readw(dev, msi + PCI_MSI_FLAGS);
    qpci_config_writew(dev, msi + PCI_MSI_FLAGS,
                       flags & ~PCI_MSI_FLAGS_ENABLE);

    /* MSI-X with the function masked, so a notification shows as pending */
    qpci_msix_enable(dev);
    flags = qpci_config_readw(dev, qpci_find_capability(dev, PCI_CAP_ID_MSIX,
                                                        0) + PCI_MSIX_FLAGS);
    qpci_config_writew(dev, qpci_find_capability(dev, PCI_CAP_ID_MSIX, 0) +
                       PCI_MSIX_FLAGS, flags | PCI_MSIX_FLAGS_MASKALL);
    memset(&c, 0, sizeof(c));
    femu_enable(&c, dev, alloc);
    femu_create_io_queues_irq(&c, 1);
    g_assert_false(qpci_msix_pending(dev, 1));
    femu_read_unconsumed(&c, buf);
    FEMU_WAIT_FOR(qpci_msix_pending(dev, 1));
    g_assert_cmpint(femu_complete(&c, &c.io, NULL, NULL), ==, NVME_SUCCESS);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    qpci_msix_disable(dev);

    guest_free(alloc, msi_addr);
    guest_free(alloc, buf);
}

/* guest-physical memory nothing answers at */
#define FEMU_UNBACKED_GPA   0xffffffff00000000ULL

/*
 * A transfer whose data pointer names memory that is not there fails with
 * Data Transfer Error (Base 2.3, Generic Command Status 04h). It used to
 * complete with a status code of zero, which the host reads as success. On a
 * zoned namespace the failed write still consumes its blocks, so the next
 * write lands where the write pointer moved to.
 */
static void femu_test_dma_error(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    bool zoned = data && *(bool *)data;
    uint64_t buf;
    uint16_t status;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);

    status = femu_rw(&c, NVME_CMD_WRITE, 0, FEMU_UNBACKED_GPA);
    g_assert_cmphex(FEMU_SC(status), ==, NVME_DATA_TRAS_ERROR);
    g_assert_cmphex(status & NVME_DNR, ==, NVME_DNR);
    status = femu_rw(&c, NVME_CMD_READ, 0, FEMU_UNBACKED_GPA);
    g_assert_cmphex(FEMU_SC(status), ==, NVME_DATA_TRAS_ERROR);

    if (zoned) {
        g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE, 8, buf), ==, NVME_SUCCESS);
    } else {
        femu_round_trip(&c, 4);
    }

    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static bool femu_zoned = true;

#define FEMU_FEAT_FDP           0x1d
#define FEMU_FEAT_FDP_EVENTS    0x1e
#define FEMU_ID_CTRL_ENDGIDMAX  340
#define FEMU_ID_NS_ENDGID       102

/* the host events log's count, and the placement handle of its last entry */
static uint32_t femu_fdp_host_events(FemuCtrlState *c, uint64_t log,
                                     uint16_t *last_ph)
{
    QTestState *qts = c->pdev->bus->qts;
    uint8_t buf[64 + 8 * 64];
    uint32_t numd = sizeof(buf) / 4 - 1;
    uint32_t count;
    NvmeCmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_GET_LOG_PAGE;
    cmd.nsid = cpu_to_le32(NVME_NSID_BROADCAST);
    cmd.dptr.prp1 = cpu_to_le64(log);
    cmd.cdw10 = cpu_to_le32(FEMU_LOG_FDP_EVENTS | (1 << 8) |
                            ((numd & 0xffff) << 16));
    cmd.cdw11 = cpu_to_le32(1 << 16);
    g_assert_cmpint(femu_admin(c, &cmd), ==, NVME_SUCCESS);
    qtest_memread(qts, log, buf, sizeof(buf));
    count = ldl_le_p(buf);
    if (count && last_ph) {
        *last_ph = lduw_le_p(buf + 64 + (MIN(count, 8) - 1) * 64 + 2);
    }
    return count;
}

/*
 * What a host needs to turn Flexible Data Placement on (Base 2.3, 5.2.26.1.20
 * and .21): the endurance group in Identify, feature 1Dh reporting FDPE for
 * it, and feature 1Eh taking one-byte event types in its buffer with the count
 * in dword 11 and the enable bit in dword 12. Linux reads 1Dh with the
 * namespace's endurance group before it uses any placement handle.
 */
static void femu_test_fdp_features(void *obj, void *data,
                                   QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint16_t list[2] = { cpu_to_le16(0), cpu_to_le16(1) };
    uint8_t descr[16];
    uint64_t buf, log, pids;
    uint32_t result;
    uint32_t before;
    uint16_t ph;
    NvmeCmd cmd;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, 4096);
    log = guest_alloc(alloc, 4096);
    pids = guest_alloc(alloc, 4096);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_IDENTIFY;
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(NVME_ID_CNS_CTRL);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    g_assert_cmpint(qtest_readw(qts, buf + FEMU_ID_CTRL_ENDGIDMAX), ==, 1);
    cmd.nsid = cpu_to_le32(1);
    cmd.cdw10 = cpu_to_le32(NVME_ID_CNS_NS);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    g_assert_cmpint(qtest_readw(qts, buf + FEMU_ID_NS_ENDGID), ==, 1);

    /* 1Dh: enabled now and in the saved value, disabled by default */
    g_assert_cmpint(femu_get_feature(&c, FEMU_FEAT_FDP, 0, 0, 1, &result),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(result & 1, ==, 1);
    g_assert_cmpint(femu_get_feature(&c, FEMU_FEAT_FDP, 2, 0, 1, &result),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(result & 1, ==, 1);
    g_assert_cmpint(femu_get_feature(&c, FEMU_FEAT_FDP, 1, 0, 1, &result),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(result, ==, 0);
    g_assert_cmpint(FEMU_SC(femu_get_feature(&c, FEMU_FEAT_FDP, 0, 0, 2,
                                             &result)),
                    ==, NVME_INVALID_FIELD);
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, FEMU_FEAT_FDP, false, 0, 1,
                                             &result)),
                    ==, NVME_CMD_SEQ_ERROR);

    /* 1Eh: every supported type, ascending, with its enable bit */
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_GET_FEATURES;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(FEMU_FEAT_FDP_EVENTS);
    cmd.cdw11 = cpu_to_le32(0);
    g_assert_cmpint(femu_admin_result(&c, &cmd, &result), ==, NVME_SUCCESS);
    g_assert_cmpint(result, >=, 2);
    g_assert_cmpint(result, <=, sizeof(descr) / 2);
    qtest_memread(qts, buf, descr, result * 2);
    for (i = 1; i < result; i++) {
        g_assert_cmpint(descr[2 * i], >, descr[2 * (i - 1)]);
    }
    g_assert_cmpint(descr[0], ==, FEMU_FDP_EVT_RU_NOT_FULLY_WRITTEN);
    g_assert_cmpint(descr[1] & 1, ==, 1);

    cmd.nsid = cpu_to_le32(NVME_NSID_BROADCAST);
    g_assert_cmpint(FEMU_SC(femu_admin(&c, &cmd)), ==, NVME_INVALID_FIELD);
    cmd.nsid = cpu_to_le32(1);
    cmd.cdw11 = cpu_to_le32(99);
    g_assert_cmpint(FEMU_SC(femu_admin(&c, &cmd)), ==, NVME_INVALID_FIELD);

    /* disable one type on placement handle 0 and only that handle */
    qtest_writeb(qts, buf, FEMU_FDP_EVT_RU_NOT_FULLY_WRITTEN);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_SET_FEATURES;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(FEMU_FEAT_FDP_EVENTS);
    cmd.cdw11 = cpu_to_le32((1 << 16) | 0);
    cmd.cdw12 = cpu_to_le32(0);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_GET_FEATURES;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(FEMU_FEAT_FDP_EVENTS);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    g_assert_cmpint(qtest_readb(qts, buf + 1) & 1, ==, 0);
    cmd.cdw11 = cpu_to_le32(1);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    g_assert_cmpint(qtest_readb(qts, buf + 1) & 1, ==, 1);

    /*
     * Moving both handles now reports only the one still enabled. Tests with
     * the same options share a subsystem, so count from where the log is.
     */
    before = femu_fdp_host_events(&c, log, NULL);
    qtest_memwrite(qts, pids, list, sizeof(list));
    g_assert_cmpint(femu_ruh_update(&c, pids, 2), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_fdp_host_events(&c, log, &ph), ==, before + 1);
    g_assert_cmpint(ph, ==, 1);

    /* and put the handle back the way the next test expects it */
    qtest_writeb(qts, buf, FEMU_FDP_EVT_RU_NOT_FULLY_WRITTEN);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_SET_FEATURES;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(FEMU_FEAT_FDP_EVENTS);
    cmd.cdw11 = cpu_to_le32(1 << 16);
    cmd.cdw12 = cpu_to_le32(1);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);

    guest_free(alloc, pids);
    guest_free(alloc, log);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

#define FEMU_PRP_PAGES      40
#define FEMU_PRP_LIST_OFF   0xf00

/* one transfer of FEMU_PRP_PAGES pages described by the list set up below */
static uint16_t femu_prp_list_rw(FemuCtrlState *c, uint8_t opcode,
                                 uint64_t first, uint64_t list)
{
    NvmeRwCmd rw;
    uint16_t want = c->cid;
    uint16_t got;
    uint16_t status;

    memset(&rw, 0, sizeof(rw));
    rw.opcode = opcode;
    rw.nsid = cpu_to_le32(1);
    rw.dptr.prp1 = cpu_to_le64(first);
    rw.dptr.prp2 = cpu_to_le64(list);
    rw.slba = cpu_to_le64(0);
    rw.nlb = cpu_to_le16(FEMU_PRP_PAGES * 4096 / c->lba_size - 1);
    femu_submit(c, &c->io, (NvmeCmd *)&rw);
    status = femu_complete(c, &c->io, &got, NULL);
    g_assert_cmpint(got, ==, want);

    return status;
}

/*
 * A PRP list may start part way into a page, and then the last entry before
 * the end of that page points at the next list (Base 2.3, Figure 110). The
 * list here starts 0xf00 into its page, so it holds 31 data pages and the
 * pointer to a second list with the other 8. Pages are listed in reverse, so
 * a list read from the wrong place moves data to the wrong place.
 */
static void femu_test_prp_list_offset(void *obj, void *data,
                                      QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    const size_t size = FEMU_PRP_PAGES * 4096;
    uint8_t *wbuf = g_malloc(size);
    uint8_t *rbuf = g_malloc0(size);
    uint64_t pages, list_a, list_b;
    uint64_t entry;
    int slots = (4096 - FEMU_PRP_LIST_OFF) / 8;
    int i;
    int k;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    pages = guest_alloc(alloc, size);
    list_a = guest_alloc(alloc, 4096);
    list_b = guest_alloc(alloc, 4096);

    /* page 0 of the transfer is PRP1; list entry k names transfer page k + 1 */
    for (k = 0; k < FEMU_PRP_PAGES - 1; k++) {
        uint64_t slot;

        entry = cpu_to_le64(pages + (FEMU_PRP_PAGES - 1 - k) * 4096);
        slot = k < slots - 1 ? list_a + FEMU_PRP_LIST_OFF + k * 8
                             : list_b + (k - (slots - 1)) * 8;
        qtest_memwrite(qts, slot, &entry, sizeof(entry));
    }
    entry = cpu_to_le64(list_b);
    qtest_memwrite(qts, list_a + 4096 - 8, &entry, sizeof(entry));

    for (i = 0; i < size; i++) {
        wbuf[i] = (uint8_t)(i / 4096 * 3 + i);
    }
    /* transfer page p lives at buffer page 0 for p == 0, else 40 - p */
    for (k = 0; k < FEMU_PRP_PAGES; k++) {
        int at = k ? FEMU_PRP_PAGES - k : 0;

        qtest_memwrite(qts, pages + at * 4096, wbuf + k * 4096, 4096);
    }
    g_assert_cmpint(femu_prp_list_rw(&c, NVME_CMD_WRITE, pages,
                                     list_a + FEMU_PRP_LIST_OFF),
                    ==, NVME_SUCCESS);

    qtest_memset(qts, pages, 0, size);
    g_assert_cmpint(femu_prp_list_rw(&c, NVME_CMD_READ, pages,
                                     list_a + FEMU_PRP_LIST_OFF),
                    ==, NVME_SUCCESS);
    for (k = 0; k < FEMU_PRP_PAGES; k++) {
        int at = k ? FEMU_PRP_PAGES - k : 0;

        qtest_memread(qts, pages + at * 4096, rbuf + k * 4096, 4096);
    }
    g_assert_cmpint(memcmp(wbuf, rbuf, size), ==, 0);

    /* and the blocks hold the pages in transfer order */
    memset(rbuf, 0, size);
    for (k = 0; k < 8; k++) {
        g_assert_cmpint(femu_rw(&c, NVME_CMD_READ, k * 8, pages),
                        ==, NVME_SUCCESS);
        qtest_memread(qts, pages, rbuf + k * 4096, 4096);
    }
    g_assert_cmpint(memcmp(wbuf, rbuf, 8 * 4096), ==, 0);

    guest_free(alloc, list_b);
    guest_free(alloc, list_a);
    guest_free(alloc, pages);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    g_free(rbuf);
    g_free(wbuf);
}

/*
 * Point a command at data through a last segment holding one data block. Read
 * as PRPs, the descriptor's address is the list, not the data, so a command
 * that ignores PSDT moves the wrong bytes.
 */
static void femu_sgl_segment(FemuCtrlState *c, NvmeCmd *cmd, uint64_t list,
                             uint64_t data, uint32_t len)
{
    NvmeSglDescriptor blk = { 0 };
    NvmeSglDescriptor seg = { 0 };

    blk.addr = cpu_to_le64(data);
    blk.len = cpu_to_le32(len);
    qtest_memwrite(c->pdev->bus->qts, list, &blk, sizeof(blk));
    seg.addr = cpu_to_le64(list);
    seg.len = cpu_to_le32(sizeof(blk));
    seg.type = NVME_SGL_DESCR_TYPE_LAST_SEGMENT << 4;
    cmd->flags = 1 << 6;                    /* PSDT: SGL */
    memcpy(&cmd->dptr.sgl, &seg, sizeof(seg));
}

static uint16_t femu_io(FemuCtrlState *c, NvmeCmd *cmd)
{
    uint16_t want = c->cid;
    uint16_t got;
    uint16_t status;

    femu_submit(c, &c->io, cmd);
    status = femu_complete(c, &c->io, &got, NULL);
    g_assert_cmpint(got, ==, want);

    return FEMU_SC(status);
}

/*
 * SGL support is reported for the controller as a whole, so every I/O
 * command with a data buffer takes one, not only Read and Write.
 */
static void femu_test_sgl_zoned(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf, list;
    NvmeCmd cmd;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    list = guest_alloc(alloc, 4096);

    /* a zoned write, which used to refuse any SGL */
    qtest_memset(qts, buf, 0x3c, FEMU_DATA_SIZE);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_CMD_WRITE;
    cmd.nsid = cpu_to_le32(1);
    cmd.cdw12 = cpu_to_le32(FEMU_DATA_SIZE / c.lba_size - 1);
    femu_sgl_segment(&c, &cmd, list, buf, FEMU_DATA_SIZE);
    g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_SUCCESS);

    /* Report Zones lands in the data block: a header, then zone 0 */
    qtest_memset(qts, buf, 0xff, FEMU_DATA_SIZE);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_CMD_ZONE_MGMT_RECV;
    cmd.nsid = cpu_to_le32(1);
    cmd.cdw12 = cpu_to_le32(4096 / 4 - 1);
    femu_sgl_segment(&c, &cmd, list, buf, 4096);
    g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_SUCCESS);
    g_assert_cmpint(qtest_readq(qts, buf), >, 0);
    g_assert_cmpint(qtest_readq(qts, buf + 64 + 8), >, 0);      /* ZCAP */
    g_assert_cmpint(qtest_readq(qts, buf + 64 + 24), ==,        /* WP */
                    FEMU_DATA_SIZE / c.lba_size);

    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static void femu_test_sgl_kv(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint8_t *wbuf = g_malloc(4096);
    uint8_t *rbuf = g_malloc0(4096);
    uint64_t buf, list;
    NvmeCmd cmd;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, 4096);
    list = guest_alloc(alloc, 4096);
    for (i = 0; i < 4096; i++) {
        wbuf[i] = (uint8_t)(i * 5 + 1);
    }
    qtest_memwrite(qts, buf, wbuf, 4096);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_KV_CMD_STORE;
    cmd.nsid = cpu_to_le32(1);
    cmd.res1 = cpu_to_le64(0x5347534753475347ULL);
    cmd.cdw10 = cpu_to_le32(4096);
    cmd.cdw11 = cpu_to_le32(8);
    femu_sgl_segment(&c, &cmd, list, buf, 4096);
    g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_SUCCESS);

    qtest_memset(qts, buf, 0, 4096);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_KV_CMD_RETRIEVE;
    cmd.nsid = cpu_to_le32(1);
    cmd.res1 = cpu_to_le64(0x5347534753475347ULL);
    cmd.cdw10 = cpu_to_le32(4096);
    cmd.cdw11 = cpu_to_le32(8);
    femu_sgl_segment(&c, &cmd, list, buf, 4096);
    g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, rbuf, 4096);
    g_assert_cmpint(memcmp(wbuf, rbuf, 4096), ==, 0);

    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    g_free(rbuf);
    g_free(wbuf);
}

#define FEMU_INVALID_QID        0x101   /* command specific */
#define FEMU_INVALID_PRP_OFFSET 0x13
#define FEMU_CMD_SEQ_ERROR      0x0c
#define FEMU_FEAT_NUM_QUEUES    0x07

static uint16_t femu_queue_cmd(FemuCtrlState *c, uint8_t opcode, uint16_t qid,
                               uint64_t prp1, uint32_t dw11)
{
    NvmeCmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = opcode;
    cmd.dptr.prp1 = cpu_to_le64(prp1);
    cmd.cdw10 = cpu_to_le32(((FEMU_QSIZE - 1) << 16) | qid);
    cmd.cdw11 = cpu_to_le32(dw11);
    return FEMU_SC(femu_admin(c, &cmd));
}

/*
 * The status each queue command returns for what it refuses (Base 2.3,
 * Figures 505, 510, 512 and 514), and Number of Queues, which may only be
 * set before any I/O queue exists (5.2.26.2.1).
 */
static void femu_test_queue_create_status(void *obj, void *data,
                                          QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t ring = guest_alloc(alloc, 2 * 4096);
    uint64_t page = (ring + 4095) & ~4095ULL;

    femu_enable(&c, &femu->dev, alloc);

    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, FEMU_FEAT_NUM_QUEUES, false,
                                             0, 0xffff, NULL)),
                    ==, NVME_INVALID_FIELD);
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, FEMU_FEAT_NUM_QUEUES, false,
                                             0, 0, NULL)),
                    ==, NVME_SUCCESS);

    /* completion queues: the admin id, one out of range, a base mid page */
    g_assert_cmpint(femu_queue_cmd(&c, NVME_ADM_CMD_CREATE_CQ, 0, page,
                                   NVME_CQ_PC), ==, FEMU_INVALID_QID);
    g_assert_cmpint(femu_queue_cmd(&c, NVME_ADM_CMD_CREATE_CQ,
                                   FEMU_DEFAULT_IO_QUEUES + 1, page,
                                   NVME_CQ_PC), ==, FEMU_INVALID_QID);
    g_assert_cmpint(femu_queue_cmd(&c, NVME_ADM_CMD_CREATE_CQ, 1, page + 0x200,
                                   NVME_CQ_PC), ==, FEMU_INVALID_PRP_OFFSET);
    g_assert_cmpint(femu_queue_cmd(&c, NVME_ADM_CMD_CREATE_CQ, 1, page,
                                   NVME_CQ_PC), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_queue_cmd(&c, NVME_ADM_CMD_CREATE_CQ, 1, page,
                                   NVME_CQ_PC), ==, FEMU_INVALID_QID);

    /* a submission queue whose base is not on a page */
    g_assert_cmpint(femu_queue_cmd(&c, NVME_ADM_CMD_CREATE_SQ, 1,
                                   page + 0x200, (1 << 16) | NVME_SQ_PC),
                    ==, FEMU_INVALID_PRP_OFFSET);

    /* and now that an I/O queue exists, the queue count is fixed */
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, FEMU_FEAT_NUM_QUEUES, false,
                                             0, 0, NULL)),
                    ==, FEMU_CMD_SEQ_ERROR);

    /* deleting the admin queue, or one that was never made */
    g_assert_cmpint(femu_queue_cmd(&c, NVME_ADM_CMD_DELETE_CQ, 0, 0, 0),
                    ==, FEMU_INVALID_QID);
    g_assert_cmpint(femu_queue_cmd(&c, NVME_ADM_CMD_DELETE_CQ, 5, 0, 0),
                    ==, FEMU_INVALID_QID);
    g_assert_cmpint(femu_queue_cmd(&c, NVME_ADM_CMD_DELETE_SQ, 5, 0, 0),
                    ==, FEMU_INVALID_QID);
    g_assert_cmpint(femu_queue_cmd(&c, NVME_ADM_CMD_DELETE_CQ, 1, 0, 0),
                    ==, NVME_SUCCESS);

    femu_disable(&c);
    guest_free(alloc, ring);
}

#define FEMU_CC_ENABLE      ((6 << 16) | (4 << 20) | 1)
#define FEMU_CC_SHN_NORMAL  (1 << 14)
#define FEMU_CSTS_SHST(x)   (((x) >> 2) & 3)
#define FEMU_INVALID_QSIZE  0x102   /* command specific */

/*
 * The controller configuration and status registers (Base 2.3, Figures 41-42
 * and 3.5): a write that disables and shuts down at once does both, a reset
 * clears the shutdown status, the I/O entry sizes may be left at 0 until an
 * I/O queue is made, and ASQ may be written as two dwords in either order.
 */
static void femu_test_cc_states(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QPCIDevice *dev = &femu->dev;
    FemuCtrlState c = { 0 };
    uint64_t ring = guest_alloc(alloc, 2 * 4096);
    uint64_t page = (ring + 4095) & ~4095ULL;
    uint32_t csts;

    femu_enable(&c, dev, alloc);
    qpci_io_writel(dev, c.bar, 0x14, (FEMU_CC_ENABLE & ~1) |
                   FEMU_CC_SHN_NORMAL);
    csts = qpci_io_readl(dev, c.bar, 0x1c);
    g_assert_cmpint(csts & NVME_CSTS_READY, ==, 0);
    g_assert_cmpint(FEMU_CSTS_SHST(csts), ==, 2);
    qpci_io_writel(dev, c.bar, 0x14, 0);
    g_assert_cmpint(FEMU_CSTS_SHST(qpci_io_readl(dev, c.bar, 0x1c)), ==, 0);
    femu_queue_free(&c, &c.admin);
    qpci_iounmap(dev, c.bar);

    /* shut down while enabled, then reset with SHN still set */
    memset(&c, 0, sizeof(c));
    femu_enable(&c, dev, alloc);
    qpci_io_writel(dev, c.bar, 0x14, FEMU_CC_ENABLE | FEMU_CC_SHN_NORMAL);
    g_assert_cmpint(FEMU_CSTS_SHST(qpci_io_readl(dev, c.bar, 0x1c)), ==, 2);
    qpci_io_writel(dev, c.bar, 0x14, FEMU_CC_SHN_NORMAL);
    csts = qpci_io_readl(dev, c.bar, 0x1c);
    g_assert_cmpint(FEMU_CSTS_SHST(csts), ==, 0);
    g_assert_cmpint(csts & NVME_CSTS_FAILED, ==, 0);
    qpci_io_writel(dev, c.bar, 0x14, 0);
    femu_queue_free(&c, &c.admin);
    qpci_iounmap(dev, c.bar);

    /* no I/O entry sizes yet: ready, but no I/O queue can be made */
    memset(&c, 0, sizeof(c));
    c.pdev = dev;
    c.alloc = alloc;
    femu_queue_init(&c, &c.admin, 0);
    femu_enable_cc(&c, dev, alloc, 1);
    g_assert_cmpint(femu_queue_cmd(&c, NVME_ADM_CMD_CREATE_CQ, 1, page,
                                   NVME_CQ_PC), ==, FEMU_INVALID_QSIZE);
    femu_disable(&c);

    /* ASQ high dword first, then low; and the reserved bits of AQA */
    c.bar = qpci_iomap(dev, 0, NULL);
    qpci_io_writel(dev, c.bar, 0x2c, 0x1);
    qpci_io_writel(dev, c.bar, 0x28, 0x2000);
    g_assert_cmphex(qpci_io_readq(dev, c.bar, 0x28), ==, 0x100002000ULL);
    qpci_io_writel(dev, c.bar, 0x28, 0x3fff);
    g_assert_cmphex(qpci_io_readq(dev, c.bar, 0x28), ==, 0x100003000ULL);
    qpci_io_writel(dev, c.bar, 0x24, 0xffffffff);
    g_assert_cmphex(qpci_io_readl(dev, c.bar, 0x24), ==, 0x0fff0fff);
    qpci_iounmap(dev, c.bar);

    guest_free(alloc, ring);
}

/*
 * Features other than the saveable ones return to their defaults on a
 * Controller Level Reset (Base 2.3, 4.4). Volatile Write Cache exists only
 * on a controller that reports a write cache, and keeps only its enable bit;
 * Power Management takes only a power state the controller describes.
 */
static void femu_test_features_reset(void *obj, void *data,
                                     QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    bool vwc = data && *(bool *)data;
    FemuCtrlState c = { 0 };
    uint32_t result;

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_ARBITRATION, false, 0,
                                             0x1, NULL)), ==, NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_ASYNCHRONOUS_EVENT_CONF,
                                             false, 0, 0x2, NULL)),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_POWER_MANAGEMENT, false,
                                             0, 1, NULL)),
                    ==, NVME_INVALID_FIELD);
    if (vwc) {
        g_assert_cmpint(FEMU_SC(femu_set_feature(&c,
                                                 NVME_VOLATILE_WRITE_CACHE,
                                                 false, 0, 0xfe, NULL)),
                        ==, NVME_SUCCESS);
        g_assert_cmpint(femu_get_feature(&c, NVME_VOLATILE_WRITE_CACHE, 0, 0,
                                         0, &result), ==, NVME_SUCCESS);
        g_assert_cmpint(result, ==, 0);
    } else {
        g_assert_cmpint(FEMU_SC(femu_set_feature(&c,
                                                 NVME_VOLATILE_WRITE_CACHE,
                                                 false, 0, 1, NULL)),
                        ==, NVME_INVALID_FIELD);
        g_assert_cmpint(FEMU_SC(femu_get_feature(&c,
                                                 NVME_VOLATILE_WRITE_CACHE, 0,
                                                 0, 0, &result)),
                        ==, NVME_INVALID_FIELD);
    }
    femu_disable(&c);

    memset(&c, 0, sizeof(c));
    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_get_feature(&c, NVME_ARBITRATION, 0, 0, 0, &result),
                    ==, NVME_SUCCESS);
    g_assert_cmphex(result, ==, 0x1f0f0706);
    g_assert_cmpint(femu_get_feature(&c, NVME_ASYNCHRONOUS_EVENT_CONF, 0, 0,
                                     0, &result), ==, NVME_SUCCESS);
    g_assert_cmphex(result, ==, 0);
    if (vwc) {
        g_assert_cmpint(femu_get_feature(&c, NVME_VOLATILE_WRITE_CACHE, 0, 0,
                                         0, &result), ==, NVME_SUCCESS);
        g_assert_cmpint(result, ==, 1);
    }
    femu_disable(&c);
}

static bool femu_vwc = true;

#define FEMU_LOG_ERROR_INFO     0x01
#define FEMU_LOG_SMART          0x02
#define FEMU_LOG_RAE            (1u << 15)
#define FEMU_INVALID_NSID       0x0b
#define FEMU_AEC_TEMPERATURE    0x02

static uint16_t femu_log_cmd(FemuCtrlState *c, uint32_t nsid, uint32_t dw10,
                             uint32_t dw14, uint64_t buf, uint32_t len)
{
    NvmeCmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_GET_LOG_PAGE;
    cmd.nsid = cpu_to_le32(nsid);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(dw10 | ((len / 4 - 1) << 16));
    cmd.cdw14 = cpu_to_le32(dw14);
    return FEMU_SC(femu_admin(c, &cmd));
}

/*
 * The Error Information log counts from 1 and lists the newest error first
 * (Base 2.3, 5.2.12.1.2). Reading SMART or the error log with Retain
 * Asynchronous Event keeps the event reported, so the same event cannot be
 * raised again until a read without it; SMART for a namespace that does not
 * exist is refused; and no log page offers an index offset.
 */
static void femu_test_error_log(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf;
    uint16_t second;
    uint16_t cid;
    NvmeCmd aer;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, 4096);

    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_READ, 0xfffff000, buf)), ==,
                    NVME_LBA_RANGE);
    second = c.cid;
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_READ, 0xfffff000, buf)), ==,
                    NVME_LBA_RANGE);
    g_assert_cmpint(femu_log_cmd(&c, 0xffffffff, FEMU_LOG_ERROR_INFO, 0, buf,
                                 128), ==, NVME_SUCCESS);
    g_assert_cmpint(qtest_readq(qts, buf) - qtest_readq(qts, buf + 64), ==, 1);
    g_assert_cmpint(qtest_readq(qts, buf + 64), >=, 1);
    g_assert_cmpint(qtest_readw(qts, buf + 10), ==, second);

    g_assert_cmpint(femu_log_cmd(&c, 99, FEMU_LOG_SMART, 0, buf, 512), ==,
                    FEMU_INVALID_NSID);
    g_assert_cmpint(femu_log_cmd(&c, 1, FEMU_LOG_SMART, 0, buf, 512), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_log_cmd(&c, 0xffffffff, FEMU_LOG_SMART, 1u << 23,
                                 buf, 512), ==, NVME_INVALID_FIELD);

    /* a temperature event, reported once to an Async Event Request */
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_ASYNCHRONOUS_EVENT_CONF,
                                             false, 0, FEMU_AEC_TEMPERATURE,
                                             NULL)), ==, NVME_SUCCESS);
    memset(&aer, 0, sizeof(aer));
    aer.opcode = NVME_ADM_CMD_ASYNC_EV_REQ;
    femu_submit(&c, &c.admin, &aer);
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_TEMPERATURE_THRESHOLD,
                                             false, 0, 0, NULL)),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(femu_complete(&c, &c.admin, NULL, NULL), ==,
                    NVME_SUCCESS);

    /*
     * Read with RAE: the event stays reported, so moving the threshold away
     * and back does not raise it again. The next completion must be the log
     * read's own, not the second request's.
     */
    memset(&aer, 0, sizeof(aer));
    aer.opcode = NVME_ADM_CMD_ASYNC_EV_REQ;
    cid = c.cid;
    femu_submit(&c, &c.admin, &aer);
    g_assert_cmpint(femu_log_cmd(&c, 0xffffffff,
                                 FEMU_LOG_SMART | FEMU_LOG_RAE, 0, buf, 512),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_TEMPERATURE_THRESHOLD,
                                             false, 0, 0xffff, NULL)),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_TEMPERATURE_THRESHOLD,
                                             false, 0, 0, NULL)),
                    ==, NVME_SUCCESS);
    g_usleep(100 * 1000);
    g_assert_cmpint(femu_log_cmd(&c, 0xffffffff, FEMU_LOG_SMART, 0, buf, 512),
                    ==, NVME_SUCCESS);

    /* read without RAE: now it can be raised again */
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_TEMPERATURE_THRESHOLD,
                                             false, 0, 0xffff, NULL)),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_TEMPERATURE_THRESHOLD,
                                             false, 0, 0, NULL)),
                    ==, NVME_SUCCESS);
    {
        uint16_t got;

        g_assert_cmpint(femu_complete(&c, &c.admin, &got, NULL), ==,
                        NVME_SUCCESS);
        g_assert_cmpint(got, ==, cid);
    }

    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

#define FEMU_CNS_NS_CS_INDEP    0x08

static uint16_t femu_identify(FemuCtrlState *c, uint32_t nsid, uint32_t dw10,
                              uint32_t dw11, uint64_t buf)
{
    NvmeCmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_IDENTIFY;
    cmd.nsid = cpu_to_le32(nsid);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(dw10);
    cmd.cdw11 = cpu_to_le32(dw11);
    return FEMU_SC(femu_admin(c, &cmd));
}

/*
 * Identify fields a version 1.4 controller must fill (Base 2.3, Figure 328),
 * the command-set-independent namespace structure (CNS 08h, Figure 335) with
 * the namespace ready, a UUID per namespace that is not zero and does not
 * change, CNS read from bits 7:0 only, and CNS 00h ignoring CSI.
 */
static void femu_test_identify_fields(void *obj, void *data,
                                      QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint8_t uuid1[16];
    uint8_t uuid2[16];
    uint8_t again[16];
    uint8_t zero[16] = { 0 };
    uint64_t buf;

    femu_enable(&c, &femu->dev, alloc);
    buf = guest_alloc(alloc, 4096);

    g_assert_cmpint(femu_identify(&c, 0, NVME_ID_CNS_CTRL, 0, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(qtest_readb(qts, buf + 111), ==, 1);        /* CNTRLTYPE */
    g_assert_cmpint(qtest_readw(qts, buf + 266), !=, 0);        /* WCTEMP */
    g_assert_cmpint(qtest_readw(qts, buf + 268), >,
                    qtest_readw(qts, buf + 266));               /* CCTEMP */
    g_assert_cmpint((qtest_readb(qts, buf + 525) >> 1) & 3, ==, 2);

    qtest_memset(qts, buf, 0, 4096);
    g_assert_cmpint(femu_identify(&c, 1, FEMU_CNS_NS_CS_INDEP, 0, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(qtest_readb(qts, buf + 14) & 1, ==, 1);     /* NRDY */
    g_assert_cmpint(femu_identify(&c, 0, FEMU_CNS_NS_CS_INDEP, 0, buf), ==,
                    FEMU_INVALID_NSID);
    g_assert_cmpint(femu_identify(&c, 99, FEMU_CNS_NS_CS_INDEP, 0, buf), ==,
                    FEMU_INVALID_NSID);

    g_assert_cmpint(femu_identify(&c, 1, NVME_ID_CNS_NS_DESCR_LIST, 0, buf),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(qtest_readb(qts, buf), ==, 3);              /* NIDT UUID */
    qtest_memread(qts, buf + 4, uuid1, 16);
    g_assert_cmpint(femu_identify(&c, 2, NVME_ID_CNS_NS_DESCR_LIST, 0, buf),
                    ==, NVME_SUCCESS);
    qtest_memread(qts, buf + 4, uuid2, 16);
    g_assert_cmpint(femu_identify(&c, 1, NVME_ID_CNS_NS_DESCR_LIST, 0, buf),
                    ==, NVME_SUCCESS);
    qtest_memread(qts, buf + 4, again, 16);
    g_assert_cmpint(memcmp(uuid1, zero, 16), !=, 0);
    g_assert_cmpint(memcmp(uuid1, uuid2, 16), !=, 0);
    g_assert_cmpint(memcmp(uuid1, again, 16), ==, 0);

    /* a controller identifier above CNS, and a CSI CNS 00h does not use */
    g_assert_cmpint(femu_identify(&c, 0, NVME_ID_CNS_CTRL | (5 << 16), 0, buf),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(femu_identify(&c, 1, NVME_ID_CNS_NS, 2 << 24, buf), ==,
                    NVME_SUCCESS);

    guest_free(alloc, buf);
    femu_disable(&c);
}

#define FEMU_ZONE_ACTION_CLOSE  0x01
#define FEMU_ZONE_ACTION_OPEN   0x03
#define FEMU_ZONE_SELECT_ALL    (1 << 8)
#define FEMU_ZS_IMP_OPEN        0x2
#define FEMU_ZS_EXP_OPEN        0x3
#define FEMU_ZS_CLOSED          0x4
#define FEMU_TOO_MANY_OPEN      0x1be   /* command specific */

/* the state of the first four zones, and where zone 1 starts */
static void femu_zone_states(FemuCtrlState *c, uint64_t buf, uint8_t *zs,
                             uint64_t *zsze)
{
    QTestState *qts = c->pdev->bus->qts;
    NvmeCmd cmd = { 0 };
    int i;

    cmd.opcode = NVME_CMD_ZONE_MGMT_RECV;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw12 = cpu_to_le32((64 + 4 * 64) / 4 - 1);
    g_assert_cmpint(femu_io(c, &cmd), ==, NVME_SUCCESS);
    for (i = 0; i < 4; i++) {
        zs[i] = qtest_readb(qts, buf + 64 + i * 64 + 1) >> 4;
    }
    *zsze = qtest_readq(qts, buf + 64 + 64 + 16);
}

/*
 * With two zones allowed open: an explicit open at the limit closes an
 * implicitly opened zone rather than failing (ZNS 1.4, 2.1.1.4), and Open with
 * Select All that cannot open every closed zone opens none (3.4.3.1.4).
 */
static void femu_test_zone_open_limits(void *obj, void *data,
                                       QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf;
    uint64_t zsze;
    uint8_t zs[4];

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, 4096);
    femu_zone_states(&c, buf, zs, &zsze);

    /* zones 0 and 1 implicitly opened by a write each */
    g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE, zsze, buf), ==, NVME_SUCCESS);
    femu_zone_states(&c, buf, zs, &zsze);
    g_assert_cmpint(zs[0], ==, FEMU_ZS_IMP_OPEN);
    g_assert_cmpint(zs[1], ==, FEMU_ZS_IMP_OPEN);

    /* explicitly opening zone 2 closes one of them */
    g_assert_cmpint(femu_zone_action(&c, 2 * zsze, FEMU_ZONE_ACTION_OPEN), ==,
                    NVME_SUCCESS);
    femu_zone_states(&c, buf, zs, &zsze);
    g_assert_cmpint(zs[2], ==, FEMU_ZS_EXP_OPEN);
    g_assert_cmpint((zs[0] == FEMU_ZS_CLOSED) + (zs[1] == FEMU_ZS_CLOSED), ==,
                    1);

    /* two closed zones and one open do not fit in two: nothing changes */
    g_assert_cmpint(femu_zone_action(&c, zs[0] == FEMU_ZS_CLOSED ? zsze : 0,
                                     FEMU_ZONE_ACTION_CLOSE), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_zone_action(&c, 0, FEMU_ZONE_ACTION_OPEN |
                                     FEMU_ZONE_SELECT_ALL), ==,
                    FEMU_TOO_MANY_OPEN);
    femu_zone_states(&c, buf, zs, &zsze);
    g_assert_cmpint(zs[0], ==, FEMU_ZS_CLOSED);
    g_assert_cmpint(zs[1], ==, FEMU_ZS_CLOSED);
    g_assert_cmpint(zs[2], ==, FEMU_ZS_EXP_OPEN);

    /* back to empty for whatever runs next on this device */
    g_assert_cmpint(femu_zone_action(&c, 0, FEMU_ZONE_ACTION_RESET |
                                     FEMU_ZONE_SELECT_ALL), ==, NVME_SUCCESS);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

#define FEMU_ZONE_BOUNDARY_ERROR    0x1b8   /* command specific */

/* Compare reads a zone, so it may not run across a zone boundary either */
static void femu_test_zoned_compare(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    NvmeRwCmd rw;
    uint64_t buf;
    uint64_t zsze;
    uint8_t zs[4];

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, 4096);
    femu_zone_states(&c, buf, zs, &zsze);

    memset(&rw, 0, sizeof(rw));
    rw.opcode = NVME_CMD_COMPARE;
    rw.nsid = cpu_to_le32(1);
    rw.dptr.prp1 = cpu_to_le64(buf);
    rw.slba = cpu_to_le64(zsze - 1);
    rw.nlb = cpu_to_le16(1);
    g_assert_cmpint(femu_io(&c, (NvmeCmd *)&rw), ==,
                    FEMU_ZONE_BOUNDARY_ERROR);

    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

#define FEMU_LOG_CHANGED_ZONES  0xbf
#define FEMU_AEC_ZDCN           (1u << 27)

/*
 * A zone the controller takes read only is reported in the Changed Zone List
 * whatever the host asked for, but announced with an Async Event only when
 * the host enabled Zone Descriptor Changed Notices, which Identify has to
 * offer (ZNS 1.4, Figures 44-45). The notice names the namespace in dword 1.
 * Reporting zones by attribute (Zone Receive Action Specific 9h) is valid.
 */
static void femu_test_zone_change_notice(void *obj, void *data,
                                         QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf;
    uint64_t zsze;
    uint32_t result;
    uint16_t aer_cid;
    uint16_t cid;
    uint8_t zs[4];
    NvmeCmd cmd;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, 4096);
    femu_zone_states(&c, buf, zs, &zsze);

    g_assert_cmpint(femu_identify(&c, 0, NVME_ID_CNS_CTRL, 0, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(qtest_readl(qts, buf + 92) & FEMU_AEC_ZDCN, ==,
                    FEMU_AEC_ZDCN);

    /* notices off: the write faults, the zone is listed, nothing is raised */
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_ASYNC_EV_REQ;
    aer_cid = c.cid;
    femu_submit(&c, &c.admin, &cmd);
    g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE, 0, buf), !=, NVME_SUCCESS);
    g_usleep(100 * 1000);
    g_assert_cmpint(femu_log_cmd(&c, 1, FEMU_LOG_CHANGED_ZONES, 0, buf, 4096),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(qtest_readw(qts, buf), ==, 1);
    g_assert_cmpint(qtest_readq(qts, buf + 8), ==, 0);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_CMD_ZONE_MGMT_RECV;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw12 = cpu_to_le32(4096 / 4 - 1);
    cmd.cdw13 = cpu_to_le32(0x9 << 8);
    g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_SUCCESS);

    /* notices on: the next zone taken read only is announced */
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_ASYNCHRONOUS_EVENT_CONF,
                                             false, 0, FEMU_AEC_ZDCN, NULL)),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE, zsze, buf), !=, NVME_SUCCESS);
    g_assert_cmpint(femu_complete(&c, &c.admin, &cid, &result), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(cid, ==, aer_cid);
    g_assert_cmphex(result & 0xffffff, ==, 0xbfef02);
    g_assert_cmpint(qtest_readl(qts, c.admin.cq_addr +
                    ((c.admin.cq_head + FEMU_QSIZE - 1) % FEMU_QSIZE) *
                    sizeof(NvmeCqe) + 4), ==, 1);

    g_assert_cmpint(femu_log_cmd(&c, 1, FEMU_LOG_CHANGED_ZONES, 0, buf, 4096),
                    ==, NVME_SUCCESS);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

#define FEMU_RW_PRACT       (1u << 29)      /* CDW12 */

static uint16_t femu_read_prps(FemuCtrlState *c, uint64_t prp1, uint64_t prp2,
                               uint32_t blocks, uint32_t dw12_flags)
{
    NvmeCmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_CMD_READ;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(prp1);
    cmd.dptr.prp2 = cpu_to_le64(prp2);
    cmd.cdw12 = cpu_to_le32((blocks - 1) | dw12_flags);
    return femu_io(c, &cmd);
}

/*
 * A PRP entry with an offset it may not have is PRP Offset Invalid (Base 2.3,
 * Figure 110): the first on a byte that is not a dword, a second entry that is
 * not a page. PRACT on a namespace without protection information is
 * ignored rather than refused.
 */
static void femu_test_prp_status(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t raw = 0;
    uint64_t buf;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = femu_alloc_64k(alloc, &raw);

    g_assert_cmpint(femu_read_prps(&c, buf + 1, 0, 1, 0), ==,
                    FEMU_INVALID_PRP_OFFSET);
    g_assert_cmpint(femu_read_prps(&c, buf, buf + 4096 + 0x10, 16, 0), ==,
                    FEMU_INVALID_PRP_OFFSET);
    g_assert_cmpint(femu_read_prps(&c, buf + 0x200, 0, 1, 0), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_read_prps(&c, buf, 0, 8, FEMU_RW_PRACT), ==,
                    NVME_SUCCESS);

    guest_free(alloc, raw);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * MDTS is a power of two in units of the minimum page size (CAP.MPSMIN), not
 * of the page size the host picked. With MDTS 1 and 8 KiB pages chosen, the
 * limit is still 8 KiB.
 */
static void femu_test_mdts_unit(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t raw = 0;
    uint64_t base = femu_alloc_64k(alloc, &raw);
    uint32_t mps1 = (6 << 16) | (4 << 20) | (1 << 7) | 1;

    c.pdev = &femu->dev;
    c.alloc = alloc;
    c.admin.qid = 0;
    c.admin.sq_addr = base;
    c.admin.cq_addr = base + 8192;
    c.admin.phase = 1;
    qtest_memset(qts, c.admin.cq_addr, 0, 8192);
    femu_enable_cc(&c, &femu->dev, alloc, mps1);

    g_assert_cmpint(femu_log_cmd(&c, 0xffffffff, FEMU_LOG_SMART, 0,
                                 base + 16384, 8192), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_log_cmd(&c, 0xffffffff, FEMU_LOG_SMART, 0,
                                 base + 16384, 12288), ==, NVME_INVALID_FIELD);

    qpci_io_writel(c.pdev, c.bar, 0x14, 0);
    qpci_iounmap(c.pdev, c.bar);
    guest_free(alloc, raw);
}

#define FEMU_ADM_DBBUF_CONFIG   0x7c

/* submit an Async Event Request and return the identifier it went out with */
static uint16_t femu_aer(FemuCtrlState *c)
{
    NvmeCmd cmd;
    uint16_t cid = c->cid;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_ASYNC_EV_REQ;
    femu_submit(c, &c->admin, &cmd);
    return cid;
}

/*
 * A write to a doorbell that does not exist, or past the end of its queue,
 * is an Error event, 00h and 01h (Base 2.3, Figure 152). After Doorbell
 * Buffer Config the admin queue's EventIdx follows the values written, so a
 * host that consults it keeps ringing (Annex B.5).
 */
static void femu_test_doorbell_errors(void *obj, void *data,
                                      QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t raw = 0;
    uint64_t pages;
    uint32_t result;
    uint16_t cid;
    uint16_t want;
    NvmeCmd cmd;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    pages = femu_alloc_64k(alloc, &raw);

    want = femu_aer(&c);
    qpci_io_writel(c.pdev, c.bar, femu_sq_doorbell(&c, 5), 1);
    g_assert_cmpint(femu_complete(&c, &c.admin, &cid, &result), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(cid, ==, want);
    g_assert_cmphex(result & 0xffffff, ==, 0x010000);
    g_assert_cmpint(femu_log_cmd(&c, 0xffffffff, FEMU_LOG_ERROR_INFO, 0,
                                 pages, 64), ==, NVME_SUCCESS);

    want = femu_aer(&c);
    qpci_io_writel(c.pdev, c.bar, femu_sq_doorbell(&c, 1), FEMU_QSIZE + 3);
    g_assert_cmpint(femu_complete(&c, &c.admin, &cid, &result), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(cid, ==, want);
    g_assert_cmphex(result & 0xffffff, ==, 0x010100);
    g_assert_cmpint(femu_log_cmd(&c, 0xffffffff, FEMU_LOG_ERROR_INFO, 0,
                                 pages, 64), ==, NVME_SUCCESS);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_ADM_DBBUF_CONFIG;
    cmd.dptr.prp1 = cpu_to_le64(pages + 8192);
    cmd.dptr.prp2 = cpu_to_le64(pages + 16384);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_identify(&c, 0, NVME_ID_CNS_CTRL, 0, pages), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(qtest_readl(qts, pages + 16384), ==, c.admin.sq_tail);
    g_assert_cmpint(qtest_readl(qts, pages + 16384 + (4 << c.db_stride)), ==,
                    c.admin.cq_head);

    guest_free(alloc, raw);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

#define FEMU_LOG_SUPPORTED      0x00

/*
 * Commands Supported and Effects lists every I/O command the controller
 * dispatches (Base 2.3, 5.2.12.1.6): Write Uncorrectable when ONCS offers it,
 * and I/O Management Receive and Send while placement is on.
 */
static void femu_test_log_contents_fdp(void *obj, void *data,
                                       QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf;

    femu_enable(&c, &femu->dev, alloc);
    buf = guest_alloc(alloc, 4096);
    g_assert_cmpint(femu_log_cmd(&c, 0, FEMU_LOG_CMD_EFFECTS, 0, buf, 4096),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(qtest_readl(qts, buf + 1024 + 4 * 0x04) & 1, ==, 1);
    g_assert_cmpint(qtest_readl(qts, buf + 1024 + 4 * 0x12) & 1, ==, 1);
    g_assert_cmpint(qtest_readl(qts, buf + 1024 + 4 * 0x1d) & 1, ==, 1);
    guest_free(alloc, buf);
    femu_disable(&c);
}

/* the Changed Zone List belongs to the zoned command set's list of pages */
static void femu_test_log_contents_zoned(void *obj, void *data,
                                         QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf;

    femu_enable(&c, &femu->dev, alloc);
    buf = guest_alloc(alloc, 4096);
    g_assert_cmpint(femu_log_cmd(&c, 0, FEMU_LOG_SUPPORTED, 0, buf, 1024),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(qtest_readl(qts, buf + 4 * FEMU_LOG_CHANGED_ZONES), ==, 0);
    g_assert_cmpint(qtest_readl(qts, buf + 4 * 0x02) & 1, ==, 1);
    g_assert_cmpint(femu_log_cmd(&c, 0, FEMU_LOG_SUPPORTED,
                                 (uint32_t)FEMU_CSI_ZONED << 24, buf, 1024),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(qtest_readl(qts, buf + 4 * FEMU_LOG_CHANGED_ZONES) & 1,
                    ==, 1);
    guest_free(alloc, buf);
    femu_disable(&c);
}

/* Format NVM with only CDW10 set, on namespace 1 */
static uint16_t femu_format_dw10(FemuCtrlState *c, uint32_t dw10)
{
    NvmeCmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_FORMAT_NVM;
    cmd.nsid = cpu_to_le32(1);
    cmd.cdw10 = cpu_to_le32(dw10);
    return FEMU_SC(femu_admin(c, &cmd));
}

/*
 * Secure Erase Settings are bits 11:9 of CDW10 (Base 2.3, Figure 193). No
 * erase and a user data erase are accepted; a cryptographic erase is not
 * offered and 011b and above are reserved. Bit 8 is PIL, not part of it.
 */
static void femu_test_format_ses(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_format_dw10(&c, 1 << 8), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_format_dw10(&c, 1 << 9), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_format_dw10(&c, 2 << 9), ==, NVME_INVALID_FIELD);
    g_assert_cmpint(femu_format_dw10(&c, 7 << 9), ==, NVME_INVALID_FIELD);
    femu_disable(&c);
}

/* a key value namespace has a size in bytes 7:0 and nothing in 15:8 */
static void femu_test_kv_identify_reserved(void *obj, void *data,
                                           QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf;

    femu_enable(&c, &femu->dev, alloc);
    buf = guest_alloc(alloc, 4096);
    g_assert_cmpint(femu_identify(&c, 1, NVME_ID_CNS_CS_NS,
                                  (uint32_t)FEMU_CSI_KV << 24, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(qtest_readq(qts, buf), >, 0);
    g_assert_cmpint(qtest_readq(qts, buf + 8), ==, 0);
    guest_free(alloc, buf);
    femu_disable(&c);
}

/* BAR0 bits 13:4 are read only, so it is at least 16 KiB (PCIe 1.3, Fig 20) */
static void femu_test_bar0_size(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QPCIBar bar;
    uint64_t size = 0;

    qpci_device_enable(&femu->dev);
    bar = qpci_iomap(&femu->dev, 0, &size);
    g_assert_cmpint(size, >=, 16384);
    qpci_iounmap(&femu->dev, bar);
}

#define FEMU_AER_LIMIT_EXCEEDED     0x105   /* command specific */

/*
 * AERL is 0's based, so 255 allows 256 outstanding requests. The count of
 * held requests was 8 bits wide and wrapped at the 256th, after which the
 * next request was taken as well and overwrote the first.
 */
static void femu_test_aer_limit(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint16_t want;
    uint16_t cid;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    for (i = 0; i < 256; i++) {
        femu_aer(&c);
    }
    want = femu_aer(&c);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.admin, &cid, NULL)), ==,
                    FEMU_AER_LIMIT_EXCEEDED);
    g_assert_cmpint(cid, ==, want);
    femu_disable(&c);
}

/* ZASL 0 means the append limit is MDTS, and MDTS 0 means there is none */
static void femu_test_zoned_append_mdts0(void *obj, void *data,
                                         QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf;
    uint64_t list;
    uint64_t e;
    NvmeRwCmd rw;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, 4 * 4096);
    list = guest_alloc(alloc, 4096);

    /* four pages: the first in PRP1, the other three in a list */
    for (i = 0; i < 3; i++) {
        e = cpu_to_le64(buf + (i + 1) * 4096);
        qtest_memwrite(qts, list + i * 8, &e, sizeof(e));
    }
    memset(&rw, 0, sizeof(rw));
    rw.opcode = NVME_CMD_ZONE_APPEND;
    rw.nsid = cpu_to_le32(1);
    rw.dptr.prp1 = cpu_to_le64(buf);
    rw.dptr.prp2 = cpu_to_le64(list);
    rw.nlb = cpu_to_le16(4 * 4096 / c.lba_size - 1);
    g_assert_cmpint(femu_io(&c, (NvmeCmd *)&rw), ==, NVME_SUCCESS);

    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * A key value Store moves the value, so MDTS bounds it. (Retrieve moves the
 * smaller of the buffer and the value, and with MDTS this small no value that
 * large can be stored to retrieve.)
 */
static void femu_test_kv_mdts(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf;
    NvmeCmd cmd;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, 4 * 4096);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_KV_CMD_STORE;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.res1 = cpu_to_le64(0x4d4d4d4d4d4d4d4dULL);
    cmd.cdw10 = cpu_to_le32(16384);
    cmd.cdw11 = cpu_to_le32(8);
    g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_INVALID_FIELD);

    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

#define FEMU_TOO_MANY_ACTIVE    0x1bd   /* command specific */

/*
 * With two zones allowed active and open, opening a third empty zone fails
 * on the active limit, whether a write or Open asks for it. Neither may close
 * one of the open zones on the way to failing.
 */
static void femu_test_zone_active_limit(void *obj, void *data,
                                        QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf;
    uint64_t zsze;
    uint8_t zs[4];

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, 4096);
    femu_zone_states(&c, buf, zs, &zsze);

    g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE, zsze, buf), ==, NVME_SUCCESS);

    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 2 * zsze, buf)), ==,
                    FEMU_TOO_MANY_ACTIVE);
    g_assert_cmpint(femu_zone_action(&c, 2 * zsze, FEMU_ZONE_ACTION_OPEN), ==,
                    FEMU_TOO_MANY_ACTIVE);
    femu_zone_states(&c, buf, zs, &zsze);
    g_assert_cmpint(zs[0], ==, FEMU_ZS_IMP_OPEN);
    g_assert_cmpint(zs[1], ==, FEMU_ZS_IMP_OPEN);

    g_assert_cmpint(femu_zone_action(&c, 0, FEMU_ZONE_ACTION_RESET |
                                     FEMU_ZONE_SELECT_ALL), ==, NVME_SUCCESS);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/* the Open-Channel 2.0 chunk log, one descriptor, get (0x02) or set (0xc1) */
static uint16_t femu_oc20_chunk(FemuCtrlState *c, uint8_t opcode, uint64_t buf,
                                uint32_t off)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = opcode;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(0xca | (7 << 16));
    cmd.cdw12 = cpu_to_le32(off);
    return FEMU_SC(femu_admin(c, &cmd));
}

/*
 * Setting chunk descriptors takes only whole descriptors that keep the
 * address and size the controller gave them, with a defined state and a
 * write pointer that state allows; anything else changes nothing.
 */
static void femu_test_oc20_set_chunks(void *obj, void *data,
                                      QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf;
    uint64_t cnlb;

    femu_enable(&c, &femu->dev, alloc);
    buf = guest_alloc(alloc, 4096);
    g_assert_cmpint(femu_oc20_chunk(&c, 0x02, buf, 0), ==, NVME_SUCCESS);
    cnlb = qtest_readq(qts, buf + 16);
    g_assert_cmpint(cnlb, >, 0);

    /* a larger chunk than the controller made */
    qtest_writeq(qts, buf + 16, cnlb + 1);
    g_assert_cmpint(femu_oc20_chunk(&c, 0xc1, buf, 0), ==, NVME_INVALID_FIELD);
    qtest_writeq(qts, buf + 16, cnlb);

    /* a state that is not one of the four, and write pointers past the end */
    qtest_writeb(qts, buf, 0x10);
    g_assert_cmpint(femu_oc20_chunk(&c, 0xc1, buf, 0), ==, NVME_INVALID_FIELD);
    qtest_writeb(qts, buf, 0x2);                /* closed */
    qtest_writeq(qts, buf + 24, cnlb + 1);
    g_assert_cmpint(femu_oc20_chunk(&c, 0xc1, buf, 0), ==, NVME_INVALID_FIELD);
    qtest_writeb(qts, buf, 0x1);                /* free */
    qtest_writeq(qts, buf + 24, 5);
    g_assert_cmpint(femu_oc20_chunk(&c, 0xc1, buf, 0), ==, NVME_INVALID_FIELD);

    /* part of a descriptor */
    g_assert_cmpint(femu_oc20_chunk(&c, 0xc1, buf, 8), ==, NVME_INVALID_FIELD);

    /* none of that stuck; a closed, full chunk does */
    g_assert_cmpint(femu_oc20_chunk(&c, 0x02, buf, 0), ==, NVME_SUCCESS);
    g_assert_cmpint(qtest_readq(qts, buf + 16), ==, cnlb);
    g_assert_cmpint(qtest_readb(qts, buf), ==, 0x1);
    qtest_writeb(qts, buf, 0x2);
    qtest_writeq(qts, buf + 24, cnlb);
    g_assert_cmpint(femu_oc20_chunk(&c, 0xc1, buf, 0), ==, NVME_SUCCESS);
    qtest_memset(qts, buf, 0, 32);
    g_assert_cmpint(femu_oc20_chunk(&c, 0x02, buf, 0), ==, NVME_SUCCESS);
    g_assert_cmpint(qtest_readb(qts, buf), ==, 0x2);

    /* and back to free for whatever runs next on this device */
    qtest_writeb(qts, buf, 0x1);
    qtest_writeq(qts, buf + 24, 0);
    g_assert_cmpint(femu_oc20_chunk(&c, 0xc1, buf, 0), ==, NVME_SUCCESS);
    guest_free(alloc, buf);
    femu_disable(&c);
}

#define FEMU_CMD_VERIFY         0x0c
#define FEMU_UNRECOVERED_READ   0x281   /* media error */

static uint16_t femu_lba_cmd(FemuCtrlState *c, uint8_t opcode, uint64_t slba,
                             uint32_t nlb)
{
    NvmeRwCmd rw;

    memset(&rw, 0, sizeof(rw));
    rw.opcode = opcode;
    rw.nsid = cpu_to_le32(1);
    rw.slba = cpu_to_le64(slba);
    rw.nlb = cpu_to_le16(nlb - 1);
    return femu_io(c, (NvmeCmd *)&rw);
}

/*
 * Verify (NVM 1.2, 3.3.4) moves no data and fails where a Read would: on an
 * uncorrectable block, and past the end of the namespace. It is listed in the
 * effects log when ONCS offers it.
 */
static void femu_test_verify(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, 4096);

    g_assert_cmpint(femu_lba_cmd(&c, FEMU_CMD_VERIFY, 0, 16), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_lba_cmd(&c, NVME_CMD_WRITE_UNCOR, 8, 8), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_lba_cmd(&c, FEMU_CMD_VERIFY, 0, 16), ==,
                    FEMU_UNRECOVERED_READ);
    g_assert_cmpint(femu_lba_cmd(&c, FEMU_CMD_VERIFY, 0, 8), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_lba_cmd(&c, FEMU_CMD_VERIFY, 0xfffff000, 8), ==,
                    NVME_LBA_RANGE);

    /* a write repairs the blocks, and Verify then passes */
    g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE, 8, buf), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_lba_cmd(&c, FEMU_CMD_VERIFY, 0, 16), ==,
                    NVME_SUCCESS);

    g_assert_cmpint(femu_log_cmd(&c, 0, FEMU_LOG_CMD_EFFECTS, 0, buf, 4096),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(qtest_readl(qts, buf + 1024 + 4 * FEMU_CMD_VERIFY) & 1,
                    ==, 1);

    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

#define FEMU_ADM_DEV_SELF_TEST  0x14
#define FEMU_LOG_DEV_SELF_TEST  0x06

static uint16_t femu_self_test(FemuCtrlState *c, uint32_t nsid, uint32_t stc)
{
    NvmeCmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_ADM_DEV_SELF_TEST;
    cmd.nsid = cpu_to_le32(nsid);
    cmd.cdw10 = cpu_to_le32(stc);
    return FEMU_SC(femu_admin(c, &cmd));
}

/*
 * Device Self-test (Base 2.3, 5.2.8): OACS offers it, a short or extended test
 * leaves its result at the head of log 06h, and codes it does not offer, or a
 * namespace that does not exist, are refused.
 */
static void femu_test_self_test(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf;

    femu_enable(&c, &femu->dev, alloc);
    buf = guest_alloc(alloc, 4096);

    g_assert_cmpint(femu_identify(&c, 0, NVME_ID_CNS_CTRL, 0, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(qtest_readw(qts, buf + 256) & (1 << 4), !=, 0);
    g_assert_cmpint(qtest_readw(qts, buf + 316), !=, 0);        /* EDSTT */

    g_assert_cmpint(femu_self_test(&c, 0, 0x1), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_self_test(&c, NVME_NSID_BROADCAST, 0x2), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_log_cmd(&c, 0, FEMU_LOG_DEV_SELF_TEST, 0, buf, 564),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(qtest_readb(qts, buf), ==, 0);      /* none in progress */
    g_assert_cmphex(qtest_readb(qts, buf + 4), ==, 0x20);
    g_assert_cmphex(qtest_readl(qts, buf + 4 + 12), ==, NVME_NSID_BROADCAST);
    g_assert_cmphex(qtest_readb(qts, buf + 4 + 28), ==, 0x10);
    g_assert_cmphex(qtest_readl(qts, buf + 4 + 28 + 12), ==, 0);

    g_assert_cmpint(femu_self_test(&c, 0, 0xf), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_self_test(&c, 0, 0x3), ==, NVME_INVALID_FIELD);
    g_assert_cmpint(femu_self_test(&c, 0, 0x0), ==, NVME_INVALID_FIELD);
    g_assert_cmpint(femu_self_test(&c, 99, 0x1), ==, FEMU_INVALID_NSID);

    guest_free(alloc, buf);
    femu_disable(&c);
}

#define FEMU_CSD_COMPUTE_LOAD   0x22
#define FEMU_CSD_TYPE_SHARED_LIB 0x03

/* where the csd-program-dir test keeps its programs; one per test process */
static char *femu_csd_dir;

static uint16_t femu_csd_load(FemuCtrlState *c, uint64_t buf,
                              const char *name, const char *symbol)
{
    QTestState *qts = c->pdev->bus->qts;
    size_t name_len = strlen(name) + 1;
    size_t size = name_len + strlen(symbol) + 1;
    NvmeCmd cmd;

    qtest_memset(qts, buf, 0, 4096);
    qtest_memwrite(qts, buf, name, name_len);
    qtest_memwrite(qts, buf + name_len, symbol, strlen(symbol) + 1);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_CSD_COMPUTE_LOAD;
    cmd.dptr.prp1 = cpu_to_le64(buf);
    /* program index 1, shared library, whole program in one piece */
    cmd.cdw10 = cpu_to_le32(1 | (FEMU_CSD_TYPE_SHARED_LIB << 16));
    cmd.cdw11 = cpu_to_le32(size);
    cmd.cdw14 = cpu_to_le32(size);

    return femu_admin(c, &cmd);
}

/*
 * A program name from the guest is resolved inside csd_program_dir. Each way
 * the lookup can end, a missing file, a link out of the directory, and a file
 * that is there but is no library, has to be refused and leave the controller
 * working.
 */
static void femu_test_csd_program_dir(void *obj, void *data,
                                      QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    g_autofree char *link = g_build_filename(femu_csd_dir, "escape", NULL);
    g_autofree char *file = g_build_filename(femu_csd_dir, "notalib", NULL);
    uint64_t buf;

    g_assert_cmpint(g_mkdir_with_parents(femu_csd_dir, 0700), ==, 0);
    g_assert_true(g_file_set_contents(file, "not an ELF", -1, NULL));
    g_assert_cmpint(symlink("/etc/hostname", link), ==, 0);

    femu_enable(&c, &femu->dev, alloc);
    buf = guest_alloc(alloc, 4096);

    g_assert_cmpint(femu_csd_load(&c, buf, "missing", "run"), ==,
                    NVME_INVALID_FIELD | NVME_DNR);
    g_assert_cmpint(femu_csd_load(&c, buf, "escape", "run"), ==,
                    NVME_INVALID_FIELD | NVME_DNR);
    g_assert_cmpint(femu_csd_load(&c, buf, "notalib", "run"), ==,
                    NVME_INVALID_FIELD | NVME_DNR);

    femu_create_io_queues(&c);
    femu_round_trip(&c, 3);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);

    unlink(link);
    unlink(file);
    rmdir(femu_csd_dir);
}

static void femu_register_nodes(void)
{
    QOSGraphEdgeOptions opts = {
        .extra_device_opts = "addr=04.0,devsz_mb=64,femu_mode=2,serial=femu0",
        /*
         * A placement-enabled subsystem for the tests that link to it. It has
         * to be on the command line before the controller, which a test's own
         * options cannot arrange, and it is inert for a controller that does
         * not name it.
         */
        .before_cmd_line =
            "-device femu-subsys,id=fdpsub,nqn=fdpsub,fdp=on,fdp.nruh=4",
    };

    add_qpci_address(&opts, &(QPCIAddress) { .devfn = QPCI_DEVFN(4, 0) });

    qos_node_create_driver("femu", femu_create);
    qos_node_consumes("femu", "pci-bus", &opts);
    qos_node_produces("femu", "pci-device");

    qos_add_test("io-by-doorbell", "femu", femu_test_io_by_doorbell,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "oncs=0x1f"
    });
    qos_add_test("io-by-shadow-doorbell", "femu",
                 femu_test_io_by_shadow_doorbell, NULL);
    qos_add_test("features", "femu", femu_test_features, NULL);
    qos_add_test("queue-mapping", "femu", femu_test_queue_mapping, NULL);
    qos_add_test("discontig-64k-pages", "femu",
                 femu_test_discontig_64k_pages, &(QOSGraphTestOptions) {
        /* non-contiguous queues allowed, memory pages up to 64 KiB */
        .edge.extra_device_opts = "cqr=0,mpsmax=4"
    });
    qos_add_test("admin-queue-refused", "femu", femu_test_admin_queue_refused,
                 NULL);
    qos_add_test("cq-churn", "femu", femu_test_cq_churn, NULL);
    qos_add_test("cmb-data-buffer", "femu", femu_test_cmb_data_buffer,
                 &(QOSGraphTestOptions) {
        /* four megabytes of controller memory on base address register two */
        .edge.extra_device_opts = "cmbsz=0x400000,cmbloc=2"
    });
    qos_add_test("dbbuf-too-many-queues", "femu",
                 femu_test_dbbuf_too_many_queues, &(QOSGraphTestOptions) {
        /* two entries per queue at four bytes each is past a 4 KiB page */
        .edge.extra_device_opts = "queues=1024"
    });
    qos_add_test("zoned-append-limit", "femu", femu_test_zoned_append_limit,
                 &(QOSGraphTestOptions) {
        /* a zoned namespace on a controller whose own mode is a black box */
        .edge.extra_device_opts =
            "devsz_mb=128,femu_mode=1,namespaces=2,namespace_modes=bbssd,,znssd"
    });
    qos_add_test("fdp-events", "femu", femu_test_fdp_events,
                 &(QOSGraphTestOptions) {
        /* the placement-enabled subsystem every controller node declares */
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "subsys=fdpsub"
    });
    qos_add_test("kv-accounting", "femu", femu_test_kv_accounting,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "devsz_mb=512,femu_mode=5"
    });
    qos_add_test("kv-discovery", "femu", femu_test_kv_discovery,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "devsz_mb=512,femu_mode=5"
    });
    qos_add_test("kv-namespaces", "femu",
                 femu_test_kv_namespaces_are_separate,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "devsz_mb=512,femu_mode=5,namespaces=2"
    });
    qos_add_test("oc20-vector-io", "femu", femu_test_oc20_vector_io,
                 &(QOSGraphTestOptions) {
        /*
         * Three groups and five units, neither a power of two, so an address
         * outside the geometry is representable. One gigabyte leaves the
         * geometry eight chunks per unit.
         */
        .edge.extra_device_opts =
            "devsz_mb=1024,femu_mode=0,lver=2,lnum_ch=3,lnum_lun=5,"
            "lsecs_per_pg=4,lpgs_per_blk=256,learly_reset=1"
    });
    qos_add_test("zoned-format-index", "femu", femu_test_zoned_format_index,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=3,lba_index=1"
    });
    qos_add_test("zone-append-parallel", "femu",
                 femu_test_zone_append_parallel, &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=3,secsz=512,multipoller_enabled=1,poller_ratio=1"
    });
    qos_add_test("zrwa-reopen", "femu", femu_test_zrwa_reopen,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=512,femu_mode=3,secsz=512,zns_chnls_per_zone=1,"
            "zns_zrwa_size=128,zns_zrwafg_size=32,zns_zrwa_num=1"
    });
    qos_add_test("zone-reset", "femu", femu_test_zone_reset,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=3,secsz=512"
    });
    qos_add_test("identify-other-csi", "femu", femu_test_identify_other_csi,
                 &(QOSGraphTestOptions) {
        /* Open-Channel 2.0, whose state object is far smaller than KV's */
        .edge.extra_device_opts = "femu_mode=0,lver=2"
    });
    qos_add_test("delete-sq-in-flight", "femu",
                 femu_test_delete_sq_in_flight, &(QOSGraphTestOptions) {
        /*
         * A black-box device, because that is the mode whose requests travel
         * through the poller's priority queue and the rings to the FTL. The
         * default no-SSD device completes inline and never reaches them.
         * The geometry holds 80 MiB so the 64 MiB namespace leaves garbage
         * collection somewhere to work.
         */
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4"
    });
    qos_add_test("format", "femu", femu_test_format,
                 &(QOSGraphTestOptions) {
        /* start with 4 KiB blocks so a format to 512 grows the block count */
        .edge.extra_device_opts = "lba_index=3"
    });
    qos_add_test("log-pages", "femu", femu_test_log_pages, NULL);
    qos_add_test("log-length", "femu", femu_test_log_length, NULL);
    qos_add_test("zone-report-length", "femu", femu_test_report_length,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=3,secsz=512",
        .arg = GINT_TO_POINTER(1),
    });
    qos_add_test("fdp-report-length", "femu", femu_test_report_length,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,subsys=fdpsub",
    });
    qos_add_test("log-length-unlimited", "femu", femu_test_log_length,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "mdts=0"
    });
    qos_add_test("oc20-set-chunks", "femu", femu_test_oc20_set_chunks,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=0,lver=2"
    });
    qos_add_test("oc20-log-length", "femu", femu_test_oc20_log_length,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=0,lver=2"
    });
    qos_add_test("media-counters", "femu", femu_test_media_counters,
                 &(QOSGraphTestOptions) {
        /*
         * A black-box device, because the counters come from its FTL. The
         * default no-SSD device has none and would report zeroes forever.
         */
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4"
    });
    qos_add_test("fdp-write-zeroes", "femu", femu_test_fdp_write_zeroes,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,lba_index=3,"
            "oncs=0xc,subsys=fdpsub",
    });
    qos_add_test("fdp-ruh-update", "femu", femu_test_fdp_ruh_update,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,lba_index=3,"
            "subsys=fdpsub",
    });
    qos_add_test("fdp-ruh-update-full", "femu", femu_test_fdp_ruh_update_full,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,lba_index=3,"
            "gc_thres_pcent=100,gc_thres_pcent_high=100,subsys=fdpsub",
    });
    qos_add_test("sgl", "femu", femu_test_sgl, &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "sgl=on"
    });
    qos_add_test("wide-lba-4k", "femu", femu_test_wide_lba,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,lba_index=3",
        .arg = &femu_wide_4k,
    });
    qos_add_test("wide-lba-8k", "femu", femu_test_wide_lba,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,lba_index=4",
        .arg = &femu_wide_8k,
    });
    qos_add_test("wide-lba-fdp", "femu", femu_test_wide_lba,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,lba_index=3,"
            "subsys=fdpsub",
        .arg = &femu_wide_fdp,
    });
    qos_add_test("shared-cq", "femu", femu_test_shared_cq, NULL);
    qos_add_test("cq-full", "femu", femu_test_cq_full, NULL);
    qos_add_test("io-interrupts", "femu", femu_test_io_interrupts, NULL);
    qos_add_test("dma-error", "femu", femu_test_dma_error, NULL);
    qos_add_test("queue-create-status", "femu", femu_test_queue_create_status,
                 NULL);
    qos_add_test("cc-states", "femu", femu_test_cc_states, NULL);
    qos_add_test("features-reset", "femu", femu_test_features_reset, NULL);
    qos_add_test("error-log", "femu", femu_test_error_log, NULL);
    qos_add_test("prp-status", "femu", femu_test_prp_status, NULL);
    qos_add_test("doorbell-errors", "femu", femu_test_doorbell_errors, NULL);
    qos_add_test("format-ses", "femu", femu_test_format_ses, NULL);
    qos_add_test("bar0-size", "femu", femu_test_bar0_size, NULL);
    qos_add_test("self-test", "femu", femu_test_self_test, NULL);
    qos_add_test("verify", "femu", femu_test_verify,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "oncs=0x86"
    });
    qos_add_test("aer-limit", "femu", femu_test_aer_limit,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "aerl=255"
    });
    qos_add_test("zoned-append-mdts0", "femu", femu_test_zoned_append_mdts0,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=3,secsz=512,mdts=0,zns_zasl_bs=0"
    });
    qos_add_test("kv-mdts", "femu", femu_test_kv_mdts,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "devsz_mb=512,femu_mode=5,mdts=1"
    });
    qos_add_test("kv-identify-reserved", "femu",
                 femu_test_kv_identify_reserved, &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "devsz_mb=512,femu_mode=5"
    });
    qos_add_test("log-contents-fdp", "femu", femu_test_log_contents_fdp,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "subsys=fdpsub,oncs=0x2"
    });
    qos_add_test("log-contents-zoned", "femu", femu_test_log_contents_zoned,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=3,secsz=512"
    });
    qos_add_test("mdts-unit", "femu", femu_test_mdts_unit,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "mpsmax=4,mdts=1"
    });
    qos_add_test("zone-change-notice", "femu", femu_test_zone_change_notice,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=3,secsz=512,err_write_fail_ppm=1000000"
    });
    qos_add_test("zone-active-limit", "femu", femu_test_zone_active_limit,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=3,secsz=512,zns_max_open=2,zns_max_active=2"
    });
    qos_add_test("zoned-compare", "femu", femu_test_zoned_compare,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=3,secsz=512,oncs=0x1"
    });
    qos_add_test("zone-open-limits", "femu", femu_test_zone_open_limits,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=3,secsz=512,zns_max_open=2"
    });
    qos_add_test("identify-fields", "femu", femu_test_identify_fields,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "namespaces=2"
    });
    qos_add_test("features-reset-vwc", "femu", femu_test_features_reset,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "vwc=1",
        .arg = &femu_vwc,
    });
    qos_add_test("sgl-zoned", "femu", femu_test_sgl_zoned,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=3,secsz=512,sgl=on"
    });
    qos_add_test("sgl-kv", "femu", femu_test_sgl_kv,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "devsz_mb=512,femu_mode=5,sgl=on"
    });
    qos_add_test("prp-list-offset", "femu", femu_test_prp_list_offset, NULL);
    qos_add_test("fdp-features", "femu", femu_test_fdp_features,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "subsys=fdpsub"
    });
    qos_add_test("dma-error-bbssd", "femu", femu_test_dma_error,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4",
    });
    qos_add_test("dma-error-zoned", "femu", femu_test_dma_error,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=3,secsz=512",
        .arg = &femu_zoned,
    });
    qos_add_test("shared-cq-pollers", "femu", femu_test_shared_cq,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "multipoller_enabled=1"
    });
    femu_csd_dir = g_strdup_printf("%s/femu-csd-%d", g_get_tmp_dir(),
                                   (int)getpid());
    qos_add_test("csd-program-dir", "femu", femu_test_csd_program_dir,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = g_strdup_printf(
            "femu_mode=4,fdm_size=16,csd_program_dir=%s", femu_csd_dir),
    });
    qos_add_test("buffer-counters", "femu", femu_test_buffer_counters,
                 &(QOSGraphTestOptions) {
        /* the same device with a buffer large enough that nothing destages */
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,buffer_size=64"
    });
}

libqos_init(femu_register_nodes);
