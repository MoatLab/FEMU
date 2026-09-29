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
#include "qobject/qdict.h"
#include "qobject/qjson.h"
#include "qobject/qlist.h"
#include "libqos/qgraph.h"
#include "libqos/pci.h"
#include "libqos/libqos-pc.h"
#include "libqos/libqos-malloc.h"
#include "block/nvme.h"
#include "hw/cxl/cxl_component.h"
#include "hw/cxl/cxl_device.h"
#include "hw/femu/tests/unit/hybrid-oracle.h"
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

/* Invalid namespace commands must not inherit a recycled transfer. */
static void femu_test_invalid_nsid_reuse(void *obj, void *data,
                                         QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd = { 0 };
    uint64_t buf;
    int64_t start;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    for (i = 0; i < FEMU_QSIZE; i++) {
        g_assert_cmpint(femu_rw(&c, NVME_CMD_READ, 0, buf), ==, NVME_SUCCESS);
    }

    cmd.opcode = NVME_CMD_READ;
    cmd.nsid = cpu_to_le32(2);
    start = g_get_monotonic_time();
    femu_submit(&c, &c.io, &cmd);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, NULL, NULL)), ==,
                   NVME_INVALID_NSID);
    g_assert_cmpint(g_get_monotonic_time() - start, <, G_USEC_PER_SEC);

    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
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

/*
 * A zoned write refused for its data pointer wrote nothing, so the zone's
 * write pointer must not move: the next write at the reported pointer has
 * to be accepted and land there.
 */
static void femu_test_zone_bad_dptr(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    NvmeRwCmd rw;
    uint8_t report[192];
    uint64_t buf;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, 3 * 4096);
    buf = (buf + 4095) & ~4095ULL;

    /* 4 KiB from mid-page needs a second PRP, and this one is unaligned */
    memset(&rw, 0, sizeof(rw));
    rw.opcode = NVME_CMD_WRITE;
    rw.nsid = cpu_to_le32(1);
    rw.dptr.prp1 = cpu_to_le64(buf + 0x800);
    rw.dptr.prp2 = cpu_to_le64(buf + 4096 + 8);
    rw.nlb = cpu_to_le16(FEMU_DATA_SIZE / c.lba_size - 1);
    femu_submit(&c, &c.io, (NvmeCmd *)&rw);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, NULL, NULL)), ==,
                    NVME_INVALID_PRP_OFFSET);

    femu_zone_report(&c, buf, report);
    g_assert_cmpuint(ldq_le_p(report + 64 + 24), ==, 0);
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 0, buf)), ==,
                    NVME_SUCCESS);
    femu_zone_report(&c, buf, report);
    g_assert_cmpuint(ldq_le_p(report + 64 + 24), ==,
                     FEMU_DATA_SIZE / c.lba_size);

    femu_disable(&c);
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
 * C0h LE64 counters: copies at 16, user programs at 24, hybrid switches at
 * 88, full merges at 96 and charged merge erases at 104. The merge counters
 * exclude physical line GC, which these short traces never require.
 */
static void femu_hybrid_check(FemuCtrlState *c, uint64_t buf,
                              const HybridOracle *o)
{
    uint8_t stats[512];

    g_assert_cmpint(femu_get_log(c, FEMU_LOG_FEMU_STATS, buf, sizeof(stats),
                                 0), ==, NVME_SUCCESS);
    qtest_memread(c->pdev->bus->qts, buf, stats, sizeof(stats));
    g_assert_cmpuint(ldq_le_p(stats + 24), ==, o->programs);
    g_assert_cmpuint(ldq_le_p(stats + 16), ==, o->copies);
    g_assert_cmpuint(ldq_le_p(stats + 88), ==, o->switches);
    g_assert_cmpuint(ldq_le_p(stats + 96), ==, o->merges);
    g_assert_cmpuint(ldq_le_p(stats + 104), ==, o->erases);
}

static void femu_test_hybrid_trim(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    HybridOracle oracle;
    uint64_t buf = guest_alloc(alloc, 4096);
    NvmeCmd cmd = { 0 };
    uint8_t range[16] = { 0 };
    unsigned i;
    uint16_t got;
    bool sequential = GPOINTER_TO_INT(data);

    hybrid_oracle_init(&oracle, 4, 16, 256);
    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    if (sequential) {
        /* Establish the old data block before opening its replacement log. */
        for (i = 0; i < 4; i++) {
            qtest_memset(c.pdev->bus->qts, buf, 0x5a, 4096);
            g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE, i * 8, buf), ==,
                            NVME_SUCCESS);
            hybrid_oracle_write(&oracle, i);
        }
    }
    qtest_memset(c.pdev->bus->qts, buf, 0x5a, 4096);
    g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE, 0, buf), ==, NVME_SUCCESS);
    hybrid_oracle_write(&oracle, 0);

    stl_le_p(range + 4, 8);
    qtest_memwrite(c.pdev->bus->qts, buf, range, sizeof(range));
    cmd.opcode = NVME_CMD_DSM;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw11 = cpu_to_le32(FEMU_DSM_AD);
    femu_submit(&c, &c.io, &cmd);
    g_assert_cmpint(femu_complete(&c, &c.io, &got, NULL), ==, NVME_SUCCESS);
    hybrid_oracle_trim(&oracle, 0);

    /* The trimmed slot is still programmed: three more writes fill the log. */
    for (i = 1; i < 4; i++) {
        qtest_memset(c.pdev->bus->qts, buf, 0x5a, 4096);
        g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE,
                                 (sequential ? i : 1) * 8, buf), ==,
                        NVME_SUCCESS);
        hybrid_oracle_write(&oracle, sequential ? i : 1);
    }
    femu_hybrid_check(&c, buf, &oracle);
    if (sequential) {
        uint8_t stats[512];

        g_assert_cmpint(femu_get_log(&c, FEMU_LOG_FEMU_STATS, buf,
                                     sizeof(stats), 0), ==, NVME_SUCCESS);
        qtest_memread(c.pdev->bus->qts, buf, stats, sizeof(stats));
        /* C0h byte 104: LE64 charged hybrid merge erases, excluding line GC. */
        g_assert_cmpuint(ldq_le_p(stats + 104), ==, 2);
    }
    hybrid_oracle_destroy(&oracle);
    femu_disable(&c);
    guest_free(alloc, buf);
}

static void femu_test_hybrid_trace(void *obj, void *data,
                                   QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    HybridOracle oracle;
    uint64_t buf = guest_alloc(alloc, 4096);
    uint8_t contents[256] = { 0 };
    unsigned kind = GPOINTER_TO_UINT(data);
    uint32_t random = 7;
    unsigned i;

    hybrid_oracle_init(&oracle, 4, 16, 256);
    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    for (i = 0; i < 96; i++) {
        unsigned lpn;

        switch (kind) {
        case 0:
            lpn = i % 32;
            break;
        case 1:
            random = random * 1664525U + 1013904223U;
            lpn = (random >> 16) % 96;
            break;
        case 2:
            lpn = 2;
            break;
        default:
            lpn = (i % 24) * 4 + i / 24;
            break;
        }
        contents[lpn] = i + 1;
        qtest_memset(c.pdev->bus->qts, buf, contents[lpn], 4096);
        g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE, lpn * 8, buf), ==,
                        NVME_SUCCESS);
        hybrid_oracle_write(&oracle, lpn);
        femu_hybrid_check(&c, buf, &oracle);
    }

    /* Merges must preserve the newest payload at every written offset. */
    for (i = 0; i < G_N_ELEMENTS(contents); i++) {
        uint8_t page[4096];
        unsigned j;

        if (!contents[i]) {
            continue;
        }
        g_assert_cmpint(femu_rw(&c, NVME_CMD_READ, i * 8, buf), ==,
                        NVME_SUCCESS);
        qtest_memread(c.pdev->bus->qts, buf, page, sizeof(page));
        for (j = 0; j < sizeof(page); j++) {
            g_assert_cmphex(page[j], ==, contents[i]);
        }
    }
    g_test_message("programs=%" PRIu64 " copies=%" PRIu64
                   " switches=%" PRIu64 " full-merges=%" PRIu64
                   " erases=%" PRIu64,
                   oracle.programs, oracle.copies, oracle.switches,
                   oracle.merges, oracle.erases);
    hybrid_oracle_destroy(&oracle);
    femu_disable(&c);
    guest_free(alloc, buf);
}

static void femu_hybrid_flush(FemuCtrlState *c)
{
    NvmeCmd cmd = { 0 };
    uint16_t got;

    cmd.opcode = NVME_CMD_FLUSH;
    cmd.nsid = cpu_to_le32(1);
    femu_submit(c, &c->io, &cmd);
    g_assert_cmpint(femu_complete(c, &c->io, &got, NULL), ==, NVME_SUCCESS);
}

static void femu_test_hybrid_batch(void *obj, void *data,
                                   QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    HybridOracle oracle;
    uint64_t buf = guest_alloc(alloc, 8192);
    bool buffered = GPOINTER_TO_INT(data);
    NvmeRwCmd rw = { 0 };
    uint16_t got;
    unsigned i;

    hybrid_oracle_init(&oracle, 4, 16, 256);
    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    for (i = 0; i < 3; i++) {
        qtest_memset(c.pdev->bus->qts, buf, 0x5a, 4096);
        g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE, i * 8, buf), ==,
                        NVME_SUCCESS);
        if (buffered) {
            femu_hybrid_flush(&c);
        }
        hybrid_oracle_write(&oracle, i);
        femu_hybrid_check(&c, buf, &oracle);
    }

    /* The first page fills the log; the second needs a fresh log. */
    qtest_memset(c.pdev->bus->qts, buf, 0xa5, 8192);
    rw.opcode = NVME_CMD_WRITE;
    rw.nsid = cpu_to_le32(1);
    rw.dptr.prp1 = cpu_to_le64(buf);
    rw.dptr.prp2 = cpu_to_le64(buf + 4096);
    rw.slba = cpu_to_le64(16);
    rw.nlb = cpu_to_le16(15);
    femu_submit(&c, &c.io, (NvmeCmd *)&rw);
    g_assert_cmpint(femu_complete(&c, &c.io, &got, NULL), ==, NVME_SUCCESS);
    if (buffered) {
        femu_hybrid_flush(&c);
    }
    hybrid_oracle_write(&oracle, 2);
    hybrid_oracle_write(&oracle, 3);
    femu_hybrid_check(&c, buf, &oracle);

    for (i = 0; i < 4; i++) {
        uint8_t page[4096];
        unsigned j;

        g_assert_cmpint(femu_rw(&c, NVME_CMD_READ, i * 8, buf), ==,
                        NVME_SUCCESS);
        qtest_memread(c.pdev->bus->qts, buf, page, sizeof(page));
        for (j = 0; j < sizeof(page); j++) {
            g_assert_cmphex(page[j], ==, i < 2 ? 0x5a : 0xa5);
        }
    }
    hybrid_oracle_destroy(&oracle);
    femu_disable(&c);
    guest_free(alloc, buf);
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

#define FEMU_FID_TIMESTAMP      0x0e
#define FEMU_ONCS_TIMESTAMP     (1 << 6)

/* Get or Set the Timestamp feature through an 8-byte buffer at buf */
static uint16_t femu_timestamp(FemuCtrlState *c, bool set, uint8_t sel,
                               uint32_t save, uint64_t buf)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = set ? NVME_ADM_CMD_SET_FEATURES : NVME_ADM_CMD_GET_FEATURES;
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(FEMU_FID_TIMESTAMP | sel << 8 | save << 31);
    return FEMU_SC(femu_admin(c, &cmd));
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
    const uint64_t host = 0x0123456789abULL;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    /* each event carries the Timestamp feature's value, as the host set it */
    pids = guest_alloc(alloc, 4096);
    qtest_writeq(femu->dev.bus->qts, pids, host);
    g_assert_cmpint(femu_timestamp(&c, true, 0, 0, pids), ==, NVME_SUCCESS);
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
        g_assert_cmpuint(ldq_le_p(ev + 4) & ((1ull << 48) - 1), >=, host);
        g_assert_cmpuint(ldq_le_p(ev + 4) & ((1ull << 48) - 1), <,
                         host + 60 * 1000);
        g_assert_cmpint(ev[10], ==, 1 << 1);            /* origin 001b */
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

    /*
     * Every identifier claimed must actually answer. The Persistent Event log
     * reads only within a reporting context, which its own test covers.
     */
    for (i = 0; i < 256; i++) {
        if (!(le32_to_cpu(lids[i]) & FEMU_LIDS_LSUPP) || i == 0x0d) {
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

static void femu_ns_fixture(QTestState *qts, const char *value);
static uint16_t femu_ns_delete(FemuCtrlState *c, uint32_t nsid);
static uint16_t femu_ns_create(FemuCtrlState *c, uint64_t buf, uint64_t nsze,
                               uint8_t flbas, uint32_t *nsid);
static uint16_t femu_ns_attach(FemuCtrlState *c, uint64_t buf, uint32_t nsid,
                               uint16_t cntlid, bool attach);

/* Delete must finish even when two SQs share a full CQ. */
static void femu_test_ns_retire(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    FemuQueue shared;
    FemuQueue other;
    NvmeCmd cmd = { 0 };
    NvmeCqe full[FEMU_QSIZE];
    NvmeCqe after[FEMU_QSIZE];
    NvmeCqe cqe;
    uint32_t result;
    uint64_t buf = guest_alloc(alloc, 4096);
    uint32_t seen = 0;
    uint32_t full_seen = 0;
    uint16_t first;
    uint16_t cid;
    uint16_t status;
    int waited = 0;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    if (data) {
        g_assert_cmpint(femu_ns_delete(&c, 0xffffffff), ==, NVME_SUCCESS);
        for (i = 1; i <= 2; i++) {
            g_assert_cmpint(femu_ns_create(&c, buf, 2048, 0, &result), ==,
                           NVME_SUCCESS);
            g_assert_cmpuint(result, ==, i);
            g_assert_cmpint(femu_ns_attach(&c, buf, i, 0, true), ==,
                           NVME_SUCCESS);
        }
    }
    femu_create_io_queues(&c);
    if (data) {
        /* Populate FTL state before exercising retirement. */
        femu_round_trip(&c, 0x5a);
    }
    femu_queue_init(&c, &shared, 2);
    cmd.opcode = NVME_ADM_CMD_CREATE_SQ;
    cmd.dptr.prp1 = cpu_to_le64(shared.sq_addr);
    cmd.cdw10 = cpu_to_le32(((FEMU_QSIZE - 1) << 16) | shared.qid);
    cmd.cdw11 = cpu_to_le32((c.io.qid << 16) | NVME_SQ_PC);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);

    femu_queue_init(&c, &other, 3);
    cmd.opcode = NVME_ADM_CMD_CREATE_CQ;
    cmd.dptr.prp1 = cpu_to_le64(other.cq_addr);
    cmd.cdw10 = cpu_to_le32(((FEMU_QSIZE - 1) << 16) | other.qid);
    cmd.cdw11 = cpu_to_le32(NVME_CQ_PC);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    cmd.opcode = NVME_ADM_CMD_CREATE_SQ;
    cmd.dptr.prp1 = cpu_to_le64(other.sq_addr);
    cmd.cdw11 = cpu_to_le32((other.qid << 16) | NVME_SQ_PC);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);

    /* Fill CQ1 and leave its head untouched throughout retirement. */
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_CMD_FLUSH;
    cmd.nsid = cpu_to_le32(1);
    first = c.cid;
    for (i = 0; i < FEMU_QSIZE - 1; i++) {
        femu_submit(&c, &c.io, &cmd);
    }
    do {
        qtest_memread(c.pdev->bus->qts,
                      c.io.cq_addr + (FEMU_QSIZE - 2) * sizeof(cqe),
                      &cqe, sizeof(cqe));
        g_assert_cmpint(waited++, <, FEMU_POLL_LIMIT_MS);
        g_usleep(1000);
    } while (!(le16_to_cpu(cqe.status) & 1));
    qtest_memread(c.pdev->bus->qts, c.io.cq_addr, full, sizeof(full));

    femu_ns_fixture(c.pdev->bus->qts, "retire");
    g_assert_cmpint(femu_ns_delete(&c, 1), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_create(&c, buf, 1024, 1, &result), ==,
                   NVME_SUCCESS);
    g_assert_cmpuint(result, ==, 1);
    g_assert_cmpint(femu_ns_attach(&c, buf, 1, 0, true), ==, NVME_SUCCESS);
    c.lba_size = 1024;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_CMD_FLUSH;
    cmd.nsid = cpu_to_le32(2);
    femu_submit(&c, &other, &cmd);
    g_assert_cmpint(femu_complete(&c, &other, &cid, NULL), ==, NVME_SUCCESS);
    g_assert_cmpint(cid, ==, le16_to_cpu(cmd.cid));
    qtest_memread(c.pdev->bus->qts, c.io.cq_addr, after, sizeof(after));
    g_assert_cmpmem(full, sizeof(full), after, sizeof(after));

    for (i = 0; i < FEMU_QSIZE - 1; i++) {
        g_assert_cmpint(femu_complete(&c, &c.io, &cid, NULL), ==, NVME_SUCCESS);
        g_assert_cmpuint(cid, >=, first);
        g_assert_cmpuint(cid, <, first + FEMU_QSIZE - 1);
        g_assert_cmphex(full_seen & (1u << (cid - first)), ==, 0);
        full_seen |= 1u << (cid - first);
    }
    for (i = 0; i < 9; i++) {
        status = femu_complete(&c, &c.io, &cid, &result);
        g_assert_cmpint(cid, >=, 0x8000);
        g_assert_cmpint(cid, <, 0x8009);
        g_assert_cmphex(seen & (1u << (cid - 0x8000)), ==, 0);
        seen |= 1u << (cid - 0x8000);
        g_assert_cmpint(status, ==, cid < 0x8003 ? NVME_INVALID_FIELD :
                       cid == 0x8003 ? NVME_LBA_RANGE : NVME_SUCCESS);
        g_assert_cmpuint(result, ==, cid < 0x8003 ? 0 : 0x100 + cid - 0x8000);
    }
    g_assert_cmphex(seen, ==, 0x1ff);
    /* Cycle both request pools to check recycling after deferred delivery. */
    for (i = 0; i < FEMU_QSIZE; i++) {
        femu_round_trip(&c, 0x69 + i);
        femu_submit(&c, &shared, &cmd);
        g_assert_cmpint(femu_complete(&c, &c.io, &cid, NULL), ==, NVME_SUCCESS);
        g_assert_cmpint(cid, ==, le16_to_cpu(cmd.cid));
    }
    qtest_memread(c.pdev->bus->qts,
                  c.io.cq_addr + c.io.cq_head * sizeof(cqe), &cqe, sizeof(cqe));
    g_assert_cmpint(le16_to_cpu(cqe.status) & 1, !=, c.io.phase);
    guest_free(alloc, buf);
    femu_disable(&c);
    femu_queue_free(&c, &c.io);
    femu_queue_free(&c, &other);
    femu_queue_free(&c, &shared);
    if (data) {
        qpci_unplug_acpi_device_test(c.pdev->bus->qts, "ns-test", 4);
    }
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
 * Protection information lives in the metadata, eight bytes of it, so a
 * format that turns it on must pick an LBA format with at least that much
 * (NVM 1.2, Format NVM). Advertising a protection type in DPC is not enough:
 * every format here has no metadata, and the command used to succeed and
 * leave the namespace reporting protection it had nowhere to keep.
 */
static void femu_test_format_pi_needs_metadata(void *obj, void *data,
                                              QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_identify(&c, 1, NVME_ID_CNS_NS, 0, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(qtest_readw(femu->dev.bus->qts, buf + 128 + 0), ==, 0);

    /* Type 1, with and without PIL */
    g_assert_cmpint(femu_format_dw10(&c, 1 << 5), ==, NVME_INVALID_FORMAT);
    g_assert_cmpint(femu_format_dw10(&c, (1 << 5) | (1 << 8)), ==,
                    NVME_INVALID_FORMAT);

    g_assert_cmpint(femu_identify(&c, 1, NVME_ID_CNS_NS, 0, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(qtest_readb(femu->dev.bus->qts, buf + 29), ==, 0); /* DPS */
    /* the plain format still works */
    g_assert_cmpint(femu_format_dw10(&c, 0), ==, NVME_SUCCESS);

    femu_disable(&c);
    guest_free(alloc, buf);
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

#define FEMU_ZRWA_SZ    128
#define FEMU_ZRWA_FG    32

/* a write of up to one page from buf */
static uint16_t femu_zrwa_write(FemuCtrlState *c, uint64_t slba, uint32_t nlb,
                                uint64_t buf)
{
    NvmeRwCmd rw;

    memset(&rw, 0, sizeof(rw));
    rw.opcode = NVME_CMD_WRITE;
    rw.nsid = cpu_to_le32(1);
    rw.slba = cpu_to_le64(slba);
    rw.nlb = cpu_to_le16(nlb - 1);
    rw.dptr.prp1 = cpu_to_le64(buf);
    return femu_io(c, (NvmeCmd *)&rw);
}

static uint64_t femu_zone0_wp(FemuCtrlState *c, uint64_t buf)
{
    uint8_t report[192];

    femu_zone_report(c, buf, report);
    return ldq_le_p(report + 64 + 24);
}

/*
 * ZNS 1.4, 5.7: a write that starts in the ZRWA or the implicit flush range
 * behind it may run to the end of the zone, and moves the write pointer by
 * whole flush granules. A write starting past that range is refused and
 * moves nothing.
 */
static void femu_test_zrwa_write_bounds(void *obj, void *data,
                                        QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint32_t open = NVME_ZONE_ACTION_OPEN | (NVME_ZSFLAG_ZRWA_ALLOC << 8);
    uint64_t mem, buf;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    mem = guest_alloc(alloc, 2 * 4096);
    buf = (mem + 4095) & ~4095ULL;

    g_assert_cmpint(femu_zone_action(&c, 0, open), ==, NVME_SUCCESS);

    /* inside the window: the write pointer stays */
    g_assert_cmpint(femu_zrwa_write(&c, 8, 8, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(femu_zone0_wp(&c, buf), ==, 0);

    /* starts in the flush range, ends past it: last LBA 257 */
    g_assert_cmpint(femu_zrwa_write(&c, 250, 8, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmpuint(femu_zone0_wp(&c, buf), ==,
                     ((257 - FEMU_ZRWA_SZ) / FEMU_ZRWA_FG + 1) * FEMU_ZRWA_FG);

    /* below the write pointer, and past the flush range */
    g_assert_cmpint(femu_zrwa_write(&c, 8, 8, buf), ==,
                    NVME_ZONE_INVALID_WRITE);
    g_assert_cmpint(femu_zrwa_write(&c, 160 + 2 * FEMU_ZRWA_SZ, 8, buf), ==,
                    NVME_ZONE_INVALID_WRITE);
    g_assert_cmpuint(femu_zone0_wp(&c, buf), ==, 160);

    guest_free(alloc, mem);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * Only sizes and flush lengths have to be whole flush granules (ZNS 1.4, 5.7);
 * a zone's start LBA need not be. With a granule of 3 blocks the second zone
 * starts off it and must still take a ZRWA.
 */
static void femu_test_zrwa_odd_granule(void *obj, void *data,
                                       QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint32_t open = NVME_ZONE_ACTION_OPEN | (NVME_ZSFLAG_ZRWA_ALLOC << 8);
    uint8_t report[192];
    uint64_t buf, second;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, 4096);
    femu_zone_report(&c, buf, report);
    second = ldq_le_p(report + 128 + 16);
    g_assert_cmpuint(second % 3, !=, 0);

    g_assert_cmpint(femu_zone_action(&c, second, open), ==, NVME_SUCCESS);
    femu_zone_report(&c, buf, report);
    g_assert_cmpint(report[128 + 2] & NVME_ZA_ZRWA_VALID, !=, 0);

    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * ZNS 1.4, 3.4.3.1.4.1: Set Zone Descriptor Extension allocates a ZRWA just
 * as Open Zone does, and takes it from the same pool.
 */
static void femu_test_zrwa_zd_ext(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint32_t open = NVME_ZONE_ACTION_OPEN | (NVME_ZSFLAG_ZRWA_ALLOC << 8);
    uint8_t report[192];
    uint64_t mem, buf, second;
    NvmeCmd cmd = { 0 };

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    mem = guest_alloc(alloc, 2 * 4096);
    buf = (mem + 4095) & ~4095ULL;
    femu_zone_report(&c, buf, report);
    second = ldq_le_p(report + 128 + 16);

    cmd.opcode = NVME_CMD_ZONE_MGMT_SEND;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(second);
    cmd.cdw11 = cpu_to_le32(second >> 32);
    cmd.cdw13 = cpu_to_le32(NVME_ZONE_ACTION_SET_ZD_EXT |
                            (NVME_ZSFLAG_ZRWA_ALLOC << 8));
    g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_SUCCESS);

    femu_zone_report(&c, buf, report);
    g_assert_cmpint(report[128 + 1] >> 4, ==, NVME_ZONE_STATE_CLOSED);
    g_assert_cmpint(report[128 + 2] & NVME_ZA_ZD_EXT_VALID, !=, 0);
    g_assert_cmpint(report[128 + 2] & NVME_ZA_ZRWA_VALID, !=, 0);
    /* the only resource is taken */
    g_assert_cmpint(femu_zone_action(&c, 0, open), ==, NVME_NOZRWA);

    /* the window takes random writes, then Finish gives the resource back */
    g_assert_cmpint(femu_zrwa_write(&c, second + 64, 8, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_zrwa_write(&c, second, 8, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_zone_action(&c, second, NVME_ZONE_ACTION_FINISH), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_zone_action(&c, 0, open), ==, NVME_SUCCESS);

    guest_free(alloc, mem);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
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

/*
 * On the pin with shadow doorbells, the host consumes a completion by moving
 * the shadow head and rings the register only when EventIdx asks. EventIdx
 * has to ask, and the ring has to drop the level: otherwise it stays asserted,
 * the line storms, and Linux disables the interrupt and falls back to polling.
 */
static void femu_test_intx_shadow_doorbell(void *obj, void *data,
                                           QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf;
    uint64_t eis_addr;
    NvmeCmd cmd;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    buf = guest_alloc(alloc, 4096);
    c.dbs_addr = guest_alloc(alloc, 4096);
    eis_addr = guest_alloc(alloc, 4096);
    qtest_memset(qts, c.dbs_addr, 0, 4096);
    qtest_memset(qts, eis_addr, 0, 4096);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_DBBUF_CONFIG;
    cmd.dptr.prp1 = cpu_to_le64(c.dbs_addr);
    cmd.dptr.prp2 = cpu_to_le64(eis_addr);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    femu_create_io_queues_irq(&c, 0);
    g_assert_false(femu_intx_asserted(&c));

    for (i = 0; i < 3; i++) {
        uint16_t old_head = c.io.cq_head;
        uint16_t ei;

        femu_read_unconsumed(&c, buf);
        FEMU_WAIT_FOR(femu_intx_asserted(&c));
        g_assert_cmpint(femu_complete(&c, &c.io, NULL, NULL), ==,
                        NVME_SUCCESS);
        /* ring only when EventIdx asks, as Linux's nvme_dbbuf_need_event() */
        ei = qtest_readl(qts, eis_addr + femu_cq_doorbell(&c, c.io.qid) -
                         0x1000);
        if ((uint16_t)(c.io.cq_head - ei - 1) <
            (uint16_t)(c.io.cq_head - old_head)) {
            qpci_io_writel(c.pdev, c.bar, femu_cq_doorbell(&c, c.io.qid),
                           c.io.cq_head);
        }
        g_assert_false(femu_intx_asserted(&c));
    }

    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

#define FEMU_FMT_NS_PAGES       4096        /* 16 MiB of 4 KiB pages */

/*
 * A Format erases the namespace, so the FTL has to let go of the old pages.
 * Kept mapped, garbage collection goes on relocating data nobody can read.
 *
 * Fill the namespace with the two halves interleaved, so every line holds
 * both. Format, then rewrite only the first half until collection runs: the
 * lines it picks held nothing but erased data, so it should move nothing.
 */
static void femu_test_format_ftl(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint32_t spp = 4096 / 512;
    uint64_t buf;
    uint8_t page[512];
    uint64_t gc;
    int pass;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, 4096);
    qtest_memset(qts, buf, 0x6b, 4096);

    for (i = 0; i < FEMU_FMT_NS_PAGES / 2; i++) {
        g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE, i * spp, buf), ==,
                        NVME_SUCCESS);
        g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE,
                                (i + FEMU_FMT_NS_PAGES / 2) * spp, buf), ==,
                        NVME_SUCCESS);
    }
    g_assert_cmpint(femu_format_dw10(&c, 0), ==, NVME_SUCCESS);

    for (pass = 0; pass < 8; pass++) {
        for (i = 0; i < FEMU_FMT_NS_PAGES / 2; i++) {
            g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE, i * spp, buf), ==,
                            NVME_SUCCESS);
        }
    }

    g_assert_cmpint(FEMU_SC(femu_get_log(&c, FEMU_LOG_FEMU_STATS, buf,
                                         sizeof(page), 0)), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, page, sizeof(page));
    gc = ldq_le_p(page + 16);
    g_assert_cmpint(ldq_le_p(page + 8), >, 0);
    g_assert_cmpint(gc, ==, 0);

    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

#define FEMU_ADM_SANITIZE       0x84
#define FEMU_LOG_SANITIZE       0x81

static uint16_t femu_sanitize(FemuCtrlState *c, uint32_t dw10)
{
    NvmeCmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_ADM_SANITIZE;
    cmd.cdw10 = cpu_to_le32(dw10);
    return FEMU_SC(femu_admin(c, &cmd));
}

/*
 * Sanitize block erase (Base 2.3, 5.2.24) on a device of block namespaces:
 * SANICAP offers it, Global Data Erased holds until a write and again after
 * an erase, the data reads back as zeros, and the operations not offered are
 * refused.
 */
static void femu_test_sanitize(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf;
    uint64_t log;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, 4096);
    log = guest_alloc(alloc, 4096);

    g_assert_cmpint(femu_identify(&c, 0, NVME_ID_CNS_CTRL, 0, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(qtest_readl(qts, buf + 328) & 0x2, ==, 0x2);

    g_assert_cmpint(femu_log_cmd(&c, 0, FEMU_LOG_SANITIZE, 0, log, 512), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(qtest_readw(qts, log + 2), ==, 0x100);     /* GDE, never */

    qtest_memset(qts, buf, 0x3c, 4096);
    g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_log_cmd(&c, 0, FEMU_LOG_SANITIZE, 0, log, 512), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(qtest_readw(qts, log + 2) & 0x100, ==, 0);

    g_assert_cmpint(femu_sanitize(&c, 0x2 | (1 << 10)), ==,
                    NVME_INVALID_FIELD);
    g_assert_cmpint(femu_sanitize(&c, 0x3), ==, NVME_INVALID_FIELD);
    g_assert_cmpint(femu_sanitize(&c, 0x2), ==, NVME_SUCCESS);

    g_assert_cmpint(femu_log_cmd(&c, 0, FEMU_LOG_SANITIZE, 0, log, 512), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(qtest_readw(qts, log), ==, 0xffff);        /* SPROG */
    g_assert_cmphex(qtest_readw(qts, log + 2), ==, 0x101);     /* GDE, done */
    g_assert_cmphex(qtest_readl(qts, log + 4), ==, 0x2);       /* SCDW10 */

    qtest_memset(qts, buf, 0xff, 4096);
    g_assert_cmpint(femu_rw(&c, NVME_CMD_READ, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, buf), ==, 0);
    g_assert_cmpint(femu_sanitize(&c, 0x1), ==, NVME_SUCCESS);

    guest_free(alloc, log);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

#define FEMU_CMD_COPY           0x19
#define FEMU_CMD_SIZE_LIMIT     0x183
#define FEMU_OVERLAP_IO_RANGE   0x187

/*
 * Copy of nr ranges; the first ndesc are laid out as format 0 descriptors in
 * guest memory at list, the rest left zero.
 */
static uint16_t femu_copy(FemuCtrlState *c, uint64_t list, uint64_t sdlba,
                          const uint64_t *slba, const uint16_t *nlb, int ndesc,
                          int nr, uint32_t dw12_extra)
{
    QTestState *qts = c->pdev->bus->qts;
    NvmeCmd cmd;
    int i;

    qtest_memset(qts, list, 0, 4096);
    for (i = 0; i < ndesc; i++) {
        qtest_writeq(qts, list + i * 32 + 8, slba[i]);
        qtest_writew(qts, list + i * 32 + 16, nlb[i] - 1);
    }
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_CMD_COPY;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(list);
    cmd.cdw10 = cpu_to_le32(sdlba);
    cmd.cdw11 = cpu_to_le32(sdlba >> 32);
    cmd.cdw12 = cpu_to_le32((nr - 1) | dw12_extra);
    return femu_io(c, &cmd);
}

#define FEMU_NS_INCOMPATIBLE    0x185

/* 4 KiB of 512-byte blocks on namespace nsid */
static uint16_t femu_rw_ns(FemuCtrlState *c, uint8_t opcode, uint32_t nsid,
                           uint64_t slba, uint64_t data)
{
    NvmeRwCmd rw = { 0 };

    rw.opcode = opcode;
    rw.nsid = cpu_to_le32(nsid);
    rw.dptr.prp1 = cpu_to_le64(data);
    rw.slba = cpu_to_le64(slba);
    rw.nlb = cpu_to_le16(FEMU_DATA_SIZE / 512 - 1);
    return femu_io(c, (NvmeCmd *)&rw);
}

#define FEMU_FEAT_HBS           0x16

/* Get (or, with set, Set) Host Behavior Support through a 512-byte buffer */
static uint16_t femu_hbs(FemuCtrlState *c, bool set, uint64_t buf)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = set ? NVME_ADM_CMD_SET_FEATURES : NVME_ADM_CMD_GET_FEATURES;
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(FEMU_FEAT_HBS);
    return FEMU_SC(femu_admin(c, &cmd));
}

/* a descriptor format 2 Copy of one range, from snsid into namespace 1 */
static uint16_t femu_copy_fmt2(FemuCtrlState *c, uint64_t list,
                               uint64_t sdlba, uint32_t snsid, uint64_t slba,
                               uint16_t nlb)
{
    QTestState *qts = c->pdev->bus->qts;
    NvmeCmd cmd = { 0 };

    qtest_memset(qts, list, 0, 4096);
    qtest_writel(qts, list, snsid);
    qtest_writeq(qts, list + 8, slba);
    qtest_writew(qts, list + 16, nlb - 1);
    cmd.opcode = FEMU_CMD_COPY;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(list);
    cmd.cdw10 = cpu_to_le32(sdlba);
    cmd.cdw11 = cpu_to_le32(sdlba >> 32);
    cmd.cdw12 = cpu_to_le32(2 << 8);             /* one range, format 2 */
    return femu_io(c, &cmd);
}

/*
 * Copy descriptor format 2 (NVM 1.2, 3.3.2): each range names the namespace
 * it comes from, which has to be a block namespace formatted the same way;
 * only ranges in the destination namespace can overlap the destination. The
 * host has to enable the format through Host Behavior Support first.
 */
static void femu_test_copy_fmt2(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint8_t w[FEMU_DATA_SIZE];
    uint8_t r[FEMU_DATA_SIZE];
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    g_assert_cmpint(femu_identify(&c, 0, NVME_ID_CNS_CTRL, 0, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(qtest_readw(qts, buf + 534) & 0x5, ==, 0x5);  /* OCFS */
    g_assert_cmpint(qtest_readw(qts, buf + 520) & (1 << 9), !=, 0); /* ONCS */

    /* not until the host enables it */
    g_assert_cmpint(femu_copy_fmt2(&c, list, 64, 2, 16, 8), ==,
                    NVME_INVALID_FIELD);
    g_assert_cmpint(femu_hbs(&c, false, buf), ==, NVME_SUCCESS);
    for (i = 0; i < 512; i++) {
        g_assert_cmpint(qtest_readb(qts, buf + i), ==, 0);
    }
    qtest_writeb(qts, buf, 2);                    /* ACRE is 0 or 1 */
    g_assert_cmpint(femu_hbs(&c, true, buf), ==, NVME_INVALID_FIELD);
    qtest_memset(qts, buf, 0, 512);
    qtest_writew(qts, buf + 4, 0x7);              /* bits 1:0 are not used */
    g_assert_cmpint(femu_hbs(&c, true, buf), ==, NVME_SUCCESS);
    qtest_memset(qts, buf, 0xff, 512);
    g_assert_cmpint(femu_hbs(&c, false, buf), ==, NVME_SUCCESS);
    g_assert_cmpint(qtest_readw(qts, buf + 4), ==, 0x4);
    g_assert_cmpint(qtest_readb(qts, buf), ==, 0);

    /* from namespace 2 into namespace 1 */
    for (i = 0; i < sizeof(w); i++) {
        w[i] = (uint8_t)(0x2c + i * 5);
    }
    qtest_memwrite(qts, buf, w, sizeof(w));
    g_assert_cmpint(femu_rw_ns(&c, NVME_CMD_WRITE, 2, 16, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_copy_fmt2(&c, list, 64, 2, 16, 8), ==, NVME_SUCCESS);
    qtest_memset(qts, buf, 0, sizeof(r));
    g_assert_cmpint(femu_rw_ns(&c, NVME_CMD_READ, 1, 64, buf), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, buf, r, sizeof(r));
    g_assert_cmpint(memcmp(w, r, sizeof(r)), ==, 0);

    /* the source has to exist */
    g_assert_cmpint(femu_copy_fmt2(&c, list, 64, 0, 16, 8), ==,
                    NVME_INVALID_NSID);
    g_assert_cmpint(femu_copy_fmt2(&c, list, 64, 3, 16, 8), ==,
                    NVME_INVALID_NSID);

    /* in the destination namespace, a source over the destination is refused */
    g_assert_cmpint(femu_copy_fmt2(&c, list, 64, 1, 60, 8), ==,
                    FEMU_OVERLAP_IO_RANGE);

    /* and it has to be formatted like the destination */
    {
        NvmeCmd f = { 0 };

        f.opcode = NVME_ADM_CMD_FORMAT_NVM;
        f.nsid = cpu_to_le32(2);
        f.cdw10 = cpu_to_le32(3);                 /* 4 KiB blocks */
        g_assert_cmpint(FEMU_SC(femu_admin(&c, &f)), ==, NVME_SUCCESS);
    }
    g_assert_cmpint(femu_copy_fmt2(&c, list, 64, 2, 1, 1), ==,
                    FEMU_NS_INCOMPATIBLE);

    femu_disable(&c);
    guest_free(alloc, list);
    guest_free(alloc, buf);
}

/*
 * Copy (NVM 1.2, 3.3.2): the limits Identify reports, two ranges landing back
 * to back at the destination and read back intact, the FTL charging the
 * programmed pages as a write would, and the refusals for an overlap, a range
 * or a command past the limits, and a descriptor format not offered.
 */
static void femu_test_copy(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf, list, log;
    uint64_t slba[2] = { 0, 64 };
    uint16_t nlb[2] = { 8, 8 };
    uint64_t host_before;
    uint8_t page[512];

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, 4096);
    list = guest_alloc(alloc, 4096);
    log = guest_alloc(alloc, 4096);

    g_assert_cmpint(femu_identify(&c, 0, NVME_ID_CNS_CTRL, 0, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(qtest_readw(qts, buf + 534) & 1, ==, 1);    /* OCFS */
    g_assert_cmpint(femu_identify(&c, 1, NVME_ID_CNS_NS, 0, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(qtest_readw(qts, buf + 74), ==, 128);       /* MSSRL */
    g_assert_cmpint(qtest_readl(qts, buf + 76), ==, 1024);      /* MCL */
    g_assert_cmpint(qtest_readb(qts, buf + 80), ==, 127);       /* MSRC */

    qtest_memset(qts, buf, 0xa1, 4096);
    g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE, 0, buf), ==, NVME_SUCCESS);
    qtest_memset(qts, buf, 0xb2, 4096);
    g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE, 64, buf), ==, NVME_SUCCESS);

    g_assert_cmpint(femu_get_log(&c, FEMU_LOG_FEMU_STATS, log, sizeof(page),
                                 0), ==, NVME_SUCCESS);
    qtest_memread(qts, log, page, sizeof(page));
    host_before = ldq_le_p(page + 8);

    g_assert_cmpint(femu_copy(&c, list, 256, slba, nlb, 2, 2, 0), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_rw(&c, NVME_CMD_READ, 256, buf), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, buf), ==, 0xa1);
    g_assert_cmphex(qtest_readb(qts, buf + 4095), ==, 0xa1);
    g_assert_cmpint(femu_rw(&c, NVME_CMD_READ, 264, buf), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, buf), ==, 0xb2);

    /* the destination was programmed through the FTL: two 4 KiB pages */
    g_assert_cmpint(femu_get_log(&c, FEMU_LOG_FEMU_STATS, log, sizeof(page),
                                 0), ==, NVME_SUCCESS);
    qtest_memread(qts, log, page, sizeof(page));
    g_assert_cmpint(ldq_le_p(page + 8) - host_before, ==, 2);

    /* a source that runs into the destination */
    slba[0] = 256;
    g_assert_cmpint(femu_copy(&c, list, 260, slba, nlb, 1, 1, 0), ==,
                    FEMU_OVERLAP_IO_RANGE);
    /* one range past MSSRL, more ranges than MSRC allows */
    slba[0] = 0;
    nlb[0] = 129;
    g_assert_cmpint(femu_copy(&c, list, 512, slba, nlb, 1, 1, 0), ==,
                    FEMU_CMD_SIZE_LIMIT);
    nlb[0] = 8;
    g_assert_cmpint(femu_copy(&c, list, 512, slba, nlb, 1, 256, 0), ==,
                    FEMU_CMD_SIZE_LIMIT);
    /* descriptor format 1 is not offered */
    g_assert_cmpint(femu_copy(&c, list, 512, slba, nlb, 1, 1, 1 << 8), ==,
                    NVME_INVALID_FIELD);

    guest_free(alloc, log);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/* A Read, Write or Compare of nlb blocks with separate metadata at mptr. */
static uint16_t femu_rw_md(FemuCtrlState *c, uint8_t opcode, uint64_t slba,
                           uint16_t nlb, uint64_t data, uint64_t mptr,
                           uint8_t psdt)
{
    NvmeRwCmd rw = { 0 };

    rw.opcode = opcode;
    rw.flags = psdt << 6;
    rw.nsid = cpu_to_le32(1);
    rw.mptr = cpu_to_le64(mptr);
    rw.dptr.prp1 = cpu_to_le64(data);
    rw.dptr.prp2 = cpu_to_le64(data + 4096);
    rw.slba = cpu_to_le64(slba);
    rw.nlb = cpu_to_le16(nlb - 1);
    return femu_io(c, (NvmeCmd *)&rw);
}

#define FEMU_MD_MS      8
#define FEMU_MD_NLBAF   5           /* the nlbaf default */

static uint16_t femu_pi_io(FemuCtrlState *c, uint8_t opcode, uint32_t nsid,
                           uint64_t slba, uint16_t nlb, uint64_t dbuf,
                           uint64_t mbuf, uint8_t prinfo, uint32_t ref,
                           uint16_t app, uint16_t mask)
{
    NvmeRwCmd rw = { 0 };

    rw.opcode = opcode;
    rw.nsid = cpu_to_le32(nsid);
    rw.slba = cpu_to_le64(slba);
    rw.nlb = cpu_to_le16(nlb - 1);
    rw.dptr.prp1 = cpu_to_le64(dbuf);
    rw.dptr.prp2 = cpu_to_le64(dbuf + 4096);
    rw.mptr = cpu_to_le64(mbuf);
    rw.control = cpu_to_le16(prinfo << 10);
    rw.reftag = cpu_to_le32(ref);
    rw.apptag = cpu_to_le16(app);
    rw.appmask = cpu_to_le16(mask);
    return FEMU_SC(femu_io(c, (NvmeCmd *)&rw));
}

static void femu_pi_tuple(uint8_t *m, uint16_t guard, uint16_t app,
                          uint32_t ref)
{
    stw_be_p(m, guard);
    stw_be_p(m + 2, app);
    stl_be_p(m + 4, ref);
}

/* Fixed T10-DIF vectors, including metadata before a final PI tuple. */
static void femu_test_pi_verify(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t dbuf = guest_alloc(alloc, 4096);
    uint64_t mbuf = guest_alloc(alloc, 4096);
    unsigned int ms = GPOINTER_TO_UINT(data);
    uint8_t d[1024];
    uint8_t m[32];
    unsigned int type;
    unsigned int first;
    unsigned int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    for (i = 0; i < sizeof(d); i++) {
        d[i] = i;
    }
    qtest_memwrite(qts, dbuf, d, sizeof(d));
    for (type = 1; type <= 3; type++) {
        for (first = 0; first <= 1; first++) {
            unsigned int off = first ? 0 : ms - 8;
            uint16_t guard = off ? 0xe876 : 0x4f10;
            uint32_t ref = type == 1 ? 16 : 0xffffffff;

            g_assert_cmpint(femu_format_dw10(&c, FEMU_MD_NLBAF |
                           (type << 5) | (first << 8)), ==, NVME_SUCCESS);
            memset(m, 0xa5, sizeof(m));
            femu_pi_tuple(m + off, guard, 0x1234, ref);
            femu_pi_tuple(m + ms + off, guard, 0x1234,
                          type == 3 ? ref : ref + 1);
            qtest_memwrite(qts, mbuf, m, 2 * ms);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_WRITE, 1, 16, 2,
                           dbuf, mbuf, 0, ref, 0x1234, 0xffff), ==,
                           NVME_SUCCESS);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_VERIFY, 1, 16, 2,
                           1, 1, 7, ref, 0x1234, 0xffff), ==, NVME_SUCCESS);
            for (i = 0; i < 3; i++) {
                unsigned int byte = off + 2 * i;
                uint16_t expected = 0x282 + i;

                m[byte] ^= 1;
                qtest_memwrite(qts, mbuf, m, 2 * ms);
                g_assert_cmpint(femu_pi_io(&c, NVME_CMD_WRITE, 1, 16, 2,
                               dbuf, mbuf, 0, ref, 0, 0), ==, NVME_SUCCESS);
                g_assert_cmpint(femu_pi_io(&c, NVME_CMD_VERIFY, 1, 16, 2,
                               1, 1, 7, ref, 0x1234, 0xffff), ==,
                               type == 3 && i == 2 ? NVME_SUCCESS : expected);
                m[byte] ^= 1;
            }
            qtest_memwrite(qts, mbuf, m, 2 * ms);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_WRITE, 1, 16, 2,
                           dbuf, mbuf, 0, ref, 0, 0), ==, NVME_SUCCESS);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_VERIFY, 1, 16, 2,
                           1, 1, 7, ref, 0x12ab, 0xff00), ==, NVME_SUCCESS);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_VERIFY, 1, 16, 2,
                           1, 1, 7, ref, 0xabcd, 0), ==, NVME_SUCCESS);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_VERIFY, 1, 16, 2,
                           1, 1, 8, ref, 0, 0), ==, NVME_INVALID_FIELD);
            if (type == 1) {
                g_assert_cmpint(femu_pi_io(&c, NVME_CMD_VERIFY, 1, 16, 2,
                               1, 1, 1, 17, 0, 0), ==,
                               NVME_INVALID_PROT_INFO);
            }
            /* Escape tuples disable checks even with an invalid guard. */
            femu_pi_tuple(m + off, 1, 0xffff, 0xffffffff);
            femu_pi_tuple(m + ms + off, 1, 0xffff, 0xffffffff);
            qtest_memwrite(qts, mbuf, m, 2 * ms);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_WRITE, 1, 16, 2,
                           dbuf, mbuf, 0, ref, 0, 0), ==, NVME_SUCCESS);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_VERIFY, 1, 16, 2,
                           1, 1, 7, ref, 0, 0xffff), ==, NVME_SUCCESS);
            if (type == 3) {
                m[off + 7] = 0;
                qtest_memwrite(qts, mbuf, m, 2 * ms);
                g_assert_cmpint(femu_pi_io(&c, NVME_CMD_WRITE, 1, 16, 2,
                               dbuf, mbuf, 0, ref, 0, 0), ==, NVME_SUCCESS);
                g_assert_cmpint(femu_pi_io(&c, NVME_CMD_VERIFY, 1, 16, 2,
                               1, 1, 4, ref, 0, 0), ==, 0x282);
            }
            /* Unwritten blocks use escape tags. */
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_VERIFY, 1, 32, 2,
                           1, 1, 7, type == 1 ? 32 : ref, 0, 0xffff), ==,
                           NVME_SUCCESS);
        }
    }
    femu_disable(&c);
    guest_free(alloc, mbuf);
    guest_free(alloc, dbuf);
}

/* Construct the host transfer without sharing the device's PI helpers. */
static void femu_pi_host(QTestState *qts, uint64_t dbuf, uint64_t mbuf,
                         const uint8_t *d, const uint8_t *m, unsigned int ms,
                         bool extended)
{
    unsigned int i;

    if (extended) {
        for (i = 0; i < 2; i++) {
            qtest_memwrite(qts, dbuf + i * (512 + ms), d + i * 512, 512);
            qtest_memwrite(qts, dbuf + i * (512 + ms) + 512, m + i * ms, ms);
        }
    } else {
        qtest_memwrite(qts, dbuf, d, 1024);
        qtest_memwrite(qts, mbuf, m, 2 * ms);
    }
}

static void femu_pi_result(QTestState *qts, uint64_t dbuf, uint64_t mbuf,
                           const uint8_t *d, const uint8_t *m, unsigned int ms,
                           bool extended)
{
    uint8_t rd[1024];
    uint8_t rm[32];
    unsigned int i;

    if (extended) {
        for (i = 0; i < 2; i++) {
            qtest_memread(qts, dbuf + i * (512 + ms), rd + i * 512, 512);
            qtest_memread(qts, dbuf + i * (512 + ms) + 512, rm + i * ms, ms);
        }
    } else {
        qtest_memread(qts, dbuf, rd, sizeof(rd));
        qtest_memread(qts, mbuf, rm, 2 * ms);
    }
    g_assert_cmpmem(rd, sizeof(rd), d, 1024);
    g_assert_cmpmem(rm, 2 * ms, m, 2 * ms);
}

static uint16_t femu_ns_create_pi(FemuCtrlState *c, uint64_t buf,
                                  uint8_t flbas, uint8_t dps, uint32_t *nsid)
{
    QTestState *qts = c->pdev->bus->qts;
    NvmeCmd cmd = { 0 };

    qos_invalidate_command_line();
    qtest_memset(qts, buf, 0, 4096);
    qtest_writeq(qts, buf, 128);
    qtest_writeq(qts, buf + 8, 128);
    qtest_writeb(qts, buf + 26, flbas);
    qtest_writeb(qts, buf + 29, dps);
    cmd.opcode = 0x0d;
    cmd.dptr.prp1 = cpu_to_le64(buf);
    return FEMU_SC(femu_admin_result(c, &cmd, nsid));
}

static void femu_test_pi_rw(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t dbuf = guest_alloc(alloc, 8192);
    uint64_t mbuf = guest_alloc(alloc, 4096);
    unsigned int ms = GPOINTER_TO_UINT(data) & 0xff;
    bool extended = GPOINTER_TO_UINT(data) & 0x100;
    bool create = GPOINTER_TO_UINT(data) & 0x200;
    uint16_t cntlid = 0;
    uint8_t d[1024];
    uint8_t m[32];
    unsigned int type;
    unsigned int first;
    unsigned int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    if (create) {
        g_assert_cmpint(femu_identify(&c, 0, 1, 0, mbuf), ==, NVME_SUCCESS);
        cntlid = qtest_readw(qts, mbuf + 78);
    }
    for (i = 0; i < sizeof(d); i++) {
        d[i] = i;
    }
    for (type = 1; type <= 3; type++) {
        for (first = 0; first <= 1; first++) {
            unsigned int off = first ? 0 : ms - 8;
            uint16_t guard = off ? 0xe876 : 0x4f10;
            uint32_t ref = type == 1 ? 16 : 0xffffffff;

            if (create) {
                uint32_t nsid;
                uint8_t clean[1024] = { 0 };
                uint8_t fresh[32] = { 0 };

                g_assert_cmpint(femu_ns_delete(&c, 1), ==, NVME_SUCCESS);
                g_assert_cmpint(femu_ns_create_pi(&c, mbuf, FEMU_MD_NLBAF |
                               (extended << 4), type | (first << 3),
                               &nsid), ==, NVME_SUCCESS);
                g_assert_cmpuint(nsid, ==, 1);
                g_assert_cmpint(femu_identify(&c, nsid, 0x11, 0, mbuf), ==,
                               NVME_SUCCESS);
                g_assert_cmphex(qtest_readb(qts, mbuf + 28), ==, 0x1f);
                g_assert_cmphex(qtest_readb(qts, mbuf + 29), ==,
                               type | (first << 3));
                g_assert_cmpint(femu_ns_attach(&c, mbuf, nsid, cntlid, true),
                               ==, NVME_SUCCESS);
                g_assert_cmpint(femu_identify(&c, nsid, 0, 0, mbuf), ==,
                               NVME_SUCCESS);
                g_assert_cmphex(qtest_readb(qts, mbuf + 29), ==,
                               type | (first << 3));
                memset(fresh + off, 0xff, 8);
                memset(fresh + ms + off, 0xff, 8);
                g_assert_cmpint(femu_pi_io(&c, NVME_CMD_READ, 1, 16, 2,
                               dbuf, mbuf, 7, ref, 0, 0xffff), ==,
                               NVME_SUCCESS);
                femu_pi_result(qts, dbuf, mbuf, clean, fresh, ms, extended);
            } else {
                g_assert_cmpint(femu_format_dw10(&c, FEMU_MD_NLBAF |
                               (type << 5) | (first << 8) | (extended << 4)),
                               ==, NVME_SUCCESS);
            }
            memset(m, 0xa5, sizeof(m));
            femu_pi_host(qts, dbuf, mbuf, d, m, ms == 8 ? 0 : ms, extended);
            /* PRACT writes ignore every PRCHK bit, including ILBRT checks. */
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_WRITE, 1, 16, 2,
                           dbuf, ms == 8 ? 1 : mbuf, 15, 0, 0x1234,
                           0xffff), ==, NVME_SUCCESS);
            if (type == 1) {
                g_assert_cmpint(femu_pi_io(&c, NVME_CMD_READ, 1, 16, 2,
                               dbuf, mbuf, 15, 0, 0x1234, 0xffff), ==,
                               NVME_INVALID_PROT_INFO);
            }
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_WRITE, 1, 16, 2,
                           dbuf, ms == 8 ? 1 : mbuf, 15, ref, 0x1234,
                           0xffff), ==, NVME_SUCCESS);
            femu_pi_tuple(m + off, guard, 0x1234, ref);
            femu_pi_tuple(m + ms + off, guard, 0x1234,
                          type == 3 ? ref : ref + 1);
            qtest_memset(qts, dbuf, 0, 4096);
            qtest_memset(qts, mbuf, 0, 4096);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_READ, 1, 16, 2,
                           dbuf, mbuf, 7, ref, 0x1234, 0xffff), ==,
                           NVME_SUCCESS);
            femu_pi_result(qts, dbuf, mbuf, d, m, ms, extended);
            /* A failed checked write must leave the previous pair intact. */
            m[off] ^= 1;
            femu_pi_host(qts, dbuf, mbuf, d, m, ms, extended);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_WRITE, 1, 16, 2,
                           dbuf, mbuf, 7, ref, 0x1234, 0xffff), ==, 0x282);
            m[off] ^= 1;
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_READ, 1, 16, 2,
                           dbuf, mbuf, 7, ref, 0x1234, 0xffff), ==,
                           NVME_SUCCESS);
            femu_pi_result(qts, dbuf, mbuf, d, m, ms, extended);
            for (i = 0; i < 3; i++) {
                unsigned int byte = off + 2 * i;

                m[byte] ^= 1;
                femu_pi_host(qts, dbuf, mbuf, d, m, ms, extended);
                g_assert_cmpint(femu_pi_io(&c, NVME_CMD_WRITE, 1, 16, 2,
                               dbuf, mbuf, 0, ref, 0, 0), ==, NVME_SUCCESS);
                g_assert_cmpint(femu_pi_io(&c, NVME_CMD_READ, 1, 16, 2,
                               dbuf, mbuf, 7, ref, 0x1234, 0xffff), ==,
                               type == 3 && i == 2 ? NVME_SUCCESS : 0x282 + i);
                m[byte] ^= 1;
            }
            femu_pi_host(qts, dbuf, mbuf, d, m, ms, extended);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_WRITE, 1, 16, 2,
                           dbuf, mbuf, 7, ref, 0x1234, 0xffff), ==,
                           NVME_SUCCESS);
            qtest_memset(qts, mbuf, 0x5a, 4096);
            qtest_memset(qts, dbuf, 0x5a, 4096);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_READ, 1, 16, 2,
                           dbuf, ms == 8 ? 1 : mbuf, 15, ref, 0x1234,
                           0xffff), ==, NVME_SUCCESS);
            femu_pi_result(qts, dbuf, mbuf, d, m, ms == 8 ? 0 : ms, extended);
            if (ms == 8) {
                g_assert_cmphex(qtest_readb(qts, mbuf), ==, 0x5a);
                g_assert_cmphex(qtest_readb(qts, dbuf + 1024), ==, 0x5a);
            }
            /* DLFEAT.GDS=0 requires an all-ones guard and escape tags. */
            memset(d, 0, sizeof(d));
            memset(m, 0, sizeof(m));
            memset(m + off, 0xff, 8);
            memset(m + ms + off, 0xff, 8);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_READ, 1, 64, 2,
                           dbuf, mbuf, 7, type == 1 ? 64 : ref, 0, 0xffff), ==,
                           NVME_SUCCESS);
            femu_pi_result(qts, dbuf, mbuf, d, m, ms, extended);
            {
                NvmeCmd cmd = { 0 };
                uint8_t range[16] = { 0 };

                stl_le_p(range + 4, 2);
                stq_le_p(range + 8, 16);
                qtest_memwrite(qts, mbuf, range, sizeof(range));
                cmd.opcode = NVME_CMD_DSM;
                cmd.nsid = cpu_to_le32(1);
                cmd.dptr.prp1 = cpu_to_le64(mbuf);
                cmd.cdw11 = cpu_to_le32(FEMU_DSM_AD);
                g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_SUCCESS);
                g_assert_cmpint(femu_pi_io(&c, NVME_CMD_READ, 1, 16, 2,
                               dbuf, mbuf, 7, ref, 0, 0xffff), ==,
                               NVME_SUCCESS);
                femu_pi_result(qts, dbuf, mbuf, d, m, ms, extended);
            }
            for (i = 0; i < sizeof(d); i++) {
                d[i] = i;
            }
            if (create) {
                femu_pi_host(qts, dbuf, mbuf, d, m, ms == 8 ? 0 : ms,
                             extended);
                g_assert_cmpint(femu_pi_io(&c, NVME_CMD_WRITE, 1, 16, 2,
                               dbuf, mbuf, 15, ref, 0x1234, 0xffff), ==,
                               NVME_SUCCESS);
            }
        }
    }
    if (extended && ms == 8) {
        g_assert_cmpint(femu_pi_io(&c, NVME_CMD_READ, 1, 64, 16,
                       dbuf, 1, 15, 64, 0, 0xffff), ==, NVME_SUCCESS);
        g_assert_cmpint(femu_pi_io(&c, NVME_CMD_READ, 1, 64, 16,
                       dbuf, mbuf, 7, 64, 0, 0xffff), ==, NVME_INVALID_FIELD);
    }
    if (create) {
        uint32_t nsid;

        g_assert_cmpint(femu_ns_delete(&c, 1), ==, NVME_SUCCESS);
        g_assert_cmpint(femu_ns_create_pi(&c, mbuf, FEMU_MD_NLBAF |
                       (extended << 4), 0, &nsid), ==, NVME_SUCCESS);
        g_assert_cmpint(femu_identify(&c, nsid, 0x11, 0, mbuf), ==,
                       NVME_SUCCESS);
        g_assert_cmphex(qtest_readb(qts, mbuf + 29), ==, 0);
        g_assert_cmpint(femu_ns_attach(&c, mbuf, nsid, cntlid, true), ==,
                       NVME_SUCCESS);
        memset(d, 0, sizeof(d));
        memset(m, 0, sizeof(m));
        g_assert_cmpint(femu_pi_io(&c, NVME_CMD_READ, nsid, 16, 2,
                       dbuf, mbuf, 0, 0, 0, 0), ==, NVME_SUCCESS);
        femu_pi_result(qts, dbuf, mbuf, d, m, ms, extended);
    }
    femu_disable(&c);
    guest_free(alloc, mbuf);
    guest_free(alloc, dbuf);
}

static void femu_test_ns_create_pi_validation(void *obj, void *data,
                                               QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    bool enabled = GPOINTER_TO_UINT(data);
    unsigned int type;
    unsigned int first;
    unsigned int extended;
    unsigned int lbaf;
    uint32_t nsid;

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_ns_delete(&c, 1), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_create(&c, buf, 128, 0, &nsid), ==, NVME_SUCCESS);
    for (type = 0; type <= 7; type++) {
        for (first = 0; first <= 1; first++) {
            for (extended = 0; extended <= 1; extended++) {
                for (lbaf = 0; lbaf <= FEMU_MD_NLBAF; lbaf += FEMU_MD_NLBAF) {
                    uint16_t status;

                    status = femu_format_dw10(&c, lbaf | (extended << 4) |
                                             (type << 5) | (first << 8));
                    /* Preserve the PI-off Create refusal of nonzero DPS. */
                    if (!enabled && first && !type) {
                        status = NVME_INVALID_FORMAT;
                    }
                    g_assert_cmpint(femu_ns_create_pi(&c, buf,
                                   lbaf | (extended << 4), type | (first << 3),
                                   &nsid), ==, status);
                    if (status == NVME_SUCCESS) {
                        g_assert_cmpint(femu_identify(&c, nsid, 0x11, 0, buf),
                                       ==, NVME_SUCCESS);
                        g_assert_cmphex(qtest_readb(qts, buf + 28), ==,
                                       GPOINTER_TO_UINT(data) == 1 ? 0x1f : 0);
                        g_assert_cmphex(qtest_readb(qts, buf + 29), ==,
                                       type ? type | (first << 3) : 0);
                        g_assert_cmpint(femu_ns_delete(&c, nsid), ==,
                                       NVME_SUCCESS);
                    }
                }
            }
        }
    }
    g_assert_cmpint(femu_ns_create_pi(&c, buf, 15, 1, &nsid), ==,
                   NVME_INVALID_FORMAT);
    g_assert_cmpint(femu_ns_create_pi(&c, buf, FEMU_MD_NLBAF, 0x11, &nsid),
                   ==, NVME_INVALID_FORMAT);
    femu_disable(&c);
    guest_free(alloc, buf);
}

static void femu_test_pi_compare(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t dbuf = guest_alloc(alloc, 4096);
    uint64_t mbuf = guest_alloc(alloc, 4096);
    uint8_t d[1024] = { 0 };
    uint8_t m[32] = { 0 };
    unsigned int first;
    unsigned int extended;
    unsigned int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    for (first = 0; first <= 1; first++) {
        for (extended = 0; extended <= 1; extended++) {
            unsigned int off = first ? 0 : 8;
            unsigned int other = first ? 8 : 0;

            g_assert_cmpint(femu_format_dw10(&c, FEMU_MD_NLBAF | (1 << 5) |
                           (first << 8) | (extended << 4)), ==, NVME_SUCCESS);
            memset(m, 0, sizeof(m));
            femu_pi_tuple(m + off, 0, 0x1234, 16);
            femu_pi_tuple(m + 16 + off, 0, 0x1234, 17);
            femu_pi_host(qts, dbuf, mbuf, d, m, 16, extended);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_WRITE, 1, 16, 2,
                           dbuf, mbuf, 7, 16, 0x1234, 0xffff), ==,
                           NVME_SUCCESS);
            /* PI is checked as requested, and excluded from comparison. */
            m[off + 2] ^= 1;
            femu_pi_host(qts, dbuf, mbuf, d, m, 16, extended);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_COMPARE, 1, 16, 2,
                           dbuf, mbuf, 0, 16, 0, 0), ==, NVME_SUCCESS);
            m[off + 2] ^= 1;
            for (i = 0; i < 3; i++) {
                m[off + 2 * i] ^= 1;
                femu_pi_host(qts, dbuf, mbuf, d, m, 16, extended);
                g_assert_cmpint(femu_pi_io(&c, NVME_CMD_COMPARE, 1, 16, 2,
                               dbuf, mbuf, 7, 16, 0x1234, 0xffff), ==,
                               0x282 + i);
                /* The same checks apply to PI read from the device. */
                g_assert_cmpint(femu_pi_io(&c, NVME_CMD_WRITE, 1, 16, 2,
                               dbuf, mbuf, 0, 16, 0, 0), ==, NVME_SUCCESS);
                m[off + 2 * i] ^= 1;
                femu_pi_host(qts, dbuf, mbuf, d, m, 16, extended);
                g_assert_cmpint(femu_pi_io(&c, NVME_CMD_COMPARE, 1, 16, 2,
                               dbuf, mbuf, 7, 16, 0x1234, 0xffff), ==,
                               0x282 + i);
                g_assert_cmpint(femu_pi_io(&c, NVME_CMD_WRITE, 1, 16, 2,
                               dbuf, mbuf, 7, 16, 0x1234, 0xffff), ==,
                               NVME_SUCCESS);
            }
            m[other] ^= 1;
            femu_pi_host(qts, dbuf, mbuf, d, m, 16, extended);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_COMPARE, 1, 16, 2,
                           dbuf, mbuf, 0, 16, 0, 0), ==, NVME_CMP_FAILURE);
            m[other] ^= 1;
            d[0] ^= 1;
            femu_pi_host(qts, dbuf, mbuf, d, m, 16, extended);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_COMPARE, 1, 16, 2,
                           dbuf, mbuf, 0, 16, 0, 0), ==, NVME_CMP_FAILURE);
            d[0] ^= 1;
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_COMPARE, 1, 16, 2,
                           dbuf, mbuf, 8, 16, 0, 0), ==,
                           NVME_INVALID_PROT_INFO);
        }
    }
    femu_disable(&c);
    guest_free(alloc, mbuf);
    guest_free(alloc, dbuf);
}

static void femu_test_pi_zeroes(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t dbuf = guest_alloc(alloc, 4096);
    uint64_t mbuf = guest_alloc(alloc, 4096);
    uint8_t d[1024] = { 0 };
    uint8_t m[32];
    unsigned int type;
    unsigned int first;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    for (type = 1; type <= 3; type++) {
        for (first = 0; first <= 1; first++) {
            unsigned int off = first ? 0 : 8;
            uint32_t ref = type == 1 ? 16 : UINT32_MAX;
            NvmeRwCmd rw = { 0 };

            g_assert_cmpint(femu_format_dw10(&c, FEMU_MD_NLBAF |
                           (type << 5) | (first << 8)), ==, NVME_SUCCESS);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_WRITE_ZEROES, 1, 16, 2,
                           1, 1, 8, ref, 0x1234, 0), ==, NVME_SUCCESS);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_READ, 1, 16, 2,
                           dbuf, mbuf, 7, ref, 0x1234, 0xffff), ==,
                           NVME_SUCCESS);
            memset(m, 0, sizeof(m));
            femu_pi_tuple(m + off, 0, 0x1234, ref);
            femu_pi_tuple(m + 16 + off, 0, 0x1234,
                          type == 3 ? ref : ref + 1);
            femu_pi_result(qts, dbuf, mbuf, d, m, 16, false);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_WRITE_ZEROES, 1, 16, 2,
                           1, 1, 15, 0, 0x1234, 0xffff), ==, NVME_SUCCESS);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_READ, 1, 16, 2,
                           dbuf, mbuf, 6, 0, 0x1234, 0xffff), ==,
                           NVME_SUCCESS);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_WRITE_ZEROES, 1, 16, 2,
                           1, 1, 7, ref, 0, 0), ==, NVME_INVALID_PROT_INFO);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_WRITE_ZEROES, 1, 16, 2,
                           1, 1, 0, ref, 0x1234, 0), ==, NVME_SUCCESS);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_READ, 1, 16, 2,
                           dbuf, mbuf, 0, ref, 0, 0), ==, NVME_SUCCESS);
            memset(m, 0, sizeof(m));
            femu_pi_result(qts, dbuf, mbuf, d, m, 16, false);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_READ, 1, 16, 2,
                           dbuf, mbuf, 2, ref, 0x1234, 0xffff), ==, 0x283);
            rw.opcode = NVME_CMD_WRITE_ZEROES;
            rw.nsid = cpu_to_le32(1);
            rw.slba = cpu_to_le64(16);
            rw.nlb = cpu_to_le16(1);
            rw.control = cpu_to_le16((8 << 10) | (1 << 9));
            g_assert_cmpint(femu_io(&c, (NvmeCmd *)&rw), ==, NVME_SUCCESS);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_READ, 1, 16, 2,
                           dbuf, mbuf, 7, ref, 0x1234, 0xffff), ==,
                           NVME_SUCCESS);
            memset(m + off, 0xff, 8);
            memset(m + 16 + off, 0xff, 8);
            femu_pi_result(qts, dbuf, mbuf, d, m, 16, false);
        }
    }
    femu_disable(&c);
    guest_free(alloc, mbuf);
    guest_free(alloc, dbuf);
}

static uint16_t femu_pi_format_ns(FemuCtrlState *c, uint32_t nsid,
                                  uint32_t dw10)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = NVME_ADM_CMD_FORMAT_NVM;
    cmd.nsid = cpu_to_le32(nsid);
    cmd.cdw10 = cpu_to_le32(dw10);
    return FEMU_SC(femu_admin(c, &cmd));
}

static uint16_t femu_pi_copy(FemuCtrlState *c, uint64_t list, uint64_t dst,
                             uint8_t fmt, uint8_t nr, uint8_t prinfor,
                             uint8_t prinfow, uint32_t ref, uint16_t app)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = FEMU_CMD_COPY;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(list);
    cmd.cdw10 = cpu_to_le32(dst);
    cmd.cdw11 = cpu_to_le32(dst >> 32);
    cmd.cdw12 = cpu_to_le32((nr - 1) | (fmt << 8) | (prinfor << 12) |
                           (prinfow << 26));
    cmd.cdw14 = cpu_to_le32(ref);
    cmd.cdw15 = cpu_to_le32(0xffff0000U | app);
    return FEMU_SC(femu_io(c, &cmd));
}

static void femu_pi_range(QTestState *qts, uint64_t list, uint32_t nsid,
                          uint64_t slba, uint32_t ref)
{
    uint8_t range[32] = { 0 };

    stl_le_p(range, nsid);
    stq_le_p(range + 8, slba);
    stw_le_p(range + 16, 1);
    stl_le_p(range + 24, ref);
    stw_le_p(range + 28, 0x12ab);
    stw_le_p(range + 30, 0xff00);
    qtest_memwrite(qts, list, range, sizeof(range));
}

static void femu_test_pi_generate_ref(void *obj, void *data,
                                       QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t dbuf = guest_alloc(alloc, 4096);
    uint64_t mbuf = guest_alloc(alloc, 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    unsigned int ms = GPOINTER_TO_UINT(data) & 0xff;
    unsigned int opcode = GPOINTER_TO_UINT(data) >> 8;
    uint8_t d[1024] = { 0 };
    uint8_t m[32];
    unsigned int first;
    unsigned int variant;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, list, 0, 512);
    qtest_writeb(qts, list + 4, 1 << 2);
    g_assert_cmpint(femu_hbs(&c, true, list), ==, NVME_SUCCESS);
    for (first = 0; first <= 1; first++) {
        for (variant = 0; variant <= 1; variant++) {
            bool copy = opcode == FEMU_CMD_COPY;
            bool extended = !copy && variant;
            unsigned int fmt = copy && variant ? 2 : 0;
            uint32_t snsid = fmt == 2 ? 2 : 1;
            uint32_t format = FEMU_MD_NLBAF | (1 << 5) | (first << 8) |
                              (extended << 4);
            unsigned int off = first ? 0 : ms - 8;
            unsigned int nlb = copy ? 4 : 2;
            unsigned int i;

            g_assert_cmpint(femu_pi_format_ns(&c, 1, format), ==, NVME_SUCCESS);
            g_assert_cmpint(femu_pi_format_ns(&c, 2, format), ==, NVME_SUCCESS);
            memset(m, 0, sizeof(m));
            femu_pi_host(qts, dbuf, mbuf, d, m, ms == 8 ? 0 : ms, extended);
            if (copy) {
                g_assert_cmpint(femu_pi_io(&c, NVME_CMD_WRITE, snsid, 16, 2,
                               dbuf, mbuf, 8, 16, 0x1234, 0), ==, NVME_SUCCESS);
                femu_pi_range(qts, list, snsid, 16, 16);
                femu_pi_range(qts, list + 32, snsid, 16, 16);
                g_assert_cmpint(femu_pi_copy(&c, list, 64, fmt, 2, 8, 8,
                               UINT32_MAX, 0xabcd), ==, NVME_SUCCESS);
            } else {
                g_assert_cmpint(femu_pi_io(&c, opcode, 1, 64, 2, dbuf, mbuf,
                               8, UINT32_MAX, 0xabcd, 0), ==, NVME_SUCCESS);
            }
            for (i = 0; i < nlb; i += 2) {
                uint32_t ref = UINT32_MAX + i;
                uint8_t stored[4];
                uint64_t addr = extended ? dbuf + 512 : mbuf;

                g_assert_cmpint(femu_pi_io(&c, NVME_CMD_READ, 1, 64 + i, 2,
                               dbuf, mbuf, 0, 0, 0, 0), ==, NVME_SUCCESS);
                qtest_memread(qts, addr + off + 4, stored, sizeof(stored));
                g_assert_cmphex((uint32_t)ldl_be_p(stored), ==, ref);
                femu_pi_tuple(m + off, 0, 0xabcd, ref);
                femu_pi_tuple(m + ms + off, 0, 0xabcd, ref + 1);
                femu_pi_result(qts, dbuf, mbuf, d, m, ms, extended);
            }
        }
    }
    femu_disable(&c);
    guest_free(alloc, list);
    guest_free(alloc, mbuf);
    guest_free(alloc, dbuf);
}

static void femu_test_pi_copy_no_pi(void *obj, void *data,
                                     QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t dbuf = guest_alloc(alloc, 4096);
    uint64_t mbuf = guest_alloc(alloc, 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint8_t d[512];
    uint8_t m[8];
    uint8_t rd[512];
    uint8_t rm[8];
    unsigned int fmt;
    unsigned int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, list, 0, 512);
    qtest_writeb(qts, list + 4, 1 << 2);
    g_assert_cmpint(femu_hbs(&c, true, list), ==, NVME_SUCCESS);
    for (fmt = 0; fmt <= 2; fmt += 2) {
        uint32_t snsid = fmt == 2 ? 2 : 1;

        for (i = 0; i < 128; i++) {
            memset(d, i, sizeof(d));
            memset(m, i ^ 0xa5, sizeof(m));
            qtest_memwrite(qts, dbuf, d, sizeof(d));
            qtest_memwrite(qts, mbuf, m, sizeof(m));
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_WRITE, snsid, 16 + i, 1,
                           dbuf, mbuf, 15, 0, 0, 0xffff), ==, NVME_SUCCESS);
            femu_pi_range(qts, list + i * 32, snsid, 16 + 127 - i, 0);
            qtest_writew(qts, list + i * 32 + 16, 0);
        }
        g_assert_cmpint(femu_pi_copy(&c, list, 512, fmt, 128, 15, 15, 0, 0), ==,
                       NVME_SUCCESS);
        for (i = 0; i < 128; i++) {
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_READ, 1, 512 + i, 1,
                           dbuf, mbuf, 15, 0, 0, 0xffff), ==, NVME_SUCCESS);
            memset(d, 127 - i, sizeof(d));
            memset(m, (127 - i) ^ 0xa5, sizeof(m));
            qtest_memread(qts, dbuf, rd, sizeof(rd));
            qtest_memread(qts, mbuf, rm, sizeof(rm));
            g_assert_cmpmem(rd, sizeof(rd), d, sizeof(d));
            g_assert_cmpmem(rm, sizeof(rm), m, sizeof(m));
        }
    }
    femu_disable(&c);
    guest_free(alloc, list);
    guest_free(alloc, mbuf);
    guest_free(alloc, dbuf);
}

static void femu_test_pi_copy(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t dbuf = guest_alloc(alloc, 4096);
    uint64_t mbuf = guest_alloc(alloc, 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    unsigned int ms = GPOINTER_TO_UINT(data) & 0xff;
    unsigned int fmt = GPOINTER_TO_UINT(data) >> 8;
    uint32_t snsid = fmt == 2 ? 2 : 1;
    uint8_t d[1024];
    uint8_t m[32];
    unsigned int type;
    unsigned int first;
    unsigned int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    if (fmt == 2) {
        qtest_memset(qts, list, 0, 512);
        qtest_writeb(qts, list + 4, 1 << 2);
        g_assert_cmpint(femu_hbs(&c, true, list), ==, NVME_SUCCESS);
    }
    for (type = 1; type <= 3; type++) {
        for (first = 0; first <= 1; first++) {
            uint32_t format = FEMU_MD_NLBAF | (type << 5) | (first << 8);
            uint32_t ref = type == 1 ? 16 : UINT32_MAX;
            uint32_t ref2 = type == 1 ? 32 : 0x12345678;
            uint32_t dstref = type == 1 ? 64 : 0xfffffffe;
            unsigned int off = first ? 0 : ms - 8;

            g_assert_cmpint(femu_pi_format_ns(&c, 1, format), ==, NVME_SUCCESS);
            if (fmt == 2) {
                g_assert_cmpint(femu_pi_format_ns(&c, 2, format), ==,
                               NVME_SUCCESS);
            }
            memset(d, 0, sizeof(d));
            memset(m, 0, sizeof(m));
            femu_pi_host(qts, dbuf, mbuf, d, m, ms, false);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_WRITE, snsid, 16, 2,
                           dbuf, mbuf, 15, ref, 0x1234, 0xffff), ==,
                           NVME_SUCCESS);
            for (i = 0; i < sizeof(d); i++) {
                d[i] = i;
            }
            femu_pi_host(qts, dbuf, mbuf, d, m, ms, false);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_WRITE, snsid, 32, 2,
                           dbuf, mbuf, 15, ref2, 0x1234, 0xffff), ==,
                           NVME_SUCCESS);
            femu_pi_range(qts, list, snsid, 16, ref);
            femu_pi_range(qts, list + 32, snsid, 32, ref2);
            /* Only destination PRCHK is ignored when generating new PI. */
            g_assert_cmpint(femu_pi_copy(&c, list, 192, fmt, 2, 15, 15,
                           0, 0xabcd), ==, NVME_SUCCESS);
            g_assert_cmpint(femu_pi_copy(&c, list, 64, fmt, 2, 15, 7,
                           dstref, 0xabcd), ==, NVME_INVALID_FIELD);
            g_assert_cmpint(femu_pi_copy(&c, list, 64, fmt, 2, 15, 15,
                           dstref, 0xabcd), ==, NVME_SUCCESS);
            for (i = 0; i < 2; i++) {
                unsigned int j;
                uint32_t expected_ref = type == 3 ? dstref : dstref + i * 2;
                uint16_t guard = 0;

                for (j = 0; j < sizeof(d); j++) {
                    d[j] = i ? j : 0;
                }
                if (i) {
                    /* CRC over the data and, for last PI, eight zero bytes. */
                    guard = off ? 0x3219 : 0x4f10;
                }
                memset(m, 0, sizeof(m));
                femu_pi_tuple(m + off, guard, 0xabcd, expected_ref);
                femu_pi_tuple(m + ms + off, guard, 0xabcd,
                              type == 3 ? expected_ref : expected_ref + 1);
                g_assert_cmpint(femu_pi_io(&c, NVME_CMD_READ, 1, 64 + i * 2, 2,
                               dbuf, mbuf, 7, expected_ref, 0xabcd, 0xffff), ==,
                               NVME_SUCCESS);
                femu_pi_result(qts, dbuf, mbuf, d, m, ms, false);
            }
            /* Pass-through retains the source tuple. */
            g_assert_cmpint(femu_pi_copy(&c, list, 128, fmt, 1, 0, 0,
                           128, 0), ==, NVME_SUCCESS);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_READ, snsid, 16, 2,
                           dbuf, mbuf, 0, ref, 0, 0), ==, NVME_SUCCESS);
            qtest_memread(qts, mbuf, m, 2 * ms);
            memset(d, 0, sizeof(d));
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_READ, 1, 128, 2,
                           dbuf, mbuf, 0, 128, 0, 0), ==, NVME_SUCCESS);
            femu_pi_result(qts, dbuf, mbuf, d, m, ms, false);
            g_assert_cmpint(femu_pi_copy(&c, list, 128, fmt, 1, 7, 7,
                           128, 0x1234), ==,
                           type == 3 ? NVME_SUCCESS : 0x284);
            /* Corrupt a later source; the destination must stay intact. */
            for (i = 0; i < 3; i++) {
                unsigned int j;

                g_assert_cmpint(femu_pi_io(&c, NVME_CMD_READ, snsid, 32, 2,
                               dbuf, mbuf, 0, ref2, 0, 0), ==, NVME_SUCCESS);
                qtest_memread(qts, mbuf, m, 2 * ms);
                m[off + 2 * i] ^= 1;
                qtest_memwrite(qts, mbuf, m, 2 * ms);
                g_assert_cmpint(femu_pi_io(&c, NVME_CMD_WRITE, snsid, 32, 2,
                               dbuf, mbuf, 0, ref2, 0, 0), ==, NVME_SUCCESS);
                g_assert_cmpint(femu_pi_copy(&c, list, 64, fmt, 2, 15, 15,
                               dstref, type == 3 && i == 2 ? 0xabcd : 0x7777),
                               ==, type == 3 && i == 2 ? NVME_SUCCESS :
                                                        0x282 + i);
                g_assert_cmpint(femu_pi_io(&c, NVME_CMD_READ, 1, 64, 4,
                               dbuf, mbuf, 7, dstref, 0xabcd, 0xffff), ==,
                               NVME_SUCCESS);
                /* Restore with generated PI and the original source data. */
                for (j = 0; j < sizeof(d); j++) {
                    d[j] = j;
                }
                memset(m, 0, sizeof(m));
                femu_pi_host(qts, dbuf, mbuf, d, m, ms, false);
                g_assert_cmpint(femu_pi_io(&c, NVME_CMD_WRITE, snsid, 32, 2,
                               dbuf, mbuf, 15, ref2, 0x1234, 0xffff), ==,
                               NVME_SUCCESS);
            }
        }
    }
    femu_disable(&c);
    guest_free(alloc, list);
    guest_free(alloc, mbuf);
    guest_free(alloc, dbuf);
}

static void femu_test_pi_copy_convert(void *obj, void *data,
                                      QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t dbuf = guest_alloc(alloc, 4096);
    uint64_t mbuf = guest_alloc(alloc, 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint8_t d[1024];
    uint8_t out[1024];

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, list, 0, 512);
    qtest_writeb(qts, list + 4, 1 << 2);
    g_assert_cmpint(femu_hbs(&c, true, list), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_pi_format_ns(&c, 1, FEMU_MD_NLBAF | (1 << 5)), ==,
                   NVME_SUCCESS);
    g_assert_cmpint(femu_pi_format_ns(&c, 2, 0), ==, NVME_SUCCESS);
    memset(d, 0x5a, sizeof(d));
    qtest_memwrite(qts, dbuf, d, sizeof(d));
    g_assert_cmpint(femu_pi_io(&c, NVME_CMD_WRITE, 2, 16, 2,
                   dbuf, 1, 0, 0, 0, 0), ==, NVME_SUCCESS);
    femu_pi_range(qts, list, 2, 16, 16);
    g_assert_cmpint(femu_pi_copy(&c, list, 64, 2, 1, 0, 15, 64, 0xabcd), ==,
                   NVME_SUCCESS);
    g_assert_cmpint(femu_pi_io(&c, NVME_CMD_READ, 1, 64, 2,
                   dbuf, mbuf, 7, 64, 0xabcd, 0xffff), ==, NVME_SUCCESS);
    qtest_memread(qts, dbuf, out, sizeof(out));
    g_assert_cmpmem(out, sizeof(out), d, sizeof(d));
    g_assert_cmpint(femu_pi_copy(&c, list, 64, 2, 1, 0, 0, 64, 0), ==,
                   FEMU_NS_INCOMPATIBLE);
    /* A later source cannot change from inserting PI to replacing it. */
    femu_pi_range(qts, list + 32, 1, 64, 64);
    g_assert_cmpint(femu_pi_copy(&c, list, 128, 2, 2, 15, 15, 128, 0xabcd), ==,
                   FEMU_NS_INCOMPATIBLE);
    g_assert_cmpint(femu_pi_copy(&c, list, 128, 2, 2, 0, 15, 128, 0xabcd), ==,
                   FEMU_NS_INCOMPATIBLE);
    g_assert_cmpint(femu_pi_format_ns(&c, 1, 0), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_pi_format_ns(&c, 2, FEMU_MD_NLBAF | (2 << 5)), ==,
                   NVME_SUCCESS);
    qtest_memwrite(qts, dbuf, d, sizeof(d));
    g_assert_cmpint(femu_pi_io(&c, NVME_CMD_WRITE, 2, 16, 2,
                   dbuf, 1, 15, 0xffffffff, 0x1234, 0xffff), ==, NVME_SUCCESS);
    femu_pi_range(qts, list, 2, 16, 0xffffffff);
    g_assert_cmpint(femu_pi_copy(&c, list, 64, 2, 1, 15, 0, 0, 0), ==,
                   NVME_SUCCESS);
    g_assert_cmpint(femu_pi_io(&c, NVME_CMD_READ, 1, 64, 2,
                   dbuf, 1, 0, 0, 0, 0), ==, NVME_SUCCESS);
    qtest_memread(qts, dbuf, out, sizeof(out));
    g_assert_cmpmem(out, sizeof(out), d, sizeof(d));
    g_assert_cmpint(femu_pi_copy(&c, list, 64, 2, 1, 7, 0, 0, 0), ==,
                   FEMU_NS_INCOMPATIBLE);
    g_assert_cmpint(femu_pi_format_ns(&c, 1, FEMU_MD_NLBAF | (1 << 5)), ==,
                   NVME_SUCCESS);
    g_assert_cmpint(femu_pi_copy(&c, list, 64, 2, 1, 15, 15, 64, 0), ==,
                   FEMU_NS_INCOMPATIBLE);
    g_assert_cmpint(femu_pi_format_ns(&c, 2, FEMU_MD_NLBAF | (1 << 5) |
                   (1 << 8)), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_pi_copy(&c, list, 64, 2, 1, 15, 15, 64, 0), ==,
                   FEMU_NS_INCOMPATIBLE);
    g_assert_cmpint(femu_pi_format_ns(&c, 2, FEMU_MD_NLBAF), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_pi_copy(&c, list, 64, 2, 1, 0, 15, 64, 0), ==,
                   FEMU_NS_INCOMPATIBLE);
    femu_disable(&c);
    guest_free(alloc, list);
    guest_free(alloc, mbuf);
    guest_free(alloc, dbuf);
}

static void femu_test_pi_dpc_no_metadata(void *obj, void *data,
                                          QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    unsigned int dpc = GPOINTER_TO_UINT(data);

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_identify(&c, 1, NVME_ID_CNS_NS, 0, buf), ==,
                   NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, buf + 28), ==, dpc);
    g_assert_cmphex(qtest_readb(qts, buf + 29), ==, 0);
    g_assert_cmpint(femu_format_dw10(&c, 1 << 5), ==, NVME_INVALID_FORMAT);
    femu_disable(&c);
    guest_free(alloc, buf);
}

static void femu_test_pi_format(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    bool enabled = GPOINTER_TO_INT(data);
    unsigned int type;
    unsigned int first;
    unsigned int lbaf;

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_identify(&c, 1, NVME_ID_CNS_NS, 0, buf), ==,
                   NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, buf + 28), ==, enabled ? 0x1f : 0);
    g_assert_cmphex(qtest_readb(qts, buf + 29), ==, 0);
    for (type = 1; type <= 3; type++) {
        for (first = 0; first <= 1; first++) {
            uint32_t dw10 = FEMU_MD_NLBAF | (type << 5) | (first << 8);

            g_assert_cmpint(femu_format_dw10(&c, dw10), ==,
                           enabled ? NVME_SUCCESS : NVME_INVALID_FORMAT);
            g_assert_cmpint(femu_identify(&c, 1, NVME_ID_CNS_NS, 0, buf), ==,
                           NVME_SUCCESS);
            g_assert_cmphex(qtest_readb(qts, buf + 29), ==,
                           enabled ? type | (first << 3) : 0);
        }
    }
    g_assert_cmpint(femu_format_dw10(&c, FEMU_MD_NLBAF | (4 << 5)), ==,
                   NVME_INVALID_FORMAT);
    g_assert_cmpint(femu_format_dw10(&c, 1 << 5), ==, NVME_INVALID_FORMAT);
    if (enabled) {
        g_assert_cmpint(femu_format_dw10(&c, FEMU_MD_NLBAF | (1 << 12)), ==,
                       NVME_INVALID_FORMAT);
    }
    g_assert_cmpint(femu_format_dw10(&c, FEMU_MD_NLBAF), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_identify(&c, 1, NVME_ID_CNS_NS, 0, buf), ==,
                   NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, buf + 29), ==, 0);
    for (lbaf = 0; lbaf <= FEMU_MD_NLBAF; lbaf += FEMU_MD_NLBAF) {
        g_assert_cmpint(femu_format_dw10(&c, lbaf | (1 << 8)), ==,
                       NVME_SUCCESS);
        g_assert_cmpint(femu_identify(&c, 1, NVME_ID_CNS_NS, 0, buf), ==,
                       NVME_SUCCESS);
        g_assert_cmphex(qtest_readb(qts, buf + 29), ==, enabled ? 0 : 8);
        g_assert_cmpint(femu_format_dw10(&c, lbaf), ==, NVME_SUCCESS);
        g_assert_cmpint(femu_identify(&c, 1, NVME_ID_CNS_NS, 0, buf), ==,
                       NVME_SUCCESS);
        g_assert_cmphex(qtest_readb(qts, buf + 29), ==, 0);
    }
    if (!enabled) {
        femu_create_io_queues(&c);
        qtest_memset(qts, buf, 0x5a, 512);
        qtest_memset(qts, buf + 2048, 0xa5, 8);
        g_assert_cmpint(femu_pi_io(&c, NVME_CMD_WRITE, 1, 16, 1, buf,
                       buf + 2048, 15, 0, 0, 0xffff), ==, NVME_SUCCESS);
        qtest_memset(qts, buf, 0, 4096);
        g_assert_cmpint(femu_pi_io(&c, NVME_CMD_READ, 1, 16, 1, buf,
                       buf + 2048, 15, 0, 0, 0xffff), ==, NVME_SUCCESS);
        g_assert_cmphex(qtest_readq(qts, buf), ==, 0x5a5a5a5a5a5a5a5aULL);
        g_assert_cmphex(qtest_readq(qts, buf + 504), ==, 0x5a5a5a5a5a5a5a5aULL);
        g_assert_cmphex(qtest_readq(qts, buf + 2048), ==,
                        0xa5a5a5a5a5a5a5a5ULL);
    }
    femu_disable(&c);
    guest_free(alloc, buf);
}

/*
 * Separate LBA metadata (NVM 1.2, 2.1.4): each block size is offered with and
 * without metadata, the device boots on the one with it, and every command
 * that moves or drops blocks treats their metadata the same way.
 */
static void femu_test_metadata(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t raw = 0;
    uint64_t buf = femu_alloc_64k(alloc, &raw);
    uint64_t dbuf = buf, mbuf = buf + 0x4000, list = buf + 0x8000;
    uint8_t d[1024], m[64], r[1024], rm[64];
    const uint64_t cslba[1] = { 16 };
    const uint16_t cnlb[1] = { 2 };
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    g_assert_cmpint(femu_identify(&c, 1, NVME_ID_CNS_NS, 0, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(qtest_readb(qts, buf + 25), ==,
                    2 * FEMU_MD_NLBAF - 1);                 /* NLBAF */
    g_assert_cmpint(qtest_readb(qts, buf + 26) & 0xf, ==, FEMU_MD_NLBAF);
    g_assert_cmpint(qtest_readw(qts, buf + 128), ==, 0);    /* LBAF0 MS */
    g_assert_cmpint(qtest_readw(qts, buf + 128 + 4 * FEMU_MD_NLBAF), ==,
                    FEMU_MD_MS);
    g_assert_cmpint(qtest_readb(qts, buf + 27) & 0x2, ==, 0x2); /* MC */

    /* data and metadata go in together and come back together */
    for (i = 0; i < sizeof(d); i++) {
        d[i] = (uint8_t)(0x31 + i * 3);
    }
    for (i = 0; i < sizeof(m); i++) {
        m[i] = (uint8_t)(0xa0 + i);
    }
    qtest_memwrite(qts, dbuf, d, sizeof(d));
    qtest_memwrite(qts, mbuf, m, 2 * FEMU_MD_MS);
    g_assert_cmpint(femu_rw_md(&c, NVME_CMD_WRITE, 16, 2, dbuf, mbuf, 0), ==,
                    NVME_SUCCESS);
    qtest_memset(qts, dbuf, 0, sizeof(d));
    qtest_memset(qts, mbuf, 0, sizeof(m));
    g_assert_cmpint(femu_rw_md(&c, NVME_CMD_READ, 16, 2, dbuf, mbuf, 0), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, dbuf, r, sizeof(r));
    qtest_memread(qts, mbuf, rm, 2 * FEMU_MD_MS);
    g_assert_cmpint(memcmp(d, r, sizeof(r)), ==, 0);
    g_assert_cmpint(memcmp(m, rm, 2 * FEMU_MD_MS), ==, 0);

    /* a misaligned MPTR, or MPTR as an SGL, is refused */
    g_assert_cmpint(femu_rw_md(&c, NVME_CMD_READ, 16, 2, dbuf, mbuf + 2, 0),
                    ==, NVME_INVALID_FIELD);
    g_assert_cmpint(femu_rw_md(&c, NVME_CMD_READ, 16, 2, dbuf, mbuf, 2),
                    ==, NVME_INVALID_FIELD);

    /* metadata that cannot be fetched fails the write and changes nothing */
    qtest_memset(qts, dbuf, 0x77, sizeof(d));
    g_assert_cmpint(femu_rw_md(&c, NVME_CMD_WRITE, 16, 2, dbuf,
                               0xffffffff00000000ULL, 0), ==,
                    NVME_DATA_TRAS_ERROR);
    g_assert_cmpint(femu_rw_md(&c, NVME_CMD_READ, 16, 2, dbuf, mbuf, 0), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, dbuf, r, sizeof(r));
    qtest_memread(qts, mbuf, rm, 2 * FEMU_MD_MS);
    g_assert_cmpint(memcmp(d, r, sizeof(r)), ==, 0);
    g_assert_cmpint(memcmp(m, rm, 2 * FEMU_MD_MS), ==, 0);

    /*
     * A write whose data cannot all be fetched changes nothing either: the
     * second page of this one is outside guest memory, and the first page
     * used to land before the transfer failed, next to the old metadata.
     */
    {
        NvmeRwCmd w = { 0 };
        uint8_t big[8192];
        uint8_t rbig[8192];
        uint8_t mm[16 * FEMU_MD_MS];
        uint8_t rmm[16 * FEMU_MD_MS];

        for (i = 0; i < sizeof(big); i++) {
            big[i] = (uint8_t)(0x13 + i * 7);
        }
        for (i = 0; i < sizeof(mm); i++) {
            mm[i] = (uint8_t)(0x55 ^ i);
        }
        qtest_memwrite(qts, dbuf, big, sizeof(big));
        qtest_memwrite(qts, mbuf, mm, sizeof(mm));
        g_assert_cmpint(femu_rw_md(&c, NVME_CMD_WRITE, 128, 16, dbuf, mbuf, 0),
                        ==, NVME_SUCCESS);

        qtest_memset(qts, dbuf, 0x99, 4096);
        qtest_memset(qts, mbuf, 0x99, sizeof(mm));
        w.opcode = NVME_CMD_WRITE;
        w.nsid = cpu_to_le32(1);
        w.mptr = cpu_to_le64(mbuf);
        w.dptr.prp1 = cpu_to_le64(dbuf);
        w.dptr.prp2 = cpu_to_le64(0xffffffff00000000ULL);
        w.slba = cpu_to_le64(128);
        w.nlb = cpu_to_le16(15);
        g_assert_cmpint(femu_io(&c, (NvmeCmd *)&w), ==, NVME_DATA_TRAS_ERROR);

        g_assert_cmpint(femu_rw_md(&c, NVME_CMD_READ, 128, 16, dbuf, mbuf, 0),
                        ==, NVME_SUCCESS);
        qtest_memread(qts, dbuf, rbig, sizeof(rbig));
        qtest_memread(qts, mbuf, rmm, sizeof(rmm));
        g_assert_cmpint(memcmp(big, rbig, sizeof(rbig)), ==, 0);
        g_assert_cmpint(memcmp(mm, rmm, sizeof(rmm)), ==, 0);
    }

    /* compare looks at the metadata as well as the data */
    qtest_memwrite(qts, dbuf, d, sizeof(d));
    qtest_memwrite(qts, mbuf, m, 2 * FEMU_MD_MS);
    g_assert_cmpint(femu_rw_md(&c, NVME_CMD_COMPARE, 16, 2, dbuf, mbuf, 0),
                    ==, NVME_SUCCESS);
    qtest_writeb(qts, mbuf + 9, m[9] ^ 0xff);
    g_assert_cmpint(femu_rw_md(&c, NVME_CMD_COMPARE, 16, 2, dbuf, mbuf, 0),
                    ==, NVME_CMP_FAILURE);

    /* copy carries it */
    g_assert_cmpint(femu_copy(&c, list, 64, cslba, cnlb, 1, 1, 0), ==,
                    NVME_SUCCESS);
    qtest_memset(qts, mbuf, 0, sizeof(m));
    g_assert_cmpint(femu_rw_md(&c, NVME_CMD_READ, 64, 2, dbuf, mbuf, 0), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, mbuf, rm, 2 * FEMU_MD_MS);
    g_assert_cmpint(memcmp(m, rm, 2 * FEMU_MD_MS), ==, 0);

    /* write zeroes clears it */
    {
        NvmeRwCmd wz = { 0 };

        wz.opcode = NVME_CMD_WRITE_ZEROES;
        wz.nsid = cpu_to_le32(1);
        wz.slba = cpu_to_le64(64);
        wz.nlb = cpu_to_le16(0);
        g_assert_cmpint(femu_io(&c, (NvmeCmd *)&wz), ==, NVME_SUCCESS);
    }
    g_assert_cmpint(femu_rw_md(&c, NVME_CMD_READ, 64, 2, dbuf, mbuf, 0), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, mbuf, rm, 2 * FEMU_MD_MS);
    for (i = 0; i < FEMU_MD_MS; i++) {
        g_assert_cmpint(rm[i], ==, 0);
    }
    g_assert_cmpint(memcmp(m + FEMU_MD_MS, rm + FEMU_MD_MS, FEMU_MD_MS), ==, 0);

    /* a format without metadata and back leaves none behind */
    g_assert_cmpint(femu_format_dw10(&c, 0), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_rw(&c, NVME_CMD_READ, 16, dbuf), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_format_dw10(&c, FEMU_MD_NLBAF), ==, NVME_SUCCESS);
    qtest_memset(qts, mbuf, 0xee, sizeof(m));
    g_assert_cmpint(femu_rw_md(&c, NVME_CMD_READ, 16, 2, dbuf, mbuf, 0), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, mbuf, rm, 2 * FEMU_MD_MS);
    for (i = 0; i < 2 * FEMU_MD_MS; i++) {
        g_assert_cmpint(rm[i], ==, 0);
    }

    femu_disable(&c);
    guest_free(alloc, raw);
}

#define FEMU_MD_UNIT    (512 + FEMU_MD_MS)

/*
 * Extended LBAs (NVM 1.2, 2.1.4.1): each block's metadata follows its data in
 * the host buffer. The same commands carry it, the transfer (and so MDTS) is
 * data plus metadata, and Format moves between interleaved and separate.
 */
static void femu_test_metadata_extended(void *obj, void *data,
                                        QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t raw = 0;
    uint64_t buf = femu_alloc_64k(alloc, &raw);
    uint64_t mbuf = buf + 0x8000;
    uint8_t d[2 * FEMU_MD_UNIT];
    uint8_t r[2 * FEMU_MD_UNIT];
    uint8_t rm[2 * FEMU_MD_MS];
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    g_assert_cmpint(femu_identify(&c, 1, NVME_ID_CNS_NS, 0, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(qtest_readb(qts, buf + 26), ==, 0x10 | FEMU_MD_NLBAF);
    g_assert_cmpint(qtest_readb(qts, buf + 27) & 0x3, ==, 0x3);   /* MC */

    /* interleaved in, interleaved out */
    for (i = 0; i < sizeof(d); i++) {
        d[i] = (uint8_t)(0x47 + i * 13);
    }
    qtest_memwrite(qts, buf, d, sizeof(d));
    g_assert_cmpint(femu_rw_md(&c, NVME_CMD_WRITE, 8, 2, buf, 0, 0), ==,
                    NVME_SUCCESS);
    qtest_memset(qts, buf, 0, sizeof(d));
    g_assert_cmpint(femu_rw_md(&c, NVME_CMD_READ, 8, 2, buf, 0, 0), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, buf, r, sizeof(r));
    g_assert_cmpint(memcmp(d, r, sizeof(r)), ==, 0);

    /* compare covers both parts of each block */
    qtest_memwrite(qts, buf, d, sizeof(d));
    g_assert_cmpint(femu_rw_md(&c, NVME_CMD_COMPARE, 8, 2, buf, 0, 0), ==,
                    NVME_SUCCESS);
    qtest_writeb(qts, buf + FEMU_MD_UNIT + 512 + 3, d[FEMU_MD_UNIT + 515] ^ 1);
    g_assert_cmpint(femu_rw_md(&c, NVME_CMD_COMPARE, 8, 2, buf, 0, 0), ==,
                    NVME_CMP_FAILURE);

    /*
     * MDTS is two 4 KiB pages here: sixteen blocks are exactly that much
     * data, and more once their metadata rides along.
     */
    g_assert_cmpint(femu_rw_md(&c, NVME_CMD_WRITE, 8, 16, buf, 0, 0), ==,
                    NVME_INVALID_FIELD);

    /* the same blocks, formatted to separate metadata, then back */
    g_assert_cmpint(femu_format_dw10(&c, FEMU_MD_NLBAF), ==, NVME_SUCCESS);
    qtest_memset(qts, mbuf, 0xee, sizeof(rm));
    g_assert_cmpint(femu_rw_md(&c, NVME_CMD_READ, 8, 2, buf, mbuf, 0), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, mbuf, rm, sizeof(rm));
    for (i = 0; i < sizeof(rm); i++) {
        g_assert_cmpint(rm[i], ==, 0);
    }
    g_assert_cmpint(femu_format_dw10(&c, FEMU_MD_NLBAF | 1 << 4), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_identify(&c, 1, NVME_ID_CNS_NS, 0, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(qtest_readb(qts, buf + 26), ==, 0x10 | FEMU_MD_NLBAF);

    femu_disable(&c);
    guest_free(alloc, raw);
}

#define FEMU_FUZZ_ROUNDS    20000
#define FEMU_ADM_DEBUG      0xee

/*
 * Whether a field gets a value the handler accepts, which it mostly does so
 * the command gets past its first check. Callers draw the value only after
 * this, inside a conditional, so the order of draws from one seed does not
 * depend on how a compiler orders function arguments.
 */
static bool femu_fuzz_sane(GRand *rng)
{
    return g_rand_int_range(rng, 0, 4) != 0;
}

/*
 * Random admin commands from a fixed seed, so a failure replays. Admin
 * commands complete synchronously, which keeps the run deterministic. Each
 * field is usually valid and sometimes not: namespace IDs around the valid
 * ones, counts across the whole range, data pointers that are unaligned or
 * point at nothing. Async Event Requests are left out, since they are held
 * rather than completed, and so are queue deletions, which would take the
 * admin queue's partners away. Whatever the statuses, the controller has to
 * keep answering, and under the sanitizer build nothing may be touched out
 * of bounds. A run that only ever fails has tested only the first checks,
 * so enough distinct commands must also succeed.
 */
static void femu_test_admin_fuzz(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    const uint32_t nsids[] = { 0, 1, 2, 3, 0xfffffffe, 0xffffffff };
    const uint8_t ops[] = {
        NVME_ADM_CMD_CREATE_SQ, NVME_ADM_CMD_GET_LOG_PAGE,
        NVME_ADM_CMD_CREATE_CQ, NVME_ADM_CMD_IDENTIFY, NVME_ADM_CMD_ABORT,
        NVME_ADM_CMD_SET_FEATURES, NVME_ADM_CMD_GET_FEATURES,
        NVME_ADM_CMD_FORMAT_NVM, FEMU_ADM_DBBUF_CONFIG,
        FEMU_ADM_SANITIZE, FEMU_ADM_DEV_SELF_TEST,
        NVME_ADM_CMD_ACTIVATE_FW, NVME_ADM_CMD_DOWNLOAD_FW,
        NVME_ADM_CMD_SECURITY_SEND, NVME_ADM_CMD_SECURITY_RECV,
        NVME_ADM_CMD_NS_ATTACHMENT, NVME_ADM_CMD_DIRECTIVE_SEND,
        NVME_ADM_CMD_DIRECTIVE_RECV, FEMU_ADM_DEBUG,
    };
    const uint32_t counts[] = { 0, 1, 0x3ff, 0x7fff, 0xffff };
    bool succeeded[256] = { false };
    uint64_t raw = 0;
    uint64_t buf = femu_alloc_64k(alloc, &raw);
    GRand *rng = g_rand_new_with_seed(0x46454d55);
    NvmeCmd cmd;
    int distinct = 0;
    int i;

    femu_enable(&c, &femu->dev, alloc);

    for (i = 0; i < FEMU_FUZZ_ROUNDS; i++) {
        uint64_t ptrs[] = { buf + 0x800, buf + 1, 0, 0xffffffff00000000ULL };
        uint32_t numd;

        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = femu_fuzz_sane(rng) ?
                     ops[g_rand_int_range(rng, 0, G_N_ELEMENTS(ops))] :
                     g_rand_int_range(rng, 0, 0x100);
        if (cmd.opcode == NVME_ADM_CMD_ASYNC_EV_REQ ||
            cmd.opcode == NVME_ADM_CMD_DELETE_SQ ||
            cmd.opcode == NVME_ADM_CMD_DELETE_CQ) {
            continue;
        }
        if (femu_fuzz_sane(rng)) {
            cmd.nsid = cpu_to_le32(nsids[g_rand_int_range(rng, 0, 3)]);
        } else if (g_rand_boolean(rng)) {
            cmd.nsid = cpu_to_le32(nsids[g_rand_int_range(rng, 3, 6)]);
        } else {
            cmd.nsid = cpu_to_le32(g_rand_int(rng));
        }
        cmd.dptr.prp1 = cpu_to_le64(g_rand_int_range(rng, 0, 4) ? buf :
                                    ptrs[g_rand_int_range(rng, 0, 4)]);
        cmd.dptr.prp2 = cpu_to_le64(g_rand_int_range(rng, 0, 4) ?
                                    buf + 4096 :
                                    ptrs[g_rand_int_range(rng, 0, 4)]);
        /*
         * The low byte selects a log ID, CNS or feature ID and the high half
         * is a count, so draw them apart.
         */
        numd = femu_fuzz_sane(rng) ? g_rand_int_range(rng, 0, 0x400) :
                                     counts[g_rand_int_range(rng, 0, 5)];
        cmd.cdw10 = cpu_to_le32(numd << 16 |
                                (femu_fuzz_sane(rng) ?
                                 g_rand_int_range(rng, 0, 0x20) :
                                 g_rand_int_range(rng, 0, 0x10000)));
        cmd.cdw11 = cpu_to_le32(femu_fuzz_sane(rng) ?
                                g_rand_int_range(rng, 0, 16) : g_rand_int(rng));
        cmd.cdw12 = cpu_to_le32(femu_fuzz_sane(rng) ? 0 : g_rand_int(rng));
        cmd.cdw13 = cpu_to_le32(femu_fuzz_sane(rng) ? 0 : g_rand_int(rng));
        cmd.cdw14 = cpu_to_le32(femu_fuzz_sane(rng) ? 0 : g_rand_int(rng));
        cmd.cdw15 = cpu_to_le32(femu_fuzz_sane(rng) ? 0 : g_rand_int(rng));
        if (femu_admin(&c, &cmd) == NVME_SUCCESS && !succeeded[cmd.opcode]) {
            succeeded[cmd.opcode] = true;
            distinct++;
        }
    }

    g_assert_cmpint(distinct, >=, 10);
    /* still answering */
    g_assert_cmpint(femu_identify(&c, 0, NVME_ID_CNS_CTRL, 0, buf), ==,
                    NVME_SUCCESS);
    femu_disable(&c);
    g_rand_free(rng);
    guest_free(alloc, raw);
}

#define FEMU_IO_FUZZ_ROUNDS 1000
#define FEMU_FUZZ_PAGES     32
#define FEMU_FUZZ_LISTS     8

/*
 * A pointer the data can go to: mostly a page of the fuzz region, sometimes
 * unaligned, sometimes a list page, sometimes outside guest memory.
 */
static uint64_t femu_fuzz_ptr(GRand *rng, uint64_t region)
{
    uint64_t page = region + 4096ULL * g_rand_int_range(rng, 0,
                                     FEMU_FUZZ_PAGES - FEMU_FUZZ_LISTS);

    switch (g_rand_int_range(rng, 0, 8)) {
    case 0:
        return page + 4 * g_rand_int_range(rng, 1, 1024);
    case 1:
        return region + 4096ULL * (FEMU_FUZZ_PAGES - 1);
    case 2:
        return 0xffffffff00000000ULL;
    default:
        return page;
    }
}

/*
 * Rewrite the list pages at the top of the fuzz region: the lower half as
 * PRP entries, the upper half as SGL descriptors of every type. Segments
 * point back into the upper half and mostly hold one descriptor, so a walk
 * chains, loops or ends early.
 */
#define FEMU_FUZZ_PRP_LISTS (FEMU_FUZZ_LISTS / 2)
#define FEMU_FUZZ_SGL_DESCS ((FEMU_FUZZ_LISTS - FEMU_FUZZ_PRP_LISTS) * 256)

static uint64_t femu_fuzz_sgl_slot(GRand *rng, uint64_t region)
{
    return region + 4096ULL * (FEMU_FUZZ_PAGES - FEMU_FUZZ_LISTS +
                               FEMU_FUZZ_PRP_LISTS) +
           16ULL * g_rand_int_range(rng, 0, FEMU_FUZZ_SGL_DESCS);
}

static void femu_fuzz_lists(FemuCtrlState *c, GRand *rng, uint64_t region)
{
    QTestState *qts = c->pdev->bus->qts;
    uint64_t lists = region + 4096ULL * (FEMU_FUZZ_PAGES - FEMU_FUZZ_LISTS);
    uint64_t sgls = lists + 4096ULL * FEMU_FUZZ_PRP_LISTS;
    int i;

    for (i = 0; i < FEMU_FUZZ_PRP_LISTS * 512; i++) {
        uint64_t e = cpu_to_le64(femu_fuzz_ptr(rng, region));

        qtest_memwrite(qts, lists + 8ULL * i, &e, sizeof(e));
    }
    for (i = 0; i < FEMU_FUZZ_SGL_DESCS; i++) {
        uint32_t kind = g_rand_int_range(rng, 0, 8);
        NvmeSglDescriptor d;

        memset(&d, 0, sizeof(d));
        if (kind < 4) {
            if (!femu_fuzz_sane(rng)) {
                d.type = g_rand_int_range(rng, 0, 0x100);
            } else if (kind < 2) {
                d.type = NVME_SGL_DESCR_TYPE_SEGMENT << 4;
            } else {
                d.type = NVME_SGL_DESCR_TYPE_LAST_SEGMENT << 4;
            }
            d.addr = cpu_to_le64(femu_fuzz_sgl_slot(rng, region));
            if (!femu_fuzz_sane(rng)) {
                d.len = cpu_to_le32(g_rand_int_range(rng, 0, 0x10000));
            } else if (g_rand_boolean(rng)) {
                d.len = cpu_to_le32(16);
            } else {
                d.len = cpu_to_le32(16 * g_rand_int_range(rng, 2, 8));
            }
        } else {
            d.type = femu_fuzz_sane(rng) ? NVME_SGL_DESCR_TYPE_DATA_BLOCK << 4 :
                                           g_rand_int_range(rng, 0, 0x100);
            d.addr = cpu_to_le64(femu_fuzz_ptr(rng, region));
            d.len = cpu_to_le32(femu_fuzz_sane(rng) ?
                                512 * g_rand_int_range(rng, 1, 9) :
                                g_rand_int(rng));
        }
        qtest_memwrite(qts, sgls + 16ULL * i, &d, sizeof(d));
    }
}

/*
 * A data pointer the command describes correctly: a PRP pair, with a list
 * when the transfer crosses a page, or, where the command takes one, an SGL
 * data block. The region's data pages are contiguous, so one block can cover
 * the whole transfer.
 */
static void femu_fuzz_valid_dptr(FemuCtrlState *c, GRand *rng,
                                 uint64_t region, NvmeRwCmd *rw,
                                 uint32_t len, bool sgl_ok)
{
    uint64_t lists = region + 4096ULL * (FEMU_FUZZ_PAGES - FEMU_FUZZ_LISTS);
    uint32_t pages = DIV_ROUND_UP(len, 4096);
    uint64_t data = region + 4096ULL * g_rand_int_range(rng, 0,
                                FEMU_FUZZ_PAGES - FEMU_FUZZ_LISTS - pages + 1);
    uint32_t i;

    /* always drawn, so a run without SGLs keeps the same sequence */
    if (g_rand_boolean(rng) && sgl_ok) {
        NvmeSglDescriptor d = {
            .addr = cpu_to_le64(data),
            .len = cpu_to_le32(len),
            .type = NVME_SGL_DESCR_TYPE_DATA_BLOCK << 4,
        };

        rw->flags = 1 << 6;
        memcpy(&rw->dptr.sgl, &d, sizeof(d));
        return;
    }
    rw->dptr.prp1 = cpu_to_le64(data);
    if (pages == 2) {
        rw->dptr.prp2 = cpu_to_le64(data + 4096);
    } else if (pages > 2) {
        for (i = 1; i < pages; i++) {
            uint64_t e = cpu_to_le64(data + 4096ULL * i);

            qtest_memwrite(c->pdev->bus->qts, lists + 8 * (i - 1), &e,
                           sizeof(e));
        }
        rw->dptr.prp2 = cpu_to_le64(lists);
    }
}

/*
 * A chain of one-descriptor segments in the SGL half of the list pages that
 * ends in the command's data block or, half the time, points back into
 * itself. Returns the descriptor for the command.
 */
static NvmeSglDescriptor femu_fuzz_sgl_chain(FemuCtrlState *c, GRand *rng,
                                             uint64_t region, uint32_t len)
{
    QTestState *qts = c->pdev->bus->qts;
    uint64_t sgls = region + 4096ULL * (FEMU_FUZZ_PAGES - FEMU_FUZZ_LISTS +
                                        FEMU_FUZZ_PRP_LISTS);
    int hops = g_rand_int_range(rng, 1, 9);
    int first = g_rand_int_range(rng, 0, FEMU_FUZZ_SGL_DESCS - hops);
    bool loop = g_rand_boolean(rng);
    NvmeSglDescriptor d;
    int i;

    for (i = 0; i < hops; i++) {
        memset(&d, 0, sizeof(d));
        if (i < hops - 1 || loop) {
            int next = i < hops - 1 ? i + 1 : g_rand_int_range(rng, 0, hops);

            d.type = NVME_SGL_DESCR_TYPE_SEGMENT << 4;
            d.addr = cpu_to_le64(sgls + 16ULL * (first + next));
            d.len = cpu_to_le32(16);
        } else {
            d.type = NVME_SGL_DESCR_TYPE_DATA_BLOCK << 4;
            d.addr = cpu_to_le64(region);
            d.len = cpu_to_le32(len);
        }
        qtest_memwrite(qts, sgls + 16ULL * (first + i), &d, sizeof(d));
    }

    memset(&d, 0, sizeof(d));
    d.type = NVME_SGL_DESCR_TYPE_SEGMENT << 4;
    d.addr = cpu_to_le64(sgls + 16ULL * first);
    d.len = cpu_to_le32(16);
    return d;
}

/* Reset zone 0, write its first blocks and read them back. */
static void femu_zoned_round_trip(FemuCtrlState *c, uint64_t buf)
{
    QTestState *qts = c->pdev->bus->qts;
    uint8_t wbuf[FEMU_DATA_SIZE];
    uint8_t rbuf[FEMU_DATA_SIZE];
    int i;

    for (i = 0; i < FEMU_DATA_SIZE; i++) {
        wbuf[i] = (uint8_t)(0x5a + i * 7);
    }
    g_assert_cmpint(femu_zone_action(c, 0, NVME_ZONE_ACTION_RESET), ==,
                    NVME_SUCCESS);
    qtest_memwrite(qts, buf, wbuf, FEMU_DATA_SIZE);
    g_assert_cmpint(FEMU_SC(femu_rw(c, NVME_CMD_WRITE, 0, buf)), ==,
                    NVME_SUCCESS);
    qtest_memset(qts, buf, 0, FEMU_DATA_SIZE);
    g_assert_cmpint(FEMU_SC(femu_rw(c, NVME_CMD_READ, 0, buf)), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, buf, rbuf, FEMU_DATA_SIZE);
    g_assert_cmpint(memcmp(wbuf, rbuf, FEMU_DATA_SIZE), ==, 0);
}

typedef struct FemuIoFuzz {
    int min_succeeded;
    bool zoned;         /* writes must land on a write pointer */
    int nruh;           /* placement handles, when writes may carry one */
} FemuIoFuzz;

static const FemuIoFuzz femu_io_fuzz_conv = { 8, false, 0 };
static const FemuIoFuzz femu_io_fuzz_zoned = { 5, true, 0 };
static const FemuIoFuzz femu_io_fuzz_fdp = { 8, false, 4 };

#define FEMU_FUZZ_ZONES     4

/* The write pointer and capacity of the zone that starts at @zslba. */
static uint64_t femu_fuzz_zone_wp(FemuCtrlState *c, uint64_t buf,
                                  uint64_t zslba, uint64_t *zcap)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = NVME_CMD_ZONE_MGMT_RECV;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(zslba);
    cmd.cdw11 = cpu_to_le32(zslba >> 32);
    cmd.cdw12 = cpu_to_le32(31);    /* header and one zone descriptor */
    g_assert_cmpint(femu_io(c, &cmd), ==, NVME_SUCCESS);
    *zcap = qtest_readq(c->pdev->bus->qts, buf + 64 + 8);
    return qtest_readq(c->pdev->bus->qts, buf + 64 + 24);
}

/*
 * Aim a valid write at one of the first few zones: at its write pointer,
 * or at its start for Zone Append, resetting the zone when the write would
 * not fit in what is left of it.
 */
static void femu_fuzz_aim_zone(FemuCtrlState *c, GRand *rng, uint64_t buf,
                               uint64_t zsze, NvmeRwCmd *rw)
{
    uint64_t zslba = zsze * g_rand_int_range(rng, 0, FEMU_FUZZ_ZONES);
    uint32_t nlb = le16_to_cpu(rw->nlb) + 1;
    uint64_t zcap;
    uint64_t wp = femu_fuzz_zone_wp(c, buf, zslba, &zcap);

    if (wp + nlb > zslba + zcap) {
        g_assert_cmpint(femu_zone_action(c, zslba, NVME_ZONE_ACTION_RESET),
                        ==, NVME_SUCCESS);
        wp = zslba;
    }
    rw->slba = cpu_to_le64(rw->opcode == NVME_CMD_ZONE_APPEND ? zslba : wp);
}

/*
 * Random I/O commands from a fixed seed. Most are valid, so they reach the
 * FTL with real data; one in four has some fields replaced: namespace IDs,
 * LBA ranges at and past the end, the reserved PSDT, and PRP lists and SGL
 * segments rebuilt at random, which chain, loop, end early or point outside
 * memory. All data stays in one region of guest memory, away from the
 * queues, so a bad pointer can hurt only the device. Each command must
 * complete, the controller must still answer and, where writes need no write
 * pointer, round-trip data afterwards. Enough distinct commands have to
 * succeed for the run to have reached past the first checks.
 */
static void femu_test_io_fuzz(void *obj, void *data, QGuestAllocator *alloc)
{
    const FemuIoFuzz *want = data;
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    const uint8_t ops[] = {
        NVME_CMD_FLUSH, NVME_CMD_WRITE, NVME_CMD_READ, NVME_CMD_WRITE_UNCOR,
        NVME_CMD_COMPARE, NVME_CMD_WRITE_ZEROES, NVME_CMD_DSM,
        NVME_CMD_VERIFY, NVME_CMD_COPY, NVME_CMD_IO_MGMT_RECV,
        NVME_CMD_IO_MGMT_SEND, NVME_CMD_ZONE_MGMT_SEND,
        NVME_CMD_ZONE_MGMT_RECV, NVME_CMD_ZONE_APPEND,
    };
    bool succeeded[256] = { false };
    uint64_t raw = 0;
    uint64_t region = femu_alloc_64k(alloc, &raw);
    uint64_t lists = region + 4096ULL * (FEMU_FUZZ_PAGES - FEMU_FUZZ_LISTS);
    GRand *rng = g_rand_new_with_seed(0x494f4655);
    uint64_t nsze;
    uint64_t zsze = 0;
    uint64_t zbuf = 0;
    NvmeRwCmd rw;
    NvmeCmd *cmd = (NvmeCmd *)&rw;
    int distinct = 0;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    g_assert_cmpint(femu_identify(&c, 1, NVME_ID_CNS_NS, 0, region), ==,
                    NVME_SUCCESS);
    nsze = qtest_readq(c.pdev->bus->qts, region);
    g_assert_cmpuint(nsze, >, 64);
    if (want->zoned) {
        uint8_t report[192];

        zbuf = guest_alloc(alloc, 4096);
        femu_zone_report(&c, zbuf, report);
        zsze = ldq_le_p(report + 128 + 16);
        g_assert_cmpuint(zsze, >=, 64);
        g_assert_cmpuint(zsze * FEMU_FUZZ_ZONES, <=, nsze);
    }

    for (i = 0; i < FEMU_IO_FUZZ_ROUNDS; i++) {
        bool wild = g_rand_int_range(rng, 0, 4) == 0;
        uint32_t nlb = g_rand_int_range(rng, 0, 64);
        uint16_t st;

        femu_fuzz_lists(&c, rng, region);
        memset(&rw, 0, sizeof(rw));
        rw.opcode = ops[g_rand_int_range(rng, 0, G_N_ELEMENTS(ops))];
        rw.nsid = cpu_to_le32(1);
        /* where separate metadata goes, if the format has any */
        rw.mptr = cpu_to_le64(lists - 4096);
        rw.slba = cpu_to_le64(g_rand_int_range(rng, 0,
                                               MIN(nsze, 1 << 20) - nlb));
        rw.nlb = cpu_to_le16(nlb);
        femu_fuzz_valid_dptr(&c, rng, region, &rw, (nlb + 1) * c.lba_size,
                             true);
        if (want->zoned && (rw.opcode == NVME_CMD_WRITE ||
                            rw.opcode == NVME_CMD_WRITE_ZEROES ||
                            rw.opcode == NVME_CMD_ZONE_APPEND)) {
            femu_fuzz_aim_zone(&c, rng, zbuf, zsze, &rw);
        }
        /* read the placement handles' status (MO 1), the whole buffer */
        if (rw.opcode == NVME_CMD_IO_MGMT_RECV) {
            cmd->cdw10 = cpu_to_le32(1);
            cmd->cdw11 = cpu_to_le32((nlb + 1) * c.lba_size / 4 - 1);
        }
        /* half the writes name a placement handle (DTYPE 2, DSPEC) */
        if (want->nruh && (rw.opcode == NVME_CMD_WRITE ||
                           rw.opcode == NVME_CMD_WRITE_ZEROES) &&
            g_rand_boolean(rng)) {
            rw.control = cpu_to_le16(2 << 4);
            rw.dsmgmt = cpu_to_le32(g_rand_int_range(rng, 0, want->nruh) << 16);
        }

        if (wild) {
            switch (g_rand_int_range(rng, 0, 7)) {
            case 0:
                rw.opcode = g_rand_int_range(rng, 0, 0x100);
                break;
            case 1:
                rw.nsid = cpu_to_le32(g_rand_boolean(rng) ? 0xffffffff :
                                      g_rand_int_range(rng, 0, 4));
                break;
            case 2:
                if (g_rand_boolean(rng)) {
                    rw.slba = cpu_to_le64(nsze - g_rand_int_range(rng, 0, 64));
                } else {
                    uint64_t hi = g_rand_int(rng);

                    rw.slba = cpu_to_le64(hi << 32 | g_rand_int(rng));
                }
                rw.nlb = cpu_to_le16(g_rand_int_range(rng, 0, 0x10000));
                break;
            case 3:
                /* PRPs from the random lists */
                rw.flags = 0;
                rw.dptr.prp1 = cpu_to_le64(femu_fuzz_ptr(rng, region));
                rw.dptr.prp2 = cpu_to_le64(g_rand_boolean(rng) ?
                        lists + 8 * g_rand_int_range(rng, 0,
                                            FEMU_FUZZ_PRP_LISTS * 512) :
                        femu_fuzz_ptr(rng, region));
                break;
            case 4:
                /* an SGL from the random segments, or the reserved PSDT */
                rw.flags = g_rand_int_range(rng, 1, 4) << 6;
                qtest_memread(c.pdev->bus->qts,
                              femu_fuzz_sgl_slot(rng, region),
                              &rw.dptr.sgl, sizeof(rw.dptr.sgl));
                break;
            case 5: {
                NvmeSglDescriptor d = femu_fuzz_sgl_chain(&c, rng, region,
                                                (nlb + 1) * c.lba_size);

                rw.flags = 1 << 6;
                memcpy(&rw.dptr.sgl, &d, sizeof(d));
                break;
            }
            default:
                rw.control = cpu_to_le16(g_rand_int_range(rng, 0, 0x10000));
                rw.dsmgmt = cpu_to_le32(g_rand_int(rng));
                cmd->cdw10 = g_rand_int(rng);
                cmd->cdw11 = g_rand_int(rng);
                break;
            }
        }

        st = femu_io(&c, cmd);
        if (st == NVME_SUCCESS && !succeeded[rw.opcode]) {
            succeeded[rw.opcode] = true;
            distinct++;
        }
    }

    g_assert_cmpint(distinct, >=, want->min_succeeded);
    /* still answering */
    g_assert_cmpint(femu_identify(&c, 0, NVME_ID_CNS_CTRL, 0, region), ==,
                    NVME_SUCCESS);
    if (!want->zoned) {
        femu_round_trip(&c, 0x5a);
    } else {
        /* zone 0 was written at its write pointer; it still reads back */
        femu_zoned_round_trip(&c, zbuf);
        guest_free(alloc, zbuf);
    }
    femu_disable(&c);
    g_rand_free(rng);
    guest_free(alloc, raw);
}

#define FEMU_LOG_TELEMETRY_HOST 0x07
#define FEMU_LOG_TELEMETRY_CTRL 0x08

static uint16_t femu_get_telemetry(FemuCtrlState *c, uint8_t lid,
                                   bool create, uint64_t buf, uint32_t len,
                                   uint64_t off)
{
    uint32_t numd = (len >> 2) - 1;
    NvmeCmd cmd = { 0 };

    cmd.opcode = NVME_ADM_CMD_GET_LOG_PAGE;
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(lid | (create ? 1 << 8 : 0) |
                            ((numd & 0xffff) << 16));
    cmd.cdw11 = cpu_to_le32((numd >> 16) & 0xffff);
    cmd.cdw12 = cpu_to_le32((uint32_t)off);
    cmd.cdw13 = cpu_to_le32((uint32_t)(off >> 32));
    return FEMU_SC(femu_admin(c, &cmd));
}

/*
 * Telemetry Host-Initiated (07h) and Controller-Initiated (08h) logs (Base
 * 2.3, 5.2.12.1.8-9): both advertised, a 512-byte header that is always
 * there, a capture on request whose data stays fixed until the next capture,
 * and whole blocks only. Data Area 1 carries the emulator's media counters,
 * the same bytes as the vendor page C0h at the moment of capture.
 */
static void femu_test_telemetry(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint8_t hdr[512];
    uint8_t blk[512];
    uint8_t c0[512];

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    g_assert_cmpint(femu_identify(&c, 0, NVME_ID_CNS_CTRL, 0, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(qtest_readb(qts, buf + 261) & (1 << 3), !=, 0); /* LPA */
    g_assert_cmpint(FEMU_SC(femu_get_log(&c, 0x00, buf, 1024, 0)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(qtest_readl(qts, buf + 4 * FEMU_LOG_TELEMETRY_HOST) & 1,
                    ==, 1);
    g_assert_cmpint(qtest_readl(qts, buf + 4 * FEMU_LOG_TELEMETRY_CTRL) & 1,
                    ==, 1);

    /* before any capture: a header and no data */
    g_assert_cmpint(femu_get_telemetry(&c, FEMU_LOG_TELEMETRY_HOST, false,
                                       buf, 512, 0), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, hdr, sizeof(hdr));
    g_assert_cmpint(hdr[0], ==, FEMU_LOG_TELEMETRY_HOST);
    g_assert_cmpint(lduw_le_p(hdr + 8), ==, 0);
    g_assert_cmpint(hdr[380], ==, 1);                   /* controller scope */
    g_assert_cmpint(hdr[381], ==, 0);

    /* something to count, then a capture */
    femu_round_trip(&c, 3);
    g_assert_cmpint(femu_get_telemetry(&c, FEMU_LOG_TELEMETRY_HOST, true,
                                       buf, 1024, 0), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, hdr, sizeof(hdr));
    qtest_memread(qts, buf + 512, blk, sizeof(blk));
    g_assert_cmpint(lduw_le_p(hdr + 8), ==, 1);         /* area 1: block 1 */
    g_assert_cmpint(lduw_le_p(hdr + 10), >=, lduw_le_p(hdr + 8));
    g_assert_cmpint(lduw_le_p(hdr + 12), >=, lduw_le_p(hdr + 10));
    g_assert_cmpint(hdr[381], ==, 1);
    g_assert_cmpint(FEMU_SC(femu_get_log(&c, FEMU_LOG_FEMU_STATS, buf, 512,
                                         0)), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, c0, sizeof(c0));
    g_assert_cmpint(memcmp(blk, c0, sizeof(blk)), ==, 0);
    g_assert_cmpuint(ldq_le_p(blk + 8), >, 0);          /* host pages */

    /* more traffic changes the vendor page but not the captured data */
    femu_round_trip(&c, 5);
    g_assert_cmpint(femu_get_telemetry(&c, FEMU_LOG_TELEMETRY_HOST, false,
                                       buf, 512, 512), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, c0, sizeof(c0));
    g_assert_cmpint(memcmp(blk, c0, sizeof(blk)), ==, 0);
    g_assert_cmpint(femu_get_telemetry(&c, FEMU_LOG_TELEMETRY_HOST, true,
                                       buf, 512, 0), ==, NVME_SUCCESS);
    g_assert_cmpint(qtest_readb(qts, buf + 381), ==, 2);

    /* only whole blocks */
    g_assert_cmpint(femu_get_telemetry(&c, FEMU_LOG_TELEMETRY_HOST, false,
                                       buf, 256, 0), ==, NVME_INVALID_FIELD);
    g_assert_cmpint(femu_get_telemetry(&c, FEMU_LOG_TELEMETRY_HOST, false,
                                       buf, 512, 256), ==, NVME_INVALID_FIELD);

    /* the controller never captures on its own */
    g_assert_cmpint(femu_get_telemetry(&c, FEMU_LOG_TELEMETRY_CTRL, false,
                                       buf, 512, 0), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, hdr, sizeof(hdr));
    g_assert_cmpint(hdr[0], ==, FEMU_LOG_TELEMETRY_CTRL);
    g_assert_cmpint(hdr[380], ==, 1);
    g_assert_cmpint(hdr[382], ==, 0);                   /* no data available */

    femu_disable(&c);
    guest_free(alloc, buf);
}

#define FEMU_ADM_GET_LBA_STATUS  0x86
#define FEMU_LOG_LBA_STATUS      0x0e

static uint16_t femu_get_lba_status(FemuCtrlState *c, uint64_t buf,
                                    uint64_t slba, uint32_t mndw,
                                    uint8_t atype, uint16_t rl)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = FEMU_ADM_GET_LBA_STATUS;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32((uint32_t)slba);
    cmd.cdw11 = cpu_to_le32((uint32_t)(slba >> 32));
    cmd.cdw12 = cpu_to_le32(mndw);
    cmd.cdw13 = cpu_to_le32((uint32_t)atype << 24 | rl);
    return FEMU_SC(femu_admin(c, &cmd));
}

/* one block uncorrectable, or back to readable by writing it */
static void femu_mark_uncor(FemuCtrlState *c, uint64_t slba, uint16_t nlb)
{
    NvmeRwCmd rw = { 0 };

    rw.opcode = NVME_CMD_WRITE_UNCOR;
    rw.nsid = cpu_to_le32(1);
    rw.slba = cpu_to_le64(slba);
    rw.nlb = cpu_to_le16(nlb - 1);
    g_assert_cmpint(femu_io(c, (NvmeCmd *)&rw), ==, NVME_SUCCESS);
}

/*
 * Get LBA Status (NVM 1.2, 4.2.1): the blocks a read would fail on, as runs
 * of LBAs, and the allocated ones; plus the LBA Status Information log that
 * says how many there are to look for.
 */
static void femu_test_get_lba_status(void *obj, void *data,
                                     QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint64_t dbuf = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    g_assert_cmpint(femu_identify(&c, 0, NVME_ID_CNS_CTRL, 0, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(qtest_readw(qts, buf + 256) & (1 << 9), !=, 0); /* GLSS */

    femu_mark_uncor(&c, 10, 3);
    femu_mark_uncor(&c, 20, 1);

    /* both runs, coalesced, reported as written uncorrectable */
    g_assert_cmpint(femu_get_lba_status(&c, buf, 0, 1023, 0x11, 0), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(qtest_readl(qts, buf), ==, 2);             /* NLSD */
    g_assert_cmpint(qtest_readb(qts, buf + 4), ==, 2);         /* COMPLETE */
    g_assert_cmpuint(qtest_readq(qts, buf + 8), ==, 10);
    g_assert_cmpint(qtest_readl(qts, buf + 16), ==, 2);        /* 0's based */
    g_assert_cmpint(qtest_readb(qts, buf + 21) & 0x7, ==, 3);
    g_assert_cmpuint(qtest_readq(qts, buf + 24), ==, 20);
    g_assert_cmpint(qtest_readl(qts, buf + 32), ==, 0);

    /* room for one: the rest is left for another command */
    g_assert_cmpint(femu_get_lba_status(&c, buf, 0, (8 + 16) / 4 - 1, 0x10,
                                        0), ==, NVME_SUCCESS);
    g_assert_cmpint(qtest_readl(qts, buf), ==, 1);
    g_assert_cmpint(qtest_readb(qts, buf + 4), ==, 1);         /* INCOMPLETE */

    /* the first run starts at the starting LBA, and the range bounds it */
    g_assert_cmpint(femu_get_lba_status(&c, buf, 11, 1023, 0x11, 5), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(qtest_readl(qts, buf), ==, 1);
    g_assert_cmpuint(qtest_readq(qts, buf + 8), ==, 11);
    g_assert_cmpint(qtest_readl(qts, buf + 16), ==, 1);

    /* LBA Status Information: nothing listed, an estimate to look for */
    g_assert_cmpint(FEMU_SC(femu_get_log(&c, 0x00, buf, 1024, 0)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(qtest_readl(qts, buf + 4 * FEMU_LOG_LBA_STATUS) & 1, ==, 1);
    g_assert_cmpint(FEMU_SC(femu_get_log(&c, FEMU_LOG_LBA_STATUS, buf, 16,
                                         0)), ==, NVME_SUCCESS);
    g_assert_cmpint(qtest_readl(qts, buf), ==, 16);            /* LSLPLEN */
    g_assert_cmpint(qtest_readl(qts, buf + 8), ==, 4);         /* ESTULB */

    /* a rewritten block is readable again and is no longer reported */
    g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE, 20, dbuf), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_get_lba_status(&c, buf, 0, 1023, 0x11, 0), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(qtest_readl(qts, buf), ==, 1);

    /*
     * allocated blocks: the ones marked uncorrectable are not deallocated,
     * and the eight just written from LBA 20
     */
    g_assert_cmpint(femu_get_lba_status(&c, buf, 0, 1023, 0x02, 0), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(qtest_readl(qts, buf), ==, 2);
    g_assert_cmpuint(qtest_readq(qts, buf + 8), ==, 10);
    g_assert_cmpint(qtest_readl(qts, buf + 16), ==, 2);
    g_assert_cmpuint(qtest_readq(qts, buf + 24), ==, 20);
    g_assert_cmpint(qtest_readl(qts, buf + 32), ==, 7);
    g_assert_cmpint(qtest_readb(qts, buf + 37) & 0x7, ==, 2);

    g_assert_cmpint(femu_get_lba_status(&c, buf, 0, 1023, 0x05, 0), ==,
                    NVME_INVALID_FIELD);
    g_assert_cmpint(femu_get_lba_status(&c, buf, 1ULL << 40, 1023, 0x11, 0),
                    ==, NVME_LBA_RANGE);

    femu_disable(&c);
    guest_free(alloc, dbuf);
    guest_free(alloc, buf);
}

#define FEMU_KV_FUZZ_KEYS   16

/* Put key @k of the pool into the command, @len bytes of it. */
static void femu_kv_fuzz_key(NvmeCmd *cmd, int k, uint8_t len)
{
    uint64_t lo = 0x6b65790000000000ULL | k;

    cmd->res1 = cpu_to_le64(lo);
    cmd->cdw14 = cpu_to_le32(k * 0x01010101U);
    cmd->cdw15 = 0;
    cmd->cdw11 = cpu_to_le32((le32_to_cpu(cmd->cdw11) & ~0xffU) | len);
}

/*
 * Key-value commands from a fixed seed over a small pool of keys, so stores,
 * retrieves, deletes and lists meet the same keys. As with the block fuzz,
 * most commands are valid and one in four has a field replaced: key length,
 * value or buffer size, store options, namespace, or a data pointer from the
 * random lists. Every command must complete, and a stored value must still
 * come back intact afterwards.
 */
static void femu_test_kv_fuzz(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    const uint8_t ops[] = {
        FEMU_KV_CMD_STORE, FEMU_KV_CMD_RETRIEVE, FEMU_KV_CMD_LIST,
        FEMU_KV_CMD_DELETE, FEMU_KV_CMD_EXIST,
    };
    bool succeeded[256] = { false };
    uint64_t raw = 0;
    uint64_t region = femu_alloc_64k(alloc, &raw);
    uint64_t lists = region + 4096ULL * (FEMU_FUZZ_PAGES - FEMU_FUZZ_LISTS);
    GRand *rng = g_rand_new_with_seed(0x4b56465a);
    uint8_t wbuf[FEMU_DATA_SIZE];
    uint8_t rbuf[FEMU_DATA_SIZE];
    NvmeRwCmd rw;
    NvmeCmd *cmd = (NvmeCmd *)&rw;
    int distinct = 0;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    for (i = 0; i < FEMU_IO_FUZZ_ROUNDS; i++) {
        int key;
        uint32_t size = femu_fuzz_sane(rng) ?
                        g_rand_int_range(rng, 1, 16385) :
                        g_rand_int_range(rng, 1, 4096);
        uint16_t st;

        femu_fuzz_lists(&c, rng, region);
        memset(&rw, 0, sizeof(rw));
        rw.opcode = ops[g_rand_int_range(rng, 0, G_N_ELEMENTS(ops))];
        rw.nsid = cpu_to_le32(1);
        cmd->cdw10 = cpu_to_le32(size);
        key = g_rand_int_range(rng, 0, FEMU_KV_FUZZ_KEYS);
        femu_kv_fuzz_key(cmd, key, g_rand_int_range(rng, 4, 17));
        femu_fuzz_valid_dptr(&c, rng, region, &rw, size, true);

        if (g_rand_int_range(rng, 0, 4) == 0) {
            switch (g_rand_int_range(rng, 0, 7)) {
            case 0:
                rw.opcode = g_rand_int_range(rng, 0, 0x100);
                break;
            case 1:
                rw.nsid = cpu_to_le32(g_rand_boolean(rng) ? 0xffffffff :
                                      g_rand_int_range(rng, 0, 4));
                break;
            case 2:
                /* no key, or longer than the command can carry */
                cmd->cdw11 = cpu_to_le32(g_rand_boolean(rng) ? 0 :
                                         g_rand_int_range(rng, 17, 0x100));
                break;
            case 3:
                cmd->cdw10 = cpu_to_le32(g_rand_boolean(rng) ? 0 :
                                         g_rand_int(rng));
                break;
            case 4:
                cmd->cdw11 = cpu_to_le32(le32_to_cpu(cmd->cdw11) |
                                         g_rand_int_range(rng, 1, 0x100) << 8);
                break;
            case 5:
                rw.flags = 0;
                rw.dptr.prp1 = cpu_to_le64(femu_fuzz_ptr(rng, region));
                rw.dptr.prp2 = cpu_to_le64(g_rand_boolean(rng) ?
                        lists + 8 * g_rand_int_range(rng, 0,
                                            FEMU_FUZZ_PRP_LISTS * 512) :
                        femu_fuzz_ptr(rng, region));
                break;
            default:
                rw.flags = g_rand_int_range(rng, 1, 4) << 6;
                qtest_memread(qts, femu_fuzz_sgl_slot(rng, region),
                              &rw.dptr.sgl, sizeof(rw.dptr.sgl));
                break;
            }
        }

        st = femu_io(&c, cmd);
        if (st == NVME_SUCCESS && !succeeded[rw.opcode]) {
            succeeded[rw.opcode] = true;
            distinct++;
        }
    }

    g_assert_cmpint(distinct, >=, 4);

    /* a value stored now comes back whole */
    for (i = 0; i < FEMU_DATA_SIZE; i++) {
        wbuf[i] = (uint8_t)(0xa5 + i * 3);
    }
    qtest_memwrite(qts, region, wbuf, FEMU_DATA_SIZE);
    memset(&rw, 0, sizeof(rw));
    rw.opcode = FEMU_KV_CMD_STORE;
    rw.nsid = cpu_to_le32(1);
    rw.dptr.prp1 = cpu_to_le64(region);
    cmd->cdw10 = cpu_to_le32(FEMU_DATA_SIZE);
    femu_kv_fuzz_key(cmd, FEMU_KV_FUZZ_KEYS, 16);
    g_assert_cmpint(femu_io(&c, cmd), ==, NVME_SUCCESS);

    qtest_memset(qts, region, 0, FEMU_DATA_SIZE);
    rw.opcode = FEMU_KV_CMD_RETRIEVE;
    g_assert_cmpint(femu_io(&c, cmd), ==, NVME_SUCCESS);
    qtest_memread(qts, region, rbuf, FEMU_DATA_SIZE);
    g_assert_cmpint(memcmp(wbuf, rbuf, FEMU_DATA_SIZE), ==, 0);

    femu_disable(&c);
    g_rand_free(rng);
    guest_free(alloc, raw);
}

/*
 * Open-Channel vector commands take their data through PRPs only. With a
 * scatter-gather list the controller read the list descriptor as a PRP pair,
 * so the length field became the second page's address: a two-sector write
 * took its second sector from guest address 0x2000. It has to be refused and
 * touch nothing outside the buffer it names.
 */
static void femu_test_oc_sgl_refused(void *obj, void *data,
                                     QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint32_t sectors = GPOINTER_TO_UINT(data);
    uint64_t buf = guest_alloc(alloc, (sectors + 1) * 4096);
    uint64_t lbas = guest_alloc(alloc, 4096);
    uint64_t e;
    uint8_t low[4096];
    NvmeSglDescriptor d = { 0 };
    NvmeCmd cmd = { 0 };
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = (buf + 4095) & ~4095ULL;
    qtest_memset(qts, buf, 0x5c, sectors * 4096);
    qtest_memset(qts, 0x2000, 0xee, sizeof(low));
    for (i = 0; i < sectors; i++) {
        e = cpu_to_le64(i);
        qtest_memwrite(qts, lbas + 8 * i, &e, sizeof(e));
    }

    d.addr = cpu_to_le64(buf);
    d.len = cpu_to_le32(sectors * 4096);
    d.type = NVME_SGL_DESCR_TYPE_DATA_BLOCK << 4;
    cmd.opcode = FEMU_OC20_VECT_WRITE;
    cmd.flags = 1 << 6;
    cmd.nsid = cpu_to_le32(1);
    memcpy(&cmd.dptr.sgl, &d, sizeof(d));
    if (sectors > 1) {
        cmd.cdw10 = cpu_to_le32((uint32_t)lbas);
        cmd.cdw11 = cpu_to_le32((uint32_t)(lbas >> 32));
    }
    cmd.cdw12 = cpu_to_le32(sectors - 1);
    g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_INVALID_FIELD);

    qtest_memread(qts, 0x2000, low, sizeof(low));
    for (i = 0; i < sizeof(low); i++) {
        g_assert_cmpint(low[i], ==, 0xee);
    }
    femu_disable(&c);
}

static void femu_test_oc12_timing_config(void *obj, void *data,
                                         QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    unsigned field = GPOINTER_TO_UINT(data);
    QDict *rsp;

    rsp = qtest_qmp(femu->dev.bus->qts,
                    "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'bad-oc12','addr':'5',"
                    "'devsz_mb':64,'femu_mode':0,'lver':1,"
                    "'oc12_channel_timing':true,'flash_type':%u,"
                    "'lpgs_per_blk':%u,'ch_xfer_lat':%d}}",
                    field == 0 ? 0 : 2, field == 1 ? 513 : 512,
                    field == 2 ? -1 : 0);
    g_assert_true(qdict_haskey(rsp, "error"));
    qobject_unref(rsp);
    qos_invalidate_command_line();
}

static void femu_test_oc12_capabilities(void *obj, void *data,
                                       QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint32_t cap;

    femu_enable(&c, &femu->dev, alloc);
    cmd.opcode = 0xe2; /* OC 1.2 Identify */
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    qtest_memread(femu->dev.bus->qts, buf + 4, &cap, sizeof(cap));
    /* Keep bad-block management advertised, without hybrid commands. */
    g_assert_cmphex(le32_to_cpu(cap), ==, 0x1);
    guest_free(alloc, buf);
    femu_disable(&c);
}

static void femu_test_oc12_opcodes(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd = { 0 };
    const uint8_t opcodes[] = { NVME_CMD_READ, NVME_CMD_WRITE, 0x93, 0x94 };
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    cmd.nsid = cpu_to_le32(1);
    for (i = 0; i < G_N_ELEMENTS(opcodes); i++) {
        cmd.opcode = opcodes[i];
        g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_INVALID_OPCODE);
    }
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static void femu_oc12_clock_start(FemuCtrlState *c, QFemu *femu,
                                  QGuestAllocator *alloc)
{
    QDict *rsp = qtest_qmp(femu->dev.bus->qts,
                         "{'execute':'qom-set', 'arguments':{"
                         "'path':'/machine/peripheral/oc12-test',"
                         "'property':'x-oc12-clock','value':true}}");

    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
    femu_enable(c, &femu->dev, alloc);
    femu_create_io_queues(c);
}

static void femu_oc12_timed_io(FemuCtrlState *c, uint8_t opcode,
                               const uint64_t *ppas, unsigned count,
                               uint64_t duration)
{
    QTestState *qts = c->pdev->bus->qts;
    uint64_t buf = guest_alloc(c->alloc, 4096);
    uint64_t list = guest_alloc(c->alloc, 4096);
    NvmeCmd cmd = { 0 };
    NvmeCmd fence = { 0 };
    NvmeCqe cqe;
    uint16_t want = c->cid;
    uint16_t got;
    unsigned i;

    /* Let resources from the preceding case become idle. */
    qtest_clock_step(qts, 10000000);
    for (i = 0; i < count; i++) {
        uint64_t entry = cpu_to_le64(ppas[i]);

        qtest_memwrite(qts, list + i * sizeof(entry), &entry, sizeof(entry));
    }
    cmd.opcode = opcode;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(count == 1 ? ppas[0] : list);
    cmd.cdw12 = cpu_to_le32(count - 1);
    femu_submit(c, &c->io, &cmd);

    /* An immediate refusal proves the preceding SQ entry was processed. */
    fence.opcode = 0x93;
    fence.nsid = cpu_to_le32(1);
    femu_submit(c, &c->io, &fence);
    g_assert_cmpint(FEMU_SC(femu_complete(c, &c->io, &got, NULL)), ==,
                    NVME_INVALID_OPCODE);
    g_assert_cmpuint(got, ==, (uint16_t)(want + 1));

    qtest_clock_step(qts, duration - 1);
    g_usleep(10000);
    qtest_memread(qts, c->io.cq_addr + c->io.cq_head * sizeof(cqe),
                  &cqe, sizeof(cqe));
    g_assert_cmpuint(le16_to_cpu(cqe.status) & 1, !=, c->io.phase);
    qtest_clock_step(qts, 1);
    g_assert_cmpint(FEMU_SC(femu_complete(c, &c->io, &got, NULL)), ==,
                    NVME_SUCCESS);
    g_assert_cmpuint(got, ==, want);
    guest_free(c->alloc, list);
    guest_free(c->alloc, buf);
}

static void femu_oc12_channel_pair(FemuCtrlState *c, uint64_t second,
                                   uint64_t finish)
{
    QTestState *qts = c->pdev->bus->qts;
    uint64_t buf = guest_alloc(c->alloc, 4096);
    NvmeCmd cmd = { 0 };
    NvmeCqe cqe;
    uint16_t first = c->cid;
    uint16_t got;
    uint16_t other;

    qtest_clock_step(qts, 10000000);
    cmd.opcode = FEMU_OC20_VECT_READ;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    femu_submit(c, &c->io, &cmd);
    cmd.cdw10 = cpu_to_le32(second);
    femu_submit(c, &c->io, &cmd);
    cmd.opcode = 0x93;
    femu_submit(c, &c->io, &cmd);
    g_assert_cmpint(FEMU_SC(femu_complete(c, &c->io, &got, NULL)), ==,
                    NVME_INVALID_OPCODE);
    g_assert_cmpuint(got, ==, (uint16_t)(first + 2));

    qtest_clock_step(qts, 147999);
    g_usleep(10000);
    qtest_memread(qts, c->io.cq_addr + c->io.cq_head * sizeof(cqe),
                  &cqe, sizeof(cqe));
    g_assert_cmpuint(le16_to_cpu(cqe.status) & 1, !=, c->io.phase);
    qtest_clock_step(qts, 1);
    g_assert_cmpint(FEMU_SC(femu_complete(c, &c->io, &got, NULL)), ==,
                    NVME_SUCCESS);
    g_assert_true(got == first || got == (uint16_t)(first + 1));
    if (finish > 148000) {
        g_assert_cmpuint(got, ==, first);
        qtest_clock_step(qts, finish - 148001);
        g_usleep(10000);
        qtest_memread(qts, c->io.cq_addr + c->io.cq_head * sizeof(cqe),
                      &cqe, sizeof(cqe));
        g_assert_cmpuint(le16_to_cpu(cqe.status) & 1, !=, c->io.phase);
        qtest_clock_step(qts, 1);
    }
    g_assert_cmpint(FEMU_SC(femu_complete(c, &c->io, &other, NULL)), ==,
                    NVME_SUCCESS);
    g_assert_true(other == first || other == (uint16_t)(first + 1));
    g_assert_cmpuint(other, !=, got);
    guest_free(c->alloc, buf);
}

static void femu_test_oc12_channel_gap(void *obj, void *data,
                                      QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    const uint64_t deadlines[] = { 1250000, 3000000, 3448000 };
    const unsigned order[] = { 2, 0, 1 };
    NvmeCmd cmd = { 0 };
    NvmeCqe cqe;
    uint16_t first;
    uint16_t got;
    uint64_t elapsed = 0;
    unsigned i;

    femu_oc12_clock_start(&c, femu, alloc);
    first = c.cid;
    cmd.opcode = FEMU_OC20_VECT_ERASE;
    cmd.nsid = cpu_to_le32(1);
    femu_submit(&c, &c.io, &cmd);

    for (i = 0; i < 8; i++) {
        uint64_t ppa = cpu_to_le64(i < 4 ? i : 32768 + i - 4);

        qtest_memwrite(qts, list + i * sizeof(ppa), &ppa, sizeof(ppa));
    }
    cmd.opcode = FEMU_OC20_VECT_READ;
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(list);
    cmd.cdw12 = cpu_to_le32(3);
    femu_submit(&c, &c.io, &cmd);
    cmd.opcode = FEMU_OC20_VECT_WRITE;
    cmd.cdw10 = cpu_to_le32(list + 4 * sizeof(uint64_t));
    femu_submit(&c, &c.io, &cmd);

    /* Keep virtual time fixed until all three entries have been processed. */
    cmd.opcode = 0x93;
    femu_submit(&c, &c.io, &cmd);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), ==,
                   NVME_INVALID_OPCODE);
    g_assert_cmpuint(got, ==, (uint16_t)(first + 3));

    for (i = 0; i < G_N_ELEMENTS(deadlines); i++) {
        qtest_clock_step(qts, deadlines[i] - elapsed - 1);
        g_usleep(10000);
        qtest_memread(qts, c.io.cq_addr + c.io.cq_head * sizeof(cqe),
                      &cqe, sizeof(cqe));
        g_assert_cmpuint(le16_to_cpu(cqe.status) & 1, !=, c.io.phase);
        qtest_clock_step(qts, 1);
        g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), ==,
                       NVME_SUCCESS);
        g_assert_cmpuint(got, ==, (uint16_t)(first + order[i]));
        elapsed = deadlines[i];
    }
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static void femu_test_oc12_channel_timing(void *obj, void *data,
                                          QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    const uint64_t page[] = { 0, 1, 2, 3 };
    const uint64_t same_channel[] = { 0, 1, 2, 3, 32768, 32769, 32770, 32771 };
    const uint64_t other_channel[] = { 0, 1, 2, 3, 65536, 65537, 65538, 65539 };

    femu_oc12_clock_start(&c, femu, alloc);
    femu_oc12_timed_io(&c, FEMU_OC20_VECT_READ, page, 1, 148000);
    femu_oc12_timed_io(&c, FEMU_OC20_VECT_READ, page, 4, 448000);
    femu_oc12_timed_io(&c, FEMU_OC20_VECT_READ, same_channel, 8, 848000);
    femu_oc12_timed_io(&c, FEMU_OC20_VECT_READ, other_channel, 8, 448000);
    femu_oc12_timed_io(&c, FEMU_OC20_VECT_WRITE, page, 4, 1250000);
    femu_oc12_timed_io(&c, FEMU_OC20_VECT_WRITE, same_channel, 8, 1650000);
    femu_oc12_timed_io(&c, FEMU_OC20_VECT_WRITE, other_channel, 8, 1250000);
    femu_oc12_channel_pair(&c, 32768, 248000);
    femu_oc12_channel_pair(&c, 65536, 148000);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static void femu_test_oc12_channel_profile(void *obj, void *data,
                                           QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    const uint64_t page[] = { 0, 0, 0, 0 };
    bool enabled = GPOINTER_TO_UINT(data);

    femu_oc12_clock_start(&c, femu, alloc);
    femu_oc12_timed_io(&c, FEMU_OC20_VECT_READ, page, 1,
                      enabled ? 61109 : 48000);
    femu_oc12_timed_io(&c, FEMU_OC20_VECT_READ, page, 4,
                      enabled ? 100433 : 48000);
    femu_oc12_timed_io(&c, FEMU_OC20_VECT_WRITE, page, 4,
                      enabled ? 902433 : 850000);
    femu_oc12_timed_io(&c, FEMU_OC20_VECT_ERASE, page, 1, 3000000);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static void femu_test_oc12_ppa_timing(void *obj, void *data,
                                      QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    const uint64_t page[] = { 0, 1, 2, 3 };

    femu_oc12_clock_start(&c, femu, alloc);
    femu_oc12_timed_io(&c, FEMU_OC20_VECT_READ, page, 4, 48000);
    femu_oc12_timed_io(&c, FEMU_OC20_VECT_WRITE, page, 4, 850000);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * An Open-Channel 1.2 namespace with sectors smaller than a page: eight
 * sectors fit in one page of the host's buffer, so the transfer maps to one
 * scatter entry for eight addresses. The device pairs addresses with entries
 * one to one, so it refused every such request rather than split the page.
 * A buffer that starts part way into a sector still cannot be paired and is
 * still refused.
 */
static void femu_test_oc12_small_sectors(void *obj, void *data,
                                         QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 2 * 4096);
    uint64_t ppas = guest_alloc(alloc, 4096);
    uint8_t wbuf[4096];
    uint8_t rbuf[4096];
    NvmeCmd cmd = { 0 };
    uint64_t e;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = (buf + 4095) & ~4095ULL;
    for (i = 0; i < 8; i++) {
        e = cpu_to_le64(i);
        qtest_memwrite(qts, ppas + 8 * i, &e, sizeof(e));
    }
    for (i = 0; i < sizeof(wbuf); i++) {
        wbuf[i] = (uint8_t)(0x21 + i * 11);
    }
    qtest_memwrite(qts, buf, wbuf, sizeof(wbuf));

    cmd.opcode = FEMU_OC20_VECT_WRITE;      /* 91h in 1.2 as well */
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32((uint32_t)ppas);
    cmd.cdw11 = cpu_to_le32((uint32_t)(ppas >> 32));
    cmd.cdw12 = cpu_to_le32(7);
    g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_SUCCESS);

    qtest_memset(qts, buf, 0, sizeof(rbuf));
    cmd.opcode = FEMU_OC20_VECT_READ;       /* 92h */
    g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, rbuf, sizeof(rbuf));
    g_assert_cmpint(memcmp(wbuf, rbuf, sizeof(rbuf)), ==, 0);

    cmd.opcode = FEMU_OC20_VECT_WRITE;
    cmd.dptr.prp1 = cpu_to_le64(buf + 256);
    cmd.dptr.prp2 = cpu_to_le64(buf + 4096);
    g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_INVALID_FIELD);

    femu_disable(&c);
    guest_free(alloc, ppas);
}

#define FEMU_CSD_ALLOC_FDM   0xb0
#define FEMU_CSD_DEALLOC     0xc0
#define FEMU_CSD_NVM_TO_AFDM 0xd0
#define FEMU_CSD_EXEC        0xe1
#define FEMU_CSD_READ_AFDM   0xf2
#define FEMU_CSD_WRITE_AFDM  0xf5
#define FEMU_CSD_NEW_GROUP   0xf6
#define FEMU_CSD_SET_QOS     0xf7
#define FEMU_CSD_DEL_GROUP   0xf8
#define FEMU_CSD_FUZZ_IDS    8

typedef struct FemuCsdFuzzMem {
    uint32_t id;
    uint32_t size;
} FemuCsdFuzzMem;

/*
 * Computational storage commands from a fixed seed. The run keeps a small
 * pool of device memory it has allocated, so reads, writes, copies from the
 * namespace and frees mostly name live allocations with in-range offsets;
 * one command in four has a field replaced: an ID that was freed or never
 * given, an offset or size at or past the end, one that wraps, a data
 * pointer from the random lists, or another opcode. Every command must
 * complete, and a fresh allocation must still round-trip data.
 */
static void femu_test_csd_fuzz(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    const uint8_t ops[] = {
        FEMU_CSD_ALLOC_FDM, FEMU_CSD_DEALLOC, FEMU_CSD_NVM_TO_AFDM,
        FEMU_CSD_EXEC, FEMU_CSD_READ_AFDM, FEMU_CSD_WRITE_AFDM,
        FEMU_CSD_NEW_GROUP, FEMU_CSD_SET_QOS, FEMU_CSD_DEL_GROUP,
        NVME_CMD_WRITE, NVME_CMD_READ,
    };
    FemuCsdFuzzMem mem[FEMU_CSD_FUZZ_IDS];
    uint32_t freed[FEMU_CSD_FUZZ_IDS] = { 0 };
    int nmem = 0;
    bool succeeded[256] = { false };
    uint64_t raw = 0;
    uint64_t region = femu_alloc_64k(alloc, &raw);
    uint64_t lists = region + 4096ULL * (FEMU_FUZZ_PAGES - FEMU_FUZZ_LISTS);
    GRand *rng = g_rand_new_with_seed(0x43534446);
    uint8_t wbuf[4096];
    uint8_t rbuf[4096];
    NvmeRwCmd rw;
    NvmeCmd *cmd = (NvmeCmd *)&rw;
    int distinct = 0;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    for (i = 0; i < FEMU_IO_FUZZ_ROUNDS; i++) {
        int pick = nmem ? g_rand_int_range(rng, 0, nmem) : -1;
        uint32_t id = pick >= 0 ? mem[pick].id : 0;
        uint32_t msize = pick >= 0 ? mem[pick].size : 0;
        uint32_t len = 0;
        uint64_t off = 0;
        uint16_t st, cid;
        uint32_t result = 0;

        femu_fuzz_lists(&c, rng, region);
        memset(&rw, 0, sizeof(rw));
        rw.opcode = ops[g_rand_int_range(rng, 0, G_N_ELEMENTS(ops))];
        rw.nsid = cpu_to_le32(1);

        switch (rw.opcode) {
        case FEMU_CSD_ALLOC_FDM:
            len = 512 * g_rand_int_range(rng, 1, 129);
            cmd->cdw10 = cpu_to_le32(len);
            break;
        case FEMU_CSD_DEALLOC:
            cmd->cdw10 = cpu_to_le32(id);
            break;
        case FEMU_CSD_READ_AFDM:
        case FEMU_CSD_WRITE_AFDM:
            if (msize) {
                len = g_rand_int_range(rng, 1,
                                       MIN(msize, 16 * 4096) + 1);
                off = g_rand_int_range(rng, 0, msize - len + 1);
            }
            cmd->cdw10 = cpu_to_le32((uint32_t)off);
            cmd->cdw12 = cpu_to_le32(len);
            cmd->cdw14 = cpu_to_le32(id);
            if (len) {
                femu_fuzz_valid_dptr(&c, rng, region, &rw, len, true);
            }
            break;
        case FEMU_CSD_NVM_TO_AFDM:
            len = g_rand_int_range(rng, 1, 9);
            rw.slba = cpu_to_le64(g_rand_int_range(rng, 0, 1024));
            cmd->cdw12 = cpu_to_le32(len - 1);
            cmd->cdw13 = cpu_to_le32(id);
            if (msize >= len * 512) {
                off = g_rand_int_range(rng, 0, msize - len * 512 + 1);
            }
            cmd->cdw14 = cpu_to_le32((uint32_t)off);
            break;
        case NVME_CMD_WRITE:
        case NVME_CMD_READ:
            len = g_rand_int_range(rng, 1, 9);
            rw.slba = cpu_to_le64(g_rand_int_range(rng, 0, 1024));
            rw.nlb = cpu_to_le16(len - 1);
            femu_fuzz_valid_dptr(&c, rng, region, &rw, len * 512, true);
            break;
        default:
            /* groups, QoS and execute: small values in every field */
            cmd->cdw10 = cpu_to_le32(g_rand_int_range(rng, 0, 16));
            cmd->cdw11 = cpu_to_le32(g_rand_int_range(rng, 0, 1024));
            cmd->cdw12 = cpu_to_le32(g_rand_int_range(rng, 0, 1024));
            break;
        }

        if (g_rand_int_range(rng, 0, 4) == 0) {
            switch (g_rand_int_range(rng, 0, 7)) {
            case 0:
                rw.opcode = g_rand_int_range(rng, 0, 0x100);
                break;
            case 1:
                /* an ID freed earlier, or one never given */
                cmd->cdw10 = cpu_to_le32(g_rand_boolean(rng) ?
                        freed[g_rand_int_range(rng, 0,
                                               FEMU_CSD_FUZZ_IDS)] :
                        g_rand_int(rng));
                cmd->cdw13 = cmd->cdw10;
                cmd->cdw14 = cmd->cdw10;
                break;
            case 2:
                /* an offset at the end, past it, or one that wraps */
                if (g_rand_boolean(rng)) {
                    cmd->cdw10 = cpu_to_le32(msize);
                    cmd->cdw14 = cpu_to_le32(msize);
                } else {
                    cmd->cdw10 = cpu_to_le32(g_rand_int(rng));
                    cmd->cdw11 = cpu_to_le32(0xffffffff);
                    cmd->cdw15 = cpu_to_le32(0xffffffff);
                }
                break;
            case 3:
                /* a size of zero, past the end, or near 2^64 */
                cmd->cdw12 = cpu_to_le32(g_rand_boolean(rng) ? 0 :
                                         g_rand_int(rng));
                cmd->cdw13 = cpu_to_le32(g_rand_boolean(rng) ? 0 :
                                         0xffffffff);
                break;
            case 4:
                rw.flags = 0;
                rw.dptr.prp1 = cpu_to_le64(femu_fuzz_ptr(rng, region));
                rw.dptr.prp2 = cpu_to_le64(g_rand_boolean(rng) ?
                        lists + 8 * g_rand_int_range(rng, 0,
                                            FEMU_FUZZ_PRP_LISTS * 512) :
                        femu_fuzz_ptr(rng, region));
                break;
            case 5:
                rw.flags = g_rand_int_range(rng, 1, 4) << 6;
                qtest_memread(qts, femu_fuzz_sgl_slot(rng, region),
                              &rw.dptr.sgl, sizeof(rw.dptr.sgl));
                break;
            default:
                cmd->cdw11 = cpu_to_le32(g_rand_int(rng));
                cmd->cdw12 = cpu_to_le32(g_rand_int(rng));
                cmd->cdw13 = cpu_to_le32(g_rand_int(rng));
                break;
            }
        }

        femu_submit(&c, &c.io, cmd);
        st = FEMU_SC(femu_complete(&c, &c.io, &cid, &result));
        if (st == NVME_SUCCESS && !succeeded[rw.opcode]) {
            succeeded[rw.opcode] = true;
            distinct++;
        }

        /* keep the pool in step with what the device holds */
        if (st == NVME_SUCCESS && rw.opcode == FEMU_CSD_ALLOC_FDM) {
            if (nmem == FEMU_CSD_FUZZ_IDS) {
                NvmeCmd free_cmd = { 0 };

                free_cmd.opcode = FEMU_CSD_DEALLOC;
                free_cmd.nsid = cpu_to_le32(1);
                free_cmd.cdw10 = cpu_to_le32(result);
                g_assert_cmpint(femu_io(&c, &free_cmd), ==, NVME_SUCCESS);
                freed[i % FEMU_CSD_FUZZ_IDS] = result;
            } else {
                mem[nmem].id = result;
                mem[nmem].size = le32_to_cpu(cmd->cdw10);
                nmem++;
            }
        } else if (st == NVME_SUCCESS && rw.opcode == FEMU_CSD_DEALLOC) {
            int k;

            for (k = 0; k < nmem; k++) {
                if (mem[k].id == le32_to_cpu(cmd->cdw10)) {
                    freed[i % FEMU_CSD_FUZZ_IDS] = mem[k].id;
                    mem[k] = mem[--nmem];
                    break;
                }
            }
        }
    }

    g_assert_cmpint(distinct, >=, 5);

    /* a fresh allocation takes data in and gives it back */
    memset(&rw, 0, sizeof(rw));
    rw.opcode = FEMU_CSD_ALLOC_FDM;
    rw.nsid = cpu_to_le32(1);
    cmd->cdw10 = cpu_to_le32(sizeof(wbuf));
    femu_submit(&c, &c.io, cmd);
    {
        uint16_t cid;
        uint32_t id = 0;

        g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &cid, &id)), ==,
                        NVME_SUCCESS);
        for (i = 0; i < sizeof(wbuf); i++) {
            wbuf[i] = (uint8_t)(0x6f + i * 9);
        }
        qtest_memwrite(qts, region, wbuf, sizeof(wbuf));
        memset(&rw, 0, sizeof(rw));
        rw.opcode = FEMU_CSD_WRITE_AFDM;
        rw.nsid = cpu_to_le32(1);
        rw.dptr.prp1 = cpu_to_le64(region);
        cmd->cdw12 = cpu_to_le32(sizeof(wbuf));
        cmd->cdw14 = cpu_to_le32(id);
        g_assert_cmpint(femu_io(&c, cmd), ==, NVME_SUCCESS);
        qtest_memset(qts, region, 0, sizeof(rbuf));
        rw.opcode = FEMU_CSD_READ_AFDM;
        g_assert_cmpint(femu_io(&c, cmd), ==, NVME_SUCCESS);
        qtest_memread(qts, region, rbuf, sizeof(rbuf));
        g_assert_cmpint(memcmp(wbuf, rbuf, sizeof(rbuf)), ==, 0);
    }

    femu_disable(&c);
    g_rand_free(rng);
    guest_free(alloc, raw);
}

#define FEMU_OC_FUZZ_CHUNKS 2
#define FEMU_OC_FUZZ_MAX    8   /* sectors in one vector command */

typedef struct FemuOcGeo {
    uint8_t sec_len;
    uint8_t chk_len;
    uint8_t lun_len;
    uint32_t num_chk;
    uint32_t num_pu;
    uint32_t clba;
    uint32_t secsz;
} FemuOcGeo;

/* Sector @sec of chunk @chk in parallel unit @pu of group 0. */
static uint64_t femu_oc_lba(const FemuOcGeo *g, uint32_t pu, uint32_t chk,
                            uint32_t sec)
{
    return (uint64_t)pu << (g->sec_len + g->chk_len) |
           (uint64_t)chk << g->sec_len | sec;
}

/*
 * The write pointer of a chunk in group 0, from the chunk information log:
 * sectors written so far, counted from the start of the chunk.
 */
static uint64_t femu_oc_wp(FemuCtrlState *c, const FemuOcGeo *g,
                           uint64_t buf, uint32_t pu, uint32_t chk)
{
    uint32_t idx = pu * g->num_chk + chk;

    g_assert_cmpint(femu_oc20_chunk(c, NVME_ADM_CMD_GET_LOG_PAGE, buf,
                                    idx * 32), ==, NVME_SUCCESS);
    return qtest_readq(c->pdev->bus->qts, buf + 24);
}

/*
 * Open-Channel 2.0 vector commands from a fixed seed over a few chunks of
 * two parallel units. Valid writes land at the chunk's write pointer, valid
 * reads only on sectors the write cache has let go of, and a full chunk is
 * reset before the next write. One in four commands has a field replaced:
 * opcode, namespace, LBA list entries (outside the geometry, in another
 * chunk, behind the write pointer), the sector count, the list pointer, or
 * a data pointer from the random lists. Every command must complete, and a
 * chunk written afterwards must read back what was written.
 */
static void femu_test_oc20_fuzz(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    FemuOcGeo g;
    uint8_t id[128];
    bool succeeded[256] = { false };
    uint64_t raw = 0;
    uint64_t region = femu_alloc_64k(alloc, &raw);
    uint64_t lists = region + 4096ULL * (FEMU_FUZZ_PAGES - FEMU_FUZZ_LISTS);
    uint64_t lbas = guest_alloc(alloc, 4096);
    uint64_t logbuf = guest_alloc(alloc, 4096);
    GRand *rng = g_rand_new_with_seed(0x4f433230);
    uint8_t wbuf[4096];
    uint8_t rbuf[4096];
    NvmeRwCmd rw;
    NvmeCmd *cmd = (NvmeCmd *)&rw;
    int distinct = 0;
    int i, j;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    memset(&rw, 0, sizeof(rw));
    rw.opcode = FEMU_OC20_IDENTIFY;
    rw.nsid = cpu_to_le32(1);
    rw.dptr.prp1 = cpu_to_le64(logbuf);
    g_assert_cmpint(femu_admin(&c, cmd), ==, NVME_SUCCESS);
    qtest_memread(qts, logbuf, id, sizeof(id));
    g.sec_len = id[11];
    g.chk_len = id[10];
    g.lun_len = id[9];
    g.num_pu = lduw_le_p(id + 66);
    g.num_chk = ldl_le_p(id + 68);
    g.clba = ldl_le_p(id + 72);

    g_assert_cmpint(femu_identify(&c, 1, NVME_ID_CNS_NS, 0, logbuf), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, logbuf, id, sizeof(id));
    g.secsz = 1U << qtest_readb(qts, logbuf + 128 + 4 * (id[26] & 0xf) + 2);
    g_assert_cmpint(g.secsz, ==, 4096);
    /*
     * The run uses chunk 0 of units 0 and 1, and chunk 1 of unit 0 is left
     * for the check after it; the device backs no more than these.
     */
    g_assert_cmpint(g.num_pu, >=, FEMU_OC_FUZZ_CHUNKS);
    g_assert_cmpint(g.num_chk, >=, 2);
    g_assert_cmpint(g.clba, >, FEMU_OC20_MW_CUNITS + FEMU_OC_FUZZ_MAX);

    /*
     * A chunk takes thousands of sectors, more than the run writes, so fill
     * all but the last few of unit 1's first and the run crosses a reset.
     */
    for (i = 0; i + FEMU_OC_FUZZ_MAX <= g.clba - 64; i += FEMU_OC_FUZZ_MAX) {
        for (j = 0; j < FEMU_OC_FUZZ_MAX; j++) {
            uint64_t e = cpu_to_le64(femu_oc_lba(&g, 1, 0, i + j));

            qtest_memwrite(qts, lbas + 8 * j, &e, sizeof(e));
        }
        memset(&rw, 0, sizeof(rw));
        rw.opcode = FEMU_OC20_VECT_WRITE;
        rw.nsid = cpu_to_le32(1);
        cmd->cdw10 = cpu_to_le32((uint32_t)lbas);
        cmd->cdw11 = cpu_to_le32((uint32_t)(lbas >> 32));
        cmd->cdw12 = cpu_to_le32(FEMU_OC_FUZZ_MAX - 1);
        femu_fuzz_valid_dptr(&c, rng, region, &rw,
                             FEMU_OC_FUZZ_MAX * g.secsz, false);
        g_assert_cmpint(femu_io(&c, cmd), ==, NVME_SUCCESS);
    }

    for (i = 0; i < FEMU_IO_FUZZ_ROUNDS; i++) {
        uint32_t pu = g_rand_int_range(rng, 0, FEMU_OC_FUZZ_CHUNKS);
        uint32_t chk = 0;
        uint32_t k = g_rand_int_range(rng, 1, FEMU_OC_FUZZ_MAX + 1);
        uint32_t kind = g_rand_int_range(rng, 0, 8);
        uint64_t wp = femu_oc_wp(&c, &g, logbuf, pu, chk);
        uint64_t first;
        uint16_t st;

        femu_fuzz_lists(&c, rng, region);
        memset(&rw, 0, sizeof(rw));
        rw.nsid = cpu_to_le32(1);

        if (wp == g.clba || kind == 0) {
            /* valid for a full chunk; an open one must refuse it */
            rw.opcode = FEMU_OC20_VECT_ERASE;
            k = 1;
            first = femu_oc_lba(&g, pu, chk, 0);
        } else if (kind < 5 || wp < FEMU_OC20_MW_CUNITS + k) {
            rw.opcode = FEMU_OC20_VECT_WRITE;
            k = MIN(k, g.clba - wp);
            first = femu_oc_lba(&g, pu, chk, wp);
        } else {
            rw.opcode = FEMU_OC20_VECT_READ;
            first = femu_oc_lba(&g, pu, chk, g_rand_int_range(rng, 0,
                                wp - FEMU_OC20_MW_CUNITS - k + 1));
        }

        for (j = 0; j < k; j++) {
            uint64_t e = cpu_to_le64(first + j);

            qtest_memwrite(qts, lbas + 8 * j, &e, sizeof(e));
        }
        cmd->cdw12 = cpu_to_le32(k - 1);
        if (k == 1) {
            cmd->cdw10 = cpu_to_le32((uint32_t)first);
            cmd->cdw11 = cpu_to_le32((uint32_t)(first >> 32));
        } else {
            cmd->cdw10 = cpu_to_le32((uint32_t)lbas);
            cmd->cdw11 = cpu_to_le32((uint32_t)(lbas >> 32));
        }
        if (rw.opcode != FEMU_OC20_VECT_ERASE) {
            femu_fuzz_valid_dptr(&c, rng, region, &rw, k * g.secsz, false);
        }

        if (g_rand_int_range(rng, 0, 4) == 0) {
            switch (g_rand_int_range(rng, 0, 7)) {
            case 0:
                rw.opcode = g_rand_int_range(rng, 0, 0x100);
                break;
            case 1:
                rw.nsid = cpu_to_le32(g_rand_boolean(rng) ? 0xffffffff :
                                      g_rand_int_range(rng, 0, 4));
                break;
            case 2: {
                /* one entry anywhere: past the geometry, another chunk */
                uint64_t e;

                if (g_rand_boolean(rng)) {
                    uint64_t hi = g_rand_int(rng);

                    e = hi << 32 | g_rand_int(rng);
                } else {
                    e = femu_oc_lba(&g, g_rand_int_range(rng, 0, 1U <<
                                                         g.lun_len),
                                    g_rand_int_range(rng, 0, 1U <<
                                                     g.chk_len), 0);
                    e |= g_rand_int_range(rng, 0, 1U << g.sec_len);
                }
                if (k == 1) {
                    cmd->cdw10 = cpu_to_le32((uint32_t)e);
                    cmd->cdw11 = cpu_to_le32((uint32_t)(e >> 32));
                } else {
                    e = cpu_to_le64(e);
                    qtest_memwrite(qts, lbas +
                                   8 * g_rand_int_range(rng, 0, k),
                                   &e, sizeof(e));
                }
                break;
            }
            case 3:
                /* up to 256 entries; the list page holds only k of them */
                cmd->cdw12 = cpu_to_le32(g_rand_int_range(rng, 0, 0x10000));
                break;
            case 4: {
                uint64_t p = femu_fuzz_ptr(rng, region);

                cmd->cdw10 = cpu_to_le32((uint32_t)p);
                cmd->cdw11 = cpu_to_le32((uint32_t)(p >> 32));
                break;
            }
            case 5:
                rw.flags = 0;
                rw.dptr.prp1 = cpu_to_le64(femu_fuzz_ptr(rng, region));
                rw.dptr.prp2 = cpu_to_le64(g_rand_boolean(rng) ?
                        lists + 8 * g_rand_int_range(rng, 0,
                                            FEMU_FUZZ_PRP_LISTS * 512) :
                        femu_fuzz_ptr(rng, region));
                break;
            default:
                rw.flags = g_rand_int_range(rng, 1, 4) << 6;
                qtest_memread(qts, femu_fuzz_sgl_slot(rng, region),
                              &rw.dptr.sgl, sizeof(rw.dptr.sgl));
                break;
            }
        }

        st = femu_io(&c, cmd);
        if (st == NVME_SUCCESS && !succeeded[rw.opcode]) {
            succeeded[rw.opcode] = true;
            distinct++;
        }
    }

    g_assert_cmpint(distinct, >=, 3);

    /* a chunk the run left alone reads back what is written to it now */
    for (i = 0; i < 4096; i++) {
        wbuf[i] = (uint8_t)(0x3d + i * 5);
    }
    qtest_memwrite(qts, region, wbuf, sizeof(wbuf));
    for (i = 0; i <= FEMU_OC20_MW_CUNITS; i++) {
        uint64_t lba = femu_oc_lba(&g, 0, 1, i);

        memset(&rw, 0, sizeof(rw));
        rw.opcode = FEMU_OC20_VECT_WRITE;
        rw.nsid = cpu_to_le32(1);
        rw.dptr.prp1 = cpu_to_le64(region);
        cmd->cdw10 = cpu_to_le32((uint32_t)lba);
        cmd->cdw11 = cpu_to_le32((uint32_t)(lba >> 32));
        g_assert_cmpint(femu_io(&c, cmd), ==, NVME_SUCCESS);
    }
    qtest_memset(qts, region, 0, sizeof(rbuf));
    rw.opcode = FEMU_OC20_VECT_READ;
    cmd->cdw10 = cpu_to_le32(femu_oc_lba(&g, 0, 1, 0));
    cmd->cdw11 = 0;
    g_assert_cmpint(femu_io(&c, cmd), ==, NVME_SUCCESS);
    qtest_memread(qts, region, rbuf, sizeof(rbuf));
    g_assert_cmpint(memcmp(wbuf, rbuf, sizeof(rbuf)), ==, 0);

    femu_disable(&c);
    g_rand_free(rng);
    guest_free(alloc, logbuf);
    guest_free(alloc, lbas);
    guest_free(alloc, raw);
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

/* the QEMU process's peak virtual size, which a large allocation raises */
static uint64_t femu_vm_peak_kb(QTestState *qts)
{
    g_autofree char *path = g_strdup_printf("/proc/%d/status", qtest_pid(qts));
    g_autofree char *text = NULL;
    const char *line;

    g_assert_true(g_file_get_contents(path, &text, NULL, NULL));
    line = strstr(text, "VmPeak:");
    g_assert_nonnull(line);
    return g_ascii_strtoull(line + strlen("VmPeak:"), NULL, 10);
}

/*
 * With MDTS 0 there is no transfer limit, so the host can ask for up to 4 GiB
 * of a report whose data is a few hundred bytes. The device allocated a
 * buffer of the whole request. Each report is sent in full, so without a PRP
 * list for 4 GiB these are refused, but only after the allocation would have
 * happened, which is why the size is checked first.
 */
static void femu_test_mdts0_reports(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t mem, buf, peak;
    uint16_t st;

    femu_enable(&c, &femu->dev, alloc);
    mem = guest_alloc(alloc, 2 * 4096);
    buf = (mem + 4095) & ~4095ULL;

    /* a single dword, shorter than the 8-byte header */
    g_assert_cmpint(femu_get_lba_status(&c, buf, 0, 0, 0x10, 0), ==,
                    NVME_SUCCESS);

    peak = femu_vm_peak_kb(qts);
    st = femu_get_lba_status(&c, buf, 0, 0x3ffffffe, 0x10, 0);
    g_assert_cmpuint(femu_vm_peak_kb(qts) - peak, <, 1024 * 1024);
    g_assert_cmpint(st, !=, NVME_SUCCESS);

    st = femu_get_telemetry(&c, FEMU_LOG_TELEMETRY_HOST, false, buf,
                            0xfffffe00, 0);
    g_assert_cmpuint(femu_vm_peak_kb(qts) - peak, <, 1024 * 1024);
    g_assert_cmpint(st, !=, NVME_SUCCESS);

    guest_free(alloc, mem);
    femu_disable(&c);
}

/* Report Zones under MDTS 0: the same bound as the reports above */
static void femu_test_mdts0_zone_report(void *obj, void *data,
                                        QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t mem, buf, peak;
    NvmeCmd cmd = { 0 };
    uint16_t st;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    mem = guest_alloc(alloc, 2 * 4096);
    buf = (mem + 4095) & ~4095ULL;
    peak = femu_vm_peak_kb(qts);

    cmd.opcode = NVME_CMD_ZONE_MGMT_RECV;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw12 = cpu_to_le32(0x3ffffffe);
    st = femu_io(&c, &cmd);
    g_assert_cmpuint(femu_vm_peak_kb(qts) - peak, <, 1024 * 1024);
    g_assert_cmpint(st, !=, NVME_SUCCESS);

    guest_free(alloc, mem);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * Past the end of the data, RUH Status sends zeroes (Base 2.3, 7.3.1.1), and
 * so does telemetry, which sends every block asked for. The host's buffer is
 * filled with a pattern first so that bytes left untouched show up.
 */
static void femu_test_report_zero_tail(void *obj, void *data,
                                       QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint8_t page[4096], zero[4096] = { 0 };
    uint64_t mem, buf;
    NvmeCmd cmd = { 0 };
    uint32_t used;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    mem = guest_alloc(alloc, 2 * 4096);
    buf = (mem + 4095) & ~4095ULL;

    memset(page, 0xa5, sizeof(page));
    qtest_memwrite(qts, buf, page, sizeof(page));
    cmd.opcode = FEMU_CMD_IO_MGMT_RECV;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(FEMU_IOMR_RUH_STATUS);
    cmd.cdw11 = cpu_to_le32(sizeof(page) / 4 - 1);
    g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, page, sizeof(page));
    used = 16 + 32 * lduw_le_p(page + 14);
    g_assert_cmpuint(used, <, sizeof(page));
    g_assert_cmpint(memcmp(page + used, zero, sizeof(page) - used), ==, 0);

    memset(page, 0xa5, sizeof(page));
    qtest_memwrite(qts, buf, page, sizeof(page));
    g_assert_cmpint(femu_get_telemetry(&c, FEMU_LOG_TELEMETRY_HOST, false,
                                       buf, sizeof(page), 0), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, buf, page, sizeof(page));
    g_assert_cmpint(page[0], ==, FEMU_LOG_TELEMETRY_HOST);
    g_assert_cmpint(memcmp(page + 512, zero, sizeof(page) - 512), ==, 0);

    guest_free(alloc, mem);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * KV List takes its host buffer size from the command, and with MDTS 0
 * nothing bounds it: the device allocated all of it, up to 4 GiB. Enough
 * keys to pass one page make its buffer grow instead, and every one of them
 * must still be listed.
 */
static void femu_test_kv_list_mdts0(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    const int keys = 300;               /* 20 bytes each, past 4 KiB */
    uint64_t mem, buf, peak;
    NvmeCmd cmd;
    uint16_t st;
    int k;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    mem = guest_alloc(alloc, 3 * 4096);
    buf = (mem + 4095) & ~4095ULL;

    for (k = 0; k < keys; k++) {
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = FEMU_KV_CMD_STORE;
        cmd.nsid = cpu_to_le32(1);
        cmd.dptr.prp1 = cpu_to_le64(buf);
        cmd.cdw10 = cpu_to_le32(64);
        femu_kv_fuzz_key(&cmd, k, 16);
        g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_SUCCESS);
    }

    peak = femu_vm_peak_kb(qts);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_KV_CMD_LIST;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.dptr.prp2 = cpu_to_le64(buf + 4096);
    cmd.cdw10 = cpu_to_le32(0xfffffffc);
    st = femu_io(&c, &cmd);
    g_assert_cmpuint(femu_vm_peak_kb(qts) - peak, <, 1024 * 1024);
    g_assert_cmpint(st, ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, keys);

    guest_free(alloc, mem);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * Timestamp (Base 2.3, 5.2.26.1.7): advertised in ONCS; after a Set the
 * controller counts on from the host's value and reports origin 001b; a
 * Controller Level Reset clears it to the time since that reset, origin 000b.
 * The value is 48 bits and the two bytes above it are reserved.
 */
static void femu_test_timestamp(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    const uint64_t host = 0x0123456789abULL;
    uint64_t mem, buf, ts;
    uint32_t cap;

    femu_enable(&c, &femu->dev, alloc);
    mem = guest_alloc(alloc, 2 * 4096);
    buf = (mem + 4095) & ~4095ULL;

    g_assert_cmpint(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpint(qtest_readw(qts, buf + 520) & FEMU_ONCS_TIMESTAMP, !=, 0);

    qtest_memset(qts, buf, 0xff, 8);
    g_assert_cmpint(femu_timestamp(&c, false, 0, 0, buf), ==, NVME_SUCCESS);
    ts = qtest_readq(qts, buf);
    g_assert_cmpuint(ts >> 48, ==, 0);          /* origin 000b, sync 0 */
    g_assert_cmpuint(ts, <, 60 * 1000);

    /* the reserved bytes of the host's value are ignored */
    qtest_writeq(qts, buf, host | 0xabcdULL << 48);
    g_assert_cmpint(femu_timestamp(&c, true, 0, 0, buf), ==, NVME_SUCCESS);
    qtest_memset(qts, buf, 0, 8);
    g_assert_cmpint(femu_timestamp(&c, false, 0, 0, buf), ==, NVME_SUCCESS);
    ts = qtest_readq(qts, buf);
    g_assert_cmpuint(ts & 0xffffffffffffULL, >=, host);
    g_assert_cmpuint(ts & 0xffffffffffffULL, <, host + 60 * 1000);
    g_assert_cmpuint((ts >> 48) & 0xff, ==, 1 << 1);    /* origin 001b */

    /* not saveable; changeable; the default is a reset's zero */
    g_assert_cmpint(femu_timestamp(&c, true, 0, 1, buf), ==,
                    NVME_FID_NOT_SAVEABLE);
    g_assert_cmpint(femu_get_feature(&c, FEMU_FID_TIMESTAMP, 3, 0, 0, &cap),
                    ==, NVME_SUCCESS);
    g_assert_cmpuint(cap, ==, NVME_FEAT_CAP_CHANGE);
    qtest_memset(qts, buf, 0xff, 8);
    g_assert_cmpint(femu_timestamp(&c, false, 1, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(qts, buf), ==, 0);

    /* a Controller Level Reset starts it over */
    femu_disable(&c);
    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_timestamp(&c, false, 0, 0, buf), ==, NVME_SUCCESS);
    ts = qtest_readq(qts, buf);
    g_assert_cmpuint(ts >> 48, ==, 0);
    g_assert_cmpuint(ts, <, 60 * 1000);

    guest_free(alloc, mem);
    femu_disable(&c);
}

#define FEMU_LOG_PEL            0x0d
#define FEMU_CMD_SEQ_ERROR      0x0c

/* Get Log Page 0Dh with an action (Figure 229), len bytes at off */
static uint16_t femu_pel(FemuCtrlState *c, uint8_t act, uint64_t buf,
                         uint32_t len, uint64_t off)
{
    uint32_t numd = len / 4 - 1;
    NvmeCmd cmd = { 0 };

    cmd.opcode = NVME_ADM_CMD_GET_LOG_PAGE;
    cmd.nsid = cpu_to_le32(NVME_NSID_BROADCAST);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(FEMU_LOG_PEL | act << 8 | (numd & 0xffff) << 16);
    cmd.cdw11 = cpu_to_le32(numd >> 16);
    cmd.cdw12 = cpu_to_le32((uint32_t)off);
    cmd.cdw13 = cpu_to_le32((uint32_t)(off >> 32));
    return FEMU_SC(femu_admin(c, &cmd));
}

/* the event type of the i'th event reported, counting from the newest */
static uint8_t femu_pel_event(QTestState *qts, uint64_t buf, int i)
{
    uint64_t e = buf + 512;

    while (i--) {
        e += 3 + qtest_readb(qts, e + 2) + qtest_readw(qts, e + 22);
    }
    return qtest_readb(qts, e);
}

static uint16_t femu_ns_delete(FemuCtrlState *c, uint32_t nsid)
{
    NvmeCmd cmd = { 0 };

    /* Namespace changes outlive qgraph's reset between tests. */
    qos_invalidate_command_line();
    cmd.opcode = 0x0d;
    cmd.nsid = cpu_to_le32(nsid);
    cmd.cdw10 = cpu_to_le32(1);
    return FEMU_SC(femu_admin(c, &cmd));
}

static uint16_t femu_ns_create(FemuCtrlState *c, uint64_t buf, uint64_t nsze,
                               uint8_t flbas, uint32_t *nsid)
{
    NvmeCmd cmd = { 0 };

    qos_invalidate_command_line();
    qtest_memset(c->pdev->bus->qts, buf, 0, 4096);
    qtest_writeq(c->pdev->bus->qts, buf, nsze);
    qtest_writeq(c->pdev->bus->qts, buf + 8, nsze);
    qtest_writeb(c->pdev->bus->qts, buf + 26, flbas);
    cmd.opcode = 0x0d;
    cmd.dptr.prp1 = cpu_to_le64(buf);
    return FEMU_SC(femu_admin_result(c, &cmd, nsid));
}

static uint16_t femu_ns_attach(FemuCtrlState *c, uint64_t buf, uint32_t nsid,
                               uint16_t cntlid, bool attach)
{
    NvmeCmd cmd = { 0 };

    qos_invalidate_command_line();
    qtest_memset(c->pdev->bus->qts, buf, 0, 4096);
    qtest_writew(c->pdev->bus->qts, buf, 1);
    qtest_writew(c->pdev->bus->qts, buf + 2, cntlid);
    cmd.opcode = 0x15;
    cmd.nsid = cpu_to_le32(nsid);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(!attach);
    return FEMU_SC(femu_admin(c, &cmd));
}

static void femu_test_ns_mgmt_commands(void *obj, void *data,
                                       QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint32_t nsid;
    uint16_t cntlid;
    NvmeCmd cmd = { 0 };
    uint8_t bytes[1024];
    int i;

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readw(qts, buf + 256) & 8, ==, 8);
    g_assert_cmpuint(qtest_readl(qts, buf + 516), ==, 256);
    cntlid = qtest_readw(qts, buf + 78);
    g_assert_cmpint(femu_ns_delete(&c, 1), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_create(&c, buf, 3, 1, &nsid), ==, NVME_SUCCESS);
    g_assert_cmpuint(nsid, ==, 1);
    g_assert_cmpint(femu_identify(&c, 0, 0x10, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 1);
    g_assert_cmpint(femu_identify(&c, 0, 2, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 0);
    g_assert_cmpint(femu_identify(&c, 1, 0, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(qts, buf), ==, 0);
    g_assert_cmpint(femu_identify(&c, 1, 0x11, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(qts, buf), ==, 3);
    g_assert_cmpuint(qtest_readb(qts, buf + 26), ==, 1);
    g_assert_cmpuint(qtest_readq(qts, buf + 48), ==, 4096);
    g_assert_cmpint(femu_ns_attach(&c, buf, 1, cntlid, true), ==, NVME_SUCCESS);
    femu_create_io_queues(&c);
    cmd.opcode = NVME_CMD_WRITE;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    qtest_memset(qts, buf, 0x5a, 1024);
    femu_submit(&c, &c.io, &cmd);
    g_assert_cmpint(femu_complete(&c, &c.io, NULL, NULL), ==, NVME_SUCCESS);
    cmd.opcode = NVME_CMD_READ;
    qtest_memset(qts, buf, 0, 1024);
    femu_submit(&c, &c.io, &cmd);
    g_assert_cmpint(femu_complete(&c, &c.io, NULL, NULL), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, bytes, sizeof(bytes));
    for (i = 0; i < sizeof(bytes); i++) {
        g_assert_cmphex(bytes[i], ==, 0x5a);
    }
    g_assert_cmpint(femu_ns_attach(&c, buf, 1, cntlid, false), ==,
                   NVME_SUCCESS);
    femu_submit(&c, &c.io, &cmd);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, NULL, NULL)), ==,
                   NVME_INVALID_FIELD);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_identify(&c, 0, 2, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 0);
    g_assert_cmpint(femu_identify(&c, 1, 0x11, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(qts, buf), ==, 3);
    g_assert_cmpint(femu_ns_delete(&c, 1), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_create(&c, buf, 8, 0, &nsid), ==, NVME_SUCCESS);
    g_assert_cmpuint(nsid, ==, 1);
    g_assert_cmpint(femu_ns_attach(&c, buf, 1, cntlid, true), ==, NVME_SUCCESS);
    femu_create_io_queues(&c);
    femu_submit(&c, &c.io, &cmd);
    g_assert_cmpint(femu_complete(&c, &c.io, NULL, NULL), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, bytes, 512);
    for (i = 0; i < 512; i++) {
        g_assert_cmphex(bytes[i], ==, 0);
    }
    g_assert_cmpint(femu_ns_delete(&c, 0xffffffff), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_delete(&c, 0xffffffff), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_identify(&c, 0, 0x10, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 0);
    g_assert_cmpint(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(qts, buf + 296), ==, 64 * 1024 * 1024);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    guest_free(alloc, buf);
}

static void femu_test_ns_mgmt_bbssd_cap(void *obj, void *data,
                                        QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint32_t nsid;
    int limit = data ? GPOINTER_TO_INT(data) : 4;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_ns_delete(&c, 0xffffffff), ==, NVME_SUCCESS);
    for (i = 1; i <= limit; i++) {
        g_assert_cmpint(femu_ns_create(&c, buf, 8, 0, &nsid), ==,
                       NVME_SUCCESS);
        g_assert_cmpuint(nsid, ==, i);
    }
    /* Detached allocations consume FTL resources too. */
    g_assert_cmphex(femu_ns_create(&c, buf, 8, 0, &nsid), ==, 0x116);
    g_assert_cmpint(femu_ns_delete(&c, 2), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_create(&c, buf, 8, 0, &nsid), ==, NVME_SUCCESS);
    g_assert_cmpuint(nsid, ==, 2);
    femu_disable(&c);
    guest_free(alloc, buf);
}

static void femu_test_ns_mgmt_bbssd_boot_cap(void *obj, void *data,
                                             QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    QDict *rsp;

    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'rejected','addr':'5',"
                    "'devsz_mb':5,'femu_mode':1,'ns_mgmt':true,"
                    "'namespaces':5,'secsz':512,'secs_per_pg':8,"
                    "'pgs_per_blk':16,'blks_per_pl':40,'pls_per_lun':1,"
                    "'luns_per_ch':1,'nchs':1}}");
    g_assert_true(qdict_haskey(rsp, "error"));
    g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                         "desc"), "bbssd_ns_limit"));
    qobject_unref(rsp);

    /* The cap must not constrain fixed boot configurations. */
    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'fixed','addr':'5',"
                    "'devsz_mb':5,'femu_mode':1,'ns_mgmt':false,"
                    "'namespaces':5,'secsz':512,'secs_per_pg':8,"
                    "'pgs_per_blk':16,'blks_per_pl':40,'pls_per_lun':1,"
                    "'luns_per_ch':1,'nchs':1}}");
    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
    qpci_unplug_acpi_device_test(qts, "fixed", 5);
    qos_invalidate_command_line();
}

static void femu_test_ns_mgmt_bbssd_capacity(void *obj, void *data,
                                             QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint32_t nsid;

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_ns_delete(&c, 0xffffffff), ==, NVME_SUCCESS);
    /* The pool fits this size; one FTL needs part of it for GC reserves. */
    g_assert_cmphex(femu_ns_create(&c, buf, 8192, 0, &nsid), ==, 0x115);
    g_assert_cmpint(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(qts, buf + 296), ==, 4 * 1024 * 1024);
    g_assert_cmpint(femu_identify(&c, 0, 0x10, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 0);
    g_assert_cmpint(femu_ns_create(&c, buf, 4096, 0, &nsid), ==, NVME_SUCCESS);
    g_assert_cmpuint(nsid, ==, 1);
    femu_disable(&c);
    guest_free(alloc, buf);
}

static void femu_ns_page(FemuCtrlState *c, uint64_t buf, uint32_t nsid,
                         uint32_t page, uint8_t pattern, bool write)
{
    QTestState *qts = c->pdev->bus->qts;
    uint8_t bytes[4096];
    int i;

    qtest_memset(qts, buf, write ? pattern : 0xff, 4096);
    g_assert_cmpint(femu_rw_ns(c, write ? NVME_CMD_WRITE : NVME_CMD_READ,
                             nsid, page * 8, buf), ==, NVME_SUCCESS);
    if (!write) {
        qtest_memread(qts, buf, bytes, sizeof(bytes));
        for (i = 0; i < sizeof(bytes); i++) {
            g_assert_cmphex(bytes[i], ==, pattern);
        }
    }
}

static void femu_test_ns_mgmt_bbssd_isolation(void *obj, void *data,
                                              QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint32_t nsid;
    uint16_t cntlid;
    int pass;
    int i;
    int ns;

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);
    cntlid = qtest_readw(qts, buf + 78);
    g_assert_cmpint(femu_ns_delete(&c, 0xffffffff), ==, NVME_SUCCESS);
    for (ns = 1; ns <= 2; ns++) {
        g_assert_cmpint(femu_ns_create(&c, buf, 4096, 0, &nsid), ==,
                       NVME_SUCCESS);
        g_assert_cmpuint(nsid, ==, ns);
        g_assert_cmpint(femu_ns_attach(&c, buf, nsid, cntlid, true), ==,
                       NVME_SUCCESS);
    }
    femu_create_io_queues(&c);
    for (ns = 1; ns <= 2; ns++) {
        for (i = 0; i < 512; i++) {
            femu_ns_page(&c, buf, ns, i, ns * 32 + i % 17, true);
        }
    }
    for (ns = 1; ns <= 2; ns++) {
        for (i = 0; i < 512; i++) {
            femu_ns_page(&c, buf, ns, i, ns * 32 + i % 17, false);
        }
    }
    /* Every original line mixes cold pages with pages invalidated below. */
    for (pass = 0; pass < 8; pass++) {
        for (ns = 1; ns <= 2; ns++) {
            for (i = 0; i < 512; i += 2) {
                femu_ns_page(&c, buf, ns, i, ns * 64 + pass, true);
            }
        }
    }
    g_assert_cmpint(FEMU_SC(femu_get_log(&c, FEMU_LOG_FEMU_STATS, buf,
                                         512, 0)), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(qts, buf + 16), >, 0);
    for (ns = 1; ns <= 2; ns++) {
        for (i = 0; i < 512; i++) {
            femu_ns_page(&c, buf, ns, i,
                         i % 2 ? ns * 32 + i % 17 : ns * 64 + 7, false);
        }
    }
    g_assert_cmpint(femu_format(&c, 1, 0, 1), ==, NVME_SUCCESS);
    for (i = 0; i < 512; i++) {
        femu_ns_page(&c, buf, 1, i, 0, false);
        femu_ns_page(&c, buf, 2, i,
                     i % 2 ? 64 + i % 17 : 135, false);
    }
    femu_ns_page(&c, buf, 1, 0, 0xa5, true);
    femu_ns_page(&c, buf, 1, 0, 0xa5, false);
    g_assert_cmpint(femu_ns_delete(&c, 1), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_create(&c, buf, 4096, 0, &nsid), ==, NVME_SUCCESS);
    g_assert_cmpuint(nsid, ==, 1);
    g_assert_cmpint(femu_ns_attach(&c, buf, 1, cntlid, true), ==, NVME_SUCCESS);
    femu_ns_page(&c, buf, 1, 0, 0, false);
    femu_ns_page(&c, buf, 2, 0, 135, false);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    guest_free(alloc, buf);
    qpci_unplug_acpi_device_test(qts, "ns-test", 4);
}

static void femu_test_ns_mgmt_format_detached(void *obj, void *data,
                                              QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint32_t nsid;

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_ns_delete(&c, 1), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_create(&c, buf, 16, 0, &nsid), ==, NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_format(&c, nsid, 1, 0)), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_identify(&c, nsid, 0x11, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readb(qts, buf + 26), ==, 1);
    g_assert_cmpuint(qtest_readq(qts, buf), ==, 8);
    g_assert_cmpint(FEMU_SC(femu_format(&c, 0xffffffff, 0, 0)), ==,
                   NVME_SUCCESS);
    g_assert_cmpint(femu_identify(&c, nsid, 0x11, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readb(qts, buf + 26), ==, 1);
    g_assert_cmpuint(qtest_readq(qts, buf), ==, 8);
    g_assert_cmpint(femu_identify(&c, 0, 2, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 0);
    g_assert_cmpint(FEMU_SC(femu_format(&c, 0, 0, 0)), ==, NVME_INVALID_NSID);
    g_assert_cmpint(FEMU_SC(femu_format(&c, 2, 0, 0)), ==, NVME_INVALID_FIELD);
    g_assert_cmpint(FEMU_SC(femu_format(&c, 256, 0, 0)), ==,
                   NVME_INVALID_FIELD);
    g_assert_cmpint(FEMU_SC(femu_format(&c, 257, 0, 0)), ==, NVME_INVALID_NSID);
    g_assert_cmpint(femu_ns_delete(&c, nsid), ==, NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_format(&c, nsid, 0, 0)), ==,
                   NVME_INVALID_FIELD);
    femu_disable(&c);
    guest_free(alloc, buf);
}

static void femu_test_ns_mgmt_unallocated(void *obj, void *data,
                                          QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint32_t ids[] = { 1, 256, 0, 257, 0xfffffffe };
    uint16_t cntlid;
    uint16_t status;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);
    cntlid = qtest_readw(qts, buf + 78);
    g_assert_cmpint(femu_ns_delete(&c, 1), ==, NVME_SUCCESS);
    for (i = 0; i < ARRAY_SIZE(ids); i++) {
        status = i < 2 ? NVME_INVALID_FIELD : NVME_INVALID_NSID;
        if (data) {
            g_assert_cmpint(femu_ns_attach(&c, buf, ids[i], cntlid, true),
                           ==, status);
            g_assert_cmpint(femu_ns_attach(&c, buf, ids[i], cntlid, false),
                           ==, status);
        } else {
            g_assert_cmpint(femu_ns_delete(&c, ids[i]), ==, status);
        }
    }
    g_assert_cmpint(femu_ns_attach(&c, buf, 0xffffffff, cntlid, true), ==,
                   NVME_INVALID_NSID);
    g_assert_cmpint(femu_ns_delete(&c, 0xffffffff), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_delete(&c, 0xffffffff), ==, NVME_SUCCESS);
    femu_disable(&c);
    guest_free(alloc, buf);
}

static void femu_test_ns_mgmt_validation(void *obj, void *data,
                                         QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint32_t nsid;
    NvmeCmd cmd = { 0 };

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_ns_create(&c, buf, 8, 0, &nsid), ==, 0x115);
    g_assert_cmpint(femu_get_log(&c, 1, buf, 64, 0), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(qts, buf + 32), ==, 4096);
    g_assert_cmpint(femu_ns_delete(&c, 0xffffffff), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_create(&c, buf, 0, 0, &nsid), ==,
                   NVME_INVALID_FIELD);
    g_assert_cmpint(femu_ns_create(&c, buf, UINT64_MAX, 0, &nsid), ==,
                   NVME_INVALID_FIELD);
    g_assert_cmpint(femu_ns_create(&c, buf, 8, 15, &nsid), ==, 0x10a);
    g_assert_cmpint(femu_ns_create(&c, buf, 8, 0, &nsid), ==, NVME_SUCCESS);
    cmd.opcode = 0x0d;
    cmd.dptr.prp1 = cpu_to_le64(buf);
    qtest_writeq(qts, buf + 8, 4);
    g_assert_cmpint(FEMU_SC(femu_admin(&c, &cmd)), ==, 0x11b);
    qtest_writeq(qts, buf + 8, 0);
    g_assert_cmpint(FEMU_SC(femu_admin(&c, &cmd)), ==, NVME_INVALID_FIELD);
    qtest_writeq(qts, buf + 8, 8);
    qtest_writeb(qts, buf + 29, 1);
    g_assert_cmpint(FEMU_SC(femu_admin(&c, &cmd)), ==, 0x10a);
    qtest_writeb(qts, buf + 29, 0);
    qtest_writeb(qts, buf + 30, 1);
    g_assert_cmpint(FEMU_SC(femu_admin(&c, &cmd)), ==, NVME_INVALID_FIELD);
    qtest_writeb(qts, buf + 30, 0);
    qtest_writel(qts, buf + 92, 1);
    g_assert_cmpint(FEMU_SC(femu_admin(&c, &cmd)), ==, 0x124);
    qtest_writel(qts, buf + 92, 0);
    qtest_writew(qts, buf + 100, 1);
    g_assert_cmpint(FEMU_SC(femu_admin(&c, &cmd)), ==, NVME_INVALID_FIELD);
    qtest_writew(qts, buf + 100, 0);
    qtest_writew(qts, buf + 102, 1);
    g_assert_cmpint(FEMU_SC(femu_admin(&c, &cmd)), ==, NVME_INVALID_FIELD);
    qtest_writew(qts, buf + 102, 0);
    cmd.cdw11 = cpu_to_le32(2u << 24);
    g_assert_cmpint(FEMU_SC(femu_admin(&c, &cmd)), ==, 0x129);
    cmd.cdw11 = 0;
    cmd.cdw10 = cpu_to_le32(2);
    g_assert_cmpint(FEMU_SC(femu_admin(&c, &cmd)), ==, NVME_INVALID_FIELD);
    g_assert_cmpint(femu_ns_attach(&c, buf, 1, 0, false), ==, 0x11a);
    g_assert_cmpint(femu_get_log(&c, 1, buf, 64, 0), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(qts, buf + 32), ==, 2);
    g_assert_cmpint(femu_ns_attach(&c, buf, 1, 1, true), ==, 0x11c);
    g_assert_cmpint(femu_ns_attach(&c, buf, 1, 0, true), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_attach(&c, buf, 1, 0, true), ==, 0x118);
    qtest_writew(qts, buf, 2);
    qtest_writew(qts, buf + 4, 0);
    cmd.opcode = 0x15;
    cmd.nsid = cpu_to_le32(1);
    cmd.cdw10 = cpu_to_le32(1);
    g_assert_cmpint(FEMU_SC(femu_admin(&c, &cmd)), ==, 0x11c);
    g_assert_cmpint(femu_get_log(&c, 1, buf, 64, 0), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(qts, buf + 32), ==, 4);
    g_assert_cmpint(femu_identify(&c, 0, 2, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 1);
    for (int i = 2; i <= 256; i++) {
        g_assert_cmpint(femu_ns_create(&c, buf, 8, 0, &nsid), ==, NVME_SUCCESS);
        g_assert_cmpuint(nsid, ==, i);
    }
    g_assert_cmpint(femu_ns_create(&c, buf, 8, 0, &nsid), ==, 0x116);
    g_assert_cmpint(femu_identify(&c, 255, 0x10, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 256);
    g_assert_cmpuint(qtest_readl(qts, buf + 4), ==, 0);
    g_assert_cmpint(femu_ns_delete(&c, 1), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_create(&c, buf, 8, 0, &nsid), ==, NVME_SUCCESS);
    g_assert_cmpuint(nsid, ==, 1);
    femu_disable(&c);
    guest_free(alloc, buf);
}

static uint16_t femu_changed_ns_log(FemuCtrlState *c, uint64_t buf, bool rae)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = NVME_ADM_CMD_GET_LOG_PAGE;
    cmd.nsid = cpu_to_le32(0xffffffff);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(4 | (rae ? 1 << 15 : 0) | (1023 << 16));
    return FEMU_SC(femu_admin(c, &cmd));
}

static void femu_no_admin_completion(FemuCtrlState *c)
{
    uint16_t status;

    g_usleep(1000);
    status = qtest_readw(c->pdev->bus->qts,
        c->admin.cq_addr + c->admin.cq_head * sizeof(NvmeCqe) + 14);
    g_assert_cmpint(status & 1, !=, c->admin.phase);
}

static void femu_ns_notice_complete(FemuCtrlState *c, uint16_t want)
{
    uint32_t result;
    uint16_t cid;

    g_assert_cmpint(femu_complete(c, &c->admin, &cid, &result), ==,
                   NVME_SUCCESS);
    g_assert_cmpuint(cid, ==, want);
    g_assert_cmphex(result, ==, 0x040002);
}

static void femu_test_ns_mgmt_notices(void *obj, void *data,
                                      QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint16_t aer;
    uint32_t nsid;

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readl(qts, buf + 92) & 0x100, ==, 0x100);
    g_assert_cmpint(femu_get_log(&c, 0, buf, 1024, 0), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readl(qts, buf + 16) & 1, ==, 1);
    aer = femu_aer(&c);
    g_assert_cmpint(femu_ns_attach(&c, buf, 1, 0, false), ==, NVME_SUCCESS);
    femu_no_admin_completion(&c);
    g_assert_cmpint(femu_changed_ns_log(&c, buf, true), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 1);
    g_assert_cmpint(femu_set_feature(&c, NVME_ASYNCHRONOUS_EVENT_CONF,
                                     false, 0, 1 << 8, NULL), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_attach(&c, buf, 1, 0, true), ==, NVME_SUCCESS);
    femu_ns_notice_complete(&c, aer);
    g_assert_cmpint(femu_changed_ns_log(&c, buf, true), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 1);
    g_assert_cmpint(femu_changed_ns_log(&c, buf, true), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 0);
    aer = femu_aer(&c);
    g_assert_cmpint(femu_ns_attach(&c, buf, 1, 0, false), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_attach(&c, buf, 1, 0, true), ==, NVME_SUCCESS);
    femu_no_admin_completion(&c);
    g_assert_cmpint(femu_changed_ns_log(&c, 0xffffffff00000000ULL, false), ==,
                   NVME_DATA_TRAS_ERROR);
    g_assert_cmpint(FEMU_SC(femu_get_log(&c, 4, buf, 4, 4096)), ==,
                   NVME_INVALID_FIELD);
    femu_no_admin_completion(&c);
    g_assert_cmpint(femu_changed_ns_log(&c, buf, false), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 1);
    g_assert_cmpuint(qtest_readl(qts, buf + 4), ==, 0);
    g_assert_cmpint(femu_format(&c, 1, 1, 0), ==, NVME_SUCCESS);
    femu_ns_notice_complete(&c, aer);
    g_assert_cmpint(femu_changed_ns_log(&c, buf, false), ==, NVME_SUCCESS);
    aer = femu_aer(&c);
    g_assert_cmpint(femu_ns_delete(&c, 1), ==, NVME_SUCCESS);
    femu_no_admin_completion(&c);
    g_assert_cmpint(femu_changed_ns_log(&c, buf, false), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 1);
    g_assert_cmpint(femu_ns_create(&c, buf, 8, 0, &nsid), ==, NVME_SUCCESS);
    femu_no_admin_completion(&c);
    g_assert_cmpint(femu_ns_attach(&c, buf, nsid, 0, true), ==, NVME_SUCCESS);
    femu_ns_notice_complete(&c, aer);
    femu_disable(&c);
    guest_free(alloc, buf);
}

static void femu_test_ns_mgmt_overflow(void *obj, void *data,
                                       QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint8_t bytes[4096];

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_changed_ns_log(&c, buf, false), ==, NVME_SUCCESS);
    femu_ns_fixture(qts, "changed-list-full");
    g_assert_cmpint(femu_ns_attach(&c, buf, 1, 0, false), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_changed_ns_log(&c, buf, true), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, bytes, sizeof(bytes));
    g_assert_cmphex((uint32_t)ldl_le_p(bytes), ==, 0xffffffff);
    for (int i = 4; i < sizeof(bytes); i++) {
        g_assert_cmpuint(bytes[i], ==, 0);
    }
    g_assert_cmpint(femu_changed_ns_log(&c, buf, false), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 0);
    femu_disable(&c);
    guest_free(alloc, buf);
}

static void *femu_ns_subsys_before(GString *cmd_line, void *arg)
{
    g_string_prepend(cmd_line,
        " -device femu-subsys,id=nssub,nqn=nssub,fdp=off ");
    return arg;
}

static void *femu_shared_before(GString *cmd_line, void *arg)
{
    g_string_prepend(cmd_line,
        " -device femu-subsys,id=shared,ns_mgmt=on ");
    return arg;
}

static void femu_shared_add(QTestState *qts, const char *id, int slot,
                            int mode)
{
    QDict *rsp = qtest_qmp(qts,
        "{'execute':'device_add','arguments':{'driver':'femu','id':%s,"
        "'addr':%s,'subsys':'shared','devsz_mb':4,'femu_mode':%d,"
        "'secsz':512,'secs_per_pg':8,'pgs_per_blk':16,'blks_per_pl':80,"
        "'pls_per_lun':1,'luns_per_ch':1,'nchs':1}}",
        id, slot == 5 ? "5" : "6", mode);

    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
}

static void femu_test_shared_lifecycle(void *obj, void *data,
                                       QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    QPCIDevice *pa;
    QPCIDevice *pb;
    FemuCtrlState a = { 0 };
    FemuCtrlState b = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint32_t nsid;

    g_test_message("adding controllers");
    femu_shared_add(qts, "shared-a", 5, 2);
    femu_shared_add(qts, "shared-b", 6, 2);
    pa = qpci_device_find(femu->dev.bus, QPCI_DEVFN(5, 0));
    pb = qpci_device_find(femu->dev.bus, QPCI_DEVFN(6, 0));
    g_test_message("enabling controllers");
    femu_enable(&a, pa, alloc);
    femu_enable(&b, pb, alloc);
    g_test_message("creating queues");
    femu_create_io_queues(&a);
    femu_create_io_queues(&b);
    g_assert_cmpint(femu_identify(&b, 0, 2, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 0);
    g_test_message("deleting namespaces");
    g_assert_cmpint(femu_ns_delete(&a, 0xffffffff), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_create(&a, buf, 2048, 0, &nsid), ==,
                   NVME_SUCCESS);
    g_assert_cmpuint(nsid, ==, 1);
    g_assert_cmpint(femu_ns_create(&b, buf, 2048, 0, &nsid), ==,
                   NVME_SUCCESS);
    g_assert_cmpuint(nsid, ==, 2);
    g_assert_cmpint(femu_ns_attach(&a, buf, 1, 1, true), ==, NVME_SUCCESS);
    femu_ns_page(&b, buf, 1, 0, 0x5a, true);
    femu_ns_page(&b, buf, 1, 0, 0x5a, false);
    g_test_message("deleting namespaces");
    g_assert_cmpint(femu_ns_delete(&a, 0xffffffff), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_identify(&b, 0, 0x10, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 0);
    g_assert_cmpint(femu_identify(&b, 0, 2, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 0);
    g_test_message("disabling controllers");
    femu_disable(&a);
    femu_disable(&b);
    femu_queue_free(&a, &a.io);
    femu_queue_free(&b, &b.io);
    g_test_message("removing controllers");
    qpci_unplug_acpi_device_test(qts, "shared-a", 5);
    qpci_unplug_acpi_device_test(qts, "shared-b", 6);
    g_free(pa);
    g_free(pb);
    guest_free(alloc, buf);
}

static void femu_shared_start(QFemu *femu, QGuestAllocator *alloc,
                               FemuCtrlState *a, FemuCtrlState *b, int mode)
{
    QTestState *qts = femu->dev.bus->qts;
    QPCIDevice *pa;
    QPCIDevice *pb;

    femu_shared_add(qts, "shared-a", 5, mode);
    femu_shared_add(qts, "shared-b", 6, mode);
    pa = qpci_device_find(femu->dev.bus, QPCI_DEVFN(5, 0));
    pb = qpci_device_find(femu->dev.bus, QPCI_DEVFN(6, 0));
    femu_enable(a, pa, alloc);
    femu_enable(b, pb, alloc);
    femu_create_io_queues(a);
    femu_create_io_queues(b);
}

static void femu_shared_stop(FemuCtrlState *a, FemuCtrlState *b)
{
    QTestState *qts = a->pdev->bus->qts;

    femu_disable(a);
    femu_disable(b);
    femu_queue_free(a, &a->io);
    femu_queue_free(b, &b->io);
    qpci_unplug_acpi_device_test(qts, "shared-a", 5);
    qpci_unplug_acpi_device_test(qts, "shared-b", 6);
    g_free(a->pdev);
    g_free(b->pdev);
}

static void femu_shared_ctrl_list(FemuCtrlState *c, uint64_t buf, uint8_t cns,
                                   uint16_t min, uint16_t count,
                                   uint16_t first)
{
    NvmeCmd cmd = { 0 };
    QTestState *qts = c->pdev->bus->qts;

    cmd.opcode = NVME_ADM_CMD_IDENTIFY;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(cns | ((uint32_t)min << 16));
    g_assert_cmpint(femu_admin(c, &cmd), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readw(qts, buf), ==, count);
    if (count) {
        g_assert_cmpuint(qtest_readw(qts, buf + 2), ==, first);
    }
    if (count == 2) {
        g_assert_cmpuint(qtest_readw(qts, buf + 4), ==, 1);
    }
    g_assert_cmpuint(qtest_readw(qts, buf + 2 * (count + 1)), ==, 0);
}

static void femu_test_shared_discovery(void *obj, void *data,
                                       QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState a = { 0 };
    FemuCtrlState b = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint8_t uuid[16];
    uint8_t other[16];
    uint16_t aer;

    femu_shared_start(femu, alloc, &a, &b, 2);
    femu_shared_ctrl_list(&b, buf, 0x12, 0, 1, 0);
    femu_shared_ctrl_list(&a, buf, 0x13, 0, 2, 0);
    femu_shared_ctrl_list(&a, buf, 0x13, 1, 1, 1);
    femu_shared_ctrl_list(&b, buf, 0x13, 2, 0, 0);
    g_assert_cmpint(femu_identify(&a, 1, 3, 0, buf), ==, NVME_SUCCESS);
    qtest_memread(qts, buf + 4, uuid, sizeof(uuid));
    g_assert_cmpint(femu_set_feature(&b, NVME_ASYNCHRONOUS_EVENT_CONF,
                                     false, 0, 1 << 8, NULL), ==, NVME_SUCCESS);
    aer = femu_aer(&b);
    g_assert_cmpint(femu_ns_attach(&a, buf, 1, 1, true), ==, NVME_SUCCESS);
    femu_ns_notice_complete(&b, aer);
    g_assert_cmpint(femu_changed_ns_log(&b, buf, false), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 1);
    femu_shared_ctrl_list(&a, buf, 0x12, 0, 2, 0);
    femu_shared_ctrl_list(&b, buf, 0x12, 1, 1, 1);
    g_assert_cmpint(femu_identify(&b, 1, 3, 0, buf), ==, NVME_SUCCESS);
    qtest_memread(qts, buf + 4, other, sizeof(other));
    g_assert_cmpmem(uuid, sizeof(uuid), other, sizeof(other));
    femu_ns_page(&a, buf, 1, 0, 0xa7, true);
    femu_ns_page(&b, buf, 1, 0, 0xa7, false);
    aer = femu_aer(&b);
    g_assert_cmpint(femu_ns_attach(&a, buf, 1, 1, false), ==, NVME_SUCCESS);
    femu_ns_notice_complete(&b, aer);
    g_assert_cmpint(femu_changed_ns_log(&b, buf, false), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 1);
    femu_shared_ctrl_list(&b, buf, 0x12, 1, 0, 0);
    g_assert_cmpint(femu_ns_attach(&a, buf, 1, 1, true), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_changed_ns_log(&b, buf, false), ==, NVME_SUCCESS);
    aer = femu_aer(&b);
    g_assert_cmpint(femu_ns_delete(&a, 0xffffffff), ==, NVME_SUCCESS);
    femu_ns_notice_complete(&b, aer);
    g_assert_cmpint(femu_changed_ns_log(&b, buf, false), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 1);
    g_assert_cmpint(femu_identify(&b, 1, 0x11, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(qts, buf), ==, 0);
    g_assert_cmpint(femu_identify(&b, 0, 1, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(qts, buf + 296), ==, 4 * 1024 * 1024);
    femu_shared_stop(&a, &b);
    guest_free(alloc, buf);
}

static uint16_t femu_shared_create(FemuCtrlState *c, uint64_t buf,
                                    uint8_t flbas, bool shared, uint32_t *nsid)
{
    QTestState *qts = c->pdev->bus->qts;
    NvmeCmd cmd = { 0 };

    qtest_memset(qts, buf, 0, 4096);
    qtest_writeq(qts, buf, 1024);
    qtest_writeq(qts, buf + 8, 1024);
    qtest_writeb(qts, buf + 26, flbas);
    qtest_writeb(qts, buf + 30, shared);
    cmd.opcode = 0x0d;
    cmd.dptr.prp1 = cpu_to_le64(buf);
    return FEMU_SC(femu_admin_result(c, &cmd, nsid));
}

static void femu_shared_full_cq(FemuCtrlState *c, FemuQueue *sq)
{
    NvmeCmd cmd = { 0 };
    NvmeCqe cqe;
    unsigned waited = 0;

    femu_queue_init(c, sq, 2);
    cmd.opcode = NVME_ADM_CMD_CREATE_SQ;
    cmd.dptr.prp1 = cpu_to_le64(sq->sq_addr);
    cmd.cdw10 = cpu_to_le32(((FEMU_QSIZE - 1) << 16) | 2);
    cmd.cdw11 = cpu_to_le32((1 << 16) | NVME_SQ_PC);
    g_assert_cmpint(femu_admin(c, &cmd), ==, NVME_SUCCESS);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_CMD_FLUSH;
    cmd.nsid = cpu_to_le32(1);
    for (int i = 0; i < FEMU_QSIZE - 1; i++) {
        femu_submit(c, &c->io, &cmd);
    }
    do {
        qtest_memread(c->pdev->bus->qts,
                      c->io.cq_addr + (FEMU_QSIZE - 2) * sizeof(cqe),
                      &cqe, sizeof(cqe));
        g_assert_cmpuint(waited++, <, FEMU_POLL_LIMIT_MS);
        g_usleep(1000);
    } while (!(le16_to_cpu(cqe.status) & 1));
}

static void femu_shared_retired(FemuCtrlState *c)
{
    uint32_t seen = 0;
    uint32_t result;
    uint16_t cid;
    uint16_t status;

    for (int i = 0; i < FEMU_QSIZE - 1; i++) {
        g_assert_cmpint(femu_complete(c, &c->io, NULL, NULL), ==, NVME_SUCCESS);
    }
    for (int i = 0; i < 9; i++) {
        status = femu_complete(c, &c->io, &cid, &result);
        g_assert_cmpuint(cid, >=, 0x8000);
        g_assert_cmpuint(cid, <, 0x8009);
        g_assert_cmphex(seen & (1u << (cid - 0x8000)), ==, 0);
        seen |= 1u << (cid - 0x8000);
        g_assert_cmpint(status, ==, cid < 0x8003 ? NVME_INVALID_FIELD :
                       cid == 0x8003 ? NVME_LBA_RANGE : NVME_SUCCESS);
        g_assert_cmpuint(result, ==, cid < 0x8003 ? 0 : 0x100 + cid - 0x8000);
    }
    g_assert_cmphex(seen, ==, 0x1ff);
}

static void femu_test_shared_retire(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c[2] = { 0 };
    FemuQueue sq[2];
    NvmeCqe full[2][FEMU_QSIZE];
    NvmeCqe after[FEMU_QSIZE];
    uint64_t buf = guest_alloc(alloc, 4096);
    uint32_t nsid;
    int mode = GPOINTER_TO_INT(data);

    femu_shared_start(femu, alloc, &c[0], &c[1], mode);
    g_assert_cmpint(femu_ns_delete(&c[0], 0xffffffff), ==, NVME_SUCCESS);
    for (int ns = 1; ns <= 2; ns++) {
        g_assert_cmpint(femu_shared_create(&c[0], buf, 0, true, &nsid), ==,
                       NVME_SUCCESS);
        g_assert_cmpuint(nsid, ==, ns);
        for (int i = 0; i < 2; i++) {
            g_assert_cmpint(femu_ns_attach(&c[0], buf, ns, i, true), ==,
                           NVME_SUCCESS);
            femu_ns_page(&c[i], buf, ns, i, 0x71 + i, true);
        }
    }
    for (int i = 0; i < 2; i++) {
        femu_shared_full_cq(&c[i], &sq[i]);
        qtest_memread(qts, c[i].io.cq_addr, full[i], sizeof(full[i]));
        qtest_qmp_assert_success(qts,
            "{'execute':'qom-set','arguments':{'path':%s,"
            "'property':'x-ns-test','value':'retire'}}",
            i ? "/machine/peripheral/shared-b" :
                "/machine/peripheral/shared-a");
    }
    g_assert_cmpint(femu_ns_delete(&c[0], 1), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_shared_create(&c[0], buf, 1, true, &nsid), ==,
                   NVME_SUCCESS);
    g_assert_cmpuint(nsid, ==, 1);
    for (int i = 0; i < 2; i++) {
        g_assert_cmpint(femu_ns_attach(&c[0], buf, 1, i, true), ==,
                       NVME_SUCCESS);
        qtest_memread(qts, c[i].io.cq_addr, after, sizeof(after));
        g_assert_cmpmem(full[i], sizeof(full[i]), after, sizeof(after));
        femu_shared_retired(&c[i]);
        c[i].lba_size = 1024;
        g_assert_cmpint(femu_rw(&c[i], NVME_CMD_READ, 0, buf), ==,
                       NVME_SUCCESS);
        if (!i) {
            for (int j = 0; j < 4096; j++) {
                g_assert_cmphex(qtest_readb(qts, buf + j), ==, 0);
            }
        }
        femu_ns_page(&c[i], buf, 2, 0, 0x71, false);
        for (int j = 0; j < FEMU_QSIZE; j++) {
            femu_round_trip(&c[i], j);
        }
    }
    femu_queue_free(&c[0], &sq[0]);
    femu_queue_free(&c[1], &sq[1]);
    femu_shared_stop(&c[0], &c[1]);
    guest_free(alloc, buf);
}

static void femu_shared_remove(FemuCtrlState *c, const char *id, int slot)
{
    QTestState *qts = c->pdev->bus->qts;

    femu_disable(c);
    femu_queue_free(c, &c->io);
    qpci_unplug_acpi_device_test(qts, id, slot);
    g_free(c->pdev);
    memset(c, 0, sizeof(*c));
}

static void femu_test_shared_features(void *obj, void *data,
                                      QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState a = { 0 };
    FemuCtrlState b = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint32_t result;

    femu_shared_start(femu, alloc, &a, &b, 2);
    g_assert_cmpint(femu_set_feature(&b, NVME_ERROR_RECOVERY, false,
                                     0xffffffff, 1 << 16, NULL), ==,
                   NVME_SUCCESS);
    g_assert_cmpint(femu_get_feature(&a, NVME_ERROR_RECOVERY, 0, 1, 0,
                                     &result), ==, NVME_SUCCESS);
    g_assert_cmphex(result, ==, 0);
    femu_ns_page(&a, buf, 1, 0, 0, false);
    g_assert_cmpint(femu_ns_attach(&a, buf, 1, 1, true), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_set_feature(&b, NVME_ERROR_RECOVERY, false,
                                     0xffffffff, 1 << 16, NULL), ==,
                   NVME_SUCCESS);
    g_assert_cmpint(femu_get_feature(&a, NVME_ERROR_RECOVERY, 0, 1, 0,
                                     &result), ==, NVME_SUCCESS);
    g_assert_cmphex(result, ==, 1 << 16);
    g_assert_cmphex(femu_rw_ns(&a, NVME_CMD_READ, 1, 0, buf), ==, 0x287);
    g_assert_cmpint(femu_ns_attach(&a, buf, 1, 1, false), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_set_feature(&b, NVME_ERROR_RECOVERY, false,
                                     0xffffffff, 0, NULL), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_get_feature(&a, NVME_ERROR_RECOVERY, 0, 1, 0,
                                     &result), ==, NVME_SUCCESS);
    g_assert_cmphex(result, ==, 1 << 16);
    femu_shared_stop(&a, &b);
    guest_free(alloc, buf);
}

static void femu_check_sanitize(FemuCtrlState *c, uint64_t buf,
                                uint16_t status, uint32_t cdw10)
{
    QTestState *qts = c->pdev->bus->qts;

    g_assert_cmpint(femu_get_log(c, 0x81, buf, 512, 0), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readw(qts, buf), ==, 0xffff);
    g_assert_cmphex(qtest_readw(qts, buf + 2), ==, status);
    g_assert_cmphex(qtest_readl(qts, buf + 4), ==, cdw10);
    for (int i = 8; i < 32; i += 4) {
        g_assert_cmphex(qtest_readl(qts, buf + i), ==, 0xffffffff);
    }
}

static void femu_test_shared_sanitize(void *obj, void *data,
                                      QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState a = { 0 };
    FemuCtrlState b = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    QPCIDevice *pdev;

    femu_shared_start(femu, alloc, &a, &b, 2);
    g_assert_cmpint(femu_ns_attach(&a, buf, 1, 1, true), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_sanitize(&a, 2), ==, NVME_SUCCESS);
    femu_check_sanitize(&a, buf, 0x101, 2);
    femu_check_sanitize(&b, buf, 0x101, 2);
    femu_ns_page(&b, buf, 1, 0, 0x5c, true);
    femu_ns_page(&a, buf, 1, 0, 0x5c, false);
    femu_check_sanitize(&a, buf, 1, 2);
    femu_check_sanitize(&b, buf, 1, 2);
    g_assert_cmpint(femu_ns_attach(&a, buf, 1, 1, false), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_sanitize(&b, 0x202), ==, NVME_SUCCESS);
    femu_ns_page(&a, buf, 1, 0, 0, false);
    femu_check_sanitize(&a, buf, 0x104, 0x202);
    femu_check_sanitize(&b, buf, 0x104, 0x202);
    femu_shared_remove(&a, "shared-a", 5);
    femu_check_sanitize(&b, buf, 0x104, 0x202);
    femu_shared_remove(&b, "shared-b", 6);
    femu_shared_add(qts, "shared-a", 5, 2);
    pdev = qpci_device_find(femu->dev.bus, QPCI_DEVFN(5, 0));
    femu_enable(&a, pdev, alloc);
    femu_create_io_queues(&a);
    femu_check_sanitize(&a, buf, 0x104, 0x202);
    g_assert_cmpint(femu_ns_attach(&a, buf, 1, 0, true), ==, NVME_SUCCESS);
    femu_ns_page(&a, buf, 1, 0, 0, false);
    femu_ns_page(&a, buf, 1, 0, 0x39, true);
    femu_check_sanitize(&a, buf, 4, 0x202);
    femu_shared_remove(&a, "shared-a", 5);
    guest_free(alloc, buf);
}

static void femu_test_shared_remove(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState a = { 0 };
    FemuCtrlState b = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint32_t result;
    uint32_t nsid;
    uint8_t uuid[16];
    uint8_t other[16];
    int mode = GPOINTER_TO_INT(data);
    QPCIDevice *pdev;

    femu_shared_start(femu, alloc, &a, &b, mode);
    g_assert_cmpint(femu_ns_attach(&a, buf, 1, 1, true), ==, NVME_SUCCESS);
    femu_ns_page(&b, buf, 1, 0, 0x5c, true);
    g_assert_cmpint(femu_identify(&b, 1, 3, 0, buf), ==, NVME_SUCCESS);
    qtest_memread(qts, buf + 4, uuid, sizeof(uuid));
    g_assert_cmpint(femu_set_feature(&b, NVME_ERROR_RECOVERY, false, 1,
                                     1 << 16, NULL), ==, NVME_SUCCESS);
    femu_shared_remove(&a, "shared-a", 5);
    g_assert_cmpint(femu_get_feature(&b, NVME_ERROR_RECOVERY, 0, 1, 0,
                                     &result), ==, NVME_SUCCESS);
    g_assert_cmphex(result, ==, 1 << 16);
    femu_ns_page(&b, buf, 1, 0, 0x5c, false);
    g_assert_cmpint(femu_identify(&b, 1, 3, 0, buf), ==, NVME_SUCCESS);
    qtest_memread(qts, buf + 4, other, sizeof(other));
    g_assert_cmpmem(uuid, sizeof(uuid), other, sizeof(other));
    g_assert_cmpint(femu_ns_attach(&b, buf, 1, 1, false), ==, NVME_SUCCESS);
    femu_disable(&b);
    femu_queue_free(&b, &b.io);
    femu_enable(&b, b.pdev, alloc);
    femu_create_io_queues(&b);
    g_assert_cmpint(femu_identify(&b, 0, 2, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 0);
    g_assert_cmpint(femu_ns_attach(&b, buf, 1, 1, true), ==, NVME_SUCCESS);
    femu_ns_page(&b, buf, 1, 0, 0x5c, false);
    femu_shared_remove(&b, "shared-b", 6);

    /* Storage outlives all transports, including its first configuration. */
    femu_shared_add(qts, "shared-a", 5, mode);
    pdev = qpci_device_find(femu->dev.bus, QPCI_DEVFN(5, 0));
    femu_enable(&a, pdev, alloc);
    femu_create_io_queues(&a);
    g_assert_cmpint(femu_ns_attach(&a, buf, 1, 0, true), ==, NVME_SUCCESS);
    femu_ns_page(&a, buf, 1, 0, 0x5c, false);
    g_assert_cmpint(femu_ns_delete(&a, 0xffffffff), ==, NVME_SUCCESS);
    femu_shared_remove(&a, "shared-a", 5);

    /* An empty bbssd pool must still start a worker for future Create. */
    femu_shared_add(qts, "shared-a", 5, mode);
    pdev = qpci_device_find(femu->dev.bus, QPCI_DEVFN(5, 0));
    femu_enable(&a, pdev, alloc);
    femu_create_io_queues(&a);
    g_assert_cmpint(femu_shared_create(&a, buf, 0, true, &nsid), ==,
                   NVME_SUCCESS);
    g_assert_cmpuint(nsid, ==, 1);
    g_assert_cmpint(femu_ns_attach(&a, buf, 1, 0, true), ==, NVME_SUCCESS);
    femu_ns_page(&a, buf, 1, 0, 0, false);
    femu_ns_page(&a, buf, 1, 0, 0x93, true);
    if (mode == 1) {
        g_assert_cmpint(femu_get_log(&a, FEMU_LOG_FEMU_STATS, buf, 512, 0), ==,
                       NVME_SUCCESS);
        g_assert_cmpuint(qtest_readq(qts, buf + 24), >, 0);
    }
    femu_shared_remove(&a, "shared-a", 5);
    qtest_qmp_assert_success(qts,
        "{'execute':'qom-set','arguments':{'path':'/machine/peripheral/shared',"
        "'property':'realized','value':false}}");
    guest_free(alloc, buf);
}

static void femu_test_shared_private(void *obj, void *data,
                                     QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState a = { 0 };
    FemuCtrlState b = { 0 };
    NvmeCmd cmd = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint32_t nsid;

    femu_shared_start(femu, alloc, &a, &b, 2);
    g_assert_cmpint(femu_ns_delete(&a, 0xffffffff), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_shared_create(&a, buf, 0, false, &nsid), ==,
                   NVME_SUCCESS);
    g_assert_cmpint(femu_identify(&b, 1, 0x11, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, buf + 30), ==, 0);
    g_assert_cmpint(femu_ns_attach(&a, buf, 1, 1, true), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_attach(&b, buf, 1, 0, true), ==, NVME_NS_PRIVATE);
    femu_shared_ctrl_list(&a, buf, 0x12, 0, 1, 1);
    g_assert_cmpint(femu_ns_attach(&a, buf, 1, 1, false), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_attach(&b, buf, 1, 0, true), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_delete(&a, 1), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_shared_create(&a, buf, 0, true, &nsid), ==,
                   NVME_SUCCESS);
    qtest_memset(qts, buf, 0, 4096);
    qtest_writew(qts, buf, 2);
    qtest_writew(qts, buf + 2, 0);
    qtest_writew(qts, buf + 4, 7);
    cmd.opcode = 0x15;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    g_assert_cmpint(FEMU_SC(femu_admin(&a, &cmd)), ==, 0x11c);
    femu_shared_ctrl_list(&b, buf, 0x12, 0, 0, 0);
    qtest_memset(qts, buf, 0, 4096);
    qtest_writew(qts, buf, 2);
    qtest_writew(qts, buf + 2, 0);
    qtest_writew(qts, buf + 4, 1);
    g_assert_cmpint(femu_admin(&b, &cmd), ==, NVME_SUCCESS);
    femu_shared_ctrl_list(&b, buf, 0x12, 0, 2, 0);
    femu_ns_page(&a, buf, 1, 0, 0x39, true);
    femu_ns_page(&b, buf, 1, 0, 0x39, false);
    femu_shared_stop(&a, &b);
    guest_free(alloc, buf);
}

static void femu_test_shared_admin(void *obj, void *data,
                                   QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState a = { 0 };
    FemuCtrlState b = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint8_t serial[20];
    uint8_t other[20];
    char nqn[256];
    uint16_t aer;

    femu_shared_start(femu, alloc, &a, &b, 1);
    g_assert_cmpint(femu_identify(&a, 0, 1, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, buf + 76) & 2, ==, 2);
    qtest_memread(qts, buf + 4, serial, sizeof(serial));
    qtest_memread(qts, buf + 768, nqn, sizeof(nqn));
    g_assert_cmpstr(nqn, ==, "nqn.2019-08.org.qemu:shared");
    g_assert_cmpint(femu_identify(&b, 0, 1, 0, buf), ==, NVME_SUCCESS);
    qtest_memread(qts, buf + 4, other, sizeof(other));
    g_assert_cmpmem(serial, sizeof(serial), other, sizeof(other));
    qtest_memread(qts, buf + 768, nqn, sizeof(nqn));
    g_assert_cmpstr(nqn, ==, "nqn.2019-08.org.qemu:shared");
    g_assert_cmpint(femu_ns_attach(&a, buf, 1, 1, true), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_changed_ns_log(&b, buf, false), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_set_feature(&b, NVME_ASYNCHRONOUS_EVENT_CONF,
                                     false, 0, 1 << 8, NULL), ==, NVME_SUCCESS);
    femu_ns_page(&b, buf, 1, 0, 0x71, true);
    aer = femu_aer(&b);
    g_assert_cmpint(femu_format(&a, 1, 1, 0), ==, NVME_SUCCESS);
    femu_ns_notice_complete(&b, aer);
    g_assert_cmpint(femu_changed_ns_log(&b, buf, false), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 1);
    g_assert_cmpint(femu_identify(&b, 1, 0, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readb(qts, buf + 26), ==, 1);
    b.lba_size = 1024;
    femu_round_trip(&b, 0x19);
    g_assert_cmpint(femu_format(&a, 1, 0, 0), ==, NVME_SUCCESS);
    femu_ns_page(&b, buf, 1, 0, 0, false);
    femu_shared_stop(&a, &b);
    guest_free(alloc, buf);
}

static void femu_test_shared_subsys_release(void *obj, void *data,
                                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState a = { 0 };
    FemuCtrlState b = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);

    femu_shared_start(femu, alloc, &a, &b, 1);
    g_assert_cmpint(femu_ns_attach(&a, buf, 1, 1, true), ==, NVME_SUCCESS);
    femu_ns_page(&b, buf, 1, 0, 0x57, true);
    qtest_qmp_assert_success(qts,
        "{'execute':'qom-set','arguments':{'path':'/machine/peripheral/shared',"
        "'property':'realized','value':false}}");
    femu_ns_page(&b, buf, 1, 0, 0x57, false);
    femu_shared_remove(&a, "shared-a", 5);
    femu_ns_page(&b, buf, 1, 0, 0x57, false);
    femu_shared_remove(&b, "shared-b", 6);
    guest_free(alloc, buf);
}

static void femu_test_ns_mgmt_subsys(void *obj, void *data,
                                     QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    const char *subsystems[] = { "nssub", "fdpsub" };
    QDict *rsp;
    int i;

    for (i = 0; i < ARRAY_SIZE(subsystems); i++) {
        rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                        "'driver':'femu','id':'rejected','addr':'5',"
                        "'devsz_mb':1,'femu_mode':2,'ns_mgmt':true,"
                        "'subsys':%s}}", subsystems[i]);
        g_assert_true(qdict_haskey(rsp, "error"));
        g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                             "desc"),
                               "ns_mgmt=on does not support subsys"));
        qobject_unref(rsp);
    }
}

/*
 * The broadcast Identify Namespace reports what every namespace can be
 * formatted or created with (NVM 1.2, Figure 114), protection included.
 */
static void femu_test_ns_mgmt_common_dpc(void *obj, void *data,
                                         QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint8_t dpc;

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_identify(&c, 1, 0, 0, buf), ==, NVME_SUCCESS);
    dpc = qtest_readb(qts, buf + 28);
    g_assert_cmpint(dpc, ==, 0x1f);
    g_assert_cmpint(femu_identify(&c, NVME_NSID_BROADCAST, 0, 0, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(qtest_readb(qts, buf + 28), ==, dpc);
    femu_disable(&c);
    guest_free(alloc, buf);
}

static void femu_test_ns_mgmt_identify_csi_common(void *obj, void *data,
                                                  QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint8_t common[4096];
    uint8_t zero[4096] = { 0 };

    femu_enable(&c, &femu->dev, alloc);
    /* Common NVM capabilities must also be available without namespaces. */
    for (int i = 0; i < 3; i++) {
        qtest_memset(qts, buf, 0xa5, sizeof(common));
        g_assert_cmpint(femu_identify(&c, 0xffffffff, 5, 0, buf), ==,
                       NVME_SUCCESS);
        qtest_memread(qts, buf, common, sizeof(common));
        g_assert_cmpmem(common, sizeof(common), zero, sizeof(zero));
        g_assert_cmpint(femu_identify(&c, 0xffffffff, 5,
                                     FEMU_CSI_ZONED << 24, buf), ==,
                       NVME_INVALID_FIELD);
        if (i == 0) {
            g_assert_cmpint(femu_ns_attach(&c, buf, 1, 0, false), ==,
                           NVME_SUCCESS);
        } else if (i == 1) {
            g_assert_cmpint(femu_ns_delete(&c, 1), ==, NVME_SUCCESS);
        }
    }
    g_assert_cmpint(femu_identify(&c, 0, 5, 0, buf), ==, NVME_INVALID_NSID);
    g_assert_cmpint(femu_identify(&c, 257, 5, 0, buf), ==, NVME_INVALID_NSID);
    femu_disable(&c);
    guest_free(alloc, buf);
}

static void femu_test_ns_mgmt_identify(void *obj, void *data,
                                       QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint8_t common[4096];
    uint16_t cntlid;

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_identify(&c, 0xffffffff, 0, 0, buf), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, common, sizeof(common));
    g_assert_cmpuint(ldq_le_p(common), ==, 0);
    g_assert_cmpuint(ldq_le_p(common + 8), ==, 0);
    g_assert_cmpuint(common[25], ==, 4);
    g_assert_cmpuint(common[26], ==, 0);
    g_assert_cmpuint(common[130], ==, 9);
    g_assert_cmpuint(common[146], ==, 13);
    g_assert_cmpint(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);
    cntlid = qtest_readw(qts, buf + 78);
    g_assert_cmpuint(cntlid, ==, 0);
    g_assert_cmpint(femu_identify(&c, 1, 0x12, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readw(qts, buf), ==, 1);
    g_assert_cmpuint(qtest_readw(qts, buf + 2), ==, cntlid);
    g_assert_cmpint(femu_identify(&c, 1, 0x12 | cntlid << 16, 0, buf), ==,
                   NVME_SUCCESS);
    g_assert_cmpuint(qtest_readw(qts, buf), ==, 1);
    g_assert_cmpint(femu_identify(&c, 1, 0x12 | (cntlid + 1) << 16, 0, buf), ==,
                   NVME_SUCCESS);
    g_assert_cmpuint(qtest_readw(qts, buf), ==, 0);
    g_assert_cmpint(femu_identify(&c, 0, 0x13, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readw(qts, buf), ==, 1);
    g_assert_cmpuint(qtest_readw(qts, buf + 2), ==, 0);
    g_assert_cmpint(femu_identify(&c, 0, 0x13 | cntlid << 16, 0, buf), ==,
                   NVME_SUCCESS);
    g_assert_cmpuint(qtest_readw(qts, buf), ==, 1);
    g_assert_cmpuint(qtest_readw(qts, buf + 2), ==, cntlid);
    g_assert_cmpint(femu_ns_attach(&c, buf, 1, cntlid, false), ==,
                   NVME_SUCCESS);
    g_assert_cmpint(femu_identify(&c, 1, 0x12, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readw(qts, buf), ==, 0);
    g_assert_cmpint(femu_ns_attach(&c, buf, 1, cntlid, true), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_delete(&c, 0xffffffff), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_identify(&c, 0xffffffff, 0, 0, buf), ==, NVME_SUCCESS);
    for (int i = 0; i < sizeof(common); i++) {
        g_assert_cmpuint(qtest_readb(qts, buf + i), ==, common[i]);
    }
    g_assert_cmpint(femu_identify(&c, 1, 0x12, 0, buf), ==, NVME_INVALID_FIELD);
    g_assert_cmpint(femu_identify(&c, 256, 0x11, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(qts, buf), ==, 0);
    g_assert_cmpint(femu_identify(&c, 257, 0x11, 0, buf), ==,
                   NVME_INVALID_NSID);
    g_assert_cmpint(femu_identify(&c, 0xffffffff, 0x11, 0, buf), ==,
                   NVME_INVALID_NSID);
    g_assert_cmpint(femu_identify(&c, 0xfffffffe, 0x10, 0, buf), ==,
                   NVME_INVALID_NSID);
    g_assert_cmpint(femu_identify(&c, 0xffffffff, 0x12, 0, buf), ==,
                   NVME_INVALID_FIELD);
    g_assert_cmpint(femu_get_log(&c, FEMU_LOG_CMD_EFFECTS, buf, 4096, 0), ==,
                   NVME_SUCCESS);
    g_assert_cmphex(qtest_readl(qts, buf + 4 * 0x0d), ==, 0x0b);
    g_assert_cmphex(qtest_readl(qts, buf + 4 * 0x15), ==, 0x09);
    femu_disable(&c);
    guest_free(alloc, buf);
}

static void femu_test_ns_mgmt_default(void *obj, void *data,
                                      QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QDict *rsp = qtest_qmp(femu->dev.bus->qts,
        "{'execute':'qom-get','arguments':{"
        "'path':'/machine/peripheral/ns-test','property':'ns_mgmt'}}");
    FemuCtrlState c = { 0 };
    NvmeCmd cmd = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);

    g_assert_true(qdict_haskey(rsp, "return"));
    g_assert_false(qdict_get_bool(rsp, "return"));
    qobject_unref(rsp);
    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readw(c.pdev->bus->qts, buf + 256) & 8, ==, 0);
    g_assert_cmpuint(qtest_readl(c.pdev->bus->qts, buf + 516), ==, 1);
    cmd.opcode = 0x0d;
    g_assert_cmpint(FEMU_SC(femu_admin(&c, &cmd)), ==, NVME_INVALID_OPCODE);
    cmd.opcode = 0x15;
    g_assert_cmpint(FEMU_SC(femu_admin(&c, &cmd)), ==, NVME_INVALID_OPCODE);
    g_assert_cmpint(femu_identify(&c, 0xffffffff, 0, 0, buf), ==,
                   NVME_INVALID_NSID);
    g_assert_cmpint(femu_identify(&c, 0xffffffff, 5, 0, buf), ==,
                   NVME_INVALID_NSID);
    guest_free(alloc, buf);
    femu_disable(&c);
}

static void femu_test_namespace_mixed_identity(void *obj, void *data,
                                                QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    char serial[21] = { 0 };

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);
    qtest_memread(c.pdev->bus->qts, buf + 4, serial, 20);
    g_strchomp(serial);
    g_assert_cmpstr(serial, ==, "vCSD0");
    femu_disable(&c);
    guest_free(alloc, buf);
}

static void femu_test_namespace_failed_identity(void *obj, void *data,
                                                 QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    QPCIDevice *pdev;
    QDict *rsp;
    uint64_t buf = guest_alloc(alloc, 4096);
    char serial[21] = { 0 };
    char nqn[256];

    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'rejected','addr':'5',"
                    "'devsz_mb':64,'femu_mode':1,'secsz':0}}");
    g_assert_true(qdict_haskey(rsp, "error"));
    qobject_unref(rsp);
    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'rejected-mixed','addr':'5',"
                    "'devsz_mb':64,'femu_mode':1,'namespaces':2,"
                    "'namespace_modes':'bbssd,csd',"
                    "'secs_per_pg':8,'pgs_per_blk':16,'blks_per_pl':80,"
                    "'pls_per_lun':1,'luns_per_ch':4,'nchs':4}}");
    g_assert_true(qdict_haskey(rsp, "error"));
    qobject_unref(rsp);
    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'accepted','addr':'5',"
                    "'devsz_mb':64,'femu_mode':1,'namespaces':2,"
                    "'secs_per_pg':8,'pgs_per_blk':16,'blks_per_pl':80,"
                    "'pls_per_lun':1,'luns_per_ch':4,'nchs':4}}");
    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
    pdev = qpci_device_find(femu->dev.bus, QPCI_DEVFN(5, 0));
    g_assert_nonnull(pdev);
    femu_enable(&c, pdev, alloc);
    g_assert_cmpint(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);
    qtest_memread(qts, buf + 4, serial, 20);
    g_strchomp(serial);
    g_assert_cmpstr(serial, ==, "vSSD2");
    qtest_memread(qts, buf + 768, nqn, sizeof(nqn));
    g_assert_cmpstr(nqn, ==, "nqn.2021-05.org.femu:vSSD2");
    femu_disable(&c);
    guest_free(alloc, buf);
    g_free(pdev);
    qos_invalidate_command_line();
}

static void femu_test_namespace_kv_byte_capacity(void *obj, void *data,
                                                 QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    QPCIDevice *pdev;
    QDict *rsp;
    uint64_t buf = guest_alloc(alloc, 4096);
    uint64_t capacity;

    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'kv-bytes','addr':'5',"
                    "'devsz_mb':8,'femu_mode':5,'nlbaf':16,'lba_index':15,"
                    "'secsz':512,'secs_per_pg':8,'pgs_per_blk':16,"
                    "'blks_per_pl':80,'pls_per_lun':1,'luns_per_ch':1,"
                    "'nchs':1}}");
    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
    pdev = qpci_device_find(femu->dev.bus, QPCI_DEVFN(5, 0));
    g_assert_nonnull(pdev);
    femu_enable(&c, pdev, alloc);
    g_assert_cmpint(femu_identify(&c, 1, 5, FEMU_CSI_KV << 24, buf), ==,
                   NVME_SUCCESS);
    capacity = qtest_readq(qts, buf);
    g_assert_cmpuint(capacity, >, 0);
    g_assert_cmpuint(capacity, <=, 5 * 1024 * 1024);
    g_assert_cmpuint(qtest_readq(qts, buf + 16), ==, 0);
    femu_disable(&c);
    guest_free(alloc, buf);
    g_free(pdev);
    qos_invalidate_command_line();
}

/*
 * A namespace slice smaller than one block realizes as an empty namespace,
 * as it always has, rather than refusing the device.
 */
static void femu_test_namespace_empty_slice(void *obj, void *data,
                                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    QPCIDevice *pdev;
    QDict *rsp;
    uint64_t buf = guest_alloc(alloc, 4096);

    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'empty-slice','addr':'5',"
                    "'devsz_mb':64,'femu_mode':2,'namespace_sizes':'512',"
                    "'lba_index':3}}");
    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
    pdev = qpci_device_find(femu->dev.bus, QPCI_DEVFN(5, 0));
    g_assert_nonnull(pdev);
    femu_enable(&c, pdev, alloc);
    g_assert_cmpint(femu_identify(&c, 1, 0, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(qts, buf), ==, 0);             /* NSZE */
    femu_disable(&c);
    guest_free(alloc, buf);
    g_free(pdev);
    qos_invalidate_command_line();
}

/* Preserve the legacy mode initializers' identity consumption. */
static void femu_test_namespace_failure_naming(void *obj, void *data,
                                                QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    bool partial = GPOINTER_TO_UINT(data);
    const char *expected = partial ? "vNoSSD2" : "vZNSSD1";
    QPCIDevice *pdev;
    QDict *rsp;
    uint64_t buf = guest_alloc(alloc, 4096);
    char serial[21] = { 0 };
    char nqn[256];
    char padded[21];
    g_autofree char *name = NULL;
    g_autofree char *expected_nqn = NULL;
    GChecksum *ck;
    uint8_t digest[32];
    uint8_t uuid[16];
    gsize len = sizeof(digest);

    if (partial) {
        /* The graph consumed 0; namespace 1 consumes 1 before 2 fails. */
        rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                        "'driver':'femu','id':'rejected','addr':'5',"
                        "'devsz_mb':64,'femu_mode':2,'namespaces':2,"
                        "'namespace_modes':'nossd,bbssd','secsz':0}}");
    } else {
        /* ZNS names the controller before discovering missing MLC timing. */
        rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                        "'driver':'femu','id':'rejected','addr':'5',"
                        "'devsz_mb':64,'femu_mode':3,'zns_flash_type':2}}");
    }
    g_assert_true(qdict_haskey(rsp, "error"));
    qobject_unref(rsp);
    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'accepted','addr':'5',"
                    "'devsz_mb':64,'femu_mode':%u}}", partial ? 2 : 3);
    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
    pdev = qpci_device_find(femu->dev.bus, QPCI_DEVFN(5, 0));
    g_assert_nonnull(pdev);
    femu_enable(&c, pdev, alloc);
    g_assert_cmpint(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);
    qtest_memread(qts, buf + 4, serial, 20);
    g_strchomp(serial);
    g_assert_cmpstr(serial, ==, expected);
    qtest_memread(qts, buf + 768, nqn, sizeof(nqn));
    expected_nqn = g_strdup_printf("nqn.2021-05.org.femu:%s", expected);
    g_assert_cmpstr(nqn, ==, expected_nqn);

    snprintf(padded, sizeof(padded), "%-20s", expected);
    name = g_strdup_printf("%s:1", padded);
    ck = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(ck, (const guchar *)name, strlen(name));
    g_checksum_get_digest(ck, digest, &len);
    g_checksum_free(ck);
    digest[6] = (digest[6] & 0x0f) | 0x80;
    digest[8] = (digest[8] & 0x3f) | 0x80;
    g_assert_cmpint(femu_identify(&c, 1, 3, 0, buf), ==, NVME_SUCCESS);
    qtest_memread(qts, buf + 4, uuid, sizeof(uuid));
    g_assert_cmpmem(uuid, sizeof(uuid), digest, sizeof(uuid));
    femu_disable(&c);
    guest_free(alloc, buf);
    g_free(pdev);
    qos_invalidate_command_line();
}

static void femu_ns_fixture(QTestState *qts, const char *value)
{
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-set', 'arguments':{"
                          "'path':'/machine/peripheral/ns-test',"
                          "'property':'x-ns-test','value':%s}}", value);

    if (qdict_haskey(rsp, "error")) {
        g_test_message("namespace fixture: %s",
                       qdict_get_str(qdict_get_qdict(rsp, "error"), "desc"));
    }
    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
    qos_invalidate_command_line();
}

static void femu_test_namespace_large(void *obj, void *data,
                                      QGuestAllocator *alloc)
{
    QFemu *femu = obj;

    femu_ns_fixture(femu->dev.bus->qts, "check-large-namespace");
}

static void femu_ns_make_sparse(FemuCtrlState *c, uint64_t buf)
{
    uint32_t nsid;
    int i;

    g_assert_cmpint(femu_ns_delete(c, 0xffffffff), ==, NVME_SUCCESS);
    for (i = 1; i <= 256; i++) {
        g_assert_cmpint(femu_ns_create(c, buf, 8, 0, &nsid), ==, NVME_SUCCESS);
        g_assert_cmpuint(nsid, ==, i);
    }
    for (i = 2; i < 256; i++) {
        g_assert_cmpint(femu_ns_delete(c, i), ==, NVME_SUCCESS);
    }
    g_assert_cmpint(femu_ns_attach(c, buf, 256, 0, true), ==, NVME_SUCCESS);
}

static void femu_test_namespace_copy_source(void *obj, void *data,
                                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    bool detached = data != NULL;
    uint32_t source = detached ? 1 : 256;
    uint32_t dest = detached ? 256 : 1;
    uint8_t bytes[4096];
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_ns_make_sparse(&c, buf);
    g_assert_cmpint(femu_ns_attach(&c, buf, 1, 0, true), ==, NVME_SUCCESS);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0, 512);
    qtest_writew(qts, buf + 4, 4);
    g_assert_cmpint(femu_hbs(&c, true, buf), ==, NVME_SUCCESS);
    qtest_memset(qts, buf, 0x5a, 4096);
    g_assert_cmpint(femu_rw_ns(&c, NVME_CMD_WRITE, source, 0, buf), ==,
                   NVME_SUCCESS);
    if (detached) {
        g_assert_cmpint(femu_ns_attach(&c, buf, source, 0, false), ==,
                       NVME_SUCCESS);
        g_assert_cmpint(femu_rw_ns(&c, NVME_CMD_READ, source, 0, buf), ==,
                       NVME_INVALID_FIELD);
    }
    qtest_memset(qts, list, 0, 4096);
    qtest_writel(qts, list, source);
    qtest_writew(qts, list + 16, 7);
    cmd.opcode = FEMU_CMD_COPY;
    cmd.nsid = cpu_to_le32(dest);
    cmd.dptr.prp1 = cpu_to_le64(list);
    cmd.cdw12 = cpu_to_le32(2 << 8);
    g_assert_cmpint(femu_io(&c, &cmd), ==,
                   detached ? NVME_INVALID_NSID : NVME_SUCCESS);
    g_assert_cmpint(femu_rw_ns(&c, NVME_CMD_READ, dest, 0, buf), ==,
                   NVME_SUCCESS);
    qtest_memread(qts, buf, bytes, sizeof(bytes));
    for (i = 0; i < sizeof(bytes); i++) {
        g_assert_cmpuint(bytes[i], ==, detached ? 0 : 0x5a);
    }
    femu_disable(&c);
    guest_free(alloc, buf);
    guest_free(alloc, list);
}

static void femu_test_namespace_sanitize_bounds(void *obj, void *data,
                                                QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);

    femu_ns_fixture(qts, "seed-sanitize");
    femu_enable(&c, &femu->dev, alloc);
    if (data) {
        g_assert_cmpint(femu_ns_delete(&c, 1), ==, NVME_SUCCESS);
        g_assert_cmpint(femu_ns_attach(&c, buf, 2, 0, false), ==,
                       NVME_SUCCESS);
    }
    g_assert_cmpint(femu_sanitize(&c, 2), ==, NVME_SUCCESS);
    femu_disable(&c);
    femu_ns_fixture(qts, "check-sanitize");
    guest_free(alloc, buf);
}

static void femu_test_namespace_sanitize_free(void *obj, void *data,
                                              QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x5a, 4096);
    g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE, 0, buf), ==, NVME_SUCCESS);
    femu_queue_free(&c, &c.io);
    g_assert_cmpint(femu_ns_delete(&c, 0xffffffff), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_sanitize(&c, 2), ==, NVME_SUCCESS);
    femu_disable(&c);
    femu_ns_fixture(qts, "check-erased");
    guest_free(alloc, buf);
}

static void femu_test_namespace_lifecycle(void *obj, void *data,
                                          QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint8_t bytes[1024];
    uint32_t nsid;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x5a, 4096);
    g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_delete(&c, 1), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_create(&c, buf, 3, 1, &nsid), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_attach(&c, buf, 1, 0, true), ==, NVME_SUCCESS);
    cmd.opcode = NVME_CMD_READ;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    femu_submit(&c, &c.io, &cmd);
    g_assert_cmpint(femu_complete(&c, &c.io, NULL, NULL), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, bytes, sizeof(bytes));
    for (i = 0; i < sizeof(bytes); i++) {
        g_assert_cmpuint(bytes[i], ==, 0);
    }
    femu_queue_free(&c, &c.io);
    g_assert_cmpint(femu_ns_delete(&c, 0xffffffff), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_delete(&c, 0xffffffff), ==, NVME_SUCCESS);
    femu_ns_fixture(qts, "fail-create");
    g_assert_cmpint(femu_ns_create(&c, buf, 3, 1, &nsid), ==,
                   NVME_INTERNAL_DEV_ERROR);
    g_assert_cmpint(femu_identify(&c, 0, 2, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 0);
    g_assert_cmpint(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(qts, buf + 280), ==, 64 * 1024 * 1024);
    g_assert_cmpuint(qtest_readq(qts, buf + 296), ==, 64 * 1024 * 1024);
    g_assert_cmpint(femu_format(&c, 0xffffffff, 0, 0), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_sanitize(&c, 2), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_create(&c, buf, 3, 1, &nsid), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_attach(&c, buf, 1, 0, true), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_identify(&c, 1, 0, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(qts, buf), ==, 3);
    femu_disable(&c);
    guest_free(alloc, buf);
    qpci_unplug_acpi_device_test(qts, "ns-test", 4);
}

static void femu_test_namespace_capacity(void *obj, void *data,
                                         QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);

    uint32_t nsid;

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_ns_delete(&c, 1), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_create(&c, buf, 3, 1, &nsid), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_attach(&c, buf, 1, 0, true), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_identify(&c, 1, 0, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readb(qts, buf + 26), ==, 1);
    g_assert_cmpuint(qtest_readq(qts, buf), ==, 3);
    g_assert_cmpint(femu_format(&c, 1, 0, 0), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_identify(&c, 1, 0, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(qts, buf), ==, 6);
    femu_disable(&c);
    guest_free(alloc, buf);
}

static void femu_test_namespace_identity(void *obj, void *data,
                                         QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint8_t before[4096];
    uint8_t after[4096];
    uint8_t uuid[4096];
    uint8_t replaced[4096];
    uint8_t created[4096];
    uint16_t cntlid;
    uint32_t nsid;
    int i;
    uint64_t buf = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, before, sizeof(before));
    cntlid = qtest_readw(qts, buf + 78);
    g_assert_cmpint(femu_identify(&c, 1, 3, 0, buf), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, uuid, sizeof(uuid));
    g_assert_cmpint(femu_identify(&c, 2, 3, 0, buf), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, replaced, sizeof(replaced));
    g_assert_cmpint(femu_ns_delete(&c, 2), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_create(&c, buf, 8, 0, &nsid), ==, NVME_SUCCESS);
    g_assert_cmpuint(nsid, ==, 2);
    g_assert_cmpint(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, after, sizeof(after));
    g_assert_cmpmem(before + 4, 20, after + 4, 20);
    g_assert_cmpmem(before + 24, 40, after + 24, 40);
    g_assert_cmpmem(before + 768, 256, after + 768, 256);
    g_assert_cmpint(femu_identify(&c, 1, 3, 0, buf), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, after, sizeof(after));
    g_assert_cmpmem(uuid, sizeof(uuid), after, sizeof(after));
    for (i = 0; i < 2; i++) {
        g_assert_cmpint(femu_ns_attach(&c, buf, nsid, cntlid, true), ==,
                       NVME_SUCCESS);
        g_assert_cmpint(femu_identify(&c, nsid, 3, 0, buf), ==, NVME_SUCCESS);
        qtest_memread(qts, buf, created, sizeof(created));
        g_assert_cmpint(memcmp(replaced + 4, created + 4, 16), !=, 0);
        g_assert_cmpint(femu_ns_attach(&c, buf, nsid, cntlid, false), ==,
                       NVME_SUCCESS);
        femu_disable(&c);
        femu_enable(&c, &femu->dev, alloc);
        g_assert_cmpint(femu_ns_attach(&c, buf, nsid, cntlid, true), ==,
                       NVME_SUCCESS);
        g_assert_cmpint(femu_identify(&c, nsid, 3, 0, buf), ==, NVME_SUCCESS);
        qtest_memread(qts, buf, after, sizeof(after));
        g_assert_cmpmem(created, sizeof(created), after, sizeof(after));
        femu_disable(&c);
        femu_enable(&c, &femu->dev, alloc);
        g_assert_cmpint(femu_identify(&c, nsid, 3, 0, buf), ==, NVME_SUCCESS);
        qtest_memread(qts, buf, after, sizeof(after));
        g_assert_cmpmem(created, sizeof(created), after, sizeof(after));
        memcpy(replaced, created, sizeof(replaced));
        g_assert_cmpint(femu_ns_delete(&c, nsid), ==, NVME_SUCCESS);
        g_assert_cmpint(femu_ns_create(&c, buf, 8, 0, &nsid), ==, NVME_SUCCESS);
        g_assert_cmpuint(nsid, ==, 2);
    }
    femu_disable(&c);
    guest_free(alloc, buf);
}

static void femu_test_namespace_allocated(void *obj, void *data,
                                          QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    femu_ns_make_sparse(&c, buf);
    g_assert_cmpint(femu_identify(&c, 0, 0x10, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 1);
    g_assert_cmpuint(qtest_readl(qts, buf + 4), ==, 256);
    g_assert_cmpuint(qtest_readl(qts, buf + 8), ==, 0);
    g_assert_cmpint(femu_identify(&c, 1, 0x11, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(qts, buf), >, 0);
    g_assert_cmpint(femu_identify(&c, 2, 0x11, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(qts, buf), ==, 0);
    g_assert_cmpint(femu_identify(&c, 0, 0x1a, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 1);
    g_assert_cmpuint(qtest_readl(qts, buf + 4), ==, 256);
    g_assert_cmpint(femu_identify(&c, 0, 7, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 256);
    g_assert_cmpint(FEMU_SC(femu_identify(&c, 1, 0x1b,
                                         FEMU_CSI_ZONED << 24,
                                         buf)), ==, NVME_INVALID_FIELD);
    g_assert_cmpint(femu_identify(&c, 1, 5, FEMU_CSI_ZONED << 24, buf), ==,
                   NVME_SUCCESS);
    femu_disable(&c);
    guest_free(alloc, buf);
}

static void femu_test_namespace_sparse(void *obj, void *data,
                                       QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd = { 0 };
    uint32_t result;
    uint64_t buf = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    femu_ns_make_sparse(&c, buf);
    femu_create_io_queues(&c);
    g_assert_cmpint(femu_identify(&c, 0, 2, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 256);
    g_assert_cmpuint(qtest_readl(qts, buf + 4), ==, 0);
    g_assert_cmpint(femu_identify(&c, 1, 0, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(qts, buf), ==, 0);
    g_assert_cmpint(femu_identify(&c, 2, 0, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(qts, buf), ==, 0);
    g_assert_cmpint(femu_identify(&c, 256, 0, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(qts, buf), >, 0);
    cmd.opcode = NVME_CMD_READ;
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.nsid = cpu_to_le32(1);
    femu_submit(&c, &c.io, &cmd);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, NULL, NULL)), ==,
                   NVME_INVALID_FIELD);
    cmd.nsid = cpu_to_le32(2);
    femu_submit(&c, &c.io, &cmd);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, NULL, NULL)), ==,
                   NVME_INVALID_FIELD);
    cmd.nsid = cpu_to_le32(256);
    femu_submit(&c, &c.io, &cmd);
    g_assert_cmpint(femu_complete(&c, &c.io, NULL, NULL), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_set_feature(&c, NVME_ERROR_RECOVERY, false,
                                     0xffffffff, 7, NULL), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_get_feature(&c, NVME_ERROR_RECOVERY, 0, 256, 0,
                                     &result), ==, NVME_SUCCESS);
    g_assert_cmpuint(result, ==, 7);
    g_assert_cmpint(femu_format(&c, 0xffffffff, 1, 0), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_sanitize(&c, 2), ==, NVME_SUCCESS);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_identify(&c, 0, 2, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 256);
    femu_disable(&c);
    guest_free(alloc, buf);
    qpci_unplug_acpi_device_test(qts, "ns-test", 4);
}

/*
 * Persistent Event log (Base 2.3, 5.2.12.1.14): advertised in LPA, PELS and
 * the supported pages; each action's rules for the reporting context; the
 * context is a snapshot, newest event first; Reporting Context Information
 * says whether one existed before the command; a Controller Level Reset
 * releases the context and is itself an event.
 */
static void femu_test_pel(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t mem, buf, ts;
    uint8_t sn[20], hdr_sn[20];
    uint32_t tnev;
    uint16_t gnum;

    femu_enable(&c, &femu->dev, alloc);
    mem = guest_alloc(alloc, 3 * 4096);
    buf = (mem + 4095) & ~4095ULL;
    ts = buf + 8192;

    g_assert_cmpint(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpint(qtest_readb(qts, buf + 261) & (1 << 4), !=, 0);
    g_assert_cmpuint(qtest_readl(qts, buf + 352), ==, 1);
    qtest_memread(qts, buf + 4, sn, sizeof(sn));
    g_assert_cmpint(FEMU_SC(femu_get_log(&c, 0x00, buf, 1024, 0)), ==,
                    NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf + 4 * FEMU_LOG_PEL), ==,
                     1 | 1 << 16);

    g_assert_cmpint(femu_get_log(&c, 2, buf, 512, 0), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(qts, buf + 112), ==, 0);

    /* no context yet: reading needs one */
    g_assert_cmpint(femu_pel(&c, 0, buf, 4096, 0), ==, FEMU_CMD_SEQ_ERROR);

    /* power on logged a reset event, then a SMART snapshot after it */
    g_assert_cmpint(femu_pel(&c, 1, buf, 4096, 0), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(qts, buf + 44), ==, 1);
    g_assert_cmpint(qtest_readb(qts, buf), ==, FEMU_LOG_PEL);
    tnev = qtest_readl(qts, buf + 4);
    g_assert_cmpuint(tnev, >=, 2);
    g_assert_cmpuint(qtest_readq(qts, buf + 8), >, 512);
    g_assert_cmpint(qtest_readb(qts, buf + 16), ==, 3);
    g_assert_cmpint(qtest_readw(qts, buf + 18), ==, 512 - 20);
    qtest_memread(qts, buf + 56, hdr_sn, sizeof(hdr_sn));
    g_assert_cmpint(memcmp(hdr_sn, sn, sizeof(sn)), ==, 0);
    gnum = qtest_readw(qts, buf + 372);
    g_assert_cmpuint(qtest_readl(qts, buf + 374), ==, 0);   /* new context */
    /* Change Namespace support follows the namespace management opt-in. */
    g_assert_cmpint(qtest_readb(qts, buf + 480), ==, data ? 0xfa : 0xba);
    g_assert_cmpint(qtest_readb(qts, buf + 481), ==, 0x1f);
    g_assert_cmpint(femu_pel_event(qts, buf, 0), ==, 0x01);
    g_assert_cmpint(femu_pel_event(qts, buf, 1), ==, 0x04);
    g_assert_cmpint(qtest_readb(qts, buf + 512 + 3) & 3, ==, 3);
    g_assert_cmpint(qtest_readw(qts, buf + 512 + 22), ==, 512);

    g_assert_cmpint(femu_pel(&c, 1, buf, 4096, 0), ==, FEMU_CMD_SEQ_ERROR);

    /* an event logged now is kept but not in the context being read */
    qtest_writeq(qts, ts, 0x0123456789abULL);
    g_assert_cmpint(femu_timestamp(&c, true, 0, 0, ts), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_pel(&c, 0, buf, 4096, 0), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf + 4), ==, tnev);
    g_assert_cmpuint(qtest_readl(qts, buf + 374), ==, 1 << 18 | 1 << 16);

    /* header only, with the length and offset ignored */
    qtest_memset(qts, buf, 0xff, 1024);
    g_assert_cmpint(femu_pel(&c, 3, buf, 4, 3), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf + 4), ==, tnev);
    g_assert_cmpuint(qtest_readl(qts, buf + 374), ==, 1 << 18 | 1 << 16);
    g_assert_cmpint(qtest_readb(qts, buf + 512), ==, 0xff);

    /* but not the offset type bit, which a page without indexes refuses */
    {
        NvmeCmd cmd = { 0 };

        cmd.opcode = NVME_ADM_CMD_GET_LOG_PAGE;
        cmd.nsid = cpu_to_le32(NVME_NSID_BROADCAST);
        cmd.dptr.prp1 = cpu_to_le64(buf);
        cmd.cdw10 = cpu_to_le32(FEMU_LOG_PEL | 3 << 8 | 127 << 16);
        cmd.cdw14 = cpu_to_le32(1 << 23);
        g_assert_cmpint(FEMU_SC(femu_admin(&c, &cmd)), ==, NVME_INVALID_FIELD);
        cmd.cdw10 = cpu_to_le32(FEMU_LOG_PEL | 2 << 8);
        g_assert_cmpint(FEMU_SC(femu_admin(&c, &cmd)), ==, NVME_INVALID_FIELD);
    }

    /* release ignores them too, and releasing twice is not an error */
    g_assert_cmpint(femu_pel(&c, 2, 0, 4, 3), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_pel(&c, 2, 0, 4, 3), ==, NVME_SUCCESS);

    /* a new context reports the timestamp change, newest first */
    g_assert_cmpint(femu_pel(&c, 3, buf, 4096, 0), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf + 374), ==, 0);
    g_assert_cmpuint(qtest_readw(qts, buf + 372), ==, (uint16_t)(gnum + 1));
    g_assert_cmpint(femu_pel(&c, 0, buf, 4096, 0), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf + 4), ==, tnev + 1);
    g_assert_cmpint(femu_pel_event(qts, buf, 0), ==, 0x03);
    g_assert_cmpuint(qtest_readq(qts, buf + 512 + 24) & ((1ULL << 48) - 1),
                     <, 0x0123456789abULL);

    /* a reset drops the context and logs itself, then a snapshot */
    femu_disable(&c);
    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_pel(&c, 0, buf, 4096, 0), ==, FEMU_CMD_SEQ_ERROR);
    g_assert_cmpint(femu_pel(&c, 1, buf, 4096, 0), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf + 4), ==, tnev + 3);
    g_assert_cmpint(femu_pel_event(qts, buf, 0), ==, 0x01);
    g_assert_cmpint(femu_pel_event(qts, buf, 1), ==, 0x04);
    g_assert_cmpint(femu_pel_event(qts, buf, 2), ==, 0x03);
    g_assert_cmpint(femu_pel(&c, 2, 0, 4, 0), ==, NVME_SUCCESS);

    guest_free(alloc, mem);
    femu_disable(&c);
}

/* the offset of the i'th event reported, counting from the newest */
static uint64_t femu_pel_at(QTestState *qts, uint64_t buf, int i)
{
    uint64_t e = buf + 512;

    while (i--) {
        e += 3 + qtest_readb(qts, e + 2) + qtest_readw(qts, e + 22);
    }
    return e;
}

/* how many of the events in the first 4 KiB of a context have this type */
static int femu_pel_count(QTestState *qts, uint64_t buf, uint8_t et,
                          uint16_t code)
{
    uint32_t tnev = qtest_readl(qts, buf + 4);
    int i, count = 0;

    for (i = 0; i < tnev; i++) {
        uint64_t e = femu_pel_at(qts, buf, i);

        if (e + 28 > buf + 4096) {
            break;
        }
        if (qtest_readb(qts, e) == et &&
            (et != 0x05 || qtest_readw(qts, e + 24) == code)) {
            count++;
        }
    }
    return count;
}

static void femu_power_cut(FemuCtrlState *c)
{
    QDict *response = qtest_qmp(c->pdev->bus->qts,
        "{'execute':'qom-set', 'arguments':{'path':'/machine/peripheral/power',"
        "'property':'simulate-power-loss', 'value':true}}");

    g_assert_true(qdict_haskey(response, "return"));
    qobject_unref(response);
    femu_queue_free(c, &c->io);
    femu_disable(c);
    femu_enable(c, c->pdev, c->alloc);
    femu_create_io_queues(c);
}

static void femu_power_write(FemuCtrlState *c, uint64_t buf, uint32_t nsid,
                              uint64_t lba, uint16_t nlb, uint8_t pattern,
                              bool fua)
{
    NvmeRwCmd rw = { 0 };

    qtest_memset(c->pdev->bus->qts, buf, pattern, nlb * 512);
    rw.opcode = NVME_CMD_WRITE;
    rw.nsid = cpu_to_le32(nsid);
    rw.dptr.prp1 = cpu_to_le64(buf);
    rw.slba = cpu_to_le64(lba);
    rw.nlb = cpu_to_le16(nlb - 1);
    rw.control = cpu_to_le16(fua ? NVME_RW_FUA : 0);
    g_assert_cmpint(femu_io(c, (NvmeCmd *)&rw), ==, NVME_SUCCESS);
}

static void femu_power_read(FemuCtrlState *c, uint64_t buf, uint32_t nsid,
                             uint64_t lba, uint8_t pattern)
{
    NvmeRwCmd rw = { 0 };
    uint8_t bytes[512];

    rw.opcode = NVME_CMD_READ;
    rw.nsid = cpu_to_le32(nsid);
    rw.dptr.prp1 = cpu_to_le64(buf);
    rw.slba = cpu_to_le64(lba);
    g_assert_cmpint(femu_io(c, (NvmeCmd *)&rw), ==, NVME_SUCCESS);
    qtest_memread(c->pdev->bus->qts, buf, bytes, sizeof(bytes));
    for (int i = 0; i < sizeof(bytes); i++) {
        g_assert_cmphex(bytes[i], ==, pattern);
    }
}

static void femu_power_flush(FemuCtrlState *c, uint32_t nsid)
{
    NvmeCmd cmd = { .opcode = NVME_CMD_FLUSH, .nsid = cpu_to_le32(nsid) };

    g_assert_cmpint(femu_io(c, &cmd), ==, NVME_SUCCESS);
}

/* Bound the QMP wait even if the device holds up the main loop. */
typedef struct FemuPowerDeadline {
    GMutex lock;
    GCond cond;
    bool done;
} FemuPowerDeadline;

static void *femu_power_deadline(void *opaque)
{
    FemuPowerDeadline *d = opaque;
    gint64 end = g_get_monotonic_time() + 10 * G_TIME_SPAN_SECOND;

    g_mutex_lock(&d->lock);
    while (!d->done) {
        if (!g_cond_wait_until(&d->cond, &d->lock, end)) {
            g_error("power cut did not return within ten seconds");
        }
    }
    g_mutex_unlock(&d->lock);
    return NULL;
}

static void femu_test_power_mmio_cut(void *obj, void *data,
                                      QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    NvmeRwCmd rw = { .opcode = NVME_CMD_WRITE, .nsid = cpu_to_le32(1),
                     .nlb = cpu_to_le16(7),
                     .dptr.prp1 = cpu_to_le64(0xfed00000) };

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    for (int cut = 0; cut < 16; cut++) {
        FemuPowerDeadline d = { 0 };
        GThread *watchdog;

        femu_power_read(&c, buf, 1, 0, 0);
        g_mutex_init(&d.lock);
        g_cond_init(&d.cond);
        watchdog = g_thread_new("power-cut-timeout", femu_power_deadline, &d);
        for (int i = 0; i < 14; i++) {
            femu_submit(&c, &c.io, (NvmeCmd *)&rw);
        }
        femu_power_cut(&c);
        g_mutex_lock(&d.lock);
        d.done = true;
        g_cond_signal(&d.cond);
        g_mutex_unlock(&d.lock);
        g_thread_join(watchdog);
        g_cond_clear(&d.cond);
        g_mutex_clear(&d.lock);
        femu_power_read(&c, buf, 1, 0, 0);
    }
    g_assert_cmphex(FEMU_SC(femu_io(&c, (NvmeCmd *)&rw)), ==,
                   NVME_DATA_TRAS_ERROR);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static void femu_test_power_dma_pointers(void *obj, void *data,
                                          QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 12288);
    uint64_t list = guest_alloc(alloc, 4096);
    const uint8_t ops[] = { NVME_CMD_WRITE, NVME_CMD_READ, NVME_CMD_COMPARE };

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    for (int op = 0; op < ARRAY_SIZE(ops); op++) {
        for (int kind = 0; kind < 8; kind++) {
            NvmeRwCmd rw = { .opcode = ops[op], .nsid = cpu_to_le32(1) };
            NvmeSglDescriptor desc[2] = { 0 };
            NvmeSglDescriptor seg = { 0 };

            qtest_memset(qts, buf, 0xa5, 12288);
            rw.dptr.prp1 = cpu_to_le64(0xfed00000);
            if (kind == 1) {
                /* A valid first page must not move before PRP2 is checked. */
                rw.nlb = cpu_to_le16(15);
                rw.dptr.prp1 = cpu_to_le64(buf);
                rw.dptr.prp2 = cpu_to_le64(0xfed00000);
            } else if (kind == 2 || kind == 3) {
                rw.nlb = cpu_to_le16(23);
                rw.dptr.prp1 = cpu_to_le64(buf);
                rw.dptr.prp2 = cpu_to_le64(0xfed00000);
                if (kind == 3) {
                    /* The last entry chains to an MMIO-resident list. */
                    qtest_writeq(qts, list + 4088, 0xfed00000);
                    rw.dptr.prp2 = cpu_to_le64(list + 4088);
                }
            } else if (kind >= 4) {
                rw.flags = 1 << 6;
                seg.addr = cpu_to_le64(0xfed00000);
                seg.len = cpu_to_le32(512);
                if (kind == 5) {
                    rw.nlb = cpu_to_le16(1);
                    desc[0].addr = cpu_to_le64(buf);
                    desc[0].len = cpu_to_le32(512);
                    desc[1] = seg;
                    qtest_memwrite(qts, list, desc, sizeof(desc));
                    seg.addr = cpu_to_le64(list);
                    seg.len = cpu_to_le32(sizeof(desc));
                    seg.type = NVME_SGL_DESCR_TYPE_LAST_SEGMENT << 4;
                } else if (kind == 6) {
                    seg.len = cpu_to_le32(sizeof(desc));
                    seg.type = NVME_SGL_DESCR_TYPE_LAST_SEGMENT << 4;
                } else if (kind == 7) {
                    /* A single descriptor crosses from RAM into VGA MMIO. */
                    rw.nlb = cpu_to_le16(1);
                    seg.addr = cpu_to_le64(0x9fe00);
                    seg.len = cpu_to_le32(1024);
                }
                memcpy(&rw.dptr.sgl, &seg, sizeof(seg));
            }
            g_test_message("opcode 0x%x, pointer case %d", ops[op], kind);
            g_assert_cmphex(FEMU_SC(femu_io(&c, (NvmeCmd *)&rw)), ==,
                           NVME_DATA_TRAS_ERROR);
            if (ops[op] == NVME_CMD_READ) {
                uint8_t bytes[4096];

                qtest_memread(qts, buf, bytes, sizeof(bytes));
                for (int i = 0; i < sizeof(bytes); i++) {
                    g_assert_cmphex(bytes[i], ==, 0xa5);
                }
            }
        }
    }
    for (int op = 0; op < 2; op++) {
        NvmeCmd cmd = { .opcode = op ? FEMU_CMD_COPY : NVME_CMD_DSM,
                       .nsid = cpu_to_le32(1),
                       .dptr.prp1 = cpu_to_le64(0xfed00000),
                       .cdw11 = cpu_to_le32(op ? 0 : FEMU_DSM_AD) };

        g_assert_cmphex(FEMU_SC(femu_io(&c, &cmd)), ==, NVME_DATA_TRAS_ERROR);
    }
    femu_power_cut(&c);
    femu_power_read(&c, buf, 1, 0, 0);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static void femu_test_power_cmb(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    QPCIBar cmb;
    uint64_t buf = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    cmb = qpci_iomap(&femu->dev, 2, NULL);
    femu_power_write(&c, cmb.addr, 1, 0, 8, 0x5a, false);
    g_assert_cmphex(femu_rw(&c, NVME_CMD_COMPARE, 0, cmb.addr), ==,
                   NVME_SUCCESS);
    femu_power_read(&c, cmb.addr, 1, 0, 0x5a);
    femu_power_cut(&c);
    femu_power_read(&c, buf, 1, 0, 0);
    femu_power_write(&c, cmb.addr, 1, 0, 8, 0x6b, true);
    femu_power_cut(&c);
    femu_power_read(&c, cmb.addr, 1, 0, 0x6b);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static void femu_test_power_no_drain(void *obj, void *data,
                                      QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    int action = GPOINTER_TO_INT(data);
    uint16_t status;
    uint16_t expected = NVME_SUCCESS;
    NvmeDsmRange ranges[2] = {
        { .nlb = cpu_to_le32(1), .slba = cpu_to_le64(8) },
        { .nlb = cpu_to_le32(1), .slba = cpu_to_le64(UINT64_MAX) },
    };
    NvmeCmd cmd = { .nsid = cpu_to_le32(1),
                    .dptr.prp1 = cpu_to_le64(list) };
    uint64_t src = 0;
    uint16_t nlb = 1;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_power_write(&c, buf, 1, 0, 8, 0x5a, false);
    switch (action) {
    case 0:
        cmd.opcode = 0x7f;
        expected = NVME_INVALID_OPCODE;
        status = femu_io(&c, &cmd);
        break;
    case 1:
        status = femu_lba_cmd(&c, NVME_CMD_VERIFY, 0, 8);
        break;
    case 2:
    case 3:
    case 6:
    case 9:
        cmd.opcode = NVME_CMD_DSM;
        if (action != 2) {
            cmd.cdw11 = cpu_to_le32(FEMU_DSM_AD);
        }
        if (action == 3) {
            ranges[0].nlb = 0;
        } else if (action == 6) {
            cmd.cdw10 = cpu_to_le32(1);
            expected = NVME_LBA_RANGE;
        } else if (action == 9) {
            cmd.dptr.prp1 = cpu_to_le64(0xfed00000);
            expected = NVME_DATA_TRAS_ERROR;
        }
        qtest_memwrite(c.pdev->bus->qts, list, ranges, sizeof(ranges));
        status = femu_io(&c, &cmd);
        break;
    case 4:
    case 5:
        status = femu_lba_cmd(&c, action == 4 ? NVME_CMD_WRITE_ZEROES :
                             NVME_CMD_WRITE_UNCOR, UINT64_MAX, 1);
        expected = NVME_LBA_RANGE;
        break;
    case 7:
    case 8:
        if (action == 8) {
            src = UINT64_MAX;
        }
        status = femu_copy(&c, list, 0, &src, &nlb, 1, 1, 0);
        expected = action == 7 ? FEMU_OVERLAP_IO_RANGE : NVME_LBA_RANGE;
        break;
    case 10:
        status = femu_format(&c, 1, 0, 2);
        expected = NVME_INVALID_FIELD;
        break;
    case 11:
    case 12:
        status = femu_sanitize(&c, action == 11 ? 1 : 0);
        expected = action == 11 ? NVME_SUCCESS : NVME_INVALID_FIELD;
        break;
    case 13:
        status = femu_rw(&c, NVME_CMD_COMPARE, 0, buf);
        break;
    default:
        g_assert_not_reached();
    }
    g_assert_cmphex(FEMU_SC(status), ==, expected);
    femu_power_cut(&c);
    femu_power_read(&c, buf, 1, 0, 0);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static void femu_test_power_mutation(void *obj, void *data,
                                      QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    int action = GPOINTER_TO_INT(data);
    NvmeRwCmd rw = { .opcode = NVME_CMD_WRITE_ZEROES,
                     .nsid = cpu_to_le32(1), .slba = cpu_to_le64(8) };
    NvmeDsmRange range = { .nlb = cpu_to_le32(1), .slba = cpu_to_le64(8) };
    NvmeCmd cmd = { .opcode = NVME_CMD_DSM, .nsid = cpu_to_le32(1),
                    .cdw11 = cpu_to_le32(FEMU_DSM_AD),
                    .dptr.prp1 = cpu_to_le64(list) };
    uint64_t src = 0;
    uint16_t nlb = 1;
    uint64_t programmed;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_power_write(&c, buf, 1, 0, 8, 0x5a, false);
    femu_power_write(&c, buf, 2, 0, 8, 0x6b, false);
    g_assert_cmpint(femu_get_log(&c, FEMU_LOG_FEMU_STATS, list, 512, 0), ==,
                   NVME_SUCCESS);
    programmed = qtest_readq(c.pdev->bus->qts, list + 24);
    switch (action) {
    case 0:
    case 1:
    case 2:
        if (action == 1) {
            rw.control = cpu_to_le16(1 << 9);
        } else if (action == 2) {
            rw.opcode = NVME_CMD_WRITE_UNCOR;
        }
        g_assert_cmphex(femu_io(&c, (NvmeCmd *)&rw), ==, NVME_SUCCESS);
        break;
    case 3:
        qtest_memwrite(c.pdev->bus->qts, list, &range, sizeof(range));
        g_assert_cmphex(femu_io(&c, &cmd), ==, NVME_SUCCESS);
        break;
    case 4:
        g_assert_cmphex(femu_copy(&c, list, 8, &src, &nlb, 1, 1, 0), ==,
                       NVME_SUCCESS);
        break;
    case 5:
        g_assert_cmphex(femu_format(&c, 1, 0, 0), ==, NVME_SUCCESS);
        break;
    case 6:
        g_assert_cmphex(femu_sanitize(&c, 2), ==, NVME_SUCCESS);
        break;
    default:
        g_assert_not_reached();
    }
    /* Erase hides the drained bytes; the media counter still proves a drain. */
    g_assert_cmpint(femu_get_log(&c, FEMU_LOG_FEMU_STATS, list, 512, 0), ==,
                   NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(c.pdev->bus->qts, list + 24), >, programmed);
    femu_power_cut(&c);
    femu_power_read(&c, buf, 1, 0, action >= 5 ? 0 : 0x5a);
    femu_power_read(&c, buf, 2, 0, 0);
    if (action == 2) {
        g_assert_cmphex(FEMU_SC(femu_rw(&c, NVME_CMD_READ, 8, buf)), ==,
                       NVME_UNRECOVERED_READ);
    } else {
        femu_power_read(&c, buf, 1, 8, action == 4 ? 0x5a : 0);
    }
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static void femu_test_power_loss(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    /* Old bytes and untouched neighbors must survive partial overwrites. */
    femu_power_write(&c, buf, 1, 0, 8, 0x31, true);
    femu_power_write(&c, buf, 1, 2, 1, 0x5a, false);
    femu_power_write(&c, buf, 1, 4, 1, 0x6b, false);
    femu_power_write(&c, buf, 1, 8, 1, 0x7c, false);
    femu_power_read(&c, buf, 1, 2, 0x5a);
    femu_power_read(&c, buf, 1, 4, 0x6b);
    femu_power_cut(&c);
    for (int i = 0; i < 8; i++) {
        femu_power_read(&c, buf, 1, i, 0x31);
    }
    femu_power_read(&c, buf, 1, 8, 0);
    femu_power_read(&c, buf, 1, 9, 0);
    /* Recovery may accept another dirty write to the same page. */
    femu_power_write(&c, buf, 1, 2, 1, 0x8d, false);
    femu_power_cut(&c);
    femu_power_read(&c, buf, 1, 2, 0x31);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static void femu_test_power_durable(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    bool fua = GPOINTER_TO_INT(data);

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_power_write(&c, buf, 1, 0, 8, 0x31, false);
    femu_power_write(&c, buf, 1, 8, 8, 0x42, fua);
    if (!fua) {
        femu_power_flush(&c, 1);
    }
    /* A write after the durability command must remain independently dirty. */
    femu_power_write(&c, buf, 1, 9, 1, 0x53, false);
    femu_power_cut(&c);
    femu_power_read(&c, buf, 1, 0, fua ? 0 : 0x31);
    femu_power_read(&c, buf, 1, 8, 0x42);
    femu_power_read(&c, buf, 1, 9, 0x42);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static void femu_test_power_destage(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    /* A one-page cache must program its old page to admit a new page. */
    femu_power_write(&c, buf, 1, 0, 8, 0x31, false);
    femu_power_write(&c, buf, 1, 8, 8, 0x42, false);
    femu_power_cut(&c);
    femu_power_read(&c, buf, 1, 0, 0x31);
    femu_power_read(&c, buf, 1, 8, 0);
    guest_free(alloc, buf);
    buf = guest_alloc(alloc, 8192);
    qtest_memset(c.pdev->bus->qts, buf, 0x53, 8192);
    /* Admission must also work within a request larger than the cache. */
    g_assert_cmpint(femu_write_8k(&c, buf, 16, 16), ==, NVME_SUCCESS);
    femu_power_cut(&c);
    femu_power_read(&c, buf, 1, 16, 0x53);
    femu_power_read(&c, buf, 1, 23, 0x53);
    femu_power_read(&c, buf, 1, 24, 0);
    femu_power_read(&c, buf, 1, 31, 0);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static void femu_test_power_cache_off(void *obj, void *data,
                                      QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_power_write(&c, buf, 1, 0, 8, 0x31, false);
    if (data) {
        QDict *response = qtest_qmp(c.pdev->bus->qts,
            "{'execute':'qom-set', 'arguments':{'path':'/machine/peripheral/power',"
            "'property':'simulate-power-loss', 'value':true}}");

        g_assert_true(qdict_haskey(response, "error"));
        qobject_unref(response);
    } else {
        femu_power_cut(&c);
    }
    femu_power_read(&c, buf, 1, 0, 0x31);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static void femu_test_power_namespaces(void *obj, void *data,
                                       QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_power_write(&c, buf, 1, 0, 8, 0x31, false);
    femu_power_write(&c, buf, 2, 0, 8, 0x42, false);
    femu_power_flush(&c, 2);
    femu_power_cut(&c);
    femu_power_read(&c, buf, 1, 0, 0);
    femu_power_read(&c, buf, 2, 0, 0x42);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static void femu_test_power_lifecycle(void *obj, void *data,
                                      QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    int action = GPOINTER_TO_INT(data);

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_power_write(&c, buf, 1, 0, 8, 0x31, false);
    if (action == 0) {
        g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_VOLATILE_WRITE_CACHE,
                                               false, 0, 0, NULL)), ==,
                       NVME_SUCCESS);
        /* Disabling the cache must also commit earlier writes. */
    } else if (action == 1) {
        uint32_t cc = qpci_io_readl(c.pdev, c.bar, 0x14);

        qpci_io_writel(c.pdev, c.bar, 0x14, cc | (1 << 14));
        g_assert_cmphex(qpci_io_readl(c.pdev, c.bar, 0x1c) & (3 << 2), ==,
                       NVME_CSTS_SHST_COMPLETE);
    } else {
        /* A controller reset alone neither loses nor commits dirty data. */
        femu_queue_free(&c, &c.io);
        femu_disable(&c);
        femu_enable(&c, &femu->dev, alloc);
        femu_create_io_queues(&c);
        femu_power_read(&c, buf, 1, 0, 0x31);
    }
    femu_power_cut(&c);
    femu_power_read(&c, buf, 1, 0, action == 2 ? 0 : 0x31);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static void femu_test_power_validity(void *obj, void *data,
                                     QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    NvmeDsmRange range = { .nlb = cpu_to_le32(1), .slba = cpu_to_le64(2) };
    NvmeCmd cmd = { .opcode = NVME_CMD_DSM, .nsid = cpu_to_le32(1),
                   .cdw11 = cpu_to_le32(FEMU_DSM_AD) };

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_power_write(&c, buf, 1, 0, 8, 0x31, false);
    qtest_memwrite(c.pdev->bus->qts, buf, &range, sizeof(range));
    cmd.dptr.prp1 = cpu_to_le64(buf);
    g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_SUCCESS);
    femu_power_write(&c, buf, 1, 2, 1, 0x42, false);
    femu_power_cut(&c);
    femu_power_read(&c, buf, 1, 1, 0x31);
    femu_power_read(&c, buf, 1, 2, 0);
    femu_power_read(&c, buf, 1, 3, 0x31);

    g_assert_cmpint(femu_lba_cmd(&c, NVME_CMD_WRITE_ZEROES, 0, 8), ==,
                   NVME_SUCCESS);
    femu_power_write(&c, buf, 1, 0, 8, 0x53, false);
    femu_power_cut(&c);
    femu_power_read(&c, buf, 1, 0, 0);

    g_assert_cmpint(femu_lba_cmd(&c, NVME_CMD_WRITE_UNCOR, 0, 8), ==,
                   NVME_SUCCESS);
    femu_power_write(&c, buf, 1, 0, 8, 0x64, false);
    femu_power_cut(&c);
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_READ, 0, buf)), ==,
                   NVME_UNRECOVERED_READ);
    femu_power_write(&c, buf, 1, 0, 8, 0x75, true);
    femu_power_cut(&c);
    femu_power_read(&c, buf, 1, 0, 0x75);

    femu_power_write(&c, buf, 1, 8, 8, 0x86, false);
    g_assert_cmpint(femu_format(&c, 1, 0, 0), ==, NVME_SUCCESS);
    femu_power_cut(&c);
    femu_power_read(&c, buf, 1, 0, 0);
    femu_power_read(&c, buf, 1, 8, 0);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static void femu_test_power_flush_pending(void *obj, void *data,
                                          QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    NvmeCmd flush = { .opcode = NVME_CMD_FLUSH, .nsid = cpu_to_le32(1) };
    NvmeRwCmd rw = { .opcode = NVME_CMD_WRITE, .nsid = cpu_to_le32(1) };

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_power_write(&c, buf, 1, 0, 8, 0x31, false);
    qtest_memset(c.pdev->bus->qts, buf, 0x42, 4096);
    rw.dptr.prp1 = cpu_to_le64(buf);
    rw.nlb = cpu_to_le16(7);
    femu_submit(&c, &c.io, &flush);
    femu_submit(&c, &c.io, (NvmeCmd *)&rw);
    for (int i = 0; i < 2; i++) {
        g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, NULL, NULL)), ==,
                       NVME_SUCCESS);
    }
    femu_power_cut(&c);
    femu_power_read(&c, buf, 1, 0, 0x31);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static void femu_test_power_log(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    QTestState *qts = femu->dev.bus->qts;
    uint64_t buf = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    for (int cut = 1; cut <= 2; cut++) {
        femu_power_cut(&c);
        if (!data) {
            g_assert_cmpint(FEMU_SC(femu_get_log(&c, NVME_LOG_SMART_INFO,
                                               buf, 512, 0)), ==, NVME_SUCCESS);
            g_assert_cmpuint(qtest_readq(qts, buf + 144), ==, cut);
            g_assert_cmpuint(qtest_readq(qts, buf + 152), ==, 0);
        } else {
            uint64_t e;

            g_assert_cmpint(femu_pel(&c, 1, buf, 4096, 0), ==, NVME_SUCCESS);
            g_assert_cmpint(femu_pel_count(qts, buf, 0x05, 0x08), ==, cut);
            e = femu_pel_at(qts, buf, 0);
            g_assert_cmphex(qtest_readb(qts, e), ==, 0x05);
            g_assert_cmpint(qtest_readb(qts, e + 1), ==, 2);
            g_assert_cmpint(qtest_readb(qts, e + 2), ==, 21);
            g_assert_cmpint(qtest_readw(qts, e + 22), ==, 21);
            g_assert_cmphex(qtest_readw(qts, e + 24), ==, 0x08);
            g_assert_cmphex(qtest_readw(qts, e + 26), ==, 0);
            g_assert_cmpuint(qtest_readq(qts, e + 28), ==, cut);
            g_assert_cmpuint(qtest_readq(qts, e + 36), ==, 0);
            g_assert_cmphex(qtest_readb(qts, e + 44), ==, 0);
            g_assert_cmpint(femu_pel(&c, 2, 0, 4, 0), ==, NVME_SUCCESS);
        }
    }
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/* Successful settings, including repeats, are retained for host diagnosis. */
static void femu_test_pel_set_feature(void *obj, void *data,
                                      QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint64_t payload = guest_alloc(alloc, 4096);
    uint64_t e;
    uint32_t before;
    uint32_t timestamps;
    uint32_t result;
    uint8_t sent[512] = { 0 };
    uint8_t logged[512];
    int i;

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_pel(&c, 1, buf, 4096, 0), ==, NVME_SUCCESS);
    before = femu_pel_count(qts, buf, 0x0b, 0);
    timestamps = femu_pel_count(qts, buf, 0x03, 0);
    g_assert_cmpint(femu_pel(&c, 2, 0, 4, 0), ==, NVME_SUCCESS);
    cmd.opcode = NVME_ADM_CMD_SET_FEATURES;
    cmd.cdw10 = cpu_to_le32(data ? FEMU_FEAT_HBS : 0x01);
    cmd.cdw11 = cpu_to_le32(data ? 0 : 0x12345607);
    cmd.cdw12 = cpu_to_le32(0x12345678);
    cmd.cdw13 = cpu_to_le32(0x23456789);
    cmd.cdw14 = cpu_to_le32(0x3456789a);
    cmd.cdw15 = cpu_to_le32(0x456789ab);
    if (data) {
        sent[0] = 1;
        sent[4] = 7; /* The log preserves even the ignored input bits. */
        qtest_memwrite(qts, payload, sent, sizeof(sent));
        cmd.dptr.prp1 = cpu_to_le64(payload);
    }
    for (i = 0; i < 2; i++) {
        g_assert_cmpint(FEMU_SC(femu_admin(&c, &cmd)), ==, NVME_SUCCESS);
        g_assert_cmpint(femu_pel(&c, 1, buf, 4096, 0), ==, NVME_SUCCESS);
        g_assert_cmpint(femu_pel_count(qts, buf, 0x0b, 0), ==, before + i + 1);
        e = femu_pel_at(qts, buf, 0);
        g_assert_cmpint(qtest_readb(qts, e), ==, 0x0b);
        g_assert_cmpint(qtest_readb(qts, e + 1), ==, 1);
        g_assert_cmpuint(qtest_readw(qts, e + 22), ==, data ? 540 : 28);
        g_assert_cmphex(qtest_readl(qts, e + 24), ==,
                        6 | (data ? 512 << 16 : 0));
        qtest_memread(qts, e + 28, logged, 24);
        g_assert_cmpmem(logged, 24, &cmd.cdw10, 24);
        if (data) {
            qtest_memread(qts, e + 52, logged, sizeof(logged));
            g_assert_cmpmem(logged, sizeof(logged), sent, sizeof(sent));
        }
        g_assert_cmpint(femu_pel(&c, 2, 0, 4, 0), ==, NVME_SUCCESS);
    }
    /* Rejected commands and P/NR identifiers must not produce type 0Bh. */
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, 0x01, true, 0, 1,
                                           &result)), !=, NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, 0x02, false, 0, 0,
                                           &result)), ==, NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, 0x0b, false, 0, 1,
                                           &result)), ==, NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, 0x80, false, 0, 1,
                                           &result)), ==, NVME_SUCCESS);
    /* LBA Range Type is NR in the NVM Command Set */
    {
        NvmeCmd lrt = { 0 };

        qtest_memset(qts, payload, 0, 4096);
        lrt.opcode = NVME_ADM_CMD_SET_FEATURES;
        lrt.nsid = cpu_to_le32(1);
        lrt.cdw10 = cpu_to_le32(0x03);
        lrt.dptr.prp1 = cpu_to_le64(payload);
        g_assert_cmpint(FEMU_SC(femu_admin(&c, &lrt)), ==, NVME_SUCCESS);
    }
    qtest_writeq(qts, payload, 123456);
    cmd.cdw10 = cpu_to_le32(0x0e);
    cmd.dptr.prp1 = cpu_to_le64(payload);
    g_assert_cmpint(FEMU_SC(femu_admin(&c, &cmd)), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_pel(&c, 1, buf, 4096, 0), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_pel_count(qts, buf, 0x0b, 0), ==, before + 2);
    g_assert_cmpint(femu_pel_count(qts, buf, 0x03, 0), ==, timestamps + 1);
    guest_free(alloc, payload);
    guest_free(alloc, buf);
    femu_disable(&c);
}

/*
 * The events other commands leave in the Persistent Event log: Format NVM
 * start and completion, Sanitize start and completion, a telemetry capture,
 * a media error in a completion (limited to about 10 a second of a status),
 * and a Critical Warning bit coming on, each time it comes on.
 */
static void femu_pel_file_wait(const char *path, uint32_t events,
                               uint16_t generation)
{
    int64_t until = g_get_monotonic_time() + 5 * G_USEC_PER_SEC;
    bool saved = false;

    do {
        g_autofree char *bytes = NULL;
        gsize len;

        if (g_file_get_contents(path, &bytes, &len, NULL) && len >= 64) {
            saved = ldl_le_p(bytes + 16) == events &&
                    lduw_le_p(bytes + 20) == generation;
        }
        if (saved) {
            break;
        }
        g_usleep(1000);
    } while (g_get_monotonic_time() < until);
    g_assert_true(saved);
}

static void femu_test_pel_file(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    g_autofree char *dir = g_dir_make_tmp("femu-pel-XXXXXX", NULL);
    g_autofree char *path = g_build_filename(dir, "events", NULL);
    uint64_t buf = guest_alloc(alloc, 4096);
    QPCIDevice *pdev;
    QDict *rsp;
    bool media = data != NULL;
    int run;

    for (run = 1; run <= 2; run++) {
        rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                       "'driver':'femu','id':'pel-disk','addr':'5',"
                       "'devsz_mb':64,'femu_mode':2,'oncs':134,"
                       "'multipoller_enabled':1,'pel_file':%s}}", path);
        g_assert_true(qdict_haskey(rsp, "return"));
        qobject_unref(rsp);
        pdev = qpci_device_find(femu->dev.bus, QPCI_DEVFN(5, 0));
        femu_enable(&c, pdev, alloc);
        g_assert_cmpint(FEMU_SC(femu_pel(&c, 0, buf, 4096, 0)), ==,
                       NVME_CMD_SEQ_ERROR);
        if (run == 1 && media) {
            FemuQueue second;
            NvmeCmd cmd = { 0 };

            femu_create_io_queues(&c);
            femu_zap_create_queue(&c, &second, 2);
            g_assert_cmpint(femu_lba_cmd(&c, NVME_CMD_WRITE_UNCOR, 0, 8),
                           ==, NVME_SUCCESS);
            cmd.opcode = NVME_CMD_READ;
            cmd.nsid = cpu_to_le32(1);
            cmd.dptr.prp1 = cpu_to_le64(buf);
            femu_submit(&c, &c.io, &cmd);
            femu_submit(&c, &second, &cmd);
            g_assert_cmpint(femu_complete(&c, &c.io, NULL, NULL), ==,
                           FEMU_UNRECOVERED_READ);
            g_assert_cmpint(femu_complete(&c, &second, NULL, NULL), ==,
                           FEMU_UNRECOVERED_READ);
            femu_queue_free(&c, &c.io);
            femu_queue_free(&c, &second);
        } else if (run == 1) {
            g_assert_cmpint(femu_format(&c, 1, 0, 0), ==, NVME_SUCCESS);
        }
        g_assert_cmpint(femu_pel(&c, 1, buf, 4096, 0), ==, NVME_SUCCESS);
        g_assert_cmpuint(qtest_readq(qts, buf + 44), ==, run);
        g_assert_cmpuint(qtest_readw(qts, buf + 372), ==, run == 1 ? 1 : 3);
        g_assert_cmpuint(qtest_readl(qts, buf + 4), ==, run == 1 ? 4 : 8);
        g_assert_cmpint(femu_pel_count(qts, buf, media ? 0x05 : 0x07,
                                     media ? 0x0a : 0), ==, media ? 2 : 1);
        g_assert_cmpuint(qtest_readl(qts,
                         femu_pel_at(qts, buf, run == 1 ? 3 : 1) + 48),
                         ==, run);
        femu_pel_file_wait(path, run == 1 ? 4 : 8, run == 1 ? 1 : 3);
        g_assert_cmpint(femu_get_log(&c, 2, buf, 512, 0), ==, NVME_SUCCESS);
        g_assert_cmpuint(qtest_readq(qts, buf + 112), ==, run);
        femu_disable(&c);
        if (run == 1) {
            femu_pel_file_wait(path, 6, 1);
            femu_enable(&c, pdev, alloc);
            g_assert_cmpint(femu_pel(&c, 1, buf, 4096, 0), ==, NVME_SUCCESS);
            g_assert_cmpuint(qtest_readq(qts, buf + 44), ==, 1);
            /* Remove with a context still established; it must not reload. */
            qpci_unplug_acpi_device_test(qts, "pel-disk", 5);
            femu_queue_free(&c, &c.admin);
        } else {
            qpci_unplug_acpi_device_test(qts, "pel-disk", 5);
        }
        g_free(pdev);
    }
    guest_free(alloc, buf);
    unlink(path);
    rmdir(dir);
}

/* Quit with the controller enabled and pollers still doing MMIO DMA. */
static void femu_test_pel_file_quit(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    g_autofree char *dir = g_dir_make_tmp("femu-pel-XXXXXX", NULL);
    g_autofree char *path = g_build_filename(dir, "events", NULL);
    uint8_t events[4096];
    uint8_t retained[4096];
    uint32_t count = 0;
    uint64_t len = 0;
    bool media = data != NULL;
    int run;

    for (run = 1; run <= 2; run++) {
        QOSState *qs = qtest_pc_boot(
            "-machine pc -nodefaults -device femu,addr=5,devsz_mb=64,"
            "femu_mode=2,oncs=134,multipoller_enabled=1,pel_file=%s", path);
        QTestState *qts = qs->qts;
        QPCIDevice *pdev = qpci_device_find(qs->pcibus, QPCI_DEVFN(5, 0));
        FemuCtrlState c = { 0 };
        uint64_t buf = guest_alloc(&qs->alloc, 4096);
        NvmeCmd cmds[FEMU_QSIZE - 1] = { 0 };
        int i;

        femu_enable(&c, pdev, &qs->alloc);
        femu_create_io_queues(&c);
        if (run == 1) {
            g_assert_cmpint(femu_lba_cmd(&c, NVME_CMD_WRITE_UNCOR, 0, 8),
                           ==, NVME_SUCCESS);
            for (i = 0; i < 2; i++) {
                g_assert_cmpint(femu_rw(&c, NVME_CMD_READ, 0, buf), ==,
                               FEMU_UNRECOVERED_READ);
            }
        }
        g_assert_cmpint(femu_pel(&c, 1, buf, 4096, 0), ==, NVME_SUCCESS);
        g_assert_cmpuint(qtest_readq(qts, buf + 44), ==, run);
        g_assert_cmpint(femu_pel_count(qts, buf, 0x05, 0x0a), >=, 2);
        if (run == 1) {
            count = qtest_readl(qts, buf + 4);
            len = qtest_readq(qts, buf + 8) - 512;
            g_assert_cmpuint(len, <=, sizeof(events));
            qtest_memread(qts, buf + 512, events, len);
        } else {
            uint32_t added = qtest_readl(qts, buf + 4) - count;

            g_assert_cmpuint(added, >=, 2);
            if (!media) {
                g_assert_cmpuint(added, ==, 2);
            }
            qtest_memread(qts, femu_pel_at(qts, buf, added), retained, len);
            g_assert_cmpmem(retained, len, events, len);
        }

        /* Race quit with MMIO DMA or more media-error completions. */
        for (i = 0; i < ARRAY_SIZE(cmds); i++) {
            cmds[i].opcode = media ? NVME_CMD_READ : NVME_CMD_WRITE;
            cmds[i].cid = cpu_to_le16(c.cid++);
            cmds[i].nsid = cpu_to_le32(1);
            cmds[i].dptr.prp1 = cpu_to_le64(media ? buf : 0xfed00000);
            cmds[i].cdw10 = cpu_to_le32(media ? 0 : 8);
            cmds[i].cdw12 = cpu_to_le32(7);
            qtest_memwrite(qts, c.io.sq_addr +
                           c.io.sq_tail * sizeof(NvmeCmd),
                           &cmds[i], sizeof(cmds[i]));
            c.io.sq_tail = (c.io.sq_tail + 1) % FEMU_QSIZE;
        }
        qpci_io_writel(pdev, c.bar, femu_sq_doorbell(&c, c.io.qid),
                      c.io.sq_tail);
        qtest_qmp_send(qts, "{'execute':'quit'}");
        /* libqtest kills a hung child after 30 seconds and fails its status. */
        qtest_set_expected_status(qts, 0);
        qtest_wait_qemu(qts);
        femu_queue_free(&c, &c.io);
        femu_queue_free(&c, &c.admin);
        guest_free(&qs->alloc, buf);
        g_free(pdev);
        qtest_pc_shutdown(qs);
    }
    unlink(path);
    rmdir(dir);
}

static void femu_test_pel_file_invalid(void *obj, void *data,
                                       QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    g_autofree char *dir = g_dir_make_tmp("femu-pel-XXXXXX", NULL);
    g_autofree char *path = g_build_filename(dir, "events", NULL);
    g_autofree char *valid = NULL;
    gsize len;
    QDict *rsp;
    int i;

    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                   "'driver':'femu','id':'pel-disk','addr':'5',"
                   "'devsz_mb':64,'femu_mode':2,'pel_file':%s}}", path);
    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
    qpci_unplug_acpi_device_test(qts, "pel-disk", 5);
    g_assert_true(g_file_get_contents(path, &valid, &len, NULL));

    /* Magic, version, size, checksum, truncation, and encoded event bounds. */
    for (i = 0; i < 6; i++) {
        g_autofree char *bad = g_memdup2(valid, len);
        g_autofree char *after = NULL;
        gsize bad_len = len;
        gsize after_len;
        const char *desc;

        switch (i) {
        case 0:
            bad[0] ^= 1;
            break;
        case 1:
            bad[8] = 2;
            break;
        case 2:
            bad[12] ^= 1;
            break;
        case 3:
            bad[len - 1] ^= 1;
            break;
        case 4:
            bad_len = 12;
            break;
        case 5:
            stw_le_p(bad + 64 + 22, 0xffff);
            break;
        }
        /* Keep structural corruption independent of checksum validation. */
        if (i < 3 || i == 5) {
            GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);
            gsize digest_len = 32;

            g_checksum_update(sum, (uint8_t *)bad, 32);
            g_checksum_update(sum, (uint8_t *)bad + 64, len - 64);
            g_checksum_get_digest(sum, (uint8_t *)bad + 32, &digest_len);
            g_checksum_free(sum);
        }
        g_test_message("PEL corruption case %d", i);
        g_assert_true(g_file_set_contents(path, bad, bad_len, NULL));
        rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                       "'driver':'femu','id':'pel-disk','addr':'5',"
                       "'devsz_mb':64,'femu_mode':2,'pel_file':%s}}", path);
        g_assert_true(qdict_haskey(rsp, "error"));
        desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
        g_assert_nonnull(strstr(desc, "Invalid or incompatible PEL file"));
        qobject_unref(rsp);
        g_assert_true(g_file_get_contents(path, &after, &after_len, NULL));
        g_assert_cmpmem(after, after_len, bad, bad_len);
    }
    /* A refusal releases its resources, so the same slot and ID can retry. */
    g_assert_true(g_file_set_contents(path, valid, len, NULL));
    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                   "'driver':'femu','id':'pel-disk','addr':'5',"
                   "'devsz_mb':64,'femu_mode':2,'pel_file':%s}}", path);
    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
    qpci_unplug_acpi_device_test(qts, "pel-disk", 5);
    unlink(path);
    rmdir(dir);
}

static void femu_test_pel_events(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t mem, buf, e;
    uint32_t result, tnev;
    int64_t t0, allowed;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    mem = guest_alloc(alloc, 2 * 4096);
    buf = (mem + 4095) & ~4095ULL;

    g_assert_cmpint(femu_format(&c, 1, 0, 0), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_pel(&c, 1, buf, 4096, 0), ==, NVME_SUCCESS);
    e = femu_pel_at(qts, buf, 0);
    g_assert_cmpint(qtest_readb(qts, e), ==, 0x08);
    g_assert_cmpint(qtest_readb(qts, e + 1), ==, 2);
    g_assert_cmpuint(qtest_readl(qts, e + 24), ==, 1);          /* NSID */
    g_assert_cmpint(qtest_readb(qts, e + 24 + 5), ==, 0);       /* FNVMS */
    e = femu_pel_at(qts, buf, 1);
    g_assert_cmpint(qtest_readb(qts, e), ==, 0x07);
    g_assert_cmpuint(qtest_readl(qts, e + 24 + 8), ==, 0);      /* CDW10 */
    tnev = qtest_readl(qts, buf + 4);
    g_assert_cmpint(femu_pel(&c, 2, 0, 4, 0), ==, NVME_SUCCESS);

    /* a refused Format changed nothing, so it leaves no events */
    g_assert_cmpint(femu_format(&c, 1, 15, 0), !=, NVME_SUCCESS);
    g_assert_cmpint(femu_pel(&c, 1, buf, 4096, 0), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf + 4), ==, tnev);
    g_assert_cmpint(femu_pel(&c, 2, 0, 4, 0), ==, NVME_SUCCESS);

    g_assert_cmpint(femu_sanitize(&c, 0x2), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_get_telemetry(&c, FEMU_LOG_TELEMETRY_HOST, true,
                                       buf, 512, 0), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_pel(&c, 1, buf, 4096, 0), ==, NVME_SUCCESS);
    e = femu_pel_at(qts, buf, 0);
    g_assert_cmpint(qtest_readb(qts, e), ==, 0x0c);
    g_assert_cmpint(qtest_readb(qts, e + 24), ==, FEMU_LOG_TELEMETRY_HOST);
    e = femu_pel_at(qts, buf, 1);
    g_assert_cmpint(qtest_readb(qts, e), ==, 0x0a);
    g_assert_cmpuint(qtest_readw(qts, e + 24), ==, 0xffff);     /* SPROG */
    g_assert_cmpuint(qtest_readl(qts, e + 24 + 8), ==, 0xffffffff);
    e = femu_pel_at(qts, buf, 2);
    g_assert_cmpint(qtest_readb(qts, e), ==, 0x09);
    g_assert_cmpuint(qtest_readl(qts, e + 24 + 4), ==, 0x2);    /* CDW10 */
    g_assert_cmpint(femu_pel(&c, 2, 0, 4, 0), ==, NVME_SUCCESS);

    /*
     * 100 unrecovered reads in a row: a burst of 10 is logged, then 10 a
     * second, so no more than 10 + 10 per elapsed second (+1 for rounding).
     * Counted by the change in TNEV, which sees every event, not only those
     * in the 4 KiB read back.
     */
    g_assert_cmpint(femu_pel(&c, 3, buf, 4096, 0), ==, NVME_SUCCESS);
    tnev = qtest_readl(qts, buf + 4);
    g_assert_cmpint(femu_pel(&c, 2, 0, 4, 0), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_lba_cmd(&c, NVME_CMD_WRITE_UNCOR, 0, 8), ==,
                    NVME_SUCCESS);
    t0 = g_get_monotonic_time();
    for (i = 0; i < 100; i++) {
        g_assert_cmpint(femu_rw(&c, NVME_CMD_READ, 0, buf + 4096), ==,
                        FEMU_UNRECOVERED_READ);
    }
    allowed = 10 + (g_get_monotonic_time() - t0) / 100000 + 1;
    g_assert_cmpint(femu_pel(&c, 1, buf, 4096, 0), ==, NVME_SUCCESS);
    e = femu_pel_at(qts, buf, 0);
    g_assert_cmpint(qtest_readb(qts, e), ==, 0x05);
    g_assert_cmpint(qtest_readb(qts, e + 1), ==, 2);
    g_assert_cmpuint(qtest_readw(qts, e + 24), ==, 0x0a);
    /* the completion itself, status in its top half with the phase */
    g_assert_cmpuint(qtest_readw(qts, e + 28 + 14) >> 1 & 0x7ff, ==,
                     FEMU_UNRECOVERED_READ);
    g_assert_cmpint(femu_pel_count(qts, buf, 0x05, 0x0a), >=, 10);
    g_assert_cmpuint(qtest_readl(qts, buf + 4) - tnev, >=, 10);
    g_assert_cmpuint(qtest_readl(qts, buf + 4) - tnev, <=,
                     MIN(allowed, 100));
    g_assert_cmpint(femu_pel(&c, 2, 0, 4, 0), ==, NVME_SUCCESS);

    /* a threshold at or under the temperature, twice: two events */
    for (i = 0; i < 2; i++) {
        g_assert_cmpint(femu_set_feature(&c, 0x04, false, 0, 0, &result), ==,
                        NVME_SUCCESS);
        g_assert_cmpint(femu_set_feature(&c, 0x04, false, 0, 0xffff,
                                         &result), ==, NVME_SUCCESS);
    }
    g_assert_cmpint(femu_pel(&c, 1, buf, 4096, 0), ==, NVME_SUCCESS);
    e = femu_pel_at(qts, buf, 2);
    g_assert_cmpint(qtest_readb(qts, e), ==, 0x05);
    g_assert_cmpuint(qtest_readw(qts, e + 24), ==, 0x06);
    g_assert_cmpint(qtest_readb(qts, e + 28) & (1 << 1), !=, 0);
    g_assert_cmpint(femu_pel_count(qts, buf, 0x05, 0x06), ==, 2);
    g_assert_cmpint(femu_pel(&c, 2, 0, 4, 0), ==, NVME_SUCCESS);

    guest_free(alloc, mem);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static void femu_test_ns_mgmt_unavailable(void *obj, void *data,
                                          QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint32_t nsid;

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readw(qts, buf + 256) & 8, ==, 0);
    g_assert_cmphex(qtest_readl(qts, buf + 92) & 0x100, ==, 0);
    g_assert_cmpuint(qtest_readl(qts, buf + 516), ==, GPOINTER_TO_UINT(data));
    g_assert_cmpint(femu_ns_create(&c, buf, 8, 0, &nsid), ==,
                   NVME_INVALID_OPCODE);
    g_assert_cmpint(femu_ns_delete(&c, 1), ==, NVME_INVALID_OPCODE);
    g_assert_cmpint(femu_ns_attach(&c, buf, 1, 0, false), ==,
                   NVME_INVALID_OPCODE);
    g_assert_cmpint(femu_identify(&c, 0xffffffff, 0, 0, buf), ==,
                   NVME_INVALID_NSID);
    g_assert_cmpint(femu_changed_ns_log(&c, buf, false), ==,
                   NVME_INVALID_LOG_ID);
    g_assert_cmpint(femu_pel(&c, 3, buf, 512, 0), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, buf + 480) & 0x40, ==, 0);
    femu_disable(&c);
    guest_free(alloc, buf);
}

static void femu_test_ns_mgmt_pel(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint64_t e;
    uint32_t nsid;
    uint8_t ev[48] = { 0 };
    uint8_t actual[48];

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_ns_delete(&c, 1), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_create(&c, buf, 3, 1, &nsid), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_pel(&c, 1, buf, 4096, 0), ==, NVME_SUCCESS);
    e = femu_pel_at(qts, buf, 0);
    g_assert_cmpuint(qtest_readb(qts, e), ==, 6);
    g_assert_cmpuint(qtest_readb(qts, e + 1), ==, 2);
    g_assert_cmpuint(qtest_readb(qts, e + 2), ==, 21);
    g_assert_cmpuint(qtest_readw(qts, e + 22), ==, 48);
    stq_le_p(ev + 8, 3);
    stq_le_p(ev + 24, 3);
    ev[32] = 1;
    stl_le_p(ev + 44, 1);
    qtest_memread(qts, e + 24, actual, sizeof(actual));
    g_assert_cmpmem(ev, sizeof(ev), actual, sizeof(actual));
    g_assert_cmphex(qtest_readb(qts, buf + 480), ==, 0xfa);
    g_assert_cmpint(femu_pel(&c, 2, 0, 4, 0), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_attach(&c, buf, 1, 0, true), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_create(&c, buf, 3, 15, &nsid), ==, 0x10a);
    g_assert_cmpint(femu_ns_delete(&c, 1), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_pel(&c, 1, buf, 4096, 0), ==, NVME_SUCCESS);
    e = femu_pel_at(qts, buf, 0);
    stl_le_p(ev, 1);
    qtest_memread(qts, e + 24, actual, sizeof(actual));
    g_assert_cmpmem(ev, sizeof(ev), actual, sizeof(actual));
    g_assert_cmpuint(qtest_readl(qts, buf + 4), ==, 5);
    g_assert_cmpint(femu_pel(&c, 2, 0, 4, 0), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_create(&c, buf, 8, 0, &nsid), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_create(&c, buf, 8, 0, &nsid), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_delete(&c, 0xffffffff), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ns_delete(&c, 0xffffffff), ==, NVME_SUCCESS);
    femu_disable(&c);
    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_pel(&c, 1, buf, 4096, 0), ==, NVME_SUCCESS);
    /* Reset adds a SMART snapshot and a power-on/reset event. */
    e = femu_pel_at(qts, buf, 2);
    g_assert_cmpuint(qtest_readb(qts, e), ==, 6);
    memset(ev, 0, sizeof(ev));
    stl_le_p(ev, 1);
    stl_le_p(ev + 44, 0xffffffff);
    qtest_memread(qts, e + 24, actual, sizeof(actual));
    g_assert_cmpmem(ev, sizeof(ev), actual, sizeof(actual));
    e = femu_pel_at(qts, buf, 3);
    qtest_memread(qts, e + 24, actual, sizeof(actual));
    g_assert_cmpmem(ev, sizeof(ev), actual, sizeof(actual));
    g_assert_cmpuint(qtest_readl(qts, buf + 4), ==, 11);
    femu_disable(&c);
    guest_free(alloc, buf);
}

static uint16_t femu_directive(FemuCtrlState *c, bool receive,
                               uint32_t nsid, uint32_t dw11, uint32_t dw12,
                               uint64_t buf, uint32_t bytes, uint32_t *result)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = receive ? 0x1a : 0x19;
    cmd.nsid = cpu_to_le32(nsid);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(bytes ? bytes / 4 - 1 : 0);
    cmd.cdw11 = cpu_to_le32(dw11);
    cmd.cdw12 = cpu_to_le32(dw12);
    return FEMU_SC(femu_admin_result(c, &cmd, result));
}

static void femu_test_streams_identify(void *obj, void *data,
                                     QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    bool enabled = GPOINTER_TO_INT(data);
    uint64_t buf = guest_alloc(alloc, 4096);
    int i;

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readw(qts, buf + 256) & 0x20, ==,
                    enabled ? 0x20 : 0);
    if (!enabled) {
        g_assert_cmphex(femu_directive(&c, true, 1, 1, 0, buf, 4096, NULL),
                       ==, NVME_INVALID_OPCODE);
        g_assert_cmphex(femu_directive(&c, false, 1, 1, 0x101, 0, 0, NULL),
                       ==, NVME_INVALID_OPCODE);
    } else {
        g_assert_cmphex(femu_directive(&c, true, 1, 1, 0, buf, 4096, NULL),
                       ==, NVME_SUCCESS);
        g_assert_cmphex(qtest_readb(qts, buf), ==, 3);
        g_assert_cmphex(qtest_readb(qts, buf + 32), ==, 1);
        for (i = 64; i < 4096; i++) {
            g_assert_cmphex(qtest_readb(qts, buf + i), ==, 0);
        }
        g_assert_cmphex(femu_directive(&c, false, 1, 1, 1, 0, 0, NULL),
                       ==, NVME_INVALID_FIELD);
        g_assert_cmphex(femu_directive(&c, false, 1, 1, 0x101, 0, 0, NULL),
                       ==, NVME_SUCCESS);
        g_assert_cmphex(femu_directive(&c, true, 1, 1, 0, buf, 4096, NULL),
                       ==, NVME_SUCCESS);
        g_assert_cmphex(qtest_readb(qts, buf + 32), ==, 3);
        g_assert_cmphex(femu_directive(&c, false, 1, 1, 0x100, 0, 0, NULL),
                       ==, NVME_SUCCESS);
        g_assert_cmphex(femu_directive(&c, true, 1, 1, 0, buf, 4, NULL),
                       ==, NVME_SUCCESS);
        g_assert_cmphex(femu_directive(&c, true, 0xffffffff, 1, 0,
                                     buf, 4096, NULL), ==, NVME_INVALID_FIELD);
        g_assert_cmphex(femu_directive(&c, true, 0, 1, 0, buf, 4096, NULL),
                       ==, NVME_INVALID_NSID);
        g_assert_cmphex(femu_directive(&c, true, 1, 0x201, 0, buf, 4096, NULL),
                       ==, NVME_INVALID_FIELD);
    }
    guest_free(alloc, buf);
    femu_disable(&c);
}

static void femu_test_streams_resources(void *obj, void *data,
                                      QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint32_t result;

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmphex(femu_directive(&c, true, 1, 0x101, 0, buf, 32, NULL),
                   ==, NVME_INVALID_FIELD);
    g_assert_cmphex(femu_directive(&c, false, 0xffffffff, 1, 0x101,
                                 0, 0, NULL), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_directive(&c, true, 1, 0x101, 0, buf, 32, NULL),
                   ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readw(qts, buf), ==, 4);
    g_assert_cmpuint(qtest_readw(qts, buf + 2), ==, 4);
    g_assert_cmpuint(qtest_readw(qts, buf + 4), ==, 0);
    g_assert_cmpuint(qtest_readb(qts, buf + 6), ==, 0);
    g_assert_cmpuint(qtest_readl(qts, buf + 16), ==, data ? 8 : 1);
    g_assert_cmpuint(qtest_readw(qts, buf + 20), ==, data ? 128 : 1);
    g_assert_cmpuint(qtest_readw(qts, buf + 22), ==, 0);
    g_assert_cmpuint(qtest_readw(qts, buf + 24), ==, 0);
    g_assert_cmphex(femu_directive(&c, true, 1, 0x103, 3, 0, 0, &result),
                   ==, NVME_SUCCESS);
    g_assert_cmpuint(result, ==, 3);
    g_assert_cmphex(femu_directive(&c, true, 1, 0x103, 1, 0, 0, &result),
                   ==, NVME_INVALID_FIELD);
    g_assert_cmphex(femu_directive(&c, true, 2, 0x103, 4, 0, 0, &result),
                   ==, NVME_SUCCESS);
    g_assert_cmpuint(result, ==, 1);
    g_assert_cmphex(femu_directive(&c, true, 1, 0x101, 0, buf, 32, NULL),
                   ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readw(qts, buf + 2), ==, 0);
    g_assert_cmpuint(qtest_readw(qts, buf + 22), ==, 3);
    g_assert_cmphex(femu_directive(&c, true, 0xffffffff, 0x101, 0,
                                 buf, 32, NULL), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readw(qts, buf + 22), ==, 0);
    g_assert_cmphex(femu_directive(&c, true, 1, 0x102, 0, buf, 4, NULL),
                   ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readw(qts, buf), ==, 0);
    g_assert_cmphex(femu_directive(&c, false, 1, 0xffff0101, 0, 0, 0, NULL),
                   ==, NVME_SUCCESS);
    g_assert_cmphex(femu_directive(&c, false, 1, 0x102, 0, 0, 0, NULL),
                   ==, NVME_SUCCESS);
    g_assert_cmphex(femu_directive(&c, false, 1, 0x102, 0, 0, 0, NULL),
                   ==, NVME_SUCCESS);
    g_assert_cmphex(femu_directive(&c, false, 2, 1, 0x100, 0, 0, NULL),
                   ==, NVME_SUCCESS);
    g_assert_cmphex(femu_directive(&c, true, 1, 0x101, 0, buf, 32, NULL),
                   ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readw(qts, buf + 2), ==, 4);
    g_assert_cmphex(femu_directive(&c, true, 1, 0x103, 4, 0, 0, &result),
                   ==, NVME_SUCCESS);
    femu_disable(&c);
    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmphex(femu_directive(&c, true, 1, 0x101, 0, buf, 32, NULL),
                   ==, NVME_INVALID_FIELD);
    g_assert_cmphex(femu_directive(&c, false, 1, 1, 0x101, 0, 0, NULL),
                   ==, NVME_SUCCESS);
    g_assert_cmphex(femu_directive(&c, true, 1, 0x101, 0, buf, 32, NULL),
                   ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readw(qts, buf + 2), ==, 4);
    g_assert_cmphex(femu_directive(&c, false, 2, 1, 0x101, 0, 0, NULL),
                   ==, NVME_SUCCESS);
    g_assert_cmphex(femu_directive(&c, true, 1, 0x103, 4, 0, 0, &result),
                   ==, NVME_SUCCESS);
    g_assert_cmphex(femu_directive(&c, true, 2, 0x103, 1, 0, 0, &result),
                   ==, 0x17f);
    if (data) {
        g_assert_cmphex(femu_format(&c, 1, 4, 0), ==, NVME_SUCCESS);
        g_assert_cmphex(femu_directive(&c, true, 1, 0x101, 0,
                                     buf, 32, NULL), ==, NVME_SUCCESS);
        g_assert_cmpuint(qtest_readl(qts, buf + 16), ==, 1);
        g_assert_cmpuint(qtest_readw(qts, buf + 20), ==, 64);
    }
    guest_free(alloc, buf);
    femu_disable(&c);
}

static uint16_t femu_stream_write(FemuCtrlState *c, uint32_t nsid,
                                  uint64_t slba, uint64_t buf,
                                  uint8_t dtype, uint16_t sid)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = NVME_CMD_WRITE;
    cmd.nsid = cpu_to_le32(nsid);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(slba);
    cmd.cdw12 = cpu_to_le32((FEMU_DATA_SIZE / c->lba_size - 1) |
                           ((uint32_t)dtype << 20));
    cmd.cdw13 = cpu_to_le32((uint32_t)sid << 16);
    femu_submit(c, &c->io, &cmd);
    return FEMU_SC(femu_complete(c, &c->io, NULL, NULL));
}

static void femu_test_streams_write(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint32_t result;
    QDict *rsp;
    unsigned line0;
    unsigned line1;
    unsigned frontiers;
    uint64_t gc_pages;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x5a, 4096);
    /* With no directive enabled even unsupported types are ignored. */
    g_assert_cmphex(femu_stream_write(&c, 1, 0, buf, 15, 1), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_directive(&c, false, 0xffffffff, 1, 0x101,
                                 0, 0, NULL), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_stream_write(&c, 1, 0, buf, 2, 1),
                   ==, NVME_INVALID_FIELD);
    g_assert_cmphex(femu_directive(&c, true, 1, 0x103, 2, 0, 0, &result),
                   ==, NVME_SUCCESS);
    g_assert_cmphex(femu_stream_write(&c, 1, 0, buf, 1, 65535),
                   ==, NVME_SUCCESS);
    g_assert_cmphex(femu_stream_write(&c, 1, 8, buf, 1, 7), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_directive(&c, true, 1, 0x102, 0, buf, 4096, NULL),
                   ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readw(qts, buf), ==, 2);
    g_assert_cmpuint(qtest_readw(qts, buf + 2), ==, 7);
    g_assert_cmpuint(qtest_readw(qts, buf + 4), ==, 65535);
    g_assert_cmpuint(qtest_readw(qts, buf + 4094), ==, 0);
    if (data) {
        rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                        "'path':'/machine/peripheral/streams-test',"
                        "'property':'x-stream-test'}}");
        g_assert_true(qdict_haskey(rsp, "return"));
        g_assert_cmpint(sscanf(qdict_get_str(rsp, "return"),
                              "%u %" SCNu64 " %u %u",
                              &frontiers, &gc_pages, &line0, &line1), ==, 4);
        g_assert_cmpuint(line0, !=, line1);
        g_assert_cmpuint(frontiers, ==, 2);
        qobject_unref(rsp);
    }
    /* Zero is an ordinary write; a third nonzero ID replaces an open ID. */
    g_assert_cmphex(femu_stream_write(&c, 1, 16, buf, 1, 0), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_stream_write(&c, 1, 16, buf, 1, 99), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_directive(&c, true, 1, 0x102, 0, buf, 4096, NULL),
                   ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readw(qts, buf), ==, 2);
    g_assert_cmphex(femu_directive(&c, false, 1, 0x630101, 0, 0, 0, NULL),
                   ==, NVME_SUCCESS);
    g_assert_cmphex(femu_directive(&c, true, 1, 0x102, 0, buf, 4096, NULL),
                   ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readw(qts, buf), ==, 1);
    g_assert_cmphex(femu_format(&c, 1, 0, 0), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_directive(&c, true, 1, 0x101, 0, buf, 32, NULL),
                   ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readw(qts, buf + 22), ==, 2);
    g_assert_cmpuint(qtest_readw(qts, buf + 24), ==, 0);
    g_assert_cmphex(femu_directive(&c, false, 1, 0x102, 0, 0, 0, NULL),
                   ==, NVME_SUCCESS);
    /* Shared resources also open streams without an exclusive allocation. */
    g_assert_cmphex(femu_stream_write(&c, 1, 0, buf, 1, 1000),
                   ==, NVME_SUCCESS);
    g_assert_cmphex(femu_directive(&c, true, 0xffffffff, 0x102, 0,
                                 buf, 4096, NULL), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readw(qts, buf), ==, 1);
    g_assert_cmpuint(qtest_readw(qts, buf + 2), ==, 1000);
    g_assert_cmphex(femu_directive(&c, true, 2, 0x103, 2, 0, 0, &result),
                   ==, NVME_SUCCESS);
    g_assert_cmphex(femu_stream_write(&c, 1, 8, buf, 1, 5000),
                   ==, NVME_SUCCESS);
    g_assert_cmphex(femu_directive(&c, true, 1, 0x102, 0, buf, 4096, NULL),
                   ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readw(qts, buf), ==, 0);
    g_assert_cmphex(femu_stream_write(&c, 2, 0, buf, 1, 5), ==, NVME_SUCCESS);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmphex(femu_directive(&c, false, 2, 1, 0x101, 0, 0, NULL),
                   ==, NVME_SUCCESS);
    g_assert_cmphex(femu_directive(&c, true, 2, 0x101, 0, buf, 32, NULL),
                   ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readw(qts, buf + 22), ==, 0);
    g_assert_cmpuint(qtest_readw(qts, buf + 24), ==, 0);
    guest_free(alloc, buf);
    femu_disable(&c);
}

static void femu_test_streams_gc(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    QDict *rsp;
    gchar **fields;
    unsigned i;
    unsigned j;
    uint64_t gc_pages;
    uint32_t result;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    g_assert_cmphex(femu_directive(&c, false, 1, 1, 0x101, 0, 0, NULL),
                   ==, NVME_SUCCESS);
    g_assert_cmphex(femu_directive(&c, true, 1, 0x103, 2, 0, 0, &result),
                   ==, NVME_SUCCESS);
    for (i = 0; i < 1024; i++) {
        unsigned lpn = i < 256 ? i : (i % 64 / 2) * 4 + i % 2;

        qtest_memset(qts, buf, lpn % 128, 4096);
        g_assert_cmphex(femu_stream_write(&c, 1, lpn * 8, buf,
                                         1, lpn % 2 ? 99 : 7),
                       ==, NVME_SUCCESS);
    }
    rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                    "'path':'/machine/peripheral/streams-test',"
                    "'property':'x-stream-test'}}");
    g_assert_true(qdict_haskey(rsp, "return"));
    fields = g_strsplit(qdict_get_str(rsp, "return"), " ", -1);
    g_assert_cmpuint(g_strv_length(fields), ==, 130);
    gc_pages = g_ascii_strtoull(fields[1], NULL, 10);
    g_assert_cmpuint(gc_pages, >, 0);
    for (i = 0; i < 128; i += 2) {
        for (j = 1; j < 128; j += 2) {
            g_assert_cmpstr(fields[i + 2], !=, fields[j + 2]);
        }
    }
    g_strfreev(fields);
    qobject_unref(rsp);
    for (i = 0; i < 128; i++) {
        g_assert_cmphex(femu_rw(&c, NVME_CMD_READ, i * 8, buf),
                       ==, NVME_SUCCESS);
        g_assert_cmpuint(qtest_readb(qts, buf), ==, i);
    }
    g_assert_cmphex(femu_directive(&c, false, 1, 0x102, 0, 0, 0, NULL),
                   ==, NVME_SUCCESS);
    rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                    "'path':'/machine/peripheral/streams-test',"
                    "'property':'x-stream-test'}}");
    g_assert_true(qdict_haskey(rsp, "return"));
    g_assert_cmpint(qdict_get_str(rsp, "return")[0], ==, '0');
    qobject_unref(rsp);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static void femu_test_streams_subpage(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    unsigned lines[2];
    unsigned i;
    unsigned j;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    g_assert_cmphex(femu_directive(&c, false, 1, 1, 0x101, 0, 0, NULL),
                   ==, NVME_SUCCESS);
    /* Both LBAs share LPN 0, which follows the most recent stream write. */
    for (i = 0; i < 2; i++) {
        NvmeCmd cmd = { 0 };
        QDict *rsp;
        unsigned frontiers;
        uint64_t gc_pages;

        qtest_memset(qts, buf, i ? 0x22 : 0x11, 512);
        cmd.opcode = NVME_CMD_WRITE;
        cmd.nsid = cpu_to_le32(1);
        cmd.dptr.prp1 = cpu_to_le64(buf);
        cmd.cdw10 = cpu_to_le32(i);
        cmd.cdw12 = cpu_to_le32(1 << 20);
        cmd.cdw13 = cpu_to_le32((i ? 99 : 7) << 16);
        femu_submit(&c, &c.io, &cmd);
        g_assert_cmphex(FEMU_SC(femu_complete(&c, &c.io, NULL, NULL)),
                       ==, NVME_SUCCESS);
        rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                        "'path':'/machine/peripheral/streams-test',"
                        "'property':'x-stream-test'}}");
        g_assert_true(qdict_haskey(rsp, "return"));
        g_assert_cmpint(sscanf(qdict_get_str(rsp, "return"),
                              "%u %" SCNu64 " %u",
                              &frontiers, &gc_pages, &lines[i]), ==, 3);
        qobject_unref(rsp);
    }
    g_assert_cmpuint(lines[0], !=, lines[1]);
    g_assert_cmphex(femu_rw(&c, NVME_CMD_READ, 0, buf), ==, NVME_SUCCESS);
    for (j = 0; j < 512; j++) {
        g_assert_cmphex(qtest_readb(qts, buf + j), ==, 0x11);
        g_assert_cmphex(qtest_readb(qts, buf + 512 + j), ==, 0x22);
    }
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static void femu_test_streams_sws(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    unsigned i;
    QDict *rsp;
    const QListEntry *entry;
    bool found = false;

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmphex(femu_directive(&c, false, 1, 1, 0x101, 0, 0, NULL),
                   ==, NVME_SUCCESS);
    for (i = 0; i < 2; i++) {
        unsigned lba_bytes = i ? 4096 : 512;

        g_assert_cmphex(femu_directive(&c, true, 1, 0x101, 0,
                                     buf, 32, NULL), ==, NVME_SUCCESS);
        /* This fixture has sixteen 512-byte sectors per FTL page. */
        g_assert_cmpuint(qtest_readl(qts, buf + 16) * lba_bytes, ==, 8192);
        if (!i) {
            g_assert_cmphex(femu_format(&c, 1, 3, 0), ==, NVME_SUCCESS);
        }
    }
    rsp = qtest_qmp(qts, "{'execute':'device-list-properties',"
                    "'arguments':{'typename':'femu'}}");
    g_assert_true(qdict_haskey(rsp, "return"));
    QLIST_FOREACH_ENTRY(qdict_get_qlist(rsp, "return"), entry) {
        QDict *prop = qobject_to(QDict, qlist_entry_obj(entry));

        if (!strcmp(qdict_get_str(prop, "name"), "streams")) {
            const char *desc = qdict_get_try_str(prop, "description");

            g_assert_nonnull(desc);
            g_assert_nonnull(strstr(desc, "FTL page (SWS)"));
            found = true;
        }
    }
    g_assert_true(found);
    qobject_unref(rsp);
    guest_free(alloc, buf);
    femu_disable(&c);
}

static void femu_test_streams_churn(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint16_t status;
    unsigned i;
    bool retained[41] = { false };
    bool exhausted = false;
    uint8_t expected[4096];
    uint8_t actual[4096];

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    g_assert_cmphex(femu_directive(&c, false, 1, 1, 0x101, 0, 0, NULL),
                   ==, NVME_SUCCESS);
    /* Preserve old data while repeatedly opening distinct stream lifetimes. */
    for (i = 1; i <= 40; i++) {
        qtest_memset(qts, buf, i, 4096);
        status = femu_stream_write(&c, 1, i * 8, buf, 1, i);
        if (i <= 8) {
            g_assert_cmphex(status, ==, NVME_SUCCESS);
        } else {
            g_assert_true(status == NVME_SUCCESS ||
                          status == NVME_CAP_EXCEEDED);
        }
        retained[i] = status == NVME_SUCCESS;
        exhausted |= status == NVME_CAP_EXCEEDED;
        g_assert_cmphex(femu_directive(&c, false, 1, (i << 16) | 0x101,
                                     0, 0, 0, NULL), ==, NVME_SUCCESS);
    }
    g_assert_true(exhausted);
    for (i = 1; i <= 40; i++) {
        if (!retained[i]) {
            continue;
        }
        memset(expected, i, sizeof(expected));
        qtest_memset(qts, buf, 0, sizeof(actual));
        g_assert_cmphex(femu_rw(&c, NVME_CMD_READ, i * 8, buf),
                       ==, NVME_SUCCESS);
        qtest_memread(qts, buf, actual, sizeof(actual));
        g_assert_cmpmem(actual, sizeof(actual), expected, sizeof(expected));
    }
    for (i = 0; i <= 16; i++) {
        status = femu_stream_write(&c, 1, (64 + i) * 8, buf, 0, 0);
        g_assert_cmphex(status, ==, i < 16 ? NVME_SUCCESS : NVME_CAP_EXCEEDED);
    }
    g_assert_cmphex(femu_format(&c, 1, 0, 0), ==, NVME_SUCCESS);
    qtest_memset(qts, buf, 0x5a, sizeof(expected));
    g_assert_cmphex(femu_stream_write(&c, 1, 0, buf, 0, 0), ==, NVME_SUCCESS);
    qtest_memset(qts, buf, 0, sizeof(actual));
    g_assert_cmphex(femu_rw(&c, NVME_CMD_READ, 0, buf), ==, NVME_SUCCESS);
    memset(expected, 0x5a, sizeof(expected));
    qtest_memread(qts, buf, actual, sizeof(actual));
    g_assert_cmpmem(actual, sizeof(actual), expected, sizeof(expected));
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static void femu_test_streams_recovery(void *obj, void *data,
                                     QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint16_t status;
    unsigned i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    g_assert_cmphex(femu_directive(&c, false, 1, 1, 0x101, 0, 0, NULL),
                   ==, NVME_SUCCESS);
    for (i = 1; i <= 40; i++) {
        status = femu_stream_write(&c, 1, i * 8, buf, 1, i);
        g_assert_true(status == NVME_SUCCESS || status == NVME_CAP_EXCEEDED);
        g_assert_cmphex(femu_directive(&c, false, 1, (i << 16) | 0x101,
                                     0, 0, 0, NULL), ==, NVME_SUCCESS);
    }
    for (i = 0; i <= 16; i++) {
        status = femu_stream_write(&c, 1, (64 + i) * 8, buf, 0, 0);
        g_assert_cmphex(status, ==, i < 16 ? NVME_SUCCESS : NVME_CAP_EXCEEDED);
    }
    g_assert_cmphex(femu_format(&c, 1, 0, 0), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_stream_write(&c, 1, 0, buf, 0, 0), ==, NVME_SUCCESS);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

typedef struct FemuPauseDeadline {
    GMutex lock;
    GCond cond;
    bool done;
} FemuPauseDeadline;

static void *femu_pause_deadline(void *opaque)
{
    FemuPauseDeadline *d = opaque;
    gint64 end = g_get_monotonic_time() + 10 * G_TIME_SPAN_SECOND;

    g_mutex_lock(&d->lock);
    while (!d->done) {
        if (!g_cond_wait_until(&d->cond, &d->lock, end)) {
            g_error("pause with MMIO DMA did not return within ten seconds");
        }
    }
    g_mutex_unlock(&d->lock);
    return NULL;
}

static void femu_test_pause_mmio(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    FemuPauseDeadline d = { 0 };
    GThread *watchdog;
    uint64_t buf = guest_alloc(alloc, 4096);
    NvmeRwCmd rw = { .opcode = NVME_CMD_WRITE, .nsid = cpu_to_le32(1),
                     .nlb = cpu_to_le16(7),
                     .dptr.prp1 = cpu_to_le64(0xfed00000) };
    int i;
    int j;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    g_mutex_init(&d.lock);
    g_cond_init(&d.cond);
    watchdog = g_thread_new("pause-timeout", femu_pause_deadline, &d);
    for (i = 0; i < 64; i++) {
        /* HPET registers, then a read that would write the BIOS ROM */
        rw.opcode = i & 1 ? NVME_CMD_READ : NVME_CMD_WRITE;
        rw.dptr.prp1 = cpu_to_le64(i & 1 ? 0xfffc0000 : 0xfed00000);
        for (j = 0; j < 14; j++) {
            femu_submit(&c, &c.io, (NvmeCmd *)&rw);
        }
        g_assert_cmphex(femu_format(&c, 1, 0, 0), ==, NVME_SUCCESS);
        for (j = 0; j < 14; j++) {
            femu_complete(&c, &c.io, NULL, NULL);
        }
    }
    rw.opcode = NVME_CMD_WRITE;
    rw.dptr.prp1 = cpu_to_le64(0xfed00000);
    g_mutex_lock(&d.lock);
    d.done = true;
    g_cond_signal(&d.cond);
    g_mutex_unlock(&d.lock);
    g_thread_join(watchdog);
    g_cond_clear(&d.cond);
    g_mutex_clear(&d.lock);
    g_assert_cmphex(FEMU_SC(femu_io(&c, (NvmeCmd *)&rw)), ==,
                   NVME_DATA_TRAS_ERROR);
    rw.opcode = NVME_CMD_READ;
    g_assert_cmphex(FEMU_SC(femu_io(&c, (NvmeCmd *)&rw)), ==,
                   NVME_DATA_TRAS_ERROR);

    /* a list the bus refuses reads as all ones, never as a register */
    rw.nlb = cpu_to_le16(23);
    rw.dptr.prp1 = cpu_to_le64(buf);
    rw.dptr.prp2 = cpu_to_le64(0xfed00000);
    g_assert_cmphex(FEMU_SC(femu_io(&c, (NvmeCmd *)&rw)), !=, NVME_SUCCESS);

    /* ROM takes no writes, so a read into it would be served as I/O */
    rw.nlb = cpu_to_le16(7);
    rw.dptr.prp1 = cpu_to_le64(0xfffc0000);
    rw.dptr.prp2 = 0;
    g_assert_cmphex(FEMU_SC(femu_io(&c, (NvmeCmd *)&rw)), ==,
                   NVME_DATA_TRAS_ERROR);

    /* memory pointers are unaffected */
    rw.nlb = cpu_to_le16(0);
    rw.dptr.prp1 = cpu_to_le64(buf);
    rw.dptr.prp2 = 0;
    g_assert_cmphex(FEMU_SC(femu_io(&c, (NvmeCmd *)&rw)), ==, NVME_SUCCESS);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * An SGL entry in the controller memory buffer joins the scatter list. The
 * device copies it itself; its own handlers would need the BQL on a poller.
 */
static void femu_test_cmb_sgl(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    NvmeSglDescriptor blk = { 0 };
    uint8_t want[FEMU_DATA_SIZE];
    uint8_t got[FEMU_DATA_SIZE];
    uint64_t buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    QPCIBar cmb;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    cmb = qpci_iomap(&femu->dev, 2, NULL);
    memset(want, 0x6c, sizeof(want));
    qtest_memwrite(qts, cmb.addr, want, sizeof(want));

    blk.addr = cpu_to_le64(cmb.addr);
    blk.len = cpu_to_le32(FEMU_DATA_SIZE);
    g_assert_cmpint(femu_sgl_write(&c, &blk), ==, NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_READ, 0, buf)), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, buf, got, sizeof(got));
    g_assert_cmpmem(got, sizeof(got), want, sizeof(want));

    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static void femu_test_streams_config(void *obj, void *data,
                                   QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    QDict *rsp;
    int modes[] = { 0, 3, 4, 5 };
    int i;

    for (i = 0; i < ARRAY_SIZE(modes); i++) {
        rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                        "'driver':'femu','id':'bad-streams','streams':true,"
                        "'femu_mode':%d,'devsz_mb':64}}", modes[i]);
        g_assert_true(qdict_haskey(rsp, "error"));
        g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                            "desc"), "streams requires"));
        qobject_unref(rsp);
    }
    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'bad-streams','streams':true,"
                    "'femu_mode':2,'devsz_mb':64,'subsys':'fdpsub'}}");
    g_assert_true(qdict_haskey(rsp, "error"));
    g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                        "desc"), "FDP disabled"));
    qobject_unref(rsp);
    for (i = 0; i < 2; i++) {
        rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                        "'driver':'femu','id':'bad-streams','streams':true,"
                        "'femu_mode':2,'devsz_mb':64,'streams.max':%d}}",
                        i ? 33 : 0);
        g_assert_true(qdict_haskey(rsp, "error"));
        g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                            "desc"), "streams.max"));
        qobject_unref(rsp);
    }
    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'good-streams','streams':true,"
                    "'femu_mode':2,'devsz_mb':64,'subsys':'streamsub'}}");
    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'other-streams',"
                    "'femu_mode':2,'devsz_mb':64,'subsys':'streamsub'}}");
    g_assert_true(qdict_haskey(rsp, "error"));
    g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                        "desc"), "single controller"));
    qobject_unref(rsp);
}

#define FEMU_CXL_MACHINE \
    "-machine q35,cxl=on -m 128M " \
    "-device pxb-cxl,id=cxl.0,bus=pcie.0,bus_nr=52 " \
    "-M cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.size=256M " \
    "-device cxl-rp,id=rp0,bus=cxl.0,chassis=0,slot=0 " \
    "-object memory-backend-ram,id=mem,size=256M "

static void femu_test_cxl_realize(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem");
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                         "'path':'/machine/peripheral/ssd',"
                         "'property':'cache-pages'}}");

    g_assert_true(qdict_haskey(rsp, "return"));
    g_assert_cmpuint(qdict_get_int(rsp, "return"), ==, 1024);
    qobject_unref(rsp);
    qtest_quit(qts);
}

/* Add a device on rp0; Type-3 also maps persistent and DC backends. */
static QDict *femu_cxl_add(QTestState *qts, const char *id, const char *cdat)
{
    QDict *args = qdict_new();

    qdict_put_str(args, "driver", "femu-cxl-ssd");
    qdict_put_str(args, "id", id);
    qdict_put_str(args, "bus", "rp0");
    qdict_put_str(args, "volatile-memdev", "mem");
    if (cdat) {
        qdict_put_str(args, "cdat", cdat);
    }
    return qtest_qmp(qts, "{'execute':'device_add','arguments':%p}", args);
}

static void femu_test_cxl_realize_retry(void *obj, void *data,
                                       QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device cxl-rp,id=rp1,bus=cxl.0,chassis=0,slot=1");
    QDict *rsp;
    g_autofree char *cdat = NULL;
    int fd = g_file_open_tmp("femu-cdat-XXXXXX", &cdat, NULL);

    g_assert_cmpint(fd, >=, 0);
    close(fd);
    /* An empty CDAT file fails after the backend has been acquired. */
    rsp = femu_cxl_add(qts, "bad", cdat);
    g_assert_true(qdict_haskey(rsp, "error"));
    qobject_unref(rsp);
    rsp = femu_cxl_add(qts, "ssd", NULL);
    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
    /* A failed second owner must not release the first owner's backend. */
    for (int i = 0; i < 2; i++) {
        rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                       "'driver':'femu-cxl-ssd','id':'other','bus':'rp1',"
                       "'volatile-memdev':'mem'}}");
        g_assert_true(qdict_haskey(rsp, "error"));
        g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                            "desc"), "multiple times"));
        qobject_unref(rsp);
    }
    qtest_quit(qts);
    unlink(cdat);
}

static uint64_t femu_cxl_stat(QTestState *qts, const char *name)
{
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                          "'path':'/machine/peripheral/ssd',"
                          "'property':%s}}", name);
    uint64_t value;

    g_assert_true(qdict_haskey(rsp, "return"));
    value = qdict_get_int(rsp, "return");
    qobject_unref(rsp);
    return value;
}

static void femu_cxl_config(QTestState *qts, unsigned bus,
                             unsigned offset, uint32_t value)
{
    qtest_outl(qts, 0xcf8, 0x80000000u | (bus << 16) | offset);
    qtest_outl(qts, 0xcfc, value);
}

#define FEMU_CXL_WINDOW 0x110000000ULL
#define FEMU_CXL_REGS   0x90001000ULL

static void femu_cxl_decode(QTestState *qts)
{
    femu_cxl_config(qts, 52, PCI_PRIMARY_BUS, 0x00353534);
    femu_cxl_config(qts, 52, PCI_MEMORY_BASE, 0x90009000);
    femu_cxl_config(qts, 52, PCI_COMMAND, PCI_COMMAND_MEMORY);
    femu_cxl_config(qts, 53, 0x10, 0x90000000);
    femu_cxl_config(qts, 53, 0x14, 0);
    femu_cxl_config(qts, 53, PCI_COMMAND, PCI_COMMAND_MEMORY);
    qtest_writel(qts, FEMU_CXL_REGS + A_CXL_HDM_DECODER0_BASE_LO,
                 FEMU_CXL_WINDOW & 0xffffffff);
    qtest_writel(qts, FEMU_CXL_REGS + A_CXL_HDM_DECODER0_BASE_HI,
                 FEMU_CXL_WINDOW >> 32);
    qtest_writel(qts, FEMU_CXL_REGS + A_CXL_HDM_DECODER0_SIZE_LO, 0x10000000);
    qtest_writel(qts, FEMU_CXL_REGS + A_CXL_HDM_DECODER0_SIZE_HI, 0);
    qtest_writel(qts, FEMU_CXL_REGS + A_CXL_HDM_DECODER0_CTRL, 0x200);
    g_assert_cmphex(qtest_readl(qts,
                   FEMU_CXL_REGS + A_CXL_HDM_DECODER0_CTRL) & 0x400, ==, 0x400);
}

static void femu_cxl_unplug(QTestState *qts)
{
    uint8_t cap;
    QDict *rsp;

    qtest_outl(qts, 0xcf8, 0x80340000 | PCI_CAPABILITY_LIST);
    cap = qtest_inb(qts, 0xcfc);
    while (cap) {
        qtest_outl(qts, 0xcf8, 0x80340000 | cap);
        if (qtest_inb(qts, 0xcfc) == PCI_CAP_ID_EXP) {
            break;
        }
        cap = qtest_inb(qts, 0xcfd);
    }
    g_assert_cmpuint(cap, !=, 0);
    qtest_qmp_assert_success(qts, "{'execute':'device_del',"
                            "'arguments':{'id':'ssd'}}");
    /* Acknowledge removal by switching off the root port slot. */
    femu_cxl_config(qts, 52, cap + PCI_EXP_SLTCTL,
                    PCI_EXP_SLTCTL_PCC | PCI_EXP_SLTCTL_PWR_IND_OFF);
    rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                   "'path':'/machine/peripheral/ssd','property':'realized'}}");
    g_assert_true(qdict_haskey(rsp, "error"));
    qobject_unref(rsp);
}

static void femu_test_cxl_bg_unplug(void *obj, void *data,
                                   QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-global cxl-rp.power_controller_present=on "
        "-global ICH9-LPC.acpi-pci-hotplug-with-bridge-support=off "
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem");
    uint64_t mbox = 0x90010000 + CXL_MAILBOX_REGISTERS_OFFSET;

    femu_cxl_decode(qts);
    femu_cxl_config(qts, 53, 0x18, 0x90010000);
    femu_cxl_config(qts, 53, 0x1c, 0);
    /* Sanitize one range, leaving command-owned state pending at unplug. */
    qtest_writeq(qts, mbox + CXL_MAILBOX_REGISTERS_SIZE, 0x100000001ULL);
    qtest_writeq(qts, mbox + CXL_MAILBOX_REGISTERS_SIZE + 8, 0);
    qtest_writeq(qts, mbox + CXL_MAILBOX_REGISTERS_SIZE + 16, 0x10000000);
    qtest_writeq(qts, mbox + A_CXL_DEV_MAILBOX_CMD, (24ULL << 16) | 0x4402);
    qtest_writel(qts, mbox + A_CXL_DEV_MAILBOX_CTRL, 1);
    g_assert_cmphex(qtest_readq(qts, mbox + A_CXL_DEV_MAILBOX_STS) >> 32,
                    ==, CXL_MBOX_BG_STARTED);
    if (data == (void *)2) {
        qtest_qmp_assert_success(qts, "{'execute':'system_reset'}");
        qtest_qmp_eventwait(qts, "RESET");
        femu_cxl_decode(qts);
    }
    femu_cxl_unplug(qts);
    qtest_clock_step(qts, 60 * NANOSECONDS_PER_SECOND);
    qtest_quit(qts);
}

static void femu_test_cxl_window(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    const char *options = data;
    g_autofree char *args = g_strdup_printf(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,%s", options);
    QTestState *qts = qtest_init(args);
    QDict *rsp;
    unsigned i;
    uint64_t ns;

    femu_cxl_decode(qts);
    for (i = 0; i < 32; i++) {
        qtest_writeq(qts, FEMU_CXL_WINDOW + i * 4096, 0x123456780000ULL + i);
    }
    for (i = 0; i < 32; i++) {
        g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW + i * 4096), ==,
                         0x123456780000ULL + i);
    }
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-evictions"), >, 0);
    ns = femu_cxl_stat(qts, "media-time-ns");
    g_assert_cmpuint(ns, >=, 200000);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-writes"), >=, 16);
    rsp = qtest_qmp(qts, "{'execute':'qom-set','arguments':{"
                    "'path':'/machine/peripheral/ssd',"
                    "'property':'flush-cache','value':true}}");
    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
    qtest_quit(qts);
}

static void femu_cxl_set(QTestState *qts, const char *name, bool value)
{
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-set','arguments':{"
                          "'path':'/machine/peripheral/ssd',"
                          "'property':%s,'value':%i}}", name, value);

    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
}

static void femu_test_cxl_local_overlay(void *obj, void *data,
                                        QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem");
    QDict *rsp;

    femu_cxl_decode(qts);
    rsp = qtest_qmp(qts, "{'execute':'human-monitor-command',"
                          "'arguments':{'command-line':'info mtree'}}");

    g_assert_nonnull(strstr(qdict_get_str(rsp, "return"), "femu-cxl-media"));
    g_assert_nonnull(strstr(qdict_get_str(rsp, "return"),
                            "femu-cxl-component"));
    qobject_unref(rsp);
    femu_cxl_decode(qts);
    qtest_writeq(qts, FEMU_CXL_WINDOW, 0x12345678);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 0x12345678);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-inserts"), ==, 1);
    femu_cxl_set(qts, "realized", false);
    rsp = qtest_qmp(qts, "{'execute':'human-monitor-command',"
                    "'arguments':{'command-line':'info mtree'}}");
    g_assert_null(strstr(qdict_get_str(rsp, "return"), "femu-cxl-media"));
    qobject_unref(rsp);
    qtest_quit(qts);
}

static void femu_test_cxl_stale_translation(void *obj, void *data,
                                            QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(
        "-machine q35,cxl=on -m 128M "
        "-device pxb-cxl,id=cxl.0,bus=pcie.0,bus_nr=52 "
        "-M cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.size=256M "
        "-device cxl-rp,id=rp0,bus=cxl.0,chassis=0,slot=0 "
        "-object memory-backend-ram,id=mem,size=512M "
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem");

    femu_cxl_decode(qts);
    qtest_writeq(qts, FEMU_CXL_WINDOW, 0xfeed);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-inserts"), ==, 1);
    /* Change to another valid DPA between translation and revalidation. */
    femu_cxl_set(qts, "test-change-dpa", true);
    qtest_readq(qts, FEMU_CXL_WINDOW);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-inserts"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-hits"), ==, 0);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-inserts"), ==, 2);
    qtest_quit(qts);
}

static void femu_test_cxl_topology(void *obj, void *data,
                                   QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(
        "-machine q35,cxl=on -m 128M "
        "-device pxb-cxl,id=cxl.0,bus=pcie.0,bus_nr=52 "
        "-device pxb-cxl,id=cxl.1,bus=pcie.0,bus_nr=60 "
        "-M cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.targets.1=cxl.1,"
        "cxl-fmw.0.size=256M "
        "-device cxl-rp,id=rp0,bus=cxl.0,chassis=0,slot=0 "
        "-object memory-backend-ram,id=mem,size=256M");
    QDict *rsp = femu_cxl_add(qts, "ssd", NULL);

    g_assert_true(qdict_haskey(rsp, "error"));
    g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                        "desc"), "single-target"));
    qobject_unref(rsp);
    qtest_quit(qts);
}

static void femu_test_cxl_forward(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem "
        "-device cxl-rp,id=rp1,bus=cxl.0,chassis=0,slot=1,port=1,addr=1 "
        "-object memory-backend-ram,id=plain,size=256M "
        "-device cxl-type3,id=plain-dev,bus=rp1,volatile-memdev=plain");
    uint64_t host = 0x100001000ULL;
    uint64_t plain = 0x90201000ULL;
    uint64_t hits;
    uint64_t misses;
    QDict *rsp;

    femu_cxl_decode(qts);
    /* Route the second root port and its endpoint register space. */
    qtest_outl(qts, 0xcf8, 0x80340800 | PCI_PRIMARY_BUS);
    qtest_outl(qts, 0xcfc, 0x00363634);
    qtest_outl(qts, 0xcf8, 0x80340800 | PCI_MEMORY_BASE);
    qtest_outl(qts, 0xcfc, 0x90209020);
    qtest_outl(qts, 0xcf8, 0x80340800 | PCI_COMMAND);
    qtest_outl(qts, 0xcfc, PCI_COMMAND_MEMORY);
    femu_cxl_config(qts, 54, 0x10, plain - 0x1000);
    femu_cxl_config(qts, 54, 0x14, 0);
    femu_cxl_config(qts, 54, PCI_COMMAND, PCI_COMMAND_MEMORY);
    qtest_writel(qts, plain + A_CXL_HDM_DECODER0_BASE_LO,
                 FEMU_CXL_WINDOW & 0xffffffff);
    qtest_writel(qts, plain + A_CXL_HDM_DECODER0_BASE_HI,
                 FEMU_CXL_WINDOW >> 32);
    qtest_writel(qts, plain + A_CXL_HDM_DECODER0_SIZE_LO, 0x10000000);
    qtest_writel(qts, plain + A_CXL_HDM_DECODER0_CTRL, 0x200);
    qtest_writel(qts, host + A_CXL_HDM_DECODER0_BASE_LO,
                 FEMU_CXL_WINDOW & 0xffffffff);
    qtest_writel(qts, host + A_CXL_HDM_DECODER0_BASE_HI, FEMU_CXL_WINDOW >> 32);
    qtest_writel(qts, host + A_CXL_HDM_DECODER0_SIZE_LO, 0x10000000);
    qtest_writel(qts, host + A_CXL_HDM_DECODER0_TARGET_LIST_LO, 0);
    qtest_writel(qts, host + A_CXL_HDM_DECODER0_CTRL, 0x200);
    qtest_writeq(qts, FEMU_CXL_WINDOW, 0xfeed);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 0xfeed);
    hits = femu_cxl_stat(qts, "cache-hits");
    misses = femu_cxl_stat(qts, "cache-misses");
    qtest_writel(qts, host + A_CXL_HDM_DECODER0_TARGET_LIST_LO, 1);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 0);
    qtest_writeq(qts, FEMU_CXL_WINDOW, 0xcafe);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 0xcafe);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-hits"), ==, hits);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-misses"), ==, misses);
    qtest_writel(qts, host + A_CXL_HDM_DECODER0_TARGET_LIST_LO, 0);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 0xfeed);
    rsp = qtest_qmp(qts, "{'execute':'human-monitor-command',"
                    "'arguments':{'command-line':'info mtree'}}");
    g_assert_nonnull(strstr(qdict_get_str(rsp, "return"), "femu-cxl-media"));
    qobject_unref(rsp);
    qtest_quit(qts);
}

static void femu_test_cxl_slot_reservation(void *obj, void *data,
                                           QGuestAllocator *alloc)
{
    QTestState *qts;
    QDict *rsp;

    if (!qtest_has_accel("kvm") || access("/dev/kvm", R_OK | W_OK)) {
        g_test_skip("KVM is unavailable");
        return;
    }
    qts = qtest_init(FEMU_CXL_MACHINE "-accel kvm -S "
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem");
    rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                   "'path':'/machine/peripheral/ssd',"
                   "'property':'test-slot-reservation'}}");
    g_assert_true(qdict_haskey(rsp, "return"));
    g_assert_true(qdict_get_bool(rsp, "return"));
    qobject_unref(rsp);
    qtest_quit(qts);
}

static void femu_test_cxl_flush(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem");

    femu_cxl_decode(qts);
    qtest_writeq(qts, FEMU_CXL_WINDOW, 0x1234);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-writes"), ==, 0);
    femu_cxl_set(qts, "flush-cache", true);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-writes"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-time-ns"), >=, 200000);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 0x1234);
    femu_cxl_set(qts, "flush-cache", true);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-writes"), ==, 1);
    qtest_quit(qts);
}

static void femu_test_cxl_der(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "cache-pages=1,cache-ways=1,der=memslot");
    uint64_t hits;
    QDict *rsp;

    g_assert_cmpuint(femu_cxl_stat(qts, "der-probes"), ==, 0);
    femu_cxl_decode(qts);
    qtest_writeq(qts, FEMU_CXL_WINDOW, 0xfeed);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 0xfeed);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 1);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 0xfeed);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 1);
    /* PCI configuration and mailbox commands revoke live mappings too. */
    femu_cxl_config(qts, 53, PCI_COMMAND, PCI_COMMAND_MEMORY);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 0);
    femu_cxl_config(qts, 53, 0x18, 0x90010000);
    femu_cxl_config(qts, 53, 0x1c, 0);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 0xfeed);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 1);
    qtest_writeq(qts, 0x90010000 + CXL_MAILBOX_REGISTERS_OFFSET +
                 A_CXL_DEV_MAILBOX_CMD, 0x4000);
    qtest_writel(qts, 0x90010000 + CXL_MAILBOX_REGISTERS_OFFSET +
                 A_CXL_DEV_MAILBOX_CTRL, 1);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 0);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 0xfeed);
    hits = femu_cxl_stat(qts, "cache-hits");
    qtest_writeq(qts, FEMU_CXL_WINDOW, 0xbeef);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 0xbeef);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-hits"), ==, hits);
    qtest_writeq(qts, FEMU_CXL_WINDOW + 4096, 0xcafe);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-writes"), ==, 1);
    femu_cxl_set(qts, "flush-cache", true);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 0);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 0xbeef);
    qtest_writel(qts, FEMU_CXL_REGS + A_CXL_HDM_DECODER0_CTRL, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 0);
    femu_cxl_decode(qts);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 0xbeef);
    rsp = qtest_qmp(qts, "{'execute':'system_reset'}");
    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
    qtest_qmp_eventwait(qts, "RESET");
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-probes"), ==, 0);
    femu_cxl_decode(qts);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 0xbeef);
    femu_cxl_set(qts, "realized", false);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-remaps"), >=, 4);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-revocations"), ==,
                     femu_cxl_stat(qts, "der-remaps"));
    g_assert_cmpuint(femu_cxl_stat(qts, "der-fallbacks"), ==, 0);
    qtest_quit(qts);
}

static void femu_test_cxl_der_modes(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    const char *mode = data;
    g_autofree char *log = g_strdup("der-stderr-XXXXXX");
    g_autofree char *quoted = NULL;
    g_autofree char *stderr_text = NULL;
    int fd = g_mkstemp(log);
    bool cylon = !strcmp(mode, "cylon");
    g_autofree char *args;
    QTestState *qts;
    QDict *rsp;
    const char *warning;

    g_assert_cmpint(fd, >=, 0);
    close(fd);
    quoted = g_shell_quote(log);
    args = g_strdup_printf(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem%s%s%s 2>%s",
        *mode ? ",der=" : "", mode,
        cylon ? ",cylon-kernel-ack=on" : "", quoted);
    qts = qtest_init(args);
    rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                          "'path':'/machine/peripheral/ssd',"
                          "'property':'der-active'}}");

    g_assert_true(qdict_haskey(rsp, "return"));
    g_assert_false(qdict_get_bool(rsp, "return"));
    qobject_unref(rsp);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-probes"), ==, cylon);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-fallbacks"), ==, cylon);
    femu_cxl_decode(qts);
    qtest_writeq(qts, FEMU_CXL_WINDOW, 0xfeed);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 0xfeed);
    femu_cxl_set(qts, "flush-cache", true);
    femu_cxl_decode(qts);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 0xfeed);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-remaps"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-revocations"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-probes"), ==, cylon);
    rsp = qtest_qmp(qts, "{'execute':'qom-set','arguments':{"
                    "'path':'/machine/peripheral/ssd',"
                    "'property':'der-active','value':true}}");
    g_assert_true(qdict_haskey(rsp, "error"));
    qobject_unref(rsp);
    qtest_quit(qts);
    g_assert_true(g_file_get_contents(log, &stderr_text, NULL, NULL));
    warning = strstr(stderr_text, "FEMU CXL DER unavailable");
    if (cylon) {
        g_assert_nonnull(warning);
        g_assert_null(strstr(warning + 1, "FEMU CXL DER unavailable"));
    } else {
        g_assert_null(warning);
    }
    unlink(log);
}

static void femu_test_cxl_der_invalid(void *obj, void *data,
                                      QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE);
    const char *values[] = { "on", "unknown", "" };
    unsigned i;

    for (i = 0; i < G_N_ELEMENTS(values); i++) {
        QDict *rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
            "'driver':'femu-cxl-ssd','id':'bad','bus':'rp0',"
            "'volatile-memdev':'mem','der':%s}}", values[i]);

        g_assert_true(qdict_haskey(rsp, "error"));
        g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                            "desc"), "der must be"));
        qobject_unref(rsp);
    }
    qtest_quit(qts);
}

static void femu_test_cxl_cylon_ack(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE);
    QDict *rsp = qtest_qmp(qts,
        "{'execute':'device_add','arguments':{'driver':'femu-cxl-ssd',"
        "'id':'bad','bus':'rp0','volatile-memdev':'mem','der':'cylon'}}");

    g_assert_true(qdict_haskey(rsp, "error"));
    g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                        "desc"), "cylon-kernel-ack"));
    qobject_unref(rsp);
    qtest_quit(qts);
}

/* A real vCPU writes CXL while qtest observes RAM under the BQL. */
static void femu_test_cxl_wait(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    static const uint8_t reset[] = {
        0xfa, 0x31, 0xc0, 0x8e, 0xd8, 0x0f, 0x01, 0x16, 0x00, 0x05, 0x0f, 0x20,
        0xc0, 0x66, 0x83, 0xc8, 0x01, 0x0f, 0x22, 0xc0, 0x66, 0xea, 0x00, 0x10,
        0x00, 0x00, 0x08, 0x00,
    };
    /* Enable PAE/LME/paging, then jump to the 64-bit code at 0x1100. */
    static const uint8_t setup[] = {
        0x0f, 0x20, 0xe0, 0x83, 0xc8, 0x20, 0x0f, 0x22, 0xe0, 0xb8, 0x00, 0x20,
        0x00, 0x00, 0x0f, 0x22, 0xd8, 0xb9, 0x80, 0x00, 0x00, 0xc0, 0x0f, 0x32,
        0x0d, 0x00, 0x01, 0x00, 0x00, 0x0f, 0x30, 0x0f, 0x20, 0xc0, 0x0d, 0x00,
        0x00, 0x00, 0x80, 0x0f, 0x22, 0xc0, 0xea, 0x00, 0x11, 0x00, 0x00, 0x18,
        0x00,
    };
    /* Set RAM marker, write CXL, set completion marker, halt. */
    static const uint8_t access[] = {
        0xb8, 0x10, 0x00, 0x00, 0x00, 0x8e, 0xd8, 0x8e, 0xd0, 0x48, 0xb8, 0x00,
        0x00, 0x00, 0x10, 0x01, 0x00, 0x00, 0x00, 0xc6, 0x04, 0x25, 0x00, 0x60,
        0x00, 0x00, 0x01, 0xc6, 0x00, 0x5a, 0xc6, 0x04, 0x25, 0x00, 0x60, 0x00,
        0x00, 0x02, 0xf4, 0xeb, 0xfd,
    };
    /*
     * Wait for the test and write PCI_COMMAND. Spin for 2^25 iterations so
     * the media write, if already released, has marked completion; then copy
     * its marker to 0x6003 and mark completion.
     */
    static const uint8_t ap[] = {
        0xfa, 0x31, 0xc0, 0x8e, 0xd8, 0xc6, 0x06, 0x01, 0x60, 0x01, 0x80, 0x3e,
        0x02, 0x60, 0x01, 0x75, 0xf9, 0xba, 0xf8, 0x0c, 0x66, 0xb8, 0x04, 0x00,
        0x35, 0x80, 0x66, 0xef, 0xba, 0xfc, 0x0c, 0x66, 0xb8, 0x02, 0x00, 0x00,
        0x00, 0x66, 0xef, 0x66, 0xb9, 0x00, 0x00, 0x00, 0x02, 0x66, 0x49, 0x75,
        0xfc, 0xa0, 0x00, 0x60, 0xa2, 0x03, 0x60, 0xc6, 0x06, 0x01, 0x60, 0x02,
        0xf4, 0xeb, 0xfd,
    };
    /* Start AP at 0x7000, then jump to the media write at 0x1100. */
    static const uint8_t sipi[] = {
        0xbb, 0x00, 0x00, 0xe0, 0xfe, 0xc7, 0x83, 0x10, 0x03, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0xc7, 0x83, 0x00, 0x03, 0x00, 0x00, 0x00, 0xc5, 0x00,
        0x00, 0xc7, 0x83, 0x00, 0x03, 0x00, 0x00, 0x07, 0x06, 0x00, 0x00, 0xe9,
        0xd8, 0xfe, 0xff, 0xff,
    };
    g_autofree char *rom_path = g_strdup("cxl-wait-rom-XXXXXX");
    g_autofree char *quoted = NULL;
    g_autofree uint8_t *rom = g_malloc0(65536);
    int fd = g_mkstemp(rom_path);
    QTestState *qts;
    int64_t deadline;
    bool invalidate = data == (void *)2;

    g_assert_cmpint(fd, >=, 0);
    memcpy(rom, reset, sizeof(reset));
    /* Reset vector: far jump to f000:0000. */
    memcpy(rom + 65520, (uint8_t[]) { 0xea, 0, 0, 0, 0xf0 }, 5);
    g_assert_cmpint(write(fd, rom, 65536), ==, 65536);
    close(fd);
    quoted = g_shell_quote(rom_path);
    qts = qtest_initf(FEMU_CXL_MACHINE
        "-accel tcg,thread=multi -S -bios %s -smp %u "
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "cache-pages=0,program-ns=1000000000", quoted, invalidate ? 2 : 1);
    femu_cxl_decode(qts);
    qtest_writew(qts, 0x500, 31);
    qtest_writel(qts, 0x502, 0x508);
    qtest_writeq(qts, 0x508, 0);
    qtest_writeq(qts, 0x510, 0x00cf9a000000ffffULL);
    qtest_writeq(qts, 0x518, 0x00cf92000000ffffULL);
    qtest_writeq(qts, 0x520, 0x00af9a000000ffffULL);
    qtest_memwrite(qts, 0x1000, setup, sizeof(setup));
    qtest_memwrite(qts, 0x1100, access, sizeof(access));
    qtest_writeq(qts, 0x2000, 0x3003);
    qtest_writeq(qts, 0x3000, 0x4003);
    qtest_writeq(qts, 0x3020, 0x5003);
    qtest_writeq(qts, 0x4000, 0x83);
    qtest_writeq(qts, 0x5400, FEMU_CXL_WINDOW | 0x83);
    if (invalidate) {
        /* Map the local APIC and redirect the long-mode entry to INIT/SIPI. */
        qtest_writeq(qts, 0x3018, 0x8003);
        qtest_writeq(qts, 0x8fb8, 0xfee00083);
        qtest_writeb(qts, 0x1000 + sizeof(setup) - 5, 0x12);
        qtest_memwrite(qts, 0x1200, sipi, sizeof(sipi));
        qtest_memwrite(qts, 0x7000, ap, sizeof(ap));
    }
    qtest_qmp_assert_success(qts, "{'execute':'cont'}");
    deadline = g_get_monotonic_time() + 10 * G_TIME_SPAN_SECOND;
    while (!femu_cxl_stat(qts, "media-writes")) {
        g_assert_cmpint(g_get_monotonic_time(), <, deadline);
        g_usleep(1000);
    }
    /* With the BQL held during sleep this can only see completion (2). */
    g_assert_cmpuint(qtest_readb(qts, 0x6000), ==, 1);
    if (invalidate) {
        /* The AP may still be starting while the media write sleeps. */
        while (qtest_readb(qts, 0x6001) != 1) {
            g_assert_cmpint(g_get_monotonic_time(), <, deadline);
            g_usleep(1000);
        }
        qtest_writeb(qts, 0x6002, 1);
        while (!femu_cxl_stat(qts, "invalidation-waiters")) {
            g_assert_cmpint(g_get_monotonic_time(), <, deadline);
            g_usleep(1000);
        }
        g_assert_cmpuint(qtest_readb(qts, 0x6000), ==, 1);
        g_assert_cmpuint(qtest_readb(qts, 0x6001), ==, 1);
        /*
         * Unrealize must release the blocked config write and let it finish
         * before PCI teardown, while the media write still holds the gate.
         */
        femu_cxl_set(qts, "realized", false);
        while (qtest_readb(qts, 0x6001) != 2) {
            g_assert_cmpint(g_get_monotonic_time(), <, deadline);
            g_usleep(1000);
        }
        g_assert_cmpuint(qtest_readb(qts, 0x6003), ==, 1);
    } else if (data) {
        /* A concurrent access must queue, not trip the IO recursion guard. */
        g_assert_cmpuint(qtest_readb(qts, FEMU_CXL_WINDOW), ==, 0x5a);
    }
    if (!invalidate) {
        femu_cxl_set(qts, "realized", false);
    }
    while (qtest_readb(qts, 0x6000) != 2) {
        g_assert_cmpint(g_get_monotonic_time(), <, deadline);
        g_usleep(1000);
    }
    qtest_quit(qts);
    unlink(rom_path);
}

static void femu_test_cxl_no_ftl(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "ftl=off,der=off,cache-pages=0");

    femu_cxl_decode(qts);
    qtest_writeq(qts, FEMU_CXL_WINDOW + 4092, 0x1122334455667788ULL);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW + 4092), ==,
                     0x1122334455667788ULL);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-time-ns"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-writes"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-probes"), ==, 0);
    qtest_quit(qts);
}

static void femu_test_cxl_invalid(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    static const struct {
        const char *args;
        const char *error;
    } cases[] = {
        { "'cache-policy':'unknown'", "cache-policy must be" },
        { "'cache-ways':0", "cache-ways (1..1024)" },
        { "'cache-pages':17,'cache-ways':16", "divisible" },
        { "'cache-pages':65537,'cache-ways':1", "fit the media" },
        { "'program-ns':1000000001", "at most one second" },
        { "'num-dc-regions':1", "requires only volatile-memdev" },
    };
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE);
    unsigned i;

    for (i = 0; i < G_N_ELEMENTS(cases); i++) {
        g_autofree char *cmd = g_strdup_printf(
            "{'execute':'device_add','arguments':{'driver':'femu-cxl-ssd',"
            "'id':'ssd','bus':'rp0','volatile-memdev':'mem',%s}}",
            cases[i].args);
        QDict *rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));

        g_assert_true(qdict_haskey(rsp, "error"));
        g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                             "desc"), cases[i].error));
        qobject_unref(rsp);
    }
    qtest_quit(qts);
}

static void femu_cxl_number(QTestState *qts, const char *name, uint64_t value,
                            bool success)
{
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-set','arguments':{"
                          "'path':'/machine/peripheral/ssd',"
                          "'property':%s,'value':%llu}}", name,
                          (unsigned long long)value);

    g_assert_true(qdict_haskey(rsp, success ? "return" : "error"));
    qobject_unref(rsp);
}

static void femu_test_cxl_prefetch(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem");

    femu_cxl_decode(qts);
    femu_cxl_number(qts, "prefetch-degree", 3, true);
    femu_cxl_number(qts, "prefetch-stride", 2, true);
    qtest_readq(qts, FEMU_CXL_WINDOW);
    g_assert_cmpuint(femu_cxl_stat(qts, "prefetch-inserts"), ==, 3);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-reads"), ==, 1);
    qtest_readq(qts, FEMU_CXL_WINDOW + 2 * 4096);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-hits"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(qts, "prefetch-inserts"), ==, 3);
    qtest_readq(qts, FEMU_CXL_WINDOW + 1 * 4096);
    g_assert_cmpuint(femu_cxl_stat(qts, "prefetch-inserts"), ==, 4);
    qtest_readq(qts, FEMU_CXL_WINDOW + 65535 * 4096);
    g_assert_cmpuint(femu_cxl_stat(qts, "prefetch-inserts"), ==, 4);
    femu_cxl_number(qts, "prefetch-degree", UINT64_MAX, false);
    femu_cxl_number(qts, "prefetch-stride", UINT64_MAX, false);
    femu_cxl_number(qts, "prefetch-degree", 0, true);
    qtest_quit(qts);
}

static void femu_test_cxl_stats(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem");

    femu_cxl_decode(qts);
    qtest_readq(qts, FEMU_CXL_WINDOW);
    qtest_readq(qts, FEMU_CXL_WINDOW);
    qtest_writeq(qts, FEMU_CXL_WINDOW, 42);
    qtest_writeq(qts, FEMU_CXL_WINDOW + 4096, 43);
    g_assert_cmpuint(femu_cxl_stat(qts, "read-hits"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(qts, "read-misses"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(qts, "write-hits"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(qts, "write-misses"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-entries"), ==, 2);
    femu_cxl_set(qts, "stats-reset", true);
    g_assert_cmpuint(femu_cxl_stat(qts, "read-hits"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "write-misses"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-inserts"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-entries"), ==, 2);
    qtest_quit(qts);
}

static void femu_test_cxl_ways(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    const char *policy = data;
    g_autofree char *args = g_strdup_printf(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "cache-pages=2048,cache-policy=%s", policy);
    QTestState *qts = qtest_init(args);

    femu_cxl_decode(qts);
    qtest_writeq(qts, FEMU_CXL_WINDOW, 42);
    femu_cxl_number(qts, "cache-ways", 2048, true);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-writes"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-entries"), ==, 0);
    g_assert_cmpuint(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 42);
    femu_cxl_number(qts, "cache-ways", 1, true);
    femu_cxl_number(qts, "cache-ways", 0, false);
    femu_cxl_number(qts, "cache-ways", 3, false);
    femu_cxl_number(qts, "cache-ways", 4096, false);
    qtest_quit(qts);
}

static void femu_test_cxl_capacity(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QTestState *qts;
    unsigned sizes[] = { 48, 96, 120 };
    unsigned i;

    for (i = 0; i < G_N_ELEMENTS(sizes); i++) {
        QDict *rsp;

        qts = qtest_init(FEMU_CXL_MACHINE);
        qtest_qmp_assert_success(qts, "{'execute':'object-add','arguments':{"
            "'qom-type':'memory-backend-ram','id':'large',"
            "'reserve':false,'size':%llu}}",
            (unsigned long long)sizes[i] * (1ULL << 30));
        rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
            "'driver':'femu-cxl-ssd','id':'ssd','bus':'rp0',"
            "'volatile-memdev':'large','ftl':false,"
            "'channels':8,'luns-per-channel':8}}");
        g_assert_true(qdict_haskey(rsp, "return"));
        qobject_unref(rsp);
        qtest_quit(qts);
    }
}

static void femu_test_cxl_geometry_bounds(void *obj, void *data,
                                         QGuestAllocator *alloc)
{
    static const char * const options[] = {
        "'channels':0", "'channels':4097", "'luns-per-channel':129",
        "'luns-per-channel':0", "'pages-per-block':0",
        "'pages-per-block':65537", "'blocks-per-plane':65537",
        "'blocks-per-plane':1", "'gc-threshold':0",
        "'gc-threshold':101", "'gc-threshold-high':74",
        "'gc-threshold-high':101", "'channel-ns':1000000001",
    };
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE);
    unsigned i;

    for (i = 0; i < G_N_ELEMENTS(options); i++) {
        g_autofree char *cmd = g_strdup_printf(
            "{'execute':'device_add','arguments':{'driver':'femu-cxl-ssd',"
            "'id':'ssd','bus':'rp0','volatile-memdev':'mem',%s}}", options[i]);
        QDict *rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));

        g_assert_true(qdict_haskey(rsp, "error"));
        g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                             "desc"), "NAND geometry"));
        qobject_unref(rsp);
    }
    qtest_quit(qts);
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

    qos_add_test("cxl-capacity", "femu", femu_test_cxl_capacity, NULL);
    qos_add_test("cxl-geometry-bounds", "femu", femu_test_cxl_geometry_bounds,
                 NULL);
    qos_add_test("cxl-prefetch", "femu", femu_test_cxl_prefetch, NULL);
    qos_add_test("cxl-stats", "femu", femu_test_cxl_stats, NULL);
    qos_node_create_driver("femu", femu_create);
    qos_add_test("cxl-stale-translation", "femu",
                 femu_test_cxl_stale_translation, NULL);
    qos_add_test("cxl-forward", "femu", femu_test_cxl_forward, NULL);
    qos_add_test("cxl-local-overlay", "femu", femu_test_cxl_local_overlay,
                 NULL);
    qos_add_test("cxl-topology", "femu", femu_test_cxl_topology, NULL);
    qos_add_test("cxl-slot-reservation", "femu",
                 femu_test_cxl_slot_reservation, NULL);
    qos_add_test("cxl-realize-retry", "femu", femu_test_cxl_realize_retry,
                 NULL);
    qos_add_test("cxl-bg-reset-unplug", "femu", femu_test_cxl_bg_unplug,
                 &(QOSGraphTestOptions) { .arg = (void *)2 });
    qos_add_test("cxl-bg-unplug", "femu", femu_test_cxl_bg_unplug,
                 NULL);
    qos_add_test("cxl-realize", "femu", femu_test_cxl_realize, NULL);
    qos_add_test("cxl-flush", "femu", femu_test_cxl_flush, NULL);
    qos_add_test("cxl-der-default", "femu", femu_test_cxl_der_modes,
                 &(QOSGraphTestOptions) { .arg = (void *)"" });
    qos_add_test("cxl-der-off", "femu", femu_test_cxl_der_modes,
                 &(QOSGraphTestOptions) { .arg = (void *)"off" });
    qos_add_test("cxl-der-cylon", "femu", femu_test_cxl_der_modes,
                 &(QOSGraphTestOptions) { .arg = (void *)"cylon" });
    qos_add_test("cxl-der-invalid", "femu", femu_test_cxl_der_invalid, NULL);
    qos_add_test("cxl-der", "femu", femu_test_cxl_der, NULL);
    qos_add_test("cxl-wait-invalidate", "femu", femu_test_cxl_wait,
                 &(QOSGraphTestOptions) { .arg = (void *)2 });
    qos_add_test("cxl-wait", "femu", femu_test_cxl_wait, NULL);
    qos_add_test("cxl-wait-queue", "femu", femu_test_cxl_wait,
                 &(QOSGraphTestOptions) { .arg = (void *)1 });
    qos_add_test("cxl-cylon-ack", "femu", femu_test_cxl_cylon_ack, NULL);
    qos_add_test("cxl-no-ftl", "femu", femu_test_cxl_no_ftl, NULL);
    qos_add_test("cxl-invalid", "femu", femu_test_cxl_invalid, NULL);
    {
        static const char * const policies[] = {
            "fifo", "lifo", "clock", "s3-fifo"
        };
        unsigned i;
        unsigned ways;

        for (i = 0; i < G_N_ELEMENTS(policies); i++) {
            g_autofree char *runtime = g_strdup_printf("cxl-ways-%s",
                                                       policies[i]);

            qos_add_test(runtime, "femu", femu_test_cxl_ways,
                         &(QOSGraphTestOptions) { .arg = (void *)policies[i] });
            for (ways = 1; ways <= 16; ways *= 16) {
                char *name = g_strdup_printf("cxl-%s-%u", policies[i], ways);
                char *options = g_strdup_printf("cache-pages=16,"
                    "cache-ways=%u,cache-policy=%s", ways, policies[i]);

                qos_add_test(name, "femu", femu_test_cxl_window,
                             &(QOSGraphTestOptions) { .arg = options });
                g_free(name);
            }
        }
    }

    qos_node_consumes("femu", "pci-bus", &opts);
    qos_node_produces("femu", "pci-device");

    qos_add_test("hybrid-oracle-sequential", "femu", femu_test_hybrid_trace,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(0),
        .edge.extra_device_opts =
            "serial=hybrid-oracle-sequential,"
            "devsz_mb=4,femu_mode=1,mapping=hybrid,secs_per_pg=8,pgs_per_blk=4,"
            "blks_per_pl=128,pls_per_lun=1,luns_per_ch=2,nchs=2"
    });
    qos_add_test("hybrid-oracle-random", "femu", femu_test_hybrid_trace,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(1),
        .edge.extra_device_opts =
            "serial=hybrid-oracle-random,"
            "devsz_mb=4,femu_mode=1,mapping=hybrid,secs_per_pg=8,pgs_per_blk=4,"
            "blks_per_pl=128,pls_per_lun=1,luns_per_ch=2,nchs=2"
    });
    qos_add_test("hybrid-oracle-hot-offset", "femu", femu_test_hybrid_trace,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(2),
        .edge.extra_device_opts =
            "serial=hybrid-oracle-hot-offset,"
            "devsz_mb=4,femu_mode=1,mapping=hybrid,secs_per_pg=8,pgs_per_blk=4,"
            "blks_per_pl=128,pls_per_lun=1,luns_per_ch=2,nchs=2"
    });
    qos_add_test("hybrid-oracle-pool-pressure", "femu", femu_test_hybrid_trace,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(3),
        .edge.extra_device_opts =
            "serial=hybrid-oracle-pool-pressure,"
            "devsz_mb=4,femu_mode=1,mapping=hybrid,secs_per_pg=8,pgs_per_blk=4,"
            "blks_per_pl=128,pls_per_lun=1,luns_per_ch=2,nchs=2"
    });
    qos_add_test("hybrid-batch-occupancy", "femu", femu_test_hybrid_batch,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "serial=hybrid-batch-occupancy,"
            "devsz_mb=4,femu_mode=1,mapping=hybrid,secs_per_pg=8,pgs_per_blk=4,"
            "blks_per_pl=128,pls_per_lun=1,luns_per_ch=2,nchs=2"
    });
    qos_add_test("hybrid-destage-occupancy", "femu", femu_test_hybrid_batch,
                 &(QOSGraphTestOptions) {
        .arg = GINT_TO_POINTER(1),
        .edge.extra_device_opts =
            "serial=hybrid-destage-occupancy,"
            "devsz_mb=4,femu_mode=1,mapping=hybrid,secs_per_pg=8,pgs_per_blk=4,"
            "blks_per_pl=128,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "vwc=1,buffer_size=16"
    });
    qos_add_test("hybrid-switch-trim-erase", "femu", femu_test_hybrid_trim,
                 &(QOSGraphTestOptions) {
        .arg = GINT_TO_POINTER(1),
        .edge.extra_device_opts =
            "serial=hybrid-switch-trim-erase,"
            "devsz_mb=4,femu_mode=1,mapping=hybrid,secs_per_pg=8,pgs_per_blk=4,"
            "blks_per_pl=128,pls_per_lun=1,luns_per_ch=2,nchs=2"
    });
    qos_add_test("hybrid-trim-occupancy", "femu", femu_test_hybrid_trim,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "serial=hybrid-trim-occupancy,"
            "devsz_mb=4,femu_mode=1,mapping=hybrid,secs_per_pg=8,pgs_per_blk=4,"
            "blks_per_pl=128,pls_per_lun=1,luns_per_ch=2,nchs=2"
    });
    qos_add_test("streams-resources", "femu", femu_test_streams_resources,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "streams=on,streams.max=4,namespaces=2"
    });
    qos_add_test("streams-geometry", "femu", femu_test_streams_resources,
                 &(QOSGraphTestOptions) {
        .arg = GINT_TO_POINTER(1),
        .edge.extra_device_opts =
            "streams=on,streams.max=4,namespaces=2,femu_mode=1,"
            "secs_per_pg=8,pgs_per_blk=32,blks_per_pl=128,"
            "pls_per_lun=1,luns_per_ch=2,nchs=2"
    });
    qos_add_test("streams-write", "femu", femu_test_streams_write,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "streams=on,streams.max=2,namespaces=2"
    });
    qos_add_test("streams-placement", "femu", femu_test_streams_write,
                 &(QOSGraphTestOptions) {
        .arg = GINT_TO_POINTER(1),
        .edge.extra_device_opts =
            "id=streams-test,streams=on,streams.max=2,namespaces=2,"
            "femu_mode=1,secs_per_pg=8,pgs_per_blk=32,blks_per_pl=128,"
            "pls_per_lun=1,luns_per_ch=2,nchs=2"
    });
    qos_add_test("streams-recovery", "femu", femu_test_streams_recovery,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "streams=on,streams.max=2,devsz_mb=1,femu_mode=1,"
            "secs_per_pg=8,pgs_per_blk=4,blks_per_pl=24,"
            "pls_per_lun=1,luns_per_ch=2,nchs=2"
    });
    qos_add_test("streams-subpage", "femu", femu_test_streams_subpage,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=streams-test,streams=on,streams.max=2,devsz_mb=1,"
            "femu_mode=1,secs_per_pg=8,pgs_per_blk=4,blks_per_pl=24,"
            "pls_per_lun=1,luns_per_ch=2,nchs=2"
    });
    qos_add_test("streams-sws", "femu", femu_test_streams_sws,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "streams=on,streams.max=2,devsz_mb=1,femu_mode=1,"
            "secs_per_pg=16,pgs_per_blk=4,blks_per_pl=24,"
            "pls_per_lun=1,luns_per_ch=2,nchs=2"
    });
    qos_add_test("streams-churn", "femu", femu_test_streams_churn,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "streams=on,streams.max=2,devsz_mb=1,femu_mode=1,"
            "secs_per_pg=8,pgs_per_blk=4,blks_per_pl=24,"
            "pls_per_lun=1,luns_per_ch=2,nchs=2"
    });
    qos_add_test("streams-gc", "femu", femu_test_streams_gc,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=streams-test,streams=on,streams.max=2,devsz_mb=1,"
            "femu_mode=1,secs_per_pg=8,pgs_per_blk=4,blks_per_pl=24,"
            "pls_per_lun=1,luns_per_ch=2,nchs=2"
    });
    qos_add_test("streams-config", "femu", femu_test_streams_config,
                 &(QOSGraphTestOptions) {
        .edge.before_cmd_line =
            "-device femu-subsys,id=streamsub,nqn=streamsub"
    });
    qos_add_test("streams-off", "femu", femu_test_streams_identify, NULL);
    qos_add_test("streams-identify", "femu", femu_test_streams_identify,
                 &(QOSGraphTestOptions) {
        .arg = GINT_TO_POINTER(1),
        .edge.extra_device_opts = "streams=on"
    });
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
    qos_add_test("pause-mmio", "femu", femu_test_pause_mmio, NULL);
    qos_add_test("cmb-sgl", "femu", femu_test_cmb_sgl,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "sgl=on,cmbsz=0x400000,cmbloc=2"
    });
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
    qos_add_test("kv-list-mdts0", "femu", femu_test_kv_list_mdts0,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "devsz_mb=512,femu_mode=5,mdts=0"
    });
    qos_add_test("kv-fuzz", "femu", femu_test_kv_fuzz,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "devsz_mb=512,femu_mode=5,sgl=on"
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
    qos_add_test("zone-bad-dptr", "femu", femu_test_zone_bad_dptr,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=3,secsz=512"
    });
    qos_add_test("zrwa-reopen", "femu", femu_test_zrwa_reopen,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=512,femu_mode=3,secsz=512,zns_chnls_per_zone=1,"
            "zns_zrwa_size=128,zns_zrwafg_size=32,zns_zrwa_num=1"
    });
    qos_add_test("zrwa-write-bounds", "femu", femu_test_zrwa_write_bounds,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=512,femu_mode=3,secsz=512,zns_chnls_per_zone=1,"
            "zns_zrwa_size=128,zns_zrwafg_size=32,zns_zrwa_num=1"
    });
    qos_add_test("zrwa-odd-granule", "femu", femu_test_zrwa_odd_granule,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=512,femu_mode=3,secsz=512,zns_chnls_per_zone=1,"
            "zns_zone_cap=3M,zns_zrwa_size=129,zns_zrwafg_size=3,"
            "zns_zrwa_num=1"
    });
    qos_add_test("zrwa-zd-ext", "femu", femu_test_zrwa_zd_ext,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=512,femu_mode=3,secsz=512,zns_chnls_per_zone=1,"
            "zns_zrwa_size=128,zns_zrwafg_size=32,zns_zrwa_num=1,"
            "zns_zd_ext_size=64"
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
    qos_add_test("format-pi-needs-metadata", "femu",
                 femu_test_format_pi_needs_metadata,
                 &(QOSGraphTestOptions) {
        /* Type 1 in either position is advertised; no format has metadata */
        .edge.extra_device_opts = "dpc=0x19"
    });
    qos_add_test("format", "femu", femu_test_format,
                 &(QOSGraphTestOptions) {
        /* start with 4 KiB blocks so a format to 512 grows the block count */
        .edge.extra_device_opts = "lba_index=3"
    });
    qos_add_test("log-pages", "femu", femu_test_log_pages, NULL);
    qos_add_test("get-lba-status", "femu", femu_test_get_lba_status,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "oncs=0x19f"
    });
    qos_add_test("mdts0-reports", "femu", femu_test_mdts0_reports,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "oncs=0x19f,mdts=0"
    });
    qos_add_test("mdts0-zone-report", "femu", femu_test_mdts0_zone_report,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=3,secsz=512,mdts=0"
    });
    qos_add_test("report-zero-tail", "femu", femu_test_report_zero_tail,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,lba_index=3,"
            "subsys=fdpsub",
    });
    qos_add_test("timestamp", "femu", femu_test_timestamp, NULL);
    qos_add_test("persistent-event-log", "femu", femu_test_pel,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "ns_mgmt=on",
        .arg = GUINT_TO_POINTER(1),
    });
    qos_add_test("persistent-event-log-fixed", "femu", femu_test_pel, NULL);
    qos_add_test("ns-mgmt-bbssd-lifecycle", "femu",
                 femu_test_ns_mgmt_commands, &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "ns_mgmt=on,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4",
    });
    qos_add_test("ns-mgmt-bbssd-cap", "femu",
                 femu_test_ns_mgmt_bbssd_cap, &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "ns_mgmt=on,femu_mode=1,namespace_sizes=1M,secsz=512,"
            "secs_per_pg=8,pgs_per_blk=16,blks_per_pl=80,"
            "pls_per_lun=1,luns_per_ch=1,nchs=1",
    });
    qos_add_test("ns-mgmt-bbssd-cap-custom", "femu",
                 femu_test_ns_mgmt_bbssd_cap, &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "ns_mgmt=on,femu_mode=1,bbssd_ns_limit=2,namespace_sizes=1M,"
            "secsz=512,secs_per_pg=8,pgs_per_blk=16,blks_per_pl=80,"
            "pls_per_lun=1,luns_per_ch=1,nchs=1",
        .arg = GUINT_TO_POINTER(2),
    });
    qos_add_test("ns-mgmt-bbssd-boot-cap", "femu",
                 femu_test_ns_mgmt_bbssd_boot_cap, NULL);
    qos_add_test("ns-mgmt-bbssd-isolation", "femu",
                 femu_test_ns_mgmt_bbssd_isolation, &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=ns-test,ns_mgmt=on,femu_mode=1,oacs=0x2,namespaces=2,"
            "namespace_sizes=2M,,2M,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=40,"
            "pls_per_lun=1,luns_per_ch=1,nchs=1",
    });
    qos_add_test("ns-mgmt-bbssd-capacity", "femu",
                 femu_test_ns_mgmt_bbssd_capacity, &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "ns_mgmt=on,femu_mode=1,namespaces=2,namespace_sizes=2M,,2M,"
            "secsz=512,secs_per_pg=8,pgs_per_blk=16,blks_per_pl=40,"
            "pls_per_lun=1,luns_per_ch=1,nchs=1",
    });
    qos_add_test("ns-mgmt-bbssd-retire", "femu",
                 femu_test_ns_retire, &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=ns-test,ns_mgmt=on,femu_mode=1,namespaces=2,buffer_size=16,"
            "secsz=512,secs_per_pg=8,pgs_per_blk=16,blks_per_pl=80,"
            "pls_per_lun=1,luns_per_ch=4,nchs=4",
        .arg = GUINT_TO_POINTER(1),
    });
    qos_add_test("ns-mgmt-unavailable-mixed", "femu",
                 femu_test_ns_mgmt_unavailable, &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "ns_mgmt=on,namespaces=2,namespace_modes=nossd,,bbssd,"
            "secsz=512,secs_per_pg=8,pgs_per_blk=16,blks_per_pl=80,"
            "pls_per_lun=1,luns_per_ch=4,nchs=4",
        .arg = GUINT_TO_POINTER(2),
    });
    qos_add_test("ns-mgmt-unavailable-fdp", "femu",
                 femu_test_ns_mgmt_unavailable, &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "subsys=fdpsub",
        .arg = GUINT_TO_POINTER(1),
    });
    qos_add_test("ns-mgmt-unavailable-zoned", "femu",
                 femu_test_ns_mgmt_unavailable, &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "ns_mgmt=on,femu_mode=3",
        .arg = GUINT_TO_POINTER(1),
    });
    qos_add_test("ns-mgmt-pel", "femu", femu_test_ns_mgmt_pel,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "ns_mgmt=on"
    });
    qos_add_test("pel-file-quit", "femu", femu_test_pel_file_quit, NULL);
    qos_add_test("pel-file-quit-media", "femu", femu_test_pel_file_quit,
                 &(QOSGraphTestOptions) { .arg = GINT_TO_POINTER(1) });
    qos_add_test("pel-file-invalid", "femu", femu_test_pel_file_invalid, NULL);
    qos_add_test("pel-file", "femu", femu_test_pel_file, NULL);
    qos_add_test("pel-file-media", "femu", femu_test_pel_file,
                 &(QOSGraphTestOptions) { .arg = GINT_TO_POINTER(1) });
    qos_add_test("pel-set-feature", "femu", femu_test_pel_set_feature, NULL);
    qos_add_test("pel-set-feature-buffer", "femu", femu_test_pel_set_feature,
                 &(QOSGraphTestOptions) { .arg = GUINT_TO_POINTER(1) });
    qos_add_test("persistent-event-log-events", "femu", femu_test_pel_events,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "oncs=0x86"
    });
    qos_add_test("telemetry", "femu", femu_test_telemetry,
                 &(QOSGraphTestOptions) {
        /* the captured counters come from the FTL, which NoSSD has none of */
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4"
    });
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
    qos_add_test("ns-mgmt-commands", "femu", femu_test_ns_mgmt_commands,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "ns_mgmt=on"
    });
    qos_add_test("ns-mgmt-notices", "femu", femu_test_ns_mgmt_notices,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "ns_mgmt=on"
    });
    qos_add_test("ns-mgmt-overflow", "femu", femu_test_ns_mgmt_overflow,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=ns-test,ns_mgmt=on"
    });
    qos_add_test("ns-mgmt-format-detached", "femu",
                 femu_test_ns_mgmt_format_detached, &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "ns_mgmt=on,oacs=0x2"
    });
    qos_add_test("ns-mgmt-delete-unallocated", "femu",
                 femu_test_ns_mgmt_unallocated, &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "ns_mgmt=on"
    });
    qos_add_test("ns-mgmt-attach-unallocated", "femu",
                 femu_test_ns_mgmt_unallocated, &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "ns_mgmt=on",
        .arg = GUINT_TO_POINTER(1),
    });
    qos_add_test("ns-mgmt-validation", "femu", femu_test_ns_mgmt_validation,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "ns_mgmt=on"
    });
    qos_add_test("ns-shared-subsys-release", "femu",
                 femu_test_shared_subsys_release, &(QOSGraphTestOptions) {
        .before = femu_shared_before,
    });
    qos_add_test("ns-shared-features", "femu", femu_test_shared_features,
                 &(QOSGraphTestOptions) { .before = femu_shared_before });
    qos_add_test("ns-shared-sanitize", "femu", femu_test_shared_sanitize,
                 &(QOSGraphTestOptions) { .before = femu_shared_before });
    qos_add_test("ns-shared-admin", "femu", femu_test_shared_admin,
                 &(QOSGraphTestOptions) { .before = femu_shared_before });
    qos_add_test("ns-shared-private", "femu", femu_test_shared_private,
                 &(QOSGraphTestOptions) { .before = femu_shared_before });
    qos_add_test("ns-shared-remove-nossd", "femu", femu_test_shared_remove,
                 &(QOSGraphTestOptions) {
        .before = femu_shared_before, .arg = GINT_TO_POINTER(2),
    });
    qos_add_test("ns-shared-remove-bbssd", "femu", femu_test_shared_remove,
                 &(QOSGraphTestOptions) {
        .before = femu_shared_before, .arg = GINT_TO_POINTER(1),
    });
    qos_add_test("ns-shared-retire-nossd", "femu", femu_test_shared_retire,
                 &(QOSGraphTestOptions) {
        .before = femu_shared_before, .arg = GINT_TO_POINTER(2),
    });
    qos_add_test("ns-shared-retire-bbssd", "femu", femu_test_shared_retire,
                 &(QOSGraphTestOptions) {
        .before = femu_shared_before, .arg = GINT_TO_POINTER(1),
    });
    qos_add_test("ns-shared-discovery", "femu", femu_test_shared_discovery,
                 &(QOSGraphTestOptions) { .before = femu_shared_before });
    qos_add_test("ns-shared-lifecycle", "femu", femu_test_shared_lifecycle,
                 &(QOSGraphTestOptions) { .before = femu_shared_before });
    qos_add_test("ns-mgmt-subsys", "femu", femu_test_ns_mgmt_subsys,
                 &(QOSGraphTestOptions) {
        .before = femu_ns_subsys_before,
    });
    qos_add_test("ns-mgmt-common-dpc", "femu", femu_test_ns_mgmt_common_dpc,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "ns_mgmt=on,pi=on,meta=8,mc=3"
    });
    qos_add_test("ns-mgmt-identify-csi-common", "femu",
                 femu_test_ns_mgmt_identify_csi_common,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "ns_mgmt=on"
    });
    qos_add_test("ns-mgmt-identify", "femu", femu_test_ns_mgmt_identify,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "ns_mgmt=on"
    });
    qos_add_test("ns-mgmt-default", "femu", femu_test_ns_mgmt_default,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=ns-test"
    });
    qos_add_test("namespace-copy-detached", "femu",
                 femu_test_namespace_copy_source, &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "ns_mgmt=on,namespaces=2,oncs=0x100",
        .arg = (void *)1,
    });
    qos_add_test("namespace-copy-high", "femu",
                 femu_test_namespace_copy_source, &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "ns_mgmt=on,namespaces=2,oncs=0x100"
    });
    qos_add_test("namespace-large", "femu", femu_test_namespace_large,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=ns-test,lba_index=0"
    });
    qos_add_test("namespace-mixed-identity", "femu",
                 femu_test_namespace_mixed_identity, &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "namespaces=2,namespace_modes=nossd,,csd,fdm_size=16,"
            "secs_per_pg=8,pgs_per_blk=16,blks_per_pl=80,"
            "pls_per_lun=1,luns_per_ch=4,nchs=4"
    });
    qos_add_test("namespace-kv-byte-capacity", "femu",
                 femu_test_namespace_kv_byte_capacity, NULL);
    qos_add_test("namespace-empty-slice", "femu",
                 femu_test_namespace_empty_slice, NULL);
    qos_add_test("namespace-partial-failure-naming", "femu",
                 femu_test_namespace_failure_naming, &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(1),
    });
    qos_add_test("namespace-early-failure-naming", "femu",
                 femu_test_namespace_failure_naming, NULL);
    qos_add_test("namespace-failed-identity", "femu",
                 femu_test_namespace_failed_identity, NULL);
    qos_add_test("namespace-sanitize-bounds", "femu",
                 femu_test_namespace_sanitize_bounds, &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=ns-test,namespaces=2,namespace_sizes=1M,,1M"
    });
    qos_add_test("namespace-sanitize-pool", "femu",
                 femu_test_namespace_sanitize_bounds, &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=ns-test,namespaces=2,namespace_sizes=1M,,1M,ns_mgmt=on",
        .arg = (void *)1,
    });
    qos_add_test("namespace-sanitize-op", "femu",
                 femu_test_namespace_sanitize_bounds, &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=ns-test,femu_mode=1,op_pcent=20,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4"
    });
    qos_add_test("namespace-sanitize-free", "femu",
                 femu_test_namespace_sanitize_free, &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=ns-test,ns_mgmt=on,namespaces=2"
    });
    qos_add_test("namespace-lifecycle", "femu", femu_test_namespace_lifecycle,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=ns-test,ns_mgmt=on,namespaces=2,oacs=0x2"
    });
    qos_add_test("namespace-capacity", "femu", femu_test_namespace_capacity,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=ns-test,ns_mgmt=on,namespaces=2,oacs=0x2"
    });
    qos_add_test("namespace-identity", "femu", femu_test_namespace_identity,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=ns-test,ns_mgmt=on,namespaces=2"
    });
    qos_add_test("namespace-allocated", "femu", femu_test_namespace_allocated,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=ns-test,ns_mgmt=on,namespaces=2"
    });
    qos_add_test("namespace-sparse", "femu", femu_test_namespace_sparse,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=ns-test,ns_mgmt=on,namespaces=2,oacs=0x2"
    });
    qos_add_test("invalid-nsid-reuse", "femu", femu_test_invalid_nsid_reuse,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "pcie_prop_delay_ns=2000000000"
    });
    qos_add_test("ns-retire-nossd", "femu", femu_test_ns_retire,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=ns-test,namespaces=2,ns_mgmt=on"
    });
    qos_add_test("ns-retire-pollers", "femu", femu_test_ns_retire,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=ns-test,namespaces=2,ns_mgmt=on,"
            "multipoller_enabled=1"
    });
    qos_add_test("shared-cq", "femu", femu_test_shared_cq, NULL);
    qos_add_test("cq-full", "femu", femu_test_cq_full, NULL);
    qos_add_test("io-interrupts", "femu", femu_test_io_interrupts, NULL);
    qos_add_test("intx-shadow-doorbell", "femu",
                 femu_test_intx_shadow_doorbell, NULL);
    qos_add_test("dma-error", "femu", femu_test_dma_error, NULL);
    qos_add_test("queue-create-status", "femu", femu_test_queue_create_status,
                 NULL);
    qos_add_test("cc-states", "femu", femu_test_cc_states, NULL);
    qos_add_test("features-reset", "femu", femu_test_features_reset, NULL);
    qos_add_test("error-log", "femu", femu_test_error_log, NULL);
    qos_add_test("prp-status", "femu", femu_test_prp_status, NULL);
    qos_add_test("doorbell-errors", "femu", femu_test_doorbell_errors, NULL);
    qos_add_test("format-ses", "femu", femu_test_format_ses, NULL);
    qos_add_test("copy", "femu", femu_test_copy,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,oncs=0x104"
    });
    qos_add_test("copy-fdp", "femu", femu_test_copy,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,oncs=0x104,"
            "subsys=fdpsub"
    });
    qos_add_test("sanitize", "femu", femu_test_sanitize,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=16,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=32,pls_per_lun=1,luns_per_ch=4,nchs=4"
    });
    qos_add_test("format-ftl", "femu", femu_test_format_ftl,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=16,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=32,pls_per_lun=1,luns_per_ch=4,nchs=4,oacs=0x2"
    });
    qos_add_test("bar0-size", "femu", femu_test_bar0_size, NULL);
    qos_add_test("io-fuzz", "femu", femu_test_io_fuzz,
                 &(QOSGraphTestOptions) {
        .arg = (void *)&femu_io_fuzz_conv,
        .edge.extra_device_opts = "sgl=on,vwc=1,oncs=0x19f"
    });
    qos_add_test("io-fuzz-zoned", "femu", femu_test_io_fuzz,
                 &(QOSGraphTestOptions) {
        .arg = (void *)&femu_io_fuzz_zoned,
        .edge.extra_device_opts = "femu_mode=3,secsz=512,sgl=on"
    });
    qos_add_test("io-fuzz-fdp", "femu", femu_test_io_fuzz,
                 &(QOSGraphTestOptions) {
        .arg = (void *)&femu_io_fuzz_fdp,
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "sgl=on,vwc=1,oncs=0x19f,subsys=fdpsub"
    });
    qos_add_test("oc12-channel-gap", "femu", femu_test_oc12_channel_gap,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=oc12-test,femu_mode=0,lver=1,oc12_channel_timing=on,"
            "flash_type=2,ch_xfer_lat=400000,lsec_size=512,lsecs_per_pg=4,"
            "lnum_pln=1,lnum_ch=2,lnum_lun=2,lpgs_per_blk=512"
    });
    qos_add_test("oc12-channel-timing", "femu", femu_test_oc12_channel_timing,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=oc12-test,femu_mode=0,lver=1,oc12_channel_timing=on,"
            "ch_xfer_lat=400000,lsec_size=512,lsecs_per_pg=4,lnum_pln=1,"
            "lnum_ch=2,lnum_lun=2,lpgs_per_blk=512"
    });
    qos_add_test("oc12-channel-default", "femu", femu_test_oc12_channel_profile,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(1),
        .edge.extra_device_opts =
            "id=oc12-test,femu_mode=0,lver=1,oc12_channel_timing=on,"
            "lsec_size=512,lsecs_per_pg=4,lnum_pln=1,lnum_ch=2,lnum_lun=2"
    });
    qos_add_test("oc12-channel-off", "femu", femu_test_oc12_channel_profile,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=oc12-test,femu_mode=0,lver=1,ch_xfer_lat=400000,"
            "lsec_size=512,lsecs_per_pg=4,lnum_pln=1,lnum_ch=2,lnum_lun=2"
    });
    qos_add_test("oc12-ppa-timing", "femu", femu_test_oc12_ppa_timing,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=oc12-test,femu_mode=0,lver=1,lsec_size=512,"
            "lsecs_per_pg=4,lnum_pln=1,lnum_ch=2,lnum_lun=2"
    });
    qos_add_test("oc12-flash-type", "femu", femu_test_oc12_timing_config,
                 &(QOSGraphTestOptions) { .arg = GUINT_TO_POINTER(0) });
    qos_add_test("oc12-page-count", "femu", femu_test_oc12_timing_config,
                 &(QOSGraphTestOptions) { .arg = GUINT_TO_POINTER(1) });
    qos_add_test("oc12-transfer-cost", "femu", femu_test_oc12_timing_config,
                 &(QOSGraphTestOptions) { .arg = GUINT_TO_POINTER(2) });
    qos_add_test("oc12-capabilities", "femu", femu_test_oc12_capabilities,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=0,lver=1"
    });
    qos_add_test("oc12-opcodes", "femu", femu_test_oc12_opcodes,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=0,lver=1"
    });
    qos_add_test("oc12-small-sectors", "femu", femu_test_oc12_small_sectors,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=0,lver=1"
    });
    qos_add_test("oc20-sgl-refused", "femu", femu_test_oc_sgl_refused,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(2),
        .edge.extra_device_opts = "femu_mode=0,lver=2,sgl=on"
    });
    qos_add_test("oc20-fuzz", "femu", femu_test_oc20_fuzz,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=0,lver=2,sgl=on"
    });
    qos_add_test("csd-fuzz", "femu", femu_test_csd_fuzz,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=4,fdm_size=16,sgl=on"
    });
    qos_add_test("io-fuzz-metadata", "femu", femu_test_io_fuzz,
                 &(QOSGraphTestOptions) {
        .arg = (void *)&femu_io_fuzz_conv,
        .edge.extra_device_opts = "sgl=on,vwc=1,oncs=0x19f,meta=8,mc=2"
    });
    qos_add_test("io-fuzz-nossd", "femu", femu_test_io_fuzz,
                 &(QOSGraphTestOptions) {
        .arg = (void *)&femu_io_fuzz_conv,
        .edge.extra_device_opts = "femu_mode=2,sgl=on,oncs=0x19f"
    });
    qos_add_test("pi-verify-8", "femu", femu_test_pi_verify,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(8),
        .edge.extra_device_opts = "pi=on,meta=8,mc=3,oncs=0x19f,mdts=1"
    });
    qos_add_test("pi-verify-16", "femu", femu_test_pi_verify,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(16),
        .edge.extra_device_opts = "pi=on,meta=16,mc=3,oncs=0x19f,mdts=1"
    });
    qos_add_test("ns-create-pi-bbssd", "femu", femu_test_pi_rw,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(528),
        .edge.extra_device_opts =
            "ns_mgmt=on,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "pi=on,meta=16,mc=3,oncs=0x19f,mdts=1"
    });
    qos_add_test("ns-create-pi-small-metadata", "femu",
                 femu_test_ns_create_pi_validation,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(2),
        .edge.extra_device_opts = "ns_mgmt=on,pi=on,meta=4,mc=3"
    });
    qos_add_test("ns-create-pi-extended-only", "femu",
                 femu_test_ns_create_pi_validation,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(1),
        .edge.extra_device_opts = "ns_mgmt=on,pi=on,meta=8,mc=1,extended=1"
    });
    qos_add_test("ns-create-pi-8", "femu", femu_test_pi_rw,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(520),
        .edge.extra_device_opts =
            "ns_mgmt=on,pi=on,meta=8,mc=3,oncs=0x19f,mdts=1"
    });
    qos_add_test("ns-create-pi-8-extended", "femu", femu_test_pi_rw,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(776),
        .edge.extra_device_opts =
            "ns_mgmt=on,pi=on,meta=8,mc=3,oncs=0x19f,mdts=1"
    });
    qos_add_test("ns-create-pi-16", "femu", femu_test_pi_rw,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(528),
        .edge.extra_device_opts =
            "ns_mgmt=on,pi=on,meta=16,mc=3,oncs=0x19f,mdts=1"
    });
    qos_add_test("ns-create-pi-16-extended", "femu", femu_test_pi_rw,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(784),
        .edge.extra_device_opts =
            "ns_mgmt=on,pi=on,meta=16,mc=3,oncs=0x19f,mdts=1"
    });
    qos_add_test("ns-create-pi-validation", "femu",
                 femu_test_ns_create_pi_validation,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(1),
        .edge.extra_device_opts = "ns_mgmt=on,pi=on,meta=8,mc=3"
    });
    qos_add_test("ns-create-pi-separate", "femu",
                 femu_test_ns_create_pi_validation,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(1),
        .edge.extra_device_opts = "ns_mgmt=on,pi=on,meta=8,mc=2"
    });
    qos_add_test("ns-create-pi-off", "femu",
                 femu_test_ns_create_pi_validation,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(0),
        .edge.extra_device_opts = "ns_mgmt=on,pi=off,meta=8,mc=3"
    });
    qos_add_test("pi-rw-8", "femu", femu_test_pi_rw,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(8),
        .edge.extra_device_opts = "pi=on,meta=8,mc=3,oncs=0x19f,mdts=1"
    });
    qos_add_test("pi-rw-8-extended", "femu", femu_test_pi_rw,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(264),
        .edge.extra_device_opts = "pi=on,meta=8,mc=3,oncs=0x19f,mdts=1"
    });
    qos_add_test("pi-rw-16", "femu", femu_test_pi_rw,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(16),
        .edge.extra_device_opts = "pi=on,meta=16,mc=3,oncs=0x19f,mdts=1"
    });
    qos_add_test("pi-rw-16-extended", "femu", femu_test_pi_rw,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(272),
        .edge.extra_device_opts = "pi=on,meta=16,mc=3,oncs=0x19f,mdts=1"
    });
    qos_add_test("pi-write-ref-8", "femu", femu_test_pi_generate_ref,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(8 | (NVME_CMD_WRITE << 8)),
        .edge.extra_device_opts =
            "pi=on,meta=8,mc=3,oncs=0x19f,namespaces=2"
    });
    qos_add_test("pi-write-ref-16", "femu", femu_test_pi_generate_ref,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(16 | (NVME_CMD_WRITE << 8)),
        .edge.extra_device_opts =
            "pi=on,meta=16,mc=3,oncs=0x19f,namespaces=2"
    });
    qos_add_test("pi-zeroes-ref-8", "femu", femu_test_pi_generate_ref,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(8 | (NVME_CMD_WRITE_ZEROES << 8)),
        .edge.extra_device_opts =
            "pi=on,meta=8,mc=3,oncs=0x19f,namespaces=2"
    });
    qos_add_test("pi-zeroes-ref-16", "femu", femu_test_pi_generate_ref,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(16 | (NVME_CMD_WRITE_ZEROES << 8)),
        .edge.extra_device_opts =
            "pi=on,meta=16,mc=3,oncs=0x19f,namespaces=2"
    });
    qos_add_test("pi-copy-ref-8", "femu", femu_test_pi_generate_ref,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(8 | (FEMU_CMD_COPY << 8)),
        .edge.extra_device_opts =
            "pi=on,meta=8,mc=3,oncs=0x19f,namespaces=2"
    });
    qos_add_test("pi-copy-ref-16", "femu", femu_test_pi_generate_ref,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(16 | (FEMU_CMD_COPY << 8)),
        .edge.extra_device_opts =
            "pi=on,meta=16,mc=3,oncs=0x19f,namespaces=2"
    });
    qos_add_test("pi-compare", "femu", femu_test_pi_compare,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "pi=on,meta=16,mc=3,oncs=0x19f"
    });
    qos_add_test("pi-zeroes", "femu", femu_test_pi_zeroes,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "pi=on,meta=16,mc=3,oncs=0x19f"
    });
    qos_add_test("pi-copy-8-fmt0", "femu", femu_test_pi_copy,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(8),
        .edge.extra_device_opts =
            "pi=on,meta=8,mc=3,oncs=0x19f,namespaces=2"
    });
    qos_add_test("pi-copy-8-fmt2", "femu", femu_test_pi_copy,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(520),
        .edge.extra_device_opts =
            "pi=on,meta=8,mc=3,oncs=0x19f,namespaces=2"
    });
    qos_add_test("pi-copy-16-fmt0", "femu", femu_test_pi_copy,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(16),
        .edge.extra_device_opts =
            "pi=on,meta=16,mc=3,oncs=0x19f,namespaces=2"
    });
    qos_add_test("pi-copy-16-fmt2", "femu", femu_test_pi_copy,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(528),
        .edge.extra_device_opts =
            "pi=on,meta=16,mc=3,oncs=0x19f,namespaces=2"
    });
    qos_add_test("pi-off-copy-metadata", "femu", femu_test_pi_copy_no_pi,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "pi=off,meta=8,mc=3,oncs=0x19f,namespaces=2"
    });
    qos_add_test("pi-copy-no-pi", "femu", femu_test_pi_copy_no_pi,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "pi=on,meta=8,mc=3,oncs=0x19f,namespaces=2"
    });
    qos_add_test("pi-copy-convert", "femu", femu_test_pi_copy_convert,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "pi=on,meta=8,mc=3,oncs=0x19f,namespaces=2"
    });
    qos_add_test("pi-copy-bbssd", "femu", femu_test_pi_copy,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(8 | (2 << 8)),
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "pi=on,meta=8,mc=3,oncs=0x19f,namespaces=2"
    });
    qos_add_test("pi-off-dpc-no-metadata", "femu", femu_test_pi_dpc_no_metadata,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(0x19),
        .edge.extra_device_opts = "pi=off,meta=0,dpc=0x19"
    });
    qos_add_test("pi-dpc-no-metadata", "femu", femu_test_pi_dpc_no_metadata,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "pi=on,meta=0,dpc=0x19"
    });
    qos_add_test("pi-format", "femu", femu_test_pi_format,
                 &(QOSGraphTestOptions) {
        .arg = GINT_TO_POINTER(1),
        .edge.extra_device_opts = "pi=on,meta=8,mc=3"
    });
    qos_add_test("pi-off", "femu", femu_test_pi_format,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "meta=8,mc=3"
    });
    qos_add_test("metadata", "femu", femu_test_metadata,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "meta=8,mc=2,oncs=0x19f"
    });
    qos_add_test("metadata-bbssd", "femu", femu_test_metadata,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "meta=8,mc=2,oncs=0x19f"
    });
    qos_add_test("metadata-extended", "femu", femu_test_metadata_extended,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "meta=8,mc=3,extended=1,mdts=1,oncs=0x19f"
    });
    qos_add_test("copy-fmt2", "femu", femu_test_copy_fmt2,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "namespaces=2,oacs=0x2,oncs=0x19f"
    });
    qos_add_test("copy-fmt2-bbssd", "femu", femu_test_copy_fmt2,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "namespaces=2,oacs=0x2,oncs=0x19f"
    });
    qos_add_test("admin-fuzz", "femu", femu_test_admin_fuzz,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "namespaces=2,oacs=0x2,oncs=0x19f"
    });
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
    qos_add_test("power-loss-mmio-cut", "femu", femu_test_power_mmio_cut,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "serial=power-mmio-cut,"
            "id=power,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "buffer_size=4,vwc=1,power_loss=on,oncs=415",
        .arg = GINT_TO_POINTER(0),
    });
    qos_add_test("power-loss-dma-pointers", "femu",
                 femu_test_power_dma_pointers,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "serial=power-dma-pointers,"
            "id=power,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "buffer_size=4,vwc=1,power_loss=on,oncs=415,sgl=on",
    });
    qos_add_test("power-loss-cmb", "femu", femu_test_power_cmb,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "serial=power-cmb,"
            "id=power,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "buffer_size=4,vwc=1,power_loss=on,oncs=415,cmbsz=0x400000,cmbloc=2",
    });
    {
        static const char * const no_drain[] = {
            "invalid-opcode", "verify", "dsm-hint", "dsm-empty",
            "invalid-zeroes", "invalid-uncor", "invalid-dsm", "copy-overlap",
            "invalid-copy", "dsm-mmio", "invalid-format", "sanitize-noop",
            "invalid-sanitize", "compare",
        };
        static const char * const mutations[] = {
            "zeroes", "zeroes-deac", "uncor", "dsm", "copy", "format",
            "sanitize",
        };

        for (int i = 0; i < ARRAY_SIZE(no_drain); i++) {
            g_autofree char *name =
                g_strdup_printf("power-loss-%s", no_drain[i]);
            g_autofree char *device_opts = g_strdup_printf(
                "serial=%s,id=power,femu_mode=1,secsz=512,secs_per_pg=8,"
                "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,"
                "luns_per_ch=4,nchs=4,buffer_size=4,vwc=1,"
                "power_loss=on,oncs=415", name);

            qos_add_test(name, "femu", femu_test_power_no_drain,
                         &(QOSGraphTestOptions) {
                .edge.extra_device_opts = device_opts,
                .arg = GINT_TO_POINTER(i),
            });
        }
        for (int i = 0; i < ARRAY_SIZE(mutations); i++) {
            g_autofree char *name =
                g_strdup_printf("power-loss-mutate-%s", mutations[i]);
            g_autofree char *device_opts = g_strdup_printf(
                "serial=%s,id=power,femu_mode=1,secsz=512,secs_per_pg=8,"
                "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,"
                "luns_per_ch=4,nchs=4,buffer_size=4,vwc=1,"
                "power_loss=on,oncs=415,namespaces=2", name);

            qos_add_test(name, "femu", femu_test_power_mutation,
                         &(QOSGraphTestOptions) {
                .edge.extra_device_opts = device_opts,
                .arg = GINT_TO_POINTER(i),
            });
        }
    }
    qos_add_test("power-loss-pel", "femu", femu_test_power_log,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "serial=power0,"
            "id=power,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "buffer_size=4,vwc=1,power_loss=on",
        .arg = GINT_TO_POINTER(1),
    });
    qos_add_test("power-loss-smart", "femu", femu_test_power_log,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "serial=power1,"
            "id=power,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "buffer_size=4,vwc=1,power_loss=on",
        .arg = GINT_TO_POINTER(0),
    });
    qos_add_test("power-loss-reset", "femu", femu_test_power_lifecycle,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "serial=power2,"
            "id=power,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "buffer_size=4,vwc=1,power_loss=on",
        .arg = GINT_TO_POINTER(2),
    });
    qos_add_test("power-loss-shutdown", "femu", femu_test_power_lifecycle,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "serial=power3,"
            "id=power,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "buffer_size=4,vwc=1,power_loss=on",
        .arg = GINT_TO_POINTER(1),
    });
    qos_add_test("power-loss-cache-disable", "femu", femu_test_power_lifecycle,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "serial=power4,"
            "id=power,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "buffer_size=4,vwc=1,power_loss=on",
        .arg = GINT_TO_POINTER(0),
    });
    qos_add_test("power-loss-dma-error", "femu", femu_test_dma_error,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "serial=power5,"
            "id=power,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "buffer_size=4,vwc=1,power_loss=on",
    });
    qos_add_test("power-loss-flush-pending", "femu",
                 femu_test_power_flush_pending,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "serial=power6,"
            "id=power,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "buffer_size=4,vwc=1,power_loss=on",
    });
    qos_add_test("power-loss-validity", "femu", femu_test_power_validity,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "serial=power7,"
            "id=power,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "buffer_size=4,vwc=1,power_loss=on,oncs=31",
    });
    qos_add_test("power-loss", "femu", femu_test_power_loss,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "serial=power8,"
            "id=power,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "buffer_size=4,vwc=1,power_loss=on",
    });
    qos_add_test("power-loss-flush", "femu", femu_test_power_durable,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "serial=power9,"
            "id=power,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "buffer_size=4,vwc=1,power_loss=on",
    });
    qos_add_test("power-loss-fua", "femu", femu_test_power_durable,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "serial=power10,"
            "id=power,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "buffer_size=4,vwc=1,power_loss=on",
        .arg = GINT_TO_POINTER(1),
    });
    qos_add_test("power-loss-destage", "femu", femu_test_power_destage,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "serial=power11,"
            "id=power,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "buffer_size=1,vwc=1,power_loss=on",
    });
    qos_add_test("power-loss-vwc-zero", "femu", femu_test_power_cache_off,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "serial=power12,"
            "id=power,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "buffer_size=4,vwc=0,power_loss=on",
    });
    qos_add_test("power-loss-off", "femu", femu_test_power_cache_off,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "serial=power13,"
            "id=power,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "buffer_size=4,vwc=1",
        .arg = GINT_TO_POINTER(1),
    });
    qos_add_test("power-loss-namespaces", "femu", femu_test_power_namespaces,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "serial=power14,"
            "id=power,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "buffer_size=4,vwc=1,power_loss=on,namespaces=2",
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
