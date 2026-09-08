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

#define FEMU_QSIZE          16
#define FEMU_DATA_SIZE      4096
#define FEMU_POLL_LIMIT_MS  10000

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
    NvmeCqe cqe;
    int waited = 0;

    for (;;) {
        qtest_memread(c->pdev->bus->qts,
                      q->cq_addr + q->cq_head * sizeof(NvmeCqe), &cqe,
                      sizeof(cqe));
        if ((le16_to_cpu(cqe.status) & 1) == q->phase) {
            break;
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

static void femu_enable(FemuCtrlState *c, QPCIDevice *pdev,
                        QGuestAllocator *alloc)
{
    uint64_t cap;
    uint32_t csts;
    int waited = 0;

    c->pdev = pdev;
    c->alloc = alloc;
    qpci_device_enable(pdev);
    c->bar = qpci_iomap(pdev, 0, NULL);

    cap = qpci_io_readq(pdev, c->bar, 0x0);
    c->db_stride = (cap >> 32) & 0xf;
    c->lba_size = 512;

    femu_queue_init(c, &c->admin, 0);
    qpci_io_writel(pdev, c->bar, 0x24,
                   ((FEMU_QSIZE - 1) << 16) | (FEMU_QSIZE - 1));
    qpci_io_writeq(pdev, c->bar, 0x28, c->admin.sq_addr);
    qpci_io_writeq(pdev, c->bar, 0x30, c->admin.cq_addr);

    /* enable, NVM command set, 4 KiB pages, 64-byte SQEs, 16-byte CQEs */
    qpci_io_writel(pdev, c->bar, 0x14, (6 << 16) | (4 << 20) | 1);
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
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * The shadow doorbell path must keep working once the host configures it:
 * after Doorbell Buffer Config the queue is driven from the shadow page and
 * the register writes are ignored.
 */
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

    femu_round_trip(&c, 4);
    femu_round_trip(&c, 5);

    guest_free(alloc, eis_addr);
    guest_free(alloc, c.dbs_addr);
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

    /* the queue count comes back in dword 0 of the completion */
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_NUMBER_OF_QUEUES,
                            false, 0, 0x00030003, &result)), ==, NVME_SUCCESS);
    g_assert_cmpint(result & 0xffff, ==, (result >> 16) & 0xffff);

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

static void femu_register_nodes(void)
{
    QOSGraphEdgeOptions opts = {
        .extra_device_opts = "addr=04.0,devsz_mb=64,femu_mode=2,serial=femu0",
    };

    add_qpci_address(&opts, &(QPCIAddress) { .devfn = QPCI_DEVFN(4, 0) });

    qos_node_create_driver("femu", femu_create);
    qos_node_consumes("femu", "pci-bus", &opts);
    qos_node_produces("femu", "pci-device");

    qos_add_test("io-by-doorbell", "femu", femu_test_io_by_doorbell, NULL);
    qos_add_test("io-by-shadow-doorbell", "femu",
                 femu_test_io_by_shadow_doorbell, NULL);
    qos_add_test("features", "femu", femu_test_features, NULL);
    qos_add_test("format", "femu", femu_test_format,
                 &(QOSGraphTestOptions) {
        /* start with 4 KiB blocks so a format to 512 grows the block count */
        .edge.extra_device_opts = "lba_index=3"
    });
}

libqos_init(femu_register_nodes);
