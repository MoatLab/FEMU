/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QTest testcases for the FEMU SSD emulator: the tests on the default
 * NoSSD device (femu_mode=2): the NVMe controller, admin and I/O commands.
 *
 * femu-test.c registers every test. This file holds the test bodies
 * and the helpers that only they use.
 */

#include "qemu/osdep.h"
#include "femu-test.h"

/* feature 01h at reset: AB 7 (no burst limit), HPW 31, MPW 15, LPW 7 */
#define FEMU_ARB_DEFAULT    0x1f0f0707
/* the femu device's queues property default, which these tests do not set */
#define FEMU_DEFAULT_IO_QUEUES  8

/* Invalid namespace commands must not inherit a recycled transfer. */
void femu_test_invalid_nsid_reuse(void *obj, void *data,
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
void femu_test_io_by_doorbell(void *obj, void *data,
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
 * An admin queue the controller cannot map whole must stop it coming ready. The
 * host chooses both addresses and both sizes, so a completion queue that failed
 * left the submission queue asserting on it and took the process down.
 */
void femu_test_admin_queue_refused(void *obj, void *data,
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

void femu_test_discontig_64k_pages(void *obj, void *data,
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
void femu_test_queue_mapping(void *obj, void *data,
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

void femu_test_io_by_shadow_doorbell(void *obj, void *data,
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
void femu_test_dbbuf_too_many_queues(void *obj, void *data,
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
void femu_test_cq_churn(void *obj, void *data, QGuestAllocator *alloc)
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
 * Byte accesses at the end of the controller memory buffer. With a 2-byte
 * minimum access size, QEMU widened each one. The write at the last byte
 * then went past the buffer, which ASan reports. The write before it also
 * cleared the last byte, so the word check fails in any build.
 */
void femu_test_cmb_last_byte(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    const uint64_t size = 0x400000;
    QPCIBar cmb;
    uint64_t last;

    qpci_device_enable(&femu->dev);
    cmb = qpci_iomap(&femu->dev, 2, NULL);
    last = cmb.addr + size - 1;

    qtest_writeb(qts, last - 2, 0x11);
    qtest_writeb(qts, last, 0xa5);
    g_assert_cmphex(qtest_readb(qts, last), ==, 0xa5);
    qtest_writeb(qts, last - 1, 0x5a);
    g_assert_cmphex(qtest_readw(qts, last - 1), ==, 0xa55a);
    /* a byte write leaves its neighbour as it was */
    g_assert_cmphex(qtest_readb(qts, last - 2), ==, 0x11);
}

/*
 * A data buffer inside the controller memory buffer is described by an iovec
 * rather than a scatter list, and the media path takes the scatter list, so the
 * transfer moves nothing. The assertion that the two agreed aborted the process
 * on a guest command; it has to be refused.
 */
void femu_test_cmb_data_buffer(void *obj, void *data,
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
 * Get and Set Features carry the identifier in the low byte of CDW10 and a
 * selector or the save bit above it. The selector chooses the current,
 * default, saved or capability value; a save request must be refused rather
 * than obeyed, and an identifier the controller does not implement is an
 * invalid field.
 */
void femu_test_features(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint32_t result;

    femu_enable(&c, &femu->dev, alloc);

    g_assert_cmpint(FEMU_SC(femu_get_feature(&c, NVME_TEMPERATURE_THRESHOLD,
                            NVME_GETFEAT_SELECT_CURRENT, 0, 0, &result)),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(result, ==, FEMU_WCTEMP);

    /*
     * Under CC.CSS 000b the profile has no effect, so any index succeeds
     * and changes nothing (Base 2.3, 5.2.26.1.17). kv-css checks 110b.
     */
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, FEMU_FEAT_CMD_SET_PROFILE,
                            false, 0, 0, NULL)), ==, NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, FEMU_FEAT_CMD_SET_PROFILE,
                            false, 0, 1, NULL)), ==, NVME_SUCCESS);
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
    g_assert_cmpint(result, ==, FEMU_WCTEMP);
    g_assert_cmpint(FEMU_SC(femu_get_feature(&c, NVME_TEMPERATURE_THRESHOLD,
                            NVME_GETFEAT_SELECT_SAVED, 0, 0, &result)),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(result, ==, FEMU_WCTEMP);

    /* nothing is saveable */
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_TEMPERATURE_THRESHOLD,
                            true, 0, 0x150, NULL)),
                    ==, NVME_FID_NOT_SAVEABLE);

    /* a selector the specification does not define */
    g_assert_cmpint(FEMU_SC(femu_get_feature(&c, NVME_TEMPERATURE_THRESHOLD,
                            4, 0, 0, &result)), ==, NVME_INVALID_FIELD);

    /* THSEL 2 and 3 are reserved; "all sensors" is for Set only */
    g_assert_cmpint(FEMU_SC(femu_get_feature(&c, NVME_TEMPERATURE_THRESHOLD,
                            NVME_GETFEAT_SELECT_CURRENT, 0, 2 << 20, &result)),
                    ==, NVME_INVALID_FIELD);
    g_assert_cmpint(FEMU_SC(femu_get_feature(&c, NVME_TEMPERATURE_THRESHOLD,
                            NVME_GETFEAT_SELECT_DEFAULT, 0, 3 << 20, &result)),
                    ==, NVME_INVALID_FIELD);
    g_assert_cmpint(FEMU_SC(femu_get_feature(&c, NVME_TEMPERATURE_THRESHOLD,
                            NVME_GETFEAT_SELECT_CURRENT, 0, 0xf << 16,
                            &result)), ==, NVME_INVALID_FIELD);
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_TEMPERATURE_THRESHOLD,
                            false, 0, (2 << 20) | 0x150, NULL)), ==,
                    NVME_INVALID_FIELD);
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_TEMPERATURE_THRESHOLD,
                            false, 0, (0xf << 16) | 0x150, NULL)), ==,
                    NVME_SUCCESS);

    /*
     * At 323 K, an under threshold of 336 K is met, so SMART critical warning
     * bit 1 is set; an under threshold of 0 clears it again.
     */
    {
        uint64_t log = guest_alloc(alloc, 512);
        uint8_t warning;

        g_assert_cmpint(FEMU_SC(femu_set_feature(&c,
                                NVME_TEMPERATURE_THRESHOLD, false, 0,
                                (1 << 20) | 0x150, NULL)), ==, NVME_SUCCESS);
        g_assert_cmpuint(femu_smart_temp(&c, log, &warning), ==, 323);
        g_assert_cmphex(warning & NVME_SMART_TEMPERATURE, ==,
                        NVME_SMART_TEMPERATURE);
        g_assert_cmpint(FEMU_SC(femu_set_feature(&c,
                                NVME_TEMPERATURE_THRESHOLD, false, 0,
                                1 << 20, NULL)), ==, NVME_SUCCESS);
        femu_smart_temp(&c, log, &warning);
        g_assert_cmphex(warning & NVME_SMART_TEMPERATURE, ==, 0);
        guest_free(alloc, log);
    }

    /* autonomous power state transitions are not implemented */
    g_assert_cmpint(FEMU_SC(femu_get_feature(&c, 0x0c,
                            NVME_GETFEAT_SELECT_CURRENT, 0, 0, &result)),
                    ==, NVME_INVALID_FIELD);

    /*
     * A controller-wide feature addressed to one namespace. Volatile Write
     * Cache is not supported without vwc=1, so it is an invalid field first.
     */
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_ARBITRATION,
                            false, 1, 0, NULL)),
                    ==, NVME_FEAT_NOT_NS_SPEC);
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_VOLATILE_WRITE_CACHE,
                            false, 1, 0, NULL)),
                    ==, NVME_INVALID_FIELD);

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
#define FEMU_LIDS_LSUPP             (1u << 0)   /* LID Supported */
#define FEMU_ONCS_TIMESTAMP     (1 << 6)

/*
 * Supported Log Pages says which identifiers the controller answers, and the
 * media counters live on their own page rather than in the SMART log's
 * temperature fields. Both must agree with what Get Log Page actually does,
 * and both must serve a request from the offset it was given -- returning the
 * start of the page whatever was asked for is the failure this covers.
 */
void femu_test_log_pages(void *obj, void *data, QGuestAllocator *alloc)
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

void femu_test_log_length(void *obj, void *data, QGuestAllocator *alloc)
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
void femu_test_format(void *obj, void *data, QGuestAllocator *alloc)
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

#define FEMU_GC_SEED_WRITES  2048
#define FEMU_GC_SEED_SAMPLE  32

/*
 * Hot-add a small black-box device: 80 lines of 16 pages behind 4 MiB, so a
 * few thousand random page writes run garbage collection many times.
 */
static QPCIDevice *femu_gc_seed_add(QFemu *femu, const char *id, int slot,
                                    const char *policy, int seed)
{
    QTestState *qts = femu->dev.bus->qts;
    g_autofree char *addr = g_strdup_printf("%d", slot);
    QDict *rsp;

    if (seed < 0) {
        rsp = qtest_qmp(qts,
            "{'execute':'device_add','arguments':{'driver':'femu','id':%s,"
            "'addr':%s,'devsz_mb':4,'femu_mode':1,'secsz':512,"
            "'secs_per_pg':8,'pgs_per_blk':16,'blks_per_pl':80,"
            "'pls_per_lun':1,'luns_per_ch':1,'nchs':1,'gc_policy':%s}}",
            id, addr, policy);
    } else {
        rsp = qtest_qmp(qts,
            "{'execute':'device_add','arguments':{'driver':'femu','id':%s,"
            "'addr':%s,'devsz_mb':4,'femu_mode':1,'secsz':512,"
            "'secs_per_pg':8,'pgs_per_blk':16,'blks_per_pl':80,"
            "'pls_per_lun':1,'luns_per_ch':1,'nchs':1,'gc_policy':%s,"
            "'gc_seed':%d}}",
            id, addr, policy, seed);
    }
    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
    return qpci_device_find(femu->dev.bus, QPCI_DEVFN(slot, 0));
}

/*
 * Run the same random overwrite sequence and record the relocation count
 * every FEMU_GC_SEED_SAMPLE writes. Each collection relocates its victim's
 * valid pages, so the trace follows the victim sequence; the last entry is
 * the write amplification.
 */
static void femu_gc_seed_run(QFemu *femu, QGuestAllocator *alloc,
                             QPCIDevice *pdev, const char *id, int slot,
                             uint64_t *trace)
{
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t data = guest_alloc(alloc, FEMU_DATA_SIZE);
    uint64_t log = guest_alloc(alloc, 512);
    uint32_t lcg = 12345;
    uint8_t page[512];
    unsigned i;

    femu_enable(&c, pdev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, data, 0x6b, FEMU_DATA_SIZE);
    for (i = 0; i < FEMU_GC_SEED_WRITES; i++) {
        lcg = lcg * 1103515245u + 12345u;
        g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE,
                                        ((lcg >> 8) % 1024) * 8, data)), ==,
                        NVME_SUCCESS);
        if ((i + 1) % FEMU_GC_SEED_SAMPLE == 0) {
            g_assert_cmpint(FEMU_SC(femu_get_log(&c, FEMU_LOG_FEMU_STATS, log,
                                                 sizeof(page), 0)), ==,
                            NVME_SUCCESS);
            qtest_memread(qts, log, page, sizeof(page));
            trace[i / FEMU_GC_SEED_SAMPLE] = ldq_le_p(page + 16);
        }
    }
    trace[FEMU_GC_SEED_WRITES / FEMU_GC_SEED_SAMPLE] = ldl_le_p(page);
    femu_disable(&c);
    femu_queue_free(&c, &c.io);
    qpci_unplug_acpi_device_test(qts, id, slot);
    g_free(pdev);
    guest_free(alloc, log);
    guest_free(alloc, data);
}

/*
 * The policies that sample victims draw from a generator seeded by gc_seed,
 * so two devices with the same configuration and workload pick the same
 * victims and report the same write amplification. A third device with
 * another seed must differ, or the trace could not tell runs apart. FIFO
 * takes the oldest line and must not depend on the seed at all.
 */
void femu_test_gc_seed(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    const char *policy = data;
    enum { N = FEMU_GC_SEED_WRITES / FEMU_GC_SEED_SAMPLE + 1 };
    uint64_t a[N];
    uint64_t b[N];
    uint64_t other[N];
    uint64_t digest = 0xcbf29ce484222325ULL;
    unsigned i;

    femu_gc_seed_run(femu, alloc,
                     femu_gc_seed_add(femu, "gc-a", 5, policy, -1),
                     "gc-a", 5, a);
    femu_gc_seed_run(femu, alloc,
                     femu_gc_seed_add(femu, "gc-b", 6, policy, -1),
                     "gc-b", 6, b);
    femu_gc_seed_run(femu, alloc,
                     femu_gc_seed_add(femu, "gc-c", 7, policy, 7),
                     "gc-c", 7, other);

    for (i = 0; i < N; i++) {
        digest = (digest ^ a[i]) * 0x100000001b3ULL;
    }
    g_test_message("%s: relocated %" PRIu64 "/%" PRIu64 "/%" PRIu64
                   ", WAF x1000 %" PRIu64 "/%" PRIu64 "/%" PRIu64
                   ", trace %016" PRIx64, policy, a[N - 2], b[N - 2],
                   other[N - 2], a[N - 1], b[N - 1], other[N - 1], digest);
    g_assert_cmpuint(a[N - 2], >, 0);           /* GC ran */
    g_assert_cmpuint(a[N - 1], >, 1000);        /* WAF above 1 */
    g_assert_cmpmem(a, sizeof(a), b, sizeof(b));
    if (!strcmp(policy, "fifo")) {
        /* FIFO samples nothing, so the seed cannot change its victims */
        g_assert_cmpmem(a, sizeof(a), other, sizeof(other));
    } else {
        g_assert_true(memcmp(a, other, sizeof(a)) != 0);
    }
}

/* A namespace query-femu does not cover yet fails with a clear error. */
void femu_test_query_unsupported(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };

    femu_enable(&c, &femu->dev, alloc);
    femu_query_fails(femu->dev.bus->qts, "", data);
    femu_query_fails(femu->dev.bus->qts, "'nsid':1,'kind':'lines'", data);
    femu_disable(&c);
}

/* power_meas off (default): no PMS bit, no log 25h, no feature 25h */
void femu_test_pmeas_off(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t log = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmphex(femu_identify(&c, 0, 1, 0, log), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readl(qts, log + 96) & (1u << 21), ==, 0);
    g_assert_cmphex(qtest_readw(qts, log + 392), ==, 0);
    g_assert_cmphex(FEMU_SC(femu_get_log(&c, FEMU_LOG_POWER_MEAS, log, 64, 0)),
                    ==, NVME_INVALID_LOG_ID);
    g_assert_cmphex(FEMU_SC(femu_get_log(&c, 0x00, log, 1024, 0)), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(qtest_readl(qts, log + 4 * FEMU_LOG_POWER_MEAS), ==, 0);
    g_assert_cmphex(FEMU_SC(femu_get_feature(&c, FEMU_FID_POWER_MEAS, 0, 0, 0,
                                             NULL)), ==, NVME_INVALID_FIELD);
    g_assert_cmphex(FEMU_SC(femu_set_feature(&c, FEMU_FID_POWER_MEAS, false, 0,
                                             0x1, NULL)), ==,
                    NVME_INVALID_FIELD);
    guest_free(alloc, log);
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

void femu_test_sgl(void *obj, void *data, QGuestAllocator *alloc)
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
 * Write atomicity (NVM Express 2.1, AWUN): Identify reports AWUN 0, so a
 * one-block Write must reach the media whole with respect to other commands.
 * Two pollers run at once here: queue 1 overwrites block 0 with one of two
 * patterns, by Write or by Copy, and queue 2 reads block 0 into a buffer of
 * its own for each read. Every read must hold one pattern whole.
 *
 * @data names the case: "write" and "copy" use 64 KiB blocks, which make the
 * copy long enough for the race to show, and an SGL; "write-4k" uses 4 KiB
 * blocks and a PRP, the shape the NoSSD inline path takes.
 *
 * Nothing forces the two pollers to overlap. Reads that all run before or all
 * after the writes of their round see one pattern, so a round whose reads see
 * both shows an overlap. The test runs rounds until RWA_WANT such rounds have
 * passed, and skips when a host never overlaps the pollers.
 */
#define RWA_MAX_BS  65536
#define RWA_PER_Q   32
#define RWA_ROUNDS  200
#define RWA_WANT    8
#define RWA_A       0xa5
#define RWA_B       0x5a

static void femu_rwa_queue_rw(FemuCtrlState *c, FemuQueue *q, uint8_t opcode,
                              uint64_t slba, uint64_t buf, uint32_t bs)
{
    NvmeRwCmd rw;

    memset(&rw, 0, sizeof(rw));
    rw.opcode = opcode;
    rw.nsid = cpu_to_le32(1);
    if (bs > 4096) {
        rw.flags = 1 << 6;                  /* PSDT: SGL */
        rw.dptr.sgl.addr = cpu_to_le64(buf);
        rw.dptr.sgl.len = cpu_to_le32(bs);
    } else {
        rw.dptr.prp1 = cpu_to_le64(buf);
    }
    rw.slba = cpu_to_le64(slba);
    femu_zap_queue(c, q, (NvmeCmd *)&rw);
}

static void femu_rwa_queue_copy(FemuCtrlState *c, FemuQueue *q, uint64_t desc)
{
    NvmeCmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_CMD_COPY;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(desc);
    femu_zap_queue(c, q, &cmd);
}

void femu_test_rw_atomic(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    bool copy = !strcmp(data, "copy");
    uint32_t bs = strcmp(data, "write-4k") ? RWA_MAX_BS : 4096;
    FemuCtrlState c = { 0 };
    FemuQueue q1, q2;
    uint64_t pat[2], desc[2], rd[RWA_PER_Q];
    g_autofree uint8_t *got = g_malloc(bs);
    uint8_t d[32];
    int round, i, torn = 0, mixed = 0, reads = 0;
    size_t k;

    femu_enable(&c, &femu->dev, alloc);
    femu_zap_create_queue(&c, &q1, 1);
    femu_zap_create_queue(&c, &q2, 2);

    for (i = 0; i < 2; i++) {
        pat[i] = guest_alloc(alloc, bs);
        qtest_memset(qts, pat[i], i ? RWA_B : RWA_A, bs);
        /* blocks 1 and 2 hold the patterns for Copy to take */
        femu_rwa_queue_rw(&c, &q1, NVME_CMD_WRITE, 1 + i, pat[i], bs);
        femu_zap_ring(&c, &q1);
        g_assert_cmpint(femu_zap_complete(&c, &q1, NULL), ==, NVME_SUCCESS);
        desc[i] = guest_alloc(alloc, 4096);
        memset(d, 0, sizeof(d));
        stq_le_p(d + 8, 1 + i);             /* one block from block 1 + i */
        qtest_memwrite(qts, desc[i], d, sizeof(d));
    }
    femu_rwa_queue_rw(&c, &q1, NVME_CMD_WRITE, 0, pat[0], bs);
    femu_zap_ring(&c, &q1);
    g_assert_cmpint(femu_zap_complete(&c, &q1, NULL), ==, NVME_SUCCESS);
    for (i = 0; i < RWA_PER_Q; i++) {
        rd[i] = guest_alloc(alloc, bs);
    }

    for (round = 0; round < RWA_ROUNDS && mixed < RWA_WANT; round++) {
        int seen_a = 0, seen_b = 0;

        for (i = 0; i < RWA_PER_Q; i++) {
            if (copy) {
                femu_rwa_queue_copy(&c, &q1, desc[(round + i) & 1]);
            } else {
                femu_rwa_queue_rw(&c, &q1, NVME_CMD_WRITE, 0,
                                  pat[(round + i) & 1], bs);
            }
            femu_rwa_queue_rw(&c, &q2, NVME_CMD_READ, 0, rd[i], bs);
        }
        femu_zap_ring(&c, &q1);
        femu_zap_ring(&c, &q2);
        for (i = 0; i < RWA_PER_Q; i++) {
            g_assert_cmpint(femu_zap_complete(&c, &q1, NULL), ==,
                            NVME_SUCCESS);
            g_assert_cmpint(femu_zap_complete(&c, &q2, NULL), ==,
                            NVME_SUCCESS);
        }
        for (i = 0; i < RWA_PER_Q; i++) {
            qtest_bufread(qts, rd[i], got, bs);
            g_assert_true(got[0] == RWA_A || got[0] == RWA_B);
            seen_a += got[0] == RWA_A;
            seen_b += got[0] == RWA_B;
            for (k = 1; k < bs && got[k] == got[0]; k++) {
            }
            if (k < bs) {
                torn++;
            }
        }
        reads += RWA_PER_Q;
        mixed += seen_a && seen_b;
    }
    g_test_message("%s: %d rounds, %d reads, %d torn, %d rounds overlapped",
                   (char *)data, round, reads, torn, mixed);
    g_assert_cmpint(torn, ==, 0);
    if (mixed < RWA_WANT) {
        g_test_skip("the pollers did not overlap often enough on this host");
    }

    for (i = 0; i < RWA_PER_Q; i++) {
        guest_free(alloc, rd[i]);
    }
    for (i = 0; i < 2; i++) {
        guest_free(alloc, desc[i]);
        guest_free(alloc, pat[i]);
    }
    femu_queue_free(&c, &q2);
    femu_queue_free(&c, &q1);
    femu_disable(&c);
}

void femu_test_rw_atomic_split(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    bool copy = !strcmp(data, "copy");
    FemuCtrlState c = { 0 };
    FemuQueue q1, q2;
    uint64_t pat[2], desc, rd;
    g_autofree uint8_t *got = g_malloc(RWA_MAX_BS);
    uint8_t d[32] = { 0 };
    bool early = false;
    uint64_t waits;
    size_t k;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_zap_create_queue(&c, &q1, 1);
    femu_zap_create_queue(&c, &q2, 2);

    /* block 0 holds A; block 1 holds B for Copy to take */
    for (i = 0; i < 2; i++) {
        pat[i] = guest_alloc(alloc, RWA_MAX_BS);
        qtest_memset(qts, pat[i], i ? RWA_B : RWA_A, RWA_MAX_BS);
        femu_rwa_queue_rw(&c, &q1, NVME_CMD_WRITE, i, pat[i], RWA_MAX_BS);
        femu_zap_ring(&c, &q1);
        g_assert_cmpint(femu_zap_complete(&c, &q1, NULL), ==, NVME_SUCCESS);
    }
    desc = guest_alloc(alloc, 4096);
    stq_le_p(d + 8, 1);
    qtest_memwrite(qts, desc, d, sizeof(d));
    rd = guest_alloc(alloc, RWA_MAX_BS);

    femu_rwa_hold(qts, 1);
    if (copy) {
        femu_rwa_queue_copy(&c, &q1, desc);
    } else {
        femu_rwa_queue_rw(&c, &q1, NVME_CMD_WRITE, 0, pat[1], RWA_MAX_BS);
    }
    femu_zap_ring(&c, &q1);
    for (i = 0; i < FEMU_POLL_LIMIT_MS && !femu_rwa_get(qts, "x-copy-held");
         i++) {
        g_usleep(1000);
    }
    g_assert_cmpuint(femu_rwa_get(qts, "x-copy-held"), ==, 1);

    waits = femu_rwa_get(qts, "x-range-waits");
    femu_rwa_queue_rw(&c, &q2, NVME_CMD_READ, 0, rd, RWA_MAX_BS);
    femu_zap_ring(&c, &q2);
    for (i = 0; i < FEMU_POLL_LIMIT_MS && !early &&
         femu_rwa_get(qts, "x-range-waits") == waits; i++) {
        g_usleep(1000);
        early = femu_rwa_cq_ready(&c, &q2);
    }
    /* the read finished or blocked while the write was still stopped */
    g_assert_true(early || femu_rwa_get(qts, "x-range-waits") != waits);
    g_assert_cmpuint(femu_rwa_get(qts, "x-copy-held"), ==, 1);
    femu_rwa_hold(qts, 0);
    g_assert_cmpint(femu_zap_complete(&c, &q2, NULL), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_zap_complete(&c, &q1, NULL), ==, NVME_SUCCESS);

    qtest_bufread(qts, rd, got, RWA_MAX_BS);
    for (k = 0; k < RWA_MAX_BS && got[k] == RWA_B; k++) {
    }
    if (k < RWA_MAX_BS) {
        g_test_message("%s: byte %zu reads 0x%02x, not the new 0x%02x",
                       (char *)data, k, got[k], RWA_B);
    }
    g_assert_false(early);
    g_assert_cmpuint(k, ==, RWA_MAX_BS);

    guest_free(alloc, rd);
    guest_free(alloc, desc);
    for (i = 0; i < 2; i++) {
        guest_free(alloc, pat[i]);
    }
    femu_queue_free(&c, &q2);
    femu_queue_free(&c, &q1);
    femu_disable(&c);
}

/*
 * The shortest of @tries rounds, each of @nr commands @op sent together from
 * @slba on, in microseconds. A round completes before the next starts, so
 * the engine is idle at its start. A host stall slows one round; time the
 * device adds to every command slows each round.
 */
static int64_t femu_crypto_min_us(FemuCtrlState *c, uint8_t op, uint64_t slba,
                                  uint64_t buf, int nr, bool ok, int tries)
{
    int64_t best = INT64_MAX;

    for (int t = 0; t < tries; t++) {
        int64_t t0 = g_get_monotonic_time();

        for (int i = 0; i < nr; i++) {
            femu_crypto_submit(c, op, slba + 16 * i, buf, 0);
        }
        for (int i = 0; i < nr; i++) {
            uint16_t sc = FEMU_SC(femu_complete(c, &c->io, NULL, NULL));

            if (ok) {
                g_assert_cmpint(sc, ==, NVME_SUCCESS);
            } else {
                g_assert_cmpint(sc, !=, NVME_SUCCESS);
            }
        }
        best = MIN(best, g_get_monotonic_time() - t0);
    }
    return best;
}

#define FEMU_CRYPTO_TRIES 5

/*
 * Inline encryption engine on NoSSD, where nothing else adds time. At
 * crypto_mbps=1 an 8 KiB write, read or Write Zeroes holds the engine for
 * 8.192 ms. Two writes in one ring share the one engine and take 16.384 ms.
 * A rejected read moves no data and pays nothing, and a reset drops the
 * time of the commands it discards (eight writes, 65.5 ms). Off, each command
 * takes well under 4 ms. An untimed first write pays the start cost of the
 * first I/O.
 *
 * Each figure is the shortest of FEMU_CRYPTO_TRIES rounds. Engine time is in
 * every round, so the minimum keeps it, and a lower bound on the minimum
 * holds for each round. A busy host slows some rounds, so an upper bound
 * needs only one quick round. The write after a reset is one round, as only
 * the first write meets the discarded engine time.
 */
void femu_test_crypto(void *obj, void *data, QGuestAllocator *alloc)
{
    static const uint8_t ops[] = {
        NVME_CMD_WRITE, NVME_CMD_READ, NVME_CMD_WRITE_ZEROES,
    };
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    bool on = g_str_equal(data, "on");
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 8192);
    int64_t t0, us;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x4e, 8192);
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 64, buf)), ==,
                    NVME_SUCCESS);
    for (size_t i = 0; i < ARRAY_SIZE(ops); i++) {
        us = femu_crypto_min_us(&c, ops[i], 0, buf, 1, true,
                                FEMU_CRYPTO_TRIES);
        g_test_message("crypto %s: opcode 0x%x %" PRId64 " us",
                       on ? "on" : "off", ops[i], us);
        if (on) {
            g_assert_cmpint(us, >=, 8192);
        } else {
            g_assert_cmpint(us, <, 4000);
        }
    }

    /* two writes in one ring wait for each other at the engine */
    us = femu_crypto_min_us(&c, NVME_CMD_WRITE, 0, buf, 2, true,
                            FEMU_CRYPTO_TRIES);
    g_test_message("crypto %s: two writes %" PRId64 " us", on ? "on" : "off",
                   us);
    if (on) {
        g_assert_cmpint(us, >=, 2 * 8192);
    } else {
        g_assert_cmpint(us, <, 4000);
    }

    /*
     * A read past the end fails and books no engine time. Reads first fill
     * every request slot of the queue with a block count, so each rejected
     * read reuses one.
     */
    for (int i = 0; i < FEMU_QSIZE; i++) {
        g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_READ, 0, buf)), ==,
                        NVME_SUCCESS);
    }
    us = femu_crypto_min_us(&c, NVME_CMD_READ, 1ull << 40, buf, 1, false,
                            FEMU_CRYPTO_TRIES);
    g_test_message("crypto %s: rejected read %" PRId64 " us",
                   on ? "on" : "off", us);
    g_assert_cmpint(us, <, 4000);

    /*
     * A reset drops the engine time of the commands it discards. Eight
     * writes book 65.5 ms; once the first completes, the rest hold the
     * engine, and the reset comes before they end.
     */
    for (int i = 0; i < 8; i++) {
        femu_crypto_submit(&c, NVME_CMD_WRITE, 32 * i, buf, 0);
    }
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, NULL, NULL)), ==,
                    NVME_SUCCESS);
    femu_disable(&c);
    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    if (on) {
        t0 = g_get_monotonic_time();
        femu_crypto_submit(&c, NVME_CMD_WRITE, 0, buf, 0);
        g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, NULL, NULL)), ==,
                        NVME_SUCCESS);
        us = g_get_monotonic_time() - t0;
    } else {
        us = femu_crypto_min_us(&c, NVME_CMD_WRITE, 0, buf, 1, true,
                                FEMU_CRYPTO_TRIES);
    }
    g_test_message("crypto %s: write after reset %" PRId64 " us",
                   on ? "on" : "off", us);
    if (on) {
        g_assert_cmpint(us, >=, 8192);
        g_assert_cmpint(us, <, 3 * 8192);
    } else {
        g_assert_cmpint(us, <, 4000);
    }

    femu_disable(&c);
    guest_free(alloc, buf);
}

/*
 * Firmware time per opcode and per core, on NoSSD so nothing else adds time.
 * @data names the case: "read" charges reads only, "other" charges commands
 * other than reads and writes (a Flush here), "cores1" and "cores2" send two
 * reads at once to one and to two firmware cores. Each figure is 200 ms, so
 * the bounds below hold however loaded the host is, except the two-core one,
 * which leaves 150 ms of slack.
 */
#define FW_COST_MS 200

static int64_t femu_fw_elapsed_ms(FemuCtrlState *c, FemuQueue *q,
                                  NvmeCmd *cmds, int n)
{
    int64_t t0 = g_get_monotonic_time();
    int i;

    for (i = 0; i < n; i++) {
        femu_zap_queue(c, q, &cmds[i]);
    }
    femu_zap_ring(c, q);
    for (i = 0; i < n; i++) {
        g_assert_cmpint(femu_zap_complete(c, q, NULL), ==, NVME_SUCCESS);
    }
    return (g_get_monotonic_time() - t0) / 1000;
}

void femu_test_fw_cost(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    const char *mode = data;
    FemuCtrlState c = { 0 };
    FemuQueue q;
    NvmeCmd cmd[2];
    uint64_t buf;
    int64_t ms;

    femu_enable(&c, &femu->dev, alloc);
    femu_zap_create_queue(&c, &q, 1);
    buf = guest_alloc(alloc, 4096);
    memset(cmd, 0, sizeof(cmd));
    for (int i = 0; i < 2; i++) {
        cmd[i].opcode = NVME_CMD_READ;
        cmd[i].nsid = cpu_to_le32(1);
        cmd[i].dptr.prp1 = cpu_to_le64(buf);
        cmd[i].cdw12 = cpu_to_le32(7);
    }

    if (g_str_equal(mode, "read")) {
        ms = femu_fw_elapsed_ms(&c, &q, cmd, 1);
        g_assert_cmpint(ms, >=, FW_COST_MS);
        cmd[0].opcode = NVME_CMD_WRITE;
        ms = femu_fw_elapsed_ms(&c, &q, cmd, 1);
        g_assert_cmpint(ms, <, FW_COST_MS / 2);
    } else if (g_str_equal(mode, "reset")) {
        FemuCtrlState c2 = { 0 };
        FemuQueue q2;

        /* eight reads hold the firmware core for 1.6 s; reset after 50 ms */
        for (int i = 0; i < 8; i++) {
            femu_zap_queue(&c, &q, &cmd[0]);
        }
        femu_zap_ring(&c, &q);
        g_usleep(50 * 1000);
        femu_disable(&c);
        femu_enable(&c2, &femu->dev, alloc);
        femu_zap_create_queue(&c2, &q2, 1);
        ms = femu_fw_elapsed_ms(&c2, &q2, cmd, 1);
        g_test_message("first read after reset took %" PRId64 " ms", ms);
        g_assert_cmpint(ms, <, 2 * FW_COST_MS);
        guest_free(alloc, buf);
        femu_queue_free(&c2, &q2);
        femu_disable(&c2);
        return;
    } else if (g_str_equal(mode, "other")) {
        ms = femu_fw_elapsed_ms(&c, &q, cmd, 1);
        g_assert_cmpint(ms, <, FW_COST_MS / 2);
        memset(&cmd[0], 0, sizeof(cmd[0]));
        cmd[0].opcode = NVME_CMD_FLUSH;
        cmd[0].nsid = cpu_to_le32(1);
        ms = femu_fw_elapsed_ms(&c, &q, cmd, 1);
        g_assert_cmpint(ms, >=, FW_COST_MS);
    } else {
        ms = femu_fw_elapsed_ms(&c, &q, cmd, 2);
        g_test_message("two reads took %" PRId64 " ms", ms);
        if (g_str_equal(mode, "cores1")) {
            g_assert_cmpint(ms, >=, 2 * FW_COST_MS);
        } else {
            g_assert_cmpint(ms, >=, FW_COST_MS);
            g_assert_cmpint(ms, <, FW_COST_MS + 150);
        }
    }

    guest_free(alloc, buf);
    femu_queue_free(&c, &q);
    femu_disable(&c);
}

/*
 * Submission queues 1 and 2 both report to completion queue 1, and there is no
 * completion queue 2 (Base 2.3, 3.3.1). The second queue has to be served
 * anyway, and its completions have to land in queue 1 naming queue 2.
 */
void femu_test_shared_cq(void *obj, void *data, QGuestAllocator *alloc)
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

#define FEMU_BURST_QUEUES   4
#define FEMU_BURST_ROUNDS   64

/*
 * A poller fetches a submission queue entry by reading and advancing the head
 * without a lock, so each queue must have exactly one poller. Fill several
 * queues, ring them together, and expect every command to complete exactly
 * once, in the queue it was submitted to.
 */
void femu_test_poller_burst(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    FemuQueue q[FEMU_BURST_QUEUES];
    uint16_t first[FEMU_BURST_QUEUES];
    const int depth = FEMU_QSIZE - 1;
    uint64_t buf;
    NvmeCqe cqe;
    int r, i, k;

    femu_enable(&c, &femu->dev, alloc);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    for (i = 0; i < FEMU_BURST_QUEUES; i++) {
        femu_burst_queue(&c, &q[i], i + 1);
    }

    for (r = 0; r < FEMU_BURST_ROUNDS; r++) {
        for (i = 0; i < FEMU_BURST_QUEUES; i++) {
            first[i] = c.cid;
            for (k = 0; k < depth; k++) {
                NvmeRwCmd rw = { 0 };

                rw.opcode = NVME_CMD_READ;
                rw.cid = cpu_to_le16(c.cid++);
                rw.nsid = cpu_to_le32(1);
                rw.dptr.prp1 = cpu_to_le64(buf);
                rw.slba = cpu_to_le64(k);
                qtest_memwrite(qts, q[i].sq_addr +
                               q[i].sq_tail * sizeof(NvmeCmd), &rw,
                               sizeof(rw));
                q[i].sq_tail = (q[i].sq_tail + 1) % FEMU_QSIZE;
            }
        }
        for (i = 0; i < FEMU_BURST_QUEUES; i++) {
            qpci_io_writel(c.pdev, c.bar, femu_sq_doorbell(&c, q[i].qid),
                           q[i].sq_tail);
        }
        for (i = 0; i < FEMU_BURST_QUEUES; i++) {
            uint32_t done = 0;

            for (k = 0; k < depth; k++) {
                uint16_t cid;

                g_assert_cmpint(FEMU_SC(femu_complete(&c, &q[i], &cid, NULL)),
                                ==, NVME_SUCCESS);
                cid -= first[i];
                g_assert_cmpuint(cid, <, depth);
                g_assert_false(done & (1u << cid));
                done |= 1u << cid;
            }
        }
    }

    /* nothing completed twice after its first completion was read */
    g_usleep(10 * 1000);
    for (i = 0; i < FEMU_BURST_QUEUES; i++) {
        qtest_memread(qts, q[i].cq_addr + q[i].cq_head * sizeof(cqe), &cqe,
                      sizeof(cqe));
        g_assert_cmpint(le16_to_cpu(cqe.status) & 1, !=, q[i].phase);
        femu_queue_free(&c, &q[i]);
    }
    guest_free(alloc, buf);
    femu_disable(&c);
}

/* settings realize must refuse, and the property its error has to name */
static const struct {
    const char *args;
    const char *names;
} femu_refused[] = {
    { "'multipoller_enabled':2", "multipoller_enabled" },
    { "'multipoller_enabled':255", "multipoller_enabled" },
    { "'femu_mode':6", "femu_mode" },
    { "'femu_mode':7", "femu_mode" },
    { "'femu_mode':255", "femu_mode" },
    { "'namespaces':2,'namespace_modes':'bbssd,smartssd'", "namespace_modes" },
    { "'femu_mode':0,'lver':0", "lver" },
    { "'femu_mode':0,'lver':3", "lver" },
    { "'femu_mode':0,'lver':2,'flash_type':0", "flash_type" },
    { "'femu_mode':0,'lver':2,'flash_type':5", "flash_type" },
    { "'femu_mode':0,'lver':2,'flash_type':6", "flash_type" },
    { "'femu_mode':0,'lver':2,'flash_type':255", "flash_type" },
    { "'tplpbsy':-1", "tplpbsy" },
    { "'tplrbsy':-1", "tplrbsy" },
    { "'femu_mode':5,'gc_policy':'fifo'", "gc_policy" },
    { "'femu_mode':5,'gc_policy':'random'", "gc_policy" },
    { "'csd_slm_size':4", "csd_slm_size" },
    { "'femu_mode':4,'fdm_size':16,'csd_cp':true", "csd_cp" },
    { "'femu_mode':4,'fdm_size':16,'csd_slm_size':2048", "csd_slm_size" },
    { "'femu_mode':4,'fdm_size':16,'namespaces':2,"
      "'namespace_modes':'nossd,nossd','csd_slm_size':4", "csd_slm_size" },
    { "'csd_legacy_opcodes':true", "csd_legacy_opcodes" },
    { "'csd_pause':true", "csd_pause" },
    { "'femu_mode':4,'fdm_size':16,'namespaces':2,"
      "'namespace_modes':'csd,nossd','csd_pause':true", "csd_pause" },
    { "'femu_mode':4,'fdm_size':16,'csd_pause':true,'csd_pause_max_ms':0",
      "csd_pause_max_ms" },
    { "'femu_mode':4,'fdm_size':16,'csd_pause':true,"
      "'csd_pause_max_ms':60001", "csd_pause_max_ms" },
    { "'femu_mode':4,'fdm_size':16,'namespaces':2,"
      "'namespace_modes':'nossd,nossd','csd_legacy_opcodes':true",
      "csd_legacy_opcodes" },
};

void femu_test_config_refused(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    int i;

    for (i = 0; i < ARRAY_SIZE(femu_refused); i++) {
        g_autofree char *cmd = g_strdup_printf("{'execute':'device_add',"
            "'arguments':{'driver':'femu','id':'refused','addr':'5',"
            "'devsz_mb':64,%s}}", femu_refused[i].args);
        QDict *rsp = qtest_qmp(femu->dev.bus->qts, "%p",
                               qobject_from_json(cmd, NULL));

        g_test_message("%s", femu_refused[i].args);
        g_assert_true(qdict_haskey(rsp, "error"));
        g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                              "desc"),
                                femu_refused[i].names));
        qobject_unref(rsp);
    }
    qos_invalidate_command_line();
}

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

void femu_test_cq_full(void *obj, void *data, QGuestAllocator *alloc)
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

static bool femu_intx_asserted(FemuCtrlState *c)
{
    return qpci_config_readw(c->pdev, PCI_STATUS) & PCI_STATUS_INTERRUPT;
}

/*
 * I/O completions interrupt the host without a KVM route of their own, by
 * each of the three mechanisms the device offers: the pin, which is level
 * triggered and masked by INTMS; MSI, held back while INTMS masks its vector;
 * and MSI-X, which records a masked vector as pending.
 */
void femu_test_io_interrupts(void *obj, void *data,
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

/*
 * Interrupt coalescing on its own MSI-X vector, with the function masked so
 * an interrupt shows as the pending bit of vector 1. On the pin nothing is
 * held, since the pin is a level the controller recomputes from the queues.
 * @data "held": one entry is signalled after the aggregation time (25.5 ms).
 * @data "clear": clearing Feature 08h while an entry is held signals it at
 * once. The pending bit stays set, so each case runs on its own device.
 */
void femu_test_intc_msix(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QPCIDevice *dev = &femu->dev;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    bool held = g_str_equal(data, "held");
    uint8_t cap;
    uint16_t flags;
    int64_t t0, ms;

    /* pin based: the threshold and time are set, the pin rises at once */
    femu_enable(&c, dev, alloc);
    femu_create_io_queues_irq(&c, 0);
    g_assert_cmpint(femu_set_feature(&c, 0x08, false, 0, 3 | (255 << 8),
                                     NULL), ==, NVME_SUCCESS);
    t0 = g_get_monotonic_time();
    femu_read_unconsumed(&c, buf);
    FEMU_WAIT_FOR(femu_intx_asserted(&c));
    ms = (g_get_monotonic_time() - t0) / 1000;
    g_test_message("pin: asserted after %" PRId64 " ms", ms);
    g_assert_cmpint(ms, <, 15);
    g_assert_cmpint(femu_complete(&c, &c.io, NULL, NULL), ==, NVME_SUCCESS);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);

    qpci_msix_enable(dev);
    cap = qpci_find_capability(dev, PCI_CAP_ID_MSIX, 0);
    flags = qpci_config_readw(dev, cap + PCI_MSIX_FLAGS);
    qpci_config_writew(dev, cap + PCI_MSIX_FLAGS,
                       flags | PCI_MSIX_FLAGS_MASKALL);
    memset(&c, 0, sizeof(c));
    femu_enable(&c, dev, alloc);
    femu_create_io_queues_irq(&c, 1);
    g_assert_cmpint(femu_set_feature(&c, 0x08, false, 0, 3 | (255 << 8),
                                     NULL), ==, NVME_SUCCESS);

    t0 = g_get_monotonic_time();
    femu_read_unconsumed(&c, buf);
    g_assert_false(qpci_msix_pending(dev, 1));
    if (held) {
        FEMU_WAIT_FOR(qpci_msix_pending(dev, 1));
        ms = (g_get_monotonic_time() - t0) / 1000;
        g_test_message("MSI-X, THR 3, TIME 25.5 ms: pending after %" PRId64
                       " ms", ms);
        g_assert_cmpint(ms, >=, 25);
        g_assert_cmpint(ms, <, 120);
    } else {
        t0 = g_get_monotonic_time();
        g_assert_cmpint(femu_set_feature(&c, 0x08, false, 0, 0, NULL), ==,
                        NVME_SUCCESS);
        FEMU_WAIT_FOR(qpci_msix_pending(dev, 1));
        ms = (g_get_monotonic_time() - t0) / 1000;
        g_test_message("Feature 08h cleared: pending after %" PRId64 " ms",
                       ms);
        g_assert_cmpint(ms, <, 15);
    }
    g_assert_cmpint(femu_complete(&c, &c.io, NULL, NULL), ==, NVME_SUCCESS);

    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    qpci_msix_disable(dev);
    guest_free(alloc, buf);
}

/* queue pair @q on interrupt vector @vector, interrupts on when @ien */
static void femu_create_pair_irq(FemuCtrlState *c, FemuQueue *q, uint16_t qid,
                                 uint16_t vector, bool ien)
{
    NvmeCmd cmd;

    femu_queue_init(c, q, qid);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_CREATE_CQ;
    cmd.dptr.prp1 = cpu_to_le64(q->cq_addr);
    cmd.cdw10 = cpu_to_le32(((FEMU_QSIZE - 1) << 16) | qid);
    cmd.cdw11 = cpu_to_le32((vector << 16) | NVME_CQ_PC |
                            (ien ? FEMU_CQ_IEN : 0));
    g_assert_cmpint(femu_admin(c, &cmd), ==, NVME_SUCCESS);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_CREATE_SQ;
    cmd.dptr.prp1 = cpu_to_le64(q->sq_addr);
    cmd.cdw10 = cpu_to_le32(((FEMU_QSIZE - 1) << 16) | qid);
    cmd.cdw11 = cpu_to_le32((qid << 16) | NVME_SQ_PC);
    g_assert_cmpint(femu_admin(c, &cmd), ==, NVME_SUCCESS);
}

/* submit one read on @q and wait until its entry is posted, unconsumed */
static void femu_read_posted(FemuCtrlState *c, FemuQueue *q, uint64_t buf)
{
    uint64_t slot = q->cq_addr + q->cq_head * sizeof(NvmeCqe);
    NvmeRwCmd rw;

    memset(&rw, 0, sizeof(rw));
    rw.opcode = NVME_CMD_READ;
    rw.nsid = cpu_to_le32(1);
    rw.dptr.prp1 = cpu_to_le64(buf);
    rw.nlb = cpu_to_le16(7);
    femu_submit(c, q, (NvmeCmd *)&rw);
    FEMU_WAIT_FOR((le16_to_cpu(qtest_readw(c->pdev->bus->qts, slot + 14)) &
                   1) == q->phase);
}

/*
 * Two completion queues on MSI-X vector 1 with THR 3 and TIME 25.5 ms. Queue
 * 1 holds one entry, then queue 2 posts one. @data "delete": queue 2 is
 * deleted before the time runs out; the delete signals the vector at once,
 * so queue 1's entry is not lost. @data "ien": queue 2 has interrupts off, so
 * it must not take the
 * vector's interrupt away from queue 1.
 */
void femu_test_intc_shared(void *obj, void *data,
                           QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QPCIDevice *dev = &femu->dev;
    FemuCtrlState c = { 0 };
    bool del = g_str_equal(data, "delete");
    uint64_t buf = guest_alloc(alloc, 4096);
    bool early;
    FemuQueue q2;
    NvmeCmd cmd;
    uint8_t cap;
    uint16_t flags;
    int64_t t0, ms;

    qpci_msix_enable(dev);
    cap = qpci_find_capability(dev, PCI_CAP_ID_MSIX, 0);
    flags = qpci_config_readw(dev, cap + PCI_MSIX_FLAGS);
    qpci_config_writew(dev, cap + PCI_MSIX_FLAGS,
                       flags | PCI_MSIX_FLAGS_MASKALL);
    femu_enable(&c, dev, alloc);
    femu_create_io_queues_irq(&c, 1);
    femu_create_pair_irq(&c, &q2, 2, 1, del);
    g_assert_cmpint(femu_set_feature(&c, 0x08, false, 0, 3 | (255 << 8),
                                     NULL), ==, NVME_SUCCESS);

    t0 = g_get_monotonic_time();
    femu_read_posted(&c, &c.io, buf);
    femu_read_posted(&c, &q2, buf);
    /*
     * Two of three completions: nothing fires before the 25.5 ms time.
     * A slow host (a sanitizer build) can take that long for two reads,
     * and then the time has rightly fired the vector. Read the bit first:
     * a read that ended within 20 ms also started within 20 ms.
     */
    early = qpci_msix_pending(dev, 1);
    if ((g_get_monotonic_time() - t0) / 1000 < 20) {
        g_assert_false(early);
    }
    if (del) {
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = NVME_ADM_CMD_DELETE_SQ;
        cmd.cdw10 = cpu_to_le32(2);
        g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
        /* the delete signals what the vector holds, at once */
        t0 = g_get_monotonic_time();
        cmd.opcode = NVME_ADM_CMD_DELETE_CQ;
        g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    }
    FEMU_WAIT_FOR(qpci_msix_pending(dev, 1));
    ms = (g_get_monotonic_time() - t0) / 1000;
    g_test_message("shared vector, %s: pending after %" PRId64 " ms",
                   del ? "queue 2 deleted" : "queue 2 without IEN", ms);
    g_assert_cmpint(ms, <, del ? 15 : 200);

    g_assert_cmpint(femu_complete(&c, &c.io, NULL, NULL), ==, NVME_SUCCESS);
    if (!del) {
        g_assert_cmpint(femu_complete(&c, &q2, NULL, NULL), ==, NVME_SUCCESS);
    }
    femu_disable(&c);
    femu_queue_free(&c, &c.io);
    femu_queue_free(&c, &q2);
    qpci_msix_disable(dev);
    guest_free(alloc, buf);
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
void femu_test_prp_list_offset(void *obj, void *data,
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

#define FEMU_INVALID_QID        0x101   /* command specific */
#define FEMU_INVALID_PRP_OFFSET 0x13
#define FEMU_CMD_SEQ_ERROR      0x0c

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
void femu_test_queue_create_status(void *obj, void *data,
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
#define FEMU_INVALID_QSIZE  0x102   /* command specific */

/*
 * The controller configuration and status registers (Base 2.3, Figures 41-42
 * and 3.5): a write that disables and shuts down at once does both, a reset
 * clears the shutdown status, the I/O entry sizes may be left at 0 until an
 * I/O queue is made, and ASQ may be written as two dwords in either order.
 */
void femu_test_cc_states(void *obj, void *data, QGuestAllocator *alloc)
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
    /* clearing SHN has no shutdown effect: SHST stays to the next enable */
    qpci_io_writel(dev, c.bar, 0x14, 0);
    g_assert_cmpint(FEMU_CSTS_SHST(qpci_io_readl(dev, c.bar, 0x1c)), ==, 2);
    femu_queue_free(&c, &c.admin);
    qpci_iounmap(dev, c.bar);

    /* shut down while enabled, then reset with SHN still set */
    memset(&c, 0, sizeof(c));
    femu_enable(&c, dev, alloc);
    qpci_io_writel(dev, c.bar, 0x14, FEMU_CC_ENABLE | FEMU_CC_SHN_NORMAL);
    g_assert_cmpint(FEMU_CSTS_SHST(qpci_io_readl(dev, c.bar, 0x1c)), ==, 2);
    /* the teardown keeps CC as the host wrote it */
    g_assert_cmphex(qpci_io_readl(dev, c.bar, 0x14), ==,
                    FEMU_CC_ENABLE | FEMU_CC_SHN_NORMAL);
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
void femu_test_features_reset(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    bool vwc = data && *(bool *)data;
    FemuCtrlState c = { 0 };
    uint32_t result;

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_ARBITRATION, false, 0,
                                             0x1, NULL)), ==, NVME_SUCCESS);
    /* Default (SEL 1) and Saved (SEL 2) keep the reset value */
    for (uint8_t sel = 1; sel <= 2; sel++) {
        g_assert_cmpint(femu_get_feature(&c, NVME_ARBITRATION, sel, 0, 0,
                                         &result), ==, NVME_SUCCESS);
        g_assert_cmphex(result, ==, FEMU_ARB_DEFAULT);
    }
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
    g_assert_cmphex(result, ==, FEMU_ARB_DEFAULT);
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
#define FEMU_INVALID_NSID       0x0b
#define FEMU_AEC_TEMPERATURE    0x02

/*
 * The Error Information log counts from 1 and lists the newest error first
 * (Base 2.3, 5.2.12.1.2). Reading SMART or the error log with Retain
 * Asynchronous Event keeps the event reported, so the same event cannot be
 * raised again until a read without it; SMART for a namespace that does not
 * exist is refused; and no log page offers an index offset.
 */
void femu_test_error_log(void *obj, void *data, QGuestAllocator *alloc)
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

/*
 * Identify fields a version 1.4 controller must fill (Base 2.3, Figure 328),
 * the command-set-independent namespace structure (CNS 08h, Figure 335) with
 * the namespace ready, a UUID per namespace that is not zero and does not
 * change, CNS read from bits 7:0 only, and CNS 00h ignoring CSI.
 */
void femu_test_identify_fields(void *obj, void *data,
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
void femu_test_prp_status(void *obj, void *data, QGuestAllocator *alloc)
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
void femu_test_mdts_unit(void *obj, void *data, QGuestAllocator *alloc)
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

/*
 * A write to a doorbell that does not exist, or past the end of its queue,
 * is an Error event, 00h and 01h (Base 2.3, Figure 152). After Doorbell
 * Buffer Config the admin queue's EventIdx follows the values written, so a
 * host that consults it keeps ringing (Annex B.5).
 */
void femu_test_doorbell_errors(void *obj, void *data,
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

/*
 * Protection information lives in the metadata, eight bytes of it, so a
 * format that turns it on must pick an LBA format with at least that much
 * (NVM 1.2, Format NVM). Advertising a protection type in DPC is not enough:
 * every format here has no metadata, and the command used to succeed and
 * leave the namespace reporting protection it had nowhere to keep.
 */
void femu_test_format_pi_needs_metadata(void *obj, void *data,
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
 * erase and a user data erase are accepted; without encryption FNA has no
 * CRYES, so a cryptographic erase is refused, and 011b and above are
 * reserved. Bit 8 is PIL, not part of it.
 */
void femu_test_format_ses(void *obj, void *data, QGuestAllocator *alloc)
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

/* BAR0 bits 13:4 are read only, so it is at least 16 KiB (PCIe 1.3, Fig 20) */
void femu_test_bar0_size(void *obj, void *data, QGuestAllocator *alloc)
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
void femu_test_aer_limit(void *obj, void *data, QGuestAllocator *alloc)
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

#define FEMU_CMD_VERIFY         0x0c
#define FEMU_UNRECOVERED_READ   0x281   /* media error */

/*
 * Verify (NVM 1.2, 3.3.4) moves no data and fails where a Read would: on an
 * uncorrectable block, and past the end of the namespace. It is listed in the
 * effects log when ONCS offers it.
 */
void femu_test_verify(void *obj, void *data, QGuestAllocator *alloc)
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

    /*
     * Write Zeroes with Deallocate repairs its own blocks, which then read
     * zeros; a marked block past its range stays marked.
     */
    qtest_memset(qts, buf, 0x5a, 4096);
    g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE, 8, buf), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_lba_cmd(&c, NVME_CMD_WRITE_UNCOR, 8, 16), ==,
                    NVME_SUCCESS);
    {
        NvmeRwCmd rw;

        memset(&rw, 0, sizeof(rw));
        rw.opcode = NVME_CMD_WRITE_ZEROES;
        rw.nsid = cpu_to_le32(1);
        rw.slba = cpu_to_le64(8);
        rw.nlb = cpu_to_le16(7);
        rw.control = cpu_to_le16(1 << 9);           /* DEAC */
        g_assert_cmpint(femu_io(&c, (NvmeCmd *)&rw), ==, NVME_SUCCESS);
    }
    g_assert_cmpint(femu_lba_cmd(&c, FEMU_CMD_VERIFY, 0, 16), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_lba_cmd(&c, FEMU_CMD_VERIFY, 16, 8), ==,
                    FEMU_UNRECOVERED_READ);
    g_assert_cmpint(femu_rw(&c, NVME_CMD_READ, 8, buf), ==, NVME_SUCCESS);
    for (int i = 0; i < 4096; i += 512) {
        g_assert_cmphex(qtest_readb(qts, buf + i), ==, 0);
    }

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
void femu_test_self_test(void *obj, void *data, QGuestAllocator *alloc)
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
void femu_test_intx_shadow_doorbell(void *obj, void *data,
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

/* Fixed T10-DIF vectors, including metadata before a final PI tuple. */
void femu_test_pi_verify(void *obj, void *data, QGuestAllocator *alloc)
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

            if (first) {
                /* NVM 1.1 Figure 114: no PI in the first metadata bytes */
                g_assert_cmpint(femu_format_dw10(&c, FEMU_MD_NLBAF |
                               (type << 5) | (first << 8)), ==,
                               NVME_INVALID_FORMAT);
                continue;
            }
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

/*
 * PCI power management (pci_pm=on): the capability with PM 1.2 and
 * No_Soft_Reset; D3hot and back to D0 keep the controller ready, and an
 * admin command runs after it.
 */
void femu_test_pci_pm(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QPCIDevice *pdev = &femu->dev;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint8_t pm;

    femu_enable(&c, pdev, alloc);
    pm = qpci_find_capability(pdev, PCI_CAP_ID_PM, 0);
    g_assert_cmpuint(pm, !=, 0);
    g_assert_cmphex(qpci_config_readw(pdev, pm + PCI_PM_PMC) & 0x7, ==, 3);
    g_assert_cmphex(qpci_config_readw(pdev, pm + PCI_PM_CTRL) &
                    PCI_PM_CTRL_NO_SOFT_RESET, ==, PCI_PM_CTRL_NO_SOFT_RESET);
    qpci_config_writew(pdev, pm + PCI_PM_CTRL, 3);
    g_assert_cmphex(qpci_config_readw(pdev, pm + PCI_PM_CTRL) & 3, ==, 3);
    qpci_config_writew(pdev, pm + PCI_PM_CTRL, 0);
    g_assert_cmphex(qpci_config_readw(pdev, pm + PCI_PM_CTRL) & 3, ==, 0);
    g_assert_cmphex(qpci_io_readl(pdev, c.bar, 0x1c) & 1, ==, 1);  /* RDY */
    g_assert_cmphex(femu_identify(&c, 0, NVME_ID_CNS_CTRL, 0, buf), ==,
                    NVME_SUCCESS);
    femu_disable(&c);
    guest_free(alloc, buf);
}

/*
 * QEMU trace points (hw/femu/trace-events): QMP lists the nine femu_*
 * events, one turns on, and commands still run with it on.
 */
void femu_test_trace_events(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    QDict *rsp;
    QList *list;
    bool io = false;
    QListEntry *e;

    rsp = qtest_qmp(qts, "{'execute':'trace-event-get-state','arguments':"
                    "{'name':'femu_*'}}");
    list = qdict_get_qlist(rsp, "return");
    g_assert_cmpuint(qlist_size(list), ==, 9);
    QLIST_FOREACH_ENTRY(list, e) {
        QDict *ev = qobject_to(QDict, qlist_entry_obj(e));

        io |= !strcmp(qdict_get_str(ev, "name"), "femu_io_cmd");
    }
    g_assert_true(io);
    qobject_unref(rsp);
    qtest_qmp_assert_success(qts, "{'execute':'trace-event-set-state',"
                             "'arguments':{'name':'femu_admin_cmd',"
                             "'enable':true}}");
    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmphex(femu_identify(&c, 0, NVME_ID_CNS_CTRL, 0, buf), ==,
                    NVME_SUCCESS);
    femu_disable(&c);
    qtest_qmp_assert_success(qts, "{'execute':'trace-event-set-state',"
                             "'arguments':{'name':'femu_admin_cmd',"
                             "'enable':false}}");
    guest_free(alloc, buf);
}

/* a PI read or write with a 48-bit reference tag: CDW3 bits 15:0, CDW14 */
static uint16_t femu_pi64_io(FemuCtrlState *c, uint8_t opcode, uint64_t slba,
                             uint64_t dbuf, uint64_t mbuf, uint8_t prinfo,
                             uint64_t ref, uint16_t app)
{
    NvmeRwCmd rw = { 0 };

    rw.opcode = opcode;
    rw.nsid = cpu_to_le32(1);
    rw.slba = cpu_to_le64(slba);
    rw.nlb = cpu_to_le16(1);
    rw.dptr.prp1 = cpu_to_le64(dbuf);
    rw.mptr = cpu_to_le64(mbuf);
    rw.control = cpu_to_le16(prinfo << 10);
    rw.cdw3 = cpu_to_le32(ref >> 32);
    rw.reftag = cpu_to_le32(ref);
    rw.apptag = cpu_to_le16(app);
    rw.appmask = cpu_to_le16(0xffff);
    return FEMU_SC(femu_io(c, (NvmeCmd *)&rw));
}

/*
 * 64-bit guard protection information (pif=2, NVM 1.2 PIF 10b): CTRATT.ELBAS
 * and the CNS 05h extended formats; a PRACT write makes 16-byte tuples
 * (CRC64 guard, application tag, 48-bit reference tag from CDW3 and CDW14);
 * a checked read passes, and a wrong reference tag or guard fails.
 */
void femu_test_pi64(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t dbuf = guest_alloc(alloc, 4096);
    uint64_t mbuf = guest_alloc(alloc, 4096);
    const uint64_t ref = 0x000700000010ULL;
    uint8_t d[1024];
    uint8_t m[32];

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    g_assert_cmpint(femu_identify(&c, 0, 1, 0, mbuf), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readl(qts, mbuf + 96) & (1u << 15), ==, 1u << 15);
    /* Type 2: the reference tag is the host's, all 48 bits */
    g_assert_cmpint(femu_format_dw10(&c, FEMU_MD_NLBAF | 2 << 5), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_identify(&c, 1, 0x05, 0, mbuf), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readl(qts, mbuf + 12 + 4 * FEMU_MD_NLBAF), ==,
                    0x100);
    g_assert_cmphex(qtest_readl(qts, mbuf + 12), ==, 0);
    g_assert_cmphex(qtest_readb(qts, mbuf + 8), ==, 0x05);         /* PIC */

    for (int i = 0; i < sizeof(d); i++) {
        d[i] = i * 7;
    }
    qtest_memwrite(qts, dbuf, d, sizeof(d));
    g_assert_cmpint(femu_pi64_io(&c, NVME_CMD_WRITE, 16, dbuf, mbuf, 0x8,
                                 ref, 0x1234), ==, NVME_SUCCESS);
    qtest_memset(qts, dbuf, 0, 4096);
    qtest_memset(qts, mbuf, 0, 4096);
    g_assert_cmpint(femu_pi64_io(&c, NVME_CMD_READ, 16, dbuf, mbuf, 0x7,
                                 ref, 0x1234), ==, NVME_SUCCESS);
    qtest_memread(qts, dbuf, d + 512, 512);
    g_assert_cmpmem(d + 512, 512, d, 512);
    qtest_memread(qts, mbuf, m, sizeof(m));
    /* each tuple: guard (8), app tag (2), 48-bit ref tag (6), big endian */
    /* CRC-64/NVME of the block, computed apart from FEMU */
    g_assert_cmphex(ldq_be_p(m), ==, 0xd9b1d30702feaed0ULL);
    g_assert_cmphex(lduw_be_p(m + 8), ==, 0x1234);
    g_assert_cmphex(lduw_be_p(m + 10), ==, 0x0007);
    g_assert_cmphex(ldl_be_p(m + 12), ==, 0x10);
    g_assert_cmphex(ldl_be_p(m + 16 + 12), ==, 0x11);
    g_assert_cmphex(ldq_be_p(m + 16), ==, 0xd9b1d30702feaed0ULL);
    /* the upper 16 bits of the tag are checked too */
    g_assert_cmpint(femu_pi64_io(&c, NVME_CMD_READ, 16, dbuf, mbuf, 0x1,
                                 ref & 0xffffffff, 0x1234), ==, 0x284);
    /* a host tuple with a 16-bit style guard fails the 64-bit check */
    stw_be_p(m, 0xbeef);
    qtest_memwrite(qts, mbuf, m, sizeof(m));
    g_assert_cmpint(femu_pi64_io(&c, NVME_CMD_WRITE, 16, dbuf, mbuf, 0x4,
                                 ref, 0x1234), ==, 0x282);

    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    guest_free(alloc, mbuf);
    guest_free(alloc, dbuf);
}

void femu_test_ns_create_pi_validation(void *obj, void *data,
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
                                       GPOINTER_TO_UINT(data) == 1 ? 0x17 : 0);
                        /* PIL is never stored */
                        g_assert_cmphex(qtest_readb(qts, buf + 29), ==, type);
                        g_assert_cmpint(femu_ns_delete(&c, nsid), ==,
                                       NVME_SUCCESS);
                    }
                }
            }
        }
    }
    /* NVM 1.1 Figure 114: no PI in the first metadata bytes */
    g_assert_cmpint(femu_ns_create_pi(&c, buf, FEMU_MD_NLBAF, 1 | (1 << 3),
                                      &nsid), ==, NVME_INVALID_FORMAT);
    g_assert_cmpint(femu_ns_create_pi(&c, buf, 15, 1, &nsid), ==,
                   NVME_INVALID_FORMAT);
    g_assert_cmpint(femu_ns_create_pi(&c, buf, FEMU_MD_NLBAF, 0x11, &nsid),
                   ==, NVME_INVALID_FORMAT);
    femu_disable(&c);
    guest_free(alloc, buf);
}

void femu_test_pi_compare(void *obj, void *data, QGuestAllocator *alloc)
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

            if (first) {
                /* NVM 1.1 Figure 114: no PI in the first metadata bytes */
                g_assert_cmpint(femu_format_dw10(&c, FEMU_MD_NLBAF |
                               (1 << 5) | (first << 8) | (extended << 4)), ==,
                               NVME_INVALID_FORMAT);
                continue;
            }
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
            g_assert_cmphex(femu_io_status & NVME_DNR, ==, NVME_DNR);
            m[other] ^= 1;
            d[0] ^= 1;
            femu_pi_host(qts, dbuf, mbuf, d, m, 16, extended);
            g_assert_cmpint(femu_pi_io(&c, NVME_CMD_COMPARE, 1, 16, 2,
                           dbuf, mbuf, 0, 16, 0, 0), ==, NVME_CMP_FAILURE);
            g_assert_cmphex(femu_io_status & NVME_DNR, ==, NVME_DNR);
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

void femu_test_pi_zeroes(void *obj, void *data, QGuestAllocator *alloc)
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

            if (first) {
                /* NVM 1.1 Figure 114: no PI in the first metadata bytes */
                g_assert_cmpint(femu_format_dw10(&c, FEMU_MD_NLBAF |
                               (type << 5) | (first << 8)), ==,
                               NVME_INVALID_FORMAT);
                continue;
            }
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

void femu_test_pi_generate_ref(void *obj, void *data,
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

            if (first) {
                /* NVM 1.1 Figure 114: no PI in the first metadata bytes */
                g_assert_cmpint(femu_pi_format_ns(&c, 1, format), ==,
                               NVME_INVALID_FORMAT);
                continue;
            }
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

void femu_test_pi_copy_no_pi(void *obj, void *data,
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

void femu_test_pi_copy_convert(void *obj, void *data,
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
    /* PI in the first bytes of metadata is not offered (DPC 17h) */
    g_assert_cmpint(femu_pi_format_ns(&c, 2, FEMU_MD_NLBAF | (1 << 5) |
                   (1 << 8)), ==, NVME_INVALID_FORMAT);
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

void femu_test_pi_dpc_no_metadata(void *obj, void *data,
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

void femu_test_pi_format(void *obj, void *data, QGuestAllocator *alloc)
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
    g_assert_cmphex(qtest_readb(qts, buf + 28), ==, enabled ? 0x17 : 0);
    g_assert_cmphex(qtest_readb(qts, buf + 29), ==, 0);
    for (type = 1; type <= 3; type++) {
        for (first = 0; first <= 1; first++) {
            uint32_t dw10 = FEMU_MD_NLBAF | (type << 5) | (first << 8);

            /* no PI in the first bytes; a refused format keeps the last */
            g_assert_cmpint(femu_format_dw10(&c, dw10), ==,
                           enabled && !first ? NVME_SUCCESS :
                           NVME_INVALID_FORMAT);
            g_assert_cmpint(femu_identify(&c, 1, NVME_ID_CNS_NS, 0, buf), ==,
                           NVME_SUCCESS);
            g_assert_cmphex(qtest_readb(qts, buf + 29), ==,
                           enabled ? type : 0);
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
        /* PIL with PI off is not stored: NVM 1.1 Figure 114 wants DPS 00h */
        g_assert_cmphex(qtest_readb(qts, buf + 29), ==, 0);
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

#define FEMU_MD_UNIT    (512 + FEMU_MD_MS)

/*
 * Extended LBAs (NVM 1.2, 2.1.4.1): each block's metadata follows its data in
 * the host buffer. The same commands carry it, the transfer (and so MDTS) is
 * data plus metadata, and Format moves between interleaved and separate.
 */
void femu_test_metadata_extended(void *obj, void *data,
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
    g_assert_cmphex(femu_io_status & NVME_DNR, ==, NVME_DNR);

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
void femu_test_admin_fuzz(void *obj, void *data, QGuestAllocator *alloc)
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
    GRand *rng = g_rand_new_with_seed(femu_fuzz_seed(0x46454d55));
    NvmeCmd cmd;
    int distinct = 0;
    int i;

    femu_enable(&c, &femu->dev, alloc);

    for (i = 0; i < femu_fuzz_rounds(FEMU_FUZZ_ROUNDS); i++) {
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

/* the planted bug of the fuzzer control is refused outside x-fuzz */
void femu_test_fuzz_control_refused(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    QDict *rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':"
                           "{'driver':'femu','id':'fc-refused','addr':'5',"
                           "'devsz_mb':16,'x-fuzz-control':true}}");

    g_assert_true(qdict_haskey(rsp, "error"));
    g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                          "desc"),
                            "x-fuzz-control needs x-fuzz"));
    qobject_unref(rsp);
    qos_invalidate_command_line();
}

/* Lockdown (24h): SCP in bits 3:0, PRHBT bit 4, IFC 6:5, OFI 15:8 */
static uint16_t femu_lockdown(FemuCtrlState *c, uint8_t scp, bool prhbt,
                              uint8_t ifc, uint8_t ofi)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = 0x24;
    cmd.cdw10 = cpu_to_le32(scp | (prhbt ? 1u << 4 : 0) | ifc << 5 |
                            ofi << 8);
    return FEMU_SC(femu_admin(c, &cmd));
}

/* Get Log 14h with LSP Contents @cnt and Scope @scp, 512 bytes */
static uint16_t femu_lockdown_log(FemuCtrlState *c, uint64_t buf,
                                  uint8_t cnt, uint8_t scp)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = NVME_ADM_CMD_GET_LOG_PAGE;
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(0x14 | (scp | cnt << 4) << 8 | 127u << 16);
    return FEMU_SC(femu_admin(c, &cmd));
}

static bool femu_list_has(const uint8_t *log, uint8_t v)
{
    for (int i = 0; i < log[3]; i++) {
        if (log[4 + i] == v) {
            return true;
        }
    }
    return false;
}

/*
 * Command and Feature Lockdown (Base 2.3, 8.1.5): OACS bit 10; log 14h
 * lists what can be prohibited, in order, and what is prohibited now; a
 * prohibited opcode or Set Features FID fails with 23h, Get Features does
 * not; a reset keeps the state; allow undoes it. Commands FEMU keeps
 * open, a Management Endpoint and reserved scopes are refused.
 */
void femu_test_lockdown(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint8_t log[512];
    uint32_t res = 0;

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmphex(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readw(qts, buf + 256) & (1 << 10), ==, 1 << 10);
    /* log 00h: entry 14h is exactly LSUPP */
    g_assert_cmphex(FEMU_SC(femu_get_log(&c, 0x00, buf, 1024, 0)), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(qtest_readl(qts, buf + 0x14 * 4), ==, 1);

    /* what can be prohibited: Set Features, not Identify; in order */
    g_assert_cmphex(femu_lockdown_log(&c, buf, 0, 0), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, log, sizeof(log));
    g_assert_cmphex(log[0], ==, 0x00);
    g_assert_cmpuint(log[3], >, 0);
    g_assert_true(femu_list_has(log, 0x09));
    g_assert_false(femu_list_has(log, 0x06));
    g_assert_false(femu_list_has(log, 0x24));
    for (int i = 1; i < log[3]; i++) {
        g_assert_cmpuint(log[4 + i - 1], <, log[4 + i]);
    }
    g_assert_cmphex(femu_lockdown_log(&c, buf, 0, 2), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, log, sizeof(log));
    g_assert_cmphex(log[0], ==, 0x02);
    g_assert_true(femu_list_has(log, 0x0b));
    /* nothing is prohibited yet */
    g_assert_cmphex(femu_lockdown_log(&c, buf, 1, 0), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readb(qts, buf + 3), ==, 0);

    /* prohibit FID 0Bh: Set fails and changes nothing, Get works */
    g_assert_cmphex(FEMU_SC(femu_set_feature(&c, 0x0b, false, 0, 1u << 8,
                                             NULL)), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_lockdown(&c, 2, true, 0, 0x0b), ==, NVME_SUCCESS);
    g_assert_cmphex(FEMU_SC(femu_set_feature(&c, 0x0b, false, 0, 0, NULL)),
                    ==, 0x023);
    g_assert_cmphex(FEMU_SC(femu_get_feature(&c, 0x0b, 0, 0, 0, &res)), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(res, ==, 1u << 8);
    /* a high FID (80h) and another opcode (Device Self-test, 14h) too */
    g_assert_cmphex(femu_lockdown(&c, 2, true, 0, 0x80), ==, NVME_SUCCESS);
    g_assert_cmphex(FEMU_SC(femu_set_feature(&c, 0x80, false, 0, 0, NULL)),
                    ==, 0x023);
    g_assert_cmphex(femu_lockdown(&c, 2, false, 0, 0x80), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_lockdown(&c, 0, true, 0, 0x14), ==, NVME_SUCCESS);
    {
        NvmeCmd dst = { 0 };

        dst.opcode = 0x14;
        dst.nsid = cpu_to_le32(0xffffffff);
        dst.cdw10 = cpu_to_le32(0xf);
        g_assert_cmphex(FEMU_SC(femu_admin(&c, &dst)), ==, 0x023);
    }
    g_assert_cmphex(femu_lockdown(&c, 0, false, 0, 0x14), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_lockdown_log(&c, buf, 1, 2), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, log, sizeof(log));
    g_assert_cmphex(log[0], ==, 0x12);
    g_assert_cmpuint(log[3], ==, 1);
    g_assert_cmphex(log[4], ==, 0x0b);

    /* prohibit Set Features as a whole; a reset keeps both */
    g_assert_cmphex(femu_lockdown(&c, 0, true, 0, 0x09), ==, NVME_SUCCESS);
    g_assert_cmphex(FEMU_SC(femu_set_feature(&c, 0x0e, false, 0, 0, NULL)),
                    ==, 0x023);
    femu_disable(&c);
    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmphex(FEMU_SC(femu_set_feature(&c, 0x0e, false, 0, 0, NULL)),
                    ==, 0x023);
    g_assert_cmphex(femu_lockdown_log(&c, buf, 1, 0), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, log, sizeof(log));
    g_assert_cmpuint(log[3], ==, 1);
    g_assert_cmphex(log[4], ==, 0x09);

    /* allow undoes each; allowing twice is not an error */
    g_assert_cmphex(femu_lockdown(&c, 0, false, 0, 0x09), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_lockdown(&c, 0, false, 0, 0x09), ==, NVME_SUCCESS);
    g_assert_cmphex(FEMU_SC(femu_set_feature(&c, 0x0b, false, 0, 0, NULL)),
                    ==, 0x023);
    g_assert_cmphex(femu_lockdown(&c, 2, false, 0, 0x0b), ==, NVME_SUCCESS);
    g_assert_cmphex(FEMU_SC(femu_set_feature(&c, 0x0b, false, 0, 0, NULL)),
                    ==, NVME_SUCCESS);

    /* refusals */
    g_assert_cmphex(femu_lockdown(&c, 0, true, 0, 0x06), ==, 0x128);
    g_assert_cmphex(femu_lockdown(&c, 0, true, 0, 0x24), ==, 0x128);
    g_assert_cmphex(femu_lockdown(&c, 2, true, 0, 0x00), ==, 0x128);
    g_assert_cmphex(femu_lockdown(&c, 3, true, 0, 0x01), ==, 0x128);
    g_assert_cmphex(femu_lockdown(&c, 0, true, 1, 0x09), ==,
                    NVME_INVALID_FIELD);
    g_assert_cmphex(femu_lockdown(&c, 0, true, 2, 0x09), ==,
                    NVME_INVALID_FIELD);
    g_assert_cmphex(femu_lockdown(&c, 1, true, 0, 0x09), ==,
                    NVME_INVALID_FIELD);
    g_assert_cmphex(femu_lockdown(&c, 4, true, 0, 0x09), ==,
                    NVME_INVALID_FIELD);
    g_assert_cmphex(femu_lockdown_log(&c, buf, 2, 0), ==, NVME_INVALID_FIELD);
    g_assert_cmphex(femu_lockdown_log(&c, buf, 0, 1), ==, NVME_INVALID_FIELD);
    g_assert_cmphex(femu_lockdown_log(&c, buf, 1, 0), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readb(qts, buf + 3), ==, 0);

    femu_disable(&c);
    guest_free(alloc, buf);
}

/* without the property there is no Lockdown command and no log 14h */
void femu_test_lockdown_off(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmphex(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readw(qts, buf + 256) & (1 << 10), ==, 0);
    g_assert_cmphex(femu_lockdown(&c, 2, true, 0, 0x0b), ==,
                    NVME_INVALID_OPCODE);
    g_assert_cmphex(femu_lockdown_log(&c, buf, 0, 0), ==, 0x109);
    femu_disable(&c);
    guest_free(alloc, buf);
}

/*
 * x-opal: OACS bit 0, both commands in log 00h, Level 0, the ComID state
 * machine around a Session Manager Properties call, and STACK_RESET. The
 * ComPacket is built here from Core 2.01 Tables 17, 18 and 20.
 */
void femu_test_opal(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 8192);
    /* CALL SMUID Properties SL EL EOD SL 0 0 0 EL */
    static const uint8_t call[] = {
        0xF8,
        0xA8, 0, 0, 0, 0, 0, 0, 0, 0xFF,
        0xA8, 0, 0, 0, 0, 0, 0, 0xFF, 0x01,
        0xF0, 0xF1,
        0xF9, 0xF0, 0x00, 0x00, 0x00, 0xF1,
    };
    uint8_t pkt[2048] = { 0 };
    uint8_t r[2048];
    uint32_t need;

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmphex(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readw(qts, buf + 256) & 1, ==, 1);
    /* log 05h, Commands Supported and Effects: CSUPP for 81h and 82h */
    g_assert_cmphex(FEMU_SC(femu_get_log(&c, 0x05, buf, 1024, 0)), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(qtest_readl(qts, buf + 0x81 * 4), ==, 1);
    g_assert_cmphex(qtest_readl(qts, buf + 0x82 * 4), ==, 1);

    /* Level 0: the header, TPer first, Opal V2 names ComID 1000h */
    qtest_memset(qts, buf, 0, 2048);
    g_assert_cmphex(femu_sec(&c, false, 1, 1, buf, 2048), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, r, sizeof(r));
    g_assert_cmpuint(femu_be32(r), ==, 196);
    g_assert_cmphex(r[48] << 8 | r[49], ==, 0x0001);
    g_assert_cmphex(r[52] & 1, ==, 1);
    g_assert_cmphex(r[128] << 8 | r[129], ==, 0x0203);
    g_assert_cmphex(r[132] << 8 | r[133], ==, 0x1000);

    /* the Properties call */
    pkt[4] = 0x10;
    pkt[19] = 24 + 12 + sizeof(call) + 1;
    pkt[43] = 12 + sizeof(call) + 1;
    pkt[55] = sizeof(call);
    memcpy(pkt + 56, call, sizeof(call));
    qtest_memwrite(qts, buf, pkt, sizeof(pkt));
    g_assert_cmphex(femu_sec(&c, true, 1, 0x1000, buf, 2048), ==,
                    NVME_SUCCESS);
    /* a second Send before the Receive */
    g_assert_cmphex(femu_sec(&c, true, 1, 0x1000, buf, 2048), ==,
                    0x00c | NVME_DNR);

    /* a short Receive: Length 0 and the size a full one needs */
    qtest_memset(qts, buf + 4096, 0, 2048);
    g_assert_cmphex(femu_sec(&c, false, 1, 0x1000, buf + 4096, 20), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, buf + 4096, r, 20);
    need = femu_be32(r + 8);
    g_assert_cmpuint(need, >, 56);
    g_assert_cmpuint(femu_be32(r + 12), ==, need);
    g_assert_cmpuint(femu_be32(r + 16), ==, 0);
    /* then the response */
    g_assert_cmphex(femu_sec(&c, false, 1, 0x1000, buf + 4096, 2048), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, buf + 4096, r, sizeof(r));
    g_assert_cmpuint(femu_be32(r + 8), ==, 0);
    g_assert_cmpuint(femu_be32(r + 16) + 20, ==, need);
    g_assert_cmphex(r[56], ==, 0xF8);
    g_assert_cmpmem(r + 57, 18, call + 1, 18);
    /* taken: the next Receive finds the ComID idle */
    g_assert_cmphex(femu_sec(&c, false, 1, 0x1000, buf + 4096, 2048), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, buf + 4096, r, 20);
    g_assert_cmpuint(femu_be32(r + 16), ==, 0);
    g_assert_cmpuint(femu_be32(r + 8), ==, 0);

    /* a host status of 1 aborts the method: the reply carries status 1 */
    pkt[56 + 23] = 0x01;
    qtest_memwrite(qts, buf, pkt, sizeof(pkt));
    g_assert_cmphex(femu_sec(&c, true, 1, 0x1000, buf, 2048), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(femu_sec(&c, false, 1, 0x1000, buf + 4096, 2048), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, buf + 4096, r, 128);
    g_assert_cmpuint(femu_be32(r + 52), ==, sizeof(call));
    g_assert_cmphex(r[56 + 23], ==, 0x01);
    pkt[56 + 23] = 0x00;

    /* STACK_RESET drops a waiting response (Core 3.3.4.7.5) */
    qtest_memwrite(qts, buf, pkt, sizeof(pkt));
    g_assert_cmphex(femu_sec(&c, true, 1, 0x1000, buf, 2048), ==,
                    NVME_SUCCESS);
    memset(pkt, 0, 16);
    pkt[0] = 0x10;
    pkt[7] = 2;
    qtest_memwrite(qts, buf, pkt, 16);
    g_assert_cmphex(femu_sec(&c, true, 2, 0x1000, buf, 2048), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(femu_sec(&c, false, 2, 0x1000, buf + 4096, 2048), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, buf + 4096, r, 16);
    g_assert_cmpuint(femu_be32(r + 4), ==, 2);
    g_assert_cmphex(r[10] << 8 | r[11], ==, 4);
    g_assert_cmpuint(femu_be32(r + 12), ==, 0);
    g_assert_cmphex(femu_sec(&c, false, 1, 0x1000, buf + 4096, 2048), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, buf + 4096, r, 20);
    g_assert_cmpuint(femu_be32(r + 8), ==, 0);
    g_assert_cmpuint(femu_be32(r + 16), ==, 0);

    /* interface errors carry DNR (SIIS 6.5) */
    g_assert_cmphex(femu_sec(&c, false, 5, 0, buf, 512), ==,
                    NVME_INVALID_FIELD | NVME_DNR);
    g_assert_cmphex(femu_sec(&c, true, 1, 0x1001, buf, 512), ==,
                    NVME_INVALID_FIELD | NVME_DNR);
    g_assert_cmphex(femu_sec(&c, true, 1, 0x1000, buf, 2049), ==,
                    NVME_INVALID_FIELD | NVME_DNR);
    /* TPER_RESET while ProgrammaticResetEnable is False */
    g_assert_cmphex(femu_sec(&c, true, 2, 0x0004, buf, 512), ==,
                    NVME_INVALID_FIELD | NVME_DNR);
    /* the protocol list: 00h 01h 02h */
    g_assert_cmphex(femu_sec(&c, false, 0, 0, buf, 512), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, r, 16);
    g_assert_cmphex(r[7], ==, 3);
    g_assert_cmphex(r[10], ==, 2);
    /* every byte the host names moves: AL 4096 pads with zeros */
    qtest_memset(qts, buf, 0xAA, 4096);
    g_assert_cmphex(femu_sec(&c, false, 0, 0, buf, 4096), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, buf + 2048), ==, 0);
    g_assert_cmphex(qtest_readb(qts, buf + 4095), ==, 0);
    /* a Level 0 Send of any length is read and discarded */
    g_assert_cmphex(femu_sec(&c, true, 1, 1, buf, 4096), ==, NVME_SUCCESS);
    /* above the 64 KiB transfer limit */
    g_assert_cmphex(femu_sec(&c, false, 1, 1, buf, 65537), ==,
                    NVME_INVALID_FIELD | NVME_DNR);

    femu_disable(&c);
    guest_free(alloc, buf);
}

/* StartSession to the Admin SP; returns the status, sets *tsn */
static uint8_t femu_opal_start(FemuCtrlState *c, QTestState *qts,
                               uint64_t buf, const uint8_t *pin,
                               uint32_t pinlen, uint32_t *tsn)
{
    FemuTb t = { .n = 0 };
    uint8_t r[2048];
    uint32_t n;

    femu_tb_call(&t, 0xFF, 0xFF02);
    t.b[t.n++] = 0x81;                  /* HostSessionID 42h */
    t.b[t.n++] = 0x42;
    femu_tb_uid(&t, 0x0000020500000001ull);
    t.b[t.n++] = 1;                     /* Write */
    if (pin) {
        t.b[t.n++] = 0xF2;
        t.b[t.n++] = 0;
        femu_tb_bytes(&t, pin, pinlen);
        t.b[t.n++] = 0xF3;
        t.b[t.n++] = 0xF2;
        t.b[t.n++] = 3;
        femu_tb_uid(&t, 0x0000000900000006ull);     /* SID */
        t.b[t.n++] = 0xF3;
    }
    femu_tb_end(&t);
    n = femu_opal_xfer(c, qts, buf, &t, 0, r);
    g_assert_cmpuint(n, >, 6);
    /* CALL SMUID SyncSession SL HSN TSN EL ...: both are short atoms */
    g_assert_cmphex(r[56 + 19], ==, 0xF0);
    g_assert_cmphex(r[56 + 20], ==, 0x81);
    g_assert_cmphex(r[56 + 21], ==, 0x42);
    if (!r[56 + n - 4]) {
        g_assert_cmphex(r[56 + 22], ==, 0x82);
        *tsn = r[56 + 23] << 8 | r[56 + 24];
    }
    return r[56 + n - 4];
}

/*
 * x-opal sessions over NVMe: read C_PIN_MSID as Anybody, open a SID
 * session with it, Activate the Locking SP, then Block SID shuts SID out.
 */
void femu_test_opal_session(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 8192);
    uint8_t r[2048];
    uint8_t msid[32];
    uint32_t mlen;
    uint32_t tsn = 0;
    uint32_t n;
    FemuTb t = { .n = 0 };
    uint8_t blk[2] = { 0, 0 };

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpuint(femu_opal_start(&c, qts, buf, NULL, 0, &tsn), ==, 0);
    g_assert_cmpuint(tsn, >=, 0x1000);

    /* Get C_PIN_MSID columns 3 to 3: SL SL SN 3 PIN EN EL EL */
    femu_tb_call(&t, 0x0000000B00008402ull, 0x0000000600000016ull);
    memcpy(t.b + t.n, (uint8_t[]){ 0xF0, 0xF2, 3, 3, 0xF3,
                                   0xF2, 4, 3, 0xF3, 0xF1 }, 10);
    t.n += 10;
    femu_tb_end(&t);
    n = femu_opal_xfer(&c, qts, buf, &t, tsn, r);
    g_assert_cmpuint(n, >, 0);
    g_assert_cmpuint(femu_be32(r + 20), ==, tsn);
    /* a medium atom: the PIN is "FEMU-MSID-" and the serial */
    g_assert_cmphex(r[56 + 4] & 0xF8, ==, 0xD0);
    mlen = (r[56 + 4] & 7) << 8 | r[56 + 5];
    g_assert_cmpmem(r + 56 + 6, mlen, "FEMU-MSID-opal-session", 22);
    memcpy(msid, r + 56 + 6, mlen);
    g_assert_cmphex(r[56 + n - 4], ==, 0);

    /* End of Session */
    t.n = 0;
    t.b[t.n++] = 0xFA;
    g_assert_cmpuint(femu_opal_xfer(&c, qts, buf, &t, tsn, r), ==, 1);
    g_assert_cmphex(r[56], ==, 0xFA);

    /* SID with the MSID PIN: Activate the Locking SP */
    g_assert_cmpuint(femu_opal_start(&c, qts, buf, msid, mlen, &tsn), ==, 0);
    t.n = 0;
    femu_tb_call(&t, 0x0000020500000002ull, 0x0000000600000203ull);
    femu_tb_end(&t);
    n = femu_opal_xfer(&c, qts, buf, &t, tsn, r);
    g_assert_cmpuint(n, >, 6);
    g_assert_cmphex(r[56 + n - 4], ==, 0);
    /* the Locking SP LifeCycleState (column 6) is now Manufactured */
    t.n = 0;
    femu_tb_call(&t, 0x0000020500000002ull, 0x0000000600000016ull);
    memcpy(t.b + t.n, (uint8_t[]){ 0xF0, 0xF2, 3, 6, 0xF3,
                                   0xF2, 4, 6, 0xF3, 0xF1 }, 10);
    t.n += 10;
    femu_tb_end(&t);
    n = femu_opal_xfer(&c, qts, buf, &t, tsn, r);
    g_assert_cmpuint(n, >, 6);
    g_assert_cmphex(r[56 + 4], ==, 0x09);
    g_assert_cmphex(r[56 + n - 4], ==, 0);
    t.n = 0;
    t.b[t.n++] = 0xFA;
    femu_opal_xfer(&c, qts, buf, &t, tsn, r);

    /* Block SID (ComID 0005h): SID still has the MSID PIN, so it blocks */
    qtest_memwrite(qts, buf, blk, sizeof(blk));
    g_assert_cmphex(femu_sec(&c, true, 2, 0x0005, buf, 512), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(femu_sec(&c, true, 2, 0x0005, buf, 512), ==,
                    NVME_INVALID_FIELD | NVME_DNR);
    qtest_memset(qts, buf, 0, 2048);
    g_assert_cmphex(femu_sec(&c, false, 1, 1, buf, 2048), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, r, 256);
    g_assert_cmphex(r[148] << 8 | r[149], ==, 0x0402);
    g_assert_cmphex(r[152], ==, 0x02);
    g_assert_cmpuint(femu_opal_start(&c, qts, buf, msid, mlen, &tsn), ==, 1);

    femu_disable(&c);
    guest_free(alloc, buf);
}

/*
 * x-opal locking over NVMe (SIIS 6.7): a locked range refuses Read and
 * Write, GenKey erases it, Format and Sanitize are refused, and an MBR
 * shadow serves Reads until Done. The 128 MiB MBR covers this whole
 * namespace, so the shadow comes last.
 */
void femu_test_opal_locking(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    static const char pin[] = "FEMU-MSID-opal-lock";
    static const int range[] = { 3, 4, 5, 6, 7, 8, -1 };
    static const uint64_t locked[] = { 64, 64, 1, 1, 1, 1 };
    static const int rw[] = { 7, 8, -1 };
    static const uint64_t open[] = { 0, 0 };
    static const uint64_t wlock[] = { 0, 1 };
    static const int en[] = { 1, -1 };
    static const int done[] = { 2, -1 };
    static const uint64_t one[] = { 1 };
    static const char mbr[] = "FEMU-MBR-SHADOW";
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 8192);
    uint64_t io = guest_alloc(alloc, FEMU_DATA_SIZE);
    uint8_t got[FEMU_DATA_SIZE];
    uint8_t want[FEMU_DATA_SIZE];
    FemuTb t = { .n = 0 };
    NvmeCmd cmd = { 0 };
    uint32_t tsn = 0;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    /* SID activates the Locking SP; Admin1 takes the MSID PIN */
    g_assert_cmpuint(femu_opal_open(&c, qts, buf, 0x0000020500000001ull,
                                    0x0000000900000006ull, pin, &tsn), ==, 0);
    femu_tb_call(&t, FEMU_OPAL_LOCKING_SP, 0x0000000600000203ull);
    g_assert_cmpuint(femu_opal_run(&c, qts, buf, &t, tsn), ==, 0);
    femu_opal_eos(&c, qts, buf, tsn);
    g_assert_cmpuint(femu_opal_open(&c, qts, buf, FEMU_OPAL_LOCKING_SP,
                                    0x0000000900010001ull, pin, &tsn), ==, 0);

    /* Range1 = LBAs 64..127, read and write locked */
    g_assert_cmpuint(femu_opal_lset(&c, qts, buf, tsn, FEMU_OPAL_LOCK1,
                                    range, locked), ==, 0);
    g_assert_cmphex(femu_opal_rw(&c, NVME_CMD_WRITE, 64, io), ==,
                    NVME_ACCESS_DENIED);
    g_assert_cmphex(femu_opal_rw(&c, NVME_CMD_READ, 64, io), ==,
                    NVME_ACCESS_DENIED);
    g_assert_cmphex(femu_opal_rw(&c, NVME_CMD_READ, 60, io), ==,
                    NVME_ACCESS_DENIED);
    g_assert_cmphex(femu_opal_rw(&c, NVME_CMD_READ, 56, io), ==,
                    NVME_SUCCESS);

    /* unlocked: data goes in and comes back */
    g_assert_cmpuint(femu_opal_lset(&c, qts, buf, tsn, FEMU_OPAL_LOCK1,
                                    rw, open), ==, 0);
    memset(want, 0x5A, sizeof(want));
    qtest_memwrite(qts, io, want, sizeof(want));
    g_assert_cmphex(femu_opal_rw(&c, NVME_CMD_WRITE, 64, io), ==,
                    NVME_SUCCESS);
    qtest_memset(qts, io, 0, FEMU_DATA_SIZE);
    g_assert_cmphex(femu_opal_rw(&c, NVME_CMD_READ, 64, io), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, io, got, sizeof(got));
    g_assert_cmpmem(got, sizeof(got), want, sizeof(want));

    /* GenKey on K_AES_256_Range1 erases the range */
    t.n = 0;
    femu_tb_call(&t, 0x0000080600030001ull, 0x0000000600000010ull);
    g_assert_cmpuint(femu_opal_run(&c, qts, buf, &t, tsn), ==, 0);
    qtest_memset(qts, io, 0xFF, FEMU_DATA_SIZE);
    g_assert_cmphex(femu_opal_rw(&c, NVME_CMD_READ, 64, io), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, io, got, sizeof(got));
    memset(want, 0, sizeof(want));
    g_assert_cmpmem(got, sizeof(got), want, sizeof(want));

    /* Format: refused while an LBA is write locked; Sanitize: owned */
    g_assert_cmpuint(femu_opal_lset(&c, qts, buf, tsn, FEMU_OPAL_LOCK1,
                                    rw, wlock), ==, 0);
    g_assert_cmphex(FEMU_SC(femu_format(&c, 1, 0, 0)), ==,
                    NVME_INVALID_FORMAT);
    g_assert_cmpuint(femu_opal_lset(&c, qts, buf, tsn, FEMU_OPAL_LOCK1,
                                    rw, open), ==, 0);
    cmd.opcode = FEMU_ADM_SANITIZE;
    cmd.cdw10 = cpu_to_le32(2);
    g_assert_cmphex(FEMU_SC(femu_admin(&c, &cmd)), ==, NVME_ACCESS_DENIED);

    /* MBR shadow: Reads get the MBR bytes, Writes are refused */
    memset(want, 0xA5, sizeof(want));
    qtest_memwrite(qts, io, want, sizeof(want));
    g_assert_cmphex(femu_opal_rw(&c, NVME_CMD_WRITE, 0, io), ==,
                    NVME_SUCCESS);
    t.n = 0;
    femu_tb_call(&t, 0x0000080400000000ull, 0x0000000600000017ull);
    t.b[t.n++] = 0xF2;
    t.b[t.n++] = 0;
    t.b[t.n++] = 0;
    t.b[t.n++] = 0xF3;
    t.b[t.n++] = 0xF2;
    t.b[t.n++] = 1;
    femu_tb_bytes(&t, (const uint8_t *)mbr, strlen(mbr));
    t.b[t.n++] = 0xF3;
    g_assert_cmpuint(femu_opal_run(&c, qts, buf, &t, tsn), ==, 0);
    g_assert_cmpuint(femu_opal_lset(&c, qts, buf, tsn, FEMU_OPAL_MBRCTL,
                                    en, one), ==, 0);
    g_assert_cmphex(femu_opal_rw(&c, NVME_CMD_READ, 0, io), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, io, got, sizeof(got));
    memset(want, 0, sizeof(want));
    memcpy(want, mbr, strlen(mbr));
    g_assert_cmpmem(got, sizeof(got), want, sizeof(want));
    g_assert_cmphex(femu_opal_rw(&c, NVME_CMD_WRITE, 0, io), ==,
                    NVME_ACCESS_DENIED);
    /* Done: the media again */
    g_assert_cmpuint(femu_opal_lset(&c, qts, buf, tsn, FEMU_OPAL_MBRCTL,
                                    done, one), ==, 0);
    g_assert_cmphex(femu_opal_rw(&c, NVME_CMD_READ, 0, io), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, io, got, sizeof(got));
    memset(want, 0xA5, sizeof(want));
    g_assert_cmpmem(got, sizeof(got), want, sizeof(want));
    femu_opal_eos(&c, qts, buf, tsn);

    femu_disable(&c);
    guest_free(alloc, io);
    guest_free(alloc, buf);
}

/*
 * crypto_mbps models an inline encryption engine, so FNA has CRYES. FNA
 * leaves SENS clear: a cryptographic erase of one namespace keeps the
 * data of the other, and the broadcast NSID erases both.
 */
void femu_test_format_crypto_ns(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    QOSState *qs = qtest_pc_boot(
        "-machine pc -nodefaults -device femu,id=cfn,addr=5,devsz_mb=64,"
        "femu_mode=2,namespaces=2,crypto_mbps=100,serial=cry-ns");
    QTestState *qts = qs->qts;
    QPCIDevice *pdev = qpci_device_find(qs->pcibus, QPCI_DEVFN(5, 0));
    FemuCtrlState c = { 0 };
    uint64_t buf;
    uint64_t io;

    femu_enable(&c, pdev, &qs->alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(&qs->alloc, 4096);
    io = guest_alloc(&qs->alloc, FEMU_DATA_SIZE);

    g_assert_cmphex(FEMU_SC(femu_identify(&c, 0, 1, 0, buf)), ==, 0);
    g_assert_cmphex(qtest_readb(qts, buf + FEMU_ID_FNA), ==, FEMU_FNA_CRYES);
    femu_opal_fill(&c, qts, 1, 8, io, 0x11);
    femu_opal_fill(&c, qts, 2, 8, io, 0x22);
    g_assert_cmphex(FEMU_SC(femu_format(&c, 1, 0, 2)), ==, NVME_SUCCESS);
    femu_opal_expect(&c, qts, 1, 8, io, 0);
    femu_opal_expect(&c, qts, 2, 8, io, 0x22);
    femu_opal_fill(&c, qts, 1, 8, io, 0x11);
    g_assert_cmphex(FEMU_SC(femu_format(&c, NVME_NSID_BROADCAST, 0, 2)), ==,
                    NVME_SUCCESS);
    femu_opal_expect(&c, qts, 1, 8, io, 0);
    femu_opal_expect(&c, qts, 2, 8, io, 0);

    g_free(pdev);
    qtest_pc_shutdown(qs);
}

void femu_test_opal_off(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmphex(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readw(qts, buf + 256) & 1, ==, 0);
    /* log 05h, Commands Supported and Effects: CSUPP for 81h and 82h */
    g_assert_cmphex(FEMU_SC(femu_get_log(&c, 0x05, buf, 1024, 0)), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(qtest_readl(qts, buf + 0x81 * 4), ==, 0);
    g_assert_cmphex(femu_sec(&c, false, 1, 1, buf, 2048), ==,
                    NVME_INVALID_OPCODE | NVME_DNR);
    g_assert_cmphex(femu_sec(&c, true, 1, 0x1000, buf, 2048), ==,
                    NVME_INVALID_OPCODE | NVME_DNR);
    femu_disable(&c);
    guest_free(alloc, buf);
}

/* without the property: ONCS bit 5 clear, no commands, no features */
void femu_test_resv_off(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    g_assert_cmphex(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readw(qts, buf + 520) & (1 << 5), ==, 0);
    g_assert_cmphex(femu_resv(&c, 0x0d, 0, 0, buf, 0, 1), ==,
                    NVME_INVALID_OPCODE);
    g_assert_cmphex(FEMU_SC(femu_get_feature(&c, 0x83, 0, 1, 0, NULL)), ==,
                    NVME_INVALID_FIELD);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    guest_free(alloc, buf);
}
#define FEMU_LOG_LBA_STATUS      0x0e

/*
 * Get LBA Status (NVM 1.2, 4.2.1): the blocks a read would fail on, as runs
 * of LBAs, and the allocated ones; plus the LBA Status Information log that
 * says how many there are to look for.
 */
void femu_test_get_lba_status(void *obj, void *data,
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

    /* LBA Status Information: one element with both runs */
    g_assert_cmpint(FEMU_SC(femu_get_log(&c, 0x00, buf, 1024, 0)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(qtest_readl(qts, buf + 4 * FEMU_LOG_LBA_STATUS) & 1, ==, 1);
    g_assert_cmpint(FEMU_SC(femu_get_log(&c, FEMU_LOG_LBA_STATUS, buf, 64,
                                         0)), ==, NVME_SUCCESS);
    g_assert_cmpint(qtest_readl(qts, buf), ==, 64);            /* LSLPLEN */
    g_assert_cmpint(qtest_readl(qts, buf + 4), ==, 1);         /* NLSLNE */
    g_assert_cmpint(qtest_readl(qts, buf + 8), ==, 4);         /* ESTULB */
    g_assert_cmpint(qtest_readw(qts, buf + 14), ==, 1);        /* LSGC */
    g_assert_cmpint(qtest_readl(qts, buf + 16), ==, 1);        /* NEID */
    g_assert_cmpint(qtest_readl(qts, buf + 20), ==, 2);        /* NLRD */
    g_assert_cmpint(qtest_readb(qts, buf + 24), ==, 0x11);     /* RATYPE */
    g_assert_cmpint(qtest_readq(qts, buf + 32), ==, 10);
    g_assert_cmpint(qtest_readl(qts, buf + 40), ==, 2);
    g_assert_cmpint(qtest_readq(qts, buf + 48), ==, 20);
    g_assert_cmpint(qtest_readl(qts, buf + 56), ==, 0);

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

/*
 * LBA Status Information Attributes (NVM 1.2, 4.1.3.5): DW0 holds LSIPI
 * (fixed, 1 s) above LSIRI. An LSIRI below LSIPI is unsupported, so the
 * closest supported value, LSIPI, is used. The feature is not saveable
 * and a controller reset restores the default.
 */
void femu_test_lsi_feature(void *obj, void *data,
                           QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 1024);
    uint32_t res;

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmphex(FEMU_SC(femu_get_feature(&c, 0x15, 0, 0, 0, &res)), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(res, ==, 10 << 16 | 10);
    g_assert_cmphex(FEMU_SC(femu_set_feature(&c, 0x15, false, 0, 30, &res)),
                    ==, NVME_SUCCESS);
    g_assert_cmphex(res, ==, 10 << 16 | 30);
    g_assert_cmphex(FEMU_SC(femu_get_feature(&c, 0x15, 0, 0, 0, &res)), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(res, ==, 10 << 16 | 30);
    /* the upper half of DW11 is reserved here: LSIPI is not settable */
    g_assert_cmphex(FEMU_SC(femu_set_feature(&c, 0x15, false, 0,
                                             0x50000 | 3, &res)),
                    ==, NVME_SUCCESS);
    g_assert_cmphex(res, ==, 10 << 16 | 10);
    g_assert_cmphex(FEMU_SC(femu_set_feature(&c, 0x15, false, 0, 0xffff,
                                             &res)), ==, NVME_SUCCESS);
    g_assert_cmphex(res, ==, 10 << 16 | 0xffff);
    g_assert_cmphex(FEMU_SC(femu_set_feature(&c, 0x15, true, 0, 40, &res)),
                    ==, NVME_FID_NOT_SAVEABLE);
    g_assert_cmphex(FEMU_SC(femu_get_feature(&c, 0x15, 0, 0, 0, &res)), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(res, ==, 10 << 16 | 0xffff);
    /* default and saved give the default; capabilities: changeable only */
    for (uint8_t sel = 1; sel <= 3; sel++) {
        g_assert_cmphex(FEMU_SC(femu_get_feature(&c, 0x15, sel, 0, 0, &res)),
                        ==, NVME_SUCCESS);
        g_assert_cmphex(res, ==, sel == 3 ? 0x4 : 10 << 16 | 10);
    }
    /* log 12h: supported, controller scope */
    g_assert_cmphex(FEMU_SC(femu_get_log(&c, 0x12, buf, 1024, 0)), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(qtest_readl(qts, buf + 4 * 0x15), ==, 0x00200001);

    femu_set_feature(&c, 0x15, false, 0, 30, &res);
    femu_disable(&c);
    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmphex(FEMU_SC(femu_get_feature(&c, 0x15, 0, 0, 0, &res)), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(res, ==, 10 << 16 | 10);

    guest_free(alloc, buf);
    femu_disable(&c);
}

/*
 * The LBA Status Information log (NVM 1.2, 4.1.4.5) and LSGC (Figure
 * 109): LSGC steps only when the log lists a block that the last host
 * read did not list. A RAE=1 read freezes the page until a RAE=0 read.
 */
void femu_test_lsi_log(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 8192);
    uint64_t dbuf = guest_alloc(alloc, 4096);
    uint8_t a[128], b[128];

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    g_assert_cmpint(femu_lsi_gen(&c, buf, 16, false), ==, 0);
    g_assert_cmpint(qtest_readl(qts, buf + 4), ==, 0);
    g_assert_cmpint(qtest_readl(qts, buf + 8), ==, 0);

    femu_mark_uncor(&c, 10, 3);
    femu_mark_uncor(&c, 20, 1);
    femu_mark_uncor(&c, 30, 2);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 80, false), ==, 1);
    g_assert_cmpint(qtest_readl(qts, buf + 8), ==, 6);
    g_assert_cmpint(qtest_readl(qts, buf + 20), ==, 3);
    g_assert_cmpint(qtest_readq(qts, buf + 64), ==, 30);
    g_assert_cmpint(qtest_readl(qts, buf + 72), ==, 1);
    /* unchanged, then a repeat of a listed block: no step */
    g_assert_cmpint(femu_lsi_gen(&c, buf, 80, false), ==, 1);
    femu_mark_uncor(&c, 20, 1);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 80, false), ==, 1);
    /* a repair alone: no step; the same block again is new to that read */
    g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE, 20, dbuf), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 64, false), ==, 1);
    femu_mark_uncor(&c, 20, 1);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 80, false), ==, 2);

    /* RAE=1 freezes the page; a RAE=0 read still returns it */
    g_assert_cmpint(femu_lsi_gen(&c, buf, 80, true), ==, 2);
    qtest_memread(qts, buf, a, 80);
    femu_mark_uncor(&c, 40, 1);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 80, true), ==, 2);
    qtest_memread(qts, buf, b, 80);
    g_assert_cmpmem(a, 80, b, 80);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 80, false), ==, 2);
    qtest_memread(qts, buf, b, 80);
    g_assert_cmpmem(a, 80, b, 80);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 96, false), ==, 3);

    /* a header-only read is a read: it takes the new block */
    femu_mark_uncor(&c, 50, 1);
    g_assert_cmphex(femu_lsi_read(&c, buf, 16, 0, false), ==, NVME_SUCCESS);
    g_assert_cmpint(qtest_readw(qts, buf + 14), ==, 4);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 112, false), ==, 4);

    /*
     * An offset past the page fails, holds nothing and is not a read: the
     * block it would have taken stays new, together with a later one.
     */
    femu_mark_uncor(&c, 55, 1);
    g_assert_cmphex(femu_lsi_read(&c, buf, 16, 128, true), ==,
                    NVME_INVALID_FIELD);
    femu_mark_uncor(&c, 60, 1);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 144, true), ==, 5);
    /* a reset keeps R: the same blocks do not step again */
    femu_disable(&c);
    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 144, false), ==, 5);
    /* and drops the held page: the next read shows a later block */
    g_assert_cmpint(femu_lsi_gen(&c, buf, 144, true), ==, 5);
    femu_mark_uncor(&c, 70, 1);
    femu_disable(&c);
    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 160, false), ==, 6);

    guest_free(alloc, dbuf);
    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * 256 runs fit in one element (4128 bytes); 257 give FFFFFFFFh
 * descriptors. For such an element, only a later add is new; a page
 * that lists descriptors again is new to it.
 */
void femu_test_lsi_many(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 8192);
    uint64_t dbuf = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    for (uint64_t lba = 0; lba < 512; lba += 2) {
        femu_mark_uncor(&c, lba, 1);
    }
    g_assert_cmphex(femu_lsi_read(&c, buf, 4128, 0, false), ==, NVME_SUCCESS);
    g_assert_cmpint(qtest_readl(qts, buf), ==, 4128);
    g_assert_cmpint(qtest_readl(qts, buf + 8), ==, 256);
    g_assert_cmpint(qtest_readw(qts, buf + 14), ==, 1);
    g_assert_cmpint(qtest_readl(qts, buf + 20), ==, 256);
    /* the last descriptor sits past the first page */
    g_assert_cmpint(qtest_readq(qts, buf + 32 + 255 * 16), ==, 510);
    g_assert_cmpint(qtest_readl(qts, buf + 40 + 255 * 16), ==, 0);

    femu_mark_uncor(&c, 512, 1);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 32, false), ==, 2);
    g_assert_cmphex(qtest_readl(qts, buf + 20), ==, 0xffffffff);
    g_assert_cmpint(qtest_readl(qts, buf + 8), ==, 257);
    /* unchanged, and a repeat: no step; a new block: a step */
    g_assert_cmpint(femu_lsi_gen(&c, buf, 32, false), ==, 2);
    femu_mark_uncor(&c, 0, 1);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 32, false), ==, 2);
    femu_mark_uncor(&c, 600, 1);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 32, false), ==, 3);
    g_assert_cmpint(qtest_readl(qts, buf + 8), ==, 258);
    /*
     * A repair alone brings back descriptors, which that read did not
     * list. One 4 KiB write repairs blocks 0, 2, 4 and 6: 254 runs remain.
     */
    g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE, 0, dbuf), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 16 + 16 + 254 * 16, false), ==, 4);
    g_assert_cmpint(qtest_readl(qts, buf + 8), ==, 254);
    g_assert_cmpint(qtest_readl(qts, buf + 20), ==, 254);
    g_assert_cmpint(qtest_readq(qts, buf + 32), ==, 8);

    guest_free(alloc, dbuf);
    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * The alert (NVM 1.2, 5.2.1): no Notice 05h before LSIRI after the last
 * clear, one by LSIRI plus the 100 ms scan gap, none while one is
 * reported, and a new one after a RAE=0 read for blocks the frozen page
 * left out. The page it announces is captured when it is posted.
 */
void femu_test_lsi_alert(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 8192);
    uint16_t want;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_lsi_aec(&c, true);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 16, false), ==, 0);
    femu_mark_uncor(&c, 10, 1);
    /* no AER yet, so an early admission would stay QUEUED */
    g_assert_false(femu_lsi_after(&c, FEMU_LSI_SEC - 1));
    g_assert_cmpint(femu_lsi_state(qts, "alert"), ==, 0);
    want = femu_aer(&c);
    g_assert_true(femu_lsi_after(&c, FEMU_LSI_SEC / 10));
    femu_lsi_alert(&c, want);
    g_assert_cmpint(femu_lsi_state(qts, "alert"), ==, 2);
    g_assert_cmpint(femu_lsi_state(qts, "alert_gen"), ==, 1);

    /* reported: nothing more until the clear; the page stays frozen */
    want = femu_aer(&c);
    femu_mark_uncor(&c, 20, 1);
    g_assert_false(femu_lsi_after(&c, 2 * FEMU_LSI_SEC));
    g_assert_cmpint(femu_lsi_gen(&c, buf, 48, true), ==, 1);
    g_assert_false(femu_lsi_after(&c, 2 * FEMU_LSI_SEC));
    g_assert_cmpint(femu_lsi_gen(&c, buf, 48, false), ==, 1);
    /* block 20 was not in it: a second alert one LSIRI after the clear */
    g_assert_false(femu_lsi_after(&c, FEMU_LSI_SEC - 1));
    g_assert_true(femu_lsi_after(&c, FEMU_LSI_SEC / 10));
    femu_lsi_alert(&c, want);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 64, false), ==, 2);

    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * A host that reads the log before the alert still gets it (4.1.3.5:
 * LSGC moved since the last alert), one LSIRI after that read, and then
 * no repeat.
 */
void femu_test_lsi_poll(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 8192);
    uint16_t want;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_lsi_aec(&c, true);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 16, false), ==, 0);
    want = femu_aer(&c);
    femu_mark_uncor(&c, 10, 1);
    g_assert_false(femu_lsi_after(&c, FEMU_LSI_SEC / 2));
    g_assert_cmpint(femu_lsi_gen(&c, buf, 48, false), ==, 1);
    g_assert_false(femu_lsi_after(&c, FEMU_LSI_SEC - 1));
    g_assert_true(femu_lsi_after(&c, FEMU_LSI_SEC / 10));
    femu_lsi_alert(&c, want);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 48, false), ==, 1);
    /* no AER: a repeat admission would stay QUEUED */
    g_assert_false(femu_lsi_after(&c, 3 * FEMU_LSI_SEC));
    g_assert_cmpint(femu_lsi_state(femu->dev.bus->qts, "alert"), ==, 0);
    femu_aer(&c);
    g_assert_false(femu_lsi_after(&c, FEMU_LSI_SEC));

    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * A component failure alerts with no LSIRI wait, also with no blocks;
 * a second one while the first is reported goes out at the clear.
 */
void femu_test_lsi_component(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 8192);
    uint16_t want;

    femu_enable(&c, &femu->dev, alloc);
    femu_lsi_aec(&c, true);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 16, false), ==, 0);
    want = femu_aer(&c);
    g_assert_false(femu_lsi_after(&c, 1000));
    femu_lsi_cmd(qts, "component:1");
    g_assert_true(femu_lsi_after(&c, 1000));
    femu_lsi_alert(&c, want);
    g_assert_cmpint(femu_lsi_state(qts, "unacked"), ==, 1);

    want = femu_aer(&c);
    femu_lsi_cmd(qts, "component:1");
    g_assert_cmpint(femu_lsi_state(qts, "alert"), ==, 2);
    g_assert_false(femu_lsi_after(&c, 2 * FEMU_LSI_SEC));
    g_assert_cmphex(femu_lsi_read(&c, buf, 16, 0, false), ==, NVME_SUCCESS);
    g_assert_cmpint(qtest_readl(qts, buf + 4), ==, 0);
    g_assert_cmpint(qtest_readl(qts, buf + 8), ==, 0);
    g_assert_true(femu_lsi_after(&c, 1000));
    femu_lsi_alert(&c, want);

    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * A full event queue refuses the alert. When an event leaves the queue,
 * the alert goes in with no new loss and no other command.
 */
void femu_test_lsi_qfull(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 8192);
    uint32_t res;
    uint16_t cid;
    uint16_t want;

    femu_enable(&c, &femu->dev, alloc);
    femu_lsi_aec(&c, true);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 16, false), ==, 0);
    femu_lsi_cmd(qts, "fill:16");
    femu_lsi_cmd(qts, "component:1");
    g_assert_false(femu_lsi_after(&c, 1000));
    g_assert_cmpint(femu_lsi_state(qts, "rejects"), ==, 1);
    g_assert_cmpint(femu_lsi_state(qts, "alert"), ==, 0);

    want = femu_aer(&c);
    g_assert_true(femu_lsi_after(&c, 1000));
    g_assert_cmphex(femu_complete(&c, &c.admin, &cid, &res), ==,
                    NVME_SUCCESS);
    g_assert_cmpuint(cid, ==, want);
    g_assert_cmphex(res & 7, ==, 7);
    want = femu_aer(&c);
    g_assert_true(femu_lsi_after(&c, 1000));
    femu_lsi_alert(&c, want);

    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * AEC bit 13 off drops a queued alert; on again, it is admitted again
 * with no new loss.
 */
void femu_test_lsi_disable(void *obj, void *data,
                           QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 8192);
    uint16_t want;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_lsi_aec(&c, true);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 16, false), ==, 0);
    femu_mark_uncor(&c, 10, 1);
    g_assert_false(femu_lsi_after(&c, FEMU_LSI_SEC * 12 / 10));
    g_assert_cmpint(femu_lsi_state(qts, "alert"), ==, 1);
    femu_lsi_aec(&c, false);
    g_assert_cmpint(femu_lsi_state(qts, "alert"), ==, 0);
    want = femu_aer(&c);
    g_assert_false(femu_lsi_after(&c, 2 * FEMU_LSI_SEC));
    femu_lsi_aec(&c, true);
    g_assert_true(femu_lsi_after(&c, 1000));
    femu_lsi_alert(&c, want);

    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * A controller reset (design 9.7). An alert the host did not read comes
 * back at the generation it announced, which the host read alone does not
 * give: here only G_pub holds generation 2 once block 20 is repaired.
 * LSIRI counts from the next enable. An acknowledged alert does not come
 * back.
 */
void femu_test_lsi_reset(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 8192);
    uint64_t dbuf = guest_alloc(alloc, 4096);
    uint16_t want;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_lsi_aec(&c, true);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 16, false), ==, 0);
    want = femu_aer(&c);
    femu_mark_uncor(&c, 10, 1);
    g_assert_true(femu_lsi_after(&c, FEMU_LSI_SEC * 11 / 10));
    femu_lsi_alert(&c, want);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 48, false), ==, 1);
    want = femu_aer(&c);
    femu_mark_uncor(&c, 20, 1);
    g_assert_true(femu_lsi_after(&c, FEMU_LSI_SEC * 11 / 10));
    femu_lsi_alert(&c, want);
    /* repaired after the post: generation 2 was given out and stays */
    g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE, 20, dbuf), ==, NVME_SUCCESS);

    femu_disable(&c);
    qtest_clock_step(femu->dev.bus->qts, 2 * FEMU_LSI_SEC);
    femu_enable(&c, &femu->dev, alloc);
    femu_lsi_aec(&c, true);
    want = femu_aer(&c);
    g_assert_false(femu_lsi_after(&c, FEMU_LSI_SEC - 1));
    g_assert_true(femu_lsi_after(&c, FEMU_LSI_SEC / 10));
    femu_lsi_alert(&c, want);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 48, false), ==, 2);

    femu_disable(&c);
    femu_enable(&c, &femu->dev, alloc);
    femu_lsi_aec(&c, true);
    femu_aer(&c);
    g_assert_false(femu_lsi_after(&c, 3 * FEMU_LSI_SEC));

    guest_free(alloc, dbuf);
    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/* LSGC rolls over from FFFFh to 0, with an alert for the new block */
void femu_test_lsi_wrap(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 8192);
    uint16_t want;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_lsi_cmd(qts, "gen:65535");
    femu_lsi_aec(&c, true);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 16, false), ==, 0xffff);
    want = femu_aer(&c);
    femu_mark_uncor(&c, 10, 1);
    g_assert_true(femu_lsi_after(&c, FEMU_LSI_SEC * 12 / 10));
    femu_lsi_alert(&c, want);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 48, false), ==, 0);
    g_assert_cmpint(femu_lsi_state(qts, "alert_gen"), ==, 65536);

    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

static void femu_lsi_wu_submit(FemuCtrlState *c, FemuQueue *q, uint64_t slba)
{
    NvmeRwCmd rw = { 0 };

    rw.opcode = NVME_CMD_WRITE_UNCOR;
    rw.nsid = cpu_to_le32(1);
    rw.slba = cpu_to_le64(slba);
    femu_submit(c, q, (NvmeCmd *)&rw);
}

/* wait (real time) until a WU holds at the stop point */
static void femu_lsi_held(QTestState *qts)
{
    for (int i = 0; i < 1000 && femu_lsi_state(qts, "stop") < 0x100; i++) {
        g_usleep(1000);
    }
    g_assert_cmpint(femu_lsi_state(qts, "stop"), >=, 0x100);
}

/*
 * A repeat Write Uncorrectable is no new block on any interleave. WU A
 * stops where the old code had its bits clear; WU B of the same block
 * runs on another poller meanwhile. add_ver must not move.
 */
void femu_test_lsi_wu_race(void *obj, void *data,
                           QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    FemuQueue q2;
    uint64_t add;
    uint32_t res;
    uint16_t cid;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_create_pair_irq(&c, &q2, 2, 0, false);
    femu_mark_uncor(&c, 10, 1);
    add = femu_lsi_state(qts, "add");
    g_assert_cmpint(add, ==, 1);
    femu_lsi_cmd(qts, "stop:1");
    femu_lsi_wu_submit(&c, &c.io, 10);
    femu_lsi_held(qts);
    femu_lsi_wu_submit(&c, &q2, 10);
    g_assert_cmphex(femu_complete(&c, &q2, &cid, &res), ==, NVME_SUCCESS);
    femu_lsi_cmd(qts, "stop:0");
    g_assert_cmphex(femu_complete(&c, &c.io, &cid, &res), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_lsi_state(qts, "add"), ==, add);
    /* control: a new block does move it */
    femu_mark_uncor(&c, 11, 1);
    g_assert_cmpint(femu_lsi_state(qts, "add"), ==, add + 1);

    femu_queue_free(&c, &q2);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * The counter order (design 12, 14) with a sentinel element, where only
 * add_ver tells a new block. WU of a new block stops after its add_ver
 * step, before media_ver; a forced check then runs. That check must not
 * take the old add_ver under a new key: once the WU ends, the alert goes
 * out with no other change. No AER is outstanding during the stop, so no
 * post pauses the stopped poller.
 */
void femu_test_lsi_publish(void *obj, void *data,
                           QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 8192);
    uint32_t res;
    uint16_t cid;
    uint16_t want;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_lsi_aec(&c, true);
    want = femu_aer(&c);
    for (int i = 0; i < 257; i++) {
        femu_mark_uncor(&c, 2 * i, 1);
    }
    g_assert_true(femu_lsi_after(&c, FEMU_LSI_SEC * 11 / 10));
    femu_lsi_alert(&c, want);
    /* sentinel element: NLRD FFFFFFFFh, no descriptors */
    g_assert_cmpint(femu_lsi_gen(&c, buf, 32, false), ==, 1);
    g_assert_cmphex(qtest_readl(qts, buf + 20), ==, 0xffffffff);
    g_assert_false(femu_lsi_after(&c, FEMU_LSI_SEC * 12 / 10));
    g_assert_cmpint(femu_lsi_state(qts, "alert"), ==, 0);

    femu_lsi_cmd(qts, "stop:2");
    femu_lsi_wu_submit(&c, &c.io, 1000);
    femu_lsi_held(qts);
    g_assert_false(femu_lsi_after(&c, FEMU_LSI_SEC / 5));
    femu_lsi_cmd(qts, "eval:1");
    g_assert_cmpint(femu_lsi_state(qts, "alert"), ==, 0);
    femu_lsi_cmd(qts, "stop:0");
    g_assert_cmphex(femu_complete(&c, &c.io, &cid, &res), ==, NVME_SUCCESS);
    want = femu_aer(&c);
    g_assert_true(femu_lsi_after(&c, FEMU_LSI_SEC / 5));
    femu_lsi_alert(&c, want);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 32, false), ==, 2);

    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * Format (design 9.6): it clears the blocks with no LSGC step. With the
 * same LBA size the host read still covers block 10, so a new WU of it
 * gives no step; with a new LBA size the old read covers nothing.
 */
void femu_test_lsi_format(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 8192);
    uint8_t cur;
    uint8_t other;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    g_assert_cmpint(femu_identify(&c, 1, 0, 0, buf), ==, NVME_SUCCESS);
    cur = qtest_readb(qts, buf + 26) & 0xf;
    other = cur ? 0 : 3;
    g_assert_cmpint(qtest_readb(qts, buf + 128 + 4 * cur + 2), !=,
                    qtest_readb(qts, buf + 128 + 4 * other + 2));

    femu_mark_uncor(&c, 10, 1);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 48, false), ==, 1);
    /* same size, WU again before any read: the read still covers it */
    g_assert_cmpint(FEMU_SC(femu_format(&c, 1, cur, 0)), ==, NVME_SUCCESS);
    femu_mark_uncor(&c, 10, 1);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 48, false), ==, 1);
    /* a new size: the same LBA is a new block */
    g_assert_cmpint(FEMU_SC(femu_format(&c, 1, other, 0)), ==, NVME_SUCCESS);
    femu_mark_uncor(&c, 10, 1);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 48, false), ==, 2);
    /* the removal alone: no step */
    g_assert_cmpint(FEMU_SC(femu_format(&c, 1, other, 0)), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 16, false), ==, 2);

    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * Sanitize clears the blocks. A queued alert whose blocks are gone at
 * the post is dropped, and LSGC does not step.
 */
void femu_test_lsi_sanitize(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 8192);
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_lsi_aec(&c, true);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 16, false), ==, 0);
    femu_mark_uncor(&c, 10, 1);
    g_assert_false(femu_lsi_after(&c, FEMU_LSI_SEC * 11 / 10));
    g_assert_cmpint(femu_lsi_state(qts, "alert"), ==, 1);
    g_assert_cmphex(femu_sanitize(&c, 0x2), ==, NVME_SUCCESS);
    for (i = 0; i < 100 && (femu_sstat(&c, buf, NULL) & 7) != 1; i++) {
        qtest_clock_step(qts, FEMU_LSI_SEC / 10);
    }
    g_assert_cmphex(femu_sstat(&c, buf, NULL) & 7, ==, 1);
    femu_aer(&c);
    g_assert_false(femu_lsi_after(&c, 2 * FEMU_LSI_SEC));
    g_assert_cmpint(femu_lsi_state(qts, "alert"), ==, 0);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 16, false), ==, 0);

    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

#define FEMU_LSI_CKPT_DEV   ",'femu_mode':1,'oncs':415"

/* add device lsi-test at slot 5 (persist_file @file if set) and enable it */
static QPCIDevice *femu_lsi_ckpt_dev(QTestState *qts, QPCIBus *bus,
                                     FemuCtrlState *c, QGuestAllocator *alloc,
                                     const char *file)
{
    g_autofree char *extra = file ?
        g_strdup_printf(FEMU_LSI_CKPT_DEV ",'persist_file':'%s'", file) :
        g_strdup(FEMU_LSI_CKPT_DEV);
    QPCIDevice *pdev;

    femu_ckpt_add(qts, "lsi-test", 5, extra);
    pdev = qpci_device_find(bus, QPCI_DEVFN(5, 0));
    memset(c, 0, sizeof(*c));
    femu_enable(c, pdev, alloc);
    femu_create_io_queues(c);
    return pdev;
}

static void femu_lsi_ckpt_del(QTestState *qts, FemuCtrlState *c,
                              QPCIDevice *pdev)
{
    femu_disable(c);
    femu_queue_free(c, &c->io);
    qpci_unplug_acpi_device_test(qts, "lsi-test", 5);
    g_free(pdev);
}

/* a device with persist_file @file fails realize with "malformed" */
static void femu_lsi_ckpt_bad(QTestState *qts, const char *file)
{
    g_autofree char *args = g_strdup_printf(
        "{'driver':'femu','id':'lsi-bad','addr':'6','devsz_mb':16"
        FEMU_LSI_CKPT_DEV ",'persist_file':'%s'}", file);
    QDict *rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':%p}",
                           qobject_from_json(args, &error_abort));

    g_assert_true(qdict_haskey(rsp, "error"));
    g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                          "desc"), "malformed"));
    qobject_unref(rsp);
}

/*
 * persist_file state saved with the controller enabled, by femu-save-data
 * (design 15), so no reset runs before the save:
 *   ckpt1: blocks 10, 20; the host read gen 2 before its alert
 *          (alert_gen 1) --> the gen 2 alert one LSIRI after enable
 *   ckpt2: the gen 3 alert of block 30 posted, unread, then 30 repaired
 *          (G_R 2, G_pub 3, alert_gen 3) --> alert_gen falls to 2: alert
 *   ckpt3: a component alert posted, unread --> an alert at once
 * Then six changed copies of ckpt1 each fail to load.
 */
void femu_test_lsi_persist_live(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    QPCIBus *bus = femu->dev.bus;
    g_autofree char *dir = g_dir_make_tmp("femu-lsi-XXXXXX", NULL);
    g_autofree char *f[3] = { NULL };
    g_autofree char *bad = g_build_filename(dir, "bad", NULL);
    g_autofree char *bytes = NULL;
    uint64_t buf = guest_alloc(alloc, 8192);
    uint64_t dbuf = guest_alloc(alloc, 4096);
    FemuCtrlState c = { 0 };
    QPCIDevice *pdev;
    uint16_t want;
    gsize len;
    char *sec;
    static const struct {
        uint32_t off;
        uint8_t size;
        uint64_t val;
    } edit[] = {
        { 4, 8, 3 },                /* G_R past G_pub */
        { 12, 8, 1ULL << 63 },      /* G_pub at the limit */
        { 28, 1, 2 },               /* comp not 0 or 1 */
        { 44, 4, 3 },               /* more runs than bytes */
        { 48, 8, 1ULL << 40 },      /* R.add_ver ahead of add_ver */
        { 72, 8, 5 },               /* run 2 starts inside run 1 */
    };

    for (int i = 0; i < 3; i++) {
        f[i] = g_strdup_printf("%s/ckpt%d", dir, i + 1);
    }
    pdev = femu_lsi_ckpt_dev(qts, bus, &c, alloc, NULL);
    femu_lsi_aec(&c, true);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 16, false), ==, 0);
    want = femu_aer(&c);
    femu_mark_uncor(&c, 10, 1);
    g_assert_true(femu_lsi_after(&c, FEMU_LSI_SEC * 11 / 10));
    femu_lsi_alert(&c, want);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 48, false), ==, 1);
    femu_mark_uncor(&c, 20, 1);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 64, false), ==, 2);
    g_assert_cmpint(femu_lsi_state(qts, "alert_gen"), ==, 1);
    g_assert_null(femu_save_data(qts, "lsi-test", f[0]));
    g_assert_true(g_file_get_contents(f[0], &bytes, &len, NULL));

    want = femu_aer(&c);
    g_assert_true(femu_lsi_after(&c, FEMU_LSI_SEC * 11 / 10));
    femu_lsi_alert(&c, want);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 64, false), ==, 2);
    femu_mark_uncor(&c, 30, 1);
    want = femu_aer(&c);
    g_assert_true(femu_lsi_after(&c, FEMU_LSI_SEC * 11 / 10));
    femu_lsi_alert(&c, want);
    g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE, 30, dbuf), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_lsi_state(qts, "alert_gen"), ==, 3);
    g_assert_cmpint(femu_lsi_state(qts, "g_r"), ==, 2);
    g_assert_null(femu_save_data(qts, "lsi-test", f[1]));

    g_assert_cmpint(femu_lsi_gen(&c, buf, 80, false), ==, 3);
    want = femu_aer(&c);
    femu_lsi_cmd(qts, "component:1");
    g_assert_true(femu_lsi_after(&c, 1000));
    femu_lsi_alert(&c, want);
    g_assert_cmpint(femu_lsi_state(qts, "unacked"), ==, 1);
    g_assert_cmpint(femu_lsi_state(qts, "comp"), ==, 0);
    g_assert_null(femu_save_data(qts, "lsi-test", f[2]));
    femu_lsi_ckpt_del(qts, &c, pdev);

    /* ckpt1: history B */
    pdev = femu_lsi_ckpt_dev(qts, bus, &c, alloc, f[0]);
    femu_lsi_aec(&c, true);
    want = femu_aer(&c);
    g_assert_false(femu_lsi_after(&c, FEMU_LSI_SEC - 1));
    g_assert_true(femu_lsi_after(&c, FEMU_LSI_SEC / 10));
    femu_lsi_alert(&c, want);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 64, false), ==, 2);
    femu_lsi_ckpt_del(qts, &c, pdev);

    /* ckpt2: the unread gen 3 alert comes back at 3 */
    pdev = femu_lsi_ckpt_dev(qts, bus, &c, alloc, f[1]);
    femu_lsi_aec(&c, true);
    want = femu_aer(&c);
    g_assert_false(femu_lsi_after(&c, FEMU_LSI_SEC - 1));
    g_assert_true(femu_lsi_after(&c, FEMU_LSI_SEC / 10));
    femu_lsi_alert(&c, want);
    g_assert_cmpint(femu_lsi_gen(&c, buf, 64, false), ==, 3);
    femu_lsi_ckpt_del(qts, &c, pdev);

    /* ckpt3: the unread component alert comes back at once */
    pdev = femu_lsi_ckpt_dev(qts, bus, &c, alloc, f[2]);
    want = femu_aer(&c);
    femu_lsi_aec(&c, true);
    g_assert_true(femu_lsi_after(&c, 1000));
    femu_lsi_alert(&c, want);
    femu_lsi_ckpt_del(qts, &c, pdev);

    /* changed copies of ckpt1: the section after "LSI1" */
    sec = memmem(bytes, len, "LSI1", 4);
    g_assert_nonnull(sec);
    g_assert_cmpuint(len - (sec - bytes), >=, 88);
    for (size_t i = 0; i < ARRAY_SIZE(edit); i++) {
        g_autofree char *copy = g_memdup2(bytes, len);
        char *e = copy + (sec - bytes) + edit[i].off;

        if (edit[i].size == 8) {
            stq_le_p(e, edit[i].val);
        } else if (edit[i].size == 4) {
            stl_le_p(e, edit[i].val);
        } else {
            *e = edit[i].val;
        }
        g_assert_true(g_file_set_contents(bad, copy, len, NULL));
        femu_lsi_ckpt_bad(qts, bad);
    }

    for (int i = 0; i < 3; i++) {
        g_autofree char *lock = g_strconcat(f[i], ".lock", NULL);

        unlink(lock);
        unlink(f[i]);
    }
    {
        g_autofree char *lock = g_strconcat(bad, ".lock", NULL);

        unlink(lock);
    }
    unlink(bad);
    rmdir(dir);
    guest_free(alloc, dbuf);
    guest_free(alloc, buf);
    qos_invalidate_command_line();
}

/*
 * Get LBA Status, when a write clears a run's first block between the
 * two bitmap searches: the scan goes on past it, with no 2^32-block run.
 */
void femu_test_lsi_gls_race(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_mark_uncor(&c, 10, 3);
    femu_mark_uncor(&c, 20, 1);
    femu_lsi_cmd(qts, "glsrace:1");
    g_assert_cmpint(femu_get_lba_status(&c, buf, 0, 1023, 0x11, 0), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(qtest_readl(qts, buf), ==, 2);
    g_assert_cmpint(qtest_readq(qts, buf + 8), ==, 11);
    g_assert_cmpint(qtest_readl(qts, buf + 16), ==, 1);
    g_assert_cmpint(qtest_readq(qts, buf + 24), ==, 20);
    g_assert_cmpint(qtest_readl(qts, buf + 32), ==, 0);

    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/* the QEMU process's current virtual size, in KiB */
static uint64_t femu_vm_size_kb(QTestState *qts)
{
    g_autofree char *path = g_strdup_printf("/proc/%d/status", qtest_pid(qts));
    g_autofree char *text = NULL;
    const char *line;

    g_assert_true(g_file_get_contents(path, &text, NULL, NULL));
    line = strstr(text, "VmSize:");
    g_assert_nonnull(line);
    return g_ascii_strtoull(line + strlen("VmSize:"), NULL, 10);
}

/*
 * The process's resident memory from smaps_rollup, in KiB, for the log:
 * VmSize is the check, as a leaked backend is address space even when its
 * pages were never touched or could not be locked.
 */
static uint64_t femu_rss_kb(QTestState *qts)
{
    g_autofree char *path = g_strdup_printf("/proc/%d/smaps_rollup",
                                            qtest_pid(qts));
    g_autofree char *text = NULL;
    const char *line;

    if (!g_file_get_contents(path, &text, NULL, NULL)) {
        return 0;
    }
    line = strstr(text, "\nRss:");
    return line ? g_ascii_strtoull(line + strlen("\nRss:"), NULL, 10) : 0;
}

#define FEMU_LIFECYCLE_CYCLES  4
#define FEMU_LIFECYCLE_MB      256
#define FEMU_LIFECYCLE_SLOT    9

/*
 * Hot-add a 256 MiB device of one mode, use it, unplug it, and repeat. The
 * backend alone is 256 MiB of address space, so a device whose teardown
 * leaves it mapped grows the process by that much each cycle. The first
 * cycle sets the base: QEMU and the allocator keep some memory once used.
 * @data is the extra device properties, starting with femu_mode; with
 * "io" in front, the cycle also writes and reads back one block.
 */
void femu_test_lifecycle(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    const char *opts = data;
    bool io = g_str_has_prefix(opts, "io,");
    uint64_t base = 0;
    uint64_t now = 0;
    int i;

    if (io) {
        opts += strlen("io,");
    }
    for (i = 0; i < FEMU_LIFECYCLE_CYCLES; i++) {
        g_autofree char *json = g_strdup_printf(
            "{\"driver\":\"femu\",\"id\":\"life\",\"addr\":\"%d\","
            "\"devsz_mb\":%d,%s}", FEMU_LIFECYCLE_SLOT, FEMU_LIFECYCLE_MB,
            opts);
        QObject *args = qobject_from_json(json, &error_abort);
        QDict *rsp = qtest_qmp(qts,
                               "{'execute':'device_add','arguments':%p}", args);
        FemuCtrlState c = { 0 };
        QPCIDevice *pdev;

        g_assert_true(qdict_haskey(rsp, "return"));
        qobject_unref(rsp);
        pdev = qpci_device_find(femu->dev.bus,
                                QPCI_DEVFN(FEMU_LIFECYCLE_SLOT, 0));
        g_assert_nonnull(pdev);
        femu_enable(&c, pdev, alloc);
        if (io) {
            femu_create_io_queues(&c);
            femu_round_trip(&c, (uint8_t)(i + 1));
            femu_queue_free(&c, &c.io);
        }
        femu_disable(&c);
        qpci_unplug_acpi_device_test(qts, "life", FEMU_LIFECYCLE_SLOT);
        g_free(pdev);

        now = femu_vm_size_kb(qts);
        if (i == 0) {
            base = now;
        }
        g_test_message("cycle %d: VmSize %" PRIu64 " KiB (%+" PRId64
                       "), Rss %" PRIu64 " KiB", i, now,
                       (int64_t)now - (int64_t)base, femu_rss_kb(qts));
        /* stop at the first cycle past the bound, before more leaks pile up */
        g_assert_cmpuint(now, <, base + 64 * 1024);
    }
}

/*
 * With MDTS 0 there is no transfer limit, so the host can ask for up to 4 GiB
 * of a report whose data is a few hundred bytes. The device allocated a
 * buffer of the whole request. Each report is sent in full, so without a PRP
 * list for 4 GiB these are refused, but only after the allocation would have
 * happened, which is why the size is checked first.
 */
void femu_test_mdts0_reports(void *obj, void *data,
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

/*
 * Timestamp (Base 2.3, 5.2.26.1.7): advertised in ONCS; after a Set the
 * controller counts on from the host's value and reports origin 001b; a
 * Controller Level Reset clears it to the time since that reset, origin 000b.
 * The value is 48 bits and the two bytes above it are reserved.
 */
void femu_test_timestamp(void *obj, void *data, QGuestAllocator *alloc)
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
#define FEMU_CMD_SEQ_ERROR      0x0c

/* the event type of the i'th event reported, counting from the newest */
static uint8_t femu_pel_event(QTestState *qts, uint64_t buf, int i)
{
    uint64_t e = buf + 512;

    while (i--) {
        e += 3 + qtest_readb(qts, e + 2) + qtest_readw(qts, e + 22);
    }
    return qtest_readb(qts, e);
}

void femu_test_ns_mgmt_format_detached(void *obj, void *data,
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

void femu_test_ns_mgmt_unallocated(void *obj, void *data,
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

void femu_test_ns_mgmt_validation(void *obj, void *data,
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

void femu_test_ns_mgmt_notices(void *obj, void *data,
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

void femu_test_ns_mgmt_overflow(void *obj, void *data,
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

void femu_test_shared_lifecycle(void *obj, void *data,
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

void femu_test_shared_discovery(void *obj, void *data,
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
    /*
     * Earlier I/O moved the head, so the last entry need not be in the last
     * slot. Wait for it at the phase its lap carries; otherwise the queue may
     * still have room when the caller snapshots it.
     */
    uint16_t last = (c->io.cq_head + FEMU_QSIZE - 2) % FEMU_QSIZE;
    uint16_t phase = last < c->io.cq_head ? !c->io.phase : c->io.phase;

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
        qtest_memread(c->pdev->bus->qts, c->io.cq_addr + last * sizeof(cqe),
                      &cqe, sizeof(cqe));
        g_assert_cmpuint(waited++, <, FEMU_POLL_LIMIT_MS);
        g_usleep(1000);
    } while ((le16_to_cpu(cqe.status) & 1) != phase);
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

void femu_test_shared_retire(void *obj, void *data,
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

void femu_test_shared_features(void *obj, void *data,
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

void femu_test_shared_sanitize(void *obj, void *data,
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

void femu_test_shared_remove(void *obj, void *data,
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

void femu_test_shared_private(void *obj, void *data,
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

void femu_test_shared_admin(void *obj, void *data,
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

void femu_test_shared_subsys_release(void *obj, void *data,
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

void femu_test_ns_mgmt_subsys(void *obj, void *data,
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
void femu_test_ns_mgmt_common_dpc(void *obj, void *data,
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
    g_assert_cmpint(dpc, ==, 0x17);
    g_assert_cmpint(femu_identify(&c, NVME_NSID_BROADCAST, 0, 0, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(qtest_readb(qts, buf + 28), ==, dpc);
    femu_disable(&c);
    guest_free(alloc, buf);
}

void femu_test_ns_mgmt_identify_csi_common(void *obj, void *data,
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

void femu_test_ns_mgmt_identify(void *obj, void *data,
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

void femu_test_ns_mgmt_default(void *obj, void *data,
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

/*
 * namespace_sizes may take the whole of devsz_mb even when the namespace
 * count does not divide it, and each size is rounded down to whole logical
 * blocks: 6 KiB of 4 KiB blocks is one block, and the capacity the controller
 * reports is what the namespaces can address.
 */
void femu_test_namespace_sizes_rounding(void *obj, void *data,
                                        QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    QPCIDevice *pdev;
    QDict *rsp;
    uint64_t buf = guest_alloc(alloc, 4096);

    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'sizes-whole','addr':'5',"
                    "'devsz_mb':64,'femu_mode':2,'namespaces':3,"
                    "'namespace_sizes':'32M,16M,16M'}}");
    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);

    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'sizes-lba','addr':'6',"
                    "'devsz_mb':64,'femu_mode':2,'namespaces':2,"
                    "'lba_index':3,'namespace_sizes':'6K,8K'}}");
    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
    pdev = qpci_device_find(femu->dev.bus, QPCI_DEVFN(6, 0));
    g_assert_nonnull(pdev);
    femu_enable(&c, pdev, alloc);
    g_assert_cmpint(femu_identify(&c, 1, 0, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(qts, buf), ==, 1);             /* NSZE */
    g_assert_cmpint(femu_identify(&c, 2, 0, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(qts, buf), ==, 2);
    g_assert_cmpint(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(qts, buf + 280), ==, 12 * 1024); /* TNVMCAP */
    femu_disable(&c);
    guest_free(alloc, buf);
    g_free(pdev);
    qos_invalidate_command_line();
}

/*
 * A namespace slice smaller than one block realizes as an empty namespace,
 * as it always has, rather than refusing the device.
 */
void femu_test_namespace_empty_slice(void *obj, void *data,
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

void femu_test_namespace_large(void *obj, void *data,
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

void femu_test_namespace_copy_source(void *obj, void *data,
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

void femu_test_namespace_sanitize_free(void *obj, void *data,
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

void femu_test_namespace_lifecycle(void *obj, void *data,
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

void femu_test_namespace_capacity(void *obj, void *data,
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

void femu_test_namespace_identity(void *obj, void *data,
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

void femu_test_namespace_allocated(void *obj, void *data,
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

void femu_test_namespace_sparse(void *obj, void *data,
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
void femu_test_pel(void *obj, void *data, QGuestAllocator *alloc)
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

/* Successful settings, including repeats, are retained for host diagnosis. */
void femu_test_pel_set_feature(void *obj, void *data,
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

void femu_test_pel_file(void *obj, void *data, QGuestAllocator *alloc)
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
                           FEMU_UNRECOVERED_READ | NVME_DNR);
            g_assert_cmpint(femu_complete(&c, &second, NULL, NULL), ==,
                           FEMU_UNRECOVERED_READ | NVME_DNR);
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
void femu_test_pel_file_quit(void *obj, void *data,
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
                               FEMU_UNRECOVERED_READ | NVME_DNR);
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

/*
 * io_trace on a NoSSD device: two writes and a read, then quit. The file
 * holds the header and one line per I/O command, in order, with the
 * opcode, the range and status 0; the admin commands are not in it. A
 * second device cannot take the file: the first one traces to it.
 */
void femu_test_io_trace(void *obj, void *data, QGuestAllocator *alloc)
{
    g_autofree char *dir = g_dir_make_tmp("femu-iotrace-XXXXXX", NULL);
    g_autofree char *path = g_build_filename(dir, "trace.csv", NULL);
    g_autofree char *text = NULL;
    g_auto(GStrv) lines = NULL;
    QOSState *qs = qtest_pc_boot(
        "-machine pc -nodefaults -device femu,id=pd,addr=5,devsz_mb=16,"
        "femu_mode=2,io_trace=%s", path);
    QTestState *qts = qs->qts;
    QPCIDevice *pdev = qpci_device_find(qs->pcibus, QPCI_DEVFN(5, 0));
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(&qs->alloc, 4096);
    QDict *rsp;

    femu_enable(&c, pdev, &qs->alloc);
    femu_create_io_queues(&c);
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 0, buf)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 16, buf)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_READ, 16, buf)), ==,
                    NVME_SUCCESS);
    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'pe','addr':'6','devsz_mb':16,"
                    "'io_trace':%s}}", path);
    g_assert_true(qdict_haskey(rsp, "error"));
    g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                          "desc"), "io_trace of a device"));
    qobject_unref(rsp);
    femu_disable(&c);
    femu_queue_free(&c, &c.io);
    guest_free(&qs->alloc, buf);
    g_free(pdev);
    qtest_qmp_send(qts, "{'execute':'quit'}");
    qtest_set_expected_status(qts, 0);
    qtest_wait_qemu(qts);
    qtest_pc_shutdown(qs);

    g_assert_true(g_file_get_contents(path, &text, NULL, NULL));
    lines = g_strsplit(text, "\n", 0);
    for (int i = 0; lines[i]; i++) {
        g_test_message("io_trace: %s", lines[i]);
    }
    g_assert_cmpuint(g_strv_length(lines), ==, 5);    /* 4 lines, then "" */
    g_assert_cmpstr(lines[0], ==, "t_submit_ns,t_cqe_ns,sqid,cid,nsid,"
                    "opcode,slba,nlb,status");
    for (int i = 1; i <= 3; i++) {
        g_auto(GStrv) f = g_strsplit(lines[i], ",", 0);
        static const char *const want[4][3] = {
            { NULL }, { "0x01", "0", "8" }, { "0x01", "16", "8" },
            { "0x02", "16", "8" },
        };

        g_assert_cmpuint(g_strv_length(f), ==, 9);
        g_assert_cmpuint(g_ascii_strtoull(f[1], NULL, 10), >=,
                         g_ascii_strtoull(f[0], NULL, 10));
        g_assert_cmpstr(f[2], ==, "1");
        g_assert_cmpstr(f[4], ==, "1");
        g_assert_cmpstr(f[5], ==, want[i][0]);
        g_assert_cmpstr(f[6], ==, want[i][1]);
        g_assert_cmpstr(f[7], ==, want[i][2]);
        g_assert_cmpstr(f[8], ==, "0x0");
    }
    unlink(path);
    rmdir(dir);
}

/* Set Features 01h, Arbitration */
static void femu_set_arbitration(FemuCtrlState *c, uint32_t arb)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = NVME_ADM_CMD_SET_FEATURES;
    cmd.cdw10 = cpu_to_le32(NVME_ARBITRATION);
    cmd.cdw11 = cpu_to_le32(arb);
    g_assert_cmpint(femu_admin(c, &cmd), ==, NVME_SUCCESS);
}

typedef struct FemuTraceRow {
    uint64_t t_submit;
    int row;        /* the completion order breaks a tie */
    int sqid;
} FemuTraceRow;

static int femu_trace_row_cmp(const void *a, const void *b)
{
    const FemuTraceRow *x = a;
    const FemuTraceRow *y = b;

    if (x->t_submit != y->t_submit) {
        return x->t_submit < y->t_submit ? -1 : 1;
    }
    return x->row - y->row;
}

#define FEMU_ARB_DEPTH  8

/*
 * The Arbitration Burst (AB) of feature 01h, on one poller and two
 * submission queues of 8 reads each. The fetch is held while both are
 * filled, then let go. io_trace stamps t_submit_ns at the fetch, so the
 * rows sorted by it give the fetch order. AB 0 takes one command of a
 * queue and moves on, AB 1 two; the reset value, AB 7, empties queue 1
 * first. 8 commands cannot tell AB 7 from a limit of 8 or more.
 */
void femu_test_arb_burst(void *obj, void *data, QGuestAllocator *alloc)
{
    static const struct {
        uint32_t arb;
        const char *order;
    } pass[] = {
        { 0, "1111111122222222" },          /* the reset value, not set */
        { FEMU_ARB_DEFAULT & ~7u, "1212121212121212" },
        { (FEMU_ARB_DEFAULT & ~7u) | 1, "1122112211221122" },
        { FEMU_ARB_DEFAULT, "1111111122222222" },
    };
    g_autofree char *dir = g_dir_make_tmp("femu-arb-XXXXXX", NULL);
    g_autofree char *path = g_build_filename(dir, "trace.csv", NULL);
    g_autofree char *text = NULL;
    g_auto(GStrv) lines = NULL;
    QOSState *qs = qtest_pc_boot(
        "-machine pc -nodefaults -device femu,id=arb,addr=5,devsz_mb=16,"
        "femu_mode=2,io_trace=%s", path);
    QTestState *qts = qs->qts;
    QPCIDevice *pdev = qpci_device_find(qs->pcibus, QPCI_DEVFN(5, 0));
    FemuCtrlState c = { 0 };
    FemuQueue q[2];
    uint64_t buf = guest_alloc(&qs->alloc, 4096);
    int row = 1;

    femu_enable(&c, pdev, &qs->alloc);
    for (int i = 0; i < 2; i++) {
        femu_burst_queue(&c, &q[i], i + 1);
    }
    for (size_t p = 0; p < ARRAY_SIZE(pass); p++) {
        if (pass[p].arb) {
            femu_set_arbitration(&c, pass[p].arb);
        }
        femu_fetch_hold(qts, "arb", 1);
        for (int i = 0; i < 2; i++) {
            for (int k = 0; k < FEMU_ARB_DEPTH; k++) {
                NvmeRwCmd rw = { 0 };

                rw.opcode = NVME_CMD_READ;
                rw.cid = cpu_to_le16(c.cid++);
                rw.nsid = cpu_to_le32(1);
                rw.dptr.prp1 = cpu_to_le64(buf);
                rw.slba = cpu_to_le64(k);
                qtest_memwrite(qts, q[i].sq_addr +
                               q[i].sq_tail * sizeof(NvmeCmd), &rw,
                               sizeof(rw));
                q[i].sq_tail = (q[i].sq_tail + 1) % FEMU_QSIZE;
            }
            qpci_io_writel(c.pdev, c.bar, femu_sq_doorbell(&c, q[i].qid),
                           q[i].sq_tail);
        }
        femu_fetch_hold(qts, "arb", 0);
        for (int i = 0; i < 2; i++) {
            for (int k = 0; k < FEMU_ARB_DEPTH; k++) {
                uint16_t cid;

                g_assert_cmpint(FEMU_SC(femu_complete(&c, &q[i], &cid,
                                                      NULL)),
                                ==, NVME_SUCCESS);
            }
        }
    }
    for (int i = 0; i < 2; i++) {
        femu_queue_free(&c, &q[i]);
    }
    femu_disable(&c);
    guest_free(&qs->alloc, buf);
    g_free(pdev);
    qtest_qmp_send(qts, "{'execute':'quit'}");
    qtest_set_expected_status(qts, 0);
    qtest_wait_qemu(qts);
    qtest_pc_shutdown(qs);

    g_assert_true(g_file_get_contents(path, &text, NULL, NULL));
    lines = g_strsplit(text, "\n", 0);
    for (size_t p = 0; p < ARRAY_SIZE(pass); p++) {
        FemuTraceRow r[2 * FEMU_ARB_DEPTH];
        char got[2 * FEMU_ARB_DEPTH + 1];

        for (int k = 0; k < 2 * FEMU_ARB_DEPTH; k++, row++) {
            g_auto(GStrv) f = NULL;

            g_assert_nonnull(lines[row]);
            f = g_strsplit(lines[row], ",", 0);
            g_assert_cmpuint(g_strv_length(f), ==, 9);
            r[k].t_submit = g_ascii_strtoull(f[0], NULL, 10);
            r[k].sqid = atoi(f[2]);
            r[k].row = row;
        }
        qsort(r, 2 * FEMU_ARB_DEPTH, sizeof(r[0]), femu_trace_row_cmp);
        for (int k = 0; k < 2 * FEMU_ARB_DEPTH; k++) {
            got[k] = '0' + r[k].sqid;
        }
        got[2 * FEMU_ARB_DEPTH] = 0;
        g_test_message("arb 0x%08x: fetch order %s", pass[p].arb, got);
        g_assert_cmpstr(got, ==, pass[p].order);
    }
    unlink(path);
    rmdir(dir);
}

/* an I/O queue pair @qid whose submission queue has priority @prio */
static void femu_prio_queue(FemuCtrlState *c, FemuQueue *q, uint16_t qid,
                            uint8_t prio)
{
    NvmeCmd cmd = { 0 };

    femu_queue_init(c, q, qid);
    cmd.opcode = NVME_ADM_CMD_CREATE_CQ;
    cmd.dptr.prp1 = cpu_to_le64(q->cq_addr);
    cmd.cdw10 = cpu_to_le32(((FEMU_QSIZE - 1) << 16) | qid);
    cmd.cdw11 = cpu_to_le32(NVME_CQ_PC);
    g_assert_cmpint(femu_admin(c, &cmd), ==, NVME_SUCCESS);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_CREATE_SQ;
    cmd.dptr.prp1 = cpu_to_le64(q->sq_addr);
    cmd.cdw10 = cpu_to_le32(((FEMU_QSIZE - 1) << 16) | qid);
    cmd.cdw11 = cpu_to_le32((qid << 16) | (prio << 1) | NVME_SQ_PC);
    g_assert_cmpint(femu_admin(c, &cmd), ==, NVME_SUCCESS);
}

/* queue @nr reads in @q and ring its doorbell */
static void femu_queue_reads(FemuCtrlState *c, FemuQueue *q, int nr,
                             uint64_t buf)
{
    for (int k = 0; k < nr; k++) {
        NvmeRwCmd rw = { 0 };

        rw.opcode = NVME_CMD_READ;
        rw.cid = cpu_to_le16(c->cid++);
        rw.nsid = cpu_to_le32(1);
        rw.dptr.prp1 = cpu_to_le64(buf);
        rw.slba = cpu_to_le64(k);
        qtest_memwrite(c->pdev->bus->qts,
                       q->sq_addr + q->sq_tail * sizeof(NvmeCmd), &rw,
                       sizeof(rw));
        q->sq_tail = (q->sq_tail + 1) % FEMU_QSIZE;
    }
    qpci_io_writel(c->pdev, c->bar, femu_sq_doorbell(c, q->qid), q->sq_tail);
}

/* the sqid of each traced command of @path, in fetch order */
static char *femu_fetch_order(const char *path)
{
    g_autofree char *text = NULL;
    g_auto(GStrv) lines = NULL;
    g_autofree FemuTraceRow *r = NULL;
    char *got;
    guint nr;

    g_assert_true(g_file_get_contents(path, &text, NULL, NULL));
    lines = g_strsplit(text, "\n", 0);
    nr = g_strv_length(lines);
    g_assert_cmpuint(nr, >, 2);
    nr -= 2;                            /* the header and the last "" */
    r = g_new0(FemuTraceRow, nr);
    for (guint k = 0; k < nr; k++) {
        g_auto(GStrv) f = g_strsplit(lines[k + 1], ",", 0);

        g_assert_cmpuint(g_strv_length(f), ==, 9);
        r[k].t_submit = g_ascii_strtoull(f[0], NULL, 10);
        r[k].sqid = atoi(f[2]);
        r[k].row = k;
    }
    qsort(r, nr, sizeof(r[0]), femu_trace_row_cmp);
    got = g_malloc0(nr + 1);
    for (guint k = 0; k < nr; k++) {
        got[k] = '0' + r[k].sqid;
    }
    return got;
}

/*
 * One poller, NoSSD, io_trace. The fetch is held while every queue is
 * filled, then let go; the trace sorted by fetch time gives the order.
 */
void femu_test_wrr(void *obj, void *data, QGuestAllocator *alloc)
{
    const FemuWrrCase *t = data;
    g_autofree char *dir = g_dir_make_tmp("femu-wrr-XXXXXX", NULL);
    g_autofree char *path = g_build_filename(dir, "trace.csv", NULL);
    g_autofree char *got = NULL;
    QOSState *qs = qtest_pc_boot(
        "-machine pc -nodefaults -device femu,id=arb,addr=5,devsz_mb=16,"
        "femu_mode=2,io_trace=%s%s", path, t->opts);
    QTestState *qts = qs->qts;
    QPCIDevice *pdev = qpci_device_find(qs->pcibus, QPCI_DEVFN(5, 0));
    FemuCtrlState c = { 0 };
    FemuQueue q[4];
    uint64_t buf = guest_alloc(&qs->alloc, 4096);

    c.pdev = pdev;
    c.alloc = &qs->alloc;
    femu_queue_init(&c, &c.admin, 0);
    femu_enable_cc(&c, pdev, &qs->alloc,
                   (6 << 16) | (4 << 20) | (t->cc_ams << 11) | 1);
    femu_set_arbitration(&c, t->arb);
    for (int i = 0; i < t->nr; i++) {
        femu_prio_queue(&c, &q[i], i + 1, t->prio[i]);
    }
    femu_fetch_hold(qts, "arb", 1);
    for (int i = 0; i < t->nr; i++) {
        femu_queue_reads(&c, &q[i], t->depth[i], buf);
    }
    femu_fetch_hold(qts, "arb", 0);
    for (int i = 0; i < t->nr; i++) {
        for (int k = 0; k < t->depth[i]; k++) {
            uint16_t cid;

            g_assert_cmpint(FEMU_SC(femu_complete(&c, &q[i], &cid, NULL)),
                            ==, NVME_SUCCESS);
        }
        femu_queue_free(&c, &q[i]);
    }
    femu_disable(&c);
    g_free(pdev);
    qtest_qmp_send(qts, "{'execute':'quit'}");
    qtest_set_expected_status(qts, 0);
    qtest_wait_qemu(qts);
    qtest_pc_shutdown(qs);

    got = femu_fetch_order(path);
    g_test_message("wrr: fetch order %s", got);
    g_assert_cmpstr(got, ==, t->order);
    unlink(path);
    rmdir(dir);
}

/*
 * wrr off: CC.AMS 001b fails the start (CSTS.CFS). wrr on needs one
 * poller, so realize refuses it with a poller per queue.
 */
void femu_test_wrr_refused(void *obj, void *data,
                           QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    QDict *rsp;

    c.pdev = &femu->dev;
    c.alloc = alloc;
    femu_queue_init(&c, &c.admin, 0);
    femu_enable_start(&c, &femu->dev, alloc,
                      (6 << 16) | (4 << 20) | (1 << 11) | 1);
    g_assert_cmpint(qpci_io_readl(c.pdev, c.bar, 0x1c) &
                    (NVME_CSTS_READY | NVME_CSTS_FAILED), ==,
                    NVME_CSTS_FAILED);
    g_assert_cmpint((qpci_io_readq(c.pdev, c.bar, 0) >> 17) & 3, ==, 0);
    femu_disable(&c);
    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'wr2','addr':'6','devsz_mb':16,"
                    "'femu_mode':2,'wrr':true,'multipoller_enabled':1}}");
    g_assert_true(qdict_haskey(rsp, "error"));
    g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                          "desc"), "wrr needs one poller"));
    qobject_unref(rsp);
}

/*
 * A blocked urgent queue does not keep the grant. Urgent SQ 2 fills its
 * completion queue (15 entries, never read), then gets 4 more commands
 * while low SQ 1 gets 8. The low queue runs; once the host reads the
 * completion queue, the urgent commands run with no new doorbell.
 */
void femu_test_wrr_blocked(void *obj, void *data,
                           QGuestAllocator *alloc)
{
    g_autofree char *dir = g_dir_make_tmp("femu-wrr-XXXXXX", NULL);
    g_autofree char *path = g_build_filename(dir, "trace.csv", NULL);
    g_autofree char *got = NULL;
    QOSState *qs = qtest_pc_boot(
        "-machine pc -nodefaults -device femu,id=arb,addr=5,devsz_mb=16,"
        "femu_mode=2,wrr=on,io_trace=%s", path);
    QTestState *qts = qs->qts;
    QPCIDevice *pdev = qpci_device_find(qs->pcibus, QPCI_DEVFN(5, 0));
    FemuCtrlState c = { 0 };
    FemuQueue q[2];
    uint64_t buf = guest_alloc(&qs->alloc, 4096);
    int waited = 0;

    c.pdev = pdev;
    c.alloc = &qs->alloc;
    femu_queue_init(&c, &c.admin, 0);
    femu_enable_cc(&c, pdev, &qs->alloc,
                   (6 << 16) | (4 << 20) | (1 << 11) | 1);
    femu_set_arbitration(&c, FEMU_ARB(31, 15, 7, 0));
    femu_prio_queue(&c, &q[0], 1, 3);
    femu_prio_queue(&c, &q[1], 2, 0);
    femu_queue_reads(&c, &q[1], FEMU_QSIZE - 1, buf);
    /* wait until the 15th completion is posted: the queue is full */
    while (!(qtest_readw(qts, q[1].cq_addr + (FEMU_QSIZE - 2) *
                         sizeof(NvmeCqe) + 14) & 1)) {
        g_assert_cmpint(waited++, <, FEMU_POLL_LIMIT_MS);
        g_usleep(1000);
    }
    femu_fetch_hold(qts, "arb", 1);
    femu_queue_reads(&c, &q[1], 4, buf);
    femu_queue_reads(&c, &q[0], 8, buf);
    femu_fetch_hold(qts, "arb", 0);
    for (int k = 0; k < 8; k++) {
        uint16_t cid;

        g_assert_cmpint(FEMU_SC(femu_complete(&c, &q[0], &cid, NULL)), ==,
                        NVME_SUCCESS);
    }
    for (int k = 0; k < FEMU_QSIZE - 1 + 4; k++) {
        uint16_t cid;

        g_assert_cmpint(FEMU_SC(femu_complete(&c, &q[1], &cid, NULL)), ==,
                        NVME_SUCCESS);
    }
    for (int i = 0; i < 2; i++) {
        femu_queue_free(&c, &q[i]);
    }
    femu_disable(&c);
    g_free(pdev);
    qtest_qmp_send(qts, "{'execute':'quit'}");
    qtest_set_expected_status(qts, 0);
    qtest_wait_qemu(qts);
    qtest_pc_shutdown(qs);

    got = femu_fetch_order(path);
    g_test_message("wrr-blocked: fetch order %s", got);
    g_assert_cmpstr(got, ==, "222222222222222" "11111111" "2222");
    unlink(path);
    rmdir(dir);
}

/* the time of event 0 of a device realized with events_file @path */
static int64_t femu_events_seed_time(const char *path)
{
    QOSState *qs = qtest_pc_boot(
        "-machine pc -nodefaults -device femu,id=ev,addr=5,devsz_mb=16,"
        "femu_mode=1,ana=on,events_file=%s", path);
    QDict *rsp;
    QDict *r = femu_events_q(qs->qts, "ev", &rsp);
    QDict *e = qobject_to(QDict, qlist_peek(qdict_get_qlist(r, "events")));
    int64_t t = qdict_get_int(e, "time-ms");

    qobject_unref(rsp);
    qtest_pc_shutdown(qs);
    return t;
}

/*
 * A seeded window draws one time, the same for the same file and seed,
 * and the one splitmix64 gives.
 */
void femu_test_events_seed(void *obj, void *data,
                           QGuestAllocator *alloc)
{
    g_autofree char *dir = g_dir_make_tmp("femu-events-XXXXXX", NULL);
    g_autofree char *path = femu_events_file(dir, "100+1000~42 ana=1:2\n");
    int64_t a = femu_events_seed_time(path);
    int64_t b = femu_events_seed_time(path);

    g_test_message("seeded time %" PRId64 " ms", a);
    /* splitmix64 seeded with 42 gives 13679457532755275413, 413 mod 1000 */
    g_assert_cmpint(a, ==, 513);
    g_assert_cmpint(a, ==, b);
    unlink(path);
    rmdir(dir);
}

/*
 * precon_fill_pct: device pre preconditions at realize, device ref takes
 * the same page writes from the host, through the timed path. The FTL
 * state hashes (x-ftl-state) must agree field by field, and so must the
 * counter changes of the same follow-up writes on both.
 */
#define FEMU_PRECON_GEOM \
    "devsz_mb=4,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16," \
    "blks_per_pl=40,pls_per_lun=1,luns_per_ch=1,nchs=2"
/* logical pages of FEMU_PRECON_GEOM, 4 KiB each */
#define FEMU_PRECON_PAGES   1024
#define FEMU_PRECON_FOLLOW  2048

static const char *const femu_precon_fields[] = {
    "map", "page", "block", "line", "pointer", "misc",
};

static gchar **femu_precon_state(QTestState *qts, const char *id)
{
    g_autofree char *path = g_strdup_printf("/machine/peripheral/%s", id);
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                           "'path':%s,'property':'x-ftl-state'}}", path);
    gchar **v;

    g_assert_true(qdict_haskey(rsp, "return"));
    v = g_strsplit(qdict_get_str(rsp, "return"), " ", 0);
    g_assert_cmpuint(g_strv_length(v), ==, 6);
    qobject_unref(rsp);
    return v;
}

/* the fields where the states of ref and pre differ */
static int femu_precon_diff(QTestState *qts, const char *when)
{
    g_auto(GStrv) r = femu_precon_state(qts, "ref");
    g_auto(GStrv) p = femu_precon_state(qts, "pre");
    int diff = 0;

    for (int i = 0; i < 6; i++) {
        if (strcmp(r[i], p[i])) {
            g_test_message("precon %s: %s differs: ref %s pre %s", when,
                           femu_precon_fields[i], r[i], p[i]);
            diff++;
        }
    }
    return diff;
}

/* the page counters of the WAF, and block erases, of device @id */
#define FEMU_PRECON_CTRS 7
static const char *const femu_precon_ctr_names[FEMU_PRECON_CTRS] = {
    "host-write-pages", "nand-write-pages", "gc-write-pages",
    "map-write-pages", "pad-write-pages", "parity-write-pages",
    "block-erases",
};

static void femu_precon_ctrs(QTestState *qts, const char *id,
                             uint64_t v[FEMU_PRECON_CTRS], QDict **pc,
                             double *waf)
{
    g_autofree char *args = g_strdup_printf(
        "'path':'/machine/peripheral/%s'", id);
    QDict *rsp;
    QDict *ns = femu_query_ns(qts, args, &rsp);
    QDict *ctr = qdict_get_qdict(ns, "counters");

    for (int i = 0; i < FEMU_PRECON_CTRS; i++) {
        /* map, pad and parity are absent where the device has none */
        v[i] = qdict_get_try_int(ctr, femu_precon_ctr_names[i], 0);
    }
    if (waf) {
        *waf = qdict_haskey(ctr, "waf") ? qdict_get_double(ctr, "waf") : 0;
    }
    if (pc) {
        *pc = qdict_haskey(ns, "precondition") ?
              qdict_get_qdict(ns, "precondition") : NULL;
        if (*pc) {
            qobject_ref(*pc);
        }
    }
    qobject_unref(rsp);
}

/* the same random page writes on the device of @c */
static void femu_precon_follow(FemuCtrlState *c, uint64_t buf)
{
    uint64_t s = 5;

    for (int i = 0; i < FEMU_PRECON_FOLLOW; i++) {
        uint64_t lpn = precon_scale(precon_rand_next(&s), FEMU_PRECON_PAGES);

        g_assert_cmpint(FEMU_SC(femu_rw(c, NVME_CMD_WRITE, lpn * 8, buf)),
                        ==, NVME_SUCCESS);
    }
}

void femu_test_precon(void *obj, void *data, QGuestAllocator *alloc)
{
    const FemuPreconCase *k = data;
    QOSState *qs = qtest_pc_boot(
        "-machine pc -nodefaults "
        "-device femu,id=ref,addr=5," FEMU_PRECON_GEOM "%s "
        "-device femu,id=pre,addr=6," FEMU_PRECON_GEOM "%s,"
        "precon_fill_pct=%u,precon_overwrite_pct=%u,precon_pattern=%s,"
        "precon_seed=%" PRIu64 "%s",
        k->opts, k->opts, k->fill, k->overwrite, k->seq ? "seq" : "rand",
        k->seed, k->brk ? ",x-precon-break=1" : "");
    QTestState *qts = qs->qts;
    QPCIDevice *rdev = qpci_device_find(qs->pcibus, QPCI_DEVFN(5, 0));
    QPCIDevice *pdev = qpci_device_find(qs->pcibus, QPCI_DEVFN(6, 0));
    FemuCtrlState rc = { 0 };
    FemuCtrlState pc = { 0 };
    uint64_t buf = guest_alloc(&qs->alloc, FEMU_DATA_SIZE);
    uint64_t r0[FEMU_PRECON_CTRS];
    uint64_t r1[FEMU_PRECON_CTRS];
    uint64_t p0[FEMU_PRECON_CTRS];
    uint64_t p1[FEMU_PRECON_CTRS];
    QDict *info;
    double waf;
    PreconPlan plan;
    uint64_t lpn;
    uint64_t skip;

    qtest_memset(qts, buf, 0, FEMU_DATA_SIZE);
    /* query-femu answers only for an enabled controller */
    femu_enable(&rc, rdev, &qs->alloc);
    femu_create_io_queues(&rc);
    femu_enable(&pc, pdev, &qs->alloc);
    femu_create_io_queues(&pc);
    precon_plan_init(&plan, FEMU_PRECON_PAGES, k->fill, k->overwrite, k->seq,
                     k->seed);
    skip = k->short_ref ? 1 : 0;
    while (precon_plan_total(&plan) - plan.done > skip &&
           precon_plan_next(&plan, &lpn)) {
        g_assert_cmpint(FEMU_SC(femu_rw(&rc, NVME_CMD_WRITE, lpn * 8, buf)),
                        ==, NVME_SUCCESS);
    }
    if (k->flush) {
        g_assert_cmpint(FEMU_SC(femu_rw(&rc, NVME_CMD_FLUSH, 0, buf)), ==,
                        NVME_SUCCESS);
    }

    if (k->brk) {
        /* the control took out passes that would have run */
        QDict *rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                               "'path':'/machine/peripheral/pre',"
                               "'property':'x-precon-break'}}");

        g_test_message("precon control: %" PRId64 " passes taken out",
                       qdict_get_int(rsp, "return") - 1);
        g_assert_cmpint(qdict_get_int(rsp, "return"), >, 1);
        qobject_unref(rsp);
    }
    if (k->brk || k->short_ref) {
        /* the control: the check sees the wrong state */
        g_assert_cmpint(femu_precon_diff(qts, "control"), >, 0);
        goto out;
    }
    g_assert_cmpint(femu_precon_diff(qts, "after the fill"), ==, 0);

    /* pre counts no host traffic, keeps the wear, reports the run */
    femu_precon_ctrs(qts, "ref", r0, &info, &waf);
    g_assert_null(info);
    femu_precon_ctrs(qts, "pre", p0, &info, NULL);
    g_assert_nonnull(info);
    for (int i = 0; i < FEMU_PRECON_CTRS - 1; i++) {
        g_assert_cmpuint(p0[i], ==, 0);
    }
    g_assert_cmpuint(p0[6], ==, r0[6]);
    g_assert_cmpuint(r0[6], >, 0);
    g_assert_cmpuint(qdict_get_int(info, "fill-pages"), ==, plan.fill);
    g_assert_cmpuint(qdict_get_int(info, "overwrite-pages"), ==,
                     plan.overwrite);
    g_assert_cmpuint(plan.fill + plan.overwrite, ==, r0[0]);
    g_assert_cmpuint(qdict_get_int(info, "nand-write-pages"), ==, r0[1]);
    g_assert_cmpuint(qdict_get_int(info, "gc-write-pages"), ==, r0[2]);
    g_assert_cmpuint(qdict_get_int(info, "map-write-pages"), ==, r0[3]);
    g_assert_cmpuint(qdict_get_int(info, "pad-write-pages"), ==, r0[4]);
    g_assert_cmpuint(qdict_get_int(info, "parity-write-pages"), ==, r0[5]);
    g_assert_cmpuint(qdict_get_int(info, "block-erases"), ==, r0[6]);
    g_assert_cmpuint(r0[2], >, 0);
    g_assert_cmpfloat_with_epsilon(qdict_get_double(info, "waf"), waf,
                                   0.000001);
    qobject_unref(info);

    /* the same workload after: the same counter changes and state */
    femu_precon_follow(&rc, buf);
    femu_precon_follow(&pc, buf);
    femu_precon_ctrs(qts, "ref", r1, NULL, NULL);
    femu_precon_ctrs(qts, "pre", p1, NULL, NULL);
    for (int i = 0; i < FEMU_PRECON_CTRS; i++) {
        g_test_message("precon follow-up %s: ref %" PRIu64 " pre %" PRIu64,
                       femu_precon_ctr_names[i], r1[i] - r0[i],
                       p1[i] - p0[i]);
        g_assert_cmpuint(r1[i] - r0[i], ==, p1[i] - p0[i]);
    }
    g_assert_cmpuint(p1[2], >, 0);
    g_assert_cmpint(femu_precon_diff(qts, "after the follow-up"), ==, 0);

out:
    femu_disable(&pc);
    femu_queue_free(&pc, &pc.io);
    femu_disable(&rc);
    femu_queue_free(&rc, &rc.io);
    guest_free(&qs->alloc, buf);
    g_free(rdev);
    g_free(pdev);
    qtest_pc_shutdown(qs);
}

/*
 * persist_ftl: boot 1 preconditions and quits, which saves the FTL. Boot
 * 2 with the same file loads it: no precondition runs, and the map, the
 * pages and the blocks are the saved ones. A load rebuilds the lists and
 * the victim heap, so their order is not compared.
 */
void femu_test_precon_persist(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    g_autofree char *dir = g_dir_make_tmp("femu-precon-XXXXXX", NULL);
    g_autofree char *path = g_build_filename(dir, "data", NULL);
    g_autofree char *lock = g_strconcat(path, ".lock", NULL);
    g_autofree char *saved = NULL;

    for (int run = 1; run <= 2; run++) {
        QOSState *qs = qtest_pc_boot(
            "-machine pc -nodefaults -device femu,id=pd,addr=5,"
            FEMU_PRECON_GEOM ",persist_ftl=on,persist_file=%s,"
            "precon_fill_pct=90,precon_overwrite_pct=200,precon_seed=3",
            path);
        QTestState *qts = qs->qts;
        QPCIDevice *pdev = qpci_device_find(qs->pcibus, QPCI_DEVFN(5, 0));
        FemuCtrlState c = { 0 };
        QDict *rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                               "'path':'/machine/peripheral/pd',"
                               "'property':'x-ftl-state'}}");
        QDict *info;
        uint64_t v[FEMU_PRECON_CTRS];

        g_assert_true(qdict_haskey(rsp, "return"));
        femu_enable(&c, pdev, &qs->alloc);
        femu_precon_ctrs(qts, "pd", v, &info, NULL);
        if (run == 1) {
            /* the map, page and block hashes: 3 x 16 digits and 2 spaces */
            saved = g_strndup(qdict_get_str(rsp, "return"), 50);
            g_assert_nonnull(info);
            qobject_unref(info);
            femu_disable(&c);
            g_free(pdev);
            qtest_qmp_send(qts, "{'execute':'quit'}");
            qtest_set_expected_status(qts, 0);
            qtest_wait_qemu(qts);
        } else {
            g_assert_null(info);
            g_assert_cmpint(strncmp(qdict_get_str(rsp, "return"), saved, 50),
                            ==, 0);
            femu_disable(&c);
            g_free(pdev);
        }
        qobject_unref(rsp);
        qtest_pc_shutdown(qs);
    }
    unlink(lock);
    unlink(path);
    rmdir(dir);
}
/* the byte of rber_retry_reads */
#define FEMU_PA_RETRY_OFF   296

#define FEMU_PA_WEAR \
    "devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=4," \
    "blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,blk_pe_limit=30," \
    "blk_pe_spread=60,blk_pe_seed=3,spare_lines=8,eol_read_only=off," \
    "wl_spread=8,read_reclaim_limit=6"
#define FEMU_PA_EOL \
    "devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=4," \
    "blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,blk_pe_limit=8," \
    "spare_lines=8,mdts=2"
#define FEMU_PA_RBER \
    "devsz_mb=4,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16," \
    "blks_per_pl=40,pls_per_lun=1,luns_per_ch=1,nchs=2,rber_ppb=2000000," \
    "rber_pe_double=1,rber_read_double=20"

/* the media state that a restart must keep, as one text */
static char *femu_pa_state(FemuPa *p, int nblocks)
{
    g_autofree char *lines = femu_ftl_dump(p->qts, "lines", 40);
    g_autofree char *blocks = femu_ftl_dump(p->qts, "blocks", nblocks);
    GString *s = g_string_new(NULL);
    uint8_t page[512];
    QDict *rsp;
    QDict *ns = femu_query_ns(p->qts, "'path':'/machine/peripheral/pd'",
                              &rsp);

    /* the read-only bit of the FTL thread, apart from the admission one */
    if (qdict_haskey(ns, "end-of-life")) {
        g_autoptr(GString) eol = qobject_to_json(qdict_get(ns, "end-of-life"));

        g_string_append_printf(s, "eol %s\n", eol->str);
    }
    qobject_unref(rsp);

    g_assert_cmpint(FEMU_SC(femu_get_log(&p->c, FEMU_LOG_FEMU_STATS, p->log,
                                         512, 0)), ==, NVME_SUCCESS);
    qtest_memread(p->qts, p->log, page, 512);
    g_string_append_printf(s, "lines %s\nblocks %s\nstats ", lines, blocks);
    for (int i = 0; i < 512; i++) {
        g_string_append_printf(s, "%02x", page[i]);
    }
    g_assert_cmpint(FEMU_SC(femu_get_log(&p->c, NVME_LOG_SMART_INFO, p->log,
                                         512, 0)), ==, NVME_SUCCESS);
    qtest_memread(p->qts, p->log, page, 512);
    /* warning, spare, used and media errors: not the session counters */
    g_string_append_printf(s, "\nsmart %02x %u %u %" PRIu64 "\ntrace %s",
                           page[0], page[3], page[5], ldq_le_p(page + 160),
                           p->trace->str);
    return g_string_free(s, false);
}

static void femu_pa_read(FemuPa *p, int lpn)
{
    uint16_t sc = FEMU_SC(femu_rw(&p->c, NVME_CMD_READ, lpn * 8, p->buf));

    g_assert_true(sc == NVME_SUCCESS || sc == NVME_UNRECOVERED_READ);
    g_string_append_c(p->trace, sc == NVME_SUCCESS ? '.' : 'U');
}

static void femu_pa_segment(FemuPa *p, const char *kind, int seg)
{
    if (!strcmp(kind, "wear")) {
        femu_wear_workload(&p->c, p->buf, p->list);
        /* reads past read_reclaim_limit queue a rewrite for the next write */
        for (int i = 0; seg == 0 && i < 7; i++) {
            femu_pa_read(p, 3);
        }
    } else if (!strcmp(kind, "eol")) {
        int ok = 0;

        for (int i = 0; i < (seg ? 50000 : 256); i++) {
            uint16_t sc = FEMU_SC(femu_rw(&p->c, NVME_CMD_WRITE,
                                          (i % 256) * 8, p->buf));

            if (sc == NVME_WRITE_TO_RO) {
                break;
            }
            g_assert_cmphex(sc, ==, NVME_SUCCESS);
            ok++;
        }
        g_string_append_printf(p->trace, "w%d ", ok);
    } else {
        for (int r = 0; seg == 0 && r < 2; r++) {
            for (int lpn = 0; lpn < 1024; lpn++) {
                g_assert_cmpint(FEMU_SC(femu_rw(&p->c, NVME_CMD_WRITE,
                                                lpn * 8, p->buf)), ==,
                                NVME_SUCCESS);
            }
        }
        for (int r = 0; r < 2; r++) {
            for (int lpn = 0; lpn < 64; lpn++) {
                femu_pa_read(p, lpn);
            }
        }
    }
}

/*
 * persist-aging: the same two workload segments run once in one process
 * and once with a persist_ftl restart before the second segment and after
 * it. The two runs must end in the same media state: lines, blocks, the
 * FEMU statistics log, SMART spare, wear and media errors, and what each
 * read returned. @data names the aging models:
 *   "wear": erase limits with spread, spare lines, levelling, and a read
 *           reclaim queued at the restart;
 *   "eol":  the reserve held at the first restart, read-only media at the
 *           second; a write is then refused and a read succeeds;
 *   "rber": the RBER generator, its counters and the read counts; some
 *           reads need a retry.
 */
void femu_test_persist_aging(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    const char *kind = data;
    const char *opts = !strcmp(kind, "wear") ? FEMU_PA_WEAR :
                       !strcmp(kind, "eol") ? FEMU_PA_EOL : FEMU_PA_RBER;
    int nblocks = !strcmp(kind, "rber") ? 80 : 160;
    g_autofree char *dir = g_dir_make_tmp("femu-paging-XXXXXX", NULL);
    char *state[2];

    for (int split = 0; split < 2; split++) {
        g_autofree char *path = g_strdup_printf("%s/data%d", dir, split);
        g_autofree char *lock = g_strconcat(path, ".lock", NULL);
        FemuPa p = { .trace = g_string_new(NULL) };

        femu_pa_boot(&p, opts, path);
        for (int seg = 0; seg < 2; seg++) {
            if (split && seg) {
                femu_pa_end(&p, true);
                femu_pa_boot(&p, opts, path);
            }
            femu_pa_segment(&p, kind, seg);
        }
        if (split) {
            femu_pa_end(&p, true);
            femu_pa_boot(&p, opts, path);
        }
        state[split] = femu_pa_state(&p, nblocks);
        g_test_message("persist-aging %s %s: %s", kind,
                       split ? "split" : "straight", p.trace->str);
        if (!strcmp(kind, "eol")) {
            g_assert_cmphex(FEMU_SC(femu_rw(&p.c, NVME_CMD_WRITE, 0, p.buf)),
                            ==, NVME_WRITE_TO_RO);
            g_assert_cmphex(FEMU_SC(femu_rw(&p.c, NVME_CMD_READ, 0, p.buf)),
                            ==, NVME_SUCCESS);
            g_assert_nonnull(strstr(state[split], "\"retired\""));
        } else if (!strcmp(kind, "wear")) {
            g_assert_nonnull(strstr(state[split], "\"retired\""));
        } else {
            uint8_t page[512];

            /* some reads needed a retry: the generator decided them */
            g_assert_cmpint(FEMU_SC(femu_get_log(&p.c, FEMU_LOG_FEMU_STATS,
                                                 p.log, 512, 0)), ==,
                            NVME_SUCCESS);
            qtest_memread(p.qts, p.log, page, 512);
            g_assert_cmpuint(ldq_le_p(page + FEMU_PA_RETRY_OFF), >, 0);
        }
        femu_pa_end(&p, false);
        g_string_free(p.trace, true);
        unlink(lock);
        unlink(path);
    }
    g_assert_cmpstr(state[1], ==, state[0]);
    g_free(state[0]);
    g_free(state[1]);
    rmdir(dir);
}

/* device_add of the aging device "pa" at slot 6; its error text or NULL */
static char *femu_pa_add(QTestState *qts, const char *path, const char *more)
{
    g_autofree char *json = g_strdup_printf(
        "{'driver':'femu','id':'pa','addr':'6','devsz_mb':2,'femu_mode':1,"
        "'secsz':512,'secs_per_pg':8,'pgs_per_blk':16,'blks_per_pl':64,"
        "'pls_per_lun':1,'luns_per_ch':1,'nchs':2,'persist_ftl':true,"
        "'persist_file':'%s'%s}", path, more);
    QObject *args = qobject_from_json(json, &error_abort);
    QDict *rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':%p}",
                           args);
    char *err = NULL;

    if (qdict_haskey(rsp, "error")) {
        err = g_strdup(qdict_get_str(qdict_get_qdict(rsp, "error"), "desc"));
    }
    qobject_unref(rsp);
    return err;
}

/* write @n pages to "pd" with @opts and quit, which saves @path */
static void femu_pa_file(const char *opts, const char *path, int n,
                         bool schema1)
{
    QOSState *qs = qtest_pc_boot("-machine pc -nodefaults -device femu,"
                                 "id=pd,addr=5,%s,persist_file=%s", opts,
                                 path);
    QPCIDevice *pdev = qpci_device_find(qs->pcibus, QPCI_DEVFN(5, 0));
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(&qs->alloc, 4096);

    femu_enable(&c, pdev, &qs->alloc);
    femu_create_io_queues(&c);
    for (int i = 0; i < n; i++) {
        g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, i * 8, buf)), ==,
                        NVME_SUCCESS);
    }
    if (schema1) {
        QDict *rsp = qtest_qmp(qs->qts, "{'execute':'qom-set','arguments':{"
                               "'path':'/machine/peripheral/pd',"
                               "'property':'x-persist-schema','value':1}}");

        g_assert_false(qdict_haskey(rsp, "error"));
        qobject_unref(rsp);
    }
    femu_disable(&c);
    femu_queue_free(&c, &c.io);
    qtest_qmp_send(qs->qts, "{'execute':'quit'}");
    qtest_set_expected_status(qs->qts, 0);
    qtest_wait_qemu(qs->qts);
    guest_free(&qs->alloc, buf);
    g_free(pdev);
    qtest_pc_shutdown(qs);
}

/* set aging value @idx of the one FTL section of @src to @v, in @dst */
static void femu_pa_patch(const char *src, const char *dst, int idx,
                          int64_t v, bool add)
{
    g_autofree char *b = NULL;
    gsize len;
    uint8_t *sec = NULL;
    uint8_t *val;

    g_assert_true(g_file_get_contents(src, &b, &len, NULL));
    for (gsize i = 0; i + 8 <= len; i++) {
        if (!memcmp(b + i, "FEMUFTL1", 8)) {
            sec = (uint8_t *)b + i;
        }
    }
    g_assert_nonnull(sec);
    /* 23 aging values of 8 bytes, then the CRC */
    val = (uint8_t *)b + len - 4 - (23 - idx) * 8;
    stq_le_p(val, add ? ldq_le_p(val) + v : (uint64_t)v);
    stl_le_p(b + len - 4, crc32c(0xffffffff, sec, (uint8_t *)b + len - 4 -
                                 sec));
    g_assert_true(g_file_set_contents(dst, b, len, NULL));
}

/*
 * Copy FTL file @src to @dst with one record changed, and the CRC made
 * good again. @kind 'l': the first line in state @idx (8: full or
 * victim); @off is the byte in its 40-byte record. 'b': block @idx;
 * @off is the byte in it. @v goes in @size bytes.
 */
static void femu_pa_patch_rec(const char *src, const char *dst, char kind,
                              int idx, int off, int size, uint64_t v)
{
    g_autofree char *b = NULL;
    gsize len;
    uint8_t *sec = NULL;
    uint8_t *rec;
    uint64_t pgs, blks, lines;
    uint32_t schema;
    gsize blk_sz, pls;

    g_assert_true(g_file_get_contents(src, &b, &len, NULL));
    for (gsize i = 0; i + 8 <= len; i++) {
        if (!memcmp(b + i, "FEMUFTL1", 8)) {
            sec = (uint8_t *)b + i;
        }
    }
    g_assert_nonnull(sec);
    schema = ldl_le_p(sec + 8);
    pgs = ldq_le_p(sec + 24);
    blks = ldq_le_p(sec + 32);
    lines = ldq_le_p(sec + 40);
    blk_sz = schema > 1 ? 32 : 24;
    /* each plane holds a block of every line */
    pls = schema > 1 ? blks / lines : 0;
    /* header, maptbl, rmap, page status */
    rec = sec + 56 + 8 * pgs + 8 * pgs + pgs;
    if (kind == 'b') {
        g_assert_cmpuint(idx, <, blks);
        rec += idx * blk_sz;
    } else {
        rec += blks * blk_sz + 4 * pls;
        int i;

        for (i = 0; i < lines; i++) {
            uint8_t st = rec[i * 40 + 33];

            if (st == idx || (idx == 8 && (st == 1 || st == 2))) {
                break;
            }
        }
        g_assert_cmpint(i, <, lines);
        rec += i * 40;
    }
    for (int k = 0; k < size; k++) {
        rec[off + k] = v >> (8 * k);
    }
    stl_le_p(b + len - 4, crc32c(0xffffffff, sec, (uint8_t *)b + len - 4 -
                                 sec));
    g_assert_true(g_file_set_contents(dst, b, len, NULL));
}

/* the device of persist-aging-files: room for the end-of-life reserve */
#define FEMU_PA_FILE \
    "devsz_mb=2,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16," \
    "blks_per_pl=64,pls_per_lun=1,luns_per_ch=1,nchs=2"

/*
 * persist-aging-files: what an aging device takes from a file.
 *   - The aging properties and those that change what the state means
 *     are in the digest: each change below is refused.
 *   - A schema 1 file (x-persist-schema) loads into a device without an
 *     aging model, and is refused by one.
 *   - A file without FTL state is refused by an aging device.
 *   - Aging values with a good CRC are still checked.
 */
void femu_test_persist_aging_files(void *obj, void *data,
                                   QGuestAllocator *alloc)
{
    g_autofree char *dir = g_dir_make_tmp("femu-pafile-XXXXXX", NULL);
    g_autofree char *fa = g_build_filename(dir, "aging", NULL);
    g_autofree char *f1 = g_build_filename(dir, "schema1", NULL);
    g_autofree char *fd = g_build_filename(dir, "dataonly", NULL);
    g_autofree char *fc = g_build_filename(dir, "corrupt", NULL);
    g_autofree char *fc1 = g_build_filename(dir, "corrupt1", NULL);
    g_autofree char *fe = g_build_filename(dir, "early", NULL);
    static const char *const aging = ",'blk_pe_limit':100,'rber_ppb':1";
    static const char *const early = ",'blk_pe_limit':100,'rber_ppb':1,"
                                     "'blk_early_ppm':10,'blk_early_pe':3";
    static const char *const early_changes[] = {
        ",'blk_pe_limit':100,'rber_ppb':1,'blk_early_ppm':20,'blk_early_pe':3",
        ",'blk_pe_limit':100,'rber_ppb':1,'blk_early_ppm':10,'blk_early_pe':4",
    };
    static const char *const changes[] = {
        ",'eol_read_only':false", ",'mdts':3", ",'age_scale':2",
        ",'ecc_hard_bits':30", ",'rber_timing_only':true",
        ",'rber_seed':7", ",'blk_pe_spread':10", ",'nlbaf':6",
        ",'blk_early_ppm':10,'blk_early_pe':3",
    };
    static const struct {
        int idx;
        int64_t v;
        bool add;
        const char *msg;
    } bad[] = {
        { 19, 2, false, "end-of-life" },        /* media_ro */
        { 4, 1, false, "end-of-life" },         /* admitted pages */
        { 21, 64, false, "rewrite" },           /* reclaim line */
        { 22, 3, false, "rewrite" },            /* reclaim reason */
        { 3, 1, true, "wear total" },           /* wear_pe_total */
        { 18, 1, false, "wear total" },         /* retired lines */
        { 0, 1, true, "wear total" },           /* grown bad blocks */
        { 5, 1 << 20, false, "levelling" },     /* wl_credit */
        { 22, 1, false, "rewrite" },            /* age reason, none queued */
        { 22, 2, false, "rewrite" },            /* open-block reason */
    };
    QOSState *qs;
    char *err;

    femu_pa_file(FEMU_PA_FILE ",persist_ftl=on,blk_pe_limit=100,rber_ppb=1",
                 fa, 64, false);
    femu_pa_file(FEMU_PA_FILE ",persist_ftl=on", f1, 64, true);
    femu_pa_file(FEMU_PA_FILE ",persist_ftl=on,blk_pe_limit=100,rber_ppb=1,"
                 "blk_early_ppm=10,blk_early_pe=3", fe, 64, false);
    /* a free line in the reserve state, which schema 1 does not have */
    femu_pa_patch_rec(f1, fc1, 'l', 0, 33, 1, 5);
    femu_pa_file(FEMU_PA_FILE, fd, 64, false);

    qs = qtest_pc_boot("-machine pc -nodefaults");
    /* the control: the same properties load the file */
    err = femu_pa_add(qs->qts, fa, aging);
    g_assert_null(err);
    qpci_unplug_acpi_device_test(qs->qts, "pa", 6);
    for (size_t i = 0; i < ARRAY_SIZE(changes); i++) {
        g_autofree char *more = g_strconcat(aging, changes[i], NULL);

        err = femu_pa_add(qs->qts, fa, more);
        g_test_message("%s: %s", changes[i], err ? err : "loaded");
        g_assert_nonnull(err);
        g_assert_nonnull(strstr(err, "other FTL properties"));
        g_free(err);
    }
    /* each early-life property is in the digest on its own */
    err = femu_pa_add(qs->qts, fe, early);
    g_assert_null(err);
    qpci_unplug_acpi_device_test(qs->qts, "pa", 6);
    for (size_t i = 0; i < ARRAY_SIZE(early_changes); i++) {
        err = femu_pa_add(qs->qts, fe, early_changes[i]);
        g_test_message("%s: %s", early_changes[i], err ? err : "loaded");
        g_assert_nonnull(err);
        g_assert_nonnull(strstr(err, "other FTL properties"));
        g_free(err);
    }
    /* the FTL section has no record of a failed block */
    {
        g_autofree char *more = g_strconcat(aging, ",'erase_fail_ppm':10",
                                            NULL);

        err = femu_pa_add(qs->qts, fa, more);
        g_assert_nonnull(err);
        g_assert_nonnull(strstr(err, "persist_ftl is not supported with "
                                "erase_fail_ppm"));
        g_free(err);
    }
    /*
     * schema 1: refused with aging, then loaded without it (that unplug
     * saves the file again, in schema 2)
     */
    err = femu_pa_add(qs->qts, f1, aging);
    g_test_message("schema 1, aging: %s", err ? err : "loaded");
    g_assert_nonnull(err);
    g_assert_nonnull(strstr(err, "no aging state"));
    g_free(err);
    err = femu_pa_add(qs->qts, f1, "");
    g_assert_null(err);
    qpci_unplug_acpi_device_test(qs->qts, "pa", 6);
    /* data only: the aging history would start again */
    err = femu_pa_add(qs->qts, fd, aging);
    g_test_message("data only, aging: %s", err ? err : "loaded");
    g_assert_nonnull(err);
    g_assert_nonnull(strstr(err, "no FTL state"));
    g_free(err);
    for (size_t i = 0; i < ARRAY_SIZE(bad); i++) {
        femu_pa_patch(fa, fc, bad[i].idx, bad[i].v, bad[i].add);
        err = femu_pa_add(qs->qts, fc, aging);
        g_test_message("aging value %d: %s", bad[i].idx,
                       err ? err : "loaded");
        g_assert_nonnull(err);
        g_assert_nonnull(strstr(err, bad[i].msg));
        g_free(err);
        unlink(fc);
    }
    /* records the totals agree with, which the state rules refuse */
    {
        static const struct {
            char kind;
            int idx, off, size;
            uint64_t v;
            const char *msg;
        } rec[] = {
            /* a full or victim line without its close time */
            { 'l', 8, 32, 1, 0, "no close time" },
            /* a free line retired, with no worn block in it */
            { 'l', 0, 33, 1, 6, "no worn block" },
        };

        for (size_t i = 0; i < ARRAY_SIZE(rec); i++) {
            femu_pa_patch_rec(fa, fc, rec[i].kind, rec[i].idx, rec[i].off,
                              rec[i].size, rec[i].v);
            err = femu_pa_add(qs->qts, fc, aging);
            g_test_message("record %zu: %s", i, err ? err : "loaded");
            g_assert_nonnull(err);
            g_assert_nonnull(strstr(err, rec[i].msg));
            g_free(err);
            unlink(fc);
        }
        /* a block worn and kept overworn: eol_read_only retires it */
        femu_pa_patch_rec(fa, fc, 'b', 0, 0, 4, 100);
        femu_pa_patch_rec(fc, fc, 'b', 0, 28, 1, 1);
        err = femu_pa_add(qs->qts, fc, aging);
        g_assert_nonnull(err);
        g_assert_nonnull(strstr(err, "overworn block with eol_read_only"));
        g_free(err);
        unlink(fc);
        err = femu_pa_add(qs->qts, fc1, "");
        g_test_message("schema 1, reserve state: %s", err ? err : "loaded");
        g_assert_nonnull(err);
        g_assert_nonnull(strstr(err, "line state is out of range"));
        g_free(err);
        unlink(fc1);
    }
    qtest_pc_shutdown(qs);
    {
        const char *const files[] = { fa, f1, fd, fc, fc1, fe };

        for (size_t i = 0; i < ARRAY_SIZE(files); i++) {
            g_autofree char *lock = g_strconcat(files[i], ".lock", NULL);

            unlink(files[i]);
            unlink(lock);
        }
    }
    rmdir(dir);
}

/* hot-add bbssd device pd at slot 5 on a 384-page FTL, with @extra */
static void femu_ckpt_add_ftl(QTestState *qts, const char *extra)
{
    g_autofree char *args = g_strdup_printf(
        "{'driver':'femu','id':'pd','addr':'5','femu_mode':1,'devsz_mb':1,"
        "'secsz':512,'secs_per_pg':8,'pgs_per_blk':8,'blks_per_pl':12,"
        "'pls_per_lun':1,'luns_per_ch':2,'nchs':2,'persist_ftl':true%s}",
        extra);
    QDict *rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':%p}",
                           qobject_from_json(args, &error_abort));

    if (qdict_haskey(rsp, "error")) {
        g_test_message("device_add pd: %s", qdict_get_str(
                       qdict_get_qdict(rsp, "error"), "desc"));
    }
    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
}

/*
 * persist_load_only with persist_ftl: a checkpoint E of the FTL after one
 * write. Two readers in turn start with its lines and counters. Each
 * overwrites page 2: the valid pages stay as they were only if the
 * mapping of page 2 came back. The second starts as the first did, since
 * no reader saves E.
 */
void femu_test_checkpoint_reuse_ftl(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    g_autofree char *dir = g_dir_make_tmp("femu-reuse-ftl-XXXXXX", NULL);
    g_autofree char *d = g_build_filename(dir, "d", NULL);
    g_autofree char *e = g_build_filename(dir, "e", NULL);
    g_autofree char *lock_d = g_strconcat(d, ".lock", NULL);
    g_autofree char *lock_e = g_strconcat(e, ".lock", NULL);
    g_autofree char *wd = g_strdup_printf(",'persist_file':'%s'", d);
    g_autofree char *re = g_strdup_printf(",'persist_file':'%s',"
                                          "'persist_load_only':true", e);
    g_autofree char *ctr0 = NULL;
    g_autofree char *lines0 = NULL;
    uint64_t buf = guest_alloc(alloc, 4096);
    uint64_t vpc0;
    FemuCtrlState c = { 0 };
    QPCIDevice *pdev;

    femu_ckpt_add_ftl(qts, wd);
    pdev = qpci_device_find(femu->dev.bus, QPCI_DEVFN(5, 0));
    femu_enable(&c, pdev, alloc);
    femu_create_io_queues(&c);
    femu_ns_page(&c, buf, 1, 2, 0x51, true);
    ctr0 = femu_ftl_counters(qts);
    lines0 = femu_ftl_dump(qts, "lines", 40);
    vpc0 = femu_ftl_vpc_sum(qts);
    g_assert_cmpuint(vpc0, >, 0);
    g_assert_null(femu_save_data(qts, "pd", e));
    femu_disable(&c);
    femu_queue_free(&c, &c.io);
    qpci_unplug_acpi_device_test(qts, "pd", 5);
    g_free(pdev);

    for (int i = 0; i < 2; i++) {
        g_autofree char *ctr = NULL;
        g_autofree char *lines = NULL;
        g_autofree char *after = NULL;

        memset(&c, 0, sizeof(c));
        femu_ckpt_add_ftl(qts, re);
        pdev = qpci_device_find(femu->dev.bus, QPCI_DEVFN(5, 0));
        /* query-femu needs an enabled controller */
        femu_enable(&c, pdev, alloc);
        femu_create_io_queues(&c);
        ctr = femu_ftl_counters(qts);
        lines = femu_ftl_dump(qts, "lines", 40);
        g_assert_cmpstr(ctr, ==, ctr0);
        g_assert_cmpstr(lines, ==, lines0);
        g_assert_cmpuint(femu_ftl_vpc_sum(qts), ==, vpc0);
        femu_ns_page(&c, buf, 1, 2, 0x51, false);
        femu_ns_page(&c, buf, 1, 2, 0x61, true);
        g_assert_cmpuint(femu_ftl_vpc_sum(qts), ==, vpc0);
        after = femu_ftl_counters(qts);
        g_assert_cmpstr(after, !=, ctr0);
        femu_disable(&c);
        femu_queue_free(&c, &c.io);
        qpci_unplug_acpi_device_test(qts, "pd", 5);
        g_free(pdev);
    }
    guest_free(alloc, buf);
    unlink(lock_d);
    unlink(lock_e);
    unlink(d);
    unlink(e);
    rmdir(dir);
}

/* femu-save-data of device pd with background=true; an error or NULL */
static char *femu_save_data_bg(QTestState *qts, const char *file)
{
    QDict *rsp = qtest_qmp(qts, "{'execute':'femu-save-data','arguments':"
                           "{'path':'/machine/peripheral/pd','file':%s,"
                           "'background':true}}", file);
    char *err = NULL;

    if (qdict_haskey(rsp, "error")) {
        err = g_strdup(qdict_get_str(qdict_get_qdict(rsp, "error"), "desc"));
        g_test_message("femu-save-data background: %s", err);
    }
    qobject_unref(rsp);
    return err;
}

static void femu_save_hold(QTestState *qts, bool hold)
{
    qtest_qmp_assert_success(qts, "{'execute':'qom-set','arguments':{"
                             "'path':'/machine/peripheral/pd',"
                             "'property':'x-save-hold','value':%i}}", hold);
}

/* the LSI generation, and the log length in @len */
static uint16_t femu_save_lsi(FemuCtrlState *c, uint64_t buf, uint32_t *len)
{
    QTestState *qts = c->pdev->bus->qts;

    g_assert_cmphex(femu_lsi_read(c, buf, 4096, 0, false), ==, NVME_SUCCESS);
    *len = qtest_readl(qts, buf);
    return qtest_readw(qts, buf + 14);
}

static void femu_save_fails(char *err, const char *want)
{
    g_assert_nonnull(err);
    g_assert_nonnull(strstr(err, want));
    g_free(err);
}

/*
 * femu-save-data background=true copies the state with the I/O paused and
 * writes it in a thread. x-save-hold keeps the writer after the copy, so
 * the test changes the device in between:
 *   before:  A at pages 0 and 1, LBA 24 and 32 uncorrectable, LSI read
 *   held:    B at pages 0 and 3 (LBA 24), page 1 deallocated, LBA 48
 *            uncorrectable and LSI read; I/O and query-femu still work
 * The checkpoint must hold the state before: counters (read first), LSI
 * generation and length, data, allocation (DULBE) and uncorrectable blocks.
 * Then a held save and an unplug: the unplug lets the writer finish.
 */
void femu_test_save_background(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    g_autofree char *tmp = g_dir_make_tmp("femu-save-bg-XXXXXX", NULL);
    /* the event names the resolved file */
    g_autofree char *dir = realpath(tmp, NULL);
    g_autofree char *d = g_build_filename(dir, "d", NULL);
    g_autofree char *k = g_build_filename(dir, "k", NULL);
    g_autofree char *k2 = g_build_filename(dir, "k2", NULL);
    g_autofree char *wd = g_strdup_printf(",'persist_file':'%s','oncs':415",
                                          d);
    g_autofree char *rk = g_strdup_printf(",'persist_file':'%s',"
                                          "'persist_load_only':true,"
                                          "'oncs':415", k);
    g_autofree char *tk = g_strdup_printf(",'io_trace':'%s'", k);
    g_autofree char *pk = g_strdup_printf(",'pel_file':'%s'", k);
    g_autofree char *fk = g_strdup_printf(",'femu_mode':1,'persist_file':"
                                          "'%s'", k);
    g_autofree char *ctr0 = NULL;
    g_autofree char *ctr = NULL;
    g_autofree uint8_t *lsi0 = NULL;
    g_autofree uint8_t *lsi = NULL;
    uint64_t buf = guest_alloc(alloc, 8192);
    FemuCtrlState c = { 0 };
    QPCIDevice *pdev;
    QDict *ev;
    QDict *evd;
    uint16_t gen;
    uint16_t gen0;
    uint32_t len;
    uint32_t len0;

    femu_ckpt_add_ftl(qts, wd);
    pdev = qpci_device_find(femu->dev.bus, QPCI_DEVFN(5, 0));
    femu_enable(&c, pdev, alloc);
    femu_create_io_queues(&c);
    femu_ns_page(&c, buf, 1, 0, 0x41, true);
    femu_ns_page(&c, buf, 1, 1, 0x41, true);
    g_assert_cmphex(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE_UNCOR, 24, buf)), ==,
                    NVME_SUCCESS);
    femu_save_lsi(&c, buf, &len);
    g_assert_cmphex(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE_UNCOR, 32, buf)), ==,
                    NVME_SUCCESS);
    gen0 = femu_save_lsi(&c, buf, &len0);
    g_assert_cmpuint(gen0, >, 1);
    g_assert_cmpuint(len0, <=, 4096);
    lsi0 = g_malloc(len0);
    qtest_memread(qts, buf, lsi0, len0);
    ctr0 = femu_ftl_counters(qts);

    /* admission: the own persist_file is refused, and sends no event */
    femu_save_fails(femu_save_data_bg(qts, d), "own persist_file");
    femu_save_hold(qts, true);
    g_assert_null(femu_save_data_bg(qts, k));

    /* held: the device runs, and k is reserved */
    femu_ns_page(&c, buf, 1, 0, 0x42, true);
    g_assert_cmphex(femu_dealloc_pages(&c, 1, 1, buf), ==, NVME_SUCCESS);
    femu_ns_page(&c, buf, 1, 3, 0x42, true);
    g_assert_cmphex(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE_UNCOR, 48, buf)), ==,
                    NVME_SUCCESS);
    gen = femu_save_lsi(&c, buf, &len);
    g_test_message("LSI generation %u length %u, held %u length %u", gen0,
                   len0, gen, len);
    g_assert_true(gen != gen0 || len != len0);
    ctr = femu_ftl_counters(qts);
    g_assert_cmpstr(ctr, !=, ctr0);
    femu_save_fails(femu_save_data(qts, "pd", k2), "in progress");
    femu_save_fails(femu_save_data_bg(qts, k2), "in progress");
    femu_save_fails(femu_ckpt_try_add(qts, "t", 6, tk), "of a device");
    femu_save_fails(femu_ckpt_try_add(qts, "t", 6, pk), "background");
    femu_save_fails(femu_ckpt_try_add(qts, "t", 6, fk), "in use");

    femu_save_hold(qts, false);
    ev = qtest_qmp_eventwait_ref(qts, "FEMU_SAVE_DATA_DONE");
    evd = qdict_get_qdict(ev, "data");
    g_assert_false(qdict_haskey(evd, "error"));
    g_assert_cmpstr(qdict_get_str(evd, "file"), ==, k);
    g_assert_cmpstr(qdict_get_str(evd, "path"), ==, "/machine/peripheral/pd");
    qobject_unref(ev);
    femu_disable(&c);
    femu_queue_free(&c, &c.io);
    qpci_unplug_acpi_device_test(qts, "pd", 5);
    g_free(pdev);

    /* the checkpoint holds the state at the copy */
    memset(&c, 0, sizeof(c));
    femu_ckpt_add_ftl(qts, rk);
    pdev = qpci_device_find(femu->dev.bus, QPCI_DEVFN(5, 0));
    femu_enable(&c, pdev, alloc);
    femu_create_io_queues(&c);
    g_free(ctr);
    ctr = femu_ftl_counters(qts);
    g_assert_cmpstr(ctr, ==, ctr0);
    gen = femu_save_lsi(&c, buf, &len);
    g_assert_cmpuint(gen, ==, gen0);
    g_assert_cmpuint(len, ==, len0);
    /* the same descriptors: LBA 24 to 39, and not 48 */
    lsi = g_malloc(len);
    qtest_memread(qts, buf, lsi, len);
    g_assert_cmpmem(lsi, len, lsi0, len0);
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_ERROR_RECOVERY, false,
                                             1, 1 << 16, NULL)), ==,
                    NVME_SUCCESS);
    femu_ns_page(&c, buf, 1, 0, 0x41, false);
    femu_ns_page(&c, buf, 1, 1, 0x41, false);
    g_assert_cmphex(FEMU_SC(femu_rw(&c, NVME_CMD_READ, 40, buf)), ==,
                    NVME_DULB);
    g_assert_cmphex(FEMU_SC(femu_rw(&c, NVME_CMD_READ, 24, buf)), ==,
                    NVME_UNRECOVERED_READ);
    femu_disable(&c);
    femu_queue_free(&c, &c.io);
    qpci_unplug_acpi_device_test(qts, "pd", 5);
    g_free(pdev);

    /* an unplug of a device with a held save lets the writer finish */
    memset(&c, 0, sizeof(c));
    femu_ckpt_add_ftl(qts, wd);
    femu_save_hold(qts, true);
    g_assert_null(femu_save_data_bg(qts, k2));
    qpci_unplug_acpi_device_test(qts, "pd", 5);
    g_assert_true(g_file_test(k2, G_FILE_TEST_IS_REGULAR));

    for (int i = 0; i < 3; i++) {
        const char *f = i == 0 ? d : i == 1 ? k : k2;
        g_autofree char *lock = g_strconcat(f, ".lock", NULL);

        unlink(f);
        unlink(lock);
    }
    rmdir(dir);
    guest_free(alloc, buf);
}

/* the FEMU_SAVE_DATA_DONE event of a QEMU with one device; its error */
static char *femu_save_done(QTestState *qts)
{
    QDict *ev = qtest_qmp_eventwait_ref(qts, "FEMU_SAVE_DATA_DONE");
    QDict *d = qdict_get_qdict(ev, "data");
    char *err = qdict_haskey(d, "error") ?
                g_strdup(qdict_get_str(d, "error")) : NULL;

    qobject_unref(ev);
    return err;
}

/*
 * The ends of a background save in a QEMU of its own (NoSSD, no
 * persist_file, so no exit save of the device):
 *   a writer that cannot create its file: the command passes, the event
 *   has an error, and the next save works;
 *   a held save, then quit: QEMU's end lets the writer finish the file.
 */
void femu_test_save_background_end(void *obj, void *data,
                                   QGuestAllocator *alloc)
{
    g_autofree char *tmp = g_dir_make_tmp("femu-save-end-XXXXXX", NULL);
    g_autofree char *dir = realpath(tmp, NULL);
    g_autofree char *ro = g_build_filename(dir, "ro", NULL);
    g_autofree char *f = g_build_filename(ro, "f", NULL);
    g_autofree char *f_lock = g_strconcat(f, ".lock", NULL);
    g_autofree char *g = g_build_filename(dir, "g", NULL);
    g_autofree char *g_lock = g_strconcat(g, ".lock", NULL);
    g_autofree char *h = g_build_filename(dir, "h", NULL);
    g_autofree char *h_lock = g_strconcat(h, ".lock", NULL);
    QTestState *qts = qtest_init("-machine pc -nodefaults -device femu,"
                                 "addr=5,id=q,femu_mode=2,devsz_mb=16");
    g_autofree char *err = NULL;
    struct stat st;
    off_t gsz;
    int fd;

    if (geteuid() != 0) {
        g_assert_cmpint(mkdir(ro, 0755), ==, 0);
        fd = open(f_lock, O_CREAT | O_RDWR, 0644);
        g_assert_cmpint(fd, >=, 0);
        close(fd);
        g_assert_cmpint(chmod(ro, 0555), ==, 0);
        qtest_qmp_assert_success(qts, "{'execute':'femu-save-data',"
                                 "'arguments':{'file':%s,'background':true}}",
                                 f);
        err = femu_save_done(qts);
        g_test_message("writer error: %s", err ? err : "(none)");
        g_assert_nonnull(err);
        g_assert_nonnull(strstr(err, "cannot create"));
        g_assert_false(g_file_test(f, G_FILE_TEST_EXISTS));
        g_assert_cmpint(chmod(ro, 0755), ==, 0);
    } else {
        g_test_message("root: the writer error case is skipped");
    }
    qtest_qmp_assert_success(qts, "{'execute':'femu-save-data','arguments':"
                             "{'file':%s,'background':true}}", g);
    g_free(err);
    err = femu_save_done(qts);
    g_assert_null(err);
    g_assert_cmpint(stat(g, &st), ==, 0);
    g_assert_cmpuint(st.st_size, >, 16 * MiB);
    gsz = st.st_size;

    qtest_qmp_assert_success(qts, "{'execute':'qom-set','arguments':{"
                             "'path':'/machine/peripheral/q',"
                             "'property':'x-save-hold','value':true}}");
    qtest_qmp_assert_success(qts, "{'execute':'femu-save-data','arguments':"
                             "{'file':%s,'background':true}}", h);
    qtest_quit(qts);
    g_assert_cmpint(stat(h, &st), ==, 0);
    g_assert_cmpuint(st.st_size, ==, gsz);

    unlink(f_lock);
    rmdir(ro);
    unlink(g);
    unlink(g_lock);
    unlink(h);
    unlink(h_lock);
    rmdir(dir);
}

void femu_test_pel_file_invalid(void *obj, void *data,
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

void femu_test_pel_events(void *obj, void *data,
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
                        FEMU_UNRECOVERED_READ | NVME_DNR);
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

void femu_test_ns_mgmt_pel(void *obj, void *data,
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

void femu_test_streams_identify(void *obj, void *data,
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

void femu_test_pause_mmio(void *obj, void *data, QGuestAllocator *alloc)
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
void femu_test_cmb_sgl(void *obj, void *data, QGuestAllocator *alloc)
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

void femu_test_streams_config(void *obj, void *data,
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

/*
 * Command lines from the documentation, handed over by
 * hw/femu/scripts/check-doc-examples.py. FEMU_DOC_EXAMPLES names a file of
 * "name<TAB>io,io,...<TAB>QEMU options" lines with one io entry per femu
 * controller, in command-line order: "rw" writes and reads back one block of
 * namespace 1, "kv" stores and retrieves one value, "identify" stops after
 * Identify. A controller whose namespace 1 is not attached is identified
 * only, but every example has to move data through at least one controller
 * unless all its entries are "identify".
 */
#define FEMU_DOC_MAX_CTRLS  16

typedef struct FemuDocCtrls {
    QPCIDevice *dev[FEMU_DOC_MAX_CTRLS];
    int n;
} FemuDocCtrls;

static void femu_doc_collect(QPCIDevice *dev, int devfn, void *data)
{
    FemuDocCtrls *f = data;

    if (qpci_config_readw(dev, PCI_CLASS_DEVICE) == 0x0108 &&
        f->n < FEMU_DOC_MAX_CTRLS) {
        f->dev[f->n++] = dev;
        return;
    }
    g_free(dev);
}

/* one command on the I/O queue against namespace 1; returns the status */
static uint16_t femu_doc_io(FemuCtrlState *c, NvmeCmd *cmd)
{
    uint16_t want = c->cid;
    uint16_t got;
    uint16_t status;

    cmd->nsid = cpu_to_le32(1);
    femu_submit(c, &c->io, cmd);
    status = femu_complete(c, &c->io, &got, NULL);
    g_assert_cmpint(got, ==, want);
    return FEMU_SC(status);
}

/* Identify, then exercise namespace 1; returns whether data moved */
static bool femu_doc_ctrl(FemuCtrlState *c, const char *io)
{
    QTestState *qts = c->pdev->bus->qts;
    uint64_t buf = guest_alloc(c->alloc, 4096);
    uint8_t *wbuf = g_malloc(4096);
    uint8_t *rbuf = g_malloc(4096);
    NvmeIdCtrl id;
    NvmeIdNs ns;
    NvmeCmd cmd;
    uint32_t len = 0;
    bool moved = false;
    int i;

    qtest_memset(qts, buf, 0, 4096);
    g_assert_cmpint(femu_identify(c, 0, NVME_ID_CNS_CTRL, 0, buf), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, buf, &id, sizeof(id));
    /* a controller that answered with an empty structure is no answer */
    g_assert_cmpint(id.mn[0], !=, 0);
    g_assert_cmpint(id.mn[0], !=, ' ');
    if (!strcmp(io, "identify")) {
        goto out;
    }

    femu_create_io_queues(c);
    for (i = 0; i < 4096; i++) {
        wbuf[i] = (uint8_t)(0x3c + i * 11);
    }
    if (!strcmp(io, "kv")) {
        len = 64;
        qtest_memwrite(qts, buf, wbuf, len);
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = FEMU_KV_CMD_STORE;
        cmd.dptr.prp1 = cpu_to_le64(buf);
        cmd.res1 = cpu_to_le64(0x53434f44ULL);  /* the key "DOCS" */
        cmd.cdw10 = cpu_to_le32(len);
        cmd.cdw11 = cpu_to_le32(4);
        g_assert_cmpint(femu_doc_io(c, &cmd), ==, NVME_SUCCESS);
        cmd.opcode = FEMU_KV_CMD_RETRIEVE;
    } else {
        qtest_memset(qts, buf, 0, 4096);
        if (femu_identify(c, 1, NVME_ID_CNS_NS, 0, buf) != NVME_SUCCESS) {
            g_test_message("namespace 1 is not attached here; Identify only");
            goto queues;
        }
        qtest_memread(qts, buf, &ns, sizeof(ns));
        if (!ns.nsze) {
            g_test_message("namespace 1 is not attached here; Identify only");
            goto queues;
        }
        len = 1u << ns.lbaf[NVME_ID_NS_FLBAS_INDEX(ns.flbas)].ds;
        g_assert_cmpint(len, <=, 4096);
        qtest_memwrite(qts, buf, wbuf, len);
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = NVME_CMD_WRITE;
        cmd.dptr.prp1 = cpu_to_le64(buf);
        g_assert_cmpint(femu_doc_io(c, &cmd), ==, NVME_SUCCESS);
        cmd.opcode = NVME_CMD_READ;
    }
    qtest_memset(qts, buf, 0, 4096);
    g_assert_cmpint(femu_doc_io(c, &cmd), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, rbuf, len);
    g_assert_cmpint(memcmp(wbuf, rbuf, len), ==, 0);
    moved = true;
queues:
    femu_queue_free(c, &c->io);
out:
    g_free(rbuf);
    g_free(wbuf);
    guest_free(c->alloc, buf);
    return moved;
}

static void femu_doc_example(const char *name, const char *ios,
                             const char *args)
{
    g_auto(GStrv) io = g_strsplit(ios, ",", -1);
    FemuDocCtrls ctrls = { 0 };
    QGuestAllocator alloc;
    QTestState *qts;
    QPCIBus *bus;
    bool need_data = false;
    bool moved = false;
    int i;

    g_test_message("doc-example %s: start", name);
    qts = qtest_init(args);
    pc_alloc_init(&alloc, qts, ALLOC_NO_FLAGS);
    bus = qpci_new_pc(qts, &alloc);
    qpci_device_foreach(bus, -1, -1, femu_doc_collect, &ctrls);
    g_assert_cmpint(ctrls.n, ==, g_strv_length(io));

    for (i = 0; i < ctrls.n; i++) {
        FemuCtrlState c = { 0 };

        /* key-value I/O runs only with CC.CSS 110b */
        if (!strcmp(io[i], "kv")) {
            femu_enable_csi(&c, ctrls.dev[i], &alloc);
        } else {
            femu_enable(&c, ctrls.dev[i], &alloc);
        }
        need_data |= strcmp(io[i], "identify") != 0;
        moved |= femu_doc_ctrl(&c, io[i]);
        femu_disable(&c);
        g_free(ctrls.dev[i]);
    }
    g_assert_true(moved || !need_data);

    qpci_free_pc(bus);
    alloc_destroy(&alloc);
    qtest_quit(qts);
    g_test_message("doc-example %s: ok", name);
}

/*
 * Properties kept only so old command lines still start. Each is set to a
 * value other than its default, and to its default in the control run.
 */
static const struct {
    const char *name;
    const char *other;
    const char *dflt;
} femu_ignored_props[] = {
    { "serial", "femu0", "" },
    { "ms", "8", "16" },
    { "ms_max", "32", "64" },
    { "dlfeat", "0", "1" },
    { "trcbsy", "100", "0" },
    { "nr_thread", "8", "4" },
    { "time_slice", "1", "200000" },
    { "context_switch_time", "1", "200" },
};

/*
 * query-femu-memory: the backend, and the per-block bitmaps (util and
 * uncorrectable, 8 bytes per 64 blocks each) plus metadata of each
 * namespace, all of 512-byte blocks.
 */
static const struct {
    const char *opts;
    uint64_t backend;
    uint32_t nr_ns;
    uint64_t ns_other;          /* each namespace */
    uint64_t ns_values;         /* the key-value arena of each namespace */
} femu_mem_cases[] = {
    { "femu_mode=2,devsz_mb=64", 64 * MiB, 1, 2 * 16384, 0 },
    { "femu_mode=2,devsz_mb=64,meta=8,mc=3", 64 * MiB, 1,
      2 * 16384 + 131072 * 8, 0 },
    { "femu_mode=2,devsz_mb=64,namespaces=2", 64 * MiB, 2, 2 * 8192, 0 },
    { "femu_mode=5,devsz_mb=64", 0, 1, 2 * 16384, 64 * MiB },
};

void femu_test_memory(void *obj, void *data, QGuestAllocator *unused)
{
    for (unsigned i = 0; i < ARRAY_SIZE(femu_mem_cases); i++) {
        QTestState *qts = qtest_initf("-machine pc -nodefaults "
                                      "-device femu,addr=5,id=mem,%s",
                                      femu_mem_cases[i].opts);
        QDict *rsp = qtest_qmp(qts, "{'execute':'query-femu-memory'}");
        QDict *ret = qdict_get_qdict(rsp, "return");
        QList *owners = qdict_get_qlist(ret, "owners");
        QList *nss = qdict_get_qlist(ret, "namespaces");
        const QListEntry *e;
        uint32_t seen_ns = 0;
        uint32_t seen_ctrl = 0;
        uint32_t seen_ftl = 0;
        uint64_t total = 0;

        g_assert_cmpstr(qdict_get_str(ret, "path"), ==,
                        "/machine/peripheral/mem");
        g_assert_false(qdict_get_bool(ret, "backend-pinned") &&
                       !femu_mem_cases[i].backend);
        QLIST_FOREACH_ENTRY(owners, e) {
            QDict *o = qobject_to(QDict, qlist_entry_obj(e));
            const char *kind = qdict_get_str(o, "kind");

            /*
             * A key-value namespace has an FTL with no block L2P: its
             * mapping is the reverse map, 8 bytes per page of the default
             * 16 GiB geometry.
             */
            if (!strcmp(kind, "ftl")) {
                g_assert_cmpuint(femu_mem_cases[i].ns_values, >, 0);
                g_assert_cmpuint(qdict_get_int(o, "mapping"), ==,
                                 16 * GiB / 4096 * 8);
                g_assert_cmpuint(qdict_get_int(o, "media"), >, 0);
                seen_ftl++;
                continue;
            }
            total += qdict_get_int(o, "backend") + qdict_get_int(o, "other");
            if (!strcmp(kind, "controller")) {
                seen_ctrl++;
                g_assert_cmpstr(qdict_get_str(o, "id"), ==,
                                "/machine/peripheral/mem");
                g_assert_cmpuint(qdict_get_int(o, "backend"), ==,
                                 femu_mem_cases[i].backend);
            } else {
                g_assert_cmpstr(kind, ==, "namespace");
                g_assert_cmpuint(qdict_get_int(o, "backend"), ==, 0);
                g_assert_cmpuint(qdict_get_int(o, "other"), ==,
                                 femu_mem_cases[i].ns_other);
                g_assert_cmpuint(qdict_get_int(o, "values"), ==,
                                 femu_mem_cases[i].ns_values);
                /* a key-value namespace has a key table, the others none */
                g_assert_true(!!qdict_get_int(o, "index") ==
                              !!femu_mem_cases[i].ns_values);
                seen_ns++;
            }
        }
        g_assert_cmpuint(seen_ctrl, ==, 1);
        g_assert_cmpuint(seen_ftl, ==, !!femu_mem_cases[i].ns_values);
        g_assert_cmpuint(seen_ns, ==, femu_mem_cases[i].nr_ns);
        g_assert_cmpuint(total, ==, femu_mem_cases[i].backend +
                         femu_mem_cases[i].nr_ns * femu_mem_cases[i].ns_other);
        g_assert_cmpuint(qlist_size(nss), ==, femu_mem_cases[i].nr_ns);
        QLIST_FOREACH_ENTRY(nss, e) {
            QDict *ns = qobject_to(QDict, qlist_entry_obj(e));
            g_autofree char *id = g_strdup_printf(
                "/machine/peripheral/mem/ns%" PRId64,
                qdict_get_int(ns, "nsid"));
            QList *ids = qdict_get_qlist(ns, "owners");
            const QListEntry *ie;
            bool has_ns = false;
            bool has_ctrl = false;
            bool has_ftl = false;

            g_assert_true(qdict_get_bool(ns, "attached"));
            QLIST_FOREACH_ENTRY(ids, ie) {
                const char *s = qstring_get_str(qobject_to(QString,
                                                qlist_entry_obj(ie)));

                has_ns |= !strcmp(s, id);
                has_ctrl |= !strcmp(s, "/machine/peripheral/mem");
                has_ftl |= !!strstr(s, "/ftl");
            }
            g_assert_true(has_ns);
            /* the backend owner, for a namespace with a backend slice */
            g_assert_true(has_ctrl == !!femu_mem_cases[i].backend);
            g_assert_true(has_ftl == !!femu_mem_cases[i].ns_values);
            g_assert_cmpuint(qlist_size(ids), ==, 1 + has_ctrl + has_ftl);
        }
        qobject_unref(rsp);

        rsp = qtest_qmp(qts, "{'execute':'query-femu-memory','arguments':{"
                        "'path':'/machine/peripheral/none'}}");
        g_assert_true(qdict_haskey(rsp, "error"));
        qobject_unref(rsp);
        qtest_quit(qts);
    }
}

/*
 * The subsystem takes its FDP units and handles in one sum before it
 * allocates. A joining controller of shared storage allocates nothing.
 */
void femu_test_mem_limit_subsys(void *obj, void *data,
                                QGuestAllocator *unused)
{
    QTestState *qts = qtest_init("-machine pc -nodefaults "
        "-device femu-subsys,id=sh,nqn=sh,ns_mgmt=on "
        "-device femu,addr=5,id=a,femu_mode=2,devsz_mb=16,subsys=sh "
        "-device femu,addr=6,id=b,femu_mode=2,devsz_mb=16,subsys=sh");
    const char *qemu = g_getenv("QTEST_QEMU_BINARY");
    g_autofree char *line = NULL;
    g_autofree char *err = NULL;
    g_auto(GStrv) argv = NULL;
    uint64_t sub = 0;
    int status = -1;

    g_assert_cmpuint(femu_mem_taken(qts, "a"), >=, 16 * MiB);
    g_assert_cmpuint(femu_mem_taken(qts, "b"), ==, 0);
    qtest_quit(qts);

    /* 4 handles of 2 groups of 128 units: read the sum, then one less */
    qts = qtest_init("-machine pc -nodefaults "
        "-device femu-subsys,id=s1,nqn=s1,fdp=on,fdp.nruh=4,fdp.nrg=2 "
        "-device femu,addr=5,id=f," FEMU_FDP_REFUSE ",secs_per_pg=8,"
        "lba_index=3,subsys=s1");
    femu_mem_total(qts, "f", &sub);
    g_assert_cmpuint(sub, >, 0);
    g_assert_cmpuint(femu_mem_taken(qts, "s1"), ==, sub);
    qtest_quit(qts);

    line = g_strdup_printf("%s -machine pc -accel qtest -nodefaults "
                           "-display none -device femu-subsys,id=s1,nqn=s1,"
                           "fdp=on,fdp.nruh=4,fdp.nrg=2,mem_limit=%" PRIu64,
                           qemu, sub - 1);
    g_assert_true(g_shell_parse_argv(line, NULL, &argv, NULL));
    g_assert_true(g_spawn_sync(NULL, argv, NULL,
                               G_SPAWN_STDOUT_TO_DEV_NULL, NULL, NULL,
                               NULL, &err, &status, NULL));
    g_assert_false(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    if (!strstr(err, "femu-subsys: memory limit")) {
        g_test_message("%s", err);
        g_assert_not_reached();
    }
}

/*
 * The optional parts of an FTL, each against the same FTL without it, on
 * the 4-LUN geometry above (384 pages, 49 logical blocks with the one past
 * the end). The slot structs are 24 bytes: two uint64_t and their bools,
 * padded. A hash entry is an int32_t. Sizes are for x86-64.
 */
void femu_test_memory_parts(void *obj, void *data,
                            QGuestAllocator *unused)
{
    static const struct {
        const char *base;
        const char *with;
        uint64_t add[3];        /* mapping, media, other */
        const char *geo;        /* NULL: FEMU_MEM_FTL */
    } cases[] = {
        /* read cache of 1 MiB: 256 slots and a hash of 513 */
        { "", ",read_cache_mb=1", { 0, 0, 256 * 24 + 513 * 4 } },
        /* RAIN over 4 dies: 4 failure ids and a 4 x 3 rank matrix */
        { "", ",rain_parity=1", { 0, 4 * 4 + 4 * 3 * 4, 0 } },
        /* a durable slot per buffer page */
        { ",buffer_size=16,power_loss=on",
          ",buffer_size=16,power_loss=on,durable_at_done=on",
          { 0, 0, 16 * 8 } },
        /*
         * DFTL with a 1 MiB cache: 256 slots and a hash of 513, and one
         * translation page of 512 LPNs (32 bytes and two one-word bitmaps)
         */
        { "", ",mapping=dftl,mapping_cache_mb=1",
          { 256 * 24 + 513 * 4 + 32 + 2 * 8, 0, 0 }, FEMU_MEM_FTL13 },
        /* hybrid: 80-byte state, 16 logs of 24 bytes, 49 blocks of 12 */
        { "", ",mapping=hybrid", { 80 + 16 * 24 + 49 * 12, 0, 0 } },
        /* FAST: 96-byte state, 49 dirty flags, 4096 dirty block ids */
        { "", ",mapping=fast", { 96 + 49 + 4096 * 8, 0, 0 } },
        /* a 32-byte statistics entry per die */
        { "", ",die_stats=on", { 0, 4 * 32, 0 } },
        /*
         * two namespace slices of one shared FTL: an offset, 3 counters
         * and 3 query-stats copies
         */
        { "", ",namespaces=2,shared_ftl=on", { 0, 0, 2 * (32 + 24) } },
    };

    for (unsigned i = 0; i < ARRAY_SIZE(cases); i++) {
        const char *geo = cases[i].geo ?: FEMU_MEM_FTL;
        g_autofree char *a = g_strdup_printf("%s%s", geo, cases[i].base);
        g_autofree char *b = g_strdup_printf("%s%s", geo, cases[i].with);
        uint64_t without[3];
        uint64_t with[3];

        femu_mem_ftl_bytes(a, without);
        femu_mem_ftl_bytes(b, with);
        for (int c = 0; c < 3; c++) {
            g_test_message("%s: category %d %" PRIu64 " -> %" PRIu64,
                           cases[i].with, c, without[c], with[c]);
            g_assert_cmpuint(with[c] - without[c], ==, cases[i].add[c]);
        }
    }
}

void femu_test_ignored_props(void *obj, void *data,
                             QGuestAllocator *unused)
{
    g_autoptr(GString) other = g_string_new("");
    g_autoptr(GString) dflt = g_string_new("");
    g_autofree char *warned = NULL;
    g_autofree char *quiet = NULL;
    unsigned i;

    for (i = 0; i < ARRAY_SIZE(femu_ignored_props); i++) {
        g_string_append_printf(other, ",%s=%s", femu_ignored_props[i].name,
                               femu_ignored_props[i].other);
        g_string_append_printf(dflt, ",%s=%s", femu_ignored_props[i].name,
                               femu_ignored_props[i].dflt);
    }

    warned = femu_realize_stderr(other->str);
    quiet = femu_realize_stderr(dflt->str);
    for (i = 0; i < ARRAY_SIZE(femu_ignored_props); i++) {
        const char *name = femu_ignored_props[i].name;
        g_autofree char *needle =
            g_strdup_printf("femu: %s has no effect", name);
        const char *hit = strstr(warned, needle);

        g_assert_nonnull(hit);
        g_assert_null(strstr(hit + 1, needle));
        g_assert_null(strstr(quiet, needle));
    }
    g_assert_null(strstr(quiet, "has no effect"));
}

void femu_test_doc_examples(void *obj, void *data,
                            QGuestAllocator *unused)
{
    const char *path = g_getenv("FEMU_DOC_EXAMPLES");
    g_autofree char *text = NULL;
    g_auto(GStrv) lines = NULL;
    int ran = 0;
    int i;

    if (!path) {
        g_test_skip("FEMU_DOC_EXAMPLES is not set; "
                    "hw/femu/scripts/check-doc-examples.py sets it");
        return;
    }
    g_assert_true(g_file_get_contents(path, &text, NULL, NULL));
    lines = g_strsplit(text, "\n", -1);
    for (i = 0; lines[i]; i++) {
        g_auto(GStrv) f = g_strsplit(lines[i], "\t", 3);

        if (!lines[i][0]) {
            continue;
        }
        g_assert_cmpint(g_strv_length(f), ==, 3);
        femu_doc_example(f[0], f[1], f[2]);
        ran++;
    }
    /* an empty list must not pass as if every example had run */
    g_assert_cmpint(ran, >, 0);
}
#define FEMU_LOG_MI_EFFECTS     0x13
#define FEMU_FID_SCOPE_CTRL     0x2

/*
 * LID 12h and 13h are listed in LID 00h and answer. 12h is built from the
 * check Get Features uses, so the two agree on every identifier; 13h is all
 * zero because there is no NVMe-MI Send or Receive.
 */
void femu_test_fid_effects(void *obj, void *data,
                           QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint32_t lids[256], fis[256];
    g_autofree uint8_t *mi = g_malloc(4096);
    uint64_t buf;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    buf = guest_alloc(alloc, 4096);

    g_assert_cmpint(femu_get_log_csi(&c, FEMU_LOG_SUPPORTED, 0, buf,
                                     sizeof(lids), 0), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, lids, sizeof(lids));
    g_assert_cmpint(le32_to_cpu(lids[FEMU_LOG_FID_EFFECTS]) & FEMU_LIDS_LSUPP,
                    ==, FEMU_LIDS_LSUPP);
    g_assert_cmpint(le32_to_cpu(lids[FEMU_LOG_MI_EFFECTS]) & FEMU_LIDS_LSUPP,
                    ==, FEMU_LIDS_LSUPP);

    g_assert_cmpint(femu_get_log_csi(&c, FEMU_LOG_FID_EFFECTS, 0, buf,
                                     sizeof(fis), 0), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, fis, sizeof(fis));
    femu_check_fid_effects(&c, fis);
    g_assert_cmphex(FEMU_FID_FSP(le32_to_cpu(fis[NVME_ARBITRATION])), ==,
                    FEMU_FID_SCOPE_CTRL);
    g_assert_cmphex(FEMU_FID_FSP(le32_to_cpu(fis[NVME_LBA_RANGE_TYPE])), ==,
                    FEMU_FID_SCOPE_NS);
    g_assert_cmphex(le32_to_cpu(fis[FEMU_FEAT_KV_CONFIG]), ==, 0);
    g_assert_cmphex(le32_to_cpu(fis[FEMU_FEAT_FDP]), ==, 0);
    g_assert_cmphex(le32_to_cpu(fis[FEMU_FEAT_FDP_EVENTS]), ==, 0);
    /* no volatile write cache without vwc=1 */
    g_assert_cmphex(le32_to_cpu(fis[NVME_VOLATILE_WRITE_CACHE]), ==, 0);
    g_assert_cmpint(femu_get_log_csi(&c, FEMU_LOG_FID_EFFECTS, 0, buf, 64,
                                     sizeof(fis)), ==, NVME_INVALID_FIELD);

    qtest_memset(qts, buf, 0xa5, 4096);
    g_assert_cmpint(femu_get_log_csi(&c, FEMU_LOG_MI_EFFECTS, 0, buf, 4096,
                                     0), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, mi, 4096);
    for (i = 0; i < 4096; i++) {
        g_assert_cmpint(mi[i], ==, 0);
    }
    g_assert_cmpint(femu_get_log_csi(&c, FEMU_LOG_MI_EFFECTS, 0, buf, 64,
                                     4096), ==, NVME_INVALID_FIELD);

    guest_free(alloc, buf);
    femu_disable(&c);
}

/*
 * CC.CSS values CAP.CSS does not offer are reserved (Base 2.3, Figure 41), so
 * enabling with one fails the controller instead of bringing it up; a reset
 * then recovers it, and the NVM command set still comes up.
 */
void femu_test_cc_css(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint32_t csts = 0;
    uint64_t cap;
    uint8_t cap_css;
    int css, waited, refused = 0;

    c.pdev = &femu->dev;
    c.alloc = alloc;
    femu_queue_init(&c, &c.admin, 0);
    qpci_device_enable(c.pdev);
    c.bar = qpci_iomap(c.pdev, 0, NULL);
    cap = qpci_io_readq(c.pdev, c.bar, 0x0);
    cap_css = (cap >> 37) & 0xff;
    g_assert_cmphex(cap_css & 0x1, ==, 0x1);

    for (css = 0; css < 8; css++) {
        uint32_t want = cap_css & (1 << css) ? NVME_CSTS_READY
                                              : NVME_CSTS_FAILED;

        qpci_io_writel(c.pdev, c.bar, 0x24,
                       ((FEMU_QSIZE - 1) << 16) | (FEMU_QSIZE - 1));
        qpci_io_writeq(c.pdev, c.bar, 0x28, c.admin.sq_addr);
        qpci_io_writeq(c.pdev, c.bar, 0x30, c.admin.cq_addr);
        qpci_io_writel(c.pdev, c.bar, 0x14,
                       (6 << 16) | (4 << 20) | (css << 4) | 1);
        for (waited = 0; waited < FEMU_POLL_LIMIT_MS; waited++) {
            csts = qpci_io_readl(c.pdev, c.bar, 0x1c);
            if (csts & (NVME_CSTS_READY | NVME_CSTS_FAILED)) {
                break;
            }
            g_usleep(1000);
        }
        g_assert_cmphex(csts & (NVME_CSTS_READY | NVME_CSTS_FAILED), ==, want);
        refused += want == NVME_CSTS_FAILED;

        qpci_io_writel(c.pdev, c.bar, 0x14, 0);
        for (waited = 0; waited < FEMU_POLL_LIMIT_MS; waited++) {
            csts = qpci_io_readl(c.pdev, c.bar, 0x1c);
            if (!(csts & (NVME_CSTS_READY | NVME_CSTS_FAILED))) {
                break;
            }
            g_usleep(1000);
        }
        g_assert_cmphex(csts & (NVME_CSTS_READY | NVME_CSTS_FAILED), ==, 0);
    }
    /* 001b to 101b are reserved whatever CAP.CSS says */
    g_assert_cmpint(refused, >=, 5);

    femu_queue_free(&c, &c.admin);
    qpci_iounmap(c.pdev, c.bar);
}

/*
 * PRPs are used for every admin command over PCIe (Base 2.3, Figure 91), so an
 * admin command naming SGLs in PSDT is an invalid field, whether or not it
 * moves data.
 */
void femu_test_admin_psdt(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf;
    NvmeCmd cmd;
    int psdt;

    femu_enable(&c, &femu->dev, alloc);
    buf = guest_alloc(alloc, 4096);

    for (psdt = 1; psdt < 4; psdt++) {
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = NVME_ADM_CMD_IDENTIFY;
        cmd.flags = psdt << 6;
        cmd.dptr.prp1 = cpu_to_le64(buf);
        cmd.cdw10 = cpu_to_le32(1);
        g_assert_cmphex(femu_admin(&c, &cmd), ==,
                        NVME_INVALID_FIELD | NVME_DNR);

        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = NVME_ADM_CMD_GET_FEATURES;
        cmd.flags = psdt << 6;
        cmd.cdw10 = cpu_to_le32(NVME_NUMBER_OF_QUEUES);
        g_assert_cmphex(femu_admin(&c, &cmd), ==,
                        NVME_INVALID_FIELD | NVME_DNR);
    }
    /* the same commands with PRPs still work */
    g_assert_cmpint(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);

    guest_free(alloc, buf);
    femu_disable(&c);
}

/*
 * A Compare that miscompares and a read of a block made uncorrectable fail
 * the same way if retried, so every such completion carries DNR (Base 2.3,
 * Figure 100), on Read, Verify, Copy and Compare alike.
 */
void femu_test_media_dnr(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t stride, buf, list;
    uint64_t slba[1];
    uint16_t nlb[1];
    NvmeCmd cmd;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    stride = FEMU_DATA_SIZE / c.lba_size;
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    list = guest_alloc(alloc, 4096);

    /* a miscompare */
    qtest_memset(qts, buf, 0x5a, FEMU_DATA_SIZE);
    g_assert_cmphex(femu_rw(&c, NVME_CMD_WRITE, 0, buf), ==, NVME_SUCCESS);
    qtest_memset(qts, buf, 0xa5, FEMU_DATA_SIZE);
    g_assert_cmphex(femu_rw(&c, NVME_CMD_COMPARE, 0, buf), ==,
                    NVME_CMP_FAILURE | NVME_DNR);

    /* an uncorrectable block, read three ways */
    g_assert_cmphex(femu_rw(&c, NVME_CMD_WRITE_UNCOR, stride, 0), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(femu_rw(&c, NVME_CMD_READ, stride, buf), ==,
                    NVME_UNRECOVERED_READ | NVME_DNR);
    g_assert_cmphex(femu_rw(&c, NVME_CMD_VERIFY, stride, 0), ==,
                    NVME_UNRECOVERED_READ | NVME_DNR);

    slba[0] = stride;
    nlb[0] = 1;
    qtest_memset(qts, list, 0, 4096);
    qtest_writeq(qts, list + 8, slba[0]);
    qtest_writew(qts, list + 16, nlb[0] - 1);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_CMD_COPY;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(list);
    cmd.cdw10 = cpu_to_le32(4 * stride);
    femu_submit(&c, &c.io, &cmd);
    g_assert_cmphex(femu_complete(&c, &c.io, NULL, NULL), ==,
                    NVME_UNRECOVERED_READ | NVME_DNR);

    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * FRMW reports one firmware slot, read-only, matching the firmware log, which
 * fills slot 1 only, and the firmware commands, which are not offered.
 */
void femu_test_frmw(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint8_t log[64];
    uint64_t buf;
    uint8_t frmw;
    int slot, i;

    femu_enable(&c, &femu->dev, alloc);
    buf = guest_alloc(alloc, 4096);

    g_assert_cmpint(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);
    frmw = qtest_readb(qts, buf + FEMU_ID_FRMW);
    g_assert_cmpint((frmw >> 1) & 0x7, ==, 1);
    g_assert_cmpint(frmw & 0x1, ==, 1);
    g_assert_cmpint(qtest_readw(qts, buf + 256) & NVME_OACS_FW, ==, 0);

    g_assert_cmpint(FEMU_SC(femu_get_log(&c, NVME_LOG_FW_SLOT_INFO, buf,
                                         sizeof(log), 0)), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, log, sizeof(log));
    g_assert_cmpint(log[0] & 0x7, ==, 1);
    g_assert_cmpint(log[8], !=, 0);
    for (slot = 2; slot <= 7; slot++) {
        for (i = 0; i < 8; i++) {
            g_assert_cmpint(log[slot * 8 + i], ==, 0);
        }
    }

    guest_free(alloc, buf);
    femu_disable(&c);
}

/*
 * rain_read_only refusals, each against a device that realizes without the
 * one change. "failed_die": 21 lines, 1 forced GC line, 16 usable; die 1
 * failed from the start leaves cap 16 * 16 = 256, the namespace: spare 0.
 */
void femu_test_rain_ro_refused(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    const struct {
        const char *opts;
        const char *msg;
        const char *mode;
        const char *ro;
    } cases[] = {
        { "'rain_parity':1,'mdts':4,'blks_per_pl':44", NULL },
        /* NoSSD: no FTL holds the reserve */
        { "'rain_parity':1,'mdts':4,'blks_per_pl':44",
          "not supported with a mode other than bbssd", "2" },
        { "'rain_parity':0,'mdts':4,'blks_per_pl':44", "needs rain_parity=1" },
        { "'rain_parity':1,'mdts':4,'eol_read_only':false,'blks_per_pl':44",
          "needs rain_parity=1 and eol_read_only=on" },
        { "'rain_parity':1,'mdts':4,'buffer_size':16,'blks_per_pl':44",
          "not supported with buffer_size" },
        { "'rain_parity':1,'mdts':4,'iu_pages':4,'blks_per_pl':44",
          "iu_pages above 1" },
        /* the wear model works with RAIN */
        { "'rain_parity':1,'mdts':4,'blk_pe_limit':9,'blks_per_pl':44", NULL },
        { "'rain_parity':1,'mdts':0,'blks_per_pl':44",
          "rain_read_only needs mdts" },
        { "'rain_parity':1,'mdts':4,'failed_die':1,'blks_per_pl':21",
          "failed_die leaves no spare" },
        { "'rain_parity':1,'mdts':4,'failed_die':1,'blks_per_pl':22", NULL },
        /* the wear end of life alone keeps the start check */
        { "'rain_parity':1,'mdts':4,'failed_die':1,'blk_pe_limit':9,"
          "'blks_per_pl':21",
          "failed_die leaves no spare", NULL, "false" },
        { "'rain_parity':1,'mdts':4,'failed_die':1,'blk_pe_limit':9,"
          "'blks_per_pl':22",
          NULL, NULL, "false" },
    };
    QDict *rsp;

    for (int i = 0; i < ARRAY_SIZE(cases); i++) {
        const char *mode = cases[i].mode;
        const char *ro = cases[i].ro;
        g_autofree char *cmd = g_strdup_printf(
            "{'execute':'device_add','arguments':{"
            "'driver':'femu','id':'rro%d','addr':'%d','devsz_mb':1,"
            "'femu_mode':%s,'secsz':512,'secs_per_pg':8,'pgs_per_blk':8,"
            "'luns_per_ch':2,'nchs':2,'pls_per_lun':1,"
            "'rain_read_only':%s,%s}}", i, 5 + i, mode ?: "1",
            ro ? ro : "true", cases[i].opts);

        rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));
        if (!cases[i].msg) {
            g_assert_false(qdict_haskey(rsp, "error"));
        } else {
            const char *desc;

            g_assert_true(qdict_haskey(rsp, "error"));
            desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
            g_test_message("%s: %s", cases[i].opts, desc);
            g_assert_nonnull(strstr(desc, cases[i].msg));
        }
        qobject_unref(rsp);
    }
    qos_invalidate_command_line();
}

/* without the property: no ANA reporting, no log 0Ch */
void femu_test_ana_off(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmphex(femu_identify(&c, 0, NVME_ID_CNS_CTRL, 0, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, buf + 76) & 8, ==, 0);
    g_assert_cmpuint(qtest_readl(qts, buf + 344), ==, 0);
    g_assert_cmphex(femu_ana_log(&c, buf, false), ==, 0x109);
    femu_disable(&c);
    guest_free(alloc, buf);
}

/* without the property: no NWPC, no feature 84h */
void femu_test_ns_wp_off(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmphex(femu_identify(&c, 0, NVME_ID_CNS_CTRL, 0, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, buf + 531), ==, 0);
    g_assert_cmphex(femu_wp_set(&c, 1, 1), ==, NVME_INVALID_FIELD);
    g_assert_cmphex(FEMU_SC(femu_get_feature(&c, FEMU_FID_NS_WP, 0, 1, 0,
                                             NULL)), ==, NVME_INVALID_FIELD);
    femu_disable(&c);
    guest_free(alloc, buf);
}

/*
 * NoSSD has no FTL thread: the poller reads to_ftl itself. x-cpl-hold 1
 * keeps two Writes there, and a Cancel of all namespaces defers both.
 * The firmware CPU model (fw_cpu_ns) sends NoSSD I/O through the rings;
 * without a model it can complete in the fetch sweep, with nothing left
 * for a Cancel to find.
 */
void femu_test_cancel_nossd(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint16_t cid[2];
    uint16_t sc[2];
    uint32_t res = 0;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_cancel_hook(qts, "cancel", "x-cpl-hold", 1);
    /* one pattern: a shared buffer cannot change under the Writes */
    cid[0] = femu_cancel_rw(&c, buf, 1, 0, true, 0xe6);
    cid[1] = femu_cancel_rw(&c, buf, 1, 8, true, 0xe6);
    femu_cancel_wait_cpl(qts, "cancel", 2);
    g_assert_cmphex(femu_cancel(&c, NVME_NSID_BROADCAST, 0xffff, c.io.qid,
                                1, &res), ==, NVME_SUCCESS);
    g_assert_cmphex(res, ==, 2 << 16);
    femu_cancel_hook(qts, "cancel", "x-cpl-hold", 0);
    femu_cancel_reap(&c, 2, cid, sc, NULL);
    g_assert_cmphex(sc[0], ==, NVME_CMD_ABORT_REQ);
    g_assert_cmphex(sc[1], ==, NVME_CMD_ABORT_REQ);
    femu_power_read(&c, buf, 1, 0, 0xe6);

    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    guest_free(alloc, buf);
    qos_invalidate_command_line();
}

/* without the property: one power state, no APST */
void femu_test_power_states_off(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmphex(femu_identify(&c, 0, NVME_ID_CNS_CTRL, 0, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmpuint(qtest_readb(qts, buf + 263), ==, 0);
    g_assert_cmpuint(qtest_readb(qts, buf + 265), ==, 0);
    g_assert_cmphex(FEMU_SC(femu_get_feature(&c, 0x0c, 0, 0, 0, NULL)), ==,
                    NVME_INVALID_FIELD);
    femu_disable(&c);
    guest_free(alloc, buf);
}

/* Without Namespace Management FEMU does not offer CNS 09h or 0Ah for NVM */
void femu_test_identify_fmt_off(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_identify(&c, 0, 0x09, 0, buf), ==,
                    NVME_INVALID_FIELD);
    g_assert_cmpint(femu_identify(&c, 0, 0x0a, 0, buf), ==,
                    NVME_INVALID_FIELD);
    guest_free(alloc, buf);
    femu_disable(&c);
}

/*
 * Run a 90/10 skewed overwrite on a hot-added device and return the pages
 * collection copied over the measured window. Greedy victims, queue depth
 * 1, a fixed seed and no time-based maintenance keep the counts exact. Both
 * GC thresholds at 95% leave collection to the forced passes, so it starts
 * only when free lines run short, not at the first victim with two
 * invalid pages.
 */
static uint64_t femu_gcf_skew_run(QFemu *femu, QGuestAllocator *alloc,
                                  bool on, int slot)
{
    QTestState *qts = femu->dev.bus->qts;
    g_autofree char *id = g_strdup_printf("gcs%d", slot);
    g_autofree char *cmd = g_strdup_printf(
        "{'execute':'device_add','arguments':{'driver':'femu','id':'%s',"
        "'addr':'%d','devsz_mb':4,'femu_mode':1,'secsz':512,"
        "'secs_per_pg':8,'pgs_per_blk':16,'blks_per_pl':80,"
        "'pls_per_lun':1,'luns_per_ch':1,'nchs':1,'gc_thres_pcent':95,"
        "'gc_thres_pcent_high':95,'gc_frontier':%s}}",
        id, slot, on ? "true" : "false");
    QDict *rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));
    uint64_t data = guest_alloc(alloc, FEMU_DATA_SIZE);
    uint64_t log = guest_alloc(alloc, 512);
    FemuCtrlState c = { 0 };
    QPCIDevice *pdev;
    uint32_t lcg = 777;
    uint64_t gc0 = 0;
    uint8_t page[512];

    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
    pdev = qpci_device_find(femu->dev.bus, QPCI_DEVFN(slot, 0));
    femu_enable(&c, pdev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, data, 0x6b, FEMU_DATA_SIZE);
    for (int i = 0; i < 1024; i++) {
        g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, i * 8, data)),
                        ==, NVME_SUCCESS);
    }
    for (int i = 0; i < 12288; i++) {
        uint32_t lpn;

        lcg = lcg * 1103515245u + 12345u;
        /* 90% of the writes go to the first 10% of the LPNs */
        lpn = ((lcg >> 8) % 10) ? (lcg >> 12) % 102 : (lcg >> 12) % 1024;
        if (i == 4096) {
            g_assert_cmpint(FEMU_SC(femu_get_log(&c, FEMU_LOG_FEMU_STATS,
                                                 log, sizeof(page), 0)), ==,
                            NVME_SUCCESS);
            qtest_memread(qts, log, page, sizeof(page));
            gc0 = ldq_le_p(page + 16);
        }
        g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, lpn * 8, data)),
                        ==, NVME_SUCCESS);
    }
    g_assert_cmpint(FEMU_SC(femu_get_log(&c, FEMU_LOG_FEMU_STATS, log,
                                         sizeof(page), 0)), ==, NVME_SUCCESS);
    qtest_memread(qts, log, page, sizeof(page));
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    qpci_unplug_acpi_device_test(qts, id, slot);
    g_free(pdev);
    guest_free(alloc, log);
    guest_free(alloc, data);
    return ldq_le_p(page + 16) - gc0;
}

/*
 * On a skewed overwrite, keeping the cold pages collection copies apart
 * from hot host writes leaves fewer valid pages in later victims. This
 * pins the order for this workload; the counts are exact for it.
 */
void femu_test_gc_frontier_skew(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    uint64_t off = femu_gcf_skew_run(obj, alloc, false, 5);
    uint64_t on = femu_gcf_skew_run(obj, alloc, true, 6);

    g_test_message("gc pages copied: gc_frontier off %" PRIu64 ", on %" PRIu64,
                   off, on);
    g_assert_cmpuint(off, >, 0);
    g_assert_cmpuint(on, <, off);
}

/*
 * gc_bg_invalid_pcent: the least share of invalid pages in the victim of a
 * background pass. One channel, one LUN, 16 pages a line, 60 lines. The
 * fill writes the 768 pages of the namespace once: 48 full lines, and at
 * most 12 free lines, under the background threshold of 15 and above the
 * forced one of 3. Each overwrite of LPN k < 16 then makes one page of the
 * first line invalid, and a background attempt follows each command.
 *
 *   pcent   attempt takes the line at    copies    erases
 *   0       2 invalid (16 / 8)           14        1
 *   50      8 invalid (8 x 100 >= 800)   8         1
 *   100     16 invalid, no valid page    0         1
 *
 * Before that overwrite no page moves and no block is erased. With the
 * property at its default the runs for 50 and 100 fail at the second
 * overwrite: the 1/8 rule copies 14 pages where they expect none.
 */
void femu_test_gc_bg_invalid(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    int pcent = atoi(data);
    int take = pcent ? 16 * pcent / 100 : 2;
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, FEMU_DATA_SIZE);

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x6b, FEMU_DATA_SIZE);
    for (int lpn = 0; lpn < 768; lpn++) {
        g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, lpn * 8, buf)),
                        ==, NVME_SUCCESS);
    }
    g_assert_cmpuint(femu_ftl_trace_field(qts, 4), ==, 0);
    g_assert_cmpuint(femu_ftl_trace_field(qts, 5), ==, 0);

    for (int k = 0; k < take; k++) {
        g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, k * 8, buf)), ==,
                        NVME_SUCCESS);
        g_test_message("gc-bg-invalid %d: %d invalid, %" PRIu64 " copies, %"
                       PRIu64 " erases", pcent, k + 1,
                       femu_ftl_trace_field(qts, 4),
                       femu_ftl_trace_field(qts, 5));
        g_assert_cmpuint(femu_ftl_trace_field(qts, 4), ==,
                         k + 1 < take ? 0 : 16 - take);
        g_assert_cmpuint(femu_ftl_trace_field(qts, 5), ==,
                         k + 1 < take ? 0 : 1);
    }
    g_assert_cmpuint(femu_ftl_trace_field(qts, 2), ==, 768 + take);

    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    guest_free(alloc, buf);
    qos_invalidate_command_line();
}

/*
 * atomic_write_lbas in Identify Namespace: with @data "on" (N = 16), NSFEAT
 * bit 1, NAWUN 15, NAWUPF 0, NABSN 15, NABO 0, NABSPF 0. With it off, bit 1
 * is clear and every field is 0.
 */
void femu_test_atomic_identify(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    bool on = !strcmp(data, "on");
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_identify(&c, 1, NVME_ID_CNS_NS, 0, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmpuint(qtest_readb(qts, buf + 24) & 0x2, ==, on ? 0x2 : 0);
    g_assert_cmpuint(qtest_readw(qts, buf + 34), ==, on ? 15 : 0);
    g_assert_cmpuint(qtest_readw(qts, buf + 36), ==, 0);
    g_assert_cmpuint(qtest_readw(qts, buf + 40), ==, on ? 15 : 0);
    g_assert_cmpuint(qtest_readw(qts, buf + 42), ==, 0);
    g_assert_cmpuint(qtest_readw(qts, buf + 44), ==, 0);
    guest_free(alloc, buf);
    femu_disable(&c);
}

/* realize refuses a tier it cannot run, and says why */
void femu_test_tier_refused(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    const struct {
        int mode;
        const char *opts;
        const char *msg;
    } cases[] = {
        { 1, "'nand_cell_type':3,'tier_mode':'cache','tier_static_mb':1",
          "tier_mode must be off, static or dynamic" },
        { 1, "'nand_cell_type':3,'tier_mode':'dynamic',"
          "'tier_full_policy':'through'", "tier_full_policy=through" },
        { 1, "'nand_cell_type':3,'tier_mode':'dynamic','tier_shrink_pct':100",
          "tier_shrink_pct must be 0 to 99" },
        { 1, "'nand_cell_type':3,'tier_mode':'static','tier_static_mb':1,"
          "'tier_idle_ms':10,'tier_lazy_pct':100",
          "tier_lazy_pct must be 0 to 99" },
        { 1, "'nand_cell_type':3,'tier_mode':'dynamic','pe_suspend':1,"
          "'buffer_size':64",
          "tier_mode=dynamic is not supported with pe_suspend with a write "
          "buffer" },
        { 1, "'nand_cell_type':3,'tier_mode':'static','tier_static_mb':1,"
          "'tier_full_policy':'concurrent'",
          "tier_full_policy must be direct or through" },
        { 1, "'tier_mode':'static','tier_static_mb':1",
          "needs nand_cell_type 2" },
        { 1, "'nand_cell_type':1,'tier_mode':'static','tier_static_mb':1",
          "needs nand_cell_type 2" },
        { 1, "'nand_cell_type':3,'tier_mode':'static'",
          "needs tier_static_mb above 0" },
        { 1, "'nand_cell_type':3,'tier_mode':'static',"
          "'tier_full_policy':'through'", "tier_full_policy=through" },
        { 1, "'nand_cell_type':3,'tier_mode':'static','tier_static_mb':1,"
          "'tier_pslc_read_ns':20000000000", "must be at most" },
        /* pe_suspend: only what the fold seals do not cover is refused */
        { 1, "'nand_cell_type':3,'tier_mode':'static','tier_static_mb':1,"
          "'pe_suspend':1,'subsys':'fdpsub'", "pe_suspend under FDP" },
        { 1, "'nand_cell_type':3,'tier_mode':'static','tier_static_mb':1,"
          "'pe_suspend':1,'buffer_size':64",
          "pe_suspend with a write buffer" },
        { 1, "'nand_cell_type':3,'tier_mode':'static','tier_static_mb':1,"
          "'pe_suspend':1,'mapping':'dftl'", "pe_suspend with mapping=dftl" },
        { 1, "'nand_cell_type':3,'tier_mode':'static','tier_static_mb':1,"
          "'pe_suspend':1,'die_parity':1", "pe_suspend with die_parity" },
        { 1, "'nand_cell_type':3,'tier_mode':'static','tier_static_mb':1,"
          "'ecc_step_ns':1000000", "ecc_step_ns" },
        { 3, "'nand_cell_type':3,'tier_mode':'static','tier_static_mb':1",
          "a mode other than bbssd" },
        { 1, "'nand_cell_type':3,'tier_mode':'static','tier_static_mb':1,"
          "'mapping':'hybrid'", "a mapping other than page or dftl" },
        { 1, "'nand_cell_type':3,'tier_mode':'static','tier_static_mb':1,"
          "'hot_cold_sep':true", "hot_cold_sep" },
        { 1, "'nand_cell_type':3,'tier_mode':'static','tier_static_mb':1,"
          "'gc_pace':true", "gc_pace" },
        { 1, "'nand_cell_type':3,'tier_mode':'static','tier_static_mb':1,"
          "'gc_copyback':true", "gc_copyback" },
        { 1, "'nand_cell_type':3,'tier_mode':'static','tier_static_mb':1,"
          "'wl_spread':8", "wl_spread" },
        { 1, "'nand_cell_type':3,'tier_mode':'static','tier_static_mb':1,"
          "'read_reclaim_limit':8", "read_reclaim_limit" },
        { 1, "'nand_cell_type':3,'tier_mode':'static','tier_static_mb':1,"
          "'namespaces':2", "more than one namespace" },
        /* 12 pool lines leave 18 x 192 pages, short of the 4096 exposed */
        { 1, "'nand_cell_type':3,'tier_mode':'static','tier_static_mb':3",
          "tier_static_mb pSLC pool" },
    };

    for (size_t i = 0; i < ARRAY_SIZE(cases); i++) {
        g_autofree char *cmd = g_strdup_printf(
            "{'execute':'device_add','arguments':{"
            "'driver':'femu','id':'tier-bad','addr':'5','devsz_mb':16,"
            "'femu_mode':%d,'secsz':512,'secs_per_pg':8,'pgs_per_blk':48,"
            "'blks_per_pl':32,'pls_per_lun':1,'luns_per_ch':2,'nchs':2,"
            "%s}}", cases[i].mode, cases[i].opts);
        QDict *rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));
        const char *desc;

        g_assert_true(qdict_haskey(rsp, "error"));
        desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
        g_test_message("tier refused %s: %s", cases[i].opts, desc);
        g_assert_nonnull(strstr(desc, cases[i].msg));
        qobject_unref(rsp);
    }
    qos_invalidate_command_line();
}

/*
 * Data pointer targets. A data pointer can name memory that is not guest
 * RAM: the controller memory buffer (CMB) of the same device, the CMB or
 * the registers of a second device, a ROM, or an address with no region.
 * These tests fix the status of each case and check which bytes move.
 *
 *  device A (addr 5): sgl=on, CMB   serves the commands
 *  device B (addr 6): CMB           a peer, never enabled
 *  device C (addr 7): no CMB        copies a short PRP transfer by itself
 *
 * Each test starts this machine itself, so the shared device line of the
 * other tests stays as it is.
 */
#define FEMU_DPT_MACHINE \
    "-machine pc -m 128M -nodefaults " \
    "-device femu,id=dpt-a,addr=5,devsz_mb=16,femu_mode=2,sgl=on," \
    "cmbsz=0x400000,cmbloc=2,serial=dpt-a " \
    "-device femu,id=dpt-b,addr=6,devsz_mb=16,femu_mode=2," \
    "cmbsz=0x400000,cmbloc=2,serial=dpt-b " \
    "-device femu,id=dpt-c,addr=7,devsz_mb=16,femu_mode=2,serial=dpt-c"

#define FEMU_DPT_PAGE       4096u
#define FEMU_DPT_GUARD      512u
/* the first address after the 128 MiB of RAM, and an address with no region */
#define FEMU_DPT_RAM_TOP    0x8000000ULL
#define FEMU_DPT_HOLE       (FEMU_DPT_RAM_TOP + 0x100000)
/* the BIOS image, as in pause-mmio */
#define FEMU_DPT_ROM        0xfffc0000ULL
#define FEMU_DPT_CMB_SIZE   0x400000ULL
/* the part of the namespace that the tests use: LBA 0 and up */
#define FEMU_DPT_NS_BYTES   (4 * FEMU_DPT_PAGE)
#define FEMU_DPT_NS_SEED    0x31
#define FEMU_DPT_NEW_SEED   0x5a
#define FEMU_DPT_GUARD_SEED 0xc5
/* values for AQA, ASQ and ACQ of the peer: a guard on its registers */
#define FEMU_DPT_AQA        0x000f000f
#define FEMU_DPT_ASQ        0x0000000001234000ULL
#define FEMU_DPT_ACQ        0x0000000005678000ULL

typedef struct FemuDpt {
    QOSState *qs;
    QTestState *qts;
    QPCIDevice *dev_a;
    QPCIDevice *dev_b;
    QPCIDevice *dev_c;
    FemuCtrlState a;
    QPCIBar own_cmb;
    QPCIBar peer_cmb;
    QPCIBar peer_regs;
    /* seven pages of RAM; ent[] names pages 1, 3 and 5 of them */
    uint64_t ram;
    uint64_t ent[3];
    uint64_t list;
    uint64_t scratch;
} FemuDpt;

/* a target that every command must refuse */
typedef struct FemuDptTarget {
    const char *name;
    uint64_t addr;
    /* the test can fill it and read it again */
    bool pattern;
} FemuDptTarget;

/* byte @off + i of the pattern @seed, so each page differs from the next */
static void femu_dpt_pattern(uint8_t *p, size_t len, uint8_t seed, size_t off)
{
    size_t i;

    for (i = 0; i < len; i++) {
        size_t pos = off + i;

        p[i] = seed ^ (uint8_t)pos ^ (uint8_t)(pos >> 8);
    }
}

static void femu_dpt_mem_put(FemuDpt *t, uint64_t addr, size_t len,
                             uint8_t seed, size_t off)
{
    g_autofree uint8_t *p = g_malloc(len);

    femu_dpt_pattern(p, len, seed, off);
    qtest_memwrite(t->qts, addr, p, len);
}

static void femu_dpt_mem_is(FemuDpt *t, uint64_t addr, size_t len,
                            uint8_t seed, size_t off)
{
    g_autofree uint8_t *want = g_malloc(len);
    g_autofree uint8_t *got = g_malloc(len);

    femu_dpt_pattern(want, len, seed, off);
    qtest_memread(t->qts, addr, got, len);
    g_assert_cmpmem(got, len, want, len);
}

/* a guard pattern in [addr, addr + len) and in 512 bytes on each side */
static void femu_dpt_guard_put(FemuDpt *t, uint64_t addr, uint32_t len)
{
    femu_dpt_mem_put(t, addr - FEMU_DPT_GUARD, len + 2 * FEMU_DPT_GUARD,
                     FEMU_DPT_GUARD_SEED, 0);
}

static void femu_dpt_guard_is(FemuDpt *t, uint64_t addr, uint32_t len)
{
    femu_dpt_mem_is(t, addr - FEMU_DPT_GUARD, len + 2 * FEMU_DPT_GUARD,
                    FEMU_DPT_GUARD_SEED, 0);
}

/* the peer is disabled and its queue registers hold what the test wrote */
static void femu_dpt_regs_is(FemuDpt *t)
{
    g_assert_cmphex(qpci_io_readl(t->dev_b, t->peer_regs, 0x14), ==, 0);
    g_assert_cmphex(qpci_io_readl(t->dev_b, t->peer_regs, 0x1c), ==, 0);
    g_assert_cmphex(qpci_io_readl(t->dev_b, t->peer_regs, 0x24), ==,
                    FEMU_DPT_AQA);
    g_assert_cmphex(qpci_io_readq(t->dev_b, t->peer_regs, 0x28), ==,
                    FEMU_DPT_ASQ);
    g_assert_cmphex(qpci_io_readq(t->dev_b, t->peer_regs, 0x30), ==,
                    FEMU_DPT_ACQ);
}

/*
 * One Read, Write or Compare of @len bytes at byte @off of namespace 1.
 * With @sgl the data pointer is that descriptor, else the PRP pair.
 */
static uint16_t femu_dpt_cmd(FemuCtrlState *c, uint8_t opcode, uint32_t off,
                             uint32_t len, uint64_t prp1, uint64_t prp2,
                             const NvmeSglDescriptor *sgl)
{
    NvmeRwCmd rw;

    memset(&rw, 0, sizeof(rw));
    rw.opcode = opcode;
    rw.nsid = cpu_to_le32(1);
    rw.slba = cpu_to_le64(off / c->lba_size);
    rw.nlb = cpu_to_le16(len / c->lba_size - 1);
    if (sgl) {
        rw.flags = 1 << 6;                  /* PSDT: SGL */
        memcpy(&rw.dptr.sgl, sgl, sizeof(*sgl));
    } else {
        rw.dptr.prp1 = cpu_to_le64(prp1);
        rw.dptr.prp2 = cpu_to_le64(prp2);
    }
    return femu_io(c, (NvmeCmd *)&rw);
}

/* fill the tested part of the namespace with the pattern @seed */
static void femu_dpt_ns_put(FemuDpt *t, FemuCtrlState *c, uint8_t seed)
{
    uint32_t off;

    for (off = 0; off < FEMU_DPT_NS_BYTES; off += FEMU_DPT_PAGE) {
        femu_dpt_mem_put(t, t->scratch, FEMU_DPT_PAGE, seed, off);
        g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_WRITE, off, FEMU_DPT_PAGE,
                                     t->scratch, 0, NULL), ==, NVME_SUCCESS);
    }
}

/* bytes [off, off + len) of the namespace hold the pattern @seed */
static void femu_dpt_ns_is(FemuDpt *t, FemuCtrlState *c, uint32_t off,
                           uint32_t len, uint8_t seed)
{
    uint32_t end = off + len;

    for (; off < end; off += FEMU_DPT_PAGE) {
        qtest_memset(t->qts, t->scratch, 0, FEMU_DPT_PAGE);
        g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_READ, off, FEMU_DPT_PAGE,
                                     t->scratch, 0, NULL), ==, NVME_SUCCESS);
        femu_dpt_mem_is(t, t->scratch, FEMU_DPT_PAGE, seed, off);
    }
}

static void femu_dpt_start(FemuDpt *t)
{
    QGuestAllocator *alloc;
    int i;

    memset(t, 0, sizeof(*t));
    t->qs = qtest_pc_boot(FEMU_DPT_MACHINE);
    t->qts = t->qs->qts;
    alloc = &t->qs->alloc;
    t->dev_a = qpci_device_find(t->qs->pcibus, QPCI_DEVFN(5, 0));
    t->dev_b = qpci_device_find(t->qs->pcibus, QPCI_DEVFN(6, 0));
    t->dev_c = qpci_device_find(t->qs->pcibus, QPCI_DEVFN(7, 0));
    g_assert_nonnull(t->dev_a);
    g_assert_nonnull(t->dev_b);
    g_assert_nonnull(t->dev_c);

    femu_enable(&t->a, t->dev_a, alloc);
    femu_create_io_queues(&t->a);
    t->own_cmb = qpci_iomap(t->dev_a, 2, NULL);

    /* the peer decodes its regions and stays disabled */
    qpci_device_enable(t->dev_b);
    t->peer_regs = qpci_iomap(t->dev_b, 0, NULL);
    t->peer_cmb = qpci_iomap(t->dev_b, 2, NULL);
    qpci_io_writel(t->dev_b, t->peer_regs, 0x24, FEMU_DPT_AQA);
    qpci_io_writeq(t->dev_b, t->peer_regs, 0x28, FEMU_DPT_ASQ);
    qpci_io_writeq(t->dev_b, t->peer_regs, 0x30, FEMU_DPT_ACQ);
    femu_dpt_regs_is(t);

    t->ram = guest_alloc(alloc, 7 * FEMU_DPT_PAGE);
    for (i = 0; i < ARRAY_SIZE(t->ent); i++) {
        t->ent[i] = t->ram + (2 * i + 1) * FEMU_DPT_PAGE;
    }
    t->list = guest_alloc(alloc, FEMU_DPT_PAGE);
    t->scratch = guest_alloc(alloc, FEMU_DPT_PAGE);
    g_assert_cmpuint(t->ram + 7 * FEMU_DPT_PAGE, <, FEMU_DPT_RAM_TOP);
    femu_dpt_ns_put(t, &t->a, FEMU_DPT_NS_SEED);
}

static void femu_dpt_stop(FemuDpt *t)
{
    guest_free(&t->qs->alloc, t->scratch);
    guest_free(&t->qs->alloc, t->list);
    guest_free(&t->qs->alloc, t->ram);
    femu_queue_free(&t->a, &t->a.io);
    femu_disable(&t->a);
    g_free(t->dev_c);
    g_free(t->dev_b);
    g_free(t->dev_a);
    qtest_pc_shutdown(t->qs);
}

/* the three targets that are neither RAM nor the CMB of device A */
static void femu_dpt_targets(FemuDpt *t, FemuDptTarget tg[3])
{
    tg[0] = (FemuDptTarget) { "CMB of the peer",
                              t->peer_cmb.addr + FEMU_DPT_PAGE, true };
    tg[1] = (FemuDptTarget) { "registers of the peer", t->peer_regs.addr,
                              false };
    tg[2] = (FemuDptTarget) { "no region", FEMU_DPT_HOLE, false };
}

static void femu_dpt_target_prep(FemuDpt *t, const FemuDptTarget *tg)
{
    g_test_message("target: %s", tg->name);
    if (tg->pattern) {
        femu_dpt_guard_put(t, tg->addr, FEMU_DPT_PAGE);
    }
}

/* no byte of the target changed, and no register of the peer */
static void femu_dpt_target_intact(FemuDpt *t, const FemuDptTarget *tg)
{
    if (tg->pattern) {
        femu_dpt_guard_is(t, tg->addr, FEMU_DPT_PAGE);
    }
    femu_dpt_regs_is(t);
}

/*
 * Read, Write and Compare of @len bytes each end with @sc, and the
 * namespace keeps its data. The caller checks the memory side.
 */
static void femu_dpt_refused(FemuDpt *t, FemuCtrlState *c, uint32_t len,
                             uint64_t prp1, uint64_t prp2,
                             const NvmeSglDescriptor *sgl, uint16_t sc)
{
    static const uint8_t ops[] = {
        NVME_CMD_READ, NVME_CMD_WRITE, NVME_CMD_COMPARE,
    };
    int i;

    for (i = 0; i < ARRAY_SIZE(ops); i++) {
        g_test_message("opcode 0x%x", ops[i]);
        g_assert_cmphex(femu_dpt_cmd(c, ops[i], 0, len, prp1, prp2, sgl),
                        ==, sc);
    }
    femu_dpt_ns_is(t, c, 0, FEMU_DPT_NS_BYTES, FEMU_DPT_NS_SEED);
}

/* an SGL data block descriptor */
static NvmeSglDescriptor femu_dpt_blk(uint64_t addr, uint32_t len)
{
    NvmeSglDescriptor d = { 0 };

    d.addr = cpu_to_le64(addr);
    d.len = cpu_to_le32(len);
    return d;
}

/*
 * Write @nr descriptors to @list and return a descriptor of @type
 * (Segment or Last Segment) that points at them.
 */
static NvmeSglDescriptor femu_dpt_seg(FemuDpt *t, uint64_t list,
                                      const NvmeSglDescriptor *d, int nr,
                                      uint8_t type)
{
    NvmeSglDescriptor s = { 0 };

    qtest_memwrite(t->qts, list, d, nr * sizeof(*d));
    s.addr = cpu_to_le64(list);
    s.len = cpu_to_le32(nr * sizeof(*d));
    s.type = type << 4;
    return s;
}

/* bytes [off, off + FEMU_DPT_PAGE) of the namespace equal @want */
static void femu_dpt_ns_equals(FemuDpt *t, FemuCtrlState *c, uint32_t off,
                               const uint8_t *want)
{
    uint8_t got[FEMU_DPT_PAGE];

    qtest_memset(t->qts, t->scratch, 0, FEMU_DPT_PAGE);
    g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_READ, off, FEMU_DPT_PAGE,
                                 t->scratch, 0, NULL), ==, NVME_SUCCESS);
    qtest_memread(t->qts, t->scratch, got, sizeof(got));
    g_assert_cmpmem(got, sizeof(got), want, FEMU_DPT_PAGE);
}

/*
 * A ROM is a source and never a destination. A Read into it fails and
 * leaves it as it was; a Write from it stores its bytes, and a Compare
 * against those bytes then matches.
 */
static void femu_dpt_rom(FemuDpt *t, FemuCtrlState *c,
                         const NvmeSglDescriptor *sgl)
{
    uint8_t rom[FEMU_DPT_PAGE];
    uint8_t after[FEMU_DPT_PAGE];

    g_test_message("target: ROM");
    qtest_memread(t->qts, FEMU_DPT_ROM, rom, sizeof(rom));
    g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_READ, 0, FEMU_DPT_PAGE,
                                 FEMU_DPT_ROM, 0, sgl), ==,
                    NVME_DATA_TRAS_ERROR);
    qtest_memread(t->qts, FEMU_DPT_ROM, after, sizeof(after));
    g_assert_cmpmem(after, sizeof(after), rom, sizeof(rom));
    femu_dpt_ns_is(t, c, 0, FEMU_DPT_NS_BYTES, FEMU_DPT_NS_SEED);

    g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_WRITE, 0, FEMU_DPT_PAGE,
                                 FEMU_DPT_ROM, 0, sgl), ==, NVME_SUCCESS);
    femu_dpt_ns_equals(t, c, 0, rom);
    g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_COMPARE, 0, FEMU_DPT_PAGE,
                                 FEMU_DPT_ROM, 0, sgl), ==, NVME_SUCCESS);
    femu_dpt_ns_put(t, c, FEMU_DPT_NS_SEED);
}

/*
 * One page between the namespace and @addr: a Read fills @addr byte for
 * byte, a Write stores it, and a Compare of equal data matches.
 */
static void femu_dpt_page_ok(FemuDpt *t, FemuCtrlState *c, uint64_t addr,
                             const NvmeSglDescriptor *sgl)
{
    femu_dpt_mem_put(t, addr, FEMU_DPT_PAGE, FEMU_DPT_GUARD_SEED, 0);
    g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_READ, 0, FEMU_DPT_PAGE, addr, 0,
                                 sgl), ==, NVME_SUCCESS);
    femu_dpt_mem_is(t, addr, FEMU_DPT_PAGE, FEMU_DPT_NS_SEED, 0);
    g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_COMPARE, 0, FEMU_DPT_PAGE, addr,
                                 0, sgl), ==, NVME_SUCCESS);

    femu_dpt_mem_put(t, addr, FEMU_DPT_PAGE, FEMU_DPT_NEW_SEED, 0);
    g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_COMPARE, 0, FEMU_DPT_PAGE, addr,
                                 0, sgl), ==, NVME_CMP_FAILURE);
    g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_WRITE, 0, FEMU_DPT_PAGE, addr, 0,
                                 sgl), ==, NVME_SUCCESS);
    femu_dpt_ns_is(t, c, 0, FEMU_DPT_PAGE, FEMU_DPT_NEW_SEED);
    femu_dpt_ns_is(t, c, FEMU_DPT_PAGE, FEMU_DPT_NS_BYTES - FEMU_DPT_PAGE,
                   FEMU_DPT_NS_SEED);
    femu_dpt_ns_put(t, c, FEMU_DPT_NS_SEED);
}

/* page 0 of the namespace: new data in its first @len bytes, old after */
static void femu_dpt_ns_half(FemuDpt *t, FemuCtrlState *c, uint32_t len)
{
    qtest_memset(t->qts, t->scratch, 0, FEMU_DPT_PAGE);
    g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_READ, 0, FEMU_DPT_PAGE,
                                 t->scratch, 0, NULL), ==, NVME_SUCCESS);
    femu_dpt_mem_is(t, t->scratch, len, FEMU_DPT_NEW_SEED, 0);
    femu_dpt_mem_is(t, t->scratch + len, FEMU_DPT_PAGE - len,
                    FEMU_DPT_NS_SEED, len);
}

/*
 * Compare returns the status of the PRP mapper, as Read and Write do. It
 * returned Invalid Field for each mapper failure: a list page that cannot
 * be read is a Data Transfer Error, and an offset in PRP2 or in a list
 * pointer is PRP Offset Invalid.
 */
void femu_test_dma_target_compare_status(void *obj, void *data,
                                         QGuestAllocator *unused)
{
    static const uint8_t ops[] = { NVME_CMD_READ, NVME_CMD_COMPARE };
    FemuDptTarget tg[3];
    FemuDpt t;
    FemuCtrlState *c;
    int op;
    int i;

    femu_dpt_start(&t);
    c = &t.a;
    femu_dpt_targets(&t, tg);
    femu_dpt_mem_put(&t, t.ent[0], FEMU_DPT_PAGE, FEMU_DPT_NS_SEED, 0);

    for (op = 0; op < ARRAY_SIZE(ops); op++) {
        g_test_message("opcode 0x%x", ops[op]);
        /* three pages: PRP2 is a list pointer, and the list is not RAM */
        for (i = 0; i < 3; i++) {
            femu_dpt_target_prep(&t, &tg[i]);
            g_assert_cmphex(femu_dpt_cmd(c, ops[op], 0, 3 * FEMU_DPT_PAGE,
                                         t.ent[0], tg[i].addr, NULL), ==,
                            NVME_DATA_TRAS_ERROR);
            femu_dpt_target_intact(&t, &tg[i]);
        }
        /* a list pointer that does not name whole entries */
        g_assert_cmphex(femu_dpt_cmd(c, ops[op], 0, 3 * FEMU_DPT_PAGE,
                                     t.ent[0], t.list + 4, NULL), ==,
                        NVME_INVALID_PRP_OFFSET);
        /* two pages: PRP2 is data and must start a page */
        g_assert_cmphex(femu_dpt_cmd(c, ops[op], 0, 2 * FEMU_DPT_PAGE,
                                     t.ent[0], t.ent[1] + 8, NULL), ==,
                        NVME_INVALID_PRP_OFFSET);
        /* no pointer at all stays an invalid field */
        g_assert_cmphex(femu_dpt_cmd(c, ops[op], 0, FEMU_DPT_PAGE, 0, 0,
                                     NULL), ==, NVME_INVALID_FIELD);
    }

    /* control: a Compare with a good pointer reads the data */
    femu_dpt_mem_put(&t, t.ent[0], FEMU_DPT_PAGE, FEMU_DPT_NS_SEED, 0);
    g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_COMPARE, 0, FEMU_DPT_PAGE,
                                 t.ent[0], 0, NULL), ==, NVME_SUCCESS);
    femu_dpt_mem_put(&t, t.ent[0], FEMU_DPT_PAGE, FEMU_DPT_NEW_SEED, 0);
    g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_COMPARE, 0, FEMU_DPT_PAGE,
                                 t.ent[0], 0, NULL), ==, NVME_CMP_FAILURE);
    femu_dpt_ns_is(&t, c, 0, FEMU_DPT_NS_BYTES, FEMU_DPT_NS_SEED);

    femu_dpt_stop(&t);
}

/*
 * PRP1 alone, one page. RAM works both ways and a ROM is a source only.
 * The CMB of the same device is refused with Invalid Field, as the media
 * path takes no iovec. Each target that is not memory gets Data Transfer
 * Error, and no byte of it or of the namespace changes.
 */
void femu_test_dma_target_prp1(void *obj, void *data,
                               QGuestAllocator *unused)
{
    FemuDptTarget tg[3];
    FemuDptTarget own;
    FemuDpt t;
    int i;

    femu_dpt_start(&t);
    femu_dpt_targets(&t, tg);

    /* control: the same command form with RAM */
    femu_dpt_page_ok(&t, &t.a, t.ent[0], NULL);

    own = (FemuDptTarget) { "own CMB", t.own_cmb.addr + FEMU_DPT_PAGE,
                            true };
    femu_dpt_target_prep(&t, &own);
    femu_dpt_refused(&t, &t.a, FEMU_DPT_PAGE, own.addr, 0, NULL,
                     NVME_INVALID_FIELD);
    femu_dpt_target_intact(&t, &own);

    for (i = 0; i < 3; i++) {
        femu_dpt_target_prep(&t, &tg[i]);
        femu_dpt_refused(&t, &t.a, FEMU_DPT_PAGE, tg[i].addr, 0, NULL,
                         NVME_DATA_TRAS_ERROR);
        femu_dpt_target_intact(&t, &tg[i]);
    }

    femu_dpt_rom(&t, &t.a, NULL);
    femu_dpt_stop(&t);
}

/*
 * PRP2 and PRP lists. An entry after the first may name the CMB of the
 * same device, and so may the list page itself. A refused list page
 * moves nothing. A refused entry after the first fails the command, and
 * the entries before it have moved: a Read filled them and a Write
 * stored them.
 */
void femu_test_dma_target_prp_list(void *obj, void *data,
                                   QGuestAllocator *unused)
{
    const uint32_t len3 = 3 * FEMU_DPT_PAGE;
    uint64_t own = 0;
    uint64_t own_list = 0;
    uint64_t low = FEMU_DPT_RAM_TOP - FEMU_DPT_PAGE;
    uint64_t ents[2];
    FemuDptTarget tg[3];
    FemuDpt t;
    FemuCtrlState *c;
    int i;

    femu_dpt_start(&t);
    c = &t.a;
    femu_dpt_targets(&t, tg);
    own = t.own_cmb.addr + FEMU_DPT_PAGE;
    own_list = t.own_cmb.addr + 2 * FEMU_DPT_PAGE;

    /* two pages: PRP1 in RAM, PRP2 in the own CMB */
    g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_READ, 0, 2 * FEMU_DPT_PAGE,
                                 t.ent[0], own, NULL), ==, NVME_SUCCESS);
    femu_dpt_mem_is(&t, t.ent[0], FEMU_DPT_PAGE, FEMU_DPT_NS_SEED, 0);
    femu_dpt_mem_is(&t, own, FEMU_DPT_PAGE, FEMU_DPT_NS_SEED,
                    FEMU_DPT_PAGE);
    g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_COMPARE, 0, 2 * FEMU_DPT_PAGE,
                                 t.ent[0], own, NULL), ==, NVME_SUCCESS);
    femu_dpt_mem_put(&t, t.ent[0], FEMU_DPT_PAGE, FEMU_DPT_NEW_SEED, 0);
    femu_dpt_mem_put(&t, own, FEMU_DPT_PAGE, FEMU_DPT_NEW_SEED,
                     FEMU_DPT_PAGE);
    g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_WRITE, 0, 2 * FEMU_DPT_PAGE,
                                 t.ent[0], own, NULL), ==, NVME_SUCCESS);
    femu_dpt_ns_is(&t, c, 0, 2 * FEMU_DPT_PAGE, FEMU_DPT_NEW_SEED);
    femu_dpt_ns_put(&t, c, FEMU_DPT_NS_SEED);

    /* two pages: PRP1 in the own CMB, PRP2 in RAM */
    femu_dpt_guard_put(&t, own, FEMU_DPT_PAGE);
    femu_dpt_refused(&t, c, 2 * FEMU_DPT_PAGE, own, t.ent[1], NULL,
                     NVME_INVALID_FIELD);
    femu_dpt_guard_is(&t, own, FEMU_DPT_PAGE);

    /* three pages: the list page lies in the own CMB */
    ents[0] = cpu_to_le64(t.ent[1]);
    ents[1] = cpu_to_le64(t.ent[2]);
    qtest_memwrite(t.qts, own_list, ents, sizeof(ents));
    g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_READ, 0, len3, t.ent[0],
                                 own_list, NULL), ==, NVME_SUCCESS);
    for (i = 0; i < 3; i++) {
        femu_dpt_mem_is(&t, t.ent[i], FEMU_DPT_PAGE, FEMU_DPT_NS_SEED,
                        i * FEMU_DPT_PAGE);
    }
    g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_COMPARE, 0, len3, t.ent[0],
                                 own_list, NULL), ==, NVME_SUCCESS);

    /* three pages: the list is in RAM and its last entry in the own CMB */
    ents[1] = cpu_to_le64(own);
    qtest_memwrite(t.qts, t.list, ents, sizeof(ents));
    g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_READ, 0, len3, t.ent[0],
                                 t.list, NULL), ==, NVME_SUCCESS);
    femu_dpt_mem_is(&t, own, FEMU_DPT_PAGE, FEMU_DPT_NS_SEED,
                    2 * FEMU_DPT_PAGE);

    /* the list page is not memory: nothing moves */
    for (i = 0; i < 3; i++) {
        femu_dpt_target_prep(&t, &tg[i]);
        femu_dpt_refused(&t, c, len3, t.ent[0], tg[i].addr, NULL,
                         NVME_DATA_TRAS_ERROR);
        femu_dpt_target_intact(&t, &tg[i]);
    }

    /* the last entry is not memory: the first two pages have moved */
    for (i = 0; i < 3; i++) {
        femu_dpt_target_prep(&t, &tg[i]);
        ents[1] = cpu_to_le64(tg[i].addr);
        qtest_memwrite(t.qts, t.list, ents, sizeof(ents));

        femu_dpt_mem_put(&t, t.ent[0], FEMU_DPT_PAGE, FEMU_DPT_GUARD_SEED, 0);
        femu_dpt_mem_put(&t, t.ent[1], FEMU_DPT_PAGE, FEMU_DPT_GUARD_SEED, 0);
        g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_READ, 0, len3, t.ent[0],
                                     t.list, NULL), ==, NVME_DATA_TRAS_ERROR);
        femu_dpt_mem_is(&t, t.ent[0], FEMU_DPT_PAGE, FEMU_DPT_NS_SEED, 0);
        femu_dpt_mem_is(&t, t.ent[1], FEMU_DPT_PAGE, FEMU_DPT_NS_SEED,
                        FEMU_DPT_PAGE);
        /* equal data up to the refused entry */
        g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_COMPARE, 0, len3,
                                     t.ent[0], t.list, NULL), ==,
                        NVME_DATA_TRAS_ERROR);

        femu_dpt_mem_put(&t, t.ent[0], FEMU_DPT_PAGE, FEMU_DPT_NEW_SEED, 0);
        femu_dpt_mem_put(&t, t.ent[1], FEMU_DPT_PAGE, FEMU_DPT_NEW_SEED,
                         FEMU_DPT_PAGE);
        g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_WRITE, 0, len3, t.ent[0],
                                     t.list, NULL), ==, NVME_DATA_TRAS_ERROR);
        femu_dpt_ns_is(&t, c, 0, 2 * FEMU_DPT_PAGE, FEMU_DPT_NEW_SEED);
        femu_dpt_ns_is(&t, c, 2 * FEMU_DPT_PAGE, 2 * FEMU_DPT_PAGE,
                       FEMU_DPT_NS_SEED);
        femu_dpt_target_intact(&t, &tg[i]);
        femu_dpt_ns_put(&t, c, FEMU_DPT_NS_SEED);
    }

    /* two pages: the last page of RAM, then the first address after it */
    femu_dpt_mem_put(&t, low, FEMU_DPT_PAGE, FEMU_DPT_GUARD_SEED, 0);
    g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_READ, 0, 2 * FEMU_DPT_PAGE, low,
                                 FEMU_DPT_RAM_TOP, NULL), ==,
                    NVME_DATA_TRAS_ERROR);
    femu_dpt_mem_is(&t, low, FEMU_DPT_PAGE, FEMU_DPT_NS_SEED, 0);
    femu_dpt_mem_put(&t, low, FEMU_DPT_PAGE, FEMU_DPT_NEW_SEED, 0);
    g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_WRITE, 0, 2 * FEMU_DPT_PAGE, low,
                                 FEMU_DPT_RAM_TOP, NULL), ==,
                    NVME_DATA_TRAS_ERROR);
    femu_dpt_ns_is(&t, c, 0, FEMU_DPT_PAGE, FEMU_DPT_NEW_SEED);
    femu_dpt_ns_is(&t, c, FEMU_DPT_PAGE, 3 * FEMU_DPT_PAGE,
                   FEMU_DPT_NS_SEED);

    femu_dpt_stop(&t);
}

/*
 * One SGL data block. RAM and the CMB of the same device both work, and
 * a ROM is a source only. A block that is not memory, or that runs past
 * the end of a region, moves nothing: each part of a block is checked
 * before any part is copied.
 */
void femu_test_dma_target_sgl(void *obj, void *data,
                              QGuestAllocator *unused)
{
    NvmeSglDescriptor blk;
    FemuDptTarget tg[3];
    FemuDpt t;
    FemuCtrlState *c;
    uint64_t end;
    int i;

    femu_dpt_start(&t);
    c = &t.a;
    femu_dpt_targets(&t, tg);

    blk = femu_dpt_blk(t.ent[0], FEMU_DPT_PAGE);
    femu_dpt_page_ok(&t, c, t.ent[0], &blk);
    blk = femu_dpt_blk(t.own_cmb.addr + FEMU_DPT_PAGE, FEMU_DPT_PAGE);
    femu_dpt_page_ok(&t, c, t.own_cmb.addr + FEMU_DPT_PAGE, &blk);

    for (i = 0; i < 3; i++) {
        femu_dpt_target_prep(&t, &tg[i]);
        blk = femu_dpt_blk(tg[i].addr, FEMU_DPT_PAGE);
        femu_dpt_refused(&t, c, FEMU_DPT_PAGE, 0, 0, &blk,
                         NVME_DATA_TRAS_ERROR);
        femu_dpt_target_intact(&t, &tg[i]);
    }

    blk = femu_dpt_blk(FEMU_DPT_ROM, FEMU_DPT_PAGE);
    femu_dpt_rom(&t, c, &blk);

    /* half a page at the end of the own CMB, then past its end */
    end = t.own_cmb.addr + FEMU_DPT_CMB_SIZE;
    femu_dpt_mem_put(&t, end - FEMU_DPT_PAGE, FEMU_DPT_PAGE,
                     FEMU_DPT_GUARD_SEED, 0);
    blk = femu_dpt_blk(end - FEMU_DPT_PAGE / 2, FEMU_DPT_PAGE);
    femu_dpt_refused(&t, c, FEMU_DPT_PAGE, 0, 0, &blk, NVME_DATA_TRAS_ERROR);
    femu_dpt_mem_is(&t, end - FEMU_DPT_PAGE, FEMU_DPT_PAGE,
                    FEMU_DPT_GUARD_SEED, 0);

    /* half a page at the end of RAM, then the hole after it */
    end = FEMU_DPT_RAM_TOP;
    femu_dpt_mem_put(&t, end - FEMU_DPT_PAGE, FEMU_DPT_PAGE,
                     FEMU_DPT_GUARD_SEED, 0);
    blk = femu_dpt_blk(end - FEMU_DPT_PAGE / 2, FEMU_DPT_PAGE);
    femu_dpt_refused(&t, c, FEMU_DPT_PAGE, 0, 0, &blk, NVME_DATA_TRAS_ERROR);
    femu_dpt_mem_is(&t, end - FEMU_DPT_PAGE, FEMU_DPT_PAGE,
                    FEMU_DPT_GUARD_SEED, 0);

    femu_dpt_stop(&t);
}

/*
 * SGL segments. A list may lie in the CMB of the same device. A list that
 * is not memory fails the command before any data moves, also when a
 * Segment chains to it. A data block that is not memory, after a block
 * in RAM, fails the command, and the block before it has moved.
 */
void femu_test_dma_target_sgl_chain(void *obj, void *data,
                                    QGuestAllocator *unused)
{
    const uint32_t half = FEMU_DPT_PAGE / 2;
    NvmeSglDescriptor d[2];
    NvmeSglDescriptor seg;
    FemuDptTarget tg[3];
    FemuDpt t;
    FemuCtrlState *c;
    uint64_t own;
    uint64_t own_list;
    int i;

    femu_dpt_start(&t);
    c = &t.a;
    femu_dpt_targets(&t, tg);
    own = t.own_cmb.addr + FEMU_DPT_PAGE;
    own_list = t.own_cmb.addr + 2 * FEMU_DPT_PAGE;

    /* a last segment in RAM: half a page in RAM, half in the own CMB */
    d[0] = femu_dpt_blk(t.ent[0], half);
    d[1] = femu_dpt_blk(own, half);
    seg = femu_dpt_seg(&t, t.list, d, 2, NVME_SGL_DESCR_TYPE_LAST_SEGMENT);
    g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_READ, 0, FEMU_DPT_PAGE, 0, 0,
                                 &seg), ==, NVME_SUCCESS);
    femu_dpt_mem_is(&t, t.ent[0], half, FEMU_DPT_NS_SEED, 0);
    femu_dpt_mem_is(&t, own, half, FEMU_DPT_NS_SEED, half);
    g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_COMPARE, 0, FEMU_DPT_PAGE, 0, 0,
                                 &seg), ==, NVME_SUCCESS);
    femu_dpt_mem_put(&t, t.ent[0], half, FEMU_DPT_NEW_SEED, 0);
    femu_dpt_mem_put(&t, own, half, FEMU_DPT_NEW_SEED, half);
    g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_WRITE, 0, FEMU_DPT_PAGE, 0, 0,
                                 &seg), ==, NVME_SUCCESS);
    femu_dpt_ns_is(&t, c, 0, FEMU_DPT_PAGE, FEMU_DPT_NEW_SEED);
    femu_dpt_ns_put(&t, c, FEMU_DPT_NS_SEED);

    /* a Segment in RAM chains to a last segment in the own CMB */
    d[0] = femu_dpt_blk(t.ent[1], half);
    seg = femu_dpt_seg(&t, own_list, d, 1, NVME_SGL_DESCR_TYPE_LAST_SEGMENT);
    d[0] = femu_dpt_blk(t.ent[0], half);
    d[1] = seg;
    seg = femu_dpt_seg(&t, t.list, d, 2, NVME_SGL_DESCR_TYPE_SEGMENT);
    g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_READ, 0, FEMU_DPT_PAGE, 0, 0,
                                 &seg), ==, NVME_SUCCESS);
    femu_dpt_mem_is(&t, t.ent[0], half, FEMU_DPT_NS_SEED, 0);
    femu_dpt_mem_is(&t, t.ent[1], half, FEMU_DPT_NS_SEED, half);

    for (i = 0; i < 3; i++) {
        /* the only list is not memory */
        femu_dpt_target_prep(&t, &tg[i]);
        seg = femu_dpt_blk(tg[i].addr, sizeof(d[0]));
        seg.type = NVME_SGL_DESCR_TYPE_LAST_SEGMENT << 4;
        femu_dpt_refused(&t, c, FEMU_DPT_PAGE, 0, 0, &seg,
                         NVME_DATA_TRAS_ERROR);
        femu_dpt_target_intact(&t, &tg[i]);

        /* a Segment in RAM chains to a list that is not memory */
        femu_dpt_mem_put(&t, t.ent[0], half, FEMU_DPT_GUARD_SEED, 0);
        d[0] = femu_dpt_blk(t.ent[0], half);
        d[1] = femu_dpt_blk(tg[i].addr, sizeof(d[0]));
        d[1].type = NVME_SGL_DESCR_TYPE_LAST_SEGMENT << 4;
        seg = femu_dpt_seg(&t, t.list, d, 2, NVME_SGL_DESCR_TYPE_SEGMENT);
        femu_dpt_refused(&t, c, FEMU_DPT_PAGE, 0, 0, &seg,
                         NVME_DATA_TRAS_ERROR);
        femu_dpt_mem_is(&t, t.ent[0], half, FEMU_DPT_GUARD_SEED, 0);
        femu_dpt_target_intact(&t, &tg[i]);

        /* the second data block is not memory: the first has moved */
        femu_dpt_mem_put(&t, t.ent[0], half, FEMU_DPT_GUARD_SEED, 0);
        d[1] = femu_dpt_blk(tg[i].addr, half);
        seg = femu_dpt_seg(&t, t.list, d, 2,
                           NVME_SGL_DESCR_TYPE_LAST_SEGMENT);
        g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_READ, 0, FEMU_DPT_PAGE, 0,
                                     0, &seg), ==, NVME_DATA_TRAS_ERROR);
        femu_dpt_mem_is(&t, t.ent[0], half, FEMU_DPT_NS_SEED, 0);
        g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_COMPARE, 0, FEMU_DPT_PAGE,
                                     0, 0, &seg), ==, NVME_DATA_TRAS_ERROR);
        femu_dpt_mem_put(&t, t.ent[0], half, FEMU_DPT_NEW_SEED, 0);
        g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_WRITE, 0, FEMU_DPT_PAGE, 0,
                                     0, &seg), ==, NVME_DATA_TRAS_ERROR);
        femu_dpt_ns_half(&t, c, half);
        femu_dpt_target_intact(&t, &tg[i]);
        femu_dpt_ns_put(&t, c, FEMU_DPT_NS_SEED);
    }

    femu_dpt_stop(&t);
}

/*
 * Device C has no CMB, so a Read or Write of one or two pages takes the
 * short PRP path, which copies each page itself. The CMBs of A and B are
 * both foreign memory here. A refused first page moves nothing, and a
 * refused second page leaves the first one moved.
 */
void femu_test_dma_target_single_prp(void *obj, void *data,
                                     QGuestAllocator *unused)
{
    static const uint8_t ops[] = { NVME_CMD_READ, NVME_CMD_WRITE };
    FemuCtrlState cs = { 0 };
    FemuCtrlState *c = &cs;
    FemuDptTarget tg[4];
    FemuDpt t;
    int op;
    int i;

    femu_dpt_start(&t);
    femu_dpt_targets(&t, tg);
    tg[3] = (FemuDptTarget) { "CMB of device A",
                              t.own_cmb.addr + FEMU_DPT_PAGE, true };
    femu_enable(c, t.dev_c, &t.qs->alloc);
    femu_create_io_queues(c);
    femu_dpt_ns_put(&t, c, FEMU_DPT_NS_SEED);

    /* control: RAM, one page and two pages */
    g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_READ, 0, 2 * FEMU_DPT_PAGE,
                                 t.ent[0], t.ent[1], NULL), ==,
                    NVME_SUCCESS);
    femu_dpt_mem_is(&t, t.ent[0], FEMU_DPT_PAGE, FEMU_DPT_NS_SEED, 0);
    femu_dpt_mem_is(&t, t.ent[1], FEMU_DPT_PAGE, FEMU_DPT_NS_SEED,
                    FEMU_DPT_PAGE);
    femu_dpt_mem_put(&t, t.ent[0], FEMU_DPT_PAGE, FEMU_DPT_NEW_SEED, 0);
    g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_WRITE, 0, FEMU_DPT_PAGE,
                                 t.ent[0], 0, NULL), ==, NVME_SUCCESS);
    femu_dpt_ns_is(&t, c, 0, FEMU_DPT_PAGE, FEMU_DPT_NEW_SEED);
    femu_dpt_ns_put(&t, c, FEMU_DPT_NS_SEED);

    for (i = 0; i < 4; i++) {
        femu_dpt_target_prep(&t, &tg[i]);
        for (op = 0; op < ARRAY_SIZE(ops); op++) {
            g_assert_cmphex(femu_dpt_cmd(c, ops[op], 0, FEMU_DPT_PAGE,
                                         tg[i].addr, 0, NULL), ==,
                            NVME_DATA_TRAS_ERROR);
        }
        femu_dpt_ns_is(&t, c, 0, FEMU_DPT_NS_BYTES, FEMU_DPT_NS_SEED);
        femu_dpt_target_intact(&t, &tg[i]);

        /* the second page is refused, after the first has moved */
        femu_dpt_mem_put(&t, t.ent[0], FEMU_DPT_PAGE, FEMU_DPT_GUARD_SEED, 0);
        g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_READ, 0, 2 * FEMU_DPT_PAGE,
                                     t.ent[0], tg[i].addr, NULL), ==,
                        NVME_DATA_TRAS_ERROR);
        femu_dpt_mem_is(&t, t.ent[0], FEMU_DPT_PAGE, FEMU_DPT_NS_SEED, 0);
        femu_dpt_mem_put(&t, t.ent[0], FEMU_DPT_PAGE, FEMU_DPT_NEW_SEED, 0);
        g_assert_cmphex(femu_dpt_cmd(c, NVME_CMD_WRITE, 0, 2 * FEMU_DPT_PAGE,
                                     t.ent[0], tg[i].addr, NULL), ==,
                        NVME_DATA_TRAS_ERROR);
        femu_dpt_ns_is(&t, c, 0, FEMU_DPT_PAGE, FEMU_DPT_NEW_SEED);
        femu_dpt_ns_is(&t, c, FEMU_DPT_PAGE, 3 * FEMU_DPT_PAGE,
                       FEMU_DPT_NS_SEED);
        femu_dpt_target_intact(&t, &tg[i]);
        femu_dpt_ns_put(&t, c, FEMU_DPT_NS_SEED);
    }

    femu_dpt_rom(&t, c, NULL);

    femu_queue_free(c, &c->io);
    femu_disable(c);
    femu_dpt_stop(&t);
}

/*
 * Commands that name foreign memory are in flight while a Format pauses
 * the pollers with the BQL held. A copy that waited for a handler would
 * stop the VM, so each round has to end within the deadline, and every
 * command fails with Data Transfer Error.
 */
void femu_test_dma_target_pause(void *obj, void *data,
                                QGuestAllocator *unused)
{
    FemuPauseDeadline d = { 0 };
    FemuDptTarget tg[3];
    GThread *watchdog;
    FemuDpt t;
    FemuCtrlState *c;
    NvmeRwCmd rw;
    int round;
    int j;

    femu_dpt_start(&t);
    c = &t.a;
    femu_dpt_targets(&t, tg);
    femu_dpt_guard_put(&t, tg[0].addr, FEMU_DPT_PAGE);

    g_mutex_init(&d.lock);
    g_cond_init(&d.cond);
    watchdog = g_thread_new("dpt-pause-timeout", femu_pause_deadline, &d);
    for (round = 0; round < 16; round++) {
        for (j = 0; j < 14; j++) {
            memset(&rw, 0, sizeof(rw));
            rw.opcode = j & 1 ? NVME_CMD_READ : NVME_CMD_WRITE;
            rw.nsid = cpu_to_le32(1);
            rw.nlb = cpu_to_le16(FEMU_DPT_PAGE / c->lba_size - 1);
            rw.dptr.prp1 = cpu_to_le64(tg[(round + j) % 3].addr);
            femu_submit(c, &c->io, (NvmeCmd *)&rw);
        }
        g_assert_cmphex(femu_format(c, 1, 0, 0), ==, NVME_SUCCESS);
        for (j = 0; j < 14; j++) {
            g_assert_cmphex(FEMU_SC(femu_complete(c, &c->io, NULL, NULL)),
                            ==, NVME_DATA_TRAS_ERROR);
        }
    }
    g_mutex_lock(&d.lock);
    d.done = true;
    g_cond_signal(&d.cond);
    g_mutex_unlock(&d.lock);
    g_thread_join(watchdog);
    g_cond_clear(&d.cond);
    g_mutex_clear(&d.lock);

    femu_dpt_target_intact(&t, &tg[0]);
    /* control: the controller still moves data */
    femu_dpt_ns_put(&t, c, FEMU_DPT_NS_SEED);
    femu_dpt_ns_is(&t, c, 0, FEMU_DPT_NS_BYTES, FEMU_DPT_NS_SEED);
    femu_dpt_stop(&t);
}
#define FEMU_G1_QUEUES      64

/*
 * With nlbaf 8 or more, one command can move 4 GiB. An mdts of 0, or one
 * that allows 4 GiB, becomes 19: 2 GiB with CAP.MPSMIN 0. A Write and a
 * Read of 8 blocks still move their data. @data is the block size.
 */
void femu_test_g1_mdts_cap(void *obj, void *data,
                           QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    const uint32_t nlb = 8;
    const uint64_t slba = 16;
    uint64_t id = guest_alloc(alloc, FEMU_G1_PAGE);
    uint64_t buf;
    uint64_t list;
    uint8_t *wbuf;
    uint8_t *rbuf;
    uint64_t nsze;
    uint32_t lba_size;
    uint32_t bytes;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    g_assert_cmpuint(femu_g1_mdts(&c, id), ==, 19);
    femu_identify_ns(&c, &nsze, &lba_size);
    g_assert_cmpuint(lba_size, ==, GPOINTER_TO_UINT(data));
    g_assert_cmpuint(nsze, >=, slba + nlb);
    c.lba_size = lba_size;
    bytes = nlb * lba_size;
    buf = guest_alloc(alloc, bytes);
    list = guest_alloc(alloc, femu_g1_list_pages(bytes / FEMU_G1_PAGE) *
                       FEMU_G1_PAGE);
    wbuf = g_malloc(bytes);
    rbuf = g_malloc0(bytes);

    femu_g1_fill(wbuf, bytes, 9);
    femu_g1_put(qts, buf, wbuf, bytes);
    g_assert_cmphex(femu_g1_rw(&c, NVME_CMD_WRITE, slba, nlb, buf, list), ==,
                    NVME_SUCCESS);
    qtest_memset(qts, buf, 0, bytes);
    g_assert_cmphex(femu_g1_rw(&c, NVME_CMD_READ, slba, nlb, buf, list), ==,
                    NVME_SUCCESS);
    femu_g1_get(qts, buf, rbuf, bytes);
    g_assert_cmpint(memcmp(wbuf, rbuf, bytes), ==, 0);

    g_free(rbuf);
    g_free(wbuf);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    guest_free(alloc, id);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * queues=64: Number of Queues reports 64 of each kind, queue 64 can be
 * created and queue 65 cannot. Each queue writes its own page. Then each
 * queue holds one Read of the page of another queue before the test takes
 * a completion, so every queue has work at one time. The same test runs
 * with three pollers that share the 64 queues.
 */
void femu_test_g1_many_queues(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    FemuQueue q[FEMU_G1_QUEUES];
    uint16_t cid[FEMU_G1_QUEUES];
    uint64_t buf = guest_alloc(alloc, FEMU_G1_QUEUES * FEMU_DATA_SIZE);
    uint64_t ring = guest_alloc(alloc, FEMU_G1_PAGE);
    uint32_t result = 0;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmphex(FEMU_SC(femu_get_feature(&c, FEMU_FEAT_NUM_QUEUES, 0, 0,
                                             0, &result)), ==, NVME_SUCCESS);
    g_assert_cmphex(result, ==, (FEMU_G1_QUEUES - 1) |
                    ((FEMU_G1_QUEUES - 1) << 16));

    for (i = 0; i < FEMU_G1_QUEUES; i++) {
        femu_burst_queue(&c, &q[i], i + 1);
    }
    g_assert_cmphex(femu_queue_cmd(&c, NVME_ADM_CMD_CREATE_CQ,
                                   FEMU_G1_QUEUES + 1, ring, NVME_CQ_PC),
                    ==, FEMU_INVALID_QID);
    g_assert_cmphex(femu_queue_cmd(&c, NVME_ADM_CMD_CREATE_SQ,
                                   FEMU_G1_QUEUES + 1, ring,
                                   (1 << 16) | NVME_SQ_PC),
                    ==, FEMU_INVALID_QID);

    for (i = 0; i < FEMU_G1_QUEUES; i++) {
        qtest_memset(qts, buf, 0x40 + i, FEMU_DATA_SIZE);
        cid[i] = femu_g1_queue_submit(&c, &q[i], NVME_CMD_WRITE, 8 * i, buf);
        g_assert_cmphex(femu_g1_queue_reap(&c, &q[i], cid[i]), ==,
                        NVME_SUCCESS);
    }

    /* queue 64 - i reads page i into a buffer page of its own */
    qtest_memset(qts, buf, 0, FEMU_G1_QUEUES * FEMU_DATA_SIZE);
    for (i = 0; i < FEMU_G1_QUEUES; i++) {
        cid[i] = femu_g1_queue_submit(&c, &q[FEMU_G1_QUEUES - 1 - i],
                                      NVME_CMD_READ, 8 * i,
                                      buf + (uint64_t)i * FEMU_DATA_SIZE);
    }
    for (i = 0; i < FEMU_G1_QUEUES; i++) {
        g_assert_cmphex(femu_g1_queue_reap(&c, &q[FEMU_G1_QUEUES - 1 - i],
                                           cid[i]), ==, NVME_SUCCESS);
        femu_g1_all(qts, buf + (uint64_t)i * FEMU_DATA_SIZE, FEMU_DATA_SIZE,
                    0x40 + i);
    }

    for (i = 0; i < FEMU_G1_QUEUES; i++) {
        femu_queue_free(&c, &q[i]);
    }
    guest_free(alloc, ring);
    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * entries=4095: CAP.MQES is 4095, so a queue holds 4096 entries and no more.
 * A full queue, 4095 commands behind one doorbell write, completes each
 * command once. Three more commands then take both rings over their end.
 */
void femu_test_g1_deep_queue(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    FemuQueue q = { .qid = 1, .phase = 1 };
    const uint32_t sq_bytes = FEMU_G1_DEPTH * sizeof(NvmeCmd);
    const uint32_t cq_bytes = FEMU_G1_DEPTH * sizeof(NvmeCqe);
    uint64_t buf = guest_alloc(alloc, FEMU_G1_PAGE);
    uint16_t first;
    NvmeCqe cqe;

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpuint(qpci_io_readq(c.pdev, c.bar, 0x0) & 0xffff, ==,
                     FEMU_G1_DEPTH - 1);
    q.sq_addr = guest_alloc(alloc, sq_bytes);
    q.cq_addr = guest_alloc(alloc, cq_bytes);
    qtest_memset(qts, q.cq_addr, 0, cq_bytes);

    g_assert_cmphex(femu_g1_create(&c, NVME_ADM_CMD_CREATE_CQ, 1, q.cq_addr,
                                   FEMU_G1_DEPTH, NVME_CQ_PC), ==,
                    FEMU_INVALID_QSIZE | NVME_DNR);
    g_assert_cmphex(femu_g1_create(&c, NVME_ADM_CMD_CREATE_CQ, 1, q.cq_addr,
                                   FEMU_G1_DEPTH - 1, NVME_CQ_PC), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(femu_g1_create(&c, NVME_ADM_CMD_CREATE_SQ, 1, q.sq_addr,
                                   FEMU_G1_DEPTH, (1 << 16) | NVME_SQ_PC),
                    ==, FEMU_INVALID_QSIZE | NVME_DNR);
    g_assert_cmphex(femu_g1_create(&c, NVME_ADM_CMD_CREATE_SQ, 1, q.sq_addr,
                                   FEMU_G1_DEPTH - 1, (1 << 16) | NVME_SQ_PC),
                    ==, NVME_SUCCESS);

    /* a ring of 4096 entries is full with 4095 */
    first = c.cid;
    femu_g1_deep_submit(&c, &q, buf, FEMU_G1_DEPTH - 1);
    g_assert_cmpuint(q.sq_tail, ==, FEMU_G1_DEPTH - 1);
    femu_g1_deep_reap(&c, &q, first, FEMU_G1_DEPTH - 1);

    /* slots 4095, 0 and 1: the tail, the head and the phase wrap */
    first = c.cid;
    femu_g1_deep_submit(&c, &q, buf, 3);
    g_assert_cmpuint(q.sq_tail, ==, 2);
    femu_g1_deep_reap(&c, &q, first, 3);
    g_assert_cmpuint(q.cq_head, ==, 2);
    g_assert_cmpuint(q.phase, ==, 0);

    /* nothing completes a second time */
    g_usleep(10 * 1000);
    qtest_memread(qts, q.cq_addr + q.cq_head * sizeof(cqe), &cqe,
                  sizeof(cqe));
    g_assert_cmpint(le16_to_cpu(cqe.status) & 1, !=, q.phase);

    guest_free(alloc, q.cq_addr);
    guest_free(alloc, q.sq_addr);
    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/* where the pieces of the 8 KiB scattered transfer lie in a 16 KiB area */
typedef struct FemuG1Piece {
    uint32_t off;
    uint32_t len;
} FemuG1Piece;

static const FemuG1Piece femu_g1_sgl_pieces[] = {
    { 0x0001, 1 }, { 0x0403, 1023 }, { 0x1001, 3073 }, { 0x2001, 4095 },
};

/* PRP1 4 bytes before a page end, then two list entries out of order */
static const FemuG1Piece femu_g1_prp_pieces[] = {
    { 0x0ffc, 4 }, { 0x2000, 4096 }, { 0x1000, 4092 },
};

/* PRP1 in the middle of a page, PRP2 a page that does not follow it */
static const FemuG1Piece femu_g1_prp2_pieces[] = {
    { 0x0800, 2048 }, { 0x2000, 2048 },
};

/* lay @buf out over the pieces of @image, in transfer order */
static void femu_g1_scatter(uint8_t *image, const FemuG1Piece *p, int nr,
                            const uint8_t *buf)
{
    int i;

    for (i = 0; i < nr; i++) {
        memcpy(image + p[i].off, buf, p[i].len);
        buf += p[i].len;
    }
}

/* an I/O command of @nlb blocks at @slba with the data pointer of @dptr */
static uint16_t femu_g1_dptr_io(FemuCtrlState *c, uint8_t opcode,
                                uint64_t slba, uint32_t nlb,
                                const NvmeCmd *dptr)
{
    NvmeRwCmd rw;

    memset(&rw, 0, sizeof(rw));
    rw.opcode = opcode;
    rw.flags = dptr->flags;
    rw.nsid = cpu_to_le32(1);
    memcpy(&rw.dptr, &dptr->dptr, sizeof(rw.dptr));
    rw.slba = cpu_to_le64(slba);
    rw.nlb = cpu_to_le16(nlb - 1);
    return femu_io(c, (NvmeCmd *)&rw);
}

/*
 * Write @nlb blocks at @slba through the layout of @dptr, whose pieces lie
 * in @area. A Read through whole pages returns them in transfer order, and a
 * Read through the layout fills the pieces and no byte beside them.
 */
static void femu_g1_layout_round(FemuCtrlState *c, uint64_t slba,
                                 uint32_t nlb, const NvmeCmd *dptr,
                                 uint64_t area, const FemuG1Piece *p, int nr,
                                 uint64_t plain, uint64_t list, uint32_t seed)
{
    QTestState *qts = c->pdev->bus->qts;
    const uint32_t bytes = nlb * 512;
    const uint32_t area_bytes = 4 * FEMU_G1_PAGE;
    g_autofree uint8_t *wbuf = g_malloc(bytes);
    g_autofree uint8_t *rbuf = g_malloc0(bytes);
    g_autofree uint8_t *want = g_malloc0(area_bytes);
    g_autofree uint8_t *got = g_malloc0(area_bytes);

    femu_g1_fill(wbuf, bytes, seed);
    femu_g1_scatter(want, p, nr, wbuf);
    qtest_memwrite(qts, area, want, area_bytes);
    g_assert_cmphex(femu_g1_dptr_io(c, NVME_CMD_WRITE, slba, nlb, dptr), ==,
                    NVME_SUCCESS);

    qtest_memset(qts, plain, 0, bytes);
    g_assert_cmphex(femu_g1_rw(c, NVME_CMD_READ, slba, nlb, plain, list), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, plain, rbuf, bytes);
    g_assert_cmpint(memcmp(wbuf, rbuf, bytes), ==, 0);

    memset(want, 0xee, area_bytes);
    femu_g1_scatter(want, p, nr, wbuf);
    qtest_memset(qts, area, 0xee, area_bytes);
    g_assert_cmphex(femu_g1_dptr_io(c, NVME_CMD_READ, slba, nlb, dptr), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, area, got, area_bytes);
    g_assert_cmpint(memcmp(want, got, area_bytes), ==, 0);
}

/*
 * Data pointers as a passthrough command of a host can carry them, on
 * 512-byte blocks. An SGL of two chained segments holds data blocks of 1,
 * 1023, 3073 and 4095 bytes at odd addresses. A PRP1 that leaves 4 bytes of
 * its page takes a list whose two entries end a list page, and a PRP1 in
 * the middle of a page takes a PRP2 page. Compare reads the scattered
 * buffer, and Dataset Management reads a range list that crosses a page.
 * A list that describes one byte more than the command moves is refused.
 */
void femu_test_g1_dptr_layouts(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t area = guest_alloc(alloc, 4 * FEMU_G1_PAGE);
    uint64_t plain = guest_alloc(alloc, 2 * FEMU_G1_PAGE);
    uint64_t list = guest_alloc(alloc, FEMU_G1_PAGE);
    uint64_t seg = guest_alloc(alloc, 2 * FEMU_G1_PAGE);
    NvmeSglDescriptor d[3];
    NvmeSglDescriptor next;
    uint8_t range[16];
    uint64_t ents[2];
    NvmeCmd dptr;
    NvmeCmd dsm;
    uint8_t byte;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    /* segment one: two data blocks and the pointer to the last segment */
    memset(d, 0, sizeof(d));
    d[0].addr = cpu_to_le64(area + femu_g1_sgl_pieces[0].off);
    d[0].len = cpu_to_le32(femu_g1_sgl_pieces[0].len);
    d[1].addr = cpu_to_le64(area + femu_g1_sgl_pieces[1].off);
    d[1].len = cpu_to_le32(femu_g1_sgl_pieces[1].len);
    d[2].addr = cpu_to_le64(seg + FEMU_G1_PAGE);
    d[2].len = cpu_to_le32(2 * sizeof(d[0]));
    d[2].type = NVME_SGL_DESCR_TYPE_LAST_SEGMENT << 4;
    qtest_memwrite(qts, seg, d, 3 * sizeof(d[0]));
    memset(d, 0, sizeof(d));
    d[0].addr = cpu_to_le64(area + femu_g1_sgl_pieces[2].off);
    d[0].len = cpu_to_le32(femu_g1_sgl_pieces[2].len);
    d[1].addr = cpu_to_le64(area + femu_g1_sgl_pieces[3].off);
    d[1].len = cpu_to_le32(femu_g1_sgl_pieces[3].len);
    qtest_memwrite(qts, seg + FEMU_G1_PAGE, d, 2 * sizeof(d[0]));
    memset(&dptr, 0, sizeof(dptr));
    dptr.flags = 1 << 6;                    /* PSDT: SGL */
    dptr.dptr.sgl.addr = cpu_to_le64(seg);
    dptr.dptr.sgl.len = cpu_to_le32(3 * sizeof(d[0]));
    dptr.dptr.sgl.type = NVME_SGL_DESCR_TYPE_SEGMENT << 4;
    femu_g1_layout_round(&c, 64, 16, &dptr, area, femu_g1_sgl_pieces,
                         G_N_ELEMENTS(femu_g1_sgl_pieces), plain, list, 11);

    /* Compare takes the same list; one changed byte is a miscompare */
    g_assert_cmphex(femu_g1_dptr_io(&c, NVME_CMD_COMPARE, 64, 16, &dptr), ==,
                    NVME_SUCCESS);
    for (i = 0; i < (int)G_N_ELEMENTS(femu_g1_sgl_pieces); i++) {
        uint64_t last = area + femu_g1_sgl_pieces[i].off +
                        femu_g1_sgl_pieces[i].len - 1;

        byte = qtest_readb(qts, last);
        qtest_writeb(qts, last, byte ^ 0xff);
        g_assert_cmphex(femu_g1_dptr_io(&c, NVME_CMD_COMPARE, 64, 16, &dptr),
                        ==, NVME_CMP_FAILURE);
        g_assert_cmphex(femu_io_status & NVME_DNR, ==, NVME_DNR);
        qtest_writeb(qts, last, byte);
    }
    g_assert_cmphex(femu_g1_dptr_io(&c, NVME_CMD_COMPARE, 64, 16, &dptr), ==,
                    NVME_SUCCESS);

    /* the last data block one byte long, then one byte short */
    d[1].len = cpu_to_le32(femu_g1_sgl_pieces[3].len + 1);
    qtest_memwrite(qts, seg + FEMU_G1_PAGE, d, 2 * sizeof(d[0]));
    g_assert_cmphex(femu_g1_dptr_io(&c, NVME_CMD_WRITE, 64, 16, &dptr), ==,
                    NVME_DATA_SGL_LEN_INVALID);
    g_assert_cmphex(femu_io_status & NVME_DNR, ==, NVME_DNR);
    d[1].len = cpu_to_le32(femu_g1_sgl_pieces[3].len - 1);
    qtest_memwrite(qts, seg + FEMU_G1_PAGE, d, 2 * sizeof(d[0]));
    g_assert_cmphex(femu_g1_dptr_io(&c, NVME_CMD_WRITE, 64, 16, &dptr), ==,
                    NVME_DATA_SGL_LEN_INVALID);
    g_assert_cmphex(femu_io_status & NVME_DNR, ==, NVME_DNR);

    /*
     * A third data block of one byte after the 8192 bytes of the command.
     * The controller does not report support for a list longer than the
     * data, so it refuses the command and moves nothing.
     */
    d[1].len = cpu_to_le32(femu_g1_sgl_pieces[3].len);
    d[2].addr = cpu_to_le64(area + 3 * FEMU_G1_PAGE + 1);
    d[2].len = cpu_to_le32(1);
    qtest_memwrite(qts, seg + FEMU_G1_PAGE, d, 3 * sizeof(d[0]));
    memset(&next, 0, sizeof(next));
    next.addr = cpu_to_le64(seg + FEMU_G1_PAGE);
    next.len = cpu_to_le32(3 * sizeof(d[0]));
    next.type = NVME_SGL_DESCR_TYPE_LAST_SEGMENT << 4;
    qtest_memwrite(qts, seg + 2 * sizeof(d[0]), &next, sizeof(next));
    qtest_memset(qts, area, 0xee, 4 * FEMU_G1_PAGE);
    g_assert_cmphex(femu_g1_dptr_io(&c, NVME_CMD_WRITE, 64, 16, &dptr), ==,
                    NVME_DATA_SGL_LEN_INVALID);
    g_assert_cmphex(femu_io_status & NVME_DNR, ==, NVME_DNR);
    g_assert_cmphex(femu_g1_dptr_io(&c, NVME_CMD_READ, 64, 16, &dptr), ==,
                    NVME_DATA_SGL_LEN_INVALID);
    g_assert_cmphex(femu_io_status & NVME_DNR, ==, NVME_DNR);
    g_assert_cmphex(femu_g1_dptr_io(&c, NVME_CMD_COMPARE, 64, 16, &dptr), ==,
                    NVME_DATA_SGL_LEN_INVALID);
    femu_g1_all(qts, area, 4 * FEMU_G1_PAGE, 0xee);
    /* the refused Write of 0xee bytes changed no block */
    g_assert_cmphex(femu_g1_rw(&c, NVME_CMD_READ, 64, 16, plain, list), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(qtest_readl(qts, plain), !=, 0xeeeeeeee);

    /* PRP1 at 0xffc; the list is the last two entries of its page */
    ents[0] = cpu_to_le64(area + femu_g1_prp_pieces[1].off);
    ents[1] = cpu_to_le64(area + femu_g1_prp_pieces[2].off);
    qtest_memwrite(qts, seg + FEMU_G1_PAGE - sizeof(ents), ents,
                   sizeof(ents));
    memset(&dptr, 0, sizeof(dptr));
    dptr.dptr.prp1 = cpu_to_le64(area + femu_g1_prp_pieces[0].off);
    dptr.dptr.prp2 = cpu_to_le64(seg + FEMU_G1_PAGE - sizeof(ents));
    femu_g1_layout_round(&c, 96, 16, &dptr, area, femu_g1_prp_pieces,
                         G_N_ELEMENTS(femu_g1_prp_pieces), plain, list, 12);

    /* PRP1 at 0x800 and a PRP2 page, for a transfer of one page */
    memset(&dptr, 0, sizeof(dptr));
    dptr.dptr.prp1 = cpu_to_le64(area + femu_g1_prp2_pieces[0].off);
    dptr.dptr.prp2 = cpu_to_le64(area + femu_g1_prp2_pieces[1].off);
    femu_g1_layout_round(&c, 112, 8, &dptr, area, femu_g1_prp2_pieces,
                         G_N_ELEMENTS(femu_g1_prp2_pieces), plain, list, 13);

    /*
     * Dataset Management, two ranges: blocks 128 to 135 in the last 16 bytes
     * of a page, blocks 168 to 175 at PRP2. The page after the first range
     * holds a range the command does not name, blocks 136 to 143.
     */
    qtest_memset(qts, plain, 0x5c, 2 * FEMU_G1_PAGE);
    g_assert_cmphex(femu_g1_rw(&c, NVME_CMD_WRITE, 128, 16, plain, list), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(femu_g1_rw(&c, NVME_CMD_WRITE, 160, 16, plain, list), ==,
                    NVME_SUCCESS);
    qtest_memset(qts, area, 0, 4 * FEMU_G1_PAGE);
    for (i = 0; i < 3; i++) {
        static const uint64_t first[] = { 128, 136, 168 };
        static const uint32_t at[] = { 0x0ff0, 0x1000, 0x2000 };

        memset(range, 0, sizeof(range));
        stl_le_p(range + 4, 8);
        stq_le_p(range + 8, first[i]);
        qtest_memwrite(qts, area + at[i], range, sizeof(range));
    }
    memset(&dsm, 0, sizeof(dsm));
    dsm.opcode = NVME_CMD_DSM;
    dsm.nsid = cpu_to_le32(1);
    dsm.dptr.prp1 = cpu_to_le64(area + 0x0ff0);
    dsm.dptr.prp2 = cpu_to_le64(area + 0x2000);
    dsm.cdw10 = cpu_to_le32(1);
    dsm.cdw11 = cpu_to_le32(FEMU_DSM_AD);
    g_assert_cmphex(femu_io(&c, &dsm), ==, NVME_SUCCESS);
    for (i = 0; i < 4; i++) {
        static const uint64_t first[] = { 128, 136, 160, 168 };
        static const uint8_t want[] = { 0, 0x5c, 0x5c, 0 };

        qtest_memset(qts, plain, 0xee, FEMU_G1_PAGE);
        g_assert_cmphex(femu_g1_rw(&c, NVME_CMD_READ, first[i], 8, plain,
                                   list), ==, NVME_SUCCESS);
        femu_g1_all(qts, plain, FEMU_G1_PAGE, want[i]);
    }

    guest_free(alloc, seg);
    guest_free(alloc, list);
    guest_free(alloc, plain);
    guest_free(alloc, area);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    qos_invalidate_command_line();
}
