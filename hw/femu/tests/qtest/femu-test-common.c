/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QTest helpers for the FEMU SSD emulator that the tests of more than one
 * mode use.
 */

#include "qemu/osdep.h"
#include "femu-test.h"

uint64_t femu_sq_doorbell(FemuCtrlState *c, uint16_t qid)
{
    return 0x1000 + (2 * qid) * (4 << c->db_stride);
}

uint64_t femu_cq_doorbell(FemuCtrlState *c, uint16_t qid)
{
    return 0x1000 + (2 * qid + 1) * (4 << c->db_stride);
}

void femu_queue_init(FemuCtrlState *c, FemuQueue *q, uint16_t qid)
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

void femu_queue_free(FemuCtrlState *c, FemuQueue *q)
{
    guest_free(c->alloc, q->sq_addr);
    guest_free(c->alloc, q->cq_addr);
}

/* queue the command and ring the controller, by register or by shadow */
void femu_submit(FemuCtrlState *c, FemuQueue *q, NvmeCmd *cmd)
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

/*
 * Wait for the next completion and return its status with the phase bit
 * removed; hand back the identifier and dword 0 when asked.
 */
uint16_t femu_complete(FemuCtrlState *c, FemuQueue *q, uint16_t *cid,
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

uint16_t femu_admin_result(FemuCtrlState *c, NvmeCmd *cmd,
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

uint16_t femu_admin(FemuCtrlState *c, NvmeCmd *cmd)
{
    return femu_admin_result(c, cmd, NULL);
}

/* map the BAR, program the admin queues and write CC; do not wait */
void femu_enable_start(FemuCtrlState *c, QPCIDevice *pdev,
                       QGuestAllocator *alloc, uint32_t cc)
{
    uint64_t cap;
    uint32_t acq;

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
}

void femu_enable_cc(FemuCtrlState *c, QPCIDevice *pdev,
                    QGuestAllocator *alloc, uint32_t cc)
{
    uint32_t csts;
    int waited = 0;

    femu_enable_start(c, pdev, alloc, cc);
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
void femu_enable(FemuCtrlState *c, QPCIDevice *pdev,
                 QGuestAllocator *alloc)
{
    c->pdev = pdev;
    c->alloc = alloc;
    femu_queue_init(c, &c->admin, 0);
    femu_enable_cc(c, pdev, alloc, (6 << 16) | (4 << 20) | 1);
}

/* as femu_enable, with CC.CSS 110b: key-value I/O runs only so, as in Linux */
void femu_enable_csi(FemuCtrlState *c, QPCIDevice *pdev,
                     QGuestAllocator *alloc)
{
    c->pdev = pdev;
    c->alloc = alloc;
    femu_queue_init(c, &c->admin, 0);
    femu_enable_cc(c, pdev, alloc,
                   (6 << 16) | (4 << 20) | (FEMU_CC_CSS_CSI << 4) | 1);
}

void femu_disable(FemuCtrlState *c)
{
    qpci_io_writel(c->pdev, c->bar, 0x14, 0);
    femu_queue_free(c, &c->admin);
    qpci_iounmap(c->pdev, c->bar);
}

/* one I/O queue pair with interrupts left off: completions are polled */
void femu_create_io_queues(FemuCtrlState *c)
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

uint16_t femu_rw(FemuCtrlState *c, uint8_t opcode, uint64_t slba,
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
void femu_round_trip(FemuCtrlState *c, uint8_t seed)
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

uint64_t femu_alloc_64k(QGuestAllocator *alloc, uint64_t *raw)
{
    *raw = guest_alloc(alloc, 4 * FEMU_64K);
    return (*raw + FEMU_64K - 1) & ~(FEMU_64K - 1);
}

uint16_t femu_zone_action(FemuCtrlState *c, uint64_t slba,
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

void femu_zone_report(FemuCtrlState *c, uint64_t buf, uint8_t *report)
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

uint16_t femu_get_feature(FemuCtrlState *c, uint8_t fid, uint8_t sel,
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

uint16_t femu_set_feature(FemuCtrlState *c, uint8_t fid, bool save,
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
 * Get Log Page. Length is a 0's based dword count split across two command
 * fields, and the offset is a byte offset split the same way.
 */
uint16_t femu_get_log(FemuCtrlState *c, uint8_t lid, uint64_t buf,
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

void femu_hybrid_flush(FemuCtrlState *c)
{
    NvmeCmd cmd = { 0 };
    uint16_t got;

    cmd.opcode = NVME_CMD_FLUSH;
    cmd.nsid = cpu_to_le32(1);
    femu_submit(c, &c->io, &cmd);
    g_assert_cmpint(femu_complete(c, &c->io, &got, NULL), ==, NVME_SUCCESS);
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
uint16_t femu_ruh_update(FemuCtrlState *c, uint64_t pids, uint16_t npid)
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

/* Get or Set the Timestamp feature through an 8-byte buffer at buf */
uint16_t femu_timestamp(FemuCtrlState *c, bool set, uint8_t sel,
                        uint32_t save, uint64_t buf)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = set ? NVME_ADM_CMD_SET_FEATURES : NVME_ADM_CMD_GET_FEATURES;
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(FEMU_FID_TIMESTAMP | sel << 8 | save << 31);
    return FEMU_SC(femu_admin(c, &cmd));
}

uint16_t femu_format(FemuCtrlState *c, uint32_t nsid, uint8_t lba_idx,
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
void femu_identify_ns(FemuCtrlState *c, uint64_t *nsze,
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
 * Write @npages 4 KiB pages from @page, every one of them taken from @data,
 * into placement identifier @pid, or unplaced when @pid is negative.
 */
uint16_t femu_write_pages_placed(FemuCtrlState *c, uint64_t page,
                                 uint32_t npages, uint64_t data,
                                 uint64_t list, int pid)
{
    NvmeRwCmd rw;
    uint16_t want = c->cid;
    uint16_t got;
    uint16_t status;
    uint32_t i;

    g_assert_cmpuint(npages, >=, 1);
    g_assert_cmpuint(npages, <=, 4096 / 8 + 1);
    for (i = 0; i + 1 < npages; i++) {
        qtest_writeq(c->pdev->bus->qts, list + i * 8, data);
    }
    memset(&rw, 0, sizeof(rw));
    rw.opcode = NVME_CMD_WRITE;
    rw.nsid = cpu_to_le32(1);
    rw.dptr.prp1 = cpu_to_le64(data);
    rw.dptr.prp2 = cpu_to_le64(npages > 2 ? list : npages == 2 ? data : 0);
    rw.slba = cpu_to_le64(page * (4096 / c->lba_size));
    rw.nlb = cpu_to_le16(npages * (4096 / c->lba_size) - 1);
    if (pid >= 0) {
        rw.control = cpu_to_le16(2 << 4);
        rw.dspec = cpu_to_le16(pid);
    }
    femu_submit(c, &c->io, (NvmeCmd *)&rw);
    status = femu_complete(c, &c->io, &got, NULL);
    g_assert_cmpint(got, ==, want);

    return status;
}

uint16_t femu_write_pages(FemuCtrlState *c, uint64_t page,
                          uint32_t npages, uint64_t data, uint64_t list)
{
    return femu_write_pages_placed(c, page, npages, data, list, -1);
}

/* Read @npages 4 KiB pages from @page, every one of them into @data. */
uint16_t femu_read_pages(FemuCtrlState *c, uint64_t page,
                         uint32_t npages, uint64_t data, uint64_t list)
{
    NvmeRwCmd rw;
    uint16_t want = c->cid;
    uint16_t got;
    uint16_t status;
    uint32_t i;

    g_assert_cmpuint(npages, >=, 1);
    g_assert_cmpuint(npages, <=, 4096 / 8 + 1);
    for (i = 0; i + 1 < npages; i++) {
        qtest_writeq(c->pdev->bus->qts, list + i * 8, data);
    }
    memset(&rw, 0, sizeof(rw));
    rw.opcode = NVME_CMD_READ;
    rw.nsid = cpu_to_le32(1);
    rw.dptr.prp1 = cpu_to_le64(data);
    rw.dptr.prp2 = cpu_to_le64(npages > 2 ? list : npages == 2 ? data : 0);
    rw.slba = cpu_to_le64(page * (4096 / c->lba_size));
    rw.nlb = cpu_to_le16(npages * (4096 / c->lba_size) - 1);
    femu_submit(c, &c->io, (NvmeCmd *)&rw);
    status = femu_complete(c, &c->io, &got, NULL);
    g_assert_cmpint(got, ==, want);

    return status;
}

/* x-ftl-check: mappings held, mappings to a page not holding them, orphans */
void femu_ftl_check(QTestState *qts, uint64_t *mapped, uint64_t *lost,
                    uint64_t *orphans)
{
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                           "'path':'/machine/peripheral/gc-test',"
                           "'property':'x-ftl-check'}}");

    g_assert_true(qdict_haskey(rsp, "return"));
    g_assert_cmpint(sscanf(qdict_get_str(rsp, "return"),
                           "%" SCNu64 " %" SCNu64 " %" SCNu64,
                           mapped, lost, orphans), ==, 3);
    qobject_unref(rsp);
}

/* field @i of x-ftl-trace on the device with id @id */
uint64_t femu_ftl_trace_id(QTestState *qts, const char *id, int i)
{
    g_autofree char *path = g_strdup_printf("/machine/peripheral/%s", id);
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                           "'path':%s,'property':'x-ftl-trace'}}", path);
    g_auto(GStrv) v = NULL;
    uint64_t ns;

    g_assert_true(qdict_haskey(rsp, "return"));
    v = g_strsplit(qdict_get_str(rsp, "return"), " ", 0);
    g_assert_cmpuint(g_strv_length(v), ==, FTL_TRACE_FIELDS);
    ns = g_ascii_strtoull(v[i], NULL, 10);
    qobject_unref(rsp);
    return ns;
}

/* field @i of x-ftl-trace on the device with id "trace" */
uint64_t femu_ftl_trace_field(QTestState *qts, int i)
{
    return femu_ftl_trace_id(qts, "trace", i);
}

/*
 * query-femu over QMP. @args is the arguments object without its braces;
 * the reply is returned whole, so a caller can check "return" or "error".
 */
QDict *femu_query(QTestState *qts, const char *args)
{
    g_autofree char *json = g_strdup_printf("{%s}", args);
    QObject *obj = qobject_from_json(json, &error_abort);

    return qtest_qmp(qts, "{'execute':'query-femu','arguments':%p}", obj);
}

/* Expect an error whose description contains @want. */
void femu_query_fails(QTestState *qts, const char *args,
                      const char *want)
{
    QDict *rsp = femu_query(qts, args);
    QDict *err = qdict_get_qdict(rsp, "error");

    g_assert_nonnull(err);
    g_test_message("query-femu {%s}: %s", args, qdict_get_str(err, "desc"));
    g_assert_nonnull(strstr(qdict_get_str(err, "desc"), want));
    qobject_unref(rsp);
}

/* The only namespace of a successful reply; the reply is handed back too. */
QDict *femu_query_ns(QTestState *qts, const char *args, QDict **rsp)
{
    QDict *ret;
    QList *nss;

    *rsp = femu_query(qts, args);
    ret = qdict_get_qdict(*rsp, "return");
    if (!ret) {
        g_test_message("query-femu {%s}: %s", args,
                       qdict_get_str(qdict_get_qdict(*rsp, "error"), "desc"));
    }
    g_assert_nonnull(ret);
    nss = qdict_get_qlist(ret, "namespaces");
    g_assert_cmpuint(qlist_size(nss), ==, 1);
    return qobject_to(QDict, qlist_peek(nss));
}

/* The summary must report what log page C0h reports for one namespace. */
void femu_query_matches_c0h(FemuCtrlState *c, uint64_t buf)
{
    QTestState *qts = c->pdev->bus->qts;
    uint8_t log[512];
    QDict *rsp;
    QDict *ns = femu_query_ns(qts, "", &rsp);
    QDict *ctr = qdict_get_qdict(ns, "counters");
    uint64_t host;
    uint32_t waf;

    g_assert_cmpint(FEMU_SC(femu_get_log(c, FEMU_LOG_FEMU_STATS, buf,
                                         sizeof(log), 0)), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, log, sizeof(log));
    host = ldq_le_p(log + 8);
    waf = ldl_le_p(log);
    g_assert_cmpuint(qdict_get_int(ctr, "host-write-pages"), ==, host);
    g_assert_cmpuint(qdict_get_int(ctr, "gc-write-pages"), ==,
                     ldq_le_p(log + 16));
    g_assert_cmpuint(qdict_get_int(ctr, "nand-write-pages"), ==,
                     ldq_le_p(log + 24));
    if (host) {
        double got = qdict_get_double(ctr, "waf");

        g_assert_cmpuint((uint32_t)(got * 1000 + 0.000001), ==, waf);
    } else {
        g_assert_false(qdict_haskey(ctr, "waf"));
    }
    /* translation pages: present with mapping=dftl, else zero in C0h */
    if (qdict_haskey(ctr, "map-write-pages")) {
        g_assert_cmpuint(qdict_get_int(ctr, "map-write-pages"), ==,
                         ldq_le_p(log + 280));
        g_assert_cmpuint(qdict_get_int(ctr, "map-read-pages"), ==,
                         ldq_le_p(log + 288));
    } else {
        g_assert_cmpuint(ldq_le_p(log + 280), ==, 0);
        g_assert_cmpuint(ldq_le_p(log + 288), ==, 0);
    }
    qobject_unref(rsp);
}

/*
 * Every line in one call: the valid pages summed over lines must be the
 * mappings the FTL holds, the states must add up to the line counts, and
 * the block erase total must lie within what the per-line wear allows.
 */
void femu_query_check_lines(QTestState *qts, const char *path,
                            uint64_t want_valid)
{
    g_autofree char *args = g_strdup_printf(
        "'path':'%s','kind':'lines','limit':4096", path);
    uint32_t free_lines = 0;
    uint32_t victim = 0;
    uint32_t full = 0;
    uint32_t retired = 0;
    uint32_t spare = 0;
    uint32_t reserve = 0;
    uint64_t vpc = 0;
    uint64_t erase_lo = 0;
    uint64_t erase_hi = 0;
    uint64_t erases;
    uint64_t blocks;
    uint64_t mapped, lost, orphans, tp_pages, tp_bad;
    QListEntry *e;
    QDict *rsp;
    QDict *ns = femu_query_ns(qts, args, &rsp);
    QDict *geo = qdict_get_qdict(ns, "geometry");
    QDict *cnt = qdict_get_qdict(ns, "line-counts");
    QList *lines = qdict_get_qlist(ns, "lines");
    uint32_t id = 0;

    g_assert_cmpuint(qlist_size(lines), ==, qdict_get_int(cnt, "total"));
    g_assert_false(qdict_haskey(ns, "next-offset"));
    blocks = qdict_get_int(geo, "channels") *
             qdict_get_int(geo, "luns-per-channel") *
             qdict_get_int(geo, "planes-per-lun");
    QLIST_FOREACH_ENTRY(lines, e) {
        QDict *l = qobject_to(QDict, qlist_entry_obj(e));
        const char *st = qdict_get_str(l, "state");

        g_assert_cmpuint(qdict_get_int(l, "id"), ==, id++);
        vpc += qdict_get_int(l, "vpc");
        g_assert_cmpuint(qdict_get_int(l, "vpc") + qdict_get_int(l, "ipc"),
                         <=, qdict_get_int(geo, "pages-per-line"));
        g_assert_cmpuint(qdict_get_int(l, "erase-min"), <=,
                         qdict_get_int(l, "erase-max"));
        erase_lo += qdict_get_int(l, "erase-min") * blocks;
        erase_hi += qdict_get_int(l, "erase-max") * blocks;
        free_lines += !strcmp(st, "free");
        victim += !strcmp(st, "victim");
        full += !strcmp(st, "full");
        retired += !strcmp(st, "retired");
        spare += !strcmp(st, "spare");
        reserve += !strcmp(st, "reserve");
        g_assert_cmpstr(st, !=, "unlisted");
        if (!strcmp(st, "free") || !strcmp(st, "retired") ||
            !strcmp(st, "spare") || !strcmp(st, "reserve")) {
            g_assert_cmpuint(qdict_get_int(l, "vpc"), ==, 0);
        }
    }
    g_assert_cmpuint(free_lines, ==, qdict_get_int(cnt, "free"));
    g_assert_cmpuint(victim, ==, qdict_get_int(cnt, "victim"));
    g_assert_cmpuint(full, ==, qdict_get_int(cnt, "full"));
    g_assert_cmpuint(retired, ==, qdict_get_int(cnt, "retired"));
    g_assert_cmpuint(spare, ==, qdict_get_int(cnt, "spare"));
    g_assert_cmpuint(reserve, ==, qdict_haskey(cnt, "reserve") ?
                     qdict_get_int(cnt, "reserve") : 0);
    erases = qdict_get_int(qdict_get_qdict(ns, "counters"), "block-erases");
    g_assert_cmpuint(erase_lo, <=, erases);
    g_assert_cmpuint(erases, <=, erase_hi);
    qobject_unref(rsp);

    rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{'path':%s,"
                    "'property':'x-ftl-check'}}", path);
    g_assert_cmpint(sscanf(qdict_get_str(rsp, "return"),
                           "%" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64
                           " %" SCNu64, &mapped, &lost, &orphans, &tp_pages,
                           &tp_bad), ==, 5);
    qobject_unref(rsp);
    g_assert_cmpuint(lost, ==, 0);
    g_assert_cmpuint(orphans, ==, 0);
    g_assert_cmpuint(tp_bad, ==, 0);
    g_test_message("lines: %" PRIu64 " valid, %" PRIu64 " mapped, %" PRIu64
                   " translation pages, %" PRIu64 " erases", vpc, mapped,
                   tp_pages, erases);
    /* a valid page holds data or a translation page of mapping=dftl */
    g_assert_cmpuint(vpc, ==, mapped + tp_pages);
    g_assert_cmpuint(mapped, ==, want_valid);
}

static const char *const femu_media_keys[20] = {
    "page-transfer-ns", "read-command-ns", "program-command-ns",
    "erase-command-ns", "copyback-read-command-ns",
    "copyback-program-command-ns", "status-ns", "data-out-lead-ns",
    "data-out-tail-ns", "plane-select-ns", "data-in-edges-ns",
    "program-confirm-ns", "plane-read-busy-ns", "plane-program-busy-ns",
    "plane-erase-busy-ns", "data-in-gap-ns", "data-out-edges-ns",
    "read-cache-busy-ns", "cache-step-ns", "cache-select-ns",
};

/*
 * Mode 26 values from the design table (x8, 2 column and 3 row cycles,
 * tWC 25, tWB 100, tADL 412, tWHR 80, tRHW 100, tRPRE2 25, tRPSTH 15,
 * tDSC 0.417): page ceil(4096 * 417 / 2000) = 855; read 7 * 25 + 100;
 * program 6 * 25 + 412; erase 5 * 25 + 100; status 25 + 80 + 25 + 0.417 +
 * 15 + 100, or with 78h 4 * 25 + ...; lead 25 + 25, or 7 * 25 + 25; tail
 * 15 + 100; edges 25 + 6.5 + 25; confirm 25 + 100; tPL*BSY 500.
 */
static const FemuMediaWant femu_media_wants[] = {
    { "m26-2lun", "bbssd", true, 26,
      { 855, 275, 562, 225, 275, 275, 321, 200, 115, 200, 57, 125,
        500, 500, 500 }, true, true, true },
    { "m26-1lun", "bbssd", true, 26,
      { 855, 275, 562, 225, 275, 275, 246, 50, 115, 200, 57, 125,
        500, 500, 500 }, true, true, false },
    /* today's default: no bus, no plane gap */
    { "default", "bbssd", false, -1, { 0 }, false, false, false },
    /* the hand-set phases: every command and the plane select take 1000 */
    { "staged", "bbssd", true, -1,
      { 10000, 1000, 1000, 1000, 1000, 1000, 500, 0, 0, 1000, 0, 0,
        0, 0, 900 }, false, false, false },
    { "csd-m26", "csd", true, 26,
      { 855, 275, 562, 225, 275, 275, 246, 50, 115, 200, 57, 125,
        500, 500, 500 }, true, true, false },
    { "kvssd", "kvssd", false, -1, { 0 }, false, false, false },
    { "zns", "znssd", true, -1,
      { 3000, 700, 700, 700, 700, 700, 200, 0, 0, 700, 0, 0, 0, 0, 0 },
      false, false, false },
    /* OC 1.2 keeps a page time, which the bus charges only when it is on */
    { "oc12-off", "ocssd", false, -1, { 0 }, false, false, false },
    { "oc12-on", "ocssd", true, -1, { 7000 }, false, false, false },
    { "oc20", "ocssd", false, -1, { 0 }, false, false, false },
    /* FDP and the KV timing model keep the profile's media timing */
    { "fdp-m26", "bbssd", true, 26,
      { 855, 275, 562, 225, 275, 275, 321, 200, 115, 200, 57, 125,
        500, 500, 500 }, true, true, true },
    { "kvssd-m26", "kvssd", true, 26,
      { 855, 275, 562, 225, 275, 275, 321, 200, 115, 200, 57, 125,
        500, 500, 500 }, true, true, true },
    /* a plane gap applies with the bus off */
    { "gap-no-bus", "bbssd", false, -1,
      { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 900 },
      false, false, false },
    /*
     * SCA, two LUNs: 12 ns packets on the CA bus. Read 7 packets + tWB;
     * program 80h, address, 12h; erase 5 packets + tWB; copyback program
     * 8 packets + tWB; 78h status 4 packets + 80 + 4 + 20 + 40 + 85;
     * select 7 packets; write burst 87 + 62; 10h + tWB; tCDL gap 313;
     * read burst 92 + 25.209 + 50.
     */
    { "m26-sca-2lun", "bbssd", true, 26,
      { 855, 184, 84, 160, 184, 196, 277, 84, 0, 84, 149, 112,
        500, 500, 500, 313, 168 }, true, true, true, true },
    /* KV reads one page at a time: no read cache sequence */
    { "kvssd-m26-cache", "kvssd", true, 26,
      { 855, 275, 562, 225, 275, 275, 321, 200, 115, 200, 57, 125,
        500, 500, 500 }, true, true, true },
    /* read cache: tRCBSY 4000 from trcbsy, 31h + tWB, 78h before it */
    { "m26-cache-2lun", "bbssd", true, 26,
      { 855, 275, 562, 225, 275, 275, 321, 200, 115, 200, 57, 125,
        500, 500, 500, 0, 0, 4000, 125, 321 }, true, true, true, false,
      true },
};

/*
 * Q5 and Q6: query-femu reports the bus phases the media layer charges, for
 * every mode that has a media layer. kind lines is refused on a namespace
 * that has the media timing only.
 */
const FemuMediaWant *femu_media_want(const char *name)
{
    for (int i = 0; i < ARRAY_SIZE(femu_media_wants); i++) {
        if (!strcmp(femu_media_wants[i].name, name)) {
            return &femu_media_wants[i];
        }
    }
    g_assert_not_reached();
}

bool femu_media_only(const char *mode)
{
    return !strcmp(mode, "csd") || !strcmp(mode, "kvssd") ||
           !strcmp(mode, "ocssd");
}

/* one namespace entry of a query-femu reply against @w */
void femu_media_check(QDict *ns, const FemuMediaWant *w)
{
    QDict *md;

    g_assert_cmpstr(qdict_get_str(ns, "mode"), ==, w->mode);
    md = qdict_get_qdict(ns, "media");
    g_assert_nonnull(md);
    /*
     * A media-only entry has nothing but its identity and the timing; a
     * kvssd one also has its value packing, on by default.
     */
    if (femu_media_only(w->mode)) {
        bool pack = !strcmp(w->mode, "kvssd");

        g_assert_cmpint(qdict_haskey(ns, "pack"), ==, pack);
        g_assert_cmpuint(qdict_size(ns), ==, 3 + pack);
    }
    g_assert_cmpint(qdict_get_bool(md, "staged-bus"), ==, w->staged);
    g_assert_cmpint(qdict_get_bool(md, "onfi-profile"), ==, w->onfi >= 0);
    g_assert_cmpint(qdict_haskey(md, "onfi-mode"), ==, w->onfi >= 0);
    if (w->onfi >= 0) {
        g_assert_cmpint(qdict_get_int(md, "onfi-mode"), ==, w->onfi);
    }
    /* without a parameter page, 2 column and 3 row cycles */
    g_assert_cmpint(qdict_get_int(md, "column-cycles"), ==,
                    w->onfi >= 0 ? 2 : 0);
    g_assert_cmpint(qdict_get_int(md, "row-cycles"), ==, w->onfi >= 0 ? 3 : 0);
    for (int i = 0; i < ARRAY_SIZE(femu_media_keys); i++) {
        g_test_message("%s %s: %" PRId64, w->name, femu_media_keys[i],
                       qdict_get_int(md, femu_media_keys[i]));
        g_assert_cmpuint(qdict_get_int(md, femu_media_keys[i]), ==,
                         w->ns[i]);
    }
    g_assert_cmpint(qdict_get_bool(md, "onfi-order"), ==, w->order);
    g_assert_cmpint(qdict_get_bool(md, "page-register-hold"), ==, w->hold);
    g_assert_cmpint(qdict_get_bool(md, "status-per-plane"), ==,
                    w->per_plane);
    g_assert_cmpint(qdict_get_bool(md, "sca"), ==, w->sca);
    g_assert_cmpint(qdict_get_bool(md, "cache-read"), ==, w->cache);
}

/* deallocate @npages 4 KiB pages from @page */
uint16_t femu_dealloc_pages(FemuCtrlState *c, uint64_t page,
                            uint32_t npages, uint64_t buf)
{
    uint8_t range[16] = { 0 };
    NvmeCmd cmd = { 0 };

    stl_le_p(range + 4, npages * (4096 / c->lba_size));
    stq_le_p(range + 8, page * (4096 / c->lba_size));
    qtest_memwrite(c->pdev->bus->qts, buf, range, sizeof(range));
    cmd.opcode = NVME_CMD_DSM;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw11 = cpu_to_le32(FEMU_DSM_AD);
    femu_submit(c, &c->io, &cmd);
    return FEMU_SC(femu_complete(c, &c->io, NULL, NULL));
}

/*
 * Block wear-out. The workload of the FTL trace collects enough to erase every
 * line many times. @data pins three exact counts from log page C0h: blocks in
 * service past their erase limit, worn-out blocks taken out of service, and
 * retired lines; and SMART Available Spare, with its warning below 20, and
 * Percentage Used. A seed
 * gives each block the same limit on every run, so the counts repeat like the
 * trace. SMART reports the reliability warning exactly
 * when a block is overworn, and no mapped page may be left in a retired line.
 */
/* Write Zeroes of @nlb blocks from @slba on namespace 1, without deallocate */
uint16_t femu_write_zeroes(FemuCtrlState *c, uint64_t slba, uint32_t nlb)
{
    NvmeCmd cmd;
    uint16_t want = c->cid;
    uint16_t got;
    uint16_t status;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_CMD_WRITE_ZEROES;
    cmd.nsid = cpu_to_le32(1);
    cmd.cdw10 = cpu_to_le32((uint32_t)slba);
    cmd.cdw11 = cpu_to_le32((uint32_t)(slba >> 32));
    cmd.cdw12 = cpu_to_le32(nlb - 1);
    femu_submit(c, &c->io, &cmd);
    status = femu_complete(c, &c->io, &got, NULL);
    g_assert_cmpint(got, ==, want);
    return FEMU_SC(status);
}

/*
 * The FTL trace's fill and 600 overwrites, every write required to succeed,
 * through placement identifier @pid, or none when it is -1. With -2 the
 * writes take placement handles 0 to 3 in turn.
 */
void femu_wear_workload_placed(FemuCtrlState *c, uint64_t buf,
                               uint64_t list, int pid)
{
    uint32_t seed = 1;
    int i;

    for (i = 0; i < 256; i += 64) {
        g_assert_cmphex(FEMU_SC(femu_write_pages_placed(c, i, 64, buf, list,
                                                        pid == -2 ? i / 64 :
                                                        pid)), ==,
                        NVME_SUCCESS);
    }
    for (i = 0; i < 600; i++) {
        uint32_t npages = i % 4 == 3 ? 64 : 1;

        seed = seed * 1103515245 + 12345;
        g_assert_cmphex(FEMU_SC(femu_write_pages_placed(c, (seed >> 8) %
                                                        (256 - npages + 1),
                                                        npages, buf, list,
                                                        pid == -2 ? i % 4 :
                                                        pid)), ==,
                        NVME_SUCCESS);
    }
}

void femu_wear_workload(FemuCtrlState *c, uint64_t buf, uint64_t list)
{
    femu_wear_workload_placed(c, buf, list, -1);
}

/* the parameter page of gc-copyback-parity, made when its QEMU starts */
char *femu_cb_page;

/* the composite temperature and the critical warning, from the SMART log */
uint16_t femu_smart_temp(FemuCtrlState *c, uint64_t log,
                         uint8_t *warning)
{
    uint8_t page[512];

    g_assert_cmpint(FEMU_SC(femu_get_log(c, NVME_LOG_SMART_INFO, log,
                                         sizeof(page), 0)), ==, NVME_SUCCESS);
    qtest_memread(c->pdev->bus->qts, log, page, sizeof(page));
    if (warning) {
        *warning = page[0];
    }
    return lduw_le_p(page + 1);
}

/* CRC-16 of an ONFI parameter page (Section 6.7.1.42) */
static uint16_t femu_onfi_crc(const uint8_t *p, size_t n)
{
    uint16_t crc = 0x4f4e;

    while (n--) {
        crc ^= (uint16_t)*p++ << 8;
        for (int b = 0; b < 8; b++) {
            crc = (uint16_t)((crc << 1) ^ ((crc & 0x8000) ? 0x8005 : 0));
        }
    }
    return crc;
}

/*
 * A one-copy ONFI 6.0 parameter page for one LUN of 4096 data bytes per
 * page, 32 pages per block and 12 blocks per LUN, with 3 column and 4 row
 * address cycles, modes 0 to 22. @mutate changes one thing, then the CRC
 * is set (@good_crc) or left wrong. @mutate 3 is the gc-copyback-parity
 * device: 32 blocks per LUN, 2 column and 3 row cycles, Copyback without
 * odd to even copyback.
 */
char *femu_onfi_page_file(int mutate, bool good_crc)
{
    uint8_t p[256] = { 'O', 'N', 'F', 'I' };
    g_autoptr(GError) err = NULL;
    char *path = NULL;
    uint16_t crc;
    int fd;

    p[5] = 0x80;                     /* revision bit 15: ONFI 6.0 */
    p[7] = 0x02;                     /* features bit 9: NV-LPDDR4 */
    p[8] = 0x48;                     /* Read Status and Column Enhanced */
    p[81] = 0x10;                    /* 4096 data bytes */
    p[92] = 32;
    p[96] = 12;
    p[100] = 1;
    p[101] = 0x34;
    p[102] = 0xff;
    p[118] = 0xff;                   /* bits 0 to 19: modes 0 to 22 */
    p[119] = 0xff;
    p[120] = 0x0f;
    if (mutate == 1) {
        p[0] = p[1] = p[2] = 0;      /* one signature byte left */
    } else if (mutate == 2) {
        p[92] = 64;                  /* pages per block */
    } else if (mutate == 3) {
        p[96] = 32;
        p[101] = 0x23;
        p[8] |= 0x10;                /* Copyback */
    }
    crc = femu_onfi_crc(p, 254);
    p[254] = crc & 0xff;
    p[255] = (crc >> 8) ^ (good_crc ? 0 : 1);
    fd = g_file_open_tmp("femu-onfi-XXXXXX", &path, &err);
    g_assert_cmpint(fd, >=, 0);
    g_assert_cmpint(write(fd, p, sizeof(p)), ==, sizeof(p));
    close(fd);
    return path;
}

uint16_t femu_delete_sq(FemuCtrlState *c, uint16_t qid)
{
    NvmeCmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_DELETE_SQ;
    cmd.cdw10 = cpu_to_le32(qid);
    return femu_admin(c, &cmd);
}

uint64_t femu_ruh0_ruamw(FemuCtrlState *c, uint64_t buf)
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
uint16_t femu_write_8k(FemuCtrlState *c, uint64_t buf, uint64_t slba,
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

/*
 * x-ftl-check of the device with id @id: mapped, lost and orphan pages,
 * valid translation pages, broken TP rules, TPs moved by collection and
 * pending TPs.
 */
void femu_tp_check(QTestState *qts, const char *id, uint64_t v[7])
{
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                           "'path':%s,'property':'x-ftl-check'}}", id);

    g_assert_true(qdict_haskey(rsp, "return"));
    g_assert_cmpint(sscanf(qdict_get_str(rsp, "return"),
                           "%" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64
                           " %" SCNu64 " %" SCNu64 " %" SCNu64, &v[0], &v[1],
                           &v[2], &v[3], &v[4], &v[5], &v[6]), ==, 7);
    g_test_message("x-ftl-check %s", qdict_get_str(rsp, "return"));
    qobject_unref(rsp);
}

/*
 * fw_gc_page_ns counters once collection is quiet: in @v the C0h GC pages
 * (offset 16), the moves with a firmware slot (336), their time (344) and,
 * with the device path @id, the TP moves of x-ftl-check. A background pass
 * can still run after the last command, so read until two reads 50 ms
 * apart agree.
 */
void femu_gc_fw_counts(FemuCtrlState *c, uint64_t log, const char *id,
                       uint64_t v[4])
{
    uint64_t last[4] = { UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX };
    int k;

    for (k = 0; k < 40; k++) {
        uint64_t t[7] = { 0 };

        v[0] = femu_c0h_field(c, log, 16);
        v[1] = femu_c0h_field(c, log, 336);
        v[2] = femu_c0h_field(c, log, 344);
        if (id) {
            femu_tp_check(c->pdev->bus->qts, id, t);
        }
        v[3] = t[5];
        if (!memcmp(v, last, sizeof(last))) {
            return;
        }
        memcpy(last, v, sizeof(last));
        g_usleep(50000);
    }
    g_assert_not_reached();
}

/*
 * A queue pair of its own depth, deep enough to keep a poller working while
 * the other one is given its own batch. The shared helpers are fixed at
 * FEMU_QSIZE entries, so this test carries its own submit and collect.
 */
void femu_zap_create_queue(FemuCtrlState *c, FemuQueue *q, uint16_t qid)
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
uint16_t femu_zap_complete(FemuCtrlState *c, FemuQueue *q,
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
void femu_zap_queue(FemuCtrlState *c, FemuQueue *q, NvmeCmd *cmd)
{
    cmd->cid = cpu_to_le16(c->cid++);
    qtest_memwrite(c->pdev->bus->qts,
                   q->sq_addr + q->sq_tail * sizeof(NvmeCmd), cmd,
                   sizeof(*cmd));
    q->sq_tail = (q->sq_tail + 1) % ZAP_QDEPTH;
}

void femu_zap_ring(FemuCtrlState *c, FemuQueue *q)
{
    qpci_io_writel(c->pdev, c->bar, femu_sq_doorbell(c, q->qid), q->sq_tail);
}

/*
 * The same rule, made certain. With x-copy-hold set, the device stops a
 * write's copy (@data "write") or a Copy's destination copy (@data "copy")
 * halfway, and x-copy-held shows that it has. Only then is a read of the
 * block sent. The write goes on once x-range-waits shows the read waiting
 * for its lock. A read that completes first has read past the write; either
 * way it must return the new data whole.
 */

void femu_rwa_hold(QTestState *qts, uint32_t on)
{
    qtest_qmp_assert_success(qts, "{'execute':'qom-set','arguments':{"
                             "'path':'/machine/peripheral/rwa',"
                             "'property':'x-copy-hold','value':%u}}", on);
}

uint64_t femu_rwa_get(QTestState *qts, const char *prop)
{
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                           "'path':'/machine/peripheral/rwa',"
                           "'property':%s}}", prop);
    uint64_t value = qdict_get_int(rsp, "return");

    qobject_unref(rsp);
    return value;
}

bool femu_rwa_cq_ready(FemuCtrlState *c, FemuQueue *q)
{
    NvmeCqe cqe;

    qtest_memread(c->pdev->bus->qts, q->cq_addr + q->cq_head * sizeof(cqe),
                  &cqe, sizeof(cqe));
    return (le16_to_cpu(cqe.status) & 1) == q->phase;
}

void femu_pe_suspend_rw(FemuCtrlState *c, FemuQueue *q, NvmeRwCmd *rw,
                        bool kv, uint8_t opcode, uint64_t page)
{
    NvmeCmd cmd;

    if (!kv) {
        rw->opcode = opcode;
        rw->slba = cpu_to_le64(page * (FEMU_DATA_SIZE / c->lba_size));
        femu_zap_queue(c, q, (NvmeCmd *)rw);
        return;
    }
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = opcode == NVME_CMD_WRITE ? FEMU_KV_CMD_STORE :
                 FEMU_KV_CMD_RETRIEVE;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = rw->dptr.prp1;
    cmd.res1 = cpu_to_le64(page + 1);
    cmd.cdw10 = cpu_to_le32(FEMU_DATA_SIZE);
    cmd.cdw11 = cpu_to_le32(8);
    femu_zap_queue(c, q, &cmd);
}

void femu_flush_check(QTestState *qts, uint64_t *v)
{
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                           "'path':'/machine/peripheral/gc-test',"
                           "'property':'x-flush-check'}}");
    g_auto(GStrv) f = NULL;
    int i;

    g_assert_true(qdict_haskey(rsp, "return"));
    g_test_message("x-flush-check %s", qdict_get_str(rsp, "return"));
    f = g_strsplit(qdict_get_str(rsp, "return"), " ", 0);
    qobject_unref(rsp);
    g_assert_cmpuint(g_strv_length(f), ==, FLUSH_FIELDS);
    for (i = 0; i < FLUSH_FIELDS; i++) {
        v[i] = g_ascii_strtoull(f[i], NULL, 10);
    }
}

/*
 * Send one 8 KiB command through two PRP pages and return without waiting.
 * @dw12hi goes to the upper half of CDW12 (the Write Zeroes flags).
 */
void femu_crypto_submit(FemuCtrlState *c, uint8_t opcode,
                        uint64_t slba, uint64_t buf, uint16_t dw12hi)
{
    NvmeRwCmd rw;

    memset(&rw, 0, sizeof(rw));
    rw.opcode = opcode;
    rw.nsid = cpu_to_le32(1);
    rw.dptr.prp1 = cpu_to_le64(buf);
    rw.dptr.prp2 = cpu_to_le64(buf + 4096);
    rw.slba = cpu_to_le64(slba);
    rw.nlb = cpu_to_le16(8192 / c->lba_size - 1);
    rw.control = cpu_to_le16(dw12hi);
    femu_submit(c, &c->io, (NvmeCmd *)&rw);
}

/*
 * Log page C0h counts the three ways a host write waits for room. @data names
 * the case. "gc": the FTL trace workload, whose writes collect first; every
 * stalled write ran at least one pass, and no more writes stall than were
 * sent. "buffer": 32 writes of 4 pages into a 16-page write buffer empty it
 * to make room. "cq": six reads into a completion queue of two entries, one
 * of which must stay empty, so completions wait for the host to reap. That
 * needs a mode whose completions come back from the FTL: NoSSD completes in
 * the submission sweep and stops fetching instead.
 */
uint64_t femu_c0h_field(FemuCtrlState *c, uint64_t log, int off)
{
    uint8_t page[512];

    g_assert_cmpint(FEMU_SC(femu_get_log(c, FEMU_LOG_FEMU_STATS, log,
                                         sizeof(page), 0)), ==, NVME_SUCCESS);
    qtest_memread(c->pdev->bus->qts, log, page, sizeof(page));
    return ldq_le_p(page + off);
}

/* a queue pair with its own completion queue, interrupts off */
void femu_burst_queue(FemuCtrlState *c, FemuQueue *q, uint16_t qid)
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
    cmd.cdw11 = cpu_to_le32((qid << 16) | NVME_SQ_PC);
    g_assert_cmpint(femu_admin(c, &cmd), ==, NVME_SUCCESS);
}

/* one queue pair whose completion queue interrupts on the given vector */
void femu_create_io_queues_irq(FemuCtrlState *c, uint16_t vector)
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
void femu_read_unconsumed(FemuCtrlState *c, uint64_t buf)
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

/* one stage of a query-femu-stages reply */
QDict *femu_stage(QDict *ret, const char *name)
{
    QListEntry *e;

    QLIST_FOREACH_ENTRY(qdict_get_qlist(ret, "stages"), e) {
        QDict *st = qobject_to(QDict, qlist_entry_obj(e));

        if (!strcmp(qdict_get_str(st, "stage"), name)) {
            return st;
        }
    }
    g_assert_not_reached();
}

/* the count in bucket @b of a stage */
uint64_t femu_stage_bucket(QDict *st, int b)
{
    QList *l = qdict_get_qlist(st, "buckets");
    QListEntry *e;
    int i = 0;

    g_assert_cmpuint(qlist_size(l), ==, 40);
    QLIST_FOREACH_ENTRY(l, e) {
        if (i++ == b) {
            return qnum_get_uint(qobject_to(QNum, qlist_entry_obj(e)));
        }
    }
    g_assert_not_reached();
}

/* the highest non-empty bucket of a stage must hold its longest time */
void femu_stage_check_buckets(QDict *st)
{
    uint64_t max = qdict_get_int(st, "max-ns");
    int top = max ? MIN(63 - clz64(max), 39) : 0;
    int b;

    if (!qdict_get_int(st, "count")) {
        return;
    }
    g_assert_cmpuint(femu_stage_bucket(st, top), >, 0);
    for (b = top + 1; b < 40; b++) {
        g_assert_cmpuint(femu_stage_bucket(st, b), ==, 0);
    }
}

/* submit + ftl + hold + post-delay must equal total, and past-due is not in it */
void femu_stages_check_sum(QDict *ret)
{
    g_assert_cmpuint(qdict_get_int(femu_stage(ret, "submit"), "sum-ns") +
                     qdict_get_int(femu_stage(ret, "ftl"), "sum-ns") +
                     qdict_get_int(femu_stage(ret, "hold"), "sum-ns") +
                     qdict_get_int(femu_stage(ret, "post-delay"), "sum-ns"),
                     ==, qdict_get_int(femu_stage(ret, "total"), "sum-ns"));
}

/*
 * The bands must agree with the histograms: band b holds exactly the
 * commands of total bucket b, their total sums add up to the total sum,
 * and their past-due sums add up to the past-due sum. The bands come in bucket
 * order, and only non-empty ones.
 */
void femu_stages_check_bands(QDict *ret)
{
    QDict *total = femu_stage(ret, "total");
    uint64_t count = 0, tsum = 0, lsum = 0;
    int last = -1;
    QListEntry *e;

    QLIST_FOREACH_ENTRY(qdict_get_qlist(ret, "bands"), e) {
        QDict *bd = qobject_to(QDict, qlist_entry_obj(e));
        int b = qdict_get_int(bd, "bucket");

        g_assert_cmpint(b, >, last);
        g_assert_cmpint(b, <, 40);
        last = b;
        g_assert_cmpuint(qdict_get_int(bd, "count"), >, 0);
        g_assert_cmpuint(qdict_get_int(bd, "count"), ==,
                         femu_stage_bucket(total, b));
        g_assert_cmpuint(qdict_get_int(bd, "total-sum-ns"), >=,
                         b ? qdict_get_int(bd, "count") << b : 0);
        count += qdict_get_int(bd, "count");
        tsum += qdict_get_int(bd, "total-sum-ns");
        lsum += qdict_get_int(bd, "past-due-sum-ns");
    }
    g_assert_cmpuint(count, ==, qdict_get_int(total, "count"));
    g_assert_cmpuint(tsum, ==, qdict_get_int(total, "sum-ns"));
    g_assert_cmpuint(lsum, ==,
                     qdict_get_int(femu_stage(ret, "past-due"), "sum-ns"));
}

/*
 * Point a command at data through a last segment holding one data block. Read
 * as PRPs, the descriptor's address is the list, not the data, so a command
 * that ignores PSDT moves the wrong bytes.
 */
void femu_sgl_segment(FemuCtrlState *c, NvmeCmd *cmd, uint64_t list,
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

/* the last femu_io() status before DNR and More were stripped */
uint16_t femu_io_status;

uint16_t femu_io(FemuCtrlState *c, NvmeCmd *cmd)
{
    uint16_t want = c->cid;
    uint16_t got;
    uint16_t status;

    femu_submit(c, &c->io, cmd);
    status = femu_complete(c, &c->io, &got, NULL);
    g_assert_cmpint(got, ==, want);

    femu_io_status = status;
    return FEMU_SC(status);
}

uint16_t femu_log_cmd(FemuCtrlState *c, uint32_t nsid, uint32_t dw10,
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

/* hold the FTL thread of device gc-test off its rings, or let it go */
void femu_zns_ftl_hold(QTestState *qts, bool hold)
{
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-set','arguments':{"
                           "'path':'/machine/peripheral/gc-test',"
                           "'property':'x-ftl-hold','value':%d}}", hold);

    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
}

uint16_t femu_identify(FemuCtrlState *c, uint32_t nsid, uint32_t dw10,
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

/* submit an Async Event Request and return the identifier it went out with */
uint16_t femu_aer(FemuCtrlState *c)
{
    NvmeCmd cmd;
    uint16_t cid = c->cid;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_ASYNC_EV_REQ;
    femu_submit(c, &c->admin, &cmd);
    return cid;
}

/* Get Log Page of endurance group 1 at byte offset @off */
uint16_t femu_endgrp_log(FemuCtrlState *c, uint8_t lid, uint64_t off,
                         uint64_t buf, uint32_t len)
{
    NvmeCmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_GET_LOG_PAGE;
    cmd.nsid = cpu_to_le32(NVME_NSID_BROADCAST);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(lid | ((len / 4 - 1) << 16));
    cmd.cdw11 = cpu_to_le32(1 << 16);
    cmd.cdw12 = cpu_to_le32(off);
    cmd.cdw13 = cpu_to_le32(off >> 32);
    return FEMU_SC(femu_admin(c, &cmd));
}

/* RUAMW of the reclaim unit behind placement id @pid of namespace 1 */
uint64_t femu_ruh_ruamw(FemuCtrlState *c, uint64_t buf, uint16_t pid)
{
    NvmeCmd cmd;
    uint8_t st[16 + 4 * 32];
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
    g_assert_cmpint(lduw_le_p(st + 16 + 32 * pid), ==, pid);
    return ldq_le_p(st + 16 + 32 * pid + 8);
}

/* low 64 bits of HBMW in the FDP Statistics log */
uint64_t femu_fdp_hbmw(FemuCtrlState *c, uint64_t buf)
{
    g_assert_cmpint(femu_endgrp_log(c, FEMU_LOG_FDP_STATS, 0, buf, 64), ==,
                    NVME_SUCCESS);
    return qtest_readq(c->pdev->bus->qts, buf);
}

/*
 * The FDP members of one query-femu reply against the device: the handle
 * byte counters sum to the FDP Statistics log, every reclaim unit is listed
 * once, the states add up to the unit counts, and the valid pages of the
 * units are the FTL's mappings. Returns the host bytes of each handle.
 */
void femu_query_check_fdp(FemuCtrlState *c, uint64_t log,
                          uint64_t want_valid, uint64_t *host)
{
    QTestState *qts = c->pdev->bus->qts;
    uint64_t sum_host = 0;
    uint64_t sum_media = 0;
    uint64_t vpc = 0;
    uint64_t mapped, lost, orphans;
    uint32_t seen[5] = { 0 };
    uint32_t n = 0;
    QListEntry *e;
    QDict *rsp;
    QDict *ns = femu_query_ns(qts, "'kind':'reclaim-units','limit':4096",
                              &rsp);
    QDict *fdp = qdict_get_qdict(ns, "fdp");
    QDict *cnt = qdict_get_qdict(fdp, "unit-counts");
    QList *handles = qdict_get_qlist(fdp, "handles");
    QList *rus = qdict_get_qlist(fdp, "reclaim-units");
    uint32_t per = qdict_get_int(fdp, "units-per-group");
    uint32_t i = 0;

    g_assert_false(qdict_haskey(ns, "line-counts"));
    g_assert_false(qdict_haskey(ns, "next-offset"));
    QLIST_FOREACH_ENTRY(handles, e) {
        QDict *h = qobject_to(QDict, qlist_entry_obj(e));

        g_assert_cmpuint(qdict_get_int(h, "id"), ==, i);
        host[i++] = qdict_get_int(h, "host-bytes");
        sum_host += qdict_get_int(h, "host-bytes");
        sum_media += qdict_get_int(h, "media-bytes");
        g_assert_cmpuint(qdict_get_int(h, "host-bytes"), <=,
                         qdict_get_int(h, "media-bytes"));
    }
    g_assert_cmpint(femu_endgrp_log(c, FEMU_LOG_FDP_STATS, 0, log, 64), ==,
                    NVME_SUCCESS);
    g_assert_cmpuint(sum_host, ==, qtest_readq(qts, log));
    g_assert_cmpuint(sum_media, ==, qtest_readq(qts, log + 16));

    g_assert_cmpuint(qlist_size(rus), ==, qdict_get_int(cnt, "total"));
    QLIST_FOREACH_ENTRY(rus, e) {
        QDict *u = qobject_to(QDict, qlist_entry_obj(e));
        const char *st = qdict_get_str(u, "state");
        static const char *const names[] = { "free", "open", "full",
                                             "victim", "unlisted" };
        int k;

        g_assert_cmpuint(qdict_get_int(u, "group") * per +
                         qdict_get_int(u, "unit"), ==, n++);
        for (k = 0; k < 5 && strcmp(st, names[k]); k++) {
        }
        g_assert_cmpint(k, <, 4);
        seen[k]++;
        vpc += qdict_get_int(u, "vpc");
        g_assert_cmpuint(qdict_get_int(u, "vpc") + qdict_get_int(u, "ipc"),
                         <=, qdict_get_int(fdp, "pages-per-unit"));
        g_assert_cmpuint(qdict_get_int(u, "erase-min"), <=,
                         qdict_get_int(u, "erase-max"));
        if (k == 0) {
            g_assert_false(qdict_haskey(u, "handle"));
            g_assert_cmpuint(qdict_get_int(u, "vpc"), ==, 0);
        } else {
            g_assert_true(qdict_haskey(u, "handle"));
            g_assert_cmpuint(qdict_get_int(u, "handle"), <,
                             qlist_size(handles));
        }
    }
    g_assert_cmpuint(seen[0], ==, qdict_get_int(cnt, "free"));
    g_assert_cmpuint(seen[1], ==, qdict_get_int(cnt, "open"));
    g_assert_cmpuint(seen[2], ==, qdict_get_int(cnt, "full"));
    g_assert_cmpuint(seen[3], ==, qdict_get_int(cnt, "victim"));
    qobject_unref(rsp);

    femu_ftl_check(qts, &mapped, &lost, &orphans);
    g_test_message("units: %" PRIu64 " valid, %" PRIu64 " mapped; host %"
                   PRIu64 " B, media %" PRIu64 " B", vpc, mapped, sum_host,
                   sum_media);
    g_assert_cmpuint(lost, ==, 0);
    g_assert_cmpuint(vpc, ==, mapped);
    g_assert_cmpuint(vpc, ==, want_valid);
}

/* reclaim units x-fdp-check finds in no list, heap or frontier, or in two */
uint64_t femu_fdp_check(QTestState *qts)
{
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                           "'path':'/machine/peripheral/gc-test',"
                           "'property':'x-fdp-check'}}");
    uint64_t bad;

    g_assert_true(qdict_haskey(rsp, "return"));
    bad = g_ascii_strtoull(qdict_get_str(rsp, "return"), NULL, 10);
    qobject_unref(rsp);
    return bad;
}

/* valid pages in the reclaim units query-femu reports for handle @h */
uint64_t femu_fdp_handle_vpc(QTestState *qts, int h)
{
    QDict *rsp;
    QDict *ns = femu_query_ns(qts, "'kind':'reclaim-units','limit':4096",
                              &rsp);
    QList *rus = qdict_get_qlist(qdict_get_qdict(ns, "fdp"), "reclaim-units");
    uint64_t vpc = 0;
    QListEntry *e;

    QLIST_FOREACH_ENTRY(rus, e) {
        QDict *u = qobject_to(QDict, qlist_entry_obj(e));

        if (qdict_haskey(u, "handle") && qdict_get_int(u, "handle") == h) {
            vpc += qdict_get_int(u, "vpc");
        }
    }
    qobject_unref(rsp);
    return vpc;
}

/*
 * Write @npages 4 KiB pages from @page through placement @pid, with Force
 * Unit Access when @fua.
 */
uint16_t femu_fdp_wb_write(FemuCtrlState *c, uint64_t page,
                           uint32_t npages, uint64_t data,
                           uint64_t list, int pid, bool fua)
{
    NvmeRwCmd rw;
    uint32_t i;

    g_assert_cmpuint(npages, >=, 1);
    g_assert_cmpuint(npages, <=, 4096 / 8 + 1);
    for (i = 0; i + 1 < npages; i++) {
        qtest_writeq(c->pdev->bus->qts, list + i * 8, data);
    }
    memset(&rw, 0, sizeof(rw));
    rw.opcode = NVME_CMD_WRITE;
    rw.nsid = cpu_to_le32(1);
    rw.dptr.prp1 = cpu_to_le64(data);
    rw.dptr.prp2 = cpu_to_le64(npages > 2 ? list : npages == 2 ? data : 0);
    rw.slba = cpu_to_le64(page * (4096 / c->lba_size));
    rw.nlb = cpu_to_le16(npages * (4096 / c->lba_size) - 1);
    rw.control = cpu_to_le16((fua ? NVME_RW_FUA : 0) | 2 << 4);
    rw.dspec = cpu_to_le16(pid);
    return FEMU_SC(femu_io(c, (NvmeCmd *)&rw));
}

uint16_t femu_fdp_wb_flush(FemuCtrlState *c)
{
    NvmeCmd cmd = { .opcode = NVME_CMD_FLUSH, .nsid = cpu_to_le32(1) };

    return FEMU_SC(femu_io(c, &cmd));
}

/* valid pages of the open unit of handle @h, or -1 without one */
int64_t femu_fdp_open_vpc(QTestState *qts, int h)
{
    QDict *rsp;
    QDict *ns = femu_query_ns(qts, "'kind':'reclaim-units','limit':4096",
                              &rsp);
    QList *rus = qdict_get_qlist(qdict_get_qdict(ns, "fdp"), "reclaim-units");
    int64_t vpc = -1;
    QListEntry *e;

    QLIST_FOREACH_ENTRY(rus, e) {
        QDict *u = qobject_to(QDict, qlist_entry_obj(e));

        if (!strcmp(qdict_get_str(u, "state"), "open") &&
            qdict_haskey(u, "handle") && qdict_get_int(u, "handle") == h) {
            vpc = qdict_get_int(u, "vpc");
        }
    }
    qobject_unref(rsp);
    return vpc;
}

/*
 * Copy the controller events (log 23h, LSP 0) into @ev, at most @max of them,
 * and return how many the log holds.
 */
uint32_t femu_fdp_ctrl_events(FemuCtrlState *c, uint64_t log,
                              uint8_t *ev, uint32_t max)
{
    uint8_t buf[64 + 8 * 64];
    uint32_t numd = sizeof(buf) / 4 - 1;
    uint32_t count;
    NvmeCmd cmd;

    g_assert_cmpuint(max, <=, 8);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_GET_LOG_PAGE;
    cmd.nsid = cpu_to_le32(NVME_NSID_BROADCAST);
    cmd.dptr.prp1 = cpu_to_le64(log);
    cmd.cdw10 = cpu_to_le32(FEMU_LOG_FDP_EVENTS | ((numd & 0xffff) << 16));
    cmd.cdw11 = cpu_to_le32(1 << 16);
    g_assert_cmpint(femu_admin(c, &cmd), ==, NVME_SUCCESS);
    qtest_memread(c->pdev->bus->qts, log, buf, sizeof(buf));
    count = ldl_le_p(buf);
    memcpy(ev, buf + 64, MIN(count, max) * 64);
    return count;
}

/* turn events 80h and 81h, as @types names them, on or off for handle @ph */
void femu_fdp_move_events_set(FemuCtrlState *c, uint64_t buf,
                              uint16_t ph, const char *types, bool on)
{
    NvmeCmd cmd = { 0 };
    uint8_t list[2];
    int n = 0;

    if (strchr(types, '0')) {
        list[n++] = FEMU_FDP_EVT_MEDIA_REALLOC;
    }
    if (strchr(types, '1')) {
        list[n++] = FEMU_FDP_EVT_RUH_MODIFIED;
    }
    qtest_memwrite(c->pdev->bus->qts, buf, list, n);
    cmd.opcode = NVME_ADM_CMD_SET_FEATURES;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(FEMU_FEAT_FDP_EVENTS);
    cmd.cdw11 = cpu_to_le32((n << 16) | ph);
    cmd.cdw12 = cpu_to_le32(on);
    g_assert_cmpint(femu_admin(c, &cmd), ==, NVME_SUCCESS);
}

/* Format NVM with only CDW10 set, on namespace 1 */
uint16_t femu_format_dw10(FemuCtrlState *c, uint32_t dw10)
{
    NvmeCmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_FORMAT_NVM;
    cmd.nsid = cpu_to_le32(1);
    cmd.cdw10 = cpu_to_le32(dw10);
    return FEMU_SC(femu_admin(c, &cmd));
}

uint16_t femu_lba_cmd(FemuCtrlState *c, uint8_t opcode, uint64_t slba,
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

uint16_t femu_sanitize(FemuCtrlState *c, uint32_t dw10)
{
    NvmeCmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_ADM_SANITIZE;
    cmd.cdw10 = cpu_to_le32(dw10);
    return FEMU_SC(femu_admin(c, &cmd));
}

/* SSTAT and SPROG from log 81h (RAE clear) */
uint16_t femu_sstat(FemuCtrlState *c, uint64_t buf, uint16_t *sprog)
{
    QTestState *qts = c->pdev->bus->qts;

    g_assert_cmphex(FEMU_SC(femu_get_log(c, 0x81, buf, 512, 0)), ==,
                    NVME_SUCCESS);
    if (sprog) {
        *sprog = qtest_readw(qts, buf);
    }
    return qtest_readw(qts, buf + 2);
}

/*
 * Copy of nr ranges; the first ndesc are laid out as format 0 descriptors in
 * guest memory at list, the rest left zero.
 */
uint16_t femu_copy(FemuCtrlState *c, uint64_t list, uint64_t sdlba,
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

/* 4 KiB of 512-byte blocks on namespace nsid */
uint16_t femu_rw_ns(FemuCtrlState *c, uint8_t opcode, uint32_t nsid,
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

/* Get (or, with set, Set) Host Behavior Support through a 512-byte buffer */
uint16_t femu_hbs(FemuCtrlState *c, bool set, uint64_t buf)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = set ? NVME_ADM_CMD_SET_FEATURES : NVME_ADM_CMD_GET_FEATURES;
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(FEMU_FEAT_HBS);
    return FEMU_SC(femu_admin(c, &cmd));
}

/* a descriptor format 2 Copy of one range, from snsid into namespace 1 */
uint16_t femu_copy_fmt2(FemuCtrlState *c, uint64_t list,
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

/* A Read, Write or Compare of nlb blocks with separate metadata at mptr. */
uint16_t femu_rw_md(FemuCtrlState *c, uint8_t opcode, uint64_t slba,
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

uint16_t femu_pi_io(FemuCtrlState *c, uint8_t opcode, uint32_t nsid,
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

void femu_pi_tuple(uint8_t *m, uint16_t guard, uint16_t app,
                   uint32_t ref)
{
    stw_be_p(m, guard);
    stw_be_p(m + 2, app);
    stl_be_p(m + 4, ref);
}

/* Construct the host transfer without sharing the device's PI helpers. */
void femu_pi_host(QTestState *qts, uint64_t dbuf, uint64_t mbuf,
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

void femu_pi_result(QTestState *qts, uint64_t dbuf, uint64_t mbuf,
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

uint16_t femu_ns_create_pi(FemuCtrlState *c, uint64_t buf,
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

uint16_t femu_pi_format_ns(FemuCtrlState *c, uint32_t nsid,
                           uint32_t dw10)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = NVME_ADM_CMD_FORMAT_NVM;
    cmd.nsid = cpu_to_le32(nsid);
    cmd.cdw10 = cpu_to_le32(dw10);
    return FEMU_SC(femu_admin(c, &cmd));
}

uint16_t femu_pi_copy(FemuCtrlState *c, uint64_t list, uint64_t dst,
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

void femu_pi_range(QTestState *qts, uint64_t list, uint32_t nsid,
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

/*
 * The fuzzers use fixed seeds so that CI sees the same inputs each run.
 * FEMU_FUZZ_SEED changes every seed and FEMU_FUZZ_SCALE multiplies every
 * round count, so a long run can try new inputs. The test log names the
 * seed, so a failure can be reproduced.
 */
guint32 femu_fuzz_seed(guint32 base)
{
    const char *s = getenv("FEMU_FUZZ_SEED");
    guint32 seed = base;

    if (s && *s) {
        seed ^= (guint32)g_ascii_strtoull(s, NULL, 0);
    }
    g_test_message("fuzz seed 0x%08x (FEMU_FUZZ_SEED=%s)", seed,
                   s && *s ? s : "unset");
    return seed;
}

int femu_fuzz_rounds(int base)
{
    const char *s = getenv("FEMU_FUZZ_SCALE");
    guint64 scale = s && *s ? g_ascii_strtoull(s, NULL, 0) : 1;

    if (scale < 1 || scale > FEMU_FUZZ_SCALE_MAX) {
        g_error("FEMU_FUZZ_SCALE must be 1 to %d, got %s",
                FEMU_FUZZ_SCALE_MAX, s);
    }
    return base * (int)scale;
}

/*
 * Whether a field gets a value the handler accepts, which it mostly does so
 * the command gets past its first check. Callers draw the value only after
 * this, inside a conditional, so the order of draws from one seed does not
 * depend on how a compiler orders function arguments.
 */
bool femu_fuzz_sane(GRand *rng)
{
    return g_rand_int_range(rng, 0, 4) != 0;
}

/*
 * A pointer the data can go to: mostly a page of the fuzz region, sometimes
 * unaligned, sometimes a list page, sometimes outside guest memory.
 */
uint64_t femu_fuzz_ptr(GRand *rng, uint64_t region)
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

uint64_t femu_fuzz_sgl_slot(GRand *rng, uint64_t region)
{
    return region + 4096ULL * (FEMU_FUZZ_PAGES - FEMU_FUZZ_LISTS +
                               FEMU_FUZZ_PRP_LISTS) +
           16ULL * g_rand_int_range(rng, 0, FEMU_FUZZ_SGL_DESCS);
}

void femu_fuzz_lists(FemuCtrlState *c, GRand *rng, uint64_t region)
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
void femu_fuzz_valid_dptr(FemuCtrlState *c, GRand *rng,
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

uint16_t femu_get_telemetry(FemuCtrlState *c, uint8_t lid,
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

/* Security Send (81h) or Receive (82h) of @len bytes at @buf */
uint16_t femu_sec(FemuCtrlState *c, bool send, uint8_t secp,
                  uint16_t spsp, uint64_t buf, uint32_t len)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = send ? 0x81 : 0x82;
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32((uint32_t)secp << 24 | (uint32_t)spsp << 8);
    cmd.cdw11 = cpu_to_le32(len);
    return femu_admin(c, &cmd);
}

uint32_t femu_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

void femu_tb_uid(FemuTb *t, uint64_t uid)
{
    int i;

    t->b[t->n++] = 0xA8;
    for (i = 7; i >= 0; i--) {
        t->b[t->n++] = uid >> (8 * i);
    }
}

void femu_tb_bytes(FemuTb *t, const uint8_t *p, uint32_t len)
{
    g_assert_cmpuint(len, <, 2048);
    if (len < 16) {
        t->b[t->n++] = 0xA0 | len;
    } else {
        t->b[t->n++] = 0xD0 | len >> 8;
        t->b[t->n++] = len;
    }
    memcpy(t->b + t->n, p, len);
    t->n += len;
}

void femu_tb_call(FemuTb *t, uint64_t obj, uint64_t method)
{
    t->b[t->n++] = 0xF8;
    femu_tb_uid(t, obj);
    femu_tb_uid(t, method);
    t->b[t->n++] = 0xF0;
}

void femu_tb_end(FemuTb *t)
{
    static const uint8_t e[] = { 0xF1, 0xF9, 0xF0, 0, 0, 0, 0xF1 };

    memcpy(t->b + t->n, e, sizeof(e));
    t->n += sizeof(e);
}

/*
 * Send @t for session @tsn (HSN 0x42) and read the reply into @r. Returns
 * the Subpacket length, 0 when no reply waits.
 */
uint32_t femu_opal_xfer(FemuCtrlState *c, QTestState *qts,
                        uint64_t buf, FemuTb *t, uint32_t tsn,
                        uint8_t *r)
{
    uint8_t pkt[2048] = { 0 };
    uint32_t pad = -t->n & 3;

    pkt[4] = 0x10;
    stl_be_p(pkt + 16, 24 + 12 + t->n + pad);
    stl_be_p(pkt + 20, tsn);
    stl_be_p(pkt + 24, tsn ? 0x42 : 0);
    stl_be_p(pkt + 40, 12 + t->n + pad);
    stl_be_p(pkt + 52, t->n);
    memcpy(pkt + 56, t->b, t->n);
    qtest_memwrite(qts, buf, pkt, sizeof(pkt));
    g_assert_cmphex(femu_sec(c, true, 1, 0x1000, buf, 2048), ==,
                    NVME_SUCCESS);
    qtest_memset(qts, buf + 4096, 0, 2048);
    g_assert_cmphex(femu_sec(c, false, 1, 0x1000, buf + 4096, 2048), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, buf + 4096, r, 2048);
    return femu_be32(r + 16) ? femu_be32(r + 52) : 0;
}

void femu_tb_u(FemuTb *t, uint64_t v)
{
    int len = 0;
    int i;

    if (v < 64) {
        t->b[t->n++] = v;
        return;
    }
    for (i = 0; i < 8; i++) {
        if (v >> (8 * i)) {
            len = i + 1;
        }
    }
    t->b[t->n++] = 0x80 | len;
    for (i = len - 1; i >= 0; i--) {
        t->b[t->n++] = v >> (8 * i);
    }
}

/* the method status of a reply: CALL ... EOD SL status 0 0 EL */
uint8_t femu_opal_run(FemuCtrlState *c, QTestState *qts, uint64_t buf,
                      FemuTb *t, uint32_t tsn)
{
    uint8_t r[2048];
    uint32_t n;

    femu_tb_end(t);
    n = femu_opal_xfer(c, qts, buf, t, tsn, r);
    g_assert_cmpuint(n, >, 4);
    return r[56 + n - 4];
}

/* StartSession to @sp as @auth with @pin; returns the status */
uint8_t femu_opal_open(FemuCtrlState *c, QTestState *qts, uint64_t buf,
                       uint64_t sp, uint64_t auth, const char *pin,
                       uint32_t *tsn)
{
    FemuTb t = { .n = 0 };
    uint8_t r[2048];
    uint32_t n;

    femu_tb_call(&t, 0xFF, 0xFF02);
    femu_tb_u(&t, 0x42);
    femu_tb_uid(&t, sp);
    t.b[t.n++] = 1;
    t.b[t.n++] = 0xF2;
    t.b[t.n++] = 0;
    femu_tb_bytes(&t, (const uint8_t *)pin, strlen(pin));
    t.b[t.n++] = 0xF3;
    t.b[t.n++] = 0xF2;
    t.b[t.n++] = 3;
    femu_tb_uid(&t, auth);
    t.b[t.n++] = 0xF3;
    femu_tb_end(&t);
    n = femu_opal_xfer(c, qts, buf, &t, 0, r);
    g_assert_cmpuint(n, >, 6);
    if (!r[56 + n - 4]) {
        g_assert_cmphex(r[56 + 22], ==, 0x82);
        *tsn = r[56 + 23] << 8 | r[56 + 24];
    }
    return r[56 + n - 4];
}

void femu_opal_eos(FemuCtrlState *c, QTestState *qts, uint64_t buf,
                   uint32_t tsn)
{
    FemuTb t = { .n = 0 };
    uint8_t r[2048];

    t.b[t.n++] = 0xFA;
    g_assert_cmpuint(femu_opal_xfer(c, qts, buf, &t, tsn, r), ==, 1);
}

/* Set uint columns of one row; @cols ends with -1 */
uint8_t femu_opal_lset(FemuCtrlState *c, QTestState *qts,
                       uint64_t buf, uint32_t tsn, uint64_t obj,
                       const int *cols, const uint64_t *vals)
{
    FemuTb t = { .n = 0 };
    int i;

    femu_tb_call(&t, obj, 0x0000000600000017ull);
    t.b[t.n++] = 0xF2;
    t.b[t.n++] = 1;
    t.b[t.n++] = 0xF0;
    for (i = 0; cols[i] >= 0; i++) {
        t.b[t.n++] = 0xF2;
        femu_tb_u(&t, cols[i]);
        femu_tb_u(&t, vals[i]);
        t.b[t.n++] = 0xF3;
    }
    t.b[t.n++] = 0xF1;
    t.b[t.n++] = 0xF3;
    return femu_opal_run(c, qts, buf, &t, tsn);
}

/* one 4 KiB command at @slba; SC only, and a refusal carries DNR */
uint16_t femu_opal_rw(FemuCtrlState *c, uint8_t opc, uint64_t slba,
                      uint64_t data)
{
    uint16_t status = femu_rw(c, opc, slba, data);

    if (FEMU_SC(status) == NVME_ACCESS_DENIED) {
        g_assert_cmphex(status & NVME_DNR, ==, NVME_DNR);
    }
    return FEMU_SC(status);
}

/* read 4 KiB at @slba and compare each byte with @v */
void femu_opal_expect(FemuCtrlState *c, QTestState *qts, uint32_t nsid,
                      uint64_t slba, uint64_t io, uint8_t v)
{
    uint8_t got[FEMU_DATA_SIZE];
    uint8_t want[FEMU_DATA_SIZE];

    qtest_memset(qts, io, ~v, FEMU_DATA_SIZE);
    g_assert_cmphex(FEMU_SC(femu_rw_ns(c, NVME_CMD_READ, nsid, slba, io)), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, io, got, sizeof(got));
    memset(want, v, sizeof(want));
    g_assert_cmpmem(got, sizeof(got), want, sizeof(want));
}

void femu_opal_fill(FemuCtrlState *c, QTestState *qts, uint32_t nsid,
                    uint64_t slba, uint64_t io, uint8_t v)
{
    qtest_memset(qts, io, v, FEMU_DATA_SIZE);
    g_assert_cmphex(FEMU_SC(femu_rw_ns(c, NVME_CMD_WRITE, nsid, slba, io)), ==,
                    NVME_SUCCESS);
}

/* a reservation command on namespace 1; @data is 16 bytes in @buf */
uint16_t femu_resv(FemuCtrlState *c, uint8_t opc, uint32_t dw10,
                   uint32_t dw11, uint64_t buf, uint64_t k1,
                   uint64_t k2)
{
    QTestState *qts = c->pdev->bus->qts;
    NvmeCmd cmd = { 0 };

    qtest_writeq(qts, buf, cpu_to_le64(k1));
    qtest_writeq(qts, buf + 8, cpu_to_le64(k2));
    cmd.opcode = opc;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(dw10);
    cmd.cdw11 = cpu_to_le32(dw11);
    return femu_io(c, &cmd);
}

uint16_t femu_get_lba_status(FemuCtrlState *c, uint64_t buf,
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
void femu_mark_uncor(FemuCtrlState *c, uint64_t slba, uint16_t nlb)
{
    NvmeRwCmd rw = { 0 };

    rw.opcode = NVME_CMD_WRITE_UNCOR;
    rw.nsid = cpu_to_le32(1);
    rw.slba = cpu_to_le64(slba);
    rw.nlb = cpu_to_le16(nlb - 1);
    g_assert_cmpint(femu_io(c, (NvmeCmd *)&rw), ==, NVME_SUCCESS);
}

/* log 0Eh with RAE; PRP2 is the next page, so a read may cross one */
uint16_t femu_lsi_read(FemuCtrlState *c, uint64_t buf, uint32_t len,
                       uint64_t off, bool rae)
{
    uint32_t numd = (len >> 2) - 1;
    NvmeCmd cmd;

    g_assert_cmphex(buf & 4095, ==, 0);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_GET_LOG_PAGE;
    cmd.nsid = cpu_to_le32(NVME_NSID_BROADCAST);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.dptr.prp2 = cpu_to_le64(buf + 4096);
    cmd.cdw10 = cpu_to_le32(0x0e | (rae ? 1u << 15 : 0) |
                            ((numd & 0xffff) << 16));
    cmd.cdw11 = cpu_to_le32((numd >> 16) & 0xffff);
    cmd.cdw12 = cpu_to_le32((uint32_t)off);
    cmd.cdw13 = cpu_to_le32((uint32_t)(off >> 32));
    return FEMU_SC(femu_admin(c, &cmd));
}

/* a full read of log 0Eh: its LSGC, after checking LSLPLEN is @len */
uint16_t femu_lsi_gen(FemuCtrlState *c, uint64_t buf, uint32_t len,
                      bool rae)
{
    QTestState *qts = c->pdev->bus->qts;

    g_assert_cmphex(femu_lsi_read(c, buf, 4096, 0, rae), ==, NVME_SUCCESS);
    g_assert_cmpint(qtest_readl(qts, buf), ==, len);
    return qtest_readw(qts, buf + 14);
}

/* field @key of x-lsi-state */
uint64_t femu_lsi_state(QTestState *qts, const char *key)
{
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                           "'path':'/machine/peripheral/lsi-test',"
                           "'property':'x-lsi-state'}}");
    g_autofree char *k = g_strdup_printf(" %s=", key);
    g_autofree char *line = NULL;
    const char *p;
    uint64_t v;

    g_assert_true(qdict_haskey(rsp, "return"));
    line = g_strdup_printf(" %s", qdict_get_str(rsp, "return"));
    p = strstr(line, k);
    g_assert_nonnull(p);
    v = g_ascii_strtoull(p + strlen(k), NULL, 10);
    qobject_unref(rsp);
    return v;
}

void femu_lsi_cmd(QTestState *qts, const char *cmd)
{
    qtest_qmp_assert_success(qts, "{'execute':'qom-set','arguments':{"
                             "'path':'/machine/peripheral/lsi-test',"
                             "'property':'x-lsi','value':%s}}", cmd);
}

/* AEC with only bit 13: LBA Status Information alerts */
void femu_lsi_aec(FemuCtrlState *c, bool on)
{
    uint32_t res;

    g_assert_cmphex(FEMU_SC(femu_set_feature(c, 0x0b, false, 0,
                                             on ? 1u << 13 : 0, &res)),
                    ==, NVME_SUCCESS);
}

/*
 * Step virtual time, then give the main loop up to 20 ms of real time for
 * the bottom halves the timers scheduled. True when the admin queue holds
 * a completion.
 */
bool femu_lsi_after(FemuCtrlState *c, int64_t ns)
{
    qtest_clock_step(c->pdev->bus->qts, ns);
    for (int i = 0; i < 20; i++) {
        if (femu_cq_ready(c, &c->admin)) {
            return true;
        }
        g_usleep(1000);
    }
    return femu_cq_ready(c, &c->admin);
}

/* the next admin completion is the alert for AER @cid */
void femu_lsi_alert(FemuCtrlState *c, uint16_t want)
{
    uint32_t res;
    uint16_t cid;

    g_assert_cmphex(femu_complete(c, &c->admin, &cid, &res), ==,
                    NVME_SUCCESS);
    g_assert_cmpuint(cid, ==, want);
    g_assert_cmphex(res, ==, FEMU_LSI_AER);
}

/* where the csd-program-dir test keeps its programs; one per test process */
char *femu_csd_dir;

/* where the csd-exec-concurrency test builds its program */
char *femu_csd_slow_dir;

/*
 * A program runs for as long as it likes, and while it runs the rest of the
 * controller has to keep working: a read on another queue must complete, and
 * an admin command must not wait for the program. Afterwards, a queue deleted
 * and a controller disabled with a program still running must not leave the
 * program's completion pointing at a request that is gone.
 */
/* where csd-runtime-floor sends QEMU's stderr */
char *femu_csd_warn_log;

/* the QEMU process's peak virtual size, which a large allocation raises */
uint64_t femu_vm_peak_kb(QTestState *qts)
{
    g_autofree char *path = g_strdup_printf("/proc/%d/status", qtest_pid(qts));
    g_autofree char *text = NULL;
    const char *line;

    g_assert_true(g_file_get_contents(path, &text, NULL, NULL));
    line = strstr(text, "VmPeak:");
    g_assert_nonnull(line);
    return g_ascii_strtoull(line + strlen("VmPeak:"), NULL, 10);
}

/* Get Log Page 0Dh with an action (Figure 229), len bytes at off */
uint16_t femu_pel(FemuCtrlState *c, uint8_t act, uint64_t buf,
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

uint16_t femu_ns_delete(FemuCtrlState *c, uint32_t nsid)
{
    NvmeCmd cmd = { 0 };

    /* Namespace changes outlive qgraph's reset between tests. */
    qos_invalidate_command_line();
    cmd.opcode = 0x0d;
    cmd.nsid = cpu_to_le32(nsid);
    cmd.cdw10 = cpu_to_le32(1);
    return FEMU_SC(femu_admin(c, &cmd));
}

uint16_t femu_ns_create(FemuCtrlState *c, uint64_t buf, uint64_t nsze,
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

uint16_t femu_ns_attach(FemuCtrlState *c, uint64_t buf, uint32_t nsid,
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

void femu_ns_page(FemuCtrlState *c, uint64_t buf, uint32_t nsid,
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

uint16_t femu_changed_ns_log(FemuCtrlState *c, uint64_t buf, bool rae)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = NVME_ADM_CMD_GET_LOG_PAGE;
    cmd.nsid = cpu_to_le32(0xffffffff);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(4 | (rae ? 1 << 15 : 0) | (1023 << 16));
    return FEMU_SC(femu_admin(c, &cmd));
}

void femu_shared_add(QTestState *qts, const char *id, int slot,
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

void femu_ns_fixture(QTestState *qts, const char *value)
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

/* the offset of the i'th event reported, counting from the newest */
uint64_t femu_pel_at(QTestState *qts, uint64_t buf, int i)
{
    uint64_t e = buf + 512;

    while (i--) {
        e += 3 + qtest_readb(qts, e + 2) + qtest_readw(qts, e + 22);
    }
    return e;
}

/* how many of the events in the first 4 KiB of a context have this type */
int femu_pel_count(QTestState *qts, uint64_t buf, uint8_t et,
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

void femu_power_read(FemuCtrlState *c, uint64_t buf, uint32_t nsid,
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

/* query-femu @kind entries 0 to @limit - 1 of device pd, as JSON text */
char *femu_ftl_dump(QTestState *qts, const char *kind, int limit)
{
    g_autofree char *args = g_strdup_printf(
        "'path':'/machine/peripheral/pd','kind':'%s','offset':0,'limit':%d",
        kind, limit);
    QDict *rsp;
    QDict *ns = femu_query_ns(qts, args, &rsp);
    GString *js = qobject_to_json(qdict_get(ns, kind));

    qobject_unref(rsp);
    return g_string_free(js, false);
}

/* the write counters of device pd, as one line of text */
char *femu_ftl_counters(QTestState *qts)
{
    QDict *rsp;
    QDict *ns = femu_query_ns(qts, "'path':'/machine/peripheral/pd'", &rsp);
    QDict *ctr = qdict_get_qdict(ns, "counters");
    char *s = g_strdup_printf("host %" PRId64 " nand %" PRId64 " gc %"
                              PRId64 " erases %" PRId64,
                              qdict_get_int(ctr, "host-write-pages"),
                              qdict_get_int(ctr, "nand-write-pages"),
                              qdict_get_int(ctr, "gc-write-pages"),
                              qdict_get_int(ctr, "block-erases"));

    qobject_unref(rsp);
    return s;
}

/* qom-set the test-only fetch hold of device @id */
void femu_fetch_hold(QTestState *qts, const char *id, int hold)
{
    g_autofree char *path = g_strdup_printf("/machine/peripheral/%s", id);

    qtest_qmp_assert_success(qts, "{'execute':'qom-set','arguments':{"
                             "'path':%s,'property':'x-fetch-hold',"
                             "'value':%i}}", path, hold);
}

/* query-femu-events of device @id */
QDict *femu_events_q(QTestState *qts, const char *id, QDict **rsp)
{
    g_autofree char *path = g_strdup_printf("/machine/peripheral/%s", id);

    *rsp = qtest_qmp(qts, "{'execute':'query-femu-events','arguments':{"
                     "'path':%s}}", path);
    g_assert_true(qdict_haskey(*rsp, "return"));
    return qdict_get_qdict(*rsp, "return");
}

char *femu_events_file(const char *dir, const char *text)
{
    char *path = g_build_filename(dir, "events.txt", NULL);

    g_assert_true(g_file_set_contents(path, text, -1, NULL));
    return path;
}

/* valid pages of all 40 lines of device pd: one per mapped LPN */
uint64_t femu_ftl_vpc_sum(QTestState *qts)
{
    QDict *rsp;
    QDict *ns = femu_query_ns(qts, "'path':'/machine/peripheral/pd',"
                              "'kind':'lines','offset':0,'limit':40", &rsp);
    QListEntry *e;
    uint64_t sum = 0;

    QLIST_FOREACH_ENTRY(qdict_get_qlist(ns, "lines"), e) {
        sum += qdict_get_int(qobject_to(QDict, qlist_entry_obj(e)), "vpc");
    }
    qobject_unref(rsp);
    return sum;
}

void femu_pa_boot(FemuPa *p, const char *opts, const char *path)
{
    p->qs = qtest_pc_boot("-machine pc -nodefaults -device femu,id=pd,addr=5,"
                          "%s,persist_ftl=on,persist_file=%s", opts, path);
    p->qts = p->qs->qts;
    p->pdev = qpci_device_find(p->qs->pcibus, QPCI_DEVFN(5, 0));
    memset(&p->c, 0, sizeof(p->c));
    femu_enable(&p->c, p->pdev, &p->qs->alloc);
    femu_create_io_queues(&p->c);
    p->buf = guest_alloc(&p->qs->alloc, 64 * 4096);
    p->list = guest_alloc(&p->qs->alloc, 4096);
    p->log = guest_alloc(&p->qs->alloc, 512);
    qtest_memset(p->qts, p->buf, 0x3c, 64 * 4096);
}

/* quit, which saves the file, or only stop the guest */
void femu_pa_end(FemuPa *p, bool quit)
{
    femu_disable(&p->c);
    femu_queue_free(&p->c, &p->c.io);
    if (quit) {
        qtest_qmp_send(p->qts, "{'execute':'quit'}");
        qtest_set_expected_status(p->qts, 0);
        qtest_wait_qemu(p->qts);
    }
    guest_free(&p->qs->alloc, p->log);
    guest_free(&p->qs->alloc, p->list);
    guest_free(&p->qs->alloc, p->buf);
    g_free(p->pdev);
    qtest_pc_shutdown(p->qs);
}

/* QMP femu-save-data for @id into @file; the error text, or NULL */
char *femu_save_data(QTestState *qts, const char *id, const char *file)
{
    g_autofree char *path = g_strdup_printf("/machine/peripheral/%s", id);
    QDict *rsp = qtest_qmp(qts, "{'execute':'femu-save-data','arguments':"
                           "{'path':%s,'file':%s}}", path, file);
    char *err = NULL;

    if (qdict_haskey(rsp, "error")) {
        err = g_strdup(qdict_get_str(qdict_get_qdict(rsp, "error"), "desc"));
        g_test_message("femu-save-data %s: %s", id, err);
    }
    qobject_unref(rsp);
    return err;
}

/* hot-add a 16 MiB femu device @id at slot @slot with @extra JSON members */
void femu_ckpt_add(QTestState *qts, const char *id, int slot,
                   const char *extra)
{
    g_autofree char *args = g_strdup_printf(
        "{'driver':'femu','id':'%s','addr':'%d','devsz_mb':16%s}", id, slot,
        extra);
    QDict *rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':%p}",
                           qobject_from_json(args, &error_abort));

    if (qdict_haskey(rsp, "error")) {
        g_test_message("device_add %s: %s", id, qdict_get_str(
                       qdict_get_qdict(rsp, "error"), "desc"));
    }
    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
}

/* device_add of femu @id at @slot; the error text, or NULL */
char *femu_ckpt_try_add(QTestState *qts, const char *id, int slot,
                        const char *extra)
{
    g_autofree char *args = g_strdup_printf(
        "{'driver':'femu','id':'%s','addr':'%d','devsz_mb':16%s}", id, slot,
        extra);
    QDict *rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':%p}",
                           qobject_from_json(args, &error_abort));
    char *err = NULL;

    if (qdict_haskey(rsp, "error")) {
        err = g_strdup(qdict_get_str(qdict_get_qdict(rsp, "error"), "desc"));
    }
    qobject_unref(rsp);
    return err;
}

uint16_t femu_directive(FemuCtrlState *c, bool receive,
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

uint16_t femu_stream_write(FemuCtrlState *c, uint32_t nsid,
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

/* Whether a completion is waiting, without consuming it. */
bool femu_cq_ready(FemuCtrlState *c, FemuQueue *q)
{
    NvmeCqe cqe;

    qtest_memread(c->pdev->bus->qts, q->cq_addr + q->cq_head * sizeof(cqe),
                  &cqe, sizeof(cqe));
    return (le16_to_cpu(cqe.status) & 1) == q->phase;
}

/*
 * Start a NoSSD controller with @opts, after the devices in @pre, and return
 * what QEMU wrote to stderr.
 */
char *femu_realize_stderr_after(const char *pre, const char *opts)
{
    g_autofree char *log = g_strdup("femu-ignored-XXXXXX");
    g_autofree char *quoted = NULL;
    char *text = NULL;
    int fd = g_mkstemp(log);
    QTestState *qts;

    g_assert_cmpint(fd, >=, 0);
    close(fd);
    quoted = g_shell_quote(log);
    qts = qtest_initf("-machine pc -nodefaults %s -device femu,addr=5,"
                      "devsz_mb=64,femu_mode=2%s 2>%s", pre, opts, quoted);
    qtest_quit(qts);
    g_assert_true(g_file_get_contents(log, &text, NULL, NULL));
    unlink(log);
    return text;
}

char *femu_realize_stderr(const char *opts)
{
    return femu_realize_stderr_after("", opts);
}

/* the FDP state a controller writes into subsystem @id; qtest only */
char *femu_fdp_state(QTestState *qts, const char *id)
{
    g_autofree char *path = g_strdup_printf("/machine/peripheral/%s", id);
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                           "'path':%s,'property':'x-fdp-state'}}", path);
    char *state;

    g_assert_true(qdict_haskey(rsp, "return"));
    state = g_strdup(qdict_get_str(rsp, "return"));
    qobject_unref(rsp);
    return state;
}

/* x-mem-taken of the device at /machine/peripheral/@id */
uint64_t femu_mem_taken(QTestState *qts, const char *id)
{
    g_autofree char *path = g_strdup_printf("/machine/peripheral/%s", id);
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                           "'path':%s,'property':'x-mem-taken'}}", path);
    uint64_t v;

    g_assert_true(qdict_haskey(rsp, "return"));
    v = qdict_get_int(rsp, "return");
    qobject_unref(rsp);
    return v;
}

/*
 * The bytes query-femu-memory reports for controller @id: every owner
 * but the subsystem, whose bytes subsystem realize took. With @sub, the
 * subsystem bytes go there.
 */
uint64_t femu_mem_total(QTestState *qts, const char *id,
                        uint64_t *sub)
{
    QDict *rsp = qtest_qmp(qts, "{'execute':'query-femu-memory',"
                           "'arguments':{'path':%s}}", id);
    const QListEntry *e;
    uint64_t total = 0;

    g_assert_true(qdict_haskey(rsp, "return"));
    QLIST_FOREACH_ENTRY(qdict_get_qlist(qdict_get_qdict(rsp, "return"),
                                        "owners"), e) {
        QDict *o = qobject_to(QDict, qlist_entry_obj(e));
        uint64_t b = qdict_get_int(o, "backend") +
                     qdict_get_int(o, "mapping") +
                     qdict_get_int(o, "media") +
                     qdict_get_int(o, "values") +
                     qdict_get_int(o, "index") +
                     qdict_get_int(o, "other");

        if (!strcmp(qdict_get_str(o, "kind"), "subsystem")) {
            if (sub) {
                *sub = b;
            }
        } else {
            total += b;
        }
    }
    qobject_unref(rsp);
    return total;
}

/* the bytes of one FTL owner in each category */
void femu_mem_ftl_bytes(const char *opts, uint64_t out[3])
{
    QTestState *qts = qtest_initf("-machine pc -nodefaults "
                                  "-device femu,addr=5,id=mem,%s", opts);
    QDict *rsp = qtest_qmp(qts, "{'execute':'query-femu-memory'}");
    const QListEntry *e;
    uint32_t nr = 0;

    QLIST_FOREACH_ENTRY(qdict_get_qlist(qdict_get_qdict(rsp, "return"),
                                        "owners"), e) {
        QDict *o = qobject_to(QDict, qlist_entry_obj(e));

        if (!strcmp(qdict_get_str(o, "kind"), "ftl")) {
            out[0] = qdict_get_int(o, "mapping");
            out[1] = qdict_get_int(o, "media");
            out[2] = qdict_get_int(o, "other");
            nr++;
        }
    }
    g_assert_cmpuint(nr, ==, 1);
    qobject_unref(rsp);
    qtest_quit(qts);
}

uint16_t femu_get_log_csi(FemuCtrlState *c, uint8_t lid, uint8_t csi,
                          uint64_t buf, uint32_t len, uint64_t off)
{
    NvmeCmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_GET_LOG_PAGE;
    cmd.nsid = cpu_to_le32(NVME_NSID_BROADCAST);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(lid | (((len >> 2) - 1) << 16));
    cmd.cdw12 = cpu_to_le32((uint32_t)off);
    cmd.cdw14 = cpu_to_le32((uint32_t)csi << 24);
    return FEMU_SC(femu_admin(c, &cmd));
}

/*
 * Check a FID Supported and Effects page against Get Features: an identifier
 * the page lists must answer, one it leaves out must be refused, and a listed
 * one names no effects and exactly one scope (Base 2.3, Figure 267) -- none
 * for FDP Events, whose scope is a reclaim unit handle, which has no bit.
 */
void femu_check_fid_effects(FemuCtrlState *c, const uint32_t *fis)
{
    int fid;

    for (fid = 0; fid < 256; fid++) {
        uint32_t e = le32_to_cpu(fis[fid]);
        uint16_t sc = FEMU_SC(femu_get_feature(c, fid, NVME_GETFEAT_SELECT_CAP,
                                               1, 0, NULL));

        if (e & 1) {
            g_assert_cmphex(sc, ==, NVME_SUCCESS);
            g_assert_cmpint(FEMU_FID_FSP(e) == 0, ==,
                            fid == FEMU_FEAT_FDP_EVENTS);
            g_assert_cmpint(FEMU_FID_FSP(e) & (FEMU_FID_FSP(e) - 1), ==, 0);
            g_assert_cmphex(e & 0x000ffffe, ==, 0);
        } else {
            g_assert_cmphex(sc, ==, NVME_INVALID_FIELD);
            g_assert_cmphex(e, ==, 0);
        }
    }
}

/* Get Log 0Ch, 4 KiB, RGO as asked, RAE clear */
uint16_t femu_ana_log(FemuCtrlState *c, uint64_t buf, bool rgo)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = NVME_ADM_CMD_GET_LOG_PAGE;
    cmd.nsid = cpu_to_le32(0xffffffff);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(0x0c | (rgo ? 1u << 8 : 0) | 1023u << 16);
    return FEMU_SC(femu_admin(c, &cmd));
}

uint16_t femu_wp_set(FemuCtrlState *c, uint32_t nsid, uint32_t wps)
{
    return FEMU_SC(femu_set_feature(c, FEMU_FID_NS_WP, false, nsid, wps,
                                    NULL));
}

/* Sanitize Namespace of @nsid with CDW10 @dw10 */
uint16_t femu_sanns(FemuCtrlState *c, uint32_t nsid, uint32_t dw10)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = FEMU_ADM_SANITIZE_NS;
    cmd.nsid = cpu_to_le32(nsid);
    cmd.cdw10 = cpu_to_le32(dw10);
    return FEMU_SC(femu_admin(c, &cmd));
}

/* set test hook @prop of device @id to @value */
void femu_cancel_hook(QTestState *qts, const char *id,
                      const char *prop, int value)
{
    g_autofree char *path = g_strdup_printf("/machine/peripheral/%s", id);
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-set','arguments':{"
                           "'path':%s,'property':%s,'value':%d}}",
                           path, prop, value);

    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
}

/* wait until @want requests of device @id wait for their CQE */
void femu_cancel_wait_cpl(QTestState *qts, const char *id,
                          int64_t want)
{
    g_autofree char *path = g_strdup_printf("/machine/peripheral/%s", id);
    int64_t got = -1;

    for (int i = 0; i < FEMU_POLL_LIMIT_MS; i++) {
        QDict *rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                               "'path':%s,'property':'x-cpl-count'}}", path);

        g_assert_true(qdict_haskey(rsp, "return"));
        got = qdict_get_int(rsp, "return");
        qobject_unref(rsp);
        if (got == want) {
            return;
        }
        g_usleep(1000);
    }
    g_assert_cmpint(got, ==, want);
}

/* submit Cancel: CID @cid, SQID @sqid, ACODE @acode, NSID @nsid */
uint16_t femu_cancel_submit(FemuCtrlState *c, uint32_t nsid,
                            uint16_t cid, uint16_t sqid, uint8_t acode)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = FEMU_IO_CANCEL;
    cmd.nsid = cpu_to_le32(nsid);
    cmd.cdw10 = cpu_to_le32((uint32_t)cid << 16 | sqid);
    cmd.cdw11 = cpu_to_le32(acode);
    femu_submit(c, &c->io, &cmd);
    return le16_to_cpu(cmd.cid);
}

/* Cancel and its completion: status, and Dword 0 in @res */
uint16_t femu_cancel(FemuCtrlState *c, uint32_t nsid, uint16_t cid,
                     uint16_t sqid, uint8_t acode, uint32_t *res)
{
    uint16_t want = femu_cancel_submit(c, nsid, cid, sqid, acode);
    uint16_t got;
    uint16_t status = femu_complete(c, &c->io, &got, res);

    g_assert_cmpint(got, ==, want);
    return FEMU_SC(status);
}

/* submit an 8-block Write (@write) or Read of @nsid at @lba; do not wait */
uint16_t femu_cancel_rw(FemuCtrlState *c, uint64_t buf, uint32_t nsid,
                        uint64_t lba, bool write, uint8_t pattern)
{
    NvmeRwCmd rw = { 0 };

    if (write) {
        qtest_memset(c->pdev->bus->qts, buf, pattern, 4096);
    }
    rw.opcode = write ? NVME_CMD_WRITE : NVME_CMD_READ;
    rw.nsid = cpu_to_le32(nsid);
    rw.dptr.prp1 = cpu_to_le64(buf);
    rw.slba = cpu_to_le64(lba);
    rw.nlb = cpu_to_le16(7);
    femu_submit(c, &c->io, (NvmeCmd *)&rw);
    return le16_to_cpu(rw.cid);
}

/*
 * @n completions in any order, one for each CID in @cid: it takes its
 * status in @sc and, when @res is given, Dword 0 in @res.
 */
void femu_cancel_reap(FemuCtrlState *c, int n, const uint16_t *cid,
                      uint16_t *sc, uint32_t *res)
{
    bool seen[8] = { false };

    g_assert_cmpint(n, <=, ARRAY_SIZE(seen));
    for (int i = 0; i < n; i++) {
        uint16_t got;
        uint32_t dw0 = 0;
        uint16_t status = femu_complete(c, &c->io, &got, &dw0);
        int j;

        for (j = 0; j < n && cid[j] != got; j++) {
            ;
        }
        g_assert_cmpint(j, <, n);
        g_assert_false(seen[j]);
        seen[j] = true;
        sc[j] = FEMU_SC(status);
        if (res) {
            res[j] = dw0;
        }
    }
}

uint16_t femu_oncs_cmd(FemuCtrlState *c, uint8_t opcode, uint64_t slba,
                       uint64_t data)
{
    NvmeRwCmd rw = { 0 };

    rw.opcode = opcode;
    rw.nsid = cpu_to_le32(1);
    rw.dptr.prp1 = cpu_to_le64(data);
    rw.slba = cpu_to_le64(slba);
    rw.nlb = cpu_to_le16(FEMU_DATA_SIZE / c->lba_size - 1);
    return femu_io(c, (NvmeCmd *)&rw);
}

uint64_t femu_pd2_fdp_check(QTestState *qts)
{
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                           "'path':'/machine/peripheral/trace',"
                           "'property':'x-fdp-check'}}");
    uint64_t bad;

    g_assert_true(qdict_haskey(rsp, "return"));
    bad = g_ascii_strtoull(qdict_get_str(rsp, "return"), NULL, 10);
    qobject_unref(rsp);
    return bad;
}

/* the number of FDP events of @type in the host (@host) or controller log */
int femu_pd2_events(FemuCtrlState *c, uint64_t log, bool host,
                    uint8_t type, uint16_t *ruhid)
{
    uint8_t buf[64 + 16 * 64];
    uint32_t numd = sizeof(buf) / 4 - 1;
    uint32_t count;
    NvmeCmd cmd;
    int n = 0;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_GET_LOG_PAGE;
    cmd.nsid = cpu_to_le32(NVME_NSID_BROADCAST);
    cmd.dptr.prp1 = cpu_to_le64(log);
    cmd.cdw10 = cpu_to_le32(FEMU_LOG_FDP_EVENTS | (host ? 1 << 8 : 0) |
                            ((numd & 0xffff) << 16));
    cmd.cdw11 = cpu_to_le32(1 << 16);
    g_assert_cmpint(femu_admin(c, &cmd), ==, NVME_SUCCESS);
    qtest_memread(c->pdev->bus->qts, log, buf, sizeof(buf));
    count = MIN(ldl_le_p(buf), 16);
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *ev = buf + 64 + i * 64;

        if (ev[0] == type) {
            /*
             * PIV, NSIDV and LV, namespace 1, reclaim group 0; placement
             * handle n of namespace 1 is handle n, so the PID is the handle
             */
            g_assert_cmphex(ev[1], ==, 0x7);
            g_assert_cmpint(lduw_le_p(ev + 2), ==, lduw_le_p(ev + 34));
            g_assert_cmpint(ldl_le_p(ev + 12), ==, 1);
            g_assert_cmpint(lduw_le_p(ev + 32), ==, 0);
            *ruhid = lduw_le_p(ev + 34);
            n++;
        }
    }
    return n;
}

/* the data of pages [0, @npages) still reads back as @pat */
void femu_pd2_readback(FemuCtrlState *c, QTestState *qts,
                       uint64_t buf, int npages, uint8_t pat)
{
    for (int i = 0; i < npages; i++) {
        qtest_memset(qts, buf, 0, 4096);
        g_assert_cmphex(femu_rw(c, NVME_CMD_READ, i * (4096 / c->lba_size),
                                buf), ==, NVME_SUCCESS);
        g_assert_cmphex(qtest_readb(qts, buf), ==, pat);
        g_assert_cmphex(qtest_readb(qts, buf + 4095), ==, pat);
    }
}

/* where the CP download tests keep their program; one per test process */
char *femu_cps_dir;

/*
 * Read-only end of life (eol_read_only with blk_pe_limit). The state that
 * query-femu reports: whether the media is read-only, the pages admitted
 * writes may hold, and what they hold now. False when the device has none.
 */
bool femu_eol_state(QTestState *qts, bool *ro, uint64_t *cap,
                    uint64_t *pages, uint64_t *reqs)
{
    QDict *rsp;
    QDict *ns = femu_query_ns(qts, "", &rsp);
    QDict *eol = qdict_haskey(ns, "end-of-life") ?
                 qdict_get_qdict(ns, "end-of-life") : NULL;

    if (eol) {
        *ro = qdict_get_bool(eol, "read-only");
        *cap = qdict_get_int(eol, "credit-pages");
        *pages = qdict_get_int(eol, "held-pages");
        *reqs = qdict_get_int(eol, "held-requests");
    }
    qobject_unref(rsp);
    return eol != NULL;
}

/* Write Zeroes of @nlb blocks from @slba, with the Deallocate bit if @deac */
uint16_t femu_wz(FemuCtrlState *c, uint64_t slba, uint32_t nlb,
                 bool deac)
{
    NvmeCmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_CMD_WRITE_ZEROES;
    cmd.nsid = cpu_to_le32(1);
    cmd.cdw10 = cpu_to_le32((uint32_t)slba);
    cmd.cdw11 = cpu_to_le32((uint32_t)(slba >> 32));
    /* DEAC is bit 25 of dword 12 (NVM 1.2, Figure 82) */
    cmd.cdw12 = cpu_to_le32((nlb - 1) | (deac ? 1u << 25 : 0));
    return femu_io(c, &cmd);
}

/* deallocate @nlb logical blocks from @slba, with @buf for the range */
uint16_t femu_dealloc_range(FemuCtrlState *c, uint64_t slba,
                            uint32_t nlb, uint64_t buf)
{
    uint8_t range[16] = { 0 };
    NvmeCmd cmd = { 0 };

    stl_le_p(range + 4, nlb);
    stq_le_p(range + 8, slba);
    qtest_memwrite(c->pdev->bus->qts, buf, range, sizeof(range));
    cmd.opcode = NVME_CMD_DSM;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw11 = cpu_to_le32(FEMU_DSM_AD);
    return femu_io(c, &cmd);
}

/* block-erases from query-femu */
uint64_t femu_eol_erases(QTestState *qts)
{
    QDict *rsp;
    QDict *ns = femu_query_ns(qts, "", &rsp);
    uint64_t v = qdict_get_int(qdict_get_qdict(ns, "counters"),
                               "block-erases");

    qobject_unref(rsp);
    return v;
}

/* a counter of query-femu for namespace 1, or -1 when it is absent */
int64_t femu_eol_query_int(QTestState *qts, const char *dict,
                           const char *key)
{
    QDict *rsp;
    QDict *ns = femu_query_ns(qts, "", &rsp);
    QDict *d = !strcmp(dict, "counters") ? qdict_get_qdict(ns, "counters") :
               qdict_get_qdict(qdict_get_qdict(ns, "fdp"), "unit-counts");
    int64_t v = qdict_haskey(d, key) ? qdict_get_int(d, key) : -1;

    qobject_unref(rsp);
    return v;
}

/* pages of the list area that a PRP chain for @npages data pages takes */
uint32_t femu_g1_list_pages(uint32_t npages)
{
    return 2 * (npages / (FEMU_G1_LIST_ENTS - 1) + 3);
}

/*
 * Point @cmd at @npages pages of guest memory from @data, which starts a
 * page. More than two pages take a PRP list in the area at @list. The first
 * list is the last @first entries of a page. A full list ends with a
 * pointer to the next one, which lies two pages on: a walk that takes the
 * next page of memory in place of the pointer reads no list.
 */
void femu_g1_prps_at(FemuCtrlState *c, NvmeCmd *cmd, uint64_t data,
                     uint32_t npages, uint64_t list, uint32_t first)
{
    QTestState *qts = c->pdev->bus->qts;
    uint64_t ents[FEMU_G1_LIST_ENTS];
    uint32_t left = npages - 1;
    uint32_t room = first;
    uint32_t page = 1;
    uint32_t here;
    uint32_t k;

    g_assert_cmpuint(npages, >=, 1);
    g_assert_cmphex(data & (FEMU_G1_PAGE - 1), ==, 0);
    g_assert_cmphex(list & (FEMU_G1_PAGE - 1), ==, 0);
    cmd->dptr.prp1 = cpu_to_le64(data);
    cmd->dptr.prp2 = 0;
    if (npages == 2) {
        cmd->dptr.prp2 = cpu_to_le64(data + FEMU_G1_PAGE);
    }
    if (npages <= 2) {
        return;
    }
    g_assert_cmpuint(first, >=, 2);
    g_assert_cmpuint(first, <=, FEMU_G1_LIST_ENTS);
    list += (FEMU_G1_LIST_ENTS - first) * sizeof(ents[0]);
    cmd->dptr.prp2 = cpu_to_le64(list);
    while (left) {
        here = left > room ? room - 1 : left;
        for (k = 0; k < here; k++) {
            ents[k] = cpu_to_le64(data + (uint64_t)page * FEMU_G1_PAGE);
            page++;
        }
        left -= here;
        list &= ~(uint64_t)(FEMU_G1_PAGE - 1);
        if (left) {
            ents[here] = cpu_to_le64(list + 2 * FEMU_G1_PAGE);
            here++;
        }
        qtest_memwrite(qts, list + (FEMU_G1_LIST_ENTS - room) *
                       sizeof(ents[0]), ents, here * sizeof(ents[0]));
        list += 2 * FEMU_G1_PAGE;
        room = FEMU_G1_LIST_ENTS;
    }
}

static void femu_g1_prps(FemuCtrlState *c, NvmeCmd *cmd, uint64_t data,
                         uint32_t npages, uint64_t list)
{
    femu_g1_prps_at(c, cmd, data, npages, list, FEMU_G1_LIST_ENTS);
}

/* every byte of @len bytes of guest memory at @addr is @byte */
void femu_g1_all(QTestState *qts, uint64_t addr, size_t len,
                 uint8_t byte)
{
    g_autofree uint8_t *got = g_malloc(len);
    g_autofree uint8_t *want = g_malloc(len);

    memset(want, byte, len);
    qtest_bufread(qts, addr, got, len);
    g_assert_cmpint(memcmp(got, want, len), ==, 0);
}

/* Read or Write @nlb blocks of namespace 1 at @slba, through PRPs */
uint16_t femu_g1_rw(FemuCtrlState *c, uint8_t opcode, uint64_t slba,
                    uint32_t nlb, uint64_t data, uint64_t list)
{
    uint64_t bytes = (uint64_t)nlb * c->lba_size;
    NvmeRwCmd rw;

    g_assert_cmpuint(nlb, >=, 1);
    g_assert_cmpuint(nlb, <=, 65536);
    memset(&rw, 0, sizeof(rw));
    rw.opcode = opcode;
    rw.nsid = cpu_to_le32(1);
    rw.slba = cpu_to_le64(slba);
    rw.nlb = cpu_to_le16(nlb - 1);
    femu_g1_prps(c, (NvmeCmd *)&rw, data,
                 DIV_ROUND_UP(bytes, FEMU_G1_PAGE), list);
    return femu_io(c, (NvmeCmd *)&rw);
}

/* a word that no other word index of the buffer holds; @len is whole words */
void femu_g1_fill(uint8_t *buf, size_t len, uint32_t seed)
{
    size_t i;

    g_assert_cmpuint(len % 4, ==, 0);
    for (i = 0; i < len; i += 4) {
        stl_le_p(buf + i, ((uint32_t)(i / 4) + seed) * 2654435761u);
    }
}

/* guest memory in pieces of 1 MiB, so no qtest command grows too long */
void femu_g1_put(QTestState *qts, uint64_t addr, const uint8_t *buf,
                 size_t len)
{
    size_t off;
    size_t n;

    for (off = 0; off < len; off += n) {
        n = MIN(len - off, (size_t)1 << 20);
        qtest_bufwrite(qts, addr + off, buf + off, n);
    }
}

void femu_g1_get(QTestState *qts, uint64_t addr, uint8_t *buf,
                 size_t len)
{
    size_t off;
    size_t n;

    for (off = 0; off < len; off += n) {
        n = MIN(len - off, (size_t)1 << 20);
        qtest_bufread(qts, addr + off, buf + off, n);
    }
}

/* MDTS as Identify Controller reports it (byte 77), with CAP.MPSMIN 0 */
uint8_t femu_g1_mdts(FemuCtrlState *c, uint64_t id)
{
    uint64_t cap = qpci_io_readq(c->pdev, c->bar, 0x0);

    g_assert_cmpuint((cap >> 48) & 0xf, ==, 0);
    g_assert_cmphex(femu_identify(c, 0, NVME_ID_CNS_CTRL, 0, id), ==,
                    NVME_SUCCESS);
    return qtest_readb(c->pdev->bus->qts, id + 77);
}

/* queue one 4 KiB Read or Write on @q and ring; returns its identifier */
uint16_t femu_g1_queue_submit(FemuCtrlState *c, FemuQueue *q,
                              uint8_t opcode, uint64_t slba,
                              uint64_t buf)
{
    uint16_t cid = c->cid;
    NvmeRwCmd rw;

    memset(&rw, 0, sizeof(rw));
    rw.opcode = opcode;
    rw.nsid = cpu_to_le32(1);
    rw.dptr.prp1 = cpu_to_le64(buf);
    rw.slba = cpu_to_le64(slba);
    rw.nlb = cpu_to_le16(FEMU_DATA_SIZE / c->lba_size - 1);
    femu_submit(c, q, (NvmeCmd *)&rw);
    return cid;
}

/* the next entry of @q is for command @want, and it names that queue */
uint16_t femu_g1_queue_reap(FemuCtrlState *c, FemuQueue *q,
                            uint16_t want)
{
    QTestState *qts = c->pdev->bus->qts;
    uint16_t slot = q->cq_head;
    uint16_t got;
    uint16_t status;
    NvmeCqe cqe;

    status = femu_complete(c, q, &got, NULL);
    g_assert_cmpint(got, ==, want);
    qtest_memread(qts, q->cq_addr + slot * sizeof(cqe), &cqe, sizeof(cqe));
    g_assert_cmpuint(le16_to_cpu(cqe.sq_id), ==, q->qid);
    return FEMU_SC(status);
}

/* Create I/O CQ or SQ @qid, 0's based size @qsize; status with DNR */
uint16_t femu_g1_create(FemuCtrlState *c, uint8_t opcode, uint16_t qid,
                        uint64_t ring, uint32_t qsize, uint32_t dw11)
{
    NvmeCmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = opcode;
    cmd.dptr.prp1 = cpu_to_le64(ring);
    cmd.cdw10 = cpu_to_le32((qsize << 16) | qid);
    cmd.cdw11 = cpu_to_le32(dw11);
    return femu_admin(c, &cmd);
}

/* queue @count Reads of one block on a queue of @size entries, ring once */
void femu_g1_sized_submit(FemuCtrlState *c, FemuQueue *q, uint64_t buf,
                          uint32_t count, uint32_t size)
{
    QTestState *qts = c->pdev->bus->qts;
    uint32_t k;

    for (k = 0; k < count; k++) {
        NvmeRwCmd rw = { 0 };

        rw.opcode = NVME_CMD_READ;
        rw.cid = cpu_to_le16(c->cid++);
        rw.nsid = cpu_to_le32(1);
        rw.dptr.prp1 = cpu_to_le64(buf);
        rw.slba = cpu_to_le64(k % 64);
        qtest_memwrite(qts, q->sq_addr + (uint64_t)q->sq_tail * sizeof(rw),
                       &rw, sizeof(rw));
        q->sq_tail = (q->sq_tail + 1) % size;
    }
    qpci_io_writel(c->pdev, c->bar, femu_sq_doorbell(c, q->qid), q->sq_tail);
}

/* the same on the deep queue of FEMU_G1_DEPTH entries */
void femu_g1_deep_submit(FemuCtrlState *c, FemuQueue *q, uint64_t buf,
                         uint32_t count)
{
    femu_g1_sized_submit(c, q, buf, count, FEMU_G1_DEPTH);
}

/* as femu_complete(), for a queue of FEMU_G1_DEPTH entries */
static uint16_t femu_g1_deep_complete(FemuCtrlState *c, FemuQueue *q,
                                      uint16_t *cid)
{
    QTestState *qts = c->pdev->bus->qts;
    uint64_t slot = q->cq_addr + (uint64_t)q->cq_head * sizeof(NvmeCqe);
    NvmeCqe cqe;
    NvmeCqe again;
    int waited = 0;

    for (;;) {
        qtest_memread(qts, slot, &cqe, sizeof(cqe));
        if ((le16_to_cpu(cqe.status) & 1) == q->phase) {
            qtest_memread(qts, slot, &again, sizeof(again));
            if (memcmp(&cqe, &again, sizeof(cqe)) == 0) {
                break;
            }
        }
        g_assert_cmpint(waited, <, FEMU_POLL_LIMIT_MS);
        g_usleep(1000);
        waited++;
    }
    *cid = le16_to_cpu(cqe.cid);
    q->cq_head = (q->cq_head + 1) % FEMU_G1_DEPTH;
    if (q->cq_head == 0) {
        q->phase ^= 1;
    }
    qpci_io_writel(c->pdev, c->bar, femu_cq_doorbell(c, q->qid), q->cq_head);
    return le16_to_cpu(cqe.status) >> 1;
}

/* reap @count completions; each of the commands from @first ends once */
void femu_g1_deep_reap(FemuCtrlState *c, FemuQueue *q, uint16_t first,
                       uint32_t count)
{
    g_autofree bool *seen = g_new0(bool, count);
    uint16_t cid;
    uint32_t k;

    for (k = 0; k < count; k++) {
        g_assert_cmphex(FEMU_SC(femu_g1_deep_complete(c, q, &cid)), ==,
                        NVME_SUCCESS);
        cid -= first;
        g_assert_cmpuint(cid, <, count);
        g_assert_false(seen[cid]);
        seen[cid] = true;
    }
}

/* wait for an entry of phase @phase in slot @slot of the queue of @q */
void femu_g1_cqe_wait(QTestState *qts, FemuQueue *q, uint32_t slot,
                      uint8_t phase, NvmeCqe *cqe)
{
    uint64_t addr = q->cq_addr + (uint64_t)slot * sizeof(*cqe);
    NvmeCqe again;
    int waited = 0;

    for (;;) {
        qtest_memread(qts, addr, cqe, sizeof(*cqe));
        if ((le16_to_cpu(cqe->status) & 1) == phase) {
            qtest_memread(qts, addr, &again, sizeof(again));
            if (memcmp(cqe, &again, sizeof(again)) == 0) {
                return;
            }
        }
        g_assert_cmpint(waited, <, FEMU_POLL_LIMIT_MS);
        g_usleep(1000);
        waited++;
    }
}
