/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QTest testcases for the FEMU SSD emulator: the key-value SSD tests
 * (femu_mode=5).
 *
 * femu-test.c registers every test. This file holds the test bodies
 * and the helpers that only they use.
 */

#include "qemu/osdep.h"
#include "femu-test.h"

#define FEMU_KV_CMD_EXIST       0x14
#define FEMU_KV_CMD_LIST        0x06
#define FEMU_KV_CMD_DELETE      0x10
#define FEMU_IOCS_COMBINATION_REJECTED  0x12b

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
void femu_test_kv_namespaces_are_separate(void *obj, void *data,
                                          QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd;
    uint64_t buf, id, used1, used2;
    uint16_t want, got;

    femu_enable_csi(&c, &femu->dev, alloc);
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
 * What the health log says a key-value namespace read, and what the most-read
 * block figure says it touched. The size field in a retrieve is the host's
 * buffer, not what the device put in it, and the per-command base cost was
 * charged as a read of block zero.
 */
void femu_test_kv_accounting(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd;
    uint64_t buf, log, units_before, units_after, most_reads;
    uint8_t page[512];
    uint16_t want, got;
    int i;

    femu_enable_csi(&c, &femu->dev, alloc);
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

static uint16_t femu_kv_store(FemuCtrlState *c, uint64_t key, uint64_t buf,
                              uint32_t len);

/*
 * Key value: a Retrieve reads the value page of a block that holds one value,
 * so with @data "on" it pays pd_open_tiers (200 ms here). The index lookup is
 * a translation read and pays nothing. Wall time measures it.
 */
void femu_test_pd_kv(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    bool on = g_str_equal(data, "on");
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 2 * 4096);
    NvmeCmd cmd;
    int64_t start, spent;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x6f, 4096);
    g_assert_cmphex(femu_kv_store(&c, 42, buf, 4096), ==, NVME_SUCCESS);
    g_usleep(20 * 1000);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_KV_CMD_RETRIEVE;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.dptr.prp2 = cpu_to_le64(buf + 4096);
    cmd.res1 = cpu_to_le64(42);
    cmd.cdw10 = cpu_to_le32(4096);
    cmd.cdw11 = cpu_to_le32(8);
    start = g_get_monotonic_time();
    femu_submit(&c, &c.io, &cmd);
    g_assert_cmphex(FEMU_SC(femu_complete(&c, &c.io, NULL, NULL)), ==,
                    NVME_SUCCESS);
    spent = g_get_monotonic_time() - start;
    g_test_message("pd kv %s: retrieve took %" PRId64 " us",
                   on ? "on" : "off", spent);
    if (on) {
        g_assert_cmpint(spent, >=, 200000);
    } else {
        g_assert_cmpint(spent, <, 100000);
    }

    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * A host finds the Key Value command set by asking which sets the controller
 * has, then what the commands of that set do. Neither answered: the set was
 * missing from the list, and its effects log came back with no command
 * supported at all, which is a host's cue to issue none of them.
 */
void femu_test_kv_discovery(void *obj, void *data,
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

void femu_test_sgl_kv(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint8_t *wbuf = g_malloc(4096);
    uint8_t *rbuf = g_malloc0(4096);
    uint64_t buf, list;
    NvmeCmd cmd;
    int i;

    femu_enable_csi(&c, &femu->dev, alloc);
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

/* a key value namespace has a size in bytes 7:0 and nothing in 15:8 */
void femu_test_kv_identify_reserved(void *obj, void *data,
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

/*
 * A key value Store moves the value, so MDTS bounds it. (Retrieve moves the
 * smaller of the buffer and the value, and with MDTS this small no value that
 * large can be stored to retrieve.)
 */
void femu_test_kv_mdts(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf;
    NvmeCmd cmd;

    femu_enable_csi(&c, &femu->dev, alloc);
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
void femu_test_kv_fuzz(void *obj, void *data, QGuestAllocator *alloc)
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
    GRand *rng = g_rand_new_with_seed(femu_fuzz_seed(0x4b56465a));
    uint8_t wbuf[FEMU_DATA_SIZE];
    uint8_t rbuf[FEMU_DATA_SIZE];
    NvmeRwCmd rw;
    NvmeCmd *cmd = (NvmeCmd *)&rw;
    int distinct = 0;
    int i;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    for (i = 0; i < femu_fuzz_rounds(FEMU_IO_FUZZ_ROUNDS); i++) {
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
 * KV List takes its host buffer size from the command, and with MDTS 0
 * nothing bounds it: the device allocated all of it, up to 4 GiB. Enough
 * keys to pass one page make its buffer grow instead, and every one of them
 * must still be listed. A buffer that large has a PRP list.
 */
void femu_test_kv_list_mdts0(void *obj, void *data,
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

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    mem = guest_alloc(alloc, 4 * 4096);
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

    /* the list page names the second data page; the data ends there */
    qtest_writeq(qts, buf + 2 * 4096, buf + 4096);
    peak = femu_vm_peak_kb(qts);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_KV_CMD_LIST;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.dptr.prp2 = cpu_to_le64(buf + 2 * 4096);
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
 * A Retrieve or a List that returns 4 to 8 KiB into a buffer of four pages.
 * The host lays out the PRPs for the whole buffer, so PRP2 is a list
 * pointer. Taken as a data pointer, it made the device write the second
 * page of data over the PRP list.
 */
void femu_test_kv_short_into_list(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    const uint32_t vlen = 6000;
    const uint32_t hbs = 4 * 4096;
    const int keys = 400;               /* 12 bytes each: 4804 bytes */
    uint8_t want[6000];
    uint8_t got[6000];
    uint64_t ents[3];
    uint64_t ents_after[3];
    uint64_t mem, buf, list;
    uint8_t *page;
    NvmeCmd cmd;
    int i;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    mem = guest_alloc(alloc, 6 * 4096);
    buf = (mem + 4095) & ~4095ULL;
    list = buf + hbs;
    for (i = 0; i < 3; i++) {
        ents[i] = cpu_to_le64(buf + (uint64_t)(i + 1) * 4096);
    }

    for (i = 0; i < (int)vlen; i++) {
        want[i] = (uint8_t)(i * 7 + 3);
    }
    qtest_memwrite(qts, buf, want, vlen);
    g_assert_cmphex(femu_kv_store(&c, 42, buf, vlen), ==, NVME_SUCCESS);

    qtest_memset(qts, buf, 0, hbs);
    qtest_memwrite(qts, list, ents, sizeof(ents));
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_KV_CMD_RETRIEVE;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.dptr.prp2 = cpu_to_le64(list);
    cmd.res1 = cpu_to_le64(42);
    cmd.cdw10 = cpu_to_le32(hbs);
    cmd.cdw11 = cpu_to_le32(8);
    g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, got, vlen);
    g_assert_cmpmem(got, vlen, want, vlen);
    qtest_memread(qts, list, ents_after, sizeof(ents_after));
    g_assert_cmpmem(ents_after, sizeof(ents_after), ents, sizeof(ents));

    for (i = 1; i < keys; i++) {
        g_assert_cmphex(femu_kv_store(&c, 1000 + i, buf, 64), ==,
                        NVME_SUCCESS);
    }
    qtest_memset(qts, buf, 0, hbs);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_KV_CMD_LIST;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.dptr.prp2 = cpu_to_le64(list);
    cmd.cdw10 = cpu_to_le32(hbs);
    g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_SUCCESS);
    page = g_malloc(hbs);
    qtest_memread(qts, buf, page, hbs);
    g_assert_cmpuint(ldl_le_p(page), ==, keys);
    for (i = 0; i < keys; i++) {
        g_assert_cmpuint(lduw_le_p(page + 4 + 12 * i), ==, 8);
    }
    qtest_memread(qts, list, ents_after, sizeof(ents_after));
    g_assert_cmpmem(ents_after, sizeof(ents_after), ents, sizeof(ents));

    /* qos may run the next test on this device, so leave no key */
    for (i = 0; i < keys; i++) {
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = FEMU_KV_CMD_DELETE;
        cmd.nsid = cpu_to_le32(1);
        cmd.res1 = cpu_to_le64(i ? 1000 + i : 42);
        cmd.cdw11 = cpu_to_le32(8);
        g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_SUCCESS);
    }

    g_free(page);
    guest_free(alloc, mem);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/* One List command from @start (@start_len bytes; 0 for none) into @buf. */
static uint32_t femu_kv_list_page(FemuCtrlState *c, uint64_t buf, uint32_t hbs,
                                  const uint8_t *start, uint8_t start_len,
                                  uint8_t *page)
{
    NvmeCmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_KV_CMD_LIST;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(hbs);
    cmd.cdw11 = cpu_to_le32(start_len);
    if (start_len) {
        cmd.res1 = cpu_to_le64(ldq_le_p(start));
        cmd.cdw14 = cpu_to_le32(ldl_le_p(start + 8));
        cmd.cdw15 = cpu_to_le32(ldl_le_p(start + 12));
    }
    qtest_memset(c->pdev->bus->qts, buf, 0xee, hbs);
    g_assert_cmpint(femu_io(c, &cmd), ==, NVME_SUCCESS);
    qtest_memread(c->pdev->bus->qts, buf, page, hbs);

    return ldl_le_p(page);
}

/*
 * Return entry @i of a List page: each entry is a 2-byte length and the key,
 * padded to end on a 4-byte boundary (KV 1.3, Figure 16).
 */
static const uint8_t *femu_kv_list_entry(const uint8_t *page, uint32_t i)
{
    uint32_t pos = 4;

    while (i--) {
        pos = (pos + 2 + lduw_le_p(page + pos) + 3) & ~3u;
    }
    g_assert_cmpuint(lduw_le_p(page + pos), ==, 16);
    return page + pos + 2;
}

/*
 * The Key Value command set has no iterator and no group delete. A host walks
 * a namespace with List (KV 1.3, 2.1.6.2): the order stays the same while
 * nothing is stored or deleted, and a start key that exists comes back first.
 * Use the last key of each page as the next start, drop the repeated first
 * entry, and stop when the first key of the walk comes back. Every stored key
 * must come back exactly once.
 */
void femu_test_kv_list_walk(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    const int keys = 200;
    const uint32_t hbs = 4 + 8 * 20;    /* eight 16-byte keys per page */
    uint8_t page[4 + 8 * 20], first[16], start[16], absent[16];
    int seen[200] = { 0 };
    uint64_t mem, buf;
    NvmeCmd cmd;
    uint32_t nrk, i;
    int k, pages, total = 0;
    bool done = false;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    mem = guest_alloc(alloc, 2 * 4096);
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

    /* key k holds k in bytes 0..1 and k * 0x01010101 in bytes 8..11 */
#define FEMU_KV_WALK_MARK(key) do {                                       \
        int id_ = (key)[0] | ((key)[1] << 8);                            \
        g_assert_cmpint(id_, <, keys);                                   \
        g_assert_cmphex((uint32_t)ldl_le_p((key) + 8), ==,               \
                        id_ * 0x01010101U);                              \
        g_assert_cmpint(seen[id_], ==, 0);                               \
        seen[id_] = 1;                                                   \
        total++;                                                         \
    } while (0)

    nrk = femu_kv_list_page(&c, buf, hbs, NULL, 0, page);
    g_assert_cmpuint(nrk, ==, 8);
    memcpy(first, femu_kv_list_entry(page, 0), 16);
    for (i = 0; i < nrk; i++) {
        FEMU_KV_WALK_MARK(femu_kv_list_entry(page, i));
    }
    memcpy(start, femu_kv_list_entry(page, nrk - 1), 16);

    for (pages = 1; !done; pages++) {
        g_assert_cmpint(pages, <=, keys);
        nrk = femu_kv_list_page(&c, buf, hbs, start, 16, page);
        g_assert_cmpuint(nrk, >, 1);
        /* a start key that exists is returned first */
        g_assert_cmpmem(femu_kv_list_entry(page, 0), 16, start, 16);
        for (i = 1; i < nrk; i++) {
            const uint8_t *key = femu_kv_list_entry(page, i);

            if (!memcmp(key, first, 16)) {
                done = true;
                break;
            }
            FEMU_KV_WALK_MARK(key);
        }
        memcpy(start, femu_kv_list_entry(page, nrk - 1), 16);
    }
#undef FEMU_KV_WALK_MARK

    g_assert_cmpint(total, ==, keys);
    for (k = 0; k < keys; k++) {
        g_assert_cmpint(seen[k], ==, 1);
    }
    g_assert_cmpint(pages, >, keys / 8);

    /*
     * A start key that is not stored gives a vendor-specific first key that
     * must not change while nothing is stored or deleted. This device then
     * starts where a List without a key starts.
     */
    memset(absent, 0x5a, sizeof(absent));
    nrk = femu_kv_list_page(&c, buf, hbs, absent, 16, page);
    g_assert_cmpuint(nrk, ==, 8);
    g_assert_cmpmem(femu_kv_list_entry(page, 0), 16, first, 16);
    nrk = femu_kv_list_page(&c, buf, hbs, absent, 16, page);
    g_assert_cmpmem(femu_kv_list_entry(page, 0), 16, first, 16);

    guest_free(alloc, mem);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/* the device's index hash, so a test can pick keys for given LUNs */
static uint32_t femu_kv_fnv1a(uint64_t key)
{
    uint8_t b[8];
    uint32_t h = 2166136261u;

    stq_le_p(b, key);
    for (int i = 0; i < 8; i++) {
        h ^= b[i];
        h *= 16777619u;
    }
    return h;
}

static uint16_t femu_kv_store(FemuCtrlState *c, uint64_t key, uint64_t buf,
                              uint32_t len)
{
    NvmeCmd cmd;
    uint16_t want = c->cid;
    uint16_t got;
    uint16_t status;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_KV_CMD_STORE;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.dptr.prp2 = cpu_to_le64(buf + 4096);
    cmd.res1 = cpu_to_le64(key);
    cmd.cdw10 = cpu_to_le32(len);
    cmd.cdw11 = cpu_to_le32(8);
    femu_submit(c, &c->io, &cmd);
    status = FEMU_SC(femu_complete(c, &c->io, &got, NULL));
    g_assert_cmpint(got, ==, want);
    return status;
}

/*
 * Every KV command pays one page read for its index lookup. The index is
 * spread over the LUNs by key, so lookups of keys on eight different LUNs run
 * side by side and take one read time between them. Charged on the LUN at
 * address 0, as they were, they queued behind each other and took eight.
 */
void femu_test_kv_base_spread(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t keys[8];
    bool taken[8] = { false };
    int found = 0;
    int64_t start;
    NvmeCmd cmd;

    for (uint64_t k = 1; found < 8; k++) {
        uint32_t lun = femu_kv_fnv1a(k) % 8;

        if (!taken[lun]) {
            taken[lun] = true;
            keys[found++] = k;
        }
    }

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    start = g_get_monotonic_time();
    for (int i = 0; i < 8; i++) {
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = FEMU_KV_CMD_EXIST;
        cmd.nsid = cpu_to_le32(1);
        cmd.res1 = cpu_to_le64(keys[i]);
        cmd.cdw11 = cpu_to_le32(8);
        femu_submit(&c, &c.io, &cmd);
    }
    for (int i = 0; i < 8; i++) {
        /* a lookup that charged nothing would pass the bound below too */
        g_assert_cmphex(FEMU_SC(femu_complete(&c, &c.io, NULL, NULL)), ==,
                        0x87);              /* KV Key Does Not Exist */
    }
    /* one 25 ms read each, on eight LUNs: about 25 ms, not 200 */
    g_assert_cmpint(g_get_monotonic_time() - start, <, 100000);
    femu_disable(&c);
}

/*
 * Value GC collects one victim line at a time. Each line here holds one
 * cold value and three overwrites of a hot key, so a victim has a quarter
 * of its pages valid. GC starts when the free lines fall to the threshold,
 * and a Store that runs it moves one victim's cold pages, a few program
 * times, not the whole live set. One LUN, 2 ms programs, 16 pages a line.
 */
#define FEMU_KV_GC_COLD 200

void femu_test_kv_gc_victim(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t raw = guest_alloc(alloc, 3 * 4096);
    uint64_t buf = (raw + 4095) & ~4095ULL;
    uint64_t log = guest_alloc(alloc, 512);
    int64_t worst = 0;
    uint64_t moved;
    uint8_t got[16];

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    for (uint64_t k = 0; k < FEMU_KV_GC_COLD; k++) {
        for (int h = 0; h < 4; h++) {
            uint64_t key = h ? 1 : 1000 + k;
            int64_t start;
            int64_t took;

            qtest_memset(qts, buf, (int)(key + k), 4096);
            start = g_get_monotonic_time();
            g_assert_cmphex(femu_kv_store(&c, key, buf, 4096), ==,
                            NVME_SUCCESS);
            took = g_get_monotonic_time() - start;
            worst = MAX(worst, took);
        }
    }
    moved = femu_c0h_field(&c, log, 16);
    g_test_message("gc moved %" PRIu64 " pages; slowest Store %" PRId64
                   " us", moved, worst);
    /* GC ran and moved cold pages */
    g_assert_cmpuint(moved, >, 0);
    /* one victim: 4 moves and a Store, not 200 live pages (400 ms) */
    g_assert_cmpint(worst, <, 100000);

    for (uint64_t k = 0; k < FEMU_KV_GC_COLD; k++) {
        NvmeCmd cmd;

        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = FEMU_KV_CMD_RETRIEVE;
        cmd.nsid = cpu_to_le32(1);
        cmd.dptr.prp1 = cpu_to_le64(buf);
        cmd.res1 = cpu_to_le64(1000 + k);
        cmd.cdw10 = cpu_to_le32(4096);
        cmd.cdw11 = cpu_to_le32(8);
        g_assert_cmphex(femu_io(&c, &cmd), ==, NVME_SUCCESS);
        qtest_memread(qts, buf, got, sizeof(got));
        g_assert_cmpuint(got[0], ==, (uint8_t)(1000 + k + k));
        g_assert_cmpuint(got[15], ==, (uint8_t)(1000 + k + k));
    }
    femu_disable(&c);
    guest_free(alloc, log);
    guest_free(alloc, raw);
}

/* the NAND times of the key-value gc-fw tests */
#define FEMU_KV_GC_FW_TR    10000ULL
#define FEMU_KV_GC_FW_TP    10000ULL
#define FEMU_KV_GC_FW_NS    1000000ULL

/*
 * fw_gc_page_ns on key-value collection, on one LUN, with the workload of
 * kv-gc-victim: each cold value is followed by three overwrites of a hot
 * key. With packing, an overwrite in the open DRAM page programs nothing.
 * So the pack case writes five overwrites, spread over 16 hot keys.
 * @data names the case:
 *
 *   pack    1 KiB values packed into GC pages: one slot per GC page
 *   nopack  4 KiB values, kv_pack=off: one slot per moved page
 *   hold    nopack with a 20 ms host stall after each GC read; a slot on
 *           host time would end far after F + tP
 *   lsm     kv_index=lsm: value and meta pages take slots, merges none
 *   off     the control, nopack with no slot
 *
 * Each GC move reads, waits for its slot, then programs, on one LUN, so a
 * Store whose GC made v moves takes at least v (tR + F + tP); v (F + tP)
 * with packing, where two GC pages can follow one read. An unpacked
 * move ends exactly F + tP after its read. A packed GC page may wait for
 * a later source read on its LUN, so only the lower bound holds there.
 */
void femu_test_gc_fw_kv(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    const char *mode = data;
    bool on = strcmp(mode, "off") != 0;
    bool pack = !strcmp(mode, "pack");
    bool lsm = !strcmp(mode, "lsm");
    uint32_t len = pack ? 1024 : 4096;
    uint32_t cold = pack ? 800 : 200;
    int hot = pack ? 6 : 4;
    FemuCtrlState c = { 0 };
    uint64_t raw = guest_alloc(alloc, 3 * 4096);
    uint64_t buf = (raw + 4095) & ~4095ULL;
    uint64_t log = guest_alloc(alloc, 512);
    uint64_t f = femu_gc_fw_ns(qts, "gc-fw");
    /* the last GC page of a victim can program with no read before it */
    uint64_t move = (pack ? 0 : FEMU_KV_GC_FW_TR) + FEMU_KV_GC_FW_NS +
                    FEMU_KV_GC_FW_TP;
    uint64_t g = 0;
    uint64_t gc_stores = 0;

    g_assert_cmpuint(f, ==, on ? FEMU_KV_GC_FW_NS : 0);
    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    if (!strcmp(mode, "hold")) {
        QDict *rsp = qtest_qmp(qts, "{'execute':'qom-set','arguments':{"
                               "'path':'/machine/peripheral/gc-fw',"
                               "'property':'x-gc-hold-us','value':20000}}");

        g_assert_true(qdict_haskey(rsp, "return"));
        qobject_unref(rsp);
    }
    for (uint64_t k = 0; k < cold; k++) {
        for (int h = 0; h < hot; h++) {
            uint64_t key = !h ? 1000 + k :
                           pack ? 1 + (k * (hot - 1) + h - 1) % 16 : 1;
            int64_t start;
            int64_t took;
            uint64_t now;

            qtest_memset(qts, buf, (int)(key + k), 4096);
            start = g_get_monotonic_time();
            g_assert_cmphex(femu_kv_store(&c, key, buf, len), ==,
                            NVME_SUCCESS);
            took = g_get_monotonic_time() - start;
            if (!on || lsm) {
                continue;
            }
            /* the host waits for the modelled time of the Store */
            now = femu_c0h_field(&c, log, 16);
            if (now > g) {
                g_assert_cmpuint((uint64_t)took * 1000, >=, (now - g) * move);
                gc_stores++;
            }
            g = now;
        }
    }
    g_test_message("gc-fw kv %s: %" PRIu64 " Stores ran GC", mode, gc_stores);
    if (on && !lsm) {
        g_assert_cmpuint(gc_stores, >, 0);
    }
    if (pack) {
        femu_gc_fw_assert(&c, log, "gc-fw", f, FEMU_KV_GC_FW_TP,
                          1000000000ULL);
    } else if (lsm) {
        femu_gc_fw_assert(&c, log, "gc-fw", f, 0, 0);
    } else {
        femu_gc_fw_assert(&c, log, "gc-fw", f, FEMU_KV_GC_FW_TP,
                          FEMU_KV_GC_FW_TP);
    }
    femu_disable(&c);
    guest_free(alloc, log);
    guest_free(alloc, raw);
    qos_invalidate_command_line();
}

/*
 * CC.CSS 000b selects the NVM command set for every I/O queue, so a KV
 * namespace answers its commands, Flush among them, with Invalid Command
 * Opcode. 110b enables every set and KV runs (Base 2.3, Figure 41). Under
 * 110b the I/O Command Set Profile takes only the one combination there is.
 */
void femu_test_kv_css(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    bool all = data != NULL;
    uint64_t raw = guest_alloc(alloc, 3 * 4096);
    uint64_t buf = (raw + 4095) & ~4095ULL;
    uint16_t want = all ? NVME_SUCCESS : NVME_INVALID_OPCODE;
    NvmeCmd cmd;

    if (all) {
        femu_enable_csi(&c, &femu->dev, alloc);
    } else {
        femu_enable(&c, &femu->dev, alloc);
    }
    femu_create_io_queues(&c);
    qtest_memset(femu->dev.bus->qts, buf, 0x5a, 4096);

    g_assert_cmphex(femu_kv_store(&c, 7, buf, 4096), ==, want);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_CMD_FLUSH;
    cmd.nsid = cpu_to_le32(1);
    g_assert_cmphex(FEMU_SC(femu_io(&c, &cmd)), ==, want);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_KV_CMD_EXIST;
    cmd.nsid = cpu_to_le32(1);
    cmd.res1 = cpu_to_le64(7);
    cmd.cdw11 = cpu_to_le32(8);
    g_assert_cmphex(FEMU_SC(femu_io(&c, &cmd)), ==, want);

    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, FEMU_FEAT_CMD_SET_PROFILE,
                            false, 0, 0, NULL)), ==, NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, FEMU_FEAT_CMD_SET_PROFILE,
                            false, 0, 1, NULL)), ==,
                    all ? FEMU_IOCS_COMBINATION_REJECTED : NVME_SUCCESS);
    femu_disable(&c);
    guest_free(alloc, raw);
}

/*
 * A hash Delete shifts later entries of its probe run back, so their
 * pages (or packed records) change owner slot. 700 keys in the 1287
 * slots of kv_max_keys=965 collide often (the Deletes shift entries
 * back 4485 times); every other key is deleted, and the owner check
 * (FEMU_KV_CHECK, every 64 commands) then finds each page and record with
 * the slot that holds it. Half of the survivors are rewritten; the other
 * half keep the records whose owners shifted. Then 600 cold keys of 990
 * bytes and overwrites of 4 hot keys fill the lines until GC moves those
 * records too. Every key that is left reads back.
 */
void femu_test_kv_hash_backshift(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t raw = guest_alloc(alloc, 3 * 4096);
    uint64_t buf = (raw + 4095) & ~4095ULL;
    uint64_t log = guest_alloc(alloc, 512);
    uint64_t gc;
    uint8_t got[16];
    NvmeCmd cmd;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    for (uint64_t k = 0; k < 700; k++) {
        qtest_memset(qts, buf, (int)(k & 0xff), 16);
        g_assert_cmphex(femu_kv_store(&c, k, buf, 16), ==, NVME_SUCCESS);
    }
    for (uint64_t k = 0; k < 700; k += 2) {
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = FEMU_KV_CMD_DELETE;
        cmd.nsid = cpu_to_le32(1);
        cmd.res1 = cpu_to_le64(k);
        cmd.cdw11 = cpu_to_le32(8);
        g_assert_cmphex(femu_io(&c, &cmd), ==, NVME_SUCCESS);
    }
    /* overwrites fill the lines, so GC moves the shifted entries' pages */
    for (int round = 0; round < 2; round++) {
        for (uint64_t k = 1; k < 700; k += 4) {
            qtest_memset(qts, buf, (int)((k + round + 1) & 0xff), 16);
            g_assert_cmphex(femu_kv_store(&c, k, buf, 16), ==,
                            NVME_SUCCESS);
        }
    }
    /*
     * Packed, those 16 byte values take a few pages. Larger cold values
     * beside dead hot ones fill the lines, and GC runs over the shifted
     * records as well.
     */
    gc = femu_c0h_field(&c, log, 16);
    qtest_memset(qts, buf, 0x6b, 990);
    for (uint64_t j = 0; j < 600; j++) {
        g_assert_cmphex(femu_kv_store(&c, 5000 + j, buf, 990), ==,
                        NVME_SUCCESS);
        g_assert_cmphex(femu_kv_store(&c, 9000 + j % 4, buf, 990), ==,
                        NVME_SUCCESS);
    }
    g_test_message("GC pages: %" PRIu64 " before the cold keys, %" PRIu64
                   " after", gc, femu_c0h_field(&c, log, 16));
    g_assert_cmpuint(femu_c0h_field(&c, log, 16), >, gc);
    for (uint64_t k = 0; k < 700; k++) {
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = FEMU_KV_CMD_RETRIEVE;
        cmd.nsid = cpu_to_le32(1);
        cmd.dptr.prp1 = cpu_to_le64(buf);
        cmd.res1 = cpu_to_le64(k);
        cmd.cdw10 = cpu_to_le32(16);
        cmd.cdw11 = cpu_to_le32(8);
        g_assert_cmphex(femu_io(&c, &cmd), ==, k & 1 ? NVME_SUCCESS : 0x87);
        if (k & 1) {
            qtest_memread(qts, buf, got, sizeof(got));
            /* k % 4 == 3 keeps the value of its first Store */
            g_assert_cmpuint(got[0], ==, (uint8_t)(k % 4 == 1 ? k + 2 : k));
        }
    }
    femu_disable(&c);
    guest_free(alloc, log);
    guest_free(alloc, raw);
}

/*
 * kv_timing=model with test coefficients: kIOPS = 0.05 + 0.075 insert +
 * 0.2 read. A window of only inserts gives 0.125 kIOPS (8 ms a command),
 * only updates 0.05 (20 ms) and only reads 0.25 (4 ms). A 64 KiB insert
 * window is past the 16 KiB fit, so it takes 4 x 8 = 32 ms. The media model
 * takes well under a millisecond for each of these.
 */
#define KV_MODEL_TEST_TERMS \
    ",0,0,0.075,0.2" ",0,0,0,0,0,0,0,0,0,0" ",0,0,0,0,0,0,0,0,0,0" \
    ",0,0,0,0,0,0,0,0,0,0" ",0"
#define KV_MODEL_TEST_COEFFS "0.05" KV_MODEL_TEST_TERMS
#define KV_MODEL_INSERT_MS  8
#define KV_MODEL_UPDATE_MS  20
#define KV_MODEL_READ_MS    4
#define KV_MODEL_BIG_MS     32

/* run one KV command and return its wall time in microseconds */
static int64_t femu_kv_timed(FemuCtrlState *c, uint8_t opcode, uint64_t buf,
                             uint64_t list, uint64_t key, uint32_t len)
{
    NvmeCmd cmd;
    int64_t t0;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = opcode;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.dptr.prp2 = cpu_to_le64(len > 2 * 4096 ? list : buf + 4096);
    cmd.res1 = cpu_to_le64(key);
    cmd.cdw10 = cpu_to_le32(len);
    cmd.cdw11 = cpu_to_le32(8);
    t0 = g_get_monotonic_time();
    femu_submit(c, &c->io, &cmd);
    g_assert_cmpint(FEMU_SC(femu_complete(c, &c->io, NULL, NULL)), ==,
                    NVME_SUCCESS);
    return g_get_monotonic_time() - t0;
}

/*
 * Run @n commands and return the shortest wall time in microseconds of the
 * last eight, when the window holds only this kind of command. A busy host
 * only adds to each command, so the shortest is the closest to the model.
 */
static int64_t femu_kv_min(FemuCtrlState *c, uint8_t opcode, uint64_t buf,
                           uint64_t list, uint64_t key0, bool same_key,
                           uint32_t len, int n)
{
    int64_t min = INT64_MAX;
    int i;

    g_assert_cmpint(n, >=, 16 + 8);
    for (i = 0; i < n; i++) {
        int64_t us = femu_kv_timed(c, opcode, buf, list,
                                   same_key ? key0 : key0 + i, len);

        if (i >= n - 8) {
            min = MIN(min, us);
        }
    }
    return min;
}

void femu_test_kv_model(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    bool on = data != NULL;
    FemuCtrlState c = { 0 };
    uint64_t buf;
    uint64_t list;
    int64_t ins, upd, rd, big;
    int i;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, 65536);
    list = guest_alloc(alloc, 4096);
    qtest_memset(femu->dev.bus->qts, buf, 0x5a, 65536);
    /* the PRP list of a 64 KiB value: every page after the first */
    for (i = 1; i < 16; i++) {
        uint64_t prp = cpu_to_le64(buf + i * 4096);

        qtest_memwrite(femu->dev.bus->qts, list + (i - 1) * 8, &prp, 8);
    }

    ins = femu_kv_min(&c, FEMU_KV_CMD_STORE, buf, list, 0x1000, false,
                      4096, 24);
    /* stores over one key that the inserts made: every one an update */
    upd = femu_kv_min(&c, FEMU_KV_CMD_STORE, buf, list, 0x1000, true,
                      4096, 24);
    rd = femu_kv_min(&c, FEMU_KV_CMD_RETRIEVE, buf, list, 0x1000, true,
                     4096, 24);
    big = femu_kv_min(&c, FEMU_KV_CMD_STORE, buf, list, 0x2000, false,
                      65536, 24);
    g_test_message("kv_timing %s: shortest us insert %" PRId64 " update %"
                   PRId64 " read %" PRId64 " 64KiB insert %" PRId64,
                   on ? "model" : "media", ins, upd, rd, big);

    if (on) {
        /*
         * The model time is a floor; a loaded host only adds to it. The
         * ceiling, 1.5 times the model time plus the 1 ms poll of the test,
         * catches a model that is wrong by half. Each value is the shortest
         * of the last eight commands, so seven slow commands pass.
         */
        g_assert_cmpint(ins, >=, KV_MODEL_INSERT_MS * 1000);
        g_assert_cmpint(upd, >=, KV_MODEL_UPDATE_MS * 1000);
        g_assert_cmpint(rd, >=, KV_MODEL_READ_MS * 1000);
        g_assert_cmpint(big, >=, KV_MODEL_BIG_MS * 1000);
        g_assert_cmpint(ins, <, KV_MODEL_INSERT_MS * 1500 + 2000);
        g_assert_cmpint(upd, <, KV_MODEL_UPDATE_MS * 1500 + 2000);
        g_assert_cmpint(rd, <, KV_MODEL_READ_MS * 1500 + 2000);
        g_assert_cmpint(big, <, KV_MODEL_BIG_MS * 1500 + 2000);
    } else {
        /* the coefficients are set, but media timing ignores them */
        g_assert_cmpint(ins, <, KV_MODEL_READ_MS * 1000);
        g_assert_cmpint(upd, <, KV_MODEL_READ_MS * 1000);
        g_assert_cmpint(rd, <, KV_MODEL_READ_MS * 1000);
        g_assert_cmpint(big, <, KV_MODEL_READ_MS * 1000);
    }

    femu_disable(&c);
    guest_free(alloc, list);
    guest_free(alloc, buf);
}

/* a bad kv_timing or kv_model_coeffs fails realize */
void femu_test_kv_model_refused(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    static const char *const bad[][2] = {
        { "fast", NULL },
        { "model", "1,2,3" },
        { "model", "inf" KV_MODEL_TEST_TERMS },
        { "model", KV_MODEL_TEST_COEFFS ",0" },
    };
    QDict *rsp;
    size_t i;

    for (i = 0; i < ARRAY_SIZE(bad); i++) {
        QDict *args = qdict_new();
        const char *desc;

        qdict_put_str(args, "driver", "femu");
        qdict_put_str(args, "id", "kvbad");
        qdict_put_str(args, "addr", "5");
        qdict_put_int(args, "devsz_mb", 512);
        qdict_put_int(args, "femu_mode", 5);
        qdict_put_str(args, "kv_timing", bad[i][0]);
        if (bad[i][1]) {
            qdict_put_str(args, "kv_model_coeffs", bad[i][1]);
        }
        rsp = qtest_qmp(femu->dev.bus->qts,
                        "{'execute':'device_add','arguments':%p}", args);
        g_assert_true(qdict_haskey(rsp, "error"));
        desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
        g_test_message("%s", desc);
        g_assert_nonnull(strstr(desc, i ? "kv_model_coeffs" : "kv_timing"));
        qobject_unref(rsp);
    }

    /*
     * The knobs time KV commands only, so a device with no KV namespace
     * refuses them. One KV namespace among others is enough.
     */
    for (i = 0; i < 3; i++) {
        QDict *args = qdict_new();

        qdict_put_str(args, "driver", "femu");
        qdict_put_str(args, "id", "kvnone");
        qdict_put_str(args, "addr", "5");
        qdict_put_int(args, "devsz_mb", 64);
        qdict_put_int(args, "femu_mode", 1);
        qdict_put_int(args, "namespaces", 2);
        qdict_put_int(args, "secs_per_pg", 8);
        qdict_put_int(args, "pgs_per_blk", 16);
        qdict_put_int(args, "blks_per_pl", 80);
        qdict_put_int(args, "pls_per_lun", 1);
        qdict_put_int(args, "luns_per_ch", 4);
        qdict_put_int(args, "nchs", 4);
        if (i == 0) {
            qdict_put_str(args, "kv_timing", "model");
        } else {
            qdict_put_str(args, "kv_model_coeffs", KV_MODEL_TEST_COEFFS);
        }
        if (i == 2) {
            qdict_put_str(args, "kv_timing", "model");
            qdict_put_str(args, "namespace_modes", "bbssd,kvssd");
        }
        rsp = qtest_qmp(femu->dev.bus->qts,
                        "{'execute':'device_add','arguments':%p}", args);
        if (i < 2) {
            const char *desc;

            g_assert_true(qdict_haskey(rsp, "error"));
            desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
            g_test_message("%s", desc);
            g_assert_nonnull(strstr(desc, "need a key-value namespace"));
        } else {
            g_assert_true(qdict_haskey(rsp, "return"));
        }
        qobject_unref(rsp);
    }
    /* the accepted device stays plugged: the next test needs a new QEMU */
    qos_invalidate_command_line();
}

static uint64_t femu_lsm_key(uint64_t i)
{
    return bswap64(i);
}

/* value byte of key @i at version @ver */
static uint8_t femu_lsm_byte(uint64_t i, int ver)
{
    return (uint8_t)(i * 13 + ver * 101 + 1);
}

static uint16_t femu_lsm_cmd(FemuCtrlState *c, uint8_t opcode, uint64_t i,
                             uint64_t buf, uint32_t len, uint8_t opt)
{
    NvmeCmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = opcode;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.dptr.prp2 = cpu_to_le64(buf + 4096);
    cmd.res1 = cpu_to_le64(femu_lsm_key(i));
    cmd.cdw10 = cpu_to_le32(len);
    cmd.cdw11 = cpu_to_le32(8 | (uint32_t)opt << 8);
    return femu_io(c, &cmd);
}

static uint16_t femu_lsm_store(FemuCtrlState *c, uint64_t i, uint64_t buf,
                               uint32_t len, int ver)
{
    qtest_memset(c->pdev->bus->qts, buf, femu_lsm_byte(i, ver), len);
    return femu_lsm_cmd(c, FEMU_KV_CMD_STORE, i, buf, len, 0);
}

/* Retrieve @i and check every byte; return the status */
static uint16_t femu_lsm_check(FemuCtrlState *c, uint64_t i, uint64_t buf,
                               uint32_t len, int ver)
{
    uint8_t got[8192];
    uint16_t status;

    g_assert_cmpuint(len, <=, sizeof(got));
    qtest_memset(c->pdev->bus->qts, buf, 0, len);
    status = femu_lsm_cmd(c, FEMU_KV_CMD_RETRIEVE, i, buf, len, 0);
    if (status == NVME_SUCCESS) {
        qtest_memread(c->pdev->bus->qts, buf, got, len);
        for (uint32_t k = 0; k < len; k++) {
            if (got[k] != femu_lsm_byte(i, ver)) {
                g_test_message("key %" PRIu64 " byte %u: 0x%x, want 0x%x", i, k,
                               got[k], femu_lsm_byte(i, ver));
                g_assert_not_reached();
            }
        }
    }
    return status;
}

/* the lsm member of namespace 1; the reply is handed back to unref */
static QDict *femu_lsm_info(QTestState *qts, QDict **rsp)
{
    QDict *lsm = qdict_get_qdict(femu_query_ns(qts, "", rsp), "lsm");

    g_assert_nonnull(lsm);
    return lsm;
}

static int64_t femu_lsm_stat(QTestState *qts, const char *name)
{
    QDict *rsp;
    int64_t v = qdict_get_int(femu_lsm_info(qts, &rsp), name);

    qobject_unref(rsp);
    return v;
}

/*
 * Walk the namespace with List pages of @hbs bytes, as a host does: each
 * page starts at the last key of the one before, which comes back first.
 * Return the keys in walk order in @out, stopping at the wrap.
 */
static int femu_lsm_walk(FemuCtrlState *c, uint64_t buf, uint32_t hbs,
                         uint64_t *out, int max)
{
    g_autofree uint8_t *page = g_malloc(hbs);
    uint8_t start[16];
    uint8_t start_len = 0;
    int n = 0;

    for (;;) {
        uint32_t nrk = femu_kv_list_page(c, buf, hbs, start, start_len, page);
        uint32_t pos = 4;
        int added = 0;

        for (uint32_t e = 0; e < nrk; e++) {
            uint16_t kl = lduw_le_p(page + pos);
            uint64_t v;

            g_assert_cmpuint(kl, ==, 8);
            v = bswap64(ldq_le_p(page + pos + 2));
            pos = (pos + 2 + kl + 3) & ~3u;
            if (start_len && e == 0 && v == out[n - 1]) {
                continue;               /* the start key comes back first */
            }
            if (n && v <= out[n - 1]) {
                return n;               /* the wrap */
            }
            g_assert_cmpint(n, <, max);
            out[n++] = v;
            added++;
        }
        if (!added) {
            return n;
        }
        stq_le_p(start, femu_lsm_key(out[n - 1]));
        memset(start + 8, 0, 8);
        start_len = 8;
    }
}

/*
 * 3000 keys over seven levels: stores in a mixed order, overwrites of a
 * third, deletes of a fifth, and stores again of half of those. Every
 * Retrieve returns the newest value or Key Does Not Exist, and a List walk
 * returns each live key once, in order.
 */
#define FEMU_LSM_MANY 3000

static int femu_lsm_ver(int i)
{
    return i % 10 == 0 ? 2 : i % 3 == 0 ? 1 : 0;
}

static bool femu_lsm_live(int i)
{
    return i % 5 != 0 || i % 10 == 0;
}

void femu_test_kv_lsm_many_keys(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t raw = guest_alloc(alloc, 3 * 4096);
    uint64_t buf = (raw + 4095) & ~4095ULL;
    g_autofree uint64_t *walk = g_new(uint64_t, FEMU_LSM_MANY);
    int live = 0;
    int n, i;
    QDict *rsp;
    QDict *lsm;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    for (i = 0; i < FEMU_LSM_MANY; i++) {
        int k = (i * 1237) % FEMU_LSM_MANY;

        g_assert_cmphex(femu_lsm_store(&c, k, buf, 64, 0), ==, NVME_SUCCESS);
    }
    for (i = 0; i < FEMU_LSM_MANY; i += 3) {
        g_assert_cmphex(femu_lsm_store(&c, i, buf, 64, 1), ==, NVME_SUCCESS);
    }
    for (i = 0; i < FEMU_LSM_MANY; i += 5) {
        g_assert_cmphex(femu_lsm_cmd(&c, FEMU_KV_CMD_DELETE, i, buf, 0, 0),
                        ==, NVME_SUCCESS);
    }
    for (i = 0; i < FEMU_LSM_MANY; i += 10) {
        g_assert_cmphex(femu_lsm_store(&c, i, buf, 64, 2), ==, NVME_SUCCESS);
    }

    for (i = 0; i < FEMU_LSM_MANY; i++) {
        uint16_t want = femu_lsm_live(i) ? NVME_SUCCESS : 0x87;

        live += femu_lsm_live(i);
        g_assert_cmphex(femu_lsm_check(&c, i, buf, 64, femu_lsm_ver(i)), ==,
                        want);
        if (i % 3 == 1) {
            g_assert_cmphex(femu_lsm_cmd(&c, FEMU_KV_CMD_EXIST, i, buf, 0, 0),
                            ==, want);
        }
    }

    n = femu_lsm_walk(&c, buf, 4096, walk, FEMU_LSM_MANY);
    g_assert_cmpint(n, ==, live);
    for (i = 0; i < n; i++) {
        g_assert_true(walk[i] < FEMU_LSM_MANY && femu_lsm_live(walk[i]));
    }

    /* the keys reached unpinned levels, and merges dropped old versions */
    lsm = femu_lsm_info(qts, &rsp);
    g_test_message("levels %zu, compactions %" PRId64 ", dropped %" PRId64
                   ", probe reads %" PRId64,
                   qlist_size(qdict_get_qlist(lsm, "levels")),
                   qdict_get_int(lsm, "compactions"),
                   qdict_get_int(lsm, "dropped-records"),
                   qdict_get_int(lsm, "probe-read-pages"));
    g_assert_cmpuint(qlist_size(qdict_get_qlist(lsm, "levels")), >=, 6);
    g_assert_cmpint(qdict_get_int(lsm, "compactions"), >, 0);
    g_assert_cmpint(qdict_get_int(lsm, "dropped-records"), >, 0);
    g_assert_cmpint(qdict_get_int(lsm, "probe-read-pages"), >, 0);
    g_assert_cmpint(qdict_get_int(lsm, "scan-read-pages"), >, 0);
    qobject_unref(rsp);

    femu_disable(&c);
    guest_free(alloc, raw);
}

/*
 * List returns the keys in byte order from the start key, then wraps; a
 * start key that is gone gives the next key, one past the last the
 * smallest. Merges between two Lists keep the order.
 */
void femu_test_kv_lsm_list_order(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t raw = guest_alloc(alloc, 3 * 4096);
    uint64_t buf = (raw + 4095) & ~4095ULL;
    g_autofree uint8_t *page = g_malloc(4096);
    uint64_t walk[256];
    uint8_t start[16] = { 0 };
    uint32_t nrk;
    int i, n;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    for (i = 0; i < 200; i++) {
        g_assert_cmphex(femu_lsm_store(&c, (i * 37) % 200, buf, 16, 0), ==,
                        NVME_SUCCESS);
    }

    stq_le_p(start, femu_lsm_key(100));
    nrk = femu_kv_list_page(&c, buf, 4096, start, 8, page);
    g_assert_cmpuint(nrk, ==, 200);
    for (i = 0; i < 200; i++) {
        uint64_t v = bswap64(ldq_le_p(page + 4 + 12 * i + 2));

        g_assert_cmpuint(v, ==, (uint64_t)(100 + i) % 200);
    }

    /* more merges, then the deleted key 150 and the absent key 1000 */
    for (i = 200; i < 240; i++) {
        g_assert_cmphex(femu_lsm_store(&c, i, buf, 16, 0), ==, NVME_SUCCESS);
    }
    g_assert_cmphex(femu_lsm_cmd(&c, FEMU_KV_CMD_DELETE, 150, buf, 0, 0), ==,
                    NVME_SUCCESS);
    n = femu_lsm_walk(&c, buf, 256, walk, 256);
    g_assert_cmpint(n, ==, 239);
    for (i = 0; i < n; i++) {
        g_assert_cmpuint(walk[i], ==, (uint64_t)(i < 150 ? i : i + 1));
    }
    stq_le_p(start, femu_lsm_key(150));
    femu_kv_list_page(&c, buf, 4096, start, 8, page);
    g_assert_cmpuint(bswap64(ldq_le_p(page + 6)), ==, 151);
    stq_le_p(start, femu_lsm_key(1000));
    femu_kv_list_page(&c, buf, 4096, start, 8, page);
    g_assert_cmpuint(bswap64(ldq_le_p(page + 6)), ==, 0);

    femu_disable(&c);
    guest_free(alloc, raw);
}

/* wall time in microseconds of one KV command that must return @want */
static int64_t femu_lsm_timed(FemuCtrlState *c, uint8_t opcode, uint64_t i,
                              uint64_t buf, uint32_t len, uint16_t want)
{
    int64_t t0 = g_get_monotonic_time();

    g_assert_cmphex(femu_lsm_cmd(c, opcode, i, buf, len, 0), ==, want);
    return g_get_monotonic_time() - t0;
}

/*
 * The least wall time of @tries runs of a KV command that reads no flash.
 * A host delay adds time to one run only; a flash read adds it to each.
 */
static int64_t femu_lsm_timed_min(FemuCtrlState *c, uint8_t opcode,
                                  uint64_t i, uint64_t buf, uint32_t len,
                                  uint16_t want, int tries)
{
    int64_t best = INT64_MAX;
    int t;

    for (t = 0; t < tries; t++) {
        best = MIN(best, femu_lsm_timed(c, opcode, i, buf, len, want));
    }
    return best;
}

/*
 * A lookup reads the meta page of each unpinned level whose key range
 * holds the key, one after the other, and then the value. With 25 ms
 * reads, a key found after k meta pages takes (k + 1) reads; a key in the
 * memtable takes one, the value read. The tree has no other index read.
 */
#define FEMU_LSM_READ_US 25000

void femu_test_kv_lsm_probe_time(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t raw = guest_alloc(alloc, 3 * 4096);
    uint64_t buf = (raw + 4095) & ~4095ULL;
    int64_t us, reads = 0;
    int i, found = -1;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    for (i = 0; i < 136; i++) {
        g_assert_cmphex(femu_lsm_store(&c, (i * 53) % 136, buf, 16, 0), ==,
                        NVME_SUCCESS);
    }
    /* the merges run in the background; let the LUNs drain */
    g_usleep(500000);

    /* a key stored last is in the memtable: no meta page read */
    reads = femu_lsm_stat(qts, "probe-read-pages");
    us = femu_lsm_timed(&c, FEMU_KV_CMD_RETRIEVE, (135 * 53) % 136, buf, 16,
                        NVME_SUCCESS);
    g_assert_cmpint(femu_lsm_stat(qts, "probe-read-pages"), ==, reads);
    g_test_message("memtable key: %" PRId64 " us", us);

    /* a key below an overlapping level reads two meta pages */
    for (i = 0; i < 136 && found < 0; i++) {
        int64_t k;

        g_usleep(3 * FEMU_LSM_READ_US);
        reads = femu_lsm_stat(qts, "probe-read-pages");
        us = femu_lsm_timed(&c, FEMU_KV_CMD_RETRIEVE, i, buf, 16,
                            NVME_SUCCESS);
        k = femu_lsm_stat(qts, "probe-read-pages") - reads;
        if (k >= 2) {
            found = i;
            g_test_message("key %d: %" PRId64 " meta reads, %" PRId64 " us",
                           i, k, us);
            /* host delays only add time, so only the floor is checked */
            g_assert_cmpint(us, >=, (k + 1) * FEMU_LSM_READ_US - 2000);
        }
    }
    g_assert_cmpint(found, >=, 0);

    /*
     * A miss past every level reads no meta page, and the tree reads no
     * other flash: no base read, so it takes no 25 ms read time.
     */
    g_usleep(3 * FEMU_LSM_READ_US);
    reads = femu_lsm_stat(qts, "probe-read-pages");
    us = femu_lsm_timed_min(&c, FEMU_KV_CMD_EXIST, 5000, buf, 0, 0x87, 5);
    g_assert_cmpint(femu_lsm_stat(qts, "probe-read-pages"), ==, reads);
    g_test_message("miss: least of 5 runs %" PRId64 " us", us);
    g_assert_cmpint(us, <, FEMU_LSM_READ_US / 2);
    /* an Exist that the memtable answers costs no flash either */
    us = femu_lsm_timed_min(&c, FEMU_KV_CMD_EXIST, (135 * 53) % 136, buf, 0,
                            NVME_SUCCESS, 5);
    g_test_message("memtable Exist: least of 5 runs %" PRId64 " us", us);
    g_assert_cmpint(us, <, FEMU_LSM_READ_US / 2);

    femu_disable(&c);
    guest_free(alloc, raw);
}

/*
 * One LUN, 200 ms programs. The 17th Store finds the memtable full and
 * flushes it to an unpinned level 1: one meta page program. It runs in
 * the background, so that Store takes one program time. An Exist sent
 * right behind it waits for that program on the LUN: two program times.
 * A merge in the foreground would make the Store take two as well. The
 * ceiling on the Store sits 120 ms above one program and 80 ms below
 * two, as wide as the other KV timing tests leave for host delays.
 */
#define FEMU_LSM_PROG_US 200000

void femu_test_kv_lsm_background(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t raw = guest_alloc(alloc, 3 * 4096);
    uint64_t buf = (raw + 4095) & ~4095ULL;
    int64_t t0, store, exist;
    NvmeCmd cmd[2];
    uint16_t cid;
    int i;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    for (i = 0; i < 16; i++) {
        g_assert_cmphex(femu_lsm_store(&c, i, buf, 16, 0), ==, NVME_SUCCESS);
    }
    g_assert_cmpint(femu_lsm_stat(qts, "flushes"), ==, 0);

    qtest_memset(qts, buf, femu_lsm_byte(16, 0), 16);
    memset(cmd, 0, sizeof(cmd));
    for (i = 0; i < 2; i++) {
        cmd[i].opcode = i ? FEMU_KV_CMD_EXIST : FEMU_KV_CMD_STORE;
        cmd[i].nsid = cpu_to_le32(1);
        cmd[i].dptr.prp1 = cpu_to_le64(buf);
        cmd[i].res1 = cpu_to_le64(femu_lsm_key(i ? 3 : 16));
        cmd[i].cdw10 = cpu_to_le32(i ? 0 : 16);
        cmd[i].cdw11 = cpu_to_le32(8);
    }
    t0 = g_get_monotonic_time();
    femu_submit(&c, &c.io, &cmd[0]);
    femu_submit(&c, &c.io, &cmd[1]);
    g_assert_cmphex(FEMU_SC(femu_complete(&c, &c.io, &cid, NULL)), ==,
                    NVME_SUCCESS);
    store = g_get_monotonic_time() - t0;
    g_assert_cmphex(FEMU_SC(femu_complete(&c, &c.io, &cid, NULL)), ==,
                    NVME_SUCCESS);
    exist = g_get_monotonic_time() - t0;
    g_test_message("flushing Store done at %" PRId64 " us, Exist at %" PRId64
                   " us", store, exist);
    g_assert_cmpint(femu_lsm_stat(qts, "flushes"), ==, 1);
    g_assert_cmpint(femu_lsm_stat(qts, "compaction-program-pages"), ==, 1);
    g_assert_cmpint(store, >=, FEMU_LSM_PROG_US - 2000);
    g_assert_cmpint(store, <, FEMU_LSM_PROG_US * 8 / 5);
    g_assert_cmpint(exist, >=, 2 * FEMU_LSM_PROG_US - 2000);

    femu_disable(&c);
    guest_free(alloc, raw);
}

/*
 * query-femu reports the tree, also before the controller is enabled:
 * every record is in a level or the memtable, the levels are numbered from
 * 1 with level 1 pinned, and the DRAM figure follows its definition. A
 * hash device reports no lsm member.
 */
void femu_test_kv_lsm_query(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t raw, buf;
    int64_t records, dram = 0, flash = 0;
    QListEntry *e;
    QDict *rsp, *lsm, *ns;
    int level = 0;
    int i;

    if (!data) {
        ns = femu_query_ns(qts, "", &rsp);
        g_assert_false(qdict_haskey(ns, "lsm"));
        /* nsid, mode, media and the value packing */
        g_assert_true(qdict_haskey(ns, "pack"));
        g_assert_cmpuint(qdict_size(ns), ==, 4);
        qobject_unref(rsp);
        return;
    }

    lsm = femu_lsm_info(qts, &rsp);
    g_assert_cmpint(qdict_get_int(lsm, "memtable-capacity"), ==, 16);
    g_assert_cmpint(qdict_get_int(lsm, "size-ratio"), ==, 2);
    g_assert_cmpint(qdict_get_int(lsm, "pinned-levels"), ==, 1);
    g_assert_cmpint(qdict_get_int(lsm, "records-per-page"), ==, 128);
    g_assert_cmpuint(qlist_size(qdict_get_qlist(lsm, "levels")), ==, 0);
    qobject_unref(rsp);

    raw = guest_alloc(alloc, 3 * 4096);
    buf = (raw + 4095) & ~4095ULL;
    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    for (i = 0; i < 300; i++) {
        g_assert_cmphex(femu_lsm_store(&c, (i * 7) % 300, buf, 16, 0), ==,
                        NVME_SUCCESS);
    }

    lsm = femu_lsm_info(qts, &rsp);
    records = qdict_get_int(lsm, "memtable-keys");
    dram = records * 32;
    QLIST_FOREACH_ENTRY(qdict_get_qlist(lsm, "levels"), e) {
        QDict *lv = qobject_to(QDict, qlist_entry_obj(e));
        int64_t nr = qdict_get_int(lv, "records");
        int64_t pages = qdict_get_int(lv, "pages");

        g_assert_cmpint(qdict_get_int(lv, "level"), ==, ++level);
        g_assert_cmpint(qdict_get_bool(lv, "pinned"), ==, level == 1);
        g_assert_cmpint(pages, >=, (nr + 127) / 128);
        if (level == 1) {
            dram += nr * 32;
        } else {
            dram += pages * 24;
            flash += pages * 4096;
        }
        records += nr;
    }
    /* distinct keys, no delete: one record each */
    g_assert_cmpint(records, ==, 300);
    g_assert_cmpint(level, >=, 4);
    g_assert_cmpint(qdict_get_int(lsm, "device-dram-bytes"), ==, dram);
    g_assert_cmpint(qdict_get_int(lsm, "meta-flash-bytes"), ==, flash);
    g_assert_cmpint(qdict_get_int(lsm, "flushes"), ==, 18);
    g_assert_cmpint(qdict_get_int(lsm, "compaction-program-pages"), >, 0);
    g_assert_cmpint(qdict_get_int(lsm, "compaction-read-pages"), >, 0);
    qobject_unref(rsp);

    femu_disable(&c);
    guest_free(alloc, raw);
}

/* each kv_index refusal, with a hint of its message */
void femu_test_kv_lsm_refused(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    static const struct {
        int mode;
        const char *opts;
        const char *want;
    } bad[] = {
        { 5, "'kv_index':'btree'", "is not hash or lsm" },
        { 1, "'kv_index':'btree'", "is not hash or lsm" },
        { 5, "'kv_lsm_size_ratio':4", "need kv_index=lsm" },
        { 5, "'kv_index':'hash','kv_lsm_pinned_levels':0",
          "need kv_index=lsm" },
        { 5, "'kv_index':'lsm','kv_lsm_size_ratio':1", "is not 2 to 64" },
        { 5, "'kv_index':'lsm','kv_lsm_size_ratio':65", "is not 2 to 64" },
        { 5, "'kv_index':'lsm','kv_lsm_memtable_keys':15",
          "is not 16 to 65536" },
        { 5, "'kv_index':'lsm','kv_lsm_memtable_keys':65537",
          "is not 16 to 65536" },
        { 5, "'kv_index':'lsm','kv_lsm_pinned_levels':25", "is not 0 to 24" },
        { 1, "'kv_index':'lsm'", "need a key-value namespace" },
        { 1, "'kv_index':'lsm','namespaces':2,"
          "'namespace_modes':'bbssd,nossd'", "need a key-value namespace" },
        { 5, "'kv_index':'lsm','secsz':16,'secs_per_pg':1",
          "needs a page of at least 32 bytes" },
        { 1, "'kv_pack':false", "kv_pack=off needs a key-value namespace" },
        { 1, "'kv_max_keys':100", "kv_max_keys needs a key-value namespace" },
        { 5, "'kv_max_keys':1610612736", "is not 0 to 1610612735" },
    };

    for (size_t i = 0; i < ARRAY_SIZE(bad); i++) {
        g_autofree char *json = g_strdup_printf(
            "{'driver':'femu','id':'lsmbad','addr':'5','devsz_mb':64,"
            "'femu_mode':%d,%s}", bad[i].mode, bad[i].opts);
        QObject *args = qobject_from_json(json, &error_abort);
        QDict *rsp = qtest_qmp(femu->dev.bus->qts,
                               "{'execute':'device_add','arguments':%p}",
                               args);
        const char *desc;

        g_assert_true(qdict_haskey(rsp, "error"));
        desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
        g_test_message("%s: %s", bad[i].opts, desc);
        g_assert_nonnull(strstr(desc, bad[i].want));
        qobject_unref(rsp);
    }
}

/* MNK, the key limit of KV format 0 (KV 1.3, Figures 41 and 42) */
static uint32_t femu_kv_mnk(FemuCtrlState *c, QGuestAllocator *alloc)
{
    uint64_t buf = guest_alloc(alloc, 4096);
    uint32_t mnk;

    g_assert_cmphex(femu_identify(c, 1, NVME_ID_CNS_CS_NS,
                                  (uint32_t)FEMU_CSI_KV << 24, buf), ==,
                    NVME_SUCCESS);
    mnk = qtest_readl(c->pdev->bus->qts, buf + 72 + 8);
    guest_free(alloc, buf);
    return mnk;
}

/*
 * With kv_pack the key limit is the number of 1-byte values the usable
 * flash holds. 1.5 MiB of NAND with 4 KiB pages, 3/4 of it usable, is
 * 288 pages of 124 records of 33 bytes. The old index took two slots for
 * each 4 KiB of value space, 1023 keys here, so 64-byte values stopped
 * with most of the space free. Now they fill it: the Stores stop with
 * Capacity Exceeded, below MNK, once NUSE is near NSZE, and every value
 * reads back.
 */
void femu_test_kv_keys_small(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t raw = guest_alloc(alloc, 3 * 4096);
    uint64_t buf = (raw + 4095) & ~4095ULL;
    uint64_t id = guest_alloc(alloc, 4096);
    uint64_t nsze, nuse;
    uint32_t mnk;
    uint16_t status;
    uint64_t n;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    mnk = femu_kv_mnk(&c, alloc);
    g_assert_cmpuint(mnk, ==, 288 * 124);
    for (n = 0; n < mnk; n++) {
        status = femu_lsm_store(&c, n, buf, 64, 0);
        if (status != NVME_SUCCESS) {
            break;
        }
    }
    g_assert_cmphex(femu_identify(&c, 1, NVME_ID_CNS_CS_NS,
                                  (uint32_t)FEMU_CSI_KV << 24, id), ==,
                    NVME_SUCCESS);
    nsze = qtest_readq(femu->dev.bus->qts, id);
    nuse = qtest_readq(femu->dev.bus->qts, id + 16);
    g_test_message("MNK %u, 64-byte values stored %" PRIu64 ", NUSE %"
                   PRIu64 " of NSZE %" PRIu64, mnk, n, nuse, nsze);
    g_assert_cmphex(status, ==, NVME_CAP_EXCEEDED);
    g_assert_cmpuint(n, <, mnk);
    g_assert_cmpuint(nuse * 10, >=, nsze * 9);
    for (uint64_t i = 0; i < n; i++) {
        g_assert_cmphex(femu_lsm_check(&c, i, buf, 64, 0), ==, NVME_SUCCESS);
    }
    femu_disable(&c);
    guest_free(alloc, id);
    guest_free(alloc, raw);
}

/*
 * The automatic key limit of a geometry, in data. 100 pages at
 * gc_thres_pcent=29 are 29 usable pages of 124 records; 100 * 0.29 in
 * double is 28.999..., which once cut a page. NAND of 1 GiB reaches the
 * top of 4194303 keys. Without kv_pack a small value space keeps the
 * old floor of 1023 keys.
 */
void femu_test_kv_mnk_auto(void *obj, void *data,
                           QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };

    femu_enable_csi(&c, &femu->dev, alloc);
    g_assert_cmpuint(femu_kv_mnk(&c, alloc), ==, GPOINTER_TO_UINT(data));
    femu_disable(&c);
}

/*
 * kv_max_keys=3000: MNK reports 3000, and 3000 keys fit. A new key past
 * them fails with Capacity Exceeded, but an overwrite at the limit
 * succeeds, and a Delete makes room for one new key. The same holds for
 * the hash index with and without kv_pack and for the LSM tree.
 */
void femu_test_kv_keys_limit(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t raw = guest_alloc(alloc, 3 * 4096);
    uint64_t buf = (raw + 4095) & ~4095ULL;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    g_assert_cmpuint(femu_kv_mnk(&c, alloc), ==, 3000);
    for (uint64_t i = 0; i < 3000; i++) {
        g_assert_cmphex(femu_lsm_store(&c, i, buf, 1, 0), ==, NVME_SUCCESS);
    }
    g_assert_cmphex(femu_lsm_store(&c, 3000, buf, 1, 0), ==,
                    NVME_CAP_EXCEEDED);
    g_assert_cmphex(femu_lsm_store(&c, 7, buf, 1, 1), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_lsm_cmd(&c, FEMU_KV_CMD_DELETE, 8, buf, 0, 0), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(femu_lsm_store(&c, 3000, buf, 1, 0), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_lsm_store(&c, 3001, buf, 1, 0), ==,
                    NVME_CAP_EXCEEDED);
    g_assert_cmphex(femu_lsm_check(&c, 7, buf, 1, 1), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_lsm_check(&c, 3000, buf, 1, 0), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_lsm_check(&c, 8, buf, 1, 0), ==, 0x87);
    femu_disable(&c);
    guest_free(alloc, raw);
}

/* the C0h log counters: host, GC and NAND programmed pages */
#define FEMU_C0H_HOST   8
#define FEMU_C0H_NAND   24

/*
 * kv_pack: 64 values of 100 bytes with 4 KiB pages. A packed value takes
 * its 32 byte header too, so 31 fill a page, which is programmed when the
 * next one does not fit. Thus two pages are programmed and the 64th value
 * waits in the open page; the host wrote one page (6400 bytes). With
 * kv_pack=off each value programs a page. A value of a page takes a whole
 * page in both models. Every value reads back.
 */
void femu_test_kv_pack_pages(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    bool pack = data != NULL;
    uint64_t raw = guest_alloc(alloc, 4 * 4096);
    uint64_t buf = (raw + 4095) & ~4095ULL;
    uint64_t log = guest_alloc(alloc, 512);

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    for (int i = 0; i < 64; i++) {
        g_assert_cmphex(femu_lsm_store(&c, i, buf, 100, 0), ==, NVME_SUCCESS);
    }
    g_assert_cmpuint(femu_c0h_field(&c, log, FEMU_C0H_NAND), ==,
                     pack ? 2 : 64);
    g_assert_cmpuint(femu_c0h_field(&c, log, FEMU_C0H_HOST), ==,
                     pack ? 1 : 64);
    for (int i = 0; i < 64; i++) {
        g_assert_cmphex(femu_lsm_check(&c, i, buf, 100, 0), ==, NVME_SUCCESS);
    }
    g_assert_cmphex(femu_lsm_store(&c, 64, buf, 4096, 0), ==, NVME_SUCCESS);
    g_assert_cmpuint(femu_c0h_field(&c, log, FEMU_C0H_NAND), ==,
                     pack ? 3 : 65);
    g_assert_cmphex(femu_lsm_check(&c, 64, buf, 4096, 0), ==, NVME_SUCCESS);
    femu_disable(&c);
    guest_free(alloc, log);
    guest_free(alloc, raw);
}

/*
 * Overwrites of one key in the open page: the device drops the dead
 * values from its DRAM page, as a write buffer drops a replaced page, so
 * 200 Stores of 100 bytes program nothing. Then 200 Stores of 2016 bytes:
 * two such records fill a page exactly, but the old one dies with the
 * Store, so the page is never full of live records and is not programmed
 * either. With kv_pack=off each Store programs a page.
 */
void femu_test_kv_pack_overwrite(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    bool pack = data != NULL;
    uint64_t raw = guest_alloc(alloc, 4 * 4096);
    uint64_t buf = (raw + 4095) & ~4095ULL;
    uint64_t log = guest_alloc(alloc, 512);

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    for (int v = 0; v < 200; v++) {
        g_assert_cmphex(femu_lsm_store(&c, 9, buf, 100, v), ==, NVME_SUCCESS);
    }
    g_assert_cmpuint(femu_c0h_field(&c, log, FEMU_C0H_NAND), ==,
                     pack ? 0 : 200);
    g_assert_cmphex(femu_lsm_check(&c, 9, buf, 100, 199), ==, NVME_SUCCESS);
    for (int v = 200; v < 400; v++) {
        g_assert_cmphex(femu_lsm_store(&c, 9, buf, 2016, v), ==,
                        NVME_SUCCESS);
    }
    g_assert_cmpuint(femu_c0h_field(&c, log, FEMU_C0H_NAND), ==,
                     pack ? 0 : 400);
    g_assert_cmphex(femu_lsm_check(&c, 9, buf, 2016, 399), ==,
                    NVME_SUCCESS);
    femu_disable(&c);
    guest_free(alloc, log);
    guest_free(alloc, raw);
}

/*
 * Durability of the open page, with a volatile write cache (vwc=1). A
 * held Store programs nothing; Flush programs the open page once, and a
 * second Flush has nothing to program (Base 2.3, 7.2). Clearing WCE
 * programs what is open, and with WCE cleared each Store programs its
 * page at once (5.2.26.1.4). The values read back.
 */
void femu_test_kv_pack_flush(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t raw = guest_alloc(alloc, 4 * 4096);
    uint64_t buf = (raw + 4095) & ~4095ULL;
    uint64_t log = guest_alloc(alloc, 512);
    NvmeCmd flush;

    memset(&flush, 0, sizeof(flush));
    flush.opcode = NVME_CMD_FLUSH;
    flush.nsid = cpu_to_le32(1);

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_VOLATILE_WRITE_CACHE,
                                             false, 0, 1, NULL)), ==,
                    NVME_SUCCESS);
    for (int i = 0; i < 3; i++) {
        g_assert_cmphex(femu_lsm_store(&c, i, buf, 100, 0), ==, NVME_SUCCESS);
    }
    g_assert_cmpuint(femu_c0h_field(&c, log, FEMU_C0H_NAND), ==, 0);
    g_assert_cmphex(FEMU_SC(femu_io(&c, &flush)), ==, NVME_SUCCESS);
    g_assert_cmpuint(femu_c0h_field(&c, log, FEMU_C0H_NAND), ==, 1);
    g_assert_cmphex(FEMU_SC(femu_io(&c, &flush)), ==, NVME_SUCCESS);
    g_assert_cmpuint(femu_c0h_field(&c, log, FEMU_C0H_NAND), ==, 1);

    g_assert_cmphex(femu_lsm_store(&c, 3, buf, 100, 0), ==, NVME_SUCCESS);
    g_assert_cmpuint(femu_c0h_field(&c, log, FEMU_C0H_NAND), ==, 1);
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_VOLATILE_WRITE_CACHE,
                                             false, 0, 0, NULL)), ==,
                    NVME_SUCCESS);
    g_assert_cmpuint(femu_c0h_field(&c, log, FEMU_C0H_NAND), ==, 2);
    g_assert_cmphex(femu_lsm_store(&c, 4, buf, 100, 0), ==, NVME_SUCCESS);
    g_assert_cmpuint(femu_c0h_field(&c, log, FEMU_C0H_NAND), ==, 3);
    for (int i = 0; i < 5; i++) {
        g_assert_cmphex(femu_lsm_check(&c, i, buf, 100, 0), ==, NVME_SUCCESS);
    }
    femu_disable(&c);
    guest_free(alloc, log);
    guest_free(alloc, raw);
}

/*
 * A Flush waits for a program that already left the open page. Value 30
 * fills the first page with live records, so its Store starts the 200 ms
 * program of values 0 to 30 and leaves no open page. A Flush that goes
 * in before that Store completes has nothing to program, yet it must wait
 * for the program: values 0 to 29 completed before the Flush (Base 2.3,
 * 7.2). vwc=1, hash index.
 */
void femu_test_kv_pack_flush_wait(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t raw = guest_alloc(alloc, 4 * 4096);
    uint64_t buf = (raw + 4095) & ~4095ULL;
    int64_t start;
    int64_t took = -1;
    uint16_t want;
    NvmeCmd cmd;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    for (int i = 0; i < 30; i++) {
        g_assert_cmphex(femu_lsm_store(&c, i, buf, 100, 0), ==, NVME_SUCCESS);
    }
    qtest_memset(qts, buf, femu_lsm_byte(30, 0), 100);
    start = g_get_monotonic_time();
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_KV_CMD_STORE;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.res1 = cpu_to_le64(femu_lsm_key(30));
    cmd.cdw10 = cpu_to_le32(100);
    cmd.cdw11 = cpu_to_le32(8);
    femu_submit(&c, &c.io, &cmd);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_CMD_FLUSH;
    cmd.nsid = cpu_to_le32(1);
    want = c.cid;
    femu_submit(&c, &c.io, &cmd);
    for (int i = 0; i < 2; i++) {
        uint16_t got;

        g_assert_cmphex(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), ==,
                        NVME_SUCCESS);
        if (got == want) {
            took = g_get_monotonic_time() - start;
        }
    }
    g_test_message("Flush beside a program of the open page: %" PRId64
                   " us", took);
    /* nothing is left to program; the program of the full page still runs */
    g_assert_cmpint(took, >=, 150000);
    g_assert_cmphex(femu_lsm_check(&c, 30, buf, 100, 0), ==, NVME_SUCCESS);
    femu_disable(&c);
    guest_free(alloc, raw);
}

/* the value packing member of namespace 1, or NULL with kv_pack=off */
static int64_t femu_pack_stat(QTestState *qts, const char *name)
{
    QDict *rsp;
    QDict *pack = qdict_get_qdict(femu_query_ns(qts, "", &rsp), "pack");
    int64_t v;

    g_assert_nonnull(pack);
    v = qdict_get_int(pack, name);
    qobject_unref(rsp);
    return v;
}

/*
 * query-femu reports value packing. 40 values of 100 bytes: 31 records of
 * 132 bytes fill the first page, which goes to flash with the 31st Store,
 * and 9 wait in the open page. A Retrieve of
 * an open value reads no NAND, and a Flush (vwc=1) programs the open page
 * before it is full. With kv_pack=off the member is absent.
 */
void femu_test_kv_pack_query(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t raw;
    uint64_t buf;
    QDict *rsp;
    NvmeCmd flush;

    if (!data) {
        g_assert_false(qdict_haskey(femu_query_ns(qts, "", &rsp), "pack"));
        qobject_unref(rsp);
        return;
    }
    raw = guest_alloc(alloc, 4 * 4096);
    buf = (raw + 4095) & ~4095ULL;
    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    g_assert_cmpint(femu_pack_stat(qts, "record-header-bytes"), ==, 32);
    for (int i = 0; i < 40; i++) {
        g_assert_cmphex(femu_lsm_store(&c, i, buf, 100, 0), ==, NVME_SUCCESS);
        /* the 31st record fills the page: it goes to flash at once */
        if (i == 30) {
            g_assert_cmpint(femu_pack_stat(qts, "packed-pages"), ==, 1);
            g_assert_cmpint(femu_pack_stat(qts, "open-values"), ==, 0);
            g_assert_cmpint(femu_pack_stat(qts, "early-programs"), ==, 0);
        }
    }
    g_assert_cmpint(femu_pack_stat(qts, "packed-pages"), ==, 1);
    g_assert_cmpint(femu_pack_stat(qts, "packed-values"), ==, 40);
    g_assert_cmpint(femu_pack_stat(qts, "open-values"), ==, 9);
    g_assert_cmpint(femu_pack_stat(qts, "open-bytes"), ==, 9 * 132);
    g_assert_cmpint(femu_pack_stat(qts, "flash-pages"), ==, 1);
    g_assert_cmpint(femu_pack_stat(qts, "flash-live-bytes"), ==, 31 * 132);
    g_assert_cmpint(femu_pack_stat(qts, "pad-bytes"), ==, 4096 - 31 * 132);
    g_assert_cmpint(femu_pack_stat(qts, "host-bytes"), ==, 4000);
    g_assert_cmphex(femu_lsm_check(&c, 39, buf, 100, 0), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_pack_stat(qts, "buffer-reads"), ==, 1);

    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_VOLATILE_WRITE_CACHE,
                                             false, 0, 1, NULL)), ==,
                    NVME_SUCCESS);
    memset(&flush, 0, sizeof(flush));
    flush.opcode = NVME_CMD_FLUSH;
    flush.nsid = cpu_to_le32(1);
    g_assert_cmphex(FEMU_SC(femu_io(&c, &flush)), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_pack_stat(qts, "packed-pages"), ==, 2);
    g_assert_cmpint(femu_pack_stat(qts, "early-programs"), ==, 1);
    g_assert_cmpint(femu_pack_stat(qts, "open-values"), ==, 0);
    g_assert_cmpint(femu_pack_stat(qts, "flash-pages"), ==, 2);
    femu_disable(&c);
    guest_free(alloc, raw);
}

/* the time of one Retrieve of @i, in us */
static int64_t femu_kv_pack_read_us(FemuCtrlState *c, uint64_t i,
                                    uint64_t buf)
{
    int64_t start = g_get_monotonic_time();

    g_assert_cmphex(femu_lsm_check(c, i, buf, 100, 0), ==, NVME_SUCCESS);
    return g_get_monotonic_time() - start;
}

/*
 * A packed value costs one page read once its page is programmed, and no
 * read while it waits in the open page. The LSM tree here holds every
 * record in DRAM (pinned levels), so a lookup reads no flash. Values 0 to
 * 30 fill the first page; value 40 stays open. 20 ms page reads.
 */
void femu_test_kv_pack_read_time(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t raw = guest_alloc(alloc, 4 * 4096);
    uint64_t buf = (raw + 4095) & ~4095ULL;
    int64_t open;
    int64_t flash;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    for (int i = 0; i < 41; i++) {
        g_assert_cmphex(femu_lsm_store(&c, i, buf, 100, 0), ==, NVME_SUCCESS);
    }
    open = femu_kv_pack_read_us(&c, 40, buf);
    flash = femu_kv_pack_read_us(&c, 7, buf);
    g_test_message("Retrieve: open page %" PRId64 " us, flash %" PRId64
                   " us", open, flash);
    g_assert_cmpint(open, <, 10000);
    g_assert_cmpint(flash, >=, 19000);
    /* one page, not one per value or per page of the value log */
    g_assert_cmpint(flash, <, 39000);
    femu_disable(&c);
    guest_free(alloc, raw);
}

/*
 * Value GC at value granularity. 300 cold values share pages with
 * overwrites of 40 hot keys, four records a page (990 bytes and a 32 byte
 * header), until the device has written more than its size. GC picks the
 * lines with the fewest live bytes and moves the live values one by one.
 * Every value reads back with its last version, and FEMU_KV_CHECK checks
 * every page header, owner and line count as the run goes. With the LSM
 * tree (@data set) the meta page programs are left out of the count.
 */
#define FEMU_KV_PACK_COLD   300
#define FEMU_KV_PACK_HOT    40
#define FEMU_KV_PACK_ROUNDS 60
#define FEMU_KV_PACK_LEN    990

void femu_test_kv_pack_gc(void *obj, void *data,
                          QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t raw = guest_alloc(alloc, 4 * 4096);
    uint64_t buf = (raw + 4095) & ~4095ULL;
    uint64_t log = guest_alloc(alloc, 512);
    uint64_t stores = 0;
    uint64_t gc;
    uint64_t nand;
    uint64_t host;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    for (int r = 0; r < FEMU_KV_PACK_ROUNDS; r++) {
        for (int h = 0; h < FEMU_KV_PACK_HOT; h++) {
            g_assert_cmphex(femu_lsm_store(&c, 1000 + h, buf,
                                           FEMU_KV_PACK_LEN, r), ==,
                            NVME_SUCCESS);
            stores++;
            if (h % 8 == 0 && r * 5 + h / 8 < FEMU_KV_PACK_COLD) {
                g_assert_cmphex(femu_lsm_store(&c, r * 5 + h / 8, buf,
                                               FEMU_KV_PACK_LEN, 0), ==,
                                NVME_SUCCESS);
                stores++;
            }
        }
    }
    gc = femu_c0h_field(&c, log, FEMU_C0H_GC);
    nand = femu_c0h_field(&c, log, FEMU_C0H_NAND);
    host = femu_c0h_field(&c, log, FEMU_C0H_HOST);
    if (data) {
        QDict *rsp;
        QDict *pack = qdict_get_qdict(femu_query_ns(qts, "", &rsp), "pack");

        g_test_message("GC: %" PRId64 " values moved, %" PRId64
                       " stale released; %" PRId64 " keys reinserted",
                       qdict_get_int(pack, "gc-moved-values"),
                       qdict_get_int(pack, "gc-stale-values"),
                       femu_lsm_stat(qts, "reinserted-keys"));
        /* moved packed values whose records are on flash go back */
        g_assert_cmpint(qdict_get_int(pack, "gc-moved-values"), >, 0);
        g_assert_cmpint(femu_lsm_stat(qts, "reinserted-keys"), >, 0);
        qobject_unref(rsp);
        nand -= femu_lsm_stat(qts, "compaction-program-pages");
    }
    g_test_message("%" PRIu64 " stores: host %" PRIu64 " value %" PRIu64
                   " gc %" PRIu64 " pages", stores, host, nand, gc);
    g_assert_cmpuint(gc, >, 0);
    /* four records a page: about a quarter of the Stores program a page */
    g_assert_cmpuint(nand, <=, stores / 4 + 1);
    g_assert_cmpuint(nand, >=, stores / 4 - 1);
    for (int k = 0; k < FEMU_KV_PACK_COLD; k++) {
        g_assert_cmphex(femu_lsm_check(&c, k, buf, FEMU_KV_PACK_LEN, 0), ==,
                        NVME_SUCCESS);
    }
    for (int h = 0; h < FEMU_KV_PACK_HOT; h++) {
        g_assert_cmphex(femu_lsm_check(&c, 1000 + h, buf, FEMU_KV_PACK_LEN,
                                       FEMU_KV_PACK_ROUNDS - 1), ==,
                        NVME_SUCCESS);
    }
    femu_disable(&c);
    guest_free(alloc, log);
    guest_free(alloc, raw);
}

/*
 * Stale packed versions with the LSM tree. 1400 keys of 990 bytes take
 * 350 pages, then two rewrites of every key need more than the 1024
 * pages of the device. The index of this namespace takes 1537 keys. A rewrite
 * leaves the old version on flash until a
 * merge drops its record, so GC checks each packed value against the
 * tree (PinK, section 4.5) and releases the stale ones in place, with no
 * move. Every key reads back as its last version.
 */
#define FEMU_KV_PACK_KEYS   1400

void femu_test_kv_pack_lsm_stale(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t raw = guest_alloc(alloc, 4 * 4096);
    uint64_t buf = (raw + 4095) & ~4095ULL;
    int64_t stale;
    int64_t moved;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    for (int v = 0; v < 3; v++) {
        for (int k = 0; k < FEMU_KV_PACK_KEYS; k++) {
            g_assert_cmphex(femu_lsm_store(&c, k, buf, FEMU_KV_PACK_LEN, v),
                            ==, NVME_SUCCESS);
        }
    }
    stale = femu_pack_stat(qts, "gc-stale-values");
    moved = femu_pack_stat(qts, "gc-moved-values");
    g_test_message("GC: %" PRId64 " values moved, %" PRId64 " stale "
                   "released, %" PRId64 " keys reinserted", moved, stale,
                   femu_lsm_stat(qts, "reinserted-keys"));
    g_assert_cmpint(stale, >, 0);
    g_assert_cmpint(femu_lsm_stat(qts, "gc-read-pages"), >, 0);
    for (int k = 0; k < FEMU_KV_PACK_KEYS; k++) {
        g_assert_cmphex(femu_lsm_check(&c, k, buf, FEMU_KV_PACK_LEN, 2), ==,
                        NVME_SUCCESS);
    }
    femu_disable(&c);
    guest_free(alloc, raw);
}

/*
 * Value GC with the LSM tree, as PinK does it (section 4.5). Each cold
 * value shares its line with three writes of a hot key, so the lines stay
 * partly valid and the free lines fall to the GC threshold. GC checks each
 * version against the tree (meta page reads), moves the live ones and
 * puts back the keys whose records are on flash, and releases the stale
 * ones: the first 50 keys are rewritten while older lines still hold their
 * first versions. Every value reads back as its last version, and the
 * owner check (FEMU_KV_CHECK) runs after each GC.
 */
void femu_test_kv_lsm_gc(void *obj, void *data,
                         QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t raw = guest_alloc(alloc, 3 * 4096);
    uint64_t buf = (raw + 4095) & ~4095ULL;
    /* with @data, values of two pages, which can span two victim lines */
    uint32_t len = data ? 8192 : 4096;
    int cold = data ? 100 : 200;
    int i;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    for (i = 0; i < cold + cold / 4; i++) {
        int key = i < cold ? i : i - cold;

        g_assert_cmphex(femu_lsm_store(&c, key, buf, len, i >= cold), ==,
                        NVME_SUCCESS);
        /* two-page values: strides of 6 pages, so GC moves them apart */
        for (int h = 0; h < (data ? 2 : 3); h++) {
            g_assert_cmphex(femu_lsm_store(&c, 10000, buf, len, h), ==,
                            NVME_SUCCESS);
        }
    }
    g_test_message("gc reads %" PRId64 ", reinserted %" PRId64
                   ", stale %" PRId64 ", meta moved %" PRId64,
                   femu_lsm_stat(qts, "gc-read-pages"),
                   femu_lsm_stat(qts, "reinserted-keys"),
                   femu_lsm_stat(qts, "gc-stale-value-pages"),
                   femu_lsm_stat(qts, "gc-meta-pages"));
    g_assert_cmpint(femu_lsm_stat(qts, "gc-read-pages"), >, 0);
    g_assert_cmpint(femu_lsm_stat(qts, "reinserted-keys"), >, 0);
    g_assert_cmpint(femu_lsm_stat(qts, "gc-stale-value-pages"), >, 0);
    /* one-page values leave meta lines with holes that GC collects */
    if (!data) {
        g_assert_cmpint(femu_lsm_stat(qts, "gc-meta-pages"), >, 0);
    }
    for (i = 0; i < cold; i++) {
        g_assert_cmphex(femu_lsm_check(&c, i, buf, len, i < cold / 4), ==,
                        NVME_SUCCESS);
    }
    g_assert_cmphex(femu_lsm_check(&c, 10000, buf, len, data ? 1 : 2), ==,
                    NVME_SUCCESS);
    /* a short buffer still gets the full value length in Dword 0 */
    for (i = 0; i < cold; i += 17) {
        NvmeCmd cmd;
        uint32_t full = 0;

        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = FEMU_KV_CMD_RETRIEVE;
        cmd.nsid = cpu_to_le32(1);
        cmd.dptr.prp1 = cpu_to_le64(buf);
        cmd.res1 = cpu_to_le64(femu_lsm_key(i));
        cmd.cdw10 = cpu_to_le32(16);
        cmd.cdw11 = cpu_to_le32(8);
        femu_submit(&c, &c.io, &cmd);
        g_assert_cmphex(FEMU_SC(femu_complete(&c, &c.io, NULL, &full)), ==,
                        NVME_SUCCESS);
        g_assert_cmpuint(full, ==, len);
    }

    femu_disable(&c);
    guest_free(alloc, raw);
}

/*
 * GC looks at every full value line when a Store needs room. The levels
 * are all pinned, so an overwrite leaves the old page valid and no line
 * has an invalid page. The oldest full line holds only live values and
 * gives no room; GC goes on to the line with the stale values, and the
 * first Store that needs it succeeds. Eight lines of 16 pages.
 */
void femu_test_kv_lsm_full_lines(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t raw = guest_alloc(alloc, 3 * 4096);
    uint64_t buf = (raw + 4095) & ~4095ULL;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    for (int i = 0; i <= 64; i++) {
        g_assert_cmphex(femu_lsm_store(&c, i, buf, 4096, 0), ==,
                        NVME_SUCCESS);
    }
    for (int i = 32; i <= 46; i++) {
        g_assert_cmphex(femu_lsm_store(&c, i, buf, 4096, 1), ==,
                        NVME_SUCCESS);
    }
    g_assert_cmphex(femu_lsm_store(&c, 1000, buf, 4096, 0), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_lsm_stat(qts, "gc-stale-value-pages"), >, 0);
    for (int i = 0; i <= 64; i++) {
        g_assert_cmphex(femu_lsm_check(&c, i, buf, 4096,
                                       i >= 32 && i <= 46), ==,
                        NVME_SUCCESS);
    }
    femu_disable(&c);
    guest_free(alloc, raw);
}

/*
 * MT19937 as Python's random module seeds and draws it, so a test can
 * replay a sequence that a Python script found.
 */
typedef struct FemuMt {
    uint32_t mt[624];
    int i;
} FemuMt;

static uint32_t femu_mt_next(FemuMt *m)
{
    uint32_t y;

    if (m->i >= 624) {
        for (int k = 0; k < 624; k++) {
            y = (m->mt[k] & 0x80000000u) | (m->mt[(k + 1) % 624] & 0x7fffffffu);
            m->mt[k] = m->mt[(k + 397) % 624] ^ (y >> 1) ^
                       ((y & 1) ? 0x9908b0dfu : 0);
        }
        m->i = 0;
    }
    y = m->mt[m->i++];
    y ^= y >> 11;
    y ^= (y << 7) & 0x9d2c5680u;
    y ^= (y << 15) & 0xefc60000u;
    return y ^ (y >> 18);
}

/* random.Random(@seed) for a seed below 2^32 (init_by_array, one word) */
static void femu_mt_seed(FemuMt *m, uint32_t seed)
{
    int i = 1, j = 0;

    m->mt[0] = 19650218u;
    for (int k = 1; k < 624; k++) {
        m->mt[k] = 1812433253u * (m->mt[k - 1] ^ (m->mt[k - 1] >> 30)) + k;
    }
    for (int k = 624; k; k--) {
        m->mt[i] = (m->mt[i] ^ ((m->mt[i - 1] ^ (m->mt[i - 1] >> 30)) *
                                1664525u)) + seed + j;
        i++;
        j = 0;
        if (i >= 624) {
            m->mt[0] = m->mt[623];
            i = 1;
        }
    }
    for (int k = 623; k; k--) {
        m->mt[i] = (m->mt[i] ^ ((m->mt[i - 1] ^ (m->mt[i - 1] >> 30)) *
                                1566083941u)) - i;
        i++;
        if (i >= 624) {
            m->mt[0] = m->mt[623];
            i = 1;
        }
    }
    m->mt[0] = 0x80000000u;
    m->i = 624;
}

/* random.randrange(@n) for n below 128: 7 bits, drawn again until below n */
static uint32_t femu_mt_below(FemuMt *m, uint32_t n)
{
    uint32_t r;

    do {
        r = femu_mt_next(m) >> 25;
    } while (r >= n);
    return r;
}

/*
 * Random overwrites on a small device: 90 keys of one page on 192 pages,
 * with merges and value GC all the time. The sequence is random.Random(9)
 * over 90 keys after keys 0 to 79. At its 721st Store a victim gave no
 * room, since the merges of its keys took what its erase freed, and GC
 * stopped there. GC now goes on to the next victim, every Store succeeds,
 * and every key reads back its last value.
 */
void femu_test_kv_lsm_churn(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t raw = guest_alloc(alloc, 3 * 4096);
    uint64_t buf = (raw + 4095) & ~4095ULL;
    uint8_t ver[90] = { 0 };
    uint8_t got[16];
    FemuMt mt;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_mt_seed(&mt, 9);
    for (int op = 0; op < 2000; op++) {
        uint32_t k = op < 80 ? (uint32_t)op : femu_mt_below(&mt, 90);

        ver[k]++;
        qtest_memset(qts, buf, ver[k], 4096);
        g_assert_cmphex(femu_kv_store(&c, k, buf, 4096), ==, NVME_SUCCESS);
    }
    for (uint32_t k = 0; k < 90; k++) {
        NvmeCmd cmd;

        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = FEMU_KV_CMD_RETRIEVE;
        cmd.nsid = cpu_to_le32(1);
        cmd.dptr.prp1 = cpu_to_le64(buf);
        cmd.res1 = cpu_to_le64(k);
        cmd.cdw10 = cpu_to_le32(4096);
        cmd.cdw11 = cpu_to_le32(8);
        g_assert_cmphex(femu_io(&c, &cmd), ==,
                        ver[k] ? NVME_SUCCESS : 0x87);
        if (ver[k]) {
            qtest_memread(qts, buf, got, sizeof(got));
            g_assert_cmpuint(got[0], ==, ver[k]);
            g_assert_cmpuint(got[15], ==, ver[k]);
        }
    }
    femu_disable(&c);
    guest_free(alloc, raw);
}

/*
 * A full device still takes a Delete, and gets its space back. 32-byte
 * pages hold one record each, so zero-length values fill the NAND with
 * meta pages until a Store gets Capacity Exceeded. Every key is then
 * deleted, and new Stores succeed again.
 */
void femu_test_kv_lsm_full_delete(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint16_t st = NVME_SUCCESS;
    int i, n;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    for (i = 0; i < 4096 && st == NVME_SUCCESS; i++) {
        st = femu_lsm_store(&c, i, buf, 0, 0);
    }
    g_test_message("first refused Store: key %d, status 0x%x", i - 1, st);
    g_assert_cmphex(st, ==, NVME_CAP_EXCEEDED);
    n = i - 1;
    for (int k = 0; k < n; k++) {
        g_assert_cmphex(femu_lsm_cmd(&c, FEMU_KV_CMD_DELETE, k, buf, 0, 0),
                        ==, NVME_SUCCESS);
        g_assert_cmphex(femu_lsm_cmd(&c, FEMU_KV_CMD_EXIST, k, buf, 0, 0),
                        ==, 0x87);
    }
    /*
     * The empty namespace takes Stores again: the first one merges the
     * tombstones down, where they drop with the records they hide.
     */
    for (int k = 0; k < n / 2; k++) {
        g_assert_cmphex(femu_lsm_store(&c, 100000 + k, buf, 0, 0), ==,
                        NVME_SUCCESS);
    }
    femu_disable(&c);
    guest_free(alloc, buf);
}

/*
 * Each Store takes a new slot, and an old version keeps its slot until
 * the tree drops its record. 900 keys written twice need more slots than
 * the 1024 the table starts with, so the table grows while the old
 * records wait in the lower levels. Every key still reads back.
 */
void femu_test_kv_lsm_versions(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    int64_t peak = 0;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    for (int i = 0; i < 1800; i++) {
        g_assert_cmphex(femu_lsm_store(&c, i % 900, buf, 0, 0), ==,
                        NVME_SUCCESS);
        if (i % 50 == 49) {
            peak = MAX(peak, femu_lsm_stat(qts, "versions"));
        }
    }
    g_test_message("peak versions %" PRId64, peak);
    g_assert_cmpint(peak, >, 1024);
    for (int i = 0; i < 900; i++) {
        g_assert_cmphex(femu_lsm_cmd(&c, FEMU_KV_CMD_EXIST, i, buf, 0, 0),
                        ==, NVME_SUCCESS);
    }
    femu_disable(&c);
    guest_free(alloc, buf);
}

/*
 * An old value stays valid on flash until the tree drops its record (PinK
 * section 4.5): a blind overwrite of a key whose record is in a level
 * leaves both versions valid. A flush that merges over the key drops the
 * old record, and only then is its page released. An overwrite of a key
 * in the memtable replaces the record there, so the old page goes at
 * once. Memtable 16, one page per value, no pinned level.
 */
void femu_test_kv_lsm_stale(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t raw = guest_alloc(alloc, 3 * 4096);
    uint64_t buf = (raw + 4095) & ~4095ULL;
    int64_t flushes;
    int live = 0;
    int i;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    /* keys 0..16: the 17th flushes 0..15 into level 1 */
    for (i = 0; i <= 16; i++) {
        g_assert_cmphex(femu_lsm_store(&c, i, buf, 4096, 0), ==,
                        NVME_SUCCESS);
        live++;
    }
    g_assert_cmpint(femu_lsm_stat(qts, "flushes"), ==, 1);
    g_assert_cmpint(femu_lsm_stat(qts, "valid-value-pages"), ==, live);

    /* key 3 is in level 1: its old page stays valid */
    g_assert_cmphex(femu_lsm_store(&c, 3, buf, 4096, 1), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_lsm_stat(qts, "valid-value-pages"), ==, live + 1);

    /* key 16 is in the memtable: its old page goes at once */
    g_assert_cmphex(femu_lsm_store(&c, 16, buf, 4096, 1), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_lsm_stat(qts, "valid-value-pages"), ==, live + 1);

    /* new keys up to the next flush; its merge drops the old key 3 */
    flushes = femu_lsm_stat(qts, "flushes");
    for (i = 100; femu_lsm_stat(qts, "flushes") == flushes; i++) {
        g_assert_cmphex(femu_lsm_store(&c, i, buf, 4096, 0), ==,
                        NVME_SUCCESS);
        live++;
    }
    g_assert_cmpint(femu_lsm_stat(qts, "valid-value-pages"), ==, live);
    g_assert_cmphex(femu_lsm_check(&c, 3, buf, 4096, 1), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_lsm_check(&c, 16, buf, 4096, 1), ==, NVME_SUCCESS);

    /* a Delete is blind too: the page goes when a merge drops the record */
    g_assert_cmphex(femu_lsm_cmd(&c, FEMU_KV_CMD_DELETE, 5, buf, 0, 0), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_lsm_stat(qts, "valid-value-pages"), ==, live);
    g_assert_cmphex(femu_lsm_check(&c, 5, buf, 4096, 0), ==, 0x87);

    femu_disable(&c);
    guest_free(alloc, raw);
}

/*
 * Meta pages are NAND programs (item 1): C0h counts each merge program as
 * a page programmed, beside the value pages the host asked for. Nothing
 * is collected here, so the difference is exactly the merge programs.
 */
void femu_test_kv_lsm_meta_flash(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t raw = guest_alloc(alloc, 3 * 4096);
    uint64_t buf = (raw + 4095) & ~4095ULL;
    uint64_t log = guest_alloc(alloc, 512);
    uint64_t host, nand, gc;
    int64_t prog;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    /* count the change: qos may hand this test a QEMU an earlier one used */
    host = femu_c0h_field(&c, log, 8);
    gc = femu_c0h_field(&c, log, 16);
    nand = femu_c0h_field(&c, log, 24);
    prog = femu_lsm_stat(qts, "compaction-program-pages");
    for (int i = 0; i < 300; i++) {
        g_assert_cmphex(femu_lsm_store(&c, (i * 53) % 300, buf, 16, 0), ==,
                        NVME_SUCCESS);
    }
    host = femu_c0h_field(&c, log, 8) - host;
    gc = femu_c0h_field(&c, log, 16) - gc;
    nand = femu_c0h_field(&c, log, 24) - nand;
    prog = femu_lsm_stat(qts, "compaction-program-pages") - prog;
    g_test_message("host %" PRIu64 ", nand %" PRIu64 ", merge programs %"
                   PRId64, host, nand, prog);
    g_assert_cmpuint(host, ==, 300);
    g_assert_cmpuint(gc, ==, 0);
    g_assert_cmpint(prog, >, 0);
    g_assert_cmpuint(nand, ==, host + (uint64_t)prog);
    /* the levels name real pages: their flash is what the query shows */
    g_assert_cmpint(femu_lsm_stat(qts, "meta-flash-bytes"), >, 0);

    femu_disable(&c);
    guest_free(alloc, log);
    guest_free(alloc, raw);
}

/*
 * Delete goes in blind with EDNEK clear. With EDNEK set its status depends
 * on the key, so it looks the key up first: a meta page read for a key in
 * an unpinned level, and a miss reports Key Does Not Exist.
 */
void femu_test_kv_lsm_delete_ednek(void *obj, void *data,
                                   QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t raw = guest_alloc(alloc, 3 * 4096);
    uint64_t buf = (raw + 4095) & ~4095ULL;
    int64_t reads;
    int i;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    for (i = 0; i < 40; i++) {
        g_assert_cmphex(femu_lsm_store(&c, i, buf, 16, 0), ==, NVME_SUCCESS);
    }

    reads = femu_lsm_stat(qts, "probe-read-pages");
    g_assert_cmphex(femu_lsm_cmd(&c, FEMU_KV_CMD_DELETE, 1, buf, 0, 0), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_lsm_stat(qts, "probe-read-pages"), ==, reads);

    g_assert_cmphex(femu_set_feature(&c, 0x20, false, 1, 1, NULL), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(femu_lsm_cmd(&c, FEMU_KV_CMD_DELETE, 2, buf, 0, 0), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_lsm_stat(qts, "probe-read-pages"), >, reads);
    /* the tombstone of key 2 is in the memtable: DRAM answers */
    reads = femu_lsm_stat(qts, "probe-read-pages");
    g_assert_cmphex(femu_lsm_cmd(&c, FEMU_KV_CMD_DELETE, 2, buf, 0, 0), ==,
                    0x87);
    g_assert_cmpint(femu_lsm_stat(qts, "probe-read-pages"), ==, reads);
    g_assert_cmphex(femu_lsm_check(&c, 1, buf, 16, 0), ==, 0x87);
    g_assert_cmphex(femu_lsm_check(&c, 3, buf, 16, 0), ==, NVME_SUCCESS);

    /* with EDNEK clear, a Delete of an absent key puts a blind tombstone */
    g_assert_cmphex(femu_set_feature(&c, 0x20, false, 1, 0, NULL), ==,
                    NVME_SUCCESS);
    reads = femu_lsm_stat(qts, "memtable-keys");
    g_assert_cmphex(femu_lsm_cmd(&c, FEMU_KV_CMD_DELETE, 777, buf, 0, 0), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_lsm_stat(qts, "memtable-keys"), ==, reads + 1);
    g_assert_cmphex(femu_lsm_check(&c, 777, buf, 16, 0), ==, 0x87);

    femu_disable(&c);
    guest_free(alloc, raw);
}

void femu_test_namespace_kv_byte_capacity(void *obj, void *data,
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
 * A controller whose namespaces are all key-value keeps the values in its
 * own arena, so it allocates no data backend. One block namespace among
 * them keeps the backend, and so does a plain NoSSD controller.
 */
static const struct {
    const char *opts;
    uint64_t backend;
} femu_kv_backend_cases[] = {
    { "femu_mode=5,devsz_mb=64", 0 },
    { "femu_mode=5,devsz_mb=64,namespaces=2", 0 },
    { "femu_mode=2,devsz_mb=64,namespaces=2,namespace_modes=kvssd,,kvssd", 0 },
    { "femu_mode=1,devsz_mb=2,secsz=512,secs_per_pg=8,pgs_per_blk=4,"
      "blks_per_pl=64,pls_per_lun=2,luns_per_ch=1,nchs=2,namespaces=2,"
      "namespace_modes=bbssd,,kvssd", 2 * MiB },
    { "femu_mode=2,devsz_mb=64", 64 * MiB },
};

void femu_test_kv_no_backend(void *obj, void *data,
                             QGuestAllocator *unused)
{
    for (unsigned i = 0; i < ARRAY_SIZE(femu_kv_backend_cases); i++) {
        QTestState *qts = qtest_initf("-machine pc -nodefaults "
                                      "-device femu,addr=5,id=kvb,%s",
                                      femu_kv_backend_cases[i].opts);
        QDict *rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                               "'path':'/machine/peripheral/kvb',"
                               "'property':'x-backend-size'}}");

        g_assert_cmpuint(qdict_get_int(rsp, "return"), ==,
                         femu_kv_backend_cases[i].backend);
        qobject_unref(rsp);
        /*
         * The sanitize fixtures need a backend and say so. A device with a
         * backend takes the same command, so the error is not a missing
         * property.
         */
        rsp = qtest_qmp(qts, "{'execute':'qom-set','arguments':{"
                        "'path':'/machine/peripheral/kvb',"
                        "'property':'x-ns-test','value':'seed-sanitize'}}");
        if (femu_kv_backend_cases[i].backend) {
            g_assert_true(qdict_haskey(rsp, "return"));
        } else {
            g_assert_true(qdict_haskey(rsp, "error"));
            g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp,
                                    "error"), "desc"), "no data backend"));
        }
        qobject_unref(rsp);
        qtest_quit(qts);
    }
}

/* the index bytes of the one key-value namespace of a device */
static uint64_t femu_mem_kv_index(const char *opts)
{
    QTestState *qts = qtest_initf("-machine pc -nodefaults "
                                  "-device femu,addr=5,id=mem,%s", opts);
    QDict *rsp = qtest_qmp(qts, "{'execute':'query-femu-memory'}");
    const QListEntry *e;
    uint64_t index = 0;
    uint32_t nr = 0;

    QLIST_FOREACH_ENTRY(qdict_get_qlist(qdict_get_qdict(rsp, "return"),
                                        "owners"), e) {
        QDict *o = qobject_to(QDict, qlist_entry_obj(e));

        if (!strcmp(qdict_get_str(o, "kind"), "namespace")) {
            index = qdict_get_int(o, "index");
            nr++;
        }
    }
    g_assert_cmpuint(nr, ==, 1);
    qobject_unref(rsp);
    qtest_quit(qts);
    return index;
}

/*
 * The LSM memtable counts in the index: a record is a 16-byte key, its
 * length, a tombstone flag and a 4-byte slot, 24 bytes with padding.
 */
void femu_test_memory_kv_lsm(void *obj, void *data,
                             QGuestAllocator *unused)
{
    uint64_t small = femu_mem_kv_index("femu_mode=5,devsz_mb=64,"
                                       "kv_index=lsm,"
                                       "kv_lsm_memtable_keys=1024");
    uint64_t large = femu_mem_kv_index("femu_mode=5,devsz_mb=64,"
                                       "kv_index=lsm,"
                                       "kv_lsm_memtable_keys=2048");

    g_assert_cmpuint(large - small, ==, 1024 * 24);
}

/*
 * With a command set selected by CSI, the page names the features of the
 * command set CDW14 asks for: the key value feature only for key value, the
 * NVM command set's own only for NVM.
 */
void femu_test_fid_effects_kv(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint32_t fis[256];
    uint32_t e;
    uint64_t buf;

    c.pdev = &femu->dev;
    c.alloc = alloc;
    femu_queue_init(&c, &c.admin, 0);
    femu_enable_cc(&c, &femu->dev, alloc,
                   (6 << 16) | (4 << 20) | (FEMU_CC_CSS_CSI << 4) | 1);
    buf = guest_alloc(alloc, 4096);

    g_assert_cmpint(femu_get_log_csi(&c, FEMU_LOG_FID_EFFECTS, FEMU_CSI_KV,
                                     buf, sizeof(fis), 0), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, fis, sizeof(fis));
    e = le32_to_cpu(fis[FEMU_FEAT_KV_CONFIG]);
    g_assert_cmphex(e & 1, ==, 1);
    g_assert_cmphex(FEMU_FID_FSP(e), ==, FEMU_FID_SCOPE_NS);
    g_assert_cmphex(le32_to_cpu(fis[NVME_LBA_RANGE_TYPE]), ==, 0);
    g_assert_cmphex(le32_to_cpu(fis[NVME_ARBITRATION]) & 1, ==, 1);
    g_assert_cmphex(FEMU_SC(femu_get_feature(&c, FEMU_FEAT_KV_CONFIG,
                                             NVME_GETFEAT_SELECT_CAP, 1, 0,
                                             NULL)), ==, NVME_SUCCESS);

    g_assert_cmpint(femu_get_log_csi(&c, FEMU_LOG_FID_EFFECTS, NVME_CSI_NVM,
                                     buf, sizeof(fis), 0), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, fis, sizeof(fis));
    g_assert_cmphex(le32_to_cpu(fis[FEMU_FEAT_KV_CONFIG]), ==, 0);
    g_assert_cmphex(le32_to_cpu(fis[NVME_LBA_RANGE_TYPE]) & 1, ==, 1);

    /* a command set the controller does not have (Figure 321) */
    g_assert_cmpint(femu_get_log_csi(&c, FEMU_LOG_FID_EFFECTS, 0x07,
                                     buf, sizeof(fis), 0), ==,
                    NVME_IOCS_NOT_SUPPORTED);

    guest_free(alloc, buf);
    femu_disable(&c);
}

/*
 * KV 1.1 Figures 40 and 41: CNS 0Ah for CSI 01h describes a KV format. NSID
 * is not used, so NSID 0, an allocated one, one that does not exist and
 * FFFFFFFFh get the same 4096 bytes. NSZE (bytes 7:0) and the namespace
 * key limit MNKS (format 0, bytes 83:80) stay zero; NKVF is 0 (one
 * format), and the key and value limits match the namespace's own CNS 05h
 * reply. Index 1 does not exist.
 */
void femu_test_kv_identify_fmt(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    static const uint32_t nsids[] = { 0, 1, 2, 99, 0xffffffff };
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint32_t dw11 = (uint32_t)FEMU_CSI_KV << 24;
    uint8_t want[4096] = { 0 };
    uint8_t first[4096];
    uint8_t got[4096];
    uint8_t ns[4096];

    /* one format: a 16-byte key and a 2 MiB value; every other byte 0 */
    stw_le_p(want + 72, 16);
    stl_le_p(want + 76, 2u << 20);
    femu_enable_csi(&c, &femu->dev, alloc);
    for (int i = 0; i < ARRAY_SIZE(nsids); i++) {
        qtest_memset(qts, buf, 0xa5, 4096);
        g_assert_cmpint(femu_identify(&c, nsids[i], 0x0a, dw11, buf), ==,
                        NVME_SUCCESS);
        qtest_memread(qts, buf, i ? got : first, sizeof(got));
        g_assert_cmpmem(i ? got : first, sizeof(got), want, sizeof(want));
    }

    /* the namespace reply keeps its size and key limit */
    qtest_memset(qts, buf, 0xa5, 4096);
    g_assert_cmpint(femu_identify(&c, 1, 0x05, dw11, buf), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, ns, sizeof(ns));
    g_assert_cmpuint(ldq_le_p(ns), !=, 0);
    g_assert_cmpuint(ldl_le_p(ns + 80), !=, 0);
    g_assert_cmpuint(lduw_le_p(first + 72), ==, lduw_le_p(ns + 72));
    g_assert_cmpuint(lduw_le_p(first + 72), !=, 0);
    g_assert_cmpuint(ldl_le_p(first + 76), ==, ldl_le_p(ns + 76));
    g_assert_cmpuint(ldl_le_p(first + 76), !=, 0);

    g_assert_cmpint(femu_identify(&c, 0, 0x0a, dw11 | 1, buf), ==,
                    NVME_INVALID_FIELD);
    guest_free(alloc, buf);
    femu_disable(&c);
}
#define FEMU_G1_KV_MAX      (2u << 20)
#define FEMU_KV_VALUE_SIZE  0x85    /* Invalid Value Size */
#define FEMU_KV_NO_KEY      0x87    /* KV Key Does Not Exist */

/* a key-value command with an 8-byte key and @size in CDW10 */
static uint16_t femu_g1_kv(FemuCtrlState *c, uint8_t opcode, uint64_t key,
                           uint32_t size, uint64_t buf, uint64_t list,
                           uint32_t *result)
{
    NvmeCmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = opcode;
    cmd.nsid = cpu_to_le32(1);
    cmd.res1 = cpu_to_le64(key);
    cmd.cdw10 = cpu_to_le32(size);
    cmd.cdw11 = cpu_to_le32(8);
    if (size) {
        /* two list entries in the first page: one page and a pointer */
        femu_g1_prps_at(c, &cmd, buf, DIV_ROUND_UP(size, FEMU_G1_PAGE), list,
                        2);
    }
    femu_submit(c, &c->io, &cmd);
    femu_io_status = femu_complete(c, &c->io, NULL, result);
    return FEMU_SC(femu_io_status);
}

/*
 * The largest value is 2 MiB (KVVML), and mdts=9 puts the transfer limit at
 * the same size. A value of exactly 2 MiB stores and comes back whole. One
 * byte more is Invalid Value Size, not the Invalid Field of the transfer
 * limit, and stores nothing.
 */
void femu_test_g1_kv_value_max(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    const uint32_t max = FEMU_G1_KV_MAX;
    const uint32_t npages = max / FEMU_G1_PAGE + 1;
    const uint64_t key = 0x4731564d41584b31ULL;
    uint64_t id = guest_alloc(alloc, FEMU_G1_PAGE);
    uint64_t buf = guest_alloc(alloc, npages * FEMU_G1_PAGE);
    uint64_t list = guest_alloc(alloc, femu_g1_list_pages(npages) *
                                FEMU_G1_PAGE);
    uint8_t *wbuf = g_malloc(max);
    uint8_t *rbuf = g_malloc0(max);
    uint32_t result = 0;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    g_assert_cmpuint(femu_g1_mdts(&c, id), ==, 9);
    g_assert_cmphex(femu_identify(&c, 1, NVME_ID_CNS_CS_NS,
                                  FEMU_CSI_KV << 24, id), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, id + 76), ==, max);

    femu_g1_fill(wbuf, max, 9);
    femu_g1_put(qts, buf, wbuf, max);
    g_assert_cmphex(femu_g1_kv(&c, FEMU_KV_CMD_STORE, key, max, buf, list,
                               &result), ==, NVME_SUCCESS);
    g_assert_cmpuint(result, ==, max);

    qtest_memset(qts, buf, 0, max);
    g_assert_cmphex(femu_g1_kv(&c, FEMU_KV_CMD_RETRIEVE, key, max, buf, list,
                               &result), ==, NVME_SUCCESS);
    g_assert_cmpuint(result, ==, max);
    femu_g1_get(qts, buf, rbuf, max);
    g_assert_cmpint(memcmp(wbuf, rbuf, max), ==, 0);

    /* one byte more, with a buffer that could hold it */
    g_assert_cmphex(femu_g1_kv(&c, FEMU_KV_CMD_STORE, key + 1, max + 1, buf,
                               list, NULL), ==, FEMU_KV_VALUE_SIZE);
    g_assert_cmphex(femu_io_status & NVME_DNR, ==, NVME_DNR);
    g_assert_cmphex(femu_g1_kv(&c, FEMU_KV_CMD_EXIST, key + 1, 0, 0, 0,
                               NULL), ==, FEMU_KV_NO_KEY);
    g_assert_cmphex(femu_io_status & NVME_DNR, ==, NVME_DNR);
    g_assert_cmphex(femu_g1_kv(&c, FEMU_KV_CMD_EXIST, key, 0, 0, 0, NULL),
                    ==, NVME_SUCCESS);

    /* a small buffer gets the head of the value and its whole size */
    qtest_memset(qts, buf, 0, FEMU_G1_PAGE);
    g_assert_cmphex(femu_g1_kv(&c, FEMU_KV_CMD_RETRIEVE, key, FEMU_G1_PAGE,
                               buf, list, &result), ==, NVME_SUCCESS);
    g_assert_cmpuint(result, ==, max);
    femu_g1_get(qts, buf, rbuf, FEMU_G1_PAGE);
    g_assert_cmpint(memcmp(wbuf, rbuf, FEMU_G1_PAGE), ==, 0);

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
 * mdts=8 puts the transfer limit at 1 MiB, below the largest value. A value
 * of 1 MiB stores and comes back. A value of 2 MiB is a valid size that the
 * transfer limit refuses with Invalid Field, and its key stores nothing.
 */
void femu_test_g1_kv_value_mdts(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    const uint32_t limit = FEMU_G1_KV_MAX / 2;
    const uint32_t npages = FEMU_G1_KV_MAX / FEMU_G1_PAGE;
    const uint64_t key = 0x4731564d4454534bULL;
    uint64_t id = guest_alloc(alloc, FEMU_G1_PAGE);
    uint64_t buf = guest_alloc(alloc, npages * FEMU_G1_PAGE);
    uint64_t list = guest_alloc(alloc, femu_g1_list_pages(npages) *
                                FEMU_G1_PAGE);
    uint8_t *wbuf = g_malloc(limit);
    uint8_t *rbuf = g_malloc0(limit);
    uint32_t result = 0;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    g_assert_cmpuint(femu_g1_mdts(&c, id), ==, 8);
    g_assert_cmphex(femu_identify(&c, 1, NVME_ID_CNS_CS_NS,
                                  FEMU_CSI_KV << 24, id), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, id + 76), ==, FEMU_G1_KV_MAX);

    femu_g1_fill(wbuf, limit, 21);
    femu_g1_put(qts, buf, wbuf, limit);
    g_assert_cmphex(femu_g1_kv(&c, FEMU_KV_CMD_STORE, key + 1,
                               FEMU_G1_KV_MAX, buf, list, NULL), ==,
                    NVME_INVALID_FIELD);
    g_assert_cmphex(femu_io_status & NVME_DNR, ==, NVME_DNR);
    g_assert_cmphex(femu_g1_kv(&c, FEMU_KV_CMD_EXIST, key + 1, 0, 0, 0,
                               NULL), ==, FEMU_KV_NO_KEY);

    g_assert_cmphex(femu_g1_kv(&c, FEMU_KV_CMD_STORE, key, limit, buf, list,
                               &result), ==, NVME_SUCCESS);
    g_assert_cmpuint(result, ==, limit);
    qtest_memset(qts, buf, 0, limit);
    g_assert_cmphex(femu_g1_kv(&c, FEMU_KV_CMD_RETRIEVE, key, limit, buf,
                               list, &result), ==, NVME_SUCCESS);
    g_assert_cmpuint(result, ==, limit);
    femu_g1_get(qts, buf, rbuf, limit);
    g_assert_cmpint(memcmp(wbuf, rbuf, limit), ==, 0);

    g_free(rbuf);
    g_free(wbuf);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    guest_free(alloc, id);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    qos_invalidate_command_line();
}
