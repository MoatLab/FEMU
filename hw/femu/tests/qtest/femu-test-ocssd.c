/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QTest testcases for the FEMU SSD emulator: the Open-Channel SSD 1.2
 * and 2.0 tests (femu_mode=0).
 *
 * femu-test.c registers every test. This file holds the test bodies
 * and the helpers that only they use.
 */

#include "qemu/osdep.h"
#include "femu-test.h"

/* not in QEMU's own block/nvme.h */
#define FEMU_CNS_CS_NS_FMT  0x0a    /* command-set NS for a format index */
#define FEMU_OC20_VECT_READ     0x92
/* sectors the write cache holds back before a read can see them */
#define FEMU_OC20_MW_CUNITS     24

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
void femu_test_identify_other_csi(void *obj, void *data,
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
 * Open-Channel 2.0's vector read and write, which nothing has ever driven: the
 * mode presents no block device to a modern Linux, so the guest cells reach its
 * admin surface only and every memory-safety fix on this path was made by
 * reading it. The address format comes from the geometry the device reports, so
 * the test does not have to rederive it from the properties.
 */
void femu_test_oc20_vector_io(void *obj, void *data,
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

/* Dword 0 and 1 of the completion femu_complete() consumed last on @q. */
static uint64_t femu_last_res64(FemuCtrlState *c, FemuQueue *q)
{
    uint16_t head = (q->cq_head + FEMU_QSIZE - 1) % FEMU_QSIZE;

    return qtest_readq(c->pdev->bus->qts, q->cq_addr + head * sizeof(NvmeCqe));
}

/*
 * Vector Chunk Reset (OCSSD 2.0, 2.2.1 and 2.2.2) works on each entry of its
 * LBA list. Dword 0 and 1 of the completion hold one bit per entry that failed,
 * and the metadata buffer gets one chunk descriptor per entry, in list order.
 * A failed entry must not stop the entries after it, and every chunk that the
 * command resets takes its unit for one erase.
 */
void femu_test_oc20_vector_reset(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    const int n = 34;                   /* entry 33 is in Dword 1 */
    NvmeCmd cmd;
    uint64_t geo, buf, list, meta, outside, lba[34];
    uint8_t g[128], desc[32];
    uint8_t lun_len, chk_len, sec_len;
    uint16_t num_grp, got;
    int64_t start;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    geo = guest_alloc(alloc, 4096);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_OC20_IDENTIFY;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(geo);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    qtest_memread(qts, geo, g, sizeof(g));
    lun_len = g[9];
    chk_len = g[10];
    sec_len = g[11];
    num_grp = lduw_le_p(g + 64);
    g_assert_cmpuint(lduw_le_p(g + 66), >=, 2);      /* units per group */
    g_assert_cmpuint(ldl_le_p(g + 68), >=, 17);      /* chunks per unit */
    outside = (uint64_t)num_grp << (sec_len + chk_len + lun_len);

    /*
     * The device backs the first two units of group 0. Entry i names unit
     * i % 2, chunk i / 2. Open the chunks of entries 0 to 32 with one write
     * each; the chunk of entry 33 stays free.
     */
    buf = guest_alloc(alloc, 4096);
    qtest_memset(qts, buf, 0x5c, 4096);
    for (i = 0; i < n; i++) {
        lba[i] = ((uint64_t)(i % 2) << (sec_len + chk_len)) |
                 ((uint64_t)(i / 2) << sec_len);
        if (i == n - 1) {
            break;
        }
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = FEMU_OC20_VECT_WRITE;
        cmd.nsid = cpu_to_le32(1);
        cmd.dptr.prp1 = cpu_to_le64(buf);
        cmd.cdw10 = cpu_to_le32((uint32_t)lba[i]);
        cmd.cdw11 = cpu_to_le32((uint32_t)(lba[i] >> 32));
        femu_submit(&c, &c.io, &cmd);
        g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), ==,
                        NVME_SUCCESS);
    }
    lba[5] = outside;                                /* no such chunk */

    list = guest_alloc(alloc, 4096);
    meta = guest_alloc(alloc, 4096);
    for (i = 0; i < n; i++) {
        qtest_writeq(qts, list + 8 * i, lba[i]);
    }
    qtest_memset(qts, meta, 0xee, n * 32);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_OC20_VECT_ERASE;
    cmd.nsid = cpu_to_le32(1);
    cmd.mptr = cpu_to_le64(meta);
    cmd.cdw10 = cpu_to_le32((uint32_t)list);
    cmd.cdw11 = cpu_to_le32((uint32_t)(list >> 32));
    cmd.cdw12 = cpu_to_le32(n - 1);
    start = g_get_monotonic_time();
    femu_submit(&c, &c.io, &cmd);
    g_assert_cmphex(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), ==, 0x2c1);

    /*
     * Unit 0 resets 17 chunks, one erase after another, 3 ms each. A command
     * that stopped at entry 5 would erase three of them.
     */
    g_assert_cmpint(g_get_monotonic_time() - start, >, 45000);
    g_assert_cmphex(femu_last_res64(&c, &c.io), ==, (1ULL << 5) | (1ULL << 33));

    for (i = 0; i < n; i++) {
        qtest_memread(qts, meta + 32 * i, desc, sizeof(desc));
        if (i == 5) {
            g_assert_cmpuint(desc[0], ==, 0xee);     /* nothing to describe */
            continue;
        }
        g_assert_cmpuint(desc[0], ==, 0x1);          /* free */
        g_assert_cmphex(ldq_le_p(desc + 8), ==, lba[i]);
        g_assert_cmpuint(ldq_le_p(desc + 24), ==, 0);
    }

    /* the entries after the failure were reset: a second reset is refused */
    for (i = 6; i < 33; i++) {
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = FEMU_OC20_VECT_ERASE;
        cmd.nsid = cpu_to_le32(1);
        cmd.cdw10 = cpu_to_le32((uint32_t)lba[i]);
        cmd.cdw11 = cpu_to_le32((uint32_t)(lba[i] >> 32));
        femu_submit(&c, &c.io, &cmd);
        g_assert_cmphex(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), ==,
                        0x2c1);
        g_assert_cmphex(femu_last_res64(&c, &c.io), ==, 1);
    }

    /* the largest list, 64 entries: entry 63 is bit 31 of Dword 1 */
    for (i = 0; i < 64; i++) {
        qtest_writeq(qts, list + 8 * i, outside);
    }
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_OC20_VECT_ERASE;
    cmd.nsid = cpu_to_le32(1);
    cmd.cdw10 = cpu_to_le32((uint32_t)list);
    cmd.cdw11 = cpu_to_le32((uint32_t)(list >> 32));
    cmd.cdw12 = cpu_to_le32(63);
    femu_submit(&c, &c.io, &cmd);
    g_assert_cmphex(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), ==, 0x2c1);
    g_assert_cmphex(femu_last_res64(&c, &c.io), ==, ~0ULL);

    guest_free(alloc, meta);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    guest_free(alloc, geo);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

void femu_test_oc20_log_length(void *obj, void *data,
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

/*
 * NVM 1.1 Figure 114 requires DPC bit 3 (protection information in the
 * first eight bytes of metadata) to be clear, so realize refuses a dpc
 * property with it. Bit 4 (the last eight bytes) stays allowed, and so does
 * bit 3 on OCSSD, which reports NVMe 1.4.
 */
void femu_test_dpc_first_refused(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    static const char *const bad[] = { "8", "25" };
    QDict *rsp;

    for (int i = 0; i < ARRAY_SIZE(bad); i++) {
        g_autofree char *cmd = g_strdup_printf(
            "{'execute':'device_add','arguments':{'driver':'femu',"
            "'id':'dpc1','addr':'5','devsz_mb':1,'dpc':%s}}", bad[i]);
        const char *desc;

        rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));
        g_assert_true(qdict_haskey(rsp, "error"));
        desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
        g_test_message("dpc %s: %s", bad[i], desc);
        g_assert_nonnull(strstr(desc, "dpc: bit 3"));
        qobject_unref(rsp);
    }
    /* OCSSD reports NVMe 1.4, so it keeps the dpc it accepted before */
    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'dpc1','addr':'5','femu_mode':0,"
                    "'dpc':8}}");
    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
    qpci_unplug_acpi_device_test(qts, "dpc1", 5);
    /* the control: bit 4 alone is accepted */
    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'dpc1','addr':'5','devsz_mb':1,"
                    "'dpc':17}}");
    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
    qpci_unplug_acpi_device_test(qts, "dpc1", 5);
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
void femu_test_oc20_set_chunks(void *obj, void *data,
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

/*
 * Open-Channel vector commands take their data through PRPs only. With a
 * scatter-gather list the controller read the list descriptor as a PRP pair,
 * so the length field became the second page's address: a two-sector write
 * took its second sector from guest address 0x2000. It has to be refused and
 * touch nothing outside the buffer it names.
 */
void femu_test_oc_sgl_refused(void *obj, void *data,
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

void femu_test_oc12_timing_config(void *obj, void *data,
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

void femu_test_oc12_capabilities(void *obj, void *data,
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

void femu_test_oc12_opcodes(void *obj, void *data,
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

void femu_test_oc12_channel_gap(void *obj, void *data,
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

void femu_test_oc12_channel_timing(void *obj, void *data,
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

void femu_test_oc12_channel_profile(void *obj, void *data,
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

void femu_test_oc12_ppa_timing(void *obj, void *data,
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
void femu_test_oc12_small_sectors(void *obj, void *data,
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

#define FEMU_OC12_GET_L2P   0xea

/* Get L2P Table: @nlb entries of 8 bytes from entry @slba, to @buf */
static uint16_t femu_oc12_get_l2p(FemuCtrlState *c, uint64_t slba,
                                  uint32_t nlb, uint64_t buf)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = FEMU_OC12_GET_L2P;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.dptr.prp2 = cpu_to_le64(buf + 4096);
    cmd.cdw10 = cpu_to_le32((uint32_t)slba);
    cmd.cdw11 = cpu_to_le32((uint32_t)(slba >> 32));
    cmd.cdw12 = cpu_to_le32(nlb);
    return FEMU_SC(femu_admin(c, &cmd));
}

/* @len bytes at @addr all hold @byte */
static void femu_oc12_all(QTestState *qts, uint64_t addr, size_t len,
                          uint8_t byte)
{
    g_autofree uint8_t *got = g_malloc(len);
    size_t i;

    qtest_memread(qts, addr, got, len);
    for (i = 0; i < len; i++) {
        g_assert_cmphex(got[i], ==, byte);
    }
}

/*
 * Open-Channel 1.2 Get L2P Table. The table has one entry of 8 bytes for
 * each block of the namespace, and each entry reads unmapped (all ones).
 * A transfer of two pages moves 1024 entries and no byte more. The last
 * entries come back; one entry past the end, and a start at the end, are
 * Invalid Field and leave the host buffer as it was.
 */
void femu_test_oc12_l2p_bounds(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t raw = guest_alloc(alloc, 4 * 4096);
    uint64_t buf = (raw + 4095) & ~4095ULL;
    uint64_t entries;
    uint32_t lba_size;

    femu_enable(&c, &femu->dev, alloc);
    femu_identify_ns(&c, &entries, &lba_size);
    g_assert_cmpuint(entries, >, 1024);

    qtest_memset(qts, buf, 0x55, 3 * 4096);
    g_assert_cmphex(femu_oc12_get_l2p(&c, 0, 1024, buf), ==, NVME_SUCCESS);
    femu_oc12_all(qts, buf, 2 * 4096, 0xff);
    femu_oc12_all(qts, buf + 2 * 4096, 4096, 0x55);

    qtest_memset(qts, buf, 0x55, 3 * 4096);
    g_assert_cmphex(femu_oc12_get_l2p(&c, entries - 3, 3, buf), ==,
                    NVME_SUCCESS);
    femu_oc12_all(qts, buf, 24, 0xff);
    femu_oc12_all(qts, buf + 24, 3 * 4096 - 24, 0x55);

    qtest_memset(qts, buf, 0x55, 3 * 4096);
    g_assert_cmphex(femu_oc12_get_l2p(&c, entries - 3, 4, buf), ==,
                    NVME_INVALID_FIELD);
    g_assert_cmphex(femu_oc12_get_l2p(&c, entries, 1, buf), ==,
                    NVME_INVALID_FIELD);
    g_assert_cmphex(femu_oc12_get_l2p(&c, UINT64_MAX, 2, buf), ==,
                    NVME_INVALID_FIELD);
    femu_oc12_all(qts, buf, 3 * 4096, 0x55);

    guest_free(alloc, raw);
    femu_disable(&c);
    qos_invalidate_command_line();
}

#define FEMU_OC12_SET_BBT   0xf1
#define FEMU_OC12_GET_BBT   0xf2

typedef struct FemuOc12Ppaf {
    uint8_t pln_off;
    uint8_t blk_off;
    uint8_t lun_off;
    uint8_t num_pln;
    uint16_t num_blk;
} FemuOc12Ppaf;

static uint64_t femu_oc12_ppa(const FemuOc12Ppaf *f, unsigned lun,
                              unsigned blk, unsigned pln, unsigned sec)
{
    return ((uint64_t)lun << f->lun_off) | ((uint64_t)blk << f->blk_off) |
           ((uint64_t)pln << f->pln_off) | sec;
}

static void femu_oc12_set_bbt(FemuCtrlState *c, uint64_t ppa, uint8_t value)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = FEMU_OC12_SET_BBT;
    cmd.nsid = cpu_to_le32(1);
    cmd.cdw10 = cpu_to_le32((uint32_t)ppa);
    cmd.cdw11 = cpu_to_le32((uint32_t)(ppa >> 32));
    cmd.cdw12 = cpu_to_le32((uint32_t)value << 16);
    g_assert_cmpint(femu_admin(c, &cmd), ==, NVME_SUCCESS);
}

/* Submit one PPA command; return its status with DNR and dword 0. */
static uint16_t femu_oc12_ppa_cmd(FemuCtrlState *c, uint8_t opcode,
                                  uint64_t list, unsigned nppa, bool dual,
                                  uint64_t buf, uint32_t *bitmap)
{
    NvmeCmd cmd = { 0 };
    uint16_t want = c->cid;
    uint16_t got;
    uint16_t status;

    cmd.opcode = opcode;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32((uint32_t)list);
    cmd.cdw11 = cpu_to_le32((uint32_t)(list >> 32));
    cmd.cdw12 = cpu_to_le32((nppa - 1) | ((dual ? 1u : 0u) << 16));
    femu_submit(c, &c->io, &cmd);
    status = femu_complete(c, &c->io, &got, bitmap);
    g_assert_cmpint(got, ==, want);

    return status;
}

/*
 * Open-Channel 1.2 bad block table. A block marked factory bad, grown bad or
 * device reserved cannot be erased or written: the command completes with
 * Write Fault (2h/80h) and every address in it marked failed in dword 0. A
 * host-reserved block stays usable, entries are one per plane, and clearing
 * an entry makes the block usable again.
 */
void femu_test_oc12_bad_blocks(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    const uint16_t fault = NVME_WRITE_FAULT | NVME_DNR;
    uint64_t id = guest_alloc(alloc, 4096);
    uint64_t tbl = guest_alloc(alloc, 4096);
    uint64_t buf = guest_alloc(alloc, 2 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    FemuOc12Ppaf f;
    NvmeCmd cmd = { 0 };
    uint8_t ident[512];
    uint8_t hdr[64];
    uint8_t ent[16];
    uint32_t bitmap;
    unsigned blk;
    unsigned i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = (buf + 4095) & ~4095ULL;

    cmd.opcode = 0xe2;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(id);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    qtest_memread(qts, id, ident, sizeof(ident));
    f.lun_off = ident[12 + 2];
    f.pln_off = ident[12 + 4];
    f.blk_off = ident[12 + 6];
    f.num_pln = ident[256 + 6];
    f.num_blk = ident[256 + 8] | (ident[256 + 9] << 8);
    g_assert_cmpuint(f.num_pln, ==, 2);
    g_assert_cmpuint(f.num_blk, >=, 6);

    /* Grown bad on plane 1 of block 1 only. */
    femu_oc12_set_bbt(&c, femu_oc12_ppa(&f, 0, 1, 1, 0), 0x2);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_OC12_GET_BBT;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(tbl);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    qtest_memread(qts, tbl, hdr, sizeof(hdr));
    qtest_memread(qts, tbl + 64, ent, sizeof(ent));
    g_assert_cmpuint(ent[2], ==, 0);            /* block 1 plane 0 */
    g_assert_cmpuint(ent[3], ==, 0x2);          /* block 1 plane 1 */
    g_assert_cmpuint(ldl_le_p(&hdr[20]), ==, 1); /* grown bad count */

    /* A single-plane erase of the good plane works; dual-plane does not. */
    g_assert_cmphex(femu_oc12_ppa_cmd(&c, FEMU_OC20_VECT_ERASE,
                                      femu_oc12_ppa(&f, 0, 1, 0, 0), 1, false,
                                      0, &bitmap), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_oc12_ppa_cmd(&c, FEMU_OC20_VECT_ERASE,
                                      femu_oc12_ppa(&f, 0, 1, 0, 0), 1, true,
                                      0, &bitmap), ==, fault);
    g_assert_cmphex(bitmap, ==, 0x1);
    g_assert_cmphex(femu_oc12_ppa_cmd(&c, FEMU_OC20_VECT_ERASE,
                                      femu_oc12_ppa(&f, 0, 1, 1, 0), 1, false,
                                      0, &bitmap), ==, fault);

    /* A list erase naming the bad block fails as a whole. */
    qtest_writeq(qts, list, femu_oc12_ppa(&f, 0, 2, 0, 0));
    qtest_writeq(qts, list + 8, femu_oc12_ppa(&f, 0, 1, 1, 0));
    g_assert_cmphex(femu_oc12_ppa_cmd(&c, FEMU_OC20_VECT_ERASE, list, 2,
                                      false, 0, &bitmap), ==, fault);
    g_assert_cmphex(bitmap, ==, 0x3);

    /* A write across both planes of a page: block 2 works, block 1 fails. */
    for (blk = 2; blk >= 1; blk--) {
        for (i = 0; i < 8; i++) {
            qtest_writeq(qts, list + 8 * i,
                         femu_oc12_ppa(&f, 0, blk, i / 4, i % 4));
        }
        bitmap = 0;
        g_assert_cmphex(femu_oc12_ppa_cmd(&c, FEMU_OC20_VECT_WRITE, list, 8,
                                          true, buf, &bitmap), ==,
                        blk == 2 ? NVME_SUCCESS : fault);
        g_assert_cmphex(bitmap, ==, blk == 2 ? 0 : 0xff);
    }

    /* Factory bad and device reserved fail; host reserved does not. */
    femu_oc12_set_bbt(&c, femu_oc12_ppa(&f, 0, 3, 0, 0), 0x1);
    femu_oc12_set_bbt(&c, femu_oc12_ppa(&f, 0, 4, 0, 0), 0x4);
    femu_oc12_set_bbt(&c, femu_oc12_ppa(&f, 0, 5, 0, 0), 0x8);
    for (blk = 3; blk <= 5; blk++) {
        g_assert_cmphex(femu_oc12_ppa_cmd(&c, FEMU_OC20_VECT_ERASE,
                                          femu_oc12_ppa(&f, 0, blk, 0, 0), 1,
                                          true, 0, &bitmap), ==,
                        blk == 5 ? NVME_SUCCESS : fault);
    }

    /* Marking the block good again makes it usable. */
    femu_oc12_set_bbt(&c, femu_oc12_ppa(&f, 0, 1, 1, 0), 0);
    g_assert_cmphex(femu_oc12_ppa_cmd(&c, FEMU_OC20_VECT_ERASE,
                                      femu_oc12_ppa(&f, 0, 1, 0, 0), 1, true,
                                      0, &bitmap), ==, NVME_SUCCESS);

    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    guest_free(alloc, list);
    guest_free(alloc, tbl);
    guest_free(alloc, id);
}

/*
 * A golden trace of OC 1.2 command timing (x-oc12-trace). The test clock
 * stays still while a batch is queued, so each command's modelled time
 * follows from the workload alone. A batch is at most 14 commands per queue
 * pair. Before the next queue is used, a refused fence proves the device took
 * every command of the last one, so the order across queues is fixed too.
 */
#define FEMU_OC12_TRACE_QUEUES  4
#define FEMU_OC12_TRACE_LIST    256

typedef struct FemuOc12Run {
    FemuCtrlState c;
    FemuQueue q[FEMU_OC12_TRACE_QUEUES];
    unsigned queued[FEMU_OC12_TRACE_QUEUES];
    FemuOc12Ppaf f;
    uint8_t ch_off;
    uint8_t pg_off;
    uint64_t buf;
    uint64_t lists;
    unsigned nr_lists;
    int cur;
} FemuOc12Run;

static uint64_t femu_oc12_trace_ppa(FemuOc12Run *t, unsigned ch,
                                    unsigned lun, unsigned blk, unsigned pg,
                                    unsigned sec)
{
    /* sectors 4..7 of a page are the same sectors of plane 1 */
    return ((uint64_t)ch << t->ch_off) | ((uint64_t)pg << t->pg_off) |
           femu_oc12_ppa(&t->f, lun, blk, sec / 4, sec % 4);
}

/* A refused command completes at once, after every entry ahead of it. */
static void femu_oc12_trace_fence(FemuOc12Run *t, unsigned qi)
{
    NvmeCmd fence = { 0 };
    uint16_t want = t->c.cid;
    uint16_t got;

    fence.opcode = 0x93;
    fence.nsid = cpu_to_le32(1);
    femu_submit(&t->c, &t->q[qi], &fence);
    g_assert_cmpint(FEMU_SC(femu_complete(&t->c, &t->q[qi], &got, NULL)),
                    ==, NVME_INVALID_OPCODE);
    g_assert_cmpuint(got, ==, want);
}

static void femu_oc12_trace_cmd(FemuOc12Run *t, unsigned qi,
                                uint8_t opcode, const uint64_t *ppas,
                                unsigned count)
{
    QTestState *qts = t->c.pdev->bus->qts;
    uint64_t list = t->lists + t->nr_lists++ * FEMU_OC12_TRACE_LIST;
    NvmeCmd cmd = { 0 };
    unsigned i;

    if (t->cur >= 0 && t->cur != qi) {
        femu_oc12_trace_fence(t, t->cur);
    }
    t->cur = qi;
    g_assert_cmpuint(t->queued[qi], <, 14);
    g_assert_cmpuint(t->nr_lists * FEMU_OC12_TRACE_LIST, <=, 64 * 4096);
    for (i = 0; i < count; i++) {
        qtest_writeq(qts, list + i * sizeof(uint64_t), ppas[i]);
    }
    if (count == 1) {
        list = ppas[0];
    }
    cmd.opcode = opcode;
    cmd.nsid = cpu_to_le32(1);
    if (opcode != FEMU_OC20_VECT_ERASE) {
        cmd.dptr.prp1 = cpu_to_le64(t->buf);
        cmd.dptr.prp2 = cpu_to_le64(t->buf + 4096);
    }
    cmd.cdw10 = cpu_to_le32((uint32_t)list);
    cmd.cdw11 = cpu_to_le32((uint32_t)(list >> 32));
    cmd.cdw12 = cpu_to_le32(count - 1);
    femu_submit(&t->c, &t->q[qi], &cmd);
    t->queued[qi]++;
}

/* Fence the last queue used, then let the batch complete. */
static void femu_oc12_trace_run(FemuOc12Run *t)
{
    unsigned qi;
    unsigned i;

    if (t->cur >= 0) {
        femu_oc12_trace_fence(t, t->cur);
        t->cur = -1;
    }
    qtest_clock_step(t->c.pdev->bus->qts, 1000000000);
    for (qi = 0; qi < FEMU_OC12_TRACE_QUEUES; qi++) {
        for (i = 0; i < t->queued[qi]; i++) {
            g_assert_cmpint(FEMU_SC(femu_complete(&t->c, &t->q[qi], NULL,
                                                  NULL)), ==, NVME_SUCCESS);
        }
        t->queued[qi] = 0;
    }
    t->nr_lists = 0;
}

/*
 * Reads of pages 0..13 of block 0 on channel 0 lun 0: lower, centre and
 * upper TLC pages, one to eight sectors, across one or both planes.
 */
static void femu_oc12_trace_reads(FemuOc12Run *t)
{
    uint64_t ppas[8];
    unsigned pg;
    unsigned s;

    for (pg = 0; pg < 14; pg++) {
        unsigned nr = 1 + pg % 8;

        for (s = 0; s < nr; s++) {
            ppas[s] = femu_oc12_trace_ppa(t, 0, 0, 0, pg, s);
        }
        femu_oc12_trace_cmd(t, 0, FEMU_OC20_VECT_READ, ppas, nr);
    }
    femu_oc12_trace_run(t);
}

/* Erases naming several blocks: two on one lun, and both planes of one. */
static void femu_oc12_trace_erases(FemuOc12Run *t)
{
    const uint64_t a[] = {
        femu_oc12_trace_ppa(t, 0, 0, 1, 0, 0),
        femu_oc12_trace_ppa(t, 0, 0, 2, 0, 0),
        femu_oc12_trace_ppa(t, 0, 1, 1, 0, 0),
    };
    const uint64_t b[] = {
        femu_oc12_trace_ppa(t, 1, 0, 1, 0, 0),
        femu_oc12_trace_ppa(t, 1, 0, 1, 0, 4),
    };

    femu_oc12_trace_cmd(t, 0, FEMU_OC20_VECT_ERASE, a, G_N_ELEMENTS(a));
    femu_oc12_trace_cmd(t, 0, FEMU_OC20_VECT_ERASE, b, G_N_ELEMENTS(b));
    femu_oc12_trace_run(t);
}

/*
 * 40 one-sector reads on channel 0, all queued before any completes. The
 * first 33 share luns 0..2; the last 7 go to the idle lun 3, so their data
 * fits in gaps the earlier reads left on the channel. Writes on both
 * channels, between reads on channel 1, then fit around the booked reads.
 */
static void femu_oc12_trace_burst(FemuOc12Run *t, unsigned blk)
{
    uint64_t ppas[16];
    unsigned i;
    unsigned s;

    for (i = 0; i < 40; i++) {
        ppas[0] = femu_oc12_trace_ppa(t, 0, i < 33 ? i % 3 : 3, 0, i % 14,
                                      i % 8);
        femu_oc12_trace_cmd(t, i / 14, FEMU_OC20_VECT_READ, ppas, 1);
    }
    for (i = 0; i < 4; i++) {
        unsigned nr = 8 + 2 * i;

        for (s = 0; s < nr; s++) {
            ppas[s] = femu_oc12_trace_ppa(t, i % 2, i, blk, s / 8, s % 8);
        }
        femu_oc12_trace_cmd(t, 3, FEMU_OC20_VECT_WRITE, ppas, nr);
        ppas[0] = femu_oc12_trace_ppa(t, 1, 0, 0, 2 * i, 0);
        femu_oc12_trace_cmd(t, 3, FEMU_OC20_VECT_READ, ppas, 1);
    }
    femu_oc12_trace_run(t);
}

/*
 * TLC, two planes: program, read, erase and a burst of queued reads, then
 * vendor command 0xEE sets new times and the reads, erases and burst run
 * again. The device's x-oc12-trace must match the recorded one exactly.
 */
void femu_test_oc12_trace(void *obj, void *data, QGuestAllocator *alloc)
{
    const FemuOc12TraceWant *want = data;
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuOc12Run *t = g_new0(FemuOc12Run, 1);
    uint64_t id = guest_alloc(alloc, 4096);
    uint64_t raw = guest_alloc(alloc, 3 * 4096);
    uint64_t ppas[16];
    uint8_t ident[512];
    NvmeCmd cmd = { 0 };
    QDict *rsp;
    unsigned pg;
    unsigned s;
    unsigned i;

    femu_oc12_clock_start(&t->c, femu, alloc);
    t->cur = -1;
    t->q[0] = t->c.io;
    for (i = 1; i < FEMU_OC12_TRACE_QUEUES; i++) {
        femu_burst_queue(&t->c, &t->q[i], i + 1);
    }
    t->buf = (raw + 4095) & ~4095ULL;
    t->lists = guest_alloc(alloc, 64 * 4096);
    qtest_memset(qts, t->buf, 0x6b, 2 * 4096);

    cmd.opcode = 0xe2;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(id);
    g_assert_cmpint(femu_admin(&t->c, &cmd), ==, NVME_SUCCESS);
    qtest_memread(qts, id, ident, sizeof(ident));
    t->ch_off = ident[12];
    t->f.lun_off = ident[12 + 2];
    t->f.pln_off = ident[12 + 4];
    t->f.blk_off = ident[12 + 6];
    t->pg_off = ident[12 + 8];
    g_assert_cmpuint(ident[256 + 6], ==, 2);    /* planes */

    /*
     * Program pages 0..13 of block 0 on channel 0 lun 0, both planes of a
     * page and then part of the next page, and on channel 1 lun 0.
     */
    for (pg = 0; pg < 14; pg++) {
        unsigned nr = 8 + pg % 3;

        for (s = 0; s < nr; s++) {
            ppas[s] = femu_oc12_trace_ppa(t, 0, 0, 0, pg + s / 8, s % 8);
        }
        femu_oc12_trace_cmd(t, 0, FEMU_OC20_VECT_WRITE, ppas, nr);
    }
    for (pg = 0; pg < 14; pg++) {
        for (s = 0; s < 8; s++) {
            ppas[s] = femu_oc12_trace_ppa(t, 1, 0, 0, pg, s);
        }
        femu_oc12_trace_cmd(t, 1, FEMU_OC20_VECT_WRITE, ppas, 8);
    }
    femu_oc12_trace_run(t);
    femu_oc12_trace_reads(t);
    femu_oc12_trace_erases(t);
    femu_oc12_trace_burst(t, 3);

    /* 0xEE: odd times, so a transfer of part of a page still rounds */
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = 0xee;
    cmd.cdw10 = cpu_to_le32(90001);         /* upper page read */
    cmd.cdw11 = cpu_to_le32(50001);         /* lower page read */
    cmd.cdw12 = cpu_to_le32(4000001);       /* upper page program */
    cmd.cdw13 = cpu_to_le32(700001);        /* lower page program */
    cmd.cdw14 = cpu_to_le32(2500001);       /* block erase */
    cmd.cdw15 = cpu_to_le32(60001);         /* channel transfer */
    g_assert_cmpint(femu_admin(&t->c, &cmd), ==, NVME_SUCCESS);

    femu_oc12_trace_reads(t);
    femu_oc12_trace_erases(t);
    femu_oc12_trace_burst(t, 4);

    rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                    "'path':'/machine/peripheral/oc12-test',"
                    "'property':'x-oc12-trace'}}");
    g_assert_true(qdict_haskey(rsp, "return"));
    g_test_message("x-oc12-trace %s", qdict_get_str(rsp, "return"));
    {
        g_auto(GStrv) got = g_strsplit(qdict_get_str(rsp, "return"), " ", 0);

        g_assert_cmpuint(g_strv_length(got), ==, want->len);
        for (i = 0; i < want->len; i++) {
            uint64_t v = g_ascii_strtoull(got[i], NULL, 10);

            if (v != want->trace[i]) {
                g_test_message("x-oc12-trace entry %u (command %u) differs",
                               i, i ? (i - 1) / 2 : 0);
            }
            g_assert_cmpuint(v, ==, want->trace[i]);
        }
    }
    qobject_unref(rsp);

    for (i = 1; i < FEMU_OC12_TRACE_QUEUES; i++) {
        femu_queue_free(&t->c, &t->q[i]);
    }
    femu_queue_free(&t->c, &t->c.io);
    femu_disable(&t->c);
    guest_free(alloc, t->lists);
    guest_free(alloc, raw);
    guest_free(alloc, id);
    g_free(t);
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
void femu_test_oc20_fuzz(void *obj, void *data, QGuestAllocator *alloc)
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
    GRand *rng = g_rand_new_with_seed(femu_fuzz_seed(0x4f433230));
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

    for (i = 0; i < femu_fuzz_rounds(FEMU_IO_FUZZ_ROUNDS); i++) {
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

/* one Open-Channel 2.0 vector command on the single sector @lba */
static void femu_oc20_one(FemuCtrlState *c, uint8_t opcode, uint64_t lba,
                          uint64_t buf)
{
    NvmeCmd cmd;
    uint16_t want, got;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = opcode;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32((uint32_t)lba);
    cmd.cdw11 = cpu_to_le32((uint32_t)(lba >> 32));
    want = c->cid;
    femu_submit(c, &c->io, &cmd);
    g_assert_cmpint(FEMU_SC(femu_complete(c, &c->io, &got, NULL)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(got, ==, want);
}

/* a vector read of sectors @a and @b in one command; returns its time in ms */
static int64_t femu_oc20_read2_ms(FemuCtrlState *c, uint64_t a, uint64_t b,
                                  uint64_t list, uint64_t buf)
{
    QTestState *qts = c->pdev->bus->qts;
    NvmeCmd cmd;
    uint16_t want, got;
    int64_t t0;

    qtest_writeq(qts, list, a);
    qtest_writeq(qts, list + 8, b);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_OC20_VECT_READ;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.dptr.prp2 = cpu_to_le64(buf + 4096);
    cmd.cdw10 = cpu_to_le32((uint32_t)list);
    cmd.cdw11 = cpu_to_le32((uint32_t)(list >> 32));
    cmd.cdw12 = cpu_to_le32(1);
    want = c->cid;
    t0 = g_get_monotonic_time();
    femu_submit(c, &c->io, &cmd);
    g_assert_cmpint(FEMU_SC(femu_complete(c, &c->io, &got, NULL)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(got, ==, want);
    return (g_get_monotonic_time() - t0) / 1000;
}

static int64_t femu_oc20_read_ms(FemuCtrlState *c, uint64_t lba, uint64_t buf)
{
    int64_t t0 = g_get_monotonic_time();

    femu_oc20_one(c, FEMU_OC20_VECT_READ, lba, buf);
    return (g_get_monotonic_time() - t0) / 1000;
}

/*
 * oc20_page_types on MLC: 0xEE sets a 50 ms lower page read and a 200 ms
 * upper page read. A page spans 4 sectors on each of 2 planes, so sector 0
 * is on page 0 and sector 24 on page 3 (both lower), and sector 48 on page 6
 * (upper); a plane factor left out would put sector 24 on an upper page. With
 * the option each read takes its page's time, and a vector read of sectors
 * 0 and 48 pays both pages on the one unit. Without it every read takes the
 * lower time and the vector pays once, as before.
 */
void femu_test_oc20_page_types(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    bool on = data != NULL;
    uint64_t buf = guest_alloc(alloc, 8192);
    uint64_t list = guest_alloc(alloc, 4096);
    NvmeCmd cmd;
    int64_t s0, s24, s48, both;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = 0xee;
    cmd.cdw10 = cpu_to_le32(200000000);     /* upper page read */
    cmd.cdw11 = cpu_to_le32(50000000);      /* lower page read */
    cmd.cdw12 = cpu_to_le32(100000);        /* upper page program */
    cmd.cdw13 = cpu_to_le32(100000);        /* lower page program */
    cmd.cdw14 = cpu_to_le32(100000);        /* block erase */
    cmd.cdw15 = cpu_to_le32(0);             /* channel transfer */
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    femu_create_io_queues(&c);

    /* past sector 48 by more than the cache units, so all of it is on NAND */
    for (i = 0; i <= 96; i++) {
        femu_oc20_one(&c, FEMU_OC20_VECT_WRITE, i, buf);
    }
    s0 = femu_oc20_read_ms(&c, 0, buf);
    s24 = femu_oc20_read_ms(&c, 24, buf);
    s48 = femu_oc20_read_ms(&c, 48, buf);
    both = femu_oc20_read2_ms(&c, 0, 48, list, buf);
    g_test_message("oc20 page types %s: sector 0 %" PRId64 " ms, 24 %" PRId64
                   " ms, 48 %" PRId64 " ms, 0 and 48 %" PRId64 " ms",
                   on ? "on" : "off", s0, s24, s48, both);
    g_assert_cmpint(s0, >=, 50);
    g_assert_cmpint(s0, <, 110);
    g_assert_cmpint(s24, >=, 50);
    g_assert_cmpint(s24, <, 110);
    if (on) {
        g_assert_cmpint(s48, >=, 200);
        g_assert_cmpint(s48, <, 260);
        g_assert_cmpint(both, >=, 250);
        g_assert_cmpint(both, <, 320);
    } else {
        g_assert_cmpint(s48, >=, 50);
        g_assert_cmpint(s48, <, 110);
        g_assert_cmpint(both, >=, 50);
        g_assert_cmpint(both, <, 110);
    }

    femu_disable(&c);
    guest_free(alloc, list);
    guest_free(alloc, buf);
}

/* the page type tables stop at 512 pages per block */
void femu_test_oc20_page_types_refused(void *obj, void *data,
                                       QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QDict *rsp = qtest_qmp(femu->dev.bus->qts,
        "{'execute':'device_add','arguments':{'driver':'femu','id':'oc2big',"
        "'addr':'5','devsz_mb':1024,'femu_mode':0,'lver':2,'lnum_ch':3,"
        "'lnum_lun':5,'lsecs_per_pg':4,'lpgs_per_blk':1024,"
        "'oc20_page_types':true}}");
    const char *desc;

    g_assert_true(qdict_haskey(rsp, "error"));
    desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
    g_test_message("%s", desc);
    g_assert_nonnull(strstr(desc, "oc20_page_types needs at most 512"));
    qobject_unref(rsp);
}

/*
 * An Open-Channel address is sparse, and the common handlers of the optional
 * commands index the backing store with a flat LBA. With every ONCS bit set,
 * the controller must neither list nor run them. The last address of the
 * namespace lies far past the backed media, so a command that still ran would
 * zero or read memory outside the store.
 */
void femu_test_oc_generic_refused(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    static const uint8_t opcodes[] = {
        NVME_CMD_DSM, NVME_CMD_WRITE_ZEROES, NVME_CMD_COMPARE,
        NVME_CMD_VERIFY, FEMU_CMD_COPY, NVME_CMD_WRITE_UNCOR,
    };
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd;
    NvmeIdCtrl id;
    uint64_t nsze, buf, last;
    uint32_t lbasz;
    uint8_t range[16] = { 0 };
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, 4096);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_IDENTIFY;
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(NVME_ID_CNS_CTRL);
    g_assert_cmpint(FEMU_SC(femu_admin(&c, &cmd)), ==, NVME_SUCCESS);
    qtest_memread(c.pdev->bus->qts, buf, &id, sizeof(id));
    g_assert_cmphex(le16_to_cpu(id.oncs) & 0x18f, ==, 0);

    femu_identify_ns(&c, &nsze, &lbasz);
    last = nsze - 1;
    stl_le_p(range + 4, 1);
    stq_le_p(range + 8, last);
    qtest_memwrite(c.pdev->bus->qts, buf, range, sizeof(range));
    for (i = 0; i < ARRAY_SIZE(opcodes); i++) {
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = opcodes[i];
        cmd.nsid = cpu_to_le32(1);
        cmd.dptr.prp1 = cpu_to_le64(buf);
        if (opcodes[i] == NVME_CMD_DSM) {
            cmd.cdw11 = cpu_to_le32(FEMU_DSM_AD);
        } else {
            cmd.cdw10 = cpu_to_le32((uint32_t)last);
            cmd.cdw11 = cpu_to_le32((uint32_t)(last >> 32));
        }
        g_assert_cmphex(femu_io(&c, &cmd), ==, NVME_INVALID_OPCODE);
    }
    femu_disable(&c);
}
