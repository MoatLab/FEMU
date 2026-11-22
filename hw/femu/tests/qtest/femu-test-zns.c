/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QTest testcases for the FEMU SSD emulator: the zoned namespace tests
 * (femu_mode=3).
 *
 * femu-test.c registers every test. This file holds the test bodies
 * and the helpers that only they use.
 */

#include "qemu/osdep.h"
#include "femu-test.h"

#define FEMU_ZONE_ACTION_RESET  0x04

/*
 * The zone size lives in the entry for the format index the namespace is
 * formatted to. It was written into the first entry whatever the index, so a
 * namespace formatted to any other index reported a zone size of zero, which a
 * host reads as a namespace it cannot use.
 */
void femu_test_zoned_format_index(void *obj, void *data,
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

/*
 * A zoned write refused for its data pointer wrote nothing, so the zone's
 * write pointer must not move: the next write at the reported pointer has
 * to be accepted and land there.
 */
void femu_test_zone_bad_dptr(void *obj, void *data,
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

void femu_test_zrwa_reopen(void *obj, void *data,
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
void femu_test_zone_reset(void *obj, void *data,
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

/*
 * Zone parallelism. Two channels of two LUNs, one plane, two blocks: with
 * zns_chnls_per_zone=1 and zns_luns_per_zone=1 each zone owns one die, and
 * four zones share each block index. Zone 2 sits on channel 0, LUN 1. With
 * zns_reset_by_fill a reset erases only programmed blocks, and SMART
 * Percentage Used (rating 1, 8 blocks) counts 12 per erase. A zone 0
 * write evicts a zone 2 write from the only write cache, which programs
 * only zone 2's die. Zone 0 then holds data, but none on the media, so its
 * reset erases nothing. A reset of zone 2 erases one block. Zone 6 is on
 * the same die as zone 2, one block index up: a program of zone 6 must not
 * reach zone 2's block.
 */
void femu_test_zns_lpz(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint8_t report[192];
    uint64_t buf;
    uint64_t log;
    uint64_t zsze;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    log = guest_alloc(alloc, 512);
    femu_zone_report(&c, buf, report);
    zsze = ldq_le_p(report + 64 + 64 + 16);
    /* one die of 64 SLC pages of 16 KiB */
    g_assert_cmpuint(zsze, ==, 64 * 16384 / c.lba_size);

    qtest_memset(qts, buf, 0x2d, FEMU_DATA_SIZE);
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 2 * zsze, buf)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 0, buf)), ==,
                    NVME_SUCCESS);

    g_assert_cmpint(femu_zone_action(&c, 0, FEMU_ZONE_ACTION_RESET), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_get_log(&c, NVME_LOG_SMART_INFO, log, 512,
                                         0)), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readb(qts, log + 5), ==, 0);

    g_assert_cmpint(femu_zone_action(&c, 2 * zsze, FEMU_ZONE_ACTION_RESET),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_get_log(&c, NVME_LOG_SMART_INFO, log, 512,
                                         0)), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readb(qts, log + 5), ==, 100 / 8);

    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 6 * zsze, buf)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 2 * zsze, buf)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_zone_action(&c, 2 * zsze, FEMU_ZONE_ACTION_RESET),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_get_log(&c, NVME_LOG_SMART_INFO, log, 512,
                                         0)), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readb(qts, log + 5), ==, 100 / 8);
    g_assert_cmpint(femu_zone_action(&c, 6 * zsze, FEMU_ZONE_ACTION_RESET),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_get_log(&c, NVME_LOG_SMART_INFO, log, 512,
                                         0)), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readb(qts, log + 5), ==, 2 * 100 / 8);

    guest_free(alloc, log);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * Interleave order of a zone. Two channels of two LUNs and one plane; a
 * page transfer holds its channel for ZNS_ORDER_XFER_MS. Eight 4 KiB writes
 * fill two 16 KiB slots of a zone, and a write to the next zone evicts the
 * only write cache. Channel order (the default) programs the two slots on
 * two channels, so the transfers overlap. LUN order programs both on
 * channel 0, so they take turns. Host delays only add time, so the check
 * uses the fastest of three such flushes. @data is "ch" or "lun".
 */
#define ZNS_ORDER_XFER_MS 400

void femu_test_zns_order(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    bool lun = g_str_equal(data, "lun");
    FemuCtrlState c = { 0 };
    uint8_t report[192];
    uint64_t buf;
    uint64_t zsze;
    int64_t t0;
    int64_t ms;
    int64_t best = INT64_MAX;
    int r;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    femu_zone_report(&c, buf, report);
    zsze = ldq_le_p(report + 64 + 64 + 16);
    /* the first I/O command pays a one-time start cost; keep it out */
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_READ, 0, buf)), ==,
                    NVME_SUCCESS);
    qtest_memset(qts, buf, 0x3e, FEMU_DATA_SIZE);
    for (r = 0; r < 3; r++) {
        for (i = 0; i < 8; i++) {
            g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE,
                                            2 * r * zsze +
                                            i * (FEMU_DATA_SIZE / c.lba_size),
                                            buf)), ==, NVME_SUCCESS);
        }
        t0 = g_get_monotonic_time();
        g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE,
                                        (2 * r + 1) * zsze, buf)), ==,
                        NVME_SUCCESS);
        ms = (g_get_monotonic_time() - t0) / 1000;
        best = MIN(best, ms);
    }
    g_test_message("order %s: fastest two-slot flush took %" PRId64 " ms",
                   (char *)data, best);
    if (lun) {
        g_assert_cmpint(best, >=, 2 * ZNS_ORDER_XFER_MS);
    } else {
        g_assert_cmpint(best, >=, ZNS_ORDER_XFER_MS);
        g_assert_cmpint(best, <, ZNS_ORDER_XFER_MS * 3 / 2);
    }

    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * The write cache of a zone holds one program unit for each die of the
 * zone. A zone of one die (one channel of two, or one LUN of two, and one
 * plane) takes four 4 KiB writes per 16 KiB SLC page. Four writes fill the
 * cache, and the next write flushes it: writes 5, 9, 13, ... each pay one
 * program of ZNS_CAP_PROG_MS. A cache sized from both dies held two
 * programs: writes 5, 13 and 21 were fast, and writes 9, 17 and 25 paid two
 * programs in series. Host delays only add time, so each check uses the
 * fastest write of its position.
 */
#define ZNS_CAP_PROG_MS 300

void femu_test_zns_cache_cap(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf;
    int64_t odd = INT64_MAX;
    int64_t even = INT64_MAX;
    int64_t t0;
    int64_t ms;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    /* the first I/O command pays a one-time start cost; keep it out */
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_READ, 0, buf)), ==,
                    NVME_SUCCESS);
    qtest_memset(qts, buf, 0x4f, FEMU_DATA_SIZE);
    for (i = 1; i <= 25; i++) {
        t0 = g_get_monotonic_time();
        g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE,
                                        (i - 1) * (FEMU_DATA_SIZE / c.lba_size),
                                        buf)), ==, NVME_SUCCESS);
        ms = (g_get_monotonic_time() - t0) / 1000;
        if (i % 8 == 5) {
            odd = MIN(odd, ms);
        } else if (i > 1 && i % 8 == 1) {
            even = MIN(even, ms);
        }
    }
    g_test_message("fastest of writes 5/13/21: %" PRId64 " ms, of writes "
                   "9/17/25: %" PRId64 " ms", odd, even);
    g_assert_cmpint(odd, >=, ZNS_CAP_PROG_MS);
    g_assert_cmpint(even, >=, ZNS_CAP_PROG_MS);
    g_assert_cmpint(even, <, 2 * ZNS_CAP_PROG_MS);

    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * zns_luns_per_zone must divide zns_num_lun; zns_zone_order is ch or lun.
 * One-die zones on two channels of two LUNs and two blocks make eight
 * zones, so eight write caches are allowed.
 */
void femu_test_zns_lpz_refused(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    const char *opts[] = { "'zns_luns_per_zone':3", "'zns_zone_order':'die'" };
    const char *msg[] = { "zns_luns_per_zone 3 must divide zns_num_lun 4",
                          "zns_zone_order must be ch or lun" };
    QDict *rsp;

    for (int i = 0; i < ARRAY_SIZE(opts); i++) {
        g_autofree char *cmd = g_strdup_printf(
            "{'execute':'device_add','arguments':{'driver':'femu',"
            "'id':'zns-lpz','addr':'5','devsz_mb':32,'femu_mode':3,"
            "'zns_num_lun':4,%s}}", opts[i]);

        rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));
        g_assert_true(qdict_haskey(rsp, "error"));
        g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                              "desc"), msg[i]));
        qobject_unref(rsp);
    }
    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'zns-wc','addr':'6','devsz_mb':8,"
                    "'femu_mode':3,'zns_num_ch':2,'zns_num_lun':2,"
                    "'zns_num_plane':1,'zns_num_blk':2,'zns_flash_type':1,"
                    "'zns_chnls_per_zone':1,'zns_luns_per_zone':1,"
                    "'zns_num_wc':8}}");
    g_assert_false(qdict_haskey(rsp, "error"));
    qobject_unref(rsp);
    qos_invalidate_command_line();
}

/*
 * More zones written at once than there are write caches: every 16 KiB a
 * zone writes evicts another zone's cache, and that flush fills only part
 * of a die. The next flush has to continue at the first free plane. If it
 * starts at plane 0 again, plane 0's block runs past its last page, and
 * reads of the blocks mapped there skip the NAND model and finish under tR.
 */
#define ZNS_PLANE_WRITERS   5
#define ZNS_PLANE_TR_NS     2000000

void femu_test_zns_flush_plane(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf;
    uint8_t report[192];
    uint64_t zsze;
    uint64_t lpns;
    uint64_t lba4k;
    uint64_t lpn;
    unsigned fast_head = 0;
    unsigned fast_tail = 0;
    int z;
    int k;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    qtest_memset(qts, buf, 0x3c, FEMU_DATA_SIZE);

    femu_zone_report(&c, buf, report);
    zsze = ldq_le_p(report + 64 + 64 + 16);
    lba4k = FEMU_DATA_SIZE / c.lba_size;
    lpns = zsze / lba4k;
    g_assert_cmpuint(lpns, ==, 512);

    for (lpn = 0; lpn < lpns; lpn += 4) {
        for (z = 0; z < ZNS_PLANE_WRITERS; z++) {
            for (k = 0; k < 4; k++) {
                g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE,
                                                z * zsze +
                                                (lpn + k) * lba4k, buf)),
                                ==, NVME_SUCCESS);
            }
        }
    }
    /* one write to each of three more zones flushes all three caches */
    for (z = ZNS_PLANE_WRITERS; z < ZNS_PLANE_WRITERS + 3; z++) {
        g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, z * zsze, buf)),
                        ==, NVME_SUCCESS);
    }

    /*
     * The head of zone 0 is the control: those reads must take tR. The
     * tail is where plane 0's block overflows.
     */
    for (lpn = 0; lpn < lpns; lpn++) {
        int64_t t0;

        if (lpn == 80) {
            lpn = lpns - 80;
        }
        t0 = g_get_monotonic_time();
        g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_READ, lpn * lba4k,
                                        buf)), ==, NVME_SUCCESS);
        if ((g_get_monotonic_time() - t0) * 1000 < ZNS_PLANE_TR_NS / 2) {
            if (lpn < 80) {
                fast_head++;
            } else {
                fast_tail++;
            }
        }
    }
    g_test_message("reads under tR/2: head %u, tail %u", fast_head,
                   fast_tail);
    g_assert_cmpuint(fast_head, ==, 0);
    g_assert_cmpuint(fast_tail, ==, 0);

    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * ZNS wear: each Zone Reset of a written zone erases one block per plane
 * (2 here), and SMART Percentage Used is the erases over the blocks (64)
 * times the rating (1). Before, a zoned namespace always reported 0.
 */
void femu_test_zns_wear(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf;
    uint64_t log;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    log = guest_alloc(alloc, 512);
    qtest_memset(qts, buf, 0x5a, FEMU_DATA_SIZE);
    for (int k = 1; k <= 32; k++) {
        g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 0, buf)), ==,
                        NVME_SUCCESS);
        g_assert_cmpint(femu_zone_action(&c, 0, FEMU_ZONE_ACTION_RESET), ==,
                        NVME_SUCCESS);
        if (k == 1 || k == 16 || k == 32) {
            g_assert_cmpint(FEMU_SC(femu_get_log(&c, NVME_LOG_SMART_INFO, log,
                                                 512, 0)), ==, NVME_SUCCESS);
            g_assert_cmpuint(qtest_readb(qts, log + 5), ==, 2 * k * 100 / 64);
        }
    }
    guest_free(alloc, log);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * One QLC wordline of a one-plane zone holds 16 4 KiB pages: four NAND pages,
 * one of each page type, in LBA order. The write cache programs it when a
 * 17th write arrives. Returns the time of a read of 4 KiB page @lpn in ms.
 */
static int64_t femu_zns_read_ms(FemuCtrlState *c, uint64_t lpn, uint64_t buf)
{
    int64_t t0 = g_get_monotonic_time();

    g_assert_cmpint(FEMU_SC(femu_rw(c, NVME_CMD_READ,
                                    lpn * (FEMU_DATA_SIZE / c->lba_size), buf)),
                    ==, NVME_SUCCESS);
    return (g_get_monotonic_time() - t0) / 1000;
}

/* fill the first wordline; returns the time of the write that programs it */
static int64_t femu_zns_fill_wordline(FemuCtrlState *c, uint64_t buf)
{
    int64_t t0 = 0;
    int i;

    for (i = 0; i < 17; i++) {
        t0 = g_get_monotonic_time();
        g_assert_cmpint(FEMU_SC(femu_rw(c, NVME_CMD_WRITE,
                                        i * (FEMU_DATA_SIZE / c->lba_size),
                                        buf)), ==, NVME_SUCCESS);
    }
    return (g_get_monotonic_time() - t0) / 1000;
}

/*
 * zns_page_types: with a mean read time of 200 ms, the lower page (type 0)
 * reads in about 107 ms and the upper page (type 3) in about 307 ms, the
 * spread of the shared QLC table. Without it both take 200 ms. A program
 * writes a whole wordline, so it keeps its one time of 100 ms either way.
 * @data is "on" when the device has page types on.
 */
void femu_test_zns_page_types(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    bool on = g_str_equal(data, "on");
    FemuCtrlState c = { 0 };
    uint64_t buf;
    int64_t lower, upper, program;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    qtest_memset(qts, buf, 0x3c, FEMU_DATA_SIZE);
    program = femu_zns_fill_wordline(&c, buf);
    g_test_message("page types %s: program %" PRId64 " ms",
                   on ? "on" : "off", program);
    g_assert_cmpint(program, >=, 100);
    g_assert_cmpint(program, <, 160);

    lower = femu_zns_read_ms(&c, 0, buf);
    upper = femu_zns_read_ms(&c, 12, buf);
    g_test_message("page types %s: lower %" PRId64 " ms, upper %" PRId64
                   " ms", on ? "on" : "off", lower, upper);
    if (on) {
        g_assert_cmpint(lower, >=, 107);
        g_assert_cmpint(lower, <, 160);
        g_assert_cmpint(upper, >=, 307);
        g_assert_cmpint(upper, <, 380);
    } else {
        g_assert_cmpint(lower, >=, 200);
        g_assert_cmpint(lower, <, 260);
        g_assert_cmpint(upper, >=, 200);
        g_assert_cmpint(upper, <, 260);
    }

    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * zns_ecc_step_ns: a read pays one ECC step more once its block has 750
 * erases. Each round writes one page to zone 0, so the zone is open, and
 * resets it, which erases its block. The read takes 50 ms before and
 * 50 + 150 ms after.
 */
/*
 * PLC has no page type table, so zns_page_types on PLC is refused, and so
 * is an ECC step past one hour.
 */
void femu_test_zns_page_types_plc(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    QDict *rsp;
    const char *desc;

    rsp = qtest_qmp(qts,
        "{'execute':'device_add','arguments':{'driver':'femu','id':'plc',"
        "'addr':'5','devsz_mb':32,'femu_mode':3,'zns_flash_type':5,"
        "'zns_pg_rd_lat':1000,'zns_pg_wr_lat':1000,'zns_blk_er_lat':1000,"
        "'zns_page_types':1}}");
    g_assert_true(qdict_haskey(rsp, "error"));
    desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
    g_test_message("%s", desc);
    g_assert_nonnull(strstr(desc, "type 5 has no page type table"));
    qobject_unref(rsp);

    /* past one hour, the scaled read or four ECC steps could overflow */
    rsp = qtest_qmp(qts,
        "{'execute':'device_add','arguments':{'driver':'femu','id':'big',"
        "'addr':'5','devsz_mb':32,'femu_mode':3,"
        "'zns_ecc_step_ns':3600000000001}}");
    g_assert_true(qdict_haskey(rsp, "error"));
    desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
    g_test_message("%s", desc);
    g_assert_nonnull(strstr(desc, "at most 3600000000000 ns"));
    qobject_unref(rsp);
}

void femu_test_zns_ecc(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf;
    int64_t before, after;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    qtest_memset(qts, buf, 0x3c, FEMU_DATA_SIZE);
    femu_zns_fill_wordline(&c, buf);
    before = femu_zns_read_ms(&c, 0, buf);

    for (i = 0; i < 760; i++) {
        g_assert_cmpint(femu_zone_action(&c, 0, FEMU_ZONE_ACTION_RESET), ==,
                        NVME_SUCCESS);
        g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 0, buf)), ==,
                        NVME_SUCCESS);
    }
    g_assert_cmpint(femu_zone_action(&c, 0, FEMU_ZONE_ACTION_RESET), ==,
                    NVME_SUCCESS);
    femu_zns_fill_wordline(&c, buf);
    after = femu_zns_read_ms(&c, 0, buf);
    g_test_message("ECC: read %" PRId64 " ms new, %" PRId64
                   " ms after 760 resets", before, after);
    g_assert_cmpint(before, >=, 50);
    g_assert_cmpint(before, <, 110);
    g_assert_cmpint(after, >=, 200);
    g_assert_cmpint(after, <, 260);

    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * LUN contention on ZNS. One LUN has two planes, and a program or an erase
 * takes ZNS_LUN_OP_MS. An SLC page is 16 KiB, so the write cache holds
 * ZNS_LUN_FILL 4 KiB pages, and the next write programs both planes. Each
 * plane runs on its own by default, so that write takes one
 * program time. With zns_lun_contention the planes take turns and the write
 * takes two. A zone reset erases both planes in one multi-plane operation,
 * so it takes one erase time either way. @data is "on" when the device has
 * contention on.
 */
#define ZNS_LUN_OP_MS 300
#define ZNS_LUN_FILL  8

void femu_test_zns_lun(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    bool on = g_str_equal(data, "on");
    FemuCtrlState c = { 0 };
    uint64_t buf;
    int64_t t0;
    int64_t ms;
    uint64_t lba = 0;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    qtest_memset(qts, buf, 0x3c, FEMU_DATA_SIZE);

    for (i = 0; i <= ZNS_LUN_FILL; i++) {
        t0 = g_get_monotonic_time();
        g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, lba, buf)), ==,
                        NVME_SUCCESS);
        ms = (g_get_monotonic_time() - t0) / 1000;
        lba += FEMU_DATA_SIZE / c.lba_size;
    }
    g_test_message("contention %s: program took %" PRId64 " ms",
                   on ? "on" : "off", ms);
    if (on) {
        g_assert_cmpint(ms, >=, 2 * ZNS_LUN_OP_MS);
    } else {
        g_assert_cmpint(ms, >=, ZNS_LUN_OP_MS);
        g_assert_cmpint(ms, <, 2 * ZNS_LUN_OP_MS - ZNS_LUN_OP_MS / 3);
    }

    t0 = g_get_monotonic_time();
    g_assert_cmpint(femu_zone_action(&c, 0, FEMU_ZONE_ACTION_RESET), ==,
                    NVME_SUCCESS);
    ms = (g_get_monotonic_time() - t0) / 1000;
    g_test_message("contention %s: reset took %" PRId64 " ms",
                   on ? "on" : "off", ms);
    g_assert_cmpint(ms, >=, ZNS_LUN_OP_MS);
    g_assert_cmpint(ms, <, 2 * ZNS_LUN_OP_MS - ZNS_LUN_OP_MS / 3);

    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * Zone reset by fill. One channel has two LUNs of two planes, so zone 0 owns
 * four blocks, and an erase takes ZNS_LUN_OP_MS. One write stays in the write
 * cache. ZNS_LUN_FILL writes fill half the stripe, and a write to zone 1
 * evicts the only cache, which programs both planes of LUN 0 only. Without
 * zns_reset_by_fill a reset erases all four blocks. With it, a reset erases
 * only programmed blocks: none after one write, two after the eviction.
 * SMART Percentage Used (rating 1, 128 blocks) shows the erase count. A
 * reset with no erase must finish under half an erase time, which leaves
 * room for host jitter. @data is "off", "on", or "lun" (on, plus
 * zns_lun_contention).
 */
void femu_test_zns_reset_fill(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    bool on = !g_str_equal(data, "off");
    FemuCtrlState c = { 0 };
    uint8_t report[192];
    uint64_t buf;
    uint64_t log;
    uint64_t zsze;
    int64_t t0;
    int64_t ms;
    uint64_t lba = 0;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    log = guest_alloc(alloc, 512);
    femu_zone_report(&c, buf, report);
    zsze = ldq_le_p(report + 64 + 64 + 16);
    /* the first I/O command pays a one-time start cost; keep it out */
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_READ, 0, buf)), ==,
                    NVME_SUCCESS);
    qtest_memset(qts, buf, 0x6b, FEMU_DATA_SIZE);

    /* an empty zone has no media work in either mode */
    t0 = g_get_monotonic_time();
    g_assert_cmpint(femu_zone_action(&c, 0, FEMU_ZONE_ACTION_RESET), ==,
                    NVME_SUCCESS);
    ms = (g_get_monotonic_time() - t0) / 1000;
    g_test_message("reset by fill %s: empty reset %" PRId64 " ms",
                   (char *)data, ms);
    g_assert_cmpint(ms, <, ZNS_LUN_OP_MS / 2);

    /* one write, still in the write cache: no block holds a programmed page */
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 0, buf)), ==,
                    NVME_SUCCESS);
    t0 = g_get_monotonic_time();
    g_assert_cmpint(femu_zone_action(&c, 0, FEMU_ZONE_ACTION_RESET), ==,
                    NVME_SUCCESS);
    ms = (g_get_monotonic_time() - t0) / 1000;
    g_test_message("reset by fill %s: cached reset %" PRId64 " ms",
                   (char *)data, ms);
    if (on) {
        g_assert_cmpint(ms, <, ZNS_LUN_OP_MS / 2);
    } else {
        g_assert_cmpint(ms, >=, ZNS_LUN_OP_MS);
    }

    /* program both planes of LUN 0; LUN 1 stays erased */
    for (i = 0; i < ZNS_LUN_FILL; i++) {
        g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, lba, buf)), ==,
                        NVME_SUCCESS);
        lba += FEMU_DATA_SIZE / c.lba_size;
    }
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, zsze, buf)), ==,
                    NVME_SUCCESS);
    t0 = g_get_monotonic_time();
    g_assert_cmpint(femu_zone_action(&c, 0, FEMU_ZONE_ACTION_RESET), ==,
                    NVME_SUCCESS);
    ms = (g_get_monotonic_time() - t0) / 1000;
    g_test_message("reset by fill %s: written reset %" PRId64 " ms",
                   (char *)data, ms);
    g_assert_cmpint(ms, >=, ZNS_LUN_OP_MS);
    g_assert_cmpint(ms, <, 2 * ZNS_LUN_OP_MS - ZNS_LUN_OP_MS / 3);

    /* erases: off 4 + 4 = 8 (6%), on 0 + 2 = 2 (1%) */
    g_assert_cmpint(FEMU_SC(femu_get_log(&c, NVME_LOG_SMART_INFO, log, 512,
                                         0)), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readb(qts, log + 5), ==, (on ? 2 : 8) * 100 / 128);

    guest_free(alloc, log);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}
#define ZAP_PER_Q   (ZAP_QDEPTH - 1)
#define ZAP_ROUNDS  150

void femu_test_zone_append_parallel(void *obj, void *data,
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
 * SGL support is reported for the controller as a whole, so every I/O
 * command with a data buffer takes one, not only Read and Write.
 */
void femu_test_sgl_zoned(void *obj, void *data, QGuestAllocator *alloc)
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

/* zone @i of a two-zone report: state and attributes */
static uint8_t femu_zr_state(const uint8_t *r, int i)
{
    return r[64 + 64 * i + 1] >> 4;
}

static uint8_t femu_zr_za(const uint8_t *r, int i)
{
    return r[64 + 64 * i + 2];
}

/* run one command and return how long it took, in ms */
static int64_t femu_zns_ms(FemuCtrlState *c, uint8_t opcode, uint64_t slba,
                           uint64_t buf)
{
    int64_t start = g_get_monotonic_time();

    if (opcode == NVME_CMD_ZONE_MGMT_SEND) {
        g_assert_cmpint(femu_zone_action(c, slba, NVME_ZONE_ACTION_FINISH),
                        ==, NVME_SUCCESS);
    } else {
        g_assert_cmpint(FEMU_SC(femu_rw(c, opcode, slba, buf)), ==,
                        NVME_SUCCESS);
    }
    return (g_get_monotonic_time() - start) / 1000;
}

/*
 * A finished zone takes no more writes, so its write cache is programmed.
 * A program takes 200 ms and a read 100 ms. A read of zone 1 first lets
 * the FTL thread start. One page written to zone 0 then stays in the
 * cache, not on NAND, so the write pays no program.
 * - @data "host": Finish waits for the program, and a read of the page
 *   then pays the NAND read.
 * - "ctlr": the controller finishes the zone (zns_frl_sec). The next read
 *   waits for the rest of the program and pays the NAND read.
 * - "drop": a controller reset drops the Finish before the FTL thread sees
 *   it. The zone stays Full, so the program must still happen: the read
 *   after the reset pays the NAND read.
 * - "late": the FTL thread waits while a write and, 150 ms later, a Finish
 *   arrive. The write reaches the cache after the finish, so its program
 *   starts at the finish: the Finish takes the whole 200 ms.
 * - "lostreset": a controller reset drops a Reset before the FTL thread
 *   sees it. After the next Reset, a write and a Finish of the zone still
 *   take the program.
 * - "refinish": after the controller finishes the zone, a host Finish of
 *   the Full zone waits for the program the controller started.
 * - "heldreset": the FTL thread waits while a write, a Finish and a Reset
 *   of the zone arrive. The Finish still waits for the program.
 * - "latefive": the FTL thread waits while five one-page writes and a
 *   Finish arrive. The five pages go to NAND packed, in one program of the
 *   two planes, not five programs one after the other.
 * - "lateread": as "latefive", with a read between each two writes.
 * - "twogen": the FTL thread waits while Reset, write, Finish arrive twice
 *   for zone 0. The first Finish still waits for its own program.
 * - "fill": zone 0 holds one stripe (zns_zone_cap=32K, 8 pages). The write
 *   that fills it programs the stripe, so it takes the program, and a
 *   read then pays the NAND read. The 7 writes before it stay cached.
 * - "fillfin": as "fill", but a Finish follows the filling write at once.
 *   The zone is Full already, and the Finish waits for the program.
 * - "zrwaend": as "fill", with a ZRWA of the whole zone. A write that ends
 *   at the capacity leaves the zone open, so it programs nothing. Then 20
 *   rewrites alternate between two LPNs: the 8-entry cache holds both, so
 *   it never fills and programs nothing.
 * - "overrun": one write cache, and one-page writes that alternate
 *   between zones 0 and 1. Each eviction pads a whole NAND page for 4 KiB,
 *   so the 128 pages of a zone's blocks run out at 512 KiB written. The
 *   flushes after that count page-overruns: (160 - 128) for zone 0 and
 *   (159 - 128) for zone 1, whose last page stays cached until a Finish
 *   adds one more. Every write still reads back. The sequential "fill"
 *   ends with page-overruns 0.
 * - "tlcfill": TLC, so a block of 64 pages ends inside a wordline of 3. A
 *   sequential fill of zone 0 still places every page: page-overruns 0.
 * - "lostfill": as "fill", 7 pages, then a controller reset drops a Reset
 *   before the FTL thread runs it. The first write of the new generation
 *   fills nothing, so it programs nothing.
 */
void femu_test_zns_finish_flush(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    bool host = !strcmp(data, "host");
    bool ctlr = !strcmp(data, "ctlr");
    bool late = !strcmp(data, "late");
    bool lost = !strcmp(data, "lostreset");
    bool rd = !strcmp(data, "lateread");
    bool five = !strcmp(data, "latefive") || rd;
    bool two = !strcmp(data, "twogen");
    bool refin = !strcmp(data, "refinish");
    bool held = !strcmp(data, "heldreset");
    bool fillfin = !strcmp(data, "fillfin");
    bool zrwaend = !strcmp(data, "zrwaend");
    bool lostfill = !strcmp(data, "lostfill");
    bool overrun = !strcmp(data, "overrun");
    bool tlcfill = !strcmp(data, "tlcfill");
    bool fill = !strcmp(data, "fill") || fillfin;
    uint8_t report[192];
    uint64_t buf, page, zone1;
    int64_t ms;
    NvmeCmd cmd;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    page = guest_alloc(alloc, 4096);
    femu_zone_report(&c, page, report);
    zone1 = ldq_le_p(report + 128 + 16);
    femu_zns_ms(&c, NVME_CMD_READ, zone1, buf);
    qtest_memset(qts, buf, 0x6b, FEMU_DATA_SIZE);

    if (lost) {
        g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 0, buf)), ==,
                        NVME_SUCCESS);
        femu_zns_ftl_hold(qts, true);
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = NVME_CMD_ZONE_MGMT_SEND;
        cmd.nsid = cpu_to_le32(1);
        cmd.cdw13 = cpu_to_le32(NVME_ZONE_ACTION_RESET);
        femu_submit(&c, &c.io, &cmd);
        g_usleep(300 * 1000);
        femu_disable(&c);
        femu_zns_ftl_hold(qts, false);
        memset(&c, 0, sizeof(c));
        femu_enable_csi(&c, &femu->dev, alloc);
        femu_create_io_queues(&c);
        g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 0, buf)), ==,
                        NVME_SUCCESS);
        g_assert_cmpint(femu_zone_action(&c, 0, NVME_ZONE_ACTION_RESET), ==,
                        NVME_SUCCESS);
    }
    if (two) {
        uint16_t fin_cid = 0;
        int64_t start = 0;

        /* an open zone, so each Reset starts a generation */
        g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 0, buf)), ==,
                        NVME_SUCCESS);
        femu_zns_ftl_hold(qts, true);
        for (int g = 0; g < 2; g++) {
            NvmeRwCmd rw = { 0 };

            memset(&cmd, 0, sizeof(cmd));
            cmd.opcode = NVME_CMD_ZONE_MGMT_SEND;
            cmd.nsid = cpu_to_le32(1);
            cmd.cdw13 = cpu_to_le32(NVME_ZONE_ACTION_RESET);
            femu_submit(&c, &c.io, &cmd);
            rw.opcode = NVME_CMD_WRITE;
            rw.nsid = cpu_to_le32(1);
            rw.dptr.prp1 = cpu_to_le64(buf);
            rw.nlb = cpu_to_le16(FEMU_DATA_SIZE / c.lba_size - 1);
            femu_submit(&c, &c.io, (NvmeCmd *)&rw);
            cmd.cdw13 = cpu_to_le32(NVME_ZONE_ACTION_FINISH);
            if (!g) {
                fin_cid = c.cid;
                start = g_get_monotonic_time();
            }
            femu_submit(&c, &c.io, &cmd);
            /* the poller takes each command before the next one */
            g_usleep(20 * 1000);
        }
        g_usleep(30 * 1000);
        femu_zns_ftl_hold(qts, false);
        ms = -1;
        for (int i = 0; i < 6; i++) {
            uint16_t got;

            g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)),
                            ==, NVME_SUCCESS);
            if (got == fin_cid) {
                ms = (g_get_monotonic_time() - start) / 1000;
            }
        }
        g_test_message("finish %" PRId64 " ms", ms);
        g_assert_cmpint(ms, >=, 190);
        guest_free(alloc, page);
        guest_free(alloc, buf);
        femu_queue_free(&c, &c.io);
        femu_disable(&c);
        /* zone 0 is Full now: the next test needs a new device */
        qos_invalidate_command_line();
        return;
    }
    if (tlcfill) {
        uint64_t lpb = FEMU_DATA_SIZE / c.lba_size;
        uint64_t zsze = ldq_le_p(report + 128 + 16);
        QDict *rsp;
        QDict *ns;

        for (uint64_t lba = 0; lba < zsze; lba += lpb) {
            g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, lba, buf)),
                            ==, NVME_SUCCESS);
        }
        femu_zone_report(&c, page, report);
        g_assert_cmpint(femu_zr_state(report, 0), ==, NVME_ZONE_STATE_FULL);
        ns = femu_query_ns(qts, "'kind':'zones','limit':1", &rsp);
        g_assert_cmpint(qdict_get_int(ns, "page-overruns"), ==, 0);
        qobject_unref(rsp);
        guest_free(alloc, page);
        guest_free(alloc, buf);
        femu_queue_free(&c, &c.io);
        femu_disable(&c);
        qos_invalidate_command_line();
        return;
    }
    if (overrun) {
        uint64_t lpb = FEMU_DATA_SIZE / c.lba_size;
        uint64_t zsze = ldq_le_p(report + 128 + 16);
        QDict *rsp;
        QDict *ns;

        for (int i = 0; i < 160; i++) {
            qtest_memset(qts, buf, i & 0xff, FEMU_DATA_SIZE);
            g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, i * lpb,
                                            buf)), ==, NVME_SUCCESS);
            g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE,
                                            zsze + i * lpb, buf)), ==,
                            NVME_SUCCESS);
        }
        ns = femu_query_ns(qts, "'kind':'zones','limit':1", &rsp);
        g_test_message("page-overruns %" PRId64,
                       qdict_get_int(ns, "page-overruns"));
        g_assert_cmpint(qdict_get_int(ns, "page-overruns"), ==, 63);
        qobject_unref(rsp);
        g_assert_cmpint(femu_zone_action(&c, zsze, NVME_ZONE_ACTION_FINISH),
                        ==, NVME_SUCCESS);
        ns = femu_query_ns(qts, "'kind':'zones','limit':1", &rsp);
        g_assert_cmpint(qdict_get_int(ns, "page-overruns"), ==, 64);
        qobject_unref(rsp);
        for (int i = 0; i < 160; i += 31) {
            g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_READ, i * lpb,
                                            buf)), ==, NVME_SUCCESS);
            g_assert_cmphex(qtest_readb(qts, buf), ==, i & 0xff);
        }
        guest_free(alloc, page);
        guest_free(alloc, buf);
        femu_queue_free(&c, &c.io);
        femu_disable(&c);
        qos_invalidate_command_line();
        return;
    }
    if (lostfill) {
        for (int i = 0; i < 7; i++) {
            femu_zns_ms(&c, NVME_CMD_WRITE,
                        i * (FEMU_DATA_SIZE / c.lba_size), buf);
        }
        femu_zns_ftl_hold(qts, true);
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = NVME_CMD_ZONE_MGMT_SEND;
        cmd.nsid = cpu_to_le32(1);
        cmd.cdw13 = cpu_to_le32(NVME_ZONE_ACTION_RESET);
        femu_submit(&c, &c.io, &cmd);
        g_usleep(300 * 1000);
        femu_disable(&c);
        femu_zns_ftl_hold(qts, false);
        memset(&c, 0, sizeof(c));
        femu_enable_csi(&c, &femu->dev, alloc);
        femu_create_io_queues(&c);
        ms = femu_zns_ms(&c, NVME_CMD_WRITE, 0, buf);
        g_test_message("write %" PRId64 " ms", ms);
        g_assert_cmpint(ms, <, 100);
        guest_free(alloc, page);
        guest_free(alloc, buf);
        femu_queue_free(&c, &c.io);
        femu_disable(&c);
        qos_invalidate_command_line();
        return;
    }
    if (zrwaend) {
        uint32_t open = NVME_ZONE_ACTION_OPEN | (NVME_ZSFLAG_ZRWA_ALLOC << 8);

        g_assert_cmpint(femu_zone_action(&c, 0, open), ==, NVME_SUCCESS);
        for (int i = 0; i < 3; i++) {
            ms = femu_zns_ms(&c, NVME_CMD_WRITE,
                             56, buf);
            g_test_message("overwrite %d: %" PRId64 " ms", i, ms);
            g_assert_cmpint(ms, <, 100);
        }
        for (int i = 0; i < 20; i++) {
            ms = femu_zns_ms(&c, NVME_CMD_WRITE, i % 2 ? 56 : 48, buf);
            g_assert_cmpint(ms, <, 100);
        }
        femu_zone_report(&c, page, report);
        g_assert_cmpint(femu_zr_state(report, 0), ==,
                        NVME_ZONE_STATE_EXPLICITLY_OPEN);
        g_assert_cmpuint(ldq_le_p(report + 64 + 24), ==, 0);
        guest_free(alloc, page);
        guest_free(alloc, buf);
        femu_queue_free(&c, &c.io);
        femu_disable(&c);
        qos_invalidate_command_line();
        return;
    }
    if (fillfin) {
        NvmeRwCmd rw = { 0 };
        uint16_t fin_cid;
        int64_t start;

        for (int i = 0; i < 7; i++) {
            femu_zns_ms(&c, NVME_CMD_WRITE,
                        i * (FEMU_DATA_SIZE / c.lba_size), buf);
        }
        rw.opcode = NVME_CMD_WRITE;
        rw.nsid = cpu_to_le32(1);
        rw.dptr.prp1 = cpu_to_le64(buf);
        rw.slba = cpu_to_le64(7 * (FEMU_DATA_SIZE / c.lba_size));
        rw.nlb = cpu_to_le16(FEMU_DATA_SIZE / c.lba_size - 1);
        start = g_get_monotonic_time();
        femu_submit(&c, &c.io, (NvmeCmd *)&rw);
        /* the poller makes the zone Full before it takes the Finish */
        g_usleep(20 * 1000);
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = NVME_CMD_ZONE_MGMT_SEND;
        cmd.nsid = cpu_to_le32(1);
        cmd.cdw13 = cpu_to_le32(NVME_ZONE_ACTION_FINISH);
        fin_cid = c.cid;
        femu_submit(&c, &c.io, &cmd);
        ms = -1;
        for (int i = 0; i < 2; i++) {
            uint16_t got;

            g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)),
                            ==, NVME_SUCCESS);
            if (got == fin_cid) {
                ms = (g_get_monotonic_time() - start) / 1000;
            }
        }
        g_test_message("finish %" PRId64 " ms", ms);
        g_assert_cmpint(ms, >=, 190);
        guest_free(alloc, page);
        guest_free(alloc, buf);
        femu_queue_free(&c, &c.io);
        femu_disable(&c);
        qos_invalidate_command_line();
        return;
    }
    if (fill) {
        for (int i = 0; i < 8; i++) {
            ms = femu_zns_ms(&c, NVME_CMD_WRITE,
                             i * (FEMU_DATA_SIZE / c.lba_size), buf);
            g_test_message("write %d: %" PRId64 " ms", i, ms);
            if (i < 7) {
                g_assert_cmpint(ms, <, 100);
            } else {
                g_assert_cmpint(ms, >=, 190);
            }
        }
        femu_zone_report(&c, page, report);
        g_assert_cmpint(femu_zr_state(report, 0), ==, NVME_ZONE_STATE_FULL);
        ms = femu_zns_ms(&c, NVME_CMD_READ, 0, buf);
        g_test_message("read %" PRId64 " ms", ms);
        g_assert_cmpint(ms, >=, 95);
        g_assert_cmphex(qtest_readb(qts, buf), ==, 0x6b);
        {
            QDict *rsp;
            QDict *ns = femu_query_ns(qts, "'kind':'zones','limit':1", &rsp);

            g_assert_cmpint(qdict_get_int(ns, "page-overruns"), ==, 0);
            qobject_unref(rsp);
        }
        guest_free(alloc, page);
        guest_free(alloc, buf);
        femu_queue_free(&c, &c.io);
        femu_disable(&c);
        qos_invalidate_command_line();
        return;
    }
    if (five) {
        uint16_t fin_cid;
        int64_t start;

        femu_zns_ftl_hold(qts, true);
        for (int i = 0; i < 5; i++) {
            NvmeRwCmd rw = { 0 };

            rw.opcode = NVME_CMD_WRITE;
            rw.nsid = cpu_to_le32(1);
            rw.dptr.prp1 = cpu_to_le64(buf);
            rw.slba = cpu_to_le64(i * (FEMU_DATA_SIZE / c.lba_size));
            rw.nlb = cpu_to_le16(FEMU_DATA_SIZE / c.lba_size - 1);
            femu_submit(&c, &c.io, (NvmeCmd *)&rw);
            if (rd && i < 4) {
                rw.opcode = NVME_CMD_READ;
                rw.slba = cpu_to_le64(zone1);
                femu_submit(&c, &c.io, (NvmeCmd *)&rw);
            }
        }
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = NVME_CMD_ZONE_MGMT_SEND;
        cmd.nsid = cpu_to_le32(1);
        cmd.cdw13 = cpu_to_le32(NVME_ZONE_ACTION_FINISH);
        fin_cid = c.cid;
        start = g_get_monotonic_time();
        femu_submit(&c, &c.io, &cmd);
        g_usleep(30 * 1000);
        femu_zns_ftl_hold(qts, false);
        ms = -1;
        for (int i = 0; i < (rd ? 10 : 6); i++) {
            uint16_t got;

            g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)),
                            ==, NVME_SUCCESS);
            if (got == fin_cid) {
                ms = (g_get_monotonic_time() - start) / 1000;
            }
        }
        g_test_message("finish %" PRId64 " ms", ms);
        g_assert_cmpint(ms, >=, 190);
        g_assert_cmpint(ms, <, 500);
        guest_free(alloc, page);
        guest_free(alloc, buf);
        femu_queue_free(&c, &c.io);
        femu_disable(&c);
        /* zone 0 is Full now: the next test needs a new device */
        qos_invalidate_command_line();
        return;
    }
    if (held) {
        NvmeRwCmd rw = { 0 };
        uint16_t fin_cid;
        int64_t start;

        femu_zns_ftl_hold(qts, true);
        rw.opcode = NVME_CMD_WRITE;
        rw.nsid = cpu_to_le32(1);
        rw.dptr.prp1 = cpu_to_le64(buf);
        rw.nlb = cpu_to_le16(FEMU_DATA_SIZE / c.lba_size - 1);
        femu_submit(&c, &c.io, (NvmeCmd *)&rw);
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = NVME_CMD_ZONE_MGMT_SEND;
        cmd.nsid = cpu_to_le32(1);
        cmd.cdw13 = cpu_to_le32(NVME_ZONE_ACTION_FINISH);
        fin_cid = c.cid;
        start = g_get_monotonic_time();
        femu_submit(&c, &c.io, &cmd);
        cmd.cdw13 = cpu_to_le32(NVME_ZONE_ACTION_RESET);
        femu_submit(&c, &c.io, &cmd);
        g_usleep(30 * 1000);
        femu_zns_ftl_hold(qts, false);
        ms = -1;
        for (int i = 0; i < 3; i++) {
            uint16_t got;

            g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)),
                            ==, NVME_SUCCESS);
            if (got == fin_cid) {
                ms = (g_get_monotonic_time() - start) / 1000;
            }
        }
        g_test_message("finish %" PRId64 " ms", ms);
        g_assert_cmpint(ms, >=, 190);
        guest_free(alloc, page);
        guest_free(alloc, buf);
        femu_queue_free(&c, &c.io);
        femu_disable(&c);
        /* zone 0 is Full now: the next test needs a new device */
        qos_invalidate_command_line();
        return;
    }
    if (late) {
        NvmeRwCmd rw = { 0 };
        int64_t start;

        femu_zns_ftl_hold(qts, true);
        rw.opcode = NVME_CMD_WRITE;
        rw.nsid = cpu_to_le32(1);
        rw.dptr.prp1 = cpu_to_le64(buf);
        rw.nlb = cpu_to_le16(FEMU_DATA_SIZE / c.lba_size - 1);
        femu_submit(&c, &c.io, (NvmeCmd *)&rw);
        g_usleep(150 * 1000);
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = NVME_CMD_ZONE_MGMT_SEND;
        cmd.nsid = cpu_to_le32(1);
        cmd.cdw13 = cpu_to_le32(NVME_ZONE_ACTION_FINISH);
        start = g_get_monotonic_time();
        femu_submit(&c, &c.io, &cmd);
        g_usleep(30 * 1000);
        femu_zns_ftl_hold(qts, false);
        g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, NULL, NULL)), ==,
                        NVME_SUCCESS);
        g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, NULL, NULL)), ==,
                        NVME_SUCCESS);
        ms = (g_get_monotonic_time() - start) / 1000;
        g_test_message("finish %" PRId64 " ms", ms);
        g_assert_cmpint(ms, >=, 190);
    } else {
        ms = femu_zns_ms(&c, NVME_CMD_WRITE, 0, buf);
        g_test_message("write %" PRId64 " ms", ms);
        g_assert_cmpint(ms, <, 100);
    }

    if (host || lost) {
        ms = femu_zns_ms(&c, NVME_CMD_ZONE_MGMT_SEND, 0, buf);
        g_test_message("finish %" PRId64 " ms", ms);
        g_assert_cmpint(ms, >=, 190);
    } else if (late) {
        /* the Finish is done */
    } else if (ctlr || refin) {
        /* FZR at the tick 1 s after the write, the finish 1 s later */
        for (int i = 0; i < 4; i++) {
            qtest_clock_step(qts, 1000LL * SCALE_MS);
        }
        if (refin) {
            ms = femu_zns_ms(&c, NVME_CMD_ZONE_MGMT_SEND, 0, buf);
            g_test_message("finish %" PRId64 " ms", ms);
            g_assert_cmpint(ms, >=, 150);
        }
    } else {
        femu_zns_ftl_hold(qts, true);
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = NVME_CMD_ZONE_MGMT_SEND;
        cmd.nsid = cpu_to_le32(1);
        cmd.cdw13 = cpu_to_le32(NVME_ZONE_ACTION_FINISH);
        femu_submit(&c, &c.io, &cmd);
        /* the poller makes the zone Full; the FTL thread never sees it */
        g_usleep(300 * 1000);
        femu_disable(&c);
        femu_zns_ftl_hold(qts, false);
        memset(&c, 0, sizeof(c));
        femu_enable_csi(&c, &femu->dev, alloc);
        femu_create_io_queues(&c);
    }
    if (!host && !late && !lost) {
        /* an I/O command: the FTL thread starts the program now */
        femu_zone_report(&c, page, report);
        g_assert_cmpint(femu_zr_state(report, 0), ==, NVME_ZONE_STATE_FULL);
        g_assert_cmphex(femu_zr_za(report, 0) & NVME_ZA_FINISHED_BY_CTLR, ==,
                        ctlr || refin ? NVME_ZA_FINISHED_BY_CTLR : 0);
    }

    ms = femu_zns_ms(&c, NVME_CMD_READ, 0, buf);
    g_test_message("read %" PRId64 " ms", ms);
    /* the rest of the 200 ms program, then the 100 ms read */
    g_assert_cmpint(ms, >=, ctlr ? 250 : 95);
    g_assert_cmphex(qtest_readb(qts, buf), ==, 0x6b);

    guest_free(alloc, page);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    /* zone 0 is Full now: the next test needs a new device */
    qos_invalidate_command_line();
}

/*
 * ZNS 1.4, 5.5 and 5.6, with zns_fzr_sec=2 and zns_frl_sec=3. Zone 0 is
 * written and left open: at the first check 2 s or more after its write
 * (checks run once a second) it gets Finish Zone Recommended, with FZRTL 00b,
 * a Zone Descriptor Changed notice and an
 * entry in the Changed Zone List. 3 s later the controller finishes it
 * (a Zone Active Excursion) and sets ZFC. Zone 1, which the host finishes
 * at once, gets neither. Identify reports ZAE and FRL 3.
 */
void femu_test_zns_fzr(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint8_t report[192];
    uint64_t buf, page, zone1;
    uint32_t result;
    uint16_t want, got;
    NvmeCmd cmd;

    /* a zoned host enables every command set, so the zoned log answers */
    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    page = guest_alloc(alloc, 4096);
    qtest_memset(qts, buf, 0x5a, FEMU_DATA_SIZE);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_IDENTIFY;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(page);
    cmd.cdw10 = cpu_to_le32(NVME_ID_CNS_CS_NS);
    cmd.cdw11 = cpu_to_le32(FEMU_CSI_ZONED << 24);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readw(qts, page) & 0x2, ==, 0x2);    /* ZOC.ZAE */
    g_assert_cmpuint(qtest_readl(qts, page + 16), ==, 3);       /* FRL */

    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_ASYNCHRONOUS_EVENT_CONF,
                                             false, 0, 1u << 27, NULL)), ==,
                    NVME_SUCCESS);
    femu_zone_report(&c, page, report);
    zone1 = ldq_le_p(report + 128 + 16);

    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 0, buf)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, zone1, buf)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_zone_action(&c, zone1, NVME_ZONE_ACTION_FINISH), ==,
                    NVME_SUCCESS);
    want = femu_aer(&c);

    qtest_clock_step(qts, 1100LL * SCALE_MS);
    femu_zone_report(&c, page, report);
    g_assert_cmphex(femu_zr_za(report, 0) & NVME_ZA_FINISH_RECOMMENDED, ==, 0);
    g_assert_false(femu_cq_ready(&c, &c.admin));

    /* the check runs once a second, so the tick at 3 s sets it */
    qtest_clock_step(qts, 2000LL * SCALE_MS);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.admin, &got, &result)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(got, ==, want);
    g_assert_cmphex(result & 0xffffff, ==, 0xbfef02);
    femu_zone_report(&c, page, report);
    g_assert_cmpint(femu_zr_state(report, 0), ==,
                    NVME_ZONE_STATE_IMPLICITLY_OPEN);
    g_assert_cmphex(femu_zr_za(report, 0) & NVME_ZA_FINISH_RECOMMENDED, !=, 0);
    g_assert_cmphex(report[64 + 3] & 0x3, ==, 0);              /* FZRTL: FRL */
    g_assert_cmpint(femu_zr_state(report, 1), ==, NVME_ZONE_STATE_FULL);
    g_assert_cmphex(femu_zr_za(report, 1) & (NVME_ZA_FINISH_RECOMMENDED |
                                             NVME_ZA_FINISHED_BY_CTLR), ==, 0);

    /* the list names zone 0 only; reading it lets the next notice through */
    g_assert_cmpint(femu_log_cmd(&c, 1, FEMU_LOG_CHANGED_ZONE_LIST,
                                 FEMU_CSI_ZONED << 24, page, 512), ==,
                    NVME_SUCCESS);
    g_assert_cmpuint(qtest_readw(qts, page), ==, 1);
    g_assert_cmpuint(qtest_readq(qts, page + 8), ==, 0);
    want = femu_aer(&c);

    qtest_clock_step(qts, 3000LL * SCALE_MS);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.admin, &got, &result)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(got, ==, want);
    femu_zone_report(&c, page, report);
    g_assert_cmpint(femu_zr_state(report, 0), ==, NVME_ZONE_STATE_FULL);
    g_assert_cmphex(femu_zr_za(report, 0) & (NVME_ZA_FINISH_RECOMMENDED |
                                             NVME_ZA_FINISHED_BY_CTLR), ==,
                    NVME_ZA_FINISHED_BY_CTLR);

    /* a reset ends the story: no attribute is left */
    g_assert_cmpint(femu_zone_action(&c, 0, FEMU_ZONE_ACTION_RESET), ==,
                    NVME_SUCCESS);
    femu_zone_report(&c, page, report);
    g_assert_cmpint(femu_zr_state(report, 0), ==, NVME_ZONE_STATE_EMPTY);
    g_assert_cmphex(femu_zr_za(report, 0), ==, 0);

    guest_free(alloc, page);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * Cancellation and re-aging, with zns_fzr_sec=2 and zns_frl_sec=3. A host
 * Finish clears FZR with no ZFC. A reset and a new write restart the clock.
 * A zone already in the Changed Zone List from its FZR still raises a
 * notice for its excursion, once the host enables notices.
 */
void femu_test_zns_fzr_cancel(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint8_t report[192];
    uint64_t buf, page, zone1;
    uint32_t result;
    uint16_t want, got;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    page = guest_alloc(alloc, 4096);
    femu_zone_report(&c, page, report);
    zone1 = ldq_le_p(report + 128 + 16);

    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 0, buf)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, zone1, buf)), ==,
                    NVME_SUCCESS);
    qtest_clock_step(qts, 3100LL * SCALE_MS);
    femu_zone_report(&c, page, report);
    g_assert_cmphex(femu_zr_za(report, 0) & NVME_ZA_FINISH_RECOMMENDED, !=, 0);
    g_assert_cmphex(femu_zr_za(report, 1) & NVME_ZA_FINISH_RECOMMENDED, !=, 0);

    /* the host's own finish clears FZR, and ZFC stays clear */
    g_assert_cmpint(femu_zone_action(&c, zone1, NVME_ZONE_ACTION_FINISH), ==,
                    NVME_SUCCESS);
    femu_zone_report(&c, page, report);
    g_assert_cmpint(femu_zr_state(report, 1), ==, NVME_ZONE_STATE_FULL);
    g_assert_cmphex(femu_zr_za(report, 1) & (NVME_ZA_FINISH_RECOMMENDED |
                                             NVME_ZA_FINISHED_BY_CTLR), ==, 0);

    /* a reset and a new write start a full interval again */
    g_assert_cmpint(femu_zone_action(&c, zone1, FEMU_ZONE_ACTION_RESET), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, zone1, buf)), ==,
                    NVME_SUCCESS);
    qtest_clock_step(qts, 1000LL * SCALE_MS);
    femu_zone_report(&c, page, report);
    g_assert_cmphex(femu_zr_za(report, 1) & NVME_ZA_FINISH_RECOMMENDED, ==, 0);

    /* zone 0 is listed already; its excursion must still raise a notice */
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_ASYNCHRONOUS_EVENT_CONF,
                                             false, 0, 1u << 27, NULL)), ==,
                    NVME_SUCCESS);
    want = femu_aer(&c);
    qtest_clock_step(qts, 2000LL * SCALE_MS);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.admin, &got, &result)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(got, ==, want);
    g_assert_cmphex(result & 0xffffff, ==, 0xbfef02);
    femu_zone_report(&c, page, report);
    g_assert_cmpint(femu_zr_state(report, 0), ==, NVME_ZONE_STATE_FULL);
    g_assert_cmphex(femu_zr_za(report, 0) & NVME_ZA_FINISHED_BY_CTLR, !=, 0);

    guest_free(alloc, page);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * A Reset of a zone with FZR set clears it, and a new write starts a full
 * interval: no FZR at the checks 1 s and 2 s after it, FZR at the check
 * 3 s after it (the first one 2 s or more after the write).
 */
void femu_test_zns_fzr_reset(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint8_t report[192];
    uint64_t buf, page;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    page = guest_alloc(alloc, 4096);
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 0, buf)), ==,
                    NVME_SUCCESS);
    qtest_clock_step(qts, 3100LL * SCALE_MS);
    femu_zone_report(&c, page, report);
    g_assert_cmphex(femu_zr_za(report, 0) & NVME_ZA_FINISH_RECOMMENDED, !=, 0);

    g_assert_cmpint(femu_zone_action(&c, 0, FEMU_ZONE_ACTION_RESET), ==,
                    NVME_SUCCESS);
    femu_zone_report(&c, page, report);
    g_assert_cmpint(femu_zr_state(report, 0), ==, NVME_ZONE_STATE_EMPTY);
    g_assert_cmphex(femu_zr_za(report, 0), ==, 0);
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 0, buf)), ==,
                    NVME_SUCCESS);
    for (int k = 0; k < 2; k++) {
        qtest_clock_step(qts, 1000LL * SCALE_MS);
        femu_zone_report(&c, page, report);
        g_assert_cmphex(femu_zr_za(report, 0) & NVME_ZA_FINISH_RECOMMENDED,
                        ==, 0);
    }
    qtest_clock_step(qts, 1000LL * SCALE_MS);
    femu_zone_report(&c, page, report);
    g_assert_cmphex(femu_zr_za(report, 0) & NVME_ZA_FINISH_RECOMMENDED, !=, 0);

    guest_free(alloc, page);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/* FZR with no FRL: the recommendation stays and the zone is never finished */
void femu_test_zns_fzr_only(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint8_t report[192];
    uint64_t buf, page;
    NvmeCmd cmd;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    page = guest_alloc(alloc, 4096);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_IDENTIFY;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(page);
    cmd.cdw10 = cpu_to_le32(NVME_ID_CNS_CS_NS);
    cmd.cdw11 = cpu_to_le32(FEMU_CSI_ZONED << 24);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readw(qts, page) & 0x2, ==, 0);
    g_assert_cmpuint(qtest_readl(qts, page + 16), ==, 0);

    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 0, buf)), ==,
                    NVME_SUCCESS);
    qtest_clock_step(qts, 3100LL * SCALE_MS);
    femu_zone_report(&c, page, report);
    g_assert_cmphex(femu_zr_za(report, 0) & NVME_ZA_FINISH_RECOMMENDED, !=, 0);
    qtest_clock_step(qts, 10000LL * SCALE_MS);
    femu_zone_report(&c, page, report);
    g_assert_cmpint(femu_zr_state(report, 0), ==,
                    NVME_ZONE_STATE_IMPLICITLY_OPEN);
    g_assert_cmphex(femu_zr_za(report, 0) & NVME_ZA_FINISHED_BY_CTLR, ==, 0);

    guest_free(alloc, page);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/* without zns_fzr_sec an open zone keeps no attribute however old it is */
void femu_test_zns_fzr_off(void *obj, void *data,
                           QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint8_t report[192];
    uint64_t buf, page;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    page = guest_alloc(alloc, 4096);
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 0, buf)), ==,
                    NVME_SUCCESS);
    qtest_clock_step(qts, 10000LL * SCALE_MS);
    femu_zone_report(&c, page, report);
    g_assert_cmpint(femu_zr_state(report, 0), ==,
                    NVME_ZONE_STATE_IMPLICITLY_OPEN);
    g_assert_cmphex(femu_zr_za(report, 0), ==, 0);
    guest_free(alloc, page);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/* an excursion limit with no recommendation to follow is refused */
void femu_test_zns_fzr_refused(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QDict *rsp;

    rsp = qtest_qmp(femu->dev.bus->qts,
                    "{'execute':'device_add','arguments':{'driver':'femu',"
                    "'id':'zns-frl','addr':'5','devsz_mb':32,'femu_mode':3,"
                    "'zns_frl_sec':3}}");
    g_assert_true(qdict_haskey(rsp, "error"));
    g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                          "desc"), "zns_frl_sec needs"));
    qobject_unref(rsp);
    qos_invalidate_command_line();
}

/* Identify Namespace for the zoned command set: ZOC, RRL and FRL */
static void femu_zns_id_limits(FemuCtrlState *c, QTestState *qts,
                               uint64_t page, uint16_t *zoc, uint32_t *rrl,
                               uint32_t *frl)
{
    NvmeCmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_IDENTIFY;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(page);
    cmd.cdw10 = cpu_to_le32(NVME_ID_CNS_CS_NS);
    cmd.cdw11 = cpu_to_le32(FEMU_CSI_ZONED << 24);
    g_assert_cmpint(femu_admin(c, &cmd), ==, NVME_SUCCESS);
    *zoc = qtest_readw(qts, page);
    *rrl = qtest_readl(qts, page + 12);
    *frl = qtest_readl(qts, page + 16);
}

/* the Changed Zone List: the count, and the first entry */
static uint16_t femu_changed_zones_rae(FemuCtrlState *c, QTestState *qts,
                                       uint64_t page, uint64_t *first,
                                       bool rae)
{
    g_assert_cmpint(femu_log_cmd(c, 1, FEMU_LOG_CHANGED_ZONE_LIST |
                                 (rae ? FEMU_LOG_RAE : 0),
                                 FEMU_CSI_ZONED << 24, page, 512), ==,
                    NVME_SUCCESS);
    *first = qtest_readq(qts, page + 8);
    return qtest_readw(qts, page);
}

static uint16_t femu_changed_zones(FemuCtrlState *c, QTestState *qts,
                                   uint64_t page, uint64_t *first)
{
    return femu_changed_zones_rae(c, qts, page, first, false);
}

/*
 * ZNS 1.4, 5.4, with zns_rzr_sec=2 and zns_rrl_sec=4. Zone 0 is written and
 * finished by the host, which raises no event. At the first check 2 s or
 * more after it became Full it gets Reset Zone Recommended, with RZRTL 00b,
 * a Zone Descriptor Changed notice and an entry in the Changed Zone List.
 * 4 s later the controller refreshes the zone itself: RZR clears with
 * another notice and the zone stays Full, and 2 s after that RZR comes
 * back. Zone 1 stays open and gets nothing, as zns_fzr_sec is 0. Identify
 * reports RRL 4, with FRL and ZOC.ZAE clear.
 *
 * The checks run once a second, at a phase the test does not know. So the
 * clock moves 1 s at a time, one check per step, and the test asserts the
 * steps between the changes.
 */
void femu_test_zns_rzr(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint8_t report[192];
    uint64_t buf, page, zone1, first;
    uint32_t result, rrl, frl;
    uint16_t want, got, zoc;
    int set = -1, clear = -1, again = -1;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    page = guest_alloc(alloc, 4096);
    qtest_memset(qts, buf, 0x5a, FEMU_DATA_SIZE);

    femu_zns_id_limits(&c, qts, page, &zoc, &rrl, &frl);
    g_assert_cmphex(zoc & 0x2, ==, 0);                          /* ZOC.ZAE */
    g_assert_cmpuint(rrl, ==, 4);
    g_assert_cmpuint(frl, ==, 0);

    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_ASYNCHRONOUS_EVENT_CONF,
                                             false, 0, 1u << 27, NULL)), ==,
                    NVME_SUCCESS);
    femu_zone_report(&c, page, report);
    zone1 = ldq_le_p(report + 128 + 16);

    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 0, buf)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_zone_action(&c, 0, NVME_ZONE_ACTION_FINISH), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, zone1, buf)), ==,
                    NVME_SUCCESS);
    want = femu_aer(&c);

    for (int k = 1; k <= 12 && again < 0; k++) {
        bool rzr, changed;

        qtest_clock_step(qts, 1000LL * SCALE_MS);
        femu_zone_report(&c, page, report);
        g_assert_cmpint(femu_zr_state(report, 0), ==, NVME_ZONE_STATE_FULL);
        g_assert_cmphex(femu_zr_za(report, 0) & ~NVME_ZA_RESET_RECOMMENDED,
                        ==, 0);
        g_assert_cmphex(report[64 + 3] & 0xc, ==, 0);          /* RZRTL: RRL */
        g_assert_cmpint(femu_zr_state(report, 1), ==,
                        NVME_ZONE_STATE_IMPLICITLY_OPEN);
        g_assert_cmphex(femu_zr_za(report, 1), ==, 0);

        rzr = femu_zr_za(report, 0) & NVME_ZA_RESET_RECOMMENDED;
        changed = set < 0 ? rzr : clear < 0 ? !rzr : rzr;
        if (!changed) {
            g_assert_false(femu_cq_ready(&c, &c.admin));
            continue;
        }
        g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.admin, &got, &result)),
                        ==, NVME_SUCCESS);
        g_assert_cmpint(got, ==, want);
        g_assert_cmphex(result & 0xffffff, ==, 0xbfef02);
        if (set < 0) {
            set = k;
        } else if (clear < 0) {
            clear = k;
        } else {
            again = k;
            break;
        }
        /* the list names zone 0 only; reading it lets the next notice in */
        g_assert_cmpuint(femu_changed_zones(&c, qts, page, &first), ==, 1);
        g_assert_cmpuint(first, ==, 0);
        want = femu_aer(&c);
    }
    g_test_message("RZR at check %d, cleared at %d, again at %d",
                   set, clear, again);
    g_assert_cmpint(set, >=, 2);
    g_assert_cmpint(set, <=, 3);
    g_assert_cmpint(clear - set, ==, 4);         /* RRL */
    g_assert_cmpint(again - clear, ==, 2);       /* the zone ages again */

    guest_free(alloc, page);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * A Reset of a zone with RZR, with zns_rzr_sec=2 and, for "rrl", also
 * zns_rrl_sec=3. Without RRL the recommendation stays on the Full zone.
 * The Reset clears it and changes neither the Changed Zone List nor the
 * notices (ZNS 1.4, Figure 43): the entry of the earlier RZR stays until
 * the host reads the list. No refresh follows at the old deadline. A
 * zone finished late by the host starts a full interval at the Finish.
 * With notices open, a Reset raises none.
 */
void femu_test_zns_rzr_reset(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    bool has_rrl = data && !strcmp(data, "rrl");
    uint8_t report[192];
    uint64_t buf, page, first;
    uint32_t rrl, frl, result;
    uint16_t zoc, want, got;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    page = guest_alloc(alloc, 4096);
    femu_zns_id_limits(&c, qts, page, &zoc, &rrl, &frl);
    g_assert_cmpuint(rrl, ==, has_rrl ? 3 : 0);
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_ASYNCHRONOUS_EVENT_CONF,
                                             false, 0, 1u << 27, NULL)), ==,
                    NVME_SUCCESS);
    want = femu_aer(&c);

    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 0, buf)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_zone_action(&c, 0, NVME_ZONE_ACTION_FINISH), ==,
                    NVME_SUCCESS);
    qtest_clock_step(qts, 3100LL * SCALE_MS);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.admin, &got, &result)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(got, ==, want);
    g_assert_cmphex(result & 0xffffff, ==, 0xbfef02);
    femu_zone_report(&c, page, report);
    g_assert_cmphex(femu_zr_za(report, 0), ==, NVME_ZA_RESET_RECOMMENDED);
    if (!has_rrl) {
        qtest_clock_step(qts, 10000LL * SCALE_MS);
        femu_zone_report(&c, page, report);
        g_assert_cmpint(femu_zr_state(report, 0), ==, NVME_ZONE_STATE_FULL);
        g_assert_cmphex(femu_zr_za(report, 0), ==, NVME_ZA_RESET_RECOMMENDED);
    }

    /* the entry is kept across the Reset; RAE keeps it for the next read */
    g_assert_cmpuint(femu_changed_zones_rae(&c, qts, page, &first, true), ==,
                     1);
    g_assert_cmpuint(first, ==, 0);
    g_assert_cmpint(femu_zone_action(&c, 0, FEMU_ZONE_ACTION_RESET), ==,
                    NVME_SUCCESS);
    femu_zone_report(&c, page, report);
    g_assert_cmpint(femu_zr_state(report, 0), ==, NVME_ZONE_STATE_EMPTY);
    g_assert_cmphex(femu_zr_za(report, 0), ==, 0);
    g_assert_cmpuint(femu_changed_zones_rae(&c, qts, page, &first, true), ==,
                     1);
    g_assert_cmpuint(first, ==, 0);
    g_assert_cmpuint(femu_changed_zones(&c, qts, page, &first), ==, 1);
    g_assert_cmpuint(femu_changed_zones(&c, qts, page, &first), ==, 0);

    /* past the deadline of the cancelled refresh: no event, no attribute */
    want = femu_aer(&c);
    qtest_clock_step(qts, 5000LL * SCALE_MS);
    g_assert_false(femu_cq_ready(&c, &c.admin));
    femu_zone_report(&c, page, report);
    g_assert_cmpint(femu_zr_state(report, 0), ==, NVME_ZONE_STATE_EMPTY);
    g_assert_cmphex(femu_zr_za(report, 0), ==, 0);

    /*
     * A write, and a host Finish 3 s later: the clock starts at the Finish,
     * so no RZR 1 s after it, RZR at the check 2 s or more after it.
     */
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 0, buf)), ==,
                    NVME_SUCCESS);
    qtest_clock_step(qts, 3000LL * SCALE_MS);
    g_assert_cmpint(femu_zone_action(&c, 0, NVME_ZONE_ACTION_FINISH), ==,
                    NVME_SUCCESS);
    qtest_clock_step(qts, 1000LL * SCALE_MS);
    femu_zone_report(&c, page, report);
    g_assert_cmphex(femu_zr_za(report, 0), ==, 0);
    g_assert_false(femu_cq_ready(&c, &c.admin));
    qtest_clock_step(qts, 2000LL * SCALE_MS);
    femu_zone_report(&c, page, report);
    g_assert_cmphex(femu_zr_za(report, 0), ==, NVME_ZA_RESET_RECOMMENDED);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.admin, &got, &result)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(got, ==, want);
    g_assert_cmphex(result & 0xffffff, ==, 0xbfef02);

    /* with the list read and notices open, a Reset raises nothing */
    g_assert_cmpuint(femu_changed_zones(&c, qts, page, &first), ==, 1);
    want = femu_aer(&c);
    g_assert_cmpint(femu_zone_action(&c, 0, FEMU_ZONE_ACTION_RESET), ==,
                    NVME_SUCCESS);
    qtest_clock_step(qts, 5000LL * SCALE_MS);
    g_assert_false(femu_cq_ready(&c, &c.admin));
    femu_zone_report(&c, page, report);
    g_assert_cmpint(femu_zr_state(report, 0), ==, NVME_ZONE_STATE_EMPTY);
    g_assert_cmphex(femu_zr_za(report, 0), ==, 0);
    g_assert_cmpuint(femu_changed_zones_rae(&c, qts, page, &first, true), ==,
                     0);

    guest_free(alloc, page);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * Each way into Full starts the RZR clock, with zns_fzr_sec=2,
 * zns_frl_sec=2, zns_rzr_sec=3 and zns_rrl_sec=2. Zone 1 fills by writes.
 * Zone 0 gets one write and FZR, then the controller finishes it and sets
 * ZFC. Each zone gets RZR 3 checks after it became Full, not after its
 * first write. On zone 0, ZFC stays through RZR, the refresh 2 checks
 * later and the next RZR, and FZR stays clear. The data still reads back.
 */
void femu_test_zns_rzr_origins(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint8_t report[192];
    uint64_t buf, page, zone1, zcap, lba;
    uint32_t per;
    int full0 = -1, rzr0 = -1, clear0 = -1, again0 = -1, rzr1 = -1;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    page = guest_alloc(alloc, 4096);
    qtest_memset(qts, buf, 0x3c, FEMU_DATA_SIZE);
    femu_zone_report(&c, page, report);
    zone1 = ldq_le_p(report + 128 + 16);
    zcap = ldq_le_p(report + 128 + 8);
    per = FEMU_DATA_SIZE / c.lba_size;

    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 0, buf)), ==,
                    NVME_SUCCESS);
    for (lba = zone1; lba < zone1 + zcap; lba += per) {
        g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, lba, buf)), ==,
                        NVME_SUCCESS);
    }
    femu_zone_report(&c, page, report);
    g_assert_cmpint(femu_zr_state(report, 1), ==, NVME_ZONE_STATE_FULL);
    g_assert_cmpint(femu_zr_state(report, 0), ==,
                    NVME_ZONE_STATE_IMPLICITLY_OPEN);

    for (int k = 1; k <= 16 && again0 < 0; k++) {
        uint8_t za0, za1;

        qtest_clock_step(qts, 1000LL * SCALE_MS);
        femu_zone_report(&c, page, report);
        za0 = femu_zr_za(report, 0);
        za1 = femu_zr_za(report, 1);
        g_assert_cmpint(femu_zr_state(report, 1), ==, NVME_ZONE_STATE_FULL);
        g_assert_cmphex(za1 & ~NVME_ZA_RESET_RECOMMENDED, ==, 0);
        if (rzr1 < 0 && (za1 & NVME_ZA_RESET_RECOMMENDED)) {
            rzr1 = k;
        }
        if (full0 < 0) {
            if (femu_zr_state(report, 0) != NVME_ZONE_STATE_FULL) {
                g_assert_cmphex(za0 & NVME_ZA_RESET_RECOMMENDED, ==, 0);
                continue;
            }
            full0 = k;
        }
        g_assert_cmpint(femu_zr_state(report, 0), ==, NVME_ZONE_STATE_FULL);
        g_assert_cmphex(za0 & ~NVME_ZA_RESET_RECOMMENDED, ==,
                        NVME_ZA_FINISHED_BY_CTLR);
        if (za0 & NVME_ZA_RESET_RECOMMENDED) {
            if (rzr0 < 0) {
                rzr0 = k;
            } else if (clear0 >= 0) {
                again0 = k;
            }
        } else if (rzr0 >= 0 && clear0 < 0) {
            clear0 = k;
        }
    }
    g_test_message("zone 1 RZR at check %d; zone 0 Full at %d, RZR at %d, "
                   "cleared at %d, again at %d",
                   rzr1, full0, rzr0, clear0, again0);
    g_assert_cmpint(rzr1, >=, 3);
    g_assert_cmpint(rzr1, <=, 4);
    /* FZR at check 2 or 3 after the write, the finish 2 checks later */
    g_assert_cmpint(full0, >=, 4);
    g_assert_cmpint(full0, <=, 5);
    g_assert_cmpint(rzr0 - full0, ==, 3);
    g_assert_cmpint(clear0 - rzr0, ==, 2);
    g_assert_cmpint(again0 - clear0, ==, 3);

    for (int z = 0; z < 2; z++) {
        g_autofree uint8_t *got = g_malloc(FEMU_DATA_SIZE);

        qtest_memset(qts, buf, 0, FEMU_DATA_SIZE);
        g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_READ,
                                        z ? zone1 + zcap - per : 0, buf)), ==,
                        NVME_SUCCESS);
        qtest_memread(qts, buf, got, FEMU_DATA_SIZE);
        for (int i = 0; i < FEMU_DATA_SIZE; i++) {
            g_assert_cmphex(got[i], ==, 0x3c);
        }
    }

    guest_free(alloc, page);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/* without zns_rzr_sec a Full zone keeps no attribute and RRL reads 0 */
void femu_test_zns_rzr_off(void *obj, void *data,
                           QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint8_t report[192];
    uint64_t buf, page;
    uint32_t rrl, frl;
    uint16_t zoc;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    page = guest_alloc(alloc, 4096);
    femu_zns_id_limits(&c, qts, page, &zoc, &rrl, &frl);
    g_assert_cmpuint(rrl, ==, 0);
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 0, buf)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_zone_action(&c, 0, NVME_ZONE_ACTION_FINISH), ==,
                    NVME_SUCCESS);
    qtest_clock_step(qts, 10000LL * SCALE_MS);
    femu_zone_report(&c, page, report);
    g_assert_cmpint(femu_zr_state(report, 0), ==, NVME_ZONE_STATE_FULL);
    g_assert_cmphex(femu_zr_za(report, 0), ==, 0);
    guest_free(alloc, page);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/* a reset limit with no recommendation to follow is refused */
void femu_test_zns_rzr_refused(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QDict *rsp;

    rsp = qtest_qmp(femu->dev.bus->qts,
                    "{'execute':'device_add','arguments':{'driver':'femu',"
                    "'id':'zns-rrl','addr':'5','devsz_mb':32,'femu_mode':3,"
                    "'zns_rrl_sec':3}}");
    g_assert_true(qdict_haskey(rsp, "error"));
    g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                          "desc"), "zns_rrl_sec needs"));
    qobject_unref(rsp);
    qos_invalidate_command_line();
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
void femu_test_zone_open_limits(void *obj, void *data,
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

#define FEMU_ZONE_ACTION_FINISH 0x02
#define FEMU_ZQ_MAX_ZONES       63      /* descriptors in a 4 KiB report */

typedef struct FemuZoneDesc {
    uint8_t zt;
    uint8_t zs;
    uint8_t za;
    uint64_t zcap;
    uint64_t zslba;
    uint64_t wp;
} FemuZoneDesc;

/* Report Zones over every zone into @zd; returns the zone count. */
static uint32_t femu_zone_report_all(FemuCtrlState *c, uint64_t buf,
                                     FemuZoneDesc *zd)
{
    QTestState *qts = c->pdev->bus->qts;
    NvmeCmd cmd = { 0 };
    uint64_t nr;

    cmd.opcode = NVME_CMD_ZONE_MGMT_RECV;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw12 = cpu_to_le32(4096 / 4 - 1);
    g_assert_cmpint(femu_io(c, &cmd), ==, NVME_SUCCESS);
    nr = qtest_readq(qts, buf);
    g_assert_cmpuint(nr, <=, FEMU_ZQ_MAX_ZONES);
    for (uint32_t i = 0; i < nr; i++) {
        uint64_t d = buf + 64 + i * 64;

        zd[i].zt = qtest_readb(qts, d);
        zd[i].zs = qtest_readb(qts, d + 1) >> 4;
        zd[i].za = qtest_readb(qts, d + 2);
        zd[i].zcap = qtest_readq(qts, d + 8);
        zd[i].zslba = qtest_readq(qts, d + 16);
        zd[i].wp = qtest_readq(qts, d + 24);
    }
    return nr;
}

static uint8_t femu_zone_state_code(const char *state)
{
    static const char *const names[16] = {
        [0x1] = "empty", [0x2] = "implicitly-open",
        [0x3] = "explicitly-open", [0x4] = "closed",
        [0xd] = "read-only", [0xe] = "full", [0xf] = "offline",
    };

    for (int i = 0; i < 16; i++) {
        if (names[i] && !strcmp(names[i], state)) {
            return i;
        }
    }
    g_assert_not_reached();
}

/*
 * Every zone through query-femu in windows of @limit: each zone comes once,
 * in order, and agrees with Report Zones; the state counts add up. The zone
 * counts of the last window are returned in @counts, indexed by state code.
 */
static void femu_query_zns_check(FemuCtrlState *c, uint64_t buf,
                                 uint32_t limit, uint32_t *counts)
{
    QTestState *qts = c->pdev->bus->qts;
    FemuZoneDesc zd[FEMU_ZQ_MAX_ZONES];
    uint32_t nr = femu_zone_report_all(c, buf, zd);
    uint32_t seen[16] = { 0 };
    uint32_t next = 0;
    uint32_t got = 0;

    do {
        g_autofree char *args = g_strdup_printf(
            "'kind':'zones','offset':%u,'limit':%u", next, limit);
        QDict *rsp;
        QDict *ns = femu_query_ns(qts, args, &rsp);
        QDict *cnt = qdict_get_qdict(ns, "zone-counts");
        QListEntry *e;

        g_assert_cmpstr(qdict_get_str(ns, "mode"), ==, "znssd");
        g_assert_cmpuint(qdict_get_int(cnt, "total"), ==, nr);
        g_assert_cmpuint(qdict_get_int(ns, "offset"), ==, next);
        counts[0x1] = qdict_get_int(cnt, "empty");
        counts[0x2] = qdict_get_int(cnt, "implicitly-open");
        counts[0x3] = qdict_get_int(cnt, "explicitly-open");
        counts[0x4] = qdict_get_int(cnt, "closed");
        counts[0xd] = qdict_get_int(cnt, "read-only");
        counts[0xe] = qdict_get_int(cnt, "full");
        counts[0xf] = qdict_get_int(cnt, "offline");
        QLIST_FOREACH_ENTRY(qdict_get_qlist(ns, "zones"), e) {
            QDict *z = qobject_to(QDict, qlist_entry_obj(e));
            uint32_t idx = qdict_get_int(z, "index");
            uint8_t zs = femu_zone_state_code(qdict_get_str(z, "state"));

            g_assert_cmpuint(idx, ==, got);
            g_assert_cmpuint(zs, ==, zd[idx].zs);
            g_assert_cmpuint(qdict_get_int(z, "start-lba"), ==,
                             zd[idx].zslba);
            g_assert_cmpuint(qdict_get_int(z, "capacity"), ==, zd[idx].zcap);
            g_assert_cmpstr(qdict_get_str(z, "type"), ==,
                            zd[idx].zt == 1 ? "conventional" : "sequential");
            g_assert_cmpint(qdict_get_bool(z, "zrwa"), ==,
                            !!(zd[idx].za & 0x8));
            if (qdict_haskey(z, "write-pointer")) {
                g_assert_cmphex(qdict_get_int(z, "write-pointer"), ==,
                                zd[idx].wp);
            } else {
                g_assert_cmphex(zd[idx].wp, ==, UINT64_MAX);
            }
            seen[zs]++;
            got++;
        }
        if (qdict_haskey(ns, "next-offset")) {
            next = qdict_get_int(ns, "next-offset");
            g_assert_cmpuint(next, ==, got);
            g_assert_cmpuint(next, <, nr);
        } else {
            next = 0;
        }
        qobject_unref(rsp);
    } while (next);
    g_assert_cmpuint(got, ==, nr);
    for (int i = 0; i < 16; i++) {
        g_assert_cmpuint(seen[i], ==, counts[i]);
    }
}

/*
 * query-femu on a zoned namespace with one conventional zone: its zones and
 * counts agree with Report Zones before and after writes, an open, a
 * finish, a close and a reset; windows and errors are checked, and queries
 * made while appends are in flight all return.
 */
void femu_test_query_zns(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint64_t rpt = guest_alloc(alloc, 4096);
    FemuZoneDesc zd[FEMU_ZQ_MAX_ZONES];
    uint32_t counts[16] = { 0 };
    uint64_t zsze;
    uint32_t nr;
    uint32_t appends;
    int64_t slowest = 0;
    QDict *rsp;
    QDict *ns;
    int i;

    /* the zone state exists before the guest enables the controller */
    ns = femu_query_ns(qts, "", &rsp);
    g_assert_cmpstr(qdict_get_str(ns, "mode"), ==, "znssd");
    g_assert_cmpuint(qdict_get_int(ns, "lba-size"), ==, 512);
    g_assert_cmpuint(qdict_get_int(ns, "max-open"), ==, 3);
    g_assert_cmpuint(qdict_get_int(ns, "max-active"), ==, 4);
    g_assert_false(qdict_haskey(ns, "zones"));
    g_assert_false(qdict_haskey(ns, "geometry"));
    g_assert_cmpuint(qdict_get_int(qdict_get_qdict(ns, "zone-counts"),
                                   "empty"), ==,
                     qdict_get_int(qdict_get_qdict(ns, "zone-counts"),
                                   "total"));
    qobject_unref(rsp);

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x3c, 4096);

    nr = femu_zone_report_all(&c, rpt, zd);
    g_assert_cmpuint(nr, >=, 6);
    zsze = zd[1].zslba - zd[0].zslba;
    ns = femu_query_ns(qts, "", &rsp);
    g_assert_cmpuint(qdict_get_int(ns, "zone-size"), ==, zsze);
    g_assert_cmpuint(qdict_get_int(ns, "zone-capacity"), ==, zd[1].zcap);
    qobject_unref(rsp);
    femu_query_zns_check(&c, rpt, 3, counts);
    femu_query_zns_check(&c, rpt, 4096, counts);
    g_assert_cmpuint(counts[0x1], ==, nr);

    /* zone 0 is conventional: a write moves no write pointer */
    g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE, 0, buf), ==, NVME_SUCCESS);
    /* 1 implicitly open, 2 explicitly open, 3 full, 4 closed */
    g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE, zsze, buf), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_zone_action(&c, 2 * zsze, FEMU_ZONE_ACTION_OPEN), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_zone_action(&c, 3 * zsze, FEMU_ZONE_ACTION_FINISH),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(femu_rw(&c, NVME_CMD_WRITE, 4 * zsze, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_zone_action(&c, 4 * zsze, FEMU_ZONE_ACTION_CLOSE), ==,
                    NVME_SUCCESS);
    femu_query_zns_check(&c, rpt, 2, counts);
    g_assert_cmpuint(counts[0x2], ==, 1);
    g_assert_cmpuint(counts[0x3], ==, 1);
    g_assert_cmpuint(counts[0x4], ==, 1);
    g_assert_cmpuint(counts[0xe], ==, 1);
    g_assert_cmpuint(counts[0x1], ==, nr - 4);

    ns = femu_query_ns(qts, "'kind':'zones','offset':1,'limit':1", &rsp);
    {
        QDict *z = qobject_to(QDict, qlist_peek(qdict_get_qlist(ns, "zones")));

        g_assert_cmpstr(qdict_get_str(z, "state"), ==, "implicitly-open");
        g_assert_cmpuint(qdict_get_int(z, "write-pointer"), ==,
                         zsze + FEMU_DATA_SIZE / c.lba_size);
        g_assert_cmpuint(qdict_get_int(ns, "next-offset"), ==, 2);
    }
    qobject_unref(rsp);
    ns = femu_query_ns(qts, "'kind':'zones','limit':1", &rsp);
    {
        QDict *z = qobject_to(QDict, qlist_peek(qdict_get_qlist(ns, "zones")));

        g_assert_cmpstr(qdict_get_str(z, "type"), ==, "conventional");
        g_assert_false(qdict_haskey(z, "write-pointer"));
    }
    qobject_unref(rsp);
    {
        g_autofree char *last = g_strdup_printf(
            "'kind':'zones','offset':%u", nr - 1);

        ns = femu_query_ns(qts, last, &rsp);
        g_assert_cmpuint(qlist_size(qdict_get_qlist(ns, "zones")), ==, 1);
        g_assert_false(qdict_haskey(ns, "next-offset"));
        qobject_unref(rsp);
    }

    /* errors */
    {
        g_autofree char *past = g_strdup_printf(
            "'kind':'zones','offset':%u", nr);

        femu_query_fails(qts, past, "past its last zone");
    }
    femu_query_fails(qts, "'kind':'lines'", "only to bbssd");
    femu_query_fails(qts, "'kind':'zones','limit':0", "limit must be");
    femu_query_fails(qts, "'kind':'zones','limit':4097", "limit must be");
    femu_query_fails(qts, "'offset':1", "only to kind");
    femu_query_fails(qts, "'nsid':2", "not attached");

    /*
     * Queries while appends to zone 1 are in flight: every query must
     * return within a second, and every append must then complete.
     */
    appends = MIN(FEMU_QSIZE - 1,
                  (zd[1].zcap - FEMU_DATA_SIZE / c.lba_size) /
                  (FEMU_DATA_SIZE / c.lba_size));
    for (i = 0; i < appends; i++) {
        NvmeRwCmd rw;

        memset(&rw, 0, sizeof(rw));
        rw.opcode = NVME_CMD_ZONE_APPEND;
        rw.nsid = cpu_to_le32(1);
        rw.dptr.prp1 = cpu_to_le64(buf);
        rw.slba = cpu_to_le64(zsze);
        rw.nlb = cpu_to_le16(FEMU_DATA_SIZE / c.lba_size - 1);
        femu_submit(&c, &c.io, (NvmeCmd *)&rw);
    }
    for (i = 0; i < 8; i++) {
        int64_t start = g_get_monotonic_time();

        ns = femu_query_ns(qts, i % 2 ? "'kind':'zones'" : "", &rsp);
        qobject_unref(rsp);
        slowest = MAX(slowest, g_get_monotonic_time() - start);
        g_assert_cmpint(slowest, <, G_USEC_PER_SEC);
    }
    for (i = 0; i < appends; i++) {
        g_assert_cmphex(FEMU_SC(femu_complete(&c, &c.io, NULL, NULL)), ==,
                        NVME_SUCCESS);
    }
    g_test_message("%u appends; slowest query with appends in flight: %"
                   PRId64 " us", appends, slowest);
    femu_query_zns_check(&c, rpt, 4096, counts);

    /* reset every zone */
    g_assert_cmpint(femu_zone_action(&c, 0, FEMU_ZONE_ACTION_RESET |
                                     FEMU_ZONE_SELECT_ALL), ==, NVME_SUCCESS);
    femu_query_zns_check(&c, rpt, 5, counts);
    g_assert_cmpuint(counts[0x1], ==, nr);

    guest_free(alloc, rpt);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/* Submit a Report Zones of every zone and do not wait for it. */
static void femu_zone_report_send(FemuCtrlState *c, uint64_t buf)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = NVME_CMD_ZONE_MGMT_RECV;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw12 = cpu_to_le32(4096 / 4 - 1);
    femu_submit(c, &c->io, &cmd);
}

static void femu_zone_lock_hold(QTestState *qts, uint32_t ms)
{
    qtest_qmp_assert_success(qts, "{'execute':'qom-set','arguments':{"
                             "'path':'/machine/peripheral/qz',"
                             "'property':'x-zone-lock-hold-ms','value':%u}}",
                             ms);
}

/*
 * A poller holds the zone lock (a Report Zones held there by
 * x-zone-lock-hold-ms). The query must wait for the lock, not read without
 * it, and must not block the main loop meanwhile: a qtest read, served by
 * the main loop, has to come back at once.
 */
void femu_test_query_zns_busy(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t rpt = guest_alloc(alloc, 4096);
    int64_t start, main_us, query_us;
    QDict *rsp;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_zone_lock_hold(qts, 400);
    femu_zone_report_send(&c, rpt);
    g_usleep(100 * 1000);

    start = g_get_monotonic_time();
    qtest_qmp_send(qts, "{'execute':'query-femu'}");
    g_usleep(20 * 1000);
    main_us = g_get_monotonic_time();
    qtest_readb(qts, rpt);
    main_us = g_get_monotonic_time() - main_us;
    rsp = qtest_qmp_receive(qts);
    query_us = g_get_monotonic_time() - start;
    g_test_message("main loop answered in %" PRId64 " us; query took %"
                   PRId64 " us", main_us, query_us);
    g_assert_nonnull(qdict_get_qdict(rsp, "return"));
    qobject_unref(rsp);
    g_assert_cmpint(main_us, <, 100 * 1000);
    g_assert_cmpint(query_us, >=, 200 * 1000);

    g_assert_cmphex(FEMU_SC(femu_complete(&c, &c.io, NULL, NULL)), ==,
                    NVME_SUCCESS);
    femu_zone_lock_hold(qts, 0);
    guest_free(alloc, rpt);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * The device is unplugged while the query sleeps between two tries of a
 * busy zone lock. When it wakes, it must see the device gone and fail,
 * without touching the namespaces; a sanitizer build reports that access.
 */
void femu_test_query_zns_busy_unplug(void *obj, void *data,
                                     QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t rpt = guest_alloc(alloc, 4096);
    QDict *rsp;
    QDict *err;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_zone_lock_hold(qts, 600);
    femu_zone_report_send(&c, rpt);
    g_usleep(100 * 1000);
    qtest_qmp_device_del_send(qts, "qz");
    qtest_qmp_send(qts, "{'execute':'query-femu'}");
    g_usleep(100 * 1000);
    qtest_outl(qts, 0xae00 + 8, 1 << 4);    /* ACPI PCI hotplug: eject slot 4 */
    rsp = qtest_qmp_receive(qts);
    err = qdict_get_qdict(rsp, "error");
    g_assert_nonnull(err);
    g_test_message("query-femu: %s", qdict_get_str(err, "desc"));
    g_assert_nonnull(strstr(qdict_get_str(err, "desc"), "removed"));
    qobject_unref(rsp);
    qtest_qmp_eventwait(qts, "DEVICE_DELETED");
    qos_invalidate_command_line();
}

/* a value of the femu device with id qz, under qtest */
static uint64_t femu_qz_get(QTestState *qts, const char *prop)
{
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                           "'path':'/machine/peripheral/qz',"
                           "'property':%s}}", prop);
    uint64_t value = qdict_get_int(rsp, "return");

    qobject_unref(rsp);
    return value;
}

/* wait until @want threads sleep in a zone hold */
static void femu_qz_set(QTestState *qts, const char *prop, uint32_t value)
{
    qtest_qmp_assert_success(qts, "{'execute':'qom-set','arguments':{"
                             "'path':'/machine/peripheral/qz',"
                             "'property':%s,'value':%u}}", prop, value);
}

static void femu_zone_held_wait(QTestState *qts, uint64_t want)
{
    int i;

    for (i = 0; i < FEMU_POLL_LIMIT_MS &&
                femu_qz_get(qts, "x-zone-held") != want; i++) {
        g_usleep(1000);
    }
    g_assert_cmpuint(femu_qz_get(qts, "x-zone-held"), ==, want);
}

typedef struct FemuDeadline {
    GMutex lock;
    GCond cond;
    bool done;
    const char *what;
} FemuDeadline;

static void *femu_deadline(void *opaque)
{
    FemuDeadline *d = opaque;
    gint64 end = g_get_monotonic_time() + 10 * G_TIME_SPAN_SECOND;

    g_mutex_lock(&d->lock);
    while (!d->done) {
        if (!g_cond_wait_until(&d->cond, &d->lock, end)) {
            g_error("%s did not return within ten seconds", d->what);
        }
    }
    g_mutex_unlock(&d->lock);
    return NULL;
}

static void femu_deadline_end(FemuDeadline *d, GThread *watchdog)
{
    g_mutex_lock(&d->lock);
    d->done = true;
    g_cond_signal(&d->cond);
    g_mutex_unlock(&d->lock);
    g_thread_join(watchdog);
}

/*
 * Report Zones into the BIOS ROM while the report holds the zone lock, and a
 * Changed Zone List read waits for that lock with the BQL held. A ROM write
 * is served as I/O, which takes the BQL: sent under the lock, the two threads
 * waited for each other for ever. The report must fail with Data Transfer
 * Error and the log read must complete.
 */
void femu_test_zone_report_rom(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    FemuDeadline d = { .what = "a log read beside a report into ROM" };
    uint64_t page = guest_alloc(alloc, 4096);
    uint8_t report[192];
    GThread *watchdog;
    NvmeCmd cmd;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    /* long enough that the test sees the hold; the log read then waits */
    femu_zone_lock_hold(qts, 1500);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_CMD_ZONE_MGMT_RECV;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(0xfffc0000);
    cmd.cdw12 = cpu_to_le32(4096 / 4 - 1);
    femu_submit(&c, &c.io, &cmd);
    for (int i = 0; i < FEMU_POLL_LIMIT_MS &&
                    !femu_qz_get(qts, "x-zone-held") &&
                    !femu_cq_ready(&c, &c.io); i++) {
        g_usleep(1000);
    }

    /* a test descheduled past the hold checks the refusal only */
    if (femu_cq_ready(&c, &c.io)) {
        g_test_message("the hold ended unseen; no log read beside it");
    } else {
        g_mutex_init(&d.lock);
        g_cond_init(&d.cond);
        watchdog = g_thread_new("report-rom-timeout", femu_deadline, &d);
        g_assert_cmpint(femu_log_cmd(&c, 1, FEMU_LOG_CHANGED_ZONE_LIST,
                                     FEMU_CSI_ZONED << 24, page, 512), ==,
                        NVME_SUCCESS);
        femu_deadline_end(&d, watchdog);
    }
    g_assert_cmphex(FEMU_SC(femu_complete(&c, &c.io, NULL, NULL)), ==,
                    NVME_DATA_TRAS_ERROR);

    /* a report into memory is unaffected */
    femu_zone_lock_hold(qts, 0);
    femu_zone_report(&c, page, report);
    g_assert_cmpint(femu_zr_state(report, 0), ==, NVME_ZONE_STATE_EMPTY);

    guest_free(alloc, page);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * A zone report is held between its build and its transfer. A Changed Zone
 * List read, which takes the zone lock with the BQL held, must complete
 * meanwhile: the lock is free during the transfer.
 */
void femu_test_zone_report_unlocked(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    FemuDeadline d = { .what = "a log read beside a held report transfer" };
    uint64_t rpt = guest_alloc(alloc, 4096);
    uint64_t page = guest_alloc(alloc, 4096);
    GThread *watchdog;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_qz_set(qts, "x-zone-report-hold-ms", 20000);
    femu_zone_report_send(&c, rpt);
    femu_zone_held_wait(qts, 1);

    g_mutex_init(&d.lock);
    g_cond_init(&d.cond);
    watchdog = g_thread_new("report-unlocked-timeout", femu_deadline, &d);
    g_assert_cmpint(femu_log_cmd(&c, 1, FEMU_LOG_CHANGED_ZONE_LIST,
                                 FEMU_CSI_ZONED << 24, page, 512), ==,
                    NVME_SUCCESS);
    femu_deadline_end(&d, watchdog);
    g_assert_false(femu_cq_ready(&c, &c.io));

    femu_qz_set(qts, "x-zone-report-hold-ms", 0);
    g_assert_cmphex(FEMU_SC(femu_complete(&c, &c.io, NULL, NULL)), ==,
                    NVME_SUCCESS);
    guest_free(alloc, page);
    guest_free(alloc, rpt);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

static void femu_zone_write_hold(QTestState *qts, uint32_t ms)
{
    femu_qz_set(qts, "x-zone-write-hold-ms", ms);
}

/*
 * A Reset of zone 0, alone or with Select All (@data), from a second poller
 * while a one-block write to it is admitted but not yet copied. The write
 * holds after admission until the test lets it go, and the Reset is sent
 * once it holds. Run in the gap, the Reset completed at once and left an
 * Empty zone whose write pointer the late write then moved to 1, with the
 * old data back in it. The Reset must wait for the write (x-zone-draining
 * shows it waiting), then leave pointer 0 and zeroes.
 */
void femu_test_zone_reset_inflight(void *obj, void *data,
                                   QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    bool all = data != NULL;
    uint8_t got[512];
    uint8_t zero[512] = { 0 };
    uint8_t zd[64];
    FemuQueue q1, q2;
    uint64_t buf, page;
    NvmeCmd cmd;

    femu_enable(&c, &femu->dev, alloc);
    femu_zap_create_queue(&c, &q1, 1);
    femu_zap_create_queue(&c, &q2, 2);
    buf = guest_alloc(alloc, 4096);
    page = guest_alloc(alloc, 4096);
    qtest_memset(qts, buf, 0x5a, 4096);

    femu_zone_write_hold(qts, 20000);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_CMD_WRITE;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    femu_zap_queue(&c, &q1, &cmd);
    femu_zap_ring(&c, &q1);
    femu_zone_held_wait(qts, 1);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_CMD_ZONE_MGMT_SEND;
    cmd.nsid = cpu_to_le32(1);
    cmd.cdw13 = cpu_to_le32(NVME_ZONE_ACTION_RESET | (all ? 0x100 : 0));
    femu_zap_queue(&c, &q2, &cmd);
    femu_zap_ring(&c, &q2);
    /* the Reset waits for the write; it must not complete first */
    for (int k = 0; k < FEMU_POLL_LIMIT_MS &&
                    !femu_qz_get(qts, "x-zone-draining") &&
                    !femu_cq_ready(&c, &q2); k++) {
        g_usleep(1000);
    }
    g_assert_false(femu_cq_ready(&c, &q2));
    g_assert_cmpuint(femu_qz_get(qts, "x-zone-draining"), ==, 1);
    femu_zone_write_hold(qts, 0);
    g_assert_cmpint(femu_zap_complete(&c, &q1, NULL), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_zap_complete(&c, &q2, NULL), ==, NVME_SUCCESS);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_CMD_ZONE_MGMT_RECV;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(page);
    cmd.cdw12 = cpu_to_le32(4096 / 4 - 1);
    femu_zap_queue(&c, &q1, &cmd);
    femu_zap_ring(&c, &q1);
    g_assert_cmpint(femu_zap_complete(&c, &q1, NULL), ==, NVME_SUCCESS);
    qtest_memread(qts, page + 64, zd, sizeof(zd));
    g_assert_cmpint(zd[1] >> 4, ==, NVME_ZONE_STATE_EMPTY);
    g_assert_cmphex(ldq_le_p(zd + 24), ==, ldq_le_p(zd + 16));

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_CMD_READ;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(page);
    femu_zap_queue(&c, &q1, &cmd);
    femu_zap_ring(&c, &q1);
    g_assert_cmpint(femu_zap_complete(&c, &q1, NULL), ==, NVME_SUCCESS);
    qtest_memread(qts, page, got, sizeof(got));
    g_assert_cmpmem(got, sizeof(got), zero, sizeof(zero));

    guest_free(alloc, page);
    guest_free(alloc, buf);
    femu_queue_free(&c, &q2);
    femu_queue_free(&c, &q1);
    femu_disable(&c);
}

#define FEMU_ZONE_BOUNDARY_ERROR    0x1b8   /* command specific */

/* Compare reads a zone, so it may not run across a zone boundary either */
void femu_test_zoned_compare(void *obj, void *data,
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
 * The list is a zoned page, so the host selects command sets by CSI.
 */
void femu_test_zone_change_notice(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { .pdev = &femu->dev, .alloc = alloc };
    uint64_t buf;
    uint64_t zsze;
    uint32_t result;
    uint16_t aer_cid;
    uint16_t cid;
    uint8_t zs[4];
    NvmeCmd cmd;

    femu_queue_init(&c, &c.admin, 0);
    femu_enable_cc(&c, &femu->dev, alloc,
                   (6 << 16) | (4 << 20) | (FEMU_CC_CSS_CSI << 4) | 1);
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
    g_assert_cmpint(femu_log_cmd(&c, 1, FEMU_LOG_CHANGED_ZONES,
                                 (uint32_t)FEMU_CSI_ZONED << 24, buf, 4096),
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

    g_assert_cmpint(femu_log_cmd(&c, 1, FEMU_LOG_CHANGED_ZONES,
                                 (uint32_t)FEMU_CSI_ZONED << 24, buf, 4096),
                    ==, NVME_SUCCESS);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/* NSID, dword 1, of the admin completion taken last */
static uint32_t femu_admin_last_nsid(FemuCtrlState *c)
{
    return qtest_readl(c->pdev->bus->qts, c->admin.cq_addr +
                       ((c->admin.cq_head + FEMU_QSIZE - 1) % FEMU_QSIZE) *
                       sizeof(NvmeCqe) + 4);
}

/* a write to namespace @nsid, which err_write_fail_ppm=1000000 fails */
static void femu_zone_fault(FemuCtrlState *c, uint32_t nsid, uint64_t slba,
                            uint64_t buf)
{
    NvmeRwCmd rw = { 0 };

    rw.opcode = NVME_CMD_WRITE;
    rw.nsid = cpu_to_le32(nsid);
    rw.slba = cpu_to_le64(slba);
    rw.dptr.prp1 = cpu_to_le64(buf);
    g_assert_cmphex(FEMU_SC(femu_io(c, (NvmeCmd *)&rw)), ==,
                    NVME_WRITE_FAULT);
}

/*
 * Two zoned namespaces. Namespace 1's Zone Descriptor Changed notice is
 * reported, which masks Notice events, and a second change of namespace 1
 * queues another. Reading namespace 2's Changed Zone List acknowledges
 * nothing that was reported (Base 2.3, 5.2.2): it used to unmask the type
 * and send namespace 1's queued notice. Only a read of namespace 1's list
 * unmasks it; the next change of namespace 1 is then reported.
 */
void femu_test_zone_notice_other_ns(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf, page, zsze;
    uint8_t report[192];
    uint32_t result;
    uint16_t want, got;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, 4096);
    page = guest_alloc(alloc, 4096);
    femu_zone_report(&c, page, report);
    zsze = ldq_le_p(report + 128 + 16);
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_ASYNCHRONOUS_EVENT_CONF,
                                             false, 0, FEMU_AEC_ZDCN, NULL)),
                    ==, NVME_SUCCESS);

    want = femu_aer(&c);
    femu_zone_fault(&c, 1, 0, buf);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.admin, &got, &result)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(got, ==, want);
    g_assert_cmphex(result & 0xffffff, ==, 0xbfef02);
    g_assert_cmpuint(femu_admin_last_nsid(&c), ==, 1);
    femu_zone_fault(&c, 1, zsze, buf);

    want = femu_aer(&c);
    g_assert_cmpint(femu_log_cmd(&c, 2, FEMU_LOG_CHANGED_ZONES,
                                 (uint32_t)FEMU_CSI_ZONED << 24, page, 4096),
                    ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readw(c.pdev->bus->qts, page), ==, 0);
    g_usleep(100 * 1000);
    g_assert_false(femu_cq_ready(&c, &c.admin));

    /* namespace 1's own read acknowledges it; both changes were in it */
    g_assert_cmpint(femu_log_cmd(&c, 1, FEMU_LOG_CHANGED_ZONES,
                                 (uint32_t)FEMU_CSI_ZONED << 24, page, 4096),
                    ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readw(c.pdev->bus->qts, page), ==, 2);
    g_usleep(100 * 1000);
    g_assert_false(femu_cq_ready(&c, &c.admin));
    femu_zone_fault(&c, 1, 2 * zsze, buf);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.admin, &got, &result)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(got, ==, want);
    g_assert_cmpuint(femu_admin_last_nsid(&c), ==, 1);

    guest_free(alloc, page);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

#define FEMU_MANY_ZNS   17

/*
 * One Zone Descriptor Changed notice in each of 17 zoned namespaces, raised
 * with no Asynchronous Event Request outstanding. Each namespace's notice is
 * a distinct event, and the 16-entry queue used to drop the 17th for good.
 * All 17 must reach the host, one per log read, each naming its namespace.
 */
void femu_test_zone_notice_many_ns(void *obj, void *data,
                                   QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    bool seen[FEMU_MANY_ZNS + 1] = { false };
    uint64_t buf, page;
    uint32_t nsid, k;
    uint16_t want, got;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, 4096);
    page = guest_alloc(alloc, 4096);
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_ASYNCHRONOUS_EVENT_CONF,
                                             false, 0, FEMU_AEC_ZDCN, NULL)),
                    ==, NVME_SUCCESS);
    for (nsid = 1; nsid <= FEMU_MANY_ZNS; nsid++) {
        femu_zone_fault(&c, nsid, 0, buf);
    }

    for (k = 0; k < FEMU_MANY_ZNS; k++) {
        want = femu_aer(&c);
        g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.admin, &got, NULL)), ==,
                        NVME_SUCCESS);
        g_assert_cmpint(got, ==, want);
        nsid = femu_admin_last_nsid(&c);
        g_assert_cmpuint(nsid, >=, 1);
        g_assert_cmpuint(nsid, <=, FEMU_MANY_ZNS);
        g_assert_false(seen[nsid]);
        seen[nsid] = true;
        g_assert_cmpint(femu_log_cmd(&c, nsid, FEMU_LOG_CHANGED_ZONES,
                                     (uint32_t)FEMU_CSI_ZONED << 24, page,
                                     4096), ==, NVME_SUCCESS);
        g_assert_cmpuint(qtest_readw(c.pdev->bus->qts, page), ==, 1);
    }

    /* nothing is left over */
    want = femu_aer(&c);
    g_usleep(100 * 1000);
    g_assert_false(femu_cq_ready(&c, &c.admin));

    guest_free(alloc, page);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * A Changed Zone List read without RAE whose transfer fails (its buffer is
 * the BIOS ROM) acknowledges nothing: the list keeps its entry and Notice
 * events stay masked. It used to clear both first, so a retry found an
 * empty list. A read that succeeds acknowledges what it carried.
 */
void femu_test_zone_list_ack_fail(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf, page, zsze;
    uint8_t report[192];
    uint16_t want, got;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, 4096);
    page = guest_alloc(alloc, 4096);
    femu_zone_report(&c, page, report);
    zsze = ldq_le_p(report + 128 + 16);
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_ASYNCHRONOUS_EVENT_CONF,
                                             false, 0, FEMU_AEC_ZDCN, NULL)),
                    ==, NVME_SUCCESS);

    want = femu_aer(&c);
    femu_zone_fault(&c, 1, 0, buf);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.admin, &got, NULL)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(got, ==, want);

    g_assert_cmpint(femu_log_cmd(&c, 1, FEMU_LOG_CHANGED_ZONES,
                                 (uint32_t)FEMU_CSI_ZONED << 24, 0xfffc0000,
                                 4096), ==, NVME_DATA_TRAS_ERROR);
    want = femu_aer(&c);
    femu_zone_fault(&c, 1, zsze, buf);
    g_usleep(100 * 1000);
    g_assert_false(femu_cq_ready(&c, &c.admin));

    g_assert_cmpint(femu_log_cmd(&c, 1, FEMU_LOG_CHANGED_ZONES,
                                 (uint32_t)FEMU_CSI_ZONED << 24, page, 4096),
                    ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readw(qts, page), ==, 2);
    g_assert_cmpuint(qtest_readq(qts, page + 8), ==, 0);
    g_assert_cmpuint(qtest_readq(qts, page + 16), ==, zsze);
    g_usleep(100 * 1000);
    g_assert_false(femu_cq_ready(&c, &c.admin));
    g_assert_cmpint(femu_log_cmd(&c, 1, FEMU_LOG_CHANGED_ZONES,
                                 (uint32_t)FEMU_CSI_ZONED << 24, page, 4096),
                    ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readw(qts, page), ==, 0);

    femu_zone_fault(&c, 1, 2 * zsze, buf);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.admin, &got, NULL)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(got, ==, want);

    guest_free(alloc, page);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * A zone changes while a Changed Zone List read without RAE is between its
 * snapshot and its transfer: the faulting write is held after admission,
 * and the read lets it go after its snapshot and waits for its fault. The
 * read acknowledges the reported notice, so the new change's notice goes
 * out at once, and the change keeps its entry for the next read.
 */
void femu_test_zone_list_ack_race(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf, page, zsze;
    uint8_t report[192];
    uint32_t result;
    uint16_t want, got, log_cid, wr_cid;
    NvmeRwCmd rw = { 0 };
    NvmeCmd cmd;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, 4096);
    page = guest_alloc(alloc, 4096);
    femu_zone_report(&c, page, report);
    zsze = ldq_le_p(report + 128 + 16);
    g_assert_cmpint(FEMU_SC(femu_set_feature(&c, NVME_ASYNCHRONOUS_EVENT_CONF,
                                             false, 0, FEMU_AEC_ZDCN, NULL)),
                    ==, NVME_SUCCESS);
    want = femu_aer(&c);
    femu_zone_fault(&c, 1, 0, buf);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.admin, &got, NULL)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(got, ==, want);
    want = femu_aer(&c);

    femu_zone_write_hold(qts, 20000);
    rw.opcode = NVME_CMD_WRITE;
    rw.nsid = cpu_to_le32(1);
    rw.slba = cpu_to_le64(zsze);
    rw.dptr.prp1 = cpu_to_le64(buf);
    wr_cid = c.cid;
    femu_submit(&c, &c.io, (NvmeCmd *)&rw);
    femu_zone_held_wait(qts, 1);

    femu_qz_set(qts, "x-zone-log-hold-ms", 5000);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_GET_LOG_PAGE;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(page);
    cmd.cdw10 = cpu_to_le32(FEMU_LOG_CHANGED_ZONES | ((512 / 4 - 1) << 16));
    cmd.cdw14 = cpu_to_le32((uint32_t)FEMU_CSI_ZONED << 24);
    log_cid = c.cid;
    femu_submit(&c, &c.admin, &cmd);

    /* the snapshot held zone 0 only; the write's fault came after it */
    g_assert_cmphex(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), ==,
                    NVME_WRITE_FAULT);
    g_assert_cmpint(got, ==, wr_cid);
    /* the log read and the notice, in either order */
    for (int k = 0; k < 2; k++) {
        g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.admin, &got, &result)),
                        ==, NVME_SUCCESS);
        if (got == log_cid) {
            g_assert_cmpuint(qtest_readw(qts, page), ==, 1);
            g_assert_cmpuint(qtest_readq(qts, page + 8), ==, 0);
        } else {
            g_assert_cmpint(got, ==, want);
            g_assert_cmphex(result & 0xffffff, ==, 0xbfef02);
        }
    }
    femu_qz_set(qts, "x-zone-log-hold-ms", 0);
    /* the change came between the snapshot and the acknowledgment */
    g_assert_cmpuint(femu_qz_get(qts, "x-zone-log-changes"), ==, 1);

    g_assert_cmpint(femu_log_cmd(&c, 1, FEMU_LOG_CHANGED_ZONES,
                                 (uint32_t)FEMU_CSI_ZONED << 24, page, 512),
                    ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readw(qts, page), ==, 1);
    g_assert_cmpuint(qtest_readq(qts, page + 8), ==, zsze);

    guest_free(alloc, page);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * The Changed Zone List belongs to the zoned command set's list of pages,
 * which CDW14.CSI selects while CC.CSS selects by CSI.
 */
void femu_test_log_contents_zoned(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { .pdev = &femu->dev, .alloc = alloc };
    uint64_t buf;

    femu_queue_init(&c, &c.admin, 0);
    femu_enable_cc(&c, &femu->dev, alloc,
                   (6 << 16) | (4 << 20) | (FEMU_CC_CSS_CSI << 4) | 1);
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

/* ZASL 0 means the append limit is MDTS, and MDTS 0 means there is none */
void femu_test_zoned_append_mdts0(void *obj, void *data,
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

#define FEMU_TOO_MANY_ACTIVE    0x1bd   /* command specific */

/*
 * With two zones allowed active and open, opening a third empty zone fails
 * on the active limit, whether a write or Open asks for it. Neither may close
 * one of the open zones on the way to failing.
 */
void femu_test_zone_active_limit(void *obj, void *data,
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
void femu_test_zrwa_write_bounds(void *obj, void *data,
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
void femu_test_zrwa_odd_granule(void *obj, void *data,
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
void femu_test_zrwa_zd_ext(void *obj, void *data,
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

/* Report Zones under MDTS 0: the same bound as the reports above */
void femu_test_mdts0_zone_report(void *obj, void *data,
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
 * persist_file keeps the data across a hot unplug and across a QEMU quit.
 * Run 1 writes page 3 and quits; run 2 reads it back, writes page 9 and
 * unplugs; a device added again reads both. A file of another size fails
 * realize, and so does a mode that keeps state outside the backend.
 */
void femu_test_persist(void *obj, void *data, QGuestAllocator *alloc)
{
    g_autofree char *dir = g_dir_make_tmp("femu-persist-XXXXXX", NULL);
    g_autofree char *path = g_build_filename(dir, "data", NULL);
    g_autofree char *lock = g_strconcat(path, ".lock", NULL);
    int mode = data ? 2 : 1;
    QDict *rsp;
    int run;

    for (run = 1; run <= 2; run++) {
        QOSState *qs = qtest_pc_boot(
            "-machine pc -nodefaults -device femu,id=pd,addr=5,devsz_mb=16,"
            "femu_mode=%d,persist_file=%s", mode, path);
        QTestState *qts = qs->qts;
        QPCIDevice *pdev = qpci_device_find(qs->pcibus, QPCI_DEVFN(5, 0));
        FemuCtrlState c = { 0 };
        uint64_t buf = guest_alloc(&qs->alloc, 4096);

        femu_enable(&c, pdev, &qs->alloc);
        femu_create_io_queues(&c);
        if (run == 1) {
            femu_ns_page(&c, buf, 1, 3, 0x3c, true);
            femu_disable(&c);
            qtest_qmp_send(qts, "{'execute':'quit'}");
            qtest_set_expected_status(qts, 0);
            qtest_wait_qemu(qts);
        } else {
            femu_ns_page(&c, buf, 1, 3, 0x3c, false);
            femu_ns_page(&c, buf, 1, 9, 0x9a, true);
            femu_disable(&c);
            femu_queue_free(&c, &c.io);
            qpci_unplug_acpi_device_test(qts, "pd", 5);
            g_free(pdev);
            rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                            "'driver':'femu','id':'pd','addr':'5',"
                            "'devsz_mb':16,'femu_mode':%d,"
                            "'persist_file':%s}}", mode, path);
            if (qdict_haskey(rsp, "error")) {
                g_test_message("device_add: %s", qdict_get_str(
                               qdict_get_qdict(rsp, "error"), "desc"));
            }
            g_assert_true(qdict_haskey(rsp, "return"));
            qobject_unref(rsp);
            pdev = qpci_device_find(qs->pcibus, QPCI_DEVFN(5, 0));
            memset(&c, 0, sizeof(c));
            femu_enable(&c, pdev, &qs->alloc);
            femu_create_io_queues(&c);
            femu_ns_page(&c, buf, 1, 3, 0x3c, false);
            femu_ns_page(&c, buf, 1, 9, 0x9a, false);
            femu_disable(&c);
            /* a second device cannot take a file in use */
            rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                            "'driver':'femu','id':'pe','addr':'6',"
                            "'devsz_mb':16,'femu_mode':%d,"
                            "'persist_file':%s}}", mode, path);
            g_assert_true(qdict_haskey(rsp, "error"));
            g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp,
                             "error"), "desc"), "in use"));
            qobject_unref(rsp);
            /* once it is free, another size does not take this file */
            femu_queue_free(&c, &c.io);
            qpci_unplug_acpi_device_test(qts, "pd", 5);
            memset(&c, 0, sizeof(c));
            rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                            "'driver':'femu','id':'pe','addr':'6',"
                            "'devsz_mb':32,'femu_mode':%d,"
                            "'persist_file':%s}}", mode, path);
            g_assert_true(qdict_haskey(rsp, "error"));
            g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp,
                             "error"), "desc"), "does not match"));
            qobject_unref(rsp);
            rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                            "'driver':'femu','id':'pe','addr':'6',"
                            "'devsz_mb':16,'femu_mode':3,"
                            "'persist_file':%s}}", path);
            g_assert_true(qdict_haskey(rsp, "error"));
            g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp,
                             "error"), "desc"), "not supported with"));
            qobject_unref(rsp);
        }
        /* femu_disable() freed the admin queue; run 2 freed the I/O queue */
        if (run == 1) {
            femu_queue_free(&c, &c.io);
        }
        guest_free(&qs->alloc, buf);
        g_free(pdev);
        qtest_pc_shutdown(qs);
    }
    unlink(lock);
    unlink(path);
    rmdir(dir);
}

/*
 * persist_load_only: checkpoint B holds page 2 = 0x21. Two readers of B
 * read it, and each then writes its own byte. A writer of B, and another
 * device's save to B, fail while a reader holds B. A reader cannot save
 * B, also when it is the only reader or names B through a link, but can
 * save C, which a later reader loads. A reader whose realize fails after
 * its load releases B. A reader loads B from a directory it cannot write.
 * A reader in a second QEMU loads C, writes it, and quits. B keeps its
 * bytes and inode until the writer, and C keeps them to the end.
 */
/*
 * zns_slc_zones=2 on QLC: 64 pages a block, 2 planes, one die. Zones 0 and
 * 1 run in SLC mode: 16 pages a block, so 32 x 16 KiB = 1024 LBAs, a
 * quarter of the 4096 of a native zone. A native read takes 100 ms
 * (zns_pg_rd_lat), an SLC read its built-in 4 us. Zone 0 fills at 1024
 * LBAs with no page overrun, and a write past it fails. Realize refuses SLC
 * zones on an SLC device, more SLC zones than sequential zones, and SLC
 * zones without a zoned namespace. @data "types" adds zns_page_types: an
 * SLC page past page 0 still reads in SLC time, and a native read takes
 * one of the page type times around 100 ms.
 * The checks are wall clock, so they tell SLC from native time; they cannot
 * tell the 4 us SLC read from no NAND time at all.
 */
void femu_test_zns_slc_zones(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    bool types = data && !strcmp(data, "types");
    uint64_t buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    uint64_t lpb;
    uint64_t zsze;
    QList *zones;
    QDict *rsp;
    QDict *ns;
    int64_t ms;
    char *err;

    femu_enable_csi(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    lpb = FEMU_DATA_SIZE / c.lba_size;
    qtest_memset(qts, buf, 0x5a, FEMU_DATA_SIZE);

    ns = femu_query_ns(qts, "'kind':'zones','limit':3", &rsp);
    zsze = qdict_get_int(ns, "zone-size");
    g_assert_cmpuint(zsze, ==, 4096);
    g_assert_cmpuint(qdict_get_int(ns, "zone-capacity"), ==, 4096);
    zones = qdict_get_qlist(ns, "zones");
    for (int i = 0; i < 3; i++) {
        QDict *z = qobject_to(QDict, qlist_pop(zones));

        g_assert_cmpuint(qdict_get_int(z, "capacity"), ==,
                         i < 2 ? 1024 : 4096);
        g_assert_cmpint(qdict_get_bool(z, "slc"), ==, i < 2);
        qobject_unref(z);
    }
    qobject_unref(rsp);

    /* fill zone 0: 128 writes of 4 KiB, then the zone is Full */
    for (uint64_t lba = 0; lba < 1024; lba += lpb) {
        g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, lba, buf)), ==,
                        NVME_SUCCESS);
    }
    g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 1024, buf)), !=,
                    NVME_SUCCESS);
    ns = femu_query_ns(qts, "'kind':'zones','limit':1", &rsp);
    g_assert_cmpint(qdict_get_int(ns, "page-overruns"), ==, 0);
    g_assert_cmpuint(qdict_get_int(qdict_get_qdict(ns, "zone-counts"),
                                   "full"), ==, 1);
    qobject_unref(rsp);

    /* zone 2: one QLC stripe (32 LPNs) and one more programs the stripe */
    for (uint64_t i = 0; i < 33; i++) {
        g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE,
                                        2 * zsze + i * lpb, buf)), ==,
                        NVME_SUCCESS);
    }
    ms = femu_zns_ms(&c, NVME_CMD_READ, 2 * zsze, buf);
    g_test_message("native read %" PRId64 " ms", ms);
    g_assert_cmpint(ms, >=, types ? 20 : 95);
    /*
     * LBA 0 is on page 0; LBA 520 is in the 9th flush, on page 8. A host
     * stall can only add time, so keep the shortest of 5 reads.
     */
    for (int k = 0; k < 2; k++) {
        ms = INT64_MAX;
        for (int i = 0; i < 5; i++) {
            ms = MIN(ms, femu_zns_ms(&c, NVME_CMD_READ, k ? 520 : 0, buf));
            g_assert_cmphex(qtest_readb(qts, buf), ==, 0x5a);
        }
        g_test_message("SLC read %" PRId64 " ms", ms);
        g_assert_cmpint(ms, <, 15);
    }

    err = femu_ckpt_try_add(qts, "s1", 7, ",'femu_mode':3,'zns_flash_type':1,"
                            "'zns_slc_zones':1,'zns_num_ch':1,'zns_num_lun':1,"
                            "'zns_num_blk':32");
    g_assert_nonnull(err);
    g_assert_nonnull(strstr(err, "SLC already"));
    g_free(err);
    err = femu_ckpt_try_add(qts, "s3", 7, ",'femu_mode':1,'zns_slc_zones':1");
    g_assert_nonnull(err);
    g_assert_nonnull(strstr(err, "needs a zoned namespace"));
    g_free(err);
    err = femu_ckpt_try_add(qts, "s2", 7, ",'femu_mode':3,"
                            "'zns_slc_zones':100000,'zns_num_ch':1,"
                            "'zns_num_lun':1,'zns_num_blk':32");
    g_assert_nonnull(err);
    g_assert_nonnull(strstr(err, "sequential zones"));
    g_free(err);

    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * The ZNS form: a 300 ms page read. Eight more writes push the first page out
 * of the write cache, so a Read of it takes the read time, and Compare and
 * Verify must take it as well, also when the Compare fails. Before, both
 * completed at once.
 */
void femu_test_compare_verify_zns(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    static const uint8_t opcodes[] = {
        NVME_CMD_READ, NVME_CMD_COMPARE, NVME_CMD_VERIFY,
    };
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf;
    gint64 start, ms;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    qtest_memset(c.pdev->bus->qts, buf, 0x3c, FEMU_DATA_SIZE);
    for (i = 0; i <= ZNS_LUN_FILL; i++) {
        g_assert_cmphex(femu_oncs_cmd(&c, NVME_CMD_WRITE,
                                      i * (FEMU_DATA_SIZE / c.lba_size), buf),
                        ==, NVME_SUCCESS);
    }
    for (i = 0; i < ARRAY_SIZE(opcodes); i++) {
        start = g_get_monotonic_time();
        g_assert_cmphex(femu_oncs_cmd(&c, opcodes[i], 0, buf), ==,
                        NVME_SUCCESS);
        ms = (g_get_monotonic_time() - start) / 1000;
        g_test_message("opcode 0x%x took %" PRId64 " ms", opcodes[i], ms);
        g_assert_cmpint(ms, >=, ZNS_LUN_OP_MS);
    }
    /* a miscompare read the media too */
    qtest_memset(c.pdev->bus->qts, buf, 0xa5, FEMU_DATA_SIZE);
    start = g_get_monotonic_time();
    g_assert_cmphex(femu_oncs_cmd(&c, NVME_CMD_COMPARE, 0, buf), ==,
                    NVME_CMP_FAILURE);
    ms = (g_get_monotonic_time() - start) / 1000;
    g_test_message("miscompare took %" PRId64 " ms", ms);
    g_assert_cmpint(ms, >=, ZNS_LUN_OP_MS);
    femu_disable(&c);
}
