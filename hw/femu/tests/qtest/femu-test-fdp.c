/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QTest testcases for the FEMU SSD emulator: the Flexible Data
 * Placement tests (fdp-*).
 *
 * femu-test.c registers every test. This file holds the test bodies
 * and the helpers that only they use.
 */

#include "qemu/osdep.h"
#include "femu-test.h"

#define FEMU_FDP_EVT_RU_NOT_FULLY_WRITTEN 0x00

static uint16_t femu_write_block_placed(FemuCtrlState *c, uint64_t lba,
                                        uint64_t data, int pid);

/*
 * RUH Update of two written units logs event 00h for each (Base 2.3,
 * 5.2.12.1.32.1.1). The handles hold a written unit first: an empty unit
 * stays, so its handle does not move and logs nothing.
 */
void femu_test_fdp_events(void *obj, void *data, QGuestAllocator *alloc)
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
    g_assert_cmphex(femu_write_block_placed(&c, 0, pids, 0), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_write_block_placed(&c, 8, pids, 1), ==, NVME_SUCCESS);
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

    /* handle 2 was never written: its unit stays, and no event follows */
    qtest_writew(femu->dev.bus->qts, pids, 2);
    g_assert_cmpint(femu_ruh_update(&c, pids, 1), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    g_assert_cmpint(qtest_readl(femu->dev.bus->qts, log), ==, 2);

    guest_free(alloc, log);
    guest_free(alloc, pids);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * Random writes spread over every placement handle of a namespace the device
 * accepted. Each handle keeps a unit open and each persistently isolated
 * handle another to collect into, so a namespace that fits only once those
 * are left out cannot take this.
 */
void femu_test_fdp_gc_handles(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    const uint32_t pages = 256;
    const int handles = 4;
    uint64_t buf = guest_alloc(alloc, 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t lost, mapped, orphans;
    uint32_t seed = 7;
    uint32_t full = 0;
    uint16_t status;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x3c, 4096);

    for (i = 0; i < pages; i += 64) {
        g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, i, 64, buf, list,
                                                        (i / 64) % handles)),
                        ==, NVME_SUCCESS);
    }
    for (i = 0; i < 1200; i++) {
        uint32_t npages = i % 4 == 3 ? 64 : 1;
        uint64_t page;

        seed = seed * 1103515245 + 12345;
        page = (seed >> 8) % (pages - npages + 1);
        status = FEMU_SC(femu_write_pages_placed(&c, page, npages, buf, list,
                                                 (seed >> 4) % handles));
        g_assert_true(status == NVME_SUCCESS || status == NVME_CAP_EXCEEDED);
        full += status == NVME_CAP_EXCEEDED;
    }

    femu_ftl_check(qts, &mapped, &lost, &orphans);
    g_test_message("capacity exceeded %u times, %" PRIu64 " of %" PRIu64
                   " mappings lost, %" PRIu64 " orphans", full, lost, mapped,
                   orphans);
    g_assert_cmpuint(mapped, ==, pages);
    g_assert_cmpuint(lost, ==, 0);
    g_assert_cmpuint(orphans, ==, 0);
    g_assert_cmpuint(full, ==, 0);

    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_disable(&c);
}
static void femu_check_event_loc(const uint8_t *ev);

/* pages garbage collection relocated, from the C0h log */
static uint64_t femu_gc_pages(FemuCtrlState *c, uint64_t buf)
{
    g_assert_cmpint(FEMU_SC(femu_get_log(c, FEMU_LOG_FEMU_STATS, buf, 512, 0)),
                    ==, NVME_SUCCESS);
    return qtest_readq(c->pdev->bus->qts, buf + 16);
}

/*
 * With forced collection waiting until no unit is free, random writes over
 * every handle leave the device with no free unit and a collection frontier
 * dropped part way through a victim. Deallocating the whole namespace then
 * leaves only units with nothing valid in them. Collection used to need a
 * frontier before it looked at the victim, and could only derive one from the
 * handle's active unit, so once both were gone it never ran again and the
 * empty namespace took no write. Once it runs, the frontiers have to be taken
 * again for pages that are still valid, and a handle left without a unit must
 * not report the room of a unit another handle has since been given.
 */
void femu_test_fdp_gc_recover(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    const uint32_t pages = 256;
    const int handles = 4;
    const int last = handles - 1;
    uint64_t buf = guest_alloc(alloc, 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t lost, mapped, orphans, gc;
    uint64_t ruamw[4];
    uint32_t seed = 7;
    uint32_t full = 0;
    uint8_t ev[8 * 64];
    uint32_t nev;
    uint16_t status;
    int i, h;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x3c, 4096);

    for (i = 0; i < pages; i += 64) {
        g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, i, 64, buf, list,
                                                        (i / 64) % handles)),
                        ==, NVME_SUCCESS);
    }
    for (i = 0; i < 2000 && full < 16; i++) {
        uint32_t npages = i % 4 == 3 ? 64 : 1;
        uint64_t page;

        seed = seed * 1103515245 + 12345;
        page = (seed >> 8) % (pages - npages + 1);
        status = FEMU_SC(femu_write_pages_placed(&c, page, npages, buf, list,
                                                 (seed >> 4) % handles));
        g_assert_true(status == NVME_SUCCESS || status == NVME_CAP_EXCEEDED);
        full += status == NVME_CAP_EXCEEDED;
    }
    g_test_message("placed %d writes, %u refused", i, full);
    g_assert_cmpuint(full, >, 0);

    g_assert_cmphex(femu_dealloc_pages(&c, 0, pages, buf), ==, NVME_SUCCESS);
    for (h = 0; h < last; h++) {
        ruamw[h] = femu_ruh_ruamw(&c, buf, h);
    }

    /*
     * The whole namespace again, then single pages until valid ones have
     * moved, all through the last handle: the initially isolated one when
     * there is one, which collects into its own active unit.
     */
    qtest_memset(qts, buf, 0x3c, 4096);
    for (i = 0; i < pages; i += 64) {
        g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, i, 64, buf, list,
                                                        last)),
                        ==, NVME_SUCCESS);
    }
    for (h = 0; h < last; h++) {
        g_assert_cmpuint(femu_ruh_ruamw(&c, buf, h), ==, ruamw[h]);
    }
    /*
     * With no unit kept free, a persistently isolated handle whose collection
     * unit was dropped cannot take another while forced collection runs, so
     * only the initially isolated one, which collects into its active unit,
     * can be asked to move valid pages now.
     */
    if (data) {
        gc = femu_gc_pages(&c, list);
        for (i = 0; i < 1024 && femu_gc_pages(&c, list) < gc + 64; i++) {
            seed = seed * 1103515245 + 12345;
            qtest_memset(qts, buf, 0x3c, 4096);
            g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c,
                                        (seed >> 8) % pages, 1, buf, list,
                                        last)), ==, NVME_SUCCESS);
        }
        g_test_message("recovered: %d writes moved %" PRIu64 " valid pages",
                       i, femu_gc_pages(&c, list) - gc);
        g_assert_cmpuint(femu_gc_pages(&c, list), >=, gc + 64);
    }

    femu_ftl_check(qts, &mapped, &lost, &orphans);
    g_assert_cmpuint(mapped, ==, pages);
    g_assert_cmpuint(lost, ==, 0);
    g_assert_cmpuint(orphans, ==, 0);

    /*
     * Persistently isolated moves log no event. Moves of the initially
     * isolated handle do, each about that handle.
     */
    nev = femu_fdp_ctrl_events(&c, list, ev, 8);
    g_test_message("%u controller events", nev);
    if (data) {
        g_assert_cmpuint(nev, >, 0);
    } else {
        g_assert_cmpuint(nev, ==, 0);
    }
    for (i = 0; i < (int)MIN(nev, 8); i++) {
        femu_check_event_loc(ev + i * 64);
    }

    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_disable(&c);
}

/*
 * A namespace must fit in what placement leaves: 24 lines of 64 KiB with four
 * persistently isolated handles leave 960 KiB for a 1 MiB namespace once each
 * handle holds a unit open, each has another to collect into and one is kept
 * free. On 19 or 23 lines, both accepted before, random writes over all four
 * handles failed nearly every time. 25 lines take it (fdp-capacity).
 */
void femu_test_fdp_capacity_refused(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    /* the last one exposes 256 pages and part of another (op_pcent) */
    const struct {
        const char *subsys;
        int blks;
        int op;
    } cases[] = {
        { "fdpsub", 19, 0 }, { "fdpsub", 24, 0 }, { "fdpsub-ii", 23, 0 },
        { "fdpsub", 25, 56 },
    };
    QDict *rsp;
    int i;

    for (i = 0; i < ARRAY_SIZE(cases); i++) {
        rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                        "'driver':'femu','id':'fdp-cap','addr':'5',"
                        "'devsz_mb':1,'femu_mode':1,'secsz':512,"
                        "'secs_per_pg':8,'pgs_per_blk':4,'blks_per_pl':%d,"
                        "'pls_per_lun':1,'luns_per_ch':2,'nchs':2,"
                        "'op_pcent':%d,'subsys':%s}}", cases[i].blks,
                        cases[i].op, cases[i].subsys);
        g_assert_true(qdict_haskey(rsp, "error"));
        g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                             "desc"), "fdp.nruh"));
        qobject_unref(rsp);
    }
    qos_invalidate_command_line();
}

/*
 * Only greedy, cost-benefit, random and per-handle collection (0, 1, 2 and 4)
 * are implemented for placement. The other numbers once fell back to greedy
 * or never collected, so realize refuses them rather than run something else.
 */
void femu_test_fdp_gc_strategy_refused(void *obj, void *data,
                                       QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    const int refused[] = { -1, 3, 5, 10, 11, 12, 13, 14, 15 };
    QDict *rsp;
    int i;

    for (i = 0; i < ARRAY_SIZE(refused); i++) {
        rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                        "'driver':'femu','id':'fdp-gcs','addr':'5',"
                        "'devsz_mb':1,'femu_mode':1,'secsz':512,"
                        "'secs_per_pg':8,'pgs_per_blk':4,'blks_per_pl':25,"
                        "'pls_per_lun':1,'luns_per_ch':2,'nchs':2,"
                        "'gc_strategy':%d,'subsys':'fdpsub'}}", refused[i]);
        g_assert_true(qdict_haskey(rsp, "error"));
        g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                             "desc"), "gc_strategy"));
        qobject_unref(rsp);
    }
    qos_invalidate_command_line();
}

/*
 * The capacity check sizes the namespaces against the whole reclaim unit
 * pool, which holds only while nothing else can draw on that pool: the
 * namespaces of the controller share it, and a second controller in the
 * subsystem is refused. Two 1 MiB namespaces on 25 lines would each fit and
 * together overcommit it.
 */
void femu_test_fdp_single_pool(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    QDict *rsp;

    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'fdp-two','addr':'5',"
                    "'devsz_mb':2,'namespaces':2,'femu_mode':1,'secsz':512,"
                    "'secs_per_pg':8,'pgs_per_blk':4,'blks_per_pl':25,"
                    "'pls_per_lun':1,'luns_per_ch':2,'nchs':2,"
                    "'subsys':'fdpsub'}}");
    g_assert_true(qdict_haskey(rsp, "error"));
    g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                         "desc"), "the 2 namespaces expose"));
    qobject_unref(rsp);

    /* one namespace that fits is accepted; a second controller is not */
    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'fdp-one','addr':'5',"
                    "'devsz_mb':1,'femu_mode':1,'secsz':512,"
                    "'secs_per_pg':8,'pgs_per_blk':4,'blks_per_pl':25,"
                    "'pls_per_lun':1,'luns_per_ch':2,'nchs':2,"
                    "'subsys':'fdpsub'}}");
    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'fdp-other','addr':'6',"
                    "'devsz_mb':1,'femu_mode':1,'secsz':512,"
                    "'secs_per_pg':8,'pgs_per_blk':4,'blks_per_pl':25,"
                    "'pls_per_lun':1,'luns_per_ch':2,'nchs':2,"
                    "'subsys':'fdpsub'}}");
    g_assert_true(qdict_haskey(rsp, "error"));
    g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                         "desc"), "single controller"));
    qobject_unref(rsp);
    qos_invalidate_command_line();
}

/*
 * A handle update moves the handle to a fresh reclaim unit. Only the unit's
 * remaining-writes count used to be reset, while the FTL went on writing into
 * the old unit, so the count ran out of step with the media. Units left part
 * written are then collected like any other.
 */
void femu_test_fdp_ruh_update(void *obj, void *data,
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
void femu_test_fdp_ruh_update_full(void *obj, void *data,
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
 * A handle update must leave collection the free unit it needs. Four
 * persistently isolated handles, 40 units of 16 pages, one unit kept free
 * for forced collection. 34 write-and-update pairs close 34 units holding
 * one valid page each, leaving 2 free; a page in each handle's new unit
 * keeps every active unit written. Two more updates would then take both
 * free units, and collection could not open a unit to move pages into, so
 * a 17-page write would fill its unit and fail with no unit to follow.
 * The namespace holds 55 live pages of 256.
 */
void femu_test_fdp_ruh_update_reserve(void *obj, void *data,
                                      QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 17 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t pids = guest_alloc(alloc, 4096);
    uint64_t mapped, lost, orphans;
    uint16_t pid;
    int k;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x6d, 17 * 4096);

    for (k = 0; k < 34; k++) {
        pid = cpu_to_le16(k % 4);
        qtest_memwrite(qts, pids, &pid, sizeof(pid));
        g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, k, 1, buf, list,
                                                        k % 4)), ==,
                        NVME_SUCCESS);
        g_assert_cmphex(femu_ruh_update(&c, pids, 1), ==, NVME_SUCCESS);
    }
    for (k = 0; k < 4; k++) {
        g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 34 + k, 1, buf,
                                                        list, k)), ==,
                        NVME_SUCCESS);
    }
    for (k = 0; k < 2; k++) {
        pid = cpu_to_le16(k);
        qtest_memwrite(qts, pids, &pid, sizeof(pid));
        g_assert_cmphex(femu_ruh_update(&c, pids, 1), ==, NVME_SUCCESS);
    }
    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 40, 17, buf, list, 0)),
                    ==, NVME_SUCCESS);

    femu_ftl_check(qts, &mapped, &lost, &orphans);
    g_assert_cmpuint(mapped, ==, 55);
    g_assert_cmpuint(lost, ==, 0);
    g_assert_cmpuint(orphans, ==, 0);
    g_assert_cmpuint(femu_fdp_check(qts), ==, 0);

    guest_free(alloc, pids);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * A handle update can leave a unit holding a single valid page: the rest of it
 * was never written, so it counts neither valid nor invalid. It then has the
 * fewest valid pages of any victim and sits at the top of the heap. Background
 * collection must not refuse it for having few invalid pages: it would stop
 * there on every pass, and a unit behind it with almost nothing valid would
 * wait for the forced watermark.
 *
 * Background collection runs on every command here (gc_thres_pcent=1) and
 * forced collection only with no unit free, which this workload never reaches.
 * A unit is four blocks of four pages.
 */
void femu_test_fdp_background_gc(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint16_t pid0 = cpu_to_le16(0);
    uint64_t buf = guest_alloc(alloc, 16 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t pids = guest_alloc(alloc, 4096);
    uint64_t i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x5a, 16 * 4096);
    qtest_memwrite(qts, pids, &pid0, sizeof(pid0));

    /* one page, then leave the unit: it retires holding 1 valid of 16 */
    g_assert_cmphex(FEMU_SC(femu_write_pages(&c, 100, 1, buf, list)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_ruh_update(&c, pids, 1), ==, NVME_SUCCESS);

    /* fill the next unit, then overwrite all but two of its pages */
    g_assert_cmphex(FEMU_SC(femu_write_pages(&c, 0, 16, buf, list)), ==,
                    NVME_SUCCESS);
    for (i = 0; i < 14; i++) {
        g_assert_cmphex(FEMU_SC(femu_write_pages(&c, i, 1, buf, list)), ==,
                        NVME_SUCCESS);
    }

    /*
     * Both units were collected: eight blocks erased, and the one page of the
     * first plus the two of the second that were still valid when it was
     * taken, which was as soon as it had two invalid pages.
     */
    g_assert_cmpuint(femu_ftl_trace_field(qts, 5), ==, 8);
    g_assert_cmpuint(femu_ftl_trace_field(qts, 4), ==, 15);

    guest_free(alloc, pids);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * Cost-benefit collection scores a unit by (1 - u) * age / u, with u the
 * share of the unit a collection copies and age the time since its last
 * invalidation. The tests below write a unit through placement 0, leave it
 * part written with a handle update, set up a competitor through placement
 * 1, and then fill the device through placement 3 until background
 * collection starts. A unit is four blocks of four pages; the competitor and
 * the part-written unit are the only victims.
 */
static void femu_fdp_cb_fill(FemuCtrlState *c, QTestState *qts, uint64_t buf,
                             uint64_t list, bool stop_at_erase)
{
    uint64_t page;

    for (page = 32; page < 256; page += 16) {
        g_assert_cmphex(FEMU_SC(femu_write_pages_placed(c, page, 16, buf, list,
                                                        3)), ==, NVME_SUCCESS);
        if (stop_at_erase && femu_ftl_trace_field(qts, 5)) {
            return;
        }
    }
}

/*
 * Cost-benefit multiplies each unit's score by its age, and the setup above
 * gives the units their ages a few writes apart. Wait ten times that gap, so
 * the ages are close to equal however slowly the host ran the setup.
 */
static void femu_fdp_cb_age(int64_t setup_start_us)
{
    int64_t gap = g_get_monotonic_time() - setup_start_us;

    g_usleep(MAX(20 * 1000, 10 * gap));
}

/*
 * A unit that was never invalidated has no last invalidation time. It used
 * to count as invalidated at time zero, so its age was the whole host clock
 * and it outscored every unit with an invalidation. Here it holds 15 valid
 * pages of 16, which background collection refuses as too little to gain, so
 * collection stopped at it on every pass, and a unit with 14 invalid pages
 * behind it was never taken.
 */
void femu_test_fdp_cb_unwritten_age(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint16_t pid0 = cpu_to_le16(0);
    uint64_t buf = guest_alloc(alloc, 16 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t pids = guest_alloc(alloc, 4096);
    int64_t setup_start;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x5a, 16 * 4096);
    qtest_memwrite(qts, pids, &pid0, sizeof(pid0));

    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 0, 15, buf, list, 0)),
                    ==, NVME_SUCCESS);
    setup_start = g_get_monotonic_time();
    g_assert_cmpint(femu_ruh_update(&c, pids, 1), ==, NVME_SUCCESS);
    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 16, 16, buf, list,
                                                    1)), ==, NVME_SUCCESS);
    for (i = 16; i < 30; i++) {
        g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, i, 1, buf, list,
                                                        2)), ==, NVME_SUCCESS);
    }
    femu_fdp_cb_age(setup_start);

    femu_fdp_cb_fill(&c, qts, buf, list, false);
    for (i = 0; i < 4; i++) {
        g_assert_cmphex(femu_read_pages(&c, i, 1, buf, list), ==,
                        NVME_SUCCESS);
    }
    /* the unit with 14 invalid pages: its 2 valid pages and 4 blocks */
    g_assert_cmpuint(femu_ftl_trace_field(qts, 4), ==, 2);
    g_assert_cmpuint(femu_ftl_trace_field(qts, 5), ==, 4);

    guest_free(alloc, pids);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    /* the next test counts from a device that has collected nothing */
    qos_invalidate_command_line();
}

/*
 * A unit left with 4 of its 16 pages written, then one of them overwritten,
 * gives back 13 pages for 3 copies. The overwrite used to measure its
 * utilization against the 4 written pages only, as 3 / 4, so a full unit
 * with half its pages valid outscored it. Utilization is now the share of
 * all 16 pages, as at retirement, and the part-written unit goes first.
 */
void femu_test_fdp_cb_utilization(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint16_t pid0 = cpu_to_le16(0);
    uint64_t buf = guest_alloc(alloc, 16 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t pids = guest_alloc(alloc, 4096);
    int64_t setup_start;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x5a, 16 * 4096);
    qtest_memwrite(qts, pids, &pid0, sizeof(pid0));

    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 0, 4, buf, list, 0)),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(femu_ruh_update(&c, pids, 1), ==, NVME_SUCCESS);
    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 16, 16, buf, list,
                                                    1)), ==, NVME_SUCCESS);
    /* half of the full unit, then one page of the part-written one */
    setup_start = g_get_monotonic_time();
    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 16, 8, buf, list, 2)),
                    ==, NVME_SUCCESS);
    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 0, 1, buf, list, 2)),
                    ==, NVME_SUCCESS);
    /* near-equal ages, so utilization decides */
    femu_fdp_cb_age(setup_start);

    femu_fdp_cb_fill(&c, qts, buf, list, true);
    g_assert_cmpuint(femu_ftl_trace_field(qts, 5), ==, 4);
    g_assert_cmpuint(femu_ftl_trace_field(qts, 4), ==, 3);

    guest_free(alloc, pids);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * mapping=dftl under FDP: a placed write charges the translation page of
 * each page it programs, as a line-mode write does. A translation page holds
 * 512 mappings of 4 KiB pages. Four writes, each to a page of a translation
 * page not cached yet, read four translation pages; two more writes to those
 * translation pages read none. @data is "dftl" or "page"; with page mapping
 * nothing is read.
 */
void femu_test_fdp_dftl(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    bool dftl = g_str_equal(data, "dftl");
    static const uint64_t cold[] = { 0, 512, 1024, 1536 };
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t log = guest_alloc(alloc, 4096);
    uint64_t rd0, pr0, rd1, pr1;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x3d, 4096);

    rd0 = femu_c0h_field(&c, log, 160);
    pr0 = femu_c0h_field(&c, log, 168);
    for (int i = 0; i < ARRAY_SIZE(cold); i++) {
        g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, cold[i], 1, buf,
                                                        list, i & 1)), ==,
                        NVME_SUCCESS);
    }
    rd1 = femu_c0h_field(&c, log, 160);
    pr1 = femu_c0h_field(&c, log, 168);
    g_test_message("%s: %" PRIu64 " reads, %" PRIu64 " programs",
                   (const char *)data, rd1 - rd0, pr1 - pr0);
    g_assert_cmpuint(rd1 - rd0, ==, dftl ? 4 : 0);
    g_assert_cmpuint(pr1 - pr0, ==, 4);

    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 1, 1, buf, list, 0)),
                    ==, NVME_SUCCESS);
    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 513, 1, buf, list,
                                                    1)), ==, NVME_SUCCESS);
    g_assert_cmpuint(femu_c0h_field(&c, log, 160), ==, rd1);

    qtest_memset(qts, buf, 0, 4096);
    g_assert_cmphex(femu_read_pages(&c, 512, 1, buf, list), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, buf + 4095), ==, 0x3d);

    guest_free(alloc, log);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * Which of two victims the first collection takes, for the policy that
 * gc_policy or gc_strategy selects. @data is "fifo", "cb" or "greedy" and
 * the pages that collection must move. Placement 0 fills unit A and
 * placement 1 fills unit B, in that order; placement 2 overwrites part of
 * each, and placement 3 then fills the device until the first erase.
 *   "fifo":   2 pages of A, 12 of B. Greedy takes B (4 valid); fifo takes
 *             A, retired first (14 valid).
 *   "cb":     8 pages of A, then a second later 10 of B. Greedy takes B
 *             (6 valid); cost-benefit takes A, whose age outweighs its
 *             share of valid pages: (1 - 1/2) * age_A / (1/2) is above
 *             (1 - 3/8) * age_B / (3/8) while age_B < 0.6 * age_A.
 *   "empty":  2 pages of A, all 16 of B. fifo takes the empty B first,
 *             which needs no destination unit.
 */
void femu_test_fdp_policy_pick(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    g_auto(GStrv) arg = g_strsplit(data, " ", 0);
    bool cb = g_str_equal(arg[0], "cb");
    bool empty = g_str_equal(arg[0], "empty");
    uint64_t want = g_ascii_strtoull(arg[1], NULL, 10);
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 16 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x5a, 16 * 4096);

    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 0, 16, buf, list, 0)),
                    ==, NVME_SUCCESS);
    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 16, 16, buf, list,
                                                    1)), ==, NVME_SUCCESS);
    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 0, cb ? 8 : 2, buf,
                                                    list, 2)), ==,
                    NVME_SUCCESS);
    if (cb) {
        g_usleep(1000 * 1000);
    }
    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 16,
                                                    cb ? 10 : empty ? 16 : 12,
                                                    buf, list, 2)), ==,
                    NVME_SUCCESS);
    g_assert_cmpuint(femu_ftl_trace_field(qts, 5), ==, 0);

    femu_fdp_cb_fill(&c, qts, buf, list, true);
    g_test_message("%s: %" PRIu64 " pages moved", (const char *)data,
                   femu_ftl_trace_field(qts, 4));
    g_assert_cmpuint(femu_ftl_trace_field(qts, 5), ==, 4);
    g_assert_cmpuint(femu_ftl_trace_field(qts, 4), ==, want);

    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * gc_policy and gc_strategy both pick the reclaim unit strategy under FDP,
 * so a controller may set one of them, on black box and CSD alike.
 */
void femu_test_fdp_policy_refused(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    int modes[] = { 1, 4 };
    QDict *rsp;

    for (int m = 0; m < ARRAY_SIZE(modes); m++) {
        g_autofree char *want = g_strdup_printf(
            "FEMU %s: set gc_policy or gc_strategy under FDP, not both",
            modes[m] == 1 ? "bbssd" : "csd");
        const char *desc;

        rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                        "'driver':'femu','id':'fdp-knob','addr':'5',"
                        "'devsz_mb':64,'femu_mode':%d,'fdm_size':16,"
                        "'secsz':512,'secs_per_pg':8,'pgs_per_blk':16,"
                        "'blks_per_pl':80,'pls_per_lun':1,"
                        "'luns_per_ch':4,'nchs':4,'subsys':'fdpsub',"
                        "'gc_policy':'fifo','gc_strategy':1}}", modes[m]);
        g_assert_true(qdict_haskey(rsp, "error"));
        desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
        g_assert_nonnull(strstr(desc, want));
        qobject_unref(rsp);
    }
    qos_invalidate_command_line();
}

/*
 * fifo in a background pass: unit A, retired first, has one invalid page
 * and unit B two. A background pass refuses A, which frees too little, and
 * used to stop there on every pass; it now takes B, the oldest unit it
 * accepts: 14 pages moved, 4 blocks erased.
 */
void femu_test_fdp_fifo_background(void *obj, void *data,
                                   QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 16 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x5a, 16 * 4096);

    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 0, 16, buf, list, 0)),
                    ==, NVME_SUCCESS);
    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 16, 16, buf, list,
                                                    1)), ==, NVME_SUCCESS);
    /* past the background watermark, with no victim yet */
    femu_fdp_cb_fill(&c, qts, buf, list, false);
    g_assert_cmpuint(femu_ftl_trace_field(qts, 5), ==, 0);

    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 0, 1, buf, list, 2)),
                    ==, NVME_SUCCESS);
    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 16, 2, buf, list, 2)),
                    ==, NVME_SUCCESS);
    g_assert_cmpuint(femu_ftl_trace_field(qts, 5), ==, 4);
    g_assert_cmpuint(femu_ftl_trace_field(qts, 4), ==, 14);

    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * Cost-benefit can rank a unit that background collection refuses above
 * one it would take. Here a unit with 15 valid pages of 16 outscores one
 * with 14 valid pages while the second's age is under 7 / 15 of the
 * first's. The background pass used to refuse the first and return
 * nothing, so the second waited until its age caught up or the foreground
 * watermark.
 */
#define FDP_CB_BG_WAIT_US   (300 * 1000)

void femu_test_fdp_cb_background(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 16 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    int64_t old_done;
    int64_t submit;
    int64_t done;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x5a, 16 * 4096);

    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 0, 16, buf, list, 0)),
                    ==, NVME_SUCCESS);
    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 16, 16, buf, list,
                                                    1)), ==, NVME_SUCCESS);
    /* past the background watermark, with no victim yet */
    femu_fdp_cb_fill(&c, qts, buf, list, false);
    g_assert_cmpuint(femu_ftl_trace_field(qts, 5), ==, 0);

    /* one invalid page: every background pass refuses this unit */
    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 0, 1, buf, list, 2)),
                    ==, NVME_SUCCESS);
    old_done = g_get_monotonic_time();
    g_usleep(FDP_CB_BG_WAIT_US);

    /*
     * The pass that decides runs in this command, after both invalidations.
     * At that moment the first unit's age is at least submit - old_done and
     * the second's at most done - submit.
     */
    submit = g_get_monotonic_time();
    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 16, 2, buf, list, 2)),
                    ==, NVME_SUCCESS);
    done = g_get_monotonic_time();

    /*
     * Two invalid pages are the fewest a background pass takes, so the
     * refused unit leads by the widest margin. Collected: 14 pages, 4 blocks.
     */
    g_assert_cmpuint(femu_ftl_trace_field(qts, 5), ==, 4);
    g_assert_cmpuint(femu_ftl_trace_field(qts, 4), ==, 14);

    /*
     * The old selector takes the second unit too once it outscores the
     * first, so the result only shows the fix if the first still led.
     */
    if (15 * (done - submit) >= 7 * (submit - old_done)) {
        g_test_skip("host too slow: the refused unit may not have led "
                    "the cost-benefit ranking");
    }

    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * Write Zeroes without the deallocate bit leaves the blocks holding written
 * zeros, so the device owes the programs that put them there. The placement
 * path returned without touching the media at all, so the command cost
 * nothing and counted nothing, while the ordinary path programmed the range.
 */
void femu_test_fdp_write_zeroes(void *obj, void *data,
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
void femu_test_fdp_features(void *obj, void *data,
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
    g_assert_cmphex(femu_write_block_placed(&c, 0, pids, 0), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_write_block_placed(&c, 8, pids, 1), ==, NVME_SUCCESS);
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

#define FEMU_LOG_FDP_RUH_USAGE  0x21
#define FEMU_RUHU_HDR           8
#define FEMU_RUHU_DESCR         8

/*
 * The Reclaim Unit Handle Usage log is an 8 byte header and one 8 byte
 * descriptor per handle, holding only the attributes byte (TP4146). Every
 * handle backs a placement handle of the namespace, so each
 * reads host specified. Counters written into the descriptors shifted every
 * handle after the first onto them, which a write makes non-zero.
 */
void femu_test_fdp_ruh_usage(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    const uint32_t nruh = 4;
    const uint32_t size = FEMU_RUHU_HDR + nruh * FEMU_RUHU_DESCR;
    uint8_t page[64];
    uint64_t buf, log;
    uint32_t i, j;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    buf = guest_alloc(alloc, 2 * 4096);
    log = guest_alloc(alloc, 4096);
    qtest_memset(qts, buf, 0x5a, 2 * 4096);
    g_assert_cmpint(femu_write_8k(&c, buf, 0, 2), ==, NVME_SUCCESS);

    qtest_memset(qts, log, 0xff, 4096);
    g_assert_cmpint(femu_endgrp_log(&c, FEMU_LOG_FDP_RUH_USAGE, 0, log,
                                    sizeof(page)), ==, NVME_SUCCESS);
    qtest_memread(qts, log, page, sizeof(page));

    g_assert_cmpint(lduw_le_p(page), ==, nruh);
    for (j = 2; j < FEMU_RUHU_HDR; j++) {
        g_assert_cmpint(page[j], ==, 0);
    }
    for (i = 0; i < nruh; i++) {
        const uint8_t *d = page + FEMU_RUHU_HDR + i * FEMU_RUHU_DESCR;

        g_assert_cmpint(d[0], ==, NVME_RUHA_HOST);
        for (j = 1; j < FEMU_RUHU_DESCR; j++) {
            g_assert_cmpint(d[j], ==, 0);
        }
    }
    /* nothing is transferred past the end of the log */
    for (j = size; j < sizeof(page); j++) {
        g_assert_cmpint(page[j], ==, 0xff);
    }

    /* a read at an offset starts at that byte: the last descriptor */
    qtest_memset(qts, log, 0xff, 4096);
    g_assert_cmpint(femu_endgrp_log(&c, FEMU_LOG_FDP_RUH_USAGE,
                                    size - FEMU_RUHU_DESCR, log, 16), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, log, page, 16);
    g_assert_cmpint(page[0], ==, NVME_RUHA_HOST);
    for (j = 1; j < FEMU_RUHU_DESCR; j++) {
        g_assert_cmpint(page[j], ==, 0);
    }
    for (j = FEMU_RUHU_DESCR; j < 16; j++) {
        g_assert_cmpint(page[j], ==, 0xff);
    }

    /* the log ends after the last descriptor */
    g_assert_cmpint(femu_endgrp_log(&c, FEMU_LOG_FDP_RUH_USAGE, size, log, 4),
                    ==, NVME_INVALID_FIELD);

    guest_free(alloc, log);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * RUH Update on a CSD namespace moves the handle to a fresh unit, as on a
 * BlackBox one. It used to reset only the RUAMW of the unit the FTL kept
 * writing. 128-page units: 2 pages, an update (full room, the unit check
 * holds, host event 0h for the part-written unit), then 1 page. With
 * @data "buffer" the pages are held: the update writes the 2 pages to the
 * old unit first, and the last page reaches the unit at a Flush.
 */
void femu_test_fdp_csd_ruh_update(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    bool held = data && !strcmp(data, "buffer");
    uint16_t ruhid = 0xffff;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 2 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t log = guest_alloc(alloc, 4096);
    uint64_t pids = guest_alloc(alloc, 4096);
    uint64_t bpp = 4096 / 512;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x77, 2 * 4096);
    qtest_writew(qts, pids, 0);
    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 0, 2, buf, list, 0)),
                    ==, NVME_SUCCESS);
    g_assert_cmpuint(femu_c0h_field(&c, log, 24), ==, held ? 0 : 2);
    g_assert_cmpuint(femu_ruh_ruamw(&c, log, 0), ==, (held ? 128 : 126) * bpp);
    g_assert_cmpint(femu_ruh_update(&c, pids, 1), ==, NVME_SUCCESS);
    g_assert_cmpuint(femu_c0h_field(&c, log, 24), ==, 2);
    g_assert_cmpuint(femu_ruh_ruamw(&c, log, 0), ==, 128 * bpp);
    g_assert_cmpuint(femu_fdp_check(qts), ==, 0);
    g_assert_cmpint(femu_pd2_events(&c, log, true, 0x00, &ruhid), ==, 1);
    g_assert_cmpint(ruhid, ==, 0);
    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 2, 1, buf, list, 0)),
                    ==, NVME_SUCCESS);
    if (held) {
        g_assert_cmpuint(femu_ruh_ruamw(&c, log, 0), ==, 128 * bpp);
        g_assert_cmphex(femu_fdp_wb_flush(&c), ==, NVME_SUCCESS);
    }
    g_assert_cmpuint(femu_ruh_ruamw(&c, log, 0), ==, 127 * bpp);
    g_assert_cmpuint(femu_fdp_check(qts), ==, 0);
    qtest_memset(qts, buf, 0, 4096);
    g_assert_cmphex(femu_read_pages(&c, 1, 1, buf, list), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, buf + 4095), ==, 0x77);

    guest_free(alloc, pids);
    guest_free(alloc, log);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * Read reclaim and retention refresh under FDP. Placement 0 fills unit A
 * (128 pages), which retires full. The read path then queues A, and the
 * next write, through placement 1, refreshes A into handle 0's own
 * collection unit. @data selects the case:
 *   "reads":    read_reclaim_limit=8, eight reads of page 0
 *   "age":      retention_limit_sec at age_scale 10^6, one read of page 0
 *   "open":     the reads hit A while it is still the active unit, so the
 *               request is dropped; after A retires, nothing refreshes it
 *   "copyback": gc_copyback=on; the refresh still reads every page
 *   "off":      no knob; eight reads queue nothing
 *   "victim":   16 pages of A are overwritten first, so A waits on a victim
 *               heap (greedy, cost-benefit or per handle, by gc_strategy)
 *               when the refresh takes it; 112 pages move
 *   "gcqueue":  gc_copyback=on and background collection on every command.
 *               A Deallocate of 120 pages of the queued A makes it a victim,
 *               and collection takes it before any write: 8 pages move with
 *               no copyback, and no refresh is counted
 * Afterwards overwrite passes, 56 units of writes, make collection erase, so a
 * unit left on two lists shows up as a lost page, a failed write or an
 * x-fdp-check count.
 */
void femu_test_fdp_refresh(void *obj, void *data,
                           QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    const char *mode = data;
    bool age = !strcmp(mode, "age");
    bool open = !strcmp(mode, "open");
    bool off = !strcmp(mode, "off");
    bool victim = !strcmp(mode, "victim");
    bool gcq = !strcmp(mode, "gcqueue");
    uint64_t moved = victim ? 112 : 128;
    uint64_t host = victim ? 160 : 144;
    uint64_t span = gcq ? 512 : 1024;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 16 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t log = guest_alloc(alloc, 4096);
    uint64_t gc0, rr0, rt0, cb0, ruamw3, gc, rr, rt, cb, hbmw, mbmw;
    uint64_t mapped, lost, orphans;
    uint64_t hosts[8];
    uint64_t lpn;
    uint8_t st[64];
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x6d, 16 * 4096);
    if (open) {
        /* A is the active unit: reads now, the rest of A afterwards */
        g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 0, 16, buf, list,
                                                        0)), ==, NVME_SUCCESS);
        for (i = 0; i < 8; i++) {
            g_assert_cmphex(femu_rw(&c, NVME_CMD_READ, 0, buf), ==,
                            NVME_SUCCESS);
        }
        for (lpn = 16; lpn < 128; lpn += 16) {
            g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, lpn, 16, buf,
                                                            list, 0)), ==,
                            NVME_SUCCESS);
        }
    } else {
        for (lpn = 0; lpn < 128; lpn += 16) {
            g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, lpn, 16, buf,
                                                            list, 0)), ==,
                            NVME_SUCCESS);
        }
        if (victim) {
            g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 112, 16, buf,
                                                            list, 1)), ==,
                            NVME_SUCCESS);
        }
        g_usleep(10 * 1000);
        for (i = 0; i < (age ? 1 : 8); i++) {
            g_assert_cmphex(femu_rw(&c, NVME_CMD_READ, 0, buf), ==,
                            NVME_SUCCESS);
        }
    }

    gc0 = femu_c0h_field(&c, log, 16);
    rr0 = femu_c0h_field(&c, log, 40);
    rt0 = femu_c0h_field(&c, log, 48);
    cb0 = femu_c0h_field(&c, log, 248);
    ruamw3 = femu_ruh_ruamw(&c, log, 3);
    qtest_memset(qts, buf, 0x6d, 16 * 4096);
    if (gcq) {
        g_assert_cmphex(femu_dealloc_pages(&c, 8, 120, list), ==,
                        NVME_SUCCESS);
    }
    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 128, 16, buf, list,
                                                    1)), ==, NVME_SUCCESS);
    gc = femu_c0h_field(&c, log, 16) - gc0;
    rr = femu_c0h_field(&c, log, 40) - rr0;
    rt = femu_c0h_field(&c, log, 48) - rt0;
    cb = femu_c0h_field(&c, log, 248) - cb0;
    g_test_message("FDP refresh %s: %" PRIu64 " read reclaims, %" PRIu64
                   " retention refreshes, %" PRIu64 " pages moved, %" PRIu64
                   " by copyback", mode, rr, rt, gc, cb);

    /* media bytes are host bytes plus the moves */
    g_assert_cmpint(femu_endgrp_log(&c, FEMU_LOG_FDP_STATS, 0, log,
                                    sizeof(st)), ==, NVME_SUCCESS);
    qtest_memread(qts, log, st, sizeof(st));
    hbmw = ldq_le_p(st);
    mbmw = ldq_le_p(st + 16);
    g_assert_cmpuint(hbmw, ==, host * 4096);
    g_assert_cmpuint(mbmw, ==, hbmw + gc * 4096);

    if (open || off) {
        g_assert_cmpuint(rr + rt, ==, 0);
        g_assert_cmpuint(gc, ==, 0);
    } else if (gcq) {
        /* collection took the queued unit: no copyback, no refresh counted */
        g_assert_cmpuint(rr + rt, ==, 0);
        g_assert_cmpuint(gc, ==, 8);
        g_assert_cmpuint(cb, ==, 0);
    } else {
        g_assert_cmpuint(rr, ==, age ? 0 : 1);
        g_assert_cmpuint(rt, ==, age ? 1 : 0);
        g_assert_cmpuint(gc, ==, moved);
        /* no copyback: the refresh passes every page through the controller */
        g_assert_cmpuint(cb, ==, 0);
        /* handle 0 is persistently isolated: its pages stay with it */
        g_assert_cmpuint(femu_fdp_handle_vpc(qts, 0), ==, moved);
        g_assert_cmpuint(femu_fdp_handle_vpc(qts, 3), ==, 0);
        g_assert_cmpuint(femu_ruh_ruamw(&c, log, 3), ==, ruamw3);
    }

    femu_ftl_check(qts, &mapped, &lost, &orphans);
    g_assert_cmpuint(mapped, ==, gcq ? 24 : 144);
    /* every unit's state agrees with the lists and heaps that count it */
    femu_query_check_fdp(&c, log, gcq ? 24 : 144, hosts);
    g_assert_cmpuint(femu_fdp_check(qts), ==, 0);
    g_assert_cmpuint(lost, ==, 0);
    g_assert_cmpuint(orphans, ==, 0);
    g_assert_cmphex(femu_rw(&c, NVME_CMD_READ, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, buf), ==, 0x6d);
    g_assert_cmphex(qtest_readb(qts, buf + 511), ==, 0x6d);

    /*
     * One full pass over the namespace, then twelve over half of its 16-page
     * chunks, each in its own order (37 and the chunk count are coprime).
     * Free units fall below the collection threshold, so collection must
     * take units from the heaps the refresh touched and erase them.
     */
    g_assert_cmpint(femu_endgrp_log(&c, FEMU_LOG_FDP_STATS, 0, log,
                                    sizeof(st)), ==, NVME_SUCCESS);
    qtest_memread(qts, log, st, sizeof(st));
    gc0 = ldq_le_p(st + 32);
    for (i = 0; i < 13; i++) {
        uint64_t chunks = span / 16;

        for (uint64_t j = 0; j < (i ? chunks / 2 : chunks); j++) {
            lpn = ((j * 37 + i * 11) % chunks) * 16;
            g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, lpn, 16, buf,
                                                            list, i & 1)), ==,
                            NVME_SUCCESS);
        }
    }
    femu_ftl_check(qts, &mapped, &lost, &orphans);
    g_assert_cmpuint(mapped, ==, span);
    g_assert_cmpint(femu_endgrp_log(&c, FEMU_LOG_FDP_STATS, 0, log,
                                    sizeof(st)), ==, NVME_SUCCESS);
    qtest_memread(qts, log, st, sizeof(st));
    g_assert_cmpuint(ldq_le_p(st + 32), >, gc0);
    femu_query_check_fdp(&c, log, span, hosts);
    g_assert_cmpuint(femu_fdp_check(qts), ==, 0);
    if (gcq) {
        /* the request died with the unit; reuse must not revive it */
        g_assert_cmpuint(femu_c0h_field(&c, log, 40) - rr0, ==, 0);
    }
    g_assert_cmpuint(lost, ==, 0);
    g_assert_cmpuint(orphans, ==, 0);

    guest_free(alloc, log);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/* one logical block @lba through placement @pid */
static uint16_t femu_fdp_wb_block(FemuCtrlState *c, uint64_t lba,
                                  uint64_t data, int pid)
{
    NvmeRwCmd rw;

    memset(&rw, 0, sizeof(rw));
    rw.opcode = NVME_CMD_WRITE;
    rw.nsid = cpu_to_le32(1);
    rw.dptr.prp1 = cpu_to_le64(data);
    rw.slba = cpu_to_le64(lba);
    rw.control = cpu_to_le16(2 << 4);
    rw.dspec = cpu_to_le16(pid);
    return FEMU_SC(femu_io(c, (NvmeCmd *)&rw));
}

/* the host and media bytes query-femu reports for handle @h */
static void femu_fdp_handle_bytes(QTestState *qts, int h, uint64_t *host,
                                  uint64_t *media)
{
    QDict *rsp;
    QDict *ns = femu_query_ns(qts, "'kind':'reclaim-units','limit':4096",
                              &rsp);
    QList *handles = qdict_get_qlist(qdict_get_qdict(ns, "fdp"), "handles");
    QListEntry *e;

    QLIST_FOREACH_ENTRY(handles, e) {
        QDict *d = qobject_to(QDict, qlist_entry_obj(e));

        if (qdict_get_int(d, "id") == h) {
            *host = qdict_get_int(d, "host-bytes");
            *media = qdict_get_int(d, "media-bytes");
        }
    }
    qobject_unref(rsp);
}

/* mapped pages, after checking that no mapping or unit is broken */
static uint64_t femu_fdp_wb_mapped(QTestState *qts)
{
    uint64_t mapped, lost, orphans;

    femu_ftl_check(qts, &mapped, &lost, &orphans);
    g_assert_cmpuint(lost, ==, 0);
    g_assert_cmpuint(orphans, ==, 0);
    g_assert_cmpuint(femu_fdp_check(qts), ==, 0);
    return mapped;
}

/*
 * The write buffer under FDP. Each page keeps the placement handle of its
 * last write and goes to that handle's unit when it is written back. A
 * reclaim unit is one 128-page line. @data selects the case; C0h 24 is the
 * pages programmed for the host.
 *   "isolation": 24 pages through placement 0 and 40 through placement 1,
 *                interleaved, then 8 pages of each again: 80 accepted, all
 *                held (buffer_size=128). Nothing is programmed until Flush,
 *                which programs 64. Handle 0's units hold 24 valid pages and
 *                handle 1's 40, and RUAMW of each handle's unit drops by
 *                just those. Host bytes count 80 pages, media bytes 64.
 *                "isolation-csd" runs it on a CSD namespace.
 *   "rehandle":  page 0 through placement 0, then through placement 1, and
 *                the two halves of page 1 each through one; the FTL maps
 *                whole pages, so the last write's handle takes each page.
 *   "dealloc":   16 pages held; 8 deallocated and 4 written as zeros
 *                (programmed at once); Flush programs the last 4.
 *   "fua":       8 pages held; an FUA write of 4 of them through placement
 *                1 programs them at once; Flush programs the other 4.
 *   "vwc":       8 pages held; disabling the volatile write cache programs
 *                them with no later write.
 *   "update":    8 pages held for handle 0; RUH Update of placement 0
 *                programs them into the unit the handle had, not its new one.
 *   "update-suspend": "update" with pe_suspend. A read can move the
 *                programs of the RUH Update, so the next Flush, with an
 *                empty buffer, still seals the LUNs: one seal, and no
 *                program ends after the Flush (x-flush-check).
 *   "full":      64 pages in one command into a 16-page buffer: the write
 *                writes back on its own, and at most 16 pages stay held.
 *   "copy":      4 pages held for handle 1; a Copy of them, unplaced, reads
 *                them from the buffer and is held too; Flush programs 8. An
 *                FUA Copy programs its 4 pages at once.
 */
void femu_test_fdp_buffer(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    const char *mode = data;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 16 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t log = guest_alloc(alloc, 4096);
    uint64_t host, media;
    uint8_t st[64];

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x6b, 16 * 4096);

    if (g_str_has_prefix(mode, "isolation")) {
        /* query-femu does not report the units of a CSD namespace */
        bool csd = g_str_has_suffix(mode, "csd");
        uint32_t bpp = 4096 / c.lba_size;
        uint64_t hit0;

        for (int i = 0; i < 40; i++) {
            if (i < 24) {
                g_assert_cmphex(femu_fdp_wb_write(&c, i, 1, buf, list, 0,
                                                  false), ==, NVME_SUCCESS);
            }
            g_assert_cmphex(femu_fdp_wb_write(&c, 100 + i, 1, buf, list, 1,
                                              false), ==, NVME_SUCCESS);
        }
        g_assert_cmphex(femu_fdp_wb_write(&c, 0, 8, buf, list, 0, false), ==,
                        NVME_SUCCESS);
        g_assert_cmphex(femu_fdp_wb_write(&c, 100, 8, buf, list, 1, false), ==,
                        NVME_SUCCESS);
        g_assert_cmpuint(femu_c0h_field(&c, log, 24), ==, 0);
        g_assert_cmpuint(femu_c0h_field(&c, log, 72), ==, 80);
        g_assert_cmpuint(femu_c0h_field(&c, log, 80), ==, 16);
        /* a held page is read from the buffer */
        hit0 = femu_c0h_field(&c, log, 64);
        qtest_memset(qts, buf, 0, 4096);
        g_assert_cmphex(femu_read_pages(&c, 120, 1, buf, list), ==,
                        NVME_SUCCESS);
        g_assert_cmphex(qtest_readb(qts, buf + 4095), ==, 0x6b);
        g_assert_cmpuint(femu_c0h_field(&c, log, 64), ==, hit0 + 1);

        g_assert_cmphex(femu_fdp_wb_flush(&c), ==, NVME_SUCCESS);
        g_assert_cmpuint(femu_c0h_field(&c, log, 24), ==, 64);
        /* each handle's 128-page unit took its own pages and no others */
        g_assert_cmpuint(femu_ruh_ruamw(&c, log, 0), ==, (128 - 24) * bpp);
        g_assert_cmpuint(femu_ruh_ruamw(&c, log, 1), ==, (128 - 40) * bpp);
        g_assert_cmpuint(femu_ruh_ruamw(&c, log, 2), ==, 128 * bpp);
        g_assert_cmpuint(femu_fdp_wb_mapped(qts), ==, 64);
        if (!csd) {
            g_assert_cmpuint(femu_fdp_handle_vpc(qts, 0), ==, 24);
            g_assert_cmpuint(femu_fdp_handle_vpc(qts, 1), ==, 40);
            femu_fdp_handle_bytes(qts, 0, &host, &media);
            g_assert_cmpuint(host, ==, 32 * 4096);
            g_assert_cmpuint(media, ==, 24 * 4096);
            femu_fdp_handle_bytes(qts, 1, &host, &media);
            g_assert_cmpuint(host, ==, 48 * 4096);
            g_assert_cmpuint(media, ==, 40 * 4096);
        }
        g_assert_cmpint(femu_endgrp_log(&c, FEMU_LOG_FDP_STATS, 0, log,
                                        sizeof(st)), ==, NVME_SUCCESS);
        qtest_memread(qts, log, st, sizeof(st));
        g_assert_cmpuint(ldq_le_p(st), ==, 80 * 4096);
        g_assert_cmpuint(ldq_le_p(st + 16), ==, 64 * 4096);
        /* a second Flush has nothing to do */
        g_assert_cmphex(femu_fdp_wb_flush(&c), ==, NVME_SUCCESS);
        g_assert_cmpuint(femu_c0h_field(&c, log, 24), ==, 64);
        qtest_memset(qts, buf, 0, 4096);
        g_assert_cmphex(femu_read_pages(&c, 23, 1, buf, list), ==,
                        NVME_SUCCESS);
        g_assert_cmphex(qtest_readb(qts, buf), ==, 0x6b);
    } else if (!strcmp(mode, "rehandle")) {
        g_assert_cmphex(femu_fdp_wb_write(&c, 0, 1, buf, list, 0, false), ==,
                        NVME_SUCCESS);
        g_assert_cmphex(femu_fdp_wb_write(&c, 0, 1, buf, list, 1, false), ==,
                        NVME_SUCCESS);
        g_assert_cmphex(femu_fdp_wb_block(&c, 4096 / c.lba_size, buf, 0), ==,
                        NVME_SUCCESS);
        g_assert_cmphex(femu_fdp_wb_block(&c, 4096 / c.lba_size + 1, buf, 1),
                        ==, NVME_SUCCESS);
        g_assert_cmphex(femu_fdp_wb_flush(&c), ==, NVME_SUCCESS);
        g_assert_cmpuint(femu_c0h_field(&c, log, 24), ==, 2);
        g_assert_cmpuint(femu_fdp_handle_vpc(qts, 0), ==, 0);
        g_assert_cmpuint(femu_fdp_handle_vpc(qts, 1), ==, 2);
        g_assert_cmpuint(femu_fdp_wb_mapped(qts), ==, 2);
    } else if (!strcmp(mode, "dealloc")) {
        g_assert_cmphex(femu_fdp_wb_write(&c, 0, 16, buf, list, 0, false), ==,
                        NVME_SUCCESS);
        g_assert_cmphex(femu_dealloc_pages(&c, 0, 8, list), ==, NVME_SUCCESS);
        g_assert_cmphex(femu_write_zeroes(&c, 8 * (4096 / c.lba_size),
                                          4 * (4096 / c.lba_size)), ==,
                        NVME_SUCCESS);
        g_assert_cmpuint(femu_c0h_field(&c, log, 24), ==, 4);
        g_assert_cmphex(femu_fdp_wb_flush(&c), ==, NVME_SUCCESS);
        g_assert_cmpuint(femu_c0h_field(&c, log, 24), ==, 8);
        g_assert_cmpuint(femu_fdp_wb_mapped(qts), ==, 8);
    } else if (!strcmp(mode, "fua")) {
        g_assert_cmphex(femu_fdp_wb_write(&c, 0, 8, buf, list, 0, false), ==,
                        NVME_SUCCESS);
        g_assert_cmpuint(femu_c0h_field(&c, log, 24), ==, 0);
        g_assert_cmphex(femu_fdp_wb_write(&c, 0, 4, buf, list, 1, true), ==,
                        NVME_SUCCESS);
        g_assert_cmpuint(femu_c0h_field(&c, log, 24), ==, 4);
        g_assert_cmphex(femu_fdp_wb_flush(&c), ==, NVME_SUCCESS);
        g_assert_cmpuint(femu_c0h_field(&c, log, 24), ==, 8);
        g_assert_cmpuint(femu_fdp_handle_vpc(qts, 0), ==, 4);
        g_assert_cmpuint(femu_fdp_handle_vpc(qts, 1), ==, 4);
        g_assert_cmpuint(femu_fdp_wb_mapped(qts), ==, 8);
    } else if (!strcmp(mode, "vwc")) {
        g_assert_cmphex(femu_fdp_wb_write(&c, 0, 8, buf, list, 0, false), ==,
                        NVME_SUCCESS);
        g_assert_cmpuint(femu_c0h_field(&c, log, 24), ==, 0);
        g_assert_cmpint(femu_set_feature(&c, NVME_VOLATILE_WRITE_CACHE, false,
                                         0, 0, NULL), ==, NVME_SUCCESS);
        g_assert_cmpuint(femu_c0h_field(&c, log, 24), ==, 8);
        /* with the cache off a write goes straight to the media */
        g_assert_cmphex(femu_fdp_wb_write(&c, 8, 1, buf, list, 0, false), ==,
                        NVME_SUCCESS);
        g_assert_cmpuint(femu_c0h_field(&c, log, 24), ==, 9);
        g_assert_cmpuint(femu_fdp_wb_mapped(qts), ==, 9);
    } else if (!strcmp(mode, "update-suspend")) {
        uint16_t pid0 = cpu_to_le16(0);
        uint64_t v[FLUSH_FIELDS];

        g_assert_cmphex(femu_fdp_wb_write(&c, 0, 8, buf, list, 0, false), ==,
                        NVME_SUCCESS);
        qtest_memwrite(qts, log, &pid0, sizeof(pid0));
        g_assert_cmpint(femu_ruh_update(&c, log, 1), ==, NVME_SUCCESS);
        g_assert_cmpuint(femu_c0h_field(&c, log, 24), ==, 8);
        femu_flush_check(qts, v);
        g_assert_cmpuint(v[FLUSH_SEALS], ==, 0);
        g_assert_cmpuint(v[FLUSH_PE_END], >, 0);
        g_assert_cmphex(femu_fdp_wb_flush(&c), ==, NVME_SUCCESS);
        femu_flush_check(qts, v);
        /* the buffer was empty, but the RUH Update programs were not sealed */
        g_assert_cmpuint(v[FLUSH_SEALS], ==, 1);
        g_assert_cmpuint(v[FLUSH_PE_END], <=, v[FLUSH_DONE]);
        g_assert_cmpuint(femu_fdp_wb_mapped(qts), ==, 8);
    } else if (!strcmp(mode, "update")) {
        uint16_t pid0 = cpu_to_le16(0);

        g_assert_cmphex(femu_fdp_wb_write(&c, 0, 8, buf, list, 0, false), ==,
                        NVME_SUCCESS);
        g_assert_cmpuint(femu_fdp_open_vpc(qts, 0), ==, 0);
        qtest_memwrite(qts, log, &pid0, sizeof(pid0));
        g_assert_cmpint(femu_ruh_update(&c, log, 1), ==, NVME_SUCCESS);
        g_assert_cmpuint(femu_c0h_field(&c, log, 24), ==, 8);
        g_assert_cmpuint(femu_fdp_handle_vpc(qts, 0), ==, 8);
        g_assert_cmpuint(femu_fdp_open_vpc(qts, 0), ==, 0);
        g_assert_cmphex(femu_fdp_wb_flush(&c), ==, NVME_SUCCESS);
        g_assert_cmpuint(femu_c0h_field(&c, log, 24), ==, 8);
        g_assert_cmpuint(femu_fdp_open_vpc(qts, 0), ==, 0);
        g_assert_cmpuint(femu_fdp_wb_mapped(qts), ==, 8);
    } else if (!strcmp(mode, "copy")) {
        uint32_t bpp = 4096 / c.lba_size;
        uint64_t src = 0;
        uint16_t nlb = 4 * bpp;
        uint64_t hit0;

        g_assert_cmphex(femu_fdp_wb_write(&c, 0, 4, buf, list, 1, false), ==,
                        NVME_SUCCESS);
        hit0 = femu_c0h_field(&c, log, 64);
        g_assert_cmphex(FEMU_SC(femu_copy(&c, list, 16 * bpp, &src, &nlb, 1,
                                          1, 0)), ==, NVME_SUCCESS);
        g_assert_cmpuint(femu_c0h_field(&c, log, 64), ==, hit0 + 4);
        g_assert_cmpuint(femu_c0h_field(&c, log, 24), ==, 0);
        g_assert_cmphex(femu_fdp_wb_flush(&c), ==, NVME_SUCCESS);
        g_assert_cmpuint(femu_c0h_field(&c, log, 24), ==, 8);
        g_assert_cmpuint(femu_fdp_handle_vpc(qts, 0), ==, 4);
        g_assert_cmpuint(femu_fdp_handle_vpc(qts, 1), ==, 4);
        g_assert_cmphex(FEMU_SC(femu_copy(&c, list, 32 * bpp, &src, &nlb, 1,
                                          1, NVME_RW_FUA << 16)), ==,
                        NVME_SUCCESS);
        g_assert_cmpuint(femu_c0h_field(&c, log, 24), ==, 12);
        g_assert_cmpuint(femu_fdp_wb_mapped(qts), ==, 12);
        qtest_memset(qts, buf, 0, 4096);
        g_assert_cmphex(femu_read_pages(&c, 35, 1, buf, list), ==,
                        NVME_SUCCESS);
        g_assert_cmphex(qtest_readb(qts, buf + 4095), ==, 0x6b);
    } else if (!strcmp(mode, "full")) {
        uint64_t nand;

        g_assert_cmphex(femu_fdp_wb_write(&c, 0, 64, buf, list, 0, false), ==,
                        NVME_SUCCESS);
        nand = femu_c0h_field(&c, log, 24);
        g_test_message("full: %" PRIu64 " of 64 pages programmed", nand);
        g_assert_cmpuint(64 - nand, <=, 16);
        g_assert_cmpuint(femu_c0h_field(&c, log, 208), ==, 1);
        g_assert_cmphex(femu_fdp_wb_flush(&c), ==, NVME_SUCCESS);
        g_assert_cmpuint(femu_c0h_field(&c, log, 24), ==, 64);
        g_assert_cmpuint(femu_fdp_handle_vpc(qts, 0), ==, 64);
        g_assert_cmpuint(femu_fdp_wb_mapped(qts), ==, 64);
    } else {
        g_assert_not_reached();
    }

    guest_free(alloc, log);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    /* the cases share a device line and count from a fresh device */
    qos_invalidate_command_line();
}

/*
 * Copyback in FDP collection, on the geometry of femu_test_gc_copyback() with
 * an 11 MiB namespace: a reclaim unit is one 128-page line over 2 channels x
 * 2 LUNs, and collection starts with half the units in use. A transfer
 * takes 2 ms and every array step 0.1 ms. Placement 0 fills a unit, half of
 * it is deallocated, and placement 1 writes until collection has moved its
 * 64 valid pages. "pi" collects into the handle's own collection unit.
 * "ii" (fdpsub-ii) writes the victim through placement 3, the Initially
 * Isolated last handle, and 16 more pages after it, so collection writes
 * into that handle's active unit, part used: 16 + 64 of its 128 pages. RUAMW
 * counts the moves too, so it shows 48 pages of room, and 48 more host pages
 * through placement 3 fill that unit: the handle shows a fresh one. On, every
 * move finds its
 * destination die; off, every move puts two transfers on the channels. The
 * media byte counters must show the moves.
 *
 * "on" times the writes on the device (io_stages=on), as gc-copyback does:
 * the hold stage runs from the return from the FTL to the due time. A busy
 * host can shorten hold, not lengthen it. A move that still books its
 * channel transfers adds up to 128 ms to the write behind it.
 */
void femu_test_fdp_copyback(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    bool on = g_str_has_suffix(data, "on");
    bool ii = g_str_has_prefix(data, "ii");
    uint16_t vpid = ii ? 3 : 0;
    uint64_t ruamw0, ruamw1;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 16 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t log = guest_alloc(alloc, 4096);
    uint64_t lpn, gc0, gc = 0, cb, mbmw, hbmw, mbe;
    uint64_t mapped, lost, orphans;
    int64_t max_ms = 0;
    int64_t hold_ms = 0;
    int writes = 0;
    uint8_t st[64];
    int n;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x5a, 16 * 4096);
    for (lpn = 0; lpn < (ii ? 144 : 128); lpn += 16) {
        g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, lpn, 16, buf, list,
                                                        vpid)), ==,
                        NVME_SUCCESS);
    }
    g_assert_cmphex(femu_dealloc_pages(&c, 0, 64, list), ==, NVME_SUCCESS);
    gc0 = femu_c0h_field(&c, log, 16);
    if (on) {
        qobject_unref(qtest_qmp(qts, "{'execute':'query-femu-stages',"
                                "'arguments':{'reset':true}}"));
    }
    /* at most up to the end of the 11 MiB namespace */
    for (n = 0; n < 160 && gc < 64; n++) {
        int64_t t0 = g_get_monotonic_time();

        g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, lpn, 16, buf, list,
                                                        1)), ==, NVME_SUCCESS);
        max_ms = MAX(max_ms, (g_get_monotonic_time() - t0) / 1000);
        writes++;
        lpn += 16;
        gc = femu_c0h_field(&c, log, 16) - gc0;
    }
    /* the write after collection waits for whatever it left on the media */
    {
        int64_t t0 = g_get_monotonic_time();

        g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, lpn, 16, buf, list,
                                                        1)), ==, NVME_SUCCESS);
        max_ms = MAX(max_ms, (g_get_monotonic_time() - t0) / 1000);
        writes++;
    }
    if (on) {
        hold_ms = femu_stage_hold_max_ms(qts, writes);
    }
    gc = femu_c0h_field(&c, log, 16) - gc0;
    cb = femu_c0h_field(&c, log, 248);
    g_test_message("FDP gc_copyback %s: %" PRIu64 " moved, %" PRIu64
                   " by copyback, slowest write %" PRId64 " ms, longest "
                   "media wait %" PRId64 " ms", (const char *)data, gc, cb,
                   max_ms, hold_ms);
    g_assert_cmpuint(gc, ==, 64);

    /* every live page still maps to the one copy that holds it */
    femu_ftl_check(qts, &mapped, &lost, &orphans);
    g_assert_cmpuint(mapped, ==, lpn + 16 - 64);
    g_assert_cmpuint(lost, ==, 0);
    g_assert_cmpuint(orphans, ==, 0);

    /* media bytes are host bytes plus the moves; erases are whole blocks */
    g_assert_cmpint(femu_endgrp_log(&c, FEMU_LOG_FDP_STATS, 0, log,
                                    sizeof(st)), ==, NVME_SUCCESS);
    qtest_memread(qts, log, st, sizeof(st));
    hbmw = ldq_le_p(st);
    mbmw = ldq_le_p(st + 16);
    mbe = ldq_le_p(st + 32);
    g_assert_cmpuint(hbmw, ==, (lpn + 16) * 4096);
    g_assert_cmpuint(mbmw, ==, hbmw + gc * 4096);
    g_assert_cmpuint(mbe % (32 * 4096), ==, 0);
    g_assert_cmpuint(mbe, >=, 4 * 32 * 4096);

    if (on) {
        g_assert_cmpuint(cb, ==, 64);
        /* each write books about 16 ms of its own transfers */
        g_assert_cmpint(hold_ms, >=, 4);
        g_assert_cmpint(hold_ms, <, 60);
    } else {
        g_assert_cmpuint(cb, ==, 0);
        g_assert_cmpint(max_ms, >, 100);
    }

    if (ii) {
        /* the moves went into placement 3's active unit: 48 pages fill it */
        lpn += 16;
        ruamw0 = femu_ruh_ruamw(&c, log, 3);
        for (n = 0; n < 3; n++, lpn += 16) {
            g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, lpn, 16, buf,
                                                            list, 3)), ==,
                            NVME_SUCCESS);
        }
        ruamw1 = femu_ruh_ruamw(&c, log, 3);
        g_test_message("RUAMW of placement 3: %" PRIu64 " before, %" PRIu64
                       " after 48 pages", ruamw0, ruamw1);
        g_assert_cmpuint(ruamw0, ==, 48 * 8);
        g_assert_cmpuint(ruamw1, ==, 128 * 8);
    }

    guest_free(alloc, log);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * The location of a controller event about placement handle 3 of namespace
 * 1, reclaim group 0, with every location field valid.
 */
static void femu_check_event_loc(const uint8_t *ev)
{
    int i;

    g_assert_true(ev[0] == FEMU_FDP_EVT_MEDIA_REALLOC ||
                  ev[0] == FEMU_FDP_EVT_RUH_MODIFIED);
    g_assert_cmphex(ev[1], ==, 0x7);                /* PIV, NSIDV, LV */
    g_assert_cmpint(lduw_le_p(ev + 2), ==, 3);
    g_assert_cmpint(ldl_le_p(ev + 12), ==, 1);
    g_assert_cmpint(lduw_le_p(ev + 32), ==, 0);
    g_assert_cmpint(lduw_le_p(ev + 34), ==, 3);
    for (i = 36; i < 40; i++) {
        g_assert_cmpint(ev[i], ==, 0);
    }
    if (ev[0] == FEMU_FDP_EVT_RUH_MODIFIED) {
        for (i = 16; i < 32; i++) {
            g_assert_cmpint(ev[i], ==, 0);
        }
    }
}

/*
 * write the one block @lba through placement identifier @pid, with the
 * control bits @ctl too
 */
static uint16_t femu_write_block_placed_ctl(FemuCtrlState *c, uint64_t lba,
                                            uint64_t data, int pid,
                                            uint16_t ctl)
{
    NvmeRwCmd rw;
    uint16_t want = c->cid;
    uint16_t got;
    uint16_t status;

    memset(&rw, 0, sizeof(rw));
    rw.opcode = NVME_CMD_WRITE;
    rw.nsid = cpu_to_le32(1);
    rw.dptr.prp1 = cpu_to_le64(data);
    rw.slba = cpu_to_le64(lba);
    rw.control = cpu_to_le16(ctl | 2 << 4);
    rw.dspec = cpu_to_le16(pid);
    femu_submit(c, &c->io, (NvmeCmd *)&rw);
    status = femu_complete(c, &c->io, &got, NULL);
    g_assert_cmpint(got, ==, want);
    return FEMU_SC(status);
}

/* write the one block @lba through placement identifier @pid */
static uint16_t femu_write_block_placed(FemuCtrlState *c, uint64_t lba,
                                        uint64_t data, int pid)
{
    return femu_write_block_placed_ctl(c, lba, data, pid, 0);
}

/*
 * The controller events reclaim moves log, on the geometry of
 * femu_test_fdp_copyback(): a reclaim unit is one 128-page line, and a page
 * holds eight 512-byte blocks. Only the last handle, placement 3 on
 * fdpsub-ii, is initially isolated. Its data moves into its own active unit.
 *
 *   "gc-pi":    placement 0 fills unit A, half of it is deallocated, and
 *               writes through placement 1 make collection move the other
 *               64 pages: no event
 *   "gc-ii":    the same through placement 3, which also writes 16 pages
 *               into its next unit B: 80h for 64 pages (512 blocks)
 *   "gc-ii-cb": "gc-ii" with copyback
 *   "gc-ii-4k": "gc-ii" with 4 KiB blocks: 80h for 64 blocks
 *   "gc-ii-part": "gc-ii", but pages 64 to 79 hold only their second block:
 *               80h for 48 * 8 + 16 = 400 blocks, all of them written
 *   "gc-ii-mix", "gc-ii-fua", "gc-ii-redo": with a write buffer, pages 64
 *               to 79 get block 0 and then block 1. "mix" writes block 0
 *               through placement 0, so the held page changes handle; "fua"
 *               writes block 1 with FUA, which programs the held page.
 *               Both: 80h for 48 * 8 + 32 = 416 blocks. "redo" deallocates
 *               the held page between the two: 400 blocks, as "gc-ii-part"
 *   "gc-ii-dsm": "gc-ii", but pages 64 to 79 are written whole and then
 *               lose block 0 to a one-block deallocate. The pages stay
 *               mapped, and the event counts only the blocks left:
 *               80h for 48 * 8 + 16 * 7 = 496 blocks, from block 513.
 *               With a write buffer the pages are still held at the
 *               deallocate.
 *   "gc-ii-rot": placement 3 writes 112 pages into B, so the 16th move fills
 *               it: 80h for 16 pages, 81h, 80h for the other 48
 *   "gc-ii-mask", "-no80", "-no81": "gc-ii-rot" with 80h and 81h, only 80h
 *               or only 81h off on placement 3
 *   "gc-ii-other": "gc-ii-rot" with both off on placement 0 only
 *   "gc-ii-empty": all of A deallocated; collection erases it and moves
 *               nothing: no event
 *   "rf-pi", "rf-ii": eight reads of A queue a refresh of its 128 pages.
 *               For placement 3 they fill the handle's empty active unit on
 *               the last move: 80h for 1024 blocks, then 81h
 *   "rf-ii-part": "rf-ii", but pages 0 to 15 hold only their second block,
 *               and the write that runs the refresh is block 0, through
 *               placement 1: 80h for 112 * 8 + 16 = 912 blocks, as that
 *               write reaches the FTL only after the moves. Pages 0 to 15
 *               were written whole and deallocated first, which forgets
 *               their blocks
 * The events carry the Timestamp feature's value, which the host sets first.
 * Without copyback the moves take pages in a fixed order, so the block each
 * 80h reports is exact: the first written block of its first page.
 */
void femu_test_fdp_move_events(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    const char *mode = data;
    bool refresh = g_str_has_prefix(mode, "rf-");
    bool ii = strstr(mode, "-ii") != NULL;
    bool k4 = !strcmp(mode, "gc-ii-4k");
    bool mix = !strcmp(mode, "gc-ii-mix");
    bool fua = !strcmp(mode, "gc-ii-fua");
    bool redo = !strcmp(mode, "gc-ii-redo");
    bool dsm = !strcmp(mode, "gc-ii-dsm");
    bool two = mix || fua;
    bool part = g_str_has_suffix(mode, "-part") || two || redo || dsm;
    uint64_t part_lo = refresh ? 0 : 64;
    bool empty = !strcmp(mode, "gc-ii-empty");
    bool cb = !strcmp(mode, "gc-ii-cb");
    bool rot = g_str_has_prefix(mode, "gc-ii-rot") ||
               g_str_has_prefix(mode, "gc-ii-mask") ||
               g_str_has_prefix(mode, "gc-ii-no") ||
               g_str_has_prefix(mode, "gc-ii-other");
    int vpid = ii ? 3 : 0;
    uint64_t first = refresh ? 128 : rot ? 240 : ii ? 144 : 128;
    const uint64_t host = 0x0123456789abULL;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 16 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t log = guest_alloc(alloc, 4096);
    /* expected events: type and blocks moved, 0 for 81h */
    uint8_t want_type[3];
    uint32_t want_nlb[3];
    uint64_t want_lba[3];
    uint32_t nwant = 0;
    uint32_t per;
    uint8_t ev[8 * 64];
    uint8_t st[64];
    uint64_t lpn, gc0, gc = 0, rr0, cb0, mbe0;
    uint32_t before, after, i;
    uint64_t nsze;
    int n;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_identify_ns(&c, &nsze, &c.lba_size);
    g_assert_cmpint(c.lba_size, ==, k4 ? 4096 : 512);
    per = 4096 / c.lba_size;
    qtest_writeq(qts, log, host);
    g_assert_cmpint(femu_timestamp(&c, true, 0, 0, log), ==, NVME_SUCCESS);
    if (g_str_has_prefix(mode, "gc-ii-mask")) {
        femu_fdp_move_events_set(&c, log, 3, "01", false);
    } else if (!strcmp(mode, "gc-ii-no80")) {
        femu_fdp_move_events_set(&c, log, 3, "0", false);
    } else if (!strcmp(mode, "gc-ii-no81")) {
        femu_fdp_move_events_set(&c, log, 3, "1", false);
    } else if (!strcmp(mode, "gc-ii-other")) {
        femu_fdp_move_events_set(&c, log, 0, "01", false);
    }
    before = femu_fdp_ctrl_events(&c, log, ev, 0);
    g_assert_cmpuint(before, ==, 0);

    qtest_memset(qts, buf, 0x5a, 16 * 4096);
    if (part && refresh) {
        g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 0, 16, buf, list,
                                                        1)), ==,
                        NVME_SUCCESS);
        g_assert_cmphex(femu_dealloc_pages(&c, 0, 16, list), ==,
                        NVME_SUCCESS);
    }
    for (lpn = 0; lpn < first; lpn += 16) {
        if (part && lpn == part_lo) {
            for (i = 0; i < 16; i++) {
                if (dsm) {
                    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(
                                        &c, lpn + i, 1, buf, list, vpid)),
                                    ==, NVME_SUCCESS);
                    g_assert_cmphex(FEMU_SC(femu_dealloc_range(
                                        &c, (lpn + i) * 8, 1, list)),
                                    ==, NVME_SUCCESS);
                    continue;
                }
                if (two || redo) {
                    g_assert_cmphex(femu_write_block_placed(&c, (lpn + i) * 8,
                                                            buf,
                                                            mix ? 0 : vpid),
                                    ==, NVME_SUCCESS);
                }
                if (redo) {
                    g_assert_cmphex(femu_dealloc_pages(&c, lpn + i, 1, list),
                                    ==, NVME_SUCCESS);
                }
                g_assert_cmphex(femu_write_block_placed_ctl(
                                    &c, (lpn + i) * 8 + 1, buf, vpid,
                                    fua ? NVME_RW_FUA : 0), ==,
                                NVME_SUCCESS);
            }
            continue;
        }
        g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, lpn, 16, buf, list,
                                                        vpid)), ==,
                        NVME_SUCCESS);
    }
    gc0 = femu_c0h_field(&c, log, 16);
    rr0 = femu_c0h_field(&c, log, 40);
    cb0 = femu_c0h_field(&c, log, 248);
    if (refresh) {
        g_usleep(10 * 1000);
        for (n = 0; n < 8; n++) {
            g_assert_cmphex(femu_rw(&c, NVME_CMD_READ, 0, buf), ==,
                            NVME_SUCCESS);
        }
        if (part) {
            g_assert_cmphex(femu_write_block_placed(&c, 0, buf, 1), ==,
                            NVME_SUCCESS);
        } else {
            g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, lpn, 16, buf,
                                                            list, 1)), ==,
                            NVME_SUCCESS);
        }
        gc = femu_c0h_field(&c, log, 16) - gc0;
        g_assert_cmpuint(femu_c0h_field(&c, log, 40) - rr0, ==, 1);
        g_assert_cmpuint(gc, ==, 128);
    } else if (empty) {
        g_assert_cmphex(femu_dealloc_pages(&c, 0, 128, list), ==,
                        NVME_SUCCESS);
        g_assert_cmpint(femu_endgrp_log(&c, FEMU_LOG_FDP_STATS, 0, log,
                                        sizeof(st)), ==, NVME_SUCCESS);
        qtest_memread(qts, log, st, sizeof(st));
        mbe0 = ldq_le_p(st + 32);
        for (n = 0; n < 160 && ldq_le_p(st + 32) == mbe0; n++, lpn += 16) {
            g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, lpn, 16, buf,
                                                            list, 1)), ==,
                            NVME_SUCCESS);
            g_assert_cmpint(femu_endgrp_log(&c, FEMU_LOG_FDP_STATS, 0, log,
                                            sizeof(st)), ==, NVME_SUCCESS);
            qtest_memread(qts, log, st, sizeof(st));
        }
        g_assert_cmpuint(ldq_le_p(st + 32), >, mbe0);
        gc = femu_c0h_field(&c, log, 16) - gc0;
        g_assert_cmpuint(gc, ==, 0);
    } else {
        g_assert_cmphex(femu_dealloc_pages(&c, 0, 64, list), ==,
                        NVME_SUCCESS);
        for (n = 0; n < 160 && gc < 64; n++, lpn += 16) {
            g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, lpn, 16, buf,
                                                            list, 1)), ==,
                            NVME_SUCCESS);
            gc = femu_c0h_field(&c, log, 16) - gc0;
        }
        g_assert_cmpuint(gc, ==, 64);
    }
    if (cb) {
        g_assert_cmpuint(femu_c0h_field(&c, log, 248) - cb0, >, 0);
    }

    if (!ii || empty || g_str_has_prefix(mode, "gc-ii-mask")) {
        nwant = 0;
    } else if (refresh) {
        want_type[nwant] = FEMU_FDP_EVT_MEDIA_REALLOC;
        want_lba[nwant] = part ? 1 : 0;
        want_nlb[nwant++] = part ? 112 * 8 + 16 : 128 * per;
        want_type[nwant] = FEMU_FDP_EVT_RUH_MODIFIED;
        want_nlb[nwant++] = 0;
    } else if (rot) {
        bool no80 = !strcmp(mode, "gc-ii-no80");
        bool no81 = !strcmp(mode, "gc-ii-no81");

        /* pages 64 and 66 open the two batches */
        if (!no80) {
            want_type[nwant] = FEMU_FDP_EVT_MEDIA_REALLOC;
            want_lba[nwant] = 64 * per;
            want_nlb[nwant++] = 16 * per;
        }
        if (!no81) {
            want_type[nwant] = FEMU_FDP_EVT_RUH_MODIFIED;
            want_nlb[nwant++] = 0;
        }
        if (!no80) {
            want_type[nwant] = FEMU_FDP_EVT_MEDIA_REALLOC;
            want_lba[nwant] = 66 * per;
            want_nlb[nwant++] = 48 * per;
        }
    } else {
        want_type[nwant] = FEMU_FDP_EVT_MEDIA_REALLOC;
        want_lba[nwant] = two ? 64 * 8 : part ? 64 * 8 + 1 : 64 * per;
        want_nlb[nwant++] = dsm ? 48 * 8 + 16 * 7 :
                            part ? 48 * 8 + (two ? 32 : 16) : 64 * per;
    }

    after = femu_fdp_ctrl_events(&c, log, ev, 8);
    g_test_message("FDP move events %s: %" PRIu64 " pages moved, %u events",
                   mode, gc, after);
    g_assert_cmpuint(after, ==, nwant);
    for (i = 0; i < nwant; i++) {
        const uint8_t *e = ev + i * 64;
        uint64_t ts = ldq_le_p(e + 4) & ((1ull << 48) - 1);
        uint64_t lba;

        femu_check_event_loc(e);
        g_assert_cmphex(e[0], ==, want_type[i]);
        g_assert_cmpuint(ts, >=, host);
        g_assert_cmpuint(ts, <, host + 60 * 1000);
        if (want_type[i] != FEMU_FDP_EVT_MEDIA_REALLOC) {
            continue;
        }
        g_assert_cmphex(e[16], ==, 1);              /* LBAV */
        g_assert_cmphex(e[17], ==, 0);
        g_assert_cmpint(lduw_le_p(e + 18), ==, want_nlb[i]);
        g_assert_cmpint(ldl_le_p(e + 28), ==, 0);
        lba = ldq_le_p(e + 20);
        g_test_message("80h: %u blocks, block %" PRIu64,
                       lduw_le_p(e + 18), lba);
        if (!cb) {
            g_assert_cmpuint(lba, ==, want_lba[i]);
            continue;
        }
        /* copyback takes pages in die order: any written block of 64..127 */
        g_assert_cmpuint(lba, >=, 64 * per);
        g_assert_cmpuint(lba, <, 128 * per);
        g_assert_cmpuint(lba % per, ==, 0);
    }

    guest_free(alloc, log);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * Write Zeroes carries placement directives in the same fields as Write.
 * They were never read, so the zeros went wherever the request slot's last
 * command had placed its data, and the host byte counters did not move.
 */
void femu_test_fdp_write_zeroes_placed(void *obj, void *data,
                                       QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    NvmeRwCmd rw;
    uint64_t buf;
    uint64_t ruamw0, ruamw1, hbmw;
    const uint32_t blocks = 8;
    uint16_t want, got;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, 4096);

    ruamw0 = femu_ruh_ruamw(&c, buf, 0);
    ruamw1 = femu_ruh_ruamw(&c, buf, 1);
    hbmw = femu_fdp_hbmw(&c, buf);

    /* no deallocate bit, data placement directive, placement id 1 */
    memset(&rw, 0, sizeof(rw));
    rw.opcode = NVME_CMD_WRITE_ZEROES;
    rw.nsid = cpu_to_le32(1);
    rw.slba = cpu_to_le64(0);
    rw.nlb = cpu_to_le16(blocks - 1);
    rw.control = cpu_to_le16(2 << 4);
    rw.dspec = cpu_to_le16(1);
    want = c.cid;
    femu_submit(&c, &c.io, (NvmeCmd *)&rw);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(got, ==, want);

    g_assert_cmpint(femu_ruh_ruamw(&c, buf, 1), ==, ruamw1 - blocks);
    g_assert_cmpint(femu_ruh_ruamw(&c, buf, 0), ==, ruamw0);
    g_assert_cmpint(femu_fdp_hbmw(&c, buf) - hbmw, ==, blocks * 4096);

    /*
     * Bit 23 of CDW12 is NSZ and DTYPE is bits 22:20 (NVM 1.2, Figure 82).
     * With NSZ set the placement still goes to handle 1, and NSZ with no
     * directive is a plain Write Zeroes, not a directive type of 8.
     */
    rw.control = cpu_to_le16((1 << 7) | (2 << 4));
    rw.slba = cpu_to_le64(blocks);
    want = c.cid;
    femu_submit(&c, &c.io, (NvmeCmd *)&rw);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(got, ==, want);
    g_assert_cmpint(femu_ruh_ruamw(&c, buf, 1), ==, ruamw1 - 2 * blocks);
    g_assert_cmpint(femu_ruh_ruamw(&c, buf, 0), ==, ruamw0);

    rw.control = cpu_to_le16(1 << 7);
    rw.slba = cpu_to_le64(2 * blocks);
    want = c.cid;
    femu_submit(&c, &c.io, (NvmeCmd *)&rw);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &got, NULL)), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(got, ==, want);
    g_assert_cmpint(femu_ruh_ruamw(&c, buf, 0), ==, ruamw0 - blocks);

    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * A computational storage namespace runs the black-box FTL, and under FDP
 * its write path, so it takes the knobs that path takes: the write buffer,
 * dftl and a gc_policy.
 */
void femu_test_fdp_csd_knobs(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    QDict *rsp;

    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'fdp-knob','addr':'5',"
                    "'devsz_mb':64,'femu_mode':4,'fdm_size':16,"
                    "'secsz':512,'secs_per_pg':8,'pgs_per_blk':16,"
                    "'blks_per_pl':80,'pls_per_lun':1,"
                    "'luns_per_ch':4,'nchs':4,'subsys':'fdpsub',"
                    "'buffer_size':16,'mapping':'dftl','gc_policy':'fifo'}}");
    g_assert_false(qdict_haskey(rsp, "error"));
    qobject_unref(rsp);
    qos_invalidate_command_line();
}

/*
 * hot_cold_sep and the log-block mappings write host data through pointers
 * of their own, past the unit a placement handle names, so FDP refuses them
 * on black-box and computational storage controllers alike, and says why.
 */
void femu_test_fdp_knobs_refused(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    static const struct {
        const char *knob;
        const char *want;
    } cases[] = {
        { "'hot_cold_sep':true", "hot_cold_sep is not supported under FDP: "
          "the placement handle of a write chooses its reclaim unit" },
        { "'mapping':'hybrid'", "mapping=hybrid is not supported under FDP: "
          "the log-block mappings" },
        { "'mapping':'fast'", "mapping=fast is not supported under FDP: "
          "the log-block mappings" },
    };
    int modes[] = { 1, 4 };
    QDict *rsp;

    for (int m = 0; m < ARRAY_SIZE(modes); m++) {
        for (int k = 0; k < ARRAY_SIZE(cases); k++) {
            g_autofree char *want = g_strdup_printf(
                "FEMU %s: %s", modes[m] == 1 ? "bbssd" : "csd",
                cases[k].want);
            g_autofree char *args = g_strdup_printf(
                "{'driver':'femu','id':'fdp-knob','addr':'5',"
                "'devsz_mb':64,'femu_mode':%d,'fdm_size':16,'secsz':512,"
                "'secs_per_pg':8,'pgs_per_blk':16,'blks_per_pl':80,"
                "'pls_per_lun':1,'luns_per_ch':4,'nchs':4,"
                "'subsys':'fdpsub',%s}", modes[m], cases[k].knob);
            const char *desc;

            rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':%p}",
                            qobject_from_json(args, &error_abort));
            g_assert_true(qdict_haskey(rsp, "error"));
            desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
            g_test_message("%s", desc);
            g_assert_nonnull(strstr(desc, want));
            qobject_unref(rsp);
        }
    }
    qos_invalidate_command_line();
}

/*
 * The reclaim unit the host is told about is the FTL's superblock, for a
 * computational storage controller as for a black-box one: four channels of
 * four LUNs of sixteen 4 KiB pages make 1 MiB, not the 96 MiB default.
 */
void femu_test_fdp_csd_runs(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_endgrp_log(&c, NVME_LOG_FDP_CONFS, 0, buf, 64), ==,
                    NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(c.pdev->bus->qts, buf + 16 + 16), ==,
                     1024 * 1024);
    femu_disable(&c);
    guest_free(alloc, buf);
}

/*
 * The Data Placement Directive under FDP: Identify reports it supported and
 * kept across a reset, the host enables and disables it per namespace, and
 * a command that names it directly fails, since it has no operations. With
 * no FDP (@data set: streams only) an enable fails with FDP Disabled.
 */
/* one 4 KiB Write at LBA 0 naming directive type @dtype, placement 0 */
static uint16_t femu_dp_write(FemuCtrlState *c, int dtype, uint64_t buf)
{
    NvmeRwCmd rw;

    memset(&rw, 0, sizeof(rw));
    rw.opcode = NVME_CMD_WRITE;
    rw.nsid = cpu_to_le32(1);
    rw.dptr.prp1 = cpu_to_le64(buf);
    rw.nlb = cpu_to_le16(4096 / c->lba_size - 1);
    rw.control = cpu_to_le16(dtype << 4);
    return FEMU_SC(femu_io(c, (NvmeCmd *)&rw));
}

/* the same as a Write Zeroes */
static uint16_t femu_dp_zeroes(FemuCtrlState *c, int dtype)
{
    NvmeRwCmd rw;

    memset(&rw, 0, sizeof(rw));
    rw.opcode = NVME_CMD_WRITE_ZEROES;
    rw.nsid = cpu_to_le32(1);
    rw.nlb = cpu_to_le16(4096 / c->lba_size - 1);
    rw.control = cpu_to_le16(dtype << 4);
    return FEMU_SC(femu_io(c, (NvmeCmd *)&rw));
}

void femu_test_fdp_directive(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    const uint64_t src = 0;
    const uint16_t nlb = 8;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readw(qts, buf + 256) & 0x20, ==, 0x20);
    if (data) {
        g_assert_cmphex(femu_directive(&c, false, 1, 1, 0x201, 0, 0, NULL),
                        ==, NVME_FDP_DISABLED);
        g_assert_cmphex(femu_directive(&c, true, 1, 1, 0, buf, 4096, NULL),
                        ==, NVME_SUCCESS);
        g_assert_cmphex(qtest_readb(qts, buf), ==, 3);
        g_assert_cmphex(qtest_readb(qts, buf + 64), ==, 0);
        guest_free(alloc, list);
        guest_free(alloc, buf);
        femu_disable(&c);
        return;
    }

    g_assert_cmphex(femu_directive(&c, true, 1, 1, 0, buf, 4096, NULL), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, buf), ==, 5);         /* Identify, DP */
    g_assert_cmphex(qtest_readb(qts, buf + 32), ==, 1);    /* DP not enabled */
    g_assert_cmphex(qtest_readb(qts, buf + 64), ==, 4);    /* DP kept */
    for (i = 96; i < 4096; i += 4) {
        g_assert_cmphex(qtest_readl(qts, buf + i), ==, 0);
    }

    /* without the enable, any directive type passes, as before */
    femu_create_io_queues(&c);
    g_assert_cmphex(femu_dp_write(&c, 3, buf), ==, NVME_SUCCESS);

    /* enable, check, disable, check */
    g_assert_cmphex(femu_directive(&c, false, 1, 1, 0x201, 0, 0, NULL), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(femu_directive(&c, true, 1, 1, 0, buf, 4096, NULL), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, buf + 32), ==, 5);
    for (i = 0; i < 4; i++) {
        uint16_t want = i == 1 || i == 3 ? NVME_INVALID_FIELD : NVME_SUCCESS;

        g_assert_cmphex(femu_dp_write(&c, i, buf), ==, want);
        g_assert_cmphex(femu_dp_zeroes(&c, i), ==, want);
        g_assert_cmphex(femu_copy(&c, list, 64, &src, &nlb, 1, 1,
                                  (uint32_t)i << 20), ==, want);
    }
    g_assert_cmphex(femu_directive(&c, false, 1, 1, 0x200, 0, 0, NULL), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(femu_directive(&c, true, 1, 1, 0, buf, 4096, NULL), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, buf + 32), ==, 1);

    /* refusals */
    g_assert_cmphex(femu_directive(&c, false, 0xffffffff, 1, 0x201, 0, 0,
                                   NULL), ==, NVME_INVALID_NSID);
    g_assert_cmphex(femu_directive(&c, true, 1, 0x201, 0, buf, 4096, NULL),
                    ==, NVME_INVALID_FIELD);
    g_assert_cmphex(femu_directive(&c, false, 1, 0x201, 0, 0, 0, NULL), ==,
                    NVME_INVALID_FIELD);
    g_assert_cmphex(femu_directive(&c, false, 1, 1, 0x101, 0, 0, NULL), ==,
                    NVME_INVALID_FIELD);                    /* no streams */
    g_assert_cmphex(femu_directive(&c, true, 1, 0x101, 0, buf, 4096, NULL),
                    ==, NVME_INVALID_FIELD);

    /* the enabled state survives a controller reset */
    g_assert_cmphex(femu_directive(&c, false, 1, 1, 0x201, 0, 0, NULL), ==,
                    NVME_SUCCESS);
    femu_disable(&c);
    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmphex(femu_directive(&c, true, 1, 1, 0, buf, 4096, NULL), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, buf + 32), ==, 5);

    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_disable(&c);
}

void femu_test_fdp_refused_restores(void *obj, void *data,
                                    QGuestAllocator *unused)
{
    QTestState *qts = qtest_init("-machine pc -nodefaults "
        "-device femu-subsys,id=sub,nqn=sub,fdp=on,fdp.nruh=4,fdp.nrg=2 "
        "-device femu-subsys,id=ctl,nqn=ctl,fdp=on,fdp.nruh=4,fdp.nrg=2");
    g_autofree char *fresh = femu_fdp_state(qts, "sub");
    g_autofree char *out = NULL;
    g_autofree char *now = NULL;
    g_autofree char *control = femu_fdp_state(qts, "ctl");

    g_assert_cmpstr(fresh, ==, control);
    out = qtest_hmp(qts, "device_add femu,addr=5,id=ff,subsys=sub,"
                    FEMU_FDP_REFUSE ",secs_per_pg=8,lba_index=3,"
                    "x-ftl-fail-at=17");
    g_assert_nonnull(strstr(out, "injected failure of FTL allocation 17"));
    now = femu_fdp_state(qts, "sub");
    g_assert_cmpstr(now, ==, fresh);
    g_free(out);
    g_free(now);

    out = qtest_hmp(qts, "device_add femu,addr=5,id=ff,subsys=sub,"
                    FEMU_FDP_REFUSE ",secs_per_pg=8,lba_index=3,"
                    "romfile=/nonexistent/femu.rom");
    g_assert_nonnull(strstr(out, "romfile"));
    now = femu_fdp_state(qts, "sub");
    g_assert_cmpstr(now, ==, fresh);
    g_free(out);
    g_free(now);

    /*
     * A 64 KiB block: the 32 KiB unit of the refused line cannot hold one,
     * the 512 KiB unit of this line can.
     */
    for (int c = 0; c < 2; c++) {
        out = qtest_hmp(qts, "device_add femu,addr=%d,id=f%d,subsys=%s,"
                        FEMU_FDP_REFUSE ",secs_per_pg=128,nlbaf=8,"
                        "lba_index=7", 5 + c, c, c ? "ctl" : "sub");
        if (*out) {
            g_test_message("%s: %s", c ? "ctl" : "sub", out);
            g_assert_not_reached();
        }
        g_free(out);
        out = NULL;
    }
    now = femu_fdp_state(qts, "sub");
    g_free(control);
    control = femu_fdp_state(qts, "ctl");
    g_assert_cmpstr(now, ==, control);
    g_assert_cmpstr(now, !=, fresh);
    qtest_quit(qts);
}

/*
 * The same property under FDP. A reclaim unit is four blocks of four pages.
 * Unit A holds pages 0 to 15 of placement 0, and the fill through placement
 * 3 takes the free units to the background threshold with no victim.
 * Each one-page overwrite through placement 2 makes one page of A invalid.
 *
 *   pcent   pass takes A at              copies    block erases
 *   0       2 invalid (16 / 8)           14        4
 *   50      8 invalid (8 x 100 >= 800)   8         4
 *
 * With the property at its default the run for 50 fails at the second
 * overwrite: 14 pages copied where it expects none.
 */
void femu_test_fdp_gc_bg_invalid(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    int pcent = atoi(data);
    int take = pcent ? 16 * pcent / 100 : 2;
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 16 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x5a, 16 * 4096);

    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 0, 16, buf, list, 0)),
                    ==, NVME_SUCCESS);
    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 16, 16, buf, list,
                                                    1)), ==, NVME_SUCCESS);
    /* past the background threshold, with no victim yet */
    femu_fdp_cb_fill(&c, qts, buf, list, false);
    g_assert_cmpuint(femu_ftl_trace_field(qts, 5), ==, 0);

    for (int k = 0; k < take; k++) {
        g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, k, 1, buf, list,
                                                        2)), ==,
                        NVME_SUCCESS);
        g_test_message("fdp-gc-bg-invalid %d: %d invalid, %" PRIu64
                       " copies, %" PRIu64 " erases", pcent, k + 1,
                       femu_ftl_trace_field(qts, 4),
                       femu_ftl_trace_field(qts, 5));
        g_assert_cmpuint(femu_ftl_trace_field(qts, 4), ==,
                         k + 1 < take ? 0 : 16 - take);
        g_assert_cmpuint(femu_ftl_trace_field(qts, 5), ==,
                         k + 1 < take ? 0 : 4);
    }

    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/* host event 00h entries of handle @ruhid in the FDP Events log */
static int femu_fdp_not_full_events(FemuCtrlState *c, uint64_t log,
                                    uint16_t ruhid)
{
    uint8_t ev[64 + 63 * 64];
    uint32_t numd = sizeof(ev) / 4 - 1;
    NvmeCmd cmd;
    int n = 0;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_GET_LOG_PAGE;
    cmd.nsid = cpu_to_le32(NVME_NSID_BROADCAST);
    cmd.dptr.prp1 = cpu_to_le64(log);
    cmd.cdw10 = cpu_to_le32(FEMU_LOG_FDP_EVENTS | 1 << 8 |
                            ((numd & 0xffff) << 16));
    cmd.cdw11 = cpu_to_le32(1 << 16);
    g_assert_cmpint(femu_admin(c, &cmd), ==, NVME_SUCCESS);
    qtest_memread(c->pdev->bus->qts, log, ev, sizeof(ev));
    for (uint32_t i = 0; i < MIN(ldl_le_p(ev), 63); i++) {
        const uint8_t *e = ev + 64 + i * 64;

        n += e[0] == FEMU_FDP_EVT_RU_NOT_FULLY_WRITTEN &&
             lduw_le_p(e + 34) == ruhid;
    }
    return n;
}

/*
 * The collection a handle update runs can fill the handle's unit and move
 * the handle on (event 81h), then collect that unit too, which erases it.
 * The update must not then report it as left part written (event 00h).
 * Handle 3 is initially isolated, the rest persistently isolated; one unit
 * is kept free. B, the first unit of handle 3, keeps 2 valid pages; A, its
 * next unit, takes 15 pages and keeps 1. 33 units of 3 pages each use up
 * the free units but one. The update of handle 3 collects B into A, which
 * fills, then A into a fresh unit.
 */
void femu_test_fdp_ruh_update_moved(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 16 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t pids = guest_alloc(alloc, 4096);
    uint64_t log = guest_alloc(alloc, 4096);
    uint64_t mapped, lost, orphans;
    uint16_t ruhid = 0xffff;
    uint16_t pid;
    int k;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x2b, 16 * 4096);
    femu_fdp_move_events_set(&c, pids, 3, "1", true);

    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 0, 16, buf, list, 3)),
                    ==, NVME_SUCCESS);
    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 100, 15, buf, list,
                                                    3)), ==, NVME_SUCCESS);
    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 2, 14, buf, list, 0)),
                    ==, NVME_SUCCESS);
    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 101, 14, buf, list,
                                                    0)), ==, NVME_SUCCESS);
    for (k = 0; k < 33; k++) {
        pid = cpu_to_le16(1 + k % 2);
        qtest_memwrite(qts, pids, &pid, sizeof(pid));
        g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 120 + 3 * k, 3,
                                                        buf, list,
                                                        1 + k % 2)), ==,
                        NVME_SUCCESS);
        g_assert_cmphex(femu_ruh_update(&c, pids, 1), ==, NVME_SUCCESS);
    }
    g_assert_cmpint(femu_pd2_events(&c, log, false, FEMU_FDP_EVT_RUH_MODIFIED,
                                    &ruhid), ==, 0);
    pid = cpu_to_le16(3);
    qtest_memwrite(qts, pids, &pid, sizeof(pid));
    g_assert_cmphex(femu_ruh_update(&c, pids, 1), ==, NVME_SUCCESS);

    /* the move to a fresh unit was the controller's, and A was full */
    g_assert_cmpint(femu_pd2_events(&c, log, false, FEMU_FDP_EVT_RUH_MODIFIED,
                                    &ruhid), ==, 1);
    g_assert_cmpint(ruhid, ==, 3);
    g_assert_cmpint(femu_fdp_not_full_events(&c, log, 3), ==, 0);

    femu_ftl_check(qts, &mapped, &lost, &orphans);
    g_assert_cmpuint(mapped, ==, 16 + 15 + 99);
    g_assert_cmpuint(lost, ==, 0);
    g_assert_cmpuint(orphans, ==, 0);
    g_assert_cmpuint(femu_fdp_check(qts), ==, 0);

    guest_free(alloc, log);
    guest_free(alloc, pids);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * RUH Update of a handle with no unit. With both collection watermarks at
 * 100 and no eol_read_only, overwrites through four persistently isolated
 * handles run the group out of units: a write fails with Capacity Exceeded,
 * and its handle is left with no unit (RUAMW 0). Deallocating the whole
 * namespace lets collection free empty units. An update of that handle
 * then gives it an empty unit (Base 2.3, 7.4.1.1), so its RUAMW is a whole
 * unit; it used to succeed and leave the handle with none.
 */
void femu_test_fdp_ruh_update_none(void *obj, void *data,
                                   QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t pids = guest_alloc(alloc, 4096);
    uint64_t log = guest_alloc(alloc, 4096);
    uint64_t full;
    uint32_t rnd = 5;
    uint16_t pid;
    int i, ph = -1;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    for (i = 0; i < 3; i++) {
        qtest_writeq(qts, list + 8 * i, buf + 4096 * (i + 1));
    }
    qtest_memset(qts, buf, 0x44, 4 * 4096);
    full = femu_ruh_ruamw(&c, log, 0);
    for (i = 0; i < 4000 && ph < 0; i++) {
        uint16_t st;

        rnd = rnd * 1103515245 + 12345;
        st = FEMU_SC(femu_write_pages_placed(&c, i < 64 ? 4 * i :
                                             (rnd >> 8) % 253,
                                             i < 64 ? 4 : 1 + (rnd >> 20) % 4,
                                             buf, list, i % 4));
        if (st == NVME_CAP_EXCEEDED) {
            ph = i % 4;
            break;
        }
        g_assert_cmphex(st, ==, NVME_SUCCESS);
    }
    g_test_message("write %d through handle %d found no unit", i, ph);
    g_assert_cmpint(ph, >=, 0);
    g_assert_cmpuint(femu_ruh_ruamw(&c, log, ph), ==, 0);

    g_assert_cmphex(femu_dealloc_pages(&c, 0, 256, list), ==, NVME_SUCCESS);
    pid = cpu_to_le16(ph);
    qtest_memwrite(qts, pids, &pid, sizeof(pid));
    g_assert_cmphex(femu_ruh_update(&c, pids, 1), ==, NVME_SUCCESS);
    g_assert_cmpuint(femu_ruh_ruamw(&c, log, ph), ==, full);
    g_assert_cmpuint(femu_fdp_check(qts), ==, 0);

    guest_free(alloc, log);
    guest_free(alloc, pids);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * A Format keeps the pages a unit has programmed, so RUAMW must not report
 * them as room again. FDP, 16-page units: 2 pages through placement 0, then
 * a Format to the same 512-byte blocks leaves 14 pages of room, and a Format
 * to 4 KiB blocks counts the same room in 4 KiB blocks. A write after it
 * takes one more page. x-fdp-check holds RUAMW against the pages each time.
 */
void femu_test_fdp_format_ruamw(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 2 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t log = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x72, 2 * 4096);
    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 0, 2, buf, list, 0)),
                    ==, NVME_SUCCESS);
    g_assert_cmpuint(femu_ruh_ruamw(&c, log, 0), ==, 14 * 8);

    g_assert_cmpint(FEMU_SC(femu_format(&c, 1, 0, 0)), ==, NVME_SUCCESS);
    g_assert_cmpuint(femu_ruh_ruamw(&c, log, 0), ==, 14 * 8);
    g_assert_cmpuint(femu_pd2_fdp_check(qts), ==, 0);

    g_assert_cmpint(FEMU_SC(femu_format(&c, 1, 3, 0)), ==, NVME_SUCCESS);
    c.lba_size = 4096;
    g_assert_cmpuint(femu_ruh_ruamw(&c, log, 0), ==, 14);
    g_assert_cmpuint(femu_pd2_fdp_check(qts), ==, 0);
    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 0, 1, buf, list, 0)),
                    ==, NVME_SUCCESS);
    g_assert_cmpuint(femu_ruh_ruamw(&c, log, 0), ==, 13);
    g_assert_cmpuint(femu_pd2_fdp_check(qts), ==, 0);
    femu_pd2_readback(&c, qts, buf, 1, 0x72);

    guest_free(alloc, log);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * FDP with more than one namespace. The namespaces of a controller share the
 * endurance group's reclaim units and handles, and so one FTL; each reaches
 * the handles through its own placement handle list (namespace_phls).
 */

/* Write or read @npages 4 KiB pages from @page of namespace @nsid via @pid */
static uint16_t femu_fdpns_io(FemuCtrlState *c, uint8_t opcode, uint32_t nsid,
                              uint64_t page, uint32_t npages, uint64_t data,
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
        qtest_writeq(c->pdev->bus->qts, list + i * 8, data + (i + 1) * 4096);
    }
    memset(&rw, 0, sizeof(rw));
    rw.opcode = opcode;
    rw.nsid = cpu_to_le32(nsid);
    rw.dptr.prp1 = cpu_to_le64(data);
    rw.dptr.prp2 = cpu_to_le64(npages > 2 ? list :
                               npages == 2 ? data + 4096 : 0);
    rw.slba = cpu_to_le64(page * (4096 / c->lba_size));
    rw.nlb = cpu_to_le16(npages * (4096 / c->lba_size) - 1);
    if (pid >= 0) {
        rw.control = cpu_to_le16(2 << 4);
        rw.dspec = cpu_to_le16(pid);
    }
    femu_submit(c, &c->io, (NvmeCmd *)&rw);
    status = femu_complete(c, &c->io, &got, NULL);
    g_assert_cmpint(got, ==, want);
    return FEMU_SC(status);
}

/* deallocate @npages 4 KiB pages from @page of namespace @nsid */
static uint16_t femu_fdpns_dealloc(FemuCtrlState *c, uint32_t nsid,
                                   uint64_t page, uint32_t npages,
                                   uint64_t buf)
{
    uint8_t range[16] = { 0 };
    NvmeCmd cmd = { 0 };

    stl_le_p(range + 4, npages * (4096 / c->lba_size));
    stq_le_p(range + 8, page * (4096 / c->lba_size));
    qtest_memwrite(c->pdev->bus->qts, buf, range, sizeof(range));
    cmd.opcode = NVME_CMD_DSM;
    cmd.nsid = cpu_to_le32(nsid);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw11 = cpu_to_le32(FEMU_DSM_AD);
    femu_submit(c, &c->io, &cmd);
    return FEMU_SC(femu_complete(c, &c->io, NULL, NULL));
}

/*
 * The RUH Status of namespace @nsid: the descriptor count, and the RUH ID
 * and RUAMW of each placement identifier, at most 8, in descriptor order.
 */
static uint16_t femu_fdpns_ruhs(FemuCtrlState *c, uint32_t nsid,
                                uint64_t buf, uint16_t *ruhid,
                                uint64_t *ruamw)
{
    NvmeCmd cmd = { 0 };
    uint8_t st[16 + 8 * 32];
    uint16_t n;

    cmd.opcode = FEMU_CMD_IO_MGMT_RECV;
    cmd.nsid = cpu_to_le32(nsid);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(FEMU_IOMR_RUH_STATUS);
    cmd.cdw11 = cpu_to_le32(sizeof(st) / 4 - 1);
    g_assert_cmpint(femu_io(c, &cmd), ==, NVME_SUCCESS);
    qtest_memread(c->pdev->bus->qts, buf, st, sizeof(st));
    n = lduw_le_p(st + 14);
    for (uint16_t i = 0; i < MIN(n, 8); i++) {
        /* one reclaim group: the placement identifier is the handle index */
        g_assert_cmpint(lduw_le_p(st + 16 + 32 * i), ==, i);
        ruhid[i] = lduw_le_p(st + 16 + 32 * i + 2);
        ruamw[i] = ldq_le_p(st + 16 + 32 * i + 8);
    }
    return n;
}

/* query-femu of namespace @nsid, with @args added */
static QDict *femu_fdpns_query(QTestState *qts, uint32_t nsid,
                               const char *args, QDict **rsp)
{
    g_autofree char *a = g_strdup_printf("'nsid':%u%s%s", nsid,
                                         *args ? "," : "", args);

    return femu_query_ns(qts, a, rsp);
}

/* host bytes of handle @h and valid pages in its units, from namespace 1 */
static void femu_fdpns_handle(QTestState *qts, int h, uint64_t *host,
                              uint64_t *vpc)
{
    QDict *rsp;
    QDict *ns = femu_fdpns_query(qts, 1, "'kind':'reclaim-units','limit':4096",
                                 &rsp);
    QDict *fdp = qdict_get_qdict(ns, "fdp");
    QListEntry *e;

    *host = 0;
    *vpc = 0;
    QLIST_FOREACH_ENTRY(qdict_get_qlist(fdp, "handles"), e) {
        QDict *d = qobject_to(QDict, qlist_entry_obj(e));

        if (qdict_get_int(d, "id") == h) {
            *host = qdict_get_int(d, "host-bytes");
        }
    }
    QLIST_FOREACH_ENTRY(qdict_get_qlist(fdp, "reclaim-units"), e) {
        QDict *u = qobject_to(QDict, qlist_entry_obj(e));

        if (qdict_haskey(u, "handle") && qdict_get_int(u, "handle") == h) {
            *vpc += qdict_get_int(u, "vpc");
        }
    }
    qobject_unref(rsp);
}

/* the mappings x-ftl-check counts, with none lost and no orphan */
static uint64_t femu_fdpns_mapped(QTestState *qts)
{
    uint64_t mapped, lost, orphans;

    femu_ftl_check(qts, &mapped, &lost, &orphans);
    g_assert_cmpuint(lost, ==, 0);
    g_assert_cmpuint(orphans, ==, 0);
    return mapped;
}

/* mapped pages in the slices of namespaces 1 and 2 (x-fdp-ns-mapped) */
static void femu_fdpns_ns_mapped(QTestState *qts, uint64_t *m1, uint64_t *m2)
{
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                           "'path':'/machine/peripheral/gc-test',"
                           "'property':'x-fdp-ns-mapped'}}");

    g_assert_true(qdict_haskey(rsp, "return"));
    g_assert_cmpint(sscanf(qdict_get_str(rsp, "return"),
                           "%" SCNu64 " %" SCNu64, m1, m2), ==, 2);
    qobject_unref(rsp);
}

/* each namespace holds @w1 and @w2 mapped pages, and the FTL their sum */
static void femu_fdpns_expect(QTestState *qts, uint64_t w1, uint64_t w2)
{
    uint64_t m1, m2;

    femu_fdpns_ns_mapped(qts, &m1, &m2);
    g_assert_cmpuint(m1, ==, w1);
    g_assert_cmpuint(m2, ==, w2);
    g_assert_cmpuint(femu_fdpns_mapped(qts), ==, w1 + w2);
}

/* a 4 KiB page that names its namespace, page and write */
static void femu_fdpns_fill(QTestState *qts, uint64_t buf, uint32_t nsid,
                            uint64_t page, uint32_t seq)
{
    uint8_t pg[4096];

    for (int i = 0; i < 4096; i += 16) {
        stl_le_p(pg + i, nsid);
        stl_le_p(pg + i + 4, page);
        stl_le_p(pg + i + 8, seq);
        stl_le_p(pg + i + 12, i);
    }
    qtest_memwrite(qts, buf, pg, sizeof(pg));
}

/* the page femu_fdpns_fill() wrote for @nsid, @page and @seq reads back */
static void femu_fdpns_verify(FemuCtrlState *c, uint64_t buf, uint64_t list,
                              uint32_t nsid, uint64_t page, uint32_t seq)
{
    QTestState *qts = c->pdev->bus->qts;
    uint8_t pg[4096];

    qtest_memset(qts, buf, 0, 4096);
    g_assert_cmphex(femu_fdpns_io(c, NVME_CMD_READ, nsid, page, 1, buf, list,
                                  -1), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, pg, sizeof(pg));
    g_assert_cmpuint(ldl_le_p(pg), ==, nsid);
    g_assert_cmpuint(ldl_le_p(pg + 4), ==, page);
    g_assert_cmpuint(ldl_le_p(pg + 8), ==, seq);
    g_assert_cmpuint(ldl_le_p(pg + 4092), ==, 4080);
}

/*
 * Two namespaces of 128 pages on 16-page units, with lists 0:1 and 1:2:
 * handle 1 is shared and handle 3 is unused. RUH Status and log 21h report
 * the lists; writes through either namespace's identifier for handle 1 land
 * in the same unit; the FTL maps both namespaces' pages apart; a deallocate
 * of one namespace leaves the other's pages; and a random overwrite of both
 * through collection keeps every page in a unit of a handle its namespace
 * lists, every mapping and every page's data.
 */
void femu_test_fdp_ns_phl(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 20 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t log = guest_alloc(alloc, 4096);
    static const uint16_t want_ruh[2][2] = { { 0, 1 }, { 1, 2 } };
    uint32_t seq[2][128] = { { 0 } };
    uint16_t ruhid[8];
    uint64_t ruamw[8];
    uint64_t host, vpc, gc0, mapped[2] = { 0 };
    uint8_t ruhu[8 + 4 * 8];
    uint32_t seed = 11;
    uint32_t next = 1;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    gc0 = femu_c0h_field(&c, log, 16);

    for (uint32_t ns = 1; ns <= 2; ns++) {
        g_assert_cmpuint(femu_fdpns_ruhs(&c, ns, log, ruhid, ruamw), ==, 2);
        for (i = 0; i < 2; i++) {
            g_assert_cmpuint(ruhid[i], ==, want_ruh[ns - 1][i]);
            /* an empty unit: 16 pages of eight 512-byte blocks */
            g_assert_cmpuint(ruamw[i], ==, 128);
        }
    }
    /* query-femu: each namespace's list, and the one FTL behind both */
    for (uint32_t ns = 1; ns <= 2; ns++) {
        QDict *rsp;
        QDict *fdp = qdict_get_qdict(femu_fdpns_query(qts, ns, "", &rsp),
                                     "fdp");
        QList *phl = qdict_get_qlist(fdp, "placement-handles");
        QListEntry *e;

        i = 0;
        QLIST_FOREACH_ENTRY(phl, e) {
            g_assert_cmpint(qnum_get_int(qobject_to(QNum, qlist_entry_obj(e))),
                            ==, want_ruh[ns - 1][i++]);
        }
        g_assert_cmpint(i, ==, 2);
        g_assert_cmpuint(qdict_get_int(fdp, "ftl-nsid"), ==, 1);
        qobject_unref(rsp);
    }
    g_assert_cmpint(femu_endgrp_log(&c, FEMU_LOG_FDP_RUH_USAGE, 0, log,
                                    sizeof(ruhu)), ==, NVME_SUCCESS);
    qtest_memread(qts, log, ruhu, sizeof(ruhu));
    g_assert_cmpint(lduw_le_p(ruhu), ==, 4);
    for (i = 0; i < 4; i++) {
        g_assert_cmpint(ruhu[8 + i * 8], ==, i < 3 ? 1 : 0);
    }

    /* handle 1 from both sides, 40 pages: two full units and half a third */
    qtest_memset(qts, buf, 0x6b, 20 * 4096);
    g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 1, 0, 20, buf, list, 1),
                    ==, NVME_SUCCESS);
    g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 2, 0, 20, buf, list, 0),
                    ==, NVME_SUCCESS);
    g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 2, 24, 8, buf, list, 1),
                    ==, NVME_SUCCESS);
    femu_fdpns_ruhs(&c, 1, log, ruhid, ruamw);
    g_assert_cmpuint(ruamw[0], ==, 128);
    g_assert_cmpuint(ruamw[1], ==, 64);
    femu_fdpns_ruhs(&c, 2, log, ruhid, ruamw);
    g_assert_cmpuint(ruamw[0], ==, 64);
    g_assert_cmpuint(ruamw[1], ==, 64);
    for (i = 0; i < 4; i++) {
        static const uint64_t want_pages[4] = { 0, 40, 8, 0 };

        femu_fdpns_handle(qts, i, &host, &vpc);
        g_assert_cmpuint(host, ==, want_pages[i] * 4096);
        g_assert_cmpuint(vpc, ==, want_pages[i]);
    }
    /* the same pages of both namespaces are mapped apart */
    femu_fdpns_expect(qts, 20, 28);
    g_assert_cmpuint(femu_fdp_check(qts), ==, 0);

    /* namespace 2's own pages go, namespace 1's stay */
    g_assert_cmphex(femu_fdpns_dealloc(&c, 2, 24, 8, log), ==, NVME_SUCCESS);
    femu_fdpns_handle(qts, 2, &host, &vpc);
    g_assert_cmpuint(vpc, ==, 0);
    femu_fdpns_expect(qts, 20, 20);
    g_assert_cmphex(femu_fdpns_dealloc(&c, 2, 0, 20, log), ==, NVME_SUCCESS);
    femu_fdpns_expect(qts, 20, 0);
    g_assert_cmphex(femu_fdpns_dealloc(&c, 1, 0, 20, log), ==, NVME_SUCCESS);
    femu_fdpns_expect(qts, 0, 0);

    /* random single pages and runs over both namespaces, past collection */
    for (i = 0; i < 1500; i++) {
        uint32_t ns, npages, pid;
        uint64_t page;

        seed = seed * 1103515245 + 12345;
        ns = 1 + ((seed >> 20) & 1);
        pid = (seed >> 21) & 1;
        npages = i % 8 == 7 ? 16 : 1;
        page = (seed >> 8) % (128 - npages + 1);
        for (uint32_t k = 0; k < npages; k++) {
            femu_fdpns_fill(qts, buf + k * 4096, ns, page + k, next);
            mapped[ns - 1] += !seq[ns - 1][page + k];
            seq[ns - 1][page + k] = next;
        }
        next++;
        g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, ns, page, npages,
                                      buf, list, pid), ==, NVME_SUCCESS);
    }
    g_test_message("collection moved %" PRIu64 " pages",
                   femu_c0h_field(&c, log, 16) - gc0);
    g_assert_cmpuint(femu_c0h_field(&c, log, 16), >, gc0);
    femu_fdpns_expect(qts, mapped[0], mapped[1]);
    g_assert_cmpuint(femu_fdp_check(qts), ==, 0);
    for (uint32_t ns = 1; ns <= 2; ns++) {
        for (uint64_t page = 0; page < 128; page += 3) {
            if (seq[ns - 1][page]) {
                femu_fdpns_verify(&c, buf, list, ns, page, seq[ns - 1][page]);
            }
        }
    }

    guest_free(alloc, log);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * Format with two namespaces. A Format of namespace 2 drops only its pages.
 * With @data "shared" the lists share handle 1, so a Format of one namespace
 * to 4 KiB blocks is Invalid Format, and a Format of both is not; RUAMW then
 * counts 4 KiB blocks. With "apart" no handle is shared: namespace 2 takes
 * 4 KiB blocks alone, and each namespace's RUAMW counts its own blocks.
 */
void femu_test_fdp_ns_format(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    bool shared = !strcmp(data, "shared");
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 20 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t log = guest_alloc(alloc, 4096);
    uint16_t ruhid[8];
    uint64_t ruamw[8];

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x2d, 20 * 4096);

    /* 20 pages through placement 1 of each namespace, 4 more through 0 */
    g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 1, 0, 20, buf, list, 1),
                    ==, NVME_SUCCESS);
    g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 2, 0, 20, buf, list, 1),
                    ==, NVME_SUCCESS);
    g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 2, 40, 4, buf, list, 0),
                    ==, NVME_SUCCESS);
    femu_fdpns_expect(qts, 20, 24);

    g_assert_cmphex(FEMU_SC(femu_format(&c, 2, 0, 0)), ==, NVME_SUCCESS);
    femu_fdpns_expect(qts, 20, 0);
    g_assert_cmpuint(femu_fdp_check(qts), ==, 0);

    if (shared) {
        g_assert_cmphex(FEMU_SC(femu_format(&c, 2, 3, 0)), ==,
                        NVME_INVALID_FORMAT);
        g_assert_cmphex(FEMU_SC(femu_format(&c, 1, 3, 0)), ==,
                        NVME_INVALID_FORMAT);
        g_assert_cmphex(FEMU_SC(femu_format(&c, NVME_NSID_BROADCAST, 3, 0)),
                        ==, NVME_SUCCESS);
        femu_fdpns_expect(qts, 0, 0);
        /* handle 1 holds 40 programmed pages: 8 left in its unit */
        femu_fdpns_ruhs(&c, 1, log, ruhid, ruamw);
        g_assert_cmpuint(ruhid[1], ==, 1);
        g_assert_cmpuint(ruamw[1], ==, 8);
        femu_fdpns_ruhs(&c, 2, log, ruhid, ruamw);
        g_assert_cmpuint(ruhid[1], ==, 1);
        g_assert_cmpuint(ruamw[1], ==, 8);
        /* handle 2 took 4 pages: 12 left */
        g_assert_cmpuint(ruhid[0], ==, 2);
        g_assert_cmpuint(ruamw[0], ==, 12);
    } else {
        g_assert_cmphex(FEMU_SC(femu_format(&c, 2, 3, 0)), ==, NVME_SUCCESS);
        femu_fdpns_expect(qts, 20, 0);
        /* namespace 1 counts 512-byte blocks, namespace 2 4 KiB ones */
        femu_fdpns_ruhs(&c, 1, log, ruhid, ruamw);
        g_assert_cmpuint(ruhid[1], ==, 1);
        g_assert_cmpuint(ruamw[1], ==, 12 * 8);
        femu_fdpns_ruhs(&c, 2, log, ruhid, ruamw);
        g_assert_cmpuint(ruhid[0], ==, 2);
        g_assert_cmpuint(ruamw[0], ==, 12);
        g_assert_cmpuint(ruhid[1], ==, 3);
        g_assert_cmpuint(ruamw[1], ==, 12);
        c.lba_size = 4096;
        g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 2, 0, 2, buf, list,
                                      1), ==, NVME_SUCCESS);
        femu_fdpns_ruhs(&c, 2, log, ruhid, ruamw);
        g_assert_cmpuint(ruamw[1], ==, 10);
    }
    g_assert_cmpuint(femu_fdp_check(qts), ==, 0);

    guest_free(alloc, log);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * Controller and host events with two namespaces on fdpsub-ii, where handle
 * 3 is initially isolated. Namespace 1 reaches it as placement 0 (list 3:0)
 * and namespace 2 as placement 2 (list 1:2:3). Each writes 64 pages into
 * one unit of handle 3 and deallocates its first 32; collection then moves
 * 32 pages of each. Every 80h names the namespace of the blocks it counts,
 * with that namespace's placement identifier and one of its blocks. A write
 * with an identifier its namespace lacks logs 03h with that namespace.
 */
void femu_test_fdp_ns_events(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 20 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t log = guest_alloc(alloc, 4096);
    uint8_t ev[8 * 64];
    uint8_t hev[64 + 8 * 64];
    uint32_t nev, seen[3] = { 0 }, nlb = 0, i;
    uint64_t gc0, gc = 0, lpn;
    NvmeCmd cmd = { 0 };
    int n;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x5a, 20 * 4096);
    g_assert_cmpuint(femu_fdp_ctrl_events(&c, log, ev, 0), ==, 0);

    for (lpn = 0; lpn < 64; lpn += 16) {
        g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 1, lpn, 16, buf,
                                      list, 0), ==, NVME_SUCCESS);
    }
    for (lpn = 0; lpn < 64; lpn += 16) {
        g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 2, lpn, 16, buf,
                                      list, 2), ==, NVME_SUCCESS);
    }
    g_assert_cmphex(femu_fdpns_dealloc(&c, 1, 0, 32, log), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_fdpns_dealloc(&c, 2, 0, 32, log), ==, NVME_SUCCESS);

    /* namespace 1, placement 1 (handle 0), until collection moves 64 pages */
    gc0 = femu_c0h_field(&c, log, 16);
    for (n = 0, lpn = 64; n < 160 && gc < 64; n++, lpn += 16) {
        g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 1, lpn, 16, buf,
                                      list, 1), ==, NVME_SUCCESS);
        gc = femu_c0h_field(&c, log, 16) - gc0;
    }
    g_assert_cmpuint(gc, ==, 64);
    g_assert_cmpuint(femu_fdp_check(qts), ==, 0);

    nev = femu_fdp_ctrl_events(&c, log, ev, 8);
    g_test_message("%u controller events", nev);
    g_assert_cmpuint(nev, >=, 2);
    g_assert_cmpuint(nev, <=, 8);
    for (i = 0; i < nev; i++) {
        const uint8_t *e = ev + i * 64;
        uint32_t nsid = ldl_le_p(e + 12);

        g_assert_cmphex(e[0], ==, FEMU_FDP_EVT_MEDIA_REALLOC);
        g_assert_cmphex(e[1], ==, 0x7);             /* PIV, NSIDV, LV */
        g_assert_cmpuint(nsid, >=, 1);
        g_assert_cmpuint(nsid, <=, 2);
        /* handle 3 is placement 0 of namespace 1 and 2 of namespace 2 */
        g_assert_cmpint(lduw_le_p(e + 2), ==, nsid == 1 ? 0 : 2);
        g_assert_cmpint(lduw_le_p(e + 34), ==, 3);
        g_assert_cmphex(e[16], ==, 1);              /* LBAV */
        g_assert_cmpuint(ldq_le_p(e + 20), >=, 32 * 8);
        g_assert_cmpuint(ldq_le_p(e + 20), <, 64 * 8);
        /* runs of one namespace are reported apart, so they alternate */
        if (i) {
            g_assert_cmpuint(nsid, !=, ldl_le_p(e - 64 + 12));
        }
        seen[nsid]++;
        nlb += lduw_le_p(e + 18);
    }
    g_assert_cmpuint(seen[1], >=, 1);
    g_assert_cmpuint(seen[2], >=, 1);
    g_assert_cmpuint(nlb, ==, 64 * 8);

    /* placement 2 is invalid for namespace 1 and valid for namespace 2 */
    g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 1, 0, 1, buf, list, 2),
                    ==, NVME_SUCCESS);
    g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 2, 0, 1, buf, list, 2),
                    ==, NVME_SUCCESS);
    g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 2, 1, 1, buf, list, 3),
                    ==, NVME_SUCCESS);
    cmd.opcode = NVME_ADM_CMD_GET_LOG_PAGE;
    cmd.nsid = cpu_to_le32(NVME_NSID_BROADCAST);
    cmd.dptr.prp1 = cpu_to_le64(log);
    cmd.cdw10 = cpu_to_le32(FEMU_LOG_FDP_EVENTS | (1 << 8) |
                            ((sizeof(hev) / 4 - 1) << 16));
    cmd.cdw11 = cpu_to_le32(1 << 16);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    qtest_memread(qts, log, hev, sizeof(hev));
    g_assert_cmpuint(ldl_le_p(hev), ==, 2);
    g_assert_cmphex(hev[64], ==, 0x03);
    g_assert_cmpint(lduw_le_p(hev + 64 + 2), ==, 2);
    g_assert_cmpuint(ldl_le_p(hev + 64 + 12), ==, 1);
    g_assert_cmphex(hev[128], ==, 0x03);
    g_assert_cmpint(lduw_le_p(hev + 128 + 2), ==, 3);
    g_assert_cmpuint(ldl_le_p(hev + 128 + 12), ==, 2);
    g_assert_cmpuint(femu_fdp_check(qts), ==, 0);

    guest_free(alloc, log);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * Two namespaces with the knobs FDP takes: a write buffer, fifo collection,
 * dftl, read refresh and the unit time limit. Both namespaces are filled,
 * then overwritten at random through both of each one's placements, and one
 * old page is read until its unit is refreshed. Every page reads back as last
 * written, the FTL holds each page once in a unit of a handle its namespace
 * lists, and log C0h counts the shared FTL once: its host pages are the
 * pages written, not twice that.
 */
void femu_test_fdp_ns_knobs(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    const uint32_t pages = 1408;    /* 5.5 MiB each */
    uint64_t buf = guest_alloc(alloc, 20 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t log = guest_alloc(alloc, 4096);
    g_autofree uint32_t *seq = g_new0(uint32_t, 2 * pages);
    uint64_t written = 0, rr0;
    uint32_t seed = 3, next = 1;
    QDict *rsp;
    QDict *ns;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    for (uint32_t n = 1; n <= 2; n++) {
        for (uint64_t page = 0; page < pages; page += 16) {
            for (uint32_t k = 0; k < 16; k++) {
                femu_fdpns_fill(qts, buf + k * 4096, n, page + k, next);
                seq[(n - 1) * pages + page + k] = next;
            }
            next++;
            g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, n, page, 16,
                                          buf, list, page / 16 % 2), ==,
                            NVME_SUCCESS);
            written += 16;
        }
    }
    for (i = 0; i < 600; i++) {
        uint32_t n, pid;
        uint64_t page;

        seed = seed * 1103515245 + 12345;
        n = 1 + ((seed >> 20) & 1);
        pid = (seed >> 21) & 1;
        /* the second half of each namespace; the first stays cold */
        page = pages / 2 + (seed >> 8) % (pages / 2);
        femu_fdpns_fill(qts, buf, n, page, next);
        seq[(n - 1) * pages + page] = next++;
        g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, n, page, 1, buf,
                                      list, pid), ==, NVME_SUCCESS);
        written++;
    }

    /* reads of one cold page of namespace 2 queue its unit for a refresh */
    rr0 = femu_c0h_field(&c, log, 40);
    for (i = 0; i < 16; i++) {
        g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_READ, 2, 5, 1, buf, list,
                                      -1), ==, NVME_SUCCESS);
    }
    femu_fdpns_fill(qts, buf, 1, pages - 1, next);
    seq[pages - 1] = next++;
    g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 1, pages - 1, 1, buf,
                                  list, 0), ==, NVME_SUCCESS);
    written++;
    g_assert_cmpuint(femu_c0h_field(&c, log, 40), >, rr0);

    /*
     * The buffer holds pages of both namespaces; a Flush through namespace
     * 1 programs all of them, and a second one has nothing left.
     */
    {
        NvmeCmd cmd = { 0 };
        uint64_t nand0 = femu_c0h_field(&c, log, 24);
        uint64_t nand1;

        cmd.opcode = NVME_CMD_FLUSH;
        cmd.nsid = cpu_to_le32(1);
        g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_SUCCESS);
        nand1 = femu_c0h_field(&c, log, 24);
        g_test_message("Flush programmed %" PRIu64 " held pages",
                       nand1 - nand0);
        g_assert_cmpuint(nand1, >, nand0);
        g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_SUCCESS);
        g_assert_cmpuint(femu_c0h_field(&c, log, 24), ==, nand1);
    }
    femu_fdpns_expect(qts, pages, pages);
    g_assert_cmpuint(femu_fdp_check(qts), ==, 0);
    g_assert_cmpuint(femu_c0h_field(&c, log, 8), ==, written);
    g_assert_cmpuint(femu_c0h_field(&c, log, 16), >, 0);
    /* each namespace reports the one FTL */
    for (uint32_t n = 1; n <= 2; n++) {
        ns = femu_fdpns_query(qts, n, "", &rsp);
        g_assert_cmpuint(qdict_get_int(qdict_get_qdict(ns, "counters"),
                                       "host-write-pages"), ==, written);
        qobject_unref(rsp);
    }
    for (uint32_t n = 1; n <= 2; n++) {
        for (uint64_t page = 0; page < pages; page += 7) {
            femu_fdpns_verify(&c, buf, list, n, page,
                              seq[(n - 1) * pages + page]);
        }
    }

    guest_free(alloc, log);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * Two NoSSD namespaces, lists 0:1 and 2: RUH Status reports each list, log
 * 21h marks handle 3 unused, and a handle update through namespace 2 logs
 * 00h with its namespace and placement identifier.
 */
void femu_test_fdp_ns_nossd(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t log = guest_alloc(alloc, 4096);
    uint64_t buf = guest_alloc(alloc, 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint8_t ruhu[8 + 4 * 8];
    uint8_t hev[64 + 8 * 64];
    uint16_t ruhid[8];
    uint64_t ruamw[8];
    NvmeCmd cmd = { 0 };
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    g_assert_cmpuint(femu_fdpns_ruhs(&c, 1, log, ruhid, ruamw), ==, 2);
    g_assert_cmpuint(ruhid[0], ==, 0);
    g_assert_cmpuint(ruhid[1], ==, 1);
    g_assert_cmpuint(femu_fdpns_ruhs(&c, 2, log, ruhid, ruamw), ==, 1);
    g_assert_cmpuint(ruhid[0], ==, 2);
    /* a written unit, so the update below moves the handle */
    g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 2, 0, 1, buf, list, 0),
                    ==, NVME_SUCCESS);
    g_assert_cmpint(femu_endgrp_log(&c, FEMU_LOG_FDP_RUH_USAGE, 0, log,
                                    sizeof(ruhu)), ==, NVME_SUCCESS);
    qtest_memread(qts, log, ruhu, sizeof(ruhu));
    for (i = 0; i < 4; i++) {
        g_assert_cmpint(ruhu[8 + i * 8], ==, i < 3 ? 1 : 0);
    }

    /* placement 0 of namespace 2: handle 2 */
    qtest_writew(qts, log, 0);
    cmd.opcode = FEMU_CMD_IO_MGMT_SEND;
    cmd.nsid = cpu_to_le32(2);
    cmd.dptr.prp1 = cpu_to_le64(log);
    cmd.cdw10 = cpu_to_le32(FEMU_IOMS_RUH_UPDATE);
    g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_SUCCESS);
    /* placement 1 does not exist on namespace 2 */
    qtest_writew(qts, log, 1);
    g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_INVALID_FIELD);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_GET_LOG_PAGE;
    cmd.nsid = cpu_to_le32(NVME_NSID_BROADCAST);
    cmd.dptr.prp1 = cpu_to_le64(log);
    cmd.cdw10 = cpu_to_le32(FEMU_LOG_FDP_EVENTS | (1 << 8) |
                            ((sizeof(hev) / 4 - 1) << 16));
    cmd.cdw11 = cpu_to_le32(1 << 16);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    qtest_memread(qts, log, hev, sizeof(hev));
    g_assert_cmpuint(ldl_le_p(hev), ==, 1);
    g_assert_cmphex(hev[64], ==, FEMU_FDP_EVT_RU_NOT_FULLY_WRITTEN);
    g_assert_cmpint(lduw_le_p(hev + 64 + 2), ==, 0);
    g_assert_cmpuint(ldl_le_p(hev + 64 + 12), ==, 2);
    g_assert_cmpint(lduw_le_p(hev + 64 + 34), ==, 2);

    guest_free(alloc, list);
    guest_free(alloc, buf);
    guest_free(alloc, log);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/* device_add of an FDP controller with @props, which realize refuses */
static void femu_fdpns_refused(QTestState *qts, const char *props,
                               const char *want)
{
    g_autofree char *json = g_strdup_printf(
        "{'driver':'femu','id':'fdpns','addr':'5','secsz':512,"
        "'secs_per_pg':8,'pgs_per_blk':4,'blks_per_pl':25,'pls_per_lun':1,"
        "'luns_per_ch':2,'nchs':2,%s}", props);
    QObject *args = qobject_from_json(json, &error_abort);
    QDict *rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':%p}",
                           args);
    const char *desc;

    g_assert_true(qdict_haskey(rsp, "error"));
    desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
    g_test_message("%s: %s", props, desc);
    g_assert_nonnull(strstr(desc, want));
    qobject_unref(rsp);
}

/* what realize refuses for FDP with more than one namespace */
void femu_test_fdp_ns_refused(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    static const struct {
        const char *props;
        const char *want;
    } cases[] = {
        { "'devsz_mb':1,'femu_mode':1,'namespaces':2,'subsys':'fdpsub',"
          "'namespace_modes':'bbssd,nossd'", "every namespace in bbssd" },
        { "'devsz_mb':1,'femu_mode':3,'namespaces':2,'subsys':'fdpsub'",
          "every namespace in bbssd" },
        { "'devsz_mb':1,'femu_mode':1,'namespaces':2,'subsys':'fdpsub',"
          "'namespace_sizes':'514K,510K'", "whole NAND pages" },
        { "'devsz_mb':1,'femu_mode':1,'namespaces':2,'subsys':'fdpsub',"
          "'fdp_trim_erase_all':1", "needs a single namespace" },
        { "'devsz_mb':2,'femu_mode':1,'namespaces':2,'subsys':'fdpsub'",
          "the 2 namespaces expose" },
        { "'devsz_mb':1,'femu_mode':1,'namespaces':2,"
          "'namespace_phls':'0,1'", "needs fdp=on" },
        { "'devsz_mb':1,'femu_mode':1,'namespaces':2,'subsys':'fdpsub',"
          "'namespace_phls':'0,1,2'", "count must equal" },
        { "'devsz_mb':1,'femu_mode':1,'namespaces':2,'subsys':'fdpsub',"
          "'namespace_phls':'0:4,1'", "handles are 0 to 3" },
        { "'devsz_mb':1,'femu_mode':1,'namespaces':2,'subsys':'fdpsub',"
          "'namespace_phls':'0:1:0,1'", "twice" },
        { "'devsz_mb':1,'femu_mode':1,'namespaces':2,'subsys':'fdpsub',"
          "'namespace_phls':'0,'", "lists no handle" },
        { "'devsz_mb':1,'femu_mode':1,'subsys':'fdpsub',"
          "'namespace_phls':'x'", "names handle 'x'" },
        /* only NVM command set namespaces (Base 2.3, 8.1.11) */
        { "'devsz_mb':1,'femu_mode':3,'subsys':'fdpsub'",
          "namespace 1 is zoned" },
        { "'devsz_mb':1,'femu_mode':0,'subsys':'fdpsub'",
          "namespace 1 is open-channel" },
        /* a 1 KiB unit holds no 4 KiB block */
        { "'devsz_mb':1,'femu_mode':2,'lba_index':3,'subsys':'fdpsub-tiny'",
          "smaller than a logical block" },
        /* reclaim groups: whole channels or LUNs of one channel */
        { "'devsz_mb':1,'femu_mode':1,'lba_index':3,'subsys':'fdpsub-rg3'",
          "must divide nchs (2)" },
        { "'devsz_mb':1,'femu_mode':1,'subsys':'fdpsub-rg2'",
          "needs a logical block of whole NAND pages" },
        { "'devsz_mb':1,'femu_mode':1,'lba_index':3,'subsys':'fdpsub-rg2'",
          "a reclaim group must hold every namespace" },
        { "'devsz_mb':1,'femu_mode':4,'fdm_size':1,'subsys':'fdpsub-rg2'",
          "needs a logical block of whole NAND pages" },
        /*
         * four groups of one die: 16 KiB units hold no 32 KiB block. The
         * namespace check sizes the unit from this geometry, so it refuses
         * before the bbssd check.
         */
        { "'devsz_mb':1,'femu_mode':1,'nlbaf':7,'lba_index':6,"
          "'subsys':'fdpsub-rg4'", "fdp.runs (16384) is smaller than a "
          "logical block of namespace 1 (32768 bytes)" },
    };

    for (int i = 0; i < ARRAY_SIZE(cases); i++) {
        femu_fdpns_refused(qts, cases[i].props, cases[i].want);
    }
    qos_invalidate_command_line();
}

/* Write Zeroes of @npages pages from @page of @nsid through @pid */
static uint16_t femu_fdpns_zeroes(FemuCtrlState *c, uint32_t nsid,
                                  uint64_t page, uint32_t npages, int pid,
                                  bool deac)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = NVME_CMD_WRITE_ZEROES;
    cmd.nsid = cpu_to_le32(nsid);
    cmd.cdw10 = cpu_to_le32(page * 8);
    cmd.cdw12 = cpu_to_le32((npages * 8 - 1) | (deac ? 1u << 25 : 0) |
                            (2u << 20));
    cmd.cdw13 = cpu_to_le32((uint32_t)pid << 16);
    return femu_io(c, &cmd);
}

/*
 * The other commands that place data, with lists 0:1 and 1:2. A format 2
 * Copy from namespace 2 into namespace 1 places through namespace 1's list,
 * Write Zeroes through namespace 2's, with and without deallocation, and a
 * handle update through namespace 1 moves the handle namespace 2 shares:
 * both see the fresh unit, and 00h names namespace 1.
 */
void femu_test_fdp_ns_cmds(void *obj, void *data,
                           QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 20 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t log = guest_alloc(alloc, 4096);
    uint8_t hev[64 + 8 * 64];
    uint16_t ruhid[8];
    uint64_t ruamw[8];
    uint64_t host, vpc;
    NvmeCmd cmd = { 0 };

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    /* four pages of namespace 2 through its placement 0: handle 1 */
    for (int k = 0; k < 4; k++) {
        femu_fdpns_fill(qts, buf + k * 4096, 2, k, 1);
    }
    g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 2, 0, 4, buf, list, 0),
                    ==, NVME_SUCCESS);
    femu_fdpns_expect(qts, 0, 4);

    /* copied to page 40 of namespace 1 through its placement 0: handle 0 */
    qtest_memset(qts, log, 0, 512);
    qtest_writew(qts, log + 4, 0x4);
    g_assert_cmpint(femu_hbs(&c, true, log), ==, NVME_SUCCESS);
    qtest_memset(qts, list, 0, 4096);
    qtest_writel(qts, list, 2);
    qtest_writeq(qts, list + 8, 0);
    qtest_writew(qts, list + 16, 32 - 1);
    cmd.opcode = FEMU_CMD_COPY;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(list);
    cmd.cdw10 = cpu_to_le32(40 * 8);
    cmd.cdw12 = cpu_to_le32((2 << 8) | (2u << 20));
    cmd.cdw13 = cpu_to_le32(0 << 16);
    g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_SUCCESS);
    femu_fdpns_expect(qts, 4, 4);
    femu_fdpns_handle(qts, 0, &host, &vpc);
    g_assert_cmpuint(vpc, ==, 4);
    femu_fdpns_handle(qts, 1, &host, &vpc);
    g_assert_cmpuint(vpc, ==, 4);
    femu_fdpns_verify(&c, buf, list, 2, 0, 1);
    qtest_memset(qts, buf, 0, 4096);
    g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_READ, 1, 41, 1, buf, list, -1),
                    ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 2);
    g_assert_cmpuint(qtest_readl(qts, buf + 4), ==, 1);

    /* zeroes into namespace 2's placement 1, handle 2, then deallocated */
    g_assert_cmpint(femu_fdpns_zeroes(&c, 2, 50, 4, 1, false), ==,
                    NVME_SUCCESS);
    femu_fdpns_expect(qts, 4, 8);
    femu_fdpns_handle(qts, 2, &host, &vpc);
    g_assert_cmpuint(vpc, ==, 4);
    g_assert_cmpint(femu_fdpns_zeroes(&c, 2, 50, 4, 1, true), ==,
                    NVME_SUCCESS);
    femu_fdpns_expect(qts, 4, 4);
    femu_fdpns_handle(qts, 2, &host, &vpc);
    g_assert_cmpuint(vpc, ==, 0);

    /* handle 1 holds 4 pages; namespace 1 moves it, namespace 2 sees it */
    femu_fdpns_ruhs(&c, 2, log, ruhid, ruamw);
    g_assert_cmpuint(ruhid[0], ==, 1);
    g_assert_cmpuint(ruamw[0], ==, 12 * 8);
    qtest_writew(qts, list, 1);
    g_assert_cmpint(femu_ruh_update(&c, list, 1), ==, NVME_SUCCESS);
    femu_fdpns_ruhs(&c, 2, log, ruhid, ruamw);
    g_assert_cmpuint(ruamw[0], ==, 16 * 8);
    femu_fdpns_ruhs(&c, 1, log, ruhid, ruamw);
    g_assert_cmpuint(ruhid[1], ==, 1);
    g_assert_cmpuint(ruamw[1], ==, 16 * 8);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_GET_LOG_PAGE;
    cmd.nsid = cpu_to_le32(NVME_NSID_BROADCAST);
    cmd.dptr.prp1 = cpu_to_le64(log);
    cmd.cdw10 = cpu_to_le32(FEMU_LOG_FDP_EVENTS | (1 << 8) |
                            ((sizeof(hev) / 4 - 1) << 16));
    cmd.cdw11 = cpu_to_le32(1 << 16);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    qtest_memread(qts, log, hev, sizeof(hev));
    g_assert_cmpuint(ldl_le_p(hev), ==, 1);
    g_assert_cmphex(hev[64], ==, FEMU_FDP_EVT_RU_NOT_FULLY_WRITTEN);
    g_assert_cmpint(lduw_le_p(hev + 64 + 2), ==, 1);
    g_assert_cmpuint(ldl_le_p(hev + 64 + 12), ==, 1);
    g_assert_cmpint(lduw_le_p(hev + 64 + 34), ==, 1);
    g_assert_cmpuint(femu_fdp_check(qts), ==, 0);
    femu_fdpns_expect(qts, 4, 4);

    guest_free(alloc, log);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * A controller with two namespaces and lists 0:1 and 1:2 is replaced by one
 * with a single 4 KiB namespace and list 1:3. Handle 0 and 2 are unused
 * again, so log 21h reports only 1 and 3, handle 1 takes the new format
 * rather than refusing it, and its byte counters stay with the subsystem.
 */
void femu_test_fdp_ns_replace(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    FemuCtrlState c2 = { 0 };
    uint64_t buf = guest_alloc(alloc, 20 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t log = guest_alloc(alloc, 4096);
    uint8_t ruhu[8 + 4 * 8];
    uint16_t ruhid[8];
    uint64_t ruamw[8];
    uint64_t host, vpc;
    QPCIDevice *pdev;
    QDict *rsp;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x3c, 20 * 4096);
    g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 2, 0, 8, buf, list, 0),
                    ==, NVME_SUCCESS);
    femu_disable(&c);

    qtest_qmp_device_del_send(qts, "fdpns-r");
    qtest_outl(qts, 0xae00 + 8, 1 << 4);    /* ACPI PCI hotplug: eject slot 4 */
    qtest_qmp_eventwait(qts, "DEVICE_DELETED");

    rsp = qtest_qmp(qts,
        "{'execute':'device_add','arguments':{'driver':'femu','id':'fdpns-r2',"
        "'addr':'4','devsz_mb':1,'femu_mode':1,'secsz':512,"
        "'secs_per_pg':8,'pgs_per_blk':4,'blks_per_pl':25,"
        "'pls_per_lun':1,'luns_per_ch':2,'nchs':2,'subsys':'fdpsub',"
        "'lba_index':3,'namespace_phls':'1:3'}}");
    if (!qdict_haskey(rsp, "return")) {
        g_test_message("%s", qdict_get_str(qdict_get_qdict(rsp, "error"),
                                           "desc"));
    }
    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
    pdev = qpci_device_find(femu->dev.bus, QPCI_DEVFN(4, 0));
    g_assert_nonnull(pdev);
    femu_enable(&c2, pdev, alloc);
    femu_create_io_queues(&c2);
    c2.lba_size = 4096;

    g_assert_cmpint(femu_endgrp_log(&c2, FEMU_LOG_FDP_RUH_USAGE, 0, log,
                                    sizeof(ruhu)), ==, NVME_SUCCESS);
    qtest_memread(qts, log, ruhu, sizeof(ruhu));
    for (int i = 0; i < 4; i++) {
        g_assert_cmpint(ruhu[8 + i * 8], ==, i == 1 || i == 3);
    }
    g_assert_cmpuint(femu_fdpns_ruhs(&c2, 1, log, ruhid, ruamw), ==, 2);
    g_assert_cmpuint(ruhid[0], ==, 1);
    g_assert_cmpuint(ruhid[1], ==, 3);
    g_assert_cmpuint(ruamw[0], ==, 16);
    /* the 8 pages namespace 2 wrote through handle 1 stay counted */
    femu_fdpns_handle(qts, 1, &host, &vpc);
    g_assert_cmpuint(host, ==, 8 * 4096);
    g_assert_cmpuint(vpc, ==, 0);

    femu_disable(&c2);
    g_free(pdev);
    guest_free(alloc, log);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    qos_invalidate_command_line();
}

/* HBMW and MBMW, the low 64 bits of each, from the FDP Statistics log */
static void femu_fdp_bytes(FemuCtrlState *c, uint64_t log, uint64_t *hbmw,
                           uint64_t *mbmw)
{
    g_assert_cmpint(femu_endgrp_log(c, FEMU_LOG_FDP_STATS, 0, log, 64), ==,
                    NVME_SUCCESS);
    *hbmw = qtest_readq(c->pdev->bus->qts, log);
    *mbmw = qtest_readq(c->pdev->bus->qts, log + 16);
}

/*
 * A handle whose units ran out shows the host a stand-in unit with no room,
 * which the FTL owns. With collection held off, handle updates through
 * placement 0 use up every free unit, and a write fills the last one. The
 * controller is then replaced by a NoSSD one on
 * the same subsystem, whose RUH Status reads that handle's unit: it must be
 * one of the subsystem's, not the freed stand-in. An ASan build reports the
 * use after free that a plain build reads past.
 */
void femu_test_fdp_replace_full(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    FemuCtrlState c2 = { 0 };
    uint64_t buf = guest_alloc(alloc, 20 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t log = guest_alloc(alloc, 4096);
    uint16_t ruhid[8];
    uint64_t ruamw[8];
    uint16_t status = NVME_SUCCESS;
    QPCIDevice *pdev;
    QDict *rsp;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x3c, 20 * 4096);
    /* a page, then a fresh unit, until no unit is free to move to */
    for (i = 0; i < 64 && status == NVME_SUCCESS; i++) {
        g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 1, i, 1, buf, list,
                                      0), ==, NVME_SUCCESS);
        qtest_writew(qts, list, 0);
        status = femu_ruh_update(&c, list, 1);
    }
    g_assert_cmphex(status, ==, NVME_CAP_EXCEEDED);
    /*
     * The unit fills with nothing to follow it: the handle has no unit, and
     * the rest of the write finds no room. HBMW counts only the pages the
     * write reached, as MBMW does.
     */
    {
        uint64_t h0, m0, h1, m1;

        femu_fdp_bytes(&c, log, &h0, &m0);
        g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 1, 100, 16, buf,
                                      list, 0), ==, NVME_CAP_EXCEEDED);
        femu_fdp_bytes(&c, log, &h1, &m1);
        g_assert_cmpuint(h1 - h0, ==, m1 - m0);
        g_assert_cmpuint(h1 - h0, <, 16 * 4096);
    }
    femu_fdpns_ruhs(&c, 1, log, ruhid, ruamw);
    g_assert_cmpuint(ruamw[0], ==, 0);
    femu_disable(&c);

    qtest_qmp_device_del_send(qts, "fdp-full");
    qtest_outl(qts, 0xae00 + 8, 1 << 4);    /* ACPI PCI hotplug: eject slot 4 */
    qtest_qmp_eventwait(qts, "DEVICE_DELETED");

    rsp = qtest_qmp(qts,
        "{'execute':'device_add','arguments':{'driver':'femu',"
        "'id':'fdp-full2','addr':'4','devsz_mb':1,'femu_mode':2,"
        "'subsys':'fdpsub'}}");
    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
    pdev = qpci_device_find(femu->dev.bus, QPCI_DEVFN(4, 0));
    g_assert_nonnull(pdev);
    femu_enable(&c2, pdev, alloc);
    femu_create_io_queues(&c2);
    g_assert_cmpuint(femu_fdpns_ruhs(&c2, 1, log, ruhid, ruamw), ==, 4);
    g_assert_cmpuint(ruhid[0], ==, 0);
    g_assert_cmpuint(ruamw[0], >, 0);
    femu_disable(&c2);
    g_free(pdev);

    guest_free(alloc, log);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    qos_invalidate_command_line();
}

/*
 * HBMW counts the bytes of user data the host wrote (Base 2.3, Figure 293),
 * MBMW what reached the media. One 512-byte block through placement 1 adds
 * 512 to HBMW and to handle 1's host bytes, and a 4 KiB page to MBMW when
 * it is programmed: at once, or with @data "buffer" when a Flush writes it
 * back. A run of whole pages adds the same to both.
 */
void femu_test_fdp_hbmw_blocks(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    bool buffer = !strcmp(data, "buffer");
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 20 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t log = guest_alloc(alloc, 4096);
    uint64_t h0, m0, h1, m1, host, vpc;
    NvmeCmd cmd = { 0 };

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x7e, 20 * 4096);
    femu_fdp_bytes(&c, log, &h0, &m0);

    g_assert_cmphex(femu_write_block_placed(&c, 9, buf, 1), ==, NVME_SUCCESS);
    femu_fdp_bytes(&c, log, &h1, &m1);
    g_assert_cmpuint(h1 - h0, ==, 512);
    g_assert_cmpuint(m1 - m0, ==, buffer ? 0 : 4096);
    femu_fdpns_handle(qts, 1, &host, &vpc);
    g_assert_cmpuint(host, ==, 512);

    if (buffer) {
        cmd.opcode = NVME_CMD_FLUSH;
        cmd.nsid = cpu_to_le32(1);
        g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_SUCCESS);
        femu_fdp_bytes(&c, log, &h1, &m1);
        g_assert_cmpuint(h1 - h0, ==, 512);
        g_assert_cmpuint(m1 - m0, ==, 4096);
    }

    /* two blocks across a page boundary: 1 KiB, on two pages */
    {
        NvmeRwCmd rw = { 0 };

        rw.opcode = NVME_CMD_WRITE;
        rw.nsid = cpu_to_le32(1);
        rw.dptr.prp1 = cpu_to_le64(buf);
        rw.slba = cpu_to_le64(15);
        rw.nlb = cpu_to_le16(1);
        rw.control = cpu_to_le16(2 << 4);
        rw.dspec = cpu_to_le16(1);
        g_assert_cmpint(femu_io(&c, (NvmeCmd *)&rw), ==, NVME_SUCCESS);
    }
    if (buffer) {
        g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_SUCCESS);
    }
    femu_fdp_bytes(&c, log, &h0, &m0);
    g_assert_cmpuint(h0 - h1, ==, 1024);
    g_assert_cmpuint(m0 - m1, ==, 2 * 4096);
    h1 = h0;
    m1 = m0;

    /* eight whole pages: the same bytes on both sides */
    g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 1, 16, 8, buf, list, 1),
                    ==, NVME_SUCCESS);
    if (buffer) {
        g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_SUCCESS);
    }
    femu_fdp_bytes(&c, log, &h0, &m0);
    g_assert_cmpuint(h0 - h1, ==, 8 * 4096);
    g_assert_cmpuint(m0 - m1, ==, 8 * 4096);

    guest_free(alloc, log);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * HBMW counts what the host asked to write (NVM 1.2, 4.1.4.6 names Write
 * Zeroes and Write Uncorrectable). On bbssd, Write Zeroes with the
 * Deallocate bit and Write Uncorrectable program no page: HBMW and the
 * handle's host bytes grow, MBMW and RUAMW do not.
 */
void femu_test_fdp_unprogrammed(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t log = guest_alloc(alloc, 4096);
    uint64_t h0, m0, h1, m1, host0, host1, vpc, ruamw;
    NvmeRwCmd rw = { 0 };

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_fdp_bytes(&c, log, &h0, &m0);
    femu_fdpns_handle(qts, 1, &host0, &vpc);
    ruamw = femu_ruh_ruamw(&c, log, 1);

    rw.opcode = NVME_CMD_WRITE_ZEROES;
    rw.nsid = cpu_to_le32(1);
    rw.slba = cpu_to_le64(64);
    rw.nlb = cpu_to_le16(7);
    rw.control = cpu_to_le16(1 << 9 | 2 << 4);   /* Deallocate */
    rw.dspec = cpu_to_le16(1);
    g_assert_cmpint(femu_io(&c, (NvmeCmd *)&rw), ==, NVME_SUCCESS);
    rw.opcode = 0x04;                            /* Write Uncorrectable */
    rw.control = cpu_to_le16(2 << 4);
    g_assert_cmpint(femu_io(&c, (NvmeCmd *)&rw), ==, NVME_SUCCESS);

    femu_fdp_bytes(&c, log, &h1, &m1);
    femu_fdpns_handle(qts, 1, &host1, &vpc);
    g_assert_cmpuint(h1 - h0, ==, 2 * 4096);
    g_assert_cmpuint(m1 - m0, ==, 0);
    g_assert_cmpuint(host1 - host0, ==, 2 * 4096);
    g_assert_cmpuint(femu_ruh_ruamw(&c, log, 1), ==, ruamw);

    guest_free(alloc, log);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * RUAMW counts logical blocks, so a reclaim unit must hold one. A Format to
 * a block larger than fdp.runs (1 KiB here) fails with Invalid Format.
 */
void femu_test_fdp_runs_block(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t log = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    g_assert_cmpuint(femu_ruh_ruamw(&c, log, 0), ==, 2);
    g_assert_cmpint(femu_format_dw10(&c, 3), ==, NVME_INVALID_FORMAT);
    g_assert_cmpuint(femu_ruh_ruamw(&c, log, 0), ==, 2);

    guest_free(alloc, log);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/* MBE of the FDP Statistics log */
static uint64_t femu_fdp_mbe(FemuCtrlState *c, uint64_t log)
{
    g_assert_cmpint(femu_endgrp_log(c, FEMU_LOG_FDP_STATS, 0, log, 64), ==,
                    NVME_SUCCESS);
    return qtest_readq(c->pdev->bus->qts, log + 32);
}

/*
 * A NoSSD namespace under FDP has no NAND model. Its writes still count:
 * HBMW per endurance group (Base 2.3, Figure 293), for Write, Copy, Write
 * Zeroes and Write Uncorrectable (NVM 1.2, 4.1.4.6). The backend keeps each
 * byte of data once and no controller write exists, so MBMW adds the bytes
 * of the commands that store data, and MBE stays 0. The unit of a handle
 * fills by the blocks stored: 64 KiB units of 512-byte blocks hold 128
 * blocks, and a write that reaches the end leaves the handle on a fresh
 * unit (RUAMW 128), or part way into the next one.
 */
void femu_test_fdp_nossd_counts(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 20 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t log = guest_alloc(alloc, 4096);
    uint64_t h0, m0, h1, m1, hev0;
    uint64_t slba = 0;
    uint16_t nlb = 8;
    NvmeRwCmd rw = { 0 };

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    g_assert_cmpuint(c.lba_size, ==, 512);
    femu_fdp_bytes(&c, log, &h0, &m0);
    g_assert_cmpuint(femu_ruh_ruamw(&c, log, 1), ==, 128);

    /* one page through placement 1 */
    g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 1, 0, 1, buf, list, 1),
                    ==, NVME_SUCCESS);
    femu_fdp_bytes(&c, log, &h1, &m1);
    g_assert_cmpuint(h1 - h0, ==, 4096);
    g_assert_cmpuint(m1 - m0, ==, 4096);
    g_assert_cmpuint(femu_fdp_mbe(&c, log), ==, 0);
    g_assert_cmpuint(femu_ruh_ruamw(&c, log, 1), ==, 120);
    g_assert_cmpuint(femu_ruh_ruamw(&c, log, 0), ==, 128);

    /* the rest of the unit: the handle is on a fresh one */
    g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 1, 1, 15, buf, list, 1),
                    ==, NVME_SUCCESS);
    g_assert_cmpuint(femu_ruh_ruamw(&c, log, 1), ==, 128);
    /* 136 blocks: one unit and 8 blocks of the next */
    g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 1, 16, 17, buf, list, 1),
                    ==, NVME_SUCCESS);
    g_assert_cmpuint(femu_ruh_ruamw(&c, log, 1), ==, 120);

    /* no directive: placement handle 0 */
    g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 1, 40, 1, buf, list, -1),
                    ==, NVME_SUCCESS);
    g_assert_cmpuint(femu_ruh_ruamw(&c, log, 0), ==, 120);
    femu_fdp_bytes(&c, log, &h0, &m0);
    g_assert_cmpuint(h0 - h1, ==, (15 + 17 + 1) * 4096);
    g_assert_cmpuint(m0 - m1, ==, (15 + 17 + 1) * 4096);

    /*
     * HBMW counts Write Zeroes with or without the Deallocate bit, and Write
     * Uncorrectable: 4.1.4.6 names both commands. Only Write Zeroes without
     * the bit stores data, for MBMW and the unit.
     */
    rw.opcode = NVME_CMD_WRITE_ZEROES;
    rw.nsid = cpu_to_le32(1);
    rw.slba = cpu_to_le64(512);
    rw.nlb = cpu_to_le16(7);
    rw.control = cpu_to_le16(2 << 4);
    rw.dspec = cpu_to_le16(1);
    g_assert_cmpint(femu_io(&c, (NvmeCmd *)&rw), ==, NVME_SUCCESS);
    rw.control = cpu_to_le16(1 << 9 | 2 << 4);   /* Deallocate */
    g_assert_cmpint(femu_io(&c, (NvmeCmd *)&rw), ==, NVME_SUCCESS);
    rw.opcode = 0x04;                            /* Write Uncorrectable */
    rw.control = cpu_to_le16(2 << 4);
    g_assert_cmpint(femu_io(&c, (NvmeCmd *)&rw), ==, NVME_SUCCESS);
    femu_fdp_bytes(&c, log, &h1, &m1);
    g_assert_cmpuint(h1 - h0, ==, 3 * 4096);
    g_assert_cmpuint(m1 - m0, ==, 4096);
    g_assert_cmpuint(femu_ruh_ruamw(&c, log, 1), ==, 112);
    h0 = h1;
    m0 = m1;

    /* the write portion of a Copy, through placement 0 */
    g_assert_cmpint(femu_copy(&c, list, 1024, &slba, &nlb, 1, 1, 2 << 20), ==,
                    NVME_SUCCESS);
    femu_fdp_bytes(&c, log, &h1, &m1);
    g_assert_cmpuint(h1 - h0, ==, 4096);
    g_assert_cmpuint(m1 - m0, ==, 4096);
    g_assert_cmpuint(femu_ruh_ruamw(&c, log, 0), ==, 112);
    g_assert_cmpuint(femu_fdp_mbe(&c, log), ==, 0);

    /* RUH Update leaves the part-written unit: event 00h, then a full one */
    hev0 = femu_fdp_host_events(&c, log, NULL);
    qtest_writew(femu->dev.bus->qts, log, 1);
    g_assert_cmpint(femu_ruh_update(&c, log, 1), ==, NVME_SUCCESS);
    g_assert_cmpuint(femu_fdp_host_events(&c, log, NULL), ==, hev0 + 1);
    g_assert_cmpuint(femu_ruh_ruamw(&c, log, 1), ==, 128);
    /* the unit is empty now: it stays, and no event follows (7.4.1.1) */
    qtest_writew(femu->dev.bus->qts, log, 1);
    g_assert_cmpint(femu_ruh_update(&c, log, 1), ==, NVME_SUCCESS);
    g_assert_cmpuint(femu_fdp_host_events(&c, log, NULL), ==, hev0 + 1);

    guest_free(alloc, log);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * The FDP Configurations log (Base 2.3, Figures 286 and 287): one valid
 * configuration with the group count, the RGIF bits that hold a group
 * identifier, and MAXPIDS. MAXPIDS is 0's based and below NRG x NRUH. A RUH
 * Update takes that many identifiers and refuses one more (7.4.1.1).
 */
void femu_test_fdp_confs(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    const FemuFdpConfWant *want = data;
    uint32_t pids = MIN(128, want->nrg * want->nruh);
    FemuCtrlState c = { 0 };
    uint64_t log = guest_alloc(alloc, 4096);
    uint8_t conf[16 + 64];
    NvmeCmd cmd = { 0 };

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    g_assert_cmpint(femu_endgrp_log(&c, 0x20, 0, log, sizeof(conf)), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, log, conf, sizeof(conf));
    g_assert_cmpuint(lduw_le_p(conf), ==, 0);
    g_assert_cmphex(conf[16 + 2] & 0x80, ==, 0x80);
    g_assert_cmpuint(conf[16 + 2] & 0xf, ==, want->rgif);
    g_assert_cmpuint(ldl_le_p(conf + 16 + 4), ==, want->nrg);
    g_assert_cmpuint(lduw_le_p(conf + 16 + 8), ==, want->nruh);
    g_assert_cmpuint(lduw_le_p(conf + 16 + 10), ==, pids - 1);
    g_assert_cmpuint(ldq_le_p(conf + 16 + 16), ==, want->runs);

    /* MAXPIDS + 1 identifiers of placement handle 0 pass, one more fails */
    for (uint32_t i = 0; i <= pids; i++) {
        qtest_writew(qts, log + 2 * i, 0);
    }
    cmd.opcode = FEMU_CMD_IO_MGMT_SEND;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(log);
    cmd.cdw10 = cpu_to_le32(FEMU_IOMS_RUH_UPDATE | ((pids - 1) << 16));
    g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_SUCCESS);
    cmd.cdw10 = cpu_to_le32(FEMU_IOMS_RUH_UPDATE | (pids << 16));
    g_assert_cmpint(femu_io(&c, &cmd), ==, NVME_INVALID_FIELD);

    guest_free(alloc, log);
    femu_disable(&c);
    qos_invalidate_command_line();
}

#define FEMU_RG_MAX 4

/*
 * The RUH Status of namespace 1: the count, then the PID, RUH ID and RUAMW
 * of each descriptor, at most 16.
 */
static uint16_t femu_rg_ruhs(FemuCtrlState *c, uint64_t buf, uint16_t *pid,
                             uint16_t *ruhid, uint64_t *ruamw)
{
    NvmeCmd cmd = { 0 };
    uint8_t st[16 + 16 * 32];
    uint16_t n;

    cmd.opcode = FEMU_CMD_IO_MGMT_RECV;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(FEMU_IOMR_RUH_STATUS);
    cmd.cdw11 = cpu_to_le32(sizeof(st) / 4 - 1);
    g_assert_cmpint(femu_io(c, &cmd), ==, NVME_SUCCESS);
    qtest_memread(c->pdev->bus->qts, buf, st, sizeof(st));
    n = lduw_le_p(st + 14);
    for (uint16_t i = 0; i < MIN(n, 16); i++) {
        pid[i] = lduw_le_p(st + 16 + 32 * i);
        ruhid[i] = lduw_le_p(st + 16 + 32 * i + 2);
        ruamw[i] = ldq_le_p(st + 16 + 32 * i + 8);
    }
    return n;
}

/*
 * From query-femu: the valid pages of each (group, handle), and the most
 * erases of a block in each group.
 */
static void femu_rg_units(QTestState *qts, uint64_t vpc[FEMU_RG_MAX][4],
                          uint64_t *erases)
{
    QDict *rsp;
    QDict *ns = femu_fdpns_query(qts, 1, "'kind':'reclaim-units','limit':4096",
                                 &rsp);
    QDict *fdp = qdict_get_qdict(ns, "fdp");
    QListEntry *e;

    memset(vpc, 0, sizeof(uint64_t) * FEMU_RG_MAX * 4);
    memset(erases, 0, sizeof(uint64_t) * FEMU_RG_MAX);
    QLIST_FOREACH_ENTRY(qdict_get_qlist(fdp, "reclaim-units"), e) {
        QDict *u = qobject_to(QDict, qlist_entry_obj(e));
        int g = qdict_get_int(u, "group");

        g_assert_cmpint(g, <, FEMU_RG_MAX);
        erases[g] = MAX(erases[g], qdict_get_int(u, "erase-max"));
        if (qdict_haskey(u, "handle")) {
            vpc[g][qdict_get_int(u, "handle")] += qdict_get_int(u, "vpc");
        }
    }
    qobject_unref(rsp);
}

/*
 * query-femu lists each group with its dies: group g takes the g-th of nrg
 * equal runs of the dies in the order ch x luns_per_ch + lun, whole
 * channels or LUNs of one channel.
 */
static void femu_rg_check_groups(QTestState *qts, const FemuRgWant *want)
{
    uint32_t per = want->nchs * want->luns / want->nrg;
    QDict *rsp;
    QDict *ns = femu_fdpns_query(qts, 1, "", &rsp);
    QDict *fdp = qdict_get_qdict(ns, "fdp");
    QListEntry *e;
    uint32_t g = 0;

    g_assert_cmpint(qdict_get_int(fdp, "reclaim-groups"), ==, want->nrg);
    QLIST_FOREACH_ENTRY(qdict_get_qlist(fdp, "groups"), e) {
        QDict *d = qobject_to(QDict, qlist_entry_obj(e));
        uint32_t d0 = g * per;

        g_assert_cmpint(qdict_get_int(d, "id"), ==, g);
        g_assert_cmpint(qdict_get_int(d, "first-channel"), ==,
                        d0 / want->luns);
        g_assert_cmpint(qdict_get_int(d, "first-lun"), ==, d0 % want->luns);
        g_assert_cmpint(qdict_get_int(d, "channels"), ==,
                        per >= want->luns ? per / want->luns : 1);
        g_assert_cmpint(qdict_get_int(d, "luns"), ==,
                        per >= want->luns ? want->luns : per);
        g_assert_cmpint(qdict_get_int(d, "free-units"), >, 0);
        g++;
    }
    g_assert_cmpuint(g, ==, want->nrg);
    qobject_unref(rsp);
}

/*
 * Placement into reclaim groups (Base 2.3, 8.1.11; Figures 289 and 290).
 * RUH Status has a descriptor per placement handle and group, by handle and
 * then by group, and each PID carries the group in its RGIF top bits. A
 * write through (group g, handle 1) goes to a unit of handle 1 in group g
 * only, and RUAMW of that pair alone goes down. Writes with no directive
 * take placement handle 0 in the group with the most free units, in turn
 * on a tie, so they spread over the groups. A PID with bit 15 - RGIF set
 * names no placement handle: event 03h, with the group and handle the
 * controller took. RUH Update of one pair moves that pair only (00h).
 * The test device has 4 KiB blocks and 4 KiB pages.
 */
void femu_test_fdp_rg_place(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    const FemuRgWant *want = data;
    uint32_t nrg = want->nrg;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t log = guest_alloc(alloc, 4096);
    uint64_t vpc[FEMU_RG_MAX][4], erases[FEMU_RG_MAX];
    uint16_t pid[16], ruhid[16];
    uint64_t ruamw[16], full;
    uint8_t hev[64 + 8 * 64];
    uint16_t bad_pid;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    c.lba_size = 4096;              /* lba_index=3 */
    femu_rg_check_groups(qts, want);

    g_assert_cmpuint(femu_rg_ruhs(&c, log, pid, ruhid, ruamw), ==, 4 * nrg);
    full = ruamw[0];
    for (uint32_t i = 0; i < 4 * nrg; i++) {
        uint16_t ph = i / nrg, rg = i % nrg;

        g_assert_cmphex(pid[i], ==, (rg << (16 - want->rgif)) | ph);
        g_assert_cmpuint(ruhid[i], ==, ph);
        g_assert_cmpuint(ruamw[i], ==, full);
    }

    /* two pages through placement handle 1 of each group */
    for (uint32_t g = 0; g < nrg; g++) {
        femu_fdpns_fill(qts, buf, 1, 8 * g, 1);
        g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 1, 8 * g, 1, buf,
                                      list, (g << (16 - want->rgif)) | 1),
                        ==, NVME_SUCCESS);
        femu_fdpns_fill(qts, buf, 1, 8 * g + 1, 1);
        g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 1, 8 * g + 1, 1,
                                      buf, list,
                                      (g << (16 - want->rgif)) | 1),
                        ==, NVME_SUCCESS);
        /* the pages are in group g alone: groups after it are still empty */
        femu_rg_units(qts, vpc, erases);
        for (uint32_t o = 0; o < nrg; o++) {
            g_assert_cmpuint(vpc[o][1], ==, o <= g ? 2 : 0);
        }
    }
    femu_rg_units(qts, vpc, erases);
    femu_rg_ruhs(&c, log, pid, ruhid, ruamw);
    for (uint32_t g = 0; g < nrg; g++) {
        for (int h = 0; h < 4; h++) {
            g_assert_cmpuint(vpc[g][h], ==, h == 1 ? 2 : 0);
        }
        g_assert_cmpuint(ruamw[1 * nrg + g], ==, full - 2);
        g_assert_cmpuint(ruamw[0 * nrg + g], ==, full);
    }
    g_assert_cmpuint(femu_fdp_check(qts), ==, 0);
    for (uint32_t g = 0; g < nrg; g++) {
        femu_fdpns_verify(&c, buf, list, 1, 8 * g, 1);
        femu_fdpns_verify(&c, buf, list, 1, 8 * g + 1, 1);
    }

    /* no directive: handle 0, one page in each group in turn */
    for (uint32_t i = 0; i < 2 * nrg; i++) {
        g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 1, 64 + i, 1, buf,
                                      list, -1), ==, NVME_SUCCESS);
    }
    femu_rg_units(qts, vpc, erases);
    for (uint32_t g = 0; g < nrg; g++) {
        g_assert_cmpuint(vpc[g][0], ==, 2);
    }

    /*
     * Bit 15 - RGIF is the top bit of the placement handle (Figure 290):
     * placement handle 2^(15 - RGIF), which the namespace does not have.
     * With nrg 3 the group field also holds 3, which is no group.
     */
    bad_pid = 1 << (15 - want->rgif);
    if (nrg == 3) {
        bad_pid = 3 << (16 - want->rgif);
    }
    g_assert_cmpuint(femu_fdp_host_events(&c, log, NULL), ==, 0);
    g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 1, 80, 1, buf, list,
                                  bad_pid), ==, NVME_SUCCESS);
    g_assert_cmpuint(femu_fdp_host_events(&c, log, NULL), ==, 1);
    qtest_memread(qts, log, hev, sizeof(hev));
    g_assert_cmphex(hev[64], ==, 0x03);
    g_assert_cmphex(hev[64 + 1], ==, 0x7);
    g_assert_cmphex(lduw_le_p(hev + 64 + 2), ==, bad_pid);
    g_assert_cmpuint(lduw_le_p(hev + 64 + 32), <, nrg);
    g_assert_cmpuint(lduw_le_p(hev + 64 + 34), ==, 0);

    /* RUH Update of (group nrg - 1, handle 1) moves that pair alone */
    qtest_writew(qts, buf, ((nrg - 1) << (16 - want->rgif)) | 1);
    g_assert_cmpint(femu_ruh_update(&c, buf, 1), ==, NVME_SUCCESS);
    femu_rg_ruhs(&c, log, pid, ruhid, ruamw);
    for (uint32_t g = 0; g < nrg; g++) {
        g_assert_cmpuint(ruamw[1 * nrg + g], ==,
                         g == nrg - 1 ? full : full - 2);
    }
    g_assert_cmpuint(femu_fdp_host_events(&c, log, NULL), ==, 2);
    qtest_memread(qts, log, hev, sizeof(hev));
    g_assert_cmphex(hev[64 + 64], ==, 0x00);
    g_assert_cmphex(lduw_le_p(hev + 128 + 2), ==,
                    ((nrg - 1) << (16 - want->rgif)) | 1);
    g_assert_cmpuint(lduw_le_p(hev + 128 + 32), ==, nrg - 1);
    g_assert_cmpuint(lduw_le_p(hev + 128 + 34), ==, 1);
    g_assert_cmpuint(femu_fdp_check(qts), ==, 0);

    /* a 512-byte block would let one page hold blocks of two groups */
    g_assert_cmpint(femu_format_dw10(&c, 0), ==, NVME_INVALID_FORMAT);

    guest_free(alloc, log);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * The whole namespace through one group, then overwrites of random pages
 * through the same (group, handle) until collection has run in it many
 * times. A group holds the whole namespace, so every write succeeds. The
 * other group is never touched: no valid page and no erase there. Every
 * page reads back, and the checks find each page on the dies of its unit's
 * group. An initially isolated handle logs its moves with that group.
 */
void femu_test_fdp_rg_gc(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    const FemuRgWant *want = data;
    const uint32_t pages = 256;
    const uint32_t g = want->nrg - 1;
    const uint16_t use = (g << (16 - want->rgif)) | want->ph;
    const uint32_t burst = want->burst ? want->burst : 1;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 16 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t log = guest_alloc(alloc, 4096);
    uint64_t vpc[FEMU_RG_MAX][4], erases[FEMU_RG_MAX];
    uint64_t mapped, lost, orphans;
    uint32_t seq[256] = { 0 };
    uint8_t ev[8 * 64];
    uint32_t seed = 5, nev;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    c.lba_size = 4096;              /* lba_index=3 */
    for (uint32_t p = 0; p < pages; p++) {
        seq[p] = 1;
        femu_fdpns_fill(qts, buf, 1, p, 1);
        g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 1, p, 1, buf, list,
                                      use), ==, NVME_SUCCESS);
    }
    /*
     * A write of several pages takes more units than one background pass
     * per command frees, so collection in the write's group must run in
     * the foreground.
     */
    for (uint32_t i = 0; i < 4 * pages / burst; i++) {
        uint32_t p;

        seed = seed * 1103515245 + 12345;
        p = (seed >> 8) % (pages - burst + 1);
        for (uint32_t k = 0; k < burst; k++) {
            femu_fdpns_fill(qts, buf + k * 4096, 1, p + k, ++seq[p + k]);
        }
        g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 1, p, burst, buf,
                                      list, use), ==, NVME_SUCCESS);
    }

    femu_rg_units(qts, vpc, erases);
    for (uint32_t o = 0; o < want->nrg; o++) {
        uint64_t sum = 0;

        for (int h = 0; h < 4; h++) {
            sum += vpc[o][h];
        }
        g_assert_cmpuint(sum, ==, o == g ? pages : 0);
        g_assert_cmpuint(erases[o], ==, o == g ? erases[o] : 0);
    }
    g_assert_cmpuint(erases[g], >, 0);
    g_assert_cmpuint(vpc[g][want->ph], ==, pages);
    g_assert_cmpuint(femu_fdp_check(qts), ==, 0);
    femu_ftl_check(qts, &mapped, &lost, &orphans);
    g_assert_cmpuint(mapped, ==, pages);
    g_assert_cmpuint(lost, ==, 0);
    g_assert_cmpuint(orphans, ==, 0);
    for (uint32_t p = 0; p < pages; p += 7) {
        femu_fdpns_verify(&c, buf, list, 1, p, seq[p]);
    }

    /* moves of initially isolated data name the group they happened in */
    nev = femu_fdp_ctrl_events(&c, log, ev, 8);
    g_test_message("%u controller events", nev);
    if (want->ph == 3) {
        g_assert_cmpuint(nev, >, 0);
    }
    for (uint32_t i = 0; i < MIN(nev, 8); i++) {
        g_assert_cmphex(ev[i * 64 + 1] & 0x4, ==, 0x4);
        g_assert_cmpuint(lduw_le_p(ev + i * 64 + 32), ==, g);
        g_assert_cmpuint(lduw_le_p(ev + i * 64 + 34), ==, 3);
    }

    guest_free(alloc, log);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * The namespace's own mode decides the Format rule: a bbssd namespace on a
 * controller of another mode (namespace_modes) keeps whole-page blocks
 * with reclaim groups. A Format of it, and a Format of every namespace,
 * to 512-byte blocks fails with Invalid Format.
 */
void femu_test_fdp_rg_format_mode(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd = { 0 };

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_format_dw10(&c, 0), ==, NVME_INVALID_FORMAT);
    cmd.opcode = NVME_ADM_CMD_FORMAT_NVM;
    cmd.nsid = cpu_to_le32(NVME_NSID_BROADCAST);
    g_assert_cmpint(FEMU_SC(femu_admin(&c, &cmd)), ==, NVME_INVALID_FORMAT);
    /* 4 KiB blocks stay allowed */
    g_assert_cmpint(femu_format_dw10(&c, 3), ==, NVME_SUCCESS);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * A full group must not stop writes to another group. With collection held
 * off (no unit kept free), page writes and RUH Updates through group 0 use
 * up its units, and writes through it then fill the write buffer with pages
 * that have nowhere to go. A write through group 1 still succeeds: its page
 * goes to group 1's unit at once. RUH Update of group 1 writes back only
 * the held pages of that pair, of which there are none, so it succeeds too.
 * Flush cannot write group 0's pages and fails, as before.
 */
void femu_test_fdp_rg_buffer(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t log = guest_alloc(alloc, 4096);
    uint64_t vpc[FEMU_RG_MAX][4], erases[FEMU_RG_MAX];
    uint16_t status = NVME_SUCCESS;
    NvmeCmd cmd = { 0 };
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    c.lba_size = 4096;              /* lba_index=3 */
    qtest_memset(qts, buf, 0x5a, 4096);

    /* a page, then a fresh unit, until group 0 has no unit left */
    for (i = 0; i < 128 && status == NVME_SUCCESS; i++) {
        g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 1, i, 1, buf, list,
                                      0), ==, NVME_SUCCESS);
        qtest_writew(qts, list, 0);
        status = femu_ruh_update(&c, list, 1);
    }
    g_assert_cmphex(status, ==, NVME_CAP_EXCEEDED);
    /* group 0 pages until the buffer holds only pages with nowhere to go */
    for (i = 0; i < 64; i++) {
        status = femu_fdpns_io(&c, NVME_CMD_WRITE, 1, 160 + i, 1, buf, list,
                               0);
        if (status == NVME_CAP_EXCEEDED) {
            break;
        }
        g_assert_cmphex(status, ==, NVME_SUCCESS);
    }
    g_assert_cmphex(status, ==, NVME_CAP_EXCEEDED);

    femu_rg_units(qts, vpc, erases);
    g_assert_cmpuint(vpc[1][0], ==, 0);
    g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 1, 250, 1, buf, list,
                                  (1 << 15) | 0), ==, NVME_SUCCESS);
    femu_rg_units(qts, vpc, erases);
    g_assert_cmpuint(vpc[1][0], ==, 1);

    qtest_writew(qts, list, (1 << 15) | 0);
    g_assert_cmphex(femu_ruh_update(&c, list, 1), ==, NVME_SUCCESS);

    cmd.opcode = NVME_CMD_FLUSH;
    cmd.nsid = cpu_to_le32(1);
    g_assert_cmphex(femu_io(&c, &cmd), ==, NVME_CAP_EXCEEDED);
    g_assert_cmpuint(femu_fdp_check(qts), ==, 0);

    guest_free(alloc, log);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * A write that names a placement identifier the namespace does not have goes
 * through placement handle 0 in a group the controller selects (Base 2.3,
 * 8.1.11). Event 03h carries the host's identifier with PIV, the namespace,
 * and with LV the group and handle the controller selected (Figure 296).
 * The page counts for handle 0, and RUAMW of placement 0 goes down.
 */
void femu_test_fdp_invalid_pid(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t log = guest_alloc(alloc, 4096);
    uint8_t hev[64 + 8 * 64];
    uint64_t h0, m0, h1, m1, ruamw0;
    uint32_t n;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_fdp_bytes(&c, log, &h0, &m0);
    ruamw0 = femu_ruh_ruamw(&c, log, 0);

    /* four handles, so placement handle 9 does not exist */
    g_assert_cmphex(femu_fdpns_io(&c, NVME_CMD_WRITE, 1, 0, 1, buf, list, 9),
                    ==, NVME_SUCCESS);

    n = femu_fdp_host_events(&c, log, NULL);
    g_assert_cmpuint(n, ==, 1);
    qtest_memread(qts, log, hev, sizeof(hev));
    g_assert_cmphex(hev[64], ==, 0x03);
    g_assert_cmphex(hev[64 + 1], ==, 0x7);           /* PIV, NSIDV, LV */
    g_assert_cmpuint(lduw_le_p(hev + 64 + 2), ==, 9);
    g_assert_cmpuint(ldl_le_p(hev + 64 + 12), ==, 1);
    g_assert_cmpuint(lduw_le_p(hev + 64 + 32), ==, 0);
    g_assert_cmpuint(lduw_le_p(hev + 64 + 34), ==, 0);

    femu_fdp_bytes(&c, log, &h1, &m1);
    g_assert_cmpuint(h1 - h0, ==, 4096);
    g_assert_cmpuint(m1 - m0, ==, 4096);
    g_assert_cmpuint(femu_ruh_ruamw(&c, log, 0), ==,
                     ruamw0 - 4096 / c.lba_size);

    guest_free(alloc, log);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * A DSM range of no blocks at LBA 0 on an FDP controller: the deallocate
 * range ends one block before it starts, so it must touch no page. Control:
 * a one-block range then completes too.
 */
void femu_test_fdp_dsm_empty(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint64_t list = guest_alloc(alloc, 4096);

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    g_assert_cmphex(FEMU_SC(femu_dealloc_range(&c, 0, 0, list)), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(FEMU_SC(femu_dealloc_range(&c, 0, 1, list)), ==,
                    NVME_SUCCESS);
    guest_free(alloc, list);
    femu_disable(&c);
}

/* x-fdp-slc of device fdpt into @v: tt, free, closed, folds, handles 0-3 */
static void femu_fdp_slc(QTestState *qts, uint64_t v[8])
{
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                           "'path':'/machine/peripheral/fdpt',"
                           "'property':'x-fdp-slc'}}");
    const char *r;

    g_assert_true(qdict_haskey(rsp, "return"));
    r = qdict_get_str(rsp, "return");
    g_test_message("x-fdp-slc %s", r);
    g_assert_cmpint(sscanf(r, "%" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64
                           " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64,
                           &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6],
                           &v[7]), ==, 8);
    qobject_unref(rsp);
}

/* x-fdp-check of device fdpt: 0 when every unit is in one right place */
static uint64_t femu_fdpt_check(QTestState *qts)
{
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                           "'path':'/machine/peripheral/fdpt',"
                           "'property':'x-fdp-check'}}");
    uint64_t bad;

    g_assert_true(qdict_haskey(rsp, "return"));
    bad = g_ascii_strtoull(qdict_get_str(rsp, "return"), NULL, 10);
    qobject_unref(rsp);
    return bad;
}

/*
 * The pSLC tier under FDP (tier_mode=static, 4 persistently isolated
 * handles). A dense unit is 4 dies x 48 TLC pages; a pSLC unit holds 4 x
 * 16 = 64 pages, so tier_static_mb=1 is 4 pSLC units, which the 4 handles
 * take as their first write units. 64 pages through handle 0 fill its
 * unit: handle 0 goes on in a dense unit, and the request folds the full
 * pSLC unit into handle 0's collection unit, which frees it. Handle 1
 * then fills its unit and takes the freed one, and its old one folds.
 * @data "gc-fw": with fw_gc_page_ns, each moved page also takes one slot.
 */
void femu_test_fdp_tier(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t log = guest_alloc(alloc, 512);
    uint64_t v[8];

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x76, 4 * 4096);
    femu_fdp_slc(qts, v);
    g_assert_cmpuint(v[0], ==, 4);
    g_assert_cmpuint(v[1], ==, 0);
    g_assert_cmpuint(v[3], ==, 0);
    g_assert_cmpuint(v[4] + v[5] + v[6] + v[7], ==, 4);

    for (int i = 0; i < 16; i++) {
        g_assert_cmphex(femu_fdp_wb_write(&c, i * 4, 4, buf, list, 0, false),
                        ==, NVME_SUCCESS);
    }
    femu_fdp_slc(qts, v);
    g_assert_cmpuint(v[3], ==, 1);          /* one fold */
    g_assert_cmpuint(v[1], ==, 1);          /* it freed the unit */
    g_assert_cmpuint(v[2], ==, 0);
    g_assert_cmpuint(v[4], ==, 0);          /* handle 0 writes dense now */
    g_assert_cmpuint(femu_fdpt_check(qts), ==, 0);

    for (int i = 0; i < 16; i++) {
        g_assert_cmphex(femu_fdp_wb_write(&c, 512 + i * 4, 4, buf, list, 1,
                                          false), ==, NVME_SUCCESS);
    }
    femu_fdp_slc(qts, v);
    g_assert_cmpuint(v[3], ==, 2);
    g_assert_cmpuint(v[5], ==, 1);          /* handle 1 took the freed unit */
    g_assert_cmpuint(femu_fdpt_check(qts), ==, 0);
    if (data && !strcmp(data, "gc-fw")) {
        femu_gc_fw_assert(&c, log, "fdpt", femu_gc_fw_ns(qts, "fdpt"), 0, 0);
    }
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    guest_free(alloc, log);
    guest_free(alloc, list);
    guest_free(alloc, buf);
}

/*
 * A page in an FDP pSLC unit takes the pSLC program time: 400 ms with
 * tier_pslc_prog_ns. A TLC program takes under 6 ms; with the wake of an
 * idle poller (up to about 100 ms) it stays far below the 300 ms bound.
 */
void femu_test_fdp_tier_timing(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    int64_t t0;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x77, 4096);
    t0 = g_get_monotonic_time();
    g_assert_cmphex(femu_fdp_wb_write(&c, 0, 1, buf, list, 2, false), ==,
                    NVME_SUCCESS);
    g_test_message("pSLC write: %" PRId64 " us", g_get_monotonic_time() - t0);
    g_assert_cmpint(g_get_monotonic_time() - t0, >=, 300000);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    guest_free(alloc, list);
    guest_free(alloc, buf);
}
#define FEMU_G1_NRUH        256
#define FEMU_G1_PHS         128     /* handles a namespace lists at most */
#define FEMU_G1_UNIT_PAGES  16      /* pages of a reclaim unit of the test */

/* host bytes of each of the @nr handles of the only namespace */
static void femu_g1_handle_bytes(QTestState *qts, uint64_t *host, uint32_t nr)
{
    QDict *rsp;
    QDict *ns = femu_query_ns(qts, "'kind':'reclaim-units','limit':4096",
                              &rsp);
    QList *handles = qdict_get_qlist(qdict_get_qdict(ns, "fdp"), "handles");
    g_autofree bool *found = g_new0(bool, nr);
    uint32_t seen = 0;
    QListEntry *e;

    QLIST_FOREACH_ENTRY(handles, e) {
        QDict *d = qobject_to(QDict, qlist_entry_obj(e));
        int64_t h = qdict_get_int(d, "id");

        g_assert_cmpint(h, >=, 0);
        g_assert_cmpint(h, <, nr);
        g_assert_false(found[h]);
        found[h] = true;
        host[h] = qdict_get_int(d, "host-bytes");
        seen++;
    }
    g_assert_cmpuint(seen, ==, nr);
    qobject_unref(rsp);
}

/* the first @bytes of the RUH Status of namespace 1, two pages at most */
static void femu_g1_ruh_status(FemuCtrlState *c, uint64_t buf, uint8_t *st,
                               uint32_t bytes)
{
    NvmeCmd cmd;

    g_assert_cmpuint(bytes, <=, 2 * FEMU_G1_PAGE);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_CMD_IO_MGMT_RECV;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.dptr.prp2 = cpu_to_le64(buf + FEMU_G1_PAGE);
    cmd.cdw10 = cpu_to_le32(FEMU_IOMR_RUH_STATUS);
    cmd.cdw11 = cpu_to_le32(bytes / 4 - 1);
    g_assert_cmphex(femu_io(c, &cmd), ==, NVME_SUCCESS);
    qtest_memread(c->pdev->bus->qts, buf, st, bytes);
}

/*
 * fdp.nruh=256 on a bbssd namespace with reclaim units of 16 pages. A
 * placement handle list holds 128 handles at most, so without namespace_phls
 * the namespace lists handles 0 to 127. Handle h takes 1 + h % 3 pages, and
 * each handle counts its own bytes and fills its own unit. Placement
 * identifier 128 is not in the list, so its write goes to placement handle
 * 0. With namespace_phls=255:128 (@data set), placement handle 0 is the last
 * handle of the group, and handle 0 takes nothing.
 */
void femu_test_g1_fdp_handles(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    const bool listed = data != NULL;
    const uint32_t nphs = listed ? 2 : FEMU_G1_PHS;
    const uint32_t st_bytes = 16 + nphs * 32;
    const uint32_t ruhu_bytes = FEMU_RUHU_HDR +
                                FEMU_G1_NRUH * FEMU_RUHU_DESCR;
    const uint32_t confs_bytes = 16 + 64 + FEMU_G1_NRUH * 4;
    const uint32_t bpp = FEMU_G1_PAGE / 512;
    uint64_t buf = guest_alloc(alloc, FEMU_G1_PAGE);
    uint64_t list = guest_alloc(alloc, FEMU_G1_PAGE);
    uint64_t log = guest_alloc(alloc, 2 * FEMU_G1_PAGE);
    g_autofree uint64_t *host = g_new0(uint64_t, FEMU_G1_NRUH);
    g_autofree uint64_t *want = g_new0(uint64_t, FEMU_G1_NRUH);
    g_autofree uint8_t *st = g_malloc0(2 * FEMU_G1_PAGE);
    uint16_t pids[FEMU_G1_PHS + 1];
    uint64_t pages = 0;
    uint32_t h;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x4a, FEMU_G1_PAGE);

    /* the configuration: 256 handles in a descriptor of 1088 bytes */
    g_assert_cmphex(femu_endgrp_log(&c, NVME_LOG_FDP_CONFS, 0, log, 64), ==,
                    NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, log + 4), ==, confs_bytes);
    g_assert_cmpuint(qtest_readw(qts, log + 16), ==, confs_bytes - 16);
    g_assert_cmpuint(qtest_readw(qts, log + 16 + 8), ==, FEMU_G1_NRUH);
    g_assert_cmpuint(qtest_readw(qts, log + 16 + 10), ==, FEMU_G1_PHS - 1);
    g_assert_cmphex(femu_endgrp_log(&c, NVME_LOG_FDP_CONFS, confs_bytes - 4,
                                    log, 4), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readb(qts, log), ==,
                     NVME_RUHT_PERSISTENTLY_ISOLATED);
    g_assert_cmphex(femu_endgrp_log(&c, NVME_LOG_FDP_CONFS, confs_bytes, log,
                                    4), ==, NVME_INVALID_FIELD);

    /* a fresh unit behind each listed handle */
    femu_g1_ruh_status(&c, log, st, st_bytes);
    g_assert_cmpuint(lduw_le_p(st + 14), ==, nphs);
    for (h = 0; h < nphs; h++) {
        g_assert_cmpuint(ldq_le_p(st + 16 + 32 * h + 8), ==,
                         FEMU_G1_UNIT_PAGES * bpp);
    }

    if (listed) {
        /* placement handle 0 is handle 255, placement handle 1 is 128 */
        g_assert_cmphex(femu_fdp_wb_write(&c, 0, 2, buf, list, 0, false), ==,
                        NVME_SUCCESS);
        g_assert_cmphex(femu_fdp_wb_write(&c, 2, 3, buf, list, 1, false), ==,
                        NVME_SUCCESS);
        want[FEMU_G1_NRUH - 1] = 2 * FEMU_G1_PAGE;
        want[FEMU_G1_PHS] = 3 * FEMU_G1_PAGE;
        pages = 5;
    } else {
        for (h = 0; h < nphs; h++) {
            uint32_t n = 1 + h % 3;

            g_assert_cmphex(femu_fdp_wb_write(&c, pages, n, buf, list, h,
                                              false), ==, NVME_SUCCESS);
            want[h] = n * FEMU_G1_PAGE;
            pages += n;
        }
    }
    femu_g1_handle_bytes(qts, host, FEMU_G1_NRUH);
    for (h = 0; h < FEMU_G1_NRUH; h++) {
        g_assert_cmpuint(host[h], ==, want[h]);
    }

    /* each placement identifier names its handle, and its unit filled */
    femu_g1_ruh_status(&c, log, st, st_bytes);
    for (h = 0; h < nphs; h++) {
        const uint8_t *d = st + 16 + 32 * h;
        uint32_t ruhid = listed ? (h ? FEMU_G1_PHS : FEMU_G1_NRUH - 1) : h;

        g_assert_cmpuint(lduw_le_p(d), ==, h);
        g_assert_cmpuint(lduw_le_p(d + 2), ==, ruhid);
        g_assert_cmpuint(ldq_le_p(d + 8), ==, (FEMU_G1_UNIT_PAGES -
                         want[ruhid] / FEMU_G1_PAGE) * bpp);
    }

    /* the usage log: a listed handle is host specified, another is unused */
    qtest_memset(qts, log, 0xff, 2 * FEMU_G1_PAGE);
    g_assert_cmphex(femu_endgrp_log(&c, FEMU_LOG_FDP_RUH_USAGE, 0, log,
                                    ruhu_bytes), ==, NVME_SUCCESS);
    qtest_memread(qts, log, st, ruhu_bytes);
    g_assert_cmpuint(lduw_le_p(st), ==, FEMU_G1_NRUH);
    for (h = 0; h < FEMU_G1_NRUH; h++) {
        bool used = listed ? h == FEMU_G1_PHS || h == FEMU_G1_NRUH - 1 :
                             h < FEMU_G1_PHS;

        g_assert_cmpuint(st[FEMU_RUHU_HDR + h * FEMU_RUHU_DESCR], ==,
                         used ? NVME_RUHA_HOST : NVME_RUHA_UNUSED);
    }
    g_assert_cmphex(qtest_readb(qts, log + ruhu_bytes), ==, 0xff);

    /* an identifier past the list: the write lands on placement handle 0 */
    g_assert_cmphex(femu_fdp_wb_write(&c, pages, 1, buf, list, nphs, false),
                    ==, NVME_SUCCESS);
    pages++;
    want[listed ? FEMU_G1_NRUH - 1 : 0] += FEMU_G1_PAGE;
    femu_g1_handle_bytes(qts, host, FEMU_G1_NRUH);
    for (h = 0; h < FEMU_G1_NRUH; h++) {
        g_assert_cmpuint(host[h], ==, want[h]);
    }

    /* RUH Update names every identifier of the list, and not one more */
    for (h = 0; h <= FEMU_G1_PHS; h++) {
        pids[h] = cpu_to_le16(h < nphs ? h : 0);
    }
    qtest_memwrite(qts, log, pids, sizeof(pids));
    g_assert_cmphex(femu_ruh_update(&c, log, FEMU_G1_PHS + 1), ==,
                    NVME_INVALID_FIELD);
    /* the refused update moved no handle to a fresh unit */
    femu_g1_ruh_status(&c, log, st, st_bytes);
    for (h = 0; h < nphs; h++) {
        uint32_t ruhid = listed ? (h ? FEMU_G1_PHS : FEMU_G1_NRUH - 1) : h;

        g_assert_cmpuint(ldq_le_p(st + 16 + 32 * h + 8), ==,
                         (FEMU_G1_UNIT_PAGES - want[ruhid] / FEMU_G1_PAGE) *
                         bpp);
    }
    qtest_memwrite(qts, log, pids, sizeof(pids));
    g_assert_cmphex(femu_ruh_update(&c, log, nphs), ==, NVME_SUCCESS);
    femu_g1_ruh_status(&c, log, st, st_bytes);
    for (h = 0; h < nphs; h++) {
        g_assert_cmpuint(ldq_le_p(st + 16 + 32 * h + 8), ==,
                         FEMU_G1_UNIT_PAGES * bpp);
    }

    /* every page is mapped once, and no unit or handle is out of step */
    g_assert_cmpuint(femu_fdp_wb_mapped(qts), ==, pages);

    guest_free(alloc, log);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * gc_thres_base under FDP, on fdpsub (four handles, persistently isolated):
 * 64 units of 16 pages in one group. op_pcent=30 exposes 3226112 bytes:
 * 787 full pages and part of one more. The FTL counts 788 pages, which
 * fill 50 units and leave 14 spare. Four handles hold four units open and
 * four more to collect into, so the spare rule keeps at least four free:
 *
 *   base   hi                     bg                       x-gc-lines
 *   spare  max(5 % of 14, 4) = 4  max(25 % of 14, 5) = 5   spare 4 5 14 8
 *   raw    5 % of 64 = 3          25 % of 64 = 16          raw 3 16 14 8
 *
 * Random writes then go to all four handles. No write may fail for want
 * of a unit, and every page must stay mapped.
 */
void femu_test_fdp_gc_spare(void *obj, void *data, QGuestAllocator *alloc)
{
    /* the last page is partial, and a 4 KiB write there is out of range */
    const uint32_t pages = 787;
    const int handles = 4;
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 16 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t mapped, lost, orphans;
    uint32_t seed = 3;
    QDict *rsp;

    rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                    "'path':'/machine/peripheral/gc-test',"
                    "'property':'x-gc-lines'}}");
    g_assert_true(qdict_haskey(rsp, "return"));
    g_test_message("x-gc-lines: %s", qdict_get_str(rsp, "return"));
    g_assert_cmpstr(qdict_get_str(rsp, "return"), ==, data);
    qobject_unref(rsp);

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x2e, 16 * 4096);
    for (uint32_t p = 0; p < pages; p += 16) {
        g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, p,
                                                        MIN(16, pages - p),
                                                        buf, list,
                                                        (p / 16) % handles)),
                        ==, NVME_SUCCESS);
    }
    for (uint32_t i = 0; i < 3 * pages; i++) {
        uint32_t npages = i % 8 == 7 ? 16 : 1;

        seed = seed * 1103515245 + 12345;
        g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c,
                                    (seed >> 8) % (pages - npages + 1),
                                    npages, buf, list,
                                    (seed >> 4) % handles)), ==,
                        NVME_SUCCESS);
    }
    femu_ftl_check(qts, &mapped, &lost, &orphans);
    g_assert_cmpuint(mapped, ==, pages);
    g_assert_cmpuint(lost, ==, 0);
    g_assert_cmpuint(orphans, ==, 0);

    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * gc_thres_base=spare under FDP refuses op_pcent=25 and 26 on the geometry
 * above: 820 and 813 pages fill 52 and 51 units and leave 12 and 13, short
 * of 4 forced, 8 open and 2. The raw rule keeps 8 open and 3 forced units,
 * so it refuses the 876 pages of op_pcent=17 (848 fit) and takes
 * op_pcent=25, last, since the subsystem takes one controller. auto at
 * op_pcent=25 keeps the raw levels: fdp-gc-auto-raw.
 */
void femu_test_fdp_gc_spare_refused(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    static const struct {
        int op;
        const char *base;
        const char *want;   /* NULL: accepted */
    } cases[] = {
        { 25, "spare", "leave 12 spare reclaim units in a group, and "
                       "gc_thres_base=spare needs 14" },
        { 26, "spare", "leave 13 spare reclaim units in a group, and "
                       "gc_thres_base=spare needs 14" },
        { 17, "raw", "placement keeps 11 of the 64 reclaim units" },
        { 25, "raw", NULL },
    };

    for (size_t i = 0; i < ARRAY_SIZE(cases); i++) {
        g_autofree char *cmd = g_strdup_printf(
            "{'execute':'device_add','arguments':{'driver':'femu',"
            "'id':'fdp-gcs','addr':'5','femu_mode':1,'secsz':512,"
            "'secs_per_pg':8,'pgs_per_blk':4,'blks_per_pl':64,"
            "'pls_per_lun':1,'luns_per_ch':2,'nchs':2,'op_pcent':%d,"
            "'gc_thres_base':'%s','subsys':'fdpsub'}}", cases[i].op,
            cases[i].base);
        QDict *rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));
        const char *desc;

        if (!cases[i].want) {
            g_assert_true(qdict_haskey(rsp, "return"));
            qobject_unref(rsp);
            continue;
        }
        g_assert_true(qdict_haskey(rsp, "error"));
        desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
        g_test_message("op_pcent=%d %s: %s", cases[i].op, cases[i].base,
                       desc);
        g_assert_nonnull(strstr(desc, cases[i].want));
        qobject_unref(rsp);
    }
    qos_invalidate_command_line();
}
