/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QTest testcases for the FEMU SSD emulator: the CXL SSD tests (cxl-*).
 *
 * femu-test.c registers every test. This file holds the test bodies
 * and the helpers that only they use.
 */

#include "qemu/osdep.h"
#include "femu-test.h"

#define FEMU_CXL_MACHINE \
    "-machine q35,cxl=on -m 128M " \
    "-device pxb-cxl,id=cxl.0,bus=pcie.0,bus_nr=52 " \
    "-M cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.size=256M " \
    "-device cxl-rp,id=rp0,bus=cxl.0,chassis=0,slot=0 " \
    "-object memory-backend-ram,id=mem,size=256M "

void femu_test_cxl_realize(void *obj, void *data,
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

void femu_test_cxl_realize_retry(void *obj, void *data,
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

/*
 * A femu-cxl-ssd whose FTL does not fit is refused, and QEMU runs on. Each
 * FTL allocation fails in turn, then the device starts on the same memory
 * backend. 4 x 4 dies of 21 blocks: the NAND tree is 1 + 1 + 4 + 16 +
 * 16 arrays, then the two maps, the lines and the line heap.
 */
void femu_test_cxl_ftl_fail_sweep(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE);
    uint32_t k;

    for (k = 1; k < 1000; k++) {
        g_autofree char *want = NULL;
        QDict *rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                               "'driver':'femu-cxl-ssd','id':'ssd',"
                               "'bus':'rp0','volatile-memdev':'mem',"
                               "'ftl':true,'cache-pages':16,'cache-ways':16,"
                               "'channels':4,'luns-per-channel':4,"
                               "'pages-per-block':256,'blocks-per-plane':21,"
                               "'test-ftl-fail-at':%u}}", k);

        if (qdict_haskey(rsp, "return")) {
            qobject_unref(rsp);
            break;
        }
        want = g_strdup_printf("injected failure of FTL allocation %u (", k);
        if (!strstr(qdict_get_str(qdict_get_qdict(rsp, "error"), "desc"),
                    want)) {
            g_test_message("k=%u: %s", k,
                           qdict_get_str(qdict_get_qdict(rsp, "error"),
                                         "desc"));
            g_assert_not_reached();
        }
        qobject_unref(rsp);
    }
    g_assert_cmpuint(k - 1, ==, 1 + 1 + 4 + 16 + 16 + 4);
    qtest_quit(qts);
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

/*
 * Route the root port on @bus to a 1 MiB register window at @bar and commit
 * the endpoint's first decoder over the 256 MiB fixed window at @window.
 */
static void femu_cxl_decode_ways(QTestState *qts, unsigned bus, uint32_t bar,
                                 uint64_t window, uint32_t size, uint32_t ctrl);

static void femu_cxl_decode_at(QTestState *qts, unsigned bus, uint32_t bar,
                               uint64_t window)
{
    femu_cxl_decode_ways(qts, bus, bar, window, 0x10000000, 0x200);
}

/* As femu_cxl_decode_at(), with a decoder size and control word. */
static void femu_cxl_decode_ways(QTestState *qts, unsigned bus, uint32_t bar,
                                 uint64_t window, uint32_t size, uint32_t ctrl)
{
    uint64_t regs = bar + 0x1000;

    femu_cxl_config(qts, bus, PCI_PRIMARY_BUS,
                    bus | (bus + 1) << 8 | (bus + 1) << 16);
    femu_cxl_config(qts, bus, PCI_MEMORY_BASE, bar >> 16 | (bar & ~0xfffffu));
    femu_cxl_config(qts, bus, PCI_COMMAND, PCI_COMMAND_MEMORY);
    femu_cxl_config(qts, bus + 1, 0x10, bar);
    femu_cxl_config(qts, bus + 1, 0x14, 0);
    femu_cxl_config(qts, bus + 1, PCI_COMMAND, PCI_COMMAND_MEMORY);
    qtest_writel(qts, regs + A_CXL_HDM_DECODER0_BASE_LO, window & 0xffffffff);
    qtest_writel(qts, regs + A_CXL_HDM_DECODER0_BASE_HI, window >> 32);
    qtest_writel(qts, regs + A_CXL_HDM_DECODER0_SIZE_LO, size);
    qtest_writel(qts, regs + A_CXL_HDM_DECODER0_SIZE_HI, 0);
    qtest_writel(qts, regs + A_CXL_HDM_DECODER0_CTRL, ctrl);
    g_assert_cmphex(qtest_readl(qts, regs + A_CXL_HDM_DECODER0_CTRL) & 0x400,
                    ==, 0x400);
}

static void femu_cxl_decode(QTestState *qts)
{
    femu_cxl_decode_at(qts, 52, FEMU_CXL_REGS - 0x1000, FEMU_CXL_WINDOW);
}

/* The PCI Express capability of the root port on bus 52. */
static uint8_t femu_cxl_rp_exp_cap(QTestState *qts)
{
    uint8_t cap;

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
    return cap;
}

static void femu_cxl_unplug(QTestState *qts)
{
    uint8_t cap = femu_cxl_rp_exp_cap(qts);
    QDict *rsp;

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

void femu_test_cxl_bg_unplug(void *obj, void *data,
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

void femu_test_cxl_window(void *obj, void *data,
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

void femu_test_cxl_local_overlay(void *obj, void *data,
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

static unsigned femu_cxl_mtree_count(QTestState *qts, const char *name)
{
    QDict *rsp = qtest_qmp(qts, "{'execute':'human-monitor-command',"
                           "'arguments':{'command-line':'info mtree'}}");
    const char *p = qdict_get_str(rsp, "return");
    unsigned count = 0;

    while ((p = strstr(p, name))) {
        count++;
        p += strlen(name);
    }
    qobject_unref(rsp);
    return count;
}

void femu_test_cxl_overlay_scope(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(
        "-machine q35,cxl=on -m 128M "
        "-device pxb-cxl,id=cxl.0,bus=pcie.0,bus_nr=52 "
        "-device pxb-cxl,id=cxl.1,bus=pcie.0,bus_nr=60 "
        "-M cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.size=256M,"
        "cxl-fmw.1.targets.0=cxl.1,cxl-fmw.1.size=256M "
        "-device cxl-rp,id=rp0,bus=cxl.0,chassis=0,slot=0 "
        "-object memory-backend-ram,id=mem,size=256M "
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem");
    unsigned windows = femu_cxl_mtree_count(qts, "cxl-fixed-memory-region");

    /* Only the window whose host bridge carries the device is overlaid. */
    g_assert_cmpuint(windows, >, 0);
    g_assert_cmpuint(windows % 2, ==, 0);
    g_assert_cmpuint(femu_cxl_mtree_count(qts, "femu-cxl-media"), ==,
                     windows / 2);
    femu_cxl_decode(qts);
    qtest_writeq(qts, FEMU_CXL_WINDOW, 0x12345678);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 0x12345678);
    qtest_quit(qts);
}

void femu_test_cxl_stale_translation(void *obj, void *data,
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
    /*
     * A decoder change while the access waits must not fail it: it completes
     * at the DPA the decoder now selects, as an unqueued access would.
     */
    femu_cxl_set(qts, "test-change-dpa", true);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-inserts"), ==, 2);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-hits"), ==, 0);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-inserts"), ==, 2);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-hits"), ==, 1);
    qtest_quit(qts);
}

static uint64_t femu_cxl_stat_of(QTestState *qts, const char *id,
                                 const char *name);

/*
 * A window interleaved over two host bridges, one femu-cxl-ssd under each,
 * as a plain Type-3 setup would be. Direct modes stay on MMIO here.
 */
void femu_test_cxl_topology(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    const char *der = data ? data : "off";
    g_autofree char *args = g_strdup_printf(
        "-machine q35,cxl=on -m 128M "
        "-device pxb-cxl,id=cxl.0,bus=pcie.0,bus_nr=52 "
        "-device pxb-cxl,id=cxl.1,bus=pcie.0,bus_nr=60 "
        "-M cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.targets.1=cxl.1,"
        "cxl-fmw.0.size=512M "
        "-device cxl-rp,id=rp0,bus=cxl.0,chassis=0,slot=0 "
        "-device cxl-rp,id=rp1,bus=cxl.1,chassis=0,slot=1 "
        "-object memory-backend-ram,id=mem,size=256M "
        "-object memory-backend-ram,id=mem1,size=256M "
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,der=%s "
        "-device femu-cxl-ssd,id=ssd1,bus=rp1,volatile-memdev=mem1,der=%s",
        der, der);
    QTestState *qts = qtest_init(args);
    unsigned i;

    /* Two ways at 256 bytes: even granules go to ssd, odd ones to ssd1. */
    femu_cxl_decode_ways(qts, 52, 0x90000000, FEMU_CXL_WINDOW, 0x20000000,
                         0x210);
    femu_cxl_decode_ways(qts, 60, 0x90400000, FEMU_CXL_WINDOW, 0x20000000,
                         0x210);
    for (i = 0; i < 4; i++) {
        qtest_writeq(qts, FEMU_CXL_WINDOW + i * 256, 0x1000 + i);
    }
    /* Granule 32 of ssd's half is its DPA 4096, a second page. */
    qtest_writeq(qts, FEMU_CXL_WINDOW + 8192, 0x2000);
    for (i = 0; i < 4; i++) {
        g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW + i * 256), ==,
                        0x1000 + i);
    }
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW + 8192), ==, 0x2000);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW + 8192 + 256), ==, 0);
    g_assert_cmpuint(femu_cxl_stat_of(qts, "ssd", "cache-inserts"), ==, 2);
    g_assert_cmpuint(femu_cxl_stat_of(qts, "ssd", "write-misses"), ==, 2);
    g_assert_cmpuint(femu_cxl_stat_of(qts, "ssd", "write-hits"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat_of(qts, "ssd1", "cache-inserts"), ==, 2);
    g_assert_cmpuint(femu_cxl_stat_of(qts, "ssd", "der-mapped"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat_of(qts, "ssd1", "der-mapped"), ==, 0);
    if (data) {
        g_assert_cmpuint(femu_cxl_stat_of(qts, "ssd", "der-fallbacks"), >,
                         0);
    }
    qtest_quit(qts);
}

/*
 * Two decoders leave a hole in HPA: the page after the first decoder's last
 * DPA lives 256 MiB further up. A prefetch must not map it at the HPA
 * right after the demand page.
 */
void femu_test_cxl_prefetch_decoders(void *obj, void *data,
                                     QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(
        "-machine q35,cxl=on -m 128M "
        "-device pxb-cxl,id=cxl.0,bus=pcie.0,bus_nr=52 "
        "-M cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.size=1G "
        "-device cxl-rp,id=rp0,bus=cxl.0,chassis=0,slot=0 "
        "-object memory-backend-ram,id=mem,size=512M "
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,der=memslot,"
        "prefetch-degree=1");
    uint64_t regs = FEMU_CXL_REGS;
    uint64_t hole = FEMU_CXL_WINDOW + 0x10000000;
    uint64_t upper = FEMU_CXL_WINDOW + 0x20000000;

    femu_cxl_decode(qts);
    qtest_writel(qts, regs + A_CXL_HDM_DECODER1_BASE_LO, upper & 0xffffffff);
    qtest_writel(qts, regs + A_CXL_HDM_DECODER1_BASE_HI, upper >> 32);
    qtest_writel(qts, regs + A_CXL_HDM_DECODER1_SIZE_LO, 0x10000000);
    qtest_writel(qts, regs + A_CXL_HDM_DECODER1_SIZE_HI, 0);
    qtest_writel(qts, regs + A_CXL_HDM_DECODER1_CTRL, 0x200);
    g_assert_cmphex(qtest_readl(qts, regs + A_CXL_HDM_DECODER1_CTRL) & 0x400,
                    ==, 0x400);
    /* The last page of decoder 0 prefetches DPA 256 MiB. */
    g_assert_cmphex(qtest_readq(qts, hole - 4096), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "prefetch-inserts"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 1);
    qtest_writeq(qts, upper, 0xabc);
    g_assert_cmphex(qtest_readq(qts, upper), ==, 0xabc);
    /* Nothing decodes the hole, so it must not show that data. */
    g_assert_cmphex(qtest_readq(qts, hole), ==, 0);
    qtest_quit(qts);
}

/* A femu-cxl-ssd below a CXL switch, routed by the upstream port decoder. */
void femu_test_cxl_switch(void *obj, void *data,
                          QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device cxl-upstream,bus=rp0,id=us0 "
        "-device cxl-downstream,port=0,bus=us0,id=swport0,chassis=0,slot=4 "
        "-device femu-cxl-ssd,id=ssd,bus=swport0,volatile-memdev=mem");
    uint64_t usp = 0x90000000 + 0x1000;

    /* Root port 52 -> upstream port 53 -> downstream port 54 -> ssd 55. */
    femu_cxl_config(qts, 52, PCI_PRIMARY_BUS, 52 | 53 << 8 | 55 << 16);
    femu_cxl_config(qts, 52, PCI_MEMORY_BASE, 0x90209000);
    femu_cxl_config(qts, 52, PCI_COMMAND, PCI_COMMAND_MEMORY);
    femu_cxl_config(qts, 53, 0x10, 0x90000000);
    femu_cxl_config(qts, 53, 0x14, 0);
    femu_cxl_config(qts, 53, PCI_PRIMARY_BUS, 53 | 54 << 8 | 55 << 16);
    femu_cxl_config(qts, 53, PCI_MEMORY_BASE, 0x90209010);
    femu_cxl_config(qts, 53, PCI_COMMAND, PCI_COMMAND_MEMORY);
    qtest_writel(qts, usp + A_CXL_HDM_DECODER0_BASE_LO,
                 FEMU_CXL_WINDOW & 0xffffffff);
    qtest_writel(qts, usp + A_CXL_HDM_DECODER0_BASE_HI, FEMU_CXL_WINDOW >> 32);
    qtest_writel(qts, usp + A_CXL_HDM_DECODER0_SIZE_LO, 0x10000000);
    qtest_writel(qts, usp + A_CXL_HDM_DECODER0_TARGET_LIST_LO, 0);
    qtest_writel(qts, usp + A_CXL_HDM_DECODER0_CTRL, 0x200);
    g_assert_cmphex(qtest_readl(qts, usp + A_CXL_HDM_DECODER0_CTRL) & 0x400,
                    ==, 0x400);
    femu_cxl_decode_ways(qts, 54, 0x90100000, FEMU_CXL_WINDOW, 0x10000000,
                         0x200);
    qtest_writeq(qts, FEMU_CXL_WINDOW, 0xfeed);
    qtest_writeq(qts, FEMU_CXL_WINDOW + 4096, 0xbeef);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 0xfeed);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW + 4096), ==, 0xbeef);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-inserts"), ==, 2);
    g_assert_cmpuint(femu_cxl_stat(qts, "read-hits"), ==, 2);
    qtest_quit(qts);
}

void femu_test_cxl_forward(void *obj, void *data,
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

/*
 * A host bridge decoder can be programmed with more interleave ways than
 * its eight-entry target list holds; such an address must decode to
 * nothing instead of asserting.
 */
void femu_test_cxl_target_bound(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem "
        "-device cxl-rp,id=rp1,bus=cxl.0,chassis=0,slot=1,port=1,addr=1");
    uint64_t host = 0x100001000ULL;

    femu_cxl_decode(qts);
    qtest_writel(qts, host + A_CXL_HDM_DECODER0_BASE_LO,
                 FEMU_CXL_WINDOW & 0xffffffff);
    qtest_writel(qts, host + A_CXL_HDM_DECODER0_BASE_HI, FEMU_CXL_WINDOW >> 32);
    qtest_writel(qts, host + A_CXL_HDM_DECODER0_SIZE_LO, 0x10000000);
    qtest_writel(qts, host + A_CXL_HDM_DECODER0_TARGET_LIST_LO, 0);
    /* Commit with sixteen ways at 256-byte granularity. */
    qtest_writel(qts, host + A_CXL_HDM_DECODER0_CTRL, 0x240);
    qtest_writeq(qts, FEMU_CXL_WINDOW, 0xfeed);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 0xfeed);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW + 8 * 256), ==, 0);
    qtest_writeq(qts, FEMU_CXL_WINDOW + 15 * 256, 1);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 0xfeed);
    qtest_quit(qts);
}

void femu_test_cxl_slot_reservation(void *obj, void *data,
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

void femu_test_cxl_flush(void *obj, void *data,
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

/*
 * One LUN, and a first-touch read programs the page, so every miss to a new
 * page costs FEMU_FAST_NS on the same timeline.
 */
#define FEMU_FAST_NS    20000000ULL
#define FEMU_FAST_PAGES 8
#define FEMU_FAST_DEVICE \
    "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem," \
    "channels=1,luns-per-channel=1,read-ns=20000000,program-ns=20000000," \
    "cylon-first-touch-program=on"

/*
 * The first access to the window can take tens of ms on its own; pay it
 * here, at full latency, so it does not count against a timed run.
 */
static void femu_fast_start(QTestState *qts)
{
    femu_cxl_decode(qts);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW + 1000 * 4096), ==, 0);
}

/* Read @n new pages from @first, one at a time; return the elapsed us. */
static int64_t femu_fast_misses(QTestState *qts, uint64_t first, unsigned n)
{
    int64_t start = g_get_monotonic_time();
    unsigned i;

    for (i = 0; i < n; i++) {
        g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW +
                                    (first + i) * 4096), ==, 0);
    }
    return g_get_monotonic_time() - start;
}

/*
 * Turn fast load off; return how long the switch took inside the device, in
 * ns, which a descheduled test process does not stretch.
 */
static int64_t femu_fast_off(QTestState *qts)
{
    femu_cxl_set(qts, "fast-load", false);
    return femu_cxl_stat(qts, "fast-load-switch-ns");
}

/* Wait out the NAND backlog that fast load left, as a harness does. */
static void femu_fast_idle(QTestState *qts)
{
    int64_t deadline = g_get_monotonic_time() + 60 * G_USEC_PER_SEC;

    while (femu_cxl_stat(qts, "nand-idle-ns")) {
        g_assert_cmpint(g_get_monotonic_time(), <, deadline);
        g_usleep(10 * 1000);
    }
}

/*
 * A miss to a new page once the NAND is idle pays exactly one program: no
 * backlog is left on the LUN to queue behind.
 */
static void femu_fast_restored(QTestState *qts, uint64_t page)
{
    uint64_t media = femu_cxl_stat(qts, "media-time-ns");
    int64_t took = femu_fast_misses(qts, page, 1);

    g_assert_cmpuint(femu_cxl_stat(qts, "media-time-ns") - media, ==,
                     FEMU_FAST_NS);
    g_assert_cmpint(took * 1000, >=, FEMU_FAST_NS);
}

/* Misses skip their wait while fast load is on, and pay it once it is off. */
void femu_test_cxl_fast_load(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE FEMU_FAST_DEVICE);
    int64_t took;

    femu_fast_start(qts);
    g_assert_false(qtest_qom_get_bool(qts, "/machine/peripheral/ssd",
                                      "fast-load"));
    femu_cxl_set(qts, "fast-load", true);
    g_assert_true(qtest_qom_get_bool(qts, "/machine/peripheral/ssd",
                                     "fast-load"));
    took = femu_fast_misses(qts, 0, FEMU_FAST_PAGES);
    g_assert_cmpint(took * 1000, <, FEMU_FAST_PAGES * FEMU_FAST_NS / 2);
    /* The FTL still ran: every miss programmed its page. */
    g_assert_cmpuint(femu_cxl_stat(qts, "media-writes"), ==,
                     FEMU_FAST_PAGES + 1);
    g_assert_cmpuint(femu_cxl_stat(qts, "read-misses"), ==,
                     FEMU_FAST_PAGES + 1);
    femu_fast_off(qts);
    femu_fast_idle(qts);
    femu_fast_restored(qts, FEMU_FAST_PAGES);
    /* Control: the same misses with it off pay each program in turn. */
    took = femu_fast_misses(qts, FEMU_FAST_PAGES + 1, FEMU_FAST_PAGES);
    g_assert_cmpint(took * 1000, >=, FEMU_FAST_PAGES * FEMU_FAST_NS);
    qtest_quit(qts);
}

/*
 * Switching off reports the NAND work the skipped waits left queued, without
 * waiting for it.
 */
void femu_test_cxl_fast_load_drain(void *obj, void *data,
                                   QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE FEMU_FAST_DEVICE);
    uint64_t drain;
    int64_t took;

    femu_fast_start(qts);
    /* Control: with nothing queued the switch has nothing to wait for. */
    femu_cxl_set(qts, "fast-load", true);
    femu_fast_off(qts);
    g_assert_cmpuint(femu_cxl_stat(qts, "fast-load-drain-ns"), ==, 0);

    femu_cxl_set(qts, "fast-load", true);
    /* Setting the same value is a no-op. */
    femu_cxl_set(qts, "fast-load", true);
    femu_fast_misses(qts, 0, FEMU_FAST_PAGES);
    took = femu_fast_off(qts);
    drain = femu_cxl_stat(qts, "fast-load-drain-ns");
    g_assert_cmpuint(drain, >, 0);
    g_assert_cmpint(took, <, drain / 2);
    /* Most of the queued programs were still ahead when the misses ended. */
    g_assert_cmpuint(drain, >=, FEMU_FAST_PAGES * FEMU_FAST_NS / 2);
    g_assert_cmpuint(femu_cxl_stat(qts, "nand-idle-ns"), >, 0);
    femu_fast_idle(qts);
    femu_fast_restored(qts, FEMU_FAST_PAGES);
    /* Already off: no second wait, and the last one is still reported. */
    took = femu_fast_off(qts);
    g_assert_cmpint(took, <, FEMU_FAST_NS);
    g_assert_cmpuint(femu_cxl_stat(qts, "fast-load-drain-ns"), ==, drain);
    qtest_quit(qts);
}

/*
 * A backlog of several seconds: each first touch programs a page on the one
 * LUN, and fast load lets the fill run far ahead of the NAND.
 */
#define FEMU_BACKLOG_NS    250000000ULL
#define FEMU_BACKLOG_PAGES 16
#define FEMU_BACKLOG_DEVICE \
    "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem," \
    "channels=1,luns-per-channel=1,read-ns=250000000," \
    "program-ns=250000000,cylon-first-touch-program=on"
/* Far above the 100 ms the switch can wait, far below the backlog. */
#define FEMU_BACKLOG_SWITCH_NS 500000000LL

/*
 * Turning fast load off must not keep the main loop for the NAND backlog: a
 * guest disk served by the main loop would time out. The backlog stays on
 * the NAND timelines, nand-idle-ns counts it down, and once it reads 0 a
 * miss pays only its own program again. fast-load-drain-ns is what was left
 * at the switch, and sleeping it out made the switch take at least that
 * long. The device times the switch itself, so the bound holds however the
 * host schedules this test. A descheduled test leaves less backlog, so the
 * misses run again until at least 1 s was left, twice the bound.
 */
void femu_test_cxl_fast_load_backlog(void *obj, void *data,
                                     QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE FEMU_BACKLOG_DEVICE);
    uint64_t drain;
    unsigned round;
    int64_t took;
    int64_t start;
    uint64_t media;
    QDict *rsp;

    femu_fast_start(qts);
    for (round = 0;; round++) {
        femu_cxl_set(qts, "fast-load", true);
        femu_fast_misses(qts, round * FEMU_BACKLOG_PAGES, FEMU_BACKLOG_PAGES);
        start = g_get_monotonic_time();
        took = femu_fast_off(qts);
        rsp = qtest_qmp(qts, "{'execute':'query-status'}");
        g_assert_true(qdict_haskey(rsp, "return"));
        qobject_unref(rsp);
        drain = femu_cxl_stat(qts, "fast-load-drain-ns");
        g_test_message("backlog %" PRIu64 " ms, switch %" PRId64 " us",
                       drain / 1000000, took / 1000);
        g_assert_cmpint(took, <, FEMU_BACKLOG_SWITCH_NS);
        if (drain >= NANOSECONDS_PER_SECOND || round == 4) {
            break;
        }
        femu_fast_idle(qts);
    }
    g_assert_cmpuint(drain, >=, NANOSECONDS_PER_SECOND);
    g_assert_cmpuint(drain, <=, FEMU_BACKLOG_PAGES * FEMU_BACKLOG_NS);
    g_assert_cmpint(took, <, drain / 2);
    g_assert_cmpuint(femu_cxl_stat(qts, "nand-idle-ns"), <=, drain);

    femu_fast_idle(qts);
    g_assert_cmpint((g_get_monotonic_time() - start) * 1000, >=, drain / 2);
    media = femu_cxl_stat(qts, "media-time-ns");
    femu_fast_misses(qts, (round + 1) * FEMU_BACKLOG_PAGES, 1);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-time-ns") - media, ==,
                     FEMU_BACKLOG_NS);
    g_assert_cmpuint(femu_cxl_stat(qts, "nand-idle-ns"), ==, 0);
    qtest_quit(qts);
}

/* Counters a serial trace must leave the same with fast load on or off. */
static const char *const femu_fast_counters[] = {
    "read-hits", "read-misses", "write-hits", "write-misses",
    "cache-hits", "cache-misses", "cache-inserts", "cache-evictions",
    "cache-entries", "prefetch-inserts", "media-reads", "media-writes",
    "media-full", "der-mapped", "der-remaps", "der-revocations",
    "der-fallbacks",
};

#define FEMU_FAST_TRACE   96
#define FEMU_FAST_SPAN    16
#define FEMU_FAST_COUNTERS ARRAY_SIZE(femu_fast_counters)

/*
 * Values a serial trace leaves: every counter above, a hash of the data it
 * read, the hit or miss of a probe read of each page afterwards (the cache
 * contents and their order), and the programs the probe and a final flush
 * issue (the dirty pages). media-time-ns is left out: misses that arrive sooner queue
 * behind each other on a LUN and are charged that wait.
 */
typedef struct FemuFastDigest {
    uint64_t counter[FEMU_FAST_COUNTERS];
    uint64_t data;
    uint64_t probe;
    uint64_t flushed;
} FemuFastDigest;

static void femu_fast_trace(FemuFastDigest *d, uint32_t seed, bool fast)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "cache-pages=4,cache-ways=2,prefetch-degree=1,read-ns=200000,"
        "program-ns=500000,cylon-first-touch-program=on");
    uint32_t x = seed;
    uint64_t writes;
    unsigned i;

    memset(d, 0, sizeof(*d));
    femu_cxl_decode(qts);
    femu_cxl_set(qts, "fast-load", fast);
    d->data = 1469598103934665603ULL;
    for (i = 0; i < FEMU_FAST_TRACE; i++) {
        uint64_t addr;

        x = x * 1103515245 + 12345;
        addr = FEMU_CXL_WINDOW + (x >> 16) % FEMU_FAST_SPAN * 4096;
        if (x >> 31) {
            qtest_writeq(qts, addr, i + 1);
        } else {
            d->data = (d->data ^ qtest_readq(qts, addr)) * 1099511628211ULL;
        }
    }
    femu_cxl_set(qts, "fast-load", false);
    femu_fast_idle(qts);
    for (i = 0; i < FEMU_FAST_COUNTERS; i++) {
        d->counter[i] = femu_cxl_stat(qts, femu_fast_counters[i]);
    }
    writes = femu_cxl_stat(qts, "media-writes");
    for (i = 0; i < FEMU_FAST_SPAN; i++) {
        uint64_t hits = femu_cxl_stat(qts, "cache-hits");

        qtest_readq(qts, FEMU_CXL_WINDOW + i * 4096);
        d->probe |= (femu_cxl_stat(qts, "cache-hits") - hits) << i;
    }
    femu_cxl_set(qts, "flush-cache", true);
    d->flushed = femu_cxl_stat(qts, "media-writes") - writes;
    qtest_quit(qts);
}

static uint64_t femu_fast_counter(const FemuFastDigest *d, const char *name)
{
    unsigned i;

    for (i = 0; i < FEMU_FAST_COUNTERS; i++) {
        if (!strcmp(femu_fast_counters[i], name)) {
            return d->counter[i];
        }
    }
    g_assert_not_reached();
}

static bool femu_fast_digest_equal(const FemuFastDigest *a,
                                   const FemuFastDigest *b)
{
    unsigned i;

    for (i = 0; i < FEMU_FAST_COUNTERS; i++) {
        if (a->counter[i] != b->counter[i]) {
            g_test_message("%s: %" PRIu64 " vs %" PRIu64,
                           femu_fast_counters[i], a->counter[i],
                           b->counter[i]);
            return false;
        }
    }
    return a->data == b->data && a->probe == b->probe &&
           a->flushed == b->flushed;
}

/*
 * A serial trace ends in the same cache and media state with fast load on.
 * Concurrent accesses carry no such promise: shorter page holds change which
 * evictions succeed.
 */
void femu_test_cxl_fast_load_state(void *obj, void *data,
                                   QGuestAllocator *alloc)
{
    FemuFastDigest normal;
    FemuFastDigest fast;
    FemuFastDigest other;

    femu_fast_trace(&normal, 1, false);
    femu_fast_trace(&fast, 1, true);
    /* The trace must exercise evictions, prefetch and write-backs. */
    g_assert_cmpuint(femu_fast_counter(&normal, "cache-evictions"), >, 0);
    g_assert_cmpuint(femu_fast_counter(&normal, "prefetch-inserts"), >, 0);
    g_assert_cmpuint(femu_fast_counter(&normal, "media-writes"), >, 0);
    g_assert_cmpuint(normal.flushed, >, 0);
    g_assert_true(femu_fast_digest_equal(&normal, &fast));
    /* Control: another trace must change the digest, or it proves nothing. */
    femu_fast_trace(&other, 2, false);
    g_assert_false(femu_fast_digest_equal(&normal, &other));
}

void femu_test_cxl_der(void *obj, void *data,
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

void femu_test_cxl_der_modes(void *obj, void *data,
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

/* How often @needle occurs in @text. */
static unsigned femu_cxl_count(const char *text, const char *needle)
{
    unsigned n = 0;

    while ((text = strstr(text, needle))) {
        n++;
        text++;
    }
    return n;
}

static void femu_cxl_set_u64(QTestState *qts, const char *name,
                             uint64_t value);

/*
 * Start a der=cylon device with cylon-never-emulate @mode (NULL: unset),
 * let it choose the fault exit version as if the host kernel offered
 * @version of KVM_CAP_CYLON_FAULT_EXIT (-1: do not choose, as on this host,
 * which has no Cylon), and return der-emul-v2 and what QEMU wrote to
 * stderr.
 */
static bool femu_cxl_version(const char *mode, int version, char **text)
{
    g_autofree char *log = g_strdup("cxl-version-XXXXXX");
    g_autofree char *quoted = NULL;
    g_autofree char *args = NULL;
    int fd = g_mkstemp(log);
    QTestState *qts;
    QDict *rsp;
    bool v2;

    g_assert_cmpint(fd, >=, 0);
    close(fd);
    quoted = g_shell_quote(log);
    args = g_strdup_printf(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,der=cylon,"
        "cylon-kernel-ack=on%s%s 2>%s", mode ? ",cylon-never-emulate=" : "",
        mode ? mode : "", quoted);
    qts = qtest_init(args);
    rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                    "'path':'/machine/peripheral/ssd',"
                    "'property':'cylon-never-emulate'}}");
    g_assert_cmpstr(qdict_get_str(rsp, "return"), ==, mode ? mode : "auto");
    qobject_unref(rsp);
    if (version >= 0) {
        femu_cxl_set_u64(qts, "test-fault-version", version);
    }
    rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                    "'path':'/machine/peripheral/ssd',"
                    "'property':'der-emul-v2'}}");
    v2 = qdict_get_bool(rsp, "return");
    qobject_unref(rsp);
    qtest_quit(qts);
    g_assert_true(g_file_get_contents(log, text, NULL, NULL));
    unlink(log);
    return v2;
}

/*
 * cylon-never-emulate defaults to auto: version 2 when the host kernel
 * offers it, otherwise version 1 with one warning. on warns when it cannot
 * have version 2, as before; off never asks for it.
 */
void femu_test_cxl_never_emulate(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    static const char auto_warning[] = "offers only version 1";
    static const char on_warning[] = "lacks version 2";
    static const char cap[] = "KVM_CAP_CYLON_FAULT_EXIT";
    char *text;

    /* This host has no Cylon: the default resolves to version 1. */
    g_assert_false(femu_cxl_version(NULL, -1, &text));
    g_assert_cmpuint(femu_cxl_count(text, auto_warning), ==, 0);
    g_free(text);
    g_assert_false(femu_cxl_version(NULL, 1, &text));
    g_assert_cmpuint(femu_cxl_count(text, auto_warning), ==, 1);
    g_assert_cmpuint(femu_cxl_count(text, on_warning), ==, 0);
    g_free(text);
    /* No capability at all: its own warning comes when the slot enables. */
    g_assert_false(femu_cxl_version("auto", 0, &text));
    g_assert_cmpuint(femu_cxl_count(text, auto_warning), ==, 0);
    g_free(text);
    g_assert_true(femu_cxl_version("auto", 2, &text));
    g_assert_cmpuint(femu_cxl_count(text, cap), ==, 0);
    g_free(text);
    g_assert_false(femu_cxl_version("on", 1, &text));
    g_assert_cmpuint(femu_cxl_count(text, on_warning), ==, 1);
    g_assert_cmpuint(femu_cxl_count(text, auto_warning), ==, 0);
    g_free(text);
    g_assert_true(femu_cxl_version("on", 2, &text));
    g_assert_cmpuint(femu_cxl_count(text, cap), ==, 0);
    g_free(text);
    g_assert_false(femu_cxl_version("off", 2, &text));
    g_assert_cmpuint(femu_cxl_count(text, cap), ==, 0);
    g_free(text);
    g_assert_false(femu_cxl_version("off", 1, &text));
    g_assert_cmpuint(femu_cxl_count(text, cap), ==, 0);
    g_free(text);
}

void femu_test_cxl_der_invalid(void *obj, void *data,
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

/* TCG cannot keep other vCPUs' TLBs coherent with memslot aliases. */
void femu_test_cxl_memslot_tcg(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE "-accel tcg ");
    QDict *rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
        "'driver':'femu-cxl-ssd','id':'bad','bus':'rp0',"
        "'volatile-memdev':'mem','der':'memslot'}}");

    g_assert_true(qdict_haskey(rsp, "error"));
    g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                        "desc"), "not supported with TCG"));
    qobject_unref(rsp);
    /* The same device without direct mapping realizes under TCG. */
    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
        "'driver':'femu-cxl-ssd','id':'ssd','bus':'rp0',"
        "'volatile-memdev':'mem','der':'off'}}");
    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
    qtest_quit(qts);
}

void femu_test_cxl_cylon_ack(void *obj, void *data,
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

/*
 * cylon-revoke-batch takes 1 to 256 pages. Without a Cylon slot nothing is
 * revoked ahead and no flush is counted.
 */
void femu_test_cxl_revoke_batch(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE);
    const int bad[] = { 0, 257 };
    QDict *rsp;
    unsigned i;

    for (i = 0; i < G_N_ELEMENTS(bad); i++) {
        rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
            "'driver':'femu-cxl-ssd','id':'bad','bus':'rp0',"
            "'volatile-memdev':'mem','cylon-revoke-batch':%d}}", bad[i]);
        g_assert_true(qdict_haskey(rsp, "error"));
        g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                            "desc"),
                                "cylon-revoke-batch must be 1 to 256"));
        qobject_unref(rsp);
    }
    qtest_quit(qts);
    qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,der=memslot,"
        "cache-pages=4,cache-ways=4,cylon-revoke-batch=256");
    femu_cxl_decode(qts);
    for (i = 0; i < 16; i++) {
        qtest_writeq(qts, FEMU_CXL_WINDOW + i * 4096, i);
    }
    for (i = 0; i < 16; i++) {
        g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW + i * 4096), ==, i);
    }
    g_assert_cmpuint(femu_cxl_stat(qts, "der-revocations"), >, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-revoke-flushes"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-revoked-ahead"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-ahead-remaps"), ==, 0);
    qtest_quit(qts);
}

/* A real vCPU writes CXL while qtest observes RAM under the BQL. */
void femu_test_cxl_wait(void *obj, void *data,
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
    int64_t start;
    uint64_t invalidations;
    bool invalidate = data == (void *)2;
    bool unplug = data == (void *)3;
    bool other = data == (void *)4 || data == (void *)5;
    /* 5: a one-page cache, whose only entry the media write's access holds. */
    bool cached = data == (void *)5;
    /* 6: the default, which keeps der=off accesses in one line. */
    bool serial = data == (void *)6;

    g_assert_cmpint(fd, >=, 0);
    memcpy(rom, reset, sizeof(reset));
    /* Reset vector: far jump to f000:0000. */
    memcpy(rom + 65520, (uint8_t[]) { 0xea, 0, 0, 0, 0xf0 }, 5);
    g_assert_cmpint(write(fd, rom, 65536), ==, 65536);
    close(fd);
    quoted = g_shell_quote(rom_path);
    qts = qtest_initf(FEMU_CXL_MACHINE
        "-accel tcg,thread=multi -S -bios %s -smp %u %s"
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "cache-pages=%s,program-ns=1000000000%s", quoted, invalidate ? 2 : 1,
        unplug ? "-global cxl-rp.power_controller_present=on "
        "-global ICH9-LPC.acpi-pci-hotplug-with-bridge-support=off " : "",
        cached ? "1,cache-ways=1" : "0", other ? ",concurrent-misses=on" : "");
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
    if (cached) {
        /* The vCPU's miss must then evict this dirty page: a 1 s program. */
        qtest_writeb(qts, FEMU_CXL_WINDOW + 2 * 4096, 0x77);
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
        invalidations = femu_cxl_stat(qts, "invalidations");
        qtest_writeb(qts, 0x6002, 1);
        /*
         * The config write runs inside the host bridge's dispatch guard, so
         * it must finish while the media write still holds the guard.
         */
        while (qtest_readb(qts, 0x6001) != 2) {
            g_assert_cmpint(g_get_monotonic_time(), <, deadline);
            g_usleep(1000);
        }
        g_assert_cmpuint(qtest_readb(qts, 0x6003), ==, 1);
        g_assert_cmpuint(qtest_readb(qts, 0x6000), ==, 1);
        g_assert_cmpuint(femu_cxl_stat(qts, "invalidations"), >,
                         invalidations);
    } else if (unplug) {
        /*
         * The slot power-off runs inside the host bridge's dispatch guard, so
         * it must not wait for the write sleeping through its 1 s delay.
         */
        start = g_get_monotonic_time();
        femu_cxl_unplug(qts);
        g_assert_cmpint(g_get_monotonic_time() - start, <,
                        G_TIME_SPAN_SECOND / 2);
    } else if (serial) {
        /*
         * Another page waits for the media write too, as before: the read
         * takes most of the 1 s write. The vCPU stores its marker after
         * the write returns, so a loaded host may show it a little later.
         */
        start = g_get_monotonic_time();
        g_assert_cmpuint(qtest_readb(qts, FEMU_CXL_WINDOW + 4096), ==, 0);
        g_assert_cmpint(g_get_monotonic_time() - start, >,
                        G_TIME_SPAN_SECOND / 10);
        while (qtest_readb(qts, 0x6000) != 2) {
            g_assert_cmpint(g_get_monotonic_time(), <, deadline);
            g_usleep(1000);
        }
    } else if (other) {
        /*
         * An access to another page must not wait for the media write: it
         * returns while the write still sleeps, so its marker is still 1.
         * With the cache, the held page is not evicted; the access goes
         * uncached.
         */
        g_assert_cmpuint(qtest_readb(qts, FEMU_CXL_WINDOW + 4096), ==, 0);
        g_assert_cmpuint(qtest_readb(qts, 0x6000), ==, 1);
        if (cached) {
            g_assert_cmpuint(femu_cxl_stat(qts, "cache-evictions"), ==, 1);
        }
    } else if (data) {
        /* A concurrent access must queue, not trip the IO recursion guard. */
        g_assert_cmpuint(qtest_readb(qts, FEMU_CXL_WINDOW), ==, 0x5a);
    }
    if (!unplug) {
        femu_cxl_set(qts, "realized", false);
    }
    while (qtest_readb(qts, 0x6000) != 2) {
        g_assert_cmpint(g_get_monotonic_time(), <, deadline);
        g_usleep(1000);
    }
    qtest_quit(qts);
    unlink(rom_path);
}

#define FEMU_CXL_DMA_BAR 0xa0000000u

/*
 * Wait for entry @index of the admin completion queue at @acq to post for
 * @cid; false at @deadline.
 */
static bool femu_cxl_dma_cqe(QTestState *qts, uint64_t acq, unsigned index,
                             uint16_t cid, int64_t deadline)
{
    while (g_get_monotonic_time() < deadline) {
        uint32_t dw3 = qtest_readl(qts, acq + index * 16 + 12);

        if ((dw3 >> 16) & 1) {
            g_assert_cmphex(dw3 & 0xffff, ==, cid);
            g_assert_cmphex((dw3 >> 17) & 0x7fff, ==, 0);
            return true;
        }
        g_usleep(1000);
    }
    return false;
}

/*
 * QEMU's NVMe controller copies an Identify page from its submission bottom
 * half, which holds the controller's re-entrancy guard. The copy starts in
 * RAM and continues into a CXL page whose miss evicts a dirty page: a 1 s
 * program. A vCPU sees the RAM part and rings the doorbell again. Had the
 * copy released the BQL, the controller would refuse that write as
 * re-entrant and the second command would never run. With @data 1 the CXL
 * page is cached clean, and with 2 the admin queues live in CXL too. The
 * vCPU's second write can only race the copy's wait; a vCPU descheduled for
 * the whole second would miss it, so the test can pass on a broken build
 * under extreme load, never fail on a correct one.
 */
void femu_test_cxl_dma_doorbell(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    static const uint8_t reset[] = {
        0xfa, 0x31, 0xc0, 0x8e, 0xd8, 0x0f, 0x01, 0x16, 0x00, 0x05, 0x0f, 0x20,
        0xc0, 0x66, 0x83, 0xc8, 0x01, 0x0f, 0x22, 0xc0, 0x66, 0xea, 0x00, 0x10,
        0x00, 0x00, 0x08, 0x00,
    };
    /*
     * In 32-bit protected mode: wait for 0x6000, ring the admin doorbell with
     * tail 1, wait for the RAM part of the copy, ring it with tail 2, mark
     * 0x6001.
     */
    uint8_t code[] = {
        0x66, 0xb8, 0x10, 0x00, 0x8e, 0xd8,
        0x80, 0x3d, 0x00, 0x60, 0x00, 0x00, 0x01, 0x75, 0xf7,
        0xc7, 0x05, 0, 0, 0, 0, 0x01, 0x00, 0x00, 0x00,
        0x66, 0x81, 0x3d, 0, 0, 0, 0, 0x36, 0x1b, 0x75, 0xf5,
        0xc7, 0x05, 0, 0, 0, 0, 0x02, 0x00, 0x00, 0x00,
        0xc6, 0x05, 0x01, 0x60, 0x00, 0x00, 0x01,
        0xf4, 0xeb, 0xfd,
    };
    const uint32_t db = FEMU_CXL_DMA_BAR + 0x1000;
    bool cached = data == (void *)1;
    bool queues = data == (void *)2;
    const uint64_t asq = queues ? FEMU_CXL_WINDOW + 3 * 4096 : 0x200000;
    const uint64_t acq = queues ? FEMU_CXL_WINDOW + 4 * 4096 : 0x201000;
    /* The RAM part of the first copy: the last 64 bytes of this page. */
    const uint64_t ram_part = 0x203000 + 4096 - 64;
    const uint64_t ram_buf = 0x205000;
    const uint64_t cxl_buf = FEMU_CXL_WINDOW + 4096;
    const uint32_t devfn = 5 << 3;
    g_autofree char *rom_path = g_strdup("cxl-dma-rom-XXXXXX");
    g_autofree char *quoted = NULL;
    g_autofree uint8_t *rom = g_malloc0(65536);
    int fd = g_mkstemp(rom_path);
    QTestState *qts;
    int64_t deadline;
    uint64_t evictions;
    uint8_t sqe[64];

    stl_le_p(code + 17, db);
    stl_le_p(code + 28, ram_part);
    stl_le_p(code + 38, db);
    g_assert_cmpint(fd, >=, 0);
    memcpy(rom, reset, sizeof(reset));
    memcpy(rom + 65520, (uint8_t[]) { 0xea, 0, 0, 0, 0xf0 }, 5);
    g_assert_cmpint(write(fd, rom, 65536), ==, 65536);
    close(fd);
    quoted = g_shell_quote(rom_path);
    qts = qtest_initf(FEMU_CXL_MACHINE
        "-accel tcg,thread=multi -S -bios %s "
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "cache-pages=1,cache-ways=1,program-ns=1000000000 "
        "-device nvme,id=nvme0,serial=cxldma,bus=pcie.0,addr=5", quoted);
    femu_cxl_decode(qts);
    /* Flat 32-bit code and data segments. */
    qtest_writew(qts, 0x500, 31);
    qtest_writel(qts, 0x502, 0x508);
    qtest_writeq(qts, 0x508, 0);
    qtest_writeq(qts, 0x510, 0x00cf9a000000ffffULL);
    qtest_writeq(qts, 0x518, 0x00cf92000000ffffULL);
    qtest_memwrite(qts, 0x1000, code, sizeof(code));

    femu_cxl_config(qts, 0, devfn << 8 | PCI_BASE_ADDRESS_0,
                    FEMU_CXL_DMA_BAR);
    femu_cxl_config(qts, 0, devfn << 8 | (PCI_BASE_ADDRESS_0 + 4), 0);
    femu_cxl_config(qts, 0, devfn << 8 | PCI_COMMAND,
                    PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);
    qtest_writel(qts, FEMU_CXL_DMA_BAR + NVME_REG_AQA, 3 << 16 | 3);
    qtest_writeq(qts, FEMU_CXL_DMA_BAR + NVME_REG_ASQ, asq);
    qtest_writeq(qts, FEMU_CXL_DMA_BAR + NVME_REG_ACQ, acq);
    qtest_writel(qts, FEMU_CXL_DMA_BAR + NVME_REG_CC,
                 4 << 20 | 6 << 16 | 1);
    deadline = g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND;
    while (!(qtest_readl(qts, FEMU_CXL_DMA_BAR + NVME_REG_CSTS) & 1)) {
        g_assert_cmpint(g_get_monotonic_time(), <, deadline);
        g_usleep(1000);
    }
    /* Identify Controller across RAM and CXL, then into RAM. */
    memset(sqe, 0, sizeof(sqe));
    sqe[0] = NVME_ADM_CMD_IDENTIFY;
    stw_le_p(sqe + 2, 1);
    stq_le_p(sqe + 24, ram_part);
    stq_le_p(sqe + 32, cxl_buf);
    stl_le_p(sqe + 40, NVME_ID_CNS_CTRL);
    qtest_memwrite(qts, asq, sqe, sizeof(sqe));
    stw_le_p(sqe + 2, 2);
    stq_le_p(sqe + 24, ram_buf);
    stq_le_p(sqe + 32, 0);
    qtest_memwrite(qts, asq + 64, sqe, sizeof(sqe));
    if (queues) {
        qtest_memset(qts, acq, 0, 4096);
    }
    /* The copy's miss must then evict this dirty page: a 1 s program. */
    qtest_writeb(qts, FEMU_CXL_WINDOW + 2 * 4096, 0x77);
    /* Or the copy hits: cache the CXL page clean, writing the other back. */
    if (cached) {
        g_assert_cmpuint(qtest_readb(qts, cxl_buf), ==, 0);
    }
    evictions = femu_cxl_stat(qts, "cache-evictions");

    qtest_qmp_assert_success(qts, "{'execute':'cont'}");
    qtest_writeb(qts, 0x6000, 1);
    deadline = g_get_monotonic_time() + 20 * G_TIME_SPAN_SECOND;
    while (qtest_readb(qts, 0x6001) != 1) {
        g_assert_cmpint(g_get_monotonic_time(), <, deadline);
        g_usleep(1000);
    }
    /* Copies into CXL change no cache state; read it before the queues. */
    if (queues) {
        g_assert_cmpuint(femu_cxl_stat(qts, "cache-evictions"), ==,
                         evictions);
    }
    g_assert_true(femu_cxl_dma_cqe(qts, acq, 0, 1, deadline));
    /* The second doorbell must not be lost. */
    g_assert_true(femu_cxl_dma_cqe(qts, acq, 1, 2, deadline));
    if (!queues) {
        g_assert_cmpuint(femu_cxl_stat(qts, "cache-evictions"), ==,
                         evictions);
    }
    /* One access per 8 bytes of CXL, and one program for the page. */
    if (queues) {
        g_assert_cmpuint(femu_cxl_stat(qts, "dma-accesses"), >, 504);
        g_assert_cmpuint(femu_cxl_stat(qts, "dma-media-ops"), >=, 2);
    } else {
        g_assert_cmpuint(femu_cxl_stat(qts, "dma-accesses"), ==, 504);
        g_assert_cmpuint(femu_cxl_stat(qts, "dma-media-ops"), ==, !cached);
    }
    while (!cached &&
           femu_cxl_stat(qts, "dma-media-time-ns") < 1000000000) {
        g_assert_cmpint(g_get_monotonic_time(), <, deadline);
        g_usleep(1000);
    }
    /* Both copies arrived, with QEMU's vendor ID. */
    g_assert_cmphex(qtest_readw(qts, ram_part), ==, 0x1b36);
    g_assert_cmphex(qtest_readw(qts, ram_buf), ==, 0x1b36);
    g_assert_cmphex(qtest_readw(qts, cxl_buf), !=, 0);
    if (cached) {
        uint64_t writes = femu_cxl_stat(qts, "media-writes");

        /* The copy dirtied the page, so evicting it programs it. */
        g_assert_cmpuint(qtest_readb(qts, FEMU_CXL_WINDOW + 2 * 4096), ==,
                         0x77);
        g_assert_cmpuint(femu_cxl_stat(qts, "media-writes"), ==, writes + 1);
    }
    qtest_quit(qts);
    unlink(rom_path);
}

void femu_test_cxl_no_ftl(void *obj, void *data,
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

void femu_test_cxl_invalid(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    static const struct {
        const char *args;
        const char *error;
    } cases[] = {
        { "'cache-policy':'unknown'", "cache-policy must be" },
        { "'cache-ways':0", "cache-ways" },
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

/* Refuse device_add with @opts and expect @need in the error. */
static void femu_cxl_refuse(QTestState *qts, const char *opts, const char *need)
{
    g_autofree char *cmd = g_strdup_printf(
        "{'execute':'device_add','arguments':{'driver':'femu-cxl-ssd',"
        "'id':'ssd','bus':'rp0','volatile-memdev':'mem',"
        "'channels':4,'luns-per-channel':4,'pages-per-block':256,%s}}", opts);
    QDict *rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));
    const char *desc;

    g_assert_true(qdict_haskey(rsp, "error"));
    desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
    g_assert_nonnull(strstr(desc, "over-provisioning"));
    g_assert_nonnull(strstr(desc, need));
    qobject_unref(rsp);
}

/*
 * 256 MiB fill 16 lines of 4 x 4 LUNs x 256 pages. Without a spare line
 * every program after the first fill fails; with one, the FTL runs out of
 * lines on the way. Realize asks for 7% of the media beyond the lines
 * gc-threshold-high keeps free and two more, and automatic sizing meets
 * that.
 */
void femu_test_cxl_nand_reserve(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE);
    QDict *rsp;

    femu_cxl_refuse(qts, "'blocks-per-plane':16", "at least 21");
    femu_cxl_refuse(qts, "'blocks-per-plane':18", "at least 21");
    femu_cxl_refuse(qts, "'blocks-per-plane':20", "at least 21");
    femu_cxl_refuse(qts, "'blocks-per-plane':25,'gc-threshold':50,"
                    "'gc-threshold-high':75", "at least 26");
    femu_cxl_refuse(qts, "'blocks-per-plane':16,'gc-threshold':50,"
                    "'gc-threshold-high':50", "at least 39");
    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu-cxl-ssd','id':'ssd','bus':'rp0',"
                    "'volatile-memdev':'mem','channels':4,"
                    "'luns-per-channel':4,'pages-per-block':256,"
                    "'gc-threshold':50,'gc-threshold-high':50}}");
    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
    g_assert_cmpuint(femu_cxl_stat(qts, "blocks-per-plane"), ==, 39);
    qtest_quit(qts);

    /* Without the FTL there is no collection to keep room for. */
    qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,ftl=off,"
        "channels=4,luns-per-channel=4,pages-per-block=256,"
        "blocks-per-plane=16");
    qtest_quit(qts);
}

/*
 * 290 lines of 4 x 4 LUNs x 16 pages, the least realize accepts for 256 MiB.
 * With 16-page blocks, scattered rewrites still find the free lines at the
 * forced threshold, so write-backs must wait for forced collection. None may
 * find NAND full or go
 * uncached, and the FTL must never run out of lines.
 */
void femu_test_cxl_gc_stall(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    g_autofree char *dir = g_dir_make_tmp("femu-cxl-gc-XXXXXX", NULL);
    g_autofree char *path = g_build_filename(dir, "errors", NULL);
    g_autofree char *args = g_strdup_printf(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "cache-pages=16,cache-ways=16,channels=4,luns-per-channel=4,"
        "pages-per-block=16,blocks-per-plane=290,read-ns=1000,"
        "program-ns=1000,erase-ns=1000 2>%s", path);
    g_autofree char *errors = NULL;
    QTestState *qts = qtest_init(args);
    uint64_t pages = 256 * 1024 * 1024 / 4096;
    uint64_t pass;
    uint64_t i;

    femu_cxl_decode(qts);
    for (pass = 0; pass < 3; pass++) {
        for (i = 0; i < pages; i++) {
            /* 4099 is odd, so the stride visits every page once a pass. */
            uint64_t lpn = pass ? i * 4099 % pages : i;

            qtest_writeq(qts, FEMU_CXL_WINDOW + lpn * 4096, lpn | pass << 32);
        }
    }
    femu_cxl_set(qts, "flush-cache", true);
    for (i = 0; i < pages; i += 61) {
        g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW + i * 4096), ==,
                        i | 2ULL << 32);
    }
    g_assert_cmpuint(femu_cxl_stat(qts, "media-full"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-inserts"), ==,
                     femu_cxl_stat(qts, "cache-misses"));
    /* Each pass programmed every page once. */
    g_assert_cmpuint(femu_cxl_stat(qts, "media-writes"), ==, 3 * pages);
    g_test_message("gc-stalls %" PRIu64 " gc-stall-ns %" PRIu64
                   " media-time-ns %" PRIu64,
                   femu_cxl_stat(qts, "gc-stalls"),
                   femu_cxl_stat(qts, "gc-stall-ns"),
                   femu_cxl_stat(qts, "media-time-ns"));
    g_assert_cmpuint(femu_cxl_stat(qts, "gc-stalls"), >, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "gc-stall-ns"), >, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "gc-stall-max-ns"), >, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "gc-stall-max-ns"), <=,
                     femu_cxl_stat(qts, "gc-stall-ns"));
    g_assert_cmpuint(femu_cxl_stat(qts, "gc-stall-max-ns"), <,
                     NANOSECONDS_PER_SECOND);
    qtest_quit(qts);
    g_assert_true(g_file_get_contents(path, &errors, NULL, NULL));
    g_assert_null(strstr(errors, "No free lines"));
    g_assert_null(strstr(errors, "forced garbage collection"));
    unlink(path);
    rmdir(dir);
}

/*
 * Scattered rewrites at 21 blocks per plane, the least realize accepts for
 * 256 MiB of 4 x 4 LUNs x 256 pages, with the NAND timing of the
 * run-cxlssd.sh presets. fast-load lets the accesses run on without waiting,
 * so NAND work queues up as it does under device DMA. The spare lines beyond
 * the forced reserve let background collection keep up: no request waits for
 * forced collection at all. At 18 blocks, the least the old rule accepted,
 * 170 requests waited, the longest 200 ms or more.
 */
void femu_test_cxl_gc_reserve_stall(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "cache-pages=16,cache-ways=16,channels=4,luns-per-channel=4,"
        "pages-per-block=256,blocks-per-plane=21,read-ns=40000,"
        "program-ns=200000,erase-ns=2000000");
    uint64_t line_copy = 256 * (40000 + 200000) + 2000000;
    uint64_t pages = 256 * 1024 * 1024 / 4096;
    uint64_t pass;
    uint64_t i;

    femu_cxl_decode(qts);
    femu_cxl_set(qts, "fast-load", true);
    for (pass = 0; pass < 3; pass++) {
        for (i = 0; i < pages; i++) {
            uint64_t lpn = pass ? i * 4099 % pages : i;

            qtest_writeq(qts, FEMU_CXL_WINDOW + lpn * 4096, lpn | pass << 32);
        }
    }
    femu_cxl_set(qts, "flush-cache", true);
    g_test_message("gc-stalls %" PRIu64 " gc-stall-max-ns %" PRIu64,
                   femu_cxl_stat(qts, "gc-stalls"),
                   femu_cxl_stat(qts, "gc-stall-max-ns"));
    g_assert_cmpuint(femu_cxl_stat(qts, "gc-stalls"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "gc-stall-max-ns"), <, line_copy);
    /* Three passes program more pages than the NAND holds: collection ran. */
    g_assert_cmpuint(3 * pages, >, 21 * 4 * 4 * 256);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-writes"), ==, 3 * pages);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-full"), ==, 0);
    qtest_quit(qts);
}

/*
 * A stall over one second warns once, with the geometry. One-second erases
 * make the first forced collection stall that long; fast-load lets the
 * accesses run on without waiting for it. 256 lines of media at 290 blocks
 * per plane, the least realize accepts.
 */
void femu_test_cxl_gc_stall_warn(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    g_autofree char *log = g_strdup("cxl-gc-warn-XXXXXX");
    g_autofree char *quoted = NULL;
    g_autofree char *args = NULL;
    g_autofree char *text = NULL;
    int fd = g_mkstemp(log);
    uint64_t pages = 256 * 1024 * 1024 / 4096;
    QTestState *qts;
    uint64_t i;

    g_assert_cmpint(fd, >=, 0);
    close(fd);
    quoted = g_shell_quote(log);
    args = g_strdup_printf(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "cache-pages=16,cache-ways=16,channels=4,luns-per-channel=4,"
        "pages-per-block=16,blocks-per-plane=290,read-ns=1000,"
        "program-ns=1000,erase-ns=1000000000 2>%s", quoted);
    qts = qtest_init(args);
    femu_cxl_decode(qts);
    femu_cxl_set(qts, "fast-load", true);
    for (i = 0; i < 2 * pages; i++) {
        uint64_t lpn = i < pages ? i : i * 4099 % pages;

        qtest_writeq(qts, FEMU_CXL_WINDOW + lpn * 4096, i);
        if (i > pages && i % 1024 == 0 &&
            femu_cxl_stat(qts, "gc-stall-max-ns") > NANOSECONDS_PER_SECOND) {
            break;
        }
    }
    g_assert_cmpuint(femu_cxl_stat(qts, "gc-stall-max-ns"), >,
                     NANOSECONDS_PER_SECOND);
    g_assert_cmpuint(femu_cxl_stat(qts, "gc-stall-max-ns"), <=,
                     femu_cxl_stat(qts, "gc-stall-ns"));
    g_assert_cmpuint(femu_cxl_stat(qts, "media-full"), ==, 0);
    qtest_quit(qts);
    g_assert_true(g_file_get_contents(log, &text, NULL, NULL));
    unlink(log);
    g_assert_cmpuint(femu_cxl_count(text, "forced garbage collection"), ==,
                     1);
    g_assert_nonnull(strstr(text, "blocks-per-plane=290;"));
}

/*
 * Four-page blocks make a line four pages per LUN, and slow reads load only
 * the LUNs that hold a victim's valid pages. A write-back must wait until
 * forced collection ends on every LUN. The probe writes pages never written
 * before, so its fill reads are free and its media time is the write-back
 * alone. 1155 blocks per plane is the least realize accepts, and
 * gc-threshold=95 starts collection only at the forced threshold. Few probe
 * pages keep the spare NAND at that least.
 *
 * The medium keeps gc_erase_order: the erases of a victim start on every
 * LUN when its last copy ends. The write-back program then queues behind
 * the erase on its own LUN. It ends at most one tPROG after collection
 * ends, and exactly one tPROG when the erases end together:
 *
 *   LUN a  [rd][rd]              [erase]
 *   LUN b          [copy program][erase][program]   media = wait + tPROG
 *                                ^fence ^ collection end (wait)
 */
void femu_test_cxl_gc_wait(void *obj, void *data,
                           QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "cache-pages=16,cache-ways=16,channels=4,luns-per-channel=4,"
        "pages-per-block=4,blocks-per-plane=1155,gc-threshold=95,"
        "read-ns=20000,program-ns=1000,erase-ns=1000");
    uint64_t pages = 256 * 1024 * 1024 / 4096;
    uint64_t probe = 128;
    uint64_t used = pages - probe;
    uint64_t stalled = 0;
    uint64_t bound = 0;
    uint64_t i;

    femu_cxl_decode(qts);
    for (i = 0; i < used; i++) {
        qtest_writeq(qts, FEMU_CXL_WINDOW + i * 4096, i);
    }
    /*
     * Rewrite until collection is first forced, and probe from there: a full
     * pass would leave every old line invalid, and background collection
     * would then free them all before the probe.
     */
    for (i = 0; i < 4 * used; i++) {
        /* 4099 shares no factor with 65408 pages. */
        uint64_t lpn = i * 4099 % used;

        qtest_writeq(qts, FEMU_CXL_WINDOW + lpn * 4096, lpn);
        if (i % 64 == 0 && femu_cxl_stat(qts, "gc-stalls")) {
            break;
        }
    }
    g_test_message("rewrites before the first forced collection: %" PRIu64,
                   i);
    g_assert_cmpuint(i, <, 4 * used);
    for (i = used; i < pages; i++) {
        uint64_t media = femu_cxl_stat(qts, "media-time-ns");
        uint64_t stalls = femu_cxl_stat(qts, "gc-stalls");
        uint64_t wait = femu_cxl_stat(qts, "gc-stall-ns");

        qtest_writeq(qts, FEMU_CXL_WINDOW + i * 4096, i);
        if (femu_cxl_stat(qts, "gc-stalls") == stalls) {
            continue;
        }
        stalled++;
        media = femu_cxl_stat(qts, "media-time-ns") - media;
        wait = femu_cxl_stat(qts, "gc-stall-ns") - wait;
        g_assert_cmpuint(media, >=, wait);
        /* The program ends at most one tPROG (1000 ns) after collection. */
        g_assert_cmpuint(media - wait, <=, 1000);
        bound += media == wait + 1000;
    }
    g_test_message("probe write-backs that waited for collection: %" PRIu64
                   ", programmed after its erase: %" PRIu64, stalled, bound);
    g_assert_cmpuint(stalled, >, 0);
    g_assert_cmpuint(bound, >, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-full"), ==, 0);
    qtest_quit(qts);
}

void femu_test_cxl_prefetch(void *obj, void *data,
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

void femu_test_cxl_prefetch_clamp(void *obj, void *data,
                                        QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "cache-pages=16,cache-ways=16");

    femu_cxl_decode(qts);
    /* A degree beyond the cache would only evict what it just fetched. */
    femu_cxl_number(qts, "prefetch-degree", 1000, true);
    qtest_writeq(qts, FEMU_CXL_WINDOW, 0xfeed);
    g_assert_cmpuint(femu_cxl_stat(qts, "prefetch-inserts"), ==, 16);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 0xfeed);
    qtest_quit(qts);
}

void femu_test_cxl_stats(void *obj, void *data,
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

void femu_test_cxl_ways(void *obj, void *data,
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

void femu_test_cxl_compat(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "cylon-first-touch-program=on,cylon-free-writeback=on,"
        "channels=8,luns-per-channel=8,pages-per-block=64,"
        "blocks-per-plane=32,channel-ns=100,gc-threshold=70,"
        "gc-threshold-high=90");

    femu_cxl_decode(qts);
    qtest_readq(qts, FEMU_CXL_WINDOW);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-writes"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-time-ns"), >=, 200000);
    qtest_writeq(qts, FEMU_CXL_WINDOW, 42);
    femu_cxl_set(qts, "flush-cache", true);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-writes"), ==, 1);
    g_assert_cmpuint(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 42);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-reads"), ==, 1);
    qtest_quit(qts);
}

void femu_test_cxl_capacity(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    unsigned sizes[] = { 48, 96, 120, 121 };
    unsigned i;

    for (i = 0; i < G_N_ELEMENTS(sizes); i++) {
        uint64_t bytes = (uint64_t)sizes[i] << 30;
        g_auto(GStrv) parts = g_strsplit(FEMU_CXL_MACHINE,
                                         "cxl-fmw.0.size=256M", 2);
        g_autofree char *args = g_strdup_printf(
            "%scxl-fmw.0.size=%uG%s "
            "-object memory-backend-ram,id=large,reserve=off,size=%uG %s",
            parts[0], sizes[i], parts[1], sizes[i], sizes[i] <= 120 ?
            "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=large,"
            "ftl=off,channels=8,luns-per-channel=8" : "");
        QTestState *qts = qtest_init(args);

        if (sizes[i] <= 120) {
            femu_cxl_decode(qts);
            qtest_writel(qts, FEMU_CXL_REGS + A_CXL_HDM_DECODER0_SIZE_LO,
                         bytes);
            qtest_writel(qts, FEMU_CXL_REGS + A_CXL_HDM_DECODER0_SIZE_HI,
                         bytes >> 32);
            qtest_writel(qts, FEMU_CXL_REGS + A_CXL_HDM_DECODER0_CTRL, 0x200);
            qtest_writeq(qts, FEMU_CXL_WINDOW + bytes - 4096, 42);
            g_assert_cmpuint(qtest_readq(qts, FEMU_CXL_WINDOW + bytes - 4096),
                             ==, 42);
        } else {
            QDict *rsp = qtest_qmp(qts,
                "{'execute':'device_add','arguments':{"
                "'driver':'femu-cxl-ssd','id':'ssd','bus':'rp0',"
                "'volatile-memdev':'large','ftl':false}}");

            g_assert_true(qdict_haskey(rsp, "error"));
            g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                                 "desc"), "120 GiB"));
            qobject_unref(rsp);
        }
        qtest_quit(qts);
    }
}

/* Wait until no Get LSA control command is queued. */
static void femu_cxl_lsa_wait(QTestState *qts)
{
    gint64 deadline = g_get_monotonic_time() + 30 * G_USEC_PER_SEC;

    while (femu_cxl_stat(qts, "control-status") == 2) {
        g_assert_cmpint(g_get_monotonic_time(), <, deadline);
        g_usleep(1000);
    }
}

static void femu_cxl_command(QTestState *qts, bool lsa, unsigned command,
                             unsigned argument)
{
    if (lsa) {
        uint64_t mbox = 0x90010000 + CXL_MAILBOX_REGISTERS_OFFSET;

        qtest_writel(qts, mbox + CXL_MAILBOX_REGISTERS_SIZE, argument);
        qtest_writel(qts, mbox + CXL_MAILBOX_REGISTERS_SIZE + 4, command);
        uint8_t status;

        qtest_writeq(qts, mbox + A_CXL_DEV_MAILBOX_CMD, (8ULL << 16) | 0x4102);
        qtest_writel(qts, mbox + A_CXL_DEV_MAILBOX_CTRL, 1);
        g_assert_cmpuint(qtest_readq(qts, mbox + A_CXL_DEV_MAILBOX_STS) >> 32,
                         ==, 0);
        status = qtest_readb(qts, mbox + CXL_MAILBOX_REGISTERS_SIZE);
        /* Commands that can wait run after the read; 2 says queued. */
        g_assert_cmpuint(status, ==,
                         command == 2 || command == 3 || command == 9 ||
                         command == 11 ? 2 : 0);
        femu_cxl_lsa_wait(qts);
    } else {
        femu_cxl_number(qts, "control-argument", argument, true);
        femu_cxl_number(qts, "control-command", command, true);
    }
    g_assert_cmpuint(femu_cxl_stat(qts, "control-status"), ==, 0);
}

static uint64_t femu_cxl_file_size(const char *dir, const char *name)
{
    g_autofree char *path = g_build_filename(dir, name, NULL);
    struct stat st;

    g_assert_cmpint(stat(path, &st), ==, 0);
    return st.st_size;
}

/* A guest drives every CXL log file; none may grow past log-limit. */
void femu_test_cxl_log_limit(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    g_autofree char *dir = g_dir_make_tmp("femu-cxl-log-XXXXXX", NULL);
    g_autofree char *args = g_strdup_printf(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "der=memslot,log-dir=%s,log-limit=4096", dir);
    g_autofree char *spt = NULL;
    QTestState *qts;
    uint64_t dropped;
    unsigned i;

    g_assert_nonnull(dir);
    qts = qtest_init(args);
    femu_cxl_decode(qts);
    femu_cxl_command(qts, false, 13, 0);
    for (i = 0; i < 400; i++) {
        qtest_writeq(qts, FEMU_CXL_WINDOW + (uint64_t)i * 4096, i);
    }
    g_assert_cmpuint(femu_cxl_file_size(dir, "cxlssd-io-1.log"), <, 4096 + 64);
    dropped = femu_cxl_stat(qts, "log-dropped");
    g_assert_cmpuint(dropped, ==, 1);
    /* Statistics appends are rate limited as well as capped. */
    for (i = 0; i < 100; i++) {
        femu_cxl_command(qts, false, 1, i);
    }
    g_assert_cmpuint(femu_cxl_file_size(dir, "cxlssd-stats.log"), <,
                     4096 + 512);
    g_assert_cmpuint(femu_cxl_stat(qts, "log-dropped"), >, dropped);
    /* 400 one-page aliases would need about 7 KiB. */
    femu_cxl_command(qts, false, 17, 0);
    g_assert_cmpuint(femu_cxl_file_size(dir, "cxlssd-spt.log"), <, 4096 + 64);
    spt = g_build_filename(dir, "cxlssd-spt.log", NULL);
    {
        g_autofree char *text = NULL;

        g_assert_true(g_file_get_contents(spt, &text, NULL, NULL));
        g_assert_nonnull(strstr(text, "truncated"));
    }
    qtest_quit(qts);
    {
        g_autofree char *io = g_build_filename(dir, "cxlssd-io-1.log", NULL);
        g_autofree char *stats = g_build_filename(dir, "cxlssd-stats.log",
                                                  NULL);

        unlink(io);
        unlink(stats);
    }
    unlink(spt);
    rmdir(dir);
}

void femu_test_cxl_control(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    bool lsa = data != NULL;
    g_autofree char *dir = g_dir_make_tmp("femu-cxl-control-XXXXXX", NULL);
    g_autofree char *args = g_strdup_printf(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "lsa-control=%s,log-dir=%s,tracefs-dir=%s,der=memslot",
        lsa ? "on" : "off", dir, dir);
    QTestState *qts = qtest_init(args);
    g_autofree char *contents = NULL;
    g_autofree char *path = NULL;
    GDir *files;
    const char *name;
    unsigned io_logs = 0;
    unsigned i;
    QDict *rsp;

    femu_cxl_decode(qts);
    femu_cxl_config(qts, 53, 0x18, 0x90010000);
    femu_cxl_config(qts, 53, 0x1c, 0);
    femu_cxl_command(qts, lsa, 5, 3);
    femu_cxl_command(qts, lsa, 7, 2);
    g_assert_cmpuint(femu_cxl_stat(qts, "prefetch-degree"), ==, 3);
    g_assert_cmpuint(femu_cxl_stat(qts, "prefetch-stride"), ==, 2);
    qtest_writeq(qts, FEMU_CXL_WINDOW + 8 * 4096, 1);
    femu_cxl_command(qts, lsa, 3, 5);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-ways"), ==, 1024);
    /* Like Cylon's buffer_clear, a way change drops the event counters. */
    g_assert_cmpuint(femu_cxl_stat(qts, "write-misses"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-inserts"), ==, 0);
    femu_cxl_command(qts, lsa, 13, 0);
    qtest_writeq(qts, FEMU_CXL_WINDOW, 42);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 4);
    femu_cxl_command(qts, lsa, 15, 0);
    femu_cxl_command(qts, lsa, 1, 42);
    g_assert_cmpuint(femu_cxl_stat(qts, "last-write-misses"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(qts, "write-misses"), ==, 0);
    qtest_readq(qts, FEMU_CXL_WINDOW + 8 * 4096);
    femu_cxl_command(qts, lsa, 2, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-entries"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "read-misses"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-evictions"), ==, 0);
    femu_cxl_command(qts, lsa, 9, 0);
    femu_cxl_command(qts, lsa, 11, 0);
    femu_cxl_command(qts, lsa, 90, 100);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 65536);
    g_assert_cmpuint(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 42);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-entries"), ==, 0);
    femu_cxl_command(qts, lsa, 17, 0);
    femu_cxl_command(qts, lsa, 80, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 0);
    path = g_build_filename(dir, "trace", NULL);
    g_assert_true(g_file_set_contents(path, "stale", -1, NULL));
    femu_cxl_command(qts, lsa, 91, 0);
    /* 91 clears the host trace buffer and leaves QEMU trace events alone. */
    g_assert_true(g_file_get_contents(path, &contents, NULL, NULL));
    g_assert_cmpstr(contents, ==, "");
    g_clear_pointer(&path, g_free);
    g_clear_pointer(&contents, g_free);
    rsp = qtest_qmp(qts, "{'execute':'trace-event-get-state','arguments':"
                    "{'name':'memory_region_ops_read'}}");
    g_assert_cmpstr(qdict_get_str(qobject_to(QDict, qlist_peek(
                    qdict_get_qlist(rsp, "return"))), "state"), ==,
                    "disabled");
    qobject_unref(rsp);
    femu_cxl_command(qts, lsa, 81, 0);
    femu_cxl_number(qts, "control-command", 1234, false);
    femu_cxl_number(qts, "control-argument", 6, true);
    femu_cxl_number(qts, "control-command", 3, false);
    femu_cxl_number(qts, "der-ratio", 101, false);
    femu_cxl_number(qts, "der-ratio", 99, true);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 64880);
    femu_cxl_number(qts, "der-ratio", 0, true);
    path = g_build_filename(dir, "cxlssd-io-1.log", NULL);
    g_assert_true(g_file_get_contents(path, &contents, NULL, NULL));
    g_assert_nonnull(strstr(contents, ",W,0,8,"));
    g_clear_pointer(&path, g_free);
    g_clear_pointer(&contents, g_free);
    path = g_build_filename(dir, "cxlssd-spt.log", NULL);
    g_assert_true(g_file_get_contents(path, &contents, NULL, NULL));
    g_assert_nonnull(strstr(contents, "mapped=65536"));
    g_clear_pointer(&path, g_free);
    g_clear_pointer(&contents, g_free);
    path = g_build_filename(dir, "cxlssd-stats.log", NULL);
    g_assert_true(g_file_get_contents(path, &contents, NULL, NULL));
    g_assert_nonnull(strstr(contents, "write=0/1"));
    /* Cylon's cxlssd_buffer.txt lines precede FEMU's summary. */
    g_assert_nonnull(strstr(contents, "NAND size: 256 MB, Buffer size: 4 MB, "
                            "eviction: FIFO, prefetch: 3, way: 1024, "
                            "== 42 ==\nEntry cnt: "));
    g_assert_nonnull(strstr(contents, "Buffer write: 0 hit/ 1 miss\n"));
    g_assert_nonnull(strstr(contents, "[Set degree]\x20\n\tNAND size: "));
    g_assert_nonnull(strstr(contents, "[Set way] eviction: FIFO, prefetch: 3, "
                            "way: 1024\n"));
    g_clear_pointer(&path, g_free);
    g_clear_pointer(&contents, g_free);
    path = g_build_filename(dir, "tracing_on", NULL);
    g_assert_true(g_file_get_contents(path, &contents, NULL, NULL));
    g_assert_cmpstr(contents, ==, "0\n");
    /* I/O logs reuse a bounded set of names. */
    for (i = 0; i < 65; i++) {
        femu_cxl_command(qts, lsa, 13, 0);
    }
    femu_cxl_command(qts, lsa, 15, 0);
    qtest_quit(qts);
    files = g_dir_open(dir, 0, NULL);
    while ((name = g_dir_read_name(files))) {
        g_autofree char *file = g_build_filename(dir, name, NULL);

        io_logs += g_str_has_prefix(name, "cxlssd-io-");
        unlink(file);
    }
    g_dir_close(files);
    rmdir(dir);
    g_assert_cmpuint(io_logs, ==, 64);
}

void femu_test_cxl_geometry_bounds(void *obj, void *data,
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

void femu_test_cxl_log_missing(void *obj, void *data,
                                     QGuestAllocator *alloc)
{
    g_autofree char *dir = g_dir_make_tmp("femu-cxl-missing-XXXXXX", NULL);
    g_autofree char *args = g_strdup_printf(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "lsa-control=on,log-dir=%s/missing,tracefs-dir=%s/missing "
        "2>%s/errors", dir, dir, dir);
    g_autofree char *path = g_build_filename(dir, "errors", NULL);
    g_autofree char *contents = NULL;
    QTestState *qts = qtest_init(args);
    static const char *const names[] = {
        "cxlssd-io-1.log", "cxlssd-stats.log", "cxlssd-spt.log", "tracing_on",
    };
    unsigned i;

    femu_cxl_command(qts, false, 13, 0);
    for (i = 0; i < 2; i++) {
        femu_cxl_command(qts, false, 1, 0);
        femu_cxl_command(qts, false, 17, 0);
        femu_cxl_command(qts, false, 91, 0);
        femu_cxl_command(qts, false, 81, 0);
    }
    qtest_quit(qts);
    g_assert_true(g_file_get_contents(path, &contents, NULL, NULL));
    /* Each unavailable file warns exactly once, however often it is used. */
    for (i = 0; i < G_N_ELEMENTS(names); i++) {
        g_autofree char *needle = g_strdup_printf("/missing/%s:", names[i]);
        char *warning = strstr(contents, needle);

        g_assert_nonnull(warning);
        g_assert_null(strstr(warning + 1, needle));
    }
    unlink(path);
    rmdir(dir);
}

void femu_test_cxl_lsa_normal(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-object memory-backend-ram,id=labels,size=1M "
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,lsa=labels");
    uint64_t mbox = 0x90010000 + CXL_MAILBOX_REGISTERS_OFFSET;

    femu_cxl_decode(qts);
    femu_cxl_config(qts, 53, 0x18, 0x90010000);
    femu_cxl_config(qts, 53, 0x1c, 0);
    qtest_writeq(qts, mbox + CXL_MAILBOX_REGISTERS_SIZE, 0);
    qtest_writeb(qts, mbox + CXL_MAILBOX_REGISTERS_SIZE + 8, 42);
    qtest_writeq(qts, mbox + A_CXL_DEV_MAILBOX_CMD, (9ULL << 16) | 0x4103);
    qtest_writel(qts, mbox + A_CXL_DEV_MAILBOX_CTRL, 1);
    g_assert_cmpuint(qtest_readq(qts, mbox + A_CXL_DEV_MAILBOX_STS) >> 32,
                     ==, 0);
    qtest_writeq(qts, mbox + CXL_MAILBOX_REGISTERS_SIZE, 1ULL << 32);
    qtest_writeq(qts, mbox + A_CXL_DEV_MAILBOX_CMD, (8ULL << 16) | 0x4102);
    qtest_writel(qts, mbox + A_CXL_DEV_MAILBOX_CTRL, 1);
    g_assert_cmpuint(qtest_readb(qts, mbox + CXL_MAILBOX_REGISTERS_SIZE),
                     ==, 42);
    g_assert_cmpuint(femu_cxl_stat(qts, "control-command"), ==, 0);
    qtest_writeq(qts, mbox + CXL_MAILBOX_REGISTERS_SIZE, 0);
    qtest_writeq(qts, mbox + A_CXL_DEV_MAILBOX_CMD, (8ULL << 16) | 0x4102);
    qtest_writel(qts, mbox + A_CXL_DEV_MAILBOX_CTRL, 1);
    g_assert_cmpuint(qtest_readq(qts, mbox + A_CXL_DEV_MAILBOX_CMD) >> 16,
                     ==, 0);
    qtest_quit(qts);
}

/*
 * Sanitize disables the media while its background operation runs: reads
 * return no data that was written, writes are dropped, and afterwards the
 * media is enabled again and reads zero.
 */
void femu_test_cxl_sanitize_media(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem");
    uint64_t mbox = 0x90010000 + CXL_MAILBOX_REGISTERS_OFFSET;
    uint64_t sts;

    femu_cxl_decode(qts);
    femu_cxl_config(qts, 53, 0x18, 0x90010000);
    femu_cxl_config(qts, 53, 0x1c, 0);
    qtest_writeq(qts, FEMU_CXL_WINDOW, 0xfeedfacecafef00dULL);
    qtest_writeq(qts, mbox + A_CXL_DEV_MAILBOX_CMD, 0x4400);
    qtest_writel(qts, mbox + A_CXL_DEV_MAILBOX_CTRL, 1);
    sts = qtest_readq(qts, mbox + A_CXL_DEV_MAILBOX_STS);
    /* Background operation started. */
    g_assert_cmphex(sts >> 32 & 0xffff, ==, 0x1);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW), !=,
                    0xfeedfacecafef00dULL);
    qtest_writeq(qts, FEMU_CXL_WINDOW + 8, 0x1234);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW + 8), !=, 0x1234);
    /* 256 MiB sanitize in 4 s of virtual time. */
    qtest_clock_step(qts, 5 * NANOSECONDS_PER_SECOND);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 0);
    qtest_writeq(qts, FEMU_CXL_WINDOW + 8, 0x1234);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW + 8), ==, 0x1234);
    qtest_quit(qts);
}

/*
 * A flush during a sanitize restores no direct ratio, and a der-ratio write
 * is refused: an alias would let accesses reach the media while it is
 * disabled. The first access after the sanitize maps the ratio again.
 */
void femu_test_cxl_sanitize_ratio(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "der=memslot");
    uint64_t mbox = 0x90010000 + CXL_MAILBOX_REGISTERS_OFFSET;

    femu_cxl_decode(qts);
    femu_cxl_config(qts, 53, 0x18, 0x90010000);
    femu_cxl_config(qts, 53, 0x1c, 0);
    femu_cxl_number(qts, "der-ratio", 100, true);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), >, 0);
    qtest_writeq(qts, FEMU_CXL_WINDOW, 0xfeedfacecafef00dULL);
    qtest_writeq(qts, mbox + A_CXL_DEV_MAILBOX_CMD, 0x4400);
    qtest_writel(qts, mbox + A_CXL_DEV_MAILBOX_CTRL, 1);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 0);
    femu_cxl_set(qts, "flush-cache", true);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 0);
    femu_cxl_number(qts, "der-ratio", 100, false);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 0);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW), !=,
                    0xfeedfacecafef00dULL);
    qtest_writeq(qts, FEMU_CXL_WINDOW + 8, 0x1234);
    qtest_clock_step(qts, 5 * NANOSECONDS_PER_SECOND);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW + 8), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-ratio"), ==, 100);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), >, 0);
    qtest_quit(qts);
}

/*
 * The mailbox handler holds the device's re-entrancy guard, so a Get LSA
 * flush must not wait out its media time there; it runs afterwards.
 */
void femu_test_cxl_lsa_queue(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "lsa-control=on,program-ns=20000000");
    uint64_t mbox = 0x90010000 + CXL_MAILBOX_REGISTERS_OFFSET;
    gint64 start;
    unsigned i;

    femu_cxl_decode(qts);
    femu_cxl_config(qts, 53, 0x18, 0x90010000);
    femu_cxl_config(qts, 53, 0x1c, 0);
    for (i = 0; i < 50; i++) {
        qtest_writeq(qts, FEMU_CXL_WINDOW + i * 4096, i);
    }
    /* Writing back 50 dirty pages costs a second of media time. */
    qtest_writel(qts, mbox + CXL_MAILBOX_REGISTERS_SIZE, 0);
    qtest_writel(qts, mbox + CXL_MAILBOX_REGISTERS_SIZE + 4, 2);
    qtest_writeq(qts, mbox + A_CXL_DEV_MAILBOX_CMD, (8ULL << 16) | 0x4102);
    start = g_get_monotonic_time();
    qtest_writel(qts, mbox + A_CXL_DEV_MAILBOX_CTRL, 1);
    g_assert_cmpint(g_get_monotonic_time() - start, <, G_USEC_PER_SEC / 2);
    g_assert_cmpuint(qtest_readb(qts, mbox + CXL_MAILBOX_REGISTERS_SIZE), ==,
                     2);
    femu_cxl_lsa_wait(qts);
    g_assert_cmpuint(femu_cxl_stat(qts, "control-status"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-writes"), >=, 50);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-entries"), ==, 0);
    qtest_quit(qts);
}

void femu_test_cxl_ratio_fallback(void *obj, void *data,
                                        QGuestAllocator *alloc)
{
    static const unsigned ratios[] = {
        50, 75, 90, 95, 97, 98, 99, 100, 995, 999, 0,
    };
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "der=cylon,cylon-kernel-ack=on,ftl=off");
    unsigned i;

    for (i = 0; i < G_N_ELEMENTS(ratios); i++) {
        femu_cxl_number(qts, "der-ratio", ratios[i], true);
        g_assert_cmpuint(femu_cxl_stat(qts, "der-ratio"), ==, ratios[i]);
        g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 0);
    }
    femu_cxl_number(qts, "der-ratio", 1, false);
    femu_cxl_number(qts, "der-ratio", UINT64_MAX, false);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-fallbacks"), ==, 1);
    qtest_quit(qts);
}

void femu_test_cxl_ratio_off(void *obj, void *data,
                                   QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem");

    /* Without DER a ratio could never map anything; refuse it. */
    femu_cxl_number(qts, "der-ratio", 99, false);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-ratio"), ==, 0);
    femu_cxl_number(qts, "der-ratio", 0, true);
    qtest_quit(qts);
}

void femu_test_cxl_ratio_runs(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,der=memslot");

    femu_cxl_decode(qts);
    /* 32768 one-page runs would overflow the dispatch map; map nothing. */
    femu_cxl_number(qts, "der-ratio", 50, false);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-ratio"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 0);
    /* A prefetch inside a mapped run must not add a second alias. */
    femu_cxl_number(qts, "der-ratio", 99, true);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 64880);
    femu_cxl_number(qts, "prefetch-degree", 3, true);
    qtest_readq(qts, FEMU_CXL_WINDOW + 100 * 4096);
    g_assert_cmpuint(femu_cxl_stat(qts, "prefetch-inserts"), ==, 3);
    /* The cached page outside the selection is direct too, as in Cylon. */
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 64881);
    /* Command 90 with argument zero selects every page. */
    femu_cxl_number(qts, "control-argument", 0, true);
    femu_cxl_number(qts, "control-command", 90, true);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-ratio"), ==, 100);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 65536);
    qtest_quit(qts);
}

void femu_test_cxl_der_budget(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,der=memslot,"
        "cache-pages=4096,ftl=off");
    unsigned i;

    femu_cxl_decode(qts);
    /* More cached pages than aliases fit must fall back, not abort QEMU. */
    for (i = 0; i < 2100; i++) {
        qtest_writeq(qts, FEMU_CXL_WINDOW + (uint64_t)i * 2 * 4096, i);
    }
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 1024);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-fallbacks"), >, 0);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW + 2099ULL * 2 * 4096),
                    ==, 2099);
    qtest_quit(qts);
}

/* Cached-hit accesses per second on pages that held no alias at first. */
static double femu_cxl_hit_rate(const char *der, unsigned rate,
                                uint64_t replacements)
{
    QTestState *qts = qtest_initf(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,der=%s,"
        "cache-pages=4096,cache-ways=1,ftl=off,der-replace-rate=%u",
        der, rate);
    gint64 deadline = g_get_monotonic_time() + 30 * G_USEC_PER_SEC;
    size_t len = 64 * 4096;
    g_autofree uint8_t *buf = g_malloc(len);
    uint64_t base = FEMU_CXL_WINDOW + 1100ULL * 4096;
    uint64_t accesses = 0;
    gint64 start;
    gint64 elapsed;
    unsigned i;

    femu_cxl_decode(qts);
    for (i = 0; i < 1164; i++) {
        qtest_writeq(qts, FEMU_CXL_WINDOW + (uint64_t)i * 4096, i);
    }
    if (!strcmp(der, "memslot")) {
        g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 1024);
    }
    /* Let the hot pages displace the oldest aliases before timing. */
    while (femu_cxl_stat(qts, "der-replacements") < replacements) {
        g_assert_cmpint(g_get_monotonic_time(), <, deadline);
        qtest_memread(qts, base, buf, len);
    }
    g_assert_cmpuint(femu_cxl_stat(qts, "der-replacements"), ==,
                     replacements);
    if (!strcmp(der, "memslot")) {
        g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 1024);
    }
    /* One memread is split into 8-byte accesses inside QEMU. */
    start = g_get_monotonic_time();
    do {
        qtest_memread(qts, base, buf, len);
        accesses += len / 8;
        elapsed = g_get_monotonic_time() - start;
    } while (elapsed < G_USEC_PER_SEC / 2);
    g_assert_cmphex(ldq_le_p(buf + 63 * 4096), ==, 1163);
    qtest_quit(qts);
    return accesses * (double)G_USEC_PER_SEC / elapsed;
}

void femu_test_cxl_der_budget_rate(void *obj, void *data,
                                         QGuestAllocator *alloc)
{
    double off = 0;
    double full = 0;
    unsigned i;

    /*
     * Host load only slows a run down, so keep each mode's best of three
     * interleaved runs. A walk of the QOM tree per hit costs ~100x.
     */
    for (i = 0; i < 3; i++) {
        off = MAX(off, femu_cxl_hit_rate("off", 0, 0));
        full = MAX(full, femu_cxl_hit_rate("memslot", 0, 0));
    }
    g_test_message("hits/s: der=off %.0f, der=memslot with full budget %.0f",
                   off, full);
    /* A full budget must not make unmapped hits much slower than MMIO. */
    g_assert_cmpfloat(full, >=, off * 0.25);
}

void femu_test_cxl_der_replace_rate(void *obj, void *data,
                                          QGuestAllocator *alloc)
{
    double full = 0;
    double replaced = 0;
    unsigned i;

    /* Best of three interleaved runs per mode, as for the budget rate. */
    for (i = 0; i < 3; i++) {
        full = MAX(full, femu_cxl_hit_rate("memslot", 0, 0));
        replaced = MAX(replaced, femu_cxl_hit_rate("memslot", 1000, 64));
    }
    g_test_message("hits/s on a new hot set: kept aliases %.0f, "
                   "replaced %.0f", full, replaced);
    /* qtest's own overhead caps the gain, most of all under ASan. */
    g_assert_cmpfloat(replaced, >, full * 1.25);
}

void femu_test_cxl_der_replace(void *obj, void *data,
                                     QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,der=memslot,"
        "cache-pages=4096,ftl=off,der-replace-rate=1000");
    uint64_t hot = FEMU_CXL_WINDOW + 2000ULL * 4096;
    unsigned i;

    femu_cxl_decode(qts);
    for (i = 0; i < 1024; i++) {
        qtest_writeq(qts, FEMU_CXL_WINDOW + (uint64_t)i * 4096, i + 100);
    }
    qtest_writeq(qts, hot, 7);
    /* Occasional misses on the direct path never displace a mapping. */
    for (i = 0; i < 200; i++) {
        g_assert_cmphex(qtest_readq(qts, hot), ==, 7);
    }
    g_assert_cmpuint(femu_cxl_stat(qts, "der-replacements"), ==, 0);
    for (i = 0; i < 100; i++) {
        qtest_readq(qts, hot);
    }
    /* The oldest alias made room; the budget itself never grows. */
    g_assert_cmpuint(femu_cxl_stat(qts, "der-replacements"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 1024);
    /* A store through the new alias survives its revocation... */
    qtest_writeq(qts, hot, 8);
    femu_cxl_set(qts, "flush-cache", true);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 0);
    g_assert_cmphex(qtest_readq(qts, hot), ==, 8);
    /* ...and the displaced page kept what was written through it. */
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 100);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW + 4096), ==, 101);
    qtest_quit(qts);
}

static uint64_t femu_cxl_stat_of(QTestState *qts, const char *id,
                                 const char *name)
{
    g_autofree char *path = g_strdup_printf("/machine/peripheral/%s", id);
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                          "'path':%s,'property':%s}}", path, name);
    uint64_t value = qdict_get_int(rsp, "return");

    qobject_unref(rsp);
    return value;
}

void femu_test_cxl_der_budget_shared(void *obj, void *data,
                                           QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(
        "-machine q35,cxl=on -m 128M "
        "-device pxb-cxl,id=cxl.0,bus=pcie.0,bus_nr=52 "
        "-device pxb-cxl,id=cxl.1,bus=pcie.0,bus_nr=60 "
        "-M cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.size=256M,"
        "cxl-fmw.1.targets.0=cxl.1,cxl-fmw.1.size=256M "
        "-device cxl-rp,id=rp0,bus=cxl.0,chassis=0,slot=0 "
        "-device cxl-rp,id=rp1,bus=cxl.1,chassis=1,slot=0 "
        "-object memory-backend-ram,id=mem,size=256M "
        "-object memory-backend-ram,id=mem1,size=256M "
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,der=memslot,"
        "cache-pages=4096,ftl=off "
        "-device femu-cxl-ssd,id=ssd1,bus=rp1,volatile-memdev=mem1,"
        "der=memslot,cache-pages=4096,ftl=off");
    uint64_t second = FEMU_CXL_WINDOW + 256 * 1024 * 1024;
    unsigned i;

    femu_cxl_decode(qts);
    femu_cxl_decode_at(qts, 60, 0x90100000, second);
    /* Both windows live in one address space and share its section limit. */
    for (i = 0; i < 1100; i++) {
        qtest_writeq(qts, FEMU_CXL_WINDOW + (uint64_t)i * 2 * 4096, i);
        qtest_writeq(qts, second + (uint64_t)i * 2 * 4096, i);
    }
    g_assert_cmpuint(femu_cxl_stat_of(qts, "ssd", "der-mapped") +
                     femu_cxl_stat_of(qts, "ssd1", "der-mapped"), ==, 1024);
    g_assert_cmphex(qtest_readq(qts, second + 1099ULL * 2 * 4096), ==, 1099);
    qtest_quit(qts);
}

void femu_test_cxl_ratio_restore(void *obj, void *data,
                                       QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,der=memslot");

    femu_cxl_decode(qts);
    femu_cxl_number(qts, "der-ratio", 99, true);
    /* Flushing or rebuilding the cache keeps the configured ratio mapped. */
    femu_cxl_set(qts, "flush-cache", true);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-ratio"), ==, 99);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 64880);
    femu_cxl_number(qts, "cache-ways", 8, true);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 64880);
    /* A config write revokes; the next access maps the whole ratio again. */
    femu_cxl_config(qts, 53, PCI_COMMAND, PCI_COMMAND_MEMORY);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 0);
    qtest_readq(qts, FEMU_CXL_WINDOW + 100 * 4096);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-ratio"), ==, 99);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 64881);
    qtest_quit(qts);
}

/*
 * Another device can take the shared alias budget while a ratio is revoked.
 * The ratio must stay configured and map again once there is room.
 */
void femu_test_cxl_ratio_budget(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(
        "-machine q35,cxl=on -m 128M "
        "-device pxb-cxl,id=cxl.0,bus=pcie.0,bus_nr=52 "
        "-device pxb-cxl,id=cxl.1,bus=pcie.0,bus_nr=60 "
        "-M cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.size=256M,"
        "cxl-fmw.1.targets.0=cxl.1,cxl-fmw.1.size=256M "
        "-device cxl-rp,id=rp0,bus=cxl.0,chassis=0,slot=0 "
        "-device cxl-rp,id=rp1,bus=cxl.1,chassis=1,slot=0 "
        "-object memory-backend-ram,id=mem,size=256M "
        "-object memory-backend-ram,id=mem1,size=256M "
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,der=memslot,"
        "ftl=off "
        "-device femu-cxl-ssd,id=ssd1,bus=rp1,volatile-memdev=mem1,"
        "der=memslot,cache-pages=4096,ftl=off");
    uint64_t second = FEMU_CXL_WINDOW + 256 * 1024 * 1024;
    QDict *rsp;
    unsigned i;

    femu_cxl_decode(qts);
    femu_cxl_decode_at(qts, 60, 0x90100000, second);
    femu_cxl_number(qts, "der-ratio", 99, true);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 64880);
    /* A config write revokes the ratio; ssd1 then fills the budget. */
    femu_cxl_config(qts, 53, PCI_COMMAND, PCI_COMMAND_MEMORY);
    for (i = 0; i < 1100; i++) {
        qtest_writeq(qts, second + (uint64_t)i * 4096, i);
    }
    g_assert_cmpuint(femu_cxl_stat_of(qts, "ssd1", "der-mapped"), ==, 1024);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW + 5 * 4096), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-ratio"), ==, 99);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 0);
    rsp = qtest_qmp(qts, "{'execute':'qom-set','arguments':{"
                    "'path':'/machine/peripheral/ssd1',"
                    "'property':'flush-cache','value':true}}");
    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW + 5 * 4096), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), >=, 64880);
    qtest_quit(qts);
}

void femu_test_cxl_lsa_bounds(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "lsa-control=on");
    uint64_t mbox = 0x90010000 + CXL_MAILBOX_REGISTERS_OFFSET;

    femu_cxl_decode(qts);
    femu_cxl_config(qts, 53, 0x18, 0x90010000);
    femu_cxl_config(qts, 53, 0x1c, 0);
    qtest_writeq(qts, mbox + CXL_MAILBOX_REGISTERS_SIZE, 1ULL << 44);
    qtest_writeq(qts, mbox + A_CXL_DEV_MAILBOX_CMD, (8ULL << 16) | 0x4102);
    qtest_writel(qts, mbox + A_CXL_DEV_MAILBOX_CTRL, 1);
    g_assert_cmpuint(qtest_readq(qts, mbox + A_CXL_DEV_MAILBOX_CMD) >> 16,
                     ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "control-status"), ==, 1);
    qtest_quit(qts);
}

void femu_test_cxl_ratio_dirty(void *obj, void *data,
                                     QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,der=memslot");

    femu_cxl_decode(qts);
    qtest_readq(qts, FEMU_CXL_WINDOW + 4092);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-entries"), ==, 2);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), ==, 0);
    femu_cxl_number(qts, "der-ratio", 100, true);
    qtest_writeq(qts, FEMU_CXL_WINDOW, 42);
    femu_cxl_set(qts, "flush-cache", true);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-writes"), ==, 2);
    g_assert_cmpuint(qtest_readq(qts, FEMU_CXL_WINDOW), ==, 42);
    qtest_quit(qts);
}

/* The caching API on BAR5, driven through its rings as a guest would. */
#define FEMU_CCA_BAR    0x90080000ULL
#define FEMU_CCA_SHM    (FEMU_CCA_BAR + CCA_SHM_OFFSET)
#define FEMU_CCA_REQ    (FEMU_CCA_SHM + CCA_REQ_RING_OFFSET)
#define FEMU_CCA_RESP   (FEMU_CCA_SHM + CCA_RESP_RING_OFFSET)
#define FEMU_CCA_SLOTS  (FEMU_CCA_SHM + CCA_SLOT_POOL_OFFSET)
#define FEMU_CCA_DEVICE "-device femu-cxl-ssd,id=ssd,bus=rp0," \
                        "volatile-memdev=mem,cca=on,"

typedef struct FemuCca {
    QTestState *qts;
    uint32_t head;
    uint32_t tail;
    uint32_t slot;
} FemuCca;

typedef struct FemuCcaResp {
    int32_t status;
    uint64_t count;
    uint64_t tag;
    uint64_t resident;
    uint64_t dirty;
    uint64_t pinned;
    uint64_t uncached;
} FemuCcaResp;

static uint32_t femu_cxl_config_read(QTestState *qts, unsigned bus,
                                     unsigned offset)
{
    qtest_outl(qts, 0xcf8, 0x80000000u | (bus << 16) | offset);
    return qtest_inl(qts, 0xcfc);
}

static uint32_t femu_cca_reg(FemuCca *c, unsigned offset)
{
    return qtest_readl(c->qts, FEMU_CCA_BAR + offset);
}

static void femu_cca_wait_status(FemuCca *c, uint32_t mask, uint32_t value)
{
    gint64 deadline = g_get_monotonic_time() + 10 * G_USEC_PER_SEC;

    while ((femu_cca_reg(c, CCA_REG_STATUS) & mask) != value) {
        g_assert_cmpint(g_get_monotonic_time(), <, deadline);
        g_usleep(1000);
    }
}

/* Route the window and BAR5; the rings start empty after realize. */
static void femu_cca_map(FemuCca *c)
{
    femu_cxl_decode(c->qts);
    femu_cxl_config(c->qts, 53, 0x24, FEMU_CCA_BAR);
    femu_cca_wait_status(c, CCA_STATUS_READY, CCA_STATUS_READY);
    c->head = 0;
    c->tail = 0;
}

static void femu_cca_start(FemuCca *c, const char *extra, const char *options)
{
    g_autofree char *args = g_strdup_printf(FEMU_CXL_MACHINE "%s"
                                            FEMU_CCA_DEVICE "%s", extra,
                                            options);

    c->qts = qtest_init(args);
    c->slot = 0;
    femu_cca_map(c);
}

static void femu_cca_post_raw(FemuCca *c, uint32_t slot, uint32_t cmd,
                              uint32_t flags, uint64_t start, uint64_t count,
                              uint64_t rsvd)
{
    uint64_t base = FEMU_CCA_SLOTS + (uint64_t)slot * CCA_SLOT_SIZE;
    unsigned i;

    qtest_writel(c->qts, base, cmd);
    qtest_writel(c->qts, base + 4, flags);
    qtest_writeq(c->qts, base + 8, start);
    qtest_writeq(c->qts, base + 16, count);
    qtest_writeq(c->qts, base + 24, c->head);
    for (i = 0; i < 4; i++) {
        qtest_writeq(c->qts, base + 32 + i * 8, i ? 0 : rsvd);
    }
    qtest_writel(c->qts, FEMU_CCA_REQ + offsetof(struct cca_ring, entries) +
                 (c->head % CCA_RING_COUNT) * 4, slot);
    c->head++;
    qtest_writel(c->qts, FEMU_CCA_REQ + offsetof(struct cca_ring, head),
                 c->head);
}

static void femu_cca_kick(FemuCca *c)
{
    qtest_writel(c->qts, FEMU_CCA_BAR + CCA_REG_DOORBELL, 1);
}

/* Commands run on a device thread in real time, so poll with a deadline. */
static void femu_cca_reap(FemuCca *c, FemuCcaResp *r)
{
    gint64 deadline = g_get_monotonic_time() + 10 * G_USEC_PER_SEC;
    uint64_t base;
    uint32_t slot;

    while (qtest_readl(c->qts, FEMU_CCA_RESP +
                       offsetof(struct cca_ring, head)) == c->tail) {
        g_assert_cmpint(g_get_monotonic_time(), <, deadline);
        g_usleep(1000);
    }
    slot = qtest_readl(c->qts, FEMU_CCA_RESP +
                       offsetof(struct cca_ring, entries) +
                       (c->tail % CCA_RING_COUNT) * 4);
    g_assert_cmpuint(slot, <, CCA_RING_COUNT);
    base = FEMU_CCA_SLOTS + (uint64_t)slot * CCA_SLOT_SIZE + 64;
    r->status = (int32_t)qtest_readl(c->qts, base);
    r->count = qtest_readq(c->qts, base + 16);
    r->tag = qtest_readq(c->qts, base + 24);
    r->resident = qtest_readq(c->qts, base + 32);
    r->dirty = qtest_readq(c->qts, base + 40);
    r->pinned = qtest_readq(c->qts, base + 48);
    r->uncached = qtest_readq(c->qts, base + 56);
    c->tail++;
    qtest_writel(c->qts, FEMU_CCA_RESP + offsetof(struct cca_ring, tail),
                 c->tail);
}

static int femu_cca_raw(FemuCca *c, uint32_t cmd, uint32_t flags,
                        uint64_t start, uint64_t count, uint64_t rsvd,
                        FemuCcaResp *out)
{
    FemuCcaResp r;
    uint64_t tag = c->head;

    femu_cca_post_raw(c, c->slot++ % CCA_RING_COUNT, cmd, flags, start,
                      count, rsvd);
    femu_cca_kick(c);
    femu_cca_reap(c, &r);
    g_assert_cmpuint(r.tag, ==, tag);
    if (out) {
        *out = r;
    }
    return r.status;
}

static int femu_cca_cmd(FemuCca *c, uint32_t cmd, uint32_t flags,
                        uint64_t start, uint64_t count, FemuCcaResp *out)
{
    return femu_cca_raw(c, cmd, flags, start, count, 0, out);
}

/* Expect @status and, when it is 0, @count pages acted on. */
static void femu_cca_expect(FemuCca *c, uint32_t cmd, uint32_t flags,
                            uint64_t start, uint64_t count, int status,
                            uint64_t acted)
{
    FemuCcaResp r;

    g_assert_cmpint(femu_cca_cmd(c, cmd, flags, start, count, &r), ==,
                    status);
    if (!status) {
        g_assert_cmpuint(r.count, ==, acted);
    }
}

static uint64_t femu_cca_page(uint64_t lpn)
{
    return FEMU_CXL_WINDOW + lpn * 4096;
}

static void femu_cca_quit(FemuCca *c)
{
    qtest_quit(c->qts);
}

#define FEMU_STRESS_CPUS  4
#define FEMU_STRESS_ITERS 3000
#define FEMU_STRESS_STRIDE 3

/*
 * Four TCG vCPUs store to and read back their own slot of 16 window pages
 * through a 4-page cache, so misses overlap, victims are held and pages are
 * shared, while the test races an exclusive operation against them. Every
 * store must read back and every slot must hold its last value.
 */
void femu_test_cxl_stress(void *obj, void *data,
                          QGuestAllocator *alloc)
{
    const FemuCxlStress *st = data;
    /* Real mode to protected mode, then setup below; shared by the APs. */
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
    static const uint8_t worker[] = {
        0xb8, 0x10, 0x00, 0x00, 0x00, 0x8e, 0xd8, 0x8e, 0xd0, 0xb8, 0x01, 0x00,
        0x00, 0x00, 0x0f, 0xa2, 0xc1, 0xeb, 0x18, 0x41, 0x89, 0xdf, 0x85, 0xdb,
        0x75, 0x29, 0xbf, 0x00, 0x03, 0xe0, 0xfe, 0xc7, 0x07, 0x00, 0xc5, 0x0c,
        0x00, 0xb9, 0x40, 0x0d, 0x03, 0x00, 0xff, 0xc9, 0x75, 0xfc, 0xc7, 0x07,
        0x07, 0x06, 0x0c, 0x00, 0xb9, 0x40, 0x0d, 0x03, 0x00, 0xff, 0xc9, 0x75,
        0xfc, 0xc7, 0x07, 0x07, 0x06, 0x0c, 0x00, 0x41, 0xc6, 0x87, 0x00, 0x60,
        0x00, 0x00, 0x01, 0x80, 0x3c, 0x25, 0x00, 0x61, 0x00, 0x00, 0x01, 0x75,
        0xf6, 0x4c, 0x8b, 0x34, 0x25, 0x10, 0x61, 0x00, 0x00, 0x4c, 0x8b, 0x1c,
        0x25, 0x18, 0x61, 0x00, 0x00, 0x4c, 0x8b, 0x14, 0x25, 0x08, 0x61, 0x00,
        0x00, 0x4c, 0x8b, 0x24, 0x25, 0x20, 0x61, 0x00, 0x00, 0x4d, 0x31, 0xed,
        0x4c, 0x89, 0xe8, 0x49, 0x0f, 0xaf, 0xc3, 0x4c, 0x89, 0xfa, 0x49, 0x0f,
        0xaf, 0xd2, 0x48, 0x01, 0xd0, 0x48, 0x83, 0xe0, 0x0f, 0x48, 0xc1, 0xe0,
        0x0c, 0x49, 0x8d, 0x3c, 0x04, 0x4a, 0x8d, 0x3c, 0xff, 0x4c, 0x89, 0xeb,
        0x48, 0xc1, 0xe3, 0x08, 0x4c, 0x09, 0xfb, 0x48, 0x89, 0x1f, 0x48, 0x8b,
        0x17, 0x48, 0x39, 0xda, 0x74, 0x08, 0x42, 0xff, 0x04, 0xbd, 0x00, 0x62,
        0x00, 0x00, 0x49, 0xff, 0xc5, 0x4d, 0x39, 0xf5, 0x72, 0xba, 0x41, 0xc6,
        0x87, 0x00, 0x60, 0x00, 0x00, 0x02, 0xf4, 0xeb, 0xfd,
    };
    g_autofree char *rom_path = g_strdup("cxl-stress-rom-XXXXXX");
    g_autofree char *quoted = NULL;
    g_autofree uint8_t *rom = g_malloc0(65536);
    int fd = g_mkstemp(rom_path);
    bool unplug = st->race == FEMU_STRESS_UNPLUG;
    FemuCca cca = { 0 };
    QTestState *qts;
    int64_t deadline;
    uint64_t invalidations;
    unsigned done;
    unsigned round = 0;
    unsigned c;
    unsigned p;
    uint64_t i;

    g_assert_cmpint(fd, >=, 0);
    memcpy(rom, reset, sizeof(reset));
    memcpy(rom + 65520, (uint8_t[]) { 0xea, 0, 0, 0, 0xf0 }, 5);
    g_assert_cmpint(write(fd, rom, 65536), ==, 65536);
    close(fd);
    quoted = g_shell_quote(rom_path);
    qts = qtest_initf(FEMU_CXL_MACHINE
        "-accel tcg,thread=multi -S -bios %s -smp %u %s"
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "cache-pages=4,cache-ways=4,read-ns=20000,program-ns=50000,"
        "concurrent-misses=on%s", quoted, FEMU_STRESS_CPUS,
        unplug ? "-global cxl-rp.power_controller_present=on "
        "-global ICH9-LPC.acpi-pci-hotplug-with-bridge-support=off " : "",
        st->options);
    femu_cxl_decode(qts);
    if (st->race == FEMU_STRESS_CCA) {
        cca.qts = qts;
        femu_cxl_config(qts, 53, 0x24, FEMU_CCA_BAR);
        femu_cca_wait_status(&cca, CCA_STATUS_READY, CCA_STATUS_READY);
    }
    qtest_writew(qts, 0x500, 31);
    qtest_writel(qts, 0x502, 0x508);
    qtest_writeq(qts, 0x508, 0);
    qtest_writeq(qts, 0x510, 0x00cf9a000000ffffULL);
    qtest_writeq(qts, 0x518, 0x00cf92000000ffffULL);
    qtest_writeq(qts, 0x520, 0x00af9a000000ffffULL);
    qtest_memwrite(qts, 0x1000, setup, sizeof(setup));
    qtest_memwrite(qts, 0x1100, worker, sizeof(worker));
    qtest_memwrite(qts, 0x7000, reset, sizeof(reset));
    qtest_writeq(qts, 0x2000, 0x3003);
    qtest_writeq(qts, 0x3000, 0x4003);
    qtest_writeq(qts, 0x3018, 0x8003);
    qtest_writeq(qts, 0x3020, 0x5003);
    qtest_writeq(qts, 0x4000, 0x83);
    qtest_writeq(qts, 0x5400, FEMU_CXL_WINDOW | 0x83);
    qtest_writeq(qts, 0x8fb8, 0xfee00083);
    qtest_writeq(qts, 0x6108, st->spread);
    qtest_writeq(qts, 0x6110, FEMU_STRESS_ITERS);
    qtest_writeq(qts, 0x6118, FEMU_STRESS_STRIDE);
    qtest_writeq(qts, 0x6120, FEMU_CXL_WINDOW);
    qtest_qmp_assert_success(qts, "{'execute':'cont'}");
    deadline = g_get_monotonic_time() + 60 * G_TIME_SPAN_SECOND;
    for (c = 0; c < FEMU_STRESS_CPUS; c++) {
        while (qtest_readb(qts, 0x6000 + c) != 1) {
            g_assert_cmpint(g_get_monotonic_time(), <, deadline);
            g_usleep(1000);
        }
    }
    invalidations = femu_cxl_stat(qts, "invalidations");
    qtest_writeb(qts, 0x6100, 1);
    do {
        switch (st->race) {
        case FEMU_STRESS_FLUSH:
            femu_cxl_set(qts, "flush-cache", true);
            break;
        case FEMU_STRESS_INVALIDATE:
            femu_cxl_config(qts, 53, PCI_COMMAND, PCI_COMMAND_MEMORY);
            break;
        case FEMU_STRESS_WAYS:
            femu_cxl_number(qts, "cache-ways", round % 2 ? 4 : 2, true);
            break;
        case FEMU_STRESS_CCA:
            /* Pin a page the CPUs never use, then drop theirs. */
            femu_cca_expect(&cca, round % 2 ? CCA_CTRL_UNPIN : CCA_CTRL_PIN,
                            0, 20, 1, 0, 1);
            femu_cca_cmd(&cca, CCA_CTRL_INVALIDATE, 0, 0, 16, NULL);
            break;
        case FEMU_STRESS_UNPLUG:
            if (round == 20) {
                femu_cxl_unplug(qts);
            }
            break;
        }
        round++;
        g_usleep(2000);
        done = 0;
        for (c = 0; c < FEMU_STRESS_CPUS; c++) {
            done += qtest_readb(qts, 0x6000 + c) == 2;
        }
        g_assert_cmpint(g_get_monotonic_time(), <, deadline);
    } while (done < FEMU_STRESS_CPUS);
    if (unplug) {
        /* The device is gone; QEMU must have survived its last accesses. */
        g_assert_cmpuint(round, >, 20);
        qtest_quit(qts);
        unlink(rom_path);
        return;
    }
    for (c = 0; c < FEMU_STRESS_CPUS; c++) {
        g_assert_cmpuint(qtest_readl(qts, 0x6200 + 4 * c), ==, 0);
    }
    /* The last store of each CPU to each page it used must be there. */
    for (c = 0; c < FEMU_STRESS_CPUS; c++) {
        for (p = 0; p < 16; p++) {
            uint64_t want = UINT64_MAX;

            for (i = 0; i < FEMU_STRESS_ITERS; i++) {
                if ((i * FEMU_STRESS_STRIDE + c * st->spread) % 16 == p) {
                    want = i << 8 | c;
                }
            }
            if (want != UINT64_MAX) {
                g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW +
                                            p * 4096 + c * 8), ==, want);
            }
        }
    }
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-evictions"), >, 0);
    if (st->race == FEMU_STRESS_INVALIDATE) {
        g_assert_cmpuint(femu_cxl_stat(qts, "invalidations"), >,
                         invalidations);
    }
    qtest_quit(qts);
    unlink(rom_path);
}

void femu_test_cca_off(void *obj, void *data, QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem");
    FemuCca c;

    femu_cxl_decode(qts);
    femu_cxl_config(qts, 53, 0x24, 0xffffffff);
    g_assert_cmphex(femu_cxl_config_read(qts, 53, 0x24), ==, 0);
    g_assert_cmpuint(femu_cxl_mtree_count(qts, "femu-cxl-cca"), ==, 0);
    qtest_quit(qts);

    /* The same probe sees a 512 KiB 32-bit memory BAR when enabled. */
    femu_cca_start(&c, "", "");
    femu_cxl_config(c.qts, 53, 0x24, 0xffffffff);
    g_assert_cmphex(femu_cxl_config_read(c.qts, 53, 0x24), ==,
                    (uint32_t)~(CCA_BAR_SIZE - 1));
    femu_cca_quit(&c);
}

void femu_test_cca_layout(void *obj, void *data,
                          QGuestAllocator *alloc)
{
    FemuCca c;

    femu_cca_start(&c, "", "cache-pages=4,cache-ways=2");
    g_assert_cmphex(femu_cca_reg(&c, CCA_REG_MAGIC), ==, CCA_SHMEM_MAGIC);
    g_assert_cmpuint(femu_cca_reg(&c, CCA_REG_VERSION), ==, 2);
    g_assert_cmphex(femu_cca_reg(&c, CCA_REG_STATUS), ==,
                    CCA_STATUS_READY | CCA_STATUS_CACHE);
    g_assert_cmpuint(qtest_readq(c.qts, FEMU_CCA_BAR + CCA_REG_MEDIA_PAGES),
                     ==, 256 * 256);
    g_assert_cmpuint(femu_cca_reg(&c, CCA_REG_CACHE_PAGES), ==, 4);
    g_assert_cmpuint(femu_cca_reg(&c, CCA_REG_CACHE_WAYS), ==, 2);
    g_assert_cmpuint(femu_cca_reg(&c, CCA_REG_PIN_LIMIT), ==, 2);
    g_assert_cmpuint(qtest_readq(c.qts, FEMU_CCA_BAR + CCA_REG_COMPLETED),
                     ==, 0);
    /* Other widths read as zero. */
    g_assert_cmpuint(qtest_readw(c.qts, FEMU_CCA_BAR + CCA_REG_MAGIC), ==, 0);
    g_assert_cmphex(qtest_readl(c.qts, FEMU_CCA_SHM), ==, CCA_SHMEM_MAGIC);
    g_assert_cmpuint(qtest_readl(c.qts, FEMU_CCA_SHM + 4), ==, 2);
    g_assert_cmpuint(qtest_readl(c.qts, FEMU_CCA_SHM + 8), ==,
                     CCA_RING_COUNT);
    g_assert_cmpuint(qtest_readl(c.qts, FEMU_CCA_SHM + 12), ==, 128);
    g_assert_cmphex(qtest_readq(c.qts, FEMU_CCA_SHM + 16), ==, 0x100);
    g_assert_cmphex(qtest_readq(c.qts, FEMU_CCA_SHM + 24), ==, 0x2200);
    g_assert_cmphex(qtest_readq(c.qts, FEMU_CCA_SHM + 32), ==, 0x5000);
    for (unsigned off = 40; off < 80; off += 8) {
        g_assert_cmpuint(qtest_readq(c.qts, FEMU_CCA_SHM + off), ==, 0);
    }
    femu_cca_quit(&c);
}

/* Slot 0 must complete; cylon-v9.0.1 dropped it as a NULL entry. */
void femu_test_cca_nop(void *obj, void *data, QGuestAllocator *alloc)
{
    FemuCca c;
    FemuCcaResp r;
    unsigned batch;
    unsigned i;

    femu_cca_start(&c, "", "cache-pages=4,cache-ways=2");
    c.slot = 0;
    femu_cca_expect(&c, CCA_CTRL_NOP, 0, 0, 0, 0, 0);
    c.slot = CCA_RING_COUNT - 1;
    femu_cca_expect(&c, CCA_CTRL_NOP, 0, 0, 0, 0, 0);
    for (batch = 0; batch < 3; batch++) {
        uint64_t first = c.head;

        for (i = 0; i < 1000; i++) {
            femu_cca_post_raw(&c, (batch * 1000 + i) % CCA_RING_COUNT,
                              CCA_CTRL_NOP, 0, 0, 0, 0);
        }
        femu_cca_kick(&c);
        for (i = 0; i < 1000; i++) {
            femu_cca_reap(&c, &r);
            g_assert_cmpint(r.status, ==, 0);
            g_assert_cmpuint(r.tag, ==, first + i);
        }
    }
    g_assert_cmpuint(qtest_readq(c.qts, FEMU_CCA_BAR + CCA_REG_COMPLETED),
                     ==, 3002);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-commands"), ==, 3002);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-errors"), ==, 0);
    femu_cca_quit(&c);
}

void femu_test_cca_pin(void *obj, void *data, QGuestAllocator *alloc)
{
    FemuCca c;
    uint64_t writes;
    uint64_t misses;
    uint64_t reads;
    unsigned lpn;

    femu_cca_start(&c, "", "cache-pages=4,cache-ways=2");
    qtest_writeq(c.qts, femu_cca_page(0), 0xa0);
    writes = femu_cxl_stat(c.qts, "media-writes");
    femu_cca_expect(&c, CCA_CTRL_PIN, 0, 0, 1, 0, 1);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-pinned"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-pin-fills"), ==, 0);
    /* Stream the rest of set 0 past it. */
    for (lpn = 2; lpn <= 8; lpn += 2) {
        qtest_readq(c.qts, femu_cca_page(lpn));
    }
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cache-entries"), ==, 2);
    misses = femu_cxl_stat(c.qts, "read-misses");
    g_assert_cmphex(qtest_readq(c.qts, femu_cca_page(0)), ==, 0xa0);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "read-misses"), ==, misses);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "media-writes"), ==, writes);
    /* Pinning a page that is not resident fills it like a miss would. */
    reads = femu_cxl_stat(c.qts, "media-reads");
    femu_cca_expect(&c, CCA_CTRL_PIN, 0, 1, 1, 0, 1);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-pin-fills"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "media-reads"), ==, reads + 1);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "read-misses"), ==, misses);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-pinned"), ==, 2);
    /* Pinning again counts the page as acted on and changes nothing. */
    femu_cca_expect(&c, CCA_CTRL_PIN, 0, 0, 2, 0, 2);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-pinned"), ==, 2);
    femu_cca_quit(&c);
}

void femu_test_cca_budget(void *obj, void *data,
                          QGuestAllocator *alloc)
{
    FemuCca c;
    FemuCcaResp r;
    uint64_t entries;
    uint64_t reads;
    uint64_t writes;

    femu_cca_start(&c, "", "cache-pages=4,cache-ways=2");
    femu_cca_expect(&c, CCA_CTRL_PIN, 0, 0, 1, 0, 1);
    femu_cca_expect(&c, CCA_CTRL_PIN, 0, 2, 1, 0, 1);
    entries = femu_cxl_stat(c.qts, "cache-entries");
    femu_cca_expect(&c, CCA_CTRL_PIN, 0, 4, 1, -ENOSPC, 0);
    /* All or nothing: page 5 has room in set 1 but is not pinned either. */
    femu_cca_expect(&c, CCA_CTRL_PIN, 0, 4, 3, -ENOSPC, 0);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-pinned"), ==, 2);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cache-entries"), ==, entries);
    g_assert_cmpint(femu_cca_cmd(&c, CCA_CTRL_QUERY, 0, 5, 1, &r), ==, 0);
    g_assert_cmpuint(r.resident, ==, 0);

    /* Misses to a fully pinned set are served from the media, uncached. */
    writes = femu_cxl_stat(c.qts, "media-writes");
    qtest_writeq(c.qts, femu_cca_page(4), 0x44);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "media-writes"), ==, writes + 1);
    reads = femu_cxl_stat(c.qts, "media-reads");
    g_assert_cmphex(qtest_readq(c.qts, femu_cca_page(4)), ==, 0x44);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "media-reads"), ==, reads + 1);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-pinned-set-misses"), ==, 2);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cache-entries"), ==, entries);
    femu_cca_quit(&c);

    femu_cca_start(&c, "", "cache-pages=0");
    femu_cca_expect(&c, CCA_CTRL_PIN, 0, 0, 1, -EOPNOTSUPP, 0);
    femu_cca_expect(&c, CCA_CTRL_UNPIN, 0, 0, 1, -EOPNOTSUPP, 0);
    femu_cca_expect(&c, CCA_CTRL_INVALIDATE, 0, 0, 1, 0, 0);
    g_assert_cmpuint(femu_cca_reg(&c, CCA_REG_PIN_LIMIT), ==, 0);
    femu_cca_quit(&c);

    /* Direct mapped: the one way of a set can be pinned. */
    femu_cca_start(&c, "", "cache-pages=4,cache-ways=1");
    g_assert_cmpuint(femu_cca_reg(&c, CCA_REG_PIN_LIMIT), ==, 1);
    femu_cca_expect(&c, CCA_CTRL_PIN, 0, 0, 1, 0, 1);
    femu_cca_expect(&c, CCA_CTRL_PIN, 0, 4, 1, -ENOSPC, 0);
    femu_cca_expect(&c, CCA_CTRL_PIN, 0, 1, 3, 0, 3);
    femu_cca_quit(&c);
}

void femu_test_cca_unpin(void *obj, void *data,
                         QGuestAllocator *alloc)
{
    FemuCca c;
    uint64_t writes;
    unsigned lpn;

    femu_cca_start(&c, "", "cache-pages=4,cache-ways=2");
    qtest_writeq(c.qts, femu_cca_page(0), 0xb0);
    femu_cca_expect(&c, CCA_CTRL_PIN, 0, 0, 1, 0, 1);
    femu_cca_expect(&c, CCA_CTRL_UNPIN, 0, 0, 1, 0, 1);
    femu_cca_expect(&c, CCA_CTRL_UNPIN, 0, 0, 1, 0, 0);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-pinned"), ==, 0);
    writes = femu_cxl_stat(c.qts, "media-writes");
    for (lpn = 2; lpn <= 8; lpn += 2) {
        qtest_readq(c.qts, femu_cca_page(lpn));
    }
    /* Still dirty after unpinning, so its eviction programs it. */
    g_assert_cmpuint(femu_cxl_stat(c.qts, "media-writes"), ==, writes + 1);
    g_assert_cmphex(qtest_readq(c.qts, femu_cca_page(0)), ==, 0xb0);
    femu_cca_quit(&c);
}

void femu_test_cca_invalidate(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    FemuCca c;
    uint64_t writes;
    uint64_t ns;
    uint64_t misses;
    uint64_t dropped;

    femu_cca_start(&c, "", "cache-pages=4,cache-ways=2");
    qtest_writeq(c.qts, femu_cca_page(0), 0x70);
    qtest_writeq(c.qts, femu_cca_page(1), 0x71);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cache-entries"), ==, 2);
    writes = femu_cxl_stat(c.qts, "media-writes");
    ns = femu_cxl_stat(c.qts, "media-time-ns");
    misses = femu_cxl_stat(c.qts, "read-misses");
    femu_cca_expect(&c, CCA_CTRL_INVALIDATE, 0, 0, 2, 0, 2);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "media-writes"), ==, writes + 2);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "media-time-ns"), >=, ns + 400000);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cache-entries"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-writebacks"), ==, 2);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-dropped"), ==, 2);
    g_assert_cmphex(qtest_readq(c.qts, femu_cca_page(0)), ==, 0x70);
    g_assert_cmphex(qtest_readq(c.qts, femu_cca_page(1)), ==, 0x71);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "read-misses"), ==, misses + 2);

    /* Clean pages are dropped without a program. */
    writes = femu_cxl_stat(c.qts, "media-writes");
    dropped = femu_cxl_stat(c.qts, "cca-dropped");
    femu_cca_expect(&c, CCA_CTRL_INVALIDATE, CCA_F_ALL, 0, 0, 0, 2);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "media-writes"), ==, writes);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-dropped"), ==, dropped + 2);

    /* Pinned pages need FORCE, which unpins and writes them back. */
    qtest_writeq(c.qts, femu_cca_page(0), 0x72);
    femu_cca_expect(&c, CCA_CTRL_PIN, 0, 0, 1, 0, 1);
    writes = femu_cxl_stat(c.qts, "media-writes");
    femu_cca_expect(&c, CCA_CTRL_INVALIDATE, 0, 0, 1, -EBUSY, 0);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-pinned"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cache-entries"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "media-writes"), ==, writes);
    femu_cca_expect(&c, CCA_CTRL_INVALIDATE, CCA_F_FORCE, 0, 1, 0, 1);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-pinned"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cache-entries"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "media-writes"), ==, writes + 1);
    femu_cca_quit(&c);
}

/*
 * A miss on a programmed page costs one NAND read and waits for it in real
 * time. The read is long enough that the qtest round trip cannot hide it.
 */
void femu_test_cca_miss_time(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    FemuCca c;
    uint64_t reads;
    uint64_t media;
    int64_t took;

    femu_cca_start(&c, "", "read-ns=5000000");
    qtest_writeq(c.qts, femu_cca_page(1), 0xd1);
    femu_cxl_set(c.qts, "flush-cache", true);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "media-writes"), ==, 1);
    g_assert_cmphex(qtest_readq(c.qts, femu_cca_page(1)), ==, 0xd1);
    femu_cca_expect(&c, CCA_CTRL_INVALIDATE, 0, 1, 1, 0, 1);
    reads = femu_cxl_stat(c.qts, "media-reads");
    media = femu_cxl_stat(c.qts, "media-time-ns");
    took = g_get_monotonic_time();
    g_assert_cmphex(qtest_readq(c.qts, femu_cca_page(1)), ==, 0xd1);
    took = g_get_monotonic_time() - took;
    g_assert_cmpuint(femu_cxl_stat(c.qts, "media-reads"), ==, reads + 1);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "media-time-ns"), ==,
                     media + 5000000);
    g_assert_cmpint(took, >=, 5000000 / 1000 * 8 / 10);
    femu_cca_quit(&c);
}

void femu_test_cca_uncached(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    FemuCca c;
    uint64_t reads;
    uint64_t writes;
    uint64_t misses;
    uint64_t inserts;
    unsigned i;

    femu_cca_start(&c, "", "cache-pages=4,cache-ways=2");
    qtest_writeq(c.qts, femu_cca_page(0), 0xc0);
    writes = femu_cxl_stat(c.qts, "media-writes");
    femu_cca_expect(&c, CCA_CTRL_CACHE_DISABLE, 0, 0, 1, 0, 1);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "media-writes"), ==, writes + 1);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cache-entries"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-uncached"), ==, 1);
    reads = femu_cxl_stat(c.qts, "media-reads");
    misses = femu_cxl_stat(c.qts, "read-misses");
    inserts = femu_cxl_stat(c.qts, "cache-inserts");
    for (i = 0; i < 3; i++) {
        g_assert_cmphex(qtest_readq(c.qts, femu_cca_page(0)), ==, 0xc0);
    }
    g_assert_cmpuint(femu_cxl_stat(c.qts, "media-reads"), ==, reads + 3);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "read-misses"), ==, misses + 3);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cache-entries"), ==, 0);
    writes = femu_cxl_stat(c.qts, "media-writes");
    qtest_writeq(c.qts, femu_cca_page(0), 0xc1);
    qtest_writeq(c.qts, femu_cca_page(0), 0xc2);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "media-writes"), ==, writes + 2);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cache-inserts"), ==, inserts);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-pinned-set-misses"), ==, 0);
    femu_cca_expect(&c, CCA_CTRL_CACHE_DISABLE, 0, 0, 1, 0, 0);
    femu_cca_expect(&c, CCA_CTRL_PIN, 0, 0, 1, -EBUSY, 0);
    femu_cca_expect(&c, CCA_CTRL_CACHE_ENABLE, 0, 0, 2, 0, 1);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-uncached"), ==, 0);
    g_assert_cmphex(qtest_readq(c.qts, femu_cca_page(0)), ==, 0xc2);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cache-inserts"), ==, inserts + 1);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cache-entries"), ==, 1);
    femu_cca_quit(&c);
}

void femu_test_cca_prefetch(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    FemuCca c;
    FemuCcaResp r;

    femu_cca_start(&c, "", "cache-pages=4,cache-ways=2,prefetch-degree=2");
    femu_cca_expect(&c, CCA_CTRL_CACHE_DISABLE, 0, 1, 1, 0, 1);
    qtest_readq(c.qts, femu_cca_page(0));
    g_assert_cmpuint(femu_cxl_stat(c.qts, "prefetch-inserts"), ==, 1);
    g_assert_cmpint(femu_cca_cmd(&c, CCA_CTRL_QUERY, 0, 0, 3, &r), ==, 0);
    g_assert_cmpuint(r.resident, ==, 2);
    g_assert_cmpuint(r.uncached, ==, 1);
    g_assert_cmpint(femu_cca_cmd(&c, CCA_CTRL_QUERY, 0, 1, 1, &r), ==, 0);
    g_assert_cmpuint(r.resident, ==, 0);
    femu_cca_quit(&c);
}

void femu_test_cca_flush(void *obj, void *data,
                         QGuestAllocator *alloc)
{
    FemuCca c;
    uint64_t writes;
    uint64_t misses;

    femu_cca_start(&c, "", "cache-pages=4,cache-ways=2");
    qtest_writeq(c.qts, femu_cca_page(0), 0xd0);
    femu_cca_expect(&c, CCA_CTRL_PIN, 0, 0, 1, 0, 1);
    writes = femu_cxl_stat(c.qts, "media-writes");
    femu_cxl_set(c.qts, "flush-cache", true);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "media-writes"), ==, writes + 1);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-pinned"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cache-entries"), ==, 1);
    misses = femu_cxl_stat(c.qts, "read-misses");
    g_assert_cmphex(qtest_readq(c.qts, femu_cca_page(0)), ==, 0xd0);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "read-misses"), ==, misses);
    /* A clean pinned page is not programmed again. */
    femu_cxl_set(c.qts, "flush-cache", true);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "media-writes"), ==, writes + 1);
    /* Cylon's buffer clear (command 2) keeps pins the same way. */
    qtest_writeq(c.qts, femu_cca_page(0), 0xd1);
    femu_cxl_command(c.qts, false, 2, 0);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "media-writes"), ==, writes + 2);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-pinned"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cache-entries"), ==, 1);
    femu_cca_quit(&c);
}

void femu_test_cca_ways(void *obj, void *data, QGuestAllocator *alloc)
{
    FemuCca c;
    uint64_t writes;
    uint64_t misses;

    femu_cca_start(&c, "", "cache-pages=4,cache-ways=4");
    qtest_writeq(c.qts, femu_cca_page(0), 0xe0);
    qtest_readq(c.qts, femu_cca_page(4));
    femu_cca_expect(&c, CCA_CTRL_PIN, 0, 0, 1, 0, 1);
    femu_cca_expect(&c, CCA_CTRL_PIN, 0, 4, 1, 0, 1);
    /* Four direct-mapped sets would put both pins in set 0: refused. */
    writes = femu_cxl_stat(c.qts, "media-writes");
    femu_cxl_number(c.qts, "cache-ways", 1, false);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cache-ways"), ==, 4);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-pinned"), ==, 2);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cache-entries"), ==, 2);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "media-writes"), ==, writes);
    /* Two ways fit both; the dirty pin is written back, then kept. */
    femu_cxl_number(c.qts, "cache-ways", 2, true);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-pinned"), ==, 2);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cache-entries"), ==, 2);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "media-writes"), ==, writes + 1);
    g_assert_cmpuint(femu_cca_reg(&c, CCA_REG_CACHE_WAYS), ==, 2);
    misses = femu_cxl_stat(c.qts, "read-misses");
    g_assert_cmphex(qtest_readq(c.qts, femu_cca_page(0)), ==, 0xe0);
    qtest_readq(c.qts, femu_cca_page(4));
    g_assert_cmpuint(femu_cxl_stat(c.qts, "read-misses"), ==, misses);
    femu_cca_expect(&c, CCA_CTRL_PIN, 0, 2, 1, -ENOSPC, 0);
    femu_cca_quit(&c);
}

void femu_test_cca_ratio(void *obj, void *data,
                         QGuestAllocator *alloc)
{
    FemuCca c;
    QDict *rsp;

    femu_cca_start(&c, "", "cache-pages=4,cache-ways=2,der=memslot");
    femu_cxl_number(c.qts, "der-ratio", 100, true);
    femu_cca_expect(&c, CCA_CTRL_CACHE_DISABLE, 0, 0, 1, -EBUSY, 0);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-uncached"), ==, 0);
    femu_cxl_number(c.qts, "der-ratio", 0, true);
    femu_cca_expect(&c, CCA_CTRL_CACHE_DISABLE, 0, 0, 1, 0, 1);
    rsp = qtest_qmp(c.qts, "{'execute':'qom-set','arguments':{"
                    "'path':'/machine/peripheral/ssd',"
                    "'property':'der-ratio','value':100}}");
    g_assert_true(qdict_haskey(rsp, "error"));
    g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                        "desc"), "uncached"));
    qobject_unref(rsp);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "der-ratio"), ==, 0);
    femu_cca_expect(&c, CCA_CTRL_CACHE_ENABLE, CCA_F_ALL, 0, 0, 0, 1);
    femu_cxl_number(c.qts, "der-ratio", 100, true);
    femu_cca_quit(&c);
}

void femu_test_cca_query(void *obj, void *data,
                         QGuestAllocator *alloc)
{
    FemuCca c;
    FemuCcaResp r;
    unsigned all;

    femu_cca_start(&c, "", "cache-pages=4,cache-ways=2");
    qtest_writeq(c.qts, femu_cca_page(0), 1);
    qtest_readq(c.qts, femu_cca_page(1));
    femu_cca_expect(&c, CCA_CTRL_PIN, 0, 1, 1, 0, 1);
    femu_cca_expect(&c, CCA_CTRL_CACHE_DISABLE, 0, 3, 1, 0, 1);
    for (all = 0; all < 2; all++) {
        g_assert_cmpint(femu_cca_cmd(&c, CCA_CTRL_QUERY,
                                     all ? CCA_F_ALL : 0, 0, all ? 0 : 4,
                                     &r), ==, 0);
        g_assert_cmpuint(r.count, ==, all ? 256 * 256 : 4);
        g_assert_cmpuint(r.resident, ==,
                         femu_cxl_stat(c.qts, "cache-entries"));
        g_assert_cmpuint(r.resident, ==, 2);
        g_assert_cmpuint(r.dirty, ==, 1);
        g_assert_cmpuint(r.pinned, ==, femu_cxl_stat(c.qts, "cca-pinned"));
        g_assert_cmpuint(r.pinned, ==, 1);
        g_assert_cmpuint(r.uncached, ==,
                         femu_cxl_stat(c.qts, "cca-uncached"));
        g_assert_cmpuint(r.uncached, ==, 1);
    }
    femu_cca_quit(&c);
}

static void femu_cca_expect_fatal(FemuCca *c, uint32_t reason)
{
    femu_cca_kick(c);
    femu_cca_wait_status(c, CCA_STATUS_FATAL, CCA_STATUS_FATAL);
    g_assert_cmpuint(femu_cca_reg(c, CCA_REG_FATAL_REASON), ==, reason);
    /* Doorbells do nothing until RESET. */
    femu_cca_kick(c);
    qtest_writel(c->qts, FEMU_CCA_BAR + CCA_REG_RESET, CCA_RESET_RINGS);
    g_assert_cmphex(femu_cca_reg(c, CCA_REG_STATUS) & CCA_STATUS_FATAL, ==, 0);
    femu_cca_wait_status(c, CCA_STATUS_READY, CCA_STATUS_READY);
    g_assert_cmpuint(femu_cca_reg(c, CCA_REG_FATAL_REASON), ==, 0);
    c->head = 0;
    c->tail = 0;
    femu_cca_expect(c, CCA_CTRL_NOP, 0, 0, 0, 0, 0);
    g_assert_cmpuint(qtest_readq(c->qts, FEMU_CCA_BAR + CCA_REG_COMPLETED),
                     ==, 1);
}

void femu_test_cca_errors(void *obj, void *data,
                          QGuestAllocator *alloc)
{
    FemuCca c;
    uint64_t pages = 256 * 256;
    uint32_t i;

    femu_cca_start(&c, "", "cache-pages=4,cache-ways=2");
    g_assert_cmpint(femu_cca_cmd(&c, CCA_CTRL_MAX, 0, 0, 1, NULL), ==,
                    -EINVAL);
    g_assert_cmpint(femu_cca_cmd(&c, CCA_CTRL_PIN, 1u << 5, 0, 1, NULL), ==,
                    -EINVAL);
    g_assert_cmpint(femu_cca_cmd(&c, CCA_CTRL_PIN, CCA_F_FORCE, 0, 1, NULL),
                    ==, -EINVAL);
    g_assert_cmpint(femu_cca_cmd(&c, CCA_CTRL_NOP, CCA_F_ALL, 0, 0, NULL), ==,
                    -EINVAL);
    g_assert_cmpint(femu_cca_raw(&c, CCA_CTRL_QUERY, 0, 0, 1, 1, NULL), ==,
                    -EINVAL);
    g_assert_cmpint(femu_cca_cmd(&c, CCA_CTRL_QUERY, CCA_F_ALL, 1, 0, NULL),
                    ==, -EINVAL);
    g_assert_cmpint(femu_cca_cmd(&c, CCA_CTRL_QUERY, 0, 0, 0, NULL), ==,
                    -EINVAL);
    g_assert_cmpint(femu_cca_cmd(&c, CCA_CTRL_QUERY, 0, pages, 1, NULL), ==,
                    -ERANGE);
    g_assert_cmpint(femu_cca_cmd(&c, CCA_CTRL_QUERY, 0, pages - 1, 2, NULL),
                    ==, -ERANGE);
    g_assert_cmpint(femu_cca_cmd(&c, CCA_CTRL_QUERY, 0, 1, UINT64_MAX, NULL),
                    ==, -ERANGE);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-errors"), ==, 10);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-commands"), ==, 10);

    /* A head beyond the ring, a slot beyond the pool, a full response ring. */
    qtest_writel(c.qts, FEMU_CCA_REQ + offsetof(struct cca_ring, head),
                 c.head + CCA_RING_COUNT + 1);
    femu_cca_expect_fatal(&c, CCA_FATAL_RING);
    qtest_writel(c.qts, FEMU_CCA_REQ + offsetof(struct cca_ring, entries) +
                 (c.head % CCA_RING_COUNT) * 4, 0xffffffff);
    qtest_writel(c.qts, FEMU_CCA_REQ + offsetof(struct cca_ring, head),
                 c.head + 1);
    femu_cca_expect_fatal(&c, CCA_FATAL_SLOT);
    /* Every response unreaped, then one more request. */
    for (i = 0; i < CCA_RING_COUNT; i++) {
        femu_cca_post_raw(&c, i, CCA_CTRL_NOP, 0, 0, 0, 0);
    }
    femu_cca_kick(&c);
    {
        gint64 deadline = g_get_monotonic_time() + 10 * G_USEC_PER_SEC;

        while (qtest_readl(c.qts, FEMU_CCA_RESP +
                           offsetof(struct cca_ring, head)) - c.tail !=
               CCA_RING_COUNT) {
            g_assert_cmpint(g_get_monotonic_time(), <, deadline);
            g_usleep(1000);
        }
    }
    femu_cca_post_raw(&c, 0, CCA_CTRL_NOP, 0, 0, 0, 0);
    femu_cca_expect_fatal(&c, CCA_FATAL_RESPONSE);
    femu_cca_quit(&c);
}

static void femu_cca_poll_stat(QTestState *qts, const char *name,
                               uint64_t value)
{
    gint64 deadline = g_get_monotonic_time() + 10 * G_USEC_PER_SEC;

    while (femu_cxl_stat(qts, name) != value) {
        g_assert_cmpint(g_get_monotonic_time(), <, deadline);
        g_usleep(1000);
    }
}

void femu_test_cca_reset(void *obj, void *data,
                         QGuestAllocator *alloc)
{
    FemuCca c;
    uint64_t entries;
    uint32_t epoch;

    femu_cca_start(&c, "", "cache-pages=4,cache-ways=2");
    qtest_writeq(c.qts, femu_cca_page(0), 0xf0);
    femu_cca_expect(&c, CCA_CTRL_PIN, 0, 0, 1, 0, 1);
    femu_cca_expect(&c, CCA_CTRL_CACHE_DISABLE, 0, 3, 1, 0, 1);
    entries = femu_cxl_stat(c.qts, "cache-entries");
    epoch = femu_cca_reg(&c, CCA_REG_EPOCH);
    qtest_qmp_assert_success(c.qts, "{'execute':'system_reset'}");
    qtest_qmp_eventwait(c.qts, "RESET");
    femu_cca_poll_stat(c.qts, "cca-pinned", 0);
    femu_cca_poll_stat(c.qts, "cca-uncached", 0);
    /* Reset keeps cached contents; only CCA state goes. */
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cache-entries"), ==, entries);
    femu_cca_map(&c);
    g_assert_cmpuint(femu_cca_reg(&c, CCA_REG_EPOCH), ==, epoch + 1);
    /* Slots are cleared too, so stale ones would run as NOPs. */
    g_assert_cmpuint(qtest_readl(c.qts, FEMU_CCA_SLOTS), ==, 0);
    g_assert_cmpuint(qtest_readq(c.qts, FEMU_CCA_SLOTS + 8), ==, 0);
    g_assert_cmpuint(qtest_readl(c.qts, FEMU_CCA_REQ), ==, 0);
    g_assert_cmpuint(qtest_readl(c.qts, FEMU_CCA_RESP), ==, 0);
    g_assert_cmpuint(qtest_readq(c.qts, FEMU_CCA_BAR + CCA_REG_COMPLETED),
                     ==, 0);
    femu_cca_expect(&c, CCA_CTRL_NOP, 0, 0, 0, 0, 0);
    femu_cca_expect(&c, CCA_CTRL_UNPIN, CCA_F_ALL, 0, 0, 0, 0);
    g_assert_cmphex(qtest_readq(c.qts, femu_cca_page(0)), ==, 0xf0);
    femu_cca_quit(&c);
}

void femu_test_cca_der(void *obj, void *data, QGuestAllocator *alloc)
{
    FemuCca c;
    uint64_t revocations;

    femu_cca_start(&c, "", "cache-pages=4,cache-ways=2,der=memslot");
    qtest_writeq(c.qts, femu_cca_page(0), 0x18);
    femu_cca_expect(&c, CCA_CTRL_PIN, 0, 0, 1, 0, 1);
    g_assert_cmphex(qtest_readq(c.qts, femu_cca_page(0)), ==, 0x18);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "der-mapped"), ==, 1);
    revocations = femu_cxl_stat(c.qts, "der-revocations");
    femu_cca_expect(&c, CCA_CTRL_INVALIDATE, CCA_F_FORCE, 0, 1, 0, 1);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "der-mapped"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "der-revocations"), ==,
                     revocations + 1);
    /* Memslot pages are conservatively dirty, so it was programmed. */
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-writebacks"), ==, 1);
    g_assert_cmphex(qtest_readq(c.qts, femu_cca_page(0)), ==, 0x18);
    femu_cca_quit(&c);
}

/* Count this QEMU's threads named @name; needs -name debug-threads=on. */
static unsigned femu_cca_threads(QTestState *qts, const char *name)
{
    g_autofree char *dir = g_strdup_printf("/proc/%d/task", qtest_pid(qts));
    GDir *tasks = g_dir_open(dir, 0, NULL);
    const char *task;
    unsigned count = 0;

    g_assert_nonnull(tasks);
    while ((task = g_dir_read_name(tasks))) {
        g_autofree char *path = g_strdup_printf("%s/%s/comm", dir, task);
        g_autofree char *comm = NULL;

        if (g_file_get_contents(path, &comm, NULL, NULL) &&
            g_str_has_prefix(comm, name)) {
            count++;
        }
    }
    g_dir_close(tasks);
    return count;
}

/*
 * Unplug while a command sleeps through a minute of modeled programs:
 * device_del must not wait, and the thread must still finish promptly
 * and release the media.
 */
void femu_test_cca_unplug(void *obj, void *data,
                          QGuestAllocator *alloc)
{
    FemuCca c;
    gint64 start;
    gint64 deadline;
    unsigned lpn;

    femu_cca_start(&c, "-name debug-threads=on "
                   "-global cxl-rp.power_controller_present=on "
                   "-global ICH9-LPC.acpi-pci-hotplug-with-bridge-support=off ",
                   "cache-pages=64,cache-ways=64,program-ns=1000000000");
    for (lpn = 0; lpn < 64; lpn++) {
        qtest_writeq(c.qts, femu_cca_page(lpn), lpn);
    }
    femu_cca_post_raw(&c, 0, CCA_CTRL_INVALIDATE, CCA_F_ALL, 0, 0, 0);
    femu_cca_kick(&c);
    /* All 64 programs are charged before the chunk's delay begins. */
    femu_cca_poll_stat(c.qts, "cca-writebacks", 64);
    g_assert_cmpuint(femu_cca_reg(&c, CCA_REG_STATUS) & CCA_STATUS_BUSY, ==,
                     CCA_STATUS_BUSY);
    g_assert_cmpuint(femu_cca_threads(c.qts, "femu-cxl-cca"), ==, 1);
    g_assert_cmpuint(femu_cca_threads(c.qts, "femu-cxl-ftl"), ==, 1);
    start = g_get_monotonic_time();
    femu_cxl_unplug(c.qts);
    g_assert_cmpint(g_get_monotonic_time() - start, <, 5 * G_USEC_PER_SEC);
    deadline = start + 5 * G_USEC_PER_SEC;
    while (femu_cca_threads(c.qts, "femu-cxl-cca") ||
           femu_cca_threads(c.qts, "femu-cxl-ftl")) {
        g_assert_cmpint(g_get_monotonic_time(), <, deadline);
        g_usleep(10000);
    }
    femu_cca_quit(&c);
}

/*
 * An access that queues behind a long command runs between its chunks,
 * not after the whole command.
 */
void femu_test_cca_interleave(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    FemuCca c;
    FemuCcaResp r;
    unsigned lpn;

    femu_cca_start(&c, "", "cache-pages=1024,cache-ways=1024,"
                   "program-ns=500000");
    for (lpn = 0; lpn < 512; lpn++) {
        qtest_writeq(c.qts, femu_cca_page(lpn), lpn);
    }
    femu_cca_post_raw(&c, 0, CCA_CTRL_INVALIDATE, CCA_F_ALL, 0, 0, 0);
    femu_cca_kick(&c);
    /* The first chunk has charged its programs and is waiting them out. */
    femu_cca_poll_stat(c.qts, "cca-writebacks", 256);
    g_assert_cmphex(qtest_readq(c.qts, femu_cca_page(700)), ==, 0);
    /* The second chunk's media time has not passed yet. */
    g_assert_cmpuint(qtest_readl(c.qts, FEMU_CCA_RESP), ==, 0);
    femu_cca_reap(&c, &r);
    g_assert_cmpint(r.status, ==, 0);
    g_assert_cmpuint(r.count, ==, 512);
    femu_cca_quit(&c);
}

/*
 * A rings reset abandons CACHE_DISABLE after its first chunk. The pages it
 * never reached are still resident, so they must not stay uncached.
 */
void femu_test_cca_disable_abandon(void *obj, void *data,
                                   QGuestAllocator *alloc)
{
    uint64_t pages = 256 * 256;
    uint64_t reads;
    FemuCca c;
    FemuCcaResp r;
    unsigned lpn;

    femu_cca_start(&c, "", "cache-pages=1024,cache-ways=1024,"
                   "program-ns=500000");
    for (lpn = 0; lpn < 512; lpn++) {
        qtest_writeq(c.qts, femu_cca_page(lpn), lpn);
    }
    femu_cca_post_raw(&c, 0, CCA_CTRL_CACHE_DISABLE, CCA_F_ALL, 0, 0, 0);
    femu_cca_kick(&c);
    femu_cca_poll_stat(c.qts, "cca-writebacks", 256);
    qtest_writel(c.qts, FEMU_CCA_BAR + CCA_REG_RESET, CCA_RESET_RINGS);
    femu_cca_wait_status(&c, CCA_STATUS_READY, CCA_STATUS_READY);
    c.head = 0;
    c.tail = 0;
    g_assert_cmpint(femu_cca_cmd(&c, CCA_CTRL_QUERY, CCA_F_ALL, 0, 0, &r), ==,
                    0);
    g_assert_cmpuint(r.resident, ==, 256);
    g_assert_cmpuint(r.uncached, ==, pages - 256);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-uncached"), ==, pages - 256);
    reads = femu_cxl_stat(c.qts, "media-reads");
    g_assert_cmphex(qtest_readq(c.qts, femu_cca_page(300)), ==, 300);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "media-reads"), ==, reads);
    femu_cca_quit(&c);
}

/* Replacement displaces the oldest alias of a page that is not pinned. */
void femu_test_cca_der_replace(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    uint64_t hot = FEMU_CXL_WINDOW + 2000ULL * 4096;
    const char *mtree;
    QDict *rsp;
    FemuCca c;
    unsigned i;

    femu_cca_start(&c, "", "der=memslot,cache-pages=4096,ftl=off,"
                   "der-replace-rate=1000");
    for (i = 0; i < 1024; i++) {
        qtest_writeq(c.qts, femu_cca_page(i), i + 100);
    }
    g_assert_cmpuint(femu_cxl_stat(c.qts, "der-mapped"), ==, 1024);
    femu_cca_expect(&c, CCA_CTRL_PIN, 0, 0, 1, 0, 1);
    qtest_writeq(c.qts, hot, 7);
    for (i = 0; i < 300; i++) {
        g_assert_cmphex(qtest_readq(c.qts, hot), ==, 7);
    }
    g_assert_cmpuint(femu_cxl_stat(c.qts, "der-replacements"), ==, 1);
    rsp = qtest_qmp(c.qts, "{'execute':'human-monitor-command',"
                    "'arguments':{'command-line':'info mtree'}}");
    mtree = qdict_get_str(rsp, "return");
    g_assert_nonnull(strstr(mtree, "femu-cxl-hit-0 @"));
    g_assert_null(strstr(mtree, "femu-cxl-hit-1 @"));
    qobject_unref(rsp);
    femu_cca_quit(&c);
}

/*
 * A Get LSA command that finds the guard held by a sleeping CCA chunk is
 * queued rather than waited for inside the mailbox handler.
 */
void femu_test_cca_lsa_busy(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    uint64_t mbox = 0x90010000 + CXL_MAILBOX_REGISTERS_OFFSET;
    FemuCca c;
    FemuCcaResp r;
    gint64 start;
    unsigned lpn;

    femu_cca_start(&c, "", "lsa-control=on,cache-pages=1024,"
                   "cache-ways=1024,program-ns=2000000");
    femu_cxl_config(c.qts, 53, 0x18, 0x90010000);
    femu_cxl_config(c.qts, 53, 0x1c, 0);
    for (lpn = 0; lpn < 512; lpn++) {
        qtest_writeq(c.qts, femu_cca_page(lpn), lpn);
    }
    femu_cca_post_raw(&c, 0, CCA_CTRL_INVALIDATE, CCA_F_ALL, 0, 0, 0);
    femu_cca_kick(&c);
    /* The first chunk now sleeps for half a second holding the guard. */
    femu_cca_poll_stat(c.qts, "cca-writebacks", 256);
    qtest_writel(c.qts, mbox + CXL_MAILBOX_REGISTERS_SIZE, 0);
    qtest_writel(c.qts, mbox + CXL_MAILBOX_REGISTERS_SIZE + 4, 1);
    qtest_writeq(c.qts, mbox + A_CXL_DEV_MAILBOX_CMD, (8ULL << 16) | 0x4102);
    start = g_get_monotonic_time();
    qtest_writel(c.qts, mbox + A_CXL_DEV_MAILBOX_CTRL, 1);
    g_assert_cmpint(g_get_monotonic_time() - start, <, G_USEC_PER_SEC / 5);
    g_assert_cmpuint(qtest_readb(c.qts, mbox + CXL_MAILBOX_REGISTERS_SIZE),
                     ==, 2);
    femu_cxl_lsa_wait(c.qts);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "control-status"), ==, 0);
    femu_cca_reap(&c, &r);
    g_assert_cmpint(r.status, ==, 0);
    femu_cca_quit(&c);
}

/*
 * A command with no media cost that revokes a full alias budget must not
 * hold the BQL for all of it: every other device and vCPU waits on it.
 */
void femu_test_cca_bql(void *obj, void *data, QGuestAllocator *alloc)
{
    gint64 worst = 0;
    gint64 start;
    FemuCca c;
    FemuCcaResp r;
    unsigned lpn;

    femu_cca_start(&c, "", "der=memslot,cache-pages=4096,ftl=off");
    for (lpn = 0; lpn < 1024; lpn++) {
        qtest_writeq(c.qts, femu_cca_page(lpn), lpn);
    }
    g_assert_cmpuint(femu_cxl_stat(c.qts, "der-mapped"), ==, 1024);
    start = g_get_monotonic_time();
    femu_cca_post_raw(&c, 0, CCA_CTRL_INVALIDATE, CCA_F_ALL, 0, 0, 0);
    femu_cca_kick(&c);
    for (;;) {
        gint64 t = g_get_monotonic_time();
        bool done = qtest_readl(c.qts, FEMU_CCA_RESP) != 0;

        worst = MAX(worst, g_get_monotonic_time() - t);
        if (done) {
            break;
        }
    }
    g_test_message("invalidate %" G_GINT64_FORMAT " us, longest ring "
                   "poll %" G_GINT64_FORMAT " us",
                   g_get_monotonic_time() - start, worst);
    femu_cca_reap(&c, &r);
    g_assert_cmpint(r.status, ==, 0);
    g_assert_cmpuint(r.count, ==, 1024);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "der-mapped"), ==, 0);
    g_assert_cmpint(worst, <, G_USEC_PER_SEC / 10);
    femu_cca_quit(&c);
}

static void femu_cxl_set_u64(QTestState *qts, const char *name,
                             uint64_t value)
{
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-set','arguments':{"
                          "'path':'/machine/peripheral/ssd',"
                          "'property':%s,'value':%" PRIu64 "}}", name, value);

    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
}

/*
 * A Cylon fill that cannot keep its page charges no media read: the page
 * goes to the emulator, which charges each access. With one way, protect
 * the only resident page; then also take the victim at the point where a
 * media wait would drop the BQL. Each failed fill must leave media-reads,
 * read-misses and the cache as they were; a later fill charges once.
 */
void femu_test_cxl_fill_charge(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "cache-pages=1,cache-ways=1,prefetch-degree=0");

    femu_cxl_decode(qts);
    femu_cxl_set_u64(qts, "test-fill", 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-reads"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(qts, "read-misses"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-entries"), ==, 1);
    /* No victim when the fill starts. */
    femu_cxl_set_u64(qts, "test-protect", 0);
    femu_cxl_set_u64(qts, "test-fill", 4096);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-reads"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(qts, "read-misses"), ==, 1);
    femu_cxl_set_u64(qts, "test-unprotect", 0);
    /* The victim goes while the fill runs. */
    femu_cxl_set(qts, "test-fill-race", true);
    femu_cxl_set_u64(qts, "test-fill", 4096);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-reads"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(qts, "read-misses"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-entries"), ==, 1);
    femu_cxl_set_u64(qts, "test-unprotect", 0);
    femu_cxl_set_u64(qts, "test-fill", 4096);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-reads"), ==, 2);
    g_assert_cmpuint(femu_cxl_stat(qts, "read-misses"), ==, 2);
    qtest_quit(qts);
}

/* Whether a fill of test-owner may revoke @lpn ahead of its eviction. */
static bool femu_cxl_ahead_ok(QTestState *qts, const char *name, uint64_t lpn)
{
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-set','arguments':{"
                           "'path':'/machine/peripheral/ssd',"
                           "'property':%s,'value':%" PRIu64 "}}", name, lpn);
    bool ok = qdict_haskey(rsp, "return");

    qobject_unref(rsp);
    return ok;
}

/*
 * A batched revocation takes a page ahead of its eviction only where the
 * eviction itself could take it now. A protection of another vCPU binds only
 * within the protection window, and the vCPU's own protections only bind a
 * refault fill. A vCPU keeps up to 64 records while it loops at one RIP, so
 * honouring every record would keep most of the cache out of each batch.
 */
void femu_test_cxl_revoke_ahead(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "cache-pages=16,cache-ways=16,prefetch-degree=0");

    femu_cxl_decode(qts);
    femu_cxl_set_u64(qts, "test-protect-window", 10ULL * 1000 * 1000 * 1000);
    femu_cxl_set_u64(qts, "test-owner", 0);
    femu_cxl_set_u64(qts, "test-protect", 5);
    g_assert_true(femu_cxl_ahead_ok(qts, "test-revoke-ahead", 5));
    g_assert_false(femu_cxl_ahead_ok(qts, "test-revoke-ahead-keep", 5));
    g_assert_true(femu_cxl_ahead_ok(qts, "test-revoke-ahead-keep", 6));
    femu_cxl_set_u64(qts, "test-owner", 1);
    g_assert_false(femu_cxl_ahead_ok(qts, "test-revoke-ahead", 5));
    g_assert_true(femu_cxl_ahead_ok(qts, "test-revoke-ahead", 6));
    /* The record stays after the window; it no longer binds vCPU 1. */
    femu_cxl_set_u64(qts, "test-protect-window", 0);
    g_assert_true(femu_cxl_ahead_ok(qts, "test-revoke-ahead", 5));
    g_assert_true(femu_cxl_ahead_ok(qts, "test-revoke-ahead-keep", 5));
    qtest_quit(qts);
}

/*
 * Working-set protection belongs to the vCPU that faulted (test-owner plays
 * the vCPU). A page that vCPU 0 protected for its last instruction must not
 * stop vCPU 1 from filling a page of the same set once the protection
 * window has passed: a refused fill hands the page to the emulator, and with
 * one way every emulated store to it then misses and is charged as an
 * uncached program. Within the window another vCPU's fill waits instead of
 * giving up, and the owner's own fills always pass over its pages.
 */
void femu_test_cxl_fill_owner(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "cache-pages=1,cache-ways=1,prefetch-degree=0");
    uint64_t writes;
    unsigned i;

    femu_cxl_decode(qts);
    /* Every protection is stale at once. */
    femu_cxl_set_u64(qts, "test-protect-window", 0);
    femu_cxl_set_u64(qts, "test-owner", 0);
    femu_cxl_set_u64(qts, "test-fill", 0);
    femu_cxl_set_u64(qts, "test-protect", 0);
    femu_cxl_set_u64(qts, "test-owner", 1);
    femu_cxl_set_u64(qts, "test-fill", 4096);
    g_assert_cmpuint(femu_cxl_stat(qts, "read-misses"), ==, 2);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-reads"), ==, 2);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-entries"), ==, 1);
    /* The guest's stores to the filled page hit and charge nothing. */
    writes = femu_cxl_stat(qts, "media-writes");
    for (i = 0; i < 4096 / 8; i++) {
        qtest_writeq(qts, FEMU_CXL_WINDOW + 4096 + i * 8, i);
    }
    g_assert_cmpuint(femu_cxl_stat(qts, "write-misses"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-writes"), ==, writes);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-reads"), ==, 2);
    /* vCPU 1 protects its page; its own next fill in the set is refused. */
    femu_cxl_set_u64(qts, "test-protect", 1);
    femu_cxl_set_u64(qts, "test-fill", 8192);
    g_assert_cmpuint(femu_cxl_stat(qts, "read-misses"), ==, 2);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-reads"), ==, 2);
    /*
     * A fault of vCPU 2 within a window longer than the 100 ms wait bound
     * keeps nothing and charges nothing.
     */
    femu_cxl_set_u64(qts, "test-protect-window", 10ULL * 1000 * 1000 * 1000);
    femu_cxl_set_u64(qts, "test-owner", 2);
    femu_cxl_set_u64(qts, "test-fault-fill", FEMU_CXL_WINDOW + 8192);
    g_assert_cmpuint(femu_cxl_stat(qts, "read-misses"), ==, 2);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-reads"), ==, 2);
    /* Within a 20 ms window it waits for the expiry, then fills once. */
    femu_cxl_set_u64(qts, "test-protect-window", 20 * 1000 * 1000);
    femu_cxl_set_u64(qts, "test-owner", 1);
    femu_cxl_set_u64(qts, "test-protect", 1);
    femu_cxl_set_u64(qts, "test-owner", 2);
    femu_cxl_set_u64(qts, "test-fault-fill", FEMU_CXL_WINDOW + 8192);
    g_assert_cmpuint(femu_cxl_stat(qts, "read-misses"), ==, 3);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-reads"), ==, 3);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-entries"), ==, 1);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW + 4096 + 8), ==, 1);
    qtest_quit(qts);
}

static QTestState *femu_cxl_fault_init(unsigned ways)
{
    g_autofree char *dev = g_strdup_printf(
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "cache-pages=%u,cache-ways=%u,cache-policy=lifo,prefetch-degree=0,"
        "cylon-fault-stop=1000", 2 * ways, ways);
    g_autofree char *args = g_strconcat(FEMU_CXL_MACHINE, "-smp 2 ", dev,
                                        NULL);
    QTestState *qts = qtest_init(args);

    femu_cxl_decode(qts);
    femu_cxl_set(qts, "test-map", true);
    femu_cxl_set_u64(qts, "test-owner", 0);
    return qts;
}

static void femu_cxl_fault(QTestState *qts, const char *kind, uint64_t page)
{
    femu_cxl_set_u64(qts, kind, FEMU_CXL_WINDOW + page * 4096);
}

/*
 * One instruction whose pages conflict in the cache: @ways + 1 pages of one
 * set (the even pages; two sets), faulted in turn at one RIP, as a rep movsb
 * page copy whose source and destination share a 1-way set does, after many
 * exits at that RIP. A page that the vCPU faults on again must not refill
 * and evict another page of the instruction: it maps outside the cache for
 * the instruction, and never goes to the emulator, whose MMIO entry an
 * event delivery or a guest page walk could not pass. Before the fix the
 * pages evicted each other on every exit, until 1,000 refills at one RIP
 * (100,000 on a VM) stopped it. The rounds run past both progress budgets
 * (1,000 exits).
 */
static void femu_cxl_pingpong(unsigned ways)
{
    QTestState *qts = femu_cxl_fault_init(ways);
    unsigned round;
    unsigned i;

    for (i = 0; i < 70; i++) {
        femu_cxl_fault(qts, "test-fault", 2 * i + 1);
    }
    for (round = 0; round < 1100 / (ways + 1) + 1; round++) {
        for (i = 0; i <= ways; i++) {
            femu_cxl_fault(qts, "test-fault", 2 * i);
        }
    }
    g_assert_cmpuint(femu_cxl_stat(qts, "der-fault-conflicts"), >=,
                     1100 / (ways + 1));
    g_assert_cmpuint(femu_cxl_stat(qts, "der-fault-overflows"), >=,
                     femu_cxl_stat(qts, "der-fault-conflicts"));
    g_assert_cmpuint(femu_cxl_stat(qts, "der-fault-emulated"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-fault-marker-refused"), ==, 0);
    qtest_quit(qts);
}

/*
 * The defect that ended a VM on d760: a guest page-table page and the data
 * page that the instruction writes share a 1-way set. The walk's refault
 * found the set held by the instruction's own page, and the conflict
 * fallback marked the page-table page for emulation; the marker became an
 * MMIO SPTE, and the next timer interrupt walked it: KVM refuses an EPT
 * misconfiguration during event delivery. The walk, an event delivery, and
 * a data access must each map outside the cache, never mark.
 */
void femu_test_cxl_walk_conflict(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    static const char *const kinds[] = {
        "test-fault-walk", "test-fault-delivery", "test-fault",
    };
    unsigned i;

    for (i = 0; i < ARRAY_SIZE(kinds); i++) {
        QTestState *qts = femu_cxl_fault_init(1);

        /* Page 2: the page table; page 0: the instruction's data page. */
        femu_cxl_fault(qts, kinds[i], 2);
        femu_cxl_fault(qts, "test-fault", 0);
        femu_cxl_fault(qts, kinds[i], 2);
        g_assert_cmpuint(femu_cxl_stat(qts, "der-fault-conflicts"), ==, 1);
        g_assert_cmpuint(femu_cxl_stat(qts, "der-fault-overflows"), ==, 1);
        g_assert_cmpuint(femu_cxl_stat(qts, "der-fault-emulated"), ==, 0);
        g_assert_cmpuint(femu_cxl_stat(qts, "der-fault-forced"), ==, 0);
        g_assert_cmpuint(femu_cxl_stat(qts, "der-fault-marker-refused"),
                         ==, 0);
        g_assert_cmpuint(femu_cxl_stat(qts, "der-fault-page-walks"), ==,
                         i == 0 ? 2 : 0);
        g_assert_cmpuint(femu_cxl_stat(qts, "der-fault-deliveries"), ==,
                         i == 1 ? 2 : 0);
        /* The data page stays resident: a hit. */
        femu_cxl_fault(qts, "test-fault", 0);
        g_assert_cmpuint(femu_cxl_stat(qts, "der-fault-overflows"), ==, 1);
        qtest_quit(qts);
    }
}

/*
 * An instruction at one RIP that needs more overflow pages than a vCPU
 * keeps (64) releases its own pages in a cycle: each mapping is served,
 * but the instruction never completes, and cylon-fault-stop (1,000 here)
 * must stop it. A cycle that fits stays mapped on a VM; here its refaults
 * find their pages still held and never stop.
 */
void femu_test_cxl_overflow_cycle(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    static const unsigned sizes[] = { 60, 70 };
    unsigned k;

    for (k = 0; k < ARRAY_SIZE(sizes); k++) {
        QTestState *qts = femu_cxl_fault_init(1);
        bool stopped = false;
        unsigned round;
        unsigned i;

        for (round = 0; round < 40 && !stopped; round++) {
            for (i = 0; i < sizes[k] && !stopped; i++) {
                QDict *rsp = qtest_qmp(qts,
                    "{'execute':'qom-set','arguments':{"
                    "'path':'/machine/peripheral/ssd',"
                    "'property':'test-fault','value':%" PRIu64 "}}",
                    (uint64_t)FEMU_CXL_WINDOW + 2 * i * 4096);

                stopped = qdict_haskey(rsp, "error");
                qobject_unref(rsp);
            }
        }
        g_assert_cmpuint(femu_cxl_stat(qts, "der-fault-emulated"), ==, 0);
        if (k) {
            g_assert_true(stopped);
            g_assert_cmpuint(femu_cxl_stat(qts, "der-fault-overflows"), >,
                             64);
        } else {
            g_assert_false(stopped);
        }
        qtest_quit(qts);
    }
}

/*
 * Version 2 marks for emulation only a data access to a page that the
 * caching API keeps uncached. A guest page walk or an event delivery on
 * such a page maps it outside the cache for the instruction (der-fault-
 * forced), charged as one read; nothing else is ever marked.
 */
void femu_test_cxl_uncached_walk(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    FemuCca c;
    uint64_t reads;

    femu_cca_start(&c, "-smp 2 ", "cache-pages=4,cache-ways=1,"
                   "cache-policy=lifo,prefetch-degree=0,"
                   "cylon-fault-stop=1000");
    femu_cxl_set(c.qts, "test-map", true);
    femu_cxl_set_u64(c.qts, "test-owner", 0);
    g_assert_cmpint(femu_cca_cmd(&c, CCA_CTRL_CACHE_DISABLE, 0, 0, 3, NULL),
                    ==, 0);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-uncached"), ==, 3);
    femu_cxl_fault(c.qts, "test-fault", 0);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "der-fault-emulated"), ==, 1);
    reads = femu_cxl_stat(c.qts, "media-reads");
    femu_cxl_fault(c.qts, "test-fault-walk", 1);
    femu_cxl_fault(c.qts, "test-fault-delivery", 2);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "der-fault-forced"), ==, 2);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "der-fault-overflows"), ==, 2);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "media-reads"), ==, reads + 2);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "der-fault-emulated"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "der-fault-marker-refused"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cache-entries"), ==, 0);
    femu_cca_quit(&c);
}

/*
 * The same with an instruction the emulator cannot decode: the page that
 * does not fit maps outside the cache, charged as one fill, and the
 * instruction's other pages stay resident.
 */
void femu_test_cxl_overflow(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QTestState *qts = femu_cxl_fault_init(1);
    uint64_t misses;

    femu_cxl_fault(qts, "test-fault", 0);
    femu_cxl_fault(qts, "test-fault", 2);
    misses = femu_cxl_stat(qts, "read-misses");
    femu_cxl_fault(qts, "test-fault-decode", 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-fault-overflows"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(qts, "read-misses"), ==, misses + 1);
    /* Page 2 is still resident: a hit. */
    femu_cxl_fault(qts, "test-fault", 2);
    g_assert_cmpuint(femu_cxl_stat(qts, "read-misses"), ==, misses + 1);
    /* A new RIP releases the overflow page; the next fill is ordinary. */
    femu_cxl_set_u64(qts, "test-rip", 0x2000);
    femu_cxl_fault(qts, "test-fault", 4);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-fault-overflows"), ==, 1);
    qtest_quit(qts);
}

/*
 * Healthy loops at one RIP must not look like a conflict. A loop of
 * undecodable loads over distinct pages of one 1-way set needs one page per
 * instruction: each fill evicts the previous page and nothing overflows.
 * A scalar loop over A, B, C of one set, then A and C alternately, is
 * served by fills and emulator handoffs and never exhausts a budget; nor do
 * two vCPUs that evict each other's page.
 */
void femu_test_cxl_one_rip_loops(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    QTestState *qts = femu_cxl_fault_init(1);
    unsigned i;

    for (i = 0; i < 40; i++) {
        femu_cxl_fault(qts, "test-fault-decode", 2 * i);
    }
    g_assert_cmpuint(femu_cxl_stat(qts, "der-fault-overflows"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-fault-conflicts"), ==, 0);
    femu_cxl_set_u64(qts, "test-rip", 0x3000);
    femu_cxl_fault(qts, "test-fault", 100);
    femu_cxl_fault(qts, "test-fault", 102);
    femu_cxl_fault(qts, "test-fault", 104);
    for (i = 0; i < 1500; i++) {
        femu_cxl_fault(qts, "test-fault", i % 2 ? 104 : 100);
    }
    /*
     * Two vCPUs, each loading its own page of one set at its own RIP, evict
     * each other's page once the other's protection has expired: each
     * refault refills, which is progress, not the ping-pong of one
     * instruction, and must not reach the repeat bound.
     */
    femu_cxl_set_u64(qts, "test-protect-window", 0);
    for (i = 0; i < 2200; i++) {
        femu_cxl_set_u64(qts, "test-owner", i % 2);
        femu_cxl_set_u64(qts, "test-rip", i % 2 ? 0x5000 : 0x4000);
        femu_cxl_fault(qts, "test-fault", i % 2 ? 202 : 200);
    }
    qtest_quit(qts);
}

/*
 * cylon-fault-stop: exits of one vCPU at one RIP on a page it already
 * filled for that RIP stop the VM at that many repeats; with 0 they only
 * warn, from 1000 repeats, also past the default bound of 100,000.
 */
void femu_test_cxl_fault_stop(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    g_autofree char *log = g_strdup("cxl-fault-stop-XXXXXX");
    g_autofree char *quoted = NULL;
    g_autofree char *args = NULL;
    g_autofree char *text = NULL;
    int fd = g_mkstemp(log);
    QTestState *qts;
    QDict *rsp;
    unsigned i;

    g_assert_cmpint(fd, >=, 0);
    close(fd);
    quoted = g_shell_quote(log);
    for (i = 0; i < 2; i++) {
        args = g_strdup_printf(FEMU_CXL_MACHINE "-smp 2 "
            "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
            "cache-pages=2,cache-ways=1,prefetch-degree=0,"
            "cylon-fault-stop=%u 2>%s", i ? 0 : 3, quoted);
        qts = qtest_init(args);
        g_clear_pointer(&args, g_free);
        femu_cxl_decode(qts);
        femu_cxl_set(qts, "test-map", true);
        femu_cxl_set_u64(qts, "test-owner", 0);
        if (!i) {
            /* The fill, then three repeats: the third stops. */
            femu_cxl_fault(qts, "test-fault-decode", 0);
            femu_cxl_fault(qts, "test-fault-decode", 0);
            femu_cxl_fault(qts, "test-fault-decode", 0);
            rsp = qtest_qmp(qts, "{'execute':'qom-set','arguments':{"
                            "'path':'/machine/peripheral/ssd',"
                            "'property':'test-fault-decode','value':%"
                            PRIu64 "}}", (uint64_t)FEMU_CXL_WINDOW);
            g_assert_true(qdict_haskey(rsp, "error"));
            qobject_unref(rsp);
            g_assert_cmpuint(femu_cxl_stat(qts, "der-emul-failures"), ==, 1);
        } else {
            femu_cxl_set_u64(qts, "test-fault-repeats", 100100);
            femu_cxl_fault(qts, "test-fault-decode", 0);
            g_assert_cmpuint(femu_cxl_stat(qts, "der-emul-failures"), ==, 0);
        }
        qtest_quit(qts);
        g_assert_true(g_file_get_contents(log, &text, NULL, NULL));
        if (!i) {
            g_assert_nonnull(strstr(text, "3 consecutive exits"));
        } else {
            /* At most one a second. */
            g_assert_cmpuint(femu_cxl_count(text, "the VM does not stop"),
                             >=, 1);
            g_assert_null(strstr(text, "retry budget exhausted"));
        }
        g_clear_pointer(&text, g_free);
    }
    unlink(log);
}

void femu_test_cxl_pingpong_1(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    femu_cxl_pingpong(1);
}

void femu_test_cxl_pingpong_2(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    femu_cxl_pingpong(2);
}

void femu_test_cxl_pingpong_4(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    femu_cxl_pingpong(4);
}

/*
 * Fault exits served without the BQL, as KVM sends them, from @threads
 * vCPUs at once: test-storm runs the real service in threads that act as
 * vCPUs. Misses overlap in the guard, as with Cylon. One set of 64 ways over
 * 128 pages, so fills evict each other, refault, protect, conflict and hand
 * pages to the emulator, while this thread reads and writes the window
 * through MMIO (the BQL path).
 */
static QTestState *femu_cxl_storm_init(const char *extra)
{
    g_autofree char *args = g_strdup_printf(FEMU_CXL_MACHINE "-smp 8 "
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "cache-pages=64,cache-ways=64,prefetch-degree=0,read-ns=2000,"
        "program-ns=4000,concurrent-misses=on%s", extra);
    QTestState *qts = qtest_init(args);

    femu_cxl_decode(qts);
    femu_cxl_set(qts, "test-map", true);
    return qts;
}

static void femu_cxl_storm(QTestState *qts, unsigned threads,
                           unsigned pages, unsigned iters, unsigned mode)
{
    g_autofree char *spec = g_strdup_printf("%u,%u,%u,%u,7", threads, pages,
                                            iters, mode);
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-set','arguments':{"
                          "'path':'/machine/peripheral/ssd',"
                          "'property':'test-storm','value':%s}}", spec);

    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
}

/* Join the storm; the device's shared bookkeeping must add up. */
static void femu_cxl_storm_wait(QTestState *qts, const char *id)
{
    g_autofree char *path = g_strdup_printf("/machine/peripheral/%s", id);
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-set','arguments':{"
                          "'path':%s,'property':'test-storm-wait',"
                          "'value':true}}", path);

    if (qdict_haskey(rsp, "error")) {
        g_test_message("%s", qdict_get_str(qdict_get_qdict(rsp, "error"),
                                          "desc"));
    }
    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
}

void femu_test_cxl_storm_set(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QTestState *qts = femu_cxl_storm_init("");
    uint64_t misses;
    unsigned i;

    femu_cxl_storm(qts, 8, 128, 4000, 0);
    /* Version 1 accesses take the BQL, then the CXL lock, meanwhile. */
    for (i = 0; i < 2000; i++) {
        uint64_t gpa = FEMU_CXL_WINDOW + (i * 37 % 128) * 4096 + 8;

        if (i % 2) {
            qtest_writeq(qts, gpa, i);
        } else {
            qtest_readq(qts, gpa);
        }
        if (i == 1000) {
            femu_cxl_set(qts, "flush-cache", true);
        }
        /* Counters that the faults update, read meanwhile. */
        if (i % 100 == 0) {
            femu_cxl_stat(qts, "read-misses");
        }
    }
    femu_cxl_storm_wait(qts, "ssd");
    g_assert_cmpuint(femu_cxl_stat(qts, "test-storm-served"), ==, 8 * 4000);
    g_assert_cmpuint(femu_cxl_stat(qts, "test-storm-stops"), ==, 0);
    misses = femu_cxl_stat(qts, "read-misses") +
             femu_cxl_stat(qts, "write-misses");
    g_assert_cmpuint(misses, >, 1000);
    /* Every miss read the media once; no counter update was lost. */
    g_assert_cmpuint(femu_cxl_stat(qts, "media-reads"), ==, misses);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-fault-reads") +
                     femu_cxl_stat(qts, "der-fault-writes"), >, 7 * 4000);
    /* Only the first exit after decoding needed the BQL (a window scan). */
    g_assert_cmpuint(femu_cxl_stat(qts, "der-fault-bql"), <=, 8);
    qtest_quit(qts);
}

/* MMIO from this thread (the BQL path) while a storm runs. */
static void femu_cxl_storm_mmio(QTestState *qts, unsigned n)
{
    unsigned i;

    for (i = 0; i < n; i++) {
        uint64_t gpa = FEMU_CXL_WINDOW + (i * 37 % 128) * 4096 + 8;

        if (i % 2) {
            qtest_writeq(qts, gpa, i);
        } else {
            qtest_readq(qts, gpa);
        }
    }
}

static bool femu_cxl_flag(QTestState *qts, const char *name)
{
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                          "'path':'/machine/peripheral/ssd',"
                          "'property':%s}}", name);
    bool value;

    g_assert_true(qdict_haskey(rsp, "return"));
    value = qdict_get_bool(rsp, "return");
    qobject_unref(rsp);
    return value;
}

/* The storm's bookkeeping after a join: every exit served, counts kept. */
static void femu_cxl_storm_check(QTestState *qts, uint64_t exits)
{
    uint64_t misses = femu_cxl_stat(qts, "read-misses") +
                      femu_cxl_stat(qts, "write-misses");

    g_assert_cmpuint(femu_cxl_stat(qts, "test-storm-served"), ==, exits);
    g_assert_cmpuint(femu_cxl_stat(qts, "test-storm-stops"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-reads"), ==, misses);
}

/*
 * Until exits run without the BQL, the CXL lock is not a mutex: holders
 * hold the BQL and waits sleep on it. Version 1 exits (mode 2) take the
 * BQL themselves then, and with MMIO they must keep every count. The lock
 * then becomes a mutex in the middle of such a storm, with exits waiting
 * on the BQL and exits in flight; later exits run without the BQL. Last, a
 * version 2 storm (mode 0).
 */
void femu_test_cxl_storm_bql(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QTestState *qts = femu_cxl_storm_init("");

    femu_cxl_storm(qts, 8, 128, 2000, 2);
    femu_cxl_storm_mmio(qts, 1000);
    femu_cxl_storm_wait(qts, "ssd");
    g_assert_false(femu_cxl_flag(qts, "test-lock-mutex"));
    femu_cxl_storm_check(qts, 8 * 2000);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-fault-bql"), ==, 0);

    femu_cxl_storm(qts, 8, 128, 8000, 2);
    femu_cxl_storm_mmio(qts, 300);
    femu_cxl_set(qts, "test-lock-mutex", true);
    femu_cxl_storm_mmio(qts, 300);
    femu_cxl_storm_wait(qts, "ssd");
    g_assert_true(femu_cxl_flag(qts, "test-lock-mutex"));
    femu_cxl_storm_check(qts, 8 * 8000);

    femu_cxl_storm(qts, 8, 128, 2000, 0);
    femu_cxl_storm_mmio(qts, 1000);
    femu_cxl_storm_wait(qts, "ssd");
    femu_cxl_storm_check(qts, 8 * 2000);
    qtest_quit(qts);
}

/* Wait until a qtest flag reads @value, at most 30 s. */
static void femu_cxl_wait_flag(QTestState *qts, const char *name, bool value)
{
    int64_t deadline = g_get_monotonic_time() + 30 * G_USEC_PER_SEC;

    while (femu_cxl_flag(qts, name) != value) {
        g_assert_cmpint(g_get_monotonic_time(), <, deadline);
        g_usleep(1000);
    }
}

/*
 * Device DMA queues its media time without waiting for the FTL mutex, which
 * the worker holds for a whole request, a long collection included. The
 * worker holds it in the first queued operation until the test lets go; a
 * second guarded write must return meanwhile. Once with the CXL lock as no
 * mutex, once as a mutex.
 */
void femu_test_cxl_dma_queue(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "cache-pages=16,cache-ways=16,prefetch-degree=0");
    int64_t deadline;
    unsigned round;

    femu_cxl_decode(qts);
    for (round = 0; round < 2; round++) {
        uint64_t first = FEMU_CXL_WINDOW + (1 + 4 * round) * 4096;
        uint64_t second = FEMU_CXL_WINDOW + (3 + 4 * round) * 4096;

        g_assert_true(femu_cxl_flag(qts, "test-lock-mutex") == round);
        femu_cxl_set_u64(qts, "test-ftl-hold", 30000);
        femu_cxl_set_u64(qts, "test-guarded-write", first);
        femu_cxl_wait_flag(qts, "test-ftl-holding", true);
        femu_cxl_set_u64(qts, "test-guarded-write", second);
        /* The second write returned while the worker held the mutex. */
        g_assert_true(femu_cxl_flag(qts, "test-ftl-holding"));
        femu_cxl_set_u64(qts, "test-ftl-hold", 0);
        deadline = g_get_monotonic_time() + 10 * G_USEC_PER_SEC;
        while (femu_cxl_stat(qts, "test-posted-done") < 2 * (round + 1)) {
            g_assert_cmpint(g_get_monotonic_time(), <, deadline);
            g_usleep(1000);
        }
        g_assert_cmpuint(femu_cxl_stat(qts, "dma-accesses"), ==,
                         2 * (round + 1));
        g_assert_cmpuint(femu_cxl_stat(qts, "dma-media-ops"), ==,
                         2 * (round + 1));
        g_assert_cmphex(qtest_readq(qts, first), ==, first);
        g_assert_cmphex(qtest_readq(qts, second), ==, second);
        femu_cxl_set(qts, "test-lock-mutex", true);
    }
    /* The programs show in media-writes once the bottom half ran. */
    deadline = g_get_monotonic_time() + 10 * G_USEC_PER_SEC;
    while (femu_cxl_stat(qts, "media-writes") < 4) {
        g_assert_cmpint(g_get_monotonic_time(), <, deadline);
        g_usleep(1000);
    }
    g_assert_cmpuint(femu_cxl_stat(qts, "dma-media-time-ns"), >, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-full"), ==, 0);
    qtest_quit(qts);
}

/* Submit @sqe at slot @tail of the queue whose tail doorbell is @db. */
static void femu_cxl_nvme_submit(QTestState *qts, uint64_t sq, uint32_t db,
                                 unsigned tail, const uint8_t *sqe)
{
    qtest_memwrite(qts, sq + tail * 64, sqe, 64);
    qtest_writel(qts, db, tail + 1);
}

/*
 * A QEMU NVMe Read into CXL memory runs on the main loop. Only its first
 * map runs in the controller's guarded bottom half; the copy into CXL
 * happens when the block layer completes, outside any re-entrancy guard.
 * The NVMe read of two pages, with the FTL held until the test lets go,
 * must not keep the main loop meanwhile: a guest disk served there would
 * time out. The monitor answers while the FTL is seen holding, so the copy
 * reached it. Before the fix each answer took the whole hold; the bound
 * on one answer is far below the hold, and far above a loaded host's
 * delays.
 */
void femu_test_cxl_dma_main_loop(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    const uint32_t db = FEMU_CXL_DMA_BAR + 0x1000;
    const uint32_t devfn = 5 << 3;
    const uint64_t asq = 0x200000;
    const uint64_t acq = 0x201000;
    const uint64_t iosq = 0x202000;
    const uint64_t iocq = 0x203000;
    const uint64_t buf = FEMU_CXL_WINDOW + 8 * 4096;
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "cache-pages=16,cache-ways=16,prefetch-degree=0 "
        "-blockdev null-co,node-name=disk,read-zeroes=on "
        "-device nvme,id=nvme0,serial=cxlml,drive=disk,bus=pcie.0,addr=5");
    int64_t deadline;
    int64_t worst = 0;
    unsigned i;
    uint8_t sqe[64];

    femu_cxl_decode(qts);
    femu_cxl_config(qts, 0, devfn << 8 | PCI_BASE_ADDRESS_0,
                    FEMU_CXL_DMA_BAR);
    femu_cxl_config(qts, 0, devfn << 8 | (PCI_BASE_ADDRESS_0 + 4), 0);
    femu_cxl_config(qts, 0, devfn << 8 | PCI_COMMAND,
                    PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);
    qtest_writel(qts, FEMU_CXL_DMA_BAR + NVME_REG_AQA, 3 << 16 | 3);
    qtest_writeq(qts, FEMU_CXL_DMA_BAR + NVME_REG_ASQ, asq);
    qtest_writeq(qts, FEMU_CXL_DMA_BAR + NVME_REG_ACQ, acq);
    qtest_writel(qts, FEMU_CXL_DMA_BAR + NVME_REG_CC,
                 4 << 20 | 6 << 16 | 1);
    deadline = g_get_monotonic_time() + 10 * G_TIME_SPAN_SECOND;
    while (!(qtest_readl(qts, FEMU_CXL_DMA_BAR + NVME_REG_CSTS) & 1)) {
        g_assert_cmpint(g_get_monotonic_time(), <, deadline);
        g_usleep(1000);
    }
    /* An I/O completion queue and submission queue 1, four entries each. */
    memset(sqe, 0, sizeof(sqe));
    sqe[0] = NVME_ADM_CMD_CREATE_CQ;
    stw_le_p(sqe + 2, 1);
    stq_le_p(sqe + 24, iocq);
    stl_le_p(sqe + 40, 3 << 16 | 1);
    stl_le_p(sqe + 44, 1);
    femu_cxl_nvme_submit(qts, asq, db, 0, sqe);
    g_assert_true(femu_cxl_dma_cqe(qts, acq, 0, 1, deadline));
    memset(sqe, 0, sizeof(sqe));
    sqe[0] = NVME_ADM_CMD_CREATE_SQ;
    stw_le_p(sqe + 2, 2);
    stq_le_p(sqe + 24, iosq);
    stl_le_p(sqe + 40, 3 << 16 | 1);
    stl_le_p(sqe + 44, 1 << 16 | 1);
    femu_cxl_nvme_submit(qts, asq, db, 1, sqe);
    g_assert_true(femu_cxl_dma_cqe(qts, acq, 1, 2, deadline));

    /* Data in the backend but not cached, so the copy misses. */
    qtest_memset(qts, buf, 0xa5, 2 * 4096);
    femu_cxl_set(qts, "flush-cache", true);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-entries"), ==, 0);

    /* Read 16 blocks of 512 bytes from LBA 0 into two CXL pages. */
    memset(sqe, 0, sizeof(sqe));
    sqe[0] = NVME_CMD_READ;
    stw_le_p(sqe + 2, 3);
    stl_le_p(sqe + 4, 1);
    stq_le_p(sqe + 24, buf);
    stq_le_p(sqe + 32, buf + 4096);
    stl_le_p(sqe + 48, 15);
    femu_cxl_set_u64(qts, "test-ftl-hold", 60000);
    femu_cxl_nvme_submit(qts, iosq, db + 8, 0, sqe);
    femu_cxl_wait_flag(qts, "test-ftl-holding", true);
    for (i = 0; i < 10; i++) {
        int64_t start = g_get_monotonic_time();
        QDict *rsp = qtest_qmp(qts, "{'execute':'query-status'}");

        worst = MAX(worst, g_get_monotonic_time() - start);
        g_assert_true(qdict_haskey(rsp, "return"));
        qobject_unref(rsp);
    }
    /* Every answer came while the FTL held. */
    g_assert_true(femu_cxl_flag(qts, "test-ftl-holding"));
    g_test_message("slowest query-status during the FTL hold: %" PRId64
                   " ms", worst / 1000);
    g_assert_cmpint(worst, <, 10 * G_TIME_SPAN_SECOND);
    femu_cxl_set_u64(qts, "test-ftl-hold", 0);
    deadline = g_get_monotonic_time() + 60 * G_TIME_SPAN_SECOND;
    g_assert_true(femu_cxl_dma_cqe(qts, iocq, 0, 3, deadline));
    g_assert_cmphex(qtest_readq(qts, buf), ==, 0);
    g_assert_cmphex(qtest_readq(qts, buf + 2 * 4096 - 8), ==, 0);
    qtest_quit(qts);
}

/* A legacy virtio-blk device at 00:06.0, its I/O BAR and its one queue. */
#define FEMU_VBLK_DEVFN  (6 << 3)
#define FEMU_VBLK_IO     0xc000
#define FEMU_VBLK_RING   0x300000ULL
#define FEMU_VBLK_HDR    0x310000ULL
#define FEMU_VBLK_STATUS 0x310100ULL

typedef struct FemuVblk {
    QTestState *qts;
    uint64_t avail;
    uint64_t used;
    uint16_t size;
    uint16_t next;
} FemuVblk;

/* Reset, acknowledge, driver, no features, queue 0, driver OK. */
static void femu_vblk_start(FemuVblk *v, QTestState *qts)
{
    uint16_t size;

    v->qts = qts;
    v->next = 0;
    femu_cxl_config(qts, 0, FEMU_VBLK_DEVFN << 8 | PCI_BASE_ADDRESS_0,
                    FEMU_VBLK_IO);
    femu_cxl_config(qts, 0, FEMU_VBLK_DEVFN << 8 | PCI_COMMAND,
                    PCI_COMMAND_IO | PCI_COMMAND_MASTER);
    qtest_outb(qts, FEMU_VBLK_IO + 0x12, 0);
    qtest_outb(qts, FEMU_VBLK_IO + 0x12, 1);
    qtest_outb(qts, FEMU_VBLK_IO + 0x12, 3);
    qtest_outl(qts, FEMU_VBLK_IO + 0x04, 0);
    qtest_outw(qts, FEMU_VBLK_IO + 0x0e, 0);
    size = qtest_inw(qts, FEMU_VBLK_IO + 0x0c);
    g_assert_cmpuint(size, >=, 3);
    v->size = size;
    v->avail = FEMU_VBLK_RING + 16 * size;
    v->used = ROUND_UP(v->avail + 6 + 2 * size, 4096);
    qtest_outl(qts, FEMU_VBLK_IO + 0x08, FEMU_VBLK_RING >> 12);
    qtest_outb(qts, FEMU_VBLK_IO + 0x12, 7);
}

/*
 * Read (or with @write, write) 4 KiB at sector 0 from (to) @buf: header,
 * data, status. Each request reuses descriptors 0 to 2.
 */
static void femu_vblk_rw(FemuVblk *v, uint64_t buf, bool write)
{
    QTestState *qts = v->qts;
    int64_t deadline;

    qtest_writel(qts, FEMU_VBLK_HDR, write);
    qtest_writel(qts, FEMU_VBLK_HDR + 4, 0);
    qtest_writeq(qts, FEMU_VBLK_HDR + 8, 0);
    qtest_writeb(qts, FEMU_VBLK_STATUS, 0xff);
    qtest_writeq(qts, FEMU_VBLK_RING, FEMU_VBLK_HDR);
    qtest_writel(qts, FEMU_VBLK_RING + 8, 16);
    qtest_writew(qts, FEMU_VBLK_RING + 12, 1);
    qtest_writew(qts, FEMU_VBLK_RING + 14, 1);
    qtest_writeq(qts, FEMU_VBLK_RING + 16, buf);
    qtest_writel(qts, FEMU_VBLK_RING + 24, 4096);
    qtest_writew(qts, FEMU_VBLK_RING + 28, write ? 1 : 1 | 2);
    qtest_writew(qts, FEMU_VBLK_RING + 30, 2);
    qtest_writeq(qts, FEMU_VBLK_RING + 32, FEMU_VBLK_STATUS);
    qtest_writel(qts, FEMU_VBLK_RING + 40, 1);
    qtest_writew(qts, FEMU_VBLK_RING + 44, 2);
    qtest_writew(qts, v->avail + 4 + 2 * (v->next % v->size), 0);
    v->next++;
    qtest_writew(qts, v->avail + 2, v->next);
    qtest_outw(qts, FEMU_VBLK_IO + 0x10, 0);
    deadline = g_get_monotonic_time() + 30 * G_TIME_SPAN_SECOND;
    while (qtest_readw(qts, v->used + 2) != v->next) {
        g_assert_cmpint(g_get_monotonic_time(), <, deadline);
        g_usleep(1000);
    }
    g_assert_cmpuint(qtest_readb(qts, FEMU_VBLK_STATUS), ==, 0);
}

/*
 * A virtio-blk read in an IOThread copies into CXL memory there. The copy
 * is MMIO, so QEMU takes the BQL for it, but the IOThread is not the main
 * loop and keeps the full model: it counts a write miss and queues no
 * device DMA operation. One 4 KiB read into a CXL page.
 */
void femu_test_cxl_dma_iothread(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    const uint64_t buf = FEMU_CXL_WINDOW + 8 * 4096;
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "cache-pages=16,cache-ways=16,prefetch-degree=0 "
        "-object iothread,id=io0 "
        "-blockdev null-co,node-name=disk,read-zeroes=on "
        "-device virtio-blk-pci,id=vblk,drive=disk,iothread=io0,"
        "disable-modern=on,disable-legacy=off,bus=pcie.0,addr=6");
    FemuVblk v;
    uint64_t misses;

    femu_cxl_decode(qts);
    femu_vblk_start(&v, qts);
    /* Data in the backend but not cached, so the copy misses. */
    qtest_memset(qts, buf, 0xa5, 4096);
    femu_cxl_set(qts, "flush-cache", true);
    misses = femu_cxl_stat(qts, "write-misses");
    femu_vblk_rw(&v, buf, false);
    g_assert_cmpuint(femu_cxl_stat(qts, "dma-accesses"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "write-misses"), >, misses);
    g_assert_cmphex(qtest_readq(qts, buf), ==, 0);
    g_assert_cmphex(qtest_readq(qts, buf + 4096 - 8), ==, 0);
    qtest_quit(qts);
}

/*
 * A thread that is neither a vCPU nor an IOThread, such as an RCU callback,
 * holds the BQL for MMIO and reports the main AioContext, as it has none
 * of its own. It is not the main loop, so it keeps the full model: a read
 * miss counts, and no device DMA operation is queued.
 */
void femu_test_cxl_dma_thread(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    const uint64_t buf = FEMU_CXL_WINDOW + 8 * 4096;
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "cache-pages=16,cache-ways=16,prefetch-degree=0");
    uint64_t misses;

    femu_cxl_decode(qts);
    qtest_memset(qts, buf, 0xa5, 4096);
    femu_cxl_set(qts, "flush-cache", true);
    misses = femu_cxl_stat(qts, "read-misses");
    femu_cxl_set_u64(qts, "test-thread-read", buf);
    g_assert_cmpuint(femu_cxl_stat(qts, "dma-accesses"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "read-misses"), >, misses);
    qtest_quit(qts);
}

/*
 * The first device DMA access is a main-loop read of page 0, outside any
 * guard: a virtio-blk write from the first CXL page, whose request the
 * main loop handles. It shares section 0 with every unguarded access, so
 * it must still start a run of its own and charge page 0.
 */
void femu_test_cxl_dma_page0(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "cache-pages=16,cache-ways=16,prefetch-degree=0 "
        "-blockdev null-co,node-name=disk "
        "-device virtio-blk-pci,id=vblk,drive=disk,"
        "disable-modern=on,disable-legacy=off,bus=pcie.0,addr=6");
    FemuVblk v;

    femu_cxl_decode(qts);
    femu_vblk_start(&v, qts);
    qtest_memset(qts, FEMU_CXL_WINDOW, 0xa5, 4096);
    femu_cxl_set(qts, "flush-cache", true);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-entries"), ==, 0);
    femu_vblk_rw(&v, FEMU_CXL_WINDOW, true);
    g_assert_cmpuint(femu_cxl_stat(qts, "dma-accesses"), >, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "dma-media-ops"), ==, 1);
    qtest_quit(qts);
}

/*
 * Device DMA queues without the FTL mutex, so it alone could keep the
 * worker busy, and the worker holds the mutex while busy. A waited request
 * must still get in. Ten operations are queued while the worker holds the
 * mutex in the first; each then takes 1 s more. A read miss that arrives
 * meanwhile must complete after at most a few of them, not after all ten.
 */
void femu_test_cxl_dma_fair(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "cache-pages=16,cache-ways=16,prefetch-degree=0");
    uint64_t done;
    unsigned i;

    femu_cxl_decode(qts);
    femu_cxl_set_u64(qts, "test-ftl-delay", 1000);
    /* The hold ends by itself after 2 s, while this thread reads. */
    femu_cxl_set_u64(qts, "test-ftl-hold", 2000);
    for (i = 0; i < 10; i++) {
        femu_cxl_set_u64(qts, "test-guarded-write",
                         FEMU_CXL_WINDOW + (16 + i) * 4096);
    }
    femu_cxl_wait_flag(qts, "test-ftl-holding", true);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW + 64 * 4096), ==, 0);
    done = femu_cxl_stat(qts, "test-posted-done");
    g_test_message("device DMA operations run before the miss: %" PRIu64,
                   done);
    g_assert_cmpuint(done, <=, 5);
    /* The rest run at once, so the teardown does not wait for them. */
    femu_cxl_set_u64(qts, "test-ftl-delay", 0);
    qtest_quit(qts);
}

/*
 * The worker can hold the FTL mutex for a whole request, a forced
 * collection included. Switching fast load off runs on the main loop, so
 * it must not wait for that mutex: it returns while the worker still holds
 * it, and reports work as queued.
 */
void femu_test_cxl_fast_load_held(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "cache-pages=16,cache-ways=16,prefetch-degree=0");

    femu_cxl_decode(qts);
    femu_cxl_set(qts, "fast-load", true);
    femu_cxl_set_u64(qts, "test-ftl-hold", 20000);
    femu_cxl_set_u64(qts, "test-guarded-write", FEMU_CXL_WINDOW + 4096);
    femu_cxl_wait_flag(qts, "test-ftl-holding", true);
    femu_cxl_set(qts, "fast-load", false);
    g_assert_true(femu_cxl_flag(qts, "test-ftl-holding"));
    g_assert_cmpuint(femu_cxl_stat(qts, "fast-load-drain-ns"), >, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "nand-idle-ns"), >, 0);
    femu_cxl_set_u64(qts, "test-ftl-hold", 0);
    femu_cxl_wait_flag(qts, "test-ftl-holding", false);
    qtest_quit(qts);
}

/*
 * Device DMA work queued before fast load goes off, and still queued when
 * the switch returns, books its NAND time before any later access, and the
 * reported backlog includes it. Two 1 s programs on one LUN are queued
 * while the worker holds the first until the test lets go, and each takes
 * 500 ms more. A read miss queued while the first still runs must find
 * both run. fast-load-drain-ns counts from the switch to the end of both
 * programs, so it is at least what nand-idle-ns reports afterwards, about
 * 1 s; left out, it is 1. A descheduled test can only see less NAND time
 * ahead, and a miss that comes late finds both run either way.
 */
void femu_test_cxl_fast_load_posted(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "cache-pages=16,cache-ways=16,prefetch-degree=0,"
        "channels=1,luns-per-channel=1,program-ns=1000000000");
    uint64_t drain;
    uint64_t idle;
    uint64_t done;

    femu_cxl_decode(qts);
    femu_cxl_set(qts, "fast-load", true);
    femu_cxl_set_u64(qts, "test-ftl-delay", 500);
    femu_cxl_set_u64(qts, "test-ftl-hold", 60000);
    femu_cxl_set_u64(qts, "test-guarded-write", FEMU_CXL_WINDOW + 4096);
    femu_cxl_set_u64(qts, "test-guarded-write", FEMU_CXL_WINDOW + 2 * 4096);
    femu_cxl_wait_flag(qts, "test-ftl-holding", true);
    femu_cxl_set(qts, "fast-load", false);
    g_assert_true(femu_cxl_flag(qts, "test-ftl-holding"));
    g_assert_cmpuint(femu_cxl_stat(qts, "test-posted-done"), ==, 0);
    femu_cxl_set_u64(qts, "test-ftl-hold", 0);
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW + 3 * 4096), ==, 0);
    done = femu_cxl_stat(qts, "test-posted-done");
    g_test_message("device DMA operations run before the later miss: %"
                   PRIu64, done);
    g_assert_cmpuint(done, ==, 2);
    /* The worker settled the backlog before it took the miss. */
    drain = femu_cxl_stat(qts, "fast-load-drain-ns");
    idle = femu_cxl_stat(qts, "nand-idle-ns");
    g_test_message("backlog at the switch %" PRIu64 " ms, NAND idle in %"
                   PRIu64 " ms", drain / 1000000, idle / 1000000);
    if (idle > 1) {
        g_assert_cmpuint(drain, >=, idle);
    }
    femu_cxl_set_u64(qts, "test-ftl-delay", 0);
    qtest_quit(qts);
}

/*
 * A fill waits out its media time inside its media read, without the locks.
 * It must take the whole read once: a 50 ms NAND read of a programmed page
 * keeps the fault exit at least 50 ms, and well under two reads.
 */
void femu_test_cxl_fill_delay(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
        "cache-pages=16,cache-ways=16,prefetch-degree=0,read-ns=50000000");
    uint64_t media;
    int64_t elapsed;
    int64_t start;

    femu_cxl_decode(qts);
    femu_cxl_set(qts, "test-map", true);
    /* Program page 3, then drop it from the cache. */
    qtest_writeq(qts, FEMU_CXL_WINDOW + 3 * 4096, 1);
    femu_cxl_set(qts, "flush-cache", true);
    media = femu_cxl_stat(qts, "media-time-ns");
    start = g_get_monotonic_time();
    femu_cxl_set_u64(qts, "test-fault-fill", FEMU_CXL_WINDOW + 3 * 4096);
    elapsed = g_get_monotonic_time() - start;
    g_assert_cmpint(elapsed, >=, 50000);
    g_assert_cmpint(elapsed, <, 95000);
    g_assert_cmpuint(femu_cxl_stat(qts, "media-time-ns") - media, >=,
                     50000000);
    g_assert_cmpuint(femu_cxl_stat(qts, "cache-entries"), ==, 1);
    qtest_quit(qts);
}

/*
 * A local scaling check, not a pass/fail test: with FEMU_STORM_BENCH set,
 * program 64 MiB, then serve random read faults over it through one 256-way
 * FIFO set with 40 us NAND reads, from 1, 4, 8 and 16 vCPUs, under the BQL
 * as before (mode 1) and without it (mode 0), and print the fault rate.
 * With FEMU_STORM_LIVE set, mode 1 runs with the CXL lock as a mutex, as
 * it is once version 2 is on; without it, mode 1 has the lock as version 1
 * has it, so the two show what the mutex costs exits that hold the BQL.
 */
void femu_test_cxl_storm_bench(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    static const unsigned threads[] = { 1, 4, 8, 16 };
    const char *iters_env = g_getenv("FEMU_STORM_BENCH");
    unsigned iters = iters_env ? atoi(iters_env) : 0;
    unsigned mode;
    unsigned page;
    unsigned i;

    if (!iters) {
        g_test_skip("set FEMU_STORM_BENCH to faults per vCPU");
        return;
    }
    for (mode = 0; mode < 2; mode++) {
        for (i = 0; i < ARRAY_SIZE(threads); i++) {
            if (g_getenv("FEMU_STORM_ONLY") &&
                atoi(g_getenv("FEMU_STORM_ONLY")) != threads[i] * 2 + mode) {
                continue;
            }
            QTestState *qts = qtest_init(FEMU_CXL_MACHINE "-smp 16 "
                "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,"
                "cache-pages=256,cache-ways=256,cache-policy=fifo,"
                "prefetch-degree=0,read-ns=40000,concurrent-misses=on");
            uint64_t ns;
            uint64_t served;

            femu_cxl_decode(qts);
            femu_cxl_set(qts, "test-map", true);
            femu_cxl_set(qts, "fast-load", true);
            for (page = 0; page < 16384; page++) {
                qtest_writeq(qts, FEMU_CXL_WINDOW + page * 4096, page);
            }
            femu_cxl_set(qts, "flush-cache", true);
            femu_cxl_set(qts, "fast-load", false);
            femu_fast_idle(qts);
            if (mode && g_getenv("FEMU_STORM_LIVE")) {
                femu_cxl_set(qts, "test-lock-mutex", true);
            }
            femu_cxl_storm(qts, threads[i], 16384, iters, mode);
            femu_cxl_storm_wait(qts, "ssd");
            ns = femu_cxl_stat(qts, "test-storm-ns");
            served = femu_cxl_stat(qts, "test-storm-served");
            printf("storm mode=%s%s threads=%u faults=%" PRIu64 " ns=%" PRIu64
                   " rate=%.0f/s misses=%" PRIu64 " bql=%" PRIu64 "\n",
                   mode ? "bql" : "cxl-lock",
                   mode && g_getenv("FEMU_STORM_LIVE") ? "+mutex" : "",
                   threads[i], served, ns,
                   served * 1e9 / MAX(ns, 1),
                   femu_cxl_stat(qts, "read-misses"),
                   femu_cxl_stat(qts, "der-fault-bql"));
            printf("  emulated=%" PRIu64 " conflicts=%" PRIu64 " hits=%" PRIu64
                   " media=%" PRIu64 "\n",
                   femu_cxl_stat(qts, "der-fault-emulated"),
                   femu_cxl_stat(qts, "der-fault-conflicts"),
                   femu_cxl_stat(qts, "read-hits"),
                   femu_cxl_stat(qts, "media-reads"));
            qtest_quit(qts);
        }
    }
}

/*
 * Change the device under faults in flight: decoder commits (each an
 * invalidation between two register writes), cache way changes and flushes
 * (the guard taken alone) and a system reset, which clears the decoders.
 */
void femu_test_cxl_storm_change(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    QTestState *qts = femu_cxl_storm_init("");
    unsigned i;

    femu_cxl_storm(qts, 8, 128, 3000, 0);
    for (i = 0; i < 20; i++) {
        femu_cxl_decode(qts);
        femu_cxl_set_u64(qts, "cache-ways", i % 2 ? 64 : 16);
        femu_cxl_set(qts, "flush-cache", true);
        qtest_readq(qts, FEMU_CXL_WINDOW + i * 4096);
    }
    qtest_qmp_assert_success(qts, "{'execute':'system_reset'}");
    qtest_qmp_eventwait(qts, "RESET");
    femu_cxl_decode(qts);
    femu_cxl_storm_wait(qts, "ssd");
    g_assert_cmpuint(femu_cxl_stat(qts, "test-storm-served") +
                     femu_cxl_stat(qts, "test-storm-stops"), ==, 8 * 3000);
    g_assert_cmpuint(femu_cxl_stat(qts, "test-storm-served"), >, 0);
    /* The device still serves faults after all of it. */
    femu_cxl_storm(qts, 4, 128, 500, 0);
    femu_cxl_storm_wait(qts, "ssd");
    g_assert_cmpuint(femu_cxl_stat(qts, "test-storm-stops"), ==, 0);
    qtest_quit(qts);
}

/*
 * Unplug the device under faults in flight: accesses leave the guard, the
 * teardown that one of them would run goes to the main loop, and nothing
 * the faults still hold is freed under them. A new device then takes the
 * window and the remaining faults.
 */
void femu_test_cxl_storm_unplug(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    QTestState *qts = femu_cxl_storm_init(
        " -global cxl-rp.power_controller_present=on "
        "-global ICH9-LPC.acpi-pci-hotplug-with-bridge-support=off");
    QDict *args = qdict_new();
    QDict *rsp;

    femu_cxl_storm(qts, 8, 128, 20000, 0);
    qtest_readq(qts, FEMU_CXL_WINDOW);
    femu_cxl_unplug(qts);
    qdict_put_str(args, "driver", "femu-cxl-ssd");
    qdict_put_str(args, "id", "ssd2");
    qdict_put_str(args, "bus", "rp0");
    qdict_put_str(args, "volatile-memdev", "mem");
    qdict_put_int(args, "cache-pages", 64);
    qdict_put_int(args, "cache-ways", 64);
    qtest_qmp_assert_success(qts, "{'execute':'device_add','arguments':%p}",
                             args);
    /* Power the slot again: the unplug switched it off. */
    femu_cxl_config(qts, 52, femu_cxl_rp_exp_cap(qts) + PCI_EXP_SLTCTL,
                    PCI_EXP_SLTCTL_PWR_IND_ON);
    femu_cxl_decode(qts);
    femu_cxl_storm_wait(qts, "ssd2");
    /*
     * The first storm can end before ssd2 decodes, so the faults left in
     * flight may not reach it. A second storm must reach it.
     */
    g_test_message("in-flight faults that reached ssd2: %" PRIu64,
                   femu_cxl_stat_of(qts, "ssd2", "der-fault-reads"));
    rsp = qtest_qmp(qts, "{'execute':'qom-set','arguments':{"
                    "'path':'/machine/peripheral/ssd2',"
                    "'property':'test-storm','value':'4,128,500,0,7'}}");
    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
    femu_cxl_storm_wait(qts, "ssd2");
    g_assert_cmpuint(femu_cxl_stat_of(qts, "ssd2", "der-fault-reads"), >, 0);
    qtest_quit(qts);
}

/*
 * A prefetch must not map a page another access is filling. The hook starts
 * a fill of page 1 (hold and entry, read pending) where the prefetch of page
 * 1 could drop the BQL, then fails that fill. No mapping may outlive the
 * entry: every direct page has a cache entry.
 */
void femu_test_cxl_prefetch_race(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem,der=memslot,"
        "cache-pages=4,cache-ways=4,prefetch-degree=1");

    femu_cxl_decode(qts);
    femu_cxl_set_u64(qts, "test-prefetch-race", 1 + 1);
    qtest_readq(qts, FEMU_CXL_WINDOW);
    femu_cxl_set(qts, "test-prefetch-race-end", true);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), <=,
                     femu_cxl_stat(qts, "cache-entries"));
    /* The page reads normally afterwards. */
    g_assert_cmphex(qtest_readq(qts, FEMU_CXL_WINDOW + 4096), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(qts, "der-mapped"), <=,
                     femu_cxl_stat(qts, "cache-entries"));
    qtest_quit(qts);
}

/* Commands that touch the cache refuse while media is disabled. */
void femu_test_cca_media(void *obj, void *data,
                         QGuestAllocator *alloc)
{
    FemuCca c;

    femu_cca_start(&c, "", "cache-pages=4,cache-ways=2");
    qtest_writeq(c.qts, femu_cca_page(0), 0x20);
    femu_cxl_set(c.qts, "test-media-disabled", true);
    femu_cca_expect(&c, CCA_CTRL_PIN, 0, 0, 1, -ENODEV, 0);
    femu_cca_expect(&c, CCA_CTRL_INVALIDATE, 0, 0, 1, -ENODEV, 0);
    femu_cca_expect(&c, CCA_CTRL_CACHE_DISABLE, 0, 0, 1, -ENODEV, 0);
    femu_cca_expect(&c, CCA_CTRL_QUERY, 0, 0, 1, -ENODEV, 0);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-pinned"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cca-uncached"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(c.qts, "cache-entries"), ==, 1);
    femu_cca_expect(&c, CCA_CTRL_NOP, 0, 0, 0, 0, 0);
    femu_cxl_set(c.qts, "test-media-disabled", false);
    femu_cca_expect(&c, CCA_CTRL_PIN, 0, 0, 1, 0, 1);
    femu_cca_quit(&c);
}

/*
 * A bbssd controller linked to the medium with cxl_ssd: both front ends
 * share one payload and one FTL.
 */
#define FEMU_LINK_SLOT  0x10
#define FEMU_LINK_HOTPLUG \
    "-global cxl-rp.power_controller_present=on " \
    "-global ICH9-LPC.acpi-pci-hotplug-with-bridge-support=off "

typedef struct FemuLink {
    QTestState *qts;
    QGuestAllocator alloc;
    QPCIBus *bus;
    QPCIDevice *pdev;
    FemuCtrlState c;
    uint64_t buf;
} FemuLink;

/* @cxl and @nvme are extra options, each empty or starting with a comma. */
static void femu_link_start(FemuLink *l, const char *extra, const char *cxl,
                            const char *nvme)
{
    memset(l, 0, sizeof(*l));
    /* qtest_pc_boot() would intercept the IOAPIC, which leaks on q35. */
    l->qts = qtest_initf(FEMU_CXL_MACHINE "%s"
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem%s "
        "-device femu,id=nvme,bus=pcie.0,addr=0x%x,femu_mode=1,cxl_ssd=ssd,"
        "oncs=0x10c%s",
        extra, cxl, FEMU_LINK_SLOT, nvme);
    pc_alloc_init(&l->alloc, l->qts, ALLOC_NO_FLAGS);
    l->bus = qpci_new_pc(l->qts, &l->alloc);
    femu_cxl_decode(l->qts);
    l->pdev = qpci_device_find(l->bus, QPCI_DEVFN(FEMU_LINK_SLOT, 0));
    g_assert_nonnull(l->pdev);
    femu_enable(&l->c, l->pdev, &l->alloc);
    femu_create_io_queues(&l->c);
    l->buf = guest_alloc(&l->alloc, FEMU_DATA_SIZE);
}

static void femu_link_quit(FemuLink *l)
{
    guest_free(&l->alloc, l->buf);
    femu_queue_free(&l->c, &l->c.io);
    femu_queue_free(&l->c, &l->c.admin);
    g_free(l->pdev);
    qpci_free_pc(l->bus);
    alloc_destroy(&l->alloc);
    qtest_quit(l->qts);
}

static uint64_t femu_link_lba(FemuLink *l, uint64_t page)
{
    return page * 4096 / l->c.lba_size;
}

/* Write one page of @seed's pattern through NVMe and return the pattern. */
static void femu_link_write(FemuLink *l, uint64_t page, uint8_t seed,
                            uint8_t *pattern)
{
    int i;

    for (i = 0; i < FEMU_DATA_SIZE; i++) {
        pattern[i] = (uint8_t)(seed + i * 13);
    }
    qtest_memwrite(l->qts, l->buf, pattern, FEMU_DATA_SIZE);
    g_assert_cmpint(FEMU_SC(femu_rw(&l->c, NVME_CMD_WRITE,
                                    femu_link_lba(l, page), l->buf)), ==,
                    NVME_SUCCESS);
}

static uint16_t femu_link_read(FemuLink *l, uint64_t page, uint8_t *out)
{
    uint16_t status;

    qtest_memset(l->qts, l->buf, 0xee, FEMU_DATA_SIZE);
    status = FEMU_SC(femu_rw(&l->c, NVME_CMD_READ, femu_link_lba(l, page),
                             l->buf));
    qtest_memread(l->qts, l->buf, out, FEMU_DATA_SIZE);
    return status;
}

static uint16_t femu_link_dsm(FemuLink *l, uint64_t slba, uint32_t nlb)
{
    NvmeCmd cmd = { 0 };
    uint8_t desc[16] = { 0 };

    stl_le_p(desc + 4, nlb);
    stq_le_p(desc + 8, slba);
    qtest_memwrite(l->qts, l->buf, desc, sizeof(desc));
    cmd.opcode = NVME_CMD_DSM;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(l->buf);
    cmd.cdw11 = cpu_to_le32(FEMU_DSM_AD);
    return femu_io(&l->c, &cmd);
}

/* Copy @nlb blocks from @src to @dst with one format-0 source range. */
static uint16_t femu_link_copy(FemuLink *l, uint64_t src, uint64_t dst,
                               uint32_t nlb)
{
    NvmeCmd cmd = { 0 };
    uint8_t desc[32] = { 0 };

    stq_le_p(desc + 8, src);
    stw_le_p(desc + 16, nlb - 1);
    qtest_memwrite(l->qts, l->buf, desc, sizeof(desc));
    cmd.opcode = NVME_CMD_COPY;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(l->buf);
    cmd.cdw10 = cpu_to_le32(dst);
    cmd.cdw11 = cpu_to_le32(dst >> 32);
    return femu_io(&l->c, &cmd);
}

static void femu_link_flip(FemuLink *l, uint32_t code)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = 0xef;
    cmd.cdw10 = cpu_to_le32(code);
    g_assert_cmpint(FEMU_SC(femu_admin(&l->c, &cmd)), ==, NVME_SUCCESS);
}

static void femu_link_expect_error(QTestState *qts, const char *args,
                                   const char *message)
{
    g_autofree char *cmd = g_strdup_printf("{'execute':'device_add',"
        "'arguments':{'driver':'femu','id':'bad','bus':'hp1',%s}}", args);
    QDict *rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));

    g_assert_true(qdict_haskey(rsp, "error"));
    if (message) {
        g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                              "desc"), message));
    }
    qobject_unref(rsp);
}

/* Every configuration the link cannot serve is refused with its reason. */
void femu_test_cxl_nvme_link(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QTestState *qts = qtest_init(FEMU_CXL_MACHINE
        "-object memory-backend-ram,id=mem2,size=256M "
        "-device cxl-rp,id=rp1,bus=cxl.0,chassis=0,slot=1 "
        "-device femu-cxl-ssd,id=ssd,bus=rp0,volatile-memdev=mem "
        "-device femu-cxl-ssd,id=noftl,bus=rp1,volatile-memdev=mem2,ftl=off "
        "-device pcie-root-port,id=hp0,bus=pcie.0,chassis=5,slot=5 "
        "-device pcie-root-port,id=hp1,bus=pcie.0,chassis=6,slot=6");
    QDict *rsp;

    femu_link_expect_error(qts, "'femu_mode':2,'cxl_ssd':'ssd'",
                           "femu_mode=1");
    femu_link_expect_error(qts, "'femu_mode':1,'cxl_ssd':'ssd',"
                           "'namespaces':2", "single bbssd namespace");
    femu_link_expect_error(qts, "'femu_mode':1,'cxl_ssd':'noftl'",
                           "ftl=on");
    femu_link_expect_error(qts, "'femu_mode':1,'cxl_ssd':'ssd',"
                           "'streams':true", "streams");
    femu_link_expect_error(qts, "'femu_mode':1,'cxl_ssd':'ssd',"
                           "'buffer_size':16", "buffer_size");
    femu_link_expect_error(qts, "'femu_mode':1,'cxl_ssd':'ssd',"
                           "'meta':8,'mc':2", "protection information");
    femu_link_expect_error(qts, "'femu_mode':1,'cxl_ssd':'ssd',"
                           "'devsz_mb':512", "devsz_mb must be unset or 256");
    /* the medium's FTL takes its settings from the CXL device */
    femu_link_expect_error(qts, "'femu_mode':1,'cxl_ssd':'ssd',"
                           "'ecc_step_ns':1000000,'pd_open_tiers':1",
                           "not supported with cxl_ssd");
    femu_link_expect_error(qts, "'femu_mode':1,'cxl_ssd':'ssd',"
                           "'gc_frontier':true",
                           "gc_frontier is not supported with cxl_ssd");
    femu_link_expect_error(qts, "'femu_mode':1,'cxl_ssd':'ssd',"
                           "'gc_erase_order':false",
                           "gc_erase_order=off is not supported with "
                           "cxl_ssd");
    /* the medium's FTL has no end-of-life reserve */
    femu_link_expect_error(qts, "'femu_mode':1,'cxl_ssd':'ssd',"
                           "'rain_parity':1,'rain_read_only':true,'mdts':4",
                           "rain_read_only is not supported with cxl_ssd");
    femu_link_expect_error(qts, "'femu_mode':1,'cxl_ssd':'rp0'", NULL);
    femu_link_expect_error(qts, "'femu_mode':1,'cxl_ssd':'later'", NULL);
    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'n1','bus':'hp0','femu_mode':1,"
                    "'cxl_ssd':'ssd','devsz_mb':256}}");
    g_assert_true(qdict_haskey(rsp, "return"));
    qobject_unref(rsp);
    femu_link_expect_error(qts, "'femu_mode':1,'cxl_ssd':'ssd'",
                           "already serves");
    rsp = qtest_qmp(qts, "{'execute':'device_del','arguments':{'id':'ssd'}}");
    g_assert_true(qdict_haskey(rsp, "error"));
    g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                          "desc"),
                            "in use by NVMe controller n1"));
    qobject_unref(rsp);
    qtest_quit(qts);
}

/* Both front ends read what the other wrote, at either block size. */
void femu_test_cxl_nvme_data(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    bool large = data != NULL;
    uint8_t want[FEMU_DATA_SIZE];
    uint8_t got[FEMU_DATA_SIZE];
    FemuLink l;
    int i;

    femu_link_start(&l, "", ",der=memslot",
                    large ? ",lba_index=3" : "");
    l.c.lba_size = large ? 4096 : 512;
    femu_link_write(&l, 5, 1, want);
    qtest_memread(l.qts, FEMU_CXL_WINDOW + 5 * 4096, got, sizeof(got));
    g_assert_cmpmem(got, sizeof(got), want, sizeof(want));

    /* A dirty cached page, then a page behind a direct mapping. */
    for (i = 0; i < FEMU_DATA_SIZE; i++) {
        want[i] = (uint8_t)(0x3c ^ i);
    }
    qtest_memwrite(l.qts, FEMU_CXL_WINDOW + 9 * 4096, want, sizeof(want));
    g_assert_cmpuint(femu_cxl_stat(l.qts, "cache-entries"), >=, 2);
    g_assert_cmpint(femu_link_read(&l, 9, got), ==, NVME_SUCCESS);
    g_assert_cmpmem(got, sizeof(got), want, sizeof(want));
    g_assert_cmphex(qtest_readq(l.qts, FEMU_CXL_WINDOW + 11 * 4096), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(l.qts, "der-mapped"), >=, 1);
    want[0] ^= 0xff;
    qtest_memwrite(l.qts, FEMU_CXL_WINDOW + 11 * 4096, want, sizeof(want));
    g_assert_cmpint(femu_link_read(&l, 11, got), ==, NVME_SUCCESS);
    g_assert_cmpmem(got, sizeof(got), want, sizeof(want));
    g_assert_cmpuint(femu_cxl_stat(l.qts, "media-writes"), >=, 1);
    femu_link_quit(&l);
}

/* A transfer of @pages pages: PRP1 names the first, a PRP list the rest. */
typedef struct FemuLinkXfer {
    uint64_t data;
    uint64_t list;
    unsigned pages;
} FemuLinkXfer;

/* The list pages are contiguous; the last slot of a full one chains on. */
static void femu_link_xfer_init(FemuLink *l, FemuLinkXfer *x, unsigned pages)
{
    uint64_t at;
    unsigned slot = 0;
    unsigned k;

    x->pages = pages;
    x->data = guest_alloc(&l->alloc, (uint64_t)pages * 4096);
    x->list = guest_alloc(&l->alloc, (pages / 511 + 1) * 4096);
    at = x->list;
    for (k = 1; k < pages; k++) {
        if (slot == 511 && pages - k > 1) {
            qtest_writeq(l->qts, at + slot * 8, at + 4096);
            at += 4096;
            slot = 0;
        }
        qtest_writeq(l->qts, at + slot * 8, x->data + (uint64_t)k * 4096);
        slot++;
    }
}

static void femu_link_xfer_free(FemuLink *l, FemuLinkXfer *x)
{
    guest_free(&l->alloc, x->list);
    guest_free(&l->alloc, x->data);
}

static void femu_link_xfer_submit(FemuLink *l, FemuQueue *q, uint8_t opcode,
                                  uint64_t page, FemuLinkXfer *x)
{
    NvmeRwCmd rw = { 0 };

    rw.opcode = opcode;
    rw.nsid = cpu_to_le32(1);
    rw.dptr.prp1 = cpu_to_le64(x->data);
    rw.dptr.prp2 = cpu_to_le64(x->list);
    rw.slba = cpu_to_le64(femu_link_lba(l, page));
    rw.nlb = cpu_to_le16(x->pages * 4096 / l->c.lba_size - 1);
    femu_submit(&l->c, q, (NvmeCmd *)&rw);
}

/* A second I/O queue pair with its own completion queue. */
static void femu_link_queue(FemuLink *l, FemuQueue *q, uint16_t qid)
{
    NvmeCmd cmd = { 0 };

    femu_queue_init(&l->c, q, qid);
    cmd.opcode = NVME_ADM_CMD_CREATE_CQ;
    cmd.dptr.prp1 = cpu_to_le64(q->cq_addr);
    cmd.cdw10 = cpu_to_le32(((FEMU_QSIZE - 1) << 16) | qid);
    cmd.cdw11 = cpu_to_le32(NVME_CQ_PC);
    g_assert_cmpint(femu_admin(&l->c, &cmd), ==, NVME_SUCCESS);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_CREATE_SQ;
    cmd.dptr.prp1 = cpu_to_le64(q->sq_addr);
    cmd.cdw10 = cpu_to_le32(((FEMU_QSIZE - 1) << 16) | qid);
    cmd.cdw11 = cpu_to_le32((qid << 16) | NVME_SQ_PC);
    g_assert_cmpint(femu_admin(&l->c, &cmd), ==, NVME_SUCCESS);
}

/*
 * Transfers of many pages at 512-byte blocks, as Linux issues them: the
 * scatter list has an entry per page. Each write lands in the shared payload
 * and drops the resident pages it covers; with two queues, one write per
 * queue is in flight at once and each is read back through the other queue.
 */
void femu_test_cxl_nvme_prp(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    unsigned pages = (uintptr_t)data & 0xffff;
    unsigned n = (uintptr_t)data & FEMU_LINK_QUEUES ? 2 : 1;
    size_t size = (size_t)pages * 4096;
    g_autofree uint8_t *want = g_malloc(n * size);
    g_autofree uint8_t *got = g_malloc(n * size);
    FemuQueue *q[2];
    FemuQueue q2;
    FemuLinkXfer x[2];
    uint64_t drops;
    uint64_t writes;
    FemuLink l;
    unsigned i;
    size_t b;

    femu_link_start(&l, "", ",cache-pages=64",
                    n > 1 ? ",multipoller_enabled=1" : "");
    q[0] = &l.c.io;
    q[1] = &q2;
    if (n > 1) {
        femu_link_queue(&l, &q2, 2);
    }
    for (b = 0; b < n * size; b++) {
        want[b] = (uint8_t)(b / 4096 * 7 + b);
    }
    for (i = 0; i < n; i++) {
        femu_link_xfer_init(&l, &x[i], pages);
        qtest_memwrite(l.qts, x[i].data, want + i * size, size);
        g_assert_cmphex(qtest_readq(l.qts, FEMU_CXL_WINDOW + i * size), ==, 0);
        g_assert_cmphex(qtest_readq(l.qts, FEMU_CXL_WINDOW + i * size +
                                    size - 4096), ==, 0);
    }
    drops = femu_cxl_stat(l.qts, "nvme-drops");
    writes = femu_cxl_stat(l.qts, "media-writes");
    for (i = 0; i < n; i++) {
        femu_link_xfer_submit(&l, q[i], NVME_CMD_WRITE, i * pages, &x[i]);
    }
    for (i = 0; i < n; i++) {
        g_assert_cmpint(FEMU_SC(femu_complete(&l.c, q[i], NULL, NULL)), ==,
                        NVME_SUCCESS);
    }
    g_assert_cmpuint(femu_cxl_stat(l.qts, "nvme-drops"), ==, drops + 2 * n);
    g_assert_cmpuint(femu_cxl_stat(l.qts, "media-writes"), >=,
                     writes + n * pages);
    qtest_memread(l.qts, FEMU_CXL_WINDOW, got, n * size);
    g_assert_cmpmem(got, n * size, want, n * size);

    for (i = 0; i < n; i++) {
        qtest_memset(l.qts, x[i].data, 0xee, size);
        femu_link_xfer_submit(&l, q[n - 1 - i], NVME_CMD_READ, i * pages,
                              &x[i]);
    }
    for (i = 0; i < n; i++) {
        g_assert_cmpint(FEMU_SC(femu_complete(&l.c, q[n - 1 - i], NULL,
                                              NULL)), ==, NVME_SUCCESS);
        qtest_memread(l.qts, x[i].data, got + i * size, size);
        femu_link_xfer_free(&l, &x[i]);
    }
    g_assert_cmpmem(got, n * size, want, n * size);
    if (n > 1) {
        femu_queue_free(&l.c, &q2);
    }
    femu_link_quit(&l);
}

/*
 * A page NVMe replaces leaves the cache and loses its direct mapping before
 * the command completes, and is not written back again later.
 */
void femu_test_cxl_nvme_invalidate(void *obj, void *data,
                                   QGuestAllocator *alloc)
{
    uintptr_t op = (uintptr_t)data;
    uint8_t pattern[FEMU_DATA_SIZE];
    uint64_t revoked;
    uint64_t writes;
    FemuLink l;

    femu_link_start(&l, "", ",der=memslot", "");
    if (op == FEMU_LINK_COPY) {
        femu_link_write(&l, 40, 7, pattern);
    }
    g_assert_cmphex(qtest_readq(l.qts, FEMU_CXL_WINDOW + 3 * 4096), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(l.qts, "cache-entries"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(l.qts, "der-mapped"), ==, 1);
    revoked = femu_cxl_stat(l.qts, "der-revocations");
    writes = femu_cxl_stat(l.qts, "media-writes");
    switch (op) {
    case FEMU_LINK_WRITE:
        femu_link_write(&l, 3, 2, pattern);
        break;
    case FEMU_LINK_ZEROES:
        g_assert_cmpint(femu_lba_cmd(&l.c, NVME_CMD_WRITE_ZEROES, 24, 8), ==,
                        NVME_SUCCESS);
        break;
    default:
        g_assert_cmpint(femu_link_copy(&l, 320, 24, 8), ==, NVME_SUCCESS);
        break;
    }
    /* Checked right after the completion: it waited for the drop. */
    g_assert_cmpuint(femu_cxl_stat(l.qts, "cache-entries"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(l.qts, "der-mapped"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(l.qts, "der-revocations"), ==,
                     revoked + 1);
    g_assert_cmpuint(femu_cxl_stat(l.qts, "nvme-drops"), ==, 1);
    if (op != FEMU_LINK_ZEROES) {
        g_assert_cmpuint(femu_cxl_stat(l.qts, "media-writes"), ==,
                         writes + 1);
    }
    writes = femu_cxl_stat(l.qts, "media-writes");
    femu_cxl_set(l.qts, "flush-cache", true);
    g_assert_cmpuint(femu_cxl_stat(l.qts, "media-writes"), ==, writes);
    if (op == FEMU_LINK_COPY) {
        uint8_t got[FEMU_DATA_SIZE];

        qtest_memread(l.qts, FEMU_CXL_WINDOW + 3 * 4096, got, sizeof(got));
        g_assert_cmpmem(got, sizeof(got), pattern, sizeof(pattern));
    }
    femu_link_quit(&l);
}

/* A long linked write keeps a direct ratio mapped, as eviction does. */
void femu_test_cxl_nvme_ratio(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    uint64_t mapped;
    FemuLink l;

    femu_link_start(&l, "", ",der=memslot", "");
    g_assert_cmphex(qtest_readq(l.qts, FEMU_CXL_WINDOW + 3 * 4096), ==, 0);
    qtest_qmp_assert_success(l.qts, "{'execute':'qom-set','arguments':{"
                             "'path':'/machine/peripheral/ssd',"
                             "'property':'der-ratio','value':100}}");
    mapped = femu_cxl_stat(l.qts, "der-mapped");
    g_assert_cmpuint(mapped, >=, 65536);
    g_assert_cmpint(femu_lba_cmd(&l.c, NVME_CMD_WRITE_ZEROES, 0, 1024), ==,
                    NVME_SUCCESS);
    g_assert_cmpuint(femu_cxl_stat(l.qts, "cache-entries"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(l.qts, "der-mapped"), ==, mapped);
    femu_link_quit(&l);
}

/* A deallocated page must not come back when its dirty copy is dropped. */
void femu_test_cxl_nvme_deallocate(void *obj, void *data,
                                   QGuestAllocator *alloc)
{
    uint8_t pattern[FEMU_DATA_SIZE];
    uint8_t zero[FEMU_DATA_SIZE] = { 0 };
    uint8_t got[FEMU_DATA_SIZE];
    uint64_t writes;
    uint64_t ns;
    FemuLink l;

    femu_link_start(&l, "", "", "");
    femu_link_write(&l, 6, 3, pattern);
    qtest_writeq(l.qts, FEMU_CXL_WINDOW + 6 * 4096, 0x1122334455667788ULL);
    g_assert_cmpuint(femu_cxl_stat(l.qts, "cache-entries"), ==, 1);
    g_assert_cmpint(femu_link_dsm(&l, 48, 8), ==, NVME_SUCCESS);
    g_assert_cmpuint(femu_cxl_stat(l.qts, "cache-entries"), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(l.qts, "nvme-drops"), ==, 1);
    writes = femu_cxl_stat(l.qts, "media-writes");
    femu_cxl_set(l.qts, "flush-cache", true);
    g_assert_cmpuint(femu_cxl_stat(l.qts, "media-writes"), ==, writes);
    g_assert_cmpint(femu_link_read(&l, 6, got), ==, NVME_SUCCESS);
    g_assert_cmpmem(got, sizeof(got), zero, sizeof(zero));
    /* An unmapped page costs no NAND read on the next miss. */
    ns = femu_cxl_stat(l.qts, "media-time-ns");
    g_assert_cmphex(qtest_readq(l.qts, FEMU_CXL_WINDOW + 6 * 4096), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(l.qts, "cache-entries"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(l.qts, "media-time-ns"), ==, ns);
    femu_link_quit(&l);
}

/* With DULBE on, blocks CXL wrote read as written through NVMe. */
void femu_test_cxl_nvme_dulbe(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    uint8_t pattern[FEMU_DATA_SIZE];
    uint8_t got[FEMU_DATA_SIZE];
    FemuLink l;

    memset(pattern, 0x5a, sizeof(pattern));
    femu_link_start(&l, "", ",der=memslot", "");
    g_assert_cmpint(FEMU_SC(femu_set_feature(&l.c, NVME_ERROR_RECOVERY,
                            false, 1, 1 << 16, NULL)), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_link_read(&l, 20, got), ==, NVME_DULB);
    qtest_memwrite(l.qts, FEMU_CXL_WINDOW + 21 * 4096, pattern,
                   sizeof(pattern));
    g_assert_cmpint(femu_link_read(&l, 21, got), ==, NVME_SUCCESS);
    g_assert_cmpmem(got, sizeof(got), pattern, sizeof(pattern));
    /* A read installs a writable mapping, so its page counts as written. */
    g_assert_cmphex(qtest_readq(l.qts, FEMU_CXL_WINDOW + 22 * 4096), ==, 0);
    g_assert_cmpuint(femu_cxl_stat(l.qts, "der-mapped"), >=, 1);
    g_assert_cmpint(femu_link_read(&l, 22, got), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_link_read(&l, 23, got), ==, NVME_DULB);
    femu_link_quit(&l);
}

/*
 * Stores through a direct ratio never trap, so a Deallocate must leave the
 * selected pages marked written or DULBE would hide data CXL wrote later.
 */
void femu_test_cxl_nvme_ratio_dulbe(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    uint8_t pattern[FEMU_DATA_SIZE];
    uint8_t got[FEMU_DATA_SIZE];
    FemuLink l;

    memset(pattern, 0xa5, sizeof(pattern));
    femu_link_start(&l, "", ",der=memslot", "");
    g_assert_cmpint(FEMU_SC(femu_set_feature(&l.c, NVME_ERROR_RECOVERY,
                            false, 1, 1 << 16, NULL)), ==, NVME_SUCCESS);
    qtest_qmp_assert_success(l.qts, "{'execute':'qom-set','arguments':{"
                             "'path':'/machine/peripheral/ssd',"
                             "'property':'der-ratio','value':999}}");
    /* Ratio 999 leaves every 1000th page, such as 1000, on MMIO. */
    g_assert_cmpint(femu_link_dsm(&l, 1000 * 8, 16), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_link_read(&l, 1000, got), ==, NVME_DULB);
    qtest_memwrite(l.qts, FEMU_CXL_WINDOW + 1001 * 4096, pattern,
                   sizeof(pattern));
    g_assert_cmpint(femu_link_read(&l, 1001, got), ==, NVME_SUCCESS);
    g_assert_cmpmem(got, sizeof(got), pattern, sizeof(pattern));
    femu_link_quit(&l);
}

/* Flips on the controller change the medium's shared timing. */
void femu_test_cxl_nvme_flip(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    FemuLink l;
    uint64_t ns;

    femu_link_start(&l, "", ",cache-pages=0,read-ns=30000,program-ns=1000,"
                    "erase-ns=1000", "");
    qtest_writeq(l.qts, FEMU_CXL_WINDOW + 3 * 4096, 1);
    femu_link_flip(&l, 4);
    ns = femu_cxl_stat(l.qts, "media-time-ns");
    g_assert_cmphex(qtest_readq(l.qts, FEMU_CXL_WINDOW + 3 * 4096), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(l.qts, "media-time-ns"), ==, ns);
    /* Restores this device's read-ns, not the compile-time default. */
    femu_link_flip(&l, 3);
    ns = femu_cxl_stat(l.qts, "media-time-ns");
    g_assert_cmphex(qtest_readq(l.qts, FEMU_CXL_WINDOW + 3 * 4096), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(l.qts, "media-time-ns"), ==, ns + 30000);
    femu_link_quit(&l);
}

/* NVMe writes to a pinned page keep it resident and pinned, but clean. */
void femu_test_cxl_nvme_pin(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    uint8_t pattern[FEMU_DATA_SIZE];
    uint64_t writes;
    FemuCca cca;
    FemuLink l;

    femu_link_start(&l, "", ",cca=on,cache-pages=64,cache-ways=64", "");
    cca.qts = l.qts;
    cca.slot = 0;
    femu_cca_map(&cca);
    qtest_writeq(l.qts, femu_cca_page(7), 0x77);
    femu_cca_expect(&cca, CCA_CTRL_PIN, 0, 7, 1, 0, 1);
    writes = femu_cxl_stat(l.qts, "media-writes");
    femu_link_write(&l, 7, 4, pattern);
    g_assert_cmpuint(femu_cxl_stat(l.qts, "cache-entries"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(l.qts, "cca-pinned"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(l.qts, "nvme-drops"), ==, 1);
    g_assert_cmpuint(femu_cxl_stat(l.qts, "media-writes"), ==, writes + 1);
    femu_cxl_set(l.qts, "flush-cache", true);
    g_assert_cmpuint(femu_cxl_stat(l.qts, "media-writes"), ==, writes + 1);
    g_assert_cmphex(qtest_readb(l.qts, femu_cca_page(7)), ==, pattern[0]);
    femu_link_quit(&l);
}

/* Power the slot of rp0 off, as a guest may without asking management. */
static void femu_cxl_slot_off(QTestState *qts)
{
    uint8_t cap;

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
    femu_cxl_config(qts, 52, cap + PCI_EXP_SLTCTL,
                    PCI_EXP_SLTCTL_PCC | PCI_EXP_SLTCTL_PWR_IND_OFF);
}

static void femu_link_unrealize(FemuLink *l)
{
    qtest_qmp_assert_success(l->qts, "{'execute':'qom-set','arguments':{"
                             "'path':'/machine/peripheral/nvme',"
                             "'property':'realized','value':false}}");
}

/*
 * Management cannot remove a linked medium. A guest can, by powering the
 * slot off; the controller then keeps the FTL and payload to itself.
 */
void femu_test_cxl_nvme_unplug(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    bool guest = data != NULL;
    uint8_t want[FEMU_DATA_SIZE];
    uint8_t got[FEMU_DATA_SIZE];
    FemuLink l;
    QDict *rsp;

    femu_link_start(&l, FEMU_LINK_HOTPLUG, "", "");
    femu_link_write(&l, 2, 5, want);
    qtest_writeq(l.qts, FEMU_CXL_WINDOW + 4 * 4096, 0xabcdef);
    if (!guest) {
        rsp = qtest_qmp(l.qts, "{'execute':'device_del',"
                        "'arguments':{'id':'ssd'}}");
        g_assert_true(qdict_haskey(rsp, "error"));
        qobject_unref(rsp);
        g_assert_cmphex(qtest_readq(l.qts, FEMU_CXL_WINDOW + 4 * 4096), ==,
                        0xabcdef);
        femu_link_unrealize(&l);
        femu_cxl_unplug(l.qts);
    } else {
        femu_cxl_slot_off(l.qts);
        rsp = qtest_qmp(l.qts, "{'execute':'qom-get','arguments':{"
                        "'path':'/machine/peripheral/ssd',"
                        "'property':'realized'}}");
        g_assert_true(qdict_haskey(rsp, "error"));
        qobject_unref(rsp);
        g_assert_cmpint(femu_link_read(&l, 4, got), ==, NVME_SUCCESS);
        g_assert_cmphex(ldq_le_p(got), ==, 0xabcdef);
        g_assert_cmpint(femu_link_read(&l, 2, got), ==, NVME_SUCCESS);
        g_assert_cmpmem(got, sizeof(got), want, sizeof(want));
        femu_link_write(&l, 8, 6, want);
        g_assert_cmpint(femu_link_read(&l, 8, got), ==, NVME_SUCCESS);
        g_assert_cmpmem(got, sizeof(got), want, sizeof(want));
        femu_link_unrealize(&l);
    }
    femu_link_quit(&l);
}

/*
 * While a long caching-API command holds the guard, a linked write's
 * completion waits for the invalidation that follows it. With the
 * controller removed meanwhile, the invalidation still runs later.
 *
 * Eight writebacks of 100 ms each hold the guard for about 800 ms but
 * occupy only eight of the sixteen LUNs, so the NVMe write itself, on the
 * next LUN, is due after about 100 ms.
 */
void femu_test_cxl_nvme_guard(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    bool unplug = data != NULL;
    uint8_t pattern[FEMU_DATA_SIZE];
    FemuCcaResp r;
    NvmeRwCmd rw = { 0 };
    FemuCca cca;
    FemuLink l;
    gint64 until;
    unsigned lpn;

    femu_link_start(&l, "", ",cca=on,cache-pages=128,cache-ways=128,"
                    "program-ns=100000000", "");
    cca.qts = l.qts;
    cca.slot = 0;
    femu_cca_map(&cca);
    for (lpn = 0; lpn < 8; lpn++) {
        qtest_writeq(l.qts, femu_cca_page(lpn), lpn);
    }
    g_assert_cmphex(qtest_readq(l.qts, femu_cca_page(100)), ==, 0);
    femu_cca_post_raw(&cca, cca.slot++, CCA_CTRL_INVALIDATE, 0, 0, 8, 0);
    femu_cca_kick(&cca);
    femu_cca_poll_stat(l.qts, "cca-writebacks", 8);

    memset(pattern, 0x42, sizeof(pattern));
    qtest_memwrite(l.qts, l.buf, pattern, sizeof(pattern));
    rw.opcode = NVME_CMD_WRITE;
    rw.nsid = cpu_to_le32(1);
    rw.dptr.prp1 = cpu_to_le64(l.buf);
    rw.slba = cpu_to_le64(100 * 8);
    rw.nlb = cpu_to_le16(7);
    femu_submit(&l.c, &l.c.io, (NvmeCmd *)&rw);
    until = g_get_monotonic_time() + 400 * 1000;
    while (g_get_monotonic_time() < until) {
        g_assert_false(femu_cq_ready(&l.c, &l.c.io));
        g_usleep(5000);
    }
    g_assert_cmpuint(femu_cxl_stat(l.qts, "nvme-drops"), ==, 0);
    if (unplug) {
        femu_link_unrealize(&l);
    }
    femu_cca_reap(&cca, &r);
    g_assert_cmpint(r.status, ==, 0);
    if (!unplug) {
        g_assert_cmpint(FEMU_SC(femu_complete(&l.c, &l.c.io, NULL, NULL)),
                        ==, NVME_SUCCESS);
    }
    femu_cca_poll_stat(l.qts, "nvme-drops", 1);
    g_assert_cmpuint(femu_cxl_stat(l.qts, "cache-entries"), ==, 0);
    g_assert_cmphex(qtest_readb(l.qts, femu_cca_page(100)), ==, 0x42);
    femu_link_quit(&l);
}

/*
 * A linked NVMe write that arrives after fast load went off must not book
 * its NAND time ahead of the device DMA operations queued before the
 * switch. Two operations are queued while the worker holds the first, and
 * each takes 1 s more; the NVMe write then waits for the FTL mutex, which
 * the worker offered it between the two. It must book after both. A test
 * that the host deschedules lets the worker take the second first, so it
 * can only pass.
 */
void femu_test_cxl_nvme_barrier(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    uint8_t pattern[FEMU_DATA_SIZE];
    NvmeRwCmd rw = { 0 };
    FemuLink l;
    int64_t deadline;

    femu_link_start(&l, "", ",cache-pages=16,cache-ways=16,"
                    "prefetch-degree=0", "");
    femu_cxl_set(l.qts, "fast-load", true);
    femu_cxl_set_u64(l.qts, "test-ftl-delay", 1000);
    femu_cxl_set_u64(l.qts, "test-ftl-hold", 60000);
    femu_cxl_set_u64(l.qts, "test-guarded-write", FEMU_CXL_WINDOW + 4096);
    femu_cxl_set_u64(l.qts, "test-guarded-write",
                     FEMU_CXL_WINDOW + 2 * 4096);
    femu_cxl_wait_flag(l.qts, "test-ftl-holding", true);
    femu_cxl_set(l.qts, "fast-load", false);

    memset(pattern, 0x42, sizeof(pattern));
    qtest_memwrite(l.qts, l.buf, pattern, sizeof(pattern));
    rw.opcode = NVME_CMD_WRITE;
    rw.nsid = cpu_to_le32(1);
    rw.dptr.prp1 = cpu_to_le64(l.buf);
    rw.slba = cpu_to_le64(femu_link_lba(&l, 100));
    rw.nlb = cpu_to_le16(4096 / l.c.lba_size - 1);
    femu_submit(&l.c, &l.c.io, (NvmeCmd *)&rw);
    femu_cxl_wait_flag(l.qts, "test-lock-wanted", true);
    femu_cxl_set_u64(l.qts, "test-ftl-hold", 0);
    deadline = g_get_monotonic_time() + 30 * G_USEC_PER_SEC;
    while (!femu_cq_ready(&l.c, &l.c.io)) {
        g_assert_cmpint(g_get_monotonic_time(), <, deadline);
        g_usleep(10 * 1000);
    }
    g_assert_cmpint(FEMU_SC(femu_complete(&l.c, &l.c.io, NULL, NULL)), ==,
                    NVME_SUCCESS);
    g_assert_cmpuint(femu_cxl_stat(l.qts, "test-nvme-after-posted"), ==, 2);
    femu_cxl_set_u64(l.qts, "test-ftl-delay", 0);
    femu_link_quit(&l);
}
