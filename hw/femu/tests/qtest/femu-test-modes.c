/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QTest testcases for the FEMU SSD emulator: the tests that run one
 * function on more than one mode.
 *
 * femu-test.c registers every test. This file holds the test bodies
 * and the helpers that only they use.
 */

#include "qemu/osdep.h"
#include "femu-test.h"

void femu_test_report_length(void *obj, void *data,
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

/*
 * The device is unplugged after the copy is made and before the command
 * replies (x-query-delay-ms holds it there). The reply must still come from
 * the copy, and the command must not touch the device once it has dropped
 * its reference; a sanitizer build reports that access. @data names the
 * namespace mode: the FTL thread copies a bbssd namespace, and the main
 * loop a znssd one.
 */
void femu_test_query_unplug(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    QDict *rsp;
    QDict *ret;

    femu_enable(&c, &femu->dev, alloc);
    qtest_qmp_assert_success(qts, "{'execute':'qom-set','arguments':{"
                             "'path':'/machine/peripheral/qu',"
                             "'property':'x-query-delay-ms','value':500}}");
    qtest_qmp_device_del_send(qts, "qu");
    qtest_qmp_send(qts, "{'execute':'query-femu'}");
    /* the copy takes microseconds; the command now sleeps for 500 ms */
    g_usleep(100 * 1000);
    qtest_outl(qts, 0xae00 + 8, 1 << 4);    /* ACPI PCI hotplug: eject slot 4 */
    rsp = qtest_qmp_receive(qts);
    ret = qdict_get_qdict(rsp, "return");
    g_assert_nonnull(ret);
    g_assert_cmpstr(qdict_get_str(ret, "path"), ==,
                    "/machine/peripheral/qu");
    if (data && !strcmp(data, "profile")) {
        /* the profile strings of the reply are copies, not the device's */
        QDict *ns = qobject_to(QDict, qlist_peek(qdict_get_qlist(ret,
                                                             "namespaces")));
        QDict *media = qdict_get_qdict(ns, "media");

        g_assert_cmpstr(qdict_get_str(media, "nand-profile"), ==,
                        "bbssd-flat-default");
        g_assert_true(g_str_has_suffix(qdict_get_str(media,
                                                     "nand-profile-file"),
                                       "/bbssd-flat-default.nprof"));
    } else {
        g_assert_cmpstr(qdict_get_str(ret, "mode"), ==,
                        data ? data : "bbssd");
    }
    qobject_unref(rsp);
    qtest_qmp_eventwait(qts, "DEVICE_DELETED");
    femu_query_fails(qts, "", "no femu device");
    qos_invalidate_command_line();
}

void femu_test_query_media(void *obj, void *data,
                           QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    const FemuMediaWant *w = femu_media_want(data);
    FemuCtrlState c = { 0 };
    QDict *rsp;

    /* a namespace with the media timing only needs no enabled controller */
    if (femu_media_only(w->mode)) {
        femu_media_check(femu_query_ns(qts, "", &rsp), w);
        qobject_unref(rsp);
        femu_query_fails(qts, "'nsid':1,'kind':'lines'", "does not apply");
    }
    femu_enable(&c, &femu->dev, alloc);
    femu_media_check(femu_query_ns(qts, "", &rsp), w);
    qobject_unref(rsp);
    femu_disable(&c);
    qos_invalidate_command_line();
}

void femu_test_wear(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    uint64_t want[5];
    uint64_t mapped, lost, orphans;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 64 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t log = guest_alloc(alloc, 512);
    uint8_t page[512];
    uint64_t got[3];
    int i;

    g_assert_cmpint(sscanf(data, "%" SCNu64 " %" SCNu64 " %" SCNu64
                           " %" SCNu64 " %" SCNu64, &want[0], &want[1],
                           &want[2], &want[3], &want[4]), ==, 5);
    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x3c, 64 * 4096);
    femu_wear_workload(&c, buf, list);

    g_assert_cmpint(FEMU_SC(femu_get_log(&c, FEMU_LOG_FEMU_STATS, log,
                                         sizeof(page), 0)), ==, NVME_SUCCESS);
    qtest_memread(qts, log, page, sizeof(page));
    for (i = 0; i < 3; i++) {
        got[i] = ldq_le_p(page + 112 + 8 * i);
    }
    g_test_message("overworn %" PRIu64 " grown bad %" PRIu64 " retired lines %"
                   PRIu64, got[0], got[1], got[2]);
    for (i = 0; i < 3; i++) {
        g_assert_cmpuint(got[i], ==, want[i]);
    }

    g_assert_cmpint(FEMU_SC(femu_get_log(&c, NVME_LOG_SMART_INFO, log,
                                         sizeof(page), 0)), ==, NVME_SUCCESS);
    qtest_memread(qts, log, page, sizeof(page));
    g_test_message("available spare %u percentage used %u", page[3], page[5]);
    g_assert_cmpuint(page[0] & NVME_SMART_RELIABILITY, ==,
                     want[0] ? NVME_SMART_RELIABILITY : 0);
    g_assert_cmpuint(page[3], ==, want[3]);
    g_assert_cmpuint(page[5], ==, want[4]);
    g_assert_cmpuint(page[0] & NVME_SMART_SPARE, ==,
                     want[3] < FEMU_SPARE_THRESHOLD ? NVME_SMART_SPARE : 0);

    femu_ftl_check(qts, &mapped, &lost, &orphans);
    g_assert_cmpuint(mapped, ==, 256);
    g_assert_cmpuint(lost, ==, 0);
    g_assert_cmpuint(orphans, ==, 0);

    guest_free(alloc, log);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_disable(&c);
    /* the device is worn out now: the next test must not inherit it */
    qos_invalidate_command_line();
}

/* gc_copyback refuses the settings that move pages some other way */
void femu_test_gc_copyback_refused(void *obj, void *data,
                                   QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    const struct {
        const char *extra;
        const char *why;
    } cases[] = {
        { "'femu_mode':1,'gc_pace':true", "with gc_pace" },
        { "'femu_mode':1,'pe_suspend':1", "with pe_suspend" },
        { "'femu_mode':1,'read_prio':1", "with read_prio" },
        { "'femu_mode':1,'mapping':'hybrid'",
          "a mapping other than page or dftl" },
        { "'femu_mode':0", "a mode other than bbssd or CSD" },
        { "'femu_mode':3", "a mode other than bbssd or CSD" },
    };
    int i;

    for (i = 0; i < ARRAY_SIZE(cases); i++) {
        g_autofree char *args = g_strdup_printf(
            "{'driver':'femu','id':'cb-refused','addr':'5','devsz_mb':16,"
            "'gc_copyback':true,%s}", cases[i].extra);
        QDict *rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':%p}",
                               qobject_from_json(args, &error_abort));
        const char *desc;

        g_assert_true(qdict_haskey(rsp, "error"));
        desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
        g_test_message("%s: %s", cases[i].extra, desc);
        g_assert_nonnull(strstr(desc, "gc_copyback"));
        g_assert_nonnull(strstr(desc, cases[i].why));
        qobject_unref(rsp);
    }
    qos_invalidate_command_line();
}

/* A setting the wear model does not cover refuses blk_pe_limit at realize */
void femu_test_wear_refused(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    /* the wear features and paced collection share one boundary */
    const char *feature = data ? data : "'blk_pe_limit':3";
    const char *name = data ? "gc_pace" : "blk_pe_limit";
    const struct {
        const char *opts;
        const char *msg;
    } cases[] = {
        { "'femu_mode':5", "a mode other than bbssd or CSD" },
        { "'femu_mode':1,'subsys':'fdpsub'", "FDP" },
        { "'femu_mode':1,'buffer_size':16", "buffer_size" },
        { "'femu_mode':1,'streams':true", "Streams" },
        { "'femu_mode':1,'hot_cold_sep':true", "hot_cold_sep" },
        { "'femu_mode':1,'mapping':'hybrid'",
          "a mapping other than page or dftl" },
        { "'femu_mode':1,'pls_per_lun':2", "pls_per_lun > 1" },
        { "'femu_mode':1,'namespaces':2", "more than one namespace" },
        { "'femu_mode':1,'ns_mgmt':true", "namespace management" },
        { "'femu_mode':1,'nand_bad_blocks':1", "nand_bad_blocks" },
        { NULL },
        { "'femu_mode':1,'blk_pe_spread':91", "blk_pe_spread must be 0 to 90" },
        { "'femu_mode':1,'spare_lines':40", "must be below blks_per_pl" },
        { "'femu_mode':1,'age_scale':0", "age_scale must be 1 or more" },
        { "'femu_mode':1,'blk_early_ppm':1000001",
          "must be at most 1000000" },
        { "'femu_mode':1,'erase_fail_ppm':1000001",
          "must be at most 1000000" },
        { "'femu_mode':1,'blk_early_ppm':10", "needs blk_early_pe" },
        { "'femu_mode':1,'erase_fail_ppm':10,'eol_read_only':false",
          "erase_fail_ppm needs eol_read_only=on" },
    };
    QDict *rsp;
    int i;

    for (i = 0; i < ARRAY_SIZE(cases) && cases[i].opts; i++) {
        g_autofree char *cmd = g_strdup_printf(
            "{'execute':'device_add','arguments':{"
            "'driver':'femu','id':'wear','addr':'5','devsz_mb':1,"
            "'secsz':512,'secs_per_pg':8,'pgs_per_blk':4,'blks_per_pl':40,"
            "'luns_per_ch':2,'nchs':2,%s,%s}}", feature, cases[i].opts);
        const char *desc;

        /* FDP takes blk_pe_limit; wear-fdp-props covers it */
        if (!data && strstr(cases[i].opts, "fdpsub")) {
            continue;
        }

        rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));
        g_assert_true(qdict_haskey(rsp, "error"));
        desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
        g_test_message("%s: %s", cases[i].opts, desc);
        g_assert_nonnull(strstr(desc, cases[i].msg));
        g_assert_nonnull(strstr(desc, name));
        qobject_unref(rsp);
    }
    /* the checks after the marker need blk_pe_limit */
    for (i++; !data && i < ARRAY_SIZE(cases); i++) {
        g_autofree char *cmd = g_strdup_printf(
            "{'execute':'device_add','arguments':{"
            "'driver':'femu','id':'wear','addr':'5','devsz_mb':1,"
            "'secsz':512,'secs_per_pg':8,'pgs_per_blk':4,'blks_per_pl':40,"
            "'luns_per_ch':2,'nchs':2,%s,%s}}", feature, cases[i].opts);

        rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));
        g_assert_true(qdict_haskey(rsp, "error"));
        g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                             "desc"), cases[i].msg));
        qobject_unref(rsp);
    }
    qos_invalidate_command_line();
}

/*
 * Realize refuses program disturb settings that cannot work: bad values, a
 * term with no ECC step, an edge wider than the block, a namespace whose mode
 * builds its own media locations, and an FTL another device owns. A ZNS
 * controller whose only namespace is bbssd takes them.
 */
void femu_test_pd_refused(void *obj, void *data,
                          QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    const struct {
        const char *opts;
        const char *msg;
    } tc[] = {
        { "'femu_mode':1,'pd_open_tiers':-1", "must not be negative" },
        { "'femu_mode':1,'pd_open_tiers':5", "the ECC tier cap" },
        { "'femu_mode':1,'pd_edge_wls':1,'pd_edge_tiers':5",
          "the ECC tier cap" },
        { "'femu_mode':1,'pd_edge_tiers':1", "must be set together" },
        { "'femu_mode':1,'pd_open_tiers':1,'ecc_step_ns':-1000000",
          "need ecc_step_ns" },
        { "'femu_mode':1,'pd_open_age':true,'ecc_retention_sec':-1",
          "needs ecc_retention_sec" },
        { "'femu_mode':1,'pd_open_tiers':1,'pd_edge_wls':1",
          "must be set together" },
        { "'femu_mode':1,'pd_open_tiers':1,'ecc_step_ns':0,"
          "'pd_open_age':false",
          "need ecc_step_ns" },
        { "'femu_mode':1,'pd_open_age':true", "needs ecc_retention_sec" },
        { "'femu_mode':1,'pd_edge_wls':16,'pd_edge_tiers':1",
          "must be below 16" },
        { "'femu_mode':1,'pd_edge_wls':8,'pd_edge_tiers':1,'cell_pages':2",
          "must be below 8" },
        { "'femu_mode':1,'pd_open_tiers':1,'ns_mgmt':true",
          "ns_mgmt or shared" },
        { "'femu_mode':3,'pd_open_tiers':1", "namespace 1 is not" },
        { "'femu_mode':2,'pd_open_tiers':1", "namespace 1 is not" },
        { "'femu_mode':1,'pd_open_tiers':1,'namespaces':2,"
          "'namespace_modes':'bbssd,znssd'", "namespace 2 is not" },
        { "'femu_mode':1,'pd_open_tiers':1,'namespaces':2,"
          "'namespace_modes':'znssd,bbssd'", "namespace 1 is not" },
        { "'femu_mode':1,'pd_open_tiers':1,'namespaces':2,"
          "'namespace_modes':'bbssd,nossd'", "namespace 2 is not" },
        { "'femu_mode':0,'pd_open_tiers':1", "namespace 1 is not" },
        { "'femu_mode':0,'lver':1,'pd_open_tiers':1", "namespace 1 is not" },
        { "'femu_mode':1,'pd_open_tiers':1,'namespaces':2,"
          "'namespace_modes':'nossd,bbssd'", "namespace 1 is not" },
        { "'femu_mode':1,'pd_edge_wls':-1,'pd_edge_tiers':1",
          "must not be negative" },
        { "'femu_mode':1,'pd_open_read_limit':-1", "must not be negative" },
        { "'femu_mode':1,'nchs':2,'rain_parity':2", "rain_parity is 0 or 1" },
        { "'femu_mode':1,'nchs':2,'rain_parity':1,'die_parity':1",
          "rain_parity is 0 or 1" },
        { "'femu_mode':1,'nchs':2,'rain_parity':1,'wl_spread':4",
          "rain_parity is 0 or 1" },
        { "'femu_mode':1,'nchs':2,'rain_parity':1,'pd_open_close_sec':1",
          "rain_parity is 0 or 1" },
        { "'femu_mode':1,'nchs':2,'rain_parity':1,'mapping':'dftl'",
          "die_parity and rain_parity need" },
        { "'femu_mode':1,'nchs':2,'rain_parity':1,'prog_pass2_ns':1000",
          "rain_parity is 0 or 1" },
        { "'femu_mode':1,'nchs':2,'rain_parity':1,'streams':true",
          "rain_parity is 0 or 1" },
        { "'femu_mode':1,'nchs':2,'rain_parity':1,'mp_program':1",
          "die_parity and rain_parity need" },
        { "'femu_mode':1,'rain_rebuild':true",
          "rain_rebuild needs rain_parity" },
        { "'femu_mode':2,'rber_timing_only':true",
          "rber_timing_only needs rber_ppb" },
        { "'femu_mode':1,'pd_open_close_sec':-1", "must not be negative" },
        { "'femu_mode':1,'pd_open_read_limit':9,'read_reclaim_limit':8",
          "not be above read_reclaim_limit" },
        { "'femu_mode':5,'pd_open_read_limit':4", "namespace 1 is KV" },
        { "'femu_mode':5,'pd_open_close_sec':4", "namespace 1 is KV" },
        { "'femu_mode':1,'pd_open_read_limit':4,'namespaces':2,"
          "'namespace_modes':'bbssd,kvssd'", "namespace 2 is KV" },
        { "'femu_mode':1,'pd_open_close_sec':1,'mapping':'hybrid'",
          "mapping=hybrid" },
        { "'femu_mode':1,'pd_open_read_limit':1,'mapping':'fast'",
          "mapping=fast" },
        { "'femu_mode':3,'pd_open_close_sec':1", "namespace 1 is not" },
        { "'femu_mode':1,'pd_open_read_limit':4,'ns_mgmt':true",
          "ns_mgmt or shared" },
    };
    QDict *rsp;

    for (int i = 0; i < ARRAY_SIZE(tc); i++) {
        /* a case may set its own channel count (rain_parity needs two) */
        const char *nchs = "'nchs':1,";
        g_autofree char *cmd = NULL;

        if (strstr(tc[i].opts, "nchs")) {
            nchs = "";
        }
        cmd = g_strdup_printf(
            "{'execute':'device_add','arguments':{"
            "'driver':'femu','id':'pd-bad','addr':'5','devsz_mb':4,"
            "'secsz':512,'secs_per_pg':8,'pgs_per_blk':16,'blks_per_pl':80,"
            "'pls_per_lun':1,'luns_per_ch':1,%s%s%s}}", nchs,
            strstr(tc[i].opts, "ecc_step_ns") ? "" :
            "'ecc_step_ns':1000000,", tc[i].opts);

        rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));
        g_assert_true(qdict_haskey(rsp, "error"));
        g_test_message("pd refused %s: %s", tc[i].opts,
                       qdict_get_str(qdict_get_qdict(rsp, "error"), "desc"));
        g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                              "desc"), tc[i].msg));
        qobject_unref(rsp);
    }
    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'pd-ok','addr':'6','devsz_mb':4,"
                    "'femu_mode':3,'namespace_modes':'bbssd',"
                    "'secsz':512,'secs_per_pg':8,'pgs_per_blk':16,"
                    "'blks_per_pl':80,'pls_per_lun':1,'luns_per_ch':1,"
                    "'nchs':1,'ecc_step_ns':1000000,'pd_open_tiers':1}}");
    if (qdict_haskey(rsp, "error")) {
        g_test_message("pd accepted case: %s",
                       qdict_get_str(qdict_get_qdict(rsp, "error"), "desc"));
    }
    g_assert_false(qdict_haskey(rsp, "error"));
    qobject_unref(rsp);
    /* the program disturb actions need no ECC step */
    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'pd-ok2','addr':'7','devsz_mb':4,"
                    "'femu_mode':1,'secsz':512,'secs_per_pg':8,"
                    "'pgs_per_blk':16,'blks_per_pl':80,'pls_per_lun':1,"
                    "'luns_per_ch':1,'nchs':1,'pd_open_read_limit':4,"
                    "'pd_open_close_sec':5}}");
    if (qdict_haskey(rsp, "error")) {
        g_test_message("pd accepted case: %s",
                       qdict_get_str(qdict_get_qdict(rsp, "error"), "desc"));
    }
    g_assert_false(qdict_haskey(rsp, "error"));
    qobject_unref(rsp);
    qos_invalidate_command_line();
}

/*
 * Realize refuses an ONFI profile that cannot apply: a bad mode or rate, a
 * hand-set bus phase knob, a namespace whose mode builds its own media
 * timing, and an FTL another device owns. A ZNS controller whose only
 * namespace is bbssd takes it.
 */
void femu_test_onfi_refused(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    const struct {
        const char *opts;
        const char *msg;
    } cases[] = {
        { "'femu_mode':1,'onfi_mode':27", "must be -1 (off) or 0 to 26" },
        { "'femu_mode':1,'onfi_mode':-2", "must be -1 (off) or 0 to 26" },
        { "'femu_mode':1,'onfi_mode':26,'onfi_mts':-1", "onfi_mts must be" },
        { "'femu_mode':1,'onfi_mode':26,'onfi_mts':100001",
          "onfi_mts must be" },
        { "'femu_mode':1,'onfi_mode':26,'onfi_spare_bytes':-1",
          "must not be negative" },
        { "'femu_mode':1,'onfi_mode':26,'onfi_tccs_ns':-1",
          "must not be negative" },
        { "'femu_mode':1,'onfi_mode':26,'onfi_spare_bytes':511",
          "needs an even page size" },
        { "'femu_mode':1,'onfi_mode':26,'cmd_addr_lat':1000",
          "cmd_addr_lat is refused with onfi_mode" },
        { "'femu_mode':1,'onfi_mode':26,'pg_xfer_lat':1000",
          "pg_xfer_lat is refused with onfi_mode" },
        { "'femu_mode':1,'onfi_mode':26,'ch_xfer_lat':1000",
          "ch_xfer_lat is refused with onfi_mode" },
        { "'femu_mode':1,'onfi_mode':26,'status_lat':1000",
          "status_lat is refused with onfi_mode" },
        { "'femu_mode':1,'onfi_mode':26,'ns_mgmt':true", "ns_mgmt or shared" },
        { "'femu_mode':1,'onfi_mode':26,'pe_suspend':1",
          "pe_suspend is refused with onfi_mode" },
        { "'femu_mode':1,'onfi_mode':26,'read_prio':1",
          "read_prio is refused with onfi_mode" },
        { "'femu_mode':3,'onfi_mode':26", "namespace 1 is not" },
        { "'femu_mode':2,'onfi_mode':26", "namespace 1 is not" },
        { "'femu_mode':0,'onfi_mode':26", "namespace 1 is not" },
        { "'femu_mode':1,'onfi_mode':26,'namespaces':2,"
          "'namespace_modes':'bbssd,znssd'", "namespace 2 is not" },
        { "'femu_mode':1,'onfi_mode':26,'namespaces':2,"
          "'namespace_modes':'nossd,bbssd'", "namespace 1 is not" },
    };
    QDict *rsp;

    for (int i = 0; i < ARRAY_SIZE(cases); i++) {
        g_autofree char *cmd = g_strdup_printf(
            "{'execute':'device_add','arguments':{"
            "'driver':'femu','id':'onfi-bad','addr':'5','devsz_mb':4,"
            "'secsz':512,'secs_per_pg':8,'pgs_per_blk':16,'blks_per_pl':80,"
            "'pls_per_lun':1,'luns_per_ch':1,'nchs':1,%s}}", cases[i].opts);

        rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));
        g_assert_true(qdict_haskey(rsp, "error"));
        g_test_message("onfi refused %s: %s", cases[i].opts,
                       qdict_get_str(qdict_get_qdict(rsp, "error"), "desc"));
        g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                              "desc"), cases[i].msg));
        qobject_unref(rsp);
    }
    /* an odd sector size gives an odd page with no spare bytes at all */
    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'onfi-odd','addr':'5','devsz_mb':1,"
                    "'femu_mode':1,'secsz':513,'secs_per_pg':1,"
                    "'pgs_per_blk':16,'blks_per_pl':160,'pls_per_lun':1,"
                    "'luns_per_ch':1,'nchs':1,'onfi_mode':26}}");
    g_assert_true(qdict_haskey(rsp, "error"));
    g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                          "desc"), "needs an even page size"));
    qobject_unref(rsp);
    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'onfi-ok','addr':'6','devsz_mb':4,"
                    "'femu_mode':3,'namespace_modes':'bbssd',"
                    "'secsz':512,'secs_per_pg':8,'pgs_per_blk':16,"
                    "'blks_per_pl':80,'pls_per_lun':1,'luns_per_ch':1,"
                    "'nchs':1,'onfi_mode':26}}");
    if (qdict_haskey(rsp, "error")) {
        g_test_message("onfi accepted case: %s",
                       qdict_get_str(qdict_get_qdict(rsp, "error"), "desc"));
    }
    g_assert_false(qdict_haskey(rsp, "error"));
    qobject_unref(rsp);
    qos_invalidate_command_line();
}

/*
 * onfi_param_page: realize refuses a missing file, a page with no
 * signature, a bad CRC, a geometry that differs and a mode the page does
 * not list. A good page turns the profile on with its own highest mode
 * and address cycles: read command 2 + 3 + 4 cycles + tWB = 325 ns, page
 * ceil(4096 * 555 / 2000) = 1137 ns at mode 22. The accepted device is a
 * CSD one, whose media timing query-femu reports with no enabled
 * controller.
 */
void femu_test_onfi_page(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    g_autofree char *good = femu_onfi_page_file(0, true);
    g_autofree char *nosig = femu_onfi_page_file(1, true);
    g_autofree char *badcrc = femu_onfi_page_file(0, false);
    g_autofree char *geom = femu_onfi_page_file(2, true);
    const struct {
        const char *page;
        const char *opts;
        const char *msg;
    } cases[] = {
        { "/nonexistent/femu-onfi-page", "", "onfi_param_page" },
        { nosig, "", "no copy has the ONFI signature" },
        { badcrc, "", "good CRC" },
        { geom, "", "pages per block (bytes 92-95) 64, FEMU 32" },
        { good, ",'onfi_mode':26", "do not list onfi_mode 26" },
        { good, ",'pg_xfer_lat':1000", "pg_xfer_lat is refused" },
    };
    QDict *rsp;
    QDict *md;

    for (int i = 0; i < ARRAY_SIZE(cases); i++) {
        g_autofree char *cmd = g_strdup_printf(
            "{'execute':'device_add','arguments':{"
            "'driver':'femu','id':'onfi-bad','addr':'5','devsz_mb':1,"
            "'femu_mode':1,'secsz':512,'secs_per_pg':8,'pgs_per_blk':32,"
            "'blks_per_pl':12,'pls_per_lun':1,'luns_per_ch':1,'nchs':1,"
            "'onfi_param_page':'%s'%s}}", cases[i].page, cases[i].opts);

        rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));
        g_assert_true(qdict_haskey(rsp, "error"));
        g_test_message("onfi page refused %s: %s", cases[i].msg,
                       qdict_get_str(qdict_get_qdict(rsp, "error"), "desc"));
        g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                              "desc"), cases[i].msg));
        qobject_unref(rsp);
    }
    rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'onfi-page','addr':'6',"
                    "'devsz_mb':1,'femu_mode':4,'fdm_size':16,'secsz':512,"
                    "'secs_per_pg':8,'pgs_per_blk':32,'blks_per_pl':12,"
                    "'pls_per_lun':1,'luns_per_ch':1,'nchs':1,"
                    "'onfi_param_page':%s}}", good);
    /* realize has read the files */
    unlink(good);
    unlink(nosig);
    unlink(badcrc);
    unlink(geom);
    if (qdict_haskey(rsp, "error")) {
        g_test_message("onfi page accepted case: %s",
                       qdict_get_str(qdict_get_qdict(rsp, "error"), "desc"));
    }
    g_assert_false(qdict_haskey(rsp, "error"));
    qobject_unref(rsp);
    md = qdict_get_qdict(femu_query_ns(qts,
                                       "'path':'/machine/peripheral/onfi-page'",
                                       &rsp), "media");
    g_assert_true(qdict_get_bool(md, "onfi-profile"));
    g_assert_cmpint(qdict_get_int(md, "onfi-mode"), ==, 22);
    g_assert_cmpint(qdict_get_int(md, "column-cycles"), ==, 3);
    g_assert_cmpint(qdict_get_int(md, "row-cycles"), ==, 4);
    g_assert_cmpint(qdict_get_int(md, "read-command-ns"), ==, 325);
    g_assert_cmpint(qdict_get_int(md, "page-transfer-ns"), ==, 1137);
    qobject_unref(rsp);
    qos_invalidate_command_line();
}

/*
 * mapping=dftl keeps its translation pages (TPs) on flash. 2048 pages of
 * 4 KiB are 4 TPs of 512 mappings, and the CMT holds one TP (x-cmt-slots),
 * so each write to another TP evicts a dirty one.
 *   - A sequential fill writes TPs 0 to 3 in turn: 3 evictions program 3
 *     TPs, and no TP has a copy to read yet.
 *   - A read of page 0 reads TP 0 back and evicts TP 3: one read, one more
 *     program.
 *   - Random overwrites fill the device many times. Collection takes TP
 *     lines as well as data lines, and every page still reads back what
 *     was last written to it.
 * The amplification of log page C0h counts the TP programs. @data names
 * the variant: "exact" checks the counts of the first two steps, which a
 * write buffer or pacing changes; "loose" only the invariants; "csd" also
 * skips query-femu, which has no line counters for a CSD namespace.
 */
void femu_test_dftl_tp(void *obj, void *data, QGuestAllocator *alloc)
{
    bool exact = g_str_equal(data, "exact");
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    const char *id = "/machine/peripheral/tp";
    FemuCtrlState c = { 0 };
    const uint32_t pages = 2048;
    g_autofree uint8_t *want = g_new0(uint8_t, pages);
    uint64_t buf = guest_alloc(alloc, 64 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t log = guest_alloc(alloc, 4096);
    uint64_t host, nand, gc, map, pad, v[7];
    uint32_t seed = 5;
    uint32_t i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    for (i = 0; i < pages / 64; i++) {
        qtest_memset(qts, buf, 0x10 + i, 64 * 4096);
        g_assert_cmphex(FEMU_SC(femu_write_pages(&c, i * 64, 64, buf, list)),
                        ==, NVME_SUCCESS);
        memset(want + i * 64, 0x10 + i, 64);
    }
    femu_tp_check(qts, id, v);
    g_assert_cmpuint(v[1] + v[2] + v[4], ==, 0);
    if (exact) {
        g_assert_cmpuint(v[0], ==, pages);
        g_assert_cmpuint(v[3], ==, 3);
        g_assert_cmpuint(femu_c0h_field(&c, log, 280), ==, 3);
        g_assert_cmpuint(femu_c0h_field(&c, log, 288), ==, 0);
    }

    g_assert_cmphex(femu_read_pages(&c, 0, 1, buf, list), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, buf), ==, 0x10);
    if (exact) {
        g_assert_cmpuint(femu_c0h_field(&c, log, 280), ==, 4);
        g_assert_cmpuint(femu_c0h_field(&c, log, 288), ==, 1);
    }

    for (i = 0; i < 6000; i++) {
        uint32_t page;
        uint8_t b = 0x80 + (i & 0x3f);

        seed = seed * 1103515245 + 12345;
        page = (seed >> 8) % pages;
        qtest_memset(qts, buf, b, 4096);
        g_assert_cmphex(FEMU_SC(femu_write_pages(&c, page, 1, buf, list)),
                        ==, NVME_SUCCESS);
        want[page] = b;
    }
    /* a write buffer may still hold pages: flush them to the media */
    femu_hybrid_flush(&c);
    femu_tp_check(qts, id, v);
    g_assert_cmpuint(v[0], ==, pages);
    g_assert_cmpuint(v[1] + v[2] + v[4], ==, 0);
    g_assert_cmpuint(v[3], ==, 4);
    g_assert_cmpuint(v[5], >, 0);
    for (i = 0; i < pages; i += 17) {
        g_assert_cmphex(femu_read_pages(&c, i, 1, buf, list), ==,
                        NVME_SUCCESS);
        g_assert_cmphex(qtest_readb(qts, buf + 4095), ==, want[i]);
    }

    host = femu_c0h_field(&c, log, 8);
    gc = femu_c0h_field(&c, log, 16);
    nand = femu_c0h_field(&c, log, 24);
    map = femu_c0h_field(&c, log, 280);
    pad = femu_c0h_field(&c, log, 264);
    g_test_message("host %" PRIu64 " nand %" PRIu64 " gc %" PRIu64
                   " map %" PRIu64, host, nand, gc, map);
    g_assert_cmpuint(gc, >, 0);
    g_assert_cmpuint(map, >, v[5]);
    g_assert_cmpuint(femu_c0h_field(&c, log, 0) & 0xffffffff, ==,
                     (nand + gc + map + pad) * 1000 / host);
    /* query-femu shows a CSD namespace without the line counters */
    if (!g_str_equal(data, "csd")) {
        femu_query_matches_c0h(&c, log);
        femu_query_check_lines(qts, id, pages);
    }
    /* fw_gc_page_ns=1000: each data move and each TP move takes one slot */
    if (g_str_equal(data, "fw")) {
        uint64_t f[4];

        femu_gc_fw_counts(&c, log, id, f);
        g_test_message("gc_fw dftl: %" PRIu64 " moved, %" PRIu64 " slots, %"
                       PRIu64 " fw ns, %" PRIu64 " TP moves",
                       f[0], f[1], f[2], f[3]);
        g_assert_cmpuint(f[3], >, 0);
        g_assert_cmpuint(f[1], ==, f[0] + f[3]);
        g_assert_cmpuint(f[2], ==, f[1] * 1000);
    }

    guest_free(alloc, log);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * The media charge of the TPs of mapping=dftl. dftl-tp checks the TP
 * counters; this test checks that each TP read and program is also a
 * media read or program (fields 6 and 7 of x-ftl-trace), so a refactor
 * cannot keep the counters and lose the time.
 *
 *   "slot": one CMT slot, 4 TPs of 512 mappings
 *     fill 2048 pages       READ 0  PROGRAM 2048 + 3 evicted TPs
 *     read page 0           READ 2  (TP 0, then the data page)
 *                           PROGRAM + 1 (TP 3 evicted)
 *   "cached": the default cache holds all 4 TPs (the control)
 *     fill 2048 pages       READ 0  PROGRAM 2048
 *     read page 0           READ 1  PROGRAM 2048
 *
 * "slot" then overwrites random pages until collection moves TPs, and
 * checks that every program is a data, collection or TP program.
 */
void femu_test_dftl_tp_charge(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    bool slot = g_str_equal(data, "slot");
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    const char *id = "/machine/peripheral/tp";
    FemuCtrlState c = { 0 };
    const uint32_t pages = 2048;
    uint64_t buf = guest_alloc(alloc, 64 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t log = guest_alloc(alloc, 4096);
    uint64_t v[7];
    uint32_t seed = 5;
    uint32_t i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    for (i = 0; i < pages / 64; i++) {
        qtest_memset(qts, buf, 0x10 + i, 64 * 4096);
        g_assert_cmphex(FEMU_SC(femu_write_pages(&c, i * 64, 64, buf, list)),
                        ==, NVME_SUCCESS);
    }
    g_assert_cmpuint(femu_ftl_trace_id(qts, "tp", 3), ==, pages);
    g_assert_cmpuint(femu_ftl_trace_id(qts, "tp", 6), ==, 0);
    g_assert_cmpuint(femu_ftl_trace_id(qts, "tp", 7), ==,
                     pages + (slot ? 3 : 0));

    g_assert_cmphex(femu_read_pages(&c, 0, 1, buf, list), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, buf), ==, 0x10);
    g_assert_cmpuint(femu_ftl_trace_id(qts, "tp", 6), ==, slot ? 2 : 1);
    g_assert_cmpuint(femu_ftl_trace_id(qts, "tp", 7), ==,
                     pages + (slot ? 4 : 0));

    if (slot) {
        for (i = 0; i < 6000; i++) {
            seed = seed * 1103515245 + 12345;
            qtest_memset(qts, buf, 0x80 + (i & 0x3f), 4096);
            g_assert_cmphex(FEMU_SC(femu_write_pages(&c, (seed >> 8) % pages,
                                                     1, buf, list)),
                            ==, NVME_SUCCESS);
        }
        femu_tp_check(qts, id, v);
        g_assert_cmpuint(v[5], >, 0);
        /* each program is a host page, a moved page or a TP (C0h 280) */
        g_assert_cmpuint(femu_ftl_trace_id(qts, "tp", 7), ==,
                         femu_ftl_trace_id(qts, "tp", 3) +
                         femu_ftl_trace_id(qts, "tp", 4) +
                         femu_c0h_field(&c, log, 280));
    }

    guest_free(alloc, log);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * Program/erase suspend, end to end. On one LUN, a write that programs NAND
 * and a read of a page written before go in one doorbell ring, so the read
 * reaches the media while the program is in flight. Off, the read waits out
 * the program and completes second; on, it preempts the program and
 * completes first. The program is 5000 times longer than the read, so how
 * loaded the host is cannot swap them. @data is "on" when the device has
 * suspend turned on.
 *
 * bbssd programs on every write. ZNS fills a write cache and programs it when
 * the next write finds it full, so the test first finds which write programs:
 * the first one that takes the program time. On a KV device (@data "kv-on"
 * or "kv-off") a store of key @page writes and a retrieve reads.
 */
#define PE_SUSPEND_SLOW_US  100000

void femu_test_pe_suspend(void *obj, void *data,
                          QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    bool on = g_str_has_suffix(data, "-on") || g_str_equal(data, "on");
    bool kv = g_str_has_prefix(data, "kv");
    FemuCtrlState c = { 0 };
    FemuQueue q;
    NvmeRwCmd rw;
    uint64_t buf;
    uint64_t page = 0;
    uint64_t fill;
    uint16_t cid[2];
    int i;

    if (kv) {
        femu_enable_csi(&c, &femu->dev, alloc);
    } else {
        femu_enable(&c, &femu->dev, alloc);
    }
    femu_zap_create_queue(&c, &q, 1);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    qtest_memset(qts, buf, 0x6b, FEMU_DATA_SIZE);

    memset(&rw, 0, sizeof(rw));
    rw.nsid = cpu_to_le32(1);
    rw.dptr.prp1 = cpu_to_le64(buf);
    rw.nlb = cpu_to_le16(FEMU_DATA_SIZE / c.lba_size - 1);

    for (;;) {
        int64_t t0 = g_get_monotonic_time();

        g_assert_cmpuint(page, <, 1024);
        femu_pe_suspend_rw(&c, &q, &rw, kv, NVME_CMD_WRITE, page++);
        femu_zap_ring(&c, &q);
        g_assert_cmpint(femu_zap_complete(&c, &q, NULL), ==, NVME_SUCCESS);
        if (g_get_monotonic_time() - t0 >= PE_SUSPEND_SLOW_US) {
            break;
        }
    }
    /*
     * The write that programmed is in the next cache now: fill it up to the
     * write that will program it.
     */
    fill = page >= 2 ? page - 2 : 0;
    g_test_message("write %" PRIu64 " programs; %" PRIu64 " more fill the "
                   "cache", page, fill);
    while (fill--) {
        femu_pe_suspend_rw(&c, &q, &rw, kv, NVME_CMD_WRITE, page++);
        femu_zap_ring(&c, &q);
        g_assert_cmpint(femu_zap_complete(&c, &q, NULL), ==, NVME_SUCCESS);
    }

    femu_pe_suspend_rw(&c, &q, &rw, kv, NVME_CMD_WRITE, page++);
    femu_pe_suspend_rw(&c, &q, &rw, kv, NVME_CMD_READ, 0);
    femu_zap_ring(&c, &q);
    for (i = 0; i < 2; i++) {
        uint64_t slot = q.cq_addr + q.cq_head * sizeof(NvmeCqe);
        NvmeCqe cqe;

        g_assert_cmpint(femu_zap_complete(&c, &q, NULL), ==, NVME_SUCCESS);
        qtest_memread(qts, slot, &cqe, sizeof(cqe));
        cid[i] = le16_to_cpu(cqe.cid);
    }
    g_test_message("suspend %s: cid %u completed before cid %u",
                   on ? "on" : "off", cid[0], cid[1]);
    /* the write took cid c.cid - 2 and the read c.cid - 1 */
    g_assert_cmpuint(cid[0], ==, on ? c.cid - 1 : c.cid - 2);
    g_assert_cmpuint(cid[1], ==, on ? c.cid - 2 : c.cid - 1);

    guest_free(alloc, buf);
    femu_queue_free(&c, &q);
    femu_disable(&c);
}

/* Delete must finish even when two SQs share a full CQ. */
void femu_test_ns_retire(void *obj, void *data, QGuestAllocator *alloc)
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

/* submit @cmd on the I/O queue and wait until its entry is posted */
static void femu_io_unconsumed(FemuCtrlState *c, NvmeCmd *cmd)
{
    uint64_t slot = c->io.cq_addr + c->io.cq_head * sizeof(NvmeCqe);

    femu_submit(c, &c->io, cmd);
    FEMU_WAIT_FOR((le16_to_cpu(qtest_readw(c->pdev->bus->qts, slot + 14)) &
                   1) == c->io.phase);
}

/* ms from @t0 until the MSI at @msi_addr arrives */
static int64_t femu_msi_wait_ms(QTestState *qts, uint64_t msi_addr, int64_t t0)
{
    FEMU_WAIT_FOR(qtest_readl(qts, msi_addr) == 0x4321);
    return (g_get_monotonic_time() - t0) / 1000;
}

#define FEMU_INTC_TRIES 5

/*
 * The shortest of FEMU_INTC_TRIES rounds, in ms from the submit to the MSI.
 * A round sends @nr reads, or with @err one read past the end, and reaps
 * them. A held interrupt is in every round, so the minimum keeps it; a
 * busy host slows only some rounds. With @held, no MSI may come in the
 * aggregation time after the post. The test can check that only when it
 * read the MSI address within 19 ms of the submit.
 *
 * Each round starts with an admin command (Get Features 08h). The admin
 * queue shares the vector, and its completion signals the vector at once,
 * with the CQE: what the vector still holds goes with it. So no entry or
 * interrupt of an earlier round reaches the round.
 */
static int64_t femu_intc_min_ms(FemuCtrlState *c, uint64_t msi_addr,
                                uint64_t buf, int nr, bool err, bool held)
{
    QTestState *qts = c->pdev->bus->qts;
    int64_t best = INT64_MAX;
    NvmeRwCmd rw;

    for (int t = 0; t < FEMU_INTC_TRIES; t++) {
        int64_t t0;

        g_assert_cmpint(femu_get_feature(c, 0x08, 0, 0, 0, NULL), ==,
                        NVME_SUCCESS);
        qtest_writel(qts, msi_addr, 0);
        t0 = g_get_monotonic_time();
        if (err) {
            memset(&rw, 0, sizeof(rw));
            rw.opcode = NVME_CMD_READ;
            rw.nsid = cpu_to_le32(1);
            rw.dptr.prp1 = cpu_to_le64(buf);
            rw.slba = cpu_to_le64(1ULL << 40);
            rw.nlb = cpu_to_le16(7);
            femu_io_unconsumed(c, (NvmeCmd *)&rw);
        } else {
            for (int i = 0; i < nr - 1; i++) {
                memset(&rw, 0, sizeof(rw));
                rw.opcode = NVME_CMD_READ;
                rw.nsid = cpu_to_le32(1);
                rw.dptr.prp1 = cpu_to_le64(buf);
                rw.nlb = cpu_to_le16(7);
                femu_submit(c, &c->io, (NvmeCmd *)&rw);
            }
            femu_read_unconsumed(c, buf);
        }
        if (held) {
            uint32_t early = qtest_readl(qts, msi_addr);

            if (g_get_monotonic_time() - t0 < 19000) {
                g_assert_cmphex(early, ==, 0);
            }
        }
        best = MIN(best, femu_msi_wait_ms(qts, msi_addr, t0));
        for (int i = 0; i < (err ? 1 : nr); i++) {
            uint16_t sc = FEMU_SC(femu_complete(c, &c->io, NULL, NULL));

            g_assert_cmpint(sc, ==, err ? NVME_LBA_RANGE : NVME_SUCCESS);
        }
    }
    return best;
}

/*
 * Interrupt Coalescing (Feature 08h) on an MSI vector. With the defaults a
 * completion interrupts at once. With a threshold of 4 entries (THR 3) and
 * 20 ms (TIME 200), one completion waits about 20 ms for its interrupt, and
 * four completions interrupt at once. A completion with an error, a vector
 * with Coalescing Disable (Feature 09h), and the admin queue are never held.
 * Each time is the shortest of FEMU_INTC_TRIES rounds (femu_intc_min_ms()).
 */
void femu_test_intc(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QPCIDevice *dev = &femu->dev;
    QTestState *qts = dev->bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint64_t msi_addr = guest_alloc(alloc, 4096);
    uint8_t msi = qpci_find_capability(dev, PCI_CAP_ID_MSI, 0);
    uint16_t flags;
    int64_t ms;

    g_assert_cmpint(msi, !=, 0);
    qpci_config_writel(dev, msi + PCI_MSI_ADDRESS_LO, (uint32_t)msi_addr);
    qpci_config_writel(dev, msi + PCI_MSI_ADDRESS_HI, msi_addr >> 32);
    qpci_config_writew(dev, msi + PCI_MSI_DATA_64, 0x4321);
    flags = qpci_config_readw(dev, msi + PCI_MSI_FLAGS);
    qpci_config_writew(dev, msi + PCI_MSI_FLAGS,
                       (flags & ~PCI_MSI_FLAGS_QSIZE) | PCI_MSI_FLAGS_ENABLE);
    femu_enable(&c, dev, alloc);
    femu_create_io_queues_irq(&c, 0);
    /* the first read of a fresh device is slow on some modes; not timed */
    femu_read_unconsumed(&c, buf);
    g_assert_cmpint(femu_complete(&c, &c.io, NULL, NULL), ==, NVME_SUCCESS);
    g_usleep(50 * 1000);

    /* defaults: no coalescing */
    ms = femu_intc_min_ms(&c, msi_addr, buf, 1, false, false);
    g_test_message("default: interrupt after %" PRId64 " ms", ms);
    g_assert_cmpint(ms, <, 10);

    g_assert_cmpint(femu_set_feature(&c, 0x08, false, 0, 3 | (200 << 8),
                                     NULL), ==, NVME_SUCCESS);
    /* the admin queue shares vector 0; let its interrupt land first */
    g_usleep(50 * 1000);

    /* one completion waits for the aggregation time */
    ms = femu_intc_min_ms(&c, msi_addr, buf, 1, false, true);
    g_test_message("THR 3, TIME 20 ms, 1 entry: interrupt after %" PRId64
                   " ms", ms);
    g_assert_cmpint(ms, >=, 19);
    g_assert_cmpint(ms, <, 120);

    /* four completions reach the threshold */
    ms = femu_intc_min_ms(&c, msi_addr, buf, 4, false, false);
    g_test_message("THR 3, TIME 20 ms, 4 entries: interrupt after %" PRId64
                   " ms", ms);
    g_assert_cmpint(ms, <, 15);

    /* a completion with an error is not held */
    ms = femu_intc_min_ms(&c, msi_addr, buf, 1, true, false);
    g_test_message("error entry: interrupt after %" PRId64 " ms", ms);
    g_assert_cmpint(ms, <, 15);

    /* Coalescing Disable on the vector */
    g_assert_cmpint(femu_set_feature(&c, 0x09, false, 0, 1 << 16, NULL), ==,
                    NVME_SUCCESS);
    g_usleep(50 * 1000);
    ms = femu_intc_min_ms(&c, msi_addr, buf, 1, false, false);
    g_test_message("CD set: interrupt after %" PRId64 " ms", ms);
    g_assert_cmpint(ms, <, 15);

    /* a controller disable with an entry held sends no interrupt */
    g_assert_cmpint(femu_set_feature(&c, 0x09, false, 0, 0, NULL), ==,
                    NVME_SUCCESS);
    g_usleep(50 * 1000);
    femu_read_unconsumed(&c, buf);
    qtest_writel(qts, msi_addr, 0);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    g_usleep(50 * 1000);
    g_assert_cmphex(qtest_readl(qts, msi_addr), ==, 0);
    flags = qpci_config_readw(dev, msi + PCI_MSI_FLAGS);
    qpci_config_writew(dev, msi + PCI_MSI_FLAGS, flags & ~PCI_MSI_FLAGS_ENABLE);
    guest_free(alloc, msi_addr);
    guest_free(alloc, buf);
}

/*
 * A band filed by past-due time instead of total time fails the bucket
 * check of femu_stages_check_bands() only when the two histograms differ.
 */
static void femu_stages_check_differ(QDict *ret)
{
    QDict *total = femu_stage(ret, "total");
    QDict *pd = femu_stage(ret, "past-due");
    bool differ = false;

    for (int b = 0; b < 40; b++) {
        differ |= femu_stage_bucket(total, b) != femu_stage_bucket(pd, b);
    }
    g_assert_true(differ);
}

/*
 * io_stages on a bbssd device. @data "3ms": eight single-page reads with a
 * 3 ms page read. The model gives each read exactly 3 ms from fetch to due,
 * so submit + ftl + hold is exactly 8 x 3 ms when no read comes back after
 * its due time, and total is at least that, whatever the host scheduler
 * does. @data "zero": with no read time every read comes back after its due
 * time, and the stages must still add up to total. Every stage keeps its
 * longest time in its highest non-empty bucket, and the bands agree
 * with the histograms. reset=true clears the counts and the bands.
 * @data NULL: io_stages is off, and the command must say so.
 */
void femu_test_io_stages(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    const char *names[] = { "submit", "ftl", "hold", "post-delay", "total",
                            "past-due" };
    bool zero = data && g_str_equal(data, "zero");
    QDict *rsp, *ret, *st;
    int i;

    if (!data) {
        rsp = qtest_qmp(qts, "{'execute':'query-femu-stages'}");
        g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                              "desc"), "set io_stages=on"));
        qobject_unref(rsp);
        guest_free(alloc, list);
        guest_free(alloc, buf);
        return;
    }

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x3c, 4096);
    g_assert_cmphex(FEMU_SC(femu_write_pages(&c, 0, 8, buf, list)), ==,
                    NVME_SUCCESS);
    rsp = qtest_qmp(qts, "{'execute':'query-femu-stages',"
                    "'arguments':{'reset':true}}");
    ret = qdict_get_qdict(rsp, "return");
    g_assert_cmpuint(qdict_get_int(femu_stage(ret, "total"), "count"), ==, 1);
    qobject_unref(rsp);

    for (i = 0; i < 8; i++) {
        g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_READ,
                                        i * (4096 / c.lba_size), buf)), ==,
                        NVME_SUCCESS);
    }
    rsp = qtest_qmp(qts, "{'execute':'query-femu-stages'}");
    ret = qdict_get_qdict(rsp, "return");
    for (i = 0; i < ARRAY_SIZE(names); i++) {
        st = femu_stage(ret, names[i]);
        g_test_message("%-10s count %" PRId64 " sum %" PRId64 " ns max %"
                       PRId64 " ns", names[i], qdict_get_int(st, "count"),
                       qdict_get_int(st, "sum-ns"),
                       qdict_get_int(st, "max-ns"));
        g_assert_cmpuint(qdict_get_int(st, "count"), ==, 8);
        femu_stage_check_buckets(st);
    }
    femu_stages_check_sum(ret);
    g_assert_cmpuint(qdict_get_int(femu_stage(ret, "past-due"), "sum-ns"), >,
                     0);
    /* io_causes is off: no cause tables */
    g_assert_false(qdict_haskey(ret, "causes"));
    femu_stages_check_bands(ret);
    if (!zero) {
        /* with a 3 ms read, past-due time is far below total time */
        femu_stages_check_differ(ret);
    }
    if (zero) {
        g_test_message("returned after due: %" PRId64,
                       qdict_get_int(ret, "returned-after-due"));
        g_assert_cmpuint(qdict_get_int(femu_stage(ret, "hold"), "sum-ns"), ==,
                         0);
    } else {
        uint64_t to_ready =
            qdict_get_int(femu_stage(ret, "submit"), "sum-ns") +
            qdict_get_int(femu_stage(ret, "ftl"), "sum-ns") +
            qdict_get_int(femu_stage(ret, "hold"), "sum-ns");

        g_test_message("fetch to ready: %" PRIu64 " ns, returned after due: %"
                       PRId64, to_ready,
                       qdict_get_int(ret, "returned-after-due"));
        if (!qdict_get_int(ret, "returned-after-due")) {
            g_assert_cmpuint(to_ready, ==, 8 * 3000000ULL);
        } else {
            g_assert_cmpuint(to_ready, >=, 8 * 3000000ULL);
        }
        g_assert_cmpuint(qdict_get_int(femu_stage(ret, "total"), "sum-ns"),
                         >=, 8 * 3000000ULL);
    }
    qobject_unref(rsp);

    rsp = qtest_qmp(qts, "{'execute':'query-femu-stages',"
                    "'arguments':{'reset':true}}");
    qobject_unref(rsp);
    rsp = qtest_qmp(qts, "{'execute':'query-femu-stages'}");
    ret = qdict_get_qdict(rsp, "return");
    for (i = 0; i < ARRAY_SIZE(names); i++) {
        st = femu_stage(ret, names[i]);
        g_assert_cmpuint(qdict_get_int(st, "count"), ==, 0);
        g_assert_cmpuint(qdict_get_int(st, "sum-ns"), ==, 0);
        g_assert_cmpuint(qdict_get_int(st, "max-ns"), ==, 0);
    }
    g_assert_cmpuint(qdict_get_int(ret, "returned-after-due"), ==, 0);
    g_assert_cmpuint(qlist_size(qdict_get_qlist(ret, "bands")), ==, 0);
    qobject_unref(rsp);

    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_disable(&c);
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
void femu_test_dma_error(void *obj, void *data, QGuestAllocator *alloc)
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

/*
 * Copy descriptor format 2 (NVM 1.2, 3.3.2): each range names the namespace
 * it comes from, which has to be a block namespace formatted the same way;
 * only ranges in the destination namespace can overlap the destination. The
 * host has to enable the format through Host Behavior Support first.
 */
void femu_test_copy_fmt2(void *obj, void *data, QGuestAllocator *alloc)
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

void femu_test_pi_rw(void *obj, void *data, QGuestAllocator *alloc)
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

            if (first) {
                /* NVM 1.1 Figure 114: no PI in the first metadata bytes */
                if (!create) {
                    g_assert_cmpint(femu_format_dw10(&c, FEMU_MD_NLBAF |
                                   (type << 5) | (first << 8) |
                                   (extended << 4)), ==, NVME_INVALID_FORMAT);
                }
                continue;
            }
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
                g_assert_cmphex(qtest_readb(qts, mbuf + 28), ==, 0x17);
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

void femu_test_pi_copy(void *obj, void *data, QGuestAllocator *alloc)
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

            if (first) {
                /* NVM 1.1 Figure 114: no PI in the first metadata bytes */
                g_assert_cmpint(femu_pi_format_ns(&c, 1, format), ==,
                               NVME_INVALID_FORMAT);
                continue;
            }
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

/*
 * Separate LBA metadata (NVM 1.2, 2.1.4): each block size is offered with and
 * without metadata, the device boots on the one with it, and every command
 * that moves or drops blocks treats their metadata the same way.
 */
void femu_test_metadata(void *obj, void *data, QGuestAllocator *alloc)
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
    g_assert_cmphex(femu_io_status & NVME_DNR, ==, NVME_DNR);

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

/*
 * x-fuzz, the mode of QEMU's generic fuzzer: admin commands complete, no
 * poller thread serves the I/O queues, and a system reset disables the
 * controller and zeroes the queue memory it used. Without x-fuzz the same
 * Read completes, so the check fails when the property no longer stops the
 * dataplane. data: 0 x-fuzz off, 1 NoSSD, 2 BBSSD.
 */
void femu_test_fuzz_mode(void *obj, void *data, QGuestAllocator *alloc)
{
    int kind = GPOINTER_TO_INT(data);
    bool fuzz = kind != 0;
    QOSState *qs = qtest_pc_boot(
        "-machine pc -nodefaults -device femu,id=fm,addr=5,queues=2%s%s",
        kind == 2 ? ",femu_mode=1,devsz_mb=1,secsz=512,secs_per_pg=8,"
        "pgs_per_blk=4,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,nchs=1" :
        ",femu_mode=2,devsz_mb=16", fuzz ? ",x-fuzz=on" : "");
    QTestState *qts = qs->qts;
    QPCIDevice *pdev = qpci_device_find(qs->pcibus, QPCI_DEVFN(5, 0));
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(&qs->alloc, 4096);
    NvmeRwCmd rw;
    NvmeCmd sqe;
    NvmeCqe cqe;

    femu_enable(&c, pdev, &qs->alloc);
    g_assert_cmpint(femu_identify(&c, 0, NVME_ID_CNS_CTRL, 0, buf), ==,
                    NVME_SUCCESS);
    femu_create_io_queues(&c);

    memset(&rw, 0, sizeof(rw));
    rw.opcode = NVME_CMD_READ;
    rw.nsid = cpu_to_le32(1);
    rw.dptr.prp1 = cpu_to_le64(buf);
    femu_submit(&c, &c.io, (NvmeCmd *)&rw);
    if (!fuzz) {
        g_assert_cmpint(femu_complete(&c, &c.io, NULL, NULL), ==,
                        NVME_SUCCESS);
    } else {
        /* a poller completes a Read in microseconds */
        g_usleep(200 * 1000);
        qtest_memread(qts, c.io.cq_addr, &cqe, sizeof(cqe));
        g_assert_cmpint(le16_to_cpu(cqe.status) & 1, ==, 0);

        qtest_qmp_assert_success(qts, "{'execute':'system_reset'}");
        qtest_qmp_eventwait(qts, "RESET");
        qpci_device_enable(pdev);
        c.bar = qpci_iomap(pdev, 0, NULL);
        g_assert_cmphex(qpci_io_readl(pdev, c.bar, 0x14), ==, 0);
        g_assert_cmphex(qpci_io_readl(pdev, c.bar, 0x1c), ==, 0);
        g_assert_cmphex(qpci_io_readl(pdev, c.bar, 0x24), ==, 0);

        /* the queued Read is gone, so no later input runs this one's bytes */
        qtest_memread(qts, c.io.sq_addr, &sqe, sizeof(sqe));
        g_assert_cmpint(sqe.opcode, ==, 0);
        g_assert_cmpint(le16_to_cpu(sqe.cid), ==, 0);

        /* the next input starts the controller again from nothing */
        femu_queue_free(&c, &c.admin);
        femu_queue_free(&c, &c.io);
        femu_enable(&c, pdev, &qs->alloc);
        g_assert_cmpint(femu_identify(&c, 0, NVME_ID_CNS_CTRL, 0, buf), ==,
                        NVME_SUCCESS);
        femu_create_io_queues(&c);
    }

    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    guest_free(&qs->alloc, buf);
    g_free(pdev);
    qtest_pc_shutdown(qs);
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
void femu_test_io_fuzz(void *obj, void *data, QGuestAllocator *alloc)
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
    GRand *rng = g_rand_new_with_seed(femu_fuzz_seed(0x494f4655));
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

    for (i = 0; i < femu_fuzz_rounds(FEMU_IO_FUZZ_ROUNDS); i++) {
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

/* x-opal accepts one NoSSD or page-mapped bbssd namespace, nothing else */
void femu_test_opal_refused(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    static const char bb[] = "'femu_mode':1,'secsz':512,'secs_per_pg':8,"
                             "'pgs_per_blk':8,'luns_per_ch':2,'nchs':2,"
                             "'pls_per_lun':1,'blks_per_pl':32";
    const struct {
        const char *opts;
        const char *msg;
    } cases[] = {
        { "'femu_mode':2", NULL },
        { bb, NULL },
        { "'femu_mode':2,'namespaces':2", "more than one namespace" },
        { "'femu_mode':2,'namespace_modes':'nossd'", "namespace_modes" },
        { "'femu_mode':2,'ns_wp':true", "ns_wp" },
        { "'femu_mode':2,'sanitize_ns':true", "sanitize_ns" },
        { "'femu_mode':2,'ns_mgmt':true", "ns_mgmt" },
        { "MAP:hybrid", "a bbssd mapping other than page" },
    };
    QDict *rsp;

    for (int i = 0; i < ARRAY_SIZE(cases); i++) {
        g_autofree char *opts = NULL;
        g_autofree char *cmd = NULL;

        if (g_str_has_prefix(cases[i].opts, "MAP:")) {
            opts = g_strdup_printf("%s,'mapping':'%s'", bb,
                                   cases[i].opts + 4);
        } else {
            opts = g_strdup(cases[i].opts);
        }
        cmd = g_strdup_printf("{'execute':'device_add','arguments':{"
                              "'driver':'femu','id':'opr%d','addr':'%d',"
                              "'devsz_mb':2,'x-opal':true,%s}}",
                              i, 5 + i, opts);
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

void femu_test_ns_mgmt_commands(void *obj, void *data,
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

/*
 * With mixed namespace modes the controller is named by its own femu_mode.
 * It used to take the name of whichever namespace was brought up last, so a
 * black-box controller with a NoSSD namespace last called itself a NoSSD
 * controller. A controller with no namespace of its own mode is named from
 * that mode too.
 */
void femu_test_namespace_mixed_identity(void *obj, void *data,
                                                QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    const FemuIdentity *want = data;
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    char serial[21] = { 0 };
    char model[41] = { 0 };

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmpint(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);
    qtest_memread(c.pdev->bus->qts, buf + 4, serial, 20);
    qtest_memread(c.pdev->bus->qts, buf + 24, model, 40);
    g_strchomp(serial);
    g_strchomp(model);
    g_assert_cmpstr(serial, ==, want->serial);
    g_assert_cmpstr(model, ==, want->model);
    femu_disable(&c);

    /*
     * The namespace of the other mode still took a serial from its mode's
     * counter, so the next controller of that mode gets the one after it.
     */
    if (want->other_serial) {
        QTestState *qts = femu->dev.bus->qts;
        QPCIDevice *pdev;
        QDict *rsp;

        rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                        "'driver':'femu','id':'next','addr':'5',"
                        "'devsz_mb':64,'femu_mode':%d}}", want->other_mode);
        g_assert_true(qdict_haskey(rsp, "return"));
        qobject_unref(rsp);
        pdev = qpci_device_find(femu->dev.bus, QPCI_DEVFN(5, 0));
        g_assert_nonnull(pdev);
        memset(&c, 0, sizeof(c));
        femu_enable(&c, pdev, alloc);
        g_assert_cmpint(femu_identify(&c, 0, 1, 0, buf), ==, NVME_SUCCESS);
        qtest_memread(qts, buf + 4, serial, 20);
        g_strchomp(serial);
        g_assert_cmpstr(serial, ==, want->other_serial);
        femu_disable(&c);
        g_free(pdev);
        qos_invalidate_command_line();
    }
    guest_free(alloc, buf);
}

/*
 * Vendor admin command 0xEE sets the NAND times of an Open-Channel device.
 * It wrote fields no timing code read; now an erase takes the time it sets.
 * Other modes have no use for it and refuse it.
 */
void femu_test_oc_set_latency(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    NvmeCmd cmd;
    uint64_t geo, buf;
    uint8_t g[128];
    uint8_t sec_len;
    uint16_t want, got;
    int64_t start;
    int i;

    femu_enable(&c, &femu->dev, alloc);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = 0xee;
    cmd.cdw10 = cpu_to_le32(64000);         /* upper page read */
    cmd.cdw11 = cpu_to_le32(48000);         /* lower page read */
    cmd.cdw12 = cpu_to_le32(2300000);       /* upper page program */
    cmd.cdw13 = cpu_to_le32(850000);        /* lower page program */
    cmd.cdw14 = cpu_to_le32(40000000);      /* block erase, 40 ms */
    cmd.cdw15 = cpu_to_le32(52433);         /* channel transfer */
    if (!data) {
        g_assert_cmpint(FEMU_SC(femu_admin(&c, &cmd)), ==,
                        NVME_INVALID_OPCODE);
        femu_disable(&c);
        return;
    }
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);

    femu_create_io_queues(&c);
    geo = guest_alloc(alloc, 4096);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_OC20_IDENTIFY;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(geo);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    qtest_memread(femu->dev.bus->qts, geo, g, sizeof(g));
    sec_len = g[11];

    buf = guest_alloc(alloc, 4096);
    for (i = 0; i < 4; i++) {
        uint64_t chunk = (uint64_t)(i + 1) << sec_len;

        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = FEMU_OC20_VECT_WRITE;
        cmd.nsid = cpu_to_le32(1);
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
    for (i = 0; i < 4; i++) {
        uint64_t chunk = (uint64_t)(i + 1) << sec_len;

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
    /* four 40 ms erases of one unit; the default MLC erase is 3 ms */
    g_assert_cmpint(g_get_monotonic_time() - start, >, 160000);
    femu_disable(&c);
    guest_free(alloc, buf);
    guest_free(alloc, geo);
}

/* Preserve the legacy mode initializers' identity consumption. */
void femu_test_namespace_failure_naming(void *obj, void *data,
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

void femu_test_namespace_sanitize_bounds(void *obj, void *data,
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

/* device_add with @args fails, and the message holds @want */
static void femu_precon_refuse(QTestState *qts, const char *args,
                               const char *want)
{
    g_autofree char *json = g_strdup_printf(
        "{'driver':'femu','id':'pr','addr':'5','devsz_mb':16,%s}", args);
    QObject *obj = qobject_from_json(json, &error_abort);
    QDict *rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':%p}",
                           obj);
    const char *desc;

    g_assert_true(qdict_haskey(rsp, "error"));
    desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
    g_test_message("precon refused {%s}: %s", args, desc);
    g_assert_nonnull(strstr(desc, want));
    qobject_unref(rsp);
}

/* properties precon_fill_pct refuses, each with a message naming why */
void femu_test_precon_refused(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;

    femu_precon_refuse(qts, "'femu_mode':3,'precon_fill_pct':50",
                       "a mode other than bbssd");
    femu_precon_refuse(qts, "'femu_mode':1,'precon_fill_pct':50,"
                       "'gc_policy':'cost-benefit'", "gc_policy=cost-benefit");
    femu_precon_refuse(qts, "'femu_mode':1,'precon_fill_pct':50,"
                       "'gc_idle_ms':10", "gc_idle_ms");
    femu_precon_refuse(qts, "'femu_mode':1,'precon_fill_pct':50,"
                       "'pd_open_close_sec':5", "pd_open_close_sec");
    femu_precon_refuse(qts, "'femu_mode':1,'precon_fill_pct':50,"
                       "'err_write_fail_ppm':10", "err_write_fail_ppm");
    femu_precon_refuse(qts, "'femu_mode':1,'precon_fill_pct':50,"
                       "'mapping':'dftl'", "a mapping other than page");
    femu_precon_refuse(qts, "'femu_mode':1,'precon_fill_pct':50,"
                       "'retention_limit_sec':60", "retention_limit_sec");
    femu_precon_refuse(qts, "'femu_mode':1,'precon_fill_pct':50,"
                       "'blk_pe_limit':100", "eol_read_only");
    femu_precon_refuse(qts, "'femu_mode':1,'precon_fill_pct':50,"
                       "'namespaces':2", "more than one namespace");
    qos_invalidate_command_line();
    femu_precon_refuse(qts, "'femu_mode':1,'precon_fill_pct':101",
                       "0 to 100");
    femu_precon_refuse(qts, "'femu_mode':1,'precon_overwrite_pct':100",
                       "need precon_fill_pct");
    femu_precon_refuse(qts, "'femu_mode':1,'precon_fill_pct':50,"
                       "'precon_overwrite_pct':1001", "0 to 1000");
    femu_precon_refuse(qts, "'femu_mode':1,'precon_fill_pct':50,"
                       "'precon_pattern':'zigzag'", "rand or seq");
}

/*
 * femu-save-data: page 2 is written, a checkpoint taken, page 2 written
 * again, and the device removed. A device added with the checkpoint as
 * persist_file reads the first data. A device with metadata cannot take
 * a checkpoint, and a file another device keeps cannot take one.
 */
void femu_test_checkpoint(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    g_autofree char *dir = g_dir_make_tmp("femu-ckpt-XXXXXX", NULL);
    g_autofree char *file = g_build_filename(dir, "ckpt", NULL);
    g_autofree char *lock = g_strconcat(file, ".lock", NULL);
    g_autofree char *extra = g_strdup_printf(",'femu_mode':1,"
                                             "'persist_file':'%s'", file);
    uint64_t buf = guest_alloc(alloc, 4096);
    FemuCtrlState c = { 0 };
    QPCIDevice *pdev;
    char *err;

    femu_ckpt_add(qts, "ck", 5, ",'femu_mode':1");
    pdev = qpci_device_find(femu->dev.bus, QPCI_DEVFN(5, 0));
    femu_enable(&c, pdev, alloc);
    femu_create_io_queues(&c);
    femu_ns_page(&c, buf, 1, 2, 0x21, true);
    g_assert_null(femu_save_data(qts, "ck", file));
    femu_ns_page(&c, buf, 1, 2, 0x77, true);
    femu_disable(&c);
    femu_queue_free(&c, &c.io);
    qpci_unplug_acpi_device_test(qts, "ck", 5);
    g_free(pdev);

    memset(&c, 0, sizeof(c));
    femu_ckpt_add(qts, "ck2", 5, extra);
    pdev = qpci_device_find(femu->dev.bus, QPCI_DEVFN(5, 0));
    femu_enable(&c, pdev, alloc);
    femu_create_io_queues(&c);
    femu_ns_page(&c, buf, 1, 2, 0x21, false);
    /* ck2 keeps the file: another device cannot write it */
    femu_ckpt_add(qts, "cx", 6, ",'femu_mode':1");
    err = femu_save_data(qts, "cx", file);
    g_assert_nonnull(err);
    g_assert_nonnull(strstr(err, "in use"));
    g_free(err);
    qpci_unplug_acpi_device_test(qts, "cx", 6);
    /* ck2 can write its own file, but not over a lock file */
    g_assert_null(femu_save_data(qts, "ck2", file));
    err = femu_save_data(qts, "ck2", lock);
    g_assert_nonnull(err);
    g_assert_nonnull(strstr(err, ".lock"));
    g_free(err);
    femu_ckpt_add(qts, "cz", 6, ",'femu_mode':2,'meta':8,'mc':2");
    err = femu_save_data(qts, "cz", file);
    g_assert_nonnull(err);
    g_assert_nonnull(strstr(err, "not supported with"));
    g_free(err);
    qpci_unplug_acpi_device_test(qts, "cz", 6);
    femu_disable(&c);
    femu_queue_free(&c, &c.io);
    qpci_unplug_acpi_device_test(qts, "ck2", 5);
    g_free(pdev);
    guest_free(alloc, buf);
    unlink(lock);
    unlink(file);
    rmdir(dir);
}

void femu_test_ns_mgmt_unavailable(void *obj, void *data,
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

void femu_test_streams_resources(void *obj, void *data,
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

void femu_test_streams_write(void *obj, void *data,
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

/*
 * x-ftl-fail-at=k fails the k-th FTL allocation of a realize. Each k must
 * refuse the device with an error that names k, and QEMU must go on. The
 * sanitizer build aborts when the failed build leaves a charge. The sweep
 * stops at the first k that starts the device: every allocation before it
 * failed once.
 */
#define FEMU_FAIL_GEO "devsz_mb=1,secsz=512,secs_per_pg=8,pgs_per_blk=8," \
                      "blks_per_pl=12,pls_per_lun=1,luns_per_ch=2,nchs=2"

void femu_test_ftl_fail_sweep(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    /*
     * One FTL has 16 allocations: the 12 NAND tree arrays (with one
     * array of page states), the L2P, the reverse map, the lines and the
     * victim heap. KV has no L2P.
     */
    static const struct {
        const char *opts;
        uint32_t allocs;
        bool selftest;  /* FEMU_KV_SELFTEST builds the KV FTL twice */
        const char *pre;        /* more of the QEMU command line */
    } cases[] = {
        { "femu_mode=1," FEMU_FAIL_GEO, 16 },
        /* the second FTL fails after the first one is whole */
        { "femu_mode=1,namespaces=2," FEMU_FAIL_GEO, 2 * 16 },
        { "femu_mode=4,fdm_size=16,csd_slm_size=4," FEMU_FAIL_GEO, 16 },
        { "femu_mode=5," FEMU_FAIL_GEO, 15 },
        { "femu_mode=5," FEMU_FAIL_GEO, 2 * 15, true },
        /* the optional parts, each on top of the 16 */
        { "femu_mode=1,read_cache_mb=1," FEMU_FAIL_GEO, 16 + 2 },
        { "femu_mode=1,rain_parity=1," FEMU_FAIL_GEO, 2 + 16 },
        { "femu_mode=1,buffer_size=16,power_loss=on,durable_at_done=on,"
          FEMU_FAIL_GEO, 16 + 1 },
        { "femu_mode=1,mapping=hybrid," FEMU_FAIL_GEO, 16 + 4 },
        { "femu_mode=1,mapping=fast," FEMU_FAIL_GEO, 16 + 3 },
        { "femu_mode=1,die_stats=on," FEMU_FAIL_GEO, 16 + 1 },
        { "femu_mode=1,pg_xfer_lat=1000," FEMU_FAIL_GEO, 16 + 1 },
        /* one FTL with two slices: the table, counters, query-stats copies */
        { "femu_mode=1,namespaces=2,shared_ftl=on," FEMU_FAIL_GEO, 16 + 3 },
        /*
         * 2^20 pages: the page states, the L2P and the reverse map each
         * reach 1 MiB and get their own mapping
         */
        { "femu_mode=1,devsz_mb=1,secsz=512,secs_per_pg=8,pgs_per_blk=256,"
          "blks_per_pl=1024,pls_per_lun=1,luns_per_ch=2,nchs=2", 16 },
        /*
         * 13 lines: a NAND tree of 12 arrays, 4 more of its own, the mapping
         * cache slots and hash, and 7 translation page arrays
         */
        { FEMU_MEM_FTL13 ",mapping=dftl,mapping_cache_mb=1", 12 + 4 + 2 + 7 },
        /*
         * The static pSLC tier on 32 blocks of TLC: a NAND tree of
         * 1 + 1 + 2 + 4 + 4 arrays, the tier header and its 4 arrays,
         * then the maps, the lines and the heap
         */
        { "femu_mode=1,devsz_mb=16,secsz=512,secs_per_pg=8,pgs_per_blk=48,"
          "blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,nchs=2,"
          "nand_cell_type=3,tier_mode=static,tier_static_mb=1",
          12 + 5 + 4 },
        /*
         * FDP, 2 groups of 80 units and 4 handles. After the NAND tree of
         * 12 arrays and the 4 of the maps and lines: the group and unit
         * arrays (2), per group the units, a manager and 2 heaps (8), the
         * block ids and group lines (2), a write pointer and line list per
         * unit (320), the handles and the written bitmap (2), and per
         * handle its active and collection unit arrays (8). The handles
         * are persistently isolated by default, so each also has a manager
         * array and a heap per group (12). The same options are added
         * again after each refusal on the one subsystem.
         */
        { "femu_mode=1,devsz_mb=1,secsz=512,secs_per_pg=8,pgs_per_blk=4,"
          "pls_per_lun=1,luns_per_ch=2,nchs=2,blks_per_pl=80,lba_index=3,"
          "subsys=failsub",
          12 + 4 + 2 + 8 + 2 + 320 + 2 + 8 + 12, false,
          "-device femu-subsys,id=failsub,nqn=failsub,fdp=on,fdp.nruh=4,"
          "fdp.nrg=2" },
    };

    for (size_t i = 0; i < ARRAY_SIZE(cases); i++) {
        const char *opts = cases[i].opts;
        g_autofree char *ctl = NULL;
        QTestState *qts;
        uint32_t k;

        /* QEMU inherits the variable, and each realize runs the selftest */
        if (cases[i].selftest) {
            g_setenv("FEMU_KV_SELFTEST", "1", true);
        }
        qts = qtest_initf("-machine pc -nodefaults %s", cases[i].pre ?: "");
        g_unsetenv("FEMU_KV_SELFTEST");

        /*
         * The control: the line starts with no injection. A subsystem case
         * skips it, so each refusal compares with a new subsystem, which
         * a working controller would have changed; the last add that
         * starts is its control.
         */
        if (!cases[i].pre) {
            ctl = qtest_hmp(qts, "device_add femu,addr=5,id=ff,%s", opts);
            if (*ctl) {
                g_test_message("%s: %s", opts, ctl);
                g_assert_not_reached();
            }
            qpci_unplug_acpi_device_test(qts, "ff", 5);
        }

        for (k = 1; k < 2000; k++) {
            g_autofree char *out = NULL;
            g_autofree char *want = NULL;
            g_autofree char *before = NULL;
            g_autofree char *after = NULL;

            /* a refusal leaves the subsystem as the last controller did */
            if (cases[i].pre) {
                before = femu_fdp_state(qts, "failsub");
            }
            out = qtest_hmp(qts, "device_add femu,addr=5,id=ff,%s,"
                            "x-ftl-fail-at=%u", opts, k);
            if (!*out) {
                qpci_unplug_acpi_device_test(qts, "ff", 5);
                break;
            }
            if (cases[i].pre) {
                after = femu_fdp_state(qts, "failsub");
                g_assert_cmpstr(after, ==, before);
            }
            want = g_strdup_printf("injected failure of FTL allocation %u (",
                                   k);
            if (!strstr(out, want)) {
                g_test_message("%s k=%u: %s", opts, k, out);
                g_assert_not_reached();
            }
        }
        g_test_message("%s: %u allocations failed in turn", opts, k - 1);
        g_assert_cmpuint(k - 1, ==, cases[i].allocs);
        qtest_quit(qts);
    }
}

/*
 * mem_limit: each take of a realize must match a charge, so x-mem-taken
 * equals the reply. The limit at that total starts the device; one byte
 * less refuses it, and the same QEMU then starts it at the total.
 */
void femu_test_mem_limit(void *obj, void *data,
                         QGuestAllocator *unused)
{
    static const struct {
        const char *opts;
        bool selftest;
        const char *pre;
    } cases[] = {
        { "femu_mode=2,devsz_mb=64" },
        { "femu_mode=2,devsz_mb=64,meta=8,mc=3" },
        { "femu_mode=2,devsz_mb=64,namespaces=2" },
        { "femu_mode=1," FEMU_FAIL_GEO },
        { "femu_mode=1,namespaces=2," FEMU_FAIL_GEO },
        { "femu_mode=1,namespaces=2,shared_ftl=on," FEMU_FAIL_GEO },
        { "femu_mode=1,read_cache_mb=1," FEMU_FAIL_GEO },
        { "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=8,luns_per_ch=2,"
          "nchs=2,pls_per_lun=1,rain_parity=1,mdts=4,devsz_mb=1,"
          "blks_per_pl=64,gc_thres_pcent_high=78,rain_read_only=on,"
          "rain_loss=on" },
        { "femu_mode=1,buffer_size=16,vwc=1,power_loss=on,sdc=on,"
          FEMU_FAIL_GEO },
        { "femu_mode=1,buffer_size=16,power_loss=on,durable_at_done=on,"
          FEMU_FAIL_GEO },
        { "femu_mode=1,mapping=hybrid," FEMU_FAIL_GEO },
        { "femu_mode=1,mapping=fast," FEMU_FAIL_GEO },
        { "femu_mode=1,die_stats=on," FEMU_FAIL_GEO },
        { "femu_mode=1,pg_xfer_lat=1000," FEMU_FAIL_GEO },
        { FEMU_MEM_FTL13 ",mapping=dftl,mapping_cache_mb=1" },
        { "femu_mode=1,devsz_mb=16,secsz=512,secs_per_pg=8,pgs_per_blk=48,"
          "blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,nchs=2,"
          "nand_cell_type=3,tier_mode=static,tier_static_mb=1" },
        { "femu_mode=4,fdm_size=16,csd_slm_size=4," FEMU_FAIL_GEO },
        { "femu_mode=5," FEMU_FAIL_GEO },
        { "femu_mode=5," FEMU_FAIL_GEO, true },
        { "femu_mode=5,devsz_mb=64,kv_index=lsm,kv_lsm_memtable_keys=1024" },
        /* FDP with one group and with two */
        { FEMU_FDP_REFUSE ",secs_per_pg=8,lba_index=3,subsys=s1", false,
          "-device femu-subsys,id=s1,nqn=s1,fdp=on,fdp.nruh=4" },
        { FEMU_FDP_REFUSE ",secs_per_pg=8,lba_index=3,subsys=s2", false,
          "-device femu-subsys,id=s2,nqn=s2,fdp=on,fdp.nruh=4,fdp.nrg=2,"
          "fdp.isolation_mode=1" },
    };

    for (size_t i = 0; i < ARRAY_SIZE(cases); i++) {
        const char *opts = cases[i].opts;
        g_autofree char *out = NULL;
        QTestState *qts;
        uint64_t total;
        uint64_t taken;

        if (cases[i].selftest) {
            g_setenv("FEMU_KV_SELFTEST", "1", true);
        }
        qts = qtest_initf("-machine pc -nodefaults %s", cases[i].pre ?: "");
        g_unsetenv("FEMU_KV_SELFTEST");

        out = qtest_hmp(qts, "device_add femu,addr=5,id=ml,%s", opts);
        if (*out) {
            g_test_message("%s: %s", opts, out);
            g_assert_not_reached();
        }
        total = femu_mem_total(qts, "ml", NULL);
        taken = femu_mem_taken(qts, "ml");
        g_test_message("%s: %" PRIu64 " bytes", opts, total);
        g_assert_cmpuint(taken, ==, total);
        qpci_unplug_acpi_device_test(qts, "ml", 5);

        g_free(out);
        out = qtest_hmp(qts, "device_add femu,addr=5,id=ml,%s,"
                        "mem_limit=%" PRIu64, opts, total - 1);
        if (!strstr(out, "femu: memory limit: ")) {
            g_test_message("%s, limit %" PRIu64 ": %s", opts, total - 1, out);
            g_assert_not_reached();
        }
        g_free(out);
        out = qtest_hmp(qts, "device_add femu,addr=5,id=ml,%s,"
                        "mem_limit=%" PRIu64, opts, total);
        if (*out) {
            g_test_message("%s, limit %" PRIu64 ": %s", opts, total, out);
            g_assert_not_reached();
        }
        g_assert_cmpuint(femu_mem_taken(qts, "ml"), ==, total);
        qpci_unplug_acpi_device_test(qts, "ml", 5);
        qtest_quit(qts);
    }
}

/* ZNS and open-channel builds abort on no memory, so a limit refuses them */
void femu_test_mem_limit_modes(void *obj, void *data,
                               QGuestAllocator *unused)
{
    static const struct {
        const char *opts;
        const char *want;
    } cases[] = {
        { "femu_mode=3,devsz_mb=64", "not available in ZNS mode" },
        { "femu_mode=0,devsz_mb=64", "not available in open-channel mode" },
        { "femu_mode=0,lver=1,devsz_mb=64",
          "not available in open-channel mode" },
        { "femu_mode=1,namespaces=2,namespace_modes=bbssd,,znssd,"
          FEMU_FAIL_GEO, "not available in ZNS mode" },
    };
    QTestState *qts = qtest_init("-machine pc -nodefaults");

    for (size_t i = 0; i < ARRAY_SIZE(cases); i++) {
        g_autofree char *out = qtest_hmp(qts, "device_add femu,addr=5,id=ml,"
                                         "%s,mem_limit=1G", cases[i].opts);

        if (!strstr(out, cases[i].want)) {
            g_test_message("%s: %s", cases[i].opts, out);
            g_assert_not_reached();
        }
    }
    qtest_quit(qts);
}

void femu_test_memory_ftl(void *obj, void *data,
                          QGuestAllocator *unused)
{
    static const struct {
        const char *opts;
        uint32_t nr_ftl;
    } cases[] = {
        { FEMU_MEM_FTL, 1 },
        { FEMU_MEM_FTL ",namespaces=2,shared_ftl=on", 1 },
        { FEMU_MEM_FTL ",namespaces=2", 2 },
    };

    for (unsigned i = 0; i < ARRAY_SIZE(cases); i++) {
        QTestState *qts = qtest_initf("-machine pc -nodefaults "
                                      "-device femu,addr=5,id=mem,%s",
                                      cases[i].opts);
        QDict *rsp = qtest_qmp(qts, "{'execute':'query-femu-memory'}");
        QDict *ret = qdict_get_qdict(rsp, "return");
        const QListEntry *e;
        g_autofree char *ftl = NULL;
        g_autoptr(GHashTable) ftls = g_hash_table_new_full(g_str_hash,
                                                           g_str_equal,
                                                           g_free, NULL);
        g_autoptr(GHashTable) named = g_hash_table_new(g_str_hash,
                                                       g_str_equal);
        uint32_t nr_ftl = 0;

        QLIST_FOREACH_ENTRY(qdict_get_qlist(ret, "owners"), e) {
            QDict *o = qobject_to(QDict, qlist_entry_obj(e));

            if (strcmp(qdict_get_str(o, "kind"), "ftl")) {
                g_assert_cmpuint(qdict_get_int(o, "mapping"), ==, 0);
                g_assert_cmpuint(qdict_get_int(o, "media"), ==, 0);
                continue;
            }
            nr_ftl++;
            g_free(ftl);
            ftl = g_strdup(qdict_get_str(o, "id"));
            g_assert_true(g_str_has_prefix(ftl, "/machine/peripheral/mem/ftl"));
            g_assert_true(g_hash_table_add(ftls, g_strdup(ftl)));
            /* each FTL has the whole geometry, also one of two namespaces */
            g_assert_cmpint(qdict_get_int(o, "mapping"), ==, 2 * 8 * 384);
            g_assert_cmpuint(qdict_get_int(o, "media"), >, 0);
        }
        g_assert_cmpuint(nr_ftl, ==, cases[i].nr_ftl);
        /* each namespace names exactly one FTL owner */
        QLIST_FOREACH_ENTRY(qdict_get_qlist(ret, "namespaces"), e) {
            QDict *ns = qobject_to(QDict, qlist_entry_obj(e));
            const QListEntry *ie;
            uint32_t n = 0;

            QLIST_FOREACH_ENTRY(qdict_get_qlist(ns, "owners"), ie) {
                const char *id = qstring_get_str(qobject_to(QString,
                                                 qlist_entry_obj(ie)));

                if (strstr(id, "/ftl")) {
                    n++;
                    g_assert_true(g_hash_table_contains(ftls, id));
                    g_hash_table_add(named, (gpointer)id);
                }
            }
            g_assert_cmpuint(n, ==, 1);
        }
        /* each FTL owner is named by a namespace */
        g_assert_cmpuint(g_hash_table_size(named), ==, cases[i].nr_ftl);
        g_hash_table_remove_all(named);
        qobject_unref(rsp);
        qtest_quit(qts);
    }

    /*
     * Two FDP reclaim groups add group lines and victim heaps to the FTL,
     * so its media exceeds that of the same geometry without FDP.
     */
    {
        uint64_t media[2] = { 0, 0 };

        for (int fdp = 0; fdp < 2; fdp++) {
            QTestState *qts = qtest_initf("-machine pc -nodefaults %s "
                "-device femu,addr=5,id=mem,devsz_mb=1,femu_mode=1,secsz=512,"
                "secs_per_pg=8,pgs_per_blk=4,pls_per_lun=1,luns_per_ch=2,"
                "nchs=2,blks_per_pl=80,lba_index=3%s",
                fdp ? "-device femu-subsys,id=memsub,nqn=memsub,fdp=on,"
                      "fdp.nruh=4,fdp.nrg=2" : "",
                fdp ? ",subsys=memsub" : "");
            QDict *rsp = qtest_qmp(qts, "{'execute':'query-femu-memory'}");
            const QListEntry *e;
            uint32_t nr_sub = 0;

            QLIST_FOREACH_ENTRY(qdict_get_qlist(qdict_get_qdict(rsp, "return"),
                                                "owners"), e) {
                QDict *o = qobject_to(QDict, qlist_entry_obj(e));

                if (!strcmp(qdict_get_str(o, "kind"), "ftl")) {
                    media[fdp] += qdict_get_int(o, "media");
                }
                /*
                 * The reclaim units and handles of the endurance group: 2
                 * group pointers, 2 x 128 units of 8 bytes, 4 handles of
                 * 64 bytes with 2 unit pointers each.
                 */
                if (!strcmp(qdict_get_str(o, "kind"), "subsystem")) {
                    g_assert_true(fdp);
                    g_assert_cmpstr(qdict_get_str(o, "id"), ==,
                                    "/machine/peripheral/memsub");
                    g_assert_cmpuint(qdict_get_int(o, "media"), ==, 2384);
                    nr_sub++;
                }
                /* 4 placement handles of 2 bytes */
                if (!strcmp(qdict_get_str(o, "kind"), "namespace")) {
                    g_assert_cmpuint(qdict_get_int(o, "media"), ==,
                                     fdp ? 8 : 0);
                }
            }
            g_assert_cmpuint(nr_sub, ==, fdp);
            qobject_unref(rsp);
            qtest_quit(qts);
        }
        g_assert_cmpuint(media[1], >, media[0]);
    }

    /*
     * A zoned namespace has no FTL owner: its L2P (8 bytes per 4 KiB of
     * the 32 MiB namespace), NAND tree and zones count at the namespace.
     */
    {
        QTestState *qts = qtest_initf("-machine pc -nodefaults "
            "-device femu,addr=5,id=mem,devsz_mb=32,femu_mode=3,secsz=512,"
            "zns_num_ch=1,zns_num_lun=1,zns_num_plane=2,zns_num_blk=32,"
            "zns_flash_type=1");
        QDict *rsp = qtest_qmp(qts, "{'execute':'query-femu-memory'}");
        QDict *ret = qdict_get_qdict(rsp, "return");
        const QListEntry *e;
        uint32_t nr_ns = 0;

        QLIST_FOREACH_ENTRY(qdict_get_qlist(ret, "owners"), e) {
            QDict *o = qobject_to(QDict, qlist_entry_obj(e));
            const char *kind = qdict_get_str(o, "kind");

            g_assert_cmpstr(kind, !=, "ftl");
            if (!strcmp(kind, "namespace")) {
                nr_ns++;
                g_assert_cmpuint(qdict_get_int(o, "mapping"), ==,
                                 32 * MiB / 4096 * 8);
                g_assert_cmpuint(qdict_get_int(o, "media"), >, 0);
                /*
                 * Two bitmaps of 65536 blocks (16384 bytes), and three
                 * write caches with their LPN arrays (312 bytes).
                 */
                g_assert_cmpuint(qdict_get_int(o, "other"), ==, 16696);
            }
        }
        g_assert_cmpuint(nr_ns, ==, 1);
        qobject_unref(rsp);
        qtest_quit(qts);
    }

    /*
     * Open-channel: OCSSD 1.2 has a translation table and bad block tables
     * per namespace and an OOB area at the controller; OCSSD 2.0 has chunk
     * state only.
     */
    for (int v = 1; v <= 2; v++) {
        QTestState *qts = qtest_initf("-machine pc -nodefaults "
            "-device femu,addr=5,id=mem,devsz_mb=64,femu_mode=0,lver=%d", v);
        QDict *rsp = qtest_qmp(qts, "{'execute':'query-femu-memory'}");
        QDict *ret = qdict_get_qdict(rsp, "return");
        const QListEntry *e;

        QLIST_FOREACH_ENTRY(qdict_get_qlist(ret, "owners"), e) {
            QDict *o = qobject_to(QDict, qlist_entry_obj(e));
            const char *kind = qdict_get_str(o, "kind");

            g_assert_cmpstr(kind, !=, "ftl");
            if (!strcmp(kind, "controller")) {
                g_assert_true(!!qdict_get_int(o, "media") == (v == 1));
            } else {
                g_assert_true(!!qdict_get_int(o, "mapping") == (v == 1));
                g_assert_cmpuint(qdict_get_int(o, "media"), >, 0);
            }
        }
        qobject_unref(rsp);
        qtest_quit(qts);
    }

    /*
     * CSD: the 4 MiB memory namespace (SLM) counts at the controller.
     * Namespace 1 stores blocks; 2 is the memory namespace, whose arena the
     * controller holds; 3 computes and holds nothing else. With FDP only
     * namespace 1 names the subsystem.
     */
    for (int fdp = 0; fdp < 2; fdp++) {
        QTestState *qts = qtest_initf("-machine pc -nodefaults %s "
            "-device femu,addr=5,id=mem,femu_mode=4,fdm_size=16,"
            "csd_slm_size=4,csd_cp=on%s",
            fdp ? "-device femu-subsys,id=memsub,nqn=memsub,fdp=on,"
                  "fdp.nruh=4" : "",
            fdp ? ",subsys=memsub,devsz_mb=32,secsz=512,secs_per_pg=8,"
                  "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,"
                  "luns_per_ch=4,nchs=4" : "");
        QDict *rsp = qtest_qmp(qts, "{'execute':'query-femu-memory'}");
        QDict *ret = qdict_get_qdict(rsp, "return");
        const char *d = "/machine/peripheral/mem";
        const char *sub = "/machine/peripheral/memsub";
        g_autofree char *ftl = NULL;
        const QListEntry *e;
        uint32_t seen = 0;

        QLIST_FOREACH_ENTRY(qdict_get_qlist(ret, "owners"), e) {
            QDict *o = qobject_to(QDict, qlist_entry_obj(e));
            const char *kind = qdict_get_str(o, "kind");

            if (!strcmp(kind, "controller")) {
                g_assert_cmpuint(qdict_get_int(o, "other"), ==, 4 * MiB);
            } else if (!strcmp(kind, "ftl")) {
                g_assert_null(ftl);
                ftl = g_strdup(qdict_get_str(o, "id"));
                g_assert_cmpuint(qdict_get_int(o, "mapping"), >, 0);
            }
        }
        g_assert_nonnull(ftl);
        QLIST_FOREACH_ENTRY(qdict_get_qlist(ret, "namespaces"), e) {
            QDict *ns = qobject_to(QDict, qlist_entry_obj(e));
            int64_t nsid = qdict_get_int(ns, "nsid");
            g_autofree char *own = g_strdup_printf("%s/ns%" PRId64, d, nsid);
            const char *want[4];
            uint32_t nr = 0;
            const QListEntry *ie;
            uint32_t k = 0;

            /* the list in the order the reply builds it */
            if (nsid == 1) {
                want[nr++] = d;
                if (fdp) {
                    want[nr++] = sub;
                }
                want[nr++] = ftl;
            } else if (nsid == 2) {
                want[nr++] = d;
            } else {
                g_assert_cmpint(nsid, ==, 3);
            }
            want[nr++] = own;
            seen |= 1u << nsid;
            g_assert_cmpuint(qlist_size(qdict_get_qlist(ns, "owners")), ==,
                             nr);
            QLIST_FOREACH_ENTRY(qdict_get_qlist(ns, "owners"), ie) {
                g_assert_cmpstr(qstring_get_str(qobject_to(QString,
                                qlist_entry_obj(ie))), ==, want[k++]);
            }
        }
        g_assert_cmpuint(seen, ==, (1u << 1) | (1u << 2) | (1u << 3));
        qobject_unref(rsp);
        qtest_quit(qts);
    }
}

/*
 * Capability agreement. Identify, the Supported Log Pages, Commands Supported
 * and Effects and FID Supported and Effects logs all describe what the
 * controller handles, and each is checked here against what it does: every
 * admin and I/O opcode, every log identifier for each command set, and the
 * Identify bits that summarise them. A command or page that answers without
 * being listed, or is listed and refused, fails the test.
 */
#define FEMU_CAPS_NCSI      5
#define FEMU_CAPS_MAX_NS    8

static const uint8_t femu_caps_csi[FEMU_CAPS_NCSI] = {
    NVME_CSI_NVM, FEMU_CSI_KV, FEMU_CSI_ZONED, 0x03, 0x04,
};

typedef struct FemuCaps {
    NvmeIdCtrl id;
    uint32_t acs[256];
    uint32_t iocs[FEMU_CAPS_NCSI][256];
    uint32_t lids[FEMU_CAPS_NCSI][256];
    uint32_t fis[FEMU_CAPS_NCSI][256];
    uint8_t cmd_sets[8];
    uint32_t nsid[FEMU_CAPS_MAX_NS];
    int csi_idx[FEMU_CAPS_MAX_NS];
    int nr_ns;
    GString *bad;
} FemuCaps;

/*
 * The memory (03h) and compute (04h) sets exist only on a controller that
 * has such a namespace; elsewhere their logs answer I/O Command Set Not
 * Supported, and nothing is checked for them.
 */
static bool femu_caps_csi_present(FemuCaps *k, int x)
{
    return femu_caps_csi[x] < 0x03 ||
           (k->cmd_sets[0] & (1 << femu_caps_csi[x]));
}

static void G_GNUC_PRINTF(2, 3) femu_caps_bad(FemuCaps *k, const char *fmt,
                                              ...)
{
    va_list ap;

    va_start(ap, fmt);
    g_string_append_vprintf(k->bad, fmt, ap);
    va_end(ap);
    g_string_append_c(k->bad, '\n');
}

static bool femu_caps_on(const uint32_t *tbl, uint8_t i)
{
    return le32_to_cpu(tbl[i]) & 1;
}

static void femu_caps_bit(FemuCaps *k, const char *field, uint32_t bit,
                          bool set, bool want)
{
    if (set != want) {
        femu_caps_bad(k, "%s bit 0x%x is %d, the logs say %d", field, bit,
                      set, want);
    }
}

/* the active namespaces and the command set each belongs to */
static void femu_caps_namespaces(FemuCtrlState *c, FemuCaps *k, uint64_t buf)
{
    QTestState *qts = c->pdev->bus->qts;
    uint32_t list[FEMU_CAPS_MAX_NS];
    int i;

    qtest_memset(qts, buf, 0, 4096);
    g_assert_cmpint(femu_identify(c, 0, NVME_ID_CNS_NS_ACTIVE_LIST, 0, buf),
                    ==, NVME_SUCCESS);
    qtest_memread(qts, buf, list, sizeof(list));
    for (i = 0; i < FEMU_CAPS_MAX_NS && list[i]; i++) {
        uint8_t d[4096];
        int off = 0;
        int idx = -1;

        k->nsid[i] = le32_to_cpu(list[i]);
        g_assert_cmpint(femu_identify(c, k->nsid[i], NVME_ID_CNS_NS_DESCR_LIST,
                                      0, buf), ==, NVME_SUCCESS);
        qtest_memread(qts, buf, d, sizeof(d));
        while (off + 4 < sizeof(d) && d[off]) {
            if (d[off] == FEMU_NIDT_CSI) {
                for (int j = 0; j < FEMU_CAPS_NCSI; j++) {
                    if (femu_caps_csi[j] == d[off + 4]) {
                        idx = j;
                    }
                }
            }
            off += 4 + d[off + 1];
        }
        g_assert_cmpint(idx, >=, 0);
        k->csi_idx[i] = idx;
    }
    k->nr_ns = i;
    g_assert_cmpint(k->nr_ns, >, 0);
}

static void femu_caps_read(FemuCtrlState *c, FemuCaps *k, uint64_t buf)
{
    QTestState *qts = c->pdev->bus->qts;
    uint8_t page[4096];
    int i;

    g_assert_cmpint(femu_identify(c, 0, NVME_ID_CNS_CTRL, 0, buf), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, buf, &k->id, sizeof(k->id));
    g_assert_cmpint(femu_identify(c, 0, FEMU_CNS_IO_CMD_SET, 0, buf), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, buf, k->cmd_sets, sizeof(k->cmd_sets));

    for (i = 0; i < FEMU_CAPS_NCSI; i++) {
        uint32_t csi = (uint32_t)femu_caps_csi[i] << 24;

        if (!femu_caps_csi_present(k, i)) {
            continue;
        }
        g_assert_cmpint(femu_log_cmd(c, NVME_NSID_BROADCAST, FEMU_LOG_SUPPORTED,
                                     csi, buf, 1024), ==, NVME_SUCCESS);
        qtest_memread(qts, buf, k->lids[i], 1024);
        g_assert_cmpint(femu_log_cmd(c, NVME_NSID_BROADCAST,
                                     FEMU_LOG_CMD_EFFECTS, csi, buf, 4096),
                        ==, NVME_SUCCESS);
        qtest_memread(qts, buf, page, sizeof(page));
        if (i == 0) {
            memcpy(k->acs, page, sizeof(k->acs));
        } else {
            /* the admin half does not depend on the command set */
            g_assert_cmpint(memcmp(k->acs, page, sizeof(k->acs)), ==, 0);
        }
        memcpy(k->iocs[i], page + 1024, sizeof(k->iocs[i]));
        g_assert_cmpint(femu_log_cmd(c, NVME_NSID_BROADCAST,
                                     FEMU_LOG_FID_EFFECTS, csi, buf, 1024),
                        ==, NVME_SUCCESS);
        qtest_memread(qts, buf, k->fis[i], sizeof(k->fis[i]));
    }
}

/* a feature Get Features serves is listed in log 12h for some command set */
static void femu_caps_features(FemuCtrlState *c, FemuCaps *k)
{
    for (int fid = 0; fid < 256; fid++) {
        uint16_t sc = FEMU_SC(femu_get_feature(c, fid, NVME_GETFEAT_SELECT_CAP,
                                               k->nsid[0], 0, NULL));
        bool adv = false;

        for (int i = 0; i < FEMU_CAPS_NCSI; i++) {
            adv |= femu_caps_on(k->fis[i], fid);
        }
        if ((sc == NVME_SUCCESS) != adv) {
            femu_caps_bad(k, "feature 0x%02x answers 0x%x, log 12h %s it", fid,
                          sc, adv ? "lists" : "does not list");
        }
    }
}

/* a listed entry carries its effects only alongside CSUPP or LSUPP */
static void femu_caps_entries(FemuCaps *k, const char *what,
                              const uint32_t *tbl)
{
    for (int i = 0; i < 256; i++) {
        uint32_t e = le32_to_cpu(tbl[i]);

        if (e && !(e & 1)) {
            femu_caps_bad(k, "%s entry 0x%02x is 0x%x without bit 0", what, i,
                          e);
        }
    }
}

/*
 * Every admin opcode, with a zeroed command. A handled command may refuse its
 * fields; only Invalid Command Opcode means it is not handled. An Asynchronous
 * Event Request is held, so it is checked from the log alone.
 */
static void femu_caps_admin(FemuCtrlState *c, FemuCaps *k, uint64_t buf)
{
    for (int opc = 0; opc < 256; opc++) {
        bool adv = femu_caps_on(k->acs, opc);
        NvmeCmd cmd;
        uint16_t sc;

        if (opc == NVME_ADM_CMD_ASYNC_EV_REQ) {
            if (!adv) {
                femu_caps_bad(k, "admin 0x%02x is not listed", opc);
            }
            continue;
        }
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = opc;
        cmd.dptr.prp1 = cpu_to_le64(buf);
        qtest_memset(c->pdev->bus->qts, buf, 0, 4096);
        sc = FEMU_SC(femu_admin(c, &cmd));
        if ((sc != NVME_INVALID_OPCODE) != adv) {
            femu_caps_bad(k, "admin 0x%02x answers 0x%x, log 05h %s it", opc,
                          sc, adv ? "lists" : "does not list");
        }
    }
}

/*
 * Every I/O opcode on every namespace. A namespace may handle only what its
 * command set lists, and each listed command must be handled by a namespace
 * of that set.
 */
static void femu_caps_io(FemuCtrlState *c, FemuCaps *k, uint64_t buf)
{
    bool any[FEMU_CAPS_NCSI][256] = { { false } };
    bool present[FEMU_CAPS_NCSI] = { false };

    for (int i = 0; i < k->nr_ns; i++) {
        int x = k->csi_idx[i];

        present[x] = true;
        for (int opc = 0; opc < 256; opc++) {
            NvmeCmd cmd;
            uint16_t sc;

            memset(&cmd, 0, sizeof(cmd));
            cmd.opcode = opc;
            cmd.nsid = cpu_to_le32(k->nsid[i]);
            cmd.dptr.prp1 = cpu_to_le64(buf);
            qtest_memset(c->pdev->bus->qts, buf, 0, 4096);
            sc = femu_io(c, &cmd);
            if (sc == NVME_INVALID_OPCODE) {
                continue;
            }
            any[x][opc] = true;
            if (!femu_caps_on(k->iocs[x], opc)) {
                femu_caps_bad(k, "namespace %u (CSI %u) answers I/O 0x%02x "
                              "with 0x%x; log 05h does not list it",
                              k->nsid[i], femu_caps_csi[x], opc, sc);
            }
        }
    }
    for (int x = 0; x < FEMU_CAPS_NCSI; x++) {
        for (int opc = 0; present[x] && opc < 256; opc++) {
            if (femu_caps_on(k->iocs[x], opc) && !any[x][opc]) {
                femu_caps_bad(k, "log 05h lists I/O 0x%02x for CSI %u; no "
                              "namespace handles it", opc, femu_caps_csi[x]);
            }
        }
    }
}

/*
 * Every log identifier for each command set, addressed to a namespace of
 * that set when there is one, since a namespace's own pages need it. A page
 * listed for a command set answers for it, and a page that answers is listed
 * for it.
 */
static void femu_caps_logs(FemuCtrlState *c, FemuCaps *k, uint64_t buf)
{
    for (int x = 0; x < FEMU_CAPS_NCSI; x++) {
        uint32_t nsid = NVME_NSID_BROADCAST;

        if (!femu_caps_csi_present(k, x)) {
            continue;
        }
        for (int i = k->nr_ns - 1; i >= 0; i--) {
            if (k->csi_idx[i] == x) {
                nsid = k->nsid[i];
            }
        }
        for (int lid = 0; lid < 256; lid++) {
            bool adv = femu_caps_on(k->lids[x], lid);
            uint16_t sc = femu_log_cmd(c, nsid, lid,
                                       (uint32_t)femu_caps_csi[x] << 24, buf,
                                       512);

            if (adv != (sc != NVME_INVALID_LOG_ID)) {
                femu_caps_bad(k, "log 0x%02x for CSI %u answers 0x%x, log 00h "
                              "%s it", lid, femu_caps_csi[x], sc,
                              adv ? "lists" : "does not list");
            }
        }
    }
}

/* the Identify bits that summarise the logs, and the behaviour behind them */
static void femu_caps_identify(FemuCtrlState *c, FemuCaps *k, uint64_t buf)
{
    QTestState *qts = c->pdev->bus->qts;
    const uint32_t *acs = k->acs;
    const uint32_t *nvm = k->iocs[0];
    const uint32_t *lids = k->lids[0];
    uint16_t oacs = le16_to_cpu(k->id.oacs);
    uint16_t oncs = le16_to_cpu(k->id.oncs);
    uint8_t lpa = k->id.lpa;
    bool copy = femu_caps_on(nvm, NVME_CMD_COPY);
    NvmeIdNs idns;
    int i;

    femu_caps_bit(k, "OACS", 1 << 0, oacs & (1 << 0),
                  femu_caps_on(acs, 0x81) && femu_caps_on(acs, 0x82));
    femu_caps_bit(k, "OACS", 1 << 1, oacs & (1 << 1), femu_caps_on(acs, 0x80));
    femu_caps_bit(k, "OACS", 1 << 2, oacs & (1 << 2),
                  femu_caps_on(acs, 0x10) && femu_caps_on(acs, 0x11));
    femu_caps_bit(k, "OACS", 1 << 3, oacs & (1 << 3),
                  femu_caps_on(acs, 0x0d) && femu_caps_on(acs, 0x15));
    femu_caps_bit(k, "OACS", 1 << 4, oacs & (1 << 4), femu_caps_on(acs, 0x14));
    femu_caps_bit(k, "OACS", 1 << 5, oacs & (1 << 5),
                  femu_caps_on(acs, 0x19) && femu_caps_on(acs, 0x1a));
    femu_caps_bit(k, "OACS", 1 << 8, oacs & (1 << 8), femu_caps_on(acs, 0x7c));
    femu_caps_bit(k, "OACS", 1 << 9, oacs & (1 << 9), femu_caps_on(acs, 0x86));

    femu_caps_bit(k, "ONCS", 1 << 0, oncs & (1 << 0), femu_caps_on(nvm, 0x05));
    femu_caps_bit(k, "ONCS", 1 << 1, oncs & (1 << 1), femu_caps_on(nvm, 0x04));
    femu_caps_bit(k, "ONCS", 1 << 2, oncs & (1 << 2), femu_caps_on(nvm, 0x09));
    femu_caps_bit(k, "ONCS", 1 << 3, oncs & (1 << 3), femu_caps_on(nvm, 0x08));
    femu_caps_bit(k, "ONCS", 1 << 5, oncs & (1 << 5), femu_caps_on(nvm, 0x0d));
    femu_caps_bit(k, "ONCS", 1 << 6, oncs & (1 << 6),
                  femu_caps_on(k->fis[0], 0x0e));
    femu_caps_bit(k, "ONCS", 1 << 7, oncs & (1 << 7), femu_caps_on(nvm, 0x0c));
    femu_caps_bit(k, "ONCS", 1 << 8, oncs & (1 << 8), copy);
    if (oncs & (1 << 9)) {
        femu_caps_bit(k, "ONCS", 1 << 9, true, copy);
    }
    /* Copy offers formats 0h and 2h; Memory Copy 2h and 4h (SLM 3.2.1) */
    femu_caps_bit(k, "OCFS", 1 << 0, le16_to_cpu(k->id.ocfs) & 1, copy);
    femu_caps_bit(k, "OCFS", 1 << 4, le16_to_cpu(k->id.ocfs) & (1 << 4),
                  femu_caps_on(k->iocs[3], 0x01));
    femu_caps_bit(k, "OCFS", 1 << 2, le16_to_cpu(k->id.ocfs) & (1 << 2),
                  copy || femu_caps_on(k->iocs[3], 0x01));

    femu_caps_bit(k, "LPA", 1 << 1, lpa & (1 << 1),
                  femu_caps_on(lids, NVME_LOG_CMD_EFFECTS));
    femu_caps_bit(k, "LPA", 1 << 3, lpa & (1 << 3),
                  femu_caps_on(lids, 0x07) && femu_caps_on(lids, 0x08));
    femu_caps_bit(k, "LPA", 1 << 4, lpa & (1 << 4),
                  femu_caps_on(lids, 0x0d));
    /* SMART for one namespace, which LPA bit 0 offers */
    femu_caps_bit(k, "LPA", 1 << 0, lpa & 1,
                  femu_log_cmd(c, k->nsid[0], NVME_LOG_SMART_INFO, 0, buf,
                               512) == NVME_SUCCESS);

    femu_caps_bit(k, "SANICAP", 0xffffffff, le32_to_cpu(k->id.sanicap) != 0,
                  femu_caps_on(acs, 0x84));
    femu_caps_bit(k, "LID 81h", 1, femu_caps_on(lids, 0x81),
                  femu_caps_on(acs, 0x84));
    femu_caps_bit(k, "VWC", 1, k->id.vwc & 1, femu_caps_on(k->fis[0], 0x06));

    /*
     * Slot 1 is read only. One slot means nothing downloads or commits
     * firmware; more slots mean both commands work, without a reset.
     */
    {
        bool slots = ((k->id.frmw >> 1) & 0x7) > 1;

        femu_caps_bit(k, "FRMW", 1, k->id.frmw & 1, true);
        femu_caps_bit(k, "FRMW", 1 << 4, k->id.frmw & (1 << 4), slots);
        femu_caps_bit(k, "OACS", 1 << 2, oacs & (1 << 2),
                      femu_caps_on(acs, NVME_ADM_CMD_ACTIVATE_FW) &&
                      femu_caps_on(acs, NVME_ADM_CMD_DOWNLOAD_FW));
        femu_caps_bit(k, "OACS", 1 << 2, oacs & (1 << 2), slots);
        femu_caps_bit(k, "FWUG", 1, k->id.fwug == 1, slots);
    }

    for (i = 0; i < FEMU_CAPS_NCSI; i++) {
        bool any = false;

        for (int opc = 0; opc < 256; opc++) {
            any |= femu_caps_on(k->iocs[i], opc);
        }
        femu_caps_bit(k, "CNS 1Ch", femu_caps_csi[i],
                      k->cmd_sets[0] & (1 << femu_caps_csi[i]), any);
    }

    /* each block namespace's Copy limits come and go with Copy for its set */
    for (i = 0; i < k->nr_ns; i++) {
        if (femu_caps_csi[k->csi_idx[i]] == FEMU_CSI_KV ||
            femu_caps_csi[k->csi_idx[i]] >= 0x03) {
            continue;
        }
        copy = femu_caps_on(k->iocs[k->csi_idx[i]], NVME_CMD_COPY);
        g_assert_cmpint(femu_identify(c, k->nsid[i], NVME_ID_CNS_NS, 0, buf),
                        ==, NVME_SUCCESS);
        qtest_memread(qts, buf, &idns, sizeof(idns));
        if ((idns.mssrl != 0) != copy || (idns.mcl != 0) != copy ||
            (idns.msrc != 0) != copy) {
            femu_caps_bad(k, "namespace %u: Copy limits %u/%u/%u, Copy %s",
                          k->nsid[i], le16_to_cpu(idns.mssrl),
                          le32_to_cpu(idns.mcl), idns.msrc,
                          copy ? "listed" : "not listed");
        }
    }
}

/*
 * SGLS bit 0 against a read through a one-block SGL on the first block
 * namespace that handles Read.
 */
static void femu_caps_sgl(FemuCtrlState *c, FemuCaps *k, uint64_t buf)
{
    QTestState *qts = c->pdev->bus->qts;
    bool sgls = le32_to_cpu(k->id.sgls) & 1;
    uint64_t list = buf + 2048;

    for (int i = 0; i < k->nr_ns; i++) {
        NvmeIdNs idns;
        uint32_t lbads;
        NvmeCmd cmd;
        uint16_t sc;

        /* key-value, memory and compute namespaces have no block Read */
        if (femu_caps_csi[k->csi_idx[i]] == FEMU_CSI_KV ||
            femu_caps_csi[k->csi_idx[i]] >= 0x03 ||
            !femu_caps_on(k->iocs[k->csi_idx[i]], NVME_CMD_READ)) {
            continue;
        }
        g_assert_cmpint(femu_identify(c, k->nsid[i], NVME_ID_CNS_NS, 0, buf),
                        ==, NVME_SUCCESS);
        qtest_memread(qts, buf, &idns, sizeof(idns));
        lbads = idns.lbaf[idns.flbas & 0xf].ds;
        if (lbads > 11) {
            continue;
        }
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = NVME_CMD_READ;
        cmd.nsid = cpu_to_le32(k->nsid[i]);
        femu_sgl_segment(c, &cmd, list, buf, 1u << lbads);
        sc = femu_io(c, &cmd);
        if (sgls ? sc == NVME_INVALID_FIELD : sc != NVME_INVALID_FIELD) {
            femu_caps_bad(k, "SGLS bit 0 is %d; an SGL read on namespace %u "
                          "answers 0x%x", sgls, k->nsid[i], sc);
        }
        return;
    }
}

/*
 * What the reported version obliges. A 2.1 controller sets CAP.CRMS.CRWMS and
 * answers CRTO (Base 2.0c, Figure 36 and 3.1.3.21), and reports BPCAP bits
 * 1:0 as 01b, since 00b is only for 2.0 and earlier (Base 2.3, Figure 328).
 * Open-Channel has no NVM Read or Write and stays at 1.4, where these are
 * reserved. LPA bit 5 stays clear, which leaves log 05h without the scopes
 * that Linux would report as unusual effects. No configuration claims
 * weighted round robin, which nothing arbitrates by.
 */
static void femu_caps_version(FemuCtrlState *c, FemuCaps *k, bool ocssd)
{
    uint64_t cap = qpci_io_readq(c->pdev, c->bar, 0x0);
    uint32_t vs = qpci_io_readl(c->pdev, c->bar, 0x8);
    uint32_t crto = qpci_io_readl(c->pdev, c->bar, 0x68);
    uint8_t bpcap = ((uint8_t *)&k->id)[102];
    uint32_t want = ocssd ? 0x00010400 : 0x00020100;
    bool v2 = !ocssd;

    if (vs != want || le32_to_cpu(k->id.ver) != want) {
        femu_caps_bad(k, "VS is 0x%x, Identify VER 0x%x; expected 0x%x", vs,
                      le32_to_cpu(k->id.ver), want);
    }
    if (((cap >> 59) & 0x3) != (v2 ? 0x1 : 0)) {
        femu_caps_bad(k, "CAP.CRMS is 0x%x", (uint32_t)(cap >> 59) & 0x3);
    }
    if (crto != (v2 ? ((cap >> 24) & 0xff) : 0)) {
        femu_caps_bad(k, "CRTO is 0x%x with CAP.TO 0x%x", crto,
                      (uint32_t)(cap >> 24) & 0xff);
    }
    if (bpcap != (v2 ? 0x1 : 0)) {
        femu_caps_bad(k, "BPCAP is 0x%x", bpcap);
    }
    femu_caps_bit(k, "CAP.AMS", 1, (cap >> 17) & 0x3, false);
    femu_caps_bit(k, "LPA bit 5", 1 << 5, k->id.lpa & (1 << 5), false);
    for (int i = 0; i < 256; i++) {
        if (le32_to_cpu(k->acs[i]) >> 20) {
            femu_caps_bad(k, "admin 0x%02x has a scope", i);
        }
        for (int j = 0; j < FEMU_CAPS_NCSI; j++) {
            if (le32_to_cpu(k->iocs[j][i]) >> 20) {
                femu_caps_bad(k, "I/O 0x%02x of set %d has a scope", i, j);
            }
        }
    }
}

/*
 * The command set versions in CNS 06h (TP4135, mandatory in Base 2.1): NVM
 * 1.1 in bytes 23:20 (NVM 1.1 Figure 120) and ZNS 1.2 in bytes 35:32 (ZNS
 * 1.2 Figure 61), with AOCS.RALBAS (byte 18 bit 0) set, as Get LBA Status
 * serves action type 02h. KV keeps 1.3 in bytes 3:0, and SLM and CP keep
 * 1.2 where the controller has them. OCSSD keeps its 1.4 replies: no VER.
 * The buffer is poisoned first, so a byte the controller did not send
 * cannot pass.
 */
static void femu_caps_csi_version(FemuCtrlState *c, FemuCaps *k, uint64_t buf,
                                  const char *opts, bool ocssd)
{
    QTestState *qts = c->pdev->bus->qts;
    static const struct {
        uint8_t csi;
        int off;
        uint32_t want;
    } v[] = {
        { NVME_CSI_NVM, 20, 0x00010100 },
        { FEMU_CSI_ZONED, 32, 0x00010200 },
        { FEMU_CSI_KV, 0, 0x00010300 },
        { 0x03, 0, 0x00010200 },
        { 0x04, 0, 0x00010200 },
    };
    /* SLM needs a nonzero csd_slm_size, CP needs csd_cp=on (nvme.h) */
    bool slm = strstr(opts, "csd_slm_size=") &&
               !strstr(opts, "csd_slm_size=0,");
    bool cp = strstr(opts, "csd_cp=on");
    uint8_t id[4096];

    for (int i = 0; i < ARRAY_SIZE(v); i++) {
        bool offered = v[i].csi < 0x03 || (v[i].csi == 0x03 ? slm : cp);
        uint16_t st;

        if (v[i].csi >= 0x03 &&
            !!(k->cmd_sets[0] & (1 << v[i].csi)) != offered) {
            femu_caps_bad(k, "CNS 1Ch CSI %02xh is %s; the configuration "
                          "says %s", v[i].csi,
                          (k->cmd_sets[0] & (1 << v[i].csi)) ? "on" : "off",
                          offered ? "on" : "off");
        }
        uint32_t want = v[i].want;
        uint32_t got;

        qtest_memset(qts, buf, 0xa5, sizeof(id));
        st = femu_identify(c, 0, 0x06, (uint32_t)v[i].csi << 24, buf);
        if (!offered) {
            if (st != NVME_INVALID_FIELD) {
                femu_caps_bad(k, "CNS 06h CSI %02xh without the set: status "
                              "0x%x", v[i].csi, st);
            }
            continue;
        }
        if (st != NVME_SUCCESS) {
            femu_caps_bad(k, "CNS 06h CSI %02xh: status 0x%x", v[i].csi, st);
            continue;
        }
        qtest_memread(qts, buf, id, sizeof(id));
        if (ocssd && v[i].csi != FEMU_CSI_KV) {
            want = 0;
        }
        got = ldl_le_p(id + v[i].off);
        if (got != want) {
            femu_caps_bad(k, "CNS 06h CSI %02xh VER at byte %d is 0x%x; "
                          "expected 0x%x", v[i].csi, v[i].off, got, want);
        }
        if (v[i].csi == NVME_CSI_NVM && (id[18] & 0x1) != (ocssd ? 0 : 1)) {
            femu_caps_bad(k, "CNS 06h AOCS byte 18 is 0x%x", id[18]);
        }
    }
}

/*
 * A rotational subsystem refuses namespaces that are not NVM ones, and
 * FDP. Each case has a control: the same controller in a subsystem without
 * the property.
 */
void femu_test_rotational_refused(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    static const struct {
        const char *opts;
        const char *sub;
        const char *control;
        const char *msg;
    } tc[] = {
        { "'femu_mode':3", "rotsub", "rotsub-off", "znssd" },
        { "'femu_mode':5", "rotsub", "rotsub-off", "kvssd" },
        { "'femu_mode':0", "rotsub", "rotsub-off", "ocssd" },
        { "'femu_mode':1,'namespaces':2,'namespace_modes':'bbssd,,znssd,',"
          "'secsz':512,'secs_per_pg':8,'pgs_per_blk':64,'blks_per_pl':80,"
          "'pls_per_lun':1,'luns_per_ch':2,'nchs':2", "rotsub", "rotsub-off",
          "namespace 2" },
        /* the control keeps FDP and drops only the rotational property */
        { "'femu_mode':2", "rotsub-fdp", "rotsub-fdp-off", "FDP" },
    };

    for (int i = 0; i < ARRAY_SIZE(tc); i++) {
        for (int on = 1; on >= 0; on--) {
            g_autofree char *cmd = g_strdup_printf(
                "{'execute':'device_add','arguments':{'driver':'femu',"
                "'id':'rot','addr':'5','devsz_mb':64,'subsys':'%s',%s}}",
                on ? tc[i].sub : tc[i].control, tc[i].opts);
            QDict *rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));

            if (on) {
                const char *desc;

                g_assert_true(qdict_haskey(rsp, "error"));
                desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
                g_test_message("%s: %s", tc[i].opts, desc);
                g_assert_nonnull(strstr(desc, "rotational"));
                g_assert_nonnull(strstr(desc, tc[i].msg));
            } else {
                if (!qdict_haskey(rsp, "return")) {
                    g_test_message("control %s refused: %s", tc[i].opts,
                                   qdict_get_str(qdict_get_qdict(rsp,
                                                 "error"), "desc"));
                    g_assert_not_reached();
                }
                qpci_unplug_acpi_device_test(qts, "rot", 5);
            }
            qobject_unref(rsp);
        }
    }
}

/*
 * plane_reads: refused outside bbssd and CSD, and with the channel phases
 * or suspend whose state is per LUN; a two-plane bbssd device realizes.
 */
void femu_test_plane_reads(void *obj, void *data,
                           QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    static const struct {
        const char *opts;
        const char *msg;
    } bad[] = {
        { "'femu_mode':2", "bbssd, CSD or KV" },
        { "'femu_mode':1,'onfi_cache_read':1", "plain channel model" },
        { "'femu_mode':1,'pe_suspend':1", "plain channel model" },
        { "'femu_mode':1,'read_prio':1", "plain channel model" },
        { "'femu_mode':1,'status_lat':100", "plain channel model" },
    };
    const char *geom = "'devsz_mb':4,'secsz':512,'secs_per_pg':8,"
                       "'pgs_per_blk':16,'luns_per_ch':1,'nchs':1,"
                       "'pls_per_lun':2,'blks_per_pl':40,'plane_reads':true";
    QDict *rsp;

    for (int i = 0; i < ARRAY_SIZE(bad); i++) {
        g_autofree char *cmd = g_strdup_printf(
            "{'execute':'device_add','arguments':{'driver':'femu',"
            "'id':'pr','addr':'5',%s,%s}}", geom, bad[i].opts);

        rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));
        g_assert_true(qdict_haskey(rsp, "error"));
        g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                              "desc"), bad[i].msg));
        qobject_unref(rsp);
    }
    {
        g_autofree char *cmd = g_strdup_printf(
            "{'execute':'device_add','arguments':{'driver':'femu',"
            "'id':'pr','addr':'5','femu_mode':1,%s}}", geom);

        rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));
        g_assert_true(qdict_haskey(rsp, "return"));
        qobject_unref(rsp);
        qpci_unplug_acpi_device_test(qts, "pr", 5);
    }
    qos_invalidate_command_line();
}

void femu_test_ns_wp_refused(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    const struct {
        const char *opts;
        const char *msg;
    } cases[] = {
        { "'femu_mode':5", "a mode other than bbssd or NoSSD" },
        { "'femu_mode':1,'ns_mgmt':true", "namespace management" },
        { "'femu_mode':1,'persist_file':'nswp.img'", "persist_file" },
    };
    QDict *rsp;
    int i;

    for (i = 0; i < ARRAY_SIZE(cases); i++) {
        g_autofree char *cmd = g_strdup_printf(
            "{'execute':'device_add','arguments':{"
            "'driver':'femu','id':'nswp','addr':'5','devsz_mb':1,"
            "'ns_wp':true,%s}}", cases[i].opts);
        const char *desc;

        rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));
        g_assert_true(qdict_haskey(rsp, "error"));
        desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
        g_test_message("%s: %s", cases[i].opts, desc);
        g_assert_nonnull(strstr(desc, cases[i].msg));
        qobject_unref(rsp);
    }
    qos_invalidate_command_line();
}

/* sanitize_ns off: 8Ch is an invalid opcode; and the refusals */
void femu_test_sanitize_ns_refused(void *obj, void *data,
                                   QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    const struct {
        const char *opts;
        const char *msg;
    } cases[] = {
        { "'femu_mode':1,'sanitize_ns':true", "needs sanitize_ops" },
        { "'femu_mode':5,'sanitize_ns':true,'sanitize_ops':true",
          "a mode other than bbssd or NoSSD" },
        { "'femu_mode':1,'sanitize_ns':true,'sanitize_ops':true,"
          "'ns_mgmt':true", "namespace management" },
        { "'femu_mode':1,'sanitize_ns':true,'sanitize_ops':true,"
          "'persist_file':'sanns.img'", "persist_file" },
    };
    QDict *rsp;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    g_assert_cmphex(femu_sanns(&c, 1, 0x4), ==, NVME_INVALID_OPCODE);
    femu_disable(&c);
    for (i = 0; i < ARRAY_SIZE(cases); i++) {
        g_autofree char *cmd = g_strdup_printf(
            "{'execute':'device_add','arguments':{"
            "'driver':'femu','id':'sanns','addr':'5','devsz_mb':1,%s}}",
            cases[i].opts);
        const char *desc;

        rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));
        g_assert_true(qdict_haskey(rsp, "error"));
        desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
        g_test_message("%s: %s", cases[i].opts, desc);
        g_assert_nonnull(strstr(desc, cases[i].msg));
        qobject_unref(rsp);
    }
    qos_invalidate_command_line();
}

/* ocp is refused without an FTL behind every namespace, and in a subsystem */
void femu_test_ocp_refused(void *obj, void *data,
                           QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    static const char *cases[] = {
        "'femu_mode':2", "'femu_mode':3", "'femu_mode':5", "'femu_mode':0",
        "'femu_mode':0,'lver':1",
        "'femu_mode':1,'subsys':'ocpsub'",
        "'femu_mode':1,'ns_mgmt':true",
        "'femu_mode':4,'fdm_size':16,'csd_slm_size':4",
        "'femu_mode':1,'namespaces':2,'namespace_modes':'bbssd,,znssd,',"
        "'secsz':512,'secs_per_pg':8,'pgs_per_blk':64,'blks_per_pl':80,"
        "'pls_per_lun':1,'luns_per_ch':2,'nchs':2",
    };
    QDict *csd;

    /*
     * ocp_profile: 13 letters A or B, only with ocp=on; DP-CFG-7 B turns
     * on Write Uncorrectable (ONCS bit 1).
     */
    {
        static const struct {
            const char *opts;
            const char *msg;
        } bad[] = {
            { "'ocp':true,'ocp_profile':'BAAB'", "13 letters" },
            { "'ocp':true,'ocp_profile':'BAABABAAAABAC'", "13 letters" },
            { "'ocp':false,'ocp_profile':'BAABABAAAABAB'", "needs ocp=on" },
            /* DP-CFG-1 B: namespaces boot in LBA format 0 (NSM-3) */
            { "'ocp':true,'lba_index':3", "lba_index 0" },
            /* A choices that need a function FEMU does not have */
            { "'ocp':true,'ocp_profile':'AAABABAAAABAB'", "DP-CFG-1 A" },
            { "'ocp':true,'ocp_profile':'BAAAABAAAABAB'", "DP-CFG-4 A" },
            { "'ocp':true,'ocp_profile':'BAABABAAAAAAB'", "DP-CFG-11 A" },
            { "'ocp':true,'ocp_profile':'BAABABAAAABAA'", "DP-CFG-13 A" },
        };
        QPCIDevice *pdev;
        FemuCtrlState c = { 0 };
        uint64_t buf;
        NvmeIdCtrl id;

        for (int i = 0; i < ARRAY_SIZE(bad); i++) {
            g_autofree char *cmd = g_strdup_printf(
                "{'execute':'device_add','arguments':{'driver':'femu',"
                "'id':'ocp','addr':'5','devsz_mb':64,'femu_mode':1,%s}}",
                bad[i].opts);
            QDict *rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));

            g_assert_true(qdict_haskey(rsp, "error"));
            g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp,
                                                  "error"), "desc"),
                                    bad[i].msg));
            qobject_unref(rsp);
        }
        csd = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                        "'driver':'femu','id':'ocp','addr':'5',"
                        "'devsz_mb':64,'femu_mode':1,'ocp':true,"
                        "'ocp_profile':'BAABABBAAABAB'}}");
        g_assert_true(qdict_haskey(csd, "return"));
        qobject_unref(csd);
        pdev = qpci_device_find(femu->dev.bus, QPCI_DEVFN(5, 0));
        g_assert_nonnull(pdev);
        femu_enable(&c, pdev, alloc);
        buf = guest_alloc(alloc, 4096);
        g_assert_cmphex(femu_identify(&c, 0, NVME_ID_CNS_CTRL, 0, buf), ==,
                        NVME_SUCCESS);
        qtest_memread(qts, buf, &id, sizeof(id));
        g_assert_cmphex(le16_to_cpu(id.oncs) & 0x2, ==, 0x2);
        guest_free(alloc, buf);
        femu_disable(&c);
        qpci_unplug_acpi_device_test(qts, "ocp", 5);
        g_free(pdev);
    }

    /* a CSD controller takes it */
    csd = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                    "'driver':'femu','id':'ocp','addr':'5','devsz_mb':64,"
                    "'ocp':true,'femu_mode':4,'fdm_size':16}}");
    g_assert_true(qdict_haskey(csd, "return"));
    qobject_unref(csd);
    qpci_unplug_acpi_device_test(qts, "ocp", 5);

    for (int i = 0; i < ARRAY_SIZE(cases); i++) {
        for (int on = 1; on >= 0; on--) {
            g_autofree char *cmd = g_strdup_printf(
                "{'execute':'device_add','arguments':{'driver':'femu',"
                "'id':'ocp','addr':'5','devsz_mb':64,'ocp':%s,%s}}",
                on ? "true" : "false", cases[i]);
            QDict *rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));

            if (on) {
                const char *desc;

                g_assert_true(qdict_haskey(rsp, "error"));
                desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
                g_test_message("%s: %s", cases[i], desc);
                g_assert_nonnull(strstr(desc, "ocp"));
            } else {
                if (!qdict_haskey(rsp, "return")) {
                    g_test_message("control %s refused: %s", cases[i],
                                   qdict_get_str(qdict_get_qdict(rsp,
                                                 "error"), "desc"));
                    g_assert_not_reached();
                }
                qpci_unplug_acpi_device_test(qts, "ocp", 5);
            }
            qobject_unref(rsp);
        }
    }
}

/*
 * Read the four Error Information entries (the default count) into a poisoned
 * buffer, so a byte the controller did not send cannot pass.
 */
static void femu_err21_read(FemuCtrlState *c, uint64_t buf, uint8_t *log)
{
    QTestState *qts = c->pdev->bus->qts;

    qtest_memset(qts, buf, 0xa5, 4096);
    g_assert_cmpint(femu_log_cmd(c, 0xffffffff, FEMU_LOG_ERROR_INFO, 0, buf,
                                 256), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, log, 256);
}

/* entry @e is empty: Error Count 0, LPVER @lpver, every other byte 0 */
static void femu_err21_empty(const uint8_t *log, int e, uint8_t lpver)
{
    const uint8_t *ent = log + 64 * e;

    for (int b = 0; b < 64; b++) {
        if (ent[b] != (b == 63 ? lpver : 0)) {
            g_test_message("entry %d byte %d is 0x%02x", e, b, ent[b]);
        }
        g_assert_cmphex(ent[b], ==, b == 63 ? lpver : 0);
    }
}

/*
 * Base 2.1 Figure 205: an Error Information entry carries the command set
 * (byte 30) and the opcode (byte 31) of the failed command, and log page
 * version 1 (byte 63) in every entry, an empty one too (TP4113a). Each
 * variant runs on a device line of its own, so the ring starts empty. OCSSD
 * keeps its 1.4 entries, with no new byte set. @data names the variant.
 */
void femu_test_error_log_fields(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    const char *v = data;
    bool ocssd = !strcmp(v, "ocssd");
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    uint8_t log[256];
    uint16_t cid[2] = { 0 };
    uint8_t csi = 0;
    uint8_t opc = 0;
    int n = 2;
    int e;

    femu_enable(&c, &femu->dev, alloc);
    femu_err21_read(&c, buf, log);
    for (e = 0; e < 4; e++) {
        femu_err21_empty(log, e, ocssd ? 0 : 1);
    }
    if (ocssd) {
        /*
         * A vector read and a vector erase over 64 addresses, refused by
         * the two OCSSD writers before any transfer. Their entries keep
         * bytes 30, 31 and 63 at 0, as in an NVMe 1.4 log.
         */
        static const uint8_t ops[] = { 0x92, 0x90 };

        femu_create_io_queues(&c);
        for (e = 0; e < 2; e++) {
            NvmeRwCmd rw;

            memset(&rw, 0, sizeof(rw));
            rw.opcode = ops[e];
            rw.nsid = cpu_to_le32(1);
            rw.nlb = cpu_to_le16(64);
            cid[e] = c.cid;
            g_assert_cmpint(femu_io(&c, (NvmeCmd *)&rw), ==,
                            NVME_INVALID_FIELD);
        }
        femu_err21_read(&c, buf, log);
        for (e = 0; e < 2; e++) {
            const uint8_t *ent = log + 64 * e;

            g_assert_cmpuint(ldq_le_p(ent), ==, 2 - e);
            g_assert_cmphex(lduw_le_p(ent + 10), ==, cid[1 - e]);
            g_assert_cmphex(ent[30], ==, 0);
            g_assert_cmphex(ent[31], ==, 0);
            g_assert_cmphex(ent[63], ==, 0);
        }
        goto out;
    }

    if (!strcmp(v, "nvm")) {
        femu_create_io_queues(&c);
        opc = NVME_CMD_READ;
        for (e = 0; e < 2; e++) {
            cid[e] = c.cid;
            g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_READ, 0xfffff000,
                                            buf)), ==, NVME_LBA_RANGE);
        }
    } else if (!strcmp(v, "zns")) {
        NvmeCmd cmp;

        femu_create_io_queues(&c);
        g_assert_cmpint(FEMU_SC(femu_rw(&c, NVME_CMD_WRITE, 0, buf)), ==,
                        NVME_SUCCESS);
        /* a Compare in a written zone with no data pointer */
        memset(&cmp, 0, sizeof(cmp));
        cmp.opcode = NVME_CMD_COMPARE;
        cmp.nsid = cpu_to_le32(1);
        cid[0] = c.cid;
        g_assert_cmpint(femu_io(&c, &cmp), ==, NVME_INVALID_FIELD);
        csi = FEMU_CSI_ZONED;
        opc = NVME_CMD_COMPARE;
        n = 1;
    } else {
        /* a Namespace Attachment whose list names another controller */
        cid[0] = c.cid;
        g_assert_cmpint(femu_ns_attach(&c, buf, 1, 1, true), ==, 0x11c);
        opc = NVME_ADM_CMD_NS_ATTACHMENT;
        n = 1;
    }

    femu_err21_read(&c, buf, log);
    for (e = 0; e < n; e++) {
        const uint8_t *ent = log + 64 * e;

        /* newest first */
        g_assert_cmpuint(ldq_le_p(ent), ==, n - e);
        g_assert_cmphex(lduw_le_p(ent + 10), ==, cid[n - 1 - e]);
        g_assert_cmphex(ent[29], ==, 0);
        g_assert_cmphex(ent[30], ==, csi);
        g_assert_cmphex(ent[31], ==, opc);
        g_assert_cmphex(ent[63], ==, 1);
    }
    for (; e < 4; e++) {
        femu_err21_empty(log, e, 1);
    }
out:
    guest_free(alloc, buf);
    femu_disable(&c);
}

/*
 * Identify for a Format Index with Namespace Management on (TP4095a):
 * CNS 09h returns the Identify Namespace fields that hold for a format
 * (NLBAF, MC, DPC, NMIC and the LBA formats), and CNS 0Ah with CSI 00h a
 * zero NVM structure, as CNS 05h is. An index past the raw NLBAF is an
 * invalid field. The expected bytes come from the device properties: 5
 * block sizes from 512 B, each also with @meta bytes of metadata when
 * @meta is set. @data is "meta", "empty" (every namespace deleted first)
 * or anything else for a plain line.
 */
void femu_test_identify_fmt(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    bool meta = !strcmp(data, "meta");
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 4096);
    int nlbaf = meta ? 9 : 4;
    uint8_t want[4096] = { 0 };
    uint8_t got[4096];
    int i;

    femu_enable(&c, &femu->dev, alloc);
    if (!strcmp(data, "empty")) {
        g_assert_cmpint(femu_ns_delete(&c, 0xffffffff), ==, NVME_SUCCESS);
    }
    want[25] = nlbaf;
    want[27] = meta ? 3 : 0;
    want[28] = meta ? 0x17 : 0;
    for (i = 0; i <= nlbaf; i++) {
        stw_le_p(want + 128 + 4 * i, i >= 5 ? 8 : 0);
        want[128 + 4 * i + 2] = 9 + i % 5;
    }
    for (i = 0; i <= nlbaf; i++) {
        qtest_memset(qts, buf, 0xa5, 4096);
        g_assert_cmpint(femu_identify(&c, 0, 0x09, i, buf), ==, NVME_SUCCESS);
        qtest_memread(qts, buf, got, sizeof(got));
        g_assert_cmpmem(got, sizeof(got), want, sizeof(want));
        qtest_memset(qts, buf, 0xa5, 4096);
        g_assert_cmpint(femu_identify(&c, 0, 0x0a, i, buf), ==, NVME_SUCCESS);
        qtest_memread(qts, buf, got, sizeof(got));
        for (int b = 0; b < sizeof(got); b++) {
            g_assert_cmphex(got[b], ==, 0);
        }
    }
    g_assert_cmpint(femu_identify(&c, 0, 0x09, nlbaf + 1, buf), ==,
                    NVME_INVALID_FIELD);
    g_assert_cmpint(femu_identify(&c, 0, 0x0a, nlbaf + 1, buf), ==,
                    NVME_INVALID_FIELD);
    /* CNS 09h belongs to the NVM Command Set */
    g_assert_cmpint(femu_identify(&c, 0, 0x09,
                                  ((uint32_t)FEMU_CSI_ZONED << 24), buf), ==,
                    NVME_INVALID_FIELD);
    guest_free(alloc, buf);
    femu_disable(&c);
}

/* maint_idle needs gc_idle_ms, and bbssd */
void femu_test_maint_idle_refused(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    static const struct {
        const char *opts;
        const char *want;
    } bad[] = {
        { "'femu_mode':1,'maint_idle':true", "maint_idle needs gc_idle_ms" },
        { "'femu_mode':2,'maint_idle':true,'gc_idle_ms':5",
          "gc_idle_ms is not supported" },
    };

    for (size_t i = 0; i < ARRAY_SIZE(bad); i++) {
        g_autofree char *json = g_strdup_printf(
            "{'driver':'femu','id':'mir','addr':'6','devsz_mb':16,%s}",
            bad[i].opts);
        QObject *args = qobject_from_json(json, &error_abort);
        QDict *rsp = qtest_qmp(qts, "{'execute':'device_add',"
                               "'arguments':%p}", args);

        g_assert_true(qdict_haskey(rsp, "error"));
        g_test_message("maint-idle-refused %s: %s", bad[i].opts,
                       qdict_get_str(qdict_get_qdict(rsp, "error"), "desc"));
        g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                              "desc"), bad[i].want));
        qobject_unref(rsp);
    }
}

/* gc_idle_ms is refused where the first version cannot keep its model */
void femu_test_gc_idle_refused(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    static const struct {
        const char *opts;
        const char *msg;
    } tc[] = {
        { "'blks_per_pl':80,'gc_pace':true", "gc_pace" },
        { "'blks_per_pl':80,'streams':true", "Streams" },
        { "'blks_per_pl':80,'power_loss':true,'buffer_size':16",
          "power_loss" },
        { "'blks_per_pl':80,'ns_mgmt':true", "ns_mgmt" },
        { "'blks_per_pl':80,'femu_mode':4,'fdm_size':16", "femu_mode 4" },
        { "'blks_per_pl':80,'mapping':'dftl'", "a mapping other than page" },
        { "'blks_per_pl':80,'namespaces':2", "more than one namespace" },
        { "'blks_per_pl':80,'subsys':'fdpsub'", "FDP" },
        { "'blks_per_pl':80,'gc_idle_pcent':100", "gc_idle_pcent above 99" },
        { "'blks_per_pl':160,'tier_mode':'static','tier_static_mb':1,"
          "'nand_cell_type':3", "the pSLC tier" },
    };

    for (int i = 0; i < ARRAY_SIZE(tc); i++) {
        g_autofree char *cmd = g_strdup_printf(
            "{'execute':'device_add','arguments':{'driver':'femu',"
            "'id':'gcir','addr':'5','devsz_mb':4,'secsz':512,"
            "'secs_per_pg':8,'pgs_per_blk':16,'pls_per_lun':1,"
            "'luns_per_ch':1,'nchs':1,'gc_idle_ms':5,%s%s}}", tc[i].opts,
            strstr(tc[i].opts, "femu_mode") ? "" : ",'femu_mode':1");
        QDict *rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));
        const char *desc;

        g_assert_true(qdict_haskey(rsp, "error"));
        desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
        g_test_message("%s: %s", tc[i].opts, desc);
        g_assert_nonnull(strstr(desc, tc[i].msg));
        g_assert_nonnull(strstr(desc, "gc_idle_ms"));
        qobject_unref(rsp);
    }
    /*
     * The controls: the plain line with gc_idle_ms is accepted, and so is
     * each refused line with gc_idle_ms=0, so each refusal comes from
     * gc_idle_ms and not from the rest of its line.
     */
    for (int i = -1; i < (int)ARRAY_SIZE(tc); i++) {
        g_autofree char *cmd = g_strdup_printf(
            "{'execute':'device_add','arguments':{'driver':'femu',"
            "'id':'gcir','addr':'5','devsz_mb':4,'secsz':512,"
            "'secs_per_pg':8,'pgs_per_blk':16,'pls_per_lun':1,"
            "'luns_per_ch':1,'nchs':1,'gc_idle_ms':%d,%s%s}}",
            i < 0 ? 5 : 0, i < 0 ? "'blks_per_pl':80" : tc[i].opts,
            i >= 0 && strstr(tc[i].opts, "femu_mode") ? "" :
            ",'femu_mode':1");
        QDict *rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));

        if (i >= 0 && strstr(tc[i].msg, "gc_idle_pcent")) {
            /* the percent alone only warns; drop the device it made */
            g_assert_true(qdict_haskey(rsp, "return"));
        } else if (!qdict_haskey(rsp, "return")) {
            g_test_message("control %d refused: %s", i,
                           qdict_get_str(qdict_get_qdict(rsp, "error"),
                                         "desc"));
            g_assert_not_reached();
        }
        qobject_unref(rsp);
        qpci_unplug_acpi_device_test(qts, "gcir", 5);
    }
}

/* the pSLC tier geometry of the tier tests (FEMU_TIER_GEO), for QMP */
#define FEMU_GC_FW_TIER_QMP \
    "'secsz':512,'secs_per_pg':8,'pgs_per_blk':48,'blks_per_pl':32," \
    "'pls_per_lun':1,'luns_per_ch':2,'nchs':2,'nand_cell_type':3"

/* fw_gc_page_ns refuses a negative time and the settings it cannot time */
void femu_test_gc_fw_refused(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    const struct {
        int ns;
        const char *extra;
        const char *why;
    } cases[] = {
        { -1, "'femu_mode':1", "must not be negative" },
        { 1000, "'femu_mode':1,'gc_erase_order':false",
          "gc_erase_order=off" },
        { 1000, "'femu_mode':1,'pe_suspend':1", "with pe_suspend" },
        { 1000, "'femu_mode':0", "a mode other than bbssd or CSD" },
        { 1000, "'femu_mode':3", "a mode other than bbssd or CSD" },
    };
    static const char *const allowed[] = {
        "'femu_mode':1,'namespace_modes':''",
        "'femu_mode':1,'mapping':'hybrid'",
        "'femu_mode':1,'mapping':'fast'",
        "'femu_mode':1," FEMU_GC_FW_TIER_QMP ",'tier_mode':'static',"
        "'tier_static_mb':1",
        "'femu_mode':1," FEMU_GC_FW_TIER_QMP ",'tier_mode':'dynamic'",
    };
    int i;

    for (i = 0; i < ARRAY_SIZE(cases); i++) {
        g_autofree char *args = g_strdup_printf(
            "{'driver':'femu','id':'fw-refused','addr':'5','devsz_mb':16,"
            "'fw_gc_page_ns':%d,%s}", cases[i].ns, cases[i].extra);
        QDict *rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':%p}",
                               qobject_from_json(args, &error_abort));
        const char *desc;

        g_assert_true(qdict_haskey(rsp, "error"));
        desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
        g_test_message("%s: %s", cases[i].extra, desc);
        g_assert_nonnull(strstr(desc, "fw_gc_page_ns"));
        g_assert_nonnull(strstr(desc, cases[i].why));
        qobject_unref(rsp);
    }
    /*
     * Allowed: an empty namespace_modes (the default) and the paths that
     * take slots outside line collection.
     */
    for (i = 0; i < ARRAY_SIZE(allowed); i++) {
        g_autofree char *args = g_strdup_printf(
            "{'driver':'femu','id':'fw-ok','addr':'5','devsz_mb':16,"
            "'fw_gc_page_ns':1000,%s}", allowed[i]);
        QDict *rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':%p}",
                               qobject_from_json(args, &error_abort));

        if (qdict_haskey(rsp, "error")) {
            g_test_message("%s refused: %s", allowed[i],
                           qdict_get_str(qdict_get_qdict(rsp, "error"),
                                         "desc"));
        }
        g_assert_false(qdict_haskey(rsp, "error"));
        qobject_unref(rsp);
        qpci_unplug_acpi_device_test(qts, "fw-ok", 5);
    }
    qos_invalidate_command_line();
}

/* a NAND profile file with @text, in the temporary directory */
static char *femu_np_file(const char *text)
{
    GError *err = NULL;
    char *path;
    int fd = g_file_open_tmp("femu-np-XXXXXX", &path, &err);

    g_assert_no_error(err);
    g_assert_cmpint(write(fd, text, strlen(text)), ==, strlen(text));
    close(fd);
    return path;
}

#define FEMU_NP_DEFAULT \
    "femu_nand_profile = 1\nname = bbssd-flat-default\nnand_type = none\n" \
    "read_ns = 40000\nprogram_ns = 200000\nerase_ns = 2000000\n" \
    "cmd_addr_ns = 0\nxfer_ns = 0\nstatus_ns = 0\n"
/* values away from the defaults, out of key order, two with a source */
#define FEMU_NP_CUSTOM \
    "; a chip with every value away from the defaults\n" \
    "femu_nand_profile = 1\nname = custom\nstatus_ns = 33\n" \
    "source.status_ns = bus; #9\nread_ns = 051000\nnand_type = tlc\n" \
    "source.read_ns = Table 1\nprogram_ns = 210000\nerase_ns = 2100000\n" \
    "cmd_addr_ns = 11\nxfer_ns = 22\n"
/* no NAND type, and a ZNS QLC program time above INT32_MAX: 4 pages */
#define FEMU_NP_BIG \
    "femu_nand_profile = 1\nname = big\nnand_type = none\n" \
    "read_ns = 51000\nprogram_ns = 600000000\nerase_ns = 2100000\n" \
    "cmd_addr_ns = 0\nxfer_ns = 0\nstatus_ns = 0\n"
#define FEMU_NP_BB "'secsz':512,'secs_per_pg':8,'pgs_per_blk':32," \
    "'blks_per_pl':12,'pls_per_lun':1,'luns_per_ch':1,'nchs':1,'devsz_mb':1"

/* add femu @id at @addr with @opts, which must realize */
static void femu_np_add(QTestState *qts, const char *id, int addr,
                        const char *opts)
{
    g_autofree char *cmd = g_strdup_printf(
        "{'execute':'device_add','arguments':{'driver':'femu','id':'%s',"
        "'addr':'%x',%s}}", id, addr, opts);    /* QEMU reads addr as hex */
    QDict *rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));

    if (qdict_haskey(rsp, "error")) {
        g_test_message("%s refused: %s", id,
                       qdict_get_str(qdict_get_qdict(rsp, "error"), "desc"));
    }
    g_assert_false(qdict_haskey(rsp, "error"));
    qobject_unref(rsp);
}

static const char *const femu_np_keys[] = {
    "nand_type", "read_ns", "program_ns", "erase_ns", "cmd_addr_ns",
    "xfer_ns", "status_ns",
};

/*
 * The value list of a profile: seven entries in line order. A shipped
 * file gives a source for each value; the test files give none. The
 * custom file reads back its raw times, also on ZNS.
 */
static void femu_np_values(QDict *md, const char *name, const char *file)
{
    /* FEMU_NP_CUSTOM in the order of its lines: key, value, line, source */
    static const struct {
        const char *key;
        const char *val;
        int line;
        int src_line;
        const char *src;
    } custom[] = {
        { "status_ns", "33", 4, 5, "bus; #9" },
        { "read_ns", "51000", 6, 8, "Table 1" },
        { "nand_type", "tlc", 7, 0, NULL },
        { "program_ns", "210000", 9, 0, NULL },
        { "erase_ns", "2100000", 10, 0, NULL },
        { "cmd_addr_ns", "11", 11, 0, NULL },
        { "xfer_ns", "22", 12, 0, NULL },
    };
    QList *vals = qdict_get_qlist(md, "nand-profile-values");
    bool shipped = strstr(file, "profiles/") != NULL;
    bool is_custom = g_str_equal(name, "custom");
    int64_t last = 0;
    int n = 0;

    g_assert_nonnull(vals);
    for (const QListEntry *e = qlist_first(vals); e; e = qlist_next(e)) {
        QDict *v = qobject_to(QDict, qlist_entry_obj(e));
        const char *key = qdict_get_str(v, "key");
        const char *val = qdict_get_str(v, "value");

        if (is_custom) {
            g_assert_cmpint(n, <, ARRAY_SIZE(custom));
            g_assert_cmpstr(key, ==, custom[n].key);
            g_assert_cmpstr(val, ==, custom[n].val);
            g_assert_cmpint(qdict_get_int(v, "line"), ==, custom[n].line);
            g_assert_cmpint(qdict_haskey(v, "source"), ==, !!custom[n].src);
            g_assert_cmpint(qdict_haskey(v, "source-line"), ==,
                            !!custom[n].src);
            if (custom[n].src) {
                g_assert_cmpstr(qdict_get_str(v, "source"), ==,
                                custom[n].src);
                g_assert_cmpint(qdict_get_int(v, "source-line"), ==,
                                custom[n].src_line);
            }
            n++;
            continue;
        }
        /* the shipped files and FEMU_NP_BIG list the keys in key order */
        g_assert_cmpint(n, <, ARRAY_SIZE(femu_np_keys));
        g_assert_cmpstr(key, ==, femu_np_keys[n]);
        g_assert_cmpint(qdict_get_int(v, "line"), >, last);
        last = qdict_get_int(v, "line");
        g_assert_cmpint(qdict_haskey(v, "source"), ==, shipped);
        g_assert_cmpint(qdict_haskey(v, "source-line"), ==, shipped);
        if (shipped) {
            g_assert_cmpstr(qdict_get_str(v, "source"), !=, "");
            g_assert_cmpint(qdict_get_int(v, "source-line"), ==, last + 1);
        }
        if (g_str_equal(name, "big") && g_str_equal(key, "program_ns")) {
            g_assert_cmpstr(val, ==, "600000000");
        }
        if (g_str_equal(name, "big") && g_str_equal(key, "nand_type")) {
            g_assert_cmpstr(val, ==, "none");
        }
        n++;
    }
    g_assert_cmpint(n, ==, 7);
}

/*
 * The media member of device @id at @slot: base times, timing and profile.
 * query-femu needs an enabled controller, so this enables it around the
 * query.
 */
static void femu_np_check(QFemu *femu, QGuestAllocator *alloc, const char *id,
                          int slot, uint64_t rd, uint64_t wr, uint64_t er,
                          const char *timing, const char *name,
                          const char *file)
{
    QTestState *qts = femu->dev.bus->qts;
    g_autofree char *arg = g_strdup_printf("'path':'/machine/peripheral/%s'",
                                           id);
    QPCIDevice *pdev = qpci_device_find(femu->dev.bus, QPCI_DEVFN(slot, 0));
    FemuCtrlState c = { 0 };
    QDict *rsp;
    QDict *md;

    g_assert_nonnull(pdev);
    femu_enable(&c, pdev, alloc);
    md = qdict_get_qdict(femu_query_ns(qts, arg, &rsp), "media");

    g_assert_cmpuint(qdict_get_int(md, "read-ns"), ==, rd);
    g_assert_cmpuint(qdict_get_int(md, "program-ns"), ==, wr);
    g_assert_cmpuint(qdict_get_int(md, "erase-ns"), ==, er);
    g_assert_cmpstr(qdict_get_str(md, "array-timing"), ==, timing);
    if (name) {
        g_assert_cmpstr(qdict_get_str(md, "nand-profile"), ==, name);
        g_assert_cmpstr(qdict_get_str(md, "nand-profile-file"), ==, file);
        femu_np_values(md, name, file);
    } else {
        g_assert_false(qdict_haskey(md, "nand-profile"));
        g_assert_false(qdict_haskey(md, "nand-profile-file"));
        g_assert_false(qdict_haskey(md, "nand-profile-values"));
    }
    if (g_str_equal(id, "np2") || g_str_equal(id, "np3")) {
        /* all three bus keys of the custom profile reach bbssd and ZNS */
        g_assert_true(qdict_get_bool(md, "staged-bus"));
        g_assert_cmpuint(qdict_get_int(md, "read-command-ns"), ==, 11);
        g_assert_cmpuint(qdict_get_int(md, "page-transfer-ns"), ==, 22);
        g_assert_cmpuint(qdict_get_int(md, "status-ns"), ==, 33);
    }
    qobject_unref(rsp);
    femu_disable(&c);
    g_free(pdev);
}

/* integer property @prop of device @id */
static int64_t femu_np_qom(QTestState *qts, const char *id, const char *prop)
{
    g_autofree char *path = g_strdup_printf("/machine/peripheral/%s", id);
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                           "'path':%s,'property':%s}}", path, prop);
    int64_t v;

    g_assert_true(qdict_haskey(rsp, "return"));
    v = qdict_get_int(rsp, "return");
    qobject_unref(rsp);
    return v;
}

/*
 * A profile file in hw/femu/profiles. The qtests run in the build
 * directory, one level below the source tree, or in the source tree.
 */
static char *femu_np_shipped(const char *name)
{
    char *p = g_strdup_printf("../hw/femu/profiles/%s", name);

    if (!g_file_test(p, G_FILE_TEST_EXISTS)) {
        g_free(p);
        p = g_strdup_printf("hw/femu/profiles/%s", name);
    }
    g_assert_true(g_file_test(p, G_FILE_TEST_EXISTS));
    return p;
}

/*
 * nand_profile. In one QEMU: bbssd with no profile, with the default
 * profile and with a custom one, ZNS with the custom one (its program
 * covers a QLC wordline: 4 pages), and bbssd with a NAND type table. Each
 * keeps its own times, read back from the live media.
 */
void femu_test_nand_profile(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    g_autofree char *def = femu_np_file(FEMU_NP_DEFAULT);
    g_autofree char *cus = femu_np_file(FEMU_NP_CUSTOM);
    g_autofree char *o1 = g_strdup_printf("'femu_mode':1,%s,'nand_profile':"
                                          "'%s'", FEMU_NP_BB, def);
    g_autofree char *o2 = g_strdup_printf("'femu_mode':1,%s,'nand_profile':"
                                          "'%s'", FEMU_NP_BB, cus);
    g_autofree char *o3 = g_strdup_printf("'femu_mode':3,'devsz_mb':64,"
                                          "'nand_profile':'%s'", cus);

    femu_np_add(qts, "np0", 5, "'femu_mode':1," FEMU_NP_BB);
    femu_np_add(qts, "np1", 6, o1);
    femu_np_add(qts, "np2", 7, o2);
    femu_np_add(qts, "np3", 8, o3);
    femu_np_add(qts, "np4", 9, "'femu_mode':1,'nand_cell_type':3,"
                FEMU_NP_BB);
    {
        g_autofree char *sb = femu_np_shipped("bbssd-flat-default.nprof");
        g_autofree char *sz = femu_np_shipped("qlc-zns-default.nprof");
        g_autofree char *o5 = g_strdup_printf("'femu_mode':1,%s,"
                                              "'nand_profile':'%s'",
                                              FEMU_NP_BB, sb);
        g_autofree char *o6 = g_strdup_printf("'femu_mode':3,'devsz_mb':64,"
                                              "'nand_profile':'%s'", sz);
        g_autofree char *o7 = g_strdup_printf("'femu_mode':4,'fdm_size':16,"
                                              "%s,'nand_profile':'%s'",
                                              FEMU_NP_BB, cus);

        femu_np_add(qts, "np5", 10, o5);
        femu_np_add(qts, "np6", 11, o6);
        femu_np_add(qts, "np7", 12, o7);
        femu_np_add(qts, "np8", 13, "'femu_mode':1,'pgtype_lat':1,"
                    "'cell_pages':3," FEMU_NP_BB);
        /* the shipped files give exactly today's defaults */
        femu_np_check(femu, alloc, "np5", 10, 40000, 200000, 2000000, "flat",
                      "bbssd-flat-default", sb);
        femu_np_check(femu, alloc, "np6", 11, 85000, 12196000, 3000000,
                      "table", "qlc-zns-default", sz);
        /* CSD runs the bbssd FTL, so it takes a profile too */
        femu_np_check(femu, alloc, "np7", 12, 51000, 210000, 2100000, "flat",
                      "custom", cus);
        /* page types: program times vary, page 0 is 0.6 of pg_wr_lat */
        femu_np_check(femu, alloc, "np8", 13, 40000, 120000, 2000000,
                      "page-type", NULL, NULL);
        for (int a = 10; a <= 13; a++) {
            g_autofree char *id = g_strdup_printf("np%d", a - 5);

            qpci_unplug_acpi_device_test(qts, id, a);
        }
    }
    /*
     * ZNS takes its wordline from zns_flash_type, not from nand_type: SLC
     * programs one page. With nand_type none the rating stays 0, and the
     * QLC product 4 x 600000000 does not fit in 32 bits.
     */
    {
        g_autofree char *big = femu_np_file(FEMU_NP_BIG);
        g_autofree char *o9 = g_strdup_printf("'femu_mode':3,'devsz_mb':64,"
                                              "'nand_profile':'%s'", big);
        g_autofree char *o10 = g_strdup_printf("'femu_mode':3,'devsz_mb':64,"
                                               "'zns_flash_type':1,"
                                               "'nand_profile':'%s'", cus);

        femu_np_add(qts, "np9", 14, o9);
        femu_np_add(qts, "np10", 15, o10);
        g_assert_cmpint(femu_np_qom(qts, "np9", "zns_pg_wr_lat"), ==,
                        2400000000LL);
        g_assert_cmpint(femu_np_qom(qts, "np9", "pe_cycles_rated"), ==, 0);
        g_assert_cmpint(femu_np_qom(qts, "np10", "zns_pg_wr_lat"), ==,
                        210000);
        /* TLC_RATED_PE_CYCLES */
        g_assert_cmpint(femu_np_qom(qts, "np10", "pe_cycles_rated"), ==,
                        1000);
        femu_np_check(femu, alloc, "np9", 14, 51000, 2400000000ULL, 2100000,
                      "table", "big", big);
        femu_np_check(femu, alloc, "np10", 15, 51000, 210000, 2100000,
                      "table", "custom", cus);
        qpci_unplug_acpi_device_test(qts, "np9", 14);
        qpci_unplug_acpi_device_test(qts, "np10", 15);
        unlink(big);
    }
    /* realize keeps its copy: a change to the file does not reach query */
    g_assert_true(g_file_set_contents(cus, FEMU_NP_DEFAULT, -1, NULL));
    /* a profile with the old defaults gives exactly the old times */
    femu_np_check(femu, alloc, "np0", 5, 40000, 200000, 2000000, "flat",
                  NULL, NULL);
    femu_np_check(femu, alloc, "np1", 6, 40000, 200000, 2000000, "flat",
                  "bbssd-flat-default", def);
    femu_np_check(femu, alloc, "np2", 7, 51000, 210000, 2100000, "flat",
                  "custom", cus);
    femu_np_check(femu, alloc, "np3", 8, 51000, 4 * 210000, 2100000, "table",
                  "custom", cus);
    femu_np_check(femu, alloc, "np4", 9, 56500, 820500, 3000000, "table",
                  NULL, NULL);
    for (int a = 5; a <= 9; a++) {
        g_autofree char *id = g_strdup_printf("np%d", a - 5);

        qpci_unplug_acpi_device_test(qts, id, a);
    }
    unlink(def);
    unlink(cus);
}

/* each rule of nand_profile alone, with the specific message, and a control */
void femu_test_nand_profile_refused(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    static const struct {
        const char *text;
        const char *opts;
        const char *msg;
    } tc[] = {
        { FEMU_NP_DEFAULT "speed = 1\n", NULL, "unknown key 'speed'" },
        { FEMU_NP_DEFAULT "read_ns = 1\n", NULL, "given twice" },
        { "femu_nand_profile = 1\nname = x\n", NULL, "missing key" },
        { "femu_nand_profile = 2\n", NULL, "version '2'" },
        { "name = x\n", NULL, "first key" },
        { "femu_nand_profile = 1\nname = x\nnand_type = plc\n", NULL,
          "nand_type" },
        { "femu_nand_profile = 1\nread_ns = 0\n", NULL, "read_ns" },
        { "femu_nand_profile = 1\nread_ns = 2147483648\n", NULL, "read_ns" },
        { "femu_nand_profile = 1\nread_ns = 4294967297\n", NULL, "read_ns" },
        { "femu_nand_profile = 1\nread_ns = 40000x\n", NULL, "read_ns" },
        { FEMU_NP_DEFAULT, "'pg_rd_lat':41000", "pg_rd_lat must keep" },
        { FEMU_NP_DEFAULT, "'pgtype_lat':1", "pgtype_lat must keep" },
        { FEMU_NP_DEFAULT, "'ch_xfer_lat':5", "ch_xfer_lat must keep" },
        { FEMU_NP_DEFAULT "source.read_ns =\n", NULL, "1 to 255 bytes" },
        { FEMU_NP_DEFAULT "source.name = x\n", NULL, "not a value key" },
        { FEMU_NP_DEFAULT "source.xfer_ns = a\nsource.xfer_ns = a\n", NULL,
          "given twice" },
        { "source.read_ns = x\n" FEMU_NP_DEFAULT, NULL, "first key" },
    };
    static const char *const modes[] = { "'femu_mode':2", "'femu_mode':0" };
    g_autofree char *good = femu_np_file(FEMU_NP_DEFAULT);

    for (int i = 0; i < ARRAY_SIZE(tc); i++) {
        g_autofree char *f = femu_np_file(tc[i].text);
        g_autofree char *cmd = g_strdup_printf(
            "{'execute':'device_add','arguments':{'driver':'femu','id':'npr',"
            "'addr':'5','femu_mode':1,%s,'nand_profile':'%s'%s%s}}",
            FEMU_NP_BB, f, tc[i].opts ? "," : "",
            tc[i].opts ? tc[i].opts : "");
        QDict *rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));
        const char *desc;

        g_assert_true(qdict_haskey(rsp, "error"));
        desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
        g_test_message("case %d: %s", i, desc);
        g_assert_nonnull(strstr(desc, tc[i].msg));
        qobject_unref(rsp);
        unlink(f);
    }
    /* a NUL byte would hide the rest of the file from the parser */
    {
        static const char nul[] = FEMU_NP_DEFAULT "\0read_ns = 1\n";
        g_autofree char *f = femu_np_file("");
        g_autofree char *cmd = NULL;
        QDict *rsp;

        g_assert_true(g_file_set_contents(f, nul, sizeof(nul) - 1, NULL));
        cmd = g_strdup_printf("{'execute':'device_add','arguments':{"
                              "'driver':'femu','id':'npr','addr':'5',"
                              "'femu_mode':1,%s,'nand_profile':'%s'}}",
                              FEMU_NP_BB, f);
        rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));
        g_assert_true(qdict_haskey(rsp, "error"));
        g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                              "desc"), "holds a NUL byte"));
        qobject_unref(rsp);
        unlink(f);
    }
    for (int i = 0; i < ARRAY_SIZE(modes); i++) {
        g_autofree char *cmd = g_strdup_printf(
            "{'execute':'device_add','arguments':{'driver':'femu','id':'npr',"
            "'addr':'5','devsz_mb':64,%s,'nand_profile':'%s'}}", modes[i],
            good);
        QDict *rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));

        g_assert_true(qdict_haskey(rsp, "error"));
        g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                              "desc"), "nand_profile needs"));
        qobject_unref(rsp);
    }
    /* the control: the same device line and a good file */
    {
        g_autofree char *o = g_strdup_printf("'femu_mode':1,%s,'nand_profile'"
                                             ":'%s'", FEMU_NP_BB, good);
        /* a timing property given at its default value is no conflict */
        g_autofree char *od = g_strdup_printf("'femu_mode':1,%s,"
                                              "'pg_rd_lat':40000,"
                                              "'nand_profile':'%s'",
                                              FEMU_NP_BB, good);

        femu_np_add(qts, "npr", 5, o);
        qpci_unplug_acpi_device_test(qts, "npr", 5);
        femu_np_add(qts, "npr", 5, od);
        qpci_unplug_acpi_device_test(qts, "npr", 5);
    }
    unlink(good);
}

/* perf_hints is refused where the geometry does not set the write layout */
void femu_test_perf_hints_refused(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    static const struct {
        const char *opts;
        const char *msg;
    } cases[] = {
        { "'femu_mode':2,'perf_hints':true", "femu_mode" },
        { "'femu_mode':3,'perf_hints':true", "femu_mode" },
        { "'femu_mode':1,'secsz':512,'secs_per_pg':8,'pgs_per_blk':16,"
          "'blks_per_pl':80,'pls_per_lun':1,'luns_per_ch':1,'nchs':1,"
          "'ns_mgmt':true,'perf_hints':true", "ns_mgmt" },
        { "'femu_mode':1,'secsz':512,'secs_per_pg':8,'pgs_per_blk':16,"
          "'blks_per_pl':80,'pls_per_lun':1,'luns_per_ch':1,'nchs':1,"
          "'subsys':'fdpsub','perf_hints':true", "FDP" },
    };

    for (int i = 0; i < ARRAY_SIZE(cases); i++) {
        for (int on = 1; on >= 0; on--) {
            g_autofree char *opts = g_strdup(cases[i].opts);
            g_autofree char *cmd = NULL;
            QDict *rsp;

            if (!on) {
                /* the control: the same line with the property off */
                char *p = strstr(opts, "'perf_hints':true");
                char *off;

                g_assert_nonnull(p);
                *p = '\0';
                off = g_strdup_printf("%s'perf_hints':false%s", opts,
                                      p + strlen("'perf_hints':true"));
                g_free(opts);
                opts = off;
            }
            cmd = g_strdup_printf("{'execute':'device_add','arguments':{"
                                  "'driver':'femu','id':'phr','addr':'5',"
                                  "'devsz_mb':4,%s}}", opts);
            rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));
            if (on) {
                const char *desc;

                g_assert_true(qdict_haskey(rsp, "error"));
                desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
                g_test_message("%s: %s", cases[i].opts, desc);
                g_assert_nonnull(strstr(desc, "perf_hints"));
                g_assert_nonnull(strstr(desc, cases[i].msg));
            } else {
                if (!qdict_haskey(rsp, "return")) {
                    g_test_message("control %s refused: %s", opts,
                                   qdict_get_str(qdict_get_qdict(rsp,
                                                 "error"), "desc"));
                    g_assert_not_reached();
                }
                qpci_unplug_acpi_device_test(qts, "phr", 5);
            }
            qobject_unref(rsp);
        }
    }
}

/* atomic_write_lbas is refused where its unit cannot hold */
void femu_test_atomic_refused(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    static const struct {
        const char *opts;
        const char *msg;
    } cases[] = {
        { "'femu_mode':2,'atomic_write_lbas':1", "a power of two" },
        { "'femu_mode':2,'atomic_write_lbas':12", "a power of two" },
        { "'femu_mode':2,'atomic_write_lbas':131072", "a power of two" },
        { "'femu_mode':3,'atomic_write_lbas':16", "femu_mode" },
        { "'femu_mode':2,'mdts':1,'atomic_write_lbas':2", "exceed MDTS" },
        { "'femu_mode':1,'secsz':512,'secs_per_pg':8,'pgs_per_blk':16,"
          "'blks_per_pl':80,'pls_per_lun':1,'luns_per_ch':1,'nchs':1,"
          "'power_loss':true,'buffer_size':16,'atomic_write_lbas':16",
          "power_loss" },
    };

    for (int i = 0; i < ARRAY_SIZE(cases); i++) {
        for (int on = 1; on >= 0; on--) {
            g_autofree char *opts = g_strdup(cases[i].opts);
            g_autofree char *cmd = NULL;
            QDict *rsp;

            if (!on) {
                /* the control: the same line with the property off */
                char *p = strstr(opts, "'atomic_write_lbas':");

                g_assert_nonnull(p);
                strcpy(p, "'atomic_write_lbas':0");
            }
            cmd = g_strdup_printf("{'execute':'device_add','arguments':{"
                                  "'driver':'femu','id':'awu','addr':'5',"
                                  "'devsz_mb':4,%s}}", opts);
            rsp = qtest_qmp(qts, "%p", qobject_from_json(cmd, NULL));
            if (on) {
                const char *desc;

                g_assert_true(qdict_haskey(rsp, "error"));
                desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
                g_test_message("%s: %s", cases[i].opts, desc);
                g_assert_nonnull(strstr(desc, "atomic_write_lbas"));
                g_assert_nonnull(strstr(desc, cases[i].msg));
            } else {
                if (!qdict_haskey(rsp, "return")) {
                    g_test_message("control %s refused: %s", opts,
                                   qdict_get_str(qdict_get_qdict(rsp,
                                                 "error"), "desc"));
                    g_assert_not_reached();
                }
                qpci_unplug_acpi_device_test(qts, "awu", 5);
            }
            qobject_unref(rsp);
        }
    }
}

void femu_test_caps(void *obj, void *data, QGuestAllocator *alloc)
{
    const FemuCapsCfg *cfg = data;
    QFemu *femu = obj;
    FemuCtrlState c = { .pdev = &femu->dev, .alloc = alloc };
    g_autofree FemuCaps *k = g_new0(FemuCaps, 1);
    uint64_t buf;
    int i;

    k->bad = g_string_new(NULL);
    femu_queue_init(&c, &c.admin, 0);
    femu_enable_cc(&c, &femu->dev, alloc,
                   (6 << 16) | (4 << 20) | (FEMU_CC_CSS_CSI << 4) | 1);
    buf = guest_alloc(alloc, 4096);

    femu_caps_read(&c, k, buf);
    femu_caps_namespaces(&c, k, buf);
    femu_caps_entries(k, "admin", k->acs);
    for (i = 0; i < FEMU_CAPS_NCSI; i++) {
        femu_caps_entries(k, "I/O", k->iocs[i]);
        femu_caps_entries(k, "log", k->lids[i]);
    }
    femu_caps_identify(&c, k, buf);
    femu_caps_version(&c, k, g_str_has_prefix(cfg->name, "caps-oc"));
    femu_caps_csi_version(&c, k, buf, cfg->opts,
                          g_str_has_prefix(cfg->name, "caps-oc"));
    /* the masks the configuration asks for, independent of the registry */
    if ((le16_to_cpu(k->id.oncs) & 0x19f) != cfg->oncs) {
        femu_caps_bad(k, "ONCS is 0x%x; the configuration asks for 0x%x",
                      le16_to_cpu(k->id.oncs) & 0x19f, cfg->oncs);
    }
    femu_caps_bit(k, "OACS (configured)", 1 << 1,
                  le16_to_cpu(k->id.oacs) & (1 << 1), cfg->format);
    femu_caps_features(&c, k);

    femu_create_io_queues(&c);
    femu_caps_sgl(&c, k, buf);
    femu_caps_io(&c, k, buf);
    femu_caps_logs(&c, k, buf);
    /* last, since a zeroed admin command may format or reset something */
    femu_caps_admin(&c, k, buf);

    if (k->bad->len) {
        g_test_message("%s mismatches", cfg->name);
        g_test_message("%s", k->bad->str);
    }
    g_assert_cmpstr(k->bad->str, ==, "");
    g_string_free(k->bad, true);

    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

#define FEMU_CPS_SUB_GEO \
    "'secsz':512,'secs_per_pg':8,'pgs_per_blk':4,'blks_per_pl':25," \
    "'pls_per_lun':1,'luns_per_ch':2,'nchs':2"

/*
 * Reachability Reporting on one controller of a subsystem needs it on every
 * controller (Base 2.3 8.1.21). Only a CSD controller with a memory
 * namespace has it. nssub has FDP and Streams off, so only that rule can
 * refuse here. data set: the CSD controller is already in nssub.
 */
void femu_test_cps_subsys_single(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    QDict *rsp;

    if (data) {
        rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                        "'driver':'femu','id':'cps-second','addr':'5',"
                        "'devsz_mb':1,'femu_mode':1," FEMU_CPS_SUB_GEO ","
                        "'subsys':'nssub'}}");
    } else {
        rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                        "'driver':'femu','id':'cps-second','addr':'5',"
                        "'devsz_mb':1,'femu_mode':4,'fdm_size':16,"
                        "'csd_slm_size':4," FEMU_CPS_SUB_GEO ","
                        "'subsys':'nssub'}}");
    }
    g_assert_true(qdict_haskey(rsp, "error"));
    g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                         "desc"), "csd_slm_size"));
    qobject_unref(rsp);

    /* the refused controller left no slot behind */
    if (!data) {
        rsp = qtest_qmp(qts, "{'execute':'device_add','arguments':{"
                        "'driver':'femu','id':'cps-third','addr':'6',"
                        "'devsz_mb':1,'femu_mode':1," FEMU_CPS_SUB_GEO ","
                        "'subsys':'nssub'}}");
        g_assert_true(qdict_haskey(rsp, "return"));
        qobject_unref(rsp);
    }
    qos_invalidate_command_line();
}

/*
 * Critical warning events (type 05h, code 06h) in a Persistent Event log
 * context read at @buf whose warning byte has @bit set
 */
static int femu_pel_warnings(QTestState *qts, uint64_t buf, uint8_t bit)
{
    uint32_t tnev = qtest_readl(qts, buf + 4);
    int i, count = 0;

    for (i = 0; i < tnev; i++) {
        uint64_t e = femu_pel_at(qts, buf, i);

        if (e + 29 > buf + 4096) {
            break;
        }
        count += qtest_readb(qts, e) == 0x05 &&
                 qtest_readw(qts, e + 24) == 0x06 &&
                 (qtest_readb(qts, e + 28) & bit);
    }
    return count;
}

/* a command of @opcode on namespace 1 that names @nlb blocks from @slba */
static uint16_t femu_eol_cmd(FemuCtrlState *c, uint8_t opcode, uint64_t slba,
                             uint32_t nlb, uint64_t buf, uint32_t cdw11)
{
    NvmeCmd cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = opcode;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32((uint32_t)slba);
    cmd.cdw11 = cpu_to_le32(cdw11 ? cdw11 : (uint32_t)(slba >> 32));
    cmd.cdw12 = cpu_to_le32(nlb - 1);
    femu_submit(c, &c->io, &cmd);
    return femu_complete(c, &c->io, NULL, NULL);
}

/* NSATTR bit 0, Currently Write Protected, of CNS 00h and of CNS 08h */
static void femu_eol_cwp(FemuCtrlState *c, uint64_t buf, uint8_t want)
{
    QTestState *qts = c->pdev->bus->qts;

    g_assert_cmphex(femu_identify(c, 1, NVME_ID_CNS_NS, 0, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, buf + 99) & 1, ==, want);
    g_assert_cmphex(femu_identify(c, 1, FEMU_CNS_NS_CS_INDEP, 0, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, buf + 8) & 1, ==, want);
}

/*
 * Read-only end of life. Writes of one or two pages, fifteen in the queue
 * at a time and each in its own 16-page region, wear the media out. The
 * media goes read-only when a worn-out block finds no spare in its plane
 * (@data "pool"), or, with no spare lines, when retiring its line would
 * cut into the namespace's lines ("nopool", and "csd" for computational
 * storage). Writes in flight then still finish: every write completes with
 * success or Attempted Write to Read Only Range (82h, DNR), never Capacity
 * Exceeded. Then:
 * - SMART critical warning bit 3 is set and Available Spare reads 0; an
 *   AER enabled for bit 3 alone completes with information 00h;
 * - Write, Write Zeroes, Copy and a deallocating Dataset Management fail
 *   with 82h and change nothing; Dataset Management without deallocate,
 *   Flush, Verify and Read succeed, and every page holds the data of its
 *   last write that succeeded;
 * - nothing is erased any more, and the FTL map is consistent.
 */
void femu_test_eol_ro(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t bufs = guest_alloc(alloc, FEMU_EOL_SLOTS * 4096);
    uint64_t buf = guest_alloc(alloc, 4 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t log = guest_alloc(alloc, 512);
    uint64_t pel = guest_alloc(alloc, 4096);
    const uint64_t slba[1] = { 0 };
    const uint16_t nlb[1] = { 8 };
    uint8_t seed_of[256];
    uint8_t page[512];
    uint16_t slot_page[FEMU_EOL_SLOTS], slot_np[FEMU_EOL_SLOTS];
    uint8_t slot_seed[FEMU_EOL_SLOTS];
    uint32_t rnd = 7;
    uint32_t result;
    uint64_t mapped, lost, orphans, erases = 0;
    uint64_t cap, pages, reqs;
    bool csd = !strcmp(data, "csd");
    /* "fdp...": a placement subsystem, so an endurance group too */
    bool fdp = !strncmp(data, "fdp", 3);
    bool subsys = !strcmp(data, "subsys") || fdp;
    const char *what = fdp ? (const char *)data + 3 : data;
    bool ro = false;
    int batch, k, i, ok = 0, refused = 0;
    NvmeCmd cmd;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_eol_cwp(&c, log, 0);
    /* FDP: 16 credit pages fill one unit; with four handles, 5 units */
    if (fdp) {
        g_assert_true(femu_eol_state(qts, &ro, &cap, &pages, &reqs));
        g_assert_cmpuint(cap, ==, 16);
        g_assert_cmpint(femu_eol_query_int(qts, "units", "reserve"), ==, 5);
    }
    g_assert_cmpint(femu_set_feature(&c, NVME_ASYNCHRONOUS_EVENT_CONF, false,
                                     0, NVME_SMART_MEDIA_READ_ONLY, NULL), ==,
                    NVME_SUCCESS);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_ASYNC_EV_REQ;
    femu_submit(&c, &c.admin, &cmd);

    /* fill every page, four at a time (MDTS is 16 KiB) */
    qtest_memset(qts, buf, 0xf0, 4096);
    for (i = 0; i < 256; i += 4) {
        g_assert_cmphex(FEMU_SC(femu_write_pages(&c, i, 4, buf, list)), ==,
                        NVME_SUCCESS);
    }
    memset(seed_of, 0xf0, sizeof(seed_of));

    for (batch = 0; batch < 1000 && !ro; batch++) {
        uint16_t first = c.cid;

        for (k = 0; k < FEMU_EOL_SLOTS; k++) {
            NvmeRwCmd rw;
            uint64_t b = bufs + k * 4096;

            rnd = rnd * 1103515245 + 12345;
            slot_np[k] = 1 + (rnd >> 20) % 2;
            slot_page[k] = k * 16 + (rnd >> 8) % 15;
            slot_seed[k] = 1 + (batch * FEMU_EOL_SLOTS + k) % 239;
            qtest_memset(qts, b, slot_seed[k], 4096);
            memset(&rw, 0, sizeof(rw));
            rw.opcode = NVME_CMD_WRITE;
            rw.nsid = cpu_to_le32(1);
            rw.dptr.prp1 = cpu_to_le64(b);
            rw.dptr.prp2 = cpu_to_le64(slot_np[k] == 2 ? b : 0);
            rw.slba = cpu_to_le64(slot_page[k] * 8);
            rw.nlb = cpu_to_le16(slot_np[k] * 8 - 1);
            femu_submit(&c, &c.io, (NvmeCmd *)&rw);
        }
        for (i = 0; i < FEMU_EOL_SLOTS; i++) {
            uint16_t got;
            uint16_t st = femu_complete(&c, &c.io, &got, NULL);

            k = (uint16_t)(got - first);
            g_assert_cmpint(k, <, FEMU_EOL_SLOTS);
            if (FEMU_SC(st) == NVME_SUCCESS) {
                memset(seed_of + slot_page[k], slot_seed[k], slot_np[k]);
                ok++;
                continue;
            }
            g_assert_cmphex(FEMU_SC(st), ==, NVME_WRITE_TO_RO);
            g_assert_cmphex(st & FEMU_DNR, ==, FEMU_DNR);
            refused++;
            ro = true;
        }
    }
    g_test_message("read-only after %d batches: %d writes done, %d refused",
                   batch, ok, refused);
    g_assert_true(ro);

    /* the event comes first on the admin queue */
    g_assert_cmpint(femu_complete(&c, &c.admin, NULL, &result), ==,
                    NVME_SUCCESS);
    g_test_message("AER result 0x%x", result);
    g_assert_cmphex(result & 0x7, ==, NVME_AER_TYPE_SMART);
    g_assert_cmphex((result >> 8) & 0xff, ==, NVME_AER_INFO_SMART_RELIABILITY);
    g_assert_cmphex((result >> 16) & 0xff, ==, NVME_LOG_SMART_INFO);

    /*
     * The FTL thread put the read-only warning in the Persistent Event log
     * when it happened; a SMART read does not add it again.
     */
    g_assert_cmphex(femu_pel(&c, 1, pel, 4096, 0), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_pel_warnings(qts, pel, NVME_SMART_MEDIA_READ_ONLY),
                    ==, 1);

    g_assert_cmpint(FEMU_SC(femu_get_log(&c, NVME_LOG_SMART_INFO, log,
                                         sizeof(page), 0)), ==, NVME_SUCCESS);
    qtest_memread(qts, log, page, sizeof(page));
    g_test_message("critical warning 0x%x spare %u used %u", page[0], page[3],
                   page[5]);
    g_assert_cmphex(femu_pel(&c, 2, pel, 512, 0), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_pel(&c, 1, pel, 4096, 0), ==, NVME_SUCCESS);
    g_assert_cmpint(femu_pel_warnings(qts, pel, NVME_SMART_MEDIA_READ_ONLY),
                    ==, 1);
    g_assert_cmphex(page[0] & NVME_SMART_MEDIA_READ_ONLY, ==,
                    NVME_SMART_MEDIA_READ_ONLY);
    g_assert_cmphex(page[0] & NVME_SMART_SPARE, ==, NVME_SMART_SPARE);
    g_assert_cmpuint(page[3], ==, 0);
    /* EGCWS repeats the endurance group's bits 0, 2 and 3 */
    g_assert_cmphex(page[6], ==, subsys ? page[0] & 0xd : 0);
    if (subsys) {
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = NVME_ADM_CMD_GET_LOG_PAGE;
        cmd.nsid = cpu_to_le32(NVME_NSID_BROADCAST);
        cmd.dptr.prp1 = cpu_to_le64(log);
        cmd.cdw10 = cpu_to_le32(NVME_LOG_ENDGRP | ((512 / 4 - 1) << 16));
        cmd.cdw11 = cpu_to_le32(1 << 16);
        g_assert_cmpint(FEMU_SC(femu_admin(&c, &cmd)), ==, NVME_SUCCESS);
        g_assert_cmphex(qtest_readb(qts, log) & 0xd, ==, page[6]);
        g_assert_cmpuint(qtest_readb(qts, log + 3), ==, 0);
    }
    femu_eol_cwp(&c, log, 1);

    /* query-femu does not serve computational storage */
    if (!csd) {
        g_assert_true(femu_eol_state(qts, &ro, &cap, &pages, &reqs));
        g_assert_true(ro);
        g_assert_cmpuint(pages, ==, 0);
        g_assert_cmpuint(reqs, ==, 0);
        erases = femu_eol_erases(qts);
    }

    /* every write-class command fails and changes nothing */
    qtest_memset(qts, buf, 0x55, 4 * 4096);
    i = femu_write_pages(&c, 0, 1, buf, list);
    g_assert_cmphex(FEMU_SC(i), ==, NVME_WRITE_TO_RO);
    g_assert_cmphex(i & FEMU_DNR, ==, FEMU_DNR);
    g_assert_cmphex(FEMU_SC(femu_eol_cmd(&c, NVME_CMD_WRITE_ZEROES, 8, 8, 0,
                                         0)), ==, NVME_WRITE_TO_RO);
    g_assert_cmphex(femu_wz(&c, 16, 8, true), ==, NVME_WRITE_TO_RO);
    g_assert_cmphex(femu_copy(&c, list, 24, slba, nlb, 1, 1, 0), ==,
                    NVME_WRITE_TO_RO);
    g_assert_cmphex(femu_dealloc_pages(&c, 4, 1, list), ==, NVME_WRITE_TO_RO);
    g_assert_cmphex(FEMU_SC(femu_eol_cmd(&c, NVME_CMD_WRITE_UNCOR, 32, 8, 0,
                                         0)), ==, NVME_WRITE_TO_RO);
    /* a hint changes nothing on the media */
    g_assert_cmphex(FEMU_SC(femu_eol_cmd(&c, NVME_CMD_DSM, 0, 1, list, 1)),
                    ==, NVME_SUCCESS);
    g_assert_cmphex(FEMU_SC(femu_eol_cmd(&c, NVME_CMD_FLUSH, 0, 1, 0, 0)), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(FEMU_SC(femu_eol_cmd(&c, NVME_CMD_VERIFY, 0, 8, 0, 0)),
                    ==, NVME_SUCCESS);

    for (i = 0; i < 256; i++) {
        uint8_t got[2];

        g_assert_cmphex(FEMU_SC(femu_read_pages(&c, i, 1, buf, list)), ==,
                        NVME_SUCCESS);
        qtest_memread(qts, buf, got, 1);
        qtest_memread(qts, buf + 4095, got + 1, 1);
        if (got[0] != seed_of[i] || got[1] != seed_of[i]) {
            g_test_message("page %d holds 0x%x, wrote 0x%x", i, got[0],
                           seed_of[i]);
        }
        g_assert_cmphex(got[0], ==, seed_of[i]);
        g_assert_cmphex(got[1], ==, seed_of[i]);
    }

    femu_ftl_check(qts, &mapped, &lost, &orphans);
    g_assert_cmpuint(lost, ==, 0);
    g_assert_cmpuint(orphans, ==, 0);
    g_assert_cmpuint(mapped, ==, 256);
    if (!csd) {
        g_assert_cmpuint(femu_eol_erases(qts), ==, erases);
    }
    if (fdp) {
        g_assert_cmpuint(femu_fdp_check(qts), ==, 0);
    } else if (!csd) {
        femu_query_check_lines(qts, "/machine/peripheral/gc-test", mapped);
    }

    /*
     * Format and Sanitize deallocate the namespace (Sanitize must run
     * whatever the critical warnings say, Base 2.3, 8.1.26). They erase
     * nothing, and the media stays read-only.
     */
    if (!strcmp(what, "-format") || !strcmp(what, "-sanitize") ||
        !strcmp(data, "format") || !strcmp(data, "sanitize")) {
        g_assert_cmphex(strstr(what, "format") ?
                        FEMU_SC(femu_format(&c, 1, 0, 0)) :
                        femu_sanitize(&c, 0x2), ==, NVME_SUCCESS);
        g_assert_cmphex(FEMU_SC(femu_read_pages(&c, 0, 1, buf, list)), ==,
                        NVME_SUCCESS);
        g_assert_cmphex(qtest_readb(qts, buf), ==, 0);
        g_assert_cmphex(FEMU_SC(femu_write_pages(&c, 0, 1, buf, list)), ==,
                        NVME_WRITE_TO_RO);
        g_assert_cmpint(FEMU_SC(femu_get_log(&c, NVME_LOG_SMART_INFO, log,
                                             sizeof(page), 0)), ==,
                        NVME_SUCCESS);
        g_assert_cmphex(qtest_readb(qts, log) & NVME_SMART_MEDIA_READ_ONLY,
                        ==, NVME_SMART_MEDIA_READ_ONLY);
        femu_eol_cwp(&c, log, 1);
        femu_ftl_check(qts, &mapped, &lost, &orphans);
        g_assert_cmpuint(mapped, ==, 0);
        g_assert_cmpuint(femu_eol_erases(qts), ==, erases);
        if (fdp) {
            g_assert_cmpuint(femu_fdp_check(qts), ==, 0);
        } else {
            femu_query_check_lines(qts, "/machine/peripheral/gc-test", 0);
        }
    }

    guest_free(alloc, pel);
    guest_free(alloc, log);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    guest_free(alloc, bufs);
    femu_disable(&c);
    /* the device is worn out now: the next test must not inherit it */
    qos_invalidate_command_line();
}

/* Write Zeroes of whole pages from @page, with the Deallocate bit */
static uint16_t femu_dftl_zeroes_deac(FemuCtrlState *c, uint64_t page,
                                      uint32_t npages)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = NVME_CMD_WRITE_ZEROES;
    cmd.nsid = cpu_to_le32(1);
    cmd.cdw10 = cpu_to_le32((uint32_t)(page * (4096 / c->lba_size)));
    cmd.cdw12 = cpu_to_le32((npages * (4096 / c->lba_size) - 1) | (1u << 25));
    return FEMU_SC(femu_io(c, &cmd));
}

/*
 * The changes a command makes to translation pages (TPs) not in the CMT
 * are written once per TP, whatever the pages it changes. 2048 pages are 4
 * TPs; the CMT holds one. After a fill, TPs 0 to 2 are on flash and TP 3
 * is in the CMT.
 *   - A deallocate of pages 0 to 999 changes 1000 mappings in TPs 0 and
 *     1: 2 reads and 2 programs.
 *   - Write Zeroes of page 1700, without Deallocate, programs the page: a
 *     CMT hit on TP 3, so no TP traffic.
 *   - Write Zeroes with Deallocate of pages 1000 to 1599 changes TPs 1 and
 *     2 (2 reads and 2 programs) and TP 3, which only gets dirty.
 *   - Write Zeroes of page 10 misses TP 0: 1 read, and the eviction of the
 *     dirty TP 3: 1 program.
 *   - Format discards every TP with no write-back: no valid TP page, no
 *     mapping, and a read after it reads no TP. With @data "csd" the
 *     namespace refuses Format, and the test ends there.
 */
void femu_test_dftl_batch(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    const char *id = "/machine/peripheral/tp";
    FemuCtrlState c = { 0 };
    uint64_t buf = guest_alloc(alloc, 64 * 4096);
    uint64_t list = guest_alloc(alloc, 4096);
    uint64_t log = guest_alloc(alloc, 4096);
    uint64_t w, r, v[7];
    uint32_t i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    qtest_memset(qts, buf, 0x21, 64 * 4096);
    for (i = 0; i < 2048; i += 64) {
        g_assert_cmphex(FEMU_SC(femu_write_pages(&c, i, 64, buf, list)), ==,
                        NVME_SUCCESS);
    }
    w = femu_c0h_field(&c, log, 280);
    r = femu_c0h_field(&c, log, 288);
    g_assert_cmpuint(w, ==, 3);
    g_assert_cmpuint(r, ==, 0);

    g_assert_cmphex(femu_dealloc_pages(&c, 0, 1000, log), ==, NVME_SUCCESS);
    g_assert_cmpuint(femu_c0h_field(&c, log, 280), ==, w + 2);
    g_assert_cmpuint(femu_c0h_field(&c, log, 288), ==, r + 2);
    femu_tp_check(qts, id, v);
    g_assert_cmpuint(v[0], ==, 2048 - 1000);
    g_assert_cmpuint(v[1] + v[2] + v[4], ==, 0);

    w = femu_c0h_field(&c, log, 280);
    r = femu_c0h_field(&c, log, 288);
    g_assert_cmphex(femu_write_zeroes(&c, 1700 * 8, 8), ==, NVME_SUCCESS);
    g_assert_cmpuint(femu_c0h_field(&c, log, 280), ==, w);
    g_assert_cmpuint(femu_c0h_field(&c, log, 288), ==, r);

    g_assert_cmphex(femu_dftl_zeroes_deac(&c, 1000, 600), ==, NVME_SUCCESS);
    g_assert_cmpuint(femu_c0h_field(&c, log, 280), ==, w + 2);
    g_assert_cmpuint(femu_c0h_field(&c, log, 288), ==, r + 2);

    g_assert_cmphex(femu_write_zeroes(&c, 10 * 8, 8), ==, NVME_SUCCESS);
    g_assert_cmpuint(femu_c0h_field(&c, log, 280), ==, w + 3);
    g_assert_cmpuint(femu_c0h_field(&c, log, 288), ==, r + 3);
    femu_tp_check(qts, id, v);
    g_assert_cmpuint(v[0], ==, 2048 - 1600 + 1);
    g_assert_cmpuint(v[3], ==, 4);
    g_assert_cmpuint(v[1] + v[2] + v[4], ==, 0);

    /* a CSD namespace takes neither Format nor Sanitize */
    if (data && g_str_equal(data, "csd")) {
        g_assert_cmphex(FEMU_SC(femu_format(&c, 1, 0, 0)), ==,
                        NVME_INVALID_FORMAT);
        goto out;
    }
    g_assert_cmphex(FEMU_SC(femu_format(&c, 1, 0, 0)), ==, NVME_SUCCESS);
    femu_tp_check(qts, id, v);
    g_assert_cmpuint(v[0] + v[1] + v[2] + v[3] + v[4], ==, 0);
    w = femu_c0h_field(&c, log, 280);
    r = femu_c0h_field(&c, log, 288);
    g_assert_cmphex(femu_read_pages(&c, 1800, 1, buf, list), ==, NVME_SUCCESS);
    g_assert_cmphex(FEMU_SC(femu_write_pages(&c, 5, 1, buf, list)), ==,
                    NVME_SUCCESS);
    g_assert_cmpuint(femu_c0h_field(&c, log, 280), ==, w);
    g_assert_cmpuint(femu_c0h_field(&c, log, 288), ==, r);
    femu_tp_check(qts, id, v);
    g_assert_cmpuint(v[0], ==, 1);
    g_assert_cmpuint(v[1] + v[2] + v[4], ==, 0);

out:
    guest_free(alloc, log);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/*
 * mdts=3 is 32 KiB: 64 blocks of 512 bytes, or 8 of 4 KiB (@data is the
 * block size the device must have). A transfer of exactly the limit moves
 * its data, also onto the last blocks of the namespace. One block more is
 * Invalid Field in both directions and changes nothing. The range check
 * comes first, so a transfer past the end is LBA Out of Range whatever its
 * size.
 */
void femu_test_g1_mdts_limit(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    const uint32_t limit = 8 * FEMU_G1_PAGE;
    uint64_t id = guest_alloc(alloc, FEMU_G1_PAGE);
    uint64_t buf = guest_alloc(alloc, limit + 2 * FEMU_G1_PAGE);
    uint64_t list = guest_alloc(alloc, FEMU_G1_PAGE);
    uint8_t *wbuf = g_malloc(limit);
    uint8_t *rbuf = g_malloc0(limit);
    uint64_t nsze;
    uint32_t lba_size;
    uint32_t max;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    g_assert_cmpuint(femu_g1_mdts(&c, id), ==, 3);
    femu_identify_ns(&c, &nsze, &lba_size);
    g_assert_cmpuint(lba_size, ==, GPOINTER_TO_UINT(data));
    c.lba_size = lba_size;
    max = limit / lba_size;
    g_assert_cmpuint(nsze, >, 4 * (uint64_t)max);

    /* exactly the limit, there and back */
    femu_g1_fill(wbuf, limit, 1);
    femu_g1_put(qts, buf, wbuf, limit);
    g_assert_cmphex(femu_g1_rw(&c, NVME_CMD_WRITE, max, max, buf, list), ==,
                    NVME_SUCCESS);
    qtest_memset(qts, buf, 0, limit);
    g_assert_cmphex(femu_g1_rw(&c, NVME_CMD_READ, max, max, buf, list), ==,
                    NVME_SUCCESS);
    femu_g1_get(qts, buf, rbuf, limit);
    g_assert_cmpint(memcmp(wbuf, rbuf, limit), ==, 0);

    /* the block after the transfer holds a mark of its own */
    qtest_memset(qts, buf, 0x33, FEMU_G1_PAGE);
    g_assert_cmphex(femu_g1_rw(&c, NVME_CMD_WRITE, 2 * max, 1, buf, list),
                    ==, NVME_SUCCESS);

    /* one block more: refused, and no block or buffer byte changes */
    qtest_memset(qts, buf, 0x77, limit + FEMU_G1_PAGE);
    g_assert_cmphex(femu_g1_rw(&c, NVME_CMD_WRITE, max, max + 1, buf, list),
                    ==, NVME_INVALID_FIELD);
    g_assert_cmphex(femu_io_status & NVME_DNR, ==, NVME_DNR);
    g_assert_cmphex(femu_g1_rw(&c, NVME_CMD_READ, max, max + 1, buf, list),
                    ==, NVME_INVALID_FIELD);
    g_assert_cmphex(femu_io_status & NVME_DNR, ==, NVME_DNR);
    femu_g1_all(qts, buf, limit + FEMU_G1_PAGE, 0x77);
    g_assert_cmphex(femu_g1_rw(&c, NVME_CMD_READ, max, max, buf, list), ==,
                    NVME_SUCCESS);
    femu_g1_get(qts, buf, rbuf, limit);
    g_assert_cmpint(memcmp(wbuf, rbuf, limit), ==, 0);
    g_assert_cmphex(femu_g1_rw(&c, NVME_CMD_READ, 2 * max, 1, buf, list), ==,
                    NVME_SUCCESS);
    femu_g1_all(qts, buf, lba_size, 0x33);

    /* the last blocks of the namespace, and the last one alone */
    femu_g1_fill(wbuf, limit, 3);
    femu_g1_put(qts, buf, wbuf, limit);
    g_assert_cmphex(femu_g1_rw(&c, NVME_CMD_WRITE, nsze - max, max, buf,
                               list), ==, NVME_SUCCESS);
    qtest_memset(qts, buf, 0, limit);
    g_assert_cmphex(femu_g1_rw(&c, NVME_CMD_READ, nsze - max, max, buf,
                               list), ==, NVME_SUCCESS);
    femu_g1_get(qts, buf, rbuf, limit);
    g_assert_cmpint(memcmp(wbuf, rbuf, limit), ==, 0);
    qtest_memset(qts, buf, 0, limit);
    g_assert_cmphex(femu_g1_rw(&c, NVME_CMD_READ, nsze - 1, 1, buf, list),
                    ==, NVME_SUCCESS);
    femu_g1_get(qts, buf, rbuf, lba_size);
    g_assert_cmpint(memcmp(wbuf + limit - lba_size, rbuf, lba_size), ==, 0);

    /* past the end: the range check answers before the size check */
    g_assert_cmphex(femu_g1_rw(&c, NVME_CMD_READ, nsze - max + 1, max, buf,
                               list), ==, NVME_LBA_RANGE);
    g_assert_cmphex(femu_io_status & NVME_DNR, ==, NVME_DNR);
    g_assert_cmphex(femu_g1_rw(&c, NVME_CMD_WRITE, nsze - max, max + 1, buf,
                               list), ==, NVME_LBA_RANGE);
    g_assert_cmphex(femu_io_status & NVME_DNR, ==, NVME_DNR);

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
 * mdts=0 is no limit. One Write of 16 MiB, 32768 blocks of 512 bytes, takes
 * a PRP list of nine chained pages. The same blocks come back in one Read,
 * and the last page of the transfer comes back alone from where it belongs.
 */
void femu_test_g1_mdts0_large(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    const uint32_t bytes = 16u << 20;
    const uint32_t npages = bytes / FEMU_G1_PAGE;
    const uint32_t nlb = bytes / 512;
    const uint64_t slba = 64;
    uint64_t id = guest_alloc(alloc, FEMU_G1_PAGE);
    uint64_t buf = guest_alloc(alloc, bytes);
    uint64_t list = guest_alloc(alloc, femu_g1_list_pages(npages) *
                                FEMU_G1_PAGE);
    uint8_t *wbuf = g_malloc(bytes);
    uint8_t *rbuf = g_malloc0(bytes);
    uint64_t nsze;
    uint32_t lba_size;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    g_assert_cmpuint(femu_g1_mdts(&c, id), ==, 0);
    femu_identify_ns(&c, &nsze, &lba_size);
    g_assert_cmpuint(lba_size, ==, 512);
    g_assert_cmpuint(nsze, >=, slba + nlb);

    femu_g1_fill(wbuf, bytes, 5);
    femu_g1_put(qts, buf, wbuf, bytes);
    g_assert_cmphex(femu_g1_rw(&c, NVME_CMD_WRITE, slba, nlb, buf, list), ==,
                    NVME_SUCCESS);
    qtest_memset(qts, buf, 0, bytes);
    g_assert_cmphex(femu_g1_rw(&c, NVME_CMD_READ, slba, nlb, buf, list), ==,
                    NVME_SUCCESS);
    femu_g1_get(qts, buf, rbuf, bytes);
    g_assert_cmpint(memcmp(wbuf, rbuf, bytes), ==, 0);

    /* the last 4 KiB of the transfer, read by a command of its own */
    qtest_memset(qts, buf, 0, FEMU_G1_PAGE);
    g_assert_cmphex(femu_g1_rw(&c, NVME_CMD_READ, slba + nlb - 8, 8, buf,
                               list), ==, NVME_SUCCESS);
    femu_g1_get(qts, buf, rbuf, FEMU_G1_PAGE);
    g_assert_cmpint(memcmp(wbuf + bytes - FEMU_G1_PAGE, rbuf, FEMU_G1_PAGE),
                    ==, 0);

    g_free(rbuf);
    g_free(wbuf);
    guest_free(alloc, list);
    guest_free(alloc, buf);
    guest_free(alloc, id);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    qos_invalidate_command_line();
}

#define FEMU_G1_RING_QUEUES 17

/*
 * queues=17,entries=4095: 17 full queues hold 69615 commands. A request
 * ring of 65536 slots takes 65535 of them. x-cpl-hold 1 keeps each request
 * on the ring that the poller reads, and x-cpl-count must find them all
 * there. A ring that is too small refuses 4080 requests, the count stops
 * at 65535, and those commands never complete. After the release each
 * queue shows 4095 entries, one for each command, and takes a new command.
 * NoSSD fills the ring to the FTL, and bbssd the ring from the FTL thread.
 * The FTL thread counts each enqueue that its ring refuses
 * (x-ftl-ring-full), and that count must stay 0.
 */
void femu_test_g1_ring_capacity(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    const uint32_t depth = FEMU_G1_DEPTH - 1;
    const uint32_t sq_bytes = FEMU_G1_DEPTH * sizeof(NvmeCmd);
    const uint32_t cq_bytes = FEMU_G1_DEPTH * sizeof(NvmeCqe);
    FemuQueue q[FEMU_G1_RING_QUEUES];
    uint64_t buf = guest_alloc(alloc, FEMU_G1_PAGE);
    g_autofree NvmeRwCmd *sqes = g_new0(NvmeRwCmd, depth);
    g_autofree NvmeCqe *cqes = g_new0(NvmeCqe, FEMU_G1_DEPTH);
    g_autofree bool *seen = g_new0(bool, depth);
    NvmeCqe cqe;
    QDict *rsp;
    uint16_t cid;
    uint32_t k;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    for (i = 0; i < FEMU_G1_RING_QUEUES; i++) {
        memset(&q[i], 0, sizeof(q[i]));
        q[i].qid = i + 1;
        q[i].sq_addr = guest_alloc(alloc, sq_bytes);
        q[i].cq_addr = guest_alloc(alloc, cq_bytes);
        qtest_memset(qts, q[i].cq_addr, 0, cq_bytes);
        g_assert_cmphex(femu_g1_create(&c, NVME_ADM_CMD_CREATE_CQ, q[i].qid,
                                       q[i].cq_addr, depth, NVME_CQ_PC), ==,
                        NVME_SUCCESS);
        g_assert_cmphex(femu_g1_create(&c, NVME_ADM_CMD_CREATE_SQ, q[i].qid,
                                       q[i].sq_addr, depth,
                                       (q[i].qid << 16) | NVME_SQ_PC), ==,
                        NVME_SUCCESS);
    }

    /* an identifier is unique in its queue, so each queue takes one image */
    for (k = 0; k < depth; k++) {
        sqes[k].opcode = NVME_CMD_READ;
        sqes[k].cid = cpu_to_le16(k);
        sqes[k].nsid = cpu_to_le32(1);
        sqes[k].dptr.prp1 = cpu_to_le64(buf);
        sqes[k].slba = cpu_to_le64(k % 8);
    }
    femu_cancel_hook(qts, "g1-ring", "x-cpl-hold", 1);
    for (i = 0; i < FEMU_G1_RING_QUEUES; i++) {
        femu_g1_put(qts, q[i].sq_addr, (const uint8_t *)sqes,
                    depth * sizeof(*sqes));
        qpci_io_writel(c.pdev, c.bar, femu_sq_doorbell(&c, q[i].qid), depth);
    }
    /* the ring holds every request: none was refused */
    femu_cancel_wait_cpl(qts, "g1-ring", FEMU_G1_RING_QUEUES * depth);
    /* and the FTL thread, where one runs, never found its ring full */
    rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                    "'path':'/machine/peripheral/g1-ring',"
                    "'property':'x-ftl-ring-full'}}");
    g_assert_true(qdict_haskey(rsp, "return"));
    g_assert_cmpint(qdict_get_int(rsp, "return"), ==, 0);
    qobject_unref(rsp);
    for (i = 0; i < FEMU_G1_RING_QUEUES; i++) {
        qtest_memread(qts, q[i].cq_addr, &cqe, sizeof(cqe));
        g_assert_cmpuint(le16_to_cpu(cqe.status), ==, 0);
    }
    femu_cancel_hook(qts, "g1-ring", "x-cpl-hold", 0);

    for (i = 0; i < FEMU_G1_RING_QUEUES; i++) {
        /* the entries go to the slots in order, so this one is the last */
        femu_g1_cqe_wait(qts, &q[i], depth - 1, 1, &cqe);
        femu_g1_get(qts, q[i].cq_addr, (uint8_t *)cqes, cq_bytes);
        memset(seen, 0, depth * sizeof(*seen));
        for (k = 0; k < depth; k++) {
            g_assert_cmphex(le16_to_cpu(cqes[k].status), ==, 1);
            g_assert_cmpuint(le16_to_cpu(cqes[k].sq_id), ==, q[i].qid);
            cid = le16_to_cpu(cqes[k].cid);
            g_assert_cmpuint(cid, <, depth);
            g_assert_false(seen[cid]);
            seen[cid] = true;
        }
        /* a queue of 4096 entries is full with 4095: the last slot is free */
        g_assert_cmpuint(le16_to_cpu(cqes[depth].status), ==, 0);
    }

    /*
     * Each queue takes the head, and then two more commands. A queue has
     * 4096 request slots and 4095 were in use, so the second command
     * needs a slot that a completion gave back.
     */
    for (i = 0; i < FEMU_G1_RING_QUEUES; i++) {
        q[i].sq_tail = depth;
        q[i].cq_head = depth;
        q[i].phase = 1;
        qpci_io_writel(c.pdev, c.bar, femu_cq_doorbell(&c, q[i].qid), depth);
        cid = c.cid;
        femu_g1_deep_submit(&c, &q[i], buf, 2);
        femu_g1_deep_reap(&c, &q[i], cid, 2);
    }

    for (i = 0; i < FEMU_G1_RING_QUEUES; i++) {
        femu_queue_free(&c, &q[i]);
    }
    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}

/* entry @e of a completion queue of @n entries: slot, phase */
static uint32_t femu_g1_cqf_slot(uint32_t e, uint32_t n)
{
    return e % n;
}

static uint8_t femu_g1_cqf_phase(uint32_t e, uint32_t n)
{
    return (e / n) & 1 ? 0 : 1;
}

/*
 * A completion queue of C entries behind a submission queue of S: 4 and
 * 64 (cq-full-deep-*), or 5 and 100 with entries=99 (cq-full-odd-*). The
 * host sends S - 1 Reads and does not move the CQ head. The controller
 * posts C - 1 entries, and the queue is full (Base 2.3, 3.3.1.2.1): the
 * last slot stays empty and the entries do not change. Then the host
 * frees one slot at a time. One more entry comes for each slot, in the
 * next slot and with the phase of its lap, and the slot the host freed
 * keeps its old entry until the next one is free. Each command completes
 * one time. The first entry reports that the controller fetched all of
 * them. Then 3 more Reads take the SQ tail over its end. Sizes that are
 * not a power of two catch an index wrapped with a mask. The cq-full
 * test covers a NoSSD that completes in the fetch sweep and so stops the
 * fetch. Here the controller fetched all commands, and the completions
 * wait in the device: NoSSD with fw_cpu_ns, and bbssd with its FTL thread.
 */
void femu_test_g1_cq_backlog(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    FemuQueue q = { .qid = 1, .phase = 1 };
    const FemuG1CqfSize *sz = data;
    const uint32_t ncq = sz->cq;
    const uint32_t count = sz->sq - 1;
    const uint32_t room = ncq - 1;
    uint64_t buf = guest_alloc(alloc, FEMU_G1_PAGE);
    g_autofree bool *seen = g_new0(bool, sz->sq);
    g_autofree NvmeCqe *held = g_new0(NvmeCqe, ncq);
    NvmeCqe cqe;
    NvmeCqe again;
    uint16_t first;
    uint16_t cid;
    uint32_t e;

    femu_enable(&c, &femu->dev, alloc);
    q.sq_addr = guest_alloc(alloc, sz->sq * sizeof(NvmeCmd));
    q.cq_addr = guest_alloc(alloc, FEMU_G1_PAGE);
    qtest_memset(qts, q.cq_addr, 0, FEMU_G1_PAGE);
    g_assert_cmphex(femu_g1_create(&c, NVME_ADM_CMD_CREATE_CQ, 1, q.cq_addr,
                                   ncq - 1, NVME_CQ_PC), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_g1_create(&c, NVME_ADM_CMD_CREATE_SQ, 1, q.sq_addr,
                                   sz->sq - 1, (1 << 16) | NVME_SQ_PC), ==,
                    NVME_SUCCESS);

    first = c.cid;
    femu_g1_sized_submit(&c, &q, buf, count, sz->sq);
    g_assert_cmpuint(q.sq_tail, ==, count);

    /* the queue fills, and the host does not move the head */
    for (e = 0; e < room; e++) {
        femu_g1_cqe_wait(qts, &q, e, 1, &held[e]);
    }
    g_usleep(50 * 1000);
    /* the controller fetched all commands before it posted the first */
    g_assert_cmpuint(le16_to_cpu(held[0].sq_head), ==, count);
    qtest_memread(qts, q.cq_addr + room * sizeof(cqe), &cqe, sizeof(cqe));
    g_assert_cmpuint(le16_to_cpu(cqe.status), ==, 0);
    for (e = 0; e < room; e++) {
        qtest_memread(qts, q.cq_addr + e * sizeof(cqe), &again,
                      sizeof(again));
        g_assert_cmpint(memcmp(&held[e], &again, sizeof(again)), ==, 0);
    }

    for (e = 0; e < count; e++) {
        femu_g1_cqe_wait(qts, &q, femu_g1_cqf_slot(e, ncq),
                         femu_g1_cqf_phase(e, ncq), &cqe);
        g_assert_cmphex(le16_to_cpu(cqe.status) >> 1, ==, NVME_SUCCESS);
        g_assert_cmpuint(le16_to_cpu(cqe.sq_id), ==, q.qid);
        cid = le16_to_cpu(cqe.cid) - first;
        g_assert_cmpuint(cid, <, count);
        g_assert_false(seen[cid]);
        seen[cid] = true;
        if (e == count - 1) {
            /* the controller fetched each command of the queue */
            g_assert_cmpuint(le16_to_cpu(cqe.sq_head), ==, count);
        }

        /* the host frees this slot */
        qpci_io_writel(c.pdev, c.bar, femu_cq_doorbell(&c, q.qid),
                       femu_g1_cqf_slot(e + 1, ncq));
        /*
         * Two laps with a check of each step: the freed slot lets one
         * entry in, and that entry fills the queue again.
         */
        if (e < 2 * ncq) {
            femu_g1_cqe_wait(qts, &q, femu_g1_cqf_slot(e + room, ncq),
                             femu_g1_cqf_phase(e + room, ncq), &again);
            g_usleep(20 * 1000);
            qtest_memread(qts,
                          q.cq_addr + femu_g1_cqf_slot(e, ncq) * sizeof(cqe),
                          &again, sizeof(again));
            g_assert_cmpint(memcmp(&cqe, &again, sizeof(again)), ==, 0);
        }
    }

    /* nothing completes a second time */
    g_usleep(10 * 1000);
    qtest_memread(qts,
                  q.cq_addr + femu_g1_cqf_slot(count, ncq) * sizeof(cqe),
                  &cqe, sizeof(cqe));
    g_assert_cmpint(le16_to_cpu(cqe.status) & 1, !=,
                    femu_g1_cqf_phase(count, ncq));

    /* 3 more Reads: the SQ tail goes over the end to slot 2 */
    first = c.cid;
    memset(seen, 0, sz->sq * sizeof(*seen));
    femu_g1_sized_submit(&c, &q, buf, 3, sz->sq);
    g_assert_cmpuint(q.sq_tail, ==, 2);
    for (e = count; e < count + 3; e++) {
        femu_g1_cqe_wait(qts, &q, femu_g1_cqf_slot(e, ncq),
                         femu_g1_cqf_phase(e, ncq), &cqe);
        g_assert_cmphex(le16_to_cpu(cqe.status) >> 1, ==, NVME_SUCCESS);
        g_assert_cmpuint(le16_to_cpu(cqe.sq_id), ==, q.qid);
        cid = le16_to_cpu(cqe.cid) - first;
        g_assert_cmpuint(cid, <, 3);
        g_assert_false(seen[cid]);
        seen[cid] = true;
        qpci_io_writel(c.pdev, c.bar, femu_cq_doorbell(&c, q.qid),
                       femu_g1_cqf_slot(e + 1, ncq));
    }
    g_assert_cmpuint(le16_to_cpu(cqe.sq_head), ==, 2);
    g_usleep(10 * 1000);
    qtest_memread(qts,
                  q.cq_addr + femu_g1_cqf_slot(count + 3, ncq) * sizeof(cqe),
                  &cqe, sizeof(cqe));
    g_assert_cmpint(le16_to_cpu(cqe.status) & 1, !=,
                    femu_g1_cqf_phase(count + 3, ncq));

    guest_free(alloc, q.cq_addr);
    guest_free(alloc, q.sq_addr);
    guest_free(alloc, buf);
    femu_disable(&c);
    qos_invalidate_command_line();
}
