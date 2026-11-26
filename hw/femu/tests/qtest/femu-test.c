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
#include "femu-test.h"

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

#define FTL_TRACE_MP_OFF \
    "764 4120000000 10306 10306 12181 11112 12821 22487 5556 " \
    "15238286681531891579"
#define FTL_TRACE_MP_OFF_SEQ_NS 17920000
static const FtlTraceMp ftl_trace_mp_off = {
    .want = FTL_TRACE_MP_OFF,
    .seq_ns = FTL_TRACE_MP_OFF_SEQ_NS,
};
static const FtlTraceMp ftl_trace_mp_fdp = {
    .want = "764 2270000000 10306 10306 4593 7320 5233 14899 3660 "
            "683895796762672279",
    .seq_ns = 17920000,
};
static const FtlTraceMp ftl_trace_mp_on = {
    .want = "764 3900000000 10306 10306 12181 11112 12619 18495 5556 "
            "15238286681531891579",
    .base = FTL_TRACE_MP_OFF,
    .seq_ns = 10040000,
    .base_seq_ns = FTL_TRACE_MP_OFF_SEQ_NS,
};

/* two handles, so the per-handle heaps compare their tops */
static const FtlTraceVar ftl_trace_fdp_noisy = {
    .want = "732 2340000000 10306 10306 4892 3732 5020 15198 3732 "
            "18370040710023928802",
    .pids = { 0, 1 },
    .npids = 2,
};
/* handle 3 is initially isolated and has no heap of its own */
static const FtlTraceVar ftl_trace_fdp_noisy_ii = {
    .want = "732 2170000000 10306 10306 4077 3528 4205 14383 3528 "
            "4801098223349791737",
    .pids = { 0, 3 },
    .npids = 2,
};
/* a whole-device reset while both kinds of heap hold victims */
static const FtlTraceVar ftl_trace_fdp_trim = {
    .want = "1333 4650000000 20356 20356 9148 7332 9276 29504 7332 "
            "6162714646788561405",
    .pids = { 0, 1 },
    .npids = 2,
    .trim = true,
};
/*
 * Each command runs one background collection pass, and a greedy placement
 * pass that refuses its victim pops it and inserts it back, which moves the
 * order of units with equal valid counts. The reads add enough refusals for
 * that order to change what later collections relocate.
 */
static const FtlTraceVar ftl_trace_fdp_reread = {
    .want = "1332 3210000000 10306 10306 9360 4852 10088 19666 4852 "
            "6214949802370350338",
    .reread = true,
};
static const FtlTraceVar ftl_trace_read_reclaim = {
    .want = "1332 1750000000 10306 10306 1399 2836 2127 11705 2836 "
            "9709285251358799837",
    .reread = true,
    .read_reclaims = 83,
};

static void *femu_cb_page_before(GString *cmd_line, void *arg)
{
    const char *mark = strstr(cmd_line->str, "@ONFI@");

    g_assert_nonnull(mark);
    femu_cb_page = femu_onfi_page_file(3, true);
    g_string_erase(cmd_line, mark - cmd_line->str, strlen("@ONFI@"));
    g_string_insert(cmd_line, mark - cmd_line->str, femu_cb_page);
    return arg;
}

/*
 * Program disturb tests. A single-LUN device with 16-page blocks puts page k
 * of a fresh device on page k of block 0, line 0. The ECC step is 10 ms, so
 * one tier stands far above the read time and the few ms a die can be busy.
 */
/* a one-channel bbssd device for the ONFI timing tests; luns_per_ch follows */
#define FEMU_ONFI_GEO \
    "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8," \
    "pgs_per_blk=16,blks_per_pl=24,pls_per_lun=1,nchs=1,"
#define FEMU_PD_GEO \
    "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8," \
    "pgs_per_blk=16,blks_per_pl=24,pls_per_lun=1,luns_per_ch=1,nchs=1," \
    "ecc_step_ns=10000000"

static FemuWideLba femu_wide_4k = { .lbads = 12 };
static FemuWideLba femu_wide_8k = { .lbads = 13 };
static FemuWideLba femu_wide_fdp = { .lbads = 12, .fdp = true };

static bool femu_zoned = true;

static bool femu_vwc = true;

static const FemuIoFuzz femu_io_fuzz_conv = { 8, false, 0 };
static const FemuIoFuzz femu_io_fuzz_zoned = { 5, true, 0 };
static const FemuIoFuzz femu_io_fuzz_fdp = { 8, false, 4 };

#define FEMU_LSI_DEV    "id=lsi-test,oncs=0x19f"

/*
 * The command count, then the opcode and modelled time in ns of each command,
 * as the OC 1.2 timing model computed them when this test was written. A
 * change to that model must leave them exact.
 */
static const uint64_t femu_oc12_trace_on[] = {
    156,
    0x91, 925366, 0x91, 2566366, 0x91, 4207366, 0x91, 5027866, 0x91, 6668866,
    0x91, 9714366, 0x91, 11939366, 0x91, 14984866, 0x91, 16625866,
    0x91, 17446366, 0x91, 21896366, 0x91, 29855366, 0x91, 35589366,
    0x91, 42143866, 0x91, 925366, 0x91, 1745866, 0x91, 2566366, 0x91, 3386866,
    0x91, 4207366, 0x91, 5027866, 0x91, 7252866, 0x91, 9477866, 0x91, 10298366,
    0x91, 11118866, 0x91, 13343866, 0x91, 15568866, 0x91, 21302866,
    0x91, 27036866, 0x92, 69609, 0x92, 139217, 0x92, 208825, 0x92, 278433,
    0x92, 348042, 0x92, 426692, 0x92, 518450, 0x92, 623316, 0x92, 636425,
    0x92, 662642, 0x92, 723825, 0x92, 814433, 0x92, 933542, 0x92, 1052650,
    0x90, 6000000, 0x90, 6000000, 0x92, 69609, 0x92, 82718, 0x92, 95827,
    0x92, 126109, 0x92, 139218, 0x92, 152327, 0x92, 203609, 0x92, 216718,
    0x92, 182609, 0x92, 260109, 0x92, 281109, 0x92, 294218, 0x92, 366109,
    0x92, 387109, 0x92, 316609, 0x92, 422609, 0x92, 443609, 0x92, 400218,
    0x92, 479109, 0x92, 500109, 0x92, 456718, 0x92, 556609, 0x92, 569718,
    0x92, 513218, 0x92, 634109, 0x92, 647218, 0x92, 613109, 0x92, 740109,
    0x92, 690609, 0x92, 669609, 0x92, 796609, 0x92, 753218, 0x92, 726109,
    0x92, 108936, 0x92, 165436, 0x92, 229827, 0x92, 329718, 0x92, 342827,
    0x92, 526327, 0x92, 539436, 0x91, 1721975, 0x92, 69609, 0x91, 1815475,
    0x92, 213801, 0x91, 2647341, 0x92, 226910, 0x91, 1972776, 0x92, 423535,
    0x92, 65002, 0x92, 130003, 0x92, 195004, 0x92, 260005, 0x92, 335007,
    0x92, 425009, 0x92, 530011, 0x92, 650013, 0x92, 665014, 0x92, 695015,
    0x92, 740016, 0x92, 800017, 0x92, 875019, 0x92, 980012, 0x90, 5000002,
    0x90, 5000002, 0x92, 65002, 0x92, 80003, 0x92, 95004, 0x92, 115003,
    0x92, 130004, 0x92, 145005, 0x92, 192503, 0x92, 207504, 0x92, 165004,
    0x92, 242504, 0x92, 270003, 0x92, 285004, 0x92, 332505, 0x92, 360004,
    0x92, 300005, 0x92, 382506, 0x92, 410005, 0x92, 425006, 0x92, 440007,
    0x92, 460006, 0x92, 475007, 0x92, 510007, 0x92, 525008, 0x92, 490008,
    0x92, 587507, 0x92, 602508, 0x92, 560008, 0x92, 677508, 0x92, 637508,
    0x92, 617509, 0x92, 727509, 0x92, 692509, 0x92, 660010, 0x92, 222505,
    0x92, 315006, 0x92, 540009, 0x92, 707510, 0x92, 742510, 0x92, 757511,
    0x92, 772512, 0x91, 1592515, 0x92, 65002, 0x91, 1585006, 0x92, 230006,
    0x91, 2412518, 0x92, 245007, 0x91, 1765011, 0x92, 470012,
};

static const uint64_t femu_oc12_trace_off[] = {
    156,
    0x91, 820500, 0x91, 2461500, 0x91, 4102500, 0x91, 4923000, 0x91, 6564000,
    0x91, 9609500, 0x91, 11834500, 0x91, 14880000, 0x91, 16521000,
    0x91, 17341500, 0x91, 21791500, 0x91, 29750500, 0x91, 35484500,
    0x91, 42039000, 0x91, 820500, 0x91, 1641000, 0x91, 2461500, 0x91, 3282000,
    0x91, 4102500, 0x91, 4923000, 0x91, 7148000, 0x91, 9373000, 0x91, 10193500,
    0x91, 11014000, 0x91, 13239000, 0x91, 15464000, 0x91, 21198000,
    0x91, 26932000, 0x92, 56500, 0x92, 113000, 0x92, 169500, 0x92, 226000,
    0x92, 282500, 0x92, 339000, 0x92, 416500, 0x92, 494000, 0x92, 550500,
    0x92, 607000, 0x92, 684500, 0x92, 762000, 0x92, 868000, 0x92, 974000,
    0x90, 6000000, 0x90, 6000000, 0x92, 56500, 0x92, 56500, 0x92, 56500,
    0x92, 113000, 0x92, 113000, 0x92, 113000, 0x92, 190500, 0x92, 190500,
    0x92, 169500, 0x92, 247000, 0x92, 268000, 0x92, 247000, 0x92, 353000,
    0x92, 374000, 0x92, 303500, 0x92, 409500, 0x92, 430500, 0x92, 360000,
    0x92, 466000, 0x92, 487000, 0x92, 437500, 0x92, 543500, 0x92, 543500,
    0x92, 494000, 0x92, 621000, 0x92, 621000, 0x92, 600000, 0x92, 727000,
    0x92, 677500, 0x92, 656500, 0x92, 783500, 0x92, 734000, 0x92, 713000,
    0x92, 56500, 0x92, 134000, 0x92, 211500, 0x92, 268000, 0x92, 324500,
    0x92, 402000, 0x92, 479500, 0x91, 1604000, 0x92, 56500, 0x91, 1641000,
    0x92, 113000, 0x91, 2354000, 0x92, 169500, 0x91, 1641000, 0x92, 247000,
    0x92, 50001, 0x92, 100002, 0x92, 150003, 0x92, 200004, 0x92, 250005,
    0x92, 300006, 0x92, 377506, 0x92, 455006, 0x92, 505007, 0x92, 555008,
    0x92, 632508, 0x92, 710008, 0x92, 800009, 0x92, 890010, 0x90, 5000002,
    0x90, 5000002, 0x92, 50001, 0x92, 50001, 0x92, 50001, 0x92, 100002,
    0x92, 100002, 0x92, 100002, 0x92, 177502, 0x92, 177502, 0x92, 150003,
    0x92, 227503, 0x92, 255002, 0x92, 227503, 0x92, 317504, 0x92, 345003,
    0x92, 277504, 0x92, 367505, 0x92, 395004, 0x92, 327505, 0x92, 417506,
    0x92, 445005, 0x92, 405005, 0x92, 495006, 0x92, 495006, 0x92, 455006,
    0x92, 572506, 0x92, 572506, 0x92, 545007, 0x92, 662507, 0x92, 622507,
    0x92, 595008, 0x92, 712508, 0x92, 672508, 0x92, 645009, 0x92, 50001,
    0x92, 127501, 0x92, 205001, 0x92, 255002, 0x92, 305003, 0x92, 382503,
    0x92, 460003, 0x91, 1412509, 0x92, 50001, 0x91, 1400002, 0x92, 100002,
    0x91, 2045011, 0x92, 150003, 0x91, 1400002, 0x92, 227503,
};
static const FemuOc12TraceWant femu_oc12_trace_want[] = {
    { femu_oc12_trace_on, G_N_ELEMENTS(femu_oc12_trace_on) },
    { femu_oc12_trace_off, G_N_ELEMENTS(femu_oc12_trace_off) },
};

static void *femu_csd_warn_before(GString *cmd_line, void *arg)
{
    g_autofree char *quoted = g_shell_quote(femu_csd_warn_log);

    g_string_append_printf(cmd_line, " 2>%s", quoted);
    return arg;
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

static const FemuIdentity femu_id_nossd = {
    "vNoSSD0", "FEMU NoSSD NVMe Controller"
};
static const FemuIdentity femu_id_bbssd = {
    "vSSD0", "FEMU BlackBox-SSD Controller", 2, "vNoSSD1"
};
static const FemuIdentity femu_id_kvssd = {
    "vKVSSD0", "FEMU KV-SSD Controller"
};
/* the same on a -device line, where a comma in a value is written twice */
#define KV_MODEL_TEST_OPT \
    "0.05,,0,,0,,0.075,,0.2" ",,0,,0,,0,,0,,0,,0,,0,,0,,0,,0" \
    ",,0,,0,,0,,0,,0,,0,,0,,0,,0,,0" ",,0,,0,,0,,0,,0,,0,,0,,0,,0,,0" ",,0"

/*
 * kv_index=lsm tests. Keys are 8 bytes whose byte order is the order of
 * the number, so List order can be checked as numbers.
 */
#define FEMU_LSM_KNOBS \
    "kv_index=lsm,kv_lsm_memtable_keys=16,kv_lsm_size_ratio=2,"

static const FemuWrrCase femu_wrr_cases[] = {
    /* urgent first, though its queue has the higher id */
    { ",wrr=on", 1, FEMU_ARB(31, 15, 7, 0), 2, { 3, 0 }, { 8, 8 },
      "2222222211111111" },
    /* urgent queues share in turn, one command each with AB 0 */
    { ",wrr=on", 1, FEMU_ARB(31, 15, 7, 0), 3, { 0, 0, 3 }, { 2, 2, 2 },
      "121233" },
    /* HPW 3: four high, one low, then four high again */
    { ",wrr=on", 1, FEMU_ARB(3, 0, 0, 0), 2, { 1, 3 }, { 8, 8 },
      "1111211112222222" },
    /* all weights 0: the high cursor moves, so SQ 2 is not starved */
    { ",wrr=on", 1, FEMU_ARB(0, 0, 0, 0), 4, { 1, 1, 2, 3 }, { 6, 6, 6, 6 },
      "134234134234134234121212" },
    /* CC.AMS 000b: round robin, the priority ignored */
    { ",wrr=on", 0, FEMU_ARB(31, 15, 7, 0), 2, { 3, 0 }, { 8, 8 },
      "1212121212121212" },
    /* AB 7: each urgent queue empties in one grant, then the low one */
    { ",wrr=on", 1, FEMU_ARB(31, 15, 7, 7), 3, { 0, 0, 3 }, { 8, 8, 8 },
      "111111112222222233333333" },
};

static const FemuPreconCase femu_precon_base = {
    .opts = "", .fill = 90, .overwrite = 300, .seed = 11,
};
static const FemuPreconCase femu_precon_seq = {
    .opts = "", .fill = 100, .overwrite = 150, .seq = true,
};
static const FemuPreconCase femu_precon_policy = {
    .opts = ",gc_policy=d-choice,gc_seed=7,hot_cold_sep=on,gc_frontier=on",
    .fill = 90, .overwrite = 300, .seed = 11,
};
static const FemuPreconCase femu_precon_buffer = {
    .opts = ",buffer_size=16,vwc=1", .fill = 90, .overwrite = 300,
    .seed = 11, .flush = true,
};
static const FemuPreconCase femu_precon_wear = {
    .opts = ",blk_pe_limit=200,eol_read_only=off,wl_spread=4",
    .fill = 90, .overwrite = 300, .seed = 11,
};
static const FemuPreconCase femu_precon_pace = {
    .opts = ",gc_pace=on", .fill = 90, .overwrite = 300, .seed = 11,
};
static const FemuPreconCase femu_precon_break = {
    .opts = "", .fill = 90, .overwrite = 300, .seed = 11, .brk = true,
};
static const FemuPreconCase femu_precon_short = {
    .opts = "", .fill = 90, .overwrite = 300, .seed = 11, .short_ref = true,
};

/* the rotational subsystems of the rotational-* tests */
static void *femu_rot_before(GString *cmd_line, void *arg)
{
    g_string_prepend(cmd_line,
        " -device femu-subsys,id=rotsub,nqn=rotsub,rotational=on"
        " -device femu-subsys,id=rotsub-off,nqn=rotsub-off"
        " -device femu-subsys,id=rotsub-fdp,nqn=rotsub-fdp,rotational=on,"
        "fdp=on,fdp.nruh=4"
        " -device femu-subsys,id=rotsub-fdp-off,nqn=rotsub-fdp-off,"
        "fdp=on,fdp.nruh=4 ");
    return arg;
}

/* rrlsub for the main controller; rrlsub-b and rrlsub-c for hot-plugs */
static void *femu_rrl_before(GString *cmd_line, void *arg)
{
    g_string_prepend(cmd_line,
        " -device femu-subsys,id=rrlsub,nqn=rrlsub"
        " -device femu-subsys,id=rrlsub-b,nqn=rrlsub-b"
        " -device femu-subsys,id=rrlsub-c,nqn=rrlsub-c ");
    return arg;
}

/*
 * plmsub for the main controller; the empty plmsub-r and plmsub-sh
 * (shared namespaces) take the refused hot-plugs of plm-refused.
 */
static void *femu_plm_before(GString *cmd_line, void *arg)
{
    g_string_prepend(cmd_line,
        " -device femu-subsys,id=plmsub,nqn=plmsub"
        " -device femu-subsys,id=plmsub-r,nqn=plmsub-r"
        " -device femu-subsys,id=plmsub-sh,nqn=plmsub-sh,ns_mgmt=on ");
    return arg;
}

static void *femu_ocp_before(GString *cmd_line, void *arg)
{
    g_string_prepend(cmd_line, " -device femu-subsys,id=ocpsub,nqn=ocpsub ");
    return arg;
}

#define FEMU_CAPS_GEO \
    "secsz=512,secs_per_pg=8,pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1," \
    "luns_per_ch=4,nchs=4"
#define FEMU_ONCS_DEFAULT   0x19d   /* the oncs property's default */
#define FEMU_ONCS_OCSSD     0x10    /* Save/Select only: no generic command */

/*
 * Every mode, and the properties that change what is advertised. The
 * optional commands each configuration turns on are stated here as well, so
 * the registry is held to the configuration and not only to itself.
 */
static const FemuCapsCfg femu_caps_cfgs[] = {
    { "caps-nossd", "", FEMU_ONCS_DEFAULT, true },
    { "caps-nossd-all", "oncs=0x19f,vwc=1,sgl=on", 0x19f, true },
    { "caps-nossd-bare", "oncs=0,oacs=0", 0, false },
    { "caps-nossd-compare-copy", "oncs=0x101", 0x101, true },
    { "caps-nossd-wu-wz-verify", "oncs=0x8a", 0x8a, true },
    { "caps-nossd-ns-mgmt", "ns_mgmt=on,namespaces=2", FEMU_ONCS_DEFAULT,
      true },
    { "caps-nossd-streams", "streams=on", FEMU_ONCS_DEFAULT, true },
    { "caps-nossd-pi", "pi=on,meta=8,mc=3,oncs=0x19f,namespaces=2", 0x19f,
      true },
    { "caps-bbssd", "femu_mode=1," FEMU_CAPS_GEO, FEMU_ONCS_DEFAULT, true },
    { "caps-bbssd-all", "femu_mode=1,oncs=0x19f,vwc=1,sgl=on," FEMU_CAPS_GEO,
      0x19f, true },
    { "caps-bbssd-ns-mgmt", "femu_mode=1,ns_mgmt=on,namespaces=2,"
      FEMU_CAPS_GEO, FEMU_ONCS_DEFAULT, true },
    { "caps-bbssd-fdp", "femu_mode=1,subsys=fdpsub," FEMU_CAPS_GEO,
      FEMU_ONCS_DEFAULT, true },
    /* an endurance group with FDP off */
    { "caps-bbssd-endgrp", "femu_mode=1,subsys=nssub," FEMU_CAPS_GEO,
      FEMU_ONCS_DEFAULT, true, femu_ns_subsys_before },
    { "caps-mixed-endgrp", "femu_mode=1,namespaces=3,subsys=nssub,"
      "namespace_modes=bbssd,,znssd,,kvssd," FEMU_CAPS_GEO,
      FEMU_ONCS_DEFAULT, true, femu_ns_subsys_before },
    { "caps-zns", "femu_mode=3,secsz=512", FEMU_ONCS_DEFAULT, true },
    { "caps-zns-all", "femu_mode=3,secsz=512,oncs=0x19f,vwc=1,sgl=on", 0x19f,
      true },
    { "caps-kv", "devsz_mb=512,femu_mode=5", FEMU_ONCS_DEFAULT, true },
    { "caps-kv-all", "devsz_mb=512,femu_mode=5,oncs=0x19f,vwc=1,sgl=on",
      0x19f, true },
    { "caps-csd", "femu_mode=4,fdm_size=16", FEMU_ONCS_DEFAULT, true },
    { "caps-csd-cpslm", "femu_mode=4,fdm_size=16,csd_slm_size=4,csd_cp=on",
      FEMU_ONCS_DEFAULT, true },
    { "caps-csd-legacy", "femu_mode=4,fdm_size=16,csd_legacy_opcodes=on,"
      "csd_slm_size=4,csd_cp=on", FEMU_ONCS_DEFAULT, true },
    { "caps-csd-no-csd-ns", "femu_mode=4,fdm_size=16,namespace_modes=nossd",
      FEMU_ONCS_DEFAULT, true },
    { "caps-csd-cpslm-fdp", "femu_mode=4,fdm_size=16,csd_slm_size=4,"
      "csd_cp=on,subsys=fdpsub," FEMU_CAPS_GEO, FEMU_ONCS_DEFAULT, true },
    { "caps-csd-slm-endgrp", "femu_mode=4,fdm_size=16,csd_slm_size=4,"
      "subsys=nssub," FEMU_CAPS_GEO, FEMU_ONCS_DEFAULT, true,
      femu_ns_subsys_before },
    { "caps-oc12", "femu_mode=0,lver=1", FEMU_ONCS_OCSSD, true },
    { "caps-oc20", "femu_mode=0,lver=2,sgl=on", FEMU_ONCS_OCSSD, true },
    { "caps-mixed", "femu_mode=1,namespaces=3,"
      "namespace_modes=bbssd,,znssd,,kvssd," FEMU_CAPS_GEO,
      FEMU_ONCS_DEFAULT, true },
    { "caps-mixed-all", "femu_mode=1,namespaces=3,oncs=0x19f,"
      "namespace_modes=bbssd,,znssd,,kvssd," FEMU_CAPS_GEO, 0x19f, true },
    { "caps-mixed-csd", "namespaces=2,namespace_modes=nossd,,csd,"
      "fdm_size=16," FEMU_CAPS_GEO, FEMU_ONCS_DEFAULT, true },
};
#define FEMU_CPS_OPTS   "femu_mode=4,fdm_size=16,csd_slm_size=4,csd_cp=on," \
                        "nr_cu=2"

/*
 * The pSLC tier (tier_mode=static). The geometry has 4 dies of 48-page TLC
 * blocks: a dense line holds 192 pages and a pool line 4 x 16 = 64 pages.
 * tier_static_mb=1 is 256 pages, so the pool takes 4 lines.
 */
#define FEMU_TIER_GEO \
    "secsz=512,secs_per_pg=8,pgs_per_blk=48,blks_per_pl=32,pls_per_lun=1," \
    "luns_per_ch=2,nchs=2,nand_cell_type=3"

/* every gc_policy name */
static const char *const femu_tier_gc_policies[] = {
    "greedy", "random", "cost-benefit", "fifo", "d-choice",
};

static const FemuG1CqfSize femu_g1_cqf_pow2 = { 64, 4 };
static const FemuG1CqfSize femu_g1_cqf_odd = { 100, 5 };

static void femu_register_nodes(void)
{
    QOSGraphEdgeOptions opts = {
        .extra_device_opts = "addr=04.0,devsz_mb=64,femu_mode=2",
        /*
         * A placement-enabled subsystem for the tests that link to it. It has
         * to be on the command line before the controller, which a test's own
         * options cannot arrange, and it is inert for a controller that does
         * not name it.
         */
        .before_cmd_line =
            "-device femu-subsys,id=fdpsub,nqn=fdpsub,fdp=on,fdp.nruh=4 "
            "-device femu-subsys,id=fdpsub-ii,nqn=fdpsub-ii,fdp=on,fdp.nruh=4,"
            "fdp.isolation_mode=1 "
            "-device femu-subsys,id=fdpsub-runs,nqn=fdpsub-runs,fdp=on,"
            "fdp.nruh=4,fdp.runs=64K "
            "-device femu-subsys,id=fdpsub-tiny,nqn=fdpsub-tiny,fdp=on,"
            "fdp.nruh=4,fdp.runs=1K "
            "-device femu-subsys,id=fdpsub-rg2,nqn=fdpsub-rg2,fdp=on,"
            "fdp.nruh=4,fdp.nrg=2 "
            "-device femu-subsys,id=fdpsub-rg2-ii,nqn=fdpsub-rg2-ii,fdp=on,"
            "fdp.nruh=4,fdp.nrg=2,fdp.isolation_mode=1 "
            "-device femu-subsys,id=fdpsub-rg3,nqn=fdpsub-rg3,fdp=on,"
            "fdp.nruh=4,fdp.nrg=3 "
            "-device femu-subsys,id=fdpsub-rg4,nqn=fdpsub-rg4,fdp=on,"
            "fdp.nruh=4,fdp.nrg=4 "
            "-device femu-subsys,id=g1sub,nqn=g1sub,fdp=on,fdp.nruh=256,"
            "fdp.nru=640",
    };

    /*
     * Every QEMU these tests start inherits this: a KV namespace checks the
     * owner of each page after value GC and every 64 commands, and aborts
     * on a broken invariant.
     */
    g_setenv("FEMU_KV_CHECK", "1", true);

    add_qpci_address(&opts, &(QPCIAddress) { .devfn = QPCI_DEVFN(4, 0) });

    qos_add_test("doc-examples", "femu", femu_test_doc_examples, NULL);
    qos_add_test("ignored-props", "femu", femu_test_ignored_props, NULL);
    qos_add_test("kv-no-backend", "femu", femu_test_kv_no_backend, NULL);
    qos_add_test("memory", "femu", femu_test_memory, NULL);
    qos_add_test("memory-ftl", "femu", femu_test_memory_ftl, NULL);
    qos_add_test("memory-page-tables", "femu", femu_test_memory_page_tables,
                 NULL);
    qos_add_test("memory-parts", "femu", femu_test_memory_parts, NULL);
    qos_add_test("memory-kv-lsm", "femu", femu_test_memory_kv_lsm, NULL);
    qos_add_test("ftl-fail-sweep", "femu", femu_test_ftl_fail_sweep, NULL);
    qos_add_test("fdp-refused-restores", "femu",
                 femu_test_fdp_refused_restores, NULL);
    qos_add_test("geometry-big", "femu", femu_test_geometry_big,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=big,femu_mode=1,devsz_mb=64,secsz=512,secs_per_pg=256,"
            "pgs_per_blk=1024,blks_per_pl=256,pls_per_lun=1,luns_per_ch=4,"
            "nchs=8"
    });
    qos_add_test("geometry-limits", "femu", femu_test_geometry_limits, NULL);
    qos_add_test("multiplane-warnings", "femu", femu_test_multiplane_warnings,
                 NULL);
    qos_add_test("cxl-geometry-bounds", "femu", femu_test_cxl_geometry_bounds,
                 NULL);
    qos_add_test("cxl-log-missing", "femu", femu_test_cxl_log_missing, NULL);
    qos_add_test("cxl-lsa-normal", "femu", femu_test_cxl_lsa_normal, NULL);
    qos_add_test("cxl-ratio-off", "femu", femu_test_cxl_ratio_off, NULL);
    qos_add_test("cxl-ratio-runs", "femu", femu_test_cxl_ratio_runs, NULL);
    qos_add_test("cxl-der-budget", "femu", femu_test_cxl_der_budget, NULL);
    qos_add_test("cxl-der-budget-rate", "femu",
                 femu_test_cxl_der_budget_rate, NULL);
    qos_add_test("cxl-der-replace", "femu", femu_test_cxl_der_replace, NULL);
    qos_add_test("cxl-der-replace-rate", "femu",
                 femu_test_cxl_der_replace_rate, NULL);
    qos_add_test("cxl-der-budget-shared", "femu",
                 femu_test_cxl_der_budget_shared, NULL);
    qos_add_test("cxl-ratio-budget", "femu", femu_test_cxl_ratio_budget,
                 NULL);
    qos_add_test("cxl-ratio-restore", "femu", femu_test_cxl_ratio_restore,
                 NULL);
    qos_add_test("cxl-ratio-fallback", "femu", femu_test_cxl_ratio_fallback,
                 NULL);
    qos_add_test("cxl-lsa-bounds", "femu", femu_test_cxl_lsa_bounds, NULL);
    qos_add_test("cxl-lsa-queue", "femu", femu_test_cxl_lsa_queue, NULL);
    qos_add_test("cxl-sanitize-media", "femu", femu_test_cxl_sanitize_media,
                 NULL);
    qos_add_test("cxl-sanitize-ratio", "femu", femu_test_cxl_sanitize_ratio,
                 NULL);
    qos_add_test("cxl-never-emulate", "femu", femu_test_cxl_never_emulate,
                 NULL);
    qos_add_test("cxl-ratio-dirty", "femu", femu_test_cxl_ratio_dirty, NULL);
    qos_add_test("cxl-control-qom", "femu", femu_test_cxl_control, NULL);
    qos_add_test("cxl-control-lsa", "femu", femu_test_cxl_control,
                 &(QOSGraphTestOptions) { .arg = (void *)1 });
    qos_add_test("cxl-compat", "femu", femu_test_cxl_compat, NULL);
    qos_add_test("cxl-capacity", "femu", femu_test_cxl_capacity, NULL);
    qos_add_test("cxl-prefetch", "femu", femu_test_cxl_prefetch, NULL);
    qos_add_test("cxl-nand-reserve", "femu", femu_test_cxl_nand_reserve,
                 NULL);
    qos_add_test("cxl-gc-stall", "femu", femu_test_cxl_gc_stall, NULL);
    qos_add_test("cxl-gc-reserve-stall", "femu",
                 femu_test_cxl_gc_reserve_stall, NULL);
    qos_add_test("cxl-gc-wait", "femu", femu_test_cxl_gc_wait, NULL);
    qos_add_test("cxl-gc-stall-warn", "femu", femu_test_cxl_gc_stall_warn,
                 NULL);
    qos_add_test("cxl-prefetch-clamp", "femu", femu_test_cxl_prefetch_clamp,
                 NULL);
    qos_add_test("cxl-stats", "femu", femu_test_cxl_stats, NULL);
    qos_add_test("cxl-log-limit", "femu", femu_test_cxl_log_limit, NULL);
    qos_node_create_driver("femu", femu_create);
    qos_add_test("cxl-stale-translation", "femu",
                 femu_test_cxl_stale_translation, NULL);
    qos_add_test("cxl-forward", "femu", femu_test_cxl_forward, NULL);
    qos_add_test("cxl-target-bound", "femu", femu_test_cxl_target_bound,
                 NULL);
    qos_add_test("cxl-local-overlay", "femu", femu_test_cxl_local_overlay,
                 NULL);
    qos_add_test("cxl-topology", "femu", femu_test_cxl_topology, NULL);
    qos_add_test("cxl-topology-memslot", "femu", femu_test_cxl_topology,
                 &(QOSGraphTestOptions) { .arg = (void *)"memslot" });
    qos_add_test("cxl-switch", "femu", femu_test_cxl_switch, NULL);
    qos_add_test("cxl-prefetch-decoders", "femu",
                 femu_test_cxl_prefetch_decoders, NULL);
    qos_add_test("cxl-overlay-scope", "femu", femu_test_cxl_overlay_scope,
                 NULL);
    qos_add_test("cxl-slot-reservation", "femu",
                 femu_test_cxl_slot_reservation, NULL);
    qos_add_test("cxl-ftl-fail-sweep", "femu", femu_test_cxl_ftl_fail_sweep,
                 NULL);
    qos_add_test("mem-limit", "femu", femu_test_mem_limit, NULL);
    qos_add_test("mem-limit-subsys", "femu", femu_test_mem_limit_subsys, NULL);
    qos_add_test("mem-limit-modes", "femu", femu_test_mem_limit_modes, NULL);
    qos_add_test("mem-limit-commands", "femu", femu_test_mem_limit_commands,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=mlc,mem_limit=1G,ns_mgmt=on,femu_mode=1,secsz=512,"
            "secs_per_pg=8,pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,"
            "luns_per_ch=4,nchs=4",
    });
    qos_add_test("cxl-realize-retry", "femu", femu_test_cxl_realize_retry,
                 NULL);
    qos_add_test("cxl-bg-reset-unplug", "femu", femu_test_cxl_bg_unplug,
                 &(QOSGraphTestOptions) { .arg = (void *)2 });
    qos_add_test("cxl-bg-unplug", "femu", femu_test_cxl_bg_unplug,
                 NULL);
    qos_add_test("cxl-realize", "femu", femu_test_cxl_realize, NULL);
    qos_add_test("cxl-flush", "femu", femu_test_cxl_flush, NULL);
    qos_add_test("cxl-fast-load", "femu", femu_test_cxl_fast_load, NULL);
    qos_add_test("cxl-fast-load-drain", "femu", femu_test_cxl_fast_load_drain,
                 NULL);
    qos_add_test("cxl-fast-load-backlog", "femu",
                 femu_test_cxl_fast_load_backlog, NULL);
    qos_add_test("cxl-fast-load-state", "femu", femu_test_cxl_fast_load_state,
                 NULL);
    qos_add_test("cxl-der-default", "femu", femu_test_cxl_der_modes,
                 &(QOSGraphTestOptions) { .arg = (void *)"" });
    qos_add_test("cxl-der-off", "femu", femu_test_cxl_der_modes,
                 &(QOSGraphTestOptions) { .arg = (void *)"off" });
    qos_add_test("cxl-der-cylon", "femu", femu_test_cxl_der_modes,
                 &(QOSGraphTestOptions) { .arg = (void *)"cylon" });
    qos_add_test("cxl-der-invalid", "femu", femu_test_cxl_der_invalid, NULL);
    qos_add_test("cxl-memslot-tcg", "femu", femu_test_cxl_memslot_tcg, NULL);
    qos_add_test("cxl-der", "femu", femu_test_cxl_der, NULL);
    qos_add_test("cxl-wait-invalidate", "femu", femu_test_cxl_wait,
                 &(QOSGraphTestOptions) { .arg = (void *)2 });
    qos_add_test("cxl-wait", "femu", femu_test_cxl_wait, NULL);
    qos_add_test("cxl-wait-unplug", "femu", femu_test_cxl_wait,
                 &(QOSGraphTestOptions) { .arg = (void *)3 });
    qos_add_test("cxl-wait-other-page", "femu", femu_test_cxl_wait,
                 &(QOSGraphTestOptions) { .arg = (void *)4 });
    qos_add_test("cxl-wait-held-victim", "femu", femu_test_cxl_wait,
                 &(QOSGraphTestOptions) { .arg = (void *)5 });
    qos_add_test("cxl-wait-other-page-serial", "femu", femu_test_cxl_wait,
                 &(QOSGraphTestOptions) { .arg = (void *)6 });
    {
        static const FemuCxlStress st = { "", FEMU_STRESS_NONE, 0 };

        qos_add_test("cxl-stress-same-page", "femu", femu_test_cxl_stress,
                     &(QOSGraphTestOptions) { .arg = (void *)&st });
    }
    {
        static const FemuCxlStress st = { "", FEMU_STRESS_NONE, 1 };

        qos_add_test("cxl-stress-spread", "femu", femu_test_cxl_stress,
                     &(QOSGraphTestOptions) { .arg = (void *)&st });
    }
    {
        static const FemuCxlStress st = { "", FEMU_STRESS_FLUSH, 0 };

        qos_add_test("cxl-stress-flush", "femu", femu_test_cxl_stress,
                     &(QOSGraphTestOptions) { .arg = (void *)&st });
    }
    {
        static const FemuCxlStress st = { "", FEMU_STRESS_INVALIDATE, 0 };

        qos_add_test("cxl-stress-invalidate", "femu", femu_test_cxl_stress,
                     &(QOSGraphTestOptions) { .arg = (void *)&st });
    }
    {
        static const FemuCxlStress st = { "", FEMU_STRESS_WAYS, 1 };

        qos_add_test("cxl-stress-ways", "femu", femu_test_cxl_stress,
                     &(QOSGraphTestOptions) { .arg = (void *)&st });
    }
    {
        static const FemuCxlStress st = { ",cca=on", FEMU_STRESS_CCA, 1 };

        qos_add_test("cxl-stress-cca", "femu", femu_test_cxl_stress,
                     &(QOSGraphTestOptions) { .arg = (void *)&st });
    }
    {
        static const FemuCxlStress st = { "", FEMU_STRESS_UNPLUG, 1 };

        qos_add_test("cxl-stress-unplug", "femu", femu_test_cxl_stress,
                     &(QOSGraphTestOptions) { .arg = (void *)&st });
    }
    qos_add_test("cxl-wait-queue", "femu", femu_test_cxl_wait,
                 &(QOSGraphTestOptions) { .arg = (void *)1 });
    qos_add_test("cxl-dma-doorbell", "femu", femu_test_cxl_dma_doorbell,
                 NULL);
    qos_add_test("cxl-dma-doorbell-cached", "femu",
                 femu_test_cxl_dma_doorbell,
                 &(QOSGraphTestOptions) { .arg = (void *)1 });
    qos_add_test("cxl-dma-doorbell-queues", "femu",
                 femu_test_cxl_dma_doorbell,
                 &(QOSGraphTestOptions) { .arg = (void *)2 });
    qos_add_test("cxl-cylon-ack", "femu", femu_test_cxl_cylon_ack, NULL);
    qos_add_test("cxl-revoke-batch", "femu", femu_test_cxl_revoke_batch,
                 NULL);
    qos_add_test("cxl-revoke-ahead", "femu", femu_test_cxl_revoke_ahead,
                 NULL);
    qos_add_test("cxl-no-ftl", "femu", femu_test_cxl_no_ftl, NULL);
    qos_add_test("cxl-invalid", "femu", femu_test_cxl_invalid, NULL);
    qos_add_test("cxl-cca-off", "femu", femu_test_cca_off, NULL);
    qos_add_test("cxl-cca-layout", "femu", femu_test_cca_layout, NULL);
    qos_add_test("cxl-cca-nop", "femu", femu_test_cca_nop, NULL);
    qos_add_test("cxl-cca-pin", "femu", femu_test_cca_pin, NULL);
    qos_add_test("cxl-cca-budget", "femu", femu_test_cca_budget, NULL);
    qos_add_test("cxl-cca-unpin", "femu", femu_test_cca_unpin, NULL);
    qos_add_test("cxl-cca-invalidate", "femu", femu_test_cca_invalidate,
                 NULL);
    qos_add_test("cxl-cca-miss-time", "femu", femu_test_cca_miss_time,
                 NULL);
    qos_add_test("cxl-cca-uncached", "femu", femu_test_cca_uncached, NULL);
    qos_add_test("cxl-cca-prefetch", "femu", femu_test_cca_prefetch, NULL);
    qos_add_test("cxl-cca-flush", "femu", femu_test_cca_flush, NULL);
    qos_add_test("cxl-cca-ways", "femu", femu_test_cca_ways, NULL);
    qos_add_test("cxl-cca-ratio", "femu", femu_test_cca_ratio, NULL);
    qos_add_test("cxl-cca-query", "femu", femu_test_cca_query, NULL);
    qos_add_test("cxl-cca-errors", "femu", femu_test_cca_errors, NULL);
    qos_add_test("cxl-cca-reset", "femu", femu_test_cca_reset, NULL);
    qos_add_test("cxl-cca-der", "femu", femu_test_cca_der, NULL);
    qos_add_test("cxl-cca-der-replace", "femu", femu_test_cca_der_replace,
                 NULL);
    qos_add_test("cxl-cca-unplug", "femu", femu_test_cca_unplug, NULL);
    qos_add_test("cxl-cca-media", "femu", femu_test_cca_media, NULL);
    qos_add_test("cxl-fill-charge", "femu", femu_test_cxl_fill_charge, NULL);
    qos_add_test("cxl-fill-owner", "femu", femu_test_cxl_fill_owner, NULL);
    qos_add_test("cxl-pingpong-1", "femu", femu_test_cxl_pingpong_1, NULL);
    qos_add_test("cxl-pingpong-2", "femu", femu_test_cxl_pingpong_2, NULL);
    qos_add_test("cxl-pingpong-4", "femu", femu_test_cxl_pingpong_4, NULL);
    qos_add_test("cxl-overflow", "femu", femu_test_cxl_overflow, NULL);
    qos_add_test("cxl-walk-conflict", "femu", femu_test_cxl_walk_conflict,
                 NULL);
    qos_add_test("cxl-uncached-walk", "femu", femu_test_cxl_uncached_walk,
                 NULL);
    qos_add_test("cxl-overflow-cycle", "femu", femu_test_cxl_overflow_cycle,
                 NULL);
    qos_add_test("cxl-one-rip-loops", "femu", femu_test_cxl_one_rip_loops,
                 NULL);
    qos_add_test("cxl-prefetch-race", "femu", femu_test_cxl_prefetch_race,
                 NULL);
    qos_add_test("cxl-storm-set", "femu", femu_test_cxl_storm_set, NULL);
    qos_add_test("cxl-fault-stop", "femu", femu_test_cxl_fault_stop, NULL);
    qos_add_test("cxl-storm-bql", "femu", femu_test_cxl_storm_bql, NULL);
    qos_add_test("cxl-dma-queue", "femu", femu_test_cxl_dma_queue, NULL);
    qos_add_test("cxl-dma-main-loop", "femu", femu_test_cxl_dma_main_loop,
                 NULL);
    qos_add_test("cxl-dma-iothread", "femu", femu_test_cxl_dma_iothread,
                 NULL);
    qos_add_test("cxl-dma-page0", "femu", femu_test_cxl_dma_page0, NULL);
    qos_add_test("cxl-dma-thread", "femu", femu_test_cxl_dma_thread, NULL);
    qos_add_test("cxl-dma-fair", "femu", femu_test_cxl_dma_fair, NULL);
    qos_add_test("cxl-fast-load-held", "femu", femu_test_cxl_fast_load_held,
                 NULL);
    qos_add_test("cxl-fast-load-posted", "femu",
                 femu_test_cxl_fast_load_posted, NULL);
    qos_add_test("cxl-storm-change", "femu", femu_test_cxl_storm_change,
                 NULL);
    qos_add_test("cxl-storm-unplug", "femu", femu_test_cxl_storm_unplug,
                 NULL);
    qos_add_test("cxl-storm-bench", "femu", femu_test_cxl_storm_bench, NULL);
    qos_add_test("cxl-fill-delay", "femu", femu_test_cxl_fill_delay, NULL);
    qos_add_test("cxl-cca-bql", "femu", femu_test_cca_bql, NULL);
    qos_add_test("cxl-cca-lsa-busy", "femu", femu_test_cca_lsa_busy, NULL);
    qos_add_test("cxl-cca-disable-abandon", "femu",
                 femu_test_cca_disable_abandon, NULL);
    qos_add_test("cxl-cca-interleave", "femu", femu_test_cca_interleave,
                 NULL);
    qos_add_test("cxl-nvme-link", "femu", femu_test_cxl_nvme_link, NULL);
    qos_add_test("cxl-nvme-data", "femu", femu_test_cxl_nvme_data, NULL);
    qos_add_test("cxl-nvme-data-4k", "femu", femu_test_cxl_nvme_data,
                 &(QOSGraphTestOptions) { .arg = (void *)1 });
    qos_add_test("cxl-nvme-prp", "femu", femu_test_cxl_nvme_prp,
                 &(QOSGraphTestOptions) { .arg = (void *)128 });
    qos_add_test("cxl-nvme-prp-mdts", "femu", femu_test_cxl_nvme_prp,
                 &(QOSGraphTestOptions) { .arg = (void *)1024 });
    qos_add_test("cxl-nvme-prp-queues", "femu", femu_test_cxl_nvme_prp,
                 &(QOSGraphTestOptions) {
                     .arg = (void *)(uintptr_t)(128 | FEMU_LINK_QUEUES) });
    qos_add_test("cxl-nvme-write", "femu", femu_test_cxl_nvme_invalidate,
                 &(QOSGraphTestOptions) { .arg = (void *)FEMU_LINK_WRITE });
    qos_add_test("cxl-nvme-write-zeroes", "femu",
                 femu_test_cxl_nvme_invalidate,
                 &(QOSGraphTestOptions) { .arg = (void *)FEMU_LINK_ZEROES });
    qos_add_test("cxl-nvme-copy", "femu", femu_test_cxl_nvme_invalidate,
                 &(QOSGraphTestOptions) { .arg = (void *)FEMU_LINK_COPY });
    qos_add_test("cxl-nvme-ratio", "femu", femu_test_cxl_nvme_ratio, NULL);
    qos_add_test("cxl-nvme-deallocate", "femu",
                 femu_test_cxl_nvme_deallocate, NULL);
    qos_add_test("cxl-nvme-dulbe", "femu", femu_test_cxl_nvme_dulbe, NULL);
    qos_add_test("cxl-nvme-ratio-dulbe", "femu",
                 femu_test_cxl_nvme_ratio_dulbe, NULL);
    qos_add_test("cxl-nvme-flip", "femu", femu_test_cxl_nvme_flip, NULL);
    qos_add_test("cxl-nvme-pin", "femu", femu_test_cxl_nvme_pin, NULL);
    qos_add_test("cxl-nvme-unplug", "femu", femu_test_cxl_nvme_unplug, NULL);
    qos_add_test("cxl-nvme-slot-off", "femu", femu_test_cxl_nvme_unplug,
                 &(QOSGraphTestOptions) { .arg = (void *)1 });
    qos_add_test("cxl-nvme-guard", "femu", femu_test_cxl_nvme_guard, NULL);
    qos_add_test("cxl-nvme-barrier", "femu", femu_test_cxl_nvme_barrier,
                 NULL);
    qos_add_test("cxl-nvme-guard-unplug", "femu", femu_test_cxl_nvme_guard,
                 &(QOSGraphTestOptions) { .arg = (void *)1 });
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
    qos_add_test("streams-gc-floor", "femu", femu_test_streams_gc_floor,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,streams=on,streams.max=1,devsz_mb=1,femu_mode=1,"
            "secsz=512,secs_per_pg=8,pgs_per_blk=8,blks_per_pl=12,"
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
    qos_add_test("fdp-directive", "femu", femu_test_fdp_directive,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub",
    });
    qos_add_test("fdp-directive-no-fdp", "femu", femu_test_fdp_directive,
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
    qos_add_test("cmb-last-byte", "femu", femu_test_cmb_last_byte,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "cmbsz=0x400000,cmbloc=2"
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
            "devsz_mb=128,femu_mode=1,namespaces=2,namespace_modes=bbssd,,"
            "znssd"
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
    qos_add_test("kv-short-into-list", "femu", femu_test_kv_short_into_list,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "devsz_mb=512,femu_mode=5"
    });
    qos_add_test("kv-list-walk", "femu", femu_test_kv_list_walk,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "devsz_mb=512,femu_mode=5"
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
    qos_add_test("compare-verify-media-bbssd", "femu",
                 femu_test_compare_verify_media, &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1," FEMU_CAPS_GEO
    });
    qos_add_test("compare-verify-media-zns", "femu",
                 femu_test_compare_verify_zns, &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,"
            "zns_pg_rd_lat=300000000"
    });
    qos_add_test("copy-timing-bbssd", "femu", femu_test_copy_timing,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=4,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,nchs=1,"
            "pg_rd_lat=100000000,pg_wr_lat=400000000"
    });
    qos_add_test("copy-fmt2-own-csd", "femu", femu_test_copy_fmt2_own,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=4,fdm_size=16,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,nchs=1"
    });
    qos_add_test("oncs-default-bbssd", "femu", femu_test_oncs_default,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1," FEMU_CAPS_GEO,
        .arg = (void *)1,
    });
    qos_add_test("oncs-zero-bbssd", "femu", femu_test_oncs_default,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1,oncs=0," FEMU_CAPS_GEO
    });
    qos_add_test("oc20-generic-refused", "femu", femu_test_oc_generic_refused,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=1024,femu_mode=0,lver=2,lnum_ch=3,lnum_lun=5,"
            "lsecs_per_pg=4,lpgs_per_blk=256,oncs=0x19f"
    });
    qos_add_test("oc12-generic-refused", "femu", femu_test_oc_generic_refused,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=0,lver=1,oncs=0x19f"
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
    qos_add_test("oc20-vector-reset", "femu", femu_test_oc20_vector_reset,
                 &(QOSGraphTestOptions) {
        /*
         * A size of its own gives this test a new device: qos reuses the
         * QEMU of oc20-vector-io, whose chunks are no longer free.
         */
        .edge.extra_device_opts =
            "devsz_mb=768,femu_mode=0,lver=2,lnum_ch=3,lnum_lun=5,"
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
    qos_add_test("rw-atomic-write", "femu", femu_test_rw_atomic,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"write",
        .edge.extra_device_opts =
            "sgl=on,nlbaf=8,lba_index=7,multipoller_enabled=1,poller_ratio=1"
    });
    qos_add_test("rw-atomic-copy", "femu", femu_test_rw_atomic,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"copy",
        .edge.extra_device_opts =
            "sgl=on,nlbaf=8,lba_index=7,multipoller_enabled=1,poller_ratio=1"
    });
    qos_add_test("rw-atomic-write-4k", "femu", femu_test_rw_atomic,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"write-4k",
        .edge.extra_device_opts =
            "lba_index=3,multipoller_enabled=1,poller_ratio=1"
    });
    qos_add_test("atomic-identify-off", "femu", femu_test_atomic_identify,
                 &(QOSGraphTestOptions) { .arg = (void *)"off" });
    qos_add_test("atomic-identify-on", "femu", femu_test_atomic_identify,
                 &(QOSGraphTestOptions) { .arg = (void *)"on",
        .edge.extra_device_opts = "atomic_write_lbas=16" });
    qos_add_test("atomic-hold", "femu", femu_test_atomic_hold,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=rwa,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "atomic_write_lbas=16,multipoller_enabled=1,poller_ratio=1"
    });
    qos_add_test("atomic-refused", "femu", femu_test_atomic_refused, NULL);
    qos_add_test("perf-hints-off", "femu", femu_test_perf_hints,
                 &(QOSGraphTestOptions) { .arg = (void *)"off",
        .edge.extra_device_opts =
            "femu_mode=1,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2" });
    qos_add_test("perf-hints-on", "femu", femu_test_perf_hints,
                 &(QOSGraphTestOptions) { .arg = (void *)"on",
        .edge.extra_device_opts =
            "femu_mode=1,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "perf_hints=on" });
    qos_add_test("nand-profile", "femu", femu_test_nand_profile, NULL);
    qos_add_test("nand-profile-refused", "femu",
                 femu_test_nand_profile_refused, NULL);
    qos_add_test("perf-hints-refused", "femu", femu_test_perf_hints_refused,
                 NULL);
    qos_add_test("rw-atomic-split-write", "femu", femu_test_rw_atomic_split,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"write",
        .edge.extra_device_opts =
            "id=rwa,sgl=on,nlbaf=8,lba_index=7,multipoller_enabled=1,"
            "poller_ratio=1"
    });
    qos_add_test("rw-atomic-split-copy", "femu", femu_test_rw_atomic_split,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"copy",
        .edge.extra_device_opts =
            "id=rwa,sgl=on,nlbaf=8,lba_index=7,multipoller_enabled=1,"
            "poller_ratio=1"
    });
    qos_add_test("fused-cw-nossd", "femu", femu_test_fused_cw,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "fused_cw=on"
    });
    qos_add_test("fused-cw-bbssd", "femu", femu_test_fused_cw,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,fused_cw=on"
    });
    qos_add_test("fused-cw-refused", "femu", femu_test_fused_cw_refused,
                 NULL);
    qos_add_test("fused-cw-life", "femu", femu_test_fused_life,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=fcl,femu_mode=1,devsz_mb=8,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,fused_cw=on,sanitize_ops=on,sanitize_ms=300"
    });
    qos_add_test("fused-cw-lock", "femu", femu_test_fused_lock,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=rwa,multipoller_enabled=1,poller_ratio=1,fused_cw=on"
    });
    qos_add_test("rw-atomic-wu", "femu", femu_test_rw_atomic_wu,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=rwa,sgl=on,nlbaf=8,lba_index=7,multipoller_enabled=1,"
            "poller_ratio=1,oncs=0x19f"
    });
    /* one LUN and plane; a 200 ms program against a 40 us read */
    qos_add_test("pe-suspend-bbssd-off", "femu", femu_test_pe_suspend,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=4,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,nchs=1,"
            "pg_wr_lat=200000000,pg_rd_lat=40000,tsusp_ns=10000"
    });
    qos_add_test("pe-suspend-bbssd-on", "femu", femu_test_pe_suspend,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"on",
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=4,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,nchs=1,"
            "pg_wr_lat=200000000,pg_rd_lat=40000,tsusp_ns=10000,pe_suspend=1"
    });
    /* the same LUN with a write buffer; a Flush and a read in one ring */
    qos_add_test("pe-suspend-flush-off", "femu", femu_test_pe_suspend_flush,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,nchs=1,"
            "pg_wr_lat=200000000,pg_rd_lat=20000000,tsusp_ns=10000,"
            "buffer_size=16"
    });
    qos_add_test("pe-suspend-flush-on", "femu", femu_test_pe_suspend_flush,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"on",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,nchs=1,"
            "pg_wr_lat=200000000,pg_rd_lat=20000000,tsusp_ns=10000,"
            "pe_suspend=1,buffer_size=16"
    });
    qos_add_test("pe-suspend-flush-fua", "femu",
                 femu_test_pe_suspend_flush_fua,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,nchs=1,"
            "pg_wr_lat=200000000,pg_rd_lat=20000000,tsusp_ns=10000,"
            "pe_suspend=1,buffer_size=16"
    });
    qos_add_test("die-parity-waf", "femu", femu_test_die_parity,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"waf",
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=40,pls_per_lun=1,luns_per_ch=1,nchs=2,"
            "die_parity=1"
    });
    qos_add_test("die-parity-degraded", "femu", femu_test_die_parity,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"degraded",
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=40,pls_per_lun=1,luns_per_ch=1,nchs=3,"
            "pg_rd_lat=100000000,die_parity=1,parity_xor_ns=50000000,"
            "failed_die=1"
    });
    qos_add_test("rain-line", "femu", femu_test_rain,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"line",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=8,luns_per_ch=2,nchs=2,rain_parity=1,"
            "blks_per_pl=40,pls_per_lun=1"
    });
    qos_add_test("rain-pf", "femu", femu_test_rain,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"pf",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=8,luns_per_ch=2,nchs=2,rain_parity=1,"
            "blks_per_pl=40,pls_per_lun=2,plane_first=1"
    });
    qos_add_test("rain-gc", "femu", femu_test_rain,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"gc",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=8,luns_per_ch=2,nchs=2,rain_parity=1,"
            "blks_per_pl=16,pls_per_lun=1"
    });
    qos_add_test("rain-fail-start", "femu", femu_test_rain_fail,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"start",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=8,luns_per_ch=2,nchs=2,rain_parity=1,"
            "blks_per_pl=40,pls_per_lun=1,failed_die=1"
    });
    qos_add_test("rain-fail-first", "femu", femu_test_rain_fail,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"first",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=8,luns_per_ch=2,nchs=2,rain_parity=1,"
            "blks_per_pl=42,pls_per_lun=1,failed_die=0"
    });
    qos_add_test("rain-fail-partial", "femu", femu_test_rain_fail,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"partial",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=8,luns_per_ch=2,nchs=2,rain_parity=1,"
            "blks_per_pl=46,pls_per_lun=1"
    });
    qos_add_test("rain-fail-refuse", "femu", femu_test_rain_fail,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"refuse",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=8,luns_per_ch=2,nchs=2,rain_parity=1,"
            "blks_per_pl=48,pls_per_lun=1,gc_thres_pcent_high=100"
    });
    qos_add_test("rain-fail-run", "femu", femu_test_rain_fail,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"run",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=8,luns_per_ch=2,nchs=2,rain_parity=1,"
            "blks_per_pl=44,pls_per_lun=1"
    });
    qos_add_test("rain-erase-failed", "femu", femu_test_rain_wear,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=8,luns_per_ch=2,nchs=2,rain_parity=1,"
            "blks_per_pl=44,pls_per_lun=1"
    });
    qos_add_test("rain-wear-erase", "femu", femu_test_rain_wear,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"wear",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=8,luns_per_ch=2,nchs=2,rain_parity=1,"
            "blks_per_pl=44,pls_per_lun=1,blk_pe_limit=6,eol_read_only=off"
    });
    qos_add_test("rain-wear-spare", "femu", femu_test_rain_wear_spare,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=8,luns_per_ch=2,nchs=2,pls_per_lun=1,"
            "blks_per_pl=64,rain_parity=1,blk_pe_limit=1000,mdts=4,"
            "op_pcent=0,mpsmin=0,gc_frontier=off,gc_thres_pcent_high=78"
    });
    qos_add_test("rain-wear-eol", "femu", femu_test_rain_wear_eol,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=8,luns_per_ch=2,nchs=2,pls_per_lun=1,"
            "blks_per_pl=64,rain_parity=1,blk_pe_limit=20,mdts=4,"
            "blk_pe_spread=50,blk_pe_seed=3,"
            "op_pcent=0,mpsmin=0,gc_frontier=off,gc_thres_pcent_high=78"
    });
    qos_add_test("rain-fifo-fit", "femu", femu_test_rain_fifo_fit,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "nchs=3,luns_per_ch=1,pls_per_lun=1,pgs_per_blk=8,"
            "blks_per_pl=40,rain_parity=1,gc_policy=fifo,"
            "gc_thres_pcent=95,gc_thres_pcent_high=95"
    });
    qos_add_test("rain-rebuild", "femu", femu_test_rain_rebuild,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=8,luns_per_ch=2,nchs=2,rain_parity=1,"
            "rain_rebuild=on,blks_per_pl=48,pls_per_lun=1"
    });
    qos_add_test("rain-seal2", "femu", femu_test_rain,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"seal2",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=8,luns_per_ch=2,nchs=2,rain_parity=1,"
            "blks_per_pl=40,pls_per_lun=2,plane_first=1,pd_open_read_limit=4"
    });
    qos_add_test("rain-seal5", "femu", femu_test_rain,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"seal5",
        /* its own device line: qos reuses a QEMU for an equal one */
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=8,luns_per_ch=2,nchs=2,rain_parity=1,"
            "blks_per_pl=48,pls_per_lun=2,plane_first=1,pd_open_read_limit=4"
    });
    qos_add_test("rain-seal", "femu", femu_test_rain,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"seal",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=8,luns_per_ch=2,nchs=2,rain_parity=1,"
            "blks_per_pl=40,pls_per_lun=1,pd_open_read_limit=4"
    });
    qos_add_test("hmb", "femu", femu_test_hmb,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=hmb,devsz_mb=16,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=64,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,nchs=1,"
            "pg_rd_lat=50000000,mapping=dftl,x-cmt-slots=1,hmb_mb=1,"
            "hmb_ns=1000000"
    });
    qos_add_test("crypto-on", "femu", femu_test_crypto,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"on",
        .edge.extra_device_opts = "femu_mode=2,devsz_mb=16,oncs=8,"
                                  "crypto_mbps=1"
    });
    qos_add_test("crypto-off", "femu", femu_test_crypto,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts = "femu_mode=2,devsz_mb=16,oncs=8"
    });
    /* one LUN; a 100 ms read shows whether the array was used */
    qos_add_test("prog-pass2-off", "femu", femu_test_prog_pass2,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=40,pls_per_lun=1,luns_per_ch=1,nchs=1,"
            "pg_wr_lat=1000000,pg_rd_lat=100000000"
    });
    qos_add_test("prog-pass2-on", "femu", femu_test_prog_pass2,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"on",
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=40,pls_per_lun=1,luns_per_ch=1,nchs=1,"
            "pg_wr_lat=1000000,pg_rd_lat=100000000,prog_pass2_ns=50000000"
    });
    qos_add_test("prog-pass2-lag2", "femu", femu_test_prog_pass2,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"lag2",
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=40,pls_per_lun=1,luns_per_ch=1,nchs=1,"
            "pg_wr_lat=1000000,pg_rd_lat=100000000,prog_pass2_ns=50000000,"
            "prog_pass2_lag=2"
    });
    /* two 200 ms programs queued on one LUN, then a 40 us read */
    qos_add_test("read-prio-bbssd-off", "femu", femu_test_read_prio,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=4,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,nchs=1,"
            "pg_wr_lat=200000000,pg_rd_lat=40000"
    });
    qos_add_test("read-prio-bbssd-on", "femu", femu_test_read_prio,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"on",
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=4,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,nchs=1,"
            "pg_wr_lat=200000000,pg_rd_lat=40000,read_prio=1"
    });
    /* one suspension allowed, with a resume cost: the read still preempts */
    qos_add_test("pe-suspend-bbssd-limit", "femu", femu_test_pe_suspend,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"on",
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=4,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,nchs=1,"
            "pg_wr_lat=200000000,pg_rd_lat=40000,tsusp_ns=10000,pe_suspend=1,"
            "pe_suspend_max=1,tresume_ns=1000"
    });
    qos_add_test("pe-suspend-csd-off", "femu", femu_test_pe_suspend,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=4,fdm_size=16,secsz=512,secs_per_pg=8,pgs_per_blk=4,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,nchs=1,"
            "pg_wr_lat=200000000,pg_rd_lat=40000,tsusp_ns=10000"
    });
    qos_add_test("pe-suspend-csd-on", "femu", femu_test_pe_suspend,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"on",
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=4,fdm_size=16,secsz=512,secs_per_pg=8,pgs_per_blk=4,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,nchs=1,"
            "pg_wr_lat=200000000,pg_rd_lat=40000,tsusp_ns=10000,pe_suspend=1"
    });
    qos_add_test("pe-suspend-kv-off", "femu", femu_test_pe_suspend,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"kv-off",
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=5,secsz=512,secs_per_pg=8,pgs_per_blk=4,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,nchs=1,"
            "pg_wr_lat=200000000,pg_rd_lat=40000,tsusp_ns=10000"
    });
    qos_add_test("pe-suspend-kv-on", "femu", femu_test_pe_suspend,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"kv-on",
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=5,secsz=512,secs_per_pg=8,pgs_per_blk=4,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,nchs=1,"
            "pg_wr_lat=200000000,pg_rd_lat=40000,tsusp_ns=10000,pe_suspend=1"
    });
    qos_add_test("pe-suspend-zns-off", "femu", femu_test_pe_suspend,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts =
            "femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=1,zns_flash_type=1,zns_pg_wr_lat=200000000,"
            "zns_pg_rd_lat=40000,zns_tsusp_ns=10000"
    });
    qos_add_test("pe-suspend-zns-on", "femu", femu_test_pe_suspend,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"on",
        .edge.extra_device_opts =
            "femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=1,zns_flash_type=1,zns_pg_wr_lat=200000000,"
            "zns_pg_rd_lat=40000,zns_tsusp_ns=10000,zns_pe_suspend=1"
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
    qos_add_test("zns-fzr", "femu", femu_test_zns_fzr,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,"
            "zns_fzr_sec=2,zns_frl_sec=3"
    });
    qos_add_test("zns-fzr-cancel", "femu", femu_test_zns_fzr_cancel,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,"
            "zns_fzr_sec=2,zns_frl_sec=3"
    });
    qos_add_test("zns-fzr-reset", "femu", femu_test_zns_fzr_reset,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,zns_fzr_sec=2"
    });
    qos_add_test("zns-fzr-only", "femu", femu_test_zns_fzr_only,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,zns_fzr_sec=2"
    });
    qos_add_test("zns-finish-flush", "femu", femu_test_zns_finish_flush,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"host",
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,"
            "zns_pg_wr_lat=200000000,zns_pg_rd_lat=100000000"
    });
    qos_add_test("zns-finish-flush-ctlr", "femu", femu_test_zns_finish_flush,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"ctlr",
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,"
            "zns_pg_wr_lat=200000000,zns_pg_rd_lat=100000000,"
            "zns_fzr_sec=1,zns_frl_sec=1"
    });
    qos_add_test("zns-finish-flush-late", "femu", femu_test_zns_finish_flush,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"late",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,"
            "zns_num_lun=1,zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,"
            "zns_pg_wr_lat=200000000,zns_pg_rd_lat=100000000"
    });
    qos_add_test("zns-finish-flush-lostreset", "femu",
                 femu_test_zns_finish_flush, &(QOSGraphTestOptions) {
        .arg = (void *)"lostreset",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,"
            "zns_num_lun=1,zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,"
            "zns_pg_wr_lat=200000000,zns_pg_rd_lat=100000000"
    });
    qos_add_test("zns-finish-flush-refinish", "femu",
                 femu_test_zns_finish_flush, &(QOSGraphTestOptions) {
        .arg = (void *)"refinish",
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,"
            "zns_pg_wr_lat=200000000,zns_pg_rd_lat=100000000,"
            "zns_fzr_sec=1,zns_frl_sec=1"
    });
    qos_add_test("zns-finish-flush-heldreset", "femu",
                 femu_test_zns_finish_flush, &(QOSGraphTestOptions) {
        .arg = (void *)"heldreset",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,"
            "zns_num_lun=1,zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,"
            "zns_pg_wr_lat=200000000,zns_pg_rd_lat=100000000"
    });
    qos_add_test("zns-finish-flush-lateread", "femu",
                 femu_test_zns_finish_flush, &(QOSGraphTestOptions) {
        .arg = (void *)"lateread",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,"
            "zns_num_lun=1,zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,"
            "zns_pg_wr_lat=200000000,zns_pg_rd_lat=100000000"
    });
    qos_add_test("zns-finish-flush-twogen", "femu",
                 femu_test_zns_finish_flush, &(QOSGraphTestOptions) {
        .arg = (void *)"twogen",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,"
            "zns_num_lun=1,zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,"
            "zns_pg_wr_lat=200000000,zns_pg_rd_lat=100000000"
    });
    qos_add_test("zns-finish-flush-latefive", "femu",
                 femu_test_zns_finish_flush, &(QOSGraphTestOptions) {
        .arg = (void *)"latefive",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,"
            "zns_num_lun=1,zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,"
            "zns_pg_wr_lat=200000000,zns_pg_rd_lat=100000000"
    });
    qos_add_test("zns-finish-flush-fill", "femu", femu_test_zns_finish_flush,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"fill",
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,"
            "zns_zone_cap=32K,zns_pg_wr_lat=200000000,"
            "zns_pg_rd_lat=100000000"
    });
    qos_add_test("zns-finish-flush-fillfin", "femu",
                 femu_test_zns_finish_flush, &(QOSGraphTestOptions) {
        .arg = (void *)"fillfin",
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,"
            "zns_zone_cap=32K,zns_pg_wr_lat=200000000,"
            "zns_pg_rd_lat=100000000"
    });
    qos_add_test("zns-finish-flush-overrun", "femu",
                 femu_test_zns_finish_flush, &(QOSGraphTestOptions) {
        .arg = (void *)"overrun",
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,zns_num_wc=1"
    });
    qos_add_test("zns-finish-flush-tlcfill", "femu",
                 femu_test_zns_finish_flush, &(QOSGraphTestOptions) {
        .arg = (void *)"tlcfill",
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=2,zns_num_blk=32,zns_flash_type=3"
    });
    qos_add_test("zns-finish-flush-lostfill", "femu",
                 femu_test_zns_finish_flush, &(QOSGraphTestOptions) {
        .arg = (void *)"lostfill",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,"
            "zns_num_lun=1,zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,"
            "zns_zone_cap=32K,zns_pg_wr_lat=200000000,"
            "zns_pg_rd_lat=100000000"
    });
    qos_add_test("zns-finish-flush-zrwaend", "femu",
                 femu_test_zns_finish_flush, &(QOSGraphTestOptions) {
        .arg = (void *)"zrwaend",
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,"
            "zns_zone_cap=32K,zns_pg_wr_lat=200000000,"
            "zns_pg_rd_lat=100000000,"
            "zns_zrwa_size=64,zns_zrwafg_size=8,zns_zrwa_num=1"
    });
    qos_add_test("zns-finish-flush-drop", "femu", femu_test_zns_finish_flush,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"drop",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,"
            "zns_num_lun=1,zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,"
            "zns_pg_wr_lat=200000000,zns_pg_rd_lat=100000000"
    });
    qos_add_test("zns-fzr-off", "femu", femu_test_zns_fzr_off,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=2,zns_num_blk=32,zns_flash_type=1"
    });
    qos_add_test("zns-fzr-refused", "femu", femu_test_zns_fzr_refused,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=3,secsz=512"
    });
    qos_add_test("zns-rzr", "femu", femu_test_zns_rzr,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,"
            "zns_rzr_sec=2,zns_rrl_sec=4"
    });
    qos_add_test("zns-rzr-reset", "femu", femu_test_zns_rzr_reset,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,zns_rzr_sec=2"
    });
    qos_add_test("zns-rzr-reset-rrl", "femu", femu_test_zns_rzr_reset,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"rrl",
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,zns_rzr_sec=2,"
            "zns_rrl_sec=3"
    });
    qos_add_test("zns-rzr-origins", "femu", femu_test_zns_rzr_origins,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,zns_fzr_sec=2,"
            "zns_frl_sec=2,zns_rzr_sec=3,zns_rrl_sec=2"
    });
    qos_add_test("zns-rzr-off", "femu", femu_test_zns_rzr_off,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=2,zns_num_blk=32,zns_flash_type=1"
    });
    qos_add_test("zns-rzr-refused", "femu", femu_test_zns_rzr_refused,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=3,secsz=512"
    });
    qos_add_test("zns-wear", "femu", femu_test_zns_wear,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,pe_cycles_rated=1"
    });
    qos_add_test("zns-page-types-off", "femu", femu_test_zns_page_types,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=1,zns_num_blk=32,zns_num_wc=1,"
            "zns_blk_er_lat=1000,zns_pg_rd_lat=200000000,"
            "zns_pg_wr_lat=100000000"
    });
    qos_add_test("zns-page-types-on", "femu", femu_test_zns_page_types,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"on",
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=1,zns_num_blk=32,zns_num_wc=1,"
            "zns_blk_er_lat=1000,zns_pg_rd_lat=200000000,"
            "zns_pg_wr_lat=100000000,zns_page_types=1"
    });
    qos_add_test("zns-page-types-plc", "femu", femu_test_zns_page_types_plc,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "devsz_mb=32,femu_mode=3"
    });
    qos_add_test("zns-ecc", "femu", femu_test_zns_ecc,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=1,zns_num_blk=32,zns_num_wc=1,"
            "zns_pg_wr_lat=1000000,zns_blk_er_lat=1000,zns_pg_rd_lat=50000000,"
            "zns_ecc_step_ns=150000000"
    });
    qos_add_test("zns-lun-off", "femu", femu_test_zns_lun,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,"
            "zns_pg_wr_lat=300000000,zns_blk_er_lat=300000000"
    });
    qos_add_test("zns-lun-on", "femu", femu_test_zns_lun,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"on",
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,"
            "zns_pg_wr_lat=300000000,zns_blk_er_lat=300000000,"
            "zns_lun_contention=1"
    });
    qos_add_test("zns-reset-fill-off", "femu", femu_test_zns_reset_fill,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=2,"
            "zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,"
            "pe_cycles_rated=1,zns_pg_wr_lat=1000000,zns_blk_er_lat=300000000,"
            "zns_num_wc=1"
    });
    qos_add_test("zns-reset-fill-on", "femu", femu_test_zns_reset_fill,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"on",
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=2,"
            "zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,"
            "pe_cycles_rated=1,zns_pg_wr_lat=1000000,zns_blk_er_lat=300000000,"
            "zns_reset_by_fill=1,zns_num_wc=1"
    });
    qos_add_test("zns-reset-fill-lun", "femu", femu_test_zns_reset_fill,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"lun",
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=2,"
            "zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,"
            "pe_cycles_rated=1,zns_pg_wr_lat=1000000,zns_blk_er_lat=300000000,"
            "zns_reset_by_fill=1,zns_num_wc=1,zns_lun_contention=1"
    });
    qos_add_test("zns-lpz-one", "femu", femu_test_zns_lpz,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=8,femu_mode=3,secsz=512,zns_num_ch=2,zns_num_lun=2,"
            "zns_num_plane=1,zns_num_blk=2,zns_flash_type=1,"
            "pe_cycles_rated=1,zns_num_wc=1,zns_reset_by_fill=1,"
            "zns_chnls_per_zone=1,zns_luns_per_zone=1"
    });
    qos_add_test("zns-order-ch", "femu", femu_test_zns_order,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"ch",
        .edge.extra_device_opts =
            "devsz_mb=8,femu_mode=3,secsz=512,zns_num_ch=2,zns_num_lun=2,"
            "zns_num_plane=1,zns_num_blk=8,zns_flash_type=1,zns_num_wc=1,"
            "zns_pg_xfer_lat=400000000"
    });
    qos_add_test("zns-order-lun", "femu", femu_test_zns_order,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"lun",
        .edge.extra_device_opts =
            "devsz_mb=8,femu_mode=3,secsz=512,zns_num_ch=2,zns_num_lun=2,"
            "zns_num_plane=1,zns_num_blk=8,zns_flash_type=1,zns_num_wc=1,"
            "zns_pg_xfer_lat=400000000,zns_zone_order=lun"
    });
    qos_add_test("zns-lpz-refused", "femu", femu_test_zns_lpz_refused, NULL);
    qos_add_test("zns-cache-cap", "femu", femu_test_zns_cache_cap,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=8,femu_mode=3,secsz=512,zns_num_ch=2,zns_num_lun=1,"
            "zns_num_plane=1,zns_num_blk=2,zns_flash_type=1,zns_num_wc=1,"
            "zns_chnls_per_zone=1,zns_pg_wr_lat=300000000"
    });
    qos_add_test("zns-cache-cap-lun", "femu", femu_test_zns_cache_cap,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=8,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=2,"
            "zns_num_plane=1,zns_num_blk=2,zns_flash_type=1,zns_num_wc=1,"
            "zns_luns_per_zone=1,zns_pg_wr_lat=300000000"
    });
    qos_add_test("zns-flush-plane", "femu", femu_test_zns_flush_plane,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=2,zns_num_blk=32,zns_flash_type=1,"
            "zns_pg_rd_lat=2000000"
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
    qos_add_test("gc-frontier-placement", "femu",
                 femu_test_gc_frontier_placement,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=trace,femu_mode=1,devsz_mb=4,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,gc_thres_pcent=95,gc_thres_pcent_high=95,"
            "gc_frontier=on" });
    qos_add_test("gc-frontier-read-reclaim", "femu",
                 femu_test_gc_frontier_reclaim,
                 &(QOSGraphTestOptions) { .arg = (void *)"rr",
        .edge.extra_device_opts =
            "id=trace,femu_mode=1,devsz_mb=4,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,gc_thres_pcent=95,gc_thres_pcent_high=95,"
            "read_reclaim_limit=4,gc_frontier=on" });
    qos_add_test("gc-frontier-open-reclaim", "femu",
                 femu_test_gc_frontier_reclaim,
                 &(QOSGraphTestOptions) { .arg = (void *)"open",
        .edge.extra_device_opts =
            "id=trace,femu_mode=1,devsz_mb=4,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,gc_thres_pcent=95,gc_thres_pcent_high=95,"
            "pd_open_read_limit=4,gc_frontier=on" });
    qos_add_test("gc-frontier-refused", "femu", femu_test_gc_frontier_refused,
                 NULL);
    qos_add_test("gc-frontier-skew", "femu", femu_test_gc_frontier_skew, NULL);
    {
        static const char *const maint[][2] = {
            { "refresh", ",retention_limit_sec=1,age_scale=4,maint_idle=on" },
            { "reclaim", ",read_reclaim_limit=4,maint_idle=on" },
            { "off", ",retention_limit_sec=1,age_scale=4" },
        };

        for (size_t i = 0; i < ARRAY_SIZE(maint); i++) {
            g_autofree char *name = g_strdup_printf("maint-idle-%s",
                                                    maint[i][0]);
            g_autofree char *dev_opts = g_strdup_printf(
                "id=gc-test,femu_mode=1,devsz_mb=3,secsz=512,"
                "secs_per_pg=8,pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,"
                "luns_per_ch=1,nchs=1,gc_idle_ms=5%s", maint[i][1]);

            qos_add_test(name, "femu", femu_test_maint_idle,
                         &(QOSGraphTestOptions) {
                .edge.extra_device_opts = dev_opts,
                .arg = (void *)maint[i][0],
            });
        }
    }
    qos_add_test("maint-idle-space", "femu", femu_test_maint_idle_space,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,femu_mode=1,devsz_mb=3,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=56,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,gc_thres_pcent=90,gc_thres_pcent_high=90,gc_idle_ms=5,"
            "read_reclaim_limit=4,maint_idle=on" });
    qos_add_test("maint-idle-burst", "femu", femu_test_maint_idle_burst,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,femu_mode=1,devsz_mb=3,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,gc_idle_ms=5,retention_limit_sec=1,read_reclaim_limit=4,"
            "maint_idle=on" });
    qos_add_test("maint-idle-refused", "femu", femu_test_maint_idle_refused,
                 NULL);
    qos_add_test("gc-idle-recover", "femu", femu_test_gc_idle_recover,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,femu_mode=1,devsz_mb=3,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,gc_thres_pcent=90,gc_thres_pcent_high=95"
            ",gc_idle_ms=5,gc_idle_pcent=75" });
    qos_add_test("gc-idle-fence", "femu", femu_test_gc_idle_fence,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,femu_mode=1,devsz_mb=3,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,gc_thres_pcent=90,gc_thres_pcent_high=95"
            ",gc_idle_ms=3000,gc_idle_pcent=50" });
    qos_add_test("gc-idle-media", "femu", femu_test_gc_idle_media,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,femu_mode=1,devsz_mb=3,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,gc_thres_pcent=90,gc_thres_pcent_high=95"
            ",gc_idle_ms=1,gc_idle_pcent=50,blk_er_lat=2000000000" });
    qos_add_test("gc-idle-sweep", "femu", femu_test_gc_idle_sweep,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,femu_mode=1,devsz_mb=3,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,gc_thres_pcent=90,gc_thres_pcent_high=95"
            ",gc_idle_ms=1,gc_idle_pcent=50" });
    qos_add_test("gc-idle-off", "femu", femu_test_gc_idle_off,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,femu_mode=1,devsz_mb=3,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,gc_thres_pcent=90,gc_thres_pcent_high=95" });
    qos_add_test("gc-idle-refused", "femu", femu_test_gc_idle_refused, NULL);
    {
        static const char *const gbi[] = { "0", "50", "100" };

        for (size_t i = 0; i < ARRAY_SIZE(gbi); i++) {
            g_autofree char *name = g_strdup_printf("gc-bg-invalid-%s",
                                                    gbi[i]);
            g_autofree char *dev_opts = g_strdup_printf(
                "id=trace,femu_mode=1,devsz_mb=3,secsz=512,secs_per_pg=8,"
                "pgs_per_blk=16,blks_per_pl=60,pls_per_lun=1,luns_per_ch=1,"
                "nchs=1,gc_bg_invalid_pcent=%s", gbi[i]);

            qos_add_test(name, "femu", femu_test_gc_bg_invalid,
                         &(QOSGraphTestOptions) {
                .edge.extra_device_opts = dev_opts,
                .arg = (void *)gbi[i],
            });
        }
        for (size_t i = 0; i < 2; i++) {
            g_autofree char *name = g_strdup_printf("fdp-gc-bg-invalid-%s",
                                                    gbi[i]);
            g_autofree char *dev_opts = g_strdup_printf(
                "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
                "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,"
                "nchs=2,gc_bg_invalid_pcent=%s,subsys=fdpsub", gbi[i]);

            qos_add_test(name, "femu", femu_test_fdp_gc_bg_invalid,
                         &(QOSGraphTestOptions) {
                .edge.extra_device_opts = dev_opts,
                .arg = (void *)gbi[i],
            });
        }
    }
    qos_add_test("gc-bg-invalid-refused", "femu",
                 femu_test_gc_bg_invalid_refused, NULL);
    qos_add_test("rber-retry", "femu", femu_test_rber_scripted,
                 &(QOSGraphTestOptions) { .arg = (void *)"retry",
        .edge.extra_device_opts =
            "id=rber-test,femu_mode=1,devsz_mb=3,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,rber_ppb=1"
            ",pg_rd_lat=100000000" });
    qos_add_test("rber-soft", "femu", femu_test_rber_scripted,
                 &(QOSGraphTestOptions) { .arg = (void *)"soft",
        .edge.extra_device_opts =
            "id=rber-test,femu_mode=1,devsz_mb=3,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,rber_ppb=1"
            ",rr_steps=2,rr_soft_ns=10000000,pg_rd_lat=100000000" });
    qos_add_test("rber-limit-timing", "femu", femu_test_rber_scripted,
                 &(QOSGraphTestOptions) { .arg = (void *)"limit-timing",
        .edge.extra_device_opts =
            "id=rber-test,femu_mode=1,devsz_mb=3,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,rber_ppb=1,rber_timing_only=on"
            ",rr_steps=2,rr_soft_ns=10000000,pg_rd_lat=100000000" });
    qos_add_test("err-inject", "femu", femu_test_err_inject,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=err-test,femu_mode=1,devsz_mb=3,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,err_read_unc_ppm=250000,err_write_fail_ppm=250000"
    });
    qos_add_test("rber-limit", "femu", femu_test_rber_scripted,
                 &(QOSGraphTestOptions) { .arg = (void *)"limit",
        .edge.extra_device_opts =
            "id=rber-test,femu_mode=1,devsz_mb=3,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,rber_ppb=1"
            ",rr_steps=2,rr_soft_ns=10000000,pg_rd_lat=100000000" });
    qos_add_test("dram-hit-buffer-on", "femu", femu_test_dram_hit,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"buffer-on",
        .edge.extra_device_opts =
            "femu_mode=1,devsz_mb=3,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,nchs=1,"
            "pg_rd_lat=100000000,buffer_size=16,dram_hit_ns=20000000"
    });
    qos_add_test("dram-hit-buffer-off", "femu", femu_test_dram_hit,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"buffer-off",
        .edge.extra_device_opts =
            "femu_mode=1,devsz_mb=3,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,nchs=1,"
            "pg_rd_lat=100000000,buffer_size=16"
    });
    qos_add_test("dram-hit-cache-on", "femu", femu_test_dram_hit,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"cache-on",
        .edge.extra_device_opts =
            "femu_mode=1,devsz_mb=3,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,nchs=1,"
            "pg_rd_lat=100000000,read_cache_mb=1,dram_hit_ns=20000000"
    });
    qos_add_test("dram-hit-cache-off", "femu", femu_test_dram_hit,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"cache-off",
        .edge.extra_device_opts =
            "femu_mode=1,devsz_mb=3,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,nchs=1,"
            "pg_rd_lat=100000000,read_cache_mb=1"
    });
#define FEMU_GC_FW_GEO \
    "id=gc-fw,femu_mode=1,devsz_mb=3,secsz=512,secs_per_pg=8,pgs_per_blk=16," \
    "blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,nchs=1,pg_rd_lat=10000," \
    "pg_wr_lat=10000,blk_er_lat=100000"
    qos_add_test("gc-fw-on", "femu", femu_test_gc_fw,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"on",
        .edge.extra_device_opts = FEMU_GC_FW_GEO ",fw_gc_page_ns=5000000"
    });
    qos_add_test("gc-fw-off", "femu", femu_test_gc_fw,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts = FEMU_GC_FW_GEO
    });
    qos_add_test("gc-fw-copyback", "femu", femu_test_gc_fw,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"copyback",
        .edge.extra_device_opts =
            FEMU_GC_FW_GEO ",fw_gc_page_ns=5000000,gc_copyback=on"
    });
    qos_add_test("gc-fw-pace", "femu", femu_test_gc_fw,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"pace",
        .edge.extra_device_opts =
            FEMU_GC_FW_GEO ",fw_gc_page_ns=5000000,gc_pace=on"
    });
    qos_add_test("gc-fw-fdp", "femu", femu_test_gc_fw,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"fdp",
        .edge.extra_device_opts =
            "id=gc-fw,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub,fw_gc_page_ns=1000",
    });
    qos_add_test("gc-fw-refused", "femu", femu_test_gc_fw_refused, NULL);
    qos_add_test("rrl", "femu", femu_test_rrl,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=rber-test,femu_mode=1,devsz_mb=3,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,rber_ppb=1,rrl=on,read_cache_mb=1"
            ",rr_steps=2,rr_soft_ns=10000000,pg_rd_lat=100000000" });
    qos_add_test("rrl-no-rber", "femu", femu_test_rrl_no_rber,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1,rrl=on," FEMU_CAPS_GEO });
    qos_add_test("rrl-subsys-one", "femu", femu_test_rrl_subsys,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"one",
        .edge.extra_device_opts =
            "femu_mode=1,rrl=on,subsys=rrlsub," FEMU_CAPS_GEO,
        .before = femu_rrl_before,
    });
    qos_add_test("rrl-subsys-two", "femu", femu_test_rrl_subsys,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"two",
        .edge.extra_device_opts =
            "femu_mode=1,rrl=on,subsys=rrlsub," FEMU_CAPS_GEO,
        .before = femu_rrl_before,
    });
    qos_add_test("rrl-modes", "femu", femu_test_rrl_modes, NULL);
    qos_add_test("plm-identify", "femu", femu_test_plm_identify,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,rrl=on,plm=on,subsys=plmsub," FEMU_CAPS_GEO,
        .before = femu_plm_before,
    });
    qos_add_test("plm-identify-hints", "femu", femu_test_plm_identify,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"hints",
        .edge.extra_device_opts = "femu_mode=1,rrl=on,plm=on,perf_hints=on,"
            "subsys=plmsub," FEMU_CAPS_GEO,
        .before = femu_plm_before,
    });
    qos_add_test("plm-rrl", "femu", femu_test_plm_rrl,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,rrl=on,plm=on,subsys=plmsub," FEMU_CAPS_GEO,
        .before = femu_plm_before,
    });
    qos_add_test("plm-refused", "femu", femu_test_plm_refused,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,rrl=on,plm=on,subsys=plmsub," FEMU_CAPS_GEO,
        .before = femu_plm_before,
    });
    qos_add_test("plm-nsid", "femu", femu_test_plm_nsid,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=plmd,femu_mode=1,rrl=on,plm=on,subsys=plmsub," FEMU_CAPS_GEO,
        .before = femu_plm_before,
    });
    qos_add_test("plm-config", "femu", femu_test_plm_config,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=plmd,femu_mode=1,rrl=on,plm=on,subsys=plmsub," FEMU_CAPS_GEO,
        .before = femu_plm_before,
    });
    qos_add_test("plm-lpe0", "femu", femu_test_plm_lpe0,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=plmd,femu_mode=1,rrl=on,plm=on,subsys=plmsub," FEMU_CAPS_GEO,
        .before = femu_plm_before,
    });
    qos_add_test("plm-logs", "femu", femu_test_plm_logs,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=plmd,femu_mode=1,rrl=on,plm=on,subsys=plmsub,"
            "plm_dtwin_ms=2000,plm_dtwin_reads=4096,plm_ndwin_ms=3000,"
            "plm_ndwin_min_ms=500," FEMU_CAPS_GEO,
        .before = femu_plm_before,
    });
    qos_add_test("plm-reset", "femu", femu_test_plm_reset,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=plmd,femu_mode=1,rrl=on,plm=on,subsys=plmsub," FEMU_CAPS_GEO,
        .before = femu_plm_before,
    });
    qos_add_test("plm-no-pause", "femu", femu_test_plm_no_pause,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,femu_mode=1,devsz_mb=3,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,gc_thres_pcent=90,gc_thres_pcent_high=95"
            ",gc_idle_ms=1,gc_idle_pcent=50,rrl=on,plm=on,subsys=plmsub",
        .before = femu_plm_before,
    });
    qos_add_test("plm-golden-off", "femu", femu_test_plm_golden_off,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"plain",
        .edge.extra_device_opts = "femu_mode=1,subsys=plmsub," FEMU_CAPS_GEO,
        .before = femu_plm_before,
    });
    qos_add_test("plm-golden-off-rrl", "femu", femu_test_plm_golden_off,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"rrl",
        .edge.extra_device_opts =
            "femu_mode=1,rrl=on,subsys=plmsub," FEMU_CAPS_GEO,
        .before = femu_plm_before,
    });
    qos_add_test("rber-clean", "femu", femu_test_rber_scripted,
                 &(QOSGraphTestOptions) { .arg = (void *)"clean",
        .edge.extra_device_opts =
            "id=rber-test,femu_mode=1,devsz_mb=3,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,rber_ppb=1"
            ",pg_rd_lat=100000000" });
    qos_add_test("rber-disturb", "femu", femu_test_rber_disturb,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=rber-test,femu_mode=1,devsz_mb=3,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,rber_ppb=1"
            ",rber_read_double=1,ecc_cw_bytes=1024,ecc_hard_bits=40,"
            "ecc_soft_bits=72,rr_gain=2,rr_floor_pct=10,rr_soft_senses=3,"
            "rr_soft_ns=20000,rber_seed=7,rber_pe_double=0,"
            "rber_age_double_sec=0" });
    qos_add_test("rber-refused", "femu", femu_test_rber_refused, NULL);
    qos_add_test("rber-off", "femu", femu_test_rber_off,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=rber-test,femu_mode=1,devsz_mb=3,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,rber_ppb=0" });
    qos_add_test("rber-age", "femu", femu_test_rber_age,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=rber-test,femu_mode=1,devsz_mb=3,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,rber_ppb=1,pd_open_age=on,age_scale=1000000,"
            "rber_age_double_sec=1000" });
    qos_add_test("rber-wear", "femu", femu_test_rber_wear,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=rber-test,femu_mode=1,devsz_mb=3,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,rber_ppb=2000000,rber_pe_double=1" });
    qos_add_test("link-write-first", "femu", femu_test_link_write_order,
                 &(QOSGraphTestOptions) { .arg = (void *)"first",
        .edge.extra_device_opts =
            "id=link,femu_mode=1,devsz_mb=3,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,pcie_bandwidth_mbps=1" });
    qos_add_test("link-write-old", "femu", femu_test_link_write_order,
                 &(QOSGraphTestOptions) { .arg = (void *)"old",
        .edge.extra_device_opts =
            "id=link,femu_mode=1,devsz_mb=3,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,pcie_bandwidth_mbps=1"
            ",pcie_write_first=off" });
    qos_add_test("identify-fmt", "femu", femu_test_identify_fmt,
                 &(QOSGraphTestOptions) { .arg = (void *)"plain",
        .edge.extra_device_opts = "id=fmt21a,ns_mgmt=on" });
    qos_add_test("identify-fmt-meta", "femu", femu_test_identify_fmt,
                 &(QOSGraphTestOptions) { .arg = (void *)"meta",
        .edge.extra_device_opts = "id=fmt21b,ns_mgmt=on,meta=8,mc=3,pi=on" });
    qos_add_test("identify-fmt-bbssd", "femu", femu_test_identify_fmt,
                 &(QOSGraphTestOptions) { .arg = (void *)"plain",
        .edge.extra_device_opts =
            "id=fmt21c,femu_mode=1,ns_mgmt=on,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,"
            "nchs=4" });
    qos_add_test("identify-fmt-empty", "femu", femu_test_identify_fmt,
                 &(QOSGraphTestOptions) { .arg = (void *)"empty",
        .edge.extra_device_opts = "id=fmt21d,ns_mgmt=on" });
    qos_add_test("identify-fmt-off", "femu", femu_test_identify_fmt_off,
                 NULL);
    qos_add_test("kv-identify-fmt", "femu", femu_test_kv_identify_fmt,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=kvfmt21,femu_mode=5,namespaces=2,namespace_sizes=24M,,8M,"
            "devsz_mb=32" });
    /* a device line of its own each, so the error ring starts empty */
    qos_add_test("error-log-fields-nvm", "femu", femu_test_error_log_fields,
                 &(QOSGraphTestOptions) { .arg = (void *)"nvm",
        .edge.extra_device_opts = "id=err21nvm" });
    qos_add_test("error-log-fields-zns", "femu", femu_test_error_log_fields,
                 &(QOSGraphTestOptions) { .arg = (void *)"zns",
        .edge.extra_device_opts = "id=err21zns,femu_mode=3,devsz_mb=64" });
    qos_add_test("error-log-fields-admin", "femu", femu_test_error_log_fields,
                 &(QOSGraphTestOptions) { .arg = (void *)"admin",
        .edge.extra_device_opts = "id=err21adm,ns_mgmt=on" });
    qos_add_test("error-log-fields-ocssd", "femu", femu_test_error_log_fields,
                 &(QOSGraphTestOptions) { .arg = (void *)"ocssd",
        .edge.extra_device_opts = "id=err21oc,femu_mode=0" });
    qos_add_test("dpc-first-refused", "femu", femu_test_dpc_first_refused,
                 NULL);
    qos_add_test("format-pi-needs-metadata", "femu",
                 femu_test_format_pi_needs_metadata,
                 &(QOSGraphTestOptions) {
        /* Type 1, last eight bytes, is advertised; no format has metadata */
        .edge.extra_device_opts = "dpc=0x11"
    });
    qos_add_test("format", "femu", femu_test_format,
                 &(QOSGraphTestOptions) {
        /* start with 4 KiB blocks so a format to 512 grows the block count */
        .edge.extra_device_opts = "lba_index=3"
    });
    qos_add_test("log-pages", "femu", femu_test_log_pages, NULL);
    qos_add_test("spare-at-threshold", "femu", femu_test_spare_threshold,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"80",
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=4,"
            "blks_per_pl=100,pls_per_lun=1,luns_per_ch=1,nchs=1,"
            "nand_bad_blocks=80,subsys=fdpsub"
    });
    qos_add_test("spare-below-threshold", "femu", femu_test_spare_threshold,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"81",
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=4,"
            "blks_per_pl=100,pls_per_lun=1,luns_per_ch=1,nchs=1,"
            "nand_bad_blocks=81,subsys=fdpsub"
    });
    qos_add_test("get-lba-status", "femu", femu_test_get_lba_status,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "oncs=0x19f"
    });
    qos_add_test("lsi-feature", "femu", femu_test_lsi_feature, NULL);
    qos_add_test("lsi-log", "femu", femu_test_lsi_log,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "oncs=0x19f"
    });
    qos_add_test("lsi-many", "femu", femu_test_lsi_many,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "oncs=0x19f"
    });
    qos_add_test("lsi-alert", "femu", femu_test_lsi_alert,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = FEMU_LSI_DEV
    });
    qos_add_test("lsi-poll", "femu", femu_test_lsi_poll,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = FEMU_LSI_DEV
    });
    qos_add_test("lsi-component", "femu", femu_test_lsi_component,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = FEMU_LSI_DEV
    });
    qos_add_test("lsi-qfull", "femu", femu_test_lsi_qfull,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = FEMU_LSI_DEV
    });
    qos_add_test("lsi-disable", "femu", femu_test_lsi_disable,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = FEMU_LSI_DEV
    });
    qos_add_test("lsi-reset", "femu", femu_test_lsi_reset,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = FEMU_LSI_DEV
    });
    qos_add_test("lsi-wrap", "femu", femu_test_lsi_wrap,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = FEMU_LSI_DEV
    });
    qos_add_test("lsi-wu-race", "femu", femu_test_lsi_wu_race,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = FEMU_LSI_DEV ",multipoller_enabled=1"
    });
    qos_add_test("lsi-publish", "femu", femu_test_lsi_publish,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = FEMU_LSI_DEV
    });
    qos_add_test("lsi-format", "femu", femu_test_lsi_format,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = FEMU_LSI_DEV
    });
    qos_add_test("lsi-sanitize", "femu", femu_test_lsi_sanitize,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = FEMU_LSI_DEV ",sanitize_ops=on"
    });
    qos_add_test("lsi-recreate", "femu", femu_test_lsi_recreate,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = FEMU_LSI_DEV ",ns_mgmt=on,femu_mode=1,"
            "secsz=512,secs_per_pg=8,pgs_per_blk=16,blks_per_pl=80,"
            "pls_per_lun=1,luns_per_ch=4,nchs=4"
    });
    qos_add_test("lsi-persist", "femu", femu_test_lsi_persist, NULL);
    qos_add_test("lsi-persist-pub", "femu", femu_test_lsi_persist_pub, NULL);
    qos_add_test("lsi-persist-live", "femu", femu_test_lsi_persist_live,
                 NULL);
    qos_add_test("lsi-gls-race", "femu", femu_test_lsi_gls_race,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = FEMU_LSI_DEV
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
    qos_add_test("persist-bbssd", "femu", femu_test_persist, NULL);
    qos_add_test("persist-ftl", "femu", femu_test_persist_ftl, NULL);
    qos_add_test("precon-base", "femu", femu_test_precon,
                 &(QOSGraphTestOptions) { .arg = (void *)&femu_precon_base });
    qos_add_test("precon-seq", "femu", femu_test_precon,
                 &(QOSGraphTestOptions) { .arg = (void *)&femu_precon_seq });
    qos_add_test("precon-policy", "femu", femu_test_precon,
                 &(QOSGraphTestOptions) {
        .arg = (void *)&femu_precon_policy });
    qos_add_test("precon-buffer", "femu", femu_test_precon,
                 &(QOSGraphTestOptions) {
        .arg = (void *)&femu_precon_buffer });
    qos_add_test("precon-wear", "femu", femu_test_precon,
                 &(QOSGraphTestOptions) { .arg = (void *)&femu_precon_wear });
    qos_add_test("precon-pace", "femu", femu_test_precon,
                 &(QOSGraphTestOptions) { .arg = (void *)&femu_precon_pace });
    qos_add_test("precon-control-break", "femu", femu_test_precon,
                 &(QOSGraphTestOptions) {
        .arg = (void *)&femu_precon_break });
    qos_add_test("precon-control-short", "femu", femu_test_precon,
                 &(QOSGraphTestOptions) {
        .arg = (void *)&femu_precon_short });
    qos_add_test("precon-refused", "femu", femu_test_precon_refused, NULL);
    qos_add_test("precon-persist", "femu", femu_test_precon_persist, NULL);
    qos_add_test("persist-aging-wear", "femu", femu_test_persist_aging,
                 &(QOSGraphTestOptions) { .arg = (void *)"wear" });
    qos_add_test("persist-aging-eol", "femu", femu_test_persist_aging,
                 &(QOSGraphTestOptions) { .arg = (void *)"eol" });
    qos_add_test("persist-aging-rber", "femu", femu_test_persist_aging,
                 &(QOSGraphTestOptions) { .arg = (void *)"rber" });
    qos_add_test("persist-aging-files", "femu", femu_test_persist_aging_files,
                 NULL);
    qos_add_test("persist-retention", "femu", femu_test_persist_retention,
                 NULL);
    qos_add_test("die-slow", "femu", femu_test_die_slow,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=ds,femu_mode=1,devsz_mb=64,pg_rd_lat=20000000,die_slow=on",
    });
    qos_add_test("die-slow-off", "femu", femu_test_die_slow_off,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=ds,femu_mode=1,devsz_mb=64",
    });
    qos_add_test("die-slow-events", "femu", femu_test_die_slow_events, NULL);
    qos_add_test("die-stats", "femu", femu_test_die_stats,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=dst,femu_mode=1,devsz_mb=64,pg_rd_lat=20000000,die_stats=on",
    });
    qos_add_test("die-stats-refused", "femu", femu_test_die_stats_refused,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=dso,femu_mode=1,devsz_mb=64",
    });
    qos_add_test("ready-delay", "femu", femu_test_ready_delay,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=rdy,femu_mode=1,devsz_mb=16,ready_ms=200",
    });
    qos_add_test("recovery-delay", "femu", femu_test_recovery_delay,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=rec,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=1,buffer_size=16,vwc=1,power_loss=on,"
            "ready_ms=50,recovery_ms=300",
    });
    qos_add_test("ready-sysreset", "femu", femu_test_ready_sysreset, NULL);
    qos_add_test("arb-burst", "femu", femu_test_arb_burst, NULL);
    for (size_t i = 0; i < ARRAY_SIZE(femu_wrr_cases); i++) {
        g_autofree char *name = g_strdup_printf("wrr-%zu", i);

        qos_add_test(name, "femu", femu_test_wrr,
                     &(QOSGraphTestOptions) {
            .arg = (void *)&femu_wrr_cases[i],
        });
    }
    qos_add_test("wrr-refused", "femu", femu_test_wrr_refused, NULL);
    qos_add_test("wrr-blocked", "femu", femu_test_wrr_blocked, NULL);
    qos_add_test("ready-bad", "femu", femu_test_ready_bad,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=rdb0,femu_mode=1,devsz_mb=16",
    });
    qos_add_test("events", "femu", femu_test_events, NULL);
    qos_add_test("events-seed", "femu", femu_test_events_seed, NULL);
    qos_add_test("events-bad", "femu", femu_test_events_bad, NULL);
    qos_add_test("events-timer", "femu", femu_test_events_timer, NULL);
    qos_add_test("io-trace", "femu", femu_test_io_trace, NULL);
    qos_add_test("io-trace-append", "femu", femu_test_io_trace_append, NULL);
    qos_add_test("mode-names", "femu", femu_test_mode_names,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=mode-test,mode=bbssd,devsz_mb=16"
    });
    qos_add_test("checkpoint", "femu", femu_test_checkpoint, NULL);
    qos_add_test("checkpoint-reuse", "femu", femu_test_checkpoint_reuse,
                 NULL);
    qos_add_test("checkpoint-ro-dir", "femu", femu_test_checkpoint_ro_dir,
                 NULL);
    qos_add_test("zns-slc-zones", "femu", femu_test_zns_slc_zones,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=2,zns_num_blk=32,zns_flash_type=4,"
            "zns_slc_zones=2,zns_pg_rd_lat=100000000"
    });
    qos_add_test("zns-slc-zones-types", "femu", femu_test_zns_slc_zones,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"types",
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=2,zns_num_blk=32,zns_flash_type=4,"
            "zns_slc_zones=2,zns_pg_rd_lat=100000000,zns_page_types=1"
    });
    qos_add_test("checkpoint-reuse-ftl", "femu",
                 femu_test_checkpoint_reuse_ftl, NULL);
    qos_add_test("save-data-background", "femu", femu_test_save_background,
                 NULL);
    qos_add_test("save-data-background-end", "femu",
                 femu_test_save_background_end, NULL);
    qos_add_test("persist-nossd", "femu", femu_test_persist,
                 &(QOSGraphTestOptions) { .arg = GINT_TO_POINTER(1) });
    qos_add_test("pel-file-media", "femu", femu_test_pel_file,
                 &(QOSGraphTestOptions) { .arg = GINT_TO_POINTER(1) });
    qos_add_test("pel-set-feature", "femu", femu_test_pel_set_feature, NULL);
    qos_add_test("pel-set-feature-buffer", "femu", femu_test_pel_set_feature,
                 &(QOSGraphTestOptions) { .arg = GUINT_TO_POINTER(1) });
    qos_add_test("persistent-event-log-events", "femu", femu_test_pel_events,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "oncs=0x86"
    });
    qos_add_test("resv", "femu", femu_test_resv,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "reservations=on,femu_mode=1,devsz_mb=64",
    });
    qos_add_test("resv-off", "femu", femu_test_resv_off, NULL);
    qos_add_test("lockdown", "femu", femu_test_lockdown,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "lockdown=on",
    });
    qos_add_test("lockdown-off", "femu", femu_test_lockdown_off, NULL);
    qos_add_test("opal-transport", "femu", femu_test_opal,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "x-opal=on",
    });
    qos_add_test("opal-session", "femu", femu_test_opal_session,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "x-opal=on,serial=opal-session",
    });
    qos_add_test("opal-locking", "femu", femu_test_opal_locking,
                 &(QOSGraphTestOptions){
        .edge.extra_device_opts = "x-opal=on,serial=opal-lock",
    });
    qos_add_test("opal-shadow", "femu", femu_test_opal_shadow, NULL);
    qos_add_test("opal-crypto-format", "femu", femu_test_opal_crypto_format,
                 NULL);
    qos_add_test("format-crypto-ns", "femu", femu_test_format_crypto_ns,
                 NULL);
    qos_add_test("opal-mpa", "femu", femu_test_opal_mpa, NULL);
    qos_add_test("opal-off", "femu", femu_test_opal_off, NULL);
    qos_add_test("opal-refused", "femu", femu_test_opal_refused, NULL);
    qos_add_test("telemetry-ctrl", "femu", femu_test_telemetry_ctrl,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=telc,femu_mode=1,devsz_mb=64",
    });
    qos_add_test("telemetry", "femu", femu_test_telemetry,
                 &(QOSGraphTestOptions) {
        /* the captured counters come from the FTL, which NoSSD has none of */
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4"
    });
    qos_add_test("telemetry-da4", "femu", femu_test_telemetry_da4,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "telemetry_da4=on,id=telc"
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
    /* 19 lines of 16 pages: the forced watermark is zero free lines */
    qos_add_test("wear-off", "femu", femu_test_wear,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"0 0 0 100 0",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2"
    });
    qos_add_test("wear-limit", "femu", femu_test_wear,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"52 4 1 0 103",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=75,"
            "eol_read_only=off"
    });
    qos_add_test("wear-spread", "femu", femu_test_wear,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"72 1 1 0 186",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=60,blk_pe_spread=50,blk_pe_seed=7,"
            "eol_read_only=off"
    });
    /* 40 lines, a floor of 18: lines retire in a row until the guard holds */
    qos_add_test("wear-retire", "femu", femu_test_wear,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"80 80 20 0 255",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=8,"
            "eol_read_only=off"
    });
    /* 8 spare lines replace worn-out blocks before any line retires */
    qos_add_test("wear-spare", "femu", femu_test_wear,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"80 80 12 0 255",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=8,spare_lines=8,"
            "eol_read_only=off"
    });
    /* spread limits: planes run out of spares at different times */
    qos_add_test("wear-spare-spread", "femu", femu_test_wear,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"0 13 0 37 37",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=40,blk_pe_spread=60,blk_pe_seed=3,spare_lines=8,"
            "eol_read_only=off"
    });
    /* some planes run out of spares while others have them left */
    qos_add_test("wear-spare-uneven", "femu", femu_test_wear,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"0 31 5 0 52",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=30,blk_pe_spread=60,blk_pe_seed=3,spare_lines=8,"
            "eol_read_only=off"
    });
    qos_add_test("wear-aer-spare", "femu", femu_test_wear_aer,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"0x1",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=75,"
            "eol_read_only=off"
    });
    qos_add_test("wear-aer-reliability", "femu", femu_test_wear_aer,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"0x4",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=75,"
            "eol_read_only=off"
    });
    qos_add_test("wear-aer-off", "femu", femu_test_wear_aer,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"0x0",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=75,"
            "eol_read_only=off"
    });
    /* CSD runs its NVM commands through the same line FTL */
    qos_add_test("wear-csd", "femu", femu_test_wear,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"52 4 1 0 103",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=4,fdm_size=16,secsz=512,"
            "secs_per_pg=8,pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,"
            "luns_per_ch=2,nchs=2,blk_pe_limit=75,"
            "eol_read_only=off"
    });
#define FEMU_WEAR_FDP_GEO \
    "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8," \
    "pgs_per_blk=4,pls_per_lun=1,luns_per_ch=2,nchs=2,eol_read_only=off,"
    /*
     * 40 units of 16 pages. The namespace fills 16, four handles keep 8,
     * forced collection 2, plus one: a floor of 27. 13 units retire, then
     * worn-out blocks stay in service.
     */
    qos_add_test("wear-fdp-retire", "femu", femu_test_wear_fdp,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"96 52 13 0 235",
        .edge.extra_device_opts = FEMU_WEAR_FDP_GEO
            "blks_per_pl=40,blk_pe_limit=8,subsys=fdpsub"
    });
    /*
     * One unit kept free for forced collection, so a relocation often
     * takes the last free unit: the victim must then go back to the free
     * list, not retire.
     */
    qos_add_test("wear-fdp-tight", "femu", femu_test_wear_fdp,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"104 56 14 0 224 handles",
        .edge.extra_device_opts = FEMU_WEAR_FDP_GEO
            "blks_per_pl=40,blk_pe_limit=8,gc_thres_pcent=99,"
            "gc_thres_pcent_high=99,subsys=fdpsub"
    });
    /* 28 units, a floor of 26: two units retire, then blocks stay */
    qos_add_test("wear-fdp-limit", "femu", femu_test_wear_fdp,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"92 8 2 0 136",
        .edge.extra_device_opts = FEMU_WEAR_FDP_GEO
            "blks_per_pl=28,blk_pe_limit=20,subsys=fdpsub"
    });
    /*
     * Two groups of one channel, 80 units of 8 pages each, a floor of 45 in
     * each. 24 units retire, 14 of them in one group: the spare is what
     * that group has left, 21 of 35 units.
     */
    qos_add_test("wear-fdp-rg2", "femu", femu_test_wear_fdp,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"0 24 24 60 37",
        .edge.extra_device_opts = FEMU_WEAR_FDP_GEO
            "blks_per_pl=80,blk_pe_limit=20,blk_pe_spread=50,blk_pe_seed=5,"
            "lba_index=3,subsys=fdpsub-rg2"
    });
    /*
     * Every write placed in group 0: that group retires its 35 units and
     * keeps worn blocks in service, the other group wears nothing, and the
     * spare is group 0's. Format then keeps the retired units.
     */
    qos_add_test("wear-fdp-rg0", "femu", femu_test_wear_fdp,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"50 37 35 0 41 rg0 format",
        .edge.extra_device_opts = FEMU_WEAR_FDP_GEO
            "blks_per_pl=80,blk_pe_limit=20,blk_pe_spread=50,blk_pe_seed=5,"
            "lba_index=3,subsys=fdpsub-rg2"
    });
    /* two planes per LUN: a unit holds a block of each plane; floor 18 */
    qos_add_test("wear-fdp-pl2", "femu", femu_test_wear_fdp,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"120 48 6 0 150",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,pls_per_lun=2,luns_per_ch=2,nchs=2,"
            "eol_read_only=off,blks_per_pl=24,blk_pe_limit=12,subsys=fdpsub"
    });
    qos_add_test("wear-fdp-aer-spare", "femu", femu_test_wear_aer,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"0x1",
        .edge.extra_device_opts = FEMU_WEAR_FDP_GEO
            "blks_per_pl=40,blk_pe_limit=8,subsys=fdpsub"
    });
    qos_add_test("wear-fdp-aer-reliability", "femu", femu_test_wear_aer,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"0x4",
        .edge.extra_device_opts = FEMU_WEAR_FDP_GEO
            "blks_per_pl=40,blk_pe_limit=8,subsys=fdpsub"
    });
    qos_add_test("wear-query", "femu", femu_test_wear_query,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=30,blk_pe_spread=60,blk_pe_seed=3,spare_lines=8,"
            "eol_read_only=off"
    });
    /* 40 lines of 16 pages, MDTS 16 KiB: one reserve line */
    qos_add_test("eol-limits", "femu", femu_test_eol_limits,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"on",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=1000,mdts=2"
    });
    qos_add_test("eol-limits-off", "femu", femu_test_eol_limits,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=1000,mdts=2,eol_read_only=off"
    });
    qos_add_test("eol-refused", "femu", femu_test_eol_refused, NULL);
    qos_add_test("eol-many-queues", "femu", femu_test_g1_eol_queues,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=g1-eolq,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=1000,mdts=2,oncs=0x8,queues=32"
    });
    qos_add_test("death-early", "femu", femu_test_block_death,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"early",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=1000,blk_early_ppm=1000000,blk_early_pe=3,spare_lines=8,eol_read_only=off"
    });
    qos_add_test("death-early-off", "femu", femu_test_block_death,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"early-off",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=1000,spare_lines=8,eol_read_only=off"
    });
    qos_add_test("death-erase", "femu", femu_test_block_death,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"erase",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=1000,erase_fail_ppm=1000000,spare_lines=8,mdts=2"
    });
    qos_add_test("death-erase-rate", "femu", femu_test_block_death,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"erase-rate",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=1000,erase_fail_ppm=100000,spare_lines=8,mdts=2"
    });
    /* a normal limit below the early bound: the minimum is the limit */
    qos_add_test("death-early-min", "femu", femu_test_block_death,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"early",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=2,blk_early_ppm=1000000,blk_early_pe=100,spare_lines=8,eol_read_only=off"
    });
    qos_add_test("death-early-part", "femu", femu_test_block_death,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"early-part",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=1000,blk_pe_seed=12345,blk_early_ppm=300000,blk_early_pe=5,spare_lines=8,eol_read_only=off"
    });
    /* each erase reaches the limit of 1, and still draws */
    qos_add_test("death-erase-limit", "femu", femu_test_block_death,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"erase-limit",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=1,erase_fail_ppm=1000000,spare_lines=8,mdts=2"
    });
    qos_add_test("death-refused", "femu", femu_test_block_death_refused, NULL);
    qos_add_test("dsm-partial", "femu", femu_test_dsm_partial,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "oncs=12"
    });
    qos_add_test("eol-wzsl-meta", "femu", femu_test_eol_wzsl,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"meta",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=1000,mdts=1,meta=8,mc=3,extended=1"
    });
    qos_add_test("eol-wzsl-nowz", "femu", femu_test_eol_wzsl,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"nowz",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=1000,mdts=2,oncs=0x195"
    });
    /* 40 lines, 8 spare lines, one reserve line: the pools run out first */
    qos_add_test("eol-ro-pool", "femu", femu_test_eol_ro,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"pool",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=8,spare_lines=8,mdts=2,oncs=0x19f"
    });
    /* no spare lines: lines retire down to the floor first */
    qos_add_test("eol-ro-nopool", "femu", femu_test_eol_ro,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"nopool",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=8,mdts=2,oncs=0x19f"
    });
    /*
     * gc_frontier on, no spare lines: the floor keeps a line for the
     * collection write pointer too, and admitted writes still finish
     */
    qos_add_test("eol-ro-nopool-gcf", "femu", femu_test_eol_ro,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"nopool",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=8,mdts=2,oncs=0x19f,gc_frontier=on"
    });
    /*
     * No forced collection reserve and 32 pages of credits: when the media
     * goes read-only, the writes in flight need the reserve lines.
     */
    qos_add_test("eol-ro-tight", "femu", femu_test_eol_ro,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"tight",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=8,mdts=4,oncs=0x19f,gc_thres_pcent=99,"
            "gc_thres_pcent_high=100"
    });
    qos_add_test("eol-ro-subsys", "femu", femu_test_eol_ro,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"subsys",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=8,mdts=2,oncs=0x19f,subsys=nssub",
        .before = femu_ns_subsys_before,
    });
    /* 1024 pages: TPs 0 and 1, and the CMT holds one of them */
    qos_add_test("eol-ro-dftl", "femu", femu_test_eol_dftl,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"1",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=4,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=96,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=8,mdts=2,oncs=0x19f,mapping=dftl,x-cmt-slots=1"
    });
    /* 8-page writes, and the free lines run down to the forced 2 */
    qos_add_test("eol-ro-dftl-big", "femu", femu_test_eol_dftl,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"8",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=4,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=96,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=8,mdts=5,oncs=0x19f,mapping=dftl,x-cmt-slots=1,"
            "gc_thres_pcent=99,gc_thres_pcent_high=100"
    });
    /* the device of dftl-tp-reserve, with 9 reserve lines */
    qos_add_test("eol-ro-dftl-tp", "femu", femu_test_eol_dftl_tp,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=2,secsz=512,secs_per_pg=1,pgs_per_blk=2,"
            "blks_per_pl=1055,pls_per_lun=1,luns_per_ch=2,nchs=1,"
            "femu_mode=1,mapping=dftl,x-cmt-slots=1,gc_thres_pcent=100,"
            "gc_thres_pcent_high=100,blk_pe_limit=1000,mdts=2"
    });
    qos_add_test("eol-ro-format", "femu", femu_test_eol_ro,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"format",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=8,mdts=2,oncs=0x19f"
    });
    qos_add_test("eol-ro-sanitize", "femu", femu_test_eol_ro,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"sanitize",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=8,mdts=2,oncs=0x19f"
    });
    qos_add_test("eol-abort-reset", "femu", femu_test_eol_abort_reset,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=1000,mdts=2"
    });
    qos_add_test("eol-format-busy", "femu", femu_test_eol_format_busy,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=1000,mdts=2"
    });
    qos_add_test("eol-ro-csd", "femu", femu_test_eol_ro,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"csd",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=4,fdm_size=16,secsz=512,"
            "secs_per_pg=8,pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,"
            "luns_per_ch=2,nchs=2,blk_pe_limit=8,mdts=2,oncs=0x19f"
    });
#define FEMU_EOL_FDP_GEO \
    "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8," \
    "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2," \
    "blk_pe_limit=8,mdts=2,oncs=0x19f,"
    /*
     * FDP: 40 units of 16 pages; 16 credit pages and four handles hold 5
     * units back; units retire down to a floor of 27 of the other 35.
     */
    qos_add_test("eol-fdp", "femu", femu_test_eol_ro,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"fdp",
        .edge.extra_device_opts = FEMU_EOL_FDP_GEO "subsys=fdpsub"
    });
    qos_add_test("eol-fdp-ii", "femu", femu_test_eol_ro,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"fdp",
        .edge.extra_device_opts = FEMU_EOL_FDP_GEO "subsys=fdpsub-ii"
    });
    qos_add_test("eol-fdp-format", "femu", femu_test_eol_ro,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"fdp-format",
        .edge.extra_device_opts = FEMU_EOL_FDP_GEO "subsys=fdpsub"
    });
    qos_add_test("eol-fdp-sanitize", "femu", femu_test_eol_ro,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"fdp-sanitize",
        .edge.extra_device_opts = FEMU_EOL_FDP_GEO "subsys=fdpsub"
    });
    /*
     * 32 credit pages (MDTS 64 KiB) and four handles: 6 reserve units of
     * 40. Forced collection keeps one unit free, so about one is free when
     * the media goes read-only.
     */
#define FEMU_EOL_FDP_DRAIN \
    "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8," \
    "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2," \
    "blk_pe_limit=1000,mdts=4,gc_thres_pcent=99,gc_thres_pcent_high=99," \
    "subsys=fdpsub"
    qos_add_test("eol-fdp-drain", "femu", femu_test_eol_fdp_drain,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"plain",
        .edge.extra_device_opts = FEMU_EOL_FDP_DRAIN
    });
    qos_add_test("eol-fdp-drain-pad", "femu", femu_test_eol_fdp_drain,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"pad",
        .edge.extra_device_opts = FEMU_EOL_FDP_DRAIN ",pd_open_close_sec=1"
    });
    qos_add_test("eol-fdp-drain-reclaim", "femu", femu_test_eol_fdp_drain,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"reclaim",
        .edge.extra_device_opts = FEMU_EOL_FDP_DRAIN ",read_reclaim_limit=4"
    });
    /*
     * Two groups of 64 units of 8 pages, 24 credit pages: 7 reserve units
     * in each. Every write goes to group 1.
     */
    qos_add_test("eol-fdp-drain-rg1", "femu", femu_test_eol_fdp_drain,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"rg1",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=64,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=1000,mdts=4,gc_thres_pcent=99,"
            "gc_thres_pcent_high=99,lba_index=3,subsys=fdpsub-rg2"
    });
    qos_add_test("eol-fdp-full", "femu", femu_test_eol_fdp_full,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=1000,mdts=4,gc_thres_pcent=100,"
            "gc_thres_pcent_high=100,subsys=fdpsub"
    });
    qos_add_test("eol-fdp-ruh", "femu", femu_test_eol_fdp_ruh,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = FEMU_EOL_FDP_DRAIN
    });
    qos_add_test("eol-sq-delete", "femu", femu_test_eol_sq_delete,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "blk_pe_limit=1000,mdts=2"
    });
    qos_add_test("age-scale-warp", "femu", femu_test_age_scale,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"warp",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "ecc_step_ns=1000000,ecc_retention_sec=100,"
            "retention_limit_sec=100,age_scale=1000000"
    });
    qos_add_test("age-scale-fdp", "femu", femu_test_age_scale,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"fdp",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "ecc_step_ns=1000000,ecc_retention_sec=100,age_scale=1000000,"
            "subsys=fdpsub"
    });
    qos_add_test("pd-off", "femu", femu_test_pd,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts = FEMU_PD_GEO
            ",ecc_retention_sec=100,age_scale=1000000"
    });
    qos_add_test("pd-edge", "femu", femu_test_pd,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"edge",
        .edge.extra_device_opts = FEMU_PD_GEO
            ",cell_pages=2,pd_edge_wls=1,pd_edge_tiers=2"
    });
    qos_add_test("pd-edge-cap", "femu", femu_test_pd,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"cap",
        .edge.extra_device_opts = FEMU_PD_GEO
            ",cell_pages=2,pd_edge_wls=1,pd_edge_tiers=2,"
            "ecc_retention_sec=100,age_scale=1000000"
    });
    qos_add_test("pd-open", "femu", femu_test_pd,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"open",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=24,pls_per_lun=1,luns_per_ch=1,"
            "nchs=2,ecc_step_ns=10000000,pd_open_tiers=1"
    });
    qos_add_test("pd-open-age", "femu", femu_test_pd,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"age",
        .edge.extra_device_opts = FEMU_PD_GEO
            ",pd_open_age=on,ecc_retention_sec=100000,age_scale=1000000"
    });
    qos_add_test("pd-stream", "femu", femu_test_pd_stream,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=64,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,ecc_step_ns=10000000,streams=on,pd_open_tiers=1"
    });
    qos_add_test("pd-fdp-open", "femu", femu_test_pd_fdp,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"open",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "ecc_step_ns=10000000,pd_open_tiers=1,subsys=fdpsub"
    });
    qos_add_test("pd-fdp-age", "femu", femu_test_pd_fdp,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"age",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "ecc_step_ns=10000000,pd_open_age=on,ecc_retention_sec=100000,"
            "age_scale=1000000,subsys=fdpsub"
    });
    qos_add_test("pd-kv-on", "femu", femu_test_pd_kv,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"on",
        .edge.extra_device_opts =
            "devsz_mb=16,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=8,ecc_step_ns=200000000,pd_open_tiers=1"
    });
    qos_add_test("pd-kv-off", "femu", femu_test_pd_kv,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts =
            "devsz_mb=16,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=8,ecc_step_ns=200000000"
    });
    qos_add_test("pd-map", "femu", femu_test_pd_map,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=trace,devsz_mb=6,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=128,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,ecc_step_ns=10000000,mapping=dftl,pd_edge_wls=1,"
            "pd_edge_tiers=2,pd_open_tiers=1,pd_open_age=on,"
            "ecc_retention_sec=100,age_scale=1000000,x-cmt-slots=1"
    });
    qos_add_test("pd-reuse", "femu", femu_test_pd_reuse,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = FEMU_PD_GEO
            ",pd_open_tiers=1,pd_open_age=on,ecc_retention_sec=500000,"
            "age_scale=1000000"
    });
    qos_add_test("pd-mp", "femu", femu_test_pd_mp,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=24,pls_per_lun=2,luns_per_ch=1,"
            "nchs=1,ecc_step_ns=10000000,mp_read=1,pd_open_tiers=1"
    });
    qos_add_test("pd-refused", "femu", femu_test_pd_refused, NULL);
    qos_add_test("pd2-read", "femu", femu_test_pd2,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"read",
        .edge.extra_device_opts = FEMU_PD_GEO
            ",pd_open_read_limit=4,gc_copyback=on"
    });
    qos_add_test("pd2-read-under", "femu", femu_test_pd2,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"under",
        .edge.extra_device_opts = FEMU_PD_GEO ",pd_open_read_limit=4"
    });
    qos_add_test("pd2-read-master", "femu", femu_test_pd2,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"master",
        .edge.extra_device_opts = FEMU_PD_GEO ",read_reclaim_limit=4"
    });
    qos_add_test("pd2-read-closed", "femu", femu_test_pd2,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"closed",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=24,pls_per_lun=1,luns_per_ch=1,"
            "nchs=2,pd_open_read_limit=4"
    });
    qos_add_test("pd2-pad", "femu", femu_test_pd2,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"pad",
        .edge.extra_device_opts = FEMU_PD_GEO
            ",pd_open_tiers=1,pd_open_close_sec=1,age_scale=1000"
    });
    qos_add_test("pd2-nopad", "femu", femu_test_pd2,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"nopad",
        .edge.extra_device_opts = FEMU_PD_GEO ",pd_open_tiers=1,age_scale=1000"
    });
    qos_add_test("pd2-stream", "femu", femu_test_pd2_stream,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=64,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,streams=on,pd_open_close_sec=1,age_scale=10"
    });
    qos_add_test("pd2-fdp-pad", "femu", femu_test_pd2_fdp,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"pad",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "pd_open_close_sec=1,subsys=fdpsub"
    });
    qos_add_test("pd2-fdp-read", "femu", femu_test_pd2_fdp,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"read",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "pd_open_read_limit=4,subsys=fdpsub"
    });
    qos_add_test("pd2-fdp-quiet", "femu", femu_test_pd2_fdp,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"quiet",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "pd_open_read_limit=4,gc_strategy=4,subsys=fdpsub"
    });
    qos_add_test("pd2-fdp-read-ii", "femu", femu_test_pd2_fdp,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"read-ii",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "pd_open_read_limit=4,subsys=fdpsub-ii"
    });
    qos_add_test("pd2-fdp-ruamw", "femu", femu_test_pd2_fdp_ruamw,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=25,pls_per_lun=1,luns_per_ch=1,nchs=1,"
            "buffer_size=32,pd_open_read_limit=4,onfi_mode=26,"
            "onfi_cache_read=1,subsys=fdpsub-ii"
    });
    qos_add_test("combo-fdp-hold-pad", "femu", femu_test_combo_fdp_hold,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"pad",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "buffer_size=16,pd_open_close_sec=1,subsys=fdpsub"
    });
    qos_add_test("combo-fdp-hold-seal", "femu", femu_test_combo_fdp_hold,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"seal",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "buffer_size=16,pd_open_read_limit=4,subsys=fdpsub-ii"
    });
    qos_add_test("combo-read-limit-m0", "femu", femu_test_combo_read_limit,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"m0",
        .edge.extra_device_opts = FEMU_ONFI_GEO
            "luns_per_ch=1,onfi_mode=0,onfi_cache_read=1,buffer_size=16,"
            "pd_open_read_limit=4"
    });
    qos_add_test("combo-read-limit-m26", "femu", femu_test_combo_read_limit,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"m26",
        .edge.extra_device_opts = FEMU_ONFI_GEO
            "luns_per_ch=1,onfi_mode=26,onfi_cache_read=1,buffer_size=16,"
            "pd_open_read_limit=4"
    });
    qos_add_test("combo-pad-conv", "femu", femu_test_combo_pad_onfi,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"conv",
        .edge.extra_device_opts = FEMU_ONFI_GEO
            "luns_per_ch=1,onfi_mode=26,pd_open_close_sec=1,age_scale=1000"
    });
    qos_add_test("combo-pad-sca", "femu", femu_test_combo_pad_onfi,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"sca",
        .edge.extra_device_opts = FEMU_ONFI_GEO
            "luns_per_ch=1,onfi_mode=26,onfi_sca=1,pd_open_close_sec=1,"
            "age_scale=1000"
    });
    qos_add_test("combo-policy-greedy-seal", "femu", femu_test_combo_policy,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"greedy/seal",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "pd_open_read_limit=4,gc_policy=greedy,subsys=fdpsub"
    });
    qos_add_test("combo-policy-greedy-pad", "femu", femu_test_combo_policy,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"greedy/pad",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "pd_open_close_sec=1,age_scale=10,gc_policy=greedy,subsys=fdpsub"
    });
    qos_add_test("combo-policy-fifo-seal", "femu", femu_test_combo_policy,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"fifo/seal",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "pd_open_read_limit=4,gc_policy=fifo,subsys=fdpsub"
    });
    qos_add_test("combo-policy-fifo-pad", "femu", femu_test_combo_policy,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"fifo/pad",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "pd_open_close_sec=1,age_scale=10,gc_policy=fifo,subsys=fdpsub"
    });
    qos_add_test("combo-policy-d-choice-seal", "femu", femu_test_combo_policy,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"d-choice/seal",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "pd_open_read_limit=4,gc_policy=d-choice,subsys=fdpsub"
    });
    qos_add_test("combo-policy-d-choice-pad", "femu", femu_test_combo_policy,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"d-choice/pad",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "pd_open_close_sec=1,age_scale=10,gc_policy=d-choice,subsys=fdpsub"
    });
    qos_add_test("combo-policy-cost-benefit-seal", "femu", femu_test_combo_policy,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"cost-benefit/seal",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "pd_open_read_limit=4,gc_policy=cost-benefit,subsys=fdpsub"
    });
    qos_add_test("combo-policy-cost-benefit-pad", "femu", femu_test_combo_policy,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"cost-benefit/pad",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "pd_open_close_sec=1,age_scale=10,gc_policy=cost-benefit,subsys=fdpsub"
    });
    qos_add_test("combo-policy-random-seal", "femu", femu_test_combo_policy,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"random/seal",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "pd_open_read_limit=4,gc_policy=random,subsys=fdpsub"
    });
    qos_add_test("combo-policy-random-pad", "femu", femu_test_combo_policy,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"random/pad",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "pd_open_close_sec=1,age_scale=10,gc_policy=random,subsys=fdpsub"
    });
    qos_add_test("fdp-format-ruamw", "femu", femu_test_fdp_format_ruamw,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub"
    });
    qos_add_test("onfi-refused", "femu", femu_test_onfi_refused, NULL);
    qos_add_test("onfi-page", "femu", femu_test_onfi_page, NULL);
    qos_add_test("onfi-m26", "femu", femu_test_onfi,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"m26",
        .edge.extra_device_opts = FEMU_ONFI_GEO "luns_per_ch=1,onfi_mode=26"
    });
    qos_add_test("onfi-m26-2lun", "femu", femu_test_onfi,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"m26-2lun",
        .edge.extra_device_opts = FEMU_ONFI_GEO "luns_per_ch=2,onfi_mode=26"
    });
    qos_add_test("onfi-m0", "femu", femu_test_onfi,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"m0",
        .edge.extra_device_opts = FEMU_ONFI_GEO "luns_per_ch=1,onfi_mode=0"
    });
    qos_add_test("onfi-mts", "femu", femu_test_onfi,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"mts",
        .edge.extra_device_opts = FEMU_ONFI_GEO
            "luns_per_ch=1,onfi_mode=26,onfi_mts=3200"
    });
    qos_add_test("onfi-spare", "femu", femu_test_onfi,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"spare",
        .edge.extra_device_opts = FEMU_ONFI_GEO
            "luns_per_ch=1,onfi_mode=26,onfi_spare_bytes=512"
    });
    qos_add_test("onfi-sca-2lun", "femu", femu_test_onfi,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"sca-2lun",
        .edge.extra_device_opts = FEMU_ONFI_GEO
            "luns_per_ch=2,onfi_mode=26,onfi_sca=1"
    });
    qos_add_test("onfi-cache-on", "femu", femu_test_onfi_cache,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"on",
        .edge.extra_device_opts = FEMU_ONFI_GEO
            "luns_per_ch=1,onfi_mode=0,onfi_cache_read=1"
    });
    qos_add_test("onfi-cache-off", "femu", femu_test_onfi_cache,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts = FEMU_ONFI_GEO "luns_per_ch=1,onfi_mode=0"
    });
    qos_add_test("onfi-cache-on-m26", "femu", femu_test_onfi_cache,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"on-m26",
        .edge.extra_device_opts = FEMU_ONFI_GEO
            "luns_per_ch=1,onfi_mode=26,onfi_cache_read=1"
    });
    qos_add_test("onfi-cache-off-m26", "femu", femu_test_onfi_cache,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off-m26",
        .edge.extra_device_opts = FEMU_ONFI_GEO "luns_per_ch=1,onfi_mode=26"
    });
    qos_add_test("onfi-cache-refused", "femu", femu_test_onfi_cache_refused,
                 NULL);
    qos_add_test("onfi-off", "femu", femu_test_onfi,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts = FEMU_ONFI_GEO
            "luns_per_ch=1,cmd_addr_lat=1000,pg_xfer_lat=10000,status_lat=500"
    });
    qos_add_test("gc-copyback-pd", "femu", femu_test_gc_copyback,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"pd",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=14,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,gc_thres_pcent=75,gc_thres_pcent_high=94,"
            "pg_rd_lat=100000,pg_wr_lat=100000,blk_er_lat=100000,"
            "pg_xfer_lat=2000000,gc_copyback=on,ecc_step_ns=1000000,"
            "pd_edge_wls=20,pd_edge_tiers=1"
    });
    qos_add_test("age-fdp-reuse", "femu", femu_test_age_fdp_reuse,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "ecc_step_ns=10000000,ecc_retention_sec=100,age_scale=1000000,"
            "subsys=fdpsub"
    });
    qos_add_test("trim-cost-on", "femu", femu_test_trim_cost,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"on",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "trim_lat_ns=1000000"
    });
    qos_add_test("trim-cost-fdp", "femu", femu_test_trim_cost,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"fdp",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "trim_lat_ns=1000000,subsys=fdpsub"
    });
    qos_add_test("trim-cost-off", "femu", femu_test_trim_cost,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub"
    });
    qos_add_test("age-scale-off", "femu", femu_test_age_scale,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "ecc_step_ns=1000000,ecc_retention_sec=100,"
            "retention_limit_sec=100,age_scale=1"
    });
    qos_add_test("wear-level-off", "femu", femu_test_wear_level,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"33 0",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,nchs=2"
            ""
    });
    qos_add_test("wear-level-on", "femu", femu_test_wear_level,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"19 61",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,nchs=2"
            ",wl_spread=4"
    });

    /*
     * gc_frontier on: this workload leaves collection nothing to copy, so
     * only levelling moves pages, and they must still land in the worn
     * line the data pointer holds. Same spread and moves as wear-level-on.
     */
    qos_add_test("wear-level-gc-frontier", "femu", femu_test_wear_level,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"19 61",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,nchs=2"
            ",wl_spread=4,gc_frontier=on"
    });
    qos_add_test("wear-level-copyback", "femu", femu_test_wear_level,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"cb 19 61",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,nchs=2"
            ",wl_spread=4,gc_copyback=on"
    });
    qos_add_test("wear-level-wz", "femu", femu_test_wear_level,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"wz 19 61",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,nchs=2"
            ",wl_spread=4,oncs=0x1c"
    });
    qos_add_test("gc-pace-on", "femu", femu_test_gc_pace,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"on",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=14,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=128,blks_per_pl=32,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,gc_thres_pcent=75,gc_thres_pcent_high=94,gc_pace=on"
    });
    qos_add_test("gc-pace-trim", "femu", femu_test_gc_pace,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"trim",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=14,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=128,blks_per_pl=32,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,gc_thres_pcent=75,gc_thres_pcent_high=94,gc_pace=on"
    });
    qos_add_test("gc-pace-takeover", "femu", femu_test_gc_pace,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"takeover",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=14,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=128,blks_per_pl=32,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,gc_thres_pcent=90,gc_thres_pcent_high=90,gc_pace=on"
    });
    qos_add_test("gc-pace-budget", "femu", femu_test_gc_pace_budget,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=14,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=128,blks_per_pl=32,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,gc_thres_pcent=87,gc_thres_pcent_high=90,gc_pace=on"
    });
    qos_add_test("gc-pace-format", "femu", femu_test_gc_pace,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"format",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=14,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=128,blks_per_pl=32,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,gc_thres_pcent=75,gc_thres_pcent_high=94,gc_pace=on"
    });
    qos_add_test("gc-pace-reset", "femu", femu_test_gc_pace,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"reset",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=14,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=128,blks_per_pl=32,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,gc_thres_pcent=75,gc_thres_pcent_high=94,gc_pace=on"
    });
    qos_add_test("gc-pace-off", "femu", femu_test_gc_pace,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=14,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=128,blks_per_pl=32,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,gc_thres_pcent=75,gc_thres_pcent_high=94"
    });
    qos_add_test("gc-pace-timing-on", "femu", femu_test_gc_pace_timing,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"on",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=5,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=128,blks_per_pl=12,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,pg_rd_lat=200000,pg_wr_lat=4000000,blk_er_lat=1000000,gc_pace=on"
    });
    qos_add_test("gc-pace-timing-off", "femu", femu_test_gc_pace_timing,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=5,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=128,blks_per_pl=12,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,pg_rd_lat=200000,pg_wr_lat=4000000,blk_er_lat=1000000"
    });
    qos_add_test("gc-copyback-off", "femu", femu_test_gc_copyback,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=14,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,gc_thres_pcent=75,gc_thres_pcent_high=94,"
            "pg_rd_lat=100000,pg_wr_lat=100000,blk_er_lat=100000,"
            "pg_xfer_lat=2000000,io_stages=on"
    });
    qos_add_test("gc-copyback-parity", "femu", femu_test_gc_copyback,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"parity",
        .before = femu_cb_page_before,
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=14,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,gc_thres_pcent=75,gc_thres_pcent_high=94,"
            "pg_rd_lat=100000,pg_wr_lat=100000,blk_er_lat=100000,"
            "gc_copyback=on,onfi_param_page=@ONFI@"
    });
    qos_add_test("gc-copyback-on", "femu", femu_test_gc_copyback,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"on",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=14,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,gc_thres_pcent=75,gc_thres_pcent_high=94,"
            "pg_rd_lat=100000,pg_wr_lat=100000,blk_er_lat=100000,"
            "pg_xfer_lat=2000000,gc_copyback=on,io_stages=on"
    });
    qos_add_test("gc-copyback-oneddie", "femu", femu_test_gc_copyback,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"oneddie",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=14,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,gc_thres_pcent=75,gc_thres_pcent_high=94,"
            "pg_rd_lat=100000,pg_wr_lat=100000,blk_er_lat=100000,"
            "pg_xfer_lat=2000000,gc_copyback=on"
    });
    qos_add_test("gc-copyback-refused", "femu", femu_test_gc_copyback_refused,
                 NULL);
    qos_add_test("read-prio-refused", "femu", femu_test_read_prio_refused,
                 NULL);
    qos_add_test("prog-pass2-refused", "femu", femu_test_prog_pass2_refused,
                 NULL);
    qos_add_test("tier-refused", "femu", femu_test_tier_refused, NULL);
    qos_add_test("tier-buffer-flush", "femu", femu_test_tier_buffer_flush,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
            ",tier_mode=static,tier_static_mb=1,buffer_size=64,"
            "buffer_thres_pcent=90"
    });
    qos_add_test("tier-buffer-upkeep", "femu", femu_test_tier_buffer_upkeep,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
            ",tier_mode=static,tier_static_mb=1,tier_full_policy=through,"
            "buffer_size=64,buffer_thres_pcent=90,buffer_low_pcent=1"
    });
    qos_add_test("fdp-tier", "femu", femu_test_fdp_tier,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=fdpt,devsz_mb=8,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=48,blks_per_pl=64,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,nand_cell_type=3,tier_mode=static,tier_static_mb=1,"
            "subsys=fdpsub"
    });
    qos_add_test("fdp-tier-timing", "femu", femu_test_fdp_tier_timing,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=fdpt,devsz_mb=8,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=48,blks_per_pl=64,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,nand_cell_type=3,tier_mode=static,tier_static_mb=1,"
            "tier_pslc_prog_ns=400000000,subsys=fdpsub"
    });
    qos_add_test("tier-dftl", "femu", femu_test_tier_dftl,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
            ",tier_mode=static,tier_static_mb=1,mapping=dftl,x-cmt-slots=2"
    });
    qos_add_test("tier-dftl-dyn", "femu", femu_test_tier_dftl,
                 &(QOSGraphTestOptions) {
        .arg = (void *)1,
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
            ",tier_mode=dynamic,tier_static_mb=1,mapping=dftl,x-cmt-slots=2,"
            "tier_shrink_pct=99"
    });
    qos_add_test("tier-dftl-idle", "femu", femu_test_tier_dftl_idle,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
            ",tier_mode=static,tier_static_mb=1,mapping=dftl,x-cmt-slots=2,"
            "tier_idle_ms=2000"
    });
    qos_add_test("tier-mp", "femu", femu_test_tier_mp,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=96,blks_per_pl=32,pls_per_lun=2,luns_per_ch=2,"
            "nchs=2,nand_cell_type=3,tier_mode=static,tier_static_mb=1,"
            "tier_full_policy=through,mp_program=1"
    });
    qos_add_test("tier-suspend-host", "femu", femu_test_tier_suspend_host,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
            ",tier_mode=static,tier_static_mb=1,tier_pslc_prog_ns=200000000,"
            "pe_suspend=1,tsusp_ns=10000"
    });
    qos_add_test("tier-suspend-fold", "femu", femu_test_tier_suspend_fold,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
            ",tier_mode=static,tier_static_mb=1,tier_full_policy=through,"
            "pe_suspend=1,tsusp_ns=10000,tier_pslc_prog_ns=20000000,"
            "tier_pslc_erase_ns=" stringify(TIER_SUSP_ERASE_NS)
    });
    qos_add_test("tier-direct", "femu", femu_test_tier_direct,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
            ",tier_mode=static,tier_static_mb=1"
    });
    qos_add_test("tier-through", "femu", femu_test_tier_through,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
            ",tier_mode=static,tier_static_mb=1,tier_full_policy=through,"
            "tier_pslc_read_ns=5000000"
    });
    qos_add_test("tier-busy", "femu", femu_test_tier_busy,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
            ",tier_mode=static,tier_static_mb=1,tier_pslc_erase_ns="
            stringify(TIER_BUSY_ERASE_NS)
    });
    qos_add_test("tier-dyn-borrow", "femu", femu_test_tier_dyn_borrow,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
            ",tier_mode=dynamic"
    });
    qos_add_test("tier-dyn-cap", "femu", femu_test_tier_dyn_cap,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
            ",tier_mode=dynamic,tier_max_mb=1"
    });
    qos_add_test("tier-dyn-shrink", "femu", femu_test_tier_dyn_shrink,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
            ",tier_mode=dynamic,tier_shrink_pct=10"
    });
    qos_add_test("tier-dyn-floor", "femu", femu_test_tier_dyn_floor,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
            ",tier_mode=dynamic,tier_static_mb=1,tier_shrink_pct=99"
    });
    qos_add_test("tier-dyn-through", "femu", femu_test_tier_dyn_through,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
            ",tier_mode=dynamic,tier_static_mb=1,tier_full_policy=through"
    });
    qos_add_test("tier-dyn-full", "femu", femu_test_tier_dyn_full,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
            ",tier_mode=dynamic"
    });
    qos_add_test("tier-fold-stop", "femu", femu_test_tier_fold_stop,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
            ",tier_mode=static,tier_static_mb=1"
    });
    qos_add_test("tier-dyn-fold-stop", "femu", femu_test_tier_dyn_fold_stop,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
            ",tier_mode=dynamic,tier_max_mb=1"
    });
    qos_add_test("tier-idle-eager", "femu", femu_test_tier_idle_eager,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
            ",tier_mode=static,tier_static_mb=1,tier_idle_ms=20"
    });
    qos_add_test("tier-idle-wait", "femu", femu_test_tier_idle_wait,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
            ",tier_mode=static,tier_static_mb=1,tier_idle_ms=1000"
    });
    qos_add_test("tier-idle-off", "femu", femu_test_tier_idle_off,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
            ",tier_mode=static,tier_static_mb=1"
    });
    qos_add_test("tier-idle-lazy", "femu", femu_test_tier_idle_lazy,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
            ",tier_mode=static,tier_static_mb=1,tier_idle_ms=20,"
            "tier_lazy_pct=50"
    });
    qos_add_test("tier-idle-dyn", "femu", femu_test_tier_idle_dyn,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
            ",tier_mode=dynamic,tier_idle_ms=20"
    });
    qos_add_test("tier-idle-steps", "femu", femu_test_tier_idle_steps,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
            ",tier_mode=static,tier_static_mb=1,tier_idle_ms=20,"
            "tier_pslc_read_ns=5000000"
    });
    qos_add_test("tier-idle-write", "femu", femu_test_tier_idle_write,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
            ",tier_mode=static,tier_static_mb=1,tier_idle_ms=20,"
            "tier_pslc_read_ns=20000000"
    });
    qos_add_test("tier-idle-format", "femu", femu_test_tier_idle_format,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
            ",tier_mode=static,tier_static_mb=1,tier_idle_ms=20,"
            "tier_pslc_read_ns=20000000"
    });
    qos_add_test("tier-idle-sanitize", "femu", femu_test_tier_idle_sanitize,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
            ",tier_mode=static,tier_static_mb=1,tier_idle_ms=20,"
            "tier_pslc_read_ns=20000000"
    });
    qos_add_test("tier-idle-reset", "femu", femu_test_tier_idle_reset,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
            ",tier_mode=static,tier_static_mb=1,tier_idle_ms=20,"
            "tier_pslc_read_ns=20000000"
    });
    for (size_t i = 0; i < ARRAY_SIZE(femu_tier_gc_policies); i++) {
        const char *pol = femu_tier_gc_policies[i];
        g_autofree char *name = g_strdup_printf("tier-dyn-gc-%s", pol);

        /* qos keeps the options for the whole run */
        qos_add_test(name, "femu", femu_test_tier_dyn_gc,
                     &(QOSGraphTestOptions) {
            .edge.extra_device_opts = g_strdup_printf(
                "id=gc-test,devsz_mb=16,femu_mode=1," FEMU_TIER_GEO
                ",tier_mode=dynamic,gc_policy=%s", pol),
            .arg = (void *)pol,
        });
    }
    qos_add_test("thermal-idle", "femu", femu_test_thermal,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"idle",
        .edge.extra_device_opts =
            "femu_mode=1,temperature=300,thermal_tau_ms=1000,thermal_r=10,"
            "idle_mw=1000"
    });
    qos_add_test("thermal-pulse", "femu", femu_test_thermal,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"pulse",
        .edge.extra_device_opts =
            "femu_mode=1,temperature=300,thermal_tau_ms=1000,thermal_r=10,"
            "energy_prog_nj=1000000"
    });
    qos_add_test("thermal-off", "femu", femu_test_thermal,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts =
            "femu_mode=1,temperature=300,energy_prog_nj=1000000"
    });
    qos_add_test("thermal-event", "femu", femu_test_thermal_event,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,temperature=300,thermal_tau_ms=1000,thermal_r=10,"
            "idle_mw=1000"
    });
    qos_add_test("thermal-refused", "femu", femu_test_thermal_refused, NULL);
    qos_add_test("power-meas-log", "femu", femu_test_pmeas,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,power_meas=on,idle_mw=500,energy_prog_nj=1000000"
    });
    qos_add_test("power-meas-off", "femu", femu_test_pmeas_off, NULL);
    qos_add_test("power-meas-refused", "femu", femu_test_pmeas_refused,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,power_meas=on,subsys=nssub",
        .before = femu_ns_subsys_before,
    });
    qos_add_test("partial-writes-bbssd", "femu", femu_test_partial_writes,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1,oncs=0x1c"
    });
    qos_add_test("partial-writes-ns2", "femu", femu_test_partial_writes_ns2,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1,devsz_mb=1,namespaces=3"
    });
    qos_add_test("partial-writes-fdp", "femu", femu_test_partial_writes,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1,subsys=fdpsub,oncs=0x1c"
    });
    qos_add_test("plane-energy", "femu", femu_test_plane_energy,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"one",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "energy_read_nj=100,energy_prog_nj=1000,energy_erase_nj=10000"
    });
    qos_add_test("plane-energy-mp", "femu", femu_test_plane_energy,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"mp",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=2,blks_per_pl=19,pls_per_lun=2,luns_per_ch=2,nchs=2,"
            "mp_program=1,mp_read=1,"
            "energy_read_nj=100,energy_prog_nj=1000,energy_erase_nj=10000"
    });
    qos_add_test("fw-cost-read", "femu", femu_test_fw_cost,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"read",
        .edge.extra_device_opts = "femu_mode=2,fw_read_ns=200000000"
    });
    qos_add_test("fw-cost-other", "femu", femu_test_fw_cost,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"other",
        .edge.extra_device_opts = "femu_mode=2,vwc=1,fw_other_ns=200000000"
    });
    qos_add_test("fw-cost-reset", "femu", femu_test_fw_cost,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"reset",
        .edge.extra_device_opts = "femu_mode=2,fw_read_ns=200000000"
    });
    qos_add_test("fw-cost-cores1", "femu", femu_test_fw_cost,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"cores1",
        .edge.extra_device_opts = "femu_mode=2,fw_read_ns=200000000,fw_cores=1"
    });
    qos_add_test("fw-cost-cores2", "femu", femu_test_fw_cost,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"cores2",
        .edge.extra_device_opts = "femu_mode=2,fw_read_ns=200000000,fw_cores=2"
    });
    qos_add_test("stall-gc", "femu", femu_test_stalls,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"gc",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2"
    });
    qos_add_test("stall-buffer", "femu", femu_test_stalls,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"buffer",
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,buffer_size=16"
    });
    qos_add_test("stall-buffer-gc", "femu", femu_test_stalls,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"buffer-gc",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "buffer_size=16"
    });
    qos_add_test("stall-fdp", "femu", femu_test_stalls,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"fdp",
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=4,"
            "blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub,gc_thres_pcent=100,gc_thres_pcent_high=100"
    });
    qos_add_test("stall-cq", "femu", femu_test_stalls,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"cq",
        .edge.extra_device_opts =
            "femu_mode=1"
    });
    qos_add_test("wear-refused", "femu", femu_test_wear_refused, NULL);
    qos_add_test("wear-fdp-props", "femu", femu_test_wear_fdp_props, NULL);
    qos_add_test("pace-refused", "femu", femu_test_wear_refused,
                 &(QOSGraphTestOptions) { .arg = (void *)"'gc_pace':true" });
    qos_add_test("ftl-trace-bbssd", "femu", femu_test_ftl_trace,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"732 3890000000 10306 10306 11408 5364 11536 21714 5364 "
                       "1758358858069010501",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2",
    });
    /* gc_frontier given as off: the same trace as the plain device */
    qos_add_test("ftl-trace-gc-frontier-off", "femu", femu_test_ftl_trace,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"732 3890000000 10306 10306 11408 5364 11536 21714 5364 "
                       "1758358858069010501",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "gc_frontier=off",
    });
    /*
     * gc_frontier on: collection copies go to lines of their own. The
     * frontier needs one more reserve line, so the geometry has 22 blocks.
     */
    qos_add_test("ftl-trace-gc-frontier", "femu", femu_test_ftl_trace,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"732 2790000000 10306 10306 6849 4224 6977 17155 4224 "
                       "4430748168361763090",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=22,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "gc_frontier=on",
    });
    /* rber_ppb given as 0: the same trace as the plain device */
    qos_add_test("ftl-trace-rber-off", "femu", femu_test_ftl_trace,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"732 3890000000 10306 10306 11408 5364 11536 21714 5364 "
                       "1758358858069010501",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "rber_ppb=0",
    });
    /* gc_idle_ms given as 0: the same trace as the plain device */
    qos_add_test("ftl-trace-gc-idle-off", "femu", femu_test_ftl_trace,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"732 3910000000 10306 10306 11408 5364 11536 21714 5364 "
                       "1758358858069010501",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "gc_idle_ms=0",
    });
    qos_add_test("ftl-trace-hot-cold", "femu", femu_test_ftl_trace,
                 &(QOSGraphTestOptions) {
        .arg = (void *)
            "732 11900000000 10306 10306 44095 13536 44223 54401 13536 "
            "15350679178168073678",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "hot_cold_sep=on",
    });
    qos_add_test("ftl-trace-fdp", "femu", femu_test_ftl_trace,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"732 2190000000 10306 10306 4416 3616 4544 14722 3616 "
                       "5667387085002007720",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub",
    });
    /*
     * fw_gc_page_ns of 1 ns: the program of each move waits for its read and
     * a slot, which changes no count, no victim order and no WAF
     */
    qos_add_test("ftl-trace-gc-fw", "femu", femu_test_ftl_trace,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"732 3990000000 10306 10306 11408 5364 11536 21714 5364 "
                       "1758358858069010501",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "fw_gc_page_ns=1",
    });
    qos_add_test("ftl-trace-fdp-gc-fw", "femu", femu_test_ftl_trace,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"732 2260000000 10306 10306 4416 3616 4544 14722 3616 "
                       "5667387085002007720",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub,fw_gc_page_ns=1",
    });
    /*
     * The victim order of each collection policy, on the workload above.
     * Cost-benefit has no pin: it ages victims by the host's real-time clock.
     * The counts alone can hide a changed draw: with gc_seed=7, FDP random
     * relocates the same pages when each draw is one higher. The victim
     * digest, the last field, still tells the two orders apart.
     */
    qos_add_test("ftl-trace-random", "femu", femu_test_ftl_trace,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"732 7680000000 10306 10306 26577 9156 26705 36883 9156 "
                       "2001030099875195277",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "gc_policy=random,gc_seed=7",
    });
    qos_add_test("ftl-trace-d-choice", "femu", femu_test_ftl_trace,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"732 5010000000 10306 10306 15855 6476 15983 26161 6476 "
                       "15202952108705383366",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "gc_policy=d-choice,gc_seed=7",
    });
    qos_add_test("ftl-trace-fifo", "femu", femu_test_ftl_trace,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"732 7730000000 10306 10306 26366 9104 26494 36672 9104 "
                       "15363890515473485230",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "gc_policy=fifo",
    });
    qos_add_test("ftl-trace-fdp-random", "femu", femu_test_ftl_trace,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"732 4390000000 10306 10306 12910 5740 13038 23216 5740 "
                       "9224531952056629341",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub,gc_strategy=2,gc_seed=1",
    });
    /*
     * gc_policy picks the reclaim unit strategy under FDP. random is the
     * strategy gc_strategy=2 runs, so the trace is that one exactly. fifo
     * relocates more pages than greedy (4416) on this workload, d-choice
     * fewer; the victim digests differ from greedy's too.
     */
    qos_add_test("ftl-trace-fdp-policy-random", "femu", femu_test_ftl_trace,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"732 4420000000 10306 10306 12910 5740 13038 23216 5740 "
                       "9224531952056629341",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub,gc_policy=random,gc_seed=1",
    });
    qos_add_test("ftl-trace-fdp-fifo", "femu", femu_test_ftl_trace,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"732 3210000000 10306 10306 8495 4636 8623 18801 4636 "
                       "8979856547963124758",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub,gc_policy=fifo",
    });
    qos_add_test("ftl-trace-fdp-d-choice", "femu", femu_test_ftl_trace,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"732 2500000000 10306 10306 5487 3884 5615 15793 3884 "
                       "5908913319105439259",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub,gc_policy=d-choice,gc_seed=7",
    });
    /* every new FDP knob named at its default: the trace of ftl-trace-fdp */
    qos_add_test("ftl-trace-fdp-knobs-off", "femu", femu_test_ftl_trace,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"732 2220000000 10306 10306 4416 3616 4544 14722 3616 "
                       "5667387085002007720",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub,gc_policy=greedy,mapping=page,buffer_size=0",
    });
    qos_add_test("ftl-trace-fdp-noisy", "femu", femu_test_ftl_trace_var,
                 &(QOSGraphTestOptions) {
        .arg = (void *)&ftl_trace_fdp_noisy,
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub,gc_strategy=4",
    });
    qos_add_test("ftl-trace-fdp-noisy-ii", "femu", femu_test_ftl_trace_var,
                 &(QOSGraphTestOptions) {
        .arg = (void *)&ftl_trace_fdp_noisy_ii,
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub-ii,gc_strategy=4",
    });
    qos_add_test("ftl-trace-fdp-trim-erase-all", "femu",
                 femu_test_ftl_trace_var, &(QOSGraphTestOptions) {
        .arg = (void *)&ftl_trace_fdp_trim,
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub,gc_strategy=4,fdp_trim_erase_all=1",
    });
    qos_add_test("ftl-trace-fdp-reread", "femu", femu_test_ftl_trace_var,
                 &(QOSGraphTestOptions) {
        .arg = (void *)&ftl_trace_fdp_reread,
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub",
    });
    /*
     * Read reclaim runs only with two lines free, so this device has more
     * lines than the others. The reads reach lines in the victim heap.
     */
    qos_add_test("ftl-trace-read-reclaim", "femu", femu_test_ftl_trace_var,
                 &(QOSGraphTestOptions) {
        .arg = (void *)&ftl_trace_read_reclaim,
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "read_reclaim_limit=2",
    });
    /*
     * gc_erase_order off: the old timing. Every count and the victim digest
     * are those of ftl-trace-bbssd, so the order changes no WAF.
     */
    qos_add_test("ftl-trace-gc-erase-order-off", "femu", femu_test_ftl_trace,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"732 3300000000 10306 10306 11408 5364 11536 21714 5364 "
                       "1758358858069010501",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "gc_erase_order=off",
    });
    qos_add_test("gc-erase-order-on", "femu", femu_test_gc_erase_order,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"on",
        .edge.extra_device_opts =
            "id=gc-order,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2",
    });
    /* the planted control: the same workload books erases too early */
    qos_add_test("gc-erase-order-off", "femu", femu_test_gc_erase_order,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts =
            "id=gc-order,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "gc_erase_order=off,pg_wr_lat=2000000",
    });
    /* fast NAND, so the NAND work of a pass is far below x-gc-hold-us */
    qos_add_test("gc-clock", "femu", femu_test_gc_clock,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"on",
        .edge.extra_device_opts =
            "id=gc-clock,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "pg_rd_lat=2000,pg_wr_lat=5000,blk_er_lat=20000",
    });
    /* the control: with no pass, the stalls reach the fence */
    qos_add_test("gc-clock-control", "femu", femu_test_gc_clock,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"control",
        .edge.extra_device_opts =
            "id=gc-clock,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "pg_rd_lat=2000,pg_wr_lat=5000,blk_er_lat=20000",
    });
    qos_add_test("gc-erase-order-fdp-on", "femu", femu_test_gc_erase_order,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"on",
        .edge.extra_device_opts =
            "id=gc-order,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub",
    });
    qos_add_test("gc-erase-order-fdp-off", "femu", femu_test_gc_erase_order,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts =
            "id=gc-order,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub,gc_erase_order=off,pg_wr_lat=2000000",
    });
    /* each copy program sealed: a read waits for it, so the fence holds */
    qos_add_test("gc-erase-order-suspend", "femu", femu_test_gc_erase_order,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"suspend",
        .edge.extra_device_opts =
            "id=gc-order,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "pe_suspend=1,tsusp_ns=5000",
    });
    /* each copy program sealed: a priority read does not pass it */
    qos_add_test("gc-erase-order-prio", "femu", femu_test_gc_erase_order,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"prio",
        .edge.extra_device_opts =
            "id=gc-order,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "read_prio=1",
    });
    qos_add_test("fdp-gc-strategy-refused", "femu",
                 femu_test_fdp_gc_strategy_refused, NULL);
    qos_add_test("query-bbssd", "femu", femu_test_query,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=qf,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2"
    });
    qos_add_test("query-stats-bbssd", "femu", femu_test_query_stats,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=qs,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "io_stages=on"
    });
    qos_add_test("query-stats-stage-hold", "femu",
                 femu_test_query_stats_stage_hold, &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=stage-test,femu_mode=1,devsz_mb=64,"
            "io_stages=on"
    });
    qos_add_test("query-stats-two-ns", "femu", femu_test_query_stats_two_ns,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=qs2,femu_mode=1,namespaces=2,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=128,pls_per_lun=1,luns_per_ch=2,nchs=2"
    });
    qos_add_test("query-stats-shared-ftl", "femu",
                 femu_test_query_stats_two_ns, &(QOSGraphTestOptions) {
        .arg = (void *)"shared",
        .edge.extra_device_opts = "id=qs2,femu_mode=1,devsz_mb=1,"
            "secsz=512,secs_per_pg=8,pgs_per_blk=8,blks_per_pl=12,"
            "pls_per_lun=1,luns_per_ch=2,nchs=2,namespaces=2,shared_ftl=on",
    });
    qos_add_test("query-zns", "femu", femu_test_query_zns,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=2,zns_num_blk=32,zns_num_conv_zones=1,"
            "zns_max_open=3,zns_max_active=4"
    });
    qos_add_test("query-unsupported-nossd", "femu",
                 femu_test_query_unsupported, &(QOSGraphTestOptions) {
        .arg = (void *)"does not support nossd namespaces",
    });
    qos_add_test("query-media-m26-2lun", "femu", femu_test_query_media,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"m26-2lun",
        .edge.extra_device_opts = FEMU_ONFI_GEO "luns_per_ch=2,onfi_mode=26"
    });
    qos_add_test("query-media-m26-sca-2lun", "femu", femu_test_query_media,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"m26-sca-2lun",
        .edge.extra_device_opts = FEMU_ONFI_GEO
            "luns_per_ch=2,onfi_mode=26,onfi_sca=1"
    });
    qos_add_test("query-media-kvssd-m26-cache", "femu", femu_test_query_media,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"kvssd-m26-cache",
        .edge.extra_device_opts =
            "devsz_mb=512,femu_mode=5,kv_timing=model,onfi_mode=26,"
            "onfi_cache_read=1"
    });
    qos_add_test("query-media-m26-cache-2lun", "femu", femu_test_query_media,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"m26-cache-2lun",
        .edge.extra_device_opts = FEMU_ONFI_GEO
            "luns_per_ch=2,onfi_mode=26,onfi_cache_read=1,trcbsy=4000"
    });
    qos_add_test("query-media-m26-1lun", "femu", femu_test_query_media,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"m26-1lun",
        .edge.extra_device_opts = FEMU_ONFI_GEO "luns_per_ch=1,onfi_mode=26"
    });
    qos_add_test("query-media-default", "femu", femu_test_query_media,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"default",
        .edge.extra_device_opts = FEMU_ONFI_GEO "luns_per_ch=2"
    });
    qos_add_test("query-media-staged", "femu", femu_test_query_media,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"staged",
        .edge.extra_device_opts = FEMU_ONFI_GEO
            "luns_per_ch=2,cmd_addr_lat=1000,pg_xfer_lat=10000,"
            "status_lat=500,tplebsy=900"
    });
    qos_add_test("query-media-csd", "femu", femu_test_query_media,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"csd-m26",
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=4,fdm_size=16,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=24,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,onfi_mode=26"
    });
    qos_add_test("query-media-kvssd", "femu", femu_test_query_media,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"kvssd",
        .edge.extra_device_opts = "devsz_mb=512,femu_mode=5"
    });
    qos_add_test("query-media-zns", "femu", femu_test_query_media,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"zns",
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=2,zns_num_blk=32,zns_cmd_addr_lat=700,"
            "zns_pg_xfer_lat=3000,zns_status_lat=200"
    });
    qos_add_test("query-media-oc12-off", "femu", femu_test_query_media,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"oc12-off",
        .edge.extra_device_opts = "femu_mode=0,lver=1,ch_xfer_lat=7000"
    });
    qos_add_test("query-media-oc20", "femu", femu_test_query_media,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"oc20",
        .edge.extra_device_opts = "femu_mode=0,lver=2"
    });
    qos_add_test("query-media-fdp", "femu", femu_test_query_media,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"fdp-m26",
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub,onfi_mode=26"
    });
    qos_add_test("query-media-kvssd-m26", "femu", femu_test_query_media,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"kvssd-m26",
        .edge.extra_device_opts =
            "devsz_mb=512,femu_mode=5,kv_timing=model,onfi_mode=26"
    });
    qos_add_test("query-media-gap-no-bus", "femu", femu_test_query_media,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"gap-no-bus",
        .edge.extra_device_opts = FEMU_ONFI_GEO "luns_per_ch=2,tplebsy=900"
    });
    qos_add_test("query-media-mixed", "femu", femu_test_query_media_mixed,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,namespaces=2,namespace_modes=bbssd,,kvssd,"
            FEMU_CAPS_GEO ",onfi_mode=26"
    });
    qos_add_test("query-media-oc12-on", "femu", femu_test_query_media,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"oc12-on",
        .edge.extra_device_opts =
            "femu_mode=0,lver=1,ch_xfer_lat=7000,oc12_channel_timing=on"
    });
    qos_add_test("query-unplug", "femu", femu_test_query_unplug,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=qu,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2"
    });
    {
        /* the shipped profile, from a build directory or the source root */
        const char *np = "../hw/femu/profiles/bbssd-flat-default.nprof";
        char *popts;

        if (!g_file_test(np, G_FILE_TEST_EXISTS)) {
            np = "hw/femu/profiles/bbssd-flat-default.nprof";
        }
        /* the test graph keeps the string for the life of the process */
        popts = g_strdup_printf("id=qu,devsz_mb=1,femu_mode=1,secsz=512,"
                               "secs_per_pg=8,pgs_per_blk=4,blks_per_pl=19,"
                               "pls_per_lun=1,luns_per_ch=2,nchs=2,"
                               "nand_profile=%s", np);
        qos_add_test("query-unplug-profile", "femu", femu_test_query_unplug,
                     &(QOSGraphTestOptions) {
            .arg = (void *)"profile",
            .edge.extra_device_opts = popts,
        });
    }
    qos_add_test("query-zns-busy", "femu", femu_test_query_zns_busy,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=qz,devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,"
            "zns_num_lun=1,zns_num_plane=2,zns_num_blk=32"
    });
    qos_add_test("zone-report-unlocked", "femu",
                 femu_test_zone_report_unlocked, &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=qz,devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,"
            "zns_num_lun=1,zns_num_plane=2,zns_num_blk=32"
    });
    qos_add_test("zone-report-rom", "femu", femu_test_zone_report_rom,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=qz,devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,"
            "zns_num_lun=1,zns_num_plane=2,zns_num_blk=32"
    });
    qos_add_test("zone-reset-inflight", "femu", femu_test_zone_reset_inflight,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=qz,devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,"
            "zns_num_lun=1,zns_num_plane=2,zns_num_blk=32,"
            "multipoller_enabled=1,poller_ratio=1"
    });
    qos_add_test("zone-reset-all-inflight", "femu",
                 femu_test_zone_reset_inflight, &(QOSGraphTestOptions) {
        .arg = (void *)"all",
        .edge.extra_device_opts =
            "id=qz,devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,"
            "zns_num_lun=1,zns_num_plane=2,zns_num_blk=32,"
            "multipoller_enabled=1,poller_ratio=1"
    });
    qos_add_test("query-zns-busy-unplug", "femu",
                 femu_test_query_zns_busy_unplug, &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=qz,devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,"
            "zns_num_lun=1,zns_num_plane=2,zns_num_blk=32"
    });
    qos_add_test("query-zns-unplug", "femu", femu_test_query_unplug,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"znssd",
        .edge.extra_device_opts =
            "id=qu,devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,"
            "zns_num_lun=1,zns_num_plane=2,zns_num_blk=32"
    });
    qos_add_test("query-fdp-update", "femu", femu_test_query_fdp_update,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub",
    });
    qos_add_test("query-fdp-replace", "femu", femu_test_query_fdp_replace,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=qr,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub",
    });
    qos_add_test("query-fdp", "femu", femu_test_query_fdp,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub",
    });
    /* one plane: multi-plane commands have nothing to combine */
    qos_add_test("ftl-trace-mp-one-plane", "femu", femu_test_ftl_trace,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"732 3910000000 10306 10306 11408 5364 11536 21714 5364 "
                       "1758358858069010501",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "mp_program=1,mp_read=1",
    });
    qos_add_test("ftl-trace-mp-off", "femu", femu_test_ftl_trace_mp,
                 &(QOSGraphTestOptions) {
        .arg = (void *)&ftl_trace_mp_off,
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=2,blks_per_pl=19,pls_per_lun=2,luns_per_ch=2,nchs=2",
    });
    qos_add_test("ftl-trace-mp-on", "femu", femu_test_ftl_trace_mp,
                 &(QOSGraphTestOptions) {
        .arg = (void *)&ftl_trace_mp_on,
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=2,blks_per_pl=19,pls_per_lun=2,luns_per_ch=2,nchs=2,"
            "mp_program=1,mp_read=1",
    });
    /* FDP keeps its own read timing: mp_read must not move it */
    qos_add_test("ftl-trace-mp-fdp-off", "femu", femu_test_ftl_trace_mp,
                 &(QOSGraphTestOptions) {
        .arg = (void *)&ftl_trace_mp_fdp,
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=2,blks_per_pl=25,pls_per_lun=2,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub",
    });
    qos_add_test("ftl-trace-mp-fdp-read", "femu", femu_test_ftl_trace_mp,
                 &(QOSGraphTestOptions) {
        .arg = (void *)&ftl_trace_mp_fdp,
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=2,blks_per_pl=25,pls_per_lun=2,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub,mp_read=1",
    });
    qos_add_test("mp-program-scopes-off", "femu", femu_test_mp_program_scopes,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=2,blks_per_pl=19,pls_per_lun=2,luns_per_ch=2,nchs=2,"
            "oncs=0x1f,vwc=1,buffer_size=64",
    });
    qos_add_test("mp-program-scopes-on", "femu", femu_test_mp_program_scopes,
                 &(QOSGraphTestOptions) {
        .arg = GINT_TO_POINTER(1),
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=2,blks_per_pl=19,pls_per_lun=2,luns_per_ch=2,nchs=2,"
            "oncs=0x1f,vwc=1,buffer_size=64,mp_program=1",
    });
    qos_add_test("plane-first-off", "femu", femu_test_plane_first,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=2,blks_per_pl=19,pls_per_lun=2,luns_per_ch=2,nchs=2,"
            "mp_program=1",
    });
    qos_add_test("plane-first-on", "femu", femu_test_plane_first,
                 &(QOSGraphTestOptions) {
        .arg = GINT_TO_POINTER(1),
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=2,blks_per_pl=19,pls_per_lun=2,luns_per_ch=2,nchs=2,"
            "mp_program=1,plane_first=1",
    });
    qos_add_test("gc-no-destination", "femu", femu_test_gc_no_destination,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2"
    });
    qos_add_test("gc-no-destination-hot-cold", "femu",
                 femu_test_gc_no_destination,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=19,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "hot_cold_sep=on"
    });
    /*
     * placement keeps a unit open per handle and one to collect into per
     * handle, so it needs more lines
     */
    qos_add_test("gc-no-destination-fdp", "femu", femu_test_gc_no_destination,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub"
    });
    /* the smallest geometries a 1 MiB namespace on four handles fits */
    qos_add_test("fdp-capacity", "femu", femu_test_fdp_gc_handles,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub"
    });
    qos_add_test("fdp-capacity-ii", "femu", femu_test_fdp_gc_handles,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=24,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub-ii"
    });
    /* 128 KiB units: the forced percentage rounds to no unit at all */
    qos_add_test("fdp-capacity-small", "femu", femu_test_fdp_gc_handles,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=8,blks_per_pl=17,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub"
    });
    qos_add_test("fdp-capacity-refused", "femu",
                 femu_test_fdp_capacity_refused, NULL);
    qos_add_test("fdp-single-pool", "femu", femu_test_fdp_single_pool, NULL);
    qos_add_test("fdp-ns-phl", "femu", femu_test_fdp_ns_phl,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub,namespaces=2,namespace_phls=0:1,,1:2",
    });
    qos_add_test("fdp-ns-cmds", "femu", femu_test_fdp_ns_cmds,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub,namespaces=2,namespace_phls=0:1,,1:2,oncs=0x10c",
    });
    qos_add_test("fdp-ns-format-shared", "femu", femu_test_fdp_ns_format,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"shared",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub,namespaces=2,namespace_phls=0:1,,2:1",
    });
    qos_add_test("fdp-ns-format-apart", "femu", femu_test_fdp_ns_format,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"apart",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub,namespaces=2,namespace_phls=0:1,,2:3",
    });
    qos_add_test("fdp-ns-events", "femu", femu_test_fdp_ns_events,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,gc_thres_pcent=20,gc_thres_pcent_high=94,"
            "subsys=fdpsub-ii,namespaces=2,namespace_phls=3:0,,1:2:3",
    });
    qos_add_test("fdp-ns-knobs", "femu", femu_test_fdp_ns_knobs,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,subsys=fdpsub,namespaces=2,namespace_phls=0:1,,2:3,"
            "buffer_size=16,vwc=1,gc_policy=fifo,mapping=dftl,"
            "read_reclaim_limit=8,retention_limit_sec=3600",
    });
    qos_add_test("fdp-ns-nossd", "femu", femu_test_fdp_ns_nossd,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=2,femu_mode=2,subsys=fdpsub,namespaces=2,"
            "namespace_phls=0:1,,2",
    });
    qos_add_test("fdp-ns-refused", "femu", femu_test_fdp_ns_refused, NULL);
    qos_add_test("fdp-hbmw-blocks", "femu", femu_test_fdp_hbmw_blocks,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"direct",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub",
    });
    qos_add_test("fdp-hbmw-blocks-buffer", "femu", femu_test_fdp_hbmw_blocks,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"buffer",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub,buffer_size=16,vwc=1",
    });
    {
        static const FemuFdpConfWant conf1 = {
            .nrg = 1, .rgif = 0, .nruh = 4, .runs = 64 * 1024,
        };

        qos_add_test("fdp-confs", "femu", femu_test_fdp_confs,
                     &(QOSGraphTestOptions) {
            .arg = (void *)&conf1,
            .edge.extra_device_opts =
                "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
                "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,"
                "nchs=2,subsys=fdpsub",
        });
    }
    {
        /* a group is one channel of two LUNs: units of 8 pages, 32 KiB */
        static const FemuFdpConfWant conf2 = {
            .nrg = 2, .rgif = 1, .nruh = 4, .runs = 32 * 1024,
        };
        static const FemuRgWant rg2 = {
            .nrg = 2, .rgif = 1, .nchs = 2, .luns = 2,
        };
        static const FemuRgWant rg3 = {
            .nrg = 3, .rgif = 2, .nchs = 3, .luns = 1,
        };
        static const FemuRgWant rg4 = {
            .nrg = 4, .rgif = 2, .nchs = 2, .luns = 4, .ph = 1,
        };
        static const FemuRgWant rg2_ii = {
            .nrg = 2, .rgif = 1, .nchs = 2, .luns = 2, .ph = 3,
        };
        static const FemuRgWant rg2_burst = {
            .nrg = 2, .rgif = 1, .nchs = 2, .luns = 2, .burst = 16,
        };

        qos_add_test("fdp-confs-rg2", "femu", femu_test_fdp_confs,
                     &(QOSGraphTestOptions) {
            .arg = (void *)&conf2,
            .edge.extra_device_opts =
                "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
                "pgs_per_blk=4,blks_per_pl=64,pls_per_lun=1,luns_per_ch=2,"
                "nchs=2,lba_index=3,subsys=fdpsub-rg2",
        });
        qos_add_test("fdp-rg2-place", "femu", femu_test_fdp_rg_place,
                     &(QOSGraphTestOptions) {
            .arg = (void *)&rg2,
            .edge.extra_device_opts =
                "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
                "pgs_per_blk=4,blks_per_pl=64,pls_per_lun=1,luns_per_ch=2,"
                "nchs=2,lba_index=3,subsys=fdpsub-rg2",
        });
        /* three groups of one die each */
        qos_add_test("fdp-rg3-place", "femu", femu_test_fdp_rg_place,
                     &(QOSGraphTestOptions) {
            .arg = (void *)&rg3,
            .edge.extra_device_opts =
                "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
                "pgs_per_blk=4,blks_per_pl=128,pls_per_lun=1,luns_per_ch=1,"
                "nchs=3,lba_index=3,subsys=fdpsub-rg3",
        });
        /* four groups of two LUNs of one channel */
        qos_add_test("fdp-rg4-place", "femu", femu_test_fdp_rg_place,
                     &(QOSGraphTestOptions) {
            .arg = (void *)&rg4,
            .edge.extra_device_opts =
                "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
                "pgs_per_blk=4,blks_per_pl=64,pls_per_lun=1,luns_per_ch=4,"
                "nchs=2,lba_index=3,subsys=fdpsub-rg4",
        });
        qos_add_test("fdp-rg2-gc", "femu", femu_test_fdp_rg_gc,
                     &(QOSGraphTestOptions) {
            .arg = (void *)&rg2,
            .edge.extra_device_opts =
                "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
                "pgs_per_blk=4,blks_per_pl=64,pls_per_lun=1,luns_per_ch=2,"
                "nchs=2,lba_index=3,subsys=fdpsub-rg2",
        });
        /* writes of 16 pages: foreground collection in the group */
        qos_add_test("fdp-rg2-gc-fg", "femu", femu_test_fdp_rg_gc,
                     &(QOSGraphTestOptions) {
            .arg = (void *)&rg2_burst,
            .edge.extra_device_opts =
                "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
                "pgs_per_blk=4,blks_per_pl=64,pls_per_lun=1,luns_per_ch=2,"
                "nchs=2,lba_index=3,subsys=fdpsub-rg2",
        });
        qos_add_test("fdp-rg2-gc-cb", "femu", femu_test_fdp_rg_gc,
                     &(QOSGraphTestOptions) {
            .arg = (void *)&rg2,
            .edge.extra_device_opts =
                "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
                "pgs_per_blk=4,blks_per_pl=64,pls_per_lun=1,luns_per_ch=2,"
                "nchs=2,lba_index=3,gc_copyback=on,subsys=fdpsub-rg2",
        });
        qos_add_test("fdp-rg2-gc-ii", "femu", femu_test_fdp_rg_gc,
                     &(QOSGraphTestOptions) {
            .arg = (void *)&rg2_ii,
            .edge.extra_device_opts =
                "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
                "pgs_per_blk=4,blks_per_pl=64,pls_per_lun=1,luns_per_ch=2,"
                "nchs=2,lba_index=3,subsys=fdpsub-rg2-ii",
        });
        qos_add_test("fdp-rg2-buffer", "femu", femu_test_fdp_rg_buffer,
                     &(QOSGraphTestOptions) {
            .edge.extra_device_opts =
                "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
                "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,"
                "nchs=2,lba_index=3,gc_thres_pcent=100,"
                "gc_thres_pcent_high=100,buffer_size=8,vwc=1,"
                "subsys=fdpsub-rg2",
        });
        qos_add_test("fdp-rg2-format-mode", "femu",
                     femu_test_fdp_rg_format_mode, &(QOSGraphTestOptions) {
            .edge.extra_device_opts =
                "id=gc-test,devsz_mb=1,femu_mode=2,namespace_modes=bbssd,"
                "secsz=512,secs_per_pg=8,pgs_per_blk=4,blks_per_pl=64,"
                "pls_per_lun=1,luns_per_ch=2,nchs=2,lba_index=3,"
                "subsys=fdpsub-rg2",
        });
        qos_add_test("fdp-rg4-gc", "femu", femu_test_fdp_rg_gc,
                     &(QOSGraphTestOptions) {
            .arg = (void *)&rg4,
            .edge.extra_device_opts =
                "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
                "pgs_per_blk=4,blks_per_pl=64,pls_per_lun=1,luns_per_ch=4,"
                "nchs=2,lba_index=3,subsys=fdpsub-rg4",
        });
    }
    qos_add_test("fdp-invalid-pid", "femu", femu_test_fdp_invalid_pid,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub",
    });
    qos_add_test("fdp-invalid-pid-nossd", "femu", femu_test_fdp_invalid_pid,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "devsz_mb=2,femu_mode=2,subsys=fdpsub",
    });
    qos_add_test("fdp-unprogrammed", "femu", femu_test_fdp_unprogrammed,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "oncs=0xe,subsys=fdpsub",
    });
    qos_add_test("fdp-runs-block", "femu", femu_test_fdp_runs_block,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "devsz_mb=2,femu_mode=2,subsys=fdpsub-tiny",
    });
    qos_add_test("fdp-nossd-counts", "femu", femu_test_fdp_nossd_counts,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=2,femu_mode=2,oncs=0x10e,subsys=fdpsub-runs",
    });
    qos_add_test("fdp-replace-full", "femu", femu_test_fdp_replace_full,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=fdp-full,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "gc_thres_pcent=100,gc_thres_pcent_high=100,subsys=fdpsub",
    });
    qos_add_test("fdp-ns-replace", "femu", femu_test_fdp_ns_replace,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=fdpns-r,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "subsys=fdpsub,namespaces=2,namespace_phls=0:1,,1:2",
    });
    /* forced only with no unit free, so a frontier can be dropped */
    qos_add_test("fdp-gc-recover", "femu", femu_test_fdp_gc_recover,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=24,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "gc_thres_pcent=100,gc_thres_pcent_high=100,subsys=fdpsub"
    });
    qos_add_test("fdp-gc-recover-ii", "femu", femu_test_fdp_gc_recover,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=23,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "gc_thres_pcent=100,gc_thres_pcent_high=100,subsys=fdpsub-ii",
        .arg = (void *)1,
    });
    qos_add_test("flush-without-vwc", "femu", femu_test_flush_without_vwc,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=4,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=4,"
            "blks_per_pl=128,pls_per_lun=1,luns_per_ch=2,nchs=2,vwc=0,"
            "buffer_size=16"
    });
    /* plug, use and unplug each mode; the process must not grow */
    qos_add_test("lifecycle-nossd", "femu", femu_test_lifecycle,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"io,\"femu_mode\":2" });
    qos_add_test("lifecycle-bbssd", "femu", femu_test_lifecycle,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"io,\"femu_mode\":1" });
    qos_add_test("lifecycle-zns", "femu", femu_test_lifecycle,
                 &(QOSGraphTestOptions) { .arg = (void *)"\"femu_mode\":3" });
    qos_add_test("lifecycle-kv", "femu", femu_test_lifecycle,
                 &(QOSGraphTestOptions) { .arg = (void *)"\"femu_mode\":5" });
    qos_add_test("lifecycle-csd", "femu", femu_test_lifecycle,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"\"femu_mode\":4,\"fdm_size\":64" });
    qos_add_test("lifecycle-ocssd", "femu", femu_test_lifecycle,
                 &(QOSGraphTestOptions) { .arg = (void *)"\"femu_mode\":0" });
    qos_add_test("lifecycle-ocssd12", "femu", femu_test_lifecycle,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"\"femu_mode\":0,\"lver\":1" });
    qos_add_test("gc-seed-d-choice", "femu", femu_test_gc_seed,
                 &(QOSGraphTestOptions) { .arg = (void *)"d-choice" });
    qos_add_test("gc-seed-random", "femu", femu_test_gc_seed,
                 &(QOSGraphTestOptions) { .arg = (void *)"random" });
    qos_add_test("gc-seed-fifo", "femu", femu_test_gc_seed,
                 &(QOSGraphTestOptions) { .arg = (void *)"fifo" });
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
    qos_add_test("fdp-csd-ruh-update", "femu", femu_test_fdp_csd_ruh_update,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=11,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,subsys=fdpsub,femu_mode=4,fdm_size=1"
    });
    qos_add_test("fdp-csd-ruh-update-buffer", "femu",
                 femu_test_fdp_csd_ruh_update, &(QOSGraphTestOptions) {
        .arg = (void *)"buffer",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=11,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,subsys=fdpsub,femu_mode=4,fdm_size=1,buffer_size=16"
    });
    qos_add_test("fdp-ruh-update-reserve", "femu",
                 femu_test_fdp_ruh_update_reserve, &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "gc_thres_pcent=99,gc_thres_pcent_high=99,subsys=fdpsub",
    });
    qos_add_test("fdp-ruh-update-moved", "femu",
                 femu_test_fdp_ruh_update_moved, &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "gc_thres_pcent=99,gc_thres_pcent_high=99,subsys=fdpsub-ii",
    });
    qos_add_test("fdp-ruh-update-none", "femu", femu_test_fdp_ruh_update_none,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "gc_thres_pcent=100,gc_thres_pcent_high=100,subsys=fdpsub"
    });
    qos_add_test("fdp-ruh-update-full", "femu", femu_test_fdp_ruh_update_full,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,lba_index=3,"
            "gc_thres_pcent=100,gc_thres_pcent_high=100,subsys=fdpsub",
    });
    qos_add_test("fdp-cb-unwritten-age", "femu",
                 femu_test_fdp_cb_unwritten_age, &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "gc_strategy=1,subsys=fdpsub",
    });
    qos_add_test("fdp-cb-utilization", "femu", femu_test_fdp_cb_utilization,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "gc_strategy=1,subsys=fdpsub",
    });
    qos_add_test("fdp-policy-fifo", "femu", femu_test_fdp_policy_pick,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"fifo 14",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "gc_policy=fifo,subsys=fdpsub",
    });
    qos_add_test("fdp-policy-fifo-greedy", "femu", femu_test_fdp_policy_pick,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"fifo 4",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "gc_policy=greedy,subsys=fdpsub",
    });
    qos_add_test("fdp-policy-cb", "femu", femu_test_fdp_policy_pick,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"cb 8",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "gc_policy=cost-benefit,subsys=fdpsub",
    });
    qos_add_test("fdp-policy-cb-strategy", "femu", femu_test_fdp_policy_pick,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"cb 8",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "gc_strategy=1,subsys=fdpsub",
    });
    qos_add_test("fdp-policy-cb-greedy", "femu", femu_test_fdp_policy_pick,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"cb 6",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "gc_strategy=0,subsys=fdpsub",
    });
    qos_add_test("fdp-policy-fifo-empty", "femu", femu_test_fdp_policy_pick,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"empty 0",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=1,gc_policy=fifo,subsys=fdpsub",
    });
    qos_add_test("fdp-policy-fifo-csd", "femu", femu_test_fdp_policy_pick,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"fifo 14",
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=4,fdm_size=1,gc_policy=fifo,subsys=fdpsub",
    });
    qos_add_test("dftl-ready", "femu", femu_test_dftl_ready,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=trace,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=1,mapping=dftl,x-cmt-slots=1"
    });
    qos_add_test("dftl-batch", "femu", femu_test_dftl_batch,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=tp,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=1,mapping=dftl,x-cmt-slots=1"
    });
    qos_add_test("dftl-batch-csd", "femu", femu_test_dftl_batch,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"csd",
        .edge.extra_device_opts =
            "id=tp,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=4,fdm_size=1,mapping=dftl,x-cmt-slots=1"
    });
    qos_add_test("shutdown-abrupt", "femu", femu_test_shutdown_abrupt,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=power,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=1,buffer_size=16,vwc=1,power_loss=on"
    });
    qos_add_test("shutdown-sysreset", "femu", femu_test_shutdown_sysreset,
                 NULL);
    qos_add_test("shutdown-delay", "femu", femu_test_shutdown_delay,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=sd,femu_mode=1,devsz_mb=16,shutdown_ms=200",
    });
    qos_add_test("shutdown-bad", "femu", femu_test_shutdown_bad,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=sd0,femu_mode=1,devsz_mb=16",
    });
    qos_add_test("power-fua-place-fail", "femu", femu_test_power_fua_place_fail,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=power,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=1,buffer_size=16,vwc=1,power_loss=on"
    });
    qos_add_test("dftl-power", "femu", femu_test_dftl_power,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=power,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=1,mapping=dftl,x-cmt-slots=1,buffer_size=16,vwc=1,"
            "power_loss=on"
    });
    {
        /* translation pages under each media action */
        static const char *const media[][2] = {
            { "reads", "read_reclaim_limit=20" },
            { "open", "pd_open_read_limit=20" },
            { "publish", "read_reclaim_limit=4" },
            { "age", "retention_limit_sec=1" },
            { "pad", "pd_open_close_sec=1" },
        };

        for (int i = 0; i < ARRAY_SIZE(media); i++) {
            g_autofree char *name = g_strdup_printf("dftl-media-%s",
                                                    media[i][0]);

            qos_add_test(name, "femu", femu_test_dftl_media,
                         &(QOSGraphTestOptions) {
                .arg = (void *)media[i][0],
                .edge.extra_device_opts = g_strdup_printf(
                    "id=tp,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
                    "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,"
                    "femu_mode=1,mapping=dftl,x-cmt-slots=1,%s",
                    media[i][1]),
            });
        }
    }
    qos_add_test("dftl-wl", "femu", femu_test_dftl_wl,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=tp,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=4,"
            "blks_per_pl=560,pls_per_lun=1,luns_per_ch=1,nchs=1,"
            "femu_mode=1,mapping=dftl,x-cmt-slots=1,wl_spread=4"
    });
    qos_add_test("dftl-capacity", "femu", femu_test_dftl_capacity, NULL);
    qos_add_test("dftl-tp-min", "femu", femu_test_dftl_tp_min,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=tp,devsz_mb=9,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=78,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=1,mapping=dftl,x-cmt-slots=1"
    });
    /* forced collection only at the 2 lines dftl keeps at least */
    qos_add_test("dftl-tp-min-tight", "femu", femu_test_dftl_tp_min,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=tp,devsz_mb=9,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=77,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=1,mapping=dftl,x-cmt-slots=1,gc_thres_pcent=99,"
            "gc_thres_pcent_high=100"
    });
    /* 512-byte pages, 4-page lines and 5 free lines after a fill */
    qos_add_test("dftl-tp-reserve", "femu", femu_test_dftl_tp_reserve,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=tp,devsz_mb=2,secsz=512,secs_per_pg=1,pgs_per_blk=2,"
            "blks_per_pl=1046,pls_per_lun=1,luns_per_ch=2,nchs=1,"
            "femu_mode=1,mapping=dftl,x-cmt-slots=1,gc_thres_pcent=100,"
            "gc_thres_pcent_high=100"
    });
    {
        /* the TP pages of mapping=dftl through each way collection runs */
        static const char *const tp_var[][2] = {
            { "dftl-tp", "femu_mode=1" },
            { "dftl-tp-copyback", "femu_mode=1,gc_copyback=on" },
            { "dftl-tp-pace", "femu_mode=1,gc_pace=on" },
            { "dftl-tp-hot-cold", "femu_mode=1,hot_cold_sep=on" },
            { "dftl-tp-buffer", "femu_mode=1,buffer_size=64" },
            { "dftl-tp-csd", "femu_mode=4,fdm_size=1" },
        };

        for (int i = 0; i < ARRAY_SIZE(tp_var); i++) {
            qos_add_test(tp_var[i][0], "femu", femu_test_dftl_tp,
                         &(QOSGraphTestOptions) {
                .arg = (void *)(!i ? "exact" :
                                g_str_has_prefix(tp_var[i][1], "femu_mode=4") ?
                                "csd" : "loose"),
                .edge.extra_device_opts = g_strdup_printf(
                    "id=tp,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
                    "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,"
                    "mapping=dftl,x-cmt-slots=1,%s", tp_var[i][1]),
            });
        }
    }
    /* the media charge of each TP read and program (T3.0) */
    qos_add_test("dftl-tp-charge", "femu", femu_test_dftl_tp_charge,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"slot",
        .edge.extra_device_opts =
            "id=tp,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "mapping=dftl,x-cmt-slots=1,femu_mode=1",
    });
    /* the control: the default cache holds all 4 TPs */
    qos_add_test("dftl-tp-charge-cached", "femu", femu_test_dftl_tp_charge,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"cached",
        .edge.extra_device_opts =
            "id=tp,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "mapping=dftl,femu_mode=1",
    });
    qos_add_test("dftl-tp-gc-fw", "femu", femu_test_dftl_tp,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"fw",
        .edge.extra_device_opts =
            "id=tp,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "mapping=dftl,x-cmt-slots=1,femu_mode=1,fw_gc_page_ns=1000",
    });
    qos_add_test("fdp-dftl", "femu", femu_test_fdp_dftl,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"dftl",
        .edge.extra_device_opts =
            "devsz_mb=11,secsz=512,secs_per_pg=8,pgs_per_blk=32,"
            "blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=1,mapping=dftl,subsys=fdpsub"
    });
    qos_add_test("fdp-dftl-page", "femu", femu_test_fdp_dftl,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"page",
        .edge.extra_device_opts =
            "devsz_mb=11,secsz=512,secs_per_pg=8,pgs_per_blk=32,"
            "blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=1,subsys=fdpsub"
    });
    qos_add_test("fdp-dftl-csd", "femu", femu_test_fdp_dftl,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"dftl",
        .edge.extra_device_opts =
            "devsz_mb=11,secsz=512,secs_per_pg=8,pgs_per_blk=32,"
            "blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=4,fdm_size=1,mapping=dftl,subsys=fdpsub"
    });
    qos_add_test("fdp-policy-refused", "femu", femu_test_fdp_policy_refused,
                 NULL);
    qos_add_test("fdp-policy-fifo-background", "femu",
                 femu_test_fdp_fifo_background, &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "gc_policy=fifo,subsys=fdpsub",
    });
    qos_add_test("fdp-cb-background", "femu", femu_test_fdp_cb_background,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "gc_strategy=1,subsys=fdpsub",
    });
    qos_add_test("fdp-buffer-isolation", "femu", femu_test_fdp_buffer,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"isolation",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=11,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,subsys=fdpsub,femu_mode=1,buffer_size=128"
    });
    qos_add_test("fdp-buffer-isolation-csd", "femu", femu_test_fdp_buffer,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"isolation-csd",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=11,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,subsys=fdpsub,femu_mode=4,fdm_size=1,buffer_size=128"
    });
    qos_add_test("fdp-buffer-rehandle", "femu", femu_test_fdp_buffer,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"rehandle",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=11,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,subsys=fdpsub,femu_mode=1,buffer_size=128"
    });
    qos_add_test("fdp-buffer-dealloc", "femu", femu_test_fdp_buffer,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"dealloc",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=11,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,subsys=fdpsub,femu_mode=1,buffer_size=128"
    });
    qos_add_test("fdp-buffer-fua", "femu", femu_test_fdp_buffer,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"fua",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=11,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,subsys=fdpsub,femu_mode=1,buffer_size=128"
    });
    qos_add_test("fdp-buffer-vwc", "femu", femu_test_fdp_buffer,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"vwc",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=11,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,subsys=fdpsub,femu_mode=1,buffer_size=128,vwc=1"
    });
    qos_add_test("fdp-buffer-update", "femu", femu_test_fdp_buffer,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"update",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=11,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,subsys=fdpsub,femu_mode=1,buffer_size=128"
    });
    qos_add_test("fdp-buffer-update-suspend", "femu", femu_test_fdp_buffer,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"update-suspend",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=11,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,subsys=fdpsub,femu_mode=1,buffer_size=128,pe_suspend=1"
    });
    qos_add_test("fdp-buffer-full", "femu", femu_test_fdp_buffer,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"full",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=11,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,subsys=fdpsub,femu_mode=1,buffer_size=16"
    });
    qos_add_test("fdp-buffer-copy", "femu", femu_test_fdp_buffer,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"copy",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=11,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,subsys=fdpsub,femu_mode=1,buffer_size=128,oncs=0x104"
    });
    qos_add_test("fdp-refresh-reads", "femu", femu_test_fdp_refresh,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"reads",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,subsys=fdpsub,read_reclaim_limit=8"
    });
    qos_add_test("fdp-refresh-age", "femu", femu_test_fdp_refresh,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"age",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,subsys=fdpsub,retention_limit_sec=100,age_scale=1000000"
    });
    qos_add_test("fdp-refresh-open", "femu", femu_test_fdp_refresh,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"open",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,subsys=fdpsub,read_reclaim_limit=8"
    });
    qos_add_test("fdp-refresh-copyback", "femu", femu_test_fdp_refresh,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"copyback",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,subsys=fdpsub,read_reclaim_limit=8,gc_copyback=on"
    });
    qos_add_test("fdp-refresh-off", "femu", femu_test_fdp_refresh,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,subsys=fdpsub"
    });
    qos_add_test("fdp-refresh-victim", "femu", femu_test_fdp_refresh,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"victim",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,subsys=fdpsub,read_reclaim_limit=8"
    });
    qos_add_test("fdp-refresh-victim-cb", "femu", femu_test_fdp_refresh,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"victim",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,subsys=fdpsub,read_reclaim_limit=8,gc_strategy=1"
    });
    qos_add_test("fdp-refresh-victim-ruh", "femu", femu_test_fdp_refresh,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"victim",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,subsys=fdpsub,read_reclaim_limit=8,gc_strategy=4"
    });
    qos_add_test("fdp-refresh-gcqueue", "femu", femu_test_fdp_refresh,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"gcqueue",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=2,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,subsys=fdpsub,read_reclaim_limit=8,gc_copyback=on,gc_thres_pcent=10,gc_thres_pcent_high=40"
    });
    qos_add_test("fdp-copyback-pi-off", "femu", femu_test_fdp_copyback,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"pi-off",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,gc_thres_pcent=50,gc_thres_pcent_high=94,"
            "pg_rd_lat=100000,pg_wr_lat=100000,blk_er_lat=100000,"
            "pg_xfer_lat=2000000,subsys=fdpsub"
    });
    qos_add_test("fdp-copyback-pi-on", "femu", femu_test_fdp_copyback,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"pi-on",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,gc_thres_pcent=50,gc_thres_pcent_high=94,"
            "pg_rd_lat=100000,pg_wr_lat=100000,blk_er_lat=100000,"
            "pg_xfer_lat=2000000,subsys=fdpsub,gc_copyback=on,io_stages=on"
    });
    qos_add_test("fdp-copyback-ii-off", "femu", femu_test_fdp_copyback,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"ii-off",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,gc_thres_pcent=50,gc_thres_pcent_high=94,"
            "pg_rd_lat=100000,pg_wr_lat=100000,blk_er_lat=100000,"
            "pg_xfer_lat=2000000,subsys=fdpsub-ii"
    });
    qos_add_test("fdp-copyback-ii-on", "femu", femu_test_fdp_copyback,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"ii-on",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,gc_thres_pcent=50,gc_thres_pcent_high=94,"
            "pg_rd_lat=100000,pg_wr_lat=100000,blk_er_lat=100000,"
            "pg_xfer_lat=2000000,subsys=fdpsub-ii,gc_copyback=on,io_stages=on"
    });
    qos_add_test("fdp-events-gc-pi", "femu", femu_test_fdp_move_events,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"gc-pi",
        .edge.extra_device_opts =
            "id=fdpev-gc-pi,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,gc_thres_pcent=50,gc_thres_pcent_high=94,"
            "subsys=fdpsub"
    });
    qos_add_test("fdp-events-gc-ii", "femu", femu_test_fdp_move_events,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"gc-ii",
        .edge.extra_device_opts =
            "id=fdpev-gc-ii,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,gc_thres_pcent=50,gc_thres_pcent_high=94,"
            "subsys=fdpsub-ii"
    });
    qos_add_test("fdp-events-gc-ii-cb", "femu", femu_test_fdp_move_events,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"gc-ii-cb",
        .edge.extra_device_opts =
            "id=fdpev-gc-ii-cb,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,gc_thres_pcent=50,gc_thres_pcent_high=94,"
            "subsys=fdpsub-ii,gc_copyback=on"
    });
    qos_add_test("fdp-events-gc-ii-4k", "femu", femu_test_fdp_move_events,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"gc-ii-4k",
        .edge.extra_device_opts =
            "id=fdpev-gc-ii-4k,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,gc_thres_pcent=50,gc_thres_pcent_high=94,"
            "subsys=fdpsub-ii,lba_index=3"
    });
    qos_add_test("fdp-events-gc-ii-part", "femu", femu_test_fdp_move_events,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"gc-ii-part",
        .edge.extra_device_opts =
            "id=fdpev-gc-ii-part,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,gc_thres_pcent=50,gc_thres_pcent_high=94,"
            "subsys=fdpsub-ii"
    });
    /*
     * The same with a 16-page write buffer: the partial pages wait in the
     * buffer, and the blocks they cover reach the event through write-back.
     */
    qos_add_test("fdp-events-gc-ii-part-buffer", "femu",
                 femu_test_fdp_move_events, &(QOSGraphTestOptions) {
        .arg = (void *)"gc-ii-part",
        .edge.extra_device_opts =
            "id=fdpev-gc-ii-part,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,gc_thres_pcent=50,gc_thres_pcent_high=94,"
            "subsys=fdpsub-ii,buffer_size=16"
    });
    qos_add_test("fdp-events-gc-ii-mix-buffer", "femu",
                 femu_test_fdp_move_events, &(QOSGraphTestOptions) {
        .arg = (void *)"gc-ii-mix",
        .edge.extra_device_opts =
            "id=fdpev-gc-ii-mix,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,gc_thres_pcent=50,gc_thres_pcent_high=94,"
            "subsys=fdpsub-ii,buffer_size=16"
    });
    qos_add_test("fdp-events-gc-ii-fua-buffer", "femu",
                 femu_test_fdp_move_events, &(QOSGraphTestOptions) {
        .arg = (void *)"gc-ii-fua",
        .edge.extra_device_opts =
            "id=fdpev-gc-ii-fua,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,gc_thres_pcent=50,gc_thres_pcent_high=94,"
            "subsys=fdpsub-ii,buffer_size=16"
    });
    qos_add_test("fdp-events-gc-ii-redo-buffer", "femu",
                 femu_test_fdp_move_events, &(QOSGraphTestOptions) {
        .arg = (void *)"gc-ii-redo",
        .edge.extra_device_opts =
            "id=fdpev-gc-ii-redo,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,gc_thres_pcent=50,gc_thres_pcent_high=94,"
            "subsys=fdpsub-ii,buffer_size=16"
    });
    qos_add_test("fdp-events-gc-ii-dsm", "femu", femu_test_fdp_move_events,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"gc-ii-dsm",
        .edge.extra_device_opts =
            "id=fdpev-gc-ii-dsm,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,gc_thres_pcent=50,gc_thres_pcent_high=94,"
            "subsys=fdpsub-ii"
    });
    qos_add_test("fdp-events-gc-ii-dsm-buffer", "femu",
                 femu_test_fdp_move_events, &(QOSGraphTestOptions) {
        .arg = (void *)"gc-ii-dsm",
        .edge.extra_device_opts =
            "id=fdpev-gc-ii-dsm,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,gc_thres_pcent=50,gc_thres_pcent_high=94,"
            "subsys=fdpsub-ii,buffer_size=16"
    });
    qos_add_test("fdp-events-gc-ii-rot", "femu", femu_test_fdp_move_events,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"gc-ii-rot",
        .edge.extra_device_opts =
            "id=fdpev-gc-ii-rot,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,gc_thres_pcent=50,gc_thres_pcent_high=94,"
            "subsys=fdpsub-ii"
    });
    qos_add_test("fdp-events-gc-ii-mask", "femu", femu_test_fdp_move_events,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"gc-ii-mask",
        .edge.extra_device_opts =
            "id=fdpev-gc-ii-mask,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,gc_thres_pcent=50,gc_thres_pcent_high=94,"
            "subsys=fdpsub-ii"
    });
    qos_add_test("fdp-events-gc-ii-no80", "femu", femu_test_fdp_move_events,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"gc-ii-no80",
        .edge.extra_device_opts =
            "id=fdpev-gc-ii-no80,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,gc_thres_pcent=50,gc_thres_pcent_high=94,"
            "subsys=fdpsub-ii"
    });
    qos_add_test("fdp-events-gc-ii-no81", "femu", femu_test_fdp_move_events,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"gc-ii-no81",
        .edge.extra_device_opts =
            "id=fdpev-gc-ii-no81,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,gc_thres_pcent=50,gc_thres_pcent_high=94,"
            "subsys=fdpsub-ii"
    });
    qos_add_test("fdp-events-gc-ii-other", "femu", femu_test_fdp_move_events,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"gc-ii-other",
        .edge.extra_device_opts =
            "id=fdpev-gc-ii-other,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,gc_thres_pcent=50,gc_thres_pcent_high=94,"
            "subsys=fdpsub-ii"
    });
    qos_add_test("fdp-events-gc-ii-empty", "femu", femu_test_fdp_move_events,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"gc-ii-empty",
        .edge.extra_device_opts =
            "id=fdpev-gc-ii-empty,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,gc_thres_pcent=50,gc_thres_pcent_high=94,"
            "subsys=fdpsub-ii"
    });
    qos_add_test("fdp-events-rf-pi", "femu", femu_test_fdp_move_events,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"rf-pi",
        .edge.extra_device_opts =
            "id=fdpev-rf-pi,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,subsys=fdpsub,read_reclaim_limit=8"
    });
    qos_add_test("fdp-events-rf-ii-part", "femu", femu_test_fdp_move_events,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"rf-ii-part",
        .edge.extra_device_opts =
            "id=fdpev-rf-ii-part,devsz_mb=11,femu_mode=1,secsz=512,"
            "secs_per_pg=8,pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,"
            "luns_per_ch=2,nchs=2,subsys=fdpsub-ii,read_reclaim_limit=8"
    });
    qos_add_test("fdp-events-rf-ii", "femu", femu_test_fdp_move_events,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"rf-ii",
        .edge.extra_device_opts =
            "id=fdpev-rf-ii,devsz_mb=11,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=32,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,subsys=fdpsub-ii,read_reclaim_limit=8"
    });
    qos_add_test("fdp-background-gc", "femu", femu_test_fdp_background_gc,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=trace,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "gc_thres_pcent=1,gc_thres_pcent_high=100,subsys=fdpsub",
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
    qos_add_test("kv-model-shared", "femu", femu_test_kv_model_shared,
                 &(QOSGraphTestOptions) { .before = femu_shared_before });
    qos_add_test("gc-erase-order-shared", "femu",
                 femu_test_gc_erase_order_shared,
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
            "pls_per_lun=1,luns_per_ch=4,nchs=4",
        .arg = (void *)&femu_id_nossd,
    });
    qos_add_test("namespace-mixed-identity-bbssd", "femu",
                 femu_test_namespace_mixed_identity, &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,namespaces=2,namespace_modes=bbssd,,nossd,"
            "secs_per_pg=8,pgs_per_blk=16,blks_per_pl=80,"
            "pls_per_lun=1,luns_per_ch=4,nchs=4",
        .arg = (void *)&femu_id_bbssd,
    });
    qos_add_test("namespace-mixed-identity-kv", "femu",
                 femu_test_namespace_mixed_identity, &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=5,namespaces=2,namespace_modes=bbssd,,kvssd,"
            "secs_per_pg=8,pgs_per_blk=16,blks_per_pl=80,"
            "pls_per_lun=1,luns_per_ch=4,nchs=4",
        .arg = (void *)&femu_id_kvssd,
    });
    qos_add_test("kv-base-spread", "femu", femu_test_kv_base_spread,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=16,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=8,pg_rd_lat=25000000"
    });
    qos_add_test("kv-gc-victim", "femu", femu_test_kv_gc_victim,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=64,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,pg_wr_lat=2000000,pg_rd_lat=1000,blk_er_lat=1000"
    });
    qos_add_test("kv-hash-backshift", "femu", femu_test_kv_hash_backshift,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=24,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,pg_wr_lat=1000,pg_rd_lat=1000,blk_er_lat=1000,"
            "kv_max_keys=965"
    });
    qos_add_test("kv-hash-backshift-off", "femu", femu_test_kv_hash_backshift,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=96,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,pg_wr_lat=1000,pg_rd_lat=1000,blk_er_lat=1000,kv_pack=off,"
            "kv_max_keys=965"
    });
    qos_add_test("kv-css-nvm", "femu", femu_test_kv_css,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "devsz_mb=16,femu_mode=5"
    });
    qos_add_test("kv-css-all", "femu", femu_test_kv_css,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "devsz_mb=16,femu_mode=5",
        .arg = (void *)1,
    });
    qos_add_test("oc-set-latency", "femu", femu_test_oc_set_latency,
                 &(QOSGraphTestOptions) {
        /* the oc20-vector-io geometry, eight backed chunks per unit */
        .edge.extra_device_opts =
            "devsz_mb=1024,femu_mode=0,lver=2,lnum_ch=3,lnum_lun=5,"
            "lsecs_per_pg=4,lpgs_per_blk=256,learly_reset=1",
        .arg = (void *)1,
    });
    qos_add_test("oc-set-latency-refused", "femu", femu_test_oc_set_latency,
                 NULL);
    qos_add_test("oc20-page-types-off", "femu", femu_test_oc20_page_types,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=1024,femu_mode=0,lver=2,lnum_ch=3,lnum_lun=5,"
            "lsecs_per_pg=4,lpgs_per_blk=256,learly_reset=1",
    });
    qos_add_test("oc20-page-types-refused", "femu",
                 femu_test_oc20_page_types_refused, NULL);
    qos_add_test("kv-model-off", "femu", femu_test_kv_model,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=512,femu_mode=5,kv_timing=media,"
            "kv_model_coeffs=" KV_MODEL_TEST_OPT,
    });
    qos_add_test("kv-model-on", "femu", femu_test_kv_model,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=512,femu_mode=5,kv_timing=model,"
            "kv_model_coeffs=" KV_MODEL_TEST_OPT,
        .arg = (void *)1,
    });
    qos_add_test("kv-model-refused", "femu", femu_test_kv_model_refused,
                 NULL);
    qos_add_test("kv-lsm-many-keys", "femu", femu_test_kv_lsm_many_keys,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=16,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=8," FEMU_LSM_KNOBS "kv_lsm_pinned_levels=1"
    });
    qos_add_test("kv-lsm-list-order", "femu", femu_test_kv_lsm_list_order,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=16,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=8," FEMU_LSM_KNOBS "kv_lsm_pinned_levels=0"
    });
    /* one value a page: the counts and times below are of value pages */
    qos_add_test("kv-lsm-probe-time", "femu", femu_test_kv_lsm_probe_time,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=16,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=8,pg_rd_lat=25000000,pg_wr_lat=100000,"
            FEMU_LSM_KNOBS "kv_lsm_pinned_levels=0,kv_pack=off"
    });
    /* one value a page: the counts and times below are of value pages */
    qos_add_test("kv-lsm-background", "femu", femu_test_kv_lsm_background,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=64,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,pg_wr_lat=200000000,pg_rd_lat=1000,blk_er_lat=1000,"
            FEMU_LSM_KNOBS "kv_lsm_pinned_levels=0,kv_pack=off"
    });
    qos_add_test("kv-lsm-query", "femu", femu_test_kv_lsm_query,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=16,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=8," FEMU_LSM_KNOBS "kv_lsm_pinned_levels=1",
        .arg = (void *)1,
    });
    qos_add_test("kv-lsm-query-hash", "femu", femu_test_kv_lsm_query,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=16,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=8,kv_index=hash"
    });
    qos_add_test("kv-lsm-refused", "femu", femu_test_kv_lsm_refused, NULL);
    qos_add_test("kv-keys-small", "femu", femu_test_kv_keys_small,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=2,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=24,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,pg_wr_lat=1000,pg_rd_lat=1000,blk_er_lat=1000"
    });
    qos_add_test("kv-mnk-pcent", "femu", femu_test_kv_mnk_auto,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(29 * 124),
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=25,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,gc_thres_pcent=29"
    });
    qos_add_test("kv-mnk-top", "femu", femu_test_kv_mnk_auto,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(4194303),
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=256,blks_per_pl=64,pls_per_lun=1,luns_per_ch=4,"
            "nchs=4"
    });
    qos_add_test("kv-mnk-off", "femu", femu_test_kv_mnk_auto,
                 &(QOSGraphTestOptions) {
        .arg = GUINT_TO_POINTER(1023),
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=24,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,kv_pack=off"
    });
    qos_add_test("kv-keys-limit", "femu", femu_test_kv_keys_limit,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=16,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=64,blks_per_pl=128,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,pg_wr_lat=1000,pg_rd_lat=1000,blk_er_lat=1000,"
            "kv_max_keys=3000"
    });
    qos_add_test("kv-keys-limit-off", "femu", femu_test_kv_keys_limit,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=16,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=64,blks_per_pl=128,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,pg_wr_lat=1000,pg_rd_lat=1000,blk_er_lat=1000,"
            "kv_max_keys=3000,kv_pack=off"
    });
    /* 1 MiB of value space: the LSM table starts at 1024 slots and grows */
    qos_add_test("kv-keys-limit-lsm", "femu", femu_test_kv_keys_limit,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=64,blks_per_pl=128,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,pg_wr_lat=1000,pg_rd_lat=1000,blk_er_lat=1000,"
            "kv_max_keys=3000,kv_index=lsm"
    });
    /* one value a page: the counts and times below are of value pages */
    qos_add_test("kv-lsm-gc", "femu", femu_test_kv_lsm_gc,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=64,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,pg_wr_lat=1000,pg_rd_lat=1000,blk_er_lat=1000,"
            FEMU_LSM_KNOBS "kv_lsm_pinned_levels=0,kv_pack=off"
    });
    /* one value a page: the counts and times below are of value pages */
    qos_add_test("kv-lsm-gc-mp", "femu", femu_test_kv_lsm_gc,
                 &(QOSGraphTestOptions) {
        /* two planes, the same 1024 pages; values of two pages */
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=32,pls_per_lun=2,luns_per_ch=1,"
            "nchs=1,pg_wr_lat=1000,pg_rd_lat=1000,blk_er_lat=1000,"
            FEMU_LSM_KNOBS "kv_lsm_pinned_levels=0,kv_pack=off",
        .arg = (void *)1,
    });
    qos_add_test("kv-lsm-full-lines", "femu", femu_test_kv_lsm_full_lines,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=8,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,pg_wr_lat=1000,pg_rd_lat=1000,blk_er_lat=1000,"
            FEMU_LSM_KNOBS "kv_lsm_pinned_levels=24"
    });
    qos_add_test("kv-lsm-churn", "femu", femu_test_kv_lsm_churn,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=12,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,pg_wr_lat=1000,pg_rd_lat=1000,blk_er_lat=1000,"
            FEMU_LSM_KNOBS "kv_lsm_pinned_levels=0"
    });
    qos_add_test("kv-lsm-full-delete", "femu", femu_test_kv_lsm_full_delete,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=5,secsz=32,secs_per_pg=1,"
            "pgs_per_blk=16,blks_per_pl=64,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,pg_wr_lat=1000,pg_rd_lat=1000,blk_er_lat=1000,"
            FEMU_LSM_KNOBS "kv_lsm_pinned_levels=0"
    });
    qos_add_test("kv-lsm-versions", "femu", femu_test_kv_lsm_versions,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=72,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,pg_wr_lat=1000,pg_rd_lat=1000,blk_er_lat=1000,"
            FEMU_LSM_KNOBS "kv_lsm_pinned_levels=0"
    });
    /* own device lines: qos reuses a QEMU whose line matches */
    qos_add_test("kv-lsm-stale", "femu", femu_test_kv_lsm_stale,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=16,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=88,pls_per_lun=1,luns_per_ch=1,"
            "nchs=8," FEMU_LSM_KNOBS "kv_lsm_pinned_levels=0"
    });
    /* one value a page: the counts and times below are of value pages */
    qos_add_test("kv-lsm-meta-flash", "femu", femu_test_kv_lsm_meta_flash,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=16,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=96,pls_per_lun=1,luns_per_ch=1,"
            "nchs=8," FEMU_LSM_KNOBS "kv_lsm_pinned_levels=0,kv_pack=off"
    });
    qos_add_test("kv-lsm-delete-ednek", "femu", femu_test_kv_lsm_delete_ednek,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=16,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=8," FEMU_LSM_KNOBS "kv_lsm_pinned_levels=0"
    });
    qos_add_test("kv-pack-pages", "femu", femu_test_kv_pack_pages,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=16,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=64,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,pg_wr_lat=1000,pg_rd_lat=1000,blk_er_lat=1000",
        .arg = (void *)1,
    });
    qos_add_test("kv-pack-off", "femu", femu_test_kv_pack_pages,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=16,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=64,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,pg_wr_lat=1000,pg_rd_lat=1000,blk_er_lat=1000,"
            "kv_pack=off"
    });
    qos_add_test("kv-pack-overwrite", "femu", femu_test_kv_pack_overwrite,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=16,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=64,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,pg_wr_lat=1000,pg_rd_lat=1000,blk_er_lat=1000",
        .arg = (void *)1,
    });
    qos_add_test("kv-pack-overwrite-off", "femu",
                 femu_test_kv_pack_overwrite, &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=16,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=64,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,pg_wr_lat=1000,pg_rd_lat=1000,blk_er_lat=1000,"
            "kv_pack=off"
    });
    qos_add_test("kv-pack-flush", "femu", femu_test_kv_pack_flush,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=16,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=64,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,pg_wr_lat=1000,pg_rd_lat=1000,blk_er_lat=1000,vwc=1"
    });
    qos_add_test("kv-pack-flush-wait", "femu", femu_test_kv_pack_flush_wait,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=16,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=64,pls_per_lun=1,luns_per_ch=1,"
            "nchs=2,pg_wr_lat=200000000,pg_rd_lat=1000,blk_er_lat=1000,"
            "vwc=1"
    });
    qos_add_test("kv-pack-query", "femu", femu_test_kv_pack_query,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=16,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=64,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,pg_wr_lat=1000,pg_rd_lat=1000,blk_er_lat=1000,vwc=1",
        .arg = (void *)1,
    });
    qos_add_test("kv-pack-query-off", "femu", femu_test_kv_pack_query,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "devsz_mb=16,femu_mode=5,kv_pack=off"
    });
    qos_add_test("kv-pack-lsm-stale", "femu", femu_test_kv_pack_lsm_stale,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=4,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=64,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,pg_wr_lat=1000,pg_rd_lat=1000,blk_er_lat=1000,"
            FEMU_LSM_KNOBS "kv_lsm_pinned_levels=0"
    });
    qos_add_test("kv-pack-read-time", "femu", femu_test_kv_pack_read_time,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=16,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=64,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,pg_wr_lat=1000,pg_rd_lat=20000000,blk_er_lat=1000,"
            FEMU_LSM_KNOBS "kv_lsm_pinned_levels=24"
    });
    qos_add_test("kv-pack-gc", "femu", femu_test_kv_pack_gc,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=48,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,pg_wr_lat=1000,pg_rd_lat=1000,blk_er_lat=1000"
    });
    qos_add_test("kv-pack-gc-lsm", "femu", femu_test_kv_pack_gc,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=5,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=48,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,pg_wr_lat=1000,pg_rd_lat=1000,blk_er_lat=1000,"
            FEMU_LSM_KNOBS "kv_lsm_pinned_levels=0",
        .arg = (void *)1,
    });
    qos_add_test("oc20-page-types-on", "femu", femu_test_oc20_page_types,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=1024,femu_mode=0,lver=2,lnum_ch=3,lnum_lun=5,"
            "lsecs_per_pg=4,lpgs_per_blk=256,learly_reset=1,"
            "oc20_page_types=on",
        .arg = (void *)1,
    });
    qos_add_test("namespace-sizes-rounding", "femu",
                 femu_test_namespace_sizes_rounding, NULL);
    qos_add_test("fdp-csd-knobs", "femu", femu_test_fdp_csd_knobs, NULL);
    qos_add_test("fdp-knobs-refused", "femu", femu_test_fdp_knobs_refused,
                 NULL);
    qos_add_test("fdp-csd-runs", "femu", femu_test_fdp_csd_runs,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=4,fdm_size=16,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,"
            "nchs=4,subsys=fdpsub"
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
    qos_add_test("intc", "femu", femu_test_intc, NULL);
    qos_add_test("intc-msix-held", "femu", femu_test_intc_msix,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=ich",
        .arg = (void *)"held",
    });
    qos_add_test("intc-shared-delete", "femu", femu_test_intc_shared,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=isd",
        .arg = (void *)"delete",
    });
    qos_add_test("intc-shared-ien", "femu", femu_test_intc_shared,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=isi",
        .arg = (void *)"ien",
    });
    qos_add_test("intc-msix-clear", "femu", femu_test_intc_msix,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=icc",
        .arg = (void *)"clear",
    });
    qos_add_test("intc-bbssd", "femu", femu_test_intc,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1,devsz_mb=64"
    });
    qos_add_test("io-stages", "femu", femu_test_io_stages,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,devsz_mb=64,pg_rd_lat=3000000,io_stages=on",
        .arg = (void *)"3ms",
    });
    qos_add_test("ocp-die-offline", "femu", femu_test_ocp_die_offline,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"parity",
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "pg_rd_lat=100000000,die_parity=1,parity_xor_ns=50000000,"
            "ocp=on,inject_die=3"
    });
    qos_add_test("ocp-die-offline-noparity", "femu",
                 femu_test_ocp_die_offline, &(QOSGraphTestOptions) {
        .arg = (void *)"noparity",
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "read_cache_mb=1,ocp=on,inject_die=3"
    });
    qos_add_test("rain-ro-base", "femu", femu_test_rain_ro,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"base",
        .edge.extra_device_opts =
            "id=gc-test,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "luns_per_ch=2,nchs=2,pls_per_lun=1,rain_parity=1,mdts=4,"
            "devsz_mb=1,blks_per_pl=44,gc_thres_pcent_high=78,"
            "rain_rebuild=on,rain_read_only=on"
    });
    qos_add_test("rain-ro-off", "femu", femu_test_rain_ro,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts =
            "id=gc-test,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "luns_per_ch=2,nchs=2,pls_per_lun=1,rain_parity=1,mdts=4,"
            "devsz_mb=1,blks_per_pl=41,gc_thres_pcent_high=78,"
            "rain_rebuild=on"
    });
    qos_add_test("rain-ro-zero", "femu", femu_test_rain_ro,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"zero",
        .edge.extra_device_opts =
            "id=gc-test,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "luns_per_ch=2,nchs=2,pls_per_lun=1,rain_parity=1,mdts=4,"
            "devsz_mb=1,blks_per_pl=44,gc_thres_pcent_high=80,"
            "rain_rebuild=on,rain_read_only=on"
    });
    qos_add_test("rain-ro-round", "femu", femu_test_rain_ro,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"round",
        .edge.extra_device_opts =
            "id=gc-test,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "luns_per_ch=2,nchs=2,pls_per_lun=1,rain_parity=1,mdts=4,"
            "devsz_mb=16,blks_per_pl=263,gc_thres_pcent_high=99,"
            "rain_read_only=on"
    });
    qos_add_test("rain-ro-gc", "femu", femu_test_rain_ro,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"gc",
        .edge.extra_device_opts =
            "id=gc-test,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "luns_per_ch=2,nchs=2,pls_per_lun=1,rain_parity=1,mdts=4,"
            "devsz_mb=2,blks_per_pl=44,gc_thres_pcent_high=100,"
            "rain_read_only=on"
    });
    qos_add_test("rain-ro-held", "femu", femu_test_rain_ro,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"held",
        .edge.extra_device_opts =
            "id=gc-test,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "luns_per_ch=2,nchs=2,pls_per_lun=1,rain_parity=1,mdts=4,"
            "devsz_mb=2,blks_per_pl=44,gc_thres_pcent=100,"
            "gc_thres_pcent_high=100,rain_read_only=on"
    });
    qos_add_test("rain-ro-refused", "femu", femu_test_rain_ro_refused, NULL);
    qos_add_test("rain-loss-base", "femu", femu_test_rain_loss,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"base",
        .edge.extra_device_opts =
            "id=gc-test,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "luns_per_ch=2,nchs=2,pls_per_lun=1,rain_parity=1,mdts=4,"
            "devsz_mb=1,blks_per_pl=64,gc_thres_pcent_high=78,oncs=415,"
            "rain_read_only=on,rain_loss=on"
    });
    qos_add_test("rain-loss-partial", "femu", femu_test_rain_loss,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"partial",
        .edge.extra_device_opts =
            "id=gc-test,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "luns_per_ch=2,nchs=2,pls_per_lun=1,rain_parity=1,mdts=4,"
            "devsz_mb=1,blks_per_pl=64,gc_thres_pcent_high=78,oncs=415,"
            "rain_read_only=on,rain_loss=on"
    });
    qos_add_test("rain-loss-wu", "femu", femu_test_rain_loss,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"wu",
        .edge.extra_device_opts =
            "id=gc-test,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "luns_per_ch=2,nchs=2,pls_per_lun=1,rain_parity=1,mdts=4,"
            "devsz_mb=1,blks_per_pl=64,gc_thres_pcent_high=78,oncs=415,"
            "rain_read_only=on,rain_loss=on"
    });
    qos_add_test("rain-loss-trim", "femu", femu_test_rain_loss,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"trim",
        .edge.extra_device_opts =
            "id=gc-test,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "luns_per_ch=2,nchs=2,pls_per_lun=1,rain_parity=1,mdts=4,"
            "devsz_mb=1,blks_per_pl=64,gc_thres_pcent_high=78,oncs=415,"
            "rain_read_only=on,rain_loss=on"
    });
    qos_add_test("rain-loss-copy", "femu", femu_test_rain_loss,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"copy",
        .edge.extra_device_opts =
            "id=gc-test,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "luns_per_ch=2,nchs=2,pls_per_lun=1,rain_parity=1,mdts=4,"
            "devsz_mb=1,blks_per_pl=64,gc_thres_pcent_high=78,oncs=415,"
            "rain_read_only=on,rain_loss=on"
    });
    qos_add_test("rain-loss-sanitize", "femu", femu_test_rain_loss,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"sanitize",
        .edge.extra_device_opts =
            "id=gc-test,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "luns_per_ch=2,nchs=2,pls_per_lun=1,rain_parity=1,mdts=4,"
            "devsz_mb=1,blks_per_pl=64,gc_thres_pcent_high=78,oncs=415,"
            "rain_read_only=on,rain_loss=on"
    });
    qos_add_test("rain-loss-hold", "femu", femu_test_rain_loss,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"hold",
        .edge.extra_device_opts =
            "id=gc-test,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "luns_per_ch=2,nchs=2,pls_per_lun=1,rain_parity=1,mdts=4,"
            "devsz_mb=1,blks_per_pl=64,gc_thres_pcent_high=78,oncs=415,"
            "rain_read_only=on,rain_loss=on"
    });
    qos_add_test("rain-loss-off", "femu", femu_test_rain_loss,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts =
            "id=gc-test,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "luns_per_ch=2,nchs=2,pls_per_lun=1,rain_parity=1,mdts=4,"
            "devsz_mb=1,blks_per_pl=64,gc_thres_pcent_high=78,oncs=415,"
            "rain_read_only=on"
    });
    qos_add_test("rain-loss-props", "femu", femu_test_rain_loss_props,
                 NULL);
    qos_add_test("rain-inject-base", "femu", femu_test_rain_inject,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"base",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=8,luns_per_ch=2,nchs=2,rain_parity=1,"
            "blks_per_pl=44,pls_per_lun=1,ocp=on,inject_die=1"
    });
    qos_add_test("rain-inject-pending", "femu", femu_test_rain_inject,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"pending",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=8,luns_per_ch=2,nchs=2,rain_parity=1,"
            "blks_per_pl=44,pls_per_lun=1,ocp=on,inject_die=1"
    });
    qos_add_test("rain-inject-open", "femu", femu_test_rain_inject,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"open",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=8,luns_per_ch=2,nchs=2,rain_parity=1,"
            "blks_per_pl=44,pls_per_lun=1,ocp=on,inject_die=0"
    });
    qos_add_test("rain-inject-old", "femu", femu_test_rain_inject,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"old",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=8,luns_per_ch=2,nchs=2,rain_parity=1,"
            "blks_per_pl=44,pls_per_lun=1,ocp=on,inject_die=1"
    });
    qos_add_test("rain-inject-same", "femu", femu_test_rain_inject,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"same",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=8,luns_per_ch=2,nchs=2,rain_parity=1,"
            "blks_per_pl=44,pls_per_lun=1,ocp=on,inject_die=1"
    });
    qos_add_test("rain-inject-trim", "femu", femu_test_rain_inject,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"trim",
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=8,luns_per_ch=2,nchs=2,rain_parity=1,"
            "blks_per_pl=44,pls_per_lun=1,ocp=on,inject_die=1"
    });
    qos_add_test("ocp-die-offline-off", "femu", femu_test_ocp_die_offline,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts =
            "devsz_mb=1,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=40,pls_per_lun=1,luns_per_ch=2,nchs=2,inject_die=3"
    });
    qos_add_test("ocp-on", "femu", femu_test_ocp,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1,devsz_mb=64,ocp=on",
        .arg = (void *)"on",
    });
    qos_add_test("fw-update", "femu", femu_test_fw_update,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=fw-test,femu_mode=1,devsz_mb=64,"
            "fw_slots=3,buffer_size=4,power_loss=on",
    });
    qos_add_test("fw-ocp", "femu", femu_test_fw_ocp,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=fw-ocp,femu_mode=1,devsz_mb=64,ocp=on",
    });
    qos_add_test("ocp-hwcomp", "femu", femu_test_ocp_hwcomp,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=hwc,femu_mode=1,devsz_mb=64,ocp=on",
    });
    qos_add_test("ocp-caps", "femu", femu_test_ocp_caps,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=caps,femu_mode=1,devsz_mb=64,ocp=on",
    });
    qos_add_test("thermal-throttle", "femu", femu_test_thermal_throttle,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=thr,femu_mode=1,devsz_mb=64,"
            "temperature=300,thermal_tau_ms=100,thermal_r=1,throttle=on,"
            "throttle_light_pct=150,throttle_heavy_pct=300,"
            "pg_rd_lat=50000000",
    });
    qos_add_test("thermal-ocp", "femu", femu_test_thermal_ocp,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=thro,femu_mode=1,devsz_mb=64,ocp=on,"
            "temperature=300,thermal_tau_ms=100,thermal_r=1,throttle=on",
    });
    qos_add_test("ana", "femu", femu_test_ana,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=anac,ana=on,femu_mode=1,devsz_mb=64",
    });
    qos_add_test("ana-off", "femu", femu_test_ana_off, NULL);
    qos_add_test("l2p-dram-on", "femu", femu_test_l2p_dram,
                 &(QOSGraphTestOptions) {
        .arg = (void *)1,
        .edge.extra_device_opts = "id=l2p-on,femu_mode=1,devsz_mb=64,"
            "l2p_dram_ns=2000000",
    });
    qos_add_test("l2p-dram-off", "femu", femu_test_l2p_dram,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=l2p-off,femu_mode=1,devsz_mb=64",
    });
    qos_add_test("power-states", "femu", femu_test_power_states,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=pwr,femu_mode=1,devsz_mb=64,"
            "power_states=on,pg_rd_lat=1000000",
    });
    qos_add_test("power-states-off", "femu", femu_test_power_states_off,
                 NULL);
    qos_add_test("power-limit", "femu", femu_test_power_limit,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=pwr,femu_mode=1,devsz_mb=64,"
            "power_states=on,power_limit=on,ps_max_watts=15,"
            "pg_rd_lat=1000000",
    });
    qos_add_test("power-limit-apst", "femu", femu_test_power_limit_apst,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=pwr-apst,femu_mode=1,devsz_mb=64,"
            "power_states=on,power_limit=on,ps_max_watts=15",
    });
    qos_add_test("power-limit-sysreset", "femu",
                 femu_test_power_limit_sysreset, NULL);
    qos_add_test("ns-wp", "femu", femu_test_ns_wp,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=nswp,femu_mode=1,devsz_mb=16,"
            "namespaces=2,oncs=0x19f,ns_wp=on",
    });
    qos_add_test("ns-wp-buffer", "femu", femu_test_ns_wp_buffer,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=power,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=1,buffer_size=16,vwc=1,power_loss=on,ns_wp=on"
    });
    qos_add_test("ns-wp-drain", "femu", femu_test_ns_wp_drain,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=wpd,femu_mode=1,devsz_mb=16,ns_wp=on",
    });
    qos_add_test("ns-wp-streams", "femu", femu_test_ns_wp_streams,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=nswps,femu_mode=1,devsz_mb=16,"
            "streams=on,streams.max=4,namespaces=2,ns_wp=on",
    });
    qos_add_test("ns-wp-off", "femu", femu_test_ns_wp_off, NULL);
    qos_add_test("sanitize-ns", "femu", femu_test_sanitize_ns,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=sanns,femu_mode=1,devsz_mb=16,"
            "namespaces=2,sanitize_ops=on,sanitize_ns=on,sanitize_ms=200",
    });
    qos_add_test("sanitize-ns-refused", "femu", femu_test_sanitize_ns_refused,
                 NULL);
    qos_add_test("durable-at-done", "femu", femu_test_durable_at_done,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=power,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=1,buffer_size=16,vwc=1,power_loss=on,"
            "durable_at_done=on,pg_wr_lat=2000000000"
    });
    qos_add_test("durable-vwc-off", "femu", femu_test_durable_vwc_off,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=power,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=1,buffer_size=16,vwc=1,power_loss=on,"
            "durable_at_done=on,pg_wr_lat=2000000000"
    });
    qos_add_test("durable-partial", "femu", femu_test_durable_partial,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=power,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=1,buffer_size=16,vwc=1,power_loss=on,oncs=0x1f,"
            "durable_at_done=on,pg_wr_lat=2000000000"
    });
    qos_add_test("durable-partial2", "femu", femu_test_durable_partial2,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=power,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=1,buffer_size=16,vwc=1,power_loss=on,oncs=0x1f,"
            "durable_at_done=on,pg_wr_lat=2000000000"
    });
    qos_add_test("durable-stall", "femu", femu_test_durable_stall,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=power,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "femu_mode=1,buffer_size=3,vwc=1,power_loss=on,"
            "durable_at_done=on,pg_wr_lat=500000000"
    });
    qos_add_test("durable-wz-copy", "femu", femu_test_durable_wz_copy,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=power,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=1,buffer_size=16,vwc=1,power_loss=on,oncs=0x11f,"
            "durable_at_done=on,pg_wr_lat=2000000000"
    });
    qos_add_test("durable-refused", "femu", femu_test_durable_refused,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=power,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=1,buffer_size=16,vwc=1,power_loss=on,"
            "durable_at_done=on"
    });
    qos_add_test("sdc-check", "femu", femu_test_sdc,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"on",
        .edge.extra_device_opts =
            "id=power,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=1,buffer_size=16,vwc=1,power_loss=on,sdc=on,ocp=on"
    });
    qos_add_test("sdc-silent", "femu", femu_test_sdc,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts =
            "id=power,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=1,buffer_size=16,vwc=1,power_loss=on,sdc=on,"
            "e2e_check=off,sdc_kind=mix,sdc_seed=7,ocp=on"
    });
    qos_add_test("awupf-control", "femu", femu_test_awupf,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"off",
        .edge.extra_device_opts =
            "id=power,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=1,buffer_size=15,vwc=1,power_loss=on"
    });
    qos_add_test("awupf", "femu", femu_test_awupf,
                 &(QOSGraphTestOptions) {
        .arg = (void *)"on",
        .edge.extra_device_opts =
            "id=power,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=1,buffer_size=16,vwc=1,power_loss=on,awupf_lbas=8"
    });
    qos_add_test("plp-keep", "femu", femu_test_plp_keep,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=power,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=1,buffer_size=16,vwc=0,power_loss=on,plp=on,"
            "ocp=on,pg_wr_lat=2000000000"
    });
    qos_add_test("plp-fail-rom", "femu", femu_test_plp_fail_rom,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=power,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=1,buffer_size=16,vwc=0,power_loss=on,plp=on,"
            "ocp=on,ocp_profile=BAABAAAAAABAB"
    });
    qos_add_test("plp-fail-wtm", "femu", femu_test_plp_fail_wtm,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=power,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=1,buffer_size=16,vwc=1,power_loss=on,plp=on,"
            "plp_fail_mode=wtm,pg_wr_lat=2000000000"
    });
    qos_add_test("plp-fail-normal", "femu", femu_test_plp_fail_normal,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=power,devsz_mb=8,secsz=512,secs_per_pg=8,pgs_per_blk=8,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=2,nchs=2,"
            "femu_mode=1,buffer_size=16,vwc=0,power_loss=on,plp=on,"
            "plp_fail_mode=normal,plp_health=0,ocp=on,"
            "ocp_profile=BAABAAAAAABAB"
    });
    qos_add_test("io-stages-ns", "femu", femu_test_io_stages_ns,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=stns,femu_mode=1,devsz_mb=16,"
            "namespaces=2,io_stages=on,stage_ns=on,pg_rd_lat=3000000",
    });
    qos_add_test("io-causes", "femu", femu_test_io_causes,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1,devsz_mb=16,io_stages=on,"
            "io_causes=on,pg_wr_lat=200000000,oncs=12",
    });
    qos_add_test("io-causes-refused", "femu", femu_test_io_causes_refused,
                 NULL);
    qos_add_test("io-causes-flush", "femu", femu_test_io_causes_flush,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=16,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=64,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,nchs=1,"
            "pg_wr_lat=1000000000,vwc=1,buffer_size=8,buffer_thres_pcent=100,"
            "namespaces=2,ns_wp=on,io_stages=on,stage_ns=on,io_causes=on",
    });
    {
        static const char *merges[][2] = {
            { "hybrid", "hybrid,blk_er_lat=2000000" },
            { "fast", "fast,blk_er_lat=2000000" },
            { "switch", "hybrid,blk_er_lat=100000000" },
        };

        for (int i = 0; i < ARRAY_SIZE(merges); i++) {
            g_autofree char *name = g_strdup_printf("io-causes-merge-%s",
                                                    merges[i][0]);
            g_autofree char *mopts = g_strdup_printf(
                "devsz_mb=1,femu_mode=1,mapping=%s,secsz=512,"
                "secs_per_pg=8,pgs_per_blk=4,blks_per_pl=128,pls_per_lun=1,"
                "luns_per_ch=1,nchs=1,buffer_size=0,pg_rd_lat=40000,"
                "pg_wr_lat=20000000,io_stages=on,io_causes=on",
                merges[i][1]);

            qos_add_test(name, "femu", femu_test_io_causes_merge,
                         &(QOSGraphTestOptions) {
                .edge.extra_device_opts = mopts,
                .arg = (void *)merges[i][0],
            });
        }
    }
    qos_add_test("io-causes-retry", "femu", femu_test_io_causes_retry,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=rber-test,femu_mode=1,devsz_mb=3,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
            "nchs=1,rber_ppb=1,rr_steps=2,rr_soft_ns=10000000,"
            "pg_rd_lat=100000000,io_stages=on,io_causes=on",
    });
    qos_add_test("io-causes-map", "femu", femu_test_io_causes_map,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=16,femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=64,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,nchs=1,"
            "pg_rd_lat=50000000,pg_wr_lat=20000000,mapping=dftl,"
            "x-cmt-slots=1,io_stages=on,io_causes=on",
    });
    {
        static const char *hmbs[] = { "5000", "1000", "1001", "serial",
                                      "buffer" };
        static const char *extra[] = { "", "", "", ",hot_cold_sep=on",
            ",hot_cold_sep=on,vwc=1,buffer_size=2,buffer_thres_pcent=50" };

        for (int i = 0; i < ARRAY_SIZE(hmbs); i++) {
            g_autofree char *name = g_strdup_printf("io-causes-hmb-%s",
                                                    hmbs[i]);
            g_autofree char *hopts = g_strdup_printf(
                "devsz_mb=16,femu_mode=1,secsz=512,secs_per_pg=8,"
                "pgs_per_blk=64,blks_per_pl=80,pls_per_lun=1,luns_per_ch=1,"
                "nchs=1,pg_wr_lat=20000000,mapping=dftl,x-cmt-slots=1,"
                "hmb_mb=1,hmb_ns=%s,io_stages=on,io_causes=on%s",
                g_ascii_isdigit(hmbs[i][0]) ? hmbs[i] : "5000", extra[i]);

            qos_add_test(name, "femu", femu_test_io_causes_hmb,
                         &(QOSGraphTestOptions) {
                .edge.extra_device_opts = hopts,
                .arg = (void *)hmbs[i],
            });
        }
    }
    qos_add_test("io-stages-ns-refused", "femu",
                 femu_test_io_stages_ns_refused, &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1,devsz_mb=16,io_stages=on",
    });
    qos_add_test("shared-ftl", "femu", femu_test_shared_ftl,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=shftl,femu_mode=1,devsz_mb=1,"
            "secsz=512,secs_per_pg=8,pgs_per_blk=8,blks_per_pl=12,"
            "pls_per_lun=1,luns_per_ch=2,nchs=2,namespaces=2,shared_ftl=on",
    });
    qos_add_test("shared-ftl-format", "femu", femu_test_shared_ftl_format,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=shftl,femu_mode=1,devsz_mb=1,"
            "secsz=512,secs_per_pg=8,pgs_per_blk=8,blks_per_pl=12,"
            "pls_per_lun=1,luns_per_ch=2,nchs=2,namespaces=2,shared_ftl=on",
    });
    qos_add_test("shared-ftl-buffer", "femu", femu_test_shared_ftl_buffer,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=shftl,femu_mode=1,devsz_mb=1,"
            "secsz=512,secs_per_pg=8,pgs_per_blk=8,blks_per_pl=12,"
            "pls_per_lun=1,luns_per_ch=2,nchs=2,namespaces=2,shared_ftl=on,"
            "buffer_size=16,vwc=1",
    });
    qos_add_test("shared-ftl-refused", "femu", femu_test_shared_ftl_refused,
                 NULL);
    qos_add_test("cancel-deferred", "femu", femu_test_cancel_deferred,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=cancel,femu_mode=1,devsz_mb=16,"
            "namespaces=2,cancel=on",
    });
    qos_add_test("cancel-immediate", "femu", femu_test_cancel_immediate,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=cancel,femu_mode=1,devsz_mb=16,"
            "cancel=on",
    });
    qos_add_test("cancel-stages", "femu", femu_test_cancel_stages,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=cancel,femu_mode=1,devsz_mb=16,"
            "io_stages=on,stage_ns=on,pg_rd_lat=100000000,cancel=on",
    });
    qos_add_test("cancel-checks", "femu", femu_test_cancel_checks,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=cancel,femu_mode=1,devsz_mb=16,"
            "namespaces=2,cancel=on",
    });
    qos_add_test("cancel-nossd", "femu", femu_test_cancel_nossd,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=cancel,femu_mode=2,devsz_mb=16,"
            "fw_cpu_ns=1000,cancel=on",
    });
    qos_add_test("cancel-refused", "femu", femu_test_cancel_refused,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1,devsz_mb=16",
    });
    qos_add_test("fused-refused", "femu", femu_test_fused_refused,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1,devsz_mb=16,oncs=0x19f",
    });
    qos_add_test("ns-wp-refused", "femu", femu_test_ns_wp_refused, NULL);
    qos_add_test("power-limit-off", "femu", femu_test_power_limit_off,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1,power_states=on",
    });
    qos_add_test("power-limit-refused", "femu", femu_test_power_limit_refused,
                 NULL);
    qos_add_test("plane-reads", "femu", femu_test_plane_reads, NULL);
    qos_add_test("plane-reads-on", "femu", femu_test_plane_reads_timing,
                 &(QOSGraphTestOptions) {
        .arg = (void *)1,
        .edge.extra_device_opts = "id=prd-on,femu_mode=1,devsz_mb=4,"
            "secsz=512,secs_per_pg=8,pgs_per_blk=16,luns_per_ch=1,nchs=1,"
            "pls_per_lun=2,blks_per_pl=40,pg_rd_lat=5000000,plane_reads=on",
    });
    qos_add_test("plane-reads-off", "femu", femu_test_plane_reads_timing,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=prd-off,femu_mode=1,devsz_mb=4,"
            "secsz=512,secs_per_pg=8,pgs_per_blk=16,luns_per_ch=1,nchs=1,"
            "pls_per_lun=2,blks_per_pl=40,pg_rd_lat=5000000",
    });
    qos_add_test("throttle-refused", "femu", femu_test_throttle_refused,
                 NULL);
    qos_add_test("fw-refused", "femu", femu_test_fw_refused,
                 &(QOSGraphTestOptions) {
        .before = femu_ocp_before,
    });
    qos_add_test("ocp-latency", "femu", femu_test_ocp_latency,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=lat-test,femu_mode=1,devsz_mb=64,"
            "ocp=on,pg_rd_lat=40000000",
    });
    qos_add_test("ocp-extcaps-on", "femu", femu_test_ocp_extcaps,
                 &(QOSGraphTestOptions) { .arg = (void *)"on" });
    qos_add_test("ocp-extcaps-off", "femu", femu_test_ocp_extcaps,
                 &(QOSGraphTestOptions) { .arg = (void *)"off" });
    qos_add_test("ocp-pcie-on", "femu", femu_test_ocp_pcie,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1,devsz_mb=64,ocp=on",
        .arg = (void *)"on",
    });
    qos_add_test("ocp-pcie-off", "femu", femu_test_ocp_pcie,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1,devsz_mb=64",
        .arg = (void *)"off",
    });
    qos_add_test("ocp-off", "femu", femu_test_ocp,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1,devsz_mb=64",
        .arg = (void *)"off",
    });
    qos_add_test("ocp-refused", "femu", femu_test_ocp_refused,
                 &(QOSGraphTestOptions) {
        .before = femu_ocp_before,
    });
    qos_add_test("io-stages-overlap", "femu", femu_test_io_stages_overlap,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=stage-test,femu_mode=1,devsz_mb=64,"
            "pg_rd_lat=3000000,io_stages=on",
    });
    qos_add_test("io-stages-zero", "femu", femu_test_io_stages,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,devsz_mb=64,pg_rd_lat=0,io_stages=on",
        .arg = (void *)"zero",
    });
    qos_add_test("io-stages-off", "femu", femu_test_io_stages, NULL);
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
    qos_add_test("sanitize-bg", "femu", femu_test_sanitize_bg,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1,devsz_mb=64,sanitize_ms=300,"
            "sanitize_ops=on",
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
    qos_add_test("fdp-dsm-empty", "femu", femu_test_fdp_dsm_empty,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "sgl=on,vwc=1,oncs=0x19f,subsys=fdpsub"
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
    qos_add_test("oc12-l2p-bounds", "femu", femu_test_oc12_l2p_bounds,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=oc12-l2p,femu_mode=0,lver=1"
    });
    qos_add_test("oc12-bad-blocks", "femu", femu_test_oc12_bad_blocks,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=0,lver=1,lsec_size=512,lsecs_per_pg=4,lnum_pln=2,"
            "lnum_ch=2,lnum_lun=2"
    });
    qos_add_test("oc12-trace-on", "femu", femu_test_oc12_trace,
                 &(QOSGraphTestOptions) {
        .arg = (void *)&femu_oc12_trace_want[0],
        .edge.extra_device_opts =
            "id=oc12-test,femu_mode=0,lver=1,oc12_channel_timing=on,"
            "flash_type=3,devsz_mb=16,lsec_size=512,lsecs_per_pg=4,"
            "lnum_pln=2,lnum_ch=2,lnum_lun=4,lpgs_per_blk=64"
    });
    qos_add_test("oc12-trace-off", "femu", femu_test_oc12_trace,
                 &(QOSGraphTestOptions) {
        .arg = (void *)&femu_oc12_trace_want[1],
        .edge.extra_device_opts =
            "id=oc12-test,femu_mode=0,lver=1,flash_type=3,devsz_mb=16,"
            "lsec_size=512,lsecs_per_pg=4,lnum_pln=2,lnum_ch=2,lnum_lun=4,"
            "lpgs_per_blk=64"
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
    qos_add_test("csd-cpslm-default", "femu", femu_test_cps_default,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=4,fdm_size=16"
    });
    qos_add_test("csd-cpslm-identify", "femu", femu_test_cps_identify,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = FEMU_CPS_OPTS
    });
    qos_add_test("csd-slm-rw", "femu", femu_test_cps_slm_rw,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = FEMU_CPS_OPTS ",sgl=on"
    });
    qos_add_test("csd-slm-copy", "femu", femu_test_cps_slm_copy,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = FEMU_CPS_OPTS
    });
    qos_add_test("csd-cp-admin", "femu", femu_test_cps_admin,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = FEMU_CPS_OPTS
    });
    qos_add_test("csd-cp-exec", "femu", femu_test_cps_exec,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = FEMU_CPS_OPTS
    });
    qos_add_test("csd-slm-atomic", "femu", femu_test_cps_slm_atomic,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = FEMU_CPS_OPTS ",multipoller_enabled=1"
    });
    qos_add_test("csd-slm-only", "femu", femu_test_cps_slm_only,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=4,namespaces=2,"
            "namespace_modes=nossd,,csd,fdm_size=16,csd_slm_size=4"
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
    qos_add_test("trace-events", "femu", femu_test_trace_events, NULL);
    qos_add_test("iu-rmw", "femu", femu_test_iu_rmw,
                 &(QOSGraphTestOptions) {
        .arg = (void *)1,
        .edge.extra_device_opts = "femu_mode=1,devsz_mb=64,iu_pages=4",
    });
    qos_add_test("iu-rmw-off", "femu", femu_test_iu_rmw,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1,devsz_mb=64",
    });
    qos_add_test("buffer-bg", "femu", femu_test_buffer_bg,
                 &(QOSGraphTestOptions) {
        .arg = (void *)1,
        .edge.extra_device_opts = "femu_mode=1,devsz_mb=64,buffer_size=64,"
            "buffer_thres_pcent=90,buffer_low_pcent=25",
    });
    qos_add_test("buffer-flush-fence", "femu", femu_test_buffer_flush_fence,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1,devsz_mb=64,buffer_size=16,"
            "buffer_thres_pcent=90,buffer_low_pcent=1,pg_wr_lat=1000000000",
    });
    qos_add_test("buffer-vwc-drain", "femu", femu_test_buffer_vwc_drain,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1,devsz_mb=64,buffer_size=16,"
            "vwc=1,pg_wr_lat=1000000000",
    });
    qos_add_test("buffer-place-fail", "femu", femu_test_buffer_place_fail,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=bp,femu_mode=1,devsz_mb=64,"
            "buffer_size=16,buffer_thres_pcent=90",
    });
    qos_add_test("buffer-bg-off", "femu", femu_test_buffer_bg,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1,devsz_mb=64,buffer_size=64,"
            "buffer_thres_pcent=90",
    });
    qos_add_test("pci-pm", "femu", femu_test_pci_pm,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "pci_pm=on"
    });
    qos_add_test("pi64", "femu", femu_test_pi64,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "pif=2,pi=on,meta=16,mc=3,oncs=0x19f,mdts=1"
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
        .arg = GUINT_TO_POINTER(0x11),
        .edge.extra_device_opts = "pi=off,meta=0,dpc=0x11"
    });
    qos_add_test("pi-dpc-no-metadata", "femu", femu_test_pi_dpc_no_metadata,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "pi=on,meta=0,dpc=0x11"
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
    /*
     * gf: QEMU's generic fuzzer. These are plain tests, so their names leave
     * out "fuzz", which CI reads as a fuzz case.
     */
    qos_add_test("gf-mode", "femu", femu_test_fuzz_mode,
                 &(QOSGraphTestOptions) { .arg = GINT_TO_POINTER(1) });
    qos_add_test("gf-mode-bbssd", "femu", femu_test_fuzz_mode,
                 &(QOSGraphTestOptions) { .arg = GINT_TO_POINTER(2) });
    qos_add_test("gf-mode-off", "femu", femu_test_fuzz_mode,
                 &(QOSGraphTestOptions) { .arg = GINT_TO_POINTER(0) });
    qos_add_test("gf-control-refused", "femu",
                 femu_test_fuzz_control_refused, NULL);
    qos_add_test("self-test", "femu", femu_test_self_test, NULL);
    qos_add_test("verify", "femu", femu_test_verify,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "oncs=0x8e"
    });
    qos_add_test("abort", "femu", femu_test_abort,
                 &(QOSGraphTestOptions) {
        /* a mode with an FTL, whose poller fetches while completions wait */
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4"
    });
    qos_add_test("fid-effects", "femu", femu_test_fid_effects, NULL);
    qos_add_test("fid-effects-kv", "femu", femu_test_fid_effects_kv,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "devsz_mb=512,femu_mode=5"
    });
    qos_add_test("fid-effects-fdp", "femu", femu_test_fid_effects_fdp,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "subsys=fdpsub"
    });
    qos_add_test("cc-css", "femu", femu_test_cc_css, NULL);
    qos_add_test("admin-psdt", "femu", femu_test_admin_psdt, NULL);
    qos_add_test("media-dnr", "femu", femu_test_media_dnr,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "oncs=0x19f"
    });
    qos_add_test("frmw", "femu", femu_test_frmw, NULL);
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
    qos_add_test("fdp-ruh-usage", "femu", femu_test_fdp_ruh_usage,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,"
            "subsys=fdpsub"
    });
    qos_add_test("fdp-write-zeroes-placed", "femu",
                 femu_test_fdp_write_zeroes_placed,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=1,secsz=512,secs_per_pg=8,pgs_per_blk=16,"
            "blks_per_pl=80,pls_per_lun=1,luns_per_ch=4,nchs=4,lba_index=3,"
            "oncs=0xc,subsys=fdpsub",
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
    qos_add_test("zone-notice-other-ns", "femu",
                 femu_test_zone_notice_other_ns, &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=64,femu_mode=3,namespaces=2,secsz=512,zns_num_ch=1,"
            "zns_num_lun=1,zns_num_plane=2,zns_num_blk=32,"
            "err_write_fail_ppm=1000000"
    });
    qos_add_test("zone-list-ack-fail", "femu", femu_test_zone_list_ack_fail,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,zns_num_lun=1,"
            "zns_num_plane=2,zns_num_blk=32,err_write_fail_ppm=1000000"
    });
    qos_add_test("zone-list-ack-race", "femu", femu_test_zone_list_ack_race,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=qz,devsz_mb=32,femu_mode=3,secsz=512,zns_num_ch=1,"
            "zns_num_lun=1,zns_num_plane=2,zns_num_blk=32,"
            "err_write_fail_ppm=1000000"
    });
    qos_add_test("zone-notice-many-ns", "femu",
                 femu_test_zone_notice_many_ns, &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "devsz_mb=544,femu_mode=3,namespaces=17,secsz=512,zns_num_ch=1,"
            "zns_num_lun=1,zns_num_plane=2,zns_num_blk=32,"
            "err_write_fail_ppm=1000000"
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
    qos_add_test("poller-burst", "femu", femu_test_poller_burst, NULL);
    qos_add_test("poller-burst-per-queue", "femu", femu_test_poller_burst,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "multipoller_enabled=1"
    });
    qos_add_test("poller-burst-sharded", "femu", femu_test_poller_burst,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "multipoller_enabled=1,poller_ratio=3"
    });
    qos_add_test("config-refused", "femu", femu_test_config_refused, NULL);
    femu_csd_dir = g_strdup_printf("%s/femu-csd-%d", g_get_tmp_dir(),
                                   (int)getpid());
    qos_add_test("csd-program-dir", "femu", femu_test_csd_program_dir,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = g_strdup_printf(
            "femu_mode=4,fdm_size=16,csd_program_dir=%s", femu_csd_dir),
    });
    femu_cps_dir = g_strdup_printf("%s/femu-cps-%d", g_get_tmp_dir(),
                                   (int)getpid());
    qos_add_test("csd-cp-download", "femu", femu_test_cps_download,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = g_strdup_printf(
            FEMU_CPS_OPTS ",csd_program_dir=%s", femu_cps_dir),
    });
    qos_add_test("csd-cp-modeled", "femu", femu_test_cps_modeled,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = g_strdup_printf(
            FEMU_CPS_OPTS ",csf_runtime_scale=100,csd_program_dir=%s",
            femu_cps_dir),
    });
    qos_add_test("csd-cp-subsys-fdp", "femu", femu_test_cps_subsys,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = FEMU_CPS_OPTS ",subsys=fdpsub",
        .arg = (void *)1,
    });
    qos_add_test("csd-cp-subsys-endgrp", "femu", femu_test_cps_subsys,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = FEMU_CPS_OPTS ",subsys=nssub",
        .before = femu_ns_subsys_before,
    });
    qos_add_test("csd-slm-subsys-single", "femu",
                 femu_test_cps_subsys_single,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=4,fdm_size=16,csd_slm_size=4,subsys=nssub",
        .before = femu_ns_subsys_before,
        .arg = (void *)1,
    });
    qos_add_test("csd-slm-subsys-joins", "femu", femu_test_cps_subsys_single,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1,subsys=nssub," FEMU_CAPS_GEO,
        .before = femu_ns_subsys_before,
    });
    qos_add_test("csd-cp-mdts", "femu", femu_test_cps_mdts,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = g_strdup_printf(
            FEMU_CPS_OPTS ",mdts=1,csd_program_dir=%s", femu_cps_dir),
    });
    femu_csd_slow_dir = g_strdup_printf("%s/femu-csd-slow-%d",
                                        g_get_tmp_dir(), (int)getpid());
    femu_csd_warn_log = g_strdup_printf("%s/femu-csd-warn-%d.log",
                                        g_get_tmp_dir(), (int)getpid());
    qos_add_test("csd-runtime-floor", "femu", femu_test_csd_runtime_floor,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = g_strdup_printf(
            "femu_mode=4,fdm_size=16,nr_cu=1,csd_program_dir=%s",
            femu_csd_slow_dir),
        .before = femu_csd_warn_before,
    });
    qos_add_test("csd-pause", "femu", femu_test_csd_pause,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = g_strdup_printf(
            "id=csd-pause,femu_mode=4,fdm_size=16,nr_cu=1,"
            "csd_program_dir=%s,csd_pause=on", femu_csd_slow_dir),
        .arg = (void *)1,
    });
    qos_add_test("csd-pause-off", "femu", femu_test_csd_pause,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = g_strdup_printf(
            "id=csd-pause,femu_mode=4,fdm_size=16,nr_cu=1,"
            "csd_program_dir=%s", femu_csd_slow_dir),
    });
    qos_add_test("csd-opcodes", "femu", femu_test_csd_opcodes,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=4,fdm_size=16",
    });
    qos_add_test("csd-opcodes-legacy", "femu", femu_test_csd_opcodes,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=4,fdm_size=16,csd_legacy_opcodes=on",
        .arg = (void *)1,
    });
    qos_add_test("csd-no-namespace", "femu", femu_test_csd_no_namespace,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "femu_mode=4,fdm_size=16,namespace_modes=nossd",
    });
    qos_add_test("csd-exec-concurrency", "femu",
                 femu_test_csd_exec_concurrency,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = g_strdup_printf(
            "femu_mode=4,fdm_size=16,nr_cu=2,csf_runtime_scale=1,"
            "csd_program_dir=%s", femu_csd_slow_dir),
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
    qos_add_test("ns-mgmt-before-identify", "femu",
                 femu_test_ns_mgmt_before_identify, &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            /* each FTL holds 48 MiB, less than the end of namespace 2 */
            "ns_mgmt=on,namespaces=2,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=48,pls_per_lun=1,luns_per_ch=4,nchs=4",
    });
    qos_add_test("v2-refusals", "femu", femu_test_v2_refusals,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1,namespaces=3,"
            "namespace_modes=bbssd,,znssd,,kvssd," FEMU_CAPS_GEO,
    });
    qos_add_test("endgrp-reported", "femu", femu_test_endgrp_reported,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1,subsys=nssub,namespaces=2,"
            "namespace_modes=bbssd,,kvssd," FEMU_CAPS_GEO,
        .before = femu_ns_subsys_before,
    });
    qos_add_test("rotational-on", "femu", femu_test_rotational,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1,subsys=rotsub," FEMU_CAPS_GEO,
        .before = femu_rot_before,
        .arg = (void *)"on",
    });
    qos_add_test("rotational-on-vwc", "femu", femu_test_rotational,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1,subsys=rotsub,vwc=1,"
            FEMU_CAPS_GEO,
        .before = femu_rot_before,
        .arg = (void *)"on-vwc",
    });
    qos_add_test("rotational-off", "femu", femu_test_rotational,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1,subsys=rotsub-off,"
            FEMU_CAPS_GEO,
        .before = femu_rot_before,
        .arg = (void *)"off",
    });
    qos_add_test("rotational-refused", "femu", femu_test_rotational_refused,
                 &(QOSGraphTestOptions) {
        .before = femu_rot_before,
    });
    qos_add_test("endgrp-list-absent", "femu", femu_test_endgrp_list_absent,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "femu_mode=1," FEMU_CAPS_GEO,
    });
    qos_add_test("mdts-limit-512b", "femu", femu_test_g1_mdts_limit,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=g1-mdts,mdts=3",
        .arg = GUINT_TO_POINTER(512),
    });
    qos_add_test("mdts-limit-4k", "femu", femu_test_g1_mdts_limit,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=g1-mdts,mdts=3,lba_index=3",
        .arg = GUINT_TO_POINTER(4096),
    });
    qos_add_test("mdts-limit-bbssd", "femu", femu_test_g1_mdts_limit,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=g1-mdts,devsz_mb=4,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,mdts=3",
        .arg = GUINT_TO_POINTER(512),
    });
    qos_add_test("mdts0-16m", "femu", femu_test_g1_mdts0_large,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=g1-large,mdts=0",
    });
    qos_add_test("mdts0-16m-bbssd", "femu", femu_test_g1_mdts0_large,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=g1-large,devsz_mb=32,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=64,blks_per_pl=64,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,mdts=0",
    });
    qos_add_test("mdts0-big-lbaf", "femu", femu_test_g1_mdts_cap,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=g1-cap,mdts=0,nlbaf=8,lba_index=7",
        .arg = GUINT_TO_POINTER(65536),
    });
    qos_add_test("mdts-high-big-lbaf", "femu", femu_test_g1_mdts_cap,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=g1-cap,mdts=25,nlbaf=8",
        .arg = GUINT_TO_POINTER(512),
    });
    qos_add_test("queues-64", "femu", femu_test_g1_many_queues,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=g1-queues,queues=64",
    });
    qos_add_test("queues-64-pollers", "femu", femu_test_g1_many_queues,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=g1-queues,queues=64,multipoller_enabled=1,poller_ratio=24",
    });
    qos_add_test("queue-depth-4096", "femu", femu_test_g1_deep_queue,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=g1-depth,entries=4095",
    });
    qos_add_test("ring-capacity-nossd", "femu", femu_test_g1_ring_capacity,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=g1-ring,queues=17,entries=4095,fw_cpu_ns=1",
    });
    qos_add_test("ring-capacity-bbssd", "femu", femu_test_g1_ring_capacity,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=g1-ring,devsz_mb=4,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,queues=17,entries=4095",
    });
    qos_add_test("ring-full-bbssd", "femu", femu_test_g1_ring_full,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=g1-small,devsz_mb=4,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2",
    });
    qos_add_test("cq-full-deep-nossd", "femu", femu_test_g1_cq_backlog,
                 &(QOSGraphTestOptions) {
        .arg = (void *)&femu_g1_cqf_pow2,
        .edge.extra_device_opts = "id=g1-cqfull,fw_cpu_ns=1",
    });
    qos_add_test("cq-full-deep-bbssd", "femu", femu_test_g1_cq_backlog,
                 &(QOSGraphTestOptions) {
        .arg = (void *)&femu_g1_cqf_pow2,
        .edge.extra_device_opts =
            "id=g1-cqfull,devsz_mb=4,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2",
    });
    qos_add_test("cq-full-odd-nossd", "femu", femu_test_g1_cq_backlog,
                 &(QOSGraphTestOptions) {
        .arg = (void *)&femu_g1_cqf_odd,
        .edge.extra_device_opts = "id=g1-cqodd,fw_cpu_ns=1,entries=99",
    });
    qos_add_test("cq-full-odd-bbssd", "femu", femu_test_g1_cq_backlog,
                 &(QOSGraphTestOptions) {
        .arg = (void *)&femu_g1_cqf_odd,
        .edge.extra_device_opts =
            "id=g1-cqodd,devsz_mb=4,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=16,blks_per_pl=32,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,entries=99",
    });
    qos_add_test("fdp-256-handles", "femu", femu_test_g1_fdp_handles,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=4,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=640,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,subsys=g1sub",
    });
    qos_add_test("fdp-256-handles-list", "femu", femu_test_g1_fdp_handles,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts =
            "id=gc-test,devsz_mb=4,femu_mode=1,secsz=512,secs_per_pg=8,"
            "pgs_per_blk=4,blks_per_pl=640,pls_per_lun=1,luns_per_ch=2,"
            "nchs=2,subsys=g1sub,namespace_phls=255:128",
        .arg = (void *)"list",
    });
    qos_add_test("kv-value-max", "femu", femu_test_g1_kv_value_max,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=g1-kv,devsz_mb=512,femu_mode=5,mdts=9",
    });
    qos_add_test("kv-value-mdts", "femu", femu_test_g1_kv_value_mdts,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=g1-kv,devsz_mb=512,femu_mode=5,mdts=8",
    });
    qos_add_test("odd-dptr-layouts", "femu", femu_test_g1_dptr_layouts,
                 &(QOSGraphTestOptions) {
        .edge.extra_device_opts = "id=g1-dptr,sgl=on,oncs=0x5",
    });
    for (int i = 0; i < ARRAY_SIZE(femu_caps_cfgs); i++) {
        qos_add_test(femu_caps_cfgs[i].name, "femu", femu_test_caps,
                     &(QOSGraphTestOptions) {
            .edge.extra_device_opts = femu_caps_cfgs[i].opts,
            .before = femu_caps_cfgs[i].before,
            .arg = (void *)&femu_caps_cfgs[i],
        });
    }
    qos_add_test("dma-target-compare-status", "femu",
                 femu_test_dma_target_compare_status, NULL);
    qos_add_test("dma-target-prp1", "femu", femu_test_dma_target_prp1, NULL);
    qos_add_test("dma-target-prp-list", "femu",
                 femu_test_dma_target_prp_list, NULL);
    qos_add_test("dma-target-sgl", "femu", femu_test_dma_target_sgl, NULL);
    qos_add_test("dma-target-sgl-chain", "femu",
                 femu_test_dma_target_sgl_chain, NULL);
    qos_add_test("dma-target-single-prp", "femu",
                 femu_test_dma_target_single_prp, NULL);
    qos_add_test("dma-target-pause", "femu", femu_test_dma_target_pause,
                 NULL);
}

libqos_init(femu_register_nodes);
