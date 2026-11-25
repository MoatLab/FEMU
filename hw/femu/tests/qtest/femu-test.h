/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Shared part of the FEMU qtests: includes, macros, types, the helpers in
 * femu-test-common.c, and the test functions that femu-test.c registers.
 */

#ifndef FEMU_TEST_H
#define FEMU_TEST_H

#include "qemu/module.h"
#include "qemu/crc32c.h"
#include "qemu/host-utils.h"
#include "qemu/units.h"
#include "libqtest.h"
#include "qobject/qdict.h"
#include "qobject/qjson.h"
#include "qobject/qlist.h"
#include "qobject/qnum.h"
#include "qobject/qstring.h"
#include "libqos/qgraph.h"
#include "libqos/pci.h"
#include "libqos/libqos-pc.h"
#include "libqos/libqos-malloc.h"
#include "libqos/malloc-pc.h"
#include "libqos/pci-pc.h"
#include "block/nvme.h"
#include "hw/cxl/cxl_component.h"
#include "hw/cxl/cxl_device.h"
#include "hw/femu/tests/unit/hybrid-oracle.h"
#include "hw/femu/bbssd/ftl-precon-math.h"
#include "hw/femu/cxlssd/cca-abi.h"
#include "hw/femu/femu-hpke.h"
#include "standard-headers/linux/pci_regs.h"

#define FEMU_QSIZE          16
#define FEMU_DATA_SIZE      4096
#define FEMU_POLL_LIMIT_MS  10000
#define FEMU_CSI_KV         0x01    /* key-value command set */
#define FEMU_DSM_AD             0x04    /* Dataset Management: deallocate */
#define FEMU_SPARE_THRESHOLD    20      /* Available Spare Threshold reported */
#define FEMU_OC20_IDENTIFY      0xe2    /* Open-Channel 2.0 geometry */
#define FEMU_OC20_VECT_WRITE    0x91
#define FEMU_OC20_VECT_ERASE    0x90
#define FEMU_KV_CMD_STORE       0x01
#define FEMU_CMD_IO_MGMT_SEND   0x1d
#define FEMU_IOMS_RUH_UPDATE    0x01
#define FEMU_CMD_IO_MGMT_RECV   0x12
#define FEMU_IOMR_RUH_STATUS    0x01
#define FEMU_FDP_EVT_MEDIA_REALLOC        0x80
#define FEMU_FDP_EVT_RUH_MODIFIED         0x81
#define FEMU_KV_CMD_RETRIEVE    0x02
#define FEMU_CNS_CS_CTRL    0x06    /* command-set controller identify */
#define FEMU_CSI_ZONED      0x02    /* zoned namespace command set */
#define FEMU_CSI_KV         0x01    /* key value command set */
#define FEMU_CNS_IO_CMD_SET 0x1c    /* the command sets the controller has */
#define FEMU_LOG_CMD_EFFECTS 0x05
#define FEMU_CC_CSS_CSI     0x06    /* CC.CSS: a command set is selected */
#define FEMU_FEAT_CMD_SET_PROFILE       0x19
#define FEMU_CQ_IEN         0x02    /* Create CQ: interrupts enabled */

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
    /* admin completion queue entries when not FEMU_QSIZE */
    uint16_t acq_entries;
} FemuCtrlState;

/* status codes come back with the phase bit dropped; this strips DNR too */
#define FEMU_SC(status)     ((status) & 0x7ff)

/*
 * A non-contiguous queue divides by the entries per page, and a 64 KiB page
 * truncated to zero in a 16-bit field.
 */
#define FEMU_64K    0x10000ULL

/* the over threshold starts at WCTEMP, 343 K */
#define FEMU_WCTEMP 0x157

/*
 * Log page identifiers as hw/femu/nvme.h numbers them. This test compiles
 * against QEMU's own block/nvme.h, which names neither the mandatory
 * supported-pages list nor FEMU's vendor page.
 */
#define FEMU_LOG_SUPPORTED          0x00
#define FEMU_LOG_CHANGED_ZONE_LIST  0xbf
#define FEMU_LOG_FEMU_STATS         0xc0
#define FEMU_LOG_FDP_EVENTS         0x23

#define FEMU_FID_TIMESTAMP      0x0e

/*
 * A fixed, queue-depth-one workload with collection, and what the FTL charged
 * for it: commands, their summed modelled latency, host, NAND and relocated
 * pages, erases, the read, program and erase commands charged to the
 * media layer, and a digest of the order of the collected victims
 * (x-ftl-trace). Refactoring the FTL must not move these. Every count is
 * exact, and the digest tells apart two victim orders with equal counts.
 * The latency sum is only held to 25%: collection starts at the host time of
 * the request that triggered it, so how soon the next request arrives, which
 * depends on how loaded the host is, changes how long it waits.
 */
/*
 * A multi-plane variant of the trace below. want and base are the traces of
 * this device and of the same device with multi-plane commands off; seq_ns
 * and base_seq_ns are the modelled time of the phase before any collection.
 */
typedef struct FtlTraceMp {
    const char *want;
    const char *base;
    uint64_t seq_ns;
    uint64_t base_seq_ns;
} FtlTraceMp;

/*
 * A variant of the workload for the victim policies the plain trace does not
 * reach. The writes take the placement identifiers in @pids in turn, so more
 * than one handle holds victims. With @reread, a read of a random page
 * follows each overwrite. Each read adds a background collection pass and
 * read stress; @read_reclaims is the exact count log page C0h must report.
 * With @trim, the overwrites run twice with one deallocate between them,
 * which resets the whole device, and the mapping must hold exactly the pages
 * written after it.
 */
typedef struct FtlTraceVar {
    const char *want;
    int pids[2];
    int npids;
    bool reread;
    uint64_t read_reclaims;
    bool trim;
} FtlTraceVar;

#define FTL_TRACE_FIELDS 10

/*
 * The media timing query-femu reports. @onfi -1 means no "onfi-mode" key.
 * The bus phases are in the order of FemuMediaTiming.
 */
typedef struct FemuMediaWant {
    const char *name;
    const char *mode;
    bool staged;
    int onfi;
    uint64_t ns[20];
    bool order;
    bool hold;
    bool per_plane;
    bool sca;
    bool cache;
} FemuMediaWant;

#define FEMU_LOG_POWER_MEAS     0x25
#define FEMU_FID_POWER_MEAS     0x25

/*
 * The FTL maps bytes, so an 8 KiB write is two 4 KiB pages whatever the block
 * size, and a placement handle loses one block of writable capacity per block
 * written. Both used to take a block for a 512-byte sector.
 */
typedef struct FemuWideLba {
    uint8_t lbads;
    bool fdp;
} FemuWideLba;

/*
 * A Zone Append reads the zone's write pointer to decide where it lands and
 * then moves it. On queues that different pollers serve, two of them read the
 * same pointer unless the zone state is held still, and the controller reports
 * the same blocks to both: one write is lost. Appending from two queues at
 * once reported a duplicate on half the runs before the zone state took a
 * lock.
 */
/* entries per queue, so 255 commands can be in flight on each */
#define ZAP_QDEPTH  256

/* x-flush-check: sealed Flushes, Flush end, program end, seal waits */
enum {
    FLUSH_SEALS,
    FLUSH_DONE,
    FLUSH_PE_END,
    FLUSH_SEAL_WAITS,
    FLUSH_FIELDS,
};

/*
 * Check a completion queue of FEMU_SMALL_CQ entries that the host has not
 * read from, after more commands than it can hold were submitted: it holds
 * one entry fewer than its size, the first commands in order, and the last
 * slot untouched (Base 2.3, 3.3.1.2.1). Then read it one entry at a time,
 * returning each slot, and expect every command to complete in order.
 */
#define FEMU_SMALL_CQ   4

/* wait for a condition the main loop makes true from a bottom half */
#define FEMU_WAIT_FOR(cond)                                 \
    do {                                                    \
        int waited_ = 0;                                    \
        while (!(cond)) {                                   \
            g_assert_cmpint(waited_, <, FEMU_POLL_LIMIT_MS); \
            g_usleep(1000);                                 \
            waited_++;                                      \
        }                                                   \
    } while (0)

#define FEMU_FEAT_FDP           0x1d
#define FEMU_FEAT_FDP_EVENTS    0x1e
#define FEMU_FEAT_NUM_QUEUES    0x07

#define FEMU_CC_ENABLE      ((6 << 16) | (4 << 20) | 1)
#define FEMU_CC_SHN_NORMAL  (1 << 14)
#define FEMU_CSTS_SHST(x)   (((x) >> 2) & 3)

#define FEMU_LOG_ERROR_INFO     0x01
#define FEMU_LOG_SMART          0x02
#define FEMU_LOG_RAE            (1u << 15)

#define FEMU_CNS_NS_CS_INDEP    0x08

#define FEMU_LOG_SUPPORTED      0x00

#define FEMU_LOG_FDP_STATS      0x22

#define FEMU_ADM_SANITIZE       0x84

#define FEMU_CMD_COPY           0x19
#define FEMU_OVERLAP_IO_RANGE   0x187

#define FEMU_NS_INCOMPATIBLE    0x185

#define FEMU_FEAT_HBS           0x16

#define FEMU_MD_MS      8
#define FEMU_MD_NLBAF   5           /* the nlbaf default */
#define FEMU_FUZZ_SCALE_MAX 1000

#define FEMU_IO_FUZZ_ROUNDS 1000
#define FEMU_FUZZ_PAGES     32
#define FEMU_FUZZ_LISTS     8

/*
 * Rewrite the list pages at the top of the fuzz region: the lower half as
 * PRP entries, the upper half as SGL descriptors of every type. Segments
 * point back into the upper half and mostly hold one descriptor, so a walk
 * chains, loops or ends early.
 */
#define FEMU_FUZZ_PRP_LISTS (FEMU_FUZZ_LISTS / 2)
#define FEMU_FUZZ_SGL_DESCS ((FEMU_FUZZ_LISTS - FEMU_FUZZ_PRP_LISTS) * 256)

typedef struct FemuIoFuzz {
    int min_succeeded;
    bool zoned;         /* writes must land on a write pointer */
    int nruh;           /* placement handles, when writes may carry one */
} FemuIoFuzz;

#define FEMU_LOG_TELEMETRY_HOST 0x07

/* a small TCG token writer for the session qtest (Core 3.2.2.3) */
typedef struct FemuTb {
    uint8_t b[2048];
    uint32_t n;
} FemuTb;

#define FEMU_OPAL_LOCKING_SP    0x0000020500000002ull
#define FEMU_OPAL_LOCK1         0x0000080200030001ull
#define FEMU_OPAL_MBRCTL        0x0000080300000001ull

#define FEMU_ID_FNA             524
#define FEMU_FNA_CRYES          0x04

#define FEMU_ADM_GET_LBA_STATUS  0x86
#define FEMU_LSI_AER    (2 | 0x05 << 8 | 0x0e << 16)
#define FEMU_LSI_SEC    (1000 * 1000 * 1000LL)

typedef struct FemuOc12TraceWant {
    const uint64_t *trace;
    unsigned len;
} FemuOc12TraceWant;

#define FEMU_LOG_PEL            0x0d

typedef struct FemuIdentity {
    const char *serial;
    const char *model;
    /* a mode the controller did not take its name from, and its next serial */
    int other_mode;
    const char *other_serial;
} FemuIdentity;
#define FEMU_C0H_GC     16

typedef struct FemuWrrCase {
    const char *opts;       /* more -device femu options */
    uint32_t cc_ams;
    uint32_t arb;           /* feature 01h */
    int nr;
    uint8_t prio[4];        /* of SQ 1 to nr */
    int depth[4];
    const char *order;      /* sqids in fetch order */
} FemuWrrCase;

/* feature 01h with the weights and burst given */
#define FEMU_ARB(hpw, mpw, lpw, ab) \
    (((hpw) << 24) | ((mpw) << 16) | ((lpw) << 8) | (ab))

typedef struct FemuPreconCase {
    const char *opts;       /* more properties of both devices, or "" */
    uint32_t fill;
    uint32_t overwrite;
    bool seq;
    uint64_t seed;
    bool flush;             /* ref ends with a Flush (write buffer) */
    bool brk;               /* control: x-precon-break=1 on pre */
    bool short_ref;         /* control: ref writes one page fewer */
} FemuPreconCase;

/* persist-aging: a device of one test, its queues and buffers */
typedef struct FemuPa {
    QOSState *qs;
    QTestState *qts;
    QPCIDevice *pdev;
    FemuCtrlState c;
    uint64_t buf;
    uint64_t list;
    uint64_t log;
    GString *trace;     /* what the segments saw, in order */
} FemuPa;

enum {
    FEMU_STRESS_NONE,
    FEMU_STRESS_FLUSH,
    FEMU_STRESS_INVALIDATE,
    FEMU_STRESS_WAYS,
    FEMU_STRESS_CCA,
    FEMU_STRESS_UNPLUG,
};

typedef struct FemuCxlStress {
    const char *options;
    int race;
    /* Page offset between CPUs: 0 makes every CPU hit the same page. */
    uint64_t spread;
} FemuCxlStress;

#define FEMU_LINK_QUEUES    (1u << 16)

enum {
    FEMU_LINK_WRITE,
    FEMU_LINK_ZEROES,
    FEMU_LINK_COPY,
};

/*
 * The FTL owners of query-femu-memory. 384 physical pages: the L2P and the
 * reverse map take 8 bytes per page each. shared_ftl=on gives both
 * namespaces one FTL owner; without it each namespace has its own.
 */
#define FEMU_MEM_FTL "femu_mode=1,devsz_mb=1,secsz=512,secs_per_pg=8," \
                     "pgs_per_blk=8,blks_per_pl=12,pls_per_lun=1," \
                     "luns_per_ch=2,nchs=2"
/* 13 lines: DFTL keeps 5 of them, and 256 pages must still fit */
#define FEMU_MEM_FTL13 "femu_mode=1,devsz_mb=1,secsz=512,secs_per_pg=8," \
                       "pgs_per_blk=8,blks_per_pl=13,pls_per_lun=1," \
                       "luns_per_ch=2,nchs=2"

/*
 * A refused FDP controller leaves its subsystem as it found it, so the next
 * controller starts as it does on a new subsystem. The first refusal fails
 * the first FDP allocation, after the namespaces wrote the handles. The
 * second passes femu_realize() and fails in PCI on the romfile. Subsystem
 * "ctl" sees neither refusal and is the control.
 */
#define FEMU_FDP_REFUSE "femu_mode=1,devsz_mb=1,secsz=512,pgs_per_blk=4," \
    "pls_per_lun=1,luns_per_ch=2,nchs=2,blks_per_pl=80"
#define FEMU_ID_FRMW            260

#define FEMU_LOG_FID_EFFECTS    0x12
#define FEMU_FID_FSP(fis)       (((fis) >> 20) & 0xfff)
#define FEMU_FID_SCOPE_NS       0x1
#define FEMU_FEAT_KV_CONFIG     0x20
#define FEMU_FEAT_FDP           0x1d
#define FEMU_FEAT_FDP_EVENTS    0x1e
#define FEMU_NIDT_CSI       0x04

typedef struct FemuCapsCfg {
    const char *name;
    const char *opts;
    uint16_t oncs;          /* the optional NVM commands it turns on */
    bool format;            /* whether Format NVM is offered */
    void *(*before)(GString *cmd_line, void *arg);
} FemuCapsCfg;

#define FEMU_FID_NS_WP          0x84

#define FEMU_ADM_SANITIZE_NS    0x8c

#define FEMU_IO_CANCEL          0x18

/* what the FDP Configurations log (20h) of a test device must report */
typedef struct FemuFdpConfWant {
    uint32_t nrg;
    uint8_t rgif;
    uint16_t nruh;
    uint64_t runs;
} FemuFdpConfWant;

/* what a test with reclaim groups needs to know of its device */
typedef struct FemuRgWant {
    uint32_t nrg;
    uint8_t rgif;
    /* the geometry, for the dies of each group */
    uint32_t nchs;
    uint32_t luns;
    /* gc test: the handle to overwrite through, and pages per write */
    int ph;
    uint32_t burst;
} FemuRgWant;

/* the raw status bits: DNR is bit 14 of what femu_complete() returns */
#define FEMU_DNR                0x4000
#define FEMU_EOL_SLOTS          (FEMU_QSIZE - 1)

/* the pSLC erase time of tier-suspend-fold, in ns */
#define TIER_SUSP_ERASE_NS 2000000000

/* the pSLC erase time of tier-busy, in ns */
#define TIER_BUSY_ERASE_NS 2000000000

/*
 * Device features at values the other tests leave at the default: a transfer
 * at the MDTS limit and one block past it, a 16 MiB transfer with no limit,
 * 64 I/O queues, a queue of 4096 entries, 256 reclaim unit handles, a key
 * value at the maximum size, and data pointers that are not page aligned.
 * Each test ends its QEMU process, so no test starts on another's state.
 */
#define FEMU_G1_PAGE        4096u
#define FEMU_G1_LIST_ENTS   (FEMU_G1_PAGE / 8)
#define FEMU_G1_DEPTH       4096
/* entries of the submission and the completion queue of cq-full-* */
typedef struct FemuG1CqfSize {
    uint32_t sq;
    uint32_t cq;
} FemuG1CqfSize;

/* defined in femu-test-common.c */
extern char *femu_cb_page;
extern uint16_t femu_io_status;
extern char *femu_csd_dir;
extern char *femu_csd_slow_dir;
extern char *femu_csd_warn_log;
extern char *femu_cps_dir;

/* femu-test-common.c */
uint64_t femu_sq_doorbell(FemuCtrlState *c, uint16_t qid);
uint64_t femu_cq_doorbell(FemuCtrlState *c, uint16_t qid);
void femu_queue_init(FemuCtrlState *c, FemuQueue *q, uint16_t qid);
void femu_queue_free(FemuCtrlState *c, FemuQueue *q);
void femu_submit(FemuCtrlState *c, FemuQueue *q, NvmeCmd *cmd);
uint16_t femu_complete(FemuCtrlState *c, FemuQueue *q, uint16_t *cid,
                       uint32_t *result);
uint16_t femu_admin_result(FemuCtrlState *c, NvmeCmd *cmd, uint32_t *result);
uint16_t femu_admin(FemuCtrlState *c, NvmeCmd *cmd);
void femu_enable_start(FemuCtrlState *c, QPCIDevice *pdev,
                       QGuestAllocator *alloc, uint32_t cc);
void femu_enable_cc(FemuCtrlState *c, QPCIDevice *pdev, QGuestAllocator *alloc,
                    uint32_t cc);
void femu_enable(FemuCtrlState *c, QPCIDevice *pdev, QGuestAllocator *alloc);
void femu_enable_csi(FemuCtrlState *c, QPCIDevice *pdev,
                     QGuestAllocator *alloc);
void femu_disable(FemuCtrlState *c);
void femu_create_io_queues(FemuCtrlState *c);
uint16_t femu_rw(FemuCtrlState *c, uint8_t opcode, uint64_t slba,
                 uint64_t data);
void femu_round_trip(FemuCtrlState *c, uint8_t seed);
uint64_t femu_alloc_64k(QGuestAllocator *alloc, uint64_t *raw);
uint64_t femu_last_res64(FemuCtrlState *c, FemuQueue *q);
uint16_t femu_zone_action(FemuCtrlState *c, uint64_t slba, uint32_t action);
void femu_zone_report(FemuCtrlState *c, uint64_t buf, uint8_t *report);
uint16_t femu_get_feature(FemuCtrlState *c, uint8_t fid, uint8_t sel,
                          uint32_t nsid, uint32_t dw11, uint32_t *result);
uint16_t femu_set_feature(FemuCtrlState *c, uint8_t fid, bool save,
                          uint32_t nsid, uint32_t dw11, uint32_t *result);
uint16_t femu_get_log(FemuCtrlState *c, uint8_t lid, uint64_t buf, uint32_t len,
                      uint64_t off);
void femu_hybrid_flush(FemuCtrlState *c);
uint16_t femu_ruh_update(FemuCtrlState *c, uint64_t pids, uint16_t npid);
uint16_t femu_timestamp(FemuCtrlState *c, bool set, uint8_t sel, uint32_t save,
                        uint64_t buf);
uint16_t femu_format(FemuCtrlState *c, uint32_t nsid, uint8_t lba_idx,
                     uint8_t ses);
void femu_identify_ns(FemuCtrlState *c, uint64_t *nsze, uint32_t *lba_size);
uint16_t femu_write_pages_placed(FemuCtrlState *c, uint64_t page,
                                 uint32_t npages, uint64_t data, uint64_t list,
                                 int pid);
uint16_t femu_write_pages(FemuCtrlState *c, uint64_t page, uint32_t npages,
                          uint64_t data, uint64_t list);
uint16_t femu_read_pages(FemuCtrlState *c, uint64_t page, uint32_t npages,
                         uint64_t data, uint64_t list);
void femu_ftl_check(QTestState *qts, uint64_t *mapped, uint64_t *lost,
                    uint64_t *orphans);
uint64_t femu_ftl_trace_id(QTestState *qts, const char *id, int i);
uint64_t femu_ftl_trace_field(QTestState *qts, int i);
QDict *femu_query(QTestState *qts, const char *args);
void femu_query_fails(QTestState *qts, const char *args, const char *want);
QDict *femu_query_ns(QTestState *qts, const char *args, QDict **rsp);
void femu_query_matches_c0h(FemuCtrlState *c, uint64_t buf);
void femu_query_check_lines(QTestState *qts, const char *path,
                            uint64_t want_valid);
const FemuMediaWant *femu_media_want(const char *name);
bool femu_media_only(const char *mode);
void femu_media_check(QDict *ns, const FemuMediaWant *w);
uint16_t femu_dealloc_pages(FemuCtrlState *c, uint64_t page, uint32_t npages,
                            uint64_t buf);
uint16_t femu_write_zeroes(FemuCtrlState *c, uint64_t slba, uint32_t nlb);
void femu_wear_workload_placed(FemuCtrlState *c, uint64_t buf, uint64_t list,
                               int pid);
void femu_wear_workload(FemuCtrlState *c, uint64_t buf, uint64_t list);
uint16_t femu_smart_temp(FemuCtrlState *c, uint64_t log, uint8_t *warning);
char *femu_onfi_page_file(int mutate, bool good_crc);
uint16_t femu_delete_sq(FemuCtrlState *c, uint16_t qid);
uint64_t femu_ruh0_ruamw(FemuCtrlState *c, uint64_t buf);
uint16_t femu_write_8k(FemuCtrlState *c, uint64_t buf, uint64_t slba,
                       uint32_t nlb);
void femu_tp_check(QTestState *qts, const char *id, uint64_t v[7]);
void femu_gc_fw_counts(FemuCtrlState *c, uint64_t log, const char *id,
                       uint64_t v[4]);
void femu_zap_create_queue(FemuCtrlState *c, FemuQueue *q, uint16_t qid);
uint16_t femu_zap_complete(FemuCtrlState *c, FemuQueue *q, uint32_t *result);
void femu_zap_queue(FemuCtrlState *c, FemuQueue *q, NvmeCmd *cmd);
void femu_zap_ring(FemuCtrlState *c, FemuQueue *q);
void femu_rwa_hold(QTestState *qts, uint32_t on);
uint64_t femu_rwa_get(QTestState *qts, const char *prop);
bool femu_rwa_cq_ready(FemuCtrlState *c, FemuQueue *q);
void femu_pe_suspend_rw(FemuCtrlState *c, FemuQueue *q, NvmeRwCmd *rw, bool kv,
                        uint8_t opcode, uint64_t page);
void femu_flush_check(QTestState *qts, uint64_t *v);
void femu_crypto_submit(FemuCtrlState *c, uint8_t opcode, uint64_t slba,
                        uint64_t buf, uint16_t dw12hi);
uint64_t femu_c0h_field(FemuCtrlState *c, uint64_t log, int off);
void femu_burst_queue(FemuCtrlState *c, FemuQueue *q, uint16_t qid);
void femu_create_io_queues_irq(FemuCtrlState *c, uint16_t vector);
void femu_read_unconsumed(FemuCtrlState *c, uint64_t buf);
QDict *femu_stage(QDict *ret, const char *name);
int64_t femu_stage_hold_max_ms(QTestState *qts, int count);
uint64_t femu_stage_bucket(QDict *st, int b);
void femu_stage_check_buckets(QDict *st);
void femu_stages_check_sum(QDict *ret);
void femu_stages_check_bands(QDict *ret);
void femu_sgl_segment(FemuCtrlState *c, NvmeCmd *cmd, uint64_t list,
                      uint64_t data, uint32_t len);
uint16_t femu_io(FemuCtrlState *c, NvmeCmd *cmd);
uint16_t femu_log_cmd(FemuCtrlState *c, uint32_t nsid, uint32_t dw10,
                      uint32_t dw14, uint64_t buf, uint32_t len);
void femu_zns_ftl_hold(QTestState *qts, bool hold);
uint16_t femu_identify(FemuCtrlState *c, uint32_t nsid, uint32_t dw10,
                       uint32_t dw11, uint64_t buf);
uint16_t femu_aer(FemuCtrlState *c);
uint16_t femu_endgrp_log(FemuCtrlState *c, uint8_t lid, uint64_t off,
                         uint64_t buf, uint32_t len);
uint64_t femu_ruh_ruamw(FemuCtrlState *c, uint64_t buf, uint16_t pid);
uint64_t femu_fdp_hbmw(FemuCtrlState *c, uint64_t buf);
void femu_query_check_fdp(FemuCtrlState *c, uint64_t log, uint64_t want_valid,
                          uint64_t *host);
uint64_t femu_fdp_check(QTestState *qts);
uint64_t femu_fdp_handle_vpc(QTestState *qts, int h);
uint16_t femu_fdp_wb_write(FemuCtrlState *c, uint64_t page, uint32_t npages,
                           uint64_t data, uint64_t list, int pid, bool fua);
uint16_t femu_fdp_wb_flush(FemuCtrlState *c);
int64_t femu_fdp_open_vpc(QTestState *qts, int h);
uint32_t femu_fdp_ctrl_events(FemuCtrlState *c, uint64_t log, uint8_t *ev,
                              uint32_t max);
void femu_fdp_move_events_set(FemuCtrlState *c, uint64_t buf, uint16_t ph,
                              const char *types, bool on);
uint16_t femu_format_dw10(FemuCtrlState *c, uint32_t dw10);
uint16_t femu_lba_cmd(FemuCtrlState *c, uint8_t opcode, uint64_t slba,
                      uint32_t nlb);
uint16_t femu_sanitize(FemuCtrlState *c, uint32_t dw10);
uint16_t femu_sstat(FemuCtrlState *c, uint64_t buf, uint16_t *sprog);
uint16_t femu_copy(FemuCtrlState *c, uint64_t list, uint64_t sdlba,
                   const uint64_t *slba, const uint16_t *nlb, int ndesc, int nr,
                   uint32_t dw12_extra);
uint16_t femu_rw_ns(FemuCtrlState *c, uint8_t opcode, uint32_t nsid,
                    uint64_t slba, uint64_t data);
uint16_t femu_hbs(FemuCtrlState *c, bool set, uint64_t buf);
uint16_t femu_copy_fmt2(FemuCtrlState *c, uint64_t list, uint64_t sdlba,
                        uint32_t snsid, uint64_t slba, uint16_t nlb);
uint16_t femu_rw_md(FemuCtrlState *c, uint8_t opcode, uint64_t slba,
                    uint16_t nlb, uint64_t data, uint64_t mptr, uint8_t psdt);
uint16_t femu_pi_io(FemuCtrlState *c, uint8_t opcode, uint32_t nsid,
                    uint64_t slba, uint16_t nlb, uint64_t dbuf, uint64_t mbuf,
                    uint8_t prinfo, uint32_t ref, uint16_t app, uint16_t mask);
void femu_pi_tuple(uint8_t *m, uint16_t guard, uint16_t app, uint32_t ref);
void femu_pi_host(QTestState *qts, uint64_t dbuf, uint64_t mbuf,
                  const uint8_t *d, const uint8_t *m, unsigned int ms,
                  bool extended);
void femu_pi_result(QTestState *qts, uint64_t dbuf, uint64_t mbuf,
                    const uint8_t *d, const uint8_t *m, unsigned int ms,
                    bool extended);
uint16_t femu_ns_create_pi(FemuCtrlState *c, uint64_t buf, uint8_t flbas,
                           uint8_t dps, uint32_t *nsid);
uint16_t femu_pi_format_ns(FemuCtrlState *c, uint32_t nsid, uint32_t dw10);
uint16_t femu_pi_copy(FemuCtrlState *c, uint64_t list, uint64_t dst,
                      uint8_t fmt, uint8_t nr, uint8_t prinfor, uint8_t prinfow,
                      uint32_t ref, uint16_t app);
void femu_pi_range(QTestState *qts, uint64_t list, uint32_t nsid, uint64_t slba,
                   uint32_t ref);
guint32 femu_fuzz_seed(guint32 base);
int femu_fuzz_rounds(int base);
bool femu_fuzz_sane(GRand *rng);
uint64_t femu_fuzz_ptr(GRand *rng, uint64_t region);
uint64_t femu_fuzz_sgl_slot(GRand *rng, uint64_t region);
void femu_fuzz_lists(FemuCtrlState *c, GRand *rng, uint64_t region);
void femu_fuzz_valid_dptr(FemuCtrlState *c, GRand *rng, uint64_t region,
                          NvmeRwCmd *rw, uint32_t len, bool sgl_ok);
uint16_t femu_get_telemetry(FemuCtrlState *c, uint8_t lid, bool create,
                            uint64_t buf, uint32_t len, uint64_t off);
uint16_t femu_sec(FemuCtrlState *c, bool send, uint8_t secp, uint16_t spsp,
                  uint64_t buf, uint32_t len);
uint32_t femu_be32(const uint8_t *p);
void femu_tb_uid(FemuTb *t, uint64_t uid);
void femu_tb_bytes(FemuTb *t, const uint8_t *p, uint32_t len);
void femu_tb_call(FemuTb *t, uint64_t obj, uint64_t method);
void femu_tb_end(FemuTb *t);
uint32_t femu_opal_xfer(FemuCtrlState *c, QTestState *qts, uint64_t buf,
                        FemuTb *t, uint32_t tsn, uint8_t *r);
void femu_tb_u(FemuTb *t, uint64_t v);
uint8_t femu_opal_run(FemuCtrlState *c, QTestState *qts, uint64_t buf,
                      FemuTb *t, uint32_t tsn);
uint8_t femu_opal_open(FemuCtrlState *c, QTestState *qts, uint64_t buf,
                       uint64_t sp, uint64_t auth, const char *pin,
                       uint32_t *tsn);
void femu_opal_eos(FemuCtrlState *c, QTestState *qts, uint64_t buf,
                   uint32_t tsn);
uint8_t femu_opal_lset(FemuCtrlState *c, QTestState *qts, uint64_t buf,
                       uint32_t tsn, uint64_t obj, const int *cols,
                       const uint64_t *vals);
uint16_t femu_opal_rw(FemuCtrlState *c, uint8_t opc, uint64_t slba,
                      uint64_t data);
void femu_opal_expect(FemuCtrlState *c, QTestState *qts, uint32_t nsid,
                      uint64_t slba, uint64_t io, uint8_t v);
void femu_opal_fill(FemuCtrlState *c, QTestState *qts, uint32_t nsid,
                    uint64_t slba, uint64_t io, uint8_t v);
uint16_t femu_resv(FemuCtrlState *c, uint8_t opc, uint32_t dw10, uint32_t dw11,
                   uint64_t buf, uint64_t k1, uint64_t k2);
uint16_t femu_get_lba_status(FemuCtrlState *c, uint64_t buf, uint64_t slba,
                             uint32_t mndw, uint8_t atype, uint16_t rl);
void femu_mark_uncor(FemuCtrlState *c, uint64_t slba, uint16_t nlb);
uint16_t femu_lsi_read(FemuCtrlState *c, uint64_t buf, uint32_t len,
                       uint64_t off, bool rae);
uint16_t femu_lsi_gen(FemuCtrlState *c, uint64_t buf, uint32_t len, bool rae);
uint64_t femu_lsi_state(QTestState *qts, const char *key);
void femu_lsi_cmd(QTestState *qts, const char *cmd);
void femu_lsi_aec(FemuCtrlState *c, bool on);
bool femu_lsi_after(FemuCtrlState *c, int64_t ns);
void femu_lsi_alert(FemuCtrlState *c, uint16_t want);
uint64_t femu_vm_peak_kb(QTestState *qts);
uint16_t femu_pel(FemuCtrlState *c, uint8_t act, uint64_t buf, uint32_t len,
                  uint64_t off);
uint16_t femu_ns_delete(FemuCtrlState *c, uint32_t nsid);
uint16_t femu_ns_create(FemuCtrlState *c, uint64_t buf, uint64_t nsze,
                        uint8_t flbas, uint32_t *nsid);
uint16_t femu_ns_attach(FemuCtrlState *c, uint64_t buf, uint32_t nsid,
                        uint16_t cntlid, bool attach);
void femu_ns_page(FemuCtrlState *c, uint64_t buf, uint32_t nsid, uint32_t page,
                  uint8_t pattern, bool write);
uint16_t femu_changed_ns_log(FemuCtrlState *c, uint64_t buf, bool rae);
void femu_shared_add(QTestState *qts, const char *id, int slot, int mode);
void femu_ns_fixture(QTestState *qts, const char *value);
uint64_t femu_pel_at(QTestState *qts, uint64_t buf, int i);
int femu_pel_count(QTestState *qts, uint64_t buf, uint8_t et, uint16_t code);
void femu_power_read(FemuCtrlState *c, uint64_t buf, uint32_t nsid,
                     uint64_t lba, uint8_t pattern);
char *femu_ftl_dump(QTestState *qts, const char *kind, int limit);
char *femu_ftl_counters(QTestState *qts);
void femu_fetch_hold(QTestState *qts, const char *id, int hold);
QDict *femu_events_q(QTestState *qts, const char *id, QDict **rsp);
char *femu_events_file(const char *dir, const char *text);
uint64_t femu_ftl_vpc_sum(QTestState *qts);
void femu_pa_boot(FemuPa *p, const char *opts, const char *path);
void femu_pa_end(FemuPa *p, bool quit);
char *femu_save_data(QTestState *qts, const char *id, const char *file);
void femu_ckpt_add(QTestState *qts, const char *id, int slot,
                   const char *extra);
char *femu_ckpt_try_add(QTestState *qts, const char *id, int slot,
                        const char *extra);
uint16_t femu_directive(FemuCtrlState *c, bool receive, uint32_t nsid,
                        uint32_t dw11, uint32_t dw12, uint64_t buf,
                        uint32_t bytes, uint32_t *result);
uint16_t femu_stream_write(FemuCtrlState *c, uint32_t nsid, uint64_t slba,
                           uint64_t buf, uint8_t dtype, uint16_t sid);
bool femu_cq_ready(FemuCtrlState *c, FemuQueue *q);
char *femu_realize_stderr_after(const char *pre, const char *opts);
char *femu_realize_stderr(const char *opts);
char *femu_fdp_state(QTestState *qts, const char *id);
uint64_t femu_mem_taken(QTestState *qts, const char *id);
uint64_t femu_mem_total(QTestState *qts, const char *id, uint64_t *sub);
void femu_mem_ftl_bytes(const char *opts, uint64_t out[3]);
uint16_t femu_get_log_csi(FemuCtrlState *c, uint8_t lid, uint8_t csi,
                          uint64_t buf, uint32_t len, uint64_t off);
void femu_check_fid_effects(FemuCtrlState *c, const uint32_t *fis);
uint16_t femu_ana_log(FemuCtrlState *c, uint64_t buf, bool rgo);
uint16_t femu_wp_set(FemuCtrlState *c, uint32_t nsid, uint32_t wps);
uint16_t femu_sanns(FemuCtrlState *c, uint32_t nsid, uint32_t dw10);
void femu_cancel_hook(QTestState *qts, const char *id, const char *prop,
                      int value);
void femu_cancel_wait_cpl(QTestState *qts, const char *id, int64_t want);
uint16_t femu_cancel_submit(FemuCtrlState *c, uint32_t nsid, uint16_t cid,
                            uint16_t sqid, uint8_t acode);
uint16_t femu_cancel(FemuCtrlState *c, uint32_t nsid, uint16_t cid,
                     uint16_t sqid, uint8_t acode, uint32_t *res);
uint16_t femu_cancel_rw(FemuCtrlState *c, uint64_t buf, uint32_t nsid,
                        uint64_t lba, bool write, uint8_t pattern);
void femu_cancel_reap(FemuCtrlState *c, int n, const uint16_t *cid,
                      uint16_t *sc, uint32_t *res);
uint16_t femu_oncs_cmd(FemuCtrlState *c, uint8_t opcode, uint64_t slba,
                       uint64_t data);
uint64_t femu_pd2_fdp_check(QTestState *qts);
int femu_pd2_events(FemuCtrlState *c, uint64_t log, bool host, uint8_t type,
                    uint16_t *ruhid);
void femu_pd2_readback(FemuCtrlState *c, QTestState *qts, uint64_t buf,
                       int npages, uint8_t pat);
bool femu_eol_state(QTestState *qts, bool *ro, uint64_t *cap, uint64_t *pages,
                    uint64_t *reqs);
uint16_t femu_wz(FemuCtrlState *c, uint64_t slba, uint32_t nlb, bool deac);
uint16_t femu_dealloc_range(FemuCtrlState *c, uint64_t slba, uint32_t nlb,
                            uint64_t buf);
uint64_t femu_eol_erases(QTestState *qts);
int64_t femu_eol_query_int(QTestState *qts, const char *dict, const char *key);
uint32_t femu_g1_list_pages(uint32_t npages);
void femu_g1_prps_at(FemuCtrlState *c, NvmeCmd *cmd, uint64_t data,
                     uint32_t npages, uint64_t list, uint32_t first);
void femu_g1_all(QTestState *qts, uint64_t addr, size_t len, uint8_t byte);
uint16_t femu_g1_rw(FemuCtrlState *c, uint8_t opcode, uint64_t slba,
                    uint32_t nlb, uint64_t data, uint64_t list);
void femu_g1_fill(uint8_t *buf, size_t len, uint32_t seed);
void femu_g1_put(QTestState *qts, uint64_t addr, const uint8_t *buf,
                 size_t len);
void femu_g1_get(QTestState *qts, uint64_t addr, uint8_t *buf, size_t len);
uint8_t femu_g1_mdts(FemuCtrlState *c, uint64_t id);
uint16_t femu_g1_queue_submit(FemuCtrlState *c, FemuQueue *q, uint8_t opcode,
                              uint64_t slba, uint64_t buf);
uint16_t femu_g1_queue_reap(FemuCtrlState *c, FemuQueue *q, uint16_t want);
uint16_t femu_g1_create(FemuCtrlState *c, uint8_t opcode, uint16_t qid,
                        uint64_t ring, uint32_t qsize, uint32_t dw11);
void femu_g1_sized_submit(FemuCtrlState *c, FemuQueue *q, uint64_t buf,
                          uint32_t count, uint32_t size);
void femu_g1_deep_submit(FemuCtrlState *c, FemuQueue *q, uint64_t buf,
                         uint32_t count);
void femu_g1_deep_reap(FemuCtrlState *c, FemuQueue *q, uint16_t first,
                       uint32_t count);
void femu_g1_cqe_wait(QTestState *qts, FemuQueue *q, uint32_t slot,
                      uint8_t phase, NvmeCqe *cqe);

/* femu-test-nossd.c */
void femu_test_invalid_nsid_reuse(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_io_by_doorbell(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_admin_queue_refused(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_discontig_64k_pages(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_queue_mapping(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_io_by_shadow_doorbell(void *obj, void *data,
                                     QGuestAllocator *alloc);
void femu_test_dbbuf_too_many_queues(void *obj, void *data,
                                     QGuestAllocator *alloc);
void femu_test_cq_churn(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cmb_last_byte(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cmb_data_buffer(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_features(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_log_pages(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_log_length(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_format(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_gc_seed(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_query_unsupported(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pmeas_off(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_sgl(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_rw_atomic(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_rw_atomic_split(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_rw_atomic_wu(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fused_cw(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fused_cw_refused(void *obj, void *data,
                                QGuestAllocator *alloc);
void femu_test_fused_lock(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fused_life(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_crypto(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fw_cost(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_shared_cq(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_poller_burst(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_config_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cq_full(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_io_interrupts(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_intc_msix(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_intc_shared(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_prp_list_offset(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_queue_create_status(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_cc_states(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_features_reset(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_error_log(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_identify_fields(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_prp_status(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_mdts_unit(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_doorbell_errors(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_format_pi_needs_metadata(void *obj, void *data,
                                        QGuestAllocator *alloc);
void femu_test_format_ses(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_bar0_size(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_aer_limit(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_verify(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_self_test(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_intx_shadow_doorbell(void *obj, void *data,
                                    QGuestAllocator *alloc);
void femu_test_pi_verify(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pci_pm(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_trace_events(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pi64(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ns_create_pi_validation(void *obj, void *data,
                                       QGuestAllocator *alloc);
void femu_test_pi_compare(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pi_zeroes(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pi_generate_ref(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pi_copy_no_pi(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pi_copy_convert(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pi_dpc_no_metadata(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_pi_format(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_metadata_extended(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_admin_fuzz(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fuzz_control_refused(void *obj, void *data,
                                    QGuestAllocator *alloc);
void femu_test_lockdown(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_lockdown_off(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_opal(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_opal_session(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_opal_locking(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_format_crypto_ns(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_opal_off(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_resv_off(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_get_lba_status(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_lsi_feature(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_lsi_log(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_lsi_many(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_lsi_alert(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_lsi_poll(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_lsi_component(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_lsi_qfull(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_lsi_disable(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_lsi_reset(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_lsi_wrap(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_lsi_wu_race(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_lsi_publish(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_lsi_format(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_lsi_sanitize(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_lsi_persist_live(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_lsi_gls_race(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_lifecycle(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_mdts0_reports(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_timestamp(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ns_mgmt_format_detached(void *obj, void *data,
                                       QGuestAllocator *alloc);
void femu_test_ns_mgmt_unallocated(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_ns_mgmt_validation(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_ns_mgmt_notices(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ns_mgmt_overflow(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_shared_lifecycle(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_shared_discovery(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_shared_retire(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_shared_features(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_shared_sanitize(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_shared_remove(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_shared_private(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_shared_admin(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_shared_subsys_release(void *obj, void *data,
                                     QGuestAllocator *alloc);
void femu_test_ns_mgmt_subsys(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ns_mgmt_common_dpc(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_ns_mgmt_identify_csi_common(void *obj, void *data,
                                           QGuestAllocator *alloc);
void femu_test_ns_mgmt_identify(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ns_mgmt_default(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_namespace_sizes_rounding(void *obj, void *data,
                                        QGuestAllocator *alloc);
void femu_test_namespace_empty_slice(void *obj, void *data,
                                     QGuestAllocator *alloc);
void femu_test_namespace_large(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_namespace_copy_source(void *obj, void *data,
                                     QGuestAllocator *alloc);
void femu_test_namespace_sanitize_free(void *obj, void *data,
                                       QGuestAllocator *alloc);
void femu_test_namespace_lifecycle(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_namespace_capacity(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_namespace_identity(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_namespace_allocated(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_namespace_sparse(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pel(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pel_set_feature(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pel_file(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pel_file_quit(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_io_trace(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_io_trace_append(void *obj, void *data,
                               QGuestAllocator *alloc);
void femu_test_arb_burst(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_wrr(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_wrr_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_wrr_blocked(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_events_seed(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_precon(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_precon_persist(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_persist_aging(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_persist_aging_files(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_checkpoint_reuse_ftl(void *obj, void *data,
                                    QGuestAllocator *alloc);
void femu_test_pel_file_invalid(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pel_events(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ns_mgmt_pel(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_streams_identify(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pause_mmio(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cmb_sgl(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_streams_config(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_memory(void *obj, void *data, QGuestAllocator *unused);
void femu_test_mem_limit_subsys(void *obj, void *data, QGuestAllocator *unused);
void femu_test_memory_parts(void *obj, void *data, QGuestAllocator *unused);
void femu_test_ignored_props(void *obj, void *data, QGuestAllocator *unused);
void femu_test_doc_examples(void *obj, void *data, QGuestAllocator *unused);
void femu_test_fid_effects(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cc_css(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_admin_psdt(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_media_dnr(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_frmw(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_rain_ro_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ana_off(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ns_wp_off(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cancel_nossd(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_power_states_off(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_identify_fmt_off(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_gc_frontier_skew(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_gc_bg_invalid(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_gc_lines(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_gc_lines_warned(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_gc_lines_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_gc_spare_waf(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_gc_spare_hotcold(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_atomic_identify(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_tier_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_dma_target_compare_status(void *obj, void *data,
                                         QGuestAllocator *unused);
void femu_test_dma_target_prp1(void *obj, void *data, QGuestAllocator *unused);
void femu_test_dma_target_prp_list(void *obj, void *data,
                                   QGuestAllocator *unused);
void femu_test_dma_target_sgl(void *obj, void *data, QGuestAllocator *unused);
void femu_test_dma_target_sgl_chain(void *obj, void *data,
                                    QGuestAllocator *unused);
void femu_test_dma_target_single_prp(void *obj, void *data,
                                     QGuestAllocator *unused);
void femu_test_dma_target_pause(void *obj, void *data, QGuestAllocator *unused);
void femu_test_g1_mdts_cap(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_g1_many_queues(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_g1_deep_queue(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_g1_dptr_layouts(void *obj, void *data, QGuestAllocator *alloc);

/* femu-test-bbssd.c */
void femu_test_zoned_append_limit(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_geometry_limits(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_hybrid_trim(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_hybrid_trace(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_hybrid_batch(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_spare_threshold(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_media_counters(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_buffer_counters(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_gc_no_destination(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ftl_trace(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ftl_trace_var(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ftl_trace_mp(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_gc_erase_order(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_gc_clock(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_geometry_big(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_buffer_bg(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_buffer_flush_fence(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_buffer_vwc_drain(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_buffer_place_fail(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_iu_rmw(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_query(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_query_media_mixed(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_wear_aer(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_wear_query(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_wear_level(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_gc_pace(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_gc_pace_budget(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_gc_pace_timing(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_gc_copyback(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_read_prio_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_prog_pass2_refused(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_thermal(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_thermal_event(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_thermal_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pmeas(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pmeas_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_partial_writes(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_partial_writes_ns2(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_plane_energy(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_age_fdp_reuse(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pd(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pd_stream(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pd_fdp(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pd_map(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pd_reuse(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pd_mp(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_onfi(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_onfi_cache(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_onfi_cache_refused(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_trim_cost(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_age_scale(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_flush_without_vwc(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_delete_sq_in_flight(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_wide_lba(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_dftl_capacity(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_dftl_tp_min(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_dftl_tp_reserve(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_dftl_ready(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pe_suspend_flush(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pe_suspend_flush_fua(void *obj, void *data,
                                    QGuestAllocator *alloc);
void femu_test_read_prio(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_prog_pass2(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_die_parity(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_rain(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_rain_fail(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_rain_wear(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_rain_wear_spare(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_rain_wear_eol(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_rain_fifo_fit(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_rain_rebuild(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_hmb(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_stalls(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_io_stages_overlap(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_mp_program_scopes(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plane_first(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_shutdown_abrupt(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_shutdown_sysreset(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_shutdown_delay(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_shutdown_bad(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_log_contents_fdp(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_query_fdp(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_query_fdp_update(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_query_fdp_replace(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_wear_fdp(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_wear_fdp_props(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_format_ftl(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_sanitize_bg(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_sanitize(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_copy(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_telemetry(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_telemetry_da4(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_telemetry_ctrl(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_opal_shadow(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_opal_crypto_format(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_opal_mpa(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_resv(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_lsi_recreate(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_lsi_persist(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_lsi_persist_pub(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_report_zero_tail(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ns_mgmt_bbssd_cap(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ns_mgmt_bbssd_boot_cap(void *obj, void *data,
                                      QGuestAllocator *alloc);
void femu_test_ns_mgmt_bbssd_capacity(void *obj, void *data,
                                      QGuestAllocator *alloc);
void femu_test_ns_mgmt_bbssd_isolation(void *obj, void *data,
                                       QGuestAllocator *alloc);
void femu_test_kv_model_shared(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_gc_erase_order_shared(void *obj, void *data,
                                     QGuestAllocator *alloc);
void femu_test_namespace_failed_identity(void *obj, void *data,
                                         QGuestAllocator *alloc);
void femu_test_power_fua_place_fail(void *obj, void *data,
                                    QGuestAllocator *alloc);
void femu_test_power_mmio_cut(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_power_dma_pointers(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_power_cmb(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_power_no_drain(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_power_mutation(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_power_loss(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_power_durable(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_power_destage(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_power_cache_off(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_power_namespaces(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_power_lifecycle(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_power_validity(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_power_flush_pending(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_power_log(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_events(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_events_bad(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_events_timer(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fsched_bad(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fsched_match(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fsched_ppm(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fsched_mdts(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fsched_unplug(void *obj, void *data,
                             QGuestAllocator *alloc);
void femu_test_fsched_groups(void *obj, void *data,
                             QGuestAllocator *alloc);
void femu_test_fsched_records(void *obj, void *data,
                              QGuestAllocator *alloc);
void femu_test_fsched_window(void *obj, void *data,
                             QGuestAllocator *alloc);
void femu_test_fsched_overflow(void *obj, void *data,
                               QGuestAllocator *alloc);
void femu_test_fsched_replay(void *obj, void *data,
                             QGuestAllocator *alloc);
void femu_test_fsched_log_files(void *obj, void *data,
                                QGuestAllocator *alloc);
void femu_test_fsched_log_unplug(void *obj, void *data,
                                 QGuestAllocator *alloc);
void femu_test_fsched_flush_lie(void *obj, void *data,
                                QGuestAllocator *alloc);
void femu_test_fsched_fua_lie(void *obj, void *data,
                              QGuestAllocator *alloc);
void femu_test_fsched_lie_reasons(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_fsched_fused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fsched_wbf_flush(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fsched_wbf_write(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fsched_wbf_wzero(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fsched_wbf_dsm(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fsched_wbf_copy(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fsched_wbf_wunc(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fsched_wbf_vwc(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fsched_wbf_wp(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fsched_wbf_format(void *obj, void *data,
                                 QGuestAllocator *alloc);
void femu_test_fsched_wbf_sanitize(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_fsched_wbf_bg(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fsched_wbf_hold(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fsched_wbf_fua(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fsched_wbf_aer(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fsched_wbf_ns(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fsched_wbf_slots(void *obj, void *data,
                                QGuestAllocator *alloc);
void femu_test_fsched_hang_io(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fsched_hang_reclaim(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_fsched_hang_count(void *obj, void *data,
                                 QGuestAllocator *alloc);
void femu_test_fsched_hang_mix(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fsched_hang_report(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_fsched_cfs(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fsched_cfs_paths(void *obj, void *data,
                                QGuestAllocator *alloc);
void femu_test_fsched_start(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fsched_start_early(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_ready_delay(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_recovery_delay(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ready_sysreset(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ready_bad(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_die_stats(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_die_stats_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_die_slow(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_die_slow_off(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_die_slow_events(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_persist_ftl(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_persist_retention(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_mode_names(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_checkpoint_reuse(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_save_background(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_save_background_end(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_checkpoint_ro_dir(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_streams_gc(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_streams_subpage(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_streams_sws(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_streams_churn(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_streams_recovery(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_streams_gc_floor(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_mem_limit_commands(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_memory_page_tables(void *obj, void *data,
                                  QGuestAllocator *unused);
void femu_test_multiplane_warnings(void *obj, void *data,
                                   QGuestAllocator *unused);
void femu_test_abort(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fid_effects_fdp(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_v2_refusals(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_endgrp_reported(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_rotational(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_rain_inject(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_rain_ro(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_rain_loss(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_rain_loss_props(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ocp_die_offline(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ocp_extcaps(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ocp_pcie(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ocp(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ocp_latency(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fw_update(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fw_ocp(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ocp_hwcomp(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ocp_caps(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_thermal_throttle(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_thermal_ocp(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plane_reads_timing(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_ana(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_power_states(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_power_limit(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_power_limit_apst(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_power_limit_sysreset(void *obj, void *data,
                                    QGuestAllocator *alloc);
void femu_test_ns_wp(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ns_wp_streams(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ns_wp_buffer(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ns_wp_drain(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fused_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_sanitize_ns(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cancel_deferred(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cancel_immediate(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cancel_stages(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cancel_checks(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cancel_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_shared_ftl(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_shared_ftl_format(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_shared_ftl_buffer(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_shared_ftl_refused(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_io_stages_ns(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_io_causes(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_io_causes_map(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_io_causes_hmb(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_io_causes_flush(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_io_causes_merge(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_io_causes_retry(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_io_causes_refused(void *obj, void *data,
                                 QGuestAllocator *alloc);
void femu_test_io_stages_ns_refused(void *obj, void *data,
                                    QGuestAllocator *alloc);
void femu_test_durable_at_done(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_durable_vwc_off(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_durable_partial(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_durable_partial2(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_durable_stall(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_durable_wz_copy(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_durable_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plp_keep(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plp_fail_rom(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plp_fail_wtm(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plp_fail_normal(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_awupf(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_sdc(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_power_limit_off(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_power_limit_refused(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_l2p_dram(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_throttle_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fw_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_endgrp_list_absent(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_gc_frontier_placement(void *obj, void *data,
                                     QGuestAllocator *alloc);
void femu_test_gc_frontier_reclaim(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_gc_frontier_refused(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_maint_idle(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_maint_idle_space(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_maint_idle_burst(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_gc_idle_recover(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_gc_idle_fence(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_gc_idle_media(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_gc_idle_sweep(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_gc_idle_off(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_gc_bg_invalid_refused(void *obj, void *data,
                                     QGuestAllocator *alloc);
void femu_test_link_write_order(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_rber_scripted(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_err_inject(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_dram_hit(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_gc_fw(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_rrl(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_rrl_no_rber(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_rrl_subsys(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_rrl_modes(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_identify(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_rrl(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_golden_off(void *obj, void *data,
                              QGuestAllocator *alloc);
void femu_test_plm_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_nsid(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_config(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_lpe0(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_logs(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_reset(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_no_pause(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_defer(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_ndwin_prep(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_prep_steady(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_gc_record(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_fence(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_reclaim(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_buffer(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_limits(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_mveat_writes(void *obj, void *data,
                                QGuestAllocator *alloc);
void femu_test_plm_dtwwe_min(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_counts(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_ows(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_mveat_time(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_warn(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_aen(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_aen_after_copy(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_plm_aen_race(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_excursion(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_rain(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_format(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_vwc(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_format_buffer(void *obj, void *data,
                                 QGuestAllocator *alloc);
void femu_test_plm_hold(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_hold_reset(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_hold_abort(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_hold_cancel(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_hold_second(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_hold_lpe(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_hold_format(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_hold_small(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_hold_room(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_hold_unplug(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_pace_wait(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_pace_rate(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_pace_hold(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_pace_io_hold(void *obj, void *data,
                                QGuestAllocator *alloc);
void femu_test_plm_pace_stall(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_pace_cap(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_pace_forced(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_pace_zero(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_pace_off(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_pace_reset(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_pace_churn(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_pace_release(void *obj, void *data,
                                QGuestAllocator *alloc);
void femu_test_plm_pace_maint(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_pace_cap_min(void *obj, void *data,
                                QGuestAllocator *alloc);
void femu_test_plm_pace_spin(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_pace_band(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_plm_pace_band_valid(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_plm_gc_record_2pl(void *obj, void *data,
                                 QGuestAllocator *alloc);
void femu_test_rber_disturb(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_rber_off(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_rber_age(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_rber_wear(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_rber_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_atomic_hold(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_perf_hints(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ns_mgmt_before_identify(void *obj, void *data,
                                       QGuestAllocator *alloc);
void femu_test_oncs_default(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_compare_verify_media(void *obj, void *data,
                                    QGuestAllocator *alloc);
void femu_test_copy_timing(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pd2(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pd2_stream(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pd2_fdp(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pd2_fdp_ruamw(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_combo_fdp_hold(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_combo_read_limit(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_combo_pad_onfi(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_combo_policy(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_dsm_partial(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_eol_limits(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_block_death(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_block_death_refused(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_eol_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_eol_sq_delete(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_eol_format_busy(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_eol_dftl(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_eol_fdp_drain(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_eol_fdp_ruh(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_eol_fdp_full(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_eol_dftl_tp(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_eol_abort_reset(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_eol_wzsl(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_dftl_power(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_dftl_media(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_dftl_wl(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_tier_dftl(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_tier_dftl_idle(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_tier_mp(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_tier_buffer_flush(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_tier_buffer_upkeep(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_tier_direct(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_tier_through(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_tier_suspend_host(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_tier_suspend_fold(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_tier_busy(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_tier_dyn_borrow(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_tier_dyn_cap(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_tier_dyn_shrink(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_tier_dyn_floor(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_tier_dyn_through(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_tier_dyn_full(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_tier_fold_stop(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_tier_dyn_fold_stop(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_tier_idle_eager(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_tier_idle_wait(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_tier_idle_off(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_tier_idle_lazy(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_tier_idle_dyn(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_tier_idle_steps(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_tier_idle_write(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_tier_idle_format(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_tier_idle_sanitize(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_tier_idle_reset(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_tier_dyn_gc(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_query_stats(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_query_stats_stage_hold(void *obj, void *data,
                                      QGuestAllocator *alloc);
void femu_test_query_stats_two_ns(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_g1_eol_queues(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_g1_ring_full(void *obj, void *data, QGuestAllocator *alloc);

/* femu-test-fdp.c */
void femu_test_fdp_events(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_gc_handles(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_gc_spare(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_gc_spare_refused(void *obj, void *data,
                                    QGuestAllocator *alloc);
void femu_test_fdp_gc_recover(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_capacity_refused(void *obj, void *data,
                                    QGuestAllocator *alloc);
void femu_test_fdp_gc_strategy_refused(void *obj, void *data,
                                       QGuestAllocator *alloc);
void femu_test_fdp_single_pool(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_ruh_update(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_ruh_update_full(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_fdp_ruh_update_reserve(void *obj, void *data,
                                      QGuestAllocator *alloc);
void femu_test_fdp_background_gc(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_cb_unwritten_age(void *obj, void *data,
                                    QGuestAllocator *alloc);
void femu_test_fdp_cb_utilization(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_fdp_dftl(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_policy_pick(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_policy_refused(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_fdp_fifo_background(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_fdp_cb_background(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_write_zeroes(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_features(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_ruh_usage(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_csd_ruh_update(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_fdp_refresh(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_buffer(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_copyback(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_move_events(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_write_zeroes_placed(void *obj, void *data,
                                       QGuestAllocator *alloc);
void femu_test_fdp_csd_knobs(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_knobs_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_csd_runs(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_directive(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_refused_restores(void *obj, void *data,
                                    QGuestAllocator *unused);
void femu_test_fdp_gc_bg_invalid(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_ruh_update_moved(void *obj, void *data,
                                    QGuestAllocator *alloc);
void femu_test_fdp_ruh_update_none(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_fdp_format_ruamw(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_ns_phl(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_ns_format(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_ns_events(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_ns_knobs(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_ns_nossd(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_ns_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_ns_cmds(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_ns_replace(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_replace_full(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_hbmw_blocks(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_unprogrammed(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_runs_block(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_nossd_counts(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_confs(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_rg_place(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_rg_gc(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_rg_format_mode(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_fdp_rg_buffer(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_invalid_pid(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_dsm_empty(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_tier(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fdp_tier_timing(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_g1_fdp_handles(void *obj, void *data, QGuestAllocator *alloc);

/* femu-test-zns.c */
void femu_test_zoned_format_index(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_zone_bad_dptr(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zrwa_reopen(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zone_reset(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zns_lpz(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zns_order(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zns_cache_cap(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zns_lpz_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zns_flush_plane(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zns_wear(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zns_page_types(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zns_page_types_plc(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_zns_ecc(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zns_lun(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zns_reset_fill(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zone_append_parallel(void *obj, void *data,
                                    QGuestAllocator *alloc);
void femu_test_sgl_zoned(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zns_finish_flush(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zns_fzr(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zns_fzr_cancel(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zns_fzr_reset(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zns_fzr_only(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zns_fzr_off(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zns_fzr_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zns_rzr(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zns_rzr_reset(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zns_rzr_origins(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zns_rzr_off(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zns_rzr_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zone_open_limits(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_query_zns(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_query_zns_busy(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_query_zns_busy_unplug(void *obj, void *data,
                                     QGuestAllocator *alloc);
void femu_test_zone_report_rom(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zone_report_unlocked(void *obj, void *data,
                                    QGuestAllocator *alloc);
void femu_test_zone_reset_inflight(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_zoned_compare(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zone_change_notice(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_zone_notice_other_ns(void *obj, void *data,
                                    QGuestAllocator *alloc);
void femu_test_zone_notice_many_ns(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_zone_list_ack_fail(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_zone_list_ack_race(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_log_contents_zoned(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_zoned_append_mdts0(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_zone_active_limit(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zrwa_write_bounds(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zrwa_odd_granule(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zrwa_zd_ext(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_mdts0_zone_report(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_persist(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_zns_slc_zones(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_compare_verify_zns(void *obj, void *data,
                                  QGuestAllocator *alloc);

/* femu-test-ocssd.c */
void femu_test_identify_other_csi(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_oc20_vector_io(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_oc20_vector_reset(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_oc20_log_length(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_dpc_first_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_oc20_set_chunks(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_oc_sgl_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_oc12_timing_config(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_oc12_capabilities(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_oc12_opcodes(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_oc12_channel_gap(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_oc12_channel_timing(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_oc12_channel_profile(void *obj, void *data,
                                    QGuestAllocator *alloc);
void femu_test_oc12_ppa_timing(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_oc12_small_sectors(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_oc12_l2p_bounds(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_oc12_bad_blocks(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_oc12_trace(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_oc20_fuzz(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_oc20_page_types(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_oc20_page_types_refused(void *obj, void *data,
                                       QGuestAllocator *alloc);
void femu_test_oc_generic_refused(void *obj, void *data,
                                  QGuestAllocator *alloc);

/* femu-test-kv.c */
void femu_test_kv_namespaces_are_separate(void *obj, void *data,
                                          QGuestAllocator *alloc);
void femu_test_kv_accounting(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pd_kv(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_discovery(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_sgl_kv(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_identify_reserved(void *obj, void *data,
                                    QGuestAllocator *alloc);
void femu_test_kv_mdts(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_fuzz(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_list_mdts0(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_short_into_list(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_kv_list_walk(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_base_spread(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_gc_victim(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_css(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_hash_backshift(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_model(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_model_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_lsm_many_keys(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_lsm_list_order(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_lsm_probe_time(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_lsm_background(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_lsm_query(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_lsm_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_keys_small(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_mnk_auto(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_keys_limit(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_pack_pages(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_pack_overwrite(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_pack_flush(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_pack_flush_wait(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_kv_pack_query(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_pack_read_time(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_pack_gc(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_pack_lsm_stale(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_lsm_gc(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_lsm_full_lines(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_lsm_churn(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_lsm_full_delete(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_kv_lsm_versions(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_lsm_stale(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_lsm_meta_flash(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_lsm_delete_ednek(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_namespace_kv_byte_capacity(void *obj, void *data,
                                          QGuestAllocator *alloc);
void femu_test_kv_no_backend(void *obj, void *data, QGuestAllocator *unused);
void femu_test_memory_kv_lsm(void *obj, void *data, QGuestAllocator *unused);
void femu_test_fid_effects_kv(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_kv_identify_fmt(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_g1_kv_value_max(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_g1_kv_value_mdts(void *obj, void *data, QGuestAllocator *alloc);

/* femu-test-csd.c */
void femu_test_csd_fuzz(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_csd_program_dir(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_csd_runtime_floor(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_csd_pause(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_csd_opcodes(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_csd_no_namespace(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_csd_exec_concurrency(void *obj, void *data,
                                    QGuestAllocator *alloc);
void femu_test_copy_fmt2_own(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cps_default(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cps_subsys(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cps_identify(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cps_slm_rw(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cps_slm_copy(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cps_admin(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cps_exec(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cps_download(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cps_modeled(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cps_mdts(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cps_slm_atomic(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cps_slm_only(void *obj, void *data, QGuestAllocator *alloc);

/* femu-test-cxl.c */
void femu_test_cxl_realize(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_realize_retry(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_ftl_fail_sweep(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_cxl_bg_unplug(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_window(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_local_overlay(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_overlay_scope(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_stale_translation(void *obj, void *data,
                                     QGuestAllocator *alloc);
void femu_test_cxl_topology(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_prefetch_decoders(void *obj, void *data,
                                     QGuestAllocator *alloc);
void femu_test_cxl_switch(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_forward(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_target_bound(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_slot_reservation(void *obj, void *data,
                                    QGuestAllocator *alloc);
void femu_test_cxl_flush(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_fast_load(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_fast_load_drain(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_cxl_fast_load_backlog(void *obj, void *data,
                                     QGuestAllocator *alloc);
void femu_test_cxl_fast_load_state(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_cxl_der(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_der_modes(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_never_emulate(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_der_invalid(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_memslot_tcg(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_cylon_ack(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_revoke_batch(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_wait(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_dma_doorbell(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_no_ftl(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_invalid(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_nand_reserve(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_gc_stall(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_gc_reserve_stall(void *obj, void *data,
                                    QGuestAllocator *alloc);
void femu_test_cxl_gc_stall_warn(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_gc_wait(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_prefetch(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_prefetch_clamp(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_cxl_stats(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_ways(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_compat(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_capacity(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_log_limit(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_control(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_geometry_bounds(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_cxl_log_missing(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_lsa_normal(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_sanitize_media(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_cxl_sanitize_ratio(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_cxl_lsa_queue(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_ratio_fallback(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_cxl_ratio_off(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_ratio_runs(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_der_budget(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_der_budget_rate(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_cxl_der_replace_rate(void *obj, void *data,
                                    QGuestAllocator *alloc);
void femu_test_cxl_der_replace(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_der_budget_shared(void *obj, void *data,
                                     QGuestAllocator *alloc);
void femu_test_cxl_ratio_restore(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_ratio_budget(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_lsa_bounds(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_ratio_dirty(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_stress(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cca_off(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cca_layout(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cca_nop(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cca_pin(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cca_budget(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cca_unpin(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cca_invalidate(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cca_miss_time(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cca_uncached(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cca_prefetch(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cca_flush(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cca_ways(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cca_ratio(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cca_query(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cca_errors(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cca_reset(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cca_der(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cca_unplug(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cca_interleave(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cca_disable_abandon(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_cca_der_replace(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cca_lsa_busy(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cca_bql(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_fill_charge(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_revoke_ahead(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_fill_owner(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_walk_conflict(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_overflow_cycle(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_cxl_uncached_walk(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_overflow(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_one_rip_loops(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_fault_stop(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_pingpong_1(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_pingpong_2(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_pingpong_4(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_storm_set(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_storm_bql(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_dma_queue(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_dma_main_loop(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_dma_iothread(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_dma_thread(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_dma_page0(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_dma_fair(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_fast_load_held(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_cxl_fast_load_posted(void *obj, void *data,
                                    QGuestAllocator *alloc);
void femu_test_cxl_fill_delay(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_storm_bench(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_storm_change(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_storm_unplug(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_prefetch_race(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cca_media(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_nvme_link(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_nvme_data(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_nvme_prp(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_nvme_invalidate(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_cxl_nvme_ratio(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_nvme_deallocate(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_cxl_nvme_dulbe(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_nvme_ratio_dulbe(void *obj, void *data,
                                    QGuestAllocator *alloc);
void femu_test_cxl_nvme_flip(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_nvme_pin(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_nvme_unplug(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_nvme_guard(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cxl_nvme_barrier(void *obj, void *data, QGuestAllocator *alloc);

/* femu-test-modes.c */
void femu_test_report_length(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_query_unplug(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_query_media(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_wear(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_gc_copyback_refused(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_wear_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pd_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_onfi_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_onfi_page(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_dftl_tp(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_dftl_tp_charge(void *obj, void *data,
                              QGuestAllocator *alloc);
void femu_test_pe_suspend(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ns_retire(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_intc(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_io_stages(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_dma_error(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_copy_fmt2(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pi_rw(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_pi_copy(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_metadata(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_fuzz_mode(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_io_fuzz(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_opal_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ns_mgmt_commands(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_namespace_mixed_identity(void *obj, void *data,
                                        QGuestAllocator *alloc);
void femu_test_oc_set_latency(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_namespace_failure_naming(void *obj, void *data,
                                        QGuestAllocator *alloc);
void femu_test_namespace_sanitize_bounds(void *obj, void *data,
                                         QGuestAllocator *alloc);
void femu_test_precon_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_checkpoint(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ns_mgmt_unavailable(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_streams_resources(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_streams_write(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ftl_fail_sweep(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_mem_limit(void *obj, void *data, QGuestAllocator *unused);
void femu_test_mem_limit_modes(void *obj, void *data, QGuestAllocator *unused);
void femu_test_memory_ftl(void *obj, void *data, QGuestAllocator *unused);
void femu_test_rotational_refused(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_plane_reads(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_ns_wp_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_sanitize_ns_refused(void *obj, void *data,
                                   QGuestAllocator *alloc);
void femu_test_ocp_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_error_log_fields(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_identify_fmt(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_maint_idle_refused(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_gc_idle_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_gc_fw_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_nand_profile(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_nand_profile_refused(void *obj, void *data,
                                    QGuestAllocator *alloc);
void femu_test_perf_hints_refused(void *obj, void *data,
                                  QGuestAllocator *alloc);
void femu_test_atomic_refused(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_caps(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_cps_subsys_single(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_eol_ro(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_dftl_batch(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_g1_mdts_limit(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_g1_mdts0_large(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_g1_ring_capacity(void *obj, void *data, QGuestAllocator *alloc);
void femu_test_g1_cq_backlog(void *obj, void *data, QGuestAllocator *alloc);

#endif
