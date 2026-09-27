/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Persistent Event log page (Base 2.3, 5.2.12.1.14).
 *
 * Events are kept encoded, oldest first, in a buffer sized by PELS less the
 * header; the oldest go when a new one does not fit. A reporting context is a
 * frozen copy of the header and the events, newest first, so that events
 * logged while the host reads it are kept but not reported in it.
 *
 * An optional backing file retains events and power cycles across runs.
 */
#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "qemu/main-loop.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "system/system.h"
#include "nvme.h"

#define PEL_SIZE            (64 * KiB)  /* PELS: one 64 KiB unit */
#define PEL_HDR_SIZE        512
#define PEL_EV_HDR_SIZE     24
#define PEL_EVENTS_SIZE     (PEL_SIZE - PEL_HDR_SIZE)
#define PEL_SNAPSHOT_MS     (24 * 60 * 60 * 1000LL)

#define PEL_ACT_READ        0
#define PEL_ACT_ESTABLISH   1
#define PEL_ACT_RELEASE     2
#define PEL_ACT_HEADER      3

/* the event types this log records, which its header reports as supported */
static const uint8_t pel_supported[] = {
    NVME_PEL_SMART_SNAPSHOT,
    NVME_PEL_TIMESTAMP_CHANGE,
    NVME_PEL_POWER_ON_RESET,
    NVME_PEL_HW_ERROR,
    NVME_PEL_CHANGE_NS,
    NVME_PEL_FORMAT_START,
    NVME_PEL_FORMAT_COMPLETION,
    NVME_PEL_SANITIZE_START,
    NVME_PEL_SANITIZE_COMPLETION,
    NVME_PEL_SET_FEATURE,
    NVME_PEL_TELEMETRY_CREATED,
};

/* NVM Subsystem Hardware Error event codes (Figure 240) */
#define PEL_HWE_CRITICAL_WARNING    0x06
#define PEL_HWE_MEDIA_INTEGRITY     0x0a

/*
 * A media error can come back on every command of a failing workload. Each
 * status is limited to 10 events a second, in bursts of up to 10, which the
 * spec allows for an event that recurs, so a storm of one kind cannot push
 * everything else out of the log.
 */
#define PEL_MEDIA_RATE          10
#define PEL_MEDIA_BURST         10

struct FemuPel {
    /* guards everything below; taken from the pollers as well as the BQL */
    QemuMutex   lock;
    QEMUBH      *write_bh;
    Notifier    exit_notifier;
    FemuCtrl    *ctrl;
    uint8_t     events[PEL_EVENTS_SIZE];
    uint32_t    used;
    uint32_t    nev;
    uint16_t    gnum;
    uint8_t     *ctx;           /* header and events, or NULL for no context */
    uint32_t    ctx_len;
    QEMUTimer   *snapshot;
    /* per status code: allowance in thousandths of an event, and when */
    int32_t     media_tokens[256];
    int64_t     media_ms[256];
    /* the critical warning bits last seen; only the BQL touches this */
    uint8_t     warning;
};

static uint32_t pel_event_len(const uint8_t *e)
{
    return 3 + e[2] + lduw_le_p(e + 22);
}

/* Private file format: little-endian metadata, SHA-256, encoded events. */
#define PEL_FILE_HDR_SIZE 64

static void pel_file_digest(const uint8_t *buf, size_t len, uint8_t *digest)
{
    GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);
    gsize size = 32;

    g_checksum_update(sum, buf, 32);
    g_checksum_update(sum, buf + PEL_FILE_HDR_SIZE, len - PEL_FILE_HDR_SIZE);
    g_checksum_get_digest(sum, digest, &size);
    g_checksum_free(sum);
}

static bool pel_file_load(FemuCtrl *n, Error **errp)
{
    FemuPel *pel = n->pel;
    g_autofree uint8_t *buf = g_malloc(PEL_FILE_HDR_SIZE + PEL_EVENTS_SIZE + 1);
    uint8_t digest[32];
    size_t len = 0;
    uint32_t off;
    uint32_t count = 0;
    ssize_t got;
    int fd;

    fd = open(n->pel_file, O_RDONLY);
    if (fd < 0) {
        if (errno == ENOENT) {
            return true;
        }
        error_setg_errno(errp, errno, "Cannot read PEL file '%s'", n->pel_file);
        return false;
    }
    do {
        got = read(fd, buf + len,
                   PEL_FILE_HDR_SIZE + PEL_EVENTS_SIZE + 1 - len);
        if (got > 0) {
            len += got;
        }
    } while ((got > 0 && len <= PEL_FILE_HDR_SIZE + PEL_EVENTS_SIZE) ||
             (got < 0 && errno == EINTR));
    close(fd);
    if (got < 0 || len < PEL_FILE_HDR_SIZE ||
        len > PEL_FILE_HDR_SIZE + PEL_EVENTS_SIZE ||
        memcmp(buf, "FEMUPEL\0", 8) || ldl_le_p(buf + 8) != 1 ||
        ldl_le_p(buf + 12) != len - PEL_FILE_HDR_SIZE) {
        goto invalid;
    }
    pel_file_digest(buf, len, digest);
    if (memcmp(digest, buf + 32, sizeof(digest))) {
        goto invalid;
    }
    for (off = PEL_FILE_HDR_SIZE; off < len; count++) {
        uint32_t size;

        if (len - off < PEL_EV_HDR_SIZE || buf[off + 2] != 21) {
            goto invalid;
        }
        size = pel_event_len(buf + off);
        if (size > len - off) {
            goto invalid;
        }
        off += size;
    }
    if (count != ldl_le_p(buf + 16) || ldq_le_p(buf + 24) == UINT64_MAX) {
        goto invalid;
    }
    pel->used = len - PEL_FILE_HDR_SIZE;
    pel->nev = count;
    pel->gnum = lduw_le_p(buf + 20);
    n->pel_power_cycles = ldq_le_p(buf + 24);
    memcpy(pel->events, buf + PEL_FILE_HDR_SIZE, pel->used);
    return true;

invalid:
    error_setg(errp, "Invalid or incompatible PEL file '%s'", n->pel_file);
    return false;
}

/* Only the main loop calls this; no file I/O while holding the log lock. */
static bool pel_file_save(FemuCtrl *n, Error **errp)
{
    FemuPel *pel = n->pel;
    g_autofree uint8_t *buf = NULL;
    g_autofree char *tmp = NULL;
    g_autofree char *dir = NULL;
    size_t len;
    int fd;
    int saved_errno;

    if (!n->pel_file) {
        return true;
    }
    qemu_mutex_lock(&pel->lock);
    len = PEL_FILE_HDR_SIZE + pel->used;
    buf = g_malloc0(len);
    memcpy(buf, "FEMUPEL\0", 8);
    stl_le_p(buf + 8, 1);
    stl_le_p(buf + 12, pel->used);
    stl_le_p(buf + 16, pel->nev);
    stw_le_p(buf + 20, pel->gnum);
    stq_le_p(buf + 24, n->pel_power_cycles);
    memcpy(buf + PEL_FILE_HDR_SIZE, pel->events, pel->used);
    qemu_mutex_unlock(&pel->lock);
    pel_file_digest(buf, len, buf + 32);

    tmp = g_strconcat(n->pel_file, ".XXXXXX", NULL);
    fd = g_mkstemp(tmp);
    if (fd < 0) {
        goto fail;
    }
    if (qemu_write_full(fd, buf, len) != len || fsync(fd) < 0) {
        saved_errno = errno;
        close(fd);
        errno = saved_errno;
        goto fail;
    }
    if (close(fd) < 0 || rename(tmp, n->pel_file) < 0) {
        goto fail;
    }
    /* Make the replacement durable in the containing directory too. */
    dir = g_path_get_dirname(n->pel_file);
    fd = open(dir, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        goto fail;
    }
    if (fsync(fd) < 0) {
        saved_errno = errno;
        close(fd);
        errno = saved_errno;
        goto fail;
    }
    if (close(fd) < 0) {
        goto fail;
    }
    return true;

fail:
    saved_errno = errno;
    unlink(tmp);
    error_setg_errno(errp, saved_errno, "Cannot save PEL file '%s'",
                     n->pel_file);
    return false;
}

static void pel_file_write(void *opaque)
{
    FemuCtrl *n = opaque;
    Error *err = NULL;

    if (!pel_file_save(n, &err)) {
        error_report_err(err);
    }
}

static void pel_file_exit(Notifier *notifier, void *data)
{
    FemuPel *pel = container_of(notifier, FemuPel, exit_notifier);
    bool resume = nvme_pause_pollers(pel->ctrl);

    pel_file_write(pel->ctrl);
    nvme_resume_pollers(pel->ctrl, resume);
}

/* Figure 414: the value alone, its top two bytes reserved */
static uint64_t pel_ts414(FemuCtrl *n)
{
    return nvme_timestamp(n) & ((1ULL << 48) - 1);
}

void femu_pel_log(FemuCtrl *n, uint8_t et, uint8_t etr, const void *data,
                  uint16_t len)
{
    FemuPel *pel = n->pel;
    uint32_t size = PEL_EV_HDR_SIZE + len;
    uint8_t *e;

    if (!pel || size > PEL_EVENTS_SIZE) {
        return;
    }

    qemu_mutex_lock(&pel->lock);
    while (pel->used + size > PEL_EVENTS_SIZE) {
        uint32_t first = pel_event_len(pel->events);

        memmove(pel->events, pel->events + first, pel->used - first);
        pel->used -= first;
        pel->nev--;
    }
    e = pel->events + pel->used;
    memset(e, 0, PEL_EV_HDR_SIZE);
    e[0] = et;
    e[1] = etr;
    e[2] = PEL_EV_HDR_SIZE - 3;                 /* EHL */
    e[3] = 0x3;                                 /* PIT 11b: no port */
    stw_le_p(e + 4, n->cntlid);
    stq_le_p(e + 6, pel_ts414(n));
    stw_le_p(e + 22, len);                      /* EL, no vendor data */
    memcpy(e + PEL_EV_HDR_SIZE, data, len);
    pel->used += size;
    pel->nev++;
    if (pel->write_bh) {
        qemu_bh_schedule(pel->write_bh);
    }
    qemu_mutex_unlock(&pel->lock);
}

/* Base Figure 250; unchanged successful settings are logged as permitted. */
void femu_pel_set_feature(FemuCtrl *n, const NvmeCmd *cmd,
                          const void *buffer, uint16_t len)
{
    g_autofree uint8_t *ev = NULL;

    /*
     * Figure 249 excludes P/NR entries for an I/O controller; LBA Range Type
     * is NR in the NVM Command Set (Figure 16), and its 4 KiB buffer would
     * push out a log's worth of events in a few commands.
     */
    switch (NVME_GETSETFEAT_FID(le32_to_cpu(cmd->cdw10))) {
    case NVME_ARBITRATION:
    case NVME_TEMPERATURE_THRESHOLD:
    case NVME_ERROR_RECOVERY:
    case NVME_VOLATILE_WRITE_CACHE:
    case NVME_NUMBER_OF_QUEUES:
    case NVME_INTERRUPT_COALESCING:
    case NVME_INTERRUPT_VECTOR_CONF:
    case NVME_WRITE_ATOMICITY:
    case NVME_HOST_BEHAVIOR_SUPPORT:
    case NVME_COMMAND_SET_PROFILE:
    case NVME_FDP_MODE:
    case NVME_FDP_EVENTS:
    case NVME_KV_FEAT_CONFIG:
        break;
    default:
        return;
    }

    ev = g_malloc(28 + len);
    stl_le_p(ev, 6 | ((uint32_t)len << 16));
    memcpy(ev + 4, &cmd->cdw10, 24);
    if (len) {
        memcpy(ev + 28, buffer, len);
    }
    femu_pel_log(n, NVME_PEL_SET_FEATURE, 1, ev, 28 + len);
}

/* Figure 237 with one Figure 238 descriptor: FEMU has one controller */
static void pel_log_power_on_reset(FemuCtrl *n)
{
    uint8_t ev[8 + 36] = { 0 };
    uint8_t *d = ev + 8;

    memcpy(ev, n->id_ctrl.fr, 8);
    stw_le_p(d, n->cntlid);
    stl_le_p(d + 16, MIN(n->pel_power_cycles, UINT32_MAX));
    stq_le_p(d + 20, nvme_power_on_ms(n));
    stq_le_p(d + 28, pel_ts414(n));
    femu_pel_log(n, NVME_PEL_POWER_ON_RESET, 1, ev, sizeof(ev));
}

/* an NVM Subsystem Hardware Error event (Figure 239), revision 2 */
static void pel_log_hw_error(FemuCtrl *n, uint16_t code, const void *info,
                             uint16_t len)
{
    uint8_t ev[4 + sizeof(NvmeCqe)] = { 0 };

    stw_le_p(ev, code);
    memcpy(ev + 4, info, len);
    femu_pel_log(n, NVME_PEL_HW_ERROR, 2, ev, 4 + len);
}

/* Figures 239-241: code 08h and the 17-byte power-loss information field. */
void femu_pel_power_loss(FemuCtrl *n)
{
    uint8_t ev[21] = { 0 };

    stw_le_p(ev, 0x08);
    stq_le_p(ev + 4, n->unsafe_shutdowns[0]);
    stq_le_p(ev + 12, n->unsafe_shutdowns[1]);
    /* No out-of-band management operation caused this cut. */
    femu_pel_log(n, NVME_PEL_HW_ERROR, 2, ev, sizeof(ev));
}

/*
 * A Critical Warning bit that has just come on is an event (code 06h), with
 * the whole warning byte as it now stands. Bits that go off are only noted,
 * so the same bit coming back on is a new event.
 */
void femu_pel_warning(FemuCtrl *n, uint8_t warning)
{
    FemuPel *pel = n->pel;

    if (!pel) {
        return;
    }
    if (warning & ~pel->warning) {
        pel_log_hw_error(n, PEL_HWE_CRITICAL_WARNING, &warning, 1);
    }
    pel->warning = warning;
}

/*
 * A completion with a Media and Data Integrity status other than Access
 * Denied or Deallocated or Unwritten Logical Block (code 0Ah), carrying the
 * completion entry. Called from wherever completions are written, pollers
 * included.
 */
void femu_pel_media_error(FemuCtrl *n, const NvmeCqe *cqe)
{
    FemuPel *pel = n->pel;
    uint8_t sc = (le16_to_cpu(cqe->status) >> 1) & 0xff;
    int64_t now, refill;
    bool log;

    if (!pel) {
        return;
    }
    /*
     * Read the clock under the lock: pollers on other queues post the same
     * status, and a time taken before waiting here could be older than the
     * one already applied, which would take tokens away.
     */
    qemu_mutex_lock(&pel->lock);
    now = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
    refill = MAX(0, now - pel->media_ms[sc]) * PEL_MEDIA_RATE;
    pel->media_tokens[sc] = MIN(PEL_MEDIA_BURST * 1000LL,
                                pel->media_tokens[sc] + refill);
    pel->media_ms[sc] = now;
    log = pel->media_tokens[sc] >= 1000;
    if (log) {
        pel->media_tokens[sc] -= 1000;
    }
    qemu_mutex_unlock(&pel->lock);

    if (log) {
        pel_log_hw_error(n, PEL_HWE_MEDIA_INTEGRITY, cqe, sizeof(*cqe));
    }
}

static void pel_log_smart(FemuCtrl *n)
{
    NvmeSmartLog smart;

    nvme_smart_fill(n, &smart);
    femu_pel_log(n, NVME_PEL_SMART_SNAPSHOT, 1, &smart, sizeof(smart));
    femu_pel_warning(n, smart.critical_warning);
}

/*
 * At least one snapshot every 24 power-on hours (5.2.12.1.14.2.1). The I/O
 * path updates the counters it reads, so it stops for the snapshot.
 */
static void pel_snapshot_timer(void *opaque)
{
    FemuCtrl *n = opaque;
    bool resume = nvme_pause_pollers(n);

    pel_log_smart(n);
    nvme_resume_pollers(n, resume);
    timer_mod(n->pel->snapshot,
              qemu_clock_get_ms(QEMU_CLOCK_REALTIME) + PEL_SNAPSHOT_MS);
}

bool femu_pel_init(FemuCtrl *n, Error **errp)
{
    FemuPel *pel = g_new0(FemuPel, 1);

    qemu_mutex_init(&pel->lock);
    for (int i = 0; i < ARRAY_SIZE(pel->media_tokens); i++) {
        pel->media_tokens[i] = PEL_MEDIA_BURST * 1000;
    }
    n->pel = pel;
    n->pel_power_cycles = 1;
    if (n->pel_file) {
        n->pel_power_cycles = 0;
        if (!pel_file_load(n, errp)) {
            n->pel = NULL;
            qemu_mutex_destroy(&pel->lock);
            g_free(pel);
            return false;
        }
        n->pel_power_cycles++;
    }
    pel->snapshot = timer_new_ms(QEMU_CLOCK_REALTIME, pel_snapshot_timer, n);
    timer_mod(pel->snapshot, n->power_on_ms + PEL_SNAPSHOT_MS);

    pel_log_power_on_reset(n);
    pel_log_smart(n);
    if (!pel_file_save(n, errp)) {
        femu_pel_exit(n);
        return false;
    }
    if (n->pel_file) {
        pel->ctrl = n;
        pel->write_bh = qemu_bh_new(pel_file_write, n);
        pel->exit_notifier.notify = pel_file_exit;
        qemu_add_exit_notifier(&pel->exit_notifier);
    }
    return true;
}

void femu_pel_exit(FemuCtrl *n)
{
    FemuPel *pel = n->pel;

    if (!pel) {
        return;
    }
    if (pel->write_bh) {
        pel_file_write(n);
        qemu_bh_delete(pel->write_bh);
        qemu_remove_exit_notifier(&pel->exit_notifier);
    }
    timer_free(pel->snapshot);
    n->pel = NULL;
    qemu_mutex_destroy(&pel->lock);
    g_free(pel->ctx);
    g_free(pel);
}

/*
 * A Controller Level Reset drops the reporting context, then is itself an
 * event, followed by the snapshot the spec asks for at power on or reset.
 */
void femu_pel_reset(FemuCtrl *n)
{
    FemuPel *pel = n->pel;

    if (!pel) {
        return;
    }
    qemu_mutex_lock(&pel->lock);
    g_clear_pointer(&pel->ctx, g_free);
    pel->ctx_len = 0;
    qemu_mutex_unlock(&pel->lock);

    pel_log_power_on_reset(n);
    pel_log_smart(n);
    pel_file_write(n);
}

/* build the context: Figure 230's header, then the events newest first */
static void pel_establish(FemuCtrl *n)
{
    FemuPel *pel = n->pel;
    NvmeIdCtrl *id = &n->id_ctrl;
    g_autofree uint32_t *offs = g_new(uint32_t, pel->nev + 1);
    uint8_t *h, *p;
    uint32_t o, i;

    pel->ctx_len = PEL_HDR_SIZE + pel->used;
    pel->ctx = g_malloc0(pel->ctx_len);
    h = pel->ctx;

    h[0] = NVME_LOG_PERSISTENT_EVENT;
    stl_le_p(h + 4, pel->nev);
    stq_le_p(h + 8, pel->ctx_len);
    h[16] = 3;                                  /* LREV */
    stw_le_p(h + 18, PEL_HDR_SIZE - 20);        /* LHL */
    stq_le_p(h + 20, nvme_timestamp(n));        /* Figure 415 */
    stq_le_p(h + 44, n->pel_power_cycles);       /* PWRCC */
    memcpy(h + 52, &id->vid, 2);
    memcpy(h + 54, &id->ssvid, 2);
    memcpy(h + 56, id->sn, sizeof(id->sn));
    memcpy(h + 76, id->mn, sizeof(id->mn));
    memcpy(h + 116, id->subnqn, sizeof(id->subnqn));
    pel->gnum++;                                /* wraps FFFFh to 0 */
    if (pel->write_bh) {
        qemu_bh_schedule(pel->write_bh);
    }
    stw_le_p(h + 372, pel->gnum);
    for (i = 0; i < ARRAY_SIZE(pel_supported); i++) {
        if (pel_supported[i] == NVME_PEL_CHANGE_NS &&
            !nvme_ns_mgmt_supported(n)) {
            continue;
        }
        h[480 + pel_supported[i] / 8] |= 1 << (pel_supported[i] % 8);
    }

    for (o = 0, i = 0; o < pel->used; o += pel_event_len(pel->events + o)) {
        offs[i++] = o;
    }
    p = h + PEL_HDR_SIZE;
    while (i--) {
        uint32_t len = pel_event_len(pel->events + offs[i]);

        memcpy(p, pel->events + offs[i], len);
        p += len;
    }
}

/* write a header field into the part of the page this read returns */
static void pel_overlay(uint8_t *out, uint64_t off, uint32_t out_len,
                        uint32_t field, const uint8_t *val, uint32_t len)
{
    uint32_t i;

    for (i = 0; i < len; i++) {
        if (field + i >= off && field + i < off + out_len) {
            out[field + i - off] = val[i];
        }
    }
}

/*
 * Get Log Page 0Dh. The action is bits 9:8 of CDW10 (Figure 229). Release
 * and header-only ignore the length and offset, which the caller has not
 * checked for them.
 */
uint16_t femu_pel_get_log(FemuCtrl *n, NvmeCmd *cmd, uint32_t len,
                          uint64_t off)
{
    FemuPel *pel = n->pel;
    uint8_t act = (le32_to_cpu(cmd->cdw10) >> 8) & 0x3;
    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp2);
    g_autofree uint8_t *out = NULL;
    uint8_t poh[16] = { 0 };
    uint8_t rci[4] = { 0 };
    uint32_t out_len;
    bool existed;

    if (!pel) {
        return NVME_INVALID_LOG_ID | NVME_DNR;
    }

    qemu_mutex_lock(&pel->lock);
    existed = pel->ctx;
    switch (act) {
    case PEL_ACT_RELEASE:
        g_clear_pointer(&pel->ctx, g_free);
        pel->ctx_len = 0;
        qemu_mutex_unlock(&pel->lock);
        return NVME_SUCCESS;
    case PEL_ACT_READ:
        if (!existed) {
            qemu_mutex_unlock(&pel->lock);
            return NVME_CMD_SEQ_ERROR;
        }
        break;
    case PEL_ACT_ESTABLISH:
        if (existed) {
            qemu_mutex_unlock(&pel->lock);
            return NVME_CMD_SEQ_ERROR;
        }
        pel_establish(n);
        break;
    case PEL_ACT_HEADER:
        if (!existed) {
            pel_establish(n);
        }
        off = 0;
        len = PEL_HDR_SIZE;
        break;
    }
    if (off >= pel->ctx_len) {
        qemu_mutex_unlock(&pel->lock);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    out_len = MIN(len, pel->ctx_len - off);
    out = g_memdup2(pel->ctx + off, out_len);
    qemu_mutex_unlock(&pel->lock);

    /*
     * Two header fields describe the request rather than the snapshot:
     * Power on Hours at retrieval, and Reporting Context Information, which
     * says whether a context existed before this command. One that existed
     * was made through the host's port, port 0 here.
     */
    stq_le_p(poh, nvme_power_on_ms(n) / 3600000);
    pel_overlay(out, off, out_len, 28, poh, sizeof(poh));
    if (existed) {
        stl_le_p(rci, 1 << 18 | 1 << 16);
    }
    pel_overlay(out, off, out_len, 374, rci, sizeof(rci));

    return dma_read_prp_fill(n, out, out_len, len, prp1, prp2);
}
