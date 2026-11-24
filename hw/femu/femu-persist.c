/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Data persistence across QEMU runs (persist_file).
 *
 * The data backend holds every byte the host wrote, addressed by LBA, so
 * the data survives a restart once the backend survives it. Realize loads
 * the file; a device unplug or the end of QEMU saves it, with the workers
 * stopped. Without persist_ftl the FTL state is not kept: a restarted bbssd
 * device times its first accesses as a fresh drive does, but every read
 * returns the data that was written, and deallocated or uncorrectable
 * blocks stay so. With persist_ftl (version 3) the bbssd FTL state of each
 * namespace follows, and the restarted drive continues where it stopped.
 *
 *   file: header (64 B) | one 32 B record per namespace | backend bytes |
 *         per namespace: allocation bitmap, uncorrectable bitmap |
 *         version 3 with flag 2: u64 length + LBA status section |
 *         version 3 with flag 1: per namespace, u64 length + FTL section
 *   save: file.XXXXXX, write, fsync, rename, fsync the directory
 *
 * The FTL state must match the data: before a save with persist_ftl, the
 * requests already fetched must leave the FTL (persist_drain()).
 *
 * The header and records name the mode, the backend size and each
 * namespace's slice and LBA format; a file that differs is refused, so
 * another layout cannot read these bytes. Format NVM keeps the LBA format
 * the device started with. A lock file keeps a second device or process
 * from saving over the same file.
 */

#include "qemu/osdep.h"
#include <sys/file.h>
#include <sys/vfs.h>
#include "qom/qom-qobject.h"
#include "qobject/qbool.h"
#include "qobject/qjson.h"
#include "qobject/qnum.h"
#include "qobject/qstring.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "system/system.h"
#include "qemu/main-loop.h"
#include "qemu/thread.h"
#include "qapi/qapi-events-femu.h"
#include "nvme.h"

#define PERSIST_MAGIC     "FEMUDATA"
#define PERSIST_VERSION   2
#define PERSIST_V_FTL     3       /* adds the FTL sections */
#define PERSIST_F_FTL     0x1     /* header byte 28: FTL sections follow */
#define PERSIST_F_LSI     0x2     /* the LBA status section follows */
#define PERSIST_HDR_SIZE  64
#define PERSIST_NS_SIZE   32
#define PERSIST_DRAIN_MS  10000

static size_t persist_meta_len(FemuCtrl *n)
{
    return PERSIST_HDR_SIZE + (size_t)n->num_namespaces * PERSIST_NS_SIZE;
}

/* the header and namespace records that describe this device's layout */
static uint8_t *persist_meta(FemuCtrl *n, uint32_t version, uint32_t flags)
{
    uint8_t *m = g_malloc0(persist_meta_len(n));

    memcpy(m, PERSIST_MAGIC, 8);
    stl_le_p(m + 8, version);
    stl_le_p(m + 28, flags);
    stl_le_p(m + 12, n->femu_mode);
    stq_le_p(m + 16, n->mbe->size);
    stl_le_p(m + 24, n->num_namespaces);
    for (uint32_t i = 0; i < n->num_namespaces; i++) {
        NvmeNamespace *ns = &n->namespaces[i];
        uint8_t *r = m + PERSIST_HDR_SIZE + i * PERSIST_NS_SIZE;
        int lbaf = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);

        stq_le_p(r, ns->backend_offset);
        stq_le_p(r + 8, ns->size);
        stq_le_p(r + 16, le64_to_cpu(ns->id_ns.nsze));
        r[24] = ns->id_ns.lbaf[lbaf].lbads;
        stw_le_p(r + 26, le16_to_cpu(ns->id_ns.lbaf[lbaf].ms));
    }
    return m;
}

static size_t persist_bitmap_len(NvmeNamespace *ns)
{
    return BITS_TO_LONGS(le64_to_cpu(ns->id_ns.nsze)) * sizeof(unsigned long);
}

static bool persist_write(int fd, const void *buf, size_t len)
{
    return !len || qemu_write_full(fd, buf, len) == len;
}

/* pread @len bytes at @off, retrying an interrupted call; false on EOF */
static bool persist_read(int fd, void *buf, size_t len, off_t off)
{
    while (len) {
        ssize_t got = pread(fd, buf, len, off);

        if (got < 0 && errno == EINTR) {
            continue;
        }
        if (got <= 0) {
            return false;
        }
        buf = (uint8_t *)buf + got;
        len -= got;
        off += got;
    }
    return true;
}

/*
 * The properties an FTL section depends on: the layout, the mapping, the
 * GC choices and the NAND times. Each enters as "name=<JSON value>;", so
 * a section loads only into an FTL that would have built the same state.
 * This list is the whole digest of schema 1: never change it.
 */
static const char *const persist_ftl_props[] = {
    "femu_mode", "devsz_mb", "namespaces", "namespace_sizes", "secsz",
    "secs_per_pg", "pgs_per_blk", "blks_per_pl", "pls_per_lun",
    "luns_per_ch", "nchs", "mapping", "op_pcent", "gc_policy",
    "gc_strategy", "gc_thres_pcent", "gc_thres_pcent_high", "gc_seed",
    "pg_rd_lat", "pg_wr_lat", "blk_er_lat", "ch_xfer_lat",
    "cmd_addr_lat", "pg_xfer_lat", "status_lat", "tplpbsy", "tplrbsy",
    "tplebsy", "trcbsy", "ecc_step_ns", "onfi_mode", "onfi_mts",
    "onfi_spare_bytes", "onfi_tccs_ns", "onfi_sca", "flash_type",
    "nand_cell_type", "cell_pages", "pgtype_lat", "lba_index",
};

/*
 * The aging models and every property that changes what their state
 * means: schema 2 hashes them after the list above.
 */
static const char *const persist_aging_props[] = {
    "blk_pe_limit", "blk_pe_spread", "blk_pe_seed", "eol_read_only",
    "spare_lines", "wl_spread", "read_reclaim_limit", "retention_limit_sec",
    "ecc_retention_sec", "age_scale", "rber_ppb", "rber_timing_only",
    "rber_seed", "rber_pe_double", "rber_age_double_sec", "rber_read_double",
    "ecc_cw_bytes", "ecc_hard_bits", "ecc_soft_bits", "rr_steps", "rr_gain",
    "rr_floor_pct", "rr_soft_senses", "rr_soft_ns", "mdts", "mpsmin",
    "pe_cycles_rated", "nand_bad_blocks", "pd_edge_wls", "pd_edge_tiers",
    "pd_open_tiers", "maint_idle", "nlbaf",
};

/*
 * Aging properties added after schema 2: each joins the digest only when
 * it is not zero, so a file of a device without them still loads.
 */
static const char *const persist_aging_opt_props[] = {
    "blk_early_ppm", "blk_early_pe",
};

/* the aging models: a device with one keeps a history across restarts */
static const char *const persist_aging_models[] = {
    "blk_pe_limit", "spare_lines", "wl_spread", "read_reclaim_limit",
    "retention_limit_sec", "ecc_retention_sec", "rber_ppb",
};

/* the digest of schema 1, or with @aging the digest of schema 2 */
static uint64_t persist_digest(FemuCtrl *n, bool aging)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    size_t n1 = ARRAY_SIZE(persist_ftl_props);
    size_t n2 = n1 + (aging ? ARRAY_SIZE(persist_aging_props) : 0);
    size_t nall = n2 + (aging ? ARRAY_SIZE(persist_aging_opt_props) : 0);

    for (size_t i = 0; i < nall; i++) {
        const char *name = i < n1 ? persist_ftl_props[i] :
                           i < n2 ? persist_aging_props[i - n1] :
                                    persist_aging_opt_props[i - n2];
        QObject *v;
        g_autoptr(GString) s = NULL;

        if (i >= n2 && !object_property_get_uint(OBJECT(n), name, NULL)) {
            continue;
        }
        v = object_property_get_qobject(OBJECT(n), name, NULL);
        s = g_string_new(name);

        /* a misspelt aging name would leave its property out unseen */
        assert(v || i < n1);

        g_string_append_c(s, '=');
        /* an unset mapping or GC policy is the default one */
        if (v && qobject_type(v) == QTYPE_QSTRING &&
            !*qstring_get_str(qobject_to(QString, v))) {
            qobject_unref(v);
            v = NULL;
            g_string_append(s, !strcmp(name, "mapping") ? "\"page\"" :
                               !strcmp(name, "gc_policy") ? "\"greedy\"" :
                               "\"\"");
        }
        if (v) {
            g_autoptr(GString) js = qobject_to_json(v);

            g_string_append(s, js->str);
            qobject_unref(v);
        }
        g_string_append_c(s, ';');
        for (size_t k = 0; k < s->len; k++) {
            h = (h ^ (uint8_t)s->str[k]) * 0x100000001b3ULL;
        }
    }
    return h;
}

/* the namespaces whose FTL a version 3 file holds, in namespace order */
static bool persist_ftl_ns(NvmeNamespace *ns)
{
    return ns->ssd && !ns->ssd_shared && NS_BBSSD(ns);
}

/* the properties an FTL section cannot carry the state of */
static const char *const persist_ftl_refused[] = {
    "streams", "tier_mode", "buffer_size", "hot_cold_sep", "gc_frontier",
    "gc_pace", "gc_idle_ms", "gc_copyback", "pd_open_read_limit",
    "pd_open_close_sec", "pd_open_age", "err_read_unc_ppm",
    "err_write_fail_ppm", "erase_fail_ppm",
    "die_parity", "rain_parity", "read_cache_mb", "prog_pass2_ns",
    "onfi_param_page",
    "nand_profile", "mp_program", "mp_read", "onfi_cache_read",
    "pe_suspend", "read_prio", "iu_pages", "plane_first", "power_loss",
};

/* whether property @name holds anything but 0, false or an empty string */
static bool persist_prop_set(FemuCtrl *n, const char *name)
{
    QObject *v = object_property_get_qobject(OBJECT(n), name, NULL);
    bool set = false;

    if (!v) {
        return false;
    }
    switch (qobject_type(v)) {
    case QTYPE_QBOOL:
        set = qbool_get_bool(qobject_to(QBool, v));
        break;
    case QTYPE_QNUM: {
        uint64_t u;

        set = qnum_get_try_uint(qobject_to(QNum, v), &u) ? u != 0 : true;
        break;
    }
    case QTYPE_QSTRING:
        set = *qstring_get_str(qobject_to(QString, v)) != '\0';
        break;
    default:
        break;
    }
    qobject_unref(v);
    return set;
}

/* an aging model is on */
static bool persist_aging(FemuCtrl *n)
{
    for (size_t i = 0; i < ARRAY_SIZE(persist_aging_models); i++) {
        if (persist_prop_set(n, persist_aging_models[i])) {
            return true;
        }
    }
    return false;
}

static bool persist_ftl_check(FemuCtrl *n, Error **errp)
{
    const char *map = n->bb_params.mapping_scheme;

    if (n->femu_mode != FEMU_BBSSD_MODE) {
        error_setg(errp, "persist_ftl needs femu_mode=1 (bbssd)");
        return false;
    }
    if (map && *map && strcmp(map, "page")) {
        error_setg(errp, "persist_ftl needs mapping=page");
        return false;
    }
    if (n->subsys && n->subsys->params.fdp.enabled) {
        error_setg(errp, "persist_ftl is not supported with FDP");
        return false;
    }
    for (size_t i = 0; i < ARRAY_SIZE(persist_ftl_refused); i++) {
        if (persist_prop_set(n, persist_ftl_refused[i])) {
            error_setg(errp, "persist_ftl is not supported with %s",
                       persist_ftl_refused[i]);
            return false;
        }
    }
    return true;
}

/* the rings of fetched requests are empty: no request is on its way in */
static bool persist_rings_empty(FemuCtrl *n)
{
    for (int i = 1; n->to_ftl && i <= n->nr_pollers; i++) {
        if (n->to_ftl[i] && femu_ring_count(n->to_ftl[i])) {
            return false;
        }
    }
    return true;
}

/*
 * Hold the workers with every fetched request through the FTL, so the
 * data and the FTL state agree. A request on the to_ftl ring has changed
 * the backend already; the FTL must take it before the save. The workers
 * run between tries. On success the workers stay paused: the caller
 * resumes them with *resume.
 */
static bool persist_drain(FemuCtrl *n, bool *resume, Error **errp)
{
    int64_t end = g_get_monotonic_time() + PERSIST_DRAIN_MS * 1000;

    for (;;) {
        *resume = nvme_pause_pollers(n);
        if (persist_rings_empty(n)) {
            return true;
        }
        nvme_resume_pollers(n, *resume);
        if (g_get_monotonic_time() >= end || !*resume) {
            error_setg(errp, "persist_ftl: fetched requests stayed on the "
                       "FTL queue; nothing saved");
            return false;
        }
        g_usleep(1000);
    }
}

/* one piece of the file, in file order */
typedef struct PersistSeg {
    const void *p;
    size_t len;
    void *own;              /* freed with the list */
    GByteArray *ba;         /* freed with the list */
} PersistSeg;

static void persist_seg(GArray *segs, const void *p, size_t len, void *own,
                        GByteArray *ba)
{
    PersistSeg seg = { .p = p, .len = len, .own = own, .ba = ba };

    g_array_append_val(segs, seg);
}

static void persist_segs_free(GArray *segs)
{
    for (guint i = 0; segs && i < segs->len; i++) {
        PersistSeg *seg = &g_array_index(segs, PersistSeg, i);

        g_free(seg->own);
        if (seg->ba) {
            g_byte_array_unref(seg->ba);
        }
    }
    if (segs) {
        g_array_free(segs, true);
    }
}

/* a little-endian length word, owned by the list */
static void persist_seg_len(GArray *segs, uint64_t len)
{
    uint8_t *w = g_malloc(8);

    stq_le_p(w, len);
    persist_seg(segs, w, 8, w, NULL);
}

/*
 * The file as a list of pieces; the workers are paused. With @copy, the
 * backend and the bitmaps go to the buffers in @pre (backend, then util
 * and uncorrectable of each namespace), so the list holds no live state.
 */
static GArray *persist_segs(FemuCtrl *n, void **pre)
{
    uint8_t *meta = persist_meta(n, PERSIST_V_FTL,
                                 PERSIST_F_LSI |
                                 (n->persist_ftl ? PERSIST_F_FTL : 0));
    GByteArray *lsi = femu_lsi_save(n);
    GArray *segs = g_array_new(false, false, sizeof(PersistSeg));
    int k = 0;

    persist_seg(segs, meta, persist_meta_len(n), meta, NULL);
    if (pre) {
        memcpy(pre[k], n->mbe->logical_space, n->mbe->size);
        persist_seg(segs, pre[k], n->mbe->size, pre[k], NULL);
        k++;
    } else {
        persist_seg(segs, n->mbe->logical_space, n->mbe->size, NULL, NULL);
    }
    for (uint32_t i = 0; i < n->num_namespaces; i++) {
        NvmeNamespace *ns = &n->namespaces[i];
        size_t len = persist_bitmap_len(ns);
        const void *bm[2] = { ns->util, ns->uncorrectable };

        for (int b = 0; b < 2; b++) {
            if (pre) {
                memcpy(pre[k], bm[b], len);
                persist_seg(segs, pre[k], len, pre[k], NULL);
                k++;
            } else {
                persist_seg(segs, bm[b], len, NULL, NULL);
            }
        }
    }
    persist_seg_len(segs, lsi->len);
    persist_seg(segs, lsi->data, lsi->len, NULL, lsi);
    for (uint32_t i = 0; n->persist_ftl && i < n->num_namespaces; i++) {
        NvmeNamespace *ns = &n->namespaces[i];
        int schema = n->test_persist_schema == 1 ? 1 : 2;
        GByteArray *sec;

        if (!persist_ftl_ns(ns)) {
            continue;
        }
        sec = ssd_persist_save(ns->ssd, persist_digest(n, schema == 2),
                               schema);
        persist_seg_len(segs, sec->len);
        persist_seg(segs, sec->data, sec->len, NULL, sec);
    }
    return segs;
}

/*
 * Write @segs to @path through a temporary file and a rename. It reads only
 * @segs, so a thread without the BQL may run it.
 */
static bool persist_write_file(const char *path, GArray *segs, Error **errp)
{
    g_autofree char *tmp = g_strconcat(path, ".XXXXXX", NULL);
    g_autofree char *dir = g_path_get_dirname(path);
    int fd;
    int saved_errno;
    bool ok = true;

    fd = g_mkstemp(tmp);
    if (fd < 0) {
        error_setg_errno(errp, errno, "persist_file: cannot create '%s'",
                         tmp);
        return false;
    }
    for (guint i = 0; ok && i < segs->len; i++) {
        PersistSeg *seg = &g_array_index(segs, PersistSeg, i);

        ok = persist_write(fd, seg->p, seg->len);
    }
    if (!ok || fsync(fd) < 0) {
        saved_errno = errno;
        close(fd);
        unlink(tmp);
        error_setg_errno(errp, saved_errno, "persist_file: cannot write '%s'",
                         path);
        return false;
    }
    if (close(fd) < 0 || rename(tmp, path) < 0) {
        saved_errno = errno;
        unlink(tmp);
        error_setg_errno(errp, saved_errno, "persist_file: cannot save '%s'",
                         path);
        return false;
    }
    /* the rename is durable only once the directory is */
    fd = open(dir, O_RDONLY | O_DIRECTORY);
    if (fd < 0 || fsync(fd) < 0) {
        error_setg_errno(errp, errno, "persist_file: cannot sync '%s'", dir);
        if (fd >= 0) {
            close(fd);
        }
        return false;
    }
    close(fd);
    return true;
}

static bool persist_torn_check(FemuCtrl *n, Error **errp)
{
    if (n->persist_ftl && n->persist_torn) {
        error_setg(errp, "persist_ftl: a fetched request left without "
                   "reaching the FTL (a queue deleted or a reset under I/O, "
                   "or a drain that timed out); nothing saved");
        return false;
    }
    return true;
}

static bool persist_save_to(FemuCtrl *n, const char *path, Error **errp)
{
    GArray *segs;
    bool ok;

    if (!persist_torn_check(n, errp)) {
        return false;
    }
    segs = persist_segs(n, NULL);
    ok = persist_write_file(path, segs, errp);
    persist_segs_free(segs);
    return ok;
}

/*
 * femu-save-data background=true. The command copies the file into @segs
 * with the workers paused; the thread writes it without the BQL. One job
 * per device, in n->save_job, which only the BQL holder changes.
 */
struct FemuSaveJob {
    FemuCtrl *n;
    QemuThread thread;
    QEMUBH *bh;             /* the writer's end, in the main loop */
    QemuEvent go;           /* x-save-hold: set when the writer may write */
    Notifier exit;          /* QEMU's end waits for the writer */
    GArray *segs;
    char *path;
    int lock_fd;            /* holds path.lock */
    Error *err;             /* the writer's result */
};

static void *persist_job_run(void *opaque)
{
    FemuSaveJob *job = opaque;

    qemu_event_wait(&job->go);
    persist_write_file(job->path, job->segs, &job->err);
    qemu_bh_schedule(job->bh);
    return NULL;
}

/*
 * End the job of @n, once: the first caller takes it from the device. The
 * writer may wait on the hold, so it is let go before the join. Only the
 * end in the main loop (@emit) sends the event: at QEMU's end the monitors
 * are gone, and at an unplug the device is.
 */
static void persist_job_end(FemuCtrl *n, bool emit)
{
    FemuSaveJob *job = n->save_job;
    g_autofree char *dev = NULL;

    if (!job) {
        return;
    }
    n->save_job = NULL;
    qemu_event_set(&job->go);
    qemu_thread_join(&job->thread);
    qemu_bh_delete(job->bh);
    qemu_event_destroy(&job->go);
    qemu_remove_exit_notifier(&job->exit);
    persist_segs_free(job->segs);
    close(job->lock_fd);
    if (emit) {
        dev = object_get_canonical_path(OBJECT(n));
        qapi_event_send_femu_save_data_done(dev, job->path,
                                            job->err ?
                                            error_get_pretty(job->err) :
                                            NULL);
    } else if (job->err) {
        error_report_err(job->err);
        job->err = NULL;
    }
    error_free(job->err);
    g_free(job->path);
    g_free(job);
}

static void persist_job_bh(void *opaque)
{
    FemuSaveJob *job = opaque;

    persist_job_end(job->n, true);
}

static void persist_job_exit(Notifier *notifier, void *data)
{
    FemuSaveJob *job = container_of(notifier, FemuSaveJob, exit);

    persist_job_end(job->n, false);
}

/* unplug: wait for a background save, so it leaves a whole file or none */
void femu_save_job_exit(FemuCtrl *n)
{
    persist_job_end(n, false);
}

/* x-save-hold: a background save waits after its copy until this is off */
void femu_save_hold_set(FemuCtrl *n, bool hold)
{
    n->save_hold = hold;
    if (!hold && n->save_job) {
        qemu_event_set(&n->save_job->go);
    }
}

/* whether a background save writes @path (resolved) */
static bool persist_job_path(FemuCtrl *n, const char *path)
{
    return n->save_job && !strcmp(n->save_job->path, path);
}

static int persist_job_match(Object *obj, void *opaque)
{
    FemuCtrl *n = (FemuCtrl *)object_dynamic_cast(obj, TYPE_NVME);

    return n && persist_job_path(n, opaque);
}

bool femu_save_path_busy(const char *path)
{
    return object_child_foreach_recursive(object_get_root(),
                                          persist_job_match, (void *)path);
}

static bool persist_save(FemuCtrl *n, Error **errp)
{
    return persist_save_to(n, n->persist_path, errp);
}

/*
 * The end of QEMU: the vCPUs have stopped, the pollers and the FTL thread
 * have not. Stop them so no copy changes the backend under the save.
 */
static void persist_exit_notify(Notifier *notifier, void *data)
{
    FemuCtrl *n = container_of(notifier, FemuCtrl, persist_notifier);
    Error *err = NULL;
    bool resume;

    /* QEMU ends here: the workers stay paused */
    if (n->persist_ftl) {
        if (!persist_drain(n, &resume, &err)) {
            error_report_err(err);
            return;
        }
    } else {
        nvme_pause_pollers(n);
    }
    if (!persist_save(n, &err)) {
        error_report_err(err);
    }
}

/* the modes and settings whose state lives in the backend and bitmaps */
static bool persist_check(FemuCtrl *n, Error **errp)
{
    const char *why = NULL;

    if (n->femu_mode != FEMU_BBSSD_MODE && n->femu_mode != FEMU_NOSSD_MODE) {
        why = "a mode other than bbssd or NoSSD";
    } else if (n->namespace_modes) {
        why = "namespace_modes";
    } else if (nvme_ns_shared(n) || n->ns_mgmt) {
        why = "ns_mgmt or shared namespaces";
    } else if (n->cxl_dev) {
        why = "cxl_ssd";
    } else if (n->meta) {
        why = "metadata (ms)";
    } else if (n->sanitize_ms) {
        why = "sanitize_ms (a sanitize in progress is not kept)";
    }
    if (why) {
        error_setg(errp, "persist_file is not supported with %s", why);
        return false;
    }
    return !n->persist_ftl || persist_ftl_check(n, errp);
}

/*
 * The file to save to, as an absolute path that QEMU's later working
 * directory (-daemonize) cannot change: a symbolic link is followed, so
 * the save replaces its target, not the link.
 */
static char *persist_resolve(const char *file, Error **errp)
{
    g_autofree char *abs = g_canonicalize_filename(file, NULL);
    g_autofree char *dir = g_path_get_dirname(abs);
    g_autofree char *base = g_path_get_basename(abs);
    char *real = realpath(abs, NULL);
    struct stat st;
    char *rdir;
    char *path;

    if (real) {
        path = g_strdup(real);
        free(real);
        goto check;
    }
    /* a link whose target is missing would be replaced, not followed */
    if (lstat(abs, &st) == 0 && S_ISLNK(st.st_mode)) {
        error_setg(errp, "persist_file: '%s' is a link to nothing", abs);
        return NULL;
    }
    rdir = realpath(dir, NULL);
    if (!rdir) {
        error_setg_errno(errp, errno, "persist_file: no directory '%s'", dir);
        return NULL;
    }
    path = g_build_filename(rdir, base, NULL);
    free(rdir);
check:
    /* FILE.lock guards FILE: a data file of that name would replace it */
    if (g_str_has_suffix(path, ".lock")) {
        error_setg(errp, "persist_file: '%s' ends in .lock, which names a "
                   "lock file", path);
        g_free(path);
        return NULL;
    }
    return path;
}

/* the pel_file of every femu device, resolved, against @path */
static int persist_pel_match(Object *obj, void *opaque)
{
    const char *path = opaque;
    FemuCtrl *n = (FemuCtrl *)object_dynamic_cast(obj, TYPE_NVME);
    g_autofree char *pel = NULL;

    if (!n || !n->pel_file) {
        return 0;
    }
    pel = persist_resolve(n->pel_file, NULL);
    return pel && !strcmp(pel, path);
}

/* @path as persist_file resolves it; NULL when its directory is missing */
char *femu_path_resolve(const char *file)
{
    return persist_resolve(file, NULL);
}

typedef struct FemuPathUse {
    FemuCtrl *self;
    const char *path;
    bool traces_only;
} FemuPathUse;

static int persist_path_match(Object *obj, void *opaque)
{
    FemuPathUse *u = opaque;
    FemuCtrl *n = (FemuCtrl *)object_dynamic_cast(obj, TYPE_NVME);
    g_autofree char *persist = NULL;
    g_autofree char *pel = NULL;

    if (!n) {
        return 0;
    }
    /* a background save renames its file over the path when it ends */
    if (persist_job_path(n, u->path)) {
        return 1;
    }
    if (n != u->self && n->iotrace_path && !strcmp(n->iotrace_path, u->path)) {
        return 1;
    }
    if (u->traces_only) {
        return 0;
    }
    persist = n->persist_file ? persist_resolve(n->persist_file, NULL) : NULL;
    pel = n->pel_file ? persist_resolve(n->pel_file, NULL) : NULL;
    return (persist && !strcmp(persist, u->path)) ||
           (pel && !strcmp(pel, u->path));
}

/*
 * Whether @path is a file a femu device keeps: another device's io_trace,
 * or (unless @traces_only) any device's persist_file or pel_file, @self
 * included. Those files are saved by rename, which would replace a trace.
 */
bool femu_path_in_use(FemuCtrl *self, const char *path, bool traces_only)
{
    FemuPathUse u = { .self = self, .path = path, .traces_only = traces_only };

    return object_child_foreach_recursive(object_get_root(),
                                          persist_path_match, &u);
}

/*
 * Open FILE.lock, and make it when it is missing. Mode 0644, also against
 * the umask, lets a second user share the empty file. @absent is set when
 * the file is missing and the directory does not take it.
 */
static int persist_open_lock(const char *lock, int acc, bool *absent)
{
    int fd = open(lock, acc | O_CLOEXEC);

    *absent = false;
    if (fd >= 0 || errno != ENOENT) {
        return fd;
    }
    fd = open(lock, acc | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd >= 0) {
        if (fchmod(fd, 0644) < 0) {
            warn_report("persist_file: cannot set the mode of '%s': %s",
                        lock, strerror(errno));
        }
        return fd;
    }
    if (errno == EEXIST) {
        return open(lock, acc | O_CLOEXEC);
    }
    *absent = errno == EACCES || errno == EROFS || errno == EPERM;
    return -1;
}

/*
 * Whether @fd is on a local file system, by the f_type values of
 * statfs(2). A network file system can cache a missing FILE.lock, so a
 * reader there cannot hold the checkpoint file in its place.
 */
static bool persist_local_fs(int fd)
{
    static const uint32_t local[] = {
        0xef53,         /* ext2, ext3, ext4 */
        0x58465342,     /* xfs */
        0x9123683e,     /* btrfs */
        0xf2f52010,     /* f2fs */
        0x01021994,     /* tmpfs */
        0x794c7630,     /* overlayfs */
        0x73717368,     /* squashfs */
        0x9660,         /* iso9660 */
    };
    struct statfs fs;

    if (fstatfs(fd, &fs) < 0) {
        return false;
    }
    for (size_t i = 0; i < ARRAY_SIZE(local); i++) {
        if ((uint32_t)fs.f_type == local[i]) {
            return true;
        }
    }
    return false;
}

/*
 * Whether a persist_load_only device holds @path itself, which it does
 * only on a local file system where it could not make FILE.lock. The
 * caller holds FILE.lock, so no such device can start after this test.
 * Returns 0 when @path is absent or not held, 1 when held, and -errno
 * when the test fails: the caller must then refuse to write @path.
 */
static int persist_file_held(const char *path)
{
    int fd = open(path, O_RDWR | O_CLOEXEC);
    int ret = 0;

    if (fd < 0 && (errno == EACCES || errno == EROFS)) {
        fd = open(path, O_RDONLY | O_CLOEXEC);
    }
    if (fd < 0) {
        return errno == ENOENT ? 0 : -errno;
    }
    if (persist_local_fs(fd) && flock(fd, LOCK_EX | LOCK_NB) < 0) {
        ret = errno == EWOULDBLOCK ? 1 : -errno;
    }
    close(fd);
    return ret;
}

/*
 * Hold FILE.lock for the device's life; another holder fails realize.
 * Readers of a checkpoint share the lock, and a device that saves the
 * file is alone. A reader that finds no FILE.lock in a directory it
 * cannot write holds the checkpoint file itself, shared.
 */
static bool persist_lock(FemuCtrl *n, Error **errp)
{
    g_autofree char *lock = g_strconcat(n->persist_path, ".lock", NULL);
    bool reader = n->persist_load_only;
    bool on_file = false;
    bool absent;
    int held;
    int fd = persist_open_lock(lock, reader ? O_RDONLY : O_RDWR, &absent);

    if (fd < 0 && reader && absent) {
        fd = open(n->persist_path, O_RDONLY | O_CLOEXEC);
        if (fd < 0 && errno == ENOENT) {
            error_setg(errp, "persist_load_only needs an existing "
                       "persist_file; '%s' does not exist", n->persist_path);
            return false;
        }
        if (fd < 0) {
            error_setg_errno(errp, errno, "persist_file: cannot open '%s'",
                             n->persist_path);
            return false;
        }
        if (!persist_local_fs(fd)) {
            error_setg(errp, "persist_load_only: no '%s', and '%s' is not on "
                       "a local file system; make an empty '%s' with mode "
                       "0644", lock, n->persist_path, lock);
            close(fd);
            return false;
        }
        on_file = true;
    } else if (fd < 0) {
        error_setg_errno(errp, errno, "persist_file: cannot open '%s'", lock);
        return false;
    }
    if (flock(fd, (reader ? LOCK_SH : LOCK_EX) | LOCK_NB) < 0) {
        error_setg(errp, "persist_file '%s' is in use by another device",
                   n->persist_path);
        close(fd);
        return false;
    }
    /*
     * A device that saves the file makes FILE.lock first and tests the
     * file second. A reader that holds the file looks for FILE.lock again,
     * so one of the two sees the other.
     */
    held = 0;
    if (!reader) {
        held = persist_file_held(n->persist_path);
    } else if (on_file && access(lock, F_OK) == 0) {
        held = 1;
    } else if (on_file && errno != ENOENT) {
        held = -errno;
    }
    if (held) {
        if (held < 0) {
            error_setg_errno(errp, -held, "persist_file: cannot test '%s' "
                             "for another device", n->persist_path);
        } else {
            error_setg(errp, "persist_file '%s' is in use by another device",
                       n->persist_path);
        }
        close(fd);
        return false;
    }
    if (on_file) {
        warn_report("persist_load_only: no '%s' and its directory is "
                    "read-only; the device holds '%s' itself", lock,
                    n->persist_path);
    }
    n->persist_lock_on_file = on_file;
    n->persist_lock_fd = fd;
    return true;
}

static void persist_unlock(FemuCtrl *n)
{
    /* the path is set first, so without it the fd was never opened */
    if (!n->persist_path) {
        return;
    }
    if (n->persist_lock_fd >= 0) {
        close(n->persist_lock_fd);
        n->persist_lock_fd = -1;
    }
    n->persist_lock_on_file = false;
    g_clear_pointer(&n->persist_path, g_free);
}

/* the directory takes a new file: a save at the end would not fail there */
static bool persist_probe_dir(FemuCtrl *n, Error **errp)
{
    g_autofree char *tmp = g_strconcat(n->persist_path, ".XXXXXX", NULL);
    int fd = g_mkstemp(tmp);

    if (fd < 0) {
        error_setg_errno(errp, errno, "persist_file: cannot write next to "
                         "'%s'", n->persist_path);
        return false;
    }
    close(fd);
    unlink(tmp);
    return true;
}

/*
 * The FTL sections at @off, one per FTL namespace: every one is checked
 * before any FTL changes, so a bad section leaves every FTL fresh.
 */
static bool persist_load_ftl(FemuCtrl *n, int fd, off_t off, Error **errp)
{
    SsdPersistKey key = {
        .digest = persist_digest(n, true),
        .digest1 = persist_digest(n, false),
        .aging = persist_aging(n),
    };
    g_autoptr(GPtrArray) secs = g_ptr_array_new_with_free_func(
                                    (GDestroyNotify)g_byte_array_unref);
    struct stat st;
    uint32_t k;

    if (fstat(fd, &st) < 0) {
        error_setg_errno(errp, errno, "persist_file: cannot stat '%s'",
                         n->persist_path);
        return false;
    }
    for (uint32_t i = 0; i < n->num_namespaces; i++) {
        GByteArray *sec;
        uint8_t lb[8];
        uint64_t len;

        if (!persist_ftl_ns(&n->namespaces[i])) {
            continue;
        }
        if (!persist_read(fd, lb, 8, off)) {
            goto short_file;
        }
        len = ldq_le_p(lb);
        off += 8;
        if (len > ssd_persist_max_len(n->namespaces[i].ssd)) {
            error_setg(errp, "persist_file '%s', namespace %u: the FTL "
                       "section is longer than this FTL's", n->persist_path,
                       i + 1);
            return false;
        }
        if (len > (uint64_t)st.st_size || off > st.st_size - (off_t)len) {
            goto short_file;
        }
        sec = g_byte_array_sized_new(len);
        g_byte_array_set_size(sec, len);
        g_ptr_array_add(secs, sec);
        if (!persist_read(fd, sec->data, len, off)) {
            goto short_file;
        }
        off += len;
    }
    if (off != st.st_size) {
        error_setg(errp, "persist_file '%s' has bytes past its FTL state",
                   n->persist_path);
        return false;
    }
    for (int pass = 0; pass < 2; pass++) {
        k = 0;
        for (uint32_t i = 0; i < n->num_namespaces; i++) {
            NvmeNamespace *ns = &n->namespaces[i];
            GByteArray *sec;
            Error *local = NULL;

            if (!persist_ftl_ns(ns)) {
                continue;
            }
            sec = g_ptr_array_index(secs, k++);
            if (!ssd_persist_load(ns->ssd, sec->data, sec->len, &key,
                                  pass == 1, &local)) {
                error_setg(errp, "persist_file '%s', namespace %u: %s",
                           n->persist_path, i + 1, error_get_pretty(local));
                error_free(local);
                return false;
            }
        }
    }
    return true;

short_file:
    error_setg(errp, "persist_file '%s' has a short FTL section",
               n->persist_path);
    return false;
}

/* the LBA status section at *@off; a file without one keeps empty state */
static bool persist_load_lsi(FemuCtrl *n, int fd, off_t *off, Error **errp)
{
    g_autofree uint8_t *sec = NULL;
    Error *local = NULL;
    struct stat st;
    uint8_t lb[8];
    uint64_t len;

    if (fstat(fd, &st) < 0) {
        error_setg_errno(errp, errno, "persist_file: cannot stat '%s'",
                         n->persist_path);
        return false;
    }
    if (!persist_read(fd, lb, 8, *off)) {
        goto short_file;
    }
    len = ldq_le_p(lb);
    *off += 8;
    if (len > femu_lsi_save_max(n)) {
        error_setg(errp, "persist_file '%s': the LBA status section is too "
                   "long", n->persist_path);
        return false;
    }
    if (*off > st.st_size || len > (uint64_t)(st.st_size - *off)) {
        goto short_file;
    }
    sec = g_malloc(len);
    if (!persist_read(fd, sec, len, *off)) {
        goto short_file;
    }
    if (!femu_lsi_load(n, sec, len, &local)) {
        error_setg(errp, "persist_file '%s': %s", n->persist_path,
                   error_get_pretty(local));
        error_free(local);
        return false;
    }
    *off += len;
    return true;

short_file:
    error_setg(errp, "persist_file '%s' has a short LBA status section",
               n->persist_path);
    return false;
}

static bool persist_load(FemuCtrl *n, int fd, Error **errp)
{
    size_t len = persist_meta_len(n);
    g_autofree uint8_t *want = NULL;
    g_autofree uint8_t *got = g_malloc0(len);
    uint32_t version = 0, flags = 0;
    off_t off = len;

    if (persist_read(fd, got, len, 0)) {
        version = ldl_le_p(got + 8);
        flags = ldl_le_p(got + 28);
    }
    /* version 2 has no flags; version 3 has the FTL and LSI flags or none */
    if ((version != PERSIST_VERSION || flags) &&
        (version != PERSIST_V_FTL ||
         (flags & ~(PERSIST_F_FTL | PERSIST_F_LSI)))) {
        version = 0;
    }
    want = persist_meta(n, version, flags);
    if (!version || memcmp(got, want, len)) {
        error_setg(errp, "persist_file '%s' does not match this device: the "
                   "mode, the backend size (%" PRId64 " bytes), or a "
                   "namespace's slice or LBA format differs", n->persist_path,
                   n->mbe->size);
        return false;
    }
    if (!persist_read(fd, n->mbe->logical_space, n->mbe->size, off)) {
        goto short_file;
    }
    n->persist_file_loaded = true;
    off += n->mbe->size;
    for (uint32_t i = 0; i < n->num_namespaces; i++) {
        NvmeNamespace *ns = &n->namespaces[i];
        size_t blen = persist_bitmap_len(ns);

        if (!persist_read(fd, ns->util, blen, off) ||
            !persist_read(fd, ns->uncorrectable, blen, off + blen)) {
            goto short_file;
        }
        femu_lsi_loaded(ns);
        off += 2 * blen;
    }
    if ((flags & PERSIST_F_LSI) && !persist_load_lsi(n, fd, &off, errp)) {
        return false;
    }
    /*
     * A file without FTL state leaves the FTL fresh; with persist_ftl off,
     * a file's FTL state is not read, and the next save drops it. An aging
     * model would then start a new history on old data without a word.
     */
    if (n->persist_ftl && !(flags & PERSIST_F_FTL) && persist_aging(n)) {
        error_setg(errp, "persist_file '%s' has no FTL state, and an aging "
                   "model needs the media history", n->persist_path);
        return false;
    }
    if (n->persist_ftl && (flags & PERSIST_F_FTL)) {
        if (!persist_load_ftl(n, fd, off, errp)) {
            return false;
        }
        n->persist_ftl_loaded = true;
    }
    /* the device holds data again: not globally erased */
    qatomic_set(&nvme_sanitize_state(n)->sstat,
                qatomic_read(&nvme_sanitize_state(n)->sstat) &
                ~NVME_SSTAT_GDE);
    return true;

short_file:
    error_setg(errp, "persist_file '%s' cannot be read in full",
               n->persist_path);
    return false;
}

/* Realize: check the file against the device and load it; none starts empty */
bool femu_persist_init(FemuCtrl *n, Error **errp)
{
    g_autofree char *pel = NULL;
    int fd;
    bool ok;

    n->persist_lock_fd = -1;
    if (!n->persist_file) {
        if (n->persist_ftl) {
            error_setg(errp, "persist_ftl needs persist_file");
            return false;
        }
        if (n->persist_load_only) {
            error_setg(errp, "persist_load_only needs persist_file");
            return false;
        }
        return true;
    }
    if (!*n->persist_file) {
        error_setg(errp, "persist_file must not be empty");
        return false;
    }
    if (!persist_check(n, errp)) {
        return false;
    }
    for (uint32_t i = 0; n->persist_ftl && i < n->num_namespaces; i++) {
        NvmeNamespace *ns = &n->namespaces[i];

        if (persist_ftl_ns(ns) && ssd_persist_max_len(ns->ssd) > G_MAXUINT) {
            error_setg(errp, "persist_ftl: namespace %u has an FTL larger "
                       "than 4 GiB to save", i + 1);
            return false;
        }
    }
    n->persist_path = persist_resolve(n->persist_file, errp);
    if (!n->persist_path) {
        return false;
    }
    if (n->pel_file) {
        pel = persist_resolve(n->pel_file, NULL);
        if (pel && !strcmp(pel, n->persist_path)) {
            error_setg(errp, "persist_file and pel_file name one file");
            persist_unlock(n);
            return false;
        }
    }
    /* a checkpoint is never saved, so its directory need not take a file */
    if (!persist_lock(n, errp) ||
        (!n->persist_load_only && !persist_probe_dir(n, errp))) {
        persist_unlock(n);
        return false;
    }
    /*
     * A reader that holds the file loads from that descriptor: over NFS a
     * close of a second one could drop the lock.
     */
    fd = n->persist_lock_on_file ? n->persist_lock_fd :
         open(n->persist_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT && n->persist_load_only) {
        error_setg(errp, "persist_load_only needs an existing persist_file; "
                   "'%s' does not exist", n->persist_path);
        persist_unlock(n);
        return false;
    }
    if (fd < 0 && errno != ENOENT) {
        error_setg_errno(errp, errno, "persist_file: cannot open '%s'",
                         n->persist_path);
        persist_unlock(n);
        return false;
    }
    if (fd >= 0) {
        ok = persist_load(n, fd, errp);
        if (!n->persist_lock_on_file) {
            close(fd);
        }
        if (!ok) {
            persist_unlock(n);
            return false;
        }
    }
    /* a checkpoint keeps its lock and path, and nothing saves it */
    if (n->persist_load_only) {
        return true;
    }
    n->persist_notifier.notify = persist_exit_notify;
    qemu_add_exit_notifier(&n->persist_notifier);
    n->persist_active = true;
    return true;
}

/* realize failed after init: keep the file as it was */
void femu_persist_abort(FemuCtrl *n)
{
    if (n->persist_active) {
        qemu_remove_exit_notifier(&n->persist_notifier);
        n->persist_active = false;
    }
    persist_unlock(n);
}

/*
 * Unplug, before the workers stop: with persist_ftl the fetched requests
 * must pass the FTL first, or the save would hold data the FTL never saw.
 * The workers stay paused for femu_exit() to stop.
 */
void femu_persist_quiesce(FemuCtrl *n)
{
    Error *err = NULL;
    bool resume;

    if (!n->persist_active || !n->persist_ftl) {
        return;
    }
    if (!persist_drain(n, &resume, &err)) {
        error_report_err(err);
        n->persist_torn = true;
    }
}

/* Unplug: the workers are stopped; save now, and not again at QEMU's end */
void femu_persist_exit(FemuCtrl *n)
{
    Error *err = NULL;

    /* no save is due (persist_load_only, or no file): only the lock goes */
    if (!n->persist_active) {
        persist_unlock(n);
        return;
    }
    qemu_remove_exit_notifier(&n->persist_notifier);
    n->persist_active = false;
    if (!persist_save(n, &err)) {
        error_report_err(err);
    }
    persist_unlock(n);
}

/*
 * Copy the file with the workers paused, then write it in a thread. The
 * copy buffers are taken before the pause, so a host without the memory
 * fails the command and the guest sees no pause. Takes @lock_fd.
 */
static bool persist_job_start(FemuCtrl *n, char *path, int lock_fd,
                              Error **errp)
{
    g_autofree void **pre = g_new0(void *, 1 + 2 * n->num_namespaces);
    FemuSaveJob *job;
    bool resume;
    int k = 0;

    pre[k++] = g_try_malloc(n->mbe->size);
    for (uint32_t i = 0; i < n->num_namespaces; i++) {
        pre[k++] = g_try_malloc(persist_bitmap_len(&n->namespaces[i]));
        pre[k++] = g_try_malloc(persist_bitmap_len(&n->namespaces[i]));
    }
    for (int i = 0; i < k; i++) {
        if (!pre[i]) {
            error_setg(errp, "femu-save-data: cannot allocate the %" PRIu64
                       " byte copy of the device", (uint64_t)n->mbe->size);
            goto fail;
        }
    }
    if (n->persist_ftl) {
        if (!persist_drain(n, &resume, errp)) {
            goto fail;
        }
    } else {
        resume = nvme_pause_pollers(n);
    }
    if (!persist_torn_check(n, errp)) {
        nvme_resume_pollers(n, resume);
        goto fail;
    }
    job = g_new0(FemuSaveJob, 1);
    /* the list owns the buffers now */
    job->segs = persist_segs(n, pre);
    nvme_resume_pollers(n, resume);
    job->n = n;
    job->path = path;
    job->lock_fd = lock_fd;
    job->bh = qemu_bh_new(persist_job_bh, job);
    qemu_event_init(&job->go, !n->save_hold);
    job->exit.notify = persist_job_exit;
    qemu_add_exit_notifier(&job->exit);
    n->save_job = job;
    qemu_thread_create(&job->thread, "femu-save", persist_job_run, job,
                       QEMU_THREAD_JOINABLE);
    return true;

fail:
    for (int i = 0; i < k; i++) {
        g_free(pre[i]);
    }
    g_free(path);
    close(lock_fd);
    return false;
}

/*
 * QMP femu-save-data: a checkpoint of the data in the persist_file format,
 * with the workers paused so no copy tears it. A later run loads it with
 * persist_file. The file's lock keeps out a file another device keeps;
 * this device's own persist_file is covered by the lock it holds.
 *
 * The write runs under the BQL, so the whole QEMU main loop waits for it,
 * not only this device. Commands queued but not yet run may or may not be
 * in the file; a completed write is in it.
 */
bool femu_persist_checkpoint(FemuCtrl *n, const char *file, bool background,
                             Error **errp)
{
    g_autofree char *path = NULL;
    g_autofree char *lock = NULL;
    int fd = -1;
    int held;
    bool absent;
    bool resume;
    bool ok;

    if (!persist_check(n, errp)) {
        return false;
    }
    if (n->save_job) {
        error_setg(errp, "femu-save-data: a background save to '%s' is in "
                   "progress", n->save_job->path);
        return false;
    }
    path = persist_resolve(file, errp);
    if (!path) {
        return false;
    }
    if (background && n->persist_path && !strcmp(path, n->persist_path)) {
        error_setg(errp, "femu-save-data: background=true cannot write this "
                   "device's own persist_file '%s'", path);
        return false;
    }
    if (object_child_foreach_recursive(object_get_root(), persist_pel_match,
                                       path)) {
        error_setg(errp, "femu-save-data: '%s' is a device's pel_file", path);
        return false;
    }
    if (femu_path_in_use(NULL, path, true)) {
        error_setg(errp, "femu-save-data: '%s' is a device's io_trace", path);
        return false;
    }
    /*
     * The file must load into a device of the same properties, which set
     * one LBA format for every namespace: a namespace formatted to another
     * one cannot be restored.
     */
    for (uint32_t i = 0; i < n->num_namespaces; i++) {
        if (NVME_ID_NS_FLBAS_INDEX(n->namespaces[i].id_ns.flbas) !=
            n->lba_index) {
            error_setg(errp, "femu-save-data: namespace %u is formatted to "
                       "LBA format %u, not lba_index %u; a later run could "
                       "not load the file", i + 1,
                       NVME_ID_NS_FLBAS_INDEX(n->namespaces[i].id_ns.flbas),
                       n->lba_index);
            return false;
        }
    }
    if (n->persist_load_only && !strcmp(path, n->persist_path)) {
        error_setg(errp, "femu-save-data: '%s' is this device's "
                   "persist_load_only checkpoint", path);
        return false;
    }
    if (!n->persist_path || strcmp(path, n->persist_path)) {
        lock = g_strconcat(path, ".lock", NULL);
        fd = persist_open_lock(lock, O_RDWR, &absent);
        held = fd < 0 || flock(fd, LOCK_EX | LOCK_NB) < 0 ? 1 :
               persist_file_held(path);
        if (held) {
            if (held < 0) {
                error_setg_errno(errp, -held, "femu-save-data: cannot test "
                                 "'%s' for a device", path);
            } else {
                error_setg(errp, "femu-save-data: '%s' is in use by a device",
                           path);
            }
            if (fd >= 0) {
                close(fd);
            }
            return false;
        }
    }
    if (background) {
        return persist_job_start(n, g_steal_pointer(&path), fd, errp);
    }
    if (n->persist_ftl) {
        ok = persist_drain(n, &resume, errp);
    } else {
        resume = nvme_pause_pollers(n);
        ok = true;
    }
    if (ok) {
        ok = persist_save_to(n, path, errp);
        nvme_resume_pollers(n, resume);
    }
    /* the lock file stays: removing it lets two later users lock apart */
    if (fd >= 0) {
        close(fd);
    }
    return ok;
}
