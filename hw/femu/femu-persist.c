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
#include "qom/qom-qobject.h"
#include "qobject/qbool.h"
#include "qobject/qjson.h"
#include "qobject/qnum.h"
#include "qobject/qstring.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "system/system.h"
#include "nvme.h"

#define PERSIST_MAGIC     "FEMUDATA"
#define PERSIST_VERSION   2
#define PERSIST_V_FTL     3       /* adds the FTL sections */
#define PERSIST_F_FTL     0x1     /* header byte 28: FTL sections follow */
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

static uint64_t persist_digest(FemuCtrl *n)
{
    uint64_t h = 0xcbf29ce484222325ULL;

    for (size_t i = 0; i < ARRAY_SIZE(persist_ftl_props); i++) {
        const char *name = persist_ftl_props[i];
        QObject *v = object_property_get_qobject(OBJECT(n), name, NULL);
        g_autoptr(GString) s = g_string_new(name);

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

/* the properties a version 1 FTL section cannot carry the state of */
static const char *const persist_ftl_refused[] = {
    "streams", "tier_mode", "buffer_size", "hot_cold_sep", "gc_frontier",
    "gc_pace", "gc_idle_ms", "gc_copyback", "blk_pe_limit", "spare_lines",
    "wl_spread", "read_reclaim_limit", "retention_limit_sec",
    "ecc_retention_sec", "pd_open_read_limit", "pd_open_close_sec",
    "pd_open_age", "rber_ppb", "err_read_unc_ppm", "err_write_fail_ppm",
    "die_parity", "read_cache_mb", "prog_pass2_ns", "onfi_param_page",
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

static bool persist_save_to(FemuCtrl *n, const char *path, Error **errp)
{
    g_autofree uint8_t *meta = persist_meta(n, n->persist_ftl ?
                                               PERSIST_V_FTL :
                                               PERSIST_VERSION,
                                           n->persist_ftl ? PERSIST_F_FTL :
                                                            0);
    g_autofree char *tmp = g_strconcat(path, ".XXXXXX", NULL);
    g_autofree char *dir = g_path_get_dirname(path);
    int fd;
    int saved_errno;
    bool ok;

    if (n->persist_ftl && n->persist_torn) {
        error_setg(errp, "persist_ftl: a fetched request left without "
                   "reaching the FTL (a queue deleted or a reset under I/O, "
                   "or a drain that timed out); nothing saved");
        return false;
    }
    fd = g_mkstemp(tmp);
    if (fd < 0) {
        error_setg_errno(errp, errno, "persist_file: cannot create '%s'",
                         tmp);
        return false;
    }
    ok = persist_write(fd, meta, persist_meta_len(n)) &&
         persist_write(fd, n->mbe->logical_space, n->mbe->size);
    for (uint32_t i = 0; ok && i < n->num_namespaces; i++) {
        NvmeNamespace *ns = &n->namespaces[i];

        ok = persist_write(fd, ns->util, persist_bitmap_len(ns)) &&
             persist_write(fd, ns->uncorrectable, persist_bitmap_len(ns));
    }
    for (uint32_t i = 0; ok && n->persist_ftl && i < n->num_namespaces; i++) {
        NvmeNamespace *ns = &n->namespaces[i];
        g_autoptr(GByteArray) sec = NULL;
        uint8_t len[8];

        if (!persist_ftl_ns(ns)) {
            continue;
        }
        sec = ssd_persist_save(ns->ssd, persist_digest(n));
        stq_le_p(len, sec->len);
        ok = persist_write(fd, len, 8) && persist_write(fd, sec->data, sec->len);
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

/* hold FILE.lock for the device's life; another holder fails realize */
static bool persist_lock(FemuCtrl *n, Error **errp)
{
    g_autofree char *lock = g_strconcat(n->persist_path, ".lock", NULL);
    int fd = open(lock, O_RDWR | O_CREAT | O_CLOEXEC, 0600);

    if (fd < 0) {
        error_setg_errno(errp, errno, "persist_file: cannot open '%s'", lock);
        return false;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        error_setg(errp, "persist_file '%s' is in use by another device",
                   n->persist_path);
        close(fd);
        return false;
    }
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
    uint64_t digest = persist_digest(n);
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
            if (!ssd_persist_load(ns->ssd, sec->data, sec->len, digest,
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
    /* version 2 has no flags; version 3 has the FTL flag or none */
    if ((version != PERSIST_VERSION || flags) &&
        (version != PERSIST_V_FTL || (flags & ~PERSIST_F_FTL))) {
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
    off += n->mbe->size;
    for (uint32_t i = 0; i < n->num_namespaces; i++) {
        NvmeNamespace *ns = &n->namespaces[i];
        size_t blen = persist_bitmap_len(ns);

        if (!persist_read(fd, ns->util, blen, off) ||
            !persist_read(fd, ns->uncorrectable, blen, off + blen)) {
            goto short_file;
        }
        off += 2 * blen;
    }
    /*
     * A file without FTL state leaves the FTL fresh; with persist_ftl off,
     * a file's FTL state is not read, and the next save drops it.
     */
    if (n->persist_ftl && (flags & PERSIST_F_FTL) &&
        !persist_load_ftl(n, fd, off, errp)) {
        return false;
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
    if (!persist_lock(n, errp) || !persist_probe_dir(n, errp)) {
        persist_unlock(n);
        return false;
    }
    fd = open(n->persist_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0 && errno != ENOENT) {
        error_setg_errno(errp, errno, "persist_file: cannot open '%s'",
                         n->persist_path);
        persist_unlock(n);
        return false;
    }
    if (fd >= 0) {
        ok = persist_load(n, fd, errp);
        close(fd);
        if (!ok) {
            persist_unlock(n);
            return false;
        }
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

    if (!n->persist_active) {
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
 * QMP femu-save-data: a checkpoint of the data in the persist_file format,
 * with the workers paused so no copy tears it. A later run loads it with
 * persist_file. The file's lock keeps out a file another device keeps;
 * this device's own persist_file is covered by the lock it holds.
 *
 * The write runs under the BQL, so the whole QEMU main loop waits for it,
 * not only this device. Commands queued but not yet run may or may not be
 * in the file; a completed write is in it.
 */
bool femu_persist_checkpoint(FemuCtrl *n, const char *file, Error **errp)
{
    g_autofree char *path = NULL;
    g_autofree char *lock = NULL;
    int fd = -1;
    bool resume;
    bool ok;

    if (!persist_check(n, errp)) {
        return false;
    }
    path = persist_resolve(file, errp);
    if (!path) {
        return false;
    }
    if (object_child_foreach_recursive(object_get_root(), persist_pel_match,
                                       path)) {
        error_setg(errp, "femu-save-data: '%s' is a device's pel_file", path);
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
    if (!n->persist_path || strcmp(path, n->persist_path)) {
        lock = g_strconcat(path, ".lock", NULL);
        fd = open(lock, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (fd < 0 || flock(fd, LOCK_EX | LOCK_NB) < 0) {
            error_setg(errp, "femu-save-data: '%s' is in use by a device",
                       path);
            if (fd >= 0) {
                close(fd);
            }
            return false;
        }
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
