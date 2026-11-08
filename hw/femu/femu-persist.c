// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Data persistence across QEMU runs (persist_file).
 *
 * The data backend holds every byte the host wrote, addressed by LBA, so
 * the data survives a restart once the backend survives it. Realize loads
 * the file; a device unplug or the end of QEMU saves it, with the workers
 * stopped. The FTL state is not kept: a restarted bbssd device times its
 * first accesses as a fresh drive does, but every read returns the data
 * that was written, and deallocated or uncorrectable blocks stay so.
 *
 *   file: header (64 B) | one 32 B record per namespace | backend bytes |
 *         per namespace: allocation bitmap, uncorrectable bitmap
 *   save: file.XXXXXX, write, fsync, rename, fsync the directory
 *
 * The header and records name the mode, the backend size and each
 * namespace's slice and LBA format; a file that differs is refused, so
 * another layout cannot read these bytes. Format NVM keeps the LBA format
 * the device started with. A lock file keeps a second device or process
 * from saving over the same file.
 */

#include "qemu/osdep.h"
#include <sys/file.h>
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "system/system.h"
#include "nvme.h"

#define PERSIST_MAGIC     "FEMUDATA"
#define PERSIST_VERSION   2
#define PERSIST_HDR_SIZE  64
#define PERSIST_NS_SIZE   32

static size_t persist_meta_len(FemuCtrl *n)
{
    return PERSIST_HDR_SIZE + (size_t)n->num_namespaces * PERSIST_NS_SIZE;
}

/* the header and namespace records that describe this device's layout */
static uint8_t *persist_meta(FemuCtrl *n)
{
    uint8_t *m = g_malloc0(persist_meta_len(n));

    memcpy(m, PERSIST_MAGIC, 8);
    stl_le_p(m + 8, PERSIST_VERSION);
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

static bool persist_save(FemuCtrl *n, Error **errp)
{
    g_autofree uint8_t *meta = persist_meta(n);
    g_autofree char *tmp = g_strconcat(n->persist_path, ".XXXXXX", NULL);
    g_autofree char *dir = g_path_get_dirname(n->persist_path);
    int fd = g_mkstemp(tmp);
    int saved_errno;
    bool ok;

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
    if (!ok || fsync(fd) < 0) {
        saved_errno = errno;
        close(fd);
        unlink(tmp);
        error_setg_errno(errp, saved_errno, "persist_file: cannot write '%s'",
                         n->persist_path);
        return false;
    }
    if (close(fd) < 0 || rename(tmp, n->persist_path) < 0) {
        saved_errno = errno;
        unlink(tmp);
        error_setg_errno(errp, saved_errno, "persist_file: cannot save '%s'",
                         n->persist_path);
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

/*
 * The end of QEMU: the vCPUs have stopped, the pollers and the FTL thread
 * have not. Stop them so no copy changes the backend under the save.
 */
static void persist_exit_notify(Notifier *notifier, void *data)
{
    FemuCtrl *n = container_of(notifier, FemuCtrl, persist_notifier);
    Error *err = NULL;

    nvme_pause_pollers(n);
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
    return true;
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
    char *rdir;
    char *path;

    if (real) {
        path = g_strdup(real);
        free(real);
        return path;
    }
    rdir = realpath(dir, NULL);
    if (!rdir) {
        error_setg_errno(errp, errno, "persist_file: no directory '%s'", dir);
        return NULL;
    }
    path = g_build_filename(rdir, base, NULL);
    free(rdir);
    return path;
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

static bool persist_load(FemuCtrl *n, int fd, Error **errp)
{
    size_t len = persist_meta_len(n);
    g_autofree uint8_t *want = persist_meta(n);
    g_autofree uint8_t *got = g_malloc0(len);
    off_t off = len;

    if (!persist_read(fd, got, len, 0) || memcmp(got, want, len)) {
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
        return true;
    }
    if (!*n->persist_file) {
        error_setg(errp, "persist_file must not be empty");
        return false;
    }
    if (!persist_check(n, errp)) {
        return false;
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
