// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Data persistence across QEMU runs (persist_file).
 *
 * The data backend holds every byte the host wrote, addressed by LBA, so
 * the data survives a restart once the backend survives it. Realize loads
 * the file; a device unplug or the end of QEMU saves it. The FTL state is
 * not kept: a restarted bbssd device times its first accesses as a fresh
 * drive does, but every read returns the data that was written.
 *
 *   realize --> load  file: header (64 B) + backend bytes
 *   femu_exit or QEMU exit --> save to file.XXXXXX, fsync, rename
 *
 * A header records the mode, the backend size and the namespace count; a
 * file that does not match the device is refused, so a changed geometry
 * cannot read another layout's bytes.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "system/system.h"
#include "nvme.h"

#define PERSIST_MAGIC     "FEMUDATA"
#define PERSIST_VERSION   1
#define PERSIST_HDR_SIZE  64

static void persist_header(FemuCtrl *n, uint8_t *hdr)
{
    memset(hdr, 0, PERSIST_HDR_SIZE);
    memcpy(hdr, PERSIST_MAGIC, 8);
    stl_le_p(hdr + 8, PERSIST_VERSION);
    stl_le_p(hdr + 12, n->femu_mode);
    stq_le_p(hdr + 16, n->mbe->size);
    stl_le_p(hdr + 24, n->num_namespaces);
}

static bool persist_save(FemuCtrl *n, Error **errp)
{
    uint8_t hdr[PERSIST_HDR_SIZE];
    g_autofree char *tmp = g_strconcat(n->persist_file, ".XXXXXX", NULL);
    int fd = g_mkstemp(tmp);
    int saved_errno;

    if (fd < 0) {
        error_setg_errno(errp, errno, "persist_file: cannot create '%s'",
                         tmp);
        return false;
    }
    persist_header(n, hdr);
    if (qemu_write_full(fd, hdr, sizeof(hdr)) != sizeof(hdr) ||
        qemu_write_full(fd, n->mbe->logical_space, n->mbe->size) !=
        n->mbe->size || fsync(fd) < 0) {
        saved_errno = errno;
        close(fd);
        unlink(tmp);
        error_setg_errno(errp, saved_errno, "persist_file: cannot write '%s'",
                         n->persist_file);
        return false;
    }
    if (close(fd) < 0 || rename(tmp, n->persist_file) < 0) {
        saved_errno = errno;
        unlink(tmp);
        error_setg_errno(errp, saved_errno, "persist_file: cannot save '%s'",
                         n->persist_file);
        return false;
    }
    return true;
}

static void persist_exit_notify(Notifier *notifier, void *data)
{
    FemuCtrl *n = container_of(notifier, FemuCtrl, persist_notifier);
    Error *err = NULL;

    if (!persist_save(n, &err)) {
        error_report_err(err);
    }
}

/* the modes and settings whose data lives in the backend alone */
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
    }
    if (why) {
        error_setg(errp, "persist_file is not supported with %s", why);
        return false;
    }
    return true;
}

/* Realize: check the file against the device and load it; none starts empty */
bool femu_persist_init(FemuCtrl *n, Error **errp)
{
    uint8_t hdr[PERSIST_HDR_SIZE];
    uint8_t want[PERSIST_HDR_SIZE];
    int fd;
    ssize_t got;

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
    fd = open(n->persist_file, O_RDONLY);
    if (fd < 0 && errno != ENOENT) {
        error_setg_errno(errp, errno, "persist_file: cannot open '%s'",
                         n->persist_file);
        return false;
    }
    if (fd >= 0) {
        persist_header(n, want);
        got = read(fd, hdr, sizeof(hdr));
        if (got != sizeof(hdr) || memcmp(hdr, want, sizeof(hdr))) {
            close(fd);
            error_setg(errp, "persist_file '%s' does not match this device: "
                       "the mode, backend size (%" PRId64 " bytes) or "
                       "namespace count differ", n->persist_file,
                       n->mbe->size);
            return false;
        }
        for (int64_t off = 0; off < n->mbe->size; off += got) {
            got = pread(fd, (uint8_t *)n->mbe->logical_space + off,
                        n->mbe->size - off, sizeof(hdr) + off);
            if (got <= 0) {
                close(fd);
                error_setg(errp, "persist_file '%s' is shorter than the "
                           "device", n->persist_file);
                return false;
            }
        }
        close(fd);
    }
    n->persist_notifier.notify = persist_exit_notify;
    qemu_add_exit_notifier(&n->persist_notifier);
    n->persist_active = true;
    return true;
}

/* Unplug: save now, and not again when QEMU ends */
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
}
