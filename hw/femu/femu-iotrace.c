/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * I/O trace export (io_trace=FILE): one CSV line per I/O command whose
 * completion a poller posts, in every mode.
 *
 *   t_submit_ns,t_cqe_ns,sqid,cid,nsid,opcode,slba,nlb,status
 *
 * t_submit_ns is the poller's fetch of the command and t_cqe_ns the CQE
 * write, both on the device clock, so their difference is the latency the
 * host sees, from the fetch to the CQE write: SQ wait before the fetch and
 * interrupt delivery after the CQE are not in it. slba and nlb (a block
 * count) are the submitted range of a Read, Write, Compare, Write Zeroes
 * or Verify on an NVM or zoned namespace; other commands leave them
 * empty. status is SCT and SC with DNR, without the phase bit.
 *
 * The file is created with O_EXCL: FEMU never writes over a file. One
 * mutex orders the pollers' lines, the final flush at QEMU exit and the
 * close at unplug; lines after the flush are counted, not written.
 */
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "system/system.h"
#include "nvme.h"

#define IOTRACE_BUF     (1 << 20)

/* a write, flush or close failed: say so once; the caller holds the lock */
static void iotrace_fail(FemuCtrl *n, const char *what)
{
    if (!n->iotrace_failed) {
        error_report("femu: io_trace '%s': %s failed; the trace stops",
                     n->iotrace_path, what);
    }
    n->iotrace_failed = true;
    n->iotrace_closed = true;
}

/* stop the trace: no line is written after this; the caller holds the lock */
static void iotrace_stop(FemuCtrl *n, bool close_file)
{
    if (n->iotrace_f) {
        if (fflush(n->iotrace_f) != 0) {
            iotrace_fail(n, "a flush");
        }
        if (close_file) {
            if (fclose(n->iotrace_f) != 0) {
                iotrace_fail(n, "the close");
            }
            n->iotrace_f = NULL;
            g_clear_pointer(&n->iotrace_buf, g_free);
        }
    }
    n->iotrace_closed = true;
}

/*
 * QEMU ends: flush, and drop the lines that come after. The lines lost so
 * far are reported here, as unplug may never run.
 */
static void iotrace_exit_notify(Notifier *notifier, void *data)
{
    FemuCtrl *n = container_of(notifier, FemuCtrl, iotrace_notifier);

    qemu_mutex_lock(&n->iotrace_lock);
    iotrace_stop(n, false);
    if (n->iotrace_dropped) {
        warn_report("femu: io_trace '%s': %" PRIu64 " lines not written",
                    n->iotrace_path, n->iotrace_dropped);
    }
    qemu_mutex_unlock(&n->iotrace_lock);
}

/* Realize: create the file; an existing file or a bad path fails realize */
bool femu_iotrace_init(FemuCtrl *n, Error **errp)
{
    g_autofree char *path = NULL;
    int fd;

    if (!n->io_trace) {
        return true;
    }
    if (!*n->io_trace) {
        error_setg(errp, "io_trace must not be empty");
        return false;
    }
    /* an absolute path, as persist_file resolves one (-daemonize, links) */
    path = femu_path_resolve(n->io_trace);
    if (!path) {
        error_setg(errp, "io_trace: no directory for '%s'", n->io_trace);
        return false;
    }
    /* a file saved by rename later would replace the trace */
    if (femu_path_in_use(n, path, false)) {
        error_setg(errp, "io_trace: '%s' is a persist_file, pel_file or "
                   "io_trace of a device", path);
        return false;
    }
    n->iotrace_path = g_steal_pointer(&path);
    fd = open(n->iotrace_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd < 0) {
        error_setg_errno(errp, errno, "io_trace: cannot create '%s' (FEMU "
                         "does not write over a file)", n->iotrace_path);
        /* not ours: femu_iotrace_abort() must not remove it */
        g_clear_pointer(&n->iotrace_path, g_free);
        return false;
    }
    n->iotrace_f = fdopen(fd, "w");
    if (!n->iotrace_f) {
        error_setg_errno(errp, errno, "io_trace: cannot open '%s'",
                         n->iotrace_path);
        close(fd);
        unlink(n->iotrace_path);
        g_clear_pointer(&n->iotrace_path, g_free);
        return false;
    }
    n->iotrace_buf = g_malloc(IOTRACE_BUF);
    if (setvbuf(n->iotrace_f, n->iotrace_buf, _IOFBF, IOTRACE_BUF) != 0 ||
        fputs("t_submit_ns,t_cqe_ns,sqid,cid,nsid,opcode,slba,nlb,status\n",
              n->iotrace_f) < 0) {
        error_setg(errp, "io_trace: cannot write '%s'", n->iotrace_path);
        fclose(n->iotrace_f);
        n->iotrace_f = NULL;
        g_clear_pointer(&n->iotrace_buf, g_free);
        unlink(n->iotrace_path);
        g_clear_pointer(&n->iotrace_path, g_free);
        return false;
    }
    n->iotrace_notifier.notify = iotrace_exit_notify;
    qemu_add_exit_notifier(&n->iotrace_notifier);
    qatomic_set(&n->iotrace_on, true);
    return true;
}

/* a poller posted the completion of @req at @now */
void femu_iotrace_note(FemuCtrl *n, NvmeRequest *req, int64_t now)
{
    const NvmeRwCmd *rw = (const NvmeRwCmd *)&req->cmd;
    char range[48] = ",";
    int ret;

    switch (req->cmd.opcode) {
    case NVME_CMD_READ:
    case NVME_CMD_WRITE:
    case NVME_CMD_COMPARE:
    case NVME_CMD_WRITE_ZEROES:
    case NVME_CMD_VERIFY:
        /*
         * Only the NVM and zoned command sets put a block range here: KV,
         * memory and program commands reuse the opcodes for other fields,
         * and a command with no namespace has no set to say.
         */
        if (req->ns && (req->ns->csi == NVME_CSI_NVM ||
                        req->ns->csi == NVME_CSI_ZONED)) {
            snprintf(range, sizeof(range), "%" PRIu64 ",%u",
                     le64_to_cpu(rw->slba), le16_to_cpu(rw->nlb) + 1u);
        }
        break;
    default:
        break;
    }

    qemu_mutex_lock(&n->iotrace_lock);
    if (n->iotrace_closed || !n->iotrace_f) {
        n->iotrace_dropped++;
        qemu_mutex_unlock(&n->iotrace_lock);
        return;
    }
    ret = fprintf(n->iotrace_f, "%" PRId64 ",%" PRId64 ",%u,%u,%u,0x%02x,%s,"
                  "0x%x\n", req->t_submit, now, req->sq ? req->sq->sqid : 0,
                  le16_to_cpu(req->cqe.cid), le32_to_cpu(req->cmd.nsid),
                  req->cmd.opcode, range, req->status);
    if (ret < 0) {
        /* the disk is full or gone */
        n->iotrace_dropped++;
        iotrace_fail(n, "a write");
    }
    qemu_mutex_unlock(&n->iotrace_lock);
}

/* unplug, after the pollers stop; and a realize that failed after init */
void femu_iotrace_exit(FemuCtrl *n)
{
    if (!n->iotrace_path) {
        return;
    }
    qemu_mutex_lock(&n->iotrace_lock);
    qatomic_set(&n->iotrace_on, false);
    if (n->iotrace_notifier.notify) {
        qemu_remove_exit_notifier(&n->iotrace_notifier);
        n->iotrace_notifier.notify = NULL;
    }
    iotrace_stop(n, true);
    qemu_mutex_unlock(&n->iotrace_lock);
    if (n->iotrace_dropped) {
        warn_report("femu: io_trace '%s': %" PRIu64 " lines not written",
                    n->iotrace_path, n->iotrace_dropped);
    }
    g_clear_pointer(&n->iotrace_path, g_free);
}

/* realize failed after init: the file FEMU made holds only the header */
void femu_iotrace_abort(FemuCtrl *n)
{
    g_autofree char *path = g_strdup(n->iotrace_path);

    femu_iotrace_exit(n);
    if (path) {
        unlink(path);
    }
}
