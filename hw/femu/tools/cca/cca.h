/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Guest library for the femu-cxl-ssd caching API (CCA): pin, unpin,
 * invalidate, uncache and query ranges of the device's DRAM cache through
 * BAR5. The layout comes from cca-abi.h, shared with the device.
 *
 * All calls are thread safe. Tags are opaque to the library.
 */
#ifndef FEMU_CCA_H
#define FEMU_CCA_H

#include <stddef.h>
#include <stdint.h>
#include "cca-abi.h"

#define CCA_FLAG_FORCE      1u          /* CCA_F_FORCE */
#define CCA_WHOLE           UINT64_MAX  /* count: whole media, start 0 */
#define CCA_SUBMIT_DEFER    0x100u      /* cca_submit: do not ring */

struct cca_dev;

struct cca_info {
    uint32_t version;
    uint64_t media_pages;
    uint32_t cache_pages;
    uint32_t cache_ways;
    uint32_t pin_limit;                 /* per set */
    uint64_t completed;
};

struct cca_result {
    int status;                         /* 0 or -errno from the device */
    uint64_t pages;                     /* pages acted on */
    uint64_t resident;                  /* QUERY only */
    uint64_t dirty;
    uint64_t pinned;
    uint64_t uncached;
};

struct cca_completion {
    uint64_t tag;
    struct cca_result r;
};

/*
 * @which: "mem0" (a CXL memdev), a PCI address such as "0000:0d:00.0", a
 * path to a resource5 file, or NULL for the only CCA device. Needs root.
 * Returns 0 or -errno: -ENODEV (no BAR5 or wrong magic), -EPROTO (layout
 * version), -EBUSY (another process holds it), -ETIMEDOUT (never ready).
 */
int cca_open(const char *which, struct cca_dev **out);
/* Attach to a BAR5 the caller has already mapped (tests, UIO). */
int cca_open_map(void *bar, struct cca_dev **out);
void cca_close(struct cca_dev *d);
int cca_info(struct cca_dev *d, struct cca_info *out);
void cca_set_timeout(struct cca_dev *d, int timeout_ms); /* <0: forever */

/* Synchronous; each returns r->status, or -errno if the call failed. */
int cca_nop(struct cca_dev *d);
int cca_pin(struct cca_dev *d, uint64_t lpn, uint64_t count,
            struct cca_result *r);
int cca_unpin(struct cca_dev *d, uint64_t lpn, uint64_t count,
              struct cca_result *r);
int cca_invalidate(struct cca_dev *d, uint64_t lpn, uint64_t count,
                   unsigned flags, struct cca_result *r);
int cca_cache_disable(struct cca_dev *d, uint64_t lpn, uint64_t count,
                      unsigned flags, struct cca_result *r);
int cca_cache_enable(struct cca_dev *d, uint64_t lpn, uint64_t count,
                     struct cca_result *r);
int cca_query(struct cca_dev *d, uint64_t lpn, uint64_t count,
              struct cca_result *r);
/* Send a command exactly as given, for tests of device validation. */
int cca_call_raw(struct cca_dev *d, const struct cca_ctrl_cmd_s *cmd,
                 struct cca_result *r);

/*
 * Asynchronous; up to CCA_RING_COUNT in flight. cca_submit returns 0,
 * -EAGAIN when every slot is busy, or -EINVAL. Reap returns the number
 * of completions stored, 0 on timeout, or -errno.
 */
int cca_submit(struct cca_dev *d, uint32_t cmd, unsigned flags, uint64_t lpn,
               uint64_t count, uint64_t tag);
void cca_kick(struct cca_dev *d);
int cca_reap(struct cca_dev *d, struct cca_completion *out, unsigned max,
             int timeout_ms);

/*
 * Address helpers for a devdax mapping of a non-interleaved region on this
 * memdev; -EOPNOTSUPP otherwise. Ranges are widened to whole pages.
 */
int cca_attach_dax(struct cca_dev *d, const char *dax, void *base,
                   size_t len);
int cca_lpn_of(struct cca_dev *d, const void *addr, uint64_t *lpn);
int cca_pin_addr(struct cca_dev *d, const void *addr, size_t len,
                 struct cca_result *r);
int cca_unpin_addr(struct cca_dev *d, const void *addr, size_t len,
                   struct cca_result *r);
int cca_invalidate_addr(struct cca_dev *d, const void *addr, size_t len,
                        unsigned flags, struct cca_result *r);
int cca_query_addr(struct cca_dev *d, const void *addr, size_t len,
                   struct cca_result *r);

/* Write the RESET register: 0 for rings only, nonzero for everything. */
int cca_reset(struct cca_dev *d, int all);
const char *cca_strerror(int status);

#endif
