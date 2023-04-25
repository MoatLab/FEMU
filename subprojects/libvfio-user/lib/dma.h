/*
 * Copyright (c) 2019 Nutanix Inc. All rights reserved.
 *
 * Authors: Mike Cui <cui@nutanix.com>
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *      * Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *      * Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in the
 *        documentation and/or other materials provided with the distribution.
 *      * Neither the name of Nutanix nor the names of its contributors may be
 *        used to endorse or promote products derived from this software without
 *        specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 *  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 *  DAMAGE.
 *
 */

#ifndef LIB_VFIO_USER_DMA_H
#define LIB_VFIO_USER_DMA_H

/*
 * FIXME check whether DMA regions must be page aligned. If so then the
 * implementation can be greatly simpified.
 */

/*
 * This library emulates a DMA controller for a device emulation application to
 * perform DMA operations on a foreign memory space.
 *
 * Concepts:
 * - A DMA controller has its own 64-bit DMA address space.
 * - Foreign memory is made available to the DMA controller in linear chunks
 *   called memory regions.
 * - Each memory region is backed by a file descriptor and
 *   is registered with the DMA controllers at a unique, non-overlapping
 *   linear span of the DMA address space.
 * - To perform DMA, the application should first build a scatter-gather
 *   list (sgl) of dma_sg_t from DMA addresses. Then the sgl
 *   can be mapped using dma_sgl_get() into the process's virtual address space
 *   as an iovec for direct access, and unmapped using dma_sgl_put() when done.
 *   Every region is mapped into the application's virtual address space
 *   at registration time with R/W permissions.
 *   dma_sgl_get() ignores all protection bits and only does lookups and
 *   returns pointers to the previously mapped regions. dma_sgl_put() is
 *   effectively a no-op.
 */

#include <stdio.h>
#ifdef DMA_MAP_PROTECTED
#undef DMA_MAP_FAST
#define DMA_MAP_FAST_IMPL 0
#else
#define DMA_MAP_FAST_IMPL 1
#endif

#include <assert.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <sys/queue.h>

#include "libvfio-user.h"
#include "common.h"
#include "private.h"

#define iov_end(iov) ((iov)->iov_base + (iov)->iov_len)

struct vfu_ctx;

struct dma_sg {
    vfu_dma_addr_t dma_addr;
    int region;
    uint64_t length;
    uint64_t offset;
    bool writeable;
};

typedef struct {
    vfu_dma_info_t info;
    int fd;                     // File descriptor to mmap
    off_t offset;               // File offset
    uint8_t *dirty_bitmap;         // Dirty page bitmap
} dma_memory_region_t;

typedef struct dma_controller {
    int max_regions;
    size_t max_size;
    int nregions;
    struct vfu_ctx *vfu_ctx;
    size_t dirty_pgsize;        // Dirty page granularity
    dma_memory_region_t regions[0];
} dma_controller_t;

dma_controller_t *
dma_controller_create(vfu_ctx_t *vfu_ctx, size_t max_regions, size_t max_size);

void
dma_controller_remove_all_regions(dma_controller_t *dma,
                                  vfu_dma_unregister_cb_t *dma_unregister,
                                  void *data);

void
dma_controller_destroy(dma_controller_t *dma);

/* Registers a new memory region.
 * Returns:
 * - On success, a non-negative region number
 * - On failure, -1 with errno set.
 */
MOCK_DECLARE(int, dma_controller_add_region, dma_controller_t *dma,
             vfu_dma_addr_t dma_addr, size_t size, int fd, off_t offset,
             uint32_t prot);

MOCK_DECLARE(int, dma_controller_remove_region, dma_controller_t *dma,
             vfu_dma_addr_t dma_addr, size_t size,
             vfu_dma_unregister_cb_t *dma_unregister, void *data);

MOCK_DECLARE(void, dma_controller_unmap_region, dma_controller_t *dma,
             dma_memory_region_t *region);

// Helper for dma_addr_to_sgl() slow path.
int
_dma_addr_sg_split(const dma_controller_t *dma,
                   vfu_dma_addr_t dma_addr, uint64_t len,
                   dma_sg_t *sg, int max_nr_sgs, int prot);

/* Convert a start address and length to its containing page numbers. */
static inline void
range_to_pages(size_t start, size_t len, size_t pgsize,
               size_t *pgstart, size_t *pgend)
{
    *pgstart = start / pgsize;
    *pgend = ROUND_UP(start + len, pgsize) / pgsize;
}

/* Given a bit position, return the containing byte. */
static inline size_t
bit_to_u8(size_t val)
{
    return val / (CHAR_BIT);
}

/* Return a value modulo the bitsize of a uint8_t. */
static inline size_t
bit_to_u8off(size_t val)
{
    return val % (CHAR_BIT);
}

static inline void
_dma_mark_dirty(const dma_controller_t *dma, const dma_memory_region_t *region,
                dma_sg_t *sg)
{
    size_t index;
    size_t end;
    size_t pgstart;
    size_t pgend;
    size_t i;

    assert(dma != NULL);
    assert(region != NULL);
    assert(sg != NULL);
    assert(region->dirty_bitmap != NULL);

    range_to_pages(sg->offset, sg->length, dma->dirty_pgsize,
                   &pgstart, &pgend);

    index = bit_to_u8(pgstart);
    end = bit_to_u8(pgend) + !!(bit_to_u8off(pgend));

    for (i = index; i < end; i++) {
        uint8_t bm = ~0;

        /* Mask off any pages in the first u8 that aren't in the range. */
        if (i == index && bit_to_u8off(pgstart) != 0) {
            bm &= ~((1 << bit_to_u8off(pgstart)) - 1);
        }

        /* Mask off any pages in the last u8 that aren't in the range. */
        if (i == end - 1 && bit_to_u8off(pgend) != 0) {
            bm &= ((1 << bit_to_u8off(pgend)) - 1);
        }

        __atomic_or_fetch(&region->dirty_bitmap[i], bm, __ATOMIC_SEQ_CST);
    }
}

static inline int
dma_init_sg(const dma_controller_t *dma, dma_sg_t *sg, vfu_dma_addr_t dma_addr,
            uint64_t len, int prot, int region_index)
{
    const dma_memory_region_t *const region = &dma->regions[region_index];

    if ((prot & PROT_WRITE) && !(region->info.prot & PROT_WRITE)) {
        return ERROR_INT(EACCES);
    }

    sg->dma_addr = region->info.iova.iov_base;
    sg->region = region_index;
    sg->offset = dma_addr - region->info.iova.iov_base;
    sg->length = len;
    sg->writeable = prot & PROT_WRITE;

    return 0;
}

/* Takes a linear dma address span and returns a sg list suitable for DMA.
 * A single linear dma address span may need to be split into multiple
 * scatter gather regions due to limitations of how memory can be mapped.
 *
 * Returns:
 * - On success, number of scatter gather entries created.
 * - On failure:
 *     -1 if
 *          - the DMA address span is invalid
 *          - protection violation (errno=EACCES)
 *     (-x - 1) if @max_nr_sgs is too small, where x is the number of sg entries
 *     necessary to complete this request.
 */
static inline int
dma_addr_to_sgl(const dma_controller_t *dma,
                vfu_dma_addr_t dma_addr, size_t len,
                dma_sg_t *sgl, size_t max_nr_sgs, int prot)
{
    static __thread int region_hint;
    int cnt, ret;

    const dma_memory_region_t *const region = &dma->regions[region_hint];
    const void *region_end = iov_end(&region->info.iova);

    // Fast path: single region.
    if (likely(max_nr_sgs > 0 && len > 0 &&
               dma_addr >= region->info.iova.iov_base &&
               dma_addr + len <= region_end &&
               region_hint < dma->nregions)) {
        ret = dma_init_sg(dma, sgl, dma_addr, len, prot, region_hint);
        if (ret < 0) {
            return ret;
        }

        return 1;
    }
    // Slow path: search through regions.
    cnt = _dma_addr_sg_split(dma, dma_addr, len, sgl, max_nr_sgs, prot);
    if (likely(cnt > 0)) {
        region_hint = sgl[0].region;
    }
    return cnt;
}

static inline int
dma_sgl_get(dma_controller_t *dma, dma_sg_t *sgl, struct iovec *iov, size_t cnt)
{
    dma_memory_region_t *region;
    dma_sg_t *sg;

    assert(dma != NULL);
    assert(sgl != NULL);
    assert(iov != NULL);
    assert(cnt > 0);

    sg = sgl;

    do {
        if (sg->region >= dma->nregions) {
            return ERROR_INT(EINVAL);
        }
        region = &dma->regions[sg->region];

        if (region->info.vaddr == NULL) {
            return ERROR_INT(EFAULT);
        }

        vfu_log(dma->vfu_ctx, LOG_DEBUG, "map %p-%p",
                sg->dma_addr + sg->offset,
                sg->dma_addr + sg->offset + sg->length);
        iov->iov_base = region->info.vaddr + sg->offset;
        iov->iov_len = sg->length;

        sg++;
        iov++;
    } while (--cnt > 0);

    return 0;
}

static inline void
dma_sgl_mark_dirty(dma_controller_t *dma, dma_sg_t *sgl, size_t cnt)
{
    dma_memory_region_t *region;
    dma_sg_t *sg;

    assert(dma != NULL);
    assert(sgl != NULL);
    assert(cnt > 0);

    sg = sgl;

    do {
        if (sg->region >= dma->nregions) {
            return;
        }

        region = &dma->regions[sg->region];

        if (sg->writeable) {
            if (dma->dirty_pgsize > 0) {
                _dma_mark_dirty(dma, region, sg);
            }
        }

        vfu_log(dma->vfu_ctx, LOG_DEBUG, "mark dirty %p-%p",
                sg->dma_addr + sg->offset,
                sg->dma_addr + sg->offset + sg->length);
        sg++;
    } while (--cnt > 0);
}

static inline void
dma_sgl_put(dma_controller_t *dma, dma_sg_t *sgl, size_t cnt)
{
    dma_memory_region_t *region;
    dma_sg_t *sg;

    assert(dma != NULL);
    assert(sgl != NULL);
    assert(cnt > 0);

    sg = sgl;

    do {
        if (sg->region >= dma->nregions) {
            return;
        }

        region = &dma->regions[sg->region];

        if (sg->writeable) {
            if (dma->dirty_pgsize > 0) {
                _dma_mark_dirty(dma, region, sg);
            }
        }

        vfu_log(dma->vfu_ctx, LOG_DEBUG, "unmap %p-%p",
                sg->dma_addr + sg->offset,
                sg->dma_addr + sg->offset + sg->length);
        sg++;
    } while (--cnt > 0);
}

int
dma_controller_dirty_page_logging_start(dma_controller_t *dma, size_t pgsize);

void
dma_controller_dirty_page_logging_stop(dma_controller_t *dma);

int
dma_controller_dirty_page_get(dma_controller_t *dma, vfu_dma_addr_t addr,
                              uint64_t len, size_t pgsize, size_t size,
                              char *bitmap);
bool
dma_sg_is_mappable(const dma_controller_t *dma, const dma_sg_t *sg);


#endif /* LIB_VFIO_USER_DMA_H */

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
