/*
 * On-chip DMA controller framework.
 *
 * Copyright (C) 2008 Nokia Corporation
 * Written by Andrzej Zaborowski <andrew@openedhand.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 or
 * (at your option) version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/timer.h"
#include "qemu/log.h"
#include "system/physmem.h"
#include "hw/dma/soc_dma.h"

static void transfer_mem2mem(struct soc_dma_ch_s *ch)
{
    /*
     * Memory-to-memory transfer: do the whole thing in one go.  The
     * hardware spec says that it is invalid to program the OMAP DMA
     * controller with addresses that don't match the port (i.e. to
     * ask for a transfer to/from a memory port with a physaddr that
     * isn't within that port range) and that if you do then the
     * transfer continues and memory can be corrupted.  So we can map
     * both source and destination, and treat short mappings and
     * failed mappings as a guest error.
     */
    hwaddr srclen = ch->bytes;
    hwaddr dstlen = ch->bytes;
    hwaddr srcaddr = ch->vaddr[0];
    hwaddr dstaddr = ch->vaddr[1];
    void *srcmem, *dstmem;
    hwaddr xferlen = 0;

    srcmem = physical_memory_map(srcaddr, &srclen, false);
    if (!srcmem) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "soc_dma mem2mem transfer: could not map source; "
                      "guest error programming source port/address\n");
        return;
    }

    dstmem = physical_memory_map(dstaddr, &dstlen, true);
    if (!dstmem) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "soc_dma mem2mem transfer: could not map destination; "
                      "guest error programming destination port/address\n");
        goto unmap_src;
    }

    xferlen = MIN(srclen, dstlen);
    if (xferlen < ch->bytes) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "soc_dma mem2mem transfer: could not transfer all data; "
                      "guest error programming src or destination addresses\n");
        /* Continue to transfer whatever did fit in the port window */
    }

    memmove(dstmem, srcmem, xferlen);

    physical_memory_unmap(dstmem, dstlen, true, xferlen);
unmap_src:
    physical_memory_unmap(srcmem, srclen, false, xferlen);
}

struct dma_s {
    struct soc_dma_s soc;
    int chnum;
    uint64_t ch_enable_mask;
    int64_t channel_freq;
    int enabled_count;

    struct memmap_entry_s {
        enum soc_dma_port_type type;
        hwaddr addr;
        struct {
            size_t size;
        } mem;
    } *memmap;
    int memmap_size;

    struct soc_dma_ch_s ch[];
};

static void soc_dma_ch_schedule(struct soc_dma_ch_s *ch, uint64_t delay_bytes)
{
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    struct dma_s *dma = (struct dma_s *) ch->dma;

    /*
     * Worst case delay bytes is only slightly larger than fits into
     * a 32-bit integer, so this won't overflow.
     */
    timer_mod(ch->timer, now + delay_bytes / dma->channel_freq);
}

static void soc_dma_ch_run(void *opaque)
{
    struct soc_dma_ch_s *ch = (struct soc_dma_ch_s *) opaque;

    ch->running = 1;
    ch->dma->setup_fn(ch);
    ch->transfer_fn(ch);
    ch->running = 0;

    if (ch->enable)
        soc_dma_ch_schedule(ch, ch->bytes);
    ch->bytes = 0;
}

static inline struct memmap_entry_s *soc_dma_lookup(struct dma_s *dma,
                hwaddr addr)
{
    struct memmap_entry_s *lo;
    int hi;

    lo = dma->memmap;
    hi = dma->memmap_size;

    while (hi > 1) {
        hi /= 2;
        if (lo[hi].addr <= addr)
            lo += hi;
    }

    return lo;
}

static inline enum soc_dma_port_type soc_dma_ch_update_type(
                struct soc_dma_ch_s *ch, int port)
{
    struct dma_s *dma = (struct dma_s *) ch->dma;
    struct memmap_entry_s *entry = soc_dma_lookup(dma, ch->vaddr[port]);

    if (entry->type == soc_dma_port_mem) {
        if (entry->addr > ch->vaddr[port] ||
                        entry->addr + entry->mem.size <= ch->vaddr[port])
            return soc_dma_port_other;

        /* TODO: support constant memory address for source port as used for
         * drawing solid rectangles by PalmOS(R).  */
        if (ch->type[port] != soc_dma_access_const)
            return soc_dma_port_other;

        return soc_dma_port_mem;
    } else
        return soc_dma_port_other;
}

void soc_dma_ch_update(struct soc_dma_ch_s *ch)
{
    enum soc_dma_port_type src, dst;

    src = soc_dma_ch_update_type(ch, 0);
    dst = soc_dma_ch_update_type(ch, 1);
    if (src == soc_dma_port_other || dst == soc_dma_port_other) {
        ch->update = 0;
        ch->transfer_fn = ch->dma->transfer_fn;
    } else {
        ch->update = 1;
        ch->transfer_fn = transfer_mem2mem;
    }
}

static void soc_dma_ch_freq_update(struct dma_s *s)
{
    if (s->enabled_count)
        /* We completely ignore channel priorities and stuff */
        s->channel_freq = s->soc.freq / s->enabled_count;
    else {
        /* TODO: Signal that we want to disable the functional clock and let
         * the platform code decide what to do with it, i.e. check that
         * auto-idle is enabled in the clock controller and if we are stopping
         * the clock, do the same with any parent clocks that had only one
         * user keeping them on and auto-idle enabled.  */
    }
}

void soc_dma_set_request(struct soc_dma_ch_s *ch, int level)
{
    struct dma_s *dma = (struct dma_s *) ch->dma;

    dma->enabled_count += level - ch->enable;

    if (level)
        dma->ch_enable_mask |= (uint64_t)1 << ch->num;
    else
        dma->ch_enable_mask &= ~((uint64_t)1 << ch->num);

    if (level != ch->enable) {
        soc_dma_ch_freq_update(dma);
        ch->enable = level;

        if (!ch->enable)
            timer_del(ch->timer);
        else if (!ch->running)
            soc_dma_ch_run(ch);
        else
            soc_dma_ch_schedule(ch, 1);
    }
}

void soc_dma_reset(struct soc_dma_s *soc)
{
    struct dma_s *s = (struct dma_s *) soc;

    s->soc.drqbmp = 0;
    s->ch_enable_mask = 0;
    s->enabled_count = 0;
    soc_dma_ch_freq_update(s);
}

/* TODO: take a functional-clock argument */
struct soc_dma_s *soc_dma_init(int n)
{
    int i;
    struct dma_s *s = g_malloc0(sizeof(*s) + n * sizeof(*s->ch));

    s->chnum = n;
    s->soc.ch = s->ch;
    for (i = 0; i < n; i ++) {
        s->ch[i].dma = &s->soc;
        s->ch[i].num = i;
        s->ch[i].timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, soc_dma_ch_run, &s->ch[i]);
    }

    soc_dma_reset(&s->soc);

    return &s->soc;
}

void soc_dma_port_add_mem(struct soc_dma_s *soc, hwaddr virt_base, size_t size)
{
    struct memmap_entry_s *entry;
    struct dma_s *dma = (struct dma_s *) soc;

    dma->memmap = g_realloc(dma->memmap, sizeof(*entry) *
                    (dma->memmap_size + 1));
    entry = soc_dma_lookup(dma, virt_base);

    if (dma->memmap_size) {
        if (entry->type == soc_dma_port_mem) {
            if ((entry->addr >= virt_base && entry->addr < virt_base + size) ||
                            (entry->addr <= virt_base &&
                             entry->addr + entry->mem.size > virt_base)) {
                error_report("%s: RAM at %"PRIx64 "-%"PRIx64
                             " collides with RAM region at %"PRIx64
                             "-%"PRIx64, __func__,
                             virt_base, virt_base + size,
                             entry->addr, entry->addr + entry->mem.size);
                exit(-1);
            }

            if (entry->addr <= virt_base)
                entry ++;
        } else {
            if (entry->addr >= virt_base &&
                            entry->addr < virt_base + size) {
                error_report("%s: RAM at %"PRIx64 "-%"PRIx64
                             " collides with FIFO at %"PRIx64,
                             __func__, virt_base, virt_base + size,
                             entry->addr);
                exit(-1);
            }

            while (entry < dma->memmap + dma->memmap_size &&
                            entry->addr <= virt_base)
                entry ++;
        }

        memmove(entry + 1, entry,
                        (uint8_t *) (dma->memmap + dma->memmap_size ++) -
                        (uint8_t *) entry);
    } else
        dma->memmap_size ++;

    entry->addr          = virt_base;
    entry->type          = soc_dma_port_mem;
    entry->mem.size    = size;
}

/* TODO: port removal for ports like PCMCIA memory */
