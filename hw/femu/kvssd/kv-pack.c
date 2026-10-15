/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * FEMU KV-SSD packed page header (kv_pack=on). See kv-pack.h.
 */
#include "qemu/osdep.h"
#include "kv-pack.h"

KvPackPage *kv_pack_new(void)
{
    KvPackPage *pg = calloc(1, sizeof(*pg));

    if (pg) {
        pg->id = KV_PACK_NO_PAGE;
    }
    return pg;
}

void kv_pack_free(KvPackPage *pg)
{
    if (pg) {
        free(pg->item);
        free(pg);
    }
}

int kv_pack_reserve(KvPackPage *pg, uint32_t n)
{
    KvPackItem *it;

    if (n <= pg->cap) {
        return 0;
    }
    it = realloc(pg->item, (size_t)n * sizeof(*it));
    if (!it) {
        return -1;
    }
    pg->item = it;
    pg->cap = n;
    return 0;
}

bool kv_pack_fits(const KvPackPage *pg, uint32_t len, uint32_t pgsz)
{
    return pg->fill <= pgsz && kv_pack_rec(len) <= pgsz - pg->fill;
}

bool kv_pack_full(const KvPackPage *pg, uint32_t pgsz)
{
    return !kv_pack_fits(pg, 1, pgsz) && pg->live_bytes == pg->fill;
}

int kv_pack_append(KvPackPage *pg, uint64_t owner, uint32_t len,
                   uint32_t *off)
{
    if (pg->nr == pg->cap &&
        kv_pack_reserve(pg, pg->cap ? 2 * pg->cap : 16)) {
        return -1;
    }
    pg->item[pg->nr++] = (KvPackItem) {
        .owner = owner, .off = pg->fill, .len = len, .live = true,
    };
    *off = pg->fill;
    pg->fill += kv_pack_rec(len);
    pg->live++;
    pg->live_bytes += kv_pack_rec(len);
    return 0;
}

int kv_pack_find(const KvPackPage *pg, uint32_t off)
{
    uint32_t lo = 0;
    uint32_t hi = pg->nr;

    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;

        if (pg->item[mid].off == off) {
            return (int)mid;
        }
        if (pg->item[mid].off < off) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return -1;
}

uint32_t kv_pack_drop(KvPackPage *pg, int i)
{
    KvPackItem *it = &pg->item[i];

    if (!it->live) {
        return 0;
    }
    it->live = false;
    pg->live--;
    pg->live_bytes -= kv_pack_rec(it->len);
    return kv_pack_rec(it->len);
}

void kv_pack_compact(KvPackPage *pg,
                     void (*moved)(void *opaque, uint64_t owner,
                                   uint32_t off),
                     void *opaque)
{
    uint32_t nr = 0;
    uint32_t fill = 0;

    for (uint32_t i = 0; i < pg->nr; i++) {
        KvPackItem it = pg->item[i];

        if (!it.live) {
            continue;
        }
        if (it.off != fill && moved) {
            moved(opaque, it.owner, fill);
        }
        it.off = fill;
        fill += kv_pack_rec(it.len);
        pg->item[nr++] = it;
    }
    pg->nr = nr;
    pg->fill = fill;
}
