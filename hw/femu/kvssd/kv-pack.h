/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * FEMU KV-SSD packed page header (kv_pack=on).
 *
 * Small values share a NAND page, as in a value log (PinK, ATC '20) or the
 * data pages of a KV-SSD. The header of a packed page lists its records:
 * the owner, the offset and the value length of each. A record is the
 * value and a header that carries the key, so GC can find the index entry.
 * The header needs nothing from QEMU, so a unit test builds it alone.
 */
#ifndef FEMU_KV_PACK_H
#define FEMU_KV_PACK_H

/* the bytes beside each value: key (16), length, version and offset */
#define KV_PACK_HDR         32
/* the page id of a header that is still in DRAM */
#define KV_PACK_NO_PAGE     UINT64_MAX

typedef struct KvPackItem {
    uint64_t owner;             /* table slot, or the caller's "none" */
    uint32_t off;               /* of the record: header, then value */
    uint32_t len;               /* of the value */
    bool live;
} KvPackItem;

typedef struct KvPackPage {
    uint64_t id;                /* the flash page, or KV_PACK_NO_PAGE */
    KvPackItem *item;           /* in order of offset */
    uint32_t nr;
    uint32_t cap;
    uint32_t fill;              /* the offset of the next record */
    uint32_t live;              /* live records */
    uint64_t live_bytes;        /* their bytes, headers too */
} KvPackPage;

/* the bytes a value of @len bytes takes in its page */
static inline uint32_t kv_pack_rec(uint32_t len)
{
    return KV_PACK_HDR + len;
}

/* a new empty header in DRAM, or NULL when memory is short */
KvPackPage *kv_pack_new(void);
void kv_pack_free(KvPackPage *pg);

/* room for @n items with no allocation later; -1 when memory is short */
int kv_pack_reserve(KvPackPage *pg, uint32_t n);

/* true when a record of a value of @len bytes fits after the fill */
bool kv_pack_fits(const KvPackPage *pg, uint32_t len, uint32_t pgsz);

/* true when no record fits after the fill and no record is dead */
bool kv_pack_full(const KvPackPage *pg, uint32_t pgsz);

/*
 * Add a live record for @owner at the fill offset, which goes to *@off.
 * Return 0, or -1 when memory is short; the header is then as it was.
 */
int kv_pack_append(KvPackPage *pg, uint64_t owner, uint32_t len,
                   uint32_t *off);

/* the item of the record at byte @off, or -1 */
int kv_pack_find(const KvPackPage *pg, uint32_t off);

/* item @i dies; return its record bytes, 0 when it was dead already */
uint32_t kv_pack_drop(KvPackPage *pg, int i);

/*
 * Close the gaps that dead records leave, as a write buffer drops the
 * data an overwrite replaced. @moved learns the new offset of each live
 * record that moves; it may be NULL.
 */
void kv_pack_compact(KvPackPage *pg,
                     void (*moved)(void *opaque, uint64_t owner,
                                   uint32_t off),
                     void *opaque);

#endif
