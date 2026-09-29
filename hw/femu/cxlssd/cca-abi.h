/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * CXL SSD caching API (CCA): the BAR5 layout shared by femu-cxl-ssd and
 * the guest library in hw/femu/tools/cca. Only fixed-width little-endian
 * fields and no pointers, so both sides compile this one file.
 *
 * BAR5 is 512 KiB: trapped registers in the first 4 KiB, then RAM holding
 * the header, a request ring, a response ring and a pool of command slots.
 * Ring sizes are constants and never read from shared memory.
 */
#ifndef FEMU_CXL_CCA_ABI_H
#define FEMU_CXL_CCA_ABI_H

#include <stdint.h>

#define CCA_SHMEM_MAGIC         0x43434131u     /* "CCA1" */
#define CCA_LAYOUT_VERSION      2u
#define CCA_RING_COUNT          2048u           /* also the slot count */
#define CCA_SLOT_SIZE           128u
#define CCA_BAR_INDEX           5
#define CCA_BAR_SIZE            (512u << 10)
#define CCA_REG_SIZE            4096u
#define CCA_SHM_OFFSET          4096u
#define CCA_SHM_SIZE            (CCA_BAR_SIZE - CCA_SHM_OFFSET)
#define CCA_PAGE_SHIFT          12

/* Offsets within the RAM part (BAR5 offset CCA_SHM_OFFSET). */
#define CCA_REQ_RING_OFFSET     0x0100u
#define CCA_RESP_RING_OFFSET    0x2200u
#define CCA_SLOT_POOL_OFFSET    0x5000u

/* Register page: 4- or 8-byte little-endian accesses. */
#define CCA_REG_MAGIC           0x00    /* RO */
#define CCA_REG_VERSION         0x04    /* RO */
#define CCA_REG_STATUS          0x08    /* RO, CCA_STATUS_* */
#define CCA_REG_DOORBELL        0x0c    /* WO, any value */
#define CCA_REG_RESET           0x10    /* WO, CCA_RESET_* */
#define CCA_REG_FATAL_REASON    0x14    /* RO, CCA_FATAL_* */
#define CCA_REG_MEDIA_PAGES     0x18    /* RO, 64 bits */
#define CCA_REG_CACHE_PAGES     0x20    /* RO */
#define CCA_REG_CACHE_WAYS      0x24    /* RO */
#define CCA_REG_PIN_LIMIT       0x28    /* RO, pins allowed per set */
#define CCA_REG_COMPLETED       0x30    /* RO, 64 bits, since last reset */
#define CCA_REG_EPOCH           0x38    /* RO, changes on every reset */
#define CCA_REG_END             0x40

#define CCA_STATUS_READY        (1u << 0)
#define CCA_STATUS_FATAL        (1u << 1)
#define CCA_STATUS_CACHE        (1u << 2)
#define CCA_STATUS_BUSY         (1u << 3)

#define CCA_RESET_RINGS         1u      /* rings only */
#define CCA_RESET_ALL           2u      /* rings, unpin all, enable all */

#define CCA_FATAL_RING          1u      /* request head too far ahead */
#define CCA_FATAL_SLOT          2u      /* slot index out of range */
#define CCA_FATAL_RESPONSE      3u      /* response ring overflow */

enum cca_ctrl_cmd {
    CCA_CTRL_NOP = 0,
    CCA_CTRL_CACHE_ENABLE = 1,
    CCA_CTRL_CACHE_DISABLE = 2,
    CCA_CTRL_PIN = 3,
    CCA_CTRL_UNPIN = 4,
    CCA_CTRL_INVALIDATE = 5,
    CCA_CTRL_QUERY = 6,
    CCA_CTRL_MAX
};

#define CCA_F_ALL       (1u << 0)   /* whole media; start and count are 0 */
#define CCA_F_FORCE     (1u << 1)   /* INVALIDATE, CACHE_DISABLE: unpin */

/* Ranges are in 4 KiB device pages (DPA >> 12). */
struct cca_ctrl_cmd_s {
    uint32_t cmd;
    uint32_t flags;
    uint64_t lpn_start;
    uint64_t lpn_count;
    uint64_t tag;                   /* opaque, echoed */
    uint64_t rsvd[4];               /* must be 0 */
};

struct cca_ctrl_resp_s {
    int32_t status;                 /* 0 or a negative Linux errno */
    uint32_t rsvd0;
    uint64_t lpn_start;             /* echoed */
    uint64_t lpn_count;             /* pages acted on, or progress */
    uint64_t tag;                   /* echoed */
    uint64_t resident;              /* QUERY only */
    uint64_t dirty;
    uint64_t pinned;
    uint64_t uncached;
};

struct cca_ctrl_slot_s {
    struct cca_ctrl_cmd_s cmd;
    struct cca_ctrl_resp_s resp;
};

/* Both indices run freely; entries are used modulo CCA_RING_COUNT. */
struct cca_ring {
    uint32_t head;                  /* producer */
    uint32_t pad0[15];
    uint32_t tail;                  /* consumer */
    uint32_t pad1[15];
    uint32_t entries[CCA_RING_COUNT];   /* slot indices */
};

struct cca_shmem_header {
    uint32_t magic;
    uint32_t version;
    uint32_t ring_count;
    uint32_t slot_size;
    uint64_t offset_ctrl_req_ring;
    uint64_t offset_ctrl_resp_ring;
    uint64_t offset_ctrl_slot_pool;
    uint64_t offset_req_ring;       /* data path: not implemented, 0 */
    uint64_t offset_resp_ring;
    uint64_t offset_req_pool;
    uint64_t offset_data_region;
    uint64_t size_data_region;
};

_Static_assert(sizeof(struct cca_ctrl_cmd_s) == 64, "command size");
_Static_assert(sizeof(struct cca_ctrl_resp_s) == 64, "response size");
_Static_assert(sizeof(struct cca_ctrl_slot_s) == CCA_SLOT_SIZE, "slot size");
_Static_assert(sizeof(struct cca_shmem_header) == 80, "header size");
_Static_assert((CCA_RING_COUNT & (CCA_RING_COUNT - 1)) == 0,
               "ring count is a power of two");
_Static_assert(CCA_REQ_RING_OFFSET + sizeof(struct cca_ring) <=
               CCA_RESP_RING_OFFSET, "request ring overlaps");
_Static_assert(CCA_RESP_RING_OFFSET + sizeof(struct cca_ring) <=
               CCA_SLOT_POOL_OFFSET, "response ring overlaps");
_Static_assert(CCA_SLOT_POOL_OFFSET + CCA_RING_COUNT * CCA_SLOT_SIZE <=
               CCA_SHM_SIZE, "slot pool exceeds the BAR");

#endif
