/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "cca-ring.h"

static struct cca_ring *cca_ring_at(CcaRingHost *h, uint32_t offset)
{
    return (struct cca_ring *)(h->shm + offset);
}

static struct cca_ctrl_slot_s *cca_slot(CcaRingHost *h, uint32_t slot)
{
    struct cca_ctrl_slot_s *pool =
        (struct cca_ctrl_slot_s *)(h->shm + CCA_SLOT_POOL_OFFSET);

    return &pool[slot % CCA_RING_COUNT];
}

/* Rewrite the header, empty both rings and zero every slot (NOP). */
void cca_ring_format(CcaRingHost *h, uint8_t *shm)
{
    struct cca_shmem_header hdr = {
        .magic = CCA_SHMEM_MAGIC,
        .version = CCA_LAYOUT_VERSION,
        .ring_count = CCA_RING_COUNT,
        .slot_size = CCA_SLOT_SIZE,
        .offset_ctrl_req_ring = CCA_REQ_RING_OFFSET,
        .offset_ctrl_resp_ring = CCA_RESP_RING_OFFSET,
        .offset_ctrl_slot_pool = CCA_SLOT_POOL_OFFSET,
    };

    h->shm = shm;
    h->req_tail = 0;
    h->resp_head = 0;
    h->fatal = 0;
    memset(shm, 0, CCA_SLOT_POOL_OFFSET + CCA_RING_COUNT * CCA_SLOT_SIZE);
    memcpy(shm, &hdr, sizeof(hdr));
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

/*
 * Take the next request: 1 with @slot and a private copy of the command,
 * 0 when the ring is empty, -1 once the ring is fatally inconsistent.
 */
int cca_ring_pop(CcaRingHost *h, uint32_t *slot, struct cca_ctrl_cmd_s *cmd)
{
    struct cca_ring *req = cca_ring_at(h, CCA_REQ_RING_OFFSET);
    uint32_t head;
    uint32_t index;

    if (h->fatal) {
        return -1;
    }
    head = __atomic_load_n(&req->head, __ATOMIC_ACQUIRE);
    if (head == h->req_tail) {
        return 0;
    }
    if (head - h->req_tail > CCA_RING_COUNT) {
        h->fatal = CCA_FATAL_RING;
        return -1;
    }
    index = __atomic_load_n(&req->entries[h->req_tail % CCA_RING_COUNT],
                            __ATOMIC_RELAXED);
    if (index >= CCA_RING_COUNT) {
        h->fatal = CCA_FATAL_SLOT;
        return -1;
    }
    /* Copy once: the guest may rewrite the slot while it is validated. */
    memcpy(cmd, &cca_slot(h, index)->cmd, sizeof(*cmd));
    h->req_tail++;
    __atomic_store_n(&req->tail, h->req_tail, __ATOMIC_RELEASE);
    *slot = index;
    return 1;
}

/* Post a response; false once the guest has let the ring overflow. */
bool cca_ring_complete(CcaRingHost *h, uint32_t slot,
                       const struct cca_ctrl_resp_s *resp)
{
    struct cca_ring *ring = cca_ring_at(h, CCA_RESP_RING_OFFSET);
    uint32_t tail;

    if (h->fatal) {
        return false;
    }
    tail = __atomic_load_n(&ring->tail, __ATOMIC_ACQUIRE);
    if (h->resp_head - tail >= CCA_RING_COUNT) {
        h->fatal = CCA_FATAL_RESPONSE;
        return false;
    }
    memcpy(&cca_slot(h, slot)->resp, resp, sizeof(*resp));
    __atomic_store_n(&ring->entries[h->resp_head % CCA_RING_COUNT],
                     slot % CCA_RING_COUNT, __ATOMIC_RELAXED);
    h->resp_head++;
    __atomic_store_n(&ring->head, h->resp_head, __ATOMIC_RELEASE);
    return true;
}
