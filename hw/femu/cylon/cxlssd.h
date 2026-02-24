#ifndef __CYLON_CXLSSD_H
#define __CYLON_CXLSSD_H

#include "qemu/osdep.h"
#include "cache/cache_backend.h"
#include "cache/cache_plugin.h"
#include "hw/femu/inc/pqueue.h"
#include "cca_shmem.h"

struct rte_ring;
struct DerKvmState;

/* CXL memory request type (Cylon-specific) */
enum {
    CXL_READ,
    CXL_WRITE,
};

struct cxl_req {
    uint64_t addr;
    unsigned size;
    void *data_ptr;
    unsigned is_read : 1;   /* 1 = CXL_READ, 0 = CXL_WRITE */

    struct {
        uint64_t start_time;
        uint64_t expire_time;
    };
    size_t pos;             /* for pqueue heap index */
};

/* CXLSSD-specific state (opaque from FTL; stored in struct ssd->opaque) */
typedef struct cxlssd {
    /* DER cache backend (buf_space, buf_size, hpa_base) */
    CylonCacheBackend cache_backend;

    /* KVM memslot / EPT state (set in der_kvm_set_user_memory_region) */
    struct DerKvmState *der_kvm;

    /* CXL request/response rings and priority queue */
    struct rte_ring *cxl_req;
    struct rte_ring *cxl_resp;
    pqueue_t *cxl_pq;

    /* CCA (Cylon Caching API) ivshmem: control rings for userspace library */
    void *cca_base;                          /* NULL if cca_dev not set */
    struct rte_ring *cca_ctrl_req_ring;      /* guest -> FEMU */
    struct rte_ring *cca_ctrl_resp_ring;     /* FEMU -> guest */
    struct cca_ctrl_slot_s *cca_ctrl_slots;
    uint32_t cca_ring_count;

    /* Cylon cache plugin (optional) */
    struct cache_plugin *cache;
} Cxlssd;

struct ssd;
struct FemuCtrl;

/* Get CXLSSD context from ssd (NULL if not cxlssd). */
Cxlssd *cxlssd_ctx_from_ssd(struct ssd *ssd);

/* Get CXLSSD context from controller (NULL if not cxlssd). */
Cxlssd *cxlssd_ctx_from_ctrl(struct FemuCtrl *n);

#endif
