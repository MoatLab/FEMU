#ifndef HW_NVME_H
#define HW_NVME_H

#include "qemu/log.h"
#include "block/nvme.h"
#include "hw/block/nvme-ns.h"
#include "hw/block/block.h"
#include "hw/pci/pci.h"

#define NVME_MAX_NAMESPACES 256

#define NVME_GUEST_ERR(trace, fmt, ...) \
    do { \
        (trace_##trace)(__VA_ARGS__); \
        qemu_log_mask(LOG_GUEST_ERROR, #trace \
            " in %s: " fmt "\n", __func__, ## __VA_ARGS__); \
    } while (0)

#define DEFINE_NVME_PROPERTIES(_state, _props) \
    DEFINE_PROP_STRING("serial", _state, _props.serial), \
    DEFINE_PROP_UINT32("cmb_size_mb", _state, _props.cmb_size_mb, 0), \
    DEFINE_PROP_UINT32("num_queues", _state, _props.num_queues, 64), \
    DEFINE_PROP_UINT8("mdts", _state, _props.mdts, 7)

typedef struct NvmeParams {
    char     *serial;
    uint32_t num_queues;
    uint8_t  mdts;
    uint32_t cmb_size_mb;
} NvmeParams;

typedef struct NvmeAsyncEvent {
    QSIMPLEQ_ENTRY(NvmeAsyncEvent) entry;
    NvmeAerResult result;
} NvmeAsyncEvent;

typedef struct NvmeBlockBackendRequest {
    uint64_t slba;
    uint16_t nlb;
    uint64_t blk_offset;

    struct NvmeRequest *req;

    BlockAIOCB      *aiocb;
    BlockAcctCookie acct;

    QEMUSGList   *qsg;
    QEMUIOVector iov;

    QTAILQ_ENTRY(NvmeBlockBackendRequest) tailq_entry;
    QSLIST_ENTRY(NvmeBlockBackendRequest) slist_entry;
} NvmeBlockBackendRequest;

typedef struct NvmeRequest {
    struct NvmeSQueue    *sq;
    struct NvmeNamespace *ns;
    NvmeCqe              cqe;
    NvmeCmd              cmd;

    uint64_t slba;
    uint16_t nlb;
    hwaddr   mptr;
    uint16_t status;
    bool     is_cmb;
    bool     is_write;

    QEMUSGList   qsg, qsg_md;

    QTAILQ_HEAD(, NvmeBlockBackendRequest) blk_req_tailq;
    QTAILQ_ENTRY(NvmeRequest)entry;
} NvmeRequest;

typedef struct NvmeSQueue {
    struct NvmeCtrl *ctrl;
    uint16_t    sqid;
    uint16_t    cqid;
    uint32_t    head;
    uint32_t    tail;
    uint32_t    size;
    uint64_t    dma_addr;
    QEMUTimer   *timer;
    NvmeRequest *io_req;
    QTAILQ_HEAD(, NvmeRequest) req_list;
    QTAILQ_HEAD(, NvmeRequest) out_req_list;
    QTAILQ_ENTRY(NvmeSQueue) entry;
} NvmeSQueue;

typedef struct NvmeCQueue {
    struct NvmeCtrl *ctrl;
    uint8_t     phase;
    uint16_t    cqid;
    uint16_t    irq_enabled;
    uint32_t    head;
    uint32_t    tail;
    uint32_t    vector;
    uint32_t    size;
    uint64_t    dma_addr;
    QEMUTimer   *timer;
    QTAILQ_HEAD(, NvmeSQueue) sq_list;
    QTAILQ_HEAD(, NvmeRequest) req_list;
} NvmeCQueue;

#define TYPE_NVME_BUS "nvme-bus"
#define NVME_BUS(obj) OBJECT_CHECK(NvmeBus, (obj), TYPE_NVME_BUS)

typedef struct NvmeBus {
    BusState parent_bus;
} NvmeBus;

#define TYPE_NVME "nvme"
#define NVME(obj) \
        OBJECT_CHECK(NvmeCtrl, (obj), TYPE_NVME)

typedef struct NvmeCtrl {
    PCIDevice    parent_obj;
    MemoryRegion iomem;
    MemoryRegion ctrl_mem;
    NvmeBar      bar;
    NvmeParams   params;

    uint64_t    starttime_ms;
    uint16_t    temperature;
    uint32_t    page_size;
    uint16_t    page_bits;
    uint16_t    max_prp_ents;
    uint16_t    cqe_size;
    uint16_t    sqe_size;
    uint32_t    reg_size;
    uint32_t    num_namespaces;
    uint32_t    max_q_ents;
    uint8_t     outstanding_aers;
    uint32_t    cmbsz;
    uint32_t    cmbloc;
    uint8_t     *cmbuf;
    uint64_t    irq_status;
    uint64_t    host_timestamp;                 /* Timestamp sent by the host */
    uint64_t    timestamp_set_qemu_clock_ms;    /* QEMU clock time */
    uint32_t    qs_created;
    QEMUTimer   *aer_timer;
    uint8_t     aer_mask;
    uint8_t     aer_mask_queued;
    NvmeRequest **aer_reqs;
    QSIMPLEQ_HEAD(, NvmeAsyncEvent) aer_queue;

    NvmeErrorLog    *elpes;
    NvmeNamespace   *namespaces[NVME_MAX_NAMESPACES];
    NvmeSQueue      **sq;
    NvmeCQueue      **cq;
    NvmeSQueue      admin_sq;
    NvmeCQueue      admin_cq;
    NvmeFeatureVal  features;
    NvmeIdCtrl      id_ctrl;

    NvmeBus bus;
    uint16_t (*admin_cmd)(struct NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req);
    uint16_t (*io_cmd)(struct NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req);
} NvmeCtrl;

typedef uint16_t (*NvmeBlockSetupFn)(NvmeCtrl *n, NvmeNamespace *ns,
    QEMUSGList *qsg, uint64_t blk_offset, uint32_t unit_len, NvmeRequest *req);

static inline bool nvme_rw_is_write(NvmeRequest *req)
{
    return req->cmd.opcode == NVME_CMD_WRITE;
}

static inline bool nvme_is_error(uint16_t status, uint16_t err)
{
    /* strip DNR and MORE */
    return (status & 0xfff) == err;
}

static inline bool nvme_nsid_is_valid(NvmeCtrl *n, uint32_t nsid)
{
    if (unlikely(nsid == 0 || nsid > n->num_namespaces)) {
        return false;
    }

    return true;
}

int nvme_register_namespace(NvmeCtrl *n, NvmeNamespace *ns, Error **errp);

void nvme_addr_read(NvmeCtrl *n, hwaddr addr, void *buf, int size);
void nvme_addr_write(NvmeCtrl *n, hwaddr addr, void *buf, int size);

uint16_t nvme_dma_read(NvmeCtrl *n, uint8_t *ptr, uint32_t len,
    NvmeCmd *cmd, NvmeRequest *req);
uint16_t nvme_dma_read_sgl(NvmeCtrl *n, uint8_t *ptr, uint32_t len,
    NvmeSglDescriptor sgl, NvmeCmd *cmd, NvmeRequest *req);
uint16_t nvme_dma_write(NvmeCtrl *n, uint8_t *ptr, uint32_t len, NvmeCmd *cmd,
    NvmeRequest *req);

void nvme_noop_cb(void *opaque, int ret);
void nvme_rw_cb(void *opaque, int ret);
uint16_t nvme_rw_check_req(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req);

void nvme_clear_events(NvmeCtrl *n, uint8_t event_type);
void nvme_enqueue_event(NvmeCtrl *n, uint8_t event_type, uint8_t event_info,
    uint8_t log_page);

void nvme_enqueue_req_completion(NvmeCQueue *cq, NvmeRequest *req);

NvmeBlockBackendRequest *nvme_blk_req_get(NvmeCtrl *n, NvmeRequest *req,
    QEMUSGList *qsg);
void nvme_blk_req_put(NvmeCtrl *n, NvmeBlockBackendRequest *blk_req);

uint16_t nvme_blk_map(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req,
    NvmeBlockSetupFn blk_setup);
uint16_t nvme_blk_submit_io(NvmeCtrl *n, NvmeRequest *req,
    BlockCompletionFunc *cb);

uint16_t nvme_io_cmd(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req);

uint16_t nvme_get_log(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req);
uint16_t nvme_get_feature(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req);
uint16_t nvme_set_feature(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req);
uint16_t nvme_admin_cmd(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req);

int nvme_check_constraints(NvmeCtrl *n, Error **errp);
int nvme_init_blk(NvmeCtrl *n, Error **errp);
void nvme_init_state(NvmeCtrl *n);
void nvme_init_pci(NvmeCtrl *n, PCIDevice *pci_dev);
void nvme_init_ctrl(NvmeCtrl *n);

void nvme_free_ctrl(NvmeCtrl *n, PCIDevice *pci_dev);

#endif /* HW_NVME_H */
