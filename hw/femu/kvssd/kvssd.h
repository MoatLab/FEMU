#ifndef FEMU_KVSSD_H
#define FEMU_KVSSD_H

#include "qemu/thread.h"
#include "kv-model.h"
#include "kv-lsm.h"

typedef struct FemuCtrl FemuCtrl;
typedef struct NvmeNamespace NvmeNamespace;
typedef struct NvmeCmd NvmeCmd;
typedef struct NvmeCqe NvmeCqe;
typedef struct NvmeRequest NvmeRequest;
struct ssd;
struct ppa;

#define FEMU_KVSSD_KEY_MAX 16          /* NVMe-KV: max KV key size is 16 bytes */

/*
 * KV index entry. The value lives in the NAND-backed value space at byte
 * `value_off` (the host-visible KV value bytes), with `length` bytes. The index
 * itself is the device-side key->location map a KV-SSD FTL owns.
 */
typedef struct FemuKvssdMappingEntry {
    uint8_t  key[FEMU_KVSSD_KEY_MAX];
    uint8_t  key_len;
    uint64_t value_off;                /* offset into the value backing store */
    uint64_t length;                   /* value length in bytes */
    struct ppa *ppas;                  /* NAND pages holding this value */
    uint32_t nr_ppas;
} FemuKvssdMappingEntry;

struct FemuKvssdState;

/*
 * Pluggable KV index strategy: the open-addressed hash (default) or the
 * LSM tree (kv_index=lsm). Hooks operate under kvssd->lock.
 */
typedef struct FemuKvIndexOps {
    const char *name;
    int  (*find)(struct FemuKvssdState *s, const uint8_t *key, uint8_t kl,
                 int *prev_slot);
    uint16_t (*upsert)(struct FemuKvssdState *s, const uint8_t *key, uint8_t kl,
                       uint64_t off, uint64_t len, struct ppa *ppas,
                       uint32_t nr_ppas);
    /* 1 removed, 0 absent, -1 the index could not record the delete */
    int  (*remove)(struct FemuKvssdState *s, const uint8_t *key, uint8_t kl);
    /*
     * Flash reads of a lookup, one after the other from @stime; return the
     * time they take. NULL for an index in DRAM.
     */
    uint64_t (*probe)(struct FemuKvssdState *s, const uint8_t *key,
                      uint8_t kl, int64_t stime);
} FemuKvIndexOps;

typedef struct FemuKvssdState {
    /* device-side key->location index */
    FemuKvssdMappingEntry *table;
    uint32_t hash_slots;
    uint32_t nr_entries;
    const FemuKvIndexOps *index;

    /* NAND-backed value space: a host-visible byte arena whose pages are charged
     * through the NAND media model via `ssd` below. value_used tracks live value
     * bytes; key_used is added for Identify NUSE. value_next is the log-append
     * frontier; value_reclaimable is dead value bytes awaiting compaction. */
    uint8_t  *values;
    uint64_t value_capacity;           /* total namespace value bytes (NSZE-ish) */
    uint64_t value_next;               /* append frontier */
    uint64_t value_used;               /* live value bytes */
    uint64_t key_used;                 /* live key bytes */
    uint64_t value_reclaimable;        /* dead bytes (overwritten/deleted) */

    /* KV format (selected at format time) */
    uint32_t kv_key_max;               /* KVKML */
    uint32_t kv_value_max;             /* KVVML */
    uint64_t kv_max_keys;              /* MNKS, 0 = unlimited */

    /* Key Value Configuration feature (20h) */
    bool ednek;                        /* Error on Delete of Non-Existent KV Key */

    /* NAND timing engine: a full bbssd ssd (channels/LUNs/planes + allocator),
     * reused only for value-page placement + latency, not block L2P. */
    struct ssd *ssd;
    NvmeNamespace *ns;      /* the namespace this state serves */
    int pgsz;                          /* value page size in bytes */

    /*
     * kv_timing=model: Store and Retrieve take their time from the model of
     * the last KV_MODEL_WINDOW of them, not from the NAND model.
     */
    bool timing_model;
    FemuKvModel model;
    FemuKvWindow window;
    uint64_t model_floored;            /* commands raised to the kIOPS floor */

    /*
     * kv_index=lsm: the tree, and the table entries it has not handed out.
     * Merge I/O waits in lsm_pend until the command that caused it has
     * charged its own work. lsm_probe, lsm_gc and lsm_level[] are offsets
     * from lsm_stime; lsm_ready, lsm_mstart and lsm_mend are absolute ns.
     */
    KvLsm *lsm;
    uint32_t *free_slots;
    uint32_t nr_free;
    struct FemuKvLsmIo *lsm_pend;
    uint32_t lsm_npend;
    uint32_t lsm_pend_cap;
    int64_t lsm_stime;
    int64_t lsm_ready;                 /* merges start no earlier (ns) */
    int64_t lsm_mstart;                /* the run of merge I/O now issued */
    int64_t lsm_mend;                  /* the end of all merge I/O so far */
    int lsm_mkind;                     /* that run: 1 programs, 0 reads */
    uint64_t lsm_probe;
    uint64_t lsm_gc;
    uint64_t lsm_level[KV_LSM_MAX_LEVELS + 1];

    /* stats */
    uint64_t nand_rd_pages;
    uint64_t nand_wr_pages;
    uint64_t gc_wr_pages;

    QemuMutex lock;
} FemuKvssdState;

/*
 * Resolve the KV state a command addresses. Each KV namespace owns its own key
 * space and value store, so a command naming a namespace is answered by that
 * namespace's state; the controller's is only the fallback for admin paths that
 * name no namespace.
 */
FemuKvssdState *kvssd_ns_state(FemuCtrl *n, NvmeNamespace *ns);

/* A copy of the LSM index state, for query-femu */
typedef struct FemuKvLsmSnap {
    uint32_t memtable_keys;
    uint32_t memtable_cap;
    uint32_t ratio;
    uint32_t pinned;
    uint32_t per_page;
    uint64_t dram_bytes;
    uint64_t meta_flash_bytes;
    int depth;
    uint64_t records[KV_LSM_MAX_LEVELS];
    uint64_t capacity[KV_LSM_MAX_LEVELS];
    uint64_t pages[KV_LSM_MAX_LEVELS];
    uint64_t flushes;
    uint64_t compactions;
    uint64_t dropped;
    uint64_t reinserted;
    uint64_t io[KV_LSM_IO_NR];
} FemuKvLsmSnap;

/* fill @snap and return true when @s runs the LSM index */
bool kvssd_ftl_lsm_snap(FemuKvssdState *s, FemuKvLsmSnap *snap);

/* --- KV-FTL firmware (kvssd-ftl.c) --- */
FemuKvssdState *kvssd_ftl_alloc(FemuCtrl *n, NvmeNamespace *ns, Error **errp);
void kvssd_ftl_free(FemuKvssdState *s);
uint64_t kvssd_ftl_max_value(FemuKvssdState *s);
bool kvssd_ftl_exists(FemuKvssdState *s, const uint8_t *key, uint8_t kl);
uint16_t kvssd_ftl_exist(FemuCtrl *n, FemuKvssdState *s, NvmeRequest *req,
                         const uint8_t *key, uint8_t kl);
uint16_t kvssd_ftl_store(FemuCtrl *n, FemuKvssdState *s, NvmeRequest *req,
                         const uint8_t *key, uint8_t kl, uint32_t vsize,
                         bool sike, bool sinke);
uint16_t kvssd_ftl_retrieve(FemuCtrl *n, FemuKvssdState *s, NvmeRequest *req,
                            const uint8_t *key, uint8_t kl, uint32_t hbs,
                            uint32_t *full_len);
uint16_t kvssd_ftl_delete(FemuCtrl *n, FemuKvssdState *s, NvmeRequest *req,
                          const uint8_t *key, uint8_t kl, bool *deleted);
uint16_t kvssd_ftl_list(FemuCtrl *n, FemuKvssdState *s, NvmeRequest *req,
                        const uint8_t *start_key, uint8_t start_len,
                        uint32_t hbs);
void kvssd_ftl_selftest(FemuKvssdState *s);

/* --- KV admin (kvssd-admin.c): Identify CNS 05h/06h/0Ah, Feature 20h --- */
uint16_t kvssd_admin_cmd(FemuCtrl *n, NvmeCmd *cmd);

#ifndef FEMU_KVSSD_REGISTER_DECLARED
#define FEMU_KVSSD_REGISTER_DECLARED
#endif


/* admin-path handlers (hw/femu/kvssd/kvssd-admin.c) */
uint16_t kvssd_identify_ns_csi(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd);
uint16_t kvssd_identify_ctrl_csi(FemuCtrl *n, NvmeCmd *cmd);
uint16_t kvssd_identify_ns_csi_fmt(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd);
uint16_t kvssd_set_feature(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,                            NvmeCqe *cqe);
uint16_t kvssd_get_feature(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,                            NvmeCqe *cqe);

#endif
