/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * The state of CSD mode, shared by the files that serve its commands.
 */
#ifndef FEMU_CSD_INT_H
#define FEMU_CSD_INT_H

#include <gmodule.h>
#include "csd.h"

#ifdef CONFIG_FEMU_CSD_UBPF
#include <ubpf.h>
#endif

typedef int64_t (*FemuCsdSharedLibFn)(FemuCsdArgs *args);

#define CSD_EXEC_DATA_MAX (1U << 20)

/*
 * A program is held whole in host memory while it loads, and the load command
 * carries its size in a 32-bit field, so an unbounded one lets the guest ask
 * for four gigabytes per program index and there are 65535 of those. Cap what
 * one program may be and what all of them together may be.
 */
#define CSD_PROGRAM_MAX (16U << 20)
#define CSD_PROGRAM_TOTAL_MAX (64U << 20)

/*
 * Computational Programs (CP 1.2) and Subsystem Local Memory (SLM 1.2) limits.
 * Program indexes 0 and 1 hold the device-defined programs; the rest take
 * downloads. A Memory Range Set holds at most 128 ranges (CP 4.2.2).
 */
#define CSD_CP_NPIND        16
#define CSD_CP_NBUILTIN     2
#define CSD_CP_MAXMEMRS     64
#define CSD_CP_MAXMEMR      128
#define CSD_CP_ALL          0xffff
#define CSD_SLM_MAX_MB      1024
#define CSD_SLM_COPY_MAX    (1U << 20)
#define CSD_SLM_COPY_MSRC   127

/* what a program runs; the CEMU kinds use the CEMU program type values */
enum {
    CSD_KIND_CP_COPY    = 0x80,
    CSD_KIND_CP_FNV64   = 0x81,
};

typedef struct FemuCsdState FemuCsdState;

/*
 * Device memory and programs are counted references: the table holds one, and
 * each Execute in flight holds one per range or program it uses, so freeing
 * one does not pull it out from under a program still running on it. The
 * quota they count against is given back only when the last one goes.
 */
typedef struct FemuCsdAfdm {
    uint32_t id;
    uint32_t refs;
    uint64_t size;
    uint8_t *data;
    FemuCsdState *csd;
} FemuCsdAfdm;

typedef struct FemuCsdProgram {
    uint32_t id;
    uint32_t refs;
    FemuCsdState *csd;
    /* running on a compute unit; runs of one program take turns */
    bool busy;
    QSLIST_ENTRY(FemuCsdProgram) dead;
    uint8_t type;
    bool active;
    bool indirect;
    bool loading;
    uint32_t runtime;
    uint16_t runtime_scale;
    uint64_t size;
    uint64_t load_size;
    uint64_t pid;
    uint8_t *data;
    GModule *module;
    FemuCsdSharedLibFn shared_lib_fn;
#ifdef CONFIG_FEMU_CSD_UBPF
    struct ubpf_vm *ubpf_vm;
    ubpf_jit_fn ubpf_jit_fn;
#endif
    /* a program of the compute namespace rather than a CEMU one */
    bool cp;
    bool builtin;
    uint8_t ptype;              /* the PTYPE the host loaded it as */
    uint8_t pit;
    uint32_t use;               /* Executes not yet completed to the host */
    unsigned long *loaded;      /* dwords received while loading */
    uint64_t nloaded;
} FemuCsdProgram;

typedef struct FemuCsdGroup {
    uint32_t id;
    int8_t prio;
    uint8_t qos_flags;
    uint32_t bandwidth;
    uint32_t deadline;
} FemuCsdGroup;

typedef struct FemuCsdMrs {
    uint16_t rsid;
    uint32_t numr;
    NvmeCsdMemoryRange *ranges;
} FemuCsdMrs;

/* a Memory Range Set of the compute namespace (CP 2.1.2.1) */
typedef struct FemuCsdCpMrs {
    uint16_t rsid;
    uint32_t numr;
    NvmeCsdMemoryRange *ranges;
    uint32_t use;               /* Executes not yet completed to the host */
} FemuCsdCpMrs;

/* an Execute handed from the poller to a compute unit thread */
typedef struct FemuCsdJob {
    NvmeRequest *req;           /* NULL once its submission queue is gone */
    int poller;                 /* whose completion ring it goes back on */
    int64_t arrival;
    uint64_t runtime;
    int64_t reserved_end;       /* compute unit hold taken at submission */
    FemuCsdProgram *program;
    FemuCsdAfdm **afdms;
    FemuCsdArgs args;
    uint8_t *data;
    QTAILQ_ENTRY(FemuCsdJob) entry;
    /*
     * An Execute on the compute namespace. The program runs on scratch copies
     * of its memory ranges, which are written back to the memory namespace
     * only if the command is still outstanding when the program returns.
     */
    bool cp;
    uint32_t cp_numr;
    uint64_t *cp_sb;
    uint32_t *cp_len;
    uint8_t *cp_scratch;        /* the ranges, then a snapshot of them */
    uint64_t cp_total;
} FemuCsdJob;

struct FemuCsdState {
    FemuCtrl *n;
    CsdCtrlParams params;
    uint64_t fdm_capacity;
    uint64_t fdm_used;
    uint64_t prog_used;         /* bytes held by loaded programs */
    uint32_t next_afdm_id;
    uint32_t next_group_id;
    uint32_t next_rsid;
    GHashTable *afdms;
    GHashTable *programs;
    GHashTable *groups;
    GHashTable *mrs;
    QemuMutex lock;
    uint64_t *cu_next_avail;    /* when each compute unit is free again */
    QemuThread *workers;        /* one per compute unit */
    QemuCond job_cond;
    QTAILQ_HEAD(, FemuCsdJob) pending;
    QTAILQ_HEAD(, FemuCsdJob) running;
    /* programs whose last reference went, destroyed by a worker unlocked */
    QSLIST_HEAD(, FemuCsdProgram) dead;
    bool stopping;
    bool overrun_warned;

    /*
     * The memory and compute namespaces. slm_lock serializes every access to
     * the memory, so each SLM command is atomic as a whole; it nests inside
     * lock.
     */
    uint8_t *slm;
    uint64_t slm_size;
    uint32_t slm_nsid;
    uint32_t cp_nsid;
    QemuMutex slm_lock;
    FemuCsdProgram *cp_prog[CSD_CP_NPIND];
    GHashTable *cp_mrs;
    uint16_t cp_next_rsid;
    uint64_t cp_prog_used;      /* bytes held by downloaded CP programs */
};

static inline FemuCsdState *csd_state(FemuCtrl *n)
{
    return n->csd_ctrl_state;
}

/* csd.c */
void csd_program_unref(gpointer opaque);
uint16_t csd_load_program_data(FemuCtrl *n, FemuCsdProgram *program, bool jit);
void csd_exec_defer(FemuCtrl *n, NvmeRequest *req, int poller);

/* cp-slm.c */
void csd_cp_slm_init(FemuCtrl *n, FemuCsdState *csd, NvmeNamespace *ns,
                     uint8_t *slm);
void csd_cp_slm_exit(FemuCsdState *csd);
uint16_t csd_slm_io_cmd(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                        NvmeRequest *req);
uint16_t csd_cp_io_cmd(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                       NvmeRequest *req);
uint16_t csd_cp_admin_cmd(FemuCtrl *n, NvmeCmd *cmd, NvmeCqe *cqe);
uint16_t csd_cp_get_log(FemuCtrl *n, NvmeCmd *cmd);
uint16_t csd_cp_job_prepare(FemuCsdState *csd, FemuCsdJob *job);
void csd_cp_job_commit_locked(FemuCsdState *csd, FemuCsdJob *job);
uint16_t csd_cp_run_builtin(FemuCsdProgram *program, FemuCsdArgs *args,
                            int64_t *result);

#endif
