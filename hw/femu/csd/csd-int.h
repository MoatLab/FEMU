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
};

static inline FemuCsdState *csd_state(FemuCtrl *n)
{
    return n->csd_ctrl_state;
}

#endif
