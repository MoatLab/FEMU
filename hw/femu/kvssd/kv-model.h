/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * FEMU KV-SSD workload-mix timing model (kv_timing=model).
 */
#ifndef FEMU_KV_MODEL_H
#define FEMU_KV_MODEL_H

/* the cubic polynomial over (value size, insert, read, update) has 35 terms */
#define KV_MODEL_TERMS      35
/* the model sees the last this many Store and Retrieve commands */
#define KV_MODEL_WINDOW     16
/* above this mean value size the fit is not used: latency scales linearly */
#define KV_MODEL_MAX_VLEN   16384
/*
 * A lower or non-finite kIOPS is replaced by this, so the latency stays
 * finite and positive.
 */
#define KV_MODEL_MIN_KIOPS  0.01

typedef enum FemuKvOp {
    KV_OP_INSERT = 0,       /* Store of a key that did not exist */
    KV_OP_READ   = 1,       /* Retrieve that found the key */
    KV_OP_UPDATE = 2,       /* Store over an existing key */
    KV_OP_NR,
} FemuKvOp;

typedef struct FemuKvModel {
    double intercept;
    double coef[KV_MODEL_TERMS];
} FemuKvModel;

typedef struct FemuKvWindow {
    uint8_t  op[KV_MODEL_WINDOW];
    uint32_t vlen[KV_MODEL_WINDOW];
    uint32_t count[KV_OP_NR];
    uint64_t vlen_sum;
    uint32_t len;           /* entries in the window, at most KV_MODEL_WINDOW */
    uint32_t next;          /* the slot the next entry replaces */
} FemuKvWindow;

/* fill @m with the default coefficients (Samsung KVSSD PDK emulator) */
void kv_model_default(FemuKvModel *m);

/*
 * Parse @s, 1 + KV_MODEL_TERMS comma-separated numbers with the intercept
 * first, into @m. Return 0, or -1 with a static reason in @why.
 */
int kv_model_parse(const char *s, FemuKvModel *m, const char **why);

/* the model throughput in kIOPS; no clamp */
double kv_model_kiops(const FemuKvModel *m, double vlen, double insert,
                      double read, double update);

/* add one command to the window, dropping the oldest when it is full */
void kv_window_add(FemuKvWindow *w, FemuKvOp op, uint32_t vlen);

/*
 * The latency in ns of a command, from the window that already holds it.
 * @floored is set when the kIOPS was raised to KV_MODEL_MIN_KIOPS.
 */
uint64_t kv_model_latency_ns(const FemuKvModel *m, const FemuKvWindow *w,
                             bool *floored);

#endif
