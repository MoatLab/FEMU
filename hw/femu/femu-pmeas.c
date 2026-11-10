/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Power Measurement (Base 2.3, 8.1.19.1) with power_meas=on: log page 25h
 * and feature 25h.
 *
 * The power is an estimate, so the log sets EPF. Each one-second interval
 * takes idle_mw plus the energy of the NAND plane operations the backends
 * booked in that interval (energy_*_nj), over the interval:
 *
 *   Set Features 25h, Start --> PMC 0, PMGN + 1, PME 1, 1 s timer
 *   each tick: P = idle_mw + booked nJ / interval --> PMC, average, maximum
 *   SMT minutes of intervals, or Set Features 25h, Stop --> PME 0, SMTS
 *
 * Energy is booked when the FTL books an operation, which can be before
 * the operation ends, so an interval can carry energy of the next one.
 * Intervals start on fixed one-second boundaries from Start. A tick that
 * fires after a boundary accounts each whole interval it passed, with the
 * energy of that time spread over them evenly. A sample clamps at
 * UINT32_MAX uW, far above the 655.35 W the log can report.
 * The timer runs on QEMU_CLOCK_VIRTUAL under the BQL: a paused VM adds no
 * interval, and a qtest steps the clock exactly. The state is the
 * controller's and is not cleared by a reset or a power cut; the log is
 * global to the NVM subsystem, so a subsystem with power_meas has one
 * controller. There is no histogram (NPHDS 0) and no Power Threshold
 * feature (24h).
 */

#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "qapi/error.h"
#include "exec/icount.h"
#include "nvme.h"

#define PM_LOG_SIZE     64
#define PM_ACT_STOP     0x0
#define PM_ACT_START    0x1

/**
 * femu_pmeas_check - validate power_meas at realize
 * @n: the controller
 * @errp: set on a refusal
 *
 * The energy sum must never go down, so the set of backends stays fixed
 * from realize to exit, as for the thermal model. The log must survive a
 * power cycle; with persist_file the data would cross QEMU runs while the
 * log would not, so persist_file is refused too.
 */
bool femu_pmeas_check(FemuCtrl *n, Error **errp)
{
    const char *why = NULL;

    if (!n->power_meas) {
        return true;
    }
    if (n->ns_mgmt || nvme_ns_shared(n)) {
        why = "namespace management or shared namespaces";
    } else if (n->cxl_dev) {
        why = "cxl_ssd";
    } else if (n->persist_file) {
        why = "persist_file";
    } else if (icount_enabled()) {
        why = "-icount";
    }
    if (why) {
        error_setg(errp, "femu: power_meas is not supported with %s", why);
        return false;
    }
    return true;
}

/* nJ of the plane operations booked since the last call */
static double femu_pmeas_energy_nj(FemuCtrl *n)
{
    const uint32_t price[3] = {
        n->energy_read_nj, n->energy_prog_nj, n->energy_erase_nj,
    };
    double e = 0;
    int i;
    int op;

    for (i = 0; i < n->namespace_limit; i++) {
        NvmeNamespace *ns = &n->namespaces[i];

        /* FDP namespaces share the first one's FTL: count it once */
        if (!ns->allocated || !ns->ssd || ns->ssd_shared ||
            !(NS_BBSSD(ns) || NS_CSD(ns) || NS_KVSSD(ns))) {
            continue;
        }
        for (op = 0; op < 3; op++) {
            uint64_t now = ssd_plane_ops(ns->ssd, op);
            uint64_t *last = &n->pm_ops[i * 3 + op];

            e += (double)(now - *last) * price[op];
            *last = now;
        }
    }
    return e;
}

static void femu_pmeas_end(FemuCtrl *n)
{
    n->pm_on = false;
    n->pm_smt = 0;
    n->pm_stop_ts = nvme_timestamp(n);
    timer_del(n->pm_timer);
}

/* one interval of @uw; true when SMT ends the collection with it */
static bool femu_pmeas_sample(FemuCtrl *n, uint64_t uw)
{
    if (n->pm_count < UINT32_MAX) {
        n->pm_count++;
    }
    /* each sample is below 2^32, so the sum holds 2^32 of them */
    if (n->pm_sum_uw <= UINT64_MAX - uw) {
        n->pm_sum_uw += uw;
        n->pm_samples++;
    }
    if (n->pm_samples == 1 || uw > n->pm_max_uw) {
        n->pm_max_uw = uw;
        n->pm_max_ts = nvme_timestamp(n);
    }
    return n->pm_smt && n->pm_count >= (uint32_t)n->pm_smt * 60;
}

static void femu_pmeas_tick(void *opaque)
{
    FemuCtrl *n = opaque;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    int64_t k;
    double uw;

    if (!n->pm_on) {
        return;
    }
    k = (now - n->pm_last_ns) / NANOSECONDS_PER_SECOND;
    if (k > 0) {
        /* nJ over one second is nW */
        uw = n->idle_mw * 1000.0 + femu_pmeas_energy_nj(n) / k / 1000.0;
        uw = MIN(uw, (double)UINT32_MAX);
        while (k--) {
            n->pm_last_ns += NANOSECONDS_PER_SECOND;
            if (femu_pmeas_sample(n, (uint64_t)uw)) {
                femu_pmeas_end(n);
                return;
            }
        }
    }
    /* stop at the end of the virtual clock rather than wrap */
    if (n->pm_last_ns > INT64_MAX - NANOSECONDS_PER_SECOND) {
        return;
    }
    timer_mod(n->pm_timer, n->pm_last_ns + NANOSECONDS_PER_SECOND);
}

/* at the end of realize; a later failure frees it through femu_exit() */
void femu_pmeas_start(FemuCtrl *n)
{
    if (!n->power_meas) {
        return;
    }
    n->pm_ops = g_new0(uint64_t, n->namespace_limit * 3);
    n->pm_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, femu_pmeas_tick, n);
}

/* the first step of exit, before the backends go */
void femu_pmeas_stop(FemuCtrl *n)
{
    if (n->pm_timer) {
        timer_free(n->pm_timer);
        n->pm_timer = NULL;
    }
    g_clear_pointer(&n->pm_ops, g_free);
}

/* the minutes left until an SMT stop, rounded up; 0 when none */
static uint16_t femu_pmeas_smtr(FemuCtrl *n)
{
    uint32_t left;

    if (!n->pm_on || !n->pm_smt) {
        return 0;
    }
    left = (uint32_t)n->pm_smt * 60 - n->pm_count;
    return DIV_ROUND_UP(left, 60);
}

/* Completion Dword 0 of Get and Set Features 25h (Figure 456) */
uint32_t femu_pmeas_get(FemuCtrl *n)
{
    return (uint32_t)femu_pmeas_smtr(n) << 16 | (uint32_t)n->pm_gen << 8 |
           n->pm_on;
}

/* Set Features 25h (Figure 454); CDW12 has no field for these actions */
uint16_t femu_pmeas_set(FemuCtrl *n, uint32_t dw11, uint32_t *result)
{
    uint8_t act = dw11 & 0xf;
    uint8_t pmts = (dw11 >> 4) & 0xf;
    int64_t now;

    switch (act) {
    case PM_ACT_STOP:
        if (n->pm_on) {
            femu_pmeas_end(n);
        }
        break;
    case PM_ACT_START:
        /* only the NVM subsystem total power (Figure 679) */
        if (pmts) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        femu_pmeas_energy_nj(n);
        n->pm_last_ns = now;
        n->pm_count = 0;
        n->pm_samples = 0;
        n->pm_sum_uw = 0;
        n->pm_max_uw = 0;
        n->pm_max_ts = 0;
        n->pm_on = true;
        n->pm_smt = dw11 >> 16;
        n->pm_gen++;
        if (now <= INT64_MAX - NANOSECONDS_PER_SECOND) {
            timer_mod(n->pm_timer, now + NANOSECONDS_PER_SECOND);
        }
        break;
    default:
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    *result = femu_pmeas_get(n);
    return NVME_SUCCESS;
}

/*
 * A power field of Figure 297: scale 01b (0.0001 W) while the value fits
 * in 16 bits, else 10b (0.01 W), saturated.
 */
static uint32_t femu_pmeas_power(uint64_t uw)
{
    uint64_t v = uw / 100;

    if (v <= UINT16_MAX) {
        return 1u << 16 | v;
    }
    return 2u << 16 | MIN(uw / 10000, UINT16_MAX);
}

/* Get Log Page 25h (Figure 297) */
uint16_t femu_pmeas_log(FemuCtrl *n, NvmeCmd *cmd, uint32_t buf_len,
                        uint64_t off)
{
    uint8_t page[PM_LOG_SIZE] = { 0 };
    uint16_t pma = 1 << 3 | 1 << 2 | n->pm_on;   /* MIPWRTS, EPF, PME */
    uint32_t nsid = le32_to_cpu(cmd->nsid);

    /* an NVM subsystem log: NSID 0 or FFFFFFFFh (5.2.12.1) */
    if ((nsid && nsid != NVME_NSID_BROADCAST) || off >= sizeof(page)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    page[1] = n->pm_gen;
    stw_le_p(page + 2, pma);
    stl_le_p(page + 4, sizeof(page));
    stl_le_p(page + 8, n->pm_count);
    stw_le_p(page + 14, femu_pmeas_smtr(n));
    stq_le_p(page + 16, n->pm_stop_ts);
    stw_le_p(page + 24, 8);
    stw_le_p(page + 26, 250);
    /* with PMC 0 the values are 0, in a scale Figure 681 defines */
    stl_le_p(page + 40, femu_pmeas_power(n->pm_samples ?
                                         n->pm_sum_uw / n->pm_samples : 0));
    stl_le_p(page + 44, femu_pmeas_power(n->pm_count ? n->pm_max_uw : 0));
    if (n->pm_count) {
        stq_le_p(page + 48, n->pm_max_ts);
    }
    page[56] = 255;
    return dma_read_prp(n, page + off, MIN(sizeof(page) - off, buf_len),
                        le64_to_cpu(cmd->dptr.prp1),
                        le64_to_cpu(cmd->dptr.prp2));
}
