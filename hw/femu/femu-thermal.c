/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * FEMU composite temperature from NAND power: a first-order thermal model.
 *
 * Power is idle_mw plus the energy of the plane operations the backends
 * counted since the last step (log page C0h's counters times energy_*_nj),
 * over the step. The package moves towards ambient + power * thermal_r with
 * time constant thermal_tau_ms. Every constant comes from the user; with
 * thermal_tau_ms at 0 the model is off and the temperature property is
 * reported as it is.
 *
 * The step runs on QEMU_CLOCK_VIRTUAL under the BQL, so a paused VM does not
 * cool and a qtest steps the model exactly. Energy that FEMU's own threads
 * add while the VM is paused goes into the first step after it.
 */

#include "qemu/osdep.h"
#include <math.h>
#include "qemu/atomic.h"
#include "qemu/error-report.h"
#include "qemu/timer.h"
#include "qapi/error.h"
#include "exec/icount.h"
#include "nvme.h"

#define THERMAL_STEP_MAX_MS 60000

/**
 * femu_thermal_check - validate the thermal properties at realize
 * @n: the controller
 * @errp: set on a refusal
 *
 * The energy sum must never go down, so the set of backends must stay fixed
 * from realize to exit: namespace management, shared namespaces and CXL
 * media are refused. Instruction counting runs the virtual clock off the
 * guest's instructions while NAND time follows the host, so it is refused too.
 */
bool femu_thermal_check(FemuCtrl *n, Error **errp)
{
    const char *why = NULL;

    n->throttle_pct_now = 100;
    n->thermal_pct = 100;
    n->ps_pct = 100;
    /*
     * The throttle stretches bbssd media (also under CSD). Other modes book
     * no energy or have no NAND timing to stretch, so they are refused.
     */
    if (n->throttle) {
        if (!n->thermal_tau_ms) {
            error_setg(errp, "femu: throttle needs thermal_tau_ms");
            return false;
        }
        if ((n->femu_mode != FEMU_BBSSD_MODE &&
             n->femu_mode != FEMU_CSD_MODE) || n->namespace_modes) {
            error_setg(errp, "femu: throttle works with bbssd or CSD "
                       "namespaces only");
            return false;
        }
        if (n->throttle_light_pct < 100 ||
            n->throttle_heavy_pct < n->throttle_light_pct ||
            n->throttle_heavy_pct > 1000) {
            error_setg(errp, "femu: throttle needs 100 <= throttle_light_pct "
                       "<= throttle_heavy_pct <= 1000");
            return false;
        }
        /* OCP TTHROTTLE-1: the temperature is checked once a second */
        if (n->ocp && n->thermal_step_ms > 1000) {
            error_setg(errp, "femu: ocp with throttle needs thermal_step_ms "
                       "of 1000 or less");
            return false;
        }
    } else if (n->hot_k) {
        error_setg(errp, "femu: hot_k needs throttle=on");
        return false;
    }

    if (!n->thermal_tau_ms) {
        if (n->thermal_r || (n->idle_mw && !n->power_meas)) {
            warn_report("femu: thermal_r and idle_mw have no effect unless "
                        "thermal_tau_ms is set");
        }
        return true;
    }
    if (!n->thermal_r) {
        error_setg(errp, "femu: thermal_tau_ms needs thermal_r");
        return false;
    }
    if (!n->thermal_step_ms || n->thermal_step_ms > THERMAL_STEP_MAX_MS) {
        error_setg(errp, "femu: thermal_step_ms must be 1 to %d, got %u",
                   THERMAL_STEP_MAX_MS, n->thermal_step_ms);
        return false;
    }
    if (n->ns_mgmt || nvme_ns_shared(n)) {
        why = "namespace management or shared namespaces";
    } else if (n->cxl_dev) {
        why = "cxl_ssd";
    } else if (icount_enabled()) {
        why = "-icount";
    }
    if (why) {
        error_setg(errp, "femu: thermal_tau_ms is not supported with %s", why);
        return false;
    }
    return true;
}

/*
 * At or over the over threshold, at or under the under threshold, or, with
 * ocp, in autonomous protection (OCP TTHROTTLE-2 and -7 tie the warning to
 * the throttle).
 */
bool femu_temp_condition(FemuCtrl *n)
{
    return n->features.temp_thresh <= n->temperature ||
           n->temperature <= n->features.temp_thresh_under ||
           (n->ocp && n->auto_hot);
}

/*
 * The temperature condition starting is a controller-initiated telemetry
 * trigger, whatever events the host enabled.
 */
void femu_tel_temp_edge(FemuCtrl *n)
{
    bool cond = femu_temp_condition(n);

    if (cond && !n->tel_temp_prev) {
        femu_tel_capture(n, FEMU_TEL_TEMPERATURE);
    }
    n->tel_temp_prev = cond;
}

/* HCTMA: the throttle is on, so feature 10h has an effect */
bool femu_hctm_supported(FemuCtrl *n)
{
    return n->throttle;
}

/* add @ns of virtual time to the HCTM level that ran, saturating */
static void hctm_account(FemuCtrl *n, int64_t ns)
{
    int l = n->hctm_level - 1;
    uint64_t ms;

    if (l < 0 || ns <= 0) {
        return;
    }
    n->hctm_rem_ns[l] += ns;
    ms = n->hctm_rem_ns[l] / SCALE_MS;
    n->hctm_rem_ns[l] %= SCALE_MS;
    n->hctm_ms[l] = MIN(n->hctm_ms[l] + ms, (uint64_t)UINT32_MAX * 1000);
}

/**
 * femu_throttle_eval - recompute the throttle level from the temperature
 * @n: the controller
 *
 *   HCTM:  light at TMT1, heavy at TMT2 (0 = that level off)
 *   autonomous: enter at hot_k (350 K with ocp), leave below hot_k - 2 K
 *   actuator: the stronger of the two; autonomous counts as heavy
 *
 * Called from the thermal step, from Set Features 10h and from a reset,
 * all under the BQL. Only HCTM levels count in SMART bytes 216 to 231.
 */
void femu_throttle_eval(FemuCtrl *n)
{
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    uint16_t t = n->temperature;
    uint16_t hot = n->ocp ? 350 : n->hot_k;
    uint8_t hl = 0;
    uint8_t level;
    bool was_hot = n->auto_hot;

    if (!n->throttle) {
        return;
    }
    if (n->hctm_tmt2 && t >= n->hctm_tmt2) {
        hl = 2;
    } else if (n->hctm_tmt1 && t >= n->hctm_tmt1) {
        hl = 1;
    }
    hctm_account(n, now - n->hctm_since_ns);
    n->hctm_since_ns = now;
    if (hl && hl != n->hctm_level && n->hctm_count[hl - 1] != UINT32_MAX) {
        n->hctm_count[hl - 1]++;
    }
    n->hctm_level = hl;

    if (hot) {
        n->auto_hot = n->auto_hot ? t >= hot - 2 : t >= hot;
    } else {
        n->auto_hot = false;
    }
    if (!was_hot && n->auto_hot) {
        femu_tel_capture(n, FEMU_TEL_PROTECTION);
    }
    level = n->auto_hot ? 2 : hl;
    /* OCP C0h byte 96 counts episodes, from none to any level */
    if (level && !n->throttle_level && n->ocp_throttle_events != UINT8_MAX) {
        n->ocp_throttle_events++;
    }
    n->throttle_level = level;
    qemu_mutex_lock(&n->ps_lock);
    n->thermal_pct = level == 2 ? n->throttle_heavy_pct :
                     level == 1 ? n->throttle_light_pct : 100;
    qemu_mutex_unlock(&n->ps_lock);
    femu_actuator_set(n);

    /*
     * With ocp, entering and leaving protection each send the temperature
     * event (TTHROTTLE-2, -7), apart from Feature 04h. A copy still queued
     * with the same content is not added twice.
     */
    if (n->ocp && was_hot != n->auto_hot &&
        (NVME_AEC_SMART(n->features.async_config) & NVME_SMART_TEMPERATURE)) {
        nvme_enqueue_event(n, NVME_AER_TYPE_SMART,
                           NVME_AER_INFO_SMART_TEMP_THRESH,
                           NVME_LOG_SMART_INFO);
    }
}

/**
 * femu_temp_eval - report a temperature condition that has just started
 * @n: the controller
 *
 * The event log gets the condition every time and records it when its bit
 * comes on, so it stays right after a reset clears its copy. The host gets
 * one SMART temperature event each time the condition starts while it has
 * those events enabled, including when it enables them during an
 * excursion; the existing mask holds further SMART events until it reads the
 * log, and that read drops any queued behind it.
 */
void femu_temp_eval(FemuCtrl *n)
{
    bool cond = femu_temp_condition(n);
    bool aec = NVME_AEC_SMART(n->features.async_config) &
               NVME_SMART_TEMPERATURE;

    femu_pel_temp_warning(n, cond);
    femu_tel_temp_edge(n);
    if (cond && aec && !n->temp_cond_prev) {
        nvme_enqueue_event(n, NVME_AER_TYPE_SMART,
                           NVME_AER_INFO_SMART_TEMP_THRESH,
                           NVME_LOG_SMART_INFO);
    }
    n->temp_cond_prev = cond && aec;
}

/* nJ of the plane operations counted since the last step */
static double femu_thermal_energy_nj(FemuCtrl *n)
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
            uint64_t *last = &n->thermal_ops[i * 3 + op];

            e += (double)(now - *last) * price[op];
            *last = now;
        }
    }
    return e;
}

static void femu_thermal_tick(void *opaque)
{
    FemuCtrl *n = opaque;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    int64_t step = (int64_t)n->thermal_step_ms * SCALE_MS;
    int64_t dt = now - n->thermal_last_ns;

    if (dt > 0) {
        double p_mw = n->idle_mw + 1000.0 * femu_thermal_energy_nj(n) / dt;
        double t_ss = n->thermal_ambient + p_mw * n->thermal_r / 1000.0;
        double t = n->thermal_t + (t_ss - n->thermal_t) *
                   -expm1(-(double)dt / ((double)n->thermal_tau_ms * SCALE_MS));

        if (isfinite(t)) {
            n->thermal_t = t;
            n->temperature = (uint16_t)lround(MIN(MAX(t, 0.0), 65535.0));
            n->ocp_max_temp_k = MAX(n->ocp_max_temp_k, n->temperature);
        }
        n->thermal_last_ns = now;
        femu_throttle_eval(n);
        femu_temp_eval(n);
    }

    /* stop at the end of the virtual clock rather than wrap */
    if (now > INT64_MAX - step || n->thermal_deadline > INT64_MAX - step) {
        return;
    }
    n->thermal_deadline += step;
    if (n->thermal_deadline <= now) {
        n->thermal_deadline = now + step;
    }
    timer_mod(n->thermal_timer, n->thermal_deadline);
}

/* start the model; the last step of realize, so nothing after it can fail */
void femu_thermal_start(FemuCtrl *n)
{
    int i;
    int op;

    if (!n->thermal_tau_ms) {
        return;
    }
    n->thermal_ambient = n->temperature;
    n->thermal_t = n->temperature;
    n->hctm_since_ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    n->thermal_ops = g_new0(uint64_t, n->namespace_limit * 3);
    for (i = 0; i < n->namespace_limit; i++) {
        NvmeNamespace *ns = &n->namespaces[i];

        if (ns->allocated && ns->ssd) {
            for (op = 0; op < 3; op++) {
                n->thermal_ops[i * 3 + op] = ssd_plane_ops(ns->ssd, op);
            }
        }
    }
    n->thermal_last_ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    n->thermal_deadline = n->thermal_last_ns +
                          (int64_t)n->thermal_step_ms * SCALE_MS;
    n->thermal_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, femu_thermal_tick, n);
    timer_mod(n->thermal_timer, n->thermal_deadline);
}

/* stop the model; the first step of exit, before the backends go */
void femu_thermal_stop(FemuCtrl *n)
{
    if (n->thermal_timer) {
        timer_free(n->thermal_timer);
        n->thermal_timer = NULL;
    }
    g_free(n->thermal_ops);
    n->thermal_ops = NULL;
}
