/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Power states (Base 2.3, 8.1.18) with power_states=on: four states, the
 * Power Management feature (02h) and Autonomous Power State Transition
 * (0Ch).
 *
 *  PS  MP (of PS0)  NOPS  ENLAT   EXLAT   NAND array time
 *  0   100 %        0     16 us   4 us    x 1
 *  1    60 %        0     50 us   50 us   x throttle_light_pct
 *  2    35 %        0     100 us  100 us  x throttle_heavy_pct
 *  3   0.05 W       1     2 ms    5 ms    no I/O
 *
 * PS1 and PS2 slow the media the way the thermal throttle does: the media
 * layer stretches the array time by the larger of the two factors. Their
 * Maximum Power figures are nominal; FEMU does not meter watts against
 * them. PS3 runs no I/O: an I/O command wakes the controller, and every
 * command fetched before the wake ends waits for it. Idle GC and the
 * thermal model do not look at the state.
 *
 * With power_limit=on, feature 23h prohibits the states whose MP is above
 * the limit (8.1.18.6). MP falls with the state number, so they are the
 * first pl_drop states, and the host numbers the rest from 0:
 *
 *   physical  0    1    2    3          drop 1:  host 0 = physical 1
 *   MP        100% 60%  35%  0.05 W     drop 2:  host 0 = physical 2
 *
 * ps_cur, ps_op and the APST table stay physical; feature 02h, feature
 * 0Ch and Identify convert. A limit below every operational MP is refused.
 * The MP figures stay nominal: the limit restricts the states, not the
 * energy the thermal model or log 25h counts.
 *
 * The state moves forward when it is read, not on a timer. Idle time runs
 * from the later of the last I/O fetch and the end of the work the FTL
 * booked. Open gap: a request still queued for the FTL, or held for a full
 * CQ, does not count as busy.
 */

#include "./nvme.h"
#include "trace.h"

#define FEMU_NPSS           3
#define FEMU_PS_NONOP       3
#define FEMU_PL_DEFAULT     (2u << 16)      /* PLS 10b (0.01 W), no limit */

static const struct {
    uint8_t mp_pct;         /* of PS0, for the operational states */
    uint32_t enlat_us;
    uint32_t exlat_us;
    uint8_t rel;            /* RRT, RRL, RWT, RWL */
} femu_ps[FEMU_NPSS + 1] = {
    { 100, 16, 4, 0 },
    { 60, 50, 50, 1 },
    { 35, 100, 100, 2 },
    { 0, 2000, 5000, 3 },
};

bool femu_power_check(FemuCtrl *n, Error **errp)
{
    n->thermal_pct = 100;
    n->ps_pct = 100;
    if (n->power_limit && !n->power_states) {
        error_setg(errp, "power_limit needs power_states");
        return false;
    }
    if (!n->power_states) {
        return true;
    }
    if (n->ocp) {
        error_setg(errp, "power_states does not work with ocp yet (OCP C7h "
                   "maps DSSD power states to PS0)");
        return false;
    }
    /* shared media would take one controller's factor for all */
    if (n->subsys) {
        error_setg(errp, "power_states does not work with a femu-subsys yet");
        return false;
    }
    if ((n->femu_mode != FEMU_BBSSD_MODE && n->femu_mode != FEMU_CSD_MODE) ||
        n->namespace_modes) {
        error_setg(errp, "power_states works with bbssd or CSD namespaces "
                   "only");
        return false;
    }
    if (n->throttle_light_pct < 100 ||
        n->throttle_heavy_pct < n->throttle_light_pct ||
        n->throttle_heavy_pct > 1000) {
        error_setg(errp, "power_states needs 100 <= throttle_light_pct <= "
                   "throttle_heavy_pct <= 1000");
        return false;
    }
    n->pl_cur = FEMU_PL_DEFAULT;
    n->pl_saved = FEMU_PL_DEFAULT;
    /* the saved limit lives in memory only */
    if (n->power_limit && n->persist_file) {
        error_setg(errp, "power_limit is not supported with persist_file");
        return false;
    }
    return true;
}

/* MP of physical state @i, in 0.01 W */
static uint32_t femu_ps_mp(FemuCtrl *n, int i)
{
    return i == FEMU_PS_NONOP ? 5 : n->ps_max_watts * femu_ps[i].mp_pct;
}

/*
 * The states a limit of CDW13 @dw13 prohibits: those whose MP is above
 * it. FEMU_PS_NONOP means it prohibits every operational state.
 */
static uint8_t femu_pl_drop(FemuCtrl *n, uint32_t dw13)
{
    uint32_t plv = dw13 & 0xffff;
    uint64_t lim = (uint64_t)plv * (((dw13 >> 16) & 0x3) == 1 ? 1 : 100);
    uint8_t d = 0;

    if (!plv) {
        return 0;
    }
    /* both sides in 0.0001 W */
    while (d < FEMU_PS_NONOP && (uint64_t)femu_ps_mp(n, d) * 100 > lim) {
        d++;
    }
    return d;
}

/*
 * The descriptors of Identify Controller, APSTA, NPSS: the states the
 * limit allows, renumbered from 0, and zero slots after them. Rebuilt
 * under the BQL when the limit changes.
 */
void femu_power_id(FemuCtrl *n, NvmeIdCtrl *id)
{
    uint8_t d = n->pl_drop;

    if (!n->power_states) {
        return;
    }
    id->npss = FEMU_NPSS - d;
    id->apsta = 1;
    memset(id->psd, 0, sizeof(id->psd));
    for (int i = d; i <= FEMU_NPSS; i++) {
        NvmePSD psd = { 0 };
        /* relative ranks stay below the number of states */
        uint8_t rel = femu_ps[i].rel - d;

        /* MXPS 0: 0.01 W units; PS3 draws 0.05 W */
        psd.mp = cpu_to_le16(femu_ps_mp(n, i));
        psd.enlat = cpu_to_le32(femu_ps[i].enlat_us);
        psd.exlat = cpu_to_le32(femu_ps[i].exlat_us);
        psd.rrt = rel;
        psd.rrl = rel;
        psd.rwt = rel;
        psd.rwl = rel;
        /* byte 3 bit 1: NOPS */
        psd.reserved = cpu_to_le16(i == FEMU_PS_NONOP ? 1 << 9 : 0);
        id->psd[i - d] = psd;
    }
    if (n->power_limit) {
        id->ctratt |= cpu_to_le32(NVME_CTRATT_PLS);
        /* MUPS 10b: MUP in 0.01 W, the MP of PS0 with no limit */
        id->mups = 2;
        id->mup = cpu_to_le16(femu_ps_mp(n, 0));
    }
}

/* the media factor: the larger of the thermal level and the power state */
static void femu_actuator_set_locked(FemuCtrl *n)
{
    qatomic_set(&n->throttle_pct_now, MAX(n->thermal_pct, n->ps_pct));
}

/* the thermal policy changed its factor (BQL; ps_lock orders the two) */
void femu_actuator_set(FemuCtrl *n)
{
    qemu_mutex_lock(&n->ps_lock);
    femu_actuator_set_locked(n);
    qemu_mutex_unlock(&n->ps_lock);
}

static uint32_t femu_ps_factor(FemuCtrl *n, uint8_t ps)
{
    return ps == 1 ? n->throttle_light_pct :
           ps == 2 ? n->throttle_heavy_pct : 100;
}

/*
 * Move the state forward to @now (ps_lock held). Idle time starts when the
 * controller last had work: the later of the last I/O fetch and the end
 * of the modelled work it booked. Each APST step waits ITPT in the state
 * it leaves; a step to the same state ends the walk.
 */
static void femu_power_advance(FemuCtrl *n, int64_t now)
{
    int64_t base = MAX(n->ps_entered, MAX(n->ps_last_io,
                                          qatomic_read(&n->ps_busy_until)));

    /* a sanitize in progress suspends autonomous transitions (8.1.26.5) */
    if (nvme_sanitize_busy(n) || femu_sanns_busy(n)) {
        return;
    }

    for (int hops = 0; n->apste && hops <= FEMU_NPSS; hops++) {
        uint64_t e = n->apst[n->ps_cur];
        int64_t itpt = (int64_t)((e >> 8) & 0xffffff) * SCALE_MS;
        uint8_t itps = (e >> 3) & 0x1f;

        if (!itpt || itps == n->ps_cur || now - base < itpt) {
            break;
        }
        base += itpt;
        trace_femu_power_state(n->ps_cur, itps);
        n->ps_cur = itps;
        n->ps_entered = base;
    }
}

static void femu_power_enter(FemuCtrl *n, uint8_t ps, int64_t now)
{
    trace_femu_power_state(n->ps_cur, ps);
    n->ps_cur = ps;
    n->ps_entered = now;
    if (ps != FEMU_PS_NONOP) {
        n->ps_op = ps;
        n->ps_pct = femu_ps_factor(n, ps);
        femu_actuator_set_locked(n);
    }
}

/*
 * An I/O command fetched at @now. In PS3 the controller returns to its last
 * operational state, which takes EXLAT. Every command fetched before that
 * ends waits for it too. Returns how long the command waits, in ns.
 */
int64_t femu_power_io(FemuCtrl *n, int64_t now)
{
    int64_t wait;

    qemu_mutex_lock(&n->ps_lock);
    femu_power_advance(n, now);
    if (n->ps_cur == FEMU_PS_NONOP) {
        n->ps_ready_at = MAX(n->ps_ready_at,
                             now + (int64_t)femu_ps[FEMU_PS_NONOP].exlat_us *
                                   SCALE_US);
        /* the last operational state, if the limit allows it */
        femu_power_enter(n, MAX(n->ps_op, n->pl_drop), now);
    }
    n->ps_last_io = now;
    wait = MAX(n->ps_ready_at - now, 0);
    qemu_mutex_unlock(&n->ps_lock);
    return wait;
}

/* the FTL booked work for a request that ends at @end */
void femu_power_busy(FemuCtrl *n, int64_t end)
{
    int64_t cur = qatomic_read(&n->ps_busy_until);

    while (end > cur) {
        int64_t seen = qatomic_cmpxchg(&n->ps_busy_until, cur, end);

        if (seen == cur) {
            break;
        }
        cur = seen;
    }
}

/*
 * Set Features 02h: the controller is in host state @ps when the command
 * completes. Leaving PS3 for an operational state takes PS3's exit
 * latency.
 */
void femu_power_set(FemuCtrl *n, uint8_t ps)
{
    int64_t now;

    if (!n->power_states) {
        return;
    }
    now = femu_io_now(n);
    qemu_mutex_lock(&n->ps_lock);
    ps += n->pl_drop;
    femu_power_advance(n, now);
    if (n->ps_cur == FEMU_PS_NONOP && ps != FEMU_PS_NONOP) {
        n->ps_ready_at = MAX(n->ps_ready_at,
                             now + (int64_t)femu_ps[FEMU_PS_NONOP].exlat_us *
                                   SCALE_US);
    }
    femu_power_enter(n, ps, now);
    qemu_mutex_unlock(&n->ps_lock);
}

/* Get Features 02h: the state now, with the workload hint the host set */
uint32_t femu_power_get(FemuCtrl *n)
{
    uint32_t wh = n->features.power_mgmt & 0xe0;
    uint8_t ps;

    if (!n->power_states) {
        return n->features.power_mgmt;
    }
    qemu_mutex_lock(&n->ps_lock);
    femu_power_advance(n, femu_io_now(n));
    ps = n->ps_cur - n->pl_drop;
    qemu_mutex_unlock(&n->ps_lock);
    return wh | ps;
}

/* an APST entry with its ITPS moved by @shift states */
static uint64_t femu_apst_shift(uint64_t e, int shift)
{
    uint8_t itps = (e >> 3) & 0x1f;

    if (!e) {
        return 0;
    }
    return (e & ~(0x1full << 3)) | (uint64_t)((itps + shift) & 0x1f) << 3;
}

/*
 * The table under a limit of @d prohibited states (8.1.18.6.1 steps 3, 5
 * and 8): their rows are cleared, and an ITPS that names one of them
 * names the new PS0.
 */
static void femu_apst_cut(uint64_t *t, uint8_t d)
{
    for (int i = 0; i < 32; i++) {
        uint8_t itps = (t[i] >> 3) & 0x1f;

        if (i < d) {
            t[i] = 0;
        } else if (t[i] && itps < d) {
            t[i] = femu_apst_shift(t[i], d - itps);
        }
    }
}

/*
 * Feature 0Ch (5.2.26.1.6): APSTE in CDW11 bit 0, 32 entries of ITPT
 * (bits 31:8, ms) and ITPS (bits 7:3), in host state numbers. An entry
 * with ITPT set must name the non-operational state; otherwise the
 * command fails and nothing changes. The table is kept by physical state.
 */
uint16_t femu_apst_set(FemuCtrl *n, NvmeCmd *cmd)
{
    uint8_t d = n->pl_drop;     /* changes under the BQL only */
    uint64_t tbl[32];
    uint16_t status;

    status = dma_write_prp(n, (uint8_t *)tbl, sizeof(tbl),
                           le64_to_cpu(cmd->dptr.prp1),
                           le64_to_cpu(cmd->dptr.prp2));
    if (status) {
        return status;
    }
    for (int i = 0; i < 32; i++) {
        uint64_t e = le64_to_cpu(tbl[i]);
        uint8_t itps = (e >> 3) & 0x1f;

        /* unused entries are zero; a timed entry names a non-op state */
        if ((i > FEMU_NPSS - d && e) ||
            ((e >> 8) & 0xffffff && itps != FEMU_PS_NONOP - d)) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
    }
    /* the state reached so far stays; the new table counts from now */
    qemu_mutex_lock(&n->ps_lock);
    femu_power_advance(n, femu_io_now(n));
    memset(n->apst, 0, sizeof(n->apst));
    for (int i = 0; i + d < 32; i++) {
        n->apst[i + d] = femu_apst_shift(le64_to_cpu(tbl[i]), d);
    }
    n->ps_entered = femu_io_now(n);
    n->apste = le32_to_cpu(cmd->cdw11) & 0x1;
    qemu_mutex_unlock(&n->ps_lock);
    return NVME_SUCCESS;
}

uint16_t femu_apst_get(FemuCtrl *n, NvmeCmd *cmd, bool dflt, uint32_t *res)
{
    uint64_t tbl[32] = { 0 };

    qemu_mutex_lock(&n->ps_lock);
    *res = dflt ? 0 : n->apste;
    for (int i = 0; i + n->pl_drop < 32 && !dflt; i++) {
        tbl[i] = cpu_to_le64(femu_apst_shift(n->apst[i + n->pl_drop],
                                             -n->pl_drop));
    }
    qemu_mutex_unlock(&n->ps_lock);
    return dma_read_prp(n, (uint8_t *)tbl, sizeof(tbl),
                        le64_to_cpu(cmd->dptr.prp1),
                        le64_to_cpu(cmd->dptr.prp2));
}

/*
 * A Controller Level Reset (also at a power cut): APST off and its table
 * cleared; feature 23h takes its saved value, and the controller enters
 * the first state that limit allows (host PS0).
 */
void femu_power_reset(FemuCtrl *n)
{
    if (!n->power_states) {
        return;
    }
    qemu_mutex_lock(&n->ps_lock);
    n->apste = false;
    memset(n->apst, 0, sizeof(n->apst));
    memset(n->apst_base, 0, sizeof(n->apst_base));
    n->pl_cur = n->pl_saved;
    n->pl_drop = femu_pl_drop(n, n->pl_cur);
    n->ps_ready_at = 0;
    n->ps_last_io = 0;
    qatomic_set(&n->ps_busy_until, 0);
    femu_power_enter(n, n->pl_drop, femu_io_now(n));
    qemu_mutex_unlock(&n->ps_lock);
    femu_power_id(n, &n->id_ctrl);
}

/*
 * Move to @d1 prohibited states (8.1.18.6), ps_lock held. More states
 * prohibited: keep the unlimited APST table the first time, cut the
 * table, and leave a prohibited state for the new PS0. Fewer: restore
 * that table and cut it again for what stays prohibited (8.1.18.6.2).
 * The state the controller is in stays; only its number changes.
 */
static void femu_pl_apply_locked(FemuCtrl *n, uint8_t d1, int64_t now)
{
    uint8_t d0 = n->pl_drop;

    if (d1 == d0) {
        return;
    }
    if (d1 > d0) {
        if (!d0) {
            memcpy(n->apst_base, n->apst, sizeof(n->apst));
        }
        femu_apst_cut(n->apst, d1);
    } else {
        memcpy(n->apst, n->apst_base, sizeof(n->apst));
        femu_apst_cut(n->apst, d1);
    }
    n->pl_drop = d1;
    if (n->ps_cur < d1) {
        femu_power_enter(n, d1, now);
    } else if (n->ps_cur == FEMU_PS_NONOP) {
        /* asleep: background media work runs at the wake target's speed */
        n->ps_pct = femu_ps_factor(n, MAX(n->ps_op, d1));
        femu_actuator_set_locked(n);
    }
}

/*
 * Set Features 23h (Figure 452): PLS in CDW13 bits 17:16, PLV in 15:0.
 * PLV 0 removes the limit. A limit below the MP of every operational
 * state fails with Invalid Power Limit and changes nothing.
 */
uint16_t femu_pl_set(FemuCtrl *n, uint32_t dw13, bool save)
{
    uint8_t pls = (dw13 >> 16) & 0x3;
    uint8_t d;

    if (pls == 0 || pls == 3) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    dw13 &= 0x3ffff;
    d = femu_pl_drop(n, dw13);
    if (d >= FEMU_PS_NONOP) {
        return NVME_INVALID_POWER_LIMIT | NVME_DNR;
    }
    qemu_mutex_lock(&n->ps_lock);
    /* a transition already due happens on the old table first */
    femu_power_advance(n, femu_io_now(n));
    femu_pl_apply_locked(n, d, femu_io_now(n));
    n->pl_cur = dw13;
    if (save) {
        n->pl_saved = dw13;
    }
    qemu_mutex_unlock(&n->ps_lock);
    femu_power_id(n, &n->id_ctrl);
    return NVME_SUCCESS;
}

/* Get Features 23h: Dword 0 for the select @sel (current, default, saved) */
uint32_t femu_pl_get(FemuCtrl *n, uint8_t sel)
{
    switch (sel) {
    case NVME_GETFEAT_SELECT_DEFAULT:
        return FEMU_PL_DEFAULT;
    case NVME_GETFEAT_SELECT_SAVED:
        return n->pl_saved;
    default:
        return n->pl_cur;
    }
}
