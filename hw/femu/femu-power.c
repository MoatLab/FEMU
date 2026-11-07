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
 * The state moves forward when it is read, not on a timer. Idle time runs
 * from the later of the last I/O fetch and the end of the work the FTL
 * booked. Open gap: a request still queued for the FTL, or held for a full
 * CQ, does not count as busy.
 */

#include "./nvme.h"

#define FEMU_NPSS           3
#define FEMU_PS_NONOP       3

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
    return true;
}

/* the descriptors of Identify Controller, APSTA, NPSS */
void femu_power_id(FemuCtrl *n, NvmeIdCtrl *id)
{
    if (!n->power_states) {
        return;
    }
    id->npss = FEMU_NPSS;
    id->apsta = 1;
    for (int i = 0; i <= FEMU_NPSS; i++) {
        NvmePSD psd = { 0 };

        /* MXPS 0: 0.01 W units; PS3 draws 0.05 W */
        psd.mp = cpu_to_le16(i == FEMU_PS_NONOP ? 5 :
                             n->ps_max_watts * femu_ps[i].mp_pct);
        psd.enlat = cpu_to_le32(femu_ps[i].enlat_us);
        psd.exlat = cpu_to_le32(femu_ps[i].exlat_us);
        psd.rrt = femu_ps[i].rel;
        psd.rrl = femu_ps[i].rel;
        psd.rwt = femu_ps[i].rel;
        psd.rwl = femu_ps[i].rel;
        /* byte 3 bit 1: NOPS */
        psd.reserved = cpu_to_le16(i == FEMU_PS_NONOP ? 1 << 9 : 0);
        id->psd[i] = psd;
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
    if (nvme_sanitize_busy(n)) {
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
        n->ps_cur = itps;
        n->ps_entered = base;
    }
}

static void femu_power_enter(FemuCtrl *n, uint8_t ps, int64_t now)
{
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
        femu_power_enter(n, n->ps_op, now);
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
 * Set Features 02h: the controller is in @ps when the command completes.
 * Leaving PS3 for an operational state takes PS3's exit latency.
 */
void femu_power_set(FemuCtrl *n, uint8_t ps)
{
    int64_t now;

    if (!n->power_states) {
        return;
    }
    now = femu_io_now(n);
    qemu_mutex_lock(&n->ps_lock);
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
    ps = n->ps_cur;
    qemu_mutex_unlock(&n->ps_lock);
    return wh | ps;
}

/*
 * Feature 0Ch (5.2.26.1.6): APSTE in CDW11 bit 0, 32 entries of ITPT
 * (bits 31:8, ms) and ITPS (bits 7:3). An entry with ITPT set must name a
 * non-operational state; otherwise the command fails and nothing changes.
 */
uint16_t femu_apst_set(FemuCtrl *n, NvmeCmd *cmd)
{
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
        if ((i > FEMU_NPSS && e) ||
            ((e >> 8) & 0xffffff && itps != FEMU_PS_NONOP)) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
    }
    /* the state reached so far stays; the new table counts from now */
    qemu_mutex_lock(&n->ps_lock);
    femu_power_advance(n, femu_io_now(n));
    for (int i = 0; i < 32; i++) {
        n->apst[i] = le64_to_cpu(tbl[i]);
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
    for (int i = 0; i < 32 && !dflt; i++) {
        tbl[i] = cpu_to_le64(n->apst[i]);
    }
    qemu_mutex_unlock(&n->ps_lock);
    return dma_read_prp(n, (uint8_t *)tbl, sizeof(tbl),
                        le64_to_cpu(cmd->dptr.prp1),
                        le64_to_cpu(cmd->dptr.prp2));
}

/* a Controller Level Reset: PS0, APST off and its table cleared */
void femu_power_reset(FemuCtrl *n)
{
    if (!n->power_states) {
        return;
    }
    qemu_mutex_lock(&n->ps_lock);
    n->apste = false;
    memset(n->apst, 0, sizeof(n->apst));
    n->ps_ready_at = 0;
    n->ps_last_io = 0;
    qatomic_set(&n->ps_busy_until, 0);
    femu_power_enter(n, 0, femu_io_now(n));
    qemu_mutex_unlock(&n->ps_lock);
}
