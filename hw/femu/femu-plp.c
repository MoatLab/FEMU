/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Power-loss protection (plp=on).
 *
 * A drive with hold-up energy writes its buffer back when the supply goes,
 * so what the buffer holds is as safe as the media. The energy is a percent
 * (OCP 2.7 SMART-19, Capacitor Health): 100 is the factory pass level and 1
 * the least that still finishes a write-back. A check reads it when the
 * controller is enabled and every C6h minutes after that (PLP-3, PLP-9).
 * Below 1 the protection has failed for good: the Critical Warning bit for
 * the volatile memory backup goes on, a SMART event goes out, and the C2h
 * mode in force then decides what writes do.
 *
 *   01b ROM     destage the buffer, then refuse writes (status 82h)
 *   10b WTM     destage the buffer, then program before each completion
 *   11b normal  keep buffering; a cut loses the buffer again
 *
 * The energy itself, not the last check, decides a cut: energy that ran out
 * between two checks writes nothing back. A failure lasts for the life of
 * the device, and the mode taken then stays, whatever C2h says later.
 * ROM turns the buffer off as WTM does, so a write fetched before the
 * failure programs the media before it completes.
 *
 * Not with durable_at_done (a write-back is then durable only when its
 * programs end) or rain_parity (a cut would leave a stripe without its
 * parity).
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "nvme.h"

#define PLP_MODE(n)     ((n)->ocp_val[NVME_OCP_PLP_FAIL_MODE - 0xc0])
#define PLP_INTERVAL(n) ((n)->ocp_val[NVME_OCP_PLP_HEALTH_INTERVAL - 0xc0])

/* C2h values (OCP 2.7, SROWTM-13) */
enum {
    PLP_ROM     = 1,
    PLP_WTM     = 2,
    PLP_NORMAL  = 3,
};

/* the buffer may hold acknowledged writes as if they were on the media */
bool femu_plp_ok(FemuCtrl *n)
{
    return n->plp && !qatomic_read(&n->plp_failed);
}

/*
 * The protection failed: act on the C2h mode (the PLP-9 flow). Called from
 * the main loop with the BQL held.
 */
static void femu_plp_fail(FemuCtrl *n)
{
    uint8_t bits = NVME_SMART_FAILED_VOLATILE_MEDIA;
    uint32_t mode = PLP_MODE(n);
    bool resume = nvme_pause_pollers(n);

    /* user data in the buffer goes to the media before the mode changes */
    if (mode != PLP_NORMAL) {
        bbssd_flush_all(n);
    }
    qatomic_set(&n->plp_failed, true);
    if (mode == PLP_ROM) {
        qatomic_set(&n->plp_ro, true);
        bits |= NVME_SMART_MEDIA_READ_ONLY;
    }
    if (mode != PLP_NORMAL) {
        qatomic_set(&n->plp_wt, true);
    }
    nvme_resume_pollers(n, resume);

    femu_pel_plp_warning(n, bits);
    qatomic_or(&n->health_pending, bits);
    qatomic_or(&n->tel_req, bits);
    qemu_bh_schedule(n->aer_bh);
}

static void femu_plp_check(FemuCtrl *n)
{
    if (femu_plp_ok(n) && qatomic_read(&n->plp_health) < 1) {
        femu_plp_fail(n);
    }
}

/* the next timed check: C6h minutes from now, none for 0 */
void femu_plp_restart(FemuCtrl *n)
{
    if (!n->plp_timer) {
        return;
    }
    if (!PLP_INTERVAL(n) || !femu_plp_ok(n)) {
        timer_del(n->plp_timer);
        return;
    }
    timer_mod(n->plp_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
              (int64_t)PLP_INTERVAL(n) * 60 * NANOSECONDS_PER_SECOND);
}

static void femu_plp_timer_cb(void *opaque)
{
    FemuCtrl *n = opaque;

    femu_plp_check(n);
    femu_plp_restart(n);
}

/* CC.EN 0 to 1, before the data path starts: the power-on check */
void femu_plp_enable(FemuCtrl *n)
{
    if (!n->plp) {
        return;
    }
    /* made here, once realize can no longer fail */
    if (!n->plp_timer) {
        n->plp_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, femu_plp_timer_cb,
                                    n);
    }
    femu_plp_check(n);
    femu_plp_restart(n);
}

/*
 * A cut, with the controller stopped and before any buffered page rolls
 * back. Each one starts the protection (SMART-24). Working protection with
 * energy left writes every buffer back; a page with no room on the media
 * then rolls back, and the cut counts as incomplete.
 */
void femu_plp_cut(FemuCtrl *n)
{
    if (!n->plp) {
        return;
    }
    if (n->plp_starts != UINT64_MAX) {
        n->plp_starts++;
    }
    if (femu_plp_ok(n) && qatomic_read(&n->plp_health) >= 1) {
        bbssd_flush_all(n);
    }
}

static void femu_plp_get_health(Object *obj, Visitor *v, const char *name,
                                void *opaque, Error **errp)
{
    FemuCtrl *n = FEMU(obj);
    uint32_t value = qatomic_read(&n->plp_health);

    visit_type_uint32(v, name, &value, errp);
}

/* the stored energy now; the next check sees it */
static void femu_plp_set_health(Object *obj, Visitor *v, const char *name,
                                void *opaque, Error **errp)
{
    FemuCtrl *n = FEMU(obj);
    uint32_t value;

    if (!visit_type_uint32(v, name, &value, errp)) {
        return;
    }
    if (!DEVICE(obj)->realized || !n->plp || value > 0xfffe) {
        error_setg(errp, "plp-health needs plp=on and 0 to 65534");
        return;
    }
    qatomic_set(&n->plp_health, value);
}

/* realize: check the properties and turn the mode name into its C2h value */
bool femu_plp_init(FemuCtrl *n, Error **errp)
{
    static const char *const names[] = { NULL, "rom", "wtm", "normal" };
    const char *mode = n->plp_fail_mode;

    n->plp_mode_def = PLP_ROM;      /* ROWTM-1 */
    if (!n->plp) {
        if (mode) {
            error_setg(errp, "plp_fail_mode needs plp=on");
            return false;
        }
        /* C2h has nothing to act on without the protection */
        if (n->ocp && nvme_ocp_choice(n->ocp_profile, 6) == 'A') {
            error_setg(errp, "ocp_profile DP-CFG-6 A needs plp=on");
            return false;
        }
        return true;
    }
    if (!n->power_loss) {
        error_setg(errp, "plp needs power_loss=on");
        return false;
    }
    if (n->durable_at_done || n->bb_params.rain_parity) {
        error_setg(errp, "plp is not supported with %s",
                   n->durable_at_done ? "durable_at_done" : "rain_parity");
        return false;
    }
    if (n->plp_health > 0xfffe) {
        error_setg(errp, "plp_health must be 0 to 65534");
        return false;
    }
    if (mode) {
        int i;

        for (i = PLP_ROM; i <= PLP_NORMAL; i++) {
            if (!strcmp(mode, names[i])) {
                break;
            }
        }
        if (i > PLP_NORMAL) {
            error_setg(errp, "plp_fail_mode must be rom, wtm or normal");
            return false;
        }
        n->plp_mode_def = i;
    }
    /* DP-CFG-6 B hides C2h and keeps the ROWTM-1 default */
    if (n->ocp && nvme_ocp_choice(n->ocp_profile, 6) == 'B' &&
        n->plp_mode_def != PLP_ROM) {
        error_setg(errp, "ocp_profile DP-CFG-6 B needs plp_fail_mode rom");
        return false;
    }
    /* an OCP drive with PLP has no volatile cache to disable (NVMe-IO-3) */
    if (n->ocp && n->vwc) {
        error_setg(errp, "plp with ocp=on needs vwc=0");
        return false;
    }
    return true;
}

void femu_plp_add_props(Object *obj)
{
    object_property_add(obj, "plp-health", "uint32", femu_plp_get_health,
                        femu_plp_set_health, NULL, NULL);
}
